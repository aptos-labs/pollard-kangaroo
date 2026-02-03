#![allow(non_snake_case)]

//! Baby-step Giant-step algorithm for solving discrete logarithms.

#[cfg(feature = "bsgs_table32")]
pub mod precomputed_tables;

#[cfg(feature = "bsgs_table32")]
use crate::bsgs::precomputed_tables::PrecomputedTables;
use crate::utils;

use anyhow::Result;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::{Add, Mul};
use std::sync::Arc;

/// Baby-step Giant-step algorithm for solving discrete logarithms.
///
/// The table is wrapped in `Arc` to allow sharing with other solvers (e.g.,
/// `NaiveLookup`) without duplicating the ~2.5 MiB precomputed data.
/// This is safe for WASM which is single-threaded, and `Arc` has negligible
/// overhead in uncontended scenarios.
pub struct BabyStepGiantStep {
    pub table: Arc<BabyStepGiantStepTable>,
}

/// Defines generated table values for BSGS.
pub struct BabyStepGiantStepTable {
    /// Size of a secret to look for (in bits).
    pub max_num_bits: u8,

    /// m = ceil(sqrt(2^max_num_bits)), the number of baby steps.
    pub m: u64,

    /// Baby-step lookup table: maps compressed point to its discrete log (j).
    /// Contains g^j for j = 0, 1, ..., m-1 where m = ceil(sqrt(2^max_num_bits)).
    ///
    /// Values are u16 since j < m <= 65536 for max_num_bits <= 32.
    pub baby_steps: HashMap<CompressedRistretto, u16>,

    /// Precomputed giant step: g^(-m) used to compute h * (g^(-m))^i.
    pub giant_step: RistrettoPoint,
}

/// Compact serialization format for BSGS table.
/// Points are stored in order by discrete log (points[i] = compress(g^i)),
/// so values are implicit and don't need to be stored.
#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
struct BabyStepGiantStepTableSerialized {
    max_num_bits: u8,
    m: u64,
    /// Points stored in order: baby_steps[j] = compress(g^j)
    baby_steps: Vec<CompressedRistretto>,
    giant_step: RistrettoPoint,
}

#[cfg(feature = "serde")]
impl BabyStepGiantStepTable {
    /// Deserialize from compact format, rebuilding the HashMap.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        let serialized: BabyStepGiantStepTableSerialized = bincode::deserialize(bytes)?;

        // Rebuild HashMap with implicit indices as values
        let mut baby_steps = HashMap::with_capacity(serialized.baby_steps.len());
        for (j, point) in serialized.baby_steps.into_iter().enumerate() {
            baby_steps.insert(point, j as u16);
        }

        Ok(BabyStepGiantStepTable {
            max_num_bits: serialized.max_num_bits,
            m: serialized.m,
            baby_steps,
            giant_step: serialized.giant_step,
        })
    }

    /// Serialize to compact format (points only, no values).
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        // Convert HashMap to sorted Vec (sorted by value = discrete log)
        let mut points: Vec<(u16, CompressedRistretto)> =
            self.baby_steps.iter().map(|(k, &v)| (v, *k)).collect();
        points.sort_by_key(|(v, _)| *v);
        let baby_steps: Vec<CompressedRistretto> = points.into_iter().map(|(_, k)| k).collect();

        let serialized = BabyStepGiantStepTableSerialized {
            max_num_bits: self.max_num_bits,
            m: self.m,
            baby_steps,
            giant_step: self.giant_step,
        };

        bincode::serialize(&serialized)
    }
}

impl BabyStepGiantStep {
    /// Creates a solver from a precomputed table.
    ///
    /// # Panics
    /// Panics if the precomputed table is corrupted (should never happen).
    #[cfg(feature = "bsgs_table32")]
    pub fn from_precomputed_table(table: PrecomputedTables) -> BabyStepGiantStep {
        let bsgs_bytes = match table {
            #[cfg(feature = "bsgs_table32")]
            PrecomputedTables::Bsgs32 => precomputed_tables::BSGS_32,
        };

        let table =
            BabyStepGiantStepTable::from_bytes(bsgs_bytes).expect("precomputed table is corrupted");
        BabyStepGiantStep {
            table: Arc::new(table),
        }
    }

    /// Returns a clone of the Arc-wrapped table.
    ///
    /// Use this to share the table with other solvers (e.g., `NaiveLookup`)
    /// without duplicating the data.
    pub fn table(&self) -> Arc<BabyStepGiantStepTable> {
        Arc::clone(&self.table)
    }

    /// Solves the discrete log problem using Baby-step Giant-step.
    ///
    /// Given pk = g^x, finds x where x is in [0, 2^max_num_bits).
    ///
    /// Algorithm:
    /// 1. For i = 0, 1, ..., m-1:
    ///    - Compute gamma = pk * (g^(-m))^i
    ///    - If gamma is in baby_steps table with value j, then x = i*m + j
    pub fn solve(&self, pk: &RistrettoPoint) -> Result<u64> {
        if pk.eq(&RistrettoPoint::identity()) {
            return Ok(0);
        }

        let m = self.table.m;

        // gamma starts as pk, then we multiply by g^(-m) each iteration
        let mut gamma = *pk;

        for i in 0..m {
            // NOTE: This is the most expensive step, actually!
            let gamma_compressed = gamma.compress();

            // Check if gamma is in the baby steps table
            if let Some(&j) = self.table.baby_steps.get(&gamma_compressed) {
                let x = i * m + j as u64;

                // Verify the result (optional but good for debugging)
                debug_assert!({
                    let computed = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
                        * utils::u64_to_scalar(x);
                    computed.eq(pk)
                });

                return Ok(x);
            }

            // gamma = gamma * g^(-m)
            gamma = gamma.add(self.table.giant_step);
        }

        // No solution found in the range [0, m^2)
        Err(anyhow::anyhow!(
            "no solution found in range [0, 2^{})",
            self.table.max_num_bits
        ))
    }
}

impl BabyStepGiantStepTable {
    /// Generates the BSGS table with baby steps.
    ///
    /// Baby step: Compute g^j for j = 0, 1, ..., m-1 and store in a hash table.
    /// Also precompute g^(-m) for the giant step phase.
    pub fn generate(max_num_bits: u8) -> BabyStepGiantStepTable {
        assert!(
            max_num_bits >= 1 && max_num_bits <= 32,
            "max_num_bits must be between 1 and 32, got {} (u16 values require m <= 65536)",
            max_num_bits
        );

        // m = ceil(sqrt(2^max_num_bits)) = 2^(ceil(max_num_bits/2))
        let m: u64 = 1 << ((max_num_bits + 1) / 2);

        // Baby steps: compute g^0, g^1, ..., g^(m-1)
        let mut baby_steps = HashMap::with_capacity(m as usize);
        let mut current = RistrettoPoint::default(); // identity
        let g = RISTRETTO_BASEPOINT_POINT;

        // g^0 = identity
        baby_steps.insert(current.compress(), 0u16);

        // g^1, g^2, ..., g^(m-1)
        for j in 1..m {
            current = current + g;
            baby_steps.insert(current.compress(), j as u16);
        }

        // Compute g^(-m) for giant steps
        // -m mod group_order
        let m_scalar = Scalar::from(m);
        let neg_m = -m_scalar;
        let giant_step = g.mul(neg_m);

        BabyStepGiantStepTable {
            max_num_bits,
            m,
            baby_steps,
            giant_step,
        }
    }
}

impl crate::DiscreteLogSolver for BabyStepGiantStep {
    fn new_and_compute_table(max_num_bits: u8) -> Self {
        let table = BabyStepGiantStepTable::generate(max_num_bits);
        BabyStepGiantStep {
            table: Arc::new(table),
        }
    }

    fn solve(&self, pk: &RistrettoPoint) -> Result<u64> {
        BabyStepGiantStep::solve(self, pk)
    }

    fn max_num_bits(&self) -> u8 {
        self.table.max_num_bits
    }
}
