#![allow(non_snake_case)]

//! Baby-step Giant-step algorithm for solving discrete logarithms.

#[cfg(feature = "bsgs_table32")]
pub mod precomputed_tables;

#[cfg(feature = "bsgs_table32")]
use crate::bsgs::precomputed_tables::PrecomputedTables;
use crate::utils;

use anyhow::{Context, Result};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use std::collections::HashMap;
use std::ops::{Add, Mul};

/// Baby-step Giant-step algorithm for solving discrete logarithms.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BabyStepGiantStep {
    pub table: BabyStepGiantStepTable,
}

/// Defines generated table values for BSGS.
#[cfg_attr(feature = "serde", serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BabyStepGiantStepTable {
    /// Size of a secret to look for (in bits).
    pub max_num_bits: u8,

    /// m = ceil(sqrt(2^max_num_bits)), the number of baby steps.
    pub m: u64,

    /// Baby-step lookup table: maps compressed point to its discrete log (j).
    /// Contains g^j for j = 0, 1, ..., m-1 where m = ceil(sqrt(2^max_num_bits)).
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<(_, _)>"))]
    pub baby_steps: HashMap<CompressedRistretto, u64>,

    /// Precomputed giant step: g^(-m) used to compute h * (g^(-m))^i.
    pub giant_step: RistrettoPoint,
}

impl BabyStepGiantStep {
    #[cfg(feature = "bsgs_table32")]
    pub fn from_precomputed_table(table: PrecomputedTables) -> Result<BabyStepGiantStep> {
        let bsgs_bytes = match table {
            #[cfg(feature = "bsgs_table32")]
            PrecomputedTables::BabyStepGiantStep32 => precomputed_tables::BSGS_32,
        };

        let bsgs: BabyStepGiantStep =
            bincode::deserialize(bsgs_bytes).context("failed to deserialize table")?;

        Ok(bsgs)
    }

    /// Solves the discrete logarithm problem using Baby-step Giant-step.
    ///
    /// Given pk = g^x, finds x where x is in [0, 2^max_num_bits).
    ///
    /// Algorithm:
    /// 1. For i = 0, 1, ..., m-1:
    ///    - Compute gamma = pk * (g^(-m))^i
    ///    - If gamma is in baby_steps table with value j, then x = i*m + j
    ///
    /// Note: `max_time` must be `None`. BSGS is deterministic and always terminates
    /// in bounded time, so timeout is not supported.
    pub fn solve_dlp(&self, pk: &RistrettoPoint, max_time: Option<u64>) -> Result<u64> {
        if max_time.is_some() {
            return Err(anyhow::anyhow!(
                "timeout not supported for BSGS (deterministic algorithm)"
            ));
        }

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
                let x = i * m + j;

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
    pub fn generate(max_num_bits: u8) -> Result<BabyStepGiantStepTable> {
        if max_num_bits < 1 || max_num_bits > 64 {
            return Err(anyhow::anyhow!("max_num_bits must be between 1 and 64"));
        }

        // m = ceil(sqrt(2^max_num_bits)) = 2^(ceil(max_num_bits/2))
        let m: u64 = 1 << ((max_num_bits + 1) / 2);

        // Baby steps: compute g^0, g^1, ..., g^(m-1)
        let mut baby_steps = HashMap::with_capacity(m as usize);
        let mut current = RistrettoPoint::default(); // identity
        let g = RISTRETTO_BASEPOINT_POINT;

        // g^0 = identity
        baby_steps.insert(current.compress(), 0u64);

        // g^1, g^2, ..., g^(m-1)
        for j in 1..m {
            current = current + g;
            baby_steps.insert(current.compress(), j);
        }

        // Compute g^(-m) for giant steps
        // -m mod group_order
        let m_scalar = Scalar::from(m);
        let neg_m = -m_scalar;
        let giant_step = g.mul(neg_m);

        Ok(BabyStepGiantStepTable {
            max_num_bits,
            m,
            baby_steps,
            giant_step,
        })
    }
}

impl crate::DlogSolver for BabyStepGiantStep {
    fn new_and_compute_table(max_num_bits: u8) -> Result<Self> {
        let table =
            BabyStepGiantStepTable::generate(max_num_bits).context("failed to generate table")?;
        Ok(BabyStepGiantStep { table })
    }

    fn solve(&self, pk: &RistrettoPoint) -> Result<u64> {
        self.solve_dlp(pk, None)
    }

    fn max_num_bits(&self) -> u8 {
        self.table.max_num_bits
    }
}
