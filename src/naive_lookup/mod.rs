//! Naive lookup-based algorithm for solving discrete logarithms.
//!
//! This is the simplest approach: precompute all possible values iG for i in [0, 2^ℓ)
//! and store them in a hash table. Solving a DLP is then a single hash lookup.
//!
//! - Table size: O(2^ℓ)
//! - Solve time: O(1) (single hash lookup)
//!
//! This is only practical for small values of ℓ (e.g., ℓ ≤ 24).

#[cfg(feature = "naive_lookup_precomputed_tables")]
pub mod precomputed_tables;

#[cfg(feature = "naive_lookup_precomputed_tables")]
use crate::naive_lookup::precomputed_tables::PrecomputedTables;

use anyhow::{Context, Result};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use std::collections::HashMap;

/// Naive lookup-based solver for discrete logarithms.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NaiveLookup {
    pub parameters: NaiveLookupParameters,
    pub table: NaiveLookupTable,
}

/// Parameters for the naive lookup algorithm.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NaiveLookupParameters {
    /// Maximum number of bits for secrets (ℓ).
    /// The solver can find discrete logs for values in [0, 2^max_num_bits).
    pub max_num_bits: u8,
}

/// Lookup table for the naive algorithm.
///
/// Maps compressed points to their discrete logs.
#[cfg_attr(feature = "serde", serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NaiveLookupTable {
    /// Lookup table: maps compressed point (iG) to its discrete log (i).
    /// Contains entries for i = 0, 1, ..., 2^max_num_bits - 1.
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<(_, _)>"))]
    pub lookup: HashMap<CompressedRistretto, u64>,
}

impl NaiveLookup {
    /// Creates a new solver from parameters.
    pub fn from_parameters(parameters: NaiveLookupParameters) -> Result<NaiveLookup> {
        let table = NaiveLookupTable::generate(&parameters).context("failed to generate table")?;

        Ok(NaiveLookup { parameters, table })
    }

    /// Creates a solver from a precomputed table.
    #[cfg(feature = "naive_lookup_precomputed_tables")]
    pub fn from_precomputed_table(table: PrecomputedTables) -> Result<NaiveLookup> {
        let bytes = match table {
            #[cfg(feature = "naive_lookup_table16")]
            PrecomputedTables::NaiveLookup16 => precomputed_tables::NAIVE_LOOKUP_16,
        };

        let naive: NaiveLookup =
            bincode::deserialize(bytes).context("failed to deserialize table")?;

        Ok(naive)
    }

    /// Solves the discrete logarithm problem using naive lookup.
    ///
    /// Given pk = g^x, finds x where x is in [0, 2^max_num_bits).
    ///
    /// Note: `max_time` must be `None`. Naive lookup is deterministic and always
    /// terminates in constant time, so timeout is not supported.
    pub fn solve_dlp(&self, pk: &RistrettoPoint, max_time: Option<u64>) -> Result<u64> {
        if max_time.is_some() {
            return Err(anyhow::anyhow!(
                "timeout not supported for naive lookup (deterministic algorithm)"
            ));
        }

        let pk_compressed = pk.compress();

        self.table
            .lookup
            .get(&pk_compressed)
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no solution found in range [0, 2^{})",
                    self.parameters.max_num_bits
                )
            })
    }
}

impl NaiveLookupTable {
    /// Generates the lookup table.
    ///
    /// Computes iG for i = 0, 1, ..., 2^max_num_bits - 1 and stores (compressed(iG) -> i).
    pub fn generate(parameters: &NaiveLookupParameters) -> Result<NaiveLookupTable> {
        if parameters.max_num_bits < 1 || parameters.max_num_bits > 32 {
            return Err(anyhow::anyhow!("max_num_bits must be between 1 and 32"));
        }

        let n: u64 = 1 << parameters.max_num_bits;

        let mut lookup = HashMap::with_capacity(n as usize);
        let mut current = RistrettoPoint::identity();
        let g = RISTRETTO_BASEPOINT_POINT;

        // 0*G = identity
        lookup.insert(current.compress(), 0u64);

        // 1*G, 2*G, ..., (2^max_num_bits - 1)*G
        for i in 1..n {
            current = current + g;
            lookup.insert(current.compress(), i);
        }

        Ok(NaiveLookupTable { lookup })
    }
}

impl crate::DlogSolver for NaiveLookup {
    fn new_and_compute_table(max_num_bits: u8) -> Result<Self> {
        if max_num_bits < 1 || max_num_bits > 32 {
            return Err(anyhow::anyhow!("max_num_bits must be between 1 and 32"));
        }

        let parameters = NaiveLookupParameters { max_num_bits };
        Self::from_parameters(parameters)
    }

    fn solve(&self, pk: &RistrettoPoint) -> Result<u64> {
        self.solve_dlp(pk, None)
    }

    fn max_num_bits(&self) -> u8 {
        self.parameters.max_num_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DlogSolver;
    use std::ops::Mul;

    #[test]
    fn naive_handles_identity_point() {
        let naive = NaiveLookup::new_and_compute_table(8).unwrap();

        // 0*G = identity
        let identity = RistrettoPoint::identity();
        let result = naive.solve(&identity).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn naive_handles_generator() {
        let naive = NaiveLookup::new_and_compute_table(8).unwrap();

        // 1*G = generator
        let result = naive.solve(&RISTRETTO_BASEPOINT_POINT).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn naive_handles_small_values() {
        let naive = NaiveLookup::new_and_compute_table(8).unwrap();

        for i in 0..=255u64 {
            let pk = RISTRETTO_BASEPOINT_POINT.mul(crate::utils::u64_to_scalar(i));
            let result = naive.solve(&pk).unwrap();
            assert_eq!(result, i, "failed for i={}", i);
        }
    }
}
