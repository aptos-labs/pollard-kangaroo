//! Naive lookup-based algorithm for solving discrete logarithms.
//!
//! This is the simplest approach: precompute all possible values iG for i in [0, 2^ℓ)
//! and store them in a hash table. Solving a DLP is then a single hash lookup.
//!
//! - Table size: O(2^ℓ)
//! - Solve time: O(1) (single hash lookup)
//!
//! This is only practical for small values of ℓ (e.g., ℓ ≤ 24).
//!
//! Note: For 16-bit lookups, prefer using `from_bsgs_precomputed_table()` which
//! reuses the BSGS 32-bit table's baby_steps, avoiding the need for a separate table.

use anyhow::Result;
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
    pub table: NaiveLookupTable,
}

/// Lookup table for the naive algorithm.
///
/// Maps compressed points to their discrete logs.
#[cfg_attr(feature = "serde", serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NaiveLookupTable {
    /// Maximum number of bits for secrets (ℓ).
    /// The solver can find discrete logs for values in [0, 2^max_num_bits).
    pub max_num_bits: u8,

    /// Lookup table: maps compressed point (iG) to its discrete log (i).
    /// Contains entries for i = 0, 1, ..., 2^max_num_bits - 1.
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<(_, _)>"))]
    pub lookup: HashMap<CompressedRistretto, u64>,
}

impl NaiveLookup {
    /// Creates a 16-bit solver by reusing the BSGS 32-bit table's baby_steps.
    ///
    /// The BSGS table for 32-bit secrets stores `compress(j*G) -> j` for `j ∈ [0, 2^16)`,
    /// which is exactly what we need for 16-bit naive lookup.
    ///
    /// # Panics
    /// Panics if the precomputed table is corrupted (should never happen).
    #[cfg(feature = "bsgs_table32")]
    pub fn from_bsgs_precomputed_table(
        table: crate::bsgs::precomputed_tables::PrecomputedTables,
    ) -> NaiveLookup {
        use crate::bsgs::precomputed_tables;

        let bsgs_bytes = match table {
            precomputed_tables::PrecomputedTables::Bsgs32 => precomputed_tables::BSGS_32,
        };

        let bsgs: crate::bsgs::BabyStepGiantStep =
            bincode::deserialize(bsgs_bytes).expect("precomputed table is corrupted");

        // The BSGS baby_steps table contains compress(j*G) -> j for j in [0, 2^16)
        // This is exactly what NaiveLookup needs for 16-bit lookups
        NaiveLookup {
            table: NaiveLookupTable {
                max_num_bits: 16, // BSGS 32-bit has m = 2^16 baby steps
                lookup: bsgs.table.baby_steps,
            },
        }
    }

    /// Solves the discrete log problem using naive lookup.
    ///
    /// Given pk = g^x, finds x where x is in [0, 2^max_num_bits).
    pub fn solve(&self, pk: &RistrettoPoint) -> Result<u64> {
        let pk_compressed = pk.compress();

        self.table
            .lookup
            .get(&pk_compressed)
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no solution found in range [0, 2^{})",
                    self.table.max_num_bits
                )
            })
    }
}

impl NaiveLookupTable {
    /// Generates the lookup table.
    ///
    /// Computes iG for i = 0, 1, ..., 2^max_num_bits - 1 and stores (compressed(iG) -> i).
    pub fn generate(max_num_bits: u8) -> NaiveLookupTable {
        assert!(
            max_num_bits >= 1 && max_num_bits <= 32,
            "max_num_bits must be between 1 and 32, got {}",
            max_num_bits
        );

        let n: u64 = 1 << max_num_bits;

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

        NaiveLookupTable {
            max_num_bits,
            lookup,
        }
    }
}

impl crate::DiscreteLogSolver for NaiveLookup {
    fn new_and_compute_table(max_num_bits: u8) -> Self {
        let table = NaiveLookupTable::generate(max_num_bits);
        NaiveLookup { table }
    }

    fn solve(&self, pk: &RistrettoPoint) -> Result<u64> {
        NaiveLookup::solve(self, pk)
    }

    fn max_num_bits(&self) -> u8 {
        self.table.max_num_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DiscreteLogSolver;
    use std::ops::Mul;

    #[test]
    fn naive_handles_identity_point() {
        let naive = NaiveLookup::new_and_compute_table(8);

        // 0*G = identity
        let identity = RistrettoPoint::identity();
        let result = naive.solve(&identity).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn naive_handles_generator() {
        let naive = NaiveLookup::new_and_compute_table(8);

        // 1*G = generator
        let result = naive.solve(&RISTRETTO_BASEPOINT_POINT).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn naive_handles_small_values() {
        let naive = NaiveLookup::new_and_compute_table(8);

        for i in 0..=255u64 {
            let pk = RISTRETTO_BASEPOINT_POINT.mul(crate::utils::u64_to_scalar(i));
            let result = naive.solve(&pk).unwrap();
            assert_eq!(result, i, "failed for i={}", i);
        }
    }

    #[cfg(feature = "bsgs_table32")]
    #[test]
    fn naive_from_bsgs_table() {
        use crate::bsgs::precomputed_tables::PrecomputedTables;

        let naive = NaiveLookup::from_bsgs_precomputed_table(PrecomputedTables::Bsgs32);
        assert_eq!(naive.table.max_num_bits, 16);

        // Test a few values
        for i in [0u64, 1, 100, 1000, 65535] {
            let pk = RISTRETTO_BASEPOINT_POINT.mul(crate::utils::u64_to_scalar(i));
            let result = naive.solve(&pk).unwrap();
            assert_eq!(result, i, "failed for i={}", i);
        }

        // 65536 should fail (out of range for 16-bit)
        let pk = RISTRETTO_BASEPOINT_POINT.mul(crate::utils::u64_to_scalar(65536));
        assert!(naive.solve(&pk).is_err());
    }
}
