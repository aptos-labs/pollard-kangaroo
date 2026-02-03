//! Naive doubled lookup algorithm for solving discrete logarithms.
//!
//! This algorithm reuses the BSGS-k "doubled" baby-step tables to perform
//! constant-time lookups for values up to half the BSGS-k table's max_num_bits.
//!
//! The BSGS-k tables store `compress(2*g^j)` for `j ∈ [0, m)` where `m = 2^(max_num_bits/2)`.
//! For a 32-bit BSGS-k table, `m = 2^16`, so we can solve 16-bit DLs in O(1) time.
//!
//! Algorithm:
//! 1. Given `y = g^x` where `x ∈ [0, 2^16)`
//! 2. Double: `2*y = 2*g^x`
//! 3. Compress and look up in the BSGS-k baby_steps table
//!
//! - Table size: Reuses BSGS-k table (no additional storage)
//! - Solve time: O(1) (single doubling + compression + hash lookup)

use crate::bsgs_k::BabyStepGiantStepKTable;
use anyhow::Result;
use curve25519_dalek::ristretto::RistrettoPoint;
use std::sync::Arc;

#[cfg(feature = "bsgs_k_table32")]
use crate::bsgs_k::precomputed_tables::PrecomputedTables;

/// Naive doubled lookup solver that reuses BSGS-k tables for O(1) lookups.
///
/// For a BSGS-k table with `max_num_bits = N`, this solver can find discrete logs
/// for values in `[0, 2^(N/2))` in constant time.
///
/// The table is wrapped in `Arc` to allow sharing with `BabyStepGiantStepK`
/// without duplicating the ~2.5 MiB precomputed data.
pub struct NaiveDoubledLookup {
    /// Shared reference to the BSGS-k table.
    /// The table stores `compress(2*g^j)` for `j ∈ [0, m)`.
    pub table: Arc<BabyStepGiantStepKTable>,
}

impl NaiveDoubledLookup {
    /// Creates a solver that shares the table with an existing `BabyStepGiantStepK`.
    ///
    /// This is the preferred constructor when you already have a `BabyStepGiantStepK`
    /// instance, as it avoids duplicating the ~2.5 MiB table data.
    pub fn from_bsgs_k<const K: usize>(
        bsgs_k: &crate::bsgs_k::BabyStepGiantStepK<K>,
    ) -> NaiveDoubledLookup {
        NaiveDoubledLookup {
            table: bsgs_k.table(),
        }
    }

    /// Creates a solver from a precomputed BSGS-k table.
    ///
    /// Note: If you already have a `BabyStepGiantStepK` instance, prefer using
    /// `from_bsgs_k()` to share the table without duplication.
    ///
    /// # Panics
    /// Panics if the precomputed table is corrupted (should never happen).
    #[cfg(feature = "bsgs_k_table32")]
    pub fn from_precomputed_table(table: PrecomputedTables) -> NaiveDoubledLookup {
        use crate::bsgs_k::precomputed_tables;

        let bsgs_bytes = match table {
            #[cfg(feature = "bsgs_k_table32")]
            PrecomputedTables::BsgsK32 => precomputed_tables::BSGS_K_32,
        };

        let bsgs_k_table = BabyStepGiantStepKTable::from_bytes(bsgs_bytes)
            .expect("precomputed table is corrupted");

        NaiveDoubledLookup {
            table: Arc::new(bsgs_k_table),
        }
    }

    /// Returns the maximum number of bits this solver can handle.
    ///
    /// For a BSGS-k table with `max_num_bits = N`, this returns `N/2`.
    pub fn max_num_bits(&self) -> u8 {
        self.table.max_num_bits / 2
    }

    /// Solves the discrete log problem using naive doubled lookup.
    ///
    /// Given `y = g^x`, finds `x` where `x` is in `[0, 2^(max_num_bits/2))`.
    ///
    /// This is O(1): one point doubling, one compression, one hash lookup.
    pub fn solve(&self, y: &RistrettoPoint) -> Result<u64> {
        // Double the point: 2*y = 2*g^x
        let doubled = y + y;

        // Compress and look up
        let compressed = doubled.compress();

        self.table
            .baby_steps
            .get(&compressed)
            .map(|&j| j as u64)
            .ok_or_else(|| {
                anyhow::anyhow!("no solution found in range [0, 2^{})", self.max_num_bits())
            })
    }
}

impl crate::DiscreteLogSolver for NaiveDoubledLookup {
    fn algorithm_name() -> &'static str {
        "NaiveDoubledLookup"
    }

    fn new_and_compute_table(max_num_bits: u8) -> Self {
        // Generate a BSGS-k table for 2*max_num_bits to support max_num_bits lookups
        let table = BabyStepGiantStepKTable::generate(max_num_bits * 2);
        NaiveDoubledLookup {
            table: Arc::new(table),
        }
    }

    fn from_precomputed_table(max_num_bits: u8) -> Self {
        // NaiveDoubledLookup uses BSGS-k tables, so for 16-bit lookups we need 32-bit BSGS-k table
        #[cfg(feature = "bsgs_k_table32")]
        if max_num_bits == 16 {
            return NaiveDoubledLookup::from_precomputed_table(PrecomputedTables::BsgsK32);
        }

        panic!(
            "No precomputed NaiveDoubledLookup table available for {} bits. \
             Available: 16 bits (requires 'bsgs_k_table32' feature, uses BSGS-k 32-bit table).",
            max_num_bits
        );
    }

    fn solve(&self, y: &RistrettoPoint) -> Result<u64> {
        NaiveDoubledLookup::solve(self, y)
    }

    fn max_num_bits(&self) -> u8 {
        NaiveDoubledLookup::max_num_bits(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DiscreteLogSolver;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::traits::Identity;
    use std::ops::Mul;

    #[test]
    fn naive_doubled_handles_identity_point() {
        // Generate a table for 16-bit lookups (needs 32-bit BSGS-k table)
        let solver = NaiveDoubledLookup::new_and_compute_table(8);
        assert_eq!(solver.max_num_bits(), 8);

        // 0*G = identity
        let identity = RistrettoPoint::identity();
        let result = solver.solve(&identity).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn naive_doubled_handles_generator() {
        let solver = NaiveDoubledLookup::new_and_compute_table(8);

        // 1*G = generator
        let result = solver.solve(&RISTRETTO_BASEPOINT_POINT).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn naive_doubled_handles_small_values() {
        let solver = NaiveDoubledLookup::new_and_compute_table(8);

        for i in 0..=255u64 {
            let pk = RISTRETTO_BASEPOINT_POINT.mul(crate::utils::u64_to_scalar(i));
            let result = solver.solve(&pk).unwrap();
            assert_eq!(result, i, "failed for i={}", i);
        }
    }

    #[cfg(feature = "bsgs_k_table32")]
    #[test]
    fn naive_doubled_with_precomputed_table() {
        use crate::bsgs_k::precomputed_tables::PrecomputedTables;

        let solver = NaiveDoubledLookup::from_precomputed_table(PrecomputedTables::BsgsK32);
        assert_eq!(solver.max_num_bits(), 16);

        // Test a few values
        for i in [0u64, 1, 100, 1000, 65535] {
            let pk = RISTRETTO_BASEPOINT_POINT.mul(crate::utils::u64_to_scalar(i));
            let result = solver.solve(&pk).unwrap();
            assert_eq!(result, i, "failed for i={}", i);
        }
    }

    #[cfg(feature = "bsgs_k_table32")]
    #[test]
    fn naive_doubled_fails_for_out_of_range() {
        use crate::bsgs_k::precomputed_tables::PrecomputedTables;

        let solver = NaiveDoubledLookup::from_precomputed_table(PrecomputedTables::BsgsK32);

        // 65536 is out of range for 16-bit
        let pk = RISTRETTO_BASEPOINT_POINT.mul(crate::utils::u64_to_scalar(65536));
        let result = solver.solve(&pk);
        assert!(result.is_err());
    }

    #[cfg(feature = "bsgs_k_table32")]
    #[test]
    fn naive_doubled_from_bsgs_k_shares_table() {
        use crate::bsgs_k::precomputed_tables::PrecomputedTables;
        use crate::bsgs_k::BabyStepGiantStepK;

        let bsgs_k = BabyStepGiantStepK::<32>::from_precomputed_table(PrecomputedTables::BsgsK32);
        let naive = NaiveDoubledLookup::from_bsgs_k(&bsgs_k);

        // Verify they share the same Arc (same pointer)
        assert!(Arc::ptr_eq(&bsgs_k.table, &naive.table));

        // Test solving works
        for i in [0u64, 1, 100, 1000, 65535] {
            let pk = RISTRETTO_BASEPOINT_POINT.mul(crate::utils::u64_to_scalar(i));
            let result = naive.solve(&pk).unwrap();
            assert_eq!(result, i, "failed for i={}", i);
        }
    }
}
