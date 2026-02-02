//! Naive lookup-based algorithm for solving discrete logarithms.
//!
//! This algorithm reuses the BSGS baby-step table to perform constant-time
//! lookups for 16-bit values.
//!
//! The BSGS 32-bit table stores `compress(j*G) -> j` for `j ∈ [0, 2^16)`,
//! which is exactly what we need for 16-bit naive lookup.
//!
//! - Table size: Reuses BSGS table (no additional storage)
//! - Solve time: O(1) (single compression + hash lookup)

use crate::bsgs::{BabyStepGiantStep, BabyStepGiantStepTable};
use anyhow::Result;
use curve25519_dalek::ristretto::RistrettoPoint;
use std::sync::Arc;

/// Naive lookup-based solver for 16-bit discrete logarithms.
///
/// Reuses the BSGS baby_steps table via `Arc` to avoid data duplication.
/// For a BSGS 32-bit table, this solver handles values in `[0, 2^16)`.
pub struct NaiveLookup {
    /// Shared reference to the BSGS table.
    /// Uses baby_steps for O(1) lookups.
    table: Arc<BabyStepGiantStepTable>,
}

impl NaiveLookup {
    /// Creates a solver that shares the table with an existing `BabyStepGiantStep`.
    ///
    /// This is the preferred constructor as it shares the ~2.5 MiB table data
    /// via Arc without duplication.
    pub fn from_bsgs(bsgs: &BabyStepGiantStep) -> NaiveLookup {
        NaiveLookup {
            table: bsgs.table(),
        }
    }

    /// Creates a solver from a precomputed BSGS table.
    ///
    /// Note: If you already have a `BabyStepGiantStep` instance, prefer using
    /// `from_bsgs()` to share the table without loading it again.
    ///
    /// # Panics
    /// Panics if the precomputed table is corrupted (should never happen).
    #[cfg(feature = "bsgs_table32")]
    pub fn from_precomputed_table(
        table: crate::bsgs::precomputed_tables::PrecomputedTables,
    ) -> NaiveLookup {
        use crate::bsgs::precomputed_tables;

        let bsgs_bytes = match table {
            precomputed_tables::PrecomputedTables::Bsgs32 => precomputed_tables::BSGS_32,
        };

        let bsgs_table: BabyStepGiantStepTable =
            bincode::deserialize(bsgs_bytes).expect("precomputed table is corrupted");

        NaiveLookup {
            table: Arc::new(bsgs_table),
        }
    }

    /// Returns the maximum number of bits this solver can handle.
    ///
    /// For a BSGS 32-bit table, this returns 16 (the number of baby steps).
    pub fn max_num_bits(&self) -> u8 {
        // BSGS table has m = 2^(max_num_bits/2) baby steps
        // So we can do lookups for max_num_bits/2 bits
        self.table.max_num_bits / 2
    }

    /// Solves the discrete log problem using naive lookup.
    ///
    /// Given y = g^x, finds x where x is in [0, 2^16).
    pub fn solve(&self, y: &RistrettoPoint) -> Result<u64> {
        let compressed = y.compress();

        self.table
            .baby_steps
            .get(&compressed)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("no solution found in range [0, 2^{})", self.max_num_bits()))
    }
}

impl crate::DiscreteLogSolver for NaiveLookup {
    fn new_and_compute_table(max_num_bits: u8) -> Self {
        // Generate a BSGS table for 2*max_num_bits to get max_num_bits baby steps
        let table = BabyStepGiantStepTable::generate(max_num_bits * 2);
        NaiveLookup {
            table: Arc::new(table),
        }
    }

    fn solve(&self, y: &RistrettoPoint) -> Result<u64> {
        NaiveLookup::solve(self, y)
    }

    fn max_num_bits(&self) -> u8 {
        NaiveLookup::max_num_bits(self)
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
    fn naive_from_precomputed_table() {
        use crate::bsgs::precomputed_tables::PrecomputedTables;

        let naive = NaiveLookup::from_precomputed_table(PrecomputedTables::Bsgs32);
        assert_eq!(naive.max_num_bits(), 16);

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

    #[cfg(feature = "bsgs_table32")]
    #[test]
    fn naive_from_bsgs_shares_table() {
        use crate::bsgs::precomputed_tables::PrecomputedTables;

        let bsgs = BabyStepGiantStep::from_precomputed_table(PrecomputedTables::Bsgs32);
        let naive = NaiveLookup::from_bsgs(&bsgs);

        // Verify they share the same Arc (same pointer)
        assert!(Arc::ptr_eq(&bsgs.table, &naive.table));

        // Test solving works
        for i in [0u64, 1, 100, 1000, 65535] {
            let pk = RISTRETTO_BASEPOINT_POINT.mul(crate::utils::u64_to_scalar(i));
            let result = naive.solve(&pk).unwrap();
            assert_eq!(result, i, "failed for i={}", i);
        }
    }
}
