//! Naive truncated doubled lookup algorithm for solving discrete logarithms.
//!
//! This algorithm reuses the TBSGS-k truncated baby-step tables to perform
//! near-constant-time lookups for values up to half the TBSGS-k table's max_num_bits.
//!
//! The TBSGS-k tables store `truncate(compress(2*g^j))` for `j ∈ [0, m)` where `m = 2^(max_num_bits/2)`.
//! For a 32-bit TBSGS-k table, `m = 2^16`, so we can solve 16-bit DLs in O(1) time.
//!
//! Algorithm:
//! 1. Given `y = g^x` where `x ∈ [0, 2^16)`
//! 2. Double and compress: `compress(2*y) = compress(2*g^x)`
//! 3. Truncate to 8 bytes and look up in the TBSGS-k baby_steps table
//! 4. On match, verify by comparing uncompressed points
//!
//! - Table size: Reuses TBSGS-k table (no additional storage) - only ~512 KiB!
//! - Solve time: O(1) (single doubling + compression + truncation + hash lookup + verification)

use crate::tbsgs_k::TruncatedBabyStepGiantStepKTable;
use anyhow::Result;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use std::ops::Mul;
use std::sync::Arc;

#[cfg(feature = "tbsgs_k_table32")]
use crate::tbsgs_k::precomputed_tables::PrecomputedTables;

/// Extracts the first 8 bytes of a CompressedRistretto as a u64.
#[inline]
fn truncate_key(compressed: &curve25519_dalek::ristretto::CompressedRistretto) -> u64 {
    let bytes = compressed.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Naive truncated doubled lookup solver that reuses TBSGS-k tables for O(1) lookups.
///
/// For a TBSGS-k table with `max_num_bits = N`, this solver can find discrete logs
/// for values in `[0, 2^(N/2))` in constant time.
///
/// The table is wrapped in `Arc` to allow sharing with `TruncatedBabyStepGiantStepK`
/// without duplicating the ~512 KiB precomputed data.
pub struct NaiveTruncatedDoubledLookup {
    /// Shared reference to the TBSGS-k table.
    /// The table stores `truncate(compress(2*g^j))` for `j ∈ [0, m)`.
    pub table: Arc<TruncatedBabyStepGiantStepKTable>,
}

impl NaiveTruncatedDoubledLookup {
    /// Creates a solver that shares the table with an existing `TruncatedBabyStepGiantStepK`.
    ///
    /// This is the preferred constructor when you already have a `TruncatedBabyStepGiantStepK`
    /// instance, as it avoids duplicating the ~512 KiB table data.
    pub fn from_tbsgs_k<const K: usize>(
        tbsgs_k: &crate::tbsgs_k::TruncatedBabyStepGiantStepK<K>,
    ) -> NaiveTruncatedDoubledLookup {
        NaiveTruncatedDoubledLookup {
            table: tbsgs_k.table(),
        }
    }

    /// Creates a solver from a precomputed TBSGS-k table.
    ///
    /// Note: If you already have a `TruncatedBabyStepGiantStepK` instance, prefer using
    /// `from_tbsgs_k()` to share the table without duplication.
    ///
    /// # Panics
    /// Panics if the precomputed table is corrupted (should never happen).
    #[cfg(feature = "tbsgs_k_table32")]
    pub fn from_precomputed_table(table: PrecomputedTables) -> NaiveTruncatedDoubledLookup {
        use crate::tbsgs_k::precomputed_tables;

        let tbsgs_bytes = match table {
            #[cfg(feature = "tbsgs_k_table32")]
            PrecomputedTables::TbsgsK32 => precomputed_tables::TBSGS_K_32,
        };

        let tbsgs_k_table = TruncatedBabyStepGiantStepKTable::from_bytes(tbsgs_bytes)
            .expect("precomputed table is corrupted");

        NaiveTruncatedDoubledLookup {
            table: Arc::new(tbsgs_k_table),
        }
    }

    /// Returns the maximum number of bits this solver can handle.
    ///
    /// For a TBSGS-k table with `max_num_bits = N`, this returns `N/2`.
    pub fn max_num_bits(&self) -> u8 {
        self.table.max_num_bits / 2
    }

    /// Solves the discrete log problem using naive truncated doubled lookup.
    ///
    /// Given `y = g^x`, finds `x` where `x` is in `[0, 2^(max_num_bits/2))`.
    ///
    /// This is O(1): one point doubling, one compression, one truncation,
    /// one hash lookup, and one verification (scalar mul + point comparison).
    pub fn solve(&self, y: &RistrettoPoint) -> Result<u64> {
        // Double the point: 2*y = 2*g^x
        let doubled = y + y;

        // Compress and truncate
        let compressed = doubled.compress();
        let truncated = truncate_key(&compressed);

        // Look up in the table
        if let Some(&j) = self.table.baby_steps.get(&truncated) {
            // Verify: compare uncompressed points directly
            let expected_point = RISTRETTO_BASEPOINT_POINT.mul(Scalar::from(j as u64));
            if *y == expected_point {
                return Ok(j as u64);
            }
            // False positive (extremely unlikely with 8-byte keys)
        }

        Err(anyhow::anyhow!(
            "no solution found in range [0, 2^{})",
            self.max_num_bits()
        ))
    }
}

impl crate::DiscreteLogSolver for NaiveTruncatedDoubledLookup {
    fn algorithm_name() -> &'static str {
        "NaiveTruncatedDoubledLookup"
    }

    fn new_and_compute_table(max_num_bits: u8) -> Self {
        // Generate a TBSGS-k table for 2*max_num_bits to support max_num_bits lookups
        let table = TruncatedBabyStepGiantStepKTable::generate(max_num_bits * 2);
        NaiveTruncatedDoubledLookup {
            table: Arc::new(table),
        }
    }

    fn from_precomputed_table(max_num_bits: u8) -> Self {
        // NaiveTruncatedDoubledLookup uses TBSGS-k tables, so for 16-bit lookups we need 32-bit TBSGS-k table
        #[cfg(feature = "tbsgs_k_table32")]
        if max_num_bits == 16 {
            return NaiveTruncatedDoubledLookup::from_precomputed_table(
                PrecomputedTables::TbsgsK32,
            );
        }

        panic!(
            "No precomputed NaiveTruncatedDoubledLookup table available for {} bits. \
             Available: 16 bits (requires 'tbsgs_k_table32' feature, uses TBSGS-k 32-bit table).",
            max_num_bits
        );
    }

    fn solve(&self, y: &RistrettoPoint) -> Result<u64> {
        NaiveTruncatedDoubledLookup::solve(self, y)
    }

    fn max_num_bits(&self) -> u8 {
        NaiveTruncatedDoubledLookup::max_num_bits(self)
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
    fn naive_truncated_doubled_handles_identity_point() {
        // Generate a table for 8-bit lookups (needs 16-bit TBSGS-k table)
        let solver = NaiveTruncatedDoubledLookup::new_and_compute_table(8);
        assert_eq!(solver.max_num_bits(), 8);

        // 0*G = identity
        let identity = RistrettoPoint::identity();
        let result = solver.solve(&identity).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn naive_truncated_doubled_handles_generator() {
        let solver = NaiveTruncatedDoubledLookup::new_and_compute_table(8);

        // 1*G = generator
        let result = solver.solve(&RISTRETTO_BASEPOINT_POINT).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn naive_truncated_doubled_handles_small_values() {
        let solver = NaiveTruncatedDoubledLookup::new_and_compute_table(8);

        for i in 0..=255u64 {
            let pk = RISTRETTO_BASEPOINT_POINT.mul(crate::utils::u64_to_scalar(i));
            let result = solver.solve(&pk).unwrap();
            assert_eq!(result, i, "failed for i={}", i);
        }
    }

    #[cfg(feature = "tbsgs_k_table32")]
    #[test]
    fn naive_truncated_doubled_with_precomputed_table() {
        use crate::tbsgs_k::precomputed_tables::PrecomputedTables;

        let solver =
            NaiveTruncatedDoubledLookup::from_precomputed_table(PrecomputedTables::TbsgsK32);
        assert_eq!(solver.max_num_bits(), 16);

        // Test a few values
        for i in [0u64, 1, 100, 1000, 65535] {
            let pk = RISTRETTO_BASEPOINT_POINT.mul(crate::utils::u64_to_scalar(i));
            let result = solver.solve(&pk).unwrap();
            assert_eq!(result, i, "failed for i={}", i);
        }
    }

    #[cfg(feature = "tbsgs_k_table32")]
    #[test]
    fn naive_truncated_doubled_fails_for_out_of_range() {
        use crate::tbsgs_k::precomputed_tables::PrecomputedTables;

        let solver =
            NaiveTruncatedDoubledLookup::from_precomputed_table(PrecomputedTables::TbsgsK32);

        // 65536 is out of range for 16-bit
        let pk = RISTRETTO_BASEPOINT_POINT.mul(crate::utils::u64_to_scalar(65536));
        let result = solver.solve(&pk);
        assert!(result.is_err());
    }

    #[cfg(feature = "tbsgs_k_table32")]
    #[test]
    fn naive_truncated_doubled_from_tbsgs_k_shares_table() {
        use crate::tbsgs_k::precomputed_tables::PrecomputedTables;
        use crate::tbsgs_k::TruncatedBabyStepGiantStepK;

        let tbsgs_k =
            TruncatedBabyStepGiantStepK::<32>::from_precomputed_table(PrecomputedTables::TbsgsK32);
        let naive = NaiveTruncatedDoubledLookup::from_tbsgs_k(&tbsgs_k);

        // Verify they share the same Arc (same pointer)
        assert!(Arc::ptr_eq(&tbsgs_k.table, &naive.table));

        // Test solving works
        for i in [0u64, 1, 100, 1000, 65535] {
            let pk = RISTRETTO_BASEPOINT_POINT.mul(crate::utils::u64_to_scalar(i));
            let result = naive.solve(&pk).unwrap();
            assert_eq!(result, i, "failed for i={}", i);
        }
    }
}
