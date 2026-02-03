#![allow(non_snake_case)]

//! TBSGS-k algorithm: Truncated Baby-step Giant-step with batched compression.
//!
//! This variant stores only 8-byte truncated keys instead of full 32-byte
//! CompressedRistretto points, reducing table size from ~2 MB to ~512 KB.
//!
//! On match, the algorithm verifies by computing the expected point, ensuring
//! correctness despite the truncation. False positive rate is ~1 per 4 billion
//! solves with 8-byte keys.
//!
//! Like BSGS-k, this uses `double_and_compress_batch` to amortize the cost of
//! point compression across K iterations.

#[cfg(feature = "tbsgs_k_table32")]
pub mod precomputed_tables;

#[cfg(feature = "tbsgs_k_table32")]
use crate::tbsgs_k::precomputed_tables::PrecomputedTables;

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

/// Extracts the first 8 bytes of a CompressedRistretto as a u64.
#[inline]
fn truncate_key(compressed: &CompressedRistretto) -> u64 {
    let bytes = compressed.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Defines generated table values for TBSGS-k.
pub struct TruncatedBabyStepGiantStepKTable {
    /// Size of a secret to look for (in bits).
    pub max_num_bits: u8,

    /// m = ceil(sqrt(2^max_num_bits)), the number of baby steps.
    pub m: u64,

    /// Baby-step lookup table: maps truncated key (first 8 bytes of compress(2*g^j))
    /// to its discrete log (j).
    ///
    /// Values are u16 since j < m <= 65536 for max_num_bits <= 32.
    pub baby_steps: HashMap<u64, u16>,

    /// Precomputed giant step: g^(-m) used to compute h * (g^(-m))^i.
    pub giant_step: RistrettoPoint,
}

/// Compact serialization format for TBSGS-k table.
/// Truncated keys are stored in order by discrete log (truncated_keys[j] = first 8 bytes of compress(2*g^j)),
/// so values are implicit and don't need to be stored.
#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
struct TruncatedBabyStepGiantStepKTableSerialized {
    max_num_bits: u8,
    m: u64,
    /// Truncated keys stored in order: truncated_keys[j] = first 8 bytes of compress(2*g^j)
    truncated_keys: Vec<u64>,
    giant_step: RistrettoPoint,
}

#[cfg(feature = "serde")]
impl TruncatedBabyStepGiantStepKTable {
    /// Deserialize from compact format, rebuilding the HashMap.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        let serialized: TruncatedBabyStepGiantStepKTableSerialized = bincode::deserialize(bytes)?;

        // Rebuild HashMap with implicit indices as values
        let mut baby_steps = HashMap::with_capacity(serialized.truncated_keys.len());
        for (j, &key) in serialized.truncated_keys.iter().enumerate() {
            baby_steps.insert(key, j as u16);
        }

        Ok(TruncatedBabyStepGiantStepKTable {
            max_num_bits: serialized.max_num_bits,
            m: serialized.m,
            baby_steps,
            giant_step: serialized.giant_step,
        })
    }

    /// Serialize to compact format (truncated keys only, no values).
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        // Convert HashMap to sorted Vec (sorted by value = discrete log)
        let mut entries: Vec<(u16, u64)> = self.baby_steps.iter().map(|(&k, &v)| (v, k)).collect();
        entries.sort_by_key(|(v, _)| *v);
        let truncated_keys: Vec<u64> = entries.into_iter().map(|(_, k)| k).collect();

        let serialized = TruncatedBabyStepGiantStepKTableSerialized {
            max_num_bits: self.max_num_bits,
            m: self.m,
            truncated_keys,
            giant_step: self.giant_step,
        };

        bincode::serialize(&serialized)
    }
}

/// TBSGS-k algorithm for solving discrete logarithms with compile-time batch size K.
///
/// Uses `double_and_compress_batch` to amortize compression cost across
/// K iterations. Stores only 8-byte truncated keys to reduce table size.
///
/// The table is wrapped in `Arc` for potential sharing.
pub struct TruncatedBabyStepGiantStepK<const K: usize> {
    pub table: Arc<TruncatedBabyStepGiantStepKTable>,
}

impl<const K: usize> TruncatedBabyStepGiantStepK<K> {
    /// Creates a solver from a precomputed table.
    ///
    /// # Panics
    /// Panics if the precomputed table is corrupted (should never happen).
    #[cfg(feature = "tbsgs_k_table32")]
    pub fn from_precomputed_table(table: PrecomputedTables) -> Self {
        let tbsgs_bytes = match table {
            #[cfg(feature = "tbsgs_k_table32")]
            PrecomputedTables::TbsgsK32 => precomputed_tables::TBSGS_K_32,
        };

        let table = TruncatedBabyStepGiantStepKTable::from_bytes(tbsgs_bytes)
            .expect("precomputed table is corrupted");
        Self {
            table: Arc::new(table),
        }
    }

    /// Returns a clone of the Arc-wrapped table.
    pub fn table(&self) -> Arc<TruncatedBabyStepGiantStepKTable> {
        Arc::clone(&self.table)
    }

    /// Solves the discrete log problem using TBSGS-k.
    ///
    /// Given pk = g^x, finds x where x is in [0, 2^max_num_bits).
    ///
    /// Algorithm:
    /// 1. Accumulate K points and double-and-compress them
    /// 2. Extract 8-byte truncated key from each compressed point
    /// 3. Look up in HashMap
    /// 4. On match: verify by comparing uncompressed points
    /// 5. If verified, return; else continue (false positive)
    pub fn solve(&self, pk: &RistrettoPoint) -> Result<u64> {
        if pk.eq(&RistrettoPoint::identity()) {
            return Ok(0);
        }

        let m = self.table.m;
        let g = RISTRETTO_BASEPOINT_POINT;

        // gamma starts as pk, then we multiply by g^(-m) each iteration
        let mut gamma = *pk;

        // Process in batches of K
        let mut batch_start: u64 = 0;

        while batch_start < m {
            // Determine actual batch size (may be smaller for last batch)
            let remaining = (m - batch_start) as usize;
            let batch_size = K.min(remaining);

            // Accumulate batch_size points
            let mut batch_points = Vec::with_capacity(batch_size);
            let mut current_gamma = gamma;

            for _ in 0..batch_size {
                batch_points.push(current_gamma);
                current_gamma = current_gamma.add(self.table.giant_step);
            }

            // Double and compress all points in the batch
            let compressed_batch = RistrettoPoint::double_and_compress_batch(&batch_points);

            // Check each compressed point against the table
            for (i, compressed) in compressed_batch.iter().enumerate() {
                let truncated = truncate_key(compressed);

                if let Some(&j) = self.table.baby_steps.get(&truncated) {
                    // Verify: compare uncompressed points directly (faster than compressing)
                    let expected_point = g.mul(Scalar::from(j as u64));
                    if batch_points[i] == expected_point {
                        let x = (batch_start + i as u64) * m + j as u64;

                        // Verify the result (optional but good for debugging)
                        debug_assert!({
                            let computed = g * crate::utils::u64_to_scalar(x);
                            computed.eq(pk)
                        });

                        return Ok(x);
                    }
                    // else: false positive, continue searching
                }
            }

            // Move to next batch
            gamma = current_gamma;
            batch_start += batch_size as u64;
        }

        // No solution found in the range [0, m^2)
        Err(anyhow::anyhow!(
            "no solution found in range [0, 2^{})",
            self.table.max_num_bits
        ))
    }
}

impl TruncatedBabyStepGiantStepKTable {
    /// Generates the TBSGS-k table with truncated keys.
    ///
    /// Baby step: Compute truncated key of compress(2*g^j) for j = 0, 1, ..., m-1.
    /// Also precompute g^(-m) for the giant step phase.
    ///
    /// # Panics
    /// Panics if two j values produce the same truncated key (probability ~2^-33).
    pub fn generate(max_num_bits: u8) -> TruncatedBabyStepGiantStepKTable {
        assert!(
            max_num_bits >= 1 && max_num_bits <= 32,
            "max_num_bits must be between 1 and 32, got {} (u16 values require m <= 65536)",
            max_num_bits
        );

        // m = ceil(sqrt(2^max_num_bits)) = 2^(ceil(max_num_bits/2))
        let m: u64 = 1 << ((max_num_bits + 1) / 2);
        let g = RISTRETTO_BASEPOINT_POINT;

        // Baby steps: compute g^0, g^1, g^2, ..., g^(m-1)
        let mut points = Vec::with_capacity(m as usize);
        let mut current = RistrettoPoint::default(); // identity = g^0

        for _ in 0..m {
            points.push(current);
            current = current + g;
        }

        // Double and compress all points in a batch
        let doubled_compressed = RistrettoPoint::double_and_compress_batch(&points);

        // Build the lookup table: truncated_key(compress(2*g^j)) -> j
        let mut baby_steps = HashMap::with_capacity(m as usize);
        for (j, compressed) in doubled_compressed.into_iter().enumerate() {
            let truncated = truncate_key(&compressed);

            // Check for collisions (extremely unlikely but check anyway)
            if let Some(&existing_j) = baby_steps.get(&truncated) {
                panic!(
                    "Truncated key collision detected: j={} and j={} both map to {:016x}. \
                     This is extremely unlikely (probability ~2^-33). Try regenerating the table.",
                    existing_j, j, truncated
                );
            }

            baby_steps.insert(truncated, j as u16);
        }

        // Compute g^(-m) for giant steps
        let m_scalar = Scalar::from(m);
        let neg_m = -m_scalar;
        let giant_step = g.mul(neg_m);

        TruncatedBabyStepGiantStepKTable {
            max_num_bits,
            m,
            baby_steps,
            giant_step,
        }
    }
}

impl<const K: usize> crate::DiscreteLogSolver for TruncatedBabyStepGiantStepK<K> {
    fn algorithm_name() -> &'static str {
        match K {
            1 => "TBSGS-k1",
            2 => "TBSGS-k2",
            4 => "TBSGS-k4",
            8 => "TBSGS-k8",
            16 => "TBSGS-k16",
            32 => "TBSGS-k32",
            64 => "TBSGS-k64",
            128 => "TBSGS-k128",
            256 => "TBSGS-k256",
            512 => "TBSGS-k512",
            1024 => "TBSGS-k1024",
            2048 => "TBSGS-k2048",
            4096 => "TBSGS-k4096",
            8192 => "TBSGS-k8192",
            16384 => "TBSGS-k16384",
            _ => "TBSGS-k?",
        }
    }

    fn new_and_compute_table(max_num_bits: u8) -> Self {
        let table = TruncatedBabyStepGiantStepKTable::generate(max_num_bits);
        Self {
            table: Arc::new(table),
        }
    }

    fn from_precomputed_table(max_num_bits: u8) -> Self {
        #[cfg(feature = "tbsgs_k_table32")]
        if max_num_bits == 32 {
            return TruncatedBabyStepGiantStepK::from_precomputed_table(
                PrecomputedTables::TbsgsK32,
            );
        }

        panic!(
            "No precomputed TBSGS-k table available for {} bits. \
             Available: 32 bits (requires 'tbsgs_k_table32' feature).",
            max_num_bits
        );
    }

    fn solve(&self, pk: &RistrettoPoint) -> Result<u64> {
        TruncatedBabyStepGiantStepK::solve(self, pk)
    }

    fn max_num_bits(&self) -> u8 {
        self.table.max_num_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DiscreteLogSolver;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use std::ops::Mul;

    #[test]
    fn tbsgs_k_handles_small_values() {
        let tbsgs = TruncatedBabyStepGiantStepK::<32>::new_and_compute_table(16);

        for i in [0u64, 1, 2, 100, 1000, 65535] {
            let pk = RISTRETTO_BASEPOINT_POINT.mul(Scalar::from(i));
            let result = tbsgs.solve(&pk).unwrap();
            assert_eq!(result, i, "Failed for i={}", i);
        }
    }

    #[test]
    fn tbsgs_k_handles_identity_point() {
        let tbsgs = TruncatedBabyStepGiantStepK::<32>::new_and_compute_table(16);

        let identity = RistrettoPoint::identity();
        let result = tbsgs.solve(&identity).unwrap();
        assert_eq!(result, 0);
    }

    /// Test TBSGS-k with secrets that are multiples of m.
    #[test]
    fn tbsgs_k_handles_multiples_of_m() {
        let tbsgs = TruncatedBabyStepGiantStepK::<32>::new_and_compute_table(16);
        let m: u64 = 256; // m = 2^8 for 16-bit table

        let test_values = [
            0u64,
            m,
            2 * m,
            3 * m,
            m + 1,
            m - 1,
            2 * m + 100,
            65535, // max for 16-bit
        ];

        for &secret in &test_values {
            let pk = RISTRETTO_BASEPOINT_POINT.mul(Scalar::from(secret));
            let result = tbsgs.solve(&pk).unwrap();
            assert_eq!(result, secret, "Failed for secret={}", secret);
        }
    }

    #[cfg(feature = "tbsgs_k_table32")]
    #[test]
    fn tbsgs_k32_solves_32_bit() {
        let tbsgs = TruncatedBabyStepGiantStepK::<32>::from_precomputed_table(
            precomputed_tables::PrecomputedTables::TbsgsK32,
        );

        // Test a range of values
        let test_values = [
            0u64,
            1,
            100,
            1000,
            65535,
            65536,
            100000,
            1000000,
            (1u64 << 32) - 1, // max 32-bit value
        ];

        for &secret in &test_values {
            let pk = RISTRETTO_BASEPOINT_POINT.mul(Scalar::from(secret));
            let result = tbsgs.solve(&pk).unwrap();
            assert_eq!(result, secret, "Failed for secret={}", secret);
        }
    }
}
