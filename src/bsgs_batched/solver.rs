use crate::bsgs_batched::BabyGiantBatched;

use anyhow::Result;
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::traits::Identity;
use std::ops::Add;
use web_time::{Duration, Instant};

impl BabyGiantBatched {
    /// Solves the discrete logarithm problem using batched Baby-step Giant-step.
    ///
    /// Given pk = g^x, finds x where x is in [0, 2^secret_size).
    ///
    /// The parameter `k` controls the batch size: we accumulate k points before
    /// calling `double_and_compress_batch`. Larger k amortizes the compression
    /// cost better but uses more memory and may do extra work if the answer
    /// is found mid-batch.
    ///
    /// Algorithm:
    /// 1. Accumulate k points: gamma_0, gamma_1, ..., gamma_{k-1}
    ///    where gamma_i = pk * (g^(-m))^(batch_start + i)
    /// 2. Call double_and_compress_batch on all k points
    /// 3. Check each compressed point against the table of doubled baby steps
    /// 4. If found at position i with value j, then x = (batch_start + i) * m + j
    pub fn solve_dlp(
        &self,
        pk: &RistrettoPoint,
        k: usize,
        max_time: Option<u64>,
    ) -> Result<Option<u64>> {
        if pk.eq(&RistrettoPoint::identity()) {
            return Ok(Some(0));
        }

        let start_time = max_time.map(|_| Instant::now());
        let m = self.parameters.m;

        // gamma starts as pk, then we multiply by g^(-m) each iteration
        let mut gamma = *pk;

        // Process in batches of k
        let mut batch_start: u64 = 0;

        while batch_start < m {
            if let Some(max_time) = max_time {
                if start_time.unwrap().elapsed() >= Duration::from_millis(max_time) {
                    return Ok(None);
                }
            }

            // Determine actual batch size (may be smaller for last batch)
            let remaining = (m - batch_start) as usize;
            let batch_size = k.min(remaining);

            // Accumulate batch_size points, tracking which indices have identity
            let mut batch_points = Vec::with_capacity(batch_size);
            let mut identity_indices = Vec::new();
            let mut current_gamma = gamma;

            for i in 0..batch_size {
                if current_gamma.eq(&RistrettoPoint::identity()) {
                    // Track identity points - they can't go through double_and_compress_batch
                    identity_indices.push(i);
                } else {
                    batch_points.push((i, current_gamma));
                }
                current_gamma = current_gamma.add(self.table.giant_step);
            }

            // Handle identity points first (2*identity = identity)
            let identity_compressed = CompressedRistretto::identity();
            for i in &identity_indices {
                if let Some(&j) = self.table.baby_steps.get(&identity_compressed) {
                    let x = (batch_start + *i as u64) * m + j;
                    return Ok(Some(x));
                }
            }

            // Double and compress non-identity points in the batch
            if !batch_points.is_empty() {
                let points_only: Vec<_> = batch_points.iter().map(|(_, p)| *p).collect();
                let compressed_batch = RistrettoPoint::double_and_compress_batch(&points_only);

                // Check each compressed point against the table
                for ((i, _), compressed) in batch_points.iter().zip(compressed_batch.iter()) {
                    if let Some(&j) = self.table.baby_steps.get(compressed) {
                        let x = (batch_start + *i as u64) * m + j;

                        // Verify the result (optional but good for debugging)
                        debug_assert!({
                            let computed = curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT
                                * crate::utils::u64_to_scalar(x);
                            computed.eq(pk)
                        });

                        return Ok(Some(x));
                    }
                }
            }

            // Move to next batch
            gamma = current_gamma;
            batch_start += batch_size as u64;
        }

        // No solution found in the range [0, m^2)
        Ok(None)
    }
}
