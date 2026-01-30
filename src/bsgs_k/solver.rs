use super::BabyGiantK;

use anyhow::Result;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use std::ops::Add;
use web_time::{Duration, Instant};

impl BabyGiantK {
    /// Solves the discrete logarithm problem using BSGS-k.
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
                if let Some(&j) = self.table.baby_steps.get(compressed) {
                    let x = (batch_start + i as u64) * m + j;

                    // Verify the result (optional but good for debugging)
                    debug_assert!({
                        let computed = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
                            * crate::utils::u64_to_scalar(x);
                        computed.eq(pk)
                    });

                    return Ok(Some(x));
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
