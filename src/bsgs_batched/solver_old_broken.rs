//! Old broken solver that panics on identity points.
//! This is kept for testing purposes to confirm the fix works.

use crate::bsgs_batched::BabyGiantBatched;

use anyhow::Result;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::traits::Identity;
use std::ops::Add;

impl BabyGiantBatched {
    /// OLD BROKEN VERSION - panics if gamma hits identity point.
    ///
    /// This happens when secret = m * i for some i, because:
    ///   gamma = g^(secret) * (g^(-m))^i = g^(m*i - m*i) = g^0 = identity
    #[allow(dead_code)]
    pub fn solve_dlp_old_broken(&self, pk: &RistrettoPoint, k: usize) -> Result<Option<u64>> {
        if pk.eq(&RistrettoPoint::identity()) {
            return Ok(Some(0));
        }

        let m = self.parameters.m;
        let mut gamma = *pk;
        let mut batch_start: u64 = 0;

        while batch_start < m {
            let remaining = (m - batch_start) as usize;
            let batch_size = k.min(remaining);

            // OLD BROKEN CODE: doesn't check for identity points
            let mut batch_points = Vec::with_capacity(batch_size);
            let mut current_gamma = gamma;

            for _ in 0..batch_size {
                batch_points.push(current_gamma); // BUG: includes identity points!
                current_gamma = current_gamma.add(self.table.giant_step);
            }

            // This will PANIC if any point in batch_points is identity!
            let compressed_batch = RistrettoPoint::double_and_compress_batch(&batch_points);

            for (i, compressed) in compressed_batch.iter().enumerate() {
                if let Some(&j) = self.table.baby_steps.get(compressed) {
                    let x = (batch_start + i as u64) * m + j;
                    return Ok(Some(x));
                }
            }

            gamma = current_gamma;
            batch_start += batch_size as u64;
        }

        Ok(None)
    }
}
