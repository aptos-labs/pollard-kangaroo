use super::BabyStepGiantStep;
use crate::utils;

use anyhow::Result;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use std::ops::Add;
use web_time::{Duration, Instant};

impl BabyStepGiantStep {
    /// Solves the discrete logarithm problem using Baby-step Giant-step.
    ///
    /// Given pk = g^x, finds x where x is in [0, 2^secret_size).
    ///
    /// Algorithm:
    /// 1. For i = 0, 1, ..., m-1:
    ///    - Compute gamma = pk * (g^(-m))^i
    ///    - If gamma is in baby_steps table with value j, then x = i*m + j
    pub fn solve_dlp(&self, pk: &RistrettoPoint, max_time: Option<u64>) -> Result<Option<u64>> {
        if pk.eq(&RistrettoPoint::identity()) {
            return Ok(Some(0));
        }

        let start_time = max_time.map(|_| Instant::now());
        let m = self.parameters.m;

        // gamma starts as pk, then we multiply by g^(-m) each iteration
        let mut gamma = *pk;

        for i in 0..m {
            if let Some(max_time) = max_time {
                if start_time.unwrap().elapsed() >= Duration::from_millis(max_time) {
                    return Ok(None);
                }
            }

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

                return Ok(Some(x));
            }

            // gamma = gamma * g^(-m)
            gamma = gamma.add(self.table.giant_step);
        }

        // No solution found in the range [0, m^2)
        Ok(None)
    }
}
