#![allow(non_snake_case)]

//! BSGS-k algorithm: Baby-step Giant-step with batched compression.
//!
//! This variant uses `double_and_compress_batch` to amortize the cost of
//! point compression across K iterations. The table stores doubled baby steps
//! (2*g^j) so that we can use the batched double-and-compress API.

#[cfg(feature = "bsgs_k_presets")]
pub mod presets;

#[cfg(feature = "bsgs_k_presets")]
use crate::bsgs_k::presets::BabyStepGiantStepKPresets;

use anyhow::{Context, Result};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use std::collections::HashMap;
use std::ops::{Add, Mul};
use web_time::{Duration, Instant};

/// Defines generated table values for BSGS-k.
#[cfg_attr(feature = "serde", serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BabyStepGiantStepKTable {
    /// Baby-step lookup table: maps compressed DOUBLED point to its discrete log (j).
    /// Contains compress(2*g^j) for j = 0, 1, ..., m-1 where m = ceil(sqrt(2^secret_size)).
    ///
    /// We store doubled points so we can use `double_and_compress_batch` during solving.
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<(_, _)>"))]
    pub baby_steps: HashMap<CompressedRistretto, u64>,

    /// Precomputed giant step: g^(-m) used to compute h * (g^(-m))^i.
    pub giant_step: RistrettoPoint,
}

/// Defines constants based on which the BSGS-k algorithm runs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BabyStepGiantStepKParameters {
    /// Size of a secret to look for (in bits).
    pub secret_size: u8,
    /// m = ceil(sqrt(2^secret_size)), the number of baby steps.
    pub m: u64,
}

/// BSGS-k algorithm for solving discrete logarithms with compile-time batch size K.
///
/// Uses `double_and_compress_batch` to amortize compression cost across
/// K iterations.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BabyStepGiantStepK<const K: usize> {
    pub parameters: BabyStepGiantStepKParameters,
    pub table: BabyStepGiantStepKTable,
}

impl<const K: usize> BabyStepGiantStepK<K> {
    /// Creates a new BSGS-k solver with the given parameters.
    pub fn from_parameters(parameters: BabyStepGiantStepKParameters) -> Result<Self> {
        let table =
            BabyStepGiantStepKTable::generate(&parameters).context("failed to generate table")?;

        Ok(Self { parameters, table })
    }

    #[cfg(feature = "bsgs_k_presets")]
    pub fn from_preset(preset: BabyStepGiantStepKPresets) -> Result<Self> {
        let bsgs_bytes = match preset {
            #[cfg(feature = "bsgs_k_table32")]
            BabyStepGiantStepKPresets::BabyStepGiantStep32 => presets::BSGS_K_32,
        };

        let bsgs: Self = bincode::deserialize(bsgs_bytes).context("failed to deserialize table")?;

        Ok(bsgs)
    }

    /// Solves the discrete logarithm problem using BSGS-k.
    ///
    /// Given pk = g^x, finds x where x is in [0, 2^secret_size).
    ///
    /// The const generic parameter `K` controls the batch size: we accumulate K points
    /// before calling `double_and_compress_batch`. Larger K amortizes the compression
    /// cost better but uses more memory and may do extra work if the answer
    /// is found mid-batch.
    ///
    /// Algorithm:
    /// 1. Accumulate K points: gamma_0, gamma_1, ..., gamma_{K-1}
    ///    where gamma_i = pk * (g^(-m))^(batch_start + i)
    /// 2. Call double_and_compress_batch on all K points
    /// 3. Check each compressed point against the table of doubled baby steps
    /// 4. If found at position i with value j, then x = (batch_start + i) * m + j
    pub fn solve_dlp(&self, pk: &RistrettoPoint, max_time: Option<u64>) -> Result<Option<u64>> {
        if pk.eq(&RistrettoPoint::identity()) {
            return Ok(Some(0));
        }

        let start_time = max_time.map(|_| Instant::now());
        let m = self.parameters.m;

        // gamma starts as pk, then we multiply by g^(-m) each iteration
        let mut gamma = *pk;

        // Process in batches of K
        let mut batch_start: u64 = 0;

        while batch_start < m {
            if let Some(max_time) = max_time {
                if start_time.unwrap().elapsed() >= Duration::from_millis(max_time) {
                    return Ok(None);
                }
            }

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

impl BabyStepGiantStepKTable {
    /// Generates the BSGS-k table with DOUBLED baby steps.
    ///
    /// Baby step: Compute 2*g^j for j = 0, 1, ..., m-1 and store compressed in a hash table.
    /// We store doubled points so we can use `double_and_compress_batch` during solving.
    /// Also precompute g^(-m) for the giant step phase.
    pub fn generate(parameters: &BabyStepGiantStepKParameters) -> Result<BabyStepGiantStepKTable> {
        if parameters.secret_size < 1 || parameters.secret_size > 64 {
            return Err(anyhow::anyhow!("secret size must be between 1 and 64"));
        }

        let m = parameters.m;
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

        // Build the lookup table: compressed(2*g^j) -> j
        let mut baby_steps = HashMap::with_capacity(m as usize);
        for (j, compressed) in doubled_compressed.into_iter().enumerate() {
            baby_steps.insert(compressed, j as u64);
        }

        // Compute g^(-m) for giant steps
        // -m mod group_order
        let m_scalar = Scalar::from(m);
        let neg_m = -m_scalar;
        let giant_step = g.mul(neg_m);

        Ok(BabyStepGiantStepKTable {
            baby_steps,
            giant_step,
        })
    }
}

impl<const K: usize> crate::DlogSolver for BabyStepGiantStepK<K> {
    fn new_and_compute_table(max_num_bits: u8) -> Result<Self> {
        if max_num_bits < 1 || max_num_bits > 64 {
            return Err(anyhow::anyhow!("max_num_bits must be between 1 and 64"));
        }

        // m = ceil(sqrt(2^max_num_bits)) = 2^(ceil(max_num_bits/2))
        let m: u64 = 1 << ((max_num_bits + 1) / 2);

        let parameters = BabyStepGiantStepKParameters {
            secret_size: max_num_bits,
            m,
        };
        Self::from_parameters(parameters)
    }

    fn solve(&self, pk: &RistrettoPoint) -> Result<Option<u64>> {
        self.solve_dlp(pk, None)
    }

    fn max_num_bits(&self) -> u8 {
        self.parameters.secret_size
    }
}
