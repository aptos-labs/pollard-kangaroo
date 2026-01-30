#![allow(non_snake_case)]

//! Baby-step Giant-step algorithm for solving discrete logarithms.

#[cfg(feature = "bsgs_presets")]
pub mod presets;

#[cfg(feature = "bsgs_presets")]
use crate::bsgs::presets::BabyStepGiantStepPresets;
use crate::utils;

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

/// Baby-step Giant-step algorithm for solving discrete logarithms.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BabyStepGiantStep {
    pub parameters: BabyStepGiantStepParameters,
    pub table: BabyStepGiantStepTable,
}

/// Defines generated table values for BSGS.
#[cfg_attr(feature = "serde", serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BabyStepGiantStepTable {
    /// Baby-step lookup table: maps compressed point to its discrete log (j).
    /// Contains g^j for j = 0, 1, ..., m-1 where m = ceil(sqrt(2^secret_size)).
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<(_, _)>"))]
    pub baby_steps: HashMap<CompressedRistretto, u64>,

    /// Precomputed giant step: g^(-m) used to compute h * (g^(-m))^i.
    pub giant_step: RistrettoPoint,

    /// The scalar -m (mod group order).
    /// TODO: is this even used? if not, remove it. (same for the BSGS-k algorithm)
    pub neg_m: Scalar,
}

/// Defines constants based on which the BSGS algorithm runs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BabyStepGiantStepParameters {
    /// Size of a secret to look for (in bits).
    pub secret_size: u8,
    /// m = ceil(sqrt(2^secret_size)), the number of baby steps.
    pub m: u64,
}

impl BabyStepGiantStep {
    pub fn from_parameters(parameters: BabyStepGiantStepParameters) -> Result<BabyStepGiantStep> {
        let table =
            BabyStepGiantStepTable::generate(&parameters).context("failed to generate table")?;

        Ok(BabyStepGiantStep { parameters, table })
    }

    #[cfg(feature = "bsgs_presets")]
    pub fn from_preset(preset: BabyStepGiantStepPresets) -> Result<BabyStepGiantStep> {
        let bsgs_bytes = match preset {
            #[cfg(feature = "bsgs_table32")]
            BabyStepGiantStepPresets::BabyStepGiantStep32 => presets::BSGS_32,
        };

        let bsgs: BabyStepGiantStep =
            bincode::deserialize(bsgs_bytes).context("failed to deserialize table")?;

        Ok(bsgs)
    }

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

impl BabyStepGiantStepTable {
    /// Generates the BSGS table with baby steps.
    ///
    /// Baby step: Compute g^j for j = 0, 1, ..., m-1 and store in a hash table.
    /// Also precompute g^(-m) for the giant step phase.
    pub fn generate(parameters: &BabyStepGiantStepParameters) -> Result<BabyStepGiantStepTable> {
        if parameters.secret_size < 1 || parameters.secret_size > 64 {
            return Err(anyhow::anyhow!("secret size must be between 1 and 64"));
        }

        let m = parameters.m;

        // Baby steps: compute g^0, g^1, ..., g^(m-1)
        let mut baby_steps = HashMap::with_capacity(m as usize);
        let mut current = RistrettoPoint::default(); // identity
        let g = RISTRETTO_BASEPOINT_POINT;

        // g^0 = identity
        baby_steps.insert(current.compress(), 0u64);

        // g^1, g^2, ..., g^(m-1)
        for j in 1..m {
            current = current + g;
            baby_steps.insert(current.compress(), j);
        }

        // Compute g^(-m) for giant steps
        // -m mod group_order
        let m_scalar = Scalar::from(m);
        let neg_m = -m_scalar;
        let giant_step = g.mul(neg_m);

        Ok(BabyStepGiantStepTable {
            baby_steps,
            giant_step,
            neg_m,
        })
    }
}

impl crate::DlogSolver for BabyStepGiantStep {
    fn new(secret_bits: u8) -> Result<Self> {
        if secret_bits < 1 || secret_bits > 32 {
            return Err(anyhow::anyhow!("secret_bits must be between 1 and 32"));
        }

        // m = ceil(sqrt(2^secret_bits)) = 2^(ceil(secret_bits/2))
        let m: u64 = 1 << ((secret_bits + 1) / 2);

        let parameters = BabyStepGiantStepParameters {
            secret_size: secret_bits,
            m,
        };
        Self::from_parameters(parameters)
    }

    fn solve(&self, pk: &RistrettoPoint) -> Result<Option<u64>> {
        self.solve_dlp(pk, None)
    }

    fn secret_bits(&self) -> u8 {
        self.parameters.secret_size
    }
}
