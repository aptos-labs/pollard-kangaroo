#![allow(non_snake_case)]

//! Batched Baby-step Giant-step (BSGS-k) algorithm.
//!
//! This variant uses `double_and_compress_batch` to amortize the cost of
//! point compression across k iterations. The table stores doubled baby steps
//! (2*g^j) so that we can use the batched double-and-compress API.

pub mod generator;
#[cfg(feature = "bsgs_batched_presets")]
pub mod presets;
pub mod solver;
pub mod solver_old_broken;

#[cfg(feature = "bsgs_batched_presets")]
use crate::bsgs_batched::presets::BsgsBatchedPresets;

use anyhow::{Context, Result};
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use std::collections::HashMap;

/// Batched Baby-step Giant-step algorithm for solving discrete logarithms.
///
/// Uses `double_and_compress_batch` to amortize compression cost across
/// multiple iterations.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BabyGiantBatched {
    pub parameters: BsgsBatchedParameters,
    pub table: BsgsBatchedTable,
}

/// Defines generated table values for batched BSGS.
#[cfg_attr(feature = "serde", serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BsgsBatchedTable {
    /// Baby-step lookup table: maps compressed DOUBLED point to its discrete log (j).
    /// Contains compress(2*g^j) for j = 0, 1, ..., m-1 where m = ceil(sqrt(2^secret_size)).
    ///
    /// We store doubled points so we can use `double_and_compress_batch` during solving.
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<(_, _)>"))]
    pub baby_steps: HashMap<CompressedRistretto, u64>,

    /// Precomputed giant step: g^(-m) used to compute h * (g^(-m))^i.
    pub giant_step: RistrettoPoint,

    /// The scalar -m (mod group order).
    pub neg_m: Scalar,
}

/// Defines constants based on which the batched BSGS algorithm runs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BsgsBatchedParameters {
    /// Size of a secret to look for (in bits).
    pub secret_size: u8,
    /// m = ceil(sqrt(2^secret_size)), the number of baby steps.
    pub m: u64,
}

impl BabyGiantBatched {
    pub fn from_parameters(parameters: BsgsBatchedParameters) -> Result<BabyGiantBatched> {
        let table = BsgsBatchedTable::generate(&parameters).context("failed to generate table")?;

        Ok(BabyGiantBatched { parameters, table })
    }

    #[cfg(feature = "bsgs_batched_presets")]
    pub fn from_preset(preset: BsgsBatchedPresets) -> Result<BabyGiantBatched> {
        let bsgs_bytes = match preset {
            #[cfg(feature = "bsgs_batched_table32")]
            BsgsBatchedPresets::BabyGiantBatched32 => presets::BSGS_BATCHED_32,
        };

        let bsgs: BabyGiantBatched =
            bincode::deserialize(bsgs_bytes).context("failed to deserialize table")?;

        Ok(bsgs)
    }
}
