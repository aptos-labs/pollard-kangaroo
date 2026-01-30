#![allow(non_snake_case)]

//! BSGS-k algorithm: Baby-step Giant-step with batched compression.
//!
//! This variant uses `double_and_compress_batch` to amortize the cost of
//! point compression across K iterations. The table stores doubled baby steps
//! (2*g^j) so that we can use the batched double-and-compress API.

pub mod generator;
#[cfg(feature = "bsgs_k_presets")]
pub mod presets;
pub mod solver;

#[cfg(feature = "bsgs_k_presets")]
use crate::bsgs_k::presets::BabyStepGiantStepKPresets;

use anyhow::{Context, Result};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use std::collections::HashMap;

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

    /// The scalar -m (mod group order).
    pub neg_m: Scalar,
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
}

impl<const K: usize> crate::DlogSolver for BabyStepGiantStepK<K> {
    fn new(secret_bits: u8) -> Result<Self> {
        if secret_bits < 1 || secret_bits > 64 {
            return Err(anyhow::anyhow!("secret_bits must be between 1 and 64"));
        }

        // m = ceil(sqrt(2^secret_bits)) = 2^(ceil(secret_bits/2))
        let m: u64 = 1 << ((secret_bits + 1) / 2);

        let parameters = BabyStepGiantStepKParameters {
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
