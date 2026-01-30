#![allow(non_snake_case)]

pub mod generator;
#[cfg(feature = "bsgs_presets")]
pub mod presets;
pub mod solver;

#[cfg(feature = "bsgs_presets")]
use crate::bsgs::presets::BabyStepGiantStepPresets;

use anyhow::{Context, Result};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use std::collections::HashMap;

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
