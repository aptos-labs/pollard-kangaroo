#![allow(non_snake_case)]

pub mod generator;
#[cfg(feature = "bsgs_presets")]
pub mod presets;
pub mod solver;

#[cfg(feature = "bsgs_presets")]
use crate::bsgs::presets::BsgsPresets;

use anyhow::{Context, Result};
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use std::collections::HashMap;

/// Baby-step Giant-step algorithm for solving discrete logarithms.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BabyGiant {
    pub parameters: BsgsParameters,
    pub table: BsgsTable,
}

/// Defines generated table values for BSGS.
#[cfg_attr(feature = "serde", serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BsgsTable {
    /// Baby-step lookup table: maps compressed point to its discrete log (j).
    /// Contains g^j for j = 0, 1, ..., m-1 where m = ceil(sqrt(2^secret_size)).
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<(_, _)>"))]
    pub baby_steps: HashMap<CompressedRistretto, u64>,

    /// Precomputed giant step: g^(-m) used to compute h * (g^(-m))^i.
    pub giant_step: RistrettoPoint,

    /// The scalar -m (mod group order).
    pub neg_m: Scalar,
}

/// Defines constants based on which the BSGS algorithm runs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BsgsParameters {
    /// Size of a secret to look for (in bits).
    pub secret_size: u8,
    /// m = ceil(sqrt(2^secret_size)), the number of baby steps.
    pub m: u64,
}

impl BabyGiant {
    pub fn from_parameters(parameters: BsgsParameters) -> Result<BabyGiant> {
        let table = BsgsTable::generate(&parameters).context("failed to generate table")?;

        Ok(BabyGiant { parameters, table })
    }

    #[cfg(feature = "bsgs_presets")]
    pub fn from_preset(preset: BsgsPresets) -> Result<BabyGiant> {
        let bsgs_bytes = match preset {
            #[cfg(feature = "bsgs_table32")]
            BsgsPresets::BabyGiant32 => presets::BSGS_32,
        };

        let bsgs: BabyGiant =
            bincode::deserialize(bsgs_bytes).context("failed to deserialize table")?;

        Ok(bsgs)
    }
}
