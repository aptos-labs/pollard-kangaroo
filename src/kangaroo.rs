#![allow(non_snake_case)]

pub mod generator;
#[cfg(feature = "presets")]
pub mod presets;
pub mod solver;

#[cfg(feature = "presets")]
use crate::kangaroo::presets::Presets;

use anyhow::{Context, Result};
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use std::collections::HashMap;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Kangaroo {
    pub parameters: Parameters,
    pub table: Table,
}

/// Defines generated table values.
#[cfg_attr(feature = "serde", serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Table {
    /// A vector of generated Ristretto256 points which are used to get the next point and perform
    /// further distinguished point checks based on [`slog`] scalars.
    ///
    /// [`Table::s_values_init`] is used to fill this value with values.
    ///
    /// [`slog`]:Table::slog
    pub s: Vec<RistrettoPoint>,

    /// A vector of generated scalars which are used to get the next point and perform further
    /// distinguished point checks.
    ///
    /// [`Table::s_values_init`] is used to fill this value with values.
    pub slog: Vec<Scalar>,

    /// Generated table map where key - distinguished (see [`is_distinguished`] function)
    /// Ristretto256 point and its discrete log - it's discrete log. Use [`Table::generate`] method
    /// to fill the table with values.
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<(_, _)>"))]
    pub table: HashMap<CompressedRistretto, Scalar>,
}

/// Defines constants based on which the algorithm runs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Parameters {
    /// Coefficient to increase [`W`] constant.
    ///
    /// [`W`]:Parameters::W
    pub i: u64,
    /// Number of iterations after which we need to regenerate a new starting point
    /// (see algorithm definition).
    pub W: u64,
    /// Size of the generated table.
    pub N: u64,
    /// Number of elements to be generated for `s` and `slog` vectors of the [`Table`] structure.
    pub R: u64,
    /// Size of a secret to look for.
    pub secret_size: u8,
}

impl Kangaroo {
    pub fn from_parameters(parameters: Parameters) -> Result<Kangaroo> {
        let table = Table::generate(&parameters).context("failed to generate table")?;

        Ok(Kangaroo { parameters, table })
    }

    #[cfg(feature = "presets")]
    pub fn from_preset(preset: Presets) -> Result<Kangaroo> {
        let kangaroo_bytes = match preset {
            #[cfg(feature = "table16")]
            Presets::Kangaroo16 => presets::KANGAROO_16,
            #[cfg(feature = "table32")]
            Presets::Kangaroo32 => presets::KANGAROO_32,
            #[cfg(feature = "table48")]
            Presets::Kangaroo48 => presets::KANGAROO_48,
        };

        let kangaroo: Kangaroo =
            bincode::deserialize(kangaroo_bytes).context("failed to deserialize table")?;

        Ok(kangaroo)
    }
}

fn is_distinguished(compressed_point: &CompressedRistretto, parameters: &Parameters) -> bool {
    let point_bytes = get_last_point_bytes(compressed_point);

    (point_bytes & (parameters.W - 1)) == 0
}

/// Gets a new index from the provided compressed Ristretto point. The index is meant to be used
/// for retrieving elements from [`Table`] `s` and `slog` vectors.
///
/// Note: it does not perform hashing. However, in the original reference implementation authors
/// (Daniel J. Bernstein and Tanja Lange) use exactly the same name.
fn hash(compressed_point: &CompressedRistretto, parameters: &Parameters) -> u64 {
    let point_bytes = get_last_point_bytes(compressed_point);

    point_bytes & (parameters.R - 1)
}

fn get_last_point_bytes(compressed_point: &CompressedRistretto) -> u64 {
    let (_, point_bytes) = compressed_point.as_bytes().split_at(32 - size_of::<u64>());

    u64::from_be_bytes(point_bytes.try_into().unwrap())
}
