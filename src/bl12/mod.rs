#![allow(non_snake_case)]

pub mod generator;
#[cfg(feature = "presets")]
pub mod presets;
pub mod solver;

#[cfg(feature = "presets")]
use crate::bl12::presets::Presets;

use anyhow::{Context, Result};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use std::collections::HashMap;

/// [BL12] discrete logarithm solver.
///
/// Implements the algorithm from "Computing small discrete logarithms faster"
/// by Daniel J. Bernstein and Tanja Lange (2012).
/// https://cr.yp.to/dlog/cuberoot-20120919.pdf
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Bl12 {
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

impl Bl12 {
    pub fn from_parameters(parameters: Parameters) -> Result<Bl12> {
        let table = Table::generate(&parameters).context("failed to generate table")?;

        Ok(Bl12 { parameters, table })
    }

    #[cfg(feature = "presets")]
    pub fn from_preset(preset: Presets) -> Result<Bl12> {
        let bl12_bytes = match preset {
            #[cfg(feature = "table16")]
            Presets::Bl12_16 => presets::BL12_16,
            #[cfg(feature = "table32")]
            Presets::Bl12_32 => presets::BL12_32,
            #[cfg(feature = "table48")]
            Presets::Bl12_48 => presets::BL12_48,
        };

        let bl12: Bl12 = bincode::deserialize(bl12_bytes).context("failed to deserialize table")?;

        Ok(bl12)
    }
}

pub(crate) fn is_distinguished(
    compressed_point: &CompressedRistretto,
    parameters: &Parameters,
) -> bool {
    let point_bytes = get_last_point_bytes(compressed_point);

    (point_bytes & (parameters.W - 1)) == 0
}

/// Gets a new index from the provided compressed Ristretto point. The index is meant to be used
/// for retrieving elements from [`Table`] `s` and `slog` vectors.
///
/// Note: it does not perform hashing. However, in the original reference implementation authors
/// (Daniel J. Bernstein and Tanja Lange) use exactly the same name.
pub(crate) fn hash(compressed_point: &CompressedRistretto, parameters: &Parameters) -> u64 {
    let point_bytes = get_last_point_bytes(compressed_point);

    point_bytes & (parameters.R - 1)
}

fn get_last_point_bytes(compressed_point: &CompressedRistretto) -> u64 {
    let (_, point_bytes) = compressed_point.as_bytes().split_at(32 - size_of::<u64>());

    u64::from_be_bytes(point_bytes.try_into().unwrap())
}

impl crate::DlogSolver for Bl12 {
    fn new(secret_bits: u8) -> Result<Self> {
        // Generate reasonable parameters based on secret_bits
        // These are heuristics based on the existing presets
        let parameters = Parameters::for_secret_bits(secret_bits)?;
        Self::from_parameters(parameters)
    }

    fn solve(&self, pk: &RistrettoPoint) -> Result<Option<u64>> {
        self.solve_dlp(pk, None)
    }

    fn secret_bits(&self) -> u8 {
        self.parameters.secret_size
    }
}

impl Parameters {
    /// Creates reasonable parameters for a given secret bit size.
    pub fn for_secret_bits(secret_bits: u8) -> Result<Self> {
        if secret_bits < 1 || secret_bits > 64 {
            return Err(anyhow::anyhow!("secret_bits must be between 1 and 64"));
        }

        // For small bit sizes (1-7), use parameters that still exercise the
        // random walk logic. W > 1 ensures not every point is distinguished,
        // so the algorithm actually walks before finding distinguished points.
        if secret_bits < 8 {
            // W controls distinguished point frequency: 1/W points are distinguished.
            // For very small spaces (1-3 bits), use W=2 (50% distinguished).
            // For slightly larger (4-7 bits), use W=4 (25% distinguished).
            let w = if secret_bits <= 3 { 2 } else { 4 };

            // N is the table size (number of distinguished points to collect).
            // For small spaces, we need N to be small enough that table generation
            // can find that many unique distinguished points without getting stuck.
            // Use roughly sqrt(2^secret_bits) * 2 as a reasonable target.
            let n = match secret_bits {
                1 => 2,
                2 => 4,
                3 => 8,
                4 => 16,
                5 => 32,
                6 => 64,
                7 => 128,
                _ => unreachable!(),
            };

            // R is the number of step scalars (must be power of 2).
            let r = if secret_bits <= 4 { 4 } else { 8 };

            // i * W gives the max iterations before restarting the walk.
            // Use larger i for small spaces to give more chances to find distinguished points.
            let i = 16;

            return Ok(Parameters {
                i,
                W: w,
                N: n,
                R: r,
                secret_size: secret_bits,
            });
        }

        // Heuristics based on existing presets:
        // - W (distinguished point threshold) scales with sqrt(search space)
        // - N (table size) scales with sqrt(search space)
        // - R (number of step scalars) is kept small (power of 2)
        // - i (iteration multiplier) is kept constant at 8

        let w_exp = secret_bits.saturating_sub(4).min(16);
        let w = 1u64 << w_exp;

        // Table size: roughly sqrt(2^secret_bits) / some factor
        let n = match secret_bits {
            8..=16 => 1000,
            17..=24 => 4000,
            25..=32 => 8000,
            33..=40 => 20000,
            41..=48 => 40000,
            _ => 80000,
        };

        // R should be a power of 2, scaled with secret_bits
        let r = match secret_bits {
            8..=16 => 64,
            17..=32 => 128,
            _ => 256,
        };

        Ok(Parameters {
            i: 8,
            W: w,
            N: n,
            R: r,
            secret_size: secret_bits,
        })
    }
}
