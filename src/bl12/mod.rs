#![allow(non_snake_case)]

//! [BL12] discrete logarithm solver.
//!
//! Implements the algorithm from "Computing small discrete logarithms faster"
//! by Daniel J. Bernstein and Tanja Lange (2012).
//! https://cr.yp.to/dlog/cuberoot-20120919.pdf

#[cfg(feature = "bl12_presets")]
pub mod presets;

#[cfg(feature = "bl12_presets")]
use crate::bl12::presets::Presets;
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
use std::ops::{Add, AddAssign, Mul, Sub};
use web_time::{Duration, Instant};

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

    #[cfg(feature = "bl12_presets")]
    pub fn from_preset(preset: Presets) -> Result<Bl12> {
        let bl12_bytes = match preset {
            #[cfg(feature = "bl12_table16")]
            Presets::Bl12_16 => presets::BL12_16,
            #[cfg(feature = "bl12_table32")]
            Presets::Bl12_32 => presets::BL12_32,
            #[cfg(feature = "bl12_table48")]
            Presets::Bl12_48 => presets::BL12_48,
        };

        let bl12: Bl12 = bincode::deserialize(bl12_bytes).context("failed to deserialize table")?;

        Ok(bl12)
    }

    pub fn solve_dlp(&self, pk: &RistrettoPoint, max_time: Option<u64>) -> Result<Option<u64>> {
        if pk.eq(&RistrettoPoint::identity()) {
            return Ok(Some(0));
        }

        let start_time = max_time.map(|_| Instant::now());

        loop {
            // wdist = r + slog_1 + slog_2 ...
            // For small secret sizes, use 0 or a small value
            let wdist_bits = self.parameters.secret_size.saturating_sub(8).max(1);
            let mut wdist = utils::generate_random_scalar(wdist_bits)
                .context("failed to generate `wdist` scalar")?;
            // w = sk * G + r * G + slog_1 * G + slog_2 * G ... = sk * G + wdist * G
            let mut w = pk.add(RISTRETTO_BASEPOINT_POINT.mul(wdist));

            for _ in 0..self.parameters.i * self.parameters.W {
                let w_compressed = w.compress();

                if is_distinguished(&w_compressed, &self.parameters) {
                    if let Some(value) = self.table.table.get(&w_compressed) {
                        // value * G = sk * G + wdist * G => sk = value - wdist
                        let sk = value.sub(wdist);

                        assert!(RISTRETTO_BASEPOINT_POINT.mul(sk).eq(pk));

                        return Ok(Some(utils::scalar_to_u64(&sk)));
                    }

                    break;
                }

                if let Some(max_time) = max_time {
                    if start_time.unwrap().elapsed() >= Duration::from_millis(max_time) {
                        return Ok(None);
                    }
                }

                let h = hash(&w_compressed, &self.parameters) as usize;

                wdist.add_assign(&self.table.slog[h]);
                w.add_assign(&self.table.s[h]);
            }
        }
    }
}

impl Table {
    pub fn generate(parameters: &Parameters) -> Result<Table> {
        if parameters.secret_size < 1 || parameters.secret_size > 64 {
            return Err(anyhow::anyhow!("secret size must be between 1 and 64"));
        }

        let (slog, s) = Self::s_values_init(parameters)?;

        let mut table = HashMap::new();

        // Track attempts to detect if we're stuck finding the same distinguished points
        let mut attempts = 0u64;
        let max_attempts = parameters.N as u64 * 1000;

        while table.len() < parameters.N as usize {
            attempts += 1;
            if attempts > max_attempts {
                // Give up if we can't find enough unique distinguished points.
                // This can happen for very small search spaces.
                break;
            }

            let mut wlog = utils::generate_random_scalar(parameters.secret_size)
                .context("failed to generate `wlog` scalar")?;
            let mut w = RISTRETTO_BASEPOINT_POINT.mul(wlog);

            for _ in 0..parameters.i * parameters.W {
                let w_compressed = w.compress();

                if is_distinguished(&w_compressed, parameters) {
                    table.insert(w_compressed, wlog);

                    break;
                }

                let h = hash(&w_compressed, parameters) as usize;

                wlog.add_assign(slog[h]);
                w.add_assign(s[h]);
            }
        }

        Ok(Table { s, slog, table })
    }

    fn s_values_init(parameters: &Parameters) -> Result<(Vec<Scalar>, Vec<RistrettoPoint>)> {
        // Calculate slog_size: step sizes should allow walks to cover the search space
        // in roughly W steps (the expected distance between distinguished points).
        //
        // For small secret_size (< 8), use secret_size directly as slog_size so that
        // steps can span the entire search space. This ensures the random walk can
        // effectively explore small spaces.
        //
        // For larger secret_size, use the ratio-based calculation which gives
        // step sizes proportional to search_space / (4 * W).
        let slog_size = if parameters.secret_size < 8 {
            parameters.secret_size.max(1)
        } else {
            let search_space = 1u64 << parameters.secret_size.min(62);
            let ratio = search_space
                .saturating_div(4)
                .saturating_div(parameters.W.max(1));
            if ratio > 0 {
                ratio.ilog2().max(1) as u8
            } else {
                1
            }
        };

        let mut scalars = Vec::with_capacity(parameters.R as usize);
        let mut points = Vec::with_capacity(parameters.R as usize);

        for _ in 0..parameters.R {
            // Generate step size in range [1, 2^slog_size] to ensure non-zero steps
            // and good variety. We generate a random value and add 1.
            let random_part = utils::generate_random_scalar(slog_size)
                .context("failed to generate `slog` scalar")?;
            let slog = random_part + Scalar::ONE;

            let s = RISTRETTO_BASEPOINT_POINT.mul(slog);

            scalars.push(slog);
            points.push(s);
        }

        Ok((scalars, points))
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
