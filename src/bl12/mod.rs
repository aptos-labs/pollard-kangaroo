#![allow(non_snake_case)]

//! [BL12] discrete logarithm solver.
//!
//! Implements the algorithm from "Computing small discrete logarithms faster"
//! by Daniel J. Bernstein and Tanja Lange (2012).
//! https://cr.yp.to/dlog/cuberoot-20120919.pdf

#[cfg(feature = "bl12_table32")]
pub mod precomputed_tables;

#[cfg(feature = "bl12_table32")]
use crate::bl12::precomputed_tables::PrecomputedTables;
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
    pub table: Table,
}

/// Defines generated table values and algorithm parameters.
#[cfg_attr(feature = "serde", serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Table {
    /// Size of a secret to look for (in bits).
    pub max_num_bits: u8,

    /// Coefficient to increase [`W`] constant.
    pub i: u64,

    /// Number of iterations after which we need to regenerate a new starting point
    /// (see algorithm definition).
    #[allow(non_snake_case)]
    pub W: u64,

    /// Size of the generated table.
    #[allow(non_snake_case)]
    pub N: u64,

    /// Number of elements to be generated for `s` and `slog` vectors.
    #[allow(non_snake_case)]
    pub R: u64,

    /// A vector of generated Ristretto256 points which are used to get the next point and perform
    /// further distinguished point checks based on [`slog`] scalars.
    pub s: Vec<RistrettoPoint>,

    /// A vector of generated scalars which are used to get the next point and perform further
    /// distinguished point checks.
    pub slog: Vec<Scalar>,

    /// Generated table map where key - distinguished (see [`is_distinguished`] function)
    /// Ristretto256 point and its discrete log - it's discrete log.
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<(_, _)>"))]
    pub distinguished_points: HashMap<CompressedRistretto, Scalar>,
}

impl Bl12 {
    #[cfg(feature = "bl12_table32")]
    pub fn from_precomputed_table(table: PrecomputedTables) -> Result<Bl12> {
        let bl12_bytes = match table {
            #[cfg(feature = "bl12_table32")]
            PrecomputedTables::Bl12_32 => precomputed_tables::BL12_32,
        };

        let bl12: Bl12 = bincode::deserialize(bl12_bytes).context("failed to deserialize table")?;

        Ok(bl12)
    }

    /// Solves the discrete log problem using the default RNG (OsRng).
    pub fn solve_dlp(&self, pk: &RistrettoPoint, max_time: Option<u64>) -> Result<u64> {
        self.solve_dlp_with_rng(pk, max_time, &mut rand_core::OsRng)
    }

    /// Solves the discrete log problem using the provided RNG.
    ///
    /// This is useful for deterministic testing when a seeded RNG is provided.
    pub fn solve_dlp_with_rng<R: rand_core::RngCore>(
        &self,
        pk: &RistrettoPoint,
        max_time: Option<u64>,
        rng: &mut R,
    ) -> Result<u64> {
        if pk.eq(&RistrettoPoint::identity()) {
            return Ok(0);
        }

        let start_time = max_time.map(|_| Instant::now());

        loop {
            // wdist = r + slog_1 + slog_2 ...
            // For small secret sizes, use 0 or a small value
            let wdist_bits = self.table.max_num_bits.saturating_sub(8).max(1);
            let mut wdist = utils::generate_random_scalar_with_rng(wdist_bits, rng)
                .context("failed to generate `wdist` scalar")?;
            // w = sk * G + r * G + slog_1 * G + slog_2 * G ... = sk * G + wdist * G
            let mut w = pk.add(RISTRETTO_BASEPOINT_POINT.mul(wdist));

            for _ in 0..self.table.i * self.table.W {
                let w_compressed = w.compress();

                if is_distinguished(&w_compressed, &self.table) {
                    if let Some(value) = self.table.distinguished_points.get(&w_compressed) {
                        // value * G = sk * G + wdist * G => sk = value - wdist
                        let sk = value.sub(wdist);

                        assert!(RISTRETTO_BASEPOINT_POINT.mul(sk).eq(pk));

                        return Ok(utils::scalar_to_u64(&sk));
                    }

                    break;
                }

                if let Some(max_time) = max_time {
                    if start_time.unwrap().elapsed() >= Duration::from_millis(max_time) {
                        return Err(anyhow::anyhow!("timeout exceeded"));
                    }
                }

                let h = hash(&w_compressed, &self.table) as usize;

                wdist.add_assign(&self.table.slog[h]);
                w.add_assign(&self.table.s[h]);
            }
        }
    }
}

impl Table {
    pub fn generate(max_num_bits: u8) -> Result<Table> {
        if max_num_bits < 1 || max_num_bits > 64 {
            return Err(anyhow::anyhow!("max_num_bits must be between 1 and 64"));
        }

        // Generate reasonable parameters based on max_num_bits
        let (i, w, n, r) = Self::params_for_max_num_bits(max_num_bits);

        let (slog, s) = Self::s_values_init(max_num_bits, w, r)?;

        let mut distinguished_points = HashMap::new();

        // Track attempts to detect if we're stuck finding the same distinguished points
        let mut attempts = 0u64;
        let max_attempts = n as u64 * 1000;

        while distinguished_points.len() < n as usize {
            attempts += 1;
            if attempts > max_attempts {
                // Give up if we can't find enough unique distinguished points.
                // This can happen for very small search spaces.
                break;
            }

            let mut wlog = utils::generate_random_scalar(max_num_bits)
                .context("failed to generate `wlog` scalar")?;
            let mut current = RISTRETTO_BASEPOINT_POINT.mul(wlog);

            for _ in 0..i * w {
                let current_compressed = current.compress();

                if is_distinguished_with_params(&current_compressed, w) {
                    distinguished_points.insert(current_compressed, wlog);
                    break;
                }

                let h = hash_with_params(&current_compressed, r) as usize;

                wlog.add_assign(slog[h]);
                current.add_assign(s[h]);
            }
        }

        Ok(Table {
            max_num_bits,
            i,
            W: w,
            N: n,
            R: r,
            s,
            slog,
            distinguished_points,
        })
    }

    /// Returns (i, W, N, R) parameters for a given max_num_bits.
    fn params_for_max_num_bits(max_num_bits: u8) -> (u64, u64, u64, u64) {
        // For small bit sizes (1-7), use parameters that still exercise the
        // random walk logic.
        if max_num_bits < 8 {
            let w = if max_num_bits <= 3 { 2 } else { 4 };
            let n = match max_num_bits {
                1 => 2,
                2 => 4,
                3 => 8,
                4 => 16,
                5 => 32,
                6 => 64,
                7 => 128,
                _ => unreachable!(),
            };
            let r = if max_num_bits <= 4 { 4 } else { 8 };
            let i = 16;
            return (i, w, n, r);
        }

        // Heuristics based on existing precomputed tables
        // Original 32-bit: W=2048 (2^11), N=4000, R=128
        // W scales roughly as 2^((max_num_bits + 1) / 3)
        let w_exp = ((max_num_bits as u64 + 1) / 3).max(4).min(20) as u8;
        let w = 1u64 << w_exp;

        let n = match max_num_bits {
            8..=16 => 1000,
            17..=24 => 2000,
            25..=32 => 4000,
            33..=40 => 20000,
            41..=48 => 40000,
            _ => 80000,
        };

        let r = match max_num_bits {
            8..=16 => 64,
            17..=48 => 128,
            _ => 256,
        };

        (8, w, n, r)
    }

    fn s_values_init(
        max_num_bits: u8,
        w: u64,
        r: u64,
    ) -> Result<(Vec<Scalar>, Vec<RistrettoPoint>)> {
        // Calculate slog_size: step sizes should allow walks to cover the search space
        // in roughly W steps (the expected distance between distinguished points).
        let slog_size = if max_num_bits < 8 {
            max_num_bits.max(1)
        } else {
            let search_space = 1u64 << max_num_bits.min(62);
            let ratio = search_space.saturating_div(4).saturating_div(w.max(1));
            if ratio > 0 {
                ratio.ilog2().max(1) as u8
            } else {
                1
            }
        };

        let mut scalars = Vec::with_capacity(r as usize);
        let mut points = Vec::with_capacity(r as usize);

        for _ in 0..r {
            // Generate step size in range [1, 2^slog_size] to ensure non-zero steps
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

fn is_distinguished(compressed_point: &CompressedRistretto, table: &Table) -> bool {
    is_distinguished_with_params(compressed_point, table.W)
}

fn is_distinguished_with_params(compressed_point: &CompressedRistretto, w: u64) -> bool {
    let point_bytes = get_last_point_bytes(compressed_point);
    (point_bytes & (w - 1)) == 0
}

/// Gets a new index from the provided compressed Ristretto point. The index is meant to be used
/// for retrieving elements from [`Table`] `s` and `slog` vectors.
///
/// Note: it does not perform hashing. However, in the original reference implementation authors
/// (Daniel J. Bernstein and Tanja Lange) use exactly the same name.
fn hash(compressed_point: &CompressedRistretto, table: &Table) -> u64 {
    hash_with_params(compressed_point, table.R)
}

fn hash_with_params(compressed_point: &CompressedRistretto, r: u64) -> u64 {
    let point_bytes = get_last_point_bytes(compressed_point);
    point_bytes & (r - 1)
}

fn get_last_point_bytes(compressed_point: &CompressedRistretto) -> u64 {
    let (_, point_bytes) = compressed_point.as_bytes().split_at(32 - size_of::<u64>());

    u64::from_be_bytes(point_bytes.try_into().unwrap())
}

impl crate::DlogSolver for Bl12 {
    fn new_and_compute_table(max_num_bits: u8) -> Result<Self> {
        let table = Table::generate(max_num_bits).context("failed to generate table")?;
        Ok(Bl12 { table })
    }

    fn solve(&self, pk: &RistrettoPoint) -> Result<u64> {
        self.solve_dlp(pk, None)
    }

    fn max_num_bits(&self) -> u8 {
        self.table.max_num_bits
    }
}
