use super::{hash, is_distinguished, Parameters, Table};
use crate::utils;

use anyhow::{Context, Result};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use std::collections::HashMap;
use std::ops::{AddAssign, Mul};

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
