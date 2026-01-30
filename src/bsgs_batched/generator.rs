use crate::bsgs_batched::{BsgsBatchedParameters, BsgsBatchedTable};

use anyhow::Result;
use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use std::collections::HashMap;
use std::ops::Mul;

impl BsgsBatchedTable {
    /// Generates the batched BSGS table with DOUBLED baby steps.
    ///
    /// Baby step: Compute 2*g^j for j = 0, 1, ..., m-1 and store compressed in a hash table.
    /// We store doubled points so we can use `double_and_compress_batch` during solving.
    /// Also precompute g^(-m) for the giant step phase.
    pub fn generate(parameters: &BsgsBatchedParameters) -> Result<BsgsBatchedTable> {
        if parameters.secret_size < 8 || parameters.secret_size > 64 {
            return Err(anyhow::anyhow!("secret size must be between 8 and 64"));
        }

        let m = parameters.m;
        let g = RISTRETTO_BASEPOINT_POINT;

        // Baby steps: compute g^1, g^2, ..., g^(m-1), then double and compress
        // Note: we skip g^0 (identity) because double_and_compress_batch panics on identity
        let mut points = Vec::with_capacity((m - 1) as usize);
        let mut current = g; // start with g^1

        for _ in 1..m {
            points.push(current);
            current = current + g;
        }

        // Double and compress all non-identity points in a batch
        let doubled_compressed = RistrettoPoint::double_and_compress_batch(&points);

        // Build the lookup table: compressed(2*g^j) -> j
        let mut baby_steps = HashMap::with_capacity(m as usize);

        // Handle identity specially: 2*identity = identity
        baby_steps.insert(CompressedRistretto::identity(), 0u64);

        // Add the rest (j = 1, 2, ..., m-1)
        for (idx, compressed) in doubled_compressed.into_iter().enumerate() {
            let j = (idx + 1) as u64;
            baby_steps.insert(compressed, j);
        }

        // Compute g^(-m) for giant steps
        // -m mod group_order
        let m_scalar = Scalar::from(m);
        let neg_m = -m_scalar;
        let giant_step = g.mul(neg_m);

        Ok(BsgsBatchedTable {
            baby_steps,
            giant_step,
            neg_m,
        })
    }
}
