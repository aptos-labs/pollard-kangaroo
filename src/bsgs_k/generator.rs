use super::{BabyStepGiantStepKParameters, BabyStepGiantStepKTable};

use anyhow::Result;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use std::collections::HashMap;
use std::ops::Mul;

impl BabyStepGiantStepKTable {
    /// Generates the BSGS-k table with DOUBLED baby steps.
    ///
    /// Baby step: Compute 2*g^j for j = 0, 1, ..., m-1 and store compressed in a hash table.
    /// We store doubled points so we can use `double_and_compress_batch` during solving.
    /// Also precompute g^(-m) for the giant step phase.
    pub fn generate(parameters: &BabyStepGiantStepKParameters) -> Result<BabyStepGiantStepKTable> {
        if parameters.secret_size < 1 || parameters.secret_size > 64 {
            return Err(anyhow::anyhow!("secret size must be between 1 and 64"));
        }

        let m = parameters.m;
        let g = RISTRETTO_BASEPOINT_POINT;

        // Baby steps: compute g^0, g^1, g^2, ..., g^(m-1)
        let mut points = Vec::with_capacity(m as usize);
        let mut current = RistrettoPoint::default(); // identity = g^0

        for _ in 0..m {
            points.push(current);
            current = current + g;
        }

        // Double and compress all points in a batch
        let doubled_compressed = RistrettoPoint::double_and_compress_batch(&points);

        // Build the lookup table: compressed(2*g^j) -> j
        let mut baby_steps = HashMap::with_capacity(m as usize);
        for (j, compressed) in doubled_compressed.into_iter().enumerate() {
            baby_steps.insert(compressed, j as u64);
        }

        // Compute g^(-m) for giant steps
        // -m mod group_order
        let m_scalar = Scalar::from(m);
        let neg_m = -m_scalar;
        let giant_step = g.mul(neg_m);

        Ok(BabyStepGiantStepKTable {
            baby_steps,
            giant_step,
            neg_m,
        })
    }
}
