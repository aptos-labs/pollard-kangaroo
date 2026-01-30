use crate::bsgs::{BsgsParameters, BsgsTable};

use anyhow::Result;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use std::collections::HashMap;
use std::ops::Mul;

impl BsgsTable {
    /// Generates the BSGS table with baby steps.
    ///
    /// Baby step: Compute g^j for j = 0, 1, ..., m-1 and store in a hash table.
    /// Also precompute g^(-m) for the giant step phase.
    pub fn generate(parameters: &BsgsParameters) -> Result<BsgsTable> {
        if parameters.secret_size < 1 || parameters.secret_size > 64 {
            return Err(anyhow::anyhow!("secret size must be between 1 and 64"));
        }

        let m = parameters.m;

        // Baby steps: compute g^0, g^1, ..., g^(m-1)
        let mut baby_steps = HashMap::with_capacity(m as usize);
        let mut current = RistrettoPoint::default(); // identity
        let g = RISTRETTO_BASEPOINT_POINT;

        // g^0 = identity
        baby_steps.insert(current.compress(), 0u64);

        // g^1, g^2, ..., g^(m-1)
        for j in 1..m {
            current = current + g;
            baby_steps.insert(current.compress(), j);
        }

        // Compute g^(-m) for giant steps
        // -m mod group_order
        let m_scalar = Scalar::from(m);
        let neg_m = -m_scalar;
        let giant_step = g.mul(neg_m);

        Ok(BsgsTable {
            baby_steps,
            giant_step,
            neg_m,
        })
    }
}
