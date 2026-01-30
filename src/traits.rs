//! Traits for discrete logarithm solvers.

use anyhow::Result;
use curve25519_dalek::ristretto::RistrettoPoint;

/// Trait for discrete logarithm solvers.
///
/// Implementors can precompute tables for solving DLog on values < 2^ℓ,
/// and then solve discrete logarithms efficiently.
pub trait DlogSolver: Sized {
    /// Creates a new solver with precomputed tables for solving DLog
    /// on values in the range [0, 2^max_num_bits).
    ///
    /// # Arguments
    /// * `max_num_bits` - The number of bits (ℓ). The solver will be able to
    ///   find discrete logs for values < 2^max_num_bits.
    ///
    /// # Panics
    /// Panics if `max_num_bits` is out of the valid range for the algorithm.
    fn new_and_compute_table(max_num_bits: u8) -> Self;

    /// Solves the discrete logarithm problem.
    ///
    /// Given `pk = g^x` where `g` is the Ristretto basepoint, finds `x`.
    ///
    /// # Arguments
    /// * `pk` - The public key (g^x) to solve the DLog for.
    ///
    /// # Returns
    /// * `Ok(x)` - The discrete log.
    /// * `Err(_)` - If no solution exists in the valid range, or on error.
    fn solve(&self, pk: &RistrettoPoint) -> Result<u64>;

    /// Returns the maximum number of bits this solver can handle.
    fn max_num_bits(&self) -> u8;
}
