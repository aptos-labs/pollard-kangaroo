//! Traits for discrete logarithm solvers.

use anyhow::Result;
use curve25519_dalek::ristretto::RistrettoPoint;

/// Trait for discrete logarithm solvers.
///
/// Implementors can precompute tables for solving DLog on values < 2^ℓ,
/// and then solve discrete logarithms efficiently.
pub trait DlogSolver: Sized {
    /// Creates a new solver with precomputed tables for solving DLog
    /// on values in the range [0, 2^secret_bits).
    ///
    /// # Arguments
    /// * `secret_bits` - The number of bits in the secret (ℓ). The solver
    ///   will be able to find discrete logs for values < 2^secret_bits.
    /// TODO: rename this `secret_bits` (and its associated getter function) to max_num_bits; do it everywhere where this "secret_bits" notion/terminology is used, not just in this file
    /// TODO: rename this function to `new_and_compute_table`
    fn new(secret_bits: u8) -> Result<Self>;

    /// Solves the discrete logarithm problem.
    ///
    /// Given `pk = g^x` where `g` is the Ristretto basepoint, finds `x`.
    ///
    /// # Arguments
    /// * `pk` - The public key (g^x) to solve the DLog for.
    ///
    /// # Returns
    /// * `Ok(Some(x))` - The discrete log if found.
    /// * `Ok(None)` - If no solution exists in the valid range.
    /// * `Err(_)` - On error.
    /// TODO: why are you returning a Result<Option<>> instead of a Result<>? Fix please.
    fn solve(&self, pk: &RistrettoPoint) -> Result<Option<u64>>;

    /// Returns the maximum number of bits this solver can handle.
    fn secret_bits(&self) -> u8;
}
