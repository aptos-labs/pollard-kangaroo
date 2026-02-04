//! Traits for discrete log solvers.

use anyhow::Result;
use curve25519_dalek::ristretto::RistrettoPoint;

/// Trait for discrete log solvers.
///
/// Implementors can precompute tables for solving discrete logs on values < 2^ℓ,
/// and then solve discrete logs efficiently.
pub trait DiscreteLogSolver: Sized {
    /// Returns the algorithm name (e.g., "BSGS", "BSGS-k32", "BL12").
    ///
    /// Used for test and benchmark output.
    fn algorithm_name() -> &'static str;

    /// Creates a new solver by computing tables for solving DLog
    /// on values in the range [0, 2^max_num_bits).
    ///
    /// # Arguments
    /// * `max_num_bits` - The number of bits (ℓ). The solver will be able to
    ///   find discrete logs for values < 2^max_num_bits.
    ///
    /// # Panics
    /// Panics if `max_num_bits` is out of the valid range for the algorithm.
    fn new_and_compute_table(max_num_bits: u8) -> Self;

    /// Creates a new solver from a precomputed table for the given bit size.
    ///
    /// This is more efficient than `new_and_compute_table` when precomputed
    /// tables are available (e.g., compiled into the binary).
    ///
    /// # Arguments
    /// * `max_num_bits` - The number of bits (ℓ). Must match an available
    ///   precomputed table (typically 32).
    ///
    /// # Panics
    /// Panics if no precomputed table is available for the given bit size.
    fn from_precomputed_table(max_num_bits: u8) -> Self;

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
