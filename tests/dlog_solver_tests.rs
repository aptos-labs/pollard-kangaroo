//! Generic tests for all DLog solver implementations.
//!
//! This module tests all DLog algorithms ([BL12], BSGS, BSGS-k) using the
//! `DlogSolver` trait. For each algorithm, we test bit sizes from 1 to 7,
//! verifying that the algorithm correctly solves DLog for all values in [0, 2^ℓ).

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use pollard_kangaroo::DlogSolver;
use std::ops::Mul;

/// Generic test function that tests a DlogSolver implementation for all values
/// in [0, 2^secret_bits).
fn test_all_values<S: DlogSolver>(secret_bits: u8) {
    let solver = S::new(secret_bits).expect("Failed to create solver");

    let max_value = 1u64 << secret_bits;

    for x in 0..max_value {
        // TODO: don't do a scalar multiplication here; you can just do an EC addition on the previous x and proceed faster
        let pk = RISTRETTO_BASEPOINT_POINT.mul(Scalar::from(x));
        let result = solver
            .solve(&pk)
            .expect("Solver returned error")
            .expect("Solver returned None");

        assert_eq!(
            result, x,
            "Failed for secret_bits={}, x={}: got {}",
            secret_bits, x, result
        );
    }
}

/// Macro to generate tests for a specific DlogSolver implementation.
/// Tests 1-7 bits exhaustively.
/// TODO: Don't use a fucking macro for this... Just write a generic function that takes the solver as a template argument and the bit size as a normal argument.
///   then call this function for all supported solvers in a for loop over the bit sizes. NO MACROS!
macro_rules! generate_dlog_tests {
    ($solver:ty, $name:ident) => {
        mod $name {
            use super::*;

            #[test]
            fn test_1_bit() {
                test_all_values::<$solver>(1);
            }

            #[test]
            fn test_2_bit() {
                test_all_values::<$solver>(2);
            }

            #[test]
            fn test_3_bit() {
                test_all_values::<$solver>(3);
            }

            #[test]
            fn test_4_bit() {
                test_all_values::<$solver>(4);
            }

            #[test]
            fn test_5_bit() {
                test_all_values::<$solver>(5);
            }

            #[test]
            fn test_6_bit() {
                test_all_values::<$solver>(6);
            }

            #[test]
            fn test_7_bit() {
                test_all_values::<$solver>(7);
            }
        }
    };
}

// Generate tests for BSGS (fastest algorithm)
#[cfg(feature = "bsgs")]
generate_dlog_tests!(pollard_kangaroo::bsgs::BabyStepGiantStep, bsgs_tests);

// Generate tests for BSGS-k with K=64
#[cfg(feature = "bsgs_k")]
generate_dlog_tests!(
    pollard_kangaroo::bsgs_k::BabyStepGiantStepK<64>,
    bsgs_k_k64_tests
);

// Generate tests for BSGS-k with K=256
#[cfg(feature = "bsgs_k")]
generate_dlog_tests!(
    pollard_kangaroo::bsgs_k::BabyStepGiantStepK<256>,
    bsgs_k_k256_tests
);

// Generate tests for [BL12]
#[cfg(feature = "bl12")]
generate_dlog_tests!(pollard_kangaroo::bl12::Bl12, bl12_tests);
