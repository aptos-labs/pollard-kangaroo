//! Generic tests for all DLog solver implementations.
//!
//! This module tests all DLog algorithms ([BL12], BSGS, BSGS-k, Naive Lookup) using the
//! `DlogSolver` trait. For each algorithm, we test bit sizes from 1 to 5,
//! verifying that the algorithm correctly solves DLog for all values in [0, 2^ℓ).

mod dlog_without_precomputation {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use pollard_kangaroo::DlogSolver;

    /// The default range of bit sizes to test exhaustively.
    const DEFAULT_TEST_BIT_SIZES: std::ops::RangeInclusive<u8> = 1..=5;

    /// Generic test function that tests a DlogSolver implementation for all values
    /// in [0, 2^max_num_bits).
    fn test_all_values<S: DlogSolver>(max_num_bits: u8) {
        let solver = S::new_and_compute_table(max_num_bits).expect("Failed to create solver");

        let max_value = 1u64 << max_num_bits;
        let g = RISTRETTO_BASEPOINT_POINT;

        // Start with g^0 = identity, then increment via EC addition: g^(x+1) = g^x + g
        let mut pk = RistrettoPoint::default(); // identity

        for x in 0..max_value {
            let result = solver.solve(&pk).expect("Solver returned error");

            assert_eq!(
                result, x,
                "Failed for max_num_bits={}, x={}: got {}",
                max_num_bits, x, result
            );

            // g^(x+1) = g^x + g
            pk = pk + g;
        }
    }

    /// Tests a DlogSolver implementation across bit sizes.
    ///
    /// If `max_num_bits` is provided, tests only that bit size.
    /// Otherwise, tests all bit sizes in DEFAULT_TEST_BIT_SIZES.
    fn test_solver<S: DlogSolver>(max_num_bits: Option<u8>) {
        match max_num_bits {
            Some(bits) => test_all_values::<S>(bits),
            None => {
                for bits in DEFAULT_TEST_BIT_SIZES {
                    test_all_values::<S>(bits);
                }
            }
        }
    }

    #[test]
    #[cfg(feature = "bsgs")]
    fn test_bsgs() {
        test_solver::<pollard_kangaroo::bsgs::BabyStepGiantStep>(None);
    }

    #[test]
    #[cfg(feature = "bsgs_k")]
    fn test_bsgs_k() {
        test_solver::<pollard_kangaroo::bsgs_k::BabyStepGiantStepK<64>>(Some(10));
        test_solver::<pollard_kangaroo::bsgs_k::BabyStepGiantStepK<256>>(Some(10));
        test_solver::<pollard_kangaroo::bsgs_k::BabyStepGiantStepK<1024>>(Some(10));
    }

    #[test]
    #[cfg(feature = "bl12")]
    fn test_bl12() {
        test_solver::<pollard_kangaroo::bl12::Bl12>(Some(5));
    }

    #[test]
    #[cfg(feature = "naive_lookup")]
    fn test_naive_lookup() {
        test_solver::<pollard_kangaroo::naive_lookup::NaiveLookup>(Some(16));
    }
}
