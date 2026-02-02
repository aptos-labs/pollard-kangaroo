//! Generic tests for all DLog solver implementations.
//!
//! This module tests all DLog algorithms ([BL12], BSGS, BSGS-k, Naive Lookup) using the
//! `DiscreteLogSolver` trait. For each algorithm, for each $\ell in [1, max_num_bits]$, we precompute a
//! table for solving $\ell$-bit DLs and test the solving algorithm on all values in [0, 2^\ell).

mod dlog_without_precomputation {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use pollard_kangaroo::DiscreteLogSolver;

    /// Tests a DiscreteLogSolver implementation for all values in [0, 2^max_num_bits).
    fn test_solver<S: DiscreteLogSolver>(max_num_bits: u8) {
        for ell in 1..=max_num_bits {
            let solver = S::new_and_compute_table(ell);

            let max_value = 1u64 << ell;
            let g = RISTRETTO_BASEPOINT_POINT;

            // Start with g^0 = identity, then increment via EC addition: g^(x+1) = g^x + g
            let mut pk = RistrettoPoint::default(); // identity

            for value in 0..max_value {
                let result = solver.solve(&pk).expect("Solver returned error");

                assert_eq!(
                    result, value,
                    "Failed for ell={}, x={}: got {}",
                    ell, value, result
                );

                // g^(x+1) = g^x + g
                pk = pk + g;
            }
        }
    }

    #[test]
    #[cfg(feature = "bsgs")]
    fn test_bsgs() {
        test_solver::<pollard_kangaroo::bsgs::BabyStepGiantStep>(11);
    }

    #[test]
    #[cfg(feature = "bsgs_k")]
    fn test_bsgs_k() {
        test_solver::<pollard_kangaroo::bsgs_k::BabyStepGiantStepK<64>>(10);
        test_solver::<pollard_kangaroo::bsgs_k::BabyStepGiantStepK<256>>(10);
        test_solver::<pollard_kangaroo::bsgs_k::BabyStepGiantStepK<1024>>(10);
    }

    #[test]
    #[cfg(feature = "bl12")]
    fn test_bl12() {
        test_solver::<pollard_kangaroo::bl12::Bl12>(4);
    }

    #[test]
    #[cfg(feature = "naive_lookup")]
    fn test_naive_lookup() {
        test_solver::<pollard_kangaroo::naive_lookup::NaiveLookup>(16);
    }
}
