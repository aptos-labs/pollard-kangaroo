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
    fn test_bsgs_all_values_up_to_11bits() {
        test_solver::<pollard_kangaroo::bsgs::BabyStepGiantStep>(11);
    }

    #[test]
    #[cfg(feature = "bsgs_k")]
    fn test_bsgs_k_all_values_up_to_10bits() {
        test_solver::<pollard_kangaroo::bsgs_k::BabyStepGiantStepK<32>>(10);
        test_solver::<pollard_kangaroo::bsgs_k::BabyStepGiantStepK<64>>(10);
        test_solver::<pollard_kangaroo::bsgs_k::BabyStepGiantStepK<256>>(10);
        test_solver::<pollard_kangaroo::bsgs_k::BabyStepGiantStepK<1024>>(10);
    }

    #[test]
    #[cfg(feature = "bl12")]
    fn test_bl12_all_values_up_to_4bits() {
        test_solver::<pollard_kangaroo::bl12::Bl12>(4);
    }

    #[test]
    #[cfg(feature = "naive_lookup")]
    fn test_naive_lookup_all_values_up_to_16bits() {
        test_solver::<pollard_kangaroo::naive_lookup::NaiveLookup>(16);
    }

    #[test]
    #[cfg(feature = "naive_doubled_lookup")]
    fn test_naive_doubled_lookup_all_values_up_to_10bits() {
        // NaiveDoubledLookup uses a table for 2*max_num_bits, so 10-bit test uses 20-bit table
        test_solver::<pollard_kangaroo::naive_doubled_lookup::NaiveDoubledLookup>(10);
    }

    #[test]
    #[cfg(feature = "tbsgs_k")]
    fn test_tbsgs_k_all_values_up_to_10bits() {
        test_solver::<pollard_kangaroo::tbsgs_k::TruncatedBabyStepGiantStepK<32>>(10);
        test_solver::<pollard_kangaroo::tbsgs_k::TruncatedBabyStepGiantStepK<64>>(10);
        test_solver::<pollard_kangaroo::tbsgs_k::TruncatedBabyStepGiantStepK<256>>(10);
        test_solver::<pollard_kangaroo::tbsgs_k::TruncatedBabyStepGiantStepK<1024>>(10);
    }

    #[test]
    #[cfg(feature = "naive_truncated_doubled_lookup")]
    fn test_naive_truncated_doubled_lookup_all_values_up_to_10bits() {
        // NaiveTruncatedDoubledLookup uses a table for 2*max_num_bits, so 10-bit test uses 20-bit table
        test_solver::<pollard_kangaroo::naive_truncated_doubled_lookup::NaiveTruncatedDoubledLookup>(
            10,
        );
    }
}
