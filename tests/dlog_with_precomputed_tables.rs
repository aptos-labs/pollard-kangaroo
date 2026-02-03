//! Tests using precomputed tables.
//!
//! These tests use a deterministic RNG seeded from system randomness.
//! The seed is printed at the start of each test for reproducibility.

mod dlog_with_precomputed_tables {
    use pollard_kangaroo::utils;
    use pollard_kangaroo::DiscreteLogSolver;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, RngCore, SeedableRng};

    /// Creates a deterministic RNG seeded from system randomness and prints the seed.
    fn create_seeded_rng(test_name: &str) -> ChaCha20Rng {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        println!(
            "[{}] RNG seed: {}",
            test_name,
            seed.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        ChaCha20Rng::from_seed(seed)
    }

    /// Generic test for any DiscreteLogSolver using precomputed tables.
    fn test_solver<S: DiscreteLogSolver>(max_num_bits: u8) {
        let mut rng = create_seeded_rng(S::algorithm_name());
        let solver = S::from_precomputed_table(max_num_bits);

        let (sk, pk) = utils::generate_dlog_instance_with_rng(max_num_bits, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        assert_eq!(
            solver.solve(&pk).unwrap(),
            sk_u64,
            "{} failed for {}-bit secret",
            S::algorithm_name(),
            max_num_bits
        );
    }

    // =============================================================================
    // 32-bit solver tests
    // =============================================================================

    #[test]
    #[cfg(feature = "bl12_table32")]
    fn bl12_solves_some_32_bit() {
        test_solver::<pollard_kangaroo::bl12::Bl12>(32);
    }

    #[test]
    #[cfg(feature = "bsgs_table32")]
    fn bsgs_solves_some_32_bit() {
        test_solver::<pollard_kangaroo::bsgs::BabyStepGiantStep>(32);
    }

    #[test]
    #[cfg(feature = "bsgs_k_table32")]
    fn bsgs_k_solves_some_32_bit() {
        test_solver::<pollard_kangaroo::bsgs_k::BabyStepGiantStepK<64>>(32);
        test_solver::<pollard_kangaroo::bsgs_k::BabyStepGiantStepK<256>>(32);
        test_solver::<pollard_kangaroo::bsgs_k::BabyStepGiantStepK<1024>>(32);
    }

    #[test]
    #[cfg(feature = "tbsgs_k_table32")]
    fn tbsgs_k_solves_some_32_bit() {
        test_solver::<pollard_kangaroo::tbsgs_k::TruncatedBabyStepGiantStepK<32>>(32);

        test_solver::<pollard_kangaroo::tbsgs_k::TruncatedBabyStepGiantStepK<64>>(32);
    }

    // =============================================================================
    // 16-bit solver tests (naive lookups)
    // =============================================================================

    #[test]
    #[cfg(feature = "bsgs_table32")]
    fn naive_lookup_solves_some_16_bit() {
        test_solver::<pollard_kangaroo::naive_lookup::NaiveLookup>(16);
    }

    #[test]
    #[cfg(feature = "bsgs_k_table32")]
    fn naive_doubled_lookup_solves_some_16_bit() {
        test_solver::<pollard_kangaroo::naive_doubled_lookup::NaiveDoubledLookup>(16);
    }

    #[test]
    #[cfg(feature = "tbsgs_k_table32")]
    fn naive_truncated_doubled_lookup_solves_some_16_bit() {
        test_solver::<pollard_kangaroo::naive_truncated_doubled_lookup::NaiveTruncatedDoubledLookup>(
            16,
        );
    }

    // =============================================================================
    // BL12-specific test (uses randomized solver)
    // =============================================================================

    #[test]
    #[ignore]
    #[cfg(feature = "bl12_table32")]
    fn bl12_solves_all_16bits() {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use curve25519_dalek::ristretto::RistrettoPoint;
        use pollard_kangaroo::bl12::Bl12;

        let bl12: Bl12 = DiscreteLogSolver::from_precomputed_table(32);
        let g = RISTRETTO_BASEPOINT_POINT;

        // Start with g^0 = identity, then increment via EC addition
        let mut pk = RistrettoPoint::default(); // identity

        for value in 0..=65535u64 {
            if value % 200 == 0 {
                println!("Testing value {}/65535...", value);
            }

            let result = bl12
                .solve(&pk)
                .unwrap_or_else(|_| panic!("BL12 failed for value {}", value));
            assert_eq!(result, value, "BL12 returned wrong value for x={}", value);

            // g^(x+1) = g^x + g
            pk = pk + g;
        }
        println!("All 65536 values passed!");
    }
}
