//! Tests using precomputed tables.
//!
//! These tests use a deterministic RNG seeded from system randomness.
//! The seed is printed at the start of each test for reproducibility.

mod dlog_with_precomputed_tables {
    use pollard_kangaroo::bl12::precomputed_tables::PrecomputedTables as Bl12Tables;
    use pollard_kangaroo::bl12::Bl12;
    use pollard_kangaroo::bsgs::precomputed_tables::PrecomputedTables as BsgsTables;
    use pollard_kangaroo::bsgs::BabyStepGiantStep;
    use pollard_kangaroo::bsgs_k::precomputed_tables::PrecomputedTables as BsgsKTables;
    use pollard_kangaroo::bsgs_k::BabyStepGiantStepK;
    use pollard_kangaroo::naive_lookup::precomputed_tables::PrecomputedTables as NaiveLookupTables;
    use pollard_kangaroo::naive_lookup::NaiveLookup;
    use pollard_kangaroo::utils;
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

    #[test]
    fn bl12_solves_32_bit() {
        let mut rng = create_seeded_rng("bl12_solves_32_bit");
        let bl12_32 = Bl12::from_precomputed_table(Bl12Tables::Bl12_32).unwrap();

        let (sk, pk) = utils::generate_dlog_instance_with_rng(32, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // Use the seeded RNG for the solver as well (BL12 is randomized)
        assert_eq!(
            bl12_32.solve_dlp_with_rng(&pk, None, &mut rng).unwrap(),
            sk_u64
        );
    }

    #[test]
    fn bsgs_solves_32_bit() {
        let mut rng = create_seeded_rng("bsgs_solves_32_bit");
        let bsgs32 =
            BabyStepGiantStep::from_precomputed_table(BsgsTables::BabyStepGiantStep32).unwrap();

        let (sk, pk) = utils::generate_dlog_instance_with_rng(32, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // BSGS is deterministic, no RNG needed for solver
        assert_eq!(bsgs32.solve_dlp(&pk, None).unwrap(), sk_u64);
    }

    #[test]
    fn bsgs_k64_solves_32_bit() {
        let mut rng = create_seeded_rng("bsgs_k64_solves_32_bit");
        let bsgs32 =
            BabyStepGiantStepK::<64>::from_precomputed_table(BsgsKTables::BabyStepGiantStep32)
                .unwrap();

        let (sk, pk) = utils::generate_dlog_instance_with_rng(32, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // BSGS-k is deterministic, no RNG needed for solver
        assert_eq!(bsgs32.solve_dlp(&pk, None).unwrap(), sk_u64);
    }

    #[test]
    fn bsgs_k256_solves_32_bit() {
        let mut rng = create_seeded_rng("bsgs_k256_solves_32_bit");
        let bsgs32 =
            BabyStepGiantStepK::<256>::from_precomputed_table(BsgsKTables::BabyStepGiantStep32)
                .unwrap();

        let (sk, pk) = utils::generate_dlog_instance_with_rng(32, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // BSGS-k is deterministic, no RNG needed for solver
        assert_eq!(bsgs32.solve_dlp(&pk, None).unwrap(), sk_u64);
    }

    #[test]
    fn bsgs_k1024_solves_32_bit() {
        let mut rng = create_seeded_rng("bsgs_k1024_solves_32_bit");
        let bsgs32 =
            BabyStepGiantStepK::<1024>::from_precomputed_table(BsgsKTables::BabyStepGiantStep32)
                .unwrap();

        let (sk, pk) = utils::generate_dlog_instance_with_rng(32, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // BSGS-k is deterministic, no RNG needed for solver
        assert_eq!(bsgs32.solve_dlp(&pk, None).unwrap(), sk_u64);
    }

    #[test]
    fn naive_lookup_solves_16_bit() {
        let mut rng = create_seeded_rng("naive_lookup_solves_16_bit");
        let naive = NaiveLookup::from_precomputed_table(NaiveLookupTables::NaiveLookup16).unwrap();

        let (sk, pk) = utils::generate_dlog_instance_with_rng(16, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // Naive lookup is deterministic, no RNG needed for solver
        assert_eq!(naive.solve_dlp(&pk, None).unwrap(), sk_u64);
    }
}
