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
    use pollard_kangaroo::naive_doubled_lookup::NaiveDoubledLookup;
    use pollard_kangaroo::naive_lookup::NaiveLookup;
    use pollard_kangaroo::tbsgs_k::precomputed_tables::PrecomputedTables as TbsgsKTables;
    use pollard_kangaroo::tbsgs_k::TruncatedBabyStepGiantStepK;
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
        let bl12_32 = Bl12::from_precomputed_table(Bl12Tables::BernsteinLange32);

        let (sk, pk) = utils::generate_dlog_instance_with_rng(32, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // Use the seeded RNG for the solver as well (BL12 is randomized)
        assert_eq!(
            bl12_32
                .solve_with_timeout_and_rng(&pk, None, &mut rng)
                .unwrap(),
            sk_u64
        );
    }

    #[test]
    fn bsgs_solves_32_bit() {
        let mut rng = create_seeded_rng("bsgs_solves_32_bit");
        let bsgs32 = BabyStepGiantStep::from_precomputed_table(BsgsTables::Bsgs32);

        let (sk, pk) = utils::generate_dlog_instance_with_rng(32, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // BSGS is deterministic, no RNG needed for solver
        assert_eq!(bsgs32.solve(&pk).unwrap(), sk_u64);
    }

    #[test]
    fn bsgs_k64_solves_32_bit() {
        let mut rng = create_seeded_rng("bsgs_k64_solves_32_bit");
        let bsgs32 = BabyStepGiantStepK::<64>::from_precomputed_table(BsgsKTables::BsgsK32);

        let (sk, pk) = utils::generate_dlog_instance_with_rng(32, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // BSGS-k is deterministic, no RNG needed for solver
        assert_eq!(bsgs32.solve(&pk).unwrap(), sk_u64);
    }

    #[test]
    fn bsgs_k256_solves_32_bit() {
        let mut rng = create_seeded_rng("bsgs_k256_solves_32_bit");
        let bsgs32 = BabyStepGiantStepK::<256>::from_precomputed_table(BsgsKTables::BsgsK32);

        let (sk, pk) = utils::generate_dlog_instance_with_rng(32, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // BSGS-k is deterministic, no RNG needed for solver
        assert_eq!(bsgs32.solve(&pk).unwrap(), sk_u64);
    }

    #[test]
    fn bsgs_k1024_solves_32_bit() {
        let mut rng = create_seeded_rng("bsgs_k1024_solves_32_bit");
        let bsgs32 = BabyStepGiantStepK::<1024>::from_precomputed_table(BsgsKTables::BsgsK32);

        let (sk, pk) = utils::generate_dlog_instance_with_rng(32, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // BSGS-k is deterministic, no RNG needed for solver
        assert_eq!(bsgs32.solve(&pk).unwrap(), sk_u64);
    }

    #[test]
    fn naive_doubled_lookup_solves_16_bit() {
        let mut rng = create_seeded_rng("naive_doubled_lookup_solves_16_bit");
        // Reuses BSGS-k 32-bit table for 16-bit lookups
        let solver = NaiveDoubledLookup::from_precomputed_table(BsgsKTables::BsgsK32);

        let (sk, pk) = utils::generate_dlog_instance_with_rng(16, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // Naive doubled lookup is deterministic
        assert_eq!(solver.solve(&pk).unwrap(), sk_u64);
    }

    #[test]
    fn tbsgs_k32_solves_32_bit() {
        let mut rng = create_seeded_rng("tbsgs_k32_solves_32_bit");
        let tbsgs32 =
            TruncatedBabyStepGiantStepK::<32>::from_precomputed_table(TbsgsKTables::TbsgsK32);

        let (sk, pk) = utils::generate_dlog_instance_with_rng(32, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // TBSGS-k is deterministic, no RNG needed for solver
        assert_eq!(tbsgs32.solve(&pk).unwrap(), sk_u64);
    }

    #[test]
    fn tbsgs_k64_solves_32_bit() {
        let mut rng = create_seeded_rng("tbsgs_k64_solves_32_bit");
        let tbsgs32 =
            TruncatedBabyStepGiantStepK::<64>::from_precomputed_table(TbsgsKTables::TbsgsK32);

        let (sk, pk) = utils::generate_dlog_instance_with_rng(32, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // TBSGS-k is deterministic, no RNG needed for solver
        assert_eq!(tbsgs32.solve(&pk).unwrap(), sk_u64);
    }

    #[test]
    fn naive_lookup_from_bsgs_solves_16_bit() {
        let mut rng = create_seeded_rng("naive_lookup_from_bsgs_solves_16_bit");
        // Reuses BSGS 32-bit table's baby_steps for 16-bit lookups
        let solver = NaiveLookup::from_precomputed_table(BsgsTables::Bsgs32);

        let (sk, pk) = utils::generate_dlog_instance_with_rng(16, &mut rng).unwrap();
        let sk_u64 = utils::scalar_to_u64(&sk);

        // Naive lookup is deterministic
        assert_eq!(solver.solve(&pk).unwrap(), sk_u64);
    }

    #[test]
    #[ignore]
    fn bl12_solves_all_16bits() {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use curve25519_dalek::ristretto::RistrettoPoint;

        let bl12 = Bl12::from_precomputed_table(Bl12Tables::BernsteinLange32);
        let g = RISTRETTO_BASEPOINT_POINT;

        // Start with g^0 = identity, then increment via EC addition
        let mut pk = RistrettoPoint::default(); // identity

        for value in 0..=65535u64 {
            if value % 200 == 0 {
                println!("Testing value {}/65535...", value);
            }

            let result = bl12
                .solve(&pk)
                .expect(&format!("BL12 failed for value {}", value));
            assert_eq!(result, value, "BL12 returned wrong value for x={}", value);

            // g^(x+1) = g^x + g
            pk = pk + g;
        }
        println!("All 65536 values passed!");
    }
}
