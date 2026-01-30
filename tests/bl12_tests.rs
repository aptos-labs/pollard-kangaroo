use pollard_kangaroo::bl12::precomputed_tables::PrecomputedTables as Bl12Tables;
use pollard_kangaroo::bl12::Bl12;
use pollard_kangaroo::bsgs::precomputed_tables::PrecomputedTables as BsgsTables;
use pollard_kangaroo::bsgs::BabyStepGiantStep;
use pollard_kangaroo::bsgs_k::precomputed_tables::PrecomputedTables as BsgsKTables;
use pollard_kangaroo::bsgs_k::BabyStepGiantStepK;
use pollard_kangaroo::utils;

#[test]
fn it_solves_32_bit_dl() {
    let bl12_32 = Bl12::from_precomputed_table(Bl12Tables::Bl12_32).unwrap();

    let (sk, pk) = utils::generate_dlog_instance(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bl12_32.solve_dlp(&pk, None).unwrap(), sk_u64);
}

#[test]
fn it_solves_48_bit_dl() {
    let bl12_48 = Bl12::from_precomputed_table(Bl12Tables::Bl12_48).unwrap();

    let (sk, pk) = utils::generate_dlog_instance(48).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bl12_48.solve_dlp(&pk, None).unwrap(), sk_u64);
}

#[test]
fn bsgs_solves_32_bit_dl() {
    let bsgs32 =
        BabyStepGiantStep::from_precomputed_table(BsgsTables::BabyStepGiantStep32).unwrap();

    let (sk, pk) = utils::generate_dlog_instance(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bsgs32.solve_dlp(&pk, None).unwrap(), sk_u64);
}

#[test]
fn bsgs_k_solves_32_bit_dl_k64() {
    let bsgs32 =
        BabyStepGiantStepK::<64>::from_precomputed_table(BsgsKTables::BabyStepGiantStep32).unwrap();

    let (sk, pk) = utils::generate_dlog_instance(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bsgs32.solve_dlp(&pk, None).unwrap(), sk_u64);
}

#[test]
fn bsgs_k_solves_32_bit_dl_k256() {
    let bsgs32 =
        BabyStepGiantStepK::<256>::from_precomputed_table(BsgsKTables::BabyStepGiantStep32)
            .unwrap();

    let (sk, pk) = utils::generate_dlog_instance(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bsgs32.solve_dlp(&pk, None).unwrap(), sk_u64);
}

#[test]
fn bsgs_k_solves_32_bit_dl_k1024() {
    let bsgs32 =
        BabyStepGiantStepK::<1024>::from_precomputed_table(BsgsKTables::BabyStepGiantStep32)
            .unwrap();

    let (sk, pk) = utils::generate_dlog_instance(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bsgs32.solve_dlp(&pk, None).unwrap(), sk_u64);
}
