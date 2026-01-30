use pollard_kangaroo::bsgs::presets::BsgsPresets;
use pollard_kangaroo::bsgs::BabyGiant;
use pollard_kangaroo::bsgs_batched::presets::BsgsBatchedPresets;
use pollard_kangaroo::bsgs_batched::BabyGiantBatched;
use pollard_kangaroo::kangaroo::presets::Presets;
use pollard_kangaroo::kangaroo::Kangaroo;
use pollard_kangaroo::utils;

#[test]
fn it_solves_16_bit_dl() {
    let kangaroo16 = Kangaroo::from_preset(Presets::Kangaroo16).unwrap();

    let (sk, pk) = utils::generate_keypair(16).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(kangaroo16.solve_dlp(&pk, None).unwrap().unwrap(), sk_u64);
}

#[test]
fn it_solves_32_bit_dl() {
    let kangaroo32 = Kangaroo::from_preset(Presets::Kangaroo32).unwrap();

    let (sk, pk) = utils::generate_keypair(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(kangaroo32.solve_dlp(&pk, None).unwrap().unwrap(), sk_u64);
}

#[test]
fn it_solves_48_bit_dl() {
    let kangaroo48 = Kangaroo::from_preset(Presets::Kangaroo48).unwrap();

    let (sk, pk) = utils::generate_keypair(48).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(kangaroo48.solve_dlp(&pk, None).unwrap().unwrap(), sk_u64);
}

#[test]
fn bsgs_solves_32_bit_dl() {
    let bsgs32 = BabyGiant::from_preset(BsgsPresets::BabyGiant32).unwrap();

    let (sk, pk) = utils::generate_keypair(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bsgs32.solve_dlp(&pk, None).unwrap().unwrap(), sk_u64);
}

#[test]
fn bsgs_batched_solves_32_bit_dl_k64() {
    let bsgs32 = BabyGiantBatched::from_preset(BsgsBatchedPresets::BabyGiantBatched32).unwrap();

    let (sk, pk) = utils::generate_keypair(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    // Test with k=64
    assert_eq!(bsgs32.solve_dlp(&pk, 64, None).unwrap().unwrap(), sk_u64);
}

#[test]
fn bsgs_batched_solves_32_bit_dl_k256() {
    let bsgs32 = BabyGiantBatched::from_preset(BsgsBatchedPresets::BabyGiantBatched32).unwrap();

    let (sk, pk) = utils::generate_keypair(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    // Test with k=256
    assert_eq!(bsgs32.solve_dlp(&pk, 256, None).unwrap().unwrap(), sk_u64);
}

#[test]
fn bsgs_batched_solves_32_bit_dl_k1024() {
    let bsgs32 = BabyGiantBatched::from_preset(BsgsBatchedPresets::BabyGiantBatched32).unwrap();

    let (sk, pk) = utils::generate_keypair(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    // Test with k=1024
    assert_eq!(bsgs32.solve_dlp(&pk, 1024, None).unwrap().unwrap(), sk_u64);
}
