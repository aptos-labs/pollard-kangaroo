use pollard_kangaroo::bsgs::presets::BsgsPresets;
use pollard_kangaroo::bsgs::BabyGiant;
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
