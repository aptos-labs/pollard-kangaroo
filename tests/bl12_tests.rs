use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use pollard_kangaroo::bl12::presets::Presets;
use pollard_kangaroo::bl12::Bl12;
use pollard_kangaroo::bsgs::presets::BabyStepGiantStepPresets;
use pollard_kangaroo::bsgs::BabyStepGiantStep;
use pollard_kangaroo::bsgs_k::presets::BabyStepGiantStepKPresets;
use pollard_kangaroo::bsgs_k::BabyStepGiantStepK;
use pollard_kangaroo::utils;
use std::ops::Mul;

#[test]
fn it_solves_16_bit_dl() {
    let bl12_16 = Bl12::from_preset(Presets::Bl12_16).unwrap();

    let (sk, pk) = utils::generate_dlog_instance(16).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bl12_16.solve_dlp(&pk, None).unwrap(), sk_u64);
}

#[test]
fn it_solves_32_bit_dl() {
    let bl12_32 = Bl12::from_preset(Presets::Bl12_32).unwrap();

    let (sk, pk) = utils::generate_dlog_instance(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bl12_32.solve_dlp(&pk, None).unwrap(), sk_u64);
}

#[test]
fn it_solves_48_bit_dl() {
    let bl12_48 = Bl12::from_preset(Presets::Bl12_48).unwrap();

    let (sk, pk) = utils::generate_dlog_instance(48).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bl12_48.solve_dlp(&pk, None).unwrap(), sk_u64);
}

#[test]
fn bsgs_solves_32_bit_dl() {
    let bsgs32 =
        BabyStepGiantStep::from_preset(BabyStepGiantStepPresets::BabyStepGiantStep32).unwrap();

    let (sk, pk) = utils::generate_dlog_instance(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bsgs32.solve_dlp(&pk, None).unwrap(), sk_u64);
}

#[test]
fn bsgs_k_solves_32_bit_dl_k64() {
    let bsgs32 =
        BabyStepGiantStepK::<64>::from_preset(BabyStepGiantStepKPresets::BabyStepGiantStep32)
            .unwrap();

    let (sk, pk) = utils::generate_dlog_instance(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bsgs32.solve_dlp(&pk, None).unwrap(), sk_u64);
}

#[test]
fn bsgs_k_solves_32_bit_dl_k256() {
    let bsgs32 =
        BabyStepGiantStepK::<256>::from_preset(BabyStepGiantStepKPresets::BabyStepGiantStep32)
            .unwrap();

    let (sk, pk) = utils::generate_dlog_instance(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bsgs32.solve_dlp(&pk, None).unwrap(), sk_u64);
}

#[test]
fn bsgs_k_solves_32_bit_dl_k1024() {
    let bsgs32 =
        BabyStepGiantStepK::<1024>::from_preset(BabyStepGiantStepKPresets::BabyStepGiantStep32)
            .unwrap();

    let (sk, pk) = utils::generate_dlog_instance(32).unwrap();
    let sk_u64 = utils::scalar_to_u64(&sk);

    assert_eq!(bsgs32.solve_dlp(&pk, None).unwrap(), sk_u64);
}

/// Test BSGS-k with secrets that are multiples of m (65536).
/// These secrets cause gamma to hit the identity point during giant steps.
///
/// For secret x = m * i, at giant step i:
///   gamma = g^x * (g^(-m))^i = g^(m*i) * g^(-m*i) = g^0 = identity
///
/// The curve25519-dalek library handles identity correctly in double_and_compress_batch.
#[test]
fn bsgs_k_handles_identity_point_secrets() {
    // m = 2^16 = 65536 for 32-bit table
    let m: u64 = 65536;

    // Test secrets that are multiples of m (these hit identity during giant steps)
    let problematic_secrets = [
        0u64,        // identity at step 0 (handled by early return, but let's test anyway)
        m,           // identity at step 1
        2 * m,       // identity at step 2
        3 * m,       // identity at step 3
        m + 1,       // near multiple of m
        m - 1,       // near multiple of m
        2 * m + 100, // offset from multiple
    ];

    // Test with K=64
    let bsgs64 =
        BabyStepGiantStepK::<64>::from_preset(BabyStepGiantStepKPresets::BabyStepGiantStep32)
            .unwrap();

    for &secret in &problematic_secrets {
        let pk = RISTRETTO_BASEPOINT_POINT.mul(Scalar::from(secret));
        let result = bsgs64.solve_dlp(&pk, None).unwrap();
        assert_eq!(result, secret, "Failed for secret={} with K=64", secret);
    }

    // Test with K=256
    let bsgs256 =
        BabyStepGiantStepK::<256>::from_preset(BabyStepGiantStepKPresets::BabyStepGiantStep32)
            .unwrap();

    for &secret in &problematic_secrets {
        let pk = RISTRETTO_BASEPOINT_POINT.mul(Scalar::from(secret));
        let result = bsgs256.solve_dlp(&pk, None).unwrap();
        assert_eq!(result, secret, "Failed for secret={} with K=256", secret);
    }
}
