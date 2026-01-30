use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek_ng::scalar::Scalar;
use pollard_kangaroo::bsgs::presets::BsgsPresets;
use pollard_kangaroo::bsgs::BabyGiant;
use pollard_kangaroo::bsgs_batched::presets::BsgsBatchedPresets;
use pollard_kangaroo::bsgs_batched::BabyGiantBatched;
use pollard_kangaroo::kangaroo::presets::Presets;
use pollard_kangaroo::kangaroo::Kangaroo;
use pollard_kangaroo::utils;
use std::ops::Mul;

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

/// Test BSGS-k with secrets that are multiples of m (65536).
/// These secrets cause gamma to hit the identity point during giant steps,
/// which would panic in double_and_compress_batch without proper handling.
///
/// For secret x = m * i, at giant step i:
///   gamma = g^x * (g^(-m))^i = g^(m*i) * g^(-m*i) = g^0 = identity
#[test]
fn bsgs_batched_handles_identity_point_secrets() {
    let bsgs32 = BabyGiantBatched::from_preset(BsgsBatchedPresets::BabyGiantBatched32).unwrap();

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

    for &secret in &problematic_secrets {
        let pk = RISTRETTO_BASEPOINT_POINT.mul(Scalar::from(secret));

        // Test with various k values
        for k in [1, 2, 4, 64, 256] {
            let result = bsgs32.solve_dlp(&pk, k, None).unwrap();
            assert_eq!(
                result,
                Some(secret),
                "Failed for secret={} with k={}",
                secret,
                k
            );
        }
    }
}

/// Confirm that the OLD broken code panics on identity point secrets.
/// This test uses should_panic to verify the bug existed.
#[test]
#[should_panic(expected = "assertion `left == right` failed")]
fn bsgs_batched_old_code_panics_on_identity() {
    let bsgs32 = BabyGiantBatched::from_preset(BsgsBatchedPresets::BabyGiantBatched32).unwrap();

    // m = 2^16 = 65536; secret = m causes identity at giant step 1
    let m: u64 = 65536;
    let secret = m;
    let pk = RISTRETTO_BASEPOINT_POINT.mul(Scalar::from(secret));

    // This should panic because the old code doesn't handle identity points
    // Use k=2 so we include the identity point in a batch (step 0 is pk, step 1 is identity)
    let _ = bsgs32.solve_dlp_old_broken(&pk, 2);
}
