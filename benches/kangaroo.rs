use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek_ng::scalar::Scalar;
use pollard_kangaroo::bsgs::presets::BsgsPresets;
use pollard_kangaroo::bsgs::BabyGiant;
use pollard_kangaroo::bsgs_batched::presets::BsgsBatchedPresets;
use pollard_kangaroo::bsgs_batched::BabyGiantBatched;
use pollard_kangaroo::kangaroo::presets::Presets;
use pollard_kangaroo::kangaroo::Kangaroo;
use pollard_kangaroo::utils;
use rand_core::OsRng;

fn bench_kangaroo16(c: &mut Criterion) {
    let kangaroo16 = Kangaroo::from_preset(Presets::Kangaroo16).unwrap();

    c.bench_function("Kangaroo 16-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_keypair(16).unwrap(),
            |(_sk, pk)| kangaroo16.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

fn bench_kangaroo32(c: &mut Criterion) {
    let kangaroo32 = Kangaroo::from_preset(Presets::Kangaroo32).unwrap();

    c.bench_function("Kangaroo 32-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_keypair(32).unwrap(),
            |(_sk, pk)| kangaroo32.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

fn bench_kangaroo48(c: &mut Criterion) {
    let kangaroo48 = Kangaroo::from_preset(Presets::Kangaroo48).unwrap();

    c.bench_function("Kangaroo 48-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_keypair(48).unwrap(),
            |(_sk, pk)| kangaroo48.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

fn bench_point_addition(c: &mut Criterion) {
    let p1 = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut OsRng);
    let p2 = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut OsRng);

    c.bench_function("ristretto255 point addition", |b| {
        b.iter(|| black_box(p1) + black_box(p2))
    });
}

fn bench_point_compression(c: &mut Criterion) {
    let p = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut OsRng);

    c.bench_function("ristretto255 point compression", |b| {
        b.iter(|| black_box(p).compress())
    });
}

fn bench_bsgs32(c: &mut Criterion) {
    let bsgs32 = BabyGiant::from_preset(BsgsPresets::BabyGiant32).unwrap();

    c.bench_function("BSGS 32-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_keypair(32).unwrap(),
            |(_sk, pk)| bsgs32.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

fn bench_bsgs_batched32(c: &mut Criterion) {
    let bsgs32 = BabyGiantBatched::from_preset(BsgsBatchedPresets::BabyGiantBatched32).unwrap();

    // k values: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384
    let k_values: Vec<usize> = (0..=14).map(|exp| 1usize << exp).collect();

    let mut group = c.benchmark_group("BSGS-k 32-bit secrets");
    group.sample_size(50);

    for k in k_values {
        group.bench_with_input(BenchmarkId::from_parameter(k), &k, |b, &k| {
            b.iter_batched(
                || utils::generate_keypair(32).unwrap(),
                |(_sk, pk)| bsgs32.solve_dlp(&pk, k, None),
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

criterion_group! {
    name = kangaroo16_group;
    config = Criterion::default().sample_size(100);
    targets = bench_kangaroo16
}
criterion_group! {
    name = kangaroo32_group;
    config = Criterion::default().sample_size(100);
    targets = bench_kangaroo32
}
criterion_group! {
    name = kangaroo48_group;
    config = Criterion::default().sample_size(10);
    targets = bench_kangaroo48
}
criterion_group!(
    point_ops_group,
    bench_point_addition,
    bench_point_compression
);
criterion_group! {
    name = bsgs32_group;
    config = Criterion::default().sample_size(50);
    targets = bench_bsgs32
}
criterion_group!(bsgs_batched32_group, bench_bsgs_batched32);

criterion_main!(
    kangaroo16_group,
    kangaroo32_group,
    kangaroo48_group,
    point_ops_group,
    bsgs32_group,
    bsgs_batched32_group
);
