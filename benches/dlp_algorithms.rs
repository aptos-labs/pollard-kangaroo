use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use pollard_kangaroo::bl12::presets::Presets;
use pollard_kangaroo::bl12::Bl12;
use pollard_kangaroo::bsgs::presets::BsgsPresets;
use pollard_kangaroo::bsgs::BabyGiant;
use pollard_kangaroo::bsgs_k::presets::BsgsKPresets;
use pollard_kangaroo::bsgs_k::BabyGiantK;
use pollard_kangaroo::utils;
use rand_core::OsRng;

fn bench_bl12_16(c: &mut Criterion) {
    let bl12_16 = Bl12::from_preset(Presets::Bl12_16).unwrap();

    c.bench_function("[BL12] 16-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_keypair(16).unwrap(),
            |(_sk, pk)| bl12_16.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

fn bench_bl12_32(c: &mut Criterion) {
    let bl12_32 = Bl12::from_preset(Presets::Bl12_32).unwrap();

    c.bench_function("[BL12] 32-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_keypair(32).unwrap(),
            |(_sk, pk)| bl12_32.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

fn bench_bl12_48(c: &mut Criterion) {
    let bl12_48 = Bl12::from_preset(Presets::Bl12_48).unwrap();

    c.bench_function("[BL12] 48-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_keypair(48).unwrap(),
            |(_sk, pk)| bl12_48.solve_dlp(&pk, None),
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

fn bench_bsgs_k_32(c: &mut Criterion) {
    let bsgs32 = BabyGiantK::from_preset(BsgsKPresets::BabyGiantK32).unwrap();

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

fn bench_bsgs_k_32_small_secrets(c: &mut Criterion) {
    let bsgs32 = BabyGiantK::from_preset(BsgsKPresets::BabyGiantK32).unwrap();

    // k values: 64, 128, 1024, 2048
    let k_values: Vec<usize> = vec![64, 128, 1024, 2048];

    // Use 18-bit secrets for faster benchmarks (uses 32-bit table)
    let mut group = c.benchmark_group("BSGS-k 18-bit small secrets (32-bit table)");
    group.sample_size(100);

    for k in k_values {
        group.bench_with_input(BenchmarkId::from_parameter(k), &k, |b, &k| {
            b.iter_batched(
                || utils::generate_keypair(18).unwrap(),
                |(_sk, pk)| bsgs32.solve_dlp(&pk, k, None),
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

criterion_group! {
    name = bl12_16_group;
    config = Criterion::default().sample_size(100);
    targets = bench_bl12_16
}
criterion_group! {
    name = bl12_32_group;
    config = Criterion::default().sample_size(100);
    targets = bench_bl12_32
}
criterion_group! {
    name = bl12_48_group;
    config = Criterion::default().sample_size(10);
    targets = bench_bl12_48
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
criterion_group!(bsgs_k_32_group, bench_bsgs_k_32);
criterion_group!(bsgs_k_32_small_group, bench_bsgs_k_32_small_secrets);

criterion_main!(
    bl12_16_group,
    bl12_32_group,
    bl12_48_group,
    point_ops_group,
    bsgs32_group,
    bsgs_k_32_group,
    bsgs_k_32_small_group
);
