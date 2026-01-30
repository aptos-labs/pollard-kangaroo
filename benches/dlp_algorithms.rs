use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use pollard_kangaroo::bl12::presets::Presets;
use pollard_kangaroo::bl12::Bl12;
use pollard_kangaroo::bsgs::presets::BabyStepGiantStepPresets;
use pollard_kangaroo::bsgs::BabyStepGiantStep;
use pollard_kangaroo::bsgs_k::presets::BabyStepGiantStepKPresets;
use pollard_kangaroo::bsgs_k::BabyStepGiantStepK;
use pollard_kangaroo::utils;
use rand_core::OsRng;

fn bench_bl12_16(c: &mut Criterion) {
    let bl12_16 = Bl12::from_preset(Presets::Bl12_16).unwrap();

    c.bench_function("[BL12] 16-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(16).unwrap(),
            |(_sk, pk)| bl12_16.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

fn bench_bl12_32(c: &mut Criterion) {
    let bl12_32 = Bl12::from_preset(Presets::Bl12_32).unwrap();

    c.bench_function("[BL12] 32-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(32).unwrap(),
            |(_sk, pk)| bl12_32.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

fn bench_bl12_48(c: &mut Criterion) {
    let bl12_48 = Bl12::from_preset(Presets::Bl12_48).unwrap();

    c.bench_function("[BL12] 48-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(48).unwrap(),
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
    let bsgs32 =
        BabyStepGiantStep::from_preset(BabyStepGiantStepPresets::BabyStepGiantStep32).unwrap();

    c.bench_function("BSGS 32-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(32).unwrap(),
            |(_sk, pk)| bsgs32.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

/// Macro to generate benchmarks for different K values
macro_rules! bench_bsgs_k {
    ($name:ident, $k:expr) => {
        fn $name(c: &mut Criterion) {
            let bsgs = BabyStepGiantStepK::<$k>::from_preset(
                BabyStepGiantStepKPresets::BabyStepGiantStep32,
            )
            .unwrap();

            c.bench_function(&format!("BSGS-k K={} 32-bit secrets", $k), |b| {
                b.iter_batched(
                    || utils::generate_dlog_instance(32).unwrap(),
                    |(_sk, pk)| bsgs.solve_dlp(&pk, None),
                    BatchSize::SmallInput,
                )
            });
        }
    };
}

bench_bsgs_k!(bench_bsgs_k_1, 1);
bench_bsgs_k!(bench_bsgs_k_2, 2);
bench_bsgs_k!(bench_bsgs_k_4, 4);
bench_bsgs_k!(bench_bsgs_k_8, 8);
bench_bsgs_k!(bench_bsgs_k_16, 16);
bench_bsgs_k!(bench_bsgs_k_32, 32);
bench_bsgs_k!(bench_bsgs_k_64, 64);
bench_bsgs_k!(bench_bsgs_k_128, 128);
bench_bsgs_k!(bench_bsgs_k_256, 256);
bench_bsgs_k!(bench_bsgs_k_512, 512);
bench_bsgs_k!(bench_bsgs_k_1024, 1024);
bench_bsgs_k!(bench_bsgs_k_2048, 2048);
bench_bsgs_k!(bench_bsgs_k_4096, 4096);
bench_bsgs_k!(bench_bsgs_k_8192, 8192);
bench_bsgs_k!(bench_bsgs_k_16384, 16384);

/// Macro to generate benchmarks for different K values with small secrets
macro_rules! bench_bsgs_k_small {
    ($name:ident, $k:expr) => {
        fn $name(c: &mut Criterion) {
            let bsgs = BabyStepGiantStepK::<$k>::from_preset(
                BabyStepGiantStepKPresets::BabyStepGiantStep32,
            )
            .unwrap();

            c.bench_function(
                &format!("BSGS-k K={} 18-bit secrets (32-bit table)", $k),
                |b| {
                    b.iter_batched(
                        || utils::generate_dlog_instance(18).unwrap(),
                        |(_sk, pk)| bsgs.solve_dlp(&pk, None),
                        BatchSize::SmallInput,
                    )
                },
            );
        }
    };
}

bench_bsgs_k_small!(bench_bsgs_k_small_64, 64);
bench_bsgs_k_small!(bench_bsgs_k_small_128, 128);
bench_bsgs_k_small!(bench_bsgs_k_small_1024, 1024);
bench_bsgs_k_small!(bench_bsgs_k_small_2048, 2048);

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
criterion_group! {
    name = bsgs_k_32_group;
    config = Criterion::default().sample_size(50);
    targets =
        bench_bsgs_k_1,
        bench_bsgs_k_2,
        bench_bsgs_k_4,
        bench_bsgs_k_8,
        bench_bsgs_k_16,
        bench_bsgs_k_32,
        bench_bsgs_k_64,
        bench_bsgs_k_128,
        bench_bsgs_k_256,
        bench_bsgs_k_512,
        bench_bsgs_k_1024,
        bench_bsgs_k_2048,
        bench_bsgs_k_4096,
        bench_bsgs_k_8192,
        bench_bsgs_k_16384
}
criterion_group! {
    name = bsgs_k_32_small_group;
    config = Criterion::default().sample_size(100);
    targets =
        bench_bsgs_k_small_64,
        bench_bsgs_k_small_128,
        bench_bsgs_k_small_1024,
        bench_bsgs_k_small_2048
}

criterion_main!(
    bl12_16_group,
    bl12_32_group,
    bl12_48_group,
    point_ops_group,
    bsgs32_group,
    bsgs_k_32_group,
    bsgs_k_32_small_group
);
