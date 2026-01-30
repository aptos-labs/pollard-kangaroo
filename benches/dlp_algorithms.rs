//! Benchmarks for discrete log algorithms.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use pollard_kangaroo::bl12::precomputed_tables::PrecomputedTables as Bl12Tables;
use pollard_kangaroo::bl12::Bl12;
use pollard_kangaroo::bsgs::precomputed_tables::PrecomputedTables as BsgsTables;
use pollard_kangaroo::bsgs::BabyStepGiantStep;
use pollard_kangaroo::bsgs_k::precomputed_tables::PrecomputedTables as BsgsKTables;
use pollard_kangaroo::bsgs_k::BabyStepGiantStepK;
use pollard_kangaroo::utils;

fn bench_bl12_32(c: &mut Criterion) {
    let bl12_32 = Bl12::from_precomputed_table(Bl12Tables::Bl12_32).unwrap();

    c.bench_function("[BL12] 32-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(32).unwrap(),
            |(_sk, pk)| bl12_32.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

fn bench_bl12_48(c: &mut Criterion) {
    let bl12_48 = Bl12::from_precomputed_table(Bl12Tables::Bl12_48).unwrap();

    c.bench_function("[BL12] 48-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(48).unwrap(),
            |(_sk, pk)| bl12_48.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

fn bench_bsgs32(c: &mut Criterion) {
    let bsgs32 =
        BabyStepGiantStep::from_precomputed_table(BsgsTables::BabyStepGiantStep32).unwrap();

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
            let bsgs =
                BabyStepGiantStepK::<$k>::from_precomputed_table(BsgsKTables::BabyStepGiantStep32)
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

bench_bsgs_k!(bench_bsgs_k1, 1);
bench_bsgs_k!(bench_bsgs_k2, 2);
bench_bsgs_k!(bench_bsgs_k4, 4);
bench_bsgs_k!(bench_bsgs_k8, 8);
bench_bsgs_k!(bench_bsgs_k16, 16);
bench_bsgs_k!(bench_bsgs_k32, 32);
bench_bsgs_k!(bench_bsgs_k64, 64);
bench_bsgs_k!(bench_bsgs_k128, 128);
bench_bsgs_k!(bench_bsgs_k256, 256);
bench_bsgs_k!(bench_bsgs_k512, 512);
bench_bsgs_k!(bench_bsgs_k1024, 1024);
bench_bsgs_k!(bench_bsgs_k2048, 2048);
bench_bsgs_k!(bench_bsgs_k4096, 4096);
bench_bsgs_k!(bench_bsgs_k8192, 8192);
bench_bsgs_k!(bench_bsgs_k16384, 16384);

/// Macro to generate benchmarks for different K values with small secrets
macro_rules! bench_bsgs_k_small {
    ($name:ident, $k:expr) => {
        fn $name(c: &mut Criterion) {
            let bsgs =
                BabyStepGiantStepK::<$k>::from_precomputed_table(BsgsKTables::BabyStepGiantStep32)
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
    name = bl12_32bit_group;
    config = Criterion::default().sample_size(100);
    targets = bench_bl12_32
}
criterion_group! {
    name = bl12_48bit_group;
    config = Criterion::default().sample_size(10);
    targets = bench_bl12_48
}
criterion_group! {
    name = bsgs_32bit_group;
    config = Criterion::default().sample_size(50);
    targets = bench_bsgs32
}
criterion_group! {
    name = bsgs_32bit_k32_group;
    config = Criterion::default().sample_size(50);
    targets =
        bench_bsgs_k1,
        bench_bsgs_k2,
        bench_bsgs_k4,
        bench_bsgs_k8,
        bench_bsgs_k16,
        bench_bsgs_k32,
        bench_bsgs_k64,
        bench_bsgs_k128,
        bench_bsgs_k256,
        bench_bsgs_k512,
        bench_bsgs_k1024,
        bench_bsgs_k2048,
        bench_bsgs_k4096,
        bench_bsgs_k8192,
        bench_bsgs_k16384
}
criterion_group! {
    name = bsgs_32bit_k32_small_group;
    config = Criterion::default().sample_size(100);
    targets =
        bench_bsgs_k_small_64,
        bench_bsgs_k_small_128,
        bench_bsgs_k_small_1024,
        bench_bsgs_k_small_2048
}

criterion_main!(
    bl12_32bit_group,
    bl12_48bit_group,
    bsgs_32bit_group,
    bsgs_32bit_k32_group,
    bsgs_32bit_k32_small_group
);
