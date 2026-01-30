//! Benchmarks for discrete log algorithms.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use pollard_kangaroo::bl12::precomputed_tables::PrecomputedTables as Bl12Tables;
use pollard_kangaroo::bl12::Bl12;
use pollard_kangaroo::bsgs::precomputed_tables::PrecomputedTables as BsgsTables;
use pollard_kangaroo::bsgs::BabyStepGiantStep;
use pollard_kangaroo::bsgs_k::precomputed_tables::PrecomputedTables as BsgsKTables;
use pollard_kangaroo::bsgs_k::BabyStepGiantStepK;
use pollard_kangaroo::naive_lookup::precomputed_tables::PrecomputedTables as NaiveLookupTables;
use pollard_kangaroo::naive_lookup::NaiveLookup;
use pollard_kangaroo::utils;

// =============================================================================
// BL12 benchmarks
// =============================================================================

fn bench_bl12_32bit(c: &mut Criterion) {
    let bl12 = Bl12::from_precomputed_table(Bl12Tables::Bl12_32).unwrap();

    c.bench_function("[BL12] 32-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(32).unwrap(),
            |(_sk, pk)| bl12.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

// =============================================================================
// BSGS benchmarks
// =============================================================================

fn bench_bsgs_32bit(c: &mut Criterion) {
    let bsgs = BabyStepGiantStep::from_precomputed_table(BsgsTables::BabyStepGiantStep32).unwrap();

    c.bench_function("[BSGS] 32-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(32).unwrap(),
            |(_sk, pk)| bsgs.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

// =============================================================================
// BSGS-k benchmarks
// =============================================================================

/// Generic benchmark for BSGS-k with compile-time K and runtime secret_bits.
fn bench_bsgs_k<const K: usize>(c: &mut Criterion, secret_bits: u8, label_suffix: &str) {
    let bsgs =
        BabyStepGiantStepK::<K>::from_precomputed_table(BsgsKTables::BabyStepGiantStep32).unwrap();

    c.bench_function(&format!("[BSGS-k{}], {}", K, label_suffix), |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(secret_bits).unwrap(),
            |(_sk, pk)| bsgs.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

/// Benchmarks BSGS-k for 32-bit secrets with varying K values.
fn bench_bsgs_k_32bit(c: &mut Criterion) {
    bench_bsgs_k::<1>(c, 32, "32-bit secrets");
    bench_bsgs_k::<2>(c, 32, "32-bit secrets");
    bench_bsgs_k::<4>(c, 32, "32-bit secrets");
    bench_bsgs_k::<8>(c, 32, "32-bit secrets");
    bench_bsgs_k::<16>(c, 32, "32-bit secrets");
    bench_bsgs_k::<32>(c, 32, "32-bit secrets");
    bench_bsgs_k::<64>(c, 32, "32-bit secrets");
    bench_bsgs_k::<128>(c, 32, "32-bit secrets");
    bench_bsgs_k::<256>(c, 32, "32-bit secrets");
    bench_bsgs_k::<512>(c, 32, "32-bit secrets");
    bench_bsgs_k::<1024>(c, 32, "32-bit secrets");
    bench_bsgs_k::<2048>(c, 32, "32-bit secrets");
    bench_bsgs_k::<4096>(c, 32, "32-bit secrets");
    bench_bsgs_k::<8192>(c, 32, "32-bit secrets");
    bench_bsgs_k::<16384>(c, 32, "32-bit secrets");
}

/// Benchmarks BSGS-k for 18-bit secrets (using 32-bit table) with varying K values.
fn bench_bsgs_k_18bit(c: &mut Criterion) {
    bench_bsgs_k::<64>(c, 18, "18-bit secrets (32-bit table)");
    bench_bsgs_k::<128>(c, 18, "18-bit secrets (32-bit table)");
    bench_bsgs_k::<1024>(c, 18, "18-bit secrets (32-bit table)");
    bench_bsgs_k::<2048>(c, 18, "18-bit secrets (32-bit table)");
}

// =============================================================================
// Naive Lookup benchmarks
// =============================================================================

fn bench_naive_lookup_16bit(c: &mut Criterion) {
    let naive = NaiveLookup::from_precomputed_table(NaiveLookupTables::NaiveLookup16).unwrap();

    c.bench_function("[Naive Lookup] 16-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(16).unwrap(),
            |(_sk, pk)| naive.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

// =============================================================================
// Criterion groups
// =============================================================================

criterion_group! {
    name = bl12_32bit_group;
    config = Criterion::default().sample_size(50);
    targets = bench_bl12_32bit
}

criterion_group! {
    name = bsgs_32bit_group;
    config = Criterion::default().sample_size(10);
    targets = bench_bsgs_32bit
}

criterion_group! {
    name = bsgs_k_32bit_group;
    config = Criterion::default().sample_size(10);
    targets = bench_bsgs_k_32bit
}

criterion_group! {
    name = bsgs_k_18bit_group;
    config = Criterion::default().sample_size(100);
    targets = bench_bsgs_k_18bit
}

criterion_group! {
    name = naive_lookup_16bit_group;
    config = Criterion::default().sample_size(100);
    targets = bench_naive_lookup_16bit
}

criterion_main!(
    bl12_32bit_group,
    bsgs_32bit_group,
    bsgs_k_32bit_group,
    bsgs_k_18bit_group,
    naive_lookup_16bit_group
);
