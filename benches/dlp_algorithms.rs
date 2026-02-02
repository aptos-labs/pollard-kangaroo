//! Benchmarks for discrete log algorithms.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use pollard_kangaroo::bl12::precomputed_tables::PrecomputedTables as Bl12Tables;
use pollard_kangaroo::bl12::Bl12;
use pollard_kangaroo::bsgs::precomputed_tables::PrecomputedTables as BsgsTables;
use pollard_kangaroo::bsgs::BabyStepGiantStep;
use pollard_kangaroo::bsgs_k::precomputed_tables::PrecomputedTables as BsgsKTables;
use pollard_kangaroo::bsgs_k::BabyStepGiantStepK;
use pollard_kangaroo::naive_doubled_lookup::NaiveDoubledLookup;
use pollard_kangaroo::naive_lookup::NaiveLookup;
use pollard_kangaroo::utils;

// =============================================================================
// BL12 benchmarks
// =============================================================================

fn bench_bl12_32bit(c: &mut Criterion) {
    let bl12 = Bl12::from_precomputed_table(Bl12Tables::BernsteinLange32);

    c.bench_function("[BL12] 32-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(32).unwrap(),
            |(_sk, pk)| bl12.solve(&pk),
            BatchSize::SmallInput,
        )
    });
}

// =============================================================================
// BSGS benchmarks
// =============================================================================

fn bench_bsgs_32bit(c: &mut Criterion) {
    let bsgs = BabyStepGiantStep::from_precomputed_table(BsgsTables::Bsgs32);

    c.bench_function("[BSGS] 32-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(32).unwrap(),
            |(_sk, pk)| bsgs.solve(&pk),
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
        BabyStepGiantStepK::<K>::from_precomputed_table(BsgsKTables::BsgsK32);

    c.bench_function(&format!("[BSGS-k{}], {}", K, label_suffix), |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(secret_bits).unwrap(),
            |(_sk, pk)| bsgs.solve(&pk),
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

/// Benchmarks BSGS-k for 17-24 bit secrets (using 32-bit table) with varying K values.
fn bench_bsgs_k_17_to_24bit(c: &mut Criterion) {
    // BSGS-k32 for 17-24 bit secrets
    bench_bsgs_k::<32>(c, 17, "17-bit secrets (32-bit table)");
    bench_bsgs_k::<32>(c, 18, "18-bit secrets (32-bit table)");
    bench_bsgs_k::<32>(c, 19, "19-bit secrets (32-bit table)");
    bench_bsgs_k::<32>(c, 20, "20-bit secrets (32-bit table)");
    bench_bsgs_k::<32>(c, 21, "21-bit secrets (32-bit table)");
    bench_bsgs_k::<32>(c, 22, "22-bit secrets (32-bit table)");
    bench_bsgs_k::<32>(c, 23, "23-bit secrets (32-bit table)");
    bench_bsgs_k::<32>(c, 24, "24-bit secrets (32-bit table)");

    // Other K values for 18-bit secrets
    bench_bsgs_k::<64>(c, 18, "18-bit secrets (32-bit table)");
    bench_bsgs_k::<128>(c, 18, "18-bit secrets (32-bit table)");
    bench_bsgs_k::<1024>(c, 18, "18-bit secrets (32-bit table)");
    bench_bsgs_k::<2048>(c, 18, "18-bit secrets (32-bit table)");
}

// =============================================================================
// Naive Lookup from BSGS table benchmarks (reuses BSGS baby_steps)
// =============================================================================

fn bench_naive_lookup_from_bsgs_16bit(c: &mut Criterion) {
    // Reuses BSGS 32-bit table's baby_steps for 16-bit lookups
    let solver = NaiveLookup::from_bsgs_precomputed_table(BsgsTables::Bsgs32);

    c.bench_function("[Naive Lookup from BSGS] 16-bit secrets (re-using BSGS table for 32-bit DLs)", |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(16).unwrap(),
            |(_sk, pk)| solver.solve(&pk),
            BatchSize::SmallInput,
        )
    });
}

// =============================================================================
// Naive Doubled Lookup benchmarks (reuses BSGS-k tables)
// =============================================================================

fn bench_naive_doubled_lookup_16bit(c: &mut Criterion) {
    // Reuses BSGS-k 32-bit table for 16-bit lookups
    let solver = NaiveDoubledLookup::from_precomputed_table(BsgsKTables::BsgsK32);

    c.bench_function("[Naive Doubled Lookup] 16-bit secrets (re-using BSGS-k table for 32-bit DLs)", |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(16).unwrap(),
            |(_sk, pk)| solver.solve(&pk),
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
    name = bsgs_k_17_to_24bit_group;
    config = Criterion::default().sample_size(100);
    targets = bench_bsgs_k_17_to_24bit
}

criterion_group! {
    name = naive_lookup_from_bsgs_16bit_group;
    config = Criterion::default().sample_size(100);
    targets = bench_naive_lookup_from_bsgs_16bit
}

criterion_group! {
    name = naive_doubled_lookup_16bit_group;
    config = Criterion::default().sample_size(100);
    targets = bench_naive_doubled_lookup_16bit
}

criterion_main!(
    bl12_32bit_group,
    bsgs_32bit_group,
    bsgs_k_32bit_group,
    bsgs_k_17_to_24bit_group,
    naive_lookup_from_bsgs_16bit_group,
    naive_doubled_lookup_16bit_group
);
