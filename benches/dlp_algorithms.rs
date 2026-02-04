//! Benchmarks for discrete log algorithms.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ristretto255_dlog::utils;
use ristretto255_dlog::DiscreteLogSolver;

// =============================================================================
// Generic benchmark function
// =============================================================================

/// Generic benchmark for any DiscreteLogSolver using precomputed tables.
///
/// - `table_bits`: passed to `from_precomputed_table()` (e.g., 32 for BSGS, 16 for NaiveLookup)
/// - `secret_bits`: size of secrets to generate for benchmarking
fn bench_solver<S: DiscreteLogSolver>(c: &mut Criterion, table_bits: u8, secret_bits: u8) {
    let solver = S::from_precomputed_table(table_bits);

    let label = if secret_bits == table_bits {
        format!("[{}], {}-bit secrets", S::algorithm_name(), secret_bits)
    } else {
        format!(
            "[{}], {}-bit secrets ({}-bit table)",
            S::algorithm_name(),
            secret_bits,
            table_bits
        )
    };

    c.bench_function(&label, |b| {
        b.iter_batched(
            || utils::generate_dlog_instance(secret_bits).unwrap(),
            |(_sk, pk)| solver.solve(&pk),
            BatchSize::SmallInput,
        )
    });
}

// =============================================================================
// BL12 benchmarks
// =============================================================================

fn bench_bl12_32bit(c: &mut Criterion) {
    bench_solver::<ristretto255_dlog::bl12::Bl12>(c, 32, 32);
}

// =============================================================================
// BSGS benchmarks
// =============================================================================

fn bench_bsgs_32bit(c: &mut Criterion) {
    bench_solver::<ristretto255_dlog::bsgs::BabyStepGiantStep>(c, 32, 32);
}

// =============================================================================
// BSGS-k benchmarks
// =============================================================================

/// Benchmarks BSGS-k for 32-bit secrets with varying K values.
fn bench_bsgs_k_32bit(c: &mut Criterion) {
    use ristretto255_dlog::bsgs_k::BabyStepGiantStepK;

    bench_solver::<BabyStepGiantStepK<1>>(c, 32, 16);
    bench_solver::<BabyStepGiantStepK<1>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<2>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<4>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<8>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<16>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<32>>(c, 32, 16);
    bench_solver::<BabyStepGiantStepK<32>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<64>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<128>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<256>>(c, 32, 16);
    bench_solver::<BabyStepGiantStepK<256>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<512>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<1024>>(c, 32, 16);
    bench_solver::<BabyStepGiantStepK<1024>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<2048>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<4096>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<8192>>(c, 32, 32);
    bench_solver::<BabyStepGiantStepK<16384>>(c, 32, 32);
}

/// Benchmarks BSGS-k for 16-24 bit secrets (using 32-bit table) with varying K values.
fn bench_bsgs_k_16_to_24bit(c: &mut Criterion) {
    use ristretto255_dlog::bsgs_k::BabyStepGiantStepK;

    // BSGS-k32 for 16-24 bit secrets
    bench_solver::<BabyStepGiantStepK<32>>(c, 32, 16);
    bench_solver::<BabyStepGiantStepK<32>>(c, 32, 17);
    bench_solver::<BabyStepGiantStepK<32>>(c, 32, 18);
    bench_solver::<BabyStepGiantStepK<32>>(c, 32, 19);
    bench_solver::<BabyStepGiantStepK<32>>(c, 32, 20);
    bench_solver::<BabyStepGiantStepK<32>>(c, 32, 21);
    bench_solver::<BabyStepGiantStepK<32>>(c, 32, 22);
    bench_solver::<BabyStepGiantStepK<32>>(c, 32, 23);
    bench_solver::<BabyStepGiantStepK<32>>(c, 32, 24);

    // Other K values for 18-bit secrets
    bench_solver::<BabyStepGiantStepK<64>>(c, 32, 18);
    bench_solver::<BabyStepGiantStepK<128>>(c, 32, 18);
    bench_solver::<BabyStepGiantStepK<1024>>(c, 32, 18);
    bench_solver::<BabyStepGiantStepK<2048>>(c, 32, 18);
}

// =============================================================================
// TBSGS-k benchmarks (Truncated BSGS-k with 8-byte truncated keys)
// =============================================================================

/// Benchmarks TBSGS-k for 32-bit secrets with varying K values.
fn bench_tbsgs_k_32bit(c: &mut Criterion) {
    use ristretto255_dlog::tbsgs_k::TruncatedBabyStepGiantStepK;

    bench_solver::<TruncatedBabyStepGiantStepK<1>>(c, 32, 16);
    bench_solver::<TruncatedBabyStepGiantStepK<1>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<2>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<4>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<8>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<16>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<32>>(c, 32, 16);
    bench_solver::<TruncatedBabyStepGiantStepK<32>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<64>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<128>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<256>>(c, 32, 16);
    bench_solver::<TruncatedBabyStepGiantStepK<256>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<512>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<1024>>(c, 32, 16);
    bench_solver::<TruncatedBabyStepGiantStepK<1024>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<2048>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<4096>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<8192>>(c, 32, 32);
    bench_solver::<TruncatedBabyStepGiantStepK<16384>>(c, 32, 32);
}

/// Benchmarks TBSGS-k for 16-24 bit secrets (using 32-bit table) with varying K values.
fn bench_tbsgs_k_16_to_24bit(c: &mut Criterion) {
    use ristretto255_dlog::tbsgs_k::TruncatedBabyStepGiantStepK;

    // TBSGS-k32 for 16-24 bit secrets
    bench_solver::<TruncatedBabyStepGiantStepK<32>>(c, 32, 16);
    bench_solver::<TruncatedBabyStepGiantStepK<32>>(c, 32, 17);
    bench_solver::<TruncatedBabyStepGiantStepK<32>>(c, 32, 18);
    bench_solver::<TruncatedBabyStepGiantStepK<32>>(c, 32, 19);
    bench_solver::<TruncatedBabyStepGiantStepK<32>>(c, 32, 20);
    bench_solver::<TruncatedBabyStepGiantStepK<32>>(c, 32, 21);
    bench_solver::<TruncatedBabyStepGiantStepK<32>>(c, 32, 22);
    bench_solver::<TruncatedBabyStepGiantStepK<32>>(c, 32, 23);
    bench_solver::<TruncatedBabyStepGiantStepK<32>>(c, 32, 24);

    // Other K values for 18-bit secrets
    bench_solver::<TruncatedBabyStepGiantStepK<64>>(c, 32, 18);
    bench_solver::<TruncatedBabyStepGiantStepK<128>>(c, 32, 18);
    bench_solver::<TruncatedBabyStepGiantStepK<1024>>(c, 32, 18);
    bench_solver::<TruncatedBabyStepGiantStepK<2048>>(c, 32, 18);
}

// =============================================================================
// Naive Lookup benchmarks (16-bit, reusing 32-bit tables)
// =============================================================================

fn bench_naive_lookup_16bit(c: &mut Criterion) {
    bench_solver::<ristretto255_dlog::naive_lookup::NaiveLookup>(c, 16, 16);
}

fn bench_naive_doubled_lookup_16bit(c: &mut Criterion) {
    bench_solver::<ristretto255_dlog::naive_doubled_lookup::NaiveDoubledLookup>(c, 16, 16);
}

fn bench_naive_truncated_doubled_lookup_16bit(c: &mut Criterion) {
    bench_solver::<ristretto255_dlog::naive_truncated_doubled_lookup::NaiveTruncatedDoubledLookup>(
        c, 16, 16,
    );
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
    config = Criterion::default().sample_size(20);
    targets = bench_bsgs_32bit
}

criterion_group! {
    name = bsgs_k_32bit_group;
    config = Criterion::default().sample_size(20);
    targets = bench_bsgs_k_32bit
}

criterion_group! {
    name = bsgs_k_16_to_24bit_group;
    config = Criterion::default().sample_size(100);
    targets = bench_bsgs_k_16_to_24bit
}

criterion_group! {
    name = tbsgs_k_32bit_group;
    config = Criterion::default().sample_size(20);
    targets = bench_tbsgs_k_32bit
}

criterion_group! {
    name = tbsgs_k_16_to_24bit_group;
    config = Criterion::default().sample_size(100);
    targets = bench_tbsgs_k_16_to_24bit
}

criterion_group! {
    name = naive_lookup_16bit_group;
    config = Criterion::default().sample_size(100);
    targets = bench_naive_lookup_16bit
}

criterion_group! {
    name = naive_doubled_lookup_16bit_group;
    config = Criterion::default().sample_size(100);
    targets = bench_naive_doubled_lookup_16bit
}

criterion_group! {
    name = naive_truncated_doubled_lookup_16bit_group;
    config = Criterion::default().sample_size(100);
    targets = bench_naive_truncated_doubled_lookup_16bit
}

criterion_main!(
    bl12_32bit_group,
    bsgs_32bit_group,
    bsgs_k_32bit_group,
    bsgs_k_16_to_24bit_group,
    tbsgs_k_32bit_group,
    tbsgs_k_16_to_24bit_group,
    naive_lookup_16bit_group,
    naive_doubled_lookup_16bit_group,
    naive_truncated_doubled_lookup_16bit_group
);
