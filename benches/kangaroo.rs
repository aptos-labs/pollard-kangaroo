use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use pollard_kangaroo::kangaroo::presets::Presets;
use pollard_kangaroo::kangaroo::Kangaroo;
use pollard_kangaroo::utils;

fn bench_kangaroo16(c: &mut Criterion) {
    let kangaroo16 = Kangaroo::from_preset(Presets::Kangaroo16).unwrap();

    c.bench_function("16-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_keypair(16).unwrap(),
            |(_sk, pk)| kangaroo16.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

fn bench_kangaroo32(c: &mut Criterion) {
    let kangaroo32 = Kangaroo::from_preset(Presets::Kangaroo32).unwrap();

    c.bench_function("32-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_keypair(32).unwrap(),
            |(_sk, pk)| kangaroo32.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

fn bench_kangaroo48(c: &mut Criterion) {
    let kangaroo48 = Kangaroo::from_preset(Presets::Kangaroo48).unwrap();

    c.bench_function("48-bit secrets", |b| {
        b.iter_batched(
            || utils::generate_keypair(48).unwrap(),
            |(_sk, pk)| kangaroo48.solve_dlp(&pk, None),
            BatchSize::SmallInput,
        )
    });
}

criterion_group! {
    name = kangaroo16_group;
    config = Criterion::default().sample_size(200);
    targets = bench_kangaroo16
}
criterion_group! {
    name = kangaroo32_group;
    config = Criterion::default().sample_size(200);
    targets = bench_kangaroo32
}
criterion_group! {
    name = kangaroo48_group;
    config = Criterion::default().sample_size(10);
    targets = bench_kangaroo48
}
criterion_main!(kangaroo16_group, kangaroo32_group, kangaroo48_group);
