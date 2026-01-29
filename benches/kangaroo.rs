use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek_ng::scalar::Scalar;
use pollard_kangaroo::kangaroo::presets::Presets;
use pollard_kangaroo::kangaroo::Kangaroo;
use pollard_kangaroo::utils;
use rand_core::OsRng;

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

fn bench_point_addition(c: &mut Criterion) {
    // Generate two random points
    let p1 = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut OsRng);
    let p2 = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut OsRng);

    c.bench_function("ristretto255 point addition", |b| {
        b.iter(|| black_box(p1) + black_box(p2))
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
criterion_group!(point_addition_group, bench_point_addition);
criterion_main!(
    kangaroo16_group,
    kangaroo32_group,
    kangaroo48_group,
    point_addition_group
);
