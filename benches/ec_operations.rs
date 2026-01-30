//! Benchmarks for elliptic curve operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;

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

criterion_group!(ec_operations, bench_point_addition, bench_point_compression);
criterion_main!(ec_operations);
