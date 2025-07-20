#![allow(dead_code)]
#![allow(unused_imports)]

use criterion::{criterion_group, criterion_main, Criterion};
use playfair_cipher::cryptable::Cypher;
use playfair_cipher::{four_square::FourSquare, playfair::PlayFairKey, two_square::TwoSquare};
use std::hint::black_box;

fn bench_playfair(c: &mut Criterion) {
    print!("Playfair");
    let cipher = PlayFairKey::new_5_to_5("MONARCHY");
    let input = "INSTRUMENTS";

    c.bench_function("Playfair encrypt", |b| {
        b.iter(|| cipher.encrypt(black_box(input)))
    });
}

fn bench_two_square(c: &mut Criterion) {
    let cipher = TwoSquare::new_5_to_5("EXAMPLE", "KEYWORD");
    let input = "INSTRUMENTS";

    c.bench_function("TwoSquare encrypt", |b| {
        b.iter(|| cipher.encrypt(black_box(input)))
    });
}

fn bench_four_square(c: &mut Criterion) {
    let cipher = FourSquare::new_5_to_5("EXAMPLE", "KEYWORD");
    let input = "INSTRUMENTS";

    c.bench_function("FourSquare encrypt", |b| {
        b.iter(|| cipher.encrypt(black_box(input)))
    });
}

criterion_group!(name = benches; config = Criterion::default(); targets = bench_playfair);
criterion_main!(benches);
