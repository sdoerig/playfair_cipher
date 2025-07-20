#![allow(dead_code)]
#![allow(unused_imports)]

use criterion::{criterion_group, criterion_main, Criterion};
use playfair_cipher::cryptable::Cypher;
use playfair_cipher::{four_square::FourSquare, playfair::PlayFairKey, two_square::TwoSquare};
use std::hint::black_box;

fn generate_long_input() -> String {
    (0..20_000)
        .map(|i| ((b'A' + (i % 26) as u8) as char))
        .collect()
}

fn generate_long_input_with_digits() -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut result = String::with_capacity(20_000);
    for i in 0..20_000 {
        result.push(CHARS[i % CHARS.len()] as char);
    }
    result
}

fn bench_playfair(c: &mut Criterion) {
    print!("Playfair");
    let cipher = PlayFairKey::new_5_to_5("MONARCHY");
    let input = "INSTRUMENTS";

    c.bench_function("Playfair encrypt", |b| {
        b.iter(|| cipher.encrypt(black_box(input)))
    });
}

fn bench_playfair_long(c: &mut Criterion) {
    let cipher = PlayFairKey::new_5_to_5("MONARCHY");
    let input = generate_long_input();

    c.bench_function("Playfair encrypt (20k)", |b| {
        b.iter(|| cipher.encrypt(black_box(&input)))
    });
}

fn bench_two_square(c: &mut Criterion) {
    let cipher = TwoSquare::new_5_to_5("EXAMPLE", "KEYWORD");
    let input = "INSTRUMENTS";

    c.bench_function("TwoSquare encrypt", |b| {
        b.iter(|| cipher.encrypt(black_box(input)))
    });
}

fn bench_two_square_long(c: &mut Criterion) {
    let cipher = TwoSquare::new_5_to_5("MONARCHY", "Whatever");
    let input = generate_long_input();

    c.bench_function("TwoSquare encrypt (20k)", |b| {
        b.iter(|| cipher.encrypt(black_box(&input)))
    });
}

fn bench_four_square(c: &mut Criterion) {
    let cipher = FourSquare::new_5_to_5("EXAMPLE", "KEYWORD");
    let input = "INSTRUMENTS";

    c.bench_function("FourSquare encrypt", |b| {
        b.iter(|| cipher.encrypt(black_box(input)))
    });
}

fn bench_four_square_long(c: &mut Criterion) {
    let cipher = FourSquare::new_5_to_5("MONARCHY", "Whatever");
    let input = generate_long_input();

    c.bench_function("FourSquare encrypt (20k)", |b| {
        b.iter(|| cipher.encrypt(black_box(&input)))
    });
}

criterion_group!(name = benches; config = Criterion::default(); 
targets = bench_playfair, bench_playfair_long, bench_two_square, bench_two_square_long, bench_four_square, bench_four_square_long);
criterion_main!(benches);
