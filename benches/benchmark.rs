#![allow(dead_code)]
#![allow(unused_imports)]
use criterion::{criterion_group, criterion_main, Criterion};
use playfair_cipher::cryptable::Cypher;
use playfair_cipher::{four_square::FourSquare, playfair::PlayFairKey, two_square::TwoSquare};
use rand::Rng;
use std::hint::black_box;

fn generate_input(chars: &[u8]) -> String {
    let mut result = String::with_capacity(20_000);
    let mut rng = rand::rng();
    for _i in 0..20_000 {
        result.push(chars[rng.random_range(0..chars.len())] as char);
    }
    result
}

fn generate_long_input() -> String {
    generate_input(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.- ()")
}

fn generate_long_decrypt_az09() -> String {
    generate_input(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
}

fn generate_long_decrypt_az() -> String {
    generate_input(b"ABCDEFGHIKLMNOPQRSTUVWXYZ")
}

fn bench_playfair_long_5_to_5_encrypt(c: &mut Criterion) {
    let cipher = PlayFairKey::new_5_to_5("MONARCHY");
    let input = generate_long_input();

    c.bench_function("Playfair encrypt 5 to 5 (20k)", |b| {
        b.iter(|| cipher.encrypt(black_box(&input)))
    });
}

fn bench_two_square_long_5_to_5_encrypt(c: &mut Criterion) {
    let cipher = TwoSquare::new_5_to_5("MONARCHY", "Whatever");
    let input = generate_long_input();

    c.bench_function("TwoSquare encrypt 5 to 5 (20k)", |b| {
        b.iter(|| cipher.encrypt(black_box(&input)))
    });
}

fn bench_four_square_long_5_to_5_encrypt(c: &mut Criterion) {
    let cipher = FourSquare::new_5_to_5("MONARCHY", "Whatever");
    let input = generate_long_input();

    c.bench_function("FourSquare encrypt 5 to 5 (20k)", |b| {
        b.iter(|| cipher.encrypt(black_box(&input)))
    });
}

fn bench_playfair_long_6_to_6_encrypt(c: &mut Criterion) {
    let cipher = PlayFairKey::new_6_to_6("MONARCHY");
    let input = generate_long_input();

    c.bench_function("Playfair encrypt 6 to 6 (20k)", |b| {
        b.iter(|| cipher.encrypt(black_box(&input)))
    });
}

fn bench_two_square_long_6_to_6_encrypt(c: &mut Criterion) {
    let cipher = TwoSquare::new_6_to_6("MONARCHY", "Whatever");
    let input = generate_long_input();

    c.bench_function("TwoSquare encrypt 6 to 6 (20k)", |b| {
        b.iter(|| cipher.encrypt(black_box(&input)))
    });
}

fn bench_four_square_long_6_to_6_encrypt(c: &mut Criterion) {
    let cipher = FourSquare::new_6_to_6("MONARCHY", "Whatever");
    let input = generate_long_input();

    c.bench_function("FourSquare encrypt 6 to 6 (20k)", |b| {
        b.iter(|| cipher.encrypt(black_box(&input)))
    });
}

fn bench_playfair_long_5_to_5_decrypt(c: &mut Criterion) {
    let cipher = PlayFairKey::new_5_to_5("MONARCHY");
    let input = generate_long_decrypt_az();

    c.bench_function("Playfair decrypt 5 to 5 (20k)", |b| {
        b.iter(|| cipher.decrypt(black_box(&input)))
    });
}

fn bench_two_square_long_5_to_5_decrypt(c: &mut Criterion) {
    let cipher = TwoSquare::new_5_to_5("MONARCHY", "Whatever");
    let input = generate_long_decrypt_az();

    c.bench_function("TwoSquare decrypt 5 to 5 (20k)", |b| {
        b.iter(|| cipher.decrypt(black_box(&input)))
    });
}

fn bench_four_square_long_5_to_5_decrypt(c: &mut Criterion) {
    let cipher = FourSquare::new_5_to_5("MONARCHY", "Whatever");
    let input = generate_long_decrypt_az();

    c.bench_function("FourSquare decrypt 5 to 5 (20k)", |b| {
        b.iter(|| cipher.decrypt(black_box(&input)))
    });
}

fn bench_playfair_long_6_to_6_decrypt(c: &mut Criterion) {
    let cipher = PlayFairKey::new_6_to_6("MONARCHY");
    let input = generate_long_decrypt_az09();

    c.bench_function("Playfair decrypt 6 to 6 (20k)", |b| {
        b.iter(|| cipher.decrypt(black_box(&input)))
    });
}

fn bench_two_square_long_6_to_6_decrypt(c: &mut Criterion) {
    let cipher = TwoSquare::new_6_to_6("MONARCHY", "Whatever");
    let input = generate_long_decrypt_az09();

    c.bench_function("TwoSquare decrypt 6 to 6 (20k)", |b| {
        b.iter(|| cipher.decrypt(black_box(&input)))
    });
}

fn bench_four_square_long_6_to_6_decrypt(c: &mut Criterion) {
    let cipher = FourSquare::new_6_to_6("MONARCHY", "Whatever");
    let input = generate_long_decrypt_az09();

    c.bench_function("FourSquare decrypt 6 to 6 (20k)", |b| {
        b.iter(|| cipher.decrypt(black_box(&input)))
    });
}

criterion_group!(name = benches; config = Criterion::default();
targets =
bench_playfair_long_5_to_5_encrypt,
bench_two_square_long_5_to_5_encrypt,
bench_four_square_long_5_to_5_encrypt,

bench_playfair_long_6_to_6_encrypt,
bench_two_square_long_6_to_6_encrypt,
bench_four_square_long_6_to_6_encrypt,

bench_playfair_long_5_to_5_decrypt,
bench_two_square_long_5_to_5_decrypt,
bench_four_square_long_5_to_5_decrypt,

bench_playfair_long_6_to_6_decrypt,
bench_two_square_long_6_to_6_decrypt,
bench_four_square_long_6_to_6_decrypt

);
criterion_main!(benches);
