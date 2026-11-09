//! Rough timings for X-Wing next to its two halves on their own:
//! `cargo run --release --example bench`.

use std::hint::black_box;
use std::time::Instant;

use ml_kem::ml_kem_768::DecapsulationKey;
use ml_kem::{B32, Decapsulate, Seed};
use pq_hybrid_kex as xwing;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

const RUNS: u32 = 2000;

fn time<T>(name: &str, mut f: impl FnMut() -> T) {
    for _ in 0..RUNS / 10 {
        black_box(f());
    }
    let start = Instant::now();
    for _ in 0..RUNS {
        black_box(f());
    }
    let micros = (start.elapsed() / RUNS).as_secs_f64() * 1e6;
    println!("  {name:<22} {micros:>7.1} µs");
}

fn main() {
    let sk = [7u8; 32];
    let eseed = [9u8; 64];

    println!("X-Wing (public key 1216 B, ciphertext 1120 B, secret key 32 B)");
    let pk = xwing::public_key(&sk);
    let (_, ct) = xwing::encapsulate_deterministic(&pk, &eseed).unwrap();
    time("keygen", || xwing::public_key(black_box(&sk)));
    time("encapsulate", || {
        xwing::encapsulate_deterministic(black_box(&pk), &eseed)
    });
    time("decapsulate", || xwing::decapsulate(black_box(&ct), &sk));
    let expanded = xwing::ExpandedKey::unpack(&sk);
    time("decapsulate, kept key", || {
        black_box(&expanded).decapsulate(&ct)
    });

    println!("ML-KEM-768 alone (public key 1184 B, ciphertext 1088 B, seed 64 B)");
    let seed = Seed::from([7u8; 64]);
    let m = B32::from([9u8; 32]);
    let dk = DecapsulationKey::from_seed(seed);
    let ek = dk.encapsulation_key().clone();
    let (ct_m, _) = ek.encapsulate_deterministic(&m);
    time("keygen", || DecapsulationKey::from_seed(black_box(seed)));
    time("encapsulate", || {
        black_box(&ek).encapsulate_deterministic(&m)
    });
    time("decapsulate", || black_box(&dk).decapsulate(&ct_m));

    println!("X25519 alone (public key 32 B, ciphertext 32 B, secret key 32 B)");
    let pk_x = x25519(sk, X25519_BASEPOINT_BYTES);
    time("keygen", || x25519(black_box(sk), X25519_BASEPOINT_BYTES));
    time("encapsulate", || {
        let ek = black_box(sk);
        (x25519(ek, X25519_BASEPOINT_BYTES), x25519(ek, pk_x))
    });
    time("decapsulate", || x25519(black_box(sk), pk_x));
}
