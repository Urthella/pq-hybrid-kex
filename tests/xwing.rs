use pq_hybrid_kex::{
    CIPHERTEXT_LEN, ExpandedKey, InvalidPublicKey, PUBLIC_KEY_LEN, decapsulate, encapsulate,
    encapsulate_deterministic, generate, public_key,
};

struct Vector {
    seed: [u8; 32],
    pk: [u8; PUBLIC_KEY_LEN],
    eseed: [u8; 64],
    ct: [u8; CIPHERTEXT_LEN],
    ss: [u8; 32],
}

fn hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), 2 * N);
    std::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
}

/// The three test vectors in draft-connolly-cfrg-xwing-kem-11, Appendix C.
fn vectors() -> Vec<Vector> {
    let text = include_str!("xwing-vectors.txt");
    let blocks = text.split("\n\n").filter(|b| b.contains("seed "));
    blocks
        .map(|block| {
            let field = |name: &str| {
                block
                    .lines()
                    .find_map(|l| l.strip_prefix(&format!("{name} ")))
                    .unwrap()
            };
            assert_eq!(field("sk"), field("seed"), "the draft's sk is its seed");
            Vector {
                seed: hex(field("seed")),
                pk: hex(field("pk")),
                eseed: hex(field("eseed")),
                ct: hex(field("ct")),
                ss: hex(field("ss")),
            }
        })
        .collect()
}

#[test]
fn matches_the_drafts_test_vectors() {
    let vectors = vectors();
    assert_eq!(vectors.len(), 3);
    for (i, v) in vectors.iter().enumerate() {
        assert!(public_key(&v.seed) == v.pk, "vector {i}: public key");
        let (ss, ct) = encapsulate_deterministic(&v.pk, &v.eseed).unwrap();
        assert!(ct == v.ct, "vector {i}: ciphertext");
        assert_eq!(ss, v.ss, "vector {i}: shared secret from encapsulation");
        assert_eq!(
            decapsulate(&v.ct, &v.seed),
            v.ss,
            "vector {i}: shared secret from decapsulation"
        );

        let expanded = ExpandedKey::unpack(&v.seed);
        assert_eq!(expanded.pack(), v.seed, "vector {i}: packed key");
        assert!(
            expanded.public_key() == v.pk,
            "vector {i}: expanded public key"
        );
        assert_eq!(
            expanded.decapsulate(&v.ct),
            v.ss,
            "vector {i}: expanded decapsulation"
        );
    }
}

#[test]
fn agrees_with_rustcryptos_x_wing() {
    use x_wing::kem::{Decapsulate, Decapsulator, KeyExport};
    for _ in 0..20 {
        let (expanded, pk) = generate();
        let sk = expanded.pack();
        let theirs = x_wing::DecapsulationKey::from(sk);
        assert!(
            theirs.encapsulation_key().to_bytes().as_slice() == pk.as_slice(),
            "public keys differ"
        );

        let eseed: [u8; 64] = std::array::from_fn(|i| (i as u8).wrapping_mul(sk[i % 32]));
        let (ss, ct) = encapsulate_deterministic(&pk, &eseed).unwrap();
        let (their_ct, their_ss) = theirs
            .encapsulation_key()
            .encapsulate_deterministic((&eseed).into());
        assert!(their_ct.as_slice() == ct.as_slice(), "ciphertexts differ");
        assert_eq!(their_ss.as_slice(), ss.as_slice());
        assert_eq!(
            theirs.decapsulate(&their_ct).as_slice(),
            decapsulate(&ct, &sk).as_slice()
        );
    }
}

#[test]
fn round_trips_with_fresh_randomness() {
    for _ in 0..50 {
        let (sk, pk) = generate();
        let (ss, ct) = encapsulate(&pk).unwrap();
        assert_eq!(sk.decapsulate(&ct), ss);
        let (ss2, ct2) = encapsulate(&pk).unwrap();
        assert!(ss2 != ss && ct2 != ct, "two encapsulations should differ");
    }
}

#[test]
fn a_tampered_ciphertext_gives_a_different_secret_without_an_error() {
    let (sk, pk) = generate();
    let (ss, ct) = encapsulate(&pk).unwrap();
    // A bit flipped in the ML-KEM part, and in the X25519 part.
    for at in [0, 500, 1087, 1088, 1119] {
        let mut bad = ct;
        bad[at] ^= 1;
        assert_ne!(sk.decapsulate(&bad), ss, "flipped byte {at}");
    }
    // The wrong secret key doesn't get the secret either.
    let (other, _) = generate();
    assert_ne!(other.decapsulate(&ct), ss);
}

#[test]
fn a_public_key_with_out_of_range_coefficients_is_refused() {
    let (_, mut pk) = generate();
    // Every 12-bit coefficient set to 4095, above the modulus 3329.
    pk[..384].fill(0xff);
    assert_eq!(encapsulate(&pk).unwrap_err(), InvalidPublicKey);
}
