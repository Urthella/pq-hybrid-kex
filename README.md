# pq-hybrid-kex

[X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/), the hybrid key
exchange that pairs ML-KEM-768 with X25519, written out so each step can be read next to the
draft. The code is about 100 lines and is checked against the draft's own test vectors.

## Why hybrid

A shared secret is safe if **either** half holds:

- **ML-KEM-768 (FIPS 203)** resists quantum computers, but it is new.
- **X25519** has years of scrutiny behind it, but falls to a large enough quantum computer.

X-Wing runs both and hashes the two secrets together:

```text
ss = SHA3-256(ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ "\.//^\")
```

Each half stays as it is. The combiner is the draft's.

## Use

```rust
let (secret_key, public_key) = pq_hybrid_kex::generate();

// The sender gets a shared secret and a ciphertext to send.
let (shared, ciphertext) = pq_hybrid_kex::encapsulate(&public_key)?;

// The receiver recovers the same secret from the ciphertext.
assert_eq!(secret_key.decapsulate(&ciphertext), shared);
```

| | Public key | Ciphertext | Secret key | Shared secret |
|---|---:|---:|---:|---:|
| X-Wing | 1216 B | 1120 B | 32 B | 32 B |

The secret key is a 32-byte seed. SHAKE256 expands it into the ML-KEM key and the X25519 key.

`generate` returns the key already expanded, as an `ExpandedKey`, following draft §5.5.1. To
store the key, save `secret_key.pack()`, the 32-byte seed. To load it, call
`ExpandedKey::unpack`. The expanded form has no byte encoding on purpose: the draft says it
must not pass between implementations.

`decapsulate(&ciphertext, &seed)` works straight from the seed. It is slower, because it
expands the key on every call.

## How it's checked

- **The draft's test vectors.** All three vectors from draft-11, Appendix C, are in
  [`tests/xwing-vectors.txt`](tests/xwing-vectors.txt). For each one the public key,
  ciphertext and shared secret must match byte for byte.
- **RustCrypto's `x-wing` crate.** Twenty random keys go through both implementations. The
  public keys, ciphertexts and shared secrets must be equal.
- **Tampering.** A flipped bit in either half of the ciphertext gives a different shared
  secret, not an error. That is ML-KEM's implicit rejection.
- **Bad public keys.** A public key whose ML-KEM coefficients are at or above the modulus is
  refused, as FIPS 203 §7.2 requires.
- **Mutation testing.** Thirteen deliberate bugs were planted one at a time, and the tests
  caught every one. The bugs included:
  - a changed label;
  - the hash inputs swapped or dropped;
  - the wrong SHAKE bytes used;
  - an X25519 input ignored;
  - randomness turned off;
  - `pack` losing the key.

## Speed

`cargo run --release --example bench` times X-Wing next to each half on its own. These are
rough numbers from one run on a desktop (µs per call):

| | keygen | encapsulate | decapsulate |
|---|---:|---:|---:|
| X-Wing, kept `ExpandedKey` | 239 | 350 | 327 |
| X-Wing, from the 32-byte seed | 239 | 350 | 527 |
| ML-KEM-768 alone | 143 | 160 | 225 |
| X25519 alone | 92 | 199 | 97 |

Each X-Wing operation costs about its two halves added together. The exception is
decapsulating from the seed, which first expands the key, and that costs a full keygen.
Keeping an `ExpandedKey` avoids that cost.

## Not for production

This is for reading and learning. For real use, choose
[RustCrypto's `x-wing`](https://crates.io/crates/x-wing). It tracks the draft and more
people review it. Specifically, this code:

- doesn't wipe secrets from memory;
- relies on `ml-kem` and `x25519-dalek` for constant-time behaviour;
- implements a draft that may still change.

## Credits

X-Wing was designed by Deirdre Connolly, Peter Schwabe and Bas Westerbaan, in
[draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).
The test vectors come from that draft. Code components of IETF documents are under the
Revised BSD License.

The two halves come from RustCrypto's [`ml-kem`](https://crates.io/crates/ml-kem) and
dalek's [`x25519-dalek`](https://crates.io/crates/x25519-dalek).

## Develop

```sh
cargo test
cargo run --release --example bench
```

Or `nix develop` for the pinned toolchain.

## License

MIT
