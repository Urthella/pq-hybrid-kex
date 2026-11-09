//! X-Wing, the hybrid KEM from draft-connolly-cfrg-xwing-kem-11: ML-KEM-768 and X25519 run side
//! by side, their shared secrets hashed together with SHA3-256. It stays secure as long as either
//! one does, so a quantum computer that breaks X25519 isn't enough, and neither is a flaw found
//! in ML-KEM.
//!
//! Each function follows the draft's pseudocode, step by step, and the tests check the result
//! against the draft's test vectors.
//!
//! ```
//! let (secret_key, public_key) = pq_hybrid_kex::generate();
//! let (shared, ciphertext) = pq_hybrid_kex::encapsulate(&public_key).unwrap();
//! assert_eq!(secret_key.decapsulate(&ciphertext), shared);
//! ```

use ml_kem::ml_kem_768::{Ciphertext as MlKemCiphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{B32, Decapsulate, KeyExport, Seed};
use sha3::{Digest, Sha3_256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

pub const SECRET_KEY_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 1216;
pub const CIPHERTEXT_LEN: usize = 1120;
pub const SHARED_SECRET_LEN: usize = 32;

const ML_KEM_PUBLIC_KEY_LEN: usize = 1184;
const ML_KEM_CIPHERTEXT_LEN: usize = 1088;

/// `\.//^\`, a picture of a wing.
const XWING_LABEL: [u8; 6] = *b"\\.//^\\";

pub type SecretKey = [u8; SECRET_KEY_LEN];
pub type PublicKey = [u8; PUBLIC_KEY_LEN];
pub type Ciphertext = [u8; CIPHERTEXT_LEN];
pub type SharedSecret = [u8; SHARED_SECRET_LEN];

/// The ML-KEM half of a public key failed the check in FIPS 203 section 7.2: its coefficients
/// must all be below the modulus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPublicKey;

impl std::fmt::Display for InvalidPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a valid X-Wing public key")
    }
}

impl std::error::Error for InvalidPublicKey {}

/// A secret key expanded once and kept, as draft section 5.5.1 allows, so that decapsulating
/// skips the SHAKE256 expansion and the ML-KEM key generation. That pays off when one key opens
/// many ciphertexts, or opens one right after it was generated, as a TLS client does.
///
/// It has no byte form on purpose: the draft says an expanded key MUST NOT pass between
/// implementations. Store the 32 bytes from [`ExpandedKey::pack`] instead.
pub struct ExpandedKey {
    sk: SecretKey,
    dk_m: DecapsulationKey,
    sk_x: [u8; 32],
    pk_x: [u8; 32],
}

impl ExpandedKey {
    /// The draft's `UnpackDecapsulationKey`, which is `expandDecapsulationKey`: 96 bytes of
    /// SHAKE256 output from the 32-byte secret key become the ML-KEM seed (d, then z) and the
    /// X25519 secret.
    pub fn unpack(sk: &SecretKey) -> Self {
        let mut expanded = [0u8; 96];
        let mut shake = Shake256::default();
        shake.update(sk);
        shake.finalize_xof().read(&mut expanded);
        let seed = Seed::try_from(&expanded[0..64]).expect("64 bytes");
        let dk_m = DecapsulationKey::from_seed(seed);
        let sk_x: [u8; 32] = expanded[64..96].try_into().expect("32 bytes");
        let pk_x = x25519(sk_x, X25519_BASEPOINT_BYTES);
        Self {
            sk: *sk,
            dk_m,
            sk_x,
            pk_x,
        }
    }

    /// The draft's `PackDecapsulationKey`: the 32-byte secret key, the form to store.
    pub fn pack(&self) -> SecretKey {
        self.sk
    }

    /// The public key that goes with this secret key.
    pub fn public_key(&self) -> PublicKey {
        let mut pk = [0u8; PUBLIC_KEY_LEN];
        pk[..ML_KEM_PUBLIC_KEY_LEN].copy_from_slice(&self.dk_m.encapsulation_key().to_bytes());
        pk[ML_KEM_PUBLIC_KEY_LEN..].copy_from_slice(&self.pk_x);
        pk
    }

    /// The draft's `Decapsulate`. A ciphertext that was tampered with doesn't cause an error:
    /// ML-KEM rejects it implicitly, so the result is a shared secret the sender doesn't have.
    pub fn decapsulate(&self, ct: &Ciphertext) -> SharedSecret {
        let (ct_m, ct_x) = ct.split_at(ML_KEM_CIPHERTEXT_LEN);
        let ct_x: [u8; 32] = ct_x.try_into().expect("32 bytes");
        let ct_m = MlKemCiphertext::try_from(ct_m).expect("1088 bytes");
        let ss_m = self.dk_m.decapsulate(&ct_m);
        let ss_x = x25519(self.sk_x, ct_x);
        combine(&ss_m, &ss_x, &ct_x, &self.pk_x)
    }
}

/// The draft's `Combiner`: SHA3-256 over both shared secrets, the X25519 ciphertext and public
/// key, and the label. Hashing in the X25519 values binds the result to them.
fn combine(ss_m: &[u8], ss_x: &[u8; 32], ct_x: &[u8; 32], pk_x: &[u8; 32]) -> SharedSecret {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, XWING_LABEL);
    h.finalize().into()
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("the operating system's random number generator failed");
    bytes
}

/// The draft's `GenerateKeyPairDerand`: the public key that goes with a 32-byte secret key.
pub fn public_key(sk: &SecretKey) -> PublicKey {
    ExpandedKey::unpack(sk).public_key()
}

/// The draft's `GenerateKeyPair`: a random secret key, already expanded, and its public key.
pub fn generate() -> (ExpandedKey, PublicKey) {
    let sk = ExpandedKey::unpack(&random());
    let pk = sk.public_key();
    (sk, pk)
}

/// The draft's `EncapsulateDerand`, with the 64 bytes of randomness given: the first 32 for
/// ML-KEM, the last 32 as the ephemeral X25519 secret. Only for testing; use [`encapsulate`].
pub fn encapsulate_deterministic(
    pk: &PublicKey,
    eseed: &[u8; 64],
) -> Result<(SharedSecret, Ciphertext), InvalidPublicKey> {
    let (pk_m, pk_x) = pk.split_at(ML_KEM_PUBLIC_KEY_LEN);
    let pk_x: [u8; 32] = pk_x.try_into().expect("32 bytes");
    let ek_m = EncapsulationKey::new(pk_m.try_into().expect("1184 bytes"))
        .map_err(|_| InvalidPublicKey)?;

    let ek_x: [u8; 32] = eseed[32..64].try_into().expect("32 bytes");
    let ct_x = x25519(ek_x, X25519_BASEPOINT_BYTES);
    let ss_x = x25519(ek_x, pk_x);
    let m = B32::try_from(&eseed[0..32]).expect("32 bytes");
    let (ct_m, ss_m) = ek_m.encapsulate_deterministic(&m);

    let mut ct = [0u8; CIPHERTEXT_LEN];
    ct[..ML_KEM_CIPHERTEXT_LEN].copy_from_slice(&ct_m);
    ct[ML_KEM_CIPHERTEXT_LEN..].copy_from_slice(&ct_x);
    Ok((combine(&ss_m, &ss_x, &ct_x, &pk_x), ct))
}

/// The draft's `Encapsulate`: a fresh shared secret, and the ciphertext that carries it to the
/// holder of the secret key.
pub fn encapsulate(pk: &PublicKey) -> Result<(SharedSecret, Ciphertext), InvalidPublicKey> {
    encapsulate_deterministic(pk, &random())
}

/// The draft's `Decapsulate` from the 32-byte secret key. It expands the key first, which costs
/// as much as generating it; keep an [`ExpandedKey`] to decapsulate more than once.
pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> SharedSecret {
    ExpandedKey::unpack(sk).decapsulate(ct)
}
