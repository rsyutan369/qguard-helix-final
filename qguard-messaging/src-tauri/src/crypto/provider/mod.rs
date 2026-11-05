//! The QGuard cryptographic boundary.
//!
//! Every primitive the app performs goes through this module; nothing else in
//! the crate names `aes_gcm`, `sha2`, `sha3`, `hkdf`, `hmac`, `x25519_dalek`,
//! `ed25519_dalek` or `pqcrypto_*`. That is what makes the cryptographic module
//! replaceable (docs/FIPS_140_3.md):
//!
//! * default — `rustcrypto.rs`: the RustCrypto / dalek / PQClean crates this
//!   app has always shipped. Not a validated module.
//! * `--features wolfcrypt` — `wolfcrypt.rs`: the same calls routed into
//!   wolfCrypt. Built from a wolfSSL FIPS 140-3 package it is a validated
//!   module for the algorithms on that package's certificate.
//!
//! What the boundary enforces for both backends:
//! * AES-GCM encryption nonces are generated inside the module and handed
//!   back (FIPS 140-3 IG C.H). No caller can choose one.
//! * Known-answer self-tests (`selftest.rs`) run before the first keyed
//!   operation. If any fails, every keyed operation refuses from then on.
//! * Random bytes come from the backend's generator, never from elsewhere.
//!
//! Hashing and random generation are infallible here (as `rand::OsRng` and the
//! `sha3` crate always were); a module that cannot do either panics, exactly
//! like `OsRng` does.

mod policy;
#[cfg(any(not(feature = "wolfcrypt"), test))]
pub(crate) mod rustcrypto;
mod selftest;
pub mod status;
#[cfg(feature = "wolfcrypt")]
pub(crate) mod wolfcrypt;

#[cfg(not(feature = "wolfcrypt"))]
use rustcrypto as backend;
#[cfg(feature = "wolfcrypt")]
use wolfcrypt as backend;

pub use policy::{
    approved_mode, approved_mode_forced, set_approved_mode, APPROVED_PASSWORD_MIN_CHARS,
    APPROVED_PBKDF2_ITERATIONS, APPROVED_PBKDF2_PRF,
};
pub use selftest::{self_test_report, SelfTestReport, SelfTestResult};

use zeroize::Zeroizing;

use crate::error::{QGuardError, Result};

pub const AES_GCM_NONCE_BYTES: usize = 12;
pub const AES_GCM_TAG_BYTES: usize = 16;
pub const MLKEM1024_PUBLIC_KEY_BYTES: usize = 1568;
pub const MLKEM1024_SECRET_KEY_BYTES: usize = 3168;
pub const MLKEM1024_CIPHERTEXT_BYTES: usize = 1568;

const MODULE_FAILURE: &str = "cryptographic module failure";

/// Hash functions the boundary exposes (also the HMAC / HKDF / PBKDF2 PRFs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
}

impl Hash {
    pub const fn output_bytes(self) -> usize {
        match self {
            Hash::Sha256 | Hash::Sha3_256 => 32,
            Hash::Sha512 | Hash::Sha3_512 => 64,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Hash::Sha256 => "SHA-256",
            Hash::Sha512 => "SHA-512",
            Hash::Sha3_256 => "SHA3-256",
            Hash::Sha3_512 => "SHA3-512",
        }
    }
}

/// ML-DSA parameter sets in use (FIPS 204).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsa {
    /// Messaging identity (shared with other devices).
    Ml65,
    /// Quantum Vault high-security profile.
    Ml87,
}

impl MlDsa {
    pub const fn label(self) -> &'static str {
        match self {
            MlDsa::Ml65 => "ML-DSA-65",
            MlDsa::Ml87 => "ML-DSA-87",
        }
    }
    pub const fn public_key_bytes(self) -> usize {
        match self {
            MlDsa::Ml65 => 1952,
            MlDsa::Ml87 => 2592,
        }
    }
    pub const fn secret_key_bytes(self) -> usize {
        match self {
            MlDsa::Ml65 => 4032,
            MlDsa::Ml87 => 4896,
        }
    }
    pub const fn signature_bytes(self) -> usize {
        match self {
            MlDsa::Ml65 => 3309,
            MlDsa::Ml87 => 4627,
        }
    }
}

/// Which module answers calls in this build.
pub fn module_identity() -> status::ModuleIdentity {
    backend::identity()
}

/// Refuse keyed work once a self-test has failed.
fn operational() -> Result<()> {
    let report = self_test_report();
    if report.passed {
        Ok(())
    } else {
        Err(QGuardError::Crypto(format!(
            "cryptographic self-test failed ({}); encryption, key agreement and signing are disabled on this device",
            report.failed_names().join(", ")
        )))
    }
}

// ---- random ---------------------------------------------------------------

/// Fill `out` from the module's random generator.
pub fn fill_random(out: &mut [u8]) {
    backend::random(out).expect("random generator failure");
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill_random(&mut out);
    out
}

// ---- AES-256-GCM ----------------------------------------------------------

/// The output of [`aes256gcm_seal`]: the module-chosen nonce, ciphertext and tag.
pub struct Sealed {
    pub nonce: [u8; AES_GCM_NONCE_BYTES],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; AES_GCM_TAG_BYTES],
}

pub fn aes256gcm_seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    operational()?;
    let (nonce, ciphertext, tag) = backend::aes256gcm_seal(key, aad, plaintext)?;
    Ok(Sealed { nonce, ciphertext, tag })
}

pub fn aes256gcm_open(key: &[u8; 32], nonce: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    operational()?;
    let (Ok(nonce), Ok(tag)) = (
        <&[u8; AES_GCM_NONCE_BYTES]>::try_from(nonce),
        <&[u8; AES_GCM_TAG_BYTES]>::try_from(tag),
    ) else {
        return Err(QGuardError::Crypto("invalid AES-GCM envelope".to_string()));
    };
    backend::aes256gcm_open(key, nonce, aad, ciphertext, tag)?
        .ok_or_else(|| QGuardError::Crypto("AEAD authentication failed".to_string()))
}

// ---- hashes ---------------------------------------------------------------

fn digest<const N: usize>(hash: Hash, data: &[u8]) -> [u8; N] {
    debug_assert_eq!(hash.output_bytes(), N);
    let mut out = [0u8; N];
    backend::hash(hash, data, &mut out).expect(MODULE_FAILURE);
    out
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    digest(Hash::Sha3_256, data)
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    digest(Hash::Sha3_512, data)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    digest(Hash::Sha256, data)
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    digest(Hash::Sha512, data)
}

/// Incremental SHA3-256, for files and streams.
#[derive(Clone)]
pub struct Sha3_256Hasher(backend::Sha3_256State);

impl Sha3_256Hasher {
    pub fn new() -> Self {
        Self(backend::Sha3_256State::new().expect(MODULE_FAILURE))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data).expect(MODULE_FAILURE);
    }

    pub fn finalize(self) -> [u8; 32] {
        self.0.finalize().expect(MODULE_FAILURE)
    }
}

impl Default for Sha3_256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

// ---- MAC / KDF ------------------------------------------------------------

pub fn hmac_sha3_256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    operational()?;
    let mut out = [0u8; 32];
    backend::hmac(Hash::Sha3_256, key, data, &mut out)?;
    Ok(out)
}

/// Constant-time comparison for MACs and verifiers.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// HKDF (RFC 5869 / SP 800-56C r2 two-step) with SHA3-256. `salt: None` is
/// HashLen zero bytes.
pub fn hkdf_sha3_256(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    operational()?;
    if out.is_empty() || out.len() > 255 * 32 {
        return Err(QGuardError::Crypto("invalid HKDF output length".to_string()));
    }
    backend::hkdf(Hash::Sha3_256, salt, ikm, info, out)
}

/// PBKDF2 (SP 800-132 / RFC 8018) with HMAC-`prf`.
pub fn pbkdf2(prf: Hash, password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> Result<()> {
    operational()?;
    if iterations == 0 || out.is_empty() {
        return Err(QGuardError::Crypto("invalid PBKDF2 parameters".to_string()));
    }
    backend::pbkdf2(prf, password, salt, iterations, out)
}

/// Argon2id (RFC 9106). NOT a FIPS-approved function and not part of any
/// backend: the standard-mode password stretch, and the read path for
/// credentials sealed before approved mode was switched on.
pub fn argon2id(secret: &[u8], salt: &[u8], memory_kib: u32, iterations: u32, lanes: u32, out: &mut [u8]) -> Result<()> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(memory_kib, iterations, lanes, Some(out.len()))
        .map_err(|e| QGuardError::Crypto(format!("argon2id params: {e}")))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret, salt, out)
        .map_err(|e| QGuardError::Crypto(format!("argon2id stretch failed: {e}")))
}

// ---- X25519 ---------------------------------------------------------------

/// An X25519 result. `contributory` is false for the all-zero output a
/// low-order peer key produces; the caller decides whether that is fatal.
pub struct X25519Shared {
    secret: Zeroizing<[u8; 32]>,
    contributory: bool,
}

impl X25519Shared {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
    pub fn was_contributory(&self) -> bool {
        self.contributory
    }
}

/// A fresh X25519 keypair. The secret is 32 random bytes, stored unclamped as
/// x25519-dalek always stored it; both backends clamp when they use it.
pub fn x25519_generate() -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
    operational()?;
    let secret = Zeroizing::new(random_array::<32>());
    let public = backend::x25519_public(&secret)?;
    Ok((secret, public))
}

pub fn x25519_public(secret: &[u8; 32]) -> Result<[u8; 32]> {
    operational()?;
    backend::x25519_public(secret)
}

pub fn x25519_shared(secret: &[u8; 32], peer_public: &[u8; 32]) -> Result<X25519Shared> {
    operational()?;
    let (secret, contributory) = backend::x25519_shared(secret, peer_public)?;
    Ok(X25519Shared { secret, contributory })
}

// ---- Ed25519 --------------------------------------------------------------

/// A fresh Ed25519 keypair: (32-byte seed, public key).
pub fn ed25519_generate() -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
    operational()?;
    let seed = Zeroizing::new(random_array::<32>());
    let public = backend::ed25519_public(&seed)?;
    Ok((seed, public))
}

pub fn ed25519_public(seed: &[u8; 32]) -> Result<[u8; 32]> {
    operational()?;
    backend::ed25519_public(seed)
}

pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> Result<[u8; 64]> {
    operational()?;
    backend::ed25519_sign(seed, message)
}

/// Ok only for a valid signature by `public_key` over `message`.
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    operational()?;
    let (Ok(public_key), Ok(signature)) = (<&[u8; 32]>::try_from(public_key), <&[u8; 64]>::try_from(signature)) else {
        return Err(QGuardError::Crypto("invalid Ed25519 key or signature length".to_string()));
    };
    if backend::ed25519_verify(public_key, message, signature)? {
        Ok(())
    } else {
        Err(QGuardError::Crypto("Ed25519 signature verification failed".to_string()))
    }
}

// ---- ML-KEM-1024 ----------------------------------------------------------

/// A fresh ML-KEM-1024 keypair: (encapsulation key, decapsulation key).
pub fn mlkem1024_generate() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    operational()?;
    backend::mlkem1024_keypair()
}

/// (ciphertext, shared secret) for `public_key`.
pub fn mlkem1024_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    operational()?;
    if public_key.len() != MLKEM1024_PUBLIC_KEY_BYTES {
        return Err(QGuardError::Crypto(format!(
            "ML-KEM-1024 encapsulation key must be {MLKEM1024_PUBLIC_KEY_BYTES} bytes, got {}",
            public_key.len()
        )));
    }
    backend::mlkem1024_encapsulate(public_key)
}

pub fn mlkem1024_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    operational()?;
    if secret_key.len() != MLKEM1024_SECRET_KEY_BYTES {
        return Err(QGuardError::Crypto("invalid ML-KEM-1024 decapsulation key".to_string()));
    }
    if ciphertext.len() != MLKEM1024_CIPHERTEXT_BYTES {
        return Err(QGuardError::Crypto("invalid ML-KEM-1024 ciphertext".to_string()));
    }
    backend::mlkem1024_decapsulate(secret_key, ciphertext)
}

// ---- ML-DSA ---------------------------------------------------------------

/// A fresh keypair: (public key, secret key).
pub fn mldsa_generate(params: MlDsa) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    operational()?;
    backend::mldsa_keypair(params)
}

/// FIPS 204 ML-DSA.Sign, pure mode, empty context, hedged.
pub fn mldsa_sign(params: MlDsa, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    operational()?;
    if secret_key.len() != params.secret_key_bytes() {
        return Err(QGuardError::Crypto(format!("invalid {} secret key", params.label())));
    }
    backend::mldsa_sign(params, secret_key, message)
}

pub fn mldsa_verify(params: MlDsa, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    operational()?;
    if public_key.len() != params.public_key_bytes() {
        return Err(QGuardError::Crypto(format!("invalid {} public key", params.label())));
    }
    if signature.len() != params.signature_bytes() {
        return Err(QGuardError::Crypto(format!("invalid {} signature", params.label())));
    }
    if backend::mldsa_verify(params, public_key, message, signature)? {
        Ok(())
    } else {
        Err(QGuardError::Crypto(format!("{} signature verification failed", params.label())))
    }
}
