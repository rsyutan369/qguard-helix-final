//! Start-up self-test of the cryptography this build actually contains.
//!
//! The hardening report used to state "post-quantum protection: active",
//! "secure memory: active" and "rate limiting: active" as constants. A constant
//! cannot be wrong, which is exactly what is wrong with it: a build whose
//! ML-KEM was linked against the wrong parameter set, or whose signatures never
//! verified, reported the same green row as a working one.
//!
//! Each of those rows is now the outcome of an operation that is really
//! performed, once, in this process:
//!
//!   * hybrid KEM  — X25519 + ML-KEM-1024 (FIPS 203): encapsulate, decapsulate,
//!     compare; and the key/ciphertext sizes must be the ML-KEM-1024 ones.
//!   * signatures  — Ed25519 + ML-DSA-65 (FIPS 204): sign, verify, and a
//!     modified message must NOT verify.
//!   * AEAD        — AES-256-GCM: round trip, and a flipped ciphertext bit and
//!     a different AAD must both be rejected.
//!   * hash        — SHA3-256 against the published FIPS 202 test vectors.
//!   * zeroize     — wiping really leaves zeros.
//!   * rate limiter — the native limiter really refuses past its limit.
//!
//! This is a functional self-test, not a validation: it shows the primitives
//! work in this binary on this machine, not that the implementation is free of
//! side channels or has been certified.

use std::sync::OnceLock;

use zeroize::Zeroize;

use crate::crypto::hybrid_kex::{decapsulate, encapsulate_bound, LocalKemKeypair};
use crate::crypto::kdf::sha3_hex;
use crate::crypto::signatures::{dual_sign, dual_verify, LocalSigningKeypair};
use crate::crypto::symmetric;

type Outcome = Result<(), String>;

#[derive(Clone, Debug)]
pub struct SelfTestReport {
    pub hybrid_kem: Outcome,
    pub signatures: Outcome,
    pub aead: Outcome,
    pub hash: Outcome,
    pub zeroize: Outcome,
    pub rate_limiter: Outcome,
}

impl SelfTestReport {
    pub fn post_quantum(&self) -> Outcome {
        self.hybrid_kem.clone().and(self.signatures.clone())
    }

    pub fn symmetric(&self) -> Outcome {
        self.aead.clone().and(self.hash.clone())
    }
}

/// The self-test result for this process. Run at most once: the primitives
/// cannot change while the process lives.
pub fn report() -> SelfTestReport {
    static REPORT: OnceLock<SelfTestReport> = OnceLock::new();
    REPORT.get_or_init(run).clone()
}

/// Run the self-test off the main thread so the first dashboard load does not
/// wait for it. Safe to call more than once.
pub fn prime() {
    std::thread::spawn(|| {
        let _ = report();
    });
}

fn run() -> SelfTestReport {
    SelfTestReport {
        hybrid_kem: hybrid_kem(),
        signatures: signatures(),
        aead: aead(),
        hash: hash(),
        zeroize: zeroize_works(),
        rate_limiter: rate_limiter(),
    }
}

fn ensure(condition: bool, failure: &str) -> Outcome {
    if condition {
        Ok(())
    } else {
        Err(failure.to_string())
    }
}

// FIPS 203, ML-KEM-1024: encapsulation key and ciphertext are both 1568 bytes.
// (ML-KEM-768 would be 1184 / 1088.) FIPS 204, ML-DSA-65: public key 1952
// bytes, signature 3309.
const MLKEM1024_PUBLIC_KEY_BYTES: usize = 1568;
const MLKEM1024_CIPHERTEXT_BYTES: usize = 1568;
const MLDSA65_PUBLIC_KEY_BYTES: usize = 1952;
const MLDSA65_SIGNATURE_BYTES: usize = 3309;

fn hybrid_kem() -> Outcome {
    let recipient = LocalKemKeypair::generate();
    ensure(
        recipient.mlkem_public.len() == MLKEM1024_PUBLIC_KEY_BYTES,
        "the ML-KEM encapsulation key is not ML-KEM-1024 sized",
    )?;
    let info = b"qguard-selftest-kem";
    let (ciphertext, sender_secret) =
        encapsulate_bound(&recipient.x25519_public, &recipient.mlkem_public, info)
            .map_err(|error| format!("hybrid encapsulation failed: {error}"))?;
    ensure(
        ciphertext.ml_kem_ciphertext.len() == MLKEM1024_CIPHERTEXT_BYTES,
        "the ML-KEM ciphertext is not ML-KEM-1024 sized",
    )?;
    let recipient_secret = decapsulate(
        &recipient.x25519_secret,
        &recipient.mlkem_secret,
        &ciphertext,
        info,
    )
    .map_err(|error| format!("hybrid decapsulation failed: {error}"))?;
    ensure(
        sender_secret == recipient_secret,
        "the two sides of the hybrid KEM derived different secrets",
    )?;
    // A different context must not yield the same secret.
    let other_context = decapsulate(
        &recipient.x25519_secret,
        &recipient.mlkem_secret,
        &ciphertext,
        b"qguard-selftest-other",
    )
    .map_err(|error| format!("hybrid decapsulation failed: {error}"))?;
    ensure(
        other_context != recipient_secret,
        "the hybrid KEM ignored its context string",
    )
}

fn signatures() -> Outcome {
    let keys = LocalSigningKeypair::generate();
    ensure(
        keys.mldsa_public.len() == MLDSA65_PUBLIC_KEY_BYTES,
        "the ML-DSA public key is not ML-DSA-65 sized",
    )?;
    let message = b"qguard-selftest-signature";
    let signature = dual_sign(&keys.ed25519_secret, &keys.mldsa_secret, message)
        .map_err(|error| format!("dual signing failed: {error}"))?;
    ensure(
        signature.ml_dsa_65.len() == MLDSA65_SIGNATURE_BYTES,
        "the ML-DSA signature is not ML-DSA-65 sized",
    )?;
    dual_verify(&keys.ed25519_public, &keys.mldsa_public, message, &signature)
        .map_err(|error| format!("a genuine dual signature did not verify: {error}"))?;
    ensure(
        dual_verify(
            &keys.ed25519_public,
            &keys.mldsa_public,
            b"qguard-selftest-signature-altered",
            &signature,
        )
        .is_err(),
        "a signature verified over a message it was not made for",
    )?;
    // Each half must be checked on its own: a verifier that only looked at
    // one would still pass the test above.
    let mut classical_broken = signature.clone();
    classical_broken.ed25519[0] ^= 0x01;
    ensure(
        dual_verify(&keys.ed25519_public, &keys.mldsa_public, message, &classical_broken).is_err(),
        "a broken Ed25519 half was accepted",
    )?;
    let mut post_quantum_broken = signature;
    post_quantum_broken.ml_dsa_65[0] ^= 0x01;
    ensure(
        dual_verify(&keys.ed25519_public, &keys.mldsa_public, message, &post_quantum_broken).is_err(),
        "a broken ML-DSA-65 half was accepted",
    )
}

fn aead() -> Outcome {
    let key = symmetric::random_key();
    let plaintext = b"qguard-selftest-aead";
    let aad = b"aad-one";
    let sealed = symmetric::encrypt(&key, plaintext, aad)
        .map_err(|error| format!("AES-256-GCM encryption failed: {error}"))?;
    let opened = symmetric::decrypt(&key, &sealed, aad)
        .map_err(|error| format!("AES-256-GCM decryption failed: {error}"))?;
    ensure(opened == plaintext, "AES-256-GCM did not return what was sealed")?;
    ensure(
        symmetric::decrypt(&key, &sealed, b"aad-two").is_err(),
        "AES-256-GCM accepted a different AAD",
    )?;
    let mut tampered = sealed.clone();
    match tampered.ciphertext.first_mut() {
        Some(byte) => *byte ^= 0x01,
        None => return Err("AES-256-GCM produced an empty ciphertext".to_string()),
    }
    ensure(
        symmetric::decrypt(&key, &tampered, aad).is_err(),
        "AES-256-GCM accepted a modified ciphertext",
    )?;
    let second = symmetric::encrypt(&key, plaintext, aad)
        .map_err(|error| format!("AES-256-GCM encryption failed: {error}"))?;
    ensure(
        second.nonce != sealed.nonce,
        "AES-256-GCM reused a nonce under the same key",
    )
}

fn hash() -> Outcome {
    // FIPS 202 example values.
    ensure(
        sha3_hex(b"abc") == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        "SHA3-256 does not match its published test vector",
    )?;
    ensure(
        sha3_hex(b"") == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "SHA3-256 of the empty string does not match its published test vector",
    )
}

fn zeroize_works() -> Outcome {
    let mut fixed = [0xA5u8; 32];
    fixed.zeroize();
    ensure(fixed.iter().all(|byte| *byte == 0), "a wiped key array still held data")?;
    let mut heap = vec![0x5Au8; 2400];
    heap.zeroize();
    ensure(heap.iter().all(|byte| *byte == 0), "a wiped key buffer still held data")
}

fn rate_limiter() -> Outcome {
    let mut attempts = Vec::new();
    let (limit, window) = (3usize, 60i64);
    for second in 0..limit as i64 {
        ensure(
            crate::state::rate_window_admit(&mut attempts, second, limit, window),
            "the rate limiter refused an attempt inside its limit",
        )?;
    }
    ensure(
        !crate::state::rate_window_admit(&mut attempts, 10, limit, window),
        "the rate limiter admitted an attempt past its limit",
    )?;
    ensure(
        crate::state::rate_window_admit(&mut attempts, window + 30, limit, window),
        "the rate limiter never recovered after its window passed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_primitive_passes_its_self_test_in_this_build() {
        let report = run();
        assert_eq!(report.hybrid_kem, Ok(()));
        assert_eq!(report.signatures, Ok(()));
        assert_eq!(report.aead, Ok(()));
        assert_eq!(report.hash, Ok(()));
        assert_eq!(report.zeroize, Ok(()));
        assert_eq!(report.rate_limiter, Ok(()));
        assert_eq!(report.post_quantum(), Ok(()));
        assert_eq!(report.symmetric(), Ok(()));
    }

    #[test]
    fn a_failed_half_fails_the_combined_result() {
        let mut report = run();
        report.signatures = Err("ML-DSA-65 failed".to_string());
        assert_eq!(report.post_quantum(), Err("ML-DSA-65 failed".to_string()));
        report.hybrid_kem = Err("ML-KEM-1024 failed".to_string());
        // The first failure is the one reported.
        assert_eq!(report.post_quantum(), Err("ML-KEM-1024 failed".to_string()));
        report.hash = Err("SHA3-256 failed".to_string());
        assert_eq!(report.symmetric(), Err("SHA3-256 failed".to_string()));
    }

    #[test]
    fn the_cached_report_is_the_same_on_every_call() {
        assert_eq!(report().post_quantum(), report().post_quantum());
    }
}
