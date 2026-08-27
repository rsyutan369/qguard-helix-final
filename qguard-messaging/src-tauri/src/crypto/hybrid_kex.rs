use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{QGuardError, Result};

use super::{
    kdf::derive_32, AlgorithmSuite, HybridCiphertext, CURRENT_PQ_KEM, CURRENT_PQ_KEM_STANDARD,
    LEGACY_PQ_KEM_PRE_FIPS,
};

/// Key material persisted before the FIPS 203 cutover carries no `kem` field.
/// Serde fills it with this, which is what makes the old material identifiable.
fn pre_fips_kem_marker() -> String {
    LEGACY_PQ_KEM_PRE_FIPS.to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalKemKeypair {
    pub x25519_secret: [u8; 32],
    pub x25519_public: Vec<u8>,
    pub mlkem_secret: Vec<u8>,
    pub mlkem_public: Vec<u8>,
    /// Which KEM actually produced this keypair.
    ///
    /// This field exists because NOTHING ELSE CAN TELL. Builds before the FIPS
    /// 203 cutover generated Kyber-1024 keys (PQClean round-3) while labelling
    /// them "ML-KEM-1024" everywhere, and Kyber-1024 and ML-KEM-1024 have
    /// byte-identical key and ciphertext sizes. A length or parse check accepts
    /// either one, so without an explicit marker the old secret key would be
    /// handed to ML-KEM decapsulation, silently derive a different shared
    /// secret, and surface as unexplained AEAD failures.
    #[serde(default = "pre_fips_kem_marker")]
    pub kem: String,
}

impl LocalKemKeypair {
    pub fn generate() -> Self {
        let x_secret = StaticSecret::random_from_rng(OsRng);
        let x_public = X25519PublicKey::from(&x_secret);
        let (ml_public, ml_secret) = mlkem1024::keypair();

        Self {
            x25519_secret: x_secret.to_bytes(),
            x25519_public: x_public.as_bytes().to_vec(),
            mlkem_secret: mlkem1024::SecretKey::as_bytes(&ml_secret).to_vec(),
            mlkem_public: mlkem1024::PublicKey::as_bytes(&ml_public).to_vec(),
            kem: CURRENT_PQ_KEM.to_string(),
        }
    }

    /// Structural check only: is this a well-formed ML-KEM-1024 encapsulation
    /// key? It cannot prove the key was produced by ML-KEM rather than Kyber —
    /// the encodings are the same size — so never use it alone to decide
    /// whether stored material needs migrating. Use `is_current_suite`.
    pub fn is_current_public_key(public_key: &[u8]) -> bool {
        mlkem1024::PublicKey::from_bytes(public_key).is_ok()
    }

    pub fn is_current_secret_key(secret_key: &[u8]) -> bool {
        mlkem1024::SecretKey::from_bytes(secret_key).is_ok()
    }

    /// True only for material this build's ML-KEM (FIPS 203) actually produced.
    pub fn is_current_suite(&self) -> bool {
        self.kem == CURRENT_PQ_KEM
            && Self::is_current_public_key(&self.mlkem_public)
            && Self::is_current_secret_key(&self.mlkem_secret)
    }
}

impl Drop for LocalKemKeypair {
    fn drop(&mut self) {
        self.x25519_secret.zeroize();
        self.mlkem_secret.zeroize();
    }
}

pub fn encapsulate(
    peer_x25519_public: &[u8],
    peer_mlkem_public: &[u8],
    info: &[u8],
) -> Result<(HybridCiphertext, [u8; 32])> {
    if peer_x25519_public.len() != 32 {
        return Err(QGuardError::InvalidInput(
            "X25519 public key must be 32 bytes".to_string(),
        ));
    }

    let mut peer_x_arr = [0u8; 32];
    peer_x_arr.copy_from_slice(peer_x25519_public);

    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_public = X25519PublicKey::from(&eph_secret);
    let peer_public = X25519PublicKey::from(peer_x_arr);
    let classical_shared = eph_secret.diffie_hellman(&peer_public);
    let mut classical = classical_shared.as_bytes().to_vec();

    // ML-KEM-1024 ONLY. The previous build chose its parameter set from the
    // LENGTH of the peer's public key and silently fell back to a weaker one,
    // which is a downgrade surface: anything that could substitute a shorter
    // key would have moved the session to a lower security level without a
    // word. There is exactly one accepted parameter set now, so there is
    // nothing to negotiate and nothing to downgrade to.
    let pq_public = mlkem1024::PublicKey::from_bytes(peer_mlkem_public).map_err(|_| {
        QGuardError::Crypto(format!(
            "peer ML-KEM-1024 encapsulation key is malformed: {} bytes, expected {}",
            peer_mlkem_public.len(),
            mlkem1024::public_key_bytes(),
        ))
    })?;
    let (pq_shared, pq_ciphertext_raw) = mlkem1024::encapsulate(&pq_public);
    let mut pq = mlkem1024::SharedSecret::as_bytes(&pq_shared).to_vec();
    let pq_ciphertext = mlkem1024::Ciphertext::as_bytes(&pq_ciphertext_raw).to_vec();
    let suite = AlgorithmSuite::default();

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&classical);
    combined.extend_from_slice(&pq);
    let shared = derive_32(&combined, info)?;

    classical.zeroize();
    pq.zeroize();
    combined.zeroize();

    Ok((
        HybridCiphertext {
            x25519_ephemeral_public: eph_public.as_bytes().to_vec(),
            ml_kem_ciphertext: pq_ciphertext,
            suite,
        },
        shared,
    ))
}

pub fn decapsulate(
    our_x25519_secret: &[u8; 32],
    our_mlkem_secret: &[u8],
    ciphertext: &HybridCiphertext,
    info: &[u8],
) -> Result<[u8; 32]> {
    if ciphertext.x25519_ephemeral_public.len() != 32 {
        return Err(QGuardError::InvalidInput(
            "ephemeral X25519 key must be 32 bytes".to_string(),
        ));
    }

    let our_secret = StaticSecret::from(*our_x25519_secret);
    let mut peer_arr = [0u8; 32];
    peer_arr.copy_from_slice(&ciphertext.x25519_ephemeral_public);
    let peer_public = X25519PublicKey::from(peer_arr);
    let classical_shared = our_secret.diffie_hellman(&peer_public);
    let mut classical = classical_shared.as_bytes().to_vec();

    let mut pq = decapsulate_pq_secret(
        our_mlkem_secret,
        &ciphertext.ml_kem_ciphertext,
        &ciphertext.suite,
    )?;

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&classical);
    combined.extend_from_slice(&pq);
    let shared = derive_32(&combined, info)?;

    classical.zeroize();
    pq.zeroize();
    combined.zeroize();

    Ok(shared)
}

fn decapsulate_pq_secret(
    our_mlkem_secret: &[u8],
    pq_ciphertext: &[u8],
    suite: &AlgorithmSuite,
) -> Result<Vec<u8>> {
    // One accepted suite. A ciphertext produced by the pre-FIPS build carries
    // the SAME `pq_kem` label ("ML-KEM-1024") and the same byte length, so it
    // reaches here looking legitimate and decapsulates to a different shared
    // secret. That is caught one layer up: the AEAD tag fails and the message
    // is rejected. This fails CLOSED — it can never return a wrong plaintext.
    if suite.pq_kem != CURRENT_PQ_KEM {
        return Err(QGuardError::Crypto(format!(
            "unsupported KEM suite for decapsulation: {} (this build accepts {CURRENT_PQ_KEM} only)",
            suite.pq_kem
        )));
    }
    // The `pq_kem` check above passes for a PRE-CUTOVER ciphertext too: that
    // build stamped the same "ML-KEM-1024" label on Kyber-1024 output of the
    // same length. Without this second check the ciphertext reaches ML-KEM
    // decapsulation looking legitimate, derives a different shared secret, and
    // surfaces as an unexplained AEAD failure that names nothing actionable.
    // Naming it here is what lets the UI say "sent by an older build" instead.
    if suite.pq_kem_standard != CURRENT_PQ_KEM_STANDARD {
        return Err(QGuardError::Crypto(format!(
            "this envelope was sealed by a pre-FIPS-203 build ({LEGACY_PQ_KEM_PRE_FIPS}); {CURRENT_PQ_KEM} ({CURRENT_PQ_KEM_STANDARD}) cannot decapsulate it. Both devices must be running the FIPS 203 build."
        )));
    }
    let pq_secret = mlkem1024::SecretKey::from_bytes(our_mlkem_secret)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-KEM-1024 decapsulation key: {e:?}")))?;
    let pq_ct = mlkem1024::Ciphertext::from_bytes(pq_ciphertext)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-KEM-1024 ciphertext: {e:?}")))?;
    let pq_shared = mlkem1024::decapsulate(&pq_ct, &pq_secret);
    Ok(mlkem1024::SharedSecret::as_bytes(&pq_shared).to_vec())
}

#[cfg(feature = "oqs-backend")]
pub mod oqs_backend {
    pub const STATUS: &str =
        "oqs-backend feature enabled; wire integration point reserved for liboqs packaging";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_key_agreement_roundtrip() {
        let bob = LocalKemKeypair::generate();
        let (ct, alice_secret) =
            encapsulate(&bob.x25519_public, &bob.mlkem_public, b"test").unwrap();
        let bob_secret = decapsulate(&bob.x25519_secret, &bob.mlkem_secret, &ct, b"test").unwrap();
        assert_eq!(ct.suite.pq_kem, CURRENT_PQ_KEM);
        assert!(LocalKemKeypair::is_current_public_key(&bob.mlkem_public));
        assert!(LocalKemKeypair::is_current_secret_key(&bob.mlkem_secret));
        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn encapsulation_refuses_a_shorter_parameter_set() {
        // The pre-FIPS build chose its parameter set from the LENGTH of the
        // peer's public key and quietly dropped to ML-KEM-768 for a shorter one.
        // That is a downgrade surface. There is one accepted parameter set now,
        // so a key of any other size is rejected outright rather than negotiated
        // down.
        let bob = LocalKemKeypair::generate();
        let short = vec![0u8; 1184]; // a well-formed 768-class key length
        let err = encapsulate(&bob.x25519_public, &short, b"downgrade").unwrap_err();
        assert!(
            format!("{err:?}").contains("ML-KEM-1024"),
            "expected an ML-KEM-1024 rejection, got {err:?}"
        );
    }

    #[test]
    fn decapsulation_refuses_any_suite_but_ml_kem_1024() {
        let bob = LocalKemKeypair::generate();
        let (mut ct, _) = encapsulate(&bob.x25519_public, &bob.mlkem_public, b"suite").unwrap();
        ct.suite.pq_kem = LEGACY_PQ_KEM_PRE_FIPS.to_string();
        let err = decapsulate(&bob.x25519_secret, &bob.mlkem_secret, &ct, b"suite").unwrap_err();
        assert!(
            format!("{err:?}").contains("unsupported KEM suite"),
            "expected a suite rejection, got {err:?}"
        );
    }

    #[test]
    fn generated_material_is_marked_as_fips_203_ml_kem() {
        let kp = LocalKemKeypair::generate();
        assert_eq!(kp.kem, CURRENT_PQ_KEM);
        assert!(kp.is_current_suite());
        // Sizes are the FIPS 203 ML-KEM-1024 sizes — which are also the Kyber
        // sizes, which is precisely why the marker above has to exist.
        assert_eq!(kp.mlkem_public.len(), mlkem1024::public_key_bytes());
        assert_eq!(kp.mlkem_secret.len(), mlkem1024::secret_key_bytes());
    }

    #[test]
    fn key_material_stored_before_the_cutover_is_detected_and_not_reused() {
        // Persisted pre-FIPS material has no `kem` field at all. Serde fills in
        // the legacy marker, and that is the ONLY thing that reveals it: the key
        // lengths are identical to ML-KEM-1024, so every structural check passes.
        let current = LocalKemKeypair::generate();
        let stored = serde_json::to_value(&current).unwrap();
        let mut pre_fips = stored.as_object().unwrap().clone();
        pre_fips.remove("kem");
        let restored: LocalKemKeypair =
            serde_json::from_value(serde_json::Value::Object(pre_fips)).unwrap();

        assert_eq!(restored.kem, LEGACY_PQ_KEM_PRE_FIPS);
        // Structural checks cannot tell the difference...
        assert!(LocalKemKeypair::is_current_public_key(&restored.mlkem_public));
        assert!(LocalKemKeypair::is_current_secret_key(&restored.mlkem_secret));
        // ...but the suite check, which reads the marker, can. This is what
        // drives the automatic re-key on the next launch.
        assert!(!restored.is_current_suite());
    }
}
