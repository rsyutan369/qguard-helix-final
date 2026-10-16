use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{QGuardError, Result};

use super::{
    kdf::{derive_32, sha3_256},
    AlgorithmSuite, HybridCiphertext, CURRENT_KEM_COMBINER, CURRENT_PQ_KEM, CURRENT_PQ_KEM_STANDARD,
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

/// How the X25519 and ML-KEM shared secrets become one key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KemCombiner {
    /// `HKDF(ss_x25519 || ss_mlkem, info)`. What every build before the bound
    /// combiner produced. Still spoken to peers that have not advertised more,
    /// and still read so existing envelopes and containers keep opening.
    LegacyConcat,
    /// `HKDF(ss_mlkem || ss_x25519, info || transcript)`, where the transcript
    /// is the X25519 ephemeral key, the recipient's X25519 public key and a
    /// hash of the ML-KEM ciphertext.
    ///
    /// The legacy form derives the key from the two secrets alone, so nothing
    /// ties it to the exchange that produced them. That is not a break while
    /// ML-KEM holds (its own shared secret already depends on its ciphertext
    /// and public key), but a hybrid exists precisely for the day one half
    /// fails — and X25519 alone gives no such binding. Mixing the X25519
    /// transcript in is what X-Wing and the IETF hybrid-KEM drafts do for the
    /// same reason. A non-contributory X25519 result (a low-order peer key) is
    /// also refused here instead of silently contributing nothing.
    BoundV2,
}

impl KemCombiner {
    /// The wire label carried in `AlgorithmSuite::kem_combiner`.
    pub fn label(self) -> &'static str {
        match self {
            KemCombiner::LegacyConcat => "",
            KemCombiner::BoundV2 => CURRENT_KEM_COMBINER,
        }
    }

    /// The combiner a ciphertext says it was made with. An unknown label is an
    /// error, never a fallback: guessing would derive a wrong key at best.
    pub fn from_label(label: &str) -> Result<Self> {
        match label {
            "" => Ok(KemCombiner::LegacyConcat),
            CURRENT_KEM_COMBINER => Ok(KemCombiner::BoundV2),
            other => Err(QGuardError::Crypto(format!(
                "unsupported hybrid KEM combiner: {other} — update QGuard Messaging"
            ))),
        }
    }

    /// The strongest combiner a peer's PUBLISHED suite says it can open.
    ///
    /// A suite with no declaration belongs to a build that predates the bound
    /// combiner, and sealing to it with anything else would produce a message
    /// that device can never read.
    pub fn for_peer_suite(suite: Option<&AlgorithmSuite>) -> Self {
        match suite {
            Some(suite) if suite.kem_combiner == CURRENT_KEM_COMBINER => KemCombiner::BoundV2,
            _ => KemCombiner::LegacyConcat,
        }
    }
}

/// Derive the hybrid shared key from both halves under `combiner`.
fn combine_shared_secrets(
    combiner: KemCombiner,
    classical: &x25519_dalek::SharedSecret,
    pq: &[u8],
    ephemeral_x25519_public: &[u8; 32],
    recipient_x25519_public: &[u8; 32],
    mlkem_ciphertext: &[u8],
    info: &[u8],
) -> Result<[u8; 32]> {
    match combiner {
        KemCombiner::LegacyConcat => {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(classical.as_bytes());
            combined.extend_from_slice(pq);
            let shared = derive_32(&combined, info);
            combined.zeroize();
            shared
        }
        KemCombiner::BoundV2 => {
            if !classical.was_contributory() {
                return Err(QGuardError::Crypto(
                    "X25519 key agreement was non-contributory (low-order public key); refusing it"
                        .to_string(),
                ));
            }
            let mut ikm = Vec::with_capacity(64);
            ikm.extend_from_slice(pq);
            ikm.extend_from_slice(classical.as_bytes());
            // Every transcript field is fixed-length, and the caller's `info`
            // is closed off by a separator before them, so the context string
            // cannot be made ambiguous by a crafted `info`.
            let mut context = Vec::with_capacity(info.len() + 1 + CURRENT_KEM_COMBINER.len() + 96);
            context.extend_from_slice(info);
            context.push(0x1f);
            context.extend_from_slice(CURRENT_KEM_COMBINER.as_bytes());
            context.extend_from_slice(ephemeral_x25519_public);
            context.extend_from_slice(recipient_x25519_public);
            context.extend_from_slice(&sha3_256(mlkem_ciphertext));
            let shared = derive_32(&ikm, &context);
            ikm.zeroize();
            shared
        }
    }
}

/// Encapsulate with the LEGACY combiner. Use [`encapsulate_with`] wherever the
/// peer's capability is known; this stays for call sites that must remain
/// readable by builds that predate the bound combiner.
pub fn encapsulate(
    peer_x25519_public: &[u8],
    peer_mlkem_public: &[u8],
    info: &[u8],
) -> Result<(HybridCiphertext, [u8; 32])> {
    encapsulate_with(
        peer_x25519_public,
        peer_mlkem_public,
        info,
        KemCombiner::LegacyConcat,
    )
}

/// Encapsulate with the transcript-bound combiner. For formats and peers that
/// are known to understand it (new vault containers, devices advertising it).
pub fn encapsulate_bound(
    peer_x25519_public: &[u8],
    peer_mlkem_public: &[u8],
    info: &[u8],
) -> Result<(HybridCiphertext, [u8; 32])> {
    encapsulate_with(
        peer_x25519_public,
        peer_mlkem_public,
        info,
        KemCombiner::BoundV2,
    )
}

pub fn encapsulate_with(
    peer_x25519_public: &[u8],
    peer_mlkem_public: &[u8],
    info: &[u8],
    combiner: KemCombiner,
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
    // The ciphertext records the combiner it was ACTUALLY made with, which is
    // not necessarily the newest one this build knows.
    let suite = AlgorithmSuite {
        kem_combiner: combiner.label().to_string(),
        ..AlgorithmSuite::default()
    };

    let shared = combine_shared_secrets(
        combiner,
        &classical_shared,
        &pq,
        eph_public.as_bytes(),
        &peer_x_arr,
        &pq_ciphertext,
        info,
    );
    pq.zeroize();
    let shared = shared?;

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

    // Decided before any key is touched: an unknown combiner is refused, never
    // guessed at.
    let combiner = KemCombiner::from_label(&ciphertext.suite.kem_combiner)?;

    let our_secret = StaticSecret::from(*our_x25519_secret);
    let our_public = X25519PublicKey::from(&our_secret);
    let mut peer_arr = [0u8; 32];
    peer_arr.copy_from_slice(&ciphertext.x25519_ephemeral_public);
    let peer_public = X25519PublicKey::from(peer_arr);
    let classical_shared = our_secret.diffie_hellman(&peer_public);

    let mut pq = decapsulate_pq_secret(
        our_mlkem_secret,
        &ciphertext.ml_kem_ciphertext,
        &ciphertext.suite,
    )?;

    let shared = combine_shared_secrets(
        combiner,
        &classical_shared,
        &pq,
        &peer_arr,
        our_public.as_bytes(),
        &ciphertext.ml_kem_ciphertext,
        info,
    );
    pq.zeroize();
    shared
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
    fn legacy_encapsulation_stays_unlabelled_and_bound_encapsulation_says_so() {
        let bob = LocalKemKeypair::generate();
        // The legacy combiner must serialise exactly as it always has: no
        // `kem_combiner` key at all, so builds that predate it see nothing new.
        let (legacy, _) = encapsulate(&bob.x25519_public, &bob.mlkem_public, b"ctx").unwrap();
        assert_eq!(legacy.suite.kem_combiner, "");
        let json = serde_json::to_string(&legacy).unwrap();
        assert!(!json.contains("kem_combiner"), "legacy ciphertext grew a field: {json}");

        let (bound, _) = encapsulate_bound(&bob.x25519_public, &bob.mlkem_public, b"ctx").unwrap();
        assert_eq!(bound.suite.kem_combiner, CURRENT_KEM_COMBINER);
        // ...and a suite written before the field existed reads back as legacy.
        let old: AlgorithmSuite = serde_json::from_str(
            r#"{"classical_kex":"X25519","pq_kem":"ML-KEM-1024","kdf":"HKDF-SHA3-256",
                "symmetric":"AES-256-GCM","classical_signature":"Ed25519",
                "pq_signature":"ML-DSA-65","pq_kem_standard":"FIPS-203"}"#,
        )
        .unwrap();
        assert_eq!(old.kem_combiner, "");
        assert_eq!(KemCombiner::for_peer_suite(Some(&old)), KemCombiner::LegacyConcat);
        assert_eq!(KemCombiner::for_peer_suite(None), KemCombiner::LegacyConcat);
        assert_eq!(
            KemCombiner::for_peer_suite(Some(&AlgorithmSuite::default())),
            KemCombiner::BoundV2
        );
    }

    #[test]
    fn bound_combiner_round_trips_and_is_tied_to_its_transcript() {
        let bob = LocalKemKeypair::generate();
        let (ct, alice_secret) =
            encapsulate_bound(&bob.x25519_public, &bob.mlkem_public, b"bound").unwrap();
        let bob_secret = decapsulate(&bob.x25519_secret, &bob.mlkem_secret, &ct, b"bound").unwrap();
        assert_eq!(alice_secret, bob_secret);

        // Different caller context -> different key.
        let other_ctx = decapsulate(&bob.x25519_secret, &bob.mlkem_secret, &ct, b"other").unwrap();
        assert_ne!(other_ctx, bob_secret);

        // Relabelling the SAME ciphertext as legacy must not reproduce the key:
        // the two combiners are domain separated, so a stripped label cannot
        // quietly move a session onto the unbound derivation.
        let mut stripped = ct.clone();
        stripped.suite.kem_combiner.clear();
        let downgraded =
            decapsulate(&bob.x25519_secret, &bob.mlkem_secret, &stripped, b"bound").unwrap();
        assert_ne!(downgraded, bob_secret);

        // An unknown combiner is refused outright rather than guessed at.
        let mut unknown = ct.clone();
        unknown.suite.kem_combiner = "QGuard-HybridKEM-v9".to_string();
        let err = decapsulate(&bob.x25519_secret, &bob.mlkem_secret, &unknown, b"bound").unwrap_err();
        assert!(format!("{err:?}").contains("unsupported hybrid KEM combiner"), "got {err:?}");
    }

    #[test]
    fn bound_combiner_refuses_a_low_order_x25519_key() {
        // The all-zero point is low order: X25519 against it yields an all-zero
        // "shared secret" that an attacker also knows. The legacy combiner let
        // that pass (the ML-KEM half still protected the key); the bound one
        // refuses to pretend the classical half contributed anything.
        let bob = LocalKemKeypair::generate();
        let low_order = [0u8; 32];
        let err = encapsulate_bound(&low_order, &bob.mlkem_public, b"low").unwrap_err();
        assert!(format!("{err:?}").contains("non-contributory"), "got {err:?}");
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
