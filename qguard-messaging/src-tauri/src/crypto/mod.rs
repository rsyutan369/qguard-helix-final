pub mod hybrid_kex;
pub mod kdf;
pub mod mnemonic;
pub mod passcode;
pub mod passphrase;
pub mod portable_identity;
pub mod provider;
pub mod shamir;
pub mod signatures;
pub mod symmetric;
pub mod vault_recovery;

use serde::{Deserialize, Serialize};

/// The one KEM this build performs. ML-KEM-1024 (FIPS 203), from
/// `pqcrypto-mlkem`. Until the FIPS 203 cutover this constant said the same
/// thing while the code underneath ran Kyber-1024 — the label is now backed by
/// the dependency that is actually compiled in.
pub const CURRENT_PQ_KEM: &str = "ML-KEM-1024";

/// What key material generated before the cutover really was. Never performed
/// by this build; used only to identify stored material that must be re-keyed,
/// and to describe it honestly where it is displayed.
pub const LEGACY_PQ_KEM_PRE_FIPS: &str = "Kyber-1024 (pre-FIPS-203)";

/// The standard the KEM in this build actually implements, published in
/// `AlgorithmSuite::pq_kem_standard`.
///
/// `pq_kem` ALONE CANNOT BE TRUSTED to identify the KEM. Pre-cutover builds set
/// it to "ML-KEM-1024" while running Kyber-1024, and the two have byte-identical
/// key and ciphertext lengths -- so a peer reading `pq_kem` (or measuring a key)
/// cannot tell whether the material it is about to encapsulate to will
/// interoperate. Sealing across that boundary produces an envelope that decrypts
/// to a different shared secret and dies as an unexplained AEAD failure at the
/// far end, on both sides, with both clients still displaying "E2EE active".
///
/// This field is the discriminator. It is absent from every pre-cutover device
/// row and every pre-cutover envelope, and `#[serde(default)]` turns that
/// absence into the empty string -- which is what makes old material
/// identifiable rather than merely indistinguishable.
pub const CURRENT_PQ_KEM_STANDARD: &str = "FIPS-203";

/// The transcript-bound hybrid combiner (see `hybrid_kex::KemCombiner`).
///
/// It plays two roles depending on where the suite appears:
///   * in a device's PUBLISHED suite it is a capability — "I can open
///     ciphertexts made with this combiner (and the legacy one)";
///   * in a `HybridCiphertext` it names the combiner that ciphertext was
///     actually made with.
/// Absent/empty means the legacy concatenation combiner, which is what every
/// build before this field existed produced and expected.
pub const CURRENT_KEM_COMBINER: &str = "QGuard-HybridKEM-v2";

/// Digital signature used by the messaging identity (shared with other devices).
pub const MESSAGING_PQ_SIGNATURE: &str = "ML-DSA-65";
/// High-security signature used by the Quantum Vault (`.qvault` v3) only. Kept
/// separate from the messaging identity so upgrading the vault never breaks
/// cross-device messaging compatibility.
pub const VAULT_PQ_SIGNATURE: &str = "ML-DSA-87";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlgorithmSuite {
    pub classical_kex: String,
    pub pq_kem: String,
    pub kdf: String,
    pub symmetric: String,
    pub classical_signature: String,
    pub pq_signature: String,
    /// Which standard produced the KEM material -- see `CURRENT_PQ_KEM_STANDARD`.
    /// Empty means "written before the FIPS 203 cutover", i.e. Kyber-1024.
    ///
    /// Safe to add to a wire type: the suite is not part of `message_signable`
    /// or `identity_signable`, so no existing signature covers it, and
    /// `#[serde(default)]` keeps every already-persisted envelope decodable.
    #[serde(default)]
    pub pq_kem_standard: String,
    /// Hybrid-KEM combiner — see `CURRENT_KEM_COMBINER` for its two meanings.
    ///
    /// Skipped when empty so a legacy-combiner ciphertext serialises to exactly
    /// the bytes it always did, and defaulted so every suite written before the
    /// field existed reads back as "legacy".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kem_combiner: String,
    /// Session ratchet (see `crate::pq_ratchet`). Same two meanings as
    /// `kem_combiner`: in a device's PUBLISHED suite it is a capability ("send
    /// me ratchet envelopes"); in an envelope's suite it names the protocol the
    /// envelope was sealed with. Empty = one-shot envelopes only, which is what
    /// every build before the ratchet published and sent. Skipped when empty
    /// so no existing suite serialises differently.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ratchet: String,
}

impl Default for AlgorithmSuite {
    fn default() -> Self {
        Self {
            classical_kex: "X25519".to_string(),
            pq_kem: CURRENT_PQ_KEM.to_string(),
            kdf: "HKDF-SHA3-256".to_string(),
            symmetric: "AES-256-GCM".to_string(),
            classical_signature: "Ed25519".to_string(),
            pq_signature: "ML-DSA-65".to_string(),
            pq_kem_standard: CURRENT_PQ_KEM_STANDARD.to_string(),
            kem_combiner: CURRENT_KEM_COMBINER.to_string(),
            // Advertised only while the ratchet is switched on — see
            // `AppState::ratchet_enabled`, which sets it on the published bundle.
            ratchet: String::new(),
        }
    }
}

impl AlgorithmSuite {
    /// True when this suite was written by a build whose KEM is the one this
    /// build performs. False for anything produced before the FIPS 203 cutover,
    /// which cannot interoperate and must never be sealed to.
    pub fn kem_interoperates(&self) -> bool {
        self.pq_kem == CURRENT_PQ_KEM && self.pq_kem_standard == CURRENT_PQ_KEM_STANDARD
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DualSignature {
    pub ed25519: Vec<u8>,
    pub ml_dsa_65: Vec<u8>,
}

/// High-security dual signature (Ed25519 + ML-DSA-87) used by the Quantum Vault
/// `.qvault` v3 header. Distinct from `DualSignature` (ML-DSA-65) so the vault can
/// move to the FIPS 204 Level 5 parameter set independently of messaging.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DualSignature87 {
    pub ed25519: Vec<u8>,
    pub ml_dsa_87: Vec<u8>,
}

/// Algorithm suite advertised for the Quantum Vault high-security profile. Same
/// hybrid KEM + symmetric stack as the default, but the FIPS 204 Level 5
/// signature (ML-DSA-87). Surfaced to the UI so displayed crypto matches reality.
pub fn vault_suite() -> AlgorithmSuite {
    AlgorithmSuite {
        pq_signature: VAULT_PQ_SIGNATURE.to_string(),
        ..AlgorithmSuite::default()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridCiphertext {
    pub x25519_ephemeral_public: Vec<u8>,
    pub ml_kem_ciphertext: Vec<u8>,
    pub suite: AlgorithmSuite,
}
