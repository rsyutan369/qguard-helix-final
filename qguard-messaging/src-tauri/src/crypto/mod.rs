pub mod hybrid_kex;
pub mod kdf;
pub mod passcode;
pub mod portable_identity;
pub mod signatures;
pub mod symmetric;
pub mod vault_recovery;

use serde::{Deserialize, Serialize};

pub const CURRENT_PQ_KEM: &str = "ML-KEM-1024";
pub const LEGACY_PQ_KEM_768: &str = "ML-KEM-768";

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
        }
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
