pub mod hybrid_kex;
pub mod kdf;
pub mod signatures;
pub mod symmetric;
pub mod vault_recovery;

use serde::{Deserialize, Serialize};

pub const CURRENT_PQ_KEM: &str = "ML-KEM-1024";
pub const LEGACY_PQ_KEM_768: &str = "ML-KEM-768";

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridCiphertext {
    pub x25519_ephemeral_public: Vec<u8>,
    pub ml_kem_ciphertext: Vec<u8>,
    pub suite: AlgorithmSuite,
}
