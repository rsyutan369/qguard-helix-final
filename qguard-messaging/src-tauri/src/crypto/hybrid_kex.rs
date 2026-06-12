use pqcrypto_kyber::{kyber1024, kyber768};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{QGuardError, Result};

use super::{kdf::derive_32, AlgorithmSuite, HybridCiphertext, CURRENT_PQ_KEM, LEGACY_PQ_KEM_768};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalKemKeypair {
    pub x25519_secret: [u8; 32],
    pub x25519_public: Vec<u8>,
    pub mlkem_secret: Vec<u8>,
    pub mlkem_public: Vec<u8>,
}

impl LocalKemKeypair {
    pub fn generate() -> Self {
        let x_secret = StaticSecret::random_from_rng(OsRng);
        let x_public = X25519PublicKey::from(&x_secret);
        let (ml_public, ml_secret) = kyber1024::keypair();

        Self {
            x25519_secret: x_secret.to_bytes(),
            x25519_public: x_public.as_bytes().to_vec(),
            mlkem_secret: kyber1024::SecretKey::as_bytes(&ml_secret).to_vec(),
            mlkem_public: kyber1024::PublicKey::as_bytes(&ml_public).to_vec(),
        }
    }

    pub fn is_current_public_key(public_key: &[u8]) -> bool {
        kyber1024::PublicKey::from_bytes(public_key).is_ok()
    }

    pub fn is_current_secret_key(secret_key: &[u8]) -> bool {
        kyber1024::SecretKey::from_bytes(secret_key).is_ok()
    }

    pub fn is_current_suite(&self) -> bool {
        Self::is_current_public_key(&self.mlkem_public)
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

    let (mut pq, pq_ciphertext, suite) = if let Ok(pq_public) =
        kyber1024::PublicKey::from_bytes(peer_mlkem_public)
    {
        let (pq_shared, pq_ciphertext) = kyber1024::encapsulate(&pq_public);
        (
            kyber1024::SharedSecret::as_bytes(&pq_shared).to_vec(),
            kyber1024::Ciphertext::as_bytes(&pq_ciphertext).to_vec(),
            AlgorithmSuite::default(),
        )
    } else if let Ok(pq_public) = kyber768::PublicKey::from_bytes(peer_mlkem_public) {
        let (pq_shared, pq_ciphertext) = kyber768::encapsulate(&pq_public);
        let mut suite = AlgorithmSuite::default();
        suite.pq_kem = LEGACY_PQ_KEM_768.to_string();
        (
            kyber768::SharedSecret::as_bytes(&pq_shared).to_vec(),
            kyber768::Ciphertext::as_bytes(&pq_ciphertext).to_vec(),
            suite,
        )
    } else {
        return Err(QGuardError::Crypto(format!(
                "invalid ML-KEM public key length: actual {}, expected 1568 for ML-KEM-1024 or 1184 for ML-KEM-768",
                peer_mlkem_public.len()
            )));
    };

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
    match suite.pq_kem.as_str() {
        CURRENT_PQ_KEM => {
            let pq_secret = kyber1024::SecretKey::from_bytes(our_mlkem_secret).map_err(|e| {
                QGuardError::Crypto(format!("invalid ML-KEM-1024 secret key: {e:?}"))
            })?;
            let pq_ct = kyber1024::Ciphertext::from_bytes(pq_ciphertext).map_err(|e| {
                QGuardError::Crypto(format!("invalid ML-KEM-1024 ciphertext: {e:?}"))
            })?;
            let pq_shared = kyber1024::decapsulate(&pq_ct, &pq_secret);
            Ok(kyber1024::SharedSecret::as_bytes(&pq_shared).to_vec())
        }
        LEGACY_PQ_KEM_768 => {
            let pq_secret = kyber768::SecretKey::from_bytes(our_mlkem_secret).map_err(|e| {
                QGuardError::Crypto(format!("invalid legacy ML-KEM-768 secret key: {e:?}"))
            })?;
            let pq_ct = kyber768::Ciphertext::from_bytes(pq_ciphertext).map_err(|e| {
                QGuardError::Crypto(format!("invalid legacy ML-KEM-768 ciphertext: {e:?}"))
            })?;
            let pq_shared = kyber768::decapsulate(&pq_ct, &pq_secret);
            Ok(kyber768::SharedSecret::as_bytes(&pq_shared).to_vec())
        }
        other => Err(QGuardError::Crypto(format!(
            "unsupported ML-KEM suite for decapsulation: {other}"
        ))),
    }
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
    fn hybrid_key_agreement_accepts_legacy_ml_kem_768_recipient() {
        let x_secret = StaticSecret::random_from_rng(OsRng);
        let x_public = X25519PublicKey::from(&x_secret);
        let (ml_public, ml_secret) = kyber768::keypair();
        let (ct, alice_secret) = encapsulate(
            x_public.as_bytes(),
            kyber768::PublicKey::as_bytes(&ml_public),
            b"legacy-test",
        )
        .unwrap();
        let bob_secret = decapsulate(
            &x_secret.to_bytes(),
            kyber768::SecretKey::as_bytes(&ml_secret),
            &ct,
            b"legacy-test",
        )
        .unwrap();
        assert_eq!(ct.suite.pq_kem, LEGACY_PQ_KEM_768);
        assert_eq!(alice_secret, bob_secret);
    }
}
