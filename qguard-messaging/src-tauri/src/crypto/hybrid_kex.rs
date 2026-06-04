use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{QGuardError, Result};

use super::{kdf::derive_32, AlgorithmSuite, HybridCiphertext};

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
        let (ml_public, ml_secret) = kyber768::keypair();

        Self {
            x25519_secret: x_secret.to_bytes(),
            x25519_public: x_public.as_bytes().to_vec(),
            mlkem_secret: kyber768::SecretKey::as_bytes(&ml_secret).to_vec(),
            mlkem_public: kyber768::PublicKey::as_bytes(&ml_public).to_vec(),
        }
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

    let pq_public = kyber768::PublicKey::from_bytes(peer_mlkem_public)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-KEM public key: {e:?}")))?;
    let (pq_shared, pq_ciphertext) = kyber768::encapsulate(&pq_public);
    let mut pq = kyber768::SharedSecret::as_bytes(&pq_shared).to_vec();

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
            ml_kem_ciphertext: kyber768::Ciphertext::as_bytes(&pq_ciphertext).to_vec(),
            suite: AlgorithmSuite::default(),
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

    let pq_secret = kyber768::SecretKey::from_bytes(our_mlkem_secret)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-KEM secret key: {e:?}")))?;
    let pq_ct = kyber768::Ciphertext::from_bytes(&ciphertext.ml_kem_ciphertext)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-KEM ciphertext: {e:?}")))?;
    let pq_shared = kyber768::decapsulate(&pq_ct, &pq_secret);
    let mut pq = kyber768::SharedSecret::as_bytes(&pq_shared).to_vec();

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&classical);
    combined.extend_from_slice(&pq);
    let shared = derive_32(&combined, info)?;

    classical.zeroize();
    pq.zeroize();
    combined.zeroize();

    Ok(shared)
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
        assert_eq!(alice_secret, bob_secret);
    }
}
