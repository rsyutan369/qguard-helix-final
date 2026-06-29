use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_mldsa::{mldsa65, mldsa87};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{QGuardError, Result};

use super::{DualSignature, DualSignature87};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSigningKeypair {
    pub ed25519_secret: [u8; 32],
    pub ed25519_public: Vec<u8>,
    pub mldsa_secret: Vec<u8>,
    pub mldsa_public: Vec<u8>,
}

impl LocalSigningKeypair {
    pub fn generate() -> Self {
        let ed = SigningKey::generate(&mut OsRng);
        let ed_public = ed.verifying_key().to_bytes().to_vec();
        let (pq_public, pq_secret) = mldsa65::keypair();

        Self {
            ed25519_secret: ed.to_bytes(),
            ed25519_public: ed_public,
            mldsa_secret: mldsa65::SecretKey::as_bytes(&pq_secret).to_vec(),
            mldsa_public: mldsa65::PublicKey::as_bytes(&pq_public).to_vec(),
        }
    }
}

impl Drop for LocalSigningKeypair {
    fn drop(&mut self) {
        self.ed25519_secret.zeroize();
        self.mldsa_secret.zeroize();
    }
}

pub fn dual_sign(ed_secret: &[u8; 32], mldsa_secret: &[u8], data: &[u8]) -> Result<DualSignature> {
    let ed = SigningKey::from_bytes(ed_secret);
    let ed_sig = ed.sign(data);

    let pq_secret = mldsa65::SecretKey::from_bytes(mldsa_secret)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-DSA secret key: {e:?}")))?;
    let pq_sig = mldsa65::detached_sign(data, &pq_secret);

    Ok(DualSignature {
        ed25519: ed_sig.to_bytes().to_vec(),
        ml_dsa_65: mldsa65::DetachedSignature::as_bytes(&pq_sig).to_vec(),
    })
}

pub fn dual_verify(
    ed_public: &[u8],
    mldsa_public: &[u8],
    data: &[u8],
    sig: &DualSignature,
) -> Result<()> {
    if ed_public.len() != 32 || sig.ed25519.len() != 64 {
        return Err(QGuardError::Crypto(
            "invalid Ed25519 key or signature length".to_string(),
        ));
    }

    let mut ed_pub_arr = [0u8; 32];
    ed_pub_arr.copy_from_slice(ed_public);
    let verifying = VerifyingKey::from_bytes(&ed_pub_arr)
        .map_err(|e| QGuardError::Crypto(format!("invalid Ed25519 public key: {e}")))?;

    let mut ed_sig_arr = [0u8; 64];
    ed_sig_arr.copy_from_slice(&sig.ed25519);
    let ed_sig = Ed25519Signature::from_bytes(&ed_sig_arr);
    verifying
        .verify(data, &ed_sig)
        .map_err(|_| QGuardError::Crypto("Ed25519 signature verification failed".to_string()))?;

    let pq_public = mldsa65::PublicKey::from_bytes(mldsa_public)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-DSA public key: {e:?}")))?;
    let pq_sig = mldsa65::DetachedSignature::from_bytes(&sig.ml_dsa_65)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-DSA signature: {e:?}")))?;
    mldsa65::verify_detached_signature(&pq_sig, data, &pq_public)
        .map_err(|_| QGuardError::Crypto("ML-DSA-65 signature verification failed".to_string()))?;

    Ok(())
}

/// High-security vault signing keypair (Ed25519 + ML-DSA-87 / FIPS 204 Level 5).
/// Persisted device-local and used only to sign Quantum Vault `.qvault` v3
/// headers — never shared with the server or other devices.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultSigningKeypair {
    pub ed25519_secret: [u8; 32],
    pub ed25519_public: Vec<u8>,
    pub mldsa87_secret: Vec<u8>,
    pub mldsa87_public: Vec<u8>,
}

impl VaultSigningKeypair {
    pub fn generate() -> Self {
        let ed = SigningKey::generate(&mut OsRng);
        let ed_public = ed.verifying_key().to_bytes().to_vec();
        let (pq_public, pq_secret) = mldsa87::keypair();

        Self {
            ed25519_secret: ed.to_bytes(),
            ed25519_public: ed_public,
            mldsa87_secret: mldsa87::SecretKey::as_bytes(&pq_secret).to_vec(),
            mldsa87_public: mldsa87::PublicKey::as_bytes(&pq_public).to_vec(),
        }
    }
}

impl Drop for VaultSigningKeypair {
    fn drop(&mut self) {
        self.ed25519_secret.zeroize();
        self.mldsa87_secret.zeroize();
    }
}

/// Dual-sign `data` with Ed25519 + ML-DSA-87 (vault high-security profile).
pub fn dual_sign_87(ed_secret: &[u8; 32], mldsa87_secret: &[u8], data: &[u8]) -> Result<DualSignature87> {
    let ed = SigningKey::from_bytes(ed_secret);
    let ed_sig = ed.sign(data);

    let pq_secret = mldsa87::SecretKey::from_bytes(mldsa87_secret)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-DSA-87 secret key: {e:?}")))?;
    let pq_sig = mldsa87::detached_sign(data, &pq_secret);

    Ok(DualSignature87 {
        ed25519: ed_sig.to_bytes().to_vec(),
        ml_dsa_87: mldsa87::DetachedSignature::as_bytes(&pq_sig).to_vec(),
    })
}

/// Verify an Ed25519 + ML-DSA-87 dual signature. Both must validate.
pub fn dual_verify_87(
    ed_public: &[u8],
    mldsa87_public: &[u8],
    data: &[u8],
    sig: &DualSignature87,
) -> Result<()> {
    if ed_public.len() != 32 || sig.ed25519.len() != 64 {
        return Err(QGuardError::Crypto(
            "invalid Ed25519 key or signature length".to_string(),
        ));
    }

    let mut ed_pub_arr = [0u8; 32];
    ed_pub_arr.copy_from_slice(ed_public);
    let verifying = VerifyingKey::from_bytes(&ed_pub_arr)
        .map_err(|e| QGuardError::Crypto(format!("invalid Ed25519 public key: {e}")))?;

    let mut ed_sig_arr = [0u8; 64];
    ed_sig_arr.copy_from_slice(&sig.ed25519);
    let ed_sig = Ed25519Signature::from_bytes(&ed_sig_arr);
    verifying
        .verify(data, &ed_sig)
        .map_err(|_| QGuardError::Crypto("Ed25519 signature verification failed".to_string()))?;

    let pq_public = mldsa87::PublicKey::from_bytes(mldsa87_public)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-DSA-87 public key: {e:?}")))?;
    let pq_sig = mldsa87::DetachedSignature::from_bytes(&sig.ml_dsa_87)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-DSA-87 signature: {e:?}")))?;
    mldsa87::verify_detached_signature(&pq_sig, data, &pq_public)
        .map_err(|_| QGuardError::Crypto("ML-DSA-87 signature verification failed".to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_signature_rejects_tamper() {
        let signer = LocalSigningKeypair::generate();
        let sig = dual_sign(&signer.ed25519_secret, &signer.mldsa_secret, b"metadata").unwrap();
        assert!(dual_verify(
            &signer.ed25519_public,
            &signer.mldsa_public,
            b"metadata",
            &sig
        )
        .is_ok());
        assert!(dual_verify(
            &signer.ed25519_public,
            &signer.mldsa_public,
            b"tampered",
            &sig
        )
        .is_err());
    }

    #[test]
    fn vault_dual_signature_87_rejects_tamper() {
        let signer = VaultSigningKeypair::generate();
        let sig = dual_sign_87(&signer.ed25519_secret, &signer.mldsa87_secret, b"vault-header").unwrap();
        assert!(dual_verify_87(
            &signer.ed25519_public,
            &signer.mldsa87_public,
            b"vault-header",
            &sig
        )
        .is_ok());
        assert!(dual_verify_87(
            &signer.ed25519_public,
            &signer.mldsa87_public,
            b"tampered-header",
            &sig
        )
        .is_err());
    }
}
