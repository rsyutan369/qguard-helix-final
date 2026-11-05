use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{QGuardError, Result};

use super::provider::{self, MlDsa};
use super::{DualSignature, DualSignature87};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSigningKeypair {
    pub ed25519_secret: [u8; 32],
    pub ed25519_public: Vec<u8>,
    pub mldsa_secret: Vec<u8>,
    pub mldsa_public: Vec<u8>,
}

impl LocalSigningKeypair {
    pub fn try_generate() -> Result<Self> {
        let (ed_seed, ed_public) = provider::ed25519_generate()?;
        let (pq_public, pq_secret) = provider::mldsa_generate(MlDsa::Ml65)?;

        Ok(Self {
            ed25519_secret: *ed_seed,
            ed25519_public: ed_public.to_vec(),
            mldsa_secret: pq_secret.to_vec(),
            mldsa_public: pq_public,
        })
    }

    /// [`Self::try_generate`] for callers with no error path. Fails only when
    /// the cryptographic self-test has disabled key generation.
    pub fn generate() -> Self {
        Self::try_generate().expect("device signing key generation")
    }
}

impl Drop for LocalSigningKeypair {
    fn drop(&mut self) {
        self.ed25519_secret.zeroize();
        self.mldsa_secret.zeroize();
    }
}

pub fn dual_sign(ed_secret: &[u8; 32], mldsa_secret: &[u8], data: &[u8]) -> Result<DualSignature> {
    let ed_sig = provider::ed25519_sign(ed_secret, data)?;
    let pq_sig = provider::mldsa_sign(MlDsa::Ml65, mldsa_secret, data)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-DSA secret key: {e}")))?;

    Ok(DualSignature {
        ed25519: ed_sig.to_vec(),
        ml_dsa_65: pq_sig,
    })
}

/// Both halves must verify; each is checked on its own.
pub fn dual_verify(
    ed_public: &[u8],
    mldsa_public: &[u8],
    data: &[u8],
    sig: &DualSignature,
) -> Result<()> {
    provider::ed25519_verify(ed_public, data, &sig.ed25519)?;
    provider::mldsa_verify(MlDsa::Ml65, mldsa_public, data, &sig.ml_dsa_65)
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
    pub fn try_generate() -> Result<Self> {
        let (ed_seed, ed_public) = provider::ed25519_generate()?;
        let (pq_public, pq_secret) = provider::mldsa_generate(MlDsa::Ml87)?;

        Ok(Self {
            ed25519_secret: *ed_seed,
            ed25519_public: ed_public.to_vec(),
            mldsa87_secret: pq_secret.to_vec(),
            mldsa87_public: pq_public,
        })
    }

    /// [`Self::try_generate`] for callers with no error path. Fails only when
    /// the cryptographic self-test has disabled key generation.
    pub fn generate() -> Self {
        Self::try_generate().expect("vault signing key generation")
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
    let ed_sig = provider::ed25519_sign(ed_secret, data)?;
    let pq_sig = provider::mldsa_sign(MlDsa::Ml87, mldsa87_secret, data)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-DSA-87 secret key: {e}")))?;

    Ok(DualSignature87 {
        ed25519: ed_sig.to_vec(),
        ml_dsa_87: pq_sig,
    })
}

/// Verify an Ed25519 + ML-DSA-87 dual signature. Both must validate.
pub fn dual_verify_87(
    ed_public: &[u8],
    mldsa87_public: &[u8],
    data: &[u8],
    sig: &DualSignature87,
) -> Result<()> {
    provider::ed25519_verify(ed_public, data, &sig.ed25519)?;
    provider::mldsa_verify(MlDsa::Ml87, mldsa87_public, data, &sig.ml_dsa_87)
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
