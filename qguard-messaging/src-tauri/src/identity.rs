use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{
    hybrid_kex::LocalKemKeypair,
    kdf::sha3_hex,
    signatures::{dual_sign, dual_verify, LocalSigningKeypair},
    AlgorithmSuite, DualSignature,
};
use crate::error::Result;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicIdentityBundle {
    pub user_id: String,
    pub device_id: String,
    pub identity_id: String,
    pub device_label: String,
    pub x25519_identity_public: Vec<u8>,
    pub mlkem_identity_public: Vec<u8>,
    pub ed25519_identity_public: Vec<u8>,
    pub mldsa_identity_public: Vec<u8>,
    pub signature: DualSignature,
    pub fingerprint: String,
    pub suite: AlgorithmSuite,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalIdentity {
    pub user_id: String,
    pub device_id: String,
    pub identity_id: String,
    pub device_label: String,
    pub kem: LocalKemKeypair,
    pub signing: LocalSigningKeypair,
    pub created_at: DateTime<Utc>,
}

impl LocalIdentity {
    pub fn generate(user_id: impl Into<String>, device_label: impl Into<String>) -> Result<Self> {
        Ok(Self {
            user_id: user_id.into(),
            device_id: Uuid::new_v4().to_string(),
            identity_id: Uuid::new_v4().to_string(),
            device_label: device_label.into(),
            kem: LocalKemKeypair::generate(),
            signing: LocalSigningKeypair::generate(),
            created_at: Utc::now(),
        })
    }

    pub fn public_bundle(&self) -> Result<PublicIdentityBundle> {
        let signable = identity_signable(
            &self.user_id,
            &self.device_id,
            &self.kem.x25519_public,
            &self.kem.mlkem_public,
            &self.signing.ed25519_public,
            &self.signing.mldsa_public,
        );

        let signature = dual_sign(
            &self.signing.ed25519_secret,
            &self.signing.mldsa_secret,
            &signable,
        )?;
        let fingerprint =
            safety_fingerprint(&self.signing.ed25519_public, &self.signing.mldsa_public);

        Ok(PublicIdentityBundle {
            user_id: self.user_id.clone(),
            device_id: self.device_id.clone(),
            identity_id: self.identity_id.clone(),
            device_label: self.device_label.clone(),
            x25519_identity_public: self.kem.x25519_public.clone(),
            mlkem_identity_public: self.kem.mlkem_public.clone(),
            ed25519_identity_public: self.signing.ed25519_public.clone(),
            mldsa_identity_public: self.signing.mldsa_public.clone(),
            signature,
            fingerprint,
            suite: AlgorithmSuite::default(),
            created_at: self.created_at,
        })
    }
}

pub fn identity_signable(
    user_id: &str,
    device_id: &str,
    x25519_public: &[u8],
    mlkem_public: &[u8],
    ed25519_public: &[u8],
    mldsa_public: &[u8],
) -> Vec<u8> {
    let mut signable = Vec::new();
    signable.extend_from_slice(user_id.as_bytes());
    signable.extend_from_slice(device_id.as_bytes());
    signable.extend_from_slice(x25519_public);
    signable.extend_from_slice(mlkem_public);
    signable.extend_from_slice(ed25519_public);
    signable.extend_from_slice(mldsa_public);
    signable
}

pub fn verify_identity_bundle(
    user_id: &str,
    device_id: &str,
    x25519_public: &[u8],
    mlkem_public: &[u8],
    ed25519_public: &[u8],
    mldsa_public: &[u8],
    signature: &DualSignature,
) -> Result<()> {
    let signable = identity_signable(
        user_id,
        device_id,
        x25519_public,
        mlkem_public,
        ed25519_public,
        mldsa_public,
    );
    dual_verify(ed25519_public, mldsa_public, &signable, signature)
}

pub fn safety_fingerprint(ed_public: &[u8], mldsa_public: &[u8]) -> String {
    let mut data = Vec::with_capacity(ed_public.len() + mldsa_public.len());
    data.extend_from_slice(ed_public);
    data.extend_from_slice(mldsa_public);
    let hex = sha3_hex(&data);
    hex.as_bytes()
        .chunks(4)
        .take(12)
        .map(|chunk| {
            std::str::from_utf8(chunk)
                .unwrap_or_default()
                .to_uppercase()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_bundle_has_safety_fingerprint() {
        let identity = LocalIdentity::generate("user", "Windows Desktop").unwrap();
        let bundle = identity.public_bundle().unwrap();
        assert_eq!(bundle.device_label, "Windows Desktop");
        assert!(bundle.fingerprint.len() > 20);
    }
}
