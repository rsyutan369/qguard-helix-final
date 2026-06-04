use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::hybrid_kex::LocalKemKeypair;
use crate::crypto::kdf::sha3_hex;
use crate::crypto::signatures::dual_sign;
use crate::crypto::DualSignature;
use crate::error::Result;
use crate::identity::LocalIdentity;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicSignedPrekey {
    pub prekey_id: String,
    pub device_id: String,
    pub x25519_public: Vec<u8>,
    pub mlkem_public: Vec<u8>,
    pub signature: DualSignature,
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicOneTimePrekey {
    pub prekey_id: String,
    pub device_id: String,
    pub x25519_public: Vec<u8>,
    pub mlkem_public: Vec<u8>,
    pub signature: DualSignature,
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSignedPrekey {
    pub public: PublicSignedPrekey,
    pub x25519_secret: [u8; 32],
    pub mlkem_secret: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalOneTimePrekey {
    pub public: PublicOneTimePrekey,
    pub x25519_secret: [u8; 32],
    pub mlkem_secret: Vec<u8>,
}

impl Drop for LocalSignedPrekey {
    fn drop(&mut self) {
        self.x25519_secret.zeroize();
        self.mlkem_secret.zeroize();
    }
}

impl Drop for LocalOneTimePrekey {
    fn drop(&mut self) {
        self.x25519_secret.zeroize();
        self.mlkem_secret.zeroize();
    }
}

pub fn generate_signed_prekey(identity: &LocalIdentity) -> Result<LocalSignedPrekey> {
    let keys = LocalKemKeypair::generate();
    let prekey_id = Uuid::new_v4().to_string();
    let signable = signed_prekey_signable(
        &identity.device_id,
        &prekey_id,
        &keys.x25519_public,
        &keys.mlkem_public,
    );

    let signature = dual_sign(
        &identity.signing.ed25519_secret,
        &identity.signing.mldsa_secret,
        &signable,
    )?;
    let fingerprint = sha3_hex(&signable);

    Ok(LocalSignedPrekey {
        public: PublicSignedPrekey {
            prekey_id,
            device_id: identity.device_id.clone(),
            x25519_public: keys.x25519_public.clone(),
            mlkem_public: keys.mlkem_public.clone(),
            signature,
            fingerprint,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(30),
        },
        x25519_secret: keys.x25519_secret,
        mlkem_secret: keys.mlkem_secret.clone(),
    })
}

pub fn signed_prekey_signable(
    device_id: &str,
    prekey_id: &str,
    x25519_public: &[u8],
    mlkem_public: &[u8],
) -> Vec<u8> {
    let mut signable = Vec::new();
    signable.extend_from_slice(device_id.as_bytes());
    signable.extend_from_slice(prekey_id.as_bytes());
    signable.extend_from_slice(x25519_public);
    signable.extend_from_slice(mlkem_public);
    signable
}

pub fn generate_one_time_prekeys(
    identity: &LocalIdentity,
    count: usize,
) -> Result<Vec<LocalOneTimePrekey>> {
    (0..count)
        .map(|_| {
            let keys = LocalKemKeypair::generate();
            let prekey_id = Uuid::new_v4().to_string();
            let signable = one_time_prekey_signable(
                &identity.device_id,
                &prekey_id,
                &keys.x25519_public,
                &keys.mlkem_public,
            );
            let signature = dual_sign(
                &identity.signing.ed25519_secret,
                &identity.signing.mldsa_secret,
                &signable,
            )?;

            Ok(LocalOneTimePrekey {
                public: PublicOneTimePrekey {
                    prekey_id,
                    device_id: identity.device_id.clone(),
                    x25519_public: keys.x25519_public.clone(),
                    mlkem_public: keys.mlkem_public.clone(),
                    signature,
                    fingerprint: sha3_hex(&signable),
                    created_at: Utc::now(),
                },
                x25519_secret: keys.x25519_secret,
                mlkem_secret: keys.mlkem_secret.clone(),
            })
        })
        .collect()
}

pub fn one_time_prekey_signable(
    device_id: &str,
    prekey_id: &str,
    x25519_public: &[u8],
    mlkem_public: &[u8],
) -> Vec<u8> {
    let mut signable = Vec::new();
    signable.extend_from_slice(device_id.as_bytes());
    signable.extend_from_slice(prekey_id.as_bytes());
    signable.extend_from_slice(x25519_public);
    signable.extend_from_slice(mlkem_public);
    signable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prekeys_are_unique() {
        let identity = LocalIdentity::generate("user", "Desktop").unwrap();
        let signed = generate_signed_prekey(&identity).unwrap();
        let otk = generate_one_time_prekeys(&identity, 8).unwrap();
        assert_eq!(otk.len(), 8);
        assert_ne!(signed.public.fingerprint, otk[0].public.fingerprint);
    }
}
