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

/// The label this build registers new devices under.
///
/// Every call site used to pass the literal `"Windows Desktop"`, on every
/// platform -- so an Android phone and a Windows desktop registered under the
/// SAME label. The delivery selector bucketed peers by `user_id:device_label`,
/// which meant an entire account collapsed into one addressable device: calls
/// rang the wrong endpoint and messages reached only one device. Selection is
/// no longer label-based (see `lib/delivery-devices.ts`), but the label is user
/// visible in Device Trust / Security Verification and must be truthful.
pub fn platform_device_label() -> &'static str {
    if cfg!(target_os = "android") {
        "Android Device"
    } else if cfg!(target_os = "ios") {
        "iOS Device"
    } else if cfg!(target_os = "macos") {
        "macOS Desktop"
    } else if cfg!(target_os = "linux") {
        "Linux Desktop"
    } else if cfg!(target_os = "windows") {
        "Windows Desktop"
    } else {
        "QGuard Device"
    }
}

/// Labels written by builds that hardcoded the desktop string everywhere. A
/// restored identity carrying one of these on a platform it cannot be true for
/// is corrected on load; `device_label` is deliberately NOT part of
/// `identity_signable`, so relabelling never invalidates a device signature.
pub fn is_legacy_hardcoded_label(label: &str) -> bool {
    label.trim().eq_ignore_ascii_case("Windows Desktop")
}

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
    /// The device row this identity SUPERSEDES, when this launch re-keyed.
    ///
    /// A re-key mints a new `device_id`, so the row the old identity registered
    /// is left behind still advertising an active prekey. Peers keep selecting
    /// it for delivery (it is trusted, well-formed and recent), and every
    /// envelope sealed to it is undecryptable from the moment it is written --
    /// the private key is gone. That is how a single account accumulated five
    /// dead prekey ids and hundreds of unreadable envelopes.
    ///
    /// Informational and unsigned: `identity_signable` does not cover it, so it
    /// cannot affect any device signature. The client uses it to revoke the
    /// superseded row right after registering the new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_device_id: Option<String>,
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
            replaced_device_id: None,
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
