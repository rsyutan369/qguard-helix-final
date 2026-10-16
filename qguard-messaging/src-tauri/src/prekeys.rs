use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::hybrid_kex::LocalKemKeypair;
use crate::crypto::kdf::sha3_hex;
use crate::crypto::signatures::{dual_sign, dual_verify};
use crate::crypto::DualSignature;
use crate::error::{QGuardError, Result};
use crate::identity::LocalIdentity;

// ---------------------------------------------------------------------------
// Prekey signatures
//
// A prekey is only worth sealing to if the device's identity signed it. The
// original payload for that signature was the bare concatenation
//
//     device_id || prekey_id || x25519_public || mlkem_public
//
// and it was the SAME for signed prekeys and one-time prekeys. Two problems:
//
//   * No domain separation. A signature made over a one-time prekey verifies
//     as a signed prekey and vice versa, and nothing marks either as "a prekey
//     signature" as opposed to any other thing this identity key signs.
//   * No framing. The fields are simply run together, so the split between
//     them is implied by their usual lengths rather than stated.
//
// Version 2 fixes both: a kind-specific context string, every field
// length-prefixed, and the owner's user id and the creation time included.
//
// Compatibility: the identity signs BOTH payloads. The version-2 signature
// rides inside the same JSON object as the original (`v2`), which builds that
// predate it ignore — they go on verifying the original — while this build
// verifies version 2 whenever it is present. A prekey published by an older
// build has no `v2` and is verified the original way.
//
// What that does and does not buy, stated plainly: between two current builds
// the confusion above is closed. It is NOT a defence against a relay that
// strips `v2` — that only puts the check back where it was. Requiring `v2`
// outright becomes possible once no supported build publishes prekeys without
// it.
// ---------------------------------------------------------------------------

const SIGNED_PREKEY_CONTEXT_V2: &[u8] = b"QGuard-Signed-Prekey-v2";
const ONE_TIME_PREKEY_CONTEXT_V2: &[u8] = b"QGuard-One-Time-Prekey-v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrekeyKind {
    Signed,
    OneTime,
}

/// The domain-separated half of a prekey signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrekeySignatureV2 {
    pub ed25519: Vec<u8>,
    pub ml_dsa_65: Vec<u8>,
    /// When the prekey was made (unix seconds). Covered by the signature, so
    /// it is the one statement of the prekey's age the relay cannot edit.
    pub created_at: i64,
}

/// A prekey's signature as published: the original dual signature, plus the
/// version-2 one when the publishing build makes it. The JSON shape is the
/// original `{ed25519, ml_dsa_65}` with one optional extra field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrekeySignature {
    pub ed25519: Vec<u8>,
    pub ml_dsa_65: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v2: Option<PrekeySignatureV2>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicSignedPrekey {
    pub prekey_id: String,
    pub device_id: String,
    pub x25519_public: Vec<u8>,
    pub mlkem_public: Vec<u8>,
    pub signature: PrekeySignature,
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
    pub signature: PrekeySignature,
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

/// Sign a prekey with the device identity: the original payload, and the
/// version-2 one.
fn sign_prekey(
    identity: &LocalIdentity,
    kind: PrekeyKind,
    prekey_id: &str,
    x25519_public: &[u8],
    mlkem_public: &[u8],
    created_at: i64,
) -> Result<PrekeySignature> {
    let legacy = dual_sign(
        &identity.signing.ed25519_secret,
        &identity.signing.mldsa_secret,
        &legacy_prekey_signable(kind, &identity.device_id, prekey_id, x25519_public, mlkem_public),
    )?;
    let v2 = dual_sign(
        &identity.signing.ed25519_secret,
        &identity.signing.mldsa_secret,
        &prekey_signable_v2(
            kind,
            &identity.user_id,
            &identity.device_id,
            prekey_id,
            x25519_public,
            mlkem_public,
            created_at,
        ),
    )?;
    Ok(PrekeySignature {
        ed25519: legacy.ed25519,
        ml_dsa_65: legacy.ml_dsa_65,
        v2: Some(PrekeySignatureV2 {
            ed25519: v2.ed25519,
            ml_dsa_65: v2.ml_dsa_65,
            created_at,
        }),
    })
}

pub fn generate_signed_prekey(identity: &LocalIdentity) -> Result<LocalSignedPrekey> {
    let keys = LocalKemKeypair::generate();
    let prekey_id = Uuid::new_v4().to_string();
    let created_at = Utc::now();
    let signature = sign_prekey(
        identity,
        PrekeyKind::Signed,
        &prekey_id,
        &keys.x25519_public,
        &keys.mlkem_public,
        created_at.timestamp(),
    )?;
    let fingerprint = sha3_hex(&signed_prekey_signable(
        &identity.device_id,
        &prekey_id,
        &keys.x25519_public,
        &keys.mlkem_public,
    ));

    Ok(LocalSignedPrekey {
        public: PublicSignedPrekey {
            prekey_id,
            device_id: identity.device_id.clone(),
            x25519_public: keys.x25519_public.clone(),
            mlkem_public: keys.mlkem_public.clone(),
            signature,
            fingerprint,
            created_at,
            expires_at: created_at + chrono::Duration::days(30),
        },
        x25519_secret: keys.x25519_secret,
        mlkem_secret: keys.mlkem_secret.clone(),
    })
}

/// The original signed-prekey payload. Kept byte-for-byte: prekeys published
/// by builds that predate version 2 carry only a signature over this.
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
            let created_at = Utc::now();
            let signature = sign_prekey(
                identity,
                PrekeyKind::OneTime,
                &prekey_id,
                &keys.x25519_public,
                &keys.mlkem_public,
                created_at.timestamp(),
            )?;
            let fingerprint = sha3_hex(&one_time_prekey_signable(
                &identity.device_id,
                &prekey_id,
                &keys.x25519_public,
                &keys.mlkem_public,
            ));

            Ok(LocalOneTimePrekey {
                public: PublicOneTimePrekey {
                    prekey_id,
                    device_id: identity.device_id.clone(),
                    x25519_public: keys.x25519_public.clone(),
                    mlkem_public: keys.mlkem_public.clone(),
                    signature,
                    fingerprint,
                    created_at,
                },
                x25519_secret: keys.x25519_secret,
                mlkem_secret: keys.mlkem_secret.clone(),
            })
        })
        .collect()
}

/// The original one-time-prekey payload — identical to the signed-prekey one,
/// which is the defect version 2 exists to fix. Kept byte-for-byte for the
/// same reason as [`signed_prekey_signable`].
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

fn legacy_prekey_signable(
    kind: PrekeyKind,
    device_id: &str,
    prekey_id: &str,
    x25519_public: &[u8],
    mlkem_public: &[u8],
) -> Vec<u8> {
    match kind {
        PrekeyKind::Signed => signed_prekey_signable(device_id, prekey_id, x25519_public, mlkem_public),
        PrekeyKind::OneTime => one_time_prekey_signable(device_id, prekey_id, x25519_public, mlkem_public),
    }
}

/// The version-2 payload: a context string that differs by kind, then every
/// field length-prefixed.
pub fn prekey_signable_v2(
    kind: PrekeyKind,
    user_id: &str,
    device_id: &str,
    prekey_id: &str,
    x25519_public: &[u8],
    mlkem_public: &[u8],
    created_at: i64,
) -> Vec<u8> {
    let context = match kind {
        PrekeyKind::Signed => SIGNED_PREKEY_CONTEXT_V2,
        PrekeyKind::OneTime => ONE_TIME_PREKEY_CONTEXT_V2,
    };
    let created_at = created_at.to_be_bytes();
    let mut signable = Vec::with_capacity(
        context.len() + user_id.len() + device_id.len() + prekey_id.len() + x25519_public.len() + mlkem_public.len() + 8 + 7 * 4,
    );
    for field in [
        context,
        user_id.as_bytes(),
        device_id.as_bytes(),
        prekey_id.as_bytes(),
        x25519_public,
        mlkem_public,
        &created_at,
    ] {
        signable.extend_from_slice(&(field.len() as u32).to_be_bytes());
        signable.extend_from_slice(field);
    }
    signable
}

/// What a verified prekey signature established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrekeyVerification {
    /// True when the version-2 signature was present and verified: the prekey
    /// is bound to its kind, its owner and its creation time. False when only
    /// the original signature was available (an older publisher).
    pub domain_separated: bool,
    /// The signed creation time, when version 2 was verified.
    pub created_at: Option<i64>,
}

/// Verify a prekey's signature against the identity keys of the device that
/// published it.
///
/// Version 2 is checked whenever it is present, and a version-2 signature that
/// is present and does NOT verify fails the prekey — it never falls back to
/// the original signature, or attaching a broken `v2` would be a way to select
/// the weaker check.
#[allow(clippy::too_many_arguments)]
pub fn verify_prekey_signature(
    kind: PrekeyKind,
    user_id: &str,
    device_id: &str,
    prekey_id: &str,
    x25519_public: &[u8],
    mlkem_public: &[u8],
    ed25519_identity_public: &[u8],
    mldsa_identity_public: &[u8],
    signature: &PrekeySignature,
) -> Result<PrekeyVerification> {
    if let Some(v2) = &signature.v2 {
        dual_verify(
            ed25519_identity_public,
            mldsa_identity_public,
            &prekey_signable_v2(
                kind,
                user_id,
                device_id,
                prekey_id,
                x25519_public,
                mlkem_public,
                v2.created_at,
            ),
            &DualSignature {
                ed25519: v2.ed25519.clone(),
                ml_dsa_65: v2.ml_dsa_65.clone(),
            },
        )
        .map_err(|_| {
            QGuardError::Crypto(format!(
                "prekey {prekey_id} carries a version-2 signature that does not verify; refusing it"
            ))
        })?;
        return Ok(PrekeyVerification {
            domain_separated: true,
            created_at: Some(v2.created_at),
        });
    }
    dual_verify(
        ed25519_identity_public,
        mldsa_identity_public,
        &legacy_prekey_signable(kind, device_id, prekey_id, x25519_public, mlkem_public),
        &DualSignature {
            ed25519: signature.ed25519.clone(),
            ml_dsa_65: signature.ml_dsa_65.clone(),
        },
    )?;
    Ok(PrekeyVerification {
        domain_separated: false,
        created_at: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verify(
        identity: &LocalIdentity,
        kind: PrekeyKind,
        prekey_id: &str,
        x25519_public: &[u8],
        mlkem_public: &[u8],
        signature: &PrekeySignature,
    ) -> Result<PrekeyVerification> {
        verify_prekey_signature(
            kind,
            &identity.user_id,
            &identity.device_id,
            prekey_id,
            x25519_public,
            mlkem_public,
            &identity.signing.ed25519_public,
            &identity.signing.mldsa_public,
            signature,
        )
    }

    #[test]
    fn prekeys_are_unique() {
        let identity = LocalIdentity::generate("user", "Desktop").unwrap();
        let signed = generate_signed_prekey(&identity).unwrap();
        let otk = generate_one_time_prekeys(&identity, 8).unwrap();
        assert_eq!(otk.len(), 8);
        assert_ne!(signed.public.fingerprint, otk[0].public.fingerprint);
    }

    #[test]
    fn a_new_prekey_carries_both_signatures_and_verifies_as_its_own_kind() {
        let identity = LocalIdentity::generate("user", "Desktop").unwrap();
        let signed = generate_signed_prekey(&identity).unwrap().public.clone();
        let outcome = verify(
            &identity,
            PrekeyKind::Signed,
            &signed.prekey_id,
            &signed.x25519_public,
            &signed.mlkem_public,
            &signed.signature,
        )
        .unwrap();
        assert!(outcome.domain_separated);
        assert_eq!(outcome.created_at, Some(signed.created_at.timestamp()));

        let one_time = generate_one_time_prekeys(&identity, 1).unwrap().pop().unwrap().public.clone();
        assert!(verify(
            &identity,
            PrekeyKind::OneTime,
            &one_time.prekey_id,
            &one_time.x25519_public,
            &one_time.mlkem_public,
            &one_time.signature,
        )
        .unwrap()
        .domain_separated);
    }

    /// The defect: with the original payload, one kind of prekey passes as the
    /// other. With version 2 it does not.
    #[test]
    fn a_prekey_of_one_kind_no_longer_verifies_as_the_other() {
        let identity = LocalIdentity::generate("user", "Desktop").unwrap();
        let one_time = generate_one_time_prekeys(&identity, 1).unwrap().pop().unwrap().public.clone();

        // Presented as a SIGNED prekey: refused.
        assert!(verify(
            &identity,
            PrekeyKind::Signed,
            &one_time.prekey_id,
            &one_time.x25519_public,
            &one_time.mlkem_public,
            &one_time.signature,
        )
        .is_err());

        // The same prekey with `v2` removed still passes as either kind —
        // which is the original behaviour, and why `v2` matters.
        let stripped = PrekeySignature { v2: None, ..one_time.signature.clone() };
        for kind in [PrekeyKind::Signed, PrekeyKind::OneTime] {
            let outcome = verify(
                &identity,
                kind,
                &one_time.prekey_id,
                &one_time.x25519_public,
                &one_time.mlkem_public,
                &stripped,
            )
            .unwrap();
            assert!(!outcome.domain_separated);
        }
    }

    #[test]
    fn a_broken_v2_signature_fails_the_prekey_instead_of_falling_back() {
        let identity = LocalIdentity::generate("user", "Desktop").unwrap();
        let signed = generate_signed_prekey(&identity).unwrap().public.clone();
        let check = |signature: &PrekeySignature| {
            verify(
                &identity,
                PrekeyKind::Signed,
                &signed.prekey_id,
                &signed.x25519_public,
                &signed.mlkem_public,
                signature,
            )
        };

        let mut tampered = signed.signature.clone();
        tampered.v2.as_mut().unwrap().ml_dsa_65[0] ^= 0x01;
        assert!(check(&tampered).is_err());

        // The creation time is signed: it cannot be moved.
        let mut redated = signed.signature.clone();
        redated.v2.as_mut().unwrap().created_at += 86_400;
        assert!(check(&redated).is_err());

        // The original signature beside it is still perfectly valid, and is
        // deliberately NOT consulted.
        assert!(check(&PrekeySignature { v2: None, ..signed.signature.clone() }).is_ok());
    }

    #[test]
    fn a_prekey_is_bound_to_its_owner_device_and_id() {
        let identity = LocalIdentity::generate("user", "Desktop").unwrap();
        let other = LocalIdentity::generate("user", "Phone").unwrap();
        let signed = generate_signed_prekey(&identity).unwrap().public.clone();

        // Another device's identity keys.
        assert!(verify(
            &other,
            PrekeyKind::Signed,
            &signed.prekey_id,
            &signed.x25519_public,
            &signed.mlkem_public,
            &signed.signature,
        )
        .is_err());
        // Another prekey id.
        assert!(verify(
            &identity,
            PrekeyKind::Signed,
            "another-id",
            &signed.x25519_public,
            &signed.mlkem_public,
            &signed.signature,
        )
        .is_err());
        // Another owner, same device keys: only version 2 covers the user id.
        assert!(verify_prekey_signature(
            PrekeyKind::Signed,
            "someone-else",
            &identity.device_id,
            &signed.prekey_id,
            &signed.x25519_public,
            &signed.mlkem_public,
            &identity.signing.ed25519_public,
            &identity.signing.mldsa_public,
            &signed.signature,
        )
        .is_err());
        // Swapped KEM key.
        let swapped = LocalKemKeypair::generate();
        assert!(verify(
            &identity,
            PrekeyKind::Signed,
            &signed.prekey_id,
            &signed.x25519_public,
            &swapped.mlkem_public,
            &signed.signature,
        )
        .is_err());
    }

    #[test]
    fn a_prekey_from_an_older_build_still_verifies() {
        // What an older build published: the original signature only.
        let identity = LocalIdentity::generate("user", "Desktop").unwrap();
        let keys = LocalKemKeypair::generate();
        let legacy = dual_sign(
            &identity.signing.ed25519_secret,
            &identity.signing.mldsa_secret,
            &signed_prekey_signable(&identity.device_id, "old-prekey", &keys.x25519_public, &keys.mlkem_public),
        )
        .unwrap();
        // ...and its JSON, exactly as stored on the relay, parses unchanged.
        let json = serde_json::json!({ "ed25519": legacy.ed25519, "ml_dsa_65": legacy.ml_dsa_65 });
        let parsed: PrekeySignature = serde_json::from_value(json).unwrap();
        assert!(parsed.v2.is_none());
        let outcome = verify(
            &identity,
            PrekeyKind::Signed,
            "old-prekey",
            &keys.x25519_public,
            &keys.mlkem_public,
            &parsed,
        )
        .unwrap();
        assert!(!outcome.domain_separated);
        assert_eq!(outcome.created_at, None);
    }

    #[test]
    fn the_published_json_keeps_its_original_shape() {
        let identity = LocalIdentity::generate("user", "Desktop").unwrap();
        let signed = generate_signed_prekey(&identity).unwrap().public.clone();
        let json = serde_json::to_value(&signed.signature).unwrap();
        // An older build reads exactly these two fields and ignores the rest.
        assert!(json["ed25519"].is_array());
        assert!(json["ml_dsa_65"].is_array());
        let as_legacy: DualSignature = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(as_legacy.ed25519, signed.signature.ed25519);
        // And a signature without `v2` serializes without the field at all.
        let stripped = serde_json::to_value(PrekeySignature { v2: None, ..signed.signature }).unwrap();
        assert!(stripped.get("v2").is_none());
    }

    #[test]
    fn v2_payloads_differ_by_kind_and_cannot_be_reframed() {
        let args = ("user", "device", "prekey", b"x".as_slice(), b"k".as_slice(), 7i64);
        let signed = prekey_signable_v2(PrekeyKind::Signed, args.0, args.1, args.2, args.3, args.4, args.5);
        let one_time = prekey_signable_v2(PrekeyKind::OneTime, args.0, args.1, args.2, args.3, args.4, args.5);
        assert_ne!(signed, one_time);
        // Moving a byte between adjacent fields changes the payload.
        assert_ne!(
            prekey_signable_v2(PrekeyKind::Signed, "user", "deviceX", "prekey", b"x", b"k", 7),
            prekey_signable_v2(PrekeyKind::Signed, "user", "device", "Xprekey", b"x", b"k", 7),
        );
        // The original payload cannot tell those two apart — that is the gap.
        assert_eq!(
            signed_prekey_signable("deviceX", "prekey", b"x", b"k"),
            signed_prekey_signable("device", "Xprekey", b"x", b"k"),
        );
    }
}
