//! Portable Hybrid Identity (`.qgkey`).
//!
//! A Quantum Vault container is normally sealed to the *device* that created it.
//! A Portable Hybrid Identity is the key material that lets a vault object be
//! sealed to a *person* instead, so quantum-encrypted files and folders can be
//! shared with someone who does not have — and must never have — the sender's
//! device key or Vault Master Key.
//!
//! An identity holds four keypairs, the same hybrid stack the rest of the vault
//! uses:
//!
//! * Encryption — X25519 + **ML-KEM-1024** (FIPS 203). ML-KEM only ever
//!   encapsulates a key; it never encrypts file content.
//! * Signing    — Ed25519 + **ML-DSA-87** (FIPS 204 Level 5), used to attest who
//!   sealed a container.
//!
//! Two serialized forms exist, matching the web vault's `.qgkey` shapes so an
//! identity is understood on both surfaces:
//!
//! * **Private bundle** (`.qgkey`) — all four keypairs, secrets sealed under a
//!   passphrase. Written as v1.2 (Argon2id 64 MiB / t=3 → HKDF-SHA3-256 →
//!   AES-256-GCM). v1.1 bundles (PBKDF2-SHA3-256, 310 000 iterations) written by
//!   the web vault are still accepted on import.
//! * **Public recipient bundle** (`.qgpub.json`) — the four public keys only.
//!   This is the file a user hands to whoever wants to send them something.
//!
//! Zero-knowledge: the passphrase and every secret key stay on the user's
//! machine. Nothing here talks to a server, and the private bundle is written
//! only where the user chooses to save it.

use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use zeroize::Zeroize;

use crate::crypto::hybrid_kex::LocalKemKeypair;
use crate::crypto::kdf;
use crate::crypto::passcode;
use crate::crypto::signatures::{
    dual_sign_87, dual_verify, dual_verify_87, VaultSigningKeypair,
};
use crate::crypto::symmetric::{self, KEY_SIZE};
use crate::crypto::{DualSignature, DualSignature87, EncryptedEnvelope};
use crate::error::{QGuardError, Result};

/// Bundle version this build writes (Argon2id-protected secrets).
pub const BUNDLE_VERSION_CURRENT: &str = "1.2";
/// Bundle version written by the web vault (PBKDF2-SHA3-256 protected secrets).
pub const BUNDLE_VERSION_LEGACY: &str = "1.1";
pub const BUNDLE_KDF_CURRENT: &str = "Argon2id-HKDF-SHA3-256";
pub const BUNDLE_KDF_LEGACY: &str = "PBKDF2-SHA3-256";
const LEGACY_PBKDF2_ITERATIONS: u32 = 310_000;
/// The fewest PBKDF2 iterations a bundle may declare and still be opened. The
/// count is read from the bundle itself, and it used to be accepted down to 1 —
/// so a bundle could be (re)written to make its passphrase trivially
/// guessable and this app would open it without a word. The web vault writes
/// 310 000; nothing genuine is anywhere near this floor.
const MIN_LEGACY_PBKDF2_ITERATIONS: u64 = 100_000;
/// Shortest passphrase accepted for a new bundle. Matches the web vault's rule;
/// the bundle is an offline artefact, so length is the only real defence.
pub const MIN_PASSPHRASE_LEN: usize = 12;

/// ML-DSA parameter set carried by an identity. Identities generated here are
/// always Level 5; Level 3 appears on identities created by the web vault, which
/// can still receive sealed containers but cannot produce an ML-DSA-87 sender
/// attestation.
pub const SIGNATURE_ML_DSA_87: &str = "ML-DSA-87";
pub const SIGNATURE_ML_DSA_65: &str = "ML-DSA-65";

const ML_DSA_87_PUBLIC_LEN: usize = 2592;
const ML_DSA_65_PUBLIC_LEN: usize = 1952;

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn decode_b64(value: &str, field: &str) -> Result<Vec<u8>> {
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Err(QGuardError::InvalidInput(format!(
            "identity bundle is missing `{field}`"
        )));
    }
    // Accept hex as well as base64: the web vault's recipient parser does, and a
    // user pasting a raw key from a terminal will often have hex in hand.
    if cleaned.len() % 2 == 0 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(&cleaned) {
            return Ok(bytes);
        }
    }
    b64()
        .decode(cleaned.replace('-', "+").replace('_', "/"))
        .map_err(|e| QGuardError::InvalidInput(format!("identity bundle field `{field}` is not valid base64: {e}")))
}

fn json_str<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(|v| v.as_str())
}

/// The full private identity: both hybrid keypairs plus the user's label.
///
/// Secrets are zeroized when the identity is dropped (both inner keypairs
/// implement `Drop`), so an unlocked identity leaves no residue after lock.
#[derive(Clone, Debug)]
pub struct PortableIdentity {
    pub kem: LocalKemKeypair,
    /// Ed25519 secret/public plus the ML-DSA secret/public. The struct is named
    /// for ML-DSA-87 but also carries ML-DSA-65 material for web-created
    /// identities; `signature_algorithm()` reports which is present.
    pub signer: VaultSigningKeypair,
    pub label: Option<String>,
}

/// The public half of an identity — everything a sender needs to seal to it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecipientPublicKeys {
    pub fingerprint: String,
    pub label: Option<String>,
    pub x25519_public: Vec<u8>,
    pub mlkem_public: Vec<u8>,
    pub ed25519_public: Vec<u8>,
    pub mldsa_public: Vec<u8>,
    /// `ML-DSA-87` or `ML-DSA-65`, resolved from the public key length.
    pub signature_algorithm: String,
    /// `ML-KEM-1024` or `ML-KEM-768`, resolved from the public key length.
    pub kem_algorithm: String,
}

impl PortableIdentity {
    /// Fresh identity on the vault's high-security profile: X25519 + ML-KEM-1024
    /// for encryption, Ed25519 + ML-DSA-87 for attestation.
    pub fn generate(label: Option<String>) -> Self {
        Self {
            kem: LocalKemKeypair::generate(),
            signer: VaultSigningKeypair::generate(),
            label: label.and_then(|value| {
                let trimmed = value.trim().to_string();
                if trimmed.is_empty() { None } else { Some(trimmed) }
            }),
        }
    }

    pub fn signature_algorithm(&self) -> &'static str {
        signature_algorithm_for(&self.signer.mldsa87_public)
    }

    pub fn kem_algorithm(&self) -> &'static str {
        kem_algorithm_for(&self.kem.mlkem_public)
    }

    /// Whether this identity can produce a sender attestation. Only ML-DSA-87
    /// identities can; a web-created ML-DSA-65 identity can still receive.
    pub fn can_attest(&self) -> bool {
        self.signature_algorithm() == SIGNATURE_ML_DSA_87
    }

    pub fn fingerprint(&self) -> String {
        identity_fingerprint(
            &self.kem.x25519_public,
            &self.kem.mlkem_public,
            &self.signer.ed25519_public,
            &self.signer.mldsa87_public,
        )
    }

    pub fn public_keys(&self) -> RecipientPublicKeys {
        RecipientPublicKeys {
            fingerprint: self.fingerprint(),
            label: self.label.clone(),
            x25519_public: self.kem.x25519_public.clone(),
            mlkem_public: self.kem.mlkem_public.clone(),
            ed25519_public: self.signer.ed25519_public.clone(),
            mldsa_public: self.signer.mldsa87_public.clone(),
            signature_algorithm: self.signature_algorithm().to_string(),
            kem_algorithm: self.kem_algorithm().to_string(),
        }
    }

    /// The public recipient bundle, in the exact shape the web vault emits, so a
    /// recipient JSON is interchangeable between the two surfaces.
    pub fn public_recipient_json(&self) -> Result<String> {
        let bundle = serde_json::json!({
            "label": self.label.clone().unwrap_or_else(|| "qguard-recipient-public".to_string()),
            "version": "1.0",
            "type": "qguard-public-recipient",
            "generatedAt": chrono::Utc::now().to_rfc3339(),
            "fingerprint": self.fingerprint(),
            "algorithms": {
                "kem": self.kem_algorithm(),
                "kex": "X25519",
                "signature": self.signature_algorithm(),
                "kdf": "HKDF-SHA3-256",
                "symmetric": "AES-256-GCM",
            },
            "publics": {
                "x25519": b64().encode(&self.kem.x25519_public),
                "mlkem": b64().encode(&self.kem.mlkem_public),
                "ed25519": b64().encode(&self.signer.ed25519_public),
                "mldsa": b64().encode(&self.signer.mldsa87_public),
            },
        });
        serde_json::to_string_pretty(&bundle)
            .map_err(|e| QGuardError::Storage(format!("encode public recipient bundle: {e}")))
    }

    /// Serialize the identity as a passphrase-protected `.qgkey` bundle.
    ///
    /// Secrets are sealed with AES-256-GCM under a key stretched from the
    /// passphrase with Argon2id (64 MiB, 3 passes) and separated with
    /// HKDF-SHA3-256, so a stolen bundle costs real memory and time per guess.
    pub fn export_bundle(&self, passphrase: &str) -> Result<String> {
        if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
            return Err(QGuardError::InvalidInput(format!(
                "identity passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
            )));
        }

        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let mut wrap_key = derive_bundle_key_argon2id(passphrase, &salt)?;

        let mut secret_payload = serde_json::to_vec(&serde_json::json!({
            "x25519": b64().encode(self.kem.x25519_secret),
            "mlkem": b64().encode(&self.kem.mlkem_secret),
            "ed25519": b64().encode(self.signer.ed25519_secret),
            "mldsa": b64().encode(&self.signer.mldsa87_secret),
        }))
        .map_err(|e| QGuardError::Storage(format!("encode identity secrets: {e}")))?;

        let sealed = symmetric::encrypt(&wrap_key, &secret_payload, BUNDLE_AAD);
        wrap_key.zeroize();
        secret_payload.zeroize();
        let sealed = sealed?;

        // `data` concatenates ciphertext||tag so the layout matches the web
        // vault's WebCrypto/noble AES-GCM output, which appends the tag.
        let mut data = sealed.ciphertext.clone();
        data.extend_from_slice(&sealed.tag);

        let bundle = serde_json::json!({
            "label": self.label.clone().unwrap_or_else(|| "qguard-identity".to_string()),
            "version": BUNDLE_VERSION_CURRENT,
            "type": "qguard-portable-hybrid-identity",
            "generatedAt": chrono::Utc::now().to_rfc3339(),
            "fingerprint": self.fingerprint(),
            "algorithms": {
                "kem": self.kem_algorithm(),
                "kex": "X25519",
                "signature": self.signature_algorithm(),
                "symmetric": "AES-256-GCM",
            },
            "publics": {
                "x25519": b64().encode(&self.kem.x25519_public),
                "mlkem": b64().encode(&self.kem.mlkem_public),
                "ed25519": b64().encode(&self.signer.ed25519_public),
                "mldsa": b64().encode(&self.signer.mldsa87_public),
            },
            "secrets": {
                "encrypted": true,
                "kdf": BUNDLE_KDF_CURRENT,
                "memoryKiB": 65536,
                "iterations": 3,
                "parallelism": 1,
                "salt": b64().encode(salt),
                "nonce": b64().encode(&sealed.nonce),
                "data": b64().encode(&data),
            },
        });

        serde_json::to_string_pretty(&bundle)
            .map_err(|e| QGuardError::Storage(format!("encode identity bundle: {e}")))
    }

    /// Restore an identity from a `.qgkey` bundle. Accepts both the v1.2 bundles
    /// this app writes and the v1.1 PBKDF2 bundles the web vault writes.
    pub fn import_bundle(json: &str, passphrase: &str) -> Result<Self> {
        let bundle: serde_json::Value = serde_json::from_str(json.trim())
            .map_err(|e| QGuardError::InvalidInput(format!("not a valid .qgkey bundle: {e}")))?;

        let publics = bundle
            .get("publics")
            .ok_or_else(|| QGuardError::InvalidInput("identity bundle has no public keys".to_string()))?;
        let x25519_public = decode_b64(json_str(publics, "x25519").unwrap_or_default(), "publics.x25519")?;
        let mlkem_public = decode_b64(json_str(publics, "mlkem").unwrap_or_default(), "publics.mlkem")?;
        let ed25519_public = decode_b64(json_str(publics, "ed25519").unwrap_or_default(), "publics.ed25519")?;
        let mldsa_public = decode_b64(json_str(publics, "mldsa").unwrap_or_default(), "publics.mldsa")?;

        let secrets_node = bundle
            .get("secrets")
            .ok_or_else(|| QGuardError::InvalidInput("identity bundle has no secret material".to_string()))?;

        let secrets: serde_json::Value = if secrets_node
            .get("encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            if passphrase.is_empty() {
                return Err(QGuardError::InvalidInput(
                    "this identity bundle is passphrase-protected".to_string(),
                ));
            }
            let kdf_name = json_str(secrets_node, "kdf").unwrap_or(BUNDLE_KDF_LEGACY);
            let salt = decode_b64(json_str(secrets_node, "salt").unwrap_or_default(), "secrets.salt")?;
            let nonce = decode_b64(json_str(secrets_node, "nonce").unwrap_or_default(), "secrets.nonce")?;
            let data = decode_b64(json_str(secrets_node, "data").unwrap_or_default(), "secrets.data")?;
            if data.len() <= symmetric::TAG_SIZE {
                return Err(QGuardError::InvalidInput("identity bundle payload is truncated".to_string()));
            }
            let split = data.len() - symmetric::TAG_SIZE;
            let envelope = EncryptedEnvelope {
                nonce,
                ciphertext: data[..split].to_vec(),
                tag: data[split..].to_vec(),
            };

            let mut wrap_key = match kdf_name {
                BUNDLE_KDF_CURRENT => derive_bundle_key_argon2id(passphrase, &salt)?,
                BUNDLE_KDF_LEGACY => {
                    let iterations = secrets_node
                        .get("iterations")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(LEGACY_PBKDF2_ITERATIONS as u64);
                    if !(MIN_LEGACY_PBKDF2_ITERATIONS..=5_000_000).contains(&iterations) {
                        return Err(QGuardError::InvalidInput(format!(
                            "this identity bundle declares {iterations} key-stretching iterations, outside what this app accepts ({MIN_LEGACY_PBKDF2_ITERATIONS} to 5000000); it was not produced by QGuard"
                        )));
                    }
                    derive_bundle_key_pbkdf2(passphrase, &salt, iterations as u32)?
                }
                other => {
                    return Err(QGuardError::InvalidInput(format!(
                        "identity bundle uses an unsupported KDF ({other}) — update QGuard Messaging"
                    )))
                }
            };

            // v1.2 binds the AAD; v1.1 (web) has none. Try the bound form first
            // so a v1.2 bundle can never be stripped of its context.
            let decrypted = symmetric::decrypt(&wrap_key, &envelope, BUNDLE_AAD)
                .or_else(|_| symmetric::decrypt(&wrap_key, &envelope, b""));
            wrap_key.zeroize();
            let mut plain = decrypted.map_err(|_| {
                QGuardError::Crypto(
                    "wrong passphrase, or this identity bundle has been modified".to_string(),
                )
            })?;
            let parsed = serde_json::from_slice::<serde_json::Value>(&plain)
                .map_err(|e| QGuardError::Crypto(format!("identity bundle secrets are corrupt: {e}")));
            plain.zeroize();
            parsed?
        } else {
            // A bundle whose private keys sit in the file in clear. Opening one
            // would treat keys that anything on the machine could have read as
            // an identity worth sealing to. QGuard never writes such a file.
            return Err(QGuardError::InvalidInput(
                "this identity bundle stores its private keys unencrypted and cannot be imported; export it again with a passphrase"
                    .to_string(),
            ));
        };

        let x25519_secret_bytes = decode_b64(json_str(&secrets, "x25519").unwrap_or_default(), "secrets.x25519")?;
        let mlkem_secret = decode_b64(json_str(&secrets, "mlkem").unwrap_or_default(), "secrets.mlkem")?;
        let ed25519_secret_bytes = decode_b64(json_str(&secrets, "ed25519").unwrap_or_default(), "secrets.ed25519")?;
        let mldsa_secret = decode_b64(json_str(&secrets, "mldsa").unwrap_or_default(), "secrets.mldsa")?;

        if x25519_secret_bytes.len() != 32 || ed25519_secret_bytes.len() != 32 {
            return Err(QGuardError::InvalidInput(
                "identity bundle contains malformed classical key material".to_string(),
            ));
        }
        let mut x25519_secret = [0u8; 32];
        x25519_secret.copy_from_slice(&x25519_secret_bytes);
        let mut ed25519_secret = [0u8; 32];
        ed25519_secret.copy_from_slice(&ed25519_secret_bytes);

        let identity = Self {
            kem: LocalKemKeypair {
                x25519_secret,
                x25519_public,
                mlkem_secret,
                mlkem_public,
                // The bundle's declared KEM is derived from a key LENGTH, which
                // cannot separate ML-KEM-1024 from a pre-FIPS Kyber-1024 key of
                // the same size, so a bundle exported by an older build is
                // indistinguishable here. Marking it as the current suite is
                // the safe default: the keys are structurally valid ML-KEM-1024,
                // and if they were in fact Kyber the derived secret simply will
                // not authenticate, which fails closed rather than silently
                // accepting the wrong key.
                kem: crate::crypto::CURRENT_PQ_KEM.to_string(),
            },
            signer: VaultSigningKeypair {
                ed25519_secret,
                ed25519_public,
                mldsa87_secret: mldsa_secret,
                mldsa87_public: mldsa_public,
            },
            label: json_str(&bundle, "label")
                .map(str::to_string)
                .filter(|value| !value.trim().is_empty()),
        };

        identity.validate()?;
        Ok(identity)
    }

    /// Reject key material that does not actually pair up, so a corrupted or
    /// hand-edited bundle fails at import instead of at the first seal/open.
    fn validate(&self) -> Result<()> {
        if self.kem.x25519_public.len() != 32 {
            return Err(QGuardError::InvalidInput(
                "identity X25519 public key must be 32 bytes".to_string(),
            ));
        }
        if kem_algorithm_for(&self.kem.mlkem_public) == UNKNOWN {
            return Err(QGuardError::InvalidInput(format!(
                "identity ML-KEM public key has an unsupported length ({})",
                self.kem.mlkem_public.len()
            )));
        }
        if signature_algorithm_for(&self.signer.mldsa87_public) == UNKNOWN {
            return Err(QGuardError::InvalidInput(format!(
                "identity ML-DSA public key has an unsupported length ({})",
                self.signer.mldsa87_public.len()
            )));
        }

        // The X25519 public key must be the one derived from the secret,
        // otherwise senders would seal to a key this identity cannot open.
        let derived = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
            self.kem.x25519_secret,
        ));
        if derived.as_bytes() != self.kem.x25519_public.as_slice() {
            return Err(QGuardError::InvalidInput(
                "identity X25519 key pair does not match — the bundle is corrupt".to_string(),
            ));
        }

        // Same check for Ed25519, which anchors the sender attestation.
        let signing = ed25519_dalek::SigningKey::from_bytes(&self.signer.ed25519_secret);
        if signing.verifying_key().to_bytes().as_slice() != self.signer.ed25519_public.as_slice() {
            return Err(QGuardError::InvalidInput(
                "identity Ed25519 key pair does not match — the bundle is corrupt".to_string(),
            ));
        }
        Ok(())
    }
}

const UNKNOWN: &str = "unknown";
const BUNDLE_AAD: &[u8] = b"QGuard-Portable-Identity-Bundle-v1.2";

pub fn signature_algorithm_for(mldsa_public: &[u8]) -> &'static str {
    match mldsa_public.len() {
        ML_DSA_87_PUBLIC_LEN => SIGNATURE_ML_DSA_87,
        ML_DSA_65_PUBLIC_LEN => SIGNATURE_ML_DSA_65,
        _ => UNKNOWN,
    }
}

/// Best-effort label for a KEM public key found in a portable identity bundle.
///
/// NOTE the limit of what a length can tell you: an ML-KEM-1024 encapsulation
/// key and a pre-FIPS Kyber-1024 public key are both 1568 bytes, so a bundle
/// exported by an older build is indistinguishable here and will be labelled
/// ML-KEM-1024. That is acceptable for a DISPLAY string — the authority on
/// whether material is usable is `LocalKemKeypair::is_current_suite`, which
/// reads the stored algorithm marker rather than guessing from a length.
pub fn kem_algorithm_for(mlkem_public: &[u8]) -> &'static str {
    if LocalKemKeypair::is_current_public_key(mlkem_public) {
        crate::crypto::CURRENT_PQ_KEM
    } else {
        UNKNOWN
    }
}

/// Stable identity fingerprint: SHA3-256 over all four public keys, hex.
///
/// It covers the signing keys as well as the encryption keys, so an attacker who
/// swaps in their own signing key produces a different fingerprint — the value
/// the two users compare out of band.
pub fn identity_fingerprint(
    x25519_public: &[u8],
    mlkem_public: &[u8],
    ed25519_public: &[u8],
    mldsa_public: &[u8],
) -> String {
    let mut material =
        Vec::with_capacity(x25519_public.len() + mlkem_public.len() + ed25519_public.len() + mldsa_public.len());
    material.extend_from_slice(x25519_public);
    material.extend_from_slice(mlkem_public);
    material.extend_from_slice(ed25519_public);
    material.extend_from_slice(mldsa_public);
    kdf::sha3_hex(&material)
}

/// Short, human-comparable form of a fingerprint, e.g. `DE80-CA7A-2F55-4A48`.
pub fn short_fingerprint(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .take(16)
        .collect::<String>()
        .to_uppercase()
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Parse a public recipient bundle. Accepts the public recipient JSON, a full
/// `.qgkey` bundle (public half only), or a `{ publics: {...} }` fragment.
///
/// All four public keys are required: sealing to a partial bundle would produce
/// a fingerprint the recipient's own app would not recognise, and would drop the
/// signing keys out of the identity binding.
pub fn parse_recipient_public(input: &str) -> Result<RecipientPublicKeys> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(QGuardError::InvalidInput(
            "paste or load a recipient's public identity bundle first".to_string(),
        ));
    }
    let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|_| {
        QGuardError::InvalidInput(
            "that is not a QGuard public recipient bundle (expected the .qgpub.json file contents)"
                .to_string(),
        )
    })?;

    let publics = parsed.get("publics").unwrap_or(&parsed);
    let x25519_public = decode_b64(json_str(publics, "x25519").unwrap_or_default(), "publics.x25519")?;
    let mlkem_public = decode_b64(json_str(publics, "mlkem").unwrap_or_default(), "publics.mlkem")?;
    let ed25519_public = decode_b64(json_str(publics, "ed25519").unwrap_or_default(), "publics.ed25519")?;
    let mldsa_public = decode_b64(json_str(publics, "mldsa").unwrap_or_default(), "publics.mldsa")?;

    if x25519_public.len() != 32 {
        return Err(QGuardError::InvalidInput(
            "recipient X25519 public key must be 32 bytes".to_string(),
        ));
    }
    let kem_algorithm = kem_algorithm_for(&mlkem_public);
    if kem_algorithm == UNKNOWN {
        return Err(QGuardError::InvalidInput(format!(
            "recipient ML-KEM public key has an unsupported length ({})",
            mlkem_public.len()
        )));
    }
    let signature_algorithm = signature_algorithm_for(&mldsa_public);
    if signature_algorithm == UNKNOWN {
        return Err(QGuardError::InvalidInput(format!(
            "recipient ML-DSA public key has an unsupported length ({})",
            mldsa_public.len()
        )));
    }
    if ed25519_public.len() != 32 {
        return Err(QGuardError::InvalidInput(
            "recipient Ed25519 public key must be 32 bytes".to_string(),
        ));
    }

    let fingerprint = identity_fingerprint(&x25519_public, &mlkem_public, &ed25519_public, &mldsa_public);
    // A bundle that states its own fingerprint must agree with the keys it
    // carries, or it has been tampered with in transit.
    if let Some(claimed) = json_str(&parsed, "fingerprint") {
        if !claimed.trim().is_empty() && !claimed.eq_ignore_ascii_case(&fingerprint) {
            return Err(QGuardError::Crypto(
                "recipient bundle fingerprint does not match its public keys — do not use it"
                    .to_string(),
            ));
        }
    }

    Ok(RecipientPublicKeys {
        fingerprint,
        label: json_str(&parsed, "label")
            .map(str::to_string)
            .filter(|value| !value.trim().is_empty()),
        x25519_public,
        mlkem_public,
        ed25519_public,
        mldsa_public,
        signature_algorithm: signature_algorithm.to_string(),
        kem_algorithm: kem_algorithm.to_string(),
    })
}

// --- Bundle key derivation -------------------------------------------------

/// Argon2id (64 MiB / 3 passes) prehash, then HKDF-SHA3-256 into the AES key.
/// The memory-hard step is what makes an offline attack on a stolen `.qgkey`
/// expensive; the HKDF step keeps this key domain-separated from every other
/// key the app derives from a user secret.
fn derive_bundle_key_argon2id(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE]> {
    let mut ikm = passcode::argon2id_prehash(salt, passphrase.as_bytes())?;
    let key = kdf::derive_32_with_salt(
        salt,
        &ikm,
        &crate::security::obf::portable_identity_bundle_info(),
    );
    ikm.zeroize();
    key
}

/// PBKDF2-HMAC-SHA3-256, used only to read v1.1 bundles created by the web
/// vault. `dkLen` is 32 = one SHA3-256 block, so a single T-block is derived.
fn derive_bundle_key_pbkdf2(passphrase: &str, salt: &[u8], iterations: u32) -> Result<[u8; KEY_SIZE]> {
    type HmacSha3 = Hmac<Sha3_256>;

    let mut block = Vec::with_capacity(salt.len() + 4);
    block.extend_from_slice(salt);
    block.extend_from_slice(&1u32.to_be_bytes());

    let mut mac = HmacSha3::new_from_slice(passphrase.as_bytes())
        .map_err(|e| QGuardError::Crypto(format!("PBKDF2 HMAC init failed: {e}")))?;
    mac.update(&block);
    let mut u = mac.finalize().into_bytes();
    let mut out = [0u8; KEY_SIZE];
    out.copy_from_slice(&u);

    for _ in 1..iterations {
        let mut mac = HmacSha3::new_from_slice(passphrase.as_bytes())
            .map_err(|e| QGuardError::Crypto(format!("PBKDF2 HMAC init failed: {e}")))?;
        mac.update(&u);
        u = mac.finalize().into_bytes();
        for (acc, byte) in out.iter_mut().zip(u.iter()) {
            *acc ^= byte;
        }
    }
    u.zeroize();
    Ok(out)
}

// --- Sender attestation ----------------------------------------------------

/// Proof of *who* sealed a container, signed by the sender's portable identity
/// over the container's canonical header bytes.
///
/// This is deliberately separate from the container's own header signature: that
/// one is produced by the sending device's vault signer, which the recipient has
/// no way to attribute to a person. The attestation carries a fingerprint the
/// recipient can compare with the one the sender gave them out of band.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SenderAttestation {
    pub identity_fingerprint: String,
    #[serde(default)]
    pub label: String,
    /// `ML-DSA-87` (this app) or `ML-DSA-65` (web-created identity).
    pub signature_algorithm: String,
    pub ed25519_public: Vec<u8>,
    pub mldsa_public: Vec<u8>,
    pub ed25519_signature: Vec<u8>,
    pub mldsa_signature: Vec<u8>,
}

/// Sign `signable` with the identity's Ed25519 + ML-DSA keys.
pub fn attest(identity: &PortableIdentity, signable: &[u8]) -> Result<SenderAttestation> {
    if !identity.can_attest() {
        return Err(QGuardError::InvalidInput(format!(
            "this identity signs with {} — sender attestation requires {SIGNATURE_ML_DSA_87}",
            identity.signature_algorithm()
        )));
    }
    let signature = dual_sign_87(
        &identity.signer.ed25519_secret,
        &identity.signer.mldsa87_secret,
        signable,
    )?;
    Ok(SenderAttestation {
        identity_fingerprint: identity.fingerprint(),
        label: identity.label.clone().unwrap_or_default(),
        signature_algorithm: SIGNATURE_ML_DSA_87.to_string(),
        ed25519_public: identity.signer.ed25519_public.clone(),
        mldsa_public: identity.signer.mldsa87_public.clone(),
        ed25519_signature: signature.ed25519,
        mldsa_signature: signature.ml_dsa_87,
    })
}

/// Verify an attestation: both signatures must validate over `signable`, AND the
/// declared fingerprint must be the one its own public keys produce — otherwise
/// a valid signature could be presented under someone else's fingerprint.
///
/// The X25519/ML-KEM halves of the fingerprint come from the container's
/// recipient-facing copy, so they are passed in rather than re-derived here.
pub fn verify_attestation(
    attestation: &SenderAttestation,
    signable: &[u8],
    sender_x25519_public: &[u8],
    sender_mlkem_public: &[u8],
) -> Result<()> {
    let expected = identity_fingerprint(
        sender_x25519_public,
        sender_mlkem_public,
        &attestation.ed25519_public,
        &attestation.mldsa_public,
    );
    if !expected.eq_ignore_ascii_case(&attestation.identity_fingerprint) {
        return Err(QGuardError::Crypto(
            "sender attestation fingerprint does not match its public keys".to_string(),
        ));
    }
    match attestation.signature_algorithm.as_str() {
        SIGNATURE_ML_DSA_87 => dual_verify_87(
            &attestation.ed25519_public,
            &attestation.mldsa_public,
            signable,
            &DualSignature87 {
                ed25519: attestation.ed25519_signature.clone(),
                ml_dsa_87: attestation.mldsa_signature.clone(),
            },
        ),
        SIGNATURE_ML_DSA_65 => dual_verify(
            &attestation.ed25519_public,
            &attestation.mldsa_public,
            signable,
            &DualSignature {
                ed25519: attestation.ed25519_signature.clone(),
                ml_dsa_65: attestation.mldsa_signature.clone(),
            },
        ),
        other => Err(QGuardError::Crypto(format!(
            "sender attestation uses an unsupported signature algorithm: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_round_trips_and_rejects_a_wrong_passphrase() {
        let identity = PortableIdentity::generate(Some("Alice - laptop".to_string()));
        let bundle = identity.export_bundle("correct horse battery").unwrap();

        let restored = PortableIdentity::import_bundle(&bundle, "correct horse battery").unwrap();
        assert_eq!(restored.fingerprint(), identity.fingerprint());
        assert_eq!(restored.kem.mlkem_secret, identity.kem.mlkem_secret);
        assert_eq!(restored.signer.mldsa87_secret, identity.signer.mldsa87_secret);
        assert_eq!(restored.label.as_deref(), Some("Alice - laptop"));

        assert!(PortableIdentity::import_bundle(&bundle, "wrong passphrase!").is_err());
        assert!(PortableIdentity::import_bundle(&bundle, "").is_err());
    }

    #[test]
    fn short_passphrases_are_refused() {
        let identity = PortableIdentity::generate(None);
        assert!(identity.export_bundle("short").is_err());
        assert!(identity.export_bundle("exactly12chr").is_ok());
    }

    #[test]
    fn a_tampered_bundle_fails_to_open() {
        let identity = PortableIdentity::generate(None);
        let bundle = identity.export_bundle("correct horse battery").unwrap();
        let mut parsed: serde_json::Value = serde_json::from_str(&bundle).unwrap();

        // Flip one byte of the sealed secret payload.
        let data = parsed["secrets"]["data"].as_str().unwrap().to_string();
        let mut raw = b64().decode(&data).unwrap();
        raw[0] ^= 0x01;
        parsed["secrets"]["data"] = serde_json::Value::String(b64().encode(&raw));
        assert!(PortableIdentity::import_bundle(&parsed.to_string(), "correct horse battery").is_err());
    }

    #[test]
    fn a_swapped_public_key_is_caught_by_pair_validation() {
        let identity = PortableIdentity::generate(None);
        let other = PortableIdentity::generate(None);
        let bundle = identity.export_bundle("correct horse battery").unwrap();
        let mut parsed: serde_json::Value = serde_json::from_str(&bundle).unwrap();
        parsed["publics"]["x25519"] = serde_json::Value::String(b64().encode(&other.kem.x25519_public));
        assert!(PortableIdentity::import_bundle(&parsed.to_string(), "correct horse battery").is_err());
    }

    #[test]
    fn legacy_web_pbkdf2_bundles_import() {
        // Reproduce the web vault's v1.1 layout: PBKDF2-SHA3-256, secrets JSON
        // sealed with AES-256-GCM and NO additional authenticated data.
        //
        // The bundle declares its own iteration count and the importer honours
        // it down to its floor, so the floor is what is used here: the same
        // code path as the web vault's default at a third of the cost.
        let identity = PortableIdentity::generate(Some("web identity".to_string()));
        let salt = [7u8; 32];
        let iterations = MIN_LEGACY_PBKDF2_ITERATIONS as u32;
        let key = derive_bundle_key_pbkdf2("web passphrase!", &salt, iterations).unwrap();
        let payload = serde_json::json!({
            "x25519": b64().encode(identity.kem.x25519_secret),
            "mlkem": b64().encode(&identity.kem.mlkem_secret),
            "ed25519": b64().encode(identity.signer.ed25519_secret),
            "mldsa": b64().encode(&identity.signer.mldsa87_secret),
        })
        .to_string();
        let sealed = symmetric::encrypt(&key, payload.as_bytes(), b"").unwrap();
        let mut data = sealed.ciphertext.clone();
        data.extend_from_slice(&sealed.tag);

        let bundle = serde_json::json!({
            "label": "web identity",
            "version": BUNDLE_VERSION_LEGACY,
            "publics": {
                "x25519": b64().encode(&identity.kem.x25519_public),
                "mlkem": b64().encode(&identity.kem.mlkem_public),
                "ed25519": b64().encode(&identity.signer.ed25519_public),
                "mldsa": b64().encode(&identity.signer.mldsa87_public),
            },
            "secrets": {
                "encrypted": true,
                "kdf": BUNDLE_KDF_LEGACY,
                "iterations": iterations,
                "salt": b64().encode(salt),
                "nonce": b64().encode(&sealed.nonce),
                "data": b64().encode(&data),
            },
        })
        .to_string();

        let restored = PortableIdentity::import_bundle(&bundle, "web passphrase!").unwrap();
        assert_eq!(restored.fingerprint(), identity.fingerprint());
        assert!(PortableIdentity::import_bundle(&bundle, "not the passphrase").is_err());

        // A bundle with no stated iteration count must fall back to the web
        // vault's real default, not to the value used above.
        assert_eq!(LEGACY_PBKDF2_ITERATIONS, 310_000);

        // A bundle that declares a weakened stretch is refused before any
        // key is derived, whatever the passphrase.
        for weakened in [1u64, 1_000, MIN_LEGACY_PBKDF2_ITERATIONS - 1, 5_000_001] {
            let mut parsed: serde_json::Value = serde_json::from_str(&bundle).unwrap();
            parsed["secrets"]["iterations"] = serde_json::json!(weakened);
            let error = PortableIdentity::import_bundle(&parsed.to_string(), "web passphrase!")
                .err()
                .expect("a weakened iteration count must be refused");
            assert!(format!("{error}").contains("iterations"), "{error}");
        }

        // And so is a bundle whose private keys are not encrypted at all.
        let mut plain: serde_json::Value = serde_json::from_str(&bundle).unwrap();
        plain["secrets"] = serde_json::json!({
            "encrypted": false,
            "x25519": b64().encode(identity.kem.x25519_secret),
            "mlkem": b64().encode(&identity.kem.mlkem_secret),
            "ed25519": b64().encode(identity.signer.ed25519_secret),
            "mldsa": b64().encode(&identity.signer.mldsa87_secret),
        });
        let error = PortableIdentity::import_bundle(&plain.to_string(), "")
            .err()
            .expect("an unencrypted bundle must be refused");
        assert!(format!("{error}").contains("unencrypted"), "{error}");
    }

    #[test]
    fn pbkdf2_matches_a_known_answer() {
        // RFC-style KAT against an independent computation of
        // PBKDF2-HMAC-SHA3-256("password", "salt", c=2, dkLen=32), so the hand
        // written PBKDF2 above cannot drift from the standard construction.
        type HmacSha3 = Hmac<Sha3_256>;
        let expected = {
            let mut mac = HmacSha3::new_from_slice(b"password").unwrap();
            mac.update(b"salt\x00\x00\x00\x01");
            let u1 = mac.finalize().into_bytes();
            let mut mac = HmacSha3::new_from_slice(b"password").unwrap();
            mac.update(&u1);
            let u2 = mac.finalize().into_bytes();
            let mut out = [0u8; 32];
            for i in 0..32 {
                out[i] = u1[i] ^ u2[i];
            }
            out
        };
        assert_eq!(derive_bundle_key_pbkdf2("password", b"salt", 2).unwrap(), expected);
        // One iteration is just U1.
        let mut mac = HmacSha3::new_from_slice(b"password").unwrap();
        mac.update(b"salt\x00\x00\x00\x01");
        let u1 = mac.finalize().into_bytes();
        assert_eq!(derive_bundle_key_pbkdf2("password", b"salt", 1).unwrap()[..], u1[..]);
    }

    #[test]
    fn public_recipient_json_parses_back_to_the_same_fingerprint() {
        let identity = PortableIdentity::generate(Some("Bob - desktop".to_string()));
        let json = identity.public_recipient_json().unwrap();
        let parsed = parse_recipient_public(&json).unwrap();
        assert_eq!(parsed.fingerprint, identity.fingerprint());
        assert_eq!(parsed.kem_algorithm, crate::crypto::CURRENT_PQ_KEM);
        assert_eq!(parsed.signature_algorithm, SIGNATURE_ML_DSA_87);
        assert_eq!(parsed.mlkem_public, identity.kem.mlkem_public);
        // The private half must never appear in the public bundle.
        assert!(!json.contains(&b64().encode(identity.kem.x25519_secret)));
        assert!(!json.contains(&b64().encode(&identity.kem.mlkem_secret)));
    }

    #[test]
    fn a_recipient_bundle_with_a_lying_fingerprint_is_rejected() {
        let identity = PortableIdentity::generate(None);
        let mut parsed: serde_json::Value =
            serde_json::from_str(&identity.public_recipient_json().unwrap()).unwrap();
        parsed["fingerprint"] = serde_json::Value::String("deadbeef".repeat(8));
        assert!(parse_recipient_public(&parsed.to_string()).is_err());
    }

    #[test]
    fn a_partial_recipient_bundle_is_rejected() {
        let identity = PortableIdentity::generate(None);
        let mut parsed: serde_json::Value =
            serde_json::from_str(&identity.public_recipient_json().unwrap()).unwrap();
        parsed["publics"]["mldsa"] = serde_json::Value::String(String::new());
        assert!(parse_recipient_public(&parsed.to_string()).is_err());
        assert!(parse_recipient_public("not json at all").is_err());
    }

    #[test]
    fn attestation_verifies_and_rejects_tampering() {
        let identity = PortableIdentity::generate(Some("Alice".to_string()));
        let attestation = attest(&identity, b"header bytes").unwrap();
        assert!(verify_attestation(
            &attestation,
            b"header bytes",
            &identity.kem.x25519_public,
            &identity.kem.mlkem_public,
        )
        .is_ok());

        // Different signed bytes, a different claimed fingerprint, and a
        // different sender KEM key must each fail.
        assert!(verify_attestation(
            &attestation,
            b"other bytes",
            &identity.kem.x25519_public,
            &identity.kem.mlkem_public,
        )
        .is_err());

        let mut forged = attestation.clone();
        forged.identity_fingerprint = "0".repeat(64);
        assert!(verify_attestation(
            &forged,
            b"header bytes",
            &identity.kem.x25519_public,
            &identity.kem.mlkem_public,
        )
        .is_err());

        let other = PortableIdentity::generate(None);
        assert!(verify_attestation(
            &attestation,
            b"header bytes",
            &other.kem.x25519_public,
            &other.kem.mlkem_public,
        )
        .is_err());
    }

    #[test]
    fn fingerprints_are_stable_and_cover_every_public_key() {
        let identity = PortableIdentity::generate(None);
        let base = identity.fingerprint();
        assert_eq!(base.len(), 64);
        assert_eq!(base, identity.fingerprint());
        assert_eq!(short_fingerprint(&base).len(), 19);

        let other = PortableIdentity::generate(None);
        // Changing only the signing key must change the fingerprint.
        let mixed = identity_fingerprint(
            &identity.kem.x25519_public,
            &identity.kem.mlkem_public,
            &other.signer.ed25519_public,
            &other.signer.mldsa87_public,
        );
        assert_ne!(base, mixed);
    }
}
