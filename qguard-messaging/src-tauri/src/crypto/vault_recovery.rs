//! Quantum-safe vault recovery key.
//!
//! A 256-bit recovery root is generated once and shown to the user as a grouped,
//! checksummed Crockford-Base32 recovery key. From the root we derive — one-way,
//! via HKDF-SHA3-256 — an AES-256-GCM wrapping key that every vault file key is
//! *also* sealed under (in addition to the device key wrap).
//!
//! Recovery flow: on a brand-new device the user installs QGuard, signs in, and
//! enters their recovery key. The key re-derives the same wrapping key locally,
//! which unwraps the file key and decrypts the `.qvault` data straight from the
//! external drive — no access to the lost device required.
//!
//! Security properties:
//! * Quantum-safe: AES-256-GCM + HKDF-SHA3-256 are post-quantum-strength
//!   symmetric primitives (no factoring/discrete-log to break with Shor's).
//! * Irreversible: the wrapping key and the verifier are HKDF outputs in
//!   *distinct* contexts; neither, nor any ciphertext, reveals the root.
//! * Zero-knowledge: the root never leaves the user and is never sent to or
//!   stored on the server.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::hybrid_kex::{decapsulate, encapsulate_with, KemCombiner, LocalKemKeypair};
use crate::crypto::kdf;
use crate::crypto::symmetric::{self, KEY_SIZE};
use crate::crypto::{EncryptedEnvelope, HybridCiphertext};
use crate::error::{QGuardError, Result};

/// Recovery modes (see `recovery_keys` spec):
/// * Personal   — recovery key only (HKDF-SHA3-256 → AES-256-GCM).
/// * Enterprise — ML-KEM-1024 recipient wrapping only.
/// * Hybrid     — both the recovery key AND the ML-KEM-1024 secret are required.
pub const RECOVERY_MODE_PERSONAL: &str = "personal";
pub const RECOVERY_MODE_ENTERPRISE: &str = "enterprise";
pub const RECOVERY_MODE_HYBRID: &str = "hybrid";

pub const RECOVERY_ROOT_SIZE: usize = 32;
/// Crockford Base32 alphabet (excludes I, L, O, U to avoid transcription errors).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const BODY_CHARS: usize = 52; // ceil(256 bits / 5)
const CHECKSUM_CHARS: usize = 4;
const KEY_CHARS: usize = BODY_CHARS + CHECKSUM_CHARS;

pub fn generate_recovery_root() -> [u8; RECOVERY_ROOT_SIZE] {
    crate::crypto::provider::random_array::<RECOVERY_ROOT_SIZE>()
}

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(CROCKFORD[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn base32_decode(s: &str) -> Result<Vec<u8>> {
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for c in s.chars() {
        let value = CROCKFORD
            .iter()
            .position(|&x| x as char == c)
            .ok_or_else(|| QGuardError::InvalidInput(format!("invalid recovery key character: {c}")))?
            as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

fn checksum(root: &[u8; RECOVERY_ROOT_SIZE]) -> String {
    base32_encode(&kdf::sha3_256(root))[..CHECKSUM_CHARS].to_string()
}

/// Normalize user input: uppercase, drop separators, map the ambiguous Crockford
/// aliases (O→0, I/L→1) to their canonical digits.
fn normalize_input(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .map(|c| match c {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect()
}

/// Encode a recovery root as a grouped, checksummed recovery key, e.g.
/// `A1B2-C3D4-…-CCCC` (14 groups of 4).
pub fn encode_recovery_key(root: &[u8; RECOVERY_ROOT_SIZE]) -> String {
    let combined = format!("{}{}", base32_encode(root), checksum(root));
    combined
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Decode and validate a user-entered recovery key back to the 256-bit root.
pub fn decode_recovery_key(input: &str) -> Result<[u8; RECOVERY_ROOT_SIZE]> {
    let normalized = normalize_input(input);
    if normalized.len() != KEY_CHARS {
        return Err(QGuardError::InvalidInput(
            "Recovery key is the wrong length. Enter all 56 characters.".to_string(),
        ));
    }
    let (body, supplied_checksum) = normalized.split_at(BODY_CHARS);
    let decoded = base32_decode(body)?;
    if decoded.len() < RECOVERY_ROOT_SIZE {
        return Err(QGuardError::InvalidInput("Recovery key is malformed.".to_string()));
    }
    let mut root = [0u8; RECOVERY_ROOT_SIZE];
    root.copy_from_slice(&decoded[..RECOVERY_ROOT_SIZE]);
    if checksum(&root) != supplied_checksum {
        return Err(QGuardError::InvalidInput(
            "Recovery key checksum failed — please check for typos.".to_string(),
        ));
    }
    Ok(root)
}

/// AES-256-GCM wrapping key derived one-way from the recovery root.
pub fn derive_wrap_key(root: &[u8; RECOVERY_ROOT_SIZE]) -> Result<[u8; KEY_SIZE]> {
    kdf::derive_32(root, &crate::security::obf::vault_recovery_wrap_info())
}

/// Public verifier (a hash of an independent HKDF output) used to confirm a
/// re-entered recovery key matches the configured one, without exposing the
/// wrapping key.
pub fn derive_verifier(root: &[u8; RECOVERY_ROOT_SIZE]) -> Result<String> {
    let mut material = kdf::derive_32(root, &crate::security::obf::vault_recovery_verifier_info())?;
    let verifier = kdf::sha3_hex(&material);
    material.zeroize();
    Ok(verifier)
}

fn wrap_aad(file_id: &str, owner_user_id: &str) -> Vec<u8> {
    format!("QGuard-Vault-Recovery-FileKey-v1:{file_id}:{owner_user_id}").into_bytes()
}

/// AAD for the recovery wrap of a v5 (PIN-bound) container.
///
/// A different label from [`wrap_aad`] on purpose. In v1–v4 containers that
/// envelope holds the per-file key (v1/v2) or the Vault Master Key (v3/v4); in
/// v5 it holds the per-file key and nothing above it. Separating the labels
/// means a wrap can never be lifted between the two meanings by relabelling a
/// header's version — it simply fails to authenticate.
fn fek_wrap_aad_v5(file_id: &str, owner_user_id: &str) -> Vec<u8> {
    format!("QGuard-Vault-Recovery-FEK-v5:{file_id}:{owner_user_id}").into_bytes()
}

fn unwrap_32(wrap_key: &[u8; KEY_SIZE], envelope: &EncryptedEnvelope, aad: &[u8]) -> Result<[u8; KEY_SIZE]> {
    let mut bytes = symmetric::decrypt(wrap_key, envelope, aad)?;
    if bytes.len() != KEY_SIZE {
        bytes.zeroize();
        return Err(QGuardError::Crypto("recovery-unwrapped key is invalid".to_string()));
    }
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(key)
}

/// Seal a key under the recovery wrapping key (v1–v4 container layout).
pub fn wrap_file_key(
    wrap_key: &[u8; KEY_SIZE],
    file_key: &[u8; KEY_SIZE],
    file_id: &str,
    owner_user_id: &str,
) -> Result<EncryptedEnvelope> {
    symmetric::encrypt(wrap_key, file_key, &wrap_aad(file_id, owner_user_id))
}

/// Recover a key from its recovery-wrapped envelope (v1–v4 container layout).
pub fn unwrap_file_key(
    wrap_key: &[u8; KEY_SIZE],
    envelope: &EncryptedEnvelope,
    file_id: &str,
    owner_user_id: &str,
) -> Result<[u8; KEY_SIZE]> {
    unwrap_32(wrap_key, envelope, &wrap_aad(file_id, owner_user_id))
}

/// Seal the per-file key of a v5 container under the recovery wrapping key.
pub fn wrap_fek_v5(
    wrap_key: &[u8; KEY_SIZE],
    file_key: &[u8; KEY_SIZE],
    file_id: &str,
    owner_user_id: &str,
) -> Result<EncryptedEnvelope> {
    symmetric::encrypt(wrap_key, file_key, &fek_wrap_aad_v5(file_id, owner_user_id))
}

/// Recover the per-file key of a v5 container with the recovery wrapping key.
pub fn unwrap_fek_v5(
    wrap_key: &[u8; KEY_SIZE],
    envelope: &EncryptedEnvelope,
    file_id: &str,
    owner_user_id: &str,
) -> Result<[u8; KEY_SIZE]> {
    unwrap_32(wrap_key, envelope, &fek_wrap_aad_v5(file_id, owner_user_id))
}

// --- Enterprise (ML-KEM-1024) and Hybrid recovery --------------------------
//
// ML-KEM-1024 (via the platform's X25519 + ML-KEM-1024 hybrid KEM) is used for
// *key encapsulation only*. The encapsulated shared secret is run through
// HKDF-SHA3-256 to derive an AES-256-GCM key that wraps the per-file key — ML-KEM
// never encrypts file content directly.

const KEM_ENCAPS_INFO: &[u8] = b"qguard-vault-recovery-pqc-kem-v1";
const ENTERPRISE_KEY_PREFIX: &str = "QG-EK1-";

/// One ML-KEM recovery recipient stored alongside a vault object (enterprise or
/// hybrid mode). Holds only public/ciphertext material — never a secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryKemWrap {
    /// `enterprise` or `hybrid`.
    pub mode: String,
    /// Fingerprint of the enterprise recovery public key this was sealed to.
    pub recipient_key_id: String,
    pub kem_ciphertext: HybridCiphertext,
    pub salt: Vec<u8>,
    pub wrapped_key: EncryptedEnvelope,
}

/// Generate a fresh enterprise recovery keypair (X25519 + ML-KEM-1024).
pub fn generate_enterprise_keypair() -> LocalKemKeypair {
    LocalKemKeypair::generate()
}

/// Short, safe fingerprint of an enterprise recovery public key, e.g.
/// `A7C3-E921-5D8F-90AA`.
pub fn enterprise_key_fingerprint(x25519_public: &[u8], mlkem_public: &[u8]) -> String {
    let mut material = Vec::with_capacity(x25519_public.len() + mlkem_public.len() + 32);
    material.extend_from_slice(b"qguard-recovery-fingerprint-v1");
    material.extend_from_slice(x25519_public);
    material.extend_from_slice(mlkem_public);
    kdf::sha3_hex(&material)[..16]
        .to_uppercase()
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Encode an enterprise recovery *private* key for the admin to store offline
/// (it is too large to type, so it is downloaded as a key file).
pub fn encode_enterprise_private_key(keypair: &LocalKemKeypair) -> Result<String> {
    let bytes = serde_json::to_vec(keypair)
        .map_err(|e| QGuardError::Storage(format!("encode enterprise recovery key: {e}")))?;
    use base64::Engine;
    Ok(format!(
        "{ENTERPRISE_KEY_PREFIX}{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
    ))
}

pub fn decode_enterprise_private_key(input: &str) -> Result<LocalKemKeypair> {
    let trimmed = input.trim();
    let payload = trimmed.strip_prefix(ENTERPRISE_KEY_PREFIX).unwrap_or(trimmed);
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(payload.trim())
        .map_err(|e| QGuardError::InvalidInput(format!("invalid enterprise recovery key: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| QGuardError::InvalidInput(format!("invalid enterprise recovery key: {e}")))
}

fn kem_wrap_aad(file_id: &str, owner_user_id: &str, mode: &str) -> Vec<u8> {
    format!("QGuard-Vault-Recovery-KEM-v1:{mode}:{file_id}:{owner_user_id}").into_bytes()
}

fn derive_kem_wrap_key(
    mode: &str,
    salt: &[u8],
    shared: &[u8; KEY_SIZE],
    recovery_secret: Option<&[u8; RECOVERY_ROOT_SIZE]>,
) -> Result<[u8; KEY_SIZE]> {
    match mode {
        RECOVERY_MODE_ENTERPRISE => kdf::derive_32_with_salt(salt, shared, &crate::security::obf::enterprise_wrap_info()),
        RECOVERY_MODE_HYBRID => {
            let secret = recovery_secret.ok_or_else(|| {
                QGuardError::InvalidInput(
                    "hybrid recovery requires the personal recovery key".to_string(),
                )
            })?;
            // IKM = recovery_key_secret || mlkem_shared_secret
            let mut ikm = Vec::with_capacity(RECOVERY_ROOT_SIZE + KEY_SIZE);
            ikm.extend_from_slice(secret);
            ikm.extend_from_slice(shared);
            let key = kdf::derive_32_with_salt(salt, &ikm, &crate::security::obf::hybrid_wrap_info());
            ikm.zeroize();
            key
        }
        other => Err(QGuardError::InvalidInput(format!(
            "unsupported recovery mode: {other}"
        ))),
    }
}

/// AAD for the enterprise/hybrid wrap of a v5 container's per-file key. See
/// [`fek_wrap_aad_v5`] for why it is not the v1–v4 label.
fn kem_fek_wrap_aad_v5(file_id: &str, owner_user_id: &str, mode: &str) -> Vec<u8> {
    format!("QGuard-Vault-Recovery-KEM-FEK-v5:{mode}:{file_id}:{owner_user_id}").into_bytes()
}

fn recovery_mode_for(recovery_secret: Option<&[u8; RECOVERY_ROOT_SIZE]>) -> &'static str {
    if recovery_secret.is_some() {
        RECOVERY_MODE_HYBRID
    } else {
        RECOVERY_MODE_ENTERPRISE
    }
}

fn wrap_kem_with(
    recipient_x25519_public: &[u8],
    recipient_mlkem_public: &[u8],
    recovery_secret: Option<&[u8; RECOVERY_ROOT_SIZE]>,
    key: &[u8; KEY_SIZE],
    mode: &'static str,
    aad: &[u8],
    combiner: KemCombiner,
) -> Result<RecoveryKemWrap> {
    let (kem_ciphertext, mut shared) = encapsulate_with(
        recipient_x25519_public,
        recipient_mlkem_public,
        KEM_ENCAPS_INFO,
        combiner,
    )?;
    let salt: [u8; 16] = crate::crypto::provider::random_array();
    let wrap_key = derive_kem_wrap_key(mode, &salt, &shared, recovery_secret);
    shared.zeroize();
    let mut wrap_key = wrap_key?;
    let wrapped_key = symmetric::encrypt(&wrap_key, key, aad);
    wrap_key.zeroize();
    Ok(RecoveryKemWrap {
        mode: mode.to_string(),
        recipient_key_id: enterprise_key_fingerprint(recipient_x25519_public, recipient_mlkem_public),
        kem_ciphertext,
        salt: salt.to_vec(),
        wrapped_key: wrapped_key?,
    })
}

fn unwrap_kem_with(
    recipient: &LocalKemKeypair,
    recovery_secret: Option<&[u8; RECOVERY_ROOT_SIZE]>,
    wrap: &RecoveryKemWrap,
    aad: &[u8],
) -> Result<[u8; KEY_SIZE]> {
    // `decapsulate` reads the combiner the ciphertext was made with from the
    // ciphertext itself, so one unwrap serves both container generations.
    let mut shared = decapsulate(
        &recipient.x25519_secret,
        &recipient.mlkem_secret,
        &wrap.kem_ciphertext,
        KEM_ENCAPS_INFO,
    )?;
    let wrap_key = derive_kem_wrap_key(&wrap.mode, &wrap.salt, &shared, recovery_secret);
    shared.zeroize();
    let mut wrap_key = wrap_key?;
    let key = unwrap_32(&wrap_key, &wrap.wrapped_key, aad);
    wrap_key.zeroize();
    key
}

/// Seal a key to an enterprise ML-KEM recipient (v1–v4 container layout). Pass
/// `recovery_secret` (the personal recovery root) for hybrid mode; pass `None`
/// for enterprise-only.
pub fn wrap_file_key_kem(
    recipient_x25519_public: &[u8],
    recipient_mlkem_public: &[u8],
    recovery_secret: Option<&[u8; RECOVERY_ROOT_SIZE]>,
    file_key: &[u8; KEY_SIZE],
    file_id: &str,
    owner_user_id: &str,
) -> Result<RecoveryKemWrap> {
    let mode = recovery_mode_for(recovery_secret);
    wrap_kem_with(
        recipient_x25519_public,
        recipient_mlkem_public,
        recovery_secret,
        file_key,
        mode,
        &kem_wrap_aad(file_id, owner_user_id, mode),
        KemCombiner::LegacyConcat,
    )
}

/// Recover a key from an enterprise/hybrid wrap (v1–v4 container layout).
/// Hybrid mode requires `recovery_secret` *and* the enterprise private key;
/// enterprise needs only the key.
pub fn unwrap_file_key_kem(
    recipient: &LocalKemKeypair,
    recovery_secret: Option<&[u8; RECOVERY_ROOT_SIZE]>,
    wrap: &RecoveryKemWrap,
    file_id: &str,
    owner_user_id: &str,
) -> Result<[u8; KEY_SIZE]> {
    unwrap_kem_with(
        recipient,
        recovery_secret,
        wrap,
        &kem_wrap_aad(file_id, owner_user_id, &wrap.mode),
    )
}

/// Seal the per-file key of a v5 container to an enterprise ML-KEM recipient,
/// using the transcript-bound hybrid combiner.
pub fn wrap_fek_kem_v5(
    recipient_x25519_public: &[u8],
    recipient_mlkem_public: &[u8],
    recovery_secret: Option<&[u8; RECOVERY_ROOT_SIZE]>,
    file_key: &[u8; KEY_SIZE],
    file_id: &str,
    owner_user_id: &str,
) -> Result<RecoveryKemWrap> {
    let mode = recovery_mode_for(recovery_secret);
    wrap_kem_with(
        recipient_x25519_public,
        recipient_mlkem_public,
        recovery_secret,
        file_key,
        mode,
        &kem_fek_wrap_aad_v5(file_id, owner_user_id, mode),
        KemCombiner::BoundV2,
    )
}

/// Recover the per-file key of a v5 container from its enterprise/hybrid wrap.
pub fn unwrap_fek_kem_v5(
    recipient: &LocalKemKeypair,
    recovery_secret: Option<&[u8; RECOVERY_ROOT_SIZE]>,
    wrap: &RecoveryKemWrap,
    file_id: &str,
    owner_user_id: &str,
) -> Result<[u8; KEY_SIZE]> {
    unwrap_kem_with(
        recipient,
        recovery_secret,
        wrap,
        &kem_fek_wrap_aad_v5(file_id, owner_user_id, &wrap.mode),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_key_round_trips_with_checksum() {
        for _ in 0..50 {
            let root = generate_recovery_root();
            let key = encode_recovery_key(&root);
            let decoded = decode_recovery_key(&key).expect("decode");
            assert_eq!(decoded, root);
            // Lowercase + spaces + Crockford aliases must still decode.
            let messy = key.to_lowercase().replace('-', " ");
            assert_eq!(decode_recovery_key(&messy).expect("messy decode"), root);
        }
    }

    #[test]
    fn tampered_recovery_key_is_rejected() {
        let root = generate_recovery_root();
        let key = encode_recovery_key(&root);
        let mut chars: Vec<char> = key.chars().filter(|c| *c != '-').collect();
        // Flip the first body character to a different valid symbol.
        chars[0] = if chars[0] == 'Z' { 'Y' } else { 'Z' };
        let tampered: String = chars.into_iter().collect();
        assert!(decode_recovery_key(&tampered).is_err());
    }

    #[test]
    fn wrap_unwrap_round_trips_and_binds_context() {
        let root = generate_recovery_root();
        let wrap_key = derive_wrap_key(&root).unwrap();
        let file_key = symmetric::random_key();
        let env = wrap_file_key(&wrap_key, &file_key, "file-1", "user-1").unwrap();
        let recovered = unwrap_file_key(&wrap_key, &env, "file-1", "user-1").unwrap();
        assert_eq!(recovered, file_key);
        // Wrong file id / owner must fail authentication.
        assert!(unwrap_file_key(&wrap_key, &env, "file-2", "user-1").is_err());
        assert!(unwrap_file_key(&wrap_key, &env, "file-1", "user-2").is_err());
        // Wrong recovery key must fail.
        let other = derive_wrap_key(&generate_recovery_root()).unwrap();
        assert!(unwrap_file_key(&other, &env, "file-1", "user-1").is_err());
    }

    #[test]
    fn verifier_is_stable_and_distinct_from_wrap_key() {
        let root = generate_recovery_root();
        assert_eq!(derive_verifier(&root).unwrap(), derive_verifier(&root).unwrap());
        let wrap_key = derive_wrap_key(&root).unwrap();
        assert_ne!(derive_verifier(&root).unwrap(), kdf::sha3_hex(&wrap_key));
    }

    #[test]
    fn enterprise_kem_wrap_round_trips() {
        let enterprise = generate_enterprise_keypair();
        let file_key = symmetric::random_key();
        let wrap = wrap_file_key_kem(
            &enterprise.x25519_public,
            &enterprise.mlkem_public,
            None,
            &file_key,
            "file-1",
            "user-1",
        )
        .unwrap();
        assert_eq!(wrap.mode, RECOVERY_MODE_ENTERPRISE);
        assert_eq!(
            unwrap_file_key_kem(&enterprise, None, &wrap, "file-1", "user-1").unwrap(),
            file_key
        );
        // Wrong enterprise key, or wrong file/owner context, must fail.
        let other = generate_enterprise_keypair();
        assert!(unwrap_file_key_kem(&other, None, &wrap, "file-1", "user-1").is_err());
        assert!(unwrap_file_key_kem(&enterprise, None, &wrap, "file-2", "user-1").is_err());
        assert!(unwrap_file_key_kem(&enterprise, None, &wrap, "file-1", "user-2").is_err());
    }

    #[test]
    fn hybrid_recovery_requires_both_secrets() {
        let enterprise = generate_enterprise_keypair();
        let root = generate_recovery_root();
        let file_key = symmetric::random_key();
        let wrap = wrap_file_key_kem(
            &enterprise.x25519_public,
            &enterprise.mlkem_public,
            Some(&root),
            &file_key,
            "file-1",
            "user-1",
        )
        .unwrap();
        assert_eq!(wrap.mode, RECOVERY_MODE_HYBRID);
        // Both secrets -> success.
        assert_eq!(
            unwrap_file_key_kem(&enterprise, Some(&root), &wrap, "file-1", "user-1").unwrap(),
            file_key
        );
        // Missing the recovery key, a wrong recovery key, or a wrong enterprise
        // key all fail — both factors are genuinely required.
        assert!(unwrap_file_key_kem(&enterprise, None, &wrap, "file-1", "user-1").is_err());
        let wrong_root = generate_recovery_root();
        assert!(unwrap_file_key_kem(&enterprise, Some(&wrong_root), &wrap, "file-1", "user-1").is_err());
        let other = generate_enterprise_keypair();
        assert!(unwrap_file_key_kem(&other, Some(&root), &wrap, "file-1", "user-1").is_err());
    }

    #[test]
    fn v5_wraps_round_trip_and_cannot_be_read_as_the_older_layout() {
        // The v5 envelope holds the per-file key; the v1–v4 envelope holds a
        // file key or the Vault Master Key. The labels differ so one can never
        // be passed off as the other by relabelling a header's version.
        let root = generate_recovery_root();
        let wrap_key = derive_wrap_key(&root).unwrap();
        let file_key = symmetric::random_key();

        let v5 = wrap_fek_v5(&wrap_key, &file_key, "file-1", "user-1").unwrap();
        assert_eq!(unwrap_fek_v5(&wrap_key, &v5, "file-1", "user-1").unwrap(), file_key);
        assert!(unwrap_file_key(&wrap_key, &v5, "file-1", "user-1").is_err());
        assert!(unwrap_fek_v5(&wrap_key, &v5, "file-2", "user-1").is_err());

        let legacy = wrap_file_key(&wrap_key, &file_key, "file-1", "user-1").unwrap();
        assert!(unwrap_fek_v5(&wrap_key, &legacy, "file-1", "user-1").is_err());

        // Same separation for the enterprise / hybrid KEM wraps, which also move
        // to the transcript-bound combiner in v5.
        let enterprise = generate_enterprise_keypair();
        for secret in [None, Some(&root)] {
            let wrap = wrap_fek_kem_v5(
                &enterprise.x25519_public,
                &enterprise.mlkem_public,
                secret,
                &file_key,
                "file-1",
                "user-1",
            )
            .unwrap();
            assert_eq!(
                wrap.kem_ciphertext.suite.kem_combiner,
                crate::crypto::CURRENT_KEM_COMBINER
            );
            assert_eq!(
                unwrap_fek_kem_v5(&enterprise, secret, &wrap, "file-1", "user-1").unwrap(),
                file_key
            );
            assert!(unwrap_file_key_kem(&enterprise, secret, &wrap, "file-1", "user-1").is_err());
            assert!(unwrap_fek_kem_v5(&enterprise, secret, &wrap, "file-9", "user-1").is_err());
        }
        // Hybrid still needs BOTH factors in v5.
        let hybrid = wrap_fek_kem_v5(
            &enterprise.x25519_public,
            &enterprise.mlkem_public,
            Some(&root),
            &file_key,
            "file-1",
            "user-1",
        )
        .unwrap();
        assert!(unwrap_fek_kem_v5(&enterprise, None, &hybrid, "file-1", "user-1").is_err());
    }

    #[test]
    fn enterprise_private_key_encodes_and_fingerprint_is_stable() {
        let enterprise = generate_enterprise_keypair();
        let encoded = encode_enterprise_private_key(&enterprise).unwrap();
        assert!(encoded.starts_with("QG-EK1-"));
        let decoded = decode_enterprise_private_key(&encoded).unwrap();
        assert_eq!(decoded.mlkem_public, enterprise.mlkem_public);
        assert_eq!(decoded.x25519_public, enterprise.x25519_public);
        let fp1 = enterprise_key_fingerprint(&enterprise.x25519_public, &enterprise.mlkem_public);
        let fp2 = enterprise_key_fingerprint(&decoded.x25519_public, &decoded.mlkem_public);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 19); // 16 hex chars + 3 dashes
    }
}
