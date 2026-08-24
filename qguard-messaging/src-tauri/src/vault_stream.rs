//! Streaming, on-disk quantum-safe vault container.
//!
//! This module streams plaintext through the hybrid post-quantum stack one chunk
//! at a time, so it works for arbitrarily large files and folders with constant
//! memory and no IPC/base64 round-trips. It is the only vault crypto path: the
//! Quantum Vault is strictly local, so there is no cloud upload/package format.
//!
//! * Content:   AES-256-GCM per 1 MiB chunk, AAD-bound to file id + chunk index
//! * Envelope (v3): File -> AES-256-GCM FEK -> FEK wrapped by the Vault Master
//!              Key (VMK) -> VMK protected by X25519 + ML-KEM-1024 (and, when
//!              configured, by the recovery key / enterprise ML-KEM recipient).
//!              ML-KEM only ever protects keys, never file content.
//! * KDF:       HKDF-SHA3-256 (inside the hybrid KEX)
//! * Header:    v3 dual-signed Ed25519 + ML-DSA-87 (FIPS 204 Level 5); v1/v2
//!              dual-signed Ed25519 + ML-DSA-65. The signature authenticates the
//!              wrapped key(s), metadata, and total chunk count -> truncation /
//!              extension proof. v1/v2 (FEK wrapped directly to the device) are
//!              still accepted on decrypt; new files are always written as v3.
//!
//! # What actually has to be known to open a container
//!
//! On v3+ the FEK is wrapped by the VMK, and the VMK is itself sealed under the
//! user's vault password (Argon2id -> HKDF-SHA3-256 -> AES-256-GCM, see
//! `commands::workspace`). [`decrypt_stream_with_vmk`] is therefore the primary
//! owner path and the one the app tries first: it needs the unlock secret and
//! nothing else.
//!
//! The KEM wrap in the header is a secondary path. It is sealed to the vault's
//! own ML-KEM keypair, which lives inside that same password-wrapped master —
//! so for a container written by a build that has one, the KEM wrap is not a way
//! around the password either. Containers written before that keypair existed
//! were wrapped to the messaging device identity key, whose secret is protected
//! by the OS keychain alone; `vault_rewrap_path` re-seals them.
//!
//! On-disk layout:
//! ```text
//! MAGIC(8) | u32 header_len | header JSON | [ u32 ct_len | nonce(12) | tag(16) | ciphertext ]*
//! ```

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::hybrid_kex::{decapsulate, encapsulate, LocalKemKeypair};
use crate::crypto::portable_identity;
use crate::crypto::signatures::{dual_verify, dual_sign_87, dual_verify_87, VaultSigningKeypair};
use crate::crypto::symmetric::{self, KEY_SIZE};
use crate::crypto::vault_recovery;
use crate::crypto::{vault_suite, AlgorithmSuite, DualSignature, DualSignature87, EncryptedEnvelope, HybridCiphertext};
use crate::error::{QGuardError, Result};

const MAGIC: &[u8; 8] = b"QGUARDVS";
/// v1: device wrap only. v2: adds an optional quantum-safe recovery-key wrap so
/// files survive total device loss. v3: introduces the Vault Master Key (VMK)
/// envelope (FEK wrapped by VMK; VMK protected by ML-KEM-1024 / recovery /
/// enterprise) and signs with ML-DSA-87. v4: adds Portable Hybrid Identity
/// recipient wraps (the per-file FEK sealed to another person's identity) plus
/// an optional sender attestation. All versions are accepted on decrypt; a
/// container is written as v4 only when it is sealed for a recipient, and as v3
/// otherwise.
pub const STREAM_VERSION: u8 = 3;
/// Version stamped on containers that carry Portable Hybrid Identity recipient
/// wraps. Kept distinct from [`STREAM_VERSION`] so ordinary device-sealed
/// containers keep producing byte-identical signable bytes.
pub const STREAM_VERSION_RECIPIENT: u8 = 4;
/// Highest container version this build can read.
pub const MAX_STREAM_VERSION: u8 = STREAM_VERSION_RECIPIENT;
/// Defensive cap on how many identities one container may be sealed to. Each
/// wrap adds ~3 KB of header, and the header itself is capped at 1 MiB.
pub const MAX_RECIPIENTS: usize = 64;
pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB plaintext per chunk
const MAX_HEADER_LEN: usize = 1024 * 1024; // signed header is a few KB; cap defensively
const MAX_FRAME_CIPHERTEXT: usize = CHUNK_SIZE + 64;

pub const KIND_FILE: &str = "file";
pub const KIND_FOLDER: &str = "folder";

/// Enterprise/hybrid recovery recipient passed to `encrypt_stream`. Provide the
/// enterprise public key; set `recovery_secret` to the personal recovery root
/// for hybrid mode (both factors required), or `None` for enterprise-only.
pub struct EnterpriseRecipient<'a> {
    pub x25519_public: &'a [u8],
    pub mlkem_public: &'a [u8],
    pub recovery_secret: Option<&'a [u8; KEY_SIZE]>,
}

/// One Portable Hybrid Identity this container is sealed to (v4).
///
/// Security note — this wrap seals the **per-file FEK**, never the Vault Master
/// Key. The device/recovery/enterprise wraps above all protect the VMK, which
/// unlocks every file the owner has; handing that to a share recipient would
/// give them the whole vault. A recipient gets exactly one file's key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientWrap {
    /// SHA3-256 over the recipient's four public keys (hex).
    pub recipient_fingerprint: String,
    /// Recipient's own label, carried so the sender's UI can list who a
    /// container was sealed for. Non-authoritative display text.
    #[serde(default)]
    pub label: String,
    /// e.g. `X25519+ML-KEM-1024/HKDF-SHA3-256/AES-256-GCM`.
    pub algorithm: String,
    pub kem_ciphertext: HybridCiphertext,
    pub salt: Vec<u8>,
    pub wrapped_key: EncryptedEnvelope,
}

/// What a sealed container carries about who created it, plus the sender's KEM
/// public keys so the recipient can recompute the attested fingerprint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SenderIdentity {
    pub x25519_public: Vec<u8>,
    pub mlkem_public: Vec<u8>,
    pub attestation: portable_identity::SenderAttestation,
}

/// Sharing parameters for [`encrypt_stream_with_progress`]. `None` (the default)
/// produces an ordinary v3 device-sealed container.
#[derive(Default)]
pub struct SharingOptions<'a> {
    /// Identities the per-file key is additionally sealed to.
    pub recipients: &'a [portable_identity::RecipientPublicKeys],
    /// The sender's unlocked identity, used to attest authorship. Optional: a
    /// container can be sealed for a recipient without naming its sender.
    pub sender: Option<&'a portable_identity::PortableIdentity>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamHeader {
    pub version: u8,
    pub file_id: String,
    pub kind: String,
    pub name: String,
    pub content_type: String,
    pub original_size: u64,
    pub chunk_size: u32,
    pub total_chunks: u64,
    pub owner_user_id: String,
    pub owner_device_id: String,
    pub hybrid_ciphertext: HybridCiphertext,
    /// v1/v2: the per-file FEK wrapped to the device hybrid-KEM. v3: the Vault
    /// Master Key (VMK) wrapped to the device hybrid-KEM. `recovery_wrapped_key`
    /// and `recovery_kem_wrap` follow the same version-dependent meaning.
    pub wrapped_key: EncryptedEnvelope,
    /// v1/v2: optional recovery-key wrap of the FEK. v3: optional recovery-key
    /// wrap of the VMK. Lets the owner decrypt on a brand-new device using only
    /// their recovery key.
    #[serde(default)]
    pub recovery_wrapped_key: Option<EncryptedEnvelope>,
    /// Optional enterprise/hybrid ML-KEM-1024 recovery recipient (v2+). Wraps the
    /// FEK in v1/v2 and the VMK in v3.
    #[serde(default)]
    pub recovery_kem_wrap: Option<vault_recovery::RecoveryKemWrap>,
    /// v3 only: the per-file FEK wrapped under the Vault Master Key (AES-256-GCM).
    /// `wrapped_key` / recovery wraps above unwrap the VMK, which then unwraps
    /// this to recover the FEK. Absent on v1/v2 containers.
    #[serde(default)]
    pub fek_wrapped_by_vmk: Option<EncryptedEnvelope>,
    pub suite: AlgorithmSuite,
    pub signer_ed25519_public: Vec<u8>,
    /// v1/v2 ML-DSA-65 signer public (empty on v3 containers).
    #[serde(default)]
    pub signer_mldsa_public: Vec<u8>,
    /// v3 ML-DSA-87 vault signer public (empty on v1/v2 containers).
    #[serde(default)]
    pub signer_mldsa87_public: Vec<u8>,
    /// v1/v2 Ed25519 + ML-DSA-65 header signature (empty vecs on v3 containers).
    pub header_signature: DualSignature,
    /// v3 Ed25519 + ML-DSA-87 header signature (absent on v1/v2 containers).
    #[serde(default)]
    pub header_signature_v3: Option<DualSignature87>,
    /// v4 only: Portable Hybrid Identity recipients the per-file FEK is sealed
    /// to. Empty on every v1/v2/v3 container.
    #[serde(default)]
    pub recipient_wraps: Vec<RecipientWrap>,
    /// v4 only: who sealed this container, signed by their portable identity.
    #[serde(default)]
    pub sender_identity: Option<SenderIdentity>,
}

/// Public, non-secret summary returned to callers after a stream operation.
#[derive(Clone, Debug, Serialize)]
pub struct StreamSummary {
    pub file_id: String,
    pub kind: String,
    pub name: String,
    pub content_type: String,
    pub original_size: u64,
    pub total_chunks: u64,
    pub suite: AlgorithmSuite,
    /// Fingerprints of every Portable Hybrid Identity this container is sealed
    /// to. Empty for ordinary device-only containers.
    #[serde(default)]
    pub sealed_for: Vec<SealedRecipient>,
    /// Set once a sender attestation has been cryptographically **verified**.
    /// A present-but-invalid attestation makes the whole operation fail, so this
    /// is never a mere claim.
    #[serde(default)]
    pub verified_sender: Option<VerifiedSender>,
}

/// Non-secret display record of one recipient a container is sealed to.
#[derive(Clone, Debug, Serialize)]
pub struct SealedRecipient {
    pub fingerprint: String,
    pub label: String,
    pub algorithm: String,
}

/// A sender attestation that verified against the container's signed header.
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedSender {
    pub fingerprint: String,
    pub label: String,
    pub signature_algorithm: String,
}

impl StreamSummary {
    fn from_header(header: &StreamHeader) -> Self {
        Self {
            file_id: header.file_id.clone(),
            kind: header.kind.clone(),
            name: header.name.clone(),
            content_type: header.content_type.clone(),
            original_size: header.original_size,
            total_chunks: header.total_chunks,
            suite: header.suite.clone(),
            sealed_for: header
                .recipient_wraps
                .iter()
                .map(|wrap| SealedRecipient {
                    fingerprint: wrap.recipient_fingerprint.clone(),
                    label: wrap.label.clone(),
                    algorithm: wrap.algorithm.clone(),
                })
                .collect(),
            verified_sender: None,
        }
    }
}

/// Real, non-secret progress update streamed to the UI during a vault stream
/// operation. Every field is measured from the actual chunk loop — never faked.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultProgress {
    pub op: String,            // "encrypt" | "decrypt" | "rewrap"
    pub phase: String,         // init|fek|vmk_wrap|recovery_wrap|sign|header|chunk|verify|decapsulate|unwrap_fek|finalize|done
    pub message: String,
    pub processed_bytes: u64,
    pub total_bytes: u64,
    pub chunk_index: u64,
    pub total_chunks: u64,
    pub level: String,         // "info" | "success"
}

/// Emit at most ~200 chunk events regardless of size: smooth bar, bounded IPC.
fn chunk_emit_every(total_chunks: u64) -> u64 {
    (total_chunks / 200).max(1)
}

fn io_err(error: io::Error) -> QGuardError {
    QGuardError::Storage(format!("vault stream I/O failed: {error}"))
}

fn wrap_aad_bytes(file_id: &str, owner_user_id: &str, owner_device_id: &str) -> Vec<u8> {
    format!("QGuard-Vault-Stream-Wrap-v1:{file_id}:{owner_user_id}:{owner_device_id}").into_bytes()
}

/// AAD binding the v3 FEK-under-VMK wrap to its container (file id + owner).
fn fek_vmk_wrap_aad(file_id: &str, owner_user_id: &str) -> Vec<u8> {
    format!("QGuard-Vault-FEK-Under-VMK-v1:{file_id}:{owner_user_id}").into_bytes()
}

fn chunk_aad(file_id: &str, index: u64, total_chunks: u64, is_last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(file_id.len() + 32);
    aad.extend_from_slice(&crate::security::obf::vault_stream_chunk_aad_prefix());
    aad.extend_from_slice(file_id.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&total_chunks.to_be_bytes());
    aad.push(if is_last { 1 } else { 0 });
    aad
}

/// Canonical, signature-covered bytes for the header (independent of JSON field order).
fn header_signable(header: &StreamHeader) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(MAGIC);
    data.push(header.version);
    data.extend_from_slice(header.file_id.as_bytes());
    data.push(0);
    data.extend_from_slice(header.kind.as_bytes());
    data.push(0);
    data.extend_from_slice(header.name.as_bytes());
    data.push(0);
    data.extend_from_slice(header.content_type.as_bytes());
    data.push(0);
    data.extend_from_slice(&header.original_size.to_be_bytes());
    data.extend_from_slice(&header.chunk_size.to_be_bytes());
    data.extend_from_slice(&header.total_chunks.to_be_bytes());
    data.extend_from_slice(header.owner_user_id.as_bytes());
    data.push(0);
    data.extend_from_slice(header.owner_device_id.as_bytes());
    data.push(0);
    data.extend_from_slice(&header.hybrid_ciphertext.x25519_ephemeral_public);
    data.extend_from_slice(&header.hybrid_ciphertext.ml_kem_ciphertext);
    data.extend_from_slice(header.hybrid_ciphertext.suite.pq_kem.as_bytes());
    data.extend_from_slice(&header.wrapped_key.nonce);
    data.extend_from_slice(&header.wrapped_key.ciphertext);
    data.extend_from_slice(&header.wrapped_key.tag);
    data.extend_from_slice(header.suite.pq_kem.as_bytes());
    data.extend_from_slice(&header.signer_ed25519_public);
    data.extend_from_slice(&header.signer_mldsa_public);
    // v2+ authenticates the optional recovery wrap. v1 bytes are left unchanged
    // so existing v1 containers still verify against their original signature.
    if header.version >= 2 {
        match &header.recovery_wrapped_key {
            Some(env) => {
                data.push(1);
                data.extend_from_slice(&env.nonce);
                data.extend_from_slice(&env.ciphertext);
                data.extend_from_slice(&env.tag);
            }
            None => data.push(0),
        }
        match &header.recovery_kem_wrap {
            Some(kem) => {
                data.push(2);
                data.extend_from_slice(kem.mode.as_bytes());
                data.push(0);
                data.extend_from_slice(kem.recipient_key_id.as_bytes());
                data.push(0);
                data.extend_from_slice(&kem.kem_ciphertext.x25519_ephemeral_public);
                data.extend_from_slice(&kem.kem_ciphertext.ml_kem_ciphertext);
                data.extend_from_slice(kem.kem_ciphertext.suite.pq_kem.as_bytes());
                data.extend_from_slice(&kem.salt);
                data.extend_from_slice(&kem.wrapped_key.nonce);
                data.extend_from_slice(&kem.wrapped_key.ciphertext);
                data.extend_from_slice(&kem.wrapped_key.tag);
            }
            None => data.push(0),
        }
    }
    // v3 additionally authenticates the FEK-under-VMK wrap and the ML-DSA-87
    // signer public key. v1/v2 bytes are untouched so older containers still
    // verify against their original signature.
    if header.version >= 3 {
        match &header.fek_wrapped_by_vmk {
            Some(env) => {
                data.push(3);
                data.extend_from_slice(&env.nonce);
                data.extend_from_slice(&env.ciphertext);
                data.extend_from_slice(&env.tag);
            }
            None => data.push(0),
        }
        data.extend_from_slice(&header.signer_mldsa87_public);
    }
    // v4 additionally authenticates every Portable Hybrid Identity recipient
    // wrap and the sender attestation's public fields (its own signature is
    // excluded, so the attestation and the header signature cover identical
    // bytes). Appended only for v4, so v1/v2/v3 containers still verify against
    // their original signatures byte-for-byte.
    if header.version >= 4 {
        data.extend_from_slice(&(header.recipient_wraps.len() as u32).to_be_bytes());
        for wrap in &header.recipient_wraps {
            data.extend_from_slice(wrap.recipient_fingerprint.as_bytes());
            data.push(0);
            data.extend_from_slice(wrap.label.as_bytes());
            data.push(0);
            data.extend_from_slice(wrap.algorithm.as_bytes());
            data.push(0);
            data.extend_from_slice(&wrap.kem_ciphertext.x25519_ephemeral_public);
            data.extend_from_slice(&wrap.kem_ciphertext.ml_kem_ciphertext);
            data.extend_from_slice(wrap.kem_ciphertext.suite.pq_kem.as_bytes());
            data.extend_from_slice(&wrap.salt);
            data.extend_from_slice(&wrap.wrapped_key.nonce);
            data.extend_from_slice(&wrap.wrapped_key.ciphertext);
            data.extend_from_slice(&wrap.wrapped_key.tag);
        }
        match &header.sender_identity {
            Some(sender) => {
                data.push(4);
                data.extend_from_slice(&sender.x25519_public);
                data.extend_from_slice(&sender.mlkem_public);
                data.extend_from_slice(sender.attestation.identity_fingerprint.as_bytes());
                data.push(0);
                data.extend_from_slice(sender.attestation.label.as_bytes());
                data.push(0);
                data.extend_from_slice(sender.attestation.signature_algorithm.as_bytes());
                data.push(0);
                data.extend_from_slice(&sender.attestation.ed25519_public);
                data.extend_from_slice(&sender.attestation.mldsa_public);
            }
            None => data.push(0),
        }
    }
    data
}

/// Canonical bytes the sender attestation signs.
///
/// Deliberately narrower than [`header_signable`]: it covers the container's
/// identity and metadata, every recipient wrap, and the sender's own public
/// keys — but NOT the owner's device / recovery / enterprise VMK wraps. Those
/// are owner-side plumbing a recipient never consumes, and they are rewritten
/// whenever the owner re-protects the container, which would otherwise silently
/// invalidate a perfectly good attestation.
///
/// Content substitution is still covered: every chunk is AAD-bound to
/// `file_id | index | total_chunks` (all signed here), and re-encrypting under a
/// different FEK necessarily changes the recipient wraps (also signed here).
fn attestation_signable(header: &StreamHeader) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(MAGIC);
    data.extend_from_slice(b"QGuard-Vault-Sender-Attestation-v1");
    data.extend_from_slice(header.file_id.as_bytes());
    data.push(0);
    data.extend_from_slice(header.kind.as_bytes());
    data.push(0);
    data.extend_from_slice(header.name.as_bytes());
    data.push(0);
    data.extend_from_slice(header.content_type.as_bytes());
    data.push(0);
    data.extend_from_slice(&header.original_size.to_be_bytes());
    data.extend_from_slice(&header.chunk_size.to_be_bytes());
    data.extend_from_slice(&header.total_chunks.to_be_bytes());
    data.extend_from_slice(header.owner_user_id.as_bytes());
    data.push(0);
    data.extend_from_slice(header.owner_device_id.as_bytes());
    data.push(0);
    data.extend_from_slice(&(header.recipient_wraps.len() as u32).to_be_bytes());
    for wrap in &header.recipient_wraps {
        data.extend_from_slice(wrap.recipient_fingerprint.as_bytes());
        data.push(0);
        data.extend_from_slice(wrap.algorithm.as_bytes());
        data.push(0);
        data.extend_from_slice(&wrap.kem_ciphertext.x25519_ephemeral_public);
        data.extend_from_slice(&wrap.kem_ciphertext.ml_kem_ciphertext);
        data.extend_from_slice(&wrap.salt);
        data.extend_from_slice(&wrap.wrapped_key.nonce);
        data.extend_from_slice(&wrap.wrapped_key.ciphertext);
        data.extend_from_slice(&wrap.wrapped_key.tag);
    }
    if let Some(sender) = &header.sender_identity {
        data.extend_from_slice(&sender.x25519_public);
        data.extend_from_slice(&sender.mlkem_public);
        data.extend_from_slice(sender.attestation.identity_fingerprint.as_bytes());
        data.push(0);
        data.extend_from_slice(sender.attestation.label.as_bytes());
        data.push(0);
        data.extend_from_slice(sender.attestation.signature_algorithm.as_bytes());
        data.push(0);
        data.extend_from_slice(&sender.attestation.ed25519_public);
        data.extend_from_slice(&sender.attestation.mldsa_public);
    }
    data
}

/// AAD binding one recipient wrap to its container AND to that exact recipient,
/// so a wrap cannot be lifted into another container or re-pointed at a
/// different identity.
fn recipient_wrap_aad(file_id: &str, owner_user_id: &str, recipient_fingerprint: &str) -> Vec<u8> {
    format!("QGuard-Vault-Recipient-FEK-v1:{file_id}:{owner_user_id}:{recipient_fingerprint}")
        .into_bytes()
}

/// Seal the per-file key to one Portable Hybrid Identity: hybrid encapsulation
/// (X25519 + ML-KEM) → HKDF-SHA3-256 with a per-wrap salt → AES-256-GCM.
fn wrap_fek_for_recipient(
    recipient: &portable_identity::RecipientPublicKeys,
    file_key: &[u8; KEY_SIZE],
    file_id: &str,
    owner_user_id: &str,
) -> Result<RecipientWrap> {
    let (kem_ciphertext, mut shared) = encapsulate(
        &recipient.x25519_public,
        &recipient.mlkem_public,
        &crate::security::obf::portable_identity_kem_info(),
    )?;
    let mut salt = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let wrap_key = crate::crypto::kdf::derive_32_with_salt(
        &salt,
        &shared,
        &crate::security::obf::portable_identity_wrap_info(),
    );
    shared.zeroize();
    let mut wrap_key = wrap_key?;
    let wrapped_key = symmetric::encrypt(
        &wrap_key,
        file_key,
        &recipient_wrap_aad(file_id, owner_user_id, &recipient.fingerprint),
    );
    wrap_key.zeroize();

    Ok(RecipientWrap {
        recipient_fingerprint: recipient.fingerprint.clone(),
        label: recipient.label.clone().unwrap_or_default(),
        algorithm: format!(
            "X25519+{}/HKDF-SHA3-256/AES-256-GCM",
            kem_ciphertext.suite.pq_kem
        ),
        kem_ciphertext,
        salt: salt.to_vec(),
        wrapped_key: wrapped_key?,
    })
}

/// Recover the per-file key from a recipient wrap using an unlocked identity.
fn unwrap_fek_for_recipient(
    identity: &portable_identity::PortableIdentity,
    wrap: &RecipientWrap,
    file_id: &str,
    owner_user_id: &str,
) -> Result<[u8; KEY_SIZE]> {
    let mut shared = decapsulate(
        &identity.kem.x25519_secret,
        &identity.kem.mlkem_secret,
        &wrap.kem_ciphertext,
        &crate::security::obf::portable_identity_kem_info(),
    )?;
    let wrap_key = crate::crypto::kdf::derive_32_with_salt(
        &wrap.salt,
        &shared,
        &crate::security::obf::portable_identity_wrap_info(),
    );
    shared.zeroize();
    let mut wrap_key = wrap_key?;
    let unwrapped = symmetric::decrypt(
        &wrap_key,
        &wrap.wrapped_key,
        &recipient_wrap_aad(file_id, owner_user_id, &wrap.recipient_fingerprint),
    );
    wrap_key.zeroize();
    let mut bytes = unwrapped?;
    if bytes.len() != KEY_SIZE {
        bytes.zeroize();
        return Err(QGuardError::Crypto(
            "recipient-unwrapped file key is invalid".to_string(),
        ));
    }
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(key)
}

fn total_chunks_for(original_size: u64) -> u64 {
    if original_size == 0 {
        0
    } else {
        ((original_size as u128 + CHUNK_SIZE as u128 - 1) / CHUNK_SIZE as u128) as u64
    }
}

/// Read up to `buf.len()` bytes, looping over short reads until full or EOF.
fn read_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_err(e)),
        }
    }
    Ok(filled)
}

fn read_exact_buf<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    reader.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            QGuardError::Crypto("vault stream is truncated or corrupt".to_string())
        } else {
            io_err(e)
        }
    })
}

fn write_chunk_frame<W: Write>(writer: &mut W, env: &EncryptedEnvelope) -> Result<()> {
    writer
        .write_all(&(env.ciphertext.len() as u32).to_be_bytes())
        .map_err(io_err)?;
    writer.write_all(&env.nonce).map_err(io_err)?;
    writer.write_all(&env.tag).map_err(io_err)?;
    writer.write_all(&env.ciphertext).map_err(io_err)?;
    Ok(())
}

fn read_chunk_frame<R: Read>(reader: &mut R) -> Result<EncryptedEnvelope> {
    let mut len_buf = [0u8; 4];
    read_exact_buf(reader, &mut len_buf)?;
    let ct_len = u32::from_be_bytes(len_buf) as usize;
    if ct_len > MAX_FRAME_CIPHERTEXT {
        return Err(QGuardError::Crypto("vault stream chunk frame is oversized".to_string()));
    }
    let mut nonce = vec![0u8; symmetric::NONCE_SIZE];
    read_exact_buf(reader, &mut nonce)?;
    let mut tag = vec![0u8; symmetric::TAG_SIZE];
    read_exact_buf(reader, &mut tag)?;
    let mut ciphertext = vec![0u8; ct_len];
    read_exact_buf(reader, &mut ciphertext)?;
    Ok(EncryptedEnvelope {
        nonce,
        ciphertext,
        tag,
    })
}

/// Stream-encrypt `reader` (exactly `original_size` bytes) into `writer`, wrapping
/// the per-file AES key to the recipient device via the hybrid KEX.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    kind: &str,
    name: &str,
    content_type: &str,
    original_size: u64,
    owner_user_id: &str,
    owner_device_id: &str,
    recipient_x25519_public: &[u8],
    recipient_mlkem_public: &[u8],
    vmk: &[u8; KEY_SIZE],
    vault_signer: &VaultSigningKeypair,
    recovery_wrap_key: Option<&[u8; KEY_SIZE]>,
    enterprise: Option<&EnterpriseRecipient>,
) -> Result<StreamSummary> {
    encrypt_stream_with_progress(
        reader,
        writer,
        kind,
        name,
        content_type,
        original_size,
        owner_user_id,
        owner_device_id,
        recipient_x25519_public,
        recipient_mlkem_public,
        vmk,
        vault_signer,
        recovery_wrap_key,
        enterprise,
        None,
        &mut |_| {},
    )
}

/// Same as [`encrypt_stream`] but reports real per-phase / per-chunk progress
/// through `progress`. The sink is best-effort telemetry only — it never affects
/// the produced container.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    kind: &str,
    name: &str,
    content_type: &str,
    original_size: u64,
    owner_user_id: &str,
    owner_device_id: &str,
    recipient_x25519_public: &[u8],
    recipient_mlkem_public: &[u8],
    vmk: &[u8; KEY_SIZE],
    vault_signer: &VaultSigningKeypair,
    recovery_wrap_key: Option<&[u8; KEY_SIZE]>,
    enterprise: Option<&EnterpriseRecipient>,
    sharing: Option<&SharingOptions>,
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let file_id = Uuid::new_v4().to_string();
    let total_chunks = total_chunks_for(original_size);
    let recipients = sharing.map(|s| s.recipients).unwrap_or(&[]);
    if recipients.len() > MAX_RECIPIENTS {
        return Err(QGuardError::InvalidInput(format!(
            "a container can be sealed to at most {MAX_RECIPIENTS} identities"
        )));
    }

    let emit = |progress: &mut dyn FnMut(VaultProgress),
                phase: &str,
                message: &str,
                processed: u64,
                idx: u64,
                level: &str| {
        progress(VaultProgress {
            op: "encrypt".into(),
            phase: phase.into(),
            message: message.into(),
            processed_bytes: processed,
            total_bytes: original_size,
            chunk_index: idx,
            total_chunks,
            level: level.into(),
        });
    };
    emit(progress, "init", "Initializing quantum-safe vault container", 0, 0, "info");

    // The per-file FEK encrypts the bulk data; the VMK protects the FEK.
    let mut file_key = symmetric::random_key();
    let fek_wrapped_by_vmk = Some(symmetric::encrypt(
        vmk,
        &file_key,
        &fek_vmk_wrap_aad(&file_id, owner_user_id),
    )?);
    emit(progress, "fek", "Per-file key generated · AES-256-GCM (256-bit) · wrapped under VMK", 0, 0, "info");

    // The device / recovery / enterprise wraps all seal the VMK (never the FEK,
    // and never the file content). ML-KEM only ever protects keys.
    let (hybrid_ciphertext, mut wrapping_secret) =
        encapsulate(recipient_x25519_public, recipient_mlkem_public, &crate::security::obf::vault_stream_wrap_info())?;
    let wrap_aad = wrap_aad_bytes(&file_id, owner_user_id, owner_device_id);
    let wrapped_key = symmetric::encrypt(&wrapping_secret, vmk, &wrap_aad)?;
    wrapping_secret.zeroize();
    emit(progress, "vmk_wrap", "Vault Master Key sealed to device · X25519 + ML-KEM-1024", 0, 0, "info");

    // Optionally seal a backup copy of the VMK under the quantum-safe recovery
    // key so the vault can be recovered on a new device without this one.
    let recovery_wrapped_key = match recovery_wrap_key {
        Some(key) => Some(vault_recovery::wrap_file_key(key, vmk, &file_id, owner_user_id)?),
        None => None,
    };
    let recovery_kem_wrap = match enterprise {
        Some(ent) => Some(vault_recovery::wrap_file_key_kem(
            ent.x25519_public,
            ent.mlkem_public,
            ent.recovery_secret,
            vmk,
            &file_id,
            owner_user_id,
        )?),
        None => None,
    };
    if recovery_wrapped_key.is_some() || recovery_kem_wrap.is_some() {
        emit(progress, "recovery_wrap", "VMK sealed to recovery recipient · ML-KEM-1024 / HKDF-SHA3-256", 0, 0, "info");
    }

    // Portable Hybrid Identity recipients. These seal the per-file FEK — never
    // the VMK — so a recipient can open this one container and nothing else.
    // Duplicate fingerprints are collapsed so a container never carries two
    // wraps for the same identity.
    let mut recipient_wraps = Vec::with_capacity(recipients.len());
    let mut seen_fingerprints = std::collections::HashSet::new();
    for recipient in recipients {
        if !seen_fingerprints.insert(recipient.fingerprint.clone()) {
            continue;
        }
        recipient_wraps.push(wrap_fek_for_recipient(
            recipient,
            &file_key,
            &file_id,
            owner_user_id,
        )?);
    }
    if !recipient_wraps.is_empty() {
        emit(
            progress,
            "recipient_wrap",
            &format!(
                "Per-file key sealed to {} portable {} · X25519 + ML-KEM-1024 / HKDF-SHA3-256",
                recipient_wraps.len(),
                if recipient_wraps.len() == 1 { "identity" } else { "identities" },
            ),
            0,
            0,
            "info",
        );
    }

    let version = if recipient_wraps.is_empty() {
        STREAM_VERSION
    } else {
        STREAM_VERSION_RECIPIENT
    };

    // A sender attestation only means something on a container someone else will
    // open, so it rides along with the recipient wraps.
    let sender_identity = match sharing.and_then(|s| s.sender) {
        Some(identity) if version >= STREAM_VERSION_RECIPIENT => Some(SenderIdentity {
            x25519_public: identity.kem.x25519_public.clone(),
            mlkem_public: identity.kem.mlkem_public.clone(),
            // Placeholder signature; replaced below once the canonical bytes exist.
            attestation: portable_identity::SenderAttestation {
                identity_fingerprint: identity.fingerprint(),
                label: identity.label.clone().unwrap_or_default(),
                signature_algorithm: identity.signature_algorithm().to_string(),
                ed25519_public: identity.signer.ed25519_public.clone(),
                mldsa_public: identity.signer.mldsa87_public.clone(),
                ed25519_signature: Vec::new(),
                mldsa_signature: Vec::new(),
            },
        }),
        _ => None,
    };

    let mut header = StreamHeader {
        version,
        file_id: file_id.clone(),
        kind: kind.to_string(),
        name: name.to_string(),
        content_type: content_type.to_string(),
        original_size,
        chunk_size: CHUNK_SIZE as u32,
        total_chunks,
        owner_user_id: owner_user_id.to_string(),
        owner_device_id: owner_device_id.to_string(),
        hybrid_ciphertext,
        wrapped_key,
        recovery_wrapped_key,
        recovery_kem_wrap,
        fek_wrapped_by_vmk,
        suite: vault_suite(),
        signer_ed25519_public: vault_signer.ed25519_public.clone(),
        signer_mldsa_public: Vec::new(),
        signer_mldsa87_public: vault_signer.mldsa87_public.clone(),
        header_signature: DualSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
        header_signature_v3: None,
        recipient_wraps,
        sender_identity,
    };
    if let (Some(_), Some(identity)) = (
        header.sender_identity.as_ref(),
        sharing.and_then(|s| s.sender),
    ) {
        let attestation_bytes = attestation_signable(&header);
        if let Some(sender) = header.sender_identity.as_mut() {
            sender.attestation = portable_identity::attest(identity, &attestation_bytes)?;
        }
        emit(
            progress,
            "attest",
            "Sender attestation signed · Ed25519 + ML-DSA-87 portable identity",
            0,
            0,
            "info",
        );
    }
    // `header_signable` excludes every signature field, so it is computed last,
    // once the attestation's own bytes are final.
    let signable = header_signable(&header);
    header.header_signature_v3 = Some(dual_sign_87(
        &vault_signer.ed25519_secret,
        &vault_signer.mldsa87_secret,
        &signable,
    )?);
    emit(progress, "sign", "Header signed · Ed25519 + ML-DSA-87 (FIPS 204 L5)", 0, 0, "info");

    let header_json = serde_json::to_vec(&header)
        .map_err(|e| QGuardError::Crypto(format!("vault stream header encode failed: {e}")))?;
    if header_json.len() > MAX_HEADER_LEN {
        return Err(QGuardError::Crypto("vault stream header too large".to_string()));
    }
    writer.write_all(MAGIC).map_err(io_err)?;
    writer
        .write_all(&(header_json.len() as u32).to_be_bytes())
        .map_err(io_err)?;
    writer.write_all(&header_json).map_err(io_err)?;
    emit(progress, "header", "Signed header written · streaming encrypted chunks", 0, 0, "info");
    let emit_every = chunk_emit_every(total_chunks);

    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut index: u64 = 0;
    let mut streamed: u64 = 0;
    loop {
        let n = read_chunk(reader, &mut buf)?;
        if n == 0 {
            break;
        }
        if index >= total_chunks {
            file_key.zeroize();
            return Err(QGuardError::Crypto(
                "vault stream source grew past its declared size".to_string(),
            ));
        }
        let is_last = index + 1 == total_chunks;
        let aad = chunk_aad(&file_id, index, total_chunks, is_last);
        let env = symmetric::encrypt(&file_key, &buf[..n], &aad)?;
        write_chunk_frame(writer, &env)?;
        index += 1;
        streamed += n as u64;
        if index % emit_every == 0 || index == total_chunks {
            emit(progress, "chunk", "Encrypting chunk · AES-256-GCM (AAD-bound)", streamed, index, "info");
        }
    }
    buf.zeroize();
    file_key.zeroize();
    writer.flush().map_err(io_err)?;

    if index != total_chunks || streamed != original_size {
        return Err(QGuardError::Crypto(format!(
            "vault stream size mismatch: declared {original_size} bytes, read {streamed}"
        )));
    }

    emit(progress, "done", "Vault container sealed · integrity protected per chunk", streamed, total_chunks, "success");
    Ok(StreamSummary::from_header(&header))
}

/// Read, length-check, parse, and dual-verify the signed header before any use.
fn read_and_verify_header<R: Read>(reader: &mut R) -> Result<StreamHeader> {
    let mut magic = [0u8; 8];
    read_exact_buf(reader, &mut magic)?;
    if &magic != MAGIC {
        return Err(QGuardError::Crypto(
            "not a QGuard vault stream (bad magic header)".to_string(),
        ));
    }
    let mut len_buf = [0u8; 4];
    read_exact_buf(reader, &mut len_buf)?;
    let header_len = u32::from_be_bytes(len_buf) as usize;
    if header_len == 0 || header_len > MAX_HEADER_LEN {
        return Err(QGuardError::Crypto("vault stream header length invalid".to_string()));
    }
    let mut header_bytes = vec![0u8; header_len];
    read_exact_buf(reader, &mut header_bytes)?;
    let header: StreamHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| QGuardError::Crypto(format!("vault stream header decode failed: {e}")))?;
    if header.version == 0 || header.version > MAX_STREAM_VERSION {
        return Err(QGuardError::Crypto(format!(
            "unsupported vault stream version {} — update QGuard Messaging to open it",
            header.version
        )));
    }
    // Recipient wraps and sender attestations are only inside the signature's
    // reach from v4 on. Refuse them on an older version rather than reading
    // unauthenticated key material.
    if header.version < 4 && (!header.recipient_wraps.is_empty() || header.sender_identity.is_some())
    {
        return Err(QGuardError::Crypto(
            "vault container declares recipient material below version 4 — refusing to trust it"
                .to_string(),
        ));
    }
    if header.recipient_wraps.len() > MAX_RECIPIENTS {
        return Err(QGuardError::Crypto(
            "vault container declares an implausible number of recipients".to_string(),
        ));
    }

    // Authenticate the header (wrapped key(s) + metadata + total_chunks) before
    // use. v3 verifies with ML-DSA-87; v1/v2 with ML-DSA-65.
    let signable = header_signable(&header);
    if header.version >= 3 {
        let sig = header.header_signature_v3.as_ref().ok_or_else(|| {
            QGuardError::Crypto("v3 vault container is missing its ML-DSA-87 signature".to_string())
        })?;
        dual_verify_87(
            &header.signer_ed25519_public,
            &header.signer_mldsa87_public,
            &signable,
            sig,
        )?;
    } else {
        dual_verify(
            &header.signer_ed25519_public,
            &header.signer_mldsa_public,
            &signable,
            &header.header_signature,
        )?;
    }
    Ok(header)
}

/// Given the key unwrapped from a device / recovery / enterprise wrap — which is
/// the VMK on v3 containers and the FEK directly on v1/v2 — return the per-file
/// FEK used to decrypt the chunk stream.
fn resolve_file_key(header: &StreamHeader, unwrapped: [u8; KEY_SIZE]) -> Result<[u8; KEY_SIZE]> {
    if header.version < 3 {
        return Ok(unwrapped);
    }
    let mut vmk = unwrapped;
    let env = match header.fek_wrapped_by_vmk.as_ref() {
        Some(env) => env,
        None => {
            vmk.zeroize();
            return Err(QGuardError::Crypto(
                "v3 vault container is missing its VMK-wrapped file key".to_string(),
            ));
        }
    };
    let aad = fek_vmk_wrap_aad(&header.file_id, &header.owner_user_id);
    let unwrapped_fek = symmetric::decrypt(&vmk, env, &aad);
    vmk.zeroize();
    let mut bytes = unwrapped_fek?;
    if bytes.len() != KEY_SIZE {
        bytes.zeroize();
        return Err(QGuardError::Crypto("v3 vault unwrapped FEK is invalid".to_string()));
    }
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(key)
}

/// Verify the sender attestation, if this container carries one.
///
/// An attestation that fails to verify is a hard error, not a downgrade: the
/// container claims an author, so returning the plaintext while quietly dropping
/// an unverifiable claim would let a forged sender name reach the user.
fn verified_sender_for(header: &StreamHeader) -> Result<Option<VerifiedSender>> {
    let Some(sender) = header.sender_identity.as_ref() else {
        return Ok(None);
    };
    portable_identity::verify_attestation(
        &sender.attestation,
        &attestation_signable(header),
        &sender.x25519_public,
        &sender.mlkem_public,
    )?;
    Ok(Some(VerifiedSender {
        fingerprint: sender.attestation.identity_fingerprint.clone(),
        label: sender.attestation.label.clone(),
        signature_algorithm: sender.attestation.signature_algorithm.clone(),
    }))
}

/// How a container's key wrap is protected, and whether re-protecting it would
/// improve that.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerProtection {
    pub version: u8,
    pub name: String,
    pub kind: String,
    pub original_size: u64,
    /// True when this container still carries the older wrap and re-protecting
    /// it would move it behind the vault password.
    pub needs_reprotect: bool,
    /// Short, non-technical explanation of `needs_reprotect`, for the UI.
    pub reason: String,
}

/// Determine whether a container's key wrap is still reachable by a key the OS
/// keychain protects, rather than by the vault's password-wrapped keypair.
///
/// This reads and authenticates the **header only** — no chunk is touched — so it
/// costs one ML-KEM decapsulation regardless of whether the container is 4 KB or
/// 40 GB. That is what makes it usable as a background scan over a whole vault.
///
/// A container needs re-protecting when either:
///
/// * it predates the VMK envelope (v1/v2, where the per-file key is wrapped
///   straight to the device), or
/// * its wrap does not open with `vault_kem` — meaning it was sealed to the
///   messaging device identity key, whose secret the OS keychain alone guards.
///
/// Note this is about the *redundant* wrap, not about whether the file can be
/// opened: the VMK path opens every v3 container either way. What re-protecting
/// changes is whether someone holding the app data directory and keychain access
/// could get in without the vault password.
pub fn inspect_protection<R: Read>(
    reader: &mut R,
    vault_kem: Option<&LocalKemKeypair>,
) -> Result<ContainerProtection> {
    let header = read_and_verify_header(reader)?;
    let mut protection = ContainerProtection {
        version: header.version,
        name: header.name.clone(),
        kind: header.kind.clone(),
        original_size: header.original_size,
        needs_reprotect: true,
        reason: String::new(),
    };

    if header.version < STREAM_VERSION {
        protection.reason = format!(
            "Sealed in an older container format (v{}) — re-protect to move it behind your vault password.",
            header.version
        );
        return Ok(protection);
    }

    let Some(vault_kem) = vault_kem else {
        protection.reason =
            "This device has not created its vault key yet — unlock the vault, then re-protect."
                .to_string();
        return Ok(protection);
    };

    // Does the container's wrap actually open with the vault's own keypair? Only
    // the AEAD tag can answer that, so try the unwrap rather than guessing.
    let opens_with_vault_key = decapsulate(
        &vault_kem.x25519_secret,
        &vault_kem.mlkem_secret,
        &header.hybrid_ciphertext,
        &crate::security::obf::vault_stream_wrap_info(),
    )
    .ok()
    .and_then(|mut secret| {
        let wrap_aad =
            wrap_aad_bytes(&header.file_id, &header.owner_user_id, &header.owner_device_id);
        let opened = symmetric::decrypt(&secret, &header.wrapped_key, &wrap_aad);
        secret.zeroize();
        opened.ok()
    })
    .map(|mut bytes| {
        let valid = bytes.len() == KEY_SIZE;
        bytes.zeroize();
        valid
    })
    .unwrap_or(false);

    protection.needs_reprotect = !opens_with_vault_key;
    protection.reason = if opens_with_vault_key {
        "Sealed to this vault's key, which only your vault password unlocks.".to_string()
    } else {
        "Sealed to the older device key, which the OS keychain can reach without your vault password."
            .to_string()
    };
    Ok(protection)
}

/// Read + authenticate a container's header WITHOUT decrypting any content, so
/// the UI can show who a `.qvault` is sealed for and who sealed it before the
/// user commits to a destination folder.
///
/// This reveals nothing a holder of the file could not already parse: everything
/// returned is public header metadata whose integrity is proven by the header
/// signature.
pub fn inspect_stream<R: Read>(reader: &mut R) -> Result<StreamSummary> {
    let header = read_and_verify_header(reader)?;
    let mut summary = StreamSummary::from_header(&header);
    summary.verified_sender = verified_sender_for(&header)?;
    Ok(summary)
}

/// Decrypt and stream out every chunk once the per-file key has been recovered.
fn decrypt_chunks<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    header: &StreamHeader,
    file_key: &[u8; KEY_SIZE],
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let emit_every = chunk_emit_every(header.total_chunks);
    let mut processed: u64 = 0;
    for index in 0..header.total_chunks {
        let env = read_chunk_frame(reader)?;
        let is_last = index + 1 == header.total_chunks;
        let aad = chunk_aad(&header.file_id, index, header.total_chunks, is_last);
        let mut plain = symmetric::decrypt(file_key, &env, &aad)?;
        processed += plain.len() as u64;
        let write_result = writer.write_all(&plain).map_err(io_err);
        plain.zeroize();
        write_result?;
        let one = index + 1;
        if one % emit_every == 0 || is_last {
            progress(VaultProgress {
                op: "decrypt".into(),
                phase: "chunk".into(),
                message: "Decrypting chunk · AES-256-GCM · integrity verified".into(),
                processed_bytes: processed,
                total_bytes: header.original_size,
                chunk_index: one,
                total_chunks: header.total_chunks,
                level: "info".into(),
            });
        }
    }
    writer.flush().map_err(io_err)?;
    Ok(StreamSummary::from_header(header))
}

/// Stream-decrypt a container using the **Vault Master Key** directly.
///
/// This is the owner's primary path on v3+ containers and the strongest one: the
/// VMK is only available after the vault password/PIN has cryptographically
/// unlocked it, so opening a container this way genuinely requires the user's
/// secret. It also needs no KEM keypair at all, which makes it immune to device
/// key rotation.
///
/// v1/v2 containers have no VMK layer — their FEK is wrapped straight to the
/// device — so this reports that clearly and the caller falls back to the KEM
/// path.
pub fn decrypt_stream_with_vmk<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    vmk: &[u8; KEY_SIZE],
) -> Result<StreamSummary> {
    decrypt_stream_with_vmk_with_progress(reader, writer, vmk, &mut |_| {})
}

/// Same as [`decrypt_stream_with_vmk`] but reports real per-phase progress.
pub fn decrypt_stream_with_vmk_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    vmk: &[u8; KEY_SIZE],
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let header = read_and_verify_header(reader)?;
    if header.version < STREAM_VERSION {
        return Err(QGuardError::NotFound(
            "this container predates the Vault Master Key envelope; open it with the device key or a recovery key".to_string(),
        ));
    }
    progress(VaultProgress {
        op: "decrypt".into(),
        phase: "verify".into(),
        message: "Header verified · Ed25519 + ML-DSA-87 signature valid".into(),
        processed_bytes: 0,
        total_bytes: header.original_size,
        chunk_index: 0,
        total_chunks: header.total_chunks,
        level: "info".into(),
    });

    // `resolve_file_key` unwraps `fek_wrapped_by_vmk` with the VMK. Its AES-GCM
    // tag, over AAD binding file id + owner, is what proves this VMK belongs to
    // this container — a wrong VMK fails here rather than yielding garbage.
    let mut file_key = resolve_file_key(&header, *vmk)?;
    progress(VaultProgress {
        op: "decrypt".into(),
        phase: "unwrap_fek".into(),
        message: "Per-file key unwrapped from the Vault Master Key · streaming decrypt".into(),
        processed_bytes: 0,
        total_bytes: header.original_size,
        chunk_index: 0,
        total_chunks: header.total_chunks,
        level: "info".into(),
    });
    // Established before any plaintext is written — see `decrypt_stream_with_progress`.
    let verified_sender = match verified_sender_for(&header) {
        Ok(sender) => sender,
        Err(error) => {
            file_key.zeroize();
            return Err(error);
        }
    };
    let result = decrypt_chunks(reader, writer, &header, &file_key, progress);
    file_key.zeroize();
    let mut summary = result?;
    summary.verified_sender = verified_sender;
    progress(VaultProgress {
        op: "decrypt".into(),
        phase: "done".into(),
        message: "Vault container fully decrypted · integrity verified".into(),
        processed_bytes: header.original_size,
        total_bytes: header.original_size,
        chunk_index: header.total_chunks,
        total_chunks: header.total_chunks,
        level: "success".into(),
    });
    Ok(summary)
}

/// Stream-decrypt `reader` into `writer` using the recipient device's KEM secret.
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    recipient: &LocalKemKeypair,
) -> Result<StreamSummary> {
    decrypt_stream_with_progress(reader, writer, recipient, &mut |_| {})
}

/// Same as [`decrypt_stream`] but reports real per-phase / per-chunk progress.
pub fn decrypt_stream_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    recipient: &LocalKemKeypair,
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let header = read_and_verify_header(reader)?;
    let sig = if header.version >= 3 { "Ed25519 + ML-DSA-87" } else { "Ed25519 + ML-DSA-65" };
    progress(VaultProgress {
        op: "decrypt".into(),
        phase: "verify".into(),
        message: format!("Header verified · {sig} signature valid"),
        processed_bytes: 0,
        total_bytes: header.original_size,
        chunk_index: 0,
        total_chunks: header.total_chunks,
        level: "info".into(),
    });

    let mut wrapping_secret = decapsulate(
        &recipient.x25519_secret,
        &recipient.mlkem_secret,
        &header.hybrid_ciphertext,
        &crate::security::obf::vault_stream_wrap_info(),
    )?;
    progress(VaultProgress {
        op: "decrypt".into(),
        phase: "decapsulate".into(),
        message: "Vault Master Key recovered · X25519 + ML-KEM-1024".into(),
        processed_bytes: 0,
        total_bytes: header.original_size,
        chunk_index: 0,
        total_chunks: header.total_chunks,
        level: "info".into(),
    });
    let wrap_aad = wrap_aad_bytes(&header.file_id, &header.owner_user_id, &header.owner_device_id);
    let mut unwrapped_bytes = symmetric::decrypt(&wrapping_secret, &header.wrapped_key, &wrap_aad)?;
    wrapping_secret.zeroize();
    if unwrapped_bytes.len() != KEY_SIZE {
        unwrapped_bytes.zeroize();
        return Err(QGuardError::Crypto("vault stream unwrapped key is invalid".to_string()));
    }
    let mut unwrapped = [0u8; KEY_SIZE];
    unwrapped.copy_from_slice(&unwrapped_bytes);
    unwrapped_bytes.zeroize();

    // v3: `unwrapped` is the VMK -> unwrap the FEK from it. v1/v2: it is the FEK.
    let mut file_key = resolve_file_key(&header, unwrapped)?;
    unwrapped.zeroize();
    progress(VaultProgress {
        op: "decrypt".into(),
        phase: "unwrap_fek".into(),
        message: "Per-file key unwrapped · streaming decrypt".into(),
        processed_bytes: 0,
        total_bytes: header.original_size,
        chunk_index: 0,
        total_chunks: header.total_chunks,
        level: "info".into(),
    });
    // Verified BEFORE any plaintext is written, matching the recipient path: a
    // container that names an author it cannot prove must fail outright rather
    // than hand back real content beside an unverifiable claim.
    let verified_sender = match verified_sender_for(&header) {
        Ok(sender) => sender,
        Err(error) => {
            file_key.zeroize();
            return Err(error);
        }
    };
    let result = decrypt_chunks(reader, writer, &header, &file_key, progress);
    file_key.zeroize();
    let mut summary = result?;
    summary.verified_sender = verified_sender;
    progress(VaultProgress {
        op: "decrypt".into(),
        phase: "done".into(),
        message: "Vault container fully decrypted · integrity verified".into(),
        processed_bytes: header.original_size,
        total_bytes: header.original_size,
        chunk_index: header.total_chunks,
        total_chunks: header.total_chunks,
        level: "success".into(),
    });
    Ok(summary)
}

/// Stream-decrypt a container that was sealed to a Portable Hybrid Identity.
///
/// The identity's wrap yields the per-file FEK directly — the VMK path is never
/// touched, so opening a shared container gives the recipient this one file and
/// no other access to the sender's vault.
pub fn decrypt_stream_with_identity<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    identity: &portable_identity::PortableIdentity,
) -> Result<StreamSummary> {
    decrypt_stream_with_identity_with_progress(reader, writer, identity, &mut |_| {})
}

/// Same as [`decrypt_stream_with_identity`] but reports real per-phase progress.
pub fn decrypt_stream_with_identity_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    identity: &portable_identity::PortableIdentity,
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let header = read_and_verify_header(reader)?;
    let emit = |progress: &mut dyn FnMut(VaultProgress), phase: &str, message: String, level: &str| {
        progress(VaultProgress {
            op: "open".into(),
            phase: phase.into(),
            message,
            processed_bytes: 0,
            total_bytes: header.original_size,
            chunk_index: 0,
            total_chunks: header.total_chunks,
            level: level.into(),
        });
    };
    emit(
        progress,
        "verify",
        "Header verified · Ed25519 + ML-DSA-87 signature valid".to_string(),
        "info",
    );

    if header.recipient_wraps.is_empty() {
        return Err(QGuardError::Crypto(
            "this container is not sealed to any portable identity — decrypt it on the owner's device or with a recovery key".to_string(),
        ));
    }

    // A verified sender must be established BEFORE any plaintext is written, so
    // a forged attestation can never reach the user alongside real content.
    let verified_sender = verified_sender_for(&header)?;
    if let Some(sender) = verified_sender.as_ref() {
        emit(
            progress,
            "attest",
            format!(
                "Sender verified · {} · {}",
                portable_identity::short_fingerprint(&sender.fingerprint),
                sender.signature_algorithm,
            ),
            "info",
        );
    }

    let fingerprint = identity.fingerprint();
    let wrap = header
        .recipient_wraps
        .iter()
        .find(|wrap| wrap.recipient_fingerprint.eq_ignore_ascii_case(&fingerprint))
        .ok_or_else(|| {
            QGuardError::Crypto(format!(
                "this container is not sealed to the unlocked identity ({}). It is sealed to: {}",
                portable_identity::short_fingerprint(&fingerprint),
                header
                    .recipient_wraps
                    .iter()
                    .map(|w| portable_identity::short_fingerprint(&w.recipient_fingerprint))
                    .collect::<Vec<_>>()
                    .join(", "),
            ))
        })?;

    let mut file_key = unwrap_fek_for_recipient(
        identity,
        wrap,
        &header.file_id,
        &header.owner_user_id,
    )?;
    emit(
        progress,
        "unwrap_fek",
        format!(
            "Per-file key recovered for {} · {}",
            portable_identity::short_fingerprint(&fingerprint),
            wrap.algorithm,
        ),
        "info",
    );

    let mut relabel = |mut p: VaultProgress| {
        p.op = "open".into();
        progress(p);
    };
    let result = decrypt_chunks(reader, writer, &header, &file_key, &mut relabel);
    file_key.zeroize();
    let mut summary = result?;
    summary.verified_sender = verified_sender;
    emit(
        progress,
        "done",
        "Sealed container opened · every chunk authenticated".to_string(),
        "success",
    );
    Ok(summary)
}

/// Fully verify a container WITHOUT writing plaintext anywhere: decrypts every
/// chunk into an in-memory sink, checking the signed header (Ed25519 + ML-DSA),
/// the device KEM unwrap, each chunk's AES-256-GCM tag + AAD binding, and the
/// declared chunk count / size. Succeeds only if the whole container is intact.
pub fn verify_stream_with_progress<R: Read>(
    reader: &mut R,
    recipient: &LocalKemKeypair,
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let mut relabel = |mut p: VaultProgress| {
        p.op = "verify".into();
        if p.phase == "done" {
            p.message = "Integrity verified · signed header + every chunk authenticated".into();
        }
        progress(p);
    };
    decrypt_stream_with_progress(reader, &mut io::sink(), recipient, &mut relabel)
}

/// Same full verification as [`verify_stream_with_progress`], driven by the Vault
/// Master Key so it exercises the owner's primary open path.
pub fn verify_stream_with_vmk_with_progress<R: Read>(
    reader: &mut R,
    vmk: &[u8; KEY_SIZE],
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let mut relabel = |mut p: VaultProgress| {
        p.op = "verify".into();
        if p.phase == "done" {
            p.message = "Integrity verified · signed header + every chunk authenticated".into();
        }
        progress(p);
    };
    decrypt_stream_with_vmk_with_progress(reader, &mut io::sink(), vmk, &mut relabel)
}

/// Stream-decrypt `reader` into `writer` using the owner's quantum-safe recovery
/// key — no access to the original device is required. On v3 the recovery key
/// unwraps the VMK, which then unwraps the per-file FEK.
pub fn decrypt_stream_with_recovery<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    recovery_wrap_key: &[u8; KEY_SIZE],
) -> Result<StreamSummary> {
    decrypt_stream_with_recovery_with_progress(reader, writer, recovery_wrap_key, &mut |_| {})
}

/// Same as [`decrypt_stream_with_recovery`] but reports real progress.
pub fn decrypt_stream_with_recovery_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    recovery_wrap_key: &[u8; KEY_SIZE],
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let header = read_and_verify_header(reader)?;
    progress(VaultProgress {
        op: "decrypt".into(),
        phase: "verify".into(),
        message: "Header verified · recovery decrypt".into(),
        processed_bytes: 0,
        total_bytes: header.original_size,
        chunk_index: 0,
        total_chunks: header.total_chunks,
        level: "info".into(),
    });
    let recovery_env = header.recovery_wrapped_key.as_ref().ok_or_else(|| {
        QGuardError::NotFound(
            "this vault container was sealed without a recovery key; re-encrypt it with recovery enabled".to_string(),
        )
    })?;
    let mut unwrapped = vault_recovery::unwrap_file_key(
        recovery_wrap_key,
        recovery_env,
        &header.file_id,
        &header.owner_user_id,
    )?;
    let mut file_key = resolve_file_key(&header, unwrapped)?;
    unwrapped.zeroize();
    progress(VaultProgress {
        op: "decrypt".into(),
        phase: "unwrap_fek".into(),
        message: "VMK unwrapped via recovery key · ML-KEM-1024 / HKDF-SHA3-256".into(),
        processed_bytes: 0,
        total_bytes: header.original_size,
        chunk_index: 0,
        total_chunks: header.total_chunks,
        level: "info".into(),
    });
    let result = decrypt_chunks(reader, writer, &header, &file_key, progress);
    file_key.zeroize();
    let summary = result?;
    progress(VaultProgress {
        op: "decrypt".into(),
        phase: "done".into(),
        message: "Vault container recovered · integrity verified".into(),
        processed_bytes: header.original_size,
        total_bytes: header.original_size,
        chunk_index: header.total_chunks,
        total_chunks: header.total_chunks,
        level: "success".into(),
    });
    Ok(summary)
}

/// Stream-decrypt using the enterprise ML-KEM-1024 recovery key. For hybrid
/// containers, `recovery_secret` (the personal recovery root) is also required.
pub fn decrypt_stream_with_enterprise<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    recipient: &LocalKemKeypair,
    recovery_secret: Option<&[u8; KEY_SIZE]>,
) -> Result<StreamSummary> {
    decrypt_stream_with_enterprise_with_progress(reader, writer, recipient, recovery_secret, &mut |_| {})
}

/// Same as [`decrypt_stream_with_enterprise`] but reports real progress.
pub fn decrypt_stream_with_enterprise_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    recipient: &LocalKemKeypair,
    recovery_secret: Option<&[u8; KEY_SIZE]>,
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let header = read_and_verify_header(reader)?;
    progress(VaultProgress {
        op: "decrypt".into(),
        phase: "verify".into(),
        message: "Header verified · enterprise recovery decrypt".into(),
        processed_bytes: 0,
        total_bytes: header.original_size,
        chunk_index: 0,
        total_chunks: header.total_chunks,
        level: "info".into(),
    });
    let kem_wrap = header.recovery_kem_wrap.as_ref().ok_or_else(|| {
        QGuardError::NotFound(
            "this vault container was sealed without an enterprise recovery key".to_string(),
        )
    })?;
    let mut unwrapped = vault_recovery::unwrap_file_key_kem(
        recipient,
        recovery_secret,
        kem_wrap,
        &header.file_id,
        &header.owner_user_id,
    )?;
    let mut file_key = resolve_file_key(&header, unwrapped)?;
    unwrapped.zeroize();
    progress(VaultProgress {
        op: "decrypt".into(),
        phase: "unwrap_fek".into(),
        message: "VMK unwrapped via enterprise key · ML-KEM-1024".into(),
        processed_bytes: 0,
        total_bytes: header.original_size,
        chunk_index: 0,
        total_chunks: header.total_chunks,
        level: "info".into(),
    });
    let result = decrypt_chunks(reader, writer, &header, &file_key, progress);
    file_key.zeroize();
    let summary = result?;
    progress(VaultProgress {
        op: "decrypt".into(),
        phase: "done".into(),
        message: "Vault container recovered · integrity verified".into(),
        processed_bytes: header.original_size,
        total_bytes: header.original_size,
        chunk_index: header.total_chunks,
        total_chunks: header.total_chunks,
        level: "success".into(),
    });
    Ok(summary)
}

/// Re-protect an existing container by rebuilding it as a fresh v3 VMK-envelope
/// container, *without* re-encrypting the bulk data. The per-file FEK is recovered
/// from the existing container using a device key, then re-sealed under the VMK;
/// the VMK is wrapped to this device (and, when configured, the recovery key /
/// enterprise recipient) and the header is re-signed with ML-DSA-87. The encrypted
/// chunk frames — and the original `file_id` / `total_chunks` they are AAD-bound
/// to — are copied verbatim. Accepts v1/v2/v3 input; always emits v3.
#[allow(clippy::too_many_arguments)]
pub fn rewrap_stream_to_v3<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    recipient_kems: &[LocalKemKeypair],
    recipient_x25519_public: &[u8],
    recipient_mlkem_public: &[u8],
    vmk: &[u8; KEY_SIZE],
    vault_signer: &VaultSigningKeypair,
    recovery_wrap_key: Option<&[u8; KEY_SIZE]>,
    enterprise: Option<&EnterpriseRecipient>,
) -> Result<StreamSummary> {
    rewrap_stream_to_v3_with_progress(
        reader,
        writer,
        recipient_kems,
        recipient_x25519_public,
        recipient_mlkem_public,
        vmk,
        vault_signer,
        recovery_wrap_key,
        enterprise,
        &mut |_| {},
    )
}

/// Same as [`rewrap_stream_to_v3`] but reports real per-phase progress. The bulk
/// chunk frames are copied verbatim (header-only re-protection), so progress is
/// reported at phase boundaries rather than per chunk.
#[allow(clippy::too_many_arguments)]
pub fn rewrap_stream_to_v3_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    recipient_kems: &[LocalKemKeypair],
    recipient_x25519_public: &[u8],
    recipient_mlkem_public: &[u8],
    vmk: &[u8; KEY_SIZE],
    vault_signer: &VaultSigningKeypair,
    recovery_wrap_key: Option<&[u8; KEY_SIZE]>,
    enterprise: Option<&EnterpriseRecipient>,
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let header = read_and_verify_header(reader)?;
    let total = header.original_size;
    let total_chunks = header.total_chunks;
    let mut emit = |phase: &str, message: &str, processed: u64, level: &str| {
        progress(VaultProgress {
            op: "rewrap".into(),
            phase: phase.into(),
            message: message.into(),
            processed_bytes: processed,
            total_bytes: total,
            chunk_index: if processed >= total { total_chunks } else { 0 },
            total_chunks,
            level: level.into(),
        });
    };
    emit("verify", "Existing container verified · re-protecting to v3 envelope", 0, "info");

    // Recover the per-file FEK from the existing container (any version) using a
    // device key. `resolve_file_key` handles the v3 VMK indirection transparently.
    let wrap_aad = wrap_aad_bytes(&header.file_id, &header.owner_user_id, &header.owner_device_id);
    let mut file_key: Option<[u8; KEY_SIZE]> = None;
    for kem in recipient_kems {
        let mut secret = match decapsulate(
            &kem.x25519_secret,
            &kem.mlkem_secret,
            &header.hybrid_ciphertext,
            &crate::security::obf::vault_stream_wrap_info(),
        ) {
            Ok(secret) => secret,
            Err(_) => continue,
        };
        let decrypted = symmetric::decrypt(&secret, &header.wrapped_key, &wrap_aad);
        secret.zeroize();
        if let Ok(mut bytes) = decrypted {
            if bytes.len() == KEY_SIZE {
                let mut unwrapped = [0u8; KEY_SIZE];
                unwrapped.copy_from_slice(&bytes);
                bytes.zeroize();
                let resolved = resolve_file_key(&header, unwrapped);
                unwrapped.zeroize();
                if let Ok(fek) = resolved {
                    file_key = Some(fek);
                    break;
                }
            } else {
                bytes.zeroize();
            }
        }
    }
    let mut file_key = file_key.ok_or_else(|| {
        QGuardError::NotFound(
            "this device cannot unwrap the file key, so it cannot re-protect this container".to_string(),
        )
    })?;
    emit("unwrap_fek", "Per-file key recovered from existing container", 0, "info");

    // Re-seal as a v3 container around the SAME FEK + file_id (so the verbatim
    // chunk frames still authenticate). The VMK now protects the FEK.
    let fek_wrapped_by_vmk = Some(symmetric::encrypt(
        vmk,
        &file_key,
        &fek_vmk_wrap_aad(&header.file_id, &header.owner_user_id),
    )?);
    let (hybrid_ciphertext, mut wrapping_secret) = encapsulate(
        recipient_x25519_public,
        recipient_mlkem_public,
        &crate::security::obf::vault_stream_wrap_info(),
    )?;
    let wrapped_key = symmetric::encrypt(&wrapping_secret, vmk, &wrap_aad)?;
    wrapping_secret.zeroize();
    emit("vmk_wrap", "Re-sealed under new VMK · X25519 + ML-KEM-1024", 0, "info");
    let recovery_wrapped_key = match recovery_wrap_key {
        Some(key) => Some(vault_recovery::wrap_file_key(key, vmk, &header.file_id, &header.owner_user_id)?),
        None => None,
    };
    let recovery_kem_wrap = match enterprise {
        Some(ent) => Some(vault_recovery::wrap_file_key_kem(
            ent.x25519_public,
            ent.mlkem_public,
            ent.recovery_secret,
            vmk,
            &header.file_id,
            &header.owner_user_id,
        )?),
        None => None,
    };
    file_key.zeroize();

    // Re-protecting must never silently revoke a share. The recipient wraps seal
    // the SAME FEK under a KEM ciphertext of their own, and their AAD binds
    // file id + owner + recipient — none of which change here — so they are
    // carried across verbatim and stay openable. The sender attestation signs
    // `attestation_signable`, which deliberately excludes the VMK wraps being
    // rewritten, so it too survives unchanged.
    let carried_recipient_wraps = header.recipient_wraps.clone();
    let carried_sender_identity = header.sender_identity.clone();
    let new_version = if carried_recipient_wraps.is_empty() {
        STREAM_VERSION
    } else {
        STREAM_VERSION_RECIPIENT
    };

    let mut new_header = StreamHeader {
        version: new_version,
        file_id: header.file_id.clone(),
        kind: header.kind.clone(),
        name: header.name.clone(),
        content_type: header.content_type.clone(),
        original_size: header.original_size,
        chunk_size: header.chunk_size,
        total_chunks: header.total_chunks,
        owner_user_id: header.owner_user_id.clone(),
        owner_device_id: header.owner_device_id.clone(),
        hybrid_ciphertext,
        wrapped_key,
        recovery_wrapped_key,
        recovery_kem_wrap,
        fek_wrapped_by_vmk,
        suite: vault_suite(),
        signer_ed25519_public: vault_signer.ed25519_public.clone(),
        signer_mldsa_public: Vec::new(),
        signer_mldsa87_public: vault_signer.mldsa87_public.clone(),
        header_signature: DualSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
        header_signature_v3: None,
        recipient_wraps: carried_recipient_wraps,
        sender_identity: carried_sender_identity,
    };
    let signable = header_signable(&new_header);
    new_header.header_signature_v3 = Some(dual_sign_87(
        &vault_signer.ed25519_secret,
        &vault_signer.mldsa87_secret,
        &signable,
    )?);
    emit("sign", "New header signed · Ed25519 + ML-DSA-87 (FIPS 204 L5)", 0, "info");

    // Write the rebuilt header, then copy the unchanged chunk frames verbatim.
    let header_json = serde_json::to_vec(&new_header)
        .map_err(|e| QGuardError::Crypto(format!("vault stream header encode failed: {e}")))?;
    if header_json.len() > MAX_HEADER_LEN {
        return Err(QGuardError::Crypto("vault stream header too large".to_string()));
    }
    writer.write_all(MAGIC).map_err(io_err)?;
    writer
        .write_all(&(header_json.len() as u32).to_be_bytes())
        .map_err(io_err)?;
    writer.write_all(&header_json).map_err(io_err)?;
    io::copy(reader, writer).map_err(io_err)?;
    writer.flush().map_err(io_err)?;
    emit("done", "Container re-protected · v3 VMK envelope (ML-DSA-87)", total, "success");

    Ok(StreamSummary::from_header(&new_header))
}

// ---------------------------------------------------------------------------
// Folder archive framing: a folder is packed into one logical byte stream of
// `[u16 path_len][rel_path][u64 content_len][content]` entries, then fed through
// the same encrypt/decrypt stream. Paths therefore live inside the ciphertext.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct FolderEntry {
    pub rel_path: String,
    pub abs_path: PathBuf,
    pub size: u64,
}

fn entry_frame_len(rel_path: &str, size: u64) -> u64 {
    2 + rel_path.as_bytes().len() as u64 + 8 + size
}

/// Recursively collect regular files under `root` (sorted) plus the total framed size.
pub fn collect_folder_entries(root: &Path) -> Result<(Vec<FolderEntry>, u64)> {
    let mut entries = Vec::new();
    walk_dir(root, root, &mut entries)?;
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    let mut total = 0u64;
    for entry in &entries {
        if entry.rel_path.as_bytes().len() > u16::MAX as usize {
            return Err(QGuardError::InvalidInput(format!(
                "path too long to archive: {}",
                entry.rel_path
            )));
        }
        total = total.saturating_add(entry_frame_len(&entry.rel_path, entry.size));
    }
    Ok((entries, total))
}

fn walk_dir(root: &Path, dir: &Path, out: &mut Vec<FolderEntry>) -> Result<()> {
    let read_dir = std::fs::read_dir(dir).map_err(io_err)?;
    for entry in read_dir {
        let entry = entry.map_err(io_err)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(io_err)?;
        if file_type.is_dir() {
            walk_dir(root, &path, out)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| QGuardError::Storage("folder walk escaped its root".to_string()))?;
            let rel_path = rel
                .components()
                .filter_map(|c| match c {
                    Component::Normal(part) => Some(part.to_string_lossy().to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("/");
            if rel_path.is_empty() {
                continue;
            }
            let size = entry.metadata().map_err(io_err)?.len();
            out.push(FolderEntry {
                rel_path,
                abs_path: path,
                size,
            });
        }
        // symlinks and other types are intentionally skipped
    }
    Ok(())
}

/// `Read` adapter that lazily emits the framed folder archive.
pub struct FolderReader {
    entries: Vec<FolderEntry>,
    index: usize,
    header: Vec<u8>,
    header_pos: usize,
    file: Option<File>,
    file_remaining: u64,
}

impl FolderReader {
    pub fn new(entries: Vec<FolderEntry>) -> Self {
        Self {
            entries,
            index: 0,
            header: Vec::new(),
            header_pos: 0,
            file: None,
            file_remaining: 0,
        }
    }
}

impl Read for FolderReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.header_pos < self.header.len() {
                let n = std::cmp::min(out.len(), self.header.len() - self.header_pos);
                out[..n].copy_from_slice(&self.header[self.header_pos..self.header_pos + n]);
                self.header_pos += n;
                return Ok(n);
            }
            if let Some(file) = self.file.as_mut() {
                if self.file_remaining == 0 {
                    self.file = None;
                    self.index += 1;
                    continue;
                }
                let want = std::cmp::min(out.len() as u64, self.file_remaining) as usize;
                let n = file.read(&mut out[..want])?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "archived file shrank during encryption",
                    ));
                }
                self.file_remaining -= n as u64;
                return Ok(n);
            }
            if self.index >= self.entries.len() {
                return Ok(0);
            }
            let entry = &self.entries[self.index];
            let path_bytes = entry.rel_path.as_bytes();
            let mut header = Vec::with_capacity(2 + path_bytes.len() + 8);
            header.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
            header.extend_from_slice(path_bytes);
            header.extend_from_slice(&entry.size.to_be_bytes());
            self.header = header;
            self.header_pos = 0;
            self.file = Some(File::open(&entry.abs_path)?);
            self.file_remaining = entry.size;
        }
    }
}

#[derive(Clone, Copy)]
enum FolderWriteState {
    PathLen,
    Path,
    ContentLen,
    Content,
}

/// `Write` adapter that parses the framed archive and restores files under `dest`.
pub struct FolderWriter {
    dest: PathBuf,
    state: FolderWriteState,
    scratch: Vec<u8>,
    path_len: usize,
    rel_path: String,
    content_remaining: u64,
    file: Option<File>,
    pub files_written: u64,
}

impl FolderWriter {
    pub fn new(dest: PathBuf) -> Self {
        Self {
            dest,
            state: FolderWriteState::PathLen,
            scratch: Vec::new(),
            path_len: 0,
            rel_path: String::new(),
            content_remaining: 0,
            file: None,
            files_written: 0,
        }
    }

    fn safe_join(&self, rel_path: &str) -> io::Result<PathBuf> {
        let mut target = self.dest.clone();
        for part in rel_path.split('/') {
            if part.is_empty() || part == "." || part == ".." {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "archive contains an unsafe path",
                ));
            }
            target.push(part);
        }
        Ok(target)
    }

    fn begin_file(&mut self) -> io::Result<()> {
        let target = self.safe_join(&self.rel_path)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        self.file = Some(File::create(&target)?);
        Ok(())
    }
}

impl Write for FolderWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut offset = 0;
        while offset < buf.len() {
            match self.state {
                FolderWriteState::PathLen => {
                    while self.scratch.len() < 2 && offset < buf.len() {
                        self.scratch.push(buf[offset]);
                        offset += 1;
                    }
                    if self.scratch.len() == 2 {
                        self.path_len = u16::from_be_bytes([self.scratch[0], self.scratch[1]]) as usize;
                        self.scratch.clear();
                        self.state = FolderWriteState::Path;
                    }
                }
                FolderWriteState::Path => {
                    while self.scratch.len() < self.path_len && offset < buf.len() {
                        self.scratch.push(buf[offset]);
                        offset += 1;
                    }
                    if self.scratch.len() == self.path_len {
                        self.rel_path = String::from_utf8(self.scratch.clone()).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "archive path is not UTF-8")
                        })?;
                        self.scratch.clear();
                        self.state = FolderWriteState::ContentLen;
                    }
                }
                FolderWriteState::ContentLen => {
                    while self.scratch.len() < 8 && offset < buf.len() {
                        self.scratch.push(buf[offset]);
                        offset += 1;
                    }
                    if self.scratch.len() == 8 {
                        let mut len = [0u8; 8];
                        len.copy_from_slice(&self.scratch);
                        self.content_remaining = u64::from_be_bytes(len);
                        self.scratch.clear();
                        self.begin_file()?;
                        self.files_written += 1;
                        self.state = FolderWriteState::Content;
                        if self.content_remaining == 0 {
                            self.file = None;
                            self.state = FolderWriteState::PathLen;
                        }
                    }
                }
                FolderWriteState::Content => {
                    let available = buf.len() - offset;
                    let want = std::cmp::min(available as u64, self.content_remaining) as usize;
                    if let Some(file) = self.file.as_mut() {
                        file.write_all(&buf[offset..offset + want])?;
                    }
                    offset += want;
                    self.content_remaining -= want as u64;
                    if self.content_remaining == 0 {
                        self.file = None;
                        self.state = FolderWriteState::PathLen;
                    }
                }
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signatures::{dual_sign, LocalSigningKeypair};
    use std::io::Cursor;

    fn keypair() -> (LocalKemKeypair, VaultSigningKeypair) {
        (LocalKemKeypair::generate(), VaultSigningKeypair::generate())
    }

    fn encrypt_bytes(plaintext: &[u8], kem: &LocalKemKeypair, signer: &VaultSigningKeypair) -> Vec<u8> {
        encrypt_bytes_with_recovery(plaintext, kem, signer, None)
    }

    fn encrypt_bytes_with_recovery(
        plaintext: &[u8],
        kem: &LocalKemKeypair,
        signer: &VaultSigningKeypair,
        recovery_wrap_key: Option<&[u8; KEY_SIZE]>,
    ) -> Vec<u8> {
        let vmk = symmetric::random_key();
        let mut out = Vec::new();
        encrypt_stream(
            &mut Cursor::new(plaintext.to_vec()),
            &mut out,
            KIND_FILE,
            "secret.bin",
            "application/octet-stream",
            plaintext.len() as u64,
            "user-1",
            "device-1",
            &kem.x25519_public,
            &kem.mlkem_public,
            &vmk,
            signer,
            recovery_wrap_key,
            None,
        )
        .unwrap();
        out
    }

    /// Build a legacy v2 container by hand (FEK wrapped directly to the device,
    /// ML-DSA-65 signature) to prove the v1/v2 decrypt paths still work after the
    /// v3 upgrade.
    fn build_v2_container(
        plaintext: &[u8],
        kem: &LocalKemKeypair,
        signer: &LocalSigningKeypair,
        recovery_wrap_key: Option<&[u8; KEY_SIZE]>,
    ) -> Vec<u8> {
        let file_id = Uuid::new_v4().to_string();
        let owner_user_id = "user-1";
        let owner_device_id = "device-1";
        let total_chunks = total_chunks_for(plaintext.len() as u64);
        let mut file_key = symmetric::random_key();
        let (hybrid_ciphertext, mut wrapping_secret) = encapsulate(
            &kem.x25519_public,
            &kem.mlkem_public,
            &crate::security::obf::vault_stream_wrap_info(),
        )
        .unwrap();
        let wrap_aad = wrap_aad_bytes(&file_id, owner_user_id, owner_device_id);
        let wrapped_key = symmetric::encrypt(&wrapping_secret, &file_key, &wrap_aad).unwrap();
        wrapping_secret.zeroize();
        let recovery_wrapped_key = recovery_wrap_key
            .map(|k| vault_recovery::wrap_file_key(k, &file_key, &file_id, owner_user_id).unwrap());

        let mut header = StreamHeader {
            version: 2,
            file_id: file_id.clone(),
            kind: KIND_FILE.to_string(),
            name: "legacy.bin".to_string(),
            content_type: "application/octet-stream".to_string(),
            original_size: plaintext.len() as u64,
            chunk_size: CHUNK_SIZE as u32,
            total_chunks,
            owner_user_id: owner_user_id.to_string(),
            owner_device_id: owner_device_id.to_string(),
            hybrid_ciphertext,
            wrapped_key,
            recovery_wrapped_key,
            recovery_kem_wrap: None,
            fek_wrapped_by_vmk: None,
            suite: AlgorithmSuite::default(),
            signer_ed25519_public: signer.ed25519_public.clone(),
            signer_mldsa_public: signer.mldsa_public.clone(),
            signer_mldsa87_public: Vec::new(),
            header_signature: DualSignature { ed25519: Vec::new(), ml_dsa_65: Vec::new() },
            header_signature_v3: None,
            // A legacy v2 container carries no recipient material: the v4-only
            // fields stay empty, which is exactly what `read_and_verify_header`
            // requires of any container below version 4.
            recipient_wraps: Vec::new(),
            sender_identity: None,
        };
        let signable = header_signable(&header);
        header.header_signature =
            dual_sign(&signer.ed25519_secret, &signer.mldsa_secret, &signable).unwrap();

        let header_json = serde_json::to_vec(&header).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(header_json.len() as u32).to_be_bytes());
        out.extend_from_slice(&header_json);
        let mut index = 0u64;
        for chunk in plaintext.chunks(CHUNK_SIZE) {
            let is_last = index + 1 == total_chunks;
            let aad = chunk_aad(&file_id, index, total_chunks, is_last);
            let env = symmetric::encrypt(&file_key, chunk, &aad).unwrap();
            write_chunk_frame(&mut out, &env).unwrap();
            index += 1;
        }
        file_key.zeroize();
        out
    }

    #[test]
    fn recovery_key_decrypts_without_device() {
        let (kem, signer) = keypair();
        let root = vault_recovery::generate_recovery_root();
        let recovery_wrap_key = vault_recovery::derive_wrap_key(&root).unwrap();
        let plaintext = vec![42u8; CHUNK_SIZE + 77];
        let sealed = encrypt_bytes_with_recovery(&plaintext, &kem, &signer, Some(&recovery_wrap_key));

        // Recovery key alone (no device KEM) restores the data.
        let mut restored = Vec::new();
        decrypt_stream_with_recovery(&mut Cursor::new(sealed.clone()), &mut restored, &recovery_wrap_key).unwrap();
        assert_eq!(restored, plaintext);

        // The device key still works on the same container.
        let mut via_device = Vec::new();
        decrypt_stream(&mut Cursor::new(sealed.clone()), &mut via_device, &kem).unwrap();
        assert_eq!(via_device, plaintext);

        // A different recovery key cannot decrypt.
        let wrong = vault_recovery::derive_wrap_key(&vault_recovery::generate_recovery_root()).unwrap();
        let mut fail = Vec::new();
        assert!(decrypt_stream_with_recovery(&mut Cursor::new(sealed), &mut fail, &wrong).is_err());
    }

    #[test]
    fn recovery_decrypt_requires_a_recovery_wrap() {
        let (kem, signer) = keypair();
        // Sealed without recovery -> recovery decrypt must fail cleanly.
        let sealed = encrypt_bytes(b"no recovery wrap here", &kem, &signer);
        let any_key = vault_recovery::derive_wrap_key(&vault_recovery::generate_recovery_root()).unwrap();
        let mut out = Vec::new();
        assert!(decrypt_stream_with_recovery(&mut Cursor::new(sealed), &mut out, &any_key).is_err());
    }

    #[test]
    fn v3_envelope_uses_vmk_and_mldsa87() {
        let (kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let plaintext = vec![1u8; CHUNK_SIZE + 5];
        let mut sealed = Vec::new();
        encrypt_stream(
            &mut Cursor::new(plaintext.clone()), &mut sealed, KIND_FILE, "v3.bin",
            "application/octet-stream", plaintext.len() as u64, "user-1", "device-1",
            &kem.x25519_public, &kem.mlkem_public, &vmk, &signer, None, None,
        )
        .unwrap();

        let header = read_and_verify_header(&mut Cursor::new(sealed.clone())).unwrap();
        // Envelope: FEK is wrapped by the VMK (not by ML-KEM); signature is ML-DSA-87.
        assert_eq!(header.version, 3);
        assert_eq!(header.suite.pq_signature, "ML-DSA-87");
        assert!(header.fek_wrapped_by_vmk.is_some());
        assert!(header.header_signature_v3.is_some());
        assert!(!header.signer_mldsa87_public.is_empty());
        assert!(header.signer_mldsa_public.is_empty());

        // The device wrap unwraps to the VMK itself (proving ML-KEM protects the
        // key, never the file content): decapsulate -> AES-unwrap == vmk.
        let mut secret = decapsulate(
            &kem.x25519_secret, &kem.mlkem_secret, &header.hybrid_ciphertext,
            &crate::security::obf::vault_stream_wrap_info(),
        )
        .unwrap();
        let wrap_aad = wrap_aad_bytes(&header.file_id, &header.owner_user_id, &header.owner_device_id);
        let unwrapped = symmetric::decrypt(&secret, &header.wrapped_key, &wrap_aad).unwrap();
        secret.zeroize();
        assert_eq!(unwrapped.as_slice(), vmk.as_slice());

        let mut restored = Vec::new();
        decrypt_stream(&mut Cursor::new(sealed), &mut restored, &kem).unwrap();
        assert_eq!(restored, plaintext);
    }

    /// A container sealed to the vault's own keypair reports itself protected;
    /// one sealed to any other device key reports that it needs re-protecting.
    ///
    /// This is what lets the app *know* which containers still carry the older
    /// keychain-reachable wrap, instead of asking the user to remember which
    /// files predate the change.
    #[test]
    fn protection_scan_distinguishes_current_containers_from_stale_ones() {
        let (vault_kem, signer) = keypair();
        let old_device_kem = LocalKemKeypair::generate();
        let vmk = symmetric::random_key();
        let plaintext = b"payload".to_vec();

        let seal = |wrap_to: &LocalKemKeypair| {
            let mut out = Vec::new();
            encrypt_stream(
                &mut Cursor::new(plaintext.clone()), &mut out, KIND_FILE, "doc.bin",
                "application/octet-stream", plaintext.len() as u64, "user-1", "device-1",
                &wrap_to.x25519_public, &wrap_to.mlkem_public, &vmk, &signer, None, None,
            )
            .unwrap();
            out
        };

        let current = seal(&vault_kem);
        let status = inspect_protection(&mut Cursor::new(current), Some(&vault_kem)).unwrap();
        assert!(!status.needs_reprotect, "{}", status.reason);
        assert_eq!(status.name, "doc.bin");

        let stale = seal(&old_device_kem);
        let status = inspect_protection(&mut Cursor::new(stale), Some(&vault_kem)).unwrap();
        assert!(status.needs_reprotect, "{}", status.reason);

        // A v2 container predates the VMK envelope entirely.
        let v2_signer = LocalSigningKeypair::generate();
        let legacy = build_v2_container(&plaintext, &vault_kem, &v2_signer, None);
        let status = inspect_protection(&mut Cursor::new(legacy), Some(&vault_kem)).unwrap();
        assert!(status.needs_reprotect);
        assert_eq!(status.version, 2);

        // With no vault keypair yet, nothing can be called current.
        let current = seal(&vault_kem);
        let status = inspect_protection(&mut Cursor::new(current), None).unwrap();
        assert!(status.needs_reprotect);
    }

    /// Scanning must not read chunk data — that is what keeps it usable across a
    /// vault full of multi-gigabyte containers.
    #[test]
    fn protection_scan_reads_only_the_header() {
        let (vault_kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let plaintext = vec![3u8; CHUNK_SIZE * 2 + 11];
        let mut sealed = Vec::new();
        encrypt_stream(
            &mut Cursor::new(plaintext.clone()), &mut sealed, KIND_FILE, "big.bin",
            "application/octet-stream", plaintext.len() as u64, "user-1", "device-1",
            &vault_kem.x25519_public, &vault_kem.mlkem_public, &vmk, &signer, None, None,
        )
        .unwrap();

        let mut cursor = Cursor::new(sealed.clone());
        inspect_protection(&mut cursor, Some(&vault_kem)).unwrap();
        let consumed = cursor.position() as usize;
        assert!(
            consumed < sealed.len() / 4,
            "inspection read {consumed} of {} bytes — it must stop after the header",
            sealed.len()
        );
    }

    /// After re-protecting, the container must report itself current — otherwise
    /// the UI would keep offering an action that never resolves.
    #[test]
    fn reprotecting_clears_the_stale_flag() {
        let (vault_kem, signer) = keypair();
        let old_device_kem = LocalKemKeypair::generate();
        let vmk = symmetric::random_key();
        let plaintext = vec![9u8; CHUNK_SIZE + 3];

        let mut stale = Vec::new();
        encrypt_stream(
            &mut Cursor::new(plaintext.clone()), &mut stale, KIND_FILE, "doc.bin",
            "application/octet-stream", plaintext.len() as u64, "user-1", "device-1",
            &old_device_kem.x25519_public, &old_device_kem.mlkem_public, &vmk, &signer, None, None,
        )
        .unwrap();
        assert!(
            inspect_protection(&mut Cursor::new(stale.clone()), Some(&vault_kem))
                .unwrap()
                .needs_reprotect
        );

        let new_vmk = symmetric::random_key();
        let mut reprotected = Vec::new();
        rewrap_stream_to_v3(
            &mut Cursor::new(stale),
            &mut reprotected,
            &[old_device_kem.clone(), vault_kem.clone()],
            &vault_kem.x25519_public,
            &vault_kem.mlkem_public,
            &new_vmk,
            &signer,
            None,
            None,
        )
        .unwrap();

        let status =
            inspect_protection(&mut Cursor::new(reprotected.clone()), Some(&vault_kem)).unwrap();
        assert!(!status.needs_reprotect, "{}", status.reason);

        // And the content survived the rewrite untouched.
        let mut restored = Vec::new();
        decrypt_stream_with_vmk(&mut Cursor::new(reprotected), &mut restored, &new_vmk).unwrap();
        assert_eq!(restored, plaintext);
    }

    /// The Vault Master Key alone opens a v3 container — no KEM keypair needed.
    ///
    /// This is what makes the vault password a real cryptographic gate: the VMK
    /// exists in memory only because the user's password/PIN decrypted it.
    #[test]
    fn vault_master_key_alone_opens_a_v3_container() {
        let (kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let plaintext = vec![7u8; CHUNK_SIZE + 128];
        let mut sealed = Vec::new();
        encrypt_stream(
            &mut Cursor::new(plaintext.clone()), &mut sealed, KIND_FILE, "vmk.bin",
            "application/octet-stream", plaintext.len() as u64, "user-1", "device-1",
            &kem.x25519_public, &kem.mlkem_public, &vmk, &signer, None, None,
        )
        .unwrap();

        let mut restored = Vec::new();
        decrypt_stream_with_vmk(&mut Cursor::new(sealed.clone()), &mut restored, &vmk).unwrap();
        assert_eq!(restored, plaintext);

        // A different VMK must fail on the AEAD tag of the FEK wrap, not produce
        // garbage plaintext.
        let mut fail = Vec::new();
        assert!(
            decrypt_stream_with_vmk(&mut Cursor::new(sealed), &mut fail, &symmetric::random_key())
                .is_err()
        );
    }

    /// A container wrapped to the vault's own keypair must NOT be openable with
    /// some other device keypair — which is the whole point of moving the wrap
    /// off the OS-keychain-protected messaging identity key.
    #[test]
    fn a_container_wrapped_to_the_vault_keypair_rejects_other_device_keys() {
        let (vault_kem, signer) = keypair();
        let device_identity_kem = LocalKemKeypair::generate();
        let vmk = symmetric::random_key();
        let plaintext = b"only the vault keypair or the VMK opens this".to_vec();
        let mut sealed = Vec::new();
        encrypt_stream(
            &mut Cursor::new(plaintext.clone()), &mut sealed, KIND_FILE, "scoped.bin",
            "application/octet-stream", plaintext.len() as u64, "user-1", "device-1",
            &vault_kem.x25519_public, &vault_kem.mlkem_public, &vmk, &signer, None, None,
        )
        .unwrap();

        let mut out = Vec::new();
        assert!(
            decrypt_stream(&mut Cursor::new(sealed.clone()), &mut out, &device_identity_kem)
                .is_err(),
            "the messaging device identity key must not unwrap a vault-keypair container"
        );

        let mut via_vault_kem = Vec::new();
        decrypt_stream(&mut Cursor::new(sealed.clone()), &mut via_vault_kem, &vault_kem).unwrap();
        assert_eq!(via_vault_kem, plaintext);

        let mut via_vmk = Vec::new();
        decrypt_stream_with_vmk(&mut Cursor::new(sealed), &mut via_vmk, &vmk).unwrap();
        assert_eq!(via_vmk, plaintext);
    }

    /// v1/v2 containers have no VMK layer, so the VMK path must say so plainly
    /// rather than failing with a confusing crypto error.
    #[test]
    fn vmk_path_reports_clearly_on_a_pre_v3_container() {
        let (kem, _signer) = keypair();
        let v2_signer = LocalSigningKeypair::generate();
        let legacy = build_v2_container(b"old container", &kem, &v2_signer, None);
        let mut out = Vec::new();
        let error = decrypt_stream_with_vmk(
            &mut Cursor::new(legacy),
            &mut out,
            &symmetric::random_key(),
        )
        .unwrap_err();
        assert!(
            format!("{error}").contains("predates the Vault Master Key envelope"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn legacy_v2_container_still_decrypts() {
        let (kem, _signer) = keypair();
        let v2_signer = LocalSigningKeypair::generate();
        let root = vault_recovery::generate_recovery_root();
        let recovery_wrap_key = vault_recovery::derive_wrap_key(&root).unwrap();
        let plaintext = vec![8u8; CHUNK_SIZE + 17];
        let legacy = build_v2_container(&plaintext, &kem, &v2_signer, Some(&recovery_wrap_key));

        // The v2 container reports version 2 and verifies with its ML-DSA-65 sig.
        let header = read_and_verify_header(&mut Cursor::new(legacy.clone())).unwrap();
        assert_eq!(header.version, 2);
        assert!(header.fek_wrapped_by_vmk.is_none());

        // Both the device key and the recovery key still decrypt it.
        let mut via_device = Vec::new();
        decrypt_stream(&mut Cursor::new(legacy.clone()), &mut via_device, &kem).unwrap();
        assert_eq!(via_device, plaintext);
        let mut via_recovery = Vec::new();
        decrypt_stream_with_recovery(&mut Cursor::new(legacy), &mut via_recovery, &recovery_wrap_key).unwrap();
        assert_eq!(via_recovery, plaintext);
    }

    #[test]
    fn enterprise_and_hybrid_recovery_round_trip() {
        let (kem, signer) = keypair();
        let enterprise = vault_recovery::generate_enterprise_keypair();
        let plaintext = vec![9u8; CHUNK_SIZE + 33];
        let vmk = symmetric::random_key();

        // Enterprise-only.
        let mut out = Vec::new();
        encrypt_stream(
            &mut Cursor::new(plaintext.clone()), &mut out, KIND_FILE, "e.bin",
            "application/octet-stream", plaintext.len() as u64, "user-1", "device-1",
            &kem.x25519_public, &kem.mlkem_public, &vmk, &signer, None,
            Some(&EnterpriseRecipient {
                x25519_public: &enterprise.x25519_public,
                mlkem_public: &enterprise.mlkem_public,
                recovery_secret: None,
            }),
        ).unwrap();
        let mut via_ent = Vec::new();
        decrypt_stream_with_enterprise(&mut Cursor::new(out.clone()), &mut via_ent, &enterprise, None).unwrap();
        assert_eq!(via_ent, plaintext);
        let mut via_dev = Vec::new();
        decrypt_stream(&mut Cursor::new(out), &mut via_dev, &kem).unwrap();
        assert_eq!(via_dev, plaintext);

        // Hybrid requires BOTH the enterprise key and the recovery root.
        let root = vault_recovery::generate_recovery_root();
        let mut hout = Vec::new();
        encrypt_stream(
            &mut Cursor::new(plaintext.clone()), &mut hout, KIND_FILE, "h.bin",
            "application/octet-stream", plaintext.len() as u64, "user-1", "device-1",
            &kem.x25519_public, &kem.mlkem_public, &vmk, &signer, None,
            Some(&EnterpriseRecipient {
                x25519_public: &enterprise.x25519_public,
                mlkem_public: &enterprise.mlkem_public,
                recovery_secret: Some(&root),
            }),
        ).unwrap();
        let mut hok = Vec::new();
        decrypt_stream_with_enterprise(&mut Cursor::new(hout.clone()), &mut hok, &enterprise, Some(&root)).unwrap();
        assert_eq!(hok, plaintext);
        let mut hfail = Vec::new();
        assert!(decrypt_stream_with_enterprise(&mut Cursor::new(hout), &mut hfail, &enterprise, None).is_err());
    }

    #[test]
    fn rewrap_to_v3_adds_recovery_to_an_existing_container() {
        let (kem, signer) = keypair();
        // A pre-existing v3 container sealed WITHOUT recovery.
        let plaintext = vec![5u8; CHUNK_SIZE + 21];
        let original = encrypt_bytes(&plaintext, &kem, &signer);
        let root = vault_recovery::generate_recovery_root();
        let recovery_wrap_key = vault_recovery::derive_wrap_key(&root).unwrap();

        // Cannot be recovered before re-wrapping.
        let mut fail = Vec::new();
        assert!(decrypt_stream_with_recovery(&mut Cursor::new(original.clone()), &mut fail, &recovery_wrap_key).is_err());

        // Re-protect it (header-only) using the device key, adding the recovery wrap.
        let vmk = symmetric::random_key();
        let mut rewrapped = Vec::new();
        rewrap_stream_to_v3(
            &mut Cursor::new(original),
            &mut rewrapped,
            std::slice::from_ref(&kem),
            &kem.x25519_public,
            &kem.mlkem_public,
            &vmk,
            &signer,
            Some(&recovery_wrap_key),
            None,
        )
        .unwrap();

        // Now BOTH the recovery key and the original device key decrypt it.
        let mut via_recovery = Vec::new();
        decrypt_stream_with_recovery(&mut Cursor::new(rewrapped.clone()), &mut via_recovery, &recovery_wrap_key).unwrap();
        assert_eq!(via_recovery, plaintext);
        let mut via_device = Vec::new();
        decrypt_stream(&mut Cursor::new(rewrapped), &mut via_device, &kem).unwrap();
        assert_eq!(via_device, plaintext);
    }

    #[test]
    fn rewrap_upgrades_a_legacy_v2_container_to_v3() {
        let (kem, vault_signer) = keypair();
        let v2_signer = LocalSigningKeypair::generate();
        let plaintext = vec![6u8; CHUNK_SIZE + 9];
        let legacy = build_v2_container(&plaintext, &kem, &v2_signer, None);

        let vmk = symmetric::random_key();
        let mut upgraded = Vec::new();
        rewrap_stream_to_v3(
            &mut Cursor::new(legacy),
            &mut upgraded,
            std::slice::from_ref(&kem),
            &kem.x25519_public,
            &kem.mlkem_public,
            &vmk,
            &vault_signer,
            None,
            None,
        )
        .unwrap();

        // The upgraded container is v3 and still decrypts with the device key.
        let header = read_and_verify_header(&mut Cursor::new(upgraded.clone())).unwrap();
        assert_eq!(header.version, 3);
        assert_eq!(header.suite.pq_signature, "ML-DSA-87");
        assert!(header.fek_wrapped_by_vmk.is_some());
        let mut restored = Vec::new();
        decrypt_stream(&mut Cursor::new(upgraded), &mut restored, &kem).unwrap();
        assert_eq!(restored, plaintext);
    }

    #[test]
    fn rewrap_requires_a_usable_device_key() {
        let (kem, signer) = keypair();
        let original = encrypt_bytes(b"locked to a device we don't have", &kem, &signer);
        let attacker = LocalKemKeypair::generate();
        let vmk = symmetric::random_key();
        let mut out = Vec::new();
        assert!(rewrap_stream_to_v3(
            &mut Cursor::new(original),
            &mut out,
            std::slice::from_ref(&attacker),
            &attacker.x25519_public,
            &attacker.mlkem_public,
            &vmk,
            &signer,
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn roundtrip_across_chunk_boundaries() {
        let (kem, signer) = keypair();
        for size in [0usize, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, CHUNK_SIZE * 2 + 123] {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let sealed = encrypt_bytes(&plaintext, &kem, &signer);
            let mut restored = Vec::new();
            let summary = decrypt_stream(&mut Cursor::new(sealed), &mut restored, &kem).unwrap();
            assert_eq!(restored, plaintext, "roundtrip failed for size {size}");
            assert_eq!(summary.original_size, size as u64);
            assert_eq!(summary.total_chunks, total_chunks_for(size as u64));
        }
    }

    #[test]
    fn tampered_chunk_is_rejected() {
        let (kem, signer) = keypair();
        let plaintext = vec![7u8; CHUNK_SIZE + 10];
        let mut sealed = encrypt_bytes(&plaintext, &kem, &signer);
        // Flip a byte well past the header, inside a chunk frame.
        let last = sealed.len() - 1;
        sealed[last] ^= 0x80;
        let mut restored = Vec::new();
        assert!(decrypt_stream(&mut Cursor::new(sealed), &mut restored, &kem).is_err());
    }

    #[test]
    fn truncated_stream_is_rejected() {
        let (kem, signer) = keypair();
        let plaintext = vec![3u8; CHUNK_SIZE * 2];
        let sealed = encrypt_bytes(&plaintext, &kem, &signer);
        let truncated = sealed[..sealed.len() - 100].to_vec();
        let mut restored = Vec::new();
        assert!(decrypt_stream(&mut Cursor::new(truncated), &mut restored, &kem).is_err());
    }

    #[test]
    fn wrong_device_key_cannot_decrypt() {
        let (kem, signer) = keypair();
        let attacker = LocalKemKeypair::generate();
        let sealed = encrypt_bytes(b"top secret", &kem, &signer);
        let mut restored = Vec::new();
        assert!(decrypt_stream(&mut Cursor::new(sealed), &mut restored, &attacker).is_err());
    }

    #[test]
    fn folder_archive_roundtrip() {
        let (kem, signer) = keypair();
        let root = std::env::temp_dir().join(format!("qvault-folder-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("a.txt"), b"alpha").unwrap();
        std::fs::write(root.join("nested/b.bin"), vec![9u8; CHUNK_SIZE + 5]).unwrap();
        std::fs::write(root.join("empty.dat"), b"").unwrap();

        let (entries, total) = collect_folder_entries(&root).unwrap();
        assert_eq!(entries.len(), 3);
        let vmk = symmetric::random_key();
        let mut sealed = Vec::new();
        encrypt_stream(
            &mut FolderReader::new(entries),
            &mut sealed,
            KIND_FOLDER,
            "vault-folder",
            "application/qguard-folder-archive",
            total,
            "user-1",
            "device-1",
            &kem.x25519_public,
            &kem.mlkem_public,
            &vmk,
            &signer,
            None,
            None,
        )
        .unwrap();

        let dest = std::env::temp_dir().join(format!("qvault-out-{}", Uuid::new_v4()));
        let mut writer = FolderWriter::new(dest.clone());
        decrypt_stream(&mut Cursor::new(sealed), &mut writer, &kem).unwrap();
        writer.flush().unwrap();

        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(std::fs::read(dest.join("nested/b.bin")).unwrap(), vec![9u8; CHUNK_SIZE + 5]);
        assert_eq!(std::fs::read(dest.join("empty.dat")).unwrap(), b"");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn folder_writer_rejects_path_traversal() {
        let dest = std::env::temp_dir().join(format!("qvault-trav-{}", Uuid::new_v4()));
        let mut writer = FolderWriter::new(dest.clone());
        // Frame: path "../escape" then 1 byte content.
        let evil = "../escape";
        let mut framed = Vec::new();
        framed.extend_from_slice(&(evil.len() as u16).to_be_bytes());
        framed.extend_from_slice(evil.as_bytes());
        framed.extend_from_slice(&1u64.to_be_bytes());
        framed.push(0);
        assert!(writer.write_all(&framed).is_err());
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn encrypt_stream_emits_monotonic_progress() {
        let (kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let plaintext = vec![4u8; CHUNK_SIZE * 3 + 11];
        let mut out = Vec::new();
        let mut seen: Vec<VaultProgress> = Vec::new();
        encrypt_stream_with_progress(
            &mut Cursor::new(plaintext.clone()), &mut out, KIND_FILE, "p.bin",
            "application/octet-stream", plaintext.len() as u64, "user-1", "device-1",
            &kem.x25519_public, &kem.mlkem_public, &vmk, &signer, None, None, None,
            &mut |p| seen.push(p),
        )
        .unwrap();

        // Phases appear in order and include the crypto milestones.
        let phases: Vec<&str> = seen.iter().map(|p| p.phase.as_str()).collect();
        assert_eq!(phases.first(), Some(&"init"));
        assert!(phases.contains(&"fek"));
        assert!(phases.contains(&"vmk_wrap"));
        assert!(phases.contains(&"sign"));
        assert!(phases.contains(&"chunk"));
        assert_eq!(phases.last(), Some(&"done"));

        // processed_bytes is non-decreasing and ends exactly at the input size.
        let mut last = 0u64;
        for p in &seen {
            assert!(p.processed_bytes >= last, "processed regressed");
            assert_eq!(p.total_bytes, plaintext.len() as u64);
            last = p.processed_bytes;
        }
        let done = seen.last().unwrap();
        assert_eq!(done.processed_bytes, plaintext.len() as u64);
        assert_eq!(done.total_chunks, total_chunks_for(plaintext.len() as u64));

        // The container still round-trips (no behavior change).
        let mut restored = Vec::new();
        decrypt_stream(&mut Cursor::new(out), &mut restored, &kem).unwrap();
        assert_eq!(restored, plaintext);
    }

    #[test]
    fn verify_stream_accepts_intact_and_rejects_tampered_containers() {
        let (kem, signer) = keypair();
        let plaintext = vec![11u8; CHUNK_SIZE + 3];
        let sealed = encrypt_bytes(&plaintext, &kem, &signer);

        let mut seen: Vec<VaultProgress> = Vec::new();
        let summary =
            verify_stream_with_progress(&mut Cursor::new(sealed.clone()), &kem, &mut |p| seen.push(p)).unwrap();
        assert_eq!(summary.original_size, plaintext.len() as u64);
        assert!(seen.iter().all(|p| p.op == "verify"), "verify must relabel every event");
        assert_eq!(seen.last().map(|p| p.phase.as_str()), Some("done"));

        // A single flipped ciphertext byte must fail verification.
        let mut tampered = sealed;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(verify_stream_with_progress(&mut Cursor::new(tampered), &kem, &mut |_| {}).is_err());

        // A wrong device key must fail verification too.
        let attacker = LocalKemKeypair::generate();
        let plain2 = vec![12u8; 64];
        let sealed2 = encrypt_bytes(&plain2, &kem, &signer);
        assert!(verify_stream_with_progress(&mut Cursor::new(sealed2), &attacker, &mut |_| {}).is_err());
    }

    #[test]
    fn decrypt_stream_emits_progress_to_completion() {
        let (kem, signer) = keypair();
        let plaintext = vec![2u8; CHUNK_SIZE * 2 + 7];
        let sealed = encrypt_bytes(&plaintext, &kem, &signer);
        let mut restored = Vec::new();
        let mut seen: Vec<VaultProgress> = Vec::new();
        decrypt_stream_with_progress(&mut Cursor::new(sealed), &mut restored, &kem, &mut |p| seen.push(p)).unwrap();
        assert_eq!(restored, plaintext);
        let phases: Vec<&str> = seen.iter().map(|p| p.phase.as_str()).collect();
        assert!(phases.contains(&"verify"));
        assert!(phases.contains(&"decapsulate"));
        assert!(phases.contains(&"chunk"));
        assert_eq!(phases.last(), Some(&"done"));
        let done = seen.last().unwrap();
        assert_eq!(done.processed_bytes, plaintext.len() as u64);
    }

    // --- Portable Hybrid Identity sharing -----------------------------------

    fn seal_bytes(
        plaintext: &[u8],
        owner_kem: &LocalKemKeypair,
        signer: &VaultSigningKeypair,
        recipients: &[portable_identity::RecipientPublicKeys],
        sender: Option<&portable_identity::PortableIdentity>,
        vmk: &[u8; KEY_SIZE],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        encrypt_stream_with_progress(
            &mut Cursor::new(plaintext.to_vec()),
            &mut out,
            KIND_FILE,
            "shared.bin",
            "application/octet-stream",
            plaintext.len() as u64,
            "user-1",
            "device-1",
            &owner_kem.x25519_public,
            &owner_kem.mlkem_public,
            vmk,
            signer,
            None,
            None,
            Some(&SharingOptions { recipients, sender }),
            &mut |_| {},
        )
        .unwrap();
        out
    }

    #[test]
    fn a_sealed_container_opens_with_the_recipient_identity_and_for_the_owner() {
        let (owner_kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let bob = portable_identity::PortableIdentity::generate(Some("Bob".to_string()));
        let plaintext = vec![7u8; CHUNK_SIZE + 4242];

        let container = seal_bytes(
            &plaintext,
            &owner_kem,
            &signer,
            &[bob.public_keys()],
            None,
            &vmk,
        );

        // The recipient opens it with their portable identity.
        let mut out = Vec::new();
        let summary =
            decrypt_stream_with_identity(&mut Cursor::new(container.clone()), &mut out, &bob).unwrap();
        assert_eq!(out, plaintext);
        assert_eq!(summary.sealed_for.len(), 1);
        assert_eq!(summary.sealed_for[0].fingerprint, bob.fingerprint());
        assert_eq!(summary.sealed_for[0].label, "Bob");
        assert!(summary.verified_sender.is_none());

        // The owner keeps their own device path into the same container.
        let mut owner_out = Vec::new();
        decrypt_stream(&mut Cursor::new(container), &mut owner_out, &owner_kem).unwrap();
        assert_eq!(owner_out, plaintext);
    }

    #[test]
    fn a_recipient_cannot_open_a_container_sealed_to_someone_else() {
        let (owner_kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let bob = portable_identity::PortableIdentity::generate(None);
        let mallory = portable_identity::PortableIdentity::generate(None);
        let plaintext = b"top secret".to_vec();

        let container = seal_bytes(&plaintext, &owner_kem, &signer, &[bob.public_keys()], None, &vmk);

        let mut out = Vec::new();
        assert!(
            decrypt_stream_with_identity(&mut Cursor::new(container.clone()), &mut out, &mallory)
                .is_err()
        );
        assert!(out.is_empty());

        // And an ordinary owner-sealed container has no identity path at all.
        let owner_only = encrypt_bytes(&plaintext, &owner_kem, &signer);
        let mut out = Vec::new();
        assert!(decrypt_stream_with_identity(&mut Cursor::new(owner_only), &mut out, &bob).is_err());
    }

    #[test]
    fn a_recipient_never_learns_the_vault_master_key() {
        // The recipient wrap must seal the per-file FEK, not the VMK: unwrapping
        // it must NOT open a second container that shares the same VMK.
        let (owner_kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let bob = portable_identity::PortableIdentity::generate(None);

        let shared = seal_bytes(b"file one", &owner_kem, &signer, &[bob.public_keys()], None, &vmk);
        let other = seal_bytes(b"file two", &owner_kem, &signer, &[], None, &vmk);

        let header_shared = read_and_verify_header(&mut Cursor::new(shared.clone())).unwrap();
        let recovered_fek = unwrap_fek_for_recipient(
            &bob,
            &header_shared.recipient_wraps[0],
            &header_shared.file_id,
            &header_shared.owner_user_id,
        )
        .unwrap();

        // What the recipient recovers is the FEK of THIS file, and it is not the VMK.
        assert_ne!(recovered_fek, vmk);

        // It also cannot unwrap the other container's FEK-under-VMK envelope.
        let header_other = read_and_verify_header(&mut Cursor::new(other)).unwrap();
        assert!(symmetric::decrypt(
            &recovered_fek,
            header_other.fek_wrapped_by_vmk.as_ref().unwrap(),
            &fek_vmk_wrap_aad(&header_other.file_id, &header_other.owner_user_id),
        )
        .is_err());
    }

    #[test]
    fn a_recipient_wrap_cannot_be_moved_into_another_container() {
        let (owner_kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let bob = portable_identity::PortableIdentity::generate(None);

        let sealed = seal_bytes(b"the real file", &owner_kem, &signer, &[bob.public_keys()], None, &vmk);
        let decoy = seal_bytes(b"a different file", &owner_kem, &signer, &[bob.public_keys()], None, &vmk);

        let sealed_header = read_and_verify_header(&mut Cursor::new(sealed)).unwrap();
        let decoy_header = read_and_verify_header(&mut Cursor::new(decoy)).unwrap();

        // The wrap is AAD-bound to its own file id + owner, so lifting it into
        // the other container fails authentication.
        assert!(unwrap_fek_for_recipient(
            &bob,
            &sealed_header.recipient_wraps[0],
            &decoy_header.file_id,
            &decoy_header.owner_user_id,
        )
        .is_err());

        // Re-pointing a wrap at a different recipient fingerprint also fails.
        let mut repointed = sealed_header.recipient_wraps[0].clone();
        repointed.recipient_fingerprint =
            portable_identity::PortableIdentity::generate(None).fingerprint();
        assert!(unwrap_fek_for_recipient(
            &bob,
            &repointed,
            &sealed_header.file_id,
            &sealed_header.owner_user_id,
        )
        .is_err());
    }

    #[test]
    fn sender_attestation_is_verified_on_open() {
        let (owner_kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let alice = portable_identity::PortableIdentity::generate(Some("Alice".to_string()));
        let bob = portable_identity::PortableIdentity::generate(None);
        let plaintext = b"signed and sealed".to_vec();

        let container = seal_bytes(
            &plaintext,
            &owner_kem,
            &signer,
            &[bob.public_keys()],
            Some(&alice),
            &vmk,
        );

        let mut out = Vec::new();
        let summary =
            decrypt_stream_with_identity(&mut Cursor::new(container.clone()), &mut out, &bob).unwrap();
        assert_eq!(out, plaintext);
        let sender = summary.verified_sender.expect("attestation must verify");
        assert_eq!(sender.fingerprint, alice.fingerprint());
        assert_eq!(sender.label, "Alice");
        assert_eq!(sender.signature_algorithm, portable_identity::SIGNATURE_ML_DSA_87);

        // Inspecting the header alone reports the same verified sender.
        let inspected = inspect_stream(&mut Cursor::new(container)).unwrap();
        assert_eq!(
            inspected.verified_sender.map(|s| s.fingerprint),
            Some(alice.fingerprint())
        );
    }

    #[test]
    fn a_forged_sender_attestation_fails_before_any_plaintext_is_written() {
        let (owner_kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let alice = portable_identity::PortableIdentity::generate(Some("Alice".to_string()));
        let mallory = portable_identity::PortableIdentity::generate(Some("Alice".to_string()));
        let bob = portable_identity::PortableIdentity::generate(None);

        let container = seal_bytes(
            b"payload",
            &owner_kem,
            &signer,
            &[bob.public_keys()],
            Some(&alice),
            &vmk,
        );
        let mut header = read_and_verify_header(&mut Cursor::new(container.clone())).unwrap();

        // Swap in Mallory's identity while keeping Alice's signature: the
        // fingerprint/key binding check must reject it.
        let sender = header.sender_identity.as_mut().unwrap();
        sender.attestation.ed25519_public = mallory.signer.ed25519_public.clone();
        sender.attestation.mldsa_public = mallory.signer.mldsa87_public.clone();
        assert!(verified_sender_for(&header).is_err());

        // Claiming a different label (part of the attested bytes) also fails.
        let mut header = read_and_verify_header(&mut Cursor::new(container)).unwrap();
        header.sender_identity.as_mut().unwrap().attestation.label = "Finance Dept".to_string();
        assert!(verified_sender_for(&header).is_err());
    }

    #[test]
    fn sealing_to_several_identities_gives_each_one_access_and_collapses_duplicates() {
        let (owner_kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let bob = portable_identity::PortableIdentity::generate(Some("Bob".to_string()));
        let carol = portable_identity::PortableIdentity::generate(Some("Carol".to_string()));
        let plaintext = b"team distribution".to_vec();

        let container = seal_bytes(
            &plaintext,
            &owner_kem,
            &signer,
            // Bob listed twice on purpose.
            &[bob.public_keys(), carol.public_keys(), bob.public_keys()],
            None,
            &vmk,
        );

        let header = read_and_verify_header(&mut Cursor::new(container.clone())).unwrap();
        assert_eq!(header.recipient_wraps.len(), 2);

        for identity in [&bob, &carol] {
            let mut out = Vec::new();
            decrypt_stream_with_identity(&mut Cursor::new(container.clone()), &mut out, identity)
                .unwrap();
            assert_eq!(out, plaintext);
        }
    }

    #[test]
    fn a_sealed_container_is_v4_and_ordinary_containers_stay_v3() {
        let (owner_kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let bob = portable_identity::PortableIdentity::generate(None);

        let sealed = seal_bytes(b"x", &owner_kem, &signer, &[bob.public_keys()], None, &vmk);
        let plain = seal_bytes(b"x", &owner_kem, &signer, &[], None, &vmk);

        assert_eq!(
            read_and_verify_header(&mut Cursor::new(sealed)).unwrap().version,
            STREAM_VERSION_RECIPIENT
        );
        let plain_header = read_and_verify_header(&mut Cursor::new(plain)).unwrap();
        assert_eq!(plain_header.version, STREAM_VERSION);
        assert!(plain_header.recipient_wraps.is_empty());
        assert!(plain_header.sender_identity.is_none());
    }

    #[test]
    fn recipient_material_smuggled_into_a_v3_header_is_refused() {
        // A v3 signature does not cover recipient wraps, so a v3 container that
        // declares them must be rejected rather than trusted.
        let (owner_kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let bob = portable_identity::PortableIdentity::generate(None);

        let sealed = seal_bytes(b"payload", &owner_kem, &signer, &[bob.public_keys()], None, &vmk);
        let mut header = read_and_verify_header(&mut Cursor::new(sealed.clone())).unwrap();
        header.version = STREAM_VERSION;
        // Re-sign as a genuine v3 header so only the version rule can catch it.
        header.header_signature_v3 = Some(
            dual_sign_87(
                &signer.ed25519_secret,
                &signer.mldsa87_secret,
                &header_signable(&header),
            )
            .unwrap(),
        );

        let header_bytes = serde_json::to_vec(&header).unwrap();
        let mut forged = Vec::new();
        forged.extend_from_slice(MAGIC);
        forged.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
        forged.extend_from_slice(&header_bytes);

        assert!(read_and_verify_header(&mut Cursor::new(forged)).is_err());
    }

    #[test]
    fn tampering_with_a_sealed_header_breaks_the_signature() {
        let (owner_kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let bob = portable_identity::PortableIdentity::generate(None);
        let mallory = portable_identity::PortableIdentity::generate(None);

        let sealed = seal_bytes(b"payload", &owner_kem, &signer, &[bob.public_keys()], None, &vmk);
        let mut header = read_and_verify_header(&mut Cursor::new(sealed)).unwrap();

        // Adding Mallory as a recipient without re-signing must fail the header
        // signature, because v4 signable bytes cover every recipient wrap.
        header.recipient_wraps.push(
            wrap_fek_for_recipient(
                &mallory.public_keys(),
                &symmetric::random_key(),
                &header.file_id,
                &header.owner_user_id,
            )
            .unwrap(),
        );
        let header_bytes = serde_json::to_vec(&header).unwrap();
        let mut forged = Vec::new();
        forged.extend_from_slice(MAGIC);
        forged.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
        forged.extend_from_slice(&header_bytes);
        assert!(read_and_verify_header(&mut Cursor::new(forged)).is_err());
    }

    #[test]
    fn re_protecting_a_sealed_container_keeps_the_share_and_the_attestation() {
        // Re-protect rotates the owner's VMK wraps. Recipients and the sender
        // attestation must survive, or "re-protect" would silently revoke a share.
        let (owner_kem, signer) = keypair();
        let old_vmk = symmetric::random_key();
        let alice = portable_identity::PortableIdentity::generate(Some("Alice".to_string()));
        let bob = portable_identity::PortableIdentity::generate(Some("Bob".to_string()));
        let plaintext = vec![3u8; 2048];

        let sealed = seal_bytes(
            &plaintext,
            &owner_kem,
            &signer,
            &[bob.public_keys()],
            Some(&alice),
            &old_vmk,
        );

        let new_kem = LocalKemKeypair::generate();
        let new_signer = VaultSigningKeypair::generate();
        let new_vmk = symmetric::random_key();
        let mut rewrapped = Vec::new();
        rewrap_stream_to_v3(
            &mut Cursor::new(sealed),
            &mut rewrapped,
            std::slice::from_ref(&owner_kem),
            &new_kem.x25519_public,
            &new_kem.mlkem_public,
            &new_vmk,
            &new_signer,
            None,
            None,
        )
        .unwrap();

        let mut out = Vec::new();
        let summary =
            decrypt_stream_with_identity(&mut Cursor::new(rewrapped.clone()), &mut out, &bob).unwrap();
        assert_eq!(out, plaintext);
        assert_eq!(
            summary.verified_sender.map(|s| s.fingerprint),
            Some(alice.fingerprint())
        );

        // The owner's NEW device key opens it too.
        let mut owner_out = Vec::new();
        decrypt_stream(&mut Cursor::new(rewrapped), &mut owner_out, &new_kem).unwrap();
        assert_eq!(owner_out, plaintext);
    }

    #[test]
    fn a_sealed_folder_archive_round_trips_through_a_recipient() {
        let (owner_kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let bob = portable_identity::PortableIdentity::generate(None);

        let root = std::env::temp_dir().join(format!("qguard-seal-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("a.txt"), b"alpha").unwrap();
        std::fs::write(root.join("nested").join("b.bin"), vec![9u8; 5000]).unwrap();

        let (entries, total) = collect_folder_entries(&root).unwrap();
        let mut reader = FolderReader::new(entries);
        let mut container = Vec::new();
        encrypt_stream_with_progress(
            &mut reader,
            &mut container,
            KIND_FOLDER,
            "bundle",
            "application/qguard-folder-archive",
            total,
            "user-1",
            "device-1",
            &owner_kem.x25519_public,
            &owner_kem.mlkem_public,
            &vmk,
            &signer,
            None,
            None,
            Some(&SharingOptions { recipients: &[bob.public_keys()], sender: None }),
            &mut |_| {},
        )
        .unwrap();

        let restore = std::env::temp_dir().join(format!("qguard-seal-out-{}", Uuid::new_v4()));
        let mut writer = FolderWriter::new(restore.clone());
        decrypt_stream_with_identity(&mut Cursor::new(container), &mut writer, &bob).unwrap();
        writer.flush().unwrap();

        assert_eq!(std::fs::read(restore.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(
            std::fs::read(restore.join("nested").join("b.bin")).unwrap(),
            vec![9u8; 5000]
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&restore);
    }
}
