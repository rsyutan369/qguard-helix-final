//! Streaming, on-disk quantum-safe vault container.
//!
//! This module streams plaintext through the hybrid post-quantum stack one chunk
//! at a time, so it works for arbitrarily large files and folders with constant
//! memory and no IPC/base64 round-trips. It is the only vault crypto path: the
//! Quantum Vault is strictly local, so there is no cloud upload/package format.
//!
//! * Content:   AES-256-GCM per 1 MiB chunk, AAD-bound to file id + chunk index
//! * Envelope (v5, what this build writes): File -> AES-256-GCM FEK -> FEK
//!              wrapped by the PIN-BOUND VAULT KEY, which exists only while the
//!              vault is unlocked (it is derived from material that is stored
//!              solely under the user's vault password / PIN). When configured,
//!              the FEK is also wrapped to the recovery key and/or the
//!              enterprise ML-KEM recipient, and — for a shared container — to
//!              each recipient's Portable Hybrid Identity. ML-KEM only ever
//!              protects keys, never file content.
//! * KDF:       HKDF-SHA3-256 (inside the hybrid KEX)
//! * Header:    dual-signed Ed25519 + ML-DSA-87 (FIPS 204 Level 5) from v3 on;
//!              v1/v2 dual-signed Ed25519 + ML-DSA-65. The signature covers the
//!              wrapped key(s), metadata, and total chunk count -> truncation /
//!              extension proof.
//!
//! WHY v5 EXISTS — the older envelopes were not PIN-protected
//! -----------------------------------------------------------------------
//! v3/v4 containers carry the Vault Master Key wrapped to the DEVICE's hybrid
//! KEM key in every single header, and v1/v2 carry the file key wrapped the same
//! way. The device KEM secret is protected by nothing but the OS-keychain
//! storage key, so anyone holding that (another process in the user's session,
//! a copied profile) could open every file without ever knowing the vault
//! password — the "vault lock" was a check in the UI, not in the cryptography.
//! v5 removes the device wrap. Old containers stay readable so nobody loses
//! data, but they are reported as `pin_bound: false` and "re-protect" rewrites
//! their header as v5.
//!
//! Authenticity, by path (a header signature alone proves nothing, because the
//! signing key travels inside the header it signs):
//!   * owner, v5     — the FEK unwraps only under this vault's PIN-bound key,
//!                     and the signer must be this vault's signer;
//!   * owner, v3/v4  — the VMK recovered through the device wrap must EQUAL the
//!                     unlocked vault's VMK, and the signer must match. A
//!                     container built by anyone else (to the device's public
//!                     key, which is published) fails both;
//!   * owner, v1/v2  — the signer must be this device's identity key; anything
//!                     else needs the user's explicit consent;
//!   * recovery      — the recovery wrap is symmetric: only a holder of the
//!                     recovery key could have produced it;
//!   * recipient     — the optional sender attestation names a Portable Hybrid
//!                     Identity fingerprint for the user to compare out of band.
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
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::hybrid_kex::{decapsulate, encapsulate_bound, LocalKemKeypair};
use crate::crypto::portable_identity;
use crate::crypto::signatures::{dual_verify, dual_sign_87, dual_verify_87, VaultSigningKeypair};
use crate::crypto::symmetric::{self, KEY_SIZE};
use crate::crypto::vault_recovery;
use crate::crypto::{vault_suite, AlgorithmSuite, DualSignature, DualSignature87, EncryptedEnvelope, HybridCiphertext};
use crate::error::{QGuardError, Result};

const MAGIC: &[u8; 8] = b"QGUARDVS";
/// The container version this build WRITES.
///
/// * v1 — file key wrapped to the device hybrid KEM.
/// * v2 — adds an optional recovery-key wrap.
/// * v3 — Vault Master Key envelope: FEK wrapped by the VMK, the VMK wrapped to
///        the device KEM (and recovery / enterprise); signed with ML-DSA-87.
/// * v4 — v3 plus Portable Hybrid Identity recipient wraps and an optional
///        sender attestation.
/// * v5 — PIN-bound: no device wrap at all. The FEK is wrapped by a key that
///        only exists while the vault is unlocked; recovery / enterprise /
///        recipient wraps seal the FEK directly. Recipient wraps and the sender
///        attestation are part of v5, so a shared container is v5 too.
///
/// Every version is still accepted on decrypt.
pub const STREAM_VERSION: u8 = 5;
/// The newest version whose owner envelope hangs off the DEVICE key rather than
/// the vault unlock secret. Containers at or below it are reported as
/// `pin_bound: false`.
pub const LAST_DEVICE_BOUND_VERSION: u8 = 4;
/// Highest container version this build can read.
pub const MAX_STREAM_VERSION: u8 = STREAM_VERSION;

/// Stable prefix of the error returned when a container was sealed under a
/// different vault than the one unlocked here (before a vault reset, on another
/// device, or by someone else entirely). The UI matches on it to point the user
/// at the recovery-key tools instead of showing a bare decrypt failure.
pub const FOREIGN_VAULT_MARKER: &str = "FOREIGN_VAULT_KEY";
/// Stable prefix of the error returned when a legacy v1/v2 container is signed
/// by a key this device does not recognise. Unlike a foreign vault key this one
/// is overridable — with the user's explicit consent — because v1/v2 predate
/// the vault key and an identity re-key legitimately orphans their signer.
pub const UNRECOGNIZED_SIGNER_MARKER: &str = "UNRECOGNIZED_VAULT_SIGNER";
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
#[derive(Clone, Copy)]
pub struct EnterpriseRecipient<'a> {
    pub x25519_public: &'a [u8],
    pub mlkem_public: &'a [u8],
    pub recovery_secret: Option<&'a [u8; KEY_SIZE]>,
}

/// What the owner's unlocked vault contributes when a container is WRITTEN.
pub struct OwnerSeal<'a> {
    pub user_id: &'a str,
    pub device_id: &'a str,
    /// The PIN-bound vault key (see `PersistedVaultMaster::vault_key`). It
    /// wraps the per-file key and is never written anywhere.
    pub vault_key: &'a [u8; KEY_SIZE],
    /// Signs the header (Ed25519 + ML-DSA-87).
    pub vault_signer: &'a VaultSigningKeypair,
    /// Personal-mode recovery wrapping key, when recovery is configured.
    pub recovery_wrap_key: Option<&'a [u8; KEY_SIZE]>,
    /// Enterprise / hybrid recovery recipient, when configured.
    pub enterprise: Option<EnterpriseRecipient<'a>>,
}

/// What the owner's unlocked vault can use to OPEN a container, and what it
/// will accept as its own.
pub struct OwnerAccess<'a> {
    /// The PIN-bound vault key: the only way into a v5 container.
    pub vault_key: &'a [u8; KEY_SIZE],
    /// The raw Vault Master Key. Never used to derive anything for v5; its only
    /// job is to be compared with the VMK a legacy v3/v4 header yields, which is
    /// what proves that header was produced by THIS vault.
    pub legacy_vmk: &'a [u8; KEY_SIZE],
    /// The signer every v3+ container from this vault carries.
    pub vault_signer: &'a VaultSigningKeypair,
    /// Device KEM keys (current first, then rotated ones) for legacy v1–v4.
    pub device_kems: &'a [LocalKemKeypair],
    /// This device's identity signing keys (Ed25519, ML-DSA-65) — the signer of
    /// a legacy v1/v2 container. `None` when no identity is loaded.
    pub device_signer: Option<(&'a [u8], &'a [u8])>,
    /// The user explicitly agreed to open a v1/v2 container whose signer this
    /// device does not recognise. Never applies to v3+.
    pub allow_unrecognized_legacy_signer: bool,
}

/// One Portable Hybrid Identity this container is sealed to (v4+).
///
/// Security note — this wrap seals the **per-file FEK**, never a vault-wide key.
/// A recipient gets exactly one file's key and nothing that opens any other.
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
    /// The container format version on disk.
    pub container_version: u8,
    /// True when the owner's way into this container requires the vault unlock
    /// secret (v5). False for v1–v4, whose owner envelope hangs off the device
    /// key — those open without the vault PIN to anyone holding that key, and
    /// should be re-protected.
    pub pin_bound: bool,
    /// Fingerprints of every Portable Hybrid Identity this container is sealed
    /// to. Empty for ordinary owner-only containers.
    #[serde(default)]
    pub sealed_for: Vec<SealedRecipient>,
    /// Set when the container carries a sender attestation whose signatures and
    /// fingerprint binding checked out. That proves the container was sealed by
    /// the holder of THAT identity — it does not, by itself, say whose identity
    /// it is: the fingerprint still has to be compared with one the user got
    /// from the sender out of band. A present-but-invalid attestation fails the
    /// whole operation, so this is never an unchecked claim.
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
            container_version: header.version,
            pin_bound: header.version > LAST_DEVICE_BOUND_VERSION,
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

/// AAD binding the v3/v4 FEK-under-VMK wrap to its container (file id + owner).
fn fek_vmk_wrap_aad(file_id: &str, owner_user_id: &str) -> Vec<u8> {
    format!("QGuard-Vault-FEK-Under-VMK-v1:{file_id}:{owner_user_id}").into_bytes()
}

/// AAD binding the v5 FEK-under-vault-key wrap to its container.
///
/// A different label from the v3/v4 one, so the two envelopes — which share a
/// header field but are sealed under different keys — are never interchangeable.
fn fek_vault_key_wrap_aad(file_id: &str, owner_user_id: &str) -> Vec<u8> {
    format!("QGuard-Vault-FEK-Under-VaultKey-v2:{file_id}:{owner_user_id}").into_bytes()
}

/// The device-wrap fields of a header that has no device wrap (v5).
///
/// They stay in the struct because v1–v4 headers need them to deserialize; a v5
/// header carries them empty, which also makes the device path fail cleanly if
/// anything ever tried to use it on one.
fn absent_device_wrap() -> (HybridCiphertext, EncryptedEnvelope) {
    (
        HybridCiphertext {
            x25519_ephemeral_public: Vec::new(),
            ml_kem_ciphertext: Vec::new(),
            suite: AlgorithmSuite {
                kem_combiner: String::new(),
                ..AlgorithmSuite::default()
            },
        },
        EncryptedEnvelope {
            nonce: Vec::new(),
            ciphertext: Vec::new(),
            tag: Vec::new(),
        },
    )
}

fn push_len_prefixed(data: &mut Vec<u8>, bytes: &[u8]) {
    data.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(bytes);
}

/// Equality that does not stop at the first differing byte. Used to compare a
/// recovered key with the vault's own, where an early exit would leak how much
/// of a guess was right.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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
    // v5 additionally authenticates WHICH hybrid combiner each KEM wrap was made
    // with. Earlier versions only ever used one, so there was nothing to sign;
    // from v5 a wrap can be either, and an unsigned label could be flipped to
    // make a recipient derive the wrong key. Length-prefixed, and appended only
    // for v5, so v1–v4 bytes are untouched.
    if header.version >= 5 {
        data.push(5);
        match &header.recovery_kem_wrap {
            Some(kem) => {
                data.push(1);
                push_len_prefixed(&mut data, kem.kem_ciphertext.suite.kem_combiner.as_bytes());
            }
            None => data.push(0),
        }
        for wrap in &header.recipient_wraps {
            push_len_prefixed(&mut data, wrap.kem_ciphertext.suite.kem_combiner.as_bytes());
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
    // Transcript-bound combiner: a recipient wrap is only ever written into a
    // v5 container, which a build without it cannot read in the first place.
    let (kem_ciphertext, mut shared) = encapsulate_bound(
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

/// Stream-encrypt `reader` (exactly `original_size` bytes) into `writer` as a
/// v5 container owned by the unlocked vault described by `owner`.
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    kind: &str,
    name: &str,
    content_type: &str,
    original_size: u64,
    owner: &OwnerSeal,
) -> Result<StreamSummary> {
    encrypt_stream_with_progress(
        reader,
        writer,
        kind,
        name,
        content_type,
        original_size,
        owner,
        None,
        &mut |_| {},
    )
}

/// Same as [`encrypt_stream`] but reports real per-phase / per-chunk progress
/// through `progress`, and optionally seals the container to Portable Hybrid
/// Identity recipients. The sink is best-effort telemetry only — it never
/// affects the produced container.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    kind: &str,
    name: &str,
    content_type: &str,
    original_size: u64,
    owner: &OwnerSeal,
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

    // The per-file FEK encrypts the bulk data. `Zeroizing` wipes it on every
    // exit path, including the early `?` returns below.
    let file_key = Zeroizing::new(symmetric::random_key());
    emit(progress, "fek", "Per-file key generated · AES-256-GCM (256-bit)", 0, 0, "info");

    // The owner's way back in: the FEK under the PIN-bound vault key. There is
    // deliberately NO device-key wrap — that is exactly what made the older
    // envelopes openable without the vault password.
    let fek_wrapped_by_vmk = Some(symmetric::encrypt(
        owner.vault_key,
        file_key.as_slice(),
        &fek_vault_key_wrap_aad(&file_id, owner.user_id),
    )?);
    emit(
        progress,
        "vmk_wrap",
        "Per-file key sealed under the PIN-bound vault key · AES-256-GCM",
        0,
        0,
        "info",
    );

    // Optional backup routes to the same FEK, so the file survives a forgotten
    // vault password or a lost device. Each seals the per-file key itself:
    // nothing above it is ever written into a header.
    let recovery_wrapped_key = match owner.recovery_wrap_key {
        Some(key) => Some(vault_recovery::wrap_fek_v5(
            key,
            &file_key,
            &file_id,
            owner.user_id,
        )?),
        None => None,
    };
    let recovery_kem_wrap = match owner.enterprise.as_ref() {
        Some(ent) => Some(vault_recovery::wrap_fek_kem_v5(
            ent.x25519_public,
            ent.mlkem_public,
            ent.recovery_secret,
            &file_key,
            &file_id,
            owner.user_id,
        )?),
        None => None,
    };
    if recovery_kem_wrap.is_some() {
        emit(
            progress,
            "recovery_wrap",
            "Per-file key sealed to the enterprise recovery recipient · X25519 + ML-KEM-1024",
            0,
            0,
            "info",
        );
    } else if recovery_wrapped_key.is_some() {
        emit(
            progress,
            "recovery_wrap",
            "Per-file key sealed to the recovery key · HKDF-SHA3-256 / AES-256-GCM",
            0,
            0,
            "info",
        );
    }

    // Portable Hybrid Identity recipients. Duplicate fingerprints are collapsed
    // so a container never carries two wraps for the same identity.
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
            owner.user_id,
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

    // A sender attestation only means something on a container someone else will
    // open, so it rides along with the recipient wraps.
    let sender_identity = match sharing.and_then(|s| s.sender) {
        Some(identity) if !recipient_wraps.is_empty() => Some(SenderIdentity {
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

    let (hybrid_ciphertext, wrapped_key) = absent_device_wrap();
    let mut header = StreamHeader {
        version: STREAM_VERSION,
        file_id: file_id.clone(),
        kind: kind.to_string(),
        name: name.to_string(),
        content_type: content_type.to_string(),
        original_size,
        chunk_size: CHUNK_SIZE as u32,
        total_chunks,
        owner_user_id: owner.user_id.to_string(),
        owner_device_id: owner.device_id.to_string(),
        hybrid_ciphertext,
        wrapped_key,
        recovery_wrapped_key,
        recovery_kem_wrap,
        fek_wrapped_by_vmk,
        suite: vault_suite(),
        signer_ed25519_public: owner.vault_signer.ed25519_public.clone(),
        signer_mldsa_public: Vec::new(),
        signer_mldsa87_public: owner.vault_signer.mldsa87_public.clone(),
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
        &owner.vault_signer.ed25519_secret,
        &owner.vault_signer.mldsa87_secret,
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

    let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut index: u64 = 0;
    let mut streamed: u64 = 0;
    loop {
        let n = read_chunk(reader, &mut buf)?;
        if n == 0 {
            break;
        }
        if index >= total_chunks {
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
///
/// NOTE what this does and does not establish. The signature is checked with
/// the public keys carried in the very header being checked, so success means
/// the header is intact and self-consistent — NOT that any particular party
/// produced it. Anyone can mint a keypair and sign a header of their own. Every
/// caller therefore adds the authentication that fits its path (see the module
/// docs); the owner paths do it in [`owner_file_key`].
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

    // Integrity of the header (wrapped key(s) + metadata + total_chunks) before
    // use. v3+ verifies with ML-DSA-87; v1/v2 with ML-DSA-65.
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

/// A 32-byte key out of an AEAD plaintext, wiped on every path.
fn key_from_bytes(bytes: Vec<u8>, what: &str) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let bytes = Zeroizing::new(bytes);
    if bytes.len() != KEY_SIZE {
        return Err(QGuardError::Crypto(what.to_string()));
    }
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// v3/v4: unwrap the per-file key from under the Vault Master Key.
fn fek_from_vmk(header: &StreamHeader, vmk: &[u8; KEY_SIZE]) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let env = header.fek_wrapped_by_vmk.as_ref().ok_or_else(|| {
        QGuardError::Crypto("v3 vault container is missing its VMK-wrapped file key".to_string())
    })?;
    let bytes = symmetric::decrypt(
        vmk,
        env,
        &fek_vmk_wrap_aad(&header.file_id, &header.owner_user_id),
    )?;
    key_from_bytes(bytes, "v3 vault unwrapped FEK is invalid")
}

/// The per-file key, by way of the personal recovery key.
///
/// What the recovery envelope holds depends on the container generation:
///   * v1/v2 — the per-file key itself;
///   * v3/v4 — the Vault Master Key, which then unwraps `fek_wrapped_by_vmk`;
///   * v5    — the per-file key itself, sealed under a v5-only label, so it can
///             never be a relabelled v3/v4 Vault Master Key.
fn recovery_file_key(
    header: &StreamHeader,
    recovery_wrap_key: &[u8; KEY_SIZE],
) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let env = header.recovery_wrapped_key.as_ref().ok_or_else(|| {
        QGuardError::NotFound(
            "this vault container was sealed without a recovery key; re-protect it with recovery enabled".to_string(),
        )
    })?;
    if header.version >= 5 {
        return Ok(Zeroizing::new(vault_recovery::unwrap_fek_v5(
            recovery_wrap_key,
            env,
            &header.file_id,
            &header.owner_user_id,
        )?));
    }
    let unwrapped = Zeroizing::new(vault_recovery::unwrap_file_key(
        recovery_wrap_key,
        env,
        &header.file_id,
        &header.owner_user_id,
    )?);
    if header.version < 3 {
        Ok(unwrapped)
    } else {
        fek_from_vmk(header, &unwrapped)
    }
}

/// The per-file key, by way of the enterprise (or hybrid) recovery recipient.
/// Same generation rules as [`recovery_file_key`].
fn enterprise_file_key(
    header: &StreamHeader,
    recipient: &LocalKemKeypair,
    recovery_secret: Option<&[u8; KEY_SIZE]>,
) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let kem_wrap = header.recovery_kem_wrap.as_ref().ok_or_else(|| {
        QGuardError::NotFound(
            "this vault container was sealed without an enterprise recovery key".to_string(),
        )
    })?;
    if header.version >= 5 {
        return Ok(Zeroizing::new(vault_recovery::unwrap_fek_kem_v5(
            recipient,
            recovery_secret,
            kem_wrap,
            &header.file_id,
            &header.owner_user_id,
        )?));
    }
    let unwrapped = Zeroizing::new(vault_recovery::unwrap_file_key_kem(
        recipient,
        recovery_secret,
        kem_wrap,
        &header.file_id,
        &header.owner_user_id,
    )?);
    if header.version < 3 {
        Ok(unwrapped)
    } else {
        fek_from_vmk(header, &unwrapped)
    }
}

fn foreign_vault_error() -> QGuardError {
    QGuardError::Trust(format!(
        "{FOREIGN_VAULT_MARKER}: this container was not sealed by the vault that is unlocked on this device. It was created before a vault reset, on another device, or by someone else. Open it with your recovery key instead."
    ))
}

/// True when `header` names exactly this vault's signing keys as its signer.
fn header_signed_by(header: &StreamHeader, signer: &VaultSigningKeypair) -> bool {
    !signer.ed25519_public.is_empty()
        && !signer.mldsa87_public.is_empty()
        && header.signer_ed25519_public == signer.ed25519_public
        && header.signer_mldsa87_public == signer.mldsa87_public
}

/// Legacy (v1–v4): open `header.wrapped_key` with whichever device KEM key it
/// was sealed to. Yields the per-file key (v1/v2) or the Vault Master Key
/// (v3/v4) — the caller decides which, and whether to believe it.
fn device_unwrap(
    header: &StreamHeader,
    device_kems: &[LocalKemKeypair],
) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let wrap_aad = wrap_aad_bytes(&header.file_id, &header.owner_user_id, &header.owner_device_id);
    for kem in device_kems {
        let Ok(secret) = decapsulate(
            &kem.x25519_secret,
            &kem.mlkem_secret,
            &header.hybrid_ciphertext,
            &crate::security::obf::vault_stream_wrap_info(),
        ) else {
            continue;
        };
        let secret = Zeroizing::new(secret);
        let Ok(bytes) = symmetric::decrypt(&secret, &header.wrapped_key, &wrap_aad) else {
            continue;
        };
        if let Ok(key) = key_from_bytes(bytes, "vault stream unwrapped key is invalid") {
            return Ok(key);
        }
    }
    Err(QGuardError::Crypto(
        "this device's keys cannot open this vault container — it was sealed to another device, or to a device key that has since been replaced. Open it with your recovery key.".to_string(),
    ))
}

/// Authenticate a container as THIS vault's own and recover its per-file key.
///
/// This is where the owner paths (decrypt, verify, re-protect) decide whether a
/// container is genuinely theirs. `read_and_verify_header` cannot: it only
/// proves the header is self-consistent. See the module docs for the rule each
/// generation gets and why.
fn owner_file_key(
    header: &StreamHeader,
    access: &OwnerAccess,
) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    if header.version >= 5 {
        // Both conditions hold together for every container this vault made
        // and for none that anyone else did: the signer is this vault's, and
        // the per-file key opens under this vault's PIN-bound key.
        if !header_signed_by(header, access.vault_signer) {
            return Err(foreign_vault_error());
        }
        let env = header.fek_wrapped_by_vmk.as_ref().ok_or_else(|| {
            QGuardError::Crypto(
                "vault container is missing its vault-key-wrapped file key".to_string(),
            )
        })?;
        let bytes = symmetric::decrypt(
            access.vault_key,
            env,
            &fek_vault_key_wrap_aad(&header.file_id, &header.owner_user_id),
        )
        .map_err(|_| foreign_vault_error())?;
        return key_from_bytes(bytes, "vault-key-unwrapped file key is invalid");
    }

    if header.version >= 3 {
        // v3/v4: the device wrap yields a Vault Master Key. The device's KEM
        // public key is published, so ANYONE can build a container that
        // decapsulates here — what they cannot do is make it yield THIS vault's
        // VMK. Requiring that equality is what authenticates a legacy
        // container, and it is also what stops a vault reset from being a way
        // around the old lock: after a reset the unlocked VMK is a new one, and
        // every pre-reset container stops matching.
        if !header_signed_by(header, access.vault_signer) {
            return Err(foreign_vault_error());
        }
        let vmk = device_unwrap(header, access.device_kems)?;
        if !constant_time_eq(vmk.as_slice(), access.legacy_vmk) {
            return Err(foreign_vault_error());
        }
        return fek_from_vmk(header, &vmk);
    }

    // v1/v2 predate the vault key entirely: the file key is wrapped straight to
    // the device, and the header was signed by the device's messaging identity.
    // The only anchor available is that identity's signing key.
    let recognised = access.device_signer.is_some_and(|(ed25519, mldsa)| {
        !ed25519.is_empty()
            && header.signer_ed25519_public == ed25519
            && header.signer_mldsa_public == mldsa
    });
    if !recognised && !access.allow_unrecognized_legacy_signer {
        return Err(QGuardError::Trust(format!(
            "{UNRECOGNIZED_SIGNER_MARKER}: this older vault container was signed by a key this device does not recognise. That is expected if it predates a device key reset — and it is also exactly what a file made by someone else would look like. Only open it if you know where it came from."
        )));
    }
    device_unwrap(header, access.device_kems)
}

/// One line for the activity log saying how the owner got into a container.
fn owner_envelope_note(header: &StreamHeader) -> &'static str {
    if header.version >= 5 {
        "Per-file key unwrapped with the PIN-bound vault key"
    } else if header.version >= 3 {
        "Legacy device-bound envelope opened · Vault Master Key matched this vault (re-protect to bind this file to your vault PIN)"
    } else {
        "Legacy device-bound envelope opened (re-protect to bind this file to your vault PIN)"
    }
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

/// Read + integrity-check a container's header WITHOUT decrypting any content,
/// so the UI can show who a `.qvault` is sealed for and which identity attested
/// to it before the user commits to a destination folder.
///
/// This reveals nothing a holder of the file could not already parse. Note the
/// limit: the header is self-signed, so its labels are only as trustworthy as
/// whoever produced the file. The one externally checkable fact in here is the
/// attested sender FINGERPRINT.
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
        let plain = Zeroizing::new(symmetric::decrypt(file_key, &env, &aad)?);
        processed += plain.len() as u64;
        writer.write_all(&plain).map_err(io_err)?;
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
    // The chunk count is AAD-bound, the byte count is not — so check it. Every
    // container this code writes satisfies it by construction.
    if processed != header.original_size {
        return Err(QGuardError::Crypto(format!(
            "vault container declares {} bytes but holds {processed}",
            header.original_size
        )));
    }
    Ok(StreamSummary::from_header(header))
}

fn phase_event(
    op: &str,
    phase: &str,
    message: impl Into<String>,
    header: &StreamHeader,
    processed: u64,
    level: &str,
) -> VaultProgress {
    VaultProgress {
        op: op.into(),
        phase: phase.into(),
        message: message.into(),
        processed_bytes: processed,
        total_bytes: header.original_size,
        chunk_index: if processed >= header.original_size { header.total_chunks } else { 0 },
        total_chunks: header.total_chunks,
        level: level.into(),
    }
}

/// Stream-decrypt a container this vault owns.
pub fn decrypt_stream_owner<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    access: &OwnerAccess,
) -> Result<StreamSummary> {
    decrypt_stream_owner_with_progress(reader, writer, access, &mut |_| {})
}

/// Same as [`decrypt_stream_owner`] but reports real per-phase / per-chunk
/// progress. Nothing is written to `writer` until the container has been
/// authenticated as this vault's own.
pub fn decrypt_stream_owner_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    access: &OwnerAccess,
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let header = read_and_verify_header(reader)?;
    let file_key = owner_file_key(&header, access)?;
    // A carried attestation is checked before any plaintext exists as well.
    let verified_sender = verified_sender_for(&header)?;

    let signature = if header.version >= 3 { "Ed25519 + ML-DSA-87" } else { "Ed25519 + ML-DSA-65" };
    progress(phase_event(
        "decrypt",
        "verify",
        format!("Header verified against this vault · {signature} signature valid"),
        &header,
        0,
        "info",
    ));
    progress(phase_event("decrypt", "decapsulate", owner_envelope_note(&header), &header, 0, "info"));
    progress(phase_event(
        "decrypt",
        "unwrap_fek",
        "Per-file key unwrapped · streaming decrypt",
        &header,
        0,
        "info",
    ));

    let mut summary = decrypt_chunks(reader, writer, &header, &file_key, progress)?;
    summary.verified_sender = verified_sender;
    progress(phase_event(
        "decrypt",
        "done",
        "Vault container fully decrypted · integrity verified",
        &header,
        header.original_size,
        "success",
    ));
    Ok(summary)
}

/// Stream-decrypt a container that was sealed to a Portable Hybrid Identity.
///
/// The identity's wrap yields the per-file FEK directly — nothing of the
/// sender's vault is touched, so opening a shared container gives the recipient
/// this one file and no other access.
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
    // Deliberately "intact", not "verified": the header is signed by a key it
    // carries itself, which a recipient has no way to attribute to anyone. Who
    // sealed the container is the attestation's job, reported just below.
    progress(phase_event(
        "open",
        "verify",
        "Header intact · Ed25519 + ML-DSA-87 signature self-consistent",
        &header,
        0,
        "info",
    ));

    if header.recipient_wraps.is_empty() {
        return Err(QGuardError::Crypto(
            "this container is not sealed to any portable identity — decrypt it on the owner's device or with a recovery key".to_string(),
        ));
    }

    // The attestation must hold BEFORE any plaintext is written, so a forged
    // sender can never reach the user alongside real content.
    let verified_sender = verified_sender_for(&header)?;
    match verified_sender.as_ref() {
        Some(sender) => progress(phase_event(
            "open",
            "attest",
            format!(
                "Sealed by identity {} · {} — compare this fingerprint with the sender's",
                portable_identity::short_fingerprint(&sender.fingerprint),
                sender.signature_algorithm,
            ),
            &header,
            0,
            "info",
        )),
        None => progress(phase_event(
            "open",
            "attest",
            "No sender attestation — who sealed this container is NOT established",
            &header,
            0,
            "info",
        )),
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

    let file_key = Zeroizing::new(unwrap_fek_for_recipient(
        identity,
        wrap,
        &header.file_id,
        &header.owner_user_id,
    )?);
    progress(phase_event(
        "open",
        "unwrap_fek",
        format!(
            "Per-file key recovered for {} · {}",
            portable_identity::short_fingerprint(&fingerprint),
            wrap.algorithm,
        ),
        &header,
        0,
        "info",
    ));

    let mut relabel = |mut p: VaultProgress| {
        p.op = "open".into();
        progress(p);
    };
    let mut summary = decrypt_chunks(reader, writer, &header, &file_key, &mut relabel)?;
    summary.verified_sender = verified_sender;
    progress(phase_event(
        "open",
        "done",
        "Sealed container opened · every chunk authenticated",
        &header,
        header.original_size,
        "success",
    ));
    Ok(summary)
}

/// Fully verify a container this vault owns WITHOUT writing plaintext anywhere:
/// decrypts every chunk into an in-memory sink, checking that the container is
/// authentically this vault's (see [`owner_file_key`]), each chunk's
/// AES-256-GCM tag + AAD binding, and the declared chunk count / size.
pub fn verify_stream_owner_with_progress<R: Read>(
    reader: &mut R,
    access: &OwnerAccess,
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let mut relabel = |mut p: VaultProgress| {
        p.op = "verify".into();
        if p.phase == "done" {
            p.message = "Integrity verified · signed header + every chunk authenticated".into();
        }
        progress(p);
    };
    decrypt_stream_owner_with_progress(reader, &mut io::sink(), access, &mut relabel)
}

/// Stream-decrypt `reader` into `writer` using the owner's quantum-safe recovery
/// key — no access to the original device or vault password is required.
///
/// Authenticity on this path comes from the recovery wrap itself: it is a
/// symmetric AEAD under the recovery key, so only a holder of that key could
/// have produced a wrap that opens.
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
    progress(phase_event("decrypt", "verify", "Header intact · recovery decrypt", &header, 0, "info"));
    let file_key = recovery_file_key(&header, recovery_wrap_key)?;
    progress(phase_event(
        "decrypt",
        "unwrap_fek",
        "Per-file key recovered with the recovery key · HKDF-SHA3-256 / AES-256-GCM",
        &header,
        0,
        "info",
    ));
    let summary = decrypt_chunks(reader, writer, &header, &file_key, progress)?;
    progress(phase_event(
        "decrypt",
        "done",
        "Vault container recovered · integrity verified",
        &header,
        header.original_size,
        "success",
    ));
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
    progress(phase_event(
        "decrypt",
        "verify",
        "Header intact · enterprise recovery decrypt",
        &header,
        0,
        "info",
    ));
    let file_key = enterprise_file_key(&header, recipient, recovery_secret)?;
    progress(phase_event(
        "decrypt",
        "unwrap_fek",
        "Per-file key recovered with the enterprise key · X25519 + ML-KEM-1024",
        &header,
        0,
        "info",
    ));
    let summary = decrypt_chunks(reader, writer, &header, &file_key, progress)?;
    progress(phase_event(
        "decrypt",
        "done",
        "Vault container recovered · integrity verified",
        &header,
        header.original_size,
        "success",
    ));
    Ok(summary)
}

/// Re-protect an existing container as a v5 (PIN-bound) container *without*
/// re-encrypting the bulk data.
///
/// The per-file FEK is recovered from the existing container — which first has
/// to authenticate as this vault's own, exactly as it would for a decrypt — and
/// is then re-sealed under the PIN-bound vault key (and, when configured, the
/// recovery key / enterprise recipient). The legacy device wrap is DROPPED, the
/// header is re-signed with this vault's ML-DSA-87 key, and the encrypted chunk
/// frames — with the original `file_id` / `total_chunks` they are AAD-bound to —
/// are copied verbatim. Accepts any version; always emits v5.
pub fn rewrap_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    access: &OwnerAccess,
    owner: &OwnerSeal,
) -> Result<StreamSummary> {
    rewrap_stream_with_progress(reader, writer, access, owner, &mut |_| {})
}

/// Same as [`rewrap_stream`] but reports real per-phase progress. The bulk
/// chunk frames are copied verbatim (header-only re-protection), so progress is
/// reported at phase boundaries rather than per chunk.
pub fn rewrap_stream_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    access: &OwnerAccess,
    owner: &OwnerSeal,
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let header = read_and_verify_header(reader)?;
    let file_key = owner_file_key(&header, access)?;
    progress(phase_event(
        "rewrap",
        "verify",
        "Existing container authenticated as this vault's · re-protecting",
        &header,
        0,
        "info",
    ));
    progress(phase_event(
        "rewrap",
        "unwrap_fek",
        "Per-file key recovered from the existing container",
        &header,
        0,
        "info",
    ));

    // Re-seal around the SAME FEK + file_id + owner ids, so the verbatim chunk
    // frames and every carried recipient wrap still authenticate.
    let fek_wrapped_by_vmk = Some(symmetric::encrypt(
        owner.vault_key,
        file_key.as_slice(),
        &fek_vault_key_wrap_aad(&header.file_id, &header.owner_user_id),
    )?);
    progress(phase_event(
        "rewrap",
        "vmk_wrap",
        "Per-file key re-sealed under the PIN-bound vault key · device wrap removed",
        &header,
        0,
        "info",
    ));
    let recovery_wrapped_key = match owner.recovery_wrap_key {
        Some(key) => Some(vault_recovery::wrap_fek_v5(
            key,
            &file_key,
            &header.file_id,
            &header.owner_user_id,
        )?),
        None => None,
    };
    let recovery_kem_wrap = match owner.enterprise.as_ref() {
        Some(ent) => Some(vault_recovery::wrap_fek_kem_v5(
            ent.x25519_public,
            ent.mlkem_public,
            ent.recovery_secret,
            &file_key,
            &header.file_id,
            &header.owner_user_id,
        )?),
        None => None,
    };
    if recovery_wrapped_key.is_some() || recovery_kem_wrap.is_some() {
        progress(phase_event(
            "rewrap",
            "recovery_wrap",
            "Per-file key sealed to the recovery recipient",
            &header,
            0,
            "info",
        ));
    }
    drop(file_key);

    // Re-protecting must never silently revoke a share. The recipient wraps seal
    // the SAME FEK under a KEM ciphertext of their own, and their AAD binds
    // file id + owner + recipient — none of which change here — so they are
    // carried across verbatim and stay openable. The sender attestation signs
    // `attestation_signable`, which deliberately excludes the owner-side wraps
    // being rewritten, so it too survives unchanged.
    let (hybrid_ciphertext, wrapped_key) = absent_device_wrap();
    let mut new_header = StreamHeader {
        version: STREAM_VERSION,
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
        signer_ed25519_public: owner.vault_signer.ed25519_public.clone(),
        signer_mldsa_public: Vec::new(),
        signer_mldsa87_public: owner.vault_signer.mldsa87_public.clone(),
        header_signature: DualSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
        header_signature_v3: None,
        recipient_wraps: header.recipient_wraps.clone(),
        sender_identity: header.sender_identity.clone(),
    };
    let signable = header_signable(&new_header);
    new_header.header_signature_v3 = Some(dual_sign_87(
        &owner.vault_signer.ed25519_secret,
        &owner.vault_signer.mldsa87_secret,
        &signable,
    )?);
    progress(phase_event(
        "rewrap",
        "sign",
        "New header signed · Ed25519 + ML-DSA-87 (FIPS 204 L5)",
        &header,
        0,
        "info",
    ));

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
    progress(phase_event(
        "rewrap",
        "done",
        "Container re-protected · PIN-bound v5 envelope (ML-DSA-87)",
        &header,
        header.original_size,
        "success",
    ));

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

fn unsafe_archive_path() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "archive contains an unsafe path")
}

/// Characters Windows either refuses in a file name or reinterprets as path
/// syntax (`\` is a separator, `:` selects a drive or an alternate data stream).
const WINDOWS_FORBIDDEN_NAME_CHARS: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

/// Names Windows resolves to a DEVICE in any directory and with any extension
/// (`NUL.txt` is still the null device).
fn is_windows_reserved_device_name(stem: &str) -> bool {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    RESERVED.iter().any(|name| name.eq_ignore_ascii_case(stem))
}

/// Turn ONE `/`-separated segment of an archived path into a name that is safe
/// to create beneath the restore destination.
///
/// The archive's paths are attacker-controlled whenever the container came from
/// someone else (a sealed share), so this is a trust boundary, not a tidy-up.
/// The framing only ever writes `/` between segments, and the old check stopped
/// there: it rejected `""`, `.` and `..` and passed everything else to
/// `PathBuf::push`. On Windows that is not one component. `..\..\x` is three,
/// `C:\x` and `\\server\share\x` are absolute and REPLACE the destination
/// outright, and `C:x` is drive-relative — so a sealed folder could write
/// anywhere its recipient could.
///
/// `windows_rules` is a parameter rather than a `cfg` so the Windows behaviour
/// is unit-tested on every platform the test-suite runs on.
///
/// * Traversal segments are REFUSED, on every platform.
/// * Under Windows rules, characters with path meaning are neutralised to `_`
///   rather than refused, so an archive made on Linux/macOS (where `:` and `\`
///   are ordinary file-name characters) still restores — into the destination.
fn safe_archive_component(part: &str, windows_rules: bool) -> io::Result<String> {
    if part.is_empty() || part == "." || part == ".." || part.contains('\0') || part.contains('/') {
        return Err(unsafe_archive_path());
    }
    if !windows_rules {
        return Ok(part.to_string());
    }

    let mapped: String = part
        .chars()
        .map(|c| {
            if c.is_control() || WINDOWS_FORBIDDEN_NAME_CHARS.contains(&c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    // Windows silently strips trailing dots and spaces, so `.. ` IS `..` once it
    // reaches the filesystem and `secret.` is `secret`.
    let trimmed = mapped.trim_end_matches(['.', ' ']);
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return Err(unsafe_archive_path());
    }
    let stem = trimmed.split('.').next().unwrap_or(trimmed).trim_end_matches(' ');
    if is_windows_reserved_device_name(stem) {
        return Ok(format!("_{trimmed}"));
    }
    Ok(trimmed.to_string())
}

/// `Write` adapter that parses the framed archive and restores files under `dest`.
pub struct FolderWriter {
    dest: PathBuf,
    /// `dest` with every symlink resolved, computed once it exists. Restored
    /// files are checked against THIS, not the lexical path, so a directory
    /// link already sitting inside the destination cannot redirect a write.
    canonical_dest: Option<PathBuf>,
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
            canonical_dest: None,
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
            let name = safe_archive_component(part, cfg!(windows))?;
            // Belt and braces: whatever the rules above produced, the platform
            // itself must read it back as exactly one ordinary component. This
            // is the check that would have caught the original bug, and it
            // keeps catching anything a future platform quirk slips past.
            let mut components = Path::new(&name).components();
            match (components.next(), components.next()) {
                (Some(Component::Normal(single)), None)
                    if single == std::ffi::OsStr::new(name.as_str()) => {}
                _ => return Err(unsafe_archive_path()),
            }
            target.push(name);
        }
        if target == self.dest || !target.starts_with(&self.dest) {
            return Err(unsafe_archive_path());
        }
        Ok(target)
    }

    /// The destination with symlinks resolved, creating it on first use.
    fn canonical_dest(&mut self) -> io::Result<PathBuf> {
        if let Some(canonical) = self.canonical_dest.as_ref() {
            return Ok(canonical.clone());
        }
        std::fs::create_dir_all(&self.dest)?;
        let canonical = self.dest.canonicalize()?;
        self.canonical_dest = Some(canonical.clone());
        Ok(canonical)
    }

    fn begin_file(&mut self) -> io::Result<()> {
        let target = self.safe_join(&self.rel_path)?;
        let canonical_dest = self.canonical_dest()?;
        let parent = target.parent().ok_or_else(unsafe_archive_path)?;
        std::fs::create_dir_all(parent)?;
        // The lexical check in `safe_join` cannot see links. Resolve the
        // directory the file is about to be created in and require it to still
        // be inside the destination.
        if !parent.canonicalize()?.starts_with(&canonical_dest) {
            return Err(unsafe_archive_path());
        }
        // Never write THROUGH a link at the final component either: creating a
        // file follows it and would overwrite whatever it points at.
        if let Ok(existing) = std::fs::symlink_metadata(&target) {
            if existing.file_type().is_symlink() || existing.is_dir() {
                return Err(unsafe_archive_path());
            }
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
    use crate::crypto::hybrid_kex::encapsulate;
    use crate::crypto::signatures::{dual_sign, LocalSigningKeypair};
    use std::io::Cursor;

    /// Everything an unlocked vault on one device holds, as the commands see it.
    struct TestVault {
        /// Device hybrid KEM keys (legacy v1–v4 envelopes hang off these).
        kems: Vec<LocalKemKeypair>,
        /// The device's messaging identity signer (signs legacy v1/v2 headers).
        device_signer: LocalSigningKeypair,
        /// The vault's own ML-DSA-87 signer.
        signer: VaultSigningKeypair,
        /// Raw Vault Master Key — what a legacy v3/v4 device wrap yields.
        vmk: [u8; KEY_SIZE],
        /// PIN-bound vault key — the only way into a v5 container.
        vault_key: [u8; KEY_SIZE],
    }

    impl TestVault {
        fn new() -> Self {
            Self {
                kems: vec![LocalKemKeypair::generate()],
                device_signer: LocalSigningKeypair::generate(),
                signer: VaultSigningKeypair::generate(),
                vmk: symmetric::random_key(),
                vault_key: symmetric::random_key(),
            }
        }

        fn kem(&self) -> &LocalKemKeypair {
            &self.kems[0]
        }

        fn seal(&self) -> OwnerSeal<'_> {
            OwnerSeal {
                user_id: "user-1",
                device_id: "device-1",
                vault_key: &self.vault_key,
                vault_signer: &self.signer,
                recovery_wrap_key: None,
                enterprise: None,
            }
        }

        fn access(&self) -> OwnerAccess<'_> {
            OwnerAccess {
                vault_key: &self.vault_key,
                legacy_vmk: &self.vmk,
                vault_signer: &self.signer,
                device_kems: &self.kems,
                device_signer: Some((
                    self.device_signer.ed25519_public.as_slice(),
                    self.device_signer.mldsa_public.as_slice(),
                )),
                allow_unrecognized_legacy_signer: false,
            }
        }
    }

    fn encrypt_with(plaintext: &[u8], owner: &OwnerSeal, sharing: Option<&SharingOptions>) -> Vec<u8> {
        let mut out = Vec::new();
        encrypt_stream_with_progress(
            &mut Cursor::new(plaintext.to_vec()),
            &mut out,
            KIND_FILE,
            "secret.bin",
            "application/octet-stream",
            plaintext.len() as u64,
            owner,
            sharing,
            &mut |_| {},
        )
        .unwrap();
        out
    }

    fn encrypt_bytes(plaintext: &[u8], vault: &TestVault) -> Vec<u8> {
        encrypt_with(plaintext, &vault.seal(), None)
    }

    fn open(container: &[u8], access: &OwnerAccess) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        decrypt_stream_owner(&mut Cursor::new(container.to_vec()), &mut out, access)?;
        Ok(out)
    }

    fn header_of(container: &[u8]) -> StreamHeader {
        read_and_verify_header(&mut Cursor::new(container.to_vec())).unwrap()
    }

    fn error_text<T>(result: Result<T>) -> String {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(error) => error.to_string(),
        }
    }

    /// Serialize `header` and append `plaintext` as AAD-bound chunk frames.
    fn assemble(header: &StreamHeader, file_key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Vec<u8> {
        let header_json = serde_json::to_vec(header).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(header_json.len() as u32).to_be_bytes());
        out.extend_from_slice(&header_json);
        let mut index = 0u64;
        for chunk in plaintext.chunks(CHUNK_SIZE) {
            let is_last = index + 1 == header.total_chunks;
            let aad = chunk_aad(&header.file_id, index, header.total_chunks, is_last);
            let env = symmetric::encrypt(file_key, chunk, &aad).unwrap();
            write_chunk_frame(&mut out, &env).unwrap();
            index += 1;
        }
        out
    }

    /// Re-serialize a (possibly edited) header in front of a container's
    /// existing chunk frames.
    fn with_header(container: &[u8], header: &StreamHeader) -> Vec<u8> {
        let old_len = u32::from_be_bytes(container[8..12].try_into().unwrap()) as usize;
        let header_json = serde_json::to_vec(header).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(header_json.len() as u32).to_be_bytes());
        out.extend_from_slice(&header_json);
        out.extend_from_slice(&container[12 + old_len..]);
        out
    }

    /// Build a legacy v2 container by hand (FEK wrapped directly to the device,
    /// ML-DSA-65 signature by the device identity) — the shape builds before
    /// the Vault Master Key produced.
    fn build_v2_container(
        plaintext: &[u8],
        kem: &LocalKemKeypair,
        signer: &LocalSigningKeypair,
        recovery_wrap_key: Option<&[u8; KEY_SIZE]>,
    ) -> Vec<u8> {
        let file_id = Uuid::new_v4().to_string();
        let owner_user_id = "user-1";
        let owner_device_id = "device-1";
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
            total_chunks: total_chunks_for(plaintext.len() as u64),
            owner_user_id: owner_user_id.to_string(),
            owner_device_id: owner_device_id.to_string(),
            hybrid_ciphertext,
            wrapped_key,
            recovery_wrapped_key,
            recovery_kem_wrap: None,
            fek_wrapped_by_vmk: None,
            suite: AlgorithmSuite {
                kem_combiner: String::new(),
                ..AlgorithmSuite::default()
            },
            signer_ed25519_public: signer.ed25519_public.clone(),
            signer_mldsa_public: signer.mldsa_public.clone(),
            signer_mldsa87_public: Vec::new(),
            header_signature: DualSignature { ed25519: Vec::new(), ml_dsa_65: Vec::new() },
            header_signature_v3: None,
            recipient_wraps: Vec::new(),
            sender_identity: None,
        };
        let signable = header_signable(&header);
        header.header_signature =
            dual_sign(&signer.ed25519_secret, &signer.mldsa_secret, &signable).unwrap();

        let out = assemble(&header, &file_key, plaintext);
        file_key.zeroize();
        out
    }

    /// A recipient wrap exactly as the v4 writer produced it (legacy combiner).
    fn legacy_recipient_wrap(
        recipient: &portable_identity::RecipientPublicKeys,
        file_key: &[u8; KEY_SIZE],
        file_id: &str,
        owner_user_id: &str,
    ) -> RecipientWrap {
        let (kem_ciphertext, mut shared) = encapsulate(
            &recipient.x25519_public,
            &recipient.mlkem_public,
            &crate::security::obf::portable_identity_kem_info(),
        )
        .unwrap();
        let salt = [7u8; 16];
        let mut wrap_key = crate::crypto::kdf::derive_32_with_salt(
            &salt,
            &shared,
            &crate::security::obf::portable_identity_wrap_info(),
        )
        .unwrap();
        shared.zeroize();
        let wrapped_key = symmetric::encrypt(
            &wrap_key,
            file_key,
            &recipient_wrap_aad(file_id, owner_user_id, &recipient.fingerprint),
        )
        .unwrap();
        wrap_key.zeroize();
        RecipientWrap {
            recipient_fingerprint: recipient.fingerprint.clone(),
            label: recipient.label.clone().unwrap_or_default(),
            algorithm: format!("X25519+{}/HKDF-SHA3-256/AES-256-GCM", kem_ciphertext.suite.pq_kem),
            kem_ciphertext,
            salt: salt.to_vec(),
            wrapped_key,
        }
    }

    /// Build a legacy v3 container by hand — or v4 when `recipients` is not
    /// empty — exactly as the previous writer did: FEK under the Vault Master
    /// Key, and the VMK itself wrapped to the device hybrid KEM in the header.
    /// This is the shape v5 exists to replace; the reader must keep opening it.
    #[allow(clippy::too_many_arguments)]
    fn build_legacy_vmk_container(
        plaintext: &[u8],
        kem: &LocalKemKeypair,
        vmk: &[u8; KEY_SIZE],
        signer: &VaultSigningKeypair,
        recovery_wrap_key: Option<&[u8; KEY_SIZE]>,
        recipients: &[portable_identity::RecipientPublicKeys],
        sender: Option<&portable_identity::PortableIdentity>,
    ) -> Vec<u8> {
        let file_id = Uuid::new_v4().to_string();
        let owner_user_id = "user-1";
        let owner_device_id = "device-1";
        let mut file_key = symmetric::random_key();
        let fek_wrapped_by_vmk = Some(
            symmetric::encrypt(vmk, &file_key, &fek_vmk_wrap_aad(&file_id, owner_user_id)).unwrap(),
        );
        let (hybrid_ciphertext, mut wrapping_secret) = encapsulate(
            &kem.x25519_public,
            &kem.mlkem_public,
            &crate::security::obf::vault_stream_wrap_info(),
        )
        .unwrap();
        let wrapped_key = symmetric::encrypt(
            &wrapping_secret,
            vmk,
            &wrap_aad_bytes(&file_id, owner_user_id, owner_device_id),
        )
        .unwrap();
        wrapping_secret.zeroize();
        let recovery_wrapped_key = recovery_wrap_key
            .map(|k| vault_recovery::wrap_file_key(k, vmk, &file_id, owner_user_id).unwrap());
        let recipient_wraps: Vec<RecipientWrap> = recipients
            .iter()
            .map(|recipient| legacy_recipient_wrap(recipient, &file_key, &file_id, owner_user_id))
            .collect();
        let version: u8 = if recipient_wraps.is_empty() { 3 } else { 4 };
        let sender_identity = sender.filter(|_| version == 4).map(|identity| SenderIdentity {
            x25519_public: identity.kem.x25519_public.clone(),
            mlkem_public: identity.kem.mlkem_public.clone(),
            attestation: portable_identity::SenderAttestation {
                identity_fingerprint: identity.fingerprint(),
                label: identity.label.clone().unwrap_or_default(),
                signature_algorithm: identity.signature_algorithm().to_string(),
                ed25519_public: identity.signer.ed25519_public.clone(),
                mldsa_public: identity.signer.mldsa87_public.clone(),
                ed25519_signature: Vec::new(),
                mldsa_signature: Vec::new(),
            },
        });

        let mut header = StreamHeader {
            version,
            file_id: file_id.clone(),
            kind: KIND_FILE.to_string(),
            name: "legacy-vmk.bin".to_string(),
            content_type: "application/octet-stream".to_string(),
            original_size: plaintext.len() as u64,
            chunk_size: CHUNK_SIZE as u32,
            total_chunks: total_chunks_for(plaintext.len() as u64),
            owner_user_id: owner_user_id.to_string(),
            owner_device_id: owner_device_id.to_string(),
            hybrid_ciphertext,
            wrapped_key,
            recovery_wrapped_key,
            recovery_kem_wrap: None,
            fek_wrapped_by_vmk,
            suite: AlgorithmSuite {
                pq_signature: "ML-DSA-87".to_string(),
                kem_combiner: String::new(),
                ..AlgorithmSuite::default()
            },
            signer_ed25519_public: signer.ed25519_public.clone(),
            signer_mldsa_public: Vec::new(),
            signer_mldsa87_public: signer.mldsa87_public.clone(),
            header_signature: DualSignature { ed25519: Vec::new(), ml_dsa_65: Vec::new() },
            header_signature_v3: None,
            recipient_wraps,
            sender_identity,
        };
        if let (Some(identity), true) = (sender, header.sender_identity.is_some()) {
            let bytes = attestation_signable(&header);
            header.sender_identity.as_mut().unwrap().attestation =
                portable_identity::attest(identity, &bytes).unwrap();
        }
        header.header_signature_v3 = Some(
            dual_sign_87(&signer.ed25519_secret, &signer.mldsa87_secret, &header_signable(&header))
                .unwrap(),
        );

        let out = assemble(&header, &file_key, plaintext);
        file_key.zeroize();
        out
    }

    fn legacy_v3(plaintext: &[u8], vault: &TestVault) -> Vec<u8> {
        build_legacy_vmk_container(plaintext, vault.kem(), &vault.vmk, &vault.signer, None, &[], None)
    }

    // --- v5: the PIN-bound envelope ------------------------------------------

    #[test]
    fn a_new_container_is_v5_and_carries_no_device_wrap() {
        let vault = TestVault::new();
        let plaintext = vec![1u8; CHUNK_SIZE + 5];
        let sealed = encrypt_bytes(&plaintext, &vault);

        let header = header_of(&sealed);
        assert_eq!(header.version, STREAM_VERSION);
        assert_eq!(header.version, 5);
        assert_eq!(header.suite.pq_signature, "ML-DSA-87");
        assert!(header.header_signature_v3.is_some());
        assert!(header.fek_wrapped_by_vmk.is_some());
        // The whole point of v5: nothing in the header is sealed to the device.
        assert!(header.hybrid_ciphertext.x25519_ephemeral_public.is_empty());
        assert!(header.hybrid_ciphertext.ml_kem_ciphertext.is_empty());
        assert!(header.wrapped_key.ciphertext.is_empty());
        assert!(header.recovery_wrapped_key.is_none());
        assert!(header.recovery_kem_wrap.is_none());

        let mut restored = Vec::new();
        let summary =
            decrypt_stream_owner(&mut Cursor::new(sealed), &mut restored, &vault.access()).unwrap();
        assert_eq!(restored, plaintext);
        assert_eq!(summary.container_version, 5);
        assert!(summary.pin_bound);
    }

    #[test]
    fn the_device_key_alone_cannot_open_a_v5_container() {
        // THE regression test for the audit finding. Before v5, holding the
        // device KEM secret (which only the OS-keychain storage key protects)
        // was enough to unwrap the Vault Master Key from any header, so the
        // vault password gated nothing. Hand an attacker every device key and
        // the raw VMK and the vault's public signer, but NOT the PIN-bound
        // vault key: the container must stay shut.
        let vault = TestVault::new();
        let sealed = encrypt_bytes(b"gated by the vault unlock secret", &vault);
        let header = header_of(&sealed);

        assert!(device_unwrap(&header, &vault.kems).is_err());

        let guessed_key = symmetric::random_key();
        let attacker = OwnerAccess { vault_key: &guessed_key, ..vault.access() };
        let message = error_text(open(&sealed, &attacker));
        assert!(message.contains(FOREIGN_VAULT_MARKER), "got: {message}");

        // The raw VMK is not the vault key either.
        let vmk_as_key = OwnerAccess { vault_key: &vault.vmk, ..vault.access() };
        assert!(open(&sealed, &vmk_as_key).is_err());
    }

    #[test]
    fn a_v5_container_from_another_vault_is_refused_even_with_the_right_key() {
        // Both halves of the v5 rule are enforced on their own: here the key
        // would open the wrap, but the header is not signed by this vault.
        let vault = TestVault::new();
        let other_signer = VaultSigningKeypair::generate();
        let foreign = encrypt_with(
            b"signed by someone else",
            &OwnerSeal { vault_signer: &other_signer, ..vault.seal() },
            None,
        );
        let message = error_text(open(&foreign, &vault.access()));
        assert!(message.contains(FOREIGN_VAULT_MARKER), "got: {message}");
    }

    #[test]
    fn rewriting_a_v5_header_and_re_signing_it_does_not_get_past_the_owner() {
        // The header signature is checked with the key the header carries, so an
        // attacker can always re-sign a doctored header. What they cannot do is
        // sign it as THIS vault — and that is what the owner path requires.
        let vault = TestVault::new();
        let sealed = encrypt_bytes(b"original", &vault);
        let mut header = header_of(&sealed);
        let attacker = VaultSigningKeypair::generate();
        header.name = "payroll-final.xlsx".to_string();
        header.kind = KIND_FOLDER.to_string();
        header.signer_ed25519_public = attacker.ed25519_public.clone();
        header.signer_mldsa87_public = attacker.mldsa87_public.clone();
        header.header_signature_v3 = Some(
            dual_sign_87(&attacker.ed25519_secret, &attacker.mldsa87_secret, &header_signable(&header))
                .unwrap(),
        );
        let doctored = with_header(&sealed, &header);

        // Self-consistent, so the bare header check passes...
        assert!(read_and_verify_header(&mut Cursor::new(doctored.clone())).is_ok());
        // ...and the owner path refuses it.
        let message = error_text(open(&doctored, &vault.access()));
        assert!(message.contains(FOREIGN_VAULT_MARKER), "got: {message}");
    }

    #[test]
    fn recovery_key_decrypts_without_the_vault() {
        let vault = TestVault::new();
        let root = vault_recovery::generate_recovery_root();
        let recovery_wrap_key = vault_recovery::derive_wrap_key(&root).unwrap();
        let plaintext = vec![42u8; CHUNK_SIZE + 77];
        let sealed = encrypt_with(
            &plaintext,
            &OwnerSeal { recovery_wrap_key: Some(&recovery_wrap_key), ..vault.seal() },
            None,
        );

        // The recovery key alone — no device, no vault key — restores the data.
        let mut restored = Vec::new();
        decrypt_stream_with_recovery(&mut Cursor::new(sealed.clone()), &mut restored, &recovery_wrap_key)
            .unwrap();
        assert_eq!(restored, plaintext);

        // The unlocked vault still opens the same container.
        assert_eq!(open(&sealed, &vault.access()).unwrap(), plaintext);

        // A different recovery key cannot decrypt.
        let wrong = vault_recovery::derive_wrap_key(&vault_recovery::generate_recovery_root()).unwrap();
        let mut fail = Vec::new();
        assert!(decrypt_stream_with_recovery(&mut Cursor::new(sealed), &mut fail, &wrong).is_err());
    }

    #[test]
    fn the_recovery_wrap_holds_the_file_key_not_a_vault_wide_key() {
        // v3/v4 put the Vault Master Key under the recovery key in every header.
        // v5 seals only this file's key, so what the recovery envelope yields
        // must not open a second container from the same vault.
        let vault = TestVault::new();
        let recovery_wrap_key =
            vault_recovery::derive_wrap_key(&vault_recovery::generate_recovery_root()).unwrap();
        let owner = OwnerSeal { recovery_wrap_key: Some(&recovery_wrap_key), ..vault.seal() };
        let first = header_of(&encrypt_with(b"file one", &owner, None));
        let second = header_of(&encrypt_with(b"file two", &owner, None));

        let first_key = recovery_file_key(&first, &recovery_wrap_key).unwrap();
        assert_ne!(first_key.as_slice(), vault.vault_key.as_slice());
        assert!(symmetric::decrypt(
            &first_key,
            second.fek_wrapped_by_vmk.as_ref().unwrap(),
            &fek_vault_key_wrap_aad(&second.file_id, &second.owner_user_id),
        )
        .is_err());
    }

    #[test]
    fn recovery_decrypt_requires_a_recovery_wrap() {
        let vault = TestVault::new();
        // Sealed without recovery -> recovery decrypt must fail cleanly.
        let sealed = encrypt_bytes(b"no recovery wrap here", &vault);
        let any_key = vault_recovery::derive_wrap_key(&vault_recovery::generate_recovery_root()).unwrap();
        let mut out = Vec::new();
        assert!(decrypt_stream_with_recovery(&mut Cursor::new(sealed), &mut out, &any_key).is_err());
    }

    #[test]
    fn enterprise_and_hybrid_recovery_round_trip() {
        let vault = TestVault::new();
        let enterprise = vault_recovery::generate_enterprise_keypair();
        let plaintext = vec![9u8; CHUNK_SIZE + 33];

        // Enterprise-only.
        let out = encrypt_with(
            &plaintext,
            &OwnerSeal {
                enterprise: Some(EnterpriseRecipient {
                    x25519_public: &enterprise.x25519_public,
                    mlkem_public: &enterprise.mlkem_public,
                    recovery_secret: None,
                }),
                ..vault.seal()
            },
            None,
        );
        let mut via_ent = Vec::new();
        decrypt_stream_with_enterprise(&mut Cursor::new(out.clone()), &mut via_ent, &enterprise, None)
            .unwrap();
        assert_eq!(via_ent, plaintext);
        assert_eq!(open(&out, &vault.access()).unwrap(), plaintext);
        // The enterprise wrap of a v5 container uses the transcript-bound combiner.
        assert_eq!(
            header_of(&out).recovery_kem_wrap.unwrap().kem_ciphertext.suite.kem_combiner,
            crate::crypto::CURRENT_KEM_COMBINER
        );

        // Hybrid requires BOTH the enterprise key and the recovery root.
        let root = vault_recovery::generate_recovery_root();
        let hout = encrypt_with(
            &plaintext,
            &OwnerSeal {
                enterprise: Some(EnterpriseRecipient {
                    x25519_public: &enterprise.x25519_public,
                    mlkem_public: &enterprise.mlkem_public,
                    recovery_secret: Some(&root),
                }),
                ..vault.seal()
            },
            None,
        );
        let mut hok = Vec::new();
        decrypt_stream_with_enterprise(&mut Cursor::new(hout.clone()), &mut hok, &enterprise, Some(&root))
            .unwrap();
        assert_eq!(hok, plaintext);
        let mut hfail = Vec::new();
        assert!(
            decrypt_stream_with_enterprise(&mut Cursor::new(hout), &mut hfail, &enterprise, None).is_err()
        );
    }

    // --- Legacy containers: still readable, but only as this vault's own ------

    #[test]
    fn legacy_v2_container_still_decrypts() {
        let vault = TestVault::new();
        let root = vault_recovery::generate_recovery_root();
        let recovery_wrap_key = vault_recovery::derive_wrap_key(&root).unwrap();
        let plaintext = vec![8u8; CHUNK_SIZE + 17];
        let legacy =
            build_v2_container(&plaintext, vault.kem(), &vault.device_signer, Some(&recovery_wrap_key));

        let header = header_of(&legacy);
        assert_eq!(header.version, 2);
        assert!(header.fek_wrapped_by_vmk.is_none());

        // Both the device key and the recovery key still decrypt it, and it is
        // honestly reported as NOT PIN-bound.
        let mut via_device = Vec::new();
        let summary =
            decrypt_stream_owner(&mut Cursor::new(legacy.clone()), &mut via_device, &vault.access())
                .unwrap();
        assert_eq!(via_device, plaintext);
        assert_eq!(summary.container_version, 2);
        assert!(!summary.pin_bound);
        let mut via_recovery = Vec::new();
        decrypt_stream_with_recovery(&mut Cursor::new(legacy), &mut via_recovery, &recovery_wrap_key)
            .unwrap();
        assert_eq!(via_recovery, plaintext);
    }

    #[test]
    fn a_legacy_v2_container_from_an_unrecognised_signer_needs_explicit_consent() {
        // v1/v2 have no vault key to prove ownership with — only the device
        // identity's signature. A header signed by any other key is what a file
        // built by someone else (to this device's PUBLISHED KEM key) looks like.
        let vault = TestVault::new();
        let stranger = LocalSigningKeypair::generate();
        let plaintext = b"sealed to this device, signed by who knows".to_vec();
        let legacy = build_v2_container(&plaintext, vault.kem(), &stranger, None);

        let message = error_text(open(&legacy, &vault.access()));
        assert!(message.contains(UNRECOGNIZED_SIGNER_MARKER), "got: {message}");

        // No loaded identity is not a free pass either.
        let no_identity = OwnerAccess { device_signer: None, ..vault.access() };
        assert!(error_text(open(&legacy, &no_identity)).contains(UNRECOGNIZED_SIGNER_MARKER));

        // With the user's explicit consent it opens (a real pre-re-key file).
        let consented = OwnerAccess { allow_unrecognized_legacy_signer: true, ..vault.access() };
        assert_eq!(open(&legacy, &consented).unwrap(), plaintext);
    }

    #[test]
    fn legacy_v3_container_still_decrypts_for_its_own_vault() {
        let vault = TestVault::new();
        let plaintext = vec![3u8; CHUNK_SIZE + 9];
        let legacy = legacy_v3(&plaintext, &vault);

        let header = header_of(&legacy);
        assert_eq!(header.version, 3);
        assert!(!header.hybrid_ciphertext.ml_kem_ciphertext.is_empty());

        let mut restored = Vec::new();
        let summary =
            decrypt_stream_owner(&mut Cursor::new(legacy), &mut restored, &vault.access()).unwrap();
        assert_eq!(restored, plaintext);
        assert_eq!(summary.container_version, 3);
        assert!(!summary.pin_bound);
    }

    #[test]
    fn a_container_forged_to_the_device_public_key_is_refused() {
        // The device KEM public key is published, so anyone can produce a
        // well-formed, validly self-signed v3 container that this device CAN
        // decapsulate. Before the fix it then decrypted and was reported as
        // "Header verified". It must be refused: it does not yield this vault's
        // master key and is not signed by this vault.
        let vault = TestVault::new();
        let attacker_vmk = symmetric::random_key();
        let attacker_signer = VaultSigningKeypair::generate();
        let forged = build_legacy_vmk_container(
            b"planted content",
            vault.kem(),
            &attacker_vmk,
            &attacker_signer,
            None,
            &[],
            None,
        );
        // It really is decapsulable by the victim — that is why this matters.
        assert!(device_unwrap(&header_of(&forged), &vault.kems).is_ok());

        let message = error_text(open(&forged, &vault.access()));
        assert!(message.contains(FOREIGN_VAULT_MARKER), "got: {message}");

        // Each half of the rule holds on its own. Right signer, wrong VMK
        // (only possible in a test — the attacker cannot sign as the vault):
        let wrong_vmk = build_legacy_vmk_container(
            b"x", vault.kem(), &attacker_vmk, &vault.signer, None, &[], None,
        );
        assert!(error_text(open(&wrong_vmk, &vault.access())).contains(FOREIGN_VAULT_MARKER));
        // Right VMK, wrong signer:
        let wrong_signer = build_legacy_vmk_container(
            b"x", vault.kem(), &vault.vmk, &attacker_signer, None, &[], None,
        );
        assert!(error_text(open(&wrong_signer, &vault.access())).contains(FOREIGN_VAULT_MARKER));
        // And consent to an unknown v1/v2 signer never extends to v3+.
        let consented = OwnerAccess { allow_unrecognized_legacy_signer: true, ..vault.access() };
        assert!(error_text(open(&forged, &consented)).contains(FOREIGN_VAULT_MARKER));
    }

    #[test]
    fn a_vault_reset_is_not_a_way_around_the_old_lock() {
        // "Forgot PIN -> start fresh" installs a NEW master. The device keys do
        // not change, so before the fix every pre-reset file still opened
        // through the device wrap — the reset was a bypass of the forgotten
        // secret. Now a pre-reset container no longer matches the unlocked
        // vault, and only the recovery key gets back in.
        let before = TestVault::new();
        let recovery_wrap_key =
            vault_recovery::derive_wrap_key(&vault_recovery::generate_recovery_root()).unwrap();
        let plaintext = vec![5u8; 4096];
        let old_file = build_legacy_vmk_container(
            &plaintext,
            before.kem(),
            &before.vmk,
            &before.signer,
            Some(&recovery_wrap_key),
            &[],
            None,
        );
        let old_v5 = encrypt_with(
            &plaintext,
            &OwnerSeal { recovery_wrap_key: Some(&recovery_wrap_key), ..before.seal() },
            None,
        );

        // Same device (same KEM keys, same identity signer), new vault master.
        let after = TestVault {
            kems: before.kems.clone(),
            device_signer: before.device_signer.clone(),
            signer: VaultSigningKeypair::generate(),
            vmk: symmetric::random_key(),
            vault_key: symmetric::random_key(),
        };
        for pre_reset in [&old_file, &old_v5] {
            let message = error_text(open(pre_reset, &after.access()));
            assert!(message.contains(FOREIGN_VAULT_MARKER), "got: {message}");
            // The documented way back in still works.
            let mut recovered = Vec::new();
            decrypt_stream_with_recovery(
                &mut Cursor::new(pre_reset.to_vec()),
                &mut recovered,
                &recovery_wrap_key,
            )
            .unwrap();
            assert_eq!(recovered, plaintext);
        }
    }

    #[test]
    fn a_container_sealed_to_a_rotated_device_key_still_opens() {
        // The current KEM key is tried first, then the retained older ones.
        let mut vault = TestVault::new();
        let plaintext = b"sealed before the device key rotated".to_vec();
        let legacy = legacy_v3(&plaintext, &vault);
        vault.kems.insert(0, LocalKemKeypair::generate());
        assert_eq!(open(&legacy, &vault.access()).unwrap(), plaintext);
    }

    // --- Re-protect: every generation becomes v5 ------------------------------

    #[test]
    fn re_protecting_a_legacy_container_binds_it_to_the_vault_key() {
        let vault = TestVault::new();
        let plaintext = vec![5u8; CHUNK_SIZE + 21];
        let original = legacy_v3(&plaintext, &vault);
        let recovery_wrap_key =
            vault_recovery::derive_wrap_key(&vault_recovery::generate_recovery_root()).unwrap();

        // Cannot be recovered before re-protecting (it had no recovery wrap).
        let mut fail = Vec::new();
        assert!(decrypt_stream_with_recovery(
            &mut Cursor::new(original.clone()),
            &mut fail,
            &recovery_wrap_key
        )
        .is_err());

        let mut rewrapped = Vec::new();
        let summary = rewrap_stream(
            &mut Cursor::new(original.clone()),
            &mut rewrapped,
            &vault.access(),
            &OwnerSeal { recovery_wrap_key: Some(&recovery_wrap_key), ..vault.seal() },
        )
        .unwrap();
        assert_eq!(summary.container_version, 5);
        assert!(summary.pin_bound);

        let header = header_of(&rewrapped);
        assert_eq!(header.version, 5);
        // The device wrap — the thing that made the old file openable without
        // the vault password — is gone...
        assert!(header.hybrid_ciphertext.ml_kem_ciphertext.is_empty());
        assert!(device_unwrap(&header, &vault.kems).is_err());
        // ...the bulk data was copied verbatim, not re-encrypted...
        let old_header_len = u32::from_be_bytes(original[8..12].try_into().unwrap()) as usize;
        let new_header_len = u32::from_be_bytes(rewrapped[8..12].try_into().unwrap()) as usize;
        assert_eq!(original[12 + old_header_len..], rewrapped[12 + new_header_len..]);
        // ...and both the vault and the recovery key open the result.
        assert_eq!(open(&rewrapped, &vault.access()).unwrap(), plaintext);
        let mut via_recovery = Vec::new();
        decrypt_stream_with_recovery(&mut Cursor::new(rewrapped), &mut via_recovery, &recovery_wrap_key)
            .unwrap();
        assert_eq!(via_recovery, plaintext);
    }

    #[test]
    fn re_protect_upgrades_a_legacy_v2_container_to_v5() {
        let vault = TestVault::new();
        let plaintext = vec![6u8; CHUNK_SIZE + 9];
        let legacy = build_v2_container(&plaintext, vault.kem(), &vault.device_signer, None);

        let mut upgraded = Vec::new();
        rewrap_stream(&mut Cursor::new(legacy), &mut upgraded, &vault.access(), &vault.seal()).unwrap();

        let header = header_of(&upgraded);
        assert_eq!(header.version, 5);
        assert_eq!(header.suite.pq_signature, "ML-DSA-87");
        assert!(header.fek_wrapped_by_vmk.is_some());
        assert_eq!(open(&upgraded, &vault.access()).unwrap(), plaintext);
    }

    #[test]
    fn re_protect_can_add_recovery_to_a_v5_container() {
        let vault = TestVault::new();
        let plaintext = b"sealed before recovery was configured".to_vec();
        let original = encrypt_bytes(&plaintext, &vault);
        let recovery_wrap_key =
            vault_recovery::derive_wrap_key(&vault_recovery::generate_recovery_root()).unwrap();

        let mut rewrapped = Vec::new();
        rewrap_stream(
            &mut Cursor::new(original),
            &mut rewrapped,
            &vault.access(),
            &OwnerSeal { recovery_wrap_key: Some(&recovery_wrap_key), ..vault.seal() },
        )
        .unwrap();
        let mut via_recovery = Vec::new();
        decrypt_stream_with_recovery(&mut Cursor::new(rewrapped), &mut via_recovery, &recovery_wrap_key)
            .unwrap();
        assert_eq!(via_recovery, plaintext);
    }

    #[test]
    fn re_protect_refuses_to_launder_a_container_that_is_not_this_vaults() {
        // Re-protect re-signs with the vault's own key. If it accepted a forged
        // container it would turn it into a genuine one.
        let vault = TestVault::new();
        let forged = build_legacy_vmk_container(
            b"planted",
            vault.kem(),
            &symmetric::random_key(),
            &VaultSigningKeypair::generate(),
            None,
            &[],
            None,
        );
        let mut out = Vec::new();
        let result = rewrap_stream(&mut Cursor::new(forged), &mut out, &vault.access(), &vault.seal());
        assert!(error_text(result).contains(FOREIGN_VAULT_MARKER));
        assert!(out.is_empty(), "nothing may be written for a refused container");

        // A device that cannot unwrap it at all fails too.
        let elsewhere = TestVault::new();
        let theirs = legacy_v3(b"locked to a device we don't have", &elsewhere);
        let unreachable = OwnerAccess {
            vault_signer: &elsewhere.signer,
            legacy_vmk: &elsewhere.vmk,
            ..vault.access()
        };
        let mut out = Vec::new();
        assert!(rewrap_stream(&mut Cursor::new(theirs), &mut out, &unreachable, &vault.seal()).is_err());
    }

    // --- Stream mechanics ------------------------------------------------------

    #[test]
    fn roundtrip_across_chunk_boundaries() {
        let vault = TestVault::new();
        for size in [0usize, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, CHUNK_SIZE * 2 + 123] {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let sealed = encrypt_bytes(&plaintext, &vault);
            let mut restored = Vec::new();
            let summary =
                decrypt_stream_owner(&mut Cursor::new(sealed), &mut restored, &vault.access()).unwrap();
            assert_eq!(restored, plaintext, "roundtrip failed for size {size}");
            assert_eq!(summary.original_size, size as u64);
            assert_eq!(summary.total_chunks, total_chunks_for(size as u64));
        }
    }

    #[test]
    fn tampered_chunk_is_rejected() {
        let vault = TestVault::new();
        let plaintext = vec![7u8; CHUNK_SIZE + 10];
        let mut sealed = encrypt_bytes(&plaintext, &vault);
        // Flip a byte well past the header, inside a chunk frame.
        let last = sealed.len() - 1;
        sealed[last] ^= 0x80;
        assert!(open(&sealed, &vault.access()).is_err());
    }

    #[test]
    fn truncated_stream_is_rejected() {
        let vault = TestVault::new();
        let plaintext = vec![3u8; CHUNK_SIZE * 2];
        let sealed = encrypt_bytes(&plaintext, &vault);
        assert!(open(&sealed[..sealed.len() - 100], &vault.access()).is_err());
        // Dropping the final chunk whole (a clean frame boundary) is caught too:
        // every chunk's AAD binds the total count and whether it is the last.
        let header_len = u32::from_be_bytes(sealed[8..12].try_into().unwrap()) as usize;
        let frame = 4 + symmetric::NONCE_SIZE + symmetric::TAG_SIZE + CHUNK_SIZE;
        assert!(open(&sealed[..12 + header_len + frame], &vault.access()).is_err());
    }

    #[test]
    fn a_wrong_device_key_cannot_open_a_legacy_container() {
        let vault = TestVault::new();
        let legacy = legacy_v3(b"top secret", &vault);
        let other_device = vec![LocalKemKeypair::generate()];
        let access = OwnerAccess { device_kems: &other_device, ..vault.access() };
        assert!(open(&legacy, &access).is_err());
    }

    #[test]
    fn folder_archive_roundtrip() {
        let vault = TestVault::new();
        let root = std::env::temp_dir().join(format!("qvault-folder-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("a.txt"), b"alpha").unwrap();
        std::fs::write(root.join("nested/b.bin"), vec![9u8; CHUNK_SIZE + 5]).unwrap();
        std::fs::write(root.join("empty.dat"), b"").unwrap();

        let (entries, total) = collect_folder_entries(&root).unwrap();
        assert_eq!(entries.len(), 3);
        let mut sealed = Vec::new();
        encrypt_stream(
            &mut FolderReader::new(entries),
            &mut sealed,
            KIND_FOLDER,
            "vault-folder",
            "application/qguard-folder-archive",
            total,
            &vault.seal(),
        )
        .unwrap();

        let dest = std::env::temp_dir().join(format!("qvault-out-{}", Uuid::new_v4()));
        let mut writer = FolderWriter::new(dest.clone());
        decrypt_stream_owner(&mut Cursor::new(sealed), &mut writer, &vault.access()).unwrap();
        writer.flush().unwrap();

        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(std::fs::read(dest.join("nested/b.bin")).unwrap(), vec![9u8; CHUNK_SIZE + 5]);
        assert_eq!(std::fs::read(dest.join("empty.dat")).unwrap(), b"");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&dest);
    }

    /// One archive entry, framed exactly as `FolderReader` emits it.
    fn archive_frame(rel_path: &str, content: &[u8]) -> Vec<u8> {
        let mut framed = Vec::new();
        framed.extend_from_slice(&(rel_path.len() as u16).to_be_bytes());
        framed.extend_from_slice(rel_path.as_bytes());
        framed.extend_from_slice(&(content.len() as u64).to_be_bytes());
        framed.extend_from_slice(content);
        framed
    }

    /// Every regular file under `root`, as paths relative to it.
    fn files_under(root: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    found.push(path.strip_prefix(root).unwrap().to_path_buf());
                }
            }
        }
        found
    }

    #[test]
    fn folder_writer_rejects_path_traversal() {
        for evil in ["../escape", "a/../../escape", "/absolute", "a//b", "./here", "a/./b"] {
            let dest = std::env::temp_dir().join(format!("qvault-trav-{}", Uuid::new_v4()));
            let mut writer = FolderWriter::new(dest.clone());
            assert!(
                writer.write_all(&archive_frame(evil, b"x")).is_err(),
                "{evil:?} must be refused"
            );
            let _ = std::fs::remove_dir_all(&dest);
        }
    }

    #[test]
    fn windows_path_syntax_in_an_archive_entry_cannot_leave_the_destination() {
        // The original check split on `/` only, so each of these reached
        // `PathBuf::push` as "one component". On Windows none of them is: the
        // first climbs out, the next three are absolute or drive-relative and
        // REPLACE the destination, the last is an alternate data stream.
        for hostile in [
            r"..\..\escape.txt",
            r"C:\Windows\Temp\escape.txt",
            r"\\server\share\escape.txt",
            r"C:escape.txt",
            r"\escape.txt",
            "report.txt:hidden",
        ] {
            let name = safe_archive_component(hostile, true).unwrap();
            assert!(
                !name.contains(['\\', '/', ':']),
                "{hostile:?} kept path syntax after sanitising: {name:?}"
            );
            assert_ne!(name, "..");
        }

        // Windows strips trailing dots and spaces, so these ARE `..` / `.` by
        // the time they reach the filesystem and must be refused outright.
        for disguised in [".. ", "..  .", ". ", "...", " . "] {
            assert!(
                safe_archive_component(disguised, true).is_err(),
                "{disguised:?} must be refused under Windows rules"
            );
        }

        // Device names are devices in any directory, with any extension.
        assert_eq!(safe_archive_component("NUL", true).unwrap(), "_NUL");
        assert_eq!(safe_archive_component("con.txt", true).unwrap(), "_con.txt");
        assert_eq!(safe_archive_component("COM1.log", true).unwrap(), "_COM1.log");
        // ...but ordinary names that merely start the same way are left alone.
        assert_eq!(safe_archive_component("console.log", true).unwrap(), "console.log");
        assert_eq!(safe_archive_component("notes.txt", true).unwrap(), "notes.txt");
        assert_eq!(safe_archive_component("trailing.dot.", true).unwrap(), "trailing.dot");

        // Off Windows, `:` and `\` are ordinary file-name characters and must
        // survive untouched — a macOS screenshot name is not an attack.
        assert_eq!(
            safe_archive_component("Screenshot 12:30:00.png", false).unwrap(),
            "Screenshot 12:30:00.png"
        );
        // Traversal is refused under both rule sets.
        for rules in [true, false] {
            assert!(safe_archive_component("..", rules).is_err());
            assert!(safe_archive_component(".", rules).is_err());
            assert!(safe_archive_component("", rules).is_err());
            assert!(safe_archive_component("nul\0byte", rules).is_err());
        }
    }

    #[test]
    fn a_hostile_archive_only_ever_writes_inside_the_destination() {
        // End to end on whatever platform this runs on: feed the writer the
        // hostile names and prove that everything it created is under `dest`,
        // and that the sibling directory an escape would land in stays empty.
        let sandbox = std::env::temp_dir().join(format!("qvault-sandbox-{}", Uuid::new_v4()));
        let dest = sandbox.join("restore-here");
        let outside = sandbox.join("outside");
        std::fs::create_dir_all(&outside).unwrap();

        for hostile in [r"..\outside\pwned.txt", r"..\..\pwned.txt", "sub/..\\..\\pwned.txt"] {
            // A fresh writer per entry: a refused entry leaves the parser
            // mid-frame, which is fine for a real restore (it aborts) but would
            // make the next iteration here test nothing.
            let mut writer = FolderWriter::new(dest.clone());
            // Either refused or neutralised — never allowed to escape.
            let _ = writer.write_all(&archive_frame(hostile, b"payload"));
            let _ = writer.flush();
        }

        assert!(files_under(&outside).is_empty(), "a write escaped the destination");
        let top_level: Vec<_> = std::fs::read_dir(&sandbox)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            top_level.iter().all(|name| name == "restore-here" || name == "outside"),
            "unexpected entries beside the destination: {top_level:?}"
        );
        let _ = std::fs::remove_dir_all(&sandbox);
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_link_inside_the_destination_cannot_redirect_a_restore() {
        let sandbox = std::env::temp_dir().join(format!("qvault-link-{}", Uuid::new_v4()));
        let dest = sandbox.join("restore-here");
        let outside = sandbox.join("outside");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        // `dest/escape` already exists and points out of the destination.
        std::os::unix::fs::symlink(&outside, dest.join("escape")).unwrap();
        // So does a FILE link at a name the archive is about to write.
        std::fs::write(outside.join("victim.txt"), b"original").unwrap();
        std::os::unix::fs::symlink(outside.join("victim.txt"), dest.join("linked.txt")).unwrap();

        let mut writer = FolderWriter::new(dest.clone());
        assert!(writer.write_all(&archive_frame("escape/pwned.txt", b"x")).is_err());
        let mut writer = FolderWriter::new(dest.clone());
        assert!(writer.write_all(&archive_frame("linked.txt", b"overwritten")).is_err());

        assert!(!outside.join("pwned.txt").exists());
        assert_eq!(std::fs::read(outside.join("victim.txt")).unwrap(), b"original");
        let _ = std::fs::remove_dir_all(&sandbox);
    }

    #[test]
    fn encrypt_stream_emits_monotonic_progress() {
        let vault = TestVault::new();
        let plaintext = vec![4u8; CHUNK_SIZE * 3 + 11];
        let mut out = Vec::new();
        let mut seen: Vec<VaultProgress> = Vec::new();
        encrypt_stream_with_progress(
            &mut Cursor::new(plaintext.clone()),
            &mut out,
            KIND_FILE,
            "p.bin",
            "application/octet-stream",
            plaintext.len() as u64,
            &vault.seal(),
            None,
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

        assert_eq!(open(&out, &vault.access()).unwrap(), plaintext);
    }

    #[test]
    fn verify_stream_accepts_intact_and_rejects_tampered_or_foreign_containers() {
        let vault = TestVault::new();
        let plaintext = vec![11u8; CHUNK_SIZE + 3];
        let sealed = encrypt_bytes(&plaintext, &vault);

        let mut seen: Vec<VaultProgress> = Vec::new();
        let summary = verify_stream_owner_with_progress(
            &mut Cursor::new(sealed.clone()),
            &vault.access(),
            &mut |p| seen.push(p),
        )
        .unwrap();
        assert_eq!(summary.original_size, plaintext.len() as u64);
        assert!(seen.iter().all(|p| p.op == "verify"), "verify must relabel every event");
        assert_eq!(seen.last().map(|p| p.phase.as_str()), Some("done"));

        // A single flipped ciphertext byte must fail verification.
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(verify_stream_owner_with_progress(
            &mut Cursor::new(tampered),
            &vault.access(),
            &mut |_| {}
        )
        .is_err());

        // "Verified" must mean "this vault's", so another vault cannot verify it.
        let other = TestVault::new();
        assert!(verify_stream_owner_with_progress(
            &mut Cursor::new(sealed),
            &other.access(),
            &mut |_| {}
        )
        .is_err());
    }

    #[test]
    fn decrypt_stream_emits_progress_to_completion() {
        let vault = TestVault::new();
        let plaintext = vec![2u8; CHUNK_SIZE * 2 + 7];
        let sealed = encrypt_bytes(&plaintext, &vault);
        let mut restored = Vec::new();
        let mut seen: Vec<VaultProgress> = Vec::new();
        decrypt_stream_owner_with_progress(
            &mut Cursor::new(sealed),
            &mut restored,
            &vault.access(),
            &mut |p| seen.push(p),
        )
        .unwrap();
        assert_eq!(restored, plaintext);
        let phases: Vec<&str> = seen.iter().map(|p| p.phase.as_str()).collect();
        assert!(phases.contains(&"verify"));
        assert!(phases.contains(&"decapsulate"));
        assert!(phases.contains(&"chunk"));
        assert_eq!(phases.last(), Some(&"done"));
        let done = seen.last().unwrap();
        assert_eq!(done.processed_bytes, plaintext.len() as u64);
    }

    #[test]
    fn nothing_is_written_for_a_container_that_fails_authentication() {
        let vault = TestVault::new();
        let other = TestVault::new();
        let sealed = encrypt_bytes(&vec![1u8; CHUNK_SIZE * 2], &other);
        let mut out = Vec::new();
        assert!(decrypt_stream_owner(&mut Cursor::new(sealed), &mut out, &vault.access()).is_err());
        assert!(out.is_empty());
    }

    // --- Portable Hybrid Identity sharing -------------------------------------

    fn seal_bytes(
        plaintext: &[u8],
        vault: &TestVault,
        recipients: &[portable_identity::RecipientPublicKeys],
        sender: Option<&portable_identity::PortableIdentity>,
    ) -> Vec<u8> {
        encrypt_with(plaintext, &vault.seal(), Some(&SharingOptions { recipients, sender }))
    }

    #[test]
    fn a_sealed_container_opens_with_the_recipient_identity_and_for_the_owner() {
        let vault = TestVault::new();
        let bob = portable_identity::PortableIdentity::generate(Some("Bob".to_string()));
        let plaintext = vec![7u8; CHUNK_SIZE + 4242];

        let container = seal_bytes(&plaintext, &vault, &[bob.public_keys()], None);

        // The recipient opens it with their portable identity.
        let mut out = Vec::new();
        let summary =
            decrypt_stream_with_identity(&mut Cursor::new(container.clone()), &mut out, &bob).unwrap();
        assert_eq!(out, plaintext);
        assert_eq!(summary.sealed_for.len(), 1);
        assert_eq!(summary.sealed_for[0].fingerprint, bob.fingerprint());
        assert_eq!(summary.sealed_for[0].label, "Bob");
        assert!(summary.verified_sender.is_none());

        // The owner keeps their own way into the same container.
        assert_eq!(open(&container, &vault.access()).unwrap(), plaintext);
    }

    #[test]
    fn a_recipient_cannot_open_a_container_sealed_to_someone_else() {
        let vault = TestVault::new();
        let bob = portable_identity::PortableIdentity::generate(None);
        let mallory = portable_identity::PortableIdentity::generate(None);
        let plaintext = b"top secret".to_vec();

        let container = seal_bytes(&plaintext, &vault, &[bob.public_keys()], None);

        let mut out = Vec::new();
        assert!(
            decrypt_stream_with_identity(&mut Cursor::new(container.clone()), &mut out, &mallory)
                .is_err()
        );
        assert!(out.is_empty());

        // And an ordinary owner-sealed container has no identity path at all.
        let owner_only = encrypt_bytes(&plaintext, &vault);
        let mut out = Vec::new();
        assert!(decrypt_stream_with_identity(&mut Cursor::new(owner_only), &mut out, &bob).is_err());
    }

    #[test]
    fn a_recipient_never_learns_anything_that_opens_another_container() {
        // The recipient wrap seals the per-file FEK and nothing above it:
        // unwrapping it must NOT open a second container from the same vault.
        let vault = TestVault::new();
        let bob = portable_identity::PortableIdentity::generate(None);

        let shared = seal_bytes(b"file one", &vault, &[bob.public_keys()], None);
        let other = seal_bytes(b"file two", &vault, &[], None);

        let header_shared = header_of(&shared);
        let recovered_fek = unwrap_fek_for_recipient(
            &bob,
            &header_shared.recipient_wraps[0],
            &header_shared.file_id,
            &header_shared.owner_user_id,
        )
        .unwrap();

        assert_ne!(recovered_fek, vault.vault_key);
        assert_ne!(recovered_fek, vault.vmk);

        let header_other = header_of(&other);
        assert!(symmetric::decrypt(
            &recovered_fek,
            header_other.fek_wrapped_by_vmk.as_ref().unwrap(),
            &fek_vault_key_wrap_aad(&header_other.file_id, &header_other.owner_user_id),
        )
        .is_err());
    }

    #[test]
    fn a_recipient_wrap_cannot_be_moved_into_another_container() {
        let vault = TestVault::new();
        let bob = portable_identity::PortableIdentity::generate(None);

        let sealed = seal_bytes(b"the real file", &vault, &[bob.public_keys()], None);
        let decoy = seal_bytes(b"a different file", &vault, &[bob.public_keys()], None);

        let sealed_header = header_of(&sealed);
        let decoy_header = header_of(&decoy);
        // New recipient wraps use the transcript-bound combiner.
        assert_eq!(
            sealed_header.recipient_wraps[0].kem_ciphertext.suite.kem_combiner,
            crate::crypto::CURRENT_KEM_COMBINER
        );

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
        let vault = TestVault::new();
        let alice = portable_identity::PortableIdentity::generate(Some("Alice".to_string()));
        let bob = portable_identity::PortableIdentity::generate(None);
        let plaintext = b"signed and sealed".to_vec();

        let container = seal_bytes(&plaintext, &vault, &[bob.public_keys()], Some(&alice));

        let mut out = Vec::new();
        let summary =
            decrypt_stream_with_identity(&mut Cursor::new(container.clone()), &mut out, &bob).unwrap();
        assert_eq!(out, plaintext);
        let sender = summary.verified_sender.expect("attestation must verify");
        assert_eq!(sender.fingerprint, alice.fingerprint());
        assert_eq!(sender.label, "Alice");
        assert_eq!(sender.signature_algorithm, portable_identity::SIGNATURE_ML_DSA_87);

        // Inspecting the header alone reports the same attested sender.
        let inspected = inspect_stream(&mut Cursor::new(container)).unwrap();
        assert_eq!(
            inspected.verified_sender.map(|s| s.fingerprint),
            Some(alice.fingerprint())
        );
    }

    #[test]
    fn a_forged_sender_attestation_fails_before_any_plaintext_is_written() {
        let vault = TestVault::new();
        let alice = portable_identity::PortableIdentity::generate(Some("Alice".to_string()));
        let mallory = portable_identity::PortableIdentity::generate(Some("Alice".to_string()));
        let bob = portable_identity::PortableIdentity::generate(None);

        let container = seal_bytes(b"payload", &vault, &[bob.public_keys()], Some(&alice));
        let mut header = header_of(&container);

        // Swap in Mallory's identity while keeping Alice's signature: the
        // fingerprint/key binding check must reject it.
        let sender = header.sender_identity.as_mut().unwrap();
        sender.attestation.ed25519_public = mallory.signer.ed25519_public.clone();
        sender.attestation.mldsa_public = mallory.signer.mldsa87_public.clone();
        assert!(verified_sender_for(&header).is_err());

        // Claiming a different label (part of the attested bytes) also fails.
        let mut header = header_of(&container);
        header.sender_identity.as_mut().unwrap().attestation.label = "Finance Dept".to_string();
        assert!(verified_sender_for(&header).is_err());
    }

    #[test]
    fn sealing_to_several_identities_gives_each_one_access_and_collapses_duplicates() {
        let vault = TestVault::new();
        let bob = portable_identity::PortableIdentity::generate(Some("Bob".to_string()));
        let carol = portable_identity::PortableIdentity::generate(Some("Carol".to_string()));
        let plaintext = b"team distribution".to_vec();

        let container = seal_bytes(
            &plaintext,
            &vault,
            // Bob listed twice on purpose.
            &[bob.public_keys(), carol.public_keys(), bob.public_keys()],
            None,
        );

        assert_eq!(header_of(&container).recipient_wraps.len(), 2);
        for identity in [&bob, &carol] {
            let mut out = Vec::new();
            decrypt_stream_with_identity(&mut Cursor::new(container.clone()), &mut out, identity)
                .unwrap();
            assert_eq!(out, plaintext);
        }
    }

    #[test]
    fn sealed_and_ordinary_containers_are_both_v5() {
        let vault = TestVault::new();
        let bob = portable_identity::PortableIdentity::generate(None);

        let sealed = header_of(&seal_bytes(b"x", &vault, &[bob.public_keys()], None));
        let plain = header_of(&seal_bytes(b"x", &vault, &[], None));

        assert_eq!(sealed.version, STREAM_VERSION);
        assert_eq!(sealed.recipient_wraps.len(), 1);
        assert_eq!(plain.version, STREAM_VERSION);
        assert!(plain.recipient_wraps.is_empty());
        assert!(plain.sender_identity.is_none());
    }

    #[test]
    fn recipient_material_smuggled_into_a_v3_header_is_refused() {
        // A v3 signature does not cover recipient wraps, so a v3 container that
        // declares them must be rejected rather than trusted.
        let vault = TestVault::new();
        let bob = portable_identity::PortableIdentity::generate(None);

        let legacy = legacy_v3(b"payload", &vault);
        let mut header = header_of(&legacy);
        header.recipient_wraps.push(
            wrap_fek_for_recipient(
                &bob.public_keys(),
                &symmetric::random_key(),
                &header.file_id,
                &header.owner_user_id,
            )
            .unwrap(),
        );
        // Re-sign as a genuine v3 header so only the version rule can catch it.
        header.header_signature_v3 = Some(
            dual_sign_87(
                &vault.signer.ed25519_secret,
                &vault.signer.mldsa87_secret,
                &header_signable(&header),
            )
            .unwrap(),
        );
        let forged = with_header(&legacy, &header);
        assert!(read_and_verify_header(&mut Cursor::new(forged)).is_err());
    }

    #[test]
    fn tampering_with_a_sealed_header_breaks_the_signature() {
        let vault = TestVault::new();
        let bob = portable_identity::PortableIdentity::generate(None);
        let mallory = portable_identity::PortableIdentity::generate(None);

        let sealed = seal_bytes(b"payload", &vault, &[bob.public_keys()], None);
        let mut header = header_of(&sealed);

        // Adding Mallory as a recipient without re-signing must fail the header
        // signature, because the signable bytes cover every recipient wrap.
        header.recipient_wraps.push(
            wrap_fek_for_recipient(
                &mallory.public_keys(),
                &symmetric::random_key(),
                &header.file_id,
                &header.owner_user_id,
            )
            .unwrap(),
        );
        assert!(read_and_verify_header(&mut Cursor::new(with_header(&sealed, &header))).is_err());

        // So does flipping which combiner a wrap claims to have been made with:
        // from v5 that label is inside the signature.
        let mut header = header_of(&sealed);
        header.recipient_wraps[0].kem_ciphertext.suite.kem_combiner.clear();
        assert!(read_and_verify_header(&mut Cursor::new(with_header(&sealed, &header))).is_err());
    }

    #[test]
    fn re_protecting_a_sealed_container_keeps_the_share_and_the_attestation() {
        // Re-protect rewrites the owner's envelope. Recipients and the sender
        // attestation must survive, or "re-protect" would silently revoke a
        // share. Exercised on a legacy v4 container, which is the case that
        // actually crosses a format boundary.
        let vault = TestVault::new();
        let alice = portable_identity::PortableIdentity::generate(Some("Alice".to_string()));
        let bob = portable_identity::PortableIdentity::generate(Some("Bob".to_string()));
        let plaintext = vec![3u8; 2048];

        let sealed = build_legacy_vmk_container(
            &plaintext,
            vault.kem(),
            &vault.vmk,
            &vault.signer,
            None,
            &[bob.public_keys()],
            Some(&alice),
        );
        assert_eq!(header_of(&sealed).version, 4);

        let mut rewrapped = Vec::new();
        rewrap_stream(&mut Cursor::new(sealed), &mut rewrapped, &vault.access(), &vault.seal()).unwrap();
        assert_eq!(header_of(&rewrapped).version, 5);

        let mut out = Vec::new();
        let summary =
            decrypt_stream_with_identity(&mut Cursor::new(rewrapped.clone()), &mut out, &bob).unwrap();
        assert_eq!(out, plaintext);
        assert_eq!(
            summary.verified_sender.map(|s| s.fingerprint),
            Some(alice.fingerprint())
        );

        // The owner opens it through the vault key now.
        assert_eq!(open(&rewrapped, &vault.access()).unwrap(), plaintext);
    }

    #[test]
    fn a_sealed_folder_archive_round_trips_through_a_recipient() {
        let vault = TestVault::new();
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
            &vault.seal(),
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
