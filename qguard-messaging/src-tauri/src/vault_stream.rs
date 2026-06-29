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
use crate::crypto::signatures::{dual_verify, dual_sign_87, dual_verify_87, VaultSigningKeypair};
use crate::crypto::symmetric::{self, KEY_SIZE};
use crate::crypto::vault_recovery;
use crate::crypto::{vault_suite, AlgorithmSuite, DualSignature, DualSignature87, EncryptedEnvelope, HybridCiphertext};
use crate::error::{QGuardError, Result};

const MAGIC: &[u8; 8] = b"QGUARDVS";
/// v1: device wrap only. v2: adds an optional quantum-safe recovery-key wrap so
/// files survive total device loss. v3: introduces the Vault Master Key (VMK)
/// envelope (FEK wrapped by VMK; VMK protected by ML-KEM-1024 / recovery /
/// enterprise) and signs with ML-DSA-87. All versions are accepted on decrypt;
/// new files are always written as v3.
pub const STREAM_VERSION: u8 = 3;
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
    data
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
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let file_id = Uuid::new_v4().to_string();
    let total_chunks = total_chunks_for(original_size);

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

    let mut header = StreamHeader {
        version: STREAM_VERSION,
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
    };
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
    if header.version == 0 || header.version > STREAM_VERSION {
        return Err(QGuardError::Crypto(format!(
            "unsupported vault stream version {}",
            header.version
        )));
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
    let result = decrypt_chunks(reader, writer, &header, &file_key, progress);
    file_key.zeroize();
    let summary = result?;
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
        signer_ed25519_public: vault_signer.ed25519_public.clone(),
        signer_mldsa_public: Vec::new(),
        signer_mldsa87_public: vault_signer.mldsa87_public.clone(),
        header_signature: DualSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
        header_signature_v3: None,
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
            &kem.x25519_public, &kem.mlkem_public, &vmk, &signer, None, None,
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
}
