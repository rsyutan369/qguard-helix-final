//! Streaming, on-disk quantum-safe vault container.
//!
//! Unlike `file_crypto::encrypt_file_for_device` (which buffers the whole file +
//! package in memory), this module streams plaintext through the SAME hybrid
//! post-quantum stack one chunk at a time, so it works for arbitrarily large
//! files and folders with constant memory and no IPC/base64 round-trips:
//!
//! * Key wrap:  X25519 + ML-KEM-1024 (`hybrid_kex::encapsulate`)
//! * KDF:       HKDF-SHA3-256 (inside the hybrid KEX)
//! * Content:   AES-256-GCM per 1 MiB chunk, AAD-bound to file id + chunk index
//! * Header:    dual-signed Ed25519 + ML-DSA-65 (authenticates the wrapped key,
//!              metadata, and total chunk count -> truncation/extension proof)
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
use crate::crypto::signatures::{dual_sign, dual_verify, LocalSigningKeypair};
use crate::crypto::symmetric;
use crate::crypto::{AlgorithmSuite, DualSignature, EncryptedEnvelope, HybridCiphertext};
use crate::error::{QGuardError, Result};

const MAGIC: &[u8; 8] = b"QGUARDVS";
pub const STREAM_VERSION: u8 = 1;
pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB plaintext per chunk
const WRAP_INFO: &[u8] = b"QGuard-Vault-Stream-FileKey-Wrap-v1";
const MAX_HEADER_LEN: usize = 1024 * 1024; // signed header is a few KB; cap defensively
const MAX_FRAME_CIPHERTEXT: usize = CHUNK_SIZE + 64;

pub const KIND_FILE: &str = "file";
pub const KIND_FOLDER: &str = "folder";

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
    pub wrapped_key: EncryptedEnvelope,
    pub suite: AlgorithmSuite,
    pub signer_ed25519_public: Vec<u8>,
    pub signer_mldsa_public: Vec<u8>,
    pub header_signature: DualSignature,
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

fn io_err(error: io::Error) -> QGuardError {
    QGuardError::Storage(format!("vault stream I/O failed: {error}"))
}

fn wrap_aad_bytes(file_id: &str, owner_user_id: &str, owner_device_id: &str) -> Vec<u8> {
    format!("QGuard-Vault-Stream-Wrap-v1:{file_id}:{owner_user_id}:{owner_device_id}").into_bytes()
}

fn chunk_aad(file_id: &str, index: u64, total_chunks: u64, is_last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(file_id.len() + 32);
    aad.extend_from_slice(b"QGuard-Vault-Stream-Chunk-v1:");
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
    signer: &LocalSigningKeypair,
) -> Result<StreamSummary> {
    let file_id = Uuid::new_v4().to_string();
    let total_chunks = total_chunks_for(original_size);

    let mut file_key = symmetric::random_key();
    let (hybrid_ciphertext, mut wrapping_secret) =
        encapsulate(recipient_x25519_public, recipient_mlkem_public, WRAP_INFO)?;
    let wrap_aad = wrap_aad_bytes(&file_id, owner_user_id, owner_device_id);
    let wrapped_key = symmetric::encrypt(&wrapping_secret, &file_key, &wrap_aad)?;
    wrapping_secret.zeroize();

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
        suite: AlgorithmSuite::default(),
        signer_ed25519_public: signer.ed25519_public.clone(),
        signer_mldsa_public: signer.mldsa_public.clone(),
        header_signature: DualSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
    };
    let signable = header_signable(&header);
    header.header_signature = dual_sign(&signer.ed25519_secret, &signer.mldsa_secret, &signable)?;

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
    }
    buf.zeroize();
    file_key.zeroize();
    writer.flush().map_err(io_err)?;

    if index != total_chunks || streamed != original_size {
        return Err(QGuardError::Crypto(format!(
            "vault stream size mismatch: declared {original_size} bytes, read {streamed}"
        )));
    }

    Ok(StreamSummary::from_header(&header))
}

/// Stream-decrypt `reader` into `writer` using the recipient device's KEM secret.
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    recipient: &LocalKemKeypair,
) -> Result<StreamSummary> {
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
    if header.version != STREAM_VERSION {
        return Err(QGuardError::Crypto(format!(
            "unsupported vault stream version {}",
            header.version
        )));
    }

    // Authenticate the header (wrapped key + metadata + total_chunks) before use.
    let signable = header_signable(&header);
    dual_verify(
        &header.signer_ed25519_public,
        &header.signer_mldsa_public,
        &signable,
        &header.header_signature,
    )?;

    let mut wrapping_secret = decapsulate(
        &recipient.x25519_secret,
        &recipient.mlkem_secret,
        &header.hybrid_ciphertext,
        WRAP_INFO,
    )?;
    let wrap_aad = wrap_aad_bytes(&header.file_id, &header.owner_user_id, &header.owner_device_id);
    let mut file_key_bytes = symmetric::decrypt(&wrapping_secret, &header.wrapped_key, &wrap_aad)?;
    wrapping_secret.zeroize();
    if file_key_bytes.len() != symmetric::KEY_SIZE {
        file_key_bytes.zeroize();
        return Err(QGuardError::Crypto("vault stream unwrapped key is invalid".to_string()));
    }
    let mut file_key = [0u8; symmetric::KEY_SIZE];
    file_key.copy_from_slice(&file_key_bytes);
    file_key_bytes.zeroize();

    for index in 0..header.total_chunks {
        let env = read_chunk_frame(reader)?;
        let is_last = index + 1 == header.total_chunks;
        let aad = chunk_aad(&header.file_id, index, header.total_chunks, is_last);
        let mut plain = symmetric::decrypt(&file_key, &env, &aad)?;
        let write_result = writer.write_all(&plain).map_err(io_err);
        plain.zeroize();
        write_result?;
    }
    file_key.zeroize();
    writer.flush().map_err(io_err)?;

    Ok(StreamSummary::from_header(&header))
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
    use std::io::Cursor;

    fn keypair() -> (LocalKemKeypair, LocalSigningKeypair) {
        (LocalKemKeypair::generate(), LocalSigningKeypair::generate())
    }

    fn encrypt_bytes(plaintext: &[u8], kem: &LocalKemKeypair, signer: &LocalSigningKeypair) -> Vec<u8> {
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
            signer,
        )
        .unwrap();
        out
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
            &signer,
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
}
