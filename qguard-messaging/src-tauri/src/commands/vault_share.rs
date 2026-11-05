use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::ipc::Response;
use tauri::State;
use zeroize::{Zeroize, Zeroizing};

use crate::commands::calls::{local_identity, CallPeerIdentity};
use crate::commands::recovery::{ciphertext_digest, framed, push_field};
use crate::commands::vault::VaultNeed;
use crate::commands::vault_cloud::{finish_download, hash_parts, load, verify_as_owned};
use crate::commands::vault_store::{open_session, StoreSession};
use crate::crypto::hybrid_kex::{decapsulate, encapsulate_bound};
use crate::crypto::kdf::derive_32;
use crate::crypto::signatures::{dual_sign, dual_verify};
use crate::crypto::symmetric::{self, KEY_SIZE};
use crate::crypto::{AlgorithmSuite, DualSignature, EncryptedEnvelope, HybridCiphertext};
use crate::error::{QGuardError, Result};
use crate::state::AppState;
use crate::vault::library;
use crate::vault::store::{self, BoundedBuffer, HashingWriter, StoreEntry, INTEGRITY_VERIFIED};
use crate::vault_stream;

// ---------------------------------------------------------------------------
// Quantum Vault phase 4: share a stored file with other QGuard users.
//
// One encrypted copy (the file's cloud object) is stored however many people it
// is shared with. Each recipient DEVICE gets its own envelope:
//
//   * the per-file key and the file's name / type / size / content hash,
//     sealed with hybrid X25519 + ML-KEM-1024 to that device's registered
//     identity keys (HKDF-SHA3-256 → AES-256-GCM, bound to share, devices and
//     every public field below);
//   * signed with Ed25519 + ML-DSA-65 by the sending device over the share id,
//     owner, both devices, the cloud object, the container hash, the
//     permission and the expiry — so the relay can neither swap the file,
//     re-address the envelope, nor change its terms.
//
// The recipient checks the sender's registered identity (and this device's pin
// of it) before opening anything, checks every downloaded part and the whole
// container against the hashes, decrypts with the file key, and compares the
// plaintext hash the sender signed. Server rules (migration 049) decide who
// may download the object at all: accepted, not revoked, not expired.
//
// What revocation cannot do — and the app says so — is take back a copy a
// recipient already saved or a key their device already opened.
// "View only" is enforced by this app, not by cryptography: a recipient that
// can view the file holds its key.
// ---------------------------------------------------------------------------

const SHARE_VERSION: u8 = 1;
const SHARE_KEM_INFO: &str = "QGuard-VaultShare-v1:";
const SHARE_SEAL_INFO: &[u8] = b"QGuard-VaultShare-Seal-v1";
pub const PERMISSION_VIEW: &str = "view";
pub const PERMISSION_DOWNLOAD: &str = "download";

fn share_err(message: &str) -> QGuardError {
    QGuardError::InvalidInput(message.to_string())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareEnvelope {
    pub v: u8,
    pub share_id: String,
    pub owner_user_id: String,
    pub sender_device_id: String,
    pub recipient_user_id: String,
    pub recipient_device_id: String,
    pub object_id: String,
    pub file_id: String,
    pub container_sha3: String,
    pub permission: String,
    /// Unix seconds; 0 = no expiry.
    pub expires_at: i64,
    pub created_at: i64,
    pub ciphertext: HybridCiphertext,
    pub sealed: EncryptedEnvelope,
    pub signature: DualSignature,
}

/// What only the recipient device can read.
#[derive(Serialize, Deserialize)]
struct ShareSecret {
    fek: Vec<u8>,
    name: String,
    content_type: String,
    category: String,
    size_bytes: u64,
    plaintext_sha3: String,
}

impl Drop for ShareSecret {
    fn drop(&mut self) {
        self.fek.zeroize();
    }
}

fn envelope_header(e: &ShareEnvelope) -> Vec<u8> {
    framed(
        b"QGuard-VaultShare-Envelope-v1",
        &[
            &[e.v],
            e.share_id.as_bytes(),
            e.owner_user_id.as_bytes(),
            e.sender_device_id.as_bytes(),
            e.recipient_user_id.as_bytes(),
            e.recipient_device_id.as_bytes(),
            e.object_id.as_bytes(),
            e.file_id.as_bytes(),
            e.container_sha3.as_bytes(),
            e.permission.as_bytes(),
            &e.expires_at.to_be_bytes(),
            &e.created_at.to_be_bytes(),
        ],
    )
}

fn envelope_signable(e: &ShareEnvelope) -> Vec<u8> {
    let mut out = envelope_header(e);
    push_field(&mut out, &ciphertext_digest(&e.ciphertext));
    push_field(&mut out, &e.sealed.nonce);
    push_field(&mut out, &e.sealed.ciphertext);
    push_field(&mut out, &e.sealed.tag);
    out
}

fn kem_info(e: &ShareEnvelope) -> String {
    format!("{SHARE_KEM_INFO}{}:{}:{}", e.share_id, e.sender_device_id, e.recipient_device_id)
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareRequest {
    pub share_id: String,
    pub entry_id: String,
    pub object_id: String,
    pub container_sha3: String,
    pub permission: String,
    /// Unix seconds; None = no expiry.
    pub expires_at: Option<i64>,
    pub recipients: Vec<CallPeerIdentity>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedDevice {
    pub user_id: String,
    pub device_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedShare {
    pub envelopes: Vec<ShareEnvelope>,
    pub skipped: Vec<SkippedDevice>,
}

/// The file key of a stored file: from its container here, or — for a file
/// kept in the cloud only — from the account library.
fn file_key_of(session: &StoreSession, entry: &StoreEntry) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let path = session.layout.object_path(&entry.id)?;
    if let Ok(file) = File::open(&path) {
        let (file_id, fek) = vault_stream::owner_file_key_from_stream(&mut BufReader::new(file), &session.ctx.owner_access(false))?;
        if file_id != entry.id {
            return Err(QGuardError::Crypto("stored container does not match its entry".to_string()));
        }
        return Ok(fek);
    }
    let index = load(session)?;
    match (entry.library_fek.as_ref(), index.library.ring.as_ref()) {
        (Some(sealed), Some(ring)) => library::unwrap_fek(ring, &session.ctx.user_id, &entry.id, sealed),
        _ => Err(share_err("this file is not on this device — download it before sharing")),
    }
}

fn seal_share(state: &AppState, session: &StoreSession, request: &ShareRequest) -> Result<SealedShare> {
    let identity = local_identity(state)?;
    let share_id = store::checked_id(&request.share_id)?;
    let object_id = store::checked_id(&request.object_id)?;
    if request.permission != PERMISSION_VIEW && request.permission != PERMISSION_DOWNLOAD {
        return Err(share_err("permission must be view or download"));
    }
    if !is_hex64(&request.container_sha3) {
        return Err(share_err("container hash is malformed"));
    }
    if let Some(expiry) = request.expires_at {
        if expiry <= Utc::now().timestamp() {
            return Err(share_err("the expiry is in the past"));
        }
    }
    let entry = session.require_file(&request.entry_id)?;
    if entry.cloud_object_id.as_deref() != Some(object_id.as_str()) {
        return Err(share_err("only a file backed up to the cloud can be shared, and only its own cloud copy"));
    }
    if load(session)?.in_trash(&entry.id) {
        return Err(share_err("restore the file from the Trash before sharing it"));
    }
    let fek = file_key_of(session, &entry)?;
    let secret = ShareSecret {
        fek: fek.to_vec(),
        name: entry.name.clone(),
        content_type: entry.content_type.clone(),
        category: entry.category.clone(),
        size_bytes: entry.size_bytes,
        plaintext_sha3: entry.plaintext_sha3.clone(),
    };
    let plain = Zeroizing::new(serde_json::to_vec(&secret).map_err(|e| QGuardError::Storage(format!("share encode: {e}")))?);

    let mut sealed = SealedShare { envelopes: Vec::new(), skipped: Vec::new() };
    for recipient in &request.recipients {
        let skip = |reason: &str| SkippedDevice { user_id: recipient.user_id.clone(), device_id: recipient.device_id.clone(), reason: reason.to_string() };
        if recipient.user_id == identity.user_id {
            sealed.skipped.push(skip("your own devices see your files through your vault library"));
            continue;
        }
        if recipient.verify().is_err() {
            sealed.skipped.push(skip("its identity bundle does not verify"));
            continue;
        }
        if let Err(error) = state.require_accepted_device(&recipient.user_id, &recipient.pin_subject()) {
            sealed.skipped.push(skip(&error.to_string()));
            continue;
        }
        let mut envelope = ShareEnvelope {
            v: SHARE_VERSION,
            share_id: share_id.clone(),
            owner_user_id: identity.user_id.clone(),
            sender_device_id: identity.device_id.clone(),
            recipient_user_id: recipient.user_id.clone(),
            recipient_device_id: recipient.device_id.clone(),
            object_id: object_id.clone(),
            file_id: entry.id.clone(),
            container_sha3: request.container_sha3.clone(),
            permission: request.permission.clone(),
            expires_at: request.expires_at.unwrap_or(0),
            created_at: Utc::now().timestamp(),
            ciphertext: HybridCiphertext { x25519_ephemeral_public: Vec::new(), ml_kem_ciphertext: Vec::new(), suite: AlgorithmSuite::default() },
            sealed: EncryptedEnvelope { nonce: Vec::new(), ciphertext: Vec::new(), tag: Vec::new() },
            signature: DualSignature { ed25519: Vec::new(), ml_dsa_65: Vec::new() },
        };
        let info = kem_info(&envelope);
        let (ciphertext, kem_secret) = encapsulate_bound(&recipient.x25519_identity_public, &recipient.mlkem_identity_public, info.as_bytes())?;
        let kem_secret = Zeroizing::new(kem_secret);
        let key = Zeroizing::new(derive_32(&*kem_secret, SHARE_SEAL_INFO)?);
        envelope.sealed = symmetric::encrypt(&key, &plain, &envelope_header(&envelope))?;
        envelope.ciphertext = ciphertext;
        envelope.signature = dual_sign(&identity.signing.ed25519_secret, &identity.signing.mldsa_secret, &envelope_signable(&envelope))?;
        sealed.envelopes.push(envelope);
    }
    Ok(sealed)
}

// ---------------------------------------------------------------------------
// Recipient
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedFileInfo {
    pub share_id: String,
    pub owner_user_id: String,
    pub object_id: String,
    pub file_id: String,
    pub container_sha3: String,
    pub name: String,
    pub content_type: String,
    pub category: String,
    pub size_bytes: u64,
    pub permission: String,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

struct Opened {
    info: SharedFileInfo,
    fek: Zeroizing<[u8; KEY_SIZE]>,
    plaintext_sha3: String,
}

fn open_envelope(state: &AppState, envelope: &ShareEnvelope, sender: &CallPeerIdentity) -> Result<Opened> {
    if envelope.v != SHARE_VERSION {
        return Err(share_err("unsupported share envelope version"));
    }
    let identity = local_identity(state)?;
    if envelope.recipient_user_id != identity.user_id || envelope.recipient_device_id != identity.device_id {
        return Err(QGuardError::Trust("this share envelope was made for another device".to_string()));
    }
    if sender.user_id != envelope.owner_user_id || sender.device_id != envelope.sender_device_id {
        return Err(QGuardError::Trust("the share envelope does not come from the device it names".to_string()));
    }
    sender.verify()?;
    state.require_accepted_device(&sender.user_id, &sender.pin_subject())?;
    dual_verify(&sender.ed25519_identity_public, &sender.mldsa_identity_public, &envelope_signable(envelope), &envelope.signature)
        .map_err(|_| QGuardError::Trust("the share envelope signature does not verify".to_string()))?;
    if envelope.expires_at != 0 && envelope.expires_at <= Utc::now().timestamp() {
        return Err(QGuardError::Trust("VAULT_SHARE_EXPIRED: this share has expired".to_string()));
    }
    store::checked_id(&envelope.object_id)?;
    store::checked_id(&envelope.share_id)?;
    let secret = Zeroizing::new(decapsulate(&identity.kem.x25519_secret, &identity.kem.mlkem_secret, &envelope.ciphertext, kem_info(envelope).as_bytes())?);
    let key = Zeroizing::new(derive_32(&*secret, SHARE_SEAL_INFO)?);
    let plain = Zeroizing::new(symmetric::decrypt(&key, &envelope.sealed, &envelope_header(envelope))?);
    let payload: ShareSecret = serde_json::from_slice(&plain).map_err(|_| QGuardError::Crypto("the share envelope is malformed".to_string()))?;
    if payload.fek.len() != KEY_SIZE {
        return Err(QGuardError::Crypto("the share envelope holds no file key".to_string()));
    }
    let mut fek = Zeroizing::new([0u8; KEY_SIZE]);
    fek.copy_from_slice(&payload.fek);
    Ok(Opened {
        info: SharedFileInfo {
            share_id: envelope.share_id.clone(),
            owner_user_id: envelope.owner_user_id.clone(),
            object_id: envelope.object_id.clone(),
            file_id: envelope.file_id.clone(),
            container_sha3: envelope.container_sha3.clone(),
            name: store::clean_name(&payload.name).unwrap_or_else(|_| "Shared file".to_string()),
            content_type: payload.content_type.clone(),
            category: payload.category.clone(),
            size_bytes: payload.size_bytes,
            permission: envelope.permission.clone(),
            expires_at: (envelope.expires_at != 0).then_some(envelope.expires_at),
            created_at: envelope.created_at,
        },
        fek,
        plaintext_sha3: payload.plaintext_sha3.clone(),
    })
}

/// A finished download of the shared object, checked against the container
/// hash the sender signed.
fn checked_download(session: &StoreSession, download_id: &str, opened: &Opened) -> Result<PathBuf> {
    let path = finish_download(&session.ctx.user_id, download_id)?;
    let (_, _, whole) = match hash_parts(&path) {
        Ok(hashed) => hashed,
        Err(error) => {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
    };
    if whole != opened.info.container_sha3 {
        let _ = std::fs::remove_file(&path);
        return Err(QGuardError::Crypto("the downloaded file is not the one that was shared".to_string()));
    }
    Ok(path)
}

fn preview(state: &AppState, session: &StoreSession, envelope: &ShareEnvelope, sender: &CallPeerIdentity, download_id: &str) -> Result<Vec<u8>> {
    let opened = open_envelope(state, envelope, sender)?;
    if opened.info.size_bytes > store::MAX_PREVIEW_BYTES {
        let _ = finish_download(&session.ctx.user_id, download_id).map(|p| std::fs::remove_file(p));
        return Err(share_err("files this large are not previewed in memory"));
    }
    let path = checked_download(session, download_id, &opened)?;
    let result = (|| -> Result<Vec<u8>> {
        let mut reader = BufReader::new(File::open(&path).map_err(|e| QGuardError::Storage(format!("open shared file: {e}")))?);
        let mut writer = HashingWriter::new(BoundedBuffer::new(store::MAX_PREVIEW_BYTES, opened.info.size_bytes));
        vault_stream::decrypt_stream_with_file_key(&mut reader, &mut writer, &opened.fek, &opened.info.file_id, &mut |_| {})?;
        let (mut buffer, hash, len) = writer.finish();
        if len != opened.info.size_bytes || hash != opened.plaintext_sha3 {
            return Err(QGuardError::Crypto("the shared file does not match what the sender signed".to_string()));
        }
        Ok(std::mem::take(&mut *buffer.bytes))
    })();
    let _ = std::fs::remove_file(&path);
    result
}

/// Save a shared file into this vault: re-sealed as this account's own
/// container, opened in full and checked before it is stored.
fn save(
    state: &AppState,
    session: &StoreSession,
    envelope: &ShareEnvelope,
    sender: &CallPeerIdentity,
    download_id: &str,
    parent_id: Option<String>,
) -> Result<StoreEntry> {
    let opened = open_envelope(state, envelope, sender)?;
    if opened.info.permission != PERMISSION_DOWNLOAD {
        let _ = finish_download(&session.ctx.user_id, download_id).map(|p| std::fs::remove_file(p));
        return Err(QGuardError::Trust("the sender allowed viewing only, not saving".to_string()));
    }
    let entry_id = store::checked_id(&opened.info.file_id)?;
    if let Some(existing) = load(session)?.get(&entry_id).cloned() {
        let _ = finish_download(&session.ctx.user_id, download_id).map(|p| std::fs::remove_file(p));
        return Ok(existing);
    }
    let downloaded = checked_download(session, download_id, &opened)?;
    let resealed = session.layout.cloud_dir().join(format!("shared-{}.qvault", uuid::Uuid::new_v4()));
    let meta = StoreEntry {
        id: entry_id.clone(),
        kind: store::KIND_FILE.to_string(),
        name: opened.info.name.clone(),
        parent_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        trashed_at: None,
        favorite: false,
        size_bytes: opened.info.size_bytes,
        stored_bytes: 0,
        content_type: opened.info.content_type.clone(),
        category: opened.info.category.clone(),
        type_check: String::new(),
        plaintext_sha3: opened.plaintext_sha3.clone(),
        container_version: 0,
        pin_bound: true,
        total_chunks: 0,
        recovery_protected: session.ctx.seals_recovery_wraps(),
        integrity: INTEGRITY_VERIFIED.to_string(),
        last_verified_at: Some(Utc::now()),
        has_thumbnail: false,
        cloud_object_id: None,
        cloud_backed_up_at: None,
        library_fek: None,
        available_offline: true,
        cloud_shared_only: false,
    };
    let sealed = (|| -> Result<vault_stream::StreamSummary> {
        let mut reader = BufReader::new(File::open(&downloaded).map_err(|e| QGuardError::Storage(format!("open shared file: {e}")))?);
        let mut writer = BufWriter::new(File::create(&resealed).map_err(|e| QGuardError::Storage(format!("create saved file: {e}")))?);
        vault_stream::reseal_stream_with_file_key(&mut reader, &mut writer, &opened.fek, &entry_id, &session.ctx.owner_seal(), true, &mut |_| {})?;
        writer
            .flush()
            .and_then(|_| writer.get_ref().sync_all())
            .map_err(|e| QGuardError::Storage(format!("flush saved file: {e}")))?;
        drop(writer);
        verify_as_owned(session, &resealed, &meta)
    })();
    let _ = std::fs::remove_file(&downloaded);
    let summary = match sealed {
        Ok(summary) => summary,
        Err(error) => {
            let _ = std::fs::remove_file(&resealed);
            return Err(error);
        }
    };
    let stored_bytes = store::file_len(&resealed);
    let object_path = session.layout.object_path(&entry_id)?;
    let parent = match parent_id {
        Some(id) if !id.trim().is_empty() => Some(store::checked_id(&id)?),
        _ => None,
    };
    let outcome = session.update(|index| {
        let entry = index.insert_file(StoreEntry {
            parent_id: parent.clone(),
            container_version: summary.container_version,
            pin_bound: summary.pin_bound,
            total_chunks: summary.total_chunks,
            stored_bytes,
            ..meta.clone()
        })?;
        std::fs::rename(&resealed, &object_path).map_err(|e| QGuardError::Storage(format!("store saved file: {e}")))?;
        index.log("share_saved", Some(&entry.id), &entry.name, "Saved from a file shared with you · re-sealed under your vault key · verified", true);
        Ok(entry)
    });
    if outcome.is_err() {
        let _ = std::fs::remove_file(&resealed);
    }
    outcome
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn vault_share_seal(state: State<'_, AppState>, request: ShareRequest) -> Result<SealedShare> {
    let session = open_session(&state, VaultNeed::Open)?;
    let sealed = seal_share(&state, &session, &request)?;
    if !sealed.envelopes.is_empty() {
        let _ = session.update(|index| {
            let name = index.get(&request.entry_id).map(|e| e.name.clone()).unwrap_or_default();
            index.log(
                "share_create",
                Some(&request.entry_id),
                &name,
                &format!("Shared · one encrypted copy, {} recipient device envelope(s) · {}", sealed.envelopes.len(), request.permission),
                true,
            );
            Ok(())
        });
        state.audit_info("vault_share_create", "Vault file shared through recipient-specific hybrid envelopes");
    }
    Ok(sealed)
}

#[tauri::command]
pub async fn vault_share_open(state: State<'_, AppState>, envelope: ShareEnvelope, sender: CallPeerIdentity) -> Result<SharedFileInfo> {
    let _session = open_session(&state, VaultNeed::Open)?;
    Ok(open_envelope(&state, &envelope, &sender)?.info)
}

#[tauri::command]
pub async fn vault_share_preview(
    state: State<'_, AppState>,
    envelope: ShareEnvelope,
    sender: CallPeerIdentity,
    download_id: String,
) -> Result<Response> {
    let session = open_session(&state, VaultNeed::Open)?;
    state.check_decrypt_rate_limit("vault_share_preview", &envelope.share_id, 60, 300)?;
    let bytes = preview(&state, &session, &envelope, &sender, &download_id)?;
    Ok(Response::new(bytes))
}

#[tauri::command]
pub async fn vault_share_save(
    state: State<'_, AppState>,
    envelope: ShareEnvelope,
    sender: CallPeerIdentity,
    download_id: String,
    parent_id: Option<String>,
) -> Result<StoreEntry> {
    let session = open_session(&state, VaultNeed::Seal)?;
    state.check_decrypt_rate_limit("vault_share_save", &envelope.share_id, 30, 300)?;
    let saved = save(&state, &session, &envelope, &sender, &download_id, parent_id)?;
    state.audit_info("vault_share_saved", "Shared vault file saved into this vault after verification");
    Ok(saved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::vault_cloud::{download_begin, download_part, PART_SIZE};
    use crate::commands::vault_store::import_one;
    use crate::crypto::signatures::VaultSigningKeypair;
    use crate::state::PersistedVaultMaster;
    use crate::test_support::TestDevice;

    fn unlocked() -> TestDevice {
        let device = TestDevice::new(false);
        device
            .state
            .set_vault_session(PersistedVaultMaster { version: 1, vmk: symmetric::random_key(), signer: VaultSigningKeypair::generate(), configured_at: Utc::now() })
            .unwrap();
        device
    }

    fn session(device: &TestDevice) -> StoreSession {
        open_session(&device.state, VaultNeed::Seal).unwrap()
    }

    /// A stored, "backed up" file: its container stands in for the cloud copy.
    fn shared_file(device: &TestDevice, name: &str, bytes: &[u8]) -> (StoreEntry, String, PathBuf) {
        let dir = device.dir.join("src");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        let s = session(device);
        let entry = import_one(&s, &path.to_string_lossy(), None, &[], true, &mut |_| {}).unwrap().entry;
        let object_id = uuid::Uuid::new_v4().to_string();
        let oid = object_id.clone();
        s.update(|index| {
            index.get_mut(&entry.id).unwrap().cloud_object_id = Some(oid);
            Ok(())
        })
        .unwrap();
        let container = s.layout.object_path(&entry.id).unwrap();
        (entry, object_id, container)
    }

    fn request(entry: &StoreEntry, object_id: &str, container: &PathBuf, permission: &str, recipients: Vec<CallPeerIdentity>) -> ShareRequest {
        let (_, _, sha) = hash_parts(container).unwrap();
        ShareRequest {
            share_id: uuid::Uuid::new_v4().to_string(),
            entry_id: entry.id.clone(),
            object_id: object_id.to_string(),
            container_sha3: sha,
            permission: permission.to_string(),
            expires_at: None,
            recipients,
        }
    }

    /// The recipient downloads the sender's cloud copy.
    fn download(recipient: &StoreSession, container: &PathBuf) -> String {
        let (bytes, parts, whole) = hash_parts(container).unwrap();
        let id = download_begin(recipient, bytes, parts.clone(), whole).unwrap();
        let data = std::fs::read(container).unwrap();
        for (i, chunk) in data.chunks(PART_SIZE as usize).enumerate() {
            download_part(&recipient.ctx.user_id, &id, i as u64, chunk).unwrap();
        }
        id
    }

    #[test]
    fn a_recipient_previews_and_saves_a_shared_file_and_nobody_else_can() {
        let alice = unlocked();
        let bob = unlocked();
        let content = b"quarterly figures: confidential".to_vec();
        let (entry, object_id, container) = shared_file(&alice, "Q3 figures.csv", &content);
        let alice_session = session(&alice);
        let sealed = seal_share(&alice.state, &alice_session, &request(&entry, &object_id, &container, PERMISSION_DOWNLOAD, vec![bob.call_peer()])).unwrap();
        assert_eq!(sealed.envelopes.len(), 1);
        let envelope = sealed.envelopes[0].clone();
        // The relay sees no name, no key.
        let wire = serde_json::to_vec(&envelope).unwrap();
        assert!(!wire.windows(10).any(|w| w == b"Q3 figures"));

        let bob_session = session(&bob);
        let info = open_envelope(&bob.state, &envelope, &alice.call_peer()).unwrap().info;
        assert_eq!(info.name, "Q3 figures.csv");
        assert_eq!(info.permission, PERMISSION_DOWNLOAD);

        let preview_bytes = preview(&bob.state, &bob_session, &envelope, &alice.call_peer(), &download(&bob_session, &container)).unwrap();
        assert_eq!(preview_bytes, content);

        let saved = save(&bob.state, &bob_session, &envelope, &alice.call_peer(), &download(&bob_session, &container), None).unwrap();
        assert_eq!(saved.name, "Q3 figures.csv");
        // Bob's copy is Bob's: it opens under Bob's vault, as Bob's own container.
        let mine = bob_session.require_file(&saved.id).unwrap();
        assert_eq!(bob_session.decrypt_into(&mine, Vec::new(), &mut |_| {}).unwrap(), content);
        // Saving again is a no-op.
        assert_eq!(save(&bob.state, &bob_session, &envelope, &alice.call_peer(), &download(&bob_session, &container), None).unwrap().id, saved.id);

        // Carol, handed Bob's envelope, gets nothing.
        let carol = unlocked();
        assert!(open_envelope(&carol.state, &envelope, &alice.call_peer()).is_err());
    }

    #[test]
    fn tampering_with_the_envelope_or_the_file_is_detected() {
        let alice = unlocked();
        let bob = unlocked();
        let (entry, object_id, container) = shared_file(&alice, "a.txt", b"original text");
        let alice_session = session(&alice);
        let envelope = seal_share(&alice.state, &alice_session, &request(&entry, &object_id, &container, PERMISSION_DOWNLOAD, vec![bob.call_peer()]))
            .unwrap()
            .envelopes
            .remove(0);

        // The relay upgrades "view" to "download", or extends the expiry: the signature breaks.
        for forged in [
            ShareEnvelope { permission: PERMISSION_VIEW.to_string(), ..envelope.clone() },
            ShareEnvelope { expires_at: 4_102_444_800, ..envelope.clone() },
            ShareEnvelope { object_id: uuid::Uuid::new_v4().to_string(), ..envelope.clone() },
        ] {
            assert!(open_envelope(&bob.state, &forged, &alice.call_peer()).is_err());
        }
        // An impostor device claiming to be Alice's sender device.
        let mallory = unlocked();
        let mut impostor = mallory.call_peer();
        impostor.user_id = alice.user.clone();
        impostor.device_id = alice.device_id.clone();
        assert!(open_envelope(&bob.state, &envelope, &impostor).is_err());

        // A different file served for the shared object.
        let (_, _, other_container) = shared_file(&alice, "b.txt", b"something else entirely");
        let bob_session = session(&bob);
        let swapped = download(&bob_session, &other_container);
        assert!(preview(&bob.state, &bob_session, &envelope, &alice.call_peer(), &swapped).is_err());
    }

    #[test]
    fn view_only_and_expired_shares_are_refused_where_they_should_be() {
        let alice = unlocked();
        let bob = unlocked();
        let (entry, object_id, container) = shared_file(&alice, "a.txt", b"look, don't keep");
        let alice_session = session(&alice);
        let view = seal_share(&alice.state, &alice_session, &request(&entry, &object_id, &container, PERMISSION_VIEW, vec![bob.call_peer()]))
            .unwrap()
            .envelopes
            .remove(0);
        let bob_session = session(&bob);
        assert!(preview(&bob.state, &bob_session, &view, &alice.call_peer(), &download(&bob_session, &container)).is_ok());
        assert!(save(&bob.state, &bob_session, &view, &alice.call_peer(), &download(&bob_session, &container), None).is_err());

        // Expiry in the past is refused at sealing; a lapsed one at opening.
        let mut past = request(&entry, &object_id, &container, PERMISSION_DOWNLOAD, vec![bob.call_peer()]);
        past.expires_at = Some(Utc::now().timestamp() - 10);
        assert!(seal_share(&alice.state, &alice_session, &past).is_err());
        let mut soon = request(&entry, &object_id, &container, PERMISSION_DOWNLOAD, vec![bob.call_peer()]);
        soon.expires_at = Some(Utc::now().timestamp() + 1);
        let expiring = seal_share(&alice.state, &alice_session, &soon).unwrap().envelopes.remove(0);
        std::thread::sleep(std::time::Duration::from_millis(2100));
        assert!(open_envelope(&bob.state, &expiring, &alice.call_peer()).err().unwrap().to_string().contains("VAULT_SHARE_EXPIRED"));
    }

    #[test]
    fn only_backed_up_files_are_shared_and_never_to_yourself() {
        let alice = unlocked();
        let bob = unlocked();
        let (entry, object_id, container) = shared_file(&alice, "a.txt", b"x");
        let alice_session = session(&alice);
        // Wrong object for the file.
        let wrong = ShareRequest { object_id: uuid::Uuid::new_v4().to_string(), ..request(&entry, &object_id, &container, PERMISSION_DOWNLOAD, vec![bob.call_peer()]) };
        assert!(seal_share(&alice.state, &alice_session, &wrong).is_err());
        // Yourself: skipped, not sealed.
        let to_self = seal_share(&alice.state, &alice_session, &request(&entry, &object_id, &container, PERMISSION_DOWNLOAD, vec![alice.call_peer()])).unwrap();
        assert!(to_self.envelopes.is_empty());
        assert_eq!(to_self.skipped.len(), 1);
    }
}
