use std::fs::File;
use std::io::BufReader;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroizing;

use crate::commands::calls::{local_identity, CallPeerIdentity};
use crate::commands::recovery::{ciphertext_digest, framed, push_field};
use crate::commands::vault::{run_stream_blocking, VaultNeed};
use crate::commands::vault_cloud::{
    finish_download, hash_parts, load, register_upload, take_upload, PreparedUpload, UploadManifest, KIND_LIBRARY_INDEX,
};
use crate::commands::vault_store::{open_session, StoreSession};
use crate::crypto::hybrid_kex::{decapsulate, encapsulate_bound};
use crate::crypto::kdf::derive_32;
use crate::crypto::signatures::{dual_sign, dual_verify};
use crate::crypto::symmetric;
use crate::crypto::vault_recovery;
use crate::crypto::{AlgorithmSuite, DualSignature, EncryptedEnvelope, HybridCiphertext};
use crate::device_pins::DeviceStanding;
use crate::error::{QGuardError, Result};
use crate::state::AppState;
use crate::vault::library::{self, LibraryRing, MergeReport, RecoveryRingEnvelope};
use crate::vault::store::{self, StoreIndex};
use crate::vault_stream;

// ---------------------------------------------------------------------------
// Quantum Vault phase 3: one library across the account's devices. The model
// and the merge rules are in `vault::library`; this module moves the library
// key ring between devices and runs merge / publish for the sync engine
// (lib/vault-cloud.ts), which talks to Supabase (migration 049).
//
// The ring lives only inside a device's sealed vault index, so everything here
// needs that vault unlocked.
// ---------------------------------------------------------------------------

const WRAP_VERSION: u8 = 1;
const WRAP_KEM_INFO: &str = "QGuard-VaultLibrary-v1:wrap:";
const WRAP_SEAL_INFO: &[u8] = b"QGuard-VaultLibrary-WrapSeal-v1";

fn lib_err(message: &str) -> QGuardError {
    QGuardError::InvalidInput(message.to_string())
}

fn ring_of(index: &StoreIndex) -> Result<&LibraryRing> {
    index
        .library
        .ring
        .as_ref()
        .ok_or_else(|| QGuardError::NotFound(format!("{}: this device has no library key yet", library::LIBRARY_KEY_MISSING)))
}

// ---------------------------------------------------------------------------
// Ring in / out
// ---------------------------------------------------------------------------

/// Take in a ring from another device or the recovery copy.
///
/// Both sources are authenticated (a pinned own device's signature, or the
/// account's recovery key), so a ring arriving here was made by this account.
/// If it disagrees with ours about an epoch, two devices started that epoch at
/// once; the copy the server published (`incoming.current >= ours`) wins, and
/// every file-key wrap we hold is moved onto it.
fn adopt_ring(index: &mut StoreIndex, user_id: &str, incoming: &LibraryRing) -> Result<bool> {
    incoming.check()?;
    let Some(mut ring) = index.library.ring.clone() else {
        index.library.ring = Some(incoming.clone());
        index.library.published_digest = None;
        return Ok(true);
    };
    match ring.absorb(incoming) {
        Ok(changed) => {
            if changed {
                library::rewrap_all_feks(&ring, user_id, index)?;
                index.library.ring = Some(ring);
                index.library.published_digest = None;
            }
            Ok(changed)
        }
        Err(error) if error.to_string().contains("LIBRARY_EPOCH_CONFLICT") && incoming.current >= ring.current => {
            // Recover every file key under our ring, then re-wrap under theirs.
            let mut feks = Vec::new();
            for entry in &index.entries {
                if let Some(sealed) = entry.library_fek.as_ref() {
                    if let Ok(fek) = library::unwrap_fek(&ring, user_id, &entry.id, sealed) {
                        feks.push((entry.id.clone(), fek));
                    }
                }
            }
            let adopted = incoming.clone();
            for entry in index.entries.iter_mut() {
                entry.library_fek = None;
            }
            for (id, fek) in feks {
                let sealed = library::wrap_fek(&adopted, user_id, &id, &fek)?;
                if let Some(entry) = index.get_mut(&id) {
                    entry.library_fek = Some(sealed);
                }
            }
            index.library.ring = Some(adopted);
            index.library.published_digest = None;
            index.library.recovery_epoch = 0;
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

/// The ring, sealed to one of the account's other devices and signed by this
/// one. Stored by the client in `qv_library_key_wraps` (migration 049).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryKeyWrap {
    pub v: u8,
    pub user_id: String,
    pub from_device_id: String,
    pub to_device_id: String,
    pub epoch: u32,
    pub created_at: i64,
    pub ciphertext: HybridCiphertext,
    pub sealed: EncryptedEnvelope,
    pub signature: DualSignature,
}

fn wrap_header(wrap: &LibraryKeyWrap) -> Vec<u8> {
    framed(
        b"QGuard-VaultLibrary-Wrap-v1",
        &[
            &[wrap.v],
            wrap.user_id.as_bytes(),
            wrap.from_device_id.as_bytes(),
            wrap.to_device_id.as_bytes(),
            &wrap.epoch.to_be_bytes(),
            &wrap.created_at.to_be_bytes(),
        ],
    )
}

fn wrap_signable(wrap: &LibraryKeyWrap) -> Vec<u8> {
    let mut out = wrap_header(wrap);
    push_field(&mut out, &ciphertext_digest(&wrap.ciphertext));
    push_field(&mut out, &wrap.sealed.nonce);
    push_field(&mut out, &wrap.sealed.ciphertext);
    push_field(&mut out, &wrap.sealed.tag);
    out
}

fn wrap_info(from: &str, to: &str) -> String {
    format!("{WRAP_KEM_INFO}{from}:{to}")
}

/// A device of this account that THIS device has pinned (recorded with the
/// same identity keys) — approved in the Device Trust Center. The only kind a
/// ring is sealed to or accepted from.
fn require_own_pinned(state: &AppState, user_id: &str, peer: &CallPeerIdentity, what: &str) -> Result<()> {
    peer.verify()?;
    if peer.user_id != user_id {
        return Err(QGuardError::Trust(format!("{what} is not a device of this account")));
    }
    if state.device_standing(user_id, &peer.pin_subject()) != Some(DeviceStanding::Pinned) {
        return Err(QGuardError::Trust(format!(
            "{what} is not a device this device has recorded for your account — approve it in the Device Trust Center first"
        )));
    }
    Ok(())
}

fn make_wrap(state: &AppState, session: &StoreSession, target: &CallPeerIdentity) -> Result<LibraryKeyWrap> {
    let identity = local_identity(state)?;
    if target.device_id == identity.device_id {
        return Err(lib_err("a device does not wrap the library key for itself"));
    }
    require_own_pinned(state, &identity.user_id, target, "the target device")?;
    let index = load(session)?;
    let ring = ring_of(&index)?;
    let plain = Zeroizing::new(serde_json::to_vec(ring).map_err(|e| QGuardError::Storage(format!("library ring: {e}")))?);
    let mut wrap = LibraryKeyWrap {
        v: WRAP_VERSION,
        user_id: identity.user_id.clone(),
        from_device_id: identity.device_id.clone(),
        to_device_id: target.device_id.clone(),
        epoch: ring.current,
        created_at: Utc::now().timestamp(),
        ciphertext: HybridCiphertext {
            x25519_ephemeral_public: Vec::new(),
            ml_kem_ciphertext: Vec::new(),
            suite: AlgorithmSuite::default(),
        },
        sealed: EncryptedEnvelope { nonce: Vec::new(), ciphertext: Vec::new(), tag: Vec::new() },
        signature: DualSignature { ed25519: Vec::new(), ml_dsa_65: Vec::new() },
    };
    let info = wrap_info(&wrap.from_device_id, &wrap.to_device_id);
    let (ciphertext, secret) = encapsulate_bound(&target.x25519_identity_public, &target.mlkem_identity_public, info.as_bytes())?;
    let secret = Zeroizing::new(secret);
    let key = Zeroizing::new(derive_32(&*secret, WRAP_SEAL_INFO)?);
    wrap.sealed = symmetric::encrypt(&key, &plain, &wrap_header(&wrap))?;
    wrap.ciphertext = ciphertext;
    wrap.signature = dual_sign(&identity.signing.ed25519_secret, &identity.signing.mldsa_secret, &wrap_signable(&wrap))?;
    Ok(wrap)
}

fn accept_wrap(state: &AppState, session: &StoreSession, wrap: &LibraryKeyWrap, sender: &CallPeerIdentity) -> Result<LibraryStatus> {
    if wrap.v != WRAP_VERSION {
        return Err(lib_err("unsupported library key wrap version"));
    }
    let identity = local_identity(state)?;
    if wrap.user_id != identity.user_id {
        return Err(QGuardError::Trust("the library key wrap is for another account".to_string()));
    }
    if wrap.to_device_id != identity.device_id {
        return Err(QGuardError::Trust("the library key wrap was made for another device".to_string()));
    }
    if sender.device_id == identity.device_id || wrap.from_device_id != sender.device_id {
        return Err(QGuardError::Trust("the library key wrap does not come from the device it names".to_string()));
    }
    require_own_pinned(state, &identity.user_id, sender, "the sending device")?;
    dual_verify(&sender.ed25519_identity_public, &sender.mldsa_identity_public, &wrap_signable(wrap), &wrap.signature)
        .map_err(|_| QGuardError::Trust("the library key wrap signature does not verify".to_string()))?;
    let info = wrap_info(&wrap.from_device_id, &wrap.to_device_id);
    let secret = Zeroizing::new(decapsulate(&identity.kem.x25519_secret, &identity.kem.mlkem_secret, &wrap.ciphertext, info.as_bytes())?);
    let key = Zeroizing::new(derive_32(&*secret, WRAP_SEAL_INFO)?);
    let plain = Zeroizing::new(symmetric::decrypt(&key, &wrap.sealed, &wrap_header(wrap))?);
    let incoming: LibraryRing = serde_json::from_slice(&plain).map_err(|_| QGuardError::Crypto("the library key wrap holds no key ring".to_string()))?;
    if incoming.current != wrap.epoch {
        return Err(QGuardError::Crypto("the library key wrap epoch does not match its ring".to_string()));
    }
    let user_id = identity.user_id.clone();
    let index = session.update(|index| {
        adopt_ring(index, &user_id, &incoming)?;
        index.log("library_join", None, "Vault library", "Library key received from another of your devices", true);
        Ok(index.clone())
    })?;
    state.audit_info("vault_library_key_received", "Vault library key received from another of your trusted devices");
    status_of(session, &index)
}

fn accept_recovery(session: &StoreSession, envelope: &RecoveryRingEnvelope, typed_key: Option<&str>) -> Result<LibraryStatus> {
    let wrap_key: Zeroizing<[u8; 32]> = match typed_key.filter(|k| !k.trim().is_empty()) {
        Some(key) => {
            let root = Zeroizing::new(
                vault_recovery::decode_recovery_key(key).map_err(|_| QGuardError::Trust("That recovery key isn't valid.".to_string()))?,
            );
            Zeroizing::new(vault_recovery::derive_wrap_key(&root)?)
        }
        None => Zeroizing::new(
            *session
                .ctx
                .personal_recovery_wrap_key()
                .ok_or_else(|| lib_err("no recovery key on this device — enter it, or approve this device from another one"))?,
        ),
    };
    let incoming = library::open_ring_from_recovery(envelope, &wrap_key, &session.ctx.user_id)?;
    let user_id = session.ctx.user_id.clone();
    let index = session.update(|index| {
        adopt_ring(index, &user_id, &incoming)?;
        index.library.recovery_epoch = index.library.recovery_epoch.max(envelope.epoch);
        index.log("library_join", None, "Vault library", "Library key opened with your recovery key", true);
        Ok(index.clone())
    })?;
    status_of(session, &index)
}

// ---------------------------------------------------------------------------
// Status, create, rotate
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryStatus {
    pub has_ring: bool,
    pub epoch: Option<u32>,
    pub revision: u64,
    pub publish_needed: bool,
    /// A personal recovery key is on this device and the cloud copy of the ring
    /// is older than the current epoch.
    pub recovery_envelope_needed: bool,
    pub recovery_ready: bool,
    pub tombstones: u64,
    pub last_merge_at: Option<chrono::DateTime<Utc>>,
    /// This device's id (as registered in messaging_devices).
    pub device_id: String,
}

fn status_of(session: &StoreSession, index: &StoreIndex) -> Result<LibraryStatus> {
    let ring = index.library.ring.as_ref();
    let recovery_ready = session.ctx.personal_recovery_wrap_key().is_some();
    Ok(LibraryStatus {
        has_ring: ring.is_some(),
        epoch: ring.map(|r| r.current),
        revision: index.library.revision,
        publish_needed: ring.is_some()
            && index.library.published_digest.as_deref() != Some(library::doc_digest(&library::build_doc(index)).as_str()),
        recovery_envelope_needed: recovery_ready && ring.is_some_and(|r| index.library.recovery_epoch < r.current),
        recovery_ready,
        tombstones: index.library.tombstones.len() as u64,
        last_merge_at: index.library.last_merge_at,
        device_id: session.ctx.device_id.clone(),
    })
}

fn create(session: &StoreSession) -> Result<LibraryStatus> {
    let index = session.update(|index| {
        if index.library.ring.is_none() {
            index.library.ring = Some(LibraryRing::generate());
            index.library.published_digest = None;
            index.log("library_create", None, "Vault library", "Library key created on this device (epoch 1)", true);
        }
        Ok(index.clone())
    })?;
    status_of(session, &index)
}

fn rotate(session: &StoreSession) -> Result<LibraryStatus> {
    let user_id = session.ctx.user_id.clone();
    let index = session.update(|index| {
        let mut ring = ring_of(index)?.clone();
        let epoch = ring.rotate()?;
        library::rewrap_all_feks(&ring, &user_id, index)?;
        index.library.ring = Some(ring);
        index.library.published_digest = None;
        index.log("library_rotate", None, "Vault library", &format!("New library key epoch {epoch}: a removed device cannot read anything from now on"), true);
        Ok(index.clone())
    })?;
    status_of(session, &index)
}

fn recovery_envelope(session: &StoreSession) -> Result<RecoveryRingEnvelope> {
    let wrap_key = session.ctx.personal_recovery_wrap_key().ok_or_else(|| lib_err("no personal recovery key on this device"))?;
    let index = load(session)?;
    library::seal_ring_for_recovery(ring_of(&index)?, wrap_key, &session.ctx.user_id)
}

fn mark_recovery_stored(session: &StoreSession, epoch: u32) -> Result<()> {
    session.update(|index| {
        index.library.recovery_epoch = index.library.recovery_epoch.max(epoch);
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Merge / publish
// ---------------------------------------------------------------------------

/// Merge a downloaded library document (server revision `revision`), then
/// remove the encrypted objects of entries other devices deleted.
fn merge_download(session: &StoreSession, download_id: &str, revision: u64) -> Result<MergeReport> {
    let path = finish_download(&session.ctx.user_id, download_id)?;
    let bytes = std::fs::read(&path).map_err(|e| QGuardError::Storage(format!("read library: {e}")));
    let _ = std::fs::remove_file(&path);
    let bytes = bytes?;
    let index = load(session)?;
    let doc = library::open_doc(ring_of(&index)?, &session.ctx.user_id, &bytes)?;
    let remote_digest = library::doc_digest(&doc);
    let mut removed_with_thumbs = Vec::new();
    let report = session.update(|index| {
        for entry in &index.entries {
            if entry.has_thumbnail {
                removed_with_thumbs.push(entry.id.clone());
            }
        }
        let report = library::merge(index, &doc, Utc::now());
        index.library.revision = index.library.revision.max(revision);
        index.library.published_digest = Some(remote_digest.clone());
        if report.added + report.updated > 0 || !report.removed.is_empty() {
            index.log(
                "library_merge",
                None,
                "Vault library",
                &format!(
                    "Synchronized with your other devices · {} new · {} updated · {} deleted elsewhere",
                    report.added,
                    report.updated,
                    report.removed.len()
                ),
                true,
            );
        }
        Ok(report)
    })?;
    for id in &report.removed {
        if let Ok(path) = session.layout.object_path(id) {
            let _ = store::shred_container(&path);
        }
        if removed_with_thumbs.contains(id) {
            if let Ok(path) = session.layout.thumb_path(id) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    Ok(report)
}

/// Give every backed-up file this device holds a file-key wrap under the
/// current epoch, so other devices can open its cloud copy.
fn ensure_library_feks(session: &StoreSession) -> Result<u64> {
    let index = load(session)?;
    let ring = ring_of(&index)?.clone();
    let mut wrapped = Vec::new();
    for entry in index.entries.iter().filter(|e| e.is_file() && e.cloud_object_id.is_some() && e.library_fek.is_none()) {
        let Ok(path) = session.layout.object_path(&entry.id) else { continue };
        let Ok(file) = File::open(&path) else { continue };
        let mut reader = BufReader::new(file);
        let (file_id, fek) = vault_stream::owner_file_key_from_stream(&mut reader, &session.ctx.owner_access(false))?;
        if file_id != entry.id {
            continue;
        }
        wrapped.push((entry.id.clone(), library::wrap_fek(&ring, &session.ctx.user_id, &entry.id, &fek)?));
    }
    let count = wrapped.len() as u64;
    if count > 0 {
        session.update(|index| {
            for (id, sealed) in wrapped {
                if let Some(entry) = index.get_mut(&id) {
                    entry.library_fek = Some(sealed);
                }
            }
            Ok(())
        })?;
    }
    Ok(count)
}

fn prepare_publish(session: &StoreSession) -> Result<PreparedUpload> {
    ensure_library_feks(session)?;
    let index = load(session)?;
    let ring = ring_of(&index)?;
    let doc = library::build_doc(&index);
    let digest = library::doc_digest(&doc);
    let sealed = library::seal_doc(ring, &session.ctx.user_id, &doc)?;
    let snapshot = session.layout.cloud_dir().join(format!("library-{}.qvl", uuid::Uuid::new_v4()));
    crate::state::write_atomic(&snapshot, &sealed).map_err(|e| QGuardError::Storage(format!("write library snapshot: {e}")))?;
    let (bytes, part_sha3, container_sha3) = match hash_parts(&snapshot) {
        Ok(hashed) => hashed,
        Err(error) => {
            let _ = std::fs::remove_file(&snapshot);
            return Err(error);
        }
    };
    register_upload(
        UploadManifest {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: session.ctx.user_id.clone(),
            kind: KIND_LIBRARY_INDEX,
            entry_id: None,
            path: snapshot,
            temporary: true,
            container_bytes: bytes,
            part_sha3,
            digest: Some(digest),
            for_sharing: false,
        },
        container_sha3,
        session.ctx.device_id.clone(),
    )
}

/// The server accepted our document as `revision`.
fn published(session: &StoreSession, upload_id: &str, object_id: &str, revision: u64, previous_object_id: Option<String>) -> Result<()> {
    let object_id = store::checked_id(object_id)?;
    let manifest = take_upload(&session.ctx.user_id, upload_id)?;
    let _ = std::fs::remove_file(&manifest.path);
    if manifest.kind != KIND_LIBRARY_INDEX {
        return Err(lib_err("not a library upload"));
    }
    let previous = match previous_object_id {
        Some(id) if !id.is_empty() => Some(store::checked_id(&id)?),
        _ => None,
    };
    session.update(|index| {
        index.library.revision = revision;
        index.library.published_digest = manifest.digest.clone();
        if let Some(previous) = previous.filter(|p| p != &object_id) {
            index.cloud.pending_deletes.push(previous);
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn vault_library_status(state: State<'_, AppState>) -> Result<LibraryStatus> {
    let session = open_session(&state, VaultNeed::Seal)?;
    run_stream_blocking(move || {
        let index = load(&session)?;
        status_of(&session, &index)
    })
    .await
}

#[tauri::command]
pub async fn vault_library_create(state: State<'_, AppState>) -> Result<LibraryStatus> {
    let session = open_session(&state, VaultNeed::Seal)?;
    let status = run_stream_blocking(move || create(&session)).await?;
    state.audit_info("vault_library_create", "Vault library key created");
    Ok(status)
}

#[tauri::command]
pub async fn vault_library_rotate(state: State<'_, AppState>) -> Result<LibraryStatus> {
    let session = open_session(&state, VaultNeed::Seal)?;
    let status = run_stream_blocking(move || rotate(&session)).await?;
    state.audit_info("vault_library_rotate", "Vault library key rotated after a device was removed");
    Ok(status)
}

#[tauri::command]
pub async fn vault_library_make_wrap(state: State<'_, AppState>, target: CallPeerIdentity) -> Result<LibraryKeyWrap> {
    let session = open_session(&state, VaultNeed::Open)?;
    let wrap = make_wrap(&state, &session, &target)?;
    state.audit_info("vault_library_key_wrapped", "Vault library key sealed to another of your trusted devices");
    Ok(wrap)
}

#[tauri::command]
pub async fn vault_library_accept_wrap(state: State<'_, AppState>, wrap: LibraryKeyWrap, sender: CallPeerIdentity) -> Result<LibraryStatus> {
    let session = open_session(&state, VaultNeed::Seal)?;
    accept_wrap(&state, &session, &wrap, &sender)
}

#[tauri::command]
pub async fn vault_library_recovery_envelope(state: State<'_, AppState>) -> Result<RecoveryRingEnvelope> {
    let session = open_session(&state, VaultNeed::Seal)?;
    run_stream_blocking(move || recovery_envelope(&session)).await
}

#[tauri::command]
pub async fn vault_library_mark_recovery_stored(state: State<'_, AppState>, epoch: u32) -> Result<()> {
    let session = open_session(&state, VaultNeed::Seal)?;
    run_stream_blocking(move || mark_recovery_stored(&session, epoch)).await
}

/// Join the library through its recovery-key copy: with this device's own
/// recovery key, or one the user types (restoring on a new device).
#[tauri::command]
pub async fn vault_library_accept_recovery(
    state: State<'_, AppState>,
    envelope: RecoveryRingEnvelope,
    recovery_key: Option<String>,
) -> Result<LibraryStatus> {
    let session = open_session(&state, VaultNeed::Seal)?;
    if recovery_key.is_some() {
        state.check_decrypt_rate_limit("vault_library_recovery", &session.ctx.user_id, 10, 300)?;
    }
    let status = run_stream_blocking(move || accept_recovery(&session, &envelope, recovery_key.as_deref())).await?;
    state.audit_info("vault_library_recovery_join", "Vault library key opened with the recovery key");
    Ok(status)
}

#[tauri::command]
pub async fn vault_library_merge(state: State<'_, AppState>, download_id: String, revision: u64) -> Result<MergeReport> {
    let session = open_session(&state, VaultNeed::Seal)?;
    run_stream_blocking(move || merge_download(&session, &download_id, revision)).await
}

#[tauri::command]
pub async fn vault_library_prepare_publish(state: State<'_, AppState>) -> Result<PreparedUpload> {
    let session = open_session(&state, VaultNeed::Seal)?;
    run_stream_blocking(move || prepare_publish(&session)).await
}

#[tauri::command]
pub async fn vault_library_published(
    state: State<'_, AppState>,
    upload_id: String,
    object_id: String,
    revision: u64,
    previous_object_id: Option<String>,
) -> Result<()> {
    let session = open_session(&state, VaultNeed::Seal)?;
    run_stream_blocking(move || published(&session, &upload_id, &object_id, revision, previous_object_id)).await
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::vault_cloud::{download_begin, download_part, PART_SIZE};
    use crate::commands::vault_store::import_one;
    use crate::crypto::signatures::VaultSigningKeypair;
    use crate::state::{PersistedVaultMaster, PersistedVaultRecovery};
    use crate::test_support::TestDevice;
    use crate::vault::store::StoreEntry;
    use std::collections::HashMap;

    fn master() -> PersistedVaultMaster {
        PersistedVaultMaster { version: 1, vmk: symmetric::random_key(), signer: VaultSigningKeypair::generate(), configured_at: Utc::now() }
    }

    fn with_recovery(device: &TestDevice, root: &[u8; 32]) {
        let wrap_key = vault_recovery::derive_wrap_key(root).unwrap();
        let vault_key = device.state.unlocked_vault_master().unwrap().vault_key().unwrap();
        device.state.save_vault_recovery(&device.user, &PersistedVaultRecovery::personal(wrap_key, "v".to_string()), &vault_key).unwrap();
    }

    fn pin_each_other(a: &TestDevice, b: &TestDevice) {
        for (me, other) in [(a, b), (b, a)] {
            let subject = other.call_peer().pin_subject();
            me.state
                .with_device_pins(&me.user, |book| {
                    book.assess(std::slice::from_ref(&subject), 1);
                    if book.standing(&subject) != Some(DeviceStanding::Pinned) {
                        book.approve(&subject, 2).unwrap();
                    }
                })
                .unwrap();
        }
    }

    /// A device of `user` with its own vault (its own vault key).
    fn device_of(user: Option<&str>) -> TestDevice {
        let device = match user {
            Some(user) => TestDevice::open(std::env::temp_dir().join(format!("qguard-lib-{}", uuid::Uuid::new_v4())), user.to_string()),
            None => TestDevice::new(false),
        };
        device.state.set_vault_session(master()).unwrap();
        device
    }

    fn seal(device: &TestDevice) -> StoreSession {
        open_session(&device.state, VaultNeed::Seal).unwrap()
    }

    /// The cloud: objects by id, and the published library (revision, object).
    #[derive(Default)]
    struct Cloud {
        objects: HashMap<String, Vec<u8>>,
        library: Option<(u64, String)>,
    }

    impl Cloud {
        fn put(&mut self, bytes: Vec<u8>) -> String {
            let id = uuid::Uuid::new_v4().to_string();
            self.objects.insert(id.clone(), bytes);
            id
        }
        fn pull(&self, session: &StoreSession, id: &str) -> String {
            let bytes = &self.objects[id];
            let dir = std::env::temp_dir().join(format!("qguard-pull-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("obj");
            std::fs::write(&path, bytes).unwrap();
            let (len, parts, whole) = hash_parts(&path).unwrap();
            let download = download_begin(session, len, parts, whole).unwrap();
            for (i, chunk) in bytes.chunks(PART_SIZE as usize).enumerate() {
                download_part(&session.ctx.user_id, &download, i as u64, chunk).unwrap();
            }
            let _ = std::fs::remove_dir_all(dir);
            download
        }
    }

    fn import(device: &TestDevice, name: &str, bytes: &[u8]) -> StoreEntry {
        let dir = device.dir.join("src");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        import_one(&seal(device), &path.to_string_lossy(), None, &[], true, &mut |_| {}).unwrap().entry
    }

    /// Back a file up: its container becomes a cloud object.
    fn back_up(device: &TestDevice, cloud: &mut Cloud, entry: &StoreEntry) -> String {
        let session = seal(device);
        let bytes = std::fs::read(session.layout.object_path(&entry.id).unwrap()).unwrap();
        let id = cloud.put(bytes);
        let oid = id.clone();
        session
            .update(|index| {
                index.get_mut(&entry.id).unwrap().cloud_object_id = Some(oid);
                Ok(())
            })
            .unwrap();
        id
    }

    /// One library round: merge what is newer in the cloud, then publish.
    fn sync(device: &TestDevice, cloud: &mut Cloud) -> MergeReport {
        let session = seal(device);
        let mut report = MergeReport::default();
        if let Some((revision, object)) = cloud.library.clone() {
            if revision > status_of(&session, &load(&session).unwrap()).unwrap().revision {
                let download = cloud.pull(&session, &object);
                report = merge_download(&session, &download, revision).unwrap();
            }
        }
        if status_of(&session, &load(&session).unwrap()).unwrap().publish_needed {
            let prepared = prepare_publish(&session).unwrap();
            let bytes = std::fs::read(&prepared_path(&session, &prepared)).unwrap();
            let object = cloud.put(bytes);
            let revision = cloud.library.as_ref().map(|(r, _)| r + 1).unwrap_or(1);
            let previous = cloud.library.as_ref().map(|(_, o)| o.clone());
            cloud.library = Some((revision, object.clone()));
            published(&session, &prepared.upload_id, &object, revision, previous).unwrap();
        }
        report
    }

    fn prepared_path(session: &StoreSession, prepared: &PreparedUpload) -> std::path::PathBuf {
        // The snapshot is the only library-*.qvl file in the transfer folder.
        let _ = prepared;
        std::fs::read_dir(session.layout.cloud_dir())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "qvl"))
            .unwrap()
    }

    fn fetch(device: &TestDevice, cloud: &Cloud, entry_id: &str) -> Vec<u8> {
        let session = seal(device);
        let entry = session.require_file(entry_id).unwrap();
        let object = entry.cloud_object_id.clone().unwrap();
        let download = cloud.pull(&session, &object);
        crate::commands::vault_cloud::tests_restore_file(&session, &download, entry_id, &object);
        let entry = session.require_file(entry_id).unwrap();
        session.decrypt_into(&entry, Vec::new(), &mut |_| {}).unwrap()
    }

    #[test]
    fn two_devices_share_one_library_through_the_recovery_copy_of_the_key() {
        let root = vault_recovery::generate_recovery_root();
        let laptop = device_of(None);
        with_recovery(&laptop, &root);
        let phone = device_of(Some(&laptop.user));
        with_recovery(&phone, &root);
        let mut cloud = Cloud::default();

        // Laptop starts the library and backs up a file.
        create(&seal(&laptop)).unwrap();
        let doc = import(&laptop, "Lease.pdf", b"%PDF-1.7 lease agreement");
        back_up(&laptop, &mut cloud, &doc);
        sync(&laptop, &mut cloud);
        let envelope = recovery_envelope(&seal(&laptop)).unwrap();

        // Phone joins with its own recovery key, merges, sees the file (cloud only),
        // downloads it under ITS vault key.
        accept_recovery(&seal(&phone), &envelope, None).unwrap();
        let report = sync(&phone, &mut cloud);
        assert_eq!(report.added, 1);
        let listed = load(&seal(&phone)).unwrap();
        assert_eq!(listed.get(&doc.id).unwrap().name, "Lease.pdf");
        assert!(!seal(&phone).layout.object_path(&doc.id).unwrap().exists());
        assert_eq!(fetch(&phone, &cloud, &doc.id), b"%PDF-1.7 lease agreement");

        // Phone renames it; laptop picks the rename up.
        seal(&phone).update(|index| index.rename(&doc.id, "Lease 2026.pdf").map(|_| ())).unwrap();
        sync(&phone, &mut cloud);
        sync(&laptop, &mut cloud);
        assert_eq!(load(&seal(&laptop)).unwrap().get(&doc.id).unwrap().name, "Lease 2026.pdf");

        // Laptop deletes it permanently; the phone's copy goes too.
        seal(&laptop).update(|index| index.trash(&doc.id).map(|_| ())).unwrap();
        crate::commands::vault_store::tests_purge_trash(&seal(&laptop));
        sync(&laptop, &mut cloud);
        let report = sync(&phone, &mut cloud);
        assert_eq!(report.removed, vec![doc.id.clone()]);
        assert!(load(&seal(&phone)).unwrap().get(&doc.id).is_none());
        assert!(!seal(&phone).layout.object_path(&doc.id).unwrap().exists());
    }

    #[test]
    fn a_pinned_device_receives_the_key_and_an_unpinned_one_does_not() {
        let laptop = device_of(None);
        let tablet = device_of(Some(&laptop.user));
        create(&seal(&laptop)).unwrap();

        // Not approved yet: no wrap is made or accepted.
        assert!(make_wrap(&laptop.state, &seal(&laptop), &tablet.call_peer()).is_err());

        pin_each_other(&laptop, &tablet);
        let wrap = make_wrap(&laptop.state, &seal(&laptop), &tablet.call_peer()).unwrap();
        // Addressed to another device, or forged: refused.
        let stranger = device_of(Some(&laptop.user));
        pin_each_other(&laptop, &stranger);
        assert!(accept_wrap(&stranger.state, &seal(&stranger), &wrap, &laptop.call_peer()).is_err());
        let mut forged = wrap.clone();
        forged.epoch += 1;
        assert!(accept_wrap(&tablet.state, &seal(&tablet), &forged, &laptop.call_peer()).is_err());

        let status = accept_wrap(&tablet.state, &seal(&tablet), &wrap, &laptop.call_peer()).unwrap();
        assert!(status.has_ring);
        assert_eq!(status.epoch, Some(1));
    }

    #[test]
    fn a_removed_device_cannot_read_what_comes_after_the_rotation() {
        let root = vault_recovery::generate_recovery_root();
        let laptop = device_of(None);
        with_recovery(&laptop, &root);
        let lost_phone = device_of(Some(&laptop.user));
        let mut cloud = Cloud::default();
        create(&seal(&laptop)).unwrap();
        pin_each_other(&laptop, &lost_phone);
        let wrap = make_wrap(&laptop.state, &seal(&laptop), &lost_phone.call_peer()).unwrap();
        accept_wrap(&lost_phone.state, &seal(&lost_phone), &wrap, &laptop.call_peer()).unwrap();

        let old = import(&laptop, "old.txt", b"before the loss");
        back_up(&laptop, &mut cloud, &old);
        sync(&laptop, &mut cloud);
        assert_eq!(sync(&lost_phone, &mut cloud).added, 1);

        // The phone is removed: new epoch, every wrap moved, new document.
        rotate(&seal(&laptop)).unwrap();
        let new = import(&laptop, "new.txt", b"after the loss");
        back_up(&laptop, &mut cloud, &new);
        sync(&laptop, &mut cloud);

        // The phone cannot open the new document at all.
        let (revision, object) = cloud.library.clone().unwrap();
        let session = seal(&lost_phone);
        let download = cloud.pull(&session, &object);
        assert!(merge_download(&session, &download, revision).unwrap_err().to_string().contains(library::LIBRARY_KEY_MISSING));
        // And the recovery copy for the new epoch needs the recovery key, which it lacks.
        let envelope = recovery_envelope(&seal(&laptop)).unwrap();
        assert_eq!(envelope.epoch, 2);
        assert!(accept_recovery(&seal(&lost_phone), &envelope, None).is_err());
    }

    #[test]
    fn a_device_that_lost_the_race_to_start_the_library_adopts_the_winner() {
        let root = vault_recovery::generate_recovery_root();
        let a = device_of(None);
        with_recovery(&a, &root);
        let b = device_of(Some(&a.user));
        with_recovery(&b, &root);
        create(&seal(&a)).unwrap();
        create(&seal(&b)).unwrap(); // both think they are first
        let file = import(&b, "b.txt", b"made on b");
        let mut cloud = Cloud::default();
        back_up(&b, &mut cloud, &file);
        // b wraps its file key under its own (losing) ring...
        ensure_library_feks(&seal(&b)).unwrap();
        // ...then takes the winner's ring from the recovery copy a stored first.
        let winner = recovery_envelope(&seal(&a)).unwrap();
        accept_recovery(&seal(&b), &winner, None).unwrap();
        let index = load(&seal(&b)).unwrap();
        let sealed = index.get(&file.id).unwrap().library_fek.clone().unwrap();
        let a_ring = load(&seal(&a)).unwrap().library.ring.unwrap();
        // a can open b's file key: one library again.
        assert!(library::unwrap_fek(&a_ring, &a.user, &file.id, &sealed).is_ok());
    }
}