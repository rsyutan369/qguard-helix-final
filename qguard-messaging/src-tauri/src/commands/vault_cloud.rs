use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::Serialize;
use crate::crypto::provider::{sha3_256, Sha3_256Hasher as Sha3_256};
use base64::Engine as _;
use tauri::ipc::Response;
use tauri::State;
use zeroize::Zeroizing;

use crate::commands::vault::{run_stream_blocking, VaultNeed};
use crate::commands::vault_store::{lock_store, open_session, StoreSession};
use crate::crypto::symmetric::KEY_SIZE;
use crate::crypto::vault_recovery;
use crate::error::{QGuardError, Result};
use crate::state::AppState;
use crate::vault::library;
use crate::vault::store::{self, StoreEntry, StoreIndex, StoreKeys, INTEGRITY_VERIFIED};
use crate::vault_stream;

// ---------------------------------------------------------------------------
// Quantum Vault cloud backup (phase 2). Design: docs/QUANTUM_VAULT_STORAGE.md.
//
// Division of labour:
//   * Rust (here) owns everything that touches keys or plaintext metadata: which
//     files still need backing up, the per-part SHA3-256 manifest, sealing the
//     recovery copy of the index, checking every downloaded part, re-binding a
//     restored container to this device's vault, and the durable queue of
//     cloud deletions in the sealed index.
//   * The app's Supabase client (lib/vault-cloud.ts) moves opaque bytes: it asks
//     the database for a quota-checked reservation (migration 048), uploads the
//     8 MiB parts this module hands it, and commits. It never sees a key or a
//     name.
//
// What leaves the device: v5 containers (no name, no type in the header) and
// the index sealed under the recovery key. Nothing else.
//
// Uploading needs a personal recovery key: a backup that could only be opened
// with this device's vault key would be lost together with the device, which is
// the one case a backup is for.
//
// The work is done by plain functions over a `StoreSession`; the Tauri commands
// at the bottom only open the session and run them off the main thread.
// ---------------------------------------------------------------------------

/// Must equal `qv_cloud_objects.part_size` and the bucket's file size limit.
pub const PART_SIZE: u64 = 8 * 1024 * 1024;

pub(crate) const KIND_FILE: &str = "file";
pub(crate) const KIND_RECOVERY_INDEX: &str = "recovery_index";
pub(crate) const KIND_LIBRARY_INDEX: &str = "library_index";

fn part_count(bytes: u64) -> u64 {
    bytes.div_ceil(PART_SIZE)
}

fn cloud_err(message: &str) -> QGuardError {
    QGuardError::InvalidInput(message.to_string())
}

fn poisoned() -> QGuardError {
    QGuardError::Storage("cloud transfer state poisoned".to_string())
}

// ---- in-flight transfers (memory only; a restart simply prepares again) ----

pub(crate) struct UploadManifest {
    pub(crate) id: String,
    pub(crate) user_id: String,
    pub(crate) kind: &'static str,
    pub(crate) entry_id: Option<String>,
    pub(crate) path: PathBuf,
    /// The file is a snapshot made for this upload and is removed with it.
    pub(crate) temporary: bool,
    pub(crate) container_bytes: u64,
    pub(crate) part_sha3: Vec<String>,
    /// For an index snapshot: the digest of what it holds.
    pub(crate) digest: Option<String>,
    /// A file uploaded so it can be shared, not as part of a backup run.
    pub(crate) for_sharing: bool,
}

struct DownloadManifest {
    id: String,
    user_id: String,
    path: PathBuf,
    container_bytes: u64,
    part_sha3: Vec<String>,
    container_sha3: String,
    next_part: u64,
    written: u64,
    hasher: Sha3_256,
}

/// A recovery index opened with the recovery key, for the restore in progress.
struct RestoreSession {
    user_id: String,
    wrap_key: Zeroizing<[u8; KEY_SIZE]>,
    index: StoreIndex,
}

static UPLOADS: Mutex<Vec<UploadManifest>> = Mutex::new(Vec::new());
static DOWNLOADS: Mutex<Vec<DownloadManifest>> = Mutex::new(Vec::new());
static RESTORE: Mutex<Vec<RestoreSession>> = Mutex::new(Vec::new());

/// SHA3-256 of each `PART_SIZE` slice and of the whole file.
pub(crate) fn hash_parts(path: &PathBuf) -> Result<(u64, Vec<String>, String)> {
    let mut file = BufReader::new(File::open(path).map_err(|e| QGuardError::Storage(format!("open for backup: {e}")))?);
    let mut whole = Sha3_256::new();
    let mut parts = Vec::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let mut part = Sha3_256::new();
        let mut in_part = 0u64;
        while in_part < PART_SIZE {
            let want = (PART_SIZE - in_part).min(buf.len() as u64) as usize;
            let n = file.read(&mut buf[..want]).map_err(|e| QGuardError::Storage(format!("read for backup: {e}")))?;
            if n == 0 {
                break;
            }
            part.update(&buf[..n]);
            whole.update(&buf[..n]);
            in_part += n as u64;
        }
        if in_part == 0 {
            break;
        }
        total += in_part;
        parts.push(hex::encode(part.finalize()));
        if in_part < PART_SIZE {
            break;
        }
    }
    if total == 0 {
        return Err(cloud_err("nothing to back up: the file is empty"));
    }
    Ok((total, parts, hex::encode(whole.finalize())))
}

// ---------------------------------------------------------------------------
// State, settings, plan
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudState {
    pub enabled: bool,
    pub enabled_at: Option<DateTime<Utc>>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    /// A personal recovery key is configured here (required to back up).
    pub recovery_ready: bool,
    pub backed_up_files: u64,
    pub backed_up_bytes: u64,
    pub pending_uploads: u64,
    pub pending_upload_bytes: u64,
    pub pending_deletes: u64,
    /// The cloud holds a recovery index matching the current folders and names.
    pub index_current: bool,
    /// Files whose container is gone from this device but backed up.
    pub restorable_missing: u64,
    /// Cloud copies that exist only because the file is shared (backup off);
    /// not counted as backed up.
    pub shared_copies: u64,
    pub shared_copy_bytes: u64,
}

fn needs_upload(session: &StoreSession, index: &StoreIndex, entry: &StoreEntry) -> bool {
    entry.is_file()
        && entry.cloud_object_id.is_none()
        && !index.in_trash(&entry.id)
        && entry.integrity != store::INTEGRITY_FAILED
        && session.layout.object_path(&entry.id).map(|p| p.is_file()).unwrap_or(false)
}

fn cloud_state(session: &StoreSession, index: &StoreIndex) -> CloudState {
    let on_disk = session.layout.object_ids();
    let mut state = CloudState {
        enabled: index.cloud.enabled,
        enabled_at: index.cloud.enabled_at,
        last_sync_at: index.cloud.last_sync_at,
        last_error: index.cloud.last_error.clone(),
        recovery_ready: can_back_up(session, index),
        backed_up_files: 0,
        backed_up_bytes: 0,
        pending_uploads: 0,
        pending_upload_bytes: 0,
        pending_deletes: index.cloud.pending_deletes.len() as u64,
        index_current: index.cloud.index_object_id.is_some()
            && index.cloud.index_digest.as_deref() == Some(index.structure_digest().as_str()),
        restorable_missing: 0,
        shared_copies: 0,
        shared_copy_bytes: 0,
    };
    for entry in index.entries.iter().filter(|e| e.is_file()) {
        if entry.cloud_object_id.is_some() && entry.cloud_shared_only {
            state.shared_copies += 1;
            state.shared_copy_bytes += entry.stored_bytes;
        } else if entry.cloud_object_id.is_some() {
            state.backed_up_files += 1;
            state.backed_up_bytes += entry.stored_bytes;
            if !on_disk.contains(&entry.id) {
                state.restorable_missing += 1;
            }
        } else if index.cloud.enabled && needs_upload(session, index, entry) {
            state.pending_uploads += 1;
            state.pending_upload_bytes += entry.stored_bytes;
        }
    }
    state
}

pub(crate) fn load(session: &StoreSession) -> Result<StoreIndex> {
    let _guard = lock_store()?;
    session.load()
}

fn state_of(session: &StoreSession) -> Result<CloudState> {
    Ok(cloud_state(session, &load(session)?))
}

/// Backing up needs a way to open the backup without this device: the personal
/// recovery key here, or the account library key (whose recovery-key copy
/// another device keeps in the cloud).
fn can_back_up(session: &StoreSession, index: &StoreIndex) -> bool {
    session.ctx.personal_recovery_wrap_key().is_some() || index.library.ring.is_some()
}

fn set_enabled(session: &StoreSession, enabled: bool) -> Result<CloudState> {
    if enabled && !can_back_up(session, &load(session)?) {
        return Err(cloud_err(
            "cloud backup needs your recovery key on this device (or this device approved for your vault library) — without one a backup could never be opened on another device",
        ));
    }
    let index = session.update(|index| {
        if index.cloud.enabled != enabled {
            index.cloud.enabled = enabled;
            if enabled {
                index.cloud.enabled_at = Some(Utc::now());
                // A copy uploaded for sharing is the same object a backup
                // would upload (one per file): from now on it is the backup.
                for entry in index.entries.iter_mut().filter(|e| e.cloud_shared_only) {
                    entry.cloud_shared_only = false;
                }
            }
            index.cloud.last_error = None;
            index.log(
                if enabled { "cloud_enable" } else { "cloud_disable" },
                None,
                "Cloud backup",
                if enabled {
                    "Turned on · encrypted containers and the recovery-key-sealed index will be uploaded"
                } else {
                    "Turned off · nothing more will be uploaded; existing backups are kept"
                },
                true,
            );
        }
        Ok(index.clone())
    })?;
    Ok(cloud_state(session, &index))
}

/// Turn backup off and queue every backed-up object for deletion from the
/// cloud. Local files are untouched. A copy that a live share still uses
/// (`in_use`, from the server's share list) is kept as a shared copy instead,
/// so deleting the backup never breaks a share; it goes when the share ends.
fn delete_backup(session: &StoreSession, in_use: &[String]) -> Result<CloudState> {
    let index = session.update(|index| {
        index.cloud.enabled = false;
        let mut doomed: Vec<String> = Vec::new();
        let mut kept = 0u64;
        for entry in index.entries.iter_mut() {
            let Some(object_id) = entry.cloud_object_id.as_deref() else {
                entry.cloud_backed_up_at = None;
                continue;
            };
            if entry.cloud_shared_only || in_use.iter().any(|id| id == object_id) {
                entry.cloud_shared_only = true;
                kept += 1;
                continue;
            }
            doomed.extend(entry.cloud_object_id.take());
            entry.cloud_backed_up_at = None;
        }
        if let Some(id) = index.cloud.index_object_id.take() {
            doomed.push(id);
        }
        index.cloud.index_digest = None;
        let count = doomed.len();
        index.cloud.pending_deletes.extend(doomed);
        let detail = if kept > 0 {
            format!("Backup turned off and {count} object(s) queued for deletion from the cloud · {kept} kept for active shares")
        } else {
            format!("Backup turned off and {count} object(s) queued for deletion from the cloud")
        };
        index.log("cloud_delete", None, "Cloud backup", &detail, true);
        Ok(index.clone())
    })?;
    Ok(cloud_state(session, &index))
}

/// What a sync run should do now.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudPlan {
    pub enabled: bool,
    pub uploads: Vec<PlannedUpload>,
    pub deletes: Vec<String>,
    pub index_needed: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedUpload {
    pub entry_id: String,
    pub name: String,
    pub stored_bytes: u64,
}

fn plan(session: &StoreSession) -> Result<CloudPlan> {
    clear_stale_transfers(session);
    let index = load(session)?;
    let enabled = index.cloud.enabled && can_back_up(session, &index);
    let uploads = if enabled {
        index
            .entries
            .iter()
            .filter(|e| needs_upload(session, &index, e))
            .map(|e| PlannedUpload { entry_id: e.id.clone(), name: e.name.clone(), stored_bytes: e.stored_bytes })
            .collect()
    } else {
        Vec::new()
    };
    // The per-device recovery index is only for an account without a library:
    // the library document (phase 3) supersedes it.
    let index_needed = enabled
        && index.library.ring.is_none()
        && session.ctx.personal_recovery_wrap_key().is_some()
        && !index.entries.is_empty()
        && index.cloud.index_digest.as_deref() != Some(index.structure_digest().as_str());
    Ok(CloudPlan { enabled, uploads, deletes: index.cloud.pending_deletes.clone(), index_needed })
}

fn record_sync(session: &StoreSession, error: Option<String>) -> Result<()> {
    session.update(|index| {
        index.cloud.last_sync_at = Some(Utc::now());
        index.cloud.last_error = error.map(|e| e.chars().take(300).collect());
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedUpload {
    pub upload_id: String,
    pub kind: String,
    pub entry_id: Option<String>,
    pub container_bytes: u64,
    pub part_size: u64,
    pub part_sha3: Vec<String>,
    pub container_sha3: String,
    pub device_id: String,
}

pub(crate) fn register_upload(manifest: UploadManifest, container_sha3: String, device_id: String) -> Result<PreparedUpload> {
    let prepared = PreparedUpload {
        upload_id: manifest.id.clone(),
        kind: manifest.kind.to_string(),
        entry_id: manifest.entry_id.clone(),
        container_bytes: manifest.container_bytes,
        part_size: PART_SIZE,
        part_sha3: manifest.part_sha3.clone(),
        container_sha3,
        device_id,
    };
    let replaced: Vec<UploadManifest> = {
        let mut uploads = UPLOADS.lock().map_err(|_| poisoned())?;
        // One upload per object at a time; an older manifest for it is replaced.
        let same = |m: &UploadManifest| m.user_id == manifest.user_id && m.kind == manifest.kind && m.entry_id == manifest.entry_id;
        let (gone, kept): (Vec<_>, Vec<_>) = uploads.drain(..).partition(same);
        *uploads = kept;
        uploads.push(manifest);
        gone
    };
    for old in replaced.into_iter().filter(|m| m.temporary) {
        let _ = std::fs::remove_file(&old.path);
    }
    Ok(prepared)
}

/// Remove transfer files a previous run left behind, but only while this
/// account has nothing in flight.
fn clear_stale_transfers(session: &StoreSession) {
    let user_id = &session.ctx.user_id;
    let busy = UPLOADS.lock().map(|u| u.iter().any(|m| &m.user_id == user_id)).unwrap_or(true)
        || DOWNLOADS.lock().map(|d| d.iter().any(|m| &m.user_id == user_id)).unwrap_or(true);
    if busy {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(session.layout.cloud_dir()) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Open `path` as a container of THIS vault and check it is exactly `entry`.
pub(crate) fn verify_as_owned(session: &StoreSession, path: &PathBuf, entry: &StoreEntry) -> Result<vault_stream::StreamSummary> {
    let mut reader = BufReader::new(File::open(path).map_err(|e| QGuardError::Storage(format!("open vault object: {e}")))?);
    let mut sink = store::HashingWriter::new(std::io::sink());
    let summary = vault_stream::decrypt_stream_owner(&mut reader, &mut sink, &session.ctx.owner_access(false))?;
    let (_, hash, len) = sink.finish();
    if len != entry.size_bytes || (!entry.plaintext_sha3.is_empty() && hash != entry.plaintext_sha3) {
        return Err(QGuardError::Crypto(
            "content does not match the SHA3-256 recorded when it was sealed".to_string(),
        ));
    }
    Ok(summary)
}

/// Re-protect a stored container in place so it carries this account's
/// recovery wrap (files added before recovery was set up). Same operation as
/// "Re-protect" in the tools, on the vault's own object; the new copy must open
/// and match before it replaces the old one.
fn ensure_recovery_wrap(session: &StoreSession, entry: &StoreEntry) -> Result<StoreEntry> {
    if entry.recovery_protected && entry.pin_bound {
        return Ok(entry.clone());
    }
    let object = session.layout.object_path(&entry.id)?;
    let tmp = session.layout.cloud_dir().join(format!("reprotect-{}.qvault", uuid::Uuid::new_v4()));
    let rewrapped = (|| -> Result<vault_stream::StreamSummary> {
        let mut reader = BufReader::new(File::open(&object).map_err(|e| QGuardError::Storage(format!("open vault object: {e}")))?);
        let mut writer = BufWriter::new(File::create(&tmp).map_err(|e| QGuardError::Storage(format!("create re-protected object: {e}")))?);
        vault_stream::rewrap_stream_with_progress(
            &mut reader,
            &mut writer,
            &session.ctx.owner_access(false),
            &session.ctx.owner_seal(),
            &mut |_| {},
        )?;
        writer
            .flush()
            .and_then(|_| writer.get_ref().sync_all())
            .map_err(|e| QGuardError::Storage(format!("flush re-protected object: {e}")))?;
        drop(writer);
        verify_as_owned(session, &tmp, entry)
    })();
    let summary = match rewrapped {
        Ok(summary) => summary,
        Err(error) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(error);
        }
    };
    let stored_bytes = store::file_len(&tmp);
    let outcome = session.update(|index| {
        let target = index.get_mut(&entry.id).ok_or_else(|| QGuardError::NotFound("vault item not found".to_string()))?;
        std::fs::rename(&tmp, &object).map_err(|e| QGuardError::Storage(format!("replace re-protected object: {e}")))?;
        target.container_version = summary.container_version;
        target.pin_bound = summary.pin_bound;
        target.recovery_protected = true;
        target.stored_bytes = stored_bytes;
        target.integrity = INTEGRITY_VERIFIED.to_string();
        target.last_verified_at = Some(Utc::now());
        let updated = target.clone();
        index.log("reprotect", Some(&entry.id), &entry.name, "Re-protected with your recovery key before backup", true);
        Ok(updated)
    });
    if outcome.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    outcome
}

/// Prepare one stored file for upload: make sure it carries a recovery wrap,
/// then hash it part by part.
fn prepare_file(session: &StoreSession, entry_id: &str) -> Result<PreparedUpload> {
    let index = load(session)?;
    if !can_back_up(session, &index) {
        return Err(cloud_err("cloud backup needs your recovery key or the vault library key on this device"));
    }
    if !index.cloud.enabled {
        return Err(cloud_err("cloud backup is turned off"));
    }
    let entry = session.require_file(entry_id)?;
    // With a recovery key here, every uploaded container also opens with it.
    // Without one, the library key (and its recovery copy) is how it is opened.
    let entry = if session.ctx.personal_recovery_wrap_key().is_some() { ensure_recovery_wrap(session, &entry)? } else { entry };
    let path = session.layout.object_path(&entry.id)?;
    let (bytes, part_sha3, container_sha3) = hash_parts(&path)?;
    register_upload(
        UploadManifest {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: session.ctx.user_id.clone(),
            kind: KIND_FILE,
            entry_id: Some(entry.id.clone()),
            path,
            temporary: false,
            container_bytes: bytes,
            part_sha3,
            digest: None,
            for_sharing: false,
        },
        container_sha3,
        session.ctx.device_id.clone(),
    )
}

/// Upload ONE file's encrypted container so it can be shared — with cloud
/// backup on or off. Sharing must not require backing everything up: only this
/// file goes, sealed exactly as a backup of it would be (so if backup is
/// switched on later it simply counts as backed up). With backup off the copy
/// is marked shared-only and taken back when no share uses it.
fn prepare_share_copy(session: &StoreSession, entry_id: &str) -> Result<PreparedUpload> {
    let entry = session.require_file(entry_id)?;
    if entry.cloud_object_id.is_some() {
        return Err(cloud_err("this file already has an encrypted cloud copy"));
    }
    if entry.integrity == store::INTEGRITY_FAILED {
        return Err(cloud_err("this file failed its integrity check and cannot be shared"));
    }
    let path = session.layout.object_path(&entry.id)?;
    if !path.is_file() {
        return Err(cloud_err("this file is not on this device"));
    }
    // With a recovery key here, the copy also opens with it, as a backup would.
    let entry = if session.ctx.personal_recovery_wrap_key().is_some() { ensure_recovery_wrap(session, &entry)? } else { entry };
    let (bytes, part_sha3, container_sha3) = hash_parts(&path)?;
    register_upload(
        UploadManifest {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: session.ctx.user_id.clone(),
            kind: KIND_FILE,
            entry_id: Some(entry.id.clone()),
            path,
            temporary: false,
            container_bytes: bytes,
            part_sha3,
            digest: None,
            for_sharing: true,
        },
        container_sha3,
        session.ctx.device_id.clone(),
    )
}

/// Take back a copy that was uploaded only for sharing, once no share uses it:
/// it is queued for deletion like a deleted file's backup. Never touches a
/// backup copy (backup on, or uploaded as a backup), nor a copy that is the
/// only one left (the file is no longer on this device).
fn release_share_copy(session: &StoreSession, entry_id: &str, object_id: &str) -> Result<bool> {
    let local = session.layout.object_path(entry_id).map(|path| path.is_file()).unwrap_or(false);
    session.update(|index| {
        let backup_on = index.cloud.enabled;
        let Some(target) = index.get_mut(entry_id) else {
            return Ok(false);
        };
        if backup_on || !local || !target.cloud_shared_only || target.cloud_object_id.as_deref() != Some(object_id) {
            return Ok(false);
        }
        target.cloud_object_id = None;
        target.cloud_backed_up_at = None;
        target.cloud_shared_only = false;
        let name = target.name.clone();
        index.cloud.pending_deletes.push(object_id.to_string());
        index.log(
            "cloud_share_copy_removed",
            Some(entry_id),
            &name,
            "Shared copy removed from the cloud · no share uses it any more",
            true,
        );
        Ok(true)
    })
}

/// Seal the current index under the recovery key into a snapshot and prepare
/// it for upload.
fn prepare_index(session: &StoreSession) -> Result<PreparedUpload> {
    let wrap_key = session
        .ctx
        .personal_recovery_wrap_key()
        .ok_or_else(|| cloud_err("cloud backup needs a personal recovery key"))?;
    let recovery_keys = StoreKeys::for_recovery(wrap_key)?;
    let index = load(session)?;
    let snapshot = session.layout.cloud_dir().join(format!("index-{}.qvs", uuid::Uuid::new_v4()));
    store::save_index_at(&snapshot, &recovery_keys, &session.ctx.user_id, &index)?;
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
            kind: KIND_RECOVERY_INDEX,
            entry_id: None,
            path: snapshot,
            temporary: true,
            container_bytes: bytes,
            part_sha3,
            digest: Some(index.structure_digest()),
            for_sharing: false,
        },
        container_sha3,
        session.ctx.device_id.clone(),
    )
}

/// The bytes of one part, re-hashed against the manifest so a file that
/// changed after it was prepared can never be uploaded under the old hashes.
fn read_part(user_id: &str, upload_id: &str, part_index: u64) -> Result<Vec<u8>> {
    let (path, expected, total) = {
        let uploads = UPLOADS.lock().map_err(|_| poisoned())?;
        let manifest = uploads
            .iter()
            .find(|m| m.id == upload_id && m.user_id == user_id)
            .ok_or_else(|| cloud_err("unknown or finished upload"))?;
        let expected = manifest
            .part_sha3
            .get(part_index as usize)
            .cloned()
            .ok_or_else(|| cloud_err("part index out of range"))?;
        (manifest.path.clone(), expected, manifest.container_bytes)
    };
    let start = part_index * PART_SIZE;
    let len = (total - start).min(PART_SIZE) as usize;
    let mut file = File::open(&path).map_err(|e| QGuardError::Storage(format!("open for backup: {e}")))?;
    file.seek(SeekFrom::Start(start)).map_err(|e| QGuardError::Storage(format!("seek for backup: {e}")))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).map_err(|e| QGuardError::Storage(format!("read for backup: {e}")))?;
    if hex::encode(sha3_256(&buf)) != expected {
        return Err(QGuardError::Crypto(
            "the file changed after it was prepared for backup — it will be prepared again".to_string(),
        ));
    }
    Ok(buf)
}

/// The server committed the object: record it in the sealed index.
fn complete_upload(session: &StoreSession, upload_id: &str, object_id: &str) -> Result<()> {
    let object_id = store::checked_id(object_id)?;
    let manifest = {
        let mut uploads = UPLOADS.lock().map_err(|_| poisoned())?;
        let position = uploads
            .iter()
            .position(|m| m.id == upload_id && m.user_id == session.ctx.user_id)
            .ok_or_else(|| cloud_err("unknown or finished upload"))?;
        uploads.remove(position)
    };
    let result = session.update(|index| {
        if manifest.kind == KIND_FILE {
            let entry_id = manifest.entry_id.as_deref().unwrap_or_default();
            let shared_only = manifest.for_sharing && !index.cloud.enabled;
            match index.get_mut(entry_id) {
                Some(target) => {
                    target.cloud_object_id = Some(object_id.clone());
                    target.cloud_backed_up_at = Some(Utc::now());
                    target.cloud_shared_only = shared_only;
                    let name = target.name.clone();
                    if shared_only {
                        index.log("cloud_share_copy", Some(entry_id), &name, "Encrypted copy uploaded so it can be shared · cloud backup stays off", true);
                    } else {
                        index.log("cloud_backup", Some(entry_id), &name, "Encrypted copy backed up to the cloud", true);
                    }
                }
                // Deleted while it was uploading: the cloud copy goes too.
                None => index.cloud.pending_deletes.push(object_id.clone()),
            }
        } else {
            if let Some(previous) = index.cloud.index_object_id.replace(object_id.clone()) {
                if previous != object_id {
                    index.cloud.pending_deletes.push(previous);
                }
            }
            index.cloud.index_digest = manifest.digest.clone();
        }
        Ok(())
    });
    if manifest.temporary {
        let _ = std::fs::remove_file(&manifest.path);
    }
    result
}

/// Remove a finished upload from the transfer table and return it.
pub(crate) fn take_upload(user_id: &str, upload_id: &str) -> Result<UploadManifest> {
    let mut uploads = UPLOADS.lock().map_err(|_| poisoned())?;
    let position = uploads
        .iter()
        .position(|m| m.id == upload_id && m.user_id == user_id)
        .ok_or_else(|| cloud_err("unknown or finished upload"))?;
    Ok(uploads.remove(position))
}

fn discard_upload(user_id: &str, upload_id: &str) -> Result<()> {
    let removed: Vec<UploadManifest> = {
        let mut uploads = UPLOADS.lock().map_err(|_| poisoned())?;
        let (gone, kept): (Vec<_>, Vec<_>) = uploads.drain(..).partition(|m| m.id == upload_id && m.user_id == user_id);
        *uploads = kept;
        gone
    };
    for manifest in removed.into_iter().filter(|m| m.temporary) {
        let _ = std::fs::remove_file(&manifest.path);
    }
    Ok(())
}

/// The server confirmed an object is gone.
fn complete_delete(session: &StoreSession, object_id: &str) -> Result<()> {
    let object_id = store::checked_id(object_id)?;
    session.update(|index| {
        index.cloud.pending_deletes.retain(|id| id != &object_id);
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Download and restore
// ---------------------------------------------------------------------------

pub(crate) fn download_begin(session: &StoreSession, container_bytes: u64, part_sha3: Vec<String>, container_sha3: String) -> Result<String> {
    if container_bytes == 0 || part_count(container_bytes) != part_sha3.len() as u64 {
        return Err(cloud_err("download manifest does not match its size"));
    }
    let is_hash = |h: &str| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !is_hash(&container_sha3) || !part_sha3.iter().all(|h| is_hash(h)) {
        return Err(cloud_err("download manifest hashes are malformed"));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let path = session.layout.cloud_dir().join(format!("download-{id}.part"));
    File::create(&path).map_err(|e| QGuardError::Storage(format!("create download: {e}")))?;
    DOWNLOADS.lock().map_err(|_| poisoned())?.push(DownloadManifest {
        id: id.clone(),
        user_id: session.ctx.user_id.clone(),
        path,
        container_bytes,
        part_sha3,
        container_sha3,
        next_part: 0,
        written: 0,
        hasher: Sha3_256::new(),
    });
    Ok(id)
}

/// Append one downloaded part. Parts must arrive in order and each must match
/// its SHA3-256 before a byte of it is kept.
pub(crate) fn download_part(user_id: &str, download_id: &str, part_index: u64, bytes: &[u8]) -> Result<u64> {
    let mut downloads = DOWNLOADS.lock().map_err(|_| poisoned())?;
    let manifest = downloads
        .iter_mut()
        .find(|m| m.id == download_id && m.user_id == user_id)
        .ok_or_else(|| cloud_err("unknown or finished download"))?;
    if part_index != manifest.next_part {
        return Err(cloud_err("parts must arrive in order"));
    }
    let expected_len = (manifest.container_bytes - part_index * PART_SIZE).min(PART_SIZE);
    if bytes.len() as u64 != expected_len {
        return Err(QGuardError::Crypto("downloaded part has the wrong size".to_string()));
    }
    if hex::encode(sha3_256(bytes)) != manifest.part_sha3[part_index as usize] {
        return Err(QGuardError::Crypto("downloaded part failed its SHA3-256 check".to_string()));
    }
    let mut file = OpenOptions::new()
        .append(true)
        .open(&manifest.path)
        .map_err(|e| QGuardError::Storage(format!("open download: {e}")))?;
    file.write_all(bytes).map_err(|e| QGuardError::Storage(format!("write download: {e}")))?;
    manifest.hasher.update(bytes);
    manifest.written += bytes.len() as u64;
    manifest.next_part += 1;
    Ok(manifest.written)
}

/// Take a complete, whole-file-verified download out of the transfer table.
pub(crate) fn finish_download(user_id: &str, download_id: &str) -> Result<PathBuf> {
    let manifest = {
        let mut downloads = DOWNLOADS.lock().map_err(|_| poisoned())?;
        let position = downloads
            .iter()
            .position(|m| m.id == download_id && m.user_id == user_id)
            .ok_or_else(|| cloud_err("unknown or finished download"))?;
        downloads.remove(position)
    };
    let complete = manifest.next_part == manifest.part_sha3.len() as u64 && manifest.written == manifest.container_bytes;
    let hash = hex::encode(manifest.hasher.finalize());
    if !complete || hash != manifest.container_sha3 {
        let _ = std::fs::remove_file(&manifest.path);
        return Err(QGuardError::Crypto(if complete {
            "downloaded backup failed its whole-file SHA3-256 check".to_string()
        } else {
            "download is incomplete".to_string()
        }));
    }
    Ok(manifest.path)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreCandidate {
    pub entry_id: String,
    pub name: String,
    pub location: String,
    pub size_bytes: u64,
    pub category: String,
    /// Already in this vault (by id) with its container present.
    pub present: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestorePreview {
    pub files: Vec<RestoreCandidate>,
    pub folders: u64,
}

/// Open a downloaded recovery index with the recovery key and hold it for the
/// restore that follows. Lists the backed-up files (not those in the Trash).
fn restore_open_index(session: &StoreSession, download_id: &str, recovery_key: &str) -> Result<RestorePreview> {
    let path = finish_download(&session.ctx.user_id, download_id)?;
    let opened = (|| -> Result<(Zeroizing<[u8; KEY_SIZE]>, StoreIndex)> {
        let root = Zeroizing::new(
            vault_recovery::decode_recovery_key(recovery_key)
                .map_err(|_| QGuardError::Trust("That recovery key isn't valid.".to_string()))?,
        );
        let wrap_key = Zeroizing::new(vault_recovery::derive_wrap_key(&root)?);
        let keys = StoreKeys::for_recovery(&wrap_key)?;
        let index = store::load_index_at(&path, &keys, &session.ctx.user_id)
            .map_err(|_| QGuardError::Trust("This recovery key does not open this backup.".to_string()))?;
        Ok((wrap_key, index))
    })();
    let _ = std::fs::remove_file(&path);
    let (wrap_key, restored) = opened?;

    let local = load(session).unwrap_or_else(|_| StoreIndex::new());
    let on_disk = session.layout.object_ids();
    let files = restored
        .entries
        .iter()
        .filter(|e| e.is_file() && !restored.in_trash(&e.id))
        .map(|e| RestoreCandidate {
            entry_id: e.id.clone(),
            name: e.name.clone(),
            location: {
                let chain = restored.breadcrumb(&e.id);
                chain[..chain.len().saturating_sub(1)].join(" / ")
            },
            size_bytes: e.size_bytes,
            category: e.category.clone(),
            present: local.get(&e.id).is_some() && on_disk.contains(&e.id),
        })
        .collect();
    let folders = restored.entries.iter().filter(|e| e.is_folder() && !restored.in_trash(&e.id)).count() as u64;
    let mut sessions = RESTORE.lock().map_err(|_| poisoned())?;
    sessions.retain(|r| r.user_id != session.ctx.user_id);
    sessions.push(RestoreSession { user_id: session.ctx.user_id.clone(), wrap_key, index: restored });
    Ok(RestorePreview { files, folders })
}

/// Put one downloaded container back into Vault Storage.
///
/// * A file this vault made opens as this vault's own — the same check as
///   every open.
/// * A file another device of the account made (listed here through the
///   library, cloud copy only) is re-bound to this vault with its file key from
///   the library, then opened in full and checked against the content hash the
///   library recorded.
/// * Otherwise the restore must have been opened with the recovery key: the
///   container is re-bound with its recovery wrap and checked the same way.
fn restore_file(session: &StoreSession, download_id: &str, entry_id: &str, object_id: &str) -> Result<StoreEntry> {
    let entry_id = store::checked_id(entry_id)?;
    let object_id = store::checked_id(object_id)?;
    let downloaded = finish_download(&session.ctx.user_id, download_id)?;
    let result = (|| -> Result<StoreEntry> {
        let local_entry = load(session)?.get(&entry_id).cloned();
        let (meta, wrap_key, source_index) = {
            let sessions = RESTORE.lock().map_err(|_| poisoned())?;
            let restore = sessions.iter().find(|r| r.user_id == session.ctx.user_id);
            let meta = local_entry
                .clone()
                .or_else(|| restore.and_then(|r| r.index.get(&entry_id).cloned()))
                .ok_or_else(|| cloud_err("open the backup with your recovery key first"))?;
            (meta, restore.map(|r| r.wrap_key.clone()), restore.map(|r| r.index.clone()))
        };
        if !meta.is_file() {
            return Err(cloud_err("only files can be restored"));
        }

        // This vault's own container — or re-bind it to this vault, with the
        // file key from the account library (another device's file) or else
        // with the recovery key (a restore).
        let (final_path, summary) = match verify_as_owned(session, &downloaded, &meta) {
            Ok(summary) => (downloaded.clone(), summary),
            Err(own_error) => {
                let ring = load(session)?.library.ring.clone();
                let library_fek = match (meta.library_fek.as_ref(), ring.as_ref()) {
                    (Some(sealed), Some(ring)) => library::unwrap_fek(ring, &session.ctx.user_id, &meta.id, sealed).ok(),
                    _ => None,
                };
                if library_fek.is_none() && wrap_key.is_none() {
                    return Err(own_error);
                }
                let rebound = session.layout.cloud_dir().join(format!("rebound-{}.qvault", uuid::Uuid::new_v4()));
                let rebind = (|| -> Result<vault_stream::StreamSummary> {
                    let mut reader = BufReader::new(File::open(&downloaded).map_err(|e| QGuardError::Storage(format!("open download: {e}")))?);
                    let mut writer = BufWriter::new(File::create(&rebound).map_err(|e| QGuardError::Storage(format!("create restored object: {e}")))?);
                    match (library_fek.as_ref(), wrap_key.as_ref()) {
                        (Some(fek), _) => {
                            vault_stream::reseal_stream_with_file_key(&mut reader, &mut writer, fek, &meta.id, &session.ctx.owner_seal(), false, &mut |_| {})?;
                        }
                        (None, Some(wrap_key)) => {
                            vault_stream::rewrap_stream_with_recovery(&mut reader, &mut writer, wrap_key, &session.ctx.owner_seal(), &mut |_| {})?;
                        }
                        (None, None) => unreachable!("checked above"),
                    }
                    writer
                        .flush()
                        .and_then(|_| writer.get_ref().sync_all())
                        .map_err(|e| QGuardError::Storage(format!("flush restored object: {e}")))?;
                    drop(writer);
                    verify_as_owned(session, &rebound, &meta)
                })();
                let _ = std::fs::remove_file(&downloaded);
                match rebind {
                    Ok(summary) => (rebound, summary),
                    Err(error) => {
                        let _ = std::fs::remove_file(&rebound);
                        return Err(error);
                    }
                }
            }
        };

        let stored_bytes = store::file_len(&final_path);
        let object_path = session.layout.object_path(&entry_id)?;
        let outcome = session.update(|index| {
            if index.get(&entry_id).is_none() {
                let parent = match source_index.as_ref() {
                    Some(source) => index.adopt_ancestors(source, &entry_id)?,
                    None => None,
                };
                index.insert_file(StoreEntry {
                    parent_id: parent,
                    trashed_at: None,
                    has_thumbnail: false,
                    updated_at: Utc::now(),
                    ..meta.clone()
                })?;
            }
            std::fs::rename(&final_path, &object_path).map_err(|e| QGuardError::Storage(format!("store restored object: {e}")))?;
            let target = index.get_mut(&entry_id).expect("present");
            target.container_version = summary.container_version;
            target.pin_bound = summary.pin_bound;
            target.total_chunks = summary.total_chunks;
            target.stored_bytes = stored_bytes;
            target.recovery_protected = true;
            target.integrity = INTEGRITY_VERIFIED.to_string();
            target.last_verified_at = Some(Utc::now());
            // The cloud copy stays this file's backup (it opens with the
            // recovery key), so it is not uploaded again.
            target.cloud_object_id = Some(object_id.clone());
            target.cloud_backed_up_at.get_or_insert_with(Utc::now);
            let updated = target.clone();
            index.log("cloud_restore", Some(&entry_id), &updated.name, "Restored from the cloud backup · verified", true);
            Ok(updated)
        });
        if outcome.is_err() {
            let _ = std::fs::remove_file(&final_path);
        }
        outcome
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&downloaded);
    }
    result
}

/// Test-only: the restore path, as the sync engine drives it.
#[cfg(test)]
pub(crate) fn tests_restore_file(session: &StoreSession, download_id: &str, entry_id: &str, object_id: &str) -> StoreEntry {
    restore_file(session, download_id, entry_id, object_id).expect("restore file")
}

/// End a restore: forget the recovery key and drop unfinished downloads.
fn restore_end(user_id: &str) -> Result<()> {
    RESTORE.lock().map_err(|_| poisoned())?.retain(|r| r.user_id != user_id);
    let stale: Vec<PathBuf> = {
        let mut downloads = DOWNLOADS.lock().map_err(|_| poisoned())?;
        let (gone, kept): (Vec<_>, Vec<_>) = downloads.drain(..).partition(|m| m.user_id == user_id);
        *downloads = kept;
        gone.into_iter().map(|m| m.path).collect()
    };
    for path in stale {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn vault_cloud_state(state: State<'_, AppState>) -> Result<CloudState> {
    let session = open_session(&state, VaultNeed::Seal)?;
    run_stream_blocking(move || state_of(&session)).await
}

/// Turn cloud backup on or off. Off stops uploads; it does not delete what is
/// already backed up (see `vault_cloud_delete_backup`).
#[tauri::command]
pub async fn vault_cloud_set_enabled(state: State<'_, AppState>, enabled: bool) -> Result<CloudState> {
    let session = open_session(&state, VaultNeed::Seal)?;
    let result = run_stream_blocking(move || set_enabled(&session, enabled)).await?;
    state.audit_info(
        if enabled { "vault_cloud_enable" } else { "vault_cloud_disable" },
        if enabled { "Quantum Vault cloud backup turned on" } else { "Quantum Vault cloud backup turned off" },
    );
    Ok(result)
}

/// `keep_object_ids`: cloud objects a live share still uses (they stay).
#[tauri::command]
pub async fn vault_cloud_delete_backup(state: State<'_, AppState>, keep_object_ids: Option<Vec<String>>) -> Result<CloudState> {
    let session = open_session(&state, VaultNeed::Seal)?;
    let in_use = keep_object_ids
        .unwrap_or_default()
        .iter()
        .map(|id| store::checked_id(id))
        .collect::<Result<Vec<_>>>()?;
    let result = run_stream_blocking(move || delete_backup(&session, &in_use)).await?;
    state.audit_info("vault_cloud_delete", "Quantum Vault cloud backup deleted (queued)");
    Ok(result)
}

#[tauri::command]
pub async fn vault_cloud_plan(state: State<'_, AppState>) -> Result<CloudPlan> {
    let session = open_session(&state, VaultNeed::Seal)?;
    run_stream_blocking(move || plan(&session)).await
}

#[tauri::command]
pub async fn vault_cloud_record_sync(state: State<'_, AppState>, error: Option<String>) -> Result<()> {
    let session = open_session(&state, VaultNeed::Open)?;
    run_stream_blocking(move || record_sync(&session, error)).await
}

#[tauri::command]
pub async fn vault_cloud_prepare_file(state: State<'_, AppState>, entry_id: String) -> Result<PreparedUpload> {
    let session = open_session(&state, VaultNeed::Seal)?;
    run_stream_blocking(move || prepare_file(&session, &entry_id)).await
}

/// One file's encrypted container, ready to upload so it can be shared (cloud
/// backup not required).
#[tauri::command]
pub async fn vault_cloud_prepare_share_copy(state: State<'_, AppState>, entry_id: String) -> Result<PreparedUpload> {
    let session = open_session(&state, VaultNeed::Seal)?;
    run_stream_blocking(move || prepare_share_copy(&session, &entry_id)).await
}

/// Queue a shared-only cloud copy for deletion once no share uses it.
#[tauri::command]
pub async fn vault_cloud_release_share_copy(state: State<'_, AppState>, entry_id: String, object_id: String) -> Result<bool> {
    let session = open_session(&state, VaultNeed::Open)?;
    run_stream_blocking(move || release_share_copy(&session, &entry_id, &object_id)).await
}

#[tauri::command]
pub async fn vault_cloud_prepare_index(state: State<'_, AppState>) -> Result<PreparedUpload> {
    let session = open_session(&state, VaultNeed::Seal)?;
    run_stream_blocking(move || prepare_index(&session)).await
}

#[tauri::command]
pub async fn vault_cloud_read_part(state: State<'_, AppState>, upload_id: String, part_index: u64) -> Result<Response> {
    let user_id = state.user_id()?;
    let bytes = run_stream_blocking(move || read_part(&user_id, &upload_id, part_index)).await?;
    Ok(Response::new(bytes))
}

#[tauri::command]
pub async fn vault_cloud_complete_upload(state: State<'_, AppState>, upload_id: String, object_id: String) -> Result<()> {
    let session = open_session(&state, VaultNeed::Seal)?;
    run_stream_blocking(move || complete_upload(&session, &upload_id, &object_id)).await
}

#[tauri::command]
pub async fn vault_cloud_discard_upload(state: State<'_, AppState>, upload_id: String) -> Result<()> {
    let user_id = state.user_id()?;
    run_stream_blocking(move || discard_upload(&user_id, &upload_id)).await
}

#[tauri::command]
pub async fn vault_cloud_complete_delete(state: State<'_, AppState>, object_id: String) -> Result<()> {
    let session = open_session(&state, VaultNeed::Open)?;
    run_stream_blocking(move || complete_delete(&session, &object_id)).await
}

#[tauri::command]
pub async fn vault_cloud_download_begin(
    state: State<'_, AppState>,
    container_bytes: u64,
    part_sha3: Vec<String>,
    container_sha3: String,
) -> Result<String> {
    let session = open_session(&state, VaultNeed::Open)?;
    run_stream_blocking(move || download_begin(&session, container_bytes, part_sha3, container_sha3)).await
}

/// One downloaded part, base64 (`part_b64`). Not a raw request body: Android
/// never delivers one (see `commands::crypto_module`), so a raw-body version of
/// this command could not restore anything there.
#[tauri::command]
pub async fn vault_cloud_download_part(
    state: State<'_, AppState>,
    download_id: String,
    part_index: u64,
    part_b64: String,
) -> Result<u64> {
    let user_id = state.user_id()?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(part_b64)
        .map_err(|_| cloud_err("part is not valid base64"))?;
    run_stream_blocking(move || download_part(&user_id, &download_id, part_index, &bytes)).await
}

#[tauri::command]
pub async fn vault_cloud_restore_open_index(
    state: State<'_, AppState>,
    download_id: String,
    recovery_key: String,
) -> Result<RestorePreview> {
    let session = open_session(&state, VaultNeed::Open)?;
    state.check_decrypt_rate_limit("vault_cloud_restore_index", &session.ctx.user_id, 10, 300)?;
    run_stream_blocking(move || restore_open_index(&session, &download_id, &recovery_key)).await
}

#[tauri::command]
pub async fn vault_cloud_restore_file(
    state: State<'_, AppState>,
    download_id: String,
    entry_id: String,
    object_id: String,
) -> Result<StoreEntry> {
    let session = open_session(&state, VaultNeed::Seal)?;
    state.check_decrypt_rate_limit("vault_cloud_restore_file", &entry_id, 30, 300)?;
    let restored = run_stream_blocking(move || restore_file(&session, &download_id, &entry_id, &object_id)).await?;
    state.audit_info("vault_cloud_restore", "Quantum Vault file restored from the cloud backup and verified");
    Ok(restored)
}

#[tauri::command]
pub async fn vault_cloud_restore_end(state: State<'_, AppState>) -> Result<()> {
    let user_id = state.user_id()?;
    run_stream_blocking(move || restore_end(&user_id)).await
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::commands::vault_store::import_one;
    use crate::crypto::signatures::VaultSigningKeypair;
    use crate::crypto::symmetric;
    use crate::state::{PersistedVaultMaster, PersistedVaultRecovery};
    use crate::test_support::TestDevice;

    /// What the database + bucket would hold, keyed by object id.
    struct CloudObject {
        kind: String,
        entry_id: Option<String>,
        parts: Vec<Vec<u8>>,
        part_sha3: Vec<String>,
        container_sha3: String,
        bytes: u64,
    }

    #[derive(Default)]
    struct FakeCloud {
        objects: HashMap<String, CloudObject>,
    }

    impl FakeCloud {
        fn latest_index(&self) -> String {
            self.objects.iter().find(|(_, o)| o.kind == KIND_RECOVERY_INDEX).map(|(id, _)| id.clone()).expect("an index in the cloud")
        }
        fn object_for(&self, entry_id: &str) -> String {
            self.objects.iter().find(|(_, o)| o.entry_id.as_deref() == Some(entry_id)).map(|(id, _)| id.clone()).expect("object")
        }
    }

    fn master() -> PersistedVaultMaster {
        PersistedVaultMaster { version: 1, vmk: symmetric::random_key(), signer: VaultSigningKeypair::generate(), configured_at: Utc::now() }
    }

    fn unlock(device: &TestDevice) {
        device.state.set_vault_session(master()).unwrap();
    }

    /// Configure the account's personal recovery key on this device.
    fn with_recovery(device: &TestDevice, root: &[u8; 32]) {
        let wrap_key = vault_recovery::derive_wrap_key(root).unwrap();
        let vault_key = device.state.unlocked_vault_master().unwrap().vault_key().unwrap();
        device
            .state
            .save_vault_recovery(&device.user, &PersistedVaultRecovery::personal(wrap_key, "verifier".to_string()), &vault_key)
            .unwrap();
    }

    fn seal(device: &TestDevice) -> StoreSession {
        open_session(&device.state, VaultNeed::Seal).unwrap()
    }

    fn import(device: &TestDevice, name: &str, bytes: &[u8], folders: &[&str]) -> StoreEntry {
        let dir = device.dir.join("sources");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        let parts: Vec<String> = folders.iter().map(|s| s.to_string()).collect();
        import_one(&seal(device), &path.to_string_lossy(), None, &parts, true, &mut |_| {}).unwrap().entry
    }

    fn push(session: &StoreSession, cloud: &mut FakeCloud, prepared: PreparedUpload) -> String {
        let parts: Vec<Vec<u8>> = (0..prepared.part_sha3.len() as u64)
            .map(|i| read_part(&session.ctx.user_id, &prepared.upload_id, i).unwrap())
            .collect();
        assert!(parts.iter().all(|p| p.len() as u64 <= PART_SIZE));
        let object_id = uuid::Uuid::new_v4().to_string();
        cloud.objects.insert(
            object_id.clone(),
            CloudObject {
                kind: prepared.kind.clone(),
                entry_id: prepared.entry_id.clone(),
                parts,
                part_sha3: prepared.part_sha3.clone(),
                container_sha3: prepared.container_sha3.clone(),
                bytes: prepared.container_bytes,
            },
        );
        complete_upload(session, &prepared.upload_id, &object_id).unwrap();
        object_id
    }

    /// One sync run, as lib/vault-cloud.ts does it.
    fn sync(session: &StoreSession, cloud: &mut FakeCloud) {
        let plan = plan(session).unwrap();
        for upload in &plan.uploads {
            let prepared = prepare_file(session, &upload.entry_id).unwrap();
            push(session, cloud, prepared);
        }
        if plan.index_needed {
            let prepared = prepare_index(session).unwrap();
            push(session, cloud, prepared);
        }
        for object_id in plan_deletes(session) {
            cloud.objects.remove(&object_id);
            complete_delete(session, &object_id).unwrap();
        }
    }

    fn plan_deletes(session: &StoreSession) -> Vec<String> {
        plan(session).unwrap().deletes
    }

    fn pull(session: &StoreSession, cloud: &FakeCloud, object_id: &str) -> String {
        let object = &cloud.objects[object_id];
        let id = download_begin(session, object.bytes, object.part_sha3.clone(), object.container_sha3.clone()).unwrap();
        for (i, part) in object.parts.iter().enumerate() {
            download_part(&session.ctx.user_id, &id, i as u64, part).unwrap();
        }
        id
    }

    fn open_owned(session: &StoreSession, entry_id: &str) -> Vec<u8> {
        let entry = session.require_file(entry_id).unwrap();
        session.decrypt_into(&entry, Vec::new(), &mut |_| {}).unwrap()
    }

    #[test]
    fn a_new_device_restores_the_whole_library_with_only_the_recovery_key() {
        let root = vault_recovery::generate_recovery_root();
        let a = TestDevice::new(false);
        unlock(&a);
        with_recovery(&a, &root);
        let big = vec![7u8; (PART_SIZE + 1234) as usize]; // container spans two parts
        let photo = import(&a, "beach.jpg", &[b"\xFF\xD8\xFF\xE0".as_slice(), &big].concat(), &["Family", "2026"]);
        let note = import(&a, "will.txt", b"leave it all to the cat", &[]);
        let mut cloud = FakeCloud::default();

        let session = seal(&a);
        set_enabled(&session, true).unwrap();
        sync(&session, &mut cloud);
        let state = state_of(&session).unwrap();
        assert_eq!((state.backed_up_files, state.pending_uploads, state.pending_deletes), (2, 0, 0));
        assert!(state.index_current);
        assert_eq!(cloud.objects.len(), 3);
        assert_eq!(cloud.objects[&cloud.object_for(&photo.id)].parts.len(), 2);

        // Nothing the server holds names a file or folder.
        for object in cloud.objects.values() {
            let all: Vec<u8> = object.parts.concat();
            for needle in [&b"beach"[..], b"will.txt", b"Family", b"image/jpeg"] {
                assert!(!all.windows(needle.len()).any(|w| w == needle), "{:?} leaked", String::from_utf8_lossy(needle));
            }
        }

        // Device B: same account, brand-new vault (different vault key), same recovery key.
        let b = TestDevice::open(std::env::temp_dir().join(format!("qguard-device-test-{}", uuid::Uuid::new_v4())), a.user.clone());
        unlock(&b);
        with_recovery(&b, &root);
        let restore = seal(&b);
        let index_download = pull(&restore, &cloud, &cloud.latest_index());
        let preview = restore_open_index(&restore, &index_download, &vault_recovery::encode_recovery_key(&root)).unwrap();
        assert_eq!(preview.files.len(), 2);
        assert_eq!(preview.folders, 2);
        assert!(preview.files.iter().all(|f| !f.present));
        for file in &preview.files {
            let object_id = cloud.object_for(&file.entry_id);
            let download = pull(&restore, &cloud, &object_id);
            let restored = restore_file(&restore, &download, &file.entry_id, &object_id).unwrap();
            assert_eq!(restored.integrity, INTEGRITY_VERIFIED);
        }
        restore_end(&b.user).unwrap();

        // B now owns both files under its own vault key, with folders back.
        assert_eq!(open_owned(&restore, &note.id), b"leave it all to the cat");
        assert_eq!(open_owned(&restore, &photo.id).len() as u64, photo.size_bytes);
        let index = restore.load().unwrap();
        let parent = index.get(&photo.id).unwrap().parent_id.clone().unwrap();
        assert_eq!(index.breadcrumb(&parent), vec!["Family", "2026"]);
        // Restored files are already backed up: nothing to upload again.
        set_enabled(&restore, true).unwrap();
        assert!(plan(&restore).unwrap().uploads.is_empty());
        let _ = std::fs::remove_dir_all(&b.dir);
    }

    #[test]
    fn a_wrong_recovery_key_or_a_tampered_part_gets_nothing() {
        let root = vault_recovery::generate_recovery_root();
        let a = TestDevice::new(false);
        unlock(&a);
        with_recovery(&a, &root);
        let entry = import(&a, "secret.txt", b"classified", &[]);
        let session = seal(&a);
        set_enabled(&session, true).unwrap();
        let mut cloud = FakeCloud::default();
        sync(&session, &mut cloud);

        let wrong = vault_recovery::encode_recovery_key(&vault_recovery::generate_recovery_root());
        let download = pull(&session, &cloud, &cloud.latest_index());
        let error = restore_open_index(&session, &download, &wrong).unwrap_err().to_string();
        assert!(error.contains("does not open this backup"), "{error}");

        // A part altered in the cloud is refused before any byte is kept.
        let object_id = cloud.object_for(&entry.id);
        let object = &cloud.objects[&object_id];
        let id = download_begin(&session, object.bytes, object.part_sha3.clone(), object.container_sha3.clone()).unwrap();
        let mut forged = object.parts[0].clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(download_part(&session.ctx.user_id, &id, 0, &forged).is_err());
        // Out of order, or a finish before every part: refused too.
        assert!(download_part(&session.ctx.user_id, &id, 1, &object.parts[0]).is_err());
        assert!(finish_download(&session.ctx.user_id, &id).is_err());

        // A server that swaps in another vault's container (consistent hashes and
        // all) still cannot get it accepted as this file.
        let stranger = TestDevice::new(false);
        unlock(&stranger);
        with_recovery(&stranger, &vault_recovery::generate_recovery_root());
        let theirs = import(&stranger, "secret.txt", b"classified", &[]);
        let their_session = seal(&stranger);
        set_enabled(&their_session, true).unwrap();
        let mut their_cloud = FakeCloud::default();
        sync(&their_session, &mut their_cloud);
        let swapped_id = their_cloud.object_for(&theirs.id);
        let swapped = pull(&session, &their_cloud, &swapped_id);
        std::fs::remove_file(session.layout.object_path(&entry.id).unwrap()).unwrap();
        assert!(restore_file(&session, &swapped, &entry.id, &swapped_id).is_err());
    }

    #[test]
    fn nothing_is_uploaded_unless_backup_is_on_and_deletes_follow_the_vault() {
        let root = vault_recovery::generate_recovery_root();
        let a = TestDevice::new(false);
        unlock(&a);
        let first = import(&a, "a.txt", b"one", &[]);
        let session = seal(&a);
        // Off by default, and cannot be turned on without a recovery key.
        assert!(!state_of(&session).unwrap().enabled);
        assert!(plan(&session).unwrap().uploads.is_empty());
        assert!(set_enabled(&session, true).is_err());

        with_recovery(&a, &root);
        let session = seal(&a);
        assert!(plan(&session).unwrap().uploads.is_empty(), "still off");
        assert!(prepare_file(&session, &first.id).is_err(), "prepare refuses while off");
        set_enabled(&session, true).unwrap();
        let mut cloud = FakeCloud::default();
        sync(&session, &mut cloud);
        assert_eq!(cloud.objects.len(), 2);
        let first_object = cloud.object_for(&first.id);
        let first_index = cloud.latest_index();

        // Renaming changes the index: a new copy replaces the old one.
        session.update(|index| index.rename(&first.id, "renamed.txt")).unwrap();
        sync(&session, &mut cloud);
        assert!(!cloud.objects.contains_key(&first_index));
        assert_eq!(cloud.objects.values().filter(|o| o.kind == KIND_RECOVERY_INDEX).count(), 1);

        // Trash keeps the cloud copy; permanent delete removes it.
        session.update(|index| index.trash(&first.id)).unwrap();
        sync(&session, &mut cloud);
        assert!(cloud.objects.contains_key(&first_object));
        crate::commands::vault_store::tests_purge_trash(&session);
        assert_eq!(plan(&session).unwrap().deletes, vec![first_object.clone()]);
        sync(&session, &mut cloud);
        assert!(!cloud.objects.contains_key(&first_object));
        assert_eq!(state_of(&session).unwrap().pending_deletes, 0);

        // Turning backup off uploads nothing new but keeps what is there.
        set_enabled(&session, false).unwrap();
        let later = import(&a, "b.txt", b"two", &[]);
        sync(&session, &mut cloud);
        assert!(cloud.objects.values().all(|o| o.entry_id.as_deref() != Some(later.id.as_str())));

        // Deleting the backup queues everything still in the cloud.
        let state = delete_backup(&session, &[]).unwrap();
        assert!(!state.enabled);
        sync(&session, &mut cloud);
        assert!(cloud.objects.is_empty());
    }

    #[test]
    fn files_added_before_recovery_are_reprotected_before_they_leave_the_device() {
        let root = vault_recovery::generate_recovery_root();
        let a = TestDevice::new(false);
        unlock(&a);
        let early = import(&a, "early.txt", b"added before recovery existed", &[]);
        assert!(!early.recovery_protected);
        with_recovery(&a, &root);
        let session = seal(&a);
        set_enabled(&session, true).unwrap();
        let mut cloud = FakeCloud::default();
        sync(&session, &mut cloud);

        let entry = session.require_file(&early.id).unwrap();
        assert!(entry.recovery_protected);
        // The uploaded bytes open with the recovery key alone.
        let uploaded = cloud.objects[&cloud.object_for(&early.id)].parts.concat();
        let wrap_key = vault_recovery::derive_wrap_key(&root).unwrap();
        let mut plain = Vec::new();
        vault_stream::decrypt_stream_with_recovery(&mut std::io::Cursor::new(uploaded), &mut plain, &wrap_key).unwrap();
        assert_eq!(plain, b"added before recovery existed");
        // And the local copy still opens normally.
        assert_eq!(open_owned(&session, &early.id), b"added before recovery existed");
    }

    #[test]
    fn a_missing_local_file_comes_back_from_its_own_backup() {
        let root = vault_recovery::generate_recovery_root();
        let a = TestDevice::new(false);
        unlock(&a);
        with_recovery(&a, &root);
        let entry = import(&a, "photo.png", b"\x89PNG\r\n\x1a\n-pixels-", &[]);
        let session = seal(&a);
        set_enabled(&session, true).unwrap();
        let mut cloud = FakeCloud::default();
        sync(&session, &mut cloud);

        std::fs::remove_file(session.layout.object_path(&entry.id).unwrap()).unwrap();
        assert_eq!(state_of(&session).unwrap().restorable_missing, 1);
        let object_id = cloud.object_for(&entry.id);
        let download = pull(&session, &cloud, &object_id);
        // No recovery key needed: it is this vault's own container.
        restore_file(&session, &download, &entry.id, &object_id).unwrap();
        assert_eq!(open_owned(&session, &entry.id), b"\x89PNG\r\n\x1a\n-pixels-");
        assert_eq!(state_of(&session).unwrap().restorable_missing, 0);
    }

    #[test]
    fn a_file_changed_after_it_was_prepared_is_not_uploaded() {
        let root = vault_recovery::generate_recovery_root();
        let a = TestDevice::new(false);
        unlock(&a);
        with_recovery(&a, &root);
        let entry = import(&a, "a.txt", b"original", &[]);
        let session = seal(&a);
        set_enabled(&session, true).unwrap();
        let prepared = prepare_file(&session, &entry.id).unwrap();
        let path = session.layout.object_path(&entry.id).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(read_part(&session.ctx.user_id, &prepared.upload_id, 0).is_err());
        discard_upload(&session.ctx.user_id, &prepared.upload_id).unwrap();
        assert!(read_part(&session.ctx.user_id, &prepared.upload_id, 0).is_err());
    }

    #[test]
    fn a_file_is_shared_with_backup_off_and_its_copy_goes_when_sharing_ends() {
        let root = vault_recovery::generate_recovery_root();
        let a = TestDevice::new(false);
        unlock(&a);
        with_recovery(&a, &root);
        let photo = import(&a, "holiday.png", b"\x89PNG\r\n\x1a\n-holiday-", &[]);
        let note = import(&a, "note.txt", b"stays on this device", &[]);
        let session = seal(&a);
        let mut cloud = FakeCloud::default();

        // Backup is off: nothing is backed up or planned...
        assert!(prepare_file(&session, &photo.id).is_err());
        assert!(plan(&session).unwrap().uploads.is_empty());

        // ...yet one file can be shared, and only that file leaves the device.
        let object_id = push(&session, &mut cloud, prepare_share_copy(&session, &photo.id).unwrap());
        assert_eq!(cloud.objects.len(), 1);
        assert_eq!(cloud.objects[&object_id].entry_id.as_deref(), Some(photo.id.as_str()));
        let entry = session.require_file(&photo.id).unwrap();
        assert_eq!(entry.cloud_object_id.as_deref(), Some(object_id.as_str()));
        assert!(entry.cloud_shared_only);
        assert!(entry.recovery_protected, "sealed exactly as a backup of it would be");
        let state = state_of(&session).unwrap();
        assert_eq!((state.backed_up_files, state.shared_copies, state.pending_uploads), (0, 1, 0));
        assert!(session.require_file(&note.id).unwrap().cloud_object_id.is_none());
        // One copy per file: sharing it again reuses this one.
        assert!(prepare_share_copy(&session, &photo.id).is_err());
        // Not part of the library the account's other devices restore from.
        assert!(crate::vault::library::build_doc(&load(&session).unwrap()).entries.is_empty());

        // Only the copy it holds is released, and only while it is still here.
        assert!(!release_share_copy(&session, &photo.id, &note.id).unwrap());
        assert!(!release_share_copy(&session, &note.id, &object_id).unwrap());
        assert!(release_share_copy(&session, &photo.id, &object_id).unwrap());
        assert_eq!(plan_deletes(&session), vec![object_id.clone()]);
        sync(&session, &mut cloud);
        assert!(cloud.objects.is_empty());
        let entry = session.require_file(&photo.id).unwrap();
        assert!(entry.cloud_object_id.is_none() && !entry.cloud_shared_only);
        assert_eq!(state_of(&session).unwrap().shared_copies, 0);
        // The file itself is untouched.
        assert_eq!(open_owned(&session, &photo.id), b"\x89PNG\r\n\x1a\n-holiday-");
    }

    #[test]
    fn a_shared_copy_becomes_the_backup_and_deleting_the_backup_keeps_shared_files() {
        let root = vault_recovery::generate_recovery_root();
        let a = TestDevice::new(false);
        unlock(&a);
        with_recovery(&a, &root);
        let photo = import(&a, "holiday.png", b"\x89PNG\r\n\x1a\n-holiday-", &[]);
        let note = import(&a, "note.txt", b"backed up, not shared", &[]);
        let session = seal(&a);
        let mut cloud = FakeCloud::default();
        let object_id = push(&session, &mut cloud, prepare_share_copy(&session, &photo.id).unwrap());

        // Turning backup on: the shared copy IS the file's backup (no second
        // upload) and is never taken back when sharing ends.
        set_enabled(&session, true).unwrap();
        assert!(!session.require_file(&photo.id).unwrap().cloud_shared_only);
        sync(&session, &mut cloud);
        assert_eq!(cloud.object_for(&photo.id), object_id);
        assert_eq!(cloud.objects.values().filter(|o| o.kind == KIND_FILE).count(), 2);
        let state = state_of(&session).unwrap();
        assert_eq!((state.backed_up_files, state.shared_copies), (2, 0));
        assert!(!release_share_copy(&session, &photo.id, &object_id).unwrap());

        // With backup on, a file shared before it was backed up is a backup.
        let later = import(&a, "later.txt", b"shared while backup is on", &[]);
        push(&session, &mut cloud, prepare_share_copy(&session, &later.id).unwrap());
        assert!(!session.require_file(&later.id).unwrap().cloud_shared_only);

        // Deleting the backup keeps the copy a live share uses, as a shared copy.
        let note_object = cloud.object_for(&note.id);
        let state = delete_backup(&session, &[object_id.clone()]).unwrap();
        assert!(!state.enabled);
        assert_eq!((state.backed_up_files, state.shared_copies), (0, 1));
        sync(&session, &mut cloud);
        assert!(cloud.objects.contains_key(&object_id));
        assert!(!cloud.objects.contains_key(&note_object));
        assert_eq!(cloud.objects.len(), 1);
        let entry = session.require_file(&photo.id).unwrap();
        assert!(entry.cloud_shared_only && entry.cloud_object_id.as_deref() == Some(object_id.as_str()));
        // ...and it goes like any shared copy once that share ends.
        assert!(release_share_copy(&session, &photo.id, &object_id).unwrap());
        sync(&session, &mut cloud);
        assert!(cloud.objects.is_empty());
    }
}