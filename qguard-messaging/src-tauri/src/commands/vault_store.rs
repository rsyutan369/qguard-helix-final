use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tauri::ipc::{Channel, Response};
use tauri::State;

use crate::commands::vault::{
    local_vault_context, open_vault_source, run_stream_blocking, sanitize_dest_name, unique_in_dir,
    LocalVaultContext, VaultDest, VaultNeed,
};
use crate::error::{QGuardError, Result};
use crate::security::content_uri;
use crate::state::AppState;
use crate::vault::sniff;
use crate::vault::store::{
    self, BoundedBuffer, HashingReader, HashingWriter, StoreActivity, StoreEntry, StoreIndex, StoreKeys,
    StoreLayout, INTEGRITY_FAILED, INTEGRITY_MISSING, INTEGRITY_UNVERIFIED, INTEGRITY_VERIFIED,
};
use crate::vault_stream::{self, VaultProgress};

// ---------------------------------------------------------------------------
// Quantum Vault Storage — the managed, on-device encrypted library (see
// `vault::store` for the format). Every command needs the vault UNLOCKED: the
// index and every object open only under the PIN-bound vault key, which exists
// only in an unlocked session. Nothing here touches the network.
//
// Writes that change what the vault holds use a `Seal` context, so the
// recovery configuration is loaded and every new container gets its recovery
// wraps, and the recovery copy of the index is kept current. Reads, previews,
// exports and verification use an `Open` context.
// ---------------------------------------------------------------------------

/// Serialises every read-modify-write of an index. Long crypto work (sealing a
/// file, decrypting for export) runs OUTSIDE it; only the index update is held.
pub(crate) static STORE_LOCK: Mutex<()> = Mutex::new(());

/// The name written into a stored container's plaintext header. Stored
/// containers never carry the real name: it lives only in the sealed index.
const OPAQUE_HEADER_NAME: &str = "vault-object";
const OPAQUE_CONTENT_TYPE: &str = "application/octet-stream";

/// Stable prefix of the error for a file whose only copy is in the cloud.
pub const CLOUD_ONLY_MARKER: &str = "VAULT_CLOUD_ONLY";

pub(crate) struct StoreSession {
    pub(crate) ctx: LocalVaultContext,
    pub(crate) need: VaultNeed,
    pub(crate) layout: StoreLayout,
    pub(crate) keys: StoreKeys,
}

pub(crate) fn open_session(state: &AppState, need: VaultNeed) -> Result<StoreSession> {
    let ctx = local_vault_context(state, need)?;
    let layout = StoreLayout::new(&state.data_dir, &AppState::safe_user_key(&ctx.user_id));
    layout.ensure()?;
    let keys = StoreKeys::derive(ctx.vault_key())?;
    Ok(StoreSession { ctx, need, layout, keys })
}

pub(crate) fn lock_store() -> Result<std::sync::MutexGuard<'static, ()>> {
    STORE_LOCK
        .lock()
        .map_err(|_| QGuardError::Storage("vault storage lock poisoned".to_string()))
}

impl StoreSession {
    pub(crate) fn load(&self) -> Result<StoreIndex> {
        store::load_index(&self.layout, &self.keys, &self.ctx.user_id)
    }

    /// Seal the index, and keep the recovery copy in step with it.
    ///
    /// Only a `Seal` context knows the recovery configuration. With personal
    /// recovery configured the copy is (re)written; without it a stale copy
    /// sealed under a recovery key that is no longer the account's is removed.
    /// An `Open` context leaves the copy as it is.
    pub(crate) fn persist(&self, index: &StoreIndex) -> Result<()> {
        store::save_index(&self.layout, &self.keys, &self.ctx.user_id, index)?;
        if self.need == VaultNeed::Seal {
            match self.ctx.personal_recovery_wrap_key() {
                Some(wrap_key) => {
                    let recovery_keys = StoreKeys::for_recovery(wrap_key)?;
                    // Non-fatal: the primary index is already committed.
                    let _ = store::save_index_at(
                        &self.layout.recovery_index_path(),
                        &recovery_keys,
                        &self.ctx.user_id,
                        index,
                    );
                }
                None => {
                    let _ = std::fs::remove_file(self.layout.recovery_index_path());
                }
            }
        }
        Ok(())
    }

    /// Load, change, save — under the store lock. Nothing is saved when `change`
    /// fails.
    pub(crate) fn update<T>(&self, change: impl FnOnce(&mut StoreIndex) -> Result<T>) -> Result<T> {
        let _guard = lock_store()?;
        let mut index = self.load()?;
        let out = change(&mut index)?;
        self.persist(&index)?;
        Ok(out)
    }

    /// Record a failed operation without letting a second failure mask the first.
    pub(crate) fn record_failure(&self, action: &str, entry_id: Option<&str>, name: &str, detail: &str) {
        let _ = self.update(|index| {
            index.log(action, entry_id, name, detail, false);
            Ok(())
        });
    }

    pub(crate) fn require_file(&self, id: &str) -> Result<StoreEntry> {
        let id = store::checked_id(id)?;
        let _guard = lock_store()?;
        let index = self.load()?;
        let entry = index.require(&id)?.clone();
        if !entry.is_file() {
            return Err(QGuardError::InvalidInput("this action needs a file, not a folder".to_string()));
        }
        Ok(entry)
    }

    /// Decrypt a stored file into `writer`, authenticating it as this vault's
    /// own (header signature + vault-key unwrap), every chunk's AES-256-GCM tag,
    /// and finally the plaintext SHA3-256 recorded when it was sealed.
    pub(crate) fn decrypt_into<W: Write>(
        &self,
        entry: &StoreEntry,
        writer: W,
        progress: &mut dyn FnMut(VaultProgress),
    ) -> Result<W> {
        let path = self.layout.object_path(&entry.id)?;
        let file = File::open(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound && entry.cloud_object_id.is_some() {
                QGuardError::NotFound(format!("{CLOUD_ONLY_MARKER}: this file is in your cloud backup only — download it to this device first"))
            } else if error.kind() == std::io::ErrorKind::NotFound {
                QGuardError::NotFound(format!("{INTEGRITY_MISSING}: the encrypted object for this file is missing from the vault"))
            } else {
                QGuardError::Storage(format!("open vault object: {error}"))
            }
        })?;
        let mut reader = BufReader::new(file);
        let mut hashing = HashingWriter::new(writer);
        vault_stream::decrypt_stream_owner_with_progress(&mut reader, &mut hashing, &self.ctx.owner_access(false), progress)?;
        let (writer, hash, len) = hashing.finish();
        if len != entry.size_bytes || (!entry.plaintext_sha3.is_empty() && hash != entry.plaintext_sha3) {
            return Err(QGuardError::Crypto(
                "decrypted content does not match the SHA3-256 recorded when it was sealed".to_string(),
            ));
        }
        Ok(writer)
    }

    /// Record the outcome of an operation that authenticated (or failed to
    /// authenticate) a file's content.
    fn record_integrity(&self, entry: &StoreEntry, outcome: &Result<()>, action: &str, detail_ok: &str) -> Result<StoreEntry> {
        self.update(|index| {
            // A file kept in the cloud only is not missing; it is just not here.
            let missing = matches!(outcome, Err(QGuardError::NotFound(_))) && entry.cloud_object_id.is_none();
            let failed = matches!(outcome, Err(QGuardError::Crypto(_)));
            let target = index.get_mut(&entry.id).ok_or_else(|| QGuardError::NotFound("vault item not found".to_string()))?;
            if outcome.is_ok() {
                target.integrity = INTEGRITY_VERIFIED.to_string();
                target.last_verified_at = Some(Utc::now());
            } else if missing {
                target.integrity = INTEGRITY_MISSING.to_string();
            } else if failed {
                target.integrity = INTEGRITY_FAILED.to_string();
            }
            let updated = target.clone();
            let detail = match outcome {
                Ok(()) => detail_ok.to_string(),
                Err(error) => error.to_string(),
            };
            index.log(action, Some(&entry.id), &entry.name, &detail, outcome.is_ok());
            Ok(updated)
        })
    }
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryUsage {
    pub files: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryBreakdown {
    pub image: CategoryUsage,
    pub video: CategoryUsage,
    pub audio: CategoryUsage,
    pub document: CategoryUsage,
    pub archive: CategoryUsage,
    pub other: CategoryUsage,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreLimits {
    pub max_preview_bytes: u64,
    pub max_import_bytes: u64,
    pub max_thumbnail_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreStatus {
    /// `ready` — the index opened under this vault's key. `foreign` — it was
    /// sealed by a previous vault key (a vault reset); nothing was changed.
    pub state: String,
    /// Where the encrypted library lives on this device.
    pub storage_location: String,
    pub vault_id: String,
    pub files: u64,
    pub folders: u64,
    pub trashed: u64,
    pub favorites: u64,
    pub plaintext_bytes: u64,
    /// Measured from the containers on disk, not from the index.
    pub stored_bytes: u64,
    pub categories: CategoryBreakdown,
    pub verified: u64,
    pub unverified: u64,
    pub failed: u64,
    pub missing: u64,
    pub type_mismatches: u64,
    /// Containers whose owner envelope is not PIN-bound (never written by this
    /// build; counted so a regression cannot hide).
    pub legacy_containers: u64,
    pub recovery_protected: u64,
    /// Containers on disk the index does not know (an import interrupted
    /// between writing the object and committing the index).
    pub orphaned_objects: u64,
    /// Backed-up files kept in the cloud only (synchronized from another
    /// device, not downloaded here).
    pub cloud_only: u64,
    /// The recovery copy of the index exists on this device.
    pub recovery_index: bool,
    pub last_import_at: Option<DateTime<Utc>>,
    pub last_full_verify_at: Option<DateTime<Utc>>,
    pub recent_activity: Vec<StoreActivity>,
    pub limits: StoreLimits,
}

fn limits() -> StoreLimits {
    StoreLimits {
        max_preview_bytes: store::MAX_PREVIEW_BYTES,
        max_import_bytes: store::MAX_IMPORT_BYTES,
        max_thumbnail_bytes: store::MAX_THUMBNAIL_BYTES as u64,
    }
}

/// What an open failure says about the file itself: missing, failed
/// authentication, or (anything else — I/O, a full disk, a cancelled save)
/// nothing at all, which leaves the recorded integrity unchanged.
fn integrity_outcome(error: &QGuardError) -> Result<()> {
    match error {
        QGuardError::NotFound(message) => Err(QGuardError::NotFound(message.clone())),
        QGuardError::Crypto(message) => Err(QGuardError::Crypto(message.clone())),
        other => Err(QGuardError::Storage(other.to_string())),
    }
}

fn foreign_index(error: &QGuardError) -> bool {
    error.to_string().contains(store::FOREIGN_INDEX_MARKER)
}

/// Entries as the UI should see them: a file whose container is gone is
/// reported as missing whatever the index last recorded.
fn live_view(layout: &StoreLayout, index: &StoreIndex) -> Vec<StoreEntry> {
    let on_disk = layout.object_ids();
    index
        .entries
        .iter()
        .map(|entry| {
            let mut entry = entry.clone();
            entry.available_offline = entry.is_file() && on_disk.contains(&entry.id);
            if entry.is_file() && !entry.available_offline && entry.cloud_object_id.is_none() {
                entry.integrity = INTEGRITY_MISSING.to_string();
            }
            entry
        })
        .collect()
}

fn build_status(session: &StoreSession, index: &StoreIndex) -> StoreStatus {
    let on_disk = session.layout.object_ids();
    let known: HashSet<&str> = index.entries.iter().map(|e| e.id.as_str()).collect();
    let mut status = StoreStatus {
        state: "ready".to_string(),
        storage_location: session.layout.root().to_string_lossy().to_string(),
        vault_id: session.keys.vault_id_hex()[..16].to_string(),
        files: 0,
        folders: 0,
        trashed: 0,
        favorites: 0,
        plaintext_bytes: 0,
        stored_bytes: 0,
        categories: CategoryBreakdown::default(),
        verified: 0,
        unverified: 0,
        failed: 0,
        missing: 0,
        type_mismatches: 0,
        legacy_containers: 0,
        recovery_protected: 0,
        orphaned_objects: on_disk.iter().filter(|id| !known.contains(id.as_str())).count() as u64,
        cloud_only: 0,
        recovery_index: session.layout.recovery_index_path().is_file(),
        last_import_at: index.activity.iter().find(|a| a.action == "import" && a.outcome == "success").map(|a| a.at),
        last_full_verify_at: index.last_full_verify_at,
        recent_activity: index.activity.iter().take(30).cloned().collect(),
        limits: limits(),
    };
    for entry in &index.entries {
        if index.in_trash(&entry.id) {
            status.trashed += 1;
            continue;
        }
        if entry.is_folder() {
            status.folders += 1;
            continue;
        }
        status.files += 1;
        status.plaintext_bytes += entry.size_bytes;
        if let Ok(path) = session.layout.object_path(&entry.id) {
            status.stored_bytes += store::file_len(&path);
        }
        if entry.favorite {
            status.favorites += 1;
        }
        let bucket = match sniff::Category::parse(&entry.category) {
            sniff::Category::Image => &mut status.categories.image,
            sniff::Category::Video => &mut status.categories.video,
            sniff::Category::Audio => &mut status.categories.audio,
            sniff::Category::Document => &mut status.categories.document,
            sniff::Category::Archive => &mut status.categories.archive,
            sniff::Category::Other => &mut status.categories.other,
        };
        bucket.files += 1;
        bucket.bytes += entry.size_bytes;
        if !on_disk.contains(&entry.id) {
            if entry.cloud_object_id.is_some() {
                status.cloud_only += 1;
            } else {
                status.missing += 1;
            }
        } else {
            match entry.integrity.as_str() {
                INTEGRITY_VERIFIED => status.verified += 1,
                INTEGRITY_FAILED => status.failed += 1,
                INTEGRITY_MISSING => status.missing += 1,
                _ => status.unverified += 1,
            }
        }
        if entry.type_check == sniff::TypeCheck::Mismatch.as_str() {
            status.type_mismatches += 1;
        }
        if !entry.pin_bound {
            status.legacy_containers += 1;
        }
        if entry.recovery_protected {
            status.recovery_protected += 1;
        }
    }
    status
}

#[tauri::command]
pub async fn vault_store_status(state: State<'_, AppState>) -> Result<StoreStatus> {
    let session = open_session(&state, VaultNeed::Open)?;
    run_stream_blocking(move || {
        let loaded = {
            let _guard = lock_store()?;
            session.load()
        };
        match loaded {
            Ok(index) => Ok(build_status(&session, &index)),
            Err(error) if foreign_index(&error) => {
                let mut status = build_status(&session, &StoreIndex::new());
                status.state = "foreign".to_string();
                Ok(status)
            }
            Err(error) => Err(error),
        }
    })
    .await
}

#[tauri::command]
pub async fn vault_store_list(state: State<'_, AppState>) -> Result<Vec<StoreEntry>> {
    let session = open_session(&state, VaultNeed::Open)?;
    run_stream_blocking(move || {
        let index = {
            let _guard = lock_store()?;
            session.load()?
        };
        Ok(live_view(&session.layout, &index))
    })
    .await
}

#[tauri::command]
pub async fn vault_store_activity(state: State<'_, AppState>) -> Result<Vec<StoreActivity>> {
    let session = open_session(&state, VaultNeed::Open)?;
    run_stream_blocking(move || {
        let _guard = lock_store()?;
        Ok(session.load()?.activity)
    })
    .await
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportOutcome {
    /// The stored file, or the existing copy when the import was skipped.
    pub entry: StoreEntry,
    /// True when an identical file already existed in that folder and the new
    /// copy was discarded.
    pub skipped_duplicate: bool,
}

/// Open an import source (path, or Android SAF document) with its display name
/// and size. SAF providers can hand out pipe-like fds with a zero stat size; the
/// provider's SIZE column is authoritative then.
pub(crate) fn open_import_source(source_path: &str) -> Result<(File, String, u64)> {
    let file = open_vault_source(source_path, "read source file")?;
    let metadata = file
        .metadata()
        .map_err(|e| QGuardError::Storage(format!("read source file: {e}")))?;
    if content_uri::is_content_uri(source_path) {
        let (display_name, provider_size) = content_uri::stat(source_path).unwrap_or((None, None));
        let size = match (metadata.len(), provider_size) {
            (0, Some(size)) => size,
            (size, _) => size,
        };
        let name = display_name.unwrap_or_else(|| content_uri::uri_tail(source_path));
        Ok((file, name, size))
    } else {
        if !metadata.is_file() {
            return Err(QGuardError::InvalidInput("the selected item is not a file".to_string()));
        }
        let name = Path::new(source_path)
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        Ok((file, name, metadata.len()))
    }
}

fn read_head<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut head = vec![0u8; sniff::SNIFF_LEN];
    let mut filled = 0;
    while filled < head.len() {
        match reader.read(&mut head[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(QGuardError::Storage(format!("read source file: {error}"))),
        }
    }
    head.truncate(filled);
    Ok(head)
}

/// Seal one source into the vault.
///
/// Order of commitment: the container is written to `staging/` and fully
/// flushed; then, under the store lock, the index entry is checked and the
/// container renamed into `objects/`; then the index is saved. A crash at any
/// point leaves either nothing, a staging file (cleared on the next import) or
/// an orphaned object (reported by the status) — never an index entry without
/// its container.
pub(crate) fn import_one(
    session: &StoreSession,
    source_path: &str,
    base_parent: Option<&str>,
    folder_parts: &[String],
    skip_duplicates: bool,
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<ImportOutcome> {
    let (file, source_name, size) = open_import_source(source_path)?;
    import_reader(session, (BufReader::new(file), source_name, size), base_parent, folder_parts, skip_duplicates, None, progress)
}

struct TransferImport<'a> {
    state: &'a AppState,
    owner: &'a str,
    digest: &'a str,
}

/// Import an already-verified XFER stream without ever writing a plaintext
/// intermediate. Duplicate content at the Vault root makes a retry safe
/// after a crash between the Vault commit and XFER's destination receipt.
pub(crate) fn import_transfer_stream(
    state: &AppState,
    owner: &str,
    reader: impl Read,
    source_name: String,
    size: u64,
    digest: &str,
) -> Result<ImportOutcome> {
    let session = open_session(state, VaultNeed::Seal)?;
    if session.ctx.user_id != owner {
        return Err(QGuardError::Trust("The active account changed before Vault import.".into()));
    }
    import_reader(
        &session, (reader, source_name, size), None, &[], true,
        Some(TransferImport { state, owner, digest }), &mut |_| {},
    )
}

fn import_reader(
    session: &StoreSession,
    (mut reader, source_name, size): (impl Read, String, u64),
    base_parent: Option<&str>,
    folder_parts: &[String],
    skip_duplicates: bool,
    transfer: Option<TransferImport<'_>>,
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<ImportOutcome> {
    if size > store::MAX_IMPORT_BYTES {
        return Err(QGuardError::InvalidInput(format!(
            "{source_name} is larger than the {} GB per-file limit",
            store::MAX_IMPORT_BYTES / (1024 * 1024 * 1024)
        )));
    }
    let name = store::clean_name(&source_name)?;
    let head = read_head(&mut reader)?;
    let detected = sniff::sniff(&head, &name);
    let mut hashing = HashingReader::new(Cursor::new(head).chain(reader));

    let staging = session.layout.new_staging_path();
    let sealed = (|| -> Result<vault_stream::StreamSummary> {
        let out = File::create(&staging).map_err(|e| QGuardError::Storage(format!("create vault object: {e}")))?;
        let mut writer = BufWriter::new(out);
        let summary = vault_stream::encrypt_stream_with_progress(
            &mut hashing,
            &mut writer,
            vault_stream::KIND_FILE,
            OPAQUE_HEADER_NAME,
            OPAQUE_CONTENT_TYPE,
            size,
            &session.ctx.owner_seal(),
            None,
            progress,
        )?;
        writer
            .flush()
            .and_then(|_| writer.get_ref().sync_all())
            .map_err(|e| QGuardError::Storage(format!("flush vault object: {e}")))?;
        Ok(summary)
    })();
    let summary = match sealed {
        Ok(summary) => summary,
        Err(error) => {
            let _ = std::fs::remove_file(&staging);
            return Err(error);
        }
    };
    let (plaintext_sha3, bytes_read) = hashing.finish();
    let stored_bytes = store::file_len(&staging);

    let committed = (|| -> Result<ImportOutcome> {
        let _guard = lock_store()?;
        if let Some(transfer) = transfer {
            if bytes_read != size || plaintext_sha3 != transfer.digest {
                return Err(QGuardError::Crypto("The verified transfer bytes changed before Vault import.".into()));
            }
            if transfer.state.offline_principal.owner(transfer.state)? != transfer.owner {
                return Err(QGuardError::Trust("The verified local account changed during Vault import.".into()));
            }
            let active = local_vault_context(transfer.state, VaultNeed::Open)?;
            if active.user_id != transfer.owner || active.vault_key() != session.ctx.vault_key() {
                return Err(QGuardError::Trust("Unlock the original Quantum Vault and retry the import.".into()));
            }
        }
        let mut index = session.load()?;
        let parent = index.ensure_folder_path(base_parent, folder_parts)?;
        if skip_duplicates {
            if let Some(existing) = index.duplicate_in(parent.as_deref(), &plaintext_sha3) {
                let existing = existing.clone();
                let _ = std::fs::remove_file(&staging);
                if !folder_parts.is_empty() {
                    session.persist(&index)?; // folders created on the way are kept
                }
                return Ok(ImportOutcome { entry: existing, skipped_duplicate: true });
            }
        }
        let now = Utc::now();
        let entry = index.insert_file(StoreEntry {
            id: summary.file_id.clone(),
            kind: store::KIND_FILE.to_string(),
            name,
            parent_id: parent,
            created_at: now,
            updated_at: now,
            trashed_at: None,
            favorite: false,
            size_bytes: summary.original_size,
            stored_bytes,
            content_type: detected.content_type.clone(),
            category: detected.category.as_str().to_string(),
            type_check: detected.type_check.as_str().to_string(),
            plaintext_sha3,
            container_version: summary.container_version,
            pin_bound: summary.pin_bound,
            total_chunks: summary.total_chunks,
            recovery_protected: session.ctx.seals_recovery_wraps(),
            // Written, not yet read back: verified only once something has
            // authenticated it.
            integrity: INTEGRITY_UNVERIFIED.to_string(),
            last_verified_at: None,
            has_thumbnail: false,
            cloud_object_id: None,
            cloud_backed_up_at: None,
            library_fek: None,
            available_offline: false,
            cloud_shared_only: false,
        })?;
        let object = session.layout.object_path(&entry.id)?;
        std::fs::rename(&staging, &object).map_err(|e| QGuardError::Storage(format!("store vault object: {e}")))?;
        index.log(
            "import",
            Some(&entry.id),
            &entry.name,
            &format!(
                "Sealed on-device · {} · AES-256-GCM, {} chunk(s) · per-file key under the PIN-bound vault key · Ed25519 + ML-DSA-87 header",
                detected.content_type, summary.total_chunks
            ),
            true,
        );
        if let Err(error) = session.persist(&index) {
            let _ = store::shred_container(&object);
            return Err(error);
        }
        Ok(ImportOutcome { entry, skipped_duplicate: false })
    })();
    if committed.is_err() {
        let _ = std::fs::remove_file(&staging);
    }
    committed
}

fn optional_id(value: Option<String>) -> Result<Option<String>> {
    match value {
        Some(id) if !id.trim().is_empty() => Ok(Some(store::checked_id(&id)?)),
        _ => Ok(None),
    }
}

/// Seal one file (path or Android SAF document) into Vault Storage.
#[tauri::command]
pub async fn vault_store_import(
    state: State<'_, AppState>,
    source_path: String,
    parent_id: Option<String>,
    skip_duplicates: Option<bool>,
    on_progress: Channel<VaultProgress>,
) -> Result<ImportOutcome> {
    let session = open_session(&state, VaultNeed::Seal)?;
    let parent = optional_id(parent_id)?;
    let skip = skip_duplicates.unwrap_or(true);
    let outcome = run_stream_blocking(move || {
        session.layout.clear_staging();
        let result = import_one(&session, &source_path, parent.as_deref(), &[], skip, &mut |p| {
            let _ = on_progress.send(p);
        });
        if let Err(error) = &result {
            let name = crate::commands::vault::vault_source_name(&source_path);
            session.record_failure("import", None, &name, &error.to_string());
        }
        result
    })
    .await?;
    if !outcome.skipped_duplicate {
        state.audit_info("vault_store_import", "File sealed into Quantum Vault Storage (v5 container, PIN-bound)");
        state.touch_telemetry(
            "vault",
            "File sealed into Vault Storage · AES-256-GCM · PIN-bound vault key · ML-DSA-87 header · name kept only in the sealed index",
            100,
        );
    }
    Ok(outcome)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportFailure {
    pub name: String,
    pub error: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderImportOutcome {
    pub root_folder_id: Option<String>,
    pub imported: u64,
    pub skipped_duplicates: u64,
    pub failed: Vec<ImportFailure>,
}

pub(crate) fn file_event(index: usize, count: usize, name: &str) -> VaultProgress {
    VaultProgress {
        op: "encrypt".to_string(),
        phase: "file".to_string(),
        message: format!("File {} of {} · {}", index + 1, count, name),
        processed_bytes: 0,
        total_bytes: 0,
        chunk_index: index as u64,
        total_chunks: count as u64,
        level: "info".to_string(),
    }
}

/// Seal a whole directory tree (desktop), recreating its folders in the vault.
/// One file failing does not stop the rest; every failure is reported.
#[tauri::command]
pub async fn vault_store_import_folder(
    state: State<'_, AppState>,
    source_dir: String,
    parent_id: Option<String>,
    skip_duplicates: Option<bool>,
    on_progress: Channel<VaultProgress>,
) -> Result<FolderImportOutcome> {
    if content_uri::is_content_uri(&source_dir) {
        return Err(QGuardError::InvalidInput(
            "folder import needs a folder on this device's file system".to_string(),
        ));
    }
    let session = open_session(&state, VaultNeed::Seal)?;
    let parent = optional_id(parent_id)?;
    let skip = skip_duplicates.unwrap_or(true);
    let outcome = run_stream_blocking(move || {
        let root = PathBuf::from(&source_dir);
        if !root.is_dir() {
            return Err(QGuardError::InvalidInput("the selected item is not a folder".to_string()));
        }
        session.layout.clear_staging();
        let root_name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Imported folder".to_string());
        let (files, _) = vault_stream::collect_folder_entries(&root)?;
        let root_parts = vec![root_name.clone()];
        let root_folder_id = session.update(|index| index.ensure_folder_path(parent.as_deref(), &root_parts))?;
        let mut outcome = FolderImportOutcome { root_folder_id, imported: 0, skipped_duplicates: 0, failed: Vec::new() };
        let count = files.len();
        for (position, file) in files.iter().enumerate() {
            let _ = on_progress.send(file_event(position, count, &file.rel_path));
            let mut parts = root_parts.clone();
            let rel: Vec<&str> = file.rel_path.split('/').collect();
            parts.extend(rel[..rel.len().saturating_sub(1)].iter().map(|s| s.to_string()));
            let source = file.abs_path.to_string_lossy().to_string();
            match import_one(&session, &source, parent.as_deref(), &parts, skip, &mut |p| {
                let _ = on_progress.send(p);
            }) {
                Ok(result) if result.skipped_duplicate => outcome.skipped_duplicates += 1,
                Ok(_) => outcome.imported += 1,
                Err(error) => {
                    session.record_failure("import", None, &file.rel_path, &error.to_string());
                    outcome.failed.push(ImportFailure { name: file.rel_path.clone(), error: error.to_string() });
                }
            }
        }
        Ok(outcome)
    })
    .await?;
    state.audit_info(
        "vault_store_import_folder",
        &format!("Folder sealed into Quantum Vault Storage: {} file(s), {} failed", outcome.imported, outcome.failed.len()),
    );
    state.touch_telemetry("vault", "Folder sealed into Vault Storage · one v5 container per file", 100);
    Ok(outcome)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreDiskUsage {
    pub objects: u64,
    pub bytes: u64,
}

/// How many encrypted objects this account's vault storage holds on this
/// device and their size on disk. Needs sign-in but NOT the vault unlocked:
/// it reads only what the file system already shows to anyone with access to
/// the directory (object count and ciphertext sizes) — no names, no types.
/// Dashboards use it; everything else needs the unlocked status.
#[tauri::command]
pub async fn vault_store_disk_usage(state: State<'_, AppState>) -> Result<StoreDiskUsage> {
    let user_id = state.user_id()?;
    let layout = StoreLayout::new(&state.data_dir, &AppState::safe_user_key(&user_id));
    run_stream_blocking(move || {
        let mut usage = StoreDiskUsage { objects: 0, bytes: 0 };
        for id in layout.object_ids() {
            if let Ok(path) = layout.object_path(&id) {
                usage.objects += 1;
                usage.bytes += store::file_len(&path);
            }
        }
        Ok(usage)
    })
    .await
}

/// `file`, `folder` or `other` for a dropped desktop path, so a drop can route
/// to the file or folder import. Android sources are documents, always `file`.
#[tauri::command]
pub async fn vault_store_path_kind(state: State<'_, AppState>, path: String) -> Result<String> {
    state.require_auth()?;
    if content_uri::is_content_uri(&path) {
        return Ok("file".to_string());
    }
    run_stream_blocking(move || {
        Ok(match std::fs::metadata(&path) {
            Ok(meta) if meta.is_dir() => "folder",
            Ok(meta) if meta.is_file() => "file",
            _ => "other",
        }
        .to_string())
    })
    .await
}

// ---------------------------------------------------------------------------
// Organise
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn vault_store_create_folder(
    state: State<'_, AppState>,
    parent_id: Option<String>,
    name: String,
) -> Result<StoreEntry> {
    let session = open_session(&state, VaultNeed::Seal)?;
    let parent = optional_id(parent_id)?;
    let entry = run_stream_blocking(move || {
        session.update(|index| {
            let entry = index.create_folder(parent.as_deref(), &name)?;
            index.log("create_folder", Some(&entry.id), &entry.name, "Folder created", true);
            Ok(entry)
        })
    })
    .await?;
    state.audit_info("vault_store_folder", "Vault Storage folder created");
    Ok(entry)
}

#[tauri::command]
pub async fn vault_store_rename(state: State<'_, AppState>, id: String, name: String) -> Result<StoreEntry> {
    let session = open_session(&state, VaultNeed::Seal)?;
    let id = store::checked_id(&id)?;
    run_stream_blocking(move || {
        session.update(|index| {
            let before = index.require(&id)?.name.clone();
            let entry = index.rename(&id, &name)?;
            index.log("rename", Some(&id), &entry.name, &format!("Renamed from \"{before}\""), true);
            Ok(entry)
        })
    })
    .await
}

#[tauri::command]
pub async fn vault_store_move(
    state: State<'_, AppState>,
    ids: Vec<String>,
    parent_id: Option<String>,
) -> Result<Vec<StoreEntry>> {
    let session = open_session(&state, VaultNeed::Seal)?;
    let parent = optional_id(parent_id)?;
    let ids = ids.iter().map(|id| store::checked_id(id)).collect::<Result<Vec<_>>>()?;
    run_stream_blocking(move || {
        session.update(|index| {
            let destination = match parent.as_deref() {
                Some(folder) => index.require(folder)?.name.clone(),
                None => "My Files".to_string(),
            };
            let mut moved = Vec::with_capacity(ids.len());
            for id in &ids {
                let entry = index.move_entry(id, parent.as_deref())?;
                index.log("move", Some(id), &entry.name, &format!("Moved to {destination}"), true);
                moved.push(entry);
            }
            Ok(moved)
        })
    })
    .await
}

#[tauri::command]
pub async fn vault_store_set_favorite(state: State<'_, AppState>, id: String, favorite: bool) -> Result<StoreEntry> {
    let session = open_session(&state, VaultNeed::Seal)?;
    let id = store::checked_id(&id)?;
    run_stream_blocking(move || session.update(|index| index.set_favorite(&id, favorite))).await
}

#[tauri::command]
pub async fn vault_store_trash(state: State<'_, AppState>, ids: Vec<String>) -> Result<Vec<StoreEntry>> {
    let session = open_session(&state, VaultNeed::Seal)?;
    let ids = ids.iter().map(|id| store::checked_id(id)).collect::<Result<Vec<_>>>()?;
    let trashed = run_stream_blocking(move || {
        session.update(|index| {
            let mut out = Vec::with_capacity(ids.len());
            for id in &ids {
                let entry = index.trash(id)?;
                index.log("trash", Some(id), &entry.name, "Moved to Trash · still encrypted, restorable", true);
                out.push(entry);
            }
            Ok(out)
        })
    })
    .await?;
    state.audit_info("vault_store_trash", "Vault Storage item(s) moved to Trash");
    Ok(trashed)
}

#[tauri::command]
pub async fn vault_store_restore(state: State<'_, AppState>, ids: Vec<String>) -> Result<Vec<StoreEntry>> {
    let session = open_session(&state, VaultNeed::Seal)?;
    let ids = ids.iter().map(|id| store::checked_id(id)).collect::<Result<Vec<_>>>()?;
    run_stream_blocking(move || {
        session.update(|index| {
            let mut out = Vec::with_capacity(ids.len());
            for id in &ids {
                let entry = index.restore(id)?;
                let location = if entry.parent_id.is_some() { "its folder" } else { "My Files" };
                index.log("restore", Some(id), &entry.name, &format!("Restored from Trash to {location}"), true);
                out.push(entry);
            }
            Ok(out)
        })
    })
    .await
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgeOutcome {
    pub removed_entries: u64,
    pub destroyed_objects: u64,
}

/// Permanently delete items that are in the Trash (and everything inside a
/// trashed folder). Index first, then the containers are crypto-shredded: if
/// shredding is interrupted the leftovers are unreferenced ciphertext, reported
/// as orphaned objects — never index entries pointing at nothing.
fn purge(session: &StoreSession, select: impl FnOnce(&StoreIndex) -> Result<Vec<String>>) -> Result<PurgeOutcome> {
    let (removed, files) = session.update(|index| {
        let roots = select(index)?;
        let mut doomed: HashSet<String> = HashSet::new();
        for root in &roots {
            if !index.in_trash(root) {
                return Err(QGuardError::InvalidInput(
                    "only items in the Trash can be deleted permanently".to_string(),
                ));
            }
            doomed.extend(index.subtree(root));
        }
        let files: Vec<(String, bool)> = index
            .entries
            .iter()
            .filter(|e| doomed.contains(&e.id) && e.is_file())
            .map(|e| (e.id.clone(), e.has_thumbnail))
            .collect();
        for root in &roots {
            let name = index.get(root).map(|e| e.name.clone()).unwrap_or_default();
            index.log("purge", Some(root), &name, "Deleted permanently · per-file key destroyed with the container header", true);
        }
        // A file deleted here is deleted from the cloud backup too, whether or
        // not backup is still switched on.
        let cloud_copies: Vec<String> = index
            .entries
            .iter()
            .filter(|e| doomed.contains(&e.id))
            .filter_map(|e| e.cloud_object_id.clone())
            .collect();
        index.cloud.pending_deletes.extend(cloud_copies);
        // Shared entries are deleted on the account's other devices too.
        let now = Utc::now();
        let tombstones: Vec<crate::vault::library::Tombstone> = index
            .entries
            .iter()
            .filter(|e| doomed.contains(&e.id) && (e.is_folder() || e.cloud_object_id.is_some()))
            .map(|e| crate::vault::library::Tombstone { id: e.id.clone(), deleted_at: now })
            .collect();
        index.library.tombstones.extend(tombstones);
        index.remove(&doomed);
        Ok((doomed.len() as u64, files))
    })?;
    let mut destroyed = 0u64;
    for (id, has_thumbnail) in files {
        if let Ok(path) = session.layout.object_path(&id) {
            if store::shred_container(&path).is_ok() {
                destroyed += 1;
            }
        }
        if has_thumbnail {
            if let Ok(path) = session.layout.thumb_path(&id) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    Ok(PurgeOutcome { removed_entries: removed, destroyed_objects: destroyed })
}

/// Test-only: empty the Trash through the same path as the command.
#[cfg(test)]
pub(crate) fn tests_purge_trash(session: &StoreSession) {
    purge(session, |index| Ok(index.entries.iter().filter(|e| e.trashed_at.is_some()).map(|e| e.id.clone()).collect()))
        .expect("purge trash");
}

#[tauri::command]
pub async fn vault_store_purge(state: State<'_, AppState>, ids: Vec<String>) -> Result<PurgeOutcome> {
    let session = open_session(&state, VaultNeed::Seal)?;
    let ids = ids.iter().map(|id| store::checked_id(id)).collect::<Result<Vec<_>>>()?;
    let outcome = run_stream_blocking(move || {
        purge(&session, |index| {
            for id in &ids {
                index.require(id)?;
            }
            Ok(ids)
        })
    })
    .await?;
    state.audit_info("vault_store_purge", "Vault Storage item(s) permanently deleted (crypto-shredded)");
    state.touch_telemetry("vault", "Vault Storage item(s) permanently deleted · container headers overwritten", 100);
    Ok(outcome)
}

#[tauri::command]
pub async fn vault_store_empty_trash(state: State<'_, AppState>) -> Result<PurgeOutcome> {
    let session = open_session(&state, VaultNeed::Seal)?;
    let outcome = run_stream_blocking(move || {
        purge(&session, |index| {
            // Only the trashed roots; their contents follow.
            Ok(index.entries.iter().filter(|e| e.trashed_at.is_some()).map(|e| e.id.clone()).collect())
        })
    })
    .await?;
    state.audit_info("vault_store_empty_trash", "Vault Storage Trash emptied (crypto-shredded)");
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// Open: verify, preview, export
// ---------------------------------------------------------------------------

/// Authenticate one stored file end to end without writing plaintext anywhere.
#[tauri::command]
pub async fn vault_store_verify(
    state: State<'_, AppState>,
    id: String,
    on_progress: Channel<VaultProgress>,
) -> Result<StoreEntry> {
    let session = open_session(&state, VaultNeed::Open)?;
    let entry = run_stream_blocking(move || {
        let entry = session.require_file(&id)?;
        let outcome = session
            .decrypt_into(&entry, std::io::sink(), &mut |p| {
                let _ = on_progress.send(p);
            })
            .map(|_| ());
        let updated = session.record_integrity(
            &entry,
            &outcome,
            "verify",
            "Integrity verified · signed header, every AES-256-GCM chunk tag and the SHA3-256 content hash",
        )?;
        outcome.map(|_| updated)
    })
    .await?;
    state.audit_info("vault_store_verify", "Vault Storage file verified end to end");
    Ok(entry)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    pub checked: u64,
    pub verified: u64,
    pub failed: u64,
    pub missing: u64,
    pub finished_at: DateTime<Utc>,
}

/// Verify every stored file (including the Trash), one at a time.
#[tauri::command]
pub async fn vault_store_verify_all(
    state: State<'_, AppState>,
    on_progress: Channel<VaultProgress>,
) -> Result<VerifyReport> {
    let session = open_session(&state, VaultNeed::Open)?;
    let report = run_stream_blocking(move || {
        let files: Vec<StoreEntry> = {
            let _guard = lock_store()?;
            session.load()?.entries.into_iter().filter(|e| e.is_file()).collect()
        };
        let mut report = VerifyReport { checked: 0, verified: 0, failed: 0, missing: 0, finished_at: Utc::now() };
        let count = files.len();
        for (position, entry) in files.iter().enumerate() {
            let mut event = file_event(position, count, &entry.name);
            event.op = "verify".to_string();
            let _ = on_progress.send(event);
            let outcome = session
                .decrypt_into(entry, std::io::sink(), &mut |p| {
                    let _ = on_progress.send(p);
                })
                .map(|_| ());
            report.checked += 1;
            match &outcome {
                Ok(()) => report.verified += 1,
                Err(QGuardError::NotFound(_)) => report.missing += 1,
                Err(_) => report.failed += 1,
            }
            // The entry may have been deleted meanwhile; that is not a failure.
            let _ = session.record_integrity(entry, &outcome, "verify", "Integrity verified (full vault check)");
        }
        report.finished_at = Utc::now();
        session.update(|index| {
            index.last_full_verify_at = Some(report.finished_at);
            index.log(
                "verify",
                None,
                "Full vault check",
                &format!(
                    "{} checked · {} verified · {} failed · {} missing",
                    report.checked, report.verified, report.failed, report.missing
                ),
                report.failed == 0 && report.missing == 0,
            );
            Ok(())
        })?;
        Ok(report)
    })
    .await?;
    state.audit_info(
        "vault_store_verify_all",
        &format!("Vault Storage full integrity check: {} verified, {} failed, {} missing", report.verified, report.failed, report.missing),
    );
    state.touch_telemetry("vault", "Vault Storage full integrity check completed", 100);
    Ok(report)
}

/// Decrypt a small, previewable file into memory and hand the bytes to the UI.
///
/// The plaintext is authenticated in full (chunk tags + content hash) before a
/// single byte is returned, and never touches the disk. Office files, archives
/// and anything over the preview limit are export-only.
#[tauri::command]
pub async fn vault_store_preview(state: State<'_, AppState>, id: String) -> Result<Response> {
    let session = open_session(&state, VaultNeed::Open)?;
    let checked = store::checked_id(&id)?;
    state.check_decrypt_rate_limit("vault_store_preview", &checked, 120, 300)?;
    let bytes = run_stream_blocking(move || {
        let entry = session.require_file(&checked)?;
        if !sniff::previewable(&entry.content_type) {
            return Err(QGuardError::InvalidInput(
                "this file type is not previewed inside the app — export it to open it".to_string(),
            ));
        }
        if entry.size_bytes > store::MAX_PREVIEW_BYTES {
            return Err(QGuardError::InvalidInput(format!(
                "files over {} MB are not previewed in memory — export it to open it",
                store::MAX_PREVIEW_BYTES / (1024 * 1024)
            )));
        }
        let buffer = BoundedBuffer::new(store::MAX_PREVIEW_BYTES, entry.size_bytes);
        match session.decrypt_into(&entry, buffer, &mut |_| {}) {
            Ok(mut buffer) => {
                // Previews are frequent; only state changes are worth an index write.
                if entry.integrity != INTEGRITY_VERIFIED {
                    let _ = session.record_integrity(&entry, &Ok(()), "verify", "Integrity verified while opening a preview");
                }
                Ok(std::mem::take(&mut *buffer.bytes))
            }
            Err(error) => {
                let _ = session.record_integrity(&entry, &integrity_outcome(&error), "preview", "");
                Err(error)
            }
        }
    })
    .await?;
    Ok(Response::new(bytes))
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportOutcome {
    pub name: String,
    pub destination: String,
    pub files: u64,
    pub bytes: u64,
}

/// Decrypt a stored file to a destination the user chose (desktop path from the
/// save dialog, or an Android SAF document from `vault_prepare_dest`).
#[tauri::command]
pub async fn vault_store_export(
    state: State<'_, AppState>,
    id: String,
    dest_path: String,
    on_progress: Channel<VaultProgress>,
) -> Result<ExportOutcome> {
    let session = open_session(&state, VaultNeed::Open)?;
    let checked = store::checked_id(&id)?;
    state.check_decrypt_rate_limit("vault_store_export", &checked, 60, 300)?;
    let outcome = run_stream_blocking(move || {
        let entry = session.require_file(&checked)?;
        let (dest_file, dest) = VaultDest::create(&dest_path)?;
        let result = session
            .decrypt_into(&entry, BufWriter::new(dest_file), &mut |p| {
                let _ = on_progress.send(p);
            })
            .and_then(|mut writer| writer.flush().map_err(|e| QGuardError::Storage(format!("flush export: {e}"))));
        match result {
            Ok(()) => {
                dest.commit()?;
                session.record_integrity(&entry, &Ok(()), "export", "Decrypted to a location you chose · integrity verified")?;
                Ok(ExportOutcome { name: entry.name.clone(), destination: dest_path.clone(), files: 1, bytes: entry.size_bytes })
            }
            Err(error) => {
                dest.abort();
                let _ = session.record_integrity(&entry, &integrity_outcome(&error), "export", "");
                Err(error)
            }
        }
    })
    .await?;
    state.audit_info("vault_store_export", "Vault Storage file decrypted to a user-chosen destination");
    state.touch_telemetry("vault_decrypt", "Vault Storage file exported · authenticated before release", 100);
    Ok(outcome)
}

/// Decrypt a stored folder tree into a new folder inside `dest_dir` (desktop).
#[tauri::command]
pub async fn vault_store_export_folder(
    state: State<'_, AppState>,
    id: String,
    dest_dir: String,
    on_progress: Channel<VaultProgress>,
) -> Result<ExportOutcome> {
    if content_uri::is_content_uri(&dest_dir) {
        return Err(QGuardError::InvalidInput("folder export needs a folder on this device's file system".to_string()));
    }
    let session = open_session(&state, VaultNeed::Open)?;
    let checked = store::checked_id(&id)?;
    state.check_decrypt_rate_limit("vault_store_export", &checked, 60, 300)?;
    let outcome = run_stream_blocking(move || {
        let index = {
            let _guard = lock_store()?;
            session.load()?
        };
        let root = index.require(&checked)?.clone();
        if !root.is_folder() {
            return Err(QGuardError::InvalidInput("this action needs a folder".to_string()));
        }
        let base = PathBuf::from(&dest_dir);
        if !base.is_dir() {
            return Err(QGuardError::InvalidInput("the selected destination is not a folder".to_string()));
        }
        let target = unique_in_dir(&base, &sanitize_dest_name(&root.name));
        std::fs::create_dir_all(&target).map_err(|e| QGuardError::Storage(format!("create export folder: {e}")))?;

        let mut queue: Vec<(String, PathBuf)> = vec![(root.id.clone(), target.clone())];
        let mut files: Vec<(StoreEntry, PathBuf)> = Vec::new();
        while let Some((folder_id, folder_path)) = queue.pop() {
            for child in index.entries.iter().filter(|e| e.parent_id.as_deref() == Some(folder_id.as_str()) && e.trashed_at.is_none()) {
                let path = unique_in_dir(&folder_path, &sanitize_dest_name(&child.name));
                if child.is_folder() {
                    std::fs::create_dir_all(&path).map_err(|e| QGuardError::Storage(format!("create export folder: {e}")))?;
                    queue.push((child.id.clone(), path));
                } else {
                    files.push((child.clone(), path));
                }
            }
        }
        let count = files.len();
        let mut bytes = 0u64;
        for (position, (entry, path)) in files.iter().enumerate() {
            let mut event = file_event(position, count, &entry.name);
            event.op = "decrypt".to_string();
            let _ = on_progress.send(event);
            let (dest_file, dest) = VaultDest::create(&path.to_string_lossy())?;
            let result = session
                .decrypt_into(entry, BufWriter::new(dest_file), &mut |p| {
                    let _ = on_progress.send(p);
                })
                .and_then(|mut writer| writer.flush().map_err(|e| QGuardError::Storage(format!("flush export: {e}"))));
            match result {
                Ok(()) => {
                    dest.commit()?;
                    bytes += entry.size_bytes;
                    let _ = session.record_integrity(entry, &Ok(()), "export", "Decrypted with its folder · integrity verified");
                }
                Err(error) => {
                    dest.abort();
                    return Err(QGuardError::Storage(format!("{}: {error}", entry.name)));
                }
            }
        }
        session.update(|index| {
            index.log("export", Some(&root.id), &root.name, &format!("Folder decrypted · {count} file(s)"), true);
            Ok(())
        })?;
        Ok(ExportOutcome {
            name: root.name.clone(),
            destination: target.to_string_lossy().to_string(),
            files: count as u64,
            bytes,
        })
    })
    .await?;
    state.audit_info("vault_store_export_folder", "Vault Storage folder decrypted to a user-chosen destination");
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// Thumbnails
// ---------------------------------------------------------------------------

/// Seal a thumbnail the UI rendered from a preview. Thumbnails are encrypted
/// under their own key before they touch the disk.
#[tauri::command]
pub async fn vault_store_set_thumbnail(state: State<'_, AppState>, id: String, data_b64: String) -> Result<()> {
    let session = open_session(&state, VaultNeed::Open)?;
    let checked = store::checked_id(&id)?;
    if data_b64.len() > store::MAX_THUMBNAIL_BYTES * 4 / 3 + 8 {
        return Err(QGuardError::InvalidInput("thumbnail is too large".to_string()));
    }
    run_stream_blocking(move || {
        let image = zeroize::Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(data_b64.as_bytes())
                .map_err(|_| QGuardError::InvalidInput("thumbnail is not valid base64".to_string()))?,
        );
        let entry = session.require_file(&checked)?;
        if !matches!(sniff::Category::parse(&entry.category), sniff::Category::Image | sniff::Category::Video) {
            return Err(QGuardError::InvalidInput("only photos and videos have thumbnails".to_string()));
        }
        store::seal_thumbnail(&session.layout, &session.keys, &session.ctx.user_id, &checked, &image)?;
        session.update(|index| {
            if let Some(target) = index.get_mut(&checked) {
                target.has_thumbnail = true;
            }
            Ok(())
        })
    })
    .await
}

#[tauri::command]
pub async fn vault_store_thumbnail(state: State<'_, AppState>, id: String) -> Result<Response> {
    let session = open_session(&state, VaultNeed::Open)?;
    let checked = store::checked_id(&id)?;
    let bytes = run_stream_blocking(move || {
        store::open_thumbnail(&session.layout, &session.keys, &session.ctx.user_id, &checked)
    })
    .await?;
    Ok(Response::new(bytes))
}

// ---------------------------------------------------------------------------
// After a vault reset
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartFreshOutcome {
    /// Where the previous vault's storage was moved, untouched.
    pub archived_to: String,
}

/// When the index belongs to a previous vault key, move that whole library
/// aside (nothing is deleted — its containers still open with the recovery
/// key) and start an empty one. Refused while the index opens normally.
#[tauri::command]
pub async fn vault_store_start_fresh(state: State<'_, AppState>, confirmation: String) -> Result<StartFreshOutcome> {
    if confirmation != "START FRESH" {
        return Err(QGuardError::InvalidInput("type START FRESH to confirm".to_string()));
    }
    let session = open_session(&state, VaultNeed::Seal)?;
    let outcome = run_stream_blocking(move || {
        let _guard = lock_store()?;
        match session.load() {
            Ok(_) => {
                return Err(QGuardError::InvalidInput(
                    "this vault storage belongs to the current vault — nothing to set aside".to_string(),
                ))
            }
            Err(error) if foreign_index(&error) => {}
            Err(error) => return Err(error),
        }
        let root = session.layout.root().to_path_buf();
        let parent = root.parent().ok_or_else(|| QGuardError::Storage("vault storage has no parent".to_string()))?;
        let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
        let leaf = root.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let archived = parent.join(format!("{leaf}.previous-{stamp}"));
        std::fs::rename(&root, &archived).map_err(|e| QGuardError::Storage(format!("set previous vault storage aside: {e}")))?;
        session.layout.ensure()?;
        let mut index = StoreIndex::new();
        index.log(
            "start_fresh",
            None,
            "Vault Storage",
            "Storage from a previous vault key was set aside unchanged; a new library was started",
            true,
        );
        session.persist(&index)?;
        Ok(StartFreshOutcome { archived_to: archived.to_string_lossy().to_string() })
    })
    .await?;
    state.audit_info("vault_store_start_fresh", "Vault Storage from a previous vault key set aside; new library started");
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signatures::VaultSigningKeypair;
    use crate::crypto::symmetric;
    use crate::crypto::vault_recovery;
    use crate::state::{PersistedVaultMaster, PersistedVaultRecovery};
    use crate::test_support::TestDevice;

    fn master() -> PersistedVaultMaster {
        PersistedVaultMaster {
            version: 1,
            vmk: symmetric::random_key(),
            signer: VaultSigningKeypair::generate(),
            configured_at: Utc::now(),
        }
    }

    fn unlocked() -> TestDevice {
        let device = TestDevice::new(false);
        device.state.set_vault_session(master()).expect("unlock");
        device
    }

    /// A plain file on disk to import.
    fn source(device: &TestDevice, name: &str, bytes: &[u8]) -> String {
        let dir = device.dir.join("import-source");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_string_lossy().to_string()
    }

    fn import(device: &TestDevice, path: &str, parent: Option<&str>) -> ImportOutcome {
        let session = open_session(&device.state, VaultNeed::Seal).unwrap();
        import_one(&session, path, parent, &[], true, &mut |_| {}).unwrap()
    }

    fn index_of(device: &TestDevice) -> StoreIndex {
        open_session(&device.state, VaultNeed::Open).unwrap().load().unwrap()
    }

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR-family-photo-pixels";

    #[test]
    fn an_imported_file_round_trips_and_its_name_never_reaches_the_disk() {
        let device = unlocked();
        let mut content = PNG.to_vec();
        content.extend(std::iter::repeat(9u8).take(vault_stream::CHUNK_SIZE + 333)); // two chunks
        let path = source(&device, "Passport scan.png", &content);
        let outcome = import(&device, &path, None);
        assert!(!outcome.skipped_duplicate);
        let entry = outcome.entry;
        assert_eq!(entry.name, "Passport scan.png");
        assert_eq!(entry.content_type, "image/png");
        assert_eq!(entry.category, "image");
        assert_eq!(entry.type_check, "match");
        assert_eq!(entry.size_bytes, content.len() as u64);
        assert_eq!(entry.total_chunks, 2);
        assert_eq!(entry.container_version, vault_stream::STREAM_VERSION);
        assert!(entry.pin_bound);
        assert_eq!(entry.integrity, INTEGRITY_UNVERIFIED);

        // Nothing in the vault directory names the file.
        let session = open_session(&device.state, VaultNeed::Open).unwrap();
        let object = std::fs::read(session.layout.object_path(&entry.id).unwrap()).unwrap();
        let index = std::fs::read(session.layout.index_path()).unwrap();
        for bytes in [&object, &index] {
            assert!(!bytes.windows(8).any(|w| w == b"Passport"));
            assert!(!bytes.windows(9).any(|w| w == b"image/png"));
        }
        assert!(object.windows(OPAQUE_HEADER_NAME.len()).any(|w| w == OPAQUE_HEADER_NAME.as_bytes()));

        // Opens, matches, and is then recorded as verified.
        let plain = session.decrypt_into(&entry, Vec::new(), &mut |_| {}).unwrap();
        assert_eq!(plain, content);
        session.record_integrity(&entry, &Ok(()), "verify", "ok").unwrap();
        assert_eq!(index_of(&device).get(&entry.id).unwrap().integrity, INTEGRITY_VERIFIED);
    }

    #[test]
    fn a_locked_vault_opens_nothing() {
        let device = unlocked();
        let path = source(&device, "a.txt", b"hello");
        import(&device, &path, None);
        device.state.clear_vault_session().unwrap();
        assert!(open_session(&device.state, VaultNeed::Open).is_err());
        assert!(open_session(&device.state, VaultNeed::Seal).is_err());
    }

    #[test]
    fn tampering_and_deletion_are_detected_and_recorded() {
        let device = unlocked();
        let path = source(&device, "contract.txt", b"the parties agree to everything");
        let entry = import(&device, &path, None).entry;
        let session = open_session(&device.state, VaultNeed::Open).unwrap();
        let object = session.layout.object_path(&entry.id).unwrap();

        // Flip one ciphertext byte near the end (inside the chunk data).
        let mut bytes = std::fs::read(&object).unwrap();
        let at = bytes.len() - 3;
        bytes[at] ^= 0x40;
        std::fs::write(&object, &bytes).unwrap();
        let outcome = session.decrypt_into(&entry, Vec::new(), &mut |_| {}).map(|_| ());
        assert!(matches!(outcome, Err(QGuardError::Crypto(_))));
        session.record_integrity(&entry, &outcome, "verify", "").unwrap();
        assert_eq!(index_of(&device).get(&entry.id).unwrap().integrity, INTEGRITY_FAILED);

        // Gone from disk: missing, in the record and in the live view.
        std::fs::remove_file(&object).unwrap();
        let outcome = session.decrypt_into(&entry, Vec::new(), &mut |_| {}).map(|_| ());
        assert!(matches!(outcome, Err(QGuardError::NotFound(_))));
        let view = live_view(&session.layout, &index_of(&device));
        assert_eq!(view[0].integrity, INTEGRITY_MISSING);
        assert_eq!(build_status(&session, &index_of(&device)).missing, 1);
    }

    #[test]
    fn a_container_from_another_vault_is_refused() {
        let device = unlocked();
        let path = source(&device, "a.txt", b"mine");
        let entry = import(&device, &path, None).entry;
        let session = open_session(&device.state, VaultNeed::Open).unwrap();

        // Someone else's vault seals a file of their own and drops it in place.
        let other = TestDevice::new(false);
        other.state.set_vault_session(master()).unwrap();
        let theirs = source(&other, "b.txt", b"mine");
        let foreign = import(&other, &theirs, None).entry;
        let foreign_session = open_session(&other.state, VaultNeed::Open).unwrap();
        std::fs::copy(
            foreign_session.layout.object_path(&foreign.id).unwrap(),
            session.layout.object_path(&entry.id).unwrap(),
        )
        .unwrap();
        assert!(session.decrypt_into(&entry, Vec::new(), &mut |_| {}).is_err());
    }

    #[test]
    fn duplicates_are_skipped_per_folder() {
        let device = unlocked();
        let first = source(&device, "a.txt", b"same bytes");
        let again = source(&device, "copy of a.txt", b"same bytes");
        let original = import(&device, &first, None).entry;
        let second = import(&device, &again, None);
        assert!(second.skipped_duplicate);
        assert_eq!(second.entry.id, original.id);
        let session = open_session(&device.state, VaultNeed::Open).unwrap();
        assert_eq!(session.layout.object_ids().len(), 1);
        assert!(std::fs::read_dir(session.layout.staging_dir()).unwrap().next().is_none());

        // Into another folder it is stored again.
        let folder = session.update(|index| index.create_folder(None, "Elsewhere")).unwrap();
        assert!(!import(&device, &again, Some(&folder.id)).skipped_duplicate);
    }

    #[test]
    fn purge_is_limited_to_the_trash_and_destroys_the_container() {
        let device = unlocked();
        let path = source(&device, "old.txt", b"to be deleted");
        let entry = import(&device, &path, None).entry;
        let session = open_session(&device.state, VaultNeed::Seal).unwrap();
        let object = session.layout.object_path(&entry.id).unwrap();

        let refused = purge(&session, |_| Ok(vec![entry.id.clone()]));
        assert!(refused.is_err());
        assert!(object.exists());

        session.update(|index| index.trash(&entry.id)).unwrap();
        let outcome = purge(&session, |index| Ok(index.entries.iter().filter(|e| e.trashed_at.is_some()).map(|e| e.id.clone()).collect())).unwrap();
        assert_eq!(outcome.removed_entries, 1);
        assert_eq!(outcome.destroyed_objects, 1);
        assert!(!object.exists());
        assert!(index_of(&device).get(&entry.id).is_none());
    }

    #[test]
    fn folder_imports_recreate_the_tree() {
        let device = unlocked();
        let session = open_session(&device.state, VaultNeed::Seal).unwrap();
        let path = source(&device, "day1.txt", b"beach");
        let parts = vec!["Trip".to_string(), "Photos".to_string()];
        let outcome = import_one(&session, &path, None, &parts, true, &mut |_| {}).unwrap();
        let index = index_of(&device);
        let parent = outcome.entry.parent_id.clone().unwrap();
        assert_eq!(index.breadcrumb(&parent), vec!["Trip", "Photos"]);
        assert_eq!(index.entries.iter().filter(|e| e.is_folder()).count(), 2);
    }

    #[test]
    fn a_vault_reset_leaves_the_old_library_untouched_and_reported() {
        let device = unlocked();
        let path = source(&device, "a.txt", b"before the reset");
        import(&device, &path, None);
        // A vault reset installs a brand-new master.
        device.state.set_vault_session(master()).unwrap();
        let session = open_session(&device.state, VaultNeed::Open).unwrap();
        let error = session.load().unwrap_err();
        assert!(foreign_index(&error), "{error}");
        // Nothing was rewritten: still one object, and the index still exists.
        assert_eq!(session.layout.object_ids().len(), 1);
        assert!(session.layout.index_path().exists());
    }

    #[test]
    fn with_personal_recovery_the_library_survives_losing_the_vault_key() {
        let device = unlocked();
        let root = vault_recovery::generate_recovery_root();
        let wrap_key = vault_recovery::derive_wrap_key(&root).unwrap();
        let vault_key = device.state.unlocked_vault_master().unwrap().vault_key().unwrap();
        device
            .state
            .save_vault_recovery(&device.user, &PersistedVaultRecovery::personal(wrap_key, "verifier".to_string()), &vault_key)
            .unwrap();

        let content = b"will outlive this device".to_vec();
        let path = source(&device, "Will.pdf", &content);
        let entry = import(&device, &path, None).entry;
        assert!(entry.recovery_protected);

        // The vault key is gone (lost device / forgotten PIN). With only the
        // recovery key: the names come back from the recovery copy...
        let session = open_session(&device.state, VaultNeed::Open).unwrap();
        let layout = session.layout.clone();
        drop(session);
        device.state.clear_vault_session().unwrap();
        let rebuilt_wrap_key = vault_recovery::derive_wrap_key(&root).unwrap();
        let recovery_keys = StoreKeys::for_recovery(&rebuilt_wrap_key).unwrap();
        let recovered_index = store::load_index_at(&layout.recovery_index_path(), &recovery_keys, &device.user).unwrap();
        let recovered_entry = recovered_index.get(&entry.id).unwrap();
        assert_eq!(recovered_entry.name, "Will.pdf");

        // ...and the content from the container's own recovery wrap.
        let mut reader = BufReader::new(File::open(layout.object_path(&entry.id).unwrap()).unwrap());
        let mut plain = Vec::new();
        vault_stream::decrypt_stream_with_recovery(&mut reader, &mut plain, &rebuilt_wrap_key).unwrap();
        assert_eq!(plain, content);

        // A different recovery key opens neither.
        let wrong = vault_recovery::derive_wrap_key(&vault_recovery::generate_recovery_root()).unwrap();
        let wrong_keys = StoreKeys::for_recovery(&wrong).unwrap();
        assert!(store::load_index_at(&layout.recovery_index_path(), &wrong_keys, &device.user).is_err());
    }

    #[test]
    fn without_recovery_no_recovery_copy_is_kept() {
        let device = unlocked();
        let path = source(&device, "a.txt", b"x");
        let entry = import(&device, &path, None).entry;
        assert!(!entry.recovery_protected);
        let session = open_session(&device.state, VaultNeed::Open).unwrap();
        assert!(!session.layout.recovery_index_path().exists());
        assert!(!build_status(&session, &index_of(&device)).recovery_index);
    }

    #[test]
    fn status_counts_come_from_the_index_and_the_disk() {
        let device = unlocked();
        import(&device, &source(&device, "p.png", PNG), None);
        import(&device, &source(&device, "n.txt", b"notes"), None);
        let gone = import(&device, &source(&device, "g.txt", b"gone soon"), None).entry;
        let session = open_session(&device.state, VaultNeed::Seal).unwrap();
        session.update(|index| index.trash(&gone.id)).unwrap();
        // An object the index does not know about (interrupted import).
        std::fs::write(session.layout.object_path(&uuid::Uuid::new_v4().to_string()).unwrap(), b"QGUARDVS").unwrap();

        let status = build_status(&session, &index_of(&device));
        assert_eq!(status.files, 2);
        assert_eq!(status.trashed, 1);
        assert_eq!(status.categories.image.files, 1);
        assert_eq!(status.categories.document.files, 1);
        assert_eq!(status.plaintext_bytes, PNG.len() as u64 + 5);
        assert!(status.stored_bytes > status.plaintext_bytes);
        assert_eq!(status.unverified, 2);
        assert_eq!(status.orphaned_objects, 1);
        assert_eq!(status.legacy_containers, 0);
        assert!(status.last_import_at.is_some());
    }
}
