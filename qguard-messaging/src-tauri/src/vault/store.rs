//! Quantum Vault Storage — the managed, on-device encrypted file library.
//!
//! The streaming vault (`vault_stream`) turns one file into one `.qvault`
//! container wherever the user chooses. Storage keeps the containers itself, in
//! the app's private data directory, and gives them a file manager: folders,
//! names, trash, integrity state and activity. It adds NO new cryptography to
//! file content — every stored file is an ordinary v5 container (AES-256-GCM
//! per 1 MiB chunk, per-file key sealed under the PIN-bound vault key, recovery
//! / enterprise wraps when configured, Ed25519 + ML-DSA-87 signed header).
//!
//! What storage adds is metadata protection:
//!
//! * A container's header is plaintext JSON and carries a `name`. Stored
//!   containers are written with the file id as that name and a generic
//!   content type, so an object on disk says nothing about what it holds.
//! * The real names, folders, types, hashes and activity live in ONE index,
//!   sealed with AES-256-GCM under `HKDF-SHA3-256(vault key, index info)`. The
//!   vault key only exists while the vault is unlocked, so a locked vault
//!   reveals neither content nor names.
//! * Thumbnails are sealed the same way under their own derived key.
//!
//! On-disk layout, per user, under `<data_dir>/vault/store/<user>/`:
//! ```text
//! index.qvs             MAGIC(8) | vault id(32) | nonce(12) | tag(16) | ciphertext
//! objects/<id>.qvault   v5 vault_stream container
//! thumbs/<id>.qvt       MAGIC(8) | nonce(12) | tag(16) | ciphertext
//! staging/              in-flight imports (deleted on failure)
//! ```
//!
//! The vault id is `SHA3-256(HKDF-SHA3-256(vault key, id info))`: it says which
//! vault sealed the index without revealing anything about the key, so an index
//! left behind by a vault reset is reported as such instead of as corruption.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::crypto::provider::Sha3_256Hasher as Sha3_256;
use zeroize::Zeroizing;

use crate::crypto::kdf;
use crate::crypto::symmetric::{self, KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use crate::crypto::EncryptedEnvelope;
use crate::error::{QGuardError, Result};

const INDEX_MAGIC: &[u8; 8] = b"QGVSIDX1";
const THUMB_MAGIC: &[u8; 8] = b"QGVSTHB1";
const INDEX_KEY_INFO: &[u8] = b"QGuard-VaultStore-Index-v1";
const THUMB_KEY_INFO: &[u8] = b"QGuard-VaultStore-Thumbnail-v1";
const VAULT_ID_INFO: &[u8] = b"QGuard-VaultStore-VaultId-v1";
const RECOVERY_INDEX_KEY_INFO: &[u8] = b"QGuard-VaultStore-RecoveryIndex-v1";
const RECOVERY_ID_INFO: &[u8] = b"QGuard-VaultStore-RecoveryId-v1";

pub const INDEX_VERSION: u8 = 1;
/// Largest thumbnail accepted for sealing.
pub const MAX_THUMBNAIL_BYTES: usize = 256 * 1024;
/// Largest file decrypted into memory for an in-app preview. Anything bigger is
/// exported instead, so plaintext of a large video never sits in app memory.
pub const MAX_PREVIEW_BYTES: u64 = 64 * 1024 * 1024;
/// Largest single file the vault accepts.
pub const MAX_IMPORT_BYTES: u64 = 32 * 1024 * 1024 * 1024;
/// Longest name kept for a file or folder, in characters.
pub const MAX_NAME_CHARS: usize = 200;
/// Defensive cap on the number of entries one vault holds.
pub const MAX_ENTRIES: usize = 100_000;
/// Activity records kept (newest first).
pub const MAX_ACTIVITY: usize = 500;
/// Largest sealed index accepted on read.
const MAX_INDEX_BYTES: u64 = 256 * 1024 * 1024;

/// Stable prefix of the error returned when the index was sealed by a different
/// vault (one that existed before a vault reset). The UI matches on it.
pub const FOREIGN_INDEX_MARKER: &str = "VAULT_STORE_FOREIGN_INDEX";

pub const KIND_FILE: &str = "file";
pub const KIND_FOLDER: &str = "folder";

pub const INTEGRITY_VERIFIED: &str = "verified";
pub const INTEGRITY_UNVERIFIED: &str = "unverified";
pub const INTEGRITY_FAILED: &str = "failed";
pub const INTEGRITY_MISSING: &str = "missing";

fn io_err(context: &str, error: io::Error) -> QGuardError {
    QGuardError::Storage(format!("{context}: {error}"))
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// Keys derived from the PIN-bound vault key for the index and thumbnails.
pub struct StoreKeys {
    index_key: Zeroizing<[u8; KEY_SIZE]>,
    thumb_key: Zeroizing<[u8; KEY_SIZE]>,
    vault_id: [u8; 32],
}

impl StoreKeys {
    pub fn derive(vault_key: &[u8; KEY_SIZE]) -> Result<Self> {
        let index_key = Zeroizing::new(kdf::derive_32(vault_key, INDEX_KEY_INFO)?);
        let thumb_key = Zeroizing::new(kdf::derive_32(vault_key, THUMB_KEY_INFO)?);
        let id_material = Zeroizing::new(kdf::derive_32(vault_key, VAULT_ID_INFO)?);
        let vault_id = kdf::sha3_256(&*id_material);
        Ok(Self { index_key, thumb_key, vault_id })
    }

    /// Keys for the recovery copy of the index, derived from the personal
    /// recovery wrap key. That key is the same on every device of the account
    /// and is reproduced from the recovery key alone, so this copy opens after
    /// the device — and with it the vault key — is gone. Its key is separate
    /// from every file's key and from the main index key.
    pub fn for_recovery(recovery_wrap_key: &[u8; KEY_SIZE]) -> Result<Self> {
        let index_key = Zeroizing::new(kdf::derive_32(recovery_wrap_key, RECOVERY_INDEX_KEY_INFO)?);
        let id_material = Zeroizing::new(kdf::derive_32(recovery_wrap_key, RECOVERY_ID_INFO)?);
        let vault_id = kdf::sha3_256(&*id_material);
        // Thumbnails are not part of the recovery copy; the key is never used.
        let thumb_key = Zeroizing::new(symmetric::random_key());
        Ok(Self { index_key, thumb_key, vault_id })
    }

    pub fn vault_id_hex(&self) -> String {
        hex::encode(self.vault_id)
    }
}

fn index_aad(user_id: &str, vault_id: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + user_id.len());
    aad.extend_from_slice(INDEX_MAGIC);
    aad.extend_from_slice(b"|");
    aad.extend_from_slice(user_id.as_bytes());
    aad.extend_from_slice(b"|");
    aad.extend_from_slice(vault_id);
    aad
}

fn thumb_aad(user_id: &str, entry_id: &str) -> Vec<u8> {
    format!("QGVS-Thumb-v1|{user_id}|{entry_id}").into_bytes()
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Where one user's vault storage lives.
#[derive(Clone, Debug)]
pub struct StoreLayout {
    root: PathBuf,
}

impl StoreLayout {
    /// `safe_user` must already be filesystem-safe (`AppState::safe_user_key`).
    pub fn new(data_dir: &Path, safe_user: &str) -> Self {
        Self { root: data_dir.join("vault").join("store").join(safe_user) }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ensure(&self) -> Result<()> {
        for dir in [self.objects_dir(), self.thumbs_dir(), self.staging_dir(), self.cloud_dir()] {
            std::fs::create_dir_all(&dir).map_err(|e| io_err("create vault storage", e))?;
        }
        Ok(())
    }

    pub fn index_path(&self) -> PathBuf {
        self.root.join("index.qvs")
    }

    /// The index sealed under the recovery key (see [`StoreKeys::for_recovery`]).
    pub fn recovery_index_path(&self) -> PathBuf {
        self.root.join("index.recovery.qvs")
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    pub fn thumbs_dir(&self) -> PathBuf {
        self.root.join("thumbs")
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.root.join("staging")
    }

    /// Container path for an entry. The id is checked to be a UUID first, so no
    /// value can address anything outside `objects/`.
    pub fn object_path(&self, entry_id: &str) -> Result<PathBuf> {
        Ok(self.objects_dir().join(format!("{}.qvault", checked_id(entry_id)?)))
    }

    pub fn thumb_path(&self, entry_id: &str) -> Result<PathBuf> {
        Ok(self.thumbs_dir().join(format!("{}.qvt", checked_id(entry_id)?)))
    }

    /// In-flight cloud transfers (index snapshots being uploaded, containers
    /// being downloaded). Ciphertext only; kept apart from `staging/` so an
    /// import starting never clears a transfer that is running.
    pub fn cloud_dir(&self) -> PathBuf {
        self.root.join("cloud")
    }

    /// A fresh in-flight import file.
    pub fn new_staging_path(&self) -> PathBuf {
        self.staging_dir().join(format!("{}.part", uuid::Uuid::new_v4()))
    }

    /// Remove imports a crash left behind. Only ever ciphertext.
    pub fn clear_staging(&self) {
        if let Ok(entries) = std::fs::read_dir(self.staging_dir()) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// Ids of every container on disk.
    pub fn object_ids(&self) -> HashSet<String> {
        let mut ids = HashSet::new();
        if let Ok(entries) = std::fs::read_dir(self.objects_dir()) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(stem) = name.strip_suffix(".qvault") {
                    if uuid::Uuid::parse_str(stem).is_ok() {
                        ids.insert(stem.to_string());
                    }
                }
            }
        }
        ids
    }
}

/// An entry id, accepted only in canonical UUID form.
pub fn checked_id(entry_id: &str) -> Result<String> {
    let parsed = uuid::Uuid::parse_str(entry_id)
        .map_err(|_| QGuardError::InvalidInput("invalid vault entry id".to_string()))?;
    Ok(parsed.hyphenated().to_string())
}

// ---------------------------------------------------------------------------
// Index model
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StoreEntry {
    pub id: String,
    /// `file` | `folder`.
    pub kind: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub trashed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub favorite: bool,
    // ---- files only (zero / empty on folders) ----
    #[serde(default)]
    pub size_bytes: u64,
    /// Size of the encrypted container on disk.
    #[serde(default)]
    pub stored_bytes: u64,
    /// Detected from the content, never from the extension.
    #[serde(default)]
    pub content_type: String,
    #[serde(default)]
    pub category: String,
    /// `match` | `mismatch` | `unknown` — extension vs content.
    #[serde(default)]
    pub type_check: String,
    /// SHA3-256 of the plaintext, taken while it was sealed. Every later open
    /// recomputes it, on top of the per-chunk AES-GCM tags.
    #[serde(default)]
    pub plaintext_sha3: String,
    #[serde(default)]
    pub container_version: u8,
    #[serde(default)]
    pub pin_bound: bool,
    #[serde(default)]
    pub total_chunks: u64,
    /// The container carries a recovery or enterprise wrap (set at seal time
    /// from the recovery configuration actually used).
    #[serde(default)]
    pub recovery_protected: bool,
    /// `verified` | `unverified` | `failed` | `missing`.
    #[serde(default)]
    pub integrity: String,
    #[serde(default)]
    pub last_verified_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub has_thumbnail: bool,
    /// Cloud backup object holding this file's container, once committed.
    #[serde(default)]
    pub cloud_object_id: Option<String>,
    #[serde(default)]
    pub cloud_backed_up_at: Option<DateTime<Utc>>,
    /// This file's key sealed under the account library key (phase 3): how the
    /// account's other devices open the cloud copy. See `vault::library`.
    #[serde(default)]
    pub library_fek: Option<crate::vault::library::SealedFek>,
    /// Computed for views, never trusted from storage: the encrypted object is
    /// on this device (false = backed up, cloud copy only).
    #[serde(default)]
    pub available_offline: bool,
    /// The cloud copy was uploaded only so the file could be SHARED, while
    /// cloud backup was off (sharing never requires backup). It is taken back
    /// when no share uses it any more, and becomes an ordinary backup copy if
    /// backup is switched on (`commands::vault_cloud`).
    #[serde(default)]
    pub cloud_shared_only: bool,
}

impl StoreEntry {
    pub fn is_folder(&self) -> bool {
        self.kind == KIND_FOLDER
    }

    pub fn is_file(&self) -> bool {
        self.kind == KIND_FILE
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StoreActivity {
    pub id: String,
    pub at: DateTime<Utc>,
    /// import | export | preview | verify | rename | move | create_folder |
    /// trash | restore | purge | favorite | thumbnail | start_fresh
    pub action: String,
    pub entry_id: Option<String>,
    pub name: String,
    pub detail: String,
    /// `success` | `failed`.
    pub outcome: String,
}

/// Cloud backup settings and the durable part of its work queue. What still has
/// to be uploaded is derived from the entries (a live file without a
/// `cloud_object_id`); what has to be removed from the cloud is listed here, so
/// a deletion survives restarts and network failures until the server confirms.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CloudSettings {
    /// The user turned cloud backup on. Off by default: nothing is uploaded
    /// unless this is true.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub enabled_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_sync_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_error: Option<String>,
    /// Cloud object holding the recovery-key-sealed copy of this index.
    #[serde(default)]
    pub index_object_id: Option<String>,
    /// [`StoreIndex::structure_digest`] of the index that copy holds.
    #[serde(default)]
    pub index_digest: Option<String>,
    /// Cloud objects to delete (files deleted permanently, replaced index
    /// copies, everything once the user deletes the backup).
    #[serde(default)]
    pub pending_deletes: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StoreIndex {
    pub version: u8,
    pub entries: Vec<StoreEntry>,
    pub activity: Vec<StoreActivity>,
    #[serde(default)]
    pub last_full_verify_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub cloud: CloudSettings,
    /// Multi-device library (phase 3): key ring, sync position, deletions.
    #[serde(default)]
    pub library: crate::vault::library::LibraryState,
}

/// Make a user-supplied name safe to keep and display. Names are never used as
/// filesystem paths inside the store (objects are addressed by id), but they do
/// become file names on export, so separators and control characters go.
pub fn clean_name(raw: &str) -> Result<String> {
    let mut cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '/' || c == '\\' { '_' } else { c })
        .collect();
    cleaned = cleaned.trim().trim_end_matches(['.', ' ']).to_string();
    if cleaned.chars().count() > MAX_NAME_CHARS {
        // Keep the extension when shortening.
        let ext = crate::vault::sniff::extension_of(&cleaned);
        let keep = MAX_NAME_CHARS.saturating_sub(if ext.is_empty() { 0 } else { ext.len() + 1 });
        let stem: String = cleaned.chars().take(keep).collect();
        cleaned = if ext.is_empty() { stem } else { format!("{}.{ext}", stem.trim_end()) };
    }
    if cleaned.is_empty() || cleaned.chars().all(|c| c == '.') {
        return Err(QGuardError::InvalidInput("a name is required".to_string()));
    }
    Ok(cleaned)
}

/// `name`, or `name (n)` keeping the extension.
fn numbered(name: &str, counter: u32, is_folder: bool) -> String {
    if !is_folder {
        if let Some((stem, ext)) = name.rsplit_once('.') {
            if !stem.is_empty() {
                return format!("{stem} ({counter}).{ext}");
            }
        }
    }
    format!("{name} ({counter})")
}

impl StoreIndex {
    pub fn new() -> Self {
        Self { version: INDEX_VERSION, ..Self::default() }
    }

    pub fn get(&self, id: &str) -> Option<&StoreEntry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut StoreEntry> {
        self.entries.iter_mut().find(|entry| entry.id == id)
    }

    pub fn require(&self, id: &str) -> Result<&StoreEntry> {
        self.get(id).ok_or_else(|| QGuardError::NotFound("vault item not found".to_string()))
    }

    /// True when the entry or any folder above it is in the trash.
    pub fn in_trash(&self, id: &str) -> bool {
        let mut current = self.get(id);
        let mut guard = 0;
        while let Some(entry) = current {
            if entry.trashed_at.is_some() {
                return true;
            }
            guard += 1;
            if guard > 256 {
                return false;
            }
            current = entry.parent_id.as_deref().and_then(|parent| self.get(parent));
        }
        false
    }

    /// A folder that can receive items: exists, is a folder, is not in the trash.
    fn require_live_folder(&self, parent_id: Option<&str>) -> Result<()> {
        if let Some(parent) = parent_id {
            let entry = self.require(parent)?;
            if !entry.is_folder() {
                return Err(QGuardError::InvalidInput("the destination is not a folder".to_string()));
            }
            if self.in_trash(parent) {
                return Err(QGuardError::InvalidInput("the destination folder is in the trash".to_string()));
            }
        }
        Ok(())
    }

    /// `name` made unique among the live items of `parent` (case-insensitive).
    pub fn unique_name(&self, parent_id: Option<&str>, name: &str, is_folder: bool, exclude: Option<&str>) -> String {
        let taken: HashSet<String> = self
            .entries
            .iter()
            .filter(|entry| entry.parent_id.as_deref() == parent_id)
            .filter(|entry| Some(entry.id.as_str()) != exclude)
            .filter(|entry| entry.trashed_at.is_none())
            .map(|entry| entry.name.to_lowercase())
            .collect();
        if !taken.contains(&name.to_lowercase()) {
            return name.to_string();
        }
        for counter in 1u32..100_000 {
            let candidate = numbered(name, counter, is_folder);
            if !taken.contains(&candidate.to_lowercase()) {
                return candidate;
            }
        }
        format!("{name} ({})", uuid::Uuid::new_v4())
    }

    fn require_capacity(&self) -> Result<()> {
        if self.entries.len() >= MAX_ENTRIES {
            return Err(QGuardError::InvalidInput(format!(
                "the vault already holds {MAX_ENTRIES} items"
            )));
        }
        Ok(())
    }

    pub fn create_folder(&mut self, parent_id: Option<&str>, raw_name: &str) -> Result<StoreEntry> {
        self.require_capacity()?;
        self.require_live_folder(parent_id)?;
        let name = self.unique_name(parent_id, &clean_name(raw_name)?, true, None);
        let now = Utc::now();
        let entry = StoreEntry {
            id: uuid::Uuid::new_v4().to_string(),
            kind: KIND_FOLDER.to_string(),
            name,
            parent_id: parent_id.map(str::to_string),
            created_at: now,
            updated_at: now,
            trashed_at: None,
            favorite: false,
            size_bytes: 0,
            stored_bytes: 0,
            content_type: String::new(),
            category: String::new(),
            type_check: String::new(),
            plaintext_sha3: String::new(),
            container_version: 0,
            pin_bound: false,
            total_chunks: 0,
            recovery_protected: false,
            integrity: String::new(),
            last_verified_at: None,
            has_thumbnail: false,
            cloud_object_id: None,
            cloud_backed_up_at: None,
            library_fek: None,
            available_offline: false,
            cloud_shared_only: false,
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// SHA3-256 over what a restore needs from the index — the tree, names and
    /// file identities — and nothing that changes on every open (integrity
    /// timestamps, thumbnails, activity). The cloud copy of the index is
    /// replaced only when this changes.
    pub fn structure_digest(&self) -> String {
        let mut rows: Vec<&StoreEntry> = self.entries.iter().collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        let mut hasher = Sha3_256::new();
        for entry in rows {
            let row = serde_json::json!([
                entry.id,
                entry.kind,
                entry.name,
                entry.parent_id,
                entry.trashed_at,
                entry.favorite,
                entry.size_bytes,
                entry.content_type,
                entry.category,
                entry.plaintext_sha3,
            ]);
            hasher.update(row.to_string().as_bytes());
            hasher.update(b"\n");
        }
        hex::encode(hasher.finalize())
    }

    /// Recreate the folder chain of `entry_id` from `source` (a restored index)
    /// in this index, reusing folders that already exist here by id. Returns the
    /// parent the restored entry should go under: its original folder when that
    /// could be recreated, otherwise the top level.
    pub fn adopt_ancestors(&mut self, source: &StoreIndex, entry_id: &str) -> Result<Option<String>> {
        let mut chain: Vec<StoreEntry> = Vec::new();
        let mut current = source.get(entry_id).and_then(|e| e.parent_id.clone());
        while let Some(id) = current {
            if chain.len() > 256 {
                break;
            }
            let Some(folder) = source.get(&id) else { break };
            if !folder.is_folder() {
                break;
            }
            chain.push(folder.clone());
            current = folder.parent_id.clone();
        }
        chain.reverse();
        let mut parent: Option<String> = None;
        for folder in chain {
            match self.get(&folder.id) {
                Some(existing) if existing.is_folder() && !self.in_trash(&existing.id) => {
                    parent = Some(existing.id.clone());
                }
                Some(_) => return Ok(None), // the id is taken by something else here
                None => {
                    self.require_capacity()?;
                    let name = self.unique_name(parent.as_deref(), &folder.name, true, None);
                    let now = Utc::now();
                    self.entries.push(StoreEntry {
                        parent_id: parent.clone(),
                        name,
                        trashed_at: None,
                        updated_at: now,
                        cloud_object_id: None,
                        cloud_backed_up_at: None,
                        library_fek: None,
                        available_offline: false,
                        cloud_shared_only: false,
                        ..folder.clone()
                    });
                    parent = Some(folder.id.clone());
                }
            }
        }
        Ok(parent)
    }

    /// Find or create the folder chain `parts` under `parent_id` (folder import).
    pub fn ensure_folder_path(&mut self, parent_id: Option<&str>, parts: &[String]) -> Result<Option<String>> {
        let mut current = parent_id.map(str::to_string);
        for part in parts {
            let name = clean_name(part)?;
            let existing = self
                .entries
                .iter()
                .find(|entry| {
                    entry.is_folder()
                        && entry.trashed_at.is_none()
                        && entry.parent_id == current
                        && entry.name.eq_ignore_ascii_case(&name)
                })
                .map(|entry| entry.id.clone());
            current = Some(match existing {
                Some(id) => id,
                None => self.create_folder(current.as_deref(), &name)?.id,
            });
        }
        Ok(current)
    }

    /// Add a sealed file. The entry's name is made unique in its folder.
    pub fn insert_file(&mut self, mut entry: StoreEntry) -> Result<StoreEntry> {
        self.require_capacity()?;
        self.require_live_folder(entry.parent_id.as_deref())?;
        if self.get(&entry.id).is_some() {
            return Err(QGuardError::InvalidInput("vault item already exists".to_string()));
        }
        entry.name = self.unique_name(entry.parent_id.as_deref(), &entry.name, false, None);
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// A live file in `parent_id` with this plaintext hash.
    pub fn duplicate_in(&self, parent_id: Option<&str>, plaintext_sha3: &str) -> Option<&StoreEntry> {
        self.entries.iter().find(|entry| {
            entry.is_file()
                && entry.parent_id.as_deref() == parent_id
                && entry.trashed_at.is_none()
                && entry.plaintext_sha3 == plaintext_sha3
        })
    }

    pub fn rename(&mut self, id: &str, raw_name: &str) -> Result<StoreEntry> {
        let entry = self.require(id)?.clone();
        if self.in_trash(id) {
            return Err(QGuardError::InvalidInput("restore the item before renaming it".to_string()));
        }
        let name = self.unique_name(entry.parent_id.as_deref(), &clean_name(raw_name)?, entry.is_folder(), Some(id));
        let target = self.get_mut(id).expect("checked above");
        target.name = name;
        target.updated_at = Utc::now();
        Ok(target.clone())
    }

    /// Whether `candidate` is `ancestor` or somewhere inside it.
    fn is_within(&self, candidate: &str, ancestor: &str) -> bool {
        let mut current = Some(candidate.to_string());
        let mut guard = 0;
        while let Some(id) = current {
            if id == ancestor {
                return true;
            }
            guard += 1;
            if guard > 256 {
                return true; // a cycle would be corruption; refuse the move
            }
            current = self.get(&id).and_then(|entry| entry.parent_id.clone());
        }
        false
    }

    pub fn move_entry(&mut self, id: &str, new_parent: Option<&str>) -> Result<StoreEntry> {
        let entry = self.require(id)?.clone();
        if self.in_trash(id) {
            return Err(QGuardError::InvalidInput("restore the item before moving it".to_string()));
        }
        self.require_live_folder(new_parent)?;
        if let Some(parent) = new_parent {
            if entry.is_folder() && self.is_within(parent, id) {
                return Err(QGuardError::InvalidInput("a folder cannot be moved into itself".to_string()));
            }
        }
        if entry.parent_id.as_deref() == new_parent {
            return Ok(entry);
        }
        let name = self.unique_name(new_parent, &entry.name, entry.is_folder(), Some(id));
        let target = self.get_mut(id).expect("checked above");
        target.parent_id = new_parent.map(str::to_string);
        target.name = name;
        target.updated_at = Utc::now();
        Ok(target.clone())
    }

    pub fn set_favorite(&mut self, id: &str, favorite: bool) -> Result<StoreEntry> {
        let target = self.get_mut(id).ok_or_else(|| QGuardError::NotFound("vault item not found".to_string()))?;
        target.favorite = favorite;
        target.updated_at = Utc::now();
        Ok(target.clone())
    }

    pub fn trash(&mut self, id: &str) -> Result<StoreEntry> {
        let target = self.get_mut(id).ok_or_else(|| QGuardError::NotFound("vault item not found".to_string()))?;
        if target.trashed_at.is_none() {
            target.trashed_at = Some(Utc::now());
            target.updated_at = Utc::now();
        }
        Ok(target.clone())
    }

    /// Restore from the trash. If the folder it lived in is gone or itself in
    /// the trash, it comes back at the top level instead.
    pub fn restore(&mut self, id: &str) -> Result<StoreEntry> {
        let entry = self.require(id)?.clone();
        if entry.trashed_at.is_none() {
            return Err(QGuardError::InvalidInput("the item is not in the trash".to_string()));
        }
        let parent_ok = match entry.parent_id.as_deref() {
            None => true,
            Some(parent) => self.get(parent).is_some_and(|p| p.is_folder()) && !self.in_trash(parent),
        };
        let parent = if parent_ok { entry.parent_id.clone() } else { None };
        let name = self.unique_name(parent.as_deref(), &entry.name, entry.is_folder(), Some(id));
        let target = self.get_mut(id).expect("checked above");
        target.trashed_at = None;
        target.parent_id = parent;
        target.name = name;
        target.updated_at = Utc::now();
        Ok(target.clone())
    }

    /// The entry and everything inside it.
    pub fn subtree(&self, id: &str) -> Vec<String> {
        let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
        for entry in &self.entries {
            if let Some(parent) = entry.parent_id.as_deref() {
                children.entry(parent).or_default().push(entry.id.as_str());
            }
        }
        let mut out = Vec::new();
        let mut stack = vec![id];
        let mut seen = HashSet::new();
        while let Some(current) = stack.pop() {
            if !seen.insert(current) || self.get(current).is_none() {
                continue;
            }
            out.push(current.to_string());
            if let Some(kids) = children.get(current) {
                stack.extend(kids.iter().copied());
            }
        }
        out
    }

    /// Every entry that is in the trash itself or inside a trashed folder.
    pub fn trashed_ids(&self) -> Vec<String> {
        self.entries.iter().filter(|e| self.in_trash(&e.id)).map(|e| e.id.clone()).collect()
    }

    pub fn remove(&mut self, ids: &HashSet<String>) {
        self.entries.retain(|entry| !ids.contains(&entry.id));
    }

    /// Folder chain from the top level down to `id` (inclusive).
    pub fn breadcrumb(&self, id: &str) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = self.get(id);
        while let Some(entry) = current {
            if chain.len() > 256 {
                break;
            }
            chain.push(entry.name.clone());
            current = entry.parent_id.as_deref().and_then(|parent| self.get(parent));
        }
        chain.reverse();
        chain
    }

    pub fn log(&mut self, action: &str, entry_id: Option<&str>, name: &str, detail: &str, ok: bool) {
        self.activity.insert(
            0,
            StoreActivity {
                id: uuid::Uuid::new_v4().to_string(),
                at: Utc::now(),
                action: action.to_string(),
                entry_id: entry_id.map(str::to_string),
                name: name.to_string(),
                detail: detail.to_string(),
                outcome: if ok { "success" } else { "failed" }.to_string(),
            },
        );
        self.activity.truncate(MAX_ACTIVITY);
    }
}

// ---------------------------------------------------------------------------
// Sealed index I/O
// ---------------------------------------------------------------------------

/// Read the index. A missing index is an empty vault. An index sealed by a
/// different vault fails with [`FOREIGN_INDEX_MARKER`] and is left untouched.
pub fn load_index(layout: &StoreLayout, keys: &StoreKeys, user_id: &str) -> Result<StoreIndex> {
    load_index_at(&layout.index_path(), keys, user_id)
}

/// Seal and atomically replace the index.
pub fn save_index(layout: &StoreLayout, keys: &StoreKeys, user_id: &str, index: &StoreIndex) -> Result<()> {
    layout.ensure()?;
    save_index_at(&layout.index_path(), keys, user_id, index)
}

pub fn load_index_at(path: &Path, keys: &StoreKeys, user_id: &str) -> Result<StoreIndex> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(StoreIndex::new()),
        Err(error) => return Err(io_err("read vault index", error)),
    };
    if metadata.len() > MAX_INDEX_BYTES {
        return Err(QGuardError::Storage("vault index is implausibly large".to_string()));
    }
    let bytes = std::fs::read(path).map_err(|e| io_err("read vault index", e))?;
    let header = INDEX_MAGIC.len() + 32 + NONCE_SIZE + TAG_SIZE;
    if bytes.len() < header || &bytes[..INDEX_MAGIC.len()] != INDEX_MAGIC {
        return Err(QGuardError::Crypto("vault index is not a QGuard vault index".to_string()));
    }
    let mut offset = INDEX_MAGIC.len();
    let stored_id = &bytes[offset..offset + 32];
    offset += 32;
    if stored_id != keys.vault_id {
        return Err(QGuardError::Trust(format!(
            "{FOREIGN_INDEX_MARKER}: this vault storage was sealed by a previous vault key (before a vault reset). Its files are kept on disk and open with your recovery key."
        )));
    }
    let envelope = EncryptedEnvelope {
        nonce: bytes[offset..offset + NONCE_SIZE].to_vec(),
        tag: bytes[offset + NONCE_SIZE..offset + NONCE_SIZE + TAG_SIZE].to_vec(),
        ciphertext: bytes[header..].to_vec(),
    };
    let plaintext = Zeroizing::new(
        symmetric::decrypt(&keys.index_key, &envelope, &index_aad(user_id, &keys.vault_id))
            .map_err(|_| QGuardError::Crypto("vault index failed authentication (tampered or corrupted)".to_string()))?,
    );
    let index: StoreIndex = serde_json::from_slice(&plaintext)
        .map_err(|e| QGuardError::Storage(format!("vault index decode failed: {e}")))?;
    if index.version == 0 || index.version > INDEX_VERSION {
        return Err(QGuardError::Storage(format!(
            "vault index version {} is newer than this app — update QGuard Messaging",
            index.version
        )));
    }
    Ok(index)
}

pub fn save_index_at(path: &Path, keys: &StoreKeys, user_id: &str, index: &StoreIndex) -> Result<()> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(index).map_err(|e| QGuardError::Storage(format!("vault index encode failed: {e}")))?,
    );
    let envelope = symmetric::encrypt(&keys.index_key, &plaintext, &index_aad(user_id, &keys.vault_id))?;
    let mut bytes = Vec::with_capacity(INDEX_MAGIC.len() + 32 + NONCE_SIZE + TAG_SIZE + envelope.ciphertext.len());
    bytes.extend_from_slice(INDEX_MAGIC);
    bytes.extend_from_slice(&keys.vault_id);
    bytes.extend_from_slice(&envelope.nonce);
    bytes.extend_from_slice(&envelope.tag);
    bytes.extend_from_slice(&envelope.ciphertext);
    crate::state::write_atomic(path, &bytes).map_err(|e| io_err("write vault index", e))
}

// ---------------------------------------------------------------------------
// Thumbnails
// ---------------------------------------------------------------------------

pub fn seal_thumbnail(layout: &StoreLayout, keys: &StoreKeys, user_id: &str, entry_id: &str, image: &[u8]) -> Result<()> {
    if image.is_empty() || image.len() > MAX_THUMBNAIL_BYTES {
        return Err(QGuardError::InvalidInput("thumbnail is empty or too large".to_string()));
    }
    let detected = crate::vault::sniff::sniff(image, "thumbnail");
    if !matches!(detected.content_type.as_str(), "image/jpeg" | "image/png" | "image/webp") {
        return Err(QGuardError::InvalidInput("thumbnail must be a JPEG, PNG or WebP image".to_string()));
    }
    let id = checked_id(entry_id)?;
    let envelope = symmetric::encrypt(&keys.thumb_key, image, &thumb_aad(user_id, &id))?;
    let mut bytes = Vec::with_capacity(THUMB_MAGIC.len() + NONCE_SIZE + TAG_SIZE + envelope.ciphertext.len());
    bytes.extend_from_slice(THUMB_MAGIC);
    bytes.extend_from_slice(&envelope.nonce);
    bytes.extend_from_slice(&envelope.tag);
    bytes.extend_from_slice(&envelope.ciphertext);
    layout.ensure()?;
    crate::state::write_atomic(&layout.thumb_path(&id)?, &bytes).map_err(|e| io_err("write thumbnail", e))
}

pub fn open_thumbnail(layout: &StoreLayout, keys: &StoreKeys, user_id: &str, entry_id: &str) -> Result<Vec<u8>> {
    let id = checked_id(entry_id)?;
    let bytes = std::fs::read(layout.thumb_path(&id)?).map_err(|e| io_err("read thumbnail", e))?;
    let header = THUMB_MAGIC.len() + NONCE_SIZE + TAG_SIZE;
    if bytes.len() < header || &bytes[..THUMB_MAGIC.len()] != THUMB_MAGIC {
        return Err(QGuardError::Crypto("not a QGuard vault thumbnail".to_string()));
    }
    let offset = THUMB_MAGIC.len();
    let envelope = EncryptedEnvelope {
        nonce: bytes[offset..offset + NONCE_SIZE].to_vec(),
        tag: bytes[offset + NONCE_SIZE..header].to_vec(),
        ciphertext: bytes[header..].to_vec(),
    };
    symmetric::decrypt(&keys.thumb_key, &envelope, &thumb_aad(user_id, &id))
}

// ---------------------------------------------------------------------------
// Secure deletion
// ---------------------------------------------------------------------------

/// Destroy a stored container.
///
/// A v5 container's per-file key exists only inside its header, wrapped (to the
/// vault key and any recovery / enterprise recipient). Overwriting the header
/// with random bytes before unlinking therefore crypto-shreds the file: even a
/// copy of the chunk data recovered from the disk afterwards has no key left
/// anywhere. Flash storage may still keep stale blocks of the old header, which
/// is why this is "as secure as the operating system permits", not a promise.
pub fn shred_container(path: &Path) -> Result<()> {
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut prefix = [0u8; 12];
        let len = file.metadata()?.len();
        let header_end = if len >= 12 {
            file.read_exact(&mut prefix)?;
            let header_len = u32::from_be_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]) as u64;
            (12 + header_len).min(len)
        } else {
            len
        };
        file.seek(SeekFrom::Start(0))?;
        let mut remaining = header_end;
        let mut noise = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let step = remaining.min(noise.len() as u64) as usize;
            crate::crypto::provider::fill_random(&mut noise[..step]);
            file.write_all(&noise[..step])?;
            remaining -= step as u64;
        }
        file.sync_all()
    })();
    match result {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        // Shredding is best effort; the unlink below still has to happen.
        Err(_) => {}
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_err("delete vault object", error)),
    }
}

// ---------------------------------------------------------------------------
// Hashing adapters
// ---------------------------------------------------------------------------

/// `Read` adapter that hashes (SHA3-256) and counts everything read through it.
pub struct HashingReader<R> {
    inner: R,
    hasher: Sha3_256,
    bytes: u64,
}

impl<R: Read> HashingReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, hasher: Sha3_256::new(), bytes: 0 }
    }

    pub fn finish(self) -> (String, u64) {
        (hex::encode(self.hasher.finalize()), self.bytes)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
}

/// `Write` adapter that hashes (SHA3-256) and counts everything written through it.
pub struct HashingWriter<W> {
    inner: W,
    hasher: Sha3_256,
    bytes: u64,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, hasher: Sha3_256::new(), bytes: 0 }
    }

    pub fn finish(self) -> (W, String, u64) {
        (self.inner, hex::encode(self.hasher.finalize()), self.bytes)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// `Write` sink that refuses to grow past a limit (in-memory previews).
pub struct BoundedBuffer {
    pub bytes: Zeroizing<Vec<u8>>,
    limit: u64,
}

impl BoundedBuffer {
    pub fn new(limit: u64, expected: u64) -> Self {
        let capacity = expected.min(limit) as usize;
        Self { bytes: Zeroizing::new(Vec::with_capacity(capacity)), limit }
    }
}

impl Write for BoundedBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.bytes.len() as u64 + buf.len() as u64 > self.limit {
            return Err(io::Error::other("preview exceeds the in-memory limit"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Size of a file on disk, 0 when unreadable.
pub fn file_len(path: &Path) -> u64 {
    File::open(path).and_then(|f| f.metadata()).map(|m| m.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_layout() -> (StoreLayout, PathBuf) {
        let dir = std::env::temp_dir().join(format!("qguard-store-test-{}", uuid::Uuid::new_v4()));
        (StoreLayout::new(&dir, "user"), dir)
    }

    fn file_entry(index: &StoreIndex, parent: Option<&str>, name: &str, sha: &str) -> StoreEntry {
        let mut entry = index.get("missing").cloned().unwrap_or_else(|| StoreEntry {
            id: uuid::Uuid::new_v4().to_string(),
            kind: KIND_FILE.to_string(),
            name: name.to_string(),
            parent_id: parent.map(str::to_string),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            trashed_at: None,
            favorite: false,
            size_bytes: 3,
            stored_bytes: 100,
            content_type: "text/plain".to_string(),
            category: "document".to_string(),
            type_check: "match".to_string(),
            plaintext_sha3: sha.to_string(),
            container_version: 5,
            pin_bound: true,
            total_chunks: 1,
            recovery_protected: false,
            integrity: INTEGRITY_UNVERIFIED.to_string(),
            last_verified_at: None,
            has_thumbnail: false,
            cloud_object_id: None,
            cloud_backed_up_at: None,
            library_fek: None,
            available_offline: false,
            cloud_shared_only: false,
        });
        entry.name = name.to_string();
        entry
    }

    #[test]
    fn the_index_opens_only_under_the_vault_key_that_sealed_it() {
        let (layout, dir) = temp_layout();
        let keys = StoreKeys::derive(&symmetric::random_key()).unwrap();
        let mut index = StoreIndex::new();
        index.create_folder(None, "Tax returns 2026").unwrap();
        save_index(&layout, &keys, "user-a", &index).unwrap();

        // Names never appear on disk.
        let raw = std::fs::read(layout.index_path()).unwrap();
        assert!(!raw.windows(11).any(|w| w == b"Tax returns"));

        assert_eq!(load_index(&layout, &keys, "user-a").unwrap(), index);

        // Another account's AAD does not open it.
        assert!(load_index(&layout, &keys, "user-b").is_err());

        // A different vault key (a vault reset) is reported as foreign, not corrupt.
        let other = StoreKeys::derive(&symmetric::random_key()).unwrap();
        let error = load_index(&layout, &other, "user-a").unwrap_err().to_string();
        assert!(error.contains(FOREIGN_INDEX_MARKER), "{error}");

        // Any flipped byte in the ciphertext fails authentication.
        let mut tampered = raw.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        std::fs::write(layout.index_path(), &tampered).unwrap();
        assert!(load_index(&layout, &keys, "user-a").is_err());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_missing_index_is_an_empty_vault() {
        let (layout, dir) = temp_layout();
        let keys = StoreKeys::derive(&symmetric::random_key()).unwrap();
        assert_eq!(load_index(&layout, &keys, "u").unwrap().entries.len(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn thumbnails_are_sealed_and_bound_to_their_entry() {
        let (layout, dir) = temp_layout();
        let keys = StoreKeys::derive(&symmetric::random_key()).unwrap();
        let jpeg = b"\xFF\xD8\xFF\xE0\0\x10JFIF\0\x01thumb-bytes";
        let a = uuid::Uuid::new_v4().to_string();
        let b = uuid::Uuid::new_v4().to_string();
        seal_thumbnail(&layout, &keys, "u", &a, jpeg).unwrap();
        assert_eq!(open_thumbnail(&layout, &keys, "u", &a).unwrap(), jpeg.to_vec());
        // Moved onto another entry, it does not open.
        std::fs::copy(layout.thumb_path(&a).unwrap(), layout.thumb_path(&b).unwrap()).unwrap();
        assert!(open_thumbnail(&layout, &keys, "u", &b).is_err());
        // Only images are accepted as thumbnails.
        assert!(seal_thumbnail(&layout, &keys, "u", &a, b"%PDF-1.4 not an image").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ids_cannot_address_anything_outside_the_store() {
        let (layout, _dir) = temp_layout();
        assert!(layout.object_path("../../keys/user.device.enc").is_err());
        assert!(layout.object_path("..\\..\\x").is_err());
        assert!(layout.thumb_path("").is_err());
        let id = uuid::Uuid::new_v4().to_string();
        assert!(layout.object_path(&id).unwrap().starts_with(layout.objects_dir()));
    }

    #[test]
    fn names_are_cleaned_and_made_unique_per_folder() {
        assert_eq!(clean_name("  ../secret\\plan.pdf  ").unwrap(), ".._secret_plan.pdf");
        assert_eq!(clean_name("bad\u{0}name\n.txt").unwrap(), "badname.txt");
        assert!(clean_name("   ").is_err());
        assert!(clean_name("..").is_err());
        let long = format!("{}.pdf", "a".repeat(400));
        let cleaned = clean_name(&long).unwrap();
        assert_eq!(cleaned.chars().count(), MAX_NAME_CHARS);
        assert!(cleaned.ends_with(".pdf"));

        let mut index = StoreIndex::new();
        let folder = index.create_folder(None, "Photos").unwrap();
        assert_eq!(index.create_folder(None, "photos").unwrap().name, "photos (1)");
        let first = index.insert_file(file_entry(&index, Some(&folder.id), "a.jpg", "h1")).unwrap();
        let second = index.insert_file(file_entry(&index, Some(&folder.id), "A.jpg", "h2")).unwrap();
        assert_eq!(first.name, "a.jpg");
        assert_eq!(second.name, "A (1).jpg");
        // Same name in another folder is fine.
        assert_eq!(index.insert_file(file_entry(&index, None, "a.jpg", "h3")).unwrap().name, "a.jpg");
    }

    #[test]
    fn folders_cannot_be_moved_into_themselves_and_trash_cascades() {
        let mut index = StoreIndex::new();
        let outer = index.create_folder(None, "Outer").unwrap();
        let inner = index.create_folder(Some(&outer.id), "Inner").unwrap();
        let file = index.insert_file(file_entry(&index, Some(&inner.id), "doc.txt", "h")).unwrap();

        assert!(index.move_entry(&outer.id, Some(&inner.id)).is_err());
        assert!(index.move_entry(&outer.id, Some(&outer.id)).is_err());
        assert!(index.move_entry(&file.id, Some(&file.id)).is_err()); // not a folder

        index.trash(&outer.id).unwrap();
        assert!(index.in_trash(&file.id));
        let trashed: HashSet<String> = index.trashed_ids().into_iter().collect();
        assert_eq!(trashed.len(), 3);
        // Nothing can be put into, renamed or moved inside a trashed folder.
        assert!(index.create_folder(Some(&inner.id), "x").is_err());
        assert!(index.rename(&file.id, "y.txt").is_err());

        let mut sub: Vec<String> = index.subtree(&outer.id);
        sub.sort();
        let mut expected = vec![outer.id.clone(), inner.id.clone(), file.id.clone()];
        expected.sort();
        assert_eq!(sub, expected);
    }

    #[test]
    fn restore_falls_back_to_the_top_level_when_the_folder_is_gone() {
        let mut index = StoreIndex::new();
        let folder = index.create_folder(None, "Work").unwrap();
        let file = index.insert_file(file_entry(&index, Some(&folder.id), "plan.txt", "h")).unwrap();
        index.trash(&file.id).unwrap();
        index.trash(&folder.id).unwrap();
        let restored = index.restore(&file.id).unwrap();
        assert_eq!(restored.parent_id, None);
        assert!(!index.in_trash(&file.id));
        assert!(index.restore(&file.id).is_err()); // not in the trash any more
    }

    #[test]
    fn duplicates_are_found_by_content_hash_in_the_same_folder() {
        let mut index = StoreIndex::new();
        let file = index.insert_file(file_entry(&index, None, "a.txt", "same")).unwrap();
        assert_eq!(index.duplicate_in(None, "same").map(|e| e.id.clone()), Some(file.id.clone()));
        let folder = index.create_folder(None, "Other").unwrap();
        assert!(index.duplicate_in(Some(&folder.id), "same").is_none());
        index.trash(&file.id).unwrap();
        assert!(index.duplicate_in(None, "same").is_none());
    }

    #[test]
    fn folder_paths_are_reused_on_import() {
        let mut index = StoreIndex::new();
        let parts = vec!["Trip".to_string(), "Day 1".to_string()];
        let first = index.ensure_folder_path(None, &parts).unwrap();
        let second = index.ensure_folder_path(None, &parts).unwrap();
        assert_eq!(first, second);
        assert_eq!(index.entries.len(), 2);
        assert_eq!(index.breadcrumb(first.as_deref().unwrap()), vec!["Trip", "Day 1"]);
    }

    #[test]
    fn shredding_overwrites_the_header_before_deleting() {
        let (layout, dir) = temp_layout();
        layout.ensure().unwrap();
        let path = layout.object_path(&uuid::Uuid::new_v4().to_string()).unwrap();
        let mut bytes = b"QGUARDVS".to_vec();
        bytes.extend_from_slice(&5u32.to_be_bytes());
        bytes.extend_from_slice(b"HEADR");
        bytes.extend_from_slice(b"chunk-data");
        std::fs::write(&path, &bytes).unwrap();
        shred_container(&path).unwrap();
        assert!(!path.exists());
        // Deleting something already gone is not an error.
        shred_container(&path).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn hashing_adapters_agree_and_the_preview_buffer_is_bounded() {
        let data = vec![7u8; 10_000];
        let mut reader = HashingReader::new(io::Cursor::new(data.clone()));
        let mut sink = Vec::new();
        io::copy(&mut reader, &mut sink).unwrap();
        let (read_hash, read_len) = reader.finish();
        let mut writer = HashingWriter::new(Vec::new());
        writer.write_all(&data).unwrap();
        let (_, write_hash, write_len) = writer.finish();
        assert_eq!(read_hash, write_hash);
        assert_eq!(read_len, 10_000);
        assert_eq!(write_len, 10_000);

        let mut bounded = BoundedBuffer::new(100, 50);
        assert!(bounded.write_all(&[0u8; 100]).is_ok());
        assert!(bounded.write_all(&[0u8; 1]).is_err());
    }

    #[test]
    fn the_structure_digest_ignores_what_changes_on_every_open() {
        let mut index = StoreIndex::new();
        let file = index.insert_file(file_entry(&index, None, "a.txt", "h")).unwrap();
        let before = index.structure_digest();
        let target = index.get_mut(&file.id).unwrap();
        target.integrity = INTEGRITY_VERIFIED.to_string();
        target.last_verified_at = Some(Utc::now());
        target.has_thumbnail = true;
        index.log("verify", None, "a.txt", "", true);
        assert_eq!(index.structure_digest(), before);
        index.rename(&file.id, "b.txt").unwrap();
        assert_ne!(index.structure_digest(), before);
    }

    #[test]
    fn restored_files_get_their_folders_back() {
        let mut source = StoreIndex::new();
        let outer = source.create_folder(None, "Family").unwrap();
        let inner = source.create_folder(Some(&outer.id), "2026").unwrap();
        let file = source.insert_file(file_entry(&source, Some(&inner.id), "photo.jpg", "h")).unwrap();

        let mut here = StoreIndex::new();
        here.create_folder(None, "Family").unwrap(); // same name, different folder
        let parent = here.adopt_ancestors(&source, &file.id).unwrap();
        assert_eq!(parent.as_deref(), Some(inner.id.as_str()));
        assert_eq!(here.breadcrumb(&inner.id), vec!["Family (1)", "2026"]);
        // A second file from the same folder reuses it.
        assert_eq!(here.adopt_ancestors(&source, &file.id).unwrap().as_deref(), Some(inner.id.as_str()));
        assert_eq!(here.entries.iter().filter(|e| e.is_folder()).count(), 3);
    }

    #[test]
    fn activity_is_capped_newest_first() {
        let mut index = StoreIndex::new();
        for n in 0..(MAX_ACTIVITY + 10) {
            index.log("import", None, &format!("f{n}"), "", true);
        }
        assert_eq!(index.activity.len(), MAX_ACTIVITY);
        assert_eq!(index.activity[0].name, format!("f{}", MAX_ACTIVITY + 9));
    }
}
