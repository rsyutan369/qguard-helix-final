//! The account library (Quantum Vault phase 3): one Vault Storage across every
//! vault-enabled device of an account.
//!
//! Each device keeps its own vault key (PIN-bound, never shared) and its own
//! copy of every file it holds. What the devices share is a LIBRARY KEY — a
//! random 256-bit key per epoch, held only inside each device's vault index
//! (so only while that vault is unlocked) — and, in the cloud, one LIBRARY
//! DOCUMENT sealed under it:
//!
//! * the folder tree and the shared metadata of every backed-up file (name,
//!   folder, trash state, favourite, type, size, content hash, cloud object);
//! * for each file, its per-file key sealed under the library key
//!   ([`SealedFek`]) — how another device opens the cloud copy;
//! * tombstones, so a permanent delete on one device reaches the others.
//!
//! Keys are separate by purpose: file content keeps its per-file key; the
//! document, the file-key wraps and the recovery copy of the ring each use their
//! own HKDF-SHA3-256 label off the epoch key; nothing here is the vault key, a
//! device identity key or the recovery key.
//!
//! How a device gets the ring:
//!  * sealed to it by another of the account's devices that it has pinned
//!    (hybrid X25519 + ML-KEM-1024 + dual signature, see
//!    `commands::vault_library`) — the device was approved in the Device Trust
//!    Center first;
//!  * or from the copy sealed under the account's recovery key.
//!
//! Removing a device starts a new epoch the removed device never receives;
//! every file-key wrap is moved to it, so the next document is unreadable to
//! that device. What it already downloaded stays with it.
//!
//! Merging two views of the library is last-writer-wins per entry on the shared
//! fields (files themselves never change once stored, so there is no content
//! conflict), deletions win over older edits, and the tree is repaired after
//! every merge: missing or trashed parents and cycles send an entry to the top
//! level, and clashing names get a " (n)" suffix rather than one replacing
//! another.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use crate::crypto::provider::Sha3_256Hasher as Sha3_256;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::kdf;
use crate::crypto::symmetric::{self, KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use crate::crypto::EncryptedEnvelope;
use crate::error::{QGuardError, Result};
use crate::vault::store::{StoreEntry, StoreIndex};

const DOC_MAGIC: &[u8; 8] = b"QGVLIB01";
const DOC_KEY_INFO: &[u8] = b"QGuard-VaultLibrary-Document-v1";
const FEK_KEY_INFO: &[u8] = b"QGuard-VaultLibrary-FileKey-v1";
const RECOVERY_KEY_INFO: &[u8] = b"QGuard-VaultLibrary-RecoveryRing-v1";
pub const MAX_EPOCHS: usize = 256;
/// Deletions are remembered this long; a device offline for longer than this
/// re-learns a deleted file as present (it never loses one it still has).
pub const TOMBSTONE_DAYS: i64 = 180;
const MAX_DOC_BYTES: usize = 256 * 1024 * 1024;

/// Stable prefix of the error when this device lacks the epoch a document or a
/// file-key wrap was sealed under.
pub const LIBRARY_KEY_MISSING: &str = "LIBRARY_KEY_MISSING";

// ---------------------------------------------------------------------------
// Ring
// ---------------------------------------------------------------------------

#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LibraryRing {
    pub current: u32,
    pub keys: BTreeMap<u32, [u8; KEY_SIZE]>,
}

impl std::fmt::Debug for LibraryRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LibraryRing").field("current", &self.current).field("epochs", &self.keys.keys().collect::<Vec<_>>()).finish()
    }
}

impl Drop for LibraryRing {
    fn drop(&mut self) {
        for key in self.keys.values_mut() {
            key.zeroize();
        }
    }
}

impl LibraryRing {
    pub fn generate() -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(1, symmetric::random_key());
        Self { current: 1, keys }
    }

    pub fn check(&self) -> Result<()> {
        if self.keys.is_empty() || self.keys.len() > MAX_EPOCHS || !self.keys.contains_key(&self.current) {
            return Err(QGuardError::Crypto("library key ring is inconsistent".to_string()));
        }
        Ok(())
    }

    pub fn key(&self, epoch: u32) -> Result<&[u8; KEY_SIZE]> {
        self.keys
            .get(&epoch)
            .ok_or_else(|| QGuardError::Trust(format!("{LIBRARY_KEY_MISSING}: this device does not hold library key epoch {epoch}")))
    }

    /// Start a new epoch (after a device is removed).
    pub fn rotate(&mut self) -> Result<u32> {
        if self.keys.len() >= MAX_EPOCHS {
            return Err(QGuardError::InvalidInput("too many library key epochs".to_string()));
        }
        let next = self.current.checked_add(1).ok_or_else(|| QGuardError::InvalidInput("library key epoch overflow".to_string()))?;
        self.keys.insert(next, symmetric::random_key());
        self.current = next;
        Ok(next)
    }

    /// Take in epochs from another copy. Two different keys for one epoch mean
    /// two devices each started that epoch: refused, never merged silently.
    pub fn absorb(&mut self, incoming: &LibraryRing) -> Result<bool> {
        incoming.check()?;
        let mut changed = false;
        for (epoch, key) in &incoming.keys {
            match self.keys.get(epoch) {
                Some(existing) if existing != key => {
                    return Err(QGuardError::Trust(format!(
                        "LIBRARY_EPOCH_CONFLICT: two different library keys exist for epoch {epoch}"
                    )))
                }
                Some(_) => {}
                None => {
                    self.keys.insert(*epoch, *key);
                    changed = true;
                }
            }
        }
        if incoming.current > self.current {
            self.current = incoming.current;
            changed = true;
        }
        self.check()?;
        Ok(changed)
    }
}

fn derived(ring: &LibraryRing, epoch: u32, info: &[u8]) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    Ok(Zeroizing::new(kdf::derive_32(ring.key(epoch)?, info)?))
}

// ---------------------------------------------------------------------------
// Per-file key wraps
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SealedFek {
    pub epoch: u32,
    pub envelope: EncryptedEnvelope,
}

fn fek_aad(user_id: &str, file_id: &str, epoch: u32) -> Vec<u8> {
    format!("QGVL-FEK-v1|{user_id}|{file_id}|{epoch}").into_bytes()
}

pub fn wrap_fek(ring: &LibraryRing, user_id: &str, file_id: &str, fek: &[u8; KEY_SIZE]) -> Result<SealedFek> {
    let epoch = ring.current;
    let key = derived(ring, epoch, FEK_KEY_INFO)?;
    Ok(SealedFek { epoch, envelope: symmetric::encrypt(&key, fek, &fek_aad(user_id, file_id, epoch))? })
}

pub fn unwrap_fek(ring: &LibraryRing, user_id: &str, file_id: &str, sealed: &SealedFek) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let key = derived(ring, sealed.epoch, FEK_KEY_INFO)?;
    let bytes = Zeroizing::new(symmetric::decrypt(&key, &sealed.envelope, &fek_aad(user_id, file_id, sealed.epoch))?);
    if bytes.len() != KEY_SIZE {
        return Err(QGuardError::Crypto("library file key is malformed".to_string()));
    }
    let mut out = Zeroizing::new([0u8; KEY_SIZE]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Move every file-key wrap in `index` to the ring's current epoch.
pub fn rewrap_all_feks(ring: &LibraryRing, user_id: &str, index: &mut StoreIndex) -> Result<u64> {
    let mut moved = 0;
    for entry in index.entries.iter_mut() {
        if let Some(sealed) = entry.library_fek.as_ref() {
            if sealed.epoch != ring.current {
                let fek = unwrap_fek(ring, user_id, &entry.id, sealed)?;
                entry.library_fek = Some(wrap_fek(ring, user_id, &entry.id, &fek)?);
                moved += 1;
            }
        }
    }
    Ok(moved)
}

// ---------------------------------------------------------------------------
// Library document
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Tombstone {
    pub id: String,
    pub deleted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LibraryDoc {
    pub version: u8,
    pub entries: Vec<StoreEntry>,
    pub tombstones: Vec<Tombstone>,
}

/// This device's part in the library, kept in its sealed vault index.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LibraryState {
    #[serde(default)]
    pub ring: Option<LibraryRing>,
    /// Server revision of the document this device last merged or published.
    #[serde(default)]
    pub revision: u64,
    /// [`doc_digest`] of what this device last published or merged to.
    #[serde(default)]
    pub published_digest: Option<String>,
    /// Permanent deletions made here, until they are published (and kept for
    /// [`TOMBSTONE_DAYS`] like those learned from other devices).
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
    /// Newest epoch whose recovery-key copy this device has stored in the cloud.
    #[serde(default)]
    pub recovery_epoch: u32,
    #[serde(default)]
    pub last_merge_at: Option<DateTime<Utc>>,
}

/// An entry is part of the shared library when it is a folder or a file with
/// a cloud backup; a file that was never backed up stays on its device, and
/// so does one whose cloud copy exists only so it could be shared.
fn shared(entry: &StoreEntry) -> bool {
    entry.is_folder() || (entry.cloud_object_id.is_some() && !entry.cloud_shared_only)
}

/// The shared view of a device's index: device-local fields cleared.
pub fn build_doc(index: &StoreIndex) -> LibraryDoc {
    let entries = index
        .entries
        .iter()
        .filter(|e| shared(e))
        .map(|e| StoreEntry {
            integrity: String::new(),
            last_verified_at: None,
            has_thumbnail: false,
            available_offline: false,
            cloud_shared_only: false,
            ..e.clone()
        })
        .collect();
    LibraryDoc { version: 1, entries, tombstones: index.library.tombstones.clone() }
}

/// Order-independent digest of a document: what decides whether there is
/// anything new to publish.
pub fn doc_digest(doc: &LibraryDoc) -> String {
    let mut entries: Vec<&StoreEntry> = doc.entries.iter().collect();
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    let mut tombstones: Vec<&Tombstone> = doc.tombstones.iter().collect();
    tombstones.sort_by(|a, b| a.id.cmp(&b.id));
    let mut hasher = Sha3_256::new();
    for entry in entries {
        // The FEK wrap's nonce differs per wrap; its epoch is what matters.
        let row = serde_json::json!([
            entry.id, entry.kind, entry.name, entry.parent_id, entry.trashed_at, entry.favorite, entry.updated_at,
            entry.cloud_object_id, entry.library_fek.as_ref().map(|s| s.epoch), entry.plaintext_sha3,
        ]);
        hasher.update(row.to_string().as_bytes());
        hasher.update(b"\n");
    }
    for tomb in tombstones {
        hasher.update(format!("tomb|{}|{}\n", tomb.id, tomb.deleted_at.timestamp_millis()).as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn doc_aad(user_id: &str, epoch: u32) -> Vec<u8> {
    let mut aad = DOC_MAGIC.to_vec();
    aad.extend_from_slice(format!("|{user_id}|{epoch}").as_bytes());
    aad
}

/// `QGVLIB01 | epoch (u32 BE) | nonce | tag | AES-256-GCM(JSON)`.
pub fn seal_doc(ring: &LibraryRing, user_id: &str, doc: &LibraryDoc) -> Result<Vec<u8>> {
    let epoch = ring.current;
    let key = derived(ring, epoch, DOC_KEY_INFO)?;
    let plain = Zeroizing::new(serde_json::to_vec(doc).map_err(|e| QGuardError::Storage(format!("library encode: {e}")))?);
    let env = symmetric::encrypt(&key, &plain, &doc_aad(user_id, epoch))?;
    let mut out = Vec::with_capacity(DOC_MAGIC.len() + 4 + NONCE_SIZE + TAG_SIZE + env.ciphertext.len());
    out.extend_from_slice(DOC_MAGIC);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&env.nonce);
    out.extend_from_slice(&env.tag);
    out.extend_from_slice(&env.ciphertext);
    Ok(out)
}

pub fn open_doc(ring: &LibraryRing, user_id: &str, bytes: &[u8]) -> Result<LibraryDoc> {
    let head = DOC_MAGIC.len() + 4 + NONCE_SIZE + TAG_SIZE;
    if bytes.len() < head || &bytes[..DOC_MAGIC.len()] != DOC_MAGIC || bytes.len() > MAX_DOC_BYTES {
        return Err(QGuardError::Crypto("not a QGuard vault library document".to_string()));
    }
    let mut epoch_bytes = [0u8; 4];
    epoch_bytes.copy_from_slice(&bytes[8..12]);
    let epoch = u32::from_be_bytes(epoch_bytes);
    let key = derived(ring, epoch, DOC_KEY_INFO)?;
    let env = EncryptedEnvelope {
        nonce: bytes[12..12 + NONCE_SIZE].to_vec(),
        tag: bytes[12 + NONCE_SIZE..head].to_vec(),
        ciphertext: bytes[head..].to_vec(),
    };
    let plain = Zeroizing::new(
        symmetric::decrypt(&key, &env, &doc_aad(user_id, epoch))
            .map_err(|_| QGuardError::Crypto("library document failed authentication".to_string()))?,
    );
    let doc: LibraryDoc = serde_json::from_slice(&plain).map_err(|e| QGuardError::Storage(format!("library decode: {e}")))?;
    if doc.version != 1 {
        return Err(QGuardError::Storage("library document version is newer than this app".to_string()));
    }
    Ok(doc)
}

// ---------------------------------------------------------------------------
// Recovery copy of the ring
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RecoveryRingEnvelope {
    pub v: u8,
    pub epoch: u32,
    pub sealed: EncryptedEnvelope,
}

fn recovery_aad(user_id: &str, epoch: u32) -> Vec<u8> {
    format!("QGVL-RecoveryRing-v1|{user_id}|{epoch}").into_bytes()
}

pub fn seal_ring_for_recovery(ring: &LibraryRing, recovery_wrap_key: &[u8; KEY_SIZE], user_id: &str) -> Result<RecoveryRingEnvelope> {
    ring.check()?;
    let key = Zeroizing::new(kdf::derive_32(recovery_wrap_key, RECOVERY_KEY_INFO)?);
    let plain = Zeroizing::new(serde_json::to_vec(ring).map_err(|e| QGuardError::Storage(format!("library ring encode: {e}")))?);
    Ok(RecoveryRingEnvelope { v: 1, epoch: ring.current, sealed: symmetric::encrypt(&key, &plain, &recovery_aad(user_id, ring.current))? })
}

pub fn open_ring_from_recovery(envelope: &RecoveryRingEnvelope, recovery_wrap_key: &[u8; KEY_SIZE], user_id: &str) -> Result<LibraryRing> {
    if envelope.v != 1 {
        return Err(QGuardError::InvalidInput("unsupported library recovery envelope".to_string()));
    }
    let key = Zeroizing::new(kdf::derive_32(recovery_wrap_key, RECOVERY_KEY_INFO)?);
    let plain = Zeroizing::new(
        symmetric::decrypt(&key, &envelope.sealed, &recovery_aad(user_id, envelope.epoch))
            .map_err(|_| QGuardError::Trust("This recovery key does not open your vault library.".to_string()))?,
    );
    let ring: LibraryRing = serde_json::from_slice(&plain).map_err(|_| QGuardError::Crypto("library recovery envelope holds no key ring".to_string()))?;
    ring.check()?;
    if ring.current != envelope.epoch {
        return Err(QGuardError::Crypto("library recovery envelope epoch mismatch".to_string()));
    }
    Ok(ring)
}

// ---------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MergeReport {
    pub added: u64,
    pub updated: u64,
    /// Entries removed here because another device deleted them permanently.
    pub removed: Vec<String>,
    /// Entries renamed or moved to the top level to keep the tree valid.
    pub repaired: u64,
}

fn prune(tombstones: &mut Vec<Tombstone>, now: DateTime<Utc>) {
    let horizon = now - Duration::days(TOMBSTONE_DAYS);
    tombstones.retain(|t| t.deleted_at > horizon);
    let mut seen: HashMap<String, DateTime<Utc>> = HashMap::new();
    for t in tombstones.iter() {
        let at = seen.entry(t.id.clone()).or_insert(t.deleted_at);
        if t.deleted_at > *at {
            *at = t.deleted_at;
        }
    }
    *tombstones = seen.into_iter().map(|(id, deleted_at)| Tombstone { id, deleted_at }).collect();
    tombstones.sort_by(|a, b| a.id.cmp(&b.id));
}

/// Merge the cloud document into this device's index. Pure: the caller removes
/// the encrypted objects of `report.removed` from disk.
pub fn merge(index: &mut StoreIndex, remote: &LibraryDoc, now: DateTime<Utc>) -> MergeReport {
    let mut report = MergeReport::default();

    // Deletions known anywhere.
    let mut tombstones = index.library.tombstones.clone();
    tombstones.extend(remote.tombstones.iter().cloned());
    prune(&mut tombstones, now);
    let deleted: HashMap<&str, DateTime<Utc>> = tombstones.iter().map(|t| (t.id.as_str(), t.deleted_at)).collect();

    // A deletion wins over every edit older than it; an edit made after the
    // deletion (on a device that had not seen it yet) keeps the entry alive.
    let mut doomed: HashSet<String> = HashSet::new();
    for entry in &index.entries {
        if let Some(at) = deleted.get(entry.id.as_str()) {
            if entry.updated_at <= *at {
                doomed.insert(entry.id.clone());
            }
        }
    }
    // Everything inside a deleted folder goes with it.
    let roots: Vec<String> = doomed.iter().cloned().collect();
    for root in roots {
        doomed.extend(index.subtree(&root));
    }
    report.removed = index.entries.iter().filter(|e| doomed.contains(&e.id)).map(|e| e.id.clone()).collect();
    report.removed.sort();
    index.entries.retain(|e| !doomed.contains(&e.id));

    // Shared entries from the other devices.
    let positions: HashMap<String, usize> = index.entries.iter().enumerate().map(|(i, e)| (e.id.clone(), i)).collect();
    for incoming in &remote.entries {
        if let Some(at) = deleted.get(incoming.id.as_str()) {
            if incoming.updated_at <= *at {
                continue;
            }
        }
        match positions.get(&incoming.id) {
            None => {
                index.entries.push(StoreEntry {
                    integrity: String::new(),
                    last_verified_at: None,
                    has_thumbnail: false,
                    available_offline: false,
                    cloud_shared_only: false,
                    ..incoming.clone()
                });
                report.added += 1;
            }
            Some(&position) => {
                let local = &mut index.entries[position];
                let mut changed = false;
                if incoming.updated_at > local.updated_at {
                    local.name = incoming.name.clone();
                    local.parent_id = incoming.parent_id.clone();
                    local.trashed_at = incoming.trashed_at;
                    local.favorite = incoming.favorite;
                    local.updated_at = incoming.updated_at;
                    changed = true;
                }
                if local.cloud_object_id.is_none() && incoming.cloud_object_id.is_some() {
                    local.cloud_object_id = incoming.cloud_object_id.clone();
                    local.cloud_backed_up_at = incoming.cloud_backed_up_at;
                    changed = true;
                }
                let newer_wrap = match (&local.library_fek, &incoming.library_fek) {
                    (None, Some(_)) => true,
                    (Some(mine), Some(theirs)) => theirs.epoch > mine.epoch,
                    _ => false,
                };
                if newer_wrap {
                    local.library_fek = incoming.library_fek.clone();
                    changed = true;
                }
                if changed {
                    report.updated += 1;
                }
            }
        }
    }

    // Tombstones of entries that survived (edited after the delete) are dropped.
    let alive: HashSet<&str> = index.entries.iter().map(|e| e.id.as_str()).collect();
    tombstones.retain(|t| !alive.contains(t.id.as_str()));
    index.library.tombstones = tombstones;

    report.repaired = repair_tree(index);
    index.library.last_merge_at = Some(now);
    report
}

/// Make the tree valid again after a merge. Returns how many entries changed.
pub fn repair_tree(index: &mut StoreIndex) -> u64 {
    let mut repaired = 0;
    let folders: HashSet<String> = index.entries.iter().filter(|e| e.is_folder()).map(|e| e.id.clone()).collect();
    let parents: HashMap<String, Option<String>> = index.entries.iter().map(|e| (e.id.clone(), e.parent_id.clone())).collect();

    // Parents that are gone, not folders, or loop back: top level.
    let mut orphaned: Vec<String> = Vec::new();
    for entry in &index.entries {
        let Some(parent) = entry.parent_id.as_ref() else { continue };
        if !folders.contains(parent) {
            orphaned.push(entry.id.clone());
            continue;
        }
        let mut seen: HashSet<&str> = HashSet::new();
        seen.insert(entry.id.as_str());
        let mut current = Some(parent.as_str());
        while let Some(id) = current {
            if !seen.insert(id) {
                orphaned.push(entry.id.clone());
                break;
            }
            current = parents.get(id).and_then(|p| p.as_deref());
        }
    }
    for id in orphaned {
        if let Some(entry) = index.get_mut(&id) {
            entry.parent_id = None;
            repaired += 1;
        }
    }

    // Names that clash among the live items of one folder: the older entry keeps
    // its name, the later ones are numbered.
    let mut order: Vec<(Option<String>, String, DateTime<Utc>, String)> = index
        .entries
        .iter()
        .filter(|e| e.trashed_at.is_none())
        .map(|e| (e.parent_id.clone(), e.name.to_lowercase(), e.created_at, e.id.clone()))
        .collect();
    order.sort_by(|a, b| (&a.0, &a.1, a.2, &a.3).cmp(&(&b.0, &b.1, b.2, &b.3)));
    let mut previous: Option<(Option<String>, String)> = None;
    let mut clashing: Vec<String> = Vec::new();
    for (parent, name, _, id) in order {
        let key = (parent, name);
        if previous.as_ref() == Some(&key) {
            clashing.push(id);
        } else {
            previous = Some(key);
        }
    }
    for id in clashing {
        let Some(entry) = index.get(&id).cloned() else { continue };
        let name = index.unique_name(entry.parent_id.as_deref(), &entry.name, entry.is_folder(), Some(&id));
        if let Some(target) = index.get_mut(&id) {
            target.name = name;
            repaired += 1;
        }
    }
    repaired
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::store::{StoreIndex, KIND_FILE, KIND_FOLDER};

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + seconds, 0).unwrap()
    }

    fn entry(id: &str, kind: &str, name: &str, parent: Option<&str>, updated: i64) -> StoreEntry {
        StoreEntry {
            id: id.to_string(),
            kind: kind.to_string(),
            name: name.to_string(),
            parent_id: parent.map(str::to_string),
            created_at: at(0),
            updated_at: at(updated),
            trashed_at: None,
            favorite: false,
            size_bytes: 1,
            stored_bytes: 2,
            content_type: "text/plain".to_string(),
            category: "document".to_string(),
            type_check: "match".to_string(),
            plaintext_sha3: "h".to_string(),
            container_version: 5,
            pin_bound: true,
            total_chunks: 1,
            recovery_protected: true,
            integrity: "verified".to_string(),
            last_verified_at: Some(at(1)),
            has_thumbnail: true,
            cloud_object_id: if kind == KIND_FILE { Some(format!("obj-{id}")) } else { None },
            cloud_backed_up_at: None,
            library_fek: None,
            available_offline: true,
            cloud_shared_only: false,
        }
    }

    fn index_with(entries: Vec<StoreEntry>) -> StoreIndex {
        let mut index = StoreIndex::new();
        index.entries = entries;
        index
    }

    #[test]
    fn the_ring_rotates_absorbs_and_refuses_conflicts() {
        let mut a = LibraryRing::generate();
        let mut b = a.clone();
        assert!(!b.absorb(&a).unwrap());
        a.rotate().unwrap();
        assert!(b.absorb(&a).unwrap());
        assert_eq!(b.current, 2);
        // A different key for an epoch both claim is a conflict, not a merge.
        let mut c = a.clone();
        c.keys.insert(2, symmetric::random_key());
        assert!(b.absorb(&c).unwrap_err().to_string().contains("LIBRARY_EPOCH_CONFLICT"));
    }

    #[test]
    fn file_keys_open_only_for_their_file_account_and_epoch() {
        let mut ring = LibraryRing::generate();
        let fek = symmetric::random_key();
        let sealed = wrap_fek(&ring, "u", "f1", &fek).unwrap();
        assert_eq!(*unwrap_fek(&ring, "u", "f1", &sealed).unwrap(), fek);
        assert!(unwrap_fek(&ring, "u", "f2", &sealed).is_err());
        assert!(unwrap_fek(&ring, "other", "f1", &sealed).is_err());
        // A device without the epoch says so.
        let stranger = LibraryRing::generate();
        assert!(unwrap_fek(&stranger, "u", "f1", &sealed).is_err());
        let missing = SealedFek { epoch: 9, envelope: sealed.envelope.clone() };
        assert!(unwrap_fek(&ring, "u", "f1", &missing).unwrap_err().to_string().contains(LIBRARY_KEY_MISSING));

        // Rotation moves every wrap; the old epoch still opens old copies.
        let mut index = index_with(vec![StoreEntry { library_fek: Some(sealed.clone()), ..entry("f1", KIND_FILE, "a", None, 0) }]);
        ring.rotate().unwrap();
        assert_eq!(rewrap_all_feks(&ring, "u", &mut index).unwrap(), 1);
        let moved = index.entries[0].library_fek.clone().unwrap();
        assert_eq!(moved.epoch, 2);
        assert_eq!(*unwrap_fek(&ring, "u", "f1", &moved).unwrap(), fek);
        // A device left on epoch 1 cannot open the moved wrap.
        let mut left_behind = ring.clone();
        left_behind.keys.remove(&2);
        left_behind.current = 1;
        assert!(unwrap_fek(&left_behind, "u", "f1", &moved).is_err());
    }

    #[test]
    fn the_document_opens_only_with_the_ring_and_account_and_carries_no_device_state() {
        let ring = LibraryRing::generate();
        let index = index_with(vec![
            entry("folder", KIND_FOLDER, "Taxes", None, 0),
            entry("file", KIND_FILE, "return.pdf", Some("folder"), 0),
            StoreEntry { cloud_object_id: None, ..entry("local", KIND_FILE, "never-backed-up.txt", None, 0) },
            StoreEntry { cloud_shared_only: true, ..entry("shared", KIND_FILE, "shared-not-backed-up.txt", None, 0) },
        ]);
        let doc = build_doc(&index);
        assert_eq!(doc.entries.len(), 2, "a file without a cloud backup stays on its device");
        assert!(doc.entries.iter().all(|e| e.integrity.is_empty() && !e.has_thumbnail && e.last_verified_at.is_none()));
        let sealed = seal_doc(&ring, "u", &doc).unwrap();
        assert!(!sealed.windows(5).any(|w| w == b"Taxes"));
        assert_eq!(open_doc(&ring, "u", &sealed).unwrap(), doc);
        assert!(open_doc(&ring, "other", &sealed).is_err());
        assert!(open_doc(&LibraryRing::generate(), "u", &sealed).is_err());
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open_doc(&ring, "u", &tampered).is_err());
    }

    #[test]
    fn the_recovery_copy_of_the_ring_opens_only_with_the_recovery_key() {
        let ring = LibraryRing::generate();
        let wrap_key = symmetric::random_key();
        let envelope = seal_ring_for_recovery(&ring, &wrap_key, "u").unwrap();
        assert_eq!(open_ring_from_recovery(&envelope, &wrap_key, "u").unwrap(), ring);
        assert!(open_ring_from_recovery(&envelope, &symmetric::random_key(), "u").is_err());
        assert!(open_ring_from_recovery(&envelope, &wrap_key, "someone-else").is_err());
    }

    #[test]
    fn merge_adds_updates_by_newest_edit_and_keeps_device_state() {
        let mut here = index_with(vec![
            entry("a", KIND_FILE, "a-local-newer.txt", None, 50),
            entry("b", KIND_FILE, "b-old.txt", None, 10),
        ]);
        let remote = LibraryDoc {
            version: 1,
            entries: vec![
                entry("a", KIND_FILE, "a-remote-older.txt", None, 40),
                entry("b", KIND_FILE, "b-renamed-elsewhere.txt", None, 20),
                entry("c", KIND_FILE, "c-new.txt", None, 5),
            ],
            tombstones: vec![],
        };
        let report = merge(&mut here, &remote, at(100));
        assert_eq!((report.added, report.updated), (1, 1));
        assert_eq!(here.get("a").unwrap().name, "a-local-newer.txt");
        assert_eq!(here.get("b").unwrap().name, "b-renamed-elsewhere.txt");
        // Device-local state survives an update; new entries start without it.
        assert_eq!(here.get("b").unwrap().integrity, "verified");
        let c = here.get("c").unwrap();
        assert!(c.integrity.is_empty() && !c.has_thumbnail && !c.available_offline);
    }

    #[test]
    fn deletions_win_over_older_edits_and_take_folder_contents_with_them() {
        let mut here = index_with(vec![
            entry("dir", KIND_FOLDER, "Old", None, 0),
            entry("inside", KIND_FILE, "x.txt", Some("dir"), 0),
            entry("edited", KIND_FILE, "renamed-after-delete.txt", None, 90),
            StoreEntry { cloud_object_id: None, ..entry("local", KIND_FILE, "unshared.txt", None, 0) },
        ]);
        let remote = LibraryDoc {
            version: 1,
            entries: vec![],
            tombstones: vec![
                Tombstone { id: "dir".to_string(), deleted_at: at(30) },
                Tombstone { id: "edited".to_string(), deleted_at: at(60) },
            ],
        };
        let report = merge(&mut here, &remote, at(100));
        assert_eq!(report.removed, vec!["dir".to_string(), "inside".to_string()]);
        assert!(here.get("edited").is_some(), "an edit made after the delete keeps the file");
        assert!(here.get("local").is_some());
        assert_eq!(here.library.tombstones.len(), 1, "only the honoured deletion is remembered");
        // A deleted entry is not re-added from a stale remote copy.
        let stale = LibraryDoc { version: 1, entries: vec![entry("dir", KIND_FOLDER, "Old", None, 0)], tombstones: vec![] };
        merge(&mut here, &stale, at(101));
        assert!(here.get("dir").is_none());
    }

    #[test]
    fn the_tree_is_repaired_after_concurrent_moves_and_name_clashes() {
        // Device 1 moved X into Y while device 2 moved Y into X: a cycle.
        let mut here = index_with(vec![
            entry("x", KIND_FOLDER, "X", Some("y"), 10),
            entry("y", KIND_FOLDER, "Y", Some("x"), 10),
            entry("orphan", KIND_FILE, "lost.txt", Some("gone"), 0),
            entry("n1", KIND_FILE, "Report.pdf", None, 0),
            StoreEntry { created_at: at(5), ..entry("n2", KIND_FILE, "report.pdf", None, 0) },
        ]);
        let repaired = repair_tree(&mut here);
        assert!(repaired >= 3);
        assert!(here.get("x").unwrap().parent_id.is_none() || here.get("y").unwrap().parent_id.is_none());
        assert!(here.get("orphan").unwrap().parent_id.is_none());
        assert_eq!(here.get("n1").unwrap().name, "Report.pdf");
        assert_eq!(here.get("n2").unwrap().name, "report (1).pdf");
    }

    #[test]
    fn the_digest_ignores_order_and_device_state_but_not_edits() {
        let index = index_with(vec![entry("a", KIND_FILE, "a", None, 0), entry("b", KIND_FILE, "b", None, 0)]);
        let doc = build_doc(&index);
        let mut reversed = doc.clone();
        reversed.entries.reverse();
        assert_eq!(doc_digest(&doc), doc_digest(&reversed));
        let mut edited = doc.clone();
        edited.entries[0].name = "renamed".to_string();
        assert_ne!(doc_digest(&doc), doc_digest(&edited));
        let mut deleted = doc.clone();
        deleted.tombstones.push(Tombstone { id: "z".to_string(), deleted_at: at(1) });
        assert_ne!(doc_digest(&doc), doc_digest(&deleted));
    }
}
