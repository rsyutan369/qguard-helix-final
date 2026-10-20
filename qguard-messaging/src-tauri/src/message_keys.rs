//! Per-message key ledger: what lets old prekeys be destroyed.
//!
//! WHY THIS EXISTS
//! ---------------------------------------------------------------------------
//! Every Secure Chat envelope is sealed with a fresh hybrid encapsulation to
//! the recipient device's signed prekey. Message history is not stored locally;
//! it is re-fetched from the relay and decrypted again whenever a conversation
//! is opened. Put together, that meant the device had to keep EVERY prekey it
//! ever published, forever — discarding one made the history sealed to it
//! unreadable. So a single copy of the device's key file decrypted every
//! message ever sent to it: there was no forward secrecy at all, whatever the
//! labels said.
//!
//! This ledger breaks that dependency. The first time an envelope is opened,
//! the 32-byte AES key that opened it is remembered here (encrypted at rest
//! under the device storage key, like the rest of the key material). From then
//! on that envelope opens from the ledger and no longer needs its prekey — so
//! prekeys can be rotated on a schedule and the retired ones destroyed once
//! everything sealed to them is accounted for (see `commands::keys`).
//!
//! WHAT THAT BUYS, STATED EXACTLY
//! ---------------------------------------------------------------------------
//!   * A prekey that has been destroyed cannot decrypt anything: traffic
//!     recorded off the relay from its epoch is no longer opened by any key
//!     this device holds, except message by message through this ledger.
//!   * Deleting a message deletes its entry — the ciphertext on the relay is
//!     then permanently undecryptable by this device.
//!   * It is NOT a ratchet. Messages sealed to the prekey that is active right
//!     now share that one key until the next rotation, and a device compromise
//!     reveals whatever is still in the ledger. Forward secrecy here is
//!     per-rotation-epoch, not per-message.
//!
//! The ledger never holds plaintext, only keys, and it is purely additive on
//! the read path: a missing or unreadable ledger degrades to exactly the old
//! behaviour (open with the prekey), never to an unreadable message.

use std::collections::HashMap;

use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::kdf::sha3_256;
use crate::crypto::symmetric::KEY_SIZE;
use crate::error::{QGuardError, Result};

/// Envelope ids are chosen by the sender. Anything longer than this is not a
/// message id this app ever produced (they are UUIDs) and is simply not cached.
pub const MAX_MESSAGE_ID_LEN: usize = 128;

/// How many new keys may sit in memory before the ledger is written out. A
/// crash loses at most this many entries, which costs nothing but a repeat
/// prekey decrypt later: prekeys are only ever destroyed after a successful
/// flush.
pub const FLUSH_EVERY: usize = 16;

const BINDING_LEN: usize = 16;

struct LedgerEntry {
    key: [u8; KEY_SIZE],
    /// Ties the entry to ONE envelope (see [`envelope_binding`]).
    binding: [u8; BINDING_LEN],
    cached_at: i64,
}

impl Drop for LedgerEntry {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// A short digest of the envelope's nonce and tag.
///
/// The ledger is indexed by message id, which the SENDER chooses. Without a
/// binding, a second envelope reusing an id would be handed the first one's
/// key. The tag is a MAC over the ciphertext and its AAD, so (nonce, tag)
/// identifies one specific envelope; a lookup only succeeds for the envelope
/// the entry was recorded for.
fn envelope_binding(nonce: &[u8], tag: &[u8]) -> [u8; BINDING_LEN] {
    let mut material = Vec::with_capacity(nonce.len() + tag.len() + 1);
    material.extend_from_slice(nonce);
    material.push(0x1f);
    material.extend_from_slice(tag);
    let digest = sha3_256(&material);
    let mut binding = [0u8; BINDING_LEN];
    binding.copy_from_slice(&digest[..BINDING_LEN]);
    binding
}

#[derive(Serialize, Deserialize)]
struct LedgerFile {
    version: u8,
    /// When this ledger first came into existence (unix seconds). A prekey with
    /// no recorded use is only considered quiet once the ledger has been
    /// watching for long enough to have seen one.
    #[serde(default)]
    created_at: i64,
    entries: Vec<LedgerFileEntry>,
    /// prekey id -> the last time (unix seconds) an envelope had to be opened
    /// with that prekey because its key was NOT in the ledger.
    #[serde(default)]
    prekey_last_needed: HashMap<String, i64>,
}

#[derive(Serialize, Deserialize)]
struct LedgerFileEntry {
    id: String,
    key: String,
    bind: String,
    at: i64,
}

pub struct MessageKeyLedger {
    owner: Option<String>,
    /// False when the stored ledger exists but could not be opened. Such a
    /// ledger caches nothing and — critically — is never written, so a
    /// transient keychain fault cannot overwrite the real file with an empty
    /// one. `retry_after` says when to try loading it again.
    available: bool,
    retry_after: i64,
    created_at: i64,
    entries: HashMap<String, LedgerEntry>,
    prekey_last_needed: HashMap<String, i64>,
    unflushed: usize,
}

impl Default for MessageKeyLedger {
    fn default() -> Self {
        Self {
            owner: None,
            available: false,
            retry_after: 0,
            created_at: 0,
            entries: HashMap::new(),
            prekey_last_needed: HashMap::new(),
            unflushed: 0,
        }
    }
}

impl MessageKeyLedger {
    /// A fresh, empty, usable ledger for `owner`.
    pub fn empty(owner: &str, now: i64) -> Self {
        Self {
            owner: Some(owner.to_string()),
            available: true,
            created_at: now,
            // An empty ledger that has never been written still has something
            // to persist: the moment it started watching.
            unflushed: 1,
            ..Self::default()
        }
    }

    /// A placeholder for a ledger that exists on disk but could not be opened.
    pub fn unavailable(owner: &str, retry_after: i64) -> Self {
        Self {
            owner: Some(owner.to_string()),
            available: false,
            retry_after,
            ..Self::default()
        }
    }

    pub fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    pub fn is_available(&self) -> bool {
        self.available
    }

    /// True when this placeholder should be replaced by another load attempt.
    pub fn should_retry_load(&self, now: i64) -> bool {
        !self.available && now >= self.retry_after
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn unflushed(&self) -> usize {
        self.unflushed
    }

    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// The key recorded for this exact envelope, if any.
    pub fn lookup(&self, message_id: &str, nonce: &[u8], tag: &[u8]) -> Option<[u8; KEY_SIZE]> {
        if !self.available {
            return None;
        }
        let entry = self.entries.get(message_id)?;
        (entry.binding == envelope_binding(nonce, tag)).then_some(entry.key)
    }

    pub fn contains(&self, message_id: &str, nonce: &[u8], tag: &[u8]) -> bool {
        self.lookup(message_id, nonce, tag).is_some()
    }

    /// Record the key that opened an envelope. Returns true when a new entry
    /// was added.
    ///
    /// FIRST WRITE WINS. An entry is never replaced: a later envelope that
    /// reuses a message id (which only its sender could arrange) is simply not
    /// cached, rather than evicting the key of the message that was there
    /// first.
    pub fn remember(
        &mut self,
        message_id: &str,
        nonce: &[u8],
        tag: &[u8],
        key: &[u8; KEY_SIZE],
        now: i64,
    ) -> bool {
        if !self.available
            || message_id.is_empty()
            || message_id.len() > MAX_MESSAGE_ID_LEN
            || self.entries.contains_key(message_id)
        {
            return false;
        }
        self.entries.insert(
            message_id.to_string(),
            LedgerEntry {
                key: *key,
                binding: envelope_binding(nonce, tag),
                cached_at: now,
            },
        );
        self.unflushed += 1;
        true
    }

    /// Destroy the key for a message. After the next flush this device can no
    /// longer open that envelope from the ledger.
    pub fn forget(&mut self, message_id: &str) -> bool {
        if !self.available {
            return false;
        }
        let removed = self.entries.remove(message_id).is_some();
        if removed {
            self.unflushed += 1;
        }
        removed
    }

    /// Note that `prekey_id` was needed just now: an envelope sealed to it was
    /// not in the ledger and had to be opened the long way.
    pub fn note_prekey_needed(&mut self, prekey_id: &str, now: i64) {
        if !self.available || prekey_id.is_empty() || prekey_id.len() > MAX_MESSAGE_ID_LEN {
            return;
        }
        self.prekey_last_needed.insert(prekey_id.to_string(), now);
        self.unflushed += 1;
    }

    /// Whether `prekey_id` has gone unneeded for at least `quiet_secs`.
    ///
    /// A prekey that was never recorded as needed is quiet only once the
    /// ledger itself has existed for that long — otherwise "never seen" would
    /// just mean "not looked yet".
    pub fn prekey_quiet_for(&self, prekey_id: &str, quiet_secs: i64, now: i64) -> bool {
        if !self.available {
            return false;
        }
        let since = self
            .prekey_last_needed
            .get(prekey_id)
            .copied()
            .unwrap_or(self.created_at);
        now.saturating_sub(since) >= quiet_secs
    }

    /// Drop the bookkeeping for prekeys that no longer exist.
    pub fn forget_prekeys(&mut self, prekey_ids: &[String]) {
        let before = self.prekey_last_needed.len();
        for id in prekey_ids {
            self.prekey_last_needed.remove(id);
        }
        if self.prekey_last_needed.len() != before {
            self.unflushed += 1;
        }
    }

    pub fn mark_flushed(&mut self) {
        self.unflushed = 0;
    }

    /// Serialise for storage. The result holds raw keys: the caller encrypts it
    /// and wipes this buffer.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let file = LedgerFile {
            version: 1,
            created_at: self.created_at,
            entries: self
                .entries
                .iter()
                .map(|(id, entry)| LedgerFileEntry {
                    id: id.clone(),
                    key: b64.encode(entry.key),
                    bind: b64.encode(entry.binding),
                    at: entry.cached_at,
                })
                .collect(),
            prekey_last_needed: self.prekey_last_needed.clone(),
        };
        let encoded = serde_json::to_vec(&file)
            .map_err(|e| QGuardError::Storage(format!("encode message key ledger: {e}")));
        // The intermediate strings hold key material in base64.
        let mut file = file;
        for entry in file.entries.iter_mut() {
            entry.key.zeroize();
        }
        encoded
    }

    /// Every entry, for an encrypted history backup (`crate::history_backup`).
    /// Same per-entry form as the stored ledger; prekey bookkeeping is local
    /// to this device and is left out. The caller encrypts and wipes it.
    pub fn export_backup(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut entries: Vec<LedgerFileEntry> = self
            .entries
            .iter()
            .map(|(id, entry)| LedgerFileEntry {
                id: id.clone(),
                key: b64.encode(entry.key),
                bind: b64.encode(entry.binding),
                at: entry.cached_at,
            })
            .collect();
        let encoded = serde_json::to_vec(&entries)
            .map(zeroize::Zeroizing::new)
            .map_err(|e| QGuardError::Storage(format!("encode history backup: {e}")));
        for entry in entries.iter_mut() {
            entry.key.zeroize();
        }
        encoded
    }

    /// Merge a backup's entries. FIRST WRITE WINS, exactly as [`Self::remember`]:
    /// an entry this ledger already has is kept. Returns (added, already held).
    pub fn import_backup(&mut self, bytes: &[u8]) -> Result<(usize, usize)> {
        if !self.available {
            return Err(QGuardError::Storage(
                "the message key ledger on this device could not be opened, so nothing can be restored right now".to_string(),
            ));
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut entries: Vec<LedgerFileEntry> = serde_json::from_slice(bytes)
            .map_err(|e| QGuardError::InvalidInput(format!("history backup contents are malformed: {e}")))?;
        let (mut added, mut held) = (0usize, 0usize);
        for entry in entries.iter_mut() {
            let key_bytes = b64.decode(&entry.key);
            entry.key.zeroize();
            let (Ok(mut key_bytes), Ok(binding_bytes)) = (key_bytes, b64.decode(&entry.bind)) else {
                continue;
            };
            if key_bytes.len() != KEY_SIZE
                || binding_bytes.len() != BINDING_LEN
                || entry.id.is_empty()
                || entry.id.len() > MAX_MESSAGE_ID_LEN
            {
                key_bytes.zeroize();
                continue;
            }
            if self.entries.contains_key(&entry.id) {
                key_bytes.zeroize();
                held += 1;
                continue;
            }
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&key_bytes);
            key_bytes.zeroize();
            let mut binding = [0u8; BINDING_LEN];
            binding.copy_from_slice(&binding_bytes);
            self.entries.insert(entry.id.clone(), LedgerEntry { key, binding, cached_at: entry.at });
            key.zeroize();
            added += 1;
        }
        if added > 0 {
            self.unflushed += added;
        }
        Ok((added, held))
    }

    /// Rebuild a ledger from its stored form. Malformed entries are skipped —
    /// one bad record must not cost every other cached key.
    pub fn decode(owner: &str, bytes: &[u8], now: i64) -> Result<Self> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut file: LedgerFile = serde_json::from_slice(bytes)
            .map_err(|e| QGuardError::Storage(format!("decode message key ledger: {e}")))?;
        if file.version != 1 {
            return Err(QGuardError::Storage(format!(
                "message key ledger has unsupported version {}; update QGuard Messaging",
                file.version
            )));
        }
        let mut entries = HashMap::with_capacity(file.entries.len());
        for entry in file.entries.iter_mut() {
            let key_bytes = b64.decode(&entry.key);
            entry.key.zeroize();
            let (Ok(mut key_bytes), Ok(binding_bytes)) = (key_bytes, b64.decode(&entry.bind)) else {
                continue;
            };
            if key_bytes.len() != KEY_SIZE
                || binding_bytes.len() != BINDING_LEN
                || entry.id.is_empty()
                || entry.id.len() > MAX_MESSAGE_ID_LEN
            {
                key_bytes.zeroize();
                continue;
            }
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&key_bytes);
            key_bytes.zeroize();
            let mut binding = [0u8; BINDING_LEN];
            binding.copy_from_slice(&binding_bytes);
            entries.insert(
                entry.id.clone(),
                LedgerEntry {
                    key,
                    binding,
                    cached_at: entry.at,
                },
            );
            key.zeroize();
        }
        Ok(Self {
            owner: Some(owner.to_string()),
            available: true,
            retry_after: 0,
            // A ledger written before `created_at` existed starts its watch now.
            created_at: if file.created_at > 0 { file.created_at } else { now },
            entries,
            prekey_last_needed: file.prekey_last_needed,
            unflushed: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: [u8; 12] = [1; 12];
    const TAG: [u8; 16] = [2; 16];

    #[test]
    fn a_key_is_returned_only_for_the_envelope_it_was_recorded_for() {
        let mut ledger = MessageKeyLedger::empty("user", 100);
        let key = [7u8; KEY_SIZE];
        assert!(ledger.remember("msg-1", &NONCE, &TAG, &key, 100));
        assert_eq!(ledger.lookup("msg-1", &NONCE, &TAG), Some(key));

        // Same id, different ciphertext: a sender reusing an id must not be
        // handed the first message's key.
        assert_eq!(ledger.lookup("msg-1", &NONCE, &[9u8; 16]), None);
        assert_eq!(ledger.lookup("msg-1", &[9u8; 12], &TAG), None);
        assert_eq!(ledger.lookup("msg-2", &NONCE, &TAG), None);
    }

    #[test]
    fn the_first_entry_for_an_id_is_never_replaced() {
        let mut ledger = MessageKeyLedger::empty("user", 100);
        let original = [7u8; KEY_SIZE];
        assert!(ledger.remember("msg-1", &NONCE, &TAG, &original, 100));
        // A second envelope arrives under the same id with its own key.
        assert!(!ledger.remember("msg-1", &[5u8; 12], &[6u8; 16], &[8u8; KEY_SIZE], 200));
        assert_eq!(ledger.lookup("msg-1", &NONCE, &TAG), Some(original));
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn oversized_or_empty_ids_are_not_cached() {
        let mut ledger = MessageKeyLedger::empty("user", 100);
        let long_id = "x".repeat(MAX_MESSAGE_ID_LEN + 1);
        assert!(!ledger.remember(&long_id, &NONCE, &TAG, &[1u8; KEY_SIZE], 100));
        assert!(!ledger.remember("", &NONCE, &TAG, &[1u8; KEY_SIZE], 100));
        assert!(ledger.is_empty());
    }

    #[test]
    fn forgetting_a_message_destroys_its_key() {
        let mut ledger = MessageKeyLedger::empty("user", 100);
        ledger.remember("msg-1", &NONCE, &TAG, &[7u8; KEY_SIZE], 100);
        ledger.mark_flushed();
        assert!(ledger.forget("msg-1"));
        assert_eq!(ledger.lookup("msg-1", &NONCE, &TAG), None);
        assert!(ledger.unflushed() > 0, "a deletion must be written out too");
        assert!(!ledger.forget("msg-1"));
    }

    #[test]
    fn the_ledger_round_trips_through_its_stored_form() {
        let mut ledger = MessageKeyLedger::empty("user", 100);
        ledger.remember("msg-1", &NONCE, &TAG, &[7u8; KEY_SIZE], 110);
        ledger.remember("msg-2", &[3u8; 12], &[4u8; 16], &[8u8; KEY_SIZE], 120);
        ledger.note_prekey_needed("prekey-a", 130);

        let encoded = ledger.encode().unwrap();
        let restored = MessageKeyLedger::decode("user", &encoded, 999).unwrap();
        assert!(restored.is_available());
        assert_eq!(restored.owner(), Some("user"));
        assert_eq!(restored.len(), 2);
        assert_eq!(restored.created_at(), 100);
        assert_eq!(restored.unflushed(), 0);
        assert_eq!(restored.lookup("msg-1", &NONCE, &TAG), Some([7u8; KEY_SIZE]));
        assert_eq!(restored.lookup("msg-2", &[3u8; 12], &[4u8; 16]), Some([8u8; KEY_SIZE]));
        assert!(!restored.prekey_quiet_for("prekey-a", 100, 150));
        assert!(restored.prekey_quiet_for("prekey-a", 100, 230));
    }

    #[test]
    fn one_malformed_entry_does_not_cost_the_rest() {
        let mut ledger = MessageKeyLedger::empty("user", 100);
        ledger.remember("good", &NONCE, &TAG, &[7u8; KEY_SIZE], 110);
        let mut file: serde_json::Value =
            serde_json::from_slice(&ledger.encode().unwrap()).unwrap();
        file["entries"].as_array_mut().unwrap().push(serde_json::json!({
            "id": "bad", "key": "not base64 !!", "bind": "AAAA", "at": 1
        }));
        let restored =
            MessageKeyLedger::decode("user", file.to_string().as_bytes(), 999).unwrap();
        assert_eq!(restored.len(), 1);
        assert!(restored.contains("good", &NONCE, &TAG));
        // A wholly unreadable document is an error, not an empty ledger: the
        // caller must be able to tell "nothing stored" from "could not read".
        assert!(MessageKeyLedger::decode("user", b"{ not json", 999).is_err());
    }

    #[test]
    fn an_unavailable_ledger_caches_nothing_and_asks_to_be_retried() {
        let mut ledger = MessageKeyLedger::unavailable("user", 500);
        assert!(!ledger.is_available());
        assert!(!ledger.remember("msg-1", &NONCE, &TAG, &[7u8; KEY_SIZE], 100));
        assert_eq!(ledger.lookup("msg-1", &NONCE, &TAG), None);
        assert_eq!(ledger.unflushed(), 0, "an unavailable ledger must never be written");
        // It can never vouch for a prekey being unused.
        assert!(!ledger.prekey_quiet_for("prekey-a", 0, 10_000));
        assert!(!ledger.should_retry_load(499));
        assert!(ledger.should_retry_load(500));
    }

    #[test]
    fn a_prekey_is_quiet_only_after_going_unneeded_for_the_whole_window() {
        let mut ledger = MessageKeyLedger::empty("user", 1_000);
        // Never needed: quiet only once the ledger has watched long enough.
        assert!(!ledger.prekey_quiet_for("prekey-a", 300, 1_200));
        assert!(ledger.prekey_quiet_for("prekey-a", 300, 1_300));
        // Needed again: the clock restarts from that moment.
        ledger.note_prekey_needed("prekey-a", 1_400);
        assert!(!ledger.prekey_quiet_for("prekey-a", 300, 1_600));
        assert!(ledger.prekey_quiet_for("prekey-a", 300, 1_700));
        // Bookkeeping for a destroyed prekey is dropped.
        ledger.forget_prekeys(&["prekey-a".to_string()]);
        assert!(ledger.prekey_quiet_for("prekey-a", 300, 1_700));
    }
}
