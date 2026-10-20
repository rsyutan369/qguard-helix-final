//! Channels — one sender to many readers (roadmap 7.4; owner decision
//! 2026-10-20: build channels before MLS has a post-quantum ciphersuite).
//! Design: `docs/superpowers/specs/2026-10-19-groups-design.md` §5.
//!
//! A channel's posts are encrypted ONCE under the channel's current epoch key
//! (AES-256-GCM, a per-post key derived with HKDF-SHA3-256) and signed by the
//! posting device (Ed25519 + ML-DSA-65). Epoch keys are random, held only in
//! this device's encrypted storage, and handed to each reader device pairwise
//! inside an ordinary sealed message (hybrid X25519 + ML-KEM-1024), so their
//! post-quantum protection is exactly that of a direct message. When a reader
//! leaves, the owner or an admin starts a new epoch and hands it only to who
//! remains: they cannot read anything posted after that.
//!
//! Limits (security-limitations.md): forward secrecy is per epoch, not per
//! post — whoever holds an epoch key reads every post of that epoch; and a new
//! reader receives only the current epoch, not earlier ones.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::{Zeroize, Zeroizing};

use crate::commands::calls::local_identity;
use crate::commands::messaging::{pin_subject_of, RecipientIdentityBundle};
use crate::crypto::kdf::{derive_32_with_salt, sha3_256};
use crate::crypto::signatures::{dual_sign, dual_verify};
use crate::crypto::symmetric;
use crate::crypto::{DualSignature, EncryptedEnvelope};
use crate::device_pins::DeviceStanding;
use crate::error::{QGuardError, Result};
use crate::identity::verify_identity_bundle;
use crate::state::AppState;

const BOOK_DOC: &str = "channel-keys";
const BOOK_DOC_AAD: &[u8] = b"QGuard-ChannelKeys-v1";
const POST_KEY_INFO: &[u8] = b"QGuard-ChannelPost-v1";
const SIGNATURE_DOMAIN: &[u8] = b"QGuard-ChannelPostSig-v1";
/// Epochs kept per channel, so older posts stay readable.
const MAX_EPOCHS: usize = 64;
const MAX_POST_BYTES: usize = 64 * 1024;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

#[derive(Clone, Serialize, Deserialize)]
struct EpochRecord {
    seq: u64,
    key: String,
    created_at: i64,
    #[serde(default)]
    recipients: BTreeSet<String>,
    #[serde(default)]
    recipient_users: BTreeSet<String>,
}

impl Drop for EpochRecord {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Default, Serialize, Deserialize)]
struct ChannelRecord {
    #[serde(default)]
    current: Option<String>,
    #[serde(default)]
    epochs: BTreeMap<String, EpochRecord>,
}

#[derive(Default, Serialize, Deserialize)]
struct ChannelBook {
    #[serde(default)]
    channels: BTreeMap<String, ChannelRecord>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChannelStatus {
    pub channel_id: String,
    pub current_epoch: Option<String>,
    pub current_seq: Option<u64>,
    /// Devices and users the current epoch key was handed to.
    pub recipients: Vec<String>,
    pub recipient_users: Vec<String>,
    pub epochs_held: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SealedChannelPost {
    pub post_id: String,
    pub channel_id: String,
    pub epoch_id: String,
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub tag: String,
    pub signature: DualSignature,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenedChannelPost {
    pub post_id: String,
    pub plaintext: String,
    /// The signing device is registered and recorded on this device.
    pub authenticated: bool,
}

fn validate_id(value: &str, what: &str) -> Result<()> {
    let ok = !value.is_empty() && value.len() <= 64 && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if ok { Ok(()) } else { Err(QGuardError::InvalidInput(format!("invalid {what}"))) }
}

fn load(state: &AppState, user_id: &str) -> Result<ChannelBook> {
    match state.load_user_secret_doc(user_id, BOOK_DOC, BOOK_DOC_AAD, "channel keys")? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|error| QGuardError::Storage(format!("channel keys unreadable: {error}"))),
        None => Ok(ChannelBook::default()),
    }
}

fn save(state: &AppState, user_id: &str, book: &ChannelBook) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(book).map_err(|error| QGuardError::Storage(format!("channel keys: {error}")))?);
    state.save_user_secret_doc(user_id, BOOK_DOC, BOOK_DOC_AAD, &bytes, "channel keys")
}

fn status_of(channel_id: &str, record: Option<&ChannelRecord>) -> ChannelStatus {
    let current = record.and_then(|item| item.current.as_ref().and_then(|id| item.epochs.get(id).map(|epoch| (id, epoch))));
    ChannelStatus {
        channel_id: channel_id.to_string(),
        current_epoch: current.map(|(id, _)| id.clone()),
        current_seq: current.map(|(_, epoch)| epoch.seq),
        recipients: current.map(|(_, epoch)| epoch.recipients.iter().cloned().collect()).unwrap_or_default(),
        recipient_users: current.map(|(_, epoch)| epoch.recipient_users.iter().cloned().collect()).unwrap_or_default(),
        epochs_held: record.map(|item| item.epochs.len()).unwrap_or(0),
    }
}

/// The highest-numbered epoch becomes current (ties: the later-made one wins
/// locally; both stay readable).
fn recompute_current(record: &mut ChannelRecord) {
    record.current = record
        .epochs
        .iter()
        .max_by(|a, b| (a.1.seq, a.1.created_at).cmp(&(b.1.seq, b.1.created_at)))
        .map(|(id, _)| id.clone());
    while record.epochs.len() > MAX_EPOCHS {
        let oldest = record.epochs.iter().min_by_key(|(_, epoch)| (epoch.seq, epoch.created_at)).map(|(id, _)| id.clone());
        match oldest {
            Some(id) => { record.epochs.remove(&id); }
            None => break,
        }
    }
}

fn decode_key(value: &str) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(b64().decode(value).map_err(|_| QGuardError::InvalidInput("channel key is not base64".to_string()))?);
    if bytes.len() != 32 {
        return Err(QGuardError::InvalidInput("channel key must be 32 bytes".to_string()));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn post_aad(post: &SealedChannelPost) -> Vec<u8> {
    format!(
        "QGC1|{}|{}|{}|{}|{}",
        post.channel_id, post.epoch_id, post.post_id, post.sender_user_id, post.sender_device_id
    )
    .into_bytes()
}

fn post_signable(post: &SealedChannelPost) -> Result<[u8; 32]> {
    let mut data = SIGNATURE_DOMAIN.to_vec();
    data.extend_from_slice(&post_aad(post));
    for part in [&post.nonce, &post.ciphertext, &post.tag] {
        let bytes = b64().decode(part).map_err(|_| QGuardError::InvalidInput("channel post is not base64".to_string()))?;
        data.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        data.extend_from_slice(&bytes);
    }
    Ok(sha3_256(&data))
}

pub(crate) fn status(state: &AppState, user_id: &str, channel_id: &str) -> Result<ChannelStatus> {
    validate_id(channel_id, "channel id")?;
    let book = load(state, user_id)?;
    Ok(status_of(channel_id, book.channels.get(channel_id)))
}

pub(crate) fn new_epoch(state: &AppState, user_id: &str, channel_id: &str) -> Result<ChannelStatus> {
    validate_id(channel_id, "channel id")?;
    let mut book = load(state, user_id)?;
    let record = book.channels.entry(channel_id.to_string()).or_default();
    let seq = record.epochs.values().map(|epoch| epoch.seq).max().map_or(1, |max| max + 1);
    let key = Zeroizing::new(symmetric::random_key());
    let epoch_id = uuid::Uuid::new_v4().to_string();
    record.epochs.insert(epoch_id, EpochRecord {
        seq,
        key: b64().encode(key.as_slice()),
        created_at: Utc::now().timestamp_millis(),
        recipients: BTreeSet::new(),
        recipient_users: BTreeSet::new(),
    });
    recompute_current(record);
    let out = status_of(channel_id, Some(record));
    save(state, user_id, &book)?;
    Ok(out)
}

pub(crate) fn export_key(state: &AppState, user_id: &str, channel_id: &str, epoch_id: &str) -> Result<(u64, String)> {
    validate_id(channel_id, "channel id")?;
    let book = load(state, user_id)?;
    let epoch = book
        .channels
        .get(channel_id)
        .and_then(|record| record.epochs.get(epoch_id))
        .ok_or_else(|| QGuardError::NotFound("channel epoch".to_string()))?;
    Ok((epoch.seq, epoch.key.clone()))
}

pub(crate) fn import_key(state: &AppState, user_id: &str, channel_id: &str, epoch_id: &str, seq: u64, key: &str) -> Result<ChannelStatus> {
    validate_id(channel_id, "channel id")?;
    validate_id(epoch_id, "epoch id")?;
    let decoded = decode_key(key)?;
    let mut book = load(state, user_id)?;
    let record = book.channels.entry(channel_id.to_string()).or_default();
    if let Some(existing) = record.epochs.get(epoch_id) {
        let held = decode_key(&existing.key)?;
        if held.as_slice() != decoded.as_slice() || existing.seq != seq {
            return Err(QGuardError::Trust("a different key was already received for this channel epoch; refusing to replace it".to_string()));
        }
        return Ok(status_of(channel_id, Some(record)));
    }
    record.epochs.insert(epoch_id.to_string(), EpochRecord {
        seq,
        key: b64().encode(decoded.as_slice()),
        created_at: Utc::now().timestamp_millis(),
        recipients: BTreeSet::new(),
        recipient_users: BTreeSet::new(),
    });
    recompute_current(record);
    let out = status_of(channel_id, Some(record));
    save(state, user_id, &book)?;
    Ok(out)
}

pub(crate) fn mark_distributed(
    state: &AppState,
    user_id: &str,
    channel_id: &str,
    epoch_id: &str,
    device_ids: &[String],
    user_ids: &[String],
) -> Result<ChannelStatus> {
    validate_id(channel_id, "channel id")?;
    let mut book = load(state, user_id)?;
    let record = book.channels.get_mut(channel_id).ok_or_else(|| QGuardError::NotFound("channel".to_string()))?;
    let epoch = record.epochs.get_mut(epoch_id).ok_or_else(|| QGuardError::NotFound("channel epoch".to_string()))?;
    epoch.recipients.extend(device_ids.iter().cloned());
    epoch.recipient_users.extend(user_ids.iter().cloned());
    let out = status_of(channel_id, Some(record));
    save(state, user_id, &book)?;
    Ok(out)
}

pub(crate) fn seal_post(state: &AppState, channel_id: &str, post_id: &str, plaintext: &str) -> Result<SealedChannelPost> {
    validate_id(channel_id, "channel id")?;
    validate_id(post_id, "post id")?;
    if plaintext.is_empty() || plaintext.len() > MAX_POST_BYTES {
        return Err(QGuardError::InvalidInput("a channel post must be 1 byte to 64 KiB".to_string()));
    }
    let identity = local_identity(state)?;
    let book = load(state, &identity.user_id)?;
    let record = book.channels.get(channel_id).ok_or_else(|| QGuardError::NotFound("this channel has no key on this device".to_string()))?;
    let epoch_id = record.current.clone().ok_or_else(|| QGuardError::NotFound("this channel has no key on this device".to_string()))?;
    let epoch = record.epochs.get(&epoch_id).ok_or_else(|| QGuardError::NotFound("channel epoch".to_string()))?;
    let epoch_key = decode_key(&epoch.key)?;
    let post_key = Zeroizing::new(derive_32_with_salt(post_id.as_bytes(), epoch_key.as_slice(), POST_KEY_INFO)?);

    let mut post = SealedChannelPost {
        post_id: post_id.to_string(),
        channel_id: channel_id.to_string(),
        epoch_id,
        sender_user_id: identity.user_id.clone(),
        sender_device_id: identity.device_id.clone(),
        nonce: String::new(),
        ciphertext: String::new(),
        tag: String::new(),
        signature: DualSignature { ed25519: Vec::new(), ml_dsa_65: Vec::new() },
    };
    let sealed = symmetric::encrypt(&post_key, plaintext.as_bytes(), &post_aad(&post))?;
    post.nonce = b64().encode(&sealed.nonce);
    post.ciphertext = b64().encode(&sealed.ciphertext);
    post.tag = b64().encode(&sealed.tag);
    post.signature = dual_sign(&identity.signing.ed25519_secret, &identity.signing.mldsa_secret, &post_signable(&post)?)?;
    Ok(post)
}

pub(crate) fn open_post(state: &AppState, post: &SealedChannelPost, sender: Option<&RecipientIdentityBundle>) -> Result<OpenedChannelPost> {
    validate_id(&post.channel_id, "channel id")?;
    validate_id(&post.post_id, "post id")?;
    let user_id = state.user_id()?;
    // The signature is checked against the sender's REGISTERED keys, never keys
    // the post carries; without the directory row there is nothing to check.
    let sender = sender.ok_or_else(|| QGuardError::Trust("the posting device is not in the directory; cannot verify this post".to_string()))?;
    if sender.user_id != post.sender_user_id || sender.device_id != post.sender_device_id {
        return Err(QGuardError::Trust("the identity supplied is not the posting device's".to_string()));
    }
    verify_identity_bundle(
        &sender.user_id,
        &sender.device_id,
        &sender.x25519_identity_public,
        &sender.mlkem_identity_public,
        &sender.ed25519_identity_public,
        &sender.mldsa_identity_public,
        &sender.identity_signature,
    )
    .map_err(|_| QGuardError::Trust("the posting device's registered identity failed its own signature check".to_string()))?;
    dual_verify(&sender.ed25519_identity_public, &sender.mldsa_identity_public, &post_signable(post)?, &post.signature)
        .map_err(|_| QGuardError::Trust("this post's signature does not verify; it was altered or forged".to_string()))?;
    let authenticated = match state.device_standing(&user_id, &pin_subject_of(sender)) {
        Some(DeviceStanding::KeyChanged) => {
            return Err(QGuardError::Trust("the posting device is presenting different identity keys than the ones recorded for it; refusing its post".to_string()))
        }
        Some(DeviceStanding::New) => false,
        Some(DeviceStanding::Pinned) | None => true,
    };

    let book = load(state, &user_id)?;
    let epoch = book
        .channels
        .get(&post.channel_id)
        .and_then(|record| record.epochs.get(&post.epoch_id))
        .ok_or_else(|| QGuardError::NotFound("the key for this post has not reached this device".to_string()))?;
    let epoch_key = decode_key(&epoch.key)?;
    let post_key = Zeroizing::new(derive_32_with_salt(post.post_id.as_bytes(), epoch_key.as_slice(), POST_KEY_INFO)?);
    let envelope = EncryptedEnvelope {
        nonce: b64().decode(&post.nonce).map_err(|_| QGuardError::InvalidInput("nonce".to_string()))?,
        ciphertext: b64().decode(&post.ciphertext).map_err(|_| QGuardError::InvalidInput("ciphertext".to_string()))?,
        tag: b64().decode(&post.tag).map_err(|_| QGuardError::InvalidInput("tag".to_string()))?,
    };
    let plaintext = Zeroizing::new(symmetric::decrypt(&post_key, &envelope, &post_aad(post))?);
    let text = String::from_utf8(plaintext.to_vec()).map_err(|_| QGuardError::Crypto("channel post is not UTF-8".to_string()))?;
    Ok(OpenedChannelPost { post_id: post.post_id.clone(), plaintext: text, authenticated })
}

pub(crate) fn forget(state: &AppState, user_id: &str, channel_id: &str) -> Result<()> {
    let mut book = load(state, user_id)?;
    if book.channels.remove(channel_id).is_some() {
        save(state, user_id, &book)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportedChannelKey {
    pub epoch_id: String,
    pub seq: u64,
    pub key: String,
}

#[tauri::command]
pub fn channel_status(state: State<'_, AppState>, channel_id: String) -> Result<ChannelStatus> {
    let user_id = state.user_id()?;
    status(&state, &user_id, &channel_id)
}

#[tauri::command]
pub fn channel_new_epoch(state: State<'_, AppState>, channel_id: String) -> Result<ChannelStatus> {
    let user_id = state.user_id()?;
    new_epoch(&state, &user_id, &channel_id)
}

/// The epoch key, for sealing to one reader device inside a pairwise message.
#[tauri::command]
pub fn channel_key_export(state: State<'_, AppState>, channel_id: String, epoch_id: String) -> Result<ExportedChannelKey> {
    let user_id = state.user_id()?;
    let (seq, key) = export_key(&state, &user_id, &channel_id, &epoch_id)?;
    Ok(ExportedChannelKey { epoch_id, seq, key })
}

#[tauri::command]
pub fn channel_key_import(state: State<'_, AppState>, channel_id: String, epoch_id: String, seq: u64, key: String) -> Result<ChannelStatus> {
    let user_id = state.user_id()?;
    let key = Zeroizing::new(key);
    import_key(&state, &user_id, &channel_id, &epoch_id, seq, &key)
}

#[tauri::command]
pub fn channel_mark_distributed(
    state: State<'_, AppState>,
    channel_id: String,
    epoch_id: String,
    device_ids: Vec<String>,
    user_ids: Vec<String>,
) -> Result<ChannelStatus> {
    let user_id = state.user_id()?;
    mark_distributed(&state, &user_id, &channel_id, &epoch_id, &device_ids, &user_ids)
}

#[tauri::command]
pub fn channel_seal_post(state: State<'_, AppState>, channel_id: String, post_id: String, plaintext: String) -> Result<SealedChannelPost> {
    state.require_auth()?;
    let plaintext = Zeroizing::new(plaintext);
    seal_post(&state, &channel_id, &post_id, &plaintext)
}

#[tauri::command]
pub fn channel_open_post(
    state: State<'_, AppState>,
    post: SealedChannelPost,
    sender_identity: Option<RecipientIdentityBundle>,
) -> Result<OpenedChannelPost> {
    open_post(&state, &post, sender_identity.as_ref())
}

#[tauri::command]
pub fn channel_forget(state: State<'_, AppState>, channel_id: String) -> Result<()> {
    let user_id = state.user_id()?;
    forget(&state, &user_id, &channel_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDevice;

    const CHANNEL: &str = "c0000000-0000-0000-0000-000000000001";

    /// The owner makes an epoch and hands its key to the reader (as the client
    /// does inside a sealed pairwise message).
    fn owner_and_reader() -> (TestDevice, TestDevice, String) {
        let owner = TestDevice::new(false);
        let reader = TestDevice::new(false);
        let status = new_epoch(&owner.state, &owner.user, CHANNEL).expect("epoch");
        let epoch = status.current_epoch.expect("current");
        let (seq, key) = export_key(&owner.state, &owner.user, CHANNEL, &epoch).expect("export");
        import_key(&reader.state, &reader.user, CHANNEL, &epoch, seq, &key).expect("import");
        (owner, reader, epoch)
    }

    #[test]
    fn a_reader_with_the_epoch_key_reads_an_authenticated_post() {
        let (owner, reader, epoch) = owner_and_reader();
        let post = seal_post(&owner.state, CHANNEL, "p-1", "Release notes: v2 is out").expect("seal");
        assert_eq!(post.epoch_id, epoch);
        assert!(!post.ciphertext.contains("Release"));
        let opened = open_post(&reader.state, &post, Some(&owner.identity_row())).expect("open");
        assert_eq!(opened.plaintext, "Release notes: v2 is out");
        assert!(opened.authenticated);
    }

    #[test]
    fn without_the_key_a_post_cannot_be_read() {
        let (owner, _reader, _) = owner_and_reader();
        let outsider = TestDevice::new(false);
        let post = seal_post(&owner.state, CHANNEL, "p-1", "members only").expect("seal");
        assert!(open_post(&outsider.state, &post, Some(&owner.identity_row())).is_err());
    }

    #[test]
    fn altered_posts_and_forged_senders_are_refused() {
        let (owner, reader, _) = owner_and_reader();
        let post = seal_post(&owner.state, CHANNEL, "p-1", "hello").expect("seal");

        let mut tampered = post.clone();
        let mut bytes = b64().decode(&tampered.ciphertext).unwrap();
        bytes[0] ^= 1;
        tampered.ciphertext = b64().encode(bytes);
        assert!(open_post(&reader.state, &tampered, Some(&owner.identity_row())).is_err());

        // Moved to another post id: the AAD and the signature both bind it.
        let mut moved = post.clone();
        moved.post_id = "p-2".to_string();
        assert!(open_post(&reader.state, &moved, Some(&owner.identity_row())).is_err());

        // Another device claims the post: its registered keys do not verify it.
        let impostor = TestDevice::new(false);
        let mut claimed = post.clone();
        claimed.sender_user_id = impostor.user.clone();
        claimed.sender_device_id = impostor.device_id.clone();
        assert!(open_post(&reader.state, &claimed, Some(&impostor.identity_row())).is_err());

        // The identity supplied must be the posting device's.
        assert!(open_post(&reader.state, &post, Some(&impostor.identity_row())).is_err());
        assert!(open_post(&reader.state, &post, None).is_err());
    }

    #[test]
    fn a_new_epoch_locks_out_whoever_did_not_receive_it() {
        let (owner, reader, first) = owner_and_reader();
        let old_post = seal_post(&owner.state, CHANNEL, "p-old", "before").expect("seal");
        let rotated = new_epoch(&owner.state, &owner.user, CHANNEL).expect("rotate");
        assert_ne!(rotated.current_epoch.as_deref(), Some(first.as_str()));
        assert_eq!(rotated.current_seq, Some(2));
        let new_post = seal_post(&owner.state, CHANNEL, "p-new", "after").expect("seal");
        // The removed reader still reads the old epoch, never the new one.
        assert!(open_post(&reader.state, &old_post, Some(&owner.identity_row())).is_ok());
        assert!(open_post(&reader.state, &new_post, Some(&owner.identity_row())).is_err());
    }

    #[test]
    fn a_received_epoch_key_cannot_be_replaced() {
        let (owner, reader, epoch) = owner_and_reader();
        let (seq, key) = export_key(&owner.state, &owner.user, CHANNEL, &epoch).expect("export");
        assert!(import_key(&reader.state, &reader.user, CHANNEL, &epoch, seq, &key).is_ok(), "same key again is fine");
        let other = b64().encode([7u8; 32]);
        assert!(import_key(&reader.state, &reader.user, CHANNEL, &epoch, seq, &other).is_err());
        assert!(import_key(&reader.state, &reader.user, CHANNEL, "e-short", 1, "AAAA").is_err());
    }

    #[test]
    fn keys_and_distribution_survive_a_restart() {
        let (owner, _reader, epoch) = owner_and_reader();
        mark_distributed(&owner.state, &owner.user, CHANNEL, &epoch, &["dev-b".into()], &["user-b".into()]).expect("mark");
        let owner = owner.restart();
        let status = status(&owner.state, &owner.user, CHANNEL).expect("status");
        assert_eq!(status.current_epoch.as_deref(), Some(epoch.as_str()));
        assert_eq!(status.recipients, vec!["dev-b".to_string()]);
        assert_eq!(status.recipient_users, vec!["user-b".to_string()]);
        assert!(seal_post(&owner.state, CHANNEL, "p-after-restart", "still works").is_ok());
    }

    #[test]
    fn only_a_device_holding_a_key_can_post_and_posts_are_bounded() {
        let poster = TestDevice::new(false);
        assert!(seal_post(&poster.state, CHANNEL, "p-1", "no key yet").is_err());
        new_epoch(&poster.state, &poster.user, CHANNEL).expect("epoch");
        assert!(seal_post(&poster.state, CHANNEL, "p-1", "").is_err());
        assert!(seal_post(&poster.state, CHANNEL, "p-1", &"x".repeat(MAX_POST_BYTES + 1)).is_err());
        assert!(seal_post(&poster.state, "../escape", "p-1", "x").is_err());
    }

    #[test]
    fn forgetting_a_channel_drops_its_keys() {
        let (owner, reader, _) = owner_and_reader();
        let post = seal_post(&owner.state, CHANNEL, "p-1", "hello").expect("seal");
        forget(&reader.state, &reader.user, CHANNEL).expect("forget");
        assert!(open_post(&reader.state, &post, Some(&owner.identity_row())).is_err());
    }
}
