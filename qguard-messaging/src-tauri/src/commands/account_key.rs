//! Account sealing key: encryption for the few fields only the app reads.
//!
//! WHY THIS EXISTS
//! ---------------------------------------------------------------------------
//! Message bodies, attachments and call media are already end-to-end encrypted.
//! A handful of rows the relay stores are not message content but are still only
//! ever read by the account's own devices: contact nicknames, the details of an
//! audit event, crypto telemetry details, per-message trust flags. They were
//! plaintext columns (one was even named `encrypted_details`), so a database
//! breach exposed them. The relay does not need them — RLS and routing use the
//! id columns, never these — so they can be sealed.
//!
//! The obstacle is that every key in the app is per-DEVICE, and these fields
//! must read the same on every device the user owns. This module adds the one
//! missing thing: a random 256-bit key per account ("epoch" 1, 2, ...), held on
//! each of the user's devices, encrypted at rest under the device storage key.
//!
//! HOW A DEVICE GETS THE KEY
//! ---------------------------------------------------------------------------
//!  * The first device (or the one the client elects when none has it) makes
//!    epoch 1 (`bootstrap`).
//!  * Any device that holds it seals the whole key ring to another of the
//!    user's devices — hybrid X25519 + ML-KEM-1024 to that device's identity
//!    keys, dual-signed (Ed25519 + ML-DSA-65) by the sender — the same shape as
//!    a social-recovery share. The client stores that wrap in
//!    `messaging_account_key_wraps` (migration 044); the relay cannot open it.
//!  * Both sides must be devices THIS device has pinned as the user's own
//!    (`device_pins`): a device the relay merely lists never receives the key
//!    and a wrap from one is refused.
//!  * Removing a device calls `rotate`: a new epoch the removed device never
//!    receives. Fields sealed earlier stay readable to whoever already held the
//!    old epoch — the same trade-off as channel key epochs.
//!
//! WHAT A FIELD LOOKS LIKE
//! ---------------------------------------------------------------------------
//! `{v, e, n, c}`: version, epoch, nonce, ciphertext||tag. AES-256-GCM under
//! HKDF-SHA3-256(epoch key, purpose). The associated data names the user, the
//! purpose and a row context (e.g. the contact's id), so a sealed value copied
//! to another row, field or account does not open.
//!
//! WHAT IT DOES NOT DO
//! ---------------------------------------------------------------------------
//!  * The wrap is sealed to a long-lived device identity key, so it has no
//!    forward secrecy: someone who later steals that identity key AND holds a
//!    copy of the wrap rows can recover the key ring. This protects low-value
//!    metadata, not message content (which keeps its own per-message keys).
//!  * Two devices that each believe they are first, at the same moment, make two
//!    different epoch-1 keys. The client elects the lowest device id to avoid
//!    that; if it happens anyway, the conflict is refused and surfaced, and
//!    affected fields read as unavailable rather than wrong.

use std::collections::BTreeMap;

use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::{Zeroize, Zeroizing};

use crate::commands::calls::{local_identity, CallPeerIdentity};
use crate::commands::recovery::{ciphertext_digest, framed, push_field};
use crate::crypto::hybrid_kex::{decapsulate, encapsulate_bound};
use crate::crypto::kdf::derive_32;
use crate::crypto::signatures::{dual_sign, dual_verify};
use crate::crypto::symmetric;
use crate::crypto::{AlgorithmSuite, DualSignature, EncryptedEnvelope, HybridCiphertext};
use crate::device_pins::DeviceStanding;
use crate::error::{QGuardError, Result};
use crate::state::AppState;

const WRAP_VERSION: u8 = 1;
const FIELD_VERSION: u8 = 1;
const RING_DOC: &str = "account-key";
const RING_DOC_AAD: &[u8] = b"QGuard-Messaging-AccountKey-v1";
const WRAP_KEM_INFO: &str = "QGuard-AccountKey-v1:wrap:";
const WRAP_SEAL_INFO: &[u8] = b"QGuard-AccountKey-WrapSeal-v1";
const FIELD_INFO_PREFIX: &str = "QGuard-AccountField-v1|";
const MAX_EPOCHS: usize = 256;
const MAX_FIELD_BYTES: usize = 16 * 1024;
const MAX_CONTEXT_BYTES: usize = 256;
const MAX_OPEN_BATCH: usize = 500;

/// Prefix of the error a field open returns when this device has no key for the
/// field's epoch. The client turns it into "not available on this device yet".
pub const UNAVAILABLE: &str = "ACCOUNT_KEY_UNAVAILABLE";

/// The only things a field may be sealed for. A fixed list keeps a caller from
/// inventing a purpose that happens to collide with another one's key.
const PURPOSES: &[&str] = &["contact_alias", "security_event", "telemetry", "message_state"];

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/* ----------------------------------------------------------------- key ring -- */

#[derive(Serialize, Deserialize, Default)]
struct KeyRing {
    current: u32,
    keys: BTreeMap<u32, [u8; 32]>,
}

impl Drop for KeyRing {
    fn drop(&mut self) {
        for key in self.keys.values_mut() {
            key.zeroize();
        }
    }
}

fn load_ring(state: &AppState, user_id: &str) -> Result<Option<KeyRing>> {
    match state.load_user_secret_doc(user_id, RING_DOC, RING_DOC_AAD, "account key")? {
        None => Ok(None),
        Some(bytes) => {
            let ring: KeyRing = serde_json::from_slice(&bytes).map_err(|e| QGuardError::Storage(format!("account key: {e}")))?;
            if ring.keys.is_empty() || !ring.keys.contains_key(&ring.current) {
                return Err(QGuardError::Storage("account key: the stored key ring is inconsistent".to_string()));
            }
            Ok(Some(ring))
        }
    }
}

fn save_ring(state: &AppState, user_id: &str, ring: &KeyRing) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(ring).map_err(|e| QGuardError::Storage(format!("account key: {e}")))?);
    state.save_user_secret_doc(user_id, RING_DOC, RING_DOC_AAD, &bytes, "account key")
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountKeyStatus {
    /// This device can seal and open fields.
    pub available: bool,
    pub current_epoch: Option<u32>,
    pub epochs: Vec<u32>,
}

fn status_of(ring: Option<&KeyRing>) -> AccountKeyStatus {
    match ring {
        None => AccountKeyStatus { available: false, current_epoch: None, epochs: Vec::new() },
        Some(ring) => AccountKeyStatus { available: true, current_epoch: Some(ring.current), epochs: ring.keys.keys().copied().collect() },
    }
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    key
}

fn status(state: &AppState) -> Result<AccountKeyStatus> {
    let user_id = state.user_id()?;
    Ok(status_of(load_ring(state, &user_id)?.as_ref()))
}

/// Make epoch 1 if this device has no key. Idempotent: a device that already
/// has one keeps it (two calls must never mint two different keys).
fn bootstrap(state: &AppState) -> Result<AccountKeyStatus> {
    let user_id = state.user_id()?;
    if let Some(ring) = load_ring(state, &user_id)? {
        return Ok(status_of(Some(&ring)));
    }
    let mut ring = KeyRing { current: 1, keys: BTreeMap::new() };
    ring.keys.insert(1, random_key());
    save_ring(state, &user_id, &ring)?;
    state.audit_info("account_key_created", "Account sealing key created on this device");
    Ok(status_of(Some(&ring)))
}

/// Start a new epoch. Called after a device is removed, so the removed device
/// never receives the key that protects what is written from now on.
fn rotate(state: &AppState) -> Result<AccountKeyStatus> {
    let user_id = state.user_id()?;
    let mut ring = load_ring(state, &user_id)?.ok_or_else(|| QGuardError::NotFound("this device has no account key to rotate".to_string()))?;
    if ring.keys.len() >= MAX_EPOCHS {
        return Err(QGuardError::InvalidInput("too many account key epochs".to_string()));
    }
    let next = ring.current.checked_add(1).ok_or_else(|| QGuardError::InvalidInput("account key epoch overflow".to_string()))?;
    ring.keys.insert(next, random_key());
    ring.current = next;
    save_ring(state, &user_id, &ring)?;
    state.audit_info("account_key_rotated", "Account sealing key rotated");
    Ok(status_of(Some(&ring)))
}

/* --------------------------------------------------------------------- wraps -- */

/// The key ring, sealed to one of the user's other devices and signed by this
/// one. Stored by the client in `messaging_account_key_wraps`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountKeyWrap {
    pub v: u8,
    pub user_id: String,
    pub from_device_id: String,
    pub to_device_id: String,
    /// The newest epoch the ring held when it was sealed (for de-duplication).
    pub epoch: u32,
    pub created_at: i64,
    pub ciphertext: HybridCiphertext,
    pub sealed: EncryptedEnvelope,
    pub signature: DualSignature,
}

fn wrap_header(wrap: &AccountKeyWrap) -> Vec<u8> {
    framed(
        b"QGuard-AccountKey-Wrap-v1",
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

fn wrap_signable(wrap: &AccountKeyWrap) -> Vec<u8> {
    let mut out = wrap_header(wrap);
    push_field(&mut out, &ciphertext_digest(&wrap.ciphertext));
    push_field(&mut out, &wrap.sealed.nonce);
    push_field(&mut out, &wrap.sealed.ciphertext);
    push_field(&mut out, &wrap.sealed.tag);
    out
}

fn wrap_info(from_device_id: &str, to_device_id: &str) -> String {
    format!("{WRAP_KEM_INFO}{from_device_id}:{to_device_id}")
}

/// A pinned device of this account other than this one — the only kind a wrap
/// may be made for or accepted from.
fn require_own_pinned(state: &AppState, user_id: &str, peer: &CallPeerIdentity, what: &str) -> Result<()> {
    peer.verify()?;
    if peer.user_id != user_id {
        return Err(QGuardError::Trust(format!("{what} is not a device of this account")));
    }
    if state.device_standing(user_id, &peer.pin_subject()) != Some(DeviceStanding::Pinned) {
        return Err(QGuardError::Trust(format!("{what} is not a device this device has recorded for your account")));
    }
    Ok(())
}

fn make_wrap(state: &AppState, target: &CallPeerIdentity) -> Result<AccountKeyWrap> {
    let identity = local_identity(state)?;
    if target.device_id == identity.device_id {
        return Err(QGuardError::InvalidInput("a device does not wrap the key for itself".to_string()));
    }
    require_own_pinned(state, &identity.user_id, target, "the target device")?;
    let ring = load_ring(state, &identity.user_id)?.ok_or_else(|| QGuardError::NotFound("this device has no account key to share".to_string()))?;
    let plain = Zeroizing::new(serde_json::to_vec(&ring).map_err(|e| QGuardError::Storage(format!("account key: {e}")))?);

    let mut wrap = AccountKeyWrap {
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
    state.audit_info("account_key_wrapped", "Account sealing key sealed to another of your devices");
    Ok(wrap)
}

fn accept_wrap(state: &AppState, wrap: &AccountKeyWrap, sender: &CallPeerIdentity) -> Result<AccountKeyStatus> {
    if wrap.v != WRAP_VERSION {
        return Err(QGuardError::InvalidInput("unsupported account key wrap version".to_string()));
    }
    let identity = local_identity(state)?;
    if wrap.user_id != identity.user_id {
        return Err(QGuardError::Trust("the account key wrap is for another account".to_string()));
    }
    if wrap.to_device_id != identity.device_id {
        return Err(QGuardError::Trust("the account key wrap was made for another device".to_string()));
    }
    if sender.device_id == identity.device_id || wrap.from_device_id != sender.device_id {
        return Err(QGuardError::Trust("the account key wrap does not come from the device it names".to_string()));
    }
    require_own_pinned(state, &identity.user_id, sender, "the sending device")?;
    dual_verify(&sender.ed25519_identity_public, &sender.mldsa_identity_public, &wrap_signable(wrap), &wrap.signature)
        .map_err(|_| QGuardError::Trust("the account key wrap signature does not verify".to_string()))?;

    let info = wrap_info(&wrap.from_device_id, &wrap.to_device_id);
    let secret = Zeroizing::new(decapsulate(&identity.kem.x25519_secret, &identity.kem.mlkem_secret, &wrap.ciphertext, info.as_bytes())?);
    let key = Zeroizing::new(derive_32(&*secret, WRAP_SEAL_INFO)?);
    let plain = Zeroizing::new(symmetric::decrypt(&key, &wrap.sealed, &wrap_header(wrap))?);
    let incoming: KeyRing = serde_json::from_slice(&plain).map_err(|_| QGuardError::Crypto("the account key wrap holds no key ring".to_string()))?;
    if incoming.keys.is_empty() || incoming.keys.len() > MAX_EPOCHS || !incoming.keys.contains_key(&incoming.current) {
        return Err(QGuardError::Crypto("the account key wrap holds an inconsistent key ring".to_string()));
    }

    let mut ring = load_ring(state, &identity.user_id)?.unwrap_or_default();
    for (epoch, key) in &incoming.keys {
        match ring.keys.get(epoch) {
            Some(existing) if existing != key => {
                return Err(QGuardError::Trust(format!(
                    "two different account keys exist for epoch {epoch}; fields sealed under the other one stay unavailable"
                )))
            }
            Some(_) => {}
            None => {
                ring.keys.insert(*epoch, *key);
            }
        }
    }
    ring.current = ring.current.max(incoming.current);
    save_ring(state, &identity.user_id, &ring)?;
    state.audit_info("account_key_received", "Account sealing key received from another of your devices");
    Ok(status_of(Some(&ring)))
}

/* ------------------------------------------------------------------ fields -- */

/// A sealed field as stored in a JSONB column. Short names: it is stored per row.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedField {
    pub v: u8,
    pub e: u32,
    pub n: String,
    pub c: String,
}

fn check_purpose(purpose: &str) -> Result<()> {
    if PURPOSES.contains(&purpose) {
        Ok(())
    } else {
        Err(QGuardError::InvalidInput("unknown account field purpose".to_string()))
    }
}

fn check_context(context: &str) -> Result<()> {
    if context.is_empty() || context.len() > MAX_CONTEXT_BYTES {
        return Err(QGuardError::InvalidInput("a sealed field needs a row context of 1-256 bytes".to_string()));
    }
    Ok(())
}

fn field_key(epoch_key: &[u8; 32], purpose: &str) -> Result<Zeroizing<[u8; 32]>> {
    Ok(Zeroizing::new(derive_32(epoch_key, format!("{FIELD_INFO_PREFIX}{purpose}").as_bytes())?))
}

fn field_aad(user_id: &str, purpose: &str, context: &str, epoch: u32) -> Vec<u8> {
    format!("{FIELD_INFO_PREFIX}{user_id}|{purpose}|{context}|{epoch}").into_bytes()
}

fn seal_field(state: &AppState, purpose: &str, context: &str, plaintext: &[u8]) -> Result<SealedField> {
    check_purpose(purpose)?;
    check_context(context)?;
    if plaintext.len() > MAX_FIELD_BYTES {
        return Err(QGuardError::InvalidInput("the field is too large to seal".to_string()));
    }
    let user_id = state.user_id()?;
    let ring = load_ring(state, &user_id)?.ok_or_else(|| QGuardError::NotFound(format!("{UNAVAILABLE}: this device has no account key yet")))?;
    let epoch = ring.current;
    let key = field_key(&ring.keys[&epoch], purpose)?;
    let sealed = symmetric::encrypt(&key, plaintext, &field_aad(&user_id, purpose, context, epoch))?;
    let mut joined = sealed.ciphertext;
    joined.extend_from_slice(&sealed.tag);
    Ok(SealedField { v: FIELD_VERSION, e: epoch, n: b64().encode(&sealed.nonce), c: b64().encode(&joined) })
}

fn open_field(state: &AppState, purpose: &str, context: &str, field: &SealedField) -> Result<Zeroizing<Vec<u8>>> {
    check_purpose(purpose)?;
    check_context(context)?;
    if field.v != FIELD_VERSION {
        return Err(QGuardError::InvalidInput("unsupported sealed field version".to_string()));
    }
    let user_id = state.user_id()?;
    let ring = load_ring(state, &user_id)?.ok_or_else(|| QGuardError::NotFound(format!("{UNAVAILABLE}: this device has no account key yet")))?;
    let epoch_key = ring
        .keys
        .get(&field.e)
        .ok_or_else(|| QGuardError::NotFound(format!("{UNAVAILABLE}: this device does not hold epoch {}", field.e)))?;
    let key = field_key(epoch_key, purpose)?;
    let nonce = b64().decode(&field.n).map_err(|_| QGuardError::InvalidInput("sealed field nonce is not base64".to_string()))?;
    let joined = b64().decode(&field.c).map_err(|_| QGuardError::InvalidInput("sealed field is not base64".to_string()))?;
    if joined.len() < 16 {
        return Err(QGuardError::Crypto("sealed field is too short".to_string()));
    }
    let (ciphertext, tag) = joined.split_at(joined.len() - 16);
    let envelope = EncryptedEnvelope { nonce, ciphertext: ciphertext.to_vec(), tag: tag.to_vec() };
    Ok(Zeroizing::new(symmetric::decrypt(&key, &envelope, &field_aad(&user_id, purpose, context, field.e))?))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenRequest {
    pub purpose: String,
    pub context: String,
    pub field: SealedField,
}

/* ---------------------------------------------------------------- commands -- */

#[tauri::command]
pub fn account_key_status(state: State<'_, AppState>) -> Result<AccountKeyStatus> {
    state.require_auth()?;
    status(&state)
}

#[tauri::command]
pub async fn account_key_bootstrap(state: State<'_, AppState>) -> Result<AccountKeyStatus> {
    state.require_auth()?;
    let _key_scope = state.lock_key_scope()?;
    bootstrap(&state)
}

#[tauri::command]
pub async fn account_key_rotate(state: State<'_, AppState>) -> Result<AccountKeyStatus> {
    let session = state.require_auth()?;
    state.check_decrypt_rate_limit("account_key_rotate", &session.user_id, 10, 300)?;
    let _key_scope = state.lock_key_scope()?;
    rotate(&state)
}

#[tauri::command]
pub async fn account_key_make_wrap(state: State<'_, AppState>, target: CallPeerIdentity) -> Result<AccountKeyWrap> {
    let session = state.require_auth()?;
    state.check_decrypt_rate_limit("account_key_wrap", &session.user_id, 30, 300)?;
    let _key_scope = state.lock_key_scope()?;
    make_wrap(&state, &target)
}

#[tauri::command]
pub async fn account_key_accept_wrap(state: State<'_, AppState>, wrap: AccountKeyWrap, sender: CallPeerIdentity) -> Result<AccountKeyStatus> {
    let session = state.require_auth()?;
    state.check_decrypt_rate_limit("account_key_accept", &session.user_id, 30, 300)?;
    let _key_scope = state.lock_key_scope()?;
    accept_wrap(&state, &wrap, &sender)
}

#[tauri::command]
pub fn account_field_seal(state: State<'_, AppState>, purpose: String, context: String, plaintext: String) -> Result<SealedField> {
    state.require_auth()?;
    seal_field(&state, &purpose, &context, plaintext.as_bytes())
}

/// Open many fields at once. A field that cannot be opened (no key for its
/// epoch yet, wrong row, tampered) comes back `null` — a list must not fail as
/// a whole because one nickname was sealed on a device this one has not heard
/// from yet.
#[tauri::command]
pub fn account_field_open_many(state: State<'_, AppState>, items: Vec<OpenRequest>) -> Result<Vec<Option<String>>> {
    state.require_auth()?;
    if items.len() > MAX_OPEN_BATCH {
        return Err(QGuardError::InvalidInput("too many sealed fields in one request".to_string()));
    }
    Ok(items
        .iter()
        .map(|item| {
            open_field(&state, &item.purpose, &item.context, &item.field)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok())
        })
        .collect())
}

/* ------------------------------------------------------------------- tests -- */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDevice;

    /// A second device of the same account, with each device recording the other
    /// as one of the user's own (what approving a device does).
    fn second_device_of(first: &TestDevice) -> TestDevice {
        let second = TestDevice::open(
            std::env::temp_dir().join(format!("qguard-account-key-{}", uuid::Uuid::new_v4())),
            first.user.clone(),
        );
        pin_each_other(first, &second);
        second
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

    fn cleanup(device: TestDevice) {
        let dir = device.dir.clone();
        drop(device);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_field_sealed_on_one_device_opens_on_a_second_after_the_key_is_wrapped() {
        let first = TestDevice::new(false);
        let second = second_device_of(&first);

        // No key anywhere yet: sealing says so rather than writing plaintext.
        let err = seal_field(&first.state, "contact_alias", "contact-1", b"Mum").unwrap_err().to_string();
        assert!(err.contains(UNAVAILABLE), "{err}");

        assert_eq!(bootstrap(&first.state).unwrap().current_epoch, Some(1));
        let before = bootstrap(&first.state).unwrap();
        assert_eq!(before.epochs, vec![1], "bootstrap is idempotent: it never mints a second key");

        let sealed = seal_field(&first.state, "contact_alias", "contact-1", b"Mum").unwrap();
        assert!(!sealed.c.contains("Mum"));
        assert_eq!(open_field(&first.state, "contact_alias", "contact-1", &sealed).unwrap().as_slice(), b"Mum");

        // The second device cannot read it yet — and says so, not "garbage".
        let err = open_field(&second.state, "contact_alias", "contact-1", &sealed).unwrap_err().to_string();
        assert!(err.contains(UNAVAILABLE), "{err}");

        let wrap = make_wrap(&first.state, &second.call_peer()).unwrap();
        let status = accept_wrap(&second.state, &wrap, &first.call_peer()).unwrap();
        assert_eq!(status.epochs, vec![1]);
        assert_eq!(open_field(&second.state, "contact_alias", "contact-1", &sealed).unwrap().as_slice(), b"Mum");

        // And the other way: sealed on the second, read on the first.
        let back = seal_field(&second.state, "contact_alias", "contact-2", "Dad ✓".as_bytes()).unwrap();
        assert_eq!(open_field(&first.state, "contact_alias", "contact-2", &back).unwrap().as_slice(), "Dad ✓".as_bytes());
        cleanup(second);
        cleanup(first);
    }

    #[test]
    fn a_sealed_field_does_not_open_for_another_row_purpose_account_or_after_tampering() {
        let device = TestDevice::new(false);
        bootstrap(&device.state).unwrap();
        let sealed = seal_field(&device.state, "contact_alias", "contact-1", b"Mum").unwrap();

        assert!(open_field(&device.state, "contact_alias", "contact-2", &sealed).is_err(), "another row");
        assert!(open_field(&device.state, "security_event", "contact-1", &sealed).is_err(), "another purpose");
        assert!(open_field(&device.state, "not-a-purpose", "contact-1", &sealed).is_err(), "unknown purpose");

        let mut flipped = sealed.clone();
        let mut bytes = b64().decode(&flipped.c).unwrap();
        bytes[0] ^= 1;
        flipped.c = b64().encode(&bytes);
        assert!(open_field(&device.state, "contact_alias", "contact-1", &flipped).is_err(), "bit flip");
        let mut other_epoch = sealed.clone();
        other_epoch.e = 9;
        assert!(open_field(&device.state, "contact_alias", "contact-1", &other_epoch).is_err(), "unknown epoch");

        // Another account's device with its own key cannot open it either.
        let stranger = TestDevice::new(false);
        bootstrap(&stranger.state).unwrap();
        assert!(open_field(&stranger.state, "contact_alias", "contact-1", &sealed).is_err());

        // Each seal uses a fresh nonce.
        let again = seal_field(&device.state, "contact_alias", "contact-1", b"Mum").unwrap();
        assert_ne!(again.n, sealed.n);
        assert_ne!(again.c, sealed.c);
        cleanup(stranger);
        cleanup(device);
    }

    #[test]
    fn a_wrap_is_refused_unless_both_devices_are_pinned_own_devices_and_it_is_untouched() {
        let first = TestDevice::new(false);
        bootstrap(&first.state).unwrap();

        // A device of the account that this one has not recorded: no wrap made.
        let unpinned = TestDevice::open(
            std::env::temp_dir().join(format!("qguard-account-key-{}", uuid::Uuid::new_v4())),
            first.user.clone(),
        );
        assert!(make_wrap(&first.state, &unpinned.call_peer()).is_err(), "the relay merely listing a device is not enough");
        // A device of another account: no wrap made.
        let stranger = TestDevice::new(false);
        assert!(make_wrap(&first.state, &stranger.call_peer()).is_err());
        // Not for itself.
        assert!(make_wrap(&first.state, &first.call_peer()).is_err());

        pin_each_other(&first, &unpinned);
        let wrap = make_wrap(&first.state, &unpinned.call_peer()).unwrap();

        // The recipient refuses a wrap from a sender it has not pinned.
        let impostor = TestDevice::open(
            std::env::temp_dir().join(format!("qguard-account-key-{}", uuid::Uuid::new_v4())),
            first.user.clone(),
        );
        assert!(accept_wrap(&unpinned.state, &wrap, &impostor.call_peer()).is_err(), "named sender mismatch");
        // Tampering with any signed field breaks the signature.
        let mut tampered = wrap.clone();
        tampered.epoch = 7;
        assert!(accept_wrap(&unpinned.state, &tampered, &first.call_peer()).is_err());
        let mut redirected = wrap.clone();
        redirected.to_device_id = impostor.device_id.clone();
        assert!(accept_wrap(&unpinned.state, &redirected, &first.call_peer()).is_err());
        // A wrap made for one device does not open on another.
        pin_each_other(&first, &impostor);
        assert!(accept_wrap(&impostor.state, &wrap, &first.call_peer()).is_err());
        // The honest path works, and accepting twice changes nothing.
        accept_wrap(&unpinned.state, &wrap, &first.call_peer()).unwrap();
        assert_eq!(accept_wrap(&unpinned.state, &wrap, &first.call_peer()).unwrap().epochs, vec![1]);
        // A wrap cannot be replayed onto a different account's device.
        assert!(accept_wrap(&stranger.state, &wrap, &first.call_peer()).is_err());
        for d in [unpinned, impostor, stranger, first] {
            cleanup(d);
        }
    }

    #[test]
    fn a_removed_device_never_gets_the_next_epoch_and_old_fields_still_open() {
        let first = TestDevice::new(false);
        let second = second_device_of(&first);
        let third = second_device_of(&first);
        pin_each_other(&second, &third);
        bootstrap(&first.state).unwrap();
        let old_field = seal_field(&first.state, "security_event", "evt-1", b"{\"x\":1}").unwrap();
        for target in [&second, &third] {
            let wrap = make_wrap(&first.state, &target.call_peer()).unwrap();
            accept_wrap(&target.state, &wrap, &first.call_peer()).unwrap();
        }

        // The third device is removed: rotate, and wrap only for the second.
        let rotated = rotate(&first.state).unwrap();
        assert_eq!(rotated.current_epoch, Some(2));
        assert_eq!(rotated.epochs, vec![1, 2]);
        let wrap = make_wrap(&first.state, &second.call_peer()).unwrap();
        assert_eq!(wrap.epoch, 2);
        accept_wrap(&second.state, &wrap, &first.call_peer()).unwrap();

        let new_field = seal_field(&second.state, "security_event", "evt-2", b"{\"x\":2}").unwrap();
        assert_eq!(new_field.e, 2);
        assert_eq!(open_field(&first.state, "security_event", "evt-2", &new_field).unwrap().as_slice(), b"{\"x\":2}");
        assert!(open_field(&third.state, "security_event", "evt-2", &new_field).is_err(), "the removed device cannot read new fields");
        // Older fields keep opening everywhere that held epoch 1.
        assert_eq!(open_field(&second.state, "security_event", "evt-1", &old_field).unwrap().as_slice(), b"{\"x\":1}");
        for d in [third, second, first] {
            cleanup(d);
        }
    }

    #[test]
    fn two_different_keys_for_the_same_epoch_are_refused_not_merged() {
        let first = TestDevice::new(false);
        let second = second_device_of(&first);
        bootstrap(&first.state).unwrap();
        bootstrap(&second.state).unwrap(); // both thought they were first
        let wrap = make_wrap(&first.state, &second.call_peer()).unwrap();
        let err = accept_wrap(&second.state, &wrap, &first.call_peer()).unwrap_err().to_string();
        assert!(err.contains("two different account keys"), "{err}");
        // The second device keeps what it had.
        let sealed = seal_field(&second.state, "telemetry", "t-1", b"x").unwrap();
        assert!(open_field(&first.state, "telemetry", "t-1", &sealed).is_err());
        cleanup(second);
        cleanup(first);
    }

    #[test]
    fn the_key_ring_is_encrypted_on_disk_and_survives_a_restart() {
        let device = TestDevice::new(false);
        bootstrap(&device.state).unwrap();
        let sealed = seal_field(&device.state, "message_state", "m-1", b"proof").unwrap();
        let raw_key = {
            let ring = load_ring(&device.state, &device.user).unwrap().unwrap();
            ring.keys[&1]
        };
        // The key is not on disk in any readable form: not as raw bytes, and not
        // as the JSON the ring is serialised to before it is sealed (which would
        // show as field names and a decimal byte list).
        let as_json = serde_json::to_string(&raw_key.to_vec()).unwrap();
        let first_bytes = as_json.trim_matches(|c| c == '[' || c == ']').split(',').take(8).collect::<Vec<_>>().join(",");
        fn walk(dir: &std::path::Path, needle: &[u8], hits: &mut usize) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        walk(&path, needle, hits);
                    } else if let Ok(bytes) = std::fs::read(&path) {
                        if bytes.windows(needle.len()).any(|w| w == needle) {
                            *hits += 1;
                        }
                    }
                }
            }
        }
        let doc_path = device.dir.join("keys").join(format!("{}.account-key.enc", AppState::safe_user_key(&device.user)));
        assert!(doc_path.exists(), "the key ring is stored in its own sealed file: {doc_path:?}");
        for needle in [&raw_key[..], first_bytes.as_bytes(), b"\"current\"", b"\"keys\""] {
            let mut hits = 0;
            walk(&device.dir, needle, &mut hits);
            assert_eq!(hits, 0, "the account key must not appear in the clear on disk ({:?})", String::from_utf8_lossy(needle));
        }
        // Control: the search does find a plaintext copy, so a pass above means something.
        let planted = device.dir.join("planted.txt");
        std::fs::write(&planted, as_json.as_bytes()).unwrap();
        let mut control = 0;
        walk(&device.dir, first_bytes.as_bytes(), &mut control);
        assert_eq!(control, 1, "the search finds a plaintext copy");
        std::fs::remove_file(&planted).unwrap();

        let device = device.restart();
        assert_eq!(open_field(&device.state, "message_state", "m-1", &sealed).unwrap().as_slice(), b"proof");
        cleanup(device);
    }
}
