//! Verified contacts and call challenge phrases (roadmap Phase 3; design:
//! `docs/superpowers/specs/2026-10-16-call-verification-design.md`).
//!
//! WHY THIS EXISTS
//! ---------------------------------------------------------------------------
//! A call's safety number defends the key exchange against a man in the
//! middle. It says nothing about WHO holds the other device: a scammer with a
//! cloned voice on a hijacked account, or on a device the directory added,
//! reads their digits just as well. Voice is no longer evidence.
//!
//! This adds a check an impostor cannot pass without the real contact's
//! device:
//!
//!   1. The user verifies a contact's device here — compares the safety number
//!      out of band and says it matched. That is recorded in this device's own
//!      encrypted device record (`device_pins`), never taken from the relay.
//!   2. Each side then seals a random half to the other's VERIFIED identity
//!      keys (hybrid X25519 + ML-KEM-1024, dual-signed). With both halves
//!      held, each device derives the same pair secret.
//!   3. During a call each side can show a four-word phrase derived from the
//!      pair secret, the call id and the current 30-second window. One person
//!      asks, the other reads THEIR screen, the first compares with theirs. The
//!      app never sends a phrase, so there is nothing on the wire to copy, and
//!      a phrase heard in one call is useless in any other.
//!
//! WHAT IT DOES NOT PROVE
//! ---------------------------------------------------------------------------
//! Possession of the verified contact's device — not the human holding it, and
//! nothing about whether audio is synthetic. The UI says exactly that.

use std::sync::OnceLock;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroizing;

use crate::commands::calls::{local_identity, validate_call_id, CallPeerIdentity};
use crate::crypto::hybrid_kex::{decapsulate, encapsulate_bound};
use crate::crypto::kdf::sha3_256;
use crate::crypto::signatures::{dual_sign, dual_verify};
use crate::crypto::{DualSignature, HybridCiphertext};
use crate::device_pins::{
    identity_digest, DeviceStanding, HalfReceived, PairingHalf, VerificationMethod, VerificationView,
};
use crate::error::{QGuardError, Result};
use crate::fingerprints::conversation_safety_number;
use crate::identity::{platform_device_label, safety_fingerprint, LocalIdentity};
use crate::state::AppState;

/// The embedded word list: 1024 words, 5–6 letters, every first four letters
/// unique. Our own list, so there is no licensing question.
const WORD_LIST: &str = include_str!("../call_words.txt");
/// Phrases change every 30 seconds; a comparison accepts the window before and
/// after the current one for clock skew.
pub const PHRASE_WINDOW_SECS: i64 = 30;
const PHRASE_WORDS: usize = 4;
const PHRASE_CONTEXT: &[u8] = b"QGuard-CallPhrase-v1";
const PAIR_SECRET_CONTEXT: &[u8] = b"QGuard-CallPairing-v1";
const OFFER_CONTEXT: &[u8] = b"QGuard-CallPairing-Offer-v1";
const PAIRING_KEM_INFO: &str = "QGuard-CallPairing-v1:kem:";
const OFFER_VERSION: u8 = 1;
/// An offer may be delivered late, but not this late (milliseconds).
const MAX_OFFER_AGE_MS: i64 = 30 * 24 * 3600 * 1000;
/// Nor dated this far in the future (clock skew allowance).
const MAX_OFFER_SKEW_MS: i64 = 10 * 60 * 1000;

pub(crate) fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| WORD_LIST.lines().map(str::trim).filter(|line| !line.is_empty()).collect())
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// Where the call pairing with a device stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingState {
    /// Nothing exchanged yet.
    None,
    /// Our half is sealed to them; theirs has not arrived (they have not
    /// verified us yet, or not opened the conversation since).
    WaitingForThem,
    /// Their half arrived, but we have not verified them here.
    NeedsYourVerification,
    /// Both halves held and verified here: a call phrase can be shown.
    Paired,
}

impl PairingState {
    fn of(view: Option<&VerificationView>) -> Self {
        let Some(view) = view else { return Self::None };
        match (view.verified.is_some(), view.sent, view.received) {
            (true, true, true) => Self::Paired,
            (true, true, false) => Self::WaitingForThem,
            (false, _, true) => Self::NeedsYourVerification,
            _ => Self::None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactVerificationStatus {
    pub user_id: String,
    pub device_id: String,
    /// `pinned`, `new`, `key_changed`, or `unknown` (record unreadable / never seen).
    pub standing: String,
    /// The number both people compare, computed here from the two devices' keys.
    pub safety_number: String,
    /// The contact device's fingerprint, computed here from its keys.
    pub fingerprint: String,
    pub verified_at: Option<i64>,
    pub method: Option<VerificationMethod>,
    pub pairing: PairingState,
}

fn standing_label(standing: Option<DeviceStanding>) -> &'static str {
    match standing {
        Some(DeviceStanding::Pinned) => "pinned",
        Some(DeviceStanding::New) => "new",
        Some(DeviceStanding::KeyChanged) => "key_changed",
        None => "unknown",
    }
}

fn status_for(state: &AppState, peer: &CallPeerIdentity) -> Result<ContactVerificationStatus> {
    peer.verify()?;
    let user_id = state.user_id()?;
    let local = state.ensure_identity(&user_id, platform_device_label())?;
    if peer.user_id == user_id && peer.device_id == local.device_id {
        return Err(QGuardError::InvalidInput("this is your own device".to_string()));
    }
    let fingerprint = safety_fingerprint(&peer.ed25519_identity_public, &peer.mldsa_identity_public);
    let safety = conversation_safety_number(&local.fingerprint, &fingerprint);
    let subject = peer.pin_subject();
    let (standing, view) = state.with_device_pins(&user_id, |book| (book.standing(&subject), book.verification(&subject)))?;
    Ok(ContactVerificationStatus {
        user_id: peer.user_id.clone(),
        device_id: peer.device_id.clone(),
        standing: standing_label(standing).to_string(),
        safety_number: safety.display,
        fingerprint,
        verified_at: view.and_then(|view| view.verified).map(|verified| verified.at),
        method: view.and_then(|view| view.verified).map(|verified| verified.method),
        pairing: PairingState::of(view.as_ref()),
    })
}

/// Safety numbers compared as people see them: case, spaces and dashes aside.
fn normalized(number: &str) -> String {
    number.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_uppercase()).collect()
}

fn mark_verified(
    state: &AppState,
    peer: &CallPeerIdentity,
    confirmed_safety_number: &str,
    method: VerificationMethod,
) -> Result<ContactVerificationStatus> {
    let status = status_for(state, peer)?;
    // The number the user confirmed must be the one these keys produce NOW —
    // a stale screen, or a number for other keys, verifies nothing.
    if normalized(confirmed_safety_number) != normalized(&status.safety_number) || normalized(confirmed_safety_number).is_empty() {
        return Err(QGuardError::Trust(
            "the safety number confirmed is not the one this device's keys produce; nothing was marked verified".to_string(),
        ));
    }
    let user_id = state.user_id()?;
    let subject = peer.pin_subject();
    let now = Utc::now().timestamp();
    state.with_device_pins(&user_id, |book| book.mark_verified(&subject, method, now))??;
    state.audit_info("contact_verified", "A contact device was verified on this device (safety number compared)");
    status_for(state, peer)
}

fn clear_verification(state: &AppState, peer: &CallPeerIdentity) -> Result<ContactVerificationStatus> {
    peer.verify()?;
    let user_id = state.user_id()?;
    let subject = peer.pin_subject();
    if state.with_device_pins(&user_id, |book| book.clear_verification(&subject))? {
        state.audit_info("contact_verification_removed", "A contact device's verification and call pairing were removed on this device");
    }
    status_for(state, peer)
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

/// One side's half of a call pairing, delivered to the other device as a
/// control message over the existing end-to-end encrypted channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingOffer {
    pub v: u8,
    pub offer_id: String,
    pub created_at: i64,
    pub from_user_id: String,
    pub from_device_id: String,
    pub to_user_id: String,
    pub to_device_id: String,
    pub ciphertext: HybridCiphertext,
    /// Whether the sender already holds the recipient's half. False asks the
    /// recipient to (re)send theirs.
    pub have_yours: bool,
    pub signature: DualSignature,
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

fn offer_signable(offer: &PairingOffer) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    push_field(&mut ciphertext, &offer.ciphertext.x25519_ephemeral_public);
    push_field(&mut ciphertext, &offer.ciphertext.ml_kem_ciphertext);
    push_field(&mut ciphertext, offer.ciphertext.suite.kem_combiner.as_bytes());
    let mut out = Vec::new();
    for field in [
        OFFER_CONTEXT,
        &[offer.v],
        offer.offer_id.as_bytes(),
        &offer.created_at.to_be_bytes(),
        offer.from_user_id.as_bytes(),
        offer.from_device_id.as_bytes(),
        offer.to_user_id.as_bytes(),
        offer.to_device_id.as_bytes(),
        &sha3_256(&ciphertext),
        &[u8::from(offer.have_yours)],
    ] {
        push_field(&mut out, field);
    }
    out
}

fn pairing_kem_info(offer_id: &str, from_device: &str, to_device: &str) -> String {
    format!("{PAIRING_KEM_INFO}{offer_id}:{from_device}:{to_device}")
}

fn create_offer(state: &AppState, peer: &CallPeerIdentity) -> Result<PairingOffer> {
    let status = status_for(state, peer)?;
    if status.verified_at.is_none() {
        return Err(QGuardError::Trust(
            "verify this contact's device first; no call pairing is made with an unverified device".to_string(),
        ));
    }
    let identity = local_identity(state)?;
    let offer_id = hex::encode(crate::crypto::provider::random_array::<16>());
    // Milliseconds: offers are ordered by it, and two in one second must not
    // read as a replay of each other.
    let created_at = Utc::now().timestamp_millis();
    let info = pairing_kem_info(&offer_id, &identity.device_id, &peer.device_id);
    let (ciphertext, secret) = encapsulate_bound(&peer.x25519_identity_public, &peer.mlkem_identity_public, info.as_bytes())?;
    let secret = Zeroizing::new(secret);
    let mut offer = PairingOffer {
        v: OFFER_VERSION,
        offer_id: offer_id.clone(),
        created_at,
        from_user_id: identity.user_id.clone(),
        from_device_id: identity.device_id.clone(),
        to_user_id: peer.user_id.clone(),
        to_device_id: peer.device_id.clone(),
        ciphertext,
        have_yours: state
            .with_device_pins(&identity.user_id, |book| book.verification(&peer.pin_subject()).is_some_and(|view| view.received))?,
        signature: DualSignature { ed25519: Vec::new(), ml_dsa_65: Vec::new() },
    };
    offer.signature = dual_sign(&identity.signing.ed25519_secret, &identity.signing.mldsa_secret, &offer_signable(&offer))?;
    let subject = peer.pin_subject();
    state.with_device_pins(&identity.user_id, |book| {
        book.record_sent_half(&subject, PairingHalf { offer_id, created_at, secret: *secret })
    })??;
    state.audit_info("contact_pairing_offer_created", "Call-pairing half sealed to a verified contact device");
    Ok(offer)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingReceipt {
    pub status: ContactVerificationStatus,
    /// The sender lacks our half (or we never sent one): send a fresh offer.
    pub reply_needed: bool,
}

fn receive_offer(state: &AppState, offer: &PairingOffer, sender: &CallPeerIdentity) -> Result<PairingReceipt> {
    if offer.v != OFFER_VERSION {
        return Err(QGuardError::InvalidInput("unsupported call-pairing offer version".to_string()));
    }
    if offer.offer_id.len() != 32 || !offer.offer_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(QGuardError::InvalidInput("malformed call-pairing offer id".to_string()));
    }
    sender.verify()?;
    let identity = local_identity(state)?;
    if offer.from_user_id != sender.user_id || offer.from_device_id != sender.device_id {
        return Err(QGuardError::Trust("call-pairing offer does not come from the device it names".to_string()));
    }
    if offer.to_user_id != identity.user_id || offer.to_device_id != identity.device_id {
        return Err(QGuardError::Trust("call-pairing offer was made for another device".to_string()));
    }
    let now = Utc::now().timestamp_millis();
    if offer.created_at > now + MAX_OFFER_SKEW_MS || now.saturating_sub(offer.created_at) > MAX_OFFER_AGE_MS {
        return Err(QGuardError::Replay("call-pairing offer is outside its validity window".to_string()));
    }
    dual_verify(
        &sender.ed25519_identity_public,
        &sender.mldsa_identity_public,
        &offer_signable(offer),
        &offer.signature,
    )
    .map_err(|_| QGuardError::Trust("call-pairing offer signature does not verify; refusing it".to_string()))?;
    let info = pairing_kem_info(&offer.offer_id, &offer.from_device_id, &offer.to_device_id);
    let secret = Zeroizing::new(decapsulate(
        &identity.kem.x25519_secret,
        &identity.kem.mlkem_secret,
        &offer.ciphertext,
        info.as_bytes(),
    )?);
    let subject = sender.pin_subject();
    // Stored only for a device whose keys are the recorded ones; USED only once
    // the user has verified it (see `DevicePinBook::record_received_half`).
    let outcome = state.with_device_pins(&identity.user_id, |book| {
        book.record_received_half(
            &subject,
            PairingHalf { offer_id: offer.offer_id.clone(), created_at: offer.created_at, secret: *secret },
        )
    })??;
    let status = status_for(state, sender)?;
    let we_sent = state
        .with_device_pins(&identity.user_id, |book| book.verification(&subject).is_some_and(|view| view.sent))?;
    if outcome == HalfReceived::Stored {
        state.audit_info(
            if status.pairing == PairingState::Paired { "contact_pairing_established" } else { "contact_pairing_half_received" },
            "Call-pairing half received from a recorded contact device",
        );
    }
    // Reply when we have verified them and they lack our half — judged on a
    // NEWLY stored offer only: history replays old offers on every load, and
    // their stale "have_yours: false" must not make us send again each time.
    let reply_needed =
        status.verified_at.is_some() && (!we_sent || (outcome == HalfReceived::Stored && !offer.have_yours));
    Ok(PairingReceipt { reply_needed, status })
}

// ---------------------------------------------------------------------------
// Phrase
// ---------------------------------------------------------------------------

/// The pair secret with `peer_device`, when both halves are held and the user
/// verified that device here.
fn pair_secret(state: &AppState, identity: &LocalIdentity, peer_user: &str, peer_device: &str) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let (halves, peer_digest) = state.with_device_pins(&identity.user_id, |book| {
        (
            book.pairing_halves(peer_user, peer_device),
            book.pin(peer_user, peer_device).map(|pin| pin.digest.clone()),
        )
    })?;
    let (Some((sent, received)), Some(peer_digest)) = (halves, peer_digest) else {
        return Ok(None);
    };
    let own_digest = identity_digest(
        &identity.signing.ed25519_public,
        &identity.signing.mldsa_public,
        &identity.kem.x25519_public,
        &identity.kem.mlkem_public,
    );
    // Ordered by device id, so both sides frame the same bytes: the lower
    // device's half (the one IT sent) first.
    let local_is_low = identity.device_id.as_str() < peer_device;
    let (low_device, high_device, low_digest, high_digest, low_half, high_half) = if local_is_low {
        (identity.device_id.as_str(), peer_device, own_digest.as_str(), peer_digest.as_str(), &sent, &received)
    } else {
        (peer_device, identity.device_id.as_str(), peer_digest.as_str(), own_digest.as_str(), &received, &sent)
    };
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(&low_half.secret);
    ikm.extend_from_slice(&high_half.secret);
    let mut info = Vec::new();
    for field in [PAIR_SECRET_CONTEXT, low_device.as_bytes(), high_device.as_bytes(), low_digest.as_bytes(), high_digest.as_bytes()] {
        push_field(&mut info, field);
    }
    let derived = crate::crypto::kdf::derive_32(&ikm, &info)?;
    Ok(Some(Zeroizing::new(derived)))
}

/// Four words for `(pair secret, call id, window)`.
pub(crate) fn phrase_for(secret: &[u8; 32], call_id: &str, window: i64) -> Result<Vec<String>> {
    let mut message = Vec::new();
    push_field(&mut message, PHRASE_CONTEXT);
    push_field(&mut message, call_id.as_bytes());
    push_field(&mut message, &window.to_be_bytes());
    let digest = crate::crypto::provider::hmac_sha3_256(secret, &message)
        .map_err(|_| QGuardError::Crypto("call phrase key rejected".to_string()))?;
    // 40 bits: four 10-bit indices into the 1024-word list.
    let mut bits: u64 = 0;
    for byte in digest.iter().take(5) {
        bits = (bits << 8) | u64::from(*byte);
    }
    let list = words();
    Ok((0..PHRASE_WORDS)
        .map(|index| list[((bits >> (30 - 10 * index)) & 0x3ff) as usize].to_string())
        .collect())
}

fn window_at(now: i64) -> i64 {
    now.div_euclid(PHRASE_WINDOW_SECS)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallPhrase {
    /// Empty when there is no pairing (see `pairing`).
    pub words: Vec<String>,
    pub seconds_left: i64,
    pub pairing: PairingState,
    pub verified_at: Option<i64>,
}

fn phrase_now(state: &AppState, peer_user: &str, peer_device: &str, call_id: &str, now: i64) -> Result<CallPhrase> {
    validate_call_id(call_id)?;
    let identity = local_identity(state)?;
    let view = state.with_device_pins(&identity.user_id, |book| book.verification_by_id(peer_user, peer_device))?;
    let pairing = PairingState::of(view.as_ref());
    let verified_at = view.and_then(|view| view.verified).map(|verified| verified.at);
    let seconds_left = PHRASE_WINDOW_SECS - now.rem_euclid(PHRASE_WINDOW_SECS);
    let words = match pair_secret(state, &identity, peer_user, peer_device)? {
        Some(secret) => phrase_for(&secret, call_id, window_at(now))?,
        None => Vec::new(),
    };
    Ok(CallPhrase { words, seconds_left, pairing, verified_at })
}

fn phrase_matches(state: &AppState, peer_user: &str, peer_device: &str, call_id: &str, spoken: &str, now: i64) -> Result<bool> {
    validate_call_id(call_id)?;
    let identity = local_identity(state)?;
    let Some(secret) = pair_secret(state, &identity, peer_user, peer_device)? else {
        return Err(QGuardError::Trust("there is no call pairing with this device, so no phrase can be checked".to_string()));
    };
    let spoken: Vec<String> = spoken
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|word| !word.is_empty())
        .map(|word| word.to_ascii_lowercase())
        .collect();
    if spoken.len() != PHRASE_WORDS {
        return Ok(false);
    }
    let current = window_at(now);
    for window in [current - 1, current, current + 1] {
        // Every list word has a unique four-letter start, so a mis-typed ending
        // still names exactly one word.
        let expected = phrase_for(&secret, call_id, window)?;
        if expected.iter().zip(&spoken).all(|(want, got)| got.len() >= 4 && want.starts_with(got.as_str())) {
            return Ok(true);
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// What a call can say about the person
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactAssurance {
    /// The device id is in this device's record for that person.
    pub recorded: bool,
    pub verified_at: Option<i64>,
    pub pairing: PairingState,
}

/// By ids: for an incoming ring, before the caller's keys have been checked.
/// It says only what this device's record holds for that id; the call setup
/// then checks the keys (a device presenting other keys is refused).
fn assurance_by_id(state: &AppState, peer_user: &str, peer_device: &str) -> Result<ContactAssurance> {
    let user_id = state.user_id()?;
    let view = state.with_device_pins(&user_id, |book| book.verification_by_id(peer_user, peer_device))?;
    Ok(ContactAssurance {
        recorded: view.is_some(),
        verified_at: view.and_then(|view| view.verified).map(|verified| verified.at),
        pairing: PairingState::of(view.as_ref()),
    })
}

/// For a call setup that has the peer's keys in hand: the user's verification
/// of exactly those keys, if any.
pub(crate) fn verification_of(state: &AppState, peer: &CallPeerIdentity) -> (Option<i64>, bool) {
    let Ok(user_id) = state.user_id() else { return (None, false) };
    let subject = peer.pin_subject();
    state
        .with_device_pins(&user_id, |book| book.verification(&subject))
        .ok()
        .flatten()
        .map(|view| (view.verified.map(|verified| verified.at), view.paired()))
        .unwrap_or((None, false))
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn contact_verification_status(state: State<'_, AppState>, peer: CallPeerIdentity) -> Result<ContactVerificationStatus> {
    state.require_auth()?;
    let _key_scope = state.lock_key_scope()?;
    status_for(&state, &peer)
}

#[tauri::command]
pub async fn contact_mark_verified(
    state: State<'_, AppState>,
    peer: CallPeerIdentity,
    safety_number: String,
    method: VerificationMethod,
) -> Result<ContactVerificationStatus> {
    let session = state.require_auth()?;
    state.check_decrypt_rate_limit("contact_mark_verified", &session.user_id, 30, 300)?;
    let _key_scope = state.lock_key_scope()?;
    mark_verified(&state, &peer, &safety_number, method)
}

#[tauri::command]
pub async fn contact_clear_verification(state: State<'_, AppState>, peer: CallPeerIdentity) -> Result<ContactVerificationStatus> {
    state.require_auth()?;
    let _key_scope = state.lock_key_scope()?;
    clear_verification(&state, &peer)
}

#[tauri::command]
pub async fn contact_pairing_offer(state: State<'_, AppState>, peer: CallPeerIdentity) -> Result<PairingOffer> {
    let session = state.require_auth()?;
    state.check_decrypt_rate_limit("contact_pairing_offer", &session.user_id, 30, 300)?;
    let _key_scope = state.lock_key_scope()?;
    create_offer(&state, &peer)
}

#[tauri::command]
pub async fn contact_pairing_receive(
    state: State<'_, AppState>,
    offer: PairingOffer,
    sender: CallPeerIdentity,
) -> Result<PairingReceipt> {
    let session = state.require_auth()?;
    state.check_decrypt_rate_limit("contact_pairing_receive", &session.user_id, 60, 300)?;
    let _key_scope = state.lock_key_scope()?;
    receive_offer(&state, &offer, &sender)
}

#[tauri::command]
pub fn contact_assurance(state: State<'_, AppState>, peer_user_id: String, peer_device_id: String) -> Result<ContactAssurance> {
    state.require_auth()?;
    assurance_by_id(&state, &peer_user_id, &peer_device_id)
}

#[tauri::command]
pub async fn call_phrase(
    state: State<'_, AppState>,
    peer_user_id: String,
    peer_device_id: String,
    call_id: String,
) -> Result<CallPhrase> {
    state.require_auth()?;
    let _key_scope = state.lock_key_scope()?;
    let phrase = phrase_now(&state, &peer_user_id, &peer_device_id, &call_id, Utc::now().timestamp())?;
    if !phrase.words.is_empty() {
        // Never the phrase or the secret: only that one was shown.
        state.audit_info("call_phrase_challenge_shown", "A call challenge phrase was shown for a verified contact");
    }
    Ok(phrase)
}

#[tauri::command]
pub async fn call_phrase_check(
    state: State<'_, AppState>,
    peer_user_id: String,
    peer_device_id: String,
    call_id: String,
    spoken: String,
) -> Result<bool> {
    let session = state.require_auth()?;
    // One live guess at a time is the design assumption; this keeps it so.
    state.check_decrypt_rate_limit("call_phrase_check", &session.user_id, 10, 60)?;
    let _key_scope = state.lock_key_scope()?;
    let matched = phrase_matches(&state, &peer_user_id, &peer_device_id, &call_id, &spoken, Utc::now().timestamp())?;
    state.audit_info(
        "call_phrase_checked",
        if matched { "Call challenge phrase matched" } else { "Call challenge phrase did NOT match" },
    );
    Ok(matched)
}

/// Test-only: `a` and `b` record each other's devices (first use) and each
/// verifies the other, as two people comparing safety numbers would.
#[cfg(test)]
pub(crate) fn verify_each_other_for_test(a: &crate::test_support::TestDevice, b: &crate::test_support::TestDevice) {
    for (me, them) in [(a, b), (b, a)] {
        let subject = them.call_peer().pin_subject();
        me.state.with_device_pins(&me.user, |book| book.assess(&[subject], 1)).unwrap();
    }
    for (me, them) in [(a, b), (b, a)] {
        let number = status_for(&me.state, &them.call_peer()).unwrap().safety_number;
        mark_verified(&me.state, &them.call_peer(), &number, VerificationMethod::SafetyNumber).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDevice;

    fn approve_each_other(a: &TestDevice, b: &TestDevice) {
        // First use: each records the other's device as listed.
        a.state
            .with_device_pins(&a.user, |book| book.assess(&[b.call_peer().pin_subject()], 1))
            .unwrap();
        b.state
            .with_device_pins(&b.user, |book| book.assess(&[a.call_peer().pin_subject()], 1))
            .unwrap();
    }

    fn verify(a: &TestDevice, b: &TestDevice) {
        let number = status_for(&a.state, &b.call_peer()).unwrap().safety_number;
        mark_verified(&a.state, &b.call_peer(), &number, VerificationMethod::SafetyNumber).unwrap();
    }

    /// Alice and Bob verify each other and exchange halves, as the app does.
    fn paired_pair() -> (TestDevice, TestDevice) {
        let alice = TestDevice::new(false);
        let bob = TestDevice::new(false);
        approve_each_other(&alice, &bob);
        verify(&alice, &bob);
        let from_alice = create_offer(&alice.state, &bob.call_peer()).unwrap();
        assert!(!from_alice.have_yours);
        // Bob has not verified Alice yet: her half is held, not used.
        let receipt = receive_offer(&bob.state, &from_alice, &alice.call_peer()).unwrap();
        assert_eq!(receipt.status.pairing, PairingState::NeedsYourVerification);
        assert!(!receipt.reply_needed);
        verify(&bob, &alice);
        let from_bob = create_offer(&bob.state, &alice.call_peer()).unwrap();
        assert!(from_bob.have_yours, "Bob holds Alice's half");
        let receipt = receive_offer(&alice.state, &from_bob, &bob.call_peer()).unwrap();
        assert_eq!(receipt.status.pairing, PairingState::Paired);
        assert!(!receipt.reply_needed, "Bob already has Alice's half");
        assert_eq!(status_for(&bob.state, &alice.call_peer()).unwrap().pairing, PairingState::Paired);
        (alice, bob)
    }

    #[test]
    fn the_word_list_is_1024_unique_words_with_unique_four_letter_starts() {
        let list = words();
        assert_eq!(list.len(), 1024);
        let unique: std::collections::HashSet<_> = list.iter().collect();
        assert_eq!(unique.len(), 1024);
        let prefixes: std::collections::HashSet<_> = list.iter().map(|word| &word[..4]).collect();
        assert_eq!(prefixes.len(), 1024, "no two words may share their first four letters");
        assert!(list.iter().all(|word| word.len() >= 4 && word.bytes().all(|byte| byte.is_ascii_lowercase())));
    }

    #[test]
    fn both_sides_see_the_same_phrase_and_it_is_bound_to_call_and_time() {
        let (alice, bob) = paired_pair();
        let now = 1_800_000_015;
        let a = phrase_now(&alice.state, &bob.user, &bob.device_id, "call-1", now).unwrap();
        let b = phrase_now(&bob.state, &alice.user, &alice.device_id, "call-1", now).unwrap();
        assert_eq!(a.words.len(), 4);
        assert_eq!(a.words, b.words, "the two devices must derive the same phrase");
        assert_eq!(a.pairing, PairingState::Paired);
        assert_eq!(a.seconds_left, 15);

        // Negative controls: another call, another window.
        assert_ne!(phrase_now(&alice.state, &bob.user, &bob.device_id, "call-2", now).unwrap().words, a.words);
        assert_ne!(phrase_now(&alice.state, &bob.user, &bob.device_id, "call-1", now + 30).unwrap().words, a.words);

        // ±1 window accepted, ±2 not; typing only the first four letters is enough.
        let spoken = a.words.join(" ");
        assert!(phrase_matches(&bob.state, &alice.user, &alice.device_id, "call-1", &spoken, now).unwrap());
        assert!(phrase_matches(&bob.state, &alice.user, &alice.device_id, "call-1", &spoken, now + 30).unwrap());
        assert!(phrase_matches(&bob.state, &alice.user, &alice.device_id, "call-1", &spoken, now - 30).unwrap());
        assert!(!phrase_matches(&bob.state, &alice.user, &alice.device_id, "call-1", &spoken, now + 60).unwrap());
        let short: Vec<String> = a.words.iter().map(|word| word[..4].to_uppercase()).collect();
        assert!(phrase_matches(&bob.state, &alice.user, &alice.device_id, "call-1", &short.join("-"), now).unwrap());
        assert!(!phrase_matches(&bob.state, &alice.user, &alice.device_id, "call-2", &spoken, now).unwrap(), "replayed in another call");
        assert!(!phrase_matches(&bob.state, &alice.user, &alice.device_id, "call-1", "able able able able", now).unwrap());
        assert!(!phrase_matches(&bob.state, &alice.user, &alice.device_id, "call-1", &a.words[..3].join(" "), now).unwrap());
    }

    #[test]
    fn a_different_secret_gives_a_different_phrase() {
        let one = phrase_for(&[1; 32], "call", 7).unwrap();
        assert_ne!(one, phrase_for(&[2; 32], "call", 7).unwrap());
        assert_eq!(one, phrase_for(&[1; 32], "call", 7).unwrap());
    }

    #[test]
    fn nothing_is_shown_without_verification_and_both_halves() {
        let alice = TestDevice::new(false);
        let bob = TestDevice::new(false);
        approve_each_other(&alice, &bob);
        let phrase = phrase_now(&alice.state, &bob.user, &bob.device_id, "c", 0).unwrap();
        assert!(phrase.words.is_empty());
        assert_eq!(phrase.pairing, PairingState::None);
        assert!(create_offer(&alice.state, &bob.call_peer()).is_err(), "no pairing with an unverified device");
        verify(&alice, &bob);
        create_offer(&alice.state, &bob.call_peer()).unwrap();
        let phrase = phrase_now(&alice.state, &bob.user, &bob.device_id, "c", 0).unwrap();
        assert!(phrase.words.is_empty());
        assert_eq!(phrase.pairing, PairingState::WaitingForThem);
        assert!(phrase_matches(&alice.state, &bob.user, &bob.device_id, "c", "a b c d", 0).is_err());
    }

    #[test]
    fn mark_verified_needs_the_number_these_keys_produce() {
        let alice = TestDevice::new(false);
        let bob = TestDevice::new(false);
        approve_each_other(&alice, &bob);
        let status = status_for(&alice.state, &bob.call_peer()).unwrap();
        assert_eq!(status.standing, "pinned");
        assert!(mark_verified(&alice.state, &bob.call_peer(), "0000 0000", VerificationMethod::SafetyNumber).is_err());
        assert!(mark_verified(&alice.state, &bob.call_peer(), "", VerificationMethod::SafetyNumber).is_err());
        // A number for someone else's keys.
        let carol = TestDevice::new(false);
        let other = status_for(&alice.state, &carol.call_peer()).unwrap().safety_number;
        assert!(mark_verified(&alice.state, &bob.call_peer(), &other, VerificationMethod::SafetyNumber).is_err());
        // The right number, in lower case without spaces, is fine.
        let typed = status.safety_number.replace(' ', "").to_lowercase();
        let verified = mark_verified(&alice.state, &bob.call_peer(), &typed, VerificationMethod::QrCode).unwrap();
        assert!(verified.verified_at.is_some());
        assert_eq!(verified.method, Some(VerificationMethod::QrCode));
        // A device this device never recorded cannot be verified at all.
        assert!(mark_verified(&alice.state, &carol.call_peer(), &other, VerificationMethod::SafetyNumber).is_err());
    }

    #[test]
    fn offers_are_refused_when_they_should_be() {
        let (alice, bob) = paired_pair();
        let offer = create_offer(&alice.state, &bob.call_peer()).unwrap();

        // Tampered: the signature no longer covers it.
        let mut tampered = offer.clone();
        tampered.have_yours = !tampered.have_yours;
        assert!(receive_offer(&bob.state, &tampered, &alice.call_peer()).is_err());
        let mut tampered = offer.clone();
        tampered.ciphertext.ml_kem_ciphertext[0] ^= 1;
        assert!(receive_offer(&bob.state, &tampered, &alice.call_peer()).is_err());

        // Presented as coming from another device, or meant for another one.
        let carol = TestDevice::new(false);
        assert!(receive_offer(&bob.state, &offer, &carol.call_peer()).is_err());
        assert!(receive_offer(&carol.state, &offer, &alice.call_peer()).is_err());

        // The genuine offer is accepted once, then is a harmless repeat (that
        // asks for nothing, however often history replays it), and an OLDER
        // genuine offer replayed after it is refused.
        receive_offer(&bob.state, &offer, &alice.call_peer()).unwrap();
        let repeat = receive_offer(&bob.state, &offer, &alice.call_peer()).unwrap();
        assert!(!repeat.reply_needed);
        let older = {
            std::thread::sleep(std::time::Duration::from_millis(5));
            let newer = create_offer(&alice.state, &bob.call_peer()).unwrap();
            receive_offer(&bob.state, &newer, &alice.call_peer()).unwrap();
            offer
        };
        assert!(matches!(receive_offer(&bob.state, &older, &alice.call_peer()), Err(QGuardError::Replay(_))));
    }

    #[test]
    fn an_offer_from_an_unrecorded_or_rekeyed_device_is_refused() {
        let alice = TestDevice::new(false);
        let bob = TestDevice::new(false);
        // Bob records Alice; Alice records Bob and verifies him.
        approve_each_other(&alice, &bob);
        verify(&alice, &bob);
        let offer = create_offer(&alice.state, &bob.call_peer()).unwrap();
        // A device Bob has never recorded presents Alice's ids with other keys:
        // the "re-keyed" Alice. Bob's record holds the old keys.
        let (impostor, impostor_peer) = impostor_of(&alice);
        let mut forged = offer.clone();
        forged.signature =
            dual_sign(&impostor.signing.ed25519_secret, &impostor.signing.mldsa_secret, &offer_signable(&forged)).unwrap();
        // Self-consistent (its own keys sign it), but not the recorded device.
        assert!(receive_offer(&bob.state, &forged, &impostor_peer).is_err());
        // And the genuine offer still goes through.
        receive_offer(&bob.state, &offer, &alice.call_peer()).unwrap();
    }

    /// Other keys presenting `device`'s user and device ids.
    fn impostor_of(device: &TestDevice) -> (LocalIdentity, CallPeerIdentity) {
        let mut identity = LocalIdentity::generate(device.user.clone(), "Desktop").unwrap();
        identity.device_id = device.device_id.clone();
        let peer = crate::test_support::call_peer_of(&identity);
        (identity, peer)
    }

    #[test]
    fn pairing_is_lost_when_the_device_rekeys_and_returns_only_after_reverification() {
        let (alice, bob) = paired_pair();
        // Bob's record now sees other keys listed under Alice's device id.
        let (_, impostor_peer) = impostor_of(&alice);
        bob.state
            .with_device_pins(&bob.user, |book| book.assess(&[impostor_peer.pin_subject()], 2))
            .unwrap();
        let phrase = phrase_now(&bob.state, &alice.user, &alice.device_id, "c", 0).unwrap();
        assert!(phrase.words.is_empty(), "a key change destroys the pairing");
        assert_eq!(status_for(&bob.state, &alice.call_peer()).unwrap().verified_at, None);

        // Verifying again does not bring the old pairing back: new halves are
        // exchanged, exactly as the first time.
        verify(&bob, &alice);
        assert_eq!(status_for(&bob.state, &alice.call_peer()).unwrap().pairing, PairingState::None);
        let from_bob = create_offer(&bob.state, &alice.call_peer()).unwrap();
        assert!(!from_bob.have_yours);
        let receipt = receive_offer(&alice.state, &from_bob, &bob.call_peer()).unwrap();
        assert!(receipt.reply_needed, "Bob lacks Alice's half, so she must send a fresh one");
        let from_alice = create_offer(&alice.state, &bob.call_peer()).unwrap();
        receive_offer(&bob.state, &from_alice, &alice.call_peer()).unwrap();
        let a = phrase_now(&alice.state, &bob.user, &bob.device_id, "c", 0).unwrap();
        let b = phrase_now(&bob.state, &alice.user, &alice.device_id, "c", 0).unwrap();
        assert_eq!(a.words.len(), 4);
        assert_eq!(a.words, b.words);
    }
}
