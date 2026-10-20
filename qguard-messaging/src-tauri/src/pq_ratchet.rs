//! Post-quantum session ratchet for Secure Chat (roadmap Phase 2).
//!
//! WHY THIS EXISTS
//! ---------------------------------------------------------------------------
//! Before this module every message was sealed with its own fresh hybrid
//! encapsulation to the recipient device's prekey. That is strong per message,
//! but forward secrecy only reached as far as the prekey: anyone who obtained a
//! prekey secret could open every not-yet-ledgered message sealed to it during
//! its rotation epoch (about a day), and a compromised device only healed at the
//! next rotation. See `crate::message_keys` for that model.
//!
//! A session between two devices replaces that, following the Double Ratchet
//! with a sparse post-quantum step (the shape of Signal's SPQR / "Triple
//! Ratchet" and Apple's PQ3 — see the design spec for references):
//!
//!   * The session's ROOT comes from the existing hybrid X25519 + ML-KEM-1024
//!     encapsulation to the peer's prekey (`crypto::hybrid_kex`). The very first
//!     messages are therefore exactly as strong as today's one-shot envelopes.
//!   * Every message advances a symmetric chain (HMAC-SHA3-256), and the chain
//!     key it came from is overwritten: per-message forward secrecy.
//!   * Every change of direction runs an X25519 ratchet step: a fresh key pair
//!     per turn, so a stolen session heals on the next round trip.
//!   * Every 50 messages / 24 h one side offers a fresh ML-KEM-1024 key in its
//!     headers, the other encapsulates to it on its next turn, and both mix the
//!     ML-KEM secret into the same root step: healing that also holds against a
//!     quantum adversary. Whether a step mixes ML-KEM is carried IN THE HEADER,
//!     so the two sides can never disagree about it.
//!
//! WHAT THIS MODULE DOES NOT DO
//! ---------------------------------------------------------------------------
//! No I/O, no signatures, no identity. It is the state machine and its key
//! schedule only. Authentication (both Ed25519 and ML-DSA-65 over the whole
//! envelope, header included), device pins and persistence live in
//! `commands::messaging` and `state`. Every receive is meant to run on a CLONE
//! of the session, committed only after the AEAD tag verifies, so a malformed
//! or hostile header can never corrupt real state.
//!
//! It has not been independently reviewed. Until it is, the capability is not
//! advertised unless the user turns it on (Settings → Advanced) or the build
//! runs with `QGUARD_RATCHET=1` (see [`env_override`]).

use std::collections::HashMap;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::kdf::sha3_256;
use crate::error::{QGuardError, Result};

/// The capability label a device publishes in its suite, and the label stamped
/// on every ratchet envelope's suite.
pub const RATCHET_PROTOCOL: &str = "QGuard-PQRatchet-v1";
pub const HEADER_VERSION: u8 = 1;

/// Largest gap allowed inside one chain (messages lost or still in flight).
pub const MAX_SKIP: u32 = 1000;
/// Keys for out-of-order messages kept per session; oldest dropped first.
pub const MAX_STORED_SKIPPED: usize = 1000;
/// Skipped keys older than this are dropped: a message that late is not coming.
pub const SKIPPED_KEY_MAX_AGE_SECS: i64 = 30 * 24 * 3600;
/// A post-quantum step is offered after this many messages sent…
pub const PQ_STEP_EVERY_MESSAGES: u32 = 50;
/// …or this long since the last one, whichever comes first.
pub const PQ_STEP_EVERY_SECS: i64 = 24 * 3600;
/// Sessions kept per peer device (the active one plus late-message stragglers).
pub const MAX_SESSIONS_PER_PEER: usize = 3;
/// A session not used for this long is retired and the next message starts a new one.
pub const SESSION_MAX_AGE_SECS: i64 = 30 * 24 * 3600;

const MAX_SESSION_ID_LEN: usize = 64;
const OFFER_ID_LEN: usize = 32;
const LABEL_INIT: &[u8] = b"QGuard-PQRatchet-v1:init";
const LABEL_ROOT: &[u8] = b"QGuard-PQRatchet-v1:root";
const LABEL_INIT_CHAIN: &[u8] = b"QGuard-PQRatchet-v1:init-chain";
const LABEL_RK: &[u8] = b"QGuard-PQRatchet-v1:rk";

/// The environment's say on whether this build ADVERTISES and STARTS ratchet
/// sessions: `Some(true)` for `QGUARD_RATCHET=1`, `Some(false)` for
/// `QGUARD_RATCHET=0` (an operator kill switch that beats the user setting),
/// `None` to leave it to the setting. See `AppState::ratchet_enabled`.
///
/// Receiving is always supported: a peer only sends ratchet envelopes to a
/// device that advertised the capability, and a device that turns it off must
/// still read what was sent while it was on. Turning it off is the kill
/// switch — new messages fall back to one-shot envelopes, nothing to migrate.
pub fn env_override() -> Option<bool> {
    match std::env::var("QGUARD_RATCHET").ok()?.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// Whether a device's published suite says it can receive ratchet envelopes.
pub fn peer_supports(suite: Option<&crate::crypto::AlgorithmSuite>) -> bool {
    suite.is_some_and(|suite| suite.ratchet == RATCHET_PROTOCOL)
}

/// The info string the SEEDING hybrid encapsulation is bound to.
///
/// One-shot envelopes bind theirs to the conversation (`message_kex_info`). A
/// session is per device pair and outlives any one conversation — its init
/// material is re-attached to messages in whichever conversation comes next —
/// so it is bound to the session and the two devices instead.
pub fn init_kex_info(
    session_id: &str,
    sender_user_id: &str,
    recipient_user_id: &str,
    sender_device_id: &str,
    recipient_device_id: &str,
) -> String {
    format!(
        "QGuard-PQRatchet-v1:seed:{session_id}:{sender_user_id}:{recipient_user_id}:{sender_device_id}:{recipient_device_id}"
    )
}

/// `sha3(x25519 ephemeral || ML-KEM ciphertext)`: what ties a session's root to
/// the exact encapsulation that seeded it.
pub fn hybrid_digest(ciphertext: &crate::crypto::HybridCiphertext) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(ciphertext.x25519_ephemeral_public.len() + ciphertext.ml_kem_ciphertext.len() + 8);
    for part in [&ciphertext.x25519_ephemeral_public, &ciphertext.ml_kem_ciphertext] {
        bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    sha3_256(&bytes)
}

/// `sha3(ed25519 || ML-DSA-65)` of a device's signing keys — what a session
/// remembers about who its peer is ([`Session::peer_signing`]).
pub fn signing_digest(ed25519_public: &[u8], mldsa_public: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(ed25519_public.len() + mldsa_public.len() + 8);
    for part in [ed25519_public, mldsa_public] {
        bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    hex::encode(sha3_256(&bytes))
}

// ---------------------------------------------------------------------------
// Wire header
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HeaderKind {
    /// Carries the hybrid ciphertext that seeds the session; sent until the
    /// peer has answered, so whichever one arrives first can start it.
    Init,
    /// An ordinary ratchet message; needs the session.
    Msg,
}

/// A fresh ML-KEM-1024 encapsulation key offered for the next post-quantum step.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqOffer {
    /// `offer_id(ek)` — recomputed and checked on receipt.
    pub id: String,
    pub ek: Vec<u8>,
}

/// The encapsulation to a peer's offer, completing a post-quantum step.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqAnswer {
    pub for_id: String,
    pub ct: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RatchetHeader {
    pub v: u8,
    pub kind: HeaderKind,
    pub session: String,
    /// The sender's current X25519 ratchet public key.
    pub dh: Vec<u8>,
    /// Length of the sender's previous sending chain.
    pub pn: u32,
    /// This message's number in the sender's current chain.
    pub n: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_offer: Option<PqOffer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_answer: Option<PqAnswer>,
}

fn is_hex_id(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The id an offer is known by: a short digest of its key, so an id can never
/// be attached to a different key than the one it names.
pub fn offer_id(ek: &[u8]) -> String {
    hex::encode(&sha3_256(ek)[..OFFER_ID_LEN / 2])
}

impl RatchetHeader {
    /// Structural checks, done before any key is touched.
    pub fn validate(&self) -> Result<()> {
        let bad = |what: &str| Err(QGuardError::InvalidInput(format!("ratchet header: {what}")));
        if self.v != HEADER_VERSION {
            return bad("unsupported version — update QGuard Messaging");
        }
        if !is_hex_id(&self.session, MAX_SESSION_ID_LEN) {
            return bad("malformed session id");
        }
        if self.dh.len() != 32 {
            return bad("ratchet key must be 32 bytes");
        }
        if let Some(offer) = &self.pq_offer {
            if offer.ek.len() != mlkem1024::public_key_bytes() {
                return bad("ML-KEM-1024 offer has the wrong length");
            }
            if offer.id != offer_id(&offer.ek) {
                return bad("ML-KEM offer id does not match its key");
            }
        }
        if let Some(answer) = &self.pq_answer {
            if answer.ct.len() != mlkem1024::ciphertext_bytes() {
                return bad("ML-KEM-1024 answer has the wrong length");
            }
            if !is_hex_id(&answer.for_id, OFFER_ID_LEN) || answer.for_id.len() != OFFER_ID_LEN {
                return bad("malformed ML-KEM answer id");
            }
        }
        Ok(())
    }

    /// Unambiguous byte encoding, covered by the envelope's signatures and bound
    /// into its AEAD associated data. Every variable-length field is
    /// length-prefixed, so no two different headers encode the same.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        fn put(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(b"QGR1");
        out.push(self.v);
        out.push(match self.kind {
            HeaderKind::Init => 1,
            HeaderKind::Msg => 2,
        });
        put(&mut out, self.session.as_bytes());
        put(&mut out, &self.dh);
        out.extend_from_slice(&self.pn.to_be_bytes());
        out.extend_from_slice(&self.n.to_be_bytes());
        match &self.pq_offer {
            Some(offer) => {
                out.push(1);
                put(&mut out, offer.id.as_bytes());
                put(&mut out, &offer.ek);
            }
            None => out.push(0),
        }
        match &self.pq_answer {
            Some(answer) => {
                out.push(1);
                put(&mut out, answer.for_id.as_bytes());
                put(&mut out, &answer.ct);
            }
            None => out.push(0),
        }
        out
    }

    pub fn digest_hex(&self) -> String {
        hex::encode(sha3_256(&self.canonical_bytes()))
    }
}

// ---------------------------------------------------------------------------
// Key schedule
// ---------------------------------------------------------------------------

type HmacSha3 = Hmac<Sha3_256>;

/// What binds a session's root to the exchange that created it.
pub struct InitContext<'a> {
    pub session_id: &'a str,
    pub initiator_device: &'a str,
    pub responder_device: &'a str,
    /// `sha3(x25519 ephemeral || ML-KEM ciphertext)` of the seeding encapsulation.
    pub hybrid_digest: [u8; 32],
}

fn init_transcript(ctx: &InitContext<'_>, initiator_dh: &[u8; 32]) -> [u8; 32] {
    let mut transcript = Vec::with_capacity(256);
    for part in [
        LABEL_INIT,
        ctx.session_id.as_bytes(),
        ctx.initiator_device.as_bytes(),
        ctx.responder_device.as_bytes(),
        initiator_dh.as_slice(),
        ctx.hybrid_digest.as_slice(),
    ] {
        transcript.extend_from_slice(&(part.len() as u32).to_be_bytes());
        transcript.extend_from_slice(part);
    }
    sha3_256(&transcript)
}

fn hkdf_expand_32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha3_256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|e| QGuardError::Crypto(format!("ratchet HKDF failed: {e}")))?;
    Ok(out)
}

/// `(root, initiator's first sending chain)` from the hybrid shared secret.
fn derive_init(shared: &[u8; 32], ctx: &InitContext<'_>, initiator_dh: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let salt = init_transcript(ctx, initiator_dh);
    Ok((
        hkdf_expand_32(&salt, shared, LABEL_ROOT)?,
        hkdf_expand_32(&salt, shared, LABEL_INIT_CHAIN)?,
    ))
}

/// Root step: `(root', chain) = HKDF(salt = root, ikm = dh || [pq] || flag)`.
fn kdf_rk(root: &[u8; 32], dh_out: &[u8; 32], pq_secret: Option<&[u8]>) -> Result<([u8; 32], [u8; 32])> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + 32 + 1));
    ikm.extend_from_slice(dh_out);
    if let Some(pq) = pq_secret {
        ikm.extend_from_slice(pq);
    }
    // The flag closes the encoding: "no ML-KEM" can never collide with a step
    // whose ML-KEM secret happened to be empty.
    ikm.push(u8::from(pq_secret.is_some()));
    let hk = Hkdf::<Sha3_256>::new(Some(root), &ikm);
    let mut out = Zeroizing::new([0u8; 64]);
    hk.expand(LABEL_RK, out.as_mut())
        .map_err(|e| QGuardError::Crypto(format!("ratchet root step failed: {e}")))?;
    let mut next_root = [0u8; 32];
    let mut chain = [0u8; 32];
    next_root.copy_from_slice(&out[..32]);
    chain.copy_from_slice(&out[32..]);
    Ok((next_root, chain))
}

/// Chain step: `(chain', message key)`.
fn kdf_ck(chain: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let derive = |byte: u8| -> Result<[u8; 32]> {
        let mut mac = HmacSha3::new_from_slice(chain)
            .map_err(|_| QGuardError::Crypto("ratchet chain key rejected".to_string()))?;
        mac.update(&[byte]);
        let mut out = [0u8; 32];
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(out)
    };
    Ok((derive(0x02)?, derive(0x01)?))
}

fn x25519(secret: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32]> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&X25519Public::from(*peer));
    if !shared.was_contributory() {
        return Err(QGuardError::Crypto(
            "ratchet X25519 step was non-contributory (low-order key); refusing it".to_string(),
        ));
    }
    Ok(*shared.as_bytes())
}

fn to_array32(bytes: &[u8], what: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| QGuardError::InvalidInput(format!("{what} must be 32 bytes")))
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct Chain {
    key: [u8; 32],
    n: u32,
}

impl Drop for Chain {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct DhKeypair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl DhKeypair {
    fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519Public::from(&secret);
        Self { secret: secret.to_bytes(), public: *public.as_bytes() }
    }
}

impl Drop for DhKeypair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct PqKeypair {
    id: String,
    ek: Vec<u8>,
    dk: Vec<u8>,
}

impl PqKeypair {
    fn generate() -> Self {
        let (ek, dk) = mlkem1024::keypair();
        let ek = mlkem1024::PublicKey::as_bytes(&ek).to_vec();
        Self { id: offer_id(&ek), ek, dk: mlkem1024::SecretKey::as_bytes(&dk).to_vec() }
    }
}

impl Drop for PqKeypair {
    fn drop(&mut self) {
        self.dk.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct SkippedKey {
    dh: [u8; 32],
    n: u32,
    key: [u8; 32],
    at: i64,
}

impl Drop for SkippedKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// What the initiator re-attaches to every message until the peer answers:
/// the hybrid ciphertext and the prekey it was sealed to. Public material.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitMaterial {
    pub hybrid_ciphertext: crate::crypto::HybridCiphertext,
    pub prekey_id: String,
    pub prekey_kind: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub peer_device: String,
    pub created_at: i64,
    pub last_used_at: i64,
    /// `sha3(ed25519 || ML-DSA-65)` of the peer device's signing keys. Every
    /// envelope on this session must be signed by exactly these keys.
    pub peer_signing: String,
    /// Combiner of the hybrid encapsulation that seeded the root.
    pub init_combiner: String,
    root: [u8; 32],
    send: Option<Chain>,
    recv: Option<Chain>,
    prev_send_len: u32,
    dh_self: Option<DhKeypair>,
    dh_peer: Option<[u8; 32]>,
    pending_init: Option<InitMaterial>,
    /// Our outstanding ML-KEM offer, until the peer answers it.
    pq_mine: Option<PqKeypair>,
    /// Our answer to the peer's offer, carried on our current sending chain.
    pq_answer: Option<PqAnswer>,
    last_answered_offer: Option<String>,
    last_pq_at: i64,
    sent_since_pq: u32,
    /// Completed post-quantum steps; for the status badge and tests.
    #[serde(default)]
    pub pq_steps: u32,
    skipped: Vec<SkippedKey>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.root.zeroize();
    }
}

pub fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The key of init message `header.n`, straight from the seeding secret.
///
/// Lets an init envelope be opened with no session at all — e.g. one from a
/// device this device will not open a session with yet (unapproved), or one
/// that arrives after the session was retired. Init envelopes are therefore
/// never worse off than today's one-shot envelopes.
pub fn init_message_key(shared: &[u8; 32], ctx: &InitContext<'_>, header: &RatchetHeader) -> Result<Zeroizing<[u8; 32]>> {
    header.validate()?;
    if header.kind != HeaderKind::Init || header.pn != 0 {
        return Err(QGuardError::InvalidInput("not an init ratchet header".to_string()));
    }
    if header.n > MAX_SKIP {
        return Err(QGuardError::Replay("init message number beyond the skip limit".to_string()));
    }
    let initiator_dh = to_array32(&header.dh, "ratchet key")?;
    let (mut root, mut chain) = derive_init(shared, ctx, &initiator_dh)?;
    root.zeroize();
    for _ in 0..header.n {
        let (next, mut discard) = kdf_ck(&chain)?;
        discard.zeroize();
        chain = next;
    }
    let (mut next, key) = kdf_ck(&chain)?;
    next.zeroize();
    chain.zeroize();
    Ok(Zeroizing::new(key))
}

impl Session {
    /// The initiator's side, right after encapsulating to the peer's prekey.
    pub fn initiate(
        shared: &[u8; 32],
        ctx: &InitContext<'_>,
        peer_signing: &str,
        init: InitMaterial,
        now: i64,
    ) -> Result<Self> {
        let dh = DhKeypair::generate();
        let (root, chain) = derive_init(shared, ctx, &dh.public)?;
        Ok(Self {
            id: ctx.session_id.to_string(),
            peer_device: ctx.responder_device.to_string(),
            created_at: now,
            last_used_at: now,
            peer_signing: peer_signing.to_string(),
            init_combiner: init.hybrid_ciphertext.suite.kem_combiner.clone(),
            root,
            send: Some(Chain { key: chain, n: 0 }),
            recv: None,
            prev_send_len: 0,
            dh_self: Some(dh),
            dh_peer: None,
            pending_init: Some(init),
            pq_mine: None,
            pq_answer: None,
            last_answered_offer: None,
            // The seeding encapsulation IS a post-quantum step.
            last_pq_at: now,
            sent_since_pq: 0,
            pq_steps: 0,
            skipped: Vec::new(),
        })
    }

    /// The responder's side, from the first init header that arrives.
    pub fn accept(
        shared: &[u8; 32],
        ctx: &InitContext<'_>,
        header: &RatchetHeader,
        peer_signing: &str,
        init_combiner: &str,
        now: i64,
    ) -> Result<Self> {
        header.validate()?;
        if header.kind != HeaderKind::Init || header.session != ctx.session_id {
            return Err(QGuardError::InvalidInput("a session can only start from its own init header".to_string()));
        }
        let initiator_dh = to_array32(&header.dh, "ratchet key")?;
        let (root, chain) = derive_init(shared, ctx, &initiator_dh)?;
        let mut session = Self {
            id: ctx.session_id.to_string(),
            peer_device: ctx.initiator_device.to_string(),
            created_at: now,
            last_used_at: now,
            peer_signing: peer_signing.to_string(),
            init_combiner: init_combiner.to_string(),
            root,
            send: None,
            recv: Some(Chain { key: chain, n: 0 }),
            prev_send_len: 0,
            dh_self: None,
            dh_peer: Some(initiator_dh),
            pending_init: None,
            pq_mine: None,
            pq_answer: None,
            last_answered_offer: None,
            last_pq_at: now,
            sent_since_pq: 0,
            pq_steps: 0,
            skipped: Vec::new(),
        };
        session.send_half(header.pq_offer.as_ref(), now)?;
        Ok(session)
    }

    pub fn pending_init(&self) -> Option<&InitMaterial> {
        self.pending_init.as_ref()
    }

    /// Retired: not used for a month. The next message starts a new session.
    pub fn is_stale(&self, now: i64) -> bool {
        now.saturating_sub(self.last_used_at) > SESSION_MAX_AGE_SECS
    }

    fn pq_due(&self, now: i64) -> bool {
        self.sent_since_pq >= PQ_STEP_EVERY_MESSAGES || now.saturating_sub(self.last_pq_at) >= PQ_STEP_EVERY_SECS
    }

    /// Seal the next message: its header and its one-use key. The caller MUST
    /// persist the session before the envelope leaves this device — reusing a
    /// chain position after a crash would make the peer drop the message.
    pub fn next_send(&mut self, now: i64) -> Result<(RatchetHeader, Zeroizing<[u8; 32]>)> {
        let dh_public = self
            .dh_self
            .as_ref()
            .map(|pair| pair.public)
            .ok_or_else(|| QGuardError::Crypto("ratchet session has no sending key".to_string()))?;
        let chain = self
            .send
            .as_mut()
            .ok_or_else(|| QGuardError::Crypto("ratchet session has no sending chain".to_string()))?;
        if chain.n == u32::MAX {
            return Err(QGuardError::Crypto("ratchet chain exhausted; a new session is needed".to_string()));
        }
        let (next, key) = kdf_ck(&chain.key)?;
        chain.key = next;
        let n = chain.n;
        chain.n += 1;
        self.sent_since_pq = self.sent_since_pq.saturating_add(1);
        self.last_used_at = now;
        let header = RatchetHeader {
            v: HEADER_VERSION,
            kind: if self.pending_init.is_some() { HeaderKind::Init } else { HeaderKind::Msg },
            session: self.id.clone(),
            dh: dh_public.to_vec(),
            pn: self.prev_send_len,
            n,
            pq_offer: self.pq_mine.as_ref().map(|mine| PqOffer { id: mine.id.clone(), ek: mine.ek.clone() }),
            pq_answer: self.pq_answer.clone(),
        };
        Ok((header, Zeroizing::new(key)))
    }

    /// The key for a received message. Run it on a clone and keep the clone
    /// only if the message then authenticates.
    pub fn recv(&mut self, header: &RatchetHeader, now: i64) -> Result<Zeroizing<[u8; 32]>> {
        header.validate()?;
        if header.session != self.id {
            return Err(QGuardError::InvalidInput("ratchet header belongs to another session".to_string()));
        }
        let header_dh = to_array32(&header.dh, "ratchet key")?;
        self.prune_skipped(now);
        if let Some(key) = self.take_skipped(&header_dh, header.n) {
            self.last_used_at = now;
            return Ok(key);
        }
        if self.dh_peer != Some(header_dh) {
            if self.recv.is_some() {
                self.skip_until(header.pn, now)?;
            }
            self.dh_ratchet(header, header_dh, now)?;
        }
        self.skip_until(header.n, now)?;
        let chain = self
            .recv
            .as_mut()
            .ok_or_else(|| QGuardError::Crypto("ratchet session has no receiving chain".to_string()))?;
        if header.n < chain.n {
            return Err(QGuardError::Replay(format!(
                "ratchet message {} of this chain was already received",
                header.n
            )));
        }
        let (next, key) = kdf_ck(&chain.key)?;
        chain.key = next;
        chain.n += 1;
        self.last_used_at = now;
        Ok(Zeroizing::new(key))
    }

    fn dh_ratchet(&mut self, header: &RatchetHeader, peer_dh: [u8; 32], now: i64) -> Result<()> {
        self.prev_send_len = self.send.as_ref().map(|chain| chain.n).unwrap_or(0);
        let dh_out = {
            let mine = self
                .dh_self
                .as_ref()
                .ok_or_else(|| QGuardError::Crypto("ratchet session has no key to answer with".to_string()))?;
            Zeroizing::new(x25519(&mine.secret, &peer_dh)?)
        };
        // Receiving half: mix ML-KEM exactly when the header says the peer did.
        let pq_secret = match &header.pq_answer {
            Some(answer) => {
                let mine = self
                    .pq_mine
                    .as_ref()
                    .filter(|mine| mine.id == answer.for_id)
                    .ok_or_else(|| QGuardError::Crypto("ML-KEM answer to an offer this session never made".to_string()))?;
                let dk = mlkem1024::SecretKey::from_bytes(&mine.dk)
                    .map_err(|_| QGuardError::Crypto("stored ML-KEM offer key is malformed".to_string()))?;
                let ct = mlkem1024::Ciphertext::from_bytes(&answer.ct)
                    .map_err(|_| QGuardError::Crypto("ML-KEM answer is malformed".to_string()))?;
                let secret = mlkem1024::decapsulate(&ct, &dk);
                Some(Zeroizing::new(mlkem1024::SharedSecret::as_bytes(&secret).to_vec()))
            }
            None => None,
        };
        let (root, chain) = kdf_rk(&self.root, &dh_out, pq_secret.as_ref().map(|secret| secret.as_slice()))?;
        if pq_secret.is_some() {
            self.pq_mine = None;
            self.last_pq_at = now;
            self.sent_since_pq = 0;
            self.pq_steps = self.pq_steps.saturating_add(1);
        }
        self.root = root;
        self.recv = Some(Chain { key: chain, n: 0 });
        self.dh_peer = Some(peer_dh);
        // The peer answered on this session, so it has it: stop re-sending the
        // seeding ciphertext.
        self.pending_init = None;
        self.send_half(header.pq_offer.as_ref(), now)
    }

    /// Start a new sending chain against the peer's current ratchet key.
    fn send_half(&mut self, peer_offer: Option<&PqOffer>, now: i64) -> Result<()> {
        let peer = self
            .dh_peer
            .ok_or_else(|| QGuardError::Crypto("ratchet session has no peer key".to_string()))?;
        let fresh = DhKeypair::generate();
        let dh_out = Zeroizing::new(x25519(&fresh.secret, &peer)?);
        let mut answer = None;
        let mut pq_secret = None;
        if let Some(offer) = peer_offer.filter(|offer| self.last_answered_offer.as_deref() != Some(offer.id.as_str())) {
            let ek = mlkem1024::PublicKey::from_bytes(&offer.ek)
                .map_err(|_| QGuardError::Crypto("ML-KEM offer is malformed".to_string()))?;
            let (secret, ct) = mlkem1024::encapsulate(&ek);
            pq_secret = Some(Zeroizing::new(mlkem1024::SharedSecret::as_bytes(&secret).to_vec()));
            answer = Some(PqAnswer { for_id: offer.id.clone(), ct: mlkem1024::Ciphertext::as_bytes(&ct).to_vec() });
        }
        let (root, chain) = kdf_rk(&self.root, &dh_out, pq_secret.as_ref().map(|secret| secret.as_slice()))?;
        self.root = root;
        self.send = Some(Chain { key: chain, n: 0 });
        self.dh_self = Some(fresh);
        if let Some(answer) = &answer {
            self.last_answered_offer = Some(answer.for_id.clone());
            self.last_pq_at = now;
            self.sent_since_pq = 0;
            self.pq_steps = self.pq_steps.saturating_add(1);
        }
        self.pq_answer = answer;
        if self.pq_mine.is_none() && self.pq_due(now) {
            self.pq_mine = Some(PqKeypair::generate());
        }
        Ok(())
    }

    fn skip_until(&mut self, until: u32, now: i64) -> Result<()> {
        let Some(peer) = self.dh_peer else { return Ok(()) };
        let Some(chain) = self.recv.as_mut() else { return Ok(()) };
        if until <= chain.n {
            return Ok(());
        }
        if until - chain.n > MAX_SKIP {
            return Err(QGuardError::Replay(format!(
                "ratchet message is {} positions ahead; more than {MAX_SKIP} are missing",
                until - chain.n
            )));
        }
        while chain.n < until {
            let (next, key) = kdf_ck(&chain.key)?;
            self.skipped.push(SkippedKey { dh: peer, n: chain.n, key, at: now });
            chain.key = next;
            chain.n += 1;
        }
        if self.skipped.len() > MAX_STORED_SKIPPED {
            let excess = self.skipped.len() - MAX_STORED_SKIPPED;
            self.skipped.drain(..excess);
        }
        Ok(())
    }

    fn take_skipped(&mut self, dh: &[u8; 32], n: u32) -> Option<Zeroizing<[u8; 32]>> {
        let index = self.skipped.iter().position(|entry| &entry.dh == dh && entry.n == n)?;
        let entry = self.skipped.remove(index);
        Some(Zeroizing::new(entry.key))
    }

    fn prune_skipped(&mut self, now: i64) {
        self.skipped.retain(|entry| now.saturating_sub(entry.at) <= SKIPPED_KEY_MAX_AGE_SECS);
    }

    /// Whether the session has completed at least one ratchet round trip.
    pub fn has_ratcheted(&self) -> bool {
        self.pending_init.is_none() && self.recv.is_some() && self.send.is_some()
    }

    /// Facts about this session for the status badge. No key material.
    pub fn summary(&self) -> SessionSummary {
        SessionSummary {
            session_id: self.id.clone(),
            created_at: self.created_at,
            last_used_at: self.last_used_at,
            ratcheted: self.has_ratcheted(),
            pq_steps: self.pq_steps,
            last_pq_at: self.last_pq_at,
            init_combiner: self.init_combiner.clone(),
        }
    }
}

/// What can be said about a session without touching its keys.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SessionSummary {
    pub session_id: String,
    pub created_at: i64,
    pub last_used_at: i64,
    /// A full round trip has happened: both sides have contributed a ratchet
    /// key, so per-message forward secrecy and healing are in effect.
    pub ratcheted: bool,
    /// Completed ML-KEM-1024 steps after the seeding one.
    pub pq_steps: u32,
    /// When ML-KEM last went into the root (the seed counts).
    pub last_pq_at: i64,
    /// Hybrid combiner of the encapsulation that seeded the session.
    pub init_combiner: String,
}

// ---------------------------------------------------------------------------
// Session book (what `state` persists)
// ---------------------------------------------------------------------------

#[derive(Default, Clone, Serialize, Deserialize)]
struct PeerSessions {
    active: Option<String>,
    sessions: Vec<Session>,
}

#[derive(Serialize, Deserialize)]
struct BookFile {
    version: u8,
    /// The local device the sessions belong to. Sessions are between DEVICES:
    /// once this device re-keys under a new device id, peers address the new
    /// id and every old session is dead.
    #[serde(default)]
    local_device: String,
    peers: HashMap<String, PeerSessions>,
}

/// Every session this device holds, by peer device. Same lifecycle discipline
/// as the device-pin book: a stored book that will not open is UNAVAILABLE and
/// never written, so a transient keychain fault cannot erase live sessions.
pub struct SessionBook {
    owner: Option<String>,
    local_device: String,
    available: bool,
    retry_after: i64,
    dirty: bool,
    peers: HashMap<String, PeerSessions>,
}

impl Default for SessionBook {
    fn default() -> Self {
        Self { owner: None, local_device: String::new(), available: false, retry_after: 0, dirty: false, peers: HashMap::new() }
    }
}

impl SessionBook {
    pub fn empty(owner: &str, local_device: &str) -> Self {
        Self { owner: Some(owner.to_string()), local_device: local_device.to_string(), available: true, ..Self::default() }
    }

    pub fn unavailable(owner: &str, local_device: &str, retry_after: i64) -> Self {
        Self {
            owner: Some(owner.to_string()),
            local_device: local_device.to_string(),
            available: false,
            retry_after,
            ..Self::default()
        }
    }

    /// Open a stored book. Sessions recorded for a different local device are
    /// discarded (the result is then dirty, so the next save drops them).
    pub fn decode(owner: &str, local_device: &str, bytes: &[u8]) -> Result<Self> {
        let file: BookFile = serde_json::from_slice(bytes)
            .map_err(|e| QGuardError::Storage(format!("ratchet sessions unreadable: {e}")))?;
        if file.version != 1 {
            return Err(QGuardError::Storage("ratchet sessions written by a newer build".to_string()));
        }
        let same_device = file.local_device == local_device;
        Ok(Self {
            owner: Some(owner.to_string()),
            local_device: local_device.to_string(),
            available: true,
            retry_after: 0,
            dirty: !same_device,
            peers: if same_device { file.peers } else { HashMap::new() },
        })
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let file = BookFile { version: 1, local_device: self.local_device.clone(), peers: self.peers.clone() };
        serde_json::to_vec(&file)
            .map(Zeroizing::new)
            .map_err(|e| QGuardError::Storage(format!("ratchet sessions could not be encoded: {e}")))
    }

    pub fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }
    pub fn local_device(&self) -> &str {
        &self.local_device
    }
    pub fn is_available(&self) -> bool {
        self.available
    }
    pub fn should_retry_load(&self, now: i64) -> bool {
        !self.available && now >= self.retry_after
    }
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
    pub fn mark_saved(&mut self) {
        self.dirty = false;
    }

    /// The session new messages to `peer` go out on, unless it is stale.
    pub fn active(&self, peer: &str, now: i64) -> Option<&Session> {
        let entry = self.peers.get(peer)?;
        let id = entry.active.as_deref()?;
        entry.sessions.iter().find(|session| session.id == id && !session.is_stale(now))
    }

    pub fn find(&self, peer: &str, session_id: &str) -> Option<&Session> {
        self.peers.get(peer)?.sessions.iter().find(|session| session.id == session_id)
    }

    /// Store `session` (replacing any copy with its id) and make it the one new
    /// messages use. The least recently used extra sessions are dropped.
    pub fn put(&mut self, session: Session) {
        if !self.available {
            return;
        }
        let entry = self.peers.entry(session.peer_device.clone()).or_default();
        entry.sessions.retain(|existing| existing.id != session.id);
        entry.active = Some(session.id.clone());
        entry.sessions.push(session);
        if entry.sessions.len() > MAX_SESSIONS_PER_PEER {
            // Keep the active session, then the most recently used others.
            let active = entry.active.clone();
            entry.sessions.sort_by_key(|existing| {
                (Some(&existing.id) != active.as_ref(), std::cmp::Reverse(existing.last_used_at))
            });
            entry.sessions.truncate(MAX_SESSIONS_PER_PEER);
        }
        self.dirty = true;
    }

    /// Store an updated session WITHOUT changing which one is active, unless
    /// none is.
    pub fn update(&mut self, session: Session) {
        if !self.available {
            return;
        }
        let entry = self.peers.entry(session.peer_device.clone()).or_default();
        if entry.active.is_none() {
            entry.active = Some(session.id.clone());
        }
        if let Some(slot) = entry.sessions.iter_mut().find(|existing| existing.id == session.id) {
            *slot = session;
        } else {
            entry.sessions.push(session);
        }
        self.dirty = true;
    }

    /// Make `session_id` the session new messages to `peer` use: the last one a
    /// message was successfully opened on, so two devices that started
    /// sessions at the same moment settle on one.
    pub fn promote(&mut self, peer: &str, session_id: &str) {
        if let Some(entry) = self.peers.get_mut(peer) {
            if entry.active.as_deref() != Some(session_id) && entry.sessions.iter().any(|session| session.id == session_id) {
                entry.active = Some(session_id.to_string());
                self.dirty = true;
            }
        }
    }

    /// Forget every session with `peer` (its keys changed, it was removed, or
    /// the user reset it). Returns whether there was anything to forget.
    pub fn forget_peer(&mut self, peer: &str) -> bool {
        if !self.available {
            return false;
        }
        let removed = self.peers.remove(peer).is_some();
        if removed {
            self.dirty = true;
        }
        removed
    }

    /// Forget every session with every peer. Returns how many were dropped.
    pub fn forget_all(&mut self) -> usize {
        if !self.available {
            return 0;
        }
        let count = self.session_count();
        if count > 0 {
            self.peers.clear();
            self.dirty = true;
        }
        count
    }

    /// Facts about the session new messages to `peer` would use, if any.
    pub fn summary_for(&self, peer: &str, now: i64) -> Option<SessionSummary> {
        self.active(peer, now).map(Session::summary)
    }

    /// Number of sessions held, for status and tests.
    pub fn session_count(&self) -> usize {
        self.peers.values().map(|entry| entry.sessions.len()).sum()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{AlgorithmSuite, HybridCiphertext};

    const NOW: i64 = 1_800_000_000;

    fn material() -> InitMaterial {
        InitMaterial {
            hybrid_ciphertext: HybridCiphertext {
                x25519_ephemeral_public: vec![7; 32],
                ml_kem_ciphertext: vec![8; 1568],
                suite: AlgorithmSuite::default(),
            },
            prekey_id: "pk-1".to_string(),
            prekey_kind: "signed_prekey".to_string(),
        }
    }

    fn ctx(session_id: &str) -> InitContext<'_> {
        InitContext {
            session_id,
            initiator_device: "dev-alice",
            responder_device: "dev-bob",
            hybrid_digest: sha3_256(b"hybrid ciphertext"),
        }
    }

    /// Alice initiates, sends one init message, Bob accepts from it.
    fn pair() -> (Session, Session, RatchetHeader, Zeroizing<[u8; 32]>) {
        let shared = [42u8; 32];
        let id = new_session_id();
        let mut alice = Session::initiate(&shared, &ctx(&id), "bob-signing", material(), NOW).unwrap();
        let (header, key) = alice.next_send(NOW).unwrap();
        let bob = Session::accept(&shared, &ctx(&id), &header, "alice-signing", "QGuard-HybridKEM-v2", NOW).unwrap();
        (alice, bob, header, key)
    }

    fn recv_ok(session: &mut Session, header: &RatchetHeader, expected: &[u8; 32]) {
        let got = session.recv(header, NOW).expect("receive");
        assert_eq!(&*got, expected, "receiver derived a different message key");
    }

    #[test]
    fn init_chain_keys_match_and_stateless_init_agrees() {
        let shared = [42u8; 32];
        let id = new_session_id();
        let mut alice = Session::initiate(&shared, &ctx(&id), "bob", material(), NOW).unwrap();
        let sent: Vec<_> = (0..3).map(|_| alice.next_send(NOW).unwrap()).collect();
        for (header, _) in &sent {
            assert_eq!(header.kind, HeaderKind::Init);
        }
        let mut bob = Session::accept(&shared, &ctx(&id), &sent[0].0, "alice", "", NOW).unwrap();
        for (header, key) in &sent {
            recv_ok(&mut bob, header, key);
            // A device with no session gets the same key from the seed alone.
            assert_eq!(&*init_message_key(&shared, &ctx(&id), header).unwrap(), &**key);
        }
    }

    #[test]
    fn ping_pong_converges_and_init_stops_after_the_first_answer() {
        let (mut alice, mut bob, first, first_key) = pair();
        recv_ok(&mut bob, &first, &first_key);
        for round in 0..20 {
            let (header, key) = bob.next_send(NOW).unwrap();
            assert_eq!(header.kind, HeaderKind::Msg, "a responder never sends init");
            recv_ok(&mut alice, &header, &key);
            let (header, key) = alice.next_send(NOW).unwrap();
            assert_eq!(header.kind, HeaderKind::Msg, "round {round}: init material must stop once Bob answered");
            recv_ok(&mut bob, &header, &key);
        }
        assert!(alice.has_ratcheted() && bob.has_ratcheted());
    }

    #[test]
    fn every_turn_uses_a_new_ratchet_key() {
        let (mut alice, mut bob, first, first_key) = pair();
        recv_ok(&mut bob, &first, &first_key);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..5 {
            let (header, key) = bob.next_send(NOW).unwrap();
            assert!(seen.insert(header.dh.clone()), "Bob reused a ratchet key across turns");
            recv_ok(&mut alice, &header, &key);
            let (header, key) = alice.next_send(NOW).unwrap();
            assert!(seen.insert(header.dh.clone()), "Alice reused a ratchet key across turns");
            recv_ok(&mut bob, &header, &key);
        }
    }

    #[test]
    fn out_of_order_within_a_chain_and_across_a_turn() {
        let (mut alice, mut bob, first, first_key) = pair();
        // Alice sends two more init messages before Bob answers.
        let late_init_1 = alice.next_send(NOW).unwrap();
        let late_init_2 = alice.next_send(NOW).unwrap();
        recv_ok(&mut bob, &first, &first_key);
        let (answer, answer_key) = bob.next_send(NOW).unwrap();
        recv_ok(&mut alice, &answer, &answer_key);
        // Alice's new chain: three messages, delivered 3, 1, 2.
        let m: Vec<_> = (0..3).map(|_| alice.next_send(NOW).unwrap()).collect();
        assert_eq!(m[0].0.pn, 3, "pn must carry the length of Alice's init chain");
        recv_ok(&mut bob, &m[2].0, &m[2].1);
        recv_ok(&mut bob, &m[0].0, &m[0].1);
        // The two init messages that were still in flight arrive after the turn.
        recv_ok(&mut bob, &late_init_2.0, &late_init_2.1);
        recv_ok(&mut bob, &late_init_1.0, &late_init_1.1);
        recv_ok(&mut bob, &m[1].0, &m[1].1);
    }

    #[test]
    fn a_message_is_opened_once() {
        let (mut alice, mut bob, first, first_key) = pair();
        recv_ok(&mut bob, &first, &first_key);
        let (header, key) = alice.next_send(NOW).unwrap();
        recv_ok(&mut bob, &header, &key);
        assert!(bob.recv(&header, NOW).is_err(), "the same chain position must not open twice");
        // The out-of-order path too: a skipped key is consumed by its message.
        let skipped = alice.next_send(NOW).unwrap();
        let after = alice.next_send(NOW).unwrap();
        recv_ok(&mut bob, &after.0, &after.1);
        recv_ok(&mut bob, &skipped.0, &skipped.1);
        assert!(bob.recv(&skipped.0, NOW).is_err());
    }

    #[test]
    fn a_gap_beyond_the_limit_is_refused() {
        let (mut alice, mut bob, first, first_key) = pair();
        recv_ok(&mut bob, &first, &first_key);
        let mut far = alice.next_send(NOW).unwrap().0;
        far.n = MAX_SKIP + 5;
        assert!(bob.clone().recv(&far, NOW).is_err());
    }

    #[test]
    fn post_quantum_step_happens_on_schedule_and_both_sides_mix_it() {
        let (mut alice, mut bob, first, first_key) = pair();
        recv_ok(&mut bob, &first, &first_key);
        // A day later, a turn: the side starting a new chain offers ML-KEM.
        let later = NOW + PQ_STEP_EVERY_SECS + 1;
        let (header, key) = bob.next_send(later).unwrap();
        let got = alice.recv(&header, later).unwrap();
        assert_eq!(*got, *key);
        let (offering, offer_key) = alice.next_send(later).unwrap();
        let offer = offering.pq_offer.clone().expect("Alice's new chain must offer an ML-KEM key once due");
        assert_eq!(offer.ek.len(), 1568);
        assert_eq!(*bob.recv(&offering, later).unwrap(), *offer_key);
        // Bob's next chain answers it; Alice mixes it on receipt.
        let (answering, answer_key) = bob.next_send(later).unwrap();
        let answer = answering.pq_answer.clone().expect("Bob must answer the offer on his next chain");
        assert_eq!(answer.for_id, offer.id);
        assert_eq!(*alice.recv(&answering, later).unwrap(), *answer_key);
        assert!(alice.pq_mine.is_none(), "an answered offer's key must be destroyed");
        assert!(alice.pq_steps >= 1 && bob.pq_steps >= 1);
        // And the session keeps working on the mixed root.
        let (header, key) = alice.next_send(later).unwrap();
        assert!(header.pq_offer.is_none(), "no new offer right after a step");
        assert_eq!(*bob.recv(&header, later).unwrap(), *key);
    }

    #[test]
    fn a_tampered_ml_kem_answer_breaks_only_the_trial_copy() {
        let (mut alice, mut bob, first, first_key) = pair();
        recv_ok(&mut bob, &first, &first_key);
        let later = NOW + PQ_STEP_EVERY_SECS + 1;
        let (header, key) = bob.next_send(later).unwrap();
        assert_eq!(*alice.recv(&header, later).unwrap(), *key);
        let (offering, offer_key) = alice.next_send(later).unwrap();
        assert_eq!(*bob.recv(&offering, later).unwrap(), *offer_key);
        let (mut answering, answer_key) = bob.next_send(later).unwrap();
        answering.pq_answer.as_mut().unwrap().ct[0] ^= 1;
        let mut trial = alice.clone();
        // ML-KEM decapsulation of a tampered ciphertext yields a different
        // secret (implicit rejection), so the derived key cannot match.
        let wrong = trial.recv(&answering, later).unwrap();
        assert_ne!(*wrong, *answer_key);
        // The caller discards the trial when the AEAD tag fails; the real
        // session still opens the genuine message.
        answering.pq_answer.as_mut().unwrap().ct[0] ^= 1;
        assert_eq!(*alice.recv(&answering, later).unwrap(), *answer_key);
    }

    #[test]
    fn an_answer_to_an_unknown_offer_is_refused() {
        let (mut alice, mut bob, first, first_key) = pair();
        recv_ok(&mut bob, &first, &first_key);
        let (mut header, _) = bob.next_send(NOW).unwrap();
        header.pq_answer = Some(PqAnswer { for_id: "ab".repeat(16), ct: vec![0; 1568] });
        assert!(alice.recv(&header, NOW).is_err());
    }

    #[test]
    fn forward_secrecy_a_used_key_is_not_in_the_state() {
        let (mut alice, mut bob, first, first_key) = pair();
        recv_ok(&mut bob, &first, &first_key);
        let (header, key) = alice.next_send(NOW).unwrap();
        recv_ok(&mut bob, &header, &key);
        let stored = serde_json::to_vec(&bob.clone()).unwrap();
        let needle = serde_json::to_vec(&key.to_vec()).unwrap();
        let needle = &needle[1..needle.len() - 1]; // the numbers, without brackets
        assert!(
            !stored.windows(needle.len()).any(|window| window == needle),
            "a message key that has been used must not survive in the session state"
        );
    }

    #[test]
    fn post_compromise_a_stolen_state_stops_working_after_a_round_trip() {
        let (mut alice, mut bob, first, first_key) = pair();
        recv_ok(&mut bob, &first, &first_key);
        // The attacker copies Bob's entire session — including the ratchet key
        // Bob already generated for his next turn.
        let mut stolen = bob.clone();
        let (b1, b1_key) = bob.next_send(NOW).unwrap();
        recv_ok(&mut alice, &b1, &b1_key);
        let (a1, a1_key) = alice.next_send(NOW).unwrap();
        recv_ok(&mut bob, &a1, &a1_key);
        // Not healed yet: Alice's reply was made against a key the thief holds.
        assert_eq!(*stolen.recv(&a1, NOW).unwrap(), *a1_key);
        // One more round trip. Bob's next turn uses a key generated AFTER the
        // theft, so Alice's answer to it is out of the thief's reach.
        let (b2, b2_key) = bob.next_send(NOW).unwrap();
        recv_ok(&mut alice, &b2, &b2_key);
        let (a2, a2_key) = alice.next_send(NOW).unwrap();
        recv_ok(&mut bob, &a2, &a2_key);
        let guessed = stolen.recv(&a2, NOW).unwrap();
        assert_ne!(*guessed, *a2_key, "a stolen session must not follow the conversation past a round trip");
    }

    #[test]
    fn sessions_survive_serialization() {
        let (mut alice, bob, first, first_key) = pair();
        let mut bob: Session = serde_json::from_slice(&serde_json::to_vec(&bob).unwrap()).unwrap();
        recv_ok(&mut bob, &first, &first_key);
        let (header, key) = bob.next_send(NOW).unwrap();
        let mut alice2: Session = serde_json::from_slice(&serde_json::to_vec(&alice).unwrap()).unwrap();
        recv_ok(&mut alice2, &header, &key);
        let _ = alice.next_send(NOW).unwrap();
    }

    #[test]
    fn header_encoding_is_unambiguous_and_validated() {
        let (_, _, header, _) = pair();
        let base = header.canonical_bytes();
        let mut changed = header.clone();
        changed.n += 1;
        assert_ne!(changed.canonical_bytes(), base);
        let mut changed = header.clone();
        changed.kind = HeaderKind::Msg;
        assert_ne!(changed.canonical_bytes(), base);
        let mut changed = header.clone();
        changed.dh[0] ^= 1;
        assert_ne!(changed.canonical_bytes(), base);

        let mut bad = header.clone();
        bad.dh.pop();
        assert!(bad.validate().is_err());
        let mut bad = header.clone();
        bad.v = 2;
        assert!(bad.validate().is_err());
        let mut bad = header.clone();
        bad.session = "not hex!".to_string();
        assert!(bad.validate().is_err());
        let mut bad = header.clone();
        let ek = PqKeypair::generate().ek.clone();
        bad.pq_offer = Some(PqOffer { id: "00".repeat(16), ek });
        assert!(bad.validate().is_err(), "an offer id must be the digest of its key");
    }

    #[test]
    fn a_low_order_ratchet_key_is_refused() {
        let (mut alice, mut bob, first, first_key) = pair();
        recv_ok(&mut bob, &first, &first_key);
        let (mut header, _) = bob.next_send(NOW).unwrap();
        header.dh = vec![0; 32];
        assert!(alice.recv(&header, NOW).is_err());
    }

    #[test]
    fn book_keeps_the_active_session_and_promotes_on_use() {
        let (alice, _, _, _) = pair();
        let mut book = SessionBook::empty("user", "dev-alice");
        let first_id = alice.id.clone();
        book.put(alice.clone());
        assert_eq!(book.active("dev-bob", NOW).unwrap().id, first_id);
        let id2 = new_session_id();
        let second = Session::initiate(&[1; 32], &ctx(&id2), "bob", material(), NOW + 5).unwrap();
        book.put(second);
        assert_eq!(book.active("dev-bob", NOW + 5).unwrap().id, id2);
        book.promote("dev-bob", &first_id);
        assert_eq!(book.active("dev-bob", NOW + 5).unwrap().id, first_id);
        for offset in 0..5 {
            let id = new_session_id();
            book.put(Session::initiate(&[2; 32], &ctx(&id), "bob", material(), NOW + 10 + offset).unwrap());
        }
        assert!(book.session_count() <= MAX_SESSIONS_PER_PEER);
        let encoded = book.encode().unwrap();
        let reloaded = SessionBook::decode("user", "dev-alice", &encoded).unwrap();
        assert_eq!(reloaded.session_count(), book.session_count());
        assert!(!reloaded.is_dirty());
        assert!(reloaded.active("dev-bob", NOW + 20).is_some());
        assert!(reloaded.active("dev-bob", NOW + 20 + SESSION_MAX_AGE_SECS + 100).is_none(), "a month-old session is retired");
        assert!(reloaded.summary_for("dev-bob", NOW + 20).is_some());
    }

    #[test]
    fn sessions_of_a_previous_device_identity_are_dropped_on_load() {
        let (alice, _, _, _) = pair();
        let mut book = SessionBook::empty("user", "dev-alice");
        book.put(alice);
        let encoded = book.encode().unwrap();
        // The same account, after this device re-keyed under a new device id.
        let reloaded = SessionBook::decode("user", "dev-alice-rekeyed", &encoded).unwrap();
        assert_eq!(reloaded.session_count(), 0, "peers address the new device id; old sessions are dead");
        assert!(reloaded.is_dirty(), "the dead sessions must be written away, not kept on disk");
    }

    #[test]
    fn an_unavailable_book_never_takes_writes() {
        let (alice, _, _, _) = pair();
        let mut book = SessionBook::unavailable("user", "dev-alice", NOW + 60);
        book.put(alice);
        assert_eq!(book.session_count(), 0);
        assert!(!book.forget_peer("dev-bob"));
        assert_eq!(book.forget_all(), 0);
        assert!(!book.is_dirty());
    }

    #[test]
    fn forgetting_a_peer_and_everything() {
        let (alice, _, _, _) = pair();
        let mut book = SessionBook::empty("user", "dev-alice");
        book.put(alice);
        book.mark_saved();
        assert!(!book.forget_peer("dev-nobody"));
        assert!(!book.is_dirty());
        assert!(book.forget_peer("dev-bob"));
        assert!(book.is_dirty());
        assert!(book.active("dev-bob", NOW).is_none());
        let id = new_session_id();
        book.put(Session::initiate(&[3; 32], &ctx(&id), "bob", material(), NOW).unwrap());
        assert_eq!(book.forget_all(), 1);
        assert_eq!(book.session_count(), 0);
    }

    #[test]
    fn helpers_bind_exactly_what_they_claim() {
        let a = init_kex_info("s1", "ua", "ub", "da", "db");
        assert_ne!(a, init_kex_info("s2", "ua", "ub", "da", "db"), "a seed is bound to its session");
        assert_ne!(a, init_kex_info("s1", "ua", "ub", "da", "dc"), "and to its devices");
        assert_ne!(signing_digest(b"ab", b"c"), signing_digest(b"a", b"bc"), "the digest is length-prefixed");
        let ct = |x: Vec<u8>, m: Vec<u8>| crate::crypto::HybridCiphertext {
            x25519_ephemeral_public: x,
            ml_kem_ciphertext: m,
            suite: AlgorithmSuite::default(),
        };
        assert_ne!(hybrid_digest(&ct(vec![1, 2], vec![3])), hybrid_digest(&ct(vec![1], vec![2, 3])));
        let mut suite = AlgorithmSuite::default();
        assert!(!peer_supports(Some(&suite)), "the default suite does not advertise the ratchet");
        assert!(!peer_supports(None));
        suite.ratchet = RATCHET_PROTOCOL.to_string();
        assert!(peer_supports(Some(&suite)));
        suite.ratchet = "QGuard-PQRatchet-v9".to_string();
        assert!(!peer_supports(Some(&suite)), "an unknown ratchet version is not ours");
    }
}
