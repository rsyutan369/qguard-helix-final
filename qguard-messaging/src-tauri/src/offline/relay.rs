//! Multi-hop Mesh relay: store, carry and forward sealed envelopes between
//! trusted devices, so a message reaches a recipient that is out of direct
//! range through up to [`MAX_HOPS`] other Qguard devices.
//!
//! End to end, independent of every relay:
//! - Key establishment: X25519 + ML-KEM-768 to the recipient's static relay
//!   key (exchanged earlier on an authenticated, paired session), combined
//!   with HKDF-SHA3-256 over both shares and the full transcript.
//! - Encryption: AES-256-GCM. The header (id, tag, times) is authenticated
//!   data; the hop counter is not, because relays decrement it.
//! - Authentication: the sender signs inside the ciphertext with its pinned
//!   Ed25519 + ML-DSA-65 device identity; the recipient accepts only a sender
//!   it paired with for Mesh.
//!
//! What a relay learns: an opaque per-envelope tag, sizes and times. Never the
//! sender, the recipient, or any text. Relays are themselves trusted devices
//! (paired for Mesh), and every store is bounded: per-peer and total quotas,
//! expiry, a hop limit, and duplicate suppression by envelope id.
//!
//! This construction needs independent cryptographic review before release.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    crypto::provider,
    error::{QGuardError, Result},
    state::AppState,
};

use super::{
    lan::fingerprint_valid,
    mesh,
    session::{self, Identity},
};

pub(super) const DOC: &str = "offline-mesh-relay";
const AAD: &[u8] = b"QGuard-Offline-Mesh-Relay-Store-v1";
pub(super) const KEY_DOC: &str = "offline-relay-key";
const KEY_AAD: &[u8] = b"QGuard-Offline-Mesh-Relay-Key-v1";
const TAG_LABEL: &[u8] = b"QGuard-Mesh-Relay-Tag-v1";
const SEAL_LABEL: &[u8] = b"QGuard-Mesh-Relay-Seal-v1";
const SIGN_LABEL: &[u8] = b"QGuard-Mesh-Relay-Signature-v1";
const HEADER_LABEL: &[u8] = b"QGuard-Mesh-Relay-Header-v1";

/// Relays an envelope may pass through after leaving its sender.
pub(super) const MAX_HOPS: u8 = 4;
/// Envelopes carried for other devices.
const MAX_CARRIED: usize = 256;
/// Envelopes carried that arrived from any one peer.
const MAX_FROM_PEER: usize = 64;
/// Envelopes this device created (its own messages and receipts).
const MAX_OWN: usize = 512;
const MAX_SEEN: usize = 4096;
const MAX_CIPHERTEXT: usize = 24 * 1024;
const MAX_LIFETIME: i64 = 7 * 24 * 60 * 60;
const CLOCK_SKEW: i64 = 5 * 60;
const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MLKEM768_SECRET_KEY_BYTES: usize = 2400;

// ---- keys -----------------------------------------------------------------

/// A device's static relay public key, as exchanged between paired devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RelayPublic {
    pub x25519: String,
    pub mlkem: String,
}

impl RelayPublic {
    fn decode(&self) -> Result<([u8; 32], Vec<u8>)> {
        let x = decode_exact(&self.x25519, 32)?;
        let kem = decode_exact(&self.mlkem, provider::MLKEM768_PUBLIC_KEY_BYTES)?;
        Ok((x.try_into().map_err(|_| invalid_key())?, kem))
    }

    pub fn validate(&self) -> Result<()> {
        self.decode().map(|_| ())
    }
}

fn invalid_key() -> QGuardError {
    QGuardError::InvalidInput("The peer sent an invalid Mesh relay key.".into())
}

/// This device's static relay key pair (sealed under the device storage key).
pub(super) struct RelayKeys {
    x_secret: Zeroizing<[u8; 32]>,
    kem_secret: Zeroizing<Vec<u8>>,
    public: RelayPublic,
    x_public: [u8; 32],
    kem_public: Vec<u8>,
}

impl RelayKeys {
    pub fn load(state: &AppState, owner: &str) -> Result<Self> {
        provider::require_offline_suite()?;
        if let Some(bytes) = state.load_user_secret_doc(owner, KEY_DOC, KEY_AAD, KEY_DOC)? {
            let expected = 32 + provider::MLKEM768_PUBLIC_KEY_BYTES + MLKEM768_SECRET_KEY_BYTES;
            if bytes.len() != expected {
                return Err(QGuardError::Storage("The Mesh relay key is unreadable.".into()));
            }
            let x_secret = Zeroizing::new(<[u8; 32]>::try_from(&bytes[..32]).map_err(|_| invalid_key())?);
            let kem_public = bytes[32..32 + provider::MLKEM768_PUBLIC_KEY_BYTES].to_vec();
            let kem_secret = Zeroizing::new(bytes[32 + provider::MLKEM768_PUBLIC_KEY_BYTES..].to_vec());
            return Self::from_parts(x_secret, kem_public, kem_secret);
        }
        let (x_secret, _) = provider::x25519_generate()?;
        let (kem_public, kem_secret) = provider::mlkem768_generate()?;
        let mut record = Zeroizing::new(Vec::with_capacity(32 + kem_public.len() + kem_secret.len()));
        record.extend_from_slice(x_secret.as_ref());
        record.extend_from_slice(&kem_public);
        record.extend_from_slice(&kem_secret);
        state.save_user_secret_doc(owner, KEY_DOC, KEY_AAD, &record, KEY_DOC)?;
        Self::from_parts(x_secret, kem_public, kem_secret)
    }

    fn from_parts(x_secret: Zeroizing<[u8; 32]>, kem_public: Vec<u8>, kem_secret: Zeroizing<Vec<u8>>) -> Result<Self> {
        let x_public = provider::x25519_public(&x_secret)?;
        Ok(Self {
            public: RelayPublic { x25519: STANDARD.encode(x_public), mlkem: STANDARD.encode(&kem_public) },
            x_secret,
            kem_secret,
            x_public,
            kem_public,
        })
    }

    pub fn public(&self) -> &RelayPublic {
        &self.public
    }

    #[cfg(test)]
    fn generate() -> Result<Self> {
        let (x_secret, _) = provider::x25519_generate()?;
        let (kem_public, kem_secret) = provider::mlkem768_generate()?;
        Self::from_parts(x_secret, kem_public, kem_secret)
    }
}

// ---- envelopes ------------------------------------------------------------

/// What crosses relays. Only `hops` changes on the way.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Envelope {
    pub id: Uuid,
    /// SHA3-256 over the recipient fingerprint and `id`: only the recipient
    /// can recognise its envelopes; relays cannot link them.
    tag: String,
    pub hops: u8,
    created_at: i64,
    pub expires_at: i64,
    ephemeral: String,
    kem: String,
    nonce: String,
    ciphertext: String,
    auth: String,
}

/// What the recipient reads inside an envelope.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase", deny_unknown_fields)]
pub(super) enum Payload {
    Message(mesh::Delivery),
    Receipt(mesh::Receipt),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inner {
    sender: String,
    recipient: String,
    /// The exact signed JSON text of the [`Payload`].
    payload: String,
    signature: String,
}

pub(super) struct Opened {
    pub sender: String,
    pub payload: Payload,
}

fn decode_exact(value: &str, len: usize) -> Result<Vec<u8>> {
    // Bound the work before decoding attacker-supplied text.
    if value.len() > len.div_ceil(3) * 4 + 4 {
        return Err(malformed());
    }
    let bytes = STANDARD.decode(value).map_err(|_| malformed())?;
    if bytes.len() != len {
        return Err(malformed());
    }
    Ok(bytes)
}

fn malformed() -> QGuardError {
    QGuardError::InvalidInput("The Mesh relay envelope is malformed.".into())
}

fn tag_for(recipient: &str, id: &Uuid) -> String {
    hex::encode(session::domain_hash(TAG_LABEL, &[recipient.as_bytes(), id.as_bytes()]))
}

fn header(id: &Uuid, tag: &str, created_at: i64, expires_at: i64) -> [u8; 32] {
    session::domain_hash(
        HEADER_LABEL,
        &[id.as_bytes(), tag.as_bytes(), &created_at.to_be_bytes(), &expires_at.to_be_bytes()],
    )
}

fn signed_digest(header: &[u8; 32], sender: &str, recipient: &str, payload: &str) -> [u8; 32] {
    session::domain_hash(SIGN_LABEL, &[header, sender.as_bytes(), recipient.as_bytes(), payload.as_bytes()])
}

fn seal_key(
    id: &Uuid,
    ephemeral: &[u8; 32],
    kem_ciphertext: &[u8],
    x_public: &[u8; 32],
    kem_public: &[u8],
    x_shared: &[u8; 32],
    kem_shared: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(x_shared);
    ikm[32..].copy_from_slice(kem_shared);
    let info = session::domain_hash(SEAL_LABEL, &[ephemeral, kem_ciphertext, x_public, kem_public]);
    let mut key = Zeroizing::new([0u8; 32]);
    provider::hkdf_sha3_256(Some(id.as_bytes()), ikm.as_ref(), &info, key.as_mut())?;
    Ok(key)
}

/// Seal `payload` for `recipient` (whose relay key this device pinned).
pub(super) fn seal(
    identity: &Identity,
    recipient: &str,
    key: &RelayPublic,
    payload: &Payload,
    created_at: i64,
    expires_at: i64,
) -> Result<Envelope> {
    provider::require_offline_suite()?;
    if !fingerprint_valid(recipient) || recipient == identity.fingerprint() {
        return Err(QGuardError::InvalidInput("Choose a different Mesh recipient.".into()));
    }
    let (x_public, kem_public) = key.decode()?;
    let id = Uuid::new_v4();
    let tag = tag_for(recipient, &id);
    let (ephemeral_secret, ephemeral) = provider::x25519_generate()?;
    let x_shared = provider::x25519_shared(&ephemeral_secret, &x_public)?;
    if !x_shared.was_contributory() {
        return Err(invalid_key());
    }
    let (kem_ciphertext, kem_shared) = provider::mlkem768_encapsulate(&kem_public)?;
    let aead_key = seal_key(&id, &ephemeral, &kem_ciphertext, &x_public, &kem_public, x_shared.as_bytes(), &kem_shared)?;
    let payload = serde_json::to_string(payload).map_err(|_| malformed())?;
    let header = header(&id, &tag, created_at, expires_at);
    let signature = identity.sign_digest(&signed_digest(&header, identity.fingerprint(), recipient, &payload))?;
    let inner = Zeroizing::new(
        serde_json::to_vec(&Inner {
            sender: identity.fingerprint().to_owned(),
            recipient: recipient.to_owned(),
            payload,
            signature: STANDARD.encode(signature),
        })
        .map_err(|_| malformed())?,
    );
    if inner.len() > MAX_CIPHERTEXT {
        return Err(QGuardError::InvalidInput("The Mesh message is too large to relay.".into()));
    }
    let sealed = provider::aes256gcm_seal(&aead_key, &header, &inner)?;
    Ok(Envelope {
        id,
        tag,
        hops: MAX_HOPS,
        created_at,
        expires_at,
        ephemeral: STANDARD.encode(ephemeral),
        kem: STANDARD.encode(kem_ciphertext),
        nonce: STANDARD.encode(sealed.nonce),
        ciphertext: STANDARD.encode(sealed.ciphertext),
        auth: STANDARD.encode(sealed.tag),
    })
}

impl Envelope {
    /// Structural checks every relay applies before storing.
    pub fn validate(&self, now: i64) -> Result<()> {
        let lifetime = self.expires_at.checked_sub(self.created_at);
        if self.id.is_nil()
            || self.tag.len() != 64
            || !self.tag.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            || self.hops > MAX_HOPS
            || self.created_at > now.saturating_add(CLOCK_SKEW)
            || self.expires_at <= now
            || lifetime.is_none_or(|lifetime| !(1..=MAX_LIFETIME).contains(&lifetime))
            || self.ciphertext.len() > MAX_CIPHERTEXT.div_ceil(3) * 4 + 4
        {
            return Err(malformed());
        }
        decode_exact(&self.ephemeral, 32)?;
        decode_exact(&self.kem, provider::MLKEM768_CIPHERTEXT_BYTES)?;
        decode_exact(&self.nonce, provider::AES_GCM_NONCE_BYTES)?;
        decode_exact(&self.auth, provider::AES_GCM_TAG_BYTES)?;
        Ok(())
    }

    /// Whether this device is the recipient (constant-time tag comparison).
    pub fn addressed_to(&self, local: &str) -> bool {
        provider::constant_time_eq(tag_for(local, &self.id).as_bytes(), self.tag.as_bytes())
    }

    /// Open an envelope addressed to `local`. `trusted_identity` returns the
    /// pinned identity key of a device paired for Mesh, else `None`.
    pub fn open(
        &self,
        keys: &RelayKeys,
        local: &str,
        trusted_identity: impl Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<Opened> {
        provider::require_offline_suite()?;
        if !self.addressed_to(local) {
            return Err(malformed());
        }
        let ephemeral: [u8; 32] = decode_exact(&self.ephemeral, 32)?.try_into().map_err(|_| malformed())?;
        let kem_ciphertext = decode_exact(&self.kem, provider::MLKEM768_CIPHERTEXT_BYTES)?;
        let nonce = decode_exact(&self.nonce, provider::AES_GCM_NONCE_BYTES)?;
        let auth = decode_exact(&self.auth, provider::AES_GCM_TAG_BYTES)?;
        let ciphertext = STANDARD.decode(&self.ciphertext).map_err(|_| malformed())?;
        let x_shared = provider::x25519_shared(&keys.x_secret, &ephemeral)?;
        if !x_shared.was_contributory() {
            return Err(malformed());
        }
        let kem_shared = provider::mlkem768_decapsulate(&keys.kem_secret, &kem_ciphertext)?;
        let aead_key = seal_key(
            &self.id,
            &ephemeral,
            &kem_ciphertext,
            &keys.x_public,
            &keys.kem_public,
            x_shared.as_bytes(),
            &kem_shared,
        )?;
        let header = header(&self.id, &self.tag, self.created_at, self.expires_at);
        let plain = Zeroizing::new(provider::aes256gcm_open(&aead_key, &nonce, &header, &ciphertext, &auth)?);
        let inner: Inner = serde_json::from_slice(&plain).map_err(|_| malformed())?;
        if inner.recipient != local || !fingerprint_valid(&inner.sender) || inner.sender == local {
            return Err(forged());
        }
        let identity = trusted_identity(&inner.sender).ok_or_else(|| {
            QGuardError::Trust("A relayed Mesh message came from a device that is not paired for Mesh.".into())
        })?;
        if session::fingerprint(&identity) != inner.sender {
            return Err(forged());
        }
        let signature = STANDARD.decode(&inner.signature).map_err(|_| forged())?;
        session::verify_digest(&identity, &signed_digest(&header, &inner.sender, local, &inner.payload), &signature)
            .map_err(|_| forged())?;
        let payload: Payload = serde_json::from_str(&inner.payload).map_err(|_| forged())?;
        let consistent = match &payload {
            Payload::Message(delivery) => delivery.sender == inner.sender && delivery.recipient == local,
            Payload::Receipt(receipt) => receipt.recipient == inner.sender && receipt.sender == local,
        };
        if !consistent {
            return Err(forged());
        }
        Ok(Opened { sender: inner.sender, payload })
    }

    /// The copy sent onward: one hop fewer.
    fn onward(&self) -> Self {
        let mut next = self.clone();
        next.hops = self.hops.saturating_sub(1);
        next
    }
}

fn forged() -> QGuardError {
    QGuardError::Trust("A relayed Mesh envelope failed end-to-end verification.".into())
}

// ---- store ----------------------------------------------------------------

/// A message or receipt this device sealed, so it is sealed only once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Origin {
    pub message: Uuid,
    pub recipient: String,
    pub receipt: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    envelope: Envelope,
    /// The peer it arrived from; `None` for envelopes this device created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<Origin>,
    #[serde(default)]
    forwarded: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Seen {
    id: Uuid,
    until: i64,
}

#[derive(PartialEq, Eq, Debug)]
pub(super) enum Accepted {
    /// Stored to carry onward.
    Carried,
    /// Already held or delivered here, or at its hop limit; the sender may stop.
    Known,
    /// Over quota; the sender should keep it and try another time.
    Full,
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct Store {
    entries: Vec<Entry>,
    seen: Vec<Seen>,
}

impl Store {
    pub fn load(state: &AppState, owner: &str, now: i64) -> Result<Self> {
        let Some(bytes) = state.load_user_secret_doc(owner, DOC, AAD, DOC)? else {
            return Ok(Self::default());
        };
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(QGuardError::Storage("The Mesh relay store exceeds its limit.".into()));
        }
        let mut store: Self = serde_json::from_slice(&bytes)
            .map_err(|_| QGuardError::Storage("The Mesh relay store is unreadable.".into()))?;
        store.prune(now);
        Ok(store)
    }

    pub fn save(&self, state: &AppState, owner: &str) -> Result<()> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(self).map_err(|_| QGuardError::Storage("The Mesh relay store could not be saved.".into()))?,
        );
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(QGuardError::Storage("The Mesh relay store is full.".into()));
        }
        state.save_user_secret_doc(owner, DOC, AAD, &bytes, DOC)
    }

    pub fn prune(&mut self, now: i64) {
        for entry in self.entries.iter().filter(|entry| entry.envelope.expires_at <= now) {
            self.seen.push(Seen { id: entry.envelope.id, until: entry.envelope.expires_at });
        }
        self.entries.retain(|entry| entry.envelope.expires_at > now);
        self.seen.retain(|seen| seen.until > now);
        if self.seen.len() > MAX_SEEN {
            self.seen.sort_by_key(|seen| std::cmp::Reverse(seen.until));
            self.seen.truncate(MAX_SEEN);
        }
    }

    pub fn known(&self, id: Uuid) -> bool {
        self.entries.iter().any(|entry| entry.envelope.id == id) || self.seen.iter().any(|seen| seen.id == id)
    }

    /// Remember an envelope that was delivered here, so copies arriving over
    /// other paths are recognised and dropped.
    pub fn remember(&mut self, envelope: &Envelope) {
        if !self.known(envelope.id) {
            self.seen.push(Seen { id: envelope.id, until: envelope.expires_at });
        }
    }

    pub fn carrying(&self) -> usize {
        self.entries.iter().filter(|entry| entry.from.is_some()).count()
    }

    /// Carry another device's envelope onward (already validated).
    pub fn carry(&mut self, envelope: Envelope, from: &str, now: i64) -> Accepted {
        if self.known(envelope.id) {
            return Accepted::Known;
        }
        if envelope.hops == 0 {
            self.remember(&envelope);
            return Accepted::Known;
        }
        if self.entries.iter().filter(|entry| entry.from.as_deref() == Some(from)).count() >= MAX_FROM_PEER {
            return Accepted::Full;
        }
        if self.carrying() >= MAX_CARRIED {
            // Make room only by dropping a carried envelope that expires sooner.
            let soonest = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.from.is_some())
                .min_by_key(|(_, entry)| entry.envelope.expires_at)
                .map(|(index, entry)| (index, entry.envelope.expires_at));
            match soonest {
                Some((index, expires_at)) if expires_at < envelope.expires_at => {
                    let dropped = self.entries.remove(index);
                    self.seen.push(Seen { id: dropped.envelope.id, until: dropped.envelope.expires_at.max(now) });
                }
                _ => return Accepted::Full,
            }
        }
        self.entries.push(Entry { envelope, from: Some(from.to_owned()), origin: None, forwarded: Vec::new() });
        Accepted::Carried
    }

    /// Messages (not receipts) this device sealed and still holds.
    pub fn own_messages(&self) -> Vec<Origin> {
        self.entries
            .iter()
            .filter_map(|entry| entry.origin.clone())
            .filter(|origin| !origin.receipt)
            .collect()
    }

    /// Stop carrying for others (the user turned relaying off).
    pub fn clear_carried(&mut self) {
        let mut dropped = Vec::new();
        self.entries.retain(|entry| {
            if entry.from.is_some() {
                dropped.push(Seen { id: entry.envelope.id, until: entry.envelope.expires_at });
            }
            entry.from.is_none()
        });
        self.seen.extend(dropped);
    }

    pub fn has_origin(&self, origin: &Origin) -> bool {
        self.entries.iter().any(|entry| entry.origin.as_ref() == Some(origin))
    }

    pub fn add_own(&mut self, envelope: Envelope, origin: Origin) -> Result<()> {
        if self.entries.iter().filter(|entry| entry.from.is_none()).count() >= MAX_OWN {
            return Err(QGuardError::Storage("The Mesh relay outbox is full. Retry after older messages expire.".into()));
        }
        self.entries.push(Entry { envelope, from: None, origin: Some(origin), forwarded: Vec::new() });
        Ok(())
    }

    /// Drop this device's sealed copies for a message (delivered or receipted).
    pub fn drop_own(&mut self, message: Uuid, recipient: &str) -> bool {
        let before = self.entries.len();
        let mut dropped = Vec::new();
        self.entries.retain(|entry| {
            let matches = entry
                .origin
                .as_ref()
                .is_some_and(|origin| !origin.receipt && origin.message == message && origin.recipient == recipient);
            if matches {
                dropped.push(Seen { id: entry.envelope.id, until: entry.envelope.expires_at });
            }
            !matches
        });
        self.seen.extend(dropped);
        self.entries.len() != before
    }

    /// Envelopes to hand to `peer`, one hop fewer, oldest first.
    pub fn outbound_for(&self, peer: &str, limit: usize) -> Vec<Envelope> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.envelope.hops > 0
                    && entry.from.as_deref() != Some(peer)
                    && !entry.forwarded.iter().any(|value| value == peer)
            })
            .take(limit)
            .map(|entry| entry.envelope.onward())
            .collect()
    }

    /// `peer` now holds `id`. Returns this device's origin for its own copies.
    pub fn forwarded(&mut self, id: Uuid, peer: &str) -> Option<Origin> {
        let entry = self.entries.iter_mut().find(|entry| entry.envelope.id == id)?;
        if !entry.forwarded.iter().any(|value| value == peer) {
            entry.forwarded.push(peer.to_owned());
        }
        entry.origin.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivery(sender: &str, recipient: &str, body: &str, now: i64) -> mesh::Delivery {
        serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(),
            "sender": sender,
            "recipient": recipient,
            "body": body,
            "group": null,
            "emergency": true,
            "createdAt": now,
            "expiresAt": now + 3600,
        }))
        .unwrap()
    }

    struct Device {
        identity: Identity,
        keys: RelayKeys,
    }

    fn device() -> Device {
        Device { identity: Identity::generate().unwrap(), keys: RelayKeys::generate().unwrap() }
    }

    fn pinned<'a>(devices: &'a [&'a Device]) -> impl Fn(&str) -> Option<Vec<u8>> + 'a {
        move |fingerprint| {
            devices
                .iter()
                .find(|device| device.identity.fingerprint() == fingerprint)
                .map(|device| device.identity.public_bytes().to_vec())
        }
    }

    #[test]
    fn only_the_recipient_opens_and_relays_see_no_identities_or_text() {
        let now = chrono::Utc::now().timestamp();
        let (alice, bob, carol) = (device(), device(), device());
        let message = delivery(alice.identity.fingerprint(), bob.identity.fingerprint(), "meet at the north gate", now);
        let envelope = seal(&alice.identity, bob.identity.fingerprint(), bob.keys.public(), &Payload::Message(message.clone()), now, now + 3600).unwrap();
        envelope.validate(now).unwrap();
        assert_eq!(envelope.hops, MAX_HOPS);

        let wire = serde_json::to_string(&envelope).unwrap();
        for secret in ["meet at the north gate", alice.identity.fingerprint(), bob.identity.fingerprint()] {
            assert!(!wire.contains(secret), "a relay must not see {secret}");
        }

        assert!(envelope.addressed_to(bob.identity.fingerprint()));
        assert!(!envelope.addressed_to(carol.identity.fingerprint()));
        assert!(envelope.open(&carol.keys, carol.identity.fingerprint(), pinned(&[&alice])).is_err());

        let opened = envelope.open(&bob.keys, bob.identity.fingerprint(), pinned(&[&alice])).unwrap();
        assert_eq!(opened.sender, alice.identity.fingerprint());
        assert!(matches!(opened.payload, Payload::Message(received) if received == message));

        // Relays decrement the hop counter; the envelope still opens.
        let onward = envelope.onward().onward();
        assert_eq!(onward.hops, MAX_HOPS - 2);
        assert!(onward.open(&bob.keys, bob.identity.fingerprint(), pinned(&[&alice])).is_ok());
    }

    #[test]
    fn tampering_an_unpaired_sender_or_a_mismatched_payload_is_rejected() {
        let now = chrono::Utc::now().timestamp();
        let (alice, bob, mallory) = (device(), device(), device());
        let message = delivery(alice.identity.fingerprint(), bob.identity.fingerprint(), "hello", now);
        let envelope = seal(&alice.identity, bob.identity.fingerprint(), bob.keys.public(), &Payload::Message(message), now, now + 3600).unwrap();
        let open = |envelope: &Envelope, devices: &[&Device]| envelope.open(&bob.keys, bob.identity.fingerprint(), pinned(devices));

        // A sender this device never paired with for Mesh.
        assert!(open(&envelope, &[&mallory]).is_err());
        // Authenticated header and ciphertext.
        let mut later = envelope.clone();
        later.expires_at += 60;
        assert!(open(&later, &[&alice]).is_err());
        let mut flipped = envelope.clone();
        let mut bytes = STANDARD.decode(&flipped.ciphertext).unwrap();
        bytes[0] ^= 1;
        flipped.ciphertext = STANDARD.encode(bytes);
        assert!(open(&flipped, &[&alice]).is_err());
        assert!(open(&envelope, &[&alice]).is_ok());

        // A sender cannot claim another device's message inside its own seal.
        let claimed = delivery(mallory.identity.fingerprint(), bob.identity.fingerprint(), "spoof", now);
        let spoof = seal(&alice.identity, bob.identity.fingerprint(), bob.keys.public(), &Payload::Message(claimed), now, now + 3600).unwrap();
        assert!(open(&spoof, &[&alice, &mallory]).is_err());
    }

    #[test]
    fn invalid_envelopes_are_refused_before_storage() {
        let now = chrono::Utc::now().timestamp();
        let (alice, bob) = (device(), device());
        let message = delivery(alice.identity.fingerprint(), bob.identity.fingerprint(), "x", now);
        let envelope = seal(&alice.identity, bob.identity.fingerprint(), bob.keys.public(), &Payload::Message(message), now, now + 3600).unwrap();
        let mut expired = envelope.clone();
        expired.expires_at = now - 1;
        assert!(expired.validate(now).is_err());
        let mut too_many_hops = envelope.clone();
        too_many_hops.hops = MAX_HOPS + 1;
        assert!(too_many_hops.validate(now).is_err());
        let mut long_lived = envelope.clone();
        long_lived.expires_at = now + MAX_LIFETIME + 3600;
        assert!(long_lived.validate(now).is_err());
        let mut huge = envelope.clone();
        huge.ciphertext = "A".repeat(MAX_CIPHERTEXT * 2);
        assert!(huge.validate(now).is_err());
        assert!(envelope.validate(now).is_ok());
    }

    #[test]
    fn the_store_is_bounded_deduplicated_and_never_returns_an_envelope_to_its_source() {
        let now = chrono::Utc::now().timestamp();
        let (alice, bob) = (device(), device());
        let seal_one = |hops: u8| {
            let message = delivery(alice.identity.fingerprint(), bob.identity.fingerprint(), "x", now);
            let mut envelope = seal(&alice.identity, bob.identity.fingerprint(), bob.keys.public(), &Payload::Message(message), now, now + 3600).unwrap();
            envelope.hops = hops;
            envelope
        };
        let peer_a = "aa".repeat(32);
        let peer_b = "bb".repeat(32);
        let mut store = Store::default();
        let envelope = seal_one(2);
        assert_eq!(store.carry(envelope.clone(), &peer_a, now), Accepted::Carried);
        assert_eq!(store.carry(envelope.clone(), &peer_b, now), Accepted::Known, "duplicates are dropped");
        assert!(store.outbound_for(&peer_a, 10).is_empty(), "never back to its source");
        let onward = store.outbound_for(&peer_b, 10);
        assert_eq!(onward.len(), 1);
        assert_eq!(onward[0].hops, 1);
        assert_eq!(store.forwarded(envelope.id, &peer_b), None);
        assert!(store.outbound_for(&peer_b, 10).is_empty(), "each peer receives it once");

        // At the hop limit it is remembered, not carried.
        let last = seal_one(0);
        assert_eq!(store.carry(last.clone(), &peer_a, now), Accepted::Known);
        assert!(store.known(last.id));
        assert_eq!(store.carrying(), 1);

        // One peer cannot fill the store.
        for _ in 1..MAX_FROM_PEER {
            assert_eq!(store.carry(seal_one(3), &peer_a, now), Accepted::Carried);
        }
        assert_eq!(store.carry(seal_one(3), &peer_a, now), Accepted::Full);
        assert_eq!(store.carry(seal_one(3), &peer_b, now), Accepted::Carried);
    }

    #[test]
    fn own_copies_are_sealed_once_and_dropped_after_delivery() {
        let now = chrono::Utc::now().timestamp();
        let (alice, bob) = (device(), device());
        let message = delivery(alice.identity.fingerprint(), bob.identity.fingerprint(), "x", now);
        let id = message.id;
        let envelope = seal(&alice.identity, bob.identity.fingerprint(), bob.keys.public(), &Payload::Message(message), now, now + 3600).unwrap();
        let origin = Origin { message: id, recipient: bob.identity.fingerprint().to_owned(), receipt: false };
        let mut store = Store::default();
        store.add_own(envelope.clone(), origin.clone()).unwrap();
        assert!(store.has_origin(&origin));
        let relay = "cc".repeat(32);
        assert_eq!(store.outbound_for(&relay, 10)[0].hops, MAX_HOPS - 1);
        assert_eq!(store.forwarded(envelope.id, &relay), Some(origin.clone()));
        assert!(store.drop_own(id, bob.identity.fingerprint()));
        assert!(!store.has_origin(&origin));
        assert!(store.known(envelope.id), "a dropped copy still suppresses echoes");
    }
}
