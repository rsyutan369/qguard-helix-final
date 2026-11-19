//! Direct and group-fanout messaging on authenticated local sessions.
//! A pending copy stays in the sender's encrypted ledger until the intended
//! device acknowledges durable storage or the message expires.

use std::collections::HashSet;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    error::{QGuardError, Result},
    state::AppState,
};

use super::lan::fingerprint_valid;

pub(super) const DOC: &str = "offline-mesh-messages";
const AAD: &[u8] = b"QGuard-Offline-Mesh-Message-Ledger-v1";
const MAX_MESSAGES: usize = 1024;
const MAX_PENDING: usize = 256;
const MAX_RECIPIENTS: usize = 16;
const MAX_BODY_BYTES: usize = 4096;
const MAX_GROUP_BYTES: usize = 100;
const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
const MIN_TTL: i64 = 60;
const MAX_TTL: i64 = 7 * 24 * 60 * 60;
const CLOCK_SKEW: i64 = 5 * 60;
const HISTORY_TTL: i64 = 30 * 24 * 60 * 60;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Direction {
    Incoming,
    Outgoing,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Status {
    Pending,
    Delivered,
    Expired,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Message {
    id: Uuid,
    sender: String,
    recipients: Vec<String>,
    body: String,
    group: Option<String>,
    emergency: bool,
    created_at: i64,
    expires_at: i64,
    direction: Direction,
    status: Status,
    delivered_to: Vec<String>,
    /// Local receive time of an incoming message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    received_at: Option<i64>,
    /// When this user opened or dismissed an incoming message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    read_at: Option<i64>,
    /// Recipients this outgoing message was handed to relays for (sealed end
    /// to end; it is delivered only when that recipient's receipt returns).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    relayed_to: Vec<String>,
}

/// An unread incoming message, for the real-time notice. The preview is
/// truncated and stays inside the app; operating-system alerts never carry it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnreadMessage {
    pub id: Uuid,
    pub sender: String,
    pub preview: String,
    pub group: Option<String>,
    pub emergency: bool,
    pub received_at: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MessageRef {
    pub id: Uuid,
    pub sender: String,
}

const MAX_UNREAD_NOTICES: usize = 20;
const PREVIEW_CHARS: usize = 140;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Delivery {
    pub id: Uuid,
    pub(super) sender: String,
    pub(super) recipient: String,
    body: String,
    group: Option<String>,
    pub(super) emergency: bool,
    pub(super) created_at: i64,
    pub(super) expires_at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Receipt {
    pub id: Uuid,
    pub(super) sender: String,
    pub(super) recipient: String,
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub(super) messages: Vec<Message>,
}

impl Snapshot {
    fn load(state: &AppState, owner: &str, now: i64) -> Result<Self> {
        let Some(bytes) = state.load_user_secret_doc(owner, DOC, AAD, DOC)? else {
            return Ok(Self::default());
        };
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(QGuardError::Storage(
                "The local message ledger exceeds its storage limit.".into(),
            ));
        }
        let mut ledger: Self = serde_json::from_slice(&bytes)
            .map_err(|_| QGuardError::Storage("The local message ledger is unreadable.".into()))?;
        ledger
            .messages
            .retain(|message| message.expires_at.saturating_add(HISTORY_TTL) > now);
        for message in &mut ledger.messages {
            if message.status == Status::Pending && message.expires_at <= now {
                message.status = Status::Expired;
            }
        }
        Ok(ledger)
    }

    fn save(&self, state: &AppState, owner: &str) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(self).map_err(|_| {
            QGuardError::Storage("The local message ledger could not be saved.".into())
        })?);
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ledger_full());
        }
        state.save_user_secret_doc(owner, DOC, AAD, &bytes, DOC)
    }

    fn make_space(&mut self, now: i64) -> Result<()> {
        if self.messages.len() < MAX_MESSAGES {
            return Ok(());
        }
        // Retain every replay record while its envelope can still be valid.
        let expired = self
            .messages
            .iter()
            .position(|message| message.expires_at <= now);
        match expired {
            Some(index) => {
                self.messages.remove(index);
                Ok(())
            }
            None => Err(ledger_full()),
        }
    }
}

fn ledger_full() -> QGuardError {
    QGuardError::Storage(
        "The local message history is full. Retry after older messages expire.".into(),
    )
}

fn validate_content(body: &str, group: Option<&str>) -> Result<()> {
    if body.trim().is_empty()
        || body.len() > MAX_BODY_BYTES
        || group.is_some_and(|value| {
            value.is_empty() || value.len() > MAX_GROUP_BYTES || value.chars().any(char::is_control)
        })
    {
        return Err(QGuardError::InvalidInput(
            "Enter a message of up to 4 KiB and an optional group name of up to 100 bytes.".into(),
        ));
    }
    Ok(())
}

fn validate_delivery(delivery: &Delivery, local: &str, peer: &str, now: i64) -> Result<()> {
    if delivery.sender != peer
        || delivery.recipient != local
        || local == peer
        || !fingerprint_valid(local)
        || !fingerprint_valid(peer)
    {
        return Err(QGuardError::Trust(
            "The message does not match the authenticated sender and recipient.".into(),
        ));
    }
    let ttl = delivery.expires_at.checked_sub(delivery.created_at);
    if delivery.created_at > now.saturating_add(CLOCK_SKEW)
        || delivery.expires_at <= now
        || ttl.map_or(true, |ttl| !(MIN_TTL..=MAX_TTL).contains(&ttl))
        || delivery.id.is_nil()
    {
        return Err(QGuardError::InvalidInput(
            "The local message has expired or has invalid timestamps.".into(),
        ));
    }
    validate_content(&delivery.body, delivery.group.as_deref())
}

fn delivery_to(message: &Message, recipient: &str) -> Delivery {
    Delivery {
        id: message.id,
        sender: message.sender.clone(),
        recipient: recipient.to_string(),
        body: message.body.clone(),
        group: message.group.clone(),
        emergency: message.emergency,
        created_at: message.created_at,
        expires_at: message.expires_at,
    }
}

pub(super) fn snapshot(state: &AppState, owner: &str) -> Result<Snapshot> {
    Snapshot::load(state, owner, Utc::now().timestamp())
}

pub(super) fn pending_count(state: &AppState, owner: &str) -> Result<usize> {
    Ok(snapshot(state, owner)?
        .messages
        .iter()
        .filter(|message| message.status == Status::Pending)
        .count())
}

pub(super) fn queue(
    state: &AppState,
    owner: &str,
    sender: &str,
    recipients: Vec<String>,
    body: String,
    group: Option<String>,
    emergency: bool,
    ttl: i64,
) -> Result<Uuid> {
    let group = group
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    validate_content(&body, group.as_deref())?;
    let distinct: HashSet<_> = recipients.iter().collect();
    if !fingerprint_valid(sender)
        || recipients.is_empty()
        || recipients.len() > MAX_RECIPIENTS
        || distinct.len() != recipients.len()
        || recipients
            .iter()
            .any(|peer| !fingerprint_valid(peer) || peer == sender)
        || !(MIN_TTL..=MAX_TTL).contains(&ttl)
    {
        return Err(QGuardError::InvalidInput(
            "Choose up to 16 unique trusted recipients and a valid message expiration.".into(),
        ));
    }
    let now = Utc::now().timestamp();
    let mut ledger = Snapshot::load(state, owner, now)?;
    if ledger
        .messages
        .iter()
        .filter(|message| message.status == Status::Pending)
        .count()
        >= MAX_PENDING
    {
        return Err(QGuardError::Storage(
            "The local outbox is full. Deliver or expire pending messages before adding more."
                .into(),
        ));
    }
    ledger.make_space(now)?;
    let id = Uuid::new_v4();
    ledger.messages.push(Message {
        id,
        sender: sender.into(),
        recipients,
        body,
        group,
        emergency,
        created_at: now,
        expires_at: now + ttl,
        direction: Direction::Outgoing,
        status: Status::Pending,
        delivered_to: Vec::new(),
        received_at: None,
        read_at: None,
        relayed_to: Vec::new(),
    });
    ledger.save(state, owner)?;
    Ok(id)
}

/// Unread incoming messages, newest first.
pub(super) fn unread(state: &AppState, owner: &str) -> Result<Vec<UnreadMessage>> {
    let mut messages: Vec<_> = snapshot(state, owner)?
        .messages
        .into_iter()
        .filter(|message| message.direction == Direction::Incoming && message.read_at.is_none())
        .collect();
    messages.sort_by_key(|message| std::cmp::Reverse((message.received_at.unwrap_or(message.created_at), message.id)));
    Ok(messages
        .into_iter()
        .take(MAX_UNREAD_NOTICES)
        .map(|message| {
            let mut preview: String = message.body.chars().take(PREVIEW_CHARS).collect();
            if message.body.chars().count() > PREVIEW_CHARS {
                preview.push('…');
            }
            UnreadMessage {
                id: message.id,
                sender: message.sender,
                preview,
                group: message.group,
                emergency: message.emergency,
                received_at: message.received_at.unwrap_or(message.created_at),
            }
        })
        .collect())
}

/// Mark incoming messages read. Unknown or outgoing references are ignored.
pub(super) fn mark_read(state: &AppState, owner: &str, messages: &[MessageRef]) -> Result<bool> {
    let now = Utc::now().timestamp();
    let mut ledger = Snapshot::load(state, owner, now)?;
    let mut changed = false;
    for message in ledger.messages.iter_mut().filter(|message| {
        message.direction == Direction::Incoming
            && message.read_at.is_none()
            && messages.iter().any(|reference| reference.id == message.id && reference.sender == message.sender)
    }) {
        message.read_at = Some(now);
        changed = true;
    }
    if changed {
        ledger.save(state, owner)?;
    }
    Ok(changed)
}

pub(super) fn pending_for_peers(
    state: &AppState,
    owner: &str,
    peers: Vec<String>,
) -> Result<Vec<(String, Delivery)>> {
    if peers.is_empty() {
        return Ok(Vec::new());
    }
    let ledger = snapshot(state, owner)?;
    let mut pending: Vec<_> = ledger
        .messages
        .iter()
        .filter(|message| message.status == Status::Pending)
        .collect();
    pending.sort_by_key(|message| (!message.emergency, message.created_at, message.id));
    let mut peers: HashSet<_> = peers.iter().map(String::as_str).collect();
    let mut deliveries = Vec::new();
    for message in pending {
        for recipient in &message.recipients {
            if !message.delivered_to.contains(recipient) && peers.remove(recipient.as_str()) {
                deliveries.push((recipient.clone(), delivery_to(message, recipient)));
            }
        }
        if peers.is_empty() {
            break;
        }
    }
    Ok(deliveries)
}

/// Every pending delivery for one peer, oldest first (emergency messages
/// ahead), for a persistent channel that sends them in order on one stream.
/// Messages queued in the same second keep the order they were written in.
pub(super) fn pending_for_peer(
    state: &AppState,
    owner: &str,
    peer: &str,
    limit: usize,
) -> Result<Vec<Delivery>> {
    let ledger = snapshot(state, owner)?;
    let mut pending: Vec<_> = ledger
        .messages
        .iter()
        .filter(|message| {
            message.status == Status::Pending
                && message.recipients.iter().any(|recipient| recipient == peer)
                && !message.delivered_to.iter().any(|recipient| recipient == peer)
        })
        .collect();
    // Stable: ties keep ledger (insertion) order.
    pending.sort_by_key(|message| (!message.emergency, message.created_at));
    Ok(pending
        .into_iter()
        .take(limit)
        .map(|message| delivery_to(message, peer))
        .collect())
}

/// Pending outgoing deliveries the relay may carry: recipients still without
/// a receipt, on messages at least `min_age` seconds old (direct delivery
/// gets the first chance). Emergency messages first.
pub(super) fn relay_candidates(state: &AppState, owner: &str, min_age: i64) -> Result<Vec<(String, Delivery)>> {
    let now = Utc::now().timestamp();
    let ledger = Snapshot::load(state, owner, now)?;
    let mut pending: Vec<_> = ledger
        .messages
        .iter()
        .filter(|message| {
            message.direction == Direction::Outgoing
                && message.status == Status::Pending
                && now.saturating_sub(message.created_at) >= min_age
        })
        .collect();
    pending.sort_by_key(|message| (!message.emergency, message.created_at, message.id));
    Ok(pending
        .into_iter()
        .flat_map(|message| {
            message
                .recipients
                .iter()
                .filter(|recipient| !message.delivered_to.contains(recipient))
                .map(move |recipient| (recipient.clone(), delivery_to(message, recipient)))
        })
        .collect())
}

/// Every (message, recipient) of an outgoing message still without a receipt.
pub(super) fn awaiting_set(state: &AppState, owner: &str) -> Result<HashSet<(Uuid, String)>> {
    Ok(snapshot(state, owner)?
        .messages
        .iter()
        .filter(|message| message.direction == Direction::Outgoing && message.status == Status::Pending)
        .flat_map(|message| {
            message
                .recipients
                .iter()
                .filter(|recipient| !message.delivered_to.contains(recipient))
                .map(|recipient| (message.id, recipient.clone()))
        })
        .collect())
}

/// Record that a sealed copy for `recipient` reached at least one relay.
pub(super) fn mark_relayed(state: &AppState, owner: &str, id: Uuid, recipient: &str) -> Result<bool> {
    let now = Utc::now().timestamp();
    let mut ledger = Snapshot::load(state, owner, now)?;
    let Some(message) = ledger.messages.iter_mut().find(|message| {
        message.id == id
            && message.direction == Direction::Outgoing
            && message.recipients.iter().any(|value| value == recipient)
    }) else {
        return Ok(false);
    };
    if message.relayed_to.iter().any(|value| value == recipient) {
        return Ok(false);
    }
    message.relayed_to.push(recipient.to_owned());
    ledger.save(state, owner)?;
    Ok(true)
}

/// Store an authenticated delivery. The flag is `Some(emergency)` only the
/// first time this message is stored, so a retried delivery alerts once.
pub(super) fn receive(
    state: &AppState,
    owner: &str,
    local: &str,
    peer: &str,
    delivery: Delivery,
) -> Result<(Receipt, Option<bool>)> {
    let now = Utc::now().timestamp();
    validate_delivery(&delivery, local, peer, now)?;
    let mut ledger = Snapshot::load(state, owner, now)?;
    let receipt = Receipt {
        id: delivery.id,
        sender: delivery.sender.clone(),
        recipient: local.into(),
    };
    if let Some(message) = ledger.messages.iter().find(|message| {
        message.id == delivery.id
            && message.sender == peer
            && message.direction == Direction::Incoming
    }) {
        if delivery_to(message, local) == delivery {
            return Ok((receipt, None));
        }
        return Err(QGuardError::Replay(
            "This peer reused a message ID for different content.".into(),
        ));
    }
    ledger.make_space(now)?;
    let emergency = delivery.emergency;
    ledger.messages.push(Message {
        id: delivery.id,
        sender: delivery.sender,
        recipients: vec![delivery.recipient],
        body: delivery.body,
        group: delivery.group,
        emergency: delivery.emergency,
        created_at: delivery.created_at,
        expires_at: delivery.expires_at,
        direction: Direction::Incoming,
        status: Status::Delivered,
        delivered_to: vec![local.into()],
        received_at: Some(now),
        read_at: None,
        relayed_to: Vec::new(),
    });
    ledger.save(state, owner)?;
    Ok((receipt, Some(emergency)))
}

pub(super) fn acknowledge(
    state: &AppState,
    owner: &str,
    peer: &str,
    receipt: Receipt,
) -> Result<()> {
    if peer != receipt.recipient {
        return Err(QGuardError::Trust(
            "The receipt does not match the authenticated recipient.".into(),
        ));
    }
    let mut ledger = snapshot(state, owner)?;
    let message = ledger
        .messages
        .iter_mut()
        .find(|message| {
            message.id == receipt.id
                && message.sender == receipt.sender
                && message.direction == Direction::Outgoing
                && message.recipients.iter().any(|recipient| recipient == peer)
        })
        .ok_or_else(|| QGuardError::NotFound("No outgoing message matches this receipt.".into()))?;
    if message.status != Status::Pending
        || message
            .delivered_to
            .iter()
            .any(|recipient| recipient == peer)
    {
        return Ok(());
    }
    message.delivered_to.push(peer.into());
    if message.delivered_to.len() == message.recipients.len() {
        message.status = Status::Delivered;
    }
    ledger.save(state, owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDevice;

    #[test]
    fn a_channel_gets_every_pending_message_for_its_peer_in_the_order_written() {
        let alice = TestDevice::new(false);
        let sender = "ab".repeat(32);
        let peer = "cd".repeat(32);
        let other = "ef".repeat(32);
        let mut ids = Vec::new();
        for index in 0..20 {
            let recipients = if index % 5 == 0 { vec![peer.clone(), other.clone()] } else { vec![peer.clone()] };
            ids.push(queue(&alice.state, &alice.user, &sender, recipients, format!("message {index}"), None, false, 3600).unwrap());
        }
        queue(&alice.state, &alice.user, &sender, vec![other.clone()], "not for this peer".into(), None, false, 3600).unwrap();
        // The one-message-per-pass queue hands out a single delivery.
        assert_eq!(pending_for_peers(&alice.state, &alice.user, vec![peer.clone()]).unwrap().len(), 1);
        // The channel gets all twenty, in the order they were written, even
        // though they share one creation second.
        let pending = pending_for_peer(&alice.state, &alice.user, &peer, 64).unwrap();
        assert_eq!(pending.iter().map(|delivery| delivery.id).collect::<Vec<_>>(), ids);
        assert!(pending.iter().all(|delivery| delivery.recipient == peer));
        assert_eq!(pending_for_peer(&alice.state, &alice.user, &peer, 3).unwrap().len(), 3);
        // A receipt removes exactly that message; an emergency goes first.
        let receipt = Receipt { id: ids[0], sender: sender.clone(), recipient: peer.clone() };
        acknowledge(&alice.state, &alice.user, &peer, receipt).unwrap();
        let urgent = queue(&alice.state, &alice.user, &sender, vec![peer.clone()], "now".into(), None, true, 3600).unwrap();
        let pending = pending_for_peer(&alice.state, &alice.user, &peer, 64).unwrap();
        assert_eq!(pending.len(), 20);
        assert_eq!(pending[0].id, urgent);
        assert_eq!(pending[1].id, ids[1]);
    }

    #[test]
    fn delivery_is_durable_account_scoped_and_replay_safe() {
        let alice = TestDevice::new(false);
        let bob = TestDevice::new(false);
        let sender = "ab".repeat(32);
        let recipient = "cd".repeat(32);
        let other = "ef".repeat(32);
        let body = "confidential message".to_string();
        let queued_id = queue(
            &alice.state,
            &alice.user,
            &sender,
            vec![recipient.clone(), other.clone()],
            body,
            Some("Field team".into()),
            true,
            3600,
        )
        .unwrap();
        let alice = alice.restart();
        let pending =
            |peer: &str| pending_for_peers(&alice.state, &alice.user, vec![peer.into()]).unwrap();
        let (_, delivery) = pending(&recipient).pop().unwrap();
        assert_eq!(delivery.id, queued_id);
        assert!(receive(&bob.state, &bob.user, &recipient, &other, delivery.clone()).is_err());
        let (receipt, first) =
            receive(&bob.state, &bob.user, &recipient, &sender, delivery.clone()).unwrap();
        // The first storage reports a new (emergency) message; a retry does not,
        // so the recipient is alerted exactly once.
        assert_eq!(first, Some(true));
        let (_, retry) = receive(&bob.state, &bob.user, &recipient, &sender, delivery.clone()).unwrap();
        assert_eq!(retry, None);
        let mut tampered = delivery;
        tampered.body.push('!');
        assert!(receive(&bob.state, &bob.user, &recipient, &sender, tampered).is_err());
        assert_eq!(snapshot(&bob.state, &bob.user).unwrap().messages.len(), 1);
        let unread_now = unread(&bob.state, &bob.user).unwrap();
        assert_eq!(unread_now.len(), 1);
        assert_eq!(unread_now[0].id, queued_id);
        assert_eq!(unread_now[0].preview, "confidential message");
        assert!(unread_now[0].emergency);
        assert!(unread(&alice.state, &alice.user).unwrap().is_empty(), "outgoing messages never notify");
        // A reference with the wrong sender cannot mark another peer's message.
        assert!(!mark_read(&bob.state, &bob.user, &[MessageRef { id: queued_id, sender: other.clone() }]).unwrap());
        assert!(mark_read(&bob.state, &bob.user, &[MessageRef { id: queued_id, sender: sender.clone() }]).unwrap());
        assert!(unread(&bob.state, &bob.user).unwrap().is_empty());
        assert!(!mark_read(&bob.state, &bob.user, &[MessageRef { id: queued_id, sender: sender.clone() }]).unwrap());
        assert!(snapshot(&bob.state, &alice.user)
            .unwrap()
            .messages
            .is_empty());
        acknowledge(&alice.state, &alice.user, &recipient, receipt).unwrap();
        assert!(pending(&recipient).is_empty());
        assert_eq!(pending(&other).len(), 1);
        let sealed = std::fs::read(alice.dir.join("keys").join(format!(
            "{}.{}.enc",
            AppState::safe_user_key(&alice.user),
            DOC
        )))
        .unwrap();
        assert!(!sealed
            .windows(b"confidential message".len())
            .any(|bytes| bytes == b"confidential message"));
    }

    #[test]
    fn an_expired_delivery_cannot_enter_the_inbox() {
        let now = Utc::now().timestamp();
        let alice = "ab".repeat(32);
        let bob = "cd".repeat(32);
        let delivery = Delivery {
            id: Uuid::new_v4(),
            sender: alice.clone(),
            recipient: bob.clone(),
            body: "hello".into(),
            group: None,
            emergency: false,
            created_at: now - 3600,
            expires_at: now - 1,
        };
        assert!(validate_delivery(&delivery, &bob, &alice, now).is_err());
    }
}
