//! Network side of the multi-hop Mesh relay (see `relay.rs` for the sealed
//! envelope and the bounded store).
//!
//! Two devices that are paired for Mesh exchange envelopes on an ordinary
//! authenticated session:
//!
//!   initiator -> Relay     { its relay key, envelopes for the responder }
//!   responder -> RelayAck  { its relay key, ids it now holds, its envelopes }
//!   initiator -> RelayDone { ids it now holds }
//!
//! Each side opens what is addressed to it, carries the rest onward (when the
//! user allows relaying), and never sends an envelope back to its source or
//! twice to the same device. A message counts as delivered only when the
//! recipient's own signed receipt comes back, directly or through relays.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use tauri::{AppHandle, Manager};
use uuid::Uuid;

use crate::{
    error::{QGuardError, Result},
    state::AppState,
};

use super::{
    alerts, commands, mesh,
    network::{changed, lock, Network, Runtime},
    profile::{PeerCapability, TrustBook},
    relay::{self, Accepted, Envelope, Origin, Payload, RelayKeys, RelayPublic, Store},
    session::{Identity, Session},
    wire::{self, Control},
};

/// Direct delivery gets this long before a sealed copy goes to relays.
const RELAY_AFTER_SECS: i64 = 20;
/// With something to hand over (or a relay key still to learn).
const ACTIVE_EXCHANGE: Duration = Duration::from_secs(8);
/// With nothing to send: how often to ask a reachable peer what it carries.
const IDLE_EXCHANGE: Duration = Duration::from_secs(60);
const LAN_BATCH: usize = 16;
/// A Bluetooth session frame holds one envelope.
const BLE_BATCH: usize = 1;
const MAX_SEALS_PER_RUN: usize = 8;

fn batch(session: &Session) -> usize {
    if session.bluetooth() {
        BLE_BATCH
    } else {
        LAN_BATCH
    }
}

/// Run `task` on the network's relay store, loading it on first use and
/// saving it when `task` reports a change. The caller holds the storage gate.
pub(super) fn with_store<T>(
    state: &AppState,
    network: &Network,
    now: i64,
    task: impl FnOnce(&mut Store) -> Result<(T, bool)>,
) -> Result<T> {
    let mut cached = lock(&network.relay_store)?;
    if cached.is_none() {
        *cached = Some(Store::load(state, &network.owner, now)?);
    }
    let Some(store) = cached.as_mut() else {
        return Err(QGuardError::Storage("The Mesh relay store is unavailable.".into()));
    };
    store.prune(now);
    let outcome = task(store).and_then(|(value, changed)| {
        if changed {
            store.save(state, &network.owner)?;
        }
        Ok(value)
    });
    if outcome.is_err() {
        // Memory may be ahead of disk: read the saved store again next time.
        *cached = None;
    }
    outcome
}

pub(super) fn schedule(app: &AppHandle, network: &Arc<Network>) {
    let app = app.clone();
    let network = Arc::clone(network);
    tauri::async_runtime::spawn(async move {
        let Ok(_worker) = network.relay_worker.try_acquire() else {
            return;
        };
        tokio::select! {
            _ = network.until_stopped() => {}
            _ = run(&app, &network) => {}
        }
    });
}

async fn run(app: &AppHandle, network: &Network) -> Result<()> {
    network.check(app)?;
    for peer in prepare(app, network)? {
        // A peer with an open channel exchanges on it. Dialing a second link
        // to the same device would compete with the channel for the radio.
        let failed = if network.channels.request_relay(&peer) {
            false
        } else {
            exchange(app, network, &peer).await.is_err()
        };
        if let Ok(mut exchanges) = lock(&network.relay_exchanges) {
            exchanges.insert(peer, (Instant::now(), failed));
        }
    }
    Ok(())
}

/// Seal waiting messages for recipients that are out of direct reach, drop
/// sealed copies of messages that were delivered meanwhile, and choose the
/// reachable peers to exchange with now.
fn prepare(app: &AppHandle, network: &Network) -> Result<Vec<String>> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let _gate = lock(&runtime.storage)?;
    let book = TrustBook::load(&state, &network.owner)?;
    let now = Utc::now().timestamp();
    let candidates = mesh::relay_candidates(&state, &network.owner, RELAY_AFTER_SECS)?;
    let awaiting = mesh::awaiting_set(&state, &network.owner)?;
    let reachable: Vec<(String, bool)> = book
        .peers
        .iter()
        .filter(|(peer, _)| book.allows(peer, PeerCapability::Mesh))
        .filter(|(peer, record)| network.mesh_reachable(peer, record.address).unwrap_or(false))
        .map(|(peer, record)| (peer.clone(), record.relay_key.is_none()))
        .collect();
    if reachable.is_empty() {
        return Ok(Vec::new());
    }
    let ready: Vec<(String, bool)> = with_store(&state, network, now, |store| {
        let mut changed = false;
        for origin in store.own_messages() {
            if !awaiting.contains(&(origin.message, origin.recipient.clone())) {
                changed |= store.drop_own(origin.message, &origin.recipient);
            }
        }
        let mut sealed = 0;
        for (recipient, delivery) in &candidates {
            if sealed >= MAX_SEALS_PER_RUN {
                break;
            }
            let origin = Origin { message: delivery.id, recipient: recipient.clone(), receipt: false };
            let key = book
                .peers
                .get(recipient)
                .filter(|_| book.allows(recipient, PeerCapability::Mesh))
                .and_then(|peer| peer.relay_key.as_ref());
            let Some(key) = key else { continue };
            if store.has_origin(&origin) {
                continue;
            }
            // A recipient whose key cannot be used must not hold up the others.
            let Ok(envelope) = relay::seal(
                &network.identity,
                recipient,
                key,
                &Payload::Message(delivery.clone()),
                delivery.created_at,
                delivery.expires_at,
            ) else {
                continue;
            };
            if store.add_own(envelope, origin).is_err() {
                break;
            }
            sealed += 1;
            changed = true;
        }
        let ready = reachable
            .iter()
            .map(|(peer, needs_key)| (peer.clone(), *needs_key || !store.outbound_for(peer, 1).is_empty()))
            .collect();
        Ok((ready, changed))
    })?;
    let exchanges = lock(&network.relay_exchanges)?;
    Ok(ready
        .into_iter()
        .filter(|(peer, active)| match exchanges.get(peer) {
            None => true,
            Some((last, failed)) => {
                last.elapsed() >= IDLE_EXCHANGE || (*active && !failed && last.elapsed() >= ACTIVE_EXCHANGE)
            }
        })
        .map(|(peer, _)| peer)
        .collect())
}

async fn exchange(app: &AppHandle, network: &Network, peer: &str) -> Result<()> {
    let mut session = commands::connect_mesh(app, network, peer).await?;
    network.require_capability(app, peer, PeerCapability::Mesh)?;
    let (key, outbound) = begin(app, network, peer, batch(&session))?;
    let sent: Vec<Uuid> = outbound.iter().map(|envelope| envelope.id).collect();
    wire::send(&mut session, &Control::Relay { key, envelopes: outbound }).await?;
    let Control::RelayAck { key: theirs, accepted, envelopes } = wire::recv(&mut session).await? else {
        return Err(wire::protocol_error());
    };
    if envelopes.len() > LAN_BATCH {
        return Err(wire::protocol_error());
    }
    let settled = settle(app, network, peer, Some(&theirs), &sent, &accepted, envelopes)?;
    wire::send(&mut session, &Control::RelayDone { accepted: settled.accepted }).await?;
    announce(app, network, settled.alerts);
    Ok(())
}

/// The responder's half, called for an incoming `Control::Relay`.
pub(super) async fn serve(
    app: &AppHandle,
    network: &Network,
    session: &mut Session,
    peer: &str,
    key: RelayPublic,
    envelopes: Vec<Envelope>,
) -> Result<()> {
    if envelopes.len() > LAN_BATCH {
        return Err(wire::protocol_error());
    }
    let settled = settle(app, network, peer, Some(&key), &[], &[], envelopes)?;
    let (own_key, outbound) = begin(app, network, peer, batch(session))?;
    let sent: Vec<Uuid> = outbound.iter().map(|envelope| envelope.id).collect();
    wire::send(session, &Control::RelayAck { key: own_key, accepted: settled.accepted, envelopes: outbound }).await?;
    announce(app, network, settled.alerts);
    if let Ok(mut exchanges) = lock(&network.relay_exchanges) {
        exchanges.insert(peer.to_owned(), (Instant::now(), false));
    }
    let Control::RelayDone { accepted } = wire::recv(session).await? else {
        return Err(wire::protocol_error());
    };
    settle(app, network, peer, None, &sent, &accepted, Vec::new())?;
    changed(app);
    Ok(())
}

// The same three-step exchange, carried on a persistent channel. The channel
// owns the session, so each step returns the frame to send and the ids to
// remember instead of doing the I/O itself. Both devices may start an
// exchange at the same time: the two directions keep separate state.

fn channel_batch(bluetooth: bool) -> usize {
    if bluetooth {
        BLE_BATCH
    } else {
        LAN_BATCH
    }
}

fn note_exchange(network: &Network, peer: &str) {
    if let Ok(mut exchanges) = lock(&network.relay_exchanges) {
        exchanges.insert(peer.to_owned(), (Instant::now(), false));
    }
}

/// Step 1, initiator: the `Relay` frame and the envelope ids it offers.
pub(super) fn channel_open(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    bluetooth: bool,
) -> Result<(Control, Vec<Uuid>)> {
    network.require_capability(app, peer, PeerCapability::Mesh)?;
    let (key, outbound) = begin(app, network, peer, channel_batch(bluetooth))?;
    let sent = outbound.iter().map(|envelope| envelope.id).collect();
    Ok((Control::Relay { key, envelopes: outbound }, sent))
}

/// Step 2, responder: take in a `Relay` frame; returns the `RelayAck` frame
/// and the envelope ids it offers back.
pub(super) fn channel_serve(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    bluetooth: bool,
    key: RelayPublic,
    envelopes: Vec<Envelope>,
) -> Result<(Control, Vec<Uuid>)> {
    if envelopes.len() > LAN_BATCH {
        return Err(wire::protocol_error());
    }
    network.require_capability(app, peer, PeerCapability::Mesh)?;
    let settled = settle(app, network, peer, Some(&key), &[], &[], envelopes)?;
    let (own_key, outbound) = begin(app, network, peer, channel_batch(bluetooth))?;
    let sent = outbound.iter().map(|envelope| envelope.id).collect();
    announce(app, network, settled.alerts);
    note_exchange(network, peer);
    Ok((Control::RelayAck { key: own_key, accepted: settled.accepted, envelopes: outbound }, sent))
}

/// Step 3, initiator: take in the `RelayAck`; returns the `RelayDone` frame.
pub(super) fn channel_ack(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    sent: &[Uuid],
    theirs: RelayPublic,
    accepted: Vec<Uuid>,
    envelopes: Vec<Envelope>,
) -> Result<Control> {
    if envelopes.len() > LAN_BATCH {
        return Err(wire::protocol_error());
    }
    let settled = settle(app, network, peer, Some(&theirs), sent, &accepted, envelopes)?;
    announce(app, network, settled.alerts);
    note_exchange(network, peer);
    Ok(Control::RelayDone { accepted: settled.accepted })
}

/// Step 4, responder: the peer's `RelayDone` for the ids offered in step 2.
pub(super) fn channel_done(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    sent: &[Uuid],
    accepted: &[Uuid],
) -> Result<()> {
    settle(app, network, peer, None, sent, accepted, Vec::new())?;
    changed(app);
    Ok(())
}

fn announce(app: &AppHandle, network: &Network, alerts: Vec<(String, Uuid, bool)>) {
    changed(app);
    for (sender, id, emergency) in alerts {
        alerts::mesh_message(app, &network.owner, &sender, id, emergency);
    }
}

/// This device's relay key and the envelopes to hand to `peer`.
fn begin(app: &AppHandle, network: &Network, peer: &str, limit: usize) -> Result<(RelayPublic, Vec<Envelope>)> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let _gate = lock(&runtime.storage)?;
    network.require_peer_locked(app, peer, false)?;
    let keys = RelayKeys::load(&state, &network.owner)?;
    let outbound = with_store(&state, network, Utc::now().timestamp(), |store| {
        Ok((store.outbound_for(peer, limit), false))
    })?;
    Ok((keys.public().clone(), outbound))
}

struct Settled {
    accepted: Vec<Uuid>,
    /// New messages for this device: (sender, message id, emergency).
    alerts: Vec<(String, Uuid, bool)>,
}

/// Record what `peer` now holds of `sent`, pin its relay key, and take in the
/// envelopes it handed over.
fn settle(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    key: Option<&RelayPublic>,
    sent: &[Uuid],
    accepted: &[Uuid],
    envelopes: Vec<Envelope>,
) -> Result<Settled> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let _gate = lock(&runtime.storage)?;
    network.require_peer_locked(app, peer, false)?;
    let mut book = TrustBook::load(&state, &network.owner)?;
    book.require(peer, PeerCapability::Mesh)?;
    if let Some(key) = key {
        key.validate()?;
        if let Some(record) = book.peers.get_mut(peer) {
            if record.relay_key.as_ref() != Some(key) {
                record.relay_key = Some(key.clone());
                book.save(&state, &network.owner)?;
            }
        }
    }
    let keys = if envelopes.is_empty() { None } else { Some(RelayKeys::load(&state, &network.owner)?) };
    let now = Utc::now().timestamp();
    with_store(&state, network, now, |store| {
        let mut changed = false;
        for id in sent.iter().filter(|id| accepted.contains(id)) {
            changed = true;
            if let Some(origin) = store.forwarded(*id, peer).filter(|origin| !origin.receipt) {
                let _ = mesh::mark_relayed(&state, &network.owner, origin.message, &origin.recipient);
            }
        }
        let mut settled = Settled { accepted: Vec::new(), alerts: Vec::new() };
        if let Some(keys) = &keys {
            for envelope in envelopes {
                changed |= absorb(&state, &network.owner, &network.identity, &book, keys, store, peer, envelope, now, &mut settled);
            }
        }
        Ok((settled, changed))
    })
}

/// Take in one envelope from `peer`. Returns whether the store changed.
#[allow(clippy::too_many_arguments)]
fn absorb(
    state: &AppState,
    owner: &str,
    identity: &Identity,
    book: &TrustBook,
    keys: &RelayKeys,
    store: &mut Store,
    peer: &str,
    envelope: Envelope,
    now: i64,
    settled: &mut Settled,
) -> bool {
    let id = envelope.id;
    // Malformed, expired or already handled: tell the peer to stop offering it.
    if envelope.validate(now).is_err() || store.known(id) {
        settled.accepted.push(id);
        return false;
    }
    let local = identity.fingerprint();
    if !envelope.addressed_to(local) {
        if !book.relay {
            return false;
        }
        return match store.carry(envelope, peer, now) {
            Accepted::Carried | Accepted::Known => {
                settled.accepted.push(id);
                true
            }
            Accepted::Full => false,
        };
    }
    let pinned_identity = |sender: &str| {
        book.peers
            .get(sender)
            .filter(|_| book.allows(sender, PeerCapability::Mesh))
            .and_then(|record| record.paired.as_ref())
            .and_then(|identity| STANDARD.decode(&identity.public_key).ok())
    };
    match envelope.open(keys, local, pinned_identity) {
        Ok(opened) => match opened.payload {
            Payload::Message(delivery) => {
                let message = delivery.id;
                match mesh::receive(state, owner, local, &opened.sender, delivery) {
                    Ok((receipt, new)) => {
                        if let Some(emergency) = new {
                            settled.alerts.push((opened.sender.clone(), message, emergency));
                        }
                        // The signed receipt travels back through the mesh.
                        let origin = Origin { message, recipient: opened.sender.clone(), receipt: true };
                        let key = book.peers.get(&opened.sender).and_then(|record| record.relay_key.as_ref());
                        if let (false, Some(key)) = (store.has_origin(&origin), key) {
                            if let Ok(reply) = relay::seal(
                                identity,
                                &opened.sender,
                                key,
                                &Payload::Receipt(receipt),
                                now,
                                envelope.expires_at,
                            ) {
                                let _ = store.add_own(reply, origin);
                            }
                        }
                    }
                    // The inbox is full: leave it with the relay for a retry.
                    Err(QGuardError::Storage(_)) => return false,
                    Err(_) => {}
                }
            }
            Payload::Receipt(receipt) => {
                let message = receipt.id;
                let _ = mesh::acknowledge(state, owner, &opened.sender, receipt);
                store.drop_own(message, &opened.sender);
            }
        },
        Err(error) => tracing::debug!("a relayed Mesh envelope was dropped: {error}"),
    }
    store.remember(&envelope);
    settled.accepted.push(id);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline::profile::PeerMetadata;
    use crate::test_support::TestDevice;

    struct Node {
        device: TestDevice,
        identity: Identity,
        keys: RelayKeys,
        store: Store,
    }

    impl Node {
        fn new() -> Self {
            let device = TestDevice::new(false);
            let identity = Identity::load(&device.state, &device.user).unwrap();
            let keys = RelayKeys::load(&device.state, &device.user).unwrap();
            Self { device, identity, keys, store: Store::default() }
        }

        fn fingerprint(&self) -> String {
            self.identity.fingerprint().to_owned()
        }

        /// Pair `peer` for Mesh on this device, with its relay key pinned.
        fn trust(&self, peer: &Node) {
            let mut book = TrustBook::load(&self.device.state, &self.device.user).unwrap();
            let metadata = PeerMetadata {
                label: "Peer".into(),
                platform: "android".into(),
                capabilities: vec![PeerCapability::Mesh, PeerCapability::Xfer],
            };
            book.trust_paired(&peer.fingerprint(), metadata, peer.identity.public_bytes(), None, &[PeerCapability::Mesh], None)
                .unwrap();
            book.peers.get_mut(&peer.fingerprint()).unwrap().relay_key = Some(peer.keys.public().clone());
            book.save(&self.device.state, &self.device.user).unwrap();
        }

        /// Take in what `from` hands over, as `settle` does. Returns accepted ids.
        fn take(&mut self, from: &str, envelopes: Vec<Envelope>) -> Settled {
            let book = TrustBook::load(&self.device.state, &self.device.user).unwrap();
            let now = Utc::now().timestamp();
            let mut settled = Settled { accepted: Vec::new(), alerts: Vec::new() };
            for envelope in envelopes {
                absorb(
                    &self.device.state, &self.device.user, &self.identity, &book, &self.keys,
                    &mut self.store, from, envelope, now, &mut settled,
                );
            }
            settled
        }
    }

    fn pair(a: &Node, b: &Node) {
        a.trust(b);
        b.trust(a);
    }

    /// Hand `from`'s outbound envelopes for `to` across, as one exchange does.
    fn hand_over(from: &mut Node, to: &mut Node) -> Settled {
        let outbound = from.store.outbound_for(&to.fingerprint(), LAN_BATCH);
        let sent: Vec<Uuid> = outbound.iter().map(|envelope| envelope.id).collect();
        let settled = to.take(&from.fingerprint(), outbound);
        for id in sent.iter().filter(|id| settled.accepted.contains(id)) {
            from.store.forwarded(*id, &to.fingerprint());
        }
        settled
    }

    fn queue_and_seal(sender: &mut Node, recipient: &Node, body: &str) -> Uuid {
        let state = &sender.device.state;
        let id = mesh::queue(state, &sender.device.user, &sender.fingerprint(), vec![recipient.fingerprint()], body.into(), None, true, 3600)
            .unwrap();
        let (to, delivery) = mesh::relay_candidates(state, &sender.device.user, 0).unwrap().pop().unwrap();
        let envelope = relay::seal(
            &sender.identity, &to, recipient.keys.public(), &Payload::Message(delivery.clone()),
            delivery.created_at, delivery.expires_at,
        )
        .unwrap();
        sender.store.add_own(envelope, Origin { message: id, recipient: to, receipt: false }).unwrap();
        id
    }

    #[test]
    fn a_message_crosses_a_relay_and_its_signed_receipt_returns() {
        let (mut alice, mut relay_node, mut carol) = (Node::new(), Node::new(), Node::new());
        pair(&alice, &relay_node);
        pair(&relay_node, &carol);
        pair(&alice, &carol);
        let id = queue_and_seal(&mut alice, &carol, "bridge is out, use the east road");

        // Alice -> relay: carried as ciphertext, never stored as a message.
        let at_relay = hand_over(&mut alice, &mut relay_node);
        assert_eq!(at_relay.accepted.len(), 1);
        assert!(at_relay.alerts.is_empty());
        assert_eq!(relay_node.store.carrying(), 1);
        assert!(mesh::unread(&relay_node.device.state, &relay_node.device.user).unwrap().is_empty());
        assert!(hand_over(&mut alice, &mut relay_node).accepted.is_empty(), "each device receives it once");

        // Relay -> Carol: opened, verified against Alice's pinned identity.
        let at_carol = hand_over(&mut relay_node, &mut carol);
        assert_eq!(at_carol.alerts, vec![(alice.fingerprint(), id, true)]);
        let unread = mesh::unread(&carol.device.state, &carol.device.user).unwrap();
        assert_eq!(unread.len(), 1);
        assert_eq!(unread[0].preview, "bridge is out, use the east road");
        assert_eq!(unread[0].sender, alice.fingerprint());

        // A copy arriving over another path is recognised and not stored twice.
        let duplicate = alice.store.outbound_for(&carol.fingerprint(), LAN_BATCH);
        assert_eq!(duplicate.len(), 1);
        let again = carol.take(&alice.fingerprint(), duplicate);
        assert!(again.alerts.is_empty());
        assert_eq!(mesh::unread(&carol.device.state, &carol.device.user).unwrap().len(), 1);

        // Carol's signed receipt returns through the relay; only then is it delivered.
        let awaiting = |node: &Node| mesh::awaiting_set(&node.device.state, &node.device.user).unwrap();
        assert!(awaiting(&alice).contains(&(id, carol.fingerprint())));
        assert_eq!(hand_over(&mut carol, &mut relay_node).accepted.len(), 1);
        assert!(awaiting(&alice).contains(&(id, carol.fingerprint())), "a relay cannot confirm delivery");
        hand_over(&mut relay_node, &mut alice);
        assert!(awaiting(&alice).is_empty());
        assert!(alice.store.own_messages().is_empty(), "the sealed copy is dropped after delivery");
    }

    #[test]
    fn a_device_with_relaying_off_or_an_unpaired_sender_is_not_served() {
        let (mut alice, mut relay_node, mut carol) = (Node::new(), Node::new(), Node::new());
        pair(&alice, &relay_node);
        pair(&relay_node, &carol);
        // Carol knows Alice's keys only one way: Alice trusts Carol, not the reverse.
        alice.trust(&carol);
        queue_and_seal(&mut alice, &carol, "hello");

        let mut book = TrustBook::load(&relay_node.device.state, &relay_node.device.user).unwrap();
        book.relay = false;
        book.save(&relay_node.device.state, &relay_node.device.user).unwrap();
        assert!(hand_over(&mut alice, &mut relay_node).accepted.is_empty());
        assert_eq!(relay_node.store.carrying(), 0);

        book.relay = true;
        book.save(&relay_node.device.state, &relay_node.device.user).unwrap();
        assert_eq!(hand_over(&mut alice, &mut relay_node).accepted.len(), 1);
        let at_carol = hand_over(&mut relay_node, &mut carol);
        assert_eq!(at_carol.accepted.len(), 1, "dropped, and the relay is told to stop offering it");
        assert!(at_carol.alerts.is_empty());
        assert!(mesh::unread(&carol.device.state, &carol.device.user).unwrap().is_empty());
    }
}
