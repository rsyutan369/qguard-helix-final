//! The persistent channel: one long-lived, authenticated, bidirectional
//! session per trusted peer.
//!
//! Discovery, the transport connection and the application session are three
//! separate stages. Before this module the application session lived for one
//! operation: every Mesh message dialed a new connection, ran a full hybrid
//! handshake, sent one frame, read one receipt and hung up. Over Bluetooth
//! that meant several seconds and a fresh radio link per message, a reply
//! dialed a second link in the opposite direction, and the peer was only
//! "connected" for the moment a message was in flight.
//!
//! A channel is opened once (by either device) and stays open until the user
//! disconnects the peer, trust is withdrawn, local networking stops, or the
//! link is lost. On it, both devices send Mesh messages and receipts at any
//! time and in order, exchange relay envelopes, nudge each other about queued
//! file transfers, and exchange heartbeats that detect a dead link. When a
//! link is lost the channel is dialed again with backoff and resends whatever
//! has no receipt yet; the receiver recognises a repeated message by its id.
//!
//! Version 2 adds the profile exchange (`avatar.rs`): on open, each side
//! sends its display name and the digest of its profile picture, and fetches
//! the peer's picture only when the digest is new. A version-2 dialer that
//! meets a version-1 build falls back to version 1 on its next dial.
//!
//! Channels exist for every trusted peer with Mesh or XFER approved, so a
//! file-transfer pairing also keeps one live, monitored session: consecutive
//! transfers reuse the pairing, and the link state the views show is real.
//!
//! The channel changes nothing about the cryptography: it is the same QHCE
//! session (ML-KEM-768 + X25519, ML-DSA-65 + Ed25519, AES-256-GCM per frame)
//! with the same per-direction keys and strictly ordered frame sequences.
//! File chunks keep their own sessions: a transfer must not stall messaging,
//! and a Bluetooth channel does not carry files.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use serde::Serialize;
use tauri::{AppHandle, Manager};
use tokio::{
    sync::{mpsc, Semaphore},
    time::{interval, timeout, MissedTickBehavior},
};
use uuid::Uuid;

use crate::{
    error::{QGuardError, Result},
    state::AppState,
};

use super::{
    avatar::{self, AvatarBook},
    commands, diag, link, transfer,
    network::{changed, lock, Network, Runtime},
    profile::{valid_owner_name, PeerCapability, TrustBook},
    relay_net,
    session::{Session, SessionWriter},
    wire::{self, Control},
};

/// Newest channel protocol: 2 adds the profile and picture exchange; 3 adds
/// file offers over the channel and the direct Wi-Fi link (`link.rs`).
pub(super) const VERSION: u8 = 3;
/// Oldest channel protocol still accepted (and dialed as a fallback).
pub(super) const MIN_VERSION: u8 = 1;
/// Messages sent per flush. The ledger holds at most 256 pending.
const FLUSH_BATCH: usize = 64;
/// Bluetooth carries one radio link per peer; keep a little headroom under
/// the adapters' four-link limit for pairing and hint reads.
const MAX_BLUETOOTH_CHANNELS: usize = 3;
const MAX_CHANNELS: usize = 12;
/// How long the device with the larger fingerprint lets the other one dial
/// first, so two devices that see each other at once open one link, not two.
const DIAL_DEFER: Duration = Duration::from_secs(6);
const REDIAL_AFTER_LOSS: Duration = Duration::from_millis(1500);
const LEGACY_RETRY: Duration = Duration::from_secs(120);
const RECENT_LOSS: Duration = Duration::from_secs(90);

struct Tuning {
    heartbeat: Duration,
    /// No frame at all for this long: the link is dead.
    dead_after: Duration,
    /// A message without a receipt is sent again after this long.
    resend_after: Duration,
    ready_timeout: Duration,
}

fn tuning(bluetooth: bool) -> Tuning {
    if bluetooth {
        Tuning {
            heartbeat: Duration::from_secs(8),
            dead_after: Duration::from_secs(30),
            resend_after: Duration::from_secs(20),
            ready_timeout: Duration::from_secs(45),
        }
    } else {
        Tuning {
            heartbeat: Duration::from_secs(4),
            dead_after: Duration::from_secs(14),
            resend_after: Duration::from_secs(8),
            ready_timeout: Duration::from_secs(15),
        }
    }
}

pub(super) enum Command {
    /// Send whatever is pending for this peer now.
    Flush,
    /// Run a relay exchange with this peer.
    Relay,
    /// Tell the peer that file-transfer work is queued for it.
    Nudge,
    /// The local display name or picture changed: announce it.
    Profile,
    /// Send one version-3 frame (file offer, offer answer, Wi-Fi link).
    Frame(Box<Control>),
    Close,
}

/// What the peer list shows about the link to one peer. Every value comes
/// from the channel registry: nothing here is inferred by the view.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LinkView {
    /// "connected", "connecting" or "reconnecting".
    state: &'static str,
    /// "bluetooth" or "lan", once a link is up.
    transport: Option<&'static str>,
    /// Unix seconds when the current channel opened.
    since: Option<i64>,
    /// First 16 hex digits of the session binding: the same on both devices.
    session: Option<String>,
    /// Latest heartbeat round trip in milliseconds.
    rtt_ms: Option<u32>,
    /// Consecutive failed dials since the last open channel.
    attempts: u32,
}

struct Open {
    serial: u64,
    commands: mpsc::Sender<Command>,
    initiator_is_local: bool,
    bluetooth: bool,
    since: i64,
    session: String,
    rtt_ms: Arc<AtomicU32>,
    /// Negotiated channel protocol.
    version: u8,
}

struct Dial {
    dialing: bool,
    failures: u32,
    next_attempt: Instant,
    wanted_since: Instant,
    lost_at: Option<Instant>,
    /// The peer answered the channel request like an older build.
    legacy: bool,
    /// Dials that authenticated but got no channel confirmation.
    unconfirmed: u32,
    /// Channel protocol to request: drops to `MIN_VERSION` for an older peer.
    version: u8,
}

impl Dial {
    fn new(now: Instant) -> Self {
        Self {
            dialing: false, failures: 0, next_attempt: now, wanted_since: now, lost_at: None, legacy: false,
            unconfirmed: 0, version: VERSION,
        }
    }
}

pub(super) struct Channels {
    open: Mutex<HashMap<String, Open>>,
    dials: Mutex<HashMap<String, Dial>>,
    serial: AtomicU64,
    dial_slots: Arc<Semaphore>,
}

impl Default for Channels {
    fn default() -> Self {
        Self {
            open: Mutex::default(),
            dials: Mutex::default(),
            serial: AtomicU64::new(0),
            dial_slots: Arc::new(Semaphore::new(2)),
        }
    }
}

impl Channels {
    pub fn is_open(&self, peer: &str) -> bool {
        self.open.lock().is_ok_and(|open| open.contains_key(peer))
    }

    fn send(&self, peer: &str, command: Command) -> bool {
        self.open
            .lock()
            .ok()
            .and_then(|open| open.get(peer).map(|channel| channel.commands.try_send(command).is_ok()))
            .unwrap_or(false)
    }

    /// Ask the open channel to send pending messages. False without a channel.
    pub fn flush(&self, peer: &str) -> bool {
        // A full command queue already holds a flush.
        self.is_open(peer) && (self.send(peer, Command::Flush) || true)
    }

    pub fn request_relay(&self, peer: &str) -> bool {
        self.is_open(peer) && (self.send(peer, Command::Relay) || true)
    }

    /// Tell the peer over its channel that transfer work is queued for it.
    pub fn nudge(&self, peer: &str) -> bool {
        self.send(peer, Command::Nudge)
    }

    /// Nudge every connected peer (a transfer attempt just failed here).
    pub fn nudge_all(&self) {
        if let Ok(open) = self.open.lock() {
            for channel in open.values().filter(|channel| !channel.bluetooth) {
                let _ = channel.commands.try_send(Command::Nudge);
            }
        }
    }

    /// Announce a changed local profile on every channel that understands it.
    pub fn announce_profile(&self) {
        if let Ok(open) = self.open.lock() {
            for channel in open.values().filter(|channel| channel.version >= 2) {
                let _ = channel.commands.try_send(Command::Profile);
            }
        }
    }

    /// The open channel speaks version 3: file offers and Wi-Fi links.
    pub fn supports_links(&self, peer: &str) -> bool {
        self.open.lock().is_ok_and(|open| open.get(peer).is_some_and(|channel| channel.version >= 3))
    }

    /// Queue a version-3 frame on the peer's channel. False without one.
    pub fn send_frame(&self, peer: &str, frame: Control) -> bool {
        self.supports_links(peer) && self.send(peer, Command::Frame(Box::new(frame)))
    }

    /// The peer only speaks the one-message-per-session protocol.
    pub fn legacy(&self, peer: &str) -> bool {
        self.dials.lock().is_ok_and(|dials| dials.get(peer).is_some_and(|dial| dial.legacy))
    }

    pub fn close(&self, peer: &str) {
        self.send(peer, Command::Close);
    }

    pub fn view(&self, peer: &str) -> Option<LinkView> {
        if let Some(channel) = self.open.lock().ok()?.get(peer) {
            let rtt = channel.rtt_ms.load(Ordering::Relaxed);
            return Some(LinkView {
                state: "connected",
                transport: Some(diag::transport(channel.bluetooth)),
                since: Some(channel.since),
                session: Some(channel.session.clone()),
                rtt_ms: (rtt != u32::MAX).then_some(rtt),
                attempts: 0,
            });
        }
        let dials = self.dials.lock().ok()?;
        let dial = dials.get(peer)?;
        let recently_lost = dial.lost_at.is_some_and(|lost| lost.elapsed() < RECENT_LOSS);
        let state = match (dial.dialing, recently_lost) {
            (_, true) => "reconnecting",
            (true, false) => "connecting",
            (false, false) => return None,
        };
        Some(LinkView { state, transport: None, since: None, session: None, rtt_ms: None, attempts: dial.failures })
    }

    fn counts(&self) -> (usize, usize) {
        self.open.lock().map_or((0, 0), |open| {
            (open.len(), open.values().filter(|channel| channel.bluetooth).count())
        })
    }

    /// Two devices can dial each other at the same moment. Both must keep the
    /// same one of the two links, so the rule only uses what both know: the
    /// link dialed by the device with the smaller fingerprint survives.
    fn register(&self, local: &str, peer: &str, channel: Open) -> bool {
        let Ok(mut open) = self.open.lock() else { return false };
        if let Some(existing) = open.get(peer) {
            if existing.initiator_is_local != channel.initiator_is_local {
                let local_dial_wins = local < peer;
                let keep_new = channel.initiator_is_local == local_dial_wins;
                if !keep_new {
                    return false;
                }
            }
            // Same direction: the peer redialed, so the old link is gone.
            let _ = existing.commands.try_send(Command::Close);
        }
        open.insert(peer.to_owned(), channel);
        true
    }

    fn deregister(&self, peer: &str, serial: u64) {
        if let Ok(mut open) = self.open.lock() {
            if open.get(peer).is_some_and(|channel| channel.serial == serial) {
                open.remove(peer);
            }
        }
    }

    fn note_loss(&self, peer: &str) {
        if let Ok(mut dials) = self.dials.lock() {
            let now = Instant::now();
            let dial = dials.entry(peer.to_owned()).or_insert_with(|| Dial::new(now));
            dial.lost_at = Some(now);
            dial.failures = 0;
            dial.next_attempt = now + REDIAL_AFTER_LOSS;
        }
    }
}

fn backoff(failures: u32) -> Duration {
    Duration::from_secs(match failures {
        0 | 1 => 3,
        2 => 6,
        3 => 12,
        4 => 25,
        _ => 60,
    })
}

pub(super) fn shared(app: &AppHandle, network: &Network) -> Option<Arc<Network>> {
    lock(&app.state::<Runtime>().network)
        .ok()?
        .as_ref()
        .filter(|current| std::ptr::eq(current.as_ref(), network))
        .cloned()
}

async fn send(writer: &mut SessionWriter, control: &Control) -> Result<()> {
    writer.send(&wire::encode(control)?).await
}

/// Why a channel ended, for diagnostics.
fn reason(error: &QGuardError) -> String {
    match error {
        QGuardError::Crypto(message)
        | QGuardError::InvalidInput(message)
        | QGuardError::NotFound(message)
        | QGuardError::Replay(message)
        | QGuardError::Trust(message)
        | QGuardError::Storage(message) => message.clone(),
    }
}

/// Serve one open channel until it ends. The caller keeps the peer's
/// `PeerActivity` alive for as long as this runs, which is what the peer list
/// reports as "connected". Returns once the channel is closed and removed.
pub(super) async fn run(app: &AppHandle, network: &Network, session: Session, initiated: bool, version: u8) {
    let peer = session.peer().to_owned();
    let bluetooth = session.bluetooth();
    let session_id = diag::session_id(session.binding());
    let subject = diag::Subject::link(&peer, &session_id, bluetooth);
    let tuning = tuning(bluetooth);
    let mut authorization = session.authorization();
    let (mut reader, mut writer) = session.split();

    let serial = network.channels.serial.fetch_add(1, Ordering::Relaxed) + 1;
    let (commands, mut inbox) = mpsc::channel(8);
    let rtt_ms = Arc::new(AtomicU32::new(u32::MAX));
    let registered = network.channels.register(&network.fingerprint, &peer, Open {
        serial,
        commands,
        initiator_is_local: initiated,
        bluetooth,
        since: chrono::Utc::now().timestamp(),
        session: session_id.clone(),
        rtt_ms: Arc::clone(&rtt_ms),
        version,
    });
    if !registered {
        diag::record_detail(app, "channel_duplicate_closed", subject, "The link dialed by the other device is kept.");
        return;
    }
    diag::record_detail(app, "channel_open", subject, if initiated { "dialed by this device" } else { "accepted from the peer" });
    changed(app);

    // The reader owns the receiving half and is never cancelled mid-frame.
    let (frames, mut incoming) = mpsc::channel::<Result<Vec<u8>>>(16);
    let idle = tuning.dead_after + tuning.heartbeat;
    let reader_task = tokio::spawn(async move {
        loop {
            let frame = reader.recv(idle).await;
            let failed = frame.is_err();
            if frames.send(frame).await.is_err() || failed {
                break;
            }
        }
    });

    let mut state = Flow {
        in_flight: HashMap::new(),
        relay_offered: None,
        relay_served: None,
        ping: None,
        next_ping: 1,
        last_received: Instant::now(),
    };
    let mut heartbeat = interval(tuning.heartbeat);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Deliver what is already waiting, and learn the peer's relay key.
    let mut outcome = flush(app, network, &peer, &subject, &tuning, &mut writer, &mut state).await;
    if outcome.is_ok() && initiated {
        outcome = start_relay(app, network, &peer, bluetooth, &mut writer, &mut state).await;
    }
    // Version 2: introduce ourselves; the peer fetches the picture if needed.
    if outcome.is_ok() && version >= 2 {
        outcome = send_profile(app, network, &mut writer).await;
    }
    let end: String = match outcome {
        Err(error) => reason(&error),
        Ok(()) => loop {
            let step: Result<Option<&'static str>> = tokio::select! {
                _ = network.until_stopped() => Ok(Some("local networking stopped")),
                _ = async {
                    match authorization.as_mut() {
                        Some(authorization) => { let _ = authorization.wait_for(|revoked| *revoked).await; }
                        None => std::future::pending().await,
                    }
                } => Ok(Some("this device was disconnected or is no longer trusted")),
                command = inbox.recv() => match command {
                    Some(Command::Flush) => flush(app, network, &peer, &subject, &tuning, &mut writer, &mut state).await.map(|()| None),
                    Some(Command::Relay) => start_relay(app, network, &peer, bluetooth, &mut writer, &mut state).await.map(|()| None),
                    Some(Command::Nudge) => send(&mut writer, &Control::Nudge).await.map(|()| None),
                    Some(Command::Profile) => send_profile(app, network, &mut writer).await.map(|()| None),
                    Some(Command::Frame(frame)) => send(&mut writer, &frame).await.map(|()| None),
                    Some(Command::Close) | None => Ok(Some("replaced by a newer link or closed")),
                },
                frame = incoming.recv() => match frame {
                    Some(Ok(bytes)) => {
                        state.last_received = Instant::now();
                        handle(app, network, &peer, bluetooth, &subject, &rtt_ms, &mut writer, &mut state, &bytes).await.map(|()| None)
                    }
                    Some(Err(error)) => Err(error),
                    None => Ok(Some("the link closed")),
                },
                _ = heartbeat.tick() => beat(app, network, &peer, &subject, &tuning, &mut writer, &mut state).await,
            };
            match step {
                Ok(None) => {}
                Ok(Some(text)) => break text.to_owned(),
                Err(error) => break reason(&error),
            }
        },
    };
    reader_task.abort();
    network.channels.deregister(&peer, serial);
    network.channels.note_loss(&peer);
    diag::record_detail(app, "channel_closed", subject, end);
    changed(app);
}

struct Flow {
    /// Messages sent on this channel that have no receipt yet.
    in_flight: HashMap<Uuid, Instant>,
    /// Envelope ids this side offered in a `Relay` it started.
    relay_offered: Option<Vec<Uuid>>,
    /// Envelope ids this side offered back in a `RelayAck`.
    relay_served: Option<Vec<Uuid>>,
    ping: Option<(u64, Instant)>,
    next_ping: u64,
    last_received: Instant,
}

async fn flush(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    subject: &diag::Subject<'_>,
    tuning: &Tuning,
    writer: &mut SessionWriter,
    state: &mut Flow,
) -> Result<()> {
    let deliveries = commands::pending_mesh_for(app, network, peer, FLUSH_BATCH)?;
    let live: std::collections::HashSet<Uuid> = deliveries.iter().map(|delivery| delivery.id).collect();
    // Acknowledged elsewhere (a relay brought the receipt) or expired.
    state.in_flight.retain(|id, _| live.contains(id));
    for delivery in deliveries {
        if state.in_flight.get(&delivery.id).is_some_and(|sent| sent.elapsed() < tuning.resend_after) {
            continue;
        }
        let id = delivery.id;
        let resend = state.in_flight.insert(id, Instant::now()).is_some();
        send(writer, &Control::Message(delivery)).await?;
        diag::record_detail(app, if resend { "message_resent" } else { "message_sent" }, *subject, format!("message {id}"));
    }
    Ok(())
}

async fn start_relay(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    bluetooth: bool,
    writer: &mut SessionWriter,
    state: &mut Flow,
) -> Result<()> {
    if state.relay_offered.is_some() {
        return Ok(());
    }
    // Relaying is optional for this peer; a refusal must not end the channel.
    let Ok((frame, offered)) = relay_net::channel_open(app, network, peer, bluetooth) else {
        return Ok(());
    };
    state.relay_offered = Some(offered);
    send(writer, &frame).await
}

async fn beat(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    subject: &diag::Subject<'_>,
    tuning: &Tuning,
    writer: &mut SessionWriter,
    state: &mut Flow,
) -> Result<Option<&'static str>> {
    if network.check(app).is_err() {
        return Ok(Some("the local account session ended"));
    }
    if network.require_peer(app, peer).is_err() {
        return Ok(Some("this device was disconnected or is no longer trusted"));
    }
    if state.last_received.elapsed() >= tuning.dead_after {
        diag::record_detail(app, "heartbeat_missed", *subject, format!("silent for {} s", state.last_received.elapsed().as_secs()));
        return Ok(Some("the other device stopped answering"));
    }
    let id = state.next_ping;
    state.next_ping += 1;
    state.ping = Some((id, Instant::now()));
    send(writer, &Control::Ping { id }).await?;
    // Also the retry path for messages whose receipt never came.
    flush(app, network, peer, subject, tuning, writer, state).await?;
    Ok(None)
}

/// This device's profile statement for a trusted peer.
fn local_profile(app: &AppHandle, network: &Network) -> Result<Control> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let _gate = lock(&runtime.storage)?;
    let owner = TrustBook::load(&state, &network.owner)?.local_owner;
    let avatar = AvatarBook::load(&state, &network.owner)?.local_digest();
    Ok(Control::Profile { owner, avatar })
}

async fn send_profile(app: &AppHandle, network: &Network, writer: &mut SessionWriter) -> Result<()> {
    let frame = local_profile(app, network)?;
    send(writer, &frame).await
}

/// Apply a peer's profile statement. Returns the picture digest to fetch.
/// Everything is stored under the fingerprint that authenticated the channel.
fn profile_received(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    owner: Option<String>,
    picture: Option<String>,
) -> Result<Option<String>> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let mut updated = false;
    let fetch = {
        let _gate = lock(&runtime.storage)?;
        network.require_peer_locked(app, peer, false)?;
        let mut book = TrustBook::load(&state, &network.owner)?;
        let Some(record) = book.peers.get_mut(peer) else {
            return Err(QGuardError::Trust("This device is no longer trusted.".into()));
        };
        // A rename reaches the peer; a missing or invalid name keeps the one
        // shared at pairing.
        if let Some(name) = owner.filter(|name| valid_owner_name(name)) {
            if record.owner.as_deref() != Some(name.as_str()) {
                record.owner = Some(name);
                book.save(&state, &network.owner)?;
                updated = true;
            }
        }
        let mut avatars = AvatarBook::load(&state, &network.owner)?;
        match picture {
            None => {
                if avatars.peers.remove(peer).is_some() {
                    avatars.save(&state, &network.owner, &book)?;
                    updated = true;
                }
                None
            }
            Some(digest) if !avatar::valid_digest(&digest) => None,
            Some(digest) => avatars
                .peer(&book, peer)
                .is_none_or(|current| current.digest != digest)
                .then_some(digest),
        }
    };
    if updated {
        changed(app);
    }
    Ok(fetch)
}

/// Store a picture the peer sent, after checking it against its digest.
fn picture_received(app: &AppHandle, network: &Network, peer: &str, digest: &str, image: &str) -> Result<()> {
    let picture = avatar::received(digest, image)?;
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    {
        let _gate = lock(&runtime.storage)?;
        network.require_peer_locked(app, peer, false)?;
        let book = TrustBook::load(&state, &network.owner)?;
        let mut avatars = AvatarBook::load(&state, &network.owner)?;
        avatars.peers.insert(peer.to_owned(), picture);
        avatars.save(&state, &network.owner, &book)?;
    }
    changed(app);
    Ok(())
}

/// The local picture, when it still has the digest the peer asked for.
fn local_picture(app: &AppHandle, network: &Network, digest: &str) -> Result<Option<Control>> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let _gate = lock(&runtime.storage)?;
    Ok(AvatarBook::load(&state, &network.owner)?
        .local
        .filter(|picture| picture.digest == digest)
        .map(|picture| Control::Avatar { digest: picture.digest, image: picture.image }))
}

#[allow(clippy::too_many_arguments)]
async fn handle(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    bluetooth: bool,
    subject: &diag::Subject<'_>,
    rtt_ms: &AtomicU32,
    writer: &mut SessionWriter,
    state: &mut Flow,
    bytes: &[u8],
) -> Result<()> {
    match wire::decode(bytes)? {
        Control::Message(delivery) => {
            let id = delivery.id;
            match commands::store_incoming_mesh(app, network, peer, delivery) {
                Ok((receipt, new)) => {
                    diag::record_detail(app, if new { "message_received" } else { "message_duplicate" }, *subject, format!("message {id}"));
                    send(writer, &Control::Receipt(receipt)).await
                }
                // No longer authorized: end the channel. Anything else is
                // about this one message (expired, altered): keep the link.
                Err(error @ QGuardError::Trust(_)) => Err(error),
                Err(error) => {
                    diag::record_detail(app, "message_rejected", *subject, format!("message {id}: {}", reason(&error)));
                    Ok(())
                }
            }
        }
        Control::Receipt(receipt) => {
            let id = receipt.id;
            state.in_flight.remove(&id);
            match commands::acknowledge_mesh(app, network, peer, receipt) {
                Ok(()) => diag::record_detail(app, "message_acknowledged", *subject, format!("message {id}")),
                Err(error @ QGuardError::Trust(_)) => return Err(error),
                Err(error) => diag::record_detail(app, "receipt_rejected", *subject, format!("message {id}: {}", reason(&error))),
            }
            Ok(())
        }
        Control::Ping { id } => send(writer, &Control::Pong { id }).await,
        Control::Pong { id } => {
            if let Some((sent, at)) = state.ping.take() {
                if sent == id {
                    let elapsed = at.elapsed().as_millis().min(u128::from(u32::MAX - 1)) as u32;
                    rtt_ms.store(elapsed, Ordering::Relaxed);
                } else {
                    state.ping = Some((sent, at));
                }
            }
            Ok(())
        }
        Control::Relay { key, envelopes } => {
            let (frame, offered) = relay_net::channel_serve(app, network, peer, bluetooth, key, envelopes)?;
            state.relay_served = Some(offered);
            send(writer, &frame).await
        }
        Control::RelayAck { key, accepted, envelopes } => {
            let Some(offered) = state.relay_offered.take() else {
                return Err(wire::protocol_error());
            };
            let frame = relay_net::channel_ack(app, network, peer, &offered, key, accepted, envelopes)?;
            send(writer, &frame).await
        }
        Control::RelayDone { accepted } => {
            let Some(offered) = state.relay_served.take() else {
                return Err(wire::protocol_error());
            };
            relay_net::channel_done(app, network, peer, &offered, &accepted)
        }
        Control::Profile { owner, avatar } => match profile_received(app, network, peer, owner, avatar)? {
            Some(digest) => {
                diag::record(app, "profile_picture_requested", *subject);
                send(writer, &Control::AvatarRequest { digest }).await
            }
            None => Ok(()),
        },
        Control::AvatarRequest { digest } => match local_picture(app, network, &digest)? {
            Some(frame) => send(writer, &frame).await,
            // The picture changed since the peer saw the digest: re-announce.
            None => send_profile(app, network, writer).await,
        },
        Control::Avatar { digest, image } => {
            match picture_received(app, network, peer, &digest, &image) {
                Ok(()) => diag::record(app, "profile_picture_received", *subject),
                Err(error @ QGuardError::Trust(_)) if network.require_peer(app, peer).is_err() => return Err(error),
                // A bad picture is refused; it never ends the link.
                Err(error) => diag::record_detail(app, "profile_picture_rejected", *subject, reason(&error)),
            }
            Ok(())
        }
        Control::ChannelOffer(manifest) => {
            let id = manifest.id;
            match transfer::channel_offer(app, network, peer, manifest).await {
                Ok(state) => send(writer, &Control::OfferState { id, state }).await,
                Err(error @ QGuardError::Trust(_)) if network.require_peer(app, peer).is_err() => Err(error),
                // An offer this device cannot take never ends the link.
                Err(error) => {
                    diag::record_detail(app, "transfer_offer_rejected", *subject, format!("transfer {id}: {}", reason(&error)));
                    Ok(())
                }
            }
        }
        Control::OfferState { id, state } => {
            if let Some(network) = shared(app, network) {
                transfer::offer_answered(app, &network, peer, id, state).await;
            }
            Ok(())
        }
        Control::LinkRequest => {
            if let Some(network) = shared(app, network) {
                link::requested(app, &network, peer);
            }
            Ok(())
        }
        Control::LinkOffer { ssid, password, security, addresses } => {
            if let Some(network) = shared(app, network) {
                link::offered(app, &network, peer, ssid, password, security, addresses);
            }
            Ok(())
        }
        Control::LinkJoined => {
            link::joined_by_peer(app, network, peer);
            Ok(())
        }
        Control::LinkFailed { reason } => {
            if let Some(network) = shared(app, network) {
                link::failed_by_peer(app, &network, peer, reason);
            }
            Ok(())
        }
        Control::LinkClose => {
            if let Some(network) = shared(app, network) {
                link::closed_by_peer(app, &network, peer);
            }
            Ok(())
        }
        Control::Nudge => {
            if let Some(network) = shared(app, network) {
                diag::record(app, "transfer_nudge_received", *subject);
                commands::schedule_queued_transfers(app, &network);
                commands::schedule_transfer_controls(app, &network);
            }
            changed(app);
            Ok(())
        }
        _ => Err(wire::protocol_error()),
    }
}

/// Trusted, Mesh-approved peers that are reachable right now and not
/// disconnected by the user: the peers a channel should exist for.
fn wanted(app: &AppHandle, network: &Network) -> Result<Vec<String>> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let _gate = lock(&runtime.storage)?;
    let book = TrustBook::load(&state, &network.owner)?;
    let mut peers = Vec::new();
    for (peer, record) in &book.peers {
        if (book.allows(peer, PeerCapability::Mesh) || book.allows(peer, PeerCapability::Xfer))
            && !network.is_disconnected(peer)
            && network.mesh_reachable(peer, record.address)?
        {
            peers.push(peer.clone());
        }
    }
    Ok(peers)
}

/// Keep a channel to every reachable trusted peer: called on each discovery
/// beacon. `urgent` names a peer with work waiting, which is dialed without
/// the polite deferral.
pub(super) fn maintain(app: &AppHandle, network: &Arc<Network>, urgent: Option<&str>) {
    if network.check(app).is_err() {
        return;
    }
    let Ok(peers) = wanted(app, network) else { return };
    let now = Instant::now();
    let (open_total, open_bluetooth) = network.channels.counts();
    let mut to_dial = Vec::new();
    {
        let Ok(mut dials) = network.channels.dials.lock() else { return };
        // Forget peers that left range, unless a dial is still running.
        dials.retain(|peer, dial| dial.dialing || dial.legacy || peers.contains(peer));
        for peer in &peers {
            if network.channels.is_open(peer) {
                if let Some(dial) = dials.get_mut(peer) {
                    dial.failures = 0;
                    dial.lost_at = None;
                    dial.wanted_since = now;
                }
                continue;
            }
            let dial = dials.entry(peer.clone()).or_insert_with(|| Dial::new(now));
            if dial.dialing || now < dial.next_attempt {
                continue;
            }
            let polite = network.fingerprint.as_str() > peer.as_str()
                && urgent != Some(peer.as_str())
                && dial.lost_at.is_none()
                && dial.wanted_since.elapsed() < DIAL_DEFER;
            if polite || open_total + to_dial.len() >= MAX_CHANNELS {
                continue;
            }
            dial.dialing = true;
            to_dial.push((peer.clone(), dial.version));
        }
    }
    for (peer, version) in to_dial {
        let app = app.clone();
        let network = Arc::clone(network);
        tauri::async_runtime::spawn(async move {
            let opened = tokio::select! {
                _ = network.until_stopped() => Dialed::Failed("local networking stopped".into()),
                outcome = dial(&app, &network, &peer, open_bluetooth, version) => outcome,
            };
            let mut fell_back = false;
            if let Ok(mut dials) = network.channels.dials.lock() {
                let now = Instant::now();
                let entry = dials.entry(peer.clone()).or_insert_with(|| Dial::new(now));
                entry.dialing = false;
                match &opened {
                    // `run` already scheduled the redial.
                    Dialed::Ran => {
                        entry.legacy = false;
                        entry.unconfirmed = 0;
                    }
                    // An older build hangs up on the channel request, which looks
                    // like a lost link. Believe it only when it happens twice.
                    // A version-1 build refuses the newer request: ask for
                    // version 1 at once, without counting it against the peer.
                    Dialed::Legacy if version > MIN_VERSION => {
                        entry.version = version - 1;
                        entry.next_attempt = now;
                        fell_back = true;
                    }
                    Dialed::Legacy => {
                        entry.unconfirmed = entry.unconfirmed.saturating_add(1);
                        entry.legacy = entry.unconfirmed >= 2;
                        entry.next_attempt = now + if entry.legacy { LEGACY_RETRY } else { backoff(1) };
                    }
                    Dialed::Failed(_) => {
                        entry.failures = entry.failures.saturating_add(1);
                        entry.next_attempt = now + backoff(entry.failures);
                    }
                }
            }
            match opened {
                Dialed::Failed(why) => diag::record_detail(&app, "dial_failed", diag::Subject::peer(&peer), why),
                Dialed::Legacy if fell_back => diag::record_detail(&app, "channel_version_fallback", diag::Subject::peer(&peer), format!("The other device runs an older channel protocol; retrying with version {}.", version - 1)),
                Dialed::Legacy => {
                    diag::record_detail(&app, "channel_unconfirmed", diag::Subject::peer(&peer), "The other device closed the link instead of confirming the channel (an older Qguard does this).");
                    // Once it is known to be an older build, deliver the old way.
                    if network.channels.legacy(&peer) {
                        commands::schedule_mesh(&app, &network);
                    }
                }
                Dialed::Ran => {}
            }
            changed(&app);
        });
    }
}

enum Dialed {
    /// A channel opened and has since closed.
    Ran,
    Legacy,
    Failed(String),
}

async fn dial(app: &AppHandle, network: &Arc<Network>, peer: &str, open_bluetooth: usize, version: u8) -> Dialed {
    let Ok(_slot) = Arc::clone(&network.channels.dial_slots).acquire_owned().await else {
        return Dialed::Failed("dialing is unavailable".into());
    };
    if network.channels.is_open(peer) {
        return Dialed::Ran;
    }
    diag::record(app, "dial_started", diag::Subject::peer(peer));
    changed(app);
    let started = Instant::now();
    let mut connection = match commands::connect_mesh(app, network, peer).await {
        Ok(connection) => connection,
        Err(error) => return Dialed::Failed(reason(&error)),
    };
    let bluetooth = connection.bluetooth();
    let session_id = diag::session_id(connection.binding());
    let subject = diag::Subject::link(peer, &session_id, bluetooth);
    diag::record_detail(app, "session_authenticated", subject, format!("hybrid handshake in {} ms", started.elapsed().as_millis()));
    if bluetooth && open_bluetooth >= MAX_BLUETOOTH_CHANNELS {
        return Dialed::Failed("all Bluetooth links are in use".into());
    }
    if let Err(error) = network
        .require_capability(app, peer, PeerCapability::Mesh)
        .or_else(|_| network.require_capability(app, peer, PeerCapability::Xfer))
    {
        return Dialed::Failed(reason(&error));
    }
    if let Err(error) = wire::send(&mut connection, &Control::Channel { version }).await {
        return Dialed::Failed(reason(&error));
    }
    match timeout(tuning(bluetooth).ready_timeout, wire::recv(&mut connection)).await {
        Ok(Ok(Control::ChannelReady { version: ready })) if ready == version => {}
        // An older build rejects the unknown frame and hangs up.
        Ok(Ok(_)) | Ok(Err(_)) => return Dialed::Legacy,
        Err(_) => return Dialed::Failed("the other device did not confirm the channel".into()),
    }
    drop(_slot);
    let (session, _activity) = connection.into_parts();
    run(app, network, session, true, version).await;
    Dialed::Ran
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(channels: &Channels, initiated: bool, bluetooth: bool) -> (Open, mpsc::Receiver<Command>) {
        let (commands, inbox) = mpsc::channel(4);
        let open = Open {
            serial: channels.serial.fetch_add(1, Ordering::Relaxed) + 1,
            commands,
            initiator_is_local: initiated,
            bluetooth,
            since: 100,
            session: "0011223344556677".into(),
            rtt_ms: Arc::new(AtomicU32::new(u32::MAX)),
            version: VERSION,
        };
        (open, inbox)
    }

    #[test]
    fn crossing_dials_keep_the_link_dialed_by_the_smaller_fingerprint_on_both_devices() {
        let small = "aa".repeat(32);
        let large = "bb".repeat(32);
        // On the smaller device: its own dial wins over the one it accepted.
        let channels = Channels::default();
        let (accepted, mut accepted_inbox) = link(&channels, false, true);
        assert!(channels.register(&small, &large, accepted));
        let (dialed, _dialed_inbox) = link(&channels, true, true);
        assert!(channels.register(&small, &large, dialed));
        assert!(matches!(accepted_inbox.try_recv(), Ok(Command::Close)));
        // And an accepted link cannot displace its own dial afterwards.
        let (late, _late_inbox) = link(&channels, false, true);
        assert!(!channels.register(&small, &large, late));

        // On the larger device the mirror image: the accepted link wins.
        let channels = Channels::default();
        let (dialed, mut dialed_inbox) = link(&channels, true, true);
        assert!(channels.register(&large, &small, dialed));
        let (accepted, _accepted_inbox) = link(&channels, false, true);
        assert!(channels.register(&large, &small, accepted));
        assert!(matches!(dialed_inbox.try_recv(), Ok(Command::Close)));
        let (redial, _redial_inbox) = link(&channels, true, true);
        assert!(!channels.register(&large, &small, redial));
    }

    #[test]
    fn a_redial_in_the_same_direction_replaces_the_stale_link_and_only_its_owner_removes_it() {
        let local = "aa".repeat(32);
        let peer = "bb".repeat(32);
        let channels = Channels::default();
        let (first, mut first_inbox) = link(&channels, false, false);
        let first_serial = first.serial;
        assert!(channels.register(&local, &peer, first));
        let (second, _second_inbox) = link(&channels, false, false);
        let second_serial = second.serial;
        assert!(channels.register(&local, &peer, second));
        assert!(matches!(first_inbox.try_recv(), Ok(Command::Close)));
        // The replaced link ending must not remove its successor.
        channels.deregister(&peer, first_serial);
        assert!(channels.is_open(&peer));
        channels.deregister(&peer, second_serial);
        assert!(!channels.is_open(&peer));
    }

    #[test]
    fn the_link_view_reports_only_registry_state() {
        let local = "aa".repeat(32);
        let peer = "bb".repeat(32);
        let channels = Channels::default();
        assert!(channels.view(&peer).is_none());
        assert!(!channels.flush(&peer) && !channels.request_relay(&peer) && !channels.nudge(&peer));

        let (open, mut inbox) = link(&channels, true, true);
        let serial = open.serial;
        let rtt = Arc::clone(&open.rtt_ms);
        assert!(channels.register(&local, &peer, open));
        let view = channels.view(&peer).unwrap();
        assert_eq!((view.state, view.transport, view.rtt_ms), ("connected", Some("bluetooth"), None));
        assert_eq!(view.session.as_deref(), Some("0011223344556677"));
        rtt.store(42, Ordering::Relaxed);
        assert_eq!(channels.view(&peer).unwrap().rtt_ms, Some(42));
        assert!(channels.flush(&peer));
        assert!(matches!(inbox.try_recv(), Ok(Command::Flush)));
        assert_eq!(channels.counts(), (1, 1));

        channels.deregister(&peer, serial);
        channels.note_loss(&peer);
        let view = channels.view(&peer).unwrap();
        assert_eq!((view.state, view.transport), ("reconnecting", None));
    }

    #[test]
    fn redial_backoff_grows_and_is_capped() {
        assert_eq!(backoff(1), Duration::from_secs(3));
        assert_eq!(backoff(3), Duration::from_secs(12));
        assert_eq!(backoff(40), Duration::from_secs(60));
        assert!(tuning(true).dead_after > tuning(true).heartbeat * 3);
        assert!(tuning(false).dead_after > tuning(false).heartbeat * 3);
    }
}
