//! First-contact trust over an isolated QHCE session. The encrypted exchange
//! binds user approval to one authenticated handshake and never carries data.

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::time::{sleep, timeout};
use uuid::Uuid;

use crate::{
    crypto::provider::{self, Sha3_256Hasher},
    error::{QGuardError, Result},
};

use super::{
    network::lock,
    profile::{valid_owner_name, PeerCapability, PeerMetadata},
    session::Session,
};

// Version 2 scopes trust to the requested capabilities and exchanges owner
// names only after both users confirm the code. Version 1 peers fail closed.
const VERSION: u8 = 2;
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
const DIAL_TIMEOUT: Duration = Duration::from_secs(240);
const HISTORY_WINDOW: Duration = Duration::from_secs(240);
const REQUEST_WINDOW: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_PENDING: usize = 4;
const MAX_INCOMING_PER_WINDOW: usize = 8;
const MAX_HISTORY: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum Direction {
    Incoming,
    Outgoing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum Status {
    Requesting,
    AwaitingApproval,
    Verifying,
    AwaitingConfirmation,
    Establishing,
    Trusted,
    Rejected,
    Cancelled,
    Failed,
    Expired,
}

impl Status {
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Trusted | Self::Rejected | Self::Cancelled | Self::Failed | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum PairingDecision {
    Allow,
    Reject,
    Confirm,
    Cancel,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PairingView {
    id: Uuid,
    peer: String,
    label: Option<String>,
    platform: Option<String>,
    capabilities: Vec<PeerCapability>,
    requested: Vec<PeerCapability>,
    direction: Direction,
    status: Status,
    code: Option<String>,
    error: Option<String>,
}

pub(super) struct PairingAlert {
    pub id: Uuid,
    pub peer: String,
    pub incoming: bool,
    pub label: String,
    pub platform: String,
    pub requested: Vec<PeerCapability>,
}

struct Attempt {
    view: PairingView,
    code: Option<String>,
    expires: Instant,
    finished: Option<Instant>,
    superseded: bool,
}

impl Attempt {
    fn new(id: Uuid, peer: &str, direction: Direction, lifetime: Duration) -> Self {
        Self {
            view: PairingView {
                id,
                peer: peer.into(),
                label: None,
                platform: None,
                capabilities: Vec::new(),
                requested: Vec::new(),
                direction,
                status: Status::Requesting,
                code: None,
                error: None,
            },
            code: None,
            expires: Instant::now() + lifetime,
            finished: None,
            superseded: false,
        }
    }

    fn prepare(&mut self, device: &PeerMetadata, requested: Vec<PeerCapability>, code: String) {
        self.view.label = Some(device.label.clone());
        self.view.platform = Some(device.platform.clone());
        self.view.capabilities = device.capabilities.clone();
        self.view.requested = requested;
        self.code = Some(code);
        self.expires = Instant::now() + APPROVAL_TIMEOUT;
        self.set(Status::AwaitingApproval);
    }

    fn set(&mut self, status: Status) {
        self.view.status = status;
        self.view.code = match status {
            Status::Verifying | Status::AwaitingConfirmation => self.code.clone(),
            _ => None,
        };
        self.view.error = match status {
            Status::Failed => {
                Some("The pairing connection ended. Start a new request to try again.".into())
            }
            Status::Expired => {
                Some("The pairing request timed out. Start a new request to try again.".into())
            }
            _ => None,
        };
        if status.terminal() {
            self.code = None;
            self.finished = Some(Instant::now());
        }
    }
}

#[derive(Default)]
struct Attempts {
    by_id: HashMap<Uuid, Attempt>,
    incoming: VecDeque<(Instant, String, Uuid)>,
}

impl Attempts {
    fn prune(&mut self) {
        let now = Instant::now();
        self.by_id.retain(|_, attempt| {
            if !attempt.view.status.terminal() && now >= attempt.expires {
                attempt.set(Status::Expired);
            }
            attempt
                .finished
                .is_none_or(|ended| now.duration_since(ended) < HISTORY_WINDOW)
        });
        self.incoming
            .retain(|(started, _, _)| now.duration_since(*started) < REQUEST_WINDOW);
        if self.by_id.len() > MAX_HISTORY {
            let mut completed: Vec<_> = self
                .by_id
                .iter()
                .filter_map(|(id, attempt)| attempt.finished.map(|ended| (ended, *id)))
                .collect();
            completed.sort_unstable();
            let excess = self.by_id.len() - MAX_HISTORY;
            for (_, id) in completed.into_iter().take(excess) {
                self.by_id.remove(&id);
            }
        }
    }

    fn pending(&self) -> usize {
        self.by_id
            .values()
            .filter(|entry| !entry.view.status.terminal())
            .count()
    }

    fn active_for_peer(&mut self, peer: &str) -> Option<&mut Attempt> {
        self.by_id
            .values_mut()
            .find(|entry| entry.view.peer == peer && !entry.view.status.terminal())
    }
}

#[derive(Default)]
pub(super) struct Pairings {
    attempts: Mutex<Attempts>,
}

impl Pairings {
    pub fn start_outgoing(&self, peer: &str, requested: Vec<PeerCapability>) -> Result<Uuid> {
        capabilities(&requested)?;
        let mut attempts = lock(&self.attempts)?;
        attempts.prune();
        if attempts.active_for_peer(peer).is_some() {
            return Err(pairing_error(
                "A pairing request for this device is already open.",
            ));
        }
        if attempts.pending() >= MAX_PENDING {
            return Err(pairing_error(
                "Too many pairing requests are open. Try again shortly.",
            ));
        }
        let id = Uuid::new_v4();
        let mut attempt = Attempt::new(id, peer, Direction::Outgoing, DIAL_TIMEOUT);
        attempt.view.requested = requested;
        attempts.by_id.insert(id, attempt);
        Ok(id)
    }

    fn start_incoming(
        &self,
        local: &str,
        peer: &str,
        id: Uuid,
        mut incoming: Attempt,
    ) -> Result<()> {
        let mut attempts = lock(&self.attempts)?;
        attempts.prune();
        if id.is_nil()
            || attempts.by_id.contains_key(&id)
            || attempts.incoming.iter().any(|(_, _, seen)| *seen == id)
        {
            return Err(pairing_error("This pairing request was already received."));
        }
        if attempts.incoming.len() >= MAX_INCOMING_PER_WINDOW
            || attempts.incoming.iter().any(|(started, source, _)| {
                source == peer && started.elapsed() < Duration::from_secs(5)
            })
        {
            return Err(pairing_error("Pairing requests are arriving too quickly."));
        }
        if let Some(active) = attempts.active_for_peer(peer) {
            // Both devices choose the same winner when their requests cross.
            // An already approved exchange takes precedence over a new dial.
            if active.view.direction != Direction::Outgoing
                || active.view.status != Status::Requesting
                || local < peer
            {
                return Err(pairing_error(
                    "A pairing request for this device is already open.",
                ));
            }
            active.set(Status::Cancelled);
            active.superseded = true;
        }
        if attempts.pending() >= MAX_PENDING {
            return Err(pairing_error(
                "Too many pairing requests are open. Try again shortly.",
            ));
        }
        incoming.view.id = id;
        attempts
            .incoming
            .push_back((Instant::now(), peer.into(), id));
        attempts.by_id.insert(id, incoming);
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<PairingView>> {
        let mut attempts = lock(&self.attempts)?;
        attempts.prune();
        let mut entries: Vec<_> = attempts
            .by_id
            .values()
            .filter(|attempt| {
                !attempt.superseded
                    && (attempt.view.direction == Direction::Outgoing
                        || attempt.view.label.is_some())
            })
            .collect();
        entries.sort_by_key(|attempt| (attempt.finished.is_some(), attempt.expires));
        Ok(entries
            .into_iter()
            .map(|attempt| attempt.view.clone())
            .collect())
    }

    /// Requests that need this user's attention: an incoming request waiting
    /// for approval, or an outgoing request whose code is ready to compare.
    pub fn alerts(&self) -> Vec<PairingAlert> {
        let Ok(mut attempts) = lock(&self.attempts) else {
            return Vec::new();
        };
        attempts.prune();
        attempts
            .by_id
            .values()
            .filter(|attempt| !attempt.superseded)
            .filter_map(|attempt| {
                let view = &attempt.view;
                let incoming = match (view.direction, view.status) {
                    (Direction::Incoming, Status::AwaitingApproval) => true,
                    (Direction::Outgoing, Status::Verifying) => false,
                    _ => return None,
                };
                Some(PairingAlert {
                    id: view.id,
                    peer: view.peer.clone(),
                    incoming,
                    label: view.label.clone()?,
                    platform: view.platform.clone()?,
                    requested: view.requested.clone(),
                })
            })
            .collect()
    }

    pub fn has_pending(&self) -> bool {
        lock(&self.attempts).is_ok_and(|mut attempts| {
            attempts.prune();
            attempts.pending() > 0
        })
    }

    fn change<T>(&self, id: Uuid, action: impl FnOnce(&mut Attempt) -> Result<T>) -> Result<T> {
        let mut attempts = lock(&self.attempts)?;
        attempts.prune();
        let attempt = attempts
            .by_id
            .get_mut(&id)
            .ok_or_else(|| pairing_error("This pairing request is no longer available."))?;
        action(attempt)
    }

    pub fn decide(&self, id: Uuid, decision: PairingDecision) -> Result<()> {
        self.change(id, |attempt| {
            let current = attempt.view.status;
            let status = match (attempt.view.direction, current, decision) {
                (Direction::Incoming, Status::AwaitingApproval, PairingDecision::Allow) => {
                    Status::Verifying
                }
                (Direction::Incoming, Status::AwaitingApproval, PairingDecision::Reject) => {
                    Status::Rejected
                }
                (_, Status::Verifying, PairingDecision::Confirm) => Status::AwaitingConfirmation,
                (_, current, PairingDecision::Cancel)
                    if !current.terminal() && current != Status::Establishing =>
                {
                    Status::Cancelled
                }
                _ => return Err(pairing_error("This pairing action is no longer available.")),
            };
            attempt.set(status);
            Ok(())
        })
    }

    fn status(&self, id: Uuid) -> Result<Status> {
        self.change(id, |attempt| Ok(attempt.view.status))
    }

    fn update(&self, id: Uuid, from: Status, to: Status) -> Result<bool> {
        self.change(id, |attempt| {
            if attempt.view.status == from {
                attempt.set(to);
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }

    fn finish(&self, id: Uuid, status: Status) {
        let _ = self.change(id, |attempt| {
            if !attempt.view.status.terminal() {
                attempt.set(status);
            }
            Ok(())
        });
    }

    pub fn fail(&self, id: Uuid) {
        self.finish(id, Status::Failed);
    }

    /// Ends a request as failed and keeps the reason the connection gave, so
    /// the user sees why (no route, Bluetooth refused, an older version) and
    /// not only that it ended. A request that already ended another way
    /// keeps its outcome.
    pub fn fail_with(&self, id: Uuid, reason: &str) {
        let reason: String = reason.chars().filter(|character| !character.is_control()).take(240).collect();
        let _ = self.change(id, |attempt| {
            if !attempt.view.status.terminal() {
                attempt.set(Status::Failed);
            }
            if attempt.view.status == Status::Failed && !reason.is_empty() {
                attempt.view.error = Some(reason);
            }
            Ok(())
        });
    }

    pub fn cancel_peer(&self, peer: &str) {
        if let Ok(mut attempts) = lock(&self.attempts) {
            if let Some(attempt) = attempts.active_for_peer(peer) {
                attempt.set(Status::Cancelled);
            }
        }
    }

    pub fn ensure_committing(&self, id: Uuid, peer: &str) -> Result<()> {
        self.change(id, |attempt| {
            if attempt.view.peer == peer && attempt.view.status == Status::Establishing {
                Ok(())
            } else {
                Err(pairing_error("This pairing is no longer authorized."))
            }
        })
    }
}

pub(super) struct AuthenticatedPeer {
    pub fingerprint: String,
    pub metadata: PeerMetadata,
    pub public_key: Vec<u8>,
    /// Capabilities both users approved, bound into the verification code.
    pub granted: Vec<PeerCapability>,
    /// Display name sent on the verified session after both confirmations.
    pub owner: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum ClientState {
    Waiting,
    Confirmed,
    Cancelled,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum ServerState {
    Waiting,
    Verifying,
    Confirmed,
    Rejected,
    Cancelled,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
enum Frame {
    Request {
        version: u8,
        id: Uuid,
        device: PeerMetadata,
        requested: Vec<PeerCapability>,
        commitment: [u8; 32],
    },
    Answer {
        version: u8,
        device: PeerMetadata,
        nonce: [u8; 32],
    },
    Reveal {
        nonce: [u8; 32],
    },
    Poll {
        state: ClientState,
    },
    Progress {
        state: ServerState,
    },
    // Owner names are personal data. They travel only after both users have
    // compared and confirmed the code for this authenticated session.
    Commit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner: Option<String>,
    },
    Committed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner: Option<String>,
    },
    Installed,
    /// Before pairing: "show me your picture" (the owner may have opted in).
    PictureRequest,
    /// The picture (base64) and its SHA3-256 digest, or neither.
    Picture {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        digest: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        image: Option<String>,
    },
}

/// Ask a nearby, not yet paired device for the picture its owner shares.
pub(super) async fn request_picture(session: &mut Session) -> Result<Option<(String, String)>> {
    if !session.pairing() {
        return Err(protocol_error());
    }
    send(session, Frame::PictureRequest).await?;
    match receive(session).await? {
        Frame::Picture { digest: Some(digest), image: Some(image) } => Ok(Some((digest, image))),
        Frame::Picture { .. } => Ok(None),
        _ => Err(protocol_error()),
    }
}

fn pairing_error(message: &'static str) -> QGuardError {
    QGuardError::Trust(message.into())
}

fn protocol_error() -> QGuardError {
    pairing_error("The other device sent an invalid pairing response.")
}

async fn send(session: &mut Session, frame: Frame) -> Result<()> {
    let bytes = serde_json::to_vec(&frame).map_err(|_| protocol_error())?;
    session.send(&bytes).await
}

async fn receive(session: &mut Session) -> Result<Frame> {
    let bytes = session.recv().await?;
    serde_json::from_slice(&bytes).map_err(|_| protocol_error())
}

fn capabilities(values: &[PeerCapability]) -> Result<u8> {
    let mut flags = 0;
    for value in values {
        let flag = match value {
            PeerCapability::Mesh => 1,
            PeerCapability::Xfer => 2,
        };
        if flags & flag != 0 {
            return Err(protocol_error());
        }
        flags |= flag;
    }
    if flags == 0 {
        return Err(protocol_error());
    }
    Ok(flags)
}

fn append_device(hash: &mut Sha3_256Hasher, device: &PeerMetadata) -> Result<()> {
    device.validate()?;
    for value in [device.label.as_bytes(), device.platform.as_bytes()] {
        hash.update(&(value.len() as u32).to_be_bytes());
        hash.update(value);
    }
    hash.update(&[capabilities(&device.capabilities)?]);
    Ok(())
}

// The initiator commits to its nonce before seeing the responder's nonce. This
// prevents either peer from freely choosing the last SAS input with knowledge of
// the other inputs. The commitment is scoped to this authenticated session and
// request so a reveal cannot be reused in a different exchange.
fn nonce_commitment(binding: &[u8; 32], id: Uuid, nonce: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha3_256Hasher::new();
    hash.update(b"QGuard-Offline-Pairing-Nonce-Commitment-v1");
    hash.update(binding);
    hash.update(id.as_bytes());
    hash.update(nonce);
    hash.finalize()
}

fn verification_code(
    binding: &[u8; 32],
    id: Uuid,
    requested: &[PeerCapability],
    initiator: &PeerMetadata,
    responder: &PeerMetadata,
    nonces: &[[u8; 32]; 2],
) -> Result<String> {
    let mut hash = Sha3_256Hasher::new();
    hash.update(b"QGuard-Offline-Pairing-Verification-Code-v1");
    hash.update(&[VERSION, capabilities(requested)?]);
    hash.update(binding);
    hash.update(id.as_bytes());
    append_device(&mut hash, initiator)?;
    append_device(&mut hash, responder)?;
    if requested.iter().any(|capability| {
        !initiator.capabilities.contains(capability) || !responder.capabilities.contains(capability)
    }) {
        return Err(pairing_error(
            "The requested pairing capability is unavailable.",
        ));
    }
    for nonce in nonces {
        hash.update(nonce);
    }
    let digest = hash.finalize();
    let display = hex::encode_upper(&digest[..8]);
    Ok(format!(
        "{}-{}-{}-{}",
        &display[..4],
        &display[4..8],
        &display[8..12],
        &display[12..]
    ))
}

fn authenticated_peer(
    session: &Session,
    metadata: PeerMetadata,
    granted: Vec<PeerCapability>,
    owner: Option<String>,
) -> Result<AuthenticatedPeer> {
    if owner.as_deref().is_some_and(|name| !valid_owner_name(name)) {
        return Err(protocol_error());
    }
    Ok(AuthenticatedPeer {
        fingerprint: session.peer().into(),
        metadata,
        public_key: session.peer_public().to_vec(),
        granted,
        owner,
    })
}

fn settle(
    pairings: &Pairings,
    id: Uuid,
    result: std::result::Result<Result<()>, tokio::time::error::Elapsed>,
    notify: impl Fn(),
) -> Result<()> {
    let result = match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            pairings.fail(id);
            Err(error)
        }
        Err(_) => {
            pairings.finish(id, Status::Expired);
            Err(pairing_error("The pairing request timed out."))
        }
    };
    notify();
    result
}

pub(super) async fn initiate(
    session: &mut Session,
    pairings: &Pairings,
    id: Uuid,
    local: PeerMetadata,
    local_owner: Option<String>,
    requested: Vec<PeerCapability>,
    notify: impl Fn(),
    check: impl Fn() -> Result<()>,
    persist: impl FnOnce(Uuid, AuthenticatedPeer) -> Result<()>,
) -> Result<()> {
    if !session.pairing() {
        return Err(protocol_error());
    }
    let result = timeout(APPROVAL_TIMEOUT, async {
        check()?;
        let may_send = pairings.change(id, |attempt| {
            if attempt.view.peer != session.peer()
                || attempt.view.direction != Direction::Outgoing
                || attempt.view.requested != requested
            {
                return Err(protocol_error());
            }
            Ok(attempt.view.status == Status::Requesting)
        })?;
        if !may_send {
            return Ok(());
        }
        local.validate()?;
        let nonce = provider::random_array();
        let commitment = nonce_commitment(session.binding(), id, &nonce);
        send(
            session,
            Frame::Request {
                version: VERSION,
                id,
                device: local.clone(),
                requested: requested.clone(),
                commitment,
            },
        )
        .await?;
        let Frame::Answer {
            version: VERSION,
            device,
            nonce: server_nonce,
        } = receive(session).await?
        else {
            return Err(protocol_error());
        };
        let code = verification_code(
            session.binding(),
            id,
            &requested,
            &local,
            &device,
            &[nonce, server_nonce],
        )?;
        check()?;
        if pairings.status(id)? != Status::Requesting {
            return Ok(());
        }
        send(session, Frame::Reveal { nonce }).await?;
        pairings.change(id, |attempt| {
            if attempt.view.status == Status::Requesting {
                attempt.prepare(&device, requested.clone(), code);
            }
            Ok(())
        })?;
        notify();
        loop {
            check()?;
            let state = match pairings.status(id)? {
                Status::AwaitingConfirmation => ClientState::Confirmed,
                Status::Cancelled | Status::Expired => ClientState::Cancelled,
                Status::AwaitingApproval | Status::Verifying => ClientState::Waiting,
                _ => return Err(protocol_error()),
            };
            let local_confirmed = matches!(state, ClientState::Confirmed);
            let local_cancelled = matches!(state, ClientState::Cancelled);
            send(session, Frame::Poll { state }).await?;
            if local_cancelled {
                return Ok(());
            }
            let Frame::Progress { state } = receive(session).await? else {
                return Err(protocol_error());
            };
            match state {
                ServerState::Waiting => {}
                ServerState::Rejected => {
                    pairings.finish(id, Status::Rejected);
                    return Ok(());
                }
                ServerState::Cancelled => {
                    pairings.finish(id, Status::Cancelled);
                    return Ok(());
                }
                ServerState::Verifying | ServerState::Confirmed => {
                    if pairings.update(id, Status::AwaitingApproval, Status::Verifying)? {
                        notify();
                    }
                    if matches!(state, ServerState::Confirmed)
                        && local_confirmed
                        && pairings.update(
                            id,
                            Status::AwaitingConfirmation,
                            Status::Establishing,
                        )?
                    {
                        notify();
                        break;
                    }
                }
            }
            sleep(POLL_INTERVAL).await;
        }
        check()?;
        send(session, Frame::Commit { owner: local_owner }).await?;
        match receive(session).await? {
            Frame::Committed { owner } => {
                check()?;
                pairings.ensure_committing(id, session.peer())?;
                persist(id, authenticated_peer(session, device, requested, owner)?)?;
                send(session, Frame::Installed).await?;
                pairings.finish(id, Status::Trusted);
                Ok(())
            }
            Frame::Progress {
                state: ServerState::Cancelled,
            } => {
                pairings.finish(id, Status::Cancelled);
                Ok(())
            }
            _ => Err(protocol_error()),
        }
    })
    .await;
    settle(pairings, id, result, notify)
}

pub(super) async fn respond(
    session: &mut Session,
    pairings: &Pairings,
    local: PeerMetadata,
    local_owner: Option<String>,
    notify: impl Fn(),
    check: impl Fn() -> Result<()>,
    persist: impl FnOnce(Uuid, AuthenticatedPeer) -> Result<()>,
    picture: impl FnOnce() -> Option<(String, String)>,
) -> Result<()> {
    if !session.pairing() {
        return Err(protocol_error());
    }
    check()?;
    let first = receive(session).await?;
    if matches!(first, Frame::PictureRequest) {
        let (digest, image) = picture().map_or((None, None), |(digest, image)| (Some(digest), Some(image)));
        return send(session, Frame::Picture { digest, image }).await;
    }
    let Frame::Request {
        version: VERSION,
        id,
        device,
        requested,
        commitment,
    } = first
    else {
        return Err(protocol_error());
    };
    let peer = session.peer().to_owned();
    device.validate()?;
    local.validate()?;
    capabilities(&requested)?;
    check()?;
    let incoming = Attempt::new(id, &peer, Direction::Incoming, APPROVAL_TIMEOUT);
    pairings.start_incoming(session.local_fingerprint(), &peer, id, incoming)?;
    let result = timeout(APPROVAL_TIMEOUT, async {
        let nonce = provider::random_array();
        send(
            session,
            Frame::Answer {
                version: VERSION,
                device: local.clone(),
                nonce,
            },
        )
        .await?;
        let Frame::Reveal {
            nonce: client_nonce,
        } = receive(session).await?
        else {
            return Err(protocol_error());
        };
        let expected = nonce_commitment(session.binding(), id, &client_nonce);
        if !provider::constant_time_eq(&commitment, &expected) {
            return Err(protocol_error());
        }
        let code = verification_code(
            session.binding(),
            id,
            &requested,
            &device,
            &local,
            &[client_nonce, nonce],
        )?;
        check()?;
        pairings.change(id, |attempt| {
            if attempt.view.status != Status::Requesting {
                return Err(pairing_error(
                    "This pairing request is no longer available.",
                ));
            }
            attempt.prepare(&device, requested.clone(), code);
            Ok(())
        })?;
        notify();
        loop {
            check()?;
            let Frame::Poll { state } = receive(session).await? else {
                return Err(protocol_error());
            };
            if matches!(state, ClientState::Cancelled) {
                pairings.finish(id, Status::Cancelled);
                return Ok(());
            }
            let local_status = pairings.status(id)?;
            if local_status == Status::AwaitingApproval && matches!(state, ClientState::Confirmed) {
                return Err(protocol_error());
            }
            let decision = match local_status {
                Status::AwaitingApproval => ServerState::Waiting,
                Status::Verifying => ServerState::Verifying,
                Status::AwaitingConfirmation => ServerState::Confirmed,
                Status::Rejected => ServerState::Rejected,
                Status::Cancelled | Status::Expired => ServerState::Cancelled,
                _ => return Err(protocol_error()),
            };
            send(session, Frame::Progress { state: decision }).await?;
            if matches!(
                local_status,
                Status::Rejected | Status::Cancelled | Status::Expired
            ) {
                return Ok(());
            }
            if local_status == Status::AwaitingConfirmation
                && matches!(state, ClientState::Confirmed)
            {
                break;
            }
        }
        let Frame::Commit { owner } = receive(session).await? else {
            return Err(protocol_error());
        };
        check()?;
        if !pairings.update(id, Status::AwaitingConfirmation, Status::Establishing)? {
            send(
                session,
                Frame::Progress {
                    state: ServerState::Cancelled,
                },
            )
            .await?;
            return Ok(());
        }
        notify();
        check()?;
        pairings.ensure_committing(id, session.peer())?;
        persist(id, authenticated_peer(session, device, requested, owner)?)?;
        send(session, Frame::Committed { owner: local_owner }).await?;
        if !matches!(receive(session).await?, Frame::Installed) {
            return Err(protocol_error());
        }
        pairings.finish(id, Status::Trusted);
        Ok(())
    })
    .await;
    settle(pairings, id, result, notify)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline::{profile::TrustBook, session::Identity, smart};
    use std::cell::RefCell;
    use tokio::net::{TcpListener, TcpStream};

    fn device(platform: &str) -> PeerMetadata {
        PeerMetadata {
            label: format!("Pairing test {platform}"),
            platform: platform.into(),
            capabilities: vec![PeerCapability::Mesh, PeerCapability::Xfer],
        }
    }

    async fn open_pairing(
        initiator: &Identity,
        responder: &Identity,
        bluetooth: bool,
    ) -> (Session, Session) {
        let allowed = |peer: &str| peer == initiator.fingerprint();
        let (client, server) = if bluetooth {
            let (client, server) = smart::test_ble_pair();
            tokio::join!(
                Session::connect_pairing_ble(client, initiator, responder.fingerprint()),
                Session::accept_mixed_ble(server, responder, |_| false, allowed),
            )
        } else {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            tokio::join!(
                async {
                    let stream = TcpStream::connect(address).await.unwrap();
                    Session::connect_pairing(stream, initiator, responder.fingerprint()).await
                },
                async {
                    let (stream, _) = listener.accept().await.unwrap();
                    Session::accept_mixed(stream, responder, |_| false, allowed).await
                },
            )
        };
        let client = client.unwrap();
        let server = server.unwrap();
        assert!(client.pairing() && server.pairing());
        assert_eq!(client.binding(), server.binding());
        assert_eq!(client.bluetooth(), bluetooth);
        assert_eq!(server.bluetooth(), bluetooth);
        (client, server)
    }

    async fn wait_for(pairings: &Pairings, id: Uuid, status: Status) -> PairingView {
        timeout(Duration::from_secs(10), async {
            loop {
                if let Some(view) = pairings
                    .list()
                    .unwrap()
                    .into_iter()
                    .find(|view| view.id == id)
                {
                    if view.status == status {
                        return view;
                    }
                    assert!(
                        !view.status.terminal(),
                        "unexpected terminal state {:?}",
                        view.status
                    );
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("expected pairing state")
    }

    #[tokio::test]
    async fn authenticated_platform_profiles_pair_over_lan_and_ble_after_two_confirmations() {
        // Real keys and encrypted sessions. The platform profiles and BLE radio
        // packet stream are fixtures, so this test does not certify hardware.
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        for (source, target, bluetooth, requested) in [
            ("android", "android", true, vec![PeerCapability::Mesh]),
            ("android", "windows", true, vec![PeerCapability::Xfer]),
            ("android", "macos", false, vec![PeerCapability::Mesh, PeerCapability::Xfer]),
            ("android", "linux", false, vec![PeerCapability::Xfer]),
            ("windows", "linux", false, vec![PeerCapability::Mesh, PeerCapability::Xfer]),
        ] {
            let (mut client, mut server) = open_pairing(&alice, &bob, bluetooth).await;
            let outgoing = Pairings::default();
            let incoming = Pairings::default();
            let id = outgoing
                .start_outgoing(bob.fingerprint(), requested.clone())
                .unwrap();
            let client_trust = RefCell::new(TrustBook::default());
            let server_trust = RefCell::new(TrustBook::default());
            let (client_result, server_result, ()) = tokio::join!(
                initiate(
                    &mut client,
                    &outgoing,
                    id,
                    device(source),
                    Some("Alice".into()),
                    requested.clone(),
                    || {},
                    || Ok(()),
                    |id, peer| {
                        outgoing.ensure_committing(id, &peer.fingerprint)?;
                        client_trust.borrow_mut().trust_paired(
                            &peer.fingerprint,
                            peer.metadata,
                            &peer.public_key,
                            None,
                            &peer.granted,
                            peer.owner,
                        )
                    }
                ),
                respond(
                    &mut server,
                    &incoming,
                    device(target),
                    None,
                    || {},
                    || Ok(()),
                    |id, peer| {
                        incoming.ensure_committing(id, &peer.fingerprint)?;
                        server_trust.borrow_mut().trust_paired(
                            &peer.fingerprint,
                            peer.metadata,
                            &peer.public_key,
                            None,
                            &peer.granted,
                            peer.owner,
                        )
                    },
                    || None,
                ),
                async {
                    let offer = wait_for(&incoming, id, Status::AwaitingApproval).await;
                    assert_eq!(offer.peer, alice.fingerprint());
                    assert_eq!(offer.platform.as_deref(), Some(source));
                    assert!(offer.code.is_none());
                    assert!(outgoing.decide(id, PairingDecision::Confirm).is_err());
                    assert!(incoming.decide(id, PairingDecision::Confirm).is_err());
                    incoming.decide(id, PairingDecision::Allow).unwrap();
                    let receiver = wait_for(&incoming, id, Status::Verifying).await;
                    let sender = wait_for(&outgoing, id, Status::Verifying).await;
                    assert_eq!(sender.platform.as_deref(), Some(target));
                    assert_eq!(sender.code, receiver.code);
                    assert_eq!(sender.code.as_deref().unwrap().len(), 19);
                    outgoing.decide(id, PairingDecision::Confirm).unwrap();
                    assert!(client_trust.borrow().peers.is_empty());
                    assert!(server_trust.borrow().peers.is_empty());
                    incoming.decide(id, PairingDecision::Confirm).unwrap();
                },
            );
            client_result.unwrap();
            server_result.unwrap();
            assert_eq!(outgoing.status(id).unwrap(), Status::Trusted);
            assert_eq!(incoming.status(id).unwrap(), Status::Trusted);
            let client_book = client_trust.into_inner();
            let server_book = server_trust.into_inner();
            assert_eq!(
                client_book.peers[bob.fingerprint()]
                    .paired
                    .as_ref()
                    .unwrap()
                    .platform,
                target
            );
            assert_eq!(
                server_book.peers[alice.fingerprint()]
                    .paired
                    .as_ref()
                    .unwrap()
                    .platform,
                source
            );
            // Both devices advertise Mesh and XFER, but each side stores only
            // the capabilities the two users approved for this request.
            for (book, peer) in [(&client_book, bob.fingerprint()), (&server_book, alice.fingerprint())] {
                let granted = &book.peers[peer].paired.as_ref().unwrap().capabilities;
                assert_eq!(granted, &requested);
                for capability in [PeerCapability::Mesh, PeerCapability::Xfer] {
                    assert_eq!(book.allows(peer, capability), requested.contains(&capability));
                }
            }
            // Owner names cross only after both confirmations and only if set.
            assert_eq!(server_book.peers[alice.fingerprint()].owner.as_deref(), Some("Alice"));
            assert!(client_book.peers[bob.fingerprint()].owner.is_none());
        }
    }

    #[tokio::test]
    async fn rejected_requests_and_mismatched_codes_never_persist_trust() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        for mismatch in [false, true] {
            let (mut client, mut server) = open_pairing(&alice, &bob, false).await;
            let outgoing = Pairings::default();
            let incoming = Pairings::default();
            let requested = vec![PeerCapability::Xfer];
            let id = outgoing
                .start_outgoing(bob.fingerprint(), requested.clone())
                .unwrap();
            let (client_result, server_result, ()) = tokio::join!(
                initiate(
                    &mut client,
                    &outgoing,
                    id,
                    device("android"),
                    Some("Alice".into()),
                    requested,
                    || {},
                    || Ok(()),
                    |_, _| panic!("unexpected initiator trust write")
                ),
                respond(
                    &mut server,
                    &incoming,
                    device("windows"),
                    Some("Bob".into()),
                    || {},
                    || Ok(()),
                    |_, _| panic!("unexpected receiver trust write"),
                    || None,
                ),
                async {
                    wait_for(&incoming, id, Status::AwaitingApproval).await;
                    if mismatch {
                        incoming.decide(id, PairingDecision::Allow).unwrap();
                        wait_for(&outgoing, id, Status::Verifying).await;
                        incoming.decide(id, PairingDecision::Confirm).unwrap();
                        outgoing.decide(id, PairingDecision::Cancel).unwrap();
                    } else {
                        incoming.decide(id, PairingDecision::Reject).unwrap();
                    }
                },
            );
            client_result.unwrap();
            server_result.unwrap();
            let expected = if mismatch {
                Status::Cancelled
            } else {
                Status::Rejected
            };
            assert_eq!(outgoing.status(id).unwrap(), expected);
            assert_eq!(incoming.status(id).unwrap(), expected);
            assert!(outgoing.list().unwrap()[0].code.is_none());
            assert!(incoming.list().unwrap()[0].code.is_none());
        }
    }

    #[tokio::test]
    async fn invalid_reveal_and_interrupted_exchange_do_not_show_or_save_trust() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        for invalid_reveal in [true, false] {
            let (mut client, mut server) = open_pairing(&alice, &bob, false).await;
            let incoming = Pairings::default();
            let id = Uuid::new_v4();
            let nonce = [1; 32];
            let commitment = nonce_commitment(client.binding(), id, &nonce);
            let ((), result) = tokio::join!(
                async move {
                    send(
                        &mut client,
                        Frame::Request {
                            version: VERSION,
                            id,
                            device: device("android"),
                            requested: vec![PeerCapability::Mesh],
                            commitment,
                        },
                    )
                    .await
                    .unwrap();
                    assert!(matches!(
                        receive(&mut client).await.unwrap(),
                        Frame::Answer { .. }
                    ));
                    if invalid_reveal {
                        send(&mut client, Frame::Reveal { nonce: [2; 32] })
                            .await
                            .unwrap();
                    }
                    // Dropping the stream after Answer aborts before the UI may
                    // display an incoming request or persist any identity.
                },
                respond(
                    &mut server,
                    &incoming,
                    device("windows"),
                    Some("Bob".into()),
                    || {},
                    || Ok(()),
                    |_, _| panic!("unexpected trust write"),
                    || None,
                ),
            );
            assert!(result.is_err());
            assert!(incoming.list().unwrap().is_empty());
            assert_eq!(incoming.status(id).unwrap(), Status::Failed);
        }
    }

    #[tokio::test]
    async fn earlier_protocol_versions_are_rejected_before_any_prompt() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (mut client, mut server) = open_pairing(&alice, &bob, false).await;
        let incoming = Pairings::default();
        let id = Uuid::new_v4();
        let commitment = nonce_commitment(client.binding(), id, &[1; 32]);
        let (sent, result) = tokio::join!(
            send(
                &mut client,
                Frame::Request {
                    version: 1,
                    id,
                    device: device("android"),
                    requested: vec![PeerCapability::Mesh, PeerCapability::Xfer],
                    commitment,
                },
            ),
            respond(
                &mut server,
                &incoming,
                device("windows"),
                None,
                || {},
                || Ok(()),
                |_, _| panic!("unexpected trust write"),
                || None,
            ),
        );
        sent.unwrap();
        assert!(result.is_err());
        assert!(incoming.list().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_nearby_picture_request_returns_only_what_the_owner_shares_and_never_starts_pairing() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (mut client, mut server) = open_pairing(&alice, &bob, false).await;
        let incoming = Pairings::default();
        let (picture, served) = tokio::join!(
            request_picture(&mut client),
            respond(
                &mut server,
                &incoming,
                device("windows"),
                None,
                || {},
                || Ok(()),
                |_, _| panic!("a picture request must not write trust"),
                || Some(("ab".repeat(32), "/9j/4AAQ".into())),
            ),
        );
        served.unwrap();
        assert_eq!(picture.unwrap(), Some(("ab".repeat(32), "/9j/4AAQ".into())));
        assert!(incoming.list().unwrap().is_empty());

        // An owner who did not opt in answers with nothing.
        let (mut client, mut server) = open_pairing(&alice, &bob, false).await;
        let (picture, served) = tokio::join!(
            request_picture(&mut client),
            respond(&mut server, &incoming, device("windows"), None, || {}, || Ok(()),
                |_, _| panic!("a picture request must not write trust"), || None),
        );
        served.unwrap();
        assert_eq!(picture.unwrap(), None);
    }

    #[test]
    fn simultaneous_duplicate_expired_and_revoked_requests_fail_closed() {
        let left = Pairings::default();
        let right = Pairings::default();
        let left_id = left
            .start_outgoing("b", vec![PeerCapability::Mesh])
            .unwrap();
        let right_id = right
            .start_outgoing("a", vec![PeerCapability::Mesh])
            .unwrap();
        assert!(left
            .start_outgoing("b", vec![PeerCapability::Xfer])
            .is_err());
        let right_offer = Attempt::new(right_id, "b", Direction::Incoming, APPROVAL_TIMEOUT);
        let left_offer = || Attempt::new(left_id, "a", Direction::Incoming, APPROVAL_TIMEOUT);
        assert!(left
            .start_incoming("a", "b", right_id, right_offer)
            .is_err());
        right
            .start_incoming("b", "a", left_id, left_offer())
            .unwrap();
        assert_eq!(right.status(right_id).unwrap(), Status::Cancelled);
        assert!(right
            .start_incoming("b", "a", left_id, left_offer())
            .is_err());
        assert!(right.list().unwrap().is_empty());
        right
            .change(left_id, |attempt| {
                attempt.expires = Instant::now();
                Ok(())
            })
            .unwrap();
        assert_eq!(right.status(left_id).unwrap(), Status::Expired);
        assert!(right.decide(left_id, PairingDecision::Allow).is_err());
        assert!(left
            .update(left_id, Status::Requesting, Status::Establishing)
            .unwrap());
        left.ensure_committing(left_id, "b").unwrap();
        assert!(left.ensure_committing(left_id, "substitute").is_err());
        left.cancel_peer("b");
        assert!(!left.has_pending());
        assert!(left.ensure_committing(left_id, "b").is_err());
    }

    #[test]
    fn verification_code_binds_capabilities_roles_nonce_session_and_request() {
        let alice = device("android");
        let bob = device("windows");
        let id = Uuid::new_v4();
        let nonces = [[1; 32], [2; 32]];
        let binding = [4; 32];
        let mesh = [PeerCapability::Mesh];
        let xfer = [PeerCapability::Xfer];
        let code = verification_code(&binding, id, &mesh, &alice, &bob, &nonces).unwrap();
        for changed in [
            verification_code(&binding, id, &xfer, &alice, &bob, &nonces),
            verification_code(&binding, id, &mesh, &bob, &alice, &nonces),
            verification_code(&binding, id, &mesh, &alice, &bob, &[[3; 32], [2; 32]]),
            verification_code(&[5; 32], id, &mesh, &alice, &bob, &nonces),
            verification_code(&binding, Uuid::nil(), &mesh, &alice, &bob, &nonces),
        ] {
            assert_ne!(code, changed.unwrap());
        }
    }

    #[tokio::test]
    async fn pairing_permission_does_not_open_an_application_session() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (client, server) = tokio::io::duplex(32 * 1024);
        let (client, server) = tokio::join!(
            Session::connect_ble(client, &alice, bob.fingerprint()),
            Session::accept_mixed_ble(server, &bob, |_| false, |_| true),
        );
        assert!(client.is_err());
        assert!(matches!(server, Err(QGuardError::Trust(_))));
    }

    #[tokio::test]
    async fn pairing_handshake_rejects_an_identity_substituted_after_discovery() {
        let alice = Identity::generate().unwrap();
        let discovered = Identity::generate().unwrap();
        let substitute = Identity::generate().unwrap();
        let (client, server) = tokio::io::duplex(32 * 1024);
        let (client, server) = tokio::join!(
            Session::connect_pairing_ble(client, &alice, discovered.fingerprint()),
            Session::accept_mixed_ble(server, &substitute, |_| false, |_| true),
        );
        assert!(matches!(client, Err(QGuardError::Trust(_))));
        assert!(server.is_err());
    }
}
