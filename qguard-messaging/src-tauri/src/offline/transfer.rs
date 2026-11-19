use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::Serialize;
use tauri::{AppHandle, Manager};
use tokio::sync::{watch, Semaphore};
use uuid::Uuid;

use crate::{
    crypto::provider,
    error::{QGuardError, Result},
    state::AppState,
};

use super::{
    alerts, channel, commands,
    link::{self, OfferState},
    network::{changed, lock, Network, Runtime},
    profile::{local_owner, xfer_key, PeerCapability, TrustBook},
    session::{self, Session, TransferSuite, TRANSFER_SUITE_V1},
    wire::{self, Control},
    xfer::{
        ControlIntent, Direction, Manifest, Record, Status, Store, TransferAction, TransferFailure,
    },
    xfer_open,
};

const CHECK_INTERVAL: Duration = Duration::from_secs(2);
const MAX_CHECK_TIME: Duration = Duration::from_secs(30 * 60);
const RATE_SAMPLE_INTERVAL: Duration = Duration::from_millis(250);
const RATE_LIFETIME: Duration = Duration::from_secs(3);
const MAX_RATE_LIFETIME: Duration = Duration::from_secs(15);
const STALL_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const GRAPH_WINDOW_MS: i64 = 60_000;
const MAX_GRAPH_SAMPLES: usize = 256;

type ThroughputHistory = Arc<Mutex<VecDeque<(Uuid, ThroughputSample)>>>;
const MAX_ACTIVE_TRANSFERS: usize = 2;
const MAX_CONTROLS_PER_SYNC: usize = 4;
const CONTROL_BACKOFF: Duration = Duration::from_secs(8);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(25);
const RECENT_COMPLETION_MS: i64 = 120_000;

pub(super) struct ActiveTransfers {
    runs: Mutex<HashMap<Uuid, Arc<Progress>>>,
    requesting: Mutex<HashSet<Uuid>>,
    history: ThroughputHistory,
    control_worker: Semaphore,
    control_attempts: Mutex<HashMap<Uuid, ControlAttempt>>,
}

struct ControlAttempt {
    revision: u64,
    tries: u32,
    next_try: Instant,
}

impl Default for ActiveTransfers {
    fn default() -> Self {
        Self {
            runs: Mutex::default(),
            requesting: Mutex::default(),
            history: Arc::default(),
            control_worker: Semaphore::new(1),
            control_attempts: Mutex::default(),
        }
    }
}

struct Progress {
    sample: watch::Sender<RateSample>,
    stop: watch::Sender<bool>,
    stage: Mutex<(SecurityPhase, Option<u32>)>,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum SecurityPhase {
    Initializing,
    KeyEstablishment,
    PayloadEncryption,
    SecureTransfer,
    IntegrityVerification,
    Verified,
    Error,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThroughputSample {
    at_ms: i64,
    bytes_per_second: u64,
}

struct RunMetrics {
    bytes_per_second: Option<u64>,
    phase: SecurityPhase,
    current_file: Option<u32>,
}

#[derive(Clone, Copy)]
struct RateSample {
    bytes: u64,
    at: Instant,
    bytes_per_second: Option<u64>,
    checkpoint_reported: bool,
    /// Measurement window that produced `bytes_per_second`.
    window: Duration,
}

impl RateSample {
    fn baseline(bytes: u64) -> Self {
        Self {
            bytes,
            at: Instant::now(),
            bytes_per_second: None,
            checkpoint_reported: false,
            window: Duration::ZERO,
        }
    }

    /// A measured rate stays current for two measurement windows. A slow link
    /// confirms each 4 MiB checkpoint less often than a fast one.
    fn lifetime(&self) -> Duration {
        (self.window * 2).clamp(RATE_LIFETIME, MAX_RATE_LIFETIME)
    }
}

fn record_sample(history: &Mutex<VecDeque<(Uuid, ThroughputSample)>>, id: Uuid, bytes_per_second: u64) {
    if let Ok(mut history) = history.lock() {
        while history.len() >= MAX_GRAPH_SAMPLES {
            history.pop_front();
        }
        history.push_back((
            id,
            ThroughputSample {
                at_ms: now_ms(),
                bytes_per_second,
            },
        ));
    }
}

pub(super) struct Run<'a> {
    parent: &'a ActiveTransfers,
    app: &'a AppHandle,
    id: Uuid,
    progress: Arc<Progress>,
    rate_expiry: tokio::task::JoinHandle<()>,
}

struct RequestSlot<'a>(&'a Mutex<HashSet<Uuid>>, Uuid);

impl Drop for RequestSlot<'_> {
    fn drop(&mut self) {
        if let Ok(mut requests) = self.0.lock() {
            requests.remove(&self.1);
        }
    }
}

impl Drop for Run<'_> {
    fn drop(&mut self) {
        self.rate_expiry.abort();
        if let Ok(mut active) = self.parent.runs.lock() {
            active.remove(&self.id);
        }
        changed(self.app);
    }
}

impl ActiveTransfers {
    pub(super) fn is_active(&self) -> bool {
        self.runs.lock().map_or(true, |active| !active.is_empty())
    }

    pub(super) fn has_run(&self, id: Uuid) -> Result<bool> {
        Ok(lock(&self.runs)?.contains_key(&id))
    }

    pub(super) fn has_capacity(&self) -> bool {
        self.runs
            .lock()
            .is_ok_and(|runs| runs.len() < MAX_ACTIVE_TRANSFERS)
    }

    fn request_slot(&self, id: Uuid) -> Result<RequestSlot<'_>> {
        let mut requests = lock(&self.requesting)?;
        if requests.len() >= MAX_ACTIVE_TRANSFERS || !requests.insert(id) {
            return Err(QGuardError::Trust(
                "This transfer already has a request in progress, or the request slots are busy."
                    .into(),
            ));
        }
        Ok(RequestSlot(&self.requesting, id))
    }

    fn begin<'a>(&'a self, app: &'a AppHandle, id: Uuid) -> Result<Run<'a>> {
        let mut active = lock(&self.runs)?;
        if active.contains_key(&id) {
            return Err(QGuardError::Trust(
                "This local transfer is already running.".into(),
            ));
        }
        if active.len() >= MAX_ACTIVE_TRANSFERS {
            return Err(QGuardError::Trust(
                "Both local transfer slots are busy. Resume this transfer when a slot opens."
                    .into(),
            ));
        }
        let progress = Arc::new(Progress {
            sample: watch::channel(RateSample::baseline(0)).0,
            stop: watch::channel(false).0,
            stage: Mutex::new((SecurityPhase::Initializing, None)),
        });
        active.insert(id, Arc::clone(&progress));
        drop(active);
        changed(app);
        Ok(Run {
            parent: self,
            app,
            id,
            rate_expiry: tokio::spawn(watch_rate(
                app.clone(),
                id,
                Arc::clone(&self.history),
                Arc::clone(&progress),
            )),
            progress,
        })
    }

    pub(super) fn stop(&self, id: Uuid) -> Result<()> {
        if let Some(progress) = lock(&self.runs)?.get(&id) {
            progress.stop.send_replace(true);
        }
        Ok(())
    }

    fn metrics(&self, id: Uuid) -> Option<RunMetrics> {
        let active = lock(&self.runs).ok()?;
        let progress = active.get(&id)?;
        let sample = *progress.sample.borrow();
        let (phase, current_file) = *lock(&progress.stage).ok()?;
        let moving = !*progress.stop.borrow() && phase == SecurityPhase::SecureTransfer;
        let bytes_per_second = match sample.bytes_per_second {
            Some(rate) if moving && sample.at.elapsed() < sample.lifetime() => Some(rate),
            // No checkpoint arrived for two measurement windows: the measured
            // current throughput is zero until the next verified chunk.
            Some(_) if moving => Some(0),
            _ => None,
        };
        Some(RunMetrics {
            bytes_per_second,
            phase,
            current_file,
        })
    }

    fn throughput(&self, id: Uuid, now: i64) -> Vec<ThroughputSample> {
        self.history.lock().map_or_else(
            |_| Vec::new(),
            |history| {
                history
                    .iter()
                    .filter_map(|(transfer, sample)| {
                        (*transfer == id && now.saturating_sub(sample.at_ms) <= GRAPH_WINDOW_MS)
                            .then_some(*sample)
                    })
                    .collect()
            },
        )
    }

    fn control_due(&self, id: Uuid, revision: u64) -> bool {
        let Ok(mut attempts) = self.control_attempts.lock() else {
            return false;
        };
        let now = Instant::now();
        let attempt = attempts.entry(id).or_insert(ControlAttempt {
            revision,
            tries: 0,
            next_try: now,
        });
        if attempt.revision != revision {
            *attempt = ControlAttempt {
                revision,
                tries: 0,
                next_try: now,
            };
        }
        if attempt.next_try > now {
            return false;
        }
        attempt.next_try = now + CONTROL_BACKOFF * (1 << attempt.tries.min(4));
        attempt.tries = attempt.tries.saturating_add(1);
        true
    }
}

// One task follows the latest sample for the lifetime of a run. When no
// verified checkpoint arrives for two measurement windows while payload is
// moving, it records measured zero throughput once per second so the graph
// shows the stall. Pauses and interruptions end the run, which leaves a gap.
async fn watch_rate(app: AppHandle, id: Uuid, history: ThroughputHistory, progress: Arc<Progress>) {
    let mut samples = progress.sample.subscribe();
    let moving = || {
        !*progress.stop.borrow()
            && progress
                .stage
                .lock()
                .is_ok_and(|stage| stage.0 == SecurityPhase::SecureTransfer)
    };
    loop {
        let sample = *samples.borrow_and_update();
        if sample.bytes_per_second.is_some() {
            tokio::select! {
                update = samples.changed() => {
                    if update.is_err() {
                        return;
                    }
                    continue;
                }
                _ = tokio::time::sleep_until((sample.at + sample.lifetime()).into()) => {}
            }
            loop {
                if moving() {
                    record_sample(&history, id, 0);
                }
                changed(&app);
                tokio::select! {
                    update = samples.changed() => {
                        if update.is_err() {
                            return;
                        }
                        break;
                    }
                    _ = tokio::time::sleep(STALL_SAMPLE_INTERVAL) => {}
                }
            }
            continue;
        }
        if samples.changed().await.is_err() {
            return;
        }
    }
}

impl Run<'_> {
    fn stage(&self, phase: SecurityPhase, current_file: Option<u32>) {
        if let Ok(mut stage) = self.progress.stage.lock() {
            if *stage != (phase, current_file) {
                *stage = (phase, current_file);
                drop(stage);
                changed(self.app);
            }
        }
    }

    fn baseline(&self, bytes: u64) {
        self.progress
            .sample
            .send_replace(RateSample::baseline(bytes));
        changed(self.app);
    }

    fn verified(&self, bytes: u64, total: u64) {
        let mut measured_rate = None;
        if self.progress.sample.send_if_modified(|sample| {
            let now = Instant::now();
            let elapsed = now.duration_since(sample.at);
            if bytes >= total || elapsed >= RATE_SAMPLE_INTERVAL {
                let rate = if elapsed >= RATE_SAMPLE_INTERVAL {
                    let measured =
                        (bytes.saturating_sub(sample.bytes) as f64 / elapsed.as_secs_f64()) as u64;
                    (measured > 0).then_some(measured)
                } else {
                    None
                };
                measured_rate = rate;
                *sample = RateSample {
                    bytes,
                    at: now,
                    bytes_per_second: rate,
                    checkpoint_reported: true,
                    window: elapsed,
                };
                true
            } else if !sample.checkpoint_reported {
                // Publish the first durable chunk even before a rate can be measured.
                sample.checkpoint_reported = true;
                true
            } else {
                false
            }
        }) {
            if let Some(rate) = measured_rate {
                record_sample(&self.parent.history, self.id, rate);
            }
            changed(self.app);
        }
    }

    async fn stopped(&self) {
        let mut stop = self.progress.stop.subscribe();
        let _ = stop.wait_for(|stopped| *stopped).await;
    }
}

pub(super) fn with_store<T>(
    app: &AppHandle,
    owner: &str,
    action: impl FnOnce(&Store) -> anyhow::Result<T>,
) -> Result<T> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let mut recovered = lock(&runtime.transfers)?;
    if local_owner(&state)? != owner {
        return Err(QGuardError::Trust("The local account changed.".into()));
    }
    let key = xfer_key(&state, owner)?;
    let storage_id = hex::encode(provider::sha3_256(key.as_ref()));
    let root = state
        .data_dir
        .join("offline-xfer")
        .join(AppState::safe_user_key(owner))
        .join(&storage_id);
    let store = Store::open(root, *key)?;
    if !recovered
        .as_ref()
        .is_some_and(|(account, id)| account == owner && id == &storage_id)
    {
        store.recover_interrupted()?;
        *recovered = Some((owner.to_string(), storage_id));
    }
    action(&store).map_err(Into::into)
}

pub(super) async fn store_task<T: Send + 'static>(
    app: &AppHandle,
    owner: &str,
    action: impl FnOnce(&Store) -> anyhow::Result<T> + Send + 'static,
) -> Result<T> {
    let app = app.clone();
    let owner = owner.to_string();
    tokio::task::spawn_blocking(move || with_store(&app, &owner, action))
        .await
        .map_err(|_| task_error())?
}

async fn authenticated_store_task<T: Send + 'static>(
    app: &AppHandle,
    network: &Network,
    peer: String,
    action: impl FnOnce(&Store, &Network) -> anyhow::Result<T> + Send + 'static,
) -> Result<T> {
    let active = {
        let runtime = app.state::<Runtime>();
        let current = lock(&runtime.network)?;
        current
            .as_ref()
            .filter(|current| std::ptr::eq(current.as_ref(), network))
            .cloned()
            .ok_or_else(|| {
                QGuardError::Trust("The current local networking session has ended.".into())
            })?
    };
    let app = app.clone();
    tokio::task::spawn_blocking(move || {
        let runtime = app.state::<Runtime>();
        // Serialize the authorization and the control mutation with revocation.
        let _gate = lock(&runtime.storage)?;
        active.require_peer_locked(&app, &peer, false)?;
        with_store(&app, &active.owner, |store| action(store, &active))
    })
    .await
    .map_err(|_| task_error())?
}

fn counterpart<'a>(record: &'a Record, local: &str) -> Option<&'a str> {
    let manifest = &record.manifest;
    match record.direction {
        Direction::Incoming if manifest.recipient == local => Some(&manifest.sender),
        Direction::Outgoing if manifest.sender == local => Some(&manifest.recipient),
        _ => None,
    }
}

pub(super) async fn receive_state(
    app: &AppHandle,
    network: &Network,
    session: &mut Session,
    id: Uuid,
    revision: u64,
    action: TransferAction,
) -> Result<()> {
    if session.bluetooth() || session.pairing() || revision == 0 {
        return Err(wire::protocol_error());
    }
    let peer = session.peer().to_string();
    let remote = peer.clone();
    let (completed, updated) =
        authenticated_store_task(app, network, peer, move |store, active| {
            let before = store.get(id)?;
            anyhow::ensure!(
                counterpart(&before, &active.fingerprint) == Some(remote.as_str()),
                "The transfer is outside the authenticated peer's authorization."
            );
            let after = store.apply_remote_control(id, revision, action)?;
            if matches!(
                after.status,
                Status::Paused | Status::Stopped | Status::Cancelled
            ) {
                // Stop only after applying the durable state. A delayed hold after
                // Resume must not interrupt a new run.
                active.transfers.stop(id)?;
            }
            Ok((
                after.direction == Direction::Incoming && after.status == Status::Verified,
                after.revision != before.revision,
            ))
        })
        .await?;
    if updated {
        changed(app);
    }
    wire::send(
        session,
        &Control::TransferStateAck {
            id,
            revision,
            completed,
        },
    )
    .await
}

pub(super) async fn sync_controls(app: &AppHandle, network: &Network) {
    let Ok(_worker) = network.transfers.control_worker.try_acquire() else {
        return;
    };
    if network.check(app).is_err() {
        return;
    }
    let Ok(records) = store_task(app, &network.owner, |store| store.list()).await else {
        return;
    };
    let now = chrono::Utc::now().timestamp();
    let pending: Vec<_> = records
        .iter()
        .filter(|record| record.manifest.expires_at > now)
        .filter_map(|record| {
            Some((
                record.manifest.id,
                record.pending_control?,
                counterpart(record, &network.fingerprint)?,
            ))
        })
        .collect();
    if let Ok(mut attempts) = network.transfers.control_attempts.lock() {
        attempts.retain(|id, _| pending.iter().any(|(record_id, _, _)| record_id == id));
    }
    if pending.is_empty() {
        return;
    }
    let Ok(book) = TrustBook::load(&app.state::<AppState>(), &network.owner) else {
        return;
    };
    let mut dispatched = 0;
    for (id, intent, peer) in pending {
        let Some(trusted) = book.peers.get(peer) else {
            continue;
        };
        if network
            .endpoints(peer, trusted.address)
            .map_or(true, |paths| paths.is_empty())
        {
            continue;
        }
        let Ok(_outbound) = network.outbound.try_acquire() else {
            break;
        };
        if !network.transfers.control_due(id, intent.revision) {
            continue;
        }
        let response = tokio::select! {
            _ = network.until_stopped() => break,
            response = tokio::time::timeout(CONTROL_TIMEOUT, send_control(app, network, peer, id, intent)) => response,
        };
        if let Ok(Ok(completed)) = response {
            let remote = peer.to_string();
            let result =
                authenticated_store_task(app, network, remote.clone(), move |store, active| {
                    let record = store.get(id)?;
                    anyhow::ensure!(
                        counterpart(&record, &active.fingerprint) == Some(remote.as_str()),
                        "The transfer is outside the authenticated peer's authorization."
                    );
                    if completed && record.direction == Direction::Outgoing {
                        // Only the receiver has authority to confirm integrity.
                        Ok(Some(store.mark_verified(id)?))
                    } else {
                        store.ack_control(id, intent.revision)?;
                        Ok(None)
                    }
                })
                .await;
            if let Ok(verified) = result {
                if let Some(record) = verified {
                    alerts::completed(app, &network.owner, &record);
                }
                changed(app);
            }
        }
        dispatched += 1;
        if dispatched == MAX_CONTROLS_PER_SYNC {
            break;
        }
    }
}

async fn send_control(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    id: Uuid,
    intent: ControlIntent,
) -> Result<bool> {
    let mut connection = commands::connect(app, network, peer).await?;
    wire::send(
        &mut connection,
        &Control::TransferState {
            id,
            revision: intent.revision,
            action: intent.action,
        },
    )
    .await?;
    match wire::recv(&mut connection).await {
        Ok(Control::TransferStateAck {
            id: reply_id,
            revision,
            completed,
        }) if reply_id == id && revision == intent.revision => Ok(completed),
        Err(error) if intent.action == TransferAction::Cancel && connection_lost(&error) => {
            // Older peers close the connection on an unknown frame. Cancellation
            // can fall back to the original protocol on a fresh authenticated session.
            drop(connection);
            let mut legacy = commands::connect(app, network, peer).await?;
            wire::send(&mut legacy, &Control::Cancel { id }).await?;
            match wire::recv(&mut legacy).await? {
                Control::Cancelled => Ok(false),
                _ => Err(wire::protocol_error()),
            }
        }
        Err(error) => Err(error),
        _ => Err(wire::protocol_error()),
    }
}

async fn check_store<T: Send + 'static>(
    app: &AppHandle,
    network: &Network,
    session: &mut Session,
    id: Uuid,
    action: impl FnOnce(&Store) -> anyhow::Result<T> + Send + 'static,
) -> Result<T> {
    let work = store_task(app, &network.owner, action);
    tokio::pin!(work);
    let mut ticks =
        tokio::time::interval_at(tokio::time::Instant::now() + CHECK_INTERVAL, CHECK_INTERVAL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = &mut work => return result,
            _ = ticks.tick() => {
                network.wait_for_account(app).await?;
                network.require_peer(app, session.peer())?;
                wire::send(session, &Control::Checking { id }).await?;
            }
        }
    }
}

async fn await_checked(session: &mut Session, id: Uuid) -> Result<Control> {
    tokio::time::timeout(MAX_CHECK_TIME, async {
        loop {
            match wire::recv(session).await? {
                Control::Checking { id: checking } if checking == id => {}
                result => return Ok(result),
            }
        }
    })
    .await
    .map_err(|_| QGuardError::Storage("The peer timed out while verifying the transfer.".into()))?
}

fn task_error() -> QGuardError {
    QGuardError::Storage("The local transfer operation ended unexpectedly.".into())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FileSummary {
    name: String,
    size: u64,
    /// SHA3-256 digest from the authenticated manifest (lowercase hex).
    digest: String,
    destination: Option<String>,
    verified_bytes: u64,
    payload_complete: bool,
    verified: bool,
    can_open_file: bool,
    can_open_folder: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecuritySummary {
    phase: SecurityPhase,
    mode: Option<&'static str>,
    key_establishment: Option<&'static str>,
    signatures: Option<&'static str>,
    encryption: Option<&'static str>,
    integrity: Option<&'static str>,
}

impl SecuritySummary {
    fn new(phase: SecurityPhase, suite: Option<TransferSuite>) -> Self {
        Self {
            phase,
            mode: suite.map(|suite| suite.mode),
            key_establishment: suite.map(|suite| suite.key_establishment),
            signatures: suite.map(|suite| suite.signatures),
            encryption: suite.map(|suite| suite.encryption),
            integrity: suite.map(|suite| suite.integrity),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransferSummary {
    id: Uuid,
    direction: Direction,
    sender: String,
    recipient: String,
    files: Vec<FileSummary>,
    folder_name: Option<String>,
    status: &'static str,
    verified_bytes: u64,
    verified_files: u32,
    total_bytes: u64,
    created_at: i64,
    expires_at: i64,
    updated_at: i64,
    revision: u64,
    started_at_ms: Option<i64>,
    completed_at_ms: Option<i64>,
    elapsed_ms: Option<u64>,
    local_copy_retained: bool,
    bytes_per_second: Option<u64>,
    average_bytes_per_second: Option<u64>,
    throughput: Vec<ThroughputSample>,
    current_file: Option<u32>,
    security: SecuritySummary,
    /// Shared authenticated session ID; identical on both devices.
    session_id: Option<String>,
    local_hold: Option<TransferAction>,
    remote_hold: Option<TransferAction>,
    control_sync_pending: bool,
    error: Option<&'static str>,
    error_kind: Option<TransferFailure>,
    /// Sender only: the receiver's answer to an offer sent over the
    /// Bluetooth channel because no local network reached it.
    channel_offer: Option<OfferState>,
}

fn view_status(record: &Record, running: bool) -> &'static str {
    match record.status {
        Status::AwaitingConsent => "awaitingConsent",
        Status::Ready => "queued",
        Status::Transferring if running => "active",
        Status::Transferring | Status::Interrupted => "interrupted",
        Status::Paused => "paused",
        Status::Stopped => "stopped",
        Status::Verified => "verified",
        Status::Rejected => "rejected",
        Status::Cancelled => "cancelled",
        Status::Expired => "expired",
        Status::Failed => "failed",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransferMonitorEntry {
    id: Uuid,
    direction: Direction,
    status: &'static str,
    created_at: i64,
    started_at_ms: Option<i64>,
    completed_at_ms: Option<i64>,
}

pub(super) fn monitor_entry(
    record: &Record,
    network: Option<&Network>,
) -> Option<TransferMonitorEntry> {
    let running = network.is_some_and(|network| {
        network
            .transfers
            .has_run(record.manifest.id)
            .unwrap_or(false)
    });
    let status = view_status(record, running);
    let recent = record
        .completed_at_ms
        .is_some_and(|at| now_ms().saturating_sub(at) <= RECENT_COMPLETION_MS);
    if status != "active"
        && !(status == "awaitingConsent" && record.direction == Direction::Incoming)
        && !(status == "verified" && recent)
    {
        return None;
    }
    Some(TransferMonitorEntry {
        id: record.manifest.id,
        direction: record.direction,
        status,
        created_at: record.manifest.created_at,
        started_at_ms: record.started_at_ms,
        completed_at_ms: record.completed_at_ms,
    })
}

pub(super) fn summarize(record: Record, network: Option<&Network>) -> TransferSummary {
    let channel_offer = (record.direction == Direction::Outgoing)
        .then(|| network.and_then(|net| net.links.offer_state(record.manifest.id)))
        .flatten();
    let metrics = network.and_then(|net| net.transfers.metrics(record.manifest.id));
    let status = view_status(&record, metrics.is_some());
    let now = now_ms();
    let throughput = network.map_or_else(Vec::new, |net| {
        net.transfers.throughput(record.manifest.id, now)
    });
    let elapsed_ms = record.started_at_ms.map(|start| {
        let end = record.completed_at_ms.unwrap_or_else(|| {
            if matches!(
                record.status,
                Status::Cancelled | Status::Expired | Status::Failed | Status::Rejected
            ) {
                record.updated_at.saturating_mul(1_000)
            } else {
                now
            }
        });
        end.saturating_sub(start).max(0) as u64
    });
    let verified = record.status == Status::Verified;
    let phase = if verified {
        SecurityPhase::Verified
    } else if matches!(
        record.failure,
        Some(TransferFailure::Encryption | TransferFailure::Integrity)
    ) {
        SecurityPhase::Error
    } else {
        metrics
            .as_ref()
            .map_or(SecurityPhase::Initializing, |metrics| metrics.phase)
    };
    // A durable first-start stamp is only written after an authenticated
    // transfer starts. Legacy verified records also used the fixed v1 suite.
    let suite = (record.started_at_ms.is_some()
        || verified
        || metrics.as_ref().is_some_and(|metrics| {
            matches!(
                metrics.phase,
                SecurityPhase::PayloadEncryption
                    | SecurityPhase::SecureTransfer
                    | SecurityPhase::IntegrityVerification,
            )
        }))
    .then_some(TRANSFER_SUITE_V1);
    let folder_name = record.folder_name().map(str::to_owned);
    let session_id = record.session_id.clone();
    let files = record
        .manifest
        .files
        .iter()
        .enumerate()
        .map(|(index, file)| {
            let progress = record.file_progress.get(index);
            let (can_open_file, can_open_folder) = xfer_open::export_actions(&record, index);
            FileSummary {
                name: file.path.clone(),
                size: file.size,
                digest: file.digest.clone(),
                destination: record.destinations.get(index).cloned().flatten(),
                verified_bytes: progress.map_or(0, |progress| progress.completed_bytes),
                payload_complete: progress.is_some_and(|progress| progress.payload_complete),
                verified,
                can_open_file,
                can_open_folder,
            }
        })
        .collect();
    let manifest = record.manifest;
    let total_bytes = manifest.total_bytes();
    TransferSummary {
        id: manifest.id,
        direction: record.direction,
        sender: manifest.sender,
        recipient: manifest.recipient,
        total_bytes,
        files,
        folder_name,
        status,
        verified_bytes: record.completed_bytes,
        verified_files: record.verified_files,
        created_at: manifest.created_at,
        expires_at: manifest.expires_at,
        updated_at: record.updated_at,
        revision: record.revision,
        started_at_ms: record.started_at_ms,
        completed_at_ms: record.completed_at_ms,
        elapsed_ms,
        local_copy_retained: record.direction == Direction::Incoming
            && verified
            && manifest.expires_at > now / 1_000,
        bytes_per_second: if status == "active" {
            metrics
                .as_ref()
                .and_then(|metrics| metrics.bytes_per_second)
        } else {
            None
        },
        average_bytes_per_second: elapsed_ms
            .filter(|&ms| ms > 0 && record.completed_bytes > 0)
            .map(|ms| record.completed_bytes.saturating_mul(1_000) / ms),
        throughput,
        current_file: metrics.and_then(|metrics| metrics.current_file),
        security: SecuritySummary::new(phase, suite),
        session_id,
        local_hold: record.local_hold,
        remote_hold: record.remote_hold,
        control_sync_pending: record.pending_control.is_some(),
        error: record.failure.map(failure_message).or_else(|| {
            (status == "interrupted").then_some(failure_message(TransferFailure::Interrupted))
        }),
        error_kind: record.failure,
        channel_offer,
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn failure_message(failure: TransferFailure) -> &'static str {
    match failure {
        TransferFailure::ConnectionLost => "The local connection was lost. Reconnect and resume from the last verified checkpoint.",
        TransferFailure::PeerUnavailable => "The other device is unavailable. Keep both devices on the same local network and retry.",
        TransferFailure::StorageFull => "There is not enough protected storage to continue. Free space and resume.",
        TransferFailure::FileWrite => "Qguard could not save the received data. Check local storage before resuming.",
        TransferFailure::Encryption => "Qguard could not establish the encrypted transfer session.",
        TransferFailure::Integrity => "File integrity verification failed. Start a new transfer from the original files.",
        TransferFailure::Timeout => "The other device did not respond in time. Reconnect and resume.",
        TransferFailure::Interrupted => "The transfer was interrupted. Resume from the last verified checkpoint.",
    }
}

pub(super) async fn incoming(
    app: &AppHandle,
    network: &Network,
    session: &mut Session,
    manifest: Manifest,
) -> Result<()> {
    let peer = session.peer().to_string();
    network.require_capability(app, &peer, PeerCapability::Xfer)?;
    let local = network.fingerprint.clone();
    let id = manifest.id;
    let source = peer.clone();
    let record = check_store(app, network, session, id, move |store| {
        store.offer(manifest, &source, &local)
    })
    .await?;
    changed(app);
    match record.status {
        Status::AwaitingConsent => {
            alerts::offer(app, &network.owner, &record);
            return wire::send(session, &Control::AwaitingConsent).await;
        }
        Status::Paused | Status::Stopped => {
            return wire::send(session, &Control::AwaitingConsent).await
        }
        Status::Failed if record.failure == Some(TransferFailure::Integrity) => {
            return wire::send(session, &Control::IntegrityFailed { id }).await
        }
        Status::Rejected | Status::Cancelled | Status::Expired | Status::Failed => {
            return wire::send(session, &Control::Declined).await
        }
        Status::Verified => return wire::send(session, &Control::Complete { id }).await,
        Status::Ready | Status::Transferring | Status::Interrupted => {}
    }
    let run = network.transfers.begin(app, id)?;
    run.stage(SecurityPhase::PayloadEncryption, None);
    let result = tokio::select! {
        biased;
        _ = run.stopped() => Err(interrupted()),
        _ = network.until_stopped() => Err(interrupted()),
        result = download(app, network, session, record, &run, &peer) => result,
    };
    settle_run(app, network, id, result).await
}

async fn download(
    app: &AppHandle,
    network: &Network,
    session: &mut Session,
    record: Record,
    run: &Run<'_>,
    peer: &str,
) -> Result<()> {
    let id = record.manifest.id;
    let total = record.manifest.total_bytes();
    let missing = check_store(app, network, session, id, move |store| store.missing(id)).await?;
    let binding = *session.binding();
    let checkpoint = store_task(app, &network.owner, move |store| {
        store.start(id, Direction::Incoming)?;
        store.note_session(id, &binding)
    })
    .await?;
    run.baseline(checkpoint.completed_bytes);
    wire::send(session, &Control::Missing(missing.clone())).await?;
    for range in missing {
        let chunks = record
            .manifest
            .files
            .get(range.file as usize)
            .ok_or_else(wire::protocol_error)?
            .chunks;
        run.stage(SecurityPhase::SecureTransfer, Some(range.file));
        for chunk in range.next..chunks {
            network.wait_for_account(app).await?;
            network.require_peer(app, peer)?;
            wire::send(
                session,
                &Control::RequestChunk {
                    file: range.file,
                    chunk,
                },
            )
            .await?;
            let bytes = wire::recv_chunk(session).await?;
            let file = range.file;
            network.wait_for_account(app).await?;
            network.require_peer(app, peer)?;
            let record = store_task(app, &network.owner, move |store| {
                let result = store.put(id, file, chunk, &bytes[1..]);
                if let Err(error) = &result {
                    if let Some(error) = error.downcast_ref::<std::io::Error>() {
                        let failure = if storage_is_full(error) {
                            TransferFailure::StorageFull
                        } else {
                            TransferFailure::FileWrite
                        };
                        let _ = store.record_failure(id, failure);
                    }
                }
                result
            })
            .await?;
            run.verified(record.completed_bytes, total);
            wire::send(session, &Control::ChunkAck { file, chunk }).await?;
        }
    }
    network.require_peer(app, peer)?;
    run.stage(SecurityPhase::IntegrityVerification, None);
    let verified = match check_store(app, network, session, id, move |store| store.verify(id)).await
    {
        Ok(record) => record,
        Err(error) => {
            if let Ok(record) = store_task(app, &network.owner, move |store| store.get(id)).await {
                if record.status == Status::Failed
                    && record.failure == Some(TransferFailure::Integrity)
                {
                    run.stage(SecurityPhase::Error, None);
                    alerts::failed(app, &record, "file integrity verification failed");
                    let _ = wire::send(session, &Control::IntegrityFailed { id }).await;
                }
            }
            return Err(error);
        }
    };
    run.stage(SecurityPhase::Verified, None);
    changed(app);
    alerts::completed(app, &network.owner, &verified);
    app.state::<AppState>().audit_info(
        "offline_transfer_verified",
        "Verified an incoming local file transfer",
    );
    if verified.receive_into_vault {
        let app = app.clone();
        let owner = network.owner.clone();
        tauri::async_runtime::spawn(async move {
            for file in 0..verified.manifest.files.len() as u32 {
                if commands::import_into_vault(&app, &owner, id, file)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            changed(&app);
        });
    }
    wire::send(session, &Control::Complete { id }).await
}

pub(super) async fn outgoing(app: &AppHandle, network: &Network, id: Uuid) -> Result<()> {
    let _outbound = network
        .outbound
        .try_acquire()
        .map_err(|_| QGuardError::Trust("The local transfer queue is busy.".into()))?;
    let record = store_task(app, &network.owner, move |store| store.get(id)).await?;
    if record.direction != Direction::Outgoing
        || record.manifest.sender != network.fingerprint
        || !matches!(
            record.status,
            Status::Ready | Status::Transferring | Status::Interrupted
        )
    {
        return Err(wire::protocol_error());
    }
    let peer = &record.manifest.recipient;
    network.require_capability(app, peer, PeerCapability::Xfer)?;
    let run = network.transfers.begin(app, id)?;
    run.stage(SecurityPhase::KeyEstablishment, None);
    let result = tokio::select! {
        biased;
        _ = run.stopped() => Err(interrupted()),
        _ = network.until_stopped() => Err(interrupted()),
        result = async {
            let mut session = commands::connect(app, network, peer).await?;
            upload(app, network, &mut session, id, &run).await
        } => result,
    };
    // No local network reaches the receiver, but the Bluetooth channel does:
    // the offer goes over the channel and, once accepted, a direct Wi-Fi link
    // carries the files. Waiting for that is not a failure.
    if matches!(&result, Err(QGuardError::NotFound(_))) {
        if let Some(shared) = channel::shared(app, network) {
            if link::sender_fallback(app, &shared, peer, id) {
                return Ok(());
            }
        }
    }
    settle_run(app, network, id, result).await
}

/// A file offer that arrived over the persistent channel (no local network
/// reaches the sender). It is stored for consent exactly like an offer on a
/// transfer session; the files themselves never cross the channel.
pub(super) async fn channel_offer(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    manifest: Manifest,
) -> Result<OfferState> {
    network.require_capability(app, peer, PeerCapability::Xfer)?;
    let local = network.fingerprint.clone();
    let source = peer.to_owned();
    let record = store_task(app, &network.owner, move |store| store.offer(manifest, &source, &local)).await?;
    changed(app);
    Ok(match record.status {
        Status::AwaitingConsent => {
            alerts::offer(app, &network.owner, &record);
            OfferState::Awaiting
        }
        Status::Paused | Status::Stopped => OfferState::Awaiting,
        Status::Failed if record.failure == Some(TransferFailure::Integrity) => OfferState::IntegrityFailed,
        Status::Rejected | Status::Cancelled | Status::Expired | Status::Failed => OfferState::Declined,
        Status::Verified => OfferState::Complete,
        Status::Ready | Status::Transferring | Status::Interrupted => OfferState::Accepted,
    })
}

/// The receiver answered an offer sent over the channel.
pub(super) async fn offer_answered(app: &AppHandle, network: &Arc<Network>, peer: &str, id: Uuid, state: OfferState) {
    let Ok(record) = store_task(app, &network.owner, move |store| store.get(id)).await else {
        return;
    };
    if record.direction != Direction::Outgoing
        || record.manifest.recipient != peer
        || record.manifest.sender != network.fingerprint
    {
        return;
    }
    network.links.record_offer_state(id, state);
    match state {
        OfferState::Awaiting => {}
        OfferState::Accepted => link::need(app, network, peer),
        OfferState::Declined => {
            if store_task(app, &network.owner, move |store| store.reject_outgoing(id)).await.is_ok() {
                let _ = network.transfers.stop(id);
            }
        }
        OfferState::Complete => {
            if let Ok(record) = store_task(app, &network.owner, move |store| store.mark_verified(id)).await {
                alerts::completed(app, &network.owner, &record);
            }
        }
        OfferState::IntegrityFailed => {
            if let Ok(record) = store_task(app, &network.owner, move |store| store.fail_integrity(id)).await {
                alerts::failed(app, &record, "the receiver's integrity verification failed");
            }
        }
    }
    changed(app);
}

pub(super) async fn request(app: &AppHandle, network: &Network, id: Uuid) -> Result<()> {
    let _request = network.transfers.request_slot(id)?;
    let _outbound = network
        .outbound
        .try_acquire()
        .map_err(|_| QGuardError::Trust("The local transfer queue is busy.".into()))?;
    let record = store_task(app, &network.owner, move |store| store.get(id)).await?;
    if record.direction != Direction::Incoming
        || record.manifest.recipient != network.fingerprint
        || !matches!(
            record.status,
            Status::Ready | Status::Interrupted | Status::Transferring
        )
    {
        return Err(wire::protocol_error());
    }
    network.require_capability(app, &record.manifest.sender, PeerCapability::Xfer)?;
    let result = async {
        let mut session = commands::connect(app, network, &record.manifest.sender).await?;
        wire::send(&mut session, &Control::RequestSend { id }).await?;
        match await_checked(&mut session, id).await? {
            Control::Offer(manifest) if manifest == record.manifest => {
                incoming(app, network, &mut session, manifest).await
            }
            _ => Err(wire::protocol_error()),
        }
    }
    .await;
    // Accepted, but no local network reaches the sender: a direct Wi-Fi link
    // is set up over the Bluetooth channel and this request runs again then.
    if matches!(&result, Err(QGuardError::NotFound(_))) {
        if let Some(shared) = channel::shared(app, network) {
            if shared.channels.supports_links(&record.manifest.sender) {
                link::need(app, &shared, &record.manifest.sender);
                return Ok(());
            }
        }
    }
    if network.transfers.has_run(id)? {
        // A concurrent authenticated incoming connection may already be
        // running this transfer after our request was rejected as duplicate.
        return result;
    }
    settle_run(app, network, id, result).await
}

pub(super) async fn requested(
    app: &AppHandle,
    network: &Network,
    session: &mut Session,
    id: Uuid,
) -> Result<()> {
    let _outbound = network
        .outbound
        .try_acquire()
        .map_err(|_| QGuardError::Trust("The local transfer queue is busy.".into()))?;
    serve_upload(app, network, session, id).await
}

async fn serve_upload(
    app: &AppHandle,
    network: &Network,
    session: &mut Session,
    id: Uuid,
) -> Result<()> {
    let record = store_task(app, &network.owner, move |store| store.get(id)).await?;
    if record.direction != Direction::Outgoing
        || record.manifest.sender != network.fingerprint
        || record.manifest.recipient != session.peer()
    {
        return Err(QGuardError::Trust(
            "This transfer is outside the authenticated peer's authorization.".into(),
        ));
    }
    network.require_capability(app, session.peer(), PeerCapability::Xfer)?;
    let run = network.transfers.begin(app, id)?;
    run.stage(SecurityPhase::PayloadEncryption, None);
    let result = tokio::select! {
        biased;
        _ = run.stopped() => Err(interrupted()),
        _ = network.until_stopped() => Err(interrupted()),
        result = upload(app, network, session, id, &run) => result,
    };
    settle_run(app, network, id, result).await
}

async fn upload(
    app: &AppHandle,
    network: &Network,
    session: &mut Session,
    id: Uuid,
    run: &Run<'_>,
) -> Result<()> {
    let upload = Arc::new(
        check_store(app, network, session, id, move |store| {
            store.open_upload(id)
        })
        .await?,
    );
    let manifest = upload.manifest();
    let total = manifest.total_bytes();
    if manifest.sender != network.fingerprint {
        return Err(QGuardError::Trust(
            "This transfer belongs to a different local device identity.".into(),
        ));
    }
    let peer = &manifest.recipient;
    network.require_peer(app, peer)?;
    wire::send(session, &Control::Offer(manifest.clone())).await?;
    let missing = match await_checked(session, id).await? {
        Control::AwaitingConsent => return Ok(()),
        Control::Declined => {
            store_task(app, &network.owner, move |store| store.reject_outgoing(id)).await?;
            return Ok(());
        }
        Control::Complete { id: completed } if completed == id => {
            let record =
                store_task(app, &network.owner, move |store| store.mark_verified(id)).await?;
            alerts::completed(app, &network.owner, &record);
            return Ok(());
        }
        Control::IntegrityFailed { id: failed } if failed == id => {
            let record =
                store_task(app, &network.owner, move |store| store.fail_integrity(id)).await?;
            alerts::failed(app, &record, "the receiver's integrity verification failed");
            return Ok(());
        }
        Control::Missing(missing) => missing,
        _ => return Err(wire::protocol_error()),
    };
    let remote = missing.clone();
    let binding = *session.binding();
    let checkpoint = store_task(app, &network.owner, move |store| {
        store.record_remote_missing(id, &remote)?;
        store.note_session(id, &binding)
    })
    .await?;
    run.stage(SecurityPhase::PayloadEncryption, None);
    run.baseline(checkpoint.completed_bytes);
    for range in missing {
        let file = range.file;
        let chunks = manifest
            .files
            .get(file as usize)
            .ok_or_else(wire::protocol_error)?
            .chunks;
        run.stage(SecurityPhase::SecureTransfer, Some(file));
        for chunk in range.next..chunks {
            if !matches!(wire::recv(session).await?, Control::RequestChunk { file: f, chunk: c } if f == file && c == chunk)
            {
                return Err(wire::protocol_error());
            }
            network.wait_for_account(app).await?;
            network.require_peer(app, peer)?;
            let source = Arc::clone(&upload);
            let bytes = tokio::task::spawn_blocking(move || source.read_chunk(file, chunk))
                .await
                .map_err(|_| task_error())??;
            network.wait_for_account(app).await?;
            network.require_peer(app, peer)?;
            wire::send_chunk(session, &bytes).await?;
            if !matches!(wire::recv(session).await?, Control::ChunkAck { file: f, chunk: c } if f == file && c == chunk)
            {
                return Err(wire::protocol_error());
            }
            let record = store_task(app, &network.owner, move |store| {
                store.record_ack(id, file, chunk)
            })
            .await?;
            run.verified(record.completed_bytes, total);
        }
    }
    run.stage(SecurityPhase::IntegrityVerification, None);
    match await_checked(session, id).await? {
        Control::Complete { id: completed } if completed == id => {}
        Control::IntegrityFailed { id: failed } if failed == id => {
            let record =
                store_task(app, &network.owner, move |store| store.fail_integrity(id)).await?;
            run.stage(SecurityPhase::Error, None);
            alerts::failed(app, &record, "the receiver's integrity verification failed");
            return Ok(());
        }
        _ => return Err(wire::protocol_error()),
    }
    let record = store_task(app, &network.owner, move |store| store.mark_verified(id)).await?;
    run.stage(SecurityPhase::Verified, None);
    alerts::completed(app, &network.owner, &record);
    app.state::<AppState>().audit_info(
        "offline_transfer_receipt",
        "Received an authenticated transfer verification receipt",
    );
    Ok(())
}

fn connection_lost(error: &QGuardError) -> bool {
    matches!(error, QGuardError::Storage(message) if message == "The local peer connection closed or could not carry the frame.")
}

fn storage_is_full(error: &std::io::Error) -> bool {
    #[cfg(windows)]
    return matches!(error.raw_os_error(), Some(39 | 112 | 1295)); // HANDLE_DISK_FULL, DISK_FULL, DISK_QUOTA_EXCEEDED
    #[cfg(not(windows))]
    return error.raw_os_error() == Some(28); // ENOSPC
}

fn classify_failure(error: &QGuardError) -> TransferFailure {
    if session::is_timeout(error)
        || matches!(error, QGuardError::Storage(message) if message == "The peer timed out while verifying the transfer.")
    {
        TransferFailure::Timeout
    } else if session::is_handshake_failure(error) {
        TransferFailure::Encryption
    } else if connection_lost(error) {
        TransferFailure::ConnectionLost
    } else if matches!(error, QGuardError::NotFound(_)) {
        TransferFailure::PeerUnavailable
    } else {
        TransferFailure::Interrupted
    }
}

async fn settle_run(
    app: &AppHandle,
    network: &Network,
    id: Uuid,
    result: Result<()>,
) -> Result<()> {
    if let Err(error) = &result {
        let failure = classify_failure(error);
        let settled = store_task(app, &network.owner, move |store| {
            let record = store.get(id)?;
            if matches!(
                record.failure,
                Some(
                    TransferFailure::StorageFull
                        | TransferFailure::FileWrite
                        | TransferFailure::Integrity
                )
            ) {
                return Ok(record);
            }
            store.record_failure(id, failure)
        })
        .await;
        // A user pause, stop or cancel also ends the run with an interruption.
        // Only failures that need the user's action raise a desktop alert.
        if let Ok(record) = settled {
            let reason = match record.failure {
                Some(TransferFailure::StorageFull) => Some("there is not enough protected storage"),
                Some(TransferFailure::FileWrite) => Some("the received data could not be saved"),
                Some(TransferFailure::Encryption) => {
                    Some("the encrypted session could not be established")
                }
                _ => None,
            };
            if let Some(reason) = reason {
                alerts::failed(app, &record, reason);
            }
        }
    }
    result
}

fn interrupted() -> QGuardError {
    QGuardError::Storage("The local transfer was interrupted.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_retry_backoff_does_not_delay_a_new_revision() {
        let transfers = ActiveTransfers::default();
        let id = Uuid::new_v4();
        assert!(transfers.control_due(id, 1));
        assert!(!transfers.control_due(id, 1));
        assert!(transfers.control_due(id, 2));
        assert!(!transfers.control_due(id, 2));
    }

    #[test]
    fn receiver_dial_reservations_are_bounded_and_deduplicated() {
        let transfers = ActiveTransfers::default();
        let id = Uuid::new_v4();
        let first = transfers.request_slot(id).unwrap();
        assert!(transfers.request_slot(id).is_err());
        let _second = transfers.request_slot(Uuid::new_v4()).unwrap();
        assert!(transfers.request_slot(Uuid::new_v4()).is_err());
        drop(first);
        assert!(transfers.request_slot(id).is_ok());
    }
}
