use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{Ipv4Addr, SocketAddrV4},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use chrono::Utc;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{watch, Semaphore},
    task::JoinSet,
    time::{interval, timeout, MissedTickBehavior},
};

use crate::{
    error::{QGuardError, Result},
    state::AppState,
};

use super::{
    lan, pairing::Pairings,
    profile::{network_owner, PeerCapability, PeerMetadata, TrustBook},
    session::Identity,
    smart::{self, SmartConnect},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(4);
const WATCH_INTERVAL: Duration = Duration::from_secs(1);
/// Beacons (4 s each) without a working Bluetooth radio before a restart.
const BLUETOOTH_RECOVERY_BEACONS: u32 = 5;
const MAX_INBOUND: usize = 8;
const MAX_INBOUND_PER_IP: usize = 2;
const PRINCIPAL_RENEWAL_GRACE: Duration = Duration::from_secs(15);
const PAIRING_ADMISSION_WINDOW: Duration = Duration::from_secs(20);
const MAX_PAIRING_HANDSHAKES_PER_WINDOW: usize = 12;

#[derive(Default)]
pub(crate) struct Runtime {
    pub(super) network: Mutex<Option<Arc<Network>>>,
    pub(super) lifecycle: tokio::sync::Mutex<()>,
    pub(super) storage: Mutex<()>,
    pub(super) transfers: Mutex<Option<(String, String)>>,
    pub(super) selections: Mutex<HashMap<uuid::Uuid, super::commands::SourceSelection>>,
    pub(super) picker: tokio::sync::Mutex<()>,
    /// Connection diagnostics recorded by the transport and session layers.
    pub(super) events: super::diag::Events,
}

pub(super) fn lock<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| QGuardError::Storage("The local networking service is unavailable.".into()))
}

pub(super) fn changed(app: &AppHandle) {
    let _ = app.emit("offline:changed", ());
}

pub(super) struct Network {
    pub owner: String,
    pub identity: Identity,
    pub fingerprint: String,
    pub port: u16,
    pub discovery: Mutex<lan::Discovery>,
    lan_receiver: AtomicBool,
    pub(super) smart: Mutex<SmartConnect>,
    ble_incoming: Mutex<Vec<tokio::io::DuplexStream>>,
    pub authenticated: Mutex<HashMap<String, i64>>,
    sessions: Mutex<PeerSessions>,
    pub(super) pairings: Pairings,
    pub(super) pairing_outbound: Arc<Semaphore>,
    pairing_admissions: Mutex<VecDeque<Instant>>,
    pub error: Mutex<Option<String>>,
    automatic: AtomicBool,
    stop_when_idle: AtomicBool,
    pub(super) outbound: Semaphore,
    pub(super) mesh_worker: Semaphore,
    pub(super) relay_worker: Semaphore,
    /// Last relay exchange per peer (multi-hop Mesh), to pace pulls.
    pub(super) relay_exchanges: Mutex<HashMap<String, (Instant, bool)>>,
    /// The sealed relay store, loaded once per network run.
    pub(super) relay_store: Mutex<Option<super::relay::Store>>,
    /// Keep serving the unlocked account while Qguard is locked (opt-in).
    background: AtomicBool,
    pub(super) queue_worker: Semaphore,
    pub(super) queued_attempts: Mutex<HashMap<uuid::Uuid, Instant>>,
    pub(super) transfers: super::transfer::ActiveTransfers,
    /// The persistent channel to each connected peer (see `channel.rs`).
    pub(super) channels: super::channel::Channels,
    /// Direct Wi-Fi links to peers that share only Bluetooth (see `link.rs`).
    pub(super) links: super::link::Links,
    /// Pictures that nearby, not yet paired devices chose to show (memory
    /// only, keyed by the fingerprint that authenticated the fetch).
    pub(super) nearby_pictures: Mutex<HashMap<String, super::avatar::Avatar>>,
    pub(super) picture_fetches: Mutex<HashMap<String, Instant>>,
    pub(super) picture_worker: Arc<Semaphore>,
    stop: watch::Sender<bool>,
    terminated: watch::Receiver<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PeerStatus {
    fingerprint: String,
    label: Option<String>,
    address: Option<String>,
    last_seen: Option<i64>,
    trusted: bool,
    authenticated_at: Option<i64>,
    discovery: Vec<&'static str>,
    ble_mesh: bool,
    /// Bluetooth signal strength in dBm, when this device is in radio range.
    rssi: Option<i16>,
    platform: Option<String>,
    paired_at: Option<i64>,
    capabilities: Vec<PeerCapability>,
    connected: bool,
    blocked: bool,
    disconnected: bool,
    /// Display name the paired user shared after both confirmations.
    owner: Option<String>,
    /// The persistent channel to this peer: connected, connecting or
    /// reconnecting, with its transport, session id and heartbeat time.
    link: Option<super::channel::LinkView>,
    /// The direct Wi-Fi link to this peer, while one is being set up or used.
    wifi_link: Option<super::link::LinkView>,
    /// Not serialized: a nearby device's opt-in picture digest, merged into
    /// `avatar` for untrusted devices by the status builder.
    #[serde(skip)]
    nearby_picture: Option<String>,
    /// SHA3-256 digest of the profile picture this trusted peer sent on its
    /// authenticated channel (`offline_avatar` returns the image).
    avatar: Option<String>,
}

impl PeerStatus {
    pub(super) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// A trusted device's synced picture, or a nearby device's opt-in one.
    pub(super) fn set_avatar(&mut self, trusted: Option<String>) {
        self.avatar = if self.trusted { trusted } else { self.nearby_picture.take() };
    }
}

#[derive(Default)]
struct PeerSessions {
    active: HashMap<String, usize>,
    authorization: HashMap<String, watch::Sender<bool>>,
    disconnected: HashSet<String>,
    revision: u64,
}

pub(super) struct PeerActivity<'a> {
    app: AppHandle,
    network: &'a Network,
    fingerprint: String,
}

impl Drop for PeerActivity<'_> {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.network.sessions.lock() {
            if let Some(count) = sessions.active.get_mut(&self.fingerprint) {
                *count -= 1;
                if *count == 0 {
                    sessions.active.remove(&self.fingerprint);
                    sessions.authorization.remove(&self.fingerprint);
                }
            }
        }
        changed(&self.app);
    }
}

impl Network {
    pub fn running(&self) -> bool {
        !*self.stop.borrow()
    }

    pub(super) fn lan_discovery_running(&self) -> bool {
        self.running() && self.lan_receiver.load(Ordering::Relaxed)
    }

    pub fn automatic(&self) -> bool {
        self.automatic.load(Ordering::Relaxed)
    }

    pub fn background(&self) -> bool {
        self.background.load(Ordering::Relaxed)
    }

    pub fn set_background(&self, enabled: bool) {
        self.background.store(enabled, Ordering::Relaxed);
    }

    pub fn keep_running(&self) {
        self.automatic.store(false, Ordering::Relaxed);
        self.stop_when_idle.store(false, Ordering::Relaxed);
    }

    pub fn set_stop_when_idle(&self, stop: bool) {
        self.stop_when_idle.store(stop, Ordering::Relaxed);
    }

    pub fn stop(&self) {
        self.stop.send_replace(true);
        if let Ok(mut sessions) = self.sessions.lock() {
            for (_, authorization) in sessions.authorization.drain() {
                authorization.send_replace(true);
            }
        }
    }

    pub async fn stop_and_wait(&self) {
        self.stop();
        let mut terminated = self.terminated.clone();
        let _ = terminated.wait_for(|terminated| *terminated).await;
    }

    pub fn check(&self, app: &AppHandle) -> Result<()> {
        crate::crypto::provider::require_offline_suite()?;
        if !self.running() || network_owner(&app.state::<AppState>(), self.background())? != self.owner {
            return Err(QGuardError::Trust(
                "The current local networking session has ended.".into(),
            ));
        }
        Ok(())
    }

    fn renewing(&self, app: &AppHandle) -> bool {
        let state = app.state::<AppState>();
        #[cfg(target_os = "android")]
        if !state.is_applock_unlocked() {
            return false;
        }
        self.running() && state.offline_principal.renewing(&state, &self.owner)
    }

    pub async fn wait_for_account(&self, app: &AppHandle) -> Result<()> {
        let until = Instant::now() + PRINCIPAL_RENEWAL_GRACE;
        loop {
            match self.check(app) {
                Ok(()) => return Ok(()),
                Err(error) if Instant::now() >= until || !self.renewing(app) => return Err(error),
                Err(_) => tokio::time::sleep(Duration::from_millis(150)).await,
            }
        }
    }

    pub fn require_peer(&self, app: &AppHandle, peer: &str) -> Result<()> {
        self.check_dial_peer(app, peer, false)
    }

    pub(super) fn require_peer_locked(&self, app: &AppHandle, peer: &str, probe: bool) -> Result<()> {
        self.check(app)?;
        let book = TrustBook::load(&app.state::<AppState>(), &self.owner)?;
        Self::require_trusted(&book, peer)?;
        if probe || !lock(&self.sessions)?.disconnected.contains(peer) {
            return Ok(());
        }
        Err(QGuardError::Trust("This device is disconnected. Reconnect it from Trusted devices.".into()))
    }

    /// The peer must be trusted, connected and paired for this capability.
    pub(super) fn require_capability(
        &self,
        app: &AppHandle,
        peer: &str,
        capability: PeerCapability,
    ) -> Result<()> {
        let runtime = app.state::<Runtime>();
        let _gate = lock(&runtime.storage)?;
        self.require_peer_locked(app, peer, true)?;
        TrustBook::load(&app.state::<AppState>(), &self.owner)?.require(peer, capability)
    }

    /// As `require_capability`, for a caller that already holds the storage gate.
    pub(super) fn require_capability_locked(
        &self,
        app: &AppHandle,
        peer: &str,
        capability: PeerCapability,
    ) -> Result<()> {
        TrustBook::load(&app.state::<AppState>(), &self.owner)?.require(peer, capability)
    }

    /// The user disconnected this peer; nothing dials it until they reconnect.
    pub(super) fn is_disconnected(&self, peer: &str) -> bool {
        self.sessions.lock().is_ok_and(|sessions| sessions.disconnected.contains(peer))
    }

    fn require_trusted(book: &TrustBook, peer: &str) -> Result<()> {
        if !book.is_blocked(peer) && book.peers.contains_key(peer) {
            return Ok(());
        }
        Err(QGuardError::Trust(
            "This device fingerprint is outside the trusted device list.".into(),
        ))
    }

    pub(super) fn require_pairing_peer(&self, app: &AppHandle, peer: &str) -> Result<()> {
        // Pairing needs the user in front: never while Qguard is locked.
        if !super::profile::unlocked_in_front(&app.state::<AppState>()) {
            return Err(QGuardError::Trust("Unlock Qguard to pair a device.".into()));
        }
        if !lan::fingerprint_valid(peer) || peer == self.fingerprint {
            return Err(QGuardError::InvalidInput("Choose a different nearby device.".into()));
        }
        self.check(app)?;
        let runtime = app.state::<Runtime>();
        let _gate = lock(&runtime.storage)?;
        self.check(app)?;
        TrustBook::load(&app.state::<AppState>(), &self.owner)?.can_pair(peer)
    }

    pub(super) fn admit_pairing(&self) -> bool {
        let Ok(mut recent) = self.pairing_admissions.lock() else { return false };
        while recent.front().is_some_and(|when| when.elapsed() >= PAIRING_ADMISSION_WINDOW) {
            recent.pop_front();
        }
        if recent.len() >= MAX_PAIRING_HANDSHAKES_PER_WINDOW {
            return false;
        }
        recent.push_back(Instant::now());
        true
    }

    /// The caller holds the storage gate so new authorizations and trust
    /// commits cannot race with revocation or an explicit disconnect.
    pub(super) fn invalidate_peer(&self, peer: &str, disconnect: bool) -> Result<()> {
        let mut sessions = lock(&self.sessions)?;
        sessions.revision = sessions.revision.wrapping_add(1);
        if disconnect {
            sessions.disconnected.insert(peer.into());
        } else {
            sessions.disconnected.remove(peer);
        }
        if let Some(authorization) = sessions.authorization.remove(peer) {
            authorization.send_replace(true);
        }
        self.pairings.cancel_peer(peer);
        Ok(())
    }

    pub(super) fn probe_revision(&self, app: &AppHandle, peer: &str) -> Result<u64> {
        let runtime = app.state::<Runtime>();
        let _gate = lock(&runtime.storage)?;
        self.require_peer_locked(app, peer, true)?;
        Ok(lock(&self.sessions)?.revision)
    }

    pub(super) fn allow_peer_after_pairing(&self, peer: &str) -> Result<()> {
        lock(&self.sessions)?.disconnected.remove(peer);
        Ok(())
    }

    pub fn peer_authenticated(&self, app: &AppHandle, peer: &str, probe_revision: Option<u64>) -> Result<(PeerActivity<'_>, watch::Receiver<bool>)> {
        let authorization = {
            let state = app.state::<AppState>();
            let runtime = app.state::<Runtime>();
            let _gate = lock(&runtime.storage)?;
            self.check(app)?;
            let mut book = TrustBook::load(&state, &self.owner)?;
            Self::require_trusted(&book, peer)?;
            let mut sessions = lock(&self.sessions)?;
            if probe_revision.map_or_else(|| sessions.disconnected.contains(peer), |revision| sessions.revision != revision)
                || !self.running() {
                return Err(QGuardError::Trust("This local connection was closed.".into()));
            }
            if book.record_connection(peer)? {
                book.save(&state, &self.owner)?;
            }
            if probe_revision.is_some() {
                sessions.disconnected.remove(peer);
            }
            lock(&self.authenticated)?.insert(peer.into(), Utc::now().timestamp());
            *sessions.active.entry(peer.into()).or_default() += 1;
            sessions.authorization.entry(peer.into()).or_insert_with(|| watch::channel(false).0).subscribe()
        };
        changed(app);
        Ok((PeerActivity {
            app: app.clone(),
            network: self,
            fingerprint: peer.into(),
        }, authorization))
    }

    pub fn active_peers(&self, book: &TrustBook) -> Result<usize> {
        let sessions = lock(&self.sessions)?;
        Ok(sessions.active.keys()
            .filter(|fingerprint| book.peers.contains_key(*fingerprint) && sessions.authorization.contains_key(*fingerprint))
            .count())
    }

    pub async fn connect(&self, app: &AppHandle, peer: &str, probe: bool) -> Result<TcpStream> {
        self.check_dial_peer(app, peer, probe)?;
        let state = app.state::<AppState>();
        let book = TrustBook::load(&state, &self.owner)?;
        let known = book.peers.get(peer).and_then(|entry| entry.address);
        let stream = self.dial(self.endpoints(peer, known)?).await?;
        self.check_dial_peer(app, peer, probe)?;
        Ok(stream)
    }

    fn check_dial_peer(&self, app: &AppHandle, peer: &str, probe: bool) -> Result<()> {
        let runtime = app.state::<Runtime>();
        let _gate = lock(&runtime.storage)?;
        self.require_peer_locked(app, peer, probe)
    }

    pub(super) async fn connect_pairing(&self, app: &AppHandle, peer: &str) -> Result<TcpStream> {
        self.require_pairing_peer(app, peer)?;
        let stream = self.dial(self.endpoints(peer, None)?).await?;
        self.require_pairing_peer(app, peer)?;
        Ok(stream)
    }

    async fn dial(&self, candidates: Vec<SocketAddrV4>) -> Result<TcpStream> {
        let connected = timeout(CONNECT_TIMEOUT, async {
            for address in candidates {
                if let Ok(Ok(stream)) =
                    timeout(Duration::from_secs(2), TcpStream::connect(address)).await
                {
                    return Some(stream);
                }
            }
            None
        })
        .await
        .ok()
        .flatten();
        if let Some(stream) = connected {
            let _ = stream.set_nodelay(true);
            return Ok(stream);
        }
        Err(QGuardError::NotFound(
            "No usable local network path reached this device. Join the same Wi-Fi network or hotspot and retry.".into(),
        ))
    }

    pub(super) fn endpoints(
        &self,
        peer: &str,
        manual: Option<SocketAddrV4>,
    ) -> Result<Vec<SocketAddrV4>> {
        let lan = lock(&self.discovery)?
            .peers
            .get(peer)
            .map(|entry| entry.address);
        let radio = lock(&self.smart)?;
        let hints = radio
            .peers
            .get(peer)
            .map_or(&[][..], |peer| peer.endpoints.as_slice());
        // A connected Wi-Fi link is the route that is known to work: try it first.
        let mut routes = self.links.endpoints(peer);
        for route in route_endpoints(manual, lan, hints) {
            if !routes.contains(&route) {
                routes.push(route);
            }
        }
        Ok(routes)
    }

    pub(super) fn mesh_reachable(&self, peer: &str, manual: Option<SocketAddrV4>) -> Result<bool> {
        if !self.endpoints(peer, manual)?.is_empty() {
            return Ok(true);
        }
        Ok(lock(&self.smart)?
            .peers
            .get(peer)
            .is_some_and(|peer| peer.ble_mesh))
    }

    pub(super) async fn connect_ble(
        &self,
        app: &AppHandle,
        peer: &str,
        probe: bool,
    ) -> Result<tokio::io::DuplexStream> {
        self.check_dial_peer(app, peer, probe)?;
        let stream = self.dial_ble(peer).await?;
        self.check_dial_peer(app, peer, probe)?;
        Ok(stream)
    }

    pub(super) async fn connect_pairing_ble(&self, app: &AppHandle, peer: &str) -> Result<tokio::io::DuplexStream> {
        self.require_pairing_peer(app, peer)?;
        let stream = self.dial_ble(peer).await?;
        self.require_pairing_peer(app, peer)?;
        Ok(stream)
    }

    async fn dial_ble(&self, _peer: &str) -> Result<tokio::io::DuplexStream> {
        #[cfg(any(target_os = "android", windows))]
        {
            let candidate = lock(&self.smart)?.connector(_peer);
            if let Some((connector, address)) = candidate {
                return connector.connect(&address).await;
            }
        }
        Err(QGuardError::NotFound(
            "This peer has no available Bluetooth link.".into(),
        ))
    }

    /// The picture fingerprint to advertise: only when the owner chose to show
    /// the picture to nearby devices and has one.
    pub(super) fn nearby_picture_tag(&self, app: &AppHandle) -> Option<String> {
        let state = app.state::<AppState>();
        let runtime = app.state::<Runtime>();
        let _gate = lock(&runtime.storage).ok()?;
        if !TrustBook::load(&state, &self.owner).ok()?.share_picture_nearby {
            return None;
        }
        let digest = super::avatar::AvatarBook::load(&state, &self.owner).ok()?.local_digest()?;
        Some(digest[..16].to_owned())
    }

    /// The picture a nearby, not yet paired device shared, if fetched.
    pub(super) fn nearby_picture(&self, peer: &str) -> Option<super::avatar::Avatar> {
        self.nearby_pictures.lock().ok()?.get(peer).cloned()
    }

    pub(super) async fn restart_bluetooth(self: &Arc<Self>, app: &AppHandle) -> Result<()> {
        self.check(app)?;
        let network = Arc::clone(self);
        let worker = app.clone();
        tokio::task::spawn_blocking(move || {
            let metadata = PeerMetadata::local(&worker.state::<AppState>(), &network.owner, &network.fingerprint);
            let picture = network.nearby_picture_tag(&worker);
            let mut radio = lock(&network.smart)?;
            network.check(&worker)?;
            radio.restart(&network.fingerprint, network.port, &metadata, picture.as_deref());
            if let Err(error) = network.check(&worker) {
                radio.stop();
                return Err(error);
            }
            Ok::<_, QGuardError>(())
        })
        .await
        .map_err(|_| QGuardError::Storage("Bluetooth discovery could not restart.".into()))??;
        changed(app);
        Ok(())
    }

    pub fn peers(&self, book: &TrustBook) -> Result<Vec<PeerStatus>> {
        let discovery = lock(&self.discovery)?;
        let smart = lock(&self.smart)?;
        let sessions = lock(&self.sessions)?;
        let authenticated = lock(&self.authenticated)?;
        let mut peers = peer_status_with_sessions(
            book,
            Some(&discovery),
            Some(&smart.peers),
            Some(&authenticated),
            Some(&sessions),
        );
        for peer in &mut peers {
            if peer.trusted && !peer.blocked {
                peer.link = self.channels.view(&peer.fingerprint);
                peer.wifi_link = self.links.view(&peer.fingerprint);
            }
            if !peer.trusted && !peer.blocked {
                if let Some(picture) = self.nearby_picture(&peer.fingerprint) {
                    peer.nearby_picture = Some(picture.digest);
                }
            }
        }
        Ok(peers)
    }

    pub async fn until_stopped(&self) {
        let mut stop = self.stop.subscribe();
        let _ = stop.wait_for(|stopped| *stopped).await;
    }
}

fn route_endpoints(
    manual: Option<SocketAddrV4>,
    lan: Option<SocketAddrV4>,
    bluetooth: &[SocketAddrV4],
) -> Vec<SocketAddrV4> {
    let mut endpoints = Vec::new();
    // A live LAN announcement is already evidence of local reachability.
    for endpoint in [lan, manual]
        .into_iter()
        .flatten()
        .chain(bluetooth.iter().copied())
    {
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
    endpoints
}

pub(super) fn peer_status(
    book: &TrustBook,
    discovery: Option<&lan::Discovery>,
    bluetooth: Option<&HashMap<String, smart::Observation>>,
    authenticated: Option<&HashMap<String, i64>>,
) -> Vec<PeerStatus> {
    peer_status_with_sessions(book, discovery, bluetooth, authenticated, None)
}

fn peer_status_with_sessions(
    book: &TrustBook,
    discovery: Option<&lan::Discovery>,
    bluetooth: Option<&HashMap<String, smart::Observation>>,
    authenticated: Option<&HashMap<String, i64>>,
    sessions: Option<&PeerSessions>,
) -> Vec<PeerStatus> {
    let mut ids: HashSet<_> = book.peers.keys().cloned().collect();
    ids.extend(book.blocked.keys().cloned());
    if let Some(discovery) = discovery {
        ids.extend(
            discovery
                .peers
                .keys()
                .filter(|id| !book.peers.contains_key(*id))
                .cloned(),
        );
    }
    if let Some(bluetooth) = bluetooth {
        ids.extend(bluetooth.keys().cloned());
    }
    let mut ids: Vec<_> = ids.into_iter().collect();
    ids.sort_unstable();
    ids.into_iter()
        .map(|fingerprint| {
            let record = book.peers.get(&fingerprint);
            let blocked = book.blocked.get(&fingerprint);
            let known = record.or_else(|| blocked.and_then(|entry| entry.previous.as_ref()));
            let paired = known.and_then(|entry| entry.paired.as_ref());
            let observed = discovery.and_then(|value| value.peers.get(&fingerprint));
            let radio = bluetooth.and_then(|value| value.get(&fingerprint));
            let manual = record.and_then(|value| value.address);
            let address = route_endpoints(
                manual,
                observed.map(|value| value.address),
                radio.map_or(&[][..], |value| value.endpoints.as_slice()),
            )
            .into_iter()
            .next();
            let discovery = [
                (observed.is_some(), "lan"),
                (radio.is_some(), "ble"),
                (manual.is_some(), "manual"),
            ]
            .into_iter()
            .filter_map(|(found, kind)| found.then_some(kind))
            .collect();
            PeerStatus {
                label: known.map(|value| value.label.clone())
                    .or_else(|| observed.and_then(|value| value.label.clone()))
                    .or_else(|| radio.and_then(|value| value.label.clone())),
                address: address.filter(|_| blocked.is_none()).map(|value| value.to_string()),
                last_seen: observed
                    .map(|value| value.last_seen)
                    .max(radio.map(|value| value.last_seen)),
                trusted: record.is_some(),
                authenticated_at: authenticated
                    .and_then(|value| value.get(&fingerprint))
                    .copied()
                    .max(known.and_then(|entry| entry.last_connected_at)),
                platform: paired.map(|identity| identity.platform.clone())
                    .or_else(|| observed.and_then(|value| value.platform.clone()))
                    .or_else(|| radio.and_then(|value| value.platform.clone())),
                paired_at: paired.map(|identity| identity.paired_at),
                capabilities: paired.map_or_else(Vec::new, |identity| identity.capabilities.clone()),
                connected: record.is_some() && sessions.is_some_and(|value| value.authorization.contains_key(&fingerprint)),
                blocked: blocked.is_some(),
                disconnected: sessions.is_some_and(|value| value.disconnected.contains(&fingerprint)),
                owner: known.and_then(|entry| entry.owner.clone()),
                link: None,
                wifi_link: None,
                nearby_picture: None,
                avatar: None,
                fingerprint,
                discovery,
                ble_mesh: radio.is_some_and(|peer| peer.ble_mesh),
                rssi: radio.and_then(|peer| peer.rssi),
            }
        })
        .collect()
}

pub(super) async fn start(
    app: AppHandle,
    owner: String,
    identity: Identity,
    automatic: bool,
) -> Result<Arc<Network>> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(network_io)?;
    let port = listener.local_addr().map_err(network_io)?.port();
    let fingerprint = identity.fingerprint().to_string();
    let (udp, discovery_error) = match lan::discovery_socket().await {
        Ok(udp) => (Some(udp), None),
        Err(error) => (
            None,
            Some(format!(
                "LAN discovery could not start. Check the local network and try again. ({error})"
            )),
        ),
    };
    let (stop, _) = watch::channel(false);
    let (terminated, completion) = watch::channel(false);
    let network = Arc::new(Network {
        owner,
        identity,
        fingerprint,
        port,
        discovery: Mutex::default(),
        lan_receiver: AtomicBool::new(udp.is_some()),
        smart: Mutex::default(),
        ble_incoming: Mutex::default(),
        authenticated: Mutex::default(),
        sessions: Mutex::default(),
        pairings: Pairings::default(),
        pairing_outbound: Arc::new(Semaphore::new(4)),
        pairing_admissions: Mutex::default(),
        error: Mutex::new(discovery_error),
        automatic: AtomicBool::new(automatic),
        stop_when_idle: AtomicBool::new(false),
        outbound: Semaphore::new(4),
        mesh_worker: Semaphore::new(1),
        relay_worker: Semaphore::new(1),
        relay_exchanges: Mutex::default(),
        relay_store: Mutex::default(),
        background: AtomicBool::new(false),
        queue_worker: Semaphore::new(1),
        queued_attempts: Mutex::default(),
        transfers: super::transfer::ActiveTransfers::default(),
        channels: super::channel::Channels::default(),
        links: super::link::Links::default(),
        nearby_pictures: Mutex::default(),
        picture_fetches: Mutex::default(),
        picture_worker: Arc::new(Semaphore::new(1)),
        stop,
        terminated: completion,
    });
    let worker = Arc::clone(&network);
    let worker_for_links = Arc::clone(&network);
    tauri::async_runtime::spawn(async move {
        supervise(app, worker, listener, udp).await;
        let _ = tokio::task::spawn_blocking(super::background::stop).await;
        // Return the PC to its own Wi-Fi network if it joined a link.
        let leaving = Arc::clone(&worker_for_links);
        let _ = tokio::task::spawn_blocking(move || super::link::shutdown(&leaving)).await;
        terminated.send_replace(true);
    });
    Ok(network)
}

async fn supervise(
    app: AppHandle,
    network: Arc<Network>,
    listener: TcpListener,
    mut udp: Option<tokio::net::UdpSocket>,
) {
    let mut accepted = JoinSet::new();
    let mut radio_tasks = JoinSet::new();
    // Starting local networking is already opt-in. Probe granted Bluetooth
    // access for automatic recovery too; never open an OS permission prompt.
    {
        let app = app.clone();
        let network = Arc::clone(&network);
        radio_tasks.spawn(async move {
            let _ = network.restart_bluetooth(&app).await;
        });
    }
    let mut watch = interval(WATCH_INTERVAL);
    watch.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut beacon = interval(DISCOVERY_INTERVAL);
    beacon.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut bytes = [0; 256];
    let mut observed = false;
    let mut renewal_since: Option<Instant> = None;
    let mut radio_idle_beacons = 0u32;
    let incoming_by_ip = Arc::new(Mutex::new(HashMap::<Ipv4Addr, usize>::new()));
    let announcement = lan::announcement(&network.fingerprint, network.port);
    let identity = PeerMetadata::local(&app.state::<AppState>(), &network.owner, &network.fingerprint);
    let enriched = lan::announcement_with_metadata(&network.fingerprint, network.port, &identity);
    loop {
        tokio::select! {
            _ = network.until_stopped() => break,
            _ = watch.tick() => {
                if network.check(&app).is_err() {
                    if !network.renewing(&app)
                        || renewal_since.get_or_insert_with(Instant::now).elapsed() >= PRINCIPAL_RENEWAL_GRACE
                    {
                        break;
                    }
                    continue;
                }
                renewal_since = None;
                // Collect new Bluetooth links every second, not only on the
                // slower beacon: the connecting device is already waiting.
                if radio_tasks.is_empty() {
                    let network = Arc::clone(&network);
                    radio_tasks.spawn_blocking(move || {
                        if let Ok(radio) = lock(&network.smart) {
                            if let Ok(streams) = radio.take_incoming() {
                                if let Ok(mut incoming) = lock(&network.ble_incoming) {
                                    let capacity = 4usize.saturating_sub(incoming.len());
                                    incoming.extend(streams.into_iter().take(capacity));
                                }
                            }
                        }
                    });
                }
                let streams = lock(&network.ble_incoming).map(|mut pending| pending.drain(..).collect::<Vec<_>>()).unwrap_or_default();
                for stream in streams {
                    if accepted.len() >= MAX_INBOUND { break }
                    let worker = app.clone();
                    let service = Arc::clone(&network);
                    accepted.spawn(async move { let _ = super::commands::serve_ble(&worker, &service, stream).await; });
                }
                if network.stop_when_idle.load(Ordering::Relaxed) && !network.transfers.is_active() && !network.pairings.has_pending() {
                    break;
                }
                if lock(&network.discovery).is_ok_and(|mut discovery| discovery.expire()) || observed {
                    changed(&app);
                    observed = false;
                }
            }
            _ = beacon.tick() => {
                if network.check(&app).is_err() {
                    continue;
                }
                // Keep one persistent channel to every reachable trusted peer.
                super::channel::maintain(&app, &network, None);
                super::link::maintain(&app, &network);
                super::commands::schedule_nearby_pictures(&app, &network);
                super::commands::schedule_mesh(&app, &network);
                super::relay_net::schedule(&app, &network);
                super::commands::schedule_transfer_controls(&app, &network);
                super::commands::schedule_queued_transfers(&app, &network);
                // Recover by itself when Bluetooth was switched off and on again,
                // or the radio was briefly unavailable. This never opens an OS
                // permission prompt; without access it only refreshes the status.
                // A busy radio lock means a poll or restart is already under way.
                let radio_running = network.smart.try_lock().map_or(true, |radio| radio.status().bluetooth_running());
                radio_idle_beacons = if radio_running { 0 } else { radio_idle_beacons + 1 };
                if radio_idle_beacons >= BLUETOOTH_RECOVERY_BEACONS && radio_tasks.is_empty() {
                    radio_idle_beacons = 0;
                    let app = app.clone();
                    let network = Arc::clone(&network);
                    radio_tasks.spawn(async move {
                        let _ = network.restart_bluetooth(&app).await;
                    });
                }
                if radio_tasks.is_empty() {
                    let app = app.clone();
                    let network = Arc::clone(&network);
                    radio_tasks.spawn_blocking(move || {
                        if let Ok(mut radio) = lock(&network.smart) {
                            let changed_radio = radio.poll(&network.fingerprint);
                            if let Ok(streams) = radio.take_incoming() {
                                if let Ok(mut incoming) = lock(&network.ble_incoming) {
                                    let capacity = 4usize.saturating_sub(incoming.len());
                                    incoming.extend(streams.into_iter().take(capacity));
                                }
                            }
                            drop(radio);
                            if changed_radio { changed(&app); }
                        }
                    });
                }
                if let (Some(udp), Some(packet)) = (&udp, &announcement) {
                    let mut result = lan::announce(udp, packet).await;
                    if let Some(packet) = &enriched {
                        let enriched_result = lan::announce(udp, packet).await;
                        result = result.and(enriched_result);
                    }
                    // A broadcast leaves on the default route only. A phone that
                    // hosts a hotspot usually has none on that interface, so it
                    // hears its guests but they never hear it. Answer every device
                    // heard on the LAN directly, which makes discovery two-way on
                    // hotspots and on networks that filter broadcasts one way.
                    let heard: Vec<Ipv4Addr> = lock(&network.discovery)
                        .map(|discovery| discovery.peers.values().map(|peer| *peer.address.ip()).collect())
                        .unwrap_or_default();
                    let mut answered = false;
                    for ip in heard.into_iter().take(32) {
                        answered |= lan::announce_to(udp, packet, ip).await.is_ok();
                        if let Some(packet) = &enriched {
                            let _ = lan::announce_to(udp, packet, ip).await;
                        }
                    }
                    // Reaching devices directly is not a broadcast failure to report.
                    if answered {
                        result = Ok(());
                    }
                    if let Ok(mut status) = lock(&network.error) {
                        let next = result.err().map(|error| format!("LAN broadcast unavailable: {error}"));
                        if *status != next {
                            *status = next;
                            changed(&app);
                        }
                    }
                }
            }
            result = async {
                match &udp {
                    Some(socket) => socket.recv_from(&mut bytes).await,
                    None => std::future::pending().await,
                }
            } => {
                match result {
                    Ok((len, source)) => {
                        observed |= lock(&network.discovery)
                            .is_ok_and(|mut value| value.observe(&bytes[..len], source, &network.fingerprint));
                    }
                    Err(error) => {
                        udp = None;
                        network.lan_receiver.store(false, Ordering::Relaxed);
                        if let Ok(mut discovery) = lock(&network.discovery) {
                            discovery.peers.clear();
                        }
                        if let Ok(mut status) = lock(&network.error) {
                            *status = Some(format!("LAN discovery was interrupted. Check the local network and try again. ({error})"));
                        }
                        changed(&app);
                    }
                }
            }
            result = listener.accept(), if accepted.len() < MAX_INBOUND => {
                match result {
                    Ok((stream, source)) => {
                        let Some(address) = lan::lan_address(source) else { continue };
                        let source = *address.ip();
                        let Some(inbound) = admit(&incoming_by_ip, source) else { continue };
                        let app = app.clone();
                        let network = Arc::clone(&network);
                        accepted.spawn(async move {
                            let _inbound = inbound;
                            let _ = stream.set_nodelay(true);
                            let _ = super::commands::serve(&app, &network, stream).await;
                        });
                    }
                    Err(_) => break,
                }
            }
            _ = accepted.join_next(), if !accepted.is_empty() => {}
            _ = radio_tasks.join_next(), if !radio_tasks.is_empty() => {}
        }
    }
    network.stop();
    changed(&app);
    accepted.shutdown().await;
    while radio_tasks.join_next().await.is_some() {}
    let radio = Arc::clone(&network);
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(mut radio) = lock(&radio.smart) {
            radio.stop();
        }
    })
    .await;
    changed(&app);
}

struct Inbound(Arc<Mutex<HashMap<Ipv4Addr, usize>>>, Ipv4Addr);

fn admit(counts: &Arc<Mutex<HashMap<Ipv4Addr, usize>>>, source: Ipv4Addr) -> Option<Inbound> {
    let mut counts_locked = counts.lock().ok()?;
    let count = counts_locked.entry(source).or_default();
    if *count >= MAX_INBOUND_PER_IP {
        return None;
    }
    *count += 1;
    Some(Inbound(Arc::clone(counts), source))
}

impl Drop for Inbound {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.0.lock() {
            if let Some(count) = counts.get_mut(&self.1) {
                *count -= 1;
                if *count == 0 {
                    counts.remove(&self.1);
                }
            }
        }
    }
}

fn network_io(error: std::io::Error) -> QGuardError {
    QGuardError::Storage(format!("Local networking could not start: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_lan_route_precedes_stale_manual_and_ble_hints_without_duplicates() {
        let live = "192.168.42.1:40000".parse().unwrap();
        let stale = "192.168.1.5:40000".parse().unwrap();
        let hint = "192.168.42.2:40000".parse().unwrap();
        assert_eq!(
            route_endpoints(Some(stale), Some(live), &[hint, live, stale]),
            vec![live, stale, hint]
        );
        assert_eq!(route_endpoints(None, None, &[]), vec![]);
    }

    #[test]
    fn bluetooth_discovery_does_not_imply_trust_or_wifi_reachability() {
        let id = "bb".repeat(32);
        let peers = HashMap::from([(
            id.clone(),
            smart::Observation {
                last_seen: 100,
                rssi: Some(-58),
                endpoints: Vec::new(),
                address: "radio-handle".into(),
                ble_mesh: true,
                label: Some("Nearby phone".into()),
                platform: Some("android".into()),
                picture: None,
            },
        )]);
        let status = peer_status(&TrustBook::default(), None, Some(&peers), None);
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].fingerprint, id);
        assert_eq!(status[0].discovery, vec!["ble"]);
        assert!(status[0].ble_mesh);
        assert!(!status[0].trusted);
        assert_eq!(status[0].label.as_deref(), Some("Nearby phone"));
        assert_eq!(status[0].platform.as_deref(), Some("android"));
        assert_eq!(status[0].address, None);
        assert_eq!(status[0].authenticated_at, None);
    }
}
