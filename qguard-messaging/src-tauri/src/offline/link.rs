//! Direct Wi-Fi link: a private Wi-Fi network between two paired devices that
//! share only Bluetooth, so XFER can move files at Wi-Fi speed.
//!
//! File data never crosses Bluetooth (too slow for files). When a transfer has
//! been accepted and neither device can reach the other over a local network,
//! the two devices agree over their authenticated persistent channel (the
//! hybrid post-quantum session that already carries Mesh) that one of them
//! hosts a temporary network:
//!
//! * The host is the Android device when exactly one side is Android (Android
//!   hosts a local-only hotspot without leaving its own network), otherwise
//!   the device with the smaller fingerprint. Both sides compute the same
//!   answer, so they never wait for each other.
//! * The host starts its hotspot and sends the network name, passphrase and
//!   its addresses over the channel (`LinkOffer`). Nothing about the network
//!   is ever advertised over Bluetooth discovery.
//! * The joiner asks its user (Windows joins automatically after that; other
//!   platforms show the network to join in system settings), then dials the
//!   host. Every transfer session on the new network is a normal QHCE session:
//!   the link adds a route, never trust.
//! * When no transfer has been pending between the pair for a while, the host
//!   closes the hotspot and the joiner returns to its previous Wi-Fi network.

use std::{
    collections::HashMap,
    net::SocketAddrV4,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::Serialize;
use tauri::{AppHandle, Manager};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::{
    error::{QGuardError, Result},
    state::AppState,
};

use super::{
    alerts, commands, diag,
    network::{changed, lock, Network, Runtime},
    profile::TrustBook,
    transfer,
    wire::Control,
    xfer::{Direction, Status},
};

const HOST_START_TIMEOUT: Duration = Duration::from_secs(40);
const REACH_TIMEOUT: Duration = Duration::from_secs(30);
const MANUAL_JOIN_WINDOW: Duration = Duration::from_secs(10 * 60);
/// No transfer pending between the pair for this long: close the link.
const IDLE_CLOSE: Duration = Duration::from_secs(90);
/// A link that never got going (peer gone, prompt ignored) is dropped.
const STALE_SETUP: Duration = Duration::from_secs(5 * 60);
const RETRY_FAILED_AFTER: Duration = Duration::from_secs(30);
const MAX_ADDRESSES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum LinkState {
    /// Asked the peer to host.
    Requested,
    /// Starting the local hotspot.
    Starting,
    /// Hotspot up, details sent: waiting for the peer to join.
    Hosting,
    /// The peer's network is known: waiting for this user's consent.
    JoinPrompt,
    /// Joining the peer's network.
    Joining,
    /// This platform cannot join by itself: the user joins in settings.
    Manual,
    /// Files can flow over the link.
    Connected,
    Failed,
    Declined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Role {
    Host,
    Join,
}

/// What the views show about the Wi-Fi link to one peer.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LinkView {
    state: LinkState,
    role: Role,
    /// The network to join, only when this user must join it by hand.
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    passphrase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// This platform joins by itself once the user agrees.
    automatic_join: bool,
}

struct Credentials {
    ssid: String,
    passphrase: Zeroizing<String>,
    security: Option<String>,
}

struct Link {
    role: Role,
    state: LinkState,
    credentials: Option<Credentials>,
    host_addresses: Vec<SocketAddrV4>,
    error: Option<String>,
    updated: Instant,
    idle_since: Option<Instant>,
    #[cfg(windows)]
    joined: Option<super::smart::windows_join::Joined>,
}

impl Link {
    fn new(role: Role, state: LinkState) -> Self {
        Self {
            role,
            state,
            credentials: None,
            host_addresses: Vec::new(),
            error: None,
            updated: Instant::now(),
            idle_since: None,
            #[cfg(windows)]
            joined: None,
        }
    }

    fn set(&mut self, state: LinkState, error: Option<String>) {
        self.state = state;
        self.error = error;
        self.updated = Instant::now();
    }
}

/// What the receiver last said about an offer sent over the channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum OfferState {
    Awaiting,
    Accepted,
    Declined,
    Complete,
    IntegrityFailed,
}

#[derive(Default)]
pub(super) struct Links {
    links: Mutex<HashMap<String, Link>>,
    /// Offers sent over a channel: when, and the receiver's last answer.
    offers: Mutex<HashMap<uuid::Uuid, (Instant, Option<OfferState>)>>,
}

/// Android hosts when exactly one side is Android; otherwise the smaller
/// fingerprint does. Both devices compute the same answer.
pub(super) fn local_hosts(local_platform: &str, peer_platform: Option<&str>, local: &str, peer: &str) -> bool {
    match (local_platform == "android", peer_platform == Some("android")) {
        (true, false) => true,
        (false, true) => false,
        _ => local < peer,
    }
}

fn automatic_join() -> bool {
    cfg!(windows)
}

fn link_error(message: impl Into<String>) -> QGuardError {
    QGuardError::Storage(message.into())
}

/// Private addresses the host offered, with its listening port.
pub(super) fn valid_addresses(addresses: &[SocketAddrV4]) -> Vec<SocketAddrV4> {
    let mut valid = Vec::new();
    for address in addresses.iter().take(MAX_ADDRESSES) {
        let ip = address.ip();
        if (ip.is_private() || ip.is_link_local()) && address.port() != 0 && !valid.contains(address) {
            valid.push(*address);
        }
    }
    valid
}

impl Links {
    /// Extra routes to a peer that a connected link provides.
    pub fn endpoints(&self, peer: &str) -> Vec<SocketAddrV4> {
        self.links.lock().map_or_else(|_| Vec::new(), |links| {
            links
                .get(peer)
                .filter(|link| link.role == Role::Join && matches!(link.state, LinkState::Connected | LinkState::Manual | LinkState::Joining))
                .map(|link| link.host_addresses.clone())
                .unwrap_or_default()
        })
    }

    pub fn view(&self, peer: &str) -> Option<LinkView> {
        let links = self.links.lock().ok()?;
        let link = links.get(peer)?;
        let manual = link.role == Role::Join && link.state == LinkState::Manual;
        Some(LinkView {
            state: link.state,
            role: link.role,
            network: manual.then(|| link.credentials.as_ref().map(|c| c.ssid.clone())).flatten(),
            passphrase: manual.then(|| link.credentials.as_ref().map(|c| c.passphrase.to_string())).flatten(),
            error: link.error.clone(),
            automatic_join: automatic_join(),
        })
    }

    /// The receiver's last answer to an offer sent over a channel.
    pub fn offer_state(&self, id: uuid::Uuid) -> Option<OfferState> {
        self.offers.lock().ok()?.get(&id).and_then(|(_, state)| *state)
    }

    fn should_offer(&self, id: uuid::Uuid) -> bool {
        let Ok(mut offers) = self.offers.lock() else { return false };
        match offers.get(&id) {
            // Re-offer now and then: the receiver may have restarted.
            Some((sent, _)) if sent.elapsed() < Duration::from_secs(30) => false,
            Some((_, state)) => {
                let state = *state;
                offers.insert(id, (Instant::now(), state));
                true
            }
            None => {
                offers.insert(id, (Instant::now(), None));
                true
            }
        }
    }

    pub fn record_offer_state(&self, id: uuid::Uuid, state: OfferState) {
        if let Ok(mut offers) = self.offers.lock() {
            let sent = offers.get(&id).map_or_else(Instant::now, |(sent, _)| *sent);
            offers.insert(id, (sent, Some(state)));
        }
    }

    fn update(&self, peer: &str, change: impl FnOnce(&mut Link)) -> bool {
        self.links.lock().is_ok_and(|mut links| match links.get_mut(peer) {
            Some(link) => {
                change(link);
                true
            }
            None => false,
        })
    }

    fn remove(&self, peer: &str) -> Option<Link> {
        self.links.lock().ok()?.remove(peer)
    }

    fn hosting_others(&self, peer: &str) -> bool {
        self.links.lock().is_ok_and(|links| {
            links.iter().any(|(other, link)| other != peer && link.role == Role::Host
                && matches!(link.state, LinkState::Starting | LinkState::Hosting | LinkState::Connected))
        })
    }
}

fn peer_platform(app: &AppHandle, network: &Network, peer: &str) -> Option<String> {
    let runtime = app.state::<Runtime>();
    let _gate = lock(&runtime.storage).ok()?;
    let book = TrustBook::load(&app.state::<AppState>(), &network.owner).ok()?;
    book.peers.get(peer)?.paired.as_ref().map(|identity| identity.platform.clone())
}

/// A transfer with this peer is accepted but no local network reaches it:
/// set up a Wi-Fi link (idempotent).
pub(super) fn need(app: &AppHandle, network: &Arc<Network>, peer: &str) {
    if !network.channels.supports_links(peer) {
        return;
    }
    let platform = peer_platform(app, network, peer);
    let hosts = local_hosts(std::env::consts::OS, platform.as_deref(), &network.fingerprint, peer);
    let start = network.links.links.lock().is_ok_and(|mut links| {
        if let Some(existing) = links.get(peer) {
            let retry = matches!(existing.state, LinkState::Failed) && existing.updated.elapsed() >= RETRY_FAILED_AFTER;
            if !retry {
                return false;
            }
        }
        let state = if hosts { LinkState::Starting } else { LinkState::Requested };
        links.insert(peer.to_owned(), Link::new(if hosts { Role::Host } else { Role::Join }, state));
        true
    });
    if !start {
        return;
    }
    diag::record_detail(app, "wifi_link_needed", diag::Subject::peer(peer), if hosts { "this device hosts" } else { "asked the other device to host" });
    changed(app);
    if hosts {
        host(app, network, peer);
    } else if !network.channels.send_frame(peer, Control::LinkRequest) {
        network.links.update(peer, |link| link.set(LinkState::Failed, Some("The Bluetooth link to the other device closed.".into())));
        changed(app);
    }
}

/// The peer asked this device to host.
pub(super) fn requested(app: &AppHandle, network: &Arc<Network>, peer: &str) {
    let resend = network.links.links.lock().is_ok_and(|mut links| {
        match links.get(peer).map(|link| (link.role, link.state)) {
            Some((Role::Host, LinkState::Starting)) => false,
            Some((Role::Host, LinkState::Hosting | LinkState::Connected)) => true,
            _ => {
                links.insert(peer.to_owned(), Link::new(Role::Host, LinkState::Starting));
                true
            }
        }
    });
    if resend {
        diag::record(app, "wifi_link_requested", diag::Subject::peer(peer));
        changed(app);
        host(app, network, peer);
    }
}

fn host(app: &AppHandle, network: &Arc<Network>, peer: &str) {
    let app = app.clone();
    let network = Arc::clone(network);
    let peer = peer.to_owned();
    tauri::async_runtime::spawn(async move {
        let outcome = start_host(&app, &network).await;
        match outcome {
            Ok((ssid, passphrase, security, addresses)) => {
                let frame = Control::LinkOffer { ssid, password: passphrase.to_string(), security, addresses };
                if network.channels.send_frame(&peer, frame) {
                    network.links.update(&peer, |link| link.set(LinkState::Hosting, None));
                    diag::record(&app, "wifi_link_hosting", diag::Subject::peer(&peer));
                } else {
                    network.links.update(&peer, |link| link.set(LinkState::Failed, Some("The Bluetooth link to the other device closed.".into())));
                }
            }
            Err(error) => {
                let reason = error.to_string();
                network.links.update(&peer, |link| link.set(LinkState::Failed, Some(reason.clone())));
                let _ = network.channels.send_frame(&peer, Control::LinkFailed { reason: reason.clone() });
                diag::record_detail(&app, "wifi_link_failed", diag::Subject::peer(&peer), reason);
            }
        }
        changed(&app);
    });
}

async fn start_host(app: &AppHandle, network: &Arc<Network>) -> Result<(String, Zeroizing<String>, Option<String>, Vec<SocketAddrV4>)> {
    let worker = Arc::clone(network);
    let checker = app.clone();
    tokio::task::spawn_blocking(move || {
        let mut smart = lock(&worker.smart)?;
        worker.check(&checker)?;
        smart.start_hotspot()
    })
    .await
    .map_err(|_| link_error("The Wi-Fi link could not start."))??;
    let deadline = Instant::now() + HOST_START_TIMEOUT;
    loop {
        let worker = Arc::clone(network);
        let (details, error) = tokio::task::spawn_blocking(move || {
            let mut smart = lock(&worker.smart)?;
            Ok::<_, QGuardError>((smart.hotspot_details()?, smart.hotspot_error()))
        })
        .await
        .map_err(|_| link_error("The Wi-Fi link could not start."))??;
        if let Some(details) = details {
            let addresses = valid_addresses(
                &details.addresses.iter().map(|ip| SocketAddrV4::new(*ip, network.port)).collect::<Vec<_>>(),
            );
            return Ok((details.ssid, Zeroizing::new(details.password), details.security, addresses));
        }
        if let Some(error) = error {
            return Err(link_error(error));
        }
        if Instant::now() >= deadline {
            return Err(link_error("The Wi-Fi link did not start in time. Check that Wi-Fi is on and retry."));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// The host sent its network: ask this user (or show it), then join.
pub(super) fn offered(
    app: &AppHandle,
    network: &Arc<Network>,
    peer: &str,
    ssid: String,
    passphrase: String,
    security: Option<String>,
    addresses: Vec<SocketAddrV4>,
) {
    let passphrase = Zeroizing::new(passphrase);
    let addresses = valid_addresses(&addresses);
    if ssid.is_empty() || ssid.len() > 32 || passphrase.len() < 8 || passphrase.len() > 63 || addresses.is_empty() {
        let _ = network.channels.send_frame(peer, Control::LinkFailed { reason: "The Wi-Fi link details were invalid.".into() });
        return;
    }
    let security = security.filter(|value| matches!(value.as_str(), "wpa2" | "wpa3" | "wpa3-transition"));
    let state = if automatic_join() { LinkState::JoinPrompt } else { LinkState::Manual };
    let fresh = network.links.links.lock().is_ok_and(|mut links| {
        let link = links.entry(peer.to_owned()).or_insert_with(|| Link::new(Role::Join, state));
        let fresh = link.credentials.as_ref().is_none_or(|current| current.ssid != ssid);
        link.role = Role::Join;
        if fresh || !matches!(link.state, LinkState::Joining | LinkState::Connected) {
            link.set(state, None);
        }
        link.credentials = Some(Credentials { ssid: ssid.clone(), passphrase: passphrase.clone(), security });
        link.host_addresses = addresses.clone();
        fresh
    });
    diag::record(app, "wifi_link_offered", diag::Subject::peer(peer));
    alerts::wifi_link(app, &network.owner, peer, automatic_join());
    changed(app);
    if fresh && !automatic_join() {
        probe_until_reachable(app, network, peer, addresses, MANUAL_JOIN_WINDOW);
    }
}

/// This user agreed (or declined) to join the peer's network.
pub(super) async fn join(app: &AppHandle, network: &Arc<Network>, peer: &str, accept: bool) -> Result<()> {
    if !accept {
        network.links.update(peer, |link| link.set(LinkState::Declined, None));
        let _ = network.channels.send_frame(peer, Control::LinkFailed { reason: "The other user did not join the Wi-Fi link.".into() });
        changed(app);
        return Ok(());
    }
    let credentials = network.links.links.lock().ok().and_then(|links| {
        links.get(peer).and_then(|link| link.credentials.as_ref().map(|c| (c.ssid.clone(), c.passphrase.clone(), c.security.clone(), link.host_addresses.clone())))
    });
    let Some((ssid, passphrase, security, addresses)) = credentials else {
        return Err(QGuardError::NotFound("There is no Wi-Fi link to join for this device.".into()));
    };
    network.links.update(peer, |link| link.set(LinkState::Joining, None));
    changed(app);
    #[cfg(windows)]
    {
        let joined = tokio::task::spawn_blocking(move || {
            super::smart::windows_join::join(&ssid, &passphrase, security.as_deref())
        })
        .await
        .map_err(|_| link_error("The PC could not join the Wi-Fi link."))?;
        match joined {
            Ok(joined) => {
                network.links.update(peer, |link| link.joined = Some(joined));
            }
            Err(error) => {
                let reason = error.to_string();
                network.links.update(peer, |link| link.set(LinkState::Failed, Some(reason.clone())));
                let _ = network.channels.send_frame(peer, Control::LinkFailed { reason: reason.clone() });
                changed(app);
                return Err(error);
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (ssid, passphrase, security);
        network.links.update(peer, |link| link.set(LinkState::Manual, None));
    }
    probe_until_reachable(app, network, peer, addresses, REACH_TIMEOUT);
    Ok(())
}

/// Dial the host until a TCP path exists, then hand it to the transfers.
fn probe_until_reachable(app: &AppHandle, network: &Arc<Network>, peer: &str, addresses: Vec<SocketAddrV4>, window: Duration) {
    let app = app.clone();
    let network = Arc::clone(network);
    let peer = peer.to_owned();
    tauri::async_runtime::spawn(async move {
        let deadline = Instant::now() + window;
        loop {
            let still_wanted = network.links.links.lock().is_ok_and(|links| {
                links.get(&peer).is_some_and(|link| matches!(link.state, LinkState::Joining | LinkState::Manual))
            });
            if !still_wanted {
                return;
            }
            for address in &addresses {
                if let Ok(Ok(_stream)) = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(*address)).await {
                    connected(&app, &network, &peer);
                    return;
                }
            }
            if Instant::now() >= deadline {
                let reason = "The other device's Wi-Fi link could not be reached.".to_string();
                network.links.update(&peer, |link| link.set(LinkState::Failed, Some(reason.clone())));
                let _ = network.channels.send_frame(&peer, Control::LinkFailed { reason });
                changed(&app);
                return;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

fn connected(app: &AppHandle, network: &Arc<Network>, peer: &str) {
    network.links.update(peer, |link| {
        link.set(LinkState::Connected, None);
        link.idle_since = None;
    });
    let _ = network.channels.send_frame(peer, Control::LinkJoined);
    diag::record(app, "wifi_link_connected", diag::Subject::peer(peer));
    changed(app);
    // The joiner starts every transfer: it can reach the host, not always the
    // other way round. A receiver asks for its accepted files; a sender
    // offers its queued ones.
    commands::schedule_queued_transfers(app, network);
    commands::resume_accepted_from(app, network, peer);
}

/// The joiner reached this device's network.
pub(super) fn joined_by_peer(app: &AppHandle, network: &Network, peer: &str) {
    network.links.update(peer, |link| {
        if link.role == Role::Host {
            link.set(LinkState::Connected, None);
            link.idle_since = None;
        }
    });
    diag::record(app, "wifi_link_peer_joined", diag::Subject::peer(peer));
    changed(app);
}

/// The peer could not host or join.
pub(super) fn failed_by_peer(app: &AppHandle, network: &Arc<Network>, peer: &str, reason: String) {
    let reason: String = reason.chars().take(200).collect();
    let role = network.links.links.lock().ok().and_then(|links| links.get(peer).map(|link| link.role));
    network.links.update(peer, |link| link.set(LinkState::Failed, Some(reason.clone())));
    if role == Some(Role::Host) {
        stop_hosting(app, network, peer);
    }
    diag::record_detail(app, "wifi_link_failed", diag::Subject::peer(peer), reason);
    changed(app);
}

/// The peer ended the link.
pub(super) fn closed_by_peer(app: &AppHandle, network: &Arc<Network>, peer: &str) {
    teardown(app, network, peer, false);
}

/// Close the link from this side (the user cancelled, or it went idle).
pub(super) fn close(app: &AppHandle, network: &Arc<Network>, peer: &str) {
    teardown(app, network, peer, true);
}

fn teardown(app: &AppHandle, network: &Arc<Network>, peer: &str, tell_peer: bool) {
    let Some(link) = network.links.remove(peer) else { return };
    if tell_peer {
        let _ = network.channels.send_frame(peer, Control::LinkClose);
    }
    if link.role == Role::Host {
        stop_hosting(app, network, peer);
    }
    #[cfg(windows)]
    if let Some(joined) = link.joined {
        tauri::async_runtime::spawn_blocking(move || super::smart::windows_join::restore(&joined));
    }
    diag::record(app, "wifi_link_closed", diag::Subject::peer(peer));
    changed(app);
}

fn stop_hosting(app: &AppHandle, network: &Arc<Network>, peer: &str) {
    if network.links.hosting_others(peer) {
        return;
    }
    let worker = Arc::clone(network);
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if let Ok(mut smart) = lock(&worker.smart) {
            smart.stop_hotspot();
        }
        changed(&app);
    });
}

/// Restore the PC's Wi-Fi and stop hosting when local networking stops.
pub(super) fn shutdown(network: &Network) {
    let Ok(mut links) = network.links.links.lock() else { return };
    for (_, link) in links.drain() {
        #[cfg(windows)]
        if let Some(joined) = link.joined {
            super::smart::windows_join::restore(&joined);
        }
        let _ = link;
    }
}

/// Close idle links and drop ones that never got going. Runs on each beacon.
pub(super) fn maintain(app: &AppHandle, network: &Arc<Network>) {
    let peers: Vec<(String, LinkState, Instant, Option<Instant>)> = network.links.links.lock().map_or_else(
        |_| Vec::new(),
        |links| links.iter().map(|(peer, link)| (peer.clone(), link.state, link.updated, link.idle_since)).collect(),
    );
    if peers.is_empty() {
        return;
    }
    let Ok(records) = transfer::with_store(app, &network.owner, |store| store.list()) else { return };
    for (peer, state, updated, idle_since) in peers {
        match state {
            LinkState::Connected | LinkState::Hosting => {
                let busy = records.iter().any(|record| {
                    let counterpart = match record.direction {
                        Direction::Incoming => &record.manifest.sender,
                        Direction::Outgoing => &record.manifest.recipient,
                    };
                    counterpart == &peer
                        && matches!(record.status, Status::Ready | Status::Transferring | Status::Interrupted | Status::AwaitingConsent)
                });
                if busy {
                    network.links.update(&peer, |link| link.idle_since = None);
                } else if idle_since.is_some_and(|since| since.elapsed() >= IDLE_CLOSE) {
                    close(app, network, &peer);
                } else if idle_since.is_none() {
                    network.links.update(&peer, |link| link.idle_since = Some(Instant::now()));
                }
            }
            LinkState::Failed | LinkState::Declined => {
                if updated.elapsed() >= STALE_SETUP {
                    network.links.remove(&peer);
                    changed(app);
                }
            }
            _ => {
                if updated.elapsed() >= STALE_SETUP {
                    close(app, network, &peer);
                }
            }
        }
    }
}

/// The sender could not reach the receiver: offer over the channel instead,
/// and set up a link once the receiver has accepted. True when handled.
pub(super) fn sender_fallback(app: &AppHandle, network: &Arc<Network>, peer: &str, id: uuid::Uuid) -> bool {
    if !network.channels.supports_links(peer) {
        return false;
    }
    if network.links.offer_state(id) == Some(OfferState::Accepted) {
        need(app, network, peer);
        return true;
    }
    if network.links.should_offer(id) {
        let manifest = transfer::with_store(app, &network.owner, move |store| {
            let record = store.get(id)?;
            anyhow::ensure!(record.direction == Direction::Outgoing, "not an outgoing transfer");
            Ok(record.manifest)
        });
        let Ok(manifest) = manifest else { return false };
        if !network.channels.send_frame(peer, Control::ChannelOffer(manifest)) {
            return false;
        }
        diag::record_detail(app, "transfer_offer_sent_on_channel", diag::Subject::peer(peer), format!("transfer {id}"));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn both_devices_agree_on_who_hosts() {
        let small = "aa".repeat(32);
        let large = "bb".repeat(32);
        // Exactly one Android: it hosts, seen from either side.
        assert!(local_hosts("android", Some("windows"), &large, &small));
        assert!(!local_hosts("windows", Some("android"), &small, &large));
        // Same platform: the smaller fingerprint hosts, and only one side does.
        assert!(local_hosts("windows", Some("windows"), &small, &large));
        assert!(!local_hosts("windows", Some("windows"), &large, &small));
        assert!(local_hosts("android", Some("android"), &small, &large));
        assert!(!local_hosts("android", Some("android"), &large, &small));
        // Unknown peer platform: deterministic by fingerprint.
        assert_ne!(local_hosts("windows", None, &small, &large), local_hosts("windows", None, &large, &small));
    }

    #[test]
    fn only_private_addresses_with_a_port_are_dialed() {
        let addresses = [
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 49, 1), 41000),
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 41000),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 0),
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 49, 1), 41000),
            SocketAddrV4::new(Ipv4Addr::new(169, 254, 3, 4), 41000),
        ];
        assert_eq!(valid_addresses(&addresses), vec![addresses[0], addresses[4]]);
    }

    #[test]
    fn an_offer_is_resent_only_after_a_pause_and_keeps_the_answer() {
        let links = Links::default();
        let id = uuid::Uuid::new_v4();
        assert!(links.should_offer(id));
        assert!(!links.should_offer(id));
        links.record_offer_state(id, OfferState::Accepted);
        assert_eq!(links.offer_state(id), Some(OfferState::Accepted));
    }

    #[test]
    fn the_view_reveals_the_network_only_to_a_manual_joiner() {
        let links = Links::default();
        let peer = "cc".repeat(32);
        let mut link = Link::new(Role::Join, LinkState::JoinPrompt);
        link.credentials = Some(Credentials { ssid: "AndroidShare_1234".into(), passphrase: Zeroizing::new("secret-pass".into()), security: None });
        links.links.lock().unwrap().insert(peer.clone(), link);
        let view = links.view(&peer).unwrap();
        assert!(view.network.is_none() && view.passphrase.is_none());
        links.update(&peer, |link| link.set(LinkState::Manual, None));
        let view = links.view(&peer).unwrap();
        assert_eq!(view.network.as_deref(), Some("AndroidShare_1234"));
        assert_eq!(view.passphrase.as_deref(), Some("secret-pass"));
    }
}
