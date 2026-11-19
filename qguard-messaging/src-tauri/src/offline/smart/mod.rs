//! Bluetooth discovers peers and shares public connection hints. Hints do not
//! authenticate an identity or authorize sending. QHCE does that on the
//! selected transport using the user's pinned fingerprint.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{QGuardError, Result};

use super::{
    lan::{fingerprint_valid, lan_address},
    profile::{valid_device_label, PeerMetadata, PEER_PLATFORMS},
};

#[cfg(target_os = "android")]
mod android;
mod ble_link;
mod hotspot;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(super) mod windows_join;
#[cfg(windows)]
mod windows_wifi;

const VERSION: u8 = 1;
const MAX_METADATA: usize = 512;
const MAX_PEERS: usize = 128;
const MAX_ENDPOINTS: usize = 8;
const PEER_TTL_SECONDS: i64 = 20;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct RadioPeer {
    pub address: String,
    pub metadata: String,
    pub last_seen: i64,
    /// Received signal strength in dBm, when the radio reports it.
    #[serde(default)]
    pub rssi: Option<i16>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct RadioSnapshot {
    pub available: bool,
    pub permission_granted: bool,
    pub scanning: bool,
    pub advertising: bool,
    pub error: Option<String>,
    pub peers: Vec<RadioPeer>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SmartStatus {
    bluetooth_available: bool,
    bluetooth_permission_granted: bool,
    bluetooth_running: bool,
    bluetooth_scanning: bool,
    bluetooth_advertising: bool,
    bluetooth_error: Option<String>,
    hotspot_available: bool,
    hotspot_active: bool,
    hotspot_starting: bool,
    hotspot_error: Option<String>,
}

#[derive(Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct HotspotSnapshot {
    pub available: bool,
    pub active: bool,
    pub starting: bool,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct HotspotDetails {
    pub ssid: String,
    pub password: String,
    /// "wpa2", "wpa3-transition" or "wpa3", when the host reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    /// The host's private IPv4 addresses, including the one on this network.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<Ipv4Addr>,
}

impl SmartStatus {
    pub(super) fn bluetooth_running(&self) -> bool {
        self.bluetooth_running
    }

    pub(super) fn bluetooth_scanning(&self) -> bool {
        self.bluetooth_scanning
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Metadata {
    version: u8,
    fingerprint: String,
    port: u16,
    addresses: Vec<Ipv4Addr>,
    #[serde(default)]
    ble_mesh: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    platform: Option<String>,
    /// First 16 hex digits of the SHA3-256 of the owner's picture, only when
    /// the owner chose to show it to nearby devices before pairing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    picture: Option<String>,
}

/// A nearby picture fingerprint: 16 lowercase hex digits.
pub(super) fn valid_picture_tag(tag: &str) -> bool {
    tag.len() == 16 && tag.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

impl Metadata {
    fn local(fingerprint: &str, port: u16, identity: &PeerMetadata, picture: Option<&str>) -> Result<String> {
        let include_hints = identity.validate().is_ok();
        serde_json::to_string(&Self {
            version: VERSION,
            fingerprint: fingerprint.into(),
            port,
            addresses: Vec::new(),
            ble_mesh: true,
            label: include_hints.then(|| identity.label.clone()),
            platform: include_hints.then(|| identity.platform.clone()),
            picture: picture.filter(|tag| valid_picture_tag(tag)).map(str::to_owned),
        })
        .map_err(|_| QGuardError::Storage("Could not encode local discovery metadata.".into()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Observation {
    pub last_seen: i64,
    pub rssi: Option<i16>,
    pub endpoints: Vec<SocketAddrV4>,
    pub address: String,
    pub ble_mesh: bool,
    pub label: Option<String>,
    pub platform: Option<String>,
    /// The picture fingerprint the device advertises (opt-in, before pairing).
    pub picture: Option<String>,
}

#[cfg(target_os = "android")]
pub(super) use android::Connector;
#[cfg(target_os = "android")]
use android::Radio;
#[cfg(windows)]
pub(super) use windows::Connector;
#[cfg(windows)]
use windows::Radio;

#[derive(Default)]
pub(super) struct SmartConnect {
    #[cfg(any(target_os = "android", windows))]
    radio: Option<Radio>,
    hotspot: Option<hotspot::Host>,
    status: SmartStatus,
    pub peers: HashMap<String, Observation>,
}

impl SmartConnect {
    #[cfg(any(target_os = "android", windows))]
    pub fn connector(&self, fingerprint: &str) -> Option<(Connector, String)> {
        let peer = self.peers.get(fingerprint).filter(|peer| peer.ble_mesh)?;
        Some((self.radio.as_ref()?.connector(), peer.address.clone()))
    }

    pub fn take_incoming(&self) -> Result<Vec<tokio::io::DuplexStream>> {
        #[cfg(any(target_os = "android", windows))]
        return self
            .radio
            .as_ref()
            .map_or(Ok(Vec::new()), |radio| radio.take_incoming());
        #[cfg(not(any(target_os = "android", windows)))]
        Ok(Vec::new())
    }
    pub fn status(&self) -> SmartStatus {
        self.status.clone()
    }

    pub fn restart(&mut self, fingerprint: &str, port: u16, identity: &PeerMetadata, picture: Option<&str>) {
        #[cfg(any(target_os = "android", windows))]
        {
            self.radio = None;
        }
        self.peers.clear();
        self.status.bluetooth_available = false;
        self.status.bluetooth_permission_granted = false;
        self.status.bluetooth_running = false;
        self.status.bluetooth_scanning = false;
        self.status.bluetooth_advertising = false;
        self.status.bluetooth_error = None;
        #[cfg(any(target_os = "android", windows))]
        {
            match Metadata::local(fingerprint, port, identity, picture)
                .and_then(|metadata| Radio::start(&metadata))
            {
                Ok(radio) => {
                    self.radio = Some(radio);
                    self.poll(fingerprint);
                }
                Err(error) => self.status.bluetooth_error = Some(error.to_string()),
            }
        }
        #[cfg(not(any(target_os = "android", windows)))]
        {
            let _ = (fingerprint, port, identity, picture);
            self.status.bluetooth_error =
                Some("Bluetooth discovery is unavailable on this platform.".into());
        }
    }

    pub fn stop(&mut self) {
        #[cfg(any(target_os = "android", windows))]
        {
            self.radio = None;
        }
        self.hotspot = None;
        self.status = SmartStatus::default();
        self.peers.clear();
    }

    pub fn poll(&mut self, fingerprint: &str) -> bool {
        let mut changed = self.poll_hotspot();
        #[cfg(any(target_os = "android", windows))]
        if let Some(radio) = &self.radio {
            let next = match radio.snapshot() {
                Ok(snapshot) => snapshot,
                Err(error) => RadioSnapshot {
                    error: Some(error.to_string()),
                    ..RadioSnapshot::default()
                },
            };
            changed |= self.apply(next, fingerprint, Utc::now().timestamp());
        }
        let _ = fingerprint;
        changed
    }

    fn poll_hotspot(&mut self) -> bool {
        let snapshot = match &self.hotspot {
            Some(host) => host.snapshot(),
            None => hotspot::snapshot(),
        }
        .unwrap_or_else(|error| HotspotSnapshot {
            error: Some(error.to_string()),
            ..HotspotSnapshot::default()
        });
        let changed = self.status.hotspot_available != snapshot.available
            || self.status.hotspot_active != snapshot.active
            || self.status.hotspot_starting != snapshot.starting
            || self.status.hotspot_error != snapshot.error;
        self.status.hotspot_available = snapshot.available;
        self.status.hotspot_active = snapshot.active;
        self.status.hotspot_starting = snapshot.starting;
        self.status.hotspot_error = snapshot.error;
        changed
    }

    pub fn start_hotspot(&mut self) -> Result<()> {
        self.poll_hotspot();
        if !self.status.hotspot_active && !self.status.hotspot_starting {
            self.hotspot = None;
        }
        if self.hotspot.is_none() {
            self.hotspot = Some(hotspot::Host::start()?);
        }
        self.poll_hotspot();
        Ok(())
    }

    pub fn stop_hotspot(&mut self) {
        self.hotspot = None;
        self.poll_hotspot();
    }

    /// Why the local hotspot failed or stopped, if it did (refreshed now).
    pub fn hotspot_error(&mut self) -> Option<String> {
        self.poll_hotspot();
        self.status.hotspot_error.clone()
    }

    pub fn hotspot_details(&self) -> Result<Option<HotspotDetails>> {
        self.hotspot
            .as_ref()
            .map_or(Ok(None), |host| host.details())
    }

    fn apply(&mut self, snapshot: RadioSnapshot, local: &str, now: i64) -> bool {
        let peers = if snapshot.scanning {
            observations(snapshot.peers, local, now)
        } else {
            HashMap::new()
        };
        let status = SmartStatus {
            bluetooth_available: snapshot.available,
            bluetooth_permission_granted: snapshot.permission_granted,
            bluetooth_running: snapshot.scanning || snapshot.advertising,
            bluetooth_scanning: snapshot.scanning,
            bluetooth_advertising: snapshot.advertising,
            bluetooth_error: snapshot.error,
            hotspot_available: self.status.hotspot_available,
            hotspot_active: self.status.hotspot_active,
            hotspot_starting: self.status.hotspot_starting,
            hotspot_error: self.status.hotspot_error.clone(),
        };
        let changed = self.peers != peers || self.status != status;
        self.peers = peers;
        self.status = status;
        changed
    }
}

// Exercises the native ATT packet contract without requiring radio hardware.
#[cfg(test)]
pub(super) fn test_ble_pair() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        runtime::Handle,
        time::{self, Duration},
    };
    let server = Arc::new(ble_link::Server::default());
    server
        .write("test-peer", &ble_link::open(ble_link::MAX_PACKET_BYTES), &Handle::current())
        .unwrap();
    server
        .write("test-peer", ble_link::PROBE_ACK, &Handle::current())
        .unwrap();
    let remote = server.accept().unwrap().pop().unwrap();
    let (application, transport) = tokio::io::duplex(32 * 1024);
    tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(transport);
        let mut input = [0; ble_link::MAX_DATA_BYTES];
        let mut sent = 0;
        let mut received = 0;
        let mut ticks = time::interval(Duration::from_millis(1));
        loop {
            tokio::select! {
                result = read.read(&mut input) => {
                    let Ok(count) = result else { break };
                    if count == 0 { break }
                    server.write("test-peer", &ble_link::packet(sent, &input[..count]).unwrap(), &Handle::current()).unwrap();
                    sent += 1;
                }
                _ = ticks.tick() => {
                    let packet = server.read("test-peer").unwrap();
                    if packet == [0] { continue }
                    if packet == ble_link::CLOSE { break }
                    let (sequence, bytes) = ble_link::data(&packet).unwrap();
                    assert_eq!(sequence, received);
                    if write.write_all(bytes).await.is_err() { break }
                    server.write("test-peer", &ble_link::ack(sequence), &Handle::current()).unwrap();
                    received += 1;
                }
            }
        }
        server.close();
    });
    (application, remote)
}

fn observations(peers: Vec<RadioPeer>, local: &str, now: i64) -> HashMap<String, Observation> {
    let mut observations = HashMap::<String, Observation>::new();
    for peer in peers.into_iter().take(MAX_PEERS) {
        if peer.metadata.len() > MAX_METADATA
            || peer.address.is_empty()
            || peer.address.len() > 128
            || !(now.saturating_sub(PEER_TTL_SECONDS)..=now).contains(&peer.last_seen)
        {
            continue;
        }
        let Ok(hint) = serde_json::from_str::<Metadata>(&peer.metadata) else {
            continue;
        };
        if hint.version != VERSION
            || !fingerprint_valid(&hint.fingerprint)
            || hint.fingerprint == local
            || hint.port == 0
            || hint.addresses.len() > MAX_ENDPOINTS
        {
            continue;
        }
        let mut endpoints = Vec::new();
        for ip in hint.addresses {
            // A remote device cannot designate this machine's loopback address.
            if !ip.is_loopback() {
                if let Some(address) = lan_address(SocketAddrV4::new(ip, hint.port).into()) {
                    if !endpoints.contains(&address) {
                        endpoints.push(address);
                    }
                }
            }
        }
        if observations
            .get(&hint.fingerprint)
            .is_some_and(|previous| previous.last_seen > peer.last_seen)
        {
            continue;
        }
        observations.insert(
            hint.fingerprint,
            Observation {
                last_seen: peer.last_seen,
                rssi: peer.rssi.filter(|value| (-127..=20).contains(value)),
                endpoints,
                address: peer.address,
                ble_mesh: hint.ble_mesh,
                label: hint.label.filter(|label| valid_device_label(label)),
                platform: hint
                    .platform
                    .filter(|platform| PEER_PLATFORMS.contains(&platform.as_str())),
                picture: hint.picture.filter(|tag| valid_picture_tag(tag)),
            },
        );
    }
    observations
}

pub(super) fn request_permissions() -> Result<()> {
    #[cfg(target_os = "android")]
    return android::request_permissions();
    #[cfg(not(target_os = "android"))]
    Err(QGuardError::InvalidInput(
        "Manage Bluetooth access in your system settings.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(fingerprint: &str, addresses: &[&str], seen: i64) -> RadioPeer {
        RadioPeer {
            address: "native-scan-handle".into(),
            metadata: serde_json::json!({
                "version":1, "fingerprint":fingerprint, "port":45111,
                "addresses":addresses, "bleMesh":false,
            })
            .to_string(),
            last_seen: seen,
            rssi: None,
        }
    }

    #[test]
    fn a_ble_peer_without_wifi_can_be_discovered_and_only_private_endpoints_are_accepted() {
        let local = "aa".repeat(32);
        let ble = "bb".repeat(32);
        let wifi = "cc".repeat(32);
        let peers = vec![
            peer(&local, &["192.168.1.4"], 100),
            peer(&ble, &[], 100),
            peer(
                &wifi,
                &["192.168.1.4", "8.8.8.8", "127.0.0.1", "192.168.1.4"],
                100,
            ),
            peer(&"dd".repeat(32), &[], 50),
        ];
        let found = observations(peers, &local, 100);
        assert_eq!(found.len(), 2);
        assert!(found[&ble].endpoints.is_empty());
        assert_eq!(
            found[&wifi].endpoints,
            vec!["192.168.1.4:45111".parse::<SocketAddrV4>().unwrap()]
        );
    }

    #[test]
    fn ble_display_hints_are_optional_and_invalid_values_do_not_remove_discovery() {
        let local = "aa".repeat(32);
        let named = "bb".repeat(32);
        let invalid = "cc".repeat(32);
        let legacy = "dd".repeat(32);
        let with_metadata = |fingerprint: &str, label: &str, platform: &str| {
            let mut entry = peer(fingerprint, &[], 100);
            let mut metadata: serde_json::Value = serde_json::from_str(&entry.metadata).unwrap();
            metadata["label"] = label.into();
            metadata["platform"] = platform.into();
            entry.metadata = metadata.to_string();
            entry
        };
        let peers = observations(
            vec![
                with_metadata(&named, "Windows Laptop", "windows"),
                with_metadata(&invalid, "Example\u{202e}", "example"),
                peer(&legacy, &[], 100),
            ],
            &local,
            100,
        );
        assert_eq!(peers[&named].label.as_deref(), Some("Windows Laptop"));
        assert_eq!(peers[&named].platform.as_deref(), Some("windows"));
        for fingerprint in [&invalid, &legacy] {
            assert_eq!(peers[fingerprint].label, None);
            assert_eq!(peers[fingerprint].platform, None);
        }
    }

    #[test]
    fn advertising_without_scanning_does_not_report_discovered_peers() {
        let mut smart = SmartConnect::default();
        let local = "aa".repeat(32);
        let remote = "bb".repeat(32);
        assert!(smart.apply(
            RadioSnapshot {
                scanning: true,
                peers: vec![peer(&remote, &[], 100)],
                ..RadioSnapshot::default()
            },
            &local,
            100
        ));
        assert_eq!(smart.peers.len(), 1);
        assert!(smart.status().bluetooth_scanning());
        assert!(smart.apply(
            RadioSnapshot {
                advertising: true,
                peers: vec![peer(&remote, &[], 100)],
                ..RadioSnapshot::default()
            },
            &local,
            101
        ));
        assert!(smart.peers.is_empty());
        assert!(!smart.status().bluetooth_scanning());
        assert!(smart.status().bluetooth_advertising);
        assert!(smart.status().bluetooth_running());
        smart.stop();
        assert!(!smart.status().bluetooth_running());
        assert!(!smart.status().bluetooth_advertising);
    }
}

/// Hardware check against a real nearby Qguard device, not part of the
/// default suite. It scans from this computer, opens the Bluetooth stream to
/// each device found and runs the real pairing-mode QHCE handshake with a
/// throwaway identity. Nothing is trusted or stored: the session is dropped
/// right after the handshake. Run with `--ignored --nocapture`.
#[cfg(all(test, windows))]
mod live {
    use std::time::{Duration, Instant};

    use super::super::session::{Identity, Session};
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs a Bluetooth LE adapter and a nearby Qguard device with discovery on"]
    async fn pairing_handshake_reaches_a_nearby_qguard_device() {
        let me = Identity::generate().unwrap();
        let metadata = serde_json::json!({
            "version": 1, "fingerprint": me.fingerprint(), "port": 45111,
            "addresses": [], "bleMesh": true, "label": "Radio self-check", "platform": "windows",
        })
        .to_string();
        let radio = tokio::task::spawn_blocking(move || windows::start(&metadata))
            .await
            .unwrap()
            .expect("the Bluetooth worker starts");
        let wait = std::env::var("QGUARD_BLE_PROBE_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(40u64);
        let started = Instant::now();
        let mut found = Vec::new();
        while started.elapsed() < Duration::from_secs(wait) && found.is_empty() {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let snapshot = radio.snapshot().unwrap();
            if !snapshot.scanning {
                println!("scanner not running: {:?}", snapshot.error);
            }
            found = snapshot.peers;
        }
        let (sightings, hint_error) = radio.diagnostics();
        println!("devices found: {} (advertisements heard: {sightings}, last hint read error: {hint_error:?})", found.len());
        assert!(!found.is_empty(), "no Qguard device answered within {wait} s");
        let mut succeeded = 0;
        for peer in found {
            let hint: Metadata = serde_json::from_str(&peer.metadata).unwrap();
            println!(
                "device {} platform={:?} label={:?} rssi={:?}",
                &hint.fingerprint[..8], hint.platform, hint.label, peer.rssi
            );
            let opened = Instant::now();
            let stream = match radio.connector().connect(&peer.address).await {
                Ok(stream) => stream,
                Err(error) => {
                    println!("  stream FAILED after {:?}: {error}", opened.elapsed());
                    continue;
                }
            };
            println!("  stream open after {:?}", opened.elapsed());
            let handshake = Instant::now();
            match Session::connect_pairing_ble(stream, &me, &hint.fingerprint).await {
                Ok(session) => {
                    println!(
                        "  HANDSHAKE OK in {:?} (peer {}, bluetooth={})",
                        handshake.elapsed(),
                        &session.peer()[..8],
                        session.bluetooth()
                    );
                    succeeded += 1;
                }
                Err(error) => println!("  HANDSHAKE FAILED after {:?}: {error}", handshake.elapsed()),
            }
        }
        assert!(succeeded > 0, "no device completed the handshake");
    }
}
