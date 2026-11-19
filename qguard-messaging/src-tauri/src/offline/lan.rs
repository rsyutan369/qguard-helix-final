//! Foreground, opt-in IPv4 LAN discovery. Announcements are untrusted hints.
//! Only the QHCE session handshake can authenticate an announced fingerprint.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::{Duration, Instant},
};

use chrono::Utc;
use tokio::net::UdpSocket;

use super::profile::{valid_device_label, PeerMetadata, PEER_PLATFORMS};

pub(super) const DISCOVERY_PORT: u16 = 39837;
const MAGIC: &[u8] = b"QGUARD-LAN/1\0";
const METADATA_MAGIC: &[u8] = b"QGUARD-LAN/2\0";
const ANNOUNCEMENT_BYTES: usize = MAGIC.len() + 32 + 2;
const PEER_TTL: Duration = Duration::from_secs(15);
const MAX_DISCOVERED: usize = 128;

pub(super) fn fingerprint_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn lan_ip(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local() || ip.is_loopback()
}

pub(super) fn lan_address(addr: SocketAddr) -> Option<SocketAddrV4> {
    match addr {
        SocketAddr::V4(addr) if lan_ip(*addr.ip()) && addr.port() != 0 => Some(addr),
        _ => None,
    }
}

pub(super) async fn discovery_socket() -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT)).await?;
    socket.set_broadcast(true)?;
    Ok(socket)
}

pub(super) fn announcement(fingerprint: &str, port: u16) -> Option<[u8; ANNOUNCEMENT_BYTES]> {
    let mut bytes = [0; ANNOUNCEMENT_BYTES];
    bytes[..MAGIC.len()].copy_from_slice(MAGIC);
    hex::decode_to_slice(fingerprint, &mut bytes[MAGIC.len()..MAGIC.len() + 32]).ok()?;
    bytes[ANNOUNCEMENT_BYTES - 2..].copy_from_slice(&port.to_be_bytes());
    Some(bytes)
}

/// Sent alongside the legacy datagram. These strings are public discovery hints.
pub(super) fn announcement_with_metadata(
    fingerprint: &str,
    port: u16,
    metadata: &PeerMetadata,
) -> Option<Vec<u8>> {
    metadata.validate().ok()?;
    let platform = PEER_PLATFORMS
        .iter()
        .position(|name| *name == metadata.platform)?;
    let mut bytes = announcement(fingerprint, port)?.to_vec();
    bytes[..MAGIC.len()].copy_from_slice(METADATA_MAGIC);
    bytes.push(platform as u8);
    bytes.extend_from_slice(metadata.label.as_bytes());
    Some(bytes)
}

pub(super) async fn announce(socket: &UdpSocket, bytes: &[u8]) -> std::io::Result<()> {
    socket
        .send_to(bytes, (Ipv4Addr::BROADCAST, DISCOVERY_PORT))
        .await?;
    Ok(())
}

/// The same announcement, sent to one device that was heard on the LAN.
pub(super) async fn announce_to(socket: &UdpSocket, bytes: &[u8], peer: Ipv4Addr) -> std::io::Result<()> {
    socket.send_to(bytes, (peer, DISCOVERY_PORT)).await?;
    Ok(())
}

#[derive(Clone)]
pub(super) struct Observation {
    pub address: SocketAddrV4,
    pub last_seen: i64,
    pub label: Option<String>,
    pub platform: Option<String>,
    observed: Instant,
    metadata_observed: Option<Instant>,
}

#[derive(Default)]
pub(super) struct Discovery {
    pub peers: HashMap<String, Observation>,
}

impl Discovery {
    pub fn observe(&mut self, bytes: &[u8], source: SocketAddr, local: &str) -> bool {
        let Some((fingerprint, mut observation)) = parse_announcement(bytes, source) else {
            return false;
        };
        if fingerprint == local {
            return false;
        }
        if self.peers.len() >= MAX_DISCOVERED && !self.peers.contains_key(&fingerprint) {
            return false;
        }
        // A reordered legacy beacon must not erase a fresh metadata beacon
        // from the same endpoint. A different endpoint never inherits it.
        if observation.metadata_observed.is_none() {
            if let Some(previous) = self.peers.get(&fingerprint).filter(|peer| {
                peer.address == observation.address
                    && peer
                        .metadata_observed
                        .is_some_and(|when| when.elapsed() < PEER_TTL)
            }) {
                observation.label = previous.label.clone();
                observation.platform = previous.platform.clone();
                observation.metadata_observed = previous.metadata_observed;
            }
        }
        self.peers.insert(fingerprint, observation);
        true
    }

    pub fn expire(&mut self) -> bool {
        let before = self.peers.len();
        self.peers
            .retain(|_, peer| peer.observed.elapsed() < PEER_TTL);
        self.peers.len() != before
    }
}

fn parse_announcement(bytes: &[u8], source: SocketAddr) -> Option<(String, Observation)> {
    let now = Instant::now();
    let (label, platform, metadata_observed) = if bytes.starts_with(METADATA_MAGIC) {
        let platform = PEER_PLATFORMS.get(*bytes.get(ANNOUNCEMENT_BYTES)? as usize)?;
        let label = std::str::from_utf8(bytes.get(ANNOUNCEMENT_BYTES + 1..)?).ok()?;
        if !valid_device_label(label) {
            return None;
        }
        (
            Some(label.to_owned()),
            Some((*platform).to_owned()),
            Some(now),
        )
    } else if bytes.len() == ANNOUNCEMENT_BYTES && bytes.starts_with(MAGIC) {
        (None, None, None)
    } else {
        return None;
    };
    let port = u16::from_be_bytes(
        bytes[ANNOUNCEMENT_BYTES - 2..ANNOUNCEMENT_BYTES]
            .try_into()
            .ok()?,
    );
    let mut address = lan_address(source)?;
    if port == 0 {
        return None;
    }
    address.set_port(port);
    Some((
        hex::encode(&bytes[MAGIC.len()..MAGIC.len() + 32]),
        Observation {
            address,
            last_seen: Utc::now().timestamp(),
            label,
            platform,
            observed: now,
            metadata_observed,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_uses_the_packet_source_and_rejects_nonlocal_and_malformed_packets() {
        let peer = "ab".repeat(32);
        let bytes = announcement(&peer, 41234).unwrap();
        assert_eq!(
            parse_announcement(&bytes, "192.168.1.24:39837".parse().unwrap())
                .map(|(id, observation)| (id, observation.address)),
            Some((peer, "192.168.1.24:41234".parse().unwrap()))
        );
        assert!(parse_announcement(&bytes, "8.8.8.8:39837".parse().unwrap()).is_none());
        assert!(parse_announcement(
            &bytes[..bytes.len() - 1],
            "192.168.1.24:39837".parse().unwrap()
        )
        .is_none());
    }

    #[test]
    fn metadata_is_optional_bounded_and_preserved_only_for_a_fresh_matching_endpoint() {
        use super::super::profile::PeerCapability;

        let local = "ab".repeat(32);
        let peer = "cd".repeat(32);
        let source = "192.168.1.24:39837".parse().unwrap();
        let metadata = PeerMetadata {
            label: "Nearby Android".into(),
            platform: "android".into(),
            capabilities: vec![PeerCapability::Mesh],
        };
        let packet = announcement_with_metadata(&peer, 41234, &metadata).unwrap();
        let legacy = announcement(&peer, 41234).unwrap();
        let mut discovery = Discovery::default();
        assert!(discovery.observe(&legacy, source, &local));
        assert!(discovery.peers[&peer].label.is_none());
        assert!(discovery.observe(&packet, source, &local));
        assert!(discovery.observe(&legacy, source, &local));
        assert_eq!(
            discovery.peers[&peer].label.as_deref(),
            Some("Nearby Android")
        );
        assert_eq!(discovery.peers[&peer].platform.as_deref(), Some("android"));
        let changed = "192.168.1.25:39837".parse().unwrap();
        assert!(discovery.observe(&legacy, changed, &local));
        assert!(discovery.peers[&peer].label.is_none());
        let mut invalid = packet;
        invalid[ANNOUNCEMENT_BYTES] = u8::MAX;
        assert!(!discovery.observe(&invalid, source, &local));
    }

    #[test]
    fn discovery_does_not_add_self_and_expires_old_peers() {
        let local = "ab".repeat(32);
        let peer = "cd".repeat(32);
        let source = "192.168.1.24:39837".parse().unwrap();
        let mut discovery = Discovery::default();
        assert!(!discovery.observe(&announcement(&local, 41234).unwrap(), source, &local));
        assert!(discovery.observe(&announcement(&peer, 41234).unwrap(), source, &local));
        discovery.peers.get_mut(&peer).unwrap().observed -= PEER_TTL;
        assert!(discovery.expire());
        assert!(discovery.peers.is_empty());
    }
}
