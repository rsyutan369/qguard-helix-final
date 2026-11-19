//! A bounded GATT byte stream. Packet sequencing detects loss and duplication.
//! Authentication belongs to the QHCE session layered above this transport.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, ensure, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    runtime::Handle,
    sync::Notify,
    time,
};

/// ATT's default payload (MTU 23). Every link can carry at least this.
pub(super) const MIN_PACKET_BYTES: usize = 20;
/// The largest attribute value ATT allows, usable once both radios agree on
/// a large MTU. The client measures the link and declares its size in OPEN.
pub(super) const MAX_PACKET_BYTES: usize = 512;
pub(super) const MAX_DATA_BYTES: usize = MAX_PACKET_BYTES - 5;

/// Version 1 OPEN: fixed 20-byte packets.
pub(super) const OPEN: &[u8] = &[1, 1];
pub(super) const CLOSE: &[u8] = &[4];

/// Version 2 OPEN: the client declares the packet size its negotiated ATT MTU
/// allows. A 15-byte payload needs well over a thousand radio round trips for
/// one post-quantum handshake; a full-size packet needs a few dozen.
pub(super) fn open(packet_bytes: usize) -> [u8; 4] {
    let size = packet_bytes.clamp(MIN_PACKET_BYTES, MAX_PACKET_BYTES) as u16;
    let [high, low] = size.to_be_bytes();
    [1, 3, high, low]
}

/// The packet size an OPEN asks for, or `None` when it is not a valid OPEN.
/// Version 3 is version 2 plus a size self-test (see [`probe`]).
pub(super) fn open_size(packet: &[u8]) -> Option<usize> {
    match packet {
        [1, 1] => Some(MIN_PACKET_BYTES),
        [1, 2 | 3, high, low] => Some(u16::from_be_bytes([*high, *low]) as usize)
            .filter(|size| (MIN_PACKET_BYTES..=MAX_PACKET_BYTES).contains(size)),
        _ => None,
    }
}

/// Confirms the size self-test and starts the data stream.
pub(super) const PROBE_ACK: &[u8] = &[6];

/// The size self-test. A read that is longer than the radio link really
/// carries is cut short without any error, which silently drops stream bytes.
/// So the first read on a version 3 link returns a packet of exactly the
/// agreed size; the connecting device compares what arrived and, when it is
/// shorter, reopens the link at the size that did arrive.
pub(super) fn probe(packet_bytes: usize) -> Vec<u8> {
    let size = packet_bytes.clamp(MIN_PACKET_BYTES, MAX_PACKET_BYTES);
    let [high, low] = (size as u16).to_be_bytes();
    let mut packet = vec![0xA5; size];
    packet[..3].copy_from_slice(&[5, high, low]);
    packet
}

/// The next size to try after a full-size write was refused.
pub(super) fn smaller_size(size: usize) -> Option<usize> {
    [244, 128, 64, MIN_PACKET_BYTES]
        .into_iter()
        .find(|candidate| *candidate < size)
}

/// What the connecting device does with the first packet read after OPEN.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Probed {
    /// The full packet arrived: acknowledge and use this size.
    Intact,
    /// Only this many bytes arrived: reopen at the size that fits them.
    Reopen(usize),
    /// The peer sent no self-test (an idle version 2 link): use the size as is.
    Absent,
}

pub(super) fn probed(packet: &[u8], asked: usize) -> Result<Probed> {
    if packet == [0] {
        return Ok(Probed::Absent);
    }
    ensure!(packet.len() >= 3 && packet[0] == 5, "Invalid BLE size test");
    ensure!(
        u16::from_be_bytes([packet[1], packet[2]]) as usize == asked,
        "BLE size test does not match the opened link"
    );
    if packet.len() == asked {
        return Ok(Probed::Intact);
    }
    ensure!(packet.len() < asked, "Invalid BLE size test length");
    // A read carries MTU - 1 bytes and a write MTU - 3: two fewer.
    Ok(Probed::Reopen(
        packet.len().saturating_sub(2).max(MIN_PACKET_BYTES),
    ))
}

/// The packet size for an ATT MTU: a write carries MTU - 3 bytes.
pub(super) fn packet_bytes_for_mtu(mtu: usize) -> usize {
    mtu.saturating_sub(3)
        .clamp(MIN_PACKET_BYTES, MAX_PACKET_BYTES)
}

const MAX_LINKS: usize = 4;
const BUFFER_BYTES: usize = 32 * 1024;
// A link now carries a persistent channel, not one message. The session layer
// above bounds an unauthenticated peer (handshake deadline) and a silent one
// (heartbeat); these are only the outer limits before a link is renewed.
pub(super) const MAX_LINK_BYTES: usize = 64 * 1024 * 1024;
const IDLE_LIMIT: Duration = Duration::from_secs(120);
pub(super) const LIFETIME_LIMIT: Duration = Duration::from_secs(12 * 60 * 60);

/// How long the connecting side waits before its next read. A read is the
/// only way to receive on this transport, so it polls quickly while data
/// flows and backs off while the link is quiet: a persistent channel must
/// not keep the radio at full duty between messages.
pub(super) fn poll_delay(idle_polls: u32) -> Duration {
    Duration::from_millis(match idle_polls {
        0..=12 => 20,
        13..=40 => 70,
        _ => 180,
    })
}

#[derive(Default)]
pub(super) struct Server {
    peers: Mutex<HashMap<String, Arc<Link>>>,
    accepted: Mutex<VecDeque<DuplexStream>>,
}

impl Server {
    pub fn write(&self, peer: &str, packet: &[u8], runtime: &Handle) -> Result<()> {
        ensure!(
            !peer.is_empty() && peer.len() <= 256,
            "Invalid BLE peer handle"
        );
        if packet.first() == Some(&1) {
            let size = open_size(packet).ok_or_else(|| anyhow!("Invalid BLE open packet"))?;
            let mut peers = self
                .peers
                .lock()
                .map_err(|_| anyhow!("BLE links unavailable"))?;
            peers.retain(|_, link| !link.closed());
            if let Some(link) = peers.get(peer) {
                // A retry of an already acknowledged OPEN cannot reset data.
                return link.open_retry(size);
            }
            ensure!(peers.len() < MAX_LINKS, "BLE connection limit reached");
            let mut accepted = self
                .accepted
                .lock()
                .map_err(|_| anyhow!("BLE accept queue unavailable"))?;
            ensure!(accepted.len() < MAX_LINKS, "BLE accept queue is full");
            let (application, transport) = tokio::io::duplex(BUFFER_BYTES);
            let link = Arc::new(Link::new(size));
            if packet[1] == 3 {
                link.expect_probe();
            }
            peers.insert(peer.to_string(), Arc::clone(&link));
            accepted.push_back(application);
            runtime.spawn(drive_server(link, transport));
            return Ok(());
        }
        let link = self.peer(peer)?;
        link.write(packet)
    }

    pub fn read(&self, peer: &str) -> Result<Vec<u8>> {
        match self.peer(peer) {
            Ok(link) => link.read(),
            Err(_) => Ok(CLOSE.to_vec()),
        }
    }

    pub fn accept(&self) -> Result<Vec<DuplexStream>> {
        Ok(self
            .accepted
            .lock()
            .map_err(|_| anyhow!("BLE accept queue unavailable"))?
            .drain(..)
            .collect())
    }

    pub(super) fn has_active_links(&self) -> bool {
        self.peers
            .lock()
            .map_or(true, |peers| peers.values().any(|link| !link.closed()))
    }

    pub fn close(&self) {
        if let Ok(mut peers) = self.peers.lock() {
            for link in peers.values() {
                link.close();
            }
            peers.clear();
        }
        if let Ok(mut accepted) = self.accepted.lock() {
            accepted.clear();
        }
    }

    fn peer(&self, peer: &str) -> Result<Arc<Link>> {
        self.peers
            .lock()
            .map_err(|_| anyhow!("BLE links unavailable"))?
            .get(peer)
            .cloned()
            .ok_or_else(|| anyhow!("BLE stream has not been opened"))
    }
}

struct State {
    packet_bytes: usize,
    /// The size self-test has not been acknowledged yet.
    probe: bool,
    incoming: VecDeque<u8>,
    outgoing: VecDeque<Vec<u8>>,
    next_incoming: u32,
    next_outgoing: u32,
    previous_incoming: Option<Vec<u8>>,
    previous_ack: Option<u32>,
    bytes_received: usize,
    bytes_sent: usize,
    closed: bool,
    started: Instant,
    touched: Instant,
}

struct Link {
    state: Mutex<State>,
    changed: Notify,
}

impl Default for Link {
    fn default() -> Self {
        Self::new(MIN_PACKET_BYTES)
    }
}

impl Link {
    fn new(packet_bytes: usize) -> Self {
        let now = Instant::now();
        Self {
            state: Mutex::new(State {
                packet_bytes: packet_bytes.clamp(MIN_PACKET_BYTES, MAX_PACKET_BYTES),
                probe: false,
                incoming: VecDeque::new(),
                outgoing: VecDeque::new(),
                next_incoming: 0,
                next_outgoing: 0,
                previous_incoming: None,
                previous_ack: None,
                bytes_received: 0,
                bytes_sent: 0,
                closed: false,
                started: now,
                touched: now,
            }),
            changed: Notify::new(),
        }
    }

    fn expect_probe(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.probe = true;
        }
    }

    fn data_bytes(&self) -> usize {
        self.state
            .lock()
            .map_or(MIN_PACKET_BYTES, |state| state.packet_bytes)
            - 5
    }

    fn closed(&self) -> bool {
        self.state.lock().map_or(true, |state| {
            state.closed
                || state.touched.elapsed() >= IDLE_LIMIT
                || state.started.elapsed() >= LIFETIME_LIMIT
        })
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            state.incoming.clear();
            state.outgoing.clear();
        }
        self.changed.notify_waiters();
    }

    fn open_retry(&self, packet_bytes: usize) -> Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("BLE stream unavailable"))?;
        ensure!(
            !state.closed
                && state.packet_bytes == packet_bytes
                && state.next_incoming == 0
                && state.next_outgoing == 0,
            "BLE stream is already active"
        );
        Ok(())
    }

    fn write(&self, packet: &[u8]) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("BLE stream unavailable"))?;
        ensure!(
            !packet.is_empty() && packet.len() <= state.packet_bytes,
            "Invalid BLE packet size"
        );
        ensure!(
            !state.closed && state.started.elapsed() < LIFETIME_LIMIT,
            "BLE stream closed"
        );
        match packet[0] {
            2 => {
                let (sequence, payload) = data(packet)?;
                if sequence != state.next_incoming {
                    ensure!(
                        state.previous_incoming.as_deref() == Some(packet),
                        "Invalid BLE packet sequence"
                    );
                    return Ok(());
                }
                ensure!(
                    state.incoming.len() + payload.len() <= BUFFER_BYTES
                        && state.bytes_received + payload.len() <= MAX_LINK_BYTES,
                    "BLE receive limit reached"
                );
                state.next_incoming = state
                    .next_incoming
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("BLE sequence exhausted"))?;
                state.bytes_received += payload.len();
                state.incoming.extend(payload);
                state.previous_incoming = Some(packet.to_vec());
            }
            3 => {
                ensure!(packet.len() == 5, "Invalid BLE acknowledgment");
                let sequence = u32::from_be_bytes(packet[1..5].try_into()?);
                if state.previous_ack != Some(sequence) {
                    let expected = state
                        .outgoing
                        .front()
                        .ok_or_else(|| anyhow!("Unexpected BLE acknowledgment"))?;
                    ensure!(
                        data(expected)?.0 == sequence,
                        "Invalid BLE acknowledgment sequence"
                    );
                    state.outgoing.pop_front();
                    state.previous_ack = Some(sequence);
                }
            }
            4 => {
                ensure!(packet.len() == 1, "Invalid BLE close");
                state.closed = true;
            }
            // The write half of the size self-test: a full-size packet must
            // arrive whole. A cut or split write is refused, never accepted.
            5 => ensure!(
                packet.len() == state.packet_bytes
                    && u16::from_be_bytes([packet[1], packet[2]]) as usize == state.packet_bytes,
                "BLE size test arrived incomplete"
            ),
            6 => {
                ensure!(packet.len() == 1, "Invalid BLE size test acknowledgment");
                state.probe = false;
            }
            _ => bail!("Invalid BLE control packet"),
        }
        state.touched = Instant::now();
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }

    fn read(&self) -> Result<Vec<u8>> {
        if self.closed() {
            return Ok(CLOSE.to_vec());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("BLE stream unavailable"))?;
        state.touched = Instant::now();
        if state.probe {
            return Ok(probe(state.packet_bytes));
        }
        Ok(state.outgoing.front().cloned().unwrap_or_else(|| vec![0]))
    }

    fn input(&self) -> Result<Vec<u8>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("BLE stream unavailable"))?;
        Ok(state.incoming.drain(..).collect())
    }

    fn can_send(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.outgoing.len() < (BUFFER_BYTES / state.packet_bytes).max(8))
    }

    fn outgoing_empty(&self) -> bool {
        self.state
            .lock()
            .map_or(true, |state| state.outgoing.is_empty())
    }

    fn output(&self, bytes: &[u8]) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("BLE stream unavailable"))?;
        ensure!(
            !state.closed && state.bytes_sent + bytes.len() <= MAX_LINK_BYTES,
            "BLE send limit reached"
        );
        let sequence = state.next_outgoing;
        state.next_outgoing = sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("BLE sequence exhausted"))?;
        state.bytes_sent += bytes.len();
        state.outgoing.push_back(packet(sequence, bytes)?);
        Ok(())
    }
}

async fn drive_server(link: Arc<Link>, stream: DuplexStream) {
    let (mut read, mut write) = tokio::io::split(stream);
    let mut buffer = vec![0; link.data_bytes()];
    let mut ticks = time::interval(Duration::from_millis(25));
    ticks.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut application_eof = None::<Instant>;
    let mut application_receive_closed = false;
    while !link.closed() {
        if application_eof.is_some_and(|ended| {
            link.outgoing_empty() || ended.elapsed() >= Duration::from_secs(30)
        }) {
            break;
        }
        let Ok(incoming) = link.input() else { break };
        if !application_receive_closed
            && !incoming.is_empty()
            && !matches!(
                time::timeout(Duration::from_secs(30), write.write_all(&incoming)).await,
                Ok(Ok(()))
            )
        {
            // The application may close immediately after writing a receipt.
            // Keep draining its outgoing bytes until the peer acknowledges them.
            application_receive_closed = true;
        }
        tokio::select! {
            result = read.read(&mut buffer), if application_eof.is_none() && link.can_send() => {
                match result {
                    Ok(count) if count > 0 => { if link.output(&buffer[..count]).is_err() { break; } }
                    Ok(_) => application_eof = Some(Instant::now()),
                    Err(_) => break,
                }
            }
            _ = link.changed.notified() => {}
            _ = ticks.tick() => {}
        }
    }
    link.close();
}

pub(super) fn packet(sequence: u32, bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_DATA_BYTES,
        "Invalid BLE payload size"
    );
    let mut packet = Vec::with_capacity(bytes.len() + 5);
    packet.push(2);
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(bytes);
    Ok(packet)
}

pub(super) fn data(packet: &[u8]) -> Result<(u32, &[u8])> {
    ensure!(
        (6..=MAX_PACKET_BYTES).contains(&packet.len()) && packet[0] == 2,
        "Invalid BLE data packet"
    );
    Ok((u32::from_be_bytes(packet[1..5].try_into()?), &packet[5..]))
}

pub(super) fn ack(sequence: u32) -> [u8; 5] {
    let mut result = [3; 5];
    result[1..].copy_from_slice(&sequence.to_be_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_do_not_duplicate_bytes_and_reads_wait_for_acknowledgment() {
        let link = Link::default();
        let input = packet(0, b"hello").unwrap();
        link.write(&input).unwrap();
        link.write(&input).unwrap();
        assert_eq!(link.input().unwrap(), b"hello");
        assert!(link.write(&packet(0, b"altered").unwrap()).is_err());
        assert!(link.write(&packet(2, b"gap").unwrap()).is_err());
        link.output(b"reply").unwrap();
        let read = link.read().unwrap();
        assert_eq!(read, link.read().unwrap());
        assert!(link.write(&ack(1)).is_err());
        link.write(&ack(0)).unwrap();
        link.write(&ack(0)).unwrap();
        assert_eq!(link.read().unwrap(), vec![0]);
    }

    #[test]
    fn open_declares_a_bounded_packet_size_and_links_enforce_it() {
        assert_eq!(open_size(OPEN), Some(MIN_PACKET_BYTES));
        assert_eq!(open_size(&open(509)), Some(509));
        assert_eq!(open_size(&open(9000)), Some(MAX_PACKET_BYTES));
        assert_eq!(open_size(&[1, 2, 0, 19]), None);
        assert_eq!(open_size(&[1, 2, 2, 1]), None);
        assert_eq!(open_size(&[1, 4, 0, 20]), None);
        assert_eq!(packet_bytes_for_mtu(23), 20);
        assert_eq!(packet_bytes_for_mtu(517), 512);
        assert_eq!(packet_bytes_for_mtu(247), 244);

        let small = Link::default();
        assert!(small.write(&packet(0, &[7; 16]).unwrap()).is_err());
        small.write(&packet(0, &[7; 15]).unwrap()).unwrap();

        let large = Link::new(244);
        assert_eq!(large.data_bytes(), 239);
        assert!(large.write(&packet(0, &[7; 240]).unwrap()).is_err());
        large.write(&packet(0, &[7; 239]).unwrap()).unwrap();
        assert_eq!(large.input().unwrap().len(), 239);
    }

    #[tokio::test]
    async fn a_large_packet_link_moves_a_handshake_sized_payload_in_few_packets() {
        let server = Server::default();
        server
            .write("peer", &open(MAX_PACKET_BYTES), &Handle::current())
            .unwrap();
        // A retried OPEN must ask for the same size.
        assert!(server.write("peer", OPEN, &Handle::current()).is_err());
        server
            .write("peer", &open(MAX_PACKET_BYTES), &Handle::current())
            .unwrap();
        // The first read is the size self-test, repeated until acknowledged.
        let test = server.read("peer").unwrap();
        assert_eq!(test.len(), MAX_PACKET_BYTES);
        assert_eq!(probed(&test, MAX_PACKET_BYTES).unwrap(), Probed::Intact);
        assert_eq!(server.read("peer").unwrap(), test);
        // A link that only carries 244-byte reads delivers it cut short.
        assert_eq!(probed(&test[..244], MAX_PACKET_BYTES).unwrap(), Probed::Reopen(242));
        assert_eq!(probed(&test[..21], MAX_PACKET_BYTES).unwrap(), Probed::Reopen(MIN_PACKET_BYTES));
        assert_eq!(probed(&[0], MAX_PACKET_BYTES).unwrap(), Probed::Absent);
        assert!(probed(&test, 300).is_err());
        // The write half: only a whole packet of the agreed size is accepted.
        assert!(server.write("peer", &test[..244], &Handle::current()).is_err());
        server.write("peer", &test, &Handle::current()).unwrap();
        assert_eq!(smaller_size(512), Some(244));
        assert_eq!(smaller_size(244), Some(128));
        assert_eq!(smaller_size(20), None);
        server.write("peer", PROBE_ACK, &Handle::current()).unwrap();
        assert_eq!(server.read("peer").unwrap(), vec![0]);
        let mut application = server.accept().unwrap().pop().unwrap();
        let payload: Vec<u8> = (0..6_509u32).map(|index| index as u8).collect();
        let mut packets = 0;
        for (sequence, chunk) in payload.chunks(MAX_DATA_BYTES).enumerate() {
            server
                .write("peer", &packet(sequence as u32, chunk).unwrap(), &Handle::current())
                .unwrap();
            packets += 1;
        }
        assert_eq!(packets, 13);
        let mut received = vec![0; payload.len()];
        time::timeout(Duration::from_secs(2), application.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, payload);

        application.write_all(&payload).await.unwrap();
        let mut echoed = Vec::new();
        let mut sequence = 0u32;
        time::timeout(Duration::from_secs(5), async {
            while echoed.len() < payload.len() {
                let response = server.read("peer").unwrap();
                if response == [0] {
                    time::sleep(Duration::from_millis(2)).await;
                    continue;
                }
                let (found, bytes) = data(&response).unwrap();
                assert_eq!(found, sequence);
                echoed.extend_from_slice(bytes);
                server.write("peer", &ack(sequence), &Handle::current()).unwrap();
                sequence += 1;
            }
        })
        .await
        .unwrap();
        assert_eq!(echoed, payload);
        assert!(sequence <= 14);
    }

    #[tokio::test]
    async fn an_opened_gatt_stream_carries_bytes_in_both_directions() {
        let server = Server::default();
        server.write("peer", OPEN, &Handle::current()).unwrap();
        let mut application = server.accept().unwrap().pop().unwrap();
        server
            .write("peer", &packet(0, b"request").unwrap(), &Handle::current())
            .unwrap();
        let mut request = [0; 7];
        time::timeout(Duration::from_secs(1), application.read_exact(&mut request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&request, b"request");
        application.write_all(b"reply").await.unwrap();
        let response = time::timeout(Duration::from_secs(1), async {
            loop {
                let response = server.read("peer").unwrap();
                if response != [0] {
                    break response;
                }
                time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(data(&response).unwrap().1, b"reply");
        server.write("peer", &ack(0), &Handle::current()).unwrap();
        server.close();
        assert_eq!(server.read("peer").unwrap(), CLOSE);
    }

    #[tokio::test]
    async fn final_bytes_remain_available_until_ack_after_application_closes() {
        let server = Server::default();
        server.write("peer", OPEN, &Handle::current()).unwrap();
        let mut application = server.accept().unwrap().pop().unwrap();
        application.write_all(b"final receipt").await.unwrap();
        drop(application);
        let response = time::timeout(Duration::from_secs(1), async {
            loop {
                let response = server.read("peer").unwrap();
                if response != [0] {
                    break response;
                }
                time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(data(&response).unwrap().1, b"final receipt");
        time::sleep(Duration::from_millis(40)).await;
        assert_eq!(server.read("peer").unwrap(), response);
        server.write("peer", &ack(0), &Handle::current()).unwrap();
        time::timeout(Duration::from_secs(1), async {
            while server.read("peer").unwrap() != CLOSE {
                time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
}
