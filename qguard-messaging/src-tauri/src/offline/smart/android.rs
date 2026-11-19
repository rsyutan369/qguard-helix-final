use super::ble_link;
use super::RadioSnapshot;
use crate::{
    error::{QGuardError, Result},
    security::android_bridge::{call_static_string, in_band},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    time::{self, Duration, Instant},
};

const CLASS: &str = "com.qguard.messaging.HelixSmartConnect";
const MAX_SNAPSHOT_BYTES: usize = 96 * 1024;

fn call(method: &str, args: &[&str]) -> Result<String> {
    call_static_string(CLASS, method, args)
        .and_then(in_band)
        .map_err(|error| QGuardError::Storage(format!("Bluetooth discovery: {error}")))
}

pub(super) struct Radio;

impl Radio {
    pub(super) fn start(metadata: &str) -> Result<Self> {
        call("start", &[metadata])?;
        Ok(Self)
    }

    pub(super) fn snapshot(&self) -> Result<RadioSnapshot> {
        let raw = call("status", &[])?;
        if raw.len() > MAX_SNAPSHOT_BYTES {
            return Err(QGuardError::Storage(
                "Bluetooth discovery status is too large.".into(),
            ));
        }
        serde_json::from_str(&raw)
            .map_err(|_| QGuardError::Storage("Bluetooth discovery status is unreadable.".into()))
    }

    pub(super) fn connector(&self) -> Connector {
        Connector
    }

    pub(super) fn take_incoming(&self) -> Result<Vec<DuplexStream>> {
        #[derive(serde::Deserialize)]
        struct Incoming {
            id: String,
            /// The packet size the connecting device declared for this link.
            #[serde(default)]
            packet: usize,
        }
        let raw = call("takeIncoming", &[])?;
        if raw.len() > 4096 {
            return Err(QGuardError::Storage(
                "Invalid Bluetooth accept queue.".into(),
            ));
        }
        let links: Vec<Incoming> = serde_json::from_str(&raw)
            .map_err(|_| QGuardError::Storage("Invalid Bluetooth accept queue.".into()))?;
        Ok(links
            .into_iter()
            .take(4)
            .map(|link| stream(link.id, link.packet))
            .collect())
    }
}

#[derive(Clone)]
pub(crate) struct Connector;

impl Connector {
    pub(crate) async fn connect(&self, address: &str) -> Result<DuplexStream> {
        let address = address.to_string();
        let opened = tokio::task::spawn_blocking(move || call("openLink", &[&address]))
            .await
            .map_err(|_| QGuardError::Storage("Bluetooth connection was interrupted.".into()))??;
        // "<link id>#<packet bytes>": the size the negotiated ATT MTU allows.
        let (id, packet) = opened.split_once('#').unwrap_or((opened.as_str(), ""));
        Ok(stream(id.to_string(), packet.parse().unwrap_or(0)))
    }
}

fn stream(id: String, packet_bytes: usize) -> DuplexStream {
    let packet_bytes =
        packet_bytes.clamp(ble_link::MIN_PACKET_BYTES, ble_link::MAX_PACKET_BYTES);
    let (application, transport) = tokio::io::duplex(32 * 1024);
    tokio::spawn(async move {
        let _ = pump(&id, packet_bytes, transport).await;
        let _ = tokio::task::spawn_blocking(move || call("linkClose", &[&id])).await;
    });
    application
}

async fn write(id: &str, bytes: &[u8]) -> Result<()> {
    let id = id.to_string();
    let encoded = STANDARD.encode(bytes);
    tokio::task::spawn_blocking(move || call("linkWrite", &[&id, &encoded]))
        .await
        .map_err(|_| QGuardError::Storage("Bluetooth write was interrupted.".into()))??;
    Ok(())
}

async fn read(id: &str) -> Result<Vec<u8>> {
    let id = id.to_string();
    let raw = tokio::task::spawn_blocking(move || call("linkRead", &[&id]))
        .await
        .map_err(|_| QGuardError::Storage("Bluetooth read was interrupted.".into()))??;
    let bytes = STANDARD
        .decode(raw)
        .map_err(|_| QGuardError::Storage("Invalid Bluetooth packet.".into()))?;
    if bytes.len() > ble_link::MAX_PACKET_BYTES {
        return Err(QGuardError::Storage("Invalid Bluetooth packet.".into()));
    }
    Ok(bytes)
}

async fn pump(id: &str, packet_bytes: usize, stream: DuplexStream) -> anyhow::Result<()> {
    let (mut source, mut destination) = tokio::io::split(stream);
    let mut buffer = vec![0; packet_bytes - 5];
    let mut sent = 0u32;
    let mut received = 0u32;
    let mut last = None::<Vec<u8>>;
    let mut outgoing = 0usize;
    let mut incoming = 0usize;
    let started = Instant::now();
    // Reads are the only way to receive: poll fast while data flows, slower
    // while the link is quiet. Writes never postpone the next read.
    let mut idle_polls = 0u32;
    let mut next_poll = Instant::now();
    while started.elapsed() < ble_link::LIFETIME_LIMIT {
        tokio::select! {
            count = source.read(&mut buffer) => {
                let count = count?;
                if count == 0 { break }
                outgoing += count;
                anyhow::ensure!(outgoing <= ble_link::MAX_LINK_BYTES, "Bluetooth stream limit reached");
                write(id, &ble_link::packet(sent, &buffer[..count])?).await?;
                // An answer usually follows what was just sent.
                idle_polls = 0;
                next_poll = next_poll.min(Instant::now() + ble_link::poll_delay(0));
                sent = sent.checked_add(1).ok_or_else(|| anyhow::anyhow!("Bluetooth sequence exhausted"))?;
            }
            _ = time::sleep_until(next_poll) => {
                let packet = read(id).await?;
                if packet == [0] {
                    idle_polls = idle_polls.saturating_add(1);
                    next_poll = Instant::now() + ble_link::poll_delay(idle_polls);
                    continue
                }
                idle_polls = 0;
                next_poll = Instant::now() + ble_link::poll_delay(0);
                if packet == ble_link::CLOSE { break }
                let (sequence, bytes) = ble_link::data(&packet)?;
                if sequence == received {
                    incoming += bytes.len();
                    anyhow::ensure!(incoming <= ble_link::MAX_LINK_BYTES, "Bluetooth stream limit reached");
                    time::timeout(Duration::from_secs(30), destination.write_all(bytes)).await??;
                    received = received.checked_add(1).ok_or_else(|| anyhow::anyhow!("Bluetooth sequence exhausted"))?;
                    last = Some(packet.clone());
                } else {
                    anyhow::ensure!(last.as_deref() == Some(packet.as_slice()), "Invalid Bluetooth sequence");
                }
                write(id, &ble_link::ack(sequence)).await?;
            }
        }
    }
    Ok(())
}

impl Drop for Radio {
    fn drop(&mut self) {
        let _ = call("stop", &[]);
    }
}

pub(super) fn request_permissions() -> Result<()> {
    call("requestPermissions", &[]).map(|_| ())
}
