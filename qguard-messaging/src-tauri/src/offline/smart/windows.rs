//! Windows foreground BLE discovery and bounded small-message byte streams.
//! Public endpoint hints are untrusted; QHCE authenticates each transport session.

use std::{
    collections::HashMap,
    future::IntoFuture,
    net::Ipv4Addr,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context};
use chrono::Utc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::{mpsc as async_mpsc, oneshot, watch},
    task::JoinSet,
    time::{self, MissedTickBehavior},
};
use windows::{
    core::GUID,
    Devices::Bluetooth::{
        Advertisement::{
            BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementWatcher,
            BluetoothLEAdvertisementWatcherStatus, BluetoothLEScanningMode,
        },
        BluetoothAdapter, BluetoothAddressType, BluetoothCacheMode, BluetoothError,
        BluetoothLEPreferredConnectionParameters, BluetoothLEPreferredConnectionParametersRequest,
        BluetoothLEDevice,
        GenericAttributeProfile::{
            GattCharacteristic, GattCharacteristicProperties, GattCommunicationStatus,
            GattLocalCharacteristic, GattLocalCharacteristicParameters, GattProtectionLevel,
            GattReadRequestedEventArgs, GattServiceProvider, GattSession,
            GattServiceProviderAdvertisementStatus, GattServiceProviderAdvertisingParameters,
            GattWriteOption, GattWriteRequestedEventArgs,
        },
    },
    Foundation::{Deferral, TypedEventHandler},
    Networking::{Connectivity::NetworkInformation, HostNameType},
    Storage::Streams::{DataReader, DataWriter},
    Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED},
};

use crate::error::{QGuardError, Result};

use super::super::profile::{valid_device_label, PEER_PLATFORMS};
use super::{ble_link, RadioPeer, RadioSnapshot};

const SERVICE: GUID = GUID::from_u128(0x8d0d6ad1_9596_473a_bff8_6f431bb720af);
const METADATA: GUID = GUID::from_u128(0x8d0d6ad1_9596_473a_bff8_6f431bb720b0);
const INGRESS: GUID = GUID::from_u128(0x8d0d6ad1_9596_473a_bff8_6f431bb720b1);
const EGRESS: GUID = GUID::from_u128(0x8d0d6ad1_9596_473a_bff8_6f431bb720b2);
const DEVICE_HINT: GUID = GUID::from_u128(0x8d0d6ad1_9596_473a_bff8_6f431bb720b3);
const ATT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DATA_LINKS: usize = 4;
const MAX_METADATA_BYTES: usize = 512;
const MAX_PEERS: usize = 64;
const PEER_TTL: Duration = Duration::from_secs(20);
const MIN_OBSERVATION_INTERVAL: Duration = Duration::from_secs(2);
const METADATA_REFRESH: Duration = Duration::from_secs(10);
/// A peer whose hints were read keeps them; reconnecting every few seconds
/// only competes with real links for the radio.
const KNOWN_METADATA_REFRESH: Duration = Duration::from_secs(45);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ADAPTER_TIMEOUT: Duration = Duration::from_secs(3);
const START_TIMEOUT: Duration = Duration::from_secs(10);
const E_ACCESSDENIED: i32 = 0x80070005u32 as i32;

/// Each await shares the caller's absolute deadline. Request cancellation
/// when WinRT does not complete, so discarded discovery cannot queue work
/// indefinitely in the Bluetooth stack.
macro_rules! await_winrt {
    ($operation:expr, $deadline:expr) => {{
        let operation = $operation?;
        let mut pending = PendingOperation(Some(|| {
            let _ = operation.Cancel();
        }));
        match time::timeout_at($deadline, operation.clone().into_future()).await {
            Ok(result) => {
                pending.0.take();
                result?
            }
            Err(_) => {
                bail!("Windows Bluetooth operation timed out.");
            }
        }
    }};
}

struct PendingOperation<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for PendingOperation<F> {
    fn drop(&mut self) {
        if let Some(cancel) = self.0.take() {
            cancel();
        }
    }
}

#[derive(Default)]
struct Status {
    available: bool,
    permission_granted: bool,
    scanning: bool,
    advertising: bool,
    error: Option<String>,
    peers: HashMap<u64, Observation>,
    /// Advertisements of the Qguard service heard, before any hint read.
    sightings: u64,
    /// Why the latest hint read from an advertising device failed.
    hint_error: Option<String>,
}

struct Observation {
    metadata: String,
    kind: BluetoothAddressType,
    observed: Instant,
    last_seen: i64,
    rssi: Option<i16>,
    read_at: Instant,
}

pub(super) struct Radio {
    status: Arc<Mutex<Status>>,
    stop: watch::Sender<bool>,
    connector: Connector,
    server: Arc<ble_link::Server>,
    stopped: mpsc::Receiver<()>,
}

impl Radio {
    pub(super) fn start(metadata_json: &str) -> Result<Self> {
        start(metadata_json)
    }

    pub(super) fn connector(&self) -> Connector {
        self.connector.clone()
    }

    pub(super) fn take_incoming(&self) -> Result<Vec<DuplexStream>> {
        self.server
            .accept()
            .map_err(|error| QGuardError::Storage(error.to_string()))
    }

    #[cfg(test)]
    pub(super) fn diagnostics(&self) -> (u64, Option<String>) {
        self.status.lock().map_or((0, None), |status| (status.sightings, status.hint_error.clone()))
    }

    pub(super) fn snapshot(&self) -> Result<RadioSnapshot> {
        let status = self
            .status
            .lock()
            .map_err(|_| QGuardError::Storage("Windows Bluetooth status is unavailable.".into()))?;
        let peers = status
            .peers
            .iter()
            .filter(|(_, entry)| entry.observed.elapsed() < PEER_TTL)
            .map(|(address, entry)| RadioPeer {
                address: format_address(*address),
                metadata: entry.metadata.clone(),
                last_seen: entry.last_seen,
                rssi: entry.rssi,
            })
            .collect();
        Ok(RadioSnapshot {
            available: status.available,
            permission_granted: status.permission_granted,
            scanning: status.scanning,
            advertising: status.advertising,
            error: status.error.clone(),
            peers,
        })
    }
}

impl Drop for Radio {
    fn drop(&mut self) {
        self.server.close();
        self.stop.send_replace(true);
        let _ = self.stopped.recv_timeout(START_TIMEOUT);
    }
}

pub(super) fn start(metadata_json: &str) -> Result<Radio> {
    if metadata_json.len() > MAX_METADATA_BYTES {
        return Err(QGuardError::Storage(
            "Windows Bluetooth discovery metadata is too large.".into(),
        ));
    }
    let metadata = public_metadata(metadata_json).ok_or_else(|| {
        QGuardError::Storage("Windows Bluetooth discovery metadata is invalid.".into())
    })?;
    let status = Arc::new(Mutex::new(Status::default()));
    let server = Arc::new(ble_link::Server::default());
    let worker_server = Arc::clone(&server);
    let (commands, requests) = async_mpsc::channel(MAX_DATA_LINKS);
    let (stop, shutdown_requested) = watch::channel(false);
    let (ready, starting) = mpsc::sync_channel(1);
    let (finished, stopped) = mpsc::sync_channel(1);
    let worker_status = Arc::clone(&status);
    thread::Builder::new()
        .name("helix-windows-bluetooth".into())
        .spawn(move || {
            let setup = || -> anyhow::Result<()> {
                let _apartment = Apartment::initialize()?;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()?;
                runtime.block_on(run(
                    metadata,
                    shutdown_requested,
                    &worker_status,
                    &ready,
                    requests,
                    worker_server,
                ))
            };
            if let Err(error) = setup() {
                if let Ok(mut status) = worker_status.lock() {
                    status.scanning = false;
                    status.advertising = false;
                    status.peers.clear();
                    status.error = Some(bluetooth_error(&error));
                }
                let _ = ready.try_send(());
            }
            let _ = finished.try_send(());
        })
        .map_err(|_| {
            QGuardError::Storage("Could not start the Windows Bluetooth worker.".into())
        })?;
    let radio = Radio {
        status,
        stop,
        connector: Connector(commands),
        server,
        stopped,
    };
    starting.recv_timeout(START_TIMEOUT).map_err(|_| {
        QGuardError::Storage("Windows Bluetooth did not respond during discovery startup.".into())
    })?;
    Ok(radio)
}

enum Command {
    Connect {
        address: u64,
        reply: oneshot::Sender<Result<DuplexStream>>,
    },
}

#[derive(Clone)]
pub(crate) struct Connector(async_mpsc::Sender<Command>);

impl Connector {
    pub(crate) async fn connect(&self, address: &str) -> Result<DuplexStream> {
        let address = address.replace(':', "");
        let address = u64::from_str_radix(&address, 16)
            .ok()
            .filter(|address| *address > 0 && *address <= 0x0000_FFFF_FFFF_FFFF)
            .ok_or_else(|| {
                QGuardError::InvalidInput("Invalid Bluetooth discovery handle.".into())
            })?;
        let (reply, waiting) = oneshot::channel();
        self.0
            .try_send(Command::Connect { address, reply })
            .map_err(|_| QGuardError::Storage("The Bluetooth connection queue is busy.".into()))?;
        time::timeout(Duration::from_secs(45), waiting)
            .await
            .map_err(|_| QGuardError::Storage("Bluetooth connection timed out.".into()))?
            .map_err(|_| QGuardError::Storage("Bluetooth discovery stopped.".into()))?
    }
}

struct Apartment;

impl Apartment {
    fn initialize() -> windows::core::Result<Self> {
        // The dedicated thread owns this MTA for the lifetime of its WinRT objects.
        unsafe { RoInitialize(RO_INIT_MULTITHREADED)? };
        Ok(Self)
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        // This guard is created and dropped on the same dedicated thread.
        unsafe { RoUninitialize() };
    }
}

#[derive(Clone, Copy)]
struct DeviceHint {
    address: u64,
    kind: BluetoothAddressType,
    observed: Instant,
    last_seen: i64,
    rssi: Option<i16>,
}

struct Watcher {
    native: BluetoothLEAdvertisementWatcher,
    subscription: i64,
}

impl Drop for Watcher {
    fn drop(&mut self) {
        let _ = self.native.Stop();
        let _ = self.native.RemoveReceived(self.subscription);
    }
}

struct Advertisement {
    native: GattServiceProvider,
    subscriptions: Vec<CharacteristicSubscription>,
}

struct CharacteristicSubscription {
    characteristic: GattLocalCharacteristic,
    token: i64,
    read: bool,
}

impl Drop for CharacteristicSubscription {
    fn drop(&mut self) {
        if self.read {
            let _ = self.characteristic.RemoveReadRequested(self.token);
        } else {
            let _ = self.characteristic.RemoveWriteRequested(self.token);
        }
    }
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        let _ = self.native.StopAdvertising();
    }
}

async fn run(
    metadata: serde_json::Value,
    mut stop: watch::Receiver<bool>,
    state: &Mutex<Status>,
    ready: &mpsc::SyncSender<()>,
    mut commands: async_mpsc::Receiver<Command>,
    server: Arc<ble_link::Server>,
) -> anyhow::Result<()> {
    let adapter = await_winrt!(
        BluetoothAdapter::GetDefaultAsync(),
        time::Instant::now() + ADAPTER_TIMEOUT
    );
    if !adapter.IsLowEnergySupported()? {
        bail!("This Windows Bluetooth adapter does not support Bluetooth LE.");
    }
    let can_advertise = adapter.IsPeripheralRoleSupported().unwrap_or(false);
    if let Ok(mut status) = state.lock() {
        status.available = true;
    }
    let (discover, mut events) = async_mpsc::channel(MAX_PEERS);
    let watcher = start_watcher(discover)?;
    let mut advertised = local_metadata(&metadata)?;
    let mut provider = if can_advertise {
        start_advertising(&advertised, Arc::clone(&server))
            .await
            .ok()
    } else {
        None
    };
    update_status(state, &watcher, provider.as_ref());
    let _ = ready.try_send(());

    let mut attempts = HashMap::<u64, Instant>::new();
    let mut clients = JoinSet::new();
    let mut status_timer = time::interval(Duration::from_secs(2));
    status_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut metadata_timer = time::interval(METADATA_REFRESH);
    metadata_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    while !*stop.borrow() {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = status_timer.tick() => {
                update_status(state, &watcher, provider.as_ref());
                attempts.retain(|_, attempt| attempt.elapsed() < PEER_TTL);
            }
            _ = metadata_timer.tick() => {
                let current = local_metadata(&metadata)?;
                if can_advertise && (provider.is_none() || current != advertised) {
                    drop(provider.take());
                    advertised = current;
                    provider = start_advertising(&advertised, Arc::clone(&server)).await.ok();
                    update_status(state, &watcher, provider.as_ref());
                }
            }
            Some(Command::Connect { address, reply }) = commands.recv() => {
                let hint = state.lock().ok().and_then(|status| status.peers.get(&address)
                    .filter(|peer| peer.observed.elapsed() < PEER_TTL)
                    .map(|peer| DeviceHint {
                        address, kind: peer.kind, observed: peer.observed, last_seen: peer.last_seen, rssi: peer.rssi,
                    }));
                if clients.len() >= MAX_DATA_LINKS || hint.is_none() {
                    let _ = reply.send(Err(QGuardError::Storage("The Bluetooth peer is unavailable or all links are busy.".into())));
                    continue;
                }
                let stopped = stop.clone();
                clients.spawn(async move {
                    client_link(hint.unwrap(), stopped, reply).await;
                });
            }
            _ = clients.join_next(), if !clients.is_empty() => {}
            Some(hint) = events.recv() => {
                if let Ok(mut status) = state.lock() {
                    status.sightings = status.sightings.saturating_add(1);
                }
                if hint.observed.elapsed() >= PEER_TTL {
                    continue;
                }
                let mut known_recently = false;
                if let Ok(mut status) = state.lock() {
                    if !status.scanning {
                        continue;
                    }
                    if let Some(previous) = status.peers.get_mut(&hint.address) {
                        previous.observed = hint.observed;
                        previous.last_seen = hint.last_seen;
                        previous.rssi = hint.rssi.or(previous.rssi);
                        known_recently = previous.read_at.elapsed() < KNOWN_METADATA_REFRESH;
                    }
                }
                // Some Windows Bluetooth drivers share the native connection
                // between handles. Avoid opening/closing metadata clients while
                // an authenticated stream is being established or transferred.
                if known_recently || !clients.is_empty() || server.has_active_links() {
                    continue;
                }
                if attempts.get(&hint.address).is_some_and(|attempt| attempt.elapsed() < METADATA_REFRESH) {
                    continue;
                }
                if !attempts.contains_key(&hint.address) && attempts.len() >= MAX_PEERS {
                    continue;
                }
                attempts.insert(hint.address, Instant::now());
                let result = tokio::select! {
                    biased;
                    _ = stop.changed() => break,
                    result = read_metadata(hint) => result,
                };
                if let (Err(error), Ok(mut status)) = (&result, state.lock()) {
                    status.hint_error = Some(link_error(error));
                }
                if let (Ok(metadata), Ok(mut status)) = (result, state.lock()) {
                    status.hint_error = None;
                    if status.peers.len() < MAX_PEERS || status.peers.contains_key(&hint.address) {
                        status.peers.insert(hint.address, Observation {
                            metadata,
                            kind: hint.kind,
                            observed: hint.observed,
                            last_seen: hint.last_seen,
                            rssi: hint.rssi,
                            read_at: Instant::now(),
                        });
                    }
                }
            }
        }
    }
    server.close();
    clients.shutdown().await;
    if let Ok(mut status) = state.lock() {
        status.scanning = false;
        status.advertising = false;
        status.peers.clear();
    }
    Ok(())
}

fn update_status(state: &Mutex<Status>, watcher: &Watcher, provider: Option<&Advertisement>) {
    let scanning =
        watcher.native.Status().ok() == Some(BluetoothLEAdvertisementWatcherStatus::Started);
    let advertising = provider
        .and_then(|provider| provider.native.AdvertisementStatus().ok())
        .is_some_and(|status| status == GattServiceProviderAdvertisementStatus::Started);
    if let Ok(mut status) = state.lock() {
        status.permission_granted = scanning || advertising;
        status.scanning = scanning;
        status.advertising = advertising;
        status.error = match (scanning, advertising) {
            (true, true) => None,
            (true, false) => Some(
                "Windows Bluetooth is scanning, but its local advertisement is unavailable.".into(),
            ),
            (false, true) => {
                Some("Windows Bluetooth is advertising, but its scanner is unavailable.".into())
            }
            (false, false) => Some(
                "Windows Bluetooth discovery is unavailable. Check Bluetooth in Windows Settings."
                    .into(),
            ),
        };
        status
            .peers
            .retain(|_, peer| scanning && peer.observed.elapsed() < PEER_TTL);
    }
}

fn start_watcher(discover: async_mpsc::Sender<DeviceHint>) -> windows::core::Result<Watcher> {
    let native = BluetoothLEAdvertisementWatcher::new()?;
    native.SetScanningMode(BluetoothLEScanningMode::Active)?;
    native
        .AdvertisementFilter()?
        .Advertisement()?
        .ServiceUuids()?
        .Append(SERVICE)?;
    let accepted = Mutex::new(HashMap::<u64, Instant>::new());
    let handler = TypedEventHandler::<
        BluetoothLEAdvertisementWatcher,
        BluetoothLEAdvertisementReceivedEventArgs,
    >::new(move |_, args| {
        let Some(args) = args.as_ref() else {
            return Ok(());
        };
        let address = args.BluetoothAddress()?;
        if address == 0 || address > 0x0000_FFFF_FFFF_FFFF {
            return Ok(());
        }
        let Ok(mut accepted) = accepted.try_lock() else {
            return Ok(());
        };
        accepted.retain(|_, observed| observed.elapsed() < PEER_TTL);
        if accepted
            .get(&address)
            .is_some_and(|observed| observed.elapsed() < MIN_OBSERVATION_INTERVAL)
            || (!accepted.contains_key(&address) && accepted.len() >= MAX_PEERS)
        {
            return Ok(());
        }
        let observed = Instant::now();
        if discover
            .try_send(DeviceHint {
                address,
                kind: args
                    .BluetoothAddressType()
                    .unwrap_or(BluetoothAddressType::Unspecified),
                observed,
                last_seen: Utc::now().timestamp(),
                rssi: args.RawSignalStrengthInDBm().ok().filter(|value| (-127..=20).contains(value)),
            })
            .is_ok()
        {
            accepted.insert(address, observed);
        }
        Ok(())
    });
    let subscription = native.Received(&handler)?;
    let watcher = Watcher {
        native,
        subscription,
    };
    watcher.native.Start()?;
    Ok(watcher)
}

async fn start_advertising(
    metadata: &AdvertisedMetadata,
    server: Arc<ble_link::Server>,
) -> anyhow::Result<Advertisement> {
    let deadline = time::Instant::now() + ADAPTER_TIMEOUT;
    let result = await_winrt!(GattServiceProvider::CreateAsync(SERVICE), deadline);
    if result.Error()? != BluetoothError::Success {
        bail!("Windows Bluetooth could not create the discovery service.");
    }
    let mut provider = Advertisement {
        native: result.ServiceProvider()?,
        subscriptions: Vec::new(),
    };
    static_metadata_characteristic(&provider, METADATA, &metadata.legacy, deadline).await?;
    data_characteristics(&mut provider, server, deadline).await?;
    if let Some(hints) = &metadata.with_hints {
        // A radio unable to expose the optional characteristic still keeps
        // its original discovery and byte-stream characteristics available.
        let _ = static_metadata_characteristic(&provider, DEVICE_HINT, hints, deadline).await;
    }
    let options = GattServiceProviderAdvertisingParameters::new()?;
    options.SetIsConnectable(true)?;
    options.SetIsDiscoverable(true)?;
    provider.native.StartAdvertisingWithParameters(&options)?;
    Ok(provider)
}

async fn static_metadata_characteristic(
    provider: &Advertisement,
    uuid: GUID,
    metadata: &str,
    deadline: time::Instant,
) -> anyhow::Result<()> {
    let parameters = GattLocalCharacteristicParameters::new()?;
    parameters.SetCharacteristicProperties(GattCharacteristicProperties::Read)?;
    parameters.SetReadProtectionLevel(GattProtectionLevel::Plain)?;
    let writer = DataWriter::new()?;
    writer.WriteBytes(metadata.as_bytes())?;
    parameters.SetStaticValue(&writer.DetachBuffer()?)?;
    let result = await_winrt!(
        provider
            .native
            .Service()?
            .CreateCharacteristicAsync(uuid, &parameters),
        deadline
    );
    if result.Error()? != BluetoothError::Success {
        bail!("Windows Bluetooth could not expose the discovery characteristic.");
    }
    Ok(())
}

struct RequestDeferral(Deferral);

impl Drop for RequestDeferral {
    fn drop(&mut self) {
        let _ = self.0.Complete();
    }
}

async fn data_characteristics(
    provider: &mut Advertisement,
    server: Arc<ble_link::Server>,
    deadline: time::Instant,
) -> anyhow::Result<()> {
    let parameters = GattLocalCharacteristicParameters::new()?;
    parameters.SetCharacteristicProperties(GattCharacteristicProperties::Write)?;
    parameters.SetWriteProtectionLevel(GattProtectionLevel::Plain)?;
    let result = await_winrt!(
        provider
            .native
            .Service()?
            .CreateCharacteristicAsync(INGRESS, &parameters),
        deadline
    );
    if result.Error()? != BluetoothError::Success {
        bail!("Could not create the Bluetooth stream ingress.");
    }
    let characteristic = result.Characteristic()?;
    let runtime = tokio::runtime::Handle::current();
    let write_runtime = runtime.clone();
    let write_server = Arc::clone(&server);
    let handler = TypedEventHandler::<GattLocalCharacteristic, GattWriteRequestedEventArgs>::new(
        move |_, args| {
            let Some(args) = args.as_ref() else {
                return Ok(());
            };
            let args = args.clone();
            let deferral = RequestDeferral(args.GetDeferral()?);
            let server = Arc::clone(&write_server);
            let runtime = write_runtime.clone();
            write_runtime.spawn(async move {
                let _deferral = deferral;
                let _ = serve_write(args, server, runtime).await;
            });
            Ok(())
        },
    );
    let token = characteristic.WriteRequested(&handler)?;
    provider.subscriptions.push(CharacteristicSubscription {
        characteristic,
        token,
        read: false,
    });

    let parameters = GattLocalCharacteristicParameters::new()?;
    parameters.SetCharacteristicProperties(GattCharacteristicProperties::Read)?;
    parameters.SetReadProtectionLevel(GattProtectionLevel::Plain)?;
    let result = await_winrt!(
        provider
            .native
            .Service()?
            .CreateCharacteristicAsync(EGRESS, &parameters),
        deadline
    );
    if result.Error()? != BluetoothError::Success {
        bail!("Could not create the Bluetooth stream egress.");
    }
    let characteristic = result.Characteristic()?;
    let handler = TypedEventHandler::<GattLocalCharacteristic, GattReadRequestedEventArgs>::new(
        move |_, args| {
            let Some(args) = args.as_ref() else {
                return Ok(());
            };
            let args = args.clone();
            let deferral = RequestDeferral(args.GetDeferral()?);
            let server = Arc::clone(&server);
            runtime.spawn(async move {
                let _deferral = deferral;
                let _ = serve_read(args, server).await;
            });
            Ok(())
        },
    );
    let token = characteristic.ReadRequested(&handler)?;
    provider.subscriptions.push(CharacteristicSubscription {
        characteristic,
        token,
        read: true,
    });
    Ok(())
}

async fn serve_write(
    args: GattWriteRequestedEventArgs,
    server: Arc<ble_link::Server>,
    runtime: tokio::runtime::Handle,
) -> anyhow::Result<()> {
    let request = await_winrt!(args.GetRequestAsync(), time::Instant::now() + ATT_TIMEOUT);
    let outcome = (|| -> anyhow::Result<()> {
        let peer = args.Session()?.DeviceId()?.Id()?.to_string();
        anyhow::ensure!(request.Offset()? == 0, "Invalid Bluetooth write offset");
        let bytes = buffer_bytes(&request.Value()?, ble_link::MAX_PACKET_BYTES)?;
        server.write(&peer, &bytes, &runtime)
    })();
    if outcome.is_ok() {
        request.Respond()?;
    } else {
        request.RespondWithProtocolError(0x0e)?;
    }
    Ok(())
}

async fn serve_read(
    args: GattReadRequestedEventArgs,
    server: Arc<ble_link::Server>,
) -> anyhow::Result<()> {
    let request = await_winrt!(args.GetRequestAsync(), time::Instant::now() + ATT_TIMEOUT);
    if request.Offset()? != 0 {
        request.RespondWithProtocolError(0x07)?;
        return Ok(());
    }
    let peer = args.Session()?.DeviceId()?.Id()?.to_string();
    let packet = server.read(&peer)?;
    let writer = DataWriter::new()?;
    writer.WriteBytes(&packet)?;
    request.RespondWithValue(&writer.DetachBuffer()?)?;
    Ok(())
}

fn buffer_bytes(
    buffer: &windows::Storage::Streams::IBuffer,
    maximum: usize,
) -> anyhow::Result<Vec<u8>> {
    let length = buffer.Length()? as usize;
    anyhow::ensure!(
        length > 0 && length <= maximum,
        "Invalid Bluetooth packet length"
    );
    let mut bytes = vec![0; length];
    DataReader::FromBuffer(buffer)?.ReadBytes(&mut bytes)?;
    Ok(bytes)
}

async fn characteristic(
    service: &windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService,
    uuid: GUID,
    deadline: time::Instant,
) -> anyhow::Result<GattCharacteristic> {
    // List every characteristic and pick this one, the way the hint reader
    // does. A by-UUID query was refused by a real Android peer whose full
    // listing worked. Fall back to Windows' cached listing before giving up.
    let mut reason = String::new();
    for mode in [BluetoothCacheMode::Uncached, BluetoothCacheMode::Cached] {
        let found = await_winrt!(service.GetCharacteristicsWithCacheModeAsync(mode), deadline);
        let status = found.Status()?;
        if status != GattCommunicationStatus::Success {
            reason = format!("status {}", status.0);
            continue;
        }
        let all = found.Characteristics()?;
        for index in 0..all.Size()?.min(64) {
            let candidate = all.GetAt(index)?;
            if candidate.Uuid()? == uuid {
                return Ok(candidate);
            }
        }
        reason = "not listed by the device".into();
    }
    bail!("Bluetooth stream characteristic unavailable, {reason}")
}

async fn client_link(
    hint: DeviceHint,
    stop: watch::Receiver<bool>,
    reply: oneshot::Sender<Result<DuplexStream>>,
) {
    // A first LE connection attempt often fails on real radios while the
    // peer is between advertising events. One retry covers that.
    let mut opened = open_client(hint).await;
    if opened.is_err() && !*stop.borrow() {
        time::sleep(Duration::from_millis(400)).await;
        opened = open_client(hint).await;
    }
    let client = match opened {
        Ok(value) => value,
        Err(error) => {
            let _ = reply.send(Err(QGuardError::Storage(format!(
                "Could not establish the Bluetooth stream with this device ({}).",
                link_error(&error)
            ))));
            return;
        }
    };
    #[cfg(test)]
    println!("  Bluetooth packet size from the negotiated MTU: {} bytes", client.packet_bytes);
    let packet_bytes = match open_stream(&client).await {
        Ok(size) => size,
        Err(error) => {
            let _ = reply.send(Err(QGuardError::Storage(format!(
                "The other device did not accept a Bluetooth stream ({}). Both devices need this Qguard version.",
                link_error(&error)
            ))));
            return;
        }
    };
    #[cfg(test)]
    println!("  Bluetooth packet size after the size self-test: {packet_bytes} bytes");
    let (application, transport) = tokio::io::duplex(32 * 1024);
    if reply.send(Ok(application)).is_ok() {
        let _ = drive_client(&client.ingress, &client.egress, packet_bytes, transport, stop).await;
    }
    let _ = write_packet(&client.ingress, ble_link::CLOSE).await;
    drop(client);
}

/// Opens the stream and runs the size self-test: the peer's first read must
/// arrive at the full agreed size. When the link delivers it cut short, the
/// stream is reopened at the size that did arrive, so no data packet can be
/// silently truncated later.
async fn open_stream(client: &Client) -> anyhow::Result<usize> {
    let mut size = client.packet_bytes;
    for _ in 0..8 {
        write_packet(&client.ingress, &ble_link::open(size)).await?;
        let first = read_packet(&client.egress).await?;
        match ble_link::probed(&first, size)? {
            ble_link::Probed::Intact => {
                // The write half: a full-size packet must be accepted whole.
                if write_packet(&client.ingress, &ble_link::probe(size)).await.is_ok() {
                    write_packet(&client.ingress, ble_link::PROBE_ACK).await?;
                    return Ok(size);
                }
                let _ = write_packet(&client.ingress, ble_link::CLOSE).await;
                size = ble_link::smaller_size(size)
                    .ok_or_else(|| anyhow::anyhow!("The Bluetooth link cannot carry a full packet"))?;
            }
            ble_link::Probed::Absent => return Ok(size),
            ble_link::Probed::Reopen(smaller) => {
                anyhow::ensure!(smaller < size, "The Bluetooth link cannot carry a full packet");
                write_packet(&client.ingress, ble_link::CLOSE).await?;
                size = smaller;
            }
        }
    }
    bail!("The Bluetooth link did not settle on a packet size")
}

/// A short reason for the user and for support, without device addresses.
fn link_error(error: &anyhow::Error) -> String {
    match error.downcast_ref::<windows::core::Error>() {
        Some(native) => format!("Windows Bluetooth error 0x{:08X}", native.code().0 as u32),
        None => error.to_string(),
    }
}

/// Field order is drop order: characteristics, then the session and the
/// connection-parameter request, then the device.
struct Client {
    ingress: GattCharacteristic,
    egress: GattCharacteristic,
    packet_bytes: usize,
    _session: Option<GattSession>,
    _parameters: Option<BluetoothLEPreferredConnectionParametersRequest>,
    _device: Device,
}

/// The packet size the negotiated ATT MTU allows. Windows exchanges the MTU
/// when the link comes up, so wait briefly while it still reports the default.
async fn negotiated_packet_bytes(session: Option<&GattSession>) -> usize {
    let Some(session) = session else {
        return ble_link::MIN_PACKET_BYTES;
    };
    let mut mtu = session.MaxPduSize().unwrap_or(23);
    let waited = Instant::now();
    while mtu <= 23 && waited.elapsed() < Duration::from_millis(1500) {
        time::sleep(Duration::from_millis(100)).await;
        mtu = session.MaxPduSize().unwrap_or(23);
    }
    ble_link::packet_bytes_for_mtu(mtu as usize)
}

async fn open_client(hint: DeviceHint) -> anyhow::Result<Client> {
    let deadline = time::Instant::now() + Duration::from_secs(15);
    let device = Device(if hint.kind == BluetoothAddressType::Unspecified {
        await_winrt!(
            BluetoothLEDevice::FromBluetoothAddressAsync(hint.address),
            deadline
        )
    } else {
        await_winrt!(
            BluetoothLEDevice::FromBluetoothAddressWithBluetoothAddressTypeAsync(
                hint.address,
                hint.kind
            ),
            deadline
        )
    });
    let services = await_winrt!(
        device
            .0
            .GetGattServicesForUuidWithCacheModeAsync(SERVICE, BluetoothCacheMode::Uncached),
        deadline
    );
    anyhow::ensure!(
        services.Status()? == GattCommunicationStatus::Success,
        "Bluetooth stream service unavailable"
    );
    let service = services.Services()?.GetAt(0)?;
    let ingress = characteristic(&service, INGRESS, deadline).await?;
    let egress = characteristic(&service, EGRESS, deadline).await?;
    // Optional tuning. A radio or Windows build without it keeps the defaults.
    let parameters = BluetoothLEPreferredConnectionParameters::ThroughputOptimized()
        .and_then(|preferred| device.0.RequestPreferredConnectionParameters(&preferred))
        .ok();
    let session = service.Session().ok();
    if let Some(session) = &session {
        let _ = session.SetMaintainConnection(true);
    }
    let packet_bytes = negotiated_packet_bytes(session.as_ref()).await;
    Ok(Client {
        ingress,
        egress,
        packet_bytes,
        _session: session,
        _parameters: parameters,
        _device: device,
    })
}

/// Reads and writes are idempotent in this protocol (a repeated packet is
/// recognised by its sequence), so a transient radio error is retried.
const ATT_ATTEMPTS: usize = 3;

async fn write_packet(characteristic: &GattCharacteristic, bytes: &[u8]) -> anyhow::Result<()> {
    let mut last = None;
    for attempt in 0..ATT_ATTEMPTS {
        if attempt > 0 {
            time::sleep(Duration::from_millis(150)).await;
        }
        match write_packet_once(characteristic, bytes).await {
            Ok(()) => return Ok(()),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("Bluetooth write failed")))
}

async fn read_packet(characteristic: &GattCharacteristic) -> anyhow::Result<Vec<u8>> {
    let mut last = None;
    for attempt in 0..ATT_ATTEMPTS {
        if attempt > 0 {
            time::sleep(Duration::from_millis(150)).await;
        }
        match read_packet_once(characteristic).await {
            Ok(packet) => return Ok(packet),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("Bluetooth read failed")))
}

async fn write_packet_once(characteristic: &GattCharacteristic, bytes: &[u8]) -> anyhow::Result<()> {
    let writer = DataWriter::new()?;
    writer.WriteBytes(bytes)?;
    let written = await_winrt!(
        characteristic.WriteValueWithResultAndOptionAsync(
            &writer.DetachBuffer()?,
            GattWriteOption::WriteWithResponse
        ),
        time::Instant::now() + ATT_TIMEOUT
    );
    anyhow::ensure!(
        written.Status()? == GattCommunicationStatus::Success,
        "Bluetooth write failed"
    );
    Ok(())
}

async fn read_packet_once(characteristic: &GattCharacteristic) -> anyhow::Result<Vec<u8>> {
    let read = await_winrt!(
        characteristic.ReadValueWithCacheModeAsync(BluetoothCacheMode::Uncached),
        time::Instant::now() + ATT_TIMEOUT
    );
    anyhow::ensure!(
        read.Status()? == GattCommunicationStatus::Success,
        "Bluetooth read failed"
    );
    buffer_bytes(&read.Value()?, ble_link::MAX_PACKET_BYTES)
}

async fn drive_client(
    ingress: &GattCharacteristic,
    egress: &GattCharacteristic,
    packet_bytes: usize,
    stream: DuplexStream,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut sent = 0u32;
    let mut received = 0u32;
    let mut previous = None::<Vec<u8>>;
    let mut total_sent = 0usize;
    let mut total_received = 0usize;
    let mut buffer = vec![0; packet_bytes - 5];
    let started = Instant::now();
    // Reads are the only way to receive: poll fast while data flows, slower
    // while the link is quiet. Writes never postpone the next read.
    let mut idle_polls = 0u32;
    let mut next_poll = time::Instant::now();
    while !*stop.borrow() && started.elapsed() < ble_link::LIFETIME_LIMIT {
        tokio::select! {
            _ = stop.changed() => break,
            read = reader.read(&mut buffer) => {
                let count = read?;
                if count == 0 { break; }
                total_sent += count;
                anyhow::ensure!(total_sent <= ble_link::MAX_LINK_BYTES, "Bluetooth session send limit reached");
                write_packet(ingress, &ble_link::packet(sent, &buffer[..count])?).await?;
                // An answer usually follows what was just sent.
                idle_polls = 0;
                next_poll = next_poll.min(time::Instant::now() + ble_link::poll_delay(0));
                sent = sent.checked_add(1).ok_or_else(|| anyhow::anyhow!("Bluetooth send sequence exhausted"))?;
            }
            _ = time::sleep_until(next_poll) => {
                let packet = read_packet(egress).await?;
                if packet == [0] {
                    idle_polls = idle_polls.saturating_add(1);
                    next_poll = time::Instant::now() + ble_link::poll_delay(idle_polls);
                    continue;
                }
                idle_polls = 0;
                next_poll = time::Instant::now() + ble_link::poll_delay(0);
                if packet == ble_link::CLOSE { break; }
                let (sequence, bytes) = ble_link::data(&packet)?;
                if sequence == received {
                    total_received += bytes.len();
                    anyhow::ensure!(total_received <= ble_link::MAX_LINK_BYTES, "Bluetooth session receive limit reached");
                    time::timeout(Duration::from_secs(30), writer.write_all(bytes)).await??;
                    received = received.checked_add(1).ok_or_else(|| anyhow::anyhow!("Bluetooth receive sequence exhausted"))?;
                    previous = Some(packet.clone());
                } else {
                    anyhow::ensure!(previous.as_deref() == Some(packet.as_slice()), "Bluetooth receive sequence mismatch");
                }
                write_packet(ingress, &ble_link::ack(sequence)).await?;
            }
        }
    }
    Ok(())
}

struct Device(BluetoothLEDevice);

impl Drop for Device {
    fn drop(&mut self) {
        let _ = self.0.Close();
    }
}

async fn read_metadata(hint: DeviceHint) -> anyhow::Result<String> {
    let deadline = time::Instant::now() + CONNECT_TIMEOUT;
    let device = Device(if hint.kind == BluetoothAddressType::Unspecified {
        await_winrt!(
            BluetoothLEDevice::FromBluetoothAddressAsync(hint.address),
            deadline
        )
    } else {
        await_winrt!(
            BluetoothLEDevice::FromBluetoothAddressWithBluetoothAddressTypeAsync(
                hint.address,
                hint.kind
            ),
            deadline
        )
    });
    let services = await_winrt!(
        device
            .0
            .GetGattServicesForUuidWithCacheModeAsync(SERVICE, BluetoothCacheMode::Uncached),
        deadline
    );
    if services.Status()? != GattCommunicationStatus::Success {
        bail!("Windows Bluetooth could not resolve the peer discovery service.");
    }
    let service = services.Services()?.GetAt(0)?;
    let characteristics = await_winrt!(
        service.GetCharacteristicsWithCacheModeAsync(BluetoothCacheMode::Uncached),
        deadline
    );
    if characteristics.Status()? != GattCommunicationStatus::Success {
        bail!("Windows Bluetooth could not resolve the peer discovery characteristic.");
    }
    let characteristics = characteristics.Characteristics()?;
    let mut enriched = None;
    let mut legacy = None;
    for index in 0..characteristics.Size()?.min(64) {
        let characteristic = characteristics.GetAt(index)?;
        match characteristic.Uuid()? {
            DEVICE_HINT => enriched = Some(characteristic),
            METADATA => legacy = Some(characteristic),
            _ => (),
        }
    }
    if let Some(characteristic) = enriched {
        if let Ok(text) = read_metadata_characteristic(&characteristic, deadline).await {
            if serde_json::from_str::<super::Metadata>(&text).is_ok() {
                return Ok(text);
            }
        }
    }
    let legacy = legacy
        .context("Windows Bluetooth could not resolve the legacy discovery characteristic.")?;
    read_metadata_characteristic(&legacy, deadline).await
}

async fn read_metadata_characteristic(
    characteristic: &GattCharacteristic,
    deadline: time::Instant,
) -> anyhow::Result<String> {
    let result = await_winrt!(
        characteristic.ReadValueWithCacheModeAsync(BluetoothCacheMode::Uncached),
        deadline
    );
    if result.Status()? != GattCommunicationStatus::Success {
        bail!("Windows Bluetooth could not read the peer discovery characteristic.");
    }
    let value = result.Value()?;
    let length = value.Length()? as usize;
    if !(1..=MAX_METADATA_BYTES).contains(&length) {
        bail!("Invalid Bluetooth discovery payload length.");
    }
    let mut bytes = vec![0; length];
    DataReader::FromBuffer(&value)?.ReadBytes(&mut bytes)?;
    let text = String::from_utf8(bytes).context("Invalid Bluetooth discovery payload encoding.")?;
    Ok(text)
}

#[derive(PartialEq, Eq)]
struct AdvertisedMetadata {
    legacy: String,
    with_hints: Option<String>,
}

/// This PC's private IPv4 addresses on wired and wireless LAN adapters
/// (Wi-Fi Direct host adapters included), wireless first, at most six.
pub(super) fn local_ipv4_addresses() -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    if let Ok(host_names) = NetworkInformation::GetHostNames() {
        for index in 0..host_names.Size().unwrap_or(0).min(64) {
            let Some((ip, adapter)) = host_names.GetAt(index).ok().and_then(|host| {
                if host.Type().ok()? != HostNameType::Ipv4 {
                    return None;
                }
                let adapter = host
                    .IPInformation()
                    .ok()?
                    .NetworkAdapter()
                    .ok()?
                    .IanaInterfaceType()
                    .ok()?;
                let ip = host
                    .CanonicalName()
                    .ok()?
                    .to_string()
                    .parse::<Ipv4Addr>()
                    .ok()?;
                Some((ip, adapter))
            }) else {
                continue;
            };
            // Include ordinary wired and wireless LAN adapters. Do not publish
            // public IPs, VPN tunnel interfaces, or loopback addresses.
            if matches!(adapter, 6 | 71) && (ip.is_private() || ip.is_link_local()) {
                ips.push((adapter != 71, ip));
            }
        }
    }
    ips.sort_unstable();
    let mut addresses = Vec::new();
    for (_, ip) in ips {
        if !addresses.contains(&ip) {
            addresses.push(ip);
        }
        if addresses.len() == 6 {
            break;
        }
    }
    addresses
}

fn local_metadata(metadata: &serde_json::Value) -> anyhow::Result<AdvertisedMetadata> {
    let mut result = metadata.clone();
    result["addresses"] = serde_json::to_value(local_ipv4_addresses())?;
    let with_hints = (result.get("label").is_some() || result.get("platform").is_some())
        .then(|| result.to_string())
        .filter(|text| text.len() <= MAX_METADATA_BYTES);
    if let Some(object) = result.as_object_mut() {
        object.remove("label");
        object.remove("platform");
        object.remove("picture");
    }
    let legacy = serde_json::to_string(&result)?;
    if legacy.len() > MAX_METADATA_BYTES {
        bail!("Windows Bluetooth discovery metadata is too large.");
    }
    Ok(AdvertisedMetadata { legacy, with_hints })
}

fn public_metadata(text: &str) -> Option<serde_json::Value> {
    let input = serde_json::from_str::<serde_json::Value>(text).ok()?;
    let version = input.get("version")?.as_u64()?;
    let fingerprint = input.get("fingerprint")?.as_str()?;
    let port = input.get("port")?.as_u64()?;
    let ble_mesh = input.get("bleMesh")?.as_bool()?;
    if version != 1
        || !(1..=u16::MAX as u64).contains(&port)
        || fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    // Publish only this explicit allow-list even if a caller adds local-only
    // configuration to its metadata object in a later protocol version.
    let mut result = serde_json::json!({
        "version": version,
        "fingerprint": fingerprint,
        "port": port,
        "addresses": [],
        "bleMesh": ble_mesh,
    });
    if let Some(label) = input
        .get("label")
        .and_then(|value| value.as_str())
        .filter(|label| valid_device_label(label))
    {
        result["label"] = label.into();
    }
    if let Some(platform) = input
        .get("platform")
        .and_then(|value| value.as_str())
        .filter(|platform| PEER_PLATFORMS.contains(platform))
    {
        result["platform"] = platform.into();
    }
    Some(result)
}

fn bluetooth_error(error: &anyhow::Error) -> String {
    if error
        .downcast_ref::<windows::core::Error>()
        .is_some_and(|error| error.code().0 == E_ACCESSDENIED)
    {
        "Windows denied access to Bluetooth discovery. Check Bluetooth permissions in Windows Settings.".into()
    } else {
        "Windows Bluetooth discovery could not start. Check Bluetooth availability in Windows Settings.".into()
    }
}

fn format_address(address: u64) -> String {
    let [_, _, a, b, c, d, e, f] = address.to_be_bytes();
    format!("{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{f:02X}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hardware check, not part of the default suite: starts the real WinRT
    /// scanner and GATT service on this computer's Bluetooth adapter and
    /// prints what the radio reports, including any Qguard devices in range.
    #[test]
    #[ignore = "needs a Bluetooth LE adapter; run with --ignored --nocapture"]
    fn radio_scans_and_advertises_on_this_adapter() {
        let metadata = serde_json::json!({
            "version": 1,
            "fingerprint": "ab".repeat(32),
            "port": 45111,
            "addresses": [],
            "bleMesh": true,
            "label": "Radio self-check",
            "platform": "windows",
        })
        .to_string();
        let radio = start(&metadata).expect("the Bluetooth worker starts");
        let seconds = std::env::var("QGUARD_BLE_PROBE_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(12u64);
        let mut last = radio.snapshot().unwrap();
        for _ in 0..seconds {
            thread::sleep(Duration::from_secs(1));
            last = radio.snapshot().unwrap();
        }
        println!(
            "available={} scanning={} advertising={} error={:?} peers={}",
            last.available,
            last.scanning,
            last.advertising,
            last.error,
            last.peers.len()
        );
        for peer in &last.peers {
            println!("peer rssi={:?} metadata={}", peer.rssi, peer.metadata);
        }
        assert!(last.available, "no usable Bluetooth LE adapter");
        assert!(last.scanning, "the scanner did not start: {:?}", last.error);
        assert!(last.advertising, "the GATT service is not advertising: {:?}", last.error);
    }
}

#[cfg(test)]
mod raw_scan {
    use super::*;

    /// Hardware check: every advertisement this adapter hears, unfiltered,
    /// and which of them carry the Qguard service UUID.
    #[test]
    #[ignore = "needs a Bluetooth LE adapter; run with --ignored --nocapture"]
    fn unfiltered_scan_lists_advertisers_and_qguard_devices() {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED).ok() };
        let seen = Arc::new(Mutex::new(HashMap::<u64, (i16, bool, String, u32)>::new()));
        let sink = Arc::clone(&seen);
        let native = BluetoothLEAdvertisementWatcher::new().unwrap();
        native.SetScanningMode(BluetoothLEScanningMode::Active).unwrap();
        let handler = TypedEventHandler::<
            BluetoothLEAdvertisementWatcher,
            BluetoothLEAdvertisementReceivedEventArgs,
        >::new(move |_, args| {
            let Some(args) = args.as_ref() else { return Ok(()) };
            let address = args.BluetoothAddress()?;
            let advertisement = args.Advertisement()?;
            let uuids = advertisement.ServiceUuids()?;
            let mut qguard = false;
            let mut listed = Vec::new();
            for index in 0..uuids.Size()?.min(8) {
                let uuid = uuids.GetAt(index)?;
                qguard |= uuid == SERVICE;
                listed.push(format!("{uuid:?}"));
            }
            let rssi = args.RawSignalStrengthInDBm().unwrap_or(0);
            if let Ok(mut seen) = sink.lock() {
                let entry = seen.entry(address).or_insert((rssi, false, String::new(), 0));
                entry.0 = rssi;
                entry.1 |= qguard;
                if !listed.is_empty() {
                    entry.2 = listed.join(",");
                }
                entry.3 += 1;
            }
            Ok(())
        });
        native.Received(&handler).unwrap();
        native.Start().unwrap();
        thread::sleep(Duration::from_secs(20));
        println!("watcher status: {:?}", native.Status().unwrap());
        native.Stop().unwrap();
        let seen = seen.lock().unwrap();
        println!("advertisers heard: {}", seen.len());
        let mut strongest: Vec<_> = seen.values().collect();
        strongest.sort_by_key(|entry| -entry.0);
        for (rssi, qguard, uuids, count) in strongest.into_iter().take(12) {
            println!("rssi={rssi} packets={count} qguard={qguard} uuids=[{uuids}]");
        }
        println!("qguard devices: {}", seen.values().filter(|entry| entry.1).count());
    }
}
