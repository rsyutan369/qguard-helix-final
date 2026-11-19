//! A local Windows Wi-Fi Direct group owner for explicitly requested sharing.
//! Network access still requires QHCE peer authentication in the Rust core.

use std::{
    future::IntoFuture,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
};

use tokio::{
    sync::{mpsc as async_mpsc, watch},
    time,
};
use windows::{
    core::HSTRING,
    Devices::WiFiDirect::{
        WiFiDirectAdvertisementPublisher, WiFiDirectAdvertisementPublisherStatus,
        WiFiDirectConnectionListener, WiFiDirectConnectionRequest,
        WiFiDirectConnectionRequestedEventArgs, WiFiDirectConnectionStatus, WiFiDirectDevice,
    },
    Foundation::TypedEventHandler,
    Security::Credentials::PasswordCredential,
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::WiFi::{
            WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory, WlanOpenHandle,
        },
        System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED},
    },
};
use zeroize::Zeroizing;

use super::{HotspotDetails, HotspotSnapshot};
use crate::{
    crypto::provider,
    error::{QGuardError, Result},
};

const START_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_CLIENTS: usize = 16;

struct State {
    snapshot: HotspotSnapshot,
    ssid: String,
    password: Zeroizing<String>,
}

pub(super) struct Hotspot {
    state: Arc<Mutex<State>>,
    stop: watch::Sender<bool>,
    stopped: mpsc::Receiver<()>,
}

impl Hotspot {
    /// Enumerate physical WLAN interfaces. A successful host callback is still
    /// required to establish that the driver supports a Wi-Fi Direct AP.
    pub(super) fn available() -> Result<bool> {
        let mut handle = HANDLE::default();
        let mut version = 0;
        // Native WLAN allocates the interface list. Both resources are released
        // below on every path, and only its validated non-null count is read.
        let status = unsafe { WlanOpenHandle(2, None, &mut version, &mut handle) };
        if status != 0 {
            return Ok(false);
        }
        let mut interfaces = std::ptr::null_mut();
        let status = unsafe { WlanEnumInterfaces(handle, None, &mut interfaces) };
        let available =
            status == 0 && !interfaces.is_null() && unsafe { (*interfaces).dwNumberOfItems > 0 };
        if !interfaces.is_null() {
            unsafe { WlanFreeMemory(interfaces.cast()) };
        }
        unsafe { WlanCloseHandle(handle, None) };
        Ok(available)
    }

    pub(super) fn start() -> Result<Self> {
        if !Self::available()? {
            return Err(wifi_error("Windows has no available WLAN adapter."));
        }
        let ssid = format!("QGuard-{}", hex::encode(provider::random_array::<4>()));
        let password = Zeroizing::new(hex::encode(provider::random_array::<16>()));
        let state = Arc::new(Mutex::new(State {
            snapshot: HotspotSnapshot {
                starting: true,
                ..HotspotSnapshot::default()
            },
            ssid,
            password,
        }));
        let (stop, stopped) = watch::channel(false);
        let (ready, setup) = mpsc::sync_channel(1);
        let (finished, completion) = mpsc::sync_channel(1);
        let worker_state = Arc::clone(&state);
        thread::Builder::new()
            .name("helix-local-wifi".into())
            .spawn(move || {
                let result = (|| -> anyhow::Result<()> {
                    let _apartment = Apartment::new()?;
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()?;
                    runtime.block_on(run(worker_state.clone(), stopped, &ready))
                })();
                if let Err(error) = result {
                    if let Ok(mut state) = worker_state.lock() {
                        state.snapshot.active = false;
                        state.snapshot.starting = false;
                        state.snapshot.error = Some(format!(
                            "Could not host a local Windows Wi-Fi link: {error}"
                        ));
                    }
                    let _ = ready.try_send(Err(error.to_string()));
                }
                let _ = finished.try_send(());
            })
            .map_err(|_| wifi_error("Could not start the Windows Wi-Fi worker."))?;
        match setup.recv_timeout(START_TIMEOUT) {
            Ok(Ok(())) => Ok(Self {
                state,
                stop,
                stopped: completion,
            }),
            Ok(Err(error)) => {
                stop.send_replace(true);
                Err(wifi_error(&error))
            }
            Err(_) => {
                stop.send_replace(true);
                Err(wifi_error(
                    "Windows did not initialize the local Wi-Fi link in time.",
                ))
            }
        }
    }

    pub(super) fn snapshot(&self) -> Result<HotspotSnapshot> {
        self.state
            .lock()
            .map(|state| state.snapshot.clone())
            .map_err(|_| wifi_error("The Windows Wi-Fi state is unavailable."))
    }

    pub(super) fn details(&self) -> Result<Option<HotspotDetails>> {
        let state = self
            .state
            .lock()
            .map_err(|_| wifi_error("The Windows Wi-Fi state is unavailable."))?;
        Ok(state.snapshot.active.then(|| HotspotDetails {
            ssid: state.ssid.clone(),
            password: state.password.to_string(),
            security: Some("wpa2".into()),
            addresses: super::windows::local_ipv4_addresses(),
        }))
    }
}

impl Drop for Hotspot {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        let _ = self.stopped.recv_timeout(START_TIMEOUT);
    }
}

struct Apartment;

impl Apartment {
    fn new() -> anyhow::Result<Self> {
        // This private worker owns its MTA lifetime, including WinRT callbacks.
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }?;
        Ok(Self)
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        // Balanced with the successful RoInitialize on this same thread.
        unsafe { RoUninitialize() };
    }
}

struct Publisher {
    publisher: WiFiDirectAdvertisementPublisher,
    listener: WiFiDirectConnectionListener,
    listener_token: i64,
}

impl Drop for Publisher {
    fn drop(&mut self) {
        let _ = self.listener.RemoveConnectionRequested(self.listener_token);
        let _ = self.publisher.Stop();
    }
}

struct Client(WiFiDirectDevice);

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.0.Close();
    }
}

async fn run(
    state: Arc<Mutex<State>>,
    mut stopped: watch::Receiver<bool>,
    ready: &mpsc::SyncSender<std::result::Result<(), String>>,
) -> anyhow::Result<()> {
    let publisher = WiFiDirectAdvertisementPublisher::new()?;
    let advertisement = publisher.Advertisement()?;
    advertisement.SetIsAutonomousGroupOwnerEnabled(true)?;
    let legacy = advertisement.LegacySettings()?;
    legacy.SetIsEnabled(true)?;
    let password = PasswordCredential::new()?;
    {
        let state = state
            .lock()
            .map_err(|_| anyhow::anyhow!("Wi-Fi state lock failed"))?;
        legacy.SetSsid(&HSTRING::from(&state.ssid))?;
        password.SetPassword(&HSTRING::from(state.password.as_str()))?;
    }
    legacy.SetPassphrase(&password)?;
    let listener = WiFiDirectConnectionListener::new()?;
    let (requests, mut incoming) = async_mpsc::channel::<WiFiDirectConnectionRequest>(MAX_CLIENTS);
    let token = listener.ConnectionRequested(&TypedEventHandler::<
        WiFiDirectConnectionListener,
        WiFiDirectConnectionRequestedEventArgs,
    >::new(move |_, args| {
        if let Some(args) = args.as_ref() {
            if let Ok(request) = args.GetConnectionRequest() {
                if let Err(error) = requests.try_send(request) {
                    let _ = error.into_inner().Close();
                }
            }
        }
        Ok(())
    }))?;
    let _publisher = Publisher {
        publisher,
        listener,
        listener_token: token,
    };
    _publisher.publisher.Start()?;
    {
        let mut state = state
            .lock()
            .map_err(|_| anyhow::anyhow!("Wi-Fi state lock failed"))?;
        state.snapshot.available = true;
    }
    let _ = ready.try_send(Ok(()));
    let mut clients: Vec<Client> = Vec::new();
    let mut poll = time::interval(Duration::from_millis(250));
    poll.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        let mut connection_stop = stopped.clone();
        tokio::select! {
            _ = stopped.wait_for(|stop| *stop) => break,
            _ = poll.tick() => {
                clients.retain(|client| client.0.ConnectionStatus()
                    .is_ok_and(|status| status == WiFiDirectConnectionStatus::Connected));
                let status = _publisher.publisher.Status()?;
                let mut current = state.lock().map_err(|_| anyhow::anyhow!("Wi-Fi state lock failed"))?;
                current.snapshot.active = status == WiFiDirectAdvertisementPublisherStatus::Started;
                current.snapshot.starting = matches!(status, WiFiDirectAdvertisementPublisherStatus::Created);
                if status == WiFiDirectAdvertisementPublisherStatus::Aborted {
                    current.snapshot.error = Some("Windows could not start Wi-Fi Direct. Check that Wi-Fi is on, the adapter supports Wi-Fi Direct, and Windows Mobile Hotspot is stopped.".into());
                    break;
                }
            }
            request = incoming.recv() => {
                let Some(request) = request else { break };
                if clients.len() >= MAX_CLIENTS {
                    let _ = request.Close();
                    continue;
                }
                let operation = WiFiDirectDevice::FromIdAsync(&request.DeviceInformation()?.Id()?)?;
                let result = tokio::select! {
                    _ = connection_stop.wait_for(|stop| *stop) => {
                        let _ = operation.Cancel();
                        let _ = request.Close();
                        break;
                    }
                    result = time::timeout(CONNECTION_TIMEOUT, operation.clone().into_future()) => result,
                };
                let _ = request.Close();
                match result {
                    Ok(Ok(device)) => clients.push(Client(device)),
                    Ok(Err(_)) => {},
                    Err(_) => { let _ = operation.Cancel(); },
                }
            }
        }
    }
    if let Ok(mut current) = state.lock() {
        current.snapshot.active = false;
        current.snapshot.starting = false;
    }
    Ok(())
}

fn wifi_error(message: &str) -> QGuardError {
    QGuardError::Storage(format!("Local Wi-Fi: {message}"))
}
