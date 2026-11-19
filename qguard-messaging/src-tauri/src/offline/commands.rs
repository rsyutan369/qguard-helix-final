//! Tauri boundary for the local network. Account IDs come from the active
//! native session. Webview arguments never select an account or a trust store.

use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::{
    error::{QGuardError, Result},
    state::AppState,
};

use super::{
    alerts,
    avatar::{self, AvatarBook},
    background, channel, diag, enrollment, link, mesh, relay_net,
    network::{self, changed, lock, Network, PeerActivity, PeerStatus, Runtime},
    pairing::{self, AuthenticatedPeer, PairingDecision, PairingView},
    profile::{local_owner, owner_name, PeerCapability, PeerMetadata, TrustBook},
    session::{Identity, Session},
    smart::{self, SmartStatus},
    transfer::{self, TransferMonitorEntry, TransferSummary},
    wire::{self, Control},
    xfer::{Direction, SelectedSource, Status, TransferAction},
};

pub(crate) use super::network::Runtime as OfflineRuntime;

#[tauri::command]
pub(crate) async fn offline_verify_principal(app: AppHandle) -> Result<()> {
    let state = app.state::<AppState>();
    state.offline_principal.verify(&state).await?;
    changed(&app);
    Ok(())
}

/// Desktop sign-in without internet: the account password against this
/// device's offline verifier. It authorizes Mesh and XFER only.
#[tauri::command]
pub(crate) async fn offline_sign_in(app: AppHandle, email: String, password: String) -> Result<enrollment::OfflineSession> {
    let password = zeroize::Zeroizing::new(password.into_bytes());
    {
        let state = app.state::<AppState>();
        state.check_decrypt_rate_limit("offline_sign_in", &enrollment::normalize_email(&email), 10, 15 * 60)?;
    }
    let worker = app.clone();
    let session = tokio::task::spawn_blocking(move || {
        enrollment::sign_in(&worker.state::<AppState>(), &email, &password, chrono::Utc::now().timestamp())
    })
    .await
    .map_err(|_| QGuardError::Storage("Offline sign-in could not finish.".into()))??;
    let state = app.state::<AppState>();
    state.offline_principal.set_offline(&session);
    state.audit_info("offline_sign_in", "Signed in for offline Mesh and XFER with this device's offline credential");
    changed(&app);
    Ok(session)
}

/// Leave offline mode (for the online sign-in screen): stop local networking
/// and drop the offline grant. The enrollment stays for the next offline use.
#[tauri::command]
pub(crate) async fn offline_sign_out(app: AppHandle) -> Result<()> {
    {
        let state = app.state::<AppState>();
        // Only an offline-mode session is ended here; an online one signs out
        // through auth_logout.
        if state.offline_principal.online_owner(&state).is_ok() {
            return Ok(());
        }
    }
    let _ = stop(&app, false, None).await;
    let state = app.state::<AppState>();
    state.offline_principal.clear_offline();
    state.audit_info("offline_sign_out", "Left offline mode on this device");
    changed(&app);
    Ok(())
}

/// Android without internet: after the app-entry lock was unlocked for this
/// account, resume offline Mesh and XFER from the device enrollment.
#[tauri::command]
pub(crate) fn offline_resume_unlocked(app: AppHandle, user_id: String) -> Result<enrollment::OfflineSession> {
    let state = app.state::<AppState>();
    #[cfg(target_os = "android")]
    let unlocked = state.is_applock_unlocked()
        && state.load_applock_user_pointer().as_deref() == Some(user_id.as_str());
    // Desktop has no app-entry lock: it signs in offline with the password.
    #[cfg(not(target_os = "android"))]
    let unlocked = false;
    let session = enrollment::resume(&state, &user_id, unlocked, chrono::Utc::now().timestamp())?;
    state.offline_principal.set_offline(&session);
    state.audit_info("offline_resume", "Resumed offline Mesh and XFER after the app-entry unlock");
    changed(&app);
    Ok(session)
}

/// After an online password sign-in: verify the account online, then keep a
/// stretched verifier so this device can sign in offline later.
#[tauri::command]
pub(crate) async fn offline_enroll_password(app: AppHandle, user_id: String, password: String) -> Result<()> {
    let password = zeroize::Zeroizing::new(password.into_bytes());
    {
        let state = app.state::<AppState>();
        state.require_user_auth(&user_id)?;
        state.offline_principal.verify(&state).await?;
        if state.offline_principal.online_owner(&state)? != user_id {
            return Err(QGuardError::Trust("The signed-in account changed.".into()));
        }
    }
    let worker = app.clone();
    let account = user_id.clone();
    tokio::task::spawn_blocking(move || enrollment::set_password(&worker.state::<AppState>(), &account, &password))
        .await
        .map_err(|_| QGuardError::Storage("Offline sign-in could not be prepared.".into()))??;
    app.state::<AppState>().audit_info("offline_enrolled", "Enabled offline sign-in for Mesh and XFER on this device");
    changed(&app);
    Ok(())
}

/// Keep the last online subscription row so the offline paywall verdict
/// matches the online one. Only an online-verified session may write it.
#[tauri::command]
pub(crate) fn offline_store_entitlement(
    app: AppHandle,
    expected_account: String,
    subscription: Option<serde_json::Value>,
) -> Result<()> {
    let state = app.state::<AppState>();
    if state.offline_principal.online_owner(&state)? != expected_account {
        return Err(QGuardError::Trust("The signed-in account changed.".into()));
    }
    enrollment::set_entitlement(&state, &expected_account, subscription)
}

/// Turn off offline sign-in for this account on this device.
#[tauri::command]
pub(crate) fn offline_forget_device(app: AppHandle, expected_account: String) -> Result<()> {
    let state = app.state::<AppState>();
    let owner = require_snapshot_owner(&state, &expected_account)?;
    enrollment::remove(&state, &owner);
    state.audit_info("offline_forgotten", "Turned off offline sign-in for this device");
    changed(&app);
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OfflineStatus {
    running: bool,
    lan_discovery_running: bool,
    fingerprint: String,
    port: Option<u16>,
    peers: Vec<PeerStatus>,
    network_error: Option<String>,
    platform: &'static str,
    auto_start: bool,
    smart_connect: SmartStatus,
    local_owner: Option<String>,
    offline_access: enrollment::OfflineAccess,
    /// Keep Mesh running while Qguard is locked (the user's setting).
    background: bool,
    /// Carry sealed envelopes for trusted devices (the user's setting).
    relay: bool,
    /// Show this account's picture to nearby devices before pairing.
    share_picture_nearby: bool,
    /// Sealed envelopes this device carries for others right now.
    relay_carrying: usize,
    /// SHA3-256 digest of this account's picture as shared with trusted
    /// devices, or none when no picture is set.
    local_avatar: Option<String>,
}

#[tauri::command]
pub(crate) async fn offline_status(app: AppHandle) -> Result<OfflineStatus> {
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let runtime = app.state::<Runtime>();
        let owner = local_owner(&state)?;
        let network = network_for(&runtime, &owner)?;
        let status = build_status(&state, &runtime, &owner, network.as_deref())?;
        require_snapshot_owner(&state, &owner)?;
        Ok(status)
    })
    .await
    .map_err(|_| QGuardError::Storage("Could not read local networking status.".into()))?
}

fn build_status(
    state: &AppState,
    runtime: &Runtime,
    owner: &str,
    network: Option<&Network>,
) -> Result<OfflineStatus> {
    let network = network.filter(|network| network.running());
    let (book, fingerprint, avatars) = {
        let _gate = lock(&runtime.storage)?;
        let fingerprint = match network {
            Some(network) => network.fingerprint.clone(),
            None => Identity::load(state, owner)?.fingerprint().to_string(),
        };
        // An unreadable picture cache must not hide the device list.
        (TrustBook::load(state, owner)?, fingerprint, AvatarBook::load(state, owner).unwrap_or_default())
    };
    let (port, mut peers, network_error, smart_connect) = match network {
        Some(network) => (
            Some(network.port),
            network.peers(&book)?,
            lock(&network.error)?.clone(),
            lock(&network.smart)?.status(),
        ),
        None => (
            None,
            network::peer_status(&book, None, None, None),
            None,
            SmartStatus::default(),
        ),
    };
    for peer in &mut peers {
        let digest = avatars.peer(&book, peer.fingerprint()).map(|picture| picture.digest.clone());
        peer.set_avatar(digest);
    }
    Ok(OfflineStatus {
        local_avatar: avatars.local_digest(),
        running: port.is_some(),
        lan_discovery_running: network.is_some_and(Network::lan_discovery_running),
        fingerprint,
        port,
        peers,
        network_error,
        platform: std::env::consts::OS,
        auto_start: book.auto_start,
        smart_connect,
        local_owner: book.local_owner,
        background: book.background,
        relay: book.relay,
        share_picture_nearby: book.share_picture_nearby,
        relay_carrying: network
            .and_then(|network| network.relay_store.lock().ok().map(|store| store.as_ref().map_or(0, |store| store.carrying())))
            .unwrap_or(0),
        offline_access: enrollment::access(state, owner, chrono::Utc::now().timestamp()),
    })
}

/// Record the signed-in profile name that this device shares with a peer only
/// after both users confirm a pairing code. Clearing it stops sharing it.
#[tauri::command]
pub(crate) fn offline_set_owner_name(
    app: AppHandle,
    display_name: Option<String>,
    expected_account: String,
) -> Result<()> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let owner = require_snapshot_owner(&state, &expected_account)?;
    let name = owner_name(display_name.as_deref());
    let updated = {
        let _gate = lock(&runtime.storage)?;
        require_snapshot_owner(&state, &owner)?;
        let mut book = TrustBook::load(&state, &owner)?;
        if book.local_owner == name {
            false
        } else {
            book.local_owner = name;
            book.save(&state, &owner)?;
            true
        }
    };
    if updated {
        changed(&app);
    }
    Ok(())
}

/// Store this account's profile picture (a small thumbnail the app made from
/// the signed-in profile) and announce it to connected trusted devices.
/// `None` removes it. Returns the picture's SHA3-256 digest.
#[tauri::command]
pub(crate) fn offline_set_avatar(
    app: AppHandle,
    image: Option<String>,
    expected_account: String,
) -> Result<Option<String>> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let owner = require_snapshot_owner(&state, &expected_account)?;
    let picture = match image {
        Some(encoded) => {
            if encoded.len() > avatar::MAX_BYTES.div_ceil(3) * 4 {
                return Err(QGuardError::InvalidInput("The profile picture is too large.".into()));
            }
            let bytes = Zeroizing::new(
                STANDARD
                    .decode(encoded.as_bytes())
                    .map_err(|_| QGuardError::InvalidInput("The profile picture is not valid base64.".into()))?,
            );
            Some(avatar::from_bytes(&bytes)?)
        }
        None => None,
    };
    let digest = picture.as_ref().map(|picture| picture.digest.clone());
    let updated = {
        let _gate = lock(&runtime.storage)?;
        require_snapshot_owner(&state, &owner)?;
        let mut avatars = AvatarBook::load(&state, &owner)?;
        if avatars.local_digest() == digest {
            false
        } else {
            avatars.local = picture;
            let book = TrustBook::load(&state, &owner)?;
            avatars.save(&state, &owner, &book)?;
            true
        }
    };
    if updated {
        if let Some(network) = network_for(&runtime, &owner)? {
            network.channels.announce_profile();
            if network.nearby_picture_tag(&app).is_some() || digest.is_none() {
                let restarting = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = network.restart_bluetooth(&restarting).await;
                });
            }
        }
        changed(&app);
    }
    Ok(digest)
}

#[derive(Serialize)]
pub(crate) struct AvatarView {
    digest: String,
    #[serde(rename = "dataUrl")]
    data_url: String,
}

/// A profile picture: this account's (`peer` omitted) or a trusted device's.
#[tauri::command]
pub(crate) async fn offline_avatar(
    app: AppHandle,
    peer: Option<String>,
    expected_account: String,
) -> Result<Option<AvatarView>> {
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let runtime = app.state::<Runtime>();
        let owner = require_snapshot_owner(&state, &expected_account)?;
        let _gate = lock(&runtime.storage)?;
        let avatars = AvatarBook::load(&state, &owner)?;
        let picture = match peer.as_deref() {
            None => avatars.local.clone(),
            Some(fingerprint) => {
                let book = TrustBook::load(&state, &owner)?;
                match avatars.peer(&book, fingerprint) {
                    Some(picture) => Some(picture.clone()),
                    None if !book.peers.contains_key(fingerprint) => {
                        network_for(&runtime, &owner)?.and_then(|network| network.nearby_picture(fingerprint))
                    }
                    None => None,
                }
            }
        };
        Ok(picture.map(|picture| AvatarView { digest: picture.digest.clone(), data_url: picture.data_url() }))
    })
    .await
    .map_err(|_| QGuardError::Storage("Could not read the profile picture.".into()))?
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DashboardPage {
    Mesh,
    Xfer,
    TransferHistory,
    OfflineSettings,
}

#[derive(Serialize)]
pub(crate) struct DashboardSnapshot {
    status: OfflineStatus,
    messages: Option<Vec<mesh::Message>>,
    transfers: Option<Vec<TransferSummary>>,
}

fn require_snapshot_owner(state: &AppState, expected: &str) -> Result<String> {
    let owner = local_owner(state)?;
    if owner != expected {
        return Err(QGuardError::Trust(
            "The active local account changed. Reopen the workspace to refresh it.".into(),
        ));
    }
    Ok(owner)
}

#[tauri::command]
pub(crate) async fn offline_dashboard_snapshot(
    app: AppHandle,
    page: DashboardPage,
    expected_account: String,
) -> Result<DashboardSnapshot> {
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let runtime = app.state::<Runtime>();
        // The view's account is a guard. Native auth still chooses the store.
        let owner = require_snapshot_owner(&state, &expected_account)?;
        let network = network_for(&runtime, &owner)?;
        let (messages, transfers) = match page {
            DashboardPage::Mesh => {
                let _gate = lock(&runtime.storage)?;
                (Some(mesh::snapshot(&state, &owner)?.messages), None)
            }
            DashboardPage::Xfer | DashboardPage::TransferHistory => (
                None,
                Some(list_transfers(&app, &owner, network.as_deref())?),
            ),
            DashboardPage::OfflineSettings => (None, None),
        };
        let status = build_status(&state, &runtime, &owner, network.as_deref())?;
        require_snapshot_owner(&state, &owner)?;
        Ok(DashboardSnapshot {
            status,
            messages,
            transfers,
        })
    })
    .await
    .map_err(|_| QGuardError::Storage("Could not read the local dashboard.".into()))?
}

#[tauri::command]
pub(crate) async fn offline_hotspot_start(app: AppHandle) -> Result<()> {
    let owner = local_owner(&app.state::<AppState>())?;
    let network = require_network(&app.state::<Runtime>(), &owner)?;
    let confirmation = app.clone();
    let allowed = tokio::task::spawn_blocking(move || {
        confirmation.dialog()
            .message("Create a temporary local Wi-Fi hotspot for nearby Qguard devices? Your current Wi-Fi connection may change.")
            .title("Create Qguard connection")
            .buttons(tauri_plugin_dialog::MessageDialogButtons::OkCancel)
            .blocking_show()
    }).await.map_err(|_| QGuardError::Storage("Could not open the hotspot confirmation.".into()))?;
    if !allowed {
        return Ok(());
    }
    let worker = app.clone();
    tokio::task::spawn_blocking(move || {
        let mut smart = lock(&network.smart)?;
        network.check(&worker)?;
        smart.start_hotspot()?;
        if let Err(error) = network.check(&worker) {
            smart.stop_hotspot();
            return Err(error);
        }
        Ok(())
    })
    .await
    .map_err(|_| QGuardError::Storage("Could not start the temporary hotspot.".into()))??;
    changed(&app);
    Ok(())
}

#[tauri::command]
pub(crate) async fn offline_hotspot_stop(app: AppHandle) -> Result<()> {
    let owner = local_owner(&app.state::<AppState>())?;
    let network = require_network(&app.state::<Runtime>(), &owner)?;
    let worker = app.clone();
    tokio::task::spawn_blocking(move || {
        let mut smart = lock(&network.smart)?;
        network.check(&worker)?;
        smart.stop_hotspot();
        Ok::<_, QGuardError>(())
    })
    .await
    .map_err(|_| QGuardError::Storage("Could not stop the temporary hotspot.".into()))??;
    changed(&app);
    Ok(())
}

#[tauri::command]
pub(crate) async fn offline_hotspot_details(
    app: AppHandle,
) -> Result<Option<smart::HotspotDetails>> {
    let owner = local_owner(&app.state::<AppState>())?;
    let network = require_network(&app.state::<Runtime>(), &owner)?;
    tokio::task::spawn_blocking(move || {
        let smart = lock(&network.smart)?;
        network.check(&app)?;
        let details = smart.hotspot_details()?;
        network.check(&app)?;
        Ok(details)
    })
    .await
    .map_err(|_| QGuardError::Storage("Could not read temporary hotspot details.".into()))?
}

#[tauri::command]
pub(crate) async fn offline_bluetooth_permissions(app: AppHandle) -> Result<()> {
    local_owner(&app.state::<AppState>())?;
    tokio::task::spawn_blocking(smart::request_permissions)
        .await
        .map_err(|_| QGuardError::Storage("Could not open Bluetooth permissions.".into()))??;
    changed(&app);
    Ok(())
}

#[tauri::command]
pub(crate) async fn offline_bluetooth_restart(app: AppHandle) -> Result<()> {
    let owner = local_owner(&app.state::<AppState>())?;
    let network = require_network(&app.state::<Runtime>(), &owner)?;
    network.restart_bluetooth(&app).await
}

#[tauri::command]
pub(crate) async fn offline_start(app: AppHandle) -> Result<()> {
    start(&app, false, None).await
}

async fn start(app: &AppHandle, automatic: bool, expected_account: Option<&str>) -> Result<()> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let owner = expected_account.map_or_else(
        || local_owner(&state),
        |id| require_snapshot_owner(&state, id),
    )?;
    let _lifecycle = runtime.lifecycle.lock().await;
    require_snapshot_owner(&state, &owner)?;
    if automatic {
        let _gate = lock(&runtime.storage)?;
        if !TrustBook::load(&state, &owner)?.auto_start {
            return Ok(());
        }
    }
    if let Some(network) = network_for(&runtime, &owner)? {
        if automatic {
            network.set_stop_when_idle(false);
        } else {
            network.keep_running();
            if !lock(&network.smart)?.status().bluetooth_running() {
                network.restart_bluetooth(app).await?;
            }
        }
        return Ok(());
    }
    let previous = lock(&runtime.network)?.take();
    if let Some(previous) = previous {
        previous.stop_and_wait().await;
    }
    require_snapshot_owner(&state, &owner)?;
    let identity = {
        let _gate = lock(&runtime.storage)?;
        Identity::load(&state, &owner)?
    };
    let network = network::start(app.clone(), owner, identity, automatic).await?;
    if let Err(error) = network.check(app) {
        network.stop();
        return Err(error);
    }
    let keep_in_background = {
        let _gate = lock(&runtime.storage)?;
        TrustBook::load(&state, &network.owner)?.background
    };
    if keep_in_background {
        enable_background(&network).await;
    }
    *lock(&runtime.network)? = Some(network);
    state.audit_info("offline_network_started", "Started local Qguard networking");
    changed(app);
    Ok(())
}

#[tauri::command]
pub(crate) async fn offline_stop(app: AppHandle) -> Result<()> {
    stop(&app, false, None).await
}

async fn stop(app: &AppHandle, only_automatic: bool, expected_account: Option<&str>) -> Result<()> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let owner = expected_account.map_or_else(
        || local_owner(&state),
        |id| require_snapshot_owner(&state, id),
    )?;
    let _lifecycle = runtime.lifecycle.lock().await;
    require_snapshot_owner(&state, &owner)?;
    let previous = {
        let mut current = lock(&runtime.network)?;
        if let Some(network) = current
            .as_ref()
            .filter(|network| network.owner == owner && (!only_automatic || network.automatic()))
        {
            if only_automatic && (network.transfers.is_active() || network.pairings.has_pending()) {
                network.set_stop_when_idle(true);
                return Ok(());
            }
            current.take()
        } else {
            None
        }
    };
    if let Some(network) = previous {
        network.stop();
        changed(app);
        network.stop_and_wait().await;
        state.audit_info("offline_network_stopped", "Stopped local Qguard networking");
        changed(app);
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn offline_set_auto(app: AppHandle, enabled: bool) -> Result<()> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let owner = local_owner(&state)?;
    {
        let _gate = lock(&runtime.storage)?;
        let mut book = TrustBook::load(&state, &owner)?;
        book.auto_start = enabled;
        book.save(&state, &owner)?;
    }
    if !enabled {
        stop(&app, true, Some(&owner)).await?;
    }
    changed(&app);
    Ok(())
}

/// Mark the network as allowed to keep serving while Qguard is locked and,
/// on Android, start the visible foreground service that keeps it alive.
async fn enable_background(network: &Arc<Network>) {
    network.set_background(true);
    let started = tokio::task::spawn_blocking(background::start)
        .await
        .unwrap_or_else(|_| Err("Background Mesh could not start.".into()));
    if let Err(error) = started {
        network.set_background(false);
        if let Ok(mut slot) = network.error.lock() {
            *slot = Some(error);
        }
    }
}

/// Keep Mesh (delivery, alerts and relaying) running while Qguard is locked
/// or in the background. Needs an unlocked Qguard to change.
#[tauri::command]
pub(crate) async fn offline_set_background(app: AppHandle, enabled: bool) -> Result<()> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let owner = local_owner(&state)?;
    {
        let _gate = lock(&runtime.storage)?;
        let mut book = TrustBook::load(&state, &owner)?;
        book.background = enabled;
        book.save(&state, &owner)?;
    }
    if let Some(network) = network_for(&runtime, &owner)? {
        if enabled {
            enable_background(&network).await;
            if !network.background() {
                let reason = lock(&network.error)?.clone();
                return Err(QGuardError::Storage(
                    reason.unwrap_or_else(|| "Background Mesh could not start.".into()),
                ));
            }
        } else {
            network.set_background(false);
            let _ = tokio::task::spawn_blocking(background::stop).await;
        }
    }
    state.audit_info(
        "offline_background_changed",
        if enabled { "Turned on background Mesh" } else { "Turned off background Mesh" },
    );
    changed(&app);
    Ok(())
}

/// Carry sealed Mesh envelopes for trusted devices. Turning it off drops
/// what this device was carrying for others; its own messages still relay.
#[tauri::command]
pub(crate) fn offline_set_relay(app: AppHandle, enabled: bool) -> Result<()> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let owner = local_owner(&state)?;
    let network = network_for(&runtime, &owner)?;
    {
        let _gate = lock(&runtime.storage)?;
        let mut book = TrustBook::load(&state, &owner)?;
        book.relay = enabled;
        book.save(&state, &owner)?;
        if !enabled {
            let now = chrono::Utc::now().timestamp();
            match &network {
                Some(network) => relay_net::with_store(&state, network, now, |store| {
                    store.clear_carried();
                    Ok(((), true))
                })?,
                None => {
                    let mut store = super::relay::Store::load(&state, &owner, now)?;
                    store.clear_carried();
                    store.save(&state, &owner)?;
                }
            }
        }
    }
    state.audit_info(
        "offline_relay_changed",
        if enabled { "Turned on Mesh relaying" } else { "Turned off Mesh relaying" },
    );
    changed(&app);
    Ok(())
}

#[tauri::command]
pub(crate) async fn offline_relay_state(
    app: AppHandle,
    unavailable: bool,
    expected_account: Option<String>,
) -> Result<()> {
    if unavailable {
        start(&app, true, expected_account.as_deref()).await
    } else {
        stop(&app, true, expected_account.as_deref()).await
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Connectivity {
    active_authenticated_peers: usize,
    pending_messages: usize,
    lan_running: bool,
    discovery_running: bool,
    auto_start: bool,
}

#[tauri::command]
pub(crate) async fn offline_connectivity(
    app: AppHandle,
    expected_account: Option<String>,
) -> Result<Connectivity> {
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let runtime = app.state::<Runtime>();
        let owner = match expected_account {
            Some(expected) => require_snapshot_owner(&state, &expected)?,
            None => local_owner(&state)?,
        };
        let network = network_for(&runtime, &owner)?;
        let (book, pending_messages) = {
            let _gate = lock(&runtime.storage)?;
            (
                TrustBook::load(&state, &owner)?,
                mesh::pending_count(&state, &owner)?,
            )
        };
        let network = network.as_deref().filter(|network| network.running());
        let active_authenticated_peers =
            network.map_or(Ok(0), |network| network.active_peers(&book))?;
        let discovery_running = match network {
            Some(network) => {
                network.lan_discovery_running()
                    || lock(&network.smart)?.status().bluetooth_scanning()
            }
            None => false,
        };
        require_snapshot_owner(&state, &owner)?;
        Ok(Connectivity {
            active_authenticated_peers,
            pending_messages,
            lan_running: network.is_some(),
            discovery_running,
            auto_start: book.auto_start,
        })
    })
    .await
    .map_err(|_| QGuardError::Storage("Could not read local connectivity.".into()))?
}

#[tauri::command]
pub(crate) fn offline_pairing_snapshot(app: AppHandle, expected_account: String) -> Result<Vec<PairingView>> {
    let state = app.state::<AppState>();
    let owner = require_snapshot_owner(&state, &expected_account)?;
    let requests = match network_for(&app.state::<Runtime>(), &owner)? {
        Some(network) => network.pairings.list()?,
        None => Vec::new(),
    };
    require_snapshot_owner(&state, &owner)?;
    Ok(requests)
}

/// `both` asks the other user to approve Mesh and XFER in one pairing.
/// Otherwise the request covers only the workflow that started it.
#[tauri::command]
pub(crate) fn offline_pairing_start(
    app: AppHandle,
    peer: String,
    mode: ProbeMode,
    both: Option<bool>,
    expected_account: String,
) -> Result<Uuid> {
    let owner = require_snapshot_owner(&app.state::<AppState>(), &expected_account)?;
    let network = require_network(&app.state::<Runtime>(), &owner)?;
    network.require_pairing_peer(&app, &peer)?;
    if !network.mesh_reachable(&peer, None)? {
        return Err(QGuardError::NotFound("This peer is no longer reachable. Discover it again before connecting.".into()));
    }
    let requested = match (mode, both.unwrap_or(false)) {
        (_, true) => vec![PeerCapability::Mesh, PeerCapability::Xfer],
        (ProbeMode::Mesh, false) => vec![PeerCapability::Mesh],
        (ProbeMode::Xfer, false) => vec![PeerCapability::Xfer],
    };
    let permit = Arc::clone(&network.pairing_outbound).try_acquire_owned().map_err(|_| {
        QGuardError::Trust("Nearby connection requests are busy. Try again shortly.".into())
    })?;
    let id = network.pairings.start_outgoing(&peer, requested.clone())?;
    diag::record_detail(&app, "pairing_requested", diag::Subject::peer(&peer), format!("pairing {id}"));
    changed(&app);
    tauri::async_runtime::spawn(async move {
        let _permit = permit;
        let exchange = async {
            let lan = async {
                let stream = network.connect_pairing(&app, &peer).await?;
                Session::connect_pairing(stream, &network.identity, &peer).await
            };
            let mut session = match lan.await {
                Ok(session) => session,
                Err(lan_error) => match network.connect_pairing_ble(&app, &peer).await {
                    Ok(stream) => Session::connect_pairing_ble(stream, &network.identity, &peer).await?,
                    // No Bluetooth route at all: the LAN reason is the useful one.
                    Err(QGuardError::NotFound(_)) => return Err(lan_error),
                    Err(bluetooth_error) => return Err(bluetooth_error),
                },
            };
            pairing::initiate(
                &mut session, &network.pairings, id, local_pairing_metadata(&app, &network),
                local_owner_name(&app, &network), requested,
                || {
                    changed(&app);
                    alerts::pairings(&app, &network.pairings);
                },
                || network.require_pairing_peer(&app, &peer),
                |id, verified| persist_pairing(&app, &network, id, verified),
            ).await
        };
        tokio::select! {
            _ = network.until_stopped() => {},
            result = exchange => {
                if let Err(error) = result {
                    diag::record_detail(&app, "pairing_failed", diag::Subject::peer(&peer), format!("pairing {id}: {}", failure_reason(&error)));
                    network.pairings.fail_with(id, failure_reason(&error));
                }
            },
        }
        network.pairings.fail(id);
        changed(&app);
    });
    Ok(id)
}

/// Connection diagnostics for Offline Settings: what the transport and
/// session layers recorded, newest last. Scoped to the verified account.
#[tauri::command]
pub(crate) fn offline_link_events(app: AppHandle, expected_account: String) -> Result<Vec<diag::LinkEvent>> {
    require_snapshot_owner(&app.state::<AppState>(), &expected_account)?;
    Ok(app.state::<Runtime>().events.list())
}

/// The message without its error-class prefix, for a status line.
fn failure_reason(error: &QGuardError) -> &str {
    match error {
        QGuardError::Crypto(message)
        | QGuardError::InvalidInput(message)
        | QGuardError::NotFound(message)
        | QGuardError::Replay(message)
        | QGuardError::Trust(message)
        | QGuardError::Storage(message) => message,
    }
}

#[tauri::command]
pub(crate) fn offline_pairing_decide(app: AppHandle, id: Uuid, decision: PairingDecision, expected_account: String) -> Result<()> {
    let state = app.state::<AppState>();
    let owner = require_snapshot_owner(&state, &expected_account)?;
    let runtime = app.state::<Runtime>();
    let network = require_network(&runtime, &owner)?;
    {
        let _gate = lock(&runtime.storage)?;
        network.check(&app)?;
        network.pairings.decide(id, decision)?;
    }
    changed(&app);
    Ok(())
}

fn local_pairing_metadata(app: &AppHandle, network: &Network) -> PeerMetadata {
    PeerMetadata::local(&app.state::<AppState>(), &network.owner, &network.fingerprint)
}

fn local_owner_name(app: &AppHandle, network: &Network) -> Option<String> {
    TrustBook::load(&app.state::<AppState>(), &network.owner)
        .ok()
        .and_then(|book| book.local_owner)
}

fn persist_pairing(app: &AppHandle, network: &Network, id: Uuid, peer: AuthenticatedPeer) -> Result<()> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    {
        let _gate = lock(&runtime.storage)?;
        network.check(app)?;
        network.pairings.ensure_committing(id, &peer.fingerprint)?;
        let mut book = TrustBook::load(&state, &network.owner)?;
        // Discovery endpoints are unverified hints and are never persisted as
        // manual addresses. The next connection authenticates its own session.
        book.trust_paired(
            &peer.fingerprint,
            peer.metadata,
            &peer.public_key,
            None,
            &peer.granted,
            peer.owner,
        )?;
        book.save(&state, &network.owner)?;
        network.allow_peer_after_pairing(&peer.fingerprint)?;
    }
    state.audit_info("offline_peer_trusted", "Confirmed a local device through mutual pairing");
    diag::record_detail(app, "pairing_trusted", diag::Subject::default(), format!("pairing {id}: both users confirmed the code"));
    changed(&app);
    Ok(())
}

#[tauri::command]
pub(crate) fn offline_revoke(app: AppHandle, fingerprint: String, expected_account: String) -> Result<()> {
    if update_trust(&app, &expected_account, &fingerprint, TrustBook::revoke, true)? {
        app.state::<AppState>().audit_info("offline_peer_revoked", "Removed a local trusted device");
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn offline_block_peer(app: AppHandle, peer: String, expected_account: String) -> Result<()> {
    if update_trust(&app, &expected_account, &peer, TrustBook::block, true)? {
        app.state::<AppState>().audit_info("offline_peer_blocked", "Blocked a local device");
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn offline_unblock_peer(app: AppHandle, peer: String, expected_account: String) -> Result<()> {
    update_trust(&app, &expected_account, &peer, TrustBook::unblock, false).map(|_| ())
}

#[tauri::command]
pub(crate) fn offline_disconnect_peer(app: AppHandle, peer: String, expected_account: String) -> Result<()> {
    let state = app.state::<AppState>();
    let owner = require_snapshot_owner(&state, &expected_account)?;
    let runtime = app.state::<Runtime>();
    let network = require_network(&runtime, &owner)?;
    {
        let _gate = lock(&runtime.storage)?;
        network.check(&app)?;
        if !TrustBook::load(&state, &owner)?.peers.contains_key(&peer) {
            return Err(QGuardError::Trust("Only a trusted device can be disconnected.".into()));
        }
        network.invalidate_peer(&peer, true)?;
    }
    changed(&app);
    Ok(())
}

fn update_trust(
    app: &AppHandle, expected_account: &str, peer: &str,
    update: fn(&mut TrustBook, &str) -> Result<bool>, invalidate: bool,
) -> Result<bool> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let owner = require_snapshot_owner(&state, expected_account)?;
    let updated = {
        let _gate = lock(&runtime.storage)?;
        require_snapshot_owner(&state, &owner)?;
        let mut book = TrustBook::load(&state, &owner)?;
        let updated = update(&mut book, peer)?;
        if updated {
            book.save(&state, &owner)?;
            // A removed or blocked device's picture goes with its trust.
            if invalidate {
                let _ = avatar::forget(&state, &owner, peer);
            }
        }
        if invalidate {
            if let Some(network) = network_for(&runtime, &owner)? {
                network.invalidate_peer(peer, false)?;
                lock(&network.authenticated)?.remove(peer);
            }
        }
        updated
    };
    changed(app);
    Ok(updated)
}

fn network_for(runtime: &Runtime, owner: &str) -> Result<Option<Arc<Network>>> {
    Ok(lock(&runtime.network)?
        .as_ref()
        .filter(|network| network.owner == owner && network.running())
        .cloned())
}

fn require_network(runtime: &Runtime, owner: &str) -> Result<Arc<Network>> {
    network_for(runtime, owner)?
        .ok_or_else(|| QGuardError::Trust("Start local networking to connect to the peer.".into()))
}

pub(super) async fn serve(app: &AppHandle, network: &Network, stream: TcpStream) -> Result<()> {
    network.check(app)?;
    let admitted = OnceLock::new();
    let session = Session::accept_mixed(stream, &network.identity,
        |peer| network.require_peer(app, peer).is_ok(),
        |peer| *admitted.get_or_init(|| network.admit_pairing()) && network.require_pairing_peer(app, peer).is_ok(),
    ).await?;
    serve_session(app, network, session).await
}

pub(super) async fn serve_ble(
    app: &AppHandle,
    network: &Network,
    stream: tokio::io::DuplexStream,
) -> Result<()> {
    network.check(app)?;
    let admitted = OnceLock::new();
    let session = Session::accept_mixed_ble(stream, &network.identity,
        |peer| network.require_peer(app, peer).is_ok(),
        |peer| *admitted.get_or_init(|| network.admit_pairing()) && network.require_pairing_peer(app, peer).is_ok(),
    ).await?;
    serve_session(app, network, session).await
}

async fn serve_session(app: &AppHandle, network: &Network, mut session: Session) -> Result<()> {
    if !session.pairing() {
        return serve_authenticated(app, network, session).await;
    }
    let peer = session.peer().to_owned();
    pairing::respond(
        &mut session, &network.pairings, local_pairing_metadata(app, network),
        local_owner_name(app, network),
        || {
            changed(app);
            alerts::pairings(app, &network.pairings);
        },
        || network.require_pairing_peer(app, &peer),
        |id, verified| persist_pairing(app, network, id, verified),
        || shared_picture(app, network),
    ).await
}

/// This account's picture, only when its owner chose to show it nearby.
fn shared_picture(app: &AppHandle, network: &Network) -> Option<(String, String)> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let _gate = lock(&runtime.storage).ok()?;
    if !TrustBook::load(&state, &network.owner).ok()?.share_picture_nearby {
        return None;
    }
    AvatarBook::load(&state, &network.owner).ok()?.local.map(|picture| (picture.digest, picture.image))
}

/// Fetch the pictures nearby, not yet paired devices advertise (opt-in on
/// their side). One fetch at a time, at most once a minute per device, and
/// only when the advertised fingerprint differs from the cached picture.
pub(super) fn schedule_nearby_pictures(app: &AppHandle, network: &Arc<Network>) {
    let Ok(book) = TrustBook::load(&app.state::<AppState>(), &network.owner) else { return };
    let wanted: Vec<(String, String)> = match lock(&network.smart) {
        Ok(smart) => smart
            .peers
            .iter()
            .filter(|(peer, _)| !book.peers.contains_key(*peer) && !book.blocked.contains_key(*peer))
            .filter_map(|(peer, seen)| seen.picture.clone().map(|tag| (peer.clone(), tag)))
            .collect(),
        Err(_) => return,
    };
    for (peer, tag) in wanted {
        if network.nearby_picture(&peer).is_some_and(|picture| picture.digest.starts_with(&tag)) {
            continue;
        }
        let due = lock(&network.picture_fetches).is_ok_and(|mut fetches| {
            if fetches.get(&peer).is_some_and(|last| last.elapsed() < Duration::from_secs(60)) {
                return false;
            }
            fetches.insert(peer.clone(), Instant::now());
            true
        });
        if !due {
            continue;
        }
        let Ok(permit) = Arc::clone(&network.picture_worker).try_acquire_owned() else { return };
        let app = app.clone();
        let network = Arc::clone(network);
        tauri::async_runtime::spawn(async move {
            let _permit = permit;
            let outcome = async {
                let mut session = match network.connect_pairing(&app, &peer).await {
                    Ok(stream) => Session::connect_pairing(stream, &network.identity, &peer).await?,
                    Err(_) => {
                        let stream = network.connect_pairing_ble(&app, &peer).await?;
                        Session::connect_pairing_ble(stream, &network.identity, &peer).await?
                    }
                };
                pairing::request_picture(&mut session).await
            }
            .await;
            match outcome {
                Ok(Some((digest, image))) if digest.starts_with(&tag) => match avatar::received(&digest, &image) {
                    Ok(picture) => {
                        if let Ok(mut pictures) = network.nearby_pictures.lock() {
                            pictures.insert(peer.clone(), picture);
                        }
                        diag::record(&app, "nearby_picture_received", diag::Subject::peer(&peer));
                        changed(&app);
                    }
                    Err(error) => diag::record_detail(&app, "nearby_picture_rejected", diag::Subject::peer(&peer), failure_reason(&error)),
                },
                Ok(_) => {}
                Err(error) => diag::record_detail(&app, "nearby_picture_failed", diag::Subject::peer(&peer), failure_reason(&error)),
            }
        });
        // One fetch per beacon keeps Bluetooth free for real work.
        break;
    }
}

/// Show (or stop showing) this account's picture to nearby devices before
/// pairing. Bluetooth discovery restarts to update what it advertises.
#[tauri::command]
pub(crate) async fn offline_set_share_picture(app: AppHandle, enabled: bool, expected_account: String) -> Result<()> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let owner = require_snapshot_owner(&state, &expected_account)?;
    let changed_setting = {
        let _gate = lock(&runtime.storage)?;
        let mut book = TrustBook::load(&state, &owner)?;
        let changed_setting = book.share_picture_nearby != enabled;
        book.share_picture_nearby = enabled;
        book.save(&state, &owner)?;
        changed_setting
    };
    state.audit_info(
        "offline_share_picture_changed",
        if enabled { "Turned on showing the profile picture to nearby devices" } else { "Turned off showing the profile picture to nearby devices" },
    );
    if changed_setting {
        if let Some(network) = network_for(&runtime, &owner)? {
            network.restart_bluetooth(&app).await?;
        }
    }
    changed(&app);
    Ok(())
}

async fn serve_authenticated(
    app: &AppHandle,
    network: &Network,
    mut session: Session,
) -> Result<()> {
    let peer = session.peer().to_string();
    let (_activity, authorization) = network.peer_authenticated(app, &peer, None)?;
    session.authorize(authorization);
    let control = wire::recv(&mut session).await?;
    network.require_peer(app, &peer)?;
    // New work needs the capability both users approved. Controls for an
    // existing transfer stay available so either side can still settle it.
    match &control {
        Control::Offer(_) | Control::RequestSend { .. } => {
            network.require_capability(app, &peer, PeerCapability::Xfer)?
        }
        Control::Message(_) | Control::Relay { .. } => {
            network.require_capability(app, &peer, PeerCapability::Mesh)?
        }
        // The persistent channel serves Mesh and XFER pairings alike.
        Control::Channel { .. } => network
            .require_capability(app, &peer, PeerCapability::Mesh)
            .or_else(|_| network.require_capability(app, &peer, PeerCapability::Xfer))?,
        _ => {}
    }
    if session.bluetooth() && !matches!(&control, Control::Message(_) | Control::Relay { .. } | Control::Channel { .. }) {
        return Err(QGuardError::InvalidInput(
            "This Bluetooth link carries small Mesh messages. Files require a local Wi-Fi link."
                .into(),
        ));
    }
    match control {
        Control::Offer(manifest) => transfer::incoming(app, network, &mut session, manifest).await,
        Control::RequestSend { id } => transfer::requested(app, network, &mut session, id).await,
        Control::Reject { id } => {
            let local = network.fingerprint.clone();
            transfer::store_task(app, &network.owner, move |store| {
                let record = store.get(id)?;
                anyhow::ensure!(
                    record.direction == Direction::Outgoing
                        && record.manifest.sender == local
                        && record.manifest.recipient == peer,
                    "The transfer is not authorized for this peer."
                );
                store.reject_outgoing(id)
            })
            .await?;
            network.transfers.stop(id)?;
            changed(app);
            Ok(())
        }
        Control::Cancel { id } => {
            let local = network.fingerprint.clone();
            let remote = peer.clone();
            transfer::store_task(app, &network.owner, move |store| {
                let record = store.get(id)?;
                let manifest = record.manifest;
                anyhow::ensure!(
                    (manifest.sender == local && manifest.recipient == remote)
                        || (manifest.recipient == local && manifest.sender == remote),
                    "The transfer is not authorized for this peer."
                );
                store.cancel_remote_legacy(id)
            })
            .await?;
            network.transfers.stop(id)?;
            changed(app);
            wire::send(&mut session, &Control::Cancelled).await
        }
        Control::TransferState { id, revision, action } => {
            transfer::receive_state(app, network, &mut session, id, revision, action).await
        }
        Control::Message(message) => receive_mesh(app, network, &mut session, &peer, message).await,
        // Keep this session open as the persistent channel to the peer. The
        // activity guard above stays alive for as long as the channel runs.
        Control::Channel { version } => {
            if !(channel::MIN_VERSION..=channel::VERSION).contains(&version) {
                return Err(wire::protocol_error());
            }
            wire::send(&mut session, &Control::ChannelReady { version }).await?;
            channel::run(app, network, session, false, version).await;
            Ok(())
        }
        Control::Relay { key, envelopes } => {
            relay_net::serve(app, network, &mut session, &peer, key, envelopes).await
        }
        _ => Err(wire::protocol_error()),
    }
}

pub(super) struct Connection<'a> {
    session: Session,
    _activity: PeerActivity<'a>,
}

impl Deref for Connection<'_> {
    type Target = Session;
    fn deref(&self) -> &Session {
        &self.session
    }
}

impl<'a> Connection<'a> {
    /// The session and the guard that keeps the peer marked as connected.
    pub(super) fn into_parts(self) -> (Session, PeerActivity<'a>) {
        (self.session, self._activity)
    }
}

impl DerefMut for Connection<'_> {
    fn deref_mut(&mut self) -> &mut Session {
        &mut self.session
    }
}

pub(super) async fn connect<'a>(
    app: &AppHandle,
    network: &'a Network,
    peer: &str,
) -> Result<Connection<'a>> {
    let stream = network.connect(app, peer, false).await?;
    let mut session = Session::connect(stream, &network.identity, peer).await?;
    let (activity, authorization) = network.peer_authenticated(app, session.peer(), None)?;
    session.authorize(authorization);
    Ok(Connection {
        session,
        _activity: activity,
    })
}

pub(super) async fn connect_mesh<'a>(
    app: &AppHandle,
    network: &'a Network,
    peer: &str,
) -> Result<Connection<'a>> {
    if let Ok(connection) = connect(app, network, peer).await {
        return Ok(connection);
    }
    let stream = network.connect_ble(app, peer, false).await?;
    let mut session = Session::connect_ble(stream, &network.identity, peer).await?;
    let (activity, authorization) = network.peer_authenticated(app, session.peer(), None)?;
    session.authorize(authorization);
    Ok(Connection {
        session,
        _activity: activity,
    })
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ProbeMode {
    Mesh,
    Xfer,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PeerRoute {
    Lan,
    Ble,
}

/// Authenticate a peer using the selected workflow's transports. The probe's
/// session closes on return. A later send authenticates its own session.
#[tauri::command]
pub(crate) async fn offline_probe_peer(
    app: AppHandle,
    peer: String,
    mode: ProbeMode,
    expected_account: String,
) -> Result<PeerRoute> {
    let owner = require_snapshot_owner(&app.state::<AppState>(), &expected_account)?;
    let network = require_network(&app.state::<Runtime>(), &owner)?;
    let _permit = network.outbound.try_acquire().map_err(|_| {
        QGuardError::Trust("Local connections are busy. Try checking this device again.".into())
    })?;
    let revision = network.probe_revision(&app, &peer)?;
    network.require_capability(&app, &peer, match mode {
        ProbeMode::Mesh => PeerCapability::Mesh,
        ProbeMode::Xfer => PeerCapability::Xfer,
    })?;
    // The Mesh check can fall back from TCP to a slower fragmented BLE handshake.
    let deadline = match mode {
        ProbeMode::Mesh => Duration::from_secs(225),
        ProbeMode::Xfer => Duration::from_secs(30),
    };
    let probe = async {
        let lan = async {
            let stream = network.connect(&app, &peer, true).await?;
            Session::connect(stream, &network.identity, &peer).await
        };
        let mut session = match (mode, lan.await) {
            (_, Ok(session)) => session,
            (ProbeMode::Mesh, Err(_)) => {
                let stream = network.connect_ble(&app, &peer, true).await?;
                Session::connect_ble(stream, &network.identity, &peer).await?
            }
            (ProbeMode::Xfer, Err(error)) => return Err(error),
        };
        require_snapshot_owner(&app.state::<AppState>(), &owner)?;
        let (_activity, authorization) = network.peer_authenticated(&app, session.peer(), Some(revision))?;
        session.authorize(authorization);
        Ok(if session.bluetooth() {
            PeerRoute::Ble
        } else {
            PeerRoute::Lan
        })
    };
    tokio::select! {
        _ = network.until_stopped() => Err(QGuardError::Trust("The current local networking session has ended.".into())),
        result = tokio::time::timeout(deadline, probe) => result.map_err(|_| {
            QGuardError::NotFound("The trusted device did not respond in time. Check its local networking and retry.".into())
        })?,
    }
}

#[tauri::command]
pub(crate) fn offline_mesh_snapshot(
    state: State<'_, AppState>,
    runtime: State<'_, Runtime>,
) -> Result<mesh::Snapshot> {
    let owner = local_owner(&state)?;
    let _gate = lock(&runtime.storage)?;
    mesh::snapshot(&state, &owner)
}

#[tauri::command]
pub(crate) fn offline_mesh_send(
    app: AppHandle,
    state: State<'_, AppState>,
    runtime: State<'_, Runtime>,
    recipients: Vec<String>,
    body: String,
    group: Option<String>,
    emergency: bool,
    ttl_seconds: i64,
) -> Result<Uuid> {
    let owner = local_owner(&state)?;
    let network = network_for(&runtime, &owner)?;
    let targets = recipients.clone();
    let id = {
        let _gate = lock(&runtime.storage)?;
        let book = TrustBook::load(&state, &owner)?;
        if recipients.iter().any(|peer| !book.peers.contains_key(peer)) {
            return Err(QGuardError::Trust(
                "Choose only device fingerprints you have verified.".into(),
            ));
        }
        for peer in &recipients {
            book.require(peer, PeerCapability::Mesh)?;
        }
        let identity = Identity::load(&state, &owner)?;
        mesh::queue(
            &state,
            &owner,
            identity.fingerprint(),
            recipients,
            body,
            group,
            emergency,
            ttl_seconds,
        )?
    };
    changed(&app);
    if let Some(network) = network {
        diag::record_detail(&app, "message_queued", diag::Subject::default(), format!("message {id} for {} device(s)", targets.len()));
        // An open channel sends it now, whatever discovery currently reports.
        for peer in &targets {
            network.channels.flush(peer);
        }
        schedule_mesh(&app, &network);
    }
    Ok(id)
}

#[tauri::command]
pub(crate) fn offline_mesh_retry(
    app: AppHandle,
    state: State<'_, AppState>,
    runtime: State<'_, Runtime>,
) -> Result<()> {
    let owner = local_owner(&state)?;
    let network = require_network(&runtime, &owner)?;
    schedule_mesh(&app, &network);
    Ok(())
}

pub(super) fn schedule_mesh(app: &AppHandle, network: &Arc<Network>) {
    let app = app.clone();
    let network = Arc::clone(network);
    tauri::async_runtime::spawn(async move {
        let Ok(_worker) = network.mesh_worker.try_acquire() else {
            return;
        };
        tokio::select! {
            _ = network.until_stopped() => {}
            _ = send_pending(&app, &network) => {}
        }
    });
}

async fn send_pending(app: &AppHandle, network: &Arc<Network>) -> Result<()> {
    network.check(app)?;
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let deliveries = {
        let _gate = lock(&runtime.storage)?;
        let book = TrustBook::load(&state, &network.owner)?;
        let mut peers = Vec::new();
        for (peer, record) in &book.peers {
            if book.allows(peer, PeerCapability::Mesh)
                && network.mesh_reachable(peer, record.address)?
            {
                peers.push(peer.clone());
            }
        }
        mesh::pending_for_peers(&state, &network.owner, peers)?
    };
    for (peer, delivery) in deliveries {
        // The persistent channel carries every pending message for this
        // peer, in order, on one long-lived session.
        if network.channels.flush(&peer) {
            continue;
        }
        if network.channels.legacy(&peer) {
            // An older build: one message per session, as before.
            let _ = send_one(app, network, &peer, delivery).await;
            continue;
        }
        // No channel yet: dial it now. It sends what is waiting when it opens.
        channel::maintain(app, network, Some(&peer));
    }
    Ok(())
}

/// Pending deliveries for one peer, for its channel.
pub(super) fn pending_mesh_for(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    limit: usize,
) -> Result<Vec<mesh::Delivery>> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let _gate = lock(&runtime.storage)?;
    network.require_peer_locked(app, peer, false)?;
    let book = TrustBook::load(&state, &network.owner)?;
    if !book.allows(peer, PeerCapability::Mesh) {
        return Ok(Vec::new());
    }
    mesh::pending_for_peer(&state, &network.owner, peer, limit)
}

/// Record the peer's signed-session receipt for a message.
pub(super) fn acknowledge_mesh(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    receipt: mesh::Receipt,
) -> Result<()> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let _gate = lock(&runtime.storage)?;
    network.require_peer_locked(app, peer, false)?;
    mesh::acknowledge(&state, &network.owner, peer, receipt)?;
    drop(_gate);
    changed(app);
    Ok(())
}

/// Store an incoming message and return its receipt, and whether it is new
/// (a repeated delivery gets the same receipt and no second alert).
pub(super) fn store_incoming_mesh(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    delivery: mesh::Delivery,
) -> Result<(mesh::Receipt, bool)> {
    let message_id = delivery.id;
    let (receipt, new) = {
        let state = app.state::<AppState>();
        let runtime = app.state::<Runtime>();
        let _gate = lock(&runtime.storage)?;
        network.require_peer_locked(app, peer, false)?;
        network.require_capability_locked(app, peer, PeerCapability::Mesh)?;
        mesh::receive(&state, &network.owner, &network.fingerprint, peer, delivery)?
    };
    // The renderer learns of the message through `offline:changed` and reads
    // it from the sealed ledger; the desktop alert names only the sender.
    changed(app);
    if let Some(emergency) = new {
        alerts::mesh_message(app, &network.owner, peer, message_id, emergency);
    }
    Ok((receipt, new.is_some()))
}

async fn send_one(
    app: &AppHandle,
    network: &Network,
    peer: &str,
    delivery: mesh::Delivery,
) -> Result<()> {
    let mut session = connect_mesh(app, network, peer).await?;
    let id = delivery.id;
    wire::send(&mut session, &Control::Message(delivery)).await?;
    let Control::Receipt(receipt) = wire::recv(&mut session).await? else {
        return Err(wire::protocol_error());
    };
    if receipt.id != id {
        return Err(wire::protocol_error());
    }
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let _gate = lock(&runtime.storage)?;
    network.require_peer_locked(app, peer, false)?;
    mesh::acknowledge(&state, &network.owner, peer, receipt)?;
    changed(app);
    Ok(())
}

async fn receive_mesh(
    app: &AppHandle,
    network: &Network,
    session: &mut Session,
    peer: &str,
    delivery: mesh::Delivery,
) -> Result<()> {
    let (receipt, _new) = store_incoming_mesh(app, network, peer, delivery)?;
    wire::send(session, &Control::Receipt(receipt)).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MeshNotice {
    #[serde(flatten)]
    message: mesh::UnreadMessage,
    sender_name: Option<String>,
}

/// Unread incoming Mesh messages for the in-app notice, scoped to the
/// verified account. Previews never leave the app's IPC boundary.
#[tauri::command]
pub(crate) async fn offline_mesh_monitor(app: AppHandle, expected_account: String) -> Result<Vec<MeshNotice>> {
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let runtime = app.state::<Runtime>();
        let owner = require_snapshot_owner(&state, &expected_account)?;
        let (unread, book) = {
            let _gate = lock(&runtime.storage)?;
            (mesh::unread(&state, &owner)?, TrustBook::load(&state, &owner)?)
        };
        require_snapshot_owner(&state, &owner)?;
        Ok(unread
            .into_iter()
            .map(|message| {
                let sender_name = book
                    .peers
                    .get(&message.sender)
                    .map(|peer| peer.owner.clone().unwrap_or_else(|| peer.label.clone()));
                MeshNotice { message, sender_name }
            })
            .collect())
    })
    .await
    .map_err(|_| QGuardError::Storage("Could not read local messages.".into()))?
}

#[tauri::command]
pub(crate) fn offline_mesh_mark_read(
    app: AppHandle,
    messages: Vec<mesh::MessageRef>,
    expected_account: String,
) -> Result<()> {
    if messages.len() > 64 {
        return Err(QGuardError::InvalidInput("Too many messages in one request.".into()));
    }
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let owner = require_snapshot_owner(&state, &expected_account)?;
    let changed_any = {
        let _gate = lock(&runtime.storage)?;
        require_snapshot_owner(&state, &owner)?;
        mesh::mark_read(&state, &owner, &messages)?
    };
    if changed_any {
        changed(&app);
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn offline_xfer_list(app: AppHandle) -> Result<Vec<TransferSummary>> {
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let owner = local_owner(&state)?;
        let network = network_for(&app.state::<Runtime>(), &owner)?;
        let records = list_transfers(&app, &owner, network.as_deref())?;
        require_snapshot_owner(&state, &owner)?;
        Ok(records)
    })
    .await
    .map_err(|_| QGuardError::Storage("Could not read local transfers.".into()))?
}

#[tauri::command]
pub(crate) async fn offline_xfer_monitor(app: AppHandle, expected_account: String) -> Result<Vec<TransferMonitorEntry>> {
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let owner = require_snapshot_owner(&state, &expected_account)?;
        let network = network_for(&app.state::<Runtime>(), &owner)?;
        let entries = transfer::with_store(&app, &owner, |store| {
            let records = store.list()?;
            Ok(records.iter().filter_map(|record| transfer::monitor_entry(
                record, network.as_deref().filter(|network| network.running()),
            )).collect())
        })?;
        require_snapshot_owner(&state, &owner)?;
        Ok(entries)
    }).await.map_err(|_| QGuardError::Storage("Could not read the transfer monitor.".into()))?
}

fn list_transfers(
    app: &AppHandle,
    owner: &str,
    network: Option<&Network>,
) -> Result<Vec<TransferSummary>> {
    transfer::with_store(app, owner, |store| {
        Ok(store
            .list()?
            .into_iter()
            .map(|record| transfer::summarize(record, network.filter(|network| network.running())))
            .collect())
    })
}

const SELECTION_LIFETIME: Duration = Duration::from_secs(15 * 60);
const MAX_SELECTIONS: usize = 32;
const MAX_SELECTED_PATHS: usize = 128;

pub(super) struct SourceSelection {
    owner: String,
    sources: Vec<SelectedSource>,
    expires: Instant,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PickedSources {
    token: Uuid,
    names: Vec<String>,
    total_bytes: Option<u64>,
}

#[tauri::command]
pub(crate) async fn offline_xfer_pick_sources(
    app: AppHandle,
    folder: bool,
) -> Result<Option<PickedSources>> {
    let state = app.state::<AppState>();
    let runtime = app.state::<Runtime>();
    let owner = local_owner(&state)?;
    let _picker = runtime
        .picker
        .try_lock()
        .map_err(|_| QGuardError::Trust("Close the current file picker first.".into()))?;
    #[cfg(target_os = "android")]
    if folder {
        let picked = tokio::task::spawn_blocking(crate::security::saf_folder::pick_source_folder)
            .await.map_err(|_| QGuardError::Storage("The native folder picker is unavailable.".into()))??;
        let Some(picked) = picked else { return Ok(None); };
        if local_owner(&state)? != owner {
            return Err(QGuardError::Trust("The local account changed while choosing the folder.".into()));
        }
        super::xfer::validate_relative_path(&picked.name)?;
        if picked.name.contains('/') || picked.files.is_empty() || picked.files.len() > MAX_SELECTED_PATHS {
            return Err(QGuardError::InvalidInput("Choose a folder with up to 128 valid files.".into()));
        }
        let prefix = format!("{}/", picked.name);
        let mut total = Some(0u64);
        let mut sources = Vec::with_capacity(picked.files.len());
        for file in picked.files {
            super::xfer::validate_relative_path(&file.path)?;
            if !file.path.starts_with(&prefix) || file.uri.len() > 4096
                || !crate::security::content_uri::is_content_uri(&file.uri)
                || file.uri.chars().any(char::is_control)
            {
                return Err(QGuardError::InvalidInput("The folder provider returned an invalid source file.".into()));
            }
            total = total.zip(file.size).and_then(|(sum, size)| sum.checked_add(size));
            sources.push(SelectedSource::DocumentTreeFile { uri: file.uri, path: file.path, size: file.size });
        }
        return store_source_selection(&runtime, owner, sources, vec![picked.name], total).map(Some);
    }
    if cfg!(mobile) && folder {
        return Err(QGuardError::InvalidInput(
            "This build supports folder selection on desktop.".into(),
        ));
    }
    let picker = app.clone();
    let selected = tokio::task::spawn_blocking(move || {
        let dialog = picker.dialog().file();
        #[cfg(desktop)]
        if folder {
            return dialog.blocking_pick_folder().map(|path| vec![path]);
        }
        dialog.blocking_pick_files()
    })
    .await
    .map_err(|_| QGuardError::Storage("The native file picker is unavailable.".into()))?;
    let Some(selected) = selected else {
        return Ok(None);
    };
    if local_owner(&state)? != owner {
        return Err(QGuardError::Trust(
            "The local account changed while choosing files.".into(),
        ));
    }
    if selected.is_empty() || selected.len() > MAX_SELECTED_PATHS {
        return Err(QGuardError::InvalidInput(
            "Choose between 1 and 128 local files.".into(),
        ));
    }
    let sources = selected
        .into_iter()
        .map(|path| {
            if let tauri_plugin_dialog::FilePath::Url(uri) = &path {
                if uri.scheme() == "content" {
                    #[cfg(target_os = "android")]
                    {
                        let uri = uri.to_string();
                        let (name, size) = crate::security::content_uri::stat(&uri)?;
                        let name =
                            name.unwrap_or_else(|| crate::security::content_uri::uri_tail(&uri));
                        return Ok(SelectedSource::Document { uri, name, size });
                    }
                    #[cfg(not(target_os = "android"))]
                    return Err(QGuardError::InvalidInput(
                        "This document source is available on Android.".into(),
                    ));
                }
            }
            let path = path.into_path().map_err(|_| {
                QGuardError::InvalidInput(
                    "This document provider does not expose a local filesystem path for XFER."
                        .into(),
                )
            })?;
            Ok(SelectedSource::Path(super::xfer::selected_source(path)?))
        })
        .collect::<Result<Vec<_>>>()?;
    let names = sources
        .iter()
        .map(|source| match source {
            SelectedSource::Document { name, .. } => Ok(name.clone()),
            SelectedSource::DocumentTreeFile { path, .. } => Ok(path.clone()),
            SelectedSource::Path(path) => path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
                .ok_or_else(|| {
                    QGuardError::InvalidInput("Choose files or folders with valid names.".into())
                }),
        })
        .collect::<Result<Vec<_>>>()?;
    let total_bytes = if folder {
        None
    } else {
        sources.iter().try_fold(0u64, |total, source| {
            let size = match source {
                SelectedSource::Document { size, .. } => (*size)?,
                SelectedSource::DocumentTreeFile { size, .. } => (*size)?,
                SelectedSource::Path(path) => {
                    let metadata = path.metadata().ok()?;
                    metadata.is_file().then_some(())?;
                    metadata.len()
                }
            };
            total.checked_add(size)
        })
    };
    store_source_selection(&runtime, owner, sources, names, total_bytes).map(Some)
}

fn store_source_selection(runtime: &Runtime, owner: String, sources: Vec<SelectedSource>, names: Vec<String>, total_bytes: Option<u64>) -> Result<PickedSources> {
    let mut selections = lock(&runtime.selections)?;
    selections
        .retain(|_, selection| selection.owner == owner && selection.expires > Instant::now());
    if selections.len() >= MAX_SELECTIONS {
        return Err(QGuardError::InvalidInput("Too many file selections are waiting. Send the current batch before choosing more files.".into()));
    }
    let token = Uuid::new_v4();
    selections.insert(
        token,
        SourceSelection {
            owner,
            sources,
            expires: Instant::now() + SELECTION_LIFETIME,
        },
    );
    Ok(PickedSources {
        token,
        names,
        total_bytes,
    })
}

fn claim_sources(runtime: &Runtime, owner: &str, tokens: &[Uuid]) -> Result<Vec<SelectedSource>> {
    if tokens.is_empty() || tokens.len() > MAX_SELECTIONS {
        return Err(QGuardError::InvalidInput(
            "Choose the files to send first.".into(),
        ));
    }
    let mut selections = lock(&runtime.selections)?;
    let mut seen = std::collections::HashSet::new();
    let mut sources = Vec::new();
    for token in tokens {
        let Some(selection) = selections
            .get(token)
            .filter(|item| item.owner == owner && item.expires > Instant::now())
        else {
            return Err(QGuardError::Trust(
                "A file selection expired. Choose the files again.".into(),
            ));
        };
        if !seen.insert(token) || sources.len() + selection.sources.len() > MAX_SELECTED_PATHS {
            return Err(QGuardError::InvalidInput(
                "Choose up to 128 unique source selections.".into(),
            ));
        }
        sources.extend(selection.sources.iter().cloned());
    }
    for token in tokens {
        selections.remove(token);
    }
    Ok(sources)
}

#[tauri::command]
pub(crate) async fn offline_xfer_offer(
    app: AppHandle,
    recipient: String,
    selection_tokens: Vec<Uuid>,
) -> Result<Uuid> {
    let owner = local_owner(&app.state::<AppState>())?;
    let runtime = app.state::<Runtime>();
    let sender = {
        let _gate = lock(&runtime.storage)?;
        let book = TrustBook::load(&app.state::<AppState>(), &owner)?;
        if !book.peers.contains_key(&recipient) {
            return Err(QGuardError::Trust(
                "Choose a device fingerprint that you have pinned.".into(),
            ));
        }
        book.require(&recipient, PeerCapability::Xfer)?;
        Identity::load(&app.state::<AppState>(), &owner)?
            .fingerprint()
            .to_string()
    };
    let sources = claim_sources(&runtime, &owner, &selection_tokens)?;
    let worker = app.clone();
    let queued_owner = owner.clone();
    let record = transfer::store_task(&app, &owner, move |store| {
        store.queue_sources_authorized(sender, recipient, sources, || {
            anyhow::ensure!(
                local_owner(&worker.state::<AppState>())? == queued_owner,
                "The local account changed while queuing the files."
            );
            Ok(())
        })
    })
    .await?;
    if local_owner(&app.state::<AppState>())? != owner {
        return Err(QGuardError::Trust("The local account changed.".into()));
    }
    let id = record.manifest.id;
    changed(&app);
    if let Some(network) = network_for(&runtime, &owner)? {
        schedule_queued_transfers(&app, &network);
    }
    Ok(id)
}

pub(super) fn schedule_queued_transfers(app: &AppHandle, network: &Arc<Network>) {
    let app = app.clone();
    let network = Arc::clone(network);
    tauri::async_runtime::spawn(async move {
        let Ok(_worker) = network.queue_worker.try_acquire() else {
            return;
        };
        if network.check(&app).is_err() || !network.transfers.has_capacity() {
            return;
        }
        let Ok(records) = transfer::store_task(&app, &network.owner, |store| store.list()).await
        else {
            return;
        };
        let Ok(book) = TrustBook::load(&app.state::<AppState>(), &network.owner) else {
            return;
        };
        let live = records
            .iter()
            .map(|record| record.manifest.id)
            .collect::<std::collections::HashSet<_>>();
        if let Ok(mut attempts) = lock(&network.queued_attempts) {
            attempts.retain(|id, _| live.contains(id));
        }
        for record in records {
            if record.direction != Direction::Outgoing
                || !record.queued_locally
                || !matches!(record.status, Status::Ready | Status::Interrupted)
            {
                continue;
            }
            let peer = &record.manifest.recipient;
            let Some(trusted) = book
                .peers
                .get(peer)
                .filter(|_| book.allows(peer, PeerCapability::Xfer))
            else {
                continue;
            };
            // Without a local route, a version-3 channel still carries the
            // offer (and sets up a Wi-Fi link once it is accepted).
            if network
                .endpoints(peer, trusted.address)
                .map_or(true, |routes| routes.is_empty())
                && !network.channels.supports_links(peer)
            {
                continue;
            }
            let id = record.manifest.id;
            // An open channel proves the peer is there: retry soon. Without
            // one, leave room for discovery to settle between attempts.
            let spacing = Duration::from_secs(if network.channels.is_open(peer) { 6 } else { 15 });
            let ready = lock(&network.queued_attempts).is_ok_and(|mut attempts| {
                if attempts
                    .get(&id)
                    .is_some_and(|last| last.elapsed() < spacing)
                {
                    return false;
                }
                attempts.insert(id, Instant::now());
                true
            });
            if ready {
                launch_transfer(app.clone(), Arc::clone(&network), id, Direction::Outgoing);
                break;
            }
        }
    });
}

#[tauri::command]
pub(crate) async fn offline_xfer_respond(
    app: AppHandle,
    id: Uuid,
    accept: bool,
    into_vault: Option<bool>,
) -> Result<()> {
    let owner = local_owner(&app.state::<AppState>())?;
    let into_vault = accept && into_vault.unwrap_or(false);
    if into_vault {
        crate::commands::vault_store::open_session(
            &app.state::<AppState>(),
            crate::commands::vault::VaultNeed::Seal,
        )?;
    }
    let record = transfer::store_task(&app, &owner, move |store| {
        let record = store.get(id)?;
        anyhow::ensure!(
            record.direction == Direction::Incoming,
            "Only an incoming offer can be accepted or declined."
        );
        if into_vault {
            store.accept_with_destination(id, true)
        } else if accept {
            store.accept(id)
        } else {
            store.reject(id)
        }
    })
    .await?;
    app.state::<AppState>().audit_info(
        "offline_transfer_consent",
        if accept {
            "Accepted a local file transfer"
        } else {
            "Declined a local file transfer"
        },
    );
    changed(&app);
    if let Some(network) = network_for(&app.state::<Runtime>(), &owner)? {
        let sender = record.manifest.sender.clone();
        // The answer travels on the channel when there is one (it may be the
        // only path between the devices); the sender then knows at once.
        let state = if accept { link::OfferState::Accepted } else { link::OfferState::Declined };
        let told = network.channels.send_frame(&sender, Control::OfferState { id, state });
        if accept {
            launch_transfer(app, network, id, record.direction);
        } else if !told {
            notify_transfer(app, network, sender, Control::Reject { id });
        }
    }
    Ok(())
}

/// A Wi-Fi link to the peer is up: ask for every accepted file it holds.
pub(super) fn resume_accepted_from(app: &AppHandle, network: &Arc<Network>, peer: &str) {
    let Ok(records) = transfer::with_store(app, &network.owner, |store| store.list()) else {
        return;
    };
    for record in records {
        if record.direction == Direction::Incoming
            && record.manifest.sender == peer
            && matches!(record.status, Status::Ready | Status::Interrupted)
            && !network.transfers.has_run(record.manifest.id).unwrap_or(true)
        {
            launch_transfer(app.clone(), Arc::clone(network), record.manifest.id, Direction::Incoming);
        }
    }
}

/// Join (or decline) the Wi-Fi link a paired device offered.
#[tauri::command]
pub(crate) async fn offline_wifi_link_join(
    app: AppHandle,
    peer: String,
    accept: bool,
    expected_account: String,
) -> Result<()> {
    let owner = require_snapshot_owner(&app.state::<AppState>(), &expected_account)?;
    let network = require_network(&app.state::<Runtime>(), &owner)?;
    network.require_capability(&app, &peer, PeerCapability::Xfer)?;
    if accept {
        app.state::<AppState>().audit_info("offline_wifi_link_join", "Joined a paired device's temporary Wi-Fi link for XFER");
    }
    link::join(&app, &network, &peer, accept).await
}

/// End the Wi-Fi link to a peer now (the PC returns to its own network).
#[tauri::command]
pub(crate) async fn offline_wifi_link_close(app: AppHandle, peer: String, expected_account: String) -> Result<()> {
    let owner = require_snapshot_owner(&app.state::<AppState>(), &expected_account)?;
    let network = require_network(&app.state::<Runtime>(), &owner)?;
    link::close(&app, &network, &peer);
    Ok(())
}

#[tauri::command]
pub(crate) async fn offline_xfer_resume(app: AppHandle, id: Uuid) -> Result<()> {
    let owner = local_owner(&app.state::<AppState>())?;
    let network = require_network(&app.state::<Runtime>(), &owner)?;
    let record = transfer::store_task(&app, &owner, move |store| store.get(id)).await?;
    if !matches!(
        record.status,
        Status::Ready | Status::Interrupted | Status::Paused | Status::Stopped | Status::Transferring
    ) || network.transfers.has_run(id)?
    {
        return Err(QGuardError::InvalidInput(
            "This transfer is outside its resumable state.".into(),
        ));
    }
    let peer = match record.direction {
        Direction::Incoming => &record.manifest.sender,
        Direction::Outgoing => &record.manifest.recipient,
    };
    network.require_peer(&app, peer)?;
    let record = transfer::store_task(&app, &owner, move |store| store.resume(id)).await?;
    changed(&app);
    tauri::async_runtime::spawn(async move {
        transfer::sync_controls(&app, &network).await;
        if matches!(record.status, Status::Ready | Status::Interrupted | Status::Transferring) {
            launch_transfer(app, network, id, record.direction);
        }
    });
    Ok(())
}

fn launch_transfer(app: AppHandle, network: Arc<Network>, id: Uuid, direction: Direction) {
    tauri::async_runtime::spawn(async move {
        let role = match direction {
            Direction::Incoming => "receiving",
            Direction::Outgoing => "sending",
        };
        diag::record_detail(&app, "transfer_session_started", diag::Subject::default(), format!("transfer {id} ({role})"));
        changed(&app);
        let outcome = match direction {
            Direction::Incoming => transfer::request(&app, &network, id).await,
            Direction::Outgoing => transfer::outgoing(&app, &network, id).await,
        };
        match &outcome {
            Ok(_) => diag::record_detail(&app, "transfer_session_ended", diag::Subject::default(), format!("transfer {id} ({role})")),
            Err(error) => {
                diag::record_detail(&app, "transfer_session_interrupted", diag::Subject::default(), format!("transfer {id} ({role}): {}", failure_reason(error)));
                // Tell connected devices now, so the other side retries on
                // its channel instead of at its next scheduled attempt.
                network.channels.nudge_all();
            }
        }
        changed(&app);
    });
}

#[tauri::command]
pub(crate) async fn offline_xfer_pause(app: AppHandle, id: Uuid) -> Result<()> {
    let owner = local_owner(&app.state::<AppState>())?;
    hold_or_cancel_transfer(app, owner, id, TransferAction::Pause).await
}

#[tauri::command]
pub(crate) async fn offline_xfer_stop(app: AppHandle, id: Uuid, expected_account: String) -> Result<()> {
    let owner = require_snapshot_owner(&app.state::<AppState>(), &expected_account)?;
    hold_or_cancel_transfer(app, owner, id, TransferAction::Stop).await
}

#[tauri::command]
pub(crate) async fn offline_xfer_cancel(app: AppHandle, id: Uuid) -> Result<()> {
    let owner = local_owner(&app.state::<AppState>())?;
    hold_or_cancel_transfer(app, owner, id, TransferAction::Cancel).await
}

async fn hold_or_cancel_transfer(app: AppHandle, owner: String, id: Uuid, action: TransferAction) -> Result<()> {
    let network = network_for(&app.state::<Runtime>(), &owner)?;
    transfer::store_task(&app, &owner, move |store| match action {
        TransferAction::Pause => store.pause(id),
        TransferAction::Stop => store.stop(id),
        TransferAction::Cancel => store.cancel(id),
        TransferAction::Resume => unreachable!("resume uses its own consented transition"),
    }).await?;
    if let Some(network) = network {
        network.transfers.stop(id)?;
        schedule_transfer_controls(&app, &network);
    }
    changed(&app);
    Ok(())
}

pub(super) fn schedule_transfer_controls(app: &AppHandle, network: &Arc<Network>) {
    let app = app.clone();
    let network = Arc::clone(network);
    tauri::async_runtime::spawn(async move { transfer::sync_controls(&app, &network).await });
}

fn notify_transfer(app: AppHandle, network: Arc<Network>, peer: String, control: Control) {
    tauri::async_runtime::spawn(async move {
        let Ok(_permit) = network.outbound.try_acquire() else {
            return;
        };
        if let Ok(mut session) = connect(&app, &network, &peer).await {
            let _ = wire::send(&mut session, &control).await;
        }
    });
}

#[tauri::command]
pub(crate) async fn offline_xfer_export(
    app: AppHandle,
    id: Uuid,
    file: u32,
) -> Result<Option<String>> {
    let owner = local_owner(&app.state::<AppState>())?;
    let record = transfer::store_task(&app, &owner, move |store| store.get(id)).await?;
    if record.direction != Direction::Incoming || record.status != Status::Verified {
        return Err(QGuardError::Trust(
            "Only verified received files can be saved.".into(),
        ));
    }
    let metadata = record
        .manifest
        .files
        .get(file as usize)
        .ok_or_else(|| QGuardError::InvalidInput("Invalid transfer file number.".into()))?;
    let file_name = metadata
        .path
        .rsplit('/')
        .next()
        .ok_or_else(wire::protocol_error)?
        .to_string();
    #[cfg(target_os = "android")]
    {
        let display =
            export_android_download(&app, &owner, id, file, file_name, metadata.size).await?;
        changed(&app);
        Ok(Some(display))
    }
    #[cfg(not(target_os = "android"))]
    {
        let picker = app.clone();
        let destination = tokio::task::spawn_blocking(move || {
            picker
                .dialog()
                .file()
                .set_file_name(file_name)
                .blocking_save_file()
        })
        .await
        .map_err(|_| QGuardError::Storage("The native save picker is unavailable.".into()))?;
        let Some(destination) = destination else {
            return Ok(None);
        };
        let path = destination.into_path().map_err(|_| {
            QGuardError::InvalidInput("Choose a local filesystem location for XFER export.".into())
        })?;
        let display = path.to_string_lossy().into_owned();
        transfer::store_task(&app, &owner, move |store| {
            store.export_file(id, file, &path)
        })
        .await?;
        changed(&app);
        Ok(Some(display))
    }
}

#[cfg(target_os = "android")]
async fn export_android_download(
    app: &AppHandle,
    owner: &str,
    id: Uuid,
    file: u32,
    name: String,
    size: u64,
) -> Result<String> {
    use crate::security::{content_uri, public_downloads};

    let mut reader =
        transfer::store_task(app, owner, move |store| store.read_verified(id, file)).await?;
    let worker = app.clone();
    let account = owner.to_owned();
    let display = tokio::task::spawn_blocking(move || -> Result<(String, String)> {
        if local_owner(&worker.state::<AppState>())? != account {
            return Err(QGuardError::Trust(
                "The local account changed before saving the file.".into(),
            ));
        }
        let uri = public_downloads::begin(&name, "application/octet-stream")?;
        let result = (|| -> Result<(String, String)> {
            let mut output = content_uri::open_write_truncate(&uri).map_err(|error| {
                QGuardError::Storage(format!("Could not open Android Downloads: {error}"))
            })?;
            let copied = std::io::copy(&mut reader, &mut output)
                .and_then(|copied| {
                    output.sync_all()?;
                    Ok(copied)
                })
                .map_err(|error| {
                    QGuardError::Storage(format!("Could not save the verified file: {error}"))
                })?;
            drop(output);
            if copied != size || local_owner(&worker.state::<AppState>())? != account {
                return Err(QGuardError::Trust(
                    "The file or local account changed while saving.".into(),
                ));
            }
            let published = public_downloads::finish(&uri)?;
            Ok((format!("{}/{}", published.relative_path, published.name), uri.clone()))
        })();
        if result.is_err() {
            let _ = public_downloads::abort(&uri);
        }
        result
    })
    .await
    .map_err(|_| {
        QGuardError::Storage("The Android Downloads operation was interrupted.".into())
    })??;
    let (display, uri) = display;
    let saved = display.clone();
    transfer::store_task(app, owner, move |store| {
        store.set_android_destination(id, file, saved, uri)
    })
    .await?;
    Ok(display)
}

#[tauri::command]
pub(crate) async fn offline_xfer_import_vault(
    app: AppHandle,
    id: Uuid,
    file: u32,
) -> Result<String> {
    let owner = local_owner(&app.state::<AppState>())?;
    import_into_vault(&app, &owner, id, file).await
}

pub(super) async fn import_into_vault(
    app: &AppHandle,
    owner: &str,
    id: Uuid,
    file: u32,
) -> Result<String> {
    let (reader, metadata) = transfer::store_task(app, owner, move |store| {
        let record = store.get(id)?;
        let metadata = record
            .manifest
            .files
            .get(file as usize)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Invalid transfer file number."))?;
        Ok((store.read_verified(id, file)?, metadata))
    })
    .await?;
    let name = metadata
        .path
        .rsplit('/')
        .next()
        .ok_or_else(wire::protocol_error)?
        .to_string();
    let worker = app.clone();
    let account = owner.to_string();
    let outcome = tokio::task::spawn_blocking(move || {
        crate::commands::vault_store::import_transfer_stream(
            &worker.state::<AppState>(),
            &account,
            reader,
            name,
            metadata.size,
            &metadata.digest,
        )
    })
    .await
    .map_err(|_| QGuardError::Storage("The Quantum Vault import was interrupted.".into()))??;
    let destination = format!("Quantum Vault / {}", outcome.entry.name);
    let saved = destination.clone();
    transfer::store_task(app, owner, move |store| {
        store.set_destination(id, file, saved)
    })
    .await?;
    app.state::<AppState>().audit_info(
        "offline_transfer_vault_import",
        "Imported a verified transfer directly into Quantum Vault Storage",
    );
    changed(app);
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn selections_are_account_scoped_atomic_and_consumed_once() {
        let runtime = Runtime::default();
        let id = Uuid::new_v4();
        let path = PathBuf::from("selected.txt");
        lock(&runtime.selections).unwrap().insert(
            id,
            SourceSelection {
                owner: "owner-a".into(),
                sources: vec![SelectedSource::Path(path.clone())],
                expires: Instant::now() + SELECTION_LIFETIME,
            },
        );
        assert!(claim_sources(&runtime, "owner-b", &[id]).is_err());
        assert!(claim_sources(&runtime, "owner-a", &[id, Uuid::new_v4()]).is_err());
        assert!(claim_sources(&runtime, "owner-a", &[id, id]).is_err());
        let selected = claim_sources(&runtime, "owner-a", &[id]).unwrap();
        assert!(matches!(selected.as_slice(), [SelectedSource::Path(value)] if value == &path));
        assert!(claim_sources(&runtime, "owner-a", &[id]).is_err());
    }
}
