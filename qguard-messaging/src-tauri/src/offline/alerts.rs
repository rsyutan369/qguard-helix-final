//! Operating-system alerts for offline events that need the user while the
//! Qguard window is not in front. The in-app prompt remains where the user
//! decides. Alerts never include file names, message text or fingerprints.
//!
//! Desktop: when the window is not in front. Android: while Qguard is locked
//! and background Mesh is on (otherwise locking suspends local networking).
//! Pairing still needs an unlocked Qguard, so a locked device refuses it.

use std::{
    collections::{HashSet, VecDeque},
    sync::{LazyLock, Mutex},
};

use tauri::{AppHandle, Manager};

use crate::state::AppState;

use super::{
    pairing::Pairings,
    profile::{PeerCapability, TrustBook},
    xfer::{Direction, Record},
};

const MAX_REMEMBERED: usize = 512;
const RECENT_COMPLETION_MS: i64 = 120_000;

static SENT: LazyLock<Mutex<(HashSet<String>, VecDeque<String>)>> =
    LazyLock::new(Mutex::default);

/// Each event alerts at most once per process, including when the window
/// was in front and the in-app prompt already showed it.
fn first_time(key: String) -> bool {
    let Ok(mut sent) = SENT.lock() else {
        return false;
    };
    let (seen, order) = &mut *sent;
    if !seen.insert(key.clone()) {
        return false;
    }
    order.push_back(key);
    while order.len() > MAX_REMEMBERED {
        if let Some(oldest) = order.pop_front() {
            seen.remove(&oldest);
        }
    }
    true
}

/// Raise the alert once, and record the event it stands for in the
/// connection diagnostics (kind, peer prefix and a detail without content).
fn notify(app: &AppHandle, key: String, title: &str, body: &str, kind: &'static str, peer: Option<&str>, detail: &str) {
    if first_time(key) {
        super::diag::record_detail(
            app,
            kind,
            super::diag::Subject { peer, ..Default::default() },
            detail,
        );
        deliver(app, title, body);
    }
}

#[cfg(desktop)]
fn deliver(app: &AppHandle, title: &str, body: &str) {
    use tauri_plugin_notification::NotificationExt;

    let in_front = app.webview_windows().values().any(|window| {
        window.is_focused().unwrap_or(false)
            && window.is_visible().unwrap_or(false)
            && !window.is_minimized().unwrap_or(false)
    });
    if in_front {
        return;
    }
    if let Err(error) = app.notification().builder().title(title).body(body).show() {
        tracing::debug!("offline alert was not shown: {error}");
    }
}

/// Android: only while Qguard is locked (it locks whenever it leaves the
/// screen); in front, the in-app notice shows instead. The notification's
/// lock-screen version is generic (see HelixMeshService.kt).
#[cfg(mobile)]
fn deliver(app: &AppHandle, title: &str, body: &str) {
    if super::profile::unlocked_in_front(&app.state::<AppState>()) {
        return;
    }
    super::background::notify(title, title, body);
}

fn capability_names(capabilities: &[PeerCapability]) -> &'static str {
    match capabilities {
        [PeerCapability::Mesh] => "Mesh messaging",
        [PeerCapability::Xfer] => "XFER file transfer",
        _ => "Mesh messaging and XFER file transfer",
    }
}

fn platform_name(platform: &str) -> &'static str {
    match platform {
        "android" => "Android",
        "windows" => "Windows",
        "macos" => "macOS",
        "linux" => "Linux",
        _ => "device",
    }
}

/// Alert on new incoming requests and on outgoing requests whose code is
/// ready to compare. Called whenever pairing state changes.
pub(super) fn pairings(app: &AppHandle, pairings: &Pairings) {
    for alert in pairings.alerts() {
        let device = format!("{} ({})", alert.label, platform_name(&alert.platform));
        if alert.incoming {
            notify(
                app,
                format!("pairing-request:{}", alert.id),
                "New device connection request",
                &format!(
                    "{device} wants to connect for {}. Open Qguard Messaging to allow or decline it.",
                    capability_names(&alert.requested)
                ),
                "pairing_request_received",
                Some(&alert.peer),
                capability_names(&alert.requested),
            );
        } else {
            notify(
                app,
                format!("pairing-code:{}", alert.id),
                "Compare the verification code",
                &format!(
                    "{device} approved your request. Open Qguard Messaging and check that both devices show the same code."
                ),
                "pairing_code_ready",
                Some(&alert.peer),
                "the other device approved; compare the verification code",
            );
        }
    }
}

fn peer_name(app: &AppHandle, owner: &str, fingerprint: &str) -> String {
    TrustBook::load(&app.state::<AppState>(), owner)
        .ok()
        .and_then(|book| {
            let peer = book.peers.get(fingerprint)?;
            Some(peer.owner.clone().unwrap_or_else(|| peer.label.clone()))
        })
        .unwrap_or_else(|| "A trusted device".into())
}

fn files_label(record: &Record) -> String {
    let count = record.manifest.files.len();
    let size = format_bytes(record.manifest.total_bytes());
    if count == 1 {
        format!("1 file ({size})")
    } else {
        format!("{count} files ({size})")
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// A paired device opened a Wi-Fi link for a transfer: this user joins it.
pub(super) fn wifi_link(app: &AppHandle, owner: &str, peer: &str, automatic: bool) {
    let name = peer_name(app, owner, peer);
    notify(
        app,
        format!("wifi-link:{peer}:{}", chrono::Utc::now().timestamp() / 300),
        "Join the Wi-Fi link for XFER",
        &if automatic {
            format!("{name} opened a private Wi-Fi link for your file transfer. Open Qguard Messaging and choose Join to continue.")
        } else {
            format!("{name} opened a private Wi-Fi link for your file transfer. Open Qguard Messaging to see the network to join.")
        },
        "wifi_link_offered",
        Some(peer),
        "temporary Wi-Fi link offered",
    );
}

pub(super) fn offer(app: &AppHandle, owner: &str, record: &Record) {
    if record.direction != Direction::Incoming {
        return;
    }
    let sender = peer_name(app, owner, &record.manifest.sender);
    notify(
        app,
        format!("offer:{}", record.manifest.id),
        "Incoming XFER file offer",
        &format!(
            "{sender} wants to send you {}. Nothing is received until you accept it in Qguard Messaging.",
            files_label(record)
        ),
        "transfer_offer_received",
        Some(&record.manifest.sender),
        &format!("transfer {}: {}", record.manifest.id, files_label(record)),
    );
}

pub(super) fn completed(app: &AppHandle, owner: &str, record: &Record) {
    let recent = record
        .completed_at_ms
        .is_some_and(|at| chrono::Utc::now().timestamp_millis() - at <= RECENT_COMPLETION_MS);
    if !recent {
        return;
    }
    let files = files_label(record);
    let (title, body) = match record.direction {
        Direction::Incoming => (
            "Files received and verified",
            format!(
                "{files} from {} passed SHA3-256 integrity verification.",
                peer_name(app, owner, &record.manifest.sender)
            ),
        ),
        Direction::Outgoing => (
            "Transfer delivered",
            format!(
                "{} received {files} and confirmed SHA3-256 integrity verification.",
                peer_name(app, owner, &record.manifest.recipient)
            ),
        ),
    };
    let other = match record.direction {
        Direction::Incoming => &record.manifest.sender,
        Direction::Outgoing => &record.manifest.recipient,
    };
    notify(
        app,
        format!("completed:{}", record.manifest.id),
        title,
        &body,
        "transfer_verified",
        Some(other),
        &format!("transfer {}: {files} passed SHA3-256 verification", record.manifest.id),
    );
}

/// A newly stored incoming Mesh message. The text stays in the app.
pub(super) fn mesh_message(app: &AppHandle, owner: &str, sender: &str, id: uuid::Uuid, emergency: bool) {
    let name = peer_name(app, owner, sender);
    let (title, body) = mesh_alert_text(&name, emergency);
    notify(app, format!("mesh:{sender}:{id}"), title, &body, "message_alert_raised", Some(sender), &format!("message {id}"));
}

fn mesh_alert_text(name: &str, emergency: bool) -> (&'static str, String) {
    if emergency {
        (
            "Emergency Mesh message",
            format!("{name} sent an emergency message over Qguard Mesh. Open Qguard Messaging to read it."),
        )
    } else {
        (
            "New Mesh message",
            format!("{name} sent you a message over Qguard Mesh. Open Qguard Messaging to read it."),
        )
    }
}

pub(super) fn failed(app: &AppHandle, record: &Record, reason: &str) {
    notify(
        app,
        format!("failed:{}:{reason}", record.manifest.id),
        "XFER transfer needs attention",
        &format!(
            "A transfer of {} stopped: {reason}. Open Qguard Messaging for recovery options.",
            files_label(record)
        ),
        "transfer_failed",
        None,
        &format!("transfer {}: {reason}", record.manifest.id),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alerts_are_sent_once_and_stay_bounded() {
        let key = format!("test:{}", uuid::Uuid::new_v4());
        assert!(first_time(key.clone()));
        assert!(!first_time(key));
        for index in 0..(MAX_REMEMBERED + 8) {
            first_time(format!("bounded:{index}"));
        }
        let sent = SENT.lock().unwrap();
        assert!(sent.0.len() <= MAX_REMEMBERED && sent.1.len() <= MAX_REMEMBERED);
    }

    #[test]
    fn alert_text_names_capabilities_and_sizes_without_file_names() {
        assert_eq!(capability_names(&[PeerCapability::Mesh]), "Mesh messaging");
        assert_eq!(
            capability_names(&[PeerCapability::Mesh, PeerCapability::Xfer]),
            "Mesh messaging and XFER file transfer"
        );
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(3 * 1024 * 1024 / 2), "1.5 MiB");
        assert_eq!(platform_name("macos"), "macOS");
    }

    #[test]
    fn mesh_alerts_name_the_sender_but_never_carry_message_text() {
        let (title, body) = mesh_alert_text("Alex", false);
        assert_eq!(title, "New Mesh message");
        assert!(body.starts_with("Alex sent you a message"));
        let (title, body) = mesh_alert_text("Alex", true);
        assert_eq!(title, "Emergency Mesh message");
        assert!(body.contains("Open Qguard Messaging to read it."));
    }
}
