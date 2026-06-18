use std::path::Path;

use tauri::State;

use crate::device_trust::DeviceTrustState;
use crate::error::Result;
use crate::state::AppState;
use crate::telemetry::{DashboardSnapshot, TelemetryEvent};

/// Recursively sum the byte size of every file under `path`. Returns 0 when the
/// directory does not exist or cannot be read, so the snapshot never invents a
/// storage figure.
fn directory_size_bytes(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_dir() {
                total += directory_size_bytes(&entry_path);
            } else if let Ok(meta) = entry.metadata() {
                total += meta.len();
            }
        }
    }
    total
}

fn human_bytes(bytes: u64) -> String {
    const GB: f64 = (1024 * 1024 * 1024) as f64;
    const MB: f64 = (1024 * 1024) as f64;
    const KB: f64 = 1024.0;
    let value = bytes as f64;
    if value >= GB {
        format!("{:.2} GB", value / GB)
    } else if value >= MB {
        format!("{:.2} MB", value / MB)
    } else if value >= KB {
        format!("{:.2} KB", value / KB)
    } else {
        format!("{bytes} B")
    }
}

/// Dashboard snapshot derived entirely from real runtime evidence: loaded
/// identity and prekeys, active ratchet sessions, device trust state, the
/// verified audit chain, and the on-disk vault size. No status or score is
/// hardcoded.
#[tauri::command]
pub fn telemetry_dashboard_snapshot(state: State<'_, AppState>) -> Result<DashboardSnapshot> {
    state.require_auth()?;

    let identity_present = state.identity.lock().map(|g| g.is_some()).unwrap_or(false);
    let signed_prekey_present = state
        .signed_prekey
        .lock()
        .map(|g| g.is_some())
        .unwrap_or(false);
    let one_time_prekeys = state.one_time_prekeys.lock().map(|g| g.len()).unwrap_or(0);
    let devices = state.devices.lock().map(|d| d.clone()).unwrap_or_default();
    let active_sessions = state.ratchets.lock().map(|r| r.len() as u32).unwrap_or(0);
    let active_devices = devices
        .values()
        .filter(|d| d.trust_state != DeviceTrustState::Revoked)
        .count() as u32;
    let revoked = devices
        .values()
        .any(|d| d.trust_state == DeviceTrustState::Revoked);
    let audit_chain_valid = state.audit.lock().map(|a| a.verify()).unwrap_or(false);
    let hybrid_ready = identity_present && signed_prekey_present;
    let vault_bytes = directory_size_bytes(&state.data_dir.join("vault"));

    // Evidence-based score: each verified control contributes; no fabricated constant.
    let mut score: u32 = 0;
    if identity_present {
        score += 30;
    }
    if signed_prekey_present {
        score += 20;
    }
    if one_time_prekeys > 0 {
        score += 15;
    }
    if active_sessions > 0 {
        score += 10;
    }
    if active_devices > 0 {
        score += 10;
    }
    if audit_chain_valid {
        score += 15;
    }
    if revoked {
        score = score.saturating_sub(15);
    }

    Ok(DashboardSnapshot {
        e2ee_status: if hybrid_ready {
            "Protected".to_string()
        } else if identity_present {
            "Needs Verification".to_string()
        } else {
            "Needs Device".to_string()
        },
        pqc_status: if hybrid_ready {
            "Hybrid Active".to_string()
        } else if identity_present {
            "Partially Configured".to_string()
        } else {
            "Awaiting Keys".to_string()
        },
        active_sessions,
        vault_storage: human_bytes(vault_bytes),
        device_count: active_devices,
        quantum_safe_score: score.min(100) as u8,
        hndl_status: if hybrid_ready {
            "Enabled".to_string()
        } else {
            "Not Ready".to_string()
        },
    })
}

#[tauri::command]
pub fn telemetry_recent_events(state: State<'_, AppState>) -> Result<Vec<TelemetryEvent>> {
    state.require_auth()?;
    let mut events = state
        .telemetry
        .lock()
        .map(|e| e.clone())
        .unwrap_or_default();
    events.reverse();
    Ok(events.into_iter().take(30).collect())
}
