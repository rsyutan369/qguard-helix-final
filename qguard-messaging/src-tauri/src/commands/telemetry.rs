use tauri::State;

use crate::device_trust::DeviceTrustState;
use crate::error::Result;
use crate::state::AppState;
use crate::telemetry::{DashboardSnapshot, TelemetryEvent};

#[tauri::command]
pub fn telemetry_dashboard_snapshot(state: State<'_, AppState>) -> Result<DashboardSnapshot> {
    state.require_auth()?;
    let devices = state.devices.lock().map(|d| d.clone()).unwrap_or_default();
    let active_sessions = state.ratchets.lock().map(|r| r.len() as u32).unwrap_or(0);
    let revoked = devices
        .values()
        .any(|d| d.trust_state == DeviceTrustState::Revoked);
    Ok(DashboardSnapshot {
        e2ee_status: "Protected".to_string(),
        pqc_status: "Hybrid Active".to_string(),
        active_sessions,
        vault_storage: "2.45 GB".to_string(),
        device_count: devices.len() as u32,
        quantum_safe_score: if revoked { 91 } else { 98 },
        hndl_status: "Enabled".to_string(),
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
