use serde::Serialize;
use tauri::State;

use crate::error::Result;
use crate::fingerprints::{conversation_safety_number, SafetyNumber};
use crate::security::{hardening_status, SecurityHardeningStatus};
use crate::state::AppState;
use crate::telemetry::QuantumSecurityReport;

#[derive(Clone, Debug, Serialize)]
pub struct SecurityReport {
    pub quantum: QuantumSecurityReport,
    pub hardening: SecurityHardeningStatus,
    pub audit_chain_valid: bool,
    pub limitations: Vec<String>,
}

#[tauri::command]
pub fn security_verify_fingerprint(
    state: State<'_, AppState>,
    remote_fingerprint: String,
) -> Result<SafetyNumber> {
    let local = state.ensure_identity(&state.user_id()?, "Windows Desktop")?;
    Ok(conversation_safety_number(
        &local.fingerprint,
        &remote_fingerprint,
    ))
}

#[tauri::command]
pub fn security_report_key_change(
    state: State<'_, AppState>,
    device_id: String,
    new_fingerprint: String,
) -> Result<bool> {
    state.require_auth()?;
    state.audit_info(
        "key_change_reported",
        &format!("Key change for {device_id}: {new_fingerprint}"),
    );
    state.touch_telemetry("warning", "Key change alert recorded", 100);
    Ok(true)
}

#[tauri::command]
pub fn security_export_report(state: State<'_, AppState>) -> Result<SecurityReport> {
    state.require_auth()?;
    let audit_chain_valid = state.audit.lock().map(|a| a.verify()).unwrap_or(false);
    Ok(SecurityReport {
        quantum: QuantumSecurityReport::default(),
        hardening: hardening_status(audit_chain_valid),
        audit_chain_valid,
        limitations: vec![
            "Requires independent cryptographic audit before handling regulated production traffic".to_string(),
            "Supabase relay is zero-knowledge for content but still observes minimum routing metadata".to_string(),
        ],
    })
}

#[tauri::command]
pub fn security_hardening_status(state: State<'_, AppState>) -> Result<SecurityHardeningStatus> {
    state.require_auth()?;
    let audit_chain_valid = state.audit.lock().map(|a| a.verify()).unwrap_or(false);
    Ok(hardening_status(audit_chain_valid))
}

#[tauri::command]
pub fn security_quantum_report(state: State<'_, AppState>) -> Result<QuantumSecurityReport> {
    state.require_auth()?;
    Ok(QuantumSecurityReport::default())
}
