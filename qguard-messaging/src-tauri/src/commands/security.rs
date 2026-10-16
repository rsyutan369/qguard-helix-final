use serde::Serialize;
use crate::identity::platform_device_label;
use tauri::State;

use crate::device_trust::DeviceTrustState;
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

/// Build the quantum security report from real runtime evidence only.
///
/// Every field is derived from state that actually exists in this session:
/// the loaded hybrid identity, signed/one-time prekeys and how recently the
/// signed prekey was rotated, conversations opened this session, device trust
/// state, and the tamper-evident audit chain. No status string or score is
/// hardcoded, so exported reports stay traceable.
fn quantum_report_from_state(state: &AppState) -> QuantumSecurityReport {
    let identity_present = state.identity.lock().map(|g| g.is_some()).unwrap_or(false);
    let signed_prekey_present = state
        .signed_prekey
        .lock()
        .map(|g| g.is_some())
        .unwrap_or(false);
    let one_time_prekeys = state.one_time_prekeys.lock().map(|g| g.len()).unwrap_or(0);
    let devices = state.devices.lock().map(|d| d.clone()).unwrap_or_default();
    let active_devices = devices
        .values()
        .filter(|d| d.trust_state != DeviceTrustState::Revoked)
        .count();
    let revoked = devices
        .values()
        .any(|d| d.trust_state == DeviceTrustState::Revoked);
    let active_sessions = state.ratchets.lock().map(|r| r.len()).unwrap_or(0);
    let audit_chain_valid = state.audit.lock().map(|a| a.verify()).unwrap_or(false);
    // Forward secrecy is a property of prekey rotation, not of how many
    // conversations happen to be open: it is read from the prekeys themselves.
    let forward_secrecy = match state.user_id() {
        Ok(user_id) => crate::commands::keys::forward_secrecy_posture(state, &user_id),
        Err(_) => crate::commands::keys::describe_forward_secrecy(None, 0, false),
    };

    // Real key-rotation history pulled from the verified audit hash chain.
    let key_rotation_history: Vec<String> = state
        .audit
        .lock()
        .map(|audit| {
            audit
                .recent(50)
                .into_iter()
                .filter(|event| {
                    let kind = event.event_type.to_lowercase();
                    kind.contains("key")
                        || kind.contains("prekey")
                        || kind.contains("identity")
                        || kind.contains("device")
                        || kind.contains("rotat")
                })
                .map(|event| format!("{} at {}", event.event_type, event.created_at.to_rfc3339()))
                .collect()
        })
        .unwrap_or_default();

    let mut warnings = Vec::new();
    if !identity_present {
        warnings.push("No local hybrid identity is loaded for this session".to_string());
    }
    if !signed_prekey_present {
        warnings.push("Signed prekey is not available in this session".to_string());
    }
    if one_time_prekeys == 0 {
        warnings.push("No one-time prekeys are available; replenish the prekey pool".to_string());
    }
    if revoked {
        warnings.push("One or more devices are revoked".to_string());
    }
    if !audit_chain_valid {
        warnings.push("Local audit hash chain failed verification".to_string());
    }
    if signed_prekey_present && !forward_secrecy.healthy {
        warnings.push(format!("Forward secrecy: {}", forward_secrecy.summary));
    }

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
    if forward_secrecy.healthy {
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
    let quantum_safe_score = score.min(100) as u8;

    let hybrid_ready = identity_present && signed_prekey_present;
    QuantumSecurityReport {
        hybrid_session_status: if active_sessions > 0 {
            "Hybrid Active".to_string()
        } else if hybrid_ready {
            "Hybrid Ready".to_string()
        } else {
            "No Active Session".to_string()
        },
        pqc_algorithm: if identity_present {
            "ML-KEM-1024 + ML-DSA-65".to_string()
        } else {
            "No active device keys".to_string()
        },
        forward_secrecy_healthy: forward_secrecy.healthy,
        forward_secrecy: forward_secrecy.summary,
        hndl_protection: if hybrid_ready {
            "Enabled".to_string()
        } else {
            "Not Ready".to_string()
        },
        quantum_safe_score,
        key_rotation_history,
        warnings,
    }
}

#[tauri::command]
pub fn security_verify_fingerprint(
    state: State<'_, AppState>,
    remote_fingerprint: String,
) -> Result<SafetyNumber> {
    let local = state.ensure_identity(&state.user_id()?, platform_device_label())?;
    Ok(conversation_safety_number(
        &local.fingerprint,
        &remote_fingerprint,
    ))
}

#[tauri::command]
pub fn security_export_report(state: State<'_, AppState>) -> Result<SecurityReport> {
    state.require_auth()?;
    let audit_chain_valid = state.audit.lock().map(|a| a.verify()).unwrap_or(false);
    Ok(SecurityReport {
        quantum: quantum_report_from_state(&state),
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
    Ok(quantum_report_from_state(&state))
}
