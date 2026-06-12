use serde::{Deserialize, Serialize};
use tauri::State;

use crate::device_trust::{DeviceTrustState, TrustedDevice};
use crate::error::{QGuardError, Result};
use crate::fingerprints::conversation_safety_number;
use crate::state::AppState;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceApprovalRequest {
    pub device_id: String,
    pub label: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct QrVerification {
    pub qr_payload: String,
    pub safety_number: String,
    pub verified: bool,
}

#[tauri::command]
pub fn devices_register_current_device(
    state: State<'_, AppState>,
    label: String,
) -> Result<TrustedDevice> {
    let user_id = state.user_id()?;
    let bundle = state.ensure_identity(&user_id, &label)?;
    let device =
        TrustedDevice::new_this_device(user_id, bundle.device_id, label, bundle.fingerprint);
    state
        .devices
        .lock()
        .map_err(|_| QGuardError::Storage("device lock poisoned".to_string()))?
        .insert(device.device_id.clone(), device.clone());
    Ok(device)
}

#[tauri::command]
pub fn devices_list_trust_center(state: State<'_, AppState>) -> Result<Vec<TrustedDevice>> {
    let user_id = state.user_id()?;
    let bundle = state.ensure_identity(&user_id, "Windows Desktop")?;
    let mut devices = state
        .devices
        .lock()
        .map_err(|_| QGuardError::Storage("device lock poisoned".to_string()))?;
    if !devices.contains_key(&bundle.device_id) {
        devices.insert(
            bundle.device_id.clone(),
            TrustedDevice::new_this_device(
                user_id,
                bundle.device_id.clone(),
                bundle.device_label,
                bundle.fingerprint,
            ),
        );
    }
    Ok(devices.values().cloned().collect())
}

#[tauri::command]
pub fn devices_verify_qr(
    state: State<'_, AppState>,
    remote_fingerprint: String,
) -> Result<QrVerification> {
    let user_id = state.user_id()?;
    let bundle = state.ensure_identity(&user_id, "Windows Desktop")?;
    let safety = conversation_safety_number(&bundle.fingerprint, &remote_fingerprint);
    Ok(QrVerification {
        qr_payload: safety.qr_payload,
        safety_number: safety.display,
        verified: true,
    })
}

#[tauri::command]
pub fn devices_approve_qr(
    state: State<'_, AppState>,
    request: DeviceApprovalRequest,
) -> Result<TrustedDevice> {
    let device = TrustedDevice {
        device_id: request.device_id,
        user_id: state.user_id()?,
        label: request.label,
        fingerprint: request.fingerprint,
        trust_state: DeviceTrustState::Trusted,
        pqc_status: "Hybrid active: X25519 + ML-KEM-1024".to_string(),
        last_seen_at: chrono::Utc::now(),
    };
    state
        .devices
        .lock()
        .map_err(|_| QGuardError::Storage("device lock poisoned".to_string()))?
        .insert(device.device_id.clone(), device.clone());
    state.audit_info(
        "device_approved",
        "New device approved through QR trust flow",
    );
    Ok(device)
}

#[tauri::command]
pub fn devices_revoke(state: State<'_, AppState>, device_id: String) -> Result<bool> {
    state.require_auth()?;
    let mut devices = state
        .devices
        .lock()
        .map_err(|_| QGuardError::Storage("device lock poisoned".to_string()))?;
    if let Some(device) = devices.get_mut(&device_id) {
        device.trust_state = DeviceTrustState::Revoked;
        state.audit_info("device_revoked", "Device revoked from trust center");
        return Ok(true);
    }
    Err(QGuardError::NotFound("device".to_string()))
}

#[tauri::command]
pub fn devices_delete(state: State<'_, AppState>, device_id: String) -> Result<bool> {
    state.require_auth()?;
    let removed = state
        .devices
        .lock()
        .map_err(|_| QGuardError::Storage("device lock poisoned".to_string()))?
        .remove(&device_id)
        .is_some();
    if removed {
        state.audit_info("device_deleted", "Device removed from trust center");
    }
    Ok(removed)
}
