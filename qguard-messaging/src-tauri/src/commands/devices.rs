use serde::{Deserialize, Serialize};
use crate::identity::platform_device_label;
use tauri::State;

use crate::commands::calls::CallPeerIdentity;
use crate::device_pins::{identity_digest, DevicePin, DeviceStanding, PinSource, PinSubject};
use crate::device_trust::{DeviceTrustState, TrustedDevice};
use crate::error::{QGuardError, Result};
use crate::fingerprints::conversation_safety_number;
use crate::identity::safety_fingerprint;
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
    /// Always false from this command. Deriving a safety number verifies
    /// nothing: it only produces the value two people must COMPARE. This field
    /// used to be hardcoded `true`, so a device read as verified the moment a
    /// fingerprint was typed in, whatever it was.
    pub verified: bool,
}

#[tauri::command]
pub fn devices_list_trust_center(state: State<'_, AppState>) -> Result<Vec<TrustedDevice>> {
    let user_id = state.user_id()?;
    let bundle = state.ensure_identity(&user_id, platform_device_label())?;
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
    let bundle = state.ensure_identity(&user_id, platform_device_label())?;
    let safety = conversation_safety_number(&bundle.fingerprint, &remote_fingerprint);
    Ok(QrVerification {
        qr_payload: safety.qr_payload,
        safety_number: safety.display,
        verified: false,
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

/// A device the user revokes or removes leaves this device's record too, so
/// that if a row with its id is ever listed again it is NEW and has to be
/// approved — not quietly accepted because it used to be trusted.
fn forget_own_device_pin(state: &AppState, user_id: &str, device_id: &str) {
    let forgotten = state
        .with_device_pins(user_id, |book| book.forget_device(user_id, device_id))
        .unwrap_or(false);
    if forgotten {
        state.audit_info(
            "device_pin_removed",
            "Revoked device removed from this device's record of the account's devices",
        );
    }
    if let Ok(this_device) = state.ensure_identity(user_id, platform_device_label()) {
        forget_ratchet_sessions(state, user_id, &this_device.device_id, &[device_id.to_string()]);
    }
}

/// Destroy the ratchet sessions with `peers` (revoked, removed, or re-keyed
/// devices). Best effort: the send path refuses such devices regardless.
fn forget_ratchet_sessions(state: &AppState, user_id: &str, local_device: &str, peers: &[String]) {
    if peers.is_empty() {
        return;
    }
    let forgotten = state
        .with_ratchet_sessions(user_id, local_device, |book| {
            peers.iter().filter(|peer| book.forget_peer(peer)).count()
        })
        .unwrap_or(0);
    if forgotten > 0 {
        let _ = state.persist_ratchet_sessions(user_id);
        state.audit_info(
            "ratchet_session_destroyed",
            &format!("Secure sessions with {forgotten} revoked or re-keyed device(s) destroyed"),
        );
    }
}

#[tauri::command]
pub fn devices_revoke(state: State<'_, AppState>, device_id: String) -> Result<bool> {
    let session = state.require_auth()?;
    forget_own_device_pin(&state, &session.user_id, &device_id);
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
    let session = state.require_auth()?;
    forget_own_device_pin(&state, &session.user_id, &device_id);
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

// ---------------------------------------------------------------------------
// Device pins
//
// The commands above manage the trust center's in-memory list. These manage
// what actually gates delivery and verification: this device's own persisted
// record of which devices belong to whom (see `crate::device_pins`).
// ---------------------------------------------------------------------------

/// Upper bound on the devices one assessment may name.
const MAX_PIN_CANDIDATES: usize = 256;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePinVerdict {
    pub user_id: String,
    pub device_id: String,
    /// `pinned`, `new`, `key_changed`, `invalid_identity` (the row's own
    /// signature does not verify — it is never recorded and never usable), or
    /// `unknown` (the record could not be opened, so nothing can be said).
    pub standing: String,
    /// The device's safety fingerprint, computed here from its keys — never
    /// the fingerprint string the directory row carries.
    pub fingerprint: String,
    pub pinned_at: Option<String>,
    pub source: Option<PinSource>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePinAssessment {
    /// False when the record on this device could not be opened. Every verdict
    /// is then `unknown`, and the UI must say that device changes cannot be
    /// checked right now rather than show nothing.
    pub available: bool,
    pub verdicts: Vec<DevicePinVerdict>,
}

fn pin_timestamp(seconds: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0).map(|at| at.to_rfc3339())
}

/// Judge `devices` against the record, optionally approving the new ones.
fn judge_devices(
    state: &AppState,
    devices: Vec<CallPeerIdentity>,
    approve: bool,
) -> Result<DevicePinAssessment> {
    if devices.len() > MAX_PIN_CANDIDATES {
        return Err(QGuardError::InvalidInput(format!(
            "at most {MAX_PIN_CANDIDATES} devices can be checked at once"
        )));
    }
    let user_id = state.user_id()?;
    let this_device = state.ensure_identity(&user_id, platform_device_label())?;
    let this_subject = PinSubject {
        user_id: this_device.user_id.clone(),
        device_id: this_device.device_id.clone(),
        digest: identity_digest(
            &this_device.ed25519_identity_public,
            &this_device.mldsa_identity_public,
            &this_device.x25519_identity_public,
            &this_device.mlkem_identity_public,
        ),
    };

    // A row whose own dual signature does not verify is not a device at all:
    // it is never recorded, never approvable, and reported as such.
    let checked: Vec<(CallPeerIdentity, bool)> = devices
        .into_iter()
        .map(|device| {
            let valid = device.verify().is_ok();
            (device, valid)
        })
        .collect();
    let subjects: Vec<PinSubject> = checked
        .iter()
        .filter(|(_, valid)| *valid)
        .map(|(device, _)| device.pin_subject())
        .collect();

    let now = chrono::Utc::now().timestamp();
    let (available, standings, approved, pins) = state.with_device_pins(&user_id, |book| {
        // Order matters. Judging first lets a person's whole listed device set
        // become their first-use record — including this account's own other
        // devices the first time this build runs. Recording this device first
        // would give this account a record of one, and every other device of
        // the user's own would then read as newly added.
        let mut standings = book.assess(&subjects, now);
        book.pin_this_device(&this_subject, now);
        let mut approved = 0usize;
        if approve {
            for (subject, standing) in subjects.iter().zip(standings.iter_mut()) {
                if *standing == Some(DeviceStanding::New) && book.approve(subject, now).is_ok() {
                    *standing = Some(DeviceStanding::Pinned);
                    approved += 1;
                }
            }
        }
        let pins: Vec<Option<DevicePin>> = subjects
            .iter()
            .map(|subject| book.pin(&subject.user_id, &subject.device_id).cloned())
            .collect();
        (book.is_available(), standings, approved, pins)
    })?;

    // A device presenting different keys is not the device any session was
    // made with: its sessions go now, so nothing is ever read or sealed on
    // them again (the send path also re-checks the keys on every use).
    let key_changed: Vec<String> = subjects
        .iter()
        .zip(standings.iter())
        .filter(|(_, standing)| **standing == Some(DeviceStanding::KeyChanged))
        .map(|(subject, _)| subject.device_id.clone())
        .collect();
    forget_ratchet_sessions(state, &user_id, &this_device.device_id, &key_changed);

    let mut judged = standings.into_iter().zip(pins);
    let verdicts = checked
        .into_iter()
        .map(|(device, valid)| {
            let fingerprint = safety_fingerprint(
                &device.ed25519_identity_public,
                &device.mldsa_identity_public,
            );
            if !valid {
                return DevicePinVerdict {
                    user_id: device.user_id,
                    device_id: device.device_id,
                    standing: "invalid_identity".to_string(),
                    fingerprint,
                    pinned_at: None,
                    source: None,
                };
            }
            let (standing, pin) = judged.next().unwrap_or((None, None));
            // A pin under this id with other keys says nothing about THIS row.
            let pin = pin.filter(|_| standing == Some(DeviceStanding::Pinned));
            DevicePinVerdict {
                user_id: device.user_id,
                device_id: device.device_id,
                standing: match standing {
                    Some(DeviceStanding::Pinned) => "pinned",
                    Some(DeviceStanding::New) => "new",
                    Some(DeviceStanding::KeyChanged) => "key_changed",
                    None => "unknown",
                }
                .to_string(),
                fingerprint,
                pinned_at: pin.as_ref().and_then(|pin| pin_timestamp(pin.pinned_at)),
                source: pin.map(|pin| pin.source),
            }
        })
        .collect();

    if approved > 0 {
        state.audit_info(
            "device_pin_approved",
            &format!("{approved} newly listed device(s) approved on this device"),
        );
    }
    Ok(DevicePinAssessment { available, verdicts })
}

/// Check the devices the directory currently lists against this device's own
/// record. Pass EVERY device listed for the people concerned: someone seen for
/// the first time has their whole list recorded as first use.
///
/// Async: each row's ML-DSA-65 + Ed25519 identity signature is verified here,
/// which must not run on the UI thread.
#[tauri::command]
pub async fn devices_assess_pins(
    state: State<'_, AppState>,
    devices: Vec<CallPeerIdentity>,
) -> Result<DevicePinAssessment> {
    state.require_auth()?;
    let _key_scope = state.lock_key_scope()?;
    judge_devices(&state, devices, false)
}

/// Approve the NEW devices among `devices` — the user has looked at them and
/// accepts them. Devices whose keys changed are never approved by this.
#[tauri::command]
pub async fn devices_approve_pins(
    state: State<'_, AppState>,
    devices: Vec<CallPeerIdentity>,
) -> Result<DevicePinAssessment> {
    let session = state.require_auth()?;
    state.check_decrypt_rate_limit("device_pin_approve", &session.user_id, 30, 300)?;
    let _key_scope = state.lock_key_scope()?;
    judge_devices(&state, devices, true)
}
