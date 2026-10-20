//! Nearby delivery (roadmap 9.1; owner decision 2026-10-20: Google Play
//! services Nearby Connections, Android only).
//!
//! Carries outbox envelope rows (commands/outbox.rs) straight to phones in
//! range when the relay cannot be reached. The rows are end-to-end sealed for
//! their recipient device, so the radio link adds no trust: a received row
//! goes through exactly the same screening, signature and decryption checks as
//! one fetched from the relay. What a nearby phone learns is what the relay
//! would: sizes, timing and device ids — and only while in radio range.
//!
//! The Android side is `NearbyRelay.kt`; every other platform reports
//! "unsupported".

use serde::Serialize;
use tauri::State;

use crate::error::{QGuardError, Result};
use crate::state::AppState;

/// Nearby Connections' BYTES payload limit.
pub const NEARBY_MAX_ROW_BYTES: usize = 32 * 1024;
const REQUIRED_FIELDS: [&str; 8] = ["id", "conversation_id", "sender_user_id", "recipient_device_id", "ciphertext", "nonce", "auth_tag", "aad"];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NearbyStatus {
    pub supported: bool,
    /// Google Play services present and current enough.
    pub available: bool,
    pub permissions_granted: bool,
    pub running: bool,
    pub peers: u32,
}

impl NearbyStatus {
    fn unsupported() -> Self {
        Self { supported: false, available: false, permissions_granted: false, running: false, peers: 0 }
    }
}

/// A row as a nearby phone handed it over: it must look like a sealed envelope
/// row and fit one payload; anything else is dropped before it reaches the UI.
pub(crate) fn accept_received(raw: &str) -> Option<serde_json::Value> {
    if raw.len() > NEARBY_MAX_ROW_BYTES {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let object = value.as_object()?;
    if object.contains_key("plaintext") {
        return None;
    }
    for field in REQUIRED_FIELDS {
        match object.get(field) {
            Some(serde_json::Value::String(text)) if !text.is_empty() => {}
            _ => return None,
        }
    }
    Some(value)
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
fn parse_status(raw: &str) -> Result<NearbyStatus> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|e| QGuardError::Storage(format!("nearby status: {e}")))?;
    Ok(NearbyStatus {
        supported: true,
        available: value.get("available").and_then(|v| v.as_bool()).unwrap_or(false),
        permissions_granted: value.get("permissions").and_then(|v| v.as_bool()).unwrap_or(false),
        running: value.get("running").and_then(|v| v.as_bool()).unwrap_or(false),
        peers: value.get("peers").and_then(|v| v.as_u64()).unwrap_or(0).min(u32::MAX as u64) as u32,
    })
}

#[cfg(target_os = "android")]
mod platform {
    use super::*;
    use crate::security::android_bridge::{call_static_string, in_band};

    const CLASS: &str = "com.qguard.messaging.NearbyRelay";

    fn call(method: &str, args: &[&str]) -> Result<String> {
        call_static_string(CLASS, method, args)
            .and_then(in_band)
            .map_err(|e| QGuardError::Storage(format!("nearby ({method}): {e}")))
    }

    pub fn status() -> Result<NearbyStatus> { parse_status(&call("status", &[])?) }
    pub fn start() -> Result<NearbyStatus> { call("start", &[])?; status() }
    pub fn stop() -> Result<NearbyStatus> { call("stop", &[])?; status() }
    pub fn request_permissions() -> Result<()> { call("requestPermissions", &[]).map(|_| ()) }
    pub fn send(row: &str) -> Result<()> { call("send", &[row]).map(|_| ()) }
    pub fn clear_outgoing() -> Result<()> { call("clearOutgoing", &[]).map(|_| ()) }
    pub fn take_received() -> Result<Vec<String>> {
        let raw = call("takeReceived", &[])?;
        serde_json::from_str::<Vec<String>>(&raw).map_err(|e| QGuardError::Storage(format!("nearby received: {e}")))
    }
}

#[cfg(not(target_os = "android"))]
mod platform {
    use super::*;

    fn unsupported<T>() -> Result<T> {
        Err(QGuardError::InvalidInput("Nearby delivery is available in the Android app only.".to_string()))
    }
    pub fn status() -> Result<NearbyStatus> { Ok(NearbyStatus::unsupported()) }
    pub fn start() -> Result<NearbyStatus> { unsupported() }
    pub fn stop() -> Result<NearbyStatus> { Ok(NearbyStatus::unsupported()) }
    pub fn request_permissions() -> Result<()> { unsupported() }
    pub fn send(_row: &str) -> Result<()> { unsupported() }
    pub fn clear_outgoing() -> Result<()> { Ok(()) }
    pub fn take_received() -> Result<Vec<String>> { Ok(Vec::new()) }
}

#[tauri::command]
pub fn nearby_status(state: State<'_, AppState>) -> Result<NearbyStatus> {
    state.require_auth()?;
    platform::status()
}

#[tauri::command]
pub fn nearby_start(state: State<'_, AppState>) -> Result<NearbyStatus> {
    state.require_auth()?;
    platform::start()
}

#[tauri::command]
pub fn nearby_stop(state: State<'_, AppState>) -> Result<NearbyStatus> {
    state.require_auth()?;
    platform::stop()
}

#[tauri::command]
pub fn nearby_request_permissions(state: State<'_, AppState>) -> Result<()> {
    state.require_auth()?;
    platform::request_permissions()
}

/// Offer one sealed envelope row to phones in range (and to any that connect later).
#[tauri::command]
pub fn nearby_send(state: State<'_, AppState>, row: serde_json::Value) -> Result<()> {
    state.require_auth()?;
    let raw = serde_json::to_string(&row).map_err(|e| QGuardError::InvalidInput(format!("row: {e}")))?;
    if accept_received(&raw).is_none() {
        return Err(QGuardError::InvalidInput("only a sealed envelope row of at most 32 KiB can be sent nearby".to_string()));
    }
    platform::send(&raw)
}

#[tauri::command]
pub fn nearby_clear_outgoing(state: State<'_, AppState>) -> Result<()> {
    state.require_auth()?;
    platform::clear_outgoing()
}

/// Rows handed over by phones in range since the last call, well-formed ones only.
#[tauri::command]
pub fn nearby_take_received(state: State<'_, AppState>) -> Result<Vec<serde_json::Value>> {
    state.require_auth()?;
    Ok(platform::take_received()?.iter().filter_map(|raw| accept_received(raw)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row() -> serde_json::Value {
        json!({
            "id": "e1", "conversation_id": "c1", "sender_user_id": "u1", "recipient_device_id": "d2",
            "ciphertext": "\\xdead", "nonce": "\\x00", "auth_tag": "\\x00", "aad": "\\x00",
        })
    }

    #[test]
    fn only_sealed_envelope_rows_are_accepted() {
        assert!(accept_received(&row().to_string()).is_some());
        let mut with_plaintext = row();
        with_plaintext["plaintext"] = json!("hi");
        assert!(accept_received(&with_plaintext.to_string()).is_none());
        let mut missing = row();
        missing.as_object_mut().unwrap().remove("aad");
        assert!(accept_received(&missing.to_string()).is_none());
        let mut empty = row();
        empty["ciphertext"] = json!("");
        assert!(accept_received(&empty.to_string()).is_none());
        assert!(accept_received("not json").is_none());
        assert!(accept_received("[1,2]").is_none());
    }

    #[test]
    fn oversized_payloads_are_dropped() {
        let mut big = row();
        big["ciphertext"] = json!("a".repeat(NEARBY_MAX_ROW_BYTES));
        assert!(accept_received(&big.to_string()).is_none());
    }

    #[test]
    fn desktop_reports_unsupported() {
        #[cfg(not(target_os = "android"))]
        assert_eq!(platform::status().unwrap(), NearbyStatus::unsupported());
    }

    #[test]
    fn status_parses_the_android_report() {
        let status = parse_status(r#"{"available":true,"permissions":true,"running":true,"peers":2}"#).unwrap();
        assert_eq!(status, NearbyStatus { supported: true, available: true, permissions_granted: true, running: true, peers: 2 });
    }
}
