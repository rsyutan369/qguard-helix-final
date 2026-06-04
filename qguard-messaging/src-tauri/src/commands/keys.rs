use serde::Serialize;
use tauri::State;

use crate::crypto::AlgorithmSuite;
use crate::error::{QGuardError, Result};
use crate::identity::PublicIdentityBundle;
use crate::prekeys::{PublicOneTimePrekey, PublicSignedPrekey};
use crate::state::AppState;

#[derive(Clone, Debug, Serialize)]
pub struct RecipientKeyBundle {
    pub identity: PublicIdentityBundle,
    pub signed_prekey: PublicSignedPrekey,
    pub one_time_prekey: Option<PublicOneTimePrekey>,
    pub suite: AlgorithmSuite,
}

#[derive(Clone, Debug, Serialize)]
pub struct PrivateKeyUnlockStatus {
    pub unlocked: bool,
    pub device_id: String,
    pub fingerprint: String,
    pub storage: String,
    pub suite: AlgorithmSuite,
    pub private_key_exported: bool,
}

#[tauri::command]
pub fn keys_unlock_private_key(state: State<'_, AppState>) -> Result<PrivateKeyUnlockStatus> {
    let session_user_id = state.user_id()?;
    state.check_decrypt_rate_limit("key_unlock", &session_user_id, 12, 300)?;
    let identity = state.ensure_identity(&session_user_id, "Windows Desktop")?;
    state.audit_info(
        "keys_unlock_private_key",
        "Device-bound private key unlocked locally for decryption",
    );
    state.touch_telemetry(
        "key",
        "Device-bound private key unlocked; no private key bytes exported",
        100,
    );
    Ok(PrivateKeyUnlockStatus {
        unlocked: true,
        device_id: identity.device_id,
        fingerprint: identity.fingerprint,
        storage: "OS keychain / device-bound secure storage".to_string(),
        suite: identity.suite,
        private_key_exported: false,
    })
}

#[tauri::command]
pub fn keys_upload_identity_bundle(state: State<'_, AppState>) -> Result<PublicIdentityBundle> {
    let bundle = state.ensure_identity(&state.user_id()?, "Windows Desktop")?;
    state.audit_info(
        "keys_upload_identity",
        "Public identity bundle prepared for Supabase relay",
    );
    Ok(bundle)
}

#[tauri::command]
pub fn keys_upload_signed_prekey(state: State<'_, AppState>) -> Result<PublicSignedPrekey> {
    state.ensure_identity(&state.user_id()?, "Windows Desktop")?;
    let prekey = state
        .signed_prekey
        .lock()
        .map_err(|_| QGuardError::Storage("signed prekey lock poisoned".to_string()))?
        .as_ref()
        .map(|p| p.public.clone())
        .ok_or_else(|| QGuardError::NotFound("signed prekey".to_string()))?;
    Ok(prekey)
}

#[tauri::command]
pub fn keys_upload_one_time_prekeys(
    state: State<'_, AppState>,
) -> Result<Vec<PublicOneTimePrekey>> {
    state.ensure_identity(&state.user_id()?, "Windows Desktop")?;
    let prekeys = state
        .one_time_prekeys
        .lock()
        .map_err(|_| QGuardError::Storage("one-time prekey lock poisoned".to_string()))?
        .iter()
        .map(|p| p.public.clone())
        .collect();
    Ok(prekeys)
}

#[tauri::command]
pub fn keys_fetch_recipient_bundle(
    state: State<'_, AppState>,
    _recipient_user_id: String,
) -> Result<RecipientKeyBundle> {
    let identity = state.ensure_identity(&state.user_id()?, "Windows Desktop")?;
    let signed_prekey = state
        .signed_prekey
        .lock()
        .map_err(|_| QGuardError::Storage("signed prekey lock poisoned".to_string()))?
        .as_ref()
        .map(|p| p.public.clone())
        .ok_or_else(|| QGuardError::NotFound("signed prekey".to_string()))?;
    let one_time_prekey = state
        .one_time_prekeys
        .lock()
        .map_err(|_| QGuardError::Storage("one-time prekey lock poisoned".to_string()))?
        .first()
        .map(|p| p.public.clone());
    Ok(RecipientKeyBundle {
        identity,
        signed_prekey,
        one_time_prekey,
        suite: AlgorithmSuite::default(),
    })
}

#[tauri::command]
pub fn keys_rotate_prekeys(state: State<'_, AppState>) -> Result<PublicSignedPrekey> {
    let session_user_id = state.user_id()?;
    state.check_decrypt_rate_limit("key_rotate", &session_user_id, 6, 300)?;
    state.ensure_identity(&session_user_id, "Windows Desktop")?;

    let identity = {
        let identity_guard = state
            .identity
            .lock()
            .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
        identity_guard
            .as_ref()
            .filter(|identity| identity.user_id == session_user_id)
            .cloned()
    };
    let identity = match identity {
        Some(identity) => identity,
        None => {
            state.ensure_identity(&session_user_id, "Windows Desktop")?;
            state
                .identity
                .lock()
                .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?
                .as_ref()
                .cloned()
                .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?
        }
    };

    let signed = crate::prekeys::generate_signed_prekey(&identity)?;
    let public = signed.public.clone();
    state
        .signed_prekey
        .lock()
        .map_err(|_| QGuardError::Storage("signed prekey lock poisoned".to_string()))?
        .replace(signed);
    state.persist_current_device_key_material()?;
    state.audit_info("keys_rotate_prekeys", "Signed prekey rotated");
    state.touch_telemetry("key", "Signed prekey rotated and persisted locally", 100);
    Ok(public)
}

#[tauri::command]
pub fn keys_revoke_device(state: State<'_, AppState>, device_id: String) -> Result<bool> {
    crate::commands::devices::devices_revoke(state, device_id)
}
