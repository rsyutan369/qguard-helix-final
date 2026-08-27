use serde::Serialize;
use tauri::State;

use crate::error::{QGuardError, Result};
use crate::identity::{PublicIdentityBundle, platform_device_label};
use crate::state::{AppState, AuthSession};

#[derive(Clone, Debug, Serialize)]
pub struct AuthResponse {
    pub user_id: String,
    pub email: String,
    pub identity_bundle: PublicIdentityBundle,
    pub zero_knowledge: bool,
}

#[tauri::command]
pub fn auth_logout(state: State<'_, AppState>, user_id: Option<String>) -> Result<bool> {
    // Zeroize unlocked workspace secrets (VMK + decrypted chat) before clearing auth.
    state.lock_all_workspaces();
    state.clear_auth_session_for(user_id.as_deref())?;
    state.audit_info("auth_logout", "Session cleared from desktop state");
    state.touch_telemetry(
        "auth",
        "Session logged out and volatile auth state cleared",
        100,
    );
    Ok(true)
}

#[tauri::command]
pub fn auth_sync_session(
    state: State<'_, AppState>,
    user_id: String,
    email: String,
    tier: String,
    access_token: String,
    expires_at: i64,
    fresh_login: Option<bool>,
) -> Result<AuthResponse> {
    validate_token_claims(&access_token, &user_id, expires_at)?;
    state.set_auth_session(AuthSession {
        user_id: user_id.clone(),
        email: email.clone(),
        tier: tier.clone(),
        access_token,
        expires_at,
    })?;
    let _key_scope = state.lock_key_scope()?;
    let identity_bundle = state.ensure_identity(&user_id, platform_device_label())?;
    // A fresh interactive sign-in (password + optional MFA, NOT a background
    // token refresh) re-proves account ownership, which is the documented way
    // out of a workspace brute-force lockdown ("sign out and back in to
    // reset"). It also starts the protected workspaces locked. Token refreshes
    // pass fresh_login=false so an active lockdown cannot be waited out and an
    // unlocked workspace never re-locks mid-session.
    if fresh_login.unwrap_or(false) {
        state.reset_workspace_lockouts(&user_id);
        state.lock_all_workspaces();
    }
    state.audit_info(
        "auth_sync",
        &format!("Supabase session synchronized with tier {tier}"),
    );
    Ok(AuthResponse {
        user_id,
        email,
        identity_bundle,
        zero_knowledge: true,
    })
}

fn validate_token_claims(
    access_token: &str,
    expected_user_id: &str,
    expires_at: i64,
) -> Result<()> {
    if access_token.trim().is_empty() {
        return Err(QGuardError::Trust(
            "Supabase access token is required".to_string(),
        ));
    }
    if expires_at <= chrono::Utc::now().timestamp() {
        return Err(QGuardError::Trust(
            "Supabase access token is expired".to_string(),
        ));
    }

    let payload = access_token
        .split('.')
        .nth(1)
        .ok_or_else(|| QGuardError::Trust("Invalid Supabase JWT format".to_string()))?;
    use base64::Engine;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| QGuardError::Trust("Invalid Supabase JWT payload".to_string()))?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|_| QGuardError::Trust("Invalid Supabase JWT JSON".to_string()))?;
    let subject = claims
        .get("sub")
        .and_then(|value| value.as_str())
        .ok_or_else(|| QGuardError::Trust("Supabase JWT missing subject".to_string()))?;
    if subject != expected_user_id {
        return Err(QGuardError::Trust(
            "Supabase JWT subject does not match session user".to_string(),
        ));
    }
    let jwt_exp = claims
        .get("exp")
        .and_then(|value| value.as_i64())
        .unwrap_or(expires_at);
    if jwt_exp <= chrono::Utc::now().timestamp() {
        return Err(QGuardError::Trust("Supabase JWT has expired".to_string()));
    }
    Ok(())
}
