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

    use base64::Engine;
    let mut parts = access_token.split('.');
    let header_segment = parts
        .next()
        .ok_or_else(|| QGuardError::Trust("Invalid Supabase JWT format".to_string()))?;
    let payload = parts
        .next()
        .ok_or_else(|| QGuardError::Trust("Invalid Supabase JWT format".to_string()))?;
    let signature = parts
        .next()
        .ok_or_else(|| QGuardError::Trust("Invalid Supabase JWT format".to_string()))?;
    if parts.next().is_some() {
        return Err(QGuardError::Trust("Invalid Supabase JWT format".to_string()));
    }

    // An unsigned token ("alg":"none", or a JWS with an empty signature) is the
    // classic way to hand a verifier claims it never checked. This app cannot
    // verify a GoTrue HS256 signature -- that key is server-side only -- so the
    // least it must do is refuse the shapes that advertise no signature at all,
    // and then hold every remaining claim to what a real Supabase access token
    // looks like. See SECURITY-HARDENING.md for why this is a local-integrity
    // control, not the authorization boundary: the real boundary is Postgres
    // RLS, which validates the signature on every request.
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_segment)
        .map_err(|_| QGuardError::Trust("Invalid Supabase JWT header".to_string()))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| QGuardError::Trust("Invalid Supabase JWT header JSON".to_string()))?;
    let alg = header.get("alg").and_then(|value| value.as_str()).unwrap_or("");
    if alg.is_empty() || alg.eq_ignore_ascii_case("none") {
        return Err(QGuardError::Trust(
            "Supabase JWT declares no signature algorithm".to_string(),
        ));
    }
    if signature.is_empty() {
        return Err(QGuardError::Trust("Supabase JWT carries no signature".to_string()));
    }

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| QGuardError::Trust("Invalid Supabase JWT payload".to_string()))?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|_| QGuardError::Trust("Invalid Supabase JWT JSON".to_string()))?;
    let subject = claims
        .get("sub")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| QGuardError::Trust("Supabase JWT missing subject".to_string()))?;
    if subject != expected_user_id {
        return Err(QGuardError::Trust(
            "Supabase JWT subject does not match session user".to_string(),
        ));
    }

    // GoTrue stamps aud = role = "authenticated" on every access token it mints
    // for a signed-in user. Anything else is a service key, a refresh token, or
    // something not issued for this purpose at all.
    if !claim_contains(claims.get("audience").or_else(|| claims.get("aud")), "authenticated") {
        return Err(QGuardError::Trust(
            "Supabase JWT audience is not an authenticated user token".to_string(),
        ));
    }
    let role = claims.get("role").and_then(|value| value.as_str()).unwrap_or("");
    if role != "authenticated" {
        return Err(QGuardError::Trust(format!(
            "Supabase JWT role is {:?}, not an authenticated user token",
            role
        )));
    }
    let issuer = claims.get("iss").and_then(|value| value.as_str()).unwrap_or("");
    if !is_plausible_auth_issuer(issuer) {
        return Err(QGuardError::Trust(
            "Supabase JWT issuer is not a Supabase auth endpoint".to_string(),
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

/// True when `claim` is the string `expected`, or an array containing it.
/// `aud` is legitimately either shape.
fn claim_contains(claim: Option<&serde_json::Value>, expected: &str) -> bool {
    match claim {
        Some(serde_json::Value::String(value)) => value == expected,
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

/// Deliberately shape-based rather than pinned to one project URL: self-hosted
/// GoTrue is a supported deployment and its issuer is whatever host it runs on.
/// This rejects the obviously-wrong (absent, relative, plain-HTTP remote) while
/// still allowing a local development stack.
fn is_plausible_auth_issuer(issuer: &str) -> bool {
    let issuer = issuer.trim();
    if issuer.is_empty() {
        return false;
    }
    issuer.starts_with("https://")
        || issuer.starts_with("http://localhost")
        || issuer.starts_with("http://127.0.0.1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn token(header: serde_json::Value, claims: serde_json::Value, signature: &str) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            engine.encode(header.to_string()),
            engine.encode(claims.to_string()),
            signature
        )
    }

    fn valid_claims(user_id: &str, exp: i64) -> serde_json::Value {
        serde_json::json!({
            "sub": user_id,
            "aud": "authenticated",
            "role": "authenticated",
            "iss": "https://project.supabase.co/auth/v1",
            "exp": exp,
        })
    }

    #[test]
    fn accepts_a_well_formed_supabase_access_token() {
        let exp = chrono::Utc::now().timestamp() + 3600;
        let jwt = token(
            serde_json::json!({ "alg": "HS256", "typ": "JWT" }),
            valid_claims("user-1", exp),
            "c2ln",
        );
        validate_token_claims(&jwt, "user-1", exp).unwrap();
    }

    #[test]
    fn refuses_an_unsigned_token() {
        let exp = chrono::Utc::now().timestamp() + 3600;
        let jwt = token(
            serde_json::json!({ "alg": "none", "typ": "JWT" }),
            valid_claims("user-1", exp),
            "",
        );
        let error = validate_token_claims(&jwt, "user-1", exp).unwrap_err();
        assert!(format!("{error:?}").contains("no signature algorithm"), "got {error:?}");
    }

    #[test]
    fn refuses_a_token_with_an_empty_signature_segment() {
        let exp = chrono::Utc::now().timestamp() + 3600;
        let jwt = token(
            serde_json::json!({ "alg": "HS256", "typ": "JWT" }),
            valid_claims("user-1", exp),
            "",
        );
        let error = validate_token_claims(&jwt, "user-1", exp).unwrap_err();
        assert!(format!("{error:?}").contains("carries no signature"), "got {error:?}");
    }

    #[test]
    fn refuses_a_non_user_role() {
        let exp = chrono::Utc::now().timestamp() + 3600;
        let mut claims = valid_claims("user-1", exp);
        claims["role"] = serde_json::json!("service_role");
        let jwt = token(serde_json::json!({ "alg": "HS256" }), claims, "c2ln");
        let error = validate_token_claims(&jwt, "user-1", exp).unwrap_err();
        assert!(format!("{error:?}").contains("not an authenticated user token"), "got {error:?}");
    }

    #[test]
    fn refuses_a_foreign_issuer() {
        let exp = chrono::Utc::now().timestamp() + 3600;
        let mut claims = valid_claims("user-1", exp);
        claims["iss"] = serde_json::json!("");
        let jwt = token(serde_json::json!({ "alg": "HS256" }), claims, "c2ln");
        let error = validate_token_claims(&jwt, "user-1", exp).unwrap_err();
        assert!(format!("{error:?}").contains("issuer"), "got {error:?}");
    }

    #[test]
    fn refuses_a_token_minted_for_a_different_user() {
        let exp = chrono::Utc::now().timestamp() + 3600;
        let jwt = token(
            serde_json::json!({ "alg": "HS256" }),
            valid_claims("someone-else", exp),
            "c2ln",
        );
        let error = validate_token_claims(&jwt, "user-1", exp).unwrap_err();
        assert!(format!("{error:?}").contains("does not match session user"), "got {error:?}");
    }

    #[test]
    fn accepts_an_array_audience() {
        let exp = chrono::Utc::now().timestamp() + 3600;
        let mut claims = valid_claims("user-1", exp);
        claims["aud"] = serde_json::json!(["authenticated", "qguard"]);
        let jwt = token(serde_json::json!({ "alg": "HS256" }), claims, "c2ln");
        validate_token_claims(&jwt, "user-1", exp).unwrap();
    }
}
