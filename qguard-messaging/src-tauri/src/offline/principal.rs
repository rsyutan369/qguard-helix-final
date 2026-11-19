//! Local network records have no Supabase RLS check. Verify the active JWT
//! at the project's Auth service before letting it authorize local records.
//! The device can use that verification while the same JWT remains valid.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use serde::Deserialize;

use crate::{
    crypto::provider,
    error::{QGuardError, Result},
    state::{AppState, AuthSession},
};

const MAX_AUTH_RESPONSE: usize = 64 * 1024;

#[derive(Default)]
pub(crate) struct Principal {
    grant: Mutex<Option<Grant>>,
    /// Device-bound offline access (see offline::enrollment). It authorizes
    /// only the offline module, never online services.
    offline: Mutex<Option<OfflineGrant>>,
    verification: tokio::sync::Mutex<()>,
}

struct Grant {
    owner: String,
    token_digest: [u8; 32],
    expires_at: i64,
}

struct OfflineGrant {
    owner: String,
    expires_at: i64,
}

impl Grant {
    fn matches(&self, session: &AuthSession, now: i64) -> bool {
        self.expires_at > now
            && session.expires_at > now
            && self.owner == session.user_id
            && provider::constant_time_eq(&self.token_digest, &token_digest(session))
    }
}

impl Principal {
    pub(crate) fn clear(&self) {
        if let Ok(mut grant) = self.grant.lock() {
            *grant = None;
        }
        if let Ok(mut offline) = self.offline.lock() {
            *offline = None;
        }
    }

    /// The account allowed to use the offline module: the online-verified
    /// session, or else a device-bound offline grant for the same account.
    pub(crate) fn owner(&self, state: &AppState) -> Result<String> {
        if let Ok(owner) = self.online_owner(state) {
            return Ok(owner);
        }
        let now = Utc::now().timestamp();
        let offline = self.offline.lock().map_err(|_| verification_required())?;
        let Some(grant) = offline.as_ref().filter(|grant| grant.expires_at > now) else {
            return Err(verification_required());
        };
        // An offline grant never acts for an account other than the one the
        // app is signed in to (signed in online, or no online session at all).
        if state
            .current_auth_user()
            .is_some_and(|user| user != grant.owner)
        {
            return Err(verification_required());
        }
        Ok(grant.owner.clone())
    }

    /// The account of a live, server-verified session only.
    pub(crate) fn online_owner(&self, state: &AppState) -> Result<String> {
        let session = state.require_auth().map_err(|_| verification_required())?;
        let grant = self.grant.lock().map_err(|_| verification_required())?;
        if grant
            .as_ref()
            .is_some_and(|grant| grant.matches(&session, Utc::now().timestamp()))
        {
            Ok(session.user_id)
        } else {
            Err(verification_required())
        }
    }

    /// Activate offline access after local proof (enrollment::sign_in/resume).
    pub(crate) fn set_offline(&self, session: &super::enrollment::OfflineSession) {
        if let Ok(mut offline) = self.offline.lock() {
            *offline = Some(OfflineGrant {
                owner: session.user_id.clone(),
                expires_at: session.offline_until,
            });
        }
    }

    /// Leave offline mode. The online grant, if any, is unaffected.
    pub(crate) fn clear_offline(&self) {
        if let Ok(mut offline) = self.offline.lock() {
            *offline = None;
        }
    }

    pub(crate) fn renewing(&self, state: &AppState, owner: &str) -> bool {
        let Ok(session) = state.require_auth() else {
            return false;
        };
        if session.user_id != owner {
            return false;
        }
        let now = Utc::now().timestamp();
        self.grant.lock().is_ok_and(|grant| {
            grant.as_ref().is_some_and(|grant| {
                grant.owner == owner && grant.expires_at > now && !grant.matches(&session, now)
            })
        })
    }

    pub(crate) async fn verify(&self, state: &AppState) -> Result<()> {
        let _verification = self.verification.lock().await;
        // An offline grant is not online proof: always verify a new token.
        if self.online_owner(state).is_ok() {
            return Ok(());
        }
        let session = state.require_auth().map_err(|_| verification_required())?;
        #[cfg(target_os = "android")]
        if !state.is_applock_unlocked()
            || state.load_applock_user_pointer().as_deref() != Some(session.user_id.as_str())
        {
            return Err(QGuardError::Trust(
                "Unlock Qguard on this device before verifying your local account.".into(),
            ));
        }
        let expires_at = session.expires_at.min(jwt_expiry(&session.access_token)?);
        let endpoint = auth_endpoint(env!("QGUARD_BUNDLED_AUTH_URL"))?;
        let api_key = env!("QGUARD_BUNDLED_AUTH_PUBLIC_KEY");
        if !public_api_key(api_key) {
            return Err(config_error());
        }
        let mut response = client()?
            .get(endpoint)
            .header("apikey", api_key)
            .bearer_auth(&session.access_token)
            .send()
            .await
            .map_err(|_| verification_required())?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|len| len > MAX_AUTH_RESPONSE as u64)
        {
            return Err(verification_required());
        }
        let mut body = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| verification_required())?
        {
            if body.len() + chunk.len() > MAX_AUTH_RESPONSE {
                return Err(verification_required());
            }
            body.extend_from_slice(&chunk);
        }
        let user: AuthUser = serde_json::from_slice(&body).map_err(|_| verification_required())?;
        if user.id != session.user_id || uuid::Uuid::parse_str(&user.id).is_err() {
            return Err(verification_required());
        }
        let grant = Grant {
            owner: session.user_id.clone(),
            token_digest: token_digest(&session),
            expires_at,
        };
        let mut current = self.grant.lock().map_err(|_| verification_required())?;
        if !grant.matches(
            &state.require_auth().map_err(|_| verification_required())?,
            Utc::now().timestamp(),
        ) {
            return Err(verification_required());
        }
        *current = Some(grant);
        drop(current);
        // A server-verified session enrolls (or renews) this device for
        // offline access and keeps it available in this process should the
        // token expire while there is no internet. A failure here must not
        // affect any online feature.
        let now = Utc::now().timestamp();
        if super::enrollment::refresh(state, &session.user_id, &session.email, now).is_ok() {
            if let Ok(mut offline) = self.offline.lock() {
                *offline = Some(OfflineGrant {
                    owner: session.user_id.clone(),
                    expires_at: now.saturating_add(super::enrollment::OFFLINE_WINDOW_SECS),
                });
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct AuthUser {
    id: String,
}

#[derive(Deserialize)]
struct TokenExpiry {
    exp: i64,
}

fn token_digest(session: &AuthSession) -> [u8; 32] {
    provider::sha3_256(session.access_token.as_bytes())
}

fn jwt_expiry(token: &str) -> Result<i64> {
    let payload = token
        .split('.')
        .nth(1)
        .filter(|value| value.len() < 32 * 1024)
        .ok_or_else(verification_required)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| verification_required())?;
    let claims: TokenExpiry =
        serde_json::from_slice(&payload).map_err(|_| verification_required())?;
    Ok(claims.exp)
}

fn public_api_key(value: &str) -> bool {
    if value.starts_with("sb_publishable_") {
        return true;
    }
    let Some(claims) = value
        .split('.')
        .nth(1)
        .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
    else {
        return false;
    };
    serde_json::from_slice::<serde_json::Value>(&claims)
        .ok()
        .and_then(|claims| {
            claims
                .get("role")
                .and_then(|role| role.as_str())
                .map(str::to_string)
        })
        .is_some_and(|role| role == "anon")
}

fn auth_endpoint(configured: &str) -> Result<url::Url> {
    let url = url::Url::parse(configured).map_err(|_| config_error())?;
    let valid_project = url
        .host_str()
        .and_then(|host| host.strip_suffix(".supabase.co"))
        .is_some_and(|project| {
            !project.is_empty()
                && project
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
    if !valid_project
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(config_error());
    }
    url.join("auth/v1/user").map_err(|_| config_error())
}

fn client() -> Result<reqwest::Client> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| config_error())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| config_error())
}

fn verification_required() -> QGuardError {
    QGuardError::Trust("OFFLINE_PRINCIPAL_UNVERIFIED: Verify your account online before opening local networking and transfers.".into())
}

fn config_error() -> QGuardError {
    QGuardError::Trust("This build is missing a supported, pinned Supabase Auth configuration for local networking.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_grant_is_bound_to_the_verified_token_account_and_expiry() {
        let mut session = AuthSession {
            user_id: "account-a".into(),
            email: String::new(),
            tier: "pro".into(),
            access_token: "verified-token".into(),
            expires_at: 300,
        };
        let grant = Grant {
            owner: session.user_id.clone(),
            token_digest: token_digest(&session),
            expires_at: 200,
        };
        assert!(grant.matches(&session, 199));
        assert!(!grant.matches(&session, 200));
        session.user_id = "account-b".into();
        assert!(!grant.matches(&session, 199));
        session.user_id = grant.owner.clone();
        session.access_token = "different-token".into();
        assert!(!grant.matches(&session, 199));
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn offline_grant_serves_only_its_account_and_never_counts_as_online_proof() {
        let dir = std::env::temp_dir().join(format!("qguard-principal-{}", uuid::Uuid::new_v4()));
        let state = AppState::new(dir.clone()).unwrap();
        let principal = Principal::default();
        let now = Utc::now().timestamp();
        let session = |owner: &str, expires_at: i64| super::super::enrollment::OfflineSession {
            user_id: owner.into(),
            email: String::new(),
            offline_until: expires_at,
            entitlement: None,
        };
        assert!(principal.owner(&state).is_err());

        // No online session at all (offline sign-in): the grant's account.
        principal.set_offline(&session("account-a", now + 600));
        assert_eq!(principal.owner(&state).unwrap(), "account-a");
        assert!(principal.online_owner(&state).is_err(), "offline access is not online proof");

        // A different account signed in online: the offline grant is refused.
        state
            .set_auth_session(AuthSession {
                user_id: "account-b".into(),
                email: String::new(),
                tier: "pro".into(),
                access_token: "token".into(),
                expires_at: now + 600,
            })
            .unwrap();
        assert!(principal.owner(&state).is_err());

        // The same account with an expired online token keeps offline access.
        state
            .set_auth_session(AuthSession {
                user_id: "account-a".into(),
                email: String::new(),
                tier: "pro".into(),
                access_token: "expired".into(),
                expires_at: now - 1,
            })
            .unwrap();
        assert_eq!(principal.owner(&state).unwrap(), "account-a");

        principal.set_offline(&session("account-a", now - 1));
        assert!(principal.owner(&state).is_err(), "an expired offline grant does nothing");
        principal.set_offline(&session("account-a", now + 600));
        principal.clear_offline();
        assert!(principal.owner(&state).is_err(), "leaving offline mode ends offline access");
        principal.set_offline(&session("account-a", now + 600));
        principal.clear();
        assert!(principal.owner(&state).is_err(), "sign-out clears offline access");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn leaving_offline_mode_keeps_an_online_grant() {
        let dir = std::env::temp_dir().join(format!("qguard-principal-{}", uuid::Uuid::new_v4()));
        let state = AppState::new(dir.clone()).unwrap();
        let principal = Principal::default();
        let now = Utc::now().timestamp();
        let online = AuthSession {
            user_id: "account-a".into(),
            email: String::new(),
            tier: "pro".into(),
            access_token: "online-token".into(),
            expires_at: now + 600,
        };
        state.set_auth_session(online.clone()).unwrap();
        *principal.grant.lock().unwrap() = Some(Grant {
            owner: online.user_id.clone(),
            token_digest: token_digest(&online),
            expires_at: now + 600,
        });
        principal.set_offline(&super::super::enrollment::OfflineSession {
            user_id: "account-a".into(),
            email: String::new(),
            offline_until: now + 600,
            entitlement: None,
        });
        principal.clear_offline();
        assert_eq!(principal.online_owner(&state).unwrap(), "account-a");
        assert_eq!(principal.owner(&state).unwrap(), "account-a");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn auth_target_is_an_https_supabase_project_without_redirectable_components() {
        let trusted = auth_endpoint("https://project123.supabase.co").unwrap();
        assert_eq!(
            trusted.as_str(),
            "https://project123.supabase.co/auth/v1/user"
        );
        for url in [
            "http://project.supabase.co",
            "https://project.supabase.co.evil.test",
            "https://nested.project.supabase.co",
            "https://user@project.supabase.co",
            "https://project.supabase.co:123",
            "https://project.supabase.co/other",
        ] {
            assert!(auth_endpoint(url).is_err(), "{url}");
        }
        assert!(!public_api_key("sb_secret_123"));
        assert!(public_api_key("sb_publishable_123"));
    }
}
