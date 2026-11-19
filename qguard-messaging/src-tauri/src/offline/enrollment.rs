//! Device-bound offline access for Mesh and XFER.
//!
//! An online-verified account session enrolls this device for a bounded
//! window. Without internet -- after a restart, or once the online token has
//! expired -- offline access needs local proof instead of a server:
//! - desktop: the account password, checked against a stretched verifier
//!   (Argon2id, or PBKDF2-HMAC-SHA-512 in FIPS approved mode) captured at the
//!   last online password sign-in, in the manner of OS cached sign-in;
//! - Android: the app-entry lock (PIN, pattern or biometric), already unlocked.
//!
//! The record is sealed under the account's device storage key, so it opens
//! only for this OS user on this device. Offline access authorizes only the
//! local offline module (Mesh, XFER and their local records). Online services
//! keep requiring a live, server-verified session.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{passcode, provider},
    error::{QGuardError, Result},
    state::AppState,
};

pub(super) const DOC: &str = "offline-enrollment";
const AAD: &[u8] = b"QGuard-Offline-Enrollment-v1";
const VERIFIER_INFO: &[u8] = b"QGuard-Offline-Sign-In-Verifier-v1";
/// How long a device stays enrolled after its last online verification.
pub(crate) const OFFLINE_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;
/// Failed offline password attempts before only an online sign-in can reset it.
pub(crate) const MAX_FAILED_ATTEMPTS: u32 = 5;
const MAX_ENTITLEMENT_BYTES: usize = 8 * 1024;
const MAX_EMAIL_BYTES: usize = 320;
const MAX_PASSWORD_BYTES: usize = 1024;
const CLOCK_SKEW_SECS: i64 = 5 * 60;

#[derive(Serialize, Deserialize)]
struct PasswordVerifier {
    kdf_version: u8,
    salt: String,
    verifier: String,
}

#[derive(Serialize, Deserialize)]
struct Enrollment {
    user_id: String,
    email: String,
    verified_at: i64,
    #[serde(default)]
    password: Option<PasswordVerifier>,
    #[serde(default)]
    failed_attempts: u32,
    /// The last subscription row seen while online, for the offline paywall
    /// verdict. It is UI state, as online: the server enforces billing.
    #[serde(default)]
    entitlement: Option<serde_json::Value>,
}

impl Enrollment {
    fn offline_until(&self) -> i64 {
        self.verified_at.saturating_add(OFFLINE_WINDOW_SECS)
    }

    /// Inside the window, and not stamped in the future (clock rollback).
    fn active(&self, now: i64) -> bool {
        now < self.offline_until() && self.verified_at <= now.saturating_add(CLOCK_SKEW_SECS)
    }

    fn session(&self) -> OfflineSession {
        OfflineSession {
            user_id: self.user_id.clone(),
            email: self.email.clone(),
            offline_until: self.offline_until(),
            entitlement: self.entitlement.clone(),
        }
    }
}

/// What an offline sign-in or resume authorizes, returned to the renderer.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OfflineSession {
    pub user_id: String,
    pub email: String,
    pub offline_until: i64,
    pub entitlement: Option<serde_json::Value>,
}

/// Offline readiness for the settings screen.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OfflineAccess {
    pub enrolled: bool,
    pub offline_until: Option<i64>,
    pub password_sign_in: bool,
}

pub(crate) fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn load(state: &AppState, user_id: &str) -> Result<Option<Enrollment>> {
    let Some(bytes) = state.load_user_secret_doc(user_id, DOC, AAD, DOC)? else {
        return Ok(None);
    };
    let enrollment: Enrollment = serde_json::from_slice(&bytes)
        .map_err(|_| QGuardError::Storage("The offline sign-in record is unreadable.".into()))?;
    if AppState::safe_user_key(&enrollment.user_id) != AppState::safe_user_key(user_id) {
        return Err(QGuardError::Storage("The offline sign-in record belongs to another account.".into()));
    }
    Ok(Some(enrollment))
}

fn save(state: &AppState, enrollment: &Enrollment) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(enrollment).map_err(|_| {
        QGuardError::Storage("The offline sign-in record could not be saved.".into())
    })?);
    state.save_user_secret_doc(&enrollment.user_id, DOC, AAD, &bytes, DOC)
}

/// Record a fresh online verification. Called only after the server confirmed
/// the account's current token; it also clears any failed offline attempts.
pub(crate) fn refresh(state: &AppState, user_id: &str, email: &str, now: i64) -> Result<()> {
    let email = normalize_email(email);
    // A record that no longer opens (for example after a device key reset)
    // holds nothing irreplaceable: online proof starts a fresh one.
    let mut enrollment = match load(state, user_id) {
        Ok(Some(enrollment)) => enrollment,
        _ => Enrollment {
            user_id: user_id.to_owned(),
            email: email.clone(),
            verified_at: now,
            password: None,
            failed_attempts: 0,
            entitlement: None,
        },
    };
    if !email.is_empty() && email.len() <= MAX_EMAIL_BYTES {
        enrollment.email = email;
    }
    enrollment.verified_at = now;
    enrollment.failed_attempts = 0;
    save(state, &enrollment)
}

fn verifier(kdf_version: u8, salt: &[u8], password: &[u8]) -> Result<String> {
    let mut ikm = passcode::secret_ikm(kdf_version, salt, password)?;
    let verifier = passcode::derive_verifier(salt, &ikm, VERIFIER_INFO);
    ikm.zeroize();
    verifier
}

/// Save a stretched verifier of the account password for offline sign-in.
/// The caller must have just completed an online password sign-in and an
/// online verification of this account.
pub(crate) fn set_password(state: &AppState, user_id: &str, password: &[u8]) -> Result<()> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err(QGuardError::InvalidInput("Invalid password.".into()));
    }
    let mut enrollment = load(state, user_id)?.ok_or_else(not_enrolled)?;
    let kdf_version = passcode::preferred_kdf();
    let salt = passcode::random_salt();
    let verifier = verifier(kdf_version, &salt, password)?;
    enrollment.password = Some(PasswordVerifier {
        kdf_version,
        salt: STANDARD.encode(&salt),
        verifier,
    });
    enrollment.failed_attempts = 0;
    save(state, &enrollment)
}

/// Keep the last online subscription row for the offline paywall verdict.
pub(crate) fn set_entitlement(state: &AppState, user_id: &str, value: Option<serde_json::Value>) -> Result<()> {
    if let Some(value) = &value {
        let size = serde_json::to_vec(value).map(|bytes| bytes.len()).unwrap_or(usize::MAX);
        if size > MAX_ENTITLEMENT_BYTES
            || value.get("user_id").and_then(serde_json::Value::as_str) != Some(user_id)
        {
            return Err(QGuardError::InvalidInput("Invalid subscription snapshot.".into()));
        }
    }
    let mut enrollment = load(state, user_id)?.ok_or_else(not_enrolled)?;
    if enrollment.entitlement == value {
        return Ok(());
    }
    enrollment.entitlement = value;
    save(state, &enrollment)
}

/// Accounts with an offline record on this device (file names carry the
/// account's storage key, which is the account ID for Supabase UUIDs).
fn enrolled_accounts(state: &AppState) -> Vec<String> {
    let suffix = format!(".{DOC}.enc");
    std::fs::read_dir(state.data_dir.join("keys"))
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
                .filter_map(|name| name.strip_suffix(&suffix).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Offline desktop sign-in with the account password. Runs the deliberately
/// slow verifier; call it off the async runtime.
pub(crate) fn sign_in(state: &AppState, email: &str, password: &[u8], now: i64) -> Result<OfflineSession> {
    let email = normalize_email(email);
    if email.is_empty() || email.len() > MAX_EMAIL_BYTES || password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err(QGuardError::InvalidInput("Enter your email address and password.".into()));
    }
    let mut enrollment = enrolled_accounts(state)
        .into_iter()
        .filter_map(|account| load(state, &account).ok().flatten())
        .find(|enrollment| enrollment.email == email)
        .ok_or_else(not_enrolled)?;
    if !enrollment.active(now) {
        return Err(expired());
    }
    if enrollment.failed_attempts >= MAX_FAILED_ATTEMPTS {
        return Err(locked());
    }
    let Some(stored) = &enrollment.password else {
        return Err(no_password());
    };
    let salt = STANDARD
        .decode(&stored.salt)
        .map_err(|_| QGuardError::Storage("The offline sign-in record is unreadable.".into()))?;
    let candidate = verifier(stored.kdf_version, &salt, password)?;
    if !provider::constant_time_eq(candidate.as_bytes(), stored.verifier.as_bytes()) {
        enrollment.failed_attempts = enrollment.failed_attempts.saturating_add(1);
        save(state, &enrollment)?;
        let left = MAX_FAILED_ATTEMPTS.saturating_sub(enrollment.failed_attempts);
        return Err(if left == 0 {
            locked()
        } else {
            QGuardError::Trust(format!(
                "The password is incorrect. {left} offline {} left before an online sign-in is required.",
                if left == 1 { "attempt" } else { "attempts" }
            ))
        });
    }
    if enrollment.failed_attempts != 0 {
        enrollment.failed_attempts = 0;
        save(state, &enrollment)?;
    }
    Ok(enrollment.session())
}

/// Offline resume after a local unlock the caller has already proven (the
/// Android app-entry lock for this account).
pub(crate) fn resume(state: &AppState, user_id: &str, unlocked: bool, now: i64) -> Result<OfflineSession> {
    if !unlocked {
        return Err(QGuardError::Trust(
            "Unlock Qguard on this device to use Mesh and XFER offline.".into(),
        ));
    }
    let enrollment = load(state, user_id)?.ok_or_else(not_enrolled)?;
    if !enrollment.active(now) {
        return Err(expired());
    }
    Ok(enrollment.session())
}

pub(crate) fn access(state: &AppState, user_id: &str, now: i64) -> OfflineAccess {
    match load(state, user_id) {
        Ok(Some(enrollment)) if enrollment.active(now) => OfflineAccess {
            enrolled: true,
            offline_until: Some(enrollment.offline_until()),
            password_sign_in: enrollment.password.is_some()
                && enrollment.failed_attempts < MAX_FAILED_ATTEMPTS,
        },
        _ => OfflineAccess::default(),
    }
}

pub(crate) fn remove(state: &AppState, user_id: &str) {
    state.delete_user_secret_doc(user_id, DOC);
}

fn not_enrolled() -> QGuardError {
    QGuardError::NotFound(
        "Offline sign-in is not set up for this account on this device. Sign in once while online to enable it.".into(),
    )
}

fn expired() -> QGuardError {
    QGuardError::Trust(
        "Offline access on this device expired. Connect to the internet and sign in to renew it.".into(),
    )
}

fn locked() -> QGuardError {
    QGuardError::Trust(
        "Too many incorrect offline sign-in attempts. Connect to the internet and sign in to unlock offline access.".into(),
    )
}

fn no_password() -> QGuardError {
    QGuardError::Trust(
        "Offline sign-in needs a password sign-in while online on this device first.".into(),
    )
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;

    struct Device {
        state: AppState,
        dir: std::path::PathBuf,
        users: Vec<String>,
    }

    impl Device {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("qguard-offline-enrollment-{}", uuid::Uuid::new_v4()));
            Self { state: AppState::new(dir.clone()).unwrap(), dir, users: Vec::new() }
        }

        fn user(&mut self) -> String {
            let user = uuid::Uuid::new_v4().to_string();
            self.users.push(user.clone());
            user
        }
    }

    impl Drop for Device {
        fn drop(&mut self) {
            for user in &self.users {
                let _ = crate::security::keystore::delete_secret(&AppState::safe_user_key(user), &self.dir);
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn offline_password_sign_in_needs_an_online_enrollment_and_the_right_password() {
        let mut device = Device::new();
        let user = device.user();
        let now = 1_800_000_000;
        assert!(matches!(sign_in(&device.state, "Person@Example.test", b"pw", now), Err(QGuardError::NotFound(_))));
        assert!(set_password(&device.state, &user, b"correct horse").is_err(), "no password before an online enrollment");

        refresh(&device.state, &user, " Person@Example.TEST ", now).unwrap();
        // Enrolled for Android-style resume, but no password verifier yet.
        assert!(sign_in(&device.state, "person@example.test", b"correct horse", now).is_err());
        set_password(&device.state, &user, b"correct horse").unwrap();

        let session = sign_in(&device.state, "PERSON@example.test", b"correct horse", now + 60).unwrap();
        assert_eq!(session.user_id, user);
        assert_eq!(session.offline_until, now + OFFLINE_WINDOW_SECS);
        let access_now = access(&device.state, &user, now);
        assert!(access_now.enrolled && access_now.password_sign_in);

        // The sealed record never holds the password itself.
        let sealed = std::fs::read(device.dir.join("keys").join(format!("{user}.{DOC}.enc"))).unwrap();
        assert!(!sealed.windows(b"correct horse".len()).any(|window| window == b"correct horse"));
    }

    #[test]
    fn wrong_passwords_lock_offline_sign_in_until_an_online_verification() {
        let mut device = Device::new();
        let user = device.user();
        let now = 1_800_000_000;
        refresh(&device.state, &user, "person@example.test", now).unwrap();
        set_password(&device.state, &user, b"correct horse").unwrap();
        for attempt in 1..MAX_FAILED_ATTEMPTS {
            let error = sign_in(&device.state, "person@example.test", b"wrong", now).unwrap_err().to_string();
            assert!(error.contains(&format!("{} offline", MAX_FAILED_ATTEMPTS - attempt)), "{error}");
        }
        assert!(sign_in(&device.state, "person@example.test", b"wrong", now).unwrap_err().to_string().contains("Too many"));
        // Even the right password is refused once locked; a restart does not help.
        let restarted = AppState::new(device.dir.clone()).unwrap();
        assert!(sign_in(&restarted, "person@example.test", b"correct horse", now).is_err());
        assert!(!access(&restarted, &user, now).password_sign_in);
        // A fresh online verification clears the lock.
        refresh(&restarted, &user, "person@example.test", now + 10).unwrap();
        assert!(sign_in(&restarted, "person@example.test", b"correct horse", now + 20).is_ok());
    }

    #[test]
    fn offline_access_expires_and_resists_clock_rollback() {
        let mut device = Device::new();
        let user = device.user();
        let now = 1_800_000_000;
        refresh(&device.state, &user, "person@example.test", now).unwrap();
        set_password(&device.state, &user, b"correct horse").unwrap();
        assert!(resume(&device.state, &user, true, now + OFFLINE_WINDOW_SECS - 1).is_ok());
        assert!(resume(&device.state, &user, true, now + OFFLINE_WINDOW_SECS).is_err());
        assert!(sign_in(&device.state, "person@example.test", b"correct horse", now + OFFLINE_WINDOW_SECS).is_err());
        // A clock set far back cannot reuse a record stamped in its future.
        assert!(resume(&device.state, &user, true, now - CLOCK_SKEW_SECS - 1).is_err());
        // Resume always needs the local unlock.
        assert!(resume(&device.state, &user, false, now).is_err());
        assert!(!access(&device.state, &user, now + OFFLINE_WINDOW_SECS).enrolled);
    }

    #[test]
    fn records_are_per_account_and_entitlements_must_match_the_account() {
        let mut device = Device::new();
        let alice = device.user();
        let bob = device.user();
        let now = 1_800_000_000;
        refresh(&device.state, &alice, "alice@example.test", now).unwrap();
        refresh(&device.state, &bob, "bob@example.test", now).unwrap();
        set_password(&device.state, &alice, b"alice password").unwrap();
        set_password(&device.state, &bob, b"bob password").unwrap();
        assert!(sign_in(&device.state, "alice@example.test", b"bob password", now).is_err());
        assert_eq!(sign_in(&device.state, "bob@example.test", b"bob password", now).unwrap().user_id, bob);

        let row = serde_json::json!({ "user_id": alice, "status": "active", "plan": "pro" });
        assert!(set_entitlement(&device.state, &bob, Some(row.clone())).is_err());
        set_entitlement(&device.state, &alice, Some(row.clone())).unwrap();
        assert_eq!(resume(&device.state, &alice, true, now).unwrap().entitlement, Some(row));
        assert!(resume(&device.state, &bob, true, now).unwrap().entitlement.is_none());

        remove(&device.state, &alice);
        assert!(resume(&device.state, &alice, true, now).is_err());
        assert!(sign_in(&device.state, "bob@example.test", b"bob password", now).is_ok());
    }
}
