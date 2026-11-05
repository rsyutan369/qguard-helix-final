//! Banking-grade app-entry PIN (Android). Sign in once with email/password,
//! then unlock the app with a 4/6-digit PIN which restores the locally stored
//! Supabase session. The session is encrypted under a random SEK; the SEK is
//! wrapped under a PIN-derived key (Argon2id, or PBKDF2-HMAC-SHA-512 in FIPS
//! approved mode, -> HKDF-SHA3-256); the whole config is encrypted at rest
//! under the hardware-backed device DEK.
//!
//! Anti-brute-force: 3rd fail -> 5s, 4th -> 15s, 5th fail -> wipe the stored
//! session and require full email/password login.

use chrono::Utc;
use serde::Serialize;
use tauri::State;
use zeroize::Zeroize;

use crate::crypto::passcode;
#[cfg(test)]
use crate::crypto::passcode::KDF_ARGON2ID_V1;
use crate::crypto::symmetric::{self, KEY_SIZE};
use crate::crypto::EncryptedEnvelope;
use crate::error::{QGuardError, Result};
use crate::security::device_privacy::{self, BiometricAvailability, BiometricFailure};
use crate::state::{AppState, DeviceRegistration, DuressPin, PersistedAppLock, StoredSession};

/// Domain separation for the duress PIN's verifier: never the same value the
/// real PIN's verifier context would produce.
const DURESS_VERIFIER_INFO: &[u8] = b"QGuard-AppLock-Duress-Verifier-v1";

const MAX_ATTEMPTS: u32 = 5;
const DEFAULT_INACTIVITY_MINUTES: u32 = 10;
const MIN_INACTIVITY_MINUTES: u32 = 1;
const MAX_INACTIVITY_MINUTES: u32 = 60;

/// Length every NEW app PIN must have.
///
/// Four digits used to be offered as well. The PIN is the only thing between
/// someone holding the unlocked phone and the stored session, and it derives
/// the key that wraps it: 10,000 possibilities against five tries is a 1-in-
/// 2,000 guess, and gives the Argon2id stretch nothing to work with. A
/// four-digit PIN that already exists still unlocks (that path does not come
/// through here); it just cannot be chosen again.
const NEW_PIN_DIGITS: u8 = 6;

/// Validate a PIN that is being SET (first setup, change, or reset).
fn validate_pin(digits: u8, pin: &str) -> Result<()> {
    if digits != NEW_PIN_DIGITS {
        return Err(QGuardError::InvalidInput(format!(
            "A new PIN must be {NEW_PIN_DIGITS} digits."
        )));
    }
    if pin.chars().count() != digits as usize || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err(QGuardError::InvalidInput(format!("PIN must be exactly {digits} digits.")));
    }
    Ok(())
}

fn clamp_inactivity(minutes: u32) -> u32 {
    minutes.clamp(MIN_INACTIVITY_MINUTES, MAX_INACTIVITY_MINUTES)
}

/// Delay (seconds) enforced *before* the next attempt after `failed_attempts`
/// failures. 0 = no delay. 5th failure never returns a delay — the caller wipes.
fn lockout_delay_secs(failed_attempts: u32) -> i64 {
    match failed_attempts {
        3 => 5,
        4 => 15,
        _ => 0,
    }
}

/// Records a failed PIN attempt on `record`: increments the counter and sets
/// the lockout delay (3rd->5s, 4th->15s). Returns true when the 5th failure is
/// reached, meaning the CALLER must wipe the stored session (delete_applock).
///
/// This is the single source of truth for the anti-brute-force ladder so every
/// PIN-guessing surface (`applock_unlock`, `applock_change_pin`) enforces the
/// same max-5-attempts contract — a caller that only incremented the counter
/// without also applying the delay/wipe ladder would leave an unthrottled PIN
/// oracle on that surface.
fn apply_failed_attempt(record: &mut PersistedAppLock) -> bool {
    record.failed_attempts += 1;
    if record.failed_attempts >= MAX_ATTEMPTS {
        return true;
    }
    let delay = lockout_delay_secs(record.failed_attempts);
    if delay > 0 {
        record.lockout_until = Some(Utc::now() + chrono::Duration::seconds(delay));
    }
    false
}

fn attempts_remaining(failed_attempts: u32) -> u32 {
    MAX_ATTEMPTS.saturating_sub(failed_attempts)
}

/// Build the PIN-derived verifier + the SEK wrapped under the PIN key, with the
/// device's current KDF. Returns (salt, verifier, sek_wrapped_by_pin, kdf).
async fn seal_pin(
    pin: &str,
    sek: &[u8; KEY_SIZE],
) -> Result<(Vec<u8>, String, EncryptedEnvelope, u8)> {
    let salt = passcode::random_salt();
    let kdf = passcode::preferred_kdf();
    let mut ikm = passcode::stretch_secret(kdf, salt.clone(), pin.as_bytes().to_vec()).await?;
    let verifier = passcode::derive_verifier(&salt, &ikm, &crate::security::obf::applock_verifier_info());
    let verifier = match verifier {
        Ok(v) => v,
        Err(e) => {
            ikm.zeroize();
            return Err(e);
        }
    };
    let wrap_key = passcode::derive_wrap_key(&salt, &ikm, &crate::security::obf::applock_sek_wrap_info());
    ikm.zeroize();
    let mut wrap_key = wrap_key?;
    let wrapped = symmetric::encrypt(&wrap_key, sek, &crate::security::obf::applock_material_aad());
    wrap_key.zeroize();
    Ok((salt, verifier, wrapped?, kdf))
}

/// Verify a PIN against a stored record and, on success, recover the SEK.
///
/// Returns `Ok(None)` ONLY for a verifier mismatch (a wrong PIN) — the sole
/// outcome the caller may count against the 5-strike anti-brute-force ladder.
/// Any internal failure (e.g. an Argon2id 64 MiB allocation failure on a
/// low-RAM device, or an AES-GCM/decode error unwrapping the SEK) propagates
/// as `Err(e)` instead, so a legitimate PIN entry on a constrained device is
/// never mistaken for — and penalized like — a wrong guess.
async fn open_with_pin(record: &PersistedAppLock, pin: &str) -> Result<Option<[u8; KEY_SIZE]>> {
    let mut ikm = passcode::stretch_secret(record.kdf_version, record.salt.clone(), pin.as_bytes().to_vec()).await?;
    let verifier = passcode::derive_verifier(&record.salt, &ikm, &crate::security::obf::applock_verifier_info());
    let verifier = match verifier {
        Ok(v) => v,
        Err(e) => {
            ikm.zeroize();
            return Err(e);
        }
    };
    if verifier != record.verifier {
        ikm.zeroize();
        return Ok(None);
    }
    let wrap_key = passcode::derive_wrap_key(&record.salt, &ikm, &crate::security::obf::applock_sek_wrap_info());
    ikm.zeroize();
    let mut wrap_key = wrap_key?;
    let sek_bytes = symmetric::decrypt(&wrap_key, &record.sek_wrapped_by_pin, &crate::security::obf::applock_material_aad());
    wrap_key.zeroize();
    let mut sek_bytes = sek_bytes?;
    if sek_bytes.len() != KEY_SIZE {
        sek_bytes.zeroize();
        return Err(QGuardError::Crypto("recovered SEK has wrong length".to_string()));
    }
    let mut sek = [0u8; KEY_SIZE];
    sek.copy_from_slice(&sek_bytes);
    sek_bytes.zeroize();
    Ok(Some(sek))
}

/// The duress PIN's verifier: the same KDF + HKDF-SHA3-256 as the real PIN's,
/// under its own salt and context. Nothing is wrapped under it.
async fn seal_duress(pin: &str) -> Result<DuressPin> {
    let salt = passcode::random_salt();
    let kdf_version = passcode::preferred_kdf();
    let mut ikm = passcode::stretch_secret(kdf_version, salt.clone(), pin.as_bytes().to_vec()).await?;
    let verifier = passcode::derive_verifier(&salt, &ikm, DURESS_VERIFIER_INFO);
    ikm.zeroize();
    Ok(DuressPin { salt, verifier: verifier?, kdf_version })
}

async fn duress_matches(duress: &DuressPin, pin: &str) -> Result<bool> {
    let mut ikm = passcode::stretch_secret(duress.kdf_version, duress.salt.clone(), pin.as_bytes().to_vec()).await?;
    let verifier = passcode::derive_verifier(&duress.salt, &ikm, DURESS_VERIFIER_INFO);
    ikm.zeroize();
    Ok(verifier? == duress.verifier)
}

/// What the lock screen gets after a wipe: no session, "sign in again" — the
/// same answer as the fifth wrong PIN or an expired session, so a duress wipe
/// looks like nothing special.
fn signed_out_result() -> AppLockUnlockResult {
    let mut status = status_from(None, false);
    status.requires_full_auth = true;
    AppLockUnlockResult { session: None, status }
}

fn wrap_session_under_sek(sek: &[u8; KEY_SIZE], session: &StoredSession) -> Result<EncryptedEnvelope> {
    let mut serialized = serde_json::to_vec(session)
        .map_err(|e| QGuardError::Storage(format!("encode session: {e}")))?;
    let wrapped = symmetric::encrypt(sek, &serialized, &crate::security::obf::applock_session_wrap_aad());
    serialized.zeroize();
    wrapped
}

fn unwrap_session_from_sek(sek: &[u8; KEY_SIZE], envelope: &EncryptedEnvelope) -> Result<StoredSession> {
    let mut plaintext = symmetric::decrypt(sek, envelope, &crate::security::obf::applock_session_wrap_aad())?;
    let session = serde_json::from_slice(&plaintext)
        .map_err(|e| QGuardError::Storage(format!("decode session: {e}")));
    plaintext.zeroize();
    session
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppLockStatus {
    pub configured: bool,
    pub enabled: bool,
    pub locked: bool,
    pub digits: u8,
    pub failed_attempts: u32,
    pub attempts_remaining: u32,
    pub lockout_until: Option<String>,
    pub inactivity_minutes: u32,
    pub device: Option<DeviceRegistration>,
    pub requires_full_auth: bool,
    /// A duress PIN is set. Reported only while the app is unlocked, so the
    /// lock screen never reveals that one exists.
    pub duress_configured: bool,
    /// Biometric unlock is set up on this device.
    pub biometric_enabled: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppLockUnlockResult {
    /// None only when the 5th wrong attempt wiped the store; the frontend then
    /// falls back to full email/password login (status.requires_full_auth = true).
    pub session: Option<StoredSession>,
    pub status: AppLockStatus,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceIntegrity {
    pub rooted: bool,
    pub emulator: bool,
    pub signals: Vec<String>,
}

fn status_from(record: Option<&PersistedAppLock>, unlocked: bool) -> AppLockStatus {
    match record {
        Some(r) => AppLockStatus {
            configured: true,
            enabled: r.enabled,
            locked: !unlocked,
            digits: r.digits,
            failed_attempts: r.failed_attempts,
            attempts_remaining: attempts_remaining(r.failed_attempts),
            lockout_until: r.lockout_until.map(|t| t.to_rfc3339()),
            inactivity_minutes: r.inactivity_minutes,
            device: Some(r.device.clone()),
            requires_full_auth: false,
            duress_configured: unlocked && r.duress.is_some(),
            biometric_enabled: r.biometric_sek.is_some(),
        },
        None => AppLockStatus {
            configured: false, enabled: false, locked: false, digits: 0,
            failed_attempts: 0, attempts_remaining: MAX_ATTEMPTS, lockout_until: None,
            inactivity_minutes: DEFAULT_INACTIVITY_MINUTES, device: None, requires_full_auth: false,
            duress_configured: false, biometric_enabled: false,
        },
    }
}

fn check_lockout(record: &PersistedAppLock) -> Result<()> {
    if let Some(until) = record.lockout_until {
        let now = Utc::now();
        if until > now {
            let secs = (until - now).num_seconds().max(1);
            return Err(QGuardError::Trust(format!("Too many attempts. Try again in {secs}s.")));
        }
    }
    Ok(())
}

fn build_device(
    state: &AppState,
    user_id: &str,
    device_name: &str,
    app_version: &str,
    existing: Option<&DeviceRegistration>,
) -> Result<DeviceRegistration> {
    let device_id = state.ensure_identity(user_id, "Android Device")?.device_id;
    let now = Utc::now();
    Ok(DeviceRegistration {
        device_id,
        device_name: if device_name.trim().is_empty() { "Android Device".to_string() } else { device_name.to_string() },
        platform: "android".to_string(),
        app_version: app_version.to_string(),
        registered_at: existing.map(|d| d.registered_at).unwrap_or(now),
        last_login_at: now,
    })
}

/// The user whose app-lock applies on THIS device. Prefers the live auth
/// session; on a cold launch (no session restored yet) it falls back to the
/// persisted enrollment pointer, so the PIN screen can be shown and the stored
/// session restored WITHOUT asking for email/password again.
fn resolve_applock_user(state: &AppState) -> Option<String> {
    if let Ok(id) = state.user_id() {
        return Some(id);
    }
    state.load_applock_user_pointer()
}

#[tauri::command]
pub fn applock_status(state: State<'_, AppState>) -> Result<AppLockStatus> {
    let user_id = match resolve_applock_user(&state) {
        Some(id) => id,
        None => return Ok(status_from(None, false)),
    };
    let record = state.load_applock(&user_id)?;
    // Self-heal: if a session is live and the user is enrolled but the device
    // pointer is missing (e.g. enrolled on a build before the pointer existed),
    // write it now so the NEXT cold launch shows the PIN, not the login form.
    if record.is_some() && state.user_id().is_ok() {
        let _ = state.save_applock_user_pointer(&user_id);
    }
    Ok(status_from(record.as_ref(), state.is_applock_unlocked()))
}

#[tauri::command]
pub async fn applock_setup(
    state: State<'_, AppState>,
    digits: u8,
    mut pin: String,
    session: StoredSession,
    device_name: String,
    app_version: String,
) -> Result<AppLockStatus> {
    // Thin wrapper: owns the PIN and guarantees it is zeroized on every exit
    // path of `applock_setup_inner` (success, validation error, auth error,
    // storage error, ...) rather than only on the paths the inner logic
    // happened to remember to zeroize inline.
    let out = applock_setup_inner(&state, digits, &pin, &session, &device_name, &app_version).await;
    pin.zeroize();
    out
}

async fn applock_setup_inner(
    state: &State<'_, AppState>,
    digits: u8,
    pin: &str,
    session: &StoredSession,
    device_name: &str,
    app_version: &str,
) -> Result<AppLockStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    validate_pin(digits, pin)?;
    if let Some(duress) = state.load_applock(&user_id)?.and_then(|record| record.duress) {
        if duress_matches(&duress, pin).await? {
            return Err(QGuardError::InvalidInput("Choose a PIN different from your duress PIN.".to_string()));
        }
    }

    let mut sek = symmetric::random_key();
    let (salt, verifier, sek_wrapped, kdf_version) = match seal_pin(pin, &sek).await {
        Ok(v) => v,
        Err(e) => {
            sek.zeroize();
            return Err(e);
        }
    };
    let session_wrapped = match wrap_session_under_sek(&sek, session) {
        Ok(v) => v,
        Err(e) => {
            sek.zeroize();
            return Err(e);
        }
    };
    let existing = match state.load_applock(&user_id) {
        Ok(v) => v,
        Err(e) => {
            sek.zeroize();
            return Err(e);
        }
    };
    let device = match build_device(state, &user_id, device_name, app_version, existing.as_ref().map(|r| &r.device)) {
        Ok(v) => v,
        Err(e) => {
            sek.zeroize();
            return Err(e);
        }
    };
    let record = PersistedAppLock {
        version: 1, enabled: true, digits, kdf_version,
        salt, verifier, sek_wrapped_by_pin: sek_wrapped, session_wrapped_by_sek: session_wrapped,
        failed_attempts: 0, lockout_until: None,
        inactivity_minutes: existing.as_ref().map(|r| r.inactivity_minutes).unwrap_or(DEFAULT_INACTIVITY_MINUTES),
        device, created_at: existing.as_ref().map(|r| r.created_at).unwrap_or_else(Utc::now),
        duress: existing.as_ref().and_then(|r| r.duress.clone()),
        // A new SEK: whatever the biometric key wrapped is stale.
        biometric_sek: None,
    };
    if existing.as_ref().is_some_and(|r| r.biometric_sek.is_some()) {
        device_privacy::biometric_disable();
    }
    if let Err(e) = state.save_applock(&user_id, &record) {
        sek.zeroize();
        return Err(e);
    }
    if let Err(e) = state.set_applock_sek(sek) {
        sek.zeroize();
        return Err(e);
    }
    sek.zeroize();
    state.audit_info("applock_setup", "App-entry PIN configured");
    Ok(status_from(Some(&record), true))
}

#[tauri::command]
pub async fn applock_unlock(state: State<'_, AppState>, mut pin: String) -> Result<AppLockUnlockResult> {
    let out = applock_unlock_inner(&state, &pin).await;
    pin.zeroize();
    out
}

async fn applock_unlock_inner(state: &State<'_, AppState>, pin: &str) -> Result<AppLockUnlockResult> {
    // Cold launch has no live session, so resolve the enrolled user from the
    // device pointer — unlocking is exactly what restores the session.
    let user_id = resolve_applock_user(state)
        .ok_or_else(|| QGuardError::NotFound("app PIN is not configured".to_string()))?;
    let mut record = state
        .load_applock(&user_id)?
        .ok_or_else(|| QGuardError::NotFound("app PIN is not configured".to_string()))?;
    check_lockout(&record)?;

    // With a duress PIN set, BOTH checks always run, so how long an attempt
    // takes does not tell a duress entry from any other.
    let outcome = open_with_pin(&record, pin).await;
    let duress_hit = match record.duress.as_ref() {
        Some(duress) => duress_matches(duress, pin).await.unwrap_or(false),
        None => false,
    };
    if duress_hit && !matches!(outcome, Ok(Some(_))) {
        // Erase this device's keys and sign out, leaving no record of why
        // (nothing is audited: the log would itself be the tell).
        let _ = state.panic_wipe(&user_id);
        device_privacy::biometric_disable();
        return Ok(signed_out_result());
    }

    match outcome {
        Ok(Some(mut sek)) => {
            let session = match unwrap_session_from_sek(&sek, &record.session_wrapped_by_sek) {
                Ok(v) => v,
                Err(e) => {
                    sek.zeroize();
                    return Err(e);
                }
            };
            record.failed_attempts = 0;
            record.lockout_until = None;
            record.device.last_login_at = Utc::now();
            // Re-seal under the device's current KDF (Argon2id <-> PBKDF2 when
            // FIPS approved mode changed) while the PIN is proven. Best-effort:
            // the old seal keeps working if this fails.
            if passcode::needs_reseal(record.kdf_version) {
                if let Ok((salt, verifier, sek_wrapped, kdf_version)) = seal_pin(pin, &sek).await {
                    record.salt = salt;
                    record.verifier = verifier;
                    record.sek_wrapped_by_pin = sek_wrapped;
                    record.kdf_version = kdf_version;
                    state.audit_info(
                        "applock_kdf_upgraded",
                        &format!("App PIN re-sealed with {}", passcode::kdf_label(kdf_version)),
                    );
                }
            }
            if let Err(e) = state.save_applock(&user_id, &record) {
                sek.zeroize();
                return Err(e);
            }
            if let Err(e) = state.set_applock_sek(sek) {
                sek.zeroize();
                return Err(e);
            }
            sek.zeroize();
            state.audit_info("applock_unlock", "App unlocked with PIN");
            Ok(AppLockUnlockResult { session: Some(session), status: status_from(Some(&record), true) })
        }
        Ok(None) => {
            // Shared max-5-attempts ladder (also used by `applock_change_pin`):
            // increments the counter, sets the 3rd/4th-failure delay, and
            // signals the 5th failure so the caller wipes the stored session.
            if apply_failed_attempt(&mut record) {
                // Wipe the stored session; the config is dropped so the next
                // launch requires full email/password login. This is NOT an
                // error to the caller — it returns a session-less result whose
                // status.requires_full_auth signals the fallback.
                state.delete_applock(&user_id)?;
                state.audit_info("applock_wiped", "5 failed PIN attempts — stored session wiped");
                let mut status = status_from(None, false);
                status.requires_full_auth = true;
                return Ok(AppLockUnlockResult { session: None, status });
            }
            state.save_applock(&user_id, &record)?;
            state.audit_info("applock_unlock_failed", "Incorrect app PIN");
            Err(QGuardError::Trust(format!(
                "Incorrect PIN. {} attempt(s) remaining.",
                attempts_remaining(record.failed_attempts)
            )))
        }
        // Internal failure (e.g. Argon2id allocation failure, AES-GCM/decode
        // error) — NOT a wrong-PIN signal, so it must never advance the
        // 5-strike ladder. Propagate as-is.
        Err(e) => Err(e),
    }
}

#[tauri::command]
pub fn applock_update_session(state: State<'_, AppState>, session: StoredSession) -> Result<()> {
    let user_id = state.user_id()?;
    // `take_applock_sek` returns a COPY of the in-memory SEK (the real one
    // stays in AppState so the app remains unlocked) — this local copy is
    // used once to re-wrap the refreshed session and is never re-stored, so
    // unlike setup/unlock/change_pin (which deliberately hand their `sek` to
    // `set_applock_sek` at the end) it must be zeroized on EVERY exit path.
    let mut sek = state
        .take_applock_sek()
        .ok_or_else(|| QGuardError::Trust("app is locked".to_string()))?;
    let mut record = match state.load_applock(&user_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            sek.zeroize();
            return Ok(());
        }
        Err(e) => {
            sek.zeroize();
            return Err(e);
        }
    };
    record.session_wrapped_by_sek = match wrap_session_under_sek(&sek, &session) {
        Ok(v) => v,
        Err(e) => {
            sek.zeroize();
            return Err(e);
        }
    };
    if let Err(e) = state.save_applock(&user_id, &record) {
        sek.zeroize();
        return Err(e);
    }
    sek.zeroize();
    Ok(())
}

#[tauri::command]
pub fn applock_lock(state: State<'_, AppState>) -> Result<()> {
    state.clear_applock_sek();
    state.audit_info("applock_lock", "App locked");
    Ok(())
}

#[tauri::command]
pub async fn applock_change_pin(
    state: State<'_, AppState>,
    mut old_pin: String,
    mut new_pin: String,
    digits: u8,
) -> Result<AppLockStatus> {
    let out = applock_change_pin_inner(&state, &old_pin, &new_pin, digits).await;
    old_pin.zeroize();
    new_pin.zeroize();
    out
}

async fn applock_change_pin_inner(
    state: &State<'_, AppState>,
    old_pin: &str,
    new_pin: &str,
    digits: u8,
) -> Result<AppLockStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    validate_pin(digits, new_pin)?;

    let mut record = state
        .load_applock(&user_id)?
        .ok_or_else(|| QGuardError::NotFound("app PIN is not configured".to_string()))?;
    check_lockout(&record)?;
    if let Some(duress) = record.duress.as_ref() {
        if duress_matches(duress, new_pin).await? {
            return Err(QGuardError::InvalidInput("Choose a PIN different from your duress PIN.".to_string()));
        }
    }
    let mut sek = match open_with_pin(&record, old_pin).await {
        Ok(Some(sek)) => sek,
        Ok(None) => {
            // Same max-5-attempts ladder as `applock_unlock`: a wrong old PIN
            // on change-PIN must count against, and be throttled/wiped by,
            // the SAME failed_attempts counter — otherwise change-PIN is an
            // unthrottled oracle for guessing the PIN.
            if apply_failed_attempt(&mut record) {
                state.delete_applock(&user_id)?;
                return Err(QGuardError::Trust(
                    "Too many attempts. Please sign in again.".to_string(),
                ));
            }
            state.save_applock(&user_id, &record)?;
            return Err(QGuardError::Trust(format!(
                "Incorrect PIN. {} attempt(s) remaining.",
                attempts_remaining(record.failed_attempts)
            )));
        }
        // Internal failure (e.g. Argon2id allocation failure, AES-GCM/decode
        // error) — NOT a wrong-PIN signal, so it must never advance the
        // 5-strike ladder. Propagate as-is.
        Err(e) => return Err(e),
    };
    let (salt, verifier, sek_wrapped, kdf_version) = match seal_pin(new_pin, &sek).await {
        Ok(v) => v,
        Err(e) => {
            sek.zeroize();
            return Err(e);
        }
    };
    record.salt = salt;
    record.verifier = verifier;
    record.sek_wrapped_by_pin = sek_wrapped;
    record.digits = digits;
    record.kdf_version = kdf_version;
    record.failed_attempts = 0;
    record.lockout_until = None;
    if let Err(e) = state.save_applock(&user_id, &record) {
        sek.zeroize();
        return Err(e);
    }
    if let Err(e) = state.set_applock_sek(sek) {
        sek.zeroize();
        return Err(e);
    }
    sek.zeroize();
    state.audit_info("applock_change_pin", "App PIN changed");
    Ok(status_from(Some(&record), true))
}

#[tauri::command]
pub fn applock_remove(state: State<'_, AppState>) -> Result<()> {
    // Caller (frontend) has already verified the account password via an
    // ephemeral Supabase client. Removing the PIN clears the stored session, so
    // the next launch requires full email/password login.
    let user_id = state.user_id()?;
    state.delete_applock(&user_id)?;
    state.audit_info("applock_remove", "App PIN removed (session persistence disabled)");
    Ok(())
}

#[tauri::command]
pub async fn applock_reset(
    state: State<'_, AppState>,
    digits: u8,
    pin: String,
    session: StoredSession,
    device_name: String,
    app_version: String,
) -> Result<AppLockStatus> {
    // Forgotten-PIN / expired-token rebind: identical to setup but explicitly
    // resets counters. Frontend has re-authenticated the account first.
    applock_setup(state, digits, pin, session, device_name, app_version).await
}

#[tauri::command]
pub fn applock_set_inactivity(state: State<'_, AppState>, minutes: u32) -> Result<AppLockStatus> {
    let user_id = state.user_id()?;
    let mut record = state
        .load_applock(&user_id)?
        .ok_or_else(|| QGuardError::NotFound("app PIN is not configured".to_string()))?;
    record.inactivity_minutes = clamp_inactivity(minutes);
    state.save_applock(&user_id, &record)?;
    Ok(status_from(Some(&record), state.is_applock_unlocked()))
}

#[tauri::command]
pub fn applock_wipe(state: State<'_, AppState>, user_id: Option<String>) -> Result<()> {
    let uid = match user_id {
        Some(id) => id,
        None => match state.user_id() {
            Ok(id) => id,
            Err(_) => return Ok(()),
        },
    };
    state.delete_applock(&uid)?;
    state.audit_info("applock_wipe", "App PIN + stored session wiped (logout)");
    Ok(())
}

// ---------------------------------------------------------------------------
// Duress PIN (roadmap 4.3)
// ---------------------------------------------------------------------------

/// Set (or replace) the duress PIN. Only from an unlocked app, never equal to
/// the real PIN. Entered at the lock screen it erases this device's keys
/// (`AppState::panic_wipe`) and lands on sign-in as if the session expired.
#[tauri::command]
pub async fn applock_set_duress_pin(state: State<'_, AppState>, mut pin: String) -> Result<AppLockStatus> {
    let out = set_duress_inner(&state, &pin).await;
    pin.zeroize();
    out
}

async fn set_duress_inner(state: &AppState, pin: &str) -> Result<AppLockStatus> {
    state.require_auth()?;
    if !state.is_applock_unlocked() {
        return Err(QGuardError::Trust("unlock the app first".to_string()));
    }
    validate_pin(NEW_PIN_DIGITS, pin)?;
    let user_id = state.user_id()?;
    let mut record = state
        .load_applock(&user_id)?
        .ok_or_else(|| QGuardError::NotFound("app PIN is not configured".to_string()))?;
    if let Ok(Some(mut sek)) = open_with_pin(&record, pin).await {
        sek.zeroize();
        return Err(QGuardError::InvalidInput("The duress PIN must be different from your PIN.".to_string()));
    }
    record.duress = Some(seal_duress(pin).await?);
    state.save_applock(&user_id, &record)?;
    // Deliberately generic: the log must not say a duress PIN exists.
    state.audit_info("applock_settings_changed", "App lock settings changed");
    Ok(status_from(Some(&record), true))
}

#[tauri::command]
pub fn applock_clear_duress_pin(state: State<'_, AppState>) -> Result<AppLockStatus> {
    state.require_auth()?;
    if !state.is_applock_unlocked() {
        return Err(QGuardError::Trust("unlock the app first".to_string()));
    }
    let user_id = state.user_id()?;
    let mut record = state
        .load_applock(&user_id)?
        .ok_or_else(|| QGuardError::NotFound("app PIN is not configured".to_string()))?;
    record.duress = None;
    state.save_applock(&user_id, &record)?;
    state.audit_info("applock_settings_changed", "App lock settings changed");
    Ok(status_from(Some(&record), true))
}

// ---------------------------------------------------------------------------
// Biometric unlock (roadmap 4.2)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BiometricStatus {
    pub availability: BiometricAvailability,
    pub enabled: bool,
}

fn biometric_status_for(record: Option<&PersistedAppLock>) -> BiometricStatus {
    BiometricStatus {
        availability: device_privacy::biometric_availability(),
        enabled: record.is_some_and(|record| record.biometric_sek.is_some()),
    }
}

#[tauri::command]
pub fn applock_biometric_status(state: State<'_, AppState>) -> Result<BiometricStatus> {
    let record = match resolve_applock_user(&state) {
        Some(user_id) => state.load_applock(&user_id)?,
        None => None,
    };
    Ok(biometric_status_for(record.as_ref()))
}

/// Wrap the SEK under a biometric-gated Keystore key. The prompt blocks, so it
/// runs on the blocking pool, never the async workers.
#[tauri::command]
pub async fn applock_biometric_enable(state: State<'_, AppState>) -> Result<BiometricStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let mut record = state
        .load_applock(&user_id)?
        .ok_or_else(|| QGuardError::NotFound("set an app PIN first".to_string()))?;
    if device_privacy::biometric_availability() != BiometricAvailability::Available {
        return Err(QGuardError::InvalidInput(
            "This device has no strong biometric (fingerprint or face) set up.".to_string(),
        ));
    }
    let sek = state
        .take_applock_sek()
        .ok_or_else(|| QGuardError::Trust("unlock the app first".to_string()))?;
    let sek = zeroize::Zeroizing::new(sek);
    let blob = tauri::async_runtime::spawn_blocking(move || device_privacy::biometric_enable(&sek))
        .await
        .map_err(|e| QGuardError::Crypto(format!("biometric worker failed: {e}")))?
        .map_err(QGuardError::from)?;
    record.biometric_sek = Some(blob);
    state.save_applock(&user_id, &record)?;
    state.audit_info("applock_biometric_enabled", "Biometric unlock turned on for the app PIN");
    Ok(biometric_status_for(Some(&record)))
}

/// Unlock with a strong biometric instead of the PIN. Same result as a correct
/// PIN; a cancelled prompt changes nothing (the PIN screen stays).
#[tauri::command]
pub async fn applock_biometric_unlock(state: State<'_, AppState>) -> Result<AppLockUnlockResult> {
    let user_id = resolve_applock_user(&state)
        .ok_or_else(|| QGuardError::NotFound("app PIN is not configured".to_string()))?;
    let mut record = state
        .load_applock(&user_id)?
        .ok_or_else(|| QGuardError::NotFound("app PIN is not configured".to_string()))?;
    check_lockout(&record)?;
    let blob = record
        .biometric_sek
        .clone()
        .ok_or_else(|| QGuardError::NotFound("biometric unlock is not set up".to_string()))?;
    let opened = tauri::async_runtime::spawn_blocking(move || device_privacy::biometric_unlock(&blob))
        .await
        .map_err(|e| QGuardError::Crypto(format!("biometric worker failed: {e}")))?;
    let sek = match opened {
        Ok(sek) => sek,
        Err(BiometricFailure::Invalidated) => {
            // The key is gone for good: forget the blob so the PIN is used.
            record.biometric_sek = None;
            state.save_applock(&user_id, &record)?;
            return Err(BiometricFailure::Invalidated.into());
        }
        Err(other) => return Err(other.into()),
    };
    let session = unwrap_session_from_sek(&sek, &record.session_wrapped_by_sek)?;
    record.failed_attempts = 0;
    record.lockout_until = None;
    record.device.last_login_at = Utc::now();
    state.save_applock(&user_id, &record)?;
    state.set_applock_sek(*sek)?;
    state.audit_info("applock_unlock", "App unlocked with biometric");
    Ok(AppLockUnlockResult { session: Some(session), status: status_from(Some(&record), true) })
}

#[tauri::command]
pub fn applock_biometric_disable(state: State<'_, AppState>) -> Result<BiometricStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let mut record = state.load_applock(&user_id)?;
    if let Some(record) = record.as_mut() {
        if record.biometric_sek.take().is_some() {
            state.save_applock(&user_id, record)?;
        }
    }
    device_privacy::biometric_disable();
    state.audit_info("applock_biometric_disabled", "Biometric unlock turned off");
    Ok(biometric_status_for(record.as_ref()))
}

#[tauri::command]
#[cfg_attr(not(target_os = "android"), allow(unused_mut))]
pub fn applock_device_integrity() -> Result<DeviceIntegrity> {
    let mut signals = Vec::new();
    let mut rooted = false;
    let mut emulator = false;

    #[cfg(target_os = "android")]
    {
        const SU_PATHS: [&str; 6] = [
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/data/local/xbin/su", "/data/local/su",
        ];
        for p in SU_PATHS {
            if std::path::Path::new(p).exists() {
                rooted = true;
                signals.push(format!("su binary present: {p}"));
            }
        }
        if std::path::Path::new("/system/bin/magisk").exists()
            || std::path::Path::new("/sbin/.magisk").exists()
        {
            rooted = true;
            signals.push("Magisk present".to_string());
        }
        // QEMU/emulator markers (advisory).
        if std::path::Path::new("/dev/socket/qemud").exists()
            || std::path::Path::new("/dev/qemu_pipe").exists()
        {
            emulator = true;
            signals.push("emulator pipe present".to_string());
        }
    }

    Ok(DeviceIntegrity { rooted, emulator, signals })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_session() -> StoredSession {
        StoredSession {
            access_token: "access-token-xyz".to_string(),
            refresh_token: "refresh-token-abc".to_string(),
            expires_at: 4102444800,
            user_id: "user-1".to_string(),
            email: "u@example.com".to_string(),
        }
    }

    #[tokio::test]
    async fn correct_pin_recovers_session_wrong_pin_fails() {
        let sek = symmetric::random_key();
        let (salt, verifier, sek_wrapped, kdf_version) = seal_pin("123456", &sek).await.unwrap();
        let session = sample_session();
        let session_wrapped = wrap_session_under_sek(&sek, &session).unwrap();
        let record = PersistedAppLock {
            version: 1, enabled: true, digits: 6, kdf_version,
            salt, verifier, sek_wrapped_by_pin: sek_wrapped, session_wrapped_by_sek: session_wrapped,
            failed_attempts: 0, lockout_until: None, inactivity_minutes: 10,
            device: DeviceRegistration {
                device_id: "d1".into(), device_name: "Tablet".into(), platform: "android".into(),
                app_version: "1.0.0".into(), registered_at: Utc::now(), last_login_at: Utc::now(),
            },
            created_at: Utc::now(),
            duress: None,
            biometric_sek: None,
        };

        let recovered_sek = open_with_pin(&record, "123456").await.unwrap().unwrap();
        let recovered = unwrap_session_from_sek(&recovered_sek, &record.session_wrapped_by_sek).unwrap();
        assert_eq!(recovered.access_token, session.access_token);
        assert_eq!(recovered.refresh_token, session.refresh_token);

        // Verifier mismatch (wrong PIN) is the ONLY outcome that resolves to
        // `Ok(None)` — it must never surface as an `Err` here, since callers
        // use `Err` to mean "internal failure, do not count against the
        // 5-strike ladder".
        assert!(open_with_pin(&record, "000000").await.unwrap().is_none());
    }

    #[test]
    fn a_new_pin_must_be_six_digits() {
        // Four digits can no longer be chosen...
        assert!(validate_pin(4, "1234").is_err());
        assert!(validate_pin(6, "123456").is_ok());
        assert!(validate_pin(4, "123").is_err());
        assert!(validate_pin(6, "12345").is_err());
        assert!(validate_pin(6, "12345a").is_err());
        assert!(validate_pin(5, "12345").is_err());
    }

    #[test]
    fn ladder_delays_and_attempts_remaining() {
        assert_eq!(lockout_delay_secs(1), 0);
        assert_eq!(lockout_delay_secs(2), 0);
        assert_eq!(lockout_delay_secs(3), 5);
        assert_eq!(lockout_delay_secs(4), 15);
        assert_eq!(attempts_remaining(0), 5);
        assert_eq!(attempts_remaining(4), 1);
        assert_eq!(attempts_remaining(5), 0);
    }

    fn blank_record() -> PersistedAppLock {
        PersistedAppLock {
            version: 1, enabled: true, digits: 6, kdf_version: KDF_ARGON2ID_V1,
            salt: vec![0u8; 16], verifier: String::new(),
            sek_wrapped_by_pin: EncryptedEnvelope { nonce: vec![], ciphertext: vec![], tag: vec![] },
            session_wrapped_by_sek: EncryptedEnvelope { nonce: vec![], ciphertext: vec![], tag: vec![] },
            failed_attempts: 0, lockout_until: None, inactivity_minutes: 10,
            device: DeviceRegistration {
                device_id: "d1".into(), device_name: "Tablet".into(), platform: "android".into(),
                app_version: "1.0.0".into(), registered_at: Utc::now(), last_login_at: Utc::now(),
            },
            created_at: Utc::now(),
            duress: None,
            biometric_sek: None,
        }
    }

    #[tokio::test]
    async fn the_duress_pin_is_recognised_and_only_it() {
        let duress = seal_duress("911911").await.unwrap();
        assert!(duress_matches(&duress, "911911").await.unwrap());
        assert!(!duress_matches(&duress, "123456").await.unwrap());
        // Its verifier is not the real PIN's verifier for the same digits.
        let sek = symmetric::random_key();
        let (salt, real_verifier, _, kdf_version) = seal_pin("911911", &sek).await.unwrap();
        let ikm = passcode::secret_ikm(kdf_version, &salt, b"911911").unwrap();
        assert_ne!(passcode::derive_verifier(&salt, &ikm, DURESS_VERIFIER_INFO).unwrap(), real_verifier);
    }

    /// An app PIN sealed with Argon2id still opens after the device moves to
    /// PBKDF2 (FIPS approved mode), and the re-sealed record opens too.
    #[tokio::test]
    async fn an_argon2id_pin_record_opens_and_reseals_under_pbkdf2() {
        use crate::crypto::passcode::KDF_PBKDF2_SHA512_V2;
        let sek = symmetric::random_key();
        let mut record = blank_record();
        record.salt = passcode::random_salt();
        let ikm = passcode::secret_ikm(KDF_ARGON2ID_V1, &record.salt, b"246810").unwrap();
        record.verifier = passcode::derive_verifier(&record.salt, &ikm, &crate::security::obf::applock_verifier_info()).unwrap();
        let wrap = passcode::derive_wrap_key(&record.salt, &ikm, &crate::security::obf::applock_sek_wrap_info()).unwrap();
        record.sek_wrapped_by_pin = symmetric::encrypt(&wrap, &sek, &crate::security::obf::applock_material_aad()).unwrap();
        record.kdf_version = KDF_ARGON2ID_V1;
        assert_eq!(open_with_pin(&record, "246810").await.unwrap().unwrap(), sek);

        // The re-seal the unlock path performs, done with PBKDF2 explicitly.
        let salt = passcode::random_salt();
        let ikm = passcode::secret_ikm(KDF_PBKDF2_SHA512_V2, &salt, b"246810").unwrap();
        record.verifier = passcode::derive_verifier(&salt, &ikm, &crate::security::obf::applock_verifier_info()).unwrap();
        let wrap = passcode::derive_wrap_key(&salt, &ikm, &crate::security::obf::applock_sek_wrap_info()).unwrap();
        record.sek_wrapped_by_pin = symmetric::encrypt(&wrap, &sek, &crate::security::obf::applock_material_aad()).unwrap();
        record.salt = salt;
        record.kdf_version = KDF_PBKDF2_SHA512_V2;
        assert_eq!(open_with_pin(&record, "246810").await.unwrap().unwrap(), sek);
        assert!(open_with_pin(&record, "135790").await.unwrap().is_none());
    }

    #[test]
    fn a_duress_pin_stored_before_it_recorded_a_kdf_reads_as_argon2id() {
        let old: DuressPin = serde_json::from_str(r#"{"salt":[1,2,3],"verifier":"v"}"#).unwrap();
        assert_eq!(old.kdf_version, KDF_ARGON2ID_V1);
    }

    #[test]
    fn the_lock_screen_never_says_a_duress_pin_exists() {
        let mut record = blank_record();
        record.duress = Some(DuressPin { salt: vec![1; 16], verifier: "v".into(), kdf_version: KDF_ARGON2ID_V1 });
        assert!(!status_from(Some(&record), false).duress_configured, "locked: not revealed");
        assert!(status_from(Some(&record), true).duress_configured, "unlocked: the owner sees it");
        let wiped = signed_out_result();
        assert!(wiped.session.is_none() && wiped.status.requires_full_auth && !wiped.status.configured);
    }

    #[test]
    fn apply_failed_attempt_ladder_and_wipe() {
        let mut record = blank_record();

        assert!(!apply_failed_attempt(&mut record)); // 1st
        assert_eq!(record.failed_attempts, 1);
        assert!(record.lockout_until.is_none());

        assert!(!apply_failed_attempt(&mut record)); // 2nd
        assert_eq!(record.failed_attempts, 2);
        assert!(record.lockout_until.is_none());

        assert!(!apply_failed_attempt(&mut record)); // 3rd -> ~5s lockout
        assert_eq!(record.failed_attempts, 3);
        let until = record.lockout_until.expect("3rd failure sets a lockout");
        let secs = (until - Utc::now()).num_seconds();
        assert!((1..=5).contains(&secs), "expected ~5s lockout, got {secs}s");

        assert!(!apply_failed_attempt(&mut record)); // 4th -> ~15s lockout
        assert_eq!(record.failed_attempts, 4);
        let until = record.lockout_until.expect("4th failure sets a lockout");
        let secs = (until - Utc::now()).num_seconds();
        assert!((11..=15).contains(&secs), "expected ~15s lockout, got {secs}s");

        assert!(apply_failed_attempt(&mut record)); // 5th -> wipe signal
        assert_eq!(record.failed_attempts, 5);
    }
}
