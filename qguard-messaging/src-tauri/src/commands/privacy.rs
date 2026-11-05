//! Device privacy controls (roadmap Phase 4): hiding the app in Recent apps,
//! the panic wipe, and the conversation privacy screen's verifier.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;

use crate::crypto::passcode::{self, KDF_ARGON2ID_V1, KDF_PBKDF2_SHA512_V2};
use crate::crypto::provider;
use crate::error::{QGuardError, Result};
use crate::security::device_privacy::{self, RecentsMasking};
use crate::state::AppState;

/// Domain separation for the conversation privacy screen's verifier.
const PRIVACY_SCREEN_INFO: &[u8] = b"QGuard-ChatPrivacyScreen-Verifier-v1";
/// The KDF label stored with a privacy-screen verifier made here.
pub const PRIVACY_SCREEN_KDF: &str = "argon2id-sha3-v1";
/// ...and the label of one made in FIPS approved mode.
pub const PRIVACY_SCREEN_KDF_APPROVED: &str = "pbkdf2-sha512-sha3-v2";

fn screen_label(kdf: u8) -> &'static str {
    if kdf == KDF_PBKDF2_SHA512_V2 {
        PRIVACY_SCREEN_KDF_APPROVED
    } else {
        PRIVACY_SCREEN_KDF
    }
}

fn screen_kdf(label: &str) -> Option<u8> {
    match label {
        PRIVACY_SCREEN_KDF => Some(KDF_ARGON2ID_V1),
        PRIVACY_SCREEN_KDF_APPROVED => Some(KDF_PBKDF2_SHA512_V2),
        _ => None,
    }
}

#[tauri::command]
pub fn privacy_recents_masking_status() -> Result<RecentsMasking> {
    device_privacy::recents_masking_status()
}

#[tauri::command]
pub fn privacy_set_recents_masking(state: State<'_, AppState>, enabled: bool) -> Result<RecentsMasking> {
    state.require_auth()?;
    let status = device_privacy::set_recents_masking(enabled)?;
    state.audit_info(
        "privacy_recents_masking",
        if enabled { "App content hidden in Recent apps" } else { "App content shown in Recent apps" },
    );
    Ok(status)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PanicWipeReport {
    pub files_removed: usize,
}

/// Erase this device's keys for the signed-in account and sign out
/// (`AppState::panic_wipe`). The caller confirms with the exact phrase shown
/// in the UI, so a stray click or a scripted call cannot trigger it.
#[tauri::command]
pub fn privacy_panic_wipe(state: State<'_, AppState>, confirmation: String) -> Result<PanicWipeReport> {
    let user_id = state.user_id()?;
    if confirmation.trim() != "ERASE" {
        return Err(QGuardError::InvalidInput("type ERASE to confirm".to_string()));
    }
    let files_removed = state.panic_wipe(&user_id)?;
    device_privacy::biometric_disable();
    Ok(PanicWipeReport { files_removed })
}

/// A privacy-screen verifier, as the WebView stores it (base64 fields).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyScreenSeal {
    pub kdf: String,
    pub salt_b64: String,
    pub verifier_b64: String,
}

fn screen_verifier(kdf: u8, salt: &[u8], secret: &[u8]) -> Result<String> {
    let mut ikm = passcode::secret_ikm(kdf, salt, secret)?;
    let verifier = passcode::derive_verifier(salt, &ikm, PRIVACY_SCREEN_INFO);
    ikm.zeroize();
    verifier
}

/// The verifier label a NEW seal gets on this device (it follows FIPS approved
/// mode). The screen compares it with what it stored to decide on a re-seal.
#[tauri::command]
pub fn privacy_screen_kdf() -> String {
    screen_label(passcode::preferred_kdf()).to_string()
}

/// Make a verifier for the conversation privacy screen: Argon2id (PBKDF2-
/// HMAC-SHA-512 in approved mode) + HKDF-SHA3-256, like the app PIN —
/// replacing the WebView's PBKDF2-SHA-256 (4.4).
#[tauri::command]
pub async fn privacy_screen_seal(mut secret: String) -> Result<PrivacyScreenSeal> {
    let salt = passcode::random_salt();
    let kdf = passcode::preferred_kdf();
    let bytes = secret.as_bytes().to_vec();
    secret.zeroize();
    let salt_for_worker = salt.clone();
    let verifier = tauri::async_runtime::spawn_blocking(move || {
        let mut bytes = bytes;
        let verifier = screen_verifier(kdf, &salt_for_worker, &bytes);
        bytes.zeroize();
        verifier
    })
    .await
    .map_err(|e| QGuardError::Crypto(format!("privacy screen worker failed: {e}")))??;
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(PrivacyScreenSeal {
        kdf: screen_label(kdf).to_string(),
        salt_b64: b64.encode(&salt),
        verifier_b64: verifier,
    })
}

#[tauri::command]
pub async fn privacy_screen_verify(mut secret: String, seal: PrivacyScreenSeal) -> Result<bool> {
    let Some(kdf) = screen_kdf(&seal.kdf) else {
        secret.zeroize();
        return Err(QGuardError::InvalidInput("unsupported privacy screen verifier".to_string()));
    };
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&seal.salt_b64)
        .map_err(|_| QGuardError::InvalidInput("malformed privacy screen salt".to_string()))?;
    let bytes = secret.as_bytes().to_vec();
    secret.zeroize();
    let expected = seal.verifier_b64;
    tauri::async_runtime::spawn_blocking(move || {
        let mut bytes = bytes;
        let verifier = screen_verifier(kdf, &salt, &bytes);
        bytes.zeroize();
        verifier.map(|verifier| provider::constant_time_eq(verifier.as_bytes(), expected.as_bytes()))
    })
    .await
    .map_err(|e| QGuardError::Crypto(format!("privacy screen worker failed: {e}")))?
}

/// Check a privacy-screen verifier written by builds before 4.4 (PBKDF2-HMAC-
/// SHA-256 in the WebView), here in the cryptographic module instead. Only
/// used to open such a screen once; the caller then re-seals it.
#[tauri::command]
pub async fn privacy_screen_verify_legacy(
    mut secret: String,
    salt_b64: String,
    verifier_b64: String,
    iterations: u32,
) -> Result<bool> {
    // The floor every released build wrote at least (privacy-screen.ts).
    if !(100_000..=5_000_000).contains(&iterations) {
        secret.zeroize();
        return Err(QGuardError::InvalidInput("unsupported privacy screen verifier".to_string()));
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let salt = b64
        .decode(&salt_b64)
        .map_err(|_| QGuardError::InvalidInput("malformed privacy screen salt".to_string()))?;
    let bytes = secret.as_bytes().to_vec();
    secret.zeroize();
    tauri::async_runtime::spawn_blocking(move || {
        let mut bytes = bytes;
        let mut derived = [0u8; 32];
        let outcome = provider::pbkdf2(provider::Hash::Sha256, &bytes, &salt, iterations, &mut derived);
        bytes.zeroize();
        let matches = outcome.map(|()| provider::constant_time_eq(b64.encode(derived).as_bytes(), verifier_b64.as_bytes()));
        derived.zeroize();
        matches
    })
    .await
    .map_err(|e| QGuardError::Crypto(format!("privacy screen worker failed: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDevice;

    #[tokio::test]
    async fn the_privacy_screen_verifier_accepts_only_its_secret() {
        let seal = privacy_screen_seal("open sesame".to_string()).await.unwrap();
        assert_eq!(seal.kdf, PRIVACY_SCREEN_KDF);
        assert!(privacy_screen_verify("open sesame".to_string(), seal.clone()).await.unwrap());
        assert!(!privacy_screen_verify("open sesame!".to_string(), seal.clone()).await.unwrap());
        let mut other_kdf = seal.clone();
        other_kdf.kdf = "pbkdf2-sha256".to_string();
        assert!(privacy_screen_verify("open sesame".to_string(), other_kdf).await.is_err());
        // Two seals of the same secret differ (fresh salt), both verify.
        let again = privacy_screen_seal("open sesame".to_string()).await.unwrap();
        assert_ne!(again.verifier_b64, seal.verifier_b64);
        assert!(privacy_screen_verify("open sesame".to_string(), again).await.unwrap());
    }

    /// A seal made in FIPS approved mode (PBKDF2) opens in either mode.
    #[tokio::test]
    async fn an_approved_mode_seal_verifies() {
        let salt = passcode::random_salt();
        let verifier = screen_verifier(KDF_PBKDF2_SHA512_V2, &salt, b"open sesame").unwrap();
        let seal = PrivacyScreenSeal {
            kdf: PRIVACY_SCREEN_KDF_APPROVED.to_string(),
            salt_b64: base64::engine::general_purpose::STANDARD.encode(&salt),
            verifier_b64: verifier,
        };
        assert!(privacy_screen_verify("open sesame".to_string(), seal.clone()).await.unwrap());
        assert!(!privacy_screen_verify("open sesame?".to_string(), seal).await.unwrap());
        assert_eq!(screen_kdf(PRIVACY_SCREEN_KDF_APPROVED), Some(KDF_PBKDF2_SHA512_V2));
        assert_eq!(screen_label(KDF_ARGON2ID_V1), PRIVACY_SCREEN_KDF);
    }

    /// The pre-4.4 WebView verifier (base64 of PBKDF2-HMAC-SHA-256) is now
    /// checked by the module.
    #[tokio::test]
    async fn a_legacy_webview_verifier_is_checked_by_the_module() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let salt = [5u8; 16];
        let mut derived = [0u8; 32];
        provider::pbkdf2(provider::Hash::Sha256, b"1234", &salt, 100_000, &mut derived).unwrap();
        let (salt_b64, verifier_b64) = (b64.encode(salt), b64.encode(derived));
        assert!(privacy_screen_verify_legacy("1234".into(), salt_b64.clone(), verifier_b64.clone(), 100_000).await.unwrap());
        assert!(!privacy_screen_verify_legacy("4321".into(), salt_b64.clone(), verifier_b64.clone(), 100_000).await.unwrap());
        // An iteration count no released build wrote is refused outright.
        assert!(privacy_screen_verify_legacy("1234".into(), salt_b64, verifier_b64, 1).await.is_err());
    }

    #[test]
    fn a_panic_wipe_leaves_nothing_that_opens_this_accounts_data() {
        let device = TestDevice::new(false);
        let keys = device.dir.join("keys");
        let prefix = format!("{}.", AppState::safe_user_key(&device.user));
        // Something besides the identity: a recorded message key.
        device.state.remember_message_key(&device.user, "m1", &[1; 12], &[2; 16], &[3; 32]);
        device.state.flush_message_keys(&device.user).unwrap();
        let before = std::fs::read_dir(&keys).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().starts_with(&prefix)).count();
        assert!(before >= 2, "the account keeps files here before the wipe");
        let old_device = device.device_id.clone();

        let removed = device.state.panic_wipe(&device.user).unwrap();
        assert_eq!(removed, before);
        let after = std::fs::read_dir(&keys).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().starts_with(&prefix)).count();
        assert_eq!(after, 0, "no file of this account survives");
        assert!(device.state.user_id().is_err(), "signed out");
        assert!(device.state.cached_message_key(&device.user, "m1", &[1; 12], &[2; 16]).is_none());
        // The device storage key is gone too: a sign-in afterwards is a NEW device.
        assert!(crate::security::keystore::load_secret(&AppState::safe_user_key(&device.user), &device.dir).unwrap().is_none());
        let relaunched = TestDevice::open(device.dir.clone(), device.user.clone());
        assert_ne!(relaunched.device_id, old_device, "the old identity cannot come back");
        std::mem::forget(relaunched); // `device` cleans up the shared directory
    }

    #[test]
    fn a_panic_wipe_touches_no_other_account() {
        let device = TestDevice::new(false);
        let other_user = format!("other-{}", uuid::Uuid::new_v4());
        let other_file = device.dir.join("keys").join(format!("{}.message-keys.enc", AppState::safe_user_key(&other_user)));
        std::fs::write(&other_file, b"other account").unwrap();
        device.state.panic_wipe(&device.user).unwrap();
        assert!(other_file.exists());
    }
}
