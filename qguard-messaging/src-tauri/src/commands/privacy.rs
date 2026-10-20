//! Device privacy controls (roadmap Phase 4): hiding the app in Recent apps,
//! the panic wipe, and the conversation privacy screen's verifier.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;

use crate::crypto::passcode::{self, KDF_ARGON2ID_V1};
use crate::error::{QGuardError, Result};
use crate::security::device_privacy::{self, RecentsMasking};
use crate::state::AppState;

/// Domain separation for the conversation privacy screen's verifier.
const PRIVACY_SCREEN_INFO: &[u8] = b"QGuard-ChatPrivacyScreen-Verifier-v1";
/// The KDF label stored with a privacy-screen verifier made here.
pub const PRIVACY_SCREEN_KDF: &str = "argon2id-sha3-v1";

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

fn screen_verifier(salt: &[u8], secret: &[u8]) -> Result<String> {
    let mut ikm = passcode::secret_ikm(KDF_ARGON2ID_V1, salt, secret)?;
    let verifier = passcode::derive_verifier(salt, &ikm, PRIVACY_SCREEN_INFO);
    ikm.zeroize();
    verifier
}

/// Make a verifier for the conversation privacy screen: Argon2id + HKDF-SHA3-
/// 256, like the app PIN — replacing the WebView's PBKDF2-SHA-256 (4.4).
#[tauri::command]
pub async fn privacy_screen_seal(mut secret: String) -> Result<PrivacyScreenSeal> {
    let salt = passcode::random_salt();
    let bytes = secret.as_bytes().to_vec();
    secret.zeroize();
    let salt_for_worker = salt.clone();
    let verifier = tauri::async_runtime::spawn_blocking(move || {
        let mut bytes = bytes;
        let verifier = screen_verifier(&salt_for_worker, &bytes);
        bytes.zeroize();
        verifier
    })
    .await
    .map_err(|e| QGuardError::Crypto(format!("privacy screen worker failed: {e}")))??;
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(PrivacyScreenSeal {
        kdf: PRIVACY_SCREEN_KDF.to_string(),
        salt_b64: b64.encode(&salt),
        verifier_b64: verifier,
    })
}

#[tauri::command]
pub async fn privacy_screen_verify(mut secret: String, seal: PrivacyScreenSeal) -> Result<bool> {
    if seal.kdf != PRIVACY_SCREEN_KDF {
        secret.zeroize();
        return Err(QGuardError::InvalidInput("unsupported privacy screen verifier".to_string()));
    }
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&seal.salt_b64)
        .map_err(|_| QGuardError::InvalidInput("malformed privacy screen salt".to_string()))?;
    let bytes = secret.as_bytes().to_vec();
    secret.zeroize();
    let expected = seal.verifier_b64;
    tauri::async_runtime::spawn_blocking(move || {
        let mut bytes = bytes;
        let verifier = screen_verifier(&salt, &bytes);
        bytes.zeroize();
        verifier.map(|verifier| verifier == expected)
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
