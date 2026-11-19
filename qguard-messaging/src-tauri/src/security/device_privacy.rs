//! Android device-privacy helpers, driving `PrivacyScreen.kt` (Recent-apps
//! masking, roadmap 4.1) and `BiometricUnlock.kt` (biometric unlock of the
//! app-entry PIN, roadmap 4.2). Desktop builds answer "unsupported": neither
//! exists there.

use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{QGuardError, Result};

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecentsMasking {
    pub supported: bool,
    pub enabled: bool,
    /// `system` (Android 13+: no snapshot is taken) or `cover` (older: an
    /// opaque view is drawn before the snapshot).
    pub method: String,
}

/// What the biometric side of the device can do.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BiometricAvailability {
    Available,
    NoneEnrolled,
    NoHardware,
    Unavailable,
    Unsupported,
}

/// Why a biometric operation did not produce a key.
#[derive(Debug, PartialEq, Eq)]
pub enum BiometricFailure {
    /// The user cancelled, chose "Use PIN", or the prompt timed out.
    Cancelled,
    /// A new fingerprint/face was enrolled (or the key is gone): biometric
    /// unlock must be set up again.
    Invalidated,
    Other(String),
}

impl From<BiometricFailure> for QGuardError {
    fn from(failure: BiometricFailure) -> Self {
        match failure {
            BiometricFailure::Cancelled => QGuardError::Trust("Biometric unlock was cancelled.".to_string()),
            BiometricFailure::Invalidated => QGuardError::Trust(
                "Biometric unlock was turned off because the device's fingerprints or face data changed. Use your PIN, then turn it on again in Settings.".to_string(),
            ),
            BiometricFailure::Other(reason) => QGuardError::Storage(format!("biometric unlock failed: {reason}")),
        }
    }
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))] // used by the android module and tests
fn biometric_failure(reason: &str) -> BiometricFailure {
    match reason {
        "cancelled" => BiometricFailure::Cancelled,
        "invalidated" => BiometricFailure::Invalidated,
        other => BiometricFailure::Other(other.to_string()),
    }
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))] // used by the android module and tests
fn parse_availability(raw: &str) -> BiometricAvailability {
    match raw {
        "available" => BiometricAvailability::Available,
        "none_enrolled" => BiometricAvailability::NoneEnrolled,
        "no_hardware" => BiometricAvailability::NoHardware,
        _ => BiometricAvailability::Unavailable,
    }
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))] // used by the android module and tests
fn parse_masking(raw: &str) -> Result<RecentsMasking> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| QGuardError::Storage(format!("recents masking status: {e}")))?;
    Ok(RecentsMasking {
        supported: true,
        enabled: value.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false),
        method: value.get("method").and_then(|v| v.as_str()).unwrap_or("cover").to_string(),
    })
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))] // used by the android module and tests
fn decode_sek(b64: &str) -> std::result::Result<Zeroizing<[u8; 32]>, BiometricFailure> {
    use base64::Engine as _;
    let bytes = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|_| BiometricFailure::Other("malformed key".to_string()))?,
    );
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| BiometricFailure::Other("unexpected key length".to_string()))?;
    Ok(Zeroizing::new(array))
}

#[cfg(target_os = "android")]
mod platform {
    use super::*;
    use crate::security::android_bridge::{call_static_string, in_band};

    const PRIVACY_CLASS: &str = "com.qguard.messaging.PrivacyScreen";
    const BIOMETRIC_CLASS: &str = "com.qguard.messaging.BiometricUnlock";
    const PROMPT_TITLE: &str = "Unlock QGuard";

    fn privacy(method: &str, args: &[&str]) -> Result<String> {
        call_static_string(PRIVACY_CLASS, method, args)
            .and_then(in_band)
            .map_err(|e| QGuardError::Storage(format!("recents masking ({method}): {e}")))
    }

    pub fn recents_masking_status() -> Result<RecentsMasking> {
        parse_masking(&privacy("recentsMaskingStatus", &[])?)
    }

    pub fn set_recents_masking(enabled: bool) -> Result<RecentsMasking> {
        privacy("setRecentsMasking", &[if enabled { "true" } else { "false" }])?;
        recents_masking_status()
    }

    fn biometric(method: &str, args: &[&str]) -> std::result::Result<String, BiometricFailure> {
        let raw = call_static_string(BIOMETRIC_CLASS, method, args).map_err(BiometricFailure::Other)?;
        in_band(raw).map_err(|reason| biometric_failure(&reason))
    }

    pub fn biometric_availability() -> BiometricAvailability {
        biometric("availability", &[]).map(|raw| parse_availability(&raw)).unwrap_or(BiometricAvailability::Unavailable)
    }

    /// Biometric sensors the device has ("fingerprint", "face", "iris").
    pub fn biometric_modalities() -> Vec<String> {
        biometric("modalities", &[])
            .map(|raw| raw.split(',').map(str::trim).filter(|m| !m.is_empty()).map(str::to_string).collect())
            .unwrap_or_default()
    }

    pub fn biometric_enable(sek: &[u8; 32]) -> std::result::Result<String, BiometricFailure> {
        use base64::Engine as _;
        let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(sek));
        biometric("enable", &[encoded.as_str(), PROMPT_TITLE])
    }

    pub fn biometric_unlock(blob: &str) -> std::result::Result<Zeroizing<[u8; 32]>, BiometricFailure> {
        let encoded = Zeroizing::new(biometric("unlock", &[blob, PROMPT_TITLE])?);
        decode_sek(&encoded)
    }

    pub fn biometric_disable() {
        let _ = biometric("disable", &[]);
    }
}

#[cfg(not(target_os = "android"))]
mod platform {
    use super::*;

    pub fn recents_masking_status() -> Result<RecentsMasking> {
        Ok(RecentsMasking { supported: false, enabled: false, method: String::new() })
    }

    pub fn set_recents_masking(_enabled: bool) -> Result<RecentsMasking> {
        Err(QGuardError::InvalidInput("hiding the app in Recent apps is an Android setting".to_string()))
    }

    pub fn biometric_availability() -> BiometricAvailability {
        BiometricAvailability::Unsupported
    }

    pub fn biometric_modalities() -> Vec<String> {
        Vec::new()
    }

    pub fn biometric_enable(_sek: &[u8; 32]) -> std::result::Result<String, BiometricFailure> {
        Err(BiometricFailure::Other("biometric unlock is available on Android only".to_string()))
    }

    pub fn biometric_unlock(_blob: &str) -> std::result::Result<Zeroizing<[u8; 32]>, BiometricFailure> {
        Err(BiometricFailure::Other("biometric unlock is available on Android only".to_string()))
    }

    pub fn biometric_disable() {}
}

pub use platform::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_band_answers_are_read_correctly() {
        assert_eq!(biometric_failure("cancelled"), BiometricFailure::Cancelled);
        assert_eq!(biometric_failure("invalidated"), BiometricFailure::Invalidated);
        assert_eq!(biometric_failure("boom"), BiometricFailure::Other("boom".to_string()));
        assert_eq!(parse_availability("available"), BiometricAvailability::Available);
        assert_eq!(parse_availability("none_enrolled"), BiometricAvailability::NoneEnrolled);
        assert_eq!(parse_availability("garbage"), BiometricAvailability::Unavailable);
        let masking = parse_masking(r#"{"enabled":true,"method":"system"}"#).unwrap();
        assert_eq!(masking, RecentsMasking { supported: true, enabled: true, method: "system".to_string() });
        assert!(parse_masking("not json").is_err());
    }

    #[test]
    fn a_returned_key_must_be_exactly_32_bytes() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        assert_eq!(*decode_sek(&b64.encode([7u8; 32])).unwrap(), [7u8; 32]);
        assert!(decode_sek(&b64.encode([7u8; 31])).is_err());
        assert!(decode_sek("@@@").is_err());
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn desktop_says_unsupported_rather_than_pretending() {
        assert!(!recents_masking_status().unwrap().supported);
        assert!(set_recents_masking(true).is_err());
        assert_eq!(biometric_availability(), BiometricAvailability::Unsupported);
        assert!(biometric_enable(&[0; 32]).is_err());
    }
}
