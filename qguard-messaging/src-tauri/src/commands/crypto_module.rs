//! The cryptographic module, as the app sees it (Settings → Security →
//! FIPS 140-3), plus the services the WebView uses instead of doing
//! cryptography itself: digests, HMAC-SHA3-256 and chat-attachment AES-256-GCM.
//!
//! Every answer here is computed, not asserted: the backend reports its own
//! identity, the self-test report is the one this process ran, a certificate is
//! named only for a wolfCrypt FIPS build whose version maps to one, and each
//! credential's KDF comes from its stored record.

use base64::Engine as _;
use serde::Serialize;
use tauri::State;
use zeroize::Zeroize;

use crate::crypto::passcode;
use crate::crypto::provider::{
    self,
    status::{AlgorithmStatus, Certificate, ModuleIdentity},
    SelfTestReport,
};
use crate::error::{QGuardError, Result};
use crate::state::AppState;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub id: &'static str,
    pub label: &'static str,
    pub kdf: &'static str,
    /// Stretched with an approved KDF (PBKDF2).
    pub approved_kdf: bool,
    /// What approved mode asks of this credential is met.
    pub meets_approved_mode: bool,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pbkdf2Policy {
    pub prf: &'static str,
    pub iterations: u32,
    pub salt_bits: u32,
    pub vault_password_min_chars: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoModuleStatus {
    pub module: ModuleIdentity,
    /// A FIPS build of the module, reporting itself operational, whose version
    /// maps to a CMVP certificate. Never true for the default backend.
    pub fips_validated_module: bool,
    pub certificate: Option<Certificate>,
    pub approved_mode: bool,
    /// "build" | "environment" | "setting"
    pub approved_mode_source: &'static str,
    pub self_test: SelfTestReport,
    pub algorithms: Vec<AlgorithmStatus>,
    pub outside_boundary: Vec<&'static str>,
    pub credentials: Vec<CredentialStatus>,
    pub pbkdf2: Pbkdf2Policy,
}

fn kdf_status(id: &'static str, label: &'static str, kdf: u8, meets: bool, note: Option<String>) -> CredentialStatus {
    CredentialStatus {
        id,
        label,
        kdf: passcode::kdf_label(kdf),
        approved_kdf: passcode::kdf_is_approved(kdf),
        meets_approved_mode: meets,
        note,
    }
}

/// The signed-in account's unlock credentials on this device, from their records.
fn credentials(state: &AppState) -> Vec<CredentialStatus> {
    let Ok(user_id) = state.user_id() else {
        return Vec::new();
    };
    let min = provider::APPROVED_PASSWORD_MIN_CHARS;
    let mut out = Vec::new();
    if let Ok(Some(vault)) = state.load_workspace_scope(&user_id, "vault") {
        if let Some(password) = vault.password.as_ref() {
            let note = (!password.approved_strength).then(|| {
                if passcode::kdf_is_approved(password.kdf_version) {
                    format!("Shorter than {min} characters: change it to meet approved mode.")
                } else {
                    "Re-sealed with PBKDF2 at the next unlock while approved mode is on.".to_string()
                }
            });
            out.push(kdf_status("vault-password", "Quantum Vault password", password.kdf_version, password.approved_strength, note));
        }
        if let Some(pin) = vault.pin.as_ref() {
            out.push(kdf_status(
                "vault-pin",
                "Quantum Vault PIN",
                pin.kdf_version,
                false,
                Some(format!(
                    "Approved mode needs a vault password of {min}+ characters. A PIN keeps Argon2id: PBKDF2 would make it easier to guess."
                )),
            ));
        }
    }
    if let Ok(Some(chat)) = state.load_workspace_scope(&user_id, "chat") {
        for (id, label, credential) in [
            ("chat-password", "Secure Chat password", chat.password.as_ref()),
            ("chat-pin", "Secure Chat PIN", chat.pin.as_ref()),
        ] {
            if let Some(credential) = credential {
                let approved = passcode::kdf_is_approved(credential.kdf_version);
                out.push(kdf_status(
                    id,
                    label,
                    credential.kdf_version,
                    approved,
                    (!approved).then(|| "Re-sealed with PBKDF2 at the next unlock while approved mode is on.".to_string()),
                ));
            }
        }
    }
    if let Ok(Some(lock)) = state.load_applock(&user_id) {
        let approved = passcode::kdf_is_approved(lock.kdf_version);
        out.push(kdf_status(
            "app-pin",
            "App lock PIN",
            lock.kdf_version,
            approved,
            Some(format!(
                "{}-digit PIN. The session it unlocks is also sealed under the device key store.",
                lock.digits
            )),
        ));
        if let Some(duress) = lock.duress.as_ref() {
            let approved = passcode::kdf_is_approved(duress.kdf_version);
            out.push(kdf_status(
                "duress-pin",
                "Duress PIN",
                duress.kdf_version,
                approved,
                (!approved).then(|| "Set it again to seal it with PBKDF2.".to_string()),
            ));
        }
    }
    out
}

fn status(state: &AppState) -> CryptoModuleStatus {
    let module = provider::module_identity();
    let certificate = module
        .fips_module_version
        .as_deref()
        .filter(|_| module.backend == "wolfcrypt")
        .and_then(provider::status::wolfcrypt_certificate);
    let fips_validated_module = certificate.is_some() && module.fips_status == Some(0);
    let approved_mode_source = if provider::approved_mode_forced() {
        "build"
    } else if AppState::fips_approved_mode_env().is_some() {
        "environment"
    } else {
        "setting"
    };
    CryptoModuleStatus {
        algorithms: provider::status::algorithms(&module.backend, certificate.as_ref().filter(|_| fips_validated_module)),
        module,
        fips_validated_module,
        certificate,
        approved_mode: provider::approved_mode(),
        approved_mode_source,
        self_test: provider::self_test_report().clone(),
        outside_boundary: provider::status::outside_boundary(),
        credentials: credentials(state),
        pbkdf2: Pbkdf2Policy {
            prf: "HMAC-SHA-512",
            iterations: provider::APPROVED_PBKDF2_ITERATIONS,
            salt_bits: 128,
            vault_password_min_chars: provider::APPROVED_PASSWORD_MIN_CHARS,
        },
    }
}

#[tauri::command]
pub fn crypto_module_status(state: State<'_, AppState>) -> Result<CryptoModuleStatus> {
    Ok(status(&state))
}

/// Switch FIPS approved mode on this device. Refused when a build or the
/// operator switch decides it, or while a self-test has failed (approved mode
/// on a module in its error state would be a claim with nothing behind it).
#[tauri::command]
pub fn crypto_set_approved_mode(state: State<'_, AppState>, enabled: bool) -> Result<CryptoModuleStatus> {
    state.require_auth()?;
    if provider::approved_mode_forced() {
        return Err(QGuardError::InvalidInput("This build always runs in FIPS approved mode.".to_string()));
    }
    if AppState::fips_approved_mode_env().is_some() {
        return Err(QGuardError::InvalidInput(
            "FIPS approved mode is set by QGUARD_FIPS_APPROVED_MODE on this device.".to_string(),
        ));
    }
    if enabled && !provider::self_test_report().passed {
        return Err(QGuardError::Crypto(
            "The cryptographic self-test failed on this device; approved mode cannot be switched on.".to_string(),
        ));
    }
    state.set_fips_approved_mode(enabled)?;
    state.audit_info(
        "fips_approved_mode",
        if enabled {
            "FIPS approved mode on: new credentials use PBKDF2-HMAC-SHA-512; existing ones re-seal at their next unlock"
        } else {
            "FIPS approved mode off: new credentials use Argon2id"
        },
    );
    Ok(status(&state))
}

// ---- services for the WebView ----------------------------------------------
//
// Bytes cross the IPC as base64 strings inside ordinary JSON arguments, never
// as a raw request body. Android's WebView cannot hand a request body to the
// app, so Tauri delivers every Android call as JSON (`InvokeBody::Json`, with
// a `Uint8Array` turned into an array of numbers), and desktop does the same
// whenever its custom IPC protocol falls back to postMessage (this app's CSP
// has no `ipc:` source). A command that insisted on `InvokeBody::Raw` failed
// with "expected raw bytes" on both. Base64 is what Tauri recommends instead.

fn decode_b64(value: &str, what: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| QGuardError::InvalidInput(format!("{what} is not valid base64")))
}

fn encode_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Digest (base64) of the base64 `data_b64`. `algorithm`: `sha3-256`,
/// `sha256`, `sha3-512` or `sha512`.
#[tauri::command]
pub fn crypto_digest(algorithm: String, data_b64: String) -> Result<String> {
    let data = decode_b64(&data_b64, "digest input")?;
    let digest = match algorithm.as_str() {
        "sha3-256" => provider::sha3_256(&data).to_vec(),
        "sha3-512" => provider::sha3_512(&data).to_vec(),
        "sha256" => provider::sha256(&data).to_vec(),
        "sha512" => provider::sha512(&data).to_vec(),
        other => return Err(QGuardError::InvalidInput(format!("unsupported digest: {other}"))),
    };
    Ok(encode_b64(&digest))
}

/// HMAC-SHA3-256 (hex) of `message` under the base64url `key_b64url`.
#[tauri::command]
pub fn crypto_hmac_sha3_256(key_b64url: String, message: String) -> Result<String> {
    let mut key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key_b64url.trim_end_matches('='))
        .map_err(|_| QGuardError::InvalidInput("HMAC key is not valid base64url".to_string()))?;
    let tag = provider::hmac_sha3_256(&key, message.as_bytes());
    key.zeroize();
    Ok(hex::encode(tag?))
}

/// A sealed chat attachment, in the fields the message carries: the raw
/// AES-256 key and the nonce (inside the end-to-end encrypted message), and
/// `ciphertext || tag` (what is uploaded) — the layout WebCrypto produced.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedAttachment {
    pub key_b64: String,
    pub iv_b64: String,
    pub sealed_b64: String,
}

fn seal_attachment(plaintext_b64: &str, aad_b64: &str) -> Result<SealedAttachment> {
    let mut plaintext = decode_b64(plaintext_b64, "attachment")?;
    let aad = decode_b64(aad_b64, "attachment AAD")?;
    let mut key: [u8; 32] = provider::random_array();
    let sealed = provider::aes256gcm_seal(&key, &aad, &plaintext);
    plaintext.zeroize();
    let out = sealed.map(|sealed| {
        let mut body = sealed.ciphertext;
        body.extend_from_slice(&sealed.tag);
        SealedAttachment { key_b64: encode_b64(&key), iv_b64: encode_b64(&sealed.nonce), sealed_b64: encode_b64(&body) }
    });
    key.zeroize();
    out
}

fn open_attachment(sealed_b64: &str, key_b64: &str, iv_b64: &str, aad_b64: Option<&str>) -> Result<String> {
    let body = decode_b64(sealed_b64, "attachment ciphertext")?;
    let mut key = decode_b64(key_b64, "attachment key")?;
    let nonce = decode_b64(iv_b64, "attachment nonce")?;
    let aad = aad_b64.map(|value| decode_b64(value, "attachment AAD")).transpose()?.unwrap_or_default();
    let opened = (|| {
        let key: &[u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| QGuardError::InvalidInput("attachment key must be 32 bytes".to_string()))?;
        let split = body
            .len()
            .checked_sub(provider::AES_GCM_TAG_BYTES)
            .ok_or_else(|| QGuardError::InvalidInput("attachment ciphertext is truncated".to_string()))?;
        provider::aes256gcm_open(key, &nonce, &aad, &body[..split], &body[split..])
    })();
    key.zeroize();
    let mut plaintext = opened?;
    let out = encode_b64(&plaintext);
    plaintext.zeroize();
    Ok(out)
}

/// Seal a chat attachment with a fresh AES-256-GCM key and nonce chosen by
/// the module. `aad_b64` binds it to its storage path, conversation and message.
#[tauri::command]
pub async fn crypto_attachment_seal(plaintext_b64: String, aad_b64: String) -> Result<SealedAttachment> {
    tauri::async_runtime::spawn_blocking(move || seal_attachment(&plaintext_b64, &aad_b64))
        .await
        .map_err(|e| QGuardError::Crypto(format!("attachment worker failed: {e}")))?
}

/// Open a chat attachment; returns the plaintext (base64). `aad_b64` is absent
/// for attachments sealed before the associated-data binding.
#[tauri::command]
pub async fn crypto_attachment_open(
    sealed_b64: String,
    key_b64: String,
    iv_b64: String,
    aad_b64: Option<String>,
) -> Result<String> {
    tauri::async_runtime::spawn_blocking(move || open_attachment(&sealed_b64, &key_b64, &iv_b64, aad_b64.as_deref()))
        .await
        .map_err(|e| QGuardError::Crypto(format!("attachment worker failed: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDevice;

    #[test]
    fn the_status_reports_the_active_module_honestly() {
        let device = TestDevice::new(false);
        let status = status(&device.state);
        assert!(status.self_test.passed, "{:?}", status.self_test.results);
        #[cfg(not(feature = "wolfcrypt"))]
        {
            assert_eq!(status.module.backend, "rustcrypto");
            assert!(!status.fips_validated_module);
            assert!(status.certificate.is_none());
            assert!(status.algorithms.iter().all(|a| !a.validated), "nothing is validated in the default build");
        }
        let x25519 = status.algorithms.iter().find(|a| a.id == "x25519").unwrap();
        assert!(!x25519.approved);
        let ml_kem = status.algorithms.iter().find(|a| a.id == "ml-kem-1024").unwrap();
        assert!(ml_kem.approved);
        assert_eq!(status.pbkdf2.iterations, 600_000);
        assert!(!status.outside_boundary.is_empty());
    }

    #[test]
    fn a_wolfcrypt_fips_version_maps_to_its_certificate_and_nothing_else_does() {
        let cert = provider::status::wolfcrypt_certificate("5.2.3").unwrap();
        assert_eq!(cert.number, 5548);
        assert!(cert.tested_platforms.iter().any(|p| p.starts_with("Android 13")));
        assert!(cert.tested_platforms.iter().any(|p| p.starts_with("Windows 11")));
        assert!(!cert.covers.contains(&"ml-kem-1024"), "no wolfCrypt certificate lists ML-KEM yet");
        assert!(provider::status::wolfcrypt_certificate("5.9.4").is_none());
        let algorithms = provider::status::algorithms("wolfcrypt", Some(&cert));
        let validated: Vec<_> = algorithms.iter().filter(|a| a.validated).map(|a| a.id).collect();
        assert_eq!(validated, vec!["aes-256-gcm", "sha3", "sha2", "hmac-sha3-256", "drbg"]);
    }

    #[test]
    fn an_attachment_round_trips_as_base64_and_only_with_its_aad() {
        let aad = encode_b64(b"user/chat-attachments/c/m/file.bin|c|m");
        let sealed = seal_attachment(&encode_b64(b"attachment bytes"), &aad).unwrap();
        assert_eq!(decode_b64(&sealed.key_b64, "key").unwrap().len(), 32);
        assert_eq!(decode_b64(&sealed.iv_b64, "iv").unwrap().len(), 12);
        assert_eq!(decode_b64(&sealed.sealed_b64, "sealed").unwrap().len(), b"attachment bytes".len() + 16);
        let opened = open_attachment(&sealed.sealed_b64, &sealed.key_b64, &sealed.iv_b64, Some(&aad)).unwrap();
        assert_eq!(decode_b64(&opened, "plaintext").unwrap(), b"attachment bytes");
        // Moved to another path / message, or stripped of its AAD: refused.
        assert!(open_attachment(&sealed.sealed_b64, &sealed.key_b64, &sealed.iv_b64, Some(&encode_b64(b"elsewhere"))).is_err());
        assert!(open_attachment(&sealed.sealed_b64, &sealed.key_b64, &sealed.iv_b64, None).is_err());
    }

    /// Attachments sealed by earlier builds (WebCrypto AES-GCM, ciphertext || tag)
    /// open unchanged: the GCM specification's test case 16, as an attachment.
    #[test]
    fn a_webcrypto_sealed_attachment_still_opens() {
        let unhex = |value: &str| hex::decode(value).unwrap();
        let mut body = unhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
        body.extend_from_slice(&unhex("76fc6ece0f4e1768cddf8853bb2d551b"));
        let opened = open_attachment(
            &encode_b64(&body),
            &encode_b64(&unhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")),
            &encode_b64(&unhex("cafebabefacedbaddecaf888")),
            Some(&encode_b64(&unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"))),
        )
        .unwrap();
        assert_eq!(
            hex::encode(decode_b64(&opened, "plaintext").unwrap()),
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        );
        // An attachment from before the AAD binding: sealed with no AAD, opened with none.
        let key: [u8; 32] = provider::random_array();
        let legacy = provider::aes256gcm_seal(&key, b"", b"old attachment").unwrap();
        let mut body = legacy.ciphertext;
        body.extend_from_slice(&legacy.tag);
        let opened = open_attachment(&encode_b64(&body), &encode_b64(&key), &encode_b64(&legacy.nonce), None).unwrap();
        assert_eq!(decode_b64(&opened, "plaintext").unwrap(), b"old attachment");
    }

    #[test]
    fn digests_come_back_as_base64() {
        let sha3 = crypto_digest("sha3-256".into(), encode_b64(b"abc")).unwrap();
        assert_eq!(hex::encode(decode_b64(&sha3, "digest").unwrap()), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        let sha256 = crypto_digest("sha256".into(), encode_b64(b"abc")).unwrap();
        assert_eq!(hex::encode(decode_b64(&sha256, "digest").unwrap()), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert!(crypto_digest("md5".into(), encode_b64(b"abc")).is_err());
    }

    /// Android never delivers a raw IPC body, and desktop does not either once
    /// its IPC falls back to postMessage: a command that needs one fails with
    /// "expected raw bytes" (the attachment bug of 2026-11-03).
    #[test]
    fn no_command_requires_a_raw_ipc_body() {
        fn scan(dir: &std::path::Path, needle: &str, hits: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    scan(&path, needle, hits);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    for (index, line) in text.lines().enumerate() {
                        if line.contains(needle) && !line.trim_start().starts_with("//") {
                            hits.push(format!("{}:{}", path.display(), index + 1));
                        }
                    }
                }
            }
        }
        let needle = ["InvokeBody", "::Raw"].concat();
        let mut hits = Vec::new();
        scan(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &needle, &mut hits);
        assert!(hits.is_empty(), "take bytes as base64 JSON arguments instead: {hits:?}");
    }
}
