use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine as _;
use chrono::Utc;
use keyring::Error as KeyringError;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::audit::{AuditChain, AuditSeverity};
use crate::crypto::hybrid_kex::LocalKemKeypair;
use crate::device_trust::TrustedDevice;
use crate::error::{QGuardError, Result};
use crate::identity::{LocalIdentity, PublicIdentityBundle};
use crate::prekeys::{
    generate_one_time_prekeys, generate_signed_prekey, LocalOneTimePrekey, LocalSignedPrekey,
};
use crate::ratchet::RatchetSession;
use crate::telemetry::TelemetryEvent;

const KEYRING_SERVICE: &str = "QGuard Messaging Device Keys";
const KEY_MATERIAL_AAD: &[u8] = b"QGuard-Messaging-Device-Key-Material-v1";
const VAULT_RECOVERY_AAD: &[u8] = b"QGuard-Messaging-Vault-Recovery-Material-v1";

/// On-disk container for the AES-256-GCM-encrypted device key material.
///
/// The full key material (ML-KEM-1024 secrets + one-time prekeys) is far larger
/// than the OS keychain blob limit (Windows Credential Manager caps a credential
/// at 2560 bytes), so it lives in an encrypted file. Only the 32-byte data
/// encryption key is held in the OS keychain.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct EncryptedKeyMaterialFile {
    version: u8,
    envelope: crate::crypto::EncryptedEnvelope,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedDeviceKeyMaterial {
    identity: LocalIdentity,
    signed_prekey: LocalSignedPrekey,
    one_time_prekeys: Vec<LocalOneTimePrekey>,
    #[serde(default)]
    legacy_kem_keypairs: Vec<LocalKemKeypair>,
    #[serde(default)]
    legacy_signed_prekeys: Vec<LocalSignedPrekey>,
    #[serde(default)]
    legacy_one_time_prekeys: Vec<LocalOneTimePrekey>,
    persisted_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyMaterialStatus {
    Generated,
    Restored,
    Upgraded,
}

/// Device-local, encrypted-at-rest copy of the vault recovery material. Stores
/// only the derived AES wrapping key + a verifier — never the recovery root,
/// which lives solely with the user. Lets this device keep adding the recovery
/// wrap to new files without re-prompting for the recovery key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedVaultRecovery {
    pub version: u8,
    /// Personal-mode AES wrap key (zeros/unused for enterprise mode).
    pub wrap_key: [u8; crate::crypto::symmetric::KEY_SIZE],
    pub verifier: String,
    pub configured_at: chrono::DateTime<Utc>,
    /// "personal" | "enterprise" | "hybrid" (None on legacy records => personal).
    #[serde(default)]
    pub mode: Option<String>,
    /// Hybrid mode: the recovery root, kept device-local (encrypted at rest) so
    /// this device can keep wrapping new files; never sent to the server.
    #[serde(default)]
    pub recovery_root: Option<[u8; crate::crypto::symmetric::KEY_SIZE]>,
    /// Enterprise/hybrid: the enterprise recovery public key used to wrap files.
    #[serde(default)]
    pub enterprise_x25519_public: Option<Vec<u8>>,
    #[serde(default)]
    pub enterprise_mlkem_public: Option<Vec<u8>>,
    #[serde(default)]
    pub recipient_key_id: Option<String>,
}

impl PersistedVaultRecovery {
    pub fn personal(wrap_key: [u8; crate::crypto::symmetric::KEY_SIZE], verifier: String) -> Self {
        Self {
            version: 1,
            wrap_key,
            verifier,
            configured_at: Utc::now(),
            mode: Some("personal".to_string()),
            recovery_root: None,
            enterprise_x25519_public: None,
            enterprise_mlkem_public: None,
            recipient_key_id: None,
        }
    }

    pub fn recovery_mode(&self) -> &str {
        self.mode.as_deref().unwrap_or("personal")
    }
}

#[derive(Clone, Debug)]
pub struct AuthSession {
    pub user_id: String,
    pub email: String,
    pub tier: String,
    pub access_token: String,
    pub expires_at: i64,
}

pub struct AppState {
    pub data_dir: PathBuf,
    pub key_scope: Mutex<()>,
    pub identity: Mutex<Option<LocalIdentity>>,
    pub signed_prekey: Mutex<Option<LocalSignedPrekey>>,
    pub one_time_prekeys: Mutex<Vec<LocalOneTimePrekey>>,
    pub legacy_kem_keypairs: Mutex<Vec<LocalKemKeypair>>,
    pub legacy_signed_prekeys: Mutex<Vec<LocalSignedPrekey>>,
    pub legacy_one_time_prekeys: Mutex<Vec<LocalOneTimePrekey>>,
    pub ratchets: Mutex<HashMap<String, RatchetSession>>,
    pub decrypted_message_cache: Mutex<HashMap<String, String>>,
    pub devices: Mutex<HashMap<String, TrustedDevice>>,
    pub audit: Mutex<AuditChain>,
    pub telemetry: Mutex<Vec<TelemetryEvent>>,
    pub auth_session: Mutex<Option<AuthSession>>,
    pub auth_sessions: Mutex<HashMap<String, AuthSession>>,
    pub decrypt_attempts: Mutex<HashMap<String, Vec<i64>>>,
}

impl AppState {
    pub fn new(data_dir: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(data_dir.join("keys"))?;
        std::fs::create_dir_all(data_dir.join("messages"))?;
        std::fs::create_dir_all(data_dir.join("vault"))?;
        Ok(Self {
            data_dir,
            key_scope: Mutex::new(()),
            identity: Mutex::new(None),
            signed_prekey: Mutex::new(None),
            one_time_prekeys: Mutex::new(Vec::new()),
            legacy_kem_keypairs: Mutex::new(Vec::new()),
            legacy_signed_prekeys: Mutex::new(Vec::new()),
            legacy_one_time_prekeys: Mutex::new(Vec::new()),
            ratchets: Mutex::new(HashMap::new()),
            decrypted_message_cache: Mutex::new(HashMap::new()),
            devices: Mutex::new(HashMap::new()),
            audit: Mutex::new(AuditChain::default()),
            telemetry: Mutex::new(Vec::new()),
            auth_session: Mutex::new(None),
            auth_sessions: Mutex::new(HashMap::new()),
            decrypt_attempts: Mutex::new(HashMap::new()),
        })
    }

    pub fn ensure_identity(&self, user_id: &str, label: &str) -> Result<PublicIdentityBundle> {
        let mut identity_guard = self
            .identity
            .lock()
            .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
        if identity_guard
            .as_ref()
            .map(|identity| identity.user_id.as_str() != user_id)
            .unwrap_or(true)
        {
            let (
                identity,
                signed,
                otks,
                legacy_kem_keypairs,
                legacy_signed_prekeys,
                legacy_one_time_prekeys,
                material_status,
            ) = match self.load_device_key_material(user_id) {
                Ok(Some(material)) => {
                    if Self::key_material_uses_current_pq_suite(&material) {
                        (
                            material.identity,
                            material.signed_prekey,
                            material.one_time_prekeys,
                            material.legacy_kem_keypairs,
                            material.legacy_signed_prekeys,
                            material.legacy_one_time_prekeys,
                            KeyMaterialStatus::Restored,
                        )
                    } else {
                        let mut legacy_kem_keypairs = material.legacy_kem_keypairs;
                        legacy_kem_keypairs.push(material.identity.kem.clone());
                        let mut legacy_signed_prekeys = material.legacy_signed_prekeys;
                        legacy_signed_prekeys.push(material.signed_prekey);
                        let mut legacy_one_time_prekeys = material.legacy_one_time_prekeys;
                        legacy_one_time_prekeys.extend(material.one_time_prekeys);
                        let device_label = if material.identity.device_label.trim().is_empty() {
                            label.to_string()
                        } else {
                            material.identity.device_label.clone()
                        };
                        let identity = LocalIdentity::generate(user_id, device_label)?;
                        let signed = generate_signed_prekey(&identity)?;
                        let otks = generate_one_time_prekeys(&identity, 24)?;
                        self.persist_device_key_material(
                            user_id,
                            &identity,
                            &signed,
                            &otks,
                            &legacy_kem_keypairs,
                            &legacy_signed_prekeys,
                            &legacy_one_time_prekeys,
                        )?;
                        (
                            identity,
                            signed,
                            otks,
                            legacy_kem_keypairs,
                            legacy_signed_prekeys,
                            legacy_one_time_prekeys,
                            KeyMaterialStatus::Upgraded,
                        )
                    }
                }
                Ok(None) => {
                    let identity = LocalIdentity::generate(user_id, label)?;
                    let signed = generate_signed_prekey(&identity)?;
                    let otks = generate_one_time_prekeys(&identity, 24)?;
                    self.persist_device_key_material(
                        user_id,
                        &identity,
                        &signed,
                        &otks,
                        &[],
                        &[],
                        &[],
                    )?;
                    (
                        identity,
                        signed,
                        otks,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        KeyMaterialStatus::Generated,
                    )
                }
                Err(_) => {
                    let identity = LocalIdentity::generate(user_id, label)?;
                    let signed = generate_signed_prekey(&identity)?;
                    let otks = generate_one_time_prekeys(&identity, 24)?;
                    self.persist_device_key_material(
                        user_id,
                        &identity,
                        &signed,
                        &otks,
                        &[],
                        &[],
                        &[],
                    )?;
                    (
                        identity,
                        signed,
                        otks,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        KeyMaterialStatus::Generated,
                    )
                }
            };
            let bundle = identity.public_bundle()?;

            self.signed_prekey
                .lock()
                .map_err(|_| QGuardError::Storage("prekey lock poisoned".to_string()))?
                .replace(signed);
            *self
                .one_time_prekeys
                .lock()
                .map_err(|_| QGuardError::Storage("one-time prekey lock poisoned".to_string()))? =
                otks;
            *self.legacy_kem_keypairs.lock().map_err(|_| {
                QGuardError::Storage("legacy KEM keypair lock poisoned".to_string())
            })? = legacy_kem_keypairs;
            *self.legacy_signed_prekeys.lock().map_err(|_| {
                QGuardError::Storage("legacy signed prekey lock poisoned".to_string())
            })? = legacy_signed_prekeys;
            *self.legacy_one_time_prekeys.lock().map_err(|_| {
                QGuardError::Storage("legacy one-time prekey lock poisoned".to_string())
            })? = legacy_one_time_prekeys;
            self.devices
                .lock()
                .map_err(|_| QGuardError::Storage("device lock poisoned".to_string()))?
                .insert(
                    bundle.device_id.clone(),
                    TrustedDevice::new_this_device(
                        user_id.to_string(),
                        bundle.device_id.clone(),
                        label.to_string(),
                        bundle.fingerprint.clone(),
                    ),
                );
            self.audit
                .lock()
                .map_err(|_| QGuardError::Storage("audit lock poisoned".to_string()))?
                .append(
                    "device_registered",
                    AuditSeverity::Info,
                    match material_status {
                        KeyMaterialStatus::Restored => {
                            "Local hybrid identity restored from secure app storage"
                        }
                        KeyMaterialStatus::Upgraded => {
                            "Local hybrid identity upgraded to ML-KEM-1024 and persisted"
                        }
                        KeyMaterialStatus::Generated => {
                            "Local hybrid identity generated and persisted"
                        }
                    },
                );
            self.telemetry
                .lock()
                .map_err(|_| QGuardError::Storage("telemetry lock poisoned".to_string()))?
                .push(TelemetryEvent::new(
                    "identity",
                    match material_status {
                        KeyMaterialStatus::Restored => "Hybrid identity and prekeys restored",
                        KeyMaterialStatus::Upgraded => {
                            "Hybrid identity and prekeys upgraded to ML-KEM-1024"
                        }
                        KeyMaterialStatus::Generated => "Hybrid identity and prekeys generated",
                    },
                    100,
                ));
            *identity_guard = Some(identity);
        }

        identity_guard
            .as_ref()
            .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?
            .public_bundle()
    }

    fn safe_user_key(user_id: &str) -> String {
        user_id
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                    ch
                } else {
                    '_'
                }
            })
            .collect::<String>()
    }

    fn key_material_path(&self, user_id: &str) -> PathBuf {
        let safe_user_id = Self::safe_user_key(user_id);
        self.data_dir
            .join("keys")
            .join(format!("{safe_user_id}.device-key-material.json"))
    }

    fn encrypted_key_material_path(&self, user_id: &str) -> PathBuf {
        let safe_user_id = Self::safe_user_key(user_id);
        self.data_dir
            .join("keys")
            .join(format!("{safe_user_id}.device-key-material.enc"))
    }

    fn key_material_entry(&self, user_id: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(KEYRING_SERVICE, &Self::safe_user_key(user_id))
            .map_err(|e| QGuardError::Storage(format!("open OS keychain entry: {e}")))
    }

    /// Returns the per-user 32-byte data encryption key, creating and persisting
    /// one in the OS keychain on first use. The keychain only ever holds this
    /// small key, never the (much larger) key material itself.
    fn device_storage_key(
        &self,
        user_id: &str,
    ) -> Result<[u8; crate::crypto::symmetric::KEY_SIZE]> {
        let entry = self.key_material_entry(user_id)?;
        match entry.get_password() {
            Ok(encoded) => {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(encoded.trim())
                    .map_err(|e| {
                        QGuardError::Storage(format!("decode device storage key: {e}"))
                    })?;
                if decoded.len() != crate::crypto::symmetric::KEY_SIZE {
                    return Err(QGuardError::Storage(
                        "device storage key has unexpected length".to_string(),
                    ));
                }
                let mut key = [0u8; crate::crypto::symmetric::KEY_SIZE];
                key.copy_from_slice(&decoded);
                Ok(key)
            }
            Err(KeyringError::NoEntry) => {
                let key = crate::crypto::symmetric::random_key();
                let encoded = base64::engine::general_purpose::STANDARD.encode(key);
                entry.set_password(&encoded).map_err(|e| {
                    QGuardError::Storage(format!(
                        "write device storage key to OS keychain: {e}"
                    ))
                })?;
                Ok(key)
            }
            Err(error) => Err(QGuardError::Storage(format!(
                "read device storage key from OS keychain: {error}"
            ))),
        }
    }

    fn load_device_key_material(
        &self,
        user_id: &str,
    ) -> Result<Option<PersistedDeviceKeyMaterial>> {
        let encrypted_path = self.encrypted_key_material_path(user_id);
        if encrypted_path.exists() {
            let bytes = std::fs::read(&encrypted_path).map_err(|e| {
                QGuardError::Storage(format!("read encrypted device key material: {e}"))
            })?;
            let file: EncryptedKeyMaterialFile = serde_json::from_slice(&bytes).map_err(|e| {
                QGuardError::Storage(format!("decode encrypted device key material: {e}"))
            })?;
            let key = self.device_storage_key(user_id)?;
            let mut plaintext =
                crate::crypto::symmetric::decrypt(&key, &file.envelope, KEY_MATERIAL_AAD)?;
            let material = Self::decode_device_key_material(user_id, &plaintext);
            plaintext.zeroize();
            return Ok(Some(material?));
        }

        // Migrate any legacy plaintext key material written by older builds.
        if let Some(material) = self.load_legacy_device_key_material(user_id)? {
            self.persist_device_key_material(
                user_id,
                &material.identity,
                &material.signed_prekey,
                &material.one_time_prekeys,
                &material.legacy_kem_keypairs,
                &material.legacy_signed_prekeys,
                &material.legacy_one_time_prekeys,
            )?;
            let _ = std::fs::remove_file(self.key_material_path(user_id));
            return Ok(Some(material));
        }

        Ok(None)
    }

    fn load_legacy_device_key_material(
        &self,
        user_id: &str,
    ) -> Result<Option<PersistedDeviceKeyMaterial>> {
        let path = self.key_material_path(user_id);
        if !path.exists() {
            return Ok(None);
        }
        let mut bytes = std::fs::read(&path)
            .map_err(|e| QGuardError::Storage(format!("read device key material: {e}")))?;
        let material = Self::decode_device_key_material(user_id, &bytes)?;
        bytes.zeroize();
        Ok(Some(material))
    }

    fn decode_device_key_material(
        user_id: &str,
        bytes: &[u8],
    ) -> Result<PersistedDeviceKeyMaterial> {
        let material: PersistedDeviceKeyMaterial = serde_json::from_slice(bytes)
            .map_err(|e| QGuardError::Storage(format!("decode device key material: {e}")))?;
        if material.identity.user_id != user_id {
            return Err(QGuardError::Trust(
                "persisted device key material belongs to another user".to_string(),
            ));
        }
        Ok(material)
    }

    fn key_material_uses_current_pq_suite(material: &PersistedDeviceKeyMaterial) -> bool {
        material.identity.kem.is_current_suite()
            && LocalKemKeypair::is_current_public_key(&material.signed_prekey.public.mlkem_public)
            && LocalKemKeypair::is_current_secret_key(&material.signed_prekey.mlkem_secret)
            && material.one_time_prekeys.iter().all(|prekey| {
                LocalKemKeypair::is_current_public_key(&prekey.public.mlkem_public)
                    && LocalKemKeypair::is_current_secret_key(&prekey.mlkem_secret)
            })
    }

    fn persist_device_key_material(
        &self,
        user_id: &str,
        identity: &LocalIdentity,
        signed_prekey: &LocalSignedPrekey,
        one_time_prekeys: &[LocalOneTimePrekey],
        legacy_kem_keypairs: &[LocalKemKeypair],
        legacy_signed_prekeys: &[LocalSignedPrekey],
        legacy_one_time_prekeys: &[LocalOneTimePrekey],
    ) -> Result<()> {
        let material = PersistedDeviceKeyMaterial {
            identity: identity.clone(),
            signed_prekey: signed_prekey.clone(),
            one_time_prekeys: one_time_prekeys.to_vec(),
            legacy_kem_keypairs: legacy_kem_keypairs.to_vec(),
            legacy_signed_prekeys: legacy_signed_prekeys.to_vec(),
            legacy_one_time_prekeys: legacy_one_time_prekeys.to_vec(),
            persisted_at: Utc::now(),
        };
        let mut encoded = serde_json::to_vec(&material)
            .map_err(|e| QGuardError::Storage(format!("encode device key material: {e}")))?;
        let key = self.device_storage_key(user_id)?;
        let envelope = crate::crypto::symmetric::encrypt(&key, &encoded, KEY_MATERIAL_AAD);
        encoded.zeroize();
        let file = EncryptedKeyMaterialFile {
            version: 1,
            envelope: envelope?,
        };
        let serialized = serde_json::to_vec(&file).map_err(|e| {
            QGuardError::Storage(format!("encode encrypted device key material: {e}"))
        })?;
        std::fs::write(self.encrypted_key_material_path(user_id), &serialized).map_err(|e| {
            QGuardError::Storage(format!("write encrypted device key material: {e}"))
        })?;
        // Remove any legacy plaintext material now that the encrypted copy is authoritative.
        let _ = std::fs::remove_file(self.key_material_path(user_id));
        Ok(())
    }

    pub fn persist_current_device_key_material(&self) -> Result<()> {
        let identity = self
            .identity
            .lock()
            .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?
            .clone()
            .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
        let signed_prekey = self
            .signed_prekey
            .lock()
            .map_err(|_| QGuardError::Storage("signed prekey lock poisoned".to_string()))?
            .clone()
            .ok_or_else(|| QGuardError::NotFound("signed prekey".to_string()))?;
        let one_time_prekeys = self
            .one_time_prekeys
            .lock()
            .map_err(|_| QGuardError::Storage("one-time prekey lock poisoned".to_string()))?
            .clone();
        let legacy_kem_keypairs = self
            .legacy_kem_keypairs
            .lock()
            .map_err(|_| QGuardError::Storage("legacy KEM keypair lock poisoned".to_string()))?
            .clone();
        let legacy_signed_prekeys = self
            .legacy_signed_prekeys
            .lock()
            .map_err(|_| QGuardError::Storage("legacy signed prekey lock poisoned".to_string()))?
            .clone();
        let legacy_one_time_prekeys = self
            .legacy_one_time_prekeys
            .lock()
            .map_err(|_| QGuardError::Storage("legacy one-time prekey lock poisoned".to_string()))?
            .clone();
        self.persist_device_key_material(
            &identity.user_id,
            &identity,
            &signed_prekey,
            &one_time_prekeys,
            &legacy_kem_keypairs,
            &legacy_signed_prekeys,
            &legacy_one_time_prekeys,
        )
    }

    fn vault_recovery_path(&self, user_id: &str) -> PathBuf {
        let safe_user_id = Self::safe_user_key(user_id);
        self.data_dir
            .join("keys")
            .join(format!("{safe_user_id}.vault-recovery.enc"))
    }

    /// Persist the derived recovery wrapping key + verifier for this user,
    /// encrypted at rest under the same OS-keychain-held DEK as the device keys.
    pub fn save_vault_recovery(&self, user_id: &str, material: &PersistedVaultRecovery) -> Result<()> {
        let mut encoded = serde_json::to_vec(material)
            .map_err(|e| QGuardError::Storage(format!("encode vault recovery material: {e}")))?;
        let key = self.device_storage_key(user_id)?;
        let envelope = crate::crypto::symmetric::encrypt(&key, &encoded, VAULT_RECOVERY_AAD);
        encoded.zeroize();
        let file = EncryptedKeyMaterialFile {
            version: 1,
            envelope: envelope?,
        };
        let serialized = serde_json::to_vec(&file).map_err(|e| {
            QGuardError::Storage(format!("encode encrypted vault recovery: {e}"))
        })?;
        std::fs::write(self.vault_recovery_path(user_id), &serialized)
            .map_err(|e| QGuardError::Storage(format!("write vault recovery material: {e}")))?;
        Ok(())
    }

    pub fn load_vault_recovery(&self, user_id: &str) -> Result<Option<PersistedVaultRecovery>> {
        let path = self.vault_recovery_path(user_id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)
            .map_err(|e| QGuardError::Storage(format!("read vault recovery material: {e}")))?;
        let file: EncryptedKeyMaterialFile = serde_json::from_slice(&bytes)
            .map_err(|e| QGuardError::Storage(format!("decode vault recovery material: {e}")))?;
        let key = self.device_storage_key(user_id)?;
        let mut plaintext =
            crate::crypto::symmetric::decrypt(&key, &file.envelope, VAULT_RECOVERY_AAD)?;
        let material: PersistedVaultRecovery = serde_json::from_slice(&plaintext)
            .map_err(|e| QGuardError::Storage(format!("decode vault recovery payload: {e}")))?;
        plaintext.zeroize();
        Ok(Some(material))
    }

    pub fn set_auth_session(&self, session: AuthSession) -> Result<()> {
        self.auth_sessions
            .lock()
            .map_err(|_| QGuardError::Storage("auth session registry lock poisoned".to_string()))?
            .insert(session.user_id.clone(), session.clone());
        *self
            .auth_session
            .lock()
            .map_err(|_| QGuardError::Storage("auth session lock poisoned".to_string()))? =
            Some(session);
        Ok(())
    }

    pub fn clear_auth_session(&self) -> Result<()> {
        self.auth_sessions
            .lock()
            .map_err(|_| QGuardError::Storage("auth session registry lock poisoned".to_string()))?
            .clear();
        *self
            .auth_session
            .lock()
            .map_err(|_| QGuardError::Storage("auth session lock poisoned".to_string()))? = None;
        let _key_scope = self.lock_key_scope()?;
        self.clear_volatile_key_state()
    }

    pub fn clear_auth_session_for(&self, user_id: Option<&str>) -> Result<()> {
        let Some(user_id) = user_id.map(str::trim).filter(|value| !value.is_empty()) else {
            return self.clear_auth_session();
        };
        self.auth_sessions
            .lock()
            .map_err(|_| QGuardError::Storage("auth session registry lock poisoned".to_string()))?
            .remove(user_id);
        let mut current = self
            .auth_session
            .lock()
            .map_err(|_| QGuardError::Storage("auth session lock poisoned".to_string()))?;
        let clear_current = current
            .as_ref()
            .map(|session| session.user_id == user_id)
            .unwrap_or(false);
        if clear_current {
            *current = None;
            drop(current);
            let _key_scope = self.lock_key_scope()?;
            self.clear_volatile_key_state()?;
        }
        Ok(())
    }

    fn clear_volatile_key_state(&self) -> Result<()> {
        *self
            .identity
            .lock()
            .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))? = None;
        self.signed_prekey
            .lock()
            .map_err(|_| QGuardError::Storage("signed prekey lock poisoned".to_string()))?
            .take();
        self.one_time_prekeys
            .lock()
            .map_err(|_| QGuardError::Storage("one-time prekey lock poisoned".to_string()))?
            .clear();
        self.legacy_kem_keypairs
            .lock()
            .map_err(|_| QGuardError::Storage("legacy KEM keypair lock poisoned".to_string()))?
            .clear();
        self.legacy_signed_prekeys
            .lock()
            .map_err(|_| QGuardError::Storage("legacy signed prekey lock poisoned".to_string()))?
            .clear();
        self.legacy_one_time_prekeys
            .lock()
            .map_err(|_| QGuardError::Storage("legacy one-time prekey lock poisoned".to_string()))?
            .clear();
        self.ratchets
            .lock()
            .map_err(|_| QGuardError::Storage("ratchet lock poisoned".to_string()))?
            .clear();
        self.decrypted_message_cache
            .lock()
            .map_err(|_| QGuardError::Storage("decrypted message cache lock poisoned".to_string()))?
            .values_mut()
            .for_each(|plaintext| plaintext.zeroize());
        self.decrypted_message_cache
            .lock()
            .map_err(|_| QGuardError::Storage("decrypted message cache lock poisoned".to_string()))?
            .clear();
        self.devices
            .lock()
            .map_err(|_| QGuardError::Storage("device lock poisoned".to_string()))?
            .clear();
        self.decrypt_attempts
            .lock()
            .map_err(|_| QGuardError::Storage("decrypt attempt lock poisoned".to_string()))?
            .clear();
        Ok(())
    }

    pub fn require_auth(&self) -> Result<AuthSession> {
        let session = self
            .auth_session
            .lock()
            .map_err(|_| QGuardError::Storage("auth session lock poisoned".to_string()))?
            .clone()
            .ok_or_else(|| QGuardError::Trust("Supabase session required".to_string()))?;
        Self::validate_auth_session(session)
    }

    pub fn require_user_auth(&self, user_id: &str) -> Result<AuthSession> {
        let user_id = user_id.trim();
        if user_id.is_empty() {
            return Err(QGuardError::Trust("Supabase session required".to_string()));
        }
        if let Some(session) = self
            .auth_session
            .lock()
            .map_err(|_| QGuardError::Storage("auth session lock poisoned".to_string()))?
            .clone()
            .filter(|session| session.user_id == user_id)
        {
            return Self::validate_auth_session(session);
        }
        let session = self
            .auth_sessions
            .lock()
            .map_err(|_| QGuardError::Storage("auth session registry lock poisoned".to_string()))?
            .get(user_id)
            .cloned()
            .ok_or_else(|| {
                QGuardError::Trust("Supabase session required for requested user".to_string())
            })?;
        Self::validate_auth_session(session)
    }

    pub fn resolve_user_id(&self, user_id: Option<String>) -> Result<String> {
        if let Some(user_id) = user_id
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            self.require_user_auth(&user_id)?;
            return Ok(user_id);
        }
        self.user_id()
    }

    pub fn lock_key_scope(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.key_scope
            .lock()
            .map_err(|_| QGuardError::Storage("key operation lock poisoned".to_string()))
    }

    fn validate_auth_session(session: AuthSession) -> Result<AuthSession> {
        if session.expires_at <= Utc::now().timestamp() {
            return Err(QGuardError::Trust("Supabase session expired".to_string()));
        }
        Ok(session)
    }

    pub fn user_id(&self) -> Result<String> {
        Ok(self.require_auth()?.user_id)
    }

    pub fn check_decrypt_rate_limit(
        &self,
        scope: &str,
        target: &str,
        limit: usize,
        window_seconds: i64,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let floor = now - window_seconds;
        let key = format!("{scope}:{target}");
        let mut attempts = self
            .decrypt_attempts
            .lock()
            .map_err(|_| QGuardError::Storage("decrypt attempt lock poisoned".to_string()))?;
        let entry = attempts.entry(key).or_default();
        entry.retain(|timestamp| *timestamp >= floor);
        if entry.len() >= limit {
            return Err(QGuardError::Trust(
                "Too many secure key operations. Wait a few minutes and try again.".to_string(),
            ));
        }
        entry.push(now);
        Ok(())
    }

    pub fn touch_telemetry(&self, stage: &str, detail: &str, progress: u8) {
        if let Ok(mut telemetry) = self.telemetry.lock() {
            telemetry.push(TelemetryEvent::new(stage, detail, progress));
            if telemetry.len() > 200 {
                let excess = telemetry.len() - 200;
                telemetry.drain(0..excess);
            }
        }
    }

    pub fn audit_info(&self, event_type: &str, description: &str) {
        if let Ok(mut audit) = self.audit.lock() {
            audit.append(event_type, AuditSeverity::Info, description);
        }
    }

    pub fn seed_local_ratchet(&self, conversation_id: &str) -> Result<()> {
        let mut ratchets = self
            .ratchets
            .lock()
            .map_err(|_| QGuardError::Storage("ratchet lock poisoned".to_string()))?;
        if !ratchets.contains_key(conversation_id) {
            let seed = crate::crypto::kdf::derive_32(
                format!(
                    "{}:{conversation_id}:{}",
                    self.user_id()?,
                    Utc::now().timestamp()
                )
                .as_bytes(),
                b"QGuard-local-ratchet",
            )?;
            ratchets.insert(
                conversation_id.to_string(),
                RatchetSession::new(conversation_id, seed)?,
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("qguard-msg-test-{}", uuid::Uuid::new_v4()))
    }

    fn cleanup(user_id: &str, dir: &PathBuf) {
        if let Ok(entry) =
            keyring::Entry::new(KEYRING_SERVICE, &AppState::safe_user_key(user_id))
        {
            let _ = entry.delete_credential();
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Regression test for the keyring mock-store bug: a brand-new `AppState`
    /// over the same data directory (i.e. an app restart) must restore the same
    /// device identity and signed prekey instead of regenerating them. Before the
    /// fix, every restart minted a new device + prekeys, orphaning every prior
    /// message ("not found: local signed prekey").
    #[test]
    fn device_identity_persists_across_restart() {
        let dir = unique_temp_dir();
        let user_id = format!("test-user-{}", uuid::Uuid::new_v4());

        let first = {
            let state = AppState::new(dir.clone()).expect("create state");
            let bundle = state.ensure_identity(&user_id, "Test Device").expect("ensure 1");
            let prekey = state
                .signed_prekey
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .public
                .prekey_id
                .clone();
            (bundle.device_id, prekey)
        };

        let second = {
            let state = AppState::new(dir.clone()).expect("create state");
            let bundle = state.ensure_identity(&user_id, "Test Device").expect("ensure 2");
            let prekey = state
                .signed_prekey
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .public
                .prekey_id
                .clone();
            (bundle.device_id, prekey)
        };

        cleanup(&user_id, &dir);

        assert_eq!(first.0, second.0, "device id must survive a restart");
        assert_eq!(first.1, second.1, "signed prekey must survive a restart");
    }
}
