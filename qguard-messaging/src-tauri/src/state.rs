use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::audit::{AuditChain, AuditSeverity};
use crate::crypto::hybrid_kex::LocalKemKeypair;
use crate::crypto::signatures::VaultSigningKeypair;
use crate::device_trust::TrustedDevice;
use crate::error::{QGuardError, Result};
use crate::identity::{LocalIdentity, PublicIdentityBundle};
use crate::prekeys::{
    generate_one_time_prekeys, generate_signed_prekey, LocalOneTimePrekey, LocalSignedPrekey,
};
use crate::ratchet::RatchetSession;
use crate::telemetry::TelemetryEvent;


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

/// Device-local, encrypted-at-rest Vault Master Key (VMK) + the vault's ML-DSA-87
/// signing keypair. The VMK wraps every per-file key (FEK) in the user's vault;
/// it is generated once and reused so it acts as a true master key. Both live
/// under the same OS-keychain-held DEK as the device key material — never sent to
/// a server. Mirrors the `PersistedVaultRecovery` storage pattern (no `Drop` impl,
/// matching that type; `VaultSigningKeypair` zeroizes its own secrets on drop).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedVaultMaster {
    pub version: u8,
    pub vmk: [u8; crate::crypto::symmetric::KEY_SIZE],
    pub signer: VaultSigningKeypair,
    pub configured_at: chrono::DateTime<Utc>,
}

/// One unlock credential (password or PIN) for a protected workspace scope.
/// Stores only a salt + a derived verifier (never the secret). For the
/// vault scope it additionally holds the VMK material wrapped under the unlock
/// key, so the password/PIN cryptographically gates the VMK (zero-knowledge).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WorkspaceCredential {
    pub salt: Vec<u8>,
    pub verifier: String,
    #[serde(default)]
    pub wrapped_master: Option<crate::crypto::EncryptedEnvelope>,
    /// How the unlock secret is stretched before the HKDF subkey derivation.
    /// 0 (and records written before this field existed) = the secret feeds
    /// HKDF-SHA3-256 directly; 1 = Argon2id prehash first, which makes offline
    /// brute force of a stolen credential file memory-hard and slow. Legacy
    /// credentials are upgraded in place on their next successful unlock.
    #[serde(default)]
    pub kdf_version: u8,
}

/// Device-local, encrypted-at-rest workspace-lock state for one scope
/// ("chat" | "vault"): the configured password/PIN credentials plus the
/// anti-bruteforce counters. Stored under the same OS-keychain DEK as the device
/// keys; holds no plaintext secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedWorkspaceScope {
    pub version: u8,
    pub scope: String,
    #[serde(default)]
    pub password: Option<WorkspaceCredential>,
    #[serde(default)]
    pub pin: Option<WorkspaceCredential>,
    #[serde(default)]
    pub failed_attempts: u32,
    #[serde(default)]
    pub lockout_until: Option<chrono::DateTime<Utc>>,
    #[serde(default)]
    pub lockdown: bool,
}

impl PersistedWorkspaceScope {
    pub fn new(scope: &str) -> Self {
        Self {
            version: 1,
            scope: scope.to_string(),
            password: None,
            pin: None,
            failed_attempts: 0,
            lockout_until: None,
            lockdown: false,
        }
    }

    pub fn configured(&self) -> bool {
        self.password.is_some() || self.pin.is_some()
    }
}

/// A trusted-device registration record (banking-style device binding).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRegistration {
    pub device_id: String,
    pub device_name: String,
    pub platform: String,
    pub app_version: String,
    pub registered_at: chrono::DateTime<Utc>,
    pub last_login_at: chrono::DateTime<Utc>,
}

/// The Supabase session the app-entry PIN restores. Serialized, encrypted under
/// the SEK, and never stored in plaintext.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredSession {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub user_id: String,
    pub email: String,
}

/// Device-local, encrypted-at-rest app-entry PIN state. The session is wrapped
/// under a random SEK; the SEK is wrapped under the PIN-derived key. The whole
/// struct is then encrypted at rest under the hardware-backed device DEK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedAppLock {
    pub version: u8,
    pub enabled: bool,
    pub digits: u8,
    pub kdf_version: u8,
    pub salt: Vec<u8>,
    pub verifier: String,
    pub sek_wrapped_by_pin: crate::crypto::EncryptedEnvelope,
    pub session_wrapped_by_sek: crate::crypto::EncryptedEnvelope,
    pub failed_attempts: u32,
    pub lockout_until: Option<chrono::DateTime<Utc>>,
    pub inactivity_minutes: u32,
    pub device: DeviceRegistration,
    pub created_at: chrono::DateTime<Utc>,
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
    /// Unlocked Vault Master Key for this session (None = vault locked). Cleared
    /// and zeroized on lock / inactivity / sign-out.
    pub vault_session: Mutex<Option<PersistedVaultMaster>>,
    /// Set of currently-unlocked workspace scopes ("chat" | "vault").
    pub workspace_unlocked: Mutex<HashSet<String>>,
    /// In-memory Session Encryption Key while the app is PIN-unlocked (None =
    /// locked). Zeroized on lock / background / sign-out.
    pub applock_sek: Mutex<Option<[u8; crate::crypto::symmetric::KEY_SIZE]>>,
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
            vault_session: Mutex::new(None),
            workspace_unlocked: Mutex::new(HashSet::new()),
            applock_sek: Mutex::new(None),
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

    /// Returns the per-user 32-byte data encryption key, creating and persisting
    /// one in the platform secure store on first use (OS keychain on desktop,
    /// Android Keystore-wrapped file on Android — see security/keystore.rs).
    /// The secure store only ever holds this small key, never the (much larger)
    /// key material itself.
    fn device_storage_key(
        &self,
        user_id: &str,
    ) -> Result<[u8; crate::crypto::symmetric::KEY_SIZE]> {
        let account = Self::safe_user_key(user_id);
        if let Some(mut decoded) =
            crate::security::keystore::load_secret(&account, &self.data_dir)?
        {
            if decoded.len() != crate::crypto::symmetric::KEY_SIZE {
                decoded.zeroize();
                return Err(QGuardError::Storage(
                    "device storage key has unexpected length".to_string(),
                ));
            }
            let mut key = [0u8; crate::crypto::symmetric::KEY_SIZE];
            key.copy_from_slice(&decoded);
            decoded.zeroize();
            return Ok(key);
        }
        let key = crate::crypto::symmetric::random_key();
        crate::security::keystore::store_secret(&account, &self.data_dir, &key)?;
        Ok(key)
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
                crate::crypto::symmetric::decrypt(&key, &file.envelope, &crate::security::obf::key_material_aad())?;
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
        let envelope = crate::crypto::symmetric::encrypt(&key, &encoded, &crate::security::obf::key_material_aad());
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
        let envelope = crate::crypto::symmetric::encrypt(&key, &encoded, &crate::security::obf::vault_recovery_material_aad());
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
            crate::crypto::symmetric::decrypt(&key, &file.envelope, &crate::security::obf::vault_recovery_material_aad())?;
        let material: PersistedVaultRecovery = serde_json::from_slice(&plaintext)
            .map_err(|e| QGuardError::Storage(format!("decode vault recovery payload: {e}")))?;
        plaintext.zeroize();
        Ok(Some(material))
    }

    fn vault_master_path(&self, user_id: &str) -> PathBuf {
        let safe_user_id = Self::safe_user_key(user_id);
        self.data_dir
            .join("keys")
            .join(format!("{safe_user_id}.vault-master.enc"))
    }

    fn load_vault_master(&self, user_id: &str) -> Result<Option<PersistedVaultMaster>> {
        let path = self.vault_master_path(user_id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)
            .map_err(|e| QGuardError::Storage(format!("read vault master material: {e}")))?;
        let file: EncryptedKeyMaterialFile = serde_json::from_slice(&bytes)
            .map_err(|e| QGuardError::Storage(format!("decode vault master material: {e}")))?;
        let key = self.device_storage_key(user_id)?;
        let mut plaintext =
            crate::crypto::symmetric::decrypt(&key, &file.envelope, &crate::security::obf::vault_master_material_aad())?;
        let material: PersistedVaultMaster = serde_json::from_slice(&plaintext)
            .map_err(|e| QGuardError::Storage(format!("decode vault master payload: {e}")))?;
        plaintext.zeroize();
        Ok(Some(material))
    }

    /// Return the user's Vault Master Key + ML-DSA-87 signing keypair WITHOUT
    /// persisting it. If a legacy keychain-protected copy exists (`*.vault-master.enc`,
    /// from before workspace lock), it is loaded so existing files stay decryptable;
    /// otherwise a fresh VMK is generated in memory. The caller (vault unlock setup)
    /// then wraps it under the user's password/PIN and deletes any legacy copy, so
    /// the VMK is only ever stored password-wrapped (zero-knowledge).
    pub fn load_or_generate_vault_master(&self, user_id: &str) -> Result<PersistedVaultMaster> {
        if let Some(material) = self.load_vault_master(user_id)? {
            return Ok(material);
        }
        Ok(PersistedVaultMaster {
            version: 1,
            vmk: crate::crypto::symmetric::random_key(),
            signer: VaultSigningKeypair::generate(),
            configured_at: Utc::now(),
        })
    }

    /// Remove the legacy keychain-only VMK file once it has been migrated to the
    /// password-wrapped store, so vault access truly requires the unlock secret.
    pub fn delete_vault_master_file(&self, user_id: &str) -> Result<()> {
        let path = self.vault_master_path(user_id);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| QGuardError::Storage(format!("remove legacy vault master file: {e}")))?;
        }
        Ok(())
    }

    // ---- Workspace lock: scope persistence + session ----------------------

    fn workspace_scope_path(&self, user_id: &str, scope: &str) -> PathBuf {
        let safe_user_id = Self::safe_user_key(user_id);
        let safe_scope = if scope == "vault" { "vault" } else { "chat" };
        self.data_dir
            .join("keys")
            .join(format!("{safe_user_id}.workspace-{safe_scope}.enc"))
    }

    pub fn save_workspace_scope(&self, user_id: &str, material: &PersistedWorkspaceScope) -> Result<()> {
        let encoded = serde_json::to_vec(material)
            .map_err(|e| QGuardError::Storage(format!("encode workspace scope: {e}")))?;
        let key = self.device_storage_key(user_id)?;
        let envelope = crate::crypto::symmetric::encrypt(&key, &encoded, &crate::security::obf::workspace_material_aad())?;
        let file = EncryptedKeyMaterialFile { version: 1, envelope };
        let serialized = serde_json::to_vec(&file)
            .map_err(|e| QGuardError::Storage(format!("encode encrypted workspace scope: {e}")))?;
        std::fs::write(self.workspace_scope_path(user_id, &material.scope), &serialized)
            .map_err(|e| QGuardError::Storage(format!("write workspace scope: {e}")))?;
        Ok(())
    }

    pub fn load_workspace_scope(&self, user_id: &str, scope: &str) -> Result<Option<PersistedWorkspaceScope>> {
        let path = self.workspace_scope_path(user_id, scope);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)
            .map_err(|e| QGuardError::Storage(format!("read workspace scope: {e}")))?;
        let file: EncryptedKeyMaterialFile = serde_json::from_slice(&bytes)
            .map_err(|e| QGuardError::Storage(format!("decode workspace scope: {e}")))?;
        let key = self.device_storage_key(user_id)?;
        let plaintext =
            crate::crypto::symmetric::decrypt(&key, &file.envelope, &crate::security::obf::workspace_material_aad())?;
        let material: PersistedWorkspaceScope = serde_json::from_slice(&plaintext)
            .map_err(|e| QGuardError::Storage(format!("decode workspace scope payload: {e}")))?;
        Ok(Some(material))
    }

    // ---- App-entry PIN (applock) ------------------------------------------

    fn applock_path(&self, user_id: &str) -> PathBuf {
        let safe_user_id = Self::safe_user_key(user_id);
        self.data_dir
            .join("keys")
            .join(format!("{safe_user_id}.applock.enc"))
    }

    pub fn save_applock(&self, user_id: &str, material: &PersistedAppLock) -> Result<()> {
        let mut encoded = serde_json::to_vec(material)
            .map_err(|e| QGuardError::Storage(format!("encode applock: {e}")))?;
        let key = self.device_storage_key(user_id)?;
        let envelope = crate::crypto::symmetric::encrypt(
            &key,
            &encoded,
            &crate::security::obf::applock_material_aad(),
        );
        encoded.zeroize();
        let file = EncryptedKeyMaterialFile { version: 1, envelope: envelope? };
        let serialized = serde_json::to_vec(&file)
            .map_err(|e| QGuardError::Storage(format!("encode encrypted applock: {e}")))?;
        std::fs::write(self.applock_path(user_id), &serialized)
            .map_err(|e| QGuardError::Storage(format!("write applock: {e}")))?;
        Ok(())
    }

    pub fn load_applock(&self, user_id: &str) -> Result<Option<PersistedAppLock>> {
        let path = self.applock_path(user_id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)
            .map_err(|e| QGuardError::Storage(format!("read applock: {e}")))?;
        let file: EncryptedKeyMaterialFile = serde_json::from_slice(&bytes)
            .map_err(|e| QGuardError::Storage(format!("decode applock file: {e}")))?;
        let key = self.device_storage_key(user_id)?;
        let mut plaintext = crate::crypto::symmetric::decrypt(
            &key,
            &file.envelope,
            &crate::security::obf::applock_material_aad(),
        )?;
        let material: PersistedAppLock = serde_json::from_slice(&plaintext)
            .map_err(|e| QGuardError::Storage(format!("decode applock payload: {e}")))?;
        plaintext.zeroize();
        Ok(Some(material))
    }

    pub fn delete_applock(&self, user_id: &str) -> Result<()> {
        let path = self.applock_path(user_id);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| QGuardError::Storage(format!("delete applock: {e}")))?;
        }
        self.clear_applock_sek();
        Ok(())
    }

    pub fn set_applock_sek(&self, sek: [u8; crate::crypto::symmetric::KEY_SIZE]) -> Result<()> {
        let mut guard = self
            .applock_sek
            .lock()
            .map_err(|_| QGuardError::Storage("applock sek lock poisoned".to_string()))?;
        *guard = Some(sek);
        Ok(())
    }

    /// Returns a COPY of the in-memory SEK, leaving it in place (needed so
    /// token refresh can re-wrap the session while unlocked). None when locked.
    pub fn take_applock_sek(&self) -> Option<[u8; crate::crypto::symmetric::KEY_SIZE]> {
        self.applock_sek.lock().ok().and_then(|guard| *guard)
    }

    pub fn clear_applock_sek(&self) {
        if let Ok(mut guard) = self.applock_sek.lock() {
            if let Some(mut sek) = guard.take() {
                sek.zeroize();
            }
        }
    }

    pub fn is_applock_unlocked(&self) -> bool {
        self.applock_sek
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    /// Store the unlocked VMK for this session (vault unlocked).
    pub fn set_vault_session(&self, master: PersistedVaultMaster) -> Result<()> {
        *self
            .vault_session
            .lock()
            .map_err(|_| QGuardError::Storage("vault session lock poisoned".to_string()))? = Some(master);
        Ok(())
    }

    /// The unlocked VMK for this session, or an error if the vault is locked.
    pub fn unlocked_vault_master(&self) -> Result<PersistedVaultMaster> {
        self.vault_session
            .lock()
            .map_err(|_| QGuardError::Storage("vault session lock poisoned".to_string()))?
            .as_ref()
            .cloned()
            .ok_or_else(|| QGuardError::Trust("Quantum Vault is locked — unlock it to continue".to_string()))
    }

    /// Zeroize + drop the unlocked VMK (vault re-locks).
    pub fn clear_vault_session(&self) -> Result<()> {
        if let Ok(mut guard) = self.vault_session.lock() {
            if let Some(mut master) = guard.take() {
                master.vmk.zeroize(); // VaultSigningKeypair zeroizes its secrets on drop
            }
        }
        Ok(())
    }

    pub fn mark_workspace_unlocked(&self, scope: &str) -> Result<()> {
        self.workspace_unlocked
            .lock()
            .map_err(|_| QGuardError::Storage("workspace lock state poisoned".to_string()))?
            .insert(scope.to_string());
        Ok(())
    }

    pub fn mark_workspace_locked(&self, scope: &str) -> Result<()> {
        self.workspace_unlocked
            .lock()
            .map_err(|_| QGuardError::Storage("workspace lock state poisoned".to_string()))?
            .remove(scope);
        Ok(())
    }

    pub fn is_workspace_unlocked(&self, scope: &str) -> bool {
        self.workspace_unlocked
            .lock()
            .map(|set| set.contains(scope))
            .unwrap_or(false)
    }

    /// Memory protection on chat lock: drop decrypted message plaintext from the
    /// in-memory cache so it can no longer be read while locked.
    pub fn clear_chat_session(&self) {
        if let Ok(mut cache) = self.decrypted_message_cache.lock() {
            cache.clear();
        }
    }

    /// Lock every protected workspace (sign-out / inactivity / app close): zeroize
    /// the VMK, clear decrypted chat plaintext, and forget all unlocked scopes.
    pub fn lock_all_workspaces(&self) {
        let _ = self.clear_vault_session();
        self.clear_chat_session();
        if let Ok(mut set) = self.workspace_unlocked.lock() {
            set.clear();
        }
    }

    /// Reset anti-bruteforce counters + lockdown for both scopes. Called on a
    /// successful application login, so re-authenticating clears a lockdown
    /// (per the Secure Workspace spec).
    pub fn reset_workspace_lockouts(&self, user_id: &str) {
        for scope in ["chat", "vault"] {
            if let Ok(Some(mut record)) = self.load_workspace_scope(user_id, scope) {
                if record.failed_attempts != 0 || record.lockout_until.is_some() || record.lockdown {
                    record.failed_attempts = 0;
                    record.lockout_until = None;
                    record.lockdown = false;
                    let _ = self.save_workspace_scope(user_id, &record);
                }
            }
        }
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
                &crate::security::obf::local_ratchet_info(),
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
        let _ = crate::security::keystore::delete_secret(&AppState::safe_user_key(user_id), dir);
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
