use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

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

    fn key_material_entry(&self, user_id: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(KEYRING_SERVICE, &Self::safe_user_key(user_id))
            .map_err(|e| QGuardError::Storage(format!("open OS keychain entry: {e}")))
    }

    fn load_device_key_material(
        &self,
        user_id: &str,
    ) -> Result<Option<PersistedDeviceKeyMaterial>> {
        let entry = self.key_material_entry(user_id)?;
        match entry.get_secret() {
            Ok(mut bytes) => {
                let material = Self::decode_device_key_material(user_id, &bytes)?;
                bytes.zeroize();
                return Ok(Some(material));
            }
            Err(KeyringError::NoEntry) => {}
            Err(error) => {
                if let Some(material) = self.load_legacy_device_key_material(user_id)? {
                    return Ok(Some(material));
                }
                return Err(QGuardError::Storage(format!(
                    "read OS keychain device key material: {error}"
                )));
            }
        }

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
        let result = self
            .key_material_entry(user_id)?
            .set_secret(&encoded)
            .map_err(|e| {
                QGuardError::Storage(format!("write OS keychain device key material: {e}"))
            });
        encoded.zeroize();
        result?;
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
