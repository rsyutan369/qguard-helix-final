use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::audit::{AuditChain, AuditSeverity};
use crate::crypto::hybrid_kex::LocalKemKeypair;
use crate::crypto::signatures::VaultSigningKeypair;
use crate::device_pins::{DevicePinBook, DeviceStanding, PinSubject};
use crate::device_trust::TrustedDevice;
use crate::error::{QGuardError, Result};
use crate::identity::{LocalIdentity, PublicIdentityBundle};
use crate::message_keys::MessageKeyLedger;
use crate::prekeys::{
    generate_one_time_prekeys, generate_signed_prekey, LocalOneTimePrekey, LocalSignedPrekey,
};
use crate::pq_ratchet::SessionBook;
use crate::ratchet::RatchetSession;
use crate::telemetry::TelemetryEvent;

/// Replace `path` with `bytes` so that a crash, power cut or full disk leaves
/// either the complete old file or the complete new one — never a torn mix.
///
/// Every file written through here is key material that exists in exactly one
/// place. `std::fs::write` truncates the target first and then writes, so an
/// interruption between those two steps leaves a half-written file where the
/// only copy of the device keys used to be. `ensure_identity` then (correctly)
/// refuses to replace material it cannot open, and the device is stuck until
/// the user resets its identity and loses its history. Writing a sibling temp
/// file, flushing it to disk and renaming it over the target removes the
/// window: a rename within one directory is atomic on every platform this app
/// ships on.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let temp = directory.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));

    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&temp)?;
        file.write_all(bytes)?;
        // Data must be on disk BEFORE the rename makes it the live copy.
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
}


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
    /// prekey id -> unix seconds at which that signed prekey stopped being the
    /// published one. A retired prekey is kept for a grace period (a sender may
    /// still be holding the bundle it fetched) and then destroyed; without the
    /// timestamp there is no way to know when that period is over, which is why
    /// retired prekeys used to be kept indefinitely.
    #[serde(default)]
    retired_prekeys: HashMap<String, i64>,
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

    /// True when this configuration holds a secret the device must not be able
    /// to reach while the vault is locked (personal: the recovery wrapping key;
    /// hybrid: the recovery root). Enterprise mode keeps public keys only.
    pub fn holds_secrets(&self) -> bool {
        self.recovery_mode() != "enterprise"
    }
}

impl Drop for PersistedVaultRecovery {
    fn drop(&mut self) {
        self.wrap_key.zeroize();
        if let Some(root) = self.recovery_root.as_mut() {
            root.zeroize();
        }
    }
}

/// The part of the recovery configuration that is safe to read while the vault
/// is LOCKED: which mode is configured, the one-way verifier, and (enterprise)
/// the recipient's public keys. No key that can open a file.
#[derive(Clone, Debug)]
pub struct VaultRecoveryPublic {
    pub mode: String,
    pub verifier: String,
    pub configured_at: chrono::DateTime<Utc>,
    pub recipient_key_id: Option<String>,
    pub enterprise_x25519_public: Option<Vec<u8>>,
    pub enterprise_mlkem_public: Option<Vec<u8>>,
}

/// On-disk layout of the recovery configuration (v2).
///
/// The record as a whole is encrypted under the device storage key like every
/// other key file. The SECRET half is additionally sealed under a key derived
/// from the PIN-bound vault key, so the device can only reach it while the
/// vault is unlocked.
///
/// That second layer is the point. In the v1 layout the personal recovery
/// wrapping key sat under the device storage key alone — and every vault file
/// carries a recovery wrap. So whoever held the storage key could open any file
/// through its recovery wrap without the vault password, which made the vault
/// lock decorative no matter what else was fixed.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct VaultRecoveryRecordV2 {
    version: u8,
    mode: String,
    verifier: String,
    configured_at: chrono::DateTime<Utc>,
    #[serde(default)]
    enterprise_x25519_public: Option<Vec<u8>>,
    #[serde(default)]
    enterprise_mlkem_public: Option<Vec<u8>>,
    #[serde(default)]
    recipient_key_id: Option<String>,
    /// `VaultRecoverySecrets`, AES-256-GCM under the vault-key-derived seal key.
    /// Absent for enterprise mode, which has nothing secret to keep.
    #[serde(default)]
    sealed_secrets: Option<crate::crypto::EncryptedEnvelope>,
}

#[derive(Serialize, Deserialize)]
struct VaultRecoverySecrets {
    wrap_key: [u8; crate::crypto::symmetric::KEY_SIZE],
    #[serde(default)]
    recovery_root: Option<[u8; crate::crypto::symmetric::KEY_SIZE]>,
}

impl Drop for VaultRecoverySecrets {
    fn drop(&mut self) {
        self.wrap_key.zeroize();
        if let Some(root) = self.recovery_root.as_mut() {
            root.zeroize();
        }
    }
}

/// AAD for the message-key ledger file (see `crate::message_keys`).
const MESSAGE_KEY_LEDGER_AAD: &[u8] = b"QGuard-Messaging-Message-Key-Ledger-v1";
/// How long to wait before trying again to open a ledger that would not open.
const MESSAGE_KEY_LEDGER_RETRY_SECS: i64 = 60;

const DEVICE_PIN_BOOK_AAD: &[u8] = b"QGuard-Messaging-Device-Pins-v1";
/// How long to wait before trying again to open a device record that would not open.
const DEVICE_PIN_BOOK_RETRY_SECS: i64 = 60;

/// AAD for the ratchet session file (see `crate::pq_ratchet`).
const RATCHET_SESSIONS_AAD: &[u8] = b"QGuard-Messaging-Ratchet-Sessions-v1";
/// How long to wait before trying again to open a session file that would not open.
const RATCHET_SESSIONS_RETRY_SECS: i64 = 60;

/// Domain separation for the PIN-bound vault key and the keys derived from it.
const VAULT_KEY_INFO: &[u8] = b"QGuard-Vault-PIN-Bound-Key-v1";
const VAULT_RECOVERY_SEAL_INFO: &[u8] = b"QGuard-Vault-Recovery-Material-Seal-v1";

/// The Vault Master Key (VMK) and the vault's ML-DSA-87 signing keypair.
///
/// Stored ONLY wrapped under the user's vault password / PIN (see
/// `commands::workspace`); held in memory while the vault is unlocked; never
/// sent to a server. Zeroized on drop (`VaultSigningKeypair` wipes its own
/// secrets).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedVaultMaster {
    pub version: u8,
    pub vmk: [u8; crate::crypto::symmetric::KEY_SIZE],
    pub signer: VaultSigningKeypair,
    pub configured_at: chrono::DateTime<Utc>,
}

impl Drop for PersistedVaultMaster {
    fn drop(&mut self) {
        self.vmk.zeroize();
    }
}

impl PersistedVaultMaster {
    /// The PIN-bound vault key: what wraps every per-file key in a v5 container.
    ///
    /// WHY THIS IS NOT SIMPLY `vmk`
    /// ---------------------------------------------------------------------
    /// Every v3/v4 container ever written carries the VMK wrapped to the
    /// device's hybrid KEM key in its header, and the device KEM secret is
    /// protected only by the OS-keychain storage key. So the raw VMK must be
    /// treated as recoverable WITHOUT the vault password by anyone who holds
    /// that storage key and a single old container. Wrapping new files under it
    /// would carry the bypass forward to every file made from now on.
    ///
    /// The signing secrets in this struct have a different history: they have
    /// only ever existed inside the password-wrapped master blob and in the
    /// memory of an unlocked session. Deriving the working key from the VMK
    /// *and* those secrets therefore yields a key that genuinely cannot be
    /// reproduced without the vault password — while staying a pure function of
    /// the stored master. That matters: the master is wrapped separately under
    /// the password and the PIN, so introducing a fresh random key would need
    /// both secrets at once to re-wrap. A derived key needs neither, changes no
    /// stored state, and comes out identical whichever credential unlocked it.
    pub fn vault_key(&self) -> Result<[u8; crate::crypto::symmetric::KEY_SIZE]> {
        let mut ikm = Vec::with_capacity(
            self.vmk.len() + self.signer.ed25519_secret.len() + self.signer.mldsa87_secret.len(),
        );
        ikm.extend_from_slice(&self.vmk);
        ikm.extend_from_slice(&self.signer.ed25519_secret);
        ikm.extend_from_slice(&self.signer.mldsa87_secret);
        let key = crate::crypto::kdf::derive_32(&ikm, VAULT_KEY_INFO);
        ikm.zeroize();
        key
    }
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
    /// A second PIN that, entered at the lock screen, erases this device's
    /// keys and lands on the sign-in screen as if the session had expired
    /// (`AppState::panic_wipe`). Only its Argon2id verifier is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duress: Option<DuressPin>,
    /// The SEK wrapped by a biometric-gated Android Keystore key (see
    /// `BiometricUnlock.kt`). Opaque here: only the Keystore, after a
    /// successful strong-biometric prompt, can unwrap it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub biometric_sek: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DuressPin {
    pub salt: Vec<u8>,
    pub verifier: String,
}

#[derive(Clone, Debug)]
pub struct AuthSession {
    pub user_id: String,
    pub email: String,
    pub tier: String,
    pub access_token: String,
    pub expires_at: i64,
}

/// Sliding-window rate limit: admit (and record) an attempt at `now` unless
/// `limit` attempts already fall inside the last `window_seconds`.
///
/// Kept as a free function so the start-up self-test can exercise the very
/// logic the key commands rely on (see `security::selftest`).
pub(crate) fn rate_window_admit(
    attempts: &mut Vec<i64>,
    now: i64,
    limit: usize,
    window_seconds: i64,
) -> bool {
    let floor = now - window_seconds;
    attempts.retain(|timestamp| *timestamp >= floor);
    if attempts.len() >= limit {
        return false;
    }
    attempts.push(now);
    true
}

/// The private half of a per-call hybrid KEM key pair, generated when this
/// device accepts an incoming call and held only until the caller's offer
/// arrives (see `commands::calls`). It is what gives a call forward secrecy:
/// it never touches disk, and `LocalKemKeypair` wipes itself when dropped.
pub struct PendingCallKey {
    pub keypair: LocalKemKeypair,
    /// Who the ring came from. The key is only ever used for a call from
    /// exactly this device.
    pub caller_user_id: String,
    pub caller_device_id: String,
    pub created_at: i64,
}

pub struct AppState {
    pub data_dir: PathBuf,
    pub key_scope: Mutex<()>,
    pub identity: Mutex<Option<LocalIdentity>>,
    pub signed_prekey: Mutex<Option<LocalSignedPrekey>>,
    pub one_time_prekeys: Mutex<Vec<LocalOneTimePrekey>>,
    pub legacy_kem_keypairs: Mutex<Vec<LocalKemKeypair>>,
    pub legacy_signed_prekeys: Mutex<Vec<LocalSignedPrekey>>,
    /// Device row that this session's identity superseded, if it re-keyed.
    /// See `PublicIdentityBundle::replaced_device_id`.
    pub superseded_device_id: Mutex<Option<String>>,
    pub legacy_one_time_prekeys: Mutex<Vec<LocalOneTimePrekey>>,
    /// When each retired signed prekey was retired (unix seconds). Persisted
    /// with the device key material; see `PersistedDeviceKeyMaterial`.
    pub prekey_retirements: Mutex<HashMap<String, i64>>,
    /// Per-message keys for envelopes this device has already opened — what
    /// allows retired prekeys to be destroyed. See `crate::message_keys`.
    pub message_keys: Mutex<MessageKeyLedger>,
    /// This device's own record of which devices belong to whom, so a device
    /// the relay lists for someone later is noticed. See `crate::device_pins`.
    pub device_pins: Mutex<DevicePinBook>,
    /// Per-call key pairs for calls this device is in the middle of answering,
    /// by call id. Memory only, and each is removed the moment it is used.
    pub pending_call_keys: Mutex<HashMap<String, PendingCallKey>>,
    pub ratchets: Mutex<HashMap<String, RatchetSession>>,
    /// Post-quantum ratchet sessions with peer devices, encrypted at rest.
    /// See `crate::pq_ratchet` and `with_ratchet_sessions`.
    pub ratchet_sessions: Mutex<SessionBook>,
    /// The user's Settings → Advanced choice to advertise and start ratchet
    /// sessions (`None` until read from disk). See `ratchet_enabled`.
    pub ratchet_setting: Mutex<Option<bool>>,
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
    /// Portable Hybrid Identity unlocked for this session (None = locked).
    ///
    /// Held in memory only — the `.qgkey` bundle itself is never copied into the
    /// app's data directory, so an identity survives exactly as long as the user
    /// keeps it unlocked. Dropped (and its secrets zeroized by the inner
    /// keypairs' `Drop`) on manual lock, workspace lock, and sign-out.
    pub portable_identity: Mutex<Option<crate::crypto::portable_identity::PortableIdentity>>,
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
            superseded_device_id: Mutex::new(None),
            legacy_one_time_prekeys: Mutex::new(Vec::new()),
            prekey_retirements: Mutex::new(HashMap::new()),
            message_keys: Mutex::new(MessageKeyLedger::default()),
            device_pins: Mutex::new(DevicePinBook::default()),
            pending_call_keys: Mutex::new(HashMap::new()),
            ratchets: Mutex::new(HashMap::new()),
            ratchet_sessions: Mutex::new(SessionBook::default()),
            ratchet_setting: Mutex::new(None),
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
            portable_identity: Mutex::new(None),
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
                    // Must happen before ANY persist below: persisting writes
                    // the retirement times held in memory, and writing an empty
                    // map here would restart the grace period of every retired
                    // prekey on every launch — so none would ever be destroyed.
                    self.install_prekey_retirements(&material.retired_prekeys);
                    if Self::key_material_uses_current_pq_suite(&material) {
                        // Builds before this one registered EVERY platform as
                        // "Windows Desktop", so an Android install carries a
                        // label that cannot be true. Correct it in place on the
                        // next launch: `device_label` is not covered by
                        // `identity_signable`, so the device signature and every
                        // key stay valid and the device id never changes.
                        //
                        // Retired prekeys written by a build that did not record
                        // WHEN they were retired get their clock started now —
                        // and that has to be written down, or "now" would be a
                        // later moment on every launch.
                        let needs_retirement_backfill = material
                            .legacy_signed_prekeys
                            .iter()
                            .any(|prekey| !material.retired_prekeys.contains_key(&prekey.public.prekey_id));
                        let mut identity = material.identity;
                        let relabel = identity.device_label.trim().is_empty()
                            || (crate::identity::is_legacy_hardcoded_label(&identity.device_label)
                                && !crate::identity::is_legacy_hardcoded_label(label));
                        if relabel {
                            identity.device_label = label.to_string();
                        }
                        if relabel || needs_retirement_backfill {
                            // Best effort: a failed rewrite must never stop the
                            // user signing in -- the label is cosmetic, the keys
                            // in memory are already correct.
                            let _ = self.persist_device_key_material(
                                user_id,
                                &identity,
                                &material.signed_prekey,
                                &material.one_time_prekeys,
                                &material.legacy_kem_keypairs,
                                &material.legacy_signed_prekeys,
                                &material.legacy_one_time_prekeys,
                            );
                        }
                        (
                            identity,
                            material.signed_prekey,
                            material.one_time_prekeys,
                            material.legacy_kem_keypairs,
                            material.legacy_signed_prekeys,
                            material.legacy_one_time_prekeys,
                            KeyMaterialStatus::Restored,
                        )
                    } else {
                        // Stored material was produced by a superseded KEM.
                        //
                        // Pre-FIPS-203 material is DISCARDED rather than kept as
                        // "legacy": those keys were generated by Kyber-1024 and
                        // this build only performs ML-KEM-1024. Retaining them
                        // would advertise a decapsulation capability that no
                        // longer exists, and — because the two encodings are the
                        // same length — they would be handed to ML-KEM, derive
                        // the wrong shared secret, and fail as an unexplained
                        // AEAD error on every retry. Anything sealed to them is
                        // unreadable by design; the re-key below is the whole
                        // point of the cutover.
                        let pre_fips = !material.identity.kem.is_current_suite();
                        self.remember_superseded_device_id(material.identity.device_id.clone());
                        let mut legacy_kem_keypairs = if pre_fips {
                            Vec::new()
                        } else {
                            material.legacy_kem_keypairs
                        };
                        let mut legacy_signed_prekeys = if pre_fips {
                            Vec::new()
                        } else {
                            material.legacy_signed_prekeys
                        };
                        let mut legacy_one_time_prekeys = if pre_fips {
                            Vec::new()
                        } else {
                            material.legacy_one_time_prekeys
                        };
                        if !pre_fips {
                            legacy_kem_keypairs.push(material.identity.kem.clone());
                            legacy_signed_prekeys.push(material.signed_prekey);
                            legacy_one_time_prekeys.extend(material.one_time_prekeys);
                        }
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
                    self.install_prekey_retirements(&HashMap::new());
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
                // A LOAD FAULT IS NOT A FIRST LAUNCH.
                //
                // This arm used to mint a new identity and overwrite the
                // key-material file, which made every transient fault -- a
                // Keystore/JNI hiccup, a half-written file, a data dir restored
                // from backup without its hardware-wrapped DEK -- destroy the
                // device's private keys PERMANENTLY and silently. The visible
                // result is the whole message history turning into "not found:
                // local signed prekey", because every envelope on the relay is
                // sealed to prekeys that no longer exist anywhere.
                //
                // The distinction that matters is already made for us:
                // `load_device_key_material` returns `Ok(None)` when there is
                // genuinely nothing stored (handled above) and `Err` only when
                // material EXISTS but could not be opened. Re-keying on the
                // latter is never recoverable, so it is never automatic --
                // report it, and let the user decide via
                // `keys_reset_device_identity`.
                Err(error) => {
                    return Err(QGuardError::Storage(format!(
                        "this device already holds encrypted key material for this account, but it could not be opened ({error}). It was NOT replaced -- re-keying would permanently destroy this device's message history. Retry after unlocking the device, or reset this device's identity deliberately if the keys are known to be lost."
                    )));
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

        let mut bundle = identity_guard
            .as_ref()
            .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?
            .public_bundle()?;
        // Carried so the client can revoke the device row this identity
        // replaced. Cloned rather than taken, and cleared only once the client
        // confirms the revoke: a failed or dropped first attempt would
        // otherwise leave the dead row collecting undecryptable envelopes for
        // good, and re-revoking an already-revoked row is a no-op.
        bundle.replaced_device_id = self
            .superseded_device_id
            .lock()
            .ok()
            .and_then(|slot| slot.clone());
        // Capability only: it says "send me ratchet envelopes". Not part of
        // the identity signature (see `AlgorithmSuite::pq_kem_standard`).
        if self.ratchet_enabled() {
            bundle.suite.ratchet = crate::pq_ratchet::RATCHET_PROTOCOL.to_string();
        }
        Ok(bundle)
    }

    /// Called once the client has revoked the superseded device row, so the
    /// bundle stops advertising it.
    pub fn clear_superseded_device_id(&self) {
        if let Ok(mut slot) = self.superseded_device_id.lock() {
            *slot = None;
        }
    }

    fn remember_superseded_device_id(&self, device_id: String) {
        if let Ok(mut slot) = self.superseded_device_id.lock() {
            *slot = Some(device_id);
        }
    }

    pub(crate) fn safe_user_key(user_id: &str) -> String {
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
    /// The DEK that encrypts this user's key-material file.
    ///
    /// `create_if_missing` is NOT a convenience flag -- it is the difference
    /// between "first run" and "silent, permanent key loss". Minting a fresh
    /// random DEK on a READ makes the existing key-material file undecryptable
    /// forever, and the old code then read that decrypt failure as "no material"
    /// and re-keyed the device. So a read must never create: if the platform
    /// store has no DEK but key material exists on disk, that is a fault to
    /// report, not a first launch.
    fn device_storage_key(
        &self,
        user_id: &str,
        create_if_missing: bool,
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
        if !create_if_missing {
            return Err(QGuardError::Storage(
                "the device storage key for this account is not available from the platform secure store, so the encrypted key material on disk cannot be opened"
                    .to_string(),
            ));
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
            let key = self.device_storage_key(user_id, false)?;
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
            retired_prekeys: self.retained_prekey_retirements(legacy_signed_prekeys),
            persisted_at: Utc::now(),
        };
        let mut encoded = serde_json::to_vec(&material)
            .map_err(|e| QGuardError::Storage(format!("encode device key material: {e}")))?;
        let key = self.device_storage_key(user_id, true)?;
        let envelope = crate::crypto::symmetric::encrypt(&key, &encoded, &crate::security::obf::key_material_aad());
        encoded.zeroize();
        let file = EncryptedKeyMaterialFile {
            version: 1,
            envelope: envelope?,
        };
        let serialized = serde_json::to_vec(&file).map_err(|e| {
            QGuardError::Storage(format!("encode encrypted device key material: {e}"))
        })?;
        write_atomic(&self.encrypted_key_material_path(user_id), &serialized).map_err(|e| {
            QGuardError::Storage(format!("write encrypted device key material: {e}"))
        })?;
        // Remove any legacy plaintext material now that the encrypted copy is authoritative.
        let _ = std::fs::remove_file(self.key_material_path(user_id));
        Ok(())
    }

    /// Replace the in-memory retirement times with the ones just loaded.
    fn install_prekey_retirements(&self, retirements: &HashMap<String, i64>) {
        if let Ok(mut map) = self.prekey_retirements.lock() {
            *map = retirements.clone();
        }
    }

    /// Retirement times for exactly the retired signed prekeys being persisted.
    ///
    /// Entries for prekeys that no longer exist are dropped, and a retired
    /// prekey with no recorded time (it was retired by an older build, or just
    /// now) starts its grace period at this moment. The result is also
    /// installed in memory, so what is on disk and what the status commands
    /// report never drift apart.
    fn retained_prekey_retirements(
        &self,
        legacy_signed_prekeys: &[LocalSignedPrekey],
    ) -> HashMap<String, i64> {
        let now = Utc::now().timestamp();
        let known = self
            .prekey_retirements
            .lock()
            .map(|map| map.clone())
            .unwrap_or_default();
        let retained: HashMap<String, i64> = legacy_signed_prekeys
            .iter()
            .map(|prekey| {
                let id = prekey.public.prekey_id.clone();
                let retired_at = known.get(&id).copied().unwrap_or(now);
                (id, retired_at)
            })
            .collect();
        self.install_prekey_retirements(&retained);
        retained
    }

    /// When `prekey_id` was retired, if it is a retired signed prekey.
    pub fn prekey_retired_at(&self, prekey_id: &str) -> Option<i64> {
        self.prekey_retirements
            .lock()
            .ok()
            .and_then(|map| map.get(prekey_id).copied())
    }

    // ---- Message-key ledger (see crate::message_keys) -----------------------

    fn message_key_ledger_path(&self, user_id: &str) -> PathBuf {
        let safe_user_id = Self::safe_user_key(user_id);
        self.data_dir
            .join("keys")
            .join(format!("{safe_user_id}.message-keys.enc"))
    }

    /// Load the ledger for `user_id`.
    ///
    /// Three outcomes, and telling them apart is the whole job:
    ///   * no file            -> a fresh, usable ledger;
    ///   * file opens         -> that ledger;
    ///   * file will not open -> an UNAVAILABLE placeholder that caches nothing
    ///     and is never written. Treating that case as "empty" would overwrite
    ///     every cached key with nothing on the next flush, on what may be no
    ///     more than a momentary keychain fault.
    fn load_message_keys(&self, user_id: &str) -> MessageKeyLedger {
        let now = Utc::now().timestamp();
        match self.read_storage_sealed_file(
            user_id,
            &self.message_key_ledger_path(user_id),
            MESSAGE_KEY_LEDGER_AAD,
            "message key ledger",
        ) {
            Ok(None) => MessageKeyLedger::empty(user_id, now),
            Ok(Some(plaintext)) => MessageKeyLedger::decode(user_id, &plaintext, now)
                .unwrap_or_else(|_| MessageKeyLedger::unavailable(user_id, now + MESSAGE_KEY_LEDGER_RETRY_SECS)),
            Err(_) => MessageKeyLedger::unavailable(user_id, now + MESSAGE_KEY_LEDGER_RETRY_SECS),
        }
    }

    /// Run `f` against the ledger belonging to `user_id`, loading it first if
    /// another user's (or none) is in memory, or if an earlier load failed long
    /// enough ago to be worth retrying.
    pub fn with_message_keys<T>(
        &self,
        user_id: &str,
        f: impl FnOnce(&mut MessageKeyLedger) -> T,
    ) -> Result<T> {
        let mut ledger = self
            .message_keys
            .lock()
            .map_err(|_| QGuardError::Storage("message key ledger lock poisoned".to_string()))?;
        if ledger.owner() != Some(user_id) || ledger.should_retry_load(Utc::now().timestamp()) {
            // Another account's ledger is about to leave memory: save what it
            // learned first. Best effort — losing it only costs repeat work.
            let _ = self.write_message_keys(&mut *ledger);
            *ledger = self.load_message_keys(user_id);
        }
        Ok(f(&mut *ledger))
    }

    /// Write `ledger` to its owner's file if it is usable and has unsaved
    /// changes. Returns whether the copy on disk is now known to be complete.
    fn write_message_keys(&self, ledger: &mut MessageKeyLedger) -> Result<bool> {
        let Some(owner) = ledger.owner().map(str::to_string) else {
            return Ok(false);
        };
        if !ledger.is_available() {
            return Ok(false);
        }
        if ledger.unflushed() == 0 {
            return Ok(true);
        }
        let mut encoded = ledger.encode()?;
        let written = self.write_storage_sealed_file(
            &owner,
            &self.message_key_ledger_path(&owner),
            MESSAGE_KEY_LEDGER_AAD,
            &encoded,
            "message key ledger",
        );
        encoded.zeroize();
        written?;
        ledger.mark_flushed();
        Ok(true)
    }

    /// The key that already opened this exact envelope, if this device has one.
    pub fn cached_message_key(
        &self,
        user_id: &str,
        message_id: &str,
        nonce: &[u8],
        tag: &[u8],
    ) -> Option<[u8; crate::crypto::symmetric::KEY_SIZE]> {
        self.with_message_keys(user_id, |ledger| ledger.lookup(message_id, nonce, tag))
            .ok()
            .flatten()
    }

    /// Record the key that just opened (or sealed) an envelope. Best effort by
    /// design: a ledger that cannot be used costs a repeat prekey decrypt later,
    /// never the message.
    pub fn remember_message_key(
        &self,
        user_id: &str,
        message_id: &str,
        nonce: &[u8],
        tag: &[u8],
        key: &[u8; crate::crypto::symmetric::KEY_SIZE],
    ) {
        let now = Utc::now().timestamp();
        let flush_due = self
            .with_message_keys(user_id, |ledger| {
                ledger.remember(message_id, nonce, tag, key, now);
                ledger.unflushed() >= crate::message_keys::FLUSH_EVERY
            })
            .unwrap_or(false);
        if flush_due {
            let _ = self.flush_message_keys(user_id);
        }
    }

    /// Note that an envelope had to be opened with `prekey_id` because its key
    /// was not in the ledger. A retired prekey that keeps being needed is not
    /// ready to be destroyed, whatever else says so.
    pub fn note_prekey_needed(&self, user_id: &str, prekey_id: &str) {
        let now = Utc::now().timestamp();
        let _ = self.with_message_keys(user_id, |ledger| ledger.note_prekey_needed(prekey_id, now));
    }

    /// Write the ledger out if it has unsaved changes. Returns whether the
    /// ledger on disk is now known to be complete — false when it is
    /// unavailable or belongs to another user, in which case nothing may be
    /// destroyed on the strength of it.
    pub fn flush_message_keys(&self, user_id: &str) -> Result<bool> {
        let mut ledger = self
            .message_keys
            .lock()
            .map_err(|_| QGuardError::Storage("message key ledger lock poisoned".to_string()))?;
        if ledger.owner() != Some(user_id) {
            return Ok(false);
        }
        self.write_message_keys(&mut ledger)
    }

    // ---- Device pins (see crate::device_pins) ------------------------------

    fn device_pin_book_path(&self, user_id: &str) -> PathBuf {
        let safe_user_id = Self::safe_user_key(user_id);
        self.data_dir
            .join("keys")
            .join(format!("{safe_user_id}.device-pins.enc"))
    }

    /// Load the device record for `user_id`. As with the message-key ledger,
    /// "no file" (a fresh, usable book) and "a file that will not open" (an
    /// UNAVAILABLE placeholder that is never written) must not be confused:
    /// treating the second as the first would re-record whatever the directory
    /// lists right now as trusted.
    fn load_device_pins(&self, user_id: &str) -> DevicePinBook {
        let retry_after = Utc::now().timestamp() + DEVICE_PIN_BOOK_RETRY_SECS;
        match self.read_storage_sealed_file(
            user_id,
            &self.device_pin_book_path(user_id),
            DEVICE_PIN_BOOK_AAD,
            "device record",
        ) {
            Ok(None) => DevicePinBook::empty(user_id),
            Ok(Some(plaintext)) => DevicePinBook::decode(user_id, &plaintext)
                .unwrap_or_else(|_| DevicePinBook::unavailable(user_id, retry_after)),
            Err(_) => DevicePinBook::unavailable(user_id, retry_after),
        }
    }

    /// Run `f` against `user_id`'s device record, loading it first if needed,
    /// and write the record out if `f` changed it. A change that cannot be
    /// saved is an error: an approval that exists only in memory would be
    /// silently forgotten at the next start.
    pub fn with_device_pins<T>(
        &self,
        user_id: &str,
        f: impl FnOnce(&mut DevicePinBook) -> T,
    ) -> Result<T> {
        let mut book = self
            .device_pins
            .lock()
            .map_err(|_| QGuardError::Storage("device record lock poisoned".to_string()))?;
        if book.owner() != Some(user_id) || book.should_retry_load(Utc::now().timestamp()) {
            *book = self.load_device_pins(user_id);
        }
        let outcome = f(&mut *book);
        if book.is_available() && book.is_dirty() {
            let encoded = book.encode()?;
            self.write_storage_sealed_file(
                user_id,
                &self.device_pin_book_path(user_id),
                DEVICE_PIN_BOOK_AAD,
                &encoded,
                "device record",
            )?;
            book.mark_saved();
        }
        Ok(outcome)
    }

    /// How a device stands against `user_id`'s record, without recording
    /// anything. `None` means there is nothing to judge it against yet.
    pub fn device_standing(&self, user_id: &str, subject: &PinSubject) -> Option<DeviceStanding> {
        self.with_device_pins(user_id, |book| book.standing(subject))
            .ok()
            .flatten()
    }

    /// Refuse to seal anything to a device this device has not accepted.
    ///
    /// A device nobody has been judged against yet (no record for its owner)
    /// passes: first use is established by `devices_assess_pins`, which sees
    /// the owner's whole device list, not by whichever device happens to be
    /// addressed first.
    pub fn require_accepted_device(&self, user_id: &str, subject: &PinSubject) -> Result<()> {
        match self.device_standing(user_id, subject) {
            None | Some(DeviceStanding::Pinned) => Ok(()),
            Some(DeviceStanding::New) => Err(QGuardError::Trust(format!(
                "device {} was added to this contact after you first exchanged keys and has not been approved on this device; nothing is sent to it until it is",
                subject.device_id
            ))),
            Some(DeviceStanding::KeyChanged) => Err(QGuardError::Trust(format!(
                "device {} is presenting different identity keys than the ones recorded for it; nothing is sent to it",
                subject.device_id
            ))),
        }
    }

    // ---- Ratchet sessions (see crate::pq_ratchet) ---------------------------

    fn ratchet_sessions_path(&self, user_id: &str) -> PathBuf {
        let safe_user_id = Self::safe_user_key(user_id);
        self.data_dir
            .join("keys")
            .join(format!("{safe_user_id}.ratchet-sessions.enc"))
    }

    fn ratchet_setting_path(&self) -> PathBuf {
        self.data_dir.join("keys").join("ratchet-enabled")
    }

    /// Whether this install advertises the ratchet and starts sessions.
    ///
    /// `QGUARD_RATCHET=1/0` wins (operator switch, and `0` is the kill switch);
    /// otherwise the user's Settings → Advanced choice, off until they make it.
    /// Receiving ratchet envelopes does not depend on this.
    pub fn ratchet_enabled(&self) -> bool {
        if let Some(forced) = crate::pq_ratchet::env_override() {
            return forced;
        }
        let Ok(mut slot) = self.ratchet_setting.lock() else {
            return false;
        };
        if slot.is_none() {
            let stored = std::fs::read_to_string(self.ratchet_setting_path())
                .map(|text| text.trim() == "1")
                .unwrap_or(false);
            *slot = Some(stored);
        }
        slot.unwrap_or(false)
    }

    /// Record the user's choice. Takes effect for the next message; the device
    /// must re-publish its suite for peers to see the capability change.
    pub fn set_ratchet_enabled(&self, enabled: bool) -> Result<()> {
        write_atomic(&self.ratchet_setting_path(), if enabled { b"1" } else { b"0" })
            .map_err(|e| QGuardError::Storage(format!("write ratchet setting: {e}")))?;
        *self
            .ratchet_setting
            .lock()
            .map_err(|_| QGuardError::Storage("ratchet setting lock poisoned".to_string()))? = Some(enabled);
        Ok(())
    }

    /// Same three outcomes as the ledger and the device record: no file is a
    /// fresh book; a file that will not open is UNAVAILABLE and never written.
    fn load_ratchet_sessions(&self, user_id: &str, local_device: &str) -> SessionBook {
        let retry_after = Utc::now().timestamp() + RATCHET_SESSIONS_RETRY_SECS;
        match self.read_storage_sealed_file(
            user_id,
            &self.ratchet_sessions_path(user_id),
            RATCHET_SESSIONS_AAD,
            "ratchet sessions",
        ) {
            Ok(None) => SessionBook::empty(user_id, local_device),
            Ok(Some(plaintext)) => SessionBook::decode(user_id, local_device, &plaintext)
                .unwrap_or_else(|_| SessionBook::unavailable(user_id, local_device, retry_after)),
            Err(_) => SessionBook::unavailable(user_id, local_device, retry_after),
        }
    }

    /// Run `f` against the session book of `user_id` on `local_device`,
    /// loading it first if needed. Changes stay in memory until
    /// [`Self::persist_ratchet_sessions`].
    pub fn with_ratchet_sessions<T>(
        &self,
        user_id: &str,
        local_device: &str,
        f: impl FnOnce(&mut SessionBook) -> T,
    ) -> Result<T> {
        let lock = || {
            self.ratchet_sessions
                .lock()
                .map_err(|_| QGuardError::Storage("ratchet session lock poisoned".to_string()))
        };
        let previous_owner = {
            let book = lock()?;
            let current = book.owner() == Some(user_id) && book.local_device() == local_device;
            if current && !book.should_retry_load(Utc::now().timestamp()) {
                None
            } else {
                Some(book.owner().map(str::to_string))
            }
        };
        if let Some(previous_owner) = previous_owner {
            // Save what the outgoing book learned (ledger first, as always).
            // Best effort: an unsaved receiving state is re-derivable.
            if let Some(owner) = previous_owner {
                let _ = self.persist_ratchet_sessions(&owner);
            }
            let loaded = self.load_ratchet_sessions(user_id, local_device);
            *lock()? = loaded;
        }
        let mut book = lock()?;
        Ok(f(&mut *book))
    }

    /// Write the session book out — ALWAYS after the message-key ledger.
    ///
    /// That order is the contract that makes chain keys disposable: a message
    /// key a session has moved past exists only in the ledger, so the ledger
    /// on disk must never be behind the sessions on disk. Returns `Ok(false)`
    /// (nothing written) when the ledger cannot be flushed or the book is not
    /// usable; the book then stays dirty and a later call retries.
    pub fn persist_ratchet_sessions(&self, user_id: &str) -> Result<bool> {
        if !self.flush_message_keys(user_id)? {
            return Ok(false);
        }
        let mut book = self
            .ratchet_sessions
            .lock()
            .map_err(|_| QGuardError::Storage("ratchet session lock poisoned".to_string()))?;
        if book.owner() != Some(user_id) || !book.is_available() {
            return Ok(false);
        }
        if !book.is_dirty() {
            return Ok(true);
        }
        let encoded = book.encode()?;
        self.write_storage_sealed_file(
            user_id,
            &self.ratchet_sessions_path(user_id),
            RATCHET_SESSIONS_AAD,
            &encoded,
            "ratchet sessions",
        )?;
        book.mark_saved();
        Ok(true)
    }

    /// A small per-user document encrypted under the device storage key, at
    /// `keys/<user>.<suffix>.enc` (so a panic wipe removes it with the rest).
    /// `Ok(None)` when there is none.
    pub(crate) fn load_user_secret_doc(
        &self,
        user_id: &str,
        suffix: &str,
        aad: &[u8],
        what: &str,
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
        let path = self.user_secret_doc_path(user_id, suffix);
        self.read_storage_sealed_file(user_id, &path, aad, what)
    }

    pub(crate) fn save_user_secret_doc(&self, user_id: &str, suffix: &str, aad: &[u8], bytes: &[u8], what: &str) -> Result<()> {
        let path = self.user_secret_doc_path(user_id, suffix);
        self.write_storage_sealed_file(user_id, &path, aad, bytes, what)
    }

    pub(crate) fn delete_user_secret_doc(&self, user_id: &str, suffix: &str) {
        let _ = std::fs::remove_file(self.user_secret_doc_path(user_id, suffix));
    }

    fn user_secret_doc_path(&self, user_id: &str, suffix: &str) -> PathBuf {
        let safe_user_id = Self::safe_user_key(user_id);
        let safe_suffix: String = suffix.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
        self.data_dir.join("keys").join(format!("{safe_user_id}.{safe_suffix}.enc"))
    }

    fn ratchet_sessions_owner(&self) -> Option<String> {
        self.ratchet_sessions
            .lock()
            .ok()
            .and_then(|book| book.owner().map(str::to_string))
    }

    /// Write out whichever ledger is in memory, whoever owns it (window close),
    /// then the ratchet sessions that depend on it.
    pub fn flush_loaded_message_keys(&self) {
        if let Ok(mut ledger) = self.message_keys.lock() {
            let _ = self.write_message_keys(&mut ledger);
        }
        if let Some(owner) = self.ratchet_sessions_owner() {
            let _ = self.persist_ratchet_sessions(&owner);
        }
    }

    /// Save and then drop the in-memory ledger (sign-out).
    fn unload_message_keys(&self) {
        if let Ok(mut ledger) = self.message_keys.lock() {
            let _ = self.write_message_keys(&mut ledger);
            *ledger = MessageKeyLedger::default();
        }
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

    /// Deliberately discard this device's key material and mint a fresh
    /// identity. THE ONLY path that is allowed to destroy device keys.
    ///
    /// Everything sealed to the old keys -- the entire message history on the
    /// relay, in both directions -- becomes permanently unreadable on this
    /// device, which is precisely why nothing calls this automatically. It
    /// exists so a device whose key material genuinely cannot be opened is
    /// recoverable by explicit user action rather than by a silent re-key.
    pub fn reset_device_identity(&self, user_id: &str, label: &str) -> Result<PublicIdentityBundle> {
        let account = Self::safe_user_key(user_id);
        // Whatever row the discarded identity registered must stop being a
        // delivery target: nothing can decapsulate to it any more.
        if let Ok(identity) = self.identity.lock() {
            if let Some(previous) = identity.as_ref().filter(|item| item.user_id == user_id) {
                self.remember_superseded_device_id(previous.device_id.clone());
            }
        }
        // Clearing the DEK first means a crash between the two steps leaves an
        // unopenable file rather than material encrypted under a key that has
        // already been thrown away with no record.
        let _ = crate::security::keystore::delete_secret(&account, &self.data_dir);
        let _ = std::fs::remove_file(self.encrypted_key_material_path(user_id));
        let _ = std::fs::remove_file(self.key_material_path(user_id));
        // The message-key ledger was encrypted under the storage key that has
        // just been discarded, so it is unreadable from here on. Drop it from
        // memory WITHOUT flushing (a flush would re-create it under a new key
        // with the old contents) and remove the dead file.
        if let Ok(mut ledger) = self.message_keys.lock() {
            *ledger = MessageKeyLedger::default();
        }
        let _ = std::fs::remove_file(self.message_key_ledger_path(user_id));
        // Same for the ratchet sessions: sealed under the discarded key, and
        // dead anyway — peers will address the new device id.
        if let Ok(mut sessions) = self.ratchet_sessions.lock() {
            *sessions = SessionBook::default();
        }
        let _ = std::fs::remove_file(self.ratchet_sessions_path(user_id));
        self.install_prekey_retirements(&HashMap::new());

        // Drop every cached artefact of the old identity so `ensure_identity`
        // rebuilds from scratch instead of handing back what is still in RAM.
        if let Ok(mut identity) = self.identity.lock() {
            *identity = None;
        }
        if let Ok(mut signed) = self.signed_prekey.lock() {
            *signed = None;
        }
        if let Ok(mut otks) = self.one_time_prekeys.lock() {
            otks.clear();
        }
        if let Ok(mut legacy) = self.legacy_kem_keypairs.lock() {
            legacy.clear();
        }
        if let Ok(mut legacy) = self.legacy_signed_prekeys.lock() {
            legacy.clear();
        }
        if let Ok(mut legacy) = self.legacy_one_time_prekeys.lock() {
            legacy.clear();
        }
        if let Ok(mut ratchets) = self.ratchets.lock() {
            ratchets.clear();
        }
        if let Ok(mut cache) = self.decrypted_message_cache.lock() {
            cache.clear();
        }
        if let Ok(mut devices) = self.devices.lock() {
            devices.clear();
        }

        self.ensure_identity(user_id, label)
    }

    /// Destroy everything on THIS device that could open `user_id`'s messages
    /// or vault, and sign them out (panic wipe; also what a duress PIN does).
    ///
    /// Order matters: the device storage key goes first, so even a file that
    /// cannot be deleted is left encrypted under a key that no longer exists.
    /// Nothing is flushed on the way out — writing the ledger or sessions now
    /// would only re-create what is about to be removed. Encrypted vault
    /// containers are left in place: without the vault key they open only with
    /// the recovery kit the user holds themselves. Returns how many files were
    /// removed. Irreversible.
    pub fn panic_wipe(&self, user_id: &str) -> Result<usize> {
        let account = Self::safe_user_key(user_id);
        let key_error = crate::security::keystore::delete_secret(&account, &self.data_dir).err();

        // Memory first, without writing anything back.
        if let Ok(mut ledger) = self.message_keys.lock() {
            *ledger = MessageKeyLedger::default();
        }
        if let Ok(mut sessions) = self.ratchet_sessions.lock() {
            *sessions = SessionBook::default();
        }
        if let Ok(mut pins) = self.device_pins.lock() {
            *pins = DevicePinBook::default();
        }
        if let Ok(mut identity) = self.identity.lock() {
            *identity = None;
        }
        if let Ok(mut signed) = self.signed_prekey.lock() {
            *signed = None;
        }
        for list in [&self.one_time_prekeys, &self.legacy_one_time_prekeys] {
            if let Ok(mut list) = list.lock() {
                list.clear();
            }
        }
        if let Ok(mut legacy) = self.legacy_signed_prekeys.lock() {
            legacy.clear();
        }
        if let Ok(mut legacy) = self.legacy_kem_keypairs.lock() {
            legacy.clear();
        }
        if let Ok(mut ratchets) = self.ratchets.lock() {
            ratchets.clear();
        }
        if let Ok(mut cache) = self.decrypted_message_cache.lock() {
            cache.values_mut().for_each(|plaintext| plaintext.zeroize());
            cache.clear();
        }
        if let Ok(mut pending) = self.pending_call_keys.lock() {
            pending.clear();
        }
        self.install_prekey_retirements(&HashMap::new());
        let _ = self.clear_vault_session();
        self.clear_portable_identity();
        self.clear_applock_sek();
        self.lock_all_workspaces();

        // Then every file this account keeps here.
        let mut removed = 0usize;
        let prefix = format!("{account}.");
        if let Ok(entries) = std::fs::read_dir(self.data_dir.join("keys")) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(&prefix) && std::fs::remove_file(entry.path()).is_ok() {
                    removed += 1;
                }
            }
        }
        if self.load_applock_user_pointer().as_deref() == Some(user_id) {
            self.clear_applock_user_pointer();
        }
        // Signed out. Directly, not via `clear_auth_session_for`: that takes
        // the key-scope lock (callers may hold it) and flushes state that has
        // just been erased.
        if let Ok(mut sessions) = self.auth_sessions.lock() {
            sessions.remove(user_id);
        }
        if let Ok(mut current) = self.auth_session.lock() {
            if current.as_ref().is_some_and(|session| session.user_id == user_id) {
                *current = None;
            }
        }
        if let Some(error) = key_error {
            // The files are gone either way; say that the key could not be.
            return Err(QGuardError::Storage(format!(
                "local data was erased, but the device storage key could not be removed from the platform key store: {error}"
            )));
        }
        Ok(removed)
    }

    /// Test-only: give this account a (legacy-format) recovery record whose
    /// verifier is `verifier`, so recovery-key checks have something to match.
    #[cfg(test)]
    pub(crate) fn test_install_recovery_verifier(&self, user_id: &str, verifier: &str) {
        let material = PersistedVaultRecovery::personal([0u8; crate::crypto::symmetric::KEY_SIZE], verifier.to_string());
        let bytes = serde_json::to_vec(&material).unwrap();
        self.write_storage_sealed_file(
            user_id,
            &self.vault_recovery_legacy_path(user_id),
            &crate::security::obf::vault_recovery_material_aad(),
            &bytes,
            "vault recovery material",
        )
        .unwrap();
    }

    /// Pre-v2 recovery file: secrets protected by the device storage key only.
    /// Read for migration, never written.
    fn vault_recovery_legacy_path(&self, user_id: &str) -> PathBuf {
        let safe_user_id = Self::safe_user_key(user_id);
        self.data_dir
            .join("keys")
            .join(format!("{safe_user_id}.vault-recovery.enc"))
    }

    /// v2 recovery file. A new NAME, not just a new version field, so a build
    /// that predates it sees "no recovery configured" instead of mis-reading a
    /// sealed record as an all-zero wrapping key.
    fn vault_recovery_path(&self, user_id: &str) -> PathBuf {
        let safe_user_id = Self::safe_user_key(user_id);
        self.data_dir
            .join("keys")
            .join(format!("{safe_user_id}.vault-recovery.v2.enc"))
    }

    /// Read a JSON document that was encrypted under the device storage key.
    /// `Ok(None)` when the file does not exist.
    fn read_storage_sealed_file(
        &self,
        user_id: &str,
        path: &Path,
        aad: &[u8],
        what: &str,
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)
            .map_err(|e| QGuardError::Storage(format!("read {what}: {e}")))?;
        let file: EncryptedKeyMaterialFile = serde_json::from_slice(&bytes)
            .map_err(|e| QGuardError::Storage(format!("decode {what}: {e}")))?;
        let mut key = self.device_storage_key(user_id, false)?;
        let plaintext = crate::crypto::symmetric::decrypt(&key, &file.envelope, aad);
        key.zeroize();
        Ok(Some(zeroize::Zeroizing::new(plaintext?)))
    }

    /// Encrypt `plaintext` under the device storage key and write it atomically.
    fn write_storage_sealed_file(
        &self,
        user_id: &str,
        path: &Path,
        aad: &[u8],
        plaintext: &[u8],
        what: &str,
    ) -> Result<()> {
        let mut key = self.device_storage_key(user_id, true)?;
        let envelope = crate::crypto::symmetric::encrypt(&key, plaintext, aad);
        key.zeroize();
        let file = EncryptedKeyMaterialFile {
            version: 1,
            envelope: envelope?,
        };
        let serialized = serde_json::to_vec(&file)
            .map_err(|e| QGuardError::Storage(format!("encode {what}: {e}")))?;
        write_atomic(path, &serialized)
            .map_err(|e| QGuardError::Storage(format!("write {what}: {e}")))
    }

    fn vault_recovery_seal_key(
        vault_key: &[u8; crate::crypto::symmetric::KEY_SIZE],
    ) -> Result<[u8; crate::crypto::symmetric::KEY_SIZE]> {
        crate::crypto::kdf::derive_32(vault_key, VAULT_RECOVERY_SEAL_INFO)
    }

    fn vault_recovery_seal_aad(user_id: &str) -> Vec<u8> {
        format!("QGuard-Vault-Recovery-Secrets-v1:{user_id}").into_bytes()
    }

    fn load_vault_recovery_record(&self, user_id: &str) -> Result<Option<VaultRecoveryRecordV2>> {
        let Some(plaintext) = self.read_storage_sealed_file(
            user_id,
            &self.vault_recovery_path(user_id),
            &crate::security::obf::vault_recovery_material_aad(),
            "vault recovery material",
        )?
        else {
            return Ok(None);
        };
        let record: VaultRecoveryRecordV2 = serde_json::from_slice(&plaintext)
            .map_err(|e| QGuardError::Storage(format!("decode vault recovery payload: {e}")))?;
        Ok(Some(record))
    }

    fn load_vault_recovery_legacy(&self, user_id: &str) -> Result<Option<PersistedVaultRecovery>> {
        let Some(plaintext) = self.read_storage_sealed_file(
            user_id,
            &self.vault_recovery_legacy_path(user_id),
            &crate::security::obf::vault_recovery_material_aad(),
            "vault recovery material",
        )?
        else {
            return Ok(None);
        };
        let material: PersistedVaultRecovery = serde_json::from_slice(&plaintext)
            .map_err(|e| QGuardError::Storage(format!("decode vault recovery payload: {e}")))?;
        Ok(Some(material))
    }

    /// What can be known about recovery while the vault is LOCKED: whether it is
    /// configured, in which mode, and the one-way verifier. Never a key.
    pub fn load_vault_recovery_public(&self, user_id: &str) -> Result<Option<VaultRecoveryPublic>> {
        if let Some(record) = self.load_vault_recovery_record(user_id)? {
            return Ok(Some(VaultRecoveryPublic {
                mode: record.mode,
                verifier: record.verifier,
                configured_at: record.configured_at,
                recipient_key_id: record.recipient_key_id,
                enterprise_x25519_public: record.enterprise_x25519_public,
                enterprise_mlkem_public: record.enterprise_mlkem_public,
            }));
        }
        // Not migrated yet (the vault has not been unlocked since the upgrade).
        Ok(self.load_vault_recovery_legacy(user_id)?.map(|material| VaultRecoveryPublic {
            mode: material.recovery_mode().to_string(),
            verifier: material.verifier.clone(),
            configured_at: material.configured_at,
            recipient_key_id: material.recipient_key_id.clone(),
            enterprise_x25519_public: material.enterprise_x25519_public.clone(),
            enterprise_mlkem_public: material.enterprise_mlkem_public.clone(),
        }))
    }

    /// Persist the recovery configuration. The secret half (personal: the
    /// wrapping key; hybrid: the recovery root) is sealed under a key derived
    /// from the PIN-bound vault key, so this needs the vault unlocked.
    pub fn save_vault_recovery(
        &self,
        user_id: &str,
        material: &PersistedVaultRecovery,
        vault_key: &[u8; crate::crypto::symmetric::KEY_SIZE],
    ) -> Result<()> {
        let sealed_secrets = if material.holds_secrets() {
            let secrets = VaultRecoverySecrets {
                wrap_key: material.wrap_key,
                recovery_root: material.recovery_root,
            };
            let mut encoded = serde_json::to_vec(&secrets)
                .map_err(|e| QGuardError::Storage(format!("encode vault recovery secrets: {e}")))?;
            let mut seal_key = Self::vault_recovery_seal_key(vault_key)?;
            let envelope = crate::crypto::symmetric::encrypt(
                &seal_key,
                &encoded,
                &Self::vault_recovery_seal_aad(user_id),
            );
            seal_key.zeroize();
            encoded.zeroize();
            Some(envelope?)
        } else {
            None
        };
        let record = VaultRecoveryRecordV2 {
            version: 2,
            mode: material.recovery_mode().to_string(),
            verifier: material.verifier.clone(),
            configured_at: material.configured_at,
            enterprise_x25519_public: material.enterprise_x25519_public.clone(),
            enterprise_mlkem_public: material.enterprise_mlkem_public.clone(),
            recipient_key_id: material.recipient_key_id.clone(),
            sealed_secrets,
        };
        let encoded = serde_json::to_vec(&record)
            .map_err(|e| QGuardError::Storage(format!("encode vault recovery material: {e}")))?;
        self.write_storage_sealed_file(
            user_id,
            &self.vault_recovery_path(user_id),
            &crate::security::obf::vault_recovery_material_aad(),
            &encoded,
            "vault recovery material",
        )?;
        // The sealed copy is authoritative; the old layout kept the same secret
        // under the device storage key alone and must not outlive it.
        let _ = std::fs::remove_file(self.vault_recovery_legacy_path(user_id));
        Ok(())
    }

    /// The full recovery configuration, INCLUDING its secret half. Requires the
    /// PIN-bound vault key — i.e. the vault must be unlocked.
    ///
    /// A record still in the pre-v2 layout is migrated here, the first time the
    /// vault is unlocked after the upgrade.
    pub fn load_vault_recovery(
        &self,
        user_id: &str,
        vault_key: &[u8; crate::crypto::symmetric::KEY_SIZE],
    ) -> Result<Option<PersistedVaultRecovery>> {
        if let Some(record) = self.load_vault_recovery_record(user_id)? {
            let (wrap_key, recovery_root) = match record.sealed_secrets.as_ref() {
                Some(envelope) => {
                    let mut seal_key = Self::vault_recovery_seal_key(vault_key)?;
                    let opened = crate::crypto::symmetric::decrypt(
                        &seal_key,
                        envelope,
                        &Self::vault_recovery_seal_aad(user_id),
                    );
                    seal_key.zeroize();
                    let plaintext = zeroize::Zeroizing::new(opened.map_err(|_| {
                        QGuardError::Trust(
                            "The recovery key stored on this device was sealed under a different vault unlock key, so it cannot be used. Re-enter your recovery key under Recovery to enable it again."
                                .to_string(),
                        )
                    })?);
                    let secrets: VaultRecoverySecrets = serde_json::from_slice(&plaintext)
                        .map_err(|e| {
                            QGuardError::Storage(format!("decode vault recovery secrets: {e}"))
                        })?;
                    (secrets.wrap_key, secrets.recovery_root)
                }
                None => ([0u8; crate::crypto::symmetric::KEY_SIZE], None),
            };
            return Ok(Some(PersistedVaultRecovery {
                version: 2,
                wrap_key,
                verifier: record.verifier,
                configured_at: record.configured_at,
                mode: Some(record.mode),
                recovery_root,
                enterprise_x25519_public: record.enterprise_x25519_public,
                enterprise_mlkem_public: record.enterprise_mlkem_public,
                recipient_key_id: record.recipient_key_id,
            }));
        }

        let Some(legacy) = self.load_vault_recovery_legacy(user_id)? else {
            return Ok(None);
        };
        // Best effort: a failed rewrite must not stop the vault working — the
        // material in hand is correct, and the next unlock retries the move.
        let _ = self.save_vault_recovery(user_id, &legacy, vault_key);
        Ok(Some(legacy))
    }

    /// Move a pre-v2 recovery record under the vault key. Called on unlock so the
    /// storage-key-only copy disappears as soon as the vault is next opened,
    /// rather than waiting for the next encryption.
    pub fn migrate_vault_recovery(
        &self,
        user_id: &str,
        vault_key: &[u8; crate::crypto::symmetric::KEY_SIZE],
    ) {
        if self.vault_recovery_legacy_path(user_id).exists() {
            let _ = self.load_vault_recovery(user_id, vault_key);
        }
    }

    /// Forget the recovery configuration on this device (both layouts).
    pub fn delete_vault_recovery(&self, user_id: &str) {
        let _ = std::fs::remove_file(self.vault_recovery_path(user_id));
        let _ = std::fs::remove_file(self.vault_recovery_legacy_path(user_id));
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
        let key = self.device_storage_key(user_id, false)?;
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
        let key = self.device_storage_key(user_id, true)?;
        let envelope = crate::crypto::symmetric::encrypt(&key, &encoded, &crate::security::obf::workspace_material_aad())?;
        let file = EncryptedKeyMaterialFile { version: 1, envelope };
        let serialized = serde_json::to_vec(&file)
            .map_err(|e| QGuardError::Storage(format!("encode encrypted workspace scope: {e}")))?;
        write_atomic(&self.workspace_scope_path(user_id, &material.scope), &serialized)
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
        let key = self.device_storage_key(user_id, false)?;
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

    fn applock_pointer_path(&self) -> PathBuf {
        self.data_dir.join("keys").join("applock.current")
    }

    /// Persist which user's app-lock is enrolled on this device, so the PIN
    /// screen can be shown on a COLD LAUNCH before any Supabase session exists.
    /// The applock config file is keyed by user id; without this pointer the
    /// app can't tell whose PIN to prompt for and falls back to full email/
    /// password login. The value is an opaque account UUID — not a secret.
    pub fn save_applock_user_pointer(&self, user_id: &str) -> Result<()> {
        write_atomic(&self.applock_pointer_path(), user_id.as_bytes())
            .map_err(|e| QGuardError::Storage(format!("write applock pointer: {e}")))
    }

    pub fn load_applock_user_pointer(&self) -> Option<String> {
        std::fs::read_to_string(self.applock_pointer_path())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    fn clear_applock_user_pointer(&self) {
        let _ = std::fs::remove_file(self.applock_pointer_path());
    }

    pub fn save_applock(&self, user_id: &str, material: &PersistedAppLock) -> Result<()> {
        let mut encoded = serde_json::to_vec(material)
            .map_err(|e| QGuardError::Storage(format!("encode applock: {e}")))?;
        let key = self.device_storage_key(user_id, true)?;
        let envelope = crate::crypto::symmetric::encrypt(
            &key,
            &encoded,
            &crate::security::obf::applock_material_aad(),
        );
        encoded.zeroize();
        let file = EncryptedKeyMaterialFile { version: 1, envelope: envelope? };
        let serialized = serde_json::to_vec(&file)
            .map_err(|e| QGuardError::Storage(format!("encode encrypted applock: {e}")))?;
        write_atomic(&self.applock_path(user_id), &serialized)
            .map_err(|e| QGuardError::Storage(format!("write applock: {e}")))?;
        // Point this device at the enrolled user so a cold-launch PIN prompt
        // can find the config before any session is restored.
        self.save_applock_user_pointer(user_id)?;
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
        let key = self.device_storage_key(user_id, false)?;
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
        self.clear_applock_user_pointer();
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

    /// Hold an unlocked Portable Hybrid Identity for this session, replacing any
    /// identity already unlocked (whose secrets are zeroized as it drops).
    pub fn set_portable_identity(
        &self,
        identity: crate::crypto::portable_identity::PortableIdentity,
    ) -> Result<()> {
        *self
            .portable_identity
            .lock()
            .map_err(|_| QGuardError::Storage("portable identity lock poisoned".to_string()))? =
            Some(identity);
        Ok(())
    }

    /// The unlocked Portable Hybrid Identity, or an error naming what to do.
    pub fn unlocked_portable_identity(
        &self,
    ) -> Result<crate::crypto::portable_identity::PortableIdentity> {
        self.portable_identity
            .lock()
            .map_err(|_| QGuardError::Storage("portable identity lock poisoned".to_string()))?
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                QGuardError::Trust(
                    "No portable identity is unlocked — generate or import a .qgkey first"
                        .to_string(),
                )
            })
    }

    /// Drop the unlocked identity (its keypairs zeroize their secrets on drop).
    pub fn clear_portable_identity(&self) {
        if let Ok(mut guard) = self.portable_identity.lock() {
            guard.take();
        }
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
        // An unlocked portable identity is share key material, so it locks with
        // the vault rather than outliving it.
        self.clear_portable_identity();
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
        // Before the keys go: anything opened this session but not yet written
        // to the ledger is saved — ledger first, then the ratchet sessions that
        // depend on it — and both leave memory.
        if let Some(owner) = self.ratchet_sessions_owner() {
            let _ = self.persist_ratchet_sessions(&owner);
        }
        *self
            .ratchet_sessions
            .lock()
            .map_err(|_| QGuardError::Storage("ratchet session lock poisoned".to_string()))? =
            SessionBook::default();
        self.unload_message_keys();
        self.install_prekey_retirements(&HashMap::new());
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
        self.pending_call_keys
            .lock()
            .map_err(|_| QGuardError::Storage("pending call key lock poisoned".to_string()))?
            .clear();
        // Already on disk (every change is written as it is made); only the
        // in-memory copy leaves with the session.
        *self
            .device_pins
            .lock()
            .map_err(|_| QGuardError::Storage("device record lock poisoned".to_string()))? =
            DevicePinBook::default();
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
        let key = format!("{scope}:{target}");
        let mut attempts = self
            .decrypt_attempts
            .lock()
            .map_err(|_| QGuardError::Storage("decrypt attempt lock poisoned".to_string()))?;
        if !rate_window_admit(attempts.entry(key).or_default(), now, limit, window_seconds) {
            return Err(QGuardError::Trust(
                "Too many secure key operations. Wait a few minutes and try again.".to_string(),
            ));
        }
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

    /// Key material that EXISTS but cannot be opened must never be silently
    /// replaced. The old code treated any load error as a first launch, minted a
    /// new identity and overwrote the file -- so one unreadable byte destroyed
    /// the device's keys for good and turned the entire message history into
    /// "not found: local signed prekey". A fault must surface as a fault.
    #[test]
    fn unreadable_key_material_is_reported_not_overwritten() {
        let dir = unique_temp_dir();
        let user_id = format!("test-user-{}", uuid::Uuid::new_v4());

        let original_device_id = {
            let state = AppState::new(dir.clone()).expect("create state");
            state
                .ensure_identity(&user_id, "Test Device")
                .expect("ensure 1")
                .device_id
        };

        // Corrupt the stored envelope the way a truncated write or a restored
        // backup would: the file is still valid JSON of the right shape, but its
        // ciphertext no longer authenticates under the DEK.
        let path = AppState::new(dir.clone())
            .expect("create state")
            .encrypted_key_material_path(&user_id);
        let raw = std::fs::read(&path).expect("read key material");
        let mut file: EncryptedKeyMaterialFile =
            serde_json::from_slice(&raw).expect("decode key material file");
        file.envelope.ciphertext[0] ^= 0xff;
        std::fs::write(&path, serde_json::to_vec(&file).expect("encode")).expect("write");

        let state = AppState::new(dir.clone()).expect("create state");
        let error = state
            .ensure_identity(&user_id, "Test Device")
            .expect_err("an unopenable key material file must not be silently re-keyed");
        assert!(
            format!("{error}").contains("could not be opened"),
            "expected a load fault, got {error}"
        );

        // The file itself must still be there, untouched: recovery depends on it.
        assert!(path.exists(), "key material must not be deleted by a failed load");

        // And the only path allowed to discard it does mint a fresh identity.
        let reset = state
            .reset_device_identity(&user_id, "Test Device")
            .expect("explicit reset");
        assert_ne!(
            reset.device_id, original_device_id,
            "an explicit reset must produce a new device identity"
        );

        cleanup(&user_id, &dir);
    }

    /// A device registered before the FIPS 203 cutover published
    /// `pq_kem: "ML-KEM-1024"` while holding Kyber-1024 keys of identical
    /// length. Only the absence of `pq_kem_standard` distinguishes it, and
    /// sealing to it produces a permanently undecryptable message.
    #[test]
    fn pre_fips_published_suite_is_not_interoperable() {
        let pre_fips: crate::crypto::AlgorithmSuite = serde_json::from_str(
            r#"{"classical_kex":"X25519","pq_kem":"ML-KEM-1024","kdf":"HKDF-SHA3-256",
                "symmetric":"AES-256-GCM","classical_signature":"Ed25519",
                "pq_signature":"ML-DSA-65"}"#,
        )
        .expect("decode a pre-cutover suite");
        assert_eq!(pre_fips.pq_kem, crate::crypto::CURRENT_PQ_KEM);
        assert!(
            !pre_fips.kem_interoperates(),
            "a suite with no FIPS 203 marker must never be treated as interoperable"
        );
        assert!(crate::crypto::AlgorithmSuite::default().kem_interoperates());
    }

    fn test_master() -> PersistedVaultMaster {
        PersistedVaultMaster {
            version: 1,
            vmk: crate::crypto::symmetric::random_key(),
            signer: VaultSigningKeypair::generate(),
            configured_at: Utc::now(),
        }
    }

    /// The PIN-bound vault key must not be reachable from the raw VMK, because
    /// the raw VMK is recoverable from any legacy container by whoever holds
    /// the device storage key. It must also be a stable function of the stored
    /// master, so both unlock credentials arrive at the same key.
    #[test]
    fn the_vault_key_needs_more_than_the_master_key() {
        let master = test_master();
        let key = master.vault_key().unwrap();
        assert_eq!(key, master.vault_key().unwrap(), "must be deterministic");
        assert_ne!(key, master.vmk, "the vault key must not be the raw VMK");

        // Same VMK, different signing secrets: an attacker who recovered the VMK
        // from an old header but never saw the password-wrapped master blob.
        let same_vmk_only = PersistedVaultMaster {
            version: 1,
            vmk: master.vmk,
            signer: VaultSigningKeypair::generate(),
            configured_at: master.configured_at,
        };
        assert_ne!(same_vmk_only.vault_key().unwrap(), key);

        // It survives the serialise -> wrap -> unwrap -> deserialise round trip
        // the master goes through on every lock/unlock.
        let restored: PersistedVaultMaster =
            serde_json::from_slice(&serde_json::to_vec(&master).unwrap()).unwrap();
        assert_eq!(restored.vault_key().unwrap(), key);
    }

    #[test]
    fn recovery_secrets_are_only_reachable_with_the_vault_key() {
        let dir = unique_temp_dir();
        let user_id = format!("test-user-{}", uuid::Uuid::new_v4());
        let state = AppState::new(dir.clone()).expect("create state");
        let vault_key = crate::crypto::symmetric::random_key();
        let wrap_key = crate::crypto::symmetric::random_key();
        state
            .save_vault_recovery(
                &user_id,
                &PersistedVaultRecovery::personal(wrap_key, "verifier-1".to_string()),
                &vault_key,
            )
            .expect("save recovery");

        // Locked: mode and verifier are visible, and nothing else.
        let public = state
            .load_vault_recovery_public(&user_id)
            .expect("public load")
            .expect("configured");
        assert_eq!(public.mode, "personal");
        assert_eq!(public.verifier, "verifier-1");

        // Unlocked with the right vault key: the wrapping key comes back.
        let loaded = state
            .load_vault_recovery(&user_id, &vault_key)
            .expect("load")
            .expect("configured");
        assert_eq!(loaded.wrap_key, wrap_key);

        // A different vault key (i.e. after a vault reset) is REFUSED — it must
        // not read as "no recovery configured", or new files would silently be
        // written without their recovery wrap.
        let other_vault_key = crate::crypto::symmetric::random_key();
        assert!(state.load_vault_recovery(&user_id, &other_vault_key).is_err());

        // The regression itself: open the file with the device storage key
        // alone, as an attacker holding only that key would, and look for the
        // recovery wrapping key. It must not be there in any encoding serde
        // would have produced for the old layout.
        let outer = state
            .read_storage_sealed_file(
                &user_id,
                &state.vault_recovery_path(&user_id),
                &crate::security::obf::vault_recovery_material_aad(),
                "vault recovery material",
            )
            .expect("outer layer opens with the storage key")
            .expect("file exists");
        let outer_text = String::from_utf8_lossy(&outer).to_string();
        let as_json_array = serde_json::to_string(&wrap_key).unwrap();
        assert!(
            !outer_text.contains(as_json_array.trim_matches(|c| c == '[' || c == ']')),
            "the recovery wrapping key is readable with the device storage key alone"
        );

        cleanup(&user_id, &dir);
    }

    #[test]
    fn a_pre_v2_recovery_record_moves_under_the_vault_key_on_unlock() {
        let dir = unique_temp_dir();
        let user_id = format!("test-user-{}", uuid::Uuid::new_v4());
        let state = AppState::new(dir.clone()).expect("create state");
        let vault_key = crate::crypto::symmetric::random_key();
        let wrap_key = crate::crypto::symmetric::random_key();

        // Exactly what an older build left behind: the whole record, secret
        // included, under the device storage key only.
        let legacy = PersistedVaultRecovery::personal(wrap_key, "legacy-verifier".to_string());
        state
            .write_storage_sealed_file(
                &user_id,
                &state.vault_recovery_legacy_path(&user_id),
                &crate::security::obf::vault_recovery_material_aad(),
                &serde_json::to_vec(&legacy).unwrap(),
                "legacy vault recovery material",
            )
            .expect("write legacy record");

        // Still reported while locked, before any migration.
        let public = state
            .load_vault_recovery_public(&user_id)
            .expect("public load")
            .expect("configured");
        assert_eq!(public.verifier, "legacy-verifier");

        state.migrate_vault_recovery(&user_id, &vault_key);
        assert!(
            !state.vault_recovery_legacy_path(&user_id).exists(),
            "the storage-key-only copy must not outlive the first unlock"
        );
        assert!(state.vault_recovery_path(&user_id).exists());
        let migrated = state
            .load_vault_recovery(&user_id, &vault_key)
            .expect("load")
            .expect("configured");
        assert_eq!(migrated.wrap_key, wrap_key);
        assert_eq!(migrated.verifier, "legacy-verifier");

        cleanup(&user_id, &dir);
    }

    #[test]
    fn enterprise_recovery_keeps_no_secret_and_needs_no_vault_key_to_survive_a_reset() {
        let dir = unique_temp_dir();
        let user_id = format!("test-user-{}", uuid::Uuid::new_v4());
        let state = AppState::new(dir.clone()).expect("create state");
        let vault_key = crate::crypto::symmetric::random_key();
        let enterprise = LocalKemKeypair::generate();
        state
            .save_vault_recovery(
                &user_id,
                &PersistedVaultRecovery {
                    version: 2,
                    wrap_key: [0u8; crate::crypto::symmetric::KEY_SIZE],
                    verifier: "fingerprint".to_string(),
                    configured_at: Utc::now(),
                    mode: Some("enterprise".to_string()),
                    recovery_root: None,
                    enterprise_x25519_public: Some(enterprise.x25519_public.clone()),
                    enterprise_mlkem_public: Some(enterprise.mlkem_public.clone()),
                    recipient_key_id: Some("fingerprint".to_string()),
                },
                &vault_key,
            )
            .expect("save");

        // Public keys only, so ANY vault key (a new one after a reset included)
        // can keep wrapping new files to the enterprise recipient.
        let after_reset = crate::crypto::symmetric::random_key();
        let loaded = state
            .load_vault_recovery(&user_id, &after_reset)
            .expect("load")
            .expect("configured");
        assert_eq!(loaded.recovery_mode(), "enterprise");
        assert_eq!(
            loaded.enterprise_mlkem_public.as_deref(),
            Some(enterprise.mlkem_public.as_slice())
        );

        cleanup(&user_id, &dir);
    }

    #[test]
    fn atomic_write_replaces_the_target_and_leaves_nothing_behind() {
        let dir = unique_temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("material.enc");

        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second version, longer than the first").unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"second version, longer than the first"
        );
        // A shorter rewrite must not leave the tail of the previous content.
        write_atomic(&path, b"3").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"3");

        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name != "material.enc")
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");

        // A failed write (no such directory) must not disturb anything or leave
        // a stray temp file where the directory would have been.
        assert!(write_atomic(&dir.join("missing").join("x.enc"), b"y").is_err());
        assert!(!dir.join("missing").exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"3");

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn contact_device(device: &str, keys: &str) -> PinSubject {
        PinSubject {
            user_id: "contact-user".to_string(),
            device_id: device.to_string(),
            digest: crate::device_pins::identity_digest(keys.as_bytes(), b"mldsa", b"x25519", b"mlkem"),
        }
    }

    /// The device record is what stands between a directory row and a sealed
    /// message. It has to gate delivery, survive a restart, and — the part
    /// that is easy to get wrong — never be replaced by a fresh "first use"
    /// record just because the stored one could not be read.
    #[test]
    fn device_pins_gate_delivery_persist_and_are_never_silently_reset() {
        let dir = unique_temp_dir();
        let user_id = format!("test-user-{}", uuid::Uuid::new_v4());
        let phone = contact_device("phone", "k1");
        let tablet = contact_device("tablet", "k2");

        {
            let state = AppState::new(dir.clone()).expect("create state");
            // Nobody recorded yet: there is nothing to refuse against.
            assert!(state.require_accepted_device(&user_id, &phone).is_ok());

            let standings = state
                .with_device_pins(&user_id, |book| book.assess(&[phone.clone()], 100))
                .expect("assess");
            assert_eq!(standings, vec![Some(DeviceStanding::Pinned)]);

            assert!(state.require_accepted_device(&user_id, &phone).is_ok());
            // A device the directory lists later, and the same id with other keys.
            let added = state.require_accepted_device(&user_id, &tablet).unwrap_err();
            assert!(format!("{added}").contains("has not been approved"), "{added}");
            let swapped = state
                .require_accepted_device(&user_id, &contact_device("phone", "attacker"))
                .unwrap_err();
            assert!(format!("{swapped}").contains("different identity keys"), "{swapped}");
        }

        {
            // Restart: the record, not the directory, still decides.
            let state = AppState::new(dir.clone()).expect("create state");
            assert!(state.require_accepted_device(&user_id, &phone).is_ok());
            assert!(state.require_accepted_device(&user_id, &tablet).is_err());

            state
                .with_device_pins(&user_id, |book| book.approve(&tablet, 200))
                .expect("store approval")
                .expect("approve");
            assert!(state.require_accepted_device(&user_id, &tablet).is_ok());
        }

        let path = {
            // Restart again: the approval was written, not just remembered.
            let state = AppState::new(dir.clone()).expect("create state");
            assert!(state.require_accepted_device(&user_id, &tablet).is_ok());
            state.device_pin_book_path(&user_id)
        };

        // The stored record becomes unreadable (a truncated write, a restored
        // backup): still valid JSON of the right shape, but it no longer
        // authenticates under the storage key.
        let mut file: EncryptedKeyMaterialFile =
            serde_json::from_slice(&std::fs::read(&path).expect("read record")).expect("decode record");
        file.envelope.ciphertext[0] ^= 0xff;
        let corrupted = serde_json::to_vec(&file).expect("encode");
        std::fs::write(&path, &corrupted).expect("write");

        {
            let state = AppState::new(dir.clone()).expect("create state");
            let stranger = contact_device("stranger", "k9");
            // It answers nothing...
            let standings = state
                .with_device_pins(&user_id, |book| book.assess(&[stranger.clone()], 300))
                .expect("assess against an unreadable record");
            assert_eq!(standings, vec![None]);
            assert_eq!(state.device_standing(&user_id, &stranger), None);
            // ...approves nothing...
            assert!(state
                .with_device_pins(&user_id, |book| book.approve(&stranger, 300))
                .expect("approval attempt")
                .is_err());
            // ...and above all is NOT overwritten with a record that would
            // make whatever is listed right now look like first use.
            assert_eq!(std::fs::read(&path).expect("read record"), corrupted);
        }

        cleanup(&user_id, &dir);
    }
}
