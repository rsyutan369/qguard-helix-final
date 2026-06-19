use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::State;

use zeroize::Zeroize;

use crate::crypto::hybrid_kex::LocalKemKeypair;
use crate::crypto::signatures::LocalSigningKeypair;
use crate::crypto::vault_recovery;
use crate::crypto::AlgorithmSuite;
use crate::error::{QGuardError, Result};
use crate::file_crypto::{
    decrypt_file_for_device, decrypt_file_name_for_device, decrypt_file_with_recovery,
    encrypt_file_for_device, rewrap_package_with_recovery, verify_file_metadata,
    EncryptedFilePackage, EncryptionContext,
};
use crate::state::{AppState, PersistedVaultRecovery};
use crate::vault_stream::{self, FolderReader, FolderWriter, StreamSummary};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEncryptRequest {
    pub file_name: String,
    pub content_type: String,
    pub plaintext_base64: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct VaultShareGrant {
    pub file_id: String,
    pub recipient_user_id: String,
    pub recipient_device_id: String,
    pub status: String,
}

#[tauri::command]
pub fn vault_encrypt_upload(
    state: State<'_, AppState>,
    request: VaultEncryptRequest,
) -> Result<EncryptedFilePackage> {
    let identity_bundle = state.ensure_identity(&state.user_id()?, "Windows Desktop")?;
    let owner_user_id = state.user_id()?;
    // Uploaded-vault recovery currently supports personal mode only; enterprise/
    // hybrid recovery is wired for the local .qvault path.
    let recovery_wrap_key = state
        .load_vault_recovery(&owner_user_id)?
        .filter(|material| material.recovery_mode() == "personal")
        .map(|material| material.wrap_key);
    let plaintext = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(request.plaintext_base64)
            .map_err(|e| QGuardError::InvalidInput(format!("invalid base64: {e}")))?
    };
    let identity = state
        .identity
        .lock()
        .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
    let identity = identity
        .as_ref()
        .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
    let signer = LocalSigningKeypair {
        ed25519_secret: identity.signing.ed25519_secret,
        ed25519_public: identity.signing.ed25519_public.clone(),
        mldsa_secret: identity.signing.mldsa_secret.clone(),
        mldsa_public: identity.signing.mldsa_public.clone(),
    };
    let recipient = (
        &identity.kem.x25519_public[..],
        &identity.kem.mlkem_public[..],
    );
    let package = encrypt_file_for_device(
        &request.file_name,
        &request.content_type,
        &plaintext,
        EncryptionContext {
            owner_user_id,
            owner_device_id: identity_bundle.device_id.clone(),
        },
        &identity_bundle.device_id,
        recipient,
        &signer,
        recovery_wrap_key.as_ref(),
    )?;
    state.touch_telemetry(
        "vault",
        "File encrypted locally; upload should store ciphertext only",
        100,
    );
    state.audit_info(
        "vault_encrypt_upload",
        "Quantum vault package prepared for Supabase Storage",
    );
    Ok(package)
}

#[tauri::command]
pub fn vault_download_decrypt(
    state: State<'_, AppState>,
    package: EncryptedFilePackage,
) -> Result<String> {
    state.require_auth()?;
    let session_user_id = state.user_id()?;
    state.ensure_identity(&session_user_id, "Windows Desktop")?;
    state.check_decrypt_rate_limit("vault_file", &package.metadata.file_id, 8, 300)?;
    let identity = state
        .identity
        .lock()
        .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
    let identity = identity
        .as_ref()
        .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
    let recipient = LocalKemKeypair {
        x25519_secret: identity.kem.x25519_secret,
        x25519_public: identity.kem.x25519_public.clone(),
        mlkem_secret: identity.kem.mlkem_secret.clone(),
        mlkem_public: identity.kem.mlkem_public.clone(),
    };
    let context = EncryptionContext {
        owner_user_id: identity.user_id.clone(),
        owner_device_id: identity.device_id.clone(),
    };
    let plaintext = match decrypt_file_for_device(
        &package,
        &identity.device_id,
        &recipient,
        context.clone(),
    ) {
        Ok(plaintext) => plaintext,
        Err(current_error) => {
            let legacy_kems = state
                .legacy_kem_keypairs
                .lock()
                .map_err(|_| QGuardError::Storage("legacy KEM keypair lock poisoned".to_string()))?
                .clone();
            decrypt_with_legacy_kems(&package, &identity.device_id, &legacy_kems, context)
                .map_err(|legacy_error| {
                    QGuardError::Crypto(format!(
                        "current ML-KEM-1024 unwrap failed: {current_error}; legacy unwrap fallback failed: {legacy_error}"
                    ))
                })?
        }
    };
    state.touch_telemetry(
        "vault_decrypt",
        "Client-side vault decrypt completed with local key material",
        100,
    );
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(plaintext))
}

#[tauri::command]
pub fn vault_decrypt_file_name(
    state: State<'_, AppState>,
    package: EncryptedFilePackage,
) -> Result<String> {
    state.require_auth()?;
    let session_user_id = state.user_id()?;
    state.ensure_identity(&session_user_id, "Windows Desktop")?;
    state.check_decrypt_rate_limit("vault_filename", &package.metadata.file_id, 24, 300)?;
    let identity = state
        .identity
        .lock()
        .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
    let identity = identity
        .as_ref()
        .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
    let recipient = LocalKemKeypair {
        x25519_secret: identity.kem.x25519_secret,
        x25519_public: identity.kem.x25519_public.clone(),
        mlkem_secret: identity.kem.mlkem_secret.clone(),
        mlkem_public: identity.kem.mlkem_public.clone(),
    };
    let context = EncryptionContext {
        owner_user_id: identity.user_id.clone(),
        owner_device_id: identity.device_id.clone(),
    };
    match decrypt_file_name_for_device(&package, &identity.device_id, &recipient, context.clone()) {
        Ok(file_name) => Ok(file_name),
        Err(current_error) => {
            let legacy_kems = state
                .legacy_kem_keypairs
                .lock()
                .map_err(|_| QGuardError::Storage("legacy KEM keypair lock poisoned".to_string()))?
                .clone();
            decrypt_file_name_with_legacy_kems(&package, &identity.device_id, &legacy_kems, context)
                .map_err(|legacy_error| {
                    QGuardError::Crypto(format!(
                        "current ML-KEM-1024 filename unwrap failed: {current_error}; legacy unwrap fallback failed: {legacy_error}"
                    ))
                })
        }
    }
}

#[tauri::command]
pub fn vault_share_file(
    state: State<'_, AppState>,
    file_id: String,
    recipient_user_id: String,
    recipient_device_id: String,
) -> Result<VaultShareGrant> {
    state.require_auth()?;
    state.audit_info("vault_share", "Encrypted file grant created");
    Ok(VaultShareGrant {
        file_id,
        recipient_user_id,
        recipient_device_id,
        status: "granted_ciphertext_only".to_string(),
    })
}

#[tauri::command]
pub fn vault_revoke_file_access(
    state: State<'_, AppState>,
    file_id: String,
    recipient_device_id: String,
) -> Result<VaultShareGrant> {
    state.require_auth()?;
    state.audit_info("vault_revoke", "Encrypted file grant revoked");
    Ok(VaultShareGrant {
        file_id,
        recipient_user_id: "revoked".to_string(),
        recipient_device_id,
        status: "revoked".to_string(),
    })
}

#[tauri::command]
pub fn vault_verify_metadata(
    state: State<'_, AppState>,
    package: EncryptedFilePackage,
) -> Result<bool> {
    state.require_auth()?;
    verify_file_metadata(&package)?;
    Ok(true)
}

fn decrypt_with_legacy_kems(
    package: &EncryptedFilePackage,
    current_device_id: &str,
    legacy_kems: &[LocalKemKeypair],
    context: EncryptionContext,
) -> Result<Vec<u8>> {
    let mut last_error: Option<QGuardError> = None;
    for legacy_kem in legacy_kems {
        match decrypt_file_for_device(package, current_device_id, legacy_kem, context.clone()) {
            Ok(plaintext) => return Ok(plaintext),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        QGuardError::NotFound("legacy ML-KEM-768 vault KEM material".to_string())
    }))
}

fn decrypt_file_name_with_legacy_kems(
    package: &EncryptedFilePackage,
    current_device_id: &str,
    legacy_kems: &[LocalKemKeypair],
    context: EncryptionContext,
) -> Result<String> {
    let mut last_error: Option<QGuardError> = None;
    for legacy_kem in legacy_kems {
        match decrypt_file_name_for_device(package, current_device_id, legacy_kem, context.clone())
        {
            Ok(file_name) => return Ok(file_name),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        QGuardError::NotFound("legacy ML-KEM-768 vault KEM material".to_string())
    }))
}

// ---------------------------------------------------------------------------
// Local-first streaming vault: encrypt/decrypt files and folders directly on
// the user's disk (any size, fully offline) using the same hybrid PQC stack.
// ---------------------------------------------------------------------------

/// Non-secret result returned to the UI after a local stream operation.
#[derive(Clone, Debug, Serialize)]
pub struct VaultLocalStreamSummary {
    pub file_id: String,
    pub kind: String,
    pub name: String,
    pub content_type: String,
    pub original_size: u64,
    pub total_chunks: u64,
    pub source_path: String,
    pub output_path: String,
    pub suite: AlgorithmSuite,
}

impl VaultLocalStreamSummary {
    fn from_stream(summary: StreamSummary, source_path: String, output_path: String) -> Self {
        Self {
            file_id: summary.file_id,
            kind: summary.kind,
            name: summary.name,
            content_type: summary.content_type,
            original_size: summary.original_size,
            total_chunks: summary.total_chunks,
            source_path,
            output_path,
            suite: summary.suite,
        }
    }
}

/// Local device crypto material: signer + the device KEM keys (current first,
/// then any rotated/legacy keys) used to wrap/unwrap vault objects on-device.
struct LocalVaultContext {
    user_id: String,
    device_id: String,
    signer: LocalSigningKeypair,
    kem_x25519_public: Vec<u8>,
    kem_mlkem_public: Vec<u8>,
    recipient_kems: Vec<LocalKemKeypair>,
    /// Personal-mode recovery wrap key for this user, if configured.
    recovery_wrap_key: Option<[u8; crate::crypto::symmetric::KEY_SIZE]>,
    /// Enterprise/hybrid recovery recipient, if configured.
    enterprise_recipient: Option<EnterpriseRecipientOwned>,
}

struct EnterpriseRecipientOwned {
    x25519_public: Vec<u8>,
    mlkem_public: Vec<u8>,
    /// Set (hybrid mode) means files require both the recovery key and the
    /// enterprise ML-KEM key to recover.
    recovery_secret: Option<[u8; crate::crypto::symmetric::KEY_SIZE]>,
}

fn local_vault_context(state: &AppState) -> Result<LocalVaultContext> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let identity_bundle = state.ensure_identity(&user_id, "Windows Desktop")?;

    let (signer, kem_x25519_public, kem_mlkem_public, current_kem) = {
        let guard = state
            .identity
            .lock()
            .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
        let identity = guard
            .as_ref()
            .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
        let signer = LocalSigningKeypair {
            ed25519_secret: identity.signing.ed25519_secret,
            ed25519_public: identity.signing.ed25519_public.clone(),
            mldsa_secret: identity.signing.mldsa_secret.clone(),
            mldsa_public: identity.signing.mldsa_public.clone(),
        };
        let current_kem = LocalKemKeypair {
            x25519_secret: identity.kem.x25519_secret,
            x25519_public: identity.kem.x25519_public.clone(),
            mlkem_secret: identity.kem.mlkem_secret.clone(),
            mlkem_public: identity.kem.mlkem_public.clone(),
        };
        (
            signer,
            identity.kem.x25519_public.clone(),
            identity.kem.mlkem_public.clone(),
            current_kem,
        )
    };

    let mut recipient_kems = vec![current_kem];
    if let Ok(legacy) = state.legacy_kem_keypairs.lock() {
        recipient_kems.extend(legacy.iter().cloned());
    }

    let (recovery_wrap_key, enterprise_recipient) = match state.load_vault_recovery(&user_id)? {
        Some(material) => match material.recovery_mode() {
            "enterprise" => (
                None,
                Some(EnterpriseRecipientOwned {
                    x25519_public: material.enterprise_x25519_public.clone().unwrap_or_default(),
                    mlkem_public: material.enterprise_mlkem_public.clone().unwrap_or_default(),
                    recovery_secret: None,
                }),
            ),
            "hybrid" => (
                None,
                Some(EnterpriseRecipientOwned {
                    x25519_public: material.enterprise_x25519_public.clone().unwrap_or_default(),
                    mlkem_public: material.enterprise_mlkem_public.clone().unwrap_or_default(),
                    recovery_secret: material.recovery_root,
                }),
            ),
            _ => (Some(material.wrap_key), None),
        },
        None => (None, None),
    };

    Ok(LocalVaultContext {
        user_id,
        device_id: identity_bundle.device_id,
        signer,
        kem_x25519_public,
        kem_mlkem_public,
        recipient_kems,
        recovery_wrap_key,
        enterprise_recipient,
    })
}

impl LocalVaultContext {
    fn enterprise(&self) -> Option<vault_stream::EnterpriseRecipient<'_>> {
        self.enterprise_recipient.as_ref().map(|e| vault_stream::EnterpriseRecipient {
            x25519_public: &e.x25519_public,
            mlkem_public: &e.mlkem_public,
            recovery_secret: e.recovery_secret.as_ref(),
        })
    }
}

fn part_path(dest_path: &str) -> String {
    format!("{dest_path}.qguard-part")
}

#[tauri::command]
pub fn vault_encrypt_path(
    state: State<'_, AppState>,
    source_path: String,
    dest_path: String,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state)?;
    let metadata = std::fs::metadata(&source_path)
        .map_err(|e| QGuardError::Storage(format!("read source file: {e}")))?;
    if !metadata.is_file() {
        return Err(QGuardError::InvalidInput(
            "selected source is not a file".to_string(),
        ));
    }
    let original_size = metadata.len();
    let name = Path::new(&source_path)
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());

    let tmp = part_path(&dest_path);
    let mut reader = BufReader::new(
        File::open(&source_path).map_err(|e| QGuardError::Storage(format!("open source: {e}")))?,
    );
    let summary = {
        let mut writer = BufWriter::new(
            File::create(&tmp)
                .map_err(|e| QGuardError::Storage(format!("create output: {e}")))?,
        );
        match vault_stream::encrypt_stream(
            &mut reader,
            &mut writer,
            vault_stream::KIND_FILE,
            &name,
            "application/octet-stream",
            original_size,
            &ctx.user_id,
            &ctx.device_id,
            &ctx.kem_x25519_public,
            &ctx.kem_mlkem_public,
            &ctx.signer,
            ctx.recovery_wrap_key.as_ref(),
            ctx.enterprise().as_ref(),
        ) {
            Ok(summary) => {
                writer
                    .flush()
                    .map_err(|e| QGuardError::Storage(format!("flush output: {e}")))?;
                summary
            }
            Err(error) => {
                drop(writer);
                let _ = std::fs::remove_file(&tmp);
                return Err(error);
            }
        }
    };
    std::fs::rename(&tmp, &dest_path)
        .map_err(|e| QGuardError::Storage(format!("finalize output: {e}")))?;

    state.audit_info(
        "vault_local_encrypt",
        "File encrypted to a local quantum-safe vault stream",
    );
    state.touch_telemetry(
        "vault",
        "Local file sealed with X25519+ML-KEM-1024 / AES-256-GCM streaming container",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(summary, source_path, dest_path))
}

#[tauri::command]
pub fn vault_decrypt_path(
    state: State<'_, AppState>,
    source_path: String,
    dest_path: String,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state)?;
    state.check_decrypt_rate_limit("vault_local_file", &source_path, 60, 300)?;

    let tmp = part_path(&dest_path);
    let mut last_error: Option<QGuardError> = None;
    for kem in &ctx.recipient_kems {
        let mut reader = match File::open(&source_path) {
            Ok(file) => BufReader::new(file),
            Err(e) => return Err(QGuardError::Storage(format!("open encrypted source: {e}"))),
        };
        let mut writer = BufWriter::new(
            File::create(&tmp)
                .map_err(|e| QGuardError::Storage(format!("create output: {e}")))?,
        );
        match vault_stream::decrypt_stream(&mut reader, &mut writer, kem) {
            Ok(summary) => {
                writer
                    .flush()
                    .map_err(|e| QGuardError::Storage(format!("flush output: {e}")))?;
                drop(writer);
                std::fs::rename(&tmp, &dest_path)
                    .map_err(|e| QGuardError::Storage(format!("finalize output: {e}")))?;
                state.audit_info(
                    "vault_local_decrypt",
                    "Local quantum-safe vault stream decrypted on-device",
                );
                state.touch_telemetry(
                    "vault_decrypt",
                    "Local vault stream decrypted with device-bound ML-KEM-1024 key",
                    100,
                );
                return Ok(VaultLocalStreamSummary::from_stream(summary, source_path, dest_path));
            }
            Err(error) => {
                drop(writer);
                let _ = std::fs::remove_file(&tmp);
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        QGuardError::Crypto("local vault stream could not be decrypted on this device".to_string())
    }))
}

#[tauri::command]
pub fn vault_encrypt_folder_path(
    state: State<'_, AppState>,
    source_dir: String,
    dest_path: String,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state)?;
    let root = PathBuf::from(&source_dir);
    if !root.is_dir() {
        return Err(QGuardError::InvalidInput(
            "selected source is not a folder".to_string(),
        ));
    }
    let (entries, total) = vault_stream::collect_folder_entries(&root)?;
    if entries.is_empty() {
        return Err(QGuardError::InvalidInput(
            "selected folder has no files to encrypt".to_string(),
        ));
    }
    let name = root
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "vault-folder".to_string());

    let tmp = part_path(&dest_path);
    let mut reader = FolderReader::new(entries);
    let summary = {
        let mut writer = BufWriter::new(
            File::create(&tmp)
                .map_err(|e| QGuardError::Storage(format!("create output: {e}")))?,
        );
        match vault_stream::encrypt_stream(
            &mut reader,
            &mut writer,
            vault_stream::KIND_FOLDER,
            &name,
            "application/qguard-folder-archive",
            total,
            &ctx.user_id,
            &ctx.device_id,
            &ctx.kem_x25519_public,
            &ctx.kem_mlkem_public,
            &ctx.signer,
            ctx.recovery_wrap_key.as_ref(),
            ctx.enterprise().as_ref(),
        ) {
            Ok(summary) => {
                writer
                    .flush()
                    .map_err(|e| QGuardError::Storage(format!("flush output: {e}")))?;
                summary
            }
            Err(error) => {
                drop(writer);
                let _ = std::fs::remove_file(&tmp);
                return Err(error);
            }
        }
    };
    std::fs::rename(&tmp, &dest_path)
        .map_err(|e| QGuardError::Storage(format!("finalize output: {e}")))?;

    state.audit_info(
        "vault_local_encrypt_folder",
        "Folder archived into a local quantum-safe vault stream",
    );
    state.touch_telemetry(
        "vault",
        "Local folder sealed into a single X25519+ML-KEM-1024 / AES-256-GCM archive",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(summary, source_dir, dest_path))
}

#[tauri::command]
pub fn vault_decrypt_folder_path(
    state: State<'_, AppState>,
    source_path: String,
    dest_dir: String,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state)?;
    state.check_decrypt_rate_limit("vault_local_folder", &source_path, 30, 300)?;
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| QGuardError::Storage(format!("create destination folder: {e}")))?;

    let mut last_error: Option<QGuardError> = None;
    for kem in &ctx.recipient_kems {
        let mut reader = match File::open(&source_path) {
            Ok(file) => BufReader::new(file),
            Err(e) => return Err(QGuardError::Storage(format!("open encrypted source: {e}"))),
        };
        let mut writer = FolderWriter::new(PathBuf::from(&dest_dir));
        match vault_stream::decrypt_stream(&mut reader, &mut writer, kem) {
            Ok(summary) => {
                writer
                    .flush()
                    .map_err(|e| QGuardError::Storage(format!("flush output: {e}")))?;
                state.audit_info(
                    "vault_local_decrypt_folder",
                    "Local quantum-safe folder archive decrypted on-device",
                );
                state.touch_telemetry(
                    "vault_decrypt",
                    "Local folder archive restored with device-bound ML-KEM-1024 key",
                    100,
                );
                return Ok(VaultLocalStreamSummary::from_stream(summary, source_path, dest_dir));
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        QGuardError::Crypto("local vault folder archive could not be decrypted on this device".to_string())
    }))
}

// ---------------------------------------------------------------------------
// Quantum-safe vault recovery: survive total device loss with an offline key.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultRecoveryStatus {
    pub enabled: bool,
    pub mode: Option<String>,
    pub recipient_key_id: Option<String>,
    pub configured_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultRecoverySetup {
    pub mode: String,
    /// Personal / hybrid: the offline recovery key string.
    pub recovery_key: Option<String>,
    /// Enterprise / hybrid: the ML-KEM-1024 enterprise recovery private key (for
    /// the admin to download and store offline).
    pub enterprise_private_key: Option<String>,
    pub enterprise_fingerprint: Option<String>,
}

#[tauri::command]
pub fn vault_recovery_status(state: State<'_, AppState>) -> Result<VaultRecoveryStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    Ok(match state.load_vault_recovery(&user_id)? {
        Some(material) => VaultRecoveryStatus {
            enabled: true,
            mode: Some(material.recovery_mode().to_string()),
            recipient_key_id: material.recipient_key_id.clone(),
            configured_at: Some(material.configured_at.to_rfc3339()),
        },
        None => VaultRecoveryStatus {
            enabled: false,
            mode: None,
            recipient_key_id: None,
            configured_at: None,
        },
    })
}

/// Configure vault recovery in one of three modes:
/// * `personal`   — returns a recovery key to store offline.
/// * `enterprise` — returns an ML-KEM-1024 enterprise recovery private key file.
/// * `hybrid`     — returns both (recovery requires both factors).
#[tauri::command]
pub fn vault_setup_recovery(state: State<'_, AppState>, mode: String) -> Result<VaultRecoverySetup> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    if state.load_vault_recovery(&user_id)?.is_some() {
        return Err(QGuardError::InvalidInput(
            "Recovery is already configured for this account.".to_string(),
        ));
    }
    let setup = match mode.trim().to_lowercase().as_str() {
        "personal" => {
            let mut root = vault_recovery::generate_recovery_root();
            let recovery_key = vault_recovery::encode_recovery_key(&root);
            let wrap_key = vault_recovery::derive_wrap_key(&root)?;
            let verifier = vault_recovery::derive_verifier(&root)?;
            root.zeroize();
            state.save_vault_recovery(&user_id, &PersistedVaultRecovery::personal(wrap_key, verifier))?;
            VaultRecoverySetup {
                mode: "personal".to_string(),
                recovery_key: Some(recovery_key),
                enterprise_private_key: None,
                enterprise_fingerprint: None,
            }
        }
        "enterprise" => {
            let keypair = vault_recovery::generate_enterprise_keypair();
            let fingerprint =
                vault_recovery::enterprise_key_fingerprint(&keypair.x25519_public, &keypair.mlkem_public);
            let private_key = vault_recovery::encode_enterprise_private_key(&keypair)?;
            state.save_vault_recovery(
                &user_id,
                &PersistedVaultRecovery {
                    version: 1,
                    wrap_key: [0u8; crate::crypto::symmetric::KEY_SIZE],
                    verifier: fingerprint.clone(),
                    configured_at: chrono::Utc::now(),
                    mode: Some("enterprise".to_string()),
                    recovery_root: None,
                    enterprise_x25519_public: Some(keypair.x25519_public.clone()),
                    enterprise_mlkem_public: Some(keypair.mlkem_public.clone()),
                    recipient_key_id: Some(fingerprint.clone()),
                },
            )?;
            VaultRecoverySetup {
                mode: "enterprise".to_string(),
                recovery_key: None,
                enterprise_private_key: Some(private_key),
                enterprise_fingerprint: Some(fingerprint),
            }
        }
        "hybrid" => {
            let root = vault_recovery::generate_recovery_root();
            let recovery_key = vault_recovery::encode_recovery_key(&root);
            let verifier = vault_recovery::derive_verifier(&root)?;
            let keypair = vault_recovery::generate_enterprise_keypair();
            let fingerprint =
                vault_recovery::enterprise_key_fingerprint(&keypair.x25519_public, &keypair.mlkem_public);
            let private_key = vault_recovery::encode_enterprise_private_key(&keypair)?;
            state.save_vault_recovery(
                &user_id,
                &PersistedVaultRecovery {
                    version: 1,
                    wrap_key: [0u8; crate::crypto::symmetric::KEY_SIZE],
                    verifier,
                    configured_at: chrono::Utc::now(),
                    mode: Some("hybrid".to_string()),
                    recovery_root: Some(root),
                    enterprise_x25519_public: Some(keypair.x25519_public.clone()),
                    enterprise_mlkem_public: Some(keypair.mlkem_public.clone()),
                    recipient_key_id: Some(fingerprint.clone()),
                },
            )?;
            VaultRecoverySetup {
                mode: "hybrid".to_string(),
                recovery_key: Some(recovery_key),
                enterprise_private_key: Some(private_key),
                enterprise_fingerprint: Some(fingerprint),
            }
        }
        other => {
            return Err(QGuardError::InvalidInput(format!("unsupported recovery mode: {other}")));
        }
    };
    state.audit_info("vault_recovery_configured", "Quantum-safe vault recovery configured");
    state.touch_telemetry(
        "vault",
        "Quantum-safe vault recovery configured (AES-256-GCM / HKDF-SHA3-256 / ML-KEM-1024)",
        100,
    );
    Ok(setup)
}

/// Enable an existing personal recovery key on this device.
#[tauri::command]
pub fn vault_enable_recovery_with_phrase(
    state: State<'_, AppState>,
    recovery_key: String,
) -> Result<VaultRecoveryStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let mut root = vault_recovery::decode_recovery_key(&recovery_key)?;
    let wrap_key = vault_recovery::derive_wrap_key(&root)?;
    let verifier = vault_recovery::derive_verifier(&root)?;
    root.zeroize();
    if let Some(existing) = state.load_vault_recovery(&user_id)? {
        if existing.verifier != verifier {
            return Err(QGuardError::InvalidInput(
                "This recovery key does not match the one already configured on this device.".to_string(),
            ));
        }
    }
    state.save_vault_recovery(&user_id, &PersistedVaultRecovery::personal(wrap_key, verifier))?;
    state.audit_info(
        "vault_recovery_enabled_on_device",
        "Vault recovery key enabled on this device",
    );
    Ok(VaultRecoveryStatus {
        enabled: true,
        mode: Some("personal".to_string()),
        recipient_key_id: None,
        configured_at: state
            .load_vault_recovery(&user_id)?
            .map(|material| material.configured_at.to_rfc3339()),
    })
}

/// Re-protect an existing `.qvault` container by adding the recovery-key wrap to
/// its header in place (chunks are copied unchanged). Use this on a working
/// device to make files that predate recovery setup recoverable.
#[tauri::command]
pub fn vault_rewrap_path(
    state: State<'_, AppState>,
    source_path: String,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state)?;
    let recovery_wrap_key = ctx.recovery_wrap_key.ok_or_else(|| {
        QGuardError::InvalidInput(
            "Set up a recovery key first, then re-protect existing files.".to_string(),
        )
    })?;

    let tmp = part_path(&source_path);
    let summary = {
        let mut reader = BufReader::new(
            File::open(&source_path)
                .map_err(|e| QGuardError::Storage(format!("open vault file: {e}")))?,
        );
        let mut writer = BufWriter::new(
            File::create(&tmp).map_err(|e| QGuardError::Storage(format!("create output: {e}")))?,
        );
        match vault_stream::rewrap_stream_with_recovery(
            &mut reader,
            &mut writer,
            &ctx.recipient_kems,
            &ctx.signer,
            &recovery_wrap_key,
        ) {
            Ok(summary) => {
                writer
                    .flush()
                    .map_err(|e| QGuardError::Storage(format!("flush output: {e}")))?;
                summary
            }
            Err(error) => {
                drop(writer);
                let _ = std::fs::remove_file(&tmp);
                return Err(error);
            }
        }
        // reader + writer are dropped here, releasing the file handles before rename.
    };
    std::fs::rename(&tmp, &source_path)
        .map_err(|e| QGuardError::Storage(format!("finalize re-protected file: {e}")))?;
    state.audit_info(
        "vault_recovery_rewrap",
        "Existing vault container re-protected with the recovery key",
    );
    state.touch_telemetry(
        "vault",
        "Existing vault file re-protected with quantum-safe recovery key",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(
        summary,
        source_path.clone(),
        source_path,
    ))
}

#[tauri::command]
pub fn vault_decrypt_path_with_recovery(
    state: State<'_, AppState>,
    source_path: String,
    dest_path: String,
    recovery_key: String,
) -> Result<VaultLocalStreamSummary> {
    state.require_auth()?;
    state.check_decrypt_rate_limit("vault_recovery_file", &source_path, 30, 300)?;
    let mut root = vault_recovery::decode_recovery_key(&recovery_key)?;
    let mut wrap_key = vault_recovery::derive_wrap_key(&root)?;
    root.zeroize();

    let tmp = part_path(&dest_path);
    let mut reader = BufReader::new(
        File::open(&source_path).map_err(|e| QGuardError::Storage(format!("open encrypted source: {e}")))?,
    );
    let mut writer = BufWriter::new(
        File::create(&tmp).map_err(|e| QGuardError::Storage(format!("create output: {e}")))?,
    );
    let result = vault_stream::decrypt_stream_with_recovery(&mut reader, &mut writer, &wrap_key);
    wrap_key.zeroize();
    match result {
        Ok(summary) => {
            writer
                .flush()
                .map_err(|e| QGuardError::Storage(format!("flush output: {e}")))?;
            drop(writer);
            std::fs::rename(&tmp, &dest_path)
                .map_err(|e| QGuardError::Storage(format!("finalize output: {e}")))?;
            state.audit_info(
                "vault_recovery_decrypt",
                "Vault file recovered with quantum-safe recovery key",
            );
            state.touch_telemetry(
                "vault_decrypt",
                "Vault file recovered on a new device using the recovery key",
                100,
            );
            Ok(VaultLocalStreamSummary::from_stream(summary, source_path, dest_path))
        }
        Err(error) => {
            drop(writer);
            let _ = std::fs::remove_file(&tmp);
            Err(error)
        }
    }
}

#[tauri::command]
pub fn vault_decrypt_folder_path_with_recovery(
    state: State<'_, AppState>,
    source_path: String,
    dest_dir: String,
    recovery_key: String,
) -> Result<VaultLocalStreamSummary> {
    state.require_auth()?;
    state.check_decrypt_rate_limit("vault_recovery_folder", &source_path, 20, 300)?;
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| QGuardError::Storage(format!("create destination folder: {e}")))?;
    let mut root = vault_recovery::decode_recovery_key(&recovery_key)?;
    let mut wrap_key = vault_recovery::derive_wrap_key(&root)?;
    root.zeroize();

    let mut reader = BufReader::new(
        File::open(&source_path).map_err(|e| QGuardError::Storage(format!("open encrypted source: {e}")))?,
    );
    let mut writer = FolderWriter::new(PathBuf::from(&dest_dir));
    let result = vault_stream::decrypt_stream_with_recovery(&mut reader, &mut writer, &wrap_key);
    wrap_key.zeroize();
    match result {
        Ok(summary) => {
            writer
                .flush()
                .map_err(|e| QGuardError::Storage(format!("flush output: {e}")))?;
            state.audit_info(
                "vault_recovery_decrypt_folder",
                "Vault folder recovered with quantum-safe recovery key",
            );
            state.touch_telemetry(
                "vault_decrypt",
                "Vault folder recovered on a new device using the recovery key",
                100,
            );
            Ok(VaultLocalStreamSummary::from_stream(summary, source_path, dest_dir))
        }
        Err(error) => Err(error),
    }
}

/// Decrypt an uploaded vault package with the recovery key (new-device recovery).
#[tauri::command]
pub fn vault_download_decrypt_with_recovery(
    state: State<'_, AppState>,
    package: EncryptedFilePackage,
    recovery_key: String,
) -> Result<String> {
    state.require_auth()?;
    let owner_user_id = state.user_id()?;
    state.check_decrypt_rate_limit("vault_recovery_upload", &package.metadata.file_id, 30, 300)?;
    let mut root = vault_recovery::decode_recovery_key(&recovery_key)?;
    let mut wrap_key = vault_recovery::derive_wrap_key(&root)?;
    root.zeroize();
    let plaintext = decrypt_file_with_recovery(&package, &owner_user_id, &wrap_key);
    wrap_key.zeroize();
    let plaintext = plaintext?;
    state.audit_info(
        "vault_recovery_decrypt_upload",
        "Uploaded vault file recovered with the recovery key",
    );
    state.touch_telemetry(
        "vault_decrypt",
        "Uploaded vault file recovered on a new device using the recovery key",
        100,
    );
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(plaintext))
}

/// Re-protect an existing uploaded package by adding the recovery wrap and
/// re-signing it. Returns the updated package for the caller to re-store
/// (chunks are unchanged; only the manifest needs rewriting).
#[tauri::command]
pub fn vault_rewrap_package(
    state: State<'_, AppState>,
    package: EncryptedFilePackage,
) -> Result<EncryptedFilePackage> {
    let ctx = local_vault_context(&state)?;
    let recovery_wrap_key = ctx.recovery_wrap_key.ok_or_else(|| {
        QGuardError::InvalidInput(
            "Set up a recovery key first, then re-protect existing files.".to_string(),
        )
    })?;
    let updated = rewrap_package_with_recovery(
        &package,
        &ctx.user_id,
        &ctx.recipient_kems,
        &recovery_wrap_key,
        &ctx.signer,
    )?;
    state.audit_info(
        "vault_recovery_rewrap_upload",
        "Uploaded vault package re-protected with the recovery key",
    );
    state.touch_telemetry(
        "vault",
        "Uploaded vault file re-protected with quantum-safe recovery key",
        100,
    );
    Ok(updated)
}

/// Recover a local `.qvault` file with the enterprise ML-KEM-1024 recovery key.
/// For hybrid containers, the personal `recovery_key` is also required.
#[tauri::command]
pub fn vault_decrypt_path_with_enterprise(
    state: State<'_, AppState>,
    source_path: String,
    dest_path: String,
    enterprise_key: String,
    recovery_key: Option<String>,
) -> Result<VaultLocalStreamSummary> {
    state.require_auth()?;
    state.check_decrypt_rate_limit("vault_enterprise_file", &source_path, 30, 300)?;
    let recipient = vault_recovery::decode_enterprise_private_key(&enterprise_key)?;
    let root = match recovery_key {
        Some(key) if !key.trim().is_empty() => Some(vault_recovery::decode_recovery_key(&key)?),
        _ => None,
    };

    let tmp = part_path(&dest_path);
    let mut reader = BufReader::new(
        File::open(&source_path).map_err(|e| QGuardError::Storage(format!("open encrypted source: {e}")))?,
    );
    let mut writer = BufWriter::new(
        File::create(&tmp).map_err(|e| QGuardError::Storage(format!("create output: {e}")))?,
    );
    let result = vault_stream::decrypt_stream_with_enterprise(&mut reader, &mut writer, &recipient, root.as_ref());
    match result {
        Ok(summary) => {
            writer
                .flush()
                .map_err(|e| QGuardError::Storage(format!("flush output: {e}")))?;
            drop(writer);
            std::fs::rename(&tmp, &dest_path)
                .map_err(|e| QGuardError::Storage(format!("finalize output: {e}")))?;
            state.audit_info(
                "vault_enterprise_recovery_decrypt",
                "Vault file recovered with enterprise ML-KEM-1024 key",
            );
            state.touch_telemetry(
                "vault_decrypt",
                "Vault file recovered with enterprise ML-KEM-1024 recovery key",
                100,
            );
            Ok(VaultLocalStreamSummary::from_stream(summary, source_path, dest_path))
        }
        Err(error) => {
            drop(writer);
            let _ = std::fs::remove_file(&tmp);
            Err(error)
        }
    }
}

#[tauri::command]
pub fn vault_decrypt_folder_path_with_enterprise(
    state: State<'_, AppState>,
    source_path: String,
    dest_dir: String,
    enterprise_key: String,
    recovery_key: Option<String>,
) -> Result<VaultLocalStreamSummary> {
    state.require_auth()?;
    state.check_decrypt_rate_limit("vault_enterprise_folder", &source_path, 20, 300)?;
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| QGuardError::Storage(format!("create destination folder: {e}")))?;
    let recipient = vault_recovery::decode_enterprise_private_key(&enterprise_key)?;
    let root = match recovery_key {
        Some(key) if !key.trim().is_empty() => Some(vault_recovery::decode_recovery_key(&key)?),
        _ => None,
    };
    let mut reader = BufReader::new(
        File::open(&source_path).map_err(|e| QGuardError::Storage(format!("open encrypted source: {e}")))?,
    );
    let mut writer = FolderWriter::new(PathBuf::from(&dest_dir));
    let result = vault_stream::decrypt_stream_with_enterprise(&mut reader, &mut writer, &recipient, root.as_ref());
    match result {
        Ok(summary) => {
            writer
                .flush()
                .map_err(|e| QGuardError::Storage(format!("flush output: {e}")))?;
            state.audit_info(
                "vault_enterprise_recovery_decrypt_folder",
                "Vault folder recovered with enterprise ML-KEM-1024 key",
            );
            state.touch_telemetry(
                "vault_decrypt",
                "Vault folder recovered with enterprise ML-KEM-1024 recovery key",
                100,
            );
            Ok(VaultLocalStreamSummary::from_stream(summary, source_path, dest_dir))
        }
        Err(error) => Err(error),
    }
}
