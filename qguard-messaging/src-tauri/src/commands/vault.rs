use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::crypto::hybrid_kex::LocalKemKeypair;
use crate::crypto::signatures::LocalSigningKeypair;
use crate::crypto::AlgorithmSuite;
use crate::error::{QGuardError, Result};
use crate::file_crypto::{
    decrypt_file_for_device, decrypt_file_name_for_device, encrypt_file_for_device,
    verify_file_metadata, EncryptedFilePackage, EncryptionContext,
};
use crate::state::AppState;
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

    Ok(LocalVaultContext {
        user_id,
        device_id: identity_bundle.device_id,
        signer,
        kem_x25519_public,
        kem_mlkem_public,
        recipient_kems,
    })
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
