use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::State;

use zeroize::Zeroize;

use crate::crypto::hybrid_kex::LocalKemKeypair;
use crate::crypto::vault_recovery;
use crate::crypto::AlgorithmSuite;
use crate::error::{QGuardError, Result};
use crate::state::{AppState, PersistedVaultMaster, PersistedVaultRecovery};
use crate::vault_stream::{self, FolderReader, FolderWriter, StreamSummary};

// ---------------------------------------------------------------------------
// Local-first streaming vault: encrypt/decrypt files and folders directly on
// the user's disk (any size, fully offline) using the same hybrid PQC stack.
// The Quantum Vault is strictly local — there is no cloud upload/download/share
// path. All cryptography happens on-device; nothing leaves the machine.
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
    /// Vault Master Key + the ML-DSA-87 vault signing key (loaded-or-created).
    vault_master: PersistedVaultMaster,
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
    // The Vault Master Key + ML-DSA-87 signing key are only available while the
    // Quantum Vault workspace is unlocked (password/PIN). Locked => this errors,
    // gating every vault operation behind the workspace unlock.
    let vault_master = state.unlocked_vault_master()?;

    let (kem_x25519_public, kem_mlkem_public, current_kem) = {
        let guard = state
            .identity
            .lock()
            .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
        let identity = guard
            .as_ref()
            .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
        let current_kem = LocalKemKeypair {
            x25519_secret: identity.kem.x25519_secret,
            x25519_public: identity.kem.x25519_public.clone(),
            mlkem_secret: identity.kem.mlkem_secret.clone(),
            mlkem_public: identity.kem.mlkem_public.clone(),
        };
        (
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
        vault_master,
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

/// Run a blocking vault stream job on the Tauri blocking thread pool.
///
/// Vault containers can be many gigabytes; a synchronous Tauri command executes
/// on the MAIN thread, so running the chunk loop there blocks the window event
/// loop for the whole stream — the app goes "Not Responding", progress Channel
/// delivery stalls, and the UI freezes. Every stream command below is therefore
/// async and does its file I/O + crypto inside `spawn_blocking`, keeping the
/// event loop free and progress events flowing in real time.
async fn run_stream_blocking<T, F>(job: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(job)
        .await
        .map_err(|e| QGuardError::Storage(format!("vault stream worker failed: {e}")))?
}

#[tauri::command]
pub async fn vault_encrypt_path(
    state: State<'_, AppState>,
    source_path: String,
    dest_path: String,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state)?;
    let source_for_result = source_path.clone();
    let dest_for_result = dest_path.clone();
    let summary = run_stream_blocking(move || {
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
            match vault_stream::encrypt_stream_with_progress(
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
                &ctx.vault_master.vmk,
                &ctx.vault_master.signer,
                ctx.recovery_wrap_key.as_ref(),
                ctx.enterprise().as_ref(),
                &mut |p| { let _ = on_progress.send(p); },
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
        Ok(summary)
    })
    .await?;

    state.audit_info(
        "vault_local_encrypt",
        "File encrypted to a local quantum-safe vault stream",
    );
    state.touch_telemetry(
        "vault",
        "Local file sealed with X25519+ML-KEM-1024 / AES-256-GCM streaming container",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(summary, source_for_result, dest_for_result))
}

#[tauri::command]
pub async fn vault_decrypt_path(
    state: State<'_, AppState>,
    source_path: String,
    dest_path: String,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state)?;
    state.check_decrypt_rate_limit("vault_local_file", &source_path, 60, 300)?;

    let source_for_result = source_path.clone();
    let dest_for_result = dest_path.clone();
    let summary = run_stream_blocking(move || {
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
            match vault_stream::decrypt_stream_with_progress(&mut reader, &mut writer, kem, &mut |p| { let _ = on_progress.send(p); }) {
                Ok(summary) => {
                    writer
                        .flush()
                        .map_err(|e| QGuardError::Storage(format!("flush output: {e}")))?;
                    drop(writer);
                    std::fs::rename(&tmp, &dest_path)
                        .map_err(|e| QGuardError::Storage(format!("finalize output: {e}")))?;
                    return Ok(summary);
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
    })
    .await?;

    state.audit_info(
        "vault_local_decrypt",
        "Local quantum-safe vault stream decrypted on-device",
    );
    state.touch_telemetry(
        "vault_decrypt",
        "Local vault stream decrypted with device-bound ML-KEM-1024 key",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(summary, source_for_result, dest_for_result))
}

#[tauri::command]
pub async fn vault_encrypt_folder_path(
    state: State<'_, AppState>,
    source_dir: String,
    dest_path: String,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state)?;
    let source_for_result = source_dir.clone();
    let dest_for_result = dest_path.clone();
    let summary = run_stream_blocking(move || {
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
            match vault_stream::encrypt_stream_with_progress(
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
                &ctx.vault_master.vmk,
                &ctx.vault_master.signer,
                ctx.recovery_wrap_key.as_ref(),
                ctx.enterprise().as_ref(),
                &mut |p| { let _ = on_progress.send(p); },
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
        Ok(summary)
    })
    .await?;

    state.audit_info(
        "vault_local_encrypt_folder",
        "Folder archived into a local quantum-safe vault stream",
    );
    state.touch_telemetry(
        "vault",
        "Local folder sealed into a single X25519+ML-KEM-1024 / AES-256-GCM archive",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(summary, source_for_result, dest_for_result))
}

#[tauri::command]
pub async fn vault_decrypt_folder_path(
    state: State<'_, AppState>,
    source_path: String,
    dest_dir: String,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state)?;
    state.check_decrypt_rate_limit("vault_local_folder", &source_path, 30, 300)?;

    let source_for_result = source_path.clone();
    let dest_for_result = dest_dir.clone();
    let summary = run_stream_blocking(move || {
        std::fs::create_dir_all(&dest_dir)
            .map_err(|e| QGuardError::Storage(format!("create destination folder: {e}")))?;

        let mut last_error: Option<QGuardError> = None;
        for kem in &ctx.recipient_kems {
            let mut reader = match File::open(&source_path) {
                Ok(file) => BufReader::new(file),
                Err(e) => return Err(QGuardError::Storage(format!("open encrypted source: {e}"))),
            };
            let mut writer = FolderWriter::new(PathBuf::from(&dest_dir));
            match vault_stream::decrypt_stream_with_progress(&mut reader, &mut writer, kem, &mut |p| { let _ = on_progress.send(p); }) {
                Ok(summary) => {
                    writer
                        .flush()
                        .map_err(|e| QGuardError::Storage(format!("flush output: {e}")))?;
                    return Ok(summary);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            QGuardError::Crypto("local vault folder archive could not be decrypted on this device".to_string())
        }))
    })
    .await?;

    state.audit_info(
        "vault_local_decrypt_folder",
        "Local quantum-safe folder archive decrypted on-device",
    );
    state.touch_telemetry(
        "vault_decrypt",
        "Local folder archive restored with device-bound ML-KEM-1024 key",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(summary, source_for_result, dest_for_result))
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

/// Re-protect an existing `.qvault` container by rebuilding it as a v3 VMK
/// envelope (ML-KEM-1024-protected VMK + ML-DSA-87 signature) in place, adding
/// the recovery / enterprise wraps when configured. Chunks are copied unchanged.
/// Use this on a working device to upgrade older v1/v2 files (and to make files
/// that predate recovery setup recoverable).
#[tauri::command]
pub async fn vault_rewrap_path(
    state: State<'_, AppState>,
    source_path: String,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state)?;

    let source_for_result = source_path.clone();
    let summary = run_stream_blocking(move || {
        let tmp = part_path(&source_path);
        let summary = {
            let mut reader = BufReader::new(
                File::open(&source_path)
                    .map_err(|e| QGuardError::Storage(format!("open vault file: {e}")))?,
            );
            let mut writer = BufWriter::new(
                File::create(&tmp).map_err(|e| QGuardError::Storage(format!("create output: {e}")))?,
            );
            match vault_stream::rewrap_stream_to_v3_with_progress(
                &mut reader,
                &mut writer,
                &ctx.recipient_kems,
                &ctx.kem_x25519_public,
                &ctx.kem_mlkem_public,
                &ctx.vault_master.vmk,
                &ctx.vault_master.signer,
                ctx.recovery_wrap_key.as_ref(),
                ctx.enterprise().as_ref(),
                &mut |p| { let _ = on_progress.send(p); },
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
        Ok(summary)
    })
    .await?;
    state.audit_info(
        "vault_recovery_rewrap",
        "Existing vault container upgraded to the v3 VMK envelope (ML-DSA-87)",
    );
    state.touch_telemetry(
        "vault",
        "Existing vault file re-protected with the v3 VMK envelope (ML-KEM-1024 / ML-DSA-87)",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(
        summary,
        source_for_result.clone(),
        source_for_result,
    ))
}

/// Fully verify a local `.qvault` container on-device: the ML-DSA-signed header,
/// the device KEM unwrap, and every chunk's AES-256-GCM tag. Plaintext is never
/// written anywhere — this proves the container is complete and untampered.
#[tauri::command]
pub async fn vault_verify_path(
    state: State<'_, AppState>,
    source_path: String,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state)?;
    let source_for_result = source_path.clone();
    let summary = run_stream_blocking(move || {
        let mut last_error: Option<QGuardError> = None;
        for kem in &ctx.recipient_kems {
            let mut reader = BufReader::new(
                File::open(&source_path)
                    .map_err(|e| QGuardError::Storage(format!("open encrypted source: {e}")))?,
            );
            match vault_stream::verify_stream_with_progress(&mut reader, kem, &mut |p| { let _ = on_progress.send(p); }) {
                Ok(summary) => return Ok(summary),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            QGuardError::Crypto("vault container could not be verified with this device's keys".to_string())
        }))
    })
    .await?;

    state.audit_info(
        "vault_verify",
        "Local vault container integrity verified on-device",
    );
    state.touch_telemetry(
        "vault",
        "Vault container verified · signed header + per-chunk AES-256-GCM tags intact",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(
        summary,
        source_for_result.clone(),
        source_for_result,
    ))
}

#[tauri::command]
pub async fn vault_decrypt_path_with_recovery(
    state: State<'_, AppState>,
    source_path: String,
    dest_path: String,
    recovery_key: String,
) -> Result<VaultLocalStreamSummary> {
    state.require_auth()?;
    state.check_decrypt_rate_limit("vault_recovery_file", &source_path, 30, 300)?;

    let source_for_result = source_path.clone();
    let dest_for_result = dest_path.clone();
    let summary = run_stream_blocking(move || {
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
                Ok(summary)
            }
            Err(error) => {
                drop(writer);
                let _ = std::fs::remove_file(&tmp);
                Err(error)
            }
        }
    })
    .await?;

    state.audit_info(
        "vault_recovery_decrypt",
        "Vault file recovered with quantum-safe recovery key",
    );
    state.touch_telemetry(
        "vault_decrypt",
        "Vault file recovered on a new device using the recovery key",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(summary, source_for_result, dest_for_result))
}

#[tauri::command]
pub async fn vault_decrypt_folder_path_with_recovery(
    state: State<'_, AppState>,
    source_path: String,
    dest_dir: String,
    recovery_key: String,
) -> Result<VaultLocalStreamSummary> {
    state.require_auth()?;
    state.check_decrypt_rate_limit("vault_recovery_folder", &source_path, 20, 300)?;

    let source_for_result = source_path.clone();
    let dest_for_result = dest_dir.clone();
    let summary = run_stream_blocking(move || {
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
                Ok(summary)
            }
            Err(error) => Err(error),
        }
    })
    .await?;

    state.audit_info(
        "vault_recovery_decrypt_folder",
        "Vault folder recovered with quantum-safe recovery key",
    );
    state.touch_telemetry(
        "vault_decrypt",
        "Vault folder recovered on a new device using the recovery key",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(summary, source_for_result, dest_for_result))
}

/// Recover a local `.qvault` file with the enterprise ML-KEM-1024 recovery key.
/// For hybrid containers, the personal `recovery_key` is also required.
#[tauri::command]
pub async fn vault_decrypt_path_with_enterprise(
    state: State<'_, AppState>,
    source_path: String,
    dest_path: String,
    enterprise_key: String,
    recovery_key: Option<String>,
) -> Result<VaultLocalStreamSummary> {
    state.require_auth()?;
    state.check_decrypt_rate_limit("vault_enterprise_file", &source_path, 30, 300)?;

    let source_for_result = source_path.clone();
    let dest_for_result = dest_path.clone();
    let summary = run_stream_blocking(move || {
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
                Ok(summary)
            }
            Err(error) => {
                drop(writer);
                let _ = std::fs::remove_file(&tmp);
                Err(error)
            }
        }
    })
    .await?;

    state.audit_info(
        "vault_enterprise_recovery_decrypt",
        "Vault file recovered with enterprise ML-KEM-1024 key",
    );
    state.touch_telemetry(
        "vault_decrypt",
        "Vault file recovered with enterprise ML-KEM-1024 recovery key",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(summary, source_for_result, dest_for_result))
}

#[tauri::command]
pub async fn vault_decrypt_folder_path_with_enterprise(
    state: State<'_, AppState>,
    source_path: String,
    dest_dir: String,
    enterprise_key: String,
    recovery_key: Option<String>,
) -> Result<VaultLocalStreamSummary> {
    state.require_auth()?;
    state.check_decrypt_rate_limit("vault_enterprise_folder", &source_path, 20, 300)?;

    let source_for_result = source_path.clone();
    let dest_for_result = dest_dir.clone();
    let summary = run_stream_blocking(move || {
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
                Ok(summary)
            }
            Err(error) => Err(error),
        }
    })
    .await?;

    state.audit_info(
        "vault_enterprise_recovery_decrypt_folder",
        "Vault folder recovered with enterprise ML-KEM-1024 key",
    );
    state.touch_telemetry(
        "vault_decrypt",
        "Vault folder recovered with enterprise ML-KEM-1024 recovery key",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(summary, source_for_result, dest_for_result))
}

/// Permanently delete a local `.qvault` container from disk. Restricted to the
/// `.qvault` extension so the command can never remove arbitrary files.
#[tauri::command]
pub fn vault_delete_file(state: State<'_, AppState>, source_path: String) -> Result<()> {
    state.require_auth()?;
    let path = Path::new(&source_path);
    let is_qvault = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("qvault"))
        .unwrap_or(false);
    if !is_qvault {
        return Err(QGuardError::InvalidInput(
            "only .qvault containers can be deleted from the vault".to_string(),
        ));
    }
    if !path.is_file() {
        return Err(QGuardError::NotFound("vault file not found".to_string()));
    }
    std::fs::remove_file(path).map_err(|e| QGuardError::Storage(format!("delete vault file: {e}")))?;
    state.audit_info("vault_delete_file", "Local vault container permanently deleted");
    state.touch_telemetry("vault", "Local vault container permanently deleted from disk", 100);
    Ok(())
}
