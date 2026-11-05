use std::fs::File;
use crate::identity::platform_device_label;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::State;

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::hybrid_kex::LocalKemKeypair;
use crate::crypto::symmetric::KEY_SIZE;
use crate::crypto::vault_recovery;
use crate::crypto::AlgorithmSuite;
use crate::error::{QGuardError, Result};
use crate::security::content_uri;
use crate::security::saf_folder;
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
    /// Container format version on disk.
    pub container_version: u8,
    /// False for a legacy container whose owner envelope hangs off the device
    /// key instead of the vault unlock secret. The UI uses it to recommend
    /// re-protecting the file.
    pub pin_bound: bool,
}

impl VaultLocalStreamSummary {
    pub(crate) fn from_stream(summary: StreamSummary, source_path: String, output_path: String) -> Self {
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
            container_version: summary.container_version,
            pin_bound: summary.pin_bound,
        }
    }
}

/// Everything a vault operation needs from the vault unlocked on this device.
///
/// Built only while the Quantum Vault workspace is unlocked: the PIN-bound vault
/// key is derived from the in-session master, which exists nowhere else.
pub(crate) struct LocalVaultContext {
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    /// The unlocked Vault Master Key + ML-DSA-87 vault signing key.
    vault_master: PersistedVaultMaster,
    /// The PIN-bound vault key (v5 containers). See
    /// `PersistedVaultMaster::vault_key` for why it is not the raw VMK.
    vault_key: Zeroizing<[u8; KEY_SIZE]>,
    /// Device KEM keys — current first, then rotated ones. Used ONLY to read
    /// legacy v1–v4 containers; nothing new is ever sealed to them.
    device_kems: Vec<LocalKemKeypair>,
    /// The device identity's signing public keys: the signer a legacy v1/v2
    /// container is expected to carry.
    device_signer_ed25519_public: Vec<u8>,
    device_signer_mldsa_public: Vec<u8>,
    /// Personal-mode recovery wrap key for this user, if configured.
    recovery_wrap_key: Option<Zeroizing<[u8; KEY_SIZE]>>,
    /// Enterprise/hybrid recovery recipient, if configured.
    enterprise_recipient: Option<EnterpriseRecipientOwned>,
}

struct EnterpriseRecipientOwned {
    x25519_public: Vec<u8>,
    mlkem_public: Vec<u8>,
    /// Set (hybrid mode) means files require both the recovery key and the
    /// enterprise ML-KEM key to recover.
    recovery_secret: Option<Zeroizing<[u8; KEY_SIZE]>>,
}

/// What an operation is going to do with the vault, which decides how much of
/// it has to be loaded.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultNeed {
    /// Open or verify an existing container: keys only.
    Open,
    /// Write a container (encrypt, seal, re-protect): also the recovery
    /// configuration, so the new header gets its recovery wraps. Asking for it
    /// only here means a recovery record that cannot be opened blocks writing a
    /// file that would silently lack its recovery wrap — but never blocks
    /// reading the files the user already has.
    Seal,
}

pub(crate) fn local_vault_context(state: &AppState, need: VaultNeed) -> Result<LocalVaultContext> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let identity_bundle = state.ensure_identity(&user_id, platform_device_label())?;
    // The Vault Master Key + ML-DSA-87 signing key are only available while the
    // Quantum Vault workspace is unlocked (password/PIN). Locked => this errors.
    // That check used to be the WHOLE gate; the keys below are what make it a
    // cryptographic one for every container written from now on.
    let vault_master = state.unlocked_vault_master()?;
    let vault_key = Zeroizing::new(vault_master.vault_key()?);

    let (mut device_kems, device_signer_ed25519_public, device_signer_mldsa_public) = {
        let guard = state
            .identity
            .lock()
            .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
        let identity = guard
            .as_ref()
            .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
        (
            vec![identity.kem.clone()],
            identity.signing.ed25519_public.clone(),
            identity.signing.mldsa_public.clone(),
        )
    };
    if let Ok(legacy) = state.legacy_kem_keypairs.lock() {
        device_kems.extend(legacy.iter().cloned());
    }

    let (recovery_wrap_key, enterprise_recipient) = if need == VaultNeed::Seal {
        match state.load_vault_recovery(&user_id, &vault_key)? {
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
                        recovery_secret: material.recovery_root.map(Zeroizing::new),
                    }),
                ),
                _ => (Some(Zeroizing::new(material.wrap_key)), None),
            },
            None => (None, None),
        }
    } else {
        (None, None)
    };

    Ok(LocalVaultContext {
        user_id,
        device_id: identity_bundle.device_id,
        vault_master,
        vault_key,
        device_kems,
        device_signer_ed25519_public,
        device_signer_mldsa_public,
        recovery_wrap_key,
        enterprise_recipient,
    })
}

impl LocalVaultContext {
    /// The PIN-bound vault key. Vault Storage derives its index and thumbnail
    /// keys from it (`vault::store::StoreKeys`); it is never written anywhere.
    pub(crate) fn vault_key(&self) -> &[u8; KEY_SIZE] {
        &self.vault_key
    }

    /// The personal recovery wrap key, when this context was built to seal and
    /// personal recovery is configured.
    pub(crate) fn personal_recovery_wrap_key(&self) -> Option<&[u8; KEY_SIZE]> {
        self.recovery_wrap_key.as_deref()
    }

    /// Whether a container sealed with this context gets a recovery or
    /// enterprise wrap.
    pub(crate) fn seals_recovery_wraps(&self) -> bool {
        self.recovery_wrap_key.is_some() || self.enterprise_recipient.is_some()
    }

    /// What a container written now is sealed with.
    pub(crate) fn owner_seal(&self) -> vault_stream::OwnerSeal<'_> {
        vault_stream::OwnerSeal {
            user_id: &self.user_id,
            device_id: &self.device_id,
            vault_key: &*self.vault_key,
            vault_signer: &self.vault_master.signer,
            recovery_wrap_key: self.recovery_wrap_key.as_deref(),
            enterprise: self.enterprise_recipient.as_ref().map(|recipient| {
                vault_stream::EnterpriseRecipient {
                    x25519_public: &recipient.x25519_public,
                    mlkem_public: &recipient.mlkem_public,
                    recovery_secret: recipient.recovery_secret.as_deref(),
                }
            }),
        }
    }

    /// What this vault can open, and what it accepts as its own.
    ///
    /// `allow_unrecognized_legacy_signer` is the user's explicit, per-operation
    /// consent to open a v1/v2 container whose signer is not this device's
    /// identity. It never loosens anything for v3 and later.
    pub(crate) fn owner_access(
        &self,
        allow_unrecognized_legacy_signer: bool,
    ) -> vault_stream::OwnerAccess<'_> {
        vault_stream::OwnerAccess {
            vault_key: &*self.vault_key,
            legacy_vmk: &self.vault_master.vmk,
            vault_signer: &self.vault_master.signer,
            device_kems: &self.device_kems,
            device_signer: Some((
                self.device_signer_ed25519_public.as_slice(),
                self.device_signer_mldsa_public.as_slice(),
            )),
            allow_unrecognized_legacy_signer,
        }
    }
}

fn part_path(dest_path: &str) -> String {
    format!("{dest_path}.qguard-part")
}

/// Opens a vault source for reading — a plain filesystem path, or (Android) a
/// Storage Access Framework `content://` document URI resolved to a real file
/// descriptor through the platform content resolver.
pub(crate) fn open_vault_source(source_path: &str, context: &str) -> Result<File> {
    if content_uri::is_content_uri(source_path) {
        content_uri::open_read(source_path)
    } else {
        File::open(source_path).map_err(|e| QGuardError::Storage(format!("{context}: {e}")))
    }
}

/// Display name for a vault source: content URIs are asked for their provider
/// DISPLAY_NAME (falling back to the decoded URI tail), plain paths use the
/// basename.
pub(crate) fn vault_source_name(source_path: &str) -> String {
    if content_uri::is_content_uri(source_path) {
        if let Ok((Some(name), _)) = content_uri::stat(source_path) {
            return name;
        }
        content_uri::uri_tail(source_path)
    } else {
        Path::new(source_path)
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string())
    }
}

/// Where an output stream is written.
///
/// Native paths keep the atomic `.qguard-part` temp + rename pattern. Android
/// SAF `content://` documents (created by the system save dialog) cannot be
/// renamed onto, so the stream writes straight into the document's fd; a failed
/// stream truncates the document back to empty instead of deleting it.
pub(crate) enum VaultDest {
    Native { tmp: String, dest: String },
    Content { uri: String },
}

impl VaultDest {
    pub(crate) fn create(dest_path: &str) -> Result<(File, VaultDest)> {
        if content_uri::is_content_uri(dest_path) {
            let file = content_uri::open_write_truncate(dest_path)?;
            Ok((file, VaultDest::Content { uri: dest_path.to_string() }))
        } else {
            let tmp = part_path(dest_path);
            let file = File::create(&tmp)
                .map_err(|e| QGuardError::Storage(format!("create output: {e}")))?;
            Ok((file, VaultDest::Native { tmp, dest: dest_path.to_string() }))
        }
    }

    /// Publishes the finished output (native: rename the temp over the target).
    pub(crate) fn commit(self) -> Result<()> {
        match self {
            VaultDest::Native { tmp, dest } => std::fs::rename(&tmp, &dest)
                .map_err(|e| QGuardError::Storage(format!("finalize output: {e}"))),
            VaultDest::Content { .. } => Ok(()),
        }
    }

    /// Discards the partial output after a failed stream (best effort).
    pub(crate) fn abort(self) {
        match self {
            VaultDest::Native { tmp, .. } => {
                let _ = std::fs::remove_file(&tmp);
            }
            VaultDest::Content { uri } => {
                // No reliable SAF delete for a foreign document; truncate it so
                // no partial ciphertext/plaintext is left behind.
                let _ = content_uri::open_write_truncate(&uri);
            }
        }
    }
}

/// Run a blocking vault stream job on the Tauri blocking thread pool.
///
/// Vault containers can be many gigabytes; a synchronous Tauri command executes
/// on the MAIN thread, so running the chunk loop there blocks the window event
/// loop for the whole stream — the app goes "Not Responding", progress Channel
/// delivery stalls, and the UI freezes. Every stream command below is therefore
/// async and does its file I/O + crypto inside `spawn_blocking`, keeping the
/// event loop free and progress events flowing in real time.
pub(crate) async fn run_stream_blocking<T, F>(job: F) -> Result<T>
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
    let ctx = local_vault_context(&state, VaultNeed::Seal)?;
    let source_for_result = source_path.clone();
    let dest_for_result = dest_path.clone();
    let summary = run_stream_blocking(move || {
        let source_is_content = content_uri::is_content_uri(&source_path);
        let source_file = open_vault_source(&source_path, "read source file")?;
        let metadata = source_file
            .metadata()
            .map_err(|e| QGuardError::Storage(format!("read source file: {e}")))?;
        if !source_is_content && !metadata.is_file() {
            return Err(QGuardError::InvalidInput(
                "selected source is not a file".to_string(),
            ));
        }
        let mut original_size = metadata.len();
        let name = if source_is_content {
            // SAF providers can hand out pipe-like fds with zero stat size; the
            // provider's SIZE column is authoritative in that case.
            let (display_name, provider_size) =
                content_uri::stat(&source_path).unwrap_or((None, None));
            if original_size == 0 {
                if let Some(size) = provider_size {
                    original_size = size;
                }
            }
            display_name.unwrap_or_else(|| content_uri::uri_tail(&source_path))
        } else {
            Path::new(&source_path)
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".to_string())
        };

        let mut reader = BufReader::new(source_file);
        let (dest_file, dest) = VaultDest::create(&dest_path)?;
        let summary = {
            let mut writer = BufWriter::new(dest_file);
            match vault_stream::encrypt_stream_with_progress(
                &mut reader,
                &mut writer,
                vault_stream::KIND_FILE,
                &name,
                "application/octet-stream",
                original_size,
                &ctx.owner_seal(),
                None, // sharing: owner-sealed container, no portable-identity recipients
                &mut |p| { let _ = on_progress.send(p); },
            ) {
                Ok(summary) => match writer.flush() {
                    Ok(()) => summary,
                    Err(e) => {
                        drop(writer);
                        dest.abort();
                        return Err(QGuardError::Storage(format!("flush output: {e}")));
                    }
                },
                Err(error) => {
                    drop(writer);
                    dest.abort();
                    return Err(error);
                }
            }
        };
        dest.commit()?;
        Ok(summary)
    })
    .await?;

    state.audit_info(
        "vault_local_encrypt",
        "File encrypted to a local PIN-bound vault container",
    );
    state.touch_telemetry(
        "vault",
        "Local file sealed · AES-256-GCM under the PIN-bound vault key · Ed25519 + ML-DSA-87 header",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(summary, source_for_result, dest_for_result))
}

/// `allow_unverified_legacy` is the user's explicit consent, given in the UI for
/// this one operation, to open a legacy v1/v2 container whose signer this device
/// does not recognise (see `vault_stream::UNRECOGNIZED_SIGNER_MARKER`). It has
/// no effect on v3 and later, which are authenticated against the vault itself.
#[tauri::command]
pub async fn vault_decrypt_path(
    state: State<'_, AppState>,
    source_path: String,
    dest_path: String,
    allow_unverified_legacy: Option<bool>,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state, VaultNeed::Open)?;
    state.check_decrypt_rate_limit("vault_local_file", &source_path, 60, 300)?;
    let allow_unverified = allow_unverified_legacy.unwrap_or(false);

    let source_for_result = source_path.clone();
    let dest_for_result = dest_path.clone();
    let summary = run_stream_blocking(move || {
        let mut reader =
            BufReader::new(open_vault_source(&source_path, "open encrypted source")?);
        let (dest_file, dest) = VaultDest::create(&dest_path)?;
        let mut writer = BufWriter::new(dest_file);
        match vault_stream::decrypt_stream_owner_with_progress(
            &mut reader,
            &mut writer,
            &ctx.owner_access(allow_unverified),
            &mut |p| { let _ = on_progress.send(p); },
        ) {
            Ok(summary) => {
                if let Err(e) = writer.flush() {
                    drop(writer);
                    dest.abort();
                    return Err(QGuardError::Storage(format!("flush output: {e}")));
                }
                drop(writer);
                dest.commit()?;
                Ok(summary)
            }
            Err(error) => {
                drop(writer);
                dest.abort();
                Err(error)
            }
        }
    })
    .await?;

    state.audit_info(
        "vault_local_decrypt",
        if summary.pin_bound {
            "Local vault container decrypted with the PIN-bound vault key"
        } else {
            "Legacy device-bound vault container decrypted (not yet re-protected)"
        },
    );
    state.touch_telemetry(
        "vault_decrypt",
        if summary.pin_bound {
            "Local vault container decrypted · authenticated against this vault"
        } else {
            "Legacy vault container decrypted · re-protect it to bind it to the vault PIN"
        },
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
    let ctx = local_vault_context(&state, VaultNeed::Seal)?;
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

        let mut reader = FolderReader::new(entries);
        let (dest_file, dest) = VaultDest::create(&dest_path)?;
        let summary = {
            let mut writer = BufWriter::new(dest_file);
            match vault_stream::encrypt_stream_with_progress(
                &mut reader,
                &mut writer,
                vault_stream::KIND_FOLDER,
                &name,
                "application/qguard-folder-archive",
                total,
                &ctx.owner_seal(),
                None, // sharing: owner-sealed container, no portable-identity recipients
                &mut |p| { let _ = on_progress.send(p); },
            ) {
                Ok(summary) => match writer.flush() {
                    Ok(()) => summary,
                    Err(e) => {
                        drop(writer);
                        dest.abort();
                        return Err(QGuardError::Storage(format!("flush output: {e}")));
                    }
                },
                Err(error) => {
                    drop(writer);
                    dest.abort();
                    return Err(error);
                }
            }
        };
        dest.commit()?;
        Ok(summary)
    })
    .await?;

    state.audit_info(
        "vault_local_encrypt_folder",
        "Folder archived into a local PIN-bound vault container",
    );
    state.touch_telemetry(
        "vault",
        "Local folder sealed into one archive · AES-256-GCM under the PIN-bound vault key",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(summary, source_for_result, dest_for_result))
}

/// See [`vault_decrypt_path`] for `allow_unverified_legacy`.
#[tauri::command]
pub async fn vault_decrypt_folder_path(
    state: State<'_, AppState>,
    source_path: String,
    dest_dir: String,
    allow_unverified_legacy: Option<bool>,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state, VaultNeed::Open)?;
    state.check_decrypt_rate_limit("vault_local_folder", &source_path, 30, 300)?;
    let allow_unverified = allow_unverified_legacy.unwrap_or(false);

    let source_for_result = source_path.clone();
    let dest_for_result = dest_dir.clone();
    let summary = run_stream_blocking(move || {
        let mut reader =
            BufReader::new(open_vault_source(&source_path, "open encrypted source")?);
        // The writer creates the destination itself, and only once the container
        // has been authenticated as this vault's own — a refused archive leaves
        // nothing behind, not even an empty folder.
        let mut writer = FolderWriter::new(PathBuf::from(&dest_dir));
        let summary = vault_stream::decrypt_stream_owner_with_progress(
            &mut reader,
            &mut writer,
            &ctx.owner_access(allow_unverified),
            &mut |p| { let _ = on_progress.send(p); },
        )?;
        writer
            .flush()
            .map_err(|e| QGuardError::Storage(format!("flush output: {e}")))?;
        Ok(summary)
    })
    .await?;

    state.audit_info(
        "vault_local_decrypt_folder",
        if summary.pin_bound {
            "Local vault folder archive decrypted with the PIN-bound vault key"
        } else {
            "Legacy device-bound folder archive decrypted (not yet re-protected)"
        },
    );
    state.touch_telemetry(
        "vault_decrypt",
        if summary.pin_bound {
            "Local folder archive restored · authenticated against this vault"
        } else {
            "Legacy folder archive restored · re-protect it to bind it to the vault PIN"
        },
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
    /// One-way verifier of the local recovery material (see
    /// `VaultRecoverySetup::verifier`). Lets the frontend backfill the account
    /// recovery registry for keys configured before the registry existed.
    pub verifier: Option<String>,
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
    /// One-way verifier of the recovery material. The frontend publishes this
    /// to the account recovery registry (messaging_account_recovery) so every
    /// signed-in device can validate the SAME account recovery key. It is a
    /// non-invertible commitment — safe to store server-side.
    pub verifier: String,
}

#[tauri::command]
pub fn vault_recovery_status(state: State<'_, AppState>) -> Result<VaultRecoveryStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    // Answerable while the vault is LOCKED: only the public half of the
    // configuration is read here, never a key.
    Ok(match state.load_vault_recovery_public(&user_id)? {
        Some(public) => VaultRecoveryStatus {
            enabled: true,
            mode: Some(public.mode),
            recipient_key_id: public.recipient_key_id,
            configured_at: Some(public.configured_at.to_rfc3339()),
            verifier: Some(public.verifier),
        },
        None => VaultRecoveryStatus {
            enabled: false,
            mode: None,
            recipient_key_id: None,
            configured_at: None,
            verifier: None,
        },
    })
}

/// The PIN-bound vault key of the vault unlocked in this session. Recovery
/// secrets are sealed under a key derived from it, so configuring recovery is —
/// like every other vault operation — only possible while the vault is open.
fn unlocked_vault_key(state: &AppState) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let master = state.unlocked_vault_master()?;
    Ok(Zeroizing::new(master.vault_key()?))
}

/// Configure vault recovery in one of three modes:
/// * `personal`   — returns a recovery key to store offline.
/// * `enterprise` — returns an ML-KEM-1024 enterprise recovery private key file.
/// * `hybrid`     — returns both (recovery requires both factors).
#[tauri::command]
pub fn vault_setup_recovery(state: State<'_, AppState>, mode: String) -> Result<VaultRecoverySetup> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let vault_key = unlocked_vault_key(&state)?;
    if state.load_vault_recovery_public(&user_id)?.is_some() {
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
            state.save_vault_recovery(
                &user_id,
                &PersistedVaultRecovery::personal(wrap_key, verifier.clone()),
                &vault_key,
            )?;
            VaultRecoverySetup {
                mode: "personal".to_string(),
                recovery_key: Some(recovery_key),
                enterprise_private_key: None,
                enterprise_fingerprint: None,
                verifier,
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
                    version: 2,
                    wrap_key: [0u8; KEY_SIZE],
                    verifier: fingerprint.clone(),
                    configured_at: chrono::Utc::now(),
                    mode: Some("enterprise".to_string()),
                    recovery_root: None,
                    enterprise_x25519_public: Some(keypair.x25519_public.clone()),
                    enterprise_mlkem_public: Some(keypair.mlkem_public.clone()),
                    recipient_key_id: Some(fingerprint.clone()),
                },
                &vault_key,
            )?;
            VaultRecoverySetup {
                mode: "enterprise".to_string(),
                recovery_key: None,
                enterprise_private_key: Some(private_key),
                enterprise_fingerprint: Some(fingerprint.clone()),
                verifier: fingerprint,
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
                    version: 2,
                    wrap_key: [0u8; KEY_SIZE],
                    verifier: verifier.clone(),
                    configured_at: chrono::Utc::now(),
                    mode: Some("hybrid".to_string()),
                    recovery_root: Some(root),
                    enterprise_x25519_public: Some(keypair.x25519_public.clone()),
                    enterprise_mlkem_public: Some(keypair.mlkem_public.clone()),
                    recipient_key_id: Some(fingerprint.clone()),
                },
                &vault_key,
            )?;
            VaultRecoverySetup {
                mode: "hybrid".to_string(),
                recovery_key: Some(recovery_key),
                enterprise_private_key: Some(private_key),
                enterprise_fingerprint: Some(fingerprint),
                verifier,
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
///
/// `account_verifier` is the one-way verifier from the account recovery
/// registry (messaging_account_recovery), fetched by the frontend over the
/// authenticated session. When present, the typed key must re-derive it —
/// this is what makes the recovery key ACCOUNT-scoped: a fresh device rejects
/// any key that is not the account's registered key instead of silently
/// accepting anything with a valid checksum.
#[tauri::command]
pub fn vault_enable_recovery_with_phrase(
    state: State<'_, AppState>,
    recovery_key: String,
    account_verifier: Option<String>,
) -> Result<VaultRecoveryStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let vault_key = unlocked_vault_key(&state)?;
    let mut root = vault_recovery::decode_recovery_key(&recovery_key)?;
    let wrap_key = vault_recovery::derive_wrap_key(&root)?;
    let verifier = vault_recovery::derive_verifier(&root)?;
    root.zeroize();
    if let Some(expected) = account_verifier.as_deref() {
        if !expected.is_empty() && expected != verifier {
            return Err(QGuardError::InvalidInput(
                "This recovery key does not match the recovery key registered for this account.".to_string(),
            ));
        }
    }
    if let Some(existing) = state.load_vault_recovery_public(&user_id)? {
        // Saving below writes a PERSONAL configuration. Doing that over an
        // enterprise or hybrid one would quietly drop the enterprise factor and
        // leave every later file recoverable with the personal key alone.
        if existing.mode != "personal" {
            return Err(QGuardError::InvalidInput(format!(
                "Recovery on this device is already configured in {} mode; a personal recovery key cannot replace it.",
                existing.mode
            )));
        }
        if existing.verifier != verifier {
            return Err(QGuardError::InvalidInput(
                "This recovery key does not match the one already configured on this device.".to_string(),
            ));
        }
    }
    let material = PersistedVaultRecovery::personal(wrap_key, verifier.clone());
    let configured_at = material.configured_at.to_rfc3339();
    state.save_vault_recovery(&user_id, &material, &vault_key)?;
    state.audit_info(
        "vault_recovery_enabled_on_device",
        "Vault recovery key enabled on this device",
    );
    Ok(VaultRecoveryStatus {
        enabled: true,
        mode: Some("personal".to_string()),
        recipient_key_id: None,
        configured_at: Some(configured_at),
        verifier: Some(verifier),
    })
}

/// Re-protect an existing `.qvault` container in place by rebuilding its header
/// as a v5 PIN-bound envelope: the legacy device wrap is removed, the per-file
/// key is re-sealed under the vault key, the recovery / enterprise wraps are
/// added when configured, and the header is re-signed with ML-DSA-87. Chunks
/// are copied unchanged. This is how a file made by an older build becomes
/// genuinely protected by the vault password / PIN (and how files that predate
/// recovery setup become recoverable).
///
/// See [`vault_decrypt_path`] for `allow_unverified_legacy`.
#[tauri::command]
pub async fn vault_rewrap_path(
    state: State<'_, AppState>,
    source_path: String,
    allow_unverified_legacy: Option<bool>,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state, VaultNeed::Seal)?;
    let allow_unverified = allow_unverified_legacy.unwrap_or(false);

    let source_for_result = source_path.clone();
    let summary = run_stream_blocking(move || {
        // Re-protection rewrites the container in place via temp + rename, which
        // SAF documents cannot do — on Android the UI re-protects the registry's
        // on-device vault files instead of picker selections.
        if content_uri::is_content_uri(&source_path) {
            return Err(QGuardError::InvalidInput(
                "re-protect needs a vault file on local storage, not a picked document".to_string(),
            ));
        }
        let tmp = part_path(&source_path);
        let summary = {
            let mut reader = BufReader::new(
                File::open(&source_path)
                    .map_err(|e| QGuardError::Storage(format!("open vault file: {e}")))?,
            );
            let mut writer = BufWriter::new(
                File::create(&tmp).map_err(|e| QGuardError::Storage(format!("create output: {e}")))?,
            );
            let outcome = vault_stream::rewrap_stream_with_progress(
                &mut reader,
                &mut writer,
                &ctx.owner_access(allow_unverified),
                &ctx.owner_seal(),
                &mut |p| { let _ = on_progress.send(p); },
            )
            .and_then(|summary| {
                // The rename below replaces the user's ONLY copy of this
                // container, so the new bytes must be on disk first.
                writer
                    .flush()
                    .and_then(|_| writer.get_ref().sync_all())
                    .map_err(|e| QGuardError::Storage(format!("flush output: {e}")))?;
                Ok(summary)
            });
            match outcome {
                Ok(summary) => summary,
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
        "Existing vault container re-protected as a v5 PIN-bound envelope (ML-DSA-87)",
    );
    state.touch_telemetry(
        "vault",
        "Existing vault file re-protected · device wrap removed · sealed under the PIN-bound vault key",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(
        summary,
        source_for_result.clone(),
        source_for_result,
    ))
}

/// Fully verify a local `.qvault` container on-device: that it is authentically
/// this vault's own, and that every chunk's AES-256-GCM tag holds. Plaintext is
/// never written anywhere — this proves the container is complete, untampered,
/// and was produced by this vault rather than merely self-consistent.
///
/// See [`vault_decrypt_path`] for `allow_unverified_legacy`.
#[tauri::command]
pub async fn vault_verify_path(
    state: State<'_, AppState>,
    source_path: String,
    allow_unverified_legacy: Option<bool>,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state, VaultNeed::Open)?;
    let allow_unverified = allow_unverified_legacy.unwrap_or(false);
    let source_for_result = source_path.clone();
    let summary = run_stream_blocking(move || {
        let mut reader =
            BufReader::new(open_vault_source(&source_path, "open encrypted source")?);
        vault_stream::verify_stream_owner_with_progress(
            &mut reader,
            &ctx.owner_access(allow_unverified),
            &mut |p| { let _ = on_progress.send(p); },
        )
    })
    .await?;

    state.audit_info(
        "vault_verify",
        "Local vault container verified as this vault's own, chunk by chunk",
    );
    state.touch_telemetry(
        "vault",
        "Vault container verified · authenticated against this vault + per-chunk AES-256-GCM tags intact",
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

        let mut reader =
            BufReader::new(open_vault_source(&source_path, "open encrypted source")?);
        let (dest_file, dest) = VaultDest::create(&dest_path)?;
        let mut writer = BufWriter::new(dest_file);
        let result = vault_stream::decrypt_stream_with_recovery(&mut reader, &mut writer, &wrap_key);
        wrap_key.zeroize();
        match result {
            Ok(summary) => {
                if let Err(e) = writer.flush() {
                    drop(writer);
                    dest.abort();
                    return Err(QGuardError::Storage(format!("flush output: {e}")));
                }
                drop(writer);
                dest.commit()?;
                Ok(summary)
            }
            Err(error) => {
                drop(writer);
                dest.abort();
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

        let mut reader =
            BufReader::new(open_vault_source(&source_path, "open encrypted source")?);
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

        let mut reader =
            BufReader::new(open_vault_source(&source_path, "open encrypted source")?);
        let (dest_file, dest) = VaultDest::create(&dest_path)?;
        let mut writer = BufWriter::new(dest_file);
        let result = vault_stream::decrypt_stream_with_enterprise(&mut reader, &mut writer, &recipient, root.as_ref());
        match result {
            Ok(summary) => {
                if let Err(e) = writer.flush() {
                    drop(writer);
                    dest.abort();
                    return Err(QGuardError::Storage(format!("flush output: {e}")));
                }
                drop(writer);
                dest.commit()?;
                Ok(summary)
            }
            Err(error) => {
                drop(writer);
                dest.abort();
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
        let mut reader =
            BufReader::new(open_vault_source(&source_path, "open encrypted source")?);
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
pub async fn vault_delete_file(state: State<'_, AppState>, source_path: String) -> Result<()> {
    state.require_auth()?;
    // Containers can now live in a user-chosen Android folder, so a registry
    // path may be a SAF document URI rather than a filesystem path. Both are
    // still restricted to `.qvault` so this command can never remove anything
    // else the app happens to hold a grant for.
    run_stream_blocking(move || {
        let name = vault_source_name(&source_path);
        let is_qvault = Path::new(&name)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("qvault"))
            .unwrap_or(false);
        if !is_qvault {
            return Err(QGuardError::InvalidInput(
                "only .qvault containers can be deleted from the vault".to_string(),
            ));
        }
        if content_uri::is_content_uri(&source_path) {
            return saf_folder::delete_document(&source_path);
        }
        let path = Path::new(&source_path);
        if !path.is_file() {
            return Err(QGuardError::NotFound("vault file not found".to_string()));
        }
        std::fs::remove_file(path)
            .map_err(|e| QGuardError::Storage(format!("delete vault file: {e}")))
    })
    .await?;
    state.audit_info("vault_delete_file", "Local vault container permanently deleted");
    state.touch_telemetry("vault", "Local vault container permanently deleted from disk", 100);
    Ok(())
}

/// User-facing file name for a picked source. Android SAF `content://` URIs are
/// queried through the content provider (their raw tail is an opaque document id
/// like `msf:33`); plain paths use the basename. Async because the provider
/// query must not run on the main thread.
#[tauri::command]
pub async fn vault_resolve_name(
    state: State<'_, AppState>,
    source_path: String,
) -> Result<String> {
    state.require_auth()?;
    run_stream_blocking(move || Ok(vault_source_name(&source_path))).await
}

/// A destination folder the user picked, as returned to the UI.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultFolderChoice {
    /// SAF tree URI (Android) or filesystem directory path (desktop).
    pub path: String,
    /// Human-readable location for the activity log.
    pub label: String,
}

/// Ask the user for a destination FOLDER on Android.
///
/// Android's document pickers only offer "pick a file" and "create one file";
/// the Tauri dialog plugin has no folder picker at all on mobile, which is why
/// encrypted containers used to be forced into the app-private vault directory.
/// This drives the Storage Access Framework tree picker instead and persists the
/// grant, so the chosen folder keeps working for later decrypt/verify/delete.
///
/// `None` means the user backed out. Desktop callers use the native directory
/// dialog and never reach this command.
#[tauri::command]
pub async fn vault_pick_folder(state: State<'_, AppState>) -> Result<Option<VaultFolderChoice>> {
    state.require_auth()?;
    // The picker blocks on an Activity result delivered by the MAIN thread, so
    // it must never run there itself.
    let choice = run_stream_blocking(saf_folder::pick_folder).await?;
    Ok(choice.map(|choice| VaultFolderChoice { path: choice.path, label: choice.label }))
}

/// Human-readable label for an already-chosen destination folder.
#[tauri::command]
pub async fn vault_describe_folder(state: State<'_, AppState>, folder: String) -> Result<String> {
    state.require_auth()?;
    if !saf_folder::is_tree_uri(&folder) {
        return Ok(folder);
    }
    run_stream_blocking(move || Ok(saf_folder::describe_folder(&folder))).await
}

/// Turn a destination FOLDER plus a file name into a concrete output target for
/// the vault stream commands.
///
/// Android: creates the document inside the granted SAF tree and returns its
/// `content://` URI (the platform de-duplicates the name itself).
/// Desktop: joins the path and adds a ` (n)` suffix so an existing file is never
/// silently overwritten.
#[tauri::command]
pub async fn vault_prepare_dest(
    state: State<'_, AppState>,
    folder: String,
    file_name: String,
) -> Result<String> {
    state.require_auth()?;
    let safe_name = sanitize_dest_name(&file_name);
    run_stream_blocking(move || {
        if saf_folder::is_tree_uri(&folder) {
            return saf_folder::create_document_in_tree(&folder, &safe_name);
        }
        let dir = PathBuf::from(&folder);
        if !dir.is_dir() {
            return Err(QGuardError::InvalidInput(
                "the selected destination is not a folder".to_string(),
            ));
        }
        Ok(unique_in_dir(&dir, &safe_name).to_string_lossy().to_string())
    })
    .await
}

/// File name that is safe to create in any destination: no path separators, no
/// NULs, never empty.
pub(crate) fn sanitize_dest_name(file_name: &str) -> String {
    let cleaned = file_name
        .replace(['/', '\\', '\0'], "_")
        .trim()
        // Windows rejects trailing dots and spaces. Leading dots are legitimate
        // (hidden files such as `.env`) and must survive — with separators gone
        // the name is already a leaf, so no traversal is possible.
        .trim_end_matches(['.', ' '])
        .to_string();
    if cleaned.is_empty() || cleaned.chars().all(|c| c == '.') {
        "file".to_string()
    } else {
        cleaned
    }
}

/// `name`, or `name (n)` keeping the extension, so an existing file in `dir` is
/// never overwritten.
pub(crate) fn unique_in_dir(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    // `report.pdf.qvault` -> stem `report.pdf`, ext `qvault`.
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| name.to_string());
    let ext = path.extension().map(|value| value.to_string_lossy().to_string());
    for counter in 1u32..10_000 {
        let next = match &ext {
            Some(ext) => format!("{stem} ({counter}).{ext}"),
            None => format!("{stem} ({counter})"),
        };
        let candidate = dir.join(next);
        if !candidate.exists() {
            return candidate;
        }
    }
    dir.join(name)
}

/// On-device destination for a new encrypted container, used by the mobile flow
/// where there is no folder/save dialog worth using: the container lives in the
/// app-private vault directory so the registry path stays valid across restarts
/// (SAF write grants do not persist). Name collisions get a ` (n)` suffix.
#[tauri::command]
pub fn vault_default_encrypt_dest(
    state: State<'_, AppState>,
    file_name: String,
) -> Result<String> {
    state.require_auth()?;
    let safe_name = file_name.replace(['/', '\\', '\0'], "_").trim().to_string();
    let base = if safe_name.is_empty() { "file".to_string() } else { safe_name };
    let dir = state.data_dir.join("vault").join("files");
    std::fs::create_dir_all(&dir)
        .map_err(|e| QGuardError::Storage(format!("create vault directory: {e}")))?;
    let mut candidate = dir.join(format!("{base}.qvault"));
    let mut counter = 1u32;
    while candidate.exists() {
        candidate = dir.join(format!("{base} ({counter}).qvault"));
        counter += 1;
    }
    Ok(candidate.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitized_names_can_never_escape_the_chosen_folder() {
        assert_eq!(sanitize_dest_name("report.pdf"), "report.pdf");
        assert_eq!(sanitize_dest_name("  spaced.txt  "), "spaced.txt");
        // Path traversal and separators are neutralised, not rejected: the user
        // picked the folder, so the name must simply be forced to a leaf.
        assert_eq!(sanitize_dest_name("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(sanitize_dest_name(r"a\b/c"), "a_b_c");
        // Hidden files keep their leading dot; a trailing dot (illegal on
        // Windows) is trimmed.
        assert_eq!(sanitize_dest_name(".env"), ".env");
        assert_eq!(sanitize_dest_name("notes.txt."), "notes.txt");
        assert_eq!(sanitize_dest_name(""), "file");
        assert_eq!(sanitize_dest_name("..."), "file");
    }

    #[test]
    fn destination_never_overwrites_an_existing_file() {
        let dir = std::env::temp_dir().join(format!("qguard-dest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Free name is used as-is.
        assert_eq!(unique_in_dir(&dir, "report.pdf.qvault"), dir.join("report.pdf.qvault"));

        // Taken names get a counter suffix that KEEPS the extension, so the
        // container is still recognised as a .qvault by every later operation.
        std::fs::write(dir.join("report.pdf.qvault"), b"x").unwrap();
        assert_eq!(unique_in_dir(&dir, "report.pdf.qvault"), dir.join("report.pdf (1).qvault"));

        std::fs::write(dir.join("report.pdf (1).qvault"), b"x").unwrap();
        assert_eq!(unique_in_dir(&dir, "report.pdf.qvault"), dir.join("report.pdf (2).qvault"));

        // Extension-less names still de-duplicate.
        std::fs::write(dir.join("README"), b"x").unwrap();
        assert_eq!(unique_in_dir(&dir, "README"), dir.join("README (1)"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
