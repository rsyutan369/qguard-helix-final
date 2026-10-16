use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::State;

use crate::crypto::portable_identity::{self, PortableIdentity, RecipientPublicKeys};
use crate::error::{QGuardError, Result};
use crate::security::content_uri;
use crate::state::AppState;
use crate::vault_stream::{self, FolderReader, FolderWriter, SharingOptions};

use super::vault::{
    local_vault_context, open_vault_source, run_stream_blocking, VaultDest,
    VaultLocalStreamSummary, VaultNeed,
};

// ---------------------------------------------------------------------------
// Portable Hybrid Identity — sharing quantum-encrypted files with other people.
//
// A `.qvault` container is normally sealed to the device that made it. These
// commands add the missing half: a portable identity (X25519 + ML-KEM-1024 for
// encryption, Ed25519 + ML-DSA-87 for attestation) that a container can be
// sealed to instead, so a file or folder can be handed to someone else without
// giving them the sender's device key or Vault Master Key.
//
// Everything here is local. The private `.qgkey` bundle is written only where
// the user chooses, is protected by their passphrase (Argon2id → HKDF-SHA3-256 →
// AES-256-GCM), and is never uploaded. Unlocked key material lives in memory
// only and is dropped on lock, workspace lock, and sign-out.
// ---------------------------------------------------------------------------

/// Non-secret description of an identity, safe to render in the UI.
#[derive(Clone, Debug, Serialize)]
pub struct IdentitySummary {
    pub fingerprint: String,
    pub short_fingerprint: String,
    pub label: Option<String>,
    pub kem_algorithm: String,
    pub signature_algorithm: String,
    /// False for web-created ML-DSA-65 identities, which can receive sealed
    /// containers but cannot sign a sender attestation.
    pub can_attest: bool,
    /// Where the private bundle was written, when this call wrote one.
    pub bundle_path: Option<String>,
    pub unlocked: bool,
}

impl IdentitySummary {
    fn from_identity(identity: &PortableIdentity, bundle_path: Option<String>) -> Self {
        let fingerprint = identity.fingerprint();
        Self {
            short_fingerprint: portable_identity::short_fingerprint(&fingerprint),
            fingerprint,
            label: identity.label.clone(),
            kem_algorithm: identity.kem_algorithm().to_string(),
            signature_algorithm: identity.signature_algorithm().to_string(),
            can_attest: identity.can_attest(),
            bundle_path,
            unlocked: true,
        }
    }
}

/// Non-secret description of a recipient's public identity bundle.
#[derive(Clone, Debug, Serialize)]
pub struct RecipientSummary {
    pub fingerprint: String,
    pub short_fingerprint: String,
    pub label: Option<String>,
    pub kem_algorithm: String,
    pub signature_algorithm: String,
    /// The canonical bundle text, so the UI can keep exactly what was validated
    /// rather than re-serialising the user's paste.
    pub bundle: String,
}

/// Read a text file the user picked, through the same source resolver the vault
/// streams use so Android SAF `content://` documents work too.
fn read_text_source(source_path: &str, context: &str, max_bytes: u64) -> Result<String> {
    use std::io::Read;
    let file = open_vault_source(source_path, context)?;
    let mut buf = String::new();
    file.take(max_bytes)
        .read_to_string(&mut buf)
        .map_err(|e| QGuardError::InvalidInput(format!("{context}: {e}")))?;
    Ok(buf)
}

/// Write a text artefact (a `.qgkey` or public bundle) to the chosen path, using
/// the vault's atomic temp-then-rename on native paths and a direct truncating
/// write on Android SAF documents.
fn write_text_dest(dest_path: &str, body: &str) -> Result<()> {
    let (file, dest) = VaultDest::create(dest_path)?;
    let mut writer = BufWriter::new(file);
    match writer
        .write_all(body.as_bytes())
        .and_then(|_| writer.flush())
    {
        Ok(()) => {
            drop(writer);
            dest.commit()
        }
        Err(e) => {
            drop(writer);
            dest.abort();
            Err(QGuardError::Storage(format!("write identity file: {e}")))
        }
    }
}

/// Generate a fresh Portable Hybrid Identity, write its passphrase-protected
/// `.qgkey` bundle to `dest_path`, and leave it unlocked for this session.
///
/// Key generation and the memory-hard bundle KDF both run on the blocking pool:
/// ML-KEM/ML-DSA keygen plus Argon2id at 64 MiB would otherwise stall the window
/// event loop for the whole operation.
#[tauri::command]
pub async fn vault_identity_generate(
    state: State<'_, AppState>,
    label: Option<String>,
    passphrase: String,
    dest_path: String,
) -> Result<IdentitySummary> {
    state.require_auth()?;
    // Generating an identity is a vault operation, so it is gated behind the
    // same workspace unlock as every other vault action.
    state.unlocked_vault_master()?;

    let dest_for_result = dest_path.clone();
    let (identity, bundle) = run_stream_blocking(move || {
        let identity = PortableIdentity::generate(label);
        let bundle = identity.export_bundle(&passphrase)?;
        write_text_dest(&dest_path, &bundle)?;
        Ok((identity, bundle))
    })
    .await?;
    drop(bundle);

    let summary = IdentitySummary::from_identity(&identity, Some(dest_for_result));
    state.set_portable_identity(identity)?;
    state.audit_info(
        "vault_identity_generated",
        "Portable Hybrid Identity generated and unlocked on this device",
    );
    state.touch_telemetry(
        "vault_identity",
        "Portable Hybrid Identity created · X25519 + ML-KEM-1024 / Ed25519 + ML-DSA-87",
        100,
    );
    Ok(summary)
}

/// Unlock a `.qgkey` bundle from disk and hold it for this session.
#[tauri::command]
pub async fn vault_identity_import(
    state: State<'_, AppState>,
    source_path: String,
    passphrase: String,
) -> Result<IdentitySummary> {
    state.require_auth()?;
    state.unlocked_vault_master()?;
    // A `.qgkey` is a small JSON document; anything larger is not one, and the
    // cap keeps a hostile file from being read into memory wholesale.
    state.check_decrypt_rate_limit("vault_identity_import", &source_path, 10, 300)?;

    let identity = run_stream_blocking(move || {
        let text = read_text_source(&source_path, "read identity bundle", 4 * 1024 * 1024)?;
        PortableIdentity::import_bundle(&text, &passphrase)
    })
    .await?;

    let summary = IdentitySummary::from_identity(&identity, None);
    state.set_portable_identity(identity)?;
    state.audit_info(
        "vault_identity_unlocked",
        "Portable Hybrid Identity unlocked from a .qgkey bundle",
    );
    Ok(summary)
}

/// Whether an identity is currently unlocked, and which one.
#[tauri::command]
pub fn vault_identity_status(state: State<'_, AppState>) -> Result<Option<IdentitySummary>> {
    state.require_auth()?;
    Ok(state
        .unlocked_portable_identity()
        .ok()
        .map(|identity| IdentitySummary::from_identity(&identity, None)))
}

/// Drop the unlocked identity from memory.
#[tauri::command]
pub fn vault_identity_lock(state: State<'_, AppState>) -> Result<()> {
    state.clear_portable_identity();
    state.audit_info("vault_identity_locked", "Portable Hybrid Identity locked");
    Ok(())
}

/// Write the public recipient bundle for the unlocked identity — the file the
/// user gives to whoever wants to send them something.
#[tauri::command]
pub async fn vault_identity_export_public(
    state: State<'_, AppState>,
    dest_path: String,
) -> Result<String> {
    state.require_auth()?;
    let identity = state.unlocked_portable_identity()?;
    let dest_for_result = dest_path.clone();
    run_stream_blocking(move || {
        let json = identity.public_recipient_json()?;
        write_text_dest(&dest_path, &json)
    })
    .await?;
    state.audit_info(
        "vault_identity_public_exported",
        "Public recipient bundle exported for the unlocked identity",
    );
    Ok(dest_for_result)
}

/// Validate a recipient's public identity bundle pasted or loaded by the user.
#[tauri::command]
pub fn vault_parse_recipient(state: State<'_, AppState>, bundle: String) -> Result<RecipientSummary> {
    state.require_auth()?;
    let recipient = portable_identity::parse_recipient_public(&bundle)?;
    Ok(RecipientSummary {
        short_fingerprint: portable_identity::short_fingerprint(&recipient.fingerprint),
        fingerprint: recipient.fingerprint,
        label: recipient.label,
        kem_algorithm: recipient.kem_algorithm,
        signature_algorithm: recipient.signature_algorithm,
        bundle: bundle.trim().to_string(),
    })
}

/// Load a recipient bundle from a file the user picked.
#[tauri::command]
pub async fn vault_load_recipient_file(
    state: State<'_, AppState>,
    source_path: String,
) -> Result<RecipientSummary> {
    state.require_auth()?;
    let bundle = run_stream_blocking(move || {
        read_text_source(&source_path, "read recipient bundle", 4 * 1024 * 1024)
    })
    .await?;
    let recipient = portable_identity::parse_recipient_public(&bundle)?;
    Ok(RecipientSummary {
        short_fingerprint: portable_identity::short_fingerprint(&recipient.fingerprint),
        fingerprint: recipient.fingerprint,
        label: recipient.label,
        kem_algorithm: recipient.kem_algorithm,
        signature_algorithm: recipient.signature_algorithm,
        bundle: bundle.trim().to_string(),
    })
}

/// Parse + de-duplicate the recipient bundles a seal call was given.
fn resolve_recipients(bundles: &[String]) -> Result<Vec<RecipientPublicKeys>> {
    if bundles.is_empty() {
        return Err(QGuardError::InvalidInput(
            "add at least one recipient before sealing".to_string(),
        ));
    }
    let mut resolved: Vec<RecipientPublicKeys> = Vec::with_capacity(bundles.len());
    for bundle in bundles {
        let recipient = portable_identity::parse_recipient_public(bundle)?;
        if !resolved
            .iter()
            .any(|existing| existing.fingerprint == recipient.fingerprint)
        {
            resolved.push(recipient);
        }
    }
    Ok(resolved)
}

/// Encrypt a file into a `.qvault` container sealed to one or more Portable
/// Hybrid Identities.
///
/// The container also keeps the owner's own (PIN-bound) way in, so the sender can
/// still open what they sent. `attest` adds a signature by the sender's unlocked
/// identity, so the recipient is shown which identity sealed the file — a
/// fingerprint they can compare with the one the sender gave them — instead of
/// an unattributed file.
#[tauri::command]
pub async fn vault_seal_path(
    state: State<'_, AppState>,
    source_path: String,
    dest_path: String,
    recipients: Vec<String>,
    attest: bool,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state, VaultNeed::Seal)?;
    let resolved = resolve_recipients(&recipients)?;
    let sender = if attest {
        let identity = state.unlocked_portable_identity()?;
        if !identity.can_attest() {
            return Err(QGuardError::InvalidInput(format!(
                "the unlocked identity signs with {} — sender attestation needs an ML-DSA-87 identity generated in this app",
                identity.signature_algorithm()
            )));
        }
        Some(identity)
    } else {
        None
    };

    let source_for_result = source_path.clone();
    let dest_for_result = dest_path.clone();
    let recipient_count = resolved.len();
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
                Some(&SharingOptions {
                    recipients: &resolved,
                    sender: sender.as_ref(),
                }),
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
        "vault_seal_for_recipients",
        &format!("File sealed to {recipient_count} portable identity/identities"),
    );
    state.touch_telemetry(
        "vault_share",
        "File sealed to portable identities · per-file key wrapped with X25519 + ML-KEM-1024",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(
        summary,
        source_for_result,
        dest_for_result,
    ))
}

/// Same as [`vault_seal_path`] for a whole folder, archived into one container.
#[tauri::command]
pub async fn vault_seal_folder_path(
    state: State<'_, AppState>,
    source_dir: String,
    dest_path: String,
    recipients: Vec<String>,
    attest: bool,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    let ctx = local_vault_context(&state, VaultNeed::Seal)?;
    let resolved = resolve_recipients(&recipients)?;
    let sender = if attest {
        let identity = state.unlocked_portable_identity()?;
        if !identity.can_attest() {
            return Err(QGuardError::InvalidInput(format!(
                "the unlocked identity signs with {} — sender attestation needs an ML-DSA-87 identity generated in this app",
                identity.signature_algorithm()
            )));
        }
        Some(identity)
    } else {
        None
    };

    let source_for_result = source_dir.clone();
    let dest_for_result = dest_path.clone();
    let recipient_count = resolved.len();
    let summary = run_stream_blocking(move || {
        let root = PathBuf::from(&source_dir);
        if !root.is_dir() {
            return Err(QGuardError::InvalidInput(
                "selected source is not a folder".to_string(),
            ));
        }
        let name = root
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "folder".to_string());
        let (entries, total) = vault_stream::collect_folder_entries(&root)?;
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
                Some(&SharingOptions {
                    recipients: &resolved,
                    sender: sender.as_ref(),
                }),
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
        "vault_seal_folder_for_recipients",
        &format!("Folder sealed to {recipient_count} portable identity/identities"),
    );
    Ok(VaultLocalStreamSummary::from_stream(
        summary,
        source_for_result,
        dest_for_result,
    ))
}

/// Read a sealed container's signed header WITHOUT decrypting it, so the user
/// can see who it is for and who sealed it before choosing a destination.
#[tauri::command]
pub async fn vault_inspect_sealed(
    state: State<'_, AppState>,
    source_path: String,
) -> Result<vault_stream::StreamSummary> {
    state.require_auth()?;
    run_stream_blocking(move || {
        let mut reader = BufReader::new(open_vault_source(&source_path, "open sealed container")?);
        vault_stream::inspect_stream(&mut reader)
    })
    .await
}

/// Decrypt a container that was sealed to the unlocked Portable Hybrid Identity.
#[tauri::command]
pub async fn vault_open_sealed_path(
    state: State<'_, AppState>,
    source_path: String,
    dest_path: String,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    state.require_auth()?;
    let identity = state.unlocked_portable_identity()?;
    state.check_decrypt_rate_limit("vault_open_sealed", &source_path, 60, 300)?;

    let source_for_result = source_path.clone();
    let dest_for_result = dest_path.clone();
    let summary = run_stream_blocking(move || {
        let mut reader = BufReader::new(open_vault_source(&source_path, "open sealed container")?);
        let (dest_file, dest) = VaultDest::create(&dest_path)?;
        let mut writer = BufWriter::new(dest_file);
        match vault_stream::decrypt_stream_with_identity_with_progress(
            &mut reader,
            &mut writer,
            &identity,
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
        "vault_open_sealed",
        "Recipient-sealed vault container opened with a portable identity",
    );
    state.touch_telemetry(
        "vault_share_open",
        "Sealed container opened · per-file key recovered via X25519 + ML-KEM-1024",
        100,
    );
    Ok(VaultLocalStreamSummary::from_stream(
        summary,
        source_for_result,
        dest_for_result,
    ))
}

/// Same as [`vault_open_sealed_path`] for a sealed folder archive.
#[tauri::command]
pub async fn vault_open_sealed_folder_path(
    state: State<'_, AppState>,
    source_path: String,
    dest_dir: String,
    on_progress: Channel<vault_stream::VaultProgress>,
) -> Result<VaultLocalStreamSummary> {
    state.require_auth()?;
    let identity = state.unlocked_portable_identity()?;
    state.check_decrypt_rate_limit("vault_open_sealed_folder", &source_path, 60, 300)?;

    let source_for_result = source_path.clone();
    let dest_for_result = dest_dir.clone();
    let summary = run_stream_blocking(move || {
        let mut reader = BufReader::new(
            File::open(&source_path)
                .map_err(|e| QGuardError::Storage(format!("open sealed container: {e}")))?,
        );
        let mut writer = FolderWriter::new(PathBuf::from(&dest_dir));
        let summary = vault_stream::decrypt_stream_with_identity_with_progress(
            &mut reader,
            &mut writer,
            &identity,
            &mut |p| { let _ = on_progress.send(p); },
        )?;
        writer
            .flush()
            .map_err(|e| QGuardError::Storage(format!("finalize restored folder: {e}")))?;
        Ok(summary)
    })
    .await?;

    state.audit_info(
        "vault_open_sealed_folder",
        "Recipient-sealed folder archive restored with a portable identity",
    );
    Ok(VaultLocalStreamSummary::from_stream(
        summary,
        source_for_result,
        dest_for_result,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_lists_are_validated_and_de_duplicated() {
        let bob = PortableIdentity::generate(Some("Bob".to_string()));
        let carol = PortableIdentity::generate(Some("Carol".to_string()));
        let bob_json = bob.public_recipient_json().unwrap();
        let carol_json = carol.public_recipient_json().unwrap();

        let resolved = resolve_recipients(&[
            bob_json.clone(),
            carol_json,
            bob_json.clone(),
        ])
        .unwrap();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].fingerprint, bob.fingerprint());

        // Empty and malformed lists are refused rather than silently producing a
        // container nobody can open.
        assert!(resolve_recipients(&[]).is_err());
        assert!(resolve_recipients(&["{}".to_string()]).is_err());
    }

    /// Full round trip through the REAL artefacts on disk, in the same order the
    /// Tauri commands perform them:
    ///
    ///   Bob   generate -> .qgkey on disk -> .qgpub.json on disk
    ///   Alice load Bob's public bundle -> seal a real file for him
    ///   Bob   unlock his .qgkey from disk -> open the sealed container
    ///
    /// The container-level tests already prove the cryptography; this one proves
    /// the file plumbing around it (bundle write/read, public-bundle export,
    /// recipient parsing, atomic destination handling) actually composes.
    #[test]
    fn identity_files_seal_and_open_a_real_container_end_to_end() {
        use crate::crypto::signatures::VaultSigningKeypair;
        use crate::crypto::symmetric;
        use std::io::Cursor;

        let dir = std::env::temp_dir().join(format!("qguard-identity-e2e-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = |name: &str| dir.join(name).to_string_lossy().to_string();

        // --- Bob creates an identity and publishes his public bundle ---------
        let bob = PortableIdentity::generate(Some("Bob - workstation".to_string()));
        let passphrase = "bob correct horse battery";
        write_text_dest(&path("bob.qgkey"), &bob.export_bundle(passphrase).unwrap()).unwrap();
        write_text_dest(&path("bob.qgpub.json"), &bob.public_recipient_json().unwrap()).unwrap();
        assert!(dir.join("bob.qgkey").is_file());
        assert!(dir.join("bob.qgpub.json").is_file());

        // The private bundle must not contain readable secret key material.
        let on_disk = std::fs::read_to_string(dir.join("bob.qgkey")).unwrap();
        let secret_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &bob.kem.mlkem_secret,
        );
        assert!(!on_disk.contains(&secret_b64), "secret key leaked in cleartext");
        // ...and the PUBLIC bundle must not contain it either.
        let public_on_disk = std::fs::read_to_string(dir.join("bob.qgpub.json")).unwrap();
        assert!(!public_on_disk.contains(&secret_b64));

        // --- Alice loads Bob's public bundle and seals a file for him --------
        let bob_bundle =
            read_text_source(&path("bob.qgpub.json"), "read recipient bundle", 1 << 20).unwrap();
        let recipients = resolve_recipients(&[bob_bundle]).unwrap();
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0].fingerprint, bob.fingerprint());
        assert_eq!(recipients[0].label.as_deref(), Some("Bob - workstation"));

        let alice = PortableIdentity::generate(Some("Alice".to_string()));
        let plaintext = vec![42u8; 3 * 1024 * 1024 + 17]; // spans several chunks
        let alice_signer = VaultSigningKeypair::generate();
        let alice_vault_key = symmetric::random_key();

        let mut container = Vec::new();
        vault_stream::encrypt_stream_with_progress(
            &mut Cursor::new(plaintext.clone()),
            &mut container,
            vault_stream::KIND_FILE,
            "quarterly-report.pdf",
            "application/pdf",
            plaintext.len() as u64,
            &vault_stream::OwnerSeal {
                user_id: "alice-user",
                device_id: "alice-device",
                vault_key: &alice_vault_key,
                vault_signer: &alice_signer,
                recovery_wrap_key: None,
                enterprise: None,
            },
            Some(&SharingOptions {
                recipients: &recipients,
                sender: Some(&alice),
            }),
            &mut |_| {},
        )
        .unwrap();
        std::fs::write(dir.join("report.qvault"), &container).unwrap();

        // --- Bob unlocks his bundle from disk and opens the container --------
        let bob_bundle_text =
            read_text_source(&path("bob.qgkey"), "read identity bundle", 4 << 20).unwrap();
        let bob_unlocked = PortableIdentity::import_bundle(&bob_bundle_text, passphrase).unwrap();
        assert_eq!(bob_unlocked.fingerprint(), bob.fingerprint());

        // Inspecting first must already name Alice as the verified sender.
        let inspected = vault_stream::inspect_stream(&mut Cursor::new(container.clone())).unwrap();
        assert_eq!(inspected.name, "quarterly-report.pdf");
        assert_eq!(
            inspected.verified_sender.as_ref().map(|s| s.fingerprint.clone()),
            Some(alice.fingerprint())
        );
        assert_eq!(inspected.sealed_for.len(), 1);
        assert_eq!(inspected.sealed_for[0].fingerprint, bob.fingerprint());

        let mut restored = Vec::new();
        let summary = vault_stream::decrypt_stream_with_identity(
            &mut Cursor::new(container.clone()),
            &mut restored,
            &bob_unlocked,
        )
        .unwrap();
        assert_eq!(restored, plaintext);
        assert_eq!(summary.name, "quarterly-report.pdf");
        assert_eq!(summary.content_type, "application/pdf");

        // --- Negative controls ----------------------------------------------
        // The wrong passphrase never yields an identity.
        assert!(PortableIdentity::import_bundle(&bob_bundle_text, "not bob's passphrase").is_err());
        // An uninvolved identity cannot open it.
        let eve = PortableIdentity::generate(None);
        let mut leaked = Vec::new();
        assert!(vault_stream::decrypt_stream_with_identity(
            &mut Cursor::new(container.clone()),
            &mut leaked,
            &eve,
        )
        .is_err());
        assert!(leaked.is_empty());
        // Alice's own public bundle is not a key to Bob's container either.
        let alice_pub = alice.public_recipient_json().unwrap();
        assert!(portable_identity::parse_recipient_public(&alice_pub).unwrap().fingerprint != bob.fingerprint());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed write must not leave a half-written `.qgkey` where the real one
    /// belongs — an identity bundle that silently truncates is unrecoverable.
    #[test]
    fn writing_an_identity_file_replaces_the_target_atomically() {
        let dir = std::env::temp_dir().join(format!("qguard-identity-atomic-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("identity.qgkey").to_string_lossy().to_string();

        let first = PortableIdentity::generate(Some("first".to_string()));
        write_text_dest(&target, &first.export_bundle("passphrase one!!").unwrap()).unwrap();
        let second = PortableIdentity::generate(Some("second".to_string()));
        write_text_dest(&target, &second.export_bundle("passphrase two!!").unwrap()).unwrap();

        // The second write fully replaced the first, and no temp file survived.
        let restored = PortableIdentity::import_bundle(
            &std::fs::read_to_string(&target).unwrap(),
            "passphrase two!!",
        )
        .unwrap();
        assert_eq!(restored.fingerprint(), second.fingerprint());
        assert!(!dir.join("identity.qgkey.qguard-part").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
