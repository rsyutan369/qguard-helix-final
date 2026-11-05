//! Commands for the hidden vault open in this session (see `vault::hidden`).
//! Opening one is `workspace::vault_pattern_unlock`; creating one is
//! `workspace::vault_hidden_create`; recovering one with its phrase is
//! `workspace::vault_hidden_recover`.
//!
//! Nothing here writes to the app's audit log, its telemetry or the Quantum
//! Vault's activity: a hidden vault leaves no record of itself outside its own
//! encrypted index. Heavy work runs on the blocking pool, holding the vault
//! only for its own duration.

use std::io::{BufWriter, Write};

use serde::Serialize;
use tauri::ipc::{Channel, Response};
use tauri::State;

use crate::commands::vault::{run_stream_blocking, VaultDest};
use crate::commands::vault_store::{open_import_source, ExportOutcome};
use crate::crypto::mnemonic;
use crate::error::{QGuardError, Result};
use crate::state::AppState;
use crate::vault::hidden::{HiddenSummary, HiddenVault};
use crate::vault::sniff;
use crate::vault::store::{self, BoundedBuffer, StoreEntry};
use crate::vault_stream::VaultProgress;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenStatus {
    pub open: bool,
    pub summary: Option<HiddenSummary>,
}

fn optional_id(value: Option<String>) -> Result<Option<String>> {
    match value {
        Some(id) if !id.trim().is_empty() => Ok(Some(store::checked_id(&id)?)),
        _ => Ok(None),
    }
}

fn progress_event(op: &str, done: u64, total: u64) -> VaultProgress {
    VaultProgress {
        op: op.to_string(),
        phase: if done >= total { "done" } else { "chunk" }.to_string(),
        message: String::new(),
        processed_bytes: done,
        total_bytes: total,
        chunk_index: done / crate::vault::hidden::CHUNK,
        total_chunks: total.div_ceil(crate::vault::hidden::CHUNK).max(1),
        level: "info".to_string(),
    }
}

/// Run `job` against the open hidden vault on the blocking pool.
async fn with_vault<T: Send + 'static>(
    state: &AppState,
    job: impl FnOnce(&mut HiddenVault) -> Result<T> + Send + 'static,
) -> Result<T> {
    state.require_auth()?;
    let vault = state.hidden_vault()?;
    run_stream_blocking(move || {
        let mut guard = vault.lock().map_err(|_| QGuardError::Storage("hidden vault lock poisoned".to_string()))?;
        job(&mut guard)
    })
    .await
}

/// Whether a hidden vault is open (what the vault screen shows). Never says
/// whether any exist.
#[tauri::command]
pub fn vault_hidden_status(state: State<'_, AppState>) -> Result<HiddenStatus> {
    state.require_auth()?;
    // `try_lock`: this runs on the main thread and must never wait for an
    // import; a busy vault is open, its summary just not ready.
    Ok(match state.hidden_vault() {
        Ok(vault) => HiddenStatus { open: true, summary: vault.try_lock().ok().map(|guard| guard.summary()) },
        Err(_) => HiddenStatus { open: false, summary: None },
    })
}

#[tauri::command]
pub async fn vault_hidden_list(state: State<'_, AppState>) -> Result<Vec<StoreEntry>> {
    with_vault(&state, |vault| Ok(vault.entries())).await
}

#[tauri::command]
pub async fn vault_hidden_import(
    state: State<'_, AppState>,
    source_path: String,
    parent_id: Option<String>,
    on_progress: Channel<VaultProgress>,
) -> Result<StoreEntry> {
    let parent = optional_id(parent_id)?;
    with_vault(&state, move |vault| {
        let (file, name, size) = open_import_source(&source_path)?;
        vault.import(file, &name, parent.as_deref(), size, &mut |done, total| {
            let _ = on_progress.send(progress_event("encrypt", done, total));
        })
    })
    .await
}

#[tauri::command]
pub async fn vault_hidden_create_folder(state: State<'_, AppState>, parent_id: Option<String>, name: String) -> Result<StoreEntry> {
    let parent = optional_id(parent_id)?;
    with_vault(&state, move |vault| vault.create_folder(parent.as_deref(), &name)).await
}

#[tauri::command]
pub async fn vault_hidden_rename(state: State<'_, AppState>, id: String, name: String) -> Result<StoreEntry> {
    with_vault(&state, move |vault| vault.rename(&id, &name)).await
}

#[tauri::command]
pub async fn vault_hidden_move(state: State<'_, AppState>, ids: Vec<String>, parent_id: Option<String>) -> Result<Vec<StoreEntry>> {
    let parent = optional_id(parent_id)?;
    with_vault(&state, move |vault| vault.move_entries(&ids, parent.as_deref())).await
}

/// Delete permanently: the keys leave the index, then the content is
/// overwritten and deleted. There is no trash in a hidden vault.
#[tauri::command]
pub async fn vault_hidden_delete(state: State<'_, AppState>, ids: Vec<String>) -> Result<u64> {
    with_vault(&state, move |vault| vault.delete(&ids)).await
}

/// Decrypt a small, previewable file into memory only (as Vault Storage does).
#[tauri::command]
pub async fn vault_hidden_preview(state: State<'_, AppState>, id: String) -> Result<Response> {
    let checked = store::checked_id(&id)?;
    state.check_decrypt_rate_limit("vault_hidden_preview", &checked, 120, 300)?;
    let bytes = with_vault(&state, move |vault| {
        let entry = vault.require_file(&checked)?;
        if !sniff::previewable(&entry.content_type) {
            return Err(QGuardError::InvalidInput(
                "this file type is not previewed inside the app — export it to open it".to_string(),
            ));
        }
        if entry.size_bytes > store::MAX_PREVIEW_BYTES {
            return Err(QGuardError::InvalidInput(format!(
                "files over {} MB are not previewed in memory — export it to open it",
                store::MAX_PREVIEW_BYTES / (1024 * 1024)
            )));
        }
        let mut buffer = vault.read_into(&checked, BoundedBuffer::new(store::MAX_PREVIEW_BYTES, entry.size_bytes), &mut |_, _| {})?;
        Ok(std::mem::take(&mut *buffer.bytes))
    })
    .await?;
    Ok(Response::new(bytes))
}

/// Decrypt a file to a destination the user chose. Leaving the hidden vault is
/// the user's decision: the exported copy is an ordinary file.
#[tauri::command]
pub async fn vault_hidden_export(
    state: State<'_, AppState>,
    id: String,
    dest_path: String,
    on_progress: Channel<VaultProgress>,
) -> Result<ExportOutcome> {
    let checked = store::checked_id(&id)?;
    state.check_decrypt_rate_limit("vault_hidden_export", &checked, 60, 300)?;
    with_vault(&state, move |vault| {
        let entry = vault.require_file(&checked)?;
        let (file, dest) = VaultDest::create(&dest_path)?;
        let written = vault
            .read_into(&checked, BufWriter::new(file), &mut |done, total| {
                let _ = on_progress.send(progress_event("decrypt", done, total));
            })
            .and_then(|mut writer| writer.flush().map_err(|e| QGuardError::Storage(format!("flush export: {e}"))));
        match written {
            Ok(()) => {
                dest.commit()?;
                Ok(ExportOutcome { name: entry.name, destination: dest_path.clone(), files: 1, bytes: entry.size_bytes })
            }
            Err(error) => {
                dest.abort();
                Err(error)
            }
        }
    })
    .await
}

/// Arm or disarm duress erase for the open vault (see `vault::hidden`). Armed,
/// the next time its pattern is drawn on the lock screen every other hidden
/// vault on this device is destroyed; opening it from inside the Quantum Vault
/// never fires it.
#[tauri::command]
pub async fn vault_hidden_set_duress(state: State<'_, AppState>, armed: bool) -> Result<HiddenSummary> {
    with_vault(&state, move |vault| {
        vault.set_duress_erase(armed)?;
        Ok(vault.summary())
    })
    .await
}

/// A new recovery phrase, shown once.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenRecoverySetup {
    pub words: Vec<String>,
    pub summary: HiddenSummary,
}

/// Set up a 12-word recovery phrase for the open vault, replacing any earlier
/// one (which stops working at once). The words go to the screen and nowhere
/// else: they are not stored, logged or kept by the core.
#[tauri::command]
pub async fn vault_hidden_recovery_setup(state: State<'_, AppState>) -> Result<HiddenRecoverySetup> {
    with_vault(&state, |vault| {
        let entropy = vault.set_up_recovery()?;
        let words = mnemonic::encode(&entropy);
        Ok(HiddenRecoverySetup { words: words.to_vec(), summary: vault.summary() })
    })
    .await
}

/// Remove the open vault's recovery phrase: from then on only its pattern
/// opens it.
#[tauri::command]
pub async fn vault_hidden_recovery_remove(state: State<'_, AppState>) -> Result<HiddenSummary> {
    with_vault(&state, |vault| {
        vault.remove_recovery()?;
        Ok(vault.summary())
    })
    .await
}

#[tauri::command]
pub fn vault_hidden_lock(state: State<'_, AppState>) -> Result<()> {
    state.require_auth()?;
    state.clear_hidden_vault();
    Ok(())
}

/// Destroy the open hidden vault and everything in it. There is no undo and
/// no copy anywhere else.
#[tauri::command]
pub async fn vault_hidden_destroy(state: State<'_, AppState>, confirmation: String) -> Result<()> {
    if confirmation != "DELETE" {
        return Err(QGuardError::InvalidInput("Type DELETE to confirm.".to_string()));
    }
    with_vault(&state, |vault| vault.destroy()).await?;
    state.clear_hidden_vault();
    Ok(())
}

/// Erase every hidden vault on this device, from inside the unlocked Quantum
/// Vault. Needs no pattern because it can only destroy, and it reveals nothing
/// about whether any existed.
#[tauri::command]
pub async fn vault_hidden_erase_all(state: State<'_, AppState>, confirmation: String) -> Result<()> {
    state.require_auth()?;
    if confirmation != "ERASE" {
        return Err(QGuardError::InvalidInput("Type ERASE to confirm.".to_string()));
    }
    state.unlocked_vault_master()?;
    let user_id = state.user_id()?;
    state.clear_hidden_vault();
    let pool = state.hidden_pool(&user_id);
    run_stream_blocking(move || pool.erase_all()).await
}
