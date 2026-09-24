//! Save a file the user asked to keep into the public Downloads folder.
//!
//! Used by every "save to device" action on Android: decrypted chat
//! attachments, MFA recovery codes, the vault recovery key and the audit export.
//! Those all used to be `<a download>` clicks, which Android's WebView drops
//! without an error, so the app reported success and wrote nothing.
//!
//! The bytes arrive in bounded base64 chunks rather than one payload: Android's
//! IPC is `postMessage`, which carries a string, and a 25 MB attachment sent as
//! one string would briefly need several copies of itself in memory at once.
//! Protocol: `begin` -> `chunk`* -> `commit`, or `abort` on any failure.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

use base64::Engine;
use serde::Serialize;
use tauri::State;
use zeroize::Zeroize;

use crate::commands::vault::sanitize_dest_name;
use crate::error::{QGuardError, Result};
use crate::security::{content_uri, public_downloads};
use crate::state::AppState;

/// Saves open at once. A save is a few seconds of work, so more than this
/// means handles are leaking, not that a user is busy.
const MAX_PENDING: usize = 8;
/// Decoded bytes per chunk. The frontend sends 512 KiB; this is the ceiling.
const MAX_CHUNK_BYTES: usize = 4 * 1024 * 1024;
/// Largest file this path accepts (chat attachments are capped at 25 MB).
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

struct PendingDownload {
    uri: String,
    file: File,
    written: u64,
}

fn pending() -> &'static Mutex<HashMap<String, PendingDownload>> {
    static PENDING: OnceLock<Mutex<HashMap<String, PendingDownload>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_pending() -> Result<std::sync::MutexGuard<'static, HashMap<String, PendingDownload>>> {
    pending()
        .lock()
        .map_err(|_| QGuardError::Storage("download registry lock poisoned".to_string()))
}

/// Remove a half-written file. Best effort: the caller is already reporting the
/// failure that got us here, and Android deletes stale pending rows itself.
fn discard(entry: PendingDownload) {
    drop(entry.file);
    if let Err(error) = public_downloads::abort(&entry.uri) {
        tracing::warn!("could not remove an incomplete download: {error}");
    }
}

/// Filesystem and JNI work must stay off the main thread (a synchronous Tauri
/// command runs on it and would freeze the UI for the whole write).
async fn run_blocking<T, F>(job: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(job)
        .await
        .map_err(|e| QGuardError::Storage(format!("download worker failed: {e}")))?
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedDownload {
    /// Name the file was saved under (may carry a ` (n)` de-duplication suffix).
    pub name: String,
    /// Where the user will find it, e.g. `Download/QGuard/report.pdf`.
    pub location: String,
    pub bytes: u64,
}

/// Create the destination and return a handle for the chunks that follow.
#[tauri::command]
pub async fn downloads_save_begin(
    state: State<'_, AppState>,
    file_name: String,
    mime_type: String,
) -> Result<String> {
    state.require_auth()?;
    let name = sanitize_dest_name(&file_name);
    run_blocking(move || {
        if lock_pending()?.len() >= MAX_PENDING {
            return Err(QGuardError::InvalidInput(
                "too many saves are already in progress".to_string(),
            ));
        }
        let uri = public_downloads::begin(&name, &mime_type)?;
        let file = match content_uri::open_write_truncate(&uri) {
            Ok(file) => file,
            Err(error) => {
                let _ = public_downloads::abort(&uri);
                return Err(error);
            }
        };
        let handle = uuid::Uuid::new_v4().to_string();
        lock_pending()?.insert(handle.clone(), PendingDownload { uri, file, written: 0 });
        Ok(handle)
    })
    .await
}

/// Append one base64 chunk. A write failure discards the whole file.
#[tauri::command]
pub async fn downloads_save_chunk(handle: String, chunk_b64: String) -> Result<()> {
    run_blocking(move || {
        let mut chunk_b64 = chunk_b64;
        let decoded = base64::engine::general_purpose::STANDARD.decode(chunk_b64.as_bytes());
        chunk_b64.zeroize();
        let mut bytes = decoded.map_err(|e| QGuardError::InvalidInput(format!("download chunk: {e}")))?;
        if bytes.len() > MAX_CHUNK_BYTES {
            bytes.zeroize();
            return Err(QGuardError::InvalidInput("download chunk is too large".to_string()));
        }

        let mut registry = lock_pending()?;
        let entry = registry
            .get_mut(&handle)
            .ok_or_else(|| QGuardError::NotFound("download handle".to_string()))?;
        let next_total = entry.written + bytes.len() as u64;
        let outcome = if next_total > MAX_FILE_BYTES {
            Err(QGuardError::InvalidInput("the file is too large to save".to_string()))
        } else {
            entry
                .file
                .write_all(&bytes)
                .map_err(|e| QGuardError::Storage(format!("write to Downloads: {e}")))
        };
        bytes.zeroize();
        match outcome {
            Ok(()) => {
                entry.written = next_total;
                Ok(())
            }
            Err(error) => {
                if let Some(entry) = registry.remove(&handle) {
                    drop(registry);
                    discard(entry);
                }
                Err(error)
            }
        }
    })
    .await
}

/// Close the file and publish it to Downloads.
#[tauri::command]
pub async fn downloads_save_commit(handle: String) -> Result<SavedDownload> {
    run_blocking(move || {
        let entry = lock_pending()?
            .remove(&handle)
            .ok_or_else(|| QGuardError::NotFound("download handle".to_string()))?;
        let PendingDownload { uri, file, written } = entry;
        // Flush to storage before the row becomes visible. Not every provider fd
        // supports fsync, and the bytes are already written, so a failure here
        // is logged rather than treated as a lost file.
        if let Err(error) = file.sync_all() {
            tracing::warn!("download fsync unsupported by provider: {error}");
        }
        drop(file);
        match public_downloads::finish(&uri) {
            Ok(published) => Ok(SavedDownload {
                location: format!("{}/{}", published.relative_path, published.name),
                name: published.name,
                bytes: written,
            }),
            Err(error) => {
                let _ = public_downloads::abort(&uri);
                Err(error)
            }
        }
    })
    .await
}

/// Throw away an unfinished save. Unknown handles are not an error: the chunk
/// path already discards on failure.
#[tauri::command]
pub async fn downloads_save_abort(handle: String) -> Result<()> {
    run_blocking(move || {
        if let Some(entry) = lock_pending()?.remove(&handle) {
            discard(entry);
        }
        Ok(())
    })
    .await
}
