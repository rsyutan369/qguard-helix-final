//! Call history commands (see `crate::call_log`).
//!
//! Recording works whenever the account is signed in — calls ring and end on
//! every page, including while Secure Chat is locked. Reading or changing the
//! history needs Secure Chat unlocked: who you talk to, and when, is
//! conversation metadata and sits behind the same lock as the conversations.
//! Only the number of unseen missed calls (the badge) is readable while
//! locked, like the unread-message count.

use std::sync::Mutex;

use tauri::State;

use crate::call_log::{self, CallRecord, CallRecordInput};
use crate::error::{QGuardError, Result};
use crate::state::AppState;

/// One read-modify-write of the sealed file at a time.
static CALL_LOG_WRITE: Mutex<()> = Mutex::new(());

fn require_chat_unlocked(state: &AppState) -> Result<()> {
    if state.is_workspace_unlocked("chat") {
        Ok(())
    } else {
        Err(QGuardError::Trust("Unlock Secure Chat to see your calls.".to_string()))
    }
}

fn with_log<T>(state: &AppState, change: impl FnOnce(&mut Vec<CallRecord>) -> T) -> Result<T> {
    let user_id = state.user_id()?;
    let _writing = CALL_LOG_WRITE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut list = state.load_call_log(&user_id)?;
    let out = change(&mut list);
    state.save_call_log(&user_id, &list)?;
    Ok(out)
}

/// Record (or re-record) one finished call.
#[tauri::command]
pub fn call_log_record(state: State<'_, AppState>, record: CallRecordInput) -> Result<()> {
    state.require_auth()?;
    let record = call_log::validate(record)?;
    with_log(&state, move |list| {
        let next = call_log::upsert(std::mem::take(list), record);
        *list = next;
    })
}

/// The whole history, newest first.
#[tauri::command]
pub fn call_log_list(state: State<'_, AppState>) -> Result<Vec<CallRecord>> {
    state.require_auth()?;
    require_chat_unlocked(&state)?;
    state.load_call_log(&state.user_id()?)
}

/// Unseen missed calls (for the badge). Readable while Secure Chat is locked.
#[tauri::command]
pub fn call_log_missed_count(state: State<'_, AppState>) -> Result<usize> {
    state.require_auth()?;
    Ok(call_log::unseen_missed(&state.load_call_log(&state.user_id()?)?))
}

/// Mark every missed call seen (the Calls page was opened).
#[tauri::command]
pub fn call_log_mark_seen(state: State<'_, AppState>) -> Result<usize> {
    state.require_auth()?;
    require_chat_unlocked(&state)?;
    with_log(&state, |list| call_log::mark_seen(list))
}

/// Remove some entries.
#[tauri::command]
pub fn call_log_delete(state: State<'_, AppState>, ids: Vec<String>) -> Result<usize> {
    state.require_auth()?;
    require_chat_unlocked(&state)?;
    if ids.len() > call_log::MAX_RECORDS {
        return Err(QGuardError::InvalidInput("too many entries in one request".to_string()));
    }
    with_log(&state, |list| call_log::remove(list, &ids))
}

/// Remove every entry.
#[tauri::command]
pub fn call_log_clear(state: State<'_, AppState>) -> Result<usize> {
    state.require_auth()?;
    require_chat_unlocked(&state)?;
    with_log(&state, |list| {
        let count = list.len();
        list.clear();
        count
    })
}
