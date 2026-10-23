//! Names of groups, large groups and channels, kept on this device.
//!
//! A name is end-to-end encrypted: it travels as a `group_meta` message (or
//! inside a channel key hand-out) and the server never sees it. Until now the
//! decrypted name lived only in memory, so after every app start a conversation
//! list showed "Encrypted channel conversation" until each thread was opened,
//! and a channel with no readers yet lost its name for good. The names this
//! device has accepted are kept here instead, in its encrypted per-user
//! storage, exactly like the channel keys beside them.
//!
//! What is stored is each name as RECEIVED — who sent it and when — not a
//! verdict: the client still decides which one counts (owner-only naming,
//! `group-chat.ts`), so a name kept here cannot outlive an ownership change.

use std::collections::BTreeMap;

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroizing;

use crate::error::{QGuardError, Result};
use crate::state::AppState;

const NAMES_DOC: &str = "conversation-names";
const NAMES_DOC_AAD: &[u8] = b"QGuard-ConversationNames-v1";
/// Names kept per conversation, newest first: enough to survive an ownership
/// change being learned after a rename.
pub const NAMES_PER_CONVERSATION: usize = 8;
/// Conversations remembered; the ones named longest ago go first.
pub const MAX_CONVERSATIONS: usize = 5000;
/// Matches GROUP_NAME_MAX_CHARS in group-chat.ts.
pub const NAME_MAX_CHARS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConversationName {
    pub conversation_id: String,
    pub name: String,
    /// When the name was sent (RFC 3339), as the relay recorded it.
    pub at: String,
    pub sender_user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Candidate {
    name: String,
    at: String,
    sender_user_id: String,
}

#[derive(Default, Serialize, Deserialize)]
struct NameBook {
    #[serde(default)]
    conversations: BTreeMap<String, Vec<Candidate>>,
}

fn validate_id(value: &str, what: &str) -> Result<()> {
    let ok = !value.is_empty() && value.len() <= 64 && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if ok { Ok(()) } else { Err(QGuardError::InvalidInput(format!("invalid {what}"))) }
}

fn millis(at: &str) -> Result<i64> {
    DateTime::parse_from_rfc3339(at)
        .map(|time| time.timestamp_millis())
        .map_err(|_| QGuardError::InvalidInput("a conversation name needs an RFC 3339 time".to_string()))
}

fn validate(entry: &ConversationName) -> Result<()> {
    validate_id(&entry.conversation_id, "conversation id")?;
    validate_id(&entry.sender_user_id, "sender id")?;
    millis(&entry.at)?;
    let count = entry.name.chars().count();
    if count == 0 || count > NAME_MAX_CHARS || entry.name.trim().is_empty() || entry.name.chars().any(char::is_control) {
        return Err(QGuardError::InvalidInput(format!("a conversation name is 1 to {NAME_MAX_CHARS} printable characters")));
    }
    Ok(())
}

fn load(state: &AppState, user_id: &str) -> Result<NameBook> {
    match state.load_user_secret_doc(user_id, NAMES_DOC, NAMES_DOC_AAD, "conversation names")? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|error| QGuardError::Storage(format!("conversation names unreadable: {error}"))),
        None => Ok(NameBook::default()),
    }
}

fn save(state: &AppState, user_id: &str, book: &NameBook) -> Result<()> {
    if book.conversations.is_empty() {
        state.delete_user_secret_doc(user_id, NAMES_DOC);
        return Ok(());
    }
    let bytes = Zeroizing::new(serde_json::to_vec(book).map_err(|error| QGuardError::Storage(format!("conversation names: {error}")))?);
    state.save_user_secret_doc(user_id, NAMES_DOC, NAMES_DOC_AAD, &bytes, "conversation names")
}

fn newest(candidates: &[Candidate]) -> i64 {
    candidates.iter().filter_map(|item| millis(&item.at).ok()).max().unwrap_or(i64::MIN)
}

/// Record names; returns how many were new. Invalid entries refuse the whole call.
pub(crate) fn remember(state: &AppState, user_id: &str, entries: &[ConversationName]) -> Result<usize> {
    for entry in entries {
        validate(entry)?;
    }
    let mut book = load(state, user_id)?;
    let mut added = 0;
    for entry in entries {
        let list = book.conversations.entry(entry.conversation_id.clone()).or_default();
        let candidate = Candidate { name: entry.name.clone(), at: entry.at.clone(), sender_user_id: entry.sender_user_id.clone() };
        if list.contains(&candidate) {
            continue;
        }
        list.push(candidate);
        list.sort_by_key(|item| std::cmp::Reverse(millis(&item.at).unwrap_or(i64::MIN)));
        list.truncate(NAMES_PER_CONVERSATION);
        added += 1;
    }
    while book.conversations.len() > MAX_CONVERSATIONS {
        let stalest = book
            .conversations
            .iter()
            .min_by_key(|(_, list)| newest(list))
            .map(|(id, _)| id.clone());
        match stalest {
            Some(id) => { book.conversations.remove(&id); }
            None => break,
        }
    }
    if added > 0 {
        save(state, user_id, &book)?;
    }
    Ok(added)
}

pub(crate) fn list(state: &AppState, user_id: &str) -> Result<Vec<ConversationName>> {
    let book = load(state, user_id)?;
    Ok(book
        .conversations
        .into_iter()
        .flat_map(|(conversation_id, list)| {
            list.into_iter().map(move |item| ConversationName {
                conversation_id: conversation_id.clone(),
                name: item.name,
                at: item.at,
                sender_user_id: item.sender_user_id,
            })
        })
        .collect())
}

/// Forget a conversation's names (left, removed or deleted).
pub(crate) fn forget(state: &AppState, user_id: &str, conversation_id: &str) -> Result<()> {
    validate_id(conversation_id, "conversation id")?;
    let mut book = load(state, user_id)?;
    if book.conversations.remove(conversation_id).is_some() {
        save(state, user_id, &book)?;
    }
    Ok(())
}

#[tauri::command]
pub fn conversation_names_list(state: State<'_, AppState>) -> Result<Vec<ConversationName>> {
    let user_id = state.user_id()?;
    list(&state, &user_id)
}

#[tauri::command]
pub fn conversation_names_remember(state: State<'_, AppState>, entries: Vec<ConversationName>) -> Result<usize> {
    let user_id = state.user_id()?;
    remember(&state, &user_id, &entries)
}

#[tauri::command]
pub fn conversation_names_forget(state: State<'_, AppState>, conversation_id: String) -> Result<()> {
    let user_id = state.user_id()?;
    forget(&state, &user_id, &conversation_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDevice;

    const CONVERSATION: &str = "c0000000-0000-0000-0000-000000000001";
    const OWNER: &str = "a0000000-0000-0000-0000-000000000001";

    fn entry(name: &str, at: &str) -> ConversationName {
        ConversationName { conversation_id: CONVERSATION.to_string(), name: name.to_string(), at: at.to_string(), sender_user_id: OWNER.to_string() }
    }

    #[test]
    fn names_survive_a_restart_and_are_not_stored_in_the_clear() {
        let device = TestDevice::new(false);
        let marker = "Quantum Ops Room 7f3c";
        assert_eq!(remember(&device.state, &device.user, &[entry(marker, "2026-10-22T08:00:00Z")]).expect("remember"), 1);
        let dir = device.dir.clone();
        let device = device.restart();
        let names = list(&device.state, &device.user).expect("list");
        assert_eq!(names, vec![entry(marker, "2026-10-22T08:00:00Z")]);
        for path in walk(&dir) {
            let bytes = std::fs::read(&path).unwrap_or_default();
            assert!(!bytes.windows(marker.len()).any(|window| window == marker.as_bytes()), "name stored in the clear: {}", path.display());
        }
    }

    #[test]
    fn duplicates_are_ignored_and_each_conversation_keeps_its_newest_names() {
        let device = TestDevice::new(false);
        remember(&device.state, &device.user, &[entry("First", "2026-10-22T08:00:00Z")]).expect("remember");
        assert_eq!(remember(&device.state, &device.user, &[entry("First", "2026-10-22T08:00:00Z")]).expect("again"), 0);
        for index in 0..(NAMES_PER_CONVERSATION + 3) {
            remember(&device.state, &device.user, &[entry(&format!("Rename {index}"), &format!("2026-10-23T08:{index:02}:00Z"))]).expect("rename");
        }
        let names = list(&device.state, &device.user).expect("list");
        assert_eq!(names.len(), NAMES_PER_CONVERSATION);
        assert_eq!(names[0].name, format!("Rename {}", NAMES_PER_CONVERSATION + 2));
        assert!(names.iter().all(|item| item.name != "First"), "the oldest name should have been dropped");
    }

    #[test]
    fn forget_removes_only_that_conversation() {
        let device = TestDevice::new(false);
        let mut other = entry("Other", "2026-10-22T08:00:00Z");
        other.conversation_id = "c0000000-0000-0000-0000-000000000002".to_string();
        remember(&device.state, &device.user, &[entry("Mine", "2026-10-22T08:00:00Z"), other.clone()]).expect("remember");
        forget(&device.state, &device.user, CONVERSATION).expect("forget");
        assert_eq!(list(&device.state, &device.user).expect("list"), vec![other]);
    }

    #[test]
    fn malformed_names_are_refused() {
        let device = TestDevice::new(false);
        assert!(remember(&device.state, &device.user, &[entry("", "2026-10-22T08:00:00Z")]).is_err());
        assert!(remember(&device.state, &device.user, &[entry("   ", "2026-10-22T08:00:00Z")]).is_err());
        assert!(remember(&device.state, &device.user, &[entry("bell\u{7}", "2026-10-22T08:00:00Z")]).is_err());
        assert!(remember(&device.state, &device.user, &[entry(&"x".repeat(NAME_MAX_CHARS + 1), "2026-10-22T08:00:00Z")]).is_err());
        assert!(remember(&device.state, &device.user, &[entry("Fine", "yesterday")]).is_err());
        let mut bad_id = entry("Fine", "2026-10-22T08:00:00Z");
        bad_id.conversation_id = "../x".to_string();
        assert!(remember(&device.state, &device.user, &[bad_id]).is_err());
        assert!(list(&device.state, &device.user).expect("list").is_empty());
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() { out.extend(walk(&path)); } else { out.push(path); }
            }
        }
        out
    }
}
