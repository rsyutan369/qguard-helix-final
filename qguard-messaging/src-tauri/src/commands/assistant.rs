//! AI assistant API keys (roadmap Phase 8; owner decision 2026-10-20: cloud
//! models — Anthropic Claude first, then OpenAI — with the user's own key).
//!
//! The key is the user's, kept in this device's encrypted per-user storage
//! (the same sealed-file store as the recovery documents, so panic wipe and
//! duress erase it with the rest of `keys/<user>.*`). The UI is told only
//! whether a key is set and its last four characters; the full key leaves the
//! core only for the request it authorises (`assistant_key_for_request`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{QGuardError, Result};
use crate::state::AppState;

const KEYS_DOC: &str = "assistant-keys";
const KEYS_DOC_AAD: &[u8] = b"QGuard-AssistantKeys-v1";
const PROVIDERS: [&str; 2] = ["anthropic", "openai"];
const MIN_KEY_LEN: usize = 20;
const MAX_KEY_LEN: usize = 400;

#[derive(Default, Serialize, Deserialize)]
struct StoredKeys {
    #[serde(default)]
    keys: BTreeMap<String, String>,
}

impl Drop for StoredKeys {
    fn drop(&mut self) {
        for value in self.keys.values_mut() {
            value.zeroize();
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AssistantKeyStatus {
    pub provider: String,
    pub configured: bool,
    /// The last four characters, so the user can tell which key is stored.
    pub hint: Option<String>,
}

fn provider_name(provider: &str) -> Result<&'static str> {
    let wanted = provider.trim().to_ascii_lowercase();
    PROVIDERS
        .iter()
        .copied()
        .find(|known| *known == wanted)
        .ok_or_else(|| QGuardError::InvalidInput(format!("Unknown assistant provider: {provider}")))
}

fn validate_key(key: &str) -> Result<()> {
    let len = key.chars().count();
    if !(MIN_KEY_LEN..=MAX_KEY_LEN).contains(&len) {
        return Err(QGuardError::InvalidInput("That does not look like an API key (wrong length).".to_string()));
    }
    if !key.chars().all(|c| c.is_ascii_graphic()) {
        return Err(QGuardError::InvalidInput("An API key has no spaces or special characters.".to_string()));
    }
    Ok(())
}

fn hint_of(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    chars[chars.len().saturating_sub(4)..].iter().collect()
}

fn load(state: &AppState, user_id: &str) -> Result<StoredKeys> {
    match state.load_user_secret_doc(user_id, KEYS_DOC, KEYS_DOC_AAD, "assistant keys")? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| QGuardError::Storage(format!("assistant keys unreadable: {error}"))),
        None => Ok(StoredKeys::default()),
    }
}

fn save(state: &AppState, user_id: &str, stored: &StoredKeys) -> Result<()> {
    if stored.keys.is_empty() {
        state.delete_user_secret_doc(user_id, KEYS_DOC);
        return Ok(());
    }
    let bytes = Zeroizing::new(
        serde_json::to_vec(stored).map_err(|error| QGuardError::Storage(format!("assistant keys: {error}")))?,
    );
    state.save_user_secret_doc(user_id, KEYS_DOC, KEYS_DOC_AAD, &bytes, "assistant keys")
}

fn status_of(stored: &StoredKeys, provider: &str) -> AssistantKeyStatus {
    let key = stored.keys.get(provider);
    AssistantKeyStatus {
        provider: provider.to_string(),
        configured: key.is_some(),
        hint: key.map(|value| hint_of(value)),
    }
}

pub(crate) fn key_status(state: &AppState, user_id: &str) -> Result<Vec<AssistantKeyStatus>> {
    let stored = load(state, user_id)?;
    Ok(PROVIDERS.iter().map(|provider| status_of(&stored, provider)).collect())
}

pub(crate) fn set_key(state: &AppState, user_id: &str, provider: &str, key: &str) -> Result<AssistantKeyStatus> {
    let provider = provider_name(provider)?;
    let key = key.trim();
    validate_key(key)?;
    let mut stored = load(state, user_id)?;
    stored.keys.insert(provider.to_string(), key.to_string());
    save(state, user_id, &stored)?;
    Ok(status_of(&stored, provider))
}

pub(crate) fn clear_key(state: &AppState, user_id: &str, provider: &str) -> Result<AssistantKeyStatus> {
    let provider = provider_name(provider)?;
    let mut stored = load(state, user_id)?;
    if let Some(mut old) = stored.keys.remove(provider) {
        old.zeroize();
    }
    save(state, user_id, &stored)?;
    Ok(status_of(&stored, provider))
}

pub(crate) fn key_for_request(state: &AppState, user_id: &str, provider: &str) -> Result<String> {
    let provider = provider_name(provider)?;
    let stored = load(state, user_id)?;
    stored
        .keys
        .get(provider)
        .cloned()
        .ok_or_else(|| QGuardError::InvalidInput("No API key saved for this assistant. Add one in Settings → AI assistant.".to_string()))
}

#[tauri::command]
pub fn assistant_key_status(state: State<'_, AppState>) -> Result<Vec<AssistantKeyStatus>> {
    let user_id = state.user_id()?;
    key_status(&state, &user_id)
}

#[tauri::command]
pub fn assistant_key_set(state: State<'_, AppState>, provider: String, key: String) -> Result<AssistantKeyStatus> {
    let user_id = state.user_id()?;
    let key = Zeroizing::new(key);
    set_key(&state, &user_id, &provider, &key)
}

#[tauri::command]
pub fn assistant_key_clear(state: State<'_, AppState>, provider: String) -> Result<AssistantKeyStatus> {
    let user_id = state.user_id()?;
    clear_key(&state, &user_id, &provider)
}

/// The full key, for the one request the user just asked for.
#[tauri::command]
pub fn assistant_key_for_request(state: State<'_, AppState>, provider: String) -> Result<String> {
    let user_id = state.user_id()?;
    key_for_request(&state, &user_id, &provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDevice;

    const ANTHROPIC_KEY: &str = "sk-ant-api03-test-key-0000000000000000wxyz";

    #[test]
    fn a_saved_key_is_reported_only_by_its_last_four_characters() {
        let device = TestDevice::new(false);
        let status = set_key(&device.state, &device.user, "Anthropic", ANTHROPIC_KEY).expect("set");
        assert_eq!(status, AssistantKeyStatus { provider: "anthropic".into(), configured: true, hint: Some("wxyz".into()) });
        let all = key_status(&device.state, &device.user).expect("status");
        assert_eq!(all.len(), 2);
        assert!(!all.iter().any(|item| item.hint.as_deref().is_some_and(|hint| hint.len() > 4)));
        assert!(!all.iter().find(|item| item.provider == "openai").unwrap().configured);
    }

    #[test]
    fn the_key_survives_a_restart_and_is_stored_encrypted() {
        let device = TestDevice::new(false);
        set_key(&device.state, &device.user, "anthropic", ANTHROPIC_KEY).expect("set");
        let dir = device.dir.clone();
        let device = device.restart();
        assert_eq!(key_for_request(&device.state, &device.user, "anthropic").expect("key"), ANTHROPIC_KEY);
        // Nothing on disk contains the key in the clear.
        for entry in walk(&dir) {
            let bytes = std::fs::read(&entry).unwrap_or_default();
            assert!(
                !bytes.windows(ANTHROPIC_KEY.len()).any(|window| window == ANTHROPIC_KEY.as_bytes()),
                "plaintext key found in {}",
                entry.display()
            );
        }
    }

    #[test]
    fn clearing_removes_the_key() {
        let device = TestDevice::new(false);
        set_key(&device.state, &device.user, "openai", "sk-proj-0123456789abcdefghij").expect("set");
        let status = clear_key(&device.state, &device.user, "openai").expect("clear");
        assert!(!status.configured);
        assert!(key_for_request(&device.state, &device.user, "openai").is_err());
    }

    #[test]
    fn unknown_providers_and_malformed_keys_are_refused() {
        let device = TestDevice::new(false);
        assert!(set_key(&device.state, &device.user, "someone-else", ANTHROPIC_KEY).is_err());
        assert!(set_key(&device.state, &device.user, "anthropic", "short").is_err());
        assert!(set_key(&device.state, &device.user, "anthropic", "sk-ant has spaces in it 0000000").is_err());
        assert!(key_for_request(&device.state, &device.user, "anthropic").is_err());
    }

    #[test]
    fn keys_belong_to_one_account() {
        let first = TestDevice::new(false);
        set_key(&first.state, &first.user, "anthropic", ANTHROPIC_KEY).expect("set");
        let other_user = format!("other-{}", uuid::Uuid::new_v4());
        assert!(key_for_request(&first.state, &other_user, "anthropic").is_err());
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    out.extend(walk(&path));
                } else {
                    out.push(path);
                }
            }
        }
        out
    }
}
