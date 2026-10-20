//! Store-and-forward outbox (roadmap 9.1).
//!
//! When the relay cannot be reached, a message that was already sealed is kept
//! here — the exact envelope rows that would have been uploaded: ciphertext,
//! signatures and routing ids, never plaintext — in this device's encrypted
//! per-user storage, and uploaded once the relay answers again. The same rows
//! can be handed to a nearby device directly (Android, Google Play services
//! Nearby Connections), because they are end-to-end sealed for their
//! recipient whatever carries them.

use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroizing;

use crate::error::{QGuardError, Result};
use crate::state::AppState;

const OUTBOX_DOC: &str = "outbox";
const OUTBOX_DOC_AAD: &[u8] = b"QGuard-Outbox-v1";
/// Messages waiting at once; beyond this, sending fails visibly instead.
pub const OUTBOX_MAX_ITEMS: usize = 200;
/// Serialized size bound, so a stuck outbox cannot grow without limit.
pub const OUTBOX_MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OutboxItem {
    /// The message's client id: one item per message, however many devices it fans out to.
    pub id: String,
    pub conversation_id: String,
    pub queued_at: i64,
    /// The `messaging_message_envelopes` rows, exactly as they would be inserted.
    pub rows: Vec<serde_json::Value>,
}

#[derive(Default, Serialize, Deserialize)]
struct Outbox {
    #[serde(default)]
    items: Vec<OutboxItem>,
}

fn load(state: &AppState, user_id: &str) -> Result<Outbox> {
    match state.load_user_secret_doc(user_id, OUTBOX_DOC, OUTBOX_DOC_AAD, "outbox")? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|error| QGuardError::Storage(format!("outbox unreadable: {error}"))),
        None => Ok(Outbox::default()),
    }
}

fn save(state: &AppState, user_id: &str, outbox: &Outbox) -> Result<()> {
    if outbox.items.is_empty() {
        state.delete_user_secret_doc(user_id, OUTBOX_DOC);
        return Ok(());
    }
    let bytes = Zeroizing::new(serde_json::to_vec(outbox).map_err(|error| QGuardError::Storage(format!("outbox: {error}")))?);
    if bytes.len() > OUTBOX_MAX_BYTES {
        return Err(QGuardError::InvalidInput("the outbox is full; reconnect to the relay before sending more".to_string()));
    }
    state.save_user_secret_doc(user_id, OUTBOX_DOC, OUTBOX_DOC_AAD, &bytes, "outbox")
}

fn validate_item(item: &OutboxItem) -> Result<()> {
    let id_ok = |value: &str| !value.is_empty() && value.len() <= 64 && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !id_ok(&item.id) || !id_ok(&item.conversation_id) {
        return Err(QGuardError::InvalidInput("invalid outbox item id".to_string()));
    }
    if item.rows.is_empty() || item.rows.len() > 64 {
        return Err(QGuardError::InvalidInput("an outbox item holds 1 to 64 envelope rows".to_string()));
    }
    for row in &item.rows {
        let object = row.as_object().ok_or_else(|| QGuardError::InvalidInput("an envelope row must be an object".to_string()))?;
        // Ciphertext only: a row without its sealed parts is not something to keep.
        for field in ["ciphertext", "nonce", "auth_tag", "aad", "recipient_device_id", "conversation_id"] {
            if !object.contains_key(field) {
                return Err(QGuardError::InvalidInput(format!("envelope row is missing {field}")));
            }
        }
        if object.contains_key("plaintext") {
            return Err(QGuardError::InvalidInput("the outbox never stores plaintext".to_string()));
        }
    }
    Ok(())
}

pub(crate) fn put(state: &AppState, user_id: &str, item: OutboxItem) -> Result<usize> {
    validate_item(&item)?;
    let mut outbox = load(state, user_id)?;
    outbox.items.retain(|existing| existing.id != item.id);
    if outbox.items.len() >= OUTBOX_MAX_ITEMS {
        return Err(QGuardError::InvalidInput("the outbox is full; reconnect to the relay before sending more".to_string()));
    }
    outbox.items.push(item);
    save(state, user_id, &outbox)?;
    Ok(outbox.items.len())
}

pub(crate) fn list(state: &AppState, user_id: &str) -> Result<Vec<OutboxItem>> {
    let mut items = load(state, user_id)?.items;
    items.sort_by_key(|item| item.queued_at);
    Ok(items)
}

pub(crate) fn remove(state: &AppState, user_id: &str, id: &str) -> Result<usize> {
    let mut outbox = load(state, user_id)?;
    outbox.items.retain(|item| item.id != id);
    save(state, user_id, &outbox)?;
    Ok(outbox.items.len())
}

#[tauri::command]
pub fn outbox_put(state: State<'_, AppState>, item: OutboxItem) -> Result<usize> {
    let user_id = state.user_id()?;
    put(&state, &user_id, item)
}

#[tauri::command]
pub fn outbox_list(state: State<'_, AppState>) -> Result<Vec<OutboxItem>> {
    let user_id = state.user_id()?;
    list(&state, &user_id)
}

#[tauri::command]
pub fn outbox_remove(state: State<'_, AppState>, id: String) -> Result<usize> {
    let user_id = state.user_id()?;
    remove(&state, &user_id, &id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDevice;
    use serde_json::json;

    const MARKER: &str = "routing-marker-7f3c";

    fn item(id: &str, queued_at: i64) -> OutboxItem {
        OutboxItem {
            id: id.to_string(),
            conversation_id: "c0000000-0000-0000-0000-000000000001".to_string(),
            queued_at,
            rows: vec![json!({
                "id": id, "conversation_id": "c0000000-0000-0000-0000-000000000001",
                "recipient_device_id": MARKER, "ciphertext": "\\xdeadbeef", "nonce": "\\x00", "auth_tag": "\\x00", "aad": "\\x00",
            })],
        }
    }

    #[test]
    fn queued_messages_survive_a_restart_in_order_and_encrypted() {
        let device = TestDevice::new(false);
        put(&device.state, &device.user, item("m-2", 20)).expect("put");
        put(&device.state, &device.user, item("m-1", 10)).expect("put");
        let dir = device.dir.clone();
        let device = device.restart();
        let ids: Vec<String> = list(&device.state, &device.user).expect("list").into_iter().map(|item| item.id).collect();
        assert_eq!(ids, vec!["m-1".to_string(), "m-2".to_string()]);
        for path in walk(&dir) {
            let bytes = std::fs::read(&path).unwrap_or_default();
            assert!(!bytes.windows(MARKER.len()).any(|window| window == MARKER.as_bytes()), "outbox stored in the clear: {}", path.display());
        }
    }

    #[test]
    fn delivered_items_are_removed_and_requeueing_replaces() {
        let device = TestDevice::new(false);
        put(&device.state, &device.user, item("m-1", 10)).expect("put");
        assert_eq!(put(&device.state, &device.user, item("m-1", 11)).expect("again"), 1);
        assert_eq!(remove(&device.state, &device.user, "m-1").expect("remove"), 0);
        assert!(list(&device.state, &device.user).expect("list").is_empty());
    }

    #[test]
    fn only_sealed_rows_are_accepted() {
        let device = TestDevice::new(false);
        let mut with_plaintext = item("m-1", 10);
        with_plaintext.rows[0]["plaintext"] = json!("hello");
        assert!(put(&device.state, &device.user, with_plaintext).is_err());
        let mut unsealed = item("m-2", 10);
        unsealed.rows[0].as_object_mut().unwrap().remove("ciphertext");
        assert!(put(&device.state, &device.user, unsealed).is_err());
        let mut empty = item("m-3", 10);
        empty.rows.clear();
        assert!(put(&device.state, &device.user, empty).is_err());
        assert!(put(&device.state, &device.user, item("../x", 10)).is_err());
    }

    #[test]
    fn the_outbox_is_bounded() {
        let device = TestDevice::new(false);
        for index in 0..OUTBOX_MAX_ITEMS {
            put(&device.state, &device.user, item(&format!("m-{index}"), index as i64)).expect("put");
        }
        assert!(put(&device.state, &device.user, item("one-too-many", 999)).is_err());
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
