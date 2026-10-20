//! Encrypted history backup (roadmap 5.3; design:
//! `docs/superpowers/specs/2026-10-19-recovery-design.md` §2).
//!
//! Message history lives on the relay; what a device needs to read it is the
//! per-message key in its ledger (`crate::message_keys`), which the receive
//! path consults first — for envelopes addressed to ANY of the account's
//! devices. So a backup of the ledger, restored on a new device, makes the
//! history still on the relay readable again after every device was lost.
//!
//! The backup holds keys, never plaintext, and is sealed under the account's
//! recovery key: one key the user already keeps restores both the vault and
//! the history. It is bound to the account (AAD), so it cannot be loaded into
//! another one.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::kdf::derive_32_with_salt;
use crate::crypto::symmetric;
use crate::crypto::EncryptedEnvelope;
use crate::error::{QGuardError, Result};

pub const BACKUP_FORMAT: &str = "qguard-history-backup";
pub const BACKUP_VERSION: u8 = 1;
const BACKUP_KEY_INFO: &[u8] = b"QGuard-HistoryBackup-v1";
/// Generous: a ledger entry is ~150 bytes, so this is millions of messages.
pub const MAX_BACKUP_BYTES: usize = 512 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct BackupFile {
    format: String,
    v: u8,
    created_at: i64,
    salt_b64: String,
    envelope: EncryptedEnvelope,
}

fn aad(user_id: &str) -> Vec<u8> {
    format!("QGuard-HistoryBackup-v1|{user_id}").into_bytes()
}

fn backup_key(root: &[u8; 32], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    derive_32_with_salt(salt, root, BACKUP_KEY_INFO).map(Zeroizing::new)
}

/// Seal `payload` (the ledger's backup form) for `user_id` under the recovery root.
pub fn seal(root: &[u8; 32], user_id: &str, payload: &[u8], now: i64) -> Result<Vec<u8>> {
    let salt = crate::crypto::passcode::random_salt();
    let key = backup_key(root, &salt)?;
    let envelope = symmetric::encrypt(&key, payload, &aad(user_id))?;
    let file = BackupFile {
        format: BACKUP_FORMAT.to_string(),
        v: BACKUP_VERSION,
        created_at: now,
        salt_b64: base64::engine::general_purpose::STANDARD.encode(&salt),
        envelope,
    };
    serde_json::to_vec(&file).map_err(|e| QGuardError::Storage(format!("encode history backup: {e}")))
}

/// Open a backup made by [`seal`] for `user_id`. A wrong recovery key, a
/// backup of another account, or any tampering fails the AEAD tag.
pub fn open(root: &[u8; 32], user_id: &str, file: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if file.len() > MAX_BACKUP_BYTES {
        return Err(QGuardError::InvalidInput("this file is too large to be a history backup".to_string()));
    }
    let parsed: BackupFile = serde_json::from_slice(file)
        .map_err(|_| QGuardError::InvalidInput("this is not a QGuard history backup".to_string()))?;
    if parsed.format != BACKUP_FORMAT {
        return Err(QGuardError::InvalidInput("this is not a QGuard history backup".to_string()));
    }
    if parsed.v != BACKUP_VERSION {
        return Err(QGuardError::InvalidInput("this backup was made by a newer version of QGuard Messaging".to_string()));
    }
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&parsed.salt_b64)
        .map_err(|_| QGuardError::InvalidInput("history backup salt is malformed".to_string()))?;
    let key = backup_key(root, &salt)?;
    let mut plaintext = symmetric::decrypt(&key, &parsed.envelope, &aad(user_id)).map_err(|_| {
        QGuardError::Trust(
            "this backup does not open with that recovery key for this account (wrong key, another account's backup, or a damaged file)".to_string(),
        )
    })?;
    let out = Zeroizing::new(std::mem::take(&mut plaintext));
    plaintext.zeroize();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backup_opens_only_with_its_key_for_its_account() {
        let root = [7u8; 32];
        let sealed = seal(&root, "user-a", b"[1,2,3]", 1).unwrap();
        assert_eq!(&*open(&root, "user-a", &sealed).unwrap(), b"[1,2,3]");
        assert!(open(&[8u8; 32], "user-a", &sealed).is_err(), "another recovery key");
        assert!(open(&root, "user-b", &sealed).is_err(), "another account");
        let mut tampered: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
        tampered["created_at"] = serde_json::json!(2); // outside the AEAD: harmless
        assert!(open(&root, "user-a", &serde_json::to_vec(&tampered).unwrap()).is_ok());
        tampered["salt_b64"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAA==");
        assert!(open(&root, "user-a", &serde_json::to_vec(&tampered).unwrap()).is_err(), "the salt is bound through the key");
        assert!(open(&root, "user-a", b"not json").is_err());
        let mut other_format: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
        other_format["format"] = serde_json::json!("something-else");
        assert!(open(&root, "user-a", &serde_json::to_vec(&other_format).unwrap()).is_err());
    }

    #[test]
    fn two_backups_of_the_same_ledger_differ() {
        let root = [7u8; 32];
        assert_ne!(seal(&root, "u", b"x", 1).unwrap(), seal(&root, "u", b"x", 1).unwrap(), "fresh salt and nonce each time");
    }
}
