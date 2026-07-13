use serde::Serialize;
use tauri::State;

use crate::crypto::AlgorithmSuite;
use crate::error::{QGuardError, Result};
use crate::identity::PublicIdentityBundle;
use crate::prekeys::{generate_one_time_prekeys, PublicOneTimePrekey, PublicSignedPrekey};
use crate::state::AppState;

// One-time prekey pool caps. The active pool keeps every key that may still be
// referenced by an in-flight X3DH message; once it grows past the cap the
// oldest keys are retired into the legacy pool (still able to decrypt) instead
// of being dropped, and the legacy pool itself is bounded so key material on
// disk cannot grow without limit.
const ONE_TIME_PREKEY_ACTIVE_CAP: usize = 96;
const ONE_TIME_PREKEY_LEGACY_CAP: usize = 192;
const ONE_TIME_PREKEY_REPLENISH_MAX: u32 = 64;

#[derive(Clone, Debug, Serialize)]
pub struct PrivateKeyUnlockStatus {
    pub unlocked: bool,
    pub device_id: String,
    pub fingerprint: String,
    pub storage: String,
    pub suite: AlgorithmSuite,
    pub private_key_exported: bool,
}

#[tauri::command]
pub fn keys_unlock_private_key(
    state: State<'_, AppState>,
    user_id: Option<String>,
) -> Result<PrivateKeyUnlockStatus> {
    let session_user_id = state.resolve_user_id(user_id)?;
    state.check_decrypt_rate_limit("key_unlock", &session_user_id, 12, 300)?;
    let _key_scope = state.lock_key_scope()?;
    let identity = state.ensure_identity(&session_user_id, "Windows Desktop")?;
    state.audit_info(
        "keys_unlock_private_key",
        "Device-bound private key unlocked locally for decryption",
    );
    state.touch_telemetry(
        "key",
        "Device-bound private key unlocked; no private key bytes exported",
        100,
    );
    Ok(PrivateKeyUnlockStatus {
        unlocked: true,
        device_id: identity.device_id,
        fingerprint: identity.fingerprint,
        storage: "OS keychain / device-bound secure storage".to_string(),
        suite: identity.suite,
        private_key_exported: false,
    })
}

#[tauri::command]
pub fn keys_upload_identity_bundle(
    state: State<'_, AppState>,
    user_id: Option<String>,
) -> Result<PublicIdentityBundle> {
    let session_user_id = state.resolve_user_id(user_id)?;
    let _key_scope = state.lock_key_scope()?;
    let bundle = state.ensure_identity(&session_user_id, "Windows Desktop")?;
    state.audit_info(
        "keys_upload_identity",
        "Public identity bundle prepared for Supabase relay",
    );
    Ok(bundle)
}

#[tauri::command]
pub fn keys_upload_signed_prekey(
    state: State<'_, AppState>,
    user_id: Option<String>,
) -> Result<PublicSignedPrekey> {
    let session_user_id = state.resolve_user_id(user_id)?;
    let _key_scope = state.lock_key_scope()?;
    state.ensure_identity(&session_user_id, "Windows Desktop")?;
    let prekey = state
        .signed_prekey
        .lock()
        .map_err(|_| QGuardError::Storage("signed prekey lock poisoned".to_string()))?
        .as_ref()
        .map(|p| p.public.clone())
        .ok_or_else(|| QGuardError::NotFound("signed prekey".to_string()))?;
    Ok(prekey)
}

#[tauri::command]
pub fn keys_upload_one_time_prekeys(
    state: State<'_, AppState>,
    user_id: Option<String>,
) -> Result<Vec<PublicOneTimePrekey>> {
    let session_user_id = state.resolve_user_id(user_id)?;
    let _key_scope = state.lock_key_scope()?;
    state.ensure_identity(&session_user_id, "Windows Desktop")?;
    let prekeys = state
        .one_time_prekeys
        .lock()
        .map_err(|_| QGuardError::Storage("one-time prekey lock poisoned".to_string()))?
        .iter()
        .map(|p| p.public.clone())
        .collect();
    Ok(prekeys)
}

/// Generate FRESH one-time prekeys so the published pool can recover after
/// peers consume the uploaded ones. Without this the pool generated once at
/// identity creation is static: re-uploading the same prekey IDs inserts
/// nothing (they already exist with `consumed_at` set) and the device stays
/// stuck at "Awaiting prekey material" forever.
///
/// Async so ML-KEM-1024/ML-DSA-65 generation and the encrypted key-material
/// write run on the async worker pool, never the main/UI thread (same pattern
/// as `call_caller_setup` and the vault commands). No `.await` inside, so no
/// lock is held across a suspend point.
#[tauri::command]
pub async fn keys_replenish_one_time_prekeys(
    state: State<'_, AppState>,
    user_id: Option<String>,
    needed: u32,
) -> Result<Vec<PublicOneTimePrekey>> {
    let session_user_id = state.resolve_user_id(user_id)?;
    state.check_decrypt_rate_limit("prekey_replenish", &session_user_id, 12, 300)?;
    let _key_scope = state.lock_key_scope()?;
    state.ensure_identity(&session_user_id, "Windows Desktop")?;

    let needed = needed.clamp(1, ONE_TIME_PREKEY_REPLENISH_MAX) as usize;
    let identity = state
        .identity
        .lock()
        .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?
        .as_ref()
        .filter(|identity| identity.user_id == session_user_id)
        .cloned()
        .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;

    let fresh = generate_one_time_prekeys(&identity, needed)?;
    let publics: Vec<PublicOneTimePrekey> = fresh.iter().map(|p| p.public.clone()).collect();

    {
        // Lock order pool -> legacy matches the decrypt path in
        // commands/messaging.rs, which holds the pool guard while falling
        // back to the legacy pool.
        let mut pool = state
            .one_time_prekeys
            .lock()
            .map_err(|_| QGuardError::Storage("one-time prekey lock poisoned".to_string()))?;
        let mut legacy = state.legacy_one_time_prekeys.lock().map_err(|_| {
            QGuardError::Storage("legacy one-time prekey lock poisoned".to_string())
        })?;
        pool.extend(fresh);
        retire_excess_one_time_prekeys(&mut pool, &mut legacy);
    }
    state.persist_current_device_key_material()?;
    state.audit_info(
        "keys_replenish_one_time_prekeys",
        &format!("Generated {needed} fresh one-time prekeys for the published pool"),
    );
    state.touch_telemetry(
        "key",
        "One-time prekey pool replenished with fresh hybrid material",
        100,
    );
    Ok(publics)
}

#[tauri::command]
pub fn keys_rotate_prekeys(
    state: State<'_, AppState>,
    user_id: Option<String>,
) -> Result<PublicSignedPrekey> {
    let session_user_id = state.resolve_user_id(user_id)?;
    state.check_decrypt_rate_limit("key_rotate", &session_user_id, 6, 300)?;
    let _key_scope = state.lock_key_scope()?;
    state.ensure_identity(&session_user_id, "Windows Desktop")?;

    let identity = {
        let identity_guard = state
            .identity
            .lock()
            .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
        identity_guard
            .as_ref()
            .filter(|identity| identity.user_id == session_user_id)
            .cloned()
    };
    let identity = match identity {
        Some(identity) => identity,
        None => {
            state.ensure_identity(&session_user_id, "Windows Desktop")?;
            state
                .identity
                .lock()
                .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?
                .as_ref()
                .cloned()
                .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?
        }
    };

    let signed = crate::prekeys::generate_signed_prekey(&identity)?;
    let public = signed.public.clone();
    let previous_signed = state
        .signed_prekey
        .lock()
        .map_err(|_| QGuardError::Storage("signed prekey lock poisoned".to_string()))?
        .replace(signed);
    if let Some(previous_signed) = previous_signed {
        let mut legacy = state
            .legacy_signed_prekeys
            .lock()
            .map_err(|_| QGuardError::Storage("legacy signed prekey lock poisoned".to_string()))?;
        if !legacy
            .iter()
            .any(|prekey| prekey.public.prekey_id == previous_signed.public.prekey_id)
        {
            legacy.push(previous_signed);
            if legacy.len() > 32 {
                legacy.remove(0);
            }
        }
    }
    state.persist_current_device_key_material()?;
    state.audit_info("keys_rotate_prekeys", "Signed prekey rotated");
    state.touch_telemetry("key", "Signed prekey rotated and persisted locally", 100);
    Ok(public)
}

/// Retire the oldest active one-time prekeys past the pool cap into the
/// legacy pool (which stays decrypt-capable for in-flight messages) and bound
/// the legacy pool itself so persisted key material cannot grow forever.
fn retire_excess_one_time_prekeys(
    pool: &mut Vec<crate::prekeys::LocalOneTimePrekey>,
    legacy: &mut Vec<crate::prekeys::LocalOneTimePrekey>,
) {
    if pool.len() > ONE_TIME_PREKEY_ACTIVE_CAP {
        let retire_count = pool.len() - ONE_TIME_PREKEY_ACTIVE_CAP;
        let retired: Vec<_> = pool.drain(0..retire_count).collect();
        legacy.extend(retired);
    }
    if legacy.len() > ONE_TIME_PREKEY_LEGACY_CAP {
        let excess = legacy.len() - ONE_TIME_PREKEY_LEGACY_CAP;
        legacy.drain(0..excess);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;
    use crate::prekeys::LocalOneTimePrekey;

    fn prekey_batch(count: usize, label: &str) -> Vec<LocalOneTimePrekey> {
        let identity = LocalIdentity::generate("user", "Desktop").unwrap();
        let template = generate_one_time_prekeys(&identity, 1)
            .unwrap()
            .pop()
            .unwrap();
        (0..count)
            .map(|index| {
                let mut prekey = template.clone();
                prekey.public.prekey_id = format!("{label}-{index}");
                prekey
            })
            .collect()
    }

    #[test]
    fn retire_keeps_pool_and_legacy_bounded_and_ordered() {
        let mut pool = prekey_batch(ONE_TIME_PREKEY_ACTIVE_CAP + 10, "active");
        let mut legacy = prekey_batch(ONE_TIME_PREKEY_LEGACY_CAP - 5, "legacy");

        retire_excess_one_time_prekeys(&mut pool, &mut legacy);

        assert_eq!(pool.len(), ONE_TIME_PREKEY_ACTIVE_CAP);
        assert_eq!(legacy.len(), ONE_TIME_PREKEY_LEGACY_CAP);
        // The OLDEST active keys were retired (newest stay published/active).
        assert_eq!(pool[0].public.prekey_id, "active-10");
        // Retired keys landed at the tail of legacy, still decrypt-capable.
        assert_eq!(
            legacy.last().unwrap().public.prekey_id,
            format!("active-{}", 9)
        );
    }

    #[test]
    fn retire_is_noop_below_caps() {
        let mut pool = prekey_batch(4, "active");
        let mut legacy: Vec<LocalOneTimePrekey> = Vec::new();
        retire_excess_one_time_prekeys(&mut pool, &mut legacy);
        assert_eq!(pool.len(), 4);
        assert!(legacy.is_empty());
    }
}
