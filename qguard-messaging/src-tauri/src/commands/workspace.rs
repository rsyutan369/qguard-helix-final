//! Zero-Trust Workspace Lock: independent password/PIN gates for the Secure Chat
//! and Quantum Vault workspaces, enforced locally (no secret ever leaves the
//! device or is sent to a server).
//!
//! * Both scopes store only a salt + an HKDF-SHA3-256 verifier (never the secret).
//! * The **vault** scope additionally wraps the Vault Master Key (VMK) under a
//!   password/PIN-derived key, so unlocking cryptographically decrypts the VMK
//!   (`password -> HKDF-SHA3-256 -> unlock key -> VMK`). The legacy keychain-only
//!   VMK copy is deleted at setup, so vault access truly requires the secret.
//! * Anti-bruteforce: 5 fails -> 30s, 10 -> 5min, 20 -> lockdown (re-login).

use chrono::Utc;
use serde::Serialize;
use tauri::State;
use zeroize::Zeroize;

use crate::crypto::kdf::{derive_32_with_salt, sha3_hex};
use crate::crypto::signatures::VaultSigningKeypair;
use crate::crypto::symmetric::{self, KEY_SIZE};
use crate::crypto::{vault_recovery, EncryptedEnvelope};
use crate::error::{QGuardError, Result};
use crate::state::{AppState, PersistedVaultMaster, PersistedWorkspaceScope, WorkspaceCredential};

const SCOPE_CHAT: &str = "chat";
const SCOPE_VAULT: &str = "vault";
const METHOD_PASSWORD: &str = "password";
const METHOD_PIN: &str = "pin";

const MIN_PASSWORD_LEN: usize = 12;
const MIN_PIN_LEN: usize = 6;
const MAX_PIN_LEN: usize = 12;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeStatus {
    pub configured: bool,
    pub has_password: bool,
    pub has_pin: bool,
    pub unlocked: bool,
    pub failed_attempts: u32,
    pub lockout_until: Option<String>,
    pub lockdown: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceStatus {
    pub chat: ScopeStatus,
    pub vault: ScopeStatus,
}

fn normalize_scope(scope: &str) -> Result<&'static str> {
    match scope {
        SCOPE_CHAT => Ok(SCOPE_CHAT),
        SCOPE_VAULT => Ok(SCOPE_VAULT),
        other => Err(QGuardError::InvalidInput(format!("unknown workspace scope: {other}"))),
    }
}

fn validate_secret(method: &str, secret: &str) -> Result<()> {
    match method {
        METHOD_PASSWORD => {
            if secret.chars().count() < MIN_PASSWORD_LEN {
                return Err(QGuardError::InvalidInput(format!(
                    "Workspace password must be at least {MIN_PASSWORD_LEN} characters."
                )));
            }
            Ok(())
        }
        METHOD_PIN => {
            let len = secret.chars().count();
            if !(MIN_PIN_LEN..=MAX_PIN_LEN).contains(&len) || !secret.chars().all(|c| c.is_ascii_digit()) {
                return Err(QGuardError::InvalidInput(format!(
                    "PIN must be {MIN_PIN_LEN}-{MAX_PIN_LEN} digits."
                )));
            }
            Ok(())
        }
        other => Err(QGuardError::InvalidInput(format!("unknown unlock method: {other}"))),
    }
}

fn random_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt.to_vec()
}

/// HKDF-SHA3-256 verifier (hash of an independent derived key) — validates a
/// re-entered secret without revealing the unlock key.
fn derive_verifier(salt: &[u8], secret: &[u8]) -> Result<String> {
    let mut k = derive_32_with_salt(salt, secret, &crate::security::obf::workspace_chat_verifier_info())?;
    let verifier = sha3_hex(&k);
    k.zeroize();
    Ok(verifier)
}

/// HKDF-SHA3-256 unlock key (distinct context from the verifier) that wraps the VMK.
fn derive_vault_wrap_key(salt: &[u8], secret: &[u8]) -> Result<[u8; KEY_SIZE]> {
    derive_32_with_salt(salt, secret, &crate::security::obf::workspace_vault_unlock_info())
}

/// AES-256-GCM-wrap a serialized `PersistedVaultMaster` under the secret-derived
/// unlock key. Shared by vault setup and vault reset so the wrap format stays in
/// lockstep. The secret is passed as bytes; both the derived key and the plaintext
/// serialization are zeroized before returning.
fn wrap_master_under_secret(
    salt: &[u8],
    secret: &[u8],
    master: &PersistedVaultMaster,
) -> Result<EncryptedEnvelope> {
    let mut serialized = serde_json::to_vec(master)
        .map_err(|e| QGuardError::Storage(format!("encode vault master for wrap: {e}")))?;
    let mut wrap_key = derive_vault_wrap_key(salt, secret)?;
    let wrapped = symmetric::encrypt(&wrap_key, &serialized, &crate::security::obf::workspace_vault_wrap_aad());
    wrap_key.zeroize();
    serialized.zeroize();
    wrapped
}

fn credential_for<'a>(scope: &'a PersistedWorkspaceScope, method: &str) -> Option<&'a WorkspaceCredential> {
    match method {
        METHOD_PASSWORD => scope.password.as_ref(),
        METHOD_PIN => scope.pin.as_ref(),
        _ => None,
    }
}

fn check_lockout(scope: &PersistedWorkspaceScope) -> Result<()> {
    if scope.lockdown {
        return Err(QGuardError::Trust(
            "Too many attempts — this workspace is locked down. Sign out and back in to reset.".to_string(),
        ));
    }
    if let Some(until) = scope.lockout_until {
        let now = Utc::now();
        if until > now {
            let secs = (until - now).num_seconds().max(1);
            return Err(QGuardError::Trust(format!("Too many attempts. Try again in {secs}s.")));
        }
    }
    Ok(())
}

fn apply_failed_attempt(scope: &mut PersistedWorkspaceScope) {
    scope.failed_attempts += 1;
    if scope.failed_attempts >= 20 {
        scope.lockdown = true;
        scope.lockout_until = None;
    } else if scope.failed_attempts >= 10 {
        scope.lockout_until = Some(Utc::now() + chrono::Duration::minutes(5));
    } else if scope.failed_attempts >= 5 {
        scope.lockout_until = Some(Utc::now() + chrono::Duration::seconds(30));
    }
}

fn scope_status(state: &AppState, scope_name: &str, scope: &Option<PersistedWorkspaceScope>) -> ScopeStatus {
    match scope {
        Some(s) => ScopeStatus {
            configured: s.configured(),
            has_password: s.password.is_some(),
            has_pin: s.pin.is_some(),
            unlocked: state.is_workspace_unlocked(scope_name),
            failed_attempts: s.failed_attempts,
            lockout_until: s.lockout_until.map(|t| t.to_rfc3339()),
            lockdown: s.lockdown,
        },
        None => ScopeStatus {
            configured: false,
            has_password: false,
            has_pin: false,
            unlocked: false,
            failed_attempts: 0,
            lockout_until: None,
            lockdown: false,
        },
    }
}

#[tauri::command]
pub fn workspace_status(state: State<'_, AppState>) -> Result<WorkspaceStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let chat = state.load_workspace_scope(&user_id, SCOPE_CHAT)?;
    let vault = state.load_workspace_scope(&user_id, SCOPE_VAULT)?;
    Ok(WorkspaceStatus {
        chat: scope_status(&state, SCOPE_CHAT, &chat),
        vault: scope_status(&state, SCOPE_VAULT, &vault),
    })
}

#[tauri::command]
pub fn workspace_setup_credential(
    state: State<'_, AppState>,
    scope: String,
    method: String,
    mut secret: String,
) -> Result<ScopeStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let scope_name = normalize_scope(&scope)?;
    validate_secret(&method, &secret)?;

    let mut record = state
        .load_workspace_scope(&user_id, scope_name)?
        .unwrap_or_else(|| PersistedWorkspaceScope::new(scope_name));
    if record.lockdown {
        secret.zeroize();
        return Err(QGuardError::Trust(
            "This workspace is locked down. Sign out and back in before configuring it.".to_string(),
        ));
    }

    let salt = random_salt();
    let verifier = derive_verifier(&salt, secret.as_bytes())?;
    let mut credential = WorkspaceCredential { salt: salt.clone(), verifier, wrapped_master: None };

    let mut first_vault_setup = false;
    if scope_name == SCOPE_VAULT {
        // Obtain the VMK to wrap under this secret. First time: load/generate it
        // (and migrate away from the legacy keychain copy). Adding a second method:
        // the vault must already be unlocked so we wrap the in-session VMK.
        let master = if record.configured() {
            state.unlocked_vault_master()?
        } else {
            first_vault_setup = true;
            state.load_or_generate_vault_master(&user_id)?
        };
        let mut serialized = serde_json::to_vec(&master)
            .map_err(|e| QGuardError::Storage(format!("encode vault master for wrap: {e}")))?;
        let mut wrap_key = derive_vault_wrap_key(&salt, secret.as_bytes())?;
        let wrapped = symmetric::encrypt(&wrap_key, &serialized, &crate::security::obf::workspace_vault_wrap_aad());
        wrap_key.zeroize();
        serialized.zeroize();
        credential.wrapped_master = Some(wrapped?);

        if first_vault_setup {
            state.delete_vault_master_file(&user_id)?;
            state.set_vault_session(master)?;
        }
    }

    match method.as_str() {
        METHOD_PASSWORD => record.password = Some(credential),
        METHOD_PIN => record.pin = Some(credential),
        _ => unreachable!("method validated above"),
    }
    record.failed_attempts = 0;
    record.lockout_until = None;
    record.lockdown = false;
    state.save_workspace_scope(&user_id, &record)?;
    state.mark_workspace_unlocked(scope_name)?;

    secret.zeroize();
    state.audit_info(
        "workspace_credential_set",
        &format!("Workspace {scope_name} {method} configured"),
    );
    if first_vault_setup {
        state.touch_telemetry(
            "vault",
            "Quantum Vault unlock configured (password -> HKDF-SHA3-256 -> VMK)",
            100,
        );
    }
    let loaded = state.load_workspace_scope(&user_id, scope_name)?;
    Ok(scope_status(&state, scope_name, &loaded))
}

#[tauri::command]
pub fn workspace_unlock(
    state: State<'_, AppState>,
    scope: String,
    method: String,
    mut secret: String,
) -> Result<ScopeStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let scope_name = normalize_scope(&scope)?;

    let mut record = state
        .load_workspace_scope(&user_id, scope_name)?
        .ok_or_else(|| QGuardError::NotFound("workspace is not configured yet".to_string()))?;
    check_lockout(&record)?;

    let credential = credential_for(&record, &method)
        .ok_or_else(|| QGuardError::InvalidInput(format!("{method} is not set up for this workspace")))?
        .clone();

    let verifier = derive_verifier(&credential.salt, secret.as_bytes())?;
    let ok = verifier == credential.verifier;

    if !ok {
        apply_failed_attempt(&mut record);
        let lockdown = record.lockdown;
        state.save_workspace_scope(&user_id, &record)?;
        secret.zeroize();
        state.audit_info("workspace_unlock_failed", &format!("Failed {scope_name} unlock"));
        if lockdown {
            return Err(QGuardError::Trust(
                "Too many attempts — this workspace is locked down. Sign out and back in to reset.".to_string(),
            ));
        }
        return Err(QGuardError::Trust("Incorrect password or PIN.".to_string()));
    }

    // For the vault, the real unlock is decrypting the VMK with the derived key.
    if scope_name == SCOPE_VAULT {
        let envelope = credential
            .wrapped_master
            .as_ref()
            .ok_or_else(|| QGuardError::Crypto("vault credential is missing its wrapped key".to_string()))?;
        let mut wrap_key = derive_vault_wrap_key(&credential.salt, secret.as_bytes())?;
        let decrypted = symmetric::decrypt(&wrap_key, envelope, &crate::security::obf::workspace_vault_wrap_aad());
        wrap_key.zeroize();
        let mut plaintext = match decrypted {
            Ok(p) => p,
            Err(_) => {
                apply_failed_attempt(&mut record);
                state.save_workspace_scope(&user_id, &record)?;
                secret.zeroize();
                return Err(QGuardError::Trust("Incorrect password or PIN.".to_string()));
            }
        };
        let master = serde_json::from_slice(&plaintext)
            .map_err(|e| QGuardError::Storage(format!("decode unlocked vault master: {e}")))?;
        plaintext.zeroize();
        state.set_vault_session(master)?;
    }

    record.failed_attempts = 0;
    record.lockout_until = None;
    state.save_workspace_scope(&user_id, &record)?;
    state.mark_workspace_unlocked(scope_name)?;
    secret.zeroize();

    state.audit_info("workspace_unlock", &format!("Workspace {scope_name} unlocked"));
    let loaded = state.load_workspace_scope(&user_id, scope_name)?;
    Ok(scope_status(&state, scope_name, &loaded))
}

#[tauri::command]
pub fn workspace_lock(state: State<'_, AppState>, scope: String) -> Result<ScopeStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let scope_name = normalize_scope(&scope)?;
    if scope_name == SCOPE_VAULT {
        state.clear_vault_session()?;
    } else {
        state.clear_chat_session();
    }
    state.mark_workspace_locked(scope_name)?;
    state.audit_info("workspace_lock", &format!("Workspace {scope_name} locked"));
    let loaded = state.load_workspace_scope(&user_id, scope_name)?;
    Ok(scope_status(&state, scope_name, &loaded))
}

/// Lock every protected workspace (inactivity / app minimize / close).
#[tauri::command]
pub fn workspace_lock_all(state: State<'_, AppState>) -> Result<()> {
    state.lock_all_workspaces();
    state.audit_info("workspace_lock_all", "All protected workspaces locked");
    Ok(())
}

/// Reset the Secure Chat lock after the user re-proves their account identity.
///
/// SAFE BY DESIGN: the chat scope is a *verifier only* — it gates local access
/// but does not encrypt any message data (messages decrypt with the device
/// identity keys, independent of this PIN). Clearing it therefore loses no
/// conversations. The caller (frontend) must re-authenticate the account
/// (Supabase sign-in) before invoking this, so a forgotten PIN can be replaced
/// without weakening security. Also clears any brute-force lockout/lockdown.
#[tauri::command]
pub fn workspace_reset_chat_lock(state: State<'_, AppState>) -> Result<ScopeStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    // A fresh scope drops both credentials and all lockout state; the gate then
    // shows the setup screen so the user picks a new PIN/password.
    let record = PersistedWorkspaceScope::new(SCOPE_CHAT);
    state.save_workspace_scope(&user_id, &record)?;
    state.clear_chat_session();
    state.mark_workspace_locked(SCOPE_CHAT)?;
    state.audit_info(
        "workspace_chat_reset",
        "Secure Chat lock reset after account re-authentication",
    );
    let loaded = state.load_workspace_scope(&user_id, SCOPE_CHAT)?;
    Ok(scope_status(&state, SCOPE_CHAT, &loaded))
}

/// Reset the Quantum Vault lock when the PIN/password is forgotten.
///
/// The old VMK is wrapped only under the forgotten secret and cannot be
/// recovered, so this installs a NEW Vault Master Key under a new secret and
/// unlocks the (now empty) vault. Files encrypted under the OLD VMK are NOT
/// destroyed — they remain on disk and are recoverable through the recovery-key
/// decrypt tools, which do not depend on this lock.
///
/// Two honest gates, both requiring the user to already be signed in:
/// * `recovery_key = Some(..)` — verified against the stored recovery verifier
///   (proves the user holds their recovery key). Preferred path.
/// * `recovery_key = None` — a "start fresh" reset; the frontend must first
///   re-authenticate the account password. Old files are only recoverable if
///   the user still has their recovery key.
#[tauri::command]
pub fn workspace_reset_vault(
    state: State<'_, AppState>,
    recovery_key: Option<String>,
    method: String,
    mut secret: String,
) -> Result<ScopeStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    if let Err(e) = validate_secret(&method, &secret) {
        secret.zeroize();
        return Err(e);
    }

    // Recovery-key path: prove possession of the recovery key before resetting.
    if let Some(ref key) = recovery_key {
        let material = state.load_vault_recovery(&user_id)?.ok_or_else(|| {
            QGuardError::InvalidInput(
                "No recovery key is configured for this account.".to_string(),
            )
        })?;
        let root = match vault_recovery::decode_recovery_key(key) {
            Ok(root) => root,
            Err(_) => {
                secret.zeroize();
                return Err(QGuardError::Trust("That recovery key isn't valid.".to_string()));
            }
        };
        let mut root = root;
        let verifier = vault_recovery::derive_verifier(&root)?;
        root.zeroize();
        if material.verifier.is_empty() || verifier != material.verifier {
            secret.zeroize();
            return Err(QGuardError::Trust(
                "That recovery key doesn't match this account.".to_string(),
            ));
        }
    }

    // Fresh master: a new VMK + new ML-DSA-87 signer, wrapped under the new secret.
    let new_master = PersistedVaultMaster {
        version: 1,
        vmk: symmetric::random_key(),
        signer: VaultSigningKeypair::generate(),
        configured_at: Utc::now(),
    };
    let salt = random_salt();
    let verifier = derive_verifier(&salt, secret.as_bytes())?;
    let wrapped = wrap_master_under_secret(&salt, secret.as_bytes(), &new_master);
    let wrapped = match wrapped {
        Ok(w) => w,
        Err(e) => {
            secret.zeroize();
            return Err(e);
        }
    };
    let credential = WorkspaceCredential { salt, verifier, wrapped_master: Some(wrapped) };

    let mut record = PersistedWorkspaceScope::new(SCOPE_VAULT);
    match method.as_str() {
        METHOD_PASSWORD => record.password = Some(credential),
        METHOD_PIN => record.pin = Some(credential),
        _ => {
            secret.zeroize();
            return Err(QGuardError::InvalidInput(format!("unknown unlock method: {method}")));
        }
    }
    secret.zeroize();

    // Legacy keychain VMK (if any) must not linger — the VMK stays password-wrapped.
    state.delete_vault_master_file(&user_id)?;
    state.save_workspace_scope(&user_id, &record)?;
    state.set_vault_session(new_master)?;
    state.mark_workspace_unlocked(SCOPE_VAULT)?;

    let via = if recovery_key.is_some() { "recovery key" } else { "account re-authentication" };
    state.audit_info(
        "workspace_vault_reset",
        &format!("Quantum Vault lock reset via {via}; new Vault Master Key generated"),
    );
    state.touch_telemetry(
        "vault",
        "Quantum Vault lock reset — new VMK sealed under the new unlock secret",
        100,
    );
    let loaded = state.load_workspace_scope(&user_id, SCOPE_VAULT)?;
    Ok(scope_status(&state, SCOPE_VAULT, &loaded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_is_deterministic_and_secret_specific() {
        let salt = random_salt();
        let a = derive_verifier(&salt, b"correct horse battery staple").unwrap();
        assert_eq!(a, derive_verifier(&salt, b"correct horse battery staple").unwrap());
        assert_ne!(a, derive_verifier(&salt, b"a different secret entirely").unwrap());
        // A different salt yields a different verifier for the same secret.
        let salt2 = random_salt();
        assert_ne!(a, derive_verifier(&salt2, b"correct horse battery staple").unwrap());
    }

    #[test]
    fn vault_unlock_key_unwraps_vmk_only_with_correct_secret() {
        let salt = random_salt();
        let secret: &[u8] = b"a-strong-vault-password-123";
        let vmk_blob: &[u8] = b"serialized-persisted-vault-master-stand-in-bytes";
        let aad = crate::security::obf::workspace_vault_wrap_aad();

        let key = derive_vault_wrap_key(&salt, secret).unwrap();
        let env = symmetric::encrypt(&key, vmk_blob, &aad).unwrap();

        // Correct secret re-derives the key and recovers the VMK material.
        let good = derive_vault_wrap_key(&salt, secret).unwrap();
        assert_eq!(symmetric::decrypt(&good, &env, &aad).unwrap(), vmk_blob);

        // Wrong secret -> AEAD authentication fails (no VMK recovered).
        let bad = derive_vault_wrap_key(&salt, b"the-wrong-password-000").unwrap();
        assert!(symmetric::decrypt(&bad, &env, &aad).is_err());
    }

    #[test]
    fn anti_bruteforce_thresholds_escalate() {
        let mut scope = PersistedWorkspaceScope::new(SCOPE_VAULT);
        for _ in 0..4 {
            apply_failed_attempt(&mut scope);
        }
        assert_eq!(scope.failed_attempts, 4);
        assert!(scope.lockout_until.is_none() && !scope.lockdown);
        assert!(check_lockout(&scope).is_ok());

        apply_failed_attempt(&mut scope); // 5 -> 30s lockout
        assert!(scope.lockout_until.is_some() && !scope.lockdown);
        assert!(check_lockout(&scope).is_err());

        for _ in 0..5 {
            apply_failed_attempt(&mut scope); // 10 -> 5 min lockout
        }
        let until = scope.lockout_until.unwrap();
        assert!((until - Utc::now()).num_seconds() > 60);

        for _ in 0..10 {
            apply_failed_attempt(&mut scope); // 20 -> lockdown
        }
        assert!(scope.lockdown);
        assert!(check_lockout(&scope).is_err());
    }

    #[test]
    fn reset_wrapped_master_round_trips_only_with_its_secret() {
        // The vault-reset wrap must behave exactly like the setup wrap: the new
        // master is recoverable with the new secret and no other.
        let master = PersistedVaultMaster {
            version: 1,
            vmk: symmetric::random_key(),
            signer: VaultSigningKeypair::generate(),
            configured_at: Utc::now(),
        };
        let salt = random_salt();
        let secret = b"a-fresh-strong-secret-123";
        let env = wrap_master_under_secret(&salt, secret, &master).unwrap();
        let aad = crate::security::obf::workspace_vault_wrap_aad();

        let good = derive_vault_wrap_key(&salt, secret).unwrap();
        let plaintext = symmetric::decrypt(&good, &env, &aad).unwrap();
        let restored: PersistedVaultMaster = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(restored.vmk, master.vmk, "reset must preserve the new VMK exactly");

        let bad = derive_vault_wrap_key(&salt, b"the-wrong-secret-000").unwrap();
        assert!(symmetric::decrypt(&bad, &env, &aad).is_err());
    }

    #[test]
    fn secret_validation_enforces_policy() {
        assert!(validate_secret(METHOD_PASSWORD, "short").is_err());
        assert!(validate_secret(METHOD_PASSWORD, "twelve-chars-ok").is_ok());
        assert!(validate_secret(METHOD_PIN, "12345").is_err()); // too short
        assert!(validate_secret(METHOD_PIN, "1234ab").is_err()); // non-digit
        assert!(validate_secret(METHOD_PIN, "123456").is_ok());
        assert!(validate_secret(METHOD_PIN, "1234567890123").is_err()); // too long
    }
}
