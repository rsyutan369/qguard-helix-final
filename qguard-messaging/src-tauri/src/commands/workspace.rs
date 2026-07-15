//! Zero-Trust Workspace Lock: independent password/PIN gates for the Secure Chat
//! and Quantum Vault workspaces, enforced locally (no secret ever leaves the
//! device or is sent to a server).
//!
//! * Both scopes store only a salt + a derived verifier (never the secret).
//! * The **vault** scope additionally wraps the Vault Master Key (VMK) under a
//!   password/PIN-derived key, so unlocking cryptographically decrypts the VMK
//!   (`password -> Argon2id -> HKDF-SHA3-256 -> unlock key -> VMK`). The legacy
//!   keychain-only VMK copy is deleted at setup, so vault access truly requires
//!   the secret.
//! * The secret is stretched with **Argon2id** (memory-hard) before any HKDF
//!   subkey derivation, so an attacker who copies the encrypted credential file
//!   off disk cannot brute-force a PIN/password at HKDF speed. Credentials
//!   written before this hardening (`kdf_version` 0) still verify and are
//!   re-sealed under Argon2id on their next successful unlock.
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

/// KDF versions for `WorkspaceCredential::kdf_version`.
const KDF_LEGACY_HKDF: u8 = 0;
const KDF_ARGON2ID_V1: u8 = 1;

/// Argon2id parameters: 64 MiB, 3 passes, 1 lane (OWASP-recommended class).
/// ~0.3–1s per stretch — slow enough to make offline brute force of a stolen
/// credential file expensive, fast enough for an interactive unlock gate.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_LANES: u32 = 1;

/// Memory-hard Argon2id prehash of the unlock secret.
fn argon2id_prehash(salt: &[u8], secret: &[u8]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_LANES, Some(32))
        .map_err(|e| QGuardError::Crypto(format!("argon2id params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(secret, salt, &mut out)
        .map_err(|e| QGuardError::Crypto(format!("argon2id stretch failed: {e}")))?;
    Ok(out)
}

/// Stretch the unlock secret into the input keying material every HKDF subkey
/// (verifier + VMK wrap key) is derived from. Legacy (v0) feeds the raw secret
/// straight into HKDF — kept only so pre-upgrade credentials still verify.
fn secret_ikm(kdf_version: u8, salt: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    match kdf_version {
        KDF_LEGACY_HKDF => Ok(secret.to_vec()),
        KDF_ARGON2ID_V1 => Ok(argon2id_prehash(salt, secret)?.to_vec()),
        other => Err(QGuardError::Crypto(format!(
            "workspace credential uses unsupported KDF version {other}; update QGuard Messaging"
        ))),
    }
}

/// Run the (deliberately slow, memory-hard) secret stretch on the blocking
/// thread pool. Workspace commands are async so the Argon2id pass never runs on
/// the MAIN thread — a sync command would freeze the window event loop for the
/// full stretch (the same freeze class the vault stream commands fixed).
async fn stretch_secret(kdf_version: u8, salt: Vec<u8>, mut secret: Vec<u8>) -> Result<Vec<u8>> {
    tauri::async_runtime::spawn_blocking(move || {
        let ikm = secret_ikm(kdf_version, &salt, &secret);
        secret.zeroize();
        ikm
    })
    .await
    .map_err(|e| QGuardError::Crypto(format!("secret stretch worker failed: {e}")))?
}

/// Verifier (hash of an independent HKDF subkey) — validates a re-entered
/// secret without revealing the unlock key.
fn derive_verifier_from_ikm(salt: &[u8], ikm: &[u8]) -> Result<String> {
    let mut k = derive_32_with_salt(salt, ikm, &crate::security::obf::workspace_chat_verifier_info())?;
    let verifier = sha3_hex(&k);
    k.zeroize();
    Ok(verifier)
}

/// Unlock key (distinct HKDF context from the verifier) that wraps the VMK.
fn derive_vault_wrap_key_from_ikm(salt: &[u8], ikm: &[u8]) -> Result<[u8; KEY_SIZE]> {
    derive_32_with_salt(salt, ikm, &crate::security::obf::workspace_vault_unlock_info())
}

/// AES-256-GCM-wrap a serialized `PersistedVaultMaster` under the unlock key
/// derived from the stretched secret. Shared by vault setup, vault reset, and
/// the KDF upgrade so the wrap format stays in lockstep. Both the derived key
/// and the plaintext serialization are zeroized before returning.
fn wrap_master_under_ikm(
    salt: &[u8],
    ikm: &[u8],
    master: &PersistedVaultMaster,
) -> Result<EncryptedEnvelope> {
    let mut serialized = serde_json::to_vec(master)
        .map_err(|e| QGuardError::Storage(format!("encode vault master for wrap: {e}")))?;
    let wrap_key = derive_vault_wrap_key_from_ikm(salt, ikm);
    let mut wrap_key = match wrap_key {
        Ok(key) => key,
        Err(e) => {
            serialized.zeroize();
            return Err(e);
        }
    };
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
pub async fn workspace_setup_credential(
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
    let stretched = stretch_secret(KDF_ARGON2ID_V1, salt.clone(), secret.as_bytes().to_vec()).await;
    secret.zeroize();
    let mut ikm = stretched?;
    let verifier = derive_verifier_from_ikm(&salt, &ikm);
    let verifier = match verifier {
        Ok(v) => v,
        Err(e) => {
            ikm.zeroize();
            return Err(e);
        }
    };
    let mut credential = WorkspaceCredential {
        salt: salt.clone(),
        verifier,
        wrapped_master: None,
        kdf_version: KDF_ARGON2ID_V1,
    };

    let mut first_vault_setup = false;
    if scope_name == SCOPE_VAULT {
        // Obtain the VMK to wrap under this secret. First time: load/generate it
        // (and migrate away from the legacy keychain copy). Adding a second method:
        // the vault must already be unlocked so we wrap the in-session VMK.
        let master = if record.configured() {
            state.unlocked_vault_master()
        } else {
            first_vault_setup = true;
            state.load_or_generate_vault_master(&user_id)
        };
        let master = match master {
            Ok(m) => m,
            Err(e) => {
                ikm.zeroize();
                return Err(e);
            }
        };
        let wrapped = wrap_master_under_ikm(&salt, &ikm, &master);
        let wrapped = match wrapped {
            Ok(w) => w,
            Err(e) => {
                ikm.zeroize();
                return Err(e);
            }
        };
        credential.wrapped_master = Some(wrapped);

        if first_vault_setup {
            state.delete_vault_master_file(&user_id)?;
            state.set_vault_session(master)?;
        }
    }
    ikm.zeroize();

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

    state.audit_info(
        "workspace_credential_set",
        &format!("Workspace {scope_name} {method} configured"),
    );
    if first_vault_setup {
        state.touch_telemetry(
            "vault",
            "Quantum Vault unlock configured (password -> Argon2id -> HKDF-SHA3-256 -> VMK)",
            100,
        );
    }
    let loaded = state.load_workspace_scope(&user_id, scope_name)?;
    Ok(scope_status(&state, scope_name, &loaded))
}

#[tauri::command]
pub async fn workspace_unlock(
    state: State<'_, AppState>,
    scope: String,
    method: String,
    mut secret: String,
) -> Result<ScopeStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let scope_name = normalize_scope(&scope)?;

    // Keep one owned copy of the secret for the whole flow (verification +
    // optional KDF upgrade), zeroized on every exit path below.
    let mut secret_bytes = secret.as_bytes().to_vec();
    secret.zeroize();

    let outcome = unlock_with_secret(&state, &user_id, scope_name, &method, &secret_bytes).await;
    secret_bytes.zeroize();
    outcome
}

async fn unlock_with_secret(
    state: &State<'_, AppState>,
    user_id: &str,
    scope_name: &'static str,
    method: &str,
    secret_bytes: &[u8],
) -> Result<ScopeStatus> {
    let mut record = state
        .load_workspace_scope(user_id, scope_name)?
        .ok_or_else(|| QGuardError::NotFound("workspace is not configured yet".to_string()))?;
    check_lockout(&record)?;

    let credential = credential_for(&record, method)
        .ok_or_else(|| QGuardError::InvalidInput(format!("{method} is not set up for this workspace")))?
        .clone();

    let mut ikm = stretch_secret(credential.kdf_version, credential.salt.clone(), secret_bytes.to_vec()).await?;
    let verifier = derive_verifier_from_ikm(&credential.salt, &ikm);
    let verifier = match verifier {
        Ok(v) => v,
        Err(e) => {
            ikm.zeroize();
            return Err(e);
        }
    };
    let ok = verifier == credential.verifier;

    if !ok {
        ikm.zeroize();
        apply_failed_attempt(&mut record);
        let lockdown = record.lockdown;
        state.save_workspace_scope(user_id, &record)?;
        state.audit_info("workspace_unlock_failed", &format!("Failed {scope_name} unlock"));
        if lockdown {
            return Err(QGuardError::Trust(
                "Too many attempts — this workspace is locked down. Sign out and back in to reset.".to_string(),
            ));
        }
        return Err(QGuardError::Trust("Incorrect password or PIN.".to_string()));
    }

    // For the vault, the real unlock is decrypting the VMK with the derived key.
    let mut unlocked_master: Option<PersistedVaultMaster> = None;
    if scope_name == SCOPE_VAULT {
        let envelope = match credential.wrapped_master.as_ref() {
            Some(e) => e,
            None => {
                ikm.zeroize();
                return Err(QGuardError::Crypto("vault credential is missing its wrapped key".to_string()));
            }
        };
        let wrap_key = derive_vault_wrap_key_from_ikm(&credential.salt, &ikm);
        let mut wrap_key = match wrap_key {
            Ok(key) => key,
            Err(e) => {
                ikm.zeroize();
                return Err(e);
            }
        };
        let decrypted = symmetric::decrypt(&wrap_key, envelope, &crate::security::obf::workspace_vault_wrap_aad());
        wrap_key.zeroize();
        let mut plaintext = match decrypted {
            Ok(p) => p,
            Err(_) => {
                ikm.zeroize();
                apply_failed_attempt(&mut record);
                state.save_workspace_scope(user_id, &record)?;
                return Err(QGuardError::Trust("Incorrect password or PIN.".to_string()));
            }
        };
        let master = serde_json::from_slice(&plaintext)
            .map_err(|e| QGuardError::Storage(format!("decode unlocked vault master: {e}")));
        plaintext.zeroize();
        let master: PersistedVaultMaster = match master {
            Ok(m) => m,
            Err(e) => {
                ikm.zeroize();
                return Err(e);
            }
        };
        unlocked_master = Some(master);
    }
    ikm.zeroize();

    // Transparent KDF hardening: a credential verified under the legacy
    // direct-HKDF derivation is re-sealed under Argon2id (fresh salt) now that
    // the secret is proven. Best-effort — a failure keeps the legacy credential
    // working and the next successful unlock retries the upgrade.
    if credential.kdf_version < KDF_ARGON2ID_V1 {
        let upgrade: Result<WorkspaceCredential> = async {
            let new_salt = random_salt();
            let mut new_ikm = stretch_secret(KDF_ARGON2ID_V1, new_salt.clone(), secret_bytes.to_vec()).await?;
            let new_verifier = derive_verifier_from_ikm(&new_salt, &new_ikm);
            let wrapped = unlocked_master
                .as_ref()
                .map(|master| wrap_master_under_ikm(&new_salt, &new_ikm, master))
                .transpose();
            new_ikm.zeroize();
            Ok(WorkspaceCredential {
                salt: new_salt,
                verifier: new_verifier?,
                wrapped_master: wrapped?,
                kdf_version: KDF_ARGON2ID_V1,
            })
        }
        .await;
        if let Ok(upgraded) = upgrade {
            match method {
                METHOD_PASSWORD => record.password = Some(upgraded),
                METHOD_PIN => record.pin = Some(upgraded),
                _ => {}
            }
            state.audit_info(
                "workspace_kdf_upgraded",
                &format!("Workspace {scope_name} {method} credential re-sealed with Argon2id"),
            );
        }
    }

    if let Some(master) = unlocked_master {
        state.set_vault_session(master)?;
    }

    record.failed_attempts = 0;
    record.lockout_until = None;
    state.save_workspace_scope(user_id, &record)?;
    state.mark_workspace_unlocked(scope_name)?;

    state.audit_info("workspace_unlock", &format!("Workspace {scope_name} unlocked"));
    let loaded = state.load_workspace_scope(user_id, scope_name)?;
    Ok(scope_status(state, scope_name, &loaded))
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
pub async fn workspace_reset_vault(
    state: State<'_, AppState>,
    recovery_key: Option<String>,
    method: String,
    mut secret: String,
    account_verifier: Option<String>,
) -> Result<ScopeStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    if let Err(e) = validate_secret(&method, &secret) {
        secret.zeroize();
        return Err(e);
    }

    // Recovery-key path: prove possession of the recovery key before resetting.
    // The expected verifier comes from the device-local recovery material when
    // this device has it, falling back to the ACCOUNT recovery registry
    // (fetched by the frontend) — so the one account recovery key also unlocks
    // a vault reset on a brand-new device that never stored local material.
    if let Some(ref key) = recovery_key {
        let expected_verifier = match state.load_vault_recovery(&user_id)? {
            Some(material) => material.verifier.clone(),
            None => account_verifier.clone().unwrap_or_default(),
        };
        if expected_verifier.is_empty() {
            secret.zeroize();
            return Err(QGuardError::InvalidInput(
                "No recovery key is configured for this account.".to_string(),
            ));
        }
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
        if verifier != expected_verifier {
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
    let stretched = stretch_secret(KDF_ARGON2ID_V1, salt.clone(), secret.as_bytes().to_vec()).await;
    secret.zeroize();
    let mut ikm = stretched?;
    let sealed = derive_verifier_from_ikm(&salt, &ikm)
        .and_then(|verifier| Ok((verifier, wrap_master_under_ikm(&salt, &ikm, &new_master)?)));
    ikm.zeroize();
    let (verifier, wrapped) = sealed?;
    let credential = WorkspaceCredential {
        salt,
        verifier,
        wrapped_master: Some(wrapped),
        kdf_version: KDF_ARGON2ID_V1,
    };

    let mut record = PersistedWorkspaceScope::new(SCOPE_VAULT);
    match method.as_str() {
        METHOD_PASSWORD => record.password = Some(credential),
        METHOD_PIN => record.pin = Some(credential),
        _ => {
            return Err(QGuardError::InvalidInput(format!("unknown unlock method: {method}")));
        }
    }

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

    fn verifier_for(kdf_version: u8, salt: &[u8], secret: &[u8]) -> String {
        let ikm = secret_ikm(kdf_version, salt, secret).unwrap();
        derive_verifier_from_ikm(salt, &ikm).unwrap()
    }

    #[test]
    fn verifier_is_deterministic_and_secret_specific() {
        let salt = random_salt();
        let a = verifier_for(KDF_ARGON2ID_V1, &salt, b"correct horse battery staple");
        assert_eq!(a, verifier_for(KDF_ARGON2ID_V1, &salt, b"correct horse battery staple"));
        assert_ne!(a, verifier_for(KDF_ARGON2ID_V1, &salt, b"a different secret entirely"));
        // A different salt yields a different verifier for the same secret.
        let salt2 = random_salt();
        assert_ne!(a, verifier_for(KDF_ARGON2ID_V1, &salt2, b"correct horse battery staple"));
    }

    #[test]
    fn kdf_versions_are_domain_separated_and_legacy_matches_old_formula() {
        let salt = random_salt();
        let secret = b"correct horse battery staple";

        // Legacy (v0) ikm is the raw secret — exactly what the pre-upgrade code
        // fed HKDF, so credentials written before the upgrade keep verifying.
        let legacy_ikm = secret_ikm(KDF_LEGACY_HKDF, &salt, secret).unwrap();
        assert_eq!(legacy_ikm, secret.to_vec());

        // Argon2id ikm is deterministic but different from the raw secret, so
        // the two versions can never validate against each other's verifier.
        let hardened_ikm = secret_ikm(KDF_ARGON2ID_V1, &salt, secret).unwrap();
        assert_eq!(hardened_ikm, secret_ikm(KDF_ARGON2ID_V1, &salt, secret).unwrap());
        assert_ne!(hardened_ikm, legacy_ikm);
        assert_ne!(
            verifier_for(KDF_LEGACY_HKDF, &salt, secret),
            verifier_for(KDF_ARGON2ID_V1, &salt, secret),
        );

        // Unknown future versions must fail closed, never fall back to legacy.
        assert!(secret_ikm(99, &salt, secret).is_err());
    }

    #[test]
    fn vault_unlock_key_unwraps_vmk_only_with_correct_secret() {
        let salt = random_salt();
        let secret: &[u8] = b"a-strong-vault-password-123";
        let vmk_blob: &[u8] = b"serialized-persisted-vault-master-stand-in-bytes";
        let aad = crate::security::obf::workspace_vault_wrap_aad();

        let ikm = secret_ikm(KDF_ARGON2ID_V1, &salt, secret).unwrap();
        let key = derive_vault_wrap_key_from_ikm(&salt, &ikm).unwrap();
        let env = symmetric::encrypt(&key, vmk_blob, &aad).unwrap();

        // Correct secret re-derives the key and recovers the VMK material.
        let good_ikm = secret_ikm(KDF_ARGON2ID_V1, &salt, secret).unwrap();
        let good = derive_vault_wrap_key_from_ikm(&salt, &good_ikm).unwrap();
        assert_eq!(symmetric::decrypt(&good, &env, &aad).unwrap(), vmk_blob);

        // Wrong secret -> AEAD authentication fails (no VMK recovered).
        let bad_ikm = secret_ikm(KDF_ARGON2ID_V1, &salt, b"the-wrong-password-000").unwrap();
        let bad = derive_vault_wrap_key_from_ikm(&salt, &bad_ikm).unwrap();
        assert!(symmetric::decrypt(&bad, &env, &aad).is_err());
    }

    #[test]
    fn legacy_wrapped_master_upgrades_to_argon2id_and_round_trips() {
        // Simulates the transparent unlock-time upgrade: a VMK wrapped under the
        // legacy direct-HKDF key is recovered with the legacy derivation, then
        // re-sealed under Argon2id, and the hardened credential recovers the
        // exact same VMK afterwards.
        let master = PersistedVaultMaster {
            version: 1,
            vmk: symmetric::random_key(),
            signer: VaultSigningKeypair::generate(),
            configured_at: Utc::now(),
        };
        let secret = b"an-older-strong-secret-42";
        let aad = crate::security::obf::workspace_vault_wrap_aad();

        // Legacy credential (as written before the upgrade).
        let legacy_salt = random_salt();
        let legacy_ikm = secret_ikm(KDF_LEGACY_HKDF, &legacy_salt, secret).unwrap();
        let legacy_env = wrap_master_under_ikm(&legacy_salt, &legacy_ikm, &master).unwrap();

        // Unlock with the legacy derivation still recovers the VMK.
        let legacy_key = derive_vault_wrap_key_from_ikm(&legacy_salt, &legacy_ikm).unwrap();
        let plaintext = symmetric::decrypt(&legacy_key, &legacy_env, &aad).unwrap();
        let recovered: PersistedVaultMaster = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(recovered.vmk, master.vmk);

        // Upgrade path: re-seal the recovered master under Argon2id + new salt.
        let new_salt = random_salt();
        let new_ikm = secret_ikm(KDF_ARGON2ID_V1, &new_salt, secret).unwrap();
        let upgraded_env = wrap_master_under_ikm(&new_salt, &new_ikm, &recovered).unwrap();
        let upgraded_key = derive_vault_wrap_key_from_ikm(&new_salt, &new_ikm).unwrap();
        let upgraded_plain = symmetric::decrypt(&upgraded_key, &upgraded_env, &aad).unwrap();
        let upgraded: PersistedVaultMaster = serde_json::from_slice(&upgraded_plain).unwrap();
        assert_eq!(upgraded.vmk, master.vmk, "KDF upgrade must preserve the VMK exactly");

        // The legacy derivation can no longer open the upgraded envelope.
        let stale_key = derive_vault_wrap_key_from_ikm(&new_salt, secret).unwrap();
        assert!(symmetric::decrypt(&stale_key, &upgraded_env, &aad).is_err());
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
        let ikm = secret_ikm(KDF_ARGON2ID_V1, &salt, secret).unwrap();
        let env = wrap_master_under_ikm(&salt, &ikm, &master).unwrap();
        let aad = crate::security::obf::workspace_vault_wrap_aad();

        let good = derive_vault_wrap_key_from_ikm(&salt, &ikm).unwrap();
        let plaintext = symmetric::decrypt(&good, &env, &aad).unwrap();
        let restored: PersistedVaultMaster = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(restored.vmk, master.vmk, "reset must preserve the new VMK exactly");

        let bad_ikm = secret_ikm(KDF_ARGON2ID_V1, &salt, b"the-wrong-secret-000").unwrap();
        let bad = derive_vault_wrap_key_from_ikm(&salt, &bad_ikm).unwrap();
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
