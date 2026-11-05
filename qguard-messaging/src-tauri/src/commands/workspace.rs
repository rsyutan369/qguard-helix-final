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
//! * The vault also opens with a drawn pattern (`vault::pattern`), sealed
//!   exactly like a PIN. The pattern pad is also how a hidden vault opens
//!   (`vault::hidden`): see `vault_pattern_unlock`.

use chrono::Utc;
use serde::Serialize;
use tauri::State;
use zeroize::Zeroize;

use crate::crypto::passcode;
#[cfg(test)]
use crate::crypto::passcode::KDF_ARGON2ID_V1;
use crate::crypto::provider;
use crate::crypto::signatures::VaultSigningKeypair;
use crate::crypto::symmetric::{self, KEY_SIZE};
use crate::crypto::{mnemonic, vault_recovery, EncryptedEnvelope};
use crate::error::{QGuardError, Result};
use crate::state::{
    AppState, PersistedVaultMaster, PersistedVaultRecovery, PersistedWorkspaceScope,
    VaultRecoveryPublic, WorkspaceCredential,
};
use crate::vault::hidden::{self, HiddenKeys, HiddenSummary, HiddenVault, PATTERN_TAKEN};
use crate::vault::pattern;

const SCOPE_CHAT: &str = "chat";
const SCOPE_VAULT: &str = "vault";
const METHOD_PASSWORD: &str = "password";
const METHOD_PIN: &str = "pin";
const METHOD_PATTERN: &str = "pattern";
const LOCKDOWN_MESSAGE: &str = "Too many attempts — this workspace is locked down. Sign out and back in to reset.";

const MIN_PASSWORD_LEN: usize = 12;
const MIN_PIN_LEN: usize = 6;
const MAX_PIN_LEN: usize = 12;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeStatus {
    pub configured: bool,
    pub has_password: bool,
    pub has_pin: bool,
    pub has_pattern: bool,
    pub unlocked: bool,
    pub failed_attempts: u32,
    pub lockout_until: Option<String>,
    pub lockdown: bool,
    /// The lock record exists but no longer opens: it was sealed under a device
    /// storage key this device no longer holds. Still configured and locked;
    /// only the re-authenticated resets can replace it.
    pub unreadable: bool,
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
        // Only the canonical text of a drawable pattern, so one pattern is
        // always exactly one secret.
        METHOD_PATTERN => pattern::parse(secret).map(|_| ()),
        other => Err(QGuardError::InvalidInput(format!("unknown unlock method: {other}"))),
    }
}

/// `validate_secret`, plus what FIPS approved mode requires of the Quantum
/// Vault: a password of at least `APPROVED_PASSWORD_MIN_CHARS` characters.
/// PBKDF2 has no memory cost, so a PIN in front of the vault key would be
/// guessable offline (see `provider::policy`).
fn validate_for_scope(scope_name: &str, method: &str, secret: &str, approved: bool) -> Result<()> {
    validate_secret(method, secret)?;
    if method == METHOD_PATTERN && scope_name != SCOPE_VAULT {
        return Err(QGuardError::InvalidInput("A pattern unlocks the Quantum Vault only.".to_string()));
    }
    if approved && scope_name == SCOPE_VAULT {
        if method != METHOD_PASSWORD {
            return Err(QGuardError::InvalidInput(format!(
                "FIPS approved mode: the Quantum Vault must use a password of at least {} characters, not a PIN.",
                provider::APPROVED_PASSWORD_MIN_CHARS
            )));
        }
        if secret.chars().count() < provider::APPROVED_PASSWORD_MIN_CHARS {
            return Err(QGuardError::InvalidInput(format!(
                "FIPS approved mode: the Quantum Vault password must be at least {} characters.",
                provider::APPROVED_PASSWORD_MIN_CHARS
            )));
        }
    }
    Ok(())
}

/// Whether a credential sealed with `kdf` from this secret meets approved mode.
fn approved_strength(method: &str, secret_chars: usize, kdf: u8) -> bool {
    passcode::kdf_is_approved(kdf) && method == METHOD_PASSWORD && secret_chars >= provider::APPROVED_PASSWORD_MIN_CHARS
}

/// The KDF a proven credential is re-sealed under. Normally the device's
/// preference; but a Quantum Vault PIN or pattern is never moved from Argon2id
/// to PBKDF2: without Argon2id's memory cost a short secret in front of the
/// vault key gets weaker, and approved mode wants it replaced by a password.
fn reseal_target(scope_name: &str, method: &str) -> u8 {
    let preferred = passcode::preferred_kdf();
    if scope_name == SCOPE_VAULT && (method == METHOD_PIN || method == METHOD_PATTERN) && passcode::kdf_is_approved(preferred) {
        passcode::KDF_ARGON2ID_V1
    } else {
        preferred
    }
}

fn secret_chars(secret: &[u8]) -> usize {
    std::str::from_utf8(secret).map(|s| s.chars().count()).unwrap_or(secret.len())
}

fn random_salt() -> Vec<u8> {
    passcode::random_salt()
}

/// Test-only: production code now stretches secrets exclusively through
/// `stretch_secret` (which delegates straight to `passcode::stretch_secret`).
/// The tests still exercise `secret_ikm` directly (e.g. to derive an IKM
/// without a `spawn_blocking` round trip), so keep the thin wrapper for them.
#[cfg(test)]
fn secret_ikm(kdf_version: u8, salt: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    passcode::secret_ikm(kdf_version, salt, secret)
}

async fn stretch_secret(kdf_version: u8, salt: Vec<u8>, secret: Vec<u8>) -> Result<Vec<u8>> {
    passcode::stretch_secret(kdf_version, salt, secret).await
}

/// Verifier (hash of an independent HKDF subkey) — validates a re-entered
/// secret without revealing the unlock key.
fn derive_verifier_from_ikm(salt: &[u8], ikm: &[u8]) -> Result<String> {
    passcode::derive_verifier(salt, ikm, &crate::security::obf::workspace_chat_verifier_info())
}

/// Unlock key (distinct HKDF context from the verifier) that wraps the VMK.
fn derive_vault_wrap_key_from_ikm(salt: &[u8], ikm: &[u8]) -> Result<[u8; KEY_SIZE]> {
    passcode::derive_wrap_key(salt, ikm, &crate::security::obf::workspace_vault_unlock_info())
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

/// Rebuild the device's recovery configuration after a vault reset, from the
/// public half that is readable while locked plus the recovery root the user
/// has just proven they hold. The caller seals it under the NEW vault key.
fn reseal_recovery_after_reset(
    public: &VaultRecoveryPublic,
    root: &[u8; KEY_SIZE],
) -> Result<PersistedVaultRecovery> {
    let hybrid = public.mode == "hybrid";
    Ok(PersistedVaultRecovery {
        version: 2,
        // Personal mode keeps the derived wrapping key; hybrid keeps the root
        // itself, because its wrap key also depends on the enterprise secret.
        wrap_key: if hybrid {
            [0u8; KEY_SIZE]
        } else {
            vault_recovery::derive_wrap_key(root)?
        },
        verifier: public.verifier.clone(),
        configured_at: public.configured_at,
        mode: Some(public.mode.clone()),
        recovery_root: if hybrid { Some(*root) } else { None },
        enterprise_x25519_public: public.enterprise_x25519_public.clone(),
        enterprise_mlkem_public: public.enterprise_mlkem_public.clone(),
        recipient_key_id: public.recipient_key_id.clone(),
    })
}

/// Move a recovery record written by an older build under the vault key. Runs
/// the moment the vault key exists (unlock / first setup), so the copy that was
/// protected by the device storage key alone does not outlive this session.
fn migrate_recovery_material(state: &AppState, user_id: &str, master: &PersistedVaultMaster) {
    if let Ok(vault_key) = master.vault_key() {
        let vault_key = zeroize::Zeroizing::new(vault_key);
        state.migrate_vault_recovery(user_id, &vault_key);
    }
}

/// Every account gets the hidden-vault pool (with its cover files) the first
/// time its vault opens, hidden vaults or not, so the pool's existence says
/// nothing. In the background: the first time writes a few MiB of noise.
fn ensure_hidden_pool(state: &AppState, user_id: &str) {
    let pool = state.hidden_pool(user_id);
    drop(tauri::async_runtime::spawn_blocking(move || {
        let _ = pool.ensure();
    }));
}

fn credential_for<'a>(scope: &'a PersistedWorkspaceScope, method: &str) -> Option<&'a WorkspaceCredential> {
    match method {
        METHOD_PASSWORD => scope.password.as_ref(),
        METHOD_PIN => scope.pin.as_ref(),
        METHOD_PATTERN => scope.pattern.as_ref(),
        _ => None,
    }
}

fn credential_slot<'a>(scope: &'a mut PersistedWorkspaceScope, method: &str) -> Result<&'a mut Option<WorkspaceCredential>> {
    match method {
        METHOD_PASSWORD => Ok(&mut scope.password),
        METHOD_PIN => Ok(&mut scope.pin),
        METHOD_PATTERN => Ok(&mut scope.pattern),
        other => Err(QGuardError::InvalidInput(format!("unknown unlock method: {other}"))),
    }
}

fn check_lockout(scope: &PersistedWorkspaceScope) -> Result<()> {
    if scope.lockdown {
        return Err(QGuardError::Trust(LOCKDOWN_MESSAGE.to_string()));
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

/// How long a pattern must wait after the last one that opened nothing, given
/// how many opened nothing in the last 24 hours. Up to ~40 tries a day.
fn pattern_wait(recent_misses: usize) -> Option<chrono::Duration> {
    match recent_misses {
        0..=4 => None,
        5..=9 => Some(chrono::Duration::seconds(30)),
        10..=19 => Some(chrono::Duration::minutes(5)),
        _ => Some(chrono::Duration::hours(1)),
    }
}

fn recent_pattern_misses(scope: &PersistedWorkspaceScope, now: chrono::DateTime<Utc>) -> Vec<chrono::DateTime<Utc>> {
    scope.pattern_misses.iter().copied().filter(|at| now - *at < chrono::Duration::hours(24)).collect()
}

/// The pattern pace limit: separate from the attempt ladder, because a correct
/// password or PIN clears that one and must not buy more pattern tries.
fn check_pattern_pace(scope: &PersistedWorkspaceScope) -> Result<()> {
    let now = Utc::now();
    let recent = recent_pattern_misses(scope, now);
    if let (Some(wait), Some(last)) = (pattern_wait(recent.len()), recent.iter().max()) {
        let until = *last + wait;
        if until > now {
            let secs = (until - now).num_seconds().max(1);
            return Err(QGuardError::Trust(format!("Too many patterns tried. Try again in {secs}s.")));
        }
    }
    Ok(())
}

fn record_pattern_miss(scope: &mut PersistedWorkspaceScope) {
    let now = Utc::now();
    scope.pattern_misses = recent_pattern_misses(scope, now);
    scope.pattern_misses.push(now);
    let excess = scope.pattern_misses.len().saturating_sub(64);
    scope.pattern_misses.drain(..excess);
}

fn scope_status(state: &AppState, scope_name: &str, scope: &Option<PersistedWorkspaceScope>) -> ScopeStatus {
    match scope {
        Some(s) => ScopeStatus {
            configured: s.configured(),
            has_password: s.password.is_some(),
            has_pin: s.pin.is_some(),
            has_pattern: s.pattern.is_some(),
            unlocked: state.is_workspace_unlocked(scope_name),
            failed_attempts: s.failed_attempts,
            lockout_until: s.lockout_until.map(|t| t.to_rfc3339()),
            lockdown: s.lockdown,
            unreadable: false,
        },
        None => ScopeStatus {
            configured: false,
            has_password: false,
            has_pin: false,
            has_pattern: false,
            unlocked: false,
            failed_attempts: 0,
            lockout_until: None,
            lockdown: false,
            unreadable: false,
        },
    }
}

#[tauri::command]
pub fn workspace_status(state: State<'_, AppState>) -> Result<WorkspaceStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    Ok(WorkspaceStatus {
        chat: status_of_record(&state, &user_id, SCOPE_CHAT),
        vault: status_of_record(&state, &user_id, SCOPE_VAULT),
    })
}

/// The status of one scope, even when its record will not open. Failing the
/// whole call left both workspaces on a loading skeleton for good after a
/// device storage key change. An unopenable record is reported as configured,
/// locked and `unreadable` -- never as "no lock", which would let anyone able
/// to corrupt the file set a new lock and walk in.
fn status_of_record(state: &AppState, user_id: &str, scope_name: &str) -> ScopeStatus {
    match state.load_workspace_scope(user_id, scope_name) {
        Ok(record) => scope_status(state, scope_name, &record),
        Err(_) => ScopeStatus {
            configured: true,
            has_password: false,
            has_pin: false,
            has_pattern: false,
            unlocked: false,
            failed_attempts: 0,
            lockout_until: None,
            lockdown: false,
            unreadable: true,
        },
    }
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
    validate_for_scope(scope_name, &method, &secret, provider::approved_mode())?;

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
    let kdf = passcode::preferred_kdf();
    let strong = approved_strength(&method, secret.chars().count(), kdf);
    let stretched = stretch_secret(kdf, salt.clone(), secret.as_bytes().to_vec()).await;
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
        kdf_version: kdf,
        approved_strength: strong,
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
            migrate_recovery_material(&state, &user_id, &master);
            state.set_vault_session(master)?;
            ensure_hidden_pool(&state, &user_id);
        }
    }
    ikm.zeroize();

    *credential_slot(&mut record, &method)? = Some(credential);
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
            &format!(
                "Quantum Vault unlock configured (password -> {} -> HKDF-SHA3-256 -> VMK)",
                passcode::kdf_label(kdf)
            ),
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
    state: &AppState,
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

    match prove(scope_name, &credential, secret_bytes).await? {
        Proof::Wrong => Err(wrong_secret(state, user_id, scope_name, &mut record, "Incorrect password or PIN.")?),
        Proof::Right(unlocked_master) => {
            finish_unlock(state, user_id, scope_name, method, record, &credential, secret_bytes, unlocked_master).await
        }
    }
}

/// What proving a secret against one stored credential showed.
enum Proof {
    Wrong,
    /// Right; for the vault, with the master key the credential unwrapped.
    Right(Option<PersistedVaultMaster>),
}

/// Stretch `secret` exactly as `credential` was sealed and check it. For the
/// vault the proof is the wrapped master key opening, not only the verifier.
async fn prove(scope_name: &str, credential: &WorkspaceCredential, secret: &[u8]) -> Result<Proof> {
    let mut ikm = stretch_secret(credential.kdf_version, credential.salt.clone(), secret.to_vec()).await?;
    let outcome = open_with_ikm(scope_name, credential, &ikm);
    ikm.zeroize();
    outcome
}

fn open_with_ikm(scope_name: &str, credential: &WorkspaceCredential, ikm: &[u8]) -> Result<Proof> {
    if derive_verifier_from_ikm(&credential.salt, ikm)? != credential.verifier {
        return Ok(Proof::Wrong);
    }
    if scope_name != SCOPE_VAULT {
        return Ok(Proof::Right(None));
    }
    let envelope = credential
        .wrapped_master
        .as_ref()
        .ok_or_else(|| QGuardError::Crypto("vault credential is missing its wrapped key".to_string()))?;
    let mut wrap_key = derive_vault_wrap_key_from_ikm(&credential.salt, ikm)?;
    let decrypted = symmetric::decrypt(&wrap_key, envelope, &crate::security::obf::workspace_vault_wrap_aad());
    wrap_key.zeroize();
    let Ok(mut plaintext) = decrypted else {
        return Ok(Proof::Wrong);
    };
    let master = serde_json::from_slice::<PersistedVaultMaster>(&plaintext)
        .map_err(|e| QGuardError::Storage(format!("decode unlocked vault master: {e}")));
    plaintext.zeroize();
    Ok(Proof::Right(Some(master?)))
}

/// Count a wrong secret against the scope, and the error to answer with.
fn wrong_secret(
    state: &AppState,
    user_id: &str,
    scope_name: &str,
    record: &mut PersistedWorkspaceScope,
    message: &str,
) -> Result<QGuardError> {
    apply_failed_attempt(record);
    state.save_workspace_scope(user_id, record)?;
    state.audit_info("workspace_unlock_failed", &format!("Failed {scope_name} unlock"));
    Ok(QGuardError::Trust(if record.lockdown { LOCKDOWN_MESSAGE } else { message }.to_string()))
}

/// A proven secret: re-seal it under the current KDF when needed, open the
/// session and clear the attempt counter.
#[allow(clippy::too_many_arguments)]
async fn finish_unlock(
    state: &AppState,
    user_id: &str,
    scope_name: &'static str,
    method: &str,
    mut record: PersistedWorkspaceScope,
    credential: &WorkspaceCredential,
    secret_bytes: &[u8],
    unlocked_master: Option<PersistedVaultMaster>,
) -> Result<ScopeStatus> {
    // Transparent KDF migration: a credential sealed with any KDF other than its
    // target — the legacy direct-HKDF derivation, Argon2id while FIPS approved
    // mode is on, PBKDF2 after it was switched off (see `reseal_target`) — is
    // re-sealed (fresh salt) now that the secret is proven. Best-effort — a
    // failure keeps the old credential working and the next unlock retries.
    let new_kdf = reseal_target(scope_name, method);
    if credential.kdf_version != new_kdf {
        let upgrade: Result<WorkspaceCredential> = async {
            let new_salt = random_salt();
            let mut new_ikm = stretch_secret(new_kdf, new_salt.clone(), secret_bytes.to_vec()).await?;
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
                kdf_version: new_kdf,
                approved_strength: approved_strength(method, secret_chars(secret_bytes), new_kdf),
            })
        }
        .await;
        if let Ok(upgraded) = upgrade {
            if let Ok(slot) = credential_slot(&mut record, method) {
                *slot = Some(upgraded);
            }
            state.audit_info(
                "workspace_kdf_upgraded",
                &format!(
                    "Workspace {scope_name} {method} credential re-sealed with {}",
                    passcode::kdf_label(new_kdf)
                ),
            );
        }
    }

    if let Some(master) = unlocked_master {
        migrate_recovery_material(state, user_id, &master);
        state.set_vault_session(master)?;
        ensure_hidden_pool(state, user_id);
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

/// Turn one unlock method off (for example the pattern) while the workspace
/// is unlocked. At least one method always remains.
#[tauri::command]
pub fn workspace_remove_credential(state: State<'_, AppState>, scope: String, method: String) -> Result<ScopeStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let scope_name = normalize_scope(&scope)?;
    if !state.is_workspace_unlocked(scope_name) {
        return Err(QGuardError::Trust("Unlock the workspace before changing how it unlocks.".to_string()));
    }
    let mut record = state
        .load_workspace_scope(&user_id, scope_name)?
        .ok_or_else(|| QGuardError::NotFound("workspace is not configured yet".to_string()))?;
    let methods = [record.password.is_some(), record.pin.is_some(), record.pattern.is_some()];
    if credential_for(&record, &method).is_none() {
        return Err(QGuardError::InvalidInput(format!("{method} is not set up for this workspace")));
    }
    if methods.iter().filter(|set| **set).count() <= 1 {
        return Err(QGuardError::InvalidInput("Keep at least one way to unlock it.".to_string()));
    }
    *credential_slot(&mut record, &method)? = None;
    state.save_workspace_scope(&user_id, &record)?;
    state.audit_info("workspace_credential_removed", &format!("Workspace {scope_name} {method} removed"));
    let loaded = state.load_workspace_scope(&user_id, scope_name)?;
    Ok(scope_status(&state, scope_name, &loaded))
}

/// What a drawn pattern opened.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatternUnlock {
    /// `vault` (the Quantum Vault) or `hidden` (a hidden vault).
    pub opened: &'static str,
    pub status: ScopeStatus,
}

/// Unlock with a drawn pattern: the Quantum Vault's own pattern, or a hidden
/// vault's. Both checks always run, side by side, so how long an attempt takes
/// says nothing about hidden vaults, and a pattern that opens neither counts
/// as one wrong attempt, like a wrong PIN. A hidden vault wins if the two ever
/// share a pattern (hidden vaults are made to differ from the vault's own).
#[tauri::command]
pub async fn vault_pattern_unlock(state: State<'_, AppState>, mut pattern: String) -> Result<PatternUnlock> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let secret = pattern::secret_bytes(&pattern);
    pattern.zeroize();
    let secret = secret?;
    let mut record = state
        .load_workspace_scope(&user_id, SCOPE_VAULT)?
        .ok_or_else(|| QGuardError::NotFound("workspace is not configured yet".to_string()))?;
    check_lockout(&record)?;
    check_pattern_pace(&record)?;

    // A hidden vault that cannot be checked (no device key yet) is simply not
    // found; it must never stand in the way of the vault's own pattern.
    let hidden_check = state.hidden_pool_secrets(&user_id).ok().map(|secrets| {
        let (pool, secret, user_id) = (state.hidden_pool(&user_id), secret.clone(), user_id.clone());
        tauri::async_runtime::spawn_blocking(move || -> Result<Option<HiddenVault>> {
            pool.ensure()?;
            HiddenVault::open(pool, &user_id, HiddenKeys::derive(&secrets, &secret)?)
        })
    });
    let own = match record.pattern.clone() {
        Some(credential) => Some((prove(SCOPE_VAULT, &credential, &secret).await, credential)),
        None => None,
    };
    let hidden = match hidden_check {
        Some(task) => task.await.ok().and_then(|found| found.ok()).flatten(),
        None => None,
    };

    if let Some(mut vault) = hidden {
        // An armed decoy shows as an ordinary vault from the first moment; the
        // erase of every other hidden vault runs after this returns, so the
        // unlock takes no longer than any other.
        let duress = vault.take_duress();
        state.set_hidden_vault(vault)?;
        if let Some(plan) = duress {
            let open = state.hidden_vault()?;
            drop(tauri::async_runtime::spawn_blocking(move || {
                let _ = hidden::run_duress(plan, &open);
            }));
        }
        // The same entry as any vault unlock: the log must not tell them apart.
        state.audit_info("workspace_unlock", &format!("Workspace {SCOPE_VAULT} unlocked"));
        let loaded = state.load_workspace_scope(&user_id, SCOPE_VAULT)?;
        return Ok(PatternUnlock { opened: "hidden", status: scope_status(&state, SCOPE_VAULT, &loaded) });
    }
    if let Some((proof, credential)) = own {
        if let Proof::Right(master) = proof? {
            let status = finish_unlock(&state, &user_id, SCOPE_VAULT, METHOD_PATTERN, record, &credential, &secret, master).await?;
            return Ok(PatternUnlock { opened: "vault", status });
        }
    }
    record_pattern_miss(&mut record);
    Err(wrong_secret(&state, &user_id, SCOPE_VAULT, &mut record, "Incorrect pattern.")?)
}

/// Create a hidden vault with a new pattern, from inside the unlocked Quantum
/// Vault, and open it (the Quantum Vault locks). Every attempt counts against
/// the vault's attempt limit, taken pattern or not: otherwise anyone inside
/// the vault could test patterns here for free and learn which are in use.
#[tauri::command]
pub async fn vault_hidden_create(state: State<'_, AppState>, mut pattern: String) -> Result<HiddenSummary> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let secret = pattern::secret_bytes(&pattern);
    pattern.zeroize();
    let secret = secret?;
    if provider::approved_mode() {
        return Err(QGuardError::InvalidInput(format!(
            "FIPS approved mode: a hidden vault opens with a pattern, and approved mode accepts only a password of at least {} characters in front of vault keys. Turn approved mode off to create one.",
            provider::APPROVED_PASSWORD_MIN_CHARS
        )));
    }
    state.unlocked_vault_master()?;
    let mut record = state
        .load_workspace_scope(&user_id, SCOPE_VAULT)?
        .ok_or_else(|| QGuardError::NotFound("workspace is not configured yet".to_string()))?;
    check_lockout(&record)?;
    check_pattern_pace(&record)?;
    apply_failed_attempt(&mut record);
    record_pattern_miss(&mut record);
    state.save_workspace_scope(&user_id, &record)?;

    if let Some(credential) = record.pattern.as_ref() {
        if matches!(prove(SCOPE_VAULT, credential, &secret).await?, Proof::Right(_)) {
            return Err(QGuardError::InvalidInput(PATTERN_TAKEN.to_string()));
        }
    }
    let (pool, secrets, uid) = (state.hidden_pool(&user_id), state.hidden_pool_secrets(&user_id)?, user_id.clone());
    let vault = tauri::async_runtime::spawn_blocking(move || -> Result<HiddenVault> {
        HiddenVault::create(pool, &uid, HiddenKeys::derive(&secrets, &secret)?)
    })
    .await
    .map_err(|e| QGuardError::Crypto(format!("hidden vault worker failed: {e}")))??;
    let summary = vault.summary();
    state.set_hidden_vault(vault)?;
    Ok(summary)
}

/// Open a hidden vault from inside the unlocked Quantum Vault, to look after
/// it (a decoy above all): its duress erase never fires here — only a pattern
/// drawn on the lock screen sets it off. The Quantum Vault locks. Every attempt
/// counts against the vault's attempt limit, as for creating one, so this is no
/// cheaper a way to test patterns than the lock screen.
#[tauri::command]
pub async fn vault_hidden_open(state: State<'_, AppState>, mut pattern: String) -> Result<HiddenSummary> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let secret = pattern::secret_bytes(&pattern);
    pattern.zeroize();
    let secret = secret?;
    state.unlocked_vault_master()?;
    let mut record = state
        .load_workspace_scope(&user_id, SCOPE_VAULT)?
        .ok_or_else(|| QGuardError::NotFound("workspace is not configured yet".to_string()))?;
    check_lockout(&record)?;
    check_pattern_pace(&record)?;
    apply_failed_attempt(&mut record);
    record_pattern_miss(&mut record);
    state.save_workspace_scope(&user_id, &record)?;

    let (pool, secrets, uid) = (state.hidden_pool(&user_id), state.hidden_pool_secrets(&user_id)?, user_id.clone());
    let found = tauri::async_runtime::spawn_blocking(move || -> Result<Option<HiddenVault>> {
        HiddenVault::open(pool, &uid, HiddenKeys::derive(&secrets, &secret)?)
    })
    .await
    .map_err(|e| QGuardError::Crypto(format!("hidden vault worker failed: {e}")))??;
    let vault = found.ok_or_else(|| QGuardError::InvalidInput("Incorrect pattern.".to_string()))?;
    let summary = vault.summary();
    state.set_hidden_vault(vault)?;
    Ok(summary)
}

/// The one answer for a phrase that opens nothing here — whether no vault ever
/// had it, it was replaced, or the vault was deleted or erased.
const PHRASE_OPENS_NOTHING: &str =
    "These words don't open a hidden vault on this device. Check each word and their order — a phrase that was replaced, or whose vault was deleted, no longer works.";

/// The hidden vault a typed recovery phrase opens, found on the blocking pool
/// (fast: no Argon2id — the phrase is 128 random bits).
async fn find_by_phrase(state: &AppState, mut phrase: String) -> Result<HiddenVault> {
    let entropy = mnemonic::decode(&phrase);
    phrase.zeroize();
    let entropy = entropy?;
    let user_id = state.user_id()?;
    let (pool, uid) = (state.hidden_pool(&user_id), user_id.clone());
    tauri::async_runtime::spawn_blocking(move || HiddenVault::recover(pool, &uid, &entropy))
        .await
        .map_err(|e| QGuardError::Crypto(format!("hidden vault worker failed: {e}")))??
        .ok_or_else(|| QGuardError::InvalidInput(PHRASE_OPENS_NOTHING.to_string()))
}

/// Check a hidden vault's recovery phrase before a new pattern is drawn: the
/// vault it opens, summarised. Nothing changes and nothing opens. Usable from
/// the lock screen (offered to everyone, like the pattern pad) and from inside
/// the Quantum Vault.
#[tauri::command]
pub async fn vault_hidden_recovery_check(state: State<'_, AppState>, phrase: String) -> Result<HiddenSummary> {
    state.require_auth()?;
    Ok(find_by_phrase(&state, phrase).await?.summary())
}

/// Recover a hidden vault whose pattern is forgotten: its recovery phrase
/// opens it, `pattern` becomes its new pattern (the old one stops working; the
/// phrase keeps working), and it opens (the Quantum Vault locks). The new
/// pattern is checked like a new hidden vault's — never the vault's own, never
/// one in use — and, as there, every such attempt counts against the attempt
/// limit, so this is no free way to test patterns. A phrase that opens nothing
/// is refused before any pattern is looked at.
#[tauri::command]
pub async fn vault_hidden_recover(state: State<'_, AppState>, phrase: String, mut pattern: String) -> Result<HiddenSummary> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    let secret = pattern::secret_bytes(&pattern);
    pattern.zeroize();
    if provider::approved_mode() {
        return Err(QGuardError::InvalidInput(format!(
            "FIPS approved mode: a hidden vault opens with a pattern, and approved mode accepts only a password of at least {} characters in front of vault keys. Turn approved mode off to recover one.",
            provider::APPROVED_PASSWORD_MIN_CHARS
        )));
    }
    let secret = secret?;
    let mut vault = find_by_phrase(&state, phrase).await?;
    let from_lock_screen = state.unlocked_vault_master().is_err();

    let mut record = state
        .load_workspace_scope(&user_id, SCOPE_VAULT)?
        .ok_or_else(|| QGuardError::NotFound("workspace is not configured yet".to_string()))?;
    check_lockout(&record)?;
    check_pattern_pace(&record)?;
    apply_failed_attempt(&mut record);
    record_pattern_miss(&mut record);
    state.save_workspace_scope(&user_id, &record)?;
    if let Some(credential) = record.pattern.as_ref() {
        if matches!(prove(SCOPE_VAULT, credential, &secret).await?, Proof::Right(_)) {
            return Err(QGuardError::InvalidInput(PATTERN_TAKEN.to_string()));
        }
    }

    let secrets = state.hidden_pool_secrets(&user_id)?;
    let vault = tauri::async_runtime::spawn_blocking(move || -> Result<HiddenVault> {
        vault.rekey(HiddenKeys::derive(&secrets, &secret)?)?;
        Ok(vault)
    })
    .await
    .map_err(|e| QGuardError::Crypto(format!("hidden vault worker failed: {e}")))??;
    let summary = vault.summary();
    state.set_hidden_vault(vault)?;
    if from_lock_screen {
        // The same entry as any vault unlock from the lock screen.
        state.audit_info("workspace_unlock", &format!("Workspace {SCOPE_VAULT} unlocked"));
    }
    Ok(summary)
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
    if let Err(e) = validate_for_scope(SCOPE_VAULT, &method, &secret, provider::approved_mode()) {
        secret.zeroize();
        return Err(e);
    }

    // Recovery-key path: prove possession of the recovery key before resetting.
    // The expected verifier comes from the device-local recovery material when
    // this device has it, falling back to the ACCOUNT recovery registry
    // (fetched by the frontend) — so the one account recovery key also unlocks
    // a vault reset on a brand-new device that never stored local material.
    // Only the PUBLIC half of the local recovery record is readable here: the
    // vault is locked, which is the whole reason for this call.
    // Local material that no longer opens (sealed under a storage key this
    // device no longer holds) counts as absent: the account registry still
    // verifies the recovery key, and the dead file goes once the new lock is set.
    let (local_recovery, local_recovery_unreadable) = match state.load_vault_recovery_public(&user_id) {
        Ok(public) => (public, false),
        Err(_) => (None, true),
    };
    // The verified recovery root, kept until the new master exists so the
    // device's recovery secrets can be re-sealed under the NEW vault key.
    let mut verified_root: Option<zeroize::Zeroizing<[u8; KEY_SIZE]>> = None;
    if let Some(ref key) = recovery_key {
        let expected_verifier = match local_recovery.as_ref() {
            Some(public) => public.verifier.clone(),
            None => account_verifier.clone().unwrap_or_default(),
        };
        if expected_verifier.is_empty() {
            secret.zeroize();
            return Err(QGuardError::InvalidInput(
                "No recovery key is configured for this account.".to_string(),
            ));
        }
        let root = match vault_recovery::decode_recovery_key(key) {
            Ok(root) => zeroize::Zeroizing::new(root),
            Err(_) => {
                secret.zeroize();
                return Err(QGuardError::Trust("That recovery key isn't valid.".to_string()));
            }
        };
        let verifier = match vault_recovery::derive_verifier(&root) {
            Ok(verifier) => verifier,
            Err(e) => {
                secret.zeroize();
                return Err(e);
            }
        };
        if verifier != expected_verifier {
            secret.zeroize();
            return Err(QGuardError::Trust(
                "That recovery key doesn't match this account.".to_string(),
            ));
        }
        verified_root = Some(root);
    }

    // Fresh master: a new VMK + new ML-DSA-87 signer, wrapped under the new secret.
    let new_master = PersistedVaultMaster {
        version: 1,
        vmk: symmetric::random_key(),
        signer: VaultSigningKeypair::generate(),
        configured_at: Utc::now(),
    };
    let salt = random_salt();
    let kdf = passcode::preferred_kdf();
    let strong = approved_strength(&method, secret.chars().count(), kdf);
    let stretched = stretch_secret(kdf, salt.clone(), secret.as_bytes().to_vec()).await;
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
        kdf_version: kdf,
        approved_strength: strong,
    };

    let mut record = PersistedWorkspaceScope::new(SCOPE_VAULT);
    *credential_slot(&mut record, &method)? = Some(credential);

    // Legacy keychain VMK (if any) must not linger — the VMK stays password-wrapped.
    state.delete_vault_master_file(&user_id)?;
    state.save_workspace_scope(&user_id, &record)?;
    if local_recovery_unreadable {
        state.delete_vault_recovery(&user_id);
    }

    // The recovery secrets this device held were sealed under the OLD vault key,
    // which is gone with the forgotten secret. Carry them over when the user has
    // just proven they hold the recovery key; otherwise drop them, so the device
    // reports recovery as "not enabled here" instead of claiming a protection it
    // can no longer apply to new files. Enterprise mode holds public keys only
    // and is unaffected. Non-fatal either way: the new lock is already in place.
    let new_vault_key = zeroize::Zeroizing::new(new_master.vault_key()?);
    if let Some(public) = local_recovery.as_ref().filter(|public| public.mode != "enterprise") {
        match verified_root.as_ref() {
            Some(root) => {
                let resealed = reseal_recovery_after_reset(public, root).and_then(|material| {
                    state.save_vault_recovery(&user_id, &material, &new_vault_key)
                });
                if resealed.is_err() {
                    state.delete_vault_recovery(&user_id);
                }
            }
            None => state.delete_vault_recovery(&user_id),
        }
    }
    drop(verified_root);

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
    use crate::crypto::passcode::KDF_LEGACY_HKDF;

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

    /// A lock record that no longer opens must keep the workspace locked and
    /// say why -- it must not fail the whole status call (both workspaces then
    /// never loaded) nor read as "no lock set" (anyone able to corrupt the file
    /// could then set their own lock and walk in).
    #[test]
    fn an_unopenable_lock_record_reports_locked_and_unreadable() {
        let dir = std::env::temp_dir().join(format!("qguard-ws-test-{}", uuid::Uuid::new_v4()));
        let user_id = format!("test-user-{}", uuid::Uuid::new_v4());
        let state = AppState::new(dir.clone()).expect("create state");
        let mut record = PersistedWorkspaceScope::new(SCOPE_CHAT);
        record.pin = Some(WorkspaceCredential {
            salt: random_salt(),
            verifier: "stand-in".to_string(),
            wrapped_master: None,
            kdf_version: KDF_ARGON2ID_V1,
            approved_strength: false,
        });
        state.save_workspace_scope(&user_id, &record).expect("save");

        let readable = status_of_record(&state, &user_id, SCOPE_CHAT);
        assert!(readable.configured && readable.has_pin && !readable.unreadable);
        let absent = status_of_record(&state, &user_id, SCOPE_VAULT);
        assert!(!absent.configured && !absent.unreadable, "no record is not an unreadable one");

        crate::security::keystore::delete_secret(&AppState::safe_user_key(&user_id), &dir)
            .expect("lose the storage key");
        let status = status_of_record(&state, &user_id, SCOPE_CHAT);
        assert!(status.unreadable, "must say the record will not open");
        assert!(status.configured && !status.unlocked, "must stay configured and locked");
        assert!(!status.has_pin && !status.has_password, "must offer no unlock method it cannot check");

        let _ = std::fs::remove_dir_all(&dir);
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

    #[test]
    fn approved_mode_requires_a_fourteen_character_vault_password() {
        // Standard mode: the ordinary rules.
        assert!(validate_for_scope(SCOPE_VAULT, METHOD_PIN, "123456", false).is_ok());
        assert!(validate_for_scope(SCOPE_VAULT, METHOD_PASSWORD, "twelve-chars", false).is_ok());
        // Approved mode: the vault takes a password of 14+ characters only...
        let pin = validate_for_scope(SCOPE_VAULT, METHOD_PIN, "123456789012", true).unwrap_err();
        assert!(format!("{pin}").contains("not a PIN"), "{pin}");
        assert!(validate_for_scope(SCOPE_VAULT, METHOD_PASSWORD, "thirteen-char", true).is_err());
        assert!(validate_for_scope(SCOPE_VAULT, METHOD_PASSWORD, "fourteen-chars", true).is_ok());
        // ...while the Secure Chat lock (a verifier, no key behind it) keeps PINs.
        assert!(validate_for_scope(SCOPE_CHAT, METHOD_PIN, "123456", true).is_ok());
    }

    #[test]
    fn a_vault_pin_is_never_moved_to_pbkdf2() {
        // Standard mode (tests never switch the global policy on): Argon2id
        // for every credential.
        assert_eq!(reseal_target(SCOPE_VAULT, METHOD_PIN), KDF_ARGON2ID_V1);
        assert_eq!(reseal_target(SCOPE_VAULT, METHOD_PASSWORD), passcode::preferred_kdf());
        assert_eq!(reseal_target(SCOPE_CHAT, METHOD_PIN), passcode::preferred_kdf());
    }

    #[test]
    fn approved_strength_needs_pbkdf2_a_password_and_fourteen_characters() {
        use crate::crypto::passcode::KDF_PBKDF2_SHA512_V2;
        assert!(approved_strength(METHOD_PASSWORD, 14, KDF_PBKDF2_SHA512_V2));
        assert!(!approved_strength(METHOD_PASSWORD, 13, KDF_PBKDF2_SHA512_V2));
        assert!(!approved_strength(METHOD_PIN, 12, KDF_PBKDF2_SHA512_V2));
        assert!(!approved_strength(METHOD_PASSWORD, 40, KDF_ARGON2ID_V1));
        assert_eq!(secret_chars("pässwörd".as_bytes()), 8);
    }

    /// A vault credential sealed with Argon2id opens with the same secret after
    /// it is re-sealed under PBKDF2 (approved mode) — and back again.
    #[test]
    fn a_vault_master_survives_reseal_between_argon2id_and_pbkdf2() {
        use crate::crypto::passcode::KDF_PBKDF2_SHA512_V2;
        let master = PersistedVaultMaster {
            version: 1,
            vmk: symmetric::random_key(),
            signer: VaultSigningKeypair::generate(),
            configured_at: Utc::now(),
        };
        let secret = b"a long vault password";
        for (from, to) in [(KDF_ARGON2ID_V1, KDF_PBKDF2_SHA512_V2), (KDF_PBKDF2_SHA512_V2, KDF_ARGON2ID_V1)] {
            let salt = random_salt();
            let ikm = secret_ikm(from, &salt, secret).unwrap();
            let wrapped = wrap_master_under_ikm(&salt, &ikm, &master).unwrap();
            // Unlock under the old KDF...
            let key = derive_vault_wrap_key_from_ikm(&salt, &ikm).unwrap();
            let opened: PersistedVaultMaster = serde_json::from_slice(
                &symmetric::decrypt(&key, &wrapped, &crate::security::obf::workspace_vault_wrap_aad()).unwrap(),
            )
            .unwrap();
            // ...re-seal under the new one, and the same secret opens it.
            let new_salt = random_salt();
            let new_ikm = secret_ikm(to, &new_salt, secret).unwrap();
            let rewrapped = wrap_master_under_ikm(&new_salt, &new_ikm, &opened).unwrap();
            let new_key = derive_vault_wrap_key_from_ikm(&new_salt, &new_ikm).unwrap();
            let reopened: PersistedVaultMaster = serde_json::from_slice(
                &symmetric::decrypt(&new_key, &rewrapped, &crate::security::obf::workspace_vault_wrap_aad()).unwrap(),
            )
            .unwrap();
            assert_eq!(reopened.vmk, master.vmk);
            assert_eq!(reopened.vault_key().unwrap(), master.vault_key().unwrap());
            // The old KDF's key does not open the re-sealed credential.
            assert!(symmetric::decrypt(&key, &rewrapped, &crate::security::obf::workspace_vault_wrap_aad()).is_err());
        }
    }

    const DRAWN: &str = "4x4:0-1-2-3-7-11";

    fn new_master() -> PersistedVaultMaster {
        PersistedVaultMaster { version: 1, vmk: symmetric::random_key(), signer: VaultSigningKeypair::generate(), configured_at: Utc::now() }
    }

    /// A vault credential sealed from `secret` exactly as setup seals one.
    fn sealed_credential(secret: &[u8], master: &PersistedVaultMaster) -> WorkspaceCredential {
        let salt = random_salt();
        let ikm = secret_ikm(KDF_ARGON2ID_V1, &salt, secret).unwrap();
        WorkspaceCredential {
            verifier: derive_verifier_from_ikm(&salt, &ikm).unwrap(),
            wrapped_master: Some(wrap_master_under_ikm(&salt, &ikm, master).unwrap()),
            salt,
            kdf_version: KDF_ARGON2ID_V1,
            approved_strength: false,
        }
    }

    #[test]
    fn a_pattern_is_a_vault_credential_held_to_the_pin_rules() {
        assert!(validate_for_scope(SCOPE_VAULT, METHOD_PATTERN, DRAWN, false).is_ok());
        assert!(validate_for_scope(SCOPE_VAULT, METHOD_PATTERN, "4x4:0-1-2-3-7", false).is_err(), "five dots");
        assert!(validate_for_scope(SCOPE_CHAT, METHOD_PATTERN, DRAWN, false).is_err(), "vault only");
        // Approved mode keeps the vault behind a 14+ character password.
        assert!(validate_for_scope(SCOPE_VAULT, METHOD_PATTERN, DRAWN, true).is_err());
        let mut record = PersistedWorkspaceScope::new(SCOPE_VAULT);
        assert!(!record.configured());
        *credential_slot(&mut record, METHOD_PATTERN).unwrap() = Some(WorkspaceCredential::default());
        assert!(record.configured() && credential_for(&record, METHOD_PATTERN).is_some());
    }

    #[test]
    fn pattern_tries_are_paced_and_no_success_resets_the_pace() {
        let mut scope = PersistedWorkspaceScope::new(SCOPE_VAULT);
        for _ in 0..4 {
            record_pattern_miss(&mut scope);
            assert!(check_pattern_pace(&scope).is_ok(), "the first misses of a day are free");
        }
        record_pattern_miss(&mut scope);
        assert!(check_pattern_pace(&scope).is_err(), "the fifth means a pause");
        // A correct password clears the attempt ladder — and not the pace.
        scope.failed_attempts = 0;
        scope.lockout_until = None;
        assert!(check_pattern_pace(&scope).is_err());
        // Misses age out after 24 hours instead.
        scope.pattern_misses = scope.pattern_misses.iter().map(|at| *at - chrono::Duration::hours(25)).collect();
        assert!(check_pattern_pace(&scope).is_ok());
        assert!(recent_pattern_misses(&scope, Utc::now()).is_empty());
        assert_eq!(pattern_wait(9), Some(chrono::Duration::seconds(30)));
        assert_eq!(pattern_wait(20), Some(chrono::Duration::hours(1)));
    }

    #[test]
    fn the_drawn_pattern_and_no_other_unwraps_the_vault_master() {
        let master = new_master();
        let credential = sealed_credential(&pattern::secret_bytes(DRAWN).unwrap(), &master);
        let right = tauri::async_runtime::block_on(prove(SCOPE_VAULT, &credential, &pattern::secret_bytes(DRAWN).unwrap())).unwrap();
        match right {
            Proof::Right(Some(opened)) => assert_eq!(opened.vmk, master.vmk),
            _ => panic!("the drawn pattern must open the vault"),
        }
        let other = pattern::secret_bytes("4x4:0-1-2-3-7-6").unwrap();
        assert!(matches!(tauri::async_runtime::block_on(prove(SCOPE_VAULT, &credential, &other)).unwrap(), Proof::Wrong));
    }

    #[test]
    fn only_one_vault_is_ever_open_and_every_lock_closes_a_hidden_one() {
        let dir = std::env::temp_dir().join(format!("qguard-ws-test-{}", uuid::Uuid::new_v4()));
        let user_id = format!("test-user-{}", uuid::Uuid::new_v4());
        let state = AppState::new(dir.clone()).expect("create state");
        let keys = |state: &AppState| {
            HiddenKeys::derive(&state.hidden_pool_secrets(&user_id).unwrap(), &pattern::secret_bytes(DRAWN).unwrap()).unwrap()
        };
        let vault = HiddenVault::create(state.hidden_pool(&user_id), &user_id, keys(&state)).unwrap();

        state.set_vault_session(new_master()).unwrap();
        state.mark_workspace_unlocked(SCOPE_VAULT).unwrap();
        state.set_hidden_vault(vault).unwrap();
        assert!(state.is_hidden_vault_open());
        assert!(state.unlocked_vault_master().is_err(), "opening a hidden vault locks the Quantum Vault");
        assert!(!state.is_workspace_unlocked(SCOPE_VAULT));

        state.lock_all_workspaces();
        assert!(!state.is_hidden_vault_open(), "locking everything closes it");

        // A restart re-derives the same device half of the key.
        let restarted = AppState::new(dir.clone()).expect("restart");
        let reopened = HiddenVault::open(restarted.hidden_pool(&user_id), &user_id, keys(&restarted)).unwrap().expect("opens again");
        restarted.set_hidden_vault(reopened).unwrap();
        restarted.set_vault_session(new_master()).unwrap();
        assert!(!restarted.is_hidden_vault_open(), "unlocking the Quantum Vault closes it");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
