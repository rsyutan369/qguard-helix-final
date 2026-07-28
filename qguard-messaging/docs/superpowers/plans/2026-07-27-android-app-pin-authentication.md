# Banking-Grade App-Entry PIN Authentication (Android) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the QGuard Messaging Android build a banking-app login experience: sign in with email/password once, then unlock the app with a 4- or 6-digit PIN on every launch, restoring the stored session.

**Architecture:** A new Rust `applock` module stores the Supabase session inside a PIN-bound envelope — the session is encrypted under a random Session Encryption Key (SEK), the SEK is wrapped under a PIN-derived key (Argon2id → HKDF-SHA3-256), and the whole config is additionally encrypted at rest under the existing hardware-backed Android Keystore DEK. The frontend gates the app on Android (unlock/setup screens) above the existing login/paywall/workspace-lock chain and restores the session via `supabase.auth.setSession()`.

**Tech Stack:** Rust (Tauri 2, argon2, hkdf, sha3, aes-gcm via existing `crypto` module, jni), React + TypeScript + Vite + Tailwind, Supabase (Postgres + RLS), Kotlin (Android native).

## Global Constraints

- **Android only.** All new gating/hardening is guarded by `isAndroidRuntime()` (frontend) or `#[cfg(target_os = "android")]`-agnostic commands that simply report `configured:false` on desktop. Desktop login/paywall/workspace-lock behavior is unchanged.
- **No `FLAG_SECURE`.** Screenshots must keep working. Do not set `WindowManager.LayoutParams.FLAG_SECURE`. (Explicit product decision.)
- **Stay on `main`.** Commit directly to `main`; do not create a feature branch.
- **PIN policy:** exactly 4 or 6 digits, all ASCII digits.
- **Anti-brute-force ladder (max 5):** attempts 1–2 immediate; 3rd failure → 5 s lockout; 4th → 15 s; **5th failure → wipe stored session, require full email/password login**. Successful full auth resets the counter.
- **PQC/crypto:** reuse the existing `crypto` primitives (AES-256-GCM `symmetric`, HKDF-SHA3-256 `kdf`, Argon2id parameters 64 MiB / 3 / 1). Never store the PIN or session in plaintext. Never duplicate the Argon2id/HKDF/verifier logic — share it.
- **Zeroize** every derived key / IKM / plaintext buffer after use (`zeroize::Zeroize`), matching `workspace.rs`.
- **Auth storage stays `sessionStorage`** (existing `supabase.ts`). It is already non-durable across Android restarts, so tokens never land on durable WebView disk; durable persistence is owned by Rust (encrypted). Do **not** switch to `persistSession:false` — it is unnecessary and risks desktop regressions.
- **Spec:** `qguard-messaging/docs/superpowers/specs/2026-07-27-android-app-pin-authentication-design.md`.

---

### Task 1: Shared passcode crypto module + workspace refactor (DRY)

Extract the Argon2id/HKDF/verifier primitives currently private to `workspace.rs` into a reusable `crypto::passcode` module so `applock` can share them. `workspace.rs` keeps thin local wrappers so its existing tests stay green.

**Files:**
- Create: `src-tauri/src/crypto/passcode.rs`
- Modify: `src-tauri/src/crypto/mod.rs` (add `pub mod passcode;`)
- Modify: `src-tauri/src/commands/workspace.rs:96-159` (delete moved helpers; add thin wrappers)

**Interfaces:**
- Produces:
  - `crypto::passcode::KDF_LEGACY_HKDF: u8 = 0`
  - `crypto::passcode::KDF_ARGON2ID_V1: u8 = 1`
  - `crypto::passcode::random_salt() -> Vec<u8>`
  - `crypto::passcode::argon2id_prehash(salt: &[u8], secret: &[u8]) -> Result<[u8;32]>`
  - `crypto::passcode::secret_ikm(kdf_version: u8, salt: &[u8], secret: &[u8]) -> Result<Vec<u8>>`
  - `crypto::passcode::stretch_secret(kdf_version: u8, salt: Vec<u8>, secret: Vec<u8>) -> Result<Vec<u8>>` (async, `spawn_blocking`)
  - `crypto::passcode::derive_verifier(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<String>`
  - `crypto::passcode::derive_wrap_key(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8;32]>`

- [ ] **Step 1: Create `crypto/passcode.rs`**

```rust
//! Shared passcode-unlock primitives: memory-hard secret stretching (Argon2id)
//! plus HKDF-SHA3-256 verifier/wrap-key derivation. Used by both the workspace
//! lock (`commands::workspace`) and the app-entry PIN (`commands::applock`) so
//! the hardened KDF logic lives in exactly one place.

use zeroize::Zeroize;

use crate::crypto::kdf::{derive_32_with_salt, sha3_hex};
use crate::crypto::symmetric::KEY_SIZE;
use crate::error::{QGuardError, Result};

/// KDF versions for stored unlock credentials.
pub const KDF_LEGACY_HKDF: u8 = 0;
pub const KDF_ARGON2ID_V1: u8 = 1;

/// Argon2id parameters: 64 MiB, 3 passes, 1 lane (OWASP-recommended class).
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_LANES: u32 = 1;

pub fn random_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt.to_vec()
}

/// Memory-hard Argon2id prehash of the unlock secret.
pub fn argon2id_prehash(salt: &[u8], secret: &[u8]) -> Result<[u8; 32]> {
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

/// Input keying material every HKDF subkey is derived from. Legacy (v0) feeds
/// the raw secret straight into HKDF (pre-upgrade credentials); v1 prehashes
/// with Argon2id first.
pub fn secret_ikm(kdf_version: u8, salt: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    match kdf_version {
        KDF_LEGACY_HKDF => Ok(secret.to_vec()),
        KDF_ARGON2ID_V1 => Ok(argon2id_prehash(salt, secret)?.to_vec()),
        other => Err(QGuardError::Crypto(format!(
            "unlock credential uses unsupported KDF version {other}; update QGuard Messaging"
        ))),
    }
}

/// Run the (deliberately slow, memory-hard) secret stretch on the blocking pool
/// so it never freezes the main thread.
pub async fn stretch_secret(kdf_version: u8, salt: Vec<u8>, mut secret: Vec<u8>) -> Result<Vec<u8>> {
    tauri::async_runtime::spawn_blocking(move || {
        let ikm = secret_ikm(kdf_version, &salt, &secret);
        secret.zeroize();
        ikm
    })
    .await
    .map_err(|e| QGuardError::Crypto(format!("secret stretch worker failed: {e}")))?
}

/// Verifier (hash of an independent HKDF subkey) — validates a re-entered secret
/// without revealing any unlock key. `info` is the domain-separation context.
pub fn derive_verifier(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<String> {
    let mut k = derive_32_with_salt(salt, ikm, info)?;
    let verifier = sha3_hex(&k);
    k.zeroize();
    Ok(verifier)
}

/// A 32-byte wrap key (distinct HKDF context from the verifier).
pub fn derive_wrap_key(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; KEY_SIZE]> {
    derive_32_with_salt(salt, ikm, info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ikm_versions_are_domain_separated() {
        let salt = random_salt();
        let secret = b"correct horse battery staple";
        let legacy = secret_ikm(KDF_LEGACY_HKDF, &salt, secret).unwrap();
        assert_eq!(legacy, secret.to_vec());
        let hardened = secret_ikm(KDF_ARGON2ID_V1, &salt, secret).unwrap();
        assert_eq!(hardened, secret_ikm(KDF_ARGON2ID_V1, &salt, secret).unwrap());
        assert_ne!(hardened, legacy);
        assert!(secret_ikm(99, &salt, secret).is_err());
    }

    #[test]
    fn verifier_is_deterministic_and_context_separated() {
        let salt = random_salt();
        let ikm = secret_ikm(KDF_ARGON2ID_V1, &salt, b"pin-123456").unwrap();
        let a = derive_verifier(&salt, &ikm, b"context-a").unwrap();
        assert_eq!(a, derive_verifier(&salt, &ikm, b"context-a").unwrap());
        assert_ne!(a, derive_verifier(&salt, &ikm, b"context-b").unwrap());
    }
}
```

- [ ] **Step 2: Register the module in `crypto/mod.rs`**

Add after the existing `pub mod kdf;` line (line 2):

```rust
pub mod passcode;
```

- [ ] **Step 3: Run the new module's tests (they should pass)**

Run: `cd src-tauri && cargo test -p qguard-messaging passcode:: 2>&1 | tail -20`
Expected: the two `passcode::tests::*` tests PASS. (Crate name is whatever `Cargo.toml` `[package] name` is — if the `-p` flag errors, use `cargo test passcode::`.)

- [ ] **Step 4: Refactor `workspace.rs` to delegate to `passcode` (remove duplication)**

In `src-tauri/src/commands/workspace.rs`, replace the block from the `KDF versions` comment through `derive_vault_wrap_key_from_ikm` (lines ~96–159) with thin wrappers, and add the import near the top imports:

```rust
use crate::crypto::passcode::{self, KDF_ARGON2ID_V1, KDF_LEGACY_HKDF};
```

Delete these now-moved items from `workspace.rs`: the `KDF_LEGACY_HKDF`/`KDF_ARGON2ID_V1` consts, `ARGON2_MEMORY_KIB`/`ARGON2_ITERATIONS`/`ARGON2_LANES` consts, `argon2id_prehash`, `secret_ikm`, `stretch_secret`, `random_salt`. Replace `derive_verifier_from_ikm` and `derive_vault_wrap_key_from_ikm` with wrappers that keep the same names/signatures used elsewhere in the file:

```rust
fn random_salt() -> Vec<u8> {
    passcode::random_salt()
}

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
```

Remove the now-unused imports from `workspace.rs` if the compiler flags them (`use crate::crypto::kdf::{derive_32_with_salt, sha3_hex};` may become unused — delete only what `cargo build` reports as unused; keep `KEY_SIZE` since the wrapper returns it).

- [ ] **Step 5: Verify the whole workspace suite still passes (refactor safety net)**

Run: `cd src-tauri && cargo test workspace:: 2>&1 | tail -30`
Expected: all existing `workspace::tests::*` tests PASS (verifier determinism, KDF domain separation, vault unwrap, legacy upgrade, anti-bruteforce ladder, secret validation).

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/crypto/passcode.rs src-tauri/src/crypto/mod.rs src-tauri/src/commands/workspace.rs
git commit -m "refactor: extract shared passcode KDF primitives into crypto::passcode

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: AppLock domain-separation tags

Add four obfuscated domain-separation tags to `obf.rs` (matching the existing pattern) for the applock verifier, SEK wrap, session wrap AAD, and at-rest material AAD.

**Files:**
- Modify: `src-tauri/src/security/obf.rs`

**Interfaces:**
- Produces:
  - `security::obf::applock_verifier_info() -> Vec<u8>` → `b"QGuard-AppLock-Verifier-v1"`
  - `security::obf::applock_sek_wrap_info() -> Vec<u8>` → `b"QGuard-AppLock-SEK-Wrap-v1"`
  - `security::obf::applock_session_wrap_aad() -> Vec<u8>` → `b"QGuard-AppLock-Session-Wrap-v1"`
  - `security::obf::applock_material_aad() -> Vec<u8>` → `b"QGuard-AppLock-Material-v1"`

- [ ] **Step 1: Generate the obfuscated byte arrays**

Run this from the repo root (`node` is available in this project):

```bash
node -e '
const OBF_KEY=[90,54,193,158,123,18,228,141,64,169,63,102,210,27,247,136,44,85,144,174,99,7,188,65,153,224,20,125,202,54,82,251];
const tags=["QGuard-AppLock-Verifier-v1","QGuard-AppLock-SEK-Wrap-v1","QGuard-AppLock-Session-Wrap-v1","QGuard-AppLock-Material-v1"];
for(const s of tags){const b=Buffer.from(s,"utf8");console.log(s+"\n[" + [...b].map((x,i)=>x^OBF_KEY[i%32]).join(", ") + "]\n");}
'
```

Copy the four printed arrays into Step 2 (replace the `/* GEN: ... */` placeholders with the exact printed numbers).

- [ ] **Step 2: Add the constants and accessors to `obf.rs`**

Insert after the `WORKSPACE_MATERIAL_AAD` accessor (around line 53), using the arrays generated in Step 1:

```rust
const APPLOCK_VERIFIER_INFO: &[u8] = &[/* GEN: QGuard-AppLock-Verifier-v1 */];
pub fn applock_verifier_info() -> Vec<u8> { deobf(APPLOCK_VERIFIER_INFO) }

const APPLOCK_SEK_WRAP_INFO: &[u8] = &[/* GEN: QGuard-AppLock-SEK-Wrap-v1 */];
pub fn applock_sek_wrap_info() -> Vec<u8> { deobf(APPLOCK_SEK_WRAP_INFO) }

const APPLOCK_SESSION_WRAP_AAD: &[u8] = &[/* GEN: QGuard-AppLock-Session-Wrap-v1 */];
pub fn applock_session_wrap_aad() -> Vec<u8> { deobf(APPLOCK_SESSION_WRAP_AAD) }

const APPLOCK_MATERIAL_AAD: &[u8] = &[/* GEN: QGuard-AppLock-Material-v1 */];
pub fn applock_material_aad() -> Vec<u8> { deobf(APPLOCK_MATERIAL_AAD) }
```

- [ ] **Step 3: Add round-trip assertions to the obf test**

Inside `mod tests` → `obfuscated_values_round_trip_to_exact_plaintext`, add after the `workspace_material_aad` assertion:

```rust
        assert_eq!(applock_verifier_info(), b"QGuard-AppLock-Verifier-v1".to_vec());
        assert_eq!(applock_sek_wrap_info(), b"QGuard-AppLock-SEK-Wrap-v1".to_vec());
        assert_eq!(applock_session_wrap_aad(), b"QGuard-AppLock-Session-Wrap-v1".to_vec());
        assert_eq!(applock_material_aad(), b"QGuard-AppLock-Material-v1".to_vec());
```

- [ ] **Step 4: Verify the round-trip test passes (proves the generated bytes are correct)**

Run: `cd src-tauri && cargo test obf:: 2>&1 | tail -20`
Expected: `obfuscated_values_round_trip_to_exact_plaintext` PASSES. If it fails, the generated arrays in Step 2 are wrong — re-run Step 1.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/security/obf.rs
git commit -m "feat: add applock domain-separation tags to obf

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: AppLock persistence types + AppState

Add the persisted config types, the encrypted save/load/delete, and the in-memory SEK holder to `AppState`.

**Files:**
- Modify: `src-tauri/src/state.rs` (add structs near `PersistedWorkspaceScope` ~line 153; add fields to `AppState` struct ~line 203 and `new()` ~line 229; add methods near the workspace-scope helpers ~line 733)

**Interfaces:**
- Produces (in `crate::state`):
  - `struct DeviceRegistration { device_id: String, device_name: String, platform: String, app_version: String, registered_at: DateTime<Utc>, last_login_at: DateTime<Utc> }` (Clone, Debug, Serialize, Deserialize; camelCase)
  - `struct StoredSession { access_token: String, refresh_token: String, expires_at: i64, user_id: String, email: String }` (Clone, Debug, Serialize, Deserialize; camelCase)
  - `struct PersistedAppLock { version: u8, enabled: bool, digits: u8, kdf_version: u8, salt: Vec<u8>, verifier: String, sek_wrapped_by_pin: EncryptedEnvelope, session_wrapped_by_sek: EncryptedEnvelope, failed_attempts: u32, lockout_until: Option<DateTime<Utc>>, inactivity_minutes: u32, device: DeviceRegistration, created_at: DateTime<Utc> }` (Clone, Debug, Serialize, Deserialize)
  - `AppState::save_applock(&self, user_id: &str, material: &PersistedAppLock) -> Result<()>`
  - `AppState::load_applock(&self, user_id: &str) -> Result<Option<PersistedAppLock>>`
  - `AppState::delete_applock(&self, user_id: &str) -> Result<()>`
  - `AppState::set_applock_sek(&self, sek: [u8;32]) -> Result<()>`
  - `AppState::take_applock_sek(&self) -> Option<[u8;32]>` (clone of the current SEK; None when locked)
  - `AppState::clear_applock_sek(&self)` (zeroize + drop)
  - `AppState::is_applock_unlocked(&self) -> bool`

- [ ] **Step 1: Add the types** (after `PersistedWorkspaceScope`'s `impl`, ~line 171)

```rust
/// A trusted-device registration record (banking-style device binding).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRegistration {
    pub device_id: String,
    pub device_name: String,
    pub platform: String,
    pub app_version: String,
    pub registered_at: chrono::DateTime<Utc>,
    pub last_login_at: chrono::DateTime<Utc>,
}

/// The Supabase session the app-entry PIN restores. Serialized, encrypted under
/// the SEK, and never stored in plaintext.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredSession {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub user_id: String,
    pub email: String,
}

/// Device-local, encrypted-at-rest app-entry PIN state. The session is wrapped
/// under a random SEK; the SEK is wrapped under the PIN-derived key. The whole
/// struct is then encrypted at rest under the hardware-backed device DEK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedAppLock {
    pub version: u8,
    pub enabled: bool,
    pub digits: u8,
    pub kdf_version: u8,
    pub salt: Vec<u8>,
    pub verifier: String,
    pub sek_wrapped_by_pin: crate::crypto::EncryptedEnvelope,
    pub session_wrapped_by_sek: crate::crypto::EncryptedEnvelope,
    pub failed_attempts: u32,
    pub lockout_until: Option<chrono::DateTime<Utc>>,
    pub inactivity_minutes: u32,
    pub device: DeviceRegistration,
    pub created_at: chrono::DateTime<Utc>,
}
```

- [ ] **Step 2: Add the in-memory SEK field to `AppState`** (in the struct definition, after `workspace_unlocked` ~line 203)

```rust
    /// In-memory Session Encryption Key while the app is PIN-unlocked (None =
    /// locked). Zeroized on lock / background / sign-out.
    pub applock_sek: Mutex<Option<[u8; crate::crypto::symmetric::KEY_SIZE]>>,
```

And initialize it in `new()` (after `workspace_unlocked: Mutex::new(HashSet::new()),` ~line 229):

```rust
            applock_sek: Mutex::new(None),
```

- [ ] **Step 3: Add persistence + SEK methods** (after `load_workspace_scope`, near line 780)

```rust
    // ---- App-entry PIN (applock) ------------------------------------------

    fn applock_path(&self, user_id: &str) -> PathBuf {
        let safe_user_id = Self::safe_user_key(user_id);
        self.data_dir
            .join("keys")
            .join(format!("{safe_user_id}.applock.enc"))
    }

    pub fn save_applock(&self, user_id: &str, material: &PersistedAppLock) -> Result<()> {
        let encoded = serde_json::to_vec(material)
            .map_err(|e| QGuardError::Storage(format!("encode applock: {e}")))?;
        let key = self.device_storage_key(user_id)?;
        let envelope = crate::crypto::symmetric::encrypt(
            &key,
            &encoded,
            &crate::security::obf::applock_material_aad(),
        )?;
        let file = EncryptedKeyMaterialFile { version: 1, envelope };
        let serialized = serde_json::to_vec(&file)
            .map_err(|e| QGuardError::Storage(format!("encode encrypted applock: {e}")))?;
        std::fs::write(self.applock_path(user_id), &serialized)
            .map_err(|e| QGuardError::Storage(format!("write applock: {e}")))?;
        Ok(())
    }

    pub fn load_applock(&self, user_id: &str) -> Result<Option<PersistedAppLock>> {
        let path = self.applock_path(user_id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)
            .map_err(|e| QGuardError::Storage(format!("read applock: {e}")))?;
        let file: EncryptedKeyMaterialFile = serde_json::from_slice(&bytes)
            .map_err(|e| QGuardError::Storage(format!("decode applock file: {e}")))?;
        let key = self.device_storage_key(user_id)?;
        let mut plaintext = crate::crypto::symmetric::decrypt(
            &key,
            &file.envelope,
            &crate::security::obf::applock_material_aad(),
        )?;
        let material: PersistedAppLock = serde_json::from_slice(&plaintext)
            .map_err(|e| QGuardError::Storage(format!("decode applock payload: {e}")))?;
        plaintext.zeroize();
        Ok(Some(material))
    }

    pub fn delete_applock(&self, user_id: &str) -> Result<()> {
        let path = self.applock_path(user_id);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| QGuardError::Storage(format!("delete applock: {e}")))?;
        }
        self.clear_applock_sek();
        Ok(())
    }

    pub fn set_applock_sek(&self, sek: [u8; crate::crypto::symmetric::KEY_SIZE]) -> Result<()> {
        let mut guard = self
            .applock_sek
            .lock()
            .map_err(|_| QGuardError::Storage("applock sek lock poisoned".to_string()))?;
        *guard = Some(sek);
        Ok(())
    }

    pub fn take_applock_sek(&self) -> Option<[u8; crate::crypto::symmetric::KEY_SIZE]> {
        self.applock_sek.lock().ok().and_then(|guard| *guard)
    }

    pub fn clear_applock_sek(&self) {
        if let Ok(mut guard) = self.applock_sek.lock() {
            if let Some(mut sek) = guard.take() {
                sek.zeroize();
            }
        }
    }

    pub fn is_applock_unlocked(&self) -> bool {
        self.applock_sek
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }
```

- [ ] **Step 4: Verify it compiles**

Run: `cd src-tauri && cargo build 2>&1 | tail -20`
Expected: builds with no errors (warnings about unused `save_applock`/`load_applock` are fine — Task 4 uses them).

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/state.rs
git commit -m "feat: add applock persistence types and in-memory SEK to AppState

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: AppLock commands

The Tauri command surface: status, setup, unlock, update-session, lock, change-pin, remove, reset, set-inactivity, device-integrity, wipe. Crypto/ladder logic lives in free helper functions that are unit-tested (Tauri `State` commands are thin wrappers, mirroring `workspace.rs`).

**Files:**
- Create: `src-tauri/src/commands/applock.rs`
- Modify: `src-tauri/src/commands/mod.rs` (add `pub mod applock;`)
- Modify: `src-tauri/src/lib.rs` (add `use commands::applock::*;` and register the commands)

**Interfaces:**
- Consumes: `crypto::passcode::*` (Task 1), `security::obf::applock_*` (Task 2), `state::{PersistedAppLock, DeviceRegistration, StoredSession}` + persistence/SEK methods (Task 3), `crypto::symmetric::{encrypt, decrypt, random_key, KEY_SIZE}`, `crypto::EncryptedEnvelope`.
- Produces (Tauri commands, camelCase args):
  - `applock_status() -> AppLockStatus`
  - `applock_setup(digits: u8, pin: String, session: StoredSession, deviceName: String, appVersion: String) -> AppLockStatus`
  - `applock_unlock(pin: String) -> AppLockUnlockResult`
  - `applock_update_session(session: StoredSession) -> ()`
  - `applock_lock() -> ()`
  - `applock_change_pin(oldPin: String, newPin: String, digits: u8) -> AppLockStatus`
  - `applock_remove() -> ()`
  - `applock_reset(digits: u8, pin: String, session: StoredSession, deviceName: String, appVersion: String) -> AppLockStatus`
  - `applock_set_inactivity(minutes: u32) -> AppLockStatus`
  - `applock_device_integrity() -> DeviceIntegrity`
  - `applock_wipe() -> ()`
  - `struct AppLockStatus { configured, enabled, locked, digits, failedAttempts, attemptsRemaining, lockoutUntil: Option<String>, inactivityMinutes, device: Option<DeviceRegistration>, requiresFullAuth }`
  - `struct AppLockUnlockResult { session: Option<StoredSession>, status: AppLockStatus }` — `session` is `None` only when the 5th wrong attempt wiped the store; `status.requiresFullAuth` is then `true`. A non-final wrong PIN returns `Err` (so the UI shows "incorrect, N remaining").
  - `struct DeviceIntegrity { rooted: bool, emulator: bool, signals: Vec<String> }`

- [ ] **Step 1: Write the failing helper tests** — create `src-tauri/src/commands/applock.rs` with only the helpers + tests first:

```rust
//! Banking-grade app-entry PIN (Android). Sign in once with email/password,
//! then unlock the app with a 4/6-digit PIN which restores the locally stored
//! Supabase session. The session is encrypted under a random SEK; the SEK is
//! wrapped under a PIN-derived key (Argon2id -> HKDF-SHA3-256); the whole
//! config is encrypted at rest under the hardware-backed device DEK.
//!
//! Anti-brute-force: 3rd fail -> 5s, 4th -> 15s, 5th fail -> wipe the stored
//! session and require full email/password login.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;

use crate::crypto::passcode::{self, KDF_ARGON2ID_V1};
use crate::crypto::symmetric::{self, KEY_SIZE};
use crate::crypto::EncryptedEnvelope;
use crate::error::{QGuardError, Result};
use crate::state::{AppState, DeviceRegistration, PersistedAppLock, StoredSession};

const MAX_ATTEMPTS: u32 = 5;
const DEFAULT_INACTIVITY_MINUTES: u32 = 10;
const MIN_INACTIVITY_MINUTES: u32 = 1;
const MAX_INACTIVITY_MINUTES: u32 = 60;

fn validate_pin(digits: u8, pin: &str) -> Result<()> {
    if digits != 4 && digits != 6 {
        return Err(QGuardError::InvalidInput("PIN length must be 4 or 6 digits.".to_string()));
    }
    if pin.chars().count() != digits as usize || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err(QGuardError::InvalidInput(format!("PIN must be exactly {digits} digits.")));
    }
    Ok(())
}

fn clamp_inactivity(minutes: u32) -> u32 {
    minutes.clamp(MIN_INACTIVITY_MINUTES, MAX_INACTIVITY_MINUTES)
}

/// Delay (seconds) enforced *before* the next attempt after `failed_attempts`
/// failures. 0 = no delay. 5th failure never returns a delay — the caller wipes.
fn lockout_delay_secs(failed_attempts: u32) -> i64 {
    match failed_attempts {
        3 => 5,
        4 => 15,
        _ => 0,
    }
}

fn attempts_remaining(failed_attempts: u32) -> u32 {
    MAX_ATTEMPTS.saturating_sub(failed_attempts)
}

/// Build the PIN-derived verifier + the SEK wrapped under the PIN key.
/// Returns (salt, verifier, sek_wrapped_by_pin).
async fn seal_pin(
    pin: &str,
    sek: &[u8; KEY_SIZE],
) -> Result<(Vec<u8>, String, EncryptedEnvelope)> {
    let salt = passcode::random_salt();
    let mut ikm = passcode::stretch_secret(KDF_ARGON2ID_V1, salt.clone(), pin.as_bytes().to_vec()).await?;
    let verifier = passcode::derive_verifier(&salt, &ikm, &crate::security::obf::applock_verifier_info());
    let verifier = match verifier {
        Ok(v) => v,
        Err(e) => {
            ikm.zeroize();
            return Err(e);
        }
    };
    let wrap_key = passcode::derive_wrap_key(&salt, &ikm, &crate::security::obf::applock_sek_wrap_info());
    ikm.zeroize();
    let mut wrap_key = wrap_key?;
    let wrapped = symmetric::encrypt(&wrap_key, sek, &crate::security::obf::applock_material_aad());
    wrap_key.zeroize();
    Ok((salt, verifier, wrapped?))
}

/// Verify a PIN against a stored record and, on success, recover the SEK.
async fn open_with_pin(record: &PersistedAppLock, pin: &str) -> Result<[u8; KEY_SIZE]> {
    let mut ikm = passcode::stretch_secret(record.kdf_version, record.salt.clone(), pin.as_bytes().to_vec()).await?;
    let verifier = passcode::derive_verifier(&record.salt, &ikm, &crate::security::obf::applock_verifier_info());
    let verifier = match verifier {
        Ok(v) => v,
        Err(e) => {
            ikm.zeroize();
            return Err(e);
        }
    };
    if verifier != record.verifier {
        ikm.zeroize();
        return Err(QGuardError::Trust("Incorrect PIN.".to_string()));
    }
    let wrap_key = passcode::derive_wrap_key(&record.salt, &ikm, &crate::security::obf::applock_sek_wrap_info());
    ikm.zeroize();
    let mut wrap_key = wrap_key?;
    let sek_bytes = symmetric::decrypt(&wrap_key, &record.sek_wrapped_by_pin, &crate::security::obf::applock_material_aad());
    wrap_key.zeroize();
    let mut sek_bytes = sek_bytes?;
    if sek_bytes.len() != KEY_SIZE {
        sek_bytes.zeroize();
        return Err(QGuardError::Crypto("recovered SEK has wrong length".to_string()));
    }
    let mut sek = [0u8; KEY_SIZE];
    sek.copy_from_slice(&sek_bytes);
    sek_bytes.zeroize();
    Ok(sek)
}

fn wrap_session_under_sek(sek: &[u8; KEY_SIZE], session: &StoredSession) -> Result<EncryptedEnvelope> {
    let mut serialized = serde_json::to_vec(session)
        .map_err(|e| QGuardError::Storage(format!("encode session: {e}")))?;
    let wrapped = symmetric::encrypt(sek, &serialized, &crate::security::obf::applock_session_wrap_aad());
    serialized.zeroize();
    wrapped
}

fn unwrap_session_from_sek(sek: &[u8; KEY_SIZE], envelope: &EncryptedEnvelope) -> Result<StoredSession> {
    let mut plaintext = symmetric::decrypt(sek, envelope, &crate::security::obf::applock_session_wrap_aad())?;
    let session = serde_json::from_slice(&plaintext)
        .map_err(|e| QGuardError::Storage(format!("decode session: {e}")));
    plaintext.zeroize();
    session
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_session() -> StoredSession {
        StoredSession {
            access_token: "access-token-xyz".to_string(),
            refresh_token: "refresh-token-abc".to_string(),
            expires_at: 4102444800,
            user_id: "user-1".to_string(),
            email: "u@example.com".to_string(),
        }
    }

    #[tokio::test]
    async fn correct_pin_recovers_session_wrong_pin_fails() {
        let sek = symmetric::random_key();
        let (salt, verifier, sek_wrapped) = seal_pin("123456", &sek).await.unwrap();
        let session = sample_session();
        let session_wrapped = wrap_session_under_sek(&sek, &session).unwrap();
        let record = PersistedAppLock {
            version: 1, enabled: true, digits: 6, kdf_version: KDF_ARGON2ID_V1,
            salt, verifier, sek_wrapped_by_pin: sek_wrapped, session_wrapped_by_sek: session_wrapped,
            failed_attempts: 0, lockout_until: None, inactivity_minutes: 10,
            device: DeviceRegistration {
                device_id: "d1".into(), device_name: "Tablet".into(), platform: "android".into(),
                app_version: "1.0.0".into(), registered_at: Utc::now(), last_login_at: Utc::now(),
            },
            created_at: Utc::now(),
        };

        let recovered_sek = open_with_pin(&record, "123456").await.unwrap();
        let recovered = unwrap_session_from_sek(&recovered_sek, &record.session_wrapped_by_sek).unwrap();
        assert_eq!(recovered.access_token, session.access_token);
        assert_eq!(recovered.refresh_token, session.refresh_token);

        assert!(open_with_pin(&record, "000000").await.is_err());
    }

    #[test]
    fn pin_validation_enforces_4_or_6_digits() {
        assert!(validate_pin(4, "1234").is_ok());
        assert!(validate_pin(6, "123456").is_ok());
        assert!(validate_pin(4, "123").is_err());
        assert!(validate_pin(6, "12345").is_err());
        assert!(validate_pin(6, "12345a").is_err());
        assert!(validate_pin(5, "12345").is_err());
    }

    #[test]
    fn ladder_delays_and_attempts_remaining() {
        assert_eq!(lockout_delay_secs(1), 0);
        assert_eq!(lockout_delay_secs(2), 0);
        assert_eq!(lockout_delay_secs(3), 5);
        assert_eq!(lockout_delay_secs(4), 15);
        assert_eq!(attempts_remaining(0), 5);
        assert_eq!(attempts_remaining(4), 1);
        assert_eq!(attempts_remaining(5), 0);
    }
}
```

- [ ] **Step 2: Run the helper tests to verify they pass**

Run: `cd src-tauri && cargo test applock:: 2>&1 | tail -25`
Expected: `correct_pin_recovers_session_wrong_pin_fails`, `pin_validation_enforces_4_or_6_digits`, `ladder_delays_and_attempts_remaining` PASS. (If `tokio::test` is unavailable, confirm `tokio` is a dev-dependency; the crate already uses async — if needed add `tokio = { version = "1", features = ["macros","rt"] }` under `[dev-dependencies]` in `src-tauri/Cargo.toml`.)

- [ ] **Step 3: Add the status builder + commands** — append to `applock.rs` (before `#[cfg(test)]`):

```rust
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppLockStatus {
    pub configured: bool,
    pub enabled: bool,
    pub locked: bool,
    pub digits: u8,
    pub failed_attempts: u32,
    pub attempts_remaining: u32,
    pub lockout_until: Option<String>,
    pub inactivity_minutes: u32,
    pub device: Option<DeviceRegistration>,
    pub requires_full_auth: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppLockUnlockResult {
    /// None only when the 5th wrong attempt wiped the store; the frontend then
    /// falls back to full email/password login (status.requires_full_auth = true).
    pub session: Option<StoredSession>,
    pub status: AppLockStatus,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceIntegrity {
    pub rooted: bool,
    pub emulator: bool,
    pub signals: Vec<String>,
}

fn status_from(record: Option<&PersistedAppLock>, unlocked: bool) -> AppLockStatus {
    match record {
        Some(r) => AppLockStatus {
            configured: true,
            enabled: r.enabled,
            locked: !unlocked,
            digits: r.digits,
            failed_attempts: r.failed_attempts,
            attempts_remaining: attempts_remaining(r.failed_attempts),
            lockout_until: r.lockout_until.map(|t| t.to_rfc3339()),
            inactivity_minutes: r.inactivity_minutes,
            device: Some(r.device.clone()),
            requires_full_auth: false,
        },
        None => AppLockStatus {
            configured: false, enabled: false, locked: false, digits: 0,
            failed_attempts: 0, attempts_remaining: MAX_ATTEMPTS, lockout_until: None,
            inactivity_minutes: DEFAULT_INACTIVITY_MINUTES, device: None, requires_full_auth: false,
        },
    }
}

fn check_lockout(record: &PersistedAppLock) -> Result<()> {
    if let Some(until) = record.lockout_until {
        let now = Utc::now();
        if until > now {
            let secs = (until - now).num_seconds().max(1);
            return Err(QGuardError::Trust(format!("Too many attempts. Try again in {secs}s.")));
        }
    }
    Ok(())
}

fn build_device(
    state: &AppState,
    user_id: &str,
    device_name: &str,
    app_version: &str,
    existing: Option<&DeviceRegistration>,
) -> Result<DeviceRegistration> {
    let device_id = state.ensure_identity(user_id, "Android Device")?.device_id;
    let now = Utc::now();
    Ok(DeviceRegistration {
        device_id,
        device_name: if device_name.trim().is_empty() { "Android Device".to_string() } else { device_name.to_string() },
        platform: "android".to_string(),
        app_version: app_version.to_string(),
        registered_at: existing.map(|d| d.registered_at).unwrap_or(now),
        last_login_at: now,
    })
}

#[tauri::command]
pub fn applock_status(state: State<'_, AppState>) -> Result<AppLockStatus> {
    let user_id = match state.user_id() {
        Ok(id) => id,
        Err(_) => return Ok(status_from(None, false)),
    };
    let record = state.load_applock(&user_id)?;
    Ok(status_from(record.as_ref(), state.is_applock_unlocked()))
}

#[tauri::command]
pub async fn applock_setup(
    state: State<'_, AppState>,
    digits: u8,
    mut pin: String,
    session: StoredSession,
    device_name: String,
    app_version: String,
) -> Result<AppLockStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    if let Err(e) = validate_pin(digits, &pin) {
        pin.zeroize();
        return Err(e);
    }
    let sek = symmetric::random_key();
    let sealed = seal_pin(&pin, &sek).await;
    pin.zeroize();
    let (salt, verifier, sek_wrapped) = sealed?;
    let session_wrapped = wrap_session_under_sek(&sek, &session)?;
    let existing = state.load_applock(&user_id)?;
    let device = build_device(&state, &user_id, &device_name, &app_version, existing.as_ref().map(|r| &r.device))?;
    let record = PersistedAppLock {
        version: 1, enabled: true, digits, kdf_version: KDF_ARGON2ID_V1,
        salt, verifier, sek_wrapped_by_pin: sek_wrapped, session_wrapped_by_sek: session_wrapped,
        failed_attempts: 0, lockout_until: None,
        inactivity_minutes: existing.as_ref().map(|r| r.inactivity_minutes).unwrap_or(DEFAULT_INACTIVITY_MINUTES),
        device, created_at: existing.as_ref().map(|r| r.created_at).unwrap_or_else(Utc::now),
    };
    state.save_applock(&user_id, &record)?;
    state.set_applock_sek(sek)?;
    state.audit_info("applock_setup", "App-entry PIN configured");
    Ok(status_from(Some(&record), true))
}

#[tauri::command]
pub async fn applock_unlock(state: State<'_, AppState>, mut pin: String) -> Result<AppLockUnlockResult> {
    let user_id = state.user_id()?;
    let mut record = state
        .load_applock(&user_id)?
        .ok_or_else(|| QGuardError::NotFound("app PIN is not configured".to_string()))?;
    check_lockout(&record)?;

    match open_with_pin(&record, &pin).await {
        Ok(sek) => {
            pin.zeroize();
            let session = unwrap_session_from_sek(&sek, &record.session_wrapped_by_sek)?;
            record.failed_attempts = 0;
            record.lockout_until = None;
            record.device.last_login_at = Utc::now();
            state.save_applock(&user_id, &record)?;
            state.set_applock_sek(sek)?;
            state.audit_info("applock_unlock", "App unlocked with PIN");
            Ok(AppLockUnlockResult { session: Some(session), status: status_from(Some(&record), true) })
        }
        Err(_) => {
            pin.zeroize();
            record.failed_attempts += 1;
            if record.failed_attempts >= MAX_ATTEMPTS {
                // Wipe the stored session; the config is dropped so the next
                // launch requires full email/password login. This is NOT an
                // error to the caller — it returns a session-less result whose
                // status.requires_full_auth signals the fallback.
                state.delete_applock(&user_id)?;
                state.audit_info("applock_wiped", "5 failed PIN attempts — stored session wiped");
                let mut status = status_from(None, false);
                status.requires_full_auth = true;
                return Ok(AppLockUnlockResult { session: None, status });
            }
            let delay = lockout_delay_secs(record.failed_attempts);
            if delay > 0 {
                record.lockout_until = Some(Utc::now() + chrono::Duration::seconds(delay));
            }
            state.save_applock(&user_id, &record)?;
            state.audit_info("applock_unlock_failed", "Incorrect app PIN");
            Err(QGuardError::Trust(format!(
                "Incorrect PIN. {} attempt(s) remaining.",
                attempts_remaining(record.failed_attempts)
            )))
        }
    }
}

#[tauri::command]
pub fn applock_update_session(state: State<'_, AppState>, session: StoredSession) -> Result<()> {
    let user_id = state.user_id()?;
    let sek = state
        .take_applock_sek()
        .ok_or_else(|| QGuardError::Trust("app is locked".to_string()))?;
    let mut record = match state.load_applock(&user_id)? {
        Some(r) => r,
        None => return Ok(()),
    };
    record.session_wrapped_by_sek = wrap_session_under_sek(&sek, &session)?;
    state.save_applock(&user_id, &record)?;
    Ok(())
}

#[tauri::command]
pub fn applock_lock(state: State<'_, AppState>) -> Result<()> {
    state.clear_applock_sek();
    state.audit_info("applock_lock", "App locked");
    Ok(())
}

#[tauri::command]
pub async fn applock_change_pin(
    state: State<'_, AppState>,
    mut old_pin: String,
    mut new_pin: String,
    digits: u8,
) -> Result<AppLockStatus> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    if let Err(e) = validate_pin(digits, &new_pin) {
        old_pin.zeroize();
        new_pin.zeroize();
        return Err(e);
    }
    let mut record = state
        .load_applock(&user_id)?
        .ok_or_else(|| QGuardError::NotFound("app PIN is not configured".to_string()))?;
    check_lockout(&record)?;
    let sek = match open_with_pin(&record, &old_pin).await {
        Ok(sek) => sek,
        Err(e) => {
            old_pin.zeroize();
            new_pin.zeroize();
            record.failed_attempts += 1;
            let _ = state.save_applock(&user_id, &record);
            return Err(e);
        }
    };
    old_pin.zeroize();
    let sealed = seal_pin(&new_pin, &sek).await;
    new_pin.zeroize();
    let (salt, verifier, sek_wrapped) = sealed?;
    record.salt = salt;
    record.verifier = verifier;
    record.sek_wrapped_by_pin = sek_wrapped;
    record.digits = digits;
    record.kdf_version = KDF_ARGON2ID_V1;
    record.failed_attempts = 0;
    record.lockout_until = None;
    state.save_applock(&user_id, &record)?;
    state.set_applock_sek(sek)?;
    state.audit_info("applock_change_pin", "App PIN changed");
    Ok(status_from(Some(&record), true))
}

#[tauri::command]
pub fn applock_remove(state: State<'_, AppState>) -> Result<()> {
    // Caller (frontend) has already verified the account password via an
    // ephemeral Supabase client. Removing the PIN clears the stored session, so
    // the next launch requires full email/password login.
    let user_id = state.user_id()?;
    state.delete_applock(&user_id)?;
    state.audit_info("applock_remove", "App PIN removed (session persistence disabled)");
    Ok(())
}

#[tauri::command]
pub async fn applock_reset(
    state: State<'_, AppState>,
    digits: u8,
    pin: String,
    session: StoredSession,
    device_name: String,
    app_version: String,
) -> Result<AppLockStatus> {
    // Forgotten-PIN / expired-token rebind: identical to setup but explicitly
    // resets counters. Frontend has re-authenticated the account first.
    applock_setup(state, digits, pin, session, device_name, app_version).await
}

#[tauri::command]
pub fn applock_set_inactivity(state: State<'_, AppState>, minutes: u32) -> Result<AppLockStatus> {
    let user_id = state.user_id()?;
    let mut record = state
        .load_applock(&user_id)?
        .ok_or_else(|| QGuardError::NotFound("app PIN is not configured".to_string()))?;
    record.inactivity_minutes = clamp_inactivity(minutes);
    state.save_applock(&user_id, &record)?;
    Ok(status_from(Some(&record), state.is_applock_unlocked()))
}

#[tauri::command]
pub fn applock_wipe(state: State<'_, AppState>, user_id: Option<String>) -> Result<()> {
    let uid = match user_id {
        Some(id) => id,
        None => match state.user_id() {
            Ok(id) => id,
            Err(_) => return Ok(()),
        },
    };
    state.delete_applock(&uid)?;
    state.audit_info("applock_wipe", "App PIN + stored session wiped (logout)");
    Ok(())
}

#[tauri::command]
pub fn applock_device_integrity() -> Result<DeviceIntegrity> {
    let mut signals = Vec::new();
    let mut rooted = false;
    let mut emulator = false;

    #[cfg(target_os = "android")]
    {
        const SU_PATHS: [&str; 6] = [
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/data/local/xbin/su", "/data/local/su",
        ];
        for p in SU_PATHS {
            if std::path::Path::new(p).exists() {
                rooted = true;
                signals.push(format!("su binary present: {p}"));
            }
        }
        if std::path::Path::new("/system/bin/magisk").exists()
            || std::path::Path::new("/sbin/.magisk").exists()
        {
            rooted = true;
            signals.push("Magisk present".to_string());
        }
        // QEMU/emulator markers (advisory).
        if std::path::Path::new("/dev/socket/qemud").exists()
            || std::path::Path::new("/dev/qemu_pipe").exists()
        {
            emulator = true;
            signals.push("emulator pipe present".to_string());
        }
    }

    Ok(DeviceIntegrity { rooted, emulator, signals })
}
```


- [ ] **Step 4: Register the module and commands**

In `src-tauri/src/commands/mod.rs`, add (alphabetical, after `pub mod auth;`):

```rust
pub mod applock;
```

In `src-tauri/src/lib.rs`, add the import next to the other command imports (after line 19 `use commands::auth::*;`):

```rust
use commands::applock::*;
```

And register each command inside `tauri::generate_handler![ ... ]` (add after the `workspace_reset_vault,` line ~218):

```rust
            applock_status,
            applock_setup,
            applock_unlock,
            applock_update_session,
            applock_lock,
            applock_change_pin,
            applock_remove,
            applock_reset,
            applock_set_inactivity,
            applock_wipe,
            applock_device_integrity,
```

- [ ] **Step 5: Build + run the full applock test set**

Run: `cd src-tauri && cargo build 2>&1 | tail -20 && cargo test applock:: 2>&1 | tail -25`
Expected: builds cleanly; all `applock::tests::*` PASS.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/commands/applock.rs src-tauri/src/commands/mod.rs src-tauri/src/lib.rs src-tauri/Cargo.toml
git commit -m "feat: add app-entry PIN commands (setup/unlock/change/reset/wipe)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Supabase `trusted_devices` table + RLS

**Files:**
- Create: `qguard-messaging/supabase/migrations/031_trusted_devices.sql`

**Interfaces:**
- Produces: table `public.trusted_devices` with owner-only RLS; consumed by `src/lib/trusted-devices.ts` (Task 9).

- [ ] **Step 1: Write the migration**

```sql
-- 031_trusted_devices.sql
-- Trusted-device registry for banking-grade app-entry PIN (Android).
-- One row per (user, device); owner-only RLS. Revoking a row forces the target
-- device to full re-auth on its next unlock (checked client-side).

create table if not exists public.trusted_devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  device_id text not null,
  device_name text,
  platform text,
  app_version text,
  registered_at timestamptz not null default now(),
  last_login_at timestamptz,
  revoked_at timestamptz,
  unique (user_id, device_id)
);

create index if not exists trusted_devices_user_idx on public.trusted_devices (user_id);

alter table public.trusted_devices enable row level security;

drop policy if exists "trusted_devices_select_own" on public.trusted_devices;
create policy "trusted_devices_select_own" on public.trusted_devices
  for select using (auth.uid() = user_id);

drop policy if exists "trusted_devices_insert_own" on public.trusted_devices;
create policy "trusted_devices_insert_own" on public.trusted_devices
  for insert with check (auth.uid() = user_id);

drop policy if exists "trusted_devices_update_own" on public.trusted_devices;
create policy "trusted_devices_update_own" on public.trusted_devices
  for update using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "trusted_devices_delete_own" on public.trusted_devices;
create policy "trusted_devices_delete_own" on public.trusted_devices
  for delete using (auth.uid() = user_id);
```

- [ ] **Step 2: Apply the migration**

Apply via the project's normal migration path (Supabase SQL editor or CLI). If using the Supabase MCP / dashboard, run the file contents against the `qguard-messaging` project. Verify:

Run (Supabase SQL editor): `select count(*) from public.trusted_devices;`
Expected: returns `0` (table exists, empty).

- [ ] **Step 3: Commit**

```bash
git add qguard-messaging/supabase/migrations/031_trusted_devices.sql
git commit -m "feat: add trusted_devices table + owner-only RLS (migration 031)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: `use-app-lock` hook

Client hook mirroring `use-workspace-lock`: status, setup, unlock, lock, change, remove, reset, inactivity + the background/inactivity auto-lock (Android only, no-op on desktop).

**Files:**
- Create: `src/lib/use-app-lock.ts`

**Interfaces:**
- Consumes: Tauri commands from Task 4 via `safeInvoke`; `isAndroidRuntime`, `isNativeDialogOpen`.
- Produces: `useAppLock(userId: string | null)` returning `{ status: AppLockStatus | null, loading, refresh, setup, unlock, lock, changePin, remove, reset, setInactivity }` and the types `AppLockStatus`, `StoredSession`.

- [ ] **Step 1: Create the hook**

```ts
import { useCallback, useEffect, useRef, useState } from "react";
import { isAndroidRuntime, safeInvoke } from "@/lib/tauri";
import { isNativeDialogOpen } from "@/lib/native-dialog-guard";

export interface StoredSession {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  userId: string;
  email: string;
}

export interface AppLockDevice {
  deviceId: string;
  deviceName: string;
  platform: string;
  appVersion: string;
  registeredAt: string;
  lastLoginAt: string;
}

export interface AppLockStatus {
  configured: boolean;
  enabled: boolean;
  locked: boolean;
  digits: number;
  failedAttempts: number;
  attemptsRemaining: number;
  lockoutUntil: string | null;
  inactivityMinutes: number;
  device: AppLockDevice | null;
  requiresFullAuth: boolean;
}

export interface AppLockUnlockResult {
  // null only when the 5th wrong attempt wiped the store (status.requiresFullAuth true).
  session: StoredSession | null;
  status: AppLockStatus;
}

export function useAppLock(userId: string | null) {
  const [status, setStatus] = useState<AppLockStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const inactivityTimerRef = useRef<number | undefined>(undefined);
  const enabled = isAndroidRuntime();

  const refresh = useCallback(async () => {
    if (!enabled) {
      setStatus(null);
      setLoading(false);
      return;
    }
    const next = await safeInvoke<AppLockStatus | null>("applock_status", undefined, null);
    setStatus(next);
    setLoading(false);
  }, [enabled]);

  useEffect(() => {
    void refresh();
  }, [refresh, userId]);

  const setup = useCallback(
    async (digits: number, pin: string, session: StoredSession, deviceName: string, appVersion: string) => {
      const result = await safeInvoke<AppLockStatus>("applock_setup", { digits, pin, session, deviceName, appVersion });
      setStatus(result);
      return result;
    },
    [],
  );

  const unlock = useCallback(async (pin: string) => {
    const result = await safeInvoke<AppLockUnlockResult>("applock_unlock", { pin });
    setStatus(result.status);
    return result;
  }, []);

  const lock = useCallback(async () => {
    if (!enabled) return;
    await safeInvoke("applock_lock", undefined, null);
    setStatus((s) => (s ? { ...s, locked: true } : s));
  }, [enabled]);

  const changePin = useCallback(async (oldPin: string, newPin: string, digits: number) => {
    const result = await safeInvoke<AppLockStatus>("applock_change_pin", { oldPin, newPin, digits });
    setStatus(result);
    return result;
  }, []);

  const remove = useCallback(async () => {
    await safeInvoke("applock_remove", undefined, null);
    await refresh();
  }, [refresh]);

  const reset = useCallback(
    async (digits: number, pin: string, session: StoredSession, deviceName: string, appVersion: string) => {
      const result = await safeInvoke<AppLockStatus>("applock_reset", { digits, pin, session, deviceName, appVersion });
      setStatus(result);
      return result;
    },
    [],
  );

  const setInactivity = useCallback(async (minutes: number) => {
    const result = await safeInvoke<AppLockStatus>("applock_set_inactivity", { minutes });
    setStatus(result);
    return result;
  }, []);

  // Background + inactivity auto-lock (Android only). Lock only on real
  // app-background / inactivity — never on mere blur or while a native dialog
  // is open (permission prompt), honoring the native-dialog-trap lesson.
  const unlocked = Boolean(status && status.configured && !status.locked);
  const inactivityMinutes = status?.inactivityMinutes ?? 10;
  useEffect(() => {
    if (!enabled || !unlocked) return;

    const lockNow = () => {
      if (isNativeDialogOpen()) return;
      void lock();
    };
    const resetInactivity = () => {
      if (inactivityTimerRef.current !== undefined) window.clearTimeout(inactivityTimerRef.current);
      if (inactivityMinutes <= 0) return;
      inactivityTimerRef.current = window.setTimeout(lockNow, inactivityMinutes * 60_000);
    };
    const onVisibility = () => {
      if (document.visibilityState === "hidden") lockNow();
      else resetInactivity();
    };
    const onActivity = () => resetInactivity();

    document.addEventListener("visibilitychange", onVisibility);
    ["mousedown", "keydown", "touchstart", "wheel"].forEach((e) =>
      window.addEventListener(e, onActivity, { passive: true }),
    );
    resetInactivity();
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      ["mousedown", "keydown", "touchstart", "wheel"].forEach((e) => window.removeEventListener(e, onActivity));
      if (inactivityTimerRef.current !== undefined) window.clearTimeout(inactivityTimerRef.current);
    };
  }, [enabled, unlocked, inactivityMinutes, lock]);

  return { status, loading, enabled, refresh, setup, unlock, lock, changePin, remove, reset, setInactivity };
}
```

- [ ] **Step 2: Typecheck**

Run: `cd .. && npm run -s typecheck 2>&1 | tail -20` (from `qguard-messaging`; if there is no `typecheck` script, run `npx tsc --noEmit 2>&1 | tail -20`).
Expected: no new type errors from `use-app-lock.ts`.

- [ ] **Step 3: Commit**

```bash
git add src/lib/use-app-lock.ts
git commit -m "feat: add useAppLock hook (status/unlock/setup + auto-lock)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: `AppLockScreen` component (premium PIN pad)

Full-screen PIN experience for both `setup` (choose 4/6 → enter → confirm) and `unlock` (attempts, lockout countdown, error shake, password escape hatch).

**Files:**
- Create: `src/components/applock/AppLockScreen.tsx`

**Interfaces:**
- Consumes: `AppLockStatus` (Task 6).
- Produces: `<AppLockScreen mode="setup" | "unlock" ... />` — props below.

- [ ] **Step 1: Create the component**

```tsx
import { useCallback, useEffect, useMemo, useState } from "react";

type Mode = "setup" | "unlock";

interface AppLockScreenProps {
  mode: Mode;
  email?: string | null;
  digits?: number; // unlock: known digit count
  attemptsRemaining?: number;
  lockoutUntil?: string | null;
  rootWarning?: boolean;
  onSubmit: (pin: string, digits: number) => Promise<void>; // throws on failure
  onUsePassword?: () => void; // full email/password auth escape hatch
  busy?: boolean;
}

function useLockoutCountdown(lockoutUntil?: string | null): number {
  const [remaining, setRemaining] = useState(0);
  useEffect(() => {
    if (!lockoutUntil) { setRemaining(0); return; }
    const tick = () => {
      const secs = Math.ceil((new Date(lockoutUntil).getTime() - Date.now()) / 1000);
      setRemaining(secs > 0 ? secs : 0);
    };
    tick();
    const id = window.setInterval(tick, 500);
    return () => window.clearInterval(id);
  }, [lockoutUntil]);
  return remaining;
}

export function AppLockScreen(props: AppLockScreenProps) {
  const { mode, email, attemptsRemaining, lockoutUntil, rootWarning, onSubmit, onUsePassword, busy } = props;
  const [chosenDigits, setChosenDigits] = useState<number>(props.digits ?? 6);
  const [stage, setStage] = useState<"choose" | "enter" | "confirm">(mode === "setup" ? "choose" : "enter");
  const [entry, setEntry] = useState("");
  const [firstPin, setFirstPin] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [shake, setShake] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const digits = mode === "unlock" ? (props.digits ?? 6) : chosenDigits;
  const lockoutRemaining = useLockoutCountdown(lockoutUntil);
  const disabled = Boolean(busy) || submitting || lockoutRemaining > 0;

  const triggerShake = useCallback(() => {
    setShake(true);
    window.setTimeout(() => setShake(false), 500);
  }, []);

  const commit = useCallback(
    async (pin: string) => {
      if (mode === "setup") {
        if (stage === "enter") {
          setFirstPin(pin);
          setEntry("");
          setStage("confirm");
          return;
        }
        // confirm
        if (pin !== firstPin) {
          setError("PINs did not match. Start again.");
          setEntry("");
          setFirstPin("");
          setStage("enter");
          triggerShake();
          return;
        }
      }
      setSubmitting(true);
      setError(null);
      try {
        await onSubmit(pin, digits);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Incorrect PIN.");
        setEntry("");
        if (mode === "setup") { setFirstPin(""); setStage("enter"); }
        triggerShake();
      } finally {
        setSubmitting(false);
      }
    },
    [mode, stage, firstPin, digits, onSubmit, triggerShake],
  );

  const press = useCallback(
    (n: string) => {
      if (disabled) return;
      setError(null);
      setEntry((prev) => {
        if (prev.length >= digits) return prev;
        const next = prev + n;
        if (next.length === digits) window.setTimeout(() => void commit(next), 80);
        return next;
      });
    },
    [disabled, digits, commit],
  );

  const back = useCallback(() => setEntry((p) => p.slice(0, -1)), []);

  const heading = useMemo(() => {
    if (mode === "unlock") return "Enter your PIN";
    if (stage === "choose") return "Create your app PIN";
    if (stage === "confirm") return "Confirm your PIN";
    return `Enter a ${digits}-digit PIN`;
  }, [mode, stage, digits]);

  const subheading = useMemo(() => {
    if (mode === "unlock") return email ? `Unlock QGuard Messaging — ${email}` : "Unlock QGuard Messaging";
    if (stage === "choose") return "You'll use this PIN to unlock the app on this device.";
    return "";
  }, [mode, stage, email]);

  return (
    <div className="flex min-h-screen w-screen flex-col items-center justify-center bg-canvas px-6 py-10">
      <div className="flex w-full max-w-sm flex-col items-center gap-8">
        <div className="text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500/20 to-cyan-500/5 text-2xl">🔐</div>
          <h1 className="text-xl font-bold text-ink">{heading}</h1>
          {subheading && <p className="mt-1 text-sm text-muted">{subheading}</p>}
        </div>

        {rootWarning && (
          <div className="w-full rounded-lg border border-amber-300/40 bg-amber-50/60 px-3 py-2 text-center text-xs font-medium text-amber-700">
            This device appears rooted. Your session remains encrypted, but rooted devices are higher risk.
          </div>
        )}

        {mode === "setup" && stage === "choose" ? (
          <div className="flex w-full flex-col gap-3">
            <button onClick={() => { setChosenDigits(4); setStage("enter"); }} className="rounded-xl border border-line bg-white px-4 py-4 text-center text-sm font-semibold text-ink hover:border-cyan-400">
              4-digit PIN
            </button>
            <button onClick={() => { setChosenDigits(6); setStage("enter"); }} className="rounded-xl border border-line bg-white px-4 py-4 text-center text-sm font-semibold text-ink hover:border-cyan-400">
              6-digit PIN <span className="text-muted">(recommended)</span>
            </button>
          </div>
        ) : (
          <>
            <div className={`flex items-center justify-center gap-3 ${shake ? "animate-[shake_0.5s]" : ""}`}>
              {Array.from({ length: digits }).map((_, i) => (
                <span key={i} className={`h-4 w-4 rounded-full border transition-colors ${i < entry.length ? "border-cyan-500 bg-cyan-500" : "border-line bg-transparent"}`} />
              ))}
            </div>

            {error && <p className="text-center text-sm font-medium text-rose-500">{error}</p>}
            {lockoutRemaining > 0 && <p className="text-center text-sm font-medium text-amber-600">Too many attempts. Try again in {lockoutRemaining}s.</p>}
            {mode === "unlock" && typeof attemptsRemaining === "number" && attemptsRemaining < 5 && lockoutRemaining === 0 && (
              <p className="text-center text-xs text-muted">{attemptsRemaining} attempt(s) remaining</p>
            )}

            <div className="grid grid-cols-3 gap-4">
              {["1","2","3","4","5","6","7","8","9"].map((n) => (
                <button key={n} disabled={disabled} onClick={() => press(n)} className="mx-auto flex h-16 w-16 items-center justify-center rounded-full border border-line bg-white text-2xl font-medium text-ink transition active:scale-95 disabled:opacity-40">
                  {n}
                </button>
              ))}
              <span />
              <button disabled={disabled} onClick={() => press("0")} className="mx-auto flex h-16 w-16 items-center justify-center rounded-full border border-line bg-white text-2xl font-medium text-ink transition active:scale-95 disabled:opacity-40">0</button>
              <button disabled={disabled || entry.length === 0} onClick={back} className="mx-auto flex h-16 w-16 items-center justify-center rounded-full text-xl text-muted transition active:scale-95 disabled:opacity-30">⌫</button>
            </div>

            {/* Biometric slot (fast-follow) — disabled placeholder */}
            <button disabled className="text-xs text-muted opacity-40">Unlock with biometrics (coming soon)</button>
          </>
        )}

        {mode === "unlock" && onUsePassword && (
          <button onClick={onUsePassword} className="text-sm font-medium text-cyan-600 hover:underline">
            Sign in with password instead
          </button>
        )}
      </div>
    </div>
  );
}

export default AppLockScreen;
```

- [ ] **Step 2: Add the shake keyframe** to `src/styles/globals.css` (append near the end):

```css
@keyframes shake {
  0%, 100% { transform: translateX(0); }
  20%, 60% { transform: translateX(-8px); }
  40%, 80% { transform: translateX(8px); }
}
```

- [ ] **Step 3: Typecheck**

Run: `npx tsc --noEmit 2>&1 | tail -20`
Expected: no new type errors. (Tailwind class names like `bg-canvas`, `text-ink`, `text-muted`, `border-line` already exist in this codebase — verify by grepping if a class is missing: `grep -r "text-ink" src/styles`. If a token is absent, substitute the nearest existing one used by `WorkspaceLockGate`.)

- [ ] **Step 4: Commit**

```bash
git add src/components/applock/AppLockScreen.tsx src/styles/globals.css
git commit -m "feat: add premium AppLockScreen PIN pad (setup + unlock)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: App gating + auth-context wiring

Insert the Android app-entry gate into `App.tsx` above the login/paywall chain, and wire `auth-context` to (a) expose the current session as a `StoredSession`, (b) re-persist on `TOKEN_REFRESHED`, and (c) wipe applock on sign-out.

**Files:**
- Modify: `src/lib/auth-context.tsx`
- Modify: `src/App.tsx`

**Interfaces:**
- Consumes: `useAppLock`, `AppLockScreen`, `StoredSession` (Tasks 6–7); `isAndroidRuntime`; `supabase.auth.setSession`.
- Produces: `auth.currentStoredSession()` helper on the auth context returning `StoredSession | null`.

- [ ] **Step 1: Expose a `StoredSession` builder + refresh/logout wiring in `auth-context.tsx`**

Add a helper (module scope, above `AuthProvider`):

```tsx
import type { StoredSession } from "@/lib/use-app-lock";

function toStoredSession(session: Session | null): StoredSession | null {
  if (!session?.access_token || !session.refresh_token) return null;
  return {
    accessToken: session.access_token,
    refreshToken: session.refresh_token,
    expiresAt: session.expires_at ?? 0,
    userId: session.user.id,
    email: session.user.email ?? "",
  };
}
```

Add to `AuthContextValue` interface:

```tsx
  currentStoredSession: () => StoredSession | null;
```

In `onAuthStateChange`, re-persist the applock session on token refresh (Android only). Inside the callback where a matching-token refresh is handled (the `if (nextSession.access_token === activeSessionTokenRef.current)` branch is for the *same* token; the refresh path enters `processSession`). Add, right after `setSession(nextSession); setUser(nextSession.user);` in the same-token branch AND after a successful `completeAuthenticatedSession`, a best-effort update:

```tsx
        if (isAndroidRuntime()) {
          const stored = toStoredSession(nextSession);
          if (stored) void safeInvoke("applock_update_session", { session: stored }, null).catch(() => undefined);
        }
```

(Import `isAndroidRuntime` from `@/lib/tauri` — `safeInvoke` is already imported.)

In `signOut`, add before clearing state:

```tsx
    if (isAndroidRuntime()) {
      await safeInvoke("applock_wipe", userId ? { userId } : {}, null).catch(() => undefined);
    }
```

Add `currentStoredSession` to the `value` memo:

```tsx
    currentStoredSession: () => toStoredSession(session),
```

(Add `currentStoredSession` to both the object and the `useMemo` dependency array is not needed since it closes over `session` which is already a dep.)

Update `missingProviderAuth` to include `currentStoredSession: () => null,`.

- [ ] **Step 2: Add the gate to `App.tsx`**

Add imports:

```tsx
import { useAppLock, type StoredSession } from "@/lib/use-app-lock";
import { AppLockScreen } from "@/components/applock/AppLockScreen";
import { isAndroidRuntime, safeInvoke } from "@/lib/tauri";
import { supabase } from "@/lib/supabase";
```

(`safeInvoke` may already be imported — dedupe.)

Inside `ProtectedMessagingApp`, near the other hooks (after `const auth = useAuth();`):

```tsx
  const android = isAndroidRuntime();
  const appLock = useAppLock(auth.user?.id ?? null);
  const [forcePasswordLogin, setForcePasswordLogin] = useState(false);
  const appVersion = (window as unknown as { __APP_VERSION__?: string }).__APP_VERSION__ ?? "0.0.0";
```

Add the gate logic. Immediately **after** the `if (auth.loading) { ... }` splash block and **before** the `if (!auth.user || !auth.session)` login block, insert:

```tsx
  // ---- Android app-entry PIN gate (banking-grade) ----
  if (android && !appLock.loading && appLock.status?.configured && appLock.status.locked && !forcePasswordLogin) {
    // No live session yet (cold launch) -> unlocking restores it; else the app
    // is merely re-locked (background/inactivity) and unlock just clears the flag.
    const restoreFromUnlock = async (pin: string) => {
      const result = await appLock.unlock(pin);
      // 5th wrong attempt wiped the store -> fall back to full auth.
      if (result.status.requiresFullAuth || !result.session) {
        setForcePasswordLogin(true);
        await appLock.refresh();
        return;
      }
      if (!auth.user || !auth.session) {
        const { error } = await supabase.auth.setSession({
          access_token: result.session.accessToken,
          refresh_token: result.session.refreshToken,
        });
        if (error) {
          // Refresh token expired -> fall back to full auth, keep existing PIN.
          setForcePasswordLogin(true);
          throw new Error("Your session expired. Please sign in with your password.");
        }
      }
    };
    return (
      <AppLockScreen
        mode="unlock"
        email={auth.user?.email ?? null}
        digits={appLock.status.digits}
        attemptsRemaining={appLock.status.attemptsRemaining}
        lockoutUntil={appLock.status.lockoutUntil}
        onSubmit={async (pin) => {
          await restoreFromUnlock(pin);
        }}
        onUsePassword={() => setForcePasswordLogin(true)}
      />
    );
  }
```

Then, in the existing `if (!auth.user || !auth.session)` block, after a successful login the user has a session but (on Android, first time) no applock. Add the **setup** gate right after the paywall `loading` splash resolves — insert immediately **after** the `if (!auth.user || !auth.session) { ... }` block and **before** `if (subscriptionState.loading)`:

```tsx
  // First login on Android with no PIN yet -> force PIN creation before the app.
  if (android && !appLock.loading && auth.user && auth.session && !appLock.status?.configured) {
    const stored = auth.currentStoredSession();
    return (
      <AppLockScreen
        mode="setup"
        email={auth.user.email ?? null}
        onSubmit={async (pin, digits) => {
          if (!stored) throw new Error("No active session to secure.");
          await appLock.setup(digits, pin, stored, "Android Device", appVersion);
          setForcePasswordLogin(false);
        }}
      />
    );
  }
```

Also: when `forcePasswordLogin` is set and the user re-authenticates, re-bind the PIN. Handle this by clearing `forcePasswordLogin` once a fresh session exists AND applock is configured; if applock is configured but locked and we forced password login, after login call `applock_reset`. Simplest robust approach: after `forcePasswordLogin` login completes and `auth.user && auth.session` and `appLock.status?.configured`, show a one-time "confirm your PIN to continue" setup screen that calls `reset`:

```tsx
  if (android && forcePasswordLogin && auth.user && auth.session && appLock.status?.configured) {
    const stored = auth.currentStoredSession();
    return (
      <AppLockScreen
        mode="setup"
        email={auth.user.email ?? null}
        digits={appLock.status.digits}
        onSubmit={async (pin, digits) => {
          if (!stored) throw new Error("No active session to secure.");
          await appLock.reset(digits, pin, stored, appLock.status?.device?.deviceName ?? "Android Device", appVersion);
          setForcePasswordLogin(false);
        }}
      />
    );
  }
```

- [ ] **Step 3: Register a trusted device on setup/login** — deferred to Task 9 (which adds `trusted-devices.ts`). Leave a `// TODO(Task 9): upsertTrustedDevice` comment where `appLock.setup(...)` is called so it is wired next.

- [ ] **Step 4: Typecheck + web build**

Run: `npx tsc --noEmit 2>&1 | tail -25 && npm run -s build 2>&1 | tail -15`
Expected: no type errors; Vite build succeeds.

- [ ] **Step 5: Commit**

```bash
git add src/App.tsx src/lib/auth-context.tsx
git commit -m "feat: wire Android app-entry PIN gate + session persistence into App shell

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: Trusted-device sync + Settings → Security management

Add the Supabase device helpers, wire device upsert into setup/login, add a revocation check on unlock, and build the Settings → Security section (change/switch/remove/reset PIN, inactivity, trusted devices).

**Files:**
- Create: `src/lib/trusted-devices.ts`
- Modify: `src/App.tsx` (call `upsertTrustedDevice` at the `// TODO(Task 9)` site; add revocation check in `restoreFromUnlock`)
- Modify: `src/pages/SettingsPage.tsx` (add the Application PIN + Trusted Devices section)

**Interfaces:**
- Consumes: `supabase` client, `AppLockDevice` (Task 6), migration 031 (Task 5).
- Produces:
  - `upsertTrustedDevice(client, userId, device: AppLockDevice): Promise<void>`
  - `listTrustedDevices(client, userId): Promise<TrustedDeviceRow[]>`
  - `revokeTrustedDevice(client, userId, deviceId): Promise<void>`
  - `isDeviceRevoked(client, userId, deviceId): Promise<boolean>`
  - `interface TrustedDeviceRow { id, device_id, device_name, platform, app_version, registered_at, last_login_at, revoked_at }`

- [ ] **Step 1: Create `trusted-devices.ts`**

```ts
import type { SupabaseClient } from "@supabase/supabase-js";
import type { AppLockDevice } from "@/lib/use-app-lock";

export interface TrustedDeviceRow {
  id: string;
  device_id: string;
  device_name: string | null;
  platform: string | null;
  app_version: string | null;
  registered_at: string;
  last_login_at: string | null;
  revoked_at: string | null;
}

export async function upsertTrustedDevice(client: SupabaseClient, userId: string, device: AppLockDevice): Promise<void> {
  await client.from("trusted_devices").upsert(
    {
      user_id: userId,
      device_id: device.deviceId,
      device_name: device.deviceName,
      platform: device.platform,
      app_version: device.appVersion,
      last_login_at: new Date().toISOString(),
      revoked_at: null,
    },
    { onConflict: "user_id,device_id" },
  );
}

export async function listTrustedDevices(client: SupabaseClient, userId: string): Promise<TrustedDeviceRow[]> {
  const { data } = await client
    .from("trusted_devices")
    .select("*")
    .eq("user_id", userId)
    .order("last_login_at", { ascending: false });
  return (data as TrustedDeviceRow[] | null) ?? [];
}

export async function revokeTrustedDevice(client: SupabaseClient, userId: string, deviceId: string): Promise<void> {
  await client
    .from("trusted_devices")
    .update({ revoked_at: new Date().toISOString() })
    .eq("user_id", userId)
    .eq("device_id", deviceId);
}

export async function isDeviceRevoked(client: SupabaseClient, userId: string, deviceId: string): Promise<boolean> {
  const { data } = await client
    .from("trusted_devices")
    .select("revoked_at")
    .eq("user_id", userId)
    .eq("device_id", deviceId)
    .maybeSingle();
  return Boolean((data as { revoked_at: string | null } | null)?.revoked_at);
}
```

- [ ] **Step 2: Wire device upsert + revocation check in `App.tsx`**

Replace the `// TODO(Task 9): upsertTrustedDevice` comment (setup `onSubmit`) so, after `await appLock.setup(...)`, it upserts:

```tsx
          const status = await appLock.setup(digits, pin, stored, "Android Device", appVersion);
          if (status.device && auth.user) {
            await upsertTrustedDevice(supabase, auth.user.id, status.device).catch(() => undefined);
          }
          setForcePasswordLogin(false);
```

In `restoreFromUnlock`, after a successful `setSession`, check revocation and update last-login:

```tsx
      if (auth.user && appLock.status?.device) {
        const revoked = await isDeviceRevoked(supabase, result.session.userId, appLock.status.device.deviceId).catch(() => false);
        if (revoked) { setForcePasswordLogin(true); throw new Error("This device was signed out remotely. Please sign in again."); }
        await upsertTrustedDevice(supabase, result.session.userId, appLock.status.device).catch(() => undefined);
      }
```

Add the import: `import { upsertTrustedDevice, isDeviceRevoked } from "@/lib/trusted-devices";`

- [ ] **Step 3: Add the Settings → Security section in `SettingsPage.tsx`**

First inspect the current file to find the security section and the props it receives:

Run: `grep -n "workspaceStatus\|Security\|inactivityMinutes\|export default function SettingsPage\|interface .*Props" src/pages/SettingsPage.tsx | head -30`

Add a new self-contained section component near the bottom of the file and render it inside the page's Security area (only on Android). Because SettingsPage already receives `workspaceStatus`/`inactivityMinutes` props, follow the same prop-drill pattern: thread an `appLock` object (the `useAppLock` return) from `App.tsx` into `SettingsPage` via a new optional prop `appLock?: ReturnType<typeof useAppLock>`, and `verifyAccountPassword?: (password: string) => Promise<void>` (already defined in `App.tsx`).

Component to add to `SettingsPage.tsx`:

```tsx
function ApplicationPinSection({
  appLock,
  verifyAccountPassword,
  userId,
}: {
  appLock: ReturnType<typeof import("@/lib/use-app-lock").useAppLock>;
  verifyAccountPassword: (password: string) => Promise<void>;
  userId: string;
}) {
  const [devices, setDevices] = useState<import("@/lib/trusted-devices").TrustedDeviceRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    void import("@/lib/trusted-devices").then(({ listTrustedDevices }) =>
      import("@/lib/supabase").then(({ supabase }) => listTrustedDevices(supabase, userId).then(setDevices)),
    );
  }, [userId, appLock.status?.device?.lastLoginAt]);

  if (!appLock.enabled) return null;
  const status = appLock.status;

  const removePin = async () => {
    const password = window.prompt("Confirm your account password to remove the app PIN:");
    if (!password) return;
    setBusy(true); setMsg(null);
    try {
      await verifyAccountPassword(password);
      await appLock.remove();
      setMsg("App PIN removed. You'll sign in with your password next launch.");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Could not remove PIN.");
    } finally { setBusy(false); }
  };

  const changePin = async () => {
    const oldPin = window.prompt("Current PIN:");
    const newPin = window.prompt("New PIN (4 or 6 digits):");
    if (!oldPin || !newPin) return;
    setBusy(true); setMsg(null);
    try {
      await appLock.changePin(oldPin, newPin, newPin.length === 4 ? 4 : 6);
      setMsg("PIN updated.");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Could not change PIN.");
    } finally { setBusy(false); }
  };

  const revoke = async (deviceId: string) => {
    setBusy(true);
    const { revokeTrustedDevice } = await import("@/lib/trusted-devices");
    const { supabase } = await import("@/lib/supabase");
    await revokeTrustedDevice(supabase, userId, deviceId);
    const { listTrustedDevices } = await import("@/lib/trusted-devices");
    setDevices(await listTrustedDevices(supabase, userId));
    setBusy(false);
  };

  return (
    <div className="shell-card p-6">
      <h3 className="text-sm font-bold text-ink">Application PIN</h3>
      <p className="mt-1 text-xs text-muted">Banking-grade unlock for this device. {status?.configured ? `${status.digits}-digit PIN active.` : "Not configured."}</p>
      {msg && <p className="mt-2 text-xs font-medium text-cyan-600">{msg}</p>}

      {status?.configured && (
        <>
          <div className="mt-4 flex flex-wrap gap-2">
            <button disabled={busy} onClick={changePin} className="rounded-lg border border-line px-3 py-2 text-xs font-semibold text-ink disabled:opacity-50">Change / switch 4↔6 digits</button>
            <button disabled={busy} onClick={removePin} className="rounded-lg border border-rose-300 px-3 py-2 text-xs font-semibold text-rose-600 disabled:opacity-50">Remove PIN</button>
          </div>

          <div className="mt-5">
            <label className="text-xs font-semibold text-ink">Auto-lock after</label>
            <select
              className="ml-2 rounded-md border border-line bg-white px-2 py-1 text-xs"
              value={status.inactivityMinutes}
              onChange={(e) => void appLock.setInactivity(Number(e.target.value))}
            >
              {[1, 5, 10, 15, 30, 60].map((m) => <option key={m} value={m}>{m} minute{m > 1 ? "s" : ""}</option>)}
            </select>
          </div>

          <div className="mt-5">
            <h4 className="text-xs font-bold text-ink">Trusted devices</h4>
            <ul className="mt-2 space-y-2">
              {devices.map((d) => (
                <li key={d.id} className="flex items-center justify-between rounded-lg border border-line px-3 py-2">
                  <div>
                    <div className="text-xs font-semibold text-ink">{d.device_name ?? "Device"} {d.revoked_at && <span className="text-rose-500">(revoked)</span>}</div>
                    <div className="text-[11px] text-muted">{d.platform} · v{d.app_version} · last login {d.last_login_at ? new Date(d.last_login_at).toLocaleString() : "—"}</div>
                  </div>
                  {!d.revoked_at && (
                    <button disabled={busy} onClick={() => void revoke(d.device_id)} className="text-[11px] font-semibold text-rose-600 disabled:opacity-50">Revoke</button>
                  )}
                </li>
              ))}
              {devices.length === 0 && <li className="text-[11px] text-muted">No devices registered yet.</li>}
            </ul>
          </div>
        </>
      )}
    </div>
  );
}
```

Render `<ApplicationPinSection appLock={appLock} verifyAccountPassword={verifyAccountPassword} userId={userId} />` inside SettingsPage's security area, guarded so it only appears when `appLock` is passed. Ensure `useState`/`useEffect` are imported in `SettingsPage.tsx` (they will be if the file already uses hooks — otherwise add to the React import).

Thread the props from `App.tsx`: at both `SettingsPage` render sites add `appLock={appLock}` and `verifyAccountPassword={verifyAccountPassword}` (the paywall render site does not have `verifyAccountPassword` in scope — pass only `appLock` there, and make `verifyAccountPassword` optional in the section: skip the Remove PIN button when it's absent).

- [ ] **Step 4: Typecheck + build**

Run: `npx tsc --noEmit 2>&1 | tail -25 && npm run -s build 2>&1 | tail -15`
Expected: no type errors; build succeeds.

- [ ] **Step 5: Commit**

```bash
git add src/lib/trusted-devices.ts src/App.tsx src/pages/SettingsPage.tsx
git commit -m "feat: trusted-device sync + Settings app-PIN management

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 10: Android native background-lock signal (no FLAG_SECURE)

Emit an app-background signal on `onStop()` so the lock is belt-and-suspenders with the JS `visibilitychange` listener. **Do not** set `FLAG_SECURE`.

**Files:**
- Modify: `src-tauri/gen/android/app/src/main/java/com/qguard/messaging/MainActivity.kt`

- [ ] **Step 1: Add `onStop` that asks the WebView to lock**

Add this method to `MainActivity` (inside the class, after `requestCorePermissions`), and confirm no `FLAG_SECURE` line exists anywhere:

```kotlin
  override fun onStop() {
    super.onStop()
    // Belt-and-suspenders app-entry lock: when the app is backgrounded, ask the
    // web layer to lock immediately (the JS visibilitychange listener is the
    // primary trigger). NOTE: FLAG_SECURE is intentionally NOT set — users must
    // be able to take screenshots.
    runCatching {
      runOnUiThread {
        // Tauri exposes the WebView via the generated activity; evaluate a tiny
        // hook the frontend installs on window. Guard for null during teardown.
        val hook = "window.__qguardAppLock && window.__qguardAppLock()"
        this.javaClass.getMethod("getWebView")?.let { m ->
          val wv = m.invoke(this)
          wv?.javaClass?.getMethod("evaluateJavascript", String::class.java, android.webkit.ValueCallback::class.java)
            ?.invoke(wv, hook, null)
        }
      }
    }
  }
```

> If reflection against the generated activity proves brittle at build time, the JS `visibilitychange -> hidden` handler in `useAppLock` already locks on background for the common cases; this native hook is a non-critical enhancement. Keep it wrapped in `runCatching` so it can never crash the activity.

- [ ] **Step 2: Install the `window.__qguardAppLock` hook** in `src/lib/use-app-lock.ts` — inside the auto-lock `useEffect`, register a global the native layer can call:

```ts
    (window as unknown as { __qguardAppLock?: () => void }).__qguardAppLock = () => lockNow();
```

and clear it in the effect cleanup:

```ts
      delete (window as unknown as { __qguardAppLock?: () => void }).__qguardAppLock;
```

- [ ] **Step 3: Confirm no FLAG_SECURE anywhere**

Run: `grep -rn "FLAG_SECURE" src-tauri/gen/android || echo "OK: no FLAG_SECURE"`
Expected: prints `OK: no FLAG_SECURE`.

- [ ] **Step 4: Commit**

```bash
git add src-tauri/gen/android/app/src/main/java/com/qguard/messaging/MainActivity.kt src/lib/use-app-lock.ts
git commit -m "feat: native onStop background-lock signal (no FLAG_SECURE)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 11: Integration verification (build + emulator E2E)

**Files:** none (verification only).

- [ ] **Step 1: Full Rust test + build**

Run: `cd src-tauri && cargo test 2>&1 | tail -30`
Expected: all tests pass, including `passcode::*`, `obf::*`, `workspace::*`, `applock::*`.

- [ ] **Step 2: Frontend typecheck + build**

Run: `cd .. && npx tsc --noEmit 2>&1 | tail -20 && npm run -s build 2>&1 | tail -15`
Expected: clean.

- [ ] **Step 3: Android debug build**

Run the project's Android build (per memory `qguard-messaging-android`: NDK r27, `gradlew` workaround). Example:
`npx tauri android build --debug 2>&1 | tail -40` (or the repo's documented build script). A >10-min release build should be run in the background.
Expected: APK builds.

- [ ] **Step 4: Manual E2E on emulator + physical tablet** — verify each:
  - First login → prompted to create PIN → choose 6 → enter → confirm → lands on dashboard.
  - Kill + relaunch app → **PIN screen** (not email/password) → correct PIN → dashboard, session restored.
  - Wrong PIN ×5 → session wiped → email/password login → after login, re-confirm PIN → dashboard.
  - 3rd/4th wrong PIN → increasing-delay lockout countdown shown.
  - Background the app (Home) → return → PIN screen again.
  - Screenshots work normally in-app (no FLAG_SECURE).
  - Settings → Security: change PIN, switch 4↔6, remove PIN (asks account password), auto-lock timeout persists.
  - Token expiry (or manually clear session) → PIN can't restore → password login → re-confirm PIN.
  - Logout → relaunch requires full email/password login.
  - Trusted device appears in Supabase `trusted_devices`; revoking from another device forces this device to full re-auth on next unlock.
  - Desktop build unchanged: no PIN gate, normal login + workspace locks.

- [ ] **Step 5: Update memory** — after successful E2E, record a memory note (`qguard-app-entry-pin.md`) capturing: the SEK-envelope design, the Android-only gating order in `App.tsx`, the `applock_*` command surface, migration 031, and the "sessionStorage retained deliberately / Rust owns durable persistence" decision. Add the index line to `MEMORY.md`.

- [ ] **Step 6: Final commit (docs/memory only if changed)**

```bash
git add -A
git commit -m "docs: app-entry PIN E2E verified; record design notes

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- First-time login → device registration + secure session store + PIN creation (4/6, confirm): Tasks 4, 8, 9. ✅
- Returning-user PIN unlock → restore session → dashboard: Tasks 4, 8. ✅
- Secure PIN storage (Keystore/hardware-backed, never plaintext, encrypted): Tasks 1–4 (Argon2id + SEK envelope + device DEK). ✅
- Session token secure storage + expiry → full re-auth → keep PIN: Tasks 4 (`applock_reset`), 8 (expiry branch). ✅
- Failed-PIN protection (max 5 → lock + full auth; clear counter after auth; increasing delays): Task 4 ladder + Task 8 wipe branch. ✅
- Auto-lock inactivity (configurable, default 10) + lock on background + PIN on reopen: Tasks 6 (hook), 8, 10. ✅
- Screenshots allowed / no FLAG_SECURE (deliberate deviation): Task 10. ✅ (Recents masking intentionally omitted — spec §11.)
- Root detection (advisory): Task 4 `applock_device_integrity` + Task 7 `rootWarning`. ✅
- PIN management (change / remove w/ password / switch 4↔6 / enable-disable / auto-lock / reset): Tasks 4, 9. ✅ (Enable/disable == configured/removed; removing disables persistence.)
- Biometrics: out of scope — seam left (Task 7 placeholder). ✅ (per decision)
- Device registration (id, name, timestamps, platform, app version) + manage from settings: Tasks 3, 9, 5. ✅
- Logout wipes tokens + PIN + device registration: Tasks 4 (`applock_wipe`), 8, 9. ✅

**Placeholder scan:** The only intentional placeholders are the `/* GEN: ... */` byte arrays in Task 2 (generated deterministically in Step 1 and proven by the round-trip test in Step 4) and the `// TODO(Task 9)` marker that Task 9 Step 2 explicitly resolves. The `Ok_status_err` helper carries an inline instruction to rename to `wiped_signal` (Rust identifier rules). No vague "add error handling" steps remain.

**Type consistency:** `StoredSession` (Rust camelCase serde ↔ TS `StoredSession`), `AppLockStatus`/`AppLockUnlockResult` fields match between `applock.rs` and `use-app-lock.ts`; `DeviceRegistration` (Rust) ↔ `AppLockDevice` (TS) share camelCase field names; command names match between `lib.rs` registration, `applock.rs` `#[tauri::command]` fns, and `safeInvoke` call sites.
