# Banking-Grade App-Entry PIN Authentication (Android) — Design

**Date:** 2026-07-27
**Scope:** QGuard Messaging Android build only. Desktop (Windows/macOS/Linux) behavior is unchanged.
**Source spec:** `Qguard_Wiki/Android_Security_Features`

---

## 1. Objective

Give the Android app a banking-app authentication experience:

1. The user signs in with email + password **once** on a trusted device.
2. The device is registered, the authenticated session is stored securely on-device, and the user creates an application **PIN** (4 or 6 digits).
3. Every subsequent app launch shows a secure **PIN entry** screen instead of the email/password form. A correct PIN restores the stored session and lands the user on their dashboard.
4. The PIN unlocks a *locally stored* session — it never replaces server authentication. When the session (refresh token) expires, the app falls back to full email/password login.

This is an **app-entry** layer. It is independent of the existing per-module *workspace lock* that separately gates Secure Chat and Quantum Vault.

## 2. Decisions (locked during brainstorming)

| Decision | Choice |
| --- | --- |
| Platform | **Android only.** Desktop keeps current per-launch Supabase login + workspace locks. |
| Relationship to workspace lock | **Fully independent layer.** The app PIN gates app entry and restores the session; Chat/Vault keep their own separate unlocks. |
| Biometrics | **Deferred (fast-follow).** Design leaves a clean seam; not implemented in this build. |
| Trusted device registry | **Local (encrypted at rest) + Supabase `trusted_devices` table** with RLS, for cross-device management/revocation. |
| Session persistence mechanism | **Approach A — PIN-bound SEK envelope in Rust** (see §4). |

## 3. Current-state facts this design builds on

- **Supabase auth storage is `window.sessionStorage`** (`src/lib/supabase.ts`), wiped on app close → today every Android relaunch requires a full email/password login. This is the primary gap.
- **Hardware-backed secure storage already exists** (`src-tauri/src/security/keystore.rs`): a non-exportable AES-256-GCM key inside `AndroidKeyStore` (TEE/StrongBox) wraps a per-user device DEK over JNI. Reused for at-rest encryption of the applock config.
- **A hardened unlock crypto stack already exists** (`src-tauri/src/commands/workspace.rs`): Argon2id (64 MiB / 3 / 1) → HKDF-SHA3-256 → verifier, envelope-wrapping, and an anti-brute-force ladder. Shared helpers are extracted and reused (no duplication).
- **App gating** lives in `src/App.tsx`: `auth.loading` → `LoginPage` → subscription paywall → workspace-lock gates. The applock gate is inserted at the top of this chain on Android.
- **Android native layer is git-tracked and editable** (`MainActivity.kt`, `AndroidManifest.xml`).
- Known lesson honored: **do not auto-lock on window blur** (native dialogs blur the window); lock only on real app-background.

## 4. Core mechanism — PIN-bound SEK envelope (Approach A)

On login the frontend hands the live Supabase session to Rust. Rust:

1. Generates a random 32-byte **Session Encryption Key (SEK)**.
2. Encrypts the serialized session (`access_token`, `refresh_token`, `expires_at`, `user_id`, `email`) under the SEK → `session_wrapped_by_sek` (AES-256-GCM). This blob is re-written on every token refresh while unlocked.
3. Derives a **PIN key** from the PIN: `PIN → Argon2id(salt) → HKDF-SHA3-256(context) → 32-byte key`. Wraps the SEK under the PIN key → `sek_wrapped_by_pin`. Stores a `verifier` (hash of an independent HKDF subkey) to validate a re-entered PIN without revealing any key.
4. Writes the whole config file **additionally encrypted at rest under the hardware-backed device DEK** (same path/pattern as `save_workspace_scope`).

**Unlock:** `PIN → Argon2id → verify → unwrap SEK → decrypt session → return session JSON to the frontend`, which calls `supabase.auth.setSession(...)`. The SEK is held in memory (`AppState`) for the unlocked lifetime so token refreshes re-encrypt the session under it without re-deriving from the PIN. Locking zeroizes the in-memory SEK.

**Why not the alternatives:** DEK-only (session recoverable by the running app without the PIN) is weaker; an encrypted Supabase storage adapter is chatty over JNI and isn't PIN-bound. The SEK envelope binds the session to *both* the PIN and the device TEE, avoids re-running Argon2id on refresh, and leaves a seam to also wrap the SEK under a biometric-gated Keystore key later.

## 5. Rust backend

### 5.1 New module `src-tauri/src/commands/applock.rs`

Persisted config `PersistedAppLock` (serialized, then encrypted at rest under the device DEK; file `{safe_user}.applock.enc` in `data_dir/keys`):

```
version: u32
enabled: bool
digits: u8                      // 4 or 6
kdf_version: u8                 // Argon2id v1
salt: Vec<u8>
verifier: String               // hex(HKDF subkey)  — validates the PIN
sek_wrapped_by_pin: EncryptedEnvelope
session_wrapped_by_sek: EncryptedEnvelope
failed_attempts: u32
lockout_until: Option<DateTime<Utc>>
inactivity_minutes: u32         // default 10
device: DeviceRegistration      // id, name, platform, app_version, registered_at, last_login_at
created_at: DateTime<Utc>
```

Volatile state added to `AppState`: `applock_sek: Mutex<Option<[u8;32]>>` (in-memory SEK while unlocked), and an `applock_unlocked` flag.

### 5.2 Commands (all Android-relevant; callable no-op/`configured:false` on desktop)

| Command | Behavior |
| --- | --- |
| `applock_status` | `{ configured, enabled, locked, digits, failedAttempts, attemptsRemaining, lockoutUntil, inactivityMinutes, device, rootWarning }` |
| `applock_setup(pin, digits, session)` | Validate PIN (all digits, length == digits). Register device. Build SEK envelope + PIN wrap + verifier. Persist. Keep SEK in memory (unlocked). |
| `applock_unlock(pin)` | Check lockout ladder → Argon2id verify → unwrap SEK → decrypt session → return session JSON; reset counter; keep SEK in memory. On mismatch: apply ladder; on 5th failure **wipe** `session_wrapped_by_sek` + `sek_wrapped_by_pin` and return `requiresFullAuth: true`. |
| `applock_update_session(session)` | Re-encrypt session under the in-memory SEK. Called on `TOKEN_REFRESHED`. No PIN. Errors if locked. |
| `applock_lock` | Zeroize in-memory SEK, mark locked. |
| `applock_change_pin(oldPin, newPin, digits)` | Verify old → re-derive PIN key (fresh salt) → re-wrap SEK → update `digits`/`verifier`. |
| `applock_remove` | Frontend has already verified the account password (ephemeral client). Delete config + stored session. Next launch requires full login. |
| `applock_reset(session, pin, digits)` | Forgotten-PIN / expired-token rebind: after a full email/password re-auth on the frontend, install a fresh PIN binding for the supplied fresh session. |
| `applock_set_inactivity(minutes)` | Clamp to a sane range (1–60) and persist. |
| `applock_device_integrity` | Best-effort root/emulator signal (`su` binary paths, `test-keys` build tag, known Magisk/root package markers, emulator fingerprints). Warn, never block. |
| `applock_wipe` | Logout hook: delete config + session + local device record. |

### 5.3 Anti-brute-force ladder (banking spec = max 5 attempts)

- Attempts 1–2: immediate retry.
- Attempt 3 fail → 5 s delay; attempt 4 fail → 15 s delay (increasing delays between attempts).
- Attempt 5 fail → **wipe stored session**, config marked `requiresFullAuth`, app drops to full email/password login.
- A successful full email/password auth resets `failed_attempts` and re-binds via `applock_reset`.

This ladder is applock-specific (5-cap) and distinct from the workspace ladder (20-cap). Shared KDF/argon helpers are extracted (e.g. into `crypto/kdf.rs` or a small shared module) so `workspace.rs` and `applock.rs` do not duplicate the Argon2id/HKDF/verifier logic.

### 5.4 Rust unit tests (mirror `workspace.rs` tests)

- Verifier is deterministic and PIN-specific; different salt → different verifier.
- SEK envelope round-trips: correct PIN recovers the exact session; wrong PIN fails AEAD.
- PIN change re-wraps SEK and preserves the session; old PIN no longer unwraps.
- Ladder escalates and the 5th failure wipes the session.
- PIN validation enforces 4-or-6 all-digit policy.

## 6. Frontend (Android-gated)

### 6.1 Supabase client (`src/lib/supabase.ts`)

On Android (`isTauriRuntime()` + mobile platform detection), use an **in-memory** storage object and `persistSession: false`, `autoRefreshToken: true`. Tokens never touch WebView disk; Rust owns durable persistence. Desktop keeps the existing `sessionStorage` behavior. After a PIN unlock, the frontend restores the session with `supabase.auth.setSession({ access_token, refresh_token })`.

### 6.2 `src/lib/use-app-lock.ts`

Hook mirroring `use-workspace-lock`: `status`, `setup(pin,digits,session)`, `unlock(pin)`, `lock()`, `changePin(...)`, `remove()`, `reset(...)`, `setInactivityMinutes(n)`. Owns the inactivity timer and the background-lock listener (see §7). Exposes `attemptsRemaining` and `lockoutUntil` for the UI.

### 6.3 `src/App.tsx` gating (Android only; desktop path unchanged)

New order on Android:

1. `auth.loading` → splash.
2. If **applock configured** and **no live session** → `AppLockScreen mode="unlock"`. On success, restore the session (`setSession`) → continue. On 5-fail wipe or expired session → `LoginPage` (full auth), then re-bind via `applock_reset`.
3. If **no live session** and **not configured** → `LoginPage` (first-time).
4. If **live session** and **applock not configured** (just completed first login) → `AppLockScreen mode="setup"` → register device + create/confirm PIN.
5. Session live + applock unlocked → existing subscription paywall → workspace-lock gates → app shell (unchanged).
6. While running: background/inactivity fires `applock_lock` → step 2 overlay (session still live; unlock just clears the flag, no `setSession` needed).

### 6.4 `src/components/applock/AppLockScreen.tsx`

Premium/enterprise PIN experience:
- 4/6 PIN dots, custom numeric keypad (0–9, backspace), large tap targets for tablets.
- `setup` mode: choose 4 or 6 digits → enter → **confirm** (mismatch re-prompts).
- `unlock` mode: attempts-remaining indicator, live lockout countdown, error shake on mismatch.
- Biometric-slot placeholder (disabled control) for the fast-follow.
- **"Sign in with password"** escape hatch → full `LoginPage` (covers expiry, lockout, forgotten PIN).
- Brand-consistent with the existing mobile shell (glass/quantum theme).

### 6.5 Settings → Security

New **Application PIN** section: Change PIN, Remove PIN (account-password-verified via ephemeral client, matching the chat-reset pattern), switch 4↔6 digits, enable/disable, auto-lock timeout slider, Reset forgotten PIN. New **Trusted Devices** manager listing registered devices with revoke.

## 7. Android native layer

### 7.1 `MainActivity.kt`

- **Screenshots are intentionally allowed.** `FLAG_SECURE` is **not** set (explicit product decision). Consequently the Recent-Apps thumbnail is also not blanked — see §11.
- Emit an app-background signal on `onStop()` as a belt-and-suspenders trigger for the lock (primary trigger is the JS `visibilitychange` listener).

### 7.2 `AndroidManifest.xml`

- Add `USE_BIOMETRIC` permission commented/stubbed for the fast-follow (no behavior yet). No other manifest changes required for v1.

### 7.3 Background lock behavior

Lock on real app-background — JS `document.visibilitychange` → `hidden`, plus the native `onStop` signal. Explicitly **not** on window `blur`, to avoid the native-dialog trap (permission prompts, later biometric prompts) locking the app spuriously.

## 8. Supabase — `trusted_devices` table

New migration adds:

```
trusted_devices(
  id uuid pk default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  device_id text not null,             -- stable per install (from Rust identity/device id)
  device_name text,
  platform text,                        -- 'android'
  app_version text,
  registered_at timestamptz not null default now(),
  last_login_at timestamptz,
  revoked_at timestamptz,
  unique (user_id, device_id)
)
```

RLS: enabled; policies restrict `select/insert/update/delete` to `auth.uid() = user_id`. Frontend upserts on setup and on each successful launch (updating `last_login_at`). On unlock, the frontend checks the row for `revoked_at`; if revoked, it forces full re-auth and wipes the local applock. Device Trust Center / Settings list and revoke devices.

## 9. Logout behavior (spec §Logout)

`signOut` (in `auth-context.tsx`) additionally:
- `applock_wipe` → delete applock config + stored session + local device record.
- Delete/soft-revoke the Supabase `trusted_devices` row for this device.
- Clear in-memory SEK.
Next launch requires a full email/password login.

## 10. Explicit design points / trade-offs

1. **Expired-token → re-confirm PIN.** When the refresh token expires while locked, the PIN cannot restore a valid session, so the app drops to full email/password login (spec requirement). Immediately after re-auth, the app re-confirms the *existing* PIN once and re-binds the fresh session under it (`applock_reset`). This keeps the session PIN-bound with no plaintext fallback and honors "continue using the existing PIN."
2. **Disabling the PIN clears the stored session.** With the PIN removed there is no key to bind the session to, so persistence is off and the next launch requires full login. This is the honest secure behavior (no DEK-only session fallback).
3. **App PIN and Chat PIN are independent** (per the locked decision). A user may set both; they are separate gates. They may choose the same digits, but the app never assumes so.
4. **Screenshots are allowed (no `FLAG_SECURE`).** Per explicit product decision, users can screenshot the app. The primary at-rest/on-return protection is the **background auto-lock** (the PIN gate covers content when the app is reopened), not screen-capture blocking.
5. **Root detection is advisory.** A best-effort signal surfaced as a warning in the gate/settings; it never blocks usage (spec: "if supported by the existing security architecture").
6. **Remote device revocation is client-side and online-only (known limitation).** Revoking a device sets `revoked_at` in the `trusted_devices` row; the target device reads that row on its next unlock and, if revoked, clears its local session (`signOut` local scope) + wipes its applock, forcing full email/password login. Two honest limits follow from this design in the current build: (a) the revocation check is a network read, so a device that is **offline** cannot observe the revocation until it reconnects; and (b) revoking the row does **not** invalidate the already-issued Supabase refresh token server-side, so a token already restored on the device keeps working until it expires per backend policy. The **primary** lost/stolen-device protection is therefore the local anti-brute-force wipe (5 wrong PINs → stored session destroyed), which covers a thief who does **not** know the PIN — the main threat model. Closing (a)/(b) fully requires server-side token invalidation (e.g. a session-epoch the app re-checks on refresh, or admin-side refresh-token revocation) and is deferred as a follow-up. Documented here so the "banking-grade remote revocation" capability is not over-claimed.

## 11. Out of scope (this build)

- Biometric unlock (fingerprint/face/device-credential) — seam left in the SEK envelope and the UI; implemented as a fast-follow.
- Desktop parity for the app-entry PIN.
- Re-architecting Quantum Vault to share the app PIN.

**Deliberate deviations from the source spec (per explicit user decision):**
- **Screenshot prevention via `FLAG_SECURE` (source spec line 73)** is omitted — screenshots remain allowed by design.
- **Recent-Apps preview masking (source spec line 74)** is consequently not implemented (it was a side-effect of `FLAG_SECURE`). Background auto-lock provides the on-return protection instead. This could be added later via a native masking overlay that does not affect in-app screenshots, if desired.

## 12. Verification plan

- **Rust:** `cargo test` for the applock crypto/ladder (§5.4).
- **Build:** TypeScript compiles; Android debug APK builds.
- **Manual E2E on emulator + physical tablet:** first login → device registered → create/confirm PIN → relaunch shows PIN → correct PIN → dashboard; wrong PIN ×5 → session wiped → full login; background the app → returns locked; screenshots work normally (no FLAG_SECURE); Settings PIN management (change / switch 4↔6 / remove with password / reset); token expiry → full login → re-confirm PIN; logout → next launch requires full login; trusted device appears in Supabase and can be revoked from another device.
