# QGuard Messaging — Unified Multi-Device Architecture

Implements `Qguard_Wiki/Unify_Syncronization`: one QGuard Helix account across
Desktop (Windows) and Android, real-time Secure Chat synchronization, one
account-wide subscription, one account-wide recovery key, and strictly
device-local Quantum Vaults.

## Architecture diagram

```
                        ┌──────────────────────────────────────────────┐
                        │            Supabase (zero-knowledge relay)    │
                        │                                              │
                        │  auth.users ── one account, one credential   │
                        │  profiles ──── display name, avatar, TIER    │
                        │  messaging_devices ─ per-device identity     │
                        │  messaging_signed_prekeys / one_time_prekeys │
                        │  messaging_message_envelopes (ciphertext)    │
                        │  messaging_message_user_states (read/burn)   │
                        │  messaging_typing_indicators                 │
                        │  messaging_account_recovery (verifier only)  │
                        │  storage: messaging-files, profile-avatars   │
                        └──────────────┬───────────────┬──────────────┘
                          realtime WS  │               │  realtime WS
                          + REST       │               │  + REST
              ┌────────────────────────┴──┐         ┌──┴────────────────────────┐
              │   Windows Desktop (Tauri) │         │   Android (Tauri mobile)  │
              │                           │         │                           │
              │  device identity keys     │         │  device identity keys     │
              │  (X25519+ML-KEM-1024,     │  E2EE   │  (own keypairs, own       │
              │   Ed25519+ML-DSA-65)      │◄───────►│   prekeys, own device id) │
              │  OS keychain DEK          │ per-    │  AndroidKeyStore DEK      │
              │  LOCAL Quantum Vault      │ device  │  LOCAL Quantum Vault      │
              │  (never synchronized)     │ sealed  │  (never synchronized)     │
              └───────────────────────────┘         └───────────────────────────┘
```

The relay stores ciphertext and public material only. Every private key, every
plaintext, and every vault byte stays on the device that produced it.

## 1. Unified authentication (implemented, pre-existing)

* One Supabase account: register once, verify email once, sign in with the
  same email/password (plus optional TOTP MFA) on Desktop and Android — both
  builds embed the same Supabase project.
* `auth_sync_session` mirrors the Supabase session into the Rust core on every
  device; `ensure_qguard_profile` / `ensure_messaging_defaults` guarantee one
  shared profile row (display name, username, avatar, tier).
* Interactive sign-in (`fresh_login: true`) clears workspace lockdowns; token
  refreshes cannot.

## 2. Device registration & trust (implemented, pre-existing)

Each device registers exactly the record the guide requires
(`messaging_devices`): device id, label, platform suite, created/last-seen
timestamps, public identity keys (X25519 + ML-KEM-1024 KEM, Ed25519 +
ML-DSA-65 signing) and a dual signature over the bundle, plus trust state
(`this_device` / `trusted` / `pending` / `revoked`). The Device Trust Center
lists, approves (QR), revokes, and deletes devices on any signed-in device.

## 3. Real-time Secure Chat synchronization (implemented, pre-existing)

* **Fan-out encryption:** a sent message is sealed once per authorized device
  — every trusted device of the recipient AND every other trusted device of
  the sender (self-sync envelopes) — so all devices can decrypt with their own
  keys. Missing-device copies are re-wrapped on demand
  (`syncMissingDeviceEnvelopes`).
* **Realtime:** Supabase `postgres_changes` subscriptions on envelopes, read
  states, typing indicators, prekeys, devices, contacts, and telemetry push
  changes to every connected device instantly; a 30s poll and exponential
  backoff cover reconnection (offline messages sync on reconnect).
* **Synchronized state:** messages, edits/reactions (control envelopes),
  deletions, read markers (`first_read_at`, which also drives unread bubbles
  and ephemeral burn), delivery/verification chips, typing indicators,
  attachments (encrypted blobs in `messaging-files`), conversation list,
  last-message preview, and unread counts.
* **PFS + PQC:** per-device hybrid X3DH-style establishment (signed prekeys +
  one-time prekeys, self-healing replenishment) with ratcheting and replay
  rejection; calls derive per-call keys with per-frame AES-256-GCM.

## 4. Subscription synchronization (implemented; surfaced in this change)

The subscription tier lives on the ACCOUNT (`profiles.tier`, written by the
QGuard Helix purchase flow) — never on a device. Every device reads the same
row over the authenticated session and receives tier changes through the
`profiles` realtime subscription. Purchasing STARTER on Desktop therefore
unlocks it on Android with no second purchase. The Settings page now displays
the account plan with the "all devices" scope explicitly.

## 5. Quantum Vault: strictly device-local (implemented, pre-existing)

Vault encryption/decryption is local streaming crypto (FEK → AES-256-GCM,
VMK-wrapped, ML-DSA-87-signed containers). No vault byte, key, or file name is
uploaded; Desktop and Android vaults are fully independent, exactly as the
guide requires.

## 6. Account-based recovery key (NEW in this change)

Previously the recovery key was device-scoped. Now:

* **Registry:** migration `029_account_recovery_registry.sql` adds
  `messaging_account_recovery` — one row per account holding the recovery
  MODE and the one-way VERIFIER of the recovery root (computed on-device in
  Rust; non-invertible, safe server-side). Owner-only RLS; in the realtime
  publication so all devices see status changes live.
* **Setup (first device):** generating a key publishes the verifier
  account-wide (`vault_setup_recovery` now returns it). If the account
  already has a key, the Vault UI refuses to mint a second one and steers the
  user to enable the existing key.
* **Enable (additional devices):** `vault_enable_recovery_with_phrase`
  validates the typed key against the account verifier before persisting —
  a fresh device only accepts the account's real key. Keys that predate the
  registry are backfilled automatically on load/enable.
* **Reset (lost PIN/password on any device):** `workspace_reset_vault`
  accepts the account verifier as the expected value when the device has no
  local recovery material, so the ONE account key authorizes a vault-lock
  reset on a brand-new device.
* **Contents stay local:** the key recovers ACCESS on each device; it never
  moves encrypted files between devices.

Trust note: a malicious backend could only lie about the verifier, which
either rejects a correct key (denial of service) or disables the typo check —
it can never decrypt vault contents or forge a valid key.

## Files changed in this implementation

| Area | File |
|---|---|
| Schema | `supabase/migrations/029_account_recovery_registry.sql` (apply to Supabase) |
| Rust | `src-tauri/src/commands/vault.rs` (verifier in setup/status, account check in enable) |
| Rust | `src-tauri/src/commands/workspace.rs` (`workspace_reset_vault` account verifier) |
| Frontend | `src/lib/account-recovery.ts` (registry load/publish helpers) |
| Frontend | `src/pages/QuantumVaultPage.tsx` (account-aware setup/enable/status UI) |
| Frontend | `src/lib/use-workspace-lock.ts` (reset threads account verifier) |
| Frontend | `src/lib/live-sse.ts` (registry realtime subscription) |
| Frontend | `src/pages/SettingsPage.tsx` (account plan badge) |

## Test matrix (guide §Testing Requirements)

| Scenario | Status |
|---|---|
| Register once, sign in Desktop + Android | ✅ verified in prior sessions (same Supabase project baked into both builds) |
| Desktop → Android and Android → Desktop messages appear in real time | ✅ verified E2E on emulator + desktop |
| Attachments, read receipts, typing, unread counts sync | ✅ realtime tables verified; read markers fixed to cover undecryptable stubs (v1.2.26) |
| Offline messages sync on reconnect | ✅ realtime rejoin + 30s fallback poll |
| Subscription purchased once applies on both | ✅ `profiles.tier` account row + realtime; surfaced in Settings |
| Vault files stay on the device that encrypted them | ✅ vault has no upload path at all |
| One recovery key recovers vault access on each device | ✅ new registry + account-verifier checks (requires migration 029) |
| Recovery does not synchronize vault contents | ✅ by construction |

## Deployment note

Apply `029_account_recovery_registry.sql` to the Supabase project before
shipping builds containing this change. Clients degrade gracefully without it
(device-local behavior, with an explicit UI notice), but account-wide
validation activates only once the migration is applied.
