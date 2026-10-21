# QGuard Messaging — Feature Roadmap & Progress Tracker

**Created:** 2026-10-16 · **Baseline:** v1.3.12 (Cargo / tauri.conf)
**How to read this file:** `[x]` = done and verified · `[ ]` = to do · `[~]` = in progress / partly done.
This is the living tracker. Update the boxes in the same change that finishes the work, and only tick a box once its **verification gate** has passed (project rule: implementation alone is not success).

Detailed designs (grounded in the current code):

| Feature | Spec |
| --- | --- |
| PQ Status badge | [2026-10-16-pq-status-badge-design.md](../specs/2026-10-16-pq-status-badge-design.md) |
| Post-quantum session ratchet | [2026-10-16-pq-ratchet-design.md](../specs/2026-10-16-pq-ratchet-design.md) |
| Call verification (verified contacts + challenge phrase) | [2026-10-16-call-verification-design.md](../specs/2026-10-16-call-verification-design.md) |

Later phases have a scope paragraph only; each gets its own spec when its phase starts, so the spec is written against the code as it will be then, not as it is today.

---

## Progress at a glance

| Phase | What | Size | Status |
| --- | --- | --- | --- |
| 0 | Research, code inventory, specs, baseline | S | **done** (baseline `449c918`) |
| 1 | PQ Status badge | S–M | **done** (2026-10-16) |
| 2 | Post-quantum session ratchet | L | **built, opt-in** (2026-10-19); live two-device run, hardware test and independent review open |
| 3 | Call verification | M | **built** (2026-10-19); live two-instance call check open |
| 4 | Privacy & lock hardening (quick wins) | S–M | **built** (2026-10-19); Android device run + Play deploy open |
| 5 | Recovery: social + passkey | M | **built** (2026-10-19): history backup + social recovery; passkeys need a decision |
| 6 | Metadata protection: sealed sender, key transparency | L | discovery review + fixes **done**; sealed sender and KT **designed, need decisions** |
| 7 | Groups, group calls, screen share | L | not started |
| 8 | Private on-device AI | M–L | not started |
| 9 | Resilience mode (offline / mesh) | L | not started |
| 10 | QGuard Helix integration & enterprise controls | M–L | not started |
| 11 | iOS | L | not started |

Order rationale: the badge goes **before** the ratchet because it reports today's truth ("forward secrecy per daily prekey rotation") and then flips honestly when the ratchet ships — it is also the measuring stick for the ratchet. Call verification follows because it reuses the same "evidence → plain-English status" pattern and the identity-KEM path the calls already use.

---

## Phase 0 — Research, inventory, specs, baseline

- [x] Competitive research (Signal SPQR, Apple PQ3, Triple Ratchet, Bitchat/Briar, Signet, twonly, on-device AI)
- [x] Feature inventory of the current app (what exists / what is missing)
- [x] Read the real protocol code: `ratchet.rs`, `message_crypto.rs`, `commands/messaging.rs`, `crypto/hybrid_kex.rs`, `commands/calls.rs`, `call-security.ts`, `security-score.ts`
- [x] Spec: PQ Status badge
- [x] Spec: PQ ratchet
- [x] Spec: Call verification
- [x] This roadmap
- [x] **Baseline committed** — `449c918` "qguard-messaging: v1.3.11 security release and v1.3.12 Android fixes" (88 files). Left out on purpose: rebuilt release `.apk`/`.aab` (28 MB of build output), `public/TO_FIX/` screenshots, and a line-ending-only change to `gradlew` (CRLF would break it on Linux).
- [x] Baseline suites green (2026-10-16, before any roadmap code): Rust **196 passed / 0 failed** (`%LOCALAPPDATA%\qguard-build-shims\run-rust-tests.ps1`), vitest **297/297** in 33 files, `tsc --noEmit` clean.
- [~] Decision: ratchet = implement from Signal's published SPQR/Triple-Ratchet spec vs. a simplified KEM ratchet for v1 — see ratchet spec §11. **Taken by default, awaiting the owner's confirmation:** v1 follows the published Double Ratchet + sparse ML-KEM step (SPQR/PQ3 shape) but sends the whole ML-KEM-1024 key occasionally instead of SPQR's erasure-coded chunks (spec §11.1 recommendation: "v1-simple, revisit after measuring real bandwidth"). No libsignal code was read or ported.

## Phase 1 — PQ Status badge  *(spec: pq-status-badge)*

- [x] 1.1 `src/lib/pq-status.ts` — pure derivation (evidence in → level + plain-English lines out), no I/O
- [x] 1.2 Unit tests incl. negative controls — 20 tests (legacy combiner never reads quantum-safe; pre-FIPS "ML-KEM-1024" label never passes; outgoing copies are not evidence; history alone never vouches for the next message)
- [x] 1.3 Evidence assembly in `SecureChatPage` from the same device lists and pin verdicts that decide delivery; opened envelopes now record the combiner they were made with (`ChatMessage.kem_combiner`)
- [x] 1.4 Chat-header chip + explainer (`src/components/PqStatusBadge.tsx`); replaced the hard-coded always-green "E2EE active" line
- [x] 1.5 Quantum Security dashboard: **"Your Contacts' Devices"** (device-level — see spec §0 for why not conversation-level), with empty state
- [x] 1.6 Security report export: `contact_device_protection`
- [x] 1.7 Gate passed 2026-10-16: vitest 317/317 · tsc clean · build OK · live render of 6 scenarios in the real app (light, dark, 390 px) — one defect found and fixed (explainer ran 99 px off-screen on phones)

## Phase 2 — Post-quantum session ratchet  *(spec: pq-ratchet)*

- [x] 2a Spike & decisions: protocol per the decision above; wire format = header in the envelope JSON, AAD `QGM2|…|sha3(header)`, header appended to the signable only when present (one-shot envelopes verify byte-for-byte as before); the seed is bound to the session, not the conversation (`init_kex_info`). History re-seal checked: `syncMissingDeviceEnvelopes` re-seals from the decrypted plaintext through the normal send path, so it never depends on session state.
- [x] 2b Session store: `SessionBook` encrypted at rest (`<user>.ratchet-sessions.enc`, device storage key), always written AFTER the message-key ledger; sender saves before the envelope leaves; ≤1000 skipped keys / 30 days; zeroize on drop; unavailable-file and other-device-identity handling.
- [x] 2c Symmetric chain + classical DH ratchet (`pq_ratchet.rs`)
- [x] 2d Sparse ML-KEM-1024 step (every 50 messages / 24 h, carried in the header)
- [x] 2e Negotiation via `suite.ratchet`; any send-side failure falls back to one-shot; reset/recovery: "session unavailable" error → forget + one `session_reset` control on a fresh session; sessions of revoked / re-keyed devices destroyed; manual reset in Device Trust Center and Settings.
- [x] 2f Migration `036_ratchet_envelope_header.sql` (header-shape CHECK + insert policy admits a null encapsulation only on a ratchet `msg`). Verified on Postgres 16 in Docker: 10/10 policy cases incl. 7 negative controls; the CHECK binds the service role too; pre-existing rows validate. RLS read rules unchanged. **Not applied to the live project** — the app works without it (the client writes `hybrid_ciphertext: null`, which 007 already admits).
- [x] 2g Tests — Rust: 20 state-machine tests + 13 two-device end-to-end tests (two complete `AppState`s: roundtrip, burst delivered newest-first, ledger reopen, restart on both sides, PQ step over the wire, capability absent either side, own-device copy one-shot, header/body/strip tamper, valid-signature bad-tag does not move the session, foreign signing keys refused, lost session → marker → recovery, unanchored sender gets no session, simultaneous first messages converge, reset, catch-up never starts a session) + 3 interop tests against a verbatim copy of the 1.3.12 envelope type (one-shot parses and verifies there; 1.3.12 envelopes open here; ratchet envelopes fail closed there). Frontend: QGM2 AAD parsing, row → core request, badge.
- [x] 2h Flag: Settings → Advanced *Per-message ratchet* (off by default, re-publishes the suite), `QGUARD_RATCHET=1/0` operator override and kill switch. Badge: "Per-message ratchet" only for devices with a session that has completed a round trip. Rollout beyond opt-in (beta → default) waits for 2k.
- [x] 2i Docs: `cryptographic-design.md` (both modes), `security-limitations.md` (default FS = prekey rotation; ratchet opt-in and unreviewed; header metadata; ledger trade-off), CHANGELOG. The 1.3.11 "not a per-message ratchet" statement stays true for the default and is kept.
- [~] 2j Gate: Rust **231/231** (was 196) · vitest **326/326** · tsc clean · `vite build` OK. The two-instance interop runs in-process (two complete app states, real send/receive paths, JSON relay). Not done: a two-window live desktop run against the real relay, and Android↔Desktop on hardware (**blocked until a device/emulator is available**).
- [ ] 2k Independent review of the protocol before it is advertised as default (documented in `security-limitations.md` as unaudited until then) — **needs an external reviewer**

## Phase 3 — Call verification  *(spec: call-verification)*

- [x] 3.1 Rust: `verified` on the device pin (`device_pins.rs`), bound to the pinned keys, set only by `contact_mark_verified` after the core re-derives the safety number the user confirmed; destroyed on key change (in `assess`), revocation, or "Remove verification"
- [x] 3.2 Rust: pairing exchange (`commands/contact_verification.rs`). Changed from the spec's "lower device id sends one encapsulation": EACH side seals a half to the other's verified identity keys (hybrid, bound combiner, dual-signed, ms-timestamped offers; older offers refused as replays); `pair_secret = HKDF-SHA3-256(half_low ‖ half_high, label ‖ device ids ‖ identity digests)`. Reason: no acknowledgement round is needed, and a half from a recorded-but-not-yet-verified device is held until the user verifies it, so the order in which the two people verify does not matter.
- [x] 3.3 Rust: `call_phrase` / `call_phrase_check` — 4 words (40 bits) from HMAC-SHA3-256(pair secret, call id, 30 s window), ±1 window, rate-limited; embedded 1024-word list (our own; unique 4-letter prefixes)
- [x] 3.4 UI: `describeCallSecurity` adds the person-level line (verified on {date} / registered but not verified — cloned-voice warning); `CallSetup` reports it from the keys the call was agreed with; incoming modal shows the record for the ringing device id and needs a second tap for a device never approved for that person (§7.1, applied to unrecorded devices only); *Verify* panel in the chat header
- [x] 3.5 UI: "Ask for their phrase" panel in `InCallOverlay.tsx` with countdown and typed check
- [x] 3.6 Tests: Rust — word list properties; same phrase both sides; different call id / window ±2 / other secret / replay in another call; pairing refused for unverified, unrecorded, re-keyed (impostor keys under the same device id), tampered, foreign-device and replayed-older offers; verification + pairing destroyed on key change and only re-made by a new exchange; stale/forged safety number refused. Frontend — `describeCallSecurity` for every §3.4 row incl. a negative control (never vouches on an unproven device), incoming assurance, pairing wording, device→identity mapping.
- [~] 3.7 Gate: Rust **242/242** · vitest **337/337** · tsc clean. Live two-instance check (verify → pair → call → compare phrases → re-key → warning) **not done**: needs two signed-in desktop instances on the real relay and a live call.

## Phase 4 — Privacy & lock hardening (quick wins)

- [~] 4.1 Recent-apps masking, Android (`PrivacyScreen.kt`): API 33+ `setRecentsScreenshotEnabled(false)`, older a cover view drawn in `onPause`. Screenshots stay allowed (PIN spec product decision). On by default, toggle in Settings → Device privacy. Kotlin compiles (`compileArm64ReleaseKotlin`). **Android 13+ path verified 2026-10-21** on the Android Studio emulator (API 37, x86_64 build of 1.4.3): after leaving the app its Recent-apps card is blank, and screenshots still work. (Opening Recents from inside the app shows the platform's live preview of the current screen, not a stored snapshot.) The API 29–32 cover-view path has not been run.
- [~] 4.2 Biometric unlock (`BiometricUnlock.kt` + `applock_biometric_*`): the SEK is wrapped by an AES-256-GCM Android Keystore key usable only through a `BiometricPrompt` `CryptoObject` (strong biometric, invalidated by new enrolment, every use authenticated); offered automatically on the lock screen. Kotlin compiles; **not run on a device**.
- [x] 4.3 Duress PIN + panic wipe. Confirmed first: `applock_wipe` only deleted the stored session (sign-out), so a real wipe was new. `AppState::panic_wipe` deletes the device storage key FIRST, then every `keys/<user>.*` file, clears memory without flushing, signs out; vault containers stay (open only with the user's recovery kit). Duress PIN: Argon2id verifier with its own context; both checks always run when one is set; a match wipes silently and returns the same "sign in again" result as an expired session; never revealed on the lock screen; cannot equal the real PIN. Settings → *Erase this device* (type ERASE; revokes the device row first, best effort). "Decoy vault" not built — the duress PIN wipes rather than opening a fake profile (a decoy needs a full parallel data set; see Phase 4 notes below). Rust tests cover it (duress recognised and only it; never revealed; attempt ladder; wipe leaves nothing that opens the account; no other account touched). **Not yet run on a device:** the 2026-10-21 emulator run was stopped before sign-in because the host was saturated (CPU 100 %, under 1 GB free).
- [x] 4.4 SHA3 everywhere it was missing: MFA recovery codes `sha3:<hex>` (migration 037 — Postgres 16 check: FIPS 202 vector, legacy + SHA3 codes single-use, mislabelled hash refused; the app writes SHA3 only after `qguard_mfa_recovery_hash_schemes()` says so, so app and migration can ship in either order); attachment checksum SHA3-256 (`sha3_b64`, SHA-256 still written for older builds, SHA3 decides when present); privacy-screen verifier → Argon2id + HKDF-SHA3-256 in the core, PBKDF2 configs upgraded on next unlock. Kept SHA-256 on purpose: the Play purchase-token ledger key (an opaque identifier shared with the Express API).
- [x] 4.5 Version drift: `package.json`/lock → 1.3.12, `tools/release.ps1` now sets them too (dry-run verified: exactly the two lockfile lines change). Also fixed: Android app-lock registrations recorded "0.0.0" (`window.__APP_VERSION__` never existed).
- [~] 4.6 Google Play verification ported into the `billing` Edge Function (`/play-billing/verify` + `/play-billing/rtdn`): WebCrypto RS256 service-account JWT, subscriptionsv2, account binding, one-token-one-account, acknowledge, list-price invoice, RTDN re-fetch + terminal-state fallback; `/health` reports `playVerification`. Checks: `deno check` clean; `tools/billing-edge-check.ts` 20/20 (8 new incl. a real RS256 sign → verify). **Not deployed**; needs the Play service account + `GOOGLE_PLAY_*`/`PLAY_RTDN_TOKEN` secrets (operator), then a live purchase test.

Phase 4 gate: Rust **250/250**, vitest **347/347**, tsc clean; Android Rust compile check — see 4.x notes in the CHANGELOG. Decoy vault: deliberately not built in this pass — it needs a second, plausible data set and a UI that never leaks which one is open; worth its own spec if wanted.

## Phase 5 — Recovery

Spec: [2026-10-19-recovery-design.md](../specs/2026-10-19-recovery-design.md). UI: Settings → Recovery (`RecoveryCenterCard.tsx`, `lib/recovery.ts`).
- [x] 5.1 Social recovery: the recovery key `R` wrapped under `HKDF(S ‖ Argon2id(PIN))`; `S` split k-of-n (`crypto/shamir.rs`, GF(2⁸), table-free arithmetic); each share sealed (hybrid, dual-signed) to one **verified** contact device; a new device asks with a fresh hybrid key; helpers release only after comparing four words out of band. Migration `038_social_recovery.sql` — Postgres 16 check **20/20** (12 negative controls: forged owner, strangers, guardian impersonating another guardian, closed requests…). Rust tests: Shamir every k-of-n to 5-of-7, k−1 shares uniform, FIPS-197 field vectors; end-to-end 3 helpers → 2-of-3 + PIN gives back the exact key; 1 share / wrong PIN / unverified helper / weak PIN / k>n / share for another helper / tampered share / forged request all refused; request consumed after use. **Not done:** a live run with real accounts and the migration applied.
- [ ] 5.2 Passkey-protected recovery — assessed in the spec §5; needs a decision (native Credential Manager / PRF-capable authenticators)
- [x] 5.3 Encrypted history backup: the message-key ledger sealed under `R` (AAD binds the account) → `.qgbackup`; restore merges additively and the history still on the relay opens from the ledger. Tests: export refused under a wrong key; restore on a fresh device of the same account; second import adds nothing; another account cannot load it; tampered salt refused. **Not done:** live restore against real relay history.

Phase 5 gate: Rust **258/258**, vitest **349/349**, tsc clean.

## Phase 6 — Metadata protection

Spec: [2026-10-19-metadata-protection-design.md](../specs/2026-10-19-metadata-protection-design.md).
- [ ] 6.1 Sealed sender — **designed, waiting on decisions** (spec §3.4: paywall model, conversation ids inside the ciphertext, server-signed sender certificate). The relay authenticates the sender on every insert today, so this needs a new anonymous submission path; not started in code because it is the change most able to break delivery.
- [ ] 6.2 Key transparency — **state of the art checked** (IETF keytrans architecture draft-05, Oct 2025; WhatsApp AKD and Apple CKV deployed; Signal reported Aug 2026, unconfirmed) and **designed, waiting on decisions** (spec §4.4: own log vs. reference implementation, signing-key custody and auditors, hosting).
- [x] 6.3 Private contact discovery review: 6 findings (spec §2). Fixed: the directory search no longer leaks email local parts or derives usernames from emails; 3-char minimum; 60 searches / 5 min (migration `039_directory_search_hardening.sql`, Postgres 16 check 12/12); client fallback no longer prefix-matches emails, shows the rate-limit message. **Decisions needed** for findings 4 (peers can read the whole `profiles` row incl. email) and 5 (exact-match-only search for strangers).

## Phase 7 — Groups, group calls, screen share

Spec: `docs/superpowers/specs/2026-10-19-groups-design.md`.

- [x] 7.0 Verify what group chat does today — confirmed: schema and RLS allowed groups, no UI; **found** that any account knowing a conversation id could add itself (fixed, migration 040)
- [x] 7.1 Group messaging — pairwise fan-out (MLS deferred: no standardized PQ ciphersuite); encrypted name, create/add/remove/leave, sender names; migration 040 verified on Postgres 16 (22/22); vitest + tsc + build green. Not live-tested between devices.
  - Owner decisions 2026-10-20, **done**:
    - only the owner renames (the client checks each name message against the server's ownership history);
    - up to 3 admins; ownership transfer (migration 042, Postgres 32/32).
- [x] 7.2 Group calls — mesh between up to 3 people (owner decision):
  - each pair is an unchanged 1:1 link with its own hybrid KEM and frame key;
  - a shared signal hub routes every signal to exactly one engine;
  - a link is auto-accepted only within a group call the user accepted.
  - Unit-tested (routing, admission, mesh pairing). **Not live-tested**: needs three machines.
- [x] 7.3 Screen share — 1:1 calls on desktop; replaces the camera track on the encrypted VP8 sender (no new codec path). Android needs MediaProjection (not done). Not live-tested.
- [x] 7.4 Channels / broadcast — built before MLS (owner decision):
  - per-epoch AES-256-GCM keys in the core; per-post HKDF-SHA3-256 keys; Ed25519 + ML-DSA-65 signed posts;
  - epoch keys handed out pairwise (hybrid ML-KEM); a new epoch when a reader leaves;
  - invite codes stored as SHA3-256 hashes; readers can't see each other;
  - migration 043, Postgres 31/31; Rust 8 tests; vitest.
  - **Not live-tested.**

## Phase 8 — Private on-device AI

Spec: `docs/superpowers/specs/2026-10-19-on-device-ai-design.md` (§7: cloud mode). **Owner decision 2026-10-20:**
- cloud models, with the user's own API key: Anthropic Claude Sonnet 5.5 (`claude-sonnet-5-5`) first, then OpenAI (the model id is entered by the user);
- no download is needed for cloud models.

- [x] 8.1 Threat model — revised for cloud mode (spec §7): message text leaves the device to the chosen provider only when the user asks, in conversations they allowed
- [x] 8.2 Summaries ("Catch me up"), suggested replies and translation:
  - the API key is encrypted in the core (5 Rust tests);
  - the conversation is sent framed as untrusted data, with `<`/`>` escaped — a test caught a closing-tag forgery;
  - the CSP admits only api.anthropic.com and api.openai.com;
  - 16 unit tests. **Not tested against the live APIs** (no key in this environment).
- [x] 8.3 Never sent: disappearing, one-time, scheduled or undecrypted messages, or attachments. Output is memory-only and wiped with the plaintext caches; suggested replies go to the composer, never sent automatically.

## Phase 9 — Resilience mode

Spec: `docs/superpowers/specs/2026-10-20-resilience-design.md`.

- [x] 9.1 Store-and-forward and nearby delivery (owner decision: Google Play services):
  - sealed envelope rows are kept in an encrypted outbox in the core when the relay never answered, and flushed when it answers (expired disappearing messages are dropped);
  - on Android, Nearby Connections hands the rows to phones in range; received rows go through the normal screening and decryption.
  - Rust tests (outbox 4, nearby 4) and vitest (outbox, nearby) pass; the Kotlin compiles.
  - **Not tested between two phones** (none available).
- [x] 9.2 Relay outage / block detection and UX — offline / relay failing / relay unreachable-but-internet-works / no internet / can't tell, from real probes (relay health + the existing update host); banner with backoff; 10 unit tests. Not tested against a real outage.

## Phase 10 — QGuard Helix integration & enterprise

Spec: `docs/superpowers/specs/2026-10-20-helix-enterprise-design.md`.

- [x] 10.1 Messenger posture into Helix — same login (owner decision; both apps use one Supabase project, verified):
  - Helix `POST /api/v1/agent-scanner/integrations/qguard-messaging/sync` reads the user's own `messaging_devices` with their token and derives evidence from each device's published suite;
  - pre-FIPS Kyber devices are graded classical, never PQC-ready;
  - "Import messenger devices" button in the Collector console;
  - `npm run check:messaging-posture` 13/13; Helix `tsc` clean.
- [x] 10.2 Owner decision: **no archive/escrow device**, so message content is never retained for organisations. Metadata retention and endpoint export remain as designed (not built).
- [x] 10.3 Role-based admin **done** (migration 041). SSO **prepared, not implemented** (owner decision): `docs/superpowers/specs/2026-10-20-sso-preparation.md` — Supabase Pro; Entra ID → Okta → Google Workspace.

## Phase 11 — iOS

- [x] 11.1 Feasibility — `docs/superpowers/specs/2026-10-20-ios-feasibility.md`: feasible; large items are APNs + Notification Service Extension (core memory in the extension must be measured) and CallKit/PushKit; needs Apple account, Mac builds, test iPhones

---

## Verification gates that apply to every phase

Frontend: tsc, vitest, `npm run build`, no console errors, empty/loading/error states. Backend/Rust: full suite green, new tests include negative controls. Security: no secrets or plaintext in logs/telemetry, tenant isolation unchanged, relay still sees ciphertext only. Docs: `security-limitations.md` and `cryptographic-design.md` change in the same change as the behavior. Data: nothing displayed may be hardcoded — every status must trace to evidence the app actually has.
