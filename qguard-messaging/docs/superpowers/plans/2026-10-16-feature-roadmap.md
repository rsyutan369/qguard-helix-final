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
| 0 | Research, code inventory, specs, baseline | S | **in progress** (planning done, baseline needs a decision) |
| 1 | PQ Status badge | S–M | not started |
| 2 | Post-quantum session ratchet | L | not started |
| 3 | Call verification | M | not started |
| 4 | Privacy & lock hardening (quick wins) | S–M | not started |
| 5 | Recovery: social + passkey | M | not started |
| 6 | Metadata protection: sealed sender, key transparency | L | not started |
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
- [ ] Decision: ratchet = implement from Signal's published SPQR/Triple-Ratchet spec (recommended) vs. a simplified in-house KEM ratchet for v1 — see ratchet spec §11

## Phase 1 — PQ Status badge  *(spec: pq-status-badge)*

- [ ] 1.1 `src/lib/pq-status.ts` — pure derivation (evidence in → level + plain-English lines out), no I/O
- [ ] 1.2 Unit tests incl. negative controls (legacy combiner never reads "verified"; pre-FIPS KEM never reads "hybrid"; key-changed device blocks)
- [ ] 1.3 Per-conversation evidence collector (peer device suites, recent envelope suites, pin standing, local prekey health)
- [ ] 1.4 Chat-header chip + explainer popover in `SecureChatPage`
- [ ] 1.5 Quantum Security dashboard: "conversations by PQ level" from real data, with empty state
- [ ] 1.6 Include in the security report export
- [ ] 1.7 Gate: vitest + tsc + build pass · live check in the real UI (headless Chrome/CDP, QA accounts) for each level reachable · no console errors

## Phase 2 — Post-quantum session ratchet  *(spec: pq-ratchet)*

- [ ] 2a Spike & decisions: finalize protocol choice, wire format, signable v2; verify trusted-device history re-seal does not depend on session state
- [ ] 2b Session store: encrypted-at-rest persistence, write-ahead, bounded skipped keys, zeroize
- [ ] 2c Symmetric chain + classical DH ratchet (per-message forward secrecy, post-compromise security per round trip)
- [ ] 2d Sparse ML-KEM-1024 step (post-quantum post-compromise security)
- [ ] 2e Capability negotiation via device `suite`, one-shot fallback preserved, session reset/recovery
- [ ] 2f DB migration (envelope without `hybrid_ciphertext` on non-init messages), RLS/constraint review
- [ ] 2g Tests: roundtrip, out-of-order, loss, replay, header tamper, PCS heal, PQ-step, desync recovery, 1.3.12 interop (both directions)
- [ ] 2h Feature flag + staged rollout; badge (Phase 1) shows "per-message ratchet"
- [ ] 2i Docs updated: `cryptographic-design.md`, `security-limitations.md`, CHANGELOG; the "not a per-message ratchet" statements removed only after 2g passes
- [ ] 2j Gate: Rust suite + two-instance desktop interop test · Android↔Desktop real-device test (**blocked until a device/emulator is available**)
- [ ] 2k Independent review of the protocol before it is advertised as default (documented in `security-limitations.md` as unaudited until then)

## Phase 3 — Call verification  *(spec: call-verification)*

- [ ] 3.1 Rust: local `user_verified` bit on the device pin, set only by the local verification flow (never from the relay)
- [ ] 3.2 Rust: pairing-secret exchange over the hybrid identity KEM, dual-signed, stored encrypted at rest
- [ ] 3.3 Rust: `call_phrase_now` — 4-word phrase from HMAC-SHA3-256(pair secret, call id, time window)
- [ ] 3.4 UI: "Verified contact" / "Not verified" on incoming-call modal and in-call overlay (extends `describeCallSecurity`)
- [ ] 3.5 UI: "Ask for their phrase" panel beside the SAS panel (`InCallOverlay.tsx`)
- [ ] 3.6 Tests incl. negative controls: wrong secret, wrong call id, expired window, replay in another call, key-changed device
- [ ] 3.7 Gate: Rust + vitest + tsc pass · two-instance live check

## Phase 4 — Privacy & lock hardening (quick wins)

- [ ] 4.1 Recent-apps / screenshot masking on Android (listed as not implemented in the PIN spec)
- [ ] 4.2 Biometric unlock (the PIN spec's "fast-follow" seam)
- [ ] 4.3 Duress PIN / decoy vault / panic wipe (builds on the existing app-lock wipe command in `applock.rs` — confirm exact behavior before designing)
- [ ] 4.4 Replace remaining SHA-256 leftovers (MFA recovery hashes, attachment `sha256_b64`, privacy-screen PBKDF2-SHA-256 verifier) with SHA3 — with migration for existing data
- [ ] 4.5 Version drift: `package.json` 0.1.0 vs Cargo/tauri 1.3.12
- [ ] 4.6 Google Play purchase verification (`/play-billing/verify` returns 501)

## Phase 5 — Recovery

- [ ] 5.1 Social recovery: split the recovery secret across trusted devices/contacts (Shamir) with a PIN second factor
- [ ] 5.2 Passkey-protected recovery
- [ ] 5.3 Encrypted history backup/restore across devices

## Phase 6 — Metadata protection

- [ ] 6.1 Sealed sender (today `sealed_sender` is deliberately `false`; the relay sees who talks to whom)
- [ ] 6.2 Key transparency — requires verifying the current state of the art first (my searches did not confirm it)
- [ ] 6.3 Private contact discovery review

## Phase 7 — Groups, group calls, screen share

- [ ] 7.0 Verify what group chat does today (schema has `group`; no group UI found by the inventory — not confirmed)
- [ ] 7.1 Group messaging (evaluate MLS / RFC 9420 and its post-quantum status before choosing)
- [ ] 7.2 Group calls
- [ ] 7.3 Screen share (`getDisplayMedia`; frame crypto is VP8-specific today — check codec coverage)
- [ ] 7.4 Channels / broadcast

## Phase 8 — Private on-device AI

- [ ] 8.1 Threat model: model reads plaintext → opt-in, off by default, nothing leaves the device
- [ ] 8.2 Summaries / "catch me up", smart replies, translation (Android: AICore/Gemini Nano where present; desktop: bundled small local model)
- [ ] 8.3 Never write AI output into the plaintext cache without the user's say-so; honor disappearing-message expiry

## Phase 9 — Resilience mode

- [ ] 9.1 Store-and-forward + nearby (Bluetooth) delivery on Android; relay fallback
- [ ] 9.2 Relay outage / block detection and UX

## Phase 10 — QGuard Helix integration & enterprise

- [ ] 10.1 Messenger crypto posture + CBOM published into Helix (Trust Center / Audit Vault) — real data only
- [ ] 10.2 Retention, legal hold, compliance export
- [ ] 10.3 SSO/SAML; replace the single hard-coded admin email in `src/lib/admin.ts` with role-based admin

## Phase 11 — iOS

- [ ] 11.1 Feasibility (Tauri mobile iOS, Keychain/Secure Enclave DEK parity, App Store billing)

---

## Verification gates that apply to every phase

Frontend: tsc, vitest, `npm run build`, no console errors, empty/loading/error states. Backend/Rust: full suite green, new tests include negative controls. Security: no secrets or plaintext in logs/telemetry, tenant isolation unchanged, relay still sees ciphertext only. Docs: `security-limitations.md` and `cryptographic-design.md` change in the same change as the behavior. Data: nothing displayed may be hardcoded — every status must trace to evidence the app actually has.
