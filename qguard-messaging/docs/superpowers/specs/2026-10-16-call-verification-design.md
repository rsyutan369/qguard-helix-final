# Call Verification — Design

**Date:** 2026-10-16 · **Roadmap:** Phase 3 · **Scope:** Rust core + React call UI · Desktop + Android

---

## 1. Objective

Let a user **prove who is on a call** even when the voice (or video) can be faked. Voice cloning needs only seconds of audio, so "it sounded like them" is no longer evidence. The goal is a check an impostor cannot pass without holding the real contact's device.

Non-goals: detecting synthetic audio with ML (unreliable, and would imply a guarantee we cannot give). This is cryptographic proof of **possession of a verified contact's device**, nothing more — and the UI says exactly that.

## 2. Current state (verified in code)

- Call protocol v2: per-call ephemeral keys, caller signs with Ed25519 + ML-DSA-65, callee checks it against the registered identity — `commands/calls.rs` (header comment l.40–52; `CallSetup { forward_secret, peer_authenticated, safety_number }`).
- A **safety number / SAS** is derived from the call's shared secret: 60 bits as five 4-digit groups, `safety_number()` l.119. The in-call UI makes the user type/confirm it (`InCallOverlay.tsx` l.155–292, `sasAcknowledged`, `typedSas`).
- The call screen reports honestly what is known: `describeCallSecurity` (`src/lib/call-security.ts`) — empty until media connects; `peerVerified` means "the registered device signed this call", **not** "the user checked this person".
- The callee fetches the caller's registered identity from `messaging_devices` (`call-peer-identity.ts`); if that fails the call connects but is shown as **unverified**.
- Device pins: this device's own TOFU record of which devices belong to whom (`device_pins.rs`, CHANGELOG 1.3.11); `DeviceStanding = Pinned | New | KeyChanged`.
- Manual verification exists in the UI (`SecurityVerificationPage`, Device Trust Center QR) and stores outcomes in Supabase tables — **relay-held**, so it cannot be trusted to say "the user verified this" locally.

### The gaps

1. The SAS defends against a man-in-the-middle on the key exchange, **not against a different person on a real device** (a scammer with a cloned voice, or a hijacked account on a new device). Reading digits aloud adds nothing against that.
2. Verification is not remembered: nothing says "you verified this person's device on 12 Sep".
3. There is no way to ask the other side for a proof that depends on a secret only the real contact's device holds.

## 3. Design

### 3.1 Verified-contact state (local, authoritative)

Add a `user_verified: { at, method }` field to the **device pin record** in `device_pins.rs` (encrypted at rest with the rest of local state). It is set **only** by the local verification flow (fingerprint/QR compare confirmed by the user in this app) and **never** from a relay row or a Supabase table. It is cleared automatically if the device's identity keys change (`KeyChanged`) or the device is revoked. New Tauri commands: `contact_verification_status(peer_user, peer_device)`, `contact_mark_verified(…)` (requires the pin to be `Pinned` and a fresh fingerprint match computed in Rust).

### 3.2 Pairing secret (so a phrase can exist)

When both sides have marked each other verified, one side (deterministically the lower device id) sends a **pairing message**: a hybrid encapsulation (X25519 + ML-KEM-1024, `encapsulate_bound`) to the peer's **verified identity keys**, dual-signed (Ed25519 + ML-DSA-65). It is delivered as a control message over the existing E2EE channel. The recipient accepts it only if the sender device is `Pinned` **and** `user_verified`. Both derive:

`pair_secret = HKDF-SHA3-256(ss, "QGuard-CallPairing-v1" ‖ device_a ‖ device_b ‖ fingerprints)`

and store it encrypted at rest next to the pin. Post-quantum safe by construction (same primitives the call key already uses). Destroyed with the pin on key change/revocation; re-pairing runs again after re-verification.

### 3.3 Challenge phrase

For a connected call, each device can compute `call_phrase_now(call_id)`:

`phrase = words4( HMAC-SHA3-256(pair_secret, "QGuard-CallPhrase-v1" ‖ call_id ‖ window) )`

- `window = floor(unix_time / 30 s)`; the UI shows the current phrase and accepts ±1 window for clock skew when comparing.
- 4 words × 10 bits from an embedded 1024-word list (**40 bits**: sufficient because the attacker gets one live guess per 30 s and the call is attended — it is not an offline target).
- **Bound to the call id**, so a phrase overheard in one call is worthless in another.
- UI flow, symmetric: **"Ask for their phrase"** → the user asks the caller aloud → the other person reads *their* screen → the user compares with *their own* screen. No phrase is transmitted by the app, so there is nothing for an attacker on the wire (or a cloned voice) to supply. Either side may challenge first.
- If the contact has no `pair_secret` yet, the panel says why and offers "Verify this contact" (deep link to the existing verification flow) — it never shows a phrase it cannot back.

### 3.4 What the call UI shows

Extends `describeCallSecurity` (same `CallSecurityLine` shape, still empty until media connects) with a contact-assurance line, derived from Rust-reported facts:

| State | Line |
| --- | --- |
| `Pinned` + `user_verified` + `pair_secret` | ✔ "You verified this person's device on {date}. Ask them for their phrase to be sure it's still them." |
| `Pinned`, not verified | ⚠ "Registered device, but you haven't verified this person. A cloned voice can't prove who it is — verify them or ask a question only they'd know." |
| `New` / `UnapprovedDevice` | ⚠ "A new device you haven't approved is calling." (incoming modal gets a stronger warning before answering) |
| `KeyChanged` | ✖ "This device is presenting different keys than the ones on record. Don't share anything sensitive." |
| identity lookup failed | existing "Caller not verified" text, unchanged |

Plain-language copy only; no unexplained "ML-KEM" etc. Surfaces: `IncomingCallModal.tsx` (assurance before answering), `InCallOverlay.tsx` (phrase panel beside the SAS panel at l.287), `CallProvider.tsx` (wires the new status into `call-state.ts`).

### 3.5 Honest limits (also shown in the UI help text)

- Protects only contacts you have verified. An unverified contact gets a warning, not a guarantee.
- If the contact's **device and PIN are in the attacker's hands**, the phrase will be correct — this proves the device, not the human. App lock and device revocation remain the control.
- It does not tell you whether audio is synthetic.

## 4. Data & telemetry

All state is local (device pin record + pair secret). The only network artifact is the existing pairing control message (ciphertext + signatures). Audit log entries (existing hash-chained `audit.rs`): `contact_verified`, `contact_pairing_established`, `call_phrase_challenge_shown` — **no phrase or secret ever logged**. Nothing is added to Supabase tables.

## 5. Test plan

Rust (negative controls first-class):
- phrase equal on both sides for the same (secret, call id, window); differs for a different call id, different secret, window beyond ±1
- pairing refused: sender not `Pinned`; sender not `user_verified`; bad dual signature; replayed pairing message; key-changed device
- verification cleared on key change/revocation
- `contact_mark_verified` rejects a stale/forged fingerprint
- word list: 1024 unique entries, no prefix collisions in the first 4 letters
Frontend (vitest): `describeCallSecurity` table for every row of §3.4; phrase panel disabled without secret; ±1 window acceptance.
Live: two desktop instances (QA accounts) — verify, pair, call, compare phrases; then break it (revoke/rekey one device) and confirm the warning. Android↔Desktop real-device run **blocked until a device/emulator is available**.
Run Rust via `%LOCALAPPDATA%\qguard-build-shims\run-rust-tests.ps1`.

## 6. Risks

- Support burden if clocks drift → ±1 window plus visible countdown; phrase comparison is human-in-the-loop so a miss is recoverable.
- Pairing message lost → status shows "pairing pending"; retried on next app start; never blocks calls.
- Users ignoring the panel → default the panel to visible for unverified incoming callers (decision in §7).

## 7. Open questions

1. Should an unverified first-time caller require an extra tap to answer (friction vs. scam resistance)? Recommend yes, for callers not in the verified list.
2. Word-list source: embed our own curated list (preferred, no licensing question).
3. Does Phase 3 also gate *sensitive in-call actions* (e.g., screen share in Phase 7) on `user_verified`?

## 8. Checklist

- [ ] 3.1 pin `user_verified` + commands · [ ] 3.2 pairing exchange · [ ] 3.3 phrase function + word list · [ ] 3.4 UI (modal, overlay, `describeCallSecurity`) · [ ] 3.5 audit events · [ ] 3.6 tests · [ ] 3.7 gate
