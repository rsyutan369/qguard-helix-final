# PQ Status Badge — Design

**Date:** 2026-10-16 · **Roadmap:** Phase 1 · **Scope:** Desktop + Android (shared React UI)

---

## 1. Objective

Show, per conversation, **how well the conversation is protected against a future quantum computer** — in plain English, derived only from evidence the app really holds. A user (or a CISO reading the dashboard) should be able to answer: *Is this chat post-quantum protected? Is the person on the other end who I think they are? What is the weakest link?*

Non-goals: a marketing badge, a score out of 100, anything computed from assumptions. When there is no evidence the badge says so.

## 2. Current-state facts this builds on (verified in code)

- Every message is sealed with a **fresh hybrid encapsulation** (X25519 + ML-KEM-1024) to the recipient device's prekey: `commands/messaging.rs` `messaging_send_encrypted_message` (≈ l.332 `encapsulate_with`).
- The ciphertext records what it was actually made with: `HybridCiphertext.suite` carries `pq_kem`, `pq_kem_standard`, `kem_combiner` (`crypto/mod.rs` `AlgorithmSuite`). Pre-FIPS Kyber material is distinguishable only by `pq_kem_standard`/`kem` markers — **length checks cannot tell** (`hybrid_kex.rs` comments).
- The combiner used is chosen from the peer's *published* suite: `KemCombiner::for_peer_suite` (`BoundV2` = `QGuard-HybridKEM-v2`, else `LegacyConcat`).
- Signatures are dual (Ed25519 + ML-DSA-65), both must verify (`dual_verify`).
- Sender trust is already classified by Rust: `SenderVerification` (`RegisteredDevice`, `UnapprovedDevice`, …) and device standing `Pinned | New | KeyChanged` (`device_pins.rs`).
- Forward secrecy is **per prekey rotation epoch**, not per message; the app already reports it honestly: `describeForwardSecrecy` / `prekeyStatus.forwardSecrecyHealthy` in `src/lib/security-score.ts` (l.198–219).
- The call screen already uses the pattern this feature generalizes: `describeCallSecurity` (`src/lib/call-security.ts`) — returns nothing until there is evidence, never over-claims.
- Peer device list for a conversation: `src/lib/delivery-devices.ts` (liveness-based selection, fan-out cap 8).

## 3. Status model

A pure function `derivePqStatus(evidence) → PqStatus` in `src/lib/pq-status.ts`.

```ts
type PqLevel =
  | "unknown"        // no evidence yet (new chat, nothing sent/received, not inside the app)
  | "classical"      // something in the path is not post-quantum (should be unreachable; shown loudly if seen)
  | "degraded"       // post-quantum, but a known weaker form is in use
  | "hybrid"         // ML-KEM-1024 + X25519, current combiner, dual-signed, peer not yet approved/verified
  | "verified-hybrid"; // as hybrid AND every peer device is pinned/approved

interface PqStatusLine { ok: boolean; text: string }   // same shape as CallSecurityLine
interface PqStatus {
  level: PqLevel;
  headline: string;            // one sentence for the chip tooltip
  lines: PqStatusLine[];       // the explainer, each line traceable to one evidence field
  weakest: { deviceId: string; reason: string } | null;
  forwardSecrecy: "per-message" | "per-prekey-epoch" | "overdue" | "not-measured";
}
```

### Level rules (all must hold; first failing rule decides)

| # | Evidence | Result if it fails |
| --- | --- | --- |
| 1 | At least one sent or received envelope in the last N (=20) for this conversation **or** peer device suites available | `unknown` |
| 2 | Every considered envelope's `suite.pq_kem == "ML-KEM-1024"` **and** `pq_kem_standard` is the FIPS 203 marker | `classical` if no PQ KEM; `degraded` if pre-FIPS marker |
| 3 | Every considered envelope has both signatures present (the Rust core already refused otherwise) | `degraded` |
| 4 | Every peer delivery device's published suite advertises `kem_combiner == "QGuard-HybridKEM-v2"` | `degraded` (reason: "device X is on an older version") |
| 5 | No peer device is `KeyChanged` | `classical`-blocking warning line; messages from it are already refused by Rust |
| 6 | Every peer device standing is `Pinned` (approved) | stays `hybrid` instead of `verified-hybrid`; line says which device awaits approval |

`weakest` is the single worst device by the rules above, because a conversation is only as strong as its weakest recipient device (messages fan out to all of them).

**Forward-secrecy line** comes from the existing `describeForwardSecrecy` today. After Phase 2 it also reads the ratchet header evidence ("per-message" only when envelopes carry a ratchet header **and** the session has advanced).

### What the frontend must NOT do
It never decides trust. "Pinned/approved", "registered", "verified" are Rust-core outputs already returned with each message and device assessment (`SenderVerification`, device standing). The badge only *aggregates* them.

## 4. Evidence collector

`usePqStatus(conversationId)` hook: gathers (1) peer delivery devices + their `suite` from `messaging_devices` (already queried for fan-out), (2) the last N envelopes' `hybrid_ciphertext.suite` already held for rendering, (3) device standing per peer device from the existing Rust assessment command, (4) `prekeyStatus` for the local device. **No new network pipeline, no new backend endpoint.** Recomputed when the conversation's realtime stream delivers a row or a device row changes (existing Supabase Realtime subscription — one subscription, not a second one).

## 5. Surfaces

1. **Chat header chip** — icon + short label (`Quantum-safe · verified`, `Quantum-safe`, `Weaker`, `Not protected`, `No messages yet`). Color + icon + text (never color alone).
2. **Popover explainer** — the `lines`, each ending with what to do ("Approve this device in Device Trust Center" with a link). Plain-English glossary line for "hybrid" and "ML-KEM" (project UX rule: no unexplained jargon).
3. **Quantum Security dashboard** — "Conversations by protection level": counts per level computed from the same function over real conversations; empty state with setup guidance when there are none.
4. **Security report export** — one section listing conversations and levels (existing `security_export_report`).

## 6. Edge cases

- Group conversations: use the weakest participant device (revisit in Phase 7).
- Peer offline / no device rows: `unknown`, never `hybrid`.
- Disappeared messages: evidence is read from rows still present; if none remain, falls back to device suites; never invents.
- Browser preview (no Tauri): device standing unavailable → forward secrecy `not-measured`, level capped at `hybrid`.

## 7. Test plan

Unit (vitest, table-driven — one test per rule, plus negative controls):
- all green evidence → `verified-hybrid`; same with one unapproved device → `hybrid` and names the device
- legacy combiner in peer suite → `degraded`; **must not** read `hybrid`
- `pq_kem_standard` empty/pre-FIPS → `degraded`, even though `pq_kem` says "ML-KEM-1024" (the exact trap documented in `hybrid_kex.rs`)
- missing PQ KEM → `classical`; no evidence → `unknown`
- one good device + one bad device → level of the bad one; `weakest` set
- key-changed device → warning line present
- forward-secrecy mapping: healthy / overdue / not-measured

Integration: chip renders each level; popover text matches `lines`; dashboard aggregation equals a manual count over fixtures.

## 8. Verification gate

`npx tsc --noEmit`, `npm test`, `npm run build` · live UI check with the QA accounts (headless Chrome/CDP) reaching at least `unknown`, `hybrid`, `verified-hybrid`, and a forced `degraded` (device with legacy suite) · no console errors · screenshot evidence kept out of the repo.

## 9. Risks

- Over-claiming: mitigated by rule order and negative controls above.
- Copy drift between chip, popover, dashboard: single derivation function, one source of strings.
- Evidence staleness: recompute on realtime events; show "as of last message" in the popover.

## 10. Checklist

- [ ] `pq-status.ts` + tests · [ ] `usePqStatus` · [ ] header chip + popover · [ ] dashboard section · [ ] report export · [ ] docs (`docs/cryptographic-design.md` §Status) · [ ] gate passed
