# Post-Quantum Session Ratchet — Design

**Date:** 2026-10-16 · **Roadmap:** Phase 2 · **Scope:** Rust core (`src-tauri`), Supabase migration, thin UI changes · **Status:** DRAFT — needs review before any code

---

## 1. Objective

Give Secure Chat **per-message forward secrecy** and **post-compromise security** that survive a quantum adversary, without losing any property the app has today (per-device fan-out, signed envelopes, device pins, the message-key ledger, replay/relocation refusal, interop with older builds).

## 2. Current state (verified in code)

The app has **no session**. Every message is independent:

1. `messaging_send_encrypted_message` verifies the recipient bundle, picks a (one-time or signed) prekey, and runs a **fresh hybrid encapsulation** — X25519 + ML-KEM-1024, `QGuard-HybridKEM-v2` combiner — `commands/messaging.rs` ≈ l.332.
2. It builds a throw-away `RatchetSession::new(shared)` + `rotate_root(shared)` and uses **counter 0** of its chain — `messaging.rs` l.348–349; `ratchet.rs`. The "ratchet" lives for one message.
3. The receiver repeats the derivation (`per_message_key`, `messaging.rs` l.650) after decapsulating with the named prekey (`decapsulate_for`).
4. Forward secrecy comes from **prekey rotation** (daily per `describeForwardSecrecy`), an **encrypted message-key ledger** (`message_keys.rs`) recorded at first open, and destruction of retired prekeys once nothing depends on them (CHANGELOG 1.3.11: *"This is not a per-message ratchet"*).
5. The envelope is stored as JSONB (`sealed_sender_envelope`); migrations 004/007 enforce `sealed_sender_envelope ? 'hybrid_ciphertext'`.
6. `AlgorithmSuite` is published per device and is the established capability-negotiation channel (`kem_combiner`, chosen via `KemCombiner::for_peer_suite`).
7. `state.ratchets: Mutex<HashMap<String, RatchetSession>>` is **in-memory only** (`state.rs` l.456); `RatchetSession` is already `Serialize`/`Deserialize` and zeroizes on drop.

### What this costs today

| Property | Today | Ratchet target |
| --- | --- | --- |
| Forward secrecy granularity | a prekey epoch (≈ a day): anyone who obtains a prekey secret during an epoch can open every not-yet-ledgered message sealed to it | per message: chain key deleted as it advances |
| Post-compromise security | heals at next prekey rotation | heals at the next ratchet step (classical: next round trip; post-quantum: next ML-KEM step) |
| Per-message overhead | ≈ 32 B X25519 + **1568 B ML-KEM-1024 ciphertext, to every recipient device, every message** | ≈ 100 B header typical; 1568 B ek and 1568 B ct only at PQ steps |
| One-time-prekey pressure | each first contact burns a one-time prekey | burned once per session init |

(ML-KEM-1024 ek and ct are each 1568 bytes per FIPS 203.)

## 3. Prior art we follow (not invent)

- Signal **SPQR / Triple Ratchet** — Double Ratchet + a sparse post-quantum ratchet ("ML-KEM Braid") + symmetric ratchet; announced 2025-10-02; sessions fall back to the old ratchet while peers upgrade. ([Signal](https://signal.org/blog/spqr/), [PQShield analysis](https://pqshield.com/?p=9081), Triple Ratchet [EUROCRYPT 2025 paper](https://pqshield.com/publications/triple-ratchet-a-bandwidth-efficient-hybrid-secure-signal-protocol/))
- Apple **PQ3** — periodic ML-KEM rekeying folded into the ratchet root.

**Rule: implement from the published specifications; do not copy code.** I believe libsignal is AGPL-3.0, which would constrain a closed-source app — verify the license before anyone looks at, let alone ports, its code. We also do not invent a new protocol: any deviation from the published design is listed in §11 and needs an explicit reason.

## 4. Design

### 4.1 Session model

One session per **(local device, peer device)** pair, keyed by the pair's device ids (not by conversation — multi-device fan-out already seals per device). State, encrypted at rest under the existing per-user DEK (same store as the message-key ledger):

```
Session {
  v: 1, session_id, local_device, peer_device, created_at,
  root_key[32],
  send_chain{key, n}, recv_chain{key, n}, prev_send_len,
  dh_self{priv,pub}, dh_peer_pub,
  pq{ epoch, self_dk?, peer_ek?, phase },        // ML-KEM-1024 decapsulation key / peer encapsulation key
  skipped{(peer_dh, n) → key}, cap 128 (existing MAX_SKIPPED_KEYS), age-limited
  last_pq_step_at, msgs_since_pq_step
}
```

Existing `RatchetSession` fields (`root_key`, chains, counters, `skipped_message_keys`) are reused and extended; the `seen_message_ids` replay set stays (it is `#[serde(skip)]` today — must be persisted or replaced by the (peer_dh, n) uniqueness rule).

### 4.2 Session initiation = today's path, unchanged

First message to a device (or any **reset**) uses the existing one-shot flow: verify bundle → pin check (`require_accepted_device`) → `encapsulate_with(prekey…)` → `shared_secret`. The envelope header is marked `init`. `shared_secret` seeds the root:

`RK₀ = HKDF-SHA3-256(shared_secret, "QGuard-PQRatchet-v1:init" ‖ transcript)`, transcript = conversation id, both device ids, both identity fingerprints, `hybrid_ciphertext` hash.

This reuses every existing safeguard and means **fallback and recovery are the shipped, tested path**.

### 4.3 Steady state

- **Symmetric step** (every message): `MK = HKDF(CK,"msg")`, `CK' = HKDF(CK,"chain")`; `CK` overwritten (zeroize). Per-message FS.
- **Classical DH step** (when a new peer ratchet key arrives): `(RK', CK) = KDF_RK(RK, X25519(dh_self, dh_peer))`. Gives PCS each round trip.
- **Post-quantum step** (sparse): sender offers a fresh ML-KEM-1024 encapsulation key in the header; the peer encapsulates to it in its next message; both mix `ss_mlkem` and a hash of (ek, ct) into the root: `RK' = KDF_RK(RK, ss_mlkem ‖ H(ek‖ct))`. Cadence v1: at most once per **50 messages or 24 h** (whichever first), only on a direction change. This is the simplification relative to SPQR (which streams the key in erasure-coded chunks to cap per-message overhead): v1 sends the whole ek occasionally. Cost-benefit and the option to adopt chunking are §11 item 1.

All KDF labels are versioned strings (`QGuard-PQRatchet-v1:…`) kept in `security/obf.rs` alongside the existing `ratchet_chain()` / `ratchet_root_rotation()` labels, **distinct from the current labels** so no key is ever derivable under two protocols.

### 4.4 Wire format

New optional header inside the existing JSONB envelope:

```jsonc
"ratchet": { "v":1, "kind":"init"|"msg", "session":"…", "dh":"<b64 32B>", "pn":0, "n":7,
             "pq_ek":"<b64 1568B>"?, "pq_ct":"<b64 1568B>"?, "pq_epoch":3 }
```

- **AAD:** new tag `QGM2|…` = existing fields **plus** SHA3-256 of the canonical header. Old builds reject `QGM2` envelopes (fail closed) — they never see one because of §4.6.
- **Signature:** `message_signable` is extended **only when a header is present** (appended after the existing fields), so every v1 envelope keeps verifying byte-for-byte. Header fields are therefore covered by both Ed25519 and ML-DSA-65.
- `hybrid_ciphertext` is present on `init` (and absent on `msg`): the struct field becomes `Option` with `#[serde(default)]`; migrations 004/007 constraint relaxed for `ratchet.kind = 'msg'` (migration 036, §7).

### 4.5 Multi-device & the ledger

- Sessions are per device pair; fan-out is unchanged. Device caps (`MESSAGE_DELIVERY_POLICY.maxPerUser = 8`) bound the number of sessions.
- **The message-key ledger is the contract that makes chain keys disposable:** the receiver records `MK` at first open (`remember_message_key`), exactly as today, then the chain key may advance and be destroyed. History never depends on session state. The sender's copy sealed to its own device **stays one-shot** (no session to itself) so its own-history path (`messaging.rs` l.384) is untouched.
- **Open item (verify in 2a):** trusted-device history re-seal (CHANGELOG 1.3.11) — confirm it re-seals from the ledger/plaintext and not from session or prekey state.
- Device pin standing is checked before **every** session use; a `KeyChanged` or revoked device destroys its session.

### 4.6 Negotiation, fallback, downgrade

- A device advertises `ratchet: "QGuard-PQRatchet-v1"` in its published `suite` (same pattern as `kem_combiner`; add `KemCombiner`-style helper `RatchetCapability::for_peer_suite`). Sender uses a session only if the peer advertises it **and** the peer's local pin is accepted; otherwise one-shot — which every build can open.
- **Downgrade:** the relay cannot force one-shot on a peer that has a session because it cannot forge signed envelopes; a *peer* may always send one-shot (it is a valid, strong mode). The PQ Status badge (Phase 1) shows which mode a conversation is actually in, so a silent fall-back is visible, not hidden.
- **Reset triggers:** no session; peer device key/prekey epoch changed; session older than 30 days; skipped-key cap exceeded; decryption failure on a `msg` (receiver posts a signed control message `session_reset_request`, sender answers with a fresh `init`); manual "Reset secure session" in the Device Trust Center.

### 4.7 Persistence & crash safety

Write-ahead: the **sender** persists the advanced chain before the envelope is uploaded; the **receiver** persists after the key is in the ledger and before the row is marked read. A crash between advance and persist can only lose a not-yet-sent message key (safe) — never reuse a key. Session blobs are tiny (< 4 KB + skipped keys) and protected by the same DEK as the rest of `state.rs`.

### 4.8 Threats considered

| Threat | Mitigation |
| --- | --- |
| Relay replays/reorders/deletes | `(peer_dh, n)` uniqueness + persisted replay window; skipped-key cap; signature covers header |
| Relay swaps device keys | unchanged: device pins + `require_accepted_device`; session destroyed on key change |
| State rollback (restored backup) | monotonic counter in header; stale state → decrypt fail → reset path; document that restoring an old device image is a reset event |
| Harvest-now-decrypt-later | every root update mixes ML-KEM-1024 at init and at each PQ step |
| Compromise of long-term identity keys | identity keys sign only; they never encrypt (unchanged) |
| Covert channels in ratchet state | out of scope; noted by recent analysis of PQ ratchets (ePrint 2026/1638) |
| Implementation error in new KDF schedule | no new primitives; HKDF-SHA3-256 (existing `derive_32`); fixed test vectors; independent review (2k) |

## 5. Security claims — what we will and will not say

Will say (once 2g passes): per-message forward secrecy; post-compromise security on the next classical and post-quantum step; hybrid at session init and every PQ step.
Will **not** say: "audited", "formally verified", or "sealed sender". `docs/security-limitations.md` keeps "not independently audited" until 2k is done. The CHANGELOG sentence "This is not a per-message ratchet" is removed only in the change that makes the ratchet the default.

## 6. Rollout

1. Merge dark: capability not advertised; code paths unit-tested only.
2. Internal flag `QGUARD_RATCHET=1` (env/Settings → Advanced), advertise capability, two-instance test.
3. Opt-in beta for users with both devices updated.
4. Default on; one-shot remains for peers without the capability and for the sender's own copy.
5. **Kill switch:** stop advertising the capability (a suite update) → new messages revert to one-shot with no data migration; existing sessions are simply unused.

## 7. Database

Migration `036_ratchet_envelope_header.sql`: relax the `hybrid_ciphertext` presence constraint for `ratchet.kind='msg'`, add a CHECK that `ratchet` (when present) has `v`, `kind`, `dh`, `n`; confirm RLS needs no change (relay still stores ciphertext + public material only). Reviewed against migrations 004, 007, 026 (expired-envelope purge), 033–034.

## 8. Test plan (Rust unless noted)

Positive: init→reply→reply roundtrip; 1000-message soak; out-of-order within cap; PQ step happens and root changes; skipped keys consumed once.
Negative controls (must fail): replayed envelope; header bit-flip (AAD + signature); wrong `session`; skipped-cap exceeded; `msg` for unknown session → reset request; envelope with `QGM2` fed to a v1 reader fails closed; forged `init` from unpinned/key-changed device refused.
Security properties: **FS test** — capture state at message *n*, prove messages < *n* cannot be derived; **PCS test** — leak full state, show a later step heals (classical and PQ); PQ step with ML-KEM ct tampered fails.
Interop: build N-1 (1.3.12) fixtures → new build opens them; new build sends to a peer without capability → one-shot opened by 1.3.12 reader (the CHANGELOG notes interop is unit-tested only — this adds a real two-instance run). Android↔Desktop on real hardware **blocked until a device or emulator is available**.
Run Rust via `%LOCALAPPDATA%\qguard-build-shims\run-rust-tests.ps1` (plain `cargo test` is wrong on this machine's toolchain).

## 9. Sub-phases (maps to the roadmap)

2a spike/decisions · 2b session store · 2c symmetric + DH · 2d PQ step · 2e negotiation/reset · 2f migration · 2g tests · 2h flag/rollout · 2i docs · 2j interop · 2k review. Each ends green before the next starts.

## 10. Effort & risk

Large, and the only phase here that can brick message delivery if wrong. Risk is contained by: init path = shipped path; capability-gated; kill switch; ledger makes history independent of session state; no change to identity, signatures, or device pins.

## 11. Open questions (need an answer before 2b)

1. **PQ step shape:** v1 whole-key every 50 msgs/24 h (simple) vs. SPQR-style chunked streaming (less peak overhead, more complexity). Recommend v1-simple, revisit after measuring real bandwidth.
2. **Group chat** will need a different construction (Phase 7); this spec is 1:1 per-device-pair only.
3. Persist `seen_message_ids` or rely on `(peer_dh, n)` uniqueness alone?
4. Where to expose "Reset secure session" (Device Trust Center vs conversation menu)?
5. Independent reviewer / budget for 2k.
