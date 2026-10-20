# Metadata Protection — Design and Review

**Date:** 2026-10-19 · **Roadmap:** Phase 6 · **Status:** 6.3 review done and its safe fixes shipped (migration 039); 6.1 and 6.2 designed, **waiting on owner decisions** (§3.4, §4.4)

---

## 1. What the relay sees today (verified in code)

- Every envelope row carries `sender_user_id`, `sender_device_id`, `recipient_user_id`, `recipient_device_id`, `conversation_id`, timestamps and sizes, in the clear. The AAD (`QGM1|…`/`QGM2|…`) repeats the ids, readable by anyone who can read the row.
- Inserts are made with the sender's own Supabase JWT; RLS requires `sender_user_id = auth.uid()` and conversation membership (migration 007), and the paywall policy (030) checks the sender's subscription. **The relay authenticates the sender on every send** — that is structural, not a column choice.
- `sealed_sender` on the wire is deliberately `false` (`message_crypto.rs`).

## 2. 6.3 Private contact discovery — review (done)

| # | Finding | Severity | Action |
| --- | --- | --- | --- |
| 1 | `search_messaging_users` prefix-matched the **local part of every email** and returned it as the username fallback: typing `jo` listed accounts whose address starts with `jo`. | High (PII leak) | **Fixed, migration 039:** email matches only exactly (must contain `@`), never returned or used to derive a display value (fallback is `user-<8 hex>`). |
| 2 | No rate limit; 2-character minimum — the directory could be enumerated. | Medium | **Fixed, migration 039:** 3-character minimum, 60 searches / 5 min / account (log table not readable by clients). Client minimum aligned, debounce 450 ms, the limit message is shown instead of falling back. |
| 3 | The client's fallback searched `profiles` by **email prefix** directly (RLS limits it to conversation peers, but it still revealed their address prefixes). | Low | **Fixed:** fallback matches email only exactly. |
| 4 | Migration 028 lets conversation peers read the **whole** `profiles` row — email and any other column — because RLS is row-level. `CallProvider` reads `name,username,email` of a caller. | Medium | **Decision needed:** expose peers only through a view/RPC returning `id,name,username,avatar` and drop the peer row policy; needs `CallProvider`/chat to stop reading `email`. Not changed here because it alters what existing screens read. |
| 5 | Strangers are still found by **name/username prefix**, so a patient account can list names (60/5 min). | Low–Medium | **Decision needed:** exact username / email / QR only for people you share no conversation with (Signal-style). Changes how people find each other. |
| 6 | Exact-email lookup is an "is this address registered?" oracle. | Inherent | Rate limit covers it; same trade-off as phone-number discovery elsewhere. |

Verification: Postgres 16 check of 039 — 12/12 (username/name/email/id still found; email-prefix, domain-prefix, email-derived username, 2-char, self, 61st search, log readability all refused).

## 3. 6.1 Sealed sender — design (decision needed)

Goal: the relay stores and delivers a message without learning which account sent it.

### 3.1 What has to change
1. **Submission path without the sender's JWT.** A `deliver` Edge Function inserts envelopes with the service role on behalf of an *unauthenticated* submitter. RLS can no longer name the sender.
2. **Abuse control without identity.** Each recipient device publishes a *delivery token* (`HMAC(K_recipient, "deliver")`), shared only with its contacts inside E2EE messages (Signal's "unidentified access key"). The function accepts an anonymous envelope only with the right token; otherwise the sender must submit authenticated (today's path).
3. **Sender identity inside the ciphertext.** `sender_user_id`, `sender_device_id` and the sender's certificate move into the encrypted payload; the row keeps only recipient fields. The AAD becomes `QGM3|message_id|conversation_id?|recipient…|counter|sealed-header-digest` — the conversation id is itself metadata and would also move inside (rows then need a recipient-side conversation lookup).
4. **Sender certificate.** A short-lived certificate (user id, device id, identity keys, expiry) signed by a server key, so the recipient can check the claimed sender belongs to a real account — the signatures already prove the device keys (`verify_sender_identity`).
5. **Paywall.** 030 checks the sender's subscription on insert. With sealed sender the function must check a *blinded* entitlement (e.g., a daily anonymous credential) or accept that the paywall gates only receiving.

### 3.2 What it does not hide
IP addresses and timing at the relay, conversation membership tables, push notifications, calls (call signalling is separate), and anything a client fetches by conversation id.

### 3.3 Cost / risk
Touches every row read and write in `SecureChatPage`, migrations 004/007/030, unread counters, device sync, and the ratchet AAD — the largest change in the roadmap and the one most able to break delivery. Interop: old builds cannot read `QGM3` rows → capability-gated like the ratchet.

### 3.4 Decisions needed
1. Paywall model under sealed sender (blinded credential vs. receive-side gate).
2. Whether conversation ids move inside the ciphertext (larger change, more hidden).
3. Accept a server-signed sender certificate (new long-lived server key to manage).

## 4. 6.2 Key transparency — state of the art and design (decision needed)

### 4.1 State of the art (checked 2026-10-19)
- **IETF KEYTRANS** working group: *Key Transparency Architecture*, draft-ietf-keytrans-architecture-05 (Oct 2025), Informational, not yet an RFC.
- **Deployed:** WhatsApp (AKD, 2023; log published every ~30 s, audited — RWC 2025), Apple iMessage Contact Key Verification (2024); a news report (TechTimes, Aug 2026) says Signal launched automatic key verification with a log audited by third parties, and Messenger in Nov 2025 — not confirmed from primary sources.
- **Research:** PRISM (ePrint 2025/2026), lightweight KT.

### 4.2 Design for QGuard
- **Log:** an append-only map from `(user_id, device_id)` to the device's identity digest (the same digest device pins use), versioned; VRF-hidden labels (IETF draft) so the log does not reveal who has how many devices.
- **Server:** a `keytrans` Edge Function appends on device registration/rotation/revocation and publishes signed tree heads every N seconds; a public `/head`, `/search` (label → value + inclusion proof) and `/consistency`.
- **Clients:** (a) *self-monitoring* — each device checks, on every head, that its own account's entries are exactly its known devices (detects a device the relay added to *your* account); (b) before pinning a contact device, verify its inclusion proof; (c) gossip heads between devices of the same account and in the PQ status badge, to detect split views.
- **Auditors:** at least one third party verifying consistency of every head; without one the log only helps the people who self-monitor.

### 4.3 Relation to what exists
Device pins (TOFU, Phase 1) already stop silent *changes* to a contact's known devices; Phase 3 verification proves a contact's device out of band. KT adds: detection when the relay adds a device to **your own** account or shows different directories to different people.

### 4.4 Decisions needed
1. Build our own log (Merkle prefix tree + VRF, per the IETF draft) vs. wait for a reference implementation of the RFC.
2. Server signing key custody (it becomes part of the trust base) and who audits.
3. Hosting: Supabase Edge Function + table vs. a separate service.
