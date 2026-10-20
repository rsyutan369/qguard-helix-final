# Resilience Mode — Design

**Date:** 2026-10-20 · **Roadmap:** Phase 9 · **Status:** 9.2 shipped; 9.1 outbox and nearby delivery built (§3) — not tested between two phones

---

## 1. 9.2 Relay outage / block detection (shipped)

**Problem:** every message goes through one relay. When it could not be reached, the only signal was realtime falling back to polling and sends failing with a generic error. Nothing told the user whether the device, the network or the service was at fault.

**What the app now does** (`src/lib/relay-health.ts`, `src/components/RelayHealthBanner.tsx`):

| Evidence | Shown as |
| --- | --- |
| OS reports no network (`navigator.onLine === false`) | **You're offline** |
| The relay answered with HTTP 5xx | **The relay is having problems** (its side, with the status code) |
| The relay did not answer, but the update server did | **Can't reach the relay**: the internet works, so it is down or blocked on this network; try another network or a VPN |
| Neither answered | **No internet connection** (or a sign-in page is in the way) |
| The relay did not answer and there is no second host to ask (Android) | **Can't reach the relay**, saying plainly that the device can't tell which |

- **Probes:**
  - The relay's own `GET /auth/v1/health`, with the public anon key and no user credentials, and an 8 s timeout.
  - The control is the existing signed-update check, run only when the relay probe failed. **No new host is ever contacted.**
- **When it checks:**
  - On launch, on OS network changes, on realtime `CHANNEL_ERROR`/`TIMED_OUT`, and on "Check again".
  - On return to the foreground, at most every 30 s while healthy.
  - While unhealthy it backs off: 5, 10, 20, 40, then every 60 s. The banner disappears by itself once the relay answers.
- **Tests:** `relay-health.test.ts`, 10 cases. They cover the classifier for every row above, that a 4xx counts as reachable, the probe's URL, headers and `credentials: omit`, the timeout, the refusal to probe placeholder or plain-http relays, and the backoff schedule.
- **Not verified here:** a real outage or block. That needs a live run with the relay firewalled.

## 2. 9.1 Store-and-forward and nearby delivery (design only)

### 2.1 Store-and-forward outbox

- **Today:** a send that fails is a failed bubble. **Proposal:** queue the **already-sealed envelopes** (ciphertext, signatures and AAD exactly as they would be inserted) in an encrypted on-device outbox, and retry when the banner's state returns to `ok`.
- **Why sealed envelopes and not plaintext:** the outbox then holds nothing the relay would not hold anyway. The plaintext stays only in the memory cache.
- **Points to settle:**
  - Ratchet sessions advance when a message is sealed. A queued message that is later dropped must be marked spent in the ledger, which the ledger already supports.
  - Prekeys used by a queued one-shot envelope may be rotated before delivery. The outbox must re-seal if the recipient device's prekey was retired, or fail visibly.
  - Disappearing messages must expire **in the outbox** as well.
  - Ordering: deliver in creation order per conversation.

### 2.2 Nearby (Bluetooth / Wi-Fi Direct) delivery on Android

- **Transport:** Android Nearby Connections (Google Play services), or BLE plus Wi-Fi Aware without Play services. Peers exchange sealed envelopes addressed to devices they have **pinned**. Nearby delivery is just another carrier for the same envelopes: they are signed and sealed end to end, so a relaying phone learns only sizes and device ids.
- **Threats:**
  - **Proximity tracking:** advertising must rotate identifiers and never broadcast a stable device id.
  - **Flooding:** rate-limit and cap stored foreign envelopes.
  - **Replay:** the existing replay and ledger checks apply unchanged.
- **Relay fallback:** anything delivered nearby is also uploaded once the relay is back, de-duplicated by `client_message_id`.
- **Needs:** two Android devices for testing (none are available in this environment), new permissions (`NEARBY_WIFI_DEVICES`, `BLUETOOTH_SCAN/ADVERTISE/CONNECT`) and a Play policy declaration. **Owner decision:** build on Google Play services (simpler, not on de-Googled phones) or on raw BLE + Wi-Fi Aware (more work).

---

## 3. 9.1 Built (owner decision 2026-10-20: Google Play services)

### Outbox

- **When:** a send whose upload never got an answer (network failure; `isNetworkFailure`) keeps its **sealed envelope rows** in the core's encrypted per-user store (`commands/outbox.rs`). A refusal the relay did answer stays an error.
- **What is stored:** ciphertext only — the store refuses rows without their sealed parts and any row carrying `plaintext`. At most 200 messages or 8 MiB.
- **In the thread:** the message shows as "Waiting to send".
- **Upload:** `OutboxCourier` uploads oldest first every 20 s, and on `online` events, stopping at the first network failure.
  - Disappearing messages that expired while waiting are dropped, never delivered late.
  - A duplicate-key answer counts as delivered.
  - Other refusals are dropped and reported.
- **Tests:** Rust 4 (restart persistence, order, encrypted on disk, requeue replaces, bounds, sealed-only); vitest (failure classification, ordering, blocking, expiry, duplicates).

### Nearby (Android)

- **Transport:** `NearbyRelay.kt` with Google Play services Nearby Connections (`play-services-nearby` 19.3.0, P2P_CLUSTER).
- **Privacy:** the endpoint name is random per session, so nothing stable is broadcast.
- **Payloads:** one sealed envelope row per BYTES payload, at most 32 KiB.
- **Permissions:** requested at run time only when the user turns the feature on. Bluetooth and Wi-Fi scanning are flagged `neverForLocation`; location is used only on Android 12 and older, where the platform requires it.
- **Sending:** rows waiting in the outbox are offered to connected phones and to phones that connect later.
- **Receiving:** `nearby_take_received` returns only well-formed sealed rows (`accept_received`). The app keeps those sealed to **this** device and merges them into the conversation. They pass the same screening and decryption as relay rows. A sender that cannot be verified offline is shown as unverified. Once the relay has the sender's copy, it replaces the nearby one by envelope id.
- **Not built:** relaying other people's rows to the relay. RLS only accepts envelopes from their own sender (`sender_user_id = auth.uid()`), so a third phone cannot upload on someone's behalf. Delivery is direct between sender and recipient phones, plus each sender's own outbox upload later.
- **Verification:**
  - Rust 4 (row acceptance, size bound, desktop "unsupported", status parsing).
  - vitest (rows for this device only; the relay copy wins).
  - Kotlin compiled against Play services.
  - **Not run between two phones**: no devices are available here.
