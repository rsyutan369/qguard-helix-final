# Lessons — Q-Shrink Vault Engine

## L1 — Web Streams: read before you write, settle both sides on error
**Failure pattern:** `CompressionStream`/`DecompressionStream` via `new Response(stream.readable).arrayBuffer()` produced intermittently truncated output (`Z_BUF_ERROR: unexpected end of file`), and a *deliberately* corrupt decompress (tamper test) crashed the **next** test with an uncaught `TypeError` from Node's webstreams adapter.
**Root cause:** (a) writing without an active reader / without awaiting risks truncated collection and backpressure deadlock; (b) when a transform errors, `new Response(readable)` can leave a dangling, unhandled stream `error` event that surfaces on a later tick.
**Prevention rule:** pump transform streams manually — get both reader and writer, run read+write concurrently, and on error `cancel()` the reader, `abort()` the writer, and `Promise.allSettled` both halves before rethrowing a clean error. Never use `new Response(readable)` for data that may be corrupt. (`src/lib/vault/q-shrink/codec.ts`)

## L2 — Test assertions must match the algorithm's real behavior
**Failure pattern:** a cross-file dedup assertion failed because the "shared" content was repetitive *text* whose 69-byte period doesn't align to 8 KB chunk boundaries — it compresses ~99% but doesn't dedup.
**Prevention rule:** to exercise block-level dedup, share a large **random** blob (stable, alignable content-defined boundaries). Compression and deduplication are different wins; test them with inputs that isolate each.

## L3 — Compress before encrypt; never inflate
**Rule:** high-entropy ciphertext is incompressible, so optimization must precede encryption. Entropy-gate + a post-compression guard + a container-vs-original guard guarantee the sealed object is never larger than the input (`applied:false` seals raw bytes). Each file compresses in isolation (no CRIME/BREACH shared-context oracle).

## L4 — A self-describing magic must be unforgeable by the payload it describes
**Failure pattern:** restore detected containers purely by the `QSHRN1` magic, while the no-inflation path sealed *raw* bytes with `applied:false`. A real user file whose plaintext happened to begin with the 7 magic bytes (`51 53 48 52 4E 31 01`) was therefore mis-detected as a container on download and `restorePackage` tried to `JSON.parse` random bytes → threw → **permanent data loss for a correctly-sealed file**. Attacker-craftable (just upload a file starting with those bytes; a re-uploaded vault container literally does).
**Root cause:** the two halves of the contract disagreed — optimize could emit a passthrough that collides with the very sentinel restore treats as authoritative. The `applied` flag that was *supposed* to disambiguate lived in mutable, unauthenticated server metadata, so restore (correctly, for zero-knowledge) ignored it — leaving magic-only detection with a false-positive hole.
**Prevention rule:** when a format is detected by an in-band sentinel, the *producer* must guarantee no non-format payload can start with that sentinel. Here: `optimizeFile` now wraps any raw input that begins with the magic instead of passing it through (`!beneficial && !isQShrinkPackage(data)` gates passthrough), so the magic is truly authoritative and the decision stays inside the GCM-authenticated bytes — never trusting mutable metadata. Regression covered in `roundtrip-test.ts` → `[magic-collision safety]`.

## L6 — A CSP is only "done" once a browser confirms it (and it surfaces hidden deps)
**Failure pattern (caught by testing):** the strict CSP built and the meta injected cleanly, but loading it under `vite preview` + Playwright showed 37 console errors — the policy was blocking third-party placeholder avatars (`randomuser.me`, `loremfaces.net`) hard-coded in `Landing.tsx`. A build-pass alone would have shipped either broken images or a quietly-weakened policy.
**Root cause:** static checks (tsc/build) can't see runtime resource loads; CSP enforcement only happens in a browser. The external images were also fake placeholder faces (against the project's "no fabricated data" rule) leaking visitor IPs.
**Prevention rule:** verify a CSP by serving the build and reading the browser console for violations (`Refused to…`) AND confirming the app still renders (root has children, inline-script hash matches → theme applies). Keep the policy strict and fix the *app* (here: local data-URI `initialsAvatar`) rather than loosening `img-src`/`script-src` to accommodate it. Inline scripts must be allow-listed by SHA-256 hash, never `'unsafe-inline'`; compute the hash at build over the exact emitted script text.

## L7 — API and DB schema drifted apart; the generic 500 hid it
**Failure pattern:** "Failed to create shared link" on every share. The share API (`/api/v1/vault/share` insert + `/public` select + GET/DELETE filters) referenced columns `owner_id, encrypted_payload, iv, integrity_hash, password_salt, destroyed_reason` that **do not exist** in the deployed `vault_shared_links` table — which actually has `user_id` (NOT NULL, RLS `user_id = auth.uid()`), `encryption_metadata` (JSONB), `password_hash`. So the INSERT referenced unknown columns AND omitted NOT-NULL `user_id` → Postgres error → the route swallowed it as a generic `DB_ERROR` 500.
**Root cause:** the route was written against a planned/phantom schema that was never migrated; nothing in the repo SQL or RLS ever defined those columns (uploads/keys work because they correctly use `user_id`). The generic error message hid the real Postgres detail.
**Prevention rule:** persist a feature's data using the columns that actually exist — store variable share crypto (`payload, iv, integrityHash, recipientWrap, passwordSalt, passwordKdf, sharingMode`) in the existing `encryption_metadata` JSONB, not invented columns; keep write and read paths reading the SAME shape. Never swallow a DB error into a generic message — surface `code/message/details/hint` (guarded to dev) so schema/RLS drift is visible immediately. Adjacent bugs found in the same pass: client sent `expiresAt` but the route read `expiresIn`; `passwordSalt/recipientWrap/passwordKdf` arrived nested under `encryptionMetadata` and were never stored or returned (so recipient-bound/password reads were also broken).

## L5 — "Encrypt the filename" is a cross-cutting cutover, not a column swap
**Failure pattern (avoided):** the obvious way to stop leaking `original_filename` is to make it a placeholder and decrypt on display. But that one column is read by **public shared-link routes** (a share recipient has *no vault keys*, so a sealed name is undecryptable for them) and by **server-side analytics dashboards** (which by design can't hold user keys). A blind flip would have shown random IDs to share recipients and placeholders in dashboards — a regression worse than the metadata leak, and untestable without an authenticated session.
**Root cause:** filename is both a confidentiality concern (owner) and a functional field (sharing/telemetry); encrypting it for the owner removes it from every party that legitimately can't decrypt.
**Prevention rule:** before "just encrypt field X", grep every reader. If any reader can't possess the key (anonymous share, server telemetry), the change needs a *separate name-delivery path* for them and authenticated E2E testing — ship the additive capture (`envelope_meta.sealedMeta`) first, defer the destructive cutover. The HNDL-critical hardening was the **passphrase KDF (PBKDF2→Argon2id) + strength enforcement**, not the metadata — fix the root-of-trust first.

## 2026-08-26 — Video calling failed in both directions on 1.3.0

**Failure pattern.** A fix that is correct in isolation can be completely inert
because of an upstream defect, and it will look like the fix did not work. The
1.3.0 ring fan-out ("ring every device") was correct code fanning out to a
one-element list, because `deliveryDeviceBucket` keyed on `user_id:device_label`
and every platform registered the identical hardcoded label `"Windows Desktop"`.

**Root causes (4, independent).**
1. Identical hardcoded device labels collapsed every account to ONE addressable
   device — for messages as well as calls.
2. `App.tsx` returned the Android PIN screen in an early return ABOVE
   `CallProvider`, so backgrounding the phone unmounted the call-signal
   subscription entirely.
3. The shipped public TURN relay could not allocate, AND an unallocatable TURN
   entry stops ICE gathering from ever completing — a broken relay was strictly
   worse than no relay.
4. One fixed 45s wall clock covered both ringing and connecting, so a
   slow-but-advancing connection was killed at the moment it was about to work.

**Prevention rules.**
- A discriminator that is *hardcoded identical everywhere* is not a
  discriminator. When deduplicating "the same device", key on something that
  actually diverges per device (here: `last_seen_at` recency), not on a label
  the code itself writes.
- Anything that must survive a lock/gate must be mounted ABOVE that gate. Check
  what an early `return` unmounts before adding one.
- Never ship a third-party dependency in the media path without a runtime health
  check. And verify a TURN server by driving REAL Chromium ICE over CDP — a
  hand-rolled STUN probe returns errors that may be your own bug.
- A timeout should measure the thing it is protecting against. Elapsed time is
  not progress; if the operation can legitimately take longer, gate on progress
  and keep a separate absolute ceiling.
- A failure state that unmounts its own UI discards its error message. Check
  that a `failed` reason has somewhere to render.
- `messaging_call_signals` is a complete call timeline — read it before theorising
  about call bugs.

## 2026-08-26 (2) — "100% · Fully protected" above "2 of 4 layers fully active"

**Failure pattern.** Two models measuring the same thing on one screen, and the
WRONG one was the pessimistic-looking one. The headline (`buildSecurityPosture`)
was right; the phone's reactor (`buildCryptoStack`) was mis-measuring. The user
reasonably read the low number as a security gap. It was not: their cryptography
was fully active.

**Root cause.** `buildCryptoStack` diverged from the canonical posture engine in
three ways, and `security-score.ts` already documented the trap in its own code
("stale device identities left behind by reinstalls ... make a perfectly healthy
device read as awaiting prekey material forever"):
1. Divided Identity/Handshake by EVERY non-revoked device row. A reinstall mints
   a new identity and strands the old row forever with no signed prekey — the
   live account had 2 live devices and 3 stranded rows, so Handshake read 2/5.
2. Counted build-provenance gates (code signing, obfuscation, control-flow
   flattening) in the Runtime layer. `security-score.ts` deliberately excludes
   them; they describe how the binary was produced, not whether the running
   cryptography works.
3. Measured Session against an aspirational target (24) instead of the readiness
   threshold the rest of the platform uses (16).

Separately, on Android the runtime genuinely could not measure itself:
`current_binary_measurement()` used `std::env::current_exe()`, which on Android
is the zygote (`/system/bin/app_process64`) — not our code, and unreadable in
the app sandbox. Two integrity checks reported "unavailable" for that reason
alone. Fixed by measuring the app's own loaded `.so`, located via
`/proc/self/maps`.

**Prevention rules.**
- Before adding a second measurement of something already measured, find the
  existing engine and reuse its vocabulary. If a module's header comment warns
  about a trap, the new module is probably about to fall into it.
- A ratio is only as honest as its denominator. State the population in the UI
  ("across N enrolled devices") — an unqualified "2 of 4" hides the bug.
- Narrowing a denominator is legitimate ONLY when the excluded rows are
  reclassified and surfaced with their own action, never silently dropped. Test
  both directions: that stranded rows stop deflating the layer, AND that a real
  gap on a live device still fails it.
- Two numbers on one screen that can contradict each other WILL. Make the
  stronger claim structurally conditional on the weaker evidence (`scoreVerdict`
  now takes the layers) so the contradiction cannot be written again.
- `#[cfg(target_os = "android")]` code is NOT compiled by a host `cargo check`.
  Verify with `cargo check --lib --target aarch64-linux-android`, and put the
  NDK's `toolchains/llvm/prebuilt/windows-x86_64/bin` on PATH first or cc-rs
  fails with "failed to find tool clang.exe".
