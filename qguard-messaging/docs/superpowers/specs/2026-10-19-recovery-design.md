# Recovery — Design

**Date:** 2026-10-19 · **Roadmap:** Phase 5 · **Scope:** Rust core, React UI, one Supabase migration · **Status:** 5.3 and 5.1 implemented; 5.2 assessed (see §5)

---

## 1. What exists (verified in code)

- **Vault recovery key** (`crypto/vault_recovery.rs`): a 256-bit root `R`, shown once as a checksummed Crockford-Base32 key. `HKDF-SHA3-256(R)` gives a wrap key that every vault file key is also sealed under, and a one-way verifier. Modes: personal (key only), enterprise (ML-KEM-1024 recipient), hybrid (both).
- **Account recovery registry** (migration 029, `lib/account-recovery.ts`): one row per account with the verifier only, so any signed-in device can validate a typed key.
- **Message history** lives on the relay as envelopes sealed per device; a device opens them with its prekeys or ratchet sessions, then records each message key in its encrypted **message-key ledger** (`message_keys.rs`). The receive path consults the ledger **first**, for envelopes addressed to *any* of the account's devices (`commands/messaging.rs`).
- **Trusted-device sync** re-seals history from an existing device to a newly approved one. If every device is lost, history is lost — today.

## 2. 5.3 Encrypted history backup (implemented)

**Idea:** the ledger is everything needed to read the history still on the relay. Back it up, encrypted under the recovery key; restore it on a new device and the old envelopes open from the ledger.

- **Format** (`.qgbackup`, JSON): `{format:"qguard-history-backup", v:1, created_at, salt_b64, envelope{nonce,ciphertext,tag}}`; payload = `{user_id, entries:[{id,key,bind,at}]}`.
- **Key:** `HKDF-SHA3-256(salt, R, "QGuard-HistoryBackup-v1")`; AEAD AES-256-GCM, AAD = `"QGuard-HistoryBackup-v1|" ‖ user_id` so a backup cannot be imported into another account.
- **Export** requires the recovery key, checked against the device's or the account's stored verifier first (a mistyped key never produces a backup nobody can open). **Import** merges entries additively (an existing entry is never replaced).
- Holds keys, never plaintext. It opens only envelopes still on the relay (expired or deleted messages stay gone). A backup is a snapshot: messages received later need a newer backup.
- Saved where the user chooses (desktop save dialog, Android Downloads); nothing is uploaded.

## 3. 5.1 Social recovery (implemented)

Recover the recovery key itself, when it is lost along with every device, with help from contacts.

- **Split:** a fresh 32-byte secret `S` is split k-of-n with Shamir over GF(2⁸) (byte-wise, random coefficients from the OS RNG). `R` is wrapped under `K = HKDF-SHA3-256(S ‖ Argon2id(PIN, salt))`. The wrapped `R`, `salt`, `k`, `n` and the guardian list (user + device ids) go to `messaging_social_recovery` (migration 038, owner-only RLS). Nobody — guardian, relay, or both — holds `R`.
- **Guardians** are verified contacts' devices (Phase 3: `contact_mark_verified`). Each share is sealed to one guardian device's identity keys (hybrid X25519 + ML-KEM-1024, dual-signed by the owner's device) and delivered as a control message; the guardian device stores it in its encrypted local store, keyed by the owner.
- **Recovery:** the owner signs in on a new device, which creates a request with a fresh hybrid key pair (`messaging_recovery_requests`, signed by the new device's identity). A guardian sees the request, **must confirm out of band** that it is really the owner (the UI shows a short code derived from the request key for both to compare), and approves: their device re-seals the share to the request key and posts it. With `k` shares and the PIN, the new device rebuilds `S`, derives `K`, unwraps `R`, and the recovery key works as if typed.
- **Threat model:** fewer than `k` guardians learn nothing about `S`. `k` colluding guardians plus the relay could brute-force a short PIN offline (Argon2id 64 MiB slows, does not stop it) — the UI asks for at least 6 digits and recommends a passphrase. A relay forging a request gets nothing unless guardians approve it — the out-of-band code is the control.

## 4. Tests

Rust: Shamir split/combine for every k-of-n up to 5-of-7, any k shares reconstruct, k−1 shares give no information (uniform check), duplicate x refused; wrong PIN fails; share sealed to one guardian cannot be opened by another; tampered share/request refused; backup roundtrip, wrong recovery key refused at export, backup for another account refused, import additive. Frontend: request code derivation, flow state.

## 5. 5.2 Passkey-protected recovery — assessed, not built

A passkey would protect `R` with the WebAuthn **PRF** extension (`R` wrapped under the PRF output). Findings:
- The desktop app runs in WebView2; WebAuthn there goes to Windows Hello, whose PRF (hmac-secret) support depends on the Windows build and authenticator — not something the app can rely on or test on this machine.
- Android's WebView does not expose WebAuthn at all; it would need the Credential Manager API through a native bridge.
- Without PRF a passkey only proves presence; it cannot derive a key, so it would add a login step, not protect `R`.

**Decision needed before building:** native Credential Manager (Android) + PRF-capable authenticator requirement (desktop), with a real-device test plan. Recorded as open in the roadmap.
