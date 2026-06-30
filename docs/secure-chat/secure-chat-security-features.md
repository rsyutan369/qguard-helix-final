# QGuard Secure Chat — Security & Advanced Features (Reference)

> **Source of truth, verified against code (2026-06-29).** Every claim below maps to the
> actual implementation in `qguard-messaging` (Rust crypto core + message/call pipelines +
> chat UI). Use the "Accuracy guidance" section before writing public copy.
>
> Key files: `src-tauri/src/crypto/*`, `message_crypto.rs`, `ratchet.rs`, `prekeys.rs`,
> `commands/messaging.rs`, `commands/calls.rs`, `src/lib/call-frame-crypto.ts`,
> `src/lib/call-quality.ts`, `src/pages/SecureChatPage.tsx`, `supabase/migrations/`.

## Positioning (accurate one-liners)
- **Post-quantum, end-to-end encrypted messaging & calling** built on NIST-standardized algorithms (FIPS 203 / 204).
- **Hybrid cryptography** — classical *and* post-quantum, so it's secure even against "harvest-now, decrypt-later" attacks.
- **Zero-knowledge** — the server stores only ciphertext and public keys; it can never read your messages, files, or calls.

## 1. Cryptographic foundation (the exact suite)

| Purpose | Algorithm | Standard |
|---|---|---|
| Key encapsulation (hybrid) | **ML-KEM-1024 + X25519** | FIPS 203 + RFC 7748 |
| Message/identity signatures (dual) | **ML-DSA-65 + Ed25519** | FIPS 204 |
| Quantum Vault signatures (dual, L5) | **ML-DSA-87 + Ed25519** | FIPS 204 Level 5 |
| Symmetric / AEAD | **AES-256-GCM** | FIPS 197 + SP 800-38D |
| Key derivation | **HKDF-SHA3-256** | FIPS 202 |
| Hashing / fingerprints | **SHA3-256** | FIPS 202 |

Both the classical *and* the post-quantum secret must be broken to compromise any key — and both signatures must verify for any message to be accepted. Legacy **ML-KEM-768** is accepted for backward compatibility; the current/default strength is **ML-KEM-1024**.

## 2. Message encryption
- **Per-message post-quantum key agreement** — *every* message performs a fresh ML-KEM-1024 + X25519 encapsulation to the recipient's signed/one-time prekey, deriving a unique key (not a single static session key).
- **Forward secrecy** — one-time prekeys + ephemeral X25519 + per-message key ratcheting; compromising one message key doesn't expose past or future messages.
- **Authenticated & tamper-evident** — AES-256-GCM with associated data bound to message ID, conversation, sender/recipient device, and counter; any tampering is rejected.
- **Sender authenticity** — every message is dual-signed (Ed25519 + ML-DSA-65); the recipient's identity bundle and prekeys are dual-verified before use.
- **Replay protection** — duplicate/replayed messages are detected and rejected.
- **Sealed-sender envelopes** + **client-side-only decryption** with built-in decryption rate-limiting.

## 3. Message lifecycle & privacy controls
- **Disappearing messages** (timer or custom expiry)
- **View-once** and **read-once** messages
- **Time-locked messages** (unlock at a future time)
- **Edit** and **delete** messages
- **Opt-in typing indicators**
- **Per-message verification badge** — valid / tampered / expired / revoked
- **Conversation controls** — archive, hide, delete

## 4. Encrypted attachments & voice notes
- Files and voice notes are **encrypted on your device with AES-256-GCM (256-bit, random IV)** *before* upload.
- The per-file key is **sealed inside the end-to-end-encrypted message envelope** — the storage server only ever holds ciphertext.
- **SHA-256 integrity verification** on download; corrupted/tampered files are rejected.

## 5. Quantum-encrypted voice & video calls
- **End-to-end encrypted 1:1 calls** with a fresh hybrid **X25519 + ML-KEM-1024** key per call.
- **Per-frame E2EE** — every encoded audio/video frame is AES-256-GCM encrypted (via insertable-stream transforms), with directional keys and audio/video separation so the relay/server only sees ciphertext.
- **Two encryption layers** — your E2EE rides on top of WebRTC's mandatory DTLS-SRTP transport encryption.
- **Safety-number verification** auto-shown on connect — confirm **aloud or by typing**, with a persistent **"Verified"** indicator.
- **Fail-closed** (no unencrypted fallback); keys derived on-device and wiped from memory after use.
- **Lightweight & responsive** — adaptive quality (Low/Auto/HD) with a stable software-codec path.

## 6. Identity & device trust
- Each device has its own hybrid identity keys; identity bundles are dual-signed and verified.
- **Multi-device** with trusted-device message sync.
- **QR-based device approval**, device **trust states** (this device / trusted / pending / revoked / suspicious), and **remote device revocation**.
- **Key-change detection** and reporting (alerts if a contact's keys change).
- **Conversation safety numbers** (SHA3-256 of both parties' fingerprints) with a QR verification payload.

## 7. Zero-knowledge backend & key custody
- The relay stores **only**: public keys, ciphertext envelopes, encrypted files, and minimal routing metadata — **never** private keys, session keys, plaintext, or recovery secrets.
- **Private keys never leave the device** — held in OS-keychain-backed encrypted storage and zeroized in memory after use.
- **Multi-tenant isolation** enforced by database Row-Level Security; realtime over authenticated channels.
- Core cryptography runs **natively (Rust) on-device**, not in browser JavaScript.

## 8. Access control
- **Zero-Trust Workspace Lock** — Secure Chat is gated by its own password/PIN, separate from account login, verified on-device, with idle/minimize auto-lock and anti-brute-force lockout.

---

## ⚠️ Accuracy guidance for marketing (so claims stay defensible)
- ✅ **Safe to say:** "post-quantum / quantum-safe," "NIST FIPS 203 & 204," "hybrid classical + post-quantum," "end-to-end encrypted," "zero-knowledge," "forward secrecy," "harvest-now-decrypt-later resistant," "QGuard cannot read your messages or calls."
- ⚠️ **Qualify, don't absolutize:** prefer *"so no one in the middle — not even QGuard — can read it"* over *"impossible to intercept / unhackable / unbreakable."* Active man-in-the-middle protection **depends on users verifying the safety number** — say so.
- ⚠️ **Don't claim** the literal "Signal Double Ratchet." It is a *post-quantum per-message key agreement with ratcheting + replay protection* — describe it that way.
