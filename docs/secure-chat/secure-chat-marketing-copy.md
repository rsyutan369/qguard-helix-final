# QGuard Secure Chat — Marketing Copy (web-ready)

> Condensed, landing-page-ready copy. Claims verified against the implementation
> (see `secure-chat-security-features.md` for the technical source of truth).
> Stay within the "Claim do's & don'ts" at the bottom.

---

## Hero

**Headline:** Conversations the quantum era can't crack.
**Sub-headline:** End-to-end encrypted messages, calls, and files — protected by NIST post-quantum cryptography. Not even QGuard can read them.

**CTA:** Start a secure chat

**Trust strip (logos/labels):** NIST FIPS 203 · FIPS 204 · End-to-End Encrypted · Zero-Knowledge · Hybrid Post-Quantum

---

## Feature cards (icon + title + one line)

🛡️ **Post-Quantum by Default**
Every message and call is secured with ML-KEM-1024 and ML-DSA — the NIST-standardized algorithms built to withstand quantum computers.

🔗 **Hybrid Encryption**
Classical *and* post-quantum together. An attacker would have to break both — so your data stays safe even from "harvest now, decrypt later."

🔒 **True End-to-End**
Messages, files, and calls are encrypted on your device and decrypted only on your contact's. The server only ever sees ciphertext.

🙈 **Zero-Knowledge**
We store ciphertext and public keys — never your private keys, plaintext, or recovery secrets. QGuard literally cannot read your conversations.

⏳ **Messages on Your Terms**
Disappearing timers, view-once, read-once, time-locked, edit, and delete — privacy controls built into every message.

📎 **Encrypted Files & Voice Notes**
Attachments and voice notes are AES-256-GCM encrypted on your device before they ever leave it, with integrity verification on every download.

📞 **Quantum-Encrypted Calls**
1:1 voice and video with per-frame encryption and a fresh post-quantum key for every call. Verify the call is private in one tap.

📱 **Device Trust You Control**
Approve new devices by QR, see every trusted device, and revoke any of them instantly. Get alerted if a contact's keys ever change.

🔑 **Forward Secrecy**
A fresh key for every single message. Compromising one key never exposes your past or future conversations.

🚪 **Zero-Trust Workspace Lock**
Secure Chat has its own password or PIN, separate from your login, with automatic locking when you step away.

---

## Short "How it's protected" band (3 steps)

1. **Encrypted on your device** — text, files, and call frames are sealed with AES-256-GCM before they leave you.
2. **Quantum-safe key exchange** — keys are agreed using hybrid X25519 + ML-KEM-1024 (NIST FIPS 203), fresh for every message and call.
3. **Only your contact can open it** — the relay stores ciphertext only; verify the safety number to confirm no one's in the middle.

---

## One-paragraph "About the security" (for footer / about page)

QGuard Secure Chat is end-to-end encrypted with hybrid post-quantum cryptography:
key exchange uses **ML-KEM-1024 + X25519** (NIST FIPS 203), identity and messages are
**dual-signed with ML-DSA-65 + Ed25519** (FIPS 204), and content is sealed with
**AES-256-GCM** (FIPS 197) keyed via **HKDF-SHA3-256**. Every message uses a fresh key
(forward secrecy), is authenticated and replay-protected, and is decrypted only on your
device. Voice and video calls add per-frame end-to-end encryption on top of WebRTC's
transport security, with one-tap safety-number verification. Private keys never leave your
device, and the server operates zero-knowledge — it can never read your messages, files, or calls.

---

## Comparison-table bullets (if you build a "Why QGuard" table)

- **Encryption:** End-to-end, hybrid post-quantum (most apps: classical-only or none)
- **Algorithms:** NIST FIPS 203 ML-KEM-1024 + FIPS 204 ML-DSA
- **Calls:** Per-frame E2EE + quantum-safe key per call
- **Server access to content:** None (zero-knowledge)
- **Forward secrecy:** Yes, per message
- **Disappearing / view-once / time-locked:** Yes
- **Device verification:** QR approval, revocation, key-change alerts, safety numbers
- **Harvest-now-decrypt-later resistant:** Yes

---

## Claim do's & don'ts (keep marketing defensible)

**✅ Do say**
- "Post-quantum / quantum-safe," "NIST FIPS 203 & 204," "hybrid classical + post-quantum"
- "End-to-end encrypted," "zero-knowledge," "forward secrecy"
- "Harvest-now-decrypt-later resistant"
- "Not even QGuard can read your messages or calls"

**🚫 Don't say**
- "Unhackable," "unbreakable," "100% secure," "impossible to intercept" — use *"so no one in the middle, not even QGuard, can read it"* instead.
- "Signal Double Ratchet" — say *"post-quantum per-message key agreement with ratcheting."*
- Anything implying MITM protection is automatic — it **requires the user to verify the safety number**; phrase accordingly (e.g., "verify in one tap that your call/chat is private").
