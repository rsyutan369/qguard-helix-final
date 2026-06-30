# QGuard Secure Chat — FAQ (web-ready)

> Customer-facing Q&A for landing/help pages. Answers are verified against the
> implementation (see `secure-chat-security-features.md`) and follow the same
> claim guardrails — accurate, not absolute.

---

### Is it really quantum-safe?
Yes. Secure Chat uses NIST-standardized post-quantum cryptography: keys are exchanged with **ML-KEM-1024** (NIST FIPS 203) and messages are signed with **ML-DSA** (FIPS 204). It's **hybrid**, meaning it combines post-quantum algorithms with proven classical ones (X25519, Ed25519) — an attacker would have to break *both*. That also makes it resistant to "harvest now, decrypt later" attacks, where data captured today is stored to be decrypted by a future quantum computer.

### Can QGuard read my messages or calls?
No. Everything is **end-to-end encrypted** — encrypted on your device and decrypted only on your contact's device. Our servers store **ciphertext and public keys only** — never your private keys, message contents, files, or call audio/video. This is what "zero-knowledge" means: there's nothing on our side to read, hand over, or leak.

### What does "end-to-end encrypted" actually protect against?
It means no one between you and your contact — not QGuard, not your network or internet provider, not the server — can read your conversation. To also rule out an active impersonation attack ("man-in-the-middle"), you and your contact can **verify the safety number** (compare the numbers, or type them in). On calls, this appears automatically when you connect, and once confirmed you'll see a **"Verified"** badge.

### Are my files and voice notes encrypted too?
Yes. Attachments and voice notes are encrypted **on your device with AES-256-GCM before they're uploaded**, and the key to open them is sealed inside the end-to-end-encrypted message — never stored with the file. Every download is integrity-checked, so tampered files are rejected.

### Are voice and video calls encrypted?
Yes. Calls are end-to-end encrypted with a **fresh post-quantum key for every call**, and **every audio/video frame is individually encrypted** — so even the relay that connects the call only sees scrambled data. There are two layers of protection: your end-to-end encryption on top of the standard encrypted call transport. Verify the safety number on connect to confirm the call is private.

### What does the server store?
Only what's needed to deliver encrypted data: your **public keys**, **encrypted message envelopes**, **encrypted files**, and minimal routing information. It never stores private keys, plaintext, session keys, or recovery secrets. Accounts are isolated from each other at the database level.

### Does it have forward secrecy?
Yes. Every single message uses a **fresh key**. If one message key were ever exposed, it would not reveal your past or future messages.

### Can messages disappear or be limited?
Yes. You can set **disappearing timers**, **view-once** and **read-once** messages, **time-locked** messages (which unlock at a future time), and you can **edit** or **delete** messages.

### Can I use it on more than one device?
Yes. Each device has its own keys. You **approve a new device by scanning a QR code**, you can see all your trusted devices, and you can **revoke** any device instantly. If a contact's keys ever change, you're alerted.

### What happens if I lose my device?
Your keys live only on your devices, never on our servers — so the safest approach is to **add and trust a second device in advance**. From a trusted device you can **revoke the lost one** so it can no longer be used. (The separate **Quantum Vault** feature also offers an offline recovery key for your stored files.) Because we're zero-knowledge, QGuard cannot recover message keys for you — that's the same property that guarantees no one else can either.

### How do I know a chat or call is really private (not intercepted)?
Compare the **safety number** with your contact. It's a short code derived from both of your identity keys; if someone were intercepting, the codes wouldn't match. On calls it pops up automatically — read it aloud or type the number your contact reads to you, and we'll confirm it matches exactly.

### Is there a separate lock for Secure Chat?
Yes. The **Zero-Trust Workspace Lock** gates Secure Chat behind its own password or PIN — separate from your account login — and locks automatically when you're idle or minimize the app.

### Is it unhackable?
No security system should claim that. What we *can* say precisely: your messages, files, and calls are **end-to-end encrypted with NIST post-quantum cryptography**, the server is **zero-knowledge**, and — when you verify the safety number — **no one in the middle, including QGuard, can read your conversation**.

### Which standards and algorithms does it use?
- **Key exchange:** ML-KEM-1024 + X25519 (NIST FIPS 203)
- **Signatures:** ML-DSA-65 + Ed25519 (NIST FIPS 204)
- **Encryption:** AES-256-GCM (FIPS 197)
- **Key derivation / hashing:** HKDF-SHA3-256 / SHA3-256 (FIPS 202)
