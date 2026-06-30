# QGuard Quantum Vault — Marketing Copy (web-ready)

> Condensed, landing-page-ready copy. Claims verified against the implementation
> (see `quantum-vault-security-features.md` for the technical source of truth).
> Stay within the "Claim do's & don'ts" at the bottom.

---

## Hero

**Headline:** Your files, sealed for the quantum age.
**Sub-headline:** Encrypt any file or folder on your device with post-quantum cryptography. Strictly local, zero-knowledge — your data never leaves your machine.

**CTA:** Open the Quantum Vault

**Trust strip:** NIST FIPS 203 · FIPS 204 Level 5 · 100% On-Device · Zero-Knowledge · Quantum-Safe Recovery

---

## Feature cards (icon + title + one line)

🛡️ **Post-Quantum Encryption**
Files are sealed with AES-256-GCM and protected by NIST ML-KEM-1024 and ML-DSA-87 (Level 5) — engineered to resist quantum computers.

💻 **Strictly On-Device**
Everything is encrypted and decrypted locally. Your files never touch QGuard's servers — there's nothing to upload, intercept, or leak.

🙈 **Zero-Knowledge, Even at Rest**
Your Vault Master Key is itself encrypted by your password. Locked, even your own device holds only ciphertext.

🧅 **Layered Key Envelope**
A unique key per file, wrapped by your Vault Master Key, sealed with post-quantum cryptography. Breaking one layer never opens your files.

🧾 **Tamper-Evident**
Every chunk is authenticated and bound to its position, so any change, reorder, or truncation is instantly detected and rejected.

🗝️ **Quantum-Safe Recovery**
Lose your device? An offline recovery key restores your `.qvault` files on a brand-new machine — no access to the old one required.

🏢 **Enterprise Dual-Control**
Optional hybrid recovery requires both a personal key and an enterprise key — two-person integrity for regulated teams.

📁 **Files & Folders, Any Size**
Encrypt whole folders into a single sealed archive — even the folder structure is hidden inside the ciphertext. Streamed, so size is unlimited.

📊 **Live Crypto Terminal**
Watch the real cryptographic pipeline as it runs — key sealing, signing, and per-chunk progress with true throughput and ETA.

🔒 **Zero-Trust Lock**
The Vault opens only with its own password or PIN, and locks automatically when you step away.

---

## Short "How it works" band (3 steps)

1. **Pick a file or folder** — it's encrypted on your device with a unique AES-256-GCM key.
2. **Sealed, quantum-safe** — that key is wrapped with hybrid X25519 + ML-KEM-1024 and the container is signed with ML-DSA-87.
3. **Stays with you** — the `.qvault` file is saved wherever you choose. Nothing is uploaded; only you (or your recovery key) can open it.

---

## One-paragraph "About the security" (for footer / about page)

QGuard Quantum Vault is a strictly local, zero-knowledge file vault. Each file is
encrypted on your device with **AES-256-GCM** under a unique key, which is wrapped by
your **Vault Master Key** and sealed using hybrid **X25519 + ML-KEM-1024** (NIST FIPS 203);
every container is dual-signed with **ML-DSA-87 + Ed25519** (FIPS 204 Level 5) and key
derivation uses **HKDF-SHA3-256**. Your Vault Master Key is itself encrypted at rest by
your password, every chunk is tamper- and truncation-proof, and nothing is ever uploaded
to QGuard. A quantum-safe, offline recovery key — with optional enterprise dual-control —
lets you restore your files on a new device if yours is ever lost.

---

## Comparison-table bullets (if you build a "Why Quantum Vault" table)

- **Where encryption happens:** 100% on your device (most: cloud-side or in-browser)
- **Server access to your files:** None — files never leave your machine
- **Algorithms:** NIST FIPS 203 ML-KEM-1024 + FIPS 204 **Level 5** ML-DSA-87 + AES-256-GCM
- **Key protection at rest:** Vault Master Key encrypted by your password (zero-knowledge)
- **Integrity:** Per-chunk tamper + truncation proof
- **File size limit:** None (streamed)
- **Recovery:** Offline quantum-safe key; optional enterprise dual-control
- **Harvest-now-decrypt-later resistant:** Yes

---

## Claim do's & don'ts (keep marketing defensible)

**✅ Do say**
- "Strictly on-device / 100% local / offline," "your files never leave your device"
- "Zero-knowledge, even at rest," "post-quantum / quantum-safe"
- "NIST FIPS 203 & 204 (Level 5)," "tamper-evident," "any file size"
- "Quantum-safe recovery key," "enterprise dual-control recovery"

**🚫 Don't say**
- "Unhackable," "unbreakable," "100% secure," "impossible to crack."
- "Files encrypted with ML-KEM" — ML-KEM protects the *keys*; **AES-256-GCM** encrypts the files.
- Anything implying QGuard can recover your files — **it can't**. If both device and recovery key are lost, the data is unrecoverable (state this as a feature of zero-knowledge, with a "back up your recovery key" reminder).
