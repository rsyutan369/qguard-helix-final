# QGuard Quantum Vault — FAQ (web-ready)

> Customer-facing Q&A for landing/help pages. Answers are verified against the
> implementation (see `quantum-vault-security-features.md`) and follow the same
> claim guardrails — accurate, not absolute.

---

### What is the Quantum Vault?
It's a strictly local, post-quantum file vault. You pick any file or folder and QGuard encrypts it **on your device** into a sealed `.qvault` container that you store wherever you like — local disk, external drive, anywhere. Nothing is uploaded to QGuard.

### Is it really quantum-safe?
Yes. Your files are encrypted with **AES-256-GCM**, the keys are sealed with **ML-KEM-1024** (NIST FIPS 203), and each container is signed with **ML-DSA-87** (NIST FIPS 204, Level 5). These are the NIST-standardized algorithms designed to resist quantum computers — which also makes the Vault resistant to "harvest now, decrypt later."

### Where are my files stored — does QGuard see them?
They're stored only where *you* save the `.qvault` file. Encryption and decryption happen entirely on your device, and **nothing is ever uploaded to QGuard's servers**. There's no copy on our side to read, hand over, or leak.

### How are the files actually protected?
In layers. Each file gets its own **AES-256-GCM** key; that key is wrapped by your **Vault Master Key**; and the Vault Master Key is sealed with hybrid **X25519 + ML-KEM-1024**. The whole container is then signed with **ML-DSA-87 + Ed25519**. Breaking any single layer doesn't open your files.

### Can someone tamper with a `.qvault` file without me knowing?
No — it's tamper-evident. Every chunk is authenticated and bound to its exact position, and the signature covers the total chunk count. Any modified, reordered, dropped, or appended data is detected and the file is rejected on decryption.

### Is there a limit on file or folder size?
No. Files are encrypted in a streaming fashion with constant memory, so you can seal anything from a small document to very large files and entire folders. When you encrypt a folder, even its internal structure is hidden inside the ciphertext.

### What protects the vault while it's "locked"?
Your **Vault Master Key is itself encrypted by your workspace password/PIN** (Zero-Trust Workspace Lock). When the vault is locked, even your own device holds only ciphertext. Every operation requires unlocking, there's brute-force lockout protection, and it locks automatically when you're idle or minimize the app.

### What happens if I lose my device?
Set up a **recovery key** in advance. It's a quantum-safe, offline key that re-derives your wrapping key on a brand-new device and decrypts your `.qvault` files straight from your drive — no access to the lost device needed. Teams can use **enterprise** or **hybrid (dual-control)** recovery instead.

### What if I lose BOTH my device and my recovery key?
Then the files cannot be recovered — by anyone, including QGuard. This is intentional: because the recovery secret never leaves you and is never stored on our servers, there is no backdoor. **Keep your recovery key backed up offline** (print it or store it in a password manager).

### What is "enterprise" / "hybrid" recovery?
For organizations: **enterprise** mode also seals files to a company recovery key (an ML-KEM-1024 key the admin keeps offline). **Hybrid** mode requires *both* the personal recovery key **and** the enterprise key to restore a file — cryptographically enforced two-person control for regulated environments.

### Can I add recovery to files I already encrypted?
Yes. "Re-protect" rewraps existing containers to add a recovery key (and upgrade older files to the latest format) **without re-encrypting the file contents** — it's fast even for large files.

### Is it unhackable?
No serious security product should claim that. What we *can* say precisely: your files are **encrypted on your device with NIST post-quantum cryptography**, the Vault is **zero-knowledge and never uploads your data**, and the container is **tamper-evident**. The strength of your password and the safekeeping of your recovery key are the parts in your hands.

### Which standards and algorithms does it use?
- **File encryption:** AES-256-GCM (FIPS 197)
- **Key protection:** ML-KEM-1024 + X25519 (FIPS 203)
- **Container signature:** ML-DSA-87 + Ed25519 — Level 5 (FIPS 204)
- **Key derivation / hashing:** HKDF-SHA3-256 / SHA3-256 (FIPS 202)
