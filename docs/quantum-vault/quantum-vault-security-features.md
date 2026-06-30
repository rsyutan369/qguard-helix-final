# QGuard Quantum Vault — Security & Advanced Features (Reference)

> **Source of truth, verified against code (2026-06-30).** Every claim maps to the
> actual implementation in `qguard-messaging`. Use the "Accuracy guidance" section
> before writing public copy.
>
> Key files: `src-tauri/src/vault_stream.rs`, `commands/vault.rs`,
> `crypto/vault_recovery.rs`, `crypto/hybrid_kex.rs`, `crypto/signatures.rs`,
> `crypto/symmetric.rs`, `crypto/kdf.rs`, `state.rs`, `src/pages/QuantumVaultPage.tsx`,
> `src/lib/vault-progress.ts`.

## Positioning (accurate one-liners)
- **Strictly local, zero-knowledge, post-quantum file vault.** Files are encrypted and decrypted entirely on your device; nothing is ever uploaded to QGuard.
- **Quantum-safe envelope** — NIST FIPS 203 (ML-KEM-1024) + FIPS 204 Level 5 (ML-DSA-87), AES-256-GCM, HKDF-SHA3-256.
- **Built to survive device loss** — an offline, quantum-safe recovery key (with optional enterprise dual-control) decrypts your `.qvault` files on a brand-new device.

## 1. Cryptographic foundation (the exact suite)

| Purpose | Algorithm | Standard |
|---|---|---|
| Bulk file/chunk encryption | **AES-256-GCM** (per-file key, 1 MiB chunks) | FIPS 197 / SP 800-38D |
| Key wrapping (FEK → VMK) | **AES-256-GCM** | FIPS 197 |
| Key protection (VMK / recovery) | **ML-KEM-1024 + X25519** (hybrid KEM) | FIPS 203 + RFC 7748 |
| Container signature (v3, dual) | **ML-DSA-87 + Ed25519** (Level 5) | FIPS 204 Level 5 |
| Key derivation | **HKDF-SHA3-256** | FIPS 202 |
| Hashing / fingerprints / checksums | **SHA3-256** | FIPS 202 |

> ML-KEM is used for **key encapsulation only** — it protects the keys that protect your files. It never encrypts file content directly. Older `.qvault` containers (v1/v2, ML-DSA-65) still decrypt; new files are always written as v3.

## 2. The encryption envelope (defense in depth)
A `.qvault` file is sealed in layers so no single key exposure breaks it:
1. **File content → AES-256-GCM** with a unique per-file key (FEK), streamed in 1 MiB chunks (constant memory, **any file size**).
2. **FEK → wrapped by the Vault Master Key (VMK)** with AES-256-GCM.
3. **VMK → sealed with hybrid X25519 + ML-KEM-1024** to this device, and (optionally) to your recovery key and/or an enterprise recovery recipient.
4. **Signed header (Ed25519 + ML-DSA-87)** authenticates the wrapped keys, metadata, **and the total chunk count** — proving the file hasn't been truncated, extended, or swapped.

## 3. Tamper, truncation & integrity protection
- Every chunk's AES-256-GCM tag is **bound (AAD) to the file ID, chunk index, total chunks, and last-chunk flag** — so any modified, reordered, dropped, or appended chunk is detected and rejected.
- The dual signature covers the chunk count, giving **truncation/extension proof** for the whole container.
- **Wrong device key cannot decrypt**; **tampered or truncated containers are rejected**; folder archives **reject path-traversal** on extraction.
- Writes are **atomic** (`.qguard-part` → rename) so an interrupted operation never corrupts an existing file.

## 4. Vault Master Key & Zero-Trust access
- The **VMK and the ML-DSA-87 signer are themselves encrypted at rest** by your workspace password/PIN: password → **HKDF-SHA3-256 → unlock key → AES-256-GCM-wraps the VMK**. Even locally, the VMK only exists password-wrapped — true zero-knowledge at rest.
- **Every vault operation requires unlock** (Zero-Trust Workspace Lock), with anti-brute-force lockout and automatic locking on idle/minimize.

## 5. Quantum-safe recovery (survive total device loss)
Three modes, all zero-knowledge — the recovery secret never reaches our servers:
- **Personal** — a 256-bit recovery key shown as a checksummed, typo-resistant **Crockford-Base32** string. It derives an AES-256-GCM wrapping key via HKDF-SHA3-256; a separate verifier confirms re-entry without exposing the key. Store it offline (download/print).
- **Enterprise** — files are also sealed to an **ML-KEM-1024** enterprise recovery recipient; the admin keeps the offline private-key file.
- **Hybrid (dual-control)** — recovery requires **both** the personal recovery key **and** the enterprise key (two-person integrity), enforced cryptographically.

Recovery decrypts `.qvault` files **straight from an external drive on a new device**, with no access to the lost device. **Re-protect** upgrades older containers to v3 and adds recovery wraps **without re-encrypting the bulk data**.

## 6. Folder protection
- Encrypt an entire folder into a **single `.qvault` archive**; file paths live **inside the ciphertext**, so the directory structure is hidden too. Restored safely with path-traversal protection.

## 7. Operations, telemetry & UX
- **Vault Crypto Terminal** — real, live per-phase and per-chunk progress: FEK generation, VMK seal (X25519 + ML-KEM-1024), header signing (ML-DSA-87), streaming chunks, with **throughput (MB/s) and ETA**. All values are measured from the real operation — never simulated.
- **Vault Explorer** — a device-local, **metadata-only** registry (no plaintext, no keys): folder/file tree, sizes, and status.
- **Activity log, security profile, and live device-key / signature-verification status.**
- Local-only, offline, external-drive friendly; **any file or folder size**.
- Permanent delete is restricted to `.qvault` files; decrypt operations are rate-limited.

---

## ⚠️ Accuracy guidance for marketing (so claims stay defensible)
- ✅ **Safe to say:** "strictly local / on-device / offline," "zero-knowledge (even at rest)," "post-quantum / quantum-safe," "NIST FIPS 203 & 204 (Level 5)," "your files never leave your device," "tamper-evident," "any file size," "quantum-safe recovery key," "enterprise dual-control recovery."
- ⚠️ **State the recovery trade-off honestly:** because it's zero-knowledge, **if you lose both your device and your recovery key, the files cannot be recovered — by anyone, including QGuard.** That's the same property that guarantees no one else can read them.
- ⚠️ **Be precise about ML-KEM:** it protects *keys*, not file content (AES-256-GCM encrypts the content). Don't say "files encrypted with ML-KEM."
- 🚫 **Don't say:** "unbreakable," "unhackable," "100% secure."
