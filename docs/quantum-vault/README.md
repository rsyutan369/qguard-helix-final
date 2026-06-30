# QGuard Quantum Vault — Documentation

Security feature documentation and ready-to-use copy for QGuard Quantum Vault.
All marketing/FAQ/store copy derives from the technical reference, which is the
**single source of truth** verified against the implementation.

## Contents

| Doc | Purpose | Audience |
|---|---|---|
| [quantum-vault-security-features.md](./quantum-vault-security-features.md) | **Source of truth.** Full, code-verified feature inventory: exact algorithm suite, layered key envelope, tamper/truncation proofs, zero-knowledge-at-rest, recovery modes. | Engineering, security review, technical marketing |
| [quantum-vault-marketing-copy.md](./quantum-vault-marketing-copy.md) | Condensed, landing-page-ready copy: hero, feature cards, "how it works" band, about paragraph, comparison bullets. | Web / marketing |
| [quantum-vault-faq.md](./quantum-vault-faq.md) | Customer-facing Q&A (13 questions) in plain language. | Web / support |
| [quantum-vault-store-and-meta.md](./quantum-vault-store-and-meta.md) | SEO meta description, Open Graph / Twitter cards, and app-store listing copy (with char counts). | Web / app-store |

## How to use these

1. Write or update public copy from the **marketing**, **FAQ**, and **store/meta** docs.
2. When in doubt about a technical claim, check it against **quantum-vault-security-features.md** — do not invent specifics.
3. Keep every claim within the guardrails below.

## Claim guardrails (applies to all public copy)

- ✅ **Say:** "strictly on-device / 100% local / offline," "zero-knowledge (even at rest)," "post-quantum / quantum-safe," "NIST FIPS 203 & 204 (Level 5)," "your files never leave your device," "tamper-evident," "any file size," "quantum-safe recovery," "enterprise dual-control recovery."
- 🚫 **Avoid:** "unhackable," "unbreakable," "100% secure," "impossible to crack."
- ⚠️ **Be precise about ML-KEM:** it protects *keys*; **AES-256-GCM** encrypts file content. Don't say "files encrypted with ML-KEM."
- ⚠️ **Recovery is zero-knowledge:** QGuard cannot recover files for a user. Always pair the recovery story with "back up your recovery key — if both it and your device are lost, the files are unrecoverable."

## Verified algorithm suite (quick reference)

| Purpose | Algorithm | Standard |
|---|---|---|
| File encryption (per-file key, chunked) | AES-256-GCM | FIPS 197 |
| Key protection (VMK / recovery) | ML-KEM-1024 + X25519 | FIPS 203 |
| Container signature (dual, Level 5) | ML-DSA-87 + Ed25519 | FIPS 204 L5 |
| KDF / hashing | HKDF-SHA3-256 / SHA3-256 | FIPS 202 |

> See also the Secure Chat documentation set in `docs/secure-chat/`.

---

_Last verified against the implementation: 2026-06-30. Re-verify the source-of-truth
doc against the code after any change to `qguard-messaging` vault, crypto, or recovery modules._
