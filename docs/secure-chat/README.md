# QGuard Secure Chat — Documentation

Security feature documentation and ready-to-use copy for QGuard Secure Chat.
All marketing/FAQ/store copy derives from the technical reference, which is the
**single source of truth** verified against the implementation.

## Contents

| Doc | Purpose | Audience |
|---|---|---|
| [secure-chat-security-features.md](./secure-chat-security-features.md) | **Source of truth.** Full, code-verified feature inventory: exact algorithm suite, message/call/attachment crypto, device trust, zero-knowledge backend. | Engineering, security review, technical marketing |
| [secure-chat-marketing-copy.md](./secure-chat-marketing-copy.md) | Condensed, landing-page-ready copy: hero, feature cards, "how it's protected" band, about paragraph, comparison bullets. | Web / marketing |
| [secure-chat-faq.md](./secure-chat-faq.md) | Customer-facing Q&A (14 questions) in plain language. | Web / support |
| [secure-chat-store-and-meta.md](./secure-chat-store-and-meta.md) | SEO meta description, Open Graph / Twitter cards, and app-store listing copy (with char counts). | Web / app-store |

## How to use these

1. Write or update public copy from the **marketing**, **FAQ**, and **store/meta** docs.
2. When in doubt about a technical claim, check it against **secure-chat-security-features.md** — do not invent specifics.
3. Keep every claim within the guardrails below.

## Claim guardrails (applies to all public copy)

- ✅ **Say:** "post-quantum / quantum-safe," "NIST FIPS 203 & 204," "hybrid classical + post-quantum," "end-to-end encrypted," "zero-knowledge," "forward secrecy," "harvest-now-decrypt-later resistant," "not even QGuard can read your messages or calls."
- 🚫 **Avoid:** "unhackable," "unbreakable," "100% secure," "impossible to intercept." Use *"so no one in the middle — not even QGuard — can read it"* instead.
- ⚠️ Active man-in-the-middle protection **requires the user to verify the safety number** — phrase it as a one-tap verification, never as automatic.
- ⚠️ Don't call it the "Signal Double Ratchet" — it is a *post-quantum per-message key agreement with ratcheting + replay protection*.

## Verified algorithm suite (quick reference)

| Purpose | Algorithm | Standard |
|---|---|---|
| Key encapsulation (hybrid) | ML-KEM-1024 + X25519 | FIPS 203 |
| Signatures (dual) | ML-DSA-65 + Ed25519 | FIPS 204 |
| Symmetric / AEAD | AES-256-GCM | FIPS 197 |
| KDF / hashing | HKDF-SHA3-256 / SHA3-256 | FIPS 202 |

---

_Last verified against the implementation: 2026-06-30. Re-verify the source-of-truth
doc against the code after any change to `qguard-messaging` crypto, messaging, or call modules._
