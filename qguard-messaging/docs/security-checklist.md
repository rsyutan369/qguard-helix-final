# Security Checklist

- [x] Private keys remain local-only.
- [x] Public identity bundles are signed.
- [x] Signed prekeys use Ed25519 + ML-DSA-65.
- [x] Session setup combines X25519 + ML-KEM-768.
- [x] HKDF-SHA3-256 derives session and message keys.
- [x] AES-256-GCM authenticates ciphertext.
- [x] Message counters and IDs reject replays.
- [x] Vault file keys are unique per file.
- [x] Vault metadata is signed.
- [x] Device revocation is modeled.
- [x] Supabase RLS is defined for messaging tables.
- [x] Storage bucket is private.
- [ ] External cryptographic audit.
- [ ] Production secrets scanning in CI.
- [ ] Dependency vulnerability scanning in CI.
- [ ] Penetration test before regulated deployment.

