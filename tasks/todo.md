# FIPS 203 Cutover — Kyber-1024 -> ML-KEM-1024 (2026-08-26)

## Decision
Option A, chosen by the product owner: PURE ML-KEM-1024. No dual-suite, no
transitional Kyber. The labels and the marketing must be literally true.

## Why a clean break is safe here (measured, not assumed)
- `messaging_vault_files` = **0 rows**. No vault container anywhere is sealed
  with Kyber, so nothing in the Vault can be orphaned by the cutover.
- 9 device identities / 9 signed prekeys / 336 one-time prekeys re-key
  automatically on next launch.
- 393 chat envelopes are sealed to pre-FIPS prekeys and will NOT be readable
  after the re-key. Accepted as the cost of Option A (test deployment, 2 users).

## The trap that makes this dangerous
Kyber-1024 and ML-KEM-1024 have **identical key and ciphertext sizes**
(pk/ek 1568, ct 1568; 768: 1184). So:
- `LocalKemKeypair::is_current_*` is a length/parse check and CANNOT see the
  change — old key material would silently be fed to ML-KEM and produce garbage
  shared secrets;
- the stored `suite.pq_kem` string already says "ML-KEM-1024" on pre-FIPS rows,
  so the suite label cannot discriminate either.
Therefore the migration needs an EXPLICIT algorithm marker on persisted key
material, and every path must fail CLOSED when it meets pre-FIPS material.

## Plan
- [x] 1. `Cargo.toml`: `pqcrypto-kyber` -> `pqcrypto-mlkem`, keeping
      `default-features = false, features = ["std"]` — that is the Android SIGILL
      mitigation (portable `clean` C impl; the default `neon` feature emits
      ARMv8.2 SHA3 opcodes with no CPU detection and kills the app on tablets
      lacking FEAT_SHA3).
- [x] 2. `crypto/hybrid_kex.rs`: mlkem1024 only. Delete the kyber768 branch —
      it was also a downgrade surface (parameter set chosen by key LENGTH).
- [x] 3. `LocalKemKeypair`: add a serde-defaulted `kem` algorithm marker so
      pre-FIPS material is detectable; `is_current_suite()` reads the marker.
- [x] 4. `state.rs`: pre-FIPS key material triggers a full re-key and its old
      KEM keys are DISCARDED, not retained as "legacy" — they cannot decapsulate
      an ML-KEM ciphertext, so keeping them would imply a capability that no
      longer exists.
- [x] 5. `crypto/mod.rs` + `portable_identity.rs`: suite constants and the
      display mapping tell the truth about pre-FIPS material.
- [x] 6. Tests: round-trip, marker migration, pre-FIPS material rejected,
      no Kyber left in the dependency graph.
- [x] 7. Verify: `cargo test --lib`, host + `aarch64-linux-android` checks,
      tsc/vitest/vite build. Update CHANGELOG (the 1.3.0 FIPS 203 claim was not
      supported by the dependency actually compiled in).

## Rollback
`git checkout` the listed files + `Cargo.lock`. Devices that already re-keyed
would need to re-key again; nothing is destroyed that the re-key had not already
superseded.

## Result (verified 2026-08-26)

- `cargo test --lib`: **91 passed / 0 failed** (was 88; +4 cutover tests, -1 obsolete
  ML-KEM-768 legacy test). Every vault, portable-identity and recovery test passes
  on real ML-KEM.
- Host `cargo check` clean; `cargo check --target aarch64-linux-android` clean.
- `tsc` clean; 111 frontend tests pass.
- **Proof from the compiled binary, not the source:** the Android arm64 build
  script emits `libml-kem-1024_clean.a` exporting exactly
  `PQCLEAN_MLKEM1024_CLEAN_crypto_kem_{keypair,enc,dec}` and **zero** Kyber
  symbols. `_CLEAN` (not `_AARCH64`) confirms the portable build, so the
  ARMv8.2 SHA3 SIGILL mitigation still holds for the new crate.
- `pqcrypto-kyber` is gone from the source tree and from `Cargo.lock`.

## Consequence to communicate

Re-keying mints a NEW device id, so every existing device row becomes a dormant
identity. That is visible and actionable already: the dormant-identity row added
to the phone dashboard this session tells the user to retire them in Device Trust.
