# TODO — Portable Hybrid Identity (Quantum Vault desktop)

- [ ] 1. `Cargo.toml`: add `hmac = "0.12"` (already in the lockfile via hkdf) for PBKDF2-SHA3-256 import compat
- [ ] 2. `security/obf.rs`: obfuscated domain-separation tags for the identity bundle + recipient wrap
- [ ] 3. `crypto/portable_identity.rs`: keypairs, `.qgkey` export/import, public recipient JSON, fingerprint, attestation sign/verify (+ unit tests)
- [ ] 4. `crypto/mod.rs`: register module
- [ ] 5. `vault_stream.rs`: v4 `recipient_wraps` + `sender_attestation`, `header_signable` v4 block, seal on encrypt, `decrypt_stream_with_identity`, `inspect_header` (+ unit tests)
- [ ] 6. `state.rs`: unlocked portable-identity session (set/get/clear, cleared by `lock_all_workspaces`)
- [ ] 7. `commands/vault_identity.rs`: generate / import / status / lock / export public / parse recipient / seal file+folder / open sealed file+folder / inspect
- [ ] 8. `commands/mod.rs` + `lib.rs`: register module + handlers
- [ ] 9. `components/vault/PortableIdentityPanel.tsx`: enterprise UI (generate, import, export public, recipient list, seal, open, inspect, auto-lock)
- [ ] 10. `QuantumVaultPage.tsx`: mount panel, renumber panels
- [ ] 11. Verify: `cargo test` (crypto + container round-trips incl. negative controls), `cargo check`, `tsc --noEmit`, `vite build`

## Validation strategy
* Positive: seal→open round-trip for file and folder; sender attestation verifies.
* Negative: wrong identity cannot open; tampered wrap/AAD fails; wrap cannot be moved between
  containers; v3 containers still verify unchanged; recipient never recovers the VMK.
* Build: Rust tests + TypeScript typecheck + production bundle.

## Rollback
Feature is additive: new module + new commands + a v4-only header branch. Reverting the three new
files and the `vault_stream`/`state`/`lib` diffs restores prior behaviour; existing `.qvault` v3
containers are untouched throughout.
