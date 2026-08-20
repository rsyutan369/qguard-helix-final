# Portable Hybrid Identity (Quantum Vault desktop) — COMPLETE

- [x] 1. `Cargo.toml`: `hmac = "0.12"` (already in the lockfile via hkdf) for PBKDF2-SHA3-256 import compat
- [x] 2. `security/obf.rs`: obfuscated domain-separation tags + round-trip assertions
- [x] 3. `crypto/portable_identity.rs`: keypairs, `.qgkey` export/import, public recipient JSON, fingerprint, attestation
- [x] 4. `crypto/mod.rs`: module registered
- [x] 5. `vault_stream.rs`: v4 `recipient_wraps` + `sender_identity`, v4 `header_signable` block, `attestation_signable`, seal on encrypt, `decrypt_stream_with_identity`, `inspect_stream`
- [x] 6. `state.rs`: unlocked-identity session, cleared by `lock_all_workspaces`
- [x] 7. `commands/vault_identity.rs`: generate / import / status / lock / export public / parse + load recipient / seal file+folder / inspect / open file+folder
- [x] 8. `commands/mod.rs` + `lib.rs`: module + 12 handlers registered
- [x] 9. `components/vault/PortableIdentityPanel.tsx`
- [x] 10. `QuantumVaultPage.tsx`: mounted as Panel 3, Explorer renumbered to 4
- [x] 11. Verified

## Verification results

| Check | Result |
|---|---|
| `cargo test --lib` | **88 passed, 0 failed** (was 55 before this work) |
| `cargo check --lib` | clean, no warnings |
| `tsc --noEmit` | clean |
| `npm run build` | bundle built (QuantumVaultPage 100.29 kB) |
| Panel render (Vite + a11y tree) | all sections present; every gate correct: Seal disabled without a ticked recipient, Open disabled while locked, Inspect enabled (needs no identity), Add-recipient disabled on empty input; no horizontal overflow |

### Positive controls
seal→open round trip for file (multi-chunk) and folder archive; multi-recipient (each opens); owner still opens their own sealed container; sender attestation verifies; `.qgkey`/`.qgpub.json` written to and read back from real disk; re-protect preserves both the share and the attestation.

### Negative controls
wrong identity cannot open (and writes no plaintext); wrong passphrase rejected; tampered bundle rejected; mismatched key pair rejected at import; lying fingerprint in a recipient bundle rejected; partial recipient bundle rejected; forged/relabelled sender attestation rejected; recipient wrap cannot be moved to another container or re-pointed at another identity; added recipient without re-signing fails the header signature; recipient material declared on a v3 header refused; **recipient never recovers the VMK** (cannot open a sibling container); PBKDF2 known-answer test; v1/v2/v3 containers still verify byte-identically.

## Not verified here
The full desktop flow inside the running Tauri app (login + workspace unlock) — it needs real Supabase credentials, so it was not driven. Everything below that boundary is covered by the tests above; the panel itself was rendered and exercised in a browser.
