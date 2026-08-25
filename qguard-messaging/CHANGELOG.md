# Changelog

All notable changes to the QGuard Messaging desktop application.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versions are set in `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml` and the
website download label in `../src/app/qguard-messaging/_shared.tsx` — all three
are kept in lock-step by `tools/release.ps1`, because a mismatch silently breaks
auto-update.

## [1.3.0] — 2026-08-25

### Security

- **Quantum Vault: recipient fingerprint verification is now required before
  sealing.** Sealing a vault file to a recipient no longer proceeds on an
  unverified identity — the recipient's key fingerprint must be confirmed first.
  This closes the window in which a substituted recipient key could be accepted
  silently.
- **Identity passphrases are checked for real strength.** Passphrase entry now
  applies genuine strength evaluation rather than a length check alone, so weak
  passphrases can no longer protect a long-lived identity key.
- **ML-KEM key generation is conformant to final FIPS 203.** Key generation now
  follows the published FIPS 203 standard rather than a pre-final draft.

### Migration

Nothing you already have needs migrating. Existing identities, vault files and
conversations continue to work unchanged after updating.

## [1.2.29] — earlier release

### Fixed

- Pointed the app at the current Supabase project. The shipped 1.2.28 bundle had
  a deleted project ref inlined at build time, so sign-in failed with "Couldn't
  reach the secure sign-in service" (a DNS NXDOMAIN, not a credential error).
- Aligned the version across all three version files (they had drifted to
  1.2.28 / 1.2.20 / 1.2.20).
- Signed the updater artifact with the real key; the previous signature was
  stale and did not match the shipped binary.
- Corrected the `latest.json` download URL, which was a malformed path.

## [1.2.0] — earlier release

### Added

- Workspace-lock recovery for Secure Chat and Quantum Vault.
- Signed installer and updater artifacts.
