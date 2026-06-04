# PQC Migration Model

The default implementation uses pure Rust PQC crates for portability and to match the existing QGuard Vault direction. The `oqs-backend` Cargo feature is reserved as a packaging point for liboqs-backed builds.

Migration rules:

- Protocol objects include algorithm identifiers.
- New sessions use the strongest enabled suite.
- Old sessions retain their suite until rotated or re-established.
- Vault files can be rewrapped without re-encrypting file chunks.
- Algorithm upgrades must produce key-change events and require device trust review.

