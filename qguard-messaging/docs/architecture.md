# Architecture Overview

QGuard Messaging is local-first. The React UI calls Tauri commands, and the Rust core performs identity generation, prekey generation, session setup, message encryption, vault encryption, audit chaining, and security reporting.

Supabase is a zero-knowledge relay:

- Auth validates users.
- Database stores public identity bundles, public prekeys, encrypted message envelopes, encrypted file metadata, grants, receipts, and security events.
- Storage stores encrypted file blobs only.
- Realtime notifies clients about encrypted queues, receipts, vault changes, and warnings.

The server must never receive private keys, raw session keys, plaintext messages, plaintext files, decrypted metadata, or recovery secrets.

## Desktop Modules

- `identity`: per-device hybrid identity bundles.
- `prekeys`: signed prekeys and one-time prekeys.
- `crypto/hybrid_kex`: X25519 + ML-KEM-1024 key agreement.
- `ratchet`: per-message key derivation and replay protection.
- `message_crypto`: encrypted message envelopes.
- `file_crypto`: envelope encryption for vault files.
- `device_trust`: linked device status and revocation.
- `audit`: local hash-chained audit log.
- `telemetry`: dashboard and quantum security status.
