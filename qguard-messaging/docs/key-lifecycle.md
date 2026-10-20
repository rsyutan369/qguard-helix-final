# Key Lifecycle

Each device owns independent key material:

- X25519 identity key
- ML-KEM-1024 identity key
- Ed25519 signing identity key
- ML-DSA-65 signing identity key
- Signed hybrid prekey
- One-time hybrid prekeys

Private keys remain local and are persisted through the device OS keychain / secure credential store. Public keys and signed public prekeys may be stored by Supabase.

## Decryption Unlock

- Vault decrypt actions validate the active Supabase session before key use.
- MFA assurance is checked when the account policy requires AAL2.
- The desktop backend unlocks local key material in-process and never returns private key bytes to the UI or backend.
- Decryption attempts are rate limited client-side and in the Tauri backend.
- Session logout clears volatile identities, prekeys, ratchets, decrypted message cache entries, and decryption attempt counters.
- Seed phrases are intentionally not used for vault decryption.

## Rotation

- Signed prekeys rotate at least every 30 days.
- One-time prekeys are replenished when inventory is low.
- Identity keys rotate only on explicit device reset or security incident.
- An explicit device reset (Device Trust Center → Reset Device Keys) replaces the identity, its prekeys, the message-key ledger, ratchet sessions and queued outbox sends. It keeps the device storage key when that key still loads, because the key also seals the Secure Chat and Quantum Vault lock records, vault recovery material, device pins and the app-entry PIN. A storage key that no longer loads is replaced; a workspace lock sealed under the lost key then reports as unreadable and can only be replaced through the re-authenticated reset (account password for Secure Chat; recovery key or start-fresh for the vault), never treated as "no lock set".
- Existing sessions report key changes and require user verification.

## Revocation

Device revocation marks a device untrusted, blocks future message fanout, and revokes future vault grants. Previously delivered ciphertext cannot be clawed back from a compromised endpoint.
