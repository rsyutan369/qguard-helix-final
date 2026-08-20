# Quantum Vault — Portable Hybrid Identity (desktop)

## Goal
Let a QGuard desktop user create/import a **Portable Hybrid Identity** (`.qgkey`) and use it to
seal `.qvault` containers **to another person**, so quantum-encrypted files/folders can be shared
without either side handing over the device key or the Vault Master Key.

Mirrors `src/app/dashboard/vault` (`PortableIdentityCard` + `lib/vault/qgkey.ts` +
`lib/vault/sharing-crypto.ts`) at the JSON level, implemented natively in Rust.

## Components

| Layer | Unit | Responsibility |
|---|---|---|
| Crypto | `crypto/portable_identity.rs` (new) | Identity keypairs, `.qgkey` bundle export/import, public recipient JSON, fingerprints, sender attestation sign/verify |
| Container | `vault_stream.rs` (extended) | v4 header: `recipient_wraps[]` (FEK sealed per recipient) + `sender_attestation`; seal + open + inspect |
| Session | `state.rs` | In-memory unlocked identity, zeroized on lock/sign-out |
| IPC | `commands/vault_identity.rs` (new) | Tauri commands for generate/import/lock/export/seal/open/inspect |
| UI | `components/vault/PortableIdentityPanel.tsx` (new) | Enterprise panel inside `QuantumVaultPage` |

## Data flow — sharing

```
Bob:   generate identity -> bob.qgkey (private, passphrase-sealed)
                         -> bob.qgpub.json (public recipient bundle)   --> sends to Alice
Alice: paste/load bob.qgpub.json -> pick file -> "Seal for recipients"
       FEK (AES-256-GCM) encrypts the data
       FEK -> wrapped for Bob:  X25519 + ML-KEM-1024 -> HKDF-SHA3-256 -> AES-256-GCM
       FEK -> also wrapped under Alice's VMK  (Alice keeps access)
       VMK -> wrapped to Alice's device + recovery/enterprise recipients (unchanged)
       header signed Ed25519 + ML-DSA-87 (device vault signer)
       + optional sender attestation signed by Alice's portable identity
Bob:   unlock bob.qgkey -> "Open sealed container" -> FEK unwrapped directly -> stream decrypt
```

## Trust boundaries / threat model

* **The recipient wrap seals the per-file FEK, never the VMK.** A recipient learns the key for
  exactly the file shared with them and nothing else in the sender's vault.
* Every wrap is AAD-bound to `file_id | owner_user_id | recipient_fingerprint`, so a wrap cannot be
  lifted into another container or re-pointed at another recipient.
* The `.qgkey` private bundle is Argon2id(64 MiB, t=3) + HKDF-SHA3-256 + AES-256-GCM. It is written
  to disk only where the user chooses and never leaves the device.
* Public recipient bundles carry all four public keys; the fingerprint covers all four, so swapping
  a signing key changes the fingerprint the user verifies out of band.
* Sender attestation is a *second, independent* signature by the sender's portable identity over the
  same canonical header bytes — the recipient sees a verified sender fingerprint, not a claim.
* No network path: sealing and opening are entirely local, same as the rest of the Quantum Vault.

## Format compatibility

* `.qgkey` v1.2 (this app, Argon2id) is written; v1.1 (web, PBKDF2-SHA3-256/310k) is also **read**.
* Public recipient JSON matches the web's `publicRecipientBundle` shape exactly.
* Identities carrying ML-DSA-65 (web-generated) can receive and be sealed to; sender attestation
  requires ML-DSA-87 and is reported as unavailable otherwise.
* `.qvault` v1/v2/v3 containers keep verifying byte-identically — v4 signable bytes are appended
  only when `version >= 4`.
