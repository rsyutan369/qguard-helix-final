# QGuard Messaging - Production Hardening

The **Production Hardening Gate** on the Quantum Security page reports *real
runtime/release evidence*. Each control is "Active" only when the running build
actually presents that evidence - nothing is hardcoded or faked. In a dev
(`debug`) build several controls correctly read **Review**; they become **Active**
in a hardened release produced by `scripts/release-build.ps1`.

> The platform's *cryptographic* security (ML-KEM-1024 / ML-DSA-65, AES-256-GCM
> AEAD, zeroize, tamper-evident audit chain, anti-debugger probe, rate limiting)
> is always active. The gate below is specifically about **anti-reverse-engineering
> and release-integrity** controls.

## One-command hardened release

```powershell
# optional: reuse a saved release key + sign the binary with your cert
$env:QGUARD_RELEASE_PRIVKEY_HEX = "<ed25519 private key hex>"   # else one is generated
$env:QGUARD_CERT_THUMBPRINT     = "<windows code-signing cert thumbprint>"  # optional

pwsh ./scripts/release-build.ps1
```

Ship `src-tauri/target/release/qguard-messaging.exe` **together with the
`release.integrity.json`** written next to it (same folder).

## How each gate control becomes genuinely active

| Control | Evidence | Status now | How it activates |
|---|---|---|---|
| **Code Obfuscation** | `!debug_assertions` + release profile | Review in debug | Any `--release` build. `[profile.release]` already does strip, lto, codegen-units=1, panic=abort, opt-level=z. |
| **String Encryption** | Compile-time XOR obfuscation of sensitive identifiers/protocol tags (`security::obf`) | Active in release | Always compiled in; plaintext for these strings is not present in the binary. |
| **Binary Integrity** | `release.integrity.json` (SHA3-256 of the exe + Ed25519 signature) verified at runtime against the embedded release public key | Review until released | `release-build.ps1` writes and signs the manifest; the runtime re-hashes its own exe and verifies hash + signature. |
| **Signed Build** | `QGUARD_SIGNED_BUILD=1` set by the pipeline only after a successful Authenticode sign+verify | Review (no cert) | Provide a cert thumbprint; the script signs with signtool and aborts if verification fails, so it cannot report active falsely. |
| **Control-Flow Flattening** | `QGUARD_CONTROL_FLOW_FLATTENING=1` | Review | **Not faked.** Rust has no turnkey CFF. Requires an external LLVM obfuscation toolchain - see below. |

### Trust-root note (important)
A self-checking binary hash detects accidental corruption and casual tampering,
but cannot stop an attacker who also rewrites the check. The **external trust
root** is **code signing** (Authenticode). The Ed25519 manifest signature raises
the bar (an attacker needs the offline release private key to forge a matching
manifest), but for production tamper-resistance enable code signing:

1. Obtain a Windows code-signing certificate.
2. Put its SHA1 thumbprint in `src-tauri/tauri.conf.json` ->
   `bundle.windows.certificateThumbprint`, or pass it to the release script.

### Control-Flow Flattening (honest path)
There is no safe, turnkey way to flatten control flow in stock Rust without
changing behavior. Genuine options:

* Build with an **LLVM obfuscation pass** (obfuscator-LLVM / Hikari / Polaris)
  via a custom toolchain, then export `QGUARD_CONTROL_FLOW_FLATTENING=1` for the
  Rust build so the marker reflects the real transform.
* Use a commercial binary obfuscator on the produced exe and set the marker in
  the pipeline once applied.

Until a real pass is wired, this control honestly stays **Review** - do **not**
set the env var without performing the transform.

## What the runtime checks (source of truth)
* `src-tauri/src/security/mod.rs` - `hardening_status()` derives every gate value
  from real evidence (binary measurement, release manifest, env markers).
* `src-tauri/src/security/obf.rs` - compile-time string obfuscation; the
  `#[cfg(test)]` round-trip test proves de-obfuscation is byte-identical to the
  originals, so cryptographic domain separation is unchanged.
* `src-tauri/examples/release_integrity.rs` - keygen / pubkey / sign tool used by
  the release script to produce the signed integrity manifest.
## Quantum Vault cryptography

The Quantum Vault (`.qvault` containers, Portable Hybrid Identities, sealing and
opening) is built from these primitives and nothing else:

| Purpose | Algorithm |
|---|---|
| Key encapsulation | X25519 + **ML-KEM-1024** (FIPS 203, `pqcrypto-mlkem`) |
| Container signature | Ed25519 + **ML-DSA-87** (FIPS 204 Level 5) |
| Bulk content | **AES-256-GCM**, one key per file, re-keyed per container |
| Key derivation | **HKDF-SHA3-256** |
| Password stretching | **Argon2id** (64 MiB, t=3, p=1) → HKDF-SHA3-256 |
| Identity passphrase | **Argon2id** + a 70-bit entropy floor (see below) |

ML-KEM is used for **key encapsulation only** — it never encrypts file content.
Content is always AES-256-GCM, chunk by chunk, with each chunk's AAD bound to the
container's file id, chunk index and total chunk count, so a container cannot be
truncated, extended or have its chunks reordered without detection.

### FIPS 203 conformance

The ML-KEM implementation is `pqcrypto-mlkem` (PQClean, final FIPS 203).

Builds up to and including 1.2.29 reached ML-KEM through `pqcrypto-kyber`
0.8.1. Despite the name that crate is **not** round-3 Kyber — it vendors
PQClean's ML-KEM *initial public draft*. The only divergence from the final
standard is key generation: the IPD expands a seed as `G(d)` where FIPS 203
specifies `G(d ‖ k)`. Encapsulation, decapsulation, and the public key / secret
key / ciphertext encodings are byte-identical, which is why:

* key material and containers written by earlier builds keep opening unchanged
  (pinned by a known-answer vector in `src/crypto/testdata/`, exercised by
  `pre_migration_key_material_still_decapsulates`), and
* Portable Hybrid Identities interoperate in both directions with the web
  vault's `@noble/post-quantum` ML-KEM-1024.

What the move buys is conformance: seed-to-key expansion now matches the
published standard, so FIPS 203 keygen test vectors pass.

### What it takes to open a container

On v3 containers the per-file key is wrapped by the Vault Master Key, and the
VMK is sealed under the user's vault password (Argon2id → HKDF-SHA3-256 →
AES-256-GCM). The VMK path is the primary way the app opens a container, so the
password is a genuine cryptographic gate, not a UI check.

The container also carries an ML-KEM wrap of the VMK. That wrap is sealed to the
**vault's own ML-KEM keypair**, which is stored inside the same password-wrapped
vault master. Previously it was sealed to the messaging device identity key,
whose secret is protected by the OS keychain alone — which meant someone with
the app data directory and keychain access could recover the VMK and decrypt the
whole vault without the password. Containers written before this change are
still wrapped that way; re-protect them with **Re-protect / rewrap** to move them
onto the password-gated keypair.

### Identity bundle passphrases

A `.qgkey` is an offline artefact: once someone has the file, nothing rate-limits
their guessing. Argon2id at 64 MiB buys a constant factor per guess; the
passphrase's entropy is the only thing that grows exponentially. So creating a
bundle requires **70 bits of estimated entropy**, not a character count — a
12-character password a person invented ("Summer2024!") clears any length rule
and falls to a wordlist, while the same rule rejects it here.

The estimator (`crypto::passphrase`) scores structure rather than characters: a
run of letters shaped like a word costs one dictionary lookup, a four-digit run
inside 1900–2100 costs a year, repeated symbols cost almost nothing after the
first. Where a word model and a composition model disagree, the lower wins —
an estimator that guesses high tells the user they are safe when they are not.
`calibration::known_passphrases_land_where_they_should` pins the behaviour on a
table of known inputs, including xkcd 936's own two examples.

Two limits are worth knowing: there is no breach corpus, and no grammar model —
so a long grammatical sentence scores like a long word list even though each word
predicts the next. Both limits mean a human-chosen passphrase is worth *less*
than the score suggests, which is why the UI leads with **Generate**: seven words
drawn uniformly without replacement from a 2048-word list, carrying 77 bits that
are counted rather than estimated.

### Which containers still need re-protecting

The app knows, rather than asking you to remember. `vault_protection_scan` reads
each container's **header only** — one ML-KEM decapsulation regardless of whether
the file is 4 KB or 40 GB — and reports whether its key wrap opens with the
vault's own keypair or only with the older, keychain-reachable device key. Stale
containers surface as a banner on the vault page and a marker on the row, and
re-protecting rewrites only those. The encrypted chunks are copied across
verbatim; nothing is re-encrypted and nothing is decrypted on the way.

### Messaging vs. the vault

Messaging and calls share the same hybrid KEM code and are equally on FIPS 203
ML-KEM after this change. Their prekeys are published to the relay, and because
encapsulation and decapsulation are unchanged, devices on older builds
interoperate with updated ones in both directions — no fleet split, no schema
change.
