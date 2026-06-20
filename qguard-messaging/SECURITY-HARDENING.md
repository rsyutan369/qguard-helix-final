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