# QGuard Messaging — Android Security Reference

Consolidated Android-specific security documentation: cryptography, JNI,
Android Keystore, WebRTC call security, Quantum Vault, TLS, and the security
checklist. Desktop-shared details live in `cryptographic-design.md`,
`threat-model.md`, and `security-checklist.md`.

## 1. Cryptography (identical native core as desktop)

All algorithms execute natively (NDK-compiled Rust + PQClean C):

| Purpose | Default profile | High-security profile (Quantum Vault) |
|---------|-----------------|----------------------------------------|
| Key exchange | X25519 + **ML-KEM-768** hybrid (FIPS 203) | **ML-KEM-1024** |
| Signatures | Ed25519 + **ML-DSA-65** hybrid (FIPS 204) | **ML-DSA-87** path per crypto-agility policy |
| Symmetric | **AES-256-GCM** only | AES-256-GCM |
| KDF | **HKDF-SHA3-256** (HKDF-SHA-256 compat fallback) | HKDF-SHA3-256 |
| Hashing | SHA3-256 / SHA3-512 | SHA3-256 / SHA3-512 |

Forbidden and absent: AES-CBC/ECB, RC4, DES/3DES, unauthenticated modes.
RNG: `getrandom` → kernel CSPRNG (`/dev/urandom`, hardware-seeded on ARM64).
Secret buffers are `zeroize`d after use (keys, decoded DEKs, plaintext
key-material envelopes).

## 2. JNI surface (JNI_GUIDE)

Two JNI paths exist — both minimal, neither exposes key material to Kotlin:

1. **Tauri IPC bridge** (generated): marshals command names + JSON args
   between the WebView/Kotlin layer and Rust. Commands validate all input
   server-side (Rust) and return no raw private keys.
2. **`security/keystore.rs`** (hand-written, Android-only): Rust *calls into*
   `AndroidKeyStore` over JNI — `KeyStore.getInstance/load/containsAlias/
   getKey`, `KeyGenerator` + `KeyGenParameterSpec.Builder` (AES-256, GCM,
   NoPadding, PURPOSE_ENCRYPT|DECRYPT), `Cipher` AES/GCM/NoPadding.
   Pending Java exceptions are always cleared and converted to typed Rust
   errors so a JNI fault can never crash-loop the app.

Rules: no `unsafe` beyond the required `JavaVM::from_raw` attach; every JNI
call's error path is mapped; no Java-side crypto beyond the non-exportable
Keystore wrapping key.

## 3. Android Keystore usage

- Per-user 32-byte DEK encrypts the device key-material file
  (`{user}.device-key-material.enc`, AES-256-GCM + AAD).
- On Android the DEK itself is wrapped by a **non-exportable AES-256-GCM key
  generated inside `AndroidKeyStore`** (hardware TEE/StrongBox when present):
  `keys/{user}.dek.androidks` = `{v, alias, iv, ct}` (base64).
- The wrapping key cannot leave the Keystore ⇒ copying the app data dir off
  the device yields nothing decryptable. App storage additionally sits under
  Android 10+ file-based encryption and per-UID sandboxing.
- `allowBackup=false` — no key material ever enters device/cloud backups.

## 4. WebRTC call security (WEBRTC_SECURITY)

- Media stack: the Android System WebView's **native libwebrtc** (DTLS-SRTP,
  ICE/STUN/TURN, adaptive bitrate, packet-loss recovery).
- On top, QGuard performs a **hybrid PQC handshake before any media flows**:
  caller/callee identity bundles verified with Ed25519 + ML-DSA-65 dual
  signatures, media key established via X25519 + ML-KEM encapsulation
  (`call_caller_setup` / `call_callee_setup`, async native commands).
- Per-frame encryption uses the derived AES-256-GCM key through Insertable
  Streams (`RTCRtpScriptTransform`, with `createEncodedStreams` fallback) —
  the SFU/TURN path never sees plaintext frames (PFS + session rekey on
  reconnect).
- Camera/mic runtime permissions are requested by `MainActivity`; the WebView
  only receives capture grants the app itself holds.

## 5. Quantum Vault on Android (QUANTUM_VAULT)

- Same native streaming engine as desktop (`vault_stream.rs`): chunked
  AES-256-GCM with per-chunk AAD, ML-KEM-1024 + ML-DSA high-security profile,
  signed metadata, integrity verification (`vault_verify_path`), recovery-key
  and enterprise recovery grants.
- Strictly local: files are encrypted in the app sandbox; nothing auto-uploads.
- Long operations run off the main thread (`spawn_blocking`) with live
  progress streamed to the UI — no ANRs on multi-GB files.

## 6. TLS configuration (TLS_CONFIGURATION)

- All backend traffic (Supabase REST/Realtime, `api.qguard.dev`) is TLS 1.3
  via the platform stack, certificate validation on (no cleartext in release;
  `usesCleartextTraffic=false`).
- **Hybrid TLS (X25519MLKEM768)** is negotiated when both endpoints support
  it — Chromium-based WebViews (M124+) enable the hybrid group by default,
  with policy-controlled classical X25519 fallback otherwise.
- Application-layer payloads remain end-to-end PQC-encrypted regardless of
  the transport suite, so a classical-TLS fallback never exposes message
  content to harvest-now-decrypt-later capture.

## 7. Android security checklist

- [x] No hardcoded secrets (obfuscated service identifiers only; no keys)
- [x] No plaintext key material at rest (Keystore-wrapped DEK + AES-256-GCM envelope)
- [x] No secrets in logs; release builds strip debug logging
- [x] Approved algorithms only; no deprecated crypto anywhere in the native layer
- [x] JNI exposes no private keys to Kotlin
- [x] Replay protection + PFS in messaging ratchet and call sessions
- [x] Certificate validation enforced; no cleartext traffic in release
- [x] `allowBackup=false`; app-private, FBE-encrypted storage
- [x] Runtime permissions minimal (camera/mic/notifications; no location, no contacts upload)
- [x] Secure memory: zeroize on drop for DEKs, key material, plaintexts
- [x] R8/ProGuard minification in release; unsigned-release impossible with signing config present

## 8. Performance (PERFORMANCE_TUNING)

- ARM64 primary ABI; PQClean cores compile with NDK clang `-O` optimizations
  (NEON available; AES-GCM via constant-time software path in RustCrypto).
- Release profile: `lto = true`, `codegen-units = 1`, `opt-level = "z"`,
  `panic = "abort"`, symbols stripped — small `.so`, fast cold start.
- Crypto/KEM work runs on the async worker pool (never the UI thread);
  history decryption is parallel + newest-first with a plaintext cache.
- The WebView UI lazy-loads route chunks and prefetches on idle.
