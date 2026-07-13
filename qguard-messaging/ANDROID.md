# QGuard Messaging for Android

The Android edition of QGuard Messaging is built from this same repository using
**Tauri 2 mobile**. It shares the desktop app's native Rust post-quantum
cryptography core (ML-KEM, ML-DSA, AES-256-GCM, HKDF-SHA3-256) compiled to
ARM64 with **Android NDK r27**, and presents a premium Material-inspired mobile
UI (light + dark) matching the QGuard Android design language.

## What ships

- **Secure Chat** — hybrid PQC E2EE messaging (single pane list ⇄ thread flow)
- **Encrypted voice/video calls** — quantum-safe media keys, verified peers
- **Quantum Vault** — local-only encrypted files (ML-KEM-1024 high-security)
- **Device trust, key management, security verification, audit, settings**
- **First-run onboarding** — branded splash + 3-slide quantum-security tour
- **Floating bottom navigation** (Home / Chats / Vault / Security / Settings)
  with an all-modules sheet, light/dark theme toggle, and unread badges

## Quick start

```powershell
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
$env:NDK_HOME     = "$env:ANDROID_HOME\ndk\27.2.12479018"
$env:JAVA_HOME    = "C:\Program Files\Android\Android Studio\jbr"

# From qguard-messaging/
npx tauri android dev                                   # live-reload on device/emulator
npx tauri android build --apk --target aarch64 --debug  # debug APK (arm64)
npx tauri android build --apk --target aarch64          # signed release APK
```

Or open `src-tauri/gen/android` in Android Studio and press Run.

## Documentation

| Topic | File |
|-------|------|
| Native architecture + module map | `docs/ANDROID_NATIVE_ARCHITECTURE.md` |
| NDK setup, build, signing | `docs/BUILD_NATIVE.md` |
| Crypto / JNI / Keystore / WebRTC / Vault / TLS / checklist | `docs/ANDROID_SECURITY.md` |

## Platform notes

- **Android 10+** (minSdk 29); phones, tablets, foldables; portrait + landscape.
- DEK is wrapped by a hardware-backed **Android Keystore** key (see
  `src-tauri/src/security/keystore.rs`); desktop keeps using the OS keychain.
- Auto-update plugins are desktop-only; Android updates ship as signed APKs.
- On Windows without Developer Mode, the Gradle build copies the built `.so`
  into `jniLibs` instead of symlinking (handled automatically).
- **Quantum Vault on Android**: the system file picker returns SAF `content://`
  URIs, which the vault resolves to real file descriptors over JNI
  (`src-tauri/src/security/content_uri.rs`) so streaming encrypt/decrypt works
  on picked documents. Encrypted `.qvault` containers are stored in the
  app-private vault directory (registry paths stay valid across restarts;
  SAF write grants do not persist); decrypted output is saved through the
  system save dialog. Folder encrypt/restore is desktop-only — Android has no
  folder picker (Tauri dialog plugin limitation).
