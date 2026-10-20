# iOS — Feasibility

**Date:** 2026-10-20 · **Roadmap:** Phase 11.1 · **Status:** assessment only. Nothing can be built or tested in this environment, because iOS builds need macOS and Xcode.

---

## Verdict

**Feasible, with three real pieces of work:** a key-protection bridge, a background-delivery design, and App Store billing. None of them blocks the start of the work.

## What carries over

- **Rust core:** the crypto crates are pure Rust (ML-KEM, ML-DSA, X25519/Ed25519, AES-GCM, SHA-3, Argon2) and build for `aarch64-apple-ios`. Tauri 2 supports iOS targets (`tauri ios init/build`).
- **Frontend:** React UI. The phone layout already exists for Android.
- **Calls:** WKWebView supports WebRTC. Encoded-transform support (`RTCRtpScriptTransform`) shipped in Safari 15.4+, which covers the frame encryption path, but it must be tested on device. Screen share: `getDisplayMedia` is not available in iOS WKWebView, so it is hidden, as on Android.

## Work items

| Area | Android today | iOS equivalent | Effort |
| --- | --- | --- | --- |
| Device storage key | Android Keystore (`StrongBox` where present) | Keychain item with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, wrapped by a Secure Enclave P-256 key. The Secure Enclave has no ML-KEM or AES; it only wraps the data-encryption key, the same split as Android. | Swift bridge through a Tauri plugin. Medium. |
| Biometric unlock | BiometricPrompt `CryptoObject` | `LAContext` + Keychain `SecAccessControl(.biometryCurrentSet)` | Medium |
| Recents masking / screenshots | `FLAG_SECURE` | No screenshot block on iOS. Obscure the app-switcher snapshot on `sceneWillResignActive`. Screenshots can only be detected (`userDidTakeScreenshotNotification`), not prevented. **Document this as a limitation.** | Small |
| Incoming messages while closed | — (foreground + polling) | iOS suspends apps, so it needs APNs push. To avoid putting content in push payloads: content-free pushes plus a Notification Service Extension that fetches and decrypts. That means the core runs in the extension, which has a memory limit of about 24 MB, so the ML-KEM-1024 and ML-DSA-65 footprint must be measured. | **Large.** Also needs an APNs key and a server sender (Edge Function). |
| Incoming calls | Full-screen intent | CallKit + PushKit VoIP pushes (Apple requires reporting every VoIP push to CallKit) | Large |
| Billing | Google Play Billing (Phase 4 server checks) | StoreKit 2 + App Store Server API verification and notifications, the same shape as `handlePlayVerify`/`handlePlayRtdn` | Medium |
| Updates | Play | App Store / TestFlight only. The desktop updater does not apply. | — |

## Owner prerequisites

An Apple Developer Program account, a Mac build machine (or CI with macOS runners), APNs credentials, App Store Connect products for the subscription tiers, and test iPhones (one with Face ID).

## Suggested order

1. Build the core and UI on the simulator, with sign-in and chats in the foreground.
2. Add Keychain + Secure Enclave storage and biometric unlock.
3. Add APNs with a Notification Service Extension, after measuring core memory in the extension.
4. Add CallKit + PushKit.
5. Add StoreKit 2 billing and server verification.
6. Run a TestFlight beta.
