# Qguard Messaging: premium theme test build

Install `QguardMessaging-1.5.0-premium-theme-arm64.apk` on an ARM64 device running Android 10 or newer. Transfer the APK to your device, open it, and install the update. It uses the same package ID and release-signing certificate as the previous onboarding build.

This build applies the onboarding palette throughout Android: pearl white, lavender, blue/violet gradient actions, rounded glass surfaces, dimensional icons, and subtle animation. Dark mode uses midnight blue and indigo. Both existing theme toggle controls remain functional and persistent. The supplied splash logo and five-screen onboarding are included.

Existing screen structures, navigation, encryption, authentication, storage, keys, and workflows are unchanged by this theme update. The build does not reset the onboarding completion flag; onboarding appears for a fresh app profile.

Version: 1.5.0 (1005000). Size: 22919887 bytes. ABI: arm64-v8a.

SHA-256: `83b9d8aabbbab02352c2967990e71a3bbcc7fe8163091e08060af41b43c0a166`

Signing certificate SHA-256: `595301f1c0dcccd8aae35ff99beac5583f57e2e7931f31fc54cad6dd95fc65a3`

Verified: valid APK v2 signature and signer continuity; ZIP CRCs; exact fresh native-library match; current JavaScript and CSS bundles; all onboarding assets; zero unsupported SHA3-extension opcodes across 1,346,640 disassembled lines. TypeScript/Vite build, 599 existing tests, onboarding regressions, and light/dark visual checks pass. No connected physical device was used; native messaging, calls, vault operations, and biometric behavior still need testing on your devices.

Evidence: `artifacts/android-premium/android-final-verification.json`. Design details: `docs/ANDROID_PREMIUM_THEME.md`.

The earlier onboarding APK, canonical release APK, and AAB remain preserved separately.
