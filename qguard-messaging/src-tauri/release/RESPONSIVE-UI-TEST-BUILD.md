# Qguard Messaging: responsive UI correction

Install `QguardMessaging-1.5.0-responsive-ui-arm64.apk` as an update over the existing app on an ARM64 phone running Android 10 or newer. It uses the same package ID, version 1.5.0 (1005000), and release-signing certificate as the premium-theme APK already tested on your phone. Previous installers remain preserved.

Corrects compact-phone header wrapping, crowded password/PIN/pattern tabs, overly inset forms, Settings/Security card overflow, and chat-composer sizing. Bottom navigation reserves its own height so it cannot overlap scrolling content. Fields have separate visible labels and short placeholders. The approved colors, light/dark toggles, animations, artwork, encryption, and workflows remain. The first-run splash stays for three seconds; the existing onboarding-completion flag is retained.

Size: 22920671 bytes.

SHA-256: `19ff583ce8ff8ad5bf8faf9dc60488bbc7f68c25c3a3182fe7e84fcb363f6450`

Signer certificate SHA-256: `595301f1c0dcccd8aae35ff99beac5583f57e2e7931f31fc54cad6dd95fc65a3`

Verification: production TypeScript/Vite build; 68 files / 599 tests; 130 responsive layouts and states including actual protected forms and an empty chat composer; compact and landscape widths, simulated 130%/200% text, both themes; full onboarding, theme toggle, reduced-motion, and Android-isolation regression checks. APK v2 signature and signer continuity, ZIP CRCs, exact fresh native-library match, current JS/CSS assets, and portable ARM64 instruction checks pass.

No physical Android device was connected for this rebuild. Please verify the corrected appearance and keyboard behavior on your phone. Browser text enlargement is a layout simulation, not a native font-settings test.

Evidence: `artifacts/android-responsive/android-final-verification.json`. Implementation details: `docs/ANDROID_RESPONSIVE_FIX.md`. Preview: `artifacts/android-responsive/phone-layout-preview.png`.
