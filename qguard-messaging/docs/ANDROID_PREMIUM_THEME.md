# Android pearl-glass theme

The Android application shares the first-run onboarding palette: pearl white, lavender, sky blue, and violet, with rounded glass surfaces, dimensional icon tiles, gradient actions, subtle press feedback, and brief entrances. Dark mode uses midnight blue and indigo surfaces with readable lavender and blue accents. Success, warning, and destructive actions retain distinct semantic colors.

## Implementation boundary

`src/styles/android-premium.css` loads after the existing Android structure styles in `src/main.tsx`. The historical `data-qg-skin="modernist"` attribute remains the Android runtime boundary. Existing component structure, navigation, encryption, authentication, account and device workflows, storage, and native code are unchanged by this theme update. The initial workspace already contained unrelated edits; these were preserved.

The existing theme hook and both toggle entry points are retained. The new sheet changes colors, borders, radii, shadows, typography treatment, and decorative animation. Masthead controls have separate 48px touch targets. All new animation respects reduced motion. Existing locally bundled fonts and onboarding artwork keep the design available offline. No UI library or external font dependency was added.

The supplied splash logo and all five onboarding screens remain intact. The onboarding completion flag is preserved, so existing installations do not automatically replay onboarding.

## Verification

- TypeScript and production Vite build pass. The pre-existing large-chunk warning remains.
- Existing regression suite: 68 files, 599 tests pass. This host's Node 26 requires `NODE_OPTIONS=--no-experimental-webstorage` for the suite's existing storage mocks.
- `artifacts/android-premium/logic-verification.json` compares 320 application TypeScript/TSX and Rust files with their hashes at the start of this theme update; none changed. The CSS-import entrypoint is excluded from that comparison.
- `tools/verify-android-theme.mjs` reviews 14 actual component surfaces in both themes: Home, chat, contacts, calls, vault, security, settings, PIN unlock, login, keys, devices, verification, audit, and the idle call display. Registration, the module sheet, vault tools, and long-page scrolling are also captured.
- Browser checks cover persisted toggles, Android-only CSS isolation, reduced motion, semantic text-token contrast against the base panel, 48px masthead controls, horizontal overflow, and visible bottom navigation at 320x568, 360x640, 852x393, and 768x1024.
- `tools/verify-mobile-onboarding.mjs` confirms all five screens, artwork loading, next/back/direct/keyboard/swipe navigation, skip/completion persistence, reduced motion, and small/landscape layouts.

The development-only preview files in `tools` are not app entrypoints and are not included in `dist`. Their document CSP blocks network connections. Browser verification also blocks fetch/XHR and external requests. Previews use unauthenticated empty data and never create an account, change a key, encrypt a file, or place a call. They do not establish evidence of end-to-end messaging, biometric, camera, native vault, or physical-device behavior.

## Reproduce visual verification

Run Vite on port 5174. Set `PLAYWRIGHT_MODULE` to the available Playwright module when it is not installed in the project, then run `node tools/verify-android-theme.mjs`. This host uses the installed Microsoft Edge channel. Evidence and PNGs are written under `artifacts/android-premium`.

The downloadable signed ARM64 APK and its exact verification details are documented separately in `src-tauri/release/PREMIUM-THEME-TEST-BUILD.md` after packaging. Testing on physical Android devices remains necessary.
