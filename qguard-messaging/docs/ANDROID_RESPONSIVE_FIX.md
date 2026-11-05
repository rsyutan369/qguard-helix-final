# Android compact-phone layout correction

This corrects the crowded forms reported during physical-device testing of the premium theme. The approved white/lavender/blue/purple colors, glass surfaces, light/dark controls, artwork, and navigation destinations remain.

## What caused the layout defects

The workspace gate combined the screen gutter, a second padded wrapper, and a padded card. At 320 CSS pixels, those layers left about 216 pixels for three fixed grid columns. The Password label could exceed its column and overlap PIN. The header also combined a shrinkable wordmark with a logo and fixed-size action buttons; at small widths the emblem could wrap above the name. An intrinsic-width input in Settings could make its card wider than its grid track when text was enlarged.

The previous visual checks covered empty screens and horizontal document overflow. They did not exercise the password/PIN/pattern gates or the active chat composer, and the page's horizontal overflow guard could mask overflowing descendants. The new checks inspect the actual controls and text bounds, not just the document width.

## Changes

- Protected forms use a single compact gutter, a full-width explanation, separate visible field labels, and short placeholders. Unlock-method tabs and bottom actions wrap to another row when their content needs more room.
- The phone masthead uses compact spacing, keeps the logo beside its wordmark, and can gain a row for larger text. Page headings can wrap. Settings/Security cards can shrink inside their grid tracks.
- Android's bottom navigation now participates in the screen's flex layout, so its measured height—including wrapped labels and gesture clearance—is reserved before page content is laid out. Scrollable forms can bring their final buttons fully above it.
- The actual chat composer uses a bounded flexible text column and a one-row starting height. Attachment and microphone glyphs retain their size inside 48px touch targets.
- Android CSS explicitly uses 100% text-size adjustment to prevent browser text inflation. No CSS zoom or transform-based page scaling, maximum-scale restriction, native text-zoom override, or system font-setting change was introduced.
- The onboarding splash timer is 3000ms. Its entry animations, supplied logo, original completion flag, and authentication handoff are retained.

The workspace component's validation, lockout state, submission callbacks, password/PIN requirements, pattern handling, recovery controls, and chat event handlers are unchanged. All Rust source and native permission/security settings are unchanged. Only JSX labels/classes/textarea presentation attributes, CSS, and the requested timer change enter the app.

## Verification

- Existing suite: 68 files / 599 tests pass, including a splash boundary assertion at 2999ms and transition at 3000ms.
- `tools/verify-android-responsive.mjs`: 130 checks in both themes; actual setup/unlock gates, all offered methods, login, Security, Settings, and the active empty chat composer; 320/360/375/412px widths, short and landscape viewports, plus simulated 130% and 200% text enlargement. Checks inspect descendant bounds and tab text, and confirm the final setup action can scroll above navigation.
- The preview's conversation is explicitly labeled “Layout test contact.” It has no messages, trusted devices, or fabricated security evidence. Preview CSP and browser routing block account/native network operations. No call, file encryption, registration, or key operation occurs during visual checks.
- The full onboarding browser regression passes with the longer splash. Theme-toggle, contrast-token, reduced-motion, and Android-isolation checks are also repeated.
- `artifacts/android-responsive/source-verification.json` records 317 unchanged files out of 321 checked TypeScript/TSX/Rust files. The four expected changed files are the onboarding component/test, workspace-gate JSX, and chat-composer JSX. The gate's state/validation code is byte-identical, and the chat diff reverses exactly using only the three presentation edits.

Browser enlargement is a layout simulation, not a physical Android font-settings test. The rebuilt signed ARM64 APK still needs verification on the user's device. Installation and checksum details are in `src-tauri/release/RESPONSIVE-UI-TEST-BUILD.md` after release verification.
