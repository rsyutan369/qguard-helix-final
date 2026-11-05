# Android onboarding presentation

## Brief and implementation boundary

Qguard Messaging's first-run Android introduction follows the supplied five-phone reference: a dark orbital splash, followed by four bright illustrated pages. The visual direction is friendly, luminous, and polished. Its signature is a coordinated set of glossy blue/violet 3D illustrations that dissolve into pale white/lavender content surfaces. The large artwork, left-aligned headlines, progress pills, round next buttons, and final gradient Get Started button retain the reference's hierarchy.

Implementation stays in `src/components/mobile/MobileOnboarding.tsx`, its scoped stylesheet, and `public/onboarding/`. The component remains mounted by the existing App entry flow. Authentication, app-lock gates, device linking, messaging, calling, Rust cryptography, vault operations, and permissions are unchanged by this work. The original `qguard_mobile_onboarding_done` key, value `1`, persistence fallback, and `onDone` handoff are preserved. The splash now stays visible for 3000 ms before the first feature page, as requested after device testing. The feature tour now contains four pages in the requested order.

## Presentation specification

The splash uses a full-screen navy image of Earth's illuminated communication network, the user's supplied Qguard helix/shield logo, Qguard Messaging wordmark, and the exact tagline “Secure. Private. Quantum Ready.” The generated background deliberately contains no rendered text or logo; the emblem and typography are rendered sharply by the UI. The supplied transparent PNG is preserved byte-for-byte at `public/onboarding/splash-logo.png`; installed application icon assets remain separate.

The tour surface is light regardless of the operational app's selected theme. Scoped tokens are paper `#f9f6ff`, ink `#10123f`, body copy `#505e91`, and focus blue `#1448ff`. The top of each illustration is sky blue; the bottom fades into paper through a mask at 81–100% of its height. A 36 px text inset becomes 30 px on short phones. Headlines use the already bundled variable Archivo face at 30–42 px, weight 780, line-height 1.04, tracking -0.045 em. Body text is 16 px with line-height 1.5, falling to 15 px on viewports below 680 px tall. No remote fonts or media are required.

The page copy is the supplied messaging, vault, calls/group-chat, and cross-device text. Artwork is decorative and excluded from the accessibility tree because the adjacent text conveys each feature. Native button elements provide 48 px minimum touch targets for skip, previous, and page indicators. Next is 58 px in diameter; Get Started has a 60 px minimum height. The visible indicator expands using a transform rather than animating layout width. Inactive articles carry both `aria-hidden` and `inert`; a separate polite announcement describes the selected page.

The content region flexes above a persistent footer. It clips offscreen slides and permits vertical scrolling when unusually large text needs more space. Safe-area insets protect the top controls and bottom action. Landscape phones switch to a 45/55 illustration/copy split. The application's existing Android theme uses blanket square-control and hover overrides; more specific rules restore only the onboarding buttons' radii and pressed feedback.

## Motion and interaction

Page movement uses 620 ms horizontal transforms with `cubic-bezier(.22,1,.36,1)` and a 380 ms opacity transition. Headlines enter from 18 px below over 650 ms after 100 ms; supporting copy follows after 190 ms. The artwork gently floats 6 px over 5600 ms with a small scale change. The splash emblem enters over 950 ms and the globe settles over 1600 ms. Get Started receives one 1400 ms light sweep after 500 ms. Button presses respond over 160 ms. All animations and transitions become static when `prefers-reduced-motion: reduce` is set.

Navigation supports next, previous, direct page buttons, keyboard arrows, and horizontal swipes. Swipe detection requires 48 px horizontal travel greater than vertical travel, so vertical reading gestures do not advance the tour. The artwork starts loading during the splash to avoid empty image regions on first entry. Both Skip and Get Started use the existing completion routine.

## Generated artwork and prompts

Provider: built-in ImageGen. Five independent images were generated, visually inspected, and optimized to local 960 px-wide WebP assets at quality 91. The five generated illustrations total approximately 724 KiB, plus the supplied original PNG logo. Generation originals remain in Codex's generated image directory; project assets are in `public/onboarding/`.

The shared prefix for the four feature illustrations was:

> Create one high-quality premium 3D illustration asset for Qguard Messaging Android onboarding. Visual style: polished charming animated-film 3D, gorgeous rounded forms, glossy glass and pearlescent surfaces, blue/cyan edge lights, lilac and violet, soft volumetric studio light, clean pastel sky-blue upper background fading to near-white pale lavender at bottom. Portrait 4:5 composition, no phone border around whole artwork, no headings, no body text, no watermark. Main subject fills frame leaving slight breathing room at edges. Match user's attached visual mood.

Append each asset's subject to that prefix:

- `messaging.webp`: A cheerful young adult woman with large expressive brown eyes and long wavy chestnut hair with purple highlights, wearing a premium violet hoodie with a tiny white Q shield badge, winking and holding up a peace sign. Beside her lower right is a cute small white friendly robot with a dark glass face and two cyan smiling eyes. Soft white/lavender clouds along bottom, subtle translucent chat bubbles and tiny blue sparkles in background. Waist-up cinematic friendly character portrait, detailed hair, excellent hands.
- `vault.webp`: A large luminous glass padlock with a rounded electric-blue shackle and a glossy violet body, centered, tilted slightly in 3D, a dark purple keyhole. Four floating translucent rounded square tiles orbit around it: photograph tile upper left, document tile upper right, download tile lower left, folder tile lower right. Tiny leafy plant at side, pastel clouds at bottom. Exquisite purple and ice-blue glass refractions, prominent hero lock, dreamy yet clean composition.
- `calls.webp`: A premium violet smartphone standing upright, slightly angled, screen displaying a cheerful young adult woman with long wavy chestnut hair, large brown eyes and a violet hoodie. Four small floating video-call portrait cards around the phone show diverse friendly adult people, two on each side. Three round call controls at screen bottom, white microphone icons and one red hangup icon. Pale lavender cloud base and subtle blue luminous arcs behind. Feature illustration of private video calls.
- `devices.webp`: A premium open slim laptop on the left, a tablet behind on right and two upright smartphones at front right, all in perspective. All screens show a glowing simple white Q inside blue violet shield on deep electric blue gradient screen. Behind devices a large luminous transparent rounded glass protective dome with a blue/violet shield at center. Dreamy pale white clouds, tiny lilac planets, blue sky and translucent rounded arches. Cohesive elegant balanced devices illustration.

Standalone splash prompt:

> Create a premium cinematic portrait 2:3 illustration for a secure messenger splash screen background, ultra detailed polished 3D. Deep midnight navy space at top two thirds left uncluttered with a few tiny electric-blue stars. At lower third an immense glowing partial Earth globe rising from the bottom edge, brilliant cyan network lines joining points across continents, blue rim light on curved horizon, violet-purple glow at bottom and lower sides. Space and horizon fill image edge to edge. Colors midnight navy, royal blue, electric cyan, deep violet. NO text, NO logos, NO shield, NO watermark. Leave top and middle empty dark navy for app logo and headline overlay.

UI/UX guidance informed touch targets, readable contrast, accessible navigation, and reduced motion. The requested ComfyUI and Remotion skills were reviewed: this implementation needs neither a ComfyUI runtime nor an exported Remotion video. Motion runs through the existing React/CSS stack without adding dependencies.

## Verification and review

Run the frontend build with `npm run build`. Focused regression coverage lives in `MobileOnboarding.test.ts` and checks splash timing, all four pages, completion persistence, Skip, previous/direct navigation, unavailable storage, and timer cleanup.

`tools/verify-mobile-onboarding.mjs` exercises the real app in Edge and saves screenshots and a JSON report under `artifacts/onboarding/`. It accepts `PLAYWRIGHT_MODULE` when Playwright is provided by a bundled runtime rather than the project. Start the existing Vite dev server on port 5174 before running it from the messaging project directory.

Browser verification passed at 393×852, 320×568, 360×640, 412×915, and 852×393. All five images render; next/back/direct/keyboard/swipe navigation works; vertical swipes do not change pages; reduced motion disables animation; both finish paths reach login; the original flag prevents replay after reload. No page exceptions or failed artwork requests were recorded. The browser previews simulate the Android theme; no physical Android device was connected. A signed ARM64 APK with this onboarding was subsequently rebuilt at `src-tauri/release/QguardMessaging-1.5.0-onboarding-arm64.apk`; the older canonical APK and AAB were preserved.

Visual review used the supplied reference and the five-screen contact sheet. The refinement pass fixed image preloading, offscreen-slide overflow, final CTA spacing, and Android hover/radius overrides. Final self-review: first glance 8, signature 8, typography 8, composition 8, color/light 9, motion 8, mobile 8. The generated illustrations closely recreate the art direction; they are newly generated artwork rather than pixel-identical extracted illustrations.

Frontend build and TypeScript passed. Full regression suite: 599/599 tests passed. On this Node 26 host, Vitest workers need `NODE_OPTIONS=--no-experimental-webstorage` so happy-dom supplies browser storage; without it the existing assistant-consent test fails. The setting was applied only to the verification process and did not change repository or system configuration. The build retains its existing large-chunk warning.

The Android rebuild used a fresh workspace Cargo target directory after Windows denied writes to the old cache. The documented copy-and-Gradle fallback handled the Windows symlink restriction. Generated packaging caches were refreshed after archive/native integrity checks caught incomplete cached outputs. The final APK passed signing, signer-continuity, archive CRC, byte-for-byte native-library, UI bundle, and onboarding-asset checks. Native disassembly contained no forbidden ARMv8.2 SHA3-extension opcodes across 1,346,644 lines. See `artifacts/onboarding/android-final-verification.json`.
