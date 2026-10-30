# Metallic white and interactive light revision

User request: restore a white background matching the other page sections, use metallic white and glass, add flowing pulsating light along the 3D connections, and make features clickable with short details.

## Changes

- White canvas, silver reflective geometry, translucent glass plates, violet controls and the original light navigation. The local SVG fallback uses the same palette.
- Local studio reflections give the metal definition. The environment render target and generated glow texture are disposed with the renderer.
- Each of the four connection paths has an animated shader core, a softer outer tube and four moving light sprites. The selected feature uses violet; other paths use cyan. Light phase and pulse stop with pause, reduced motion, hidden documents and offscreen rendering.
- Actual 3D satellites, the central QKMS anchor and connecting paths use raycast hit testing. Thin paths have a wider invisible pick area. A narrow line threshold prevents core outlines from intercepting nearby feature clicks.
- Four 44px feature-label buttons provide keyboard and touch access, including when WebGL is unavailable. The existing capability rail remains available.
- Selecting a node, path or feature label opens a short, nonmodal glass detail card. Escape and the close button dismiss it and restore focus to the trigger. Feature changes update the card. It never reports tenant posture or invented evidence.

## Verification

`artifacts/governance-trust-hero/verify-white-glass.mjs` verifies white background, readable dark heading, primary CTA visibility, no horizontal overflow, stable reduced motion, all four feature detail cards, focus placement and restoration, keyboard activation, actual geometry selection for all four satellites, front-facing path selection, advancing light phase, pause/resume and interactive fallback.

Desktop 1440x1000, tablet 1024x768 and Chrome touch emulation at 390x844 and 320x740 were checked. Actual rendered screenshots of the desktop, mobile, detail cards and two light phases were opened and inspected. The detail card is clamped between the navigation and the bottom viewport margin on opening, feature changes, scroll and resize; it can scroll internally on unusually short screens. The harness also checks its vertical bounds on phones.

The only observed browser resource error is the existing missing favicon. A physical phone and screen reader were not available. TypeScript and the production build are checked separately, with the final build output saved beside the screenshots.

Evidence: `artifacts/governance-trust-hero/white-glass/verification.json`, `desktop.png`, `mobile-hero.png`, `mobile-small-details.png`, `flow-a.png`, `flow-b.png`, and `build.log`.

## Final completion check

Production build and TypeScript both completed with exit code 0, recorded in `build-status.json` and `typescript-status.json`. The local Vite preview was restarted on loopback port 3000 after it had stopped. A fresh browser confirmed HTTP 200, the white background, the native WebGL render, opening Audit evidence details and closing them with Escape, with no JavaScript page errors. See `final-preview-status.json` and `final-preview.png`.

Verified feature flow: public page loads local assets, Three.js renders the conceptual architecture, a node/path/label updates the selected capability, and the local capability definition renders in the nonmodal detail card. This hero does not depend on a backend API, tenant data or environment credentials.
