---
workflow: product-launch-video
flow: automation
storyboard: no
message: "One app. Quantum-safe chat and vault — private by default, quantum-safe by design."
destination: youtube-website
aspect: 1920x1080
delivery: 3840x2160 (4K, supersampled 2x from the 1920x1080 composition)
language: en
audience: security engineers, architects, CISOs and compliance leads evaluating quantum-safe communications
length: 60s
angle: PAS with a feature-benefit progression
narration: no
---

## Intent

A 60-second, unnarrated motion-graphics promo for **QGuard Messaging** — the
desktop (Windows) and mobile (Android) app that combines end-to-end encrypted
Secure Chat with a strictly on-device Quantum Vault. Premium, enterprise grade,
built like a motion designer's showreel piece. In the user's words: "go all
out", but "not super fast and not super slow — just balance speed and
transitions, so that the audience can carefully read the details".

It is a promo (sell), not a site tour.

## Assets

- assets/img/logo.png — the user's attached Qguard Helix logo (`public/NEW_LOGO.png`); the brand reveal and the closing lockup. Never redrawn or recoloured.
- assets/img/logo-feather.png — the same logo with an alpha feather on its outer edge only, so its pale ground melts into the canvas.
- assets/fonts/geist-latin-wght-normal.woff2 — Geist Variable, the typeface of the three source pages.
- assets/fonts/archivo-latin.woff2 — Archivo Variable, the typeface of the Android (Modernist) skin.

## Customizations

- Source of truth for every claim: `/qguard-messaging`, `/qguard-messaging/secure-chat` and `/qguard-messaging/quantum-vault` on the local site, read on 2026-10-07.
- Product UI is rebuilt as vector from the real app source (`qguard-messaging/src`) so it stays sharp at 4K: desktop in its Cold Fusion skin, Android in its Modernist skin. Labels, status lines and the Vault Crypto Terminal log lines are the app's own strings.
- Music is an original score synthesised for this cut on a 120 BPM grid; sound effects come from the bundled Pixabay-licensed library. No narration.
- Every scene change lands on a bar line; every on-screen line is held long enough to read.

## Notes

- PQC terminology follows the platform constitution: ML-KEM (FIPS 203) is key encapsulation only, ML-DSA (FIPS 204) is signatures, AES-256-GCM encrypts content.
- No invented metrics, customer names, testimonials or performance figures. The only numbers on screen are algorithm parameters, FIPS numbers, the app version, and values the animation itself produces.
- The earlier `qguard-showreel.mp4` used an invented mark; this cut uses the real logo.
- Decisions taken without asking, because the request was already specific: 16:9, no voice-over, promo rather than tour, straight to render.
