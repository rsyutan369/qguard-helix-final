# Qguard Helix enterprise platform film

The 3:00 commercial is authored in Remotion at 1920 × 1080 and 24 fps. Its master includes open English captions. The SRT is available for players and publishing tools that accept a separate subtitle track.

- `src/film-plan.ts` sets the edit, chapter timing, titles, and on-screen coverage.
- `src/Spatial.tsx` supplies the frame-synchronized Three.js network, processor, and finale.
- `src/EditorialGraphics.tsx` supplies GSAP-driven editorial animations for exposure, migration, and cryptographic agility.
- `audio/` contains the narration script and synthesis and mixing source. The rendered voice uses [Kokoro](https://huggingface.co/hexgrad/Kokoro-82M) with the female American English `af_heart` voice and an original score.
- `FEATURE-COVERAGE.md` traces the claims to platform implementation and the standards review.

Run `npm ci`, `npm run typecheck`, and `npm run studio` from this directory. Use `npm run render` to export the composition. If using existing headless Chromium, append `-- --browser-executable="path-to-chromium"`.

The product imagery comes from a screen recording of the public overview and isolated offline renders of dashboard components. The offline dashboard state uses no connected tenant, telemetry, or completed scan. Graphic and 3D scenes depict concepts. The closing mark uses the supplied Qguard Helix image.

The lab comes from `public/helix-features/hero-quantum-migration.mp4` in the repository. Concept plates are sourced from `public/inventory.png`, `public/readiness-assessment/migration-waves.webp`, and the existing Crypto Agility, PQAuth, and Trust Fabric visuals in `public/helix-features/`. [Opening Earth image credit](public/plates/EARTH-CREDIT.md)
