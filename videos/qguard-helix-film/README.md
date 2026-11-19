# QGUARD HELIX campaign film

Both edits are authored separately in Remotion at 24 fps with open English captions.

| Composition | Frame size | Runtime |
| --- | --- | --- |
| QGuardHelixHD | 1920 × 1080 | 2:00 |
| QGuardHelixVertical | 1080 × 1920 | 0:45 |

Run `npm ci`, then `npm run typecheck` and `npm run studio` from this directory. Export with `npm run render:wide` or `npm run render:vertical`. To use an existing headless Chromium, append `-- --browser-executable="path-to-chromium"`. The renderer needs access to its local browser and asset server.

The product images and screen recordings use the repository's Messaging store capture harness and fictional demo data. The recordings show Chats and Quantum Vault interface interactions. The [Messaging claims audit](../../docs/qguard-messaging-security-claims-audit-2026-11-15.md) is the source for the film's workflow and algorithm claims.

The closing mark uses the supplied PNG. [Earth plate credits](public/plates/EARTH-CREDIT.md) document the opening photograph. The lab and glass imagery come from the existing Helix site assets. The main edit combines them with frame-driven GSAP easing and a frame-synchronized React Three Fiber core. The English voice is synthesized locally with [Kokoro](https://huggingface.co/hexgrad/Kokoro-82M), mixed with an original score and effects. Narration and audio generation source live in `audio/`. The optional [ComfyUI shot workflows](comfyui/README.md) are a starting point for future plate renders.
