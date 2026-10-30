# Migration Platform hero enhancement

Scope: replace only the existing hero presentation. Preserve the headline, descriptive paragraph, CTA labels and destinations, six trust items, console labels and figures, navigation and all lower page content. Adapt the supplied Targo reference rather than its fictional brand copy or its instruction to remove the rest of the website.

Mood: precise, architectural, assured. Signature: a cyan-tinted orbital form beside a staircase-set migration headline, with scroll-linked depth and a clean handoff into the existing operational command preview. The orbit is a conceptual migration motif, not telemetry.

Use existing React/Vite/Motion. Load Quantico 400/700 locally for the hero display; retain existing body and navigation fonts. Hero background #f2f1f0, foreground #17212b, secondary #52616d, cyan #15bcdf and border #0fa3c2. Keep all styles scoped to migration-specific classes.

Desktop composition: content within 1408px; 64–96px horizontal gutters. Eyebrow starts at 118px from page top. Headline has five lines: See / every asset. / Migrate / with / confidence. Last three lines indented clamp(42px,6vw,100px). Display 700, clamp(40px,5.2vw,76px), line-height .99 and -.025em tracking, uppercase through CSS. Confidence is cyan. Supplied orbital footage occupies the upper right, 66% width, contained without cropping, with a left-side background scrim and a soft fade at the bottom. No foreign logos or invented statistics.

The existing descriptive paragraph and Choose Pro / Compare Plans actions remain alongside the lower part of the headline, protected by a pale surface. Buttons have 12px chamfered corners, 44px minimum height and visible external focus outlines; primary cyan with dark text, secondary dark with white text. Existing trust items form a compact ruled strip below the composition.

Retain the entire existing migration command console in a second hero band: maximum width 1200px, border #ccd8dc, light shell with dark console interior. Add a plain illustrative-preview caption to clarify that existing sample figures are not tenant results. This band is part of the hero, before the unchanged next section; do not remove or silently alter existing figures.

Mobile below 768px: cinematic media becomes an upper visual 270–330px tall, title follows in flow at clamp(36px,8.7vw,54px), 22px gutters, smaller 40px staircase indent. Paragraph and buttons follow in flow. Media never overlaps copy or CTAs. Trust items wrap. Console uses available width with responsive padding and no horizontal overflow.

Motion: headline line rise 24px to 0 and opacity 0 to 1 over 650ms, stagger 70ms, cubic-bezier(.16,1,.3,1), total under 1.1s. Cinematic video fades in over 700ms only after a decoded frame is available; local still poster remains underneath. Scroll moves media up at most 52px and scales 1 to 1.045, while supporting copy stays readable. Native scrolling and anchor links remain intact. Observe visibility and document visibility to pause offscreen footage. Provide pause/play control. Try playback on initial readiness and first user gesture; no indefinite retry loop. Reduced motion shows a still poster and removes parallax and line entrances.

Media source: user-provided Targo hero URL ending hf_20260823_050407_500d0339-ab28-41c1-9688-132a74a3b5aa.mp4. Convert locally to H.264/yuv420p/faststart because the original codec is not supported by the test browser. Self-host the converted video, poster and Quantico fonts in public/migration-hero.

Verification: before/after screenshots, desktop 1440×1000 and 1440×810, phone 390×844 and 320×740, reduced motion, decoded video frames and playhead progress, controls, readable text, no horizontal overflow, unchanged lower-page source and exact original hero information. TypeScript and production build must pass. Review typography, composition and media integration after the first screenshot and correct concrete weaknesses.
