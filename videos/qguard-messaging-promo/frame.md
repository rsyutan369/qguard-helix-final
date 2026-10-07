---
version: alpha
name: QGuard Messaging — Frame (video / frame layer)
description: >
  The video-layer design system for the QGuard Messaging promo. Its atoms are lifted from the
  product's own surfaces, not from a shipped preset: the pale grid canvas, ink Geist 900
  headlines, JetBrains Mono taxonomy pills and hard offset ink shadows of the three source
  pages (/qguard-messaging, /secure-chat, /quantum-vault), plus the app's own two skins for
  the UI shown inside devices — Cold Fusion on desktop, Modernist on Android. Two worlds:
  Day (paper) carries the brand and the product; Night (ink) is reserved for the threat and
  for looking inside the cryptography.
unit: the frame — 1920×1080, rendered 2× to 3840×2160
principle: the product's own atoms · light leads, dark explains · one idea per beat, held long enough to read

colors:
  # Day — the source pages
  paper: "#F8FBFF"
  paper-plate: "#ECEEF9"      # the logo's own ground; used only as a soft plate behind the logo
  grid: "rgba(203, 213, 225, 0.55)"
  ink: "#090D16"
  ink-soft: "#1E293B"
  slate: "#475569"
  line: "rgba(9, 13, 22, 0.18)"
  card: "#FFFFFF"
  # Accents — the pages' cyan → violet run, and the primary button blue
  cyan: "#00C5EB"
  cyan-deep: "#0891B2"
  blue: "#2563EB"
  violet: "#7C3AED"
  emerald: "#059669"          # verified / sealed, on paper
  # Night — Cold Fusion dark
  night: "#04070F"
  night-panel: "#0A1120"
  night-line: "rgba(124, 163, 255, 0.24)"
  night-text: "#EAF1FF"
  night-text-2: "#9FB2D4"
  night-cyan: "#22D3EE"
  night-blue: "#4C8DFF"
  night-violet: "#A78BFA"
  plasma: "#2DE1C2"           # verified / sealed, on ink
  alert: "#FF5C7A"            # exposed plaintext, broken keys — scene 1 only
  # Android Modernist skin (inside the phone only)
  m-ink: "#1B1A19"
  m-paper: "#F3F2F2"
  m-accent: "#EC3013"

typography:
  display-hero: { fontFamily: "Geist", px: 200, weight: 900, lineHeight: 0.92, tracking: "-0.045em" }
  display-xl:   { fontFamily: "Geist", px: 132, weight: 900, lineHeight: 0.98, tracking: "-0.04em" }
  display-lg:   { fontFamily: "Geist", px: 96,  weight: 900, lineHeight: 1.02, tracking: "-0.035em" }
  display-md:   { fontFamily: "Geist", px: 64,  weight: 800, lineHeight: 1.06, tracking: "-0.03em" }
  body-lg:      { fontFamily: "Geist", px: 34,  weight: 500, lineHeight: 1.3 }
  body-md:      { fontFamily: "Geist", px: 28,  weight: 500, lineHeight: 1.35 }
  mono-kicker:  { fontFamily: "JetBrains Mono", px: 22, weight: 700, tracking: "0.16em", upper: true }
  mono-label:   { fontFamily: "JetBrains Mono", px: 20, weight: 700, tracking: "0.08em", upper: true }
  mono-spec:    { fontFamily: "JetBrains Mono", px: 44, weight: 700, tracking: "-0.01em" }
  ui-desktop:   { fontFamily: "Inter", note: "desktop app UI only" }
  ui-android:   { fontFamily: "Archivo", note: "Android Modernist UI only, 800 uppercase" }

spacing:
  frame-pad: 96px
  frame-pad-y: 80px
  grid-cell: 60px
  gap: 28px

components:
  kicker-pill:
    backgroundColor: "{colors.cyan}"
    textColor: "#FFFFFF"
    typography: "{typography.mono-kicker}"
    rounded: "999px"
    border: "2px solid {colors.line}"
    description: "The cyan pill eyebrow from every page hero. Opens a chapter."
  chip:
    backgroundColor: "{colors.card}"
    textColor: "{colors.ink-soft}"
    typography: "{typography.mono-label}"
    rounded: "999px"
    border: "2px solid {colors.line}"
    shadow: "7px 7px 0 rgba(9,13,22,0.88)"
    description: "White mono chip with the hard offset ink shadow — the pages' badge."
  card:
    backgroundColor: "{colors.card}"
    border: "2px solid {colors.line}"
    rounded: "12px"
    shadow: "10px 10px 0 rgba(9,13,22,0.88), 0 34px 70px rgba(15,23,42,0.10)"
    description: "Hard-shadow card. The single most recognisable atom of the source pages."
  gradient-word:
    fill: "linear-gradient(90deg, {colors.cyan-deep}, {colors.cyan} 45%, {colors.violet})"
    description: "One phrase per headline, exactly as the pages do it (chat & vault, quantum era, quantum age)."
  night-panel:
    backgroundColor: "{colors.night-panel}"
    border: "2px solid {colors.night-line}"
    rounded: "14px"
    description: "Cold Fusion instrument panel for Night scenes."
  device-desktop:
    description: "Windows window: title bar, 232-unit sidebar with the logo tile, top bar, content. Cold Fusion light."
  device-phone:
    description: "Android phone: Modernist skin — ink masthead QGUARD ■, hairline rules, zero radius, one vermilion accent."
---

# How this frame system is used

**Day leads.** Paper canvas, 60px grid, ink type. This is where the brand, the product
surfaces, the specification and the close live. It is the look of the product's own pages.

**Night explains.** Ink canvas, cool glows. Only three reasons to go there: the threat that
opens the film, the inside of a single encrypted message, and the inside of a sealed vault
container. Night never holds a call to action.

**Type.** Geist carries every statement; JetBrains Mono carries every fact (algorithm names,
FIPS numbers, status lines, terminal output). Weight contrast is 900 against 500. One
gradient phrase per headline at most. Nothing under 20px.

**Colour roles.** Cyan and blue are the brand in motion. Violet is the second strand of the
helix. Emerald (plasma at night) means verified or sealed and is used for nothing else. Alert
rose appears once, in scene 1, for exposed plaintext. Vermilion exists only inside the phone,
because that is what the Android app really looks like.

**Do.** Anchor to the left or right gutter. Split the frame. Let hard shadows and hairline
rules do the structural work. Keep one focal action per beat.

**Don't.** No glassmorphism on paper. No invented metrics, logos, quotes or customer names.
No bounce. No text that is on screen for less time than it takes to read twice.
