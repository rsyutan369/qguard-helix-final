---
format: 1920x1080
delivery: 3840x2160
fps: 30
duration: 60s
message: "One app. Quantum-safe chat and vault — private by default, quantum-safe by design."
arc: Hook (threat) → Product intro → Surfaces → Secure Chat ×3 → Quantum Vault ×3 → Proof (the suite) → Principles → CTA
audience: security engineers, architects, CISOs and compliance leads
mode: autonomous
music: original score — 120 BPM, D minor lifting to F major, restrained cinematic electronic (synthesised for this cut)
tempo: 120 BPM · 1 beat = 0.5s · 1 bar = 2s · every scene change lands on a bar line
---

## Video direction

- **Two worlds.** Day = paper `#F8FBFF`, 60px grid, ink Geist, hard offset shadows — the look of the source pages. Night = ink `#04070F`, cool glows — used only for the threat (01), the inside of one message (05) and the inside of the vault (08, 09). One shared background world sits under every scene and crossfades between the two; scenes themselves are transparent.
- **A living ground, a still foreground.** The only ambient motion is the lattice drifting in the background world (the mathematics behind ML-KEM, and the hex field of the logo). Foreground content arrives, lands and holds. No breathing cards, no drifting cameras over text.
- **Motion grammar.** `power3.out` is the house settle; `expo.out` for hero arrivals; critically-damped spring for the two logo lockups; `power4.in/out` for cut-the-curve seams. No overshoot anywhere. Headlines rise through a line mask, word by word; facts set in mono decode from cipher glyphs; chips lift off their hard shadow.
- **Reveal model.** No narration, so reveals are paced to the beat grid: one new idea per bar (2s), nothing front-loaded, every line held at least as long as it takes to read twice.
- **Transitions — three types only.** Primary: zoom-through at chapter turns (03→04, 06→07, 09→10) and for diving in (04→05). Related beats: cut-the-curve, leftward (02→03, 05→06, 07→08→09). Accent, used twice as a bookend: a bloom to paper (01→02 and 11→12). One hard cut, on the downbeat, into the principles (10→11).
- **Chapter rail.** From scene 03 to scene 11 a thin mono rail sits at the bottom edge: product name left, chapter right.
- **Never.** Invented metrics, customer names or quotes · bounce · gradient text beyond one phrase per headline · a redrawn logo · anything under 20px.

## Frame 1 — The threat

- scene: A wall of ciphertext is swept and copied; then time jumps and it reads as plaintext
- duration: 6s
- transition_in: cut
- status: outline
- src: compositions/01-threat.html
- type: hook
- persuasion: Pain agitation
- beat: tension
- blueprint: kinetic-type-beats (Adapt)
- mode: night
- sfx: riser, glitch-3, impact-bass-2

narrativeRole: name the threat in two beats, in the viewer's own stakes.
keyMessage: what is encrypted today can be opened later.

Adapt: keep the in-place hard swap of two short statements; the surface behind them is a live glyph wall instead of a bare field.
Scene 1 (0.0–2.2s): ink field; a full-bleed wall of mono cipher glyphs fades up, low contrast. "Harvest now." rises through a line mask, left-anchored, display-hero. A cyan scan line crosses the wall left to right; rows it passes flare and shed ghost copies that stream to the right edge. Kicker `THE THREAT MODEL` top-left.
Scene 2 (2.2–4.6s): zoom-through seam on the headline to "Decrypt later." A timeline rule at the bottom whips its playhead from `TODAY` to `Q-DAY`; runs of glyphs flip to plaintext nouns in alert rose (CONTRACTS, CREDENTIALS, SOURCE CODE…). Caption rises under the headline: "Recorded today. Opened when quantum computers break RSA and ECC."
Scene 3 (4.6–6.0s): a two-strand helix (violet, cyan) sweeps the frame left to right; where it passes, rose plaintext re-scrambles to calm blue cipher. The helix core brightens toward the bloom.

## Frame 2 — One app

- scene: The real logo forms on paper; the name and the promise land beside it
- duration: 6s
- transition_in: bloom
- status: outline
- src: compositions/02-brand.html
- type: product_intro
- persuasion: Future pacing
- beat: relief + clarity
- blueprint: logo-assemble-lockup (Adapt)
- mode: day
- focal: assets/img/logo-feather.png
- sfx: impact-bass-1, sparkle

narrativeRole: answer the threat with the product, by name.
keyMessage: QGuard Messaging — one app, quantum-safe chat and vault.

Adapt: keep "the mark comes to exist on a cleared stage"; the mark is the untouched logo image revealed through an expanding soft iris, not rebuilt from parts.
Scene 1 (0.0–1.5s): bloom resolves to paper, grid fades in. Logo reveals centre through an iris with a ring drawing around the Q, settling on a critically-damped spring; one sheen crosses it.
Scene 2 (1.5–3.4s): the logo nudges left to the 30% line; cyan kicker pill `QGUARD MESSAGING`, then "One app." and "Quantum-safe chat & vault." rise word by word on the right, display-xl, gradient on "chat & vault".
Scene 3 (3.4–6.0s): five mono chips lift off their shadows one per half-beat — NIST FIPS 203 · FIPS 204 · END-TO-END ENCRYPTED · ZERO-KNOWLEDGE · HYBRID POST-QUANTUM — then hold.

## Frame 3 — Desktop and mobile

- scene: The Windows app and the Android app rise together; the phone's reactor fills to 100%
- duration: 6s
- transition_in: cut-the-curve LEFT
- status: outline
- src: compositions/03-devices.html
- type: product_intro
- persuasion: Show-don't-tell proof
- beat: confidence
- blueprint: device-surface-showcase (Adapt)
- mode: day
- sfx: whoosh-short, pop, ping

narrativeRole: show that it is a real product on the two devices people use.
keyMessage: the same protection on desktop and on mobile.

Adapt: keep the device held as hero while its screen does something; two devices instead of one, static camera until the final push.
Scene 1 (0.0–2.0s): headline left, "On your desktop. In your pocket." The desktop window rises from the lower right with a shallow 3D tilt and settles; tag `WINDOWS · v1.3.9`.
Scene 2 (2.0–4.2s): the phone slides in front of it from the right; tag `ANDROID`. Its Helix Reactor arcs sweep to 100% and the core block resolves to "100% · FULLY PROTECTED". A dashed link draws between the devices: `DEVICE APPROVAL BY QR`.
Scene 3 (4.2–6.0s): chip `NATIVE RUST CRYPTO CORE` lifts under the headline; the camera begins a push toward the desktop's chat thread.

## Frame 4 — Secure Chat

- scene: A message is written and sent in the real chat surface
- duration: 4s
- transition_in: zoom-through
- status: outline
- src: compositions/04-chat.html
- type: feature_showcase
- persuasion: Show-don't-tell proof
- beat: control
- blueprint: device-surface-showcase (Adapt)
- mode: day
- sfx: typing, click, pop

narrativeRole: open chapter one inside the working product.
keyMessage: conversations the quantum era can't crack — with lifecycle controls on every message.

Scene 1 (0.0–1.4s): kicker `01 — SECURE CHAT`; "Conversations the quantum era can't crack." rises on the left. The chat window holds right, thread header reading `E2EE active - ML-KEM-1024 - Forward secrecy`.
Scene 2 (1.4–2.8s): a reply types in the composer and sends; the violet bubble lands with `09:41 · Verified · Replay-safe`.
Scene 3 (2.8–4.0s): "Message options" opens; four chips lift — READ ONCE · VIEW ONCE · DISAPPEAR 1H · TIME-LOCKED.

## Frame 5 — Inside one message

- scene: The message travels device → relay → device, sealed the whole way
- duration: 4s
- transition_in: zoom-through
- status: outline
- src: compositions/05-chat-inside.html
- type: feature_showcase
- persuasion: Feature-to-benefit translation
- beat: clarity + trust
- blueprint: compose
- mode: night
- sfx: whoosh, ping

narrativeRole: explain the protection in three steps, the way the page does.
keyMessage: sealed on your device, exchanged with hybrid keys, opened only by your contact; the relay sees ciphertext only.

Scene 1 (0.0–1.2s): night. Three nodes on one rail — YOUR DEVICE, ZERO-KNOWLEDGE RELAY, YOUR CONTACT. Step 01 "Sealed on your device" decodes in under the first node with `AES-256-GCM`; the message card becomes cipher glyphs.
Scene 2 (1.2–2.6s): two strands — X25519 and ML-KEM-1024 — braid along the rail and fuse into one key; step 02 "Hybrid key exchange". The sealed packet crosses the relay, tagged "Stores ciphertext only".
Scene 3 (2.6–4.0s): the packet reaches the contact and resolves to readable text; step 03 "Opened only by your contact". Caption: "A fresh key for every message."

## Frame 6 — Calls

- scene: A call connects and is verified with one tap
- duration: 4s
- transition_in: cut-the-curve LEFT
- status: outline
- src: compositions/06-calls.html
- type: feature_showcase
- persuasion: Risk reversal
- beat: trust
- blueprint: device-surface-showcase (Adapt)
- mode: day
- sfx: notification, click, chime

narrativeRole: extend the promise from messages to live voice and video.
keyMessage: per-frame encryption, a fresh post-quantum key per call, verified in one tap.

Scene 1 (0.0–1.4s): kicker `QUANTUM-ENCRYPTED CALLS`; "Voice and video, sealed frame by frame." The call window lands right — Connected, Low / Auto / HD, pill `Quantum-encrypted`.
Scene 2 (1.4–2.8s): the card VERIFY THIS CALL IS PRIVATE decodes its safety number; "They match — continue" is pressed.
Scene 3 (2.8–4.0s): the pill flips to `Verified` in emerald. Chips: PER-FRAME E2EE · FRESH POST-QUANTUM KEY PER CALL.

## Frame 7 — Quantum Vault

- scene: A file is dropped into the real vault workspace and sealed on the device
- duration: 4s
- transition_in: zoom-through
- status: outline
- src: compositions/07-vault.html
- type: feature_showcase
- persuasion: Show-don't-tell proof
- beat: control
- blueprint: device-surface-showcase (Adapt)
- mode: day
- sfx: whoosh-short, click

narrativeRole: open chapter two inside the working product.
keyMessage: your files, sealed for the quantum age, on your own device.

Scene 1 (0.0–1.4s): kicker `02 — QUANTUM VAULT`; "Your files, sealed for the quantum age." The vault workspace holds right — Encrypt / Decrypt, the dropzone, the suite line.
Scene 2 (1.4–2.8s): a file card drops into the dropzone; "Encrypt File" is pressed.
Scene 3 (2.8–4.0s): chips lift — 100% ON-DEVICE · ZERO-KNOWLEDGE · ANY FILE OR FOLDER.

## Frame 8 — The key envelope

- scene: Four layers close around the file and it becomes a .qvault container
- duration: 4s
- transition_in: zoom-through
- status: outline
- src: compositions/08-envelope.html
- type: feature_showcase
- persuasion: Feature-to-benefit translation
- beat: clarity + awe
- blueprint: compose
- mode: night
- sfx: ping, impact-bass-1

narrativeRole: show why one broken layer is not a broken file.
keyMessage: file key, master key, hybrid seal, dual signature — breaking one layer never opens your files.

Scene 1 (0.0–2.6s): night. An exploded stack of four plates in shallow 3D, one arriving per half-bar with its mono name and one-line role on a leader to the right: AES-256-GCM · VAULT MASTER KEY · X25519 + ML-KEM-1024 · ML-DSA-87 + Ed25519.
Scene 2 (2.6–4.0s): the stack closes into one sealed block labelled `board-pack-q4.pdf.qvault`; plasma edge-light runs its border. Caption: "Breaking one layer never opens your files."

## Frame 9 — Live crypto terminal

- scene: The vault's own terminal streams the real pipeline to "sealed"
- duration: 4s
- transition_in: cut-the-curve LEFT
- status: outline
- src: compositions/09-terminal.html
- type: feature_showcase
- persuasion: Show-don't-tell proof
- beat: confidence
- blueprint: agent-progress-theater (Adapt)
- mode: night
- sfx: typing, chime

narrativeRole: prove the vault is doing real, inspectable work.
keyMessage: watch the real pipeline run — and end tamper-evident, recoverable, yours.

Adapt: keep trigger → working theatre → receipt; the theatre is the app's actual log lines and progress row.
Scene 1 (0.0–2.6s): the Vault Crypto Terminal fills the left two-thirds. Log lines arrive one per quarter-bar, verbatim from the app; the progress bar and chunk counter run to 64/64.
Scene 2 (2.6–4.0s): the last line lands in emerald — "Vault container sealed · integrity protected per chunk". Three tags lift on the right: TAMPER-EVIDENT · OFFLINE RECOVERY KEY · ENTERPRISE DUAL-CONTROL.

## Frame 10 — The exact suite

- scene: The four-line specification, set like a specimen sheet
- duration: 8s
- transition_in: zoom-through
- status: outline
- src: compositions/10-suite.html
- type: benefit_highlight
- persuasion: Authority by association
- beat: trust + inevitability
- blueprint: grid-card-assemble (Adapt)
- mode: day
- sfx: pop, ping

narrativeRole: the proof beat — every claim so far, as named standards.
keyMessage: hybrid and standards-based: ML-KEM protects the keys, AES-256-GCM encrypts the content.

Adapt: keep the staggered self-assembly and the hold; four full-width specification rows instead of a tile grid.
Scene 1 (0.0–1.6s): back to paper. Kicker `CRYPTOGRAPHIC FOUNDATION`; "The exact suite." rises, display-xl.
Scene 2 (1.6–5.6s): four rows arrive one per bar — role in mono, algorithm large in mono, FIPS chip right: KEY ENCAPSULATION (HYBRID) ML-KEM-1024 + X25519 · DIGITAL SIGNATURES (DUAL) ML-DSA + Ed25519 · SYMMETRIC / AEAD AES-256-GCM · KEY DERIVATION / HASHING HKDF-SHA3-256.
Scene 3 (5.6–8.0s): footnote rises: "ML-KEM protects the keys. AES-256-GCM encrypts the content." Hold.

## Frame 11 — Principles

- scene: Four statements, one per beat pair
- duration: 4s
- transition_in: cut
- status: outline
- src: compositions/11-principles.html
- type: benefit_highlight
- persuasion: Rule of three (plus one)
- beat: power
- blueprint: kinetic-type-beats (Reproduce)
- mode: alternating
- sfx: impact-bass-1

narrativeRole: compress everything into four phrases before the close.
keyMessage: end-to-end, zero-knowledge, forward secrecy, post-quantum by default.

Scene 1–4 (one second each): "End-to-end." · "Zero-knowledge." · "Forward secrecy." · "Post-quantum by default." Full-frame, display-hero, hard cut on the beat, ground flipping night / day / night / day.

## Frame 12 — Close

- scene: The logo, the line, the download
- duration: 6s
- transition_in: bloom
- status: outline
- src: compositions/12-close.html
- type: cta
- persuasion: Friction reduction
- beat: peace of mind
- blueprint: logo-assemble-lockup (Adapt)
- mode: day
- focal: assets/img/logo-feather.png
- sfx: impact-bass-2, sparkle

narrativeRole: land the brand and tell the viewer what to do.
keyMessage: private by default, quantum-safe by design — download for Windows.

Scene 1 (0.0–1.4s): bloom to paper; the logo lands centre on the spring.
Scene 2 (1.4–3.0s): "Private by default." then "Quantum-safe by design." rise beneath it.
Scene 3 (3.0–6.0s): the blue button `DOWNLOAD FOR WINDOWS  v1.3.9` lifts, then `qguardhelix.com/qguard-messaging` in mono and `WINDOWS · ANDROID`. Hold to the end.
