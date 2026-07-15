# Video Call Quality — Root-Cause Report & Production Media Pipeline

**Date:** 2026-07-15 · **Spec:** `Qguard_Wiki/VideoCall_Fix_Guidelines`
**Symptom:** Desktop ↔ Android-emulator video call on one laptop rendered as a
gray, macroblocked smear on the desktop and blocky mush on Android
(`test_images/Video Call blurred Images2.png`). Audio degraded intermittently.

---

## 1. Root causes (each with evidence)

### RC1 — Capture & encoder ceilings were below HD *(primary, deterministic)*
`src/lib/call-quality.ts` capped the default **auto** tier at **960×540 max
@ 1.2 Mbps encoder ceiling**. A 540p stream rendered fullscreen on a laptop
display is soft *by construction* — even on a perfect network the call could
never look sharp. The HD tier existed but reset to Auto on every call.
*Evidence:* tier table in the previous `call-quality.ts`; spec requires
720p minimum / 1080p when supported.

### RC2 — Every WebRTC hardware media path was force-disabled on Windows *(primary under load)*
`src-tauri/src/lib.rs` launched WebView2 with
`--disable-accelerated-video-decode --disable-accelerated-video-encode`
(plus capture-path flags) on **every** start. All encode + decode ran on the
CPU. The test topology stacks the desktop app, the Android emulator, the
emulator's WebView (also software-encoding), and per-frame AES-256-GCM E2EE on
**one laptop CPU** — Chromium's overuse detector then collapses the encoded
resolution/bitrate (`qualityLimitationReason: "cpu"`), which is exactly the
macroblock/smear signature in the screenshot.
*Evidence:* flags in `lib.rs run()`; the in-code incident note shows the
confirmed GPU-driver wedge was the **capture** path ("Disabling encode/decode
alone was NOT enough"), so the encode/decode disables were precautionary, not
the proven fault.

### RC3 — Codec negotiation was non-deterministic while the E2EE frame crypto is VP8-specific *(correctness landmine)*
`call-frame-crypto.ts` leaves exactly the **VP8** payload-descriptor bytes
(10 keyframe / 3 delta / 1 audio) unencrypted for the RTP packetizer, but no
code pinned the negotiated codec. Any WebView update reordering SDP codecs
(VP9/H264/AV1) would put encrypted bytes where the depacketizer expects codec
headers → corrupted video on a "successfully" connected call.

### RC4 — Possible congested public-TURN routing with zero visibility
`call-ice.ts` falls back to the free Open Relay (`openrelay.metered.ca`). In
the desktop↔emulator topology, both peers' server-reflexive candidates hairpin
through the home router (frequently unsupported) and the emulator's host
candidate (`10.0.2.15`) is unreachable from the host — if the emulator→host
direct check is lost, ICE lands on the congested public relay and the
bandwidth estimate collapses (mush + audio dropouts). There was **no
instrumentation anywhere** (grep: zero `getStats` usages) to even see which
route a call took — spec §7/§8 violations in themselves.

### RC5 — No content hints, default 32 kbps Opus, no audio priority
Video tracks carried no `contentHint`, audio had no bitrate target or network
priority — leaving degradation decisions untuned and voice below its quality
potential.

---

## 2. Fixes implemented (permanent, root-cause level)

| # | Fix | File(s) |
|---|-----|---------|
| 1 | **HD tiers**: auto = 1280×720@30 / 2.5 Mbps, hd = 1920×1080@30 / 4.5 Mbps, low unchanged (320×180@15 / 250 kbps). Encoder still adapts *down* under genuine pressure (`degradationPreference: "balanced"`), so ceilings define the best case, not a constraint. | `src/lib/call-quality.ts` |
| 2 | **Hardware video encode/decode restored by default on Windows.** Only the *confirmed* driver-wedge path (MJPEG decode, D3D11 capture, GPU-memory frame buffers, DirectComposition overlays) stays software. The self-healing watchdog is unchanged: a mid-call crash still flips the next launch to full software media + `--disable-gpu` until cleared from Settings. | `src-tauri/src/lib.rs` |
| 3 | **VP8 pinned via `setCodecPreferences`** (+rtx/red/ulpfec) on both caller and callee before negotiation — the E2EE header convention is now deterministic on every platform/WebView version. | `src/lib/call-quality.ts` (`pinVideoCodec`), `src/lib/use-secure-call.ts` |
| 4 | **Live diagnostics engine**: `getStats()` sampled every 2 s while connected → route (Direct vs TURN relay), codec, encode/decode resolution + fps + bitrate, RTT, jitter, packet loss, `qualityLimitationReason`. Every sample logs one structured `[call-stats]` console line (DevTools / `adb logcat`). | `src/lib/call-stats.ts` (new) |
| 5 | **In-call diagnostics UI**: bottom-left chip (received resolution, relay/limited badges) expanding to a full panel; names the cause ("limited by CPU", "limited by bandwidth", "Relay (TURN)") whenever quality drops. | `src/components/call/InCallOverlay.tsx`, `CallProvider.tsx` |
| 6 | **Content hints + audio tuning**: video `contentHint="motion"`, audio `"speech"`; Opus target raised to 64 kbps (auto) / 96 kbps (hd) with `networkPriority/priority = "high"`; echo-cancel/noise-suppress/AGC unchanged. Sender params re-asserted when the connection reaches `connected`. | `call-quality.ts`, `use-secure-call.ts` |
| 7 | **Quality selection persisted** (`localStorage`) so HD/Low survive across calls and restarts. | `call-quality.ts`, `use-secure-call.ts` |

## 3. Verification

- `vitest run`: **26/26 passed** — including 9 new tests: tier invariants
  (720p floor, 1080p HD, low-tier bounds, ideal/max-never-exact constraints,
  Opus targets) and the stats summarizer (route detection incl. relay,
  bitrate-from-deltas, RTT/jitter/loss extraction, teardown resilience,
  transport-less fallback).
- `npm run build` (tsc + Vite): clean.
- `cargo check`: clean. `cargo test commands::calls`: **5/5** — watchdog
  safe-mode semantics (promote / consume / graceful-clear) unchanged.

### End-to-end validation checklist (requires two live ends)
1. Rebuild desktop app and Android APK; place a Desktop ↔ emulator call.
2. Open the bottom-left stats chip: expect **Route: Direct** on a same-laptop
   call; if it says **Relay (TURN)**, the free public relay is carrying the
   media — configure a local/operator TURN via the `messaging_call_relay` row.
3. Expect sending/receiving to climb to **1280×720@30** within ~10–20 s on an
   unloaded machine; if the panel shows "limited by CPU", the emulator is
   starving the encoder — that is now *named*, not silent.
4. `[call-stats]` lines in DevTools (desktop) / `adb logcat` (Android) record
   the full timeline for any report.

## 4. Before vs after

| | Before | After |
|--|--------|-------|
| Best-case video | 960×540 @ 1.2 Mbps (never sharp fullscreen) | 1280×720@30 @ 2.5 Mbps default, 1080p opt-in |
| Windows codecs | Software forced always | Hardware by default; software only in self-healed safe mode |
| Codec | SDP default (drift = corrupted E2EE) | VP8 pinned deterministically |
| Audio | Opus ~32 kbps, no priority | 64–96 kbps target, high network priority, speech hint |
| Diagnostics | None (zero `getStats`) | 2 s sampling + UI panel + structured logs |
| Quality choice | Reset to Auto each call | Persisted |

## 5. Remaining risks

- **Hardware encode on a machine with a broken GPU driver** could in theory
  wedge again — mitigated by the unchanged watchdog (one crash → permanent
  software mode until the user opts out) and by capture staying software.
- **Emulator ceiling**: the Android emulator's virtual camera and software
  WebView encoder cap what that *end* can produce; on physical devices the
  hardware path applies. CPU-limited degradation is now visible, not silent.
- **Public Open Relay fallback** remains for out-of-the-box cross-NAT calls;
  operators should provision their own TURN (`messaging_call_relay`) for
  production traffic. The stats panel now exposes relay usage per call.
