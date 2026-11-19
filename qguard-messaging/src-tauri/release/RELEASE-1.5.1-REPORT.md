# QGuard Messaging 1.5.3: XFER without a shared network, radar pictures (2026-11-13)

**Issue:** with 1.5.2 the phone and PC were connected only over Bluetooth. The phone retried until "Receiver unavailable"; the PC never got the offer.
**Root cause:** XFER sent both the offer and the file data over Wi-Fi/LAN only. The phone's advertised Wi-Fi addresses were unreachable from the PC (a different network or client isolation; the PC is on a Public-profile Wi-Fi network). Bluetooth carried Mesh only.
**Fix (owner chose the automatic Wi-Fi link):**
- Offers, accept and decline travel over the encrypted Bluetooth channel (protocol 3) when no network path exists, so the receiver is notified at once.
- After acceptance the devices set up a private Wi-Fi link over that channel. The Android side (or, on the same platform, the smaller fingerprint) hosts a temporary hotspot. A Windows PC joins after the user taps **Join Wi-Fi link** and returns to its previous network 90 s after the last transfer. Android-to-Android shows the network and password to join by hand. Transfers on the link remain QHCE-authenticated end to end.
- Paired devices show their picture on the radar and in device lists. New opt-in "Show my picture to nearby devices" (off by default) lets unpaired devices show it too, over Bluetooth discovery plus an authenticated fetch.

| File | SHA-256 | Signing |
|---|---|---|
| `For PlayStore Upload/Nov-13-2026-v1.5.3/Qguard-Messaging-Release.aab` | `2b5eaadfcbabef507ea70454f941759ff2975d0e82716a14f894ecf030a0f882` | Upload key `59:53:01:F1:…:FC:65:A3`, jarsigner verified; versionCode 1005003 |
| `For PlayStore Upload/Nov-13-2026-v1.5.3/Qguard-Messaging-1.5.3-arm64-release.apk` | `465d22175e7a478702ba7665413191ab339bdba0d61e6c8f4eb6f02ca39acfb4` | v2 signature; verify-android-release: all checks passed |
| `Desktop-Windows-v1.5.3/QGuard Messaging_1.5.3_x64-setup.exe` | `b83d51a19622bfa7ae98cb3307171fa992db1a3d17ed2ffbc52a76847fd32fcc` | Updater signature verified; **not Authenticode-signed** |

Tests: Rust offline 94/94 (6 new: host choice, address filter, offer throttle, manual-join secrecy, Windows profile XML, nearby-picture protocol); vitest 770/771 (unrelated `ai-assistant` failure); TypeScript clean; link card, radar pictures and setting checked in the browser harness.
**Not verified on devices:** the Wi-Fi link needs a two-device run (phone hotspot permission prompt, PC joining, return to home Wi-Fi). Both devices must run 1.5.3.

---

# QGuard Messaging 1.5.2: profile picture sync fix (2026-11-13)

**Issue:** after installing 1.5.1, each device still showed only its own picture.
**Root cause:** the app read the profile picture with `fetch()` on its `blob:` URL.
The app Content-Security-Policy (`connect-src`) does not allow `blob:`, so the
request was refused inside the desktop and Android apps. No device ever made or
stored its thumbnail, so there was nothing to send. The browser test harness had no
CSP, which is why it passed there. Proven with `tools/avatar-csp-probe.html` under
the real policy: the browser logs "Connecting to blob:… violates … connect-src".
**Fix:** `src/lib/offline-avatars.ts` draws the thumbnail from an `<img>` element
(`img-src` allows `blob:`) and encodes with `canvas.toDataURL`. A regression test
asserts `fetch` is never used. The rest of the exchange is unchanged.

| File | SHA-256 | Signing |
|---|---|---|
| `For PlayStore Upload/Nov-13-2026-v1.5.2/Qguard-Messaging-Release.aab` | `1f0a472a7ca122fb78454801580d073f51ad55ee16904ade2820ce107e6ac8a8` | Upload key `59:53:01:F1:…:FC:65:A3`, jarsigner verified; versionCode 1005002 |
| `For PlayStore Upload/Nov-13-2026-v1.5.2/Qguard-Messaging-1.5.2-arm64-release.apk` | `6fa6f48cce72ef85261166164ad232377f5b4bf60229ffa9f65ee6a25abd9817` | v2 signature, same key; verify-android-release: all checks passed |
| `Desktop-Windows-v1.5.2/QGuard Messaging_1.5.2_x64-setup.exe` | `875c5be8432d8ca69a7824d1d8959fc97763299d56019235cba7930e6d3ba101` | Updater signature verified; **not Authenticode-signed** (no certificate) |

Tests: TypeScript clean; vitest 764/765 (the unrelated `ai-assistant.test.ts` failure persists); Rust offline 88/88 (no Rust change since 1.5.1).
Not yet confirmed on the two physical devices: install 1.5.2 on both, open the app once while online (that is when each device makes its thumbnail), then open XFER or Mesh with the other device connected.

---

# QGuard Messaging 1.5.1: Mesh and XFER fixes, release report (2026-11-13)

Scope: `Qguard_Wiki/UI-UX_Fixes`. Version 1.5.1 (Android versionCode 1005001),
because the 1.5.0 bundle (versionCode 1005000) was already staged for Play.

## Issues and root causes

| Issue | Root cause | Fix |
|---|---|---|
| Mesh composer overlaps the bottom navigation | The conversation height was a viewport guess (`100dvh - 11rem`) that ignored the app header, offline banner, network notice and the navigation bar (the installed builds predate the first fix). | `MeshConversation` measures the space left in its scroll area and the real top edge of the navigation bar (`[data-qg-bottom-bar]`, gesture inset included) and keeps 12 px clearance; it refits on resize/keyboard and scrolls the composer into view when space runs out. |
| Each device shows only its own avatar | No profile data was exchanged between devices: only a display name at pairing. | Channel protocol 2: digest-first picture exchange on the authenticated persistent channel (`src-tauri/src/offline/avatar.rs`), stored under the session-authenticated fingerprint. |
| No "Send More Files" after a transfer | The installed builds predate the button; XFER-only pairings also had no persistent channel, so there was no live session to show. | After a verified send, **Send more files** opens the file picker for the same device; the receiver gets **Wait for more files**. XFER-only pairings now hold a persistent channel; XFER screens show the live link state and **Disconnect**. |

## Implementation

- **Avatars:** the app makes a 192 px JPEG thumbnail of the signed-in profile picture (`src/lib/offline-avatars.ts`) and hands it to the native core (`offline_set_avatar`). On channel open, each side sends `Profile {owner, avatar-digest}`; the peer requests the picture only when the SHA3-256 digest is new, re-hashes it on receipt, and accepts only JPEG/PNG/WebP ≤ 48 KiB. Pictures are sealed per account (`offline-avatars`), shared only with trusted paired devices, deleted when a device is removed or blocked, and refreshed on every change (the digest changes). The views read digests from the status snapshot and fetch each image once (`offline_avatar`); initials or the platform icon are the fallback.
- **Persistent sessions:** the existing channel (heartbeat, dead-link detection, redial with backoff, resend of unacknowledged messages) now also serves XFER-only pairings. A version-2 dial refused by a version-1 build is retried with version 1 at once (messaging works; no pictures).
- **XFER flow:** a receiver that approved a pairing waits on "Ready to receive", which opens the offer when it arrives; consecutive batches reuse the pairing (no new pairing or probe); repeat clicks are blocked by the single-flight action runner.

## Testing performed

| Area | Result |
|---|---|
| TypeScript (`tsc --noEmit`) | Pass |
| Front-end tests (vitest) | 763 pass, 1 fail: `ai-assistant.test.ts` (consent memory), which fails on its own and is unrelated to these changes |
| New UI tests | Send-more opens the picker once and offers to the same device without re-pairing; waiting screen opens an arriving offer; Disconnect requires confirmation; peer picture is looked up by fingerprint and digest; composer clearance math; avatar sync rules |
| Rust offline tests | 88 pass, 0 fail (including new avatar validation and digest tests) |
| Layout (browser harness, real shell classes) | Composer clear of the navigation at 360×640, 375×812 and 412×915 on the Android skin (29 px) and the floating rail (68–80 px); with the keyboard open the composer stays visible |
| Physical devices | **Not performed.** No Android device is attached to this machine. Android↔Windows, Android↔Android and Windows↔Windows pairing, picture sync, picture change, restart, interruption/reconnect and consecutive transfers need a two-device run. |

## Artifacts

| File | SHA-256 | Signing |
|---|---|---|
| `For PlayStore Upload/Nov-13-2026-v1.5.1/Qguard-Messaging-Release.aab` | `6e33531186224b41a77814a12698c9486a3ff158d199ddbc3198629e127a645c` | Upload key, cert SHA-256 `59:53:01:F1:…:FC:65:A3`; `jarsigner` verified |
| `For PlayStore Upload/Nov-13-2026-v1.5.1/Qguard-Messaging-1.5.1-arm64-release.apk` | `9a757be3f5b1f170d903c6f39660e269b0ce764cb30d5f8e09b2e1e3cf5d91e2` | APK Signature Scheme v2, same key; fresh UI, SIGILL-safe |
| `Desktop-Windows-v1.5.1/QGuard Messaging_1.5.1_x64-setup.exe` | `20eaf6bb31d51bc38804e131289c007a5071efa793c1668a1a9373d8d3f01ac9` | **Not Authenticode-signed** (no code-signing certificate on this machine). Tauri updater signature `.sig` verified against the app's public key (key ID 64F12F02CE76C3A2). |

Android manifest: `com.qguard.messaging`, target SDK 36, not debuggable,
`usesCleartextTraffic=false`, `allowBackup=false`, Bluetooth/Nearby permissions
`neverForLocation`, legacy location capped at SDK 32.

## Remaining manual actions

1. Two-device testing on physical hardware (see above). Both devices must run 1.5.1: older builds pair differently.
2. Upload the AAB in Play Console (the older 1.5.0 bundle in `Nov-13-2026/` is superseded).
3. Windows code signing needs an Authenticode certificate (OV/EV or Azure Trusted Signing). Until then SmartScreen warns on install.
4. Publishing the desktop installer (`tools/release.ps1`) updates the website download label and `latest.json`; not done here.
