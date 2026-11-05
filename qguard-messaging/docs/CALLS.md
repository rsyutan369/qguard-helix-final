# Calls: voice calls, call history and the Calls page

## Voice calls

A call is **voice** (microphone only) or **video**. Both use the same pipeline:
hybrid **X25519 + ML-KEM-1024** key agreement in the Rust core, optional
per-call key pair for forward secrecy, and **AES-256-GCM on every media frame**
(audio and video alike, `attachMediaTransforms` in `lib/use-secure-call.ts`). A
call never runs without that transform; if the device cannot install it the
call refuses to start.

- Wire: the ring and the offer carry `payload.media = "voice"`; absent means
  video (`callMediaOf` in `lib/call-types.ts`). No server change: the relay
  stores the payload opaquely.
- A voice call never opens the camera (`getMedia`), the callee answers
  microphone-only, and screen share / camera / video-quality controls are
  hidden. The in-call screen shows the person, talk time and the protection.
- Interop: an older build ignores the flag and answers as video; the caller's
  offer has no video section, so only audio flows (still encrypted).
- Start points: the phone icon beside the video icon in every one-to-one chat
  header, and the Calls page.
- Chat header call buttons are one definition (`callControls` in
  `SecureChatPage.tsx`) used by the desktop and phone headers: voice + video in
  a direct chat, a group video call in a group, none in a channel. The group
  button is shown in every group and disabled with the reason
  (`groupCallBlockedReason` in `lib/call-targets.ts`) when a call cannot start:
  not a group of 3 (`GROUP_CALL_SIZE`), someone has no device that can take
  calls, or a call is already running.
- **Calls button in Secure Chat**: beside Contacts — on desktop in the right
  panel's tabs (two rows: Contacts | Calls, Files | Terminal), on the phone in
  the folder tabs (Chats, Contacts, Calls, …). It opens the Calls page and shows
  the unseen missed-call count. The Calls page sits behind the same Secure Chat
  lock, so no second unlock is asked.

## Call history (`src-tauri/src/call_log.rs`)

- Recorded in `CallProvider` from the live call state (`lib/call-history-recorder.ts`),
  one entry per call when it ends: direction, voice/video, group, the other
  people, outcome, start/answer/end times, failure reason, and the key-agreement
  facts the core reported when media connected.
- Outcomes come from an explicit end reason (`CallEndReason` in the call state),
  never guessed: completed, missed, declined, no answer, busy, cancelled, failed
  (`classifyCallOutcome`).
- **Stored only on this device**: one file per account,
  `<data>/history/<account>.calls.enc`, sealed with AES-256-GCM under the
  device storage key (the key that seals the workspace locks), AAD
  `QGuard-CallLog-v1|<user id>`. Never uploaded or synced.
- The core validates every field (UUIDs, closed enumerations, bounded text,
  ordered times), computes talk time itself, keeps newest first, one entry per
  call id, at most 1000.
- Recording works while Secure Chat is locked (calls ring on every page).
  **Listing, deleting and clearing need Secure Chat unlocked** — enforced in
  `commands/call_log.rs`, not only by the UI. Only the unseen-missed count (the
  badge) is readable while locked, like the unread-message count.

## The Calls page (`pages/CallsPage.tsx`)

Behind the Secure Chat lock. 7-day figures computed from the history (calls,
missed, talk time, forward-secret share of connected calls); filters (All,
Missed, Incoming, Outgoing, Voice, Video) with counts; search; day-grouped list;
details beside the list on desktop and in a sheet on phones; New call picker
over your contacts. Opening the page marks missed calls seen (they keep a
marker for that visit).

Calling back never picks devices on this page: it hands the request to Secure
Chat (`callIntent`), which opens the direct chat through `openConversation` /
`startPrivateChat` (blocked contacts refused) and starts the call with the same
ring-target selection as the chat's own call buttons. If nothing can be rung
within 15 s it says so.

## Dashboard cards always ask

The dashboard's Secure Chat, Calls, Quantum Vault and Contacts cards — on the
phone/Android dashboard and, since 2026-11-05, as a row under the metric cards
on the desktop dashboard — call `openProtectedArea` (App.tsx), which **locks the
area first** and then opens it, so the PIN, password or pattern is asked on
every click. Calls and Contacts sit behind the Secure Chat lock. Both layouts
build the cards from one list (`lib/dashboard-hub.ts`): same areas, same unread
and missed-call counts, same lock rule. Other dashboard links keep the normal
behaviour.

## Desktop and Android parity

| Capability | Desktop | Android / phone |
| --- | --- | --- |
| Calls page (filters, search, 7-day stats, New call, call back) | Sidebar → Calls; details beside the list | ⊞ menu → Calls or the dashboard card; details in a sheet |
| Missed-call count | Sidebar badge + dashboard Calls card | Dashboard Calls card |
| Dashboard cards that always ask to unlock | Yes (row under the metric cards) | Yes |
| Voice and video buttons in every 1:1 chat header | Yes | Yes |
| Group video call (groups of 3) | Chat header button | Chat header button (since 2026-11-05) |
| Calls button beside Contacts in Secure Chat | Right-panel tabs | Folder tabs |
| Incoming call screen, ringtone, in-call screen, screen awake | Shared components | Shared components |
| Encryption (X25519 + ML-KEM-1024, AES-256-GCM per frame) | Same code path | Same code path |
| History (device-local, Secure Chat lock) | Same core | Same core |

## Not covered

- Calls that ring while the app is fully closed are not recorded (nothing on
  the device sees them).
- Group calls remain video-only and limited to groups of 3 (a mesh of
  separately encrypted one-to-one links), on desktop and Android alike.
- History is per device by design (no sync).

## Verification

`call_log` Rust tests (validation, talk time, dedupe/cap, missed/seen, older
records); `lib/call-history.test.ts` (outcomes, recorder for 1:1 and group,
grouping, filters, stats, wire flag); headless render of the Calls page
(desktop + phone/Android skin), the voice-call screen and the dashboard cards
over a faked core (20 checks). Not yet run on two real devices.
