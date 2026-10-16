# Changelog

All notable changes to the QGuard Messaging desktop application.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versions are set in `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml` and the
website download label in `../src/app/qguard-messaging/_shared.tsx` — all three
are kept in lock-step by `tools/release.ps1`, because a mismatch silently breaks
auto-update.

## [1.3.12] — 2026-10-14

Android fix release. Built locally; not yet published. No database migration;
the desktop app is unchanged from 1.3.11.

### Fixed

- **Android: every Quantum Vault folder action failed with "vault folder picker
  needs the app activity".** Encrypting or decrypting a file and creating a
  Portable Hybrid Identity all stopped at the destination-folder step. The
  Tauri 2.12 runtime (tao 0.37) hands native code the application context
  instead of the activity, and the folder picker needs the activity to open.
  The app now registers its activity for the picker. Google Play purchases had
  the same fault and are fixed with it.
- **Android: after the right PIN, the email/password sign-in screen flashed
  before the app opened.** The PIN screen used to close as soon as the PIN was
  accepted, before the session behind it was restored. It now stays up, showing
  "Unlocking your secure session…", until the app is ready.

## [1.3.11] — 2026-10-13

Security release. Desktop and Android. Built locally; not yet published.

This release adds no database migration. The new hybrid-KEM combiner and call
protocol v2 are used only with peers that advertise them; the previous forms
are still spoken and read. Interoperation with a 1.3.10 device is covered by
unit tests, not yet by a two-device test.

### Security

- **Device pins — the relay can no longer add a device to someone's account.**
  The relay is the device directory, and a row it invents is as self-consistent
  as a real one. A device added that way received every new message, had
  history re-sealed to it by trusted-device sync, and had its own messages shown
  as verified. This device now keeps its own record of which devices belong to
  whom (trust on first use, encrypted at rest). A device that appears later is
  **new**: nothing is sealed to it and nothing from it is shown as verified
  until the user approves it. A device id that returns with different identity
  keys is never accepted.
- **Forward secrecy for Secure Chat, per rotation epoch.** A device used to keep
  every prekey it had ever published, so one copy of its key file opened every
  message ever sent to it. Message keys are now remembered in an encrypted
  ledger the first time an envelope opens, prekeys rotate on a schedule, and
  retired prekeys are destroyed once everything sealed to them is accounted
  for. This is not a per-message ratchet: messages sealed to the currently
  active prekey share it until the next rotation.
- **Replayed, relocated and re-attributed messages are refused.** A genuine
  envelope copied into a new row, into another conversation, or shown under
  another person's name used to verify. The row is now checked against the
  fields its sender signed.
- **Calls: per-call keys and an authenticated caller (call protocol v2).** The
  media key now also depends on a key pair that exists only for that call, so a
  later compromise of a device's long-term identity plus a recording of the
  exchange does not yield it. The caller signs the call's key material with its
  registered Ed25519 + ML-DSA-65 identity; a signature that is present and does
  not verify ends the call instead of downgrading it. The call screen states
  only what was proven for that call.
- **Hybrid KEM combiner bound to its transcript (`QGuard-HybridKEM-v2`).** The
  X25519 ephemeral key, the recipient key and a hash of the ML-KEM ciphertext
  are mixed into HKDF-SHA3-256, and a non-contributory X25519 result is
  refused. Used with peers that advertise it; the previous combiner is still
  read so existing envelopes and containers keep opening.
- **Quantum Vault containers are bound to the vault PIN (`.qvault` v5).** Older
  containers carried their key wrapped to the device's KEM key, which is
  protected only by the OS keychain, so the vault lock was a check in the UI
  rather than in the cryptography. v5 wraps the file key under the PIN-bound
  vault key. Older containers stay readable, are reported as not PIN-bound, and
  "re-protect" rewrites their header. A container is authenticated as this
  vault's own before a byte is written.
- **The hardening report is measured, not asserted.** "Post-quantum protection",
  "secure memory" and "rate limiting" were constants. Each is now the outcome of
  a start-up self-test of the primitives in this binary: X25519 + ML-KEM-1024,
  Ed25519 + ML-DSA-65, AES-256-GCM, SHA3-256 against the FIPS 202 vectors,
  zeroisation and the rate limiter.
- **SHA3-256 in the WebView.** Audit event digests, the web asset integrity
  manifest and the rate-limit e-mail key were SHA-256, because WebCrypto has no
  SHA-3. They now use SHA3-256, matching the approved stack and the Rust core.
  Three SHA-256 uses remain on purpose and are listed under Known limitations.

### Fixed

- **"Encrypted history is taking longer than expected" on a long thread.** One
  envelope row is about 27 KB (ML-KEM ciphertext, ML-DSA signature and sender
  keys as JSON), and the thread downloaded 250 whole rows — about 7 MB — in one
  request with a six-second deadline, again on every realtime event. On a phone
  that request did not finish in time. The thread now fetches a small listing,
  then only the envelope bodies it does not already hold, in chunks of 24 with
  this device's copies first. Measured on a 250-row thread: first chunk after
  1.3 s instead of one 7 MB request; a reload with nothing new is 52 KB.
- **A contact's new device read as "Waiting for recipient PQC prekeys".** When
  the only deliverable device of a contact is one waiting for approval (as after
  they reinstall), the status now says to approve it, and the approval card
  stays pinned to the top of the thread instead of sitting above the history.
- `tools/messaging-reset.mjs` treated a storage folder it could not list as
  empty, so a reset could leave attachments behind and say it had handled them.
  It now stops with the error.

### Changed

- Tauri 2.10 → 2.12 (runtime, CLI and plugins), `webview2-com` 0.39,
  `windows` 0.62, Supabase client 2.117, React 19.3. The cryptographic crates
  are unchanged.

### Known limitations

- MFA recovery-code hashes stay SHA-256: Postgres recomputes them with
  pgcrypto, so client and database must change together in a migration.
- The chat attachment `sha256_b64` field stays: it is a transfer checksum that
  released clients verify. Integrity comes from AES-256-GCM.
- The conversation privacy screen verifier stays PBKDF2-HMAC-SHA-256 (WebCrypto).
  It is a screen, not encryption; the workspace lock (Argon2id → HKDF-SHA3-256,
  in the Rust core) protects data at rest.
- The auto-update signature is Ed25519 (minisign) — the Tauri updater has no
  post-quantum signature option.

## [1.3.9] — 2026-09-21

Desktop and Android. Built locally; not yet published.

### Fixed

- **Android: "Save" / "Decrypt" never wrote a file.** Every save in the app —
  decrypted chat attachments, MFA recovery codes, the Quantum Vault recovery
  key and the audit export — was an `<a download>` click on a blob URL. Android's
  system WebView drops those silently, so the app reported "decrypted locally"
  (and ticked "I saved my recovery key") while nothing reached the device. Saves
  on Android now go through a native MediaStore bridge into
  **`Download/QGuard/`** (no storage permission needed on Android 10+), the
  status line names the exact file written, and a failed save leaves view-once
  messages unburned and the recovery checkbox unticked. Desktop keeps the
  WebView download manager.
- **Desktop: "Upgrade" failed with "Failed to fetch".** Billing requests went
  to `api.qguard.dev`, which does not exist. They now go to the `billing`
  Supabase Edge Function on the app's own project; network failures name the
  host instead of the browser's generic text, and a paid checkout is confirmed
  directly from PayPal so activation no longer depends on webhook delivery.
  Android uses the same PayPal checkout until the billing service can verify
  Google Play purchases, so Play can never charge for a plan it cannot grant.
- **Runtime layer stuck at 8/9 on Android ("Review coverage", 96%).** The
  Transport Policy check reported only what the app could *configure*, which on
  Android is nothing, so it always failed. It now measures what the live backend
  connection actually negotiated: TLS 1.3 with an ML-KEM (FIPS 203) group
  passes on any platform; a classical group, the pre-standard Kyber draft, or
  older TLS fails with the specific fix; and
  a Windows runtime that ignored the post-quantum request now fails instead of
  passing on configuration alone.

## [1.3.8] — 2026-09-16

Security release. Desktop and Android. Every item below was found by a full
audit of the message, call and file paths against the QGuard Helix mandatory
cryptographic stack; the primitives were already correct, and every defect was
in a layer that treated a self-consistency check as proof of identity.

**Requires migration `034_sender_identity_remains_verifiable.sql`.** Without it,
messages a peer sent before their most recent device re-key show as
"Sender unverified" rather than "Verified".

### Security

- **Messages were not authenticated.** An inbound envelope's Ed25519 + ML-DSA-65
  signature was verified against the sender's public keys *carried inside that
  same envelope*, which proves the envelope is internally consistent and nothing
  more. Anyone able to insert a row into `messaging_message_envelopes` could mint
  their own keypair, encapsulate to the recipient's published prekey bundle
  (public by design), stamp any `sender_device_id` on the result, sign it with
  their own key, and the message would decrypt and render with a **"Verified"**
  badge under the impersonated sender's name. Row-level security kept ordinary
  users from forging another user's `sender_user_id`, so the live reach was the
  relay itself or a compromised service role — exactly the adversary
  end-to-end encryption exists to resist. It also made out-of-band safety-number
  verification decorative for messages: a verified fingerprint did not stop
  forgeries signed by a key that fingerprint never covered.

  `verify_sender_identity` now requires the envelope's signing keys to be the
  ones the named device published to `messaging_devices`. Keys match, the message
  is **Verified**; no registry row is available, it is **Sender unverified**; the
  row exists and the keys differ, the message is **refused**. The associated data
  is also recomputed from the envelope and required to match, so a message can
  never display one sender while having been sealed under another.

- **Call signals were not bound to the call's peer device.** `messaging_call_signals`
  is writable by every member of a conversation and only `from_user_id` is
  enforced, so a third member could write an `answer` carrying the live call id
  and re-point the media transport, inject ICE candidates, or end someone else's
  call with a single `hangup` row. Inbound signals are now accepted only from the
  device the call is actually bound to — any ringing device before an answer,
  the answering device after it, the caller for a callee. Media was never
  readable by an injector, since the media key is encapsulated to the device that
  answered; the exposure was session hijack and denial of service.

- **End-to-end call media encryption could fail open.** On the
  `createEncodedStreams` fallback path used by older WebView2 builds, a transform
  that failed to install was swallowed as "non-fatal", leaving media protected by
  hop-by-hop DTLS-SRTP alone while the app still displayed a safety number and
  reported the call as quantum-encrypted. A transform that cannot be installed
  now ends the call.

- **Call media had no replay protection.** A replayed frame carries its original
  counter, header and tag, so AES-256-GCM authenticates it perfectly; anything on
  the media path could re-inject earlier audio or video. Added a 256-wide sliding
  replay window per direction and media kind, checked before decryption and
  committed only after the frame authenticates.

- **Session token claims are now pinned.** `alg: none`, an empty signature
  segment, a non-`authenticated` role or audience, and an implausible issuer are
  refused. This is a local integrity control; Postgres row-level security remains
  the authorization boundary and verifies the signature on every request.

- **Chat attachments are bound to their container.** The per-file AES-256-GCM
  ciphertext now carries the storage path, conversation and message id as
  associated data (`aad_version: 1`), so a ciphertext cannot be relocated between
  objects. Attachments sealed before this release carry no marker and continue to
  decrypt unchanged.

- **Transport policy.** `QGUARD_TLS_POLICY` selects `strict` (default: minimum
  TLS 1.3 plus hybrid post-quantum key agreement) or `compat` (TLS 1.2 permitted,
  for networks behind a TLS-1.2-only inspection proxy). Enforced on Windows
  through the WebView2 network stack and surfaced as a security gate. On Android
  the operating system owns the TLS stack, so the gate reports that the app does
  not enforce it rather than claiming a control it does not have.

### Changed

- A decrypted message whose sender cannot be anchored is recorded as `pending`,
  never `tampered`. `tampered` is an accusation that the ciphertext or signature
  failed; an unanchored sender is a proof that is absent, not one that failed,
  and it can still be obtained later.
- The ratchet's sending and receiving chains no longer start from the same
  derived key. Nothing exploited it, and this is not a wire change, but a
  primitive that hands out the same key in both directions is one refactor away
  from a reflection bug.

### Migration

Apply `supabase/migrations/034_sender_identity_remains_verifiable.sql`. It lets
conversation peers read a device row regardless of `trust_state`, because
retiring a key does not retroactively unsign the messages it signed while it was
live. Delivery is unchanged: revoked devices remain unaddressable.

## [1.3.5] — 2026-08-27

Android-only release. The Windows installer, the website download label and
`public/downloads/latest.json` remain at 1.3.4 — cut a desktop release with
`tools/release.ps1 -Version 1.3.5` before advertising this version there.

### Fixed

- **A whole conversation could turn into "Decryption failed - not found: local
  signed prekey", in both directions, including your own sent messages.** The
  message history was not corrupt and the cipher was not broken: this build's
  move to ML-KEM-1024 (FIPS 203) replaces key material generated by the previous
  build, which was Kyber-1024. Replacing it mints a new device identity, and
  every message already sealed to the old identity was encrypted to a private key
  that no longer exists. Nothing could open them, and the app said so in the
  language of a failure rather than the language of a re-key.

  Those messages are now shown as "Sealed to a retired device key", with one
  explanation per conversation instead of an error on every bubble. They remain
  unreadable — that is what re-keying means — but nothing is wrong, no resend
  helps, and messages sent after the update are unaffected.

- **A device is no longer re-keyed behind your back when its stored keys cannot
  be read.** Any fault while loading the encrypted key material — a hardware
  keystore hiccup, a partially written file — was treated as a first launch: the
  app generated a new identity and overwrote the file, destroying that device's
  keys permanently and silently, along with its ability to read its own history.
  A fault is now reported as a fault and the stored material is left untouched.
  When keys genuinely are unrecoverable, Device Trust Center offers a deliberate
  **Reset Device Keys** action that states the consequence and requires the
  phrase to be typed out.

- **Messages are no longer sealed to devices that could never open them.** A
  device registered by a pre-FIPS-203 build published the same suite label
  ("ML-KEM-1024") as this one while holding Kyber-1024 keys of exactly the same
  length, so every signature and size check passed and it looked perfectly
  reachable. Sealing to it produced a valid, undecryptable message: delivered as
  far as the sender could tell, permanently unreadable at the far end, with both
  clients still displaying "E2EE active". Devices now publish which standard
  produced their KEM, and delivery, sending and decapsulation all refuse to cross
  that boundary — with a message naming the cause. **Both devices in a
  conversation must be on 1.3.5 or later to exchange messages.**

- **Re-keying now retires the device record it replaced.** The old record kept a
  live prekey, so peers went on selecting it and sealing messages to a key that
  had already been discarded. It is revoked rather than deleted, because deleting
  a device record nulls the device reference on every message it ever touched.

## [1.3.4] — 2026-08-27

### Fixed

- **Messages no longer fail to decrypt after you retire a device.** Every message
  in an affected conversation showed "Decryption failed - crypto error: Ed25519
  signature verification failed", permanently, with nothing to connect the cause
  to the effect.

  The messages were never corrupt. `sender_device_id` and `recipient_device_id`
  are foreign keys declared `ON DELETE SET NULL`, so deleting a device row
  rewrote history: Postgres nulled those columns in every message that device had
  already sent or received, including messages signed weeks earlier. The app
  rebuilt each message's signed bytes from those columns, so it reconstructed an
  empty string where the sender had signed a device id, and the signature check
  correctly rejected what was now a different message.

  The signed fields are now recovered from the message's own AAD, which is
  covered by the signature and by the AES-256-GCM tag and cannot be rewritten by
  a foreign key. This is the stricter source, not merely the surviving one: the
  verified content is now derived only from bytes the sender actually signed,
  never from mutable server-side columns. All 200 stored messages on the test
  account verify under the new reconstruction; none did before.

### Changed

- **The chat composer's message options are collapsed by default.** Read once,
  View once, expiry preset, exact expiry time and the typing toggle occupied
  three rows above the input and left little room for the conversation on a
  phone. They now sit behind a "Message options" disclosure. Anything currently
  armed stays visible in the collapsed summary — a burn-on-read or an expiry the
  sender cannot see would be a trap, so the controls hide but their state never
  does.

## [1.3.3] — 2026-08-27

Android-only release. The Windows installer, the website download label and
`public/downloads/latest.json` remain at 1.3.2 — cut a desktop release with
`tools/release.ps1 -Version 1.3.3` before advertising this version there.

### Fixed

- **The Android app can measure its own runtime again.** On an installed release
  build, Anti-Tampering Detection reported "Runtime binary could not be measured"
  and Integrity Hash Checks reported a failed SHA3-256 check — two of the eight
  live security checks — even though nothing was wrong with the device. The app
  looked for its own code by searching the process's memory map for a file whose
  name ended in `.so`. Release builds are packaged with
  `extractNativeLibs="false"`, so no such file exists: the library is stored
  uncompressed inside the APK and mapped straight out of it, and the memory map
  names `base.apk`. Debug builds *do* unpack a `.so`, which is why this only ever
  appeared on an installed release build.

  The app now finds its own image by looking up which mapping contains its own
  code, so the file is identified by what it holds rather than by what it is
  called, and the measurement works for both packaging layouts. The two checks
  also now name the artifact they hashed instead of only saying that they failed.

- **Retiring a device no longer lowers your security score.** Device removals
  were recorded as security *warnings*, and the posture score read that
  literally: retiring dormant identities — the exact housekeeping the dashboard
  asks for — deducted points until the score hit its penalty floor. One account
  read **68% · Action needed** with a completely healthy cryptographic stack.
  These are now recorded as informational events. They keep their full entry in
  the tamper-evident audit log; they simply stop being counted as evidence of a
  weakness that is not there.

- **Security warnings stop dragging the score forever.** Events now count toward
  live posture for 30 days. Posture is a statement about the present, and a
  score permanently depressed by one mistyped password months ago says nothing
  about today. Older events remain in the audit log in full.

- **The phone dashboard no longer hides warnings behind a silent cap.** It showed
  the first two warnings only, so a score could be lower than the visible items
  explained. It now says how many more are affecting the score.

## [1.3.2] — 2026-08-26

### Security

- **The post-quantum key exchange is now genuinely ML-KEM-1024 (FIPS 203).**
  Every previous release performed **Kyber-1024** — the NIST round-3 candidate
  that ML-KEM was standardised from — while describing it as ML-KEM-1024 in the
  app, the device records and the documentation. The two are not the same
  algorithm: they differ in the Fujisaki–Okamoto transform and in how the shared
  secret is derived, and they do not interoperate. Because their keys and
  ciphertexts are byte-for-byte the same size, nothing on the wire or in the
  database revealed the difference; only the compiled dependency did. The
  dependency has been replaced with the FIPS 203 implementation, so the stated
  algorithm and the performed algorithm are now the same thing.

  There was no weakness to exploit — Kyber-1024 has no known break — but a
  platform that certifies post-quantum readiness cannot claim a standard it does
  not run. This corrects the "conformant to final FIPS 203" statement made in
  1.3.0, which was not supported by the code that shipped.

  **What this means for you:** each device generates fresh ML-KEM-1024 keys on
  its next launch and registers as a new device. Messages exchanged before this
  release were sealed to the old keys and cannot be opened afterwards. No Vault
  file is affected. Your previous device entries become dormant and can be
  retired from Device Trust.

- **The key exchange no longer negotiates a weaker parameter set.** It
  previously chose between two parameter sets based on the *length* of the
  recipient's public key, and silently accepted the weaker one. ML-KEM-1024 is
  now the only option, so there is nothing to negotiate and nothing to downgrade
  to.

- **Video call frames are now protected against tampering, not just against
  reading.** Each frame carries a few unencrypted bytes that the media pipeline
  has to read, plus its sequence counter. They were left unauthenticated, so
  anything on the media path could rewrite them without detection — not enough
  to read a call, but enough to corrupt or stall the picture. Those bytes are
  now covered by the same authentication tag as the frame contents, and any
  altered frame is discarded.

- Devices record which algorithm produced their key material, so material from
  an older release is recognised and replaced rather than being used with the
  wrong algorithm. Where the two cannot be told apart, the app fails closed and
  rejects the message rather than accepting a key it cannot verify.

## [1.3.1] — 2026-08-26

### Fixed

- **Calls now ring every device you are signed in on.** Every device — desktop
  and Android alike — registered itself under the same fixed name, and the code
  that picks delivery targets treated devices with the same name as one device.
  An entire account therefore collapsed to a single reachable endpoint: a call
  rang whichever device had been used most recently and no other, so calling
  someone sitting at their other device rang nothing at all. Devices are now
  distinguished by whether they are actually in use, and a call rings all of
  them, as a phone system does. Messages were affected by the same defect and
  are fixed with it.
- **An incoming call now reaches a locked Android phone.** The app-entry PIN
  lock engages the moment the app leaves the foreground, and doing so tore down
  the call listener completely. A call placed while the phone was locked was not
  merely silent — it had nowhere to arrive, and only surfaced once the phone was
  unlocked, by which time the caller had given up. The call listener now runs
  above the lock, so the phone rings while locked and answering never exposes
  message history. The lock also no longer engages during a call.
- **Removed a media relay that was preventing calls from connecting.** The
  bundled public relay could not carry traffic, and its presence stopped the
  connection setup from ever finishing — candidates that should have been ready
  in under a second were still arriving 48 seconds later, past the point where
  the call gave up. This affected calls on the same network too. Setup now
  completes in well under a second. A relay is used only when one is configured,
  it is verified before use, and one that cannot carry traffic is set aside
  rather than left to slow every call down.
- **A call is no longer abandoned while it is still connecting.** The give-up
  timer ran on elapsed time alone and could end a call at the exact moment it
  was about to succeed. Connection progress now holds the timer open, with a
  firm upper bound so a call that genuinely cannot connect still ends promptly.
- **A call now survives a change of network.** Moving between Wi-Fi and mobile
  data, or a router re-assigning an address mid-call, ends the connection; the
  call now re-establishes itself once instead of dropping.
- **A call no longer dies when the phone's screen turns off.** The screen is now
  held awake for the duration of a call, as a video call should.
- **A failed call now says why it failed.** The reason was previously discarded
  along with the call window, leaving no explanation. If the cause is a missing
  relay, the message says so, because that is something an administrator can
  fix.

### Changed

- Devices report their real platform (Android, Windows, macOS, Linux) instead of
  all reporting "Windows Desktop". Existing devices correct themselves on next
  launch; keys and device identity are unaffected.
- Incoming call signals are delivered faster while the app is on screen, and
  more sparingly while it is not.

## [1.3.0] — 2026-08-25

### Security

- **Quantum Vault: recipient fingerprint verification is now required before
  sealing.** Sealing a vault file to a recipient no longer proceeds on an
  unverified identity — the recipient's key fingerprint must be confirmed first.
  This closes the window in which a substituted recipient key could be accepted
  silently.
- **Identity passphrases are checked for real strength.** Passphrase entry now
  applies genuine strength evaluation rather than a length check alone, so weak
  passphrases can no longer protect a long-lived identity key.
- **ML-KEM key generation is conformant to final FIPS 203.** Key generation now
  follows the published FIPS 203 standard rather than a pre-final draft.

### Migration

Nothing you already have needs migrating. Existing identities, vault files and
conversations continue to work unchanged after updating.

## [1.2.29] — earlier release

### Fixed

- Pointed the app at the current Supabase project. The shipped 1.2.28 bundle had
  a deleted project ref inlined at build time, so sign-in failed with "Couldn't
  reach the secure sign-in service" (a DNS NXDOMAIN, not a credential error).
- Aligned the version across all three version files (they had drifted to
  1.2.28 / 1.2.20 / 1.2.20).
- Signed the updater artifact with the real key; the previous signature was
  stale and did not match the shipped binary.
- Corrected the `latest.json` download URL, which was a malformed path.

## [1.2.0] — earlier release

### Added

- Workspace-lock recovery for Secure Chat and Quantum Vault.
- Signed installer and updater artifacts.
