# Changelog

All notable changes to the QGuard Messaging desktop application.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versions are set in `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml` and the
website download label in `../src/app/qguard-messaging/_shared.tsx` — all three
are kept in lock-step by `tools/release.ps1`, because a mismatch silently breaks
auto-update.

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
