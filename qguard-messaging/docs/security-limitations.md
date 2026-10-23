# Security Limitations

- This implementation is production-oriented, not independently audited.
- **Message forward secrecy, by default, follows prekey rotation, not each
  message.** One-shot envelopes are sealed to a signed prekey; anyone who
  obtains a prekey secret during its epoch (about a day, until the prekey is
  destroyed) can open messages sealed to it that are not yet recorded in the
  ledger. See `cryptographic-design.md`.
- **The post-quantum session ratchet (`QGuard-PQRatchet-v1`) is opt-in and has
  not been independently reviewed.** It is off unless switched on in
  Settings → Advanced (or `QGUARD_RATCHET=1`), and used only with contact
  devices that have it on too. It follows the published Double Ratchet with a
  sparse ML-KEM step (Signal SPQR / Apple PQ3 shape) but simplifies the ML-KEM
  step (whole key, occasionally) and is our own implementation. It is not
  formally verified. Do not rely on it for regulated deployments until the
  independent review (roadmap 2k) is done.
- With the ratchet on, the message-key ledger still keeps each opened message's
  key (encrypted at rest) so history stays readable; the ratchet's forward
  secrecy protects messages not yet opened and the session state, not keys
  already in the ledger. Deleting a message destroys its ledger key.
- The ratchet header is visible to the relay: a session id, public ratchet keys,
  message counters and, occasionally, a public ML-KEM key or ciphertext. This
  lets the relay group messages by session; it already knows which devices talk.
- Restoring an old copy of a device's data is a session reset: messages sent on
  sessions newer than the copy cannot be opened there.
- **Call phrases prove a device, not a person.** If a verified contact's
  unlocked device is in someone else's hands, the phrase will match. It says
  nothing about whether audio or video is synthetic, and protects only contacts
  the user has verified. Call pairing is processed when the conversation is
  open on both devices; until then the status reads "waiting".
- **Duress PIN and panic wipe erase this device only.** They destroy local keys
  and sign out; ciphertext on the relay stays (unreadable without keys), other
  devices keep their copies, and the platform keychain or Keystore could, on
  some hardware, retain material until it is overwritten. The duress PIN
  protects against being forced to unlock — not against forensic imaging made
  before it was entered. An observer who knows the app could notice that the
  account must sign in again.
- **Biometric unlock** trusts the device's strong biometric and its Keystore;
  anyone the device owner enrolled can unlock. Hiding the app in Recent apps
  relies on Android honouring `setRecentsScreenshotEnabled` (13+) or the cover
  view being drawn before the snapshot (older versions).
- **History backups** hold message keys: anyone with the backup file AND the
  recovery key can read the history still on the relay. A backup covers
  messages up to when it was made; deleted or expired messages are not
  recoverable. Restoring re-adds keys that deletion had destroyed on the old
  device only if they were in the backup.
- **Social recovery** resists fewer than k helpers, and k helpers without the
  PIN — but k colluding helpers together with the relay can try to guess the PIN
  offline (Argon2id slows that, it does not stop it). Use a passphrase. Helpers
  must confirm the four words out of band; approving a request without doing so
  defeats the protection against a forged request.
- **Account sealing key (audit and telemetry details).** The key is wrapped to
  each of your devices' long-lived identity keys, so the wrap has no forward
  secrecy: someone who later steals a device identity key AND holds a copy of the
  wrap rows can recover the key and read those details. They are low-value
  (event types, ids, error text), not message content. Fields sealed before a
  device was removed stay readable to whoever already held that epoch. Two
  devices that both believed they were first could mint different keys; that is
  refused and shows as "unavailable", never as wrong data. Rows written before
  the migration stay plaintext until they age out. Audit event types, severities
  and hashes, telemetry stage names and status, and every id column remain
  readable to the relay.
- Supabase sees minimum routing metadata such as recipient IDs and queue timing.
  There is no sealed sender (`sealed_sender` is deliberately `false`).
- The relay cannot decrypt content, but compromised endpoints can access local
  plaintext after decryption.
- Secure deletion cannot be guaranteed on all SSDs.
- Optional liboqs support is a feature-gated integration point, not the default dependency path.

- **Groups use pairwise fan-out, not MLS.** Each message is sealed separately to
  every member device (same hybrid KEM, signatures and pins as a direct chat), so
  groups are capped at 32 people (enforced by the server since migration 047).
  The server sees who is in a group (not its name). Members learn of membership
  changes on their next refresh, so a message sent in that window can still
  reach a just-removed member or miss a just-added one. A removed member keeps
  whatever was already delivered. Only the owner renames; the owner and up to 3
  admins manage members. MLS was not used because its post-quantum ciphersuites
  are not yet standardized (`docs/superpowers/specs/2026-10-19-groups-design.md`).
- **Large groups (up to 1,000) trade per-message keys for one key per epoch.**
  Posts are encrypted once under a shared epoch key, exactly as in a channel,
  so the channel limits below apply. In addition: members hand nothing out —
  only the owner's and admins' devices distribute keys and start a new epoch,
  so after someone leaves, members' posts keep using the key that person held
  until the owner or an admin next has the group open. The relay stops serving
  posts to them at once; only someone holding both that key and a copy of the
  relay's data could read those posts. Large groups carry text posts only (no
  files, voice notes, reactions or calls yet).
- **Block and Restrict rely on the relay.** A block makes the server drop the
  blocked person's envelopes and call signals to you; Restrict drops their calls
  and stops them adding you to groups. Both are enforced by migration 047's
  triggers, so a server that has not applied 047 shows the state but does not
  enforce it. Blocking is one-way and silent: they are not told, and you can
  still be in groups with them. In a large group or channel their posts still
  reach your device (the timeline is shared) and are folded away by the app,
  not by the server.
- **Group and channel names are kept on the device.** Decrypted names are stored
  in the core's encrypted per-user storage (like channel keys) so the
  conversation list can show them after a restart; they never reach the server.
- **Screen sharing** sends exactly what the system picker selected, encrypted
  like the camera. Check what is on that screen before sharing. It is not
  available on Android, or in calls that started without video.
- **Relay health checks** contact only the relay's own health endpoint and, on
  desktop, the existing update server — so the update server learns when this
  device could not reach the relay. On Android there is no second host, and the
  banner says it cannot tell an outage from a blocked network.
- **The operator role only changes what is displayed.** Internal panels show the
  caller's own data; any future privileged action must be enforced server-side,
  not by `useIsAdmin`.
- **The AI assistant sends message text to a cloud provider.** What you ask it to
  read leaves the device to Anthropic or OpenAI (your key, their terms) and is no
  longer end-to-end encrypted there. The others in the conversation are not
  told. Disappearing, one-time, scheduled and undecrypted messages and
  attachments are never sent. Its answers can be wrong, and a message written to
  manipulate it can still skew a summary, even though it cannot make the app act.
- **Channels: forward secrecy is per key epoch, not per post.** Whoever holds an
  epoch key reads every post of that epoch; a new key starts when someone
  leaves. New readers get only the current epoch. A staff member's second device
  starts its own epoch rather than receiving one.
- **Group calls are a mesh of 1:1 links (up to 3 people).** If someone joins after
  another member's ring timed out, those two are not connected. The call phrase
  is per link and not shown in the group view yet.
- **Group names:** only the owner's names count, judged by the server's record of
  who owned the group when. The server is trusted for that record, as it is for
  membership.
- **Outbox and nearby delivery:** waiting messages are stored sealed on the device
  until the relay answers. Phones in Bluetooth/Wi-Fi range learn that something
  was sent, its size and the device ids on it — never the content. A message
  received nearby whose sender cannot be checked offline is shown as unverified.
