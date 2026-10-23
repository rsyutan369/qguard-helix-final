# Cryptographic Design

## Algorithms

| Purpose | Classical | Post-Quantum | Combination |
| --- | --- | --- | --- |
| Key agreement | X25519 | ML-KEM-1024 | HKDF-SHA3-256 over both shared secrets |
| Signatures | Ed25519 | ML-DSA-65 | Both signatures must verify |
| Symmetric encryption | AES-256-GCM | N/A | Unique key/nonce per operation |
| Hash/KDF | N/A | SHA3-256 | HKDF-SHA3-256 |

## Session Establishment

The sender fetches the recipient device bundle, verifies identity and signed prekey signatures, consumes a one-time prekey when available, and establishes a hybrid shared secret:

1. X25519 ephemeral DH against recipient public prekey.
2. ML-KEM-1024 encapsulation against recipient PQ prekey.
3. Concatenate both secrets.
4. Derive a root secret with HKDF-SHA3-256.

The session remains protected if either X25519 or ML-KEM-1024 remains secure.

## Message Encryption

Every message is sealed separately to every receiving device, in one of two
modes. Which one is used is decided per device and shown in the conversation's
protection badge.

### One-shot envelopes (default)

Each message runs its own hybrid encapsulation (above) to the recipient
device's signed prekey; its AES-256-GCM key is derived from that one shared
secret. Forward secrecy reaches as far as the prekey: retired prekeys are
destroyed once every message sealed to them has its key recorded in the
encrypted message-key ledger (`message_keys.rs`), normally after about a day.
This is **not** a per-message ratchet. The sender's copy to its own device is
always one-shot.

### Post-quantum session ratchet (opt-in, `QGuard-PQRatchet-v1`)

`src-tauri/src/pq_ratchet.rs`; design in
`docs/superpowers/specs/2026-10-16-pq-ratchet-design.md`. Used only when this
device has it switched on (Settings → Advanced, or `QGUARD_RATCHET=1`) **and**
the recipient device advertises it in its published suite (`suite.ratchet`).
`QGUARD_RATCHET=0` is the operator kill switch. Every build can still receive
ratchet envelopes.

- **Seed.** A session between two devices starts from the same hybrid X25519 +
  ML-KEM-1024 encapsulation to the peer's prekey as a one-shot envelope, bound
  to the session id and both devices. The root is
  HKDF-SHA3-256(shared secret, transcript of session id, devices, initiator
  ratchet key and a hash of the encapsulation).
- **Symmetric step, every message.** HMAC-SHA3-256 chain; the chain key is
  overwritten as it advances (per-message forward secrecy).
- **X25519 step, every change of direction.** A fresh ratchet key pair per
  turn, mixed into the root: a stolen session stops working after a round trip.
- **ML-KEM-1024 step.** At least every 50 messages or 24 hours, one side offers
  a fresh ML-KEM-1024 encapsulation key in its headers; the other encapsulates
  to it on its next turn and both mix the secret into the same root step.
  Whether a step mixes ML-KEM is carried in the header, so the sides cannot
  disagree. This is a simplification of Signal's SPQR, which streams the key in
  erasure-coded chunks; v1 sends the whole 1568-byte key occasionally.
- **Wire.** The header (`v, kind, session, dh, pn, n`, optional `pq_offer` /
  `pq_answer`) travels in the envelope. Its canonical bytes are covered by both
  signatures (appended to the signable only when present, so one-shot
  envelopes verify byte-for-byte as before) and its SHA3-256 digest is in the
  AEAD associated data (`QGM2|…|<digest>`). An `init` carries the seed; an
  ordinary `msg` carries `hybrid_ciphertext: null`.
- **Receiving** runs on a copy of the session that is committed only after the
  AEAD tag verifies, so a hostile header can never move real state. A session
  answers only to the signing keys it was made with. Out-of-order messages are
  handled with skipped keys (at most 1000 per session, 30 days).
- **Storage.** Sessions are encrypted at rest under the device storage key
  (`<user>.ratchet-sessions.enc`), always written after the message-key ledger,
  so a key the chain has moved past exists only in the ledger. The sender saves
  the session before the envelope leaves the device. Sessions of a previous
  device identity are discarded.
- **Recovery.** A message on a session this device does not hold is reported
  as such (not as a broken cipher); the app forgets any session with that
  device and sends it one empty control on a fresh session, which it adopts.
  Sessions with revoked or re-keyed devices are destroyed. Any failure on the
  send side falls back to a one-shot envelope.
- **Database.** Migration 036 constrains the header shape and admits a null
  encapsulation only on a ratchet `msg`.

### Both modes

- AEAD tags are verified before plaintext is returned; nonces come from the OS
  CSPRNG.
- Envelopes are dual-signed (Ed25519 + ML-DSA-65); the signing keys must be the
  sender device's registered and pinned identity.
- A message is opened once from its key source; reopening uses the ledger.

## Conversation Protection Status

Each conversation header shows what can be proven about its protection
(`src/lib/pq-status.ts`), built only from evidence the client holds:

- the contact devices the next message will be sealed to, and the hybrid
  combiner their published suite selects (`KemCombiner::for_peer_suite`);
- the combiner label of messages that actually opened on this device (the
  core refuses an unknown label, so an opened envelope proves it);
- the core's device-pin verdicts and its own forward-secrecy summary;
- when this device runs the ratchet, the sessions the core holds with each
  receiving device. "Per-message ratchet" is claimed only for a device with a
  session that has completed a round trip, never from the capability alone.

Levels: *Not measured yet* (no evidence), *Needs attention* (a weaker form is
in use, or nothing can be delivered), *Quantum-safe* (hybrid with the bound
combiner everywhere measured) and *Quantum-safe* with every receiving device
pinned. Devices excluded from delivery are reported but do not lower the
level, since nothing is sealed to them. "Pinned" proves the device, not the
person.

## Account Sealing Key (app-only fields)

`src-tauri/src/commands/account_key.rs`, `src/lib/account-key.ts`, migration 044.

A few relay rows are read only by the account's own devices — the details of an
audit event and crypto telemetry details — so they are sealed rather than left
as plaintext columns. Message content, files and calls are not involved; they
keep their own keys.

- **Key.** 256 random bits per epoch (1, 2, ...), stored on each device in the
  device-storage-key-sealed document `<user>.account-key.enc`. The ring holds
  every epoch so older fields stay readable.
- **Field.** `{v, e, n, c}`: AES-256-GCM, key = HKDF-SHA3-256(epoch key,
  "QGuard-AccountField-v1|" + purpose); associated data = user id, purpose, row
  context (the event hash, or the telemetry row id) and epoch. A value moved to
  another row, purpose or account does not open. Purposes are a fixed list.
- **Wrap.** The whole ring, sealed to another device of the same account:
  hybrid X25519 + ML-KEM-1024 to that device's identity keys
  (`QGuard-AccountKey-v1:wrap:<from>:<to>`), AES-256-GCM, dual-signed by the
  sender over the header, the ciphertext digest and the sealed bytes. Made and
  accepted only for devices `device_pins` records as pinned for this account.
- **First key / rotation.** The first key is made by the only trusted device, or
  by the lowest device id when several have none and no wrap exists. A device
  that held the current epoch and is no longer trusted triggers a new epoch,
  made by the lowest-id remaining holder.
- **Failure.** No key for an epoch → the field reads as unavailable, never as
  garbage. No key at write time → a bare marker is written, never plaintext.

## Call Media Encryption

Voice/video calls are end-to-end encrypted independently of the transport
(WebRTC/DTLS-SRTP is treated as untrusted):

1. The caller loads the callee device's published identity bundle and the Rust
   core verifies its Ed25519 + ML-DSA-65 dual signature before any key
   material is derived — a relay that swaps KEM keys cannot complete a call.
2. The caller encapsulates against the verified X25519 + ML-KEM-1024 identity
   keys (HKDF-SHA3-256 binds the shared secret to the call ID).
3. Two directional AES-256-GCM frame keys are derived (caller→callee,
   callee→caller); every media frame is sealed in an RTCRtpScriptTransform
   worker with a per-frame counter nonce before it reaches the transport.
4. Both ends derive the same short authentication string (SAS) from the shared
   secret; the UI requires verbal/typed confirmation so a full relay
   compromise is still detectable out of band.

### Screen share

A shared screen replaces the camera track on the call's existing video sender
(`RTCRtpSender.replaceTrack`), so its frames pass through the same per-frame
AES-256-GCM transform with the same VP8 header handling; no renegotiation, no
unencrypted path. Video only.

## Verified Contacts and Call Phrases

A call's safety number protects the key exchange, not the identity of whoever
holds the other device; a cloned voice reads digits as well as anyone.
`src-tauri/src/commands/contact_verification.rs` adds a check that needs the
real contact's device:

1. **Verify.** The user compares a contact device's safety number (computed by
   the core from both devices' keys) out of band and confirms it. The core
   re-derives the number on confirmation, so a stale screen verifies nothing.
   The verification is recorded in this device's encrypted device record
   (`device_pins.rs`), bound to that device's keys; it is never read from the
   relay, and it is destroyed with the pairing when the device presents other
   keys or is revoked.
2. **Pair.** Each side seals a random half to the other's verified identity
   keys (hybrid X25519 + ML-KEM-1024, transcript-bound combiner) and dual-signs
   the offer (Ed25519 + ML-DSA-65). Offers travel as control messages to that
   one device. A half from a device whose keys are not the recorded ones is
   refused; one from a recorded but not-yet-verified device is held and used
   only once the user verifies it. Older offers are refused as replays.
   `pair_secret = HKDF-SHA3-256(half_low ‖ half_high, "QGuard-CallPairing-v1" ‖
   device ids ‖ identity digests)`, ordered by device id.
3. **Phrase.** `HMAC-SHA3-256(pair_secret, "QGuard-CallPhrase-v1" ‖ call id ‖
   ⌊t/30 s⌋)`, first 40 bits as four words from an embedded 1024-word list
   (every word's first four letters unique). One person asks, the other reads
   their own screen; the app never transmits a phrase. Checks accept the
   window before and after for clock skew, and are rate-limited.

The call screen reports, from the core's call setup, whether the user verified
the exact device the call was agreed with; an unproven device is never
described as verified. The incoming-call screen shows what this device's
record holds for the ringing device id and asks for a second tap before
answering a device never approved for that person. This proves possession of
the verified device — not the human, and nothing about synthetic audio.

## Group Conversations

A group is a conversation of type `group`. There is no group key: every message
is sealed separately to each member device exactly as in a direct chat (hybrid
X25519 + ML-KEM-1024 under `QGuard-HybridKEM-v2`, Ed25519 + ML-DSA-65
signatures, device pins, and the opt-in `QGuard-PQRatchet-v1` session per device
pair). Membership is the server's member rows, which only the owner can grant
(migration 040), so removal is enforced by senders no longer sealing to the
removed devices — no re-keying exists or is needed.

The group name is an encrypted control message
(`{"qguard_control_v1":true,"type":"group_meta","target_client_message_id":<conversation id>,"name":…}`),
accepted only from an authenticated envelope or one's own; the newest wins.
`encrypted_title` holds no hint. MLS (RFC 9420) was evaluated and deferred
until a post-quantum ciphersuite is standardized
(`docs/superpowers/specs/2026-10-19-groups-design.md`).

## Channels

A channel (conversation type `channel`, migration 043) has epoch keys: 32
random bytes each, held only in the core's encrypted per-user storage
(`commands/channels.rs`). A post is sealed once:

- post key = HKDF-SHA3-256(epoch key, salt = post id, info "QGuard-ChannelPost-v1")
- AES-256-GCM, AAD `QGC1|channel|epoch|post|sender user|sender device`
- dual signature (Ed25519 + ML-DSA-65) by the posting device over
  SHA3-256(domain ‖ AAD ‖ length-prefixed nonce, ciphertext, tag)

Readers verify the signature against the sender's registered identity bundle
(itself signature-checked) and refuse a device whose keys changed. Epoch keys
reach reader devices only inside ordinary pairwise envelopes (hybrid
X25519 + ML-KEM-1024), taken only from the owner or an admin, and a held key
is never replaced. A new epoch is started when anyone who held the current key
has left.

## Group Calls

A group call (up to 3 people) is a mesh of one-to-one calls: each pair runs the
unchanged call setup (hybrid KEM to the other device, its own media key and
per-frame AES-256-GCM transform). Nothing is shared between links.

## File Encryption

Files use envelope encryption:

1. Generate a random AES-256-GCM file key.
2. Encrypt file chunks locally.
3. Wrap the file key separately for each recipient device using hybrid X25519 + ML-KEM.
4. Sign metadata and ciphertext bindings with Ed25519 + ML-DSA-65.
5. Upload ciphertext and encrypted metadata only.
