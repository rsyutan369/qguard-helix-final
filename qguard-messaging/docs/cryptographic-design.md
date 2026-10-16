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

Messages use a Double Ratchet-style model:

- A chain key derives one message key per message.
- Message counters are monotonic.
- Replays are rejected by message ID and counter state.
- AEAD tags are verified before plaintext is returned.
- Nonces are generated with the OS CSPRNG.

## Conversation Protection Status

Each conversation header shows what can be proven about its protection
(`src/lib/pq-status.ts`), built only from evidence the client holds:

- the contact devices the next message will be sealed to, and the hybrid
  combiner their published suite selects (`KemCombiner::for_peer_suite`);
- the combiner label of messages that actually opened on this device (the
  core refuses an unknown label, so an opened envelope proves it);
- the core's device-pin verdicts and its own forward-secrecy summary.

Levels: *Not measured yet* (no evidence), *Needs attention* (a weaker form is
in use, or nothing can be delivered), *Quantum-safe* (hybrid with the bound
combiner everywhere measured) and *Quantum-safe* with every receiving device
pinned. Devices excluded from delivery are reported but do not lower the
level, since nothing is sealed to them. "Pinned" proves the device, not the
person.

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

## File Encryption

Files use envelope encryption:

1. Generate a random AES-256-GCM file key.
2. Encrypt file chunks locally.
3. Wrap the file key separately for each recipient device using hybrid X25519 + ML-KEM.
4. Sign metadata and ciphertext bindings with Ed25519 + ML-DSA-65.
5. Upload ciphertext and encrypted metadata only.
