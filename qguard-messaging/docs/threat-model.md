# Threat Model

## Protected Against

- Server compromise: content and private keys are unavailable to the relay.
- Harvest Now, Decrypt Later: sessions and file keys are protected by hybrid classical + PQC exchange.
- Message replay: message IDs and counters are tracked locally.
- Ciphertext tampering: AES-256-GCM tags and dual metadata signatures fail closed.
- Malicious key changes: fingerprints, QR verification, and key change warnings are surfaced.
- Device loss: devices can be revoked and excluded from future fanout and file grants.

## Partially Mitigated

- Metadata exposure: routing metadata is minimized but not eliminated.
- Endpoint compromise: forward secrecy and post-compromise recovery reduce future exposure, but compromised endpoints can read current plaintext.
- SSD secure deletion: secure deletion is not fully reliable on wear-leveled media.

## Out Of Scope For This Codebase Alone

- Independent cryptographic audit.
- Legal/regulatory certification.
- Traffic-analysis resistance against global passive adversaries.
- Anonymous account creation and payment privacy.

