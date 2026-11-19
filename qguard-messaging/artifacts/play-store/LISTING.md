# Qguard Messaging — Google Play store listing

Package: `com.qguard.messaging` · Category: Communication · Generated 2026-11-12

## Assets in this folder

| File | Size | Use |
|---|---|---|
| `phone/01…10-*.png` | 1080 × 1920 (9:16) | Phone screenshots, upload in this order (Play shows at most 8; use 01–08, swap in 09/10 as you like) |
| `phone-light/01…11-*.png` | 1080 × 1920 (9:16) | **Light, encryption-focused set** (11 images): each screen carries chips naming the algorithms that feature really uses, plus an encryption-overview card (02) and an in-call screen (04). Upload 01–08 as the main listing. Pick ONE theme per listing; the other set suits a custom store listing or A/B test (Play Console → Store listing experiments) |
| `feature-graphic-1024x500.png` | 1024 × 500 | Feature graphic (required), dark |
| `feature-graphic-1024x500-light.png` | 1024 × 500 | Feature graphic, light |
| `raw/*.png`, `raw-light/*.png` | 1179 × 2556 | Unframed app captures at 3× (for the website, press kit, or a 7"/10" tablet set later). Not uploadable to Play as-is: the 2.17:1 aspect is over Play's 2:1 limit |
| App icon | 512 × 512 | Already exists: `brand/play-store-icon-512.png` |

How they were made: `tools/store-screens.html` renders the real app components (dashboard, chat list, vault, hidden vault, lock screen, Mesh, XFER) in a phone viewport over a **fictional demo account** (Alex Rivera, Maya Chen, etc.); `node tools/store-screens-capture.mjs` captures them with headless Chrome and frames them with `tools/store-frame.html`. Add `light` for the light set: `node tools/store-screens-capture.mjs all light`. Re-run after UI changes (the `qguard-messaging` dev server on port 5174 must be up).

Screenshot captions, in upload order:

1. **Talk. Share. Stay private.** — End-to-end encrypted messaging, calls and storage in one app.
2. **Quantum-safe, at a glance** — See every cryptographic layer protecting your account, live.
3. **Messages no one else can read** — Hybrid ML-KEM + X25519 encryption on every message and file.
4. **Your private Quantum Vault** — Photos, videos and documents encrypted with AES-256-GCM on your device.
5. **A vault nobody knows exists** — Hidden vaults open only with their own secret pattern.
6. **Locked by PIN, password or pattern** — Every protected area asks again. Auto-lock when you step away.
7. **No signal? Still connected.** — Qguard Mesh finds trusted devices nearby over Bluetooth and Wi-Fi.
8. **Off-grid encrypted chat** — Message trusted devices with no internet, sealed end to end.
9. **Send big files fast and offline** — Qguard XFER moves folders device-to-device, verified file by file.
10. **All your chats, sealed** — One-to-one and group conversations, encrypted on every device.

Light set order (`phone-light/`):

1. Talk. Share. Stay private. — ML-KEM · ML-DSA · AES-256-GCM · Argon2id
2. Quantum encryption, everywhere — overview card, one row per feature
3. Messages no one else can read — ML-KEM-1024 + X25519 · ML-DSA-65 + Ed25519 · AES-256-GCM · post-quantum ratchet
4. Quantum-encrypted voice & video calls — ML-KEM-1024 + X25519 · ML-DSA-65 + Ed25519 · AES-256-GCM per frame
5. Your private Quantum Vault — AES-256-GCM · Argon2id · ML-DSA-87 signed · ML-KEM-1024 sharing
6. A vault nobody knows exists — AES-256-GCM · Argon2id 64 MiB · Android Keystore · 12-word recovery
7. Off-grid encrypted chat — ML-KEM-768 + X25519 · ML-DSA-65 + Ed25519 · AES-256-GCM
8. Send big files fast and offline — same as Mesh + SHA3-256 per file
9. Quantum-safe, at a glance · 10. Locked by PIN, password or pattern · 11. No signal? Still connected.

## Verified cryptography (checked in code, 2026-11-12)

Only claim what is in this table. The source column is where it was confirmed.

| Feature | Key agreement | Signatures | Encryption | Other | Source |
|---|---|---|---|---|---|
| Secure Chat | X25519 + ML-KEM-1024; ML-KEM-1024 re-key every 50 msgs / 24 h | Ed25519 + ML-DSA-65 | AES-256-GCM, new key per message | Ratchet chain HMAC-SHA3-256; X25519 step each turn; HKDF-SHA3-256 | `src-tauri/src/pq_ratchet.rs`, `crypto/hybrid_kex.rs`, `message_crypto.rs` |
| Voice / video calls (incl. 3-person group) | X25519 + ML-KEM-1024 per call, plus a per-call key pair (forward secret) | Ed25519 + ML-DSA-65 | AES-256-GCM per audio/video frame, anti-replay | HKDF-SHA3-256; 20-digit safety number | `commands/calls.rs`, `src/lib/call-frame-crypto.ts`, `group-call.ts` |
| Quantum Vault | ML-KEM-1024 only for sharing / enterprise recipient | Ed25519 + ML-DSA-87 on every container header | AES-256-GCM per 1 MiB chunk | File key bound to vault PIN/password (Argon2id 64 MiB, 3 passes); SHA3-256 integrity | `vault_stream.rs`, `crypto/passcode.rs` |
| Hidden Vault | none (symmetric only) | none | AES-256-GCM, no headers, random names | Argon2id 64 MiB from the pattern + Android Keystore key; BIP-39 12-word recovery | `vault/hidden.rs` |
| Qguard Mesh | X25519 + ML-KEM-768 | Ed25519 + ML-DSA-65 | AES-256-GCM | HKDF-SHA3-256; multi-hop relays see only an opaque tag | `offline/session.rs`, `offline/relay.rs` |
| Qguard XFER | X25519 + ML-KEM-768 (same session as Mesh) | Ed25519 + ML-DSA-65 | AES-256-GCM | SHA3-256 per file from a signed manifest | `offline/session.rs`, `offline/transfer.rs` |
| App / workspace locks | — | — | — | Argon2id (64 MiB, 3 passes); PBKDF2-HMAC-SHA-512 when FIPS approved mode is on | `crypto/passcode.rs` |

Not true, so never claim it:
- **"SHA-256 ratchet"**: the ratchet uses HMAC-SHA3-256.
- **Hidden Vault "ML-KEM"**: it uses no public-key crypto at all. That is fine for quantum resistance (AES-256 is not broken by Shor's algorithm), but say "AES-256-GCM + Argon2id", not ML-KEM.
- **Quantum Vault files "encrypted with ML-KEM"**: ML-KEM only wraps keys when a file is shared.
- **Mesh/XFER at ML-KEM-1024**: they use ML-KEM-768.
- **"FIPS validated"**: never. The Mesh session code itself notes the protocol "needs independent review before release".

---

## App name (max 30)

**Qguard Messaging**

Alternative with a keyword (exactly 30): `Qguard: Quantum-Safe Messenger`

## Short description (max 80)

Post-quantum encrypted chat, calls, vault and off-grid Mesh in one private app.

*(79 characters)*

## Full description (max 4,000)

Qguard Messaging is a private messenger and encrypted vault built for the post-quantum era. Your messages, calls and files are encrypted on your device with hybrid post-quantum cryptography, so they stay private today and are designed to stay private against the quantum computers of tomorrow.

🔐 SECURE CHAT
• End-to-end encrypted one-to-one and group chats
• Hybrid key exchange: ML-KEM-1024 (NIST FIPS 203) combined with X25519
• Post-quantum ratchet: a new AES-256-GCM key for every message (HMAC-SHA3-256 chain), and a fresh ML-KEM-1024 exchange every 50 messages or 24 hours
• Every message signed with ML-DSA-65 (NIST FIPS 204) and Ed25519, so you can see it really came from your contact's device
• Encrypted attachments, replies, reactions and disappearing messages
• Archive and hide chats; hidden chats stay behind their own lock

📞 ENCRYPTED CALLS
• Private voice and video calls, encrypted end to end, including group calls of up to 3
• A new key for every call: ML-KEM-1024 + X25519, signed with ML-DSA-65 + Ed25519
• Every audio and video frame sealed with AES-256-GCM
• Safety numbers and one-tap call verification so you know who you are talking to
• Call history stays on your device

🗄️ QUANTUM VAULT
• Store photos, videos, documents and notes in an encrypted vault on your phone
• Files sealed with AES-256-GCM in 1 MiB chunks; only your vault PIN or password (stretched with Argon2id) unlocks their keys
• Every file signed with ML-DSA-87 and integrity-checked with SHA3-256, so tampering is detected
• Shared files are wrapped to the recipient with ML-KEM-1024
• Share a vault file with a contact without uploading it in the clear

🙈 HIDDEN VAULT
• Create hidden vaults that open only when you draw their secret pattern on the vault lock screen
• The app keeps no list of them: nothing on screen reveals that a hidden vault exists
• On disk, only AES-256-GCM noise with random names; keys come from your pattern (Argon2id) and the Android Keystore
• Optional duress pattern that erases your other hidden vaults
• Optional 12-word recovery phrase if you forget a pattern

🛡️ LOCKS AND DEVICE SECURITY
• Unlock with PIN, password or pattern; chats and vault each have their own lock
• Auto-lock when you leave the app or stop using it
• A live security dashboard that measures identity, handshake, session and runtime protection on your devices, instead of just claiming it
• Trusted-device management with approval for every new device

📡 QGUARD MESH: CHAT WITH NO SIGNAL
• Message trusted people nearby over Bluetooth and local Wi-Fi when there is no mobile signal or internet
• Sealed end to end with ML-KEM-768 + X25519 and AES-256-GCM, signed with ML-DSA-65 + Ed25519, even when relayed through other trusted devices
• Emergency messages stand out in the conversation

⚡ QGUARD XFER: OFFLINE FILE TRANSFER
• Send large files and whole folders directly to a trusted device, with no internet and no upload
• Same post-quantum session as Mesh; every file is verified with SHA3-256 when it arrives

💻 ONE ACCOUNT, ALL YOUR DEVICES
• Link phones, tablets and computers to one account
• Each device has its own keys; your data stays encrypted everywhere

HOW QGUARD PROTECTS YOU
• Encryption happens on your device. Our servers relay sealed envelopes they cannot read.
• We use NIST-standardised post-quantum algorithms (ML-KEM, ML-DSA) together with proven classical ones (X25519, Ed25519), so your data stays protected even if one of them is ever broken.

SUBSCRIPTION
Qguard Messaging requires a subscription. Every plan, starting with Starter, includes secure chat, encrypted calls, the Quantum Vault, Hidden Vault, Qguard Mesh and XFER. Higher plans add Qguard Helix platform features. Subscriptions are billed through Google Play and renew automatically until cancelled; you can cancel any time in Google Play, and access continues until the end of the paid period.

Questions or feedback? Contact us from Settings → About in the app.

*(3,960 characters, under the 4,000 limit)*

---

## Release notes ("What's new", max 500)

• Qguard Mesh: chat with trusted people nearby over Bluetooth and Wi-Fi with no internet
• Qguard XFER: send large files and folders device-to-device, verified file by file
• Hidden vaults with duress erase and 12-word recovery phrase
• Chat controls: mute, report, share contact, notification settings
• New onboarding and refreshed Android design
• Subscriptions now through Google Play

## Tags / keywords to target

encrypted messenger, private chat, post-quantum, quantum-safe, secure messaging, encrypted vault, hidden vault, offline messaging, mesh chat, bluetooth chat, offline file transfer, end-to-end encryption

---

## Check before you publish

- **Screenshots use sample content.** Names, messages and files are fictional; the screens themselves are the real app components. That is normal practice, but don't present the demo names as real users anywhere else.
- **Posture shown is an example.** The dashboard's "100% · Fully protected" is what the app computes for a fully enrolled 3-device account. A new user sees a lower score until their devices finish enrolling.
- **Claims kept deliberately careful.** The copy never says "unbreakable", "FIPS validated" or "quantum-proof"; keep it that way. "Designed to resist" and "built to resist" are the honest wording for post-quantum protection.
- **Contact line.** Add your real support email and privacy policy URL in Play Console (both required). The description points users to Settings → About; confirm that is where contact details live, or replace that line.
- **Data safety form.** It must match what the app sends: account email/phone, device keys, encrypted envelopes, subscription status. Declare encryption in transit; don't declare "data not collected".
- **Mesh/XFER permissions.** Play will ask why the app needs Bluetooth and nearby-device permissions. Point to the Mesh/XFER screenshots (07–09).
