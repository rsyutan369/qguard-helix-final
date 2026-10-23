# Groups, Group Calls, Screen Share and Channels — Design

**Date:** 2026-10-19 (updated 2026-10-20) · **Roadmap:** Phase 7 · **Status:** 7.0–7.4 built (owner decisions 2026-10-20, §7); group calls, channels and groups are not yet live-tested between devices

---

## 1. 7.0 What existed before this change (verified in code)

- **Schema:** `messaging_conversations.conversation_type` has allowed `'group'` since migration 001. Member rows are per device (`conversation_id, user_id, device_id`).
- **RLS:** people who share a conversation can read each other's devices, signed prekeys (migrations 018 and 034) and profiles (028). The send path already seals to every member device (`member_user_ids` → `selectDeliveryDevicesForUsers`).
- **No UI:** nothing created a group. `activeContact`, the thread title and "start a chat with X" all assumed one other person. "Start a chat with X" reopened **any** conversation containing X, so it would have opened a group.
- **Hole found:** two permissive RLS policies from migration 001 (`messaging_members_insert_self`, `messaging_members_update_self`) let **any account that knows a conversation's id add itself**, and let a revoked member clear its own `revoked_at`. Senders seal to every active member, so that is a silent extra recipient. Only past participants know a direct chat's id, which limited the damage; for groups it would make removal meaningless. Fixed by migration 040 (§2.4).

## 2. 7.1 Group messaging

### 2.1 Protocol choice: pairwise fan-out, not MLS (yet)

| Option | For | Against |
| --- | --- | --- |
| **MLS (RFC 9420)** | O(log n) member changes, one encryption per message, a standard. | Every RFC 9420 ciphersuite is classical (X25519/P-256 with Ed25519/ECDSA). The post-quantum ciphersuites (ML-KEM / X-Wing hybrids) are still IETF drafts, so they are not stable and not in a released library we could audit. A classical MLS group would be **weaker than this app's direct chats**, which are hybrid X25519 + ML-KEM-1024 with Ed25519 + ML-DSA-65 signatures. It also means a second state machine (the tree) to keep consistent across devices, which is more than this release can take. |
| **Pairwise fan-out (chosen)** | Reuses the reviewed path: every message is sealed separately to each member device with the same hybrid KEM, dual signatures, device pins and (opt-in) PQ ratchet as a direct chat. There is no shared group key, so removing someone needs **no re-keying**: their devices just stop being delivery targets. | Cost grows with members × devices, so groups are capped at 32 people (`GROUP_MAX_OTHER_MEMBERS = 31`). Senders do the work per message. |

**When to revisit:** once an MLS ciphersuite with ML-KEM (FIPS 203) and ML-DSA (FIPS 204), or a hybrid of them, is published as an RFC and is in an audited library. At that point groups above about 32 people, and channels (§5), are the reason to move.

### 2.2 What the server learns

It learns that a conversation of type `group` exists, who owns it, which users and devices are members, and the usual per-envelope metadata (sizes, times, sender and recipient devices). It does **not** learn the group's name. The name travels as an end-to-end-encrypted `group_meta` control message (`{type:"group_meta", target_client_message_id:<conversation id>, name}`), and `encrypted_title` stays `{version:1}` with no hint. As with all decrypted content, the name is kept in memory only (`group-chat.ts`) and is wiped with the plaintext caches (`clearChatPlaintextCaches`, `ensureChatCacheOwner`).

### 2.3 Behaviour

- **Create:** a name plus at least two of your contacts (at most 31). Every member needs at least one device that passes the same delivery gates as a direct chat (published prekeys, not awaiting your approval). Otherwise creation is refused and names who is unreachable.
- **Name:** accepted from an authenticated envelope, or from your own. The newest wins, so history replayed out of order cannot roll it back. Any member can send one; there is no rename UI in this version, and the owner-only rename question is open (§6).
- **Add (owner):** adds a contact's devices, then re-sends the name. Earlier messages were sealed before the new member joined, so they cannot read the original name message, nor any earlier history.
- **Remove (owner) and leave (anyone but the owner):** revoke membership rows server-side. From then on senders stop sealing to those devices. Anything already delivered stays readable to the person who left or was removed.
- **Bubbles** show the sender's name: the contact name, else their profile name (readable by co-members per migration 028), else "Group member".
- **Verify** lists every member's devices, each labelled with its owner.
- **Calls** stay one-to-one; the call button is disabled in groups (§3).

### 2.4 Migration 040 — membership is granted, never taken

- **INSERT:**
  - The owner may add rows for itself, or for users it has as `'added'` contacts.
  - An active member may add a row for another of its **own** devices.
  - Every row's device must belong to that row's user (`messaging_device_belongs_to`).
  - Device rebinding after a re-key stays in migration 033's SECURITY DEFINER function, which only follows **active** membership for groups.
- **UPDATE:** owner only, with the same device check. Members can no longer edit their own rows: no self-promotion, no un-revoking.
- **`leave_messaging_conversation(conversation)`** and **`remove_messaging_conversation_member(conversation, user)`:** SECURITY DEFINER, groups only. They only ever set `revoked_at`. The owner cannot leave or remove itself.

Verified on Postgres 16 (22/22). The baseline shows a stranger **could** self-join before 040. After 040 the following hold:

- Owner, contact and own-second-device inserts work.
- Non-contacts, devices enrolled under the wrong user, member-added strangers, self-promotion, stranger self-join, and stranger leave and remove are all refused.
- Remove revokes 1 row and leave revokes 2 (both devices).
- The owner cannot leave or remove itself, and remove does not apply to direct chats.
- A removed member cannot un-revoke or re-add itself.

**Deploy note:** the client already only inserts member rows the new policies allow (it adds people only after adding them as contacts), so 040 can be applied before or after the app update.

### 2.5 Known limits (also in `security-limitations.md`)

- Existing members learn of a membership change on their next data refresh (the realtime subscription is per user), so a message sent in that window can still go to a just-removed member, or miss a just-added one.
- The owner is the only admin. There is no ownership transfer, and if the owner deletes their account the group cannot be managed.
- The server sees the member list (§2.2). Hiding it needs sealed sender and private membership (roadmap 6.1).

## 3. 7.2 Group calls — design only

**Why it isn't built yet:** the call engine (`use-secure-call.ts`) holds **one** `RTCPeerConnection` with **one** per-device hybrid-KEM setup and one frame key. Group calls change its core assumptions.

**Plan (mesh, up to 4 people):**

1. One `RTCPeerConnection` per remote participant device, each with its own existing `CallSetup` (hybrid KEM to that device, its own frame key), so the per-pair crypto stays exactly the reviewed 1:1 code.
2. Signalling gains a `group_call_id` and a roster message. Each pair runs the existing offer/answer and ICE flow.
3. The UI becomes a tile grid. Call phrases are per pair, so the phrase panel picks a participant.
4. Cap at 4: mesh upload is (n−1) × video bitrate.

Beyond 4 needs an SFU. With end-to-end encryption that means SFrame-style keys shared across the group, which brings back the group key management question in §2.1.

**Acceptance:** two-machine and three-machine live tests (not possible in this environment), plus a frame-crypto negative test that a participant's key cannot decrypt another pair's frames.

## 4. 7.3 Screen share (shipped for 1:1 calls on desktop)

- **How it works:** the captured screen track **replaces** the camera track on the existing video sender (`RTCRtpSender.replaceTrack`).
  - It keeps the sender's per-frame AES-256-GCM transform (worker or `createEncodedStreams`) and the codec pinned to VP8. The frame-crypto header offsets in `call-frame-crypto.ts` are VP8's and stay valid.
  - Nothing is renegotiated, and no frame is sent unencrypted.
- **Codec coverage:** unchanged. The screen frames go through the same VP8 encoder as the camera, so no other codec has to be supported. If VP8 pinning ever fails, the 1:1 call already has that exposure; screen share adds no new one.
- **Platforms:**
  - Offered only where `navigator.mediaDevices.getDisplayMedia` exists (`screen-share.ts`): WebView2, WebKitGTK and WKWebView.
  - Android's WebView has no `getDisplayMedia`, so the button is hidden there. Android screen capture needs `MediaProjection` plus a foreground service, a separate piece of work.
- **Settings and states:**
  - Video only: system audio is never captured. 15 fps ideal, with `contentHint = "detail"` so text stays sharp.
  - The platform's own "Stop sharing" ends the track and the camera comes back.
  - A call that started audio-only has no video sender, and the user is told so.
  - Hang-up stops the capture.
- **Not verified here:** an actual share between two machines. No live call environment is available.

## 5. 7.4 Channels / broadcast — design only

- **Why it isn't built:** a channel is one sender to many readers, potentially thousands. Pairwise fan-out (§2.1) costs a sealed copy per reader device per post, which does not scale past a group.
- **Options:**
  - **(a)** a per-channel content key, rotated whenever a reader leaves and distributed pairwise. Posts are encrypted once. This is sender-keys style: cheap per post, expensive on churn, and with weaker forward secrecy.
  - **(b)** MLS once PQ ciphersuites are standard (§2.1).
- **Recommendation:** wait for (b). Option (a) would add a third key-management scheme, and its PQ properties would depend on the pairwise distribution alone. **Owner decision needed** on whether channels are wanted before MLS.

## 6. Open questions for the owner (answered 2026-10-20 — see §7)

1. Should renaming be owner-only? Today any member's `group_meta` is accepted.
2. Ownership transfer and multiple admins (the schema has `role = 'admin'`; it is unused).
3. Channels before MLS (§5)?
4. Should group calls (§3) start with mesh up to 4?

---

## 7. Owner decisions of 2026-10-20 and what was built

### 7.1 Admins, ownership transfer, owner-only names (migration 042; Postgres 32/32)

- **Roles:** the owner and up to **3 admins**.
  - Admins add their own contacts and remove plain members.
  - Only the owner renames, appoints or dismisses admins, and hands the group on (`set_messaging_group_admin`, `transfer_messaging_group_ownership`).
  - The previous owner stays as an admin when there is room.
- **Roles can no longer be written by clients.** A trigger derives each inserted row's role from the conversation and freezes it on update, except inside those functions. This closed a path in migration 040 where a member adding their own second device could label it `admin`. `owner_user_id` changes only through the transfer function.
- **Owner-only names:**
  - `messaging_conversation_owner_history` records every owner with from/until times, readable by members only.
  - A `group_meta` name counts **only if its sender owned the group when it was sent** (`group-chat.ts`, `ownerAt`). A transfer therefore cannot be used to rewrite the past, and a former owner cannot rename afterwards.
  - Until the history loads, only the current owner's names count.
- **Late joiners:** a member added after the name was sent cannot read that message. Their client sends `group_meta_request` to the owner's devices once per session, and the owner's client answers that device. Replays older than 24 hours are ignored.

### 7.2 Group calls, up to 3 people (built; not live-tested)

- **Mesh:** each pair is an ordinary one-to-one link with its own hybrid KEM, media key and frame transform. Nothing is shared across links.
- **Signal hub** (`call-signal-hub.ts`): one subscription that routes every signal to exactly one engine — by call id, by group invite on first contact, otherwise to the primary (1:1) engine. One-to-one calls are unchanged. Two engines on separate subscriptions would answer each other's rings with "busy".
- **Admission** (`admitGroupRing`): a group link rings only if the invite names me and the caller, in the same conversation. Once I have accepted a group call, further links of that same call are accepted without ringing. A different group call, or a link whose invite would add people, is refused.
- **Pairing** (`meshTargets`): the inviter rings everyone. Each joiner rings the members whose id sorts after theirs, so every pair is linked once.
- **Limits:**
  - If one person joins after the other's ring has timed out (45 s), that pair is not linked.
  - The four-word call phrase is per link and is not shown in the group view yet.
  - Screen share is for 1:1 calls only.

### 7.3 Channels (built before MLS; migration 043, Postgres 31/31; Rust 8 tests)

- **Crypto** (`commands/channels.rs`):
  - Each channel has epoch keys: random 32 bytes held in the core's encrypted storage.
  - Each post uses its own key, HKDF-SHA3-256(epoch key, salt = post id), with AES-256-GCM. The AAD binds channel, epoch, post and sender.
  - Each post is signed with Ed25519 + ML-DSA-65 by the posting device and verified against the sender's **registered** identity and device pin. A key-changed device is refused.
- **Key hand-out:** staff (owner and admins) seal the current epoch key to each reader device inside an ordinary pairwise envelope (hybrid X25519 + ML-KEM-1024).
  - A reader takes keys only from staff, and a held key can never be replaced.
  - When anyone who held the current key has left, the next staff action starts a new epoch and hands it only to current members.
- **Server:**
  - Posts are ciphertext. Only staff may insert; staff or the poster may delete.
  - In a channel, every envelope must be to or from staff, so readers cannot broadcast to each other.
  - Readers see only themselves and staff in the member list.
  - Invites: 128-bit codes; only their SHA3-256 hash is stored; validity 1 hour to 30 days, with a use count; revocable. A fresh invite readmits someone removed earlier. At most 1,000 readers.
- **Limits:**
  - Forward secrecy is per epoch, not per post.
  - A new reader receives the current epoch only, so earlier posts are not readable.
  - A staff member's second device makes its own epoch rather than receiving one.
  - A channel name set before anyone joins is held only in memory until a reader exists to send it to.

---

## 8. Contacts on Android, names that stay, and 1,000 members (owner request 2026-10-22)

### 8.1 What was wrong (verified in code)

- **Names:** a group's or channel's name exists only end-to-end encrypted (§2.2), and the decrypted name was kept in memory only. After every app start the list fell back to its member names, and a channel, whose reader sees only the staff, or which nobody has joined, fell back to the generic `Encrypted channel conversation`. A channel's own owner lost the name on restart, because with no readers it had never been sent anywhere.
- **Contacts on phones:** the Contacts panel is the desktop's right-hand column, which the phone layout hides. A phone could add a contact only through *New chat*, and could not see, block or delete one.
- **Block did nothing on the server.** `trust_state = 'blocked'` was a label; no policy read it, so a blocked person's messages and calls still arrived.
- **Limits:** the 32-person group cap lived only in the client; the 1,000-reader channel cap only in `join_messaging_channel`, so adding contacts directly was never counted.

### 8.2 Names (both platforms)

- `commands/conversation_names.rs`: the names this device accepted, each as received (name, time, sender), in the core's encrypted per-user storage (AAD `QGuard-ConversationNames-v1`). At most 8 per conversation and 5,000 conversations. `group-chat.ts` reads them back on start and after an unlock, and still applies the owner check (§7.1) on every read, so a stored name cannot outlive an ownership change. Leaving or deleting a conversation forgets its names.
- The owner's **channel key hand-out carries the name** (`channel_key.name`), so a new member of a channel or large group learns it with the key; it counts only if the sender owned the conversation then.
- **Background lookup:** for each unnamed group or channel in the list, the client opens only the `group_meta` and `channel_key` envelopes addressed to this device (once per session), without opening the thread.
- **Fallback titles** say what the conversation is (`Channel`, `Group · 4 people`, `Large group · 120 people`) or list member names; never `Encrypted … conversation`.

### 8.3 Contacts, Restrict and Block (migration 047)

- **Phone:** a *Contacts* folder next to *Chats* lists every contact with its state; a tap opens *Chat*, *Restrict / Lift restriction*, *Block / Unblock* and *Delete contact*. *Add a contact* searches the directory as the desktop does, and shows your QGuard ID to share. Desktop gains *Restrict*.
- **Restrict** (new state): they can still message you, but cannot call you or add you to a group or channel.
- **Block:** the relay drops their envelopes and call signals to you without telling them (a `BEFORE INSERT` trigger returns no row, so the sender's batch still succeeds); they cannot add you to conversations; the app hides their posts in shared timelines and will not send to them.
- `qguard_contact_state` is not granted to clients: whether someone blocked you is theirs to know.

### 8.4 Large groups and member limits (migration 047)

- **Why not just raise the group cap:** a group seals every message once per member device (§2.1). At 1,000 people with ~1.5 devices each, one message is ~1,500 hybrid encapsulations and ML-DSA-65 signatures and an upload of roughly 10–20 MB. That does not work on a phone.
- **Large group** = a channel whose members all post (`member_posting = true`, fixed at creation). It reuses the reviewed channel crypto (§7.3): one encryption per post under the epoch key, signed by the posting device and verified against its registered identity. Members see each other, as in a group. Keys are still handed out and rotated only by the owner's and admins' devices.
- **Limits are data:** `messaging_conversation_limits` holds `group = 32`, `large_group = 1000`, `channel = 1000`. A statement-level trigger locks each conversation that gained a person and refuses a statement that would pass its limit, on every path (owner or admin adds, reinstating a revoked row, joining with a code). Role changes and removals are never refused, even when a lowered limit leaves a conversation over it. Invites accept up to 100,000 uses.
- **Client reads at this size:** member rows, devices and prekeys are read page by page (the relay returns at most 1,000 rows per request, so a large group would otherwise silently drop rows, including this account's own memberships in other conversations); `.in()` filters go in chunks of 150 ids; a rename or name fan-out goes in batches of 50 devices.

Verification: Postgres 16, migrations 001–047 applied in order, 047 re-applied (idempotent), **62/62** checks: restricted and blocked contacts (messages, calls, the sender's own copy, one-way blocking), consent to be added (insert and reinstate), limits (under, over, one statement over, nothing left behind, roles and removal while over a lowered limit, raising by data, the 100,000 bound), large groups (members post, readers of a channel cannot, non-members cannot, members see each other, channel readers still do not, `member_posting` frozen), invites to 5,000 and joining against the limit. A baseline without 047 shows the defect: the blocked message and call are stored, five people are added to a group with no count, and someone who blocked the owner is added. Rust: 4 tests (`conversation_names`). Vitest: 510/510.

### 8.5 To go from 1,000 to 10,000 and 100,000

Raising a row in `messaging_conversation_limits` is enough for the server. These are what would then become the bottleneck, in the order they bite:

1. **Key rotation cost.** Each epoch is sealed pairwise to every member device: about 1,500 seals at 1,000 members, 15,000 at 10,000. Rotation is lazy (the next staff action after someone leaves), which holds at 1,000. Past that, either batch rotations (at most one per interval) or move to MLS once a post-quantum ciphersuite is an RFC (§2.1), where a member change costs O(log n).
2. **Member list loading.** The dashboard reads every visible member row. At 10,000 that has to become paged on demand (count from the server, names fetched as the list scrolls), and the members panel already shows 200 at a time with search.
3. **Device and prekey reads** for key hand-out: chunked already; at 10,000 they should come from a server-side RPC that returns only devices missing the current epoch.
4. **Realtime fan-out** of post inserts to every subscriber is Supabase Realtime's limit, not ours; at 100,000 posts should be fetched on notification rather than pushed with the row.

### 8.6 Not verified here

- No two-device run: names arriving with a key hand-out, Block between two real accounts, and a 1,000-member group were exercised in Postgres and unit tests only.
- Migration 047 is **not applied to the live project**. Until it is, Restrict and Block are shown but not enforced, large groups cannot be created (the app says so), and the old limits apply.
