# Quantum Vault Storage

**Spec:** `Qguard_Wiki/Quantum Vault` · **Phases delivered:** 1 — local encrypted storage (desktop + Android); 2 — opt-in encrypted cloud backup and restore (§8); 3 — one library across the account's devices (§9); 4 — secure sharing between users (§10) · **Updated:** 2026-11-03

Quantum Vault Storage is the managed, on-device encrypted file library behind
the *Quantum Vault* page. It reuses the existing vault cryptography unchanged
and adds a file manager plus metadata protection around it. Phase 2 adds an
optional backup of the encrypted containers to Supabase, quota-checked by the
database, restorable on a new device with the recovery key alone. Phase 3
makes that backup one library shared by all of the account's approved
devices; phase 4 shares single files with other QGuard users through
recipient-specific envelopes, without copying the file.

## 1. Repository audit (before this change)

| Area | What existed | Reused? |
| --- | --- | --- |
| `src-tauri/src/vault_stream.rs` | Streaming v5 container: AES-256-GCM per 1 MiB chunk (AAD binds file id, index, count, last flag), per-file key (FEK) sealed under the PIN-bound vault key, optional recovery wrap, enterprise ML-KEM-1024 wrap, X25519 + ML-KEM-1024 recipient wraps, Ed25519 + ML-DSA-87 header signature, full legacy v1–v4 read path | Yes — the only file crypto path; untouched |
| `state.rs` `PersistedVaultMaster::vault_key` | PIN-bound vault key (HKDF-SHA3-256 over VMK + vault signing secrets); exists only while unlocked | Yes — root of the new index/thumbnail keys |
| `commands/vault.rs` | Encrypt/decrypt a chosen file or folder to a chosen destination; recovery, enterprise, verify, re-protect; Android SAF sources/destinations | Yes — `local_vault_context`, `VaultDest`, `open_vault_source`, `run_stream_blocking`, `sanitize_dest_name`, `unique_in_dir` |
| `commands/vault_identity.rs` | Portable Hybrid Identity sharing (seal a container to a recipient) | Unchanged; still under *Tools* |
| `crypto/vault_recovery.rs` | Account recovery key → recovery wrap key | Yes — recovery copy of the index |
| `QuantumVaultPage.tsx` | Encrypt-anywhere UI; registry of containers kept in **browser localStorage** (names, paths in plaintext) | Kept as *Encrypt & Decrypt Tools*; Storage does not use localStorage for any vault state |
| Supabase `messaging_vault_files` / `messaging_file_grants` | Retired cloud vault tables (migration 001); no longer read or written by the app | Not used. Phase 2 must decide between reviving them and new tables — see §7 |

Gap the audit found: there was no vault *storage* — files lived wherever the
user saved a `.qvault`, the file list was a localStorage registry that exposed
names to anything that can read the WebView profile, and container headers
carried the original file name in plaintext.

## 2. Architecture

```
React (src/components/vault/storage/*, src/lib/vault-store.ts)
   │  Tauri commands only — no key, no plaintext name is stored in JS
   ▼
commands/vault_store.rs   ── session = unlocked vault context + layout + derived keys
   │
   ├─ vault/store.rs      sealed index, thumbnails, layout, tree rules, shredding
   ├─ vault/sniff.rs      content-type detection from magic bytes
   └─ vault_stream.rs     (unchanged) v5 containers
```

On disk, per account, in the app's private data directory
(`<app data>/vault/store/<account>/`; Android: internal app storage):

| Path | Content | Key |
| --- | --- | --- |
| `objects/<uuid>.qvault` | v5 container. Header `name` is `vault-object`, `content_type` is `application/octet-stream` | per-file FEK (AES-256-GCM) |
| `index.qvs` | `QGVSIDX1 ‖ vault-id ‖ nonce ‖ tag ‖ AES-256-GCM(JSON index)` | `HKDF-SHA3-256(vault key, "QGuard-VaultStore-Index-v1")` |
| `index.recovery.qvs` | Same index, only when a personal recovery key is configured | `HKDF-SHA3-256(recovery wrap key, "QGuard-VaultStore-RecoveryIndex-v1")` |
| `thumbs/<uuid>.qvt` | `QGVSTHB1 ‖ nonce ‖ tag ‖ AES-256-GCM(JPEG)` | `HKDF-SHA3-256(vault key, "QGuard-VaultStore-Thumbnail-v1")` |
| `staging/` | In-flight imports (ciphertext only), cleared on the next import | — |

### Key separation

| Key | Protects | Derived from |
| --- | --- | --- |
| FEK (random, per file) | One file's content | OS CSPRNG |
| PIN-bound vault key | Every FEK (owner wrap) | VMK + vault signing secrets; exists only while unlocked |
| Index key | Names, folders, types, hashes, activity | vault key, distinct HKDF label |
| Thumbnail key | Thumbnails | vault key, distinct HKDF label |
| Recovery wrap key | Recovery wrap of every FEK; recovery copy of index (distinct HKDF label) | Account recovery key |
| Enterprise ML-KEM-1024 key | Enterprise wrap of every FEK (when configured) | Organisation |
| Recipient X25519 + ML-KEM-1024 | Recipient wrap of one FEK (sharing, *Tools*) | Recipient identity |
| Device identity (X25519/ML-KEM-1024/Ed25519/ML-DSA-65) | Messaging only — **not** on the storage path | Device |

The vault engine shares only audited primitives (`crypto::symmetric`,
`crypto::kdf`, `crypto::signatures`, `crypto::hybrid_kex`) with Secure Chat; no
chat key protects vault data and no vault key protects chat data.

AAD bindings: the index is bound to `QGVSIDX1|<user id>|<vault id>`, a thumbnail
to `QGVS-Thumb-v1|<user id>|<entry id>`. A file moved between accounts or entries
does not open.

### Write ordering and crash safety

Import: plaintext → SHA3-256 + `encrypt_stream` → `staging/<rand>.part` →
`fsync` → *(store lock)* load index → validate parent / duplicate → rename into
`objects/` → seal index (`write_atomic`: temp + fsync + rename). A crash leaves
nothing, a staging file, or an **unlisted object** (reported in Security) —
never an index entry without its container. If sealing the index fails, the
just-stored object is shredded.

Permanent delete: index first (entries removed), then each container's
`12 + header_len` bytes are overwritten with random data, `fsync`, unlink.
The header holds the only wrapped copies of the FEK, so the file is
crypto-shredded even if chunk blocks survive on flash. Thumbnails are deleted.

### Integrity

Every open (preview, export, verify) checks: the header's Ed25519 + ML-DSA-87
signature; that the FEK unwraps under **this** vault's key (a container from any
other vault is refused); every chunk's GCM tag and position; the chunk count;
and finally that the plaintext SHA3-256 and length equal what was recorded at
import. Results are persisted as `verified` / `failed` / `missing`. A missing
container is reported from the disk on every listing.

### Previews

Images, audio, video (≤ 64 MiB) and text are decrypted into memory, fully
authenticated before a byte is returned (`tauri::ipc::Response`), shown from an
object URL that is revoked when the viewer closes. Nothing is written to disk.
PDFs, Office files and archives are export-only: the app's CSP allows no framed
documents, the Android WebView has no PDF renderer, and no plaintext is ever sent
to an external preview service.

### Content types

`vault/sniff.rs` classifies from the first 512 bytes (JPEG, PNG, GIF, WebP,
HEIC/AVIF, PDF, OLE2 Office, OOXML/ODF (ZIP), MP4/MOV/M4A, AVI, WAV, MKV/WebM,
MP3, AAC, FLAC, Ogg, 7z, RAR, gzip, UTF-8 text/CSV/JSON). The extension is only
used to narrow a ZIP and to flag a **mismatch** (shown on the file). Unknown
content is `application/octet-stream` / *Other*, never guessed from the name.
Classification is not malware scanning, and the UI says so.

## 3. Commands

| Command | Unlock | Notes |
| --- | --- | --- |
| `vault_store_status` | Open | All overview figures; `state: foreign` after a vault reset |
| `vault_store_list`, `vault_store_activity` | Open | Listing marks missing containers live |
| `vault_store_import` | Seal | Path or Android SAF URI; progress channel; duplicate skip by content hash per folder |
| `vault_store_import_folder` | Seal | Desktop; recreates the tree; per-file failures reported |
| `vault_store_create_folder`, `_rename`, `_move`, `_set_favorite` | Seal | Names cleaned (no separators/control chars, ≤ 200 chars), unique per folder; no move into self |
| `vault_store_trash`, `_restore` | Seal | Trash cascades to folder contents; restore falls back to top level |
| `vault_store_purge`, `_empty_trash` | Seal | Trash only; crypto-shred |
| `vault_store_verify`, `_verify_all` | Open | Full decrypt to a hashing sink |
| `vault_store_preview` | Open | ≤ 64 MiB, previewable types, rate-limited |
| `vault_store_export`, `_export_folder` | Open | Desktop save dialog / Android SAF; `.qguard-part` + rename; rate-limited |
| `vault_store_set_thumbnail`, `_thumbnail` | Open | JPEG/PNG/WebP ≤ 256 KiB, photos/videos only |
| `vault_store_start_fresh` | Seal | Only for a foreign index; moves the old library aside unchanged |
| `vault_store_disk_usage` | Sign-in | Object count + ciphertext bytes for dashboards |
| `vault_store_path_kind` | Sign-in | Routes a desktop drop to file or folder import |

*Seal* contexts load the recovery configuration (so new containers get their
recovery wraps and the recovery index is refreshed); *Open* contexts do not.
Every command fails while the vault is locked. Audit entries go to the local
audit chain; nothing about names leaves the sealed index.

## 4. Verification

| Feature | Implementation | Tests | Status |
| --- | --- | --- | --- |
| Local encrypted storage | `vault/store.rs`, `commands/vault_store.rs` | Rust: round trip (2-chunk file), name/type absent from object and index bytes, locked vault refuses | Completed (tests on Windows; core compiles for `aarch64-linux-android`) |
| AES-256-GCM (content) | `vault_stream` (unchanged) | Rust: tampered chunk → `failed` recorded; existing `vault_stream` suite | Completed |
| ML-KEM-1024 | Recovery / enterprise / recipient wraps (unchanged); not on the owner path of a v5 container (PIN-bound key instead) | Existing `vault_stream` / `vault_identity` suites | Completed (unchanged) |
| ML-DSA-87 header signature | `vault_stream` (unchanged) | Rust: container from another vault refused | Completed |
| Sealed metadata index | `store::save_index_at` / `load_index_at` | Rust: wrong AAD, wrong vault key (reported as *foreign*), flipped byte all refused | Completed |
| Recovery after device / PIN loss | Recovery wraps + `index.recovery.qvs` | Rust: with only the recovery key, names and content recovered; wrong key opens neither | Completed (crypto path); **no restore UI yet** — see §6 |
| Thumbnails | `EntryVisual.tsx` + `store::seal_thumbnail` | Rust: sealed, entry-bound, images only | Completed; on-device visual check pending |
| Integrity verification | `decrypt_into` + SHA3-256 | Rust: tamper → failed, delete → missing, status counts | Completed |
| Secure delete | `store::shred_container` | Rust: header overwritten and removed; purge refused outside Trash | Completed |
| Content-type detection | `vault/sniff.rs` | Rust: 19 formats, disguised PNG/EXE, OOXML only when ZIP | Completed |
| Tree rules (unique names, move, trash, restore) | `StoreIndex` | Rust + Vitest | Completed |
| Frontend | `components/vault/storage/*`, `lib/vault-store.ts` | Vitest (tree/sort/filter/preview/errors); `tsc` clean | Completed; interactive run pending |
| Cloud backup (opt-in) | §8: migration 048, `commands/vault_cloud.rs`, `lib/vault-cloud.ts`, `CloudBackupPanel.tsx` | Rust end-to-end with an in-memory server (6); Vitest sync engine (7); SQL checks on Postgres 16 with Supabase's default grants (13 groups); live project: schema, function bodies and per-role privileges verified, anonymous API calls refused | Migration 048 **applied to the live project 2026-11-02**; no signed-in upload/restore against it yet |
| Restore on a new device | Recovery index + `rewrap_stream_with_recovery` | Rust: new device, new vault key, only the recovery key → every file and folder back, verified | Completed (tests); live run pending |
| Subscription storage quotas | `qv_plan_quotas` + `qv_begin_upload` (database) | SQL: Basic/Pro quotas, reservation counting, no entitlement for none/expired/Starter | Completed (tests) |
| Multi-device library (phase 3) | §9: `vault/library.rs`, `commands/vault_library.rs`, migration 049, `lib/vault-library.ts` | Rust: 8 library unit tests + 4 two-device end-to-end tests; Vitest: 6 key-sync + 3 publish/merge tests; SQL: CAS publish, recovery-copy election, owner-only keys | Completed in code; **migration 049 not yet applied to the live project**; not yet run on real devices |
| Device enrollment / revocation | Device Trust Center approval → library key wrap; removal → new epoch | Rust: unapproved device refused, removed device locked out of new data; Vitest: wraps only to approved devices, rotation | Completed in code; live run pending |
| Secure sharing (phase 4) | §10: `commands/vault_share.rs`, migration 049, `lib/vault-share.ts`, `Sharing.tsx` | Rust: 4 tests (preview/save, third party refused, every signed field tamper-checked, swapped file caught, view-only, expiry); Vitest: 4; SQL: invitations, accept/decline, expiry, revocation, block rules, cascade | Completed in code; **migration 049 not yet applied**; live run pending |
| Pattern unlock | §11: `vault/pattern.rs`, `commands/workspace.rs` (`pattern` credential, `vault_pattern_unlock`), `PatternPad.tsx` / `PatternCapture.tsx` | Rust: canonical-form and no-jump rules, pattern unwraps the vault master and no other does, held to the PIN rules (vault only, refused in approved mode); Vitest: same rules as the core, hit test, lock screen | Completed in code and at 360 px in a browser render; device run pending |
| Hidden vaults | §11: `vault/hidden.rs`, `commands/vault_hidden.rs`, `HiddenVaultPage.tsx`, `VaultLockCards.tsx` | Rust: 9 engine tests (covers, round trip, nothing readable on disk, opens only with pattern + device key + account, two vaults apart, delete leaves one index generation, tamper/truncation, destroy/erase) + session exclusivity | Completed in code and at 360 px in a browser render; device run pending |
| Device enrollment for the vault | — | — | **Pending (phase 3)** |
| Android | Same Rust core; SAF import/export reused | `cargo check --lib --target aarch64-linux-android`: clean | Compiles; **APK build and on-device run pending** (no test device on this machine) |
| Desktop interactive run | — | — | **Pending** — needs a signed-in session with the vault unlocked |

Results on 2026-11-02:

- Rust (`%LOCALAPPDATA%\qguard-build-shims\run-rust-tests.ps1 vault`): 98 passed,
  0 failed — 11 `commands::vault_store`, 6 `commands::vault_cloud`, 13
  `vault::store`, 5 `vault::sniff`, the new `vault_stream` recovery-rewrap test,
  plus the existing `vault_stream` / `vault_identity` / `vault` suites unchanged.
  No compiler warnings.
- Database (phase 2): migration 048 applied twice on `postgres:16` with the
  Supabase stand-in, then all 13 check groups passed (`ALL 048 CHECKS PASSED`).
- Frontend: `npx tsc --noEmit` clean; `npx vite build` succeeds; `npx vitest run`
  524 / 525 — the one failure (`ai-assistant.test.ts › consent and memory`) is in
  code this change does not touch and failed before it.

## 5. User-facing status vocabulary

Only shown when the core reports it: *Encrypted* (stored), *Integrity verified*
(an open or verify authenticated it, with time), *Not yet verified*,
*Integrity check failed*, *Encrypted object missing*, *Recoverable with your
recovery key* (container carries a recovery wrap), *In Trash*. *Cloud backup* is
shown as **not available yet** — never as on.

## 6. Known limitations

- **Without cloud backup, files exist only on this device.** Backup is opt-in
  and needs a plan with cloud storage and a personal recovery key.
- **Vault reset.** A reset makes the old library *foreign*. It is never
  modified; *Start fresh* sets it aside unchanged. If it was backed up, *Restore
  from backup* brings it back under the new vault key.
- **Files added before a recovery key existed** are re-protected automatically
  just before their first upload. Without cloud backup they stay without a
  recovery wrap (shown per file and in Security).
- **Previews** cover images, audio, video ≤ 64 MiB and text. HEIC and some
  codecs cannot be decoded by the WebView (no thumbnail; export works).
- **Folder import/export** is desktop-only (SAF gives no directory traversal for
  imports). Android imports multiple files and exports one file at a time.
- **Flash storage** may retain stale blocks; crypto-shredding the header is the
  mitigation, not a guarantee of physical erasure.
- **Plaintext in memory.** Previews and thumbnail generation hold plaintext in
  WebView memory while shown; exported copies are plaintext by design and the
  UI says so.

## 7. Not done / next

- The retired `messaging_vault_files` / `messaging_file_grants` tables
  (migration 001) are used by none of the phases and should be dropped in a
  later migration.
- Live runs on real devices and against the live project for phases 3 and 4.

## 8. Phase 2 — encrypted cloud backup

### What leaves the device

| Uploaded | Content | Readable by the server? |
| --- | --- | --- |
| Each file's v5 container | AES-256-GCM chunks; header with the FEK wrapped to the vault key **and the recovery key**; Ed25519 + ML-DSA-87 signature; name `vault-object`, type `application/octet-stream` | No: ciphertext and random ids only |
| The recovery index | Names, folders, types, hashes — sealed with AES-256-GCM under HKDF-SHA3-256(recovery wrap key, …) | No |
| Metadata rows | Object id, vault entry id (random UUID), sizes, per-part and whole-file SHA3-256 of the *ciphertext*, device id | Yes — nothing about content |

Nothing is uploaded unless the user turns backup on (*Security & Backup*); it is
off by default, and turning it on needs a personal recovery key (a backup that
only this device's vault key opens would die with the device). Files added
before recovery existed are re-protected — same FEK, new header with the
recovery wrap, verified before it replaces the local copy — immediately before
their first upload.

### Server (migration 048)

- `quantum-vault` bucket: private, 8 MiB file limit, `application/octet-stream`
  only. Parts live at `<user>/<object>/<00000…>`; no UPDATE policy, so a part
  can never be overwritten.
- `qv_cloud_objects`: one row per object, written only by SECURITY DEFINER
  functions; owners can read their rows, nothing else.
- `qv_begin_upload` takes a per-user advisory lock, checks entitlement and quota,
  and reserves. A storage part is accepted only inside an `uploading`
  reservation of the caller with an in-range part number. Idempotent by
  (kind, entry, container hash), so an interrupted upload resumes.
- `qv_commit_upload` commits only if storage holds exactly `part_count` parts
  whose sizes sum to the reserved size.
- `qv_begin_delete` / `qv_finish_delete`: space is released only once the parts
  are gone.
- `qv_plan_quotas`: Starter 0, Basic 2 GiB, Pro 10 GiB, Elite 100 GiB — rows,
  changed with an UPDATE; the app reads them for display only. Entitlement uses
  migration 030's rule (active / trial / pending renewal, 72 h grace). A lapsed
  plan blocks new uploads only; reading, restoring and deleting keep working and
  nothing is deleted.
- `qv_cloud_audit`: reserved / committed / delete started / delete finished,
  with sizes, readable by the owner (storage usage history).
- Privileges are revoked from `anon` and `authenticated` by name. Supabase
  grants new `public` tables and functions to those roles directly, so
  `REVOKE … FROM PUBLIC` alone leaves them in place — which would let any
  caller run the quota helpers for another user id, and `TRUNCATE` (which RLS
  does not cover) the tables. Signed-in users may SELECT their rows and call
  the five RPCs; the helpers are callable only from inside them; anon gets
  nothing. The test stand-in reproduces Supabase's default grants.

### Client

`vault_cloud_*` commands (Rust) decide what to back up, hand out parts whose
SHA3-256 they re-check at read time (a file that changed after preparation is
never uploaded under old hashes), and record committed object ids — and the
durable queue of cloud deletions — in the sealed index. `lib/vault-cloud.ts`
moves the bytes with the app's Supabase session. Sync runs automatically after
changes while the vault is open, on reconnect and every 10 minutes; the same
outstanding work is not retried more often than every 10 minutes, and a quota,
entitlement or session failure stops the run with a plain message instead of
retrying. *Synchronization complete* is shown only when no upload, deletion or
index copy is outstanding and the last run had no error.

Moving a file to Trash keeps its backup; deleting it permanently queues its
cloud copy for deletion. *Delete cloud backup* turns backup off and removes
everything in the cloud; local files are untouched.

### Restore

- **Missing file, same vault:** the container is downloaded part by part (each
  part's SHA3-256 checked before it is kept, then the whole file's), opened as
  this vault's own and checked against the recorded plaintext SHA3-256.
- **New device or after a vault reset:** *Restore from backup* asks for the
  recovery key, downloads the newest recovery index and opens it; each file is
  downloaded and checked as above, then re-bound to this device's vault with
  `vault_stream::rewrap_stream_with_recovery` (same FEK and chunks; new v5
  header sealed to this vault and the recovery key, signed with this vault's
  ML-DSA-87 key), then opened in full and checked before it is stored. Folders
  are recreated. Signing in never decrypts anything.

The only addition to `vault_stream.rs` is `rewrap_stream_with_recovery`, which
shares the existing re-protect code after the FEK has been recovered: no new
algorithm, and the container format is unchanged.

### Deploying

1. Apply `supabase/migrations/048_quantum_vault_cloud_backup.sql` to the
   messaging project (needs migration 030 and `billing_subscriptions`). It is
   idempotent. Rollback is described in its header.
2. Ship the app build containing this change. Until step 1 is done the Backup
   panel shows that the backup service is unavailable; nothing else is affected.

Check the migration on plain Postgres with `supabase/tests/048_bootstrap.sql`,
the migration, then `supabase/tests/048_quantum_vault_cloud_backup.test.sql`
(ends with `ALL 048 CHECKS PASSED`).

### Phase 2 limitations

- Migration 048 is live, but no signed-in upload or restore has been run against
  the real project yet, and nothing has run on an Android device.
- The server cannot compute SHA3, so it checks part counts and sizes; content
  integrity is checked by the device on every download (per part, whole file,
  container authentication, plaintext hash).
- A malicious server could withhold the newest recovery index and serve an
  older one (rollback); every file it serves still has to authenticate.
- Restored files keep the cloud copy made by the original device as their
  backup (it opens with the recovery key); they are not uploaded again.
- Personal recovery mode only; enterprise / hybrid recovery modes cannot enable
  backup yet.

## 9. Phase 3 — one library across the account's devices

**Model.** Every device keeps its own PIN-bound vault key and its own copy of
each file it holds. What the account's devices share is a **library key ring**
(`vault/library.rs`): a random 256-bit key per epoch, stored only inside each
device's sealed vault index — so it exists only while that vault is unlocked.
In the cloud there is one **library document** (`library_index` object) sealed
with AES-256-GCM under HKDF-SHA3-256(epoch key, document label): the folder
tree and shared metadata of every backed-up file, each file's key sealed under
HKDF-SHA3-256(epoch key, file-key label) bound to account, file and epoch, and
deletion records. The library never holds a vault key, a device key or the
recovery key.

**Getting the key.** A device gets the ring either
- sealed to it by another of the account's devices that it has pinned — i.e.
  approved in the Device Trust Center (hybrid X25519 + ML-KEM-1024 to its
  identity keys, Ed25519 + ML-DSA-65 signed; same rules as the account key,
  `qv_library_key_wraps`), or
- from the copy sealed under the account's recovery key (`qv_library_recovery`),
  automatically when that recovery key is set up on the device, or typed in via
  *Restore from backup*.
Signing in alone gives no access. The recovery copy is also the election: the
first device to store it starts the library; a device that started one at the
same moment is refused and adopts the winner (its file-key wraps are moved over).

**Sync.** Each run (`runCloudSync`): receive / start / rotate / hand out the
ring → merge the newest document if another device published one → upload new
files → publish this device's view as the next revision. Publishing is
compare-and-swap (`qv_publish_library`): a device that has not merged the
current revision is refused, merges, and retries — it never overwrites another
device. Merge rules: newest edit wins per entry for name / folder / trash /
favourite (file contents never change, so there is no content conflict);
a permanent delete wins over older edits and removes the file — and its
encrypted object — on every device; afterwards the tree is repaired (missing
or looping parents → top level, clashing names → " (n)"). Files from other
devices appear as **in the cloud only** and are downloaded, re-bound to this
vault with their library file key, opened in full and checked against the
recorded content hash the first time they are opened.

**Removing a device.** When a device that was handed the current epoch is
removed in the Device Trust Center, one remaining device starts a new epoch,
moves every file-key wrap to it and republishes; the removed device cannot open
anything published afterwards. It keeps what it already downloaded, and a
device that holds the recovery key can always re-open the library — replace the
recovery key after losing a device you do not control.

## 10. Phase 4 — secure sharing

One cloud object, however many recipients. For each recipient **device** the
sender's core seals the file key plus name / type / size / content hash with
hybrid X25519 + ML-KEM-1024 to that device's registered identity and signs,
with Ed25519 + ML-DSA-65, the share id, owner, both devices, the object, the
container hash, the permission and the expiry (`commands/vault_share.rs`). The
recipient verifies the sender's device identity (and its pin) and the
signature before opening, then checks every downloaded part, the whole
container hash the sender signed, and the plaintext hash.

Server (migration 049): `qv_shares`, `qv_share_recipients` (pending /
accepted / declined / revoked), `qv_share_envelopes`, `qv_share_events`.
Recipients who blocked or restricted the sender are left out silently, as with
messages. A recipient reads the object row and its parts only after accepting,
and only while the share is neither revoked nor expired and the object
committed. Revoking (one recipient or all) and declining delete the envelopes
from the relay; deleting the file deletes its shares. *Save to my vault*
re-seals the container as the recipient's own (new owner, recipient's vault key,
recipient's recovery wrap), verified before it is stored. The sender's app
tops up envelopes for recipients' newly added devices.

Stated in the app: revoking stops further downloads but cannot take back a
copy already saved or a file already opened; *view only* is enforced by the
app, not by cryptography; *opened* / *saved* in the access history are reported
by the recipient's app.

**Sharing without cloud backup.** Backup is optional and never a precondition.
A file with no cloud object gets one when it is shared:
`vault_cloud_prepare_share_copy` prepares that one container exactly as a
backup of it would be (recovery wrap first, part hashes), through the same
quota-checked upload (`uploadShareCopy`, which takes turns with backup runs so
the two never upload one file at once). With backup off, `complete_upload`
marks the entry `cloud_shared_only`: not counted as backed up
(`CloudState.shared_copies` instead), not in the library document other
devices restore from, and taken back by `vault_cloud_release_share_copy` once
no live share uses it — not revoked, not expired, someone still pending or
accepted (`releaseUnusedShareCopies`, on opening the vault and the *Shared by
me* list; a copy younger than 15 minutes is left alone while its share is
created). The core refuses to release anything else: a backup copy, a copy
backup was turned on over (which then *is* the backup), or the only copy of a
file no longer on the device. *Delete cloud backup* passes the objects live
shares use and keeps them as shared copies, so it never breaks a share.
Removing the object cascades its share rows (migration 049), so an ended share
leaves *Shared by me* when its copy is gone.

### Deploying phases 3–4

Apply `supabase/migrations/049_quantum_vault_library_and_sharing.sql` after 048
(needs 030, 044's `messaging_owns_device` is recreated, 047's
`qguard_contact_state`). Checked with `048_bootstrap.sql`, 048 + 049 applied
twice, then `048_…test.sql` and `049_…test.sql` (ends `ALL 049 CHECKS PASSED`).

## 11. Pattern unlock and hidden vaults

**Pattern unlock.** A third vault credential (`PersistedWorkspaceScope.pattern`)
beside password and PIN, sealed by the same code: the pattern's canonical text
`4x4:<dots>` → Argon2id (64 MiB, 3 passes) → HKDF-SHA3-256 verifier and wrap
key → AES-256-GCM wrap of the Vault Master Key, inside the scope record that is
itself sealed under the device storage key. 4 × 4 dots, at least 6, no stroke
over an unconnected dot (the pad picks such a dot up), checked again in the
core. Same attempt ladder (5 → 30 s, 10 → 5 min, 20 → lockdown). Like a PIN it
is refused in FIPS approved mode and never moved to PBKDF2.

**Hidden vaults** (`vault::hidden`). Goals and how each is met:

| Goal | How |
| --- | --- |
| The app never says a hidden vault exists | No list, count or setting names one. The lock screen offers the pattern pad to every vault user. `vault_pattern_unlock` always runs both checks side by side (the vault's own pattern if set, and the hidden derivation) so timing says nothing; no match is one wrong attempt. An open hidden vault is logged as the same `workspace_unlock` as any vault; its commands write nothing to the audit log, telemetry or the vault's activity. |
| The disk shows nothing useful | `<data>/vault/pool/<user>/`, one flat folder every account gets, created with a random 1–3 bands of 16 cover files (16 KiB × 2^(0..7), log-spread like real files). Every file is named by 32 random-looking hex characters and is pure AES-256-GCM output or random padding: no header, magic or extension. Sizes are rounded up (≥ 16 KiB, then to 1/32 of the next power of two). After every create, import, delete or destroy the file count is topped up to a multiple of 16 (covers are never removed: nothing records which files are covers). Every pool file's modified/accessed time — and on Windows its created time — is set to 2020-01-01 UTC. |
| Nothing opens without the pattern and this device | vault key = HKDF(pool salt, Argon2id(pool salt, pattern) ‖ pool key); pool key and salt are HKDF'd from the account's device storage key in the OS secure store (Android Keystore / Windows Credential Manager). A disk image alone cannot be used to test guesses. The one other way in is the vault's own 12-word recovery phrase, if its owner set one up (§14). |
| Files stay authentic | Per-file random key held only in the encrypted index; 1 MiB chunks, each AAD binding file id, position and "last" (no reordering, splicing or truncation); SHA3-256 of the plaintext checked at the end. |
| Deleted means gone | The key leaves the index first (a new index generation is written, the previous one overwritten and deleted — two names alternate, so only one generation exists); then the content is overwritten (up to 64 MiB) and deleted. *Delete this hidden vault* and *Erase all hidden vaults* (no pattern needed: it only destroys) do the same for everything. |
| No back door | No escrow, cloud copy, library or sharing; the only recovery is the owner's own phrase (§14), which QGuard never sees or stores. The Quantum Vault locks while a hidden vault is open and the reverse; every lock path closes both. |
| No pattern oracle | A hidden vault can only be created from the unlocked vault, and every creation counts as an attempt whether the pattern was free or not — otherwise anyone inside the vault could test patterns there for free. Pattern tries have their own pace limit (5 a day free, then 30 s, 5 min, 1 h between tries) that no success clears — a correct password must not buy more tries, and a reset would itself say a hidden vault opened; misses age out after 24 h. If the vault's own pattern equals a hidden vault's, the hidden vault opens (creation refuses the vault's own pattern). |

Stated limits (also in the app): an examiner can see the pool folder's total
size, its file count rounded to a band (a vault with many files can push it past
what a decoy alone explains), and comparing two images of the device, that it
changed. Timestamps the app cannot set — Linux/Android inode change and birth
times, NTFS `$FILE_NAME` attributes, the folder's own times — still record when
files were written or deleted. Flash
storage can keep stale blocks of overwritten files — ciphertext under keys that
exist nowhere but in the pattern. Someone who extracts this device's secure-store
key can try patterns offline at Argon2id cost each, so a short or common pattern
is guessable: use 8 or more dots. Patterns, like PINs, are not offered in FIPS
approved mode (Argon2id is not an approved function and PBKDF2 alone cannot
protect a pattern offline); hidden vaults created before approved mode was
switched on still open.

## 12. Decoy vaults and duress erase

**Decoys.** Every hidden vault is the same kind of object; nothing in its index
or on disk marks it "real" or "decoy". A decoy is simply a hidden vault the
owner fills with believable, harmless files and opens when coerced, instead of
the vault that matters. Plausible deniability rests on the properties in §11.

**Duress erase** (opt-in per vault, off by default). From inside an open hidden
vault, *Duress erase → Arm* sets `duressErase` in that vault's encrypted index
(`vault_hidden_set_duress`). The flag is not stored anywhere else: no setting
file, OS secure-store entry, log or telemetry records it.

When an armed vault's pattern is drawn on the **lock screen**
(`vault_pattern_unlock`):

1. `HiddenVault::take_duress` disarms it *in memory* and lists every pool file
   that is not its own (both index names and its content blobs). The vault opens
   and the UI shows it as an ordinary, unarmed vault from the first frame. The
   unlock returns as fast as any other; the audit log gets the same
   `workspace_unlock` line as any vault unlock.
2. In the background (`hidden::run_duress`): the first 64 KiB of every listed
   file is overwritten — that holds the nonce of an index and of a file's first
   chunk, so no other vault's index, and therefore no file key, can be decrypted
   again even if the app is killed next; then the disarmed index is written (a
   new generation, the armed one overwritten); then every listed file is
   overwritten (up to 64 MiB) and deleted; then covers refill the folder to a
   random 1–3 bands, like a new pool.
3. Files the decoy writes during the erase were not in the list and are never
   touched. A decoy deleted during the erase is not recreated.

Opening a hidden vault from **inside the unlocked Quantum Vault**
(`vault_hidden_open`, *Security & Backup → Open a hidden vault here*) never
fires duress erase — that is how an armed decoy is looked after. Like creating a
hidden vault, every try there counts against the pattern attempt limit and pace,
so it is no cheaper a pattern oracle than the lock screen.

What it does **not** do:

- The Quantum Vault (and its cloud backup, library and shares) is never touched.
  Its master key stays sealed; under duress it simply stays locked.
- No prompt, no confirmation, no undo. Hidden vaults have no cloud copy (§11),
  and the erase destroys every other vault's recovery record too (§14), so an
  erased vault is gone for good — its 12 words no longer open anything. The
  decoy's own recovery record is kept.
- Not instantaneous: keys go within moments, the full clean-up takes seconds.
  If the app is killed before the disarmed index is written, the next lock-screen
  draw of the decoy fires it again.
- Not invisible to forensics. Someone imaging the device before and after, or
  reading filesystem journals/inode times, can see that files were overwritten
  and deleted. Flash wear-levelling may keep stale blocks — ciphertext under keys
  that no longer exist anywhere but in the patterns.
- An attacker who watches the owner arm it, or who has an earlier device image
  plus the decoy pattern and device key material, can read the flag from that
  older index.

Verification: `vault::hidden` unit tests
`a_duress_erase_destroys_every_other_vault_and_leaves_the_decoy_looking_ordinary`,
`a_decoy_deleted_during_a_duress_erase_is_not_brought_back`,
`an_index_from_before_decoys_reads_as_not_armed`,
`the_count_stays_on_a_band_and_every_file_carries_one_fixed_date`. Not yet run
on a real device or in a signed-in desktop session.

## 13. Personal and Work spaces

The sidebar's *Personal* and *Work* (which replaced the audio-only *Audio &
Media* filter) are spaces users file things into by choice, whatever the file
type. Each is an ordinary folder named `Personal` / `Work` at the top of My Files
(`SPACE_FOLDERS` in `VaultStorage.tsx`): no new storage, index field or
command, so encryption, integrity, cloud backup, the device library and sharing
treat them like any folder.

- The folder is created the first time something is added to the space (Add
  files, Add folder, drag and drop, New folder, or *To Personal* / *To Work* on a
  selection); just opening an empty space writes nothing.
- Folders inside a space open within it; search there covers only that space.
- The space folders themselves are never moved into one another by *To …*.
- Renaming or deleting the `Personal`/`Work` folder in My Files is allowed; the
  space then starts empty again and a new folder is made on the next add.
- Audio files still appear in My Files, search, Favorites and the Overview's
  per-type breakdown.

Verified 2026-11-04 with a temporary headless-Chrome harness over a faked core
(18 checks: sections, first-add folder creation, To Work, nested folders, scoped
search, 360 px layout, no console errors). Not yet run in the signed-in app.

## 14. Hidden vault recovery phrase

Added 2026-11-05 at the owner's request (reversing the 2026-11-04 "no recovery
phrase" choice): a forgotten hidden vault pattern can be replaced with the
vault's own 12-word recovery phrase.

**The phrase.** 128 random bits from the crypto provider, written as 12 words
of the standard BIP-39 English list (11 bits per word, last word carrying a
4-bit SHA-256 checksum — `crypto::mnemonic`, checked against the official
test vectors and the list's published SHA-256). Typed words are accepted in any
case, with list numbers, commas or new lines, and by their first four letters
(every BIP-39 word is unique in four). The checksum catches typos and swapped
words before anything is looked up; it is not part of the secret.

**What is stored.** Nothing that reveals the phrase:

```text
recovery key  = HKDF-SHA3-256(phrase, "QGuard-HiddenVault-RecoveryKey-v1")
recovery name = HKDF-SHA3-256(phrase, "QGuard-HiddenVault-RecoveryName-v1")[..16], hex
record        = nonce ‖ AES-256-GCM(recovery key, AAD "QGHV-Recovery-v1|user|name",
                                    len ‖ {indexKey, names[2]} ‖ zeros) ‖ tag
```

The record is one more pool file at the recovery name: same 32-hex name shape,
same padding bucket (16 KiB), same fixed timestamps, counted in the cover band —
it cannot be told from a cover or an index. The vault's index stores the record's
name and key (not the phrase) so the vault can rewrite or remove its record.
No stretching: the phrase is 128 random bits, so a KDF cost adds nothing.

**Not bound to the device key**, on purpose: if the OS secure-store key is lost
or replaced (the "storage key was replaced" state), the pattern no longer opens
the vault, but the phrase still does, and the new pattern is then sealed under
the new device key. The phrase only opens files still in this device's pool
folder — there is no cloud copy to restore from.

**Flows.**

| Action | Where | Core |
| --- | --- | --- |
| Set up / new phrase | Open hidden vault → *Recovery phrase* card | `vault_hidden_recovery_setup`: new entropy, record written, index updated, any earlier record overwritten and deleted (old words stop working). The words are returned once for the screen; the UI shows them, then asks for three random words back. |
| Remove | Same card | `vault_hidden_recovery_remove`: index updated, record shredded; a cover keeps the count on its band. |
| Check | Lock screen → *Forgot …?* → *Forgot a hidden vault's pattern?*, or Security & Backup → *Forgot a pattern? Use a recovery phrase* | `vault_hidden_recovery_check`: decodes the words, finds and opens the record and the index it names, returns the summary. Changes nothing. |
| Recover | Same, after the check | `vault_hidden_recover(phrase, pattern)`: phrase checked first (a phrase that opens nothing never reaches the pattern checks); then, exactly as creating a hidden vault, lockout/pace checks, the attempt counted, the vault's own pattern refused; then `HiddenVault::rekey`: new index under the new pattern's names → recovery record rewritten to the new keys → old index generations shredded. The vault opens (Quantum Vault locks). From the lock screen it is logged as the same `workspace_unlock` as any unlock; from inside the vault nothing is logged. Refused in FIPS approved mode, like creating one. |

Both recovery entry points are shown to every vault user, like the pattern pad,
so they say nothing about whether a hidden vault exists. A phrase that opens
nothing gets one message whatever the reason (never set up, replaced, vault
deleted or erased).

**Destruction.** *Delete this hidden vault* shreds the record first; *Erase all*
shreds everything; a duress erase shreds every record except the decoy's own.
A phrase whose record is gone opens nothing; a record whose index no longer names
it (replaced phrase) opens nothing either.

**Limits.** Anyone holding the words can open that vault on this device with no
pattern and no attempt limit — the app tells the owner to keep it on paper, away
from the device, and that a written phrase is itself evidence a hidden vault
exists. If the app is killed during a rekey after the new index and record are
written but before the old index is shredded, the forgotten pattern still opens
an old copy of the index that shares file blobs with the live one; it is never
shown by the app and only that forgotten pattern reaches it.

Verification: `crypto::mnemonic` tests (BIP-39 vectors, word-list hash, typing
variants, named mistakes); `vault::hidden` tests
`a_forgotten_pattern_is_replaced_through_the_recovery_phrase`,
`a_tampered_or_moved_recovery_record_fails_authentication_and_releases_nothing`,
`the_phrase_works_after_the_device_key_is_lost`,
`a_new_phrase_replaces_the_old_and_removing_it_leaves_only_the_pattern`,
`a_taken_pattern_is_refused_on_rekey_and_nothing_changes`,
`deleting_or_a_duress_erase_takes_the_phrase_with_the_vault`; UI tests in
`HiddenRecovery.test.ts`, `vault-hidden.test.ts` and
`WorkspaceLockGate.test.ts`. Not yet run on a real device or in a signed-in
desktop session.
