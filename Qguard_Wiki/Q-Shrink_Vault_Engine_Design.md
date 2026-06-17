# Q-Shrink Vault Engine™ — Design & Implementation

**Quantum-Safe Storage Reduction and Integrity-Native Knowledge Engine**

> Pre-encryption data reduction with exact post-decryption restoration — *not*
> "compressing encrypted data". The plaintext is optimized locally first, then
> the **reduced** package is sealed with the existing hybrid PQC envelope
> (X25519 + ML-KEM-1024 + AES-256-GCM). High-entropy ciphertext cannot be
> meaningfully compressed, so compression must always precede encryption.

Status: **Implemented & wired** into `http://localhost:3000/dashboard/vault`.
Round-trip reversibility proven (27/27 checks). TypeScript + production build clean.

---

## 1. Objective

Reduce the storage footprint of large files/folders **before** encryption so that
sealed vault objects consume less cloud and local storage, while preserving full
reversibility: after decryption + rehydration the user receives the exact
original bytes, filename, MIME type, and (for bundles) folder structure.

```
Original File/Folder
  → Chunking → Deduplication → Compression → Manifest + Merkle Integrity
  → PQC Envelope Encryption → Smaller Encrypted Vault Object

Restore:
Encrypted Vault Object
  → Decryption → Integrity Verification → Decompression
  → Deduplication Rehydration → Original File/Folder
```

---

## 2. Architecture

### 2.1 Module map (`src/lib/vault/q-shrink/`)

| File | Responsibility |
|------|----------------|
| `types.ts` | Shared types, codec ids, manifest/report schemas |
| `entropy.ts` | Shannon entropy sampling + type-aware "already compressed" detection |
| `chunker.ts` | FastCDC content-defined chunking (deterministic gear table) |
| `codec.ts` | Native `CompressionStream` deflate-raw/gzip; STORE passthrough |
| `manifest.ts` | SHA3-256 hex helpers + chunk-level Merkle root |
| `container.ts` | `QSHRN1` binary container (pack/parse, magic detection) |
| `index.ts` | Public API: `optimizeFile`, `restoreFile`, `optimizeBundle`, `restorePackage`, `analyzeFiles`, `decodeReport`, `isQShrinkPackage` |

### 2.2 Where it plugs into the vault

The engine is a **pure pre-encryption transform** that sits in front of the
existing zero-knowledge crypto (`src/lib/vault/client-crypto.ts`) — nothing in
the cryptographic core changed.

```
Upload (page.tsx handleFileUpload / handleEncrypt):
  fileBytes ─▶ optimizeForVault() ─▶ package ─▶ encryptFileLocal(package, …)
                                                   │
                                                   ▼
                              vault_files row: encrypted_size = |sealed package|
                              original_size = true file size
                              envelope_meta.qshrink = report (signed)

Download (page.tsx handleDecrypt / getPlaintextForSharing):
  sealed ─▶ decryptFileLocal(…) ─▶ package ─▶ restoreFromVault() ─▶ original bytes
```

Trust boundaries: optimization + encryption happen entirely **client-side**. The
server only ever stores the encrypted, reduced container and the **non-secret**
`qshrink` summary (sizes/ratios/labels — never content). Zero-knowledge is
preserved.

### 2.3 Data-flow diagram

```
            ┌──────────────────────── CLIENT (browser, zero-knowledge) ───────────────────────┐
            │                                                                                   │
 plaintext ─┼─▶ FastCDC chunk ─▶ SHA3-256 dedup ─▶ concat dedup blob ─▶ entropy gate ─▶ deflate │
            │         │                    │                                     │              │
            │         └── per-file seq ────┴── unique-chunk table ── Merkle root ─┘              │
            │                                   │                                                │
            │                          QSHRN1 container ──▶ encryptFileLocal (X25519+ML-KEM-1024 │
            │                                                + AES-256-GCM, HKDF-SHA3-256 wrap,   │
            │                                                Ed25519+ML-DSA-65 signed manifest)   │
            └───────────────────────────────────────────────────────────────────┬───────────────┘
                                                                                 ▼
                                                          Supabase Storage (vault-encrypted) +
                                                          vault_files (envelope_meta.qshrink)
```

---

## 3. Pipeline (step-by-step)

1. **Intake / type detection** — `optimizeFile(data, { path, mime })`.
2. **Chunking** — FastCDC over the bytes; content-defined boundaries
   (`minSize 2 KiB`, `avgSize 8 KiB`, `maxSize 64 KiB`).
3. **Per-chunk hashing** — SHA3-256 of each chunk.
4. **Deduplication** — content-addressed: first occurrence of a hash becomes a
   unique chunk; later occurrences become references. Works **across files** in a
   bundle (folder-level dedup).
5. **Dedup blob** — unique chunks concatenated in storage order.
6. **Entropy analysis** — Shannon entropy sample of the blob; type pre-filter for
   already-compressed formats (jpg/png/zip/pdf/mp4/…).
7. **Compression** — if compressible, deflate-raw the **whole** dedup blob (one
   stream → no per-chunk header overhead). Kept only if it actually shrinks.
8. **Merkle tree** — SHA3-256 Merkle root over the unique-chunk hashes.
9. **Manifest** — JSON (chunk table, per-file digests + sequences, totals);
   independently deflate-raw compressed when beneficial.
10. **Container** — serialize header + manifest + payload into `QSHRN1`.
11. **No-inflation guard** — if the container ≥ the original, return the original
    bytes with `applied:false` (the package is never larger than the input).
12. **PQC envelope** — `encryptFileLocal(package, …)` seals it.
13. **Restore** — decrypt → (magic/flag detect) → decompress → rehydrate from
    manifest sequences → verify each file's SHA3-256 + Merkle root → original.

### 3.1 Compression decision tree

```
incoming dedup blob
├─ CompressionStream unavailable? ─────────────▶ STORE
├─ every input is a precompressed type? ───────▶ STORE  (jpg/png/zip/pdf/mp4/…)
├─ blob < 64 bytes? ───────────────────────────▶ STORE
├─ Shannon entropy ≥ 7.85 bits/byte? ──────────▶ STORE  (random/encrypted)
└─ else deflate-raw
      └─ compressed ≥ original? ────────────────▶ STORE  (fallback guard)
      └─ else ─────────────────────────────────▶ DEFLATE_RAW
```

Codec is recorded per-object, so a native/WASM **Zstandard** or **Brotli** backend
can be added later (ids 3/4 reserved) without breaking stored objects.

---

## 4. File format specification (`QSHRN1`)

All integers little-endian. Sections capped at 4 GiB (uint32); a future `QSHRN2`
widens to 64-bit for multi-GiB streaming.

```
offset  size  field
------  ----  --------------------------------------------------------------
0       6     magic   = "QSHRN1" (0x51 53 48 52 4E 31)
6       1     version = 1
7       1     flags   (bit0: manifest deflate-raw, bit1: payload codec-compressed)
8       1     codec   (payload codec id: 0 STORE / 1 DEFLATE_RAW / 2 GZIP)
9       1     reserved = 0
10      4     manifestLength (uint32)
14      4     payloadLength  (uint32)
18      M     manifest bytes (UTF-8 JSON; deflate-raw if flags.bit0)
18+M    P     payload bytes  (dedup blob; codec-compressed if flags.bit1)
```

Detection: `isQShrinkPackage()` validates magic + version, and the magic is
**authoritative** on restore. To make that safe, `optimizeFile` guarantees it
never emits a *raw passthrough* whose bytes begin with the `QSHRN1` magic — such
an input (a binary asset, or a re-uploaded container) is wrapped in a container
instead, so a real user file can never be mis-parsed as one of ours. Because the
decision lives entirely in the GCM-authenticated package bytes, restore does
**not** depend on the mutable `envelope_meta.qshrink.applied` flag; a
tampered/incorrect flag can never cause the wrong bytes to be returned. Legacy
pre-Q-Shrink files (no magic) pass through unchanged.

### 4.1 Chunk manifest format (JSON, inside the container)

```jsonc
{
  "v": 1,
  "algo": "q-shrink-vault-engine/v1",
  "hashAlgo": "SHA3-256",
  "chunker": { "algo": "fastcdc-v1", "minSize": 2048, "avgSize": 8192, "maxSize": 65536 },
  "codecId": 1,
  "codecName": "deflate-raw",
  "dedup": {
    "table": [ { "o": 0, "l": 8192 }, { "o": 8192, "l": 6144 }, … ],   // unique chunks: offset+len in dedup blob
    "merkleRoot": "<sha3-256 hex over unique-chunk hashes>"
  },
  "files": [
    { "path": "report.csv", "size": 1048576, "hash": "<sha3-256 of original>",
      "mime": "text/csv", "seq": [0,1,2,1,3,…] }                        // indices into dedup.table
  ],
  "totals": { "logicalSize": 1048576, "dedupedBlobSize": 262144, "totalChunks": 128, "uniqueChunks": 41 }
}
```

### 4.2 Metadata schema (`vault_files.envelope_meta.qshrink`, non-secret, signed)

```jsonc
{
  "applied": true,
  "algorithm": "q-shrink-vault-engine/v1",
  "logicalSize": 1048576, "optimizedSize": 131072, "reductionPercent": 87.5,
  "fileCount": 1, "totalChunks": 128, "uniqueChunks": 41,
  "dedupSavedBytes": 786432, "dedupRatio": 3.12,
  "codec": "deflate-raw", "compressionRatio": 2.0,
  "entropyBitsPerByte": 4.20, "chunker": "fastcdc-v1",
  "avgChunkSize": 8192, "merkleRoot": "<sha3-256 hex>"
}
```

This summary is added to the **signed metadata** (Ed25519 + ML-DSA-65), so the
reported sizes/ratios are tamper-evident. The authoritative manifest (with the
original-file digest) lives *inside* the encrypted container.

### 4.3 Encryption envelope (unchanged, for reference)

`client-crypto.ts` seals the `QSHRN1` package with: ML-KEM-1024 (+ optional
X25519 hybrid) KEM, per-file random AES-256-GCM data key wrapped via
HKDF-SHA3-256, SHA3-256/SHA3-512 content hashes, SHA3-256 Merkle over the sealed
package, Ed25519 + ML-DSA-65 signed manifest. Q-Shrink does **not** alter any of
this — it only changes *what plaintext* is fed in.

---

## 5. Deduplication strategy

- **Granularity:** content-defined chunks (FastCDC). Boundaries depend on a
  rolling gear hash of the preceding bytes, so they are shift-resistant —
  inserting/removing bytes only re-chunks the local region, keeping unchanged
  regions byte-identical across file versions and across files.
- **Identity:** SHA3-256 of chunk bytes (content-addressed). First occurrence is
  stored; repeats become table references.
- **Scope:** intra-file today (single-file vault uploads) and cross-file in
  bundle mode (`optimizeBundle`, used by the analyzer's multi-file demo). The
  container/manifest is bundle-native, so folder-level dedup in the live upload
  path is a UI addition only.
- **Restoration:** never re-chunks — it replays each file's recorded `seq` of
  table indices, guaranteeing byte-exactness independent of chunker tuning.

---

## 6. Security & threat model

| Concern | Mitigation |
|---------|------------|
| Zero-knowledge | Optimize + encrypt are client-side; server stores only ciphertext + non-secret summary. |
| Authenticated encryption | AES-256-GCM (unchanged envelope). |
| Per-file keys | Random per-file DEK, hybrid-wrapped (unchanged). |
| Per-chunk integrity | SHA3-256 per chunk, committed via the manifest Merkle root. |
| Whole-file integrity | SHA3-256 digest per file in the manifest; re-checked on restore (throws `QSHRINK_INTEGRITY_FAILED`). |
| Tamper / corruption | Any payload mutation fails Merkle and/or file-digest checks; the surrounding GCM tag also fails first. |
| Compression side channel (CRIME/BREACH) | Each file is compressed **in isolation** with its own random key and no shared dictionary across files/tenants. There is no interactive oracle mixing a secret with attacker-controlled input. |
| No inflation | If the container ≥ original, the original bytes are sealed instead (`applied:false`). |
| Tenant isolation | Unchanged — storage paths + RLS are keyed per user; Q-Shrink adds no cross-tenant state. |
| Audit without content exposure | Only sizes/ratios/codecs are logged/displayed. |
| DoS via crafted input | Section length bounds are validated on parse; `>4 GiB` inputs throw `QSHRINK_TOO_LARGE` and fall back to raw sealing. |

### 6.1 Side-channel analysis

- **Length leakage:** the sealed object's size approximates the file's
  compressibility (an at-rest property, not an interactive oracle). This is the
  standard, accepted trade-off for storage compression. Future work: optional
  bucketed padding for high-assurance vault mode.
- **Timing:** chunking/compression time correlates loosely with size/entropy.
  Operations are client-side and not exposed as a server oracle.
- **No shared compression context:** unlike CRIME/BREACH (TLS/HTTP compressing
  secret+attacker data together), each vault object is an independent stream.

---

## 7. Performance (measured, `tools/q-shrink/roundtrip-test.ts`, Node 24)

| Input | Size | Result | Codec | Notes |
|-------|------|--------|-------|-------|
| Highly repetitive log | 350 KB | **99.5%** reduction | deflate-raw | structured text |
| Random bytes | 512 KB | 0% (stored) | store | entropy 8.0 → skipped, no inflation |
| `image/jpeg` (random) | 256 KB | 0% (stored) | store | type pre-filter |
| Backup w/ 256× duplicate 16 KB block | 4 MB | **98–99%** | store/deflate | dedup 50–128× |
| Mixed text + random | 1 MB | ~75% | deflate-raw | partial |
| 3-file bundle w/ shared 256 KB blob | 768 KB | ~64% | — | cross-file dedup |

All 27 reversibility/integrity/no-inflation checks pass.

---

## 8. Upload & restore workflows (as wired)

**Upload** (`handleFileUpload`, `handleEncrypt`):
1. read bytes → `optimizeForVault()` (best-effort; falls back to raw on error)
2. `encryptFileLocal(package, encPub, x25519Pub)`
3. sign metadata incl. `qshrink` summary (Ed25519 + ML-DSA-65)
4. `uploadVaultFile()` — `original_size` = true size, `encrypted_size` = sealed
   reduced size, `envelope_meta.qshrink` = report
5. zero plaintext + package buffers

**Restore** (`handleDecrypt`, `getPlaintextForSharing`):
1. download ciphertext → `decryptFileLocal()` (verifies GCM tag, SHA3 digest,
   package Merkle)
2. `restoreFromVault()` → if `qshrink.applied !== false` and bytes are a `QSHRN1`
   package, rehydrate + verify; else return bytes unchanged (legacy-safe)
3. deliver original bytes; zero buffers

**Verify** (`handleVerify`) is unaffected: it checks the sealed package's
SHA3-512, Merkle proof, and signature over the (now qshrink-inclusive) signed
metadata.

---

## 9. Test cases & CI/CD

`tools/q-shrink/roundtrip-test.ts` (run: `npx tsx tools/q-shrink/roundtrip-test.ts`):
empty / 1-byte / tiny / compressible / incompressible / precompressed-type /
heavy-dedup / mixed / cross-file-bundle / **tamper rejection** / analyzer dry-run.

Recommended CI gates:
- `npm run lint` (`tsc --noEmit`) — type safety
- `npx tsx tools/q-shrink/roundtrip-test.ts` — reversibility + integrity (exit 1 on any failure)
- `npx vite build` — bundling
- (optional) dependency audit — engine adds **zero** new runtime dependencies.

---

## 10. Future backend / desktop integration (design notes)

These are forward-looking plans; the current implementation is the TypeScript
browser engine above.

- **Rust core:** port `chunker`/`codec`/`container` to a `qshrink-core` crate
  (FastCDC + `zstd`/`brotli` + SHA3 via `sha3`), exposing `optimize`/`restore`
  over a stable FFI. The `QSHRN1` format is language-neutral and already
  codec-tagged for Zstandard/Brotli.
- **Tauri desktop:** invoke the Rust core via `#[tauri::command]` for native-speed
  optimization of large local files before the same PQC envelope; reuse `QSHRN1`
  so desktop and web objects are interchangeable.
- **Node.js / FastAPI:** server-side **re-chunk/dedup-aware GC** and global dedup
  index can operate on chunk hashes only (never plaintext), preserving zero-
  knowledge. Streaming `QSHRN2` (64-bit sections) for multi-GiB uploads.

---

## 11. Output note (accuracy)

This is a **secure data optimization, deduplication, and pre-encryption
compression system** for a post-quantum encrypted vault. It is **not** "quantum
compression". ML-KEM is used for key establishment, never as a compressor; the
PQC envelope is applied to the already-reduced package.
