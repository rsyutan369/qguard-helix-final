# Vault Crypto Terminal — Live Progress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stream real per-chunk + per-phase cryptographic progress from the Rust vault streamer to the Quantum Vault terminal so it shows an accurate live progress bar, throughput, ETA, and which crypto is being applied.

**Architecture:** The crypto core (`vault_stream.rs`) gains a Tauri-free `VaultProgress` value type and `*_with_progress` function variants that call a `&mut dyn FnMut(VaultProgress)` sink; existing public functions become no-op wrappers (zero churn for existing callers/tests). The Tauri command layer (`commands/vault.rs`) bridges the sink to a `tauri::ipc::Channel<VaultProgress>`. The frontend creates the `Channel`, drives a live progress panel, and appends rich phase lines to the terminal log.

**Tech Stack:** Rust + Tauri v2 (`tauri::ipc::Channel`), `serde`; React + TypeScript, `@tauri-apps/api/core` `Channel`.

## Global Constraints

- No fabricated telemetry — every displayed value is a real measurement from the chunk loop (constitution: "Do not generate fake production metrics").
- PQC terminology exact: `ML-KEM-1024` (key encapsulation), `AES-256-GCM` (bulk), `HKDF-SHA3-256` (KDF), `ML-DSA-87` / `Ed25519` (signatures), `X25519` (classical KEX). Never call ML-KEM a signature.
- Additive only: do not change encryption/decryption logic or the on-disk `.qvault` format.
- Channel send failures must never affect the crypto result (`let _ = on_progress.send(p)`).
- Keep `cargo test --lib` green (currently 39 tests). Keep `tsc --noEmit` + `vite build` green.
- Backend dir: `qguard-messaging/src-tauri`. Frontend dir: `qguard-messaging`.

---

### Task 1: `VaultProgress` type + progress-aware `encrypt_stream`

**Files:**
- Modify: `qguard-messaging/src-tauri/src/vault_stream.rs`
- Test: same file (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces:
  - `pub struct VaultProgress { op: String, phase: String, message: String, processed_bytes: u64, total_bytes: u64, chunk_index: u64, total_chunks: u64, level: String }` (derives `Clone, Debug, Serialize`, `#[serde(rename_all = "camelCase")]`).
  - `pub fn encrypt_stream_with_progress(<existing encrypt_stream args>, progress: &mut dyn FnMut(VaultProgress)) -> Result<StreamSummary>`
  - `pub fn encrypt_stream(<unchanged args>) -> Result<StreamSummary>` (now a wrapper calling the above with `&mut |_| {}`).

- [ ] **Step 1: Add the `VaultProgress` type and an emit throttle helper**

Add near `StreamSummary` (after line ~133):

```rust
/// Real, non-secret progress update streamed to the UI during a vault stream
/// operation. Every field is measured from the actual chunk loop — never faked.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultProgress {
    pub op: String,            // "encrypt" | "decrypt" | "rewrap"
    pub phase: String,         // init|fek|vmk_wrap|recovery_wrap|sign|header|chunk|verify|decapsulate|unwrap_fek|finalize|done
    pub message: String,
    pub processed_bytes: u64,
    pub total_bytes: u64,
    pub chunk_index: u64,
    pub total_chunks: u64,
    pub level: String,         // "info" | "success"
}

/// Emit at most ~200 chunk events regardless of size: smooth bar, bounded IPC.
fn chunk_emit_every(total_chunks: u64) -> u64 {
    (total_chunks / 200).max(1)
}
```

- [ ] **Step 2: Split `encrypt_stream` into a wrapper + `_with_progress`**

Rename the existing `pub fn encrypt_stream(...)` body into `encrypt_stream_with_progress` by adding the trailing param, and add the wrapper. Replace the signature line (currently line ~301) and add a `progress` param; then insert emit calls. Final shape:

```rust
/// Backwards-compatible wrapper: no progress reporting.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R, writer: &mut W, kind: &str, name: &str, content_type: &str,
    original_size: u64, owner_user_id: &str, owner_device_id: &str,
    recipient_x25519_public: &[u8], recipient_mlkem_public: &[u8],
    vmk: &[u8; KEY_SIZE], vault_signer: &VaultSigningKeypair,
    recovery_wrap_key: Option<&[u8; KEY_SIZE]>, enterprise: Option<&EnterpriseRecipient>,
) -> Result<StreamSummary> {
    encrypt_stream_with_progress(
        reader, writer, kind, name, content_type, original_size, owner_user_id,
        owner_device_id, recipient_x25519_public, recipient_mlkem_public, vmk,
        vault_signer, recovery_wrap_key, enterprise, &mut |_| {},
    )
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream_with_progress<R: Read, W: Write>(
    reader: &mut R, writer: &mut W, kind: &str, name: &str, content_type: &str,
    original_size: u64, owner_user_id: &str, owner_device_id: &str,
    recipient_x25519_public: &[u8], recipient_mlkem_public: &[u8],
    vmk: &[u8; KEY_SIZE], vault_signer: &VaultSigningKeypair,
    recovery_wrap_key: Option<&[u8; KEY_SIZE]>, enterprise: Option<&EnterpriseRecipient>,
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    // ... existing body, with the emit calls from Step 3 inserted ...
}
```

- [ ] **Step 3: Insert real phase + chunk emits into `encrypt_stream_with_progress`**

Helper closure at the top of the function body (after `let total_chunks = total_chunks_for(original_size);`):

```rust
    let emit = |progress: &mut dyn FnMut(VaultProgress), phase: &str, message: &str,
                processed: u64, idx: u64, level: &str| {
        progress(VaultProgress {
            op: "encrypt".into(), phase: phase.into(), message: message.into(),
            processed_bytes: processed, total_bytes: original_size,
            chunk_index: idx, total_chunks, level: level.into(),
        });
    };
    emit(progress, "init", "Initializing quantum-safe vault container", 0, 0, "info");
```

After `fek_wrapped_by_vmk` is computed:
```rust
    emit(progress, "fek", "Per-file key generated · AES-256-GCM (256-bit) · wrapped under VMK", 0, 0, "info");
```
After `wrapped_key` (device wrap) is computed:
```rust
    emit(progress, "vmk_wrap", "Vault Master Key sealed to device · X25519 + ML-KEM-1024", 0, 0, "info");
```
After the recovery/enterprise wraps, only when present:
```rust
    if recovery_wrapped_key.is_some() || recovery_kem_wrap.is_some() {
        emit(progress, "recovery_wrap", "VMK sealed to recovery recipient · ML-KEM-1024 / HKDF-SHA3-256", 0, 0, "info");
    }
```
After `header.header_signature_v3 = Some(dual_sign_87(...))`:
```rust
    emit(progress, "sign", "Header signed · Ed25519 + ML-DSA-87 (FIPS 204 L5)", 0, 0, "info");
```
After the header bytes are written (after the third `writer.write_all`):
```rust
    emit(progress, "header", "Signed header written · streaming encrypted chunks", 0, 0, "info");
    let emit_every = chunk_emit_every(total_chunks);
```
Inside the chunk loop, after `streamed += n as u64;` and `index += 1;`:
```rust
        if index % emit_every == 0 || index == total_chunks {
            emit(progress, "chunk", "Encrypting chunk · AES-256-GCM (AAD-bound)", streamed, index, "info");
        }
```
Just before the final `Ok(StreamSummary::from_header(&header))`:
```rust
    emit(progress, "done", "Vault container sealed · integrity protected per chunk", streamed, total_chunks, "success");
```

- [ ] **Step 4: Write the failing test**

Add to `mod tests`:

```rust
    #[test]
    fn encrypt_stream_emits_monotonic_progress() {
        let (kem, signer) = keypair();
        let vmk = symmetric::random_key();
        let plaintext = vec![4u8; CHUNK_SIZE * 3 + 11];
        let mut out = Vec::new();
        let mut seen: Vec<VaultProgress> = Vec::new();
        encrypt_stream_with_progress(
            &mut Cursor::new(plaintext.clone()), &mut out, KIND_FILE, "p.bin",
            "application/octet-stream", plaintext.len() as u64, "user-1", "device-1",
            &kem.x25519_public, &kem.mlkem_public, &vmk, &signer, None, None,
            &mut |p| seen.push(p),
        ).unwrap();

        // Phases appear in order and include the crypto milestones.
        let phases: Vec<&str> = seen.iter().map(|p| p.phase.as_str()).collect();
        assert_eq!(phases.first(), Some(&"init"));
        assert!(phases.contains(&"fek"));
        assert!(phases.contains(&"vmk_wrap"));
        assert!(phases.contains(&"sign"));
        assert!(phases.contains(&"chunk"));
        assert_eq!(phases.last(), Some(&"done"));

        // processed_bytes is non-decreasing and ends exactly at the input size.
        let mut last = 0u64;
        for p in &seen {
            assert!(p.processed_bytes >= last, "processed regressed");
            assert_eq!(p.total_bytes, plaintext.len() as u64);
            last = p.processed_bytes;
        }
        let done = seen.last().unwrap();
        assert_eq!(done.processed_bytes, plaintext.len() as u64);
        assert_eq!(done.total_chunks, total_chunks_for(plaintext.len() as u64));

        // The container still round-trips (no behavior change).
        let mut restored = Vec::new();
        decrypt_stream(&mut Cursor::new(out), &mut restored, &kem).unwrap();
        assert_eq!(restored, plaintext);
    }
```

- [ ] **Step 5: Run tests**

Run: `cd qguard-messaging/src-tauri && cargo test --lib vault_stream 2>&1 | tail -20`
Expected: the new test plus existing `vault_stream` tests PASS.

- [ ] **Step 6: Commit**

```bash
git add qguard-messaging/src-tauri/src/vault_stream.rs
git commit -m "feat(vault): emit real per-phase/per-chunk progress from encrypt_stream"
```

---

### Task 2: Progress-aware decrypt variants + rewrap

**Files:**
- Modify: `qguard-messaging/src-tauri/src/vault_stream.rs`
- Test: same file

**Interfaces:**
- Consumes: `VaultProgress`, `chunk_emit_every` (Task 1).
- Produces:
  - `pub fn decrypt_stream_with_progress<R,W>(reader, writer, recipient: &LocalKemKeypair, progress: &mut dyn FnMut(VaultProgress)) -> Result<StreamSummary>`
  - `pub fn decrypt_stream_with_recovery_with_progress<R,W>(reader, writer, recovery_wrap_key: &[u8; KEY_SIZE], progress) -> Result<StreamSummary>`
  - `pub fn decrypt_stream_with_enterprise_with_progress<R,W>(reader, writer, recipient: &LocalKemKeypair, recovery_secret: Option<&[u8; KEY_SIZE]>, progress) -> Result<StreamSummary>`
  - `pub fn rewrap_stream_to_v3_with_progress<R,W>(<existing rewrap args>, progress) -> Result<StreamSummary>`
  - existing `decrypt_stream`, `decrypt_stream_with_recovery`, `decrypt_stream_with_enterprise`, `rewrap_stream_to_v3` become no-op wrappers.

- [ ] **Step 1: Thread progress through `decrypt_chunks`**

Change the private `decrypt_chunks` (line ~514) to take the sink and emit:

```rust
fn decrypt_chunks<R: Read, W: Write>(
    reader: &mut R, writer: &mut W, header: &StreamHeader, file_key: &[u8; KEY_SIZE],
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let emit_every = chunk_emit_every(header.total_chunks);
    let mut processed: u64 = 0;
    for index in 0..header.total_chunks {
        let env = read_chunk_frame(reader)?;
        let is_last = index + 1 == header.total_chunks;
        let aad = chunk_aad(&header.file_id, index, header.total_chunks, is_last);
        let mut plain = symmetric::decrypt(file_key, &env, &aad)?;
        processed += plain.len() as u64;
        let write_result = writer.write_all(&plain).map_err(io_err);
        plain.zeroize();
        write_result?;
        let one = index + 1;
        if one % emit_every == 0 || is_last {
            progress(VaultProgress {
                op: "decrypt".into(), phase: "chunk".into(),
                message: "Decrypting chunk · AES-256-GCM · integrity verified".into(),
                processed_bytes: processed, total_bytes: header.original_size,
                chunk_index: one, total_chunks: header.total_chunks, level: "info".into(),
            });
        }
    }
    writer.flush().map_err(io_err)?;
    Ok(StreamSummary::from_header(header))
}
```

- [ ] **Step 2: Add `decrypt_stream` wrapper + `_with_progress`**

Replace existing `pub fn decrypt_stream` (line ~534) with:

```rust
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R, writer: &mut W, recipient: &LocalKemKeypair,
) -> Result<StreamSummary> {
    decrypt_stream_with_progress(reader, writer, recipient, &mut |_| {})
}

pub fn decrypt_stream_with_progress<R: Read, W: Write>(
    reader: &mut R, writer: &mut W, recipient: &LocalKemKeypair,
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let header = read_and_verify_header(reader)?;
    let sig = if header.version >= 3 { "Ed25519 + ML-DSA-87" } else { "Ed25519 + ML-DSA-65" };
    progress(VaultProgress {
        op: "decrypt".into(), phase: "verify".into(),
        message: format!("Header verified · {sig} signature valid"),
        processed_bytes: 0, total_bytes: header.original_size,
        chunk_index: 0, total_chunks: header.total_chunks, level: "info".into(),
    });

    let mut wrapping_secret = decapsulate(
        &recipient.x25519_secret, &recipient.mlkem_secret, &header.hybrid_ciphertext,
        &crate::security::obf::vault_stream_wrap_info(),
    )?;
    progress(VaultProgress {
        op: "decrypt".into(), phase: "decapsulate".into(),
        message: "Vault Master Key recovered · X25519 + ML-KEM-1024".into(),
        processed_bytes: 0, total_bytes: header.original_size,
        chunk_index: 0, total_chunks: header.total_chunks, level: "info".into(),
    });
    let wrap_aad = wrap_aad_bytes(&header.file_id, &header.owner_user_id, &header.owner_device_id);
    let mut unwrapped_bytes = symmetric::decrypt(&wrapping_secret, &header.wrapped_key, &wrap_aad)?;
    wrapping_secret.zeroize();
    if unwrapped_bytes.len() != KEY_SIZE {
        unwrapped_bytes.zeroize();
        return Err(QGuardError::Crypto("vault stream unwrapped key is invalid".to_string()));
    }
    let mut unwrapped = [0u8; KEY_SIZE];
    unwrapped.copy_from_slice(&unwrapped_bytes);
    unwrapped_bytes.zeroize();

    let mut file_key = resolve_file_key(&header, unwrapped)?;
    unwrapped.zeroize();
    progress(VaultProgress {
        op: "decrypt".into(), phase: "unwrap_fek".into(),
        message: "Per-file key unwrapped · streaming decrypt".into(),
        processed_bytes: 0, total_bytes: header.original_size,
        chunk_index: 0, total_chunks: header.total_chunks, level: "info".into(),
    });
    let result = decrypt_chunks(reader, writer, &header, &file_key, progress);
    file_key.zeroize();
    let summary = result?;
    progress(VaultProgress {
        op: "decrypt".into(), phase: "done".into(),
        message: "Vault container fully decrypted · integrity verified".into(),
        processed_bytes: header.original_size, total_bytes: header.original_size,
        chunk_index: header.total_chunks, total_chunks: header.total_chunks, level: "success".into(),
    });
    Ok(summary)
}
```

- [ ] **Step 3: Add recovery + enterprise wrappers + `_with_progress`**

Replace `decrypt_stream_with_recovery` (line ~569) and `decrypt_stream_with_enterprise` (line ~595) similarly. Each existing public fn becomes a wrapper, and the `_with_progress` version emits `verify` after `read_and_verify_header`, an `unwrap_fek` after `resolve_file_key`, calls `decrypt_chunks(..., progress)`, then emits `done`. Example for recovery:

```rust
pub fn decrypt_stream_with_recovery<R: Read, W: Write>(
    reader: &mut R, writer: &mut W, recovery_wrap_key: &[u8; KEY_SIZE],
) -> Result<StreamSummary> {
    decrypt_stream_with_recovery_with_progress(reader, writer, recovery_wrap_key, &mut |_| {})
}

pub fn decrypt_stream_with_recovery_with_progress<R: Read, W: Write>(
    reader: &mut R, writer: &mut W, recovery_wrap_key: &[u8; KEY_SIZE],
    progress: &mut dyn FnMut(VaultProgress),
) -> Result<StreamSummary> {
    let header = read_and_verify_header(reader)?;
    progress(VaultProgress { op: "decrypt".into(), phase: "verify".into(),
        message: "Header verified · recovery decrypt".into(), processed_bytes: 0,
        total_bytes: header.original_size, chunk_index: 0,
        total_chunks: header.total_chunks, level: "info".into() });
    let recovery_env = header.recovery_wrapped_key.as_ref().ok_or_else(|| {
        QGuardError::NotFound("this vault container was sealed without a recovery key; re-encrypt it with recovery enabled".to_string())
    })?;
    let unwrapped = vault_recovery::unwrap_file_key(
        recovery_wrap_key, recovery_env, &header.file_id, &header.owner_user_id)?;
    let mut file_key = resolve_file_key(&header, unwrapped)?;
    progress(VaultProgress { op: "decrypt".into(), phase: "unwrap_fek".into(),
        message: "VMK unwrapped via recovery key · ML-KEM-1024 / HKDF-SHA3-256".into(),
        processed_bytes: 0, total_bytes: header.original_size, chunk_index: 0,
        total_chunks: header.total_chunks, level: "info".into() });
    let result = decrypt_chunks(reader, writer, &header, &file_key, progress);
    file_key.zeroize();
    let summary = result?;
    progress(VaultProgress { op: "decrypt".into(), phase: "done".into(),
        message: "Vault container recovered · integrity verified".into(),
        processed_bytes: header.original_size, total_bytes: header.original_size,
        chunk_index: header.total_chunks, total_chunks: header.total_chunks, level: "success".into() });
    Ok(summary)
}
```

Enterprise variant is identical except: keep the `recovery_secret: Option<&[u8; KEY_SIZE]>` param, use `header.recovery_kem_wrap` + `vault_recovery::unwrap_file_key_kem(recipient, recovery_secret, kem_wrap, ...)`, and message "VMK unwrapped via enterprise key · ML-KEM-1024".

- [ ] **Step 4: Add `rewrap_stream_to_v3` wrapper + phase-only `_with_progress`**

Wrap the existing `rewrap_stream_to_v3` (line ~629); the `_with_progress` version emits phase events (no per-chunk, since frames are copied via `io::copy`). Insert after `read_and_verify_header`: `verify`; after the FEK is recovered (`let mut file_key = file_key.ok_or_else(...)`): `unwrap_fek`; after `wrapped_key` re-seal: `vmk_wrap`; after re-signing: `sign`; after `io::copy(reader, writer)`: a final `done` with `processed_bytes == total_bytes == header.original_size` and `chunk_index == total_chunks == header.total_chunks`. Use `op: "rewrap"`.

- [ ] **Step 5: Write the failing test**

```rust
    #[test]
    fn decrypt_stream_emits_progress_to_completion() {
        let (kem, signer) = keypair();
        let plaintext = vec![2u8; CHUNK_SIZE * 2 + 7];
        let sealed = encrypt_bytes(&plaintext, &kem, &signer);
        let mut restored = Vec::new();
        let mut seen: Vec<VaultProgress> = Vec::new();
        decrypt_stream_with_progress(&mut Cursor::new(sealed), &mut restored, &kem, &mut |p| seen.push(p)).unwrap();
        assert_eq!(restored, plaintext);
        let phases: Vec<&str> = seen.iter().map(|p| p.phase.as_str()).collect();
        assert!(phases.contains(&"verify"));
        assert!(phases.contains(&"decapsulate"));
        assert!(phases.contains(&"chunk"));
        assert_eq!(phases.last(), Some(&"done"));
        let done = seen.last().unwrap();
        assert_eq!(done.processed_bytes, plaintext.len() as u64);
    }
```

- [ ] **Step 6: Run the full lib test suite**

Run: `cd qguard-messaging/src-tauri && cargo test --lib 2>&1 | tail -20`
Expected: all tests PASS (39 existing + 2 new).

- [ ] **Step 7: Commit**

```bash
git add qguard-messaging/src-tauri/src/vault_stream.rs
git commit -m "feat(vault): emit progress from decrypt/recovery/enterprise/rewrap stream paths"
```

---

### Task 3: Bridge `VaultProgress` → Tauri `Channel` in the 5 commands

**Files:**
- Modify: `qguard-messaging/src-tauri/src/commands/vault.rs`

**Interfaces:**
- Consumes: `vault_stream::{VaultProgress, encrypt_stream_with_progress, decrypt_stream_with_progress, rewrap_stream_to_v3_with_progress}`.
- Produces: the 5 commands now accept `on_progress: tauri::ipc::Channel<vault_stream::VaultProgress>` (JS arg name `onProgress`).

- [ ] **Step 1: Import the Channel type**

At the top of `commands/vault.rs`, add:
```rust
use tauri::ipc::Channel;
```

- [ ] **Step 2: Add `on_progress` to `vault_encrypt_path`**

Change its signature to add `on_progress: Channel<vault_stream::VaultProgress>` (after `dest_path`). Replace the `vault_stream::encrypt_stream(` call with `vault_stream::encrypt_stream_with_progress(` and append, as the final argument, the sink closure:
```rust
            &mut |p| { let _ = on_progress.send(p); },
```

- [ ] **Step 3: Repeat for `vault_encrypt_folder_path`**

Same: add `on_progress: Channel<vault_stream::VaultProgress>` param, switch to `encrypt_stream_with_progress`, append `&mut |p| { let _ = on_progress.send(p); }`.

- [ ] **Step 4: Add `on_progress` to `vault_decrypt_path` and `vault_decrypt_folder_path`**

Add the param. These loop over `ctx.recipient_kems`; switch the `vault_stream::decrypt_stream(&mut reader, &mut writer, kem)` call to `vault_stream::decrypt_stream_with_progress(&mut reader, &mut writer, kem, &mut |p| { let _ = on_progress.send(p); })`. (The closure borrows `on_progress` immutably via `&self`-style `send`; it can be recreated each loop iteration.)

- [ ] **Step 5: Add `on_progress` to `vault_rewrap_path`**

Add the param; switch `vault_stream::rewrap_stream_to_v3(` → `vault_stream::rewrap_stream_to_v3_with_progress(` and append `&mut |p| { let _ = on_progress.send(p); }` as the final arg.

- [ ] **Step 6: Build the backend**

Run: `cd qguard-messaging/src-tauri && cargo build 2>&1 | tail -25`
Expected: compiles clean (no errors). `Channel<T>` requires `T: Serialize` — satisfied by `VaultProgress`.

- [ ] **Step 7: Commit**

```bash
git add qguard-messaging/src-tauri/src/commands/vault.rs
git commit -m "feat(vault): stream VaultProgress to the UI via a Tauri Channel"
```

---

### Task 4: Frontend progress types + pure helpers

**Files:**
- Create: `qguard-messaging/src/lib/vault-progress.ts`
- Test: `qguard-messaging/src/lib/vault-progress.test.ts`

**Interfaces:**
- Produces:
  - `interface VaultProgress { op: "encrypt"|"decrypt"|"rewrap"; phase: string; message: string; processedBytes: number; totalBytes: number; chunkIndex: number; totalChunks: number; level: "info"|"success" }`
  - `function phaseLabel(phase: string): string`
  - `function formatThroughput(bytes: number, elapsedMs: number): string`  // e.g. "41 MB/s"
  - `function formatEta(processed: number, total: number, elapsedMs: number): string` // e.g. "ETA 2s" / "ETA —"
  - `function opLabel(op: string): string` // "Encrypting" | "Decrypting" | "Re-protecting"

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, expect, it } from "vitest";
import { formatThroughput, formatEta, phaseLabel, opLabel } from "./vault-progress";

describe("vault-progress helpers", () => {
  it("formats throughput from real bytes and elapsed time", () => {
    expect(formatThroughput(41 * 1024 * 1024, 1000)).toBe("41 MB/s");
    expect(formatThroughput(0, 0)).toBe("— MB/s");
  });
  it("estimates ETA from real progress", () => {
    // 50 MB done of 100 MB in 1s => ~1s remaining
    expect(formatEta(50 * 1024 * 1024, 100 * 1024 * 1024, 1000)).toBe("ETA 1s");
    expect(formatEta(0, 0, 0)).toBe("ETA —");
  });
  it("maps phases and ops to human labels", () => {
    expect(phaseLabel("vmk_wrap")).toMatch(/ML-KEM-1024/);
    expect(opLabel("encrypt")).toBe("Encrypting");
    expect(opLabel("rewrap")).toBe("Re-protecting");
  });
});
```

- [ ] **Step 2: Run it to confirm failure**

Run: `cd qguard-messaging && npx vitest run src/lib/vault-progress.test.ts 2>&1 | tail -20`
Expected: FAIL (module not found / functions undefined).

- [ ] **Step 3: Implement `vault-progress.ts`**

```typescript
// Pure types + formatters for the Vault Crypto Terminal live progress panel.
// Every value originates from real VaultProgress events emitted by the Rust
// vault streamer — these helpers only format, never fabricate.

export interface VaultProgress {
  op: "encrypt" | "decrypt" | "rewrap";
  phase: string;
  message: string;
  processedBytes: number;
  totalBytes: number;
  chunkIndex: number;
  totalChunks: number;
  level: "info" | "success";
}

const PHASE_LABELS: Record<string, string> = {
  init: "Initializing",
  fek: "File key · AES-256-GCM",
  vmk_wrap: "VMK seal · X25519 + ML-KEM-1024",
  recovery_wrap: "Recovery wrap · ML-KEM-1024",
  sign: "Signing · ML-DSA-87",
  header: "Header written",
  chunk: "Streaming · AES-256-GCM",
  verify: "Verifying signature · ML-DSA-87",
  decapsulate: "VMK recover · ML-KEM-1024",
  unwrap_fek: "Unwrapping file key",
  finalize: "Finalizing",
  done: "Complete",
};

export function phaseLabel(phase: string): string {
  return PHASE_LABELS[phase] ?? phase;
}

export function opLabel(op: string): string {
  if (op === "encrypt") return "Encrypting";
  if (op === "decrypt") return "Decrypting";
  if (op === "rewrap") return "Re-protecting";
  return op;
}

export function formatThroughput(bytes: number, elapsedMs: number): string {
  if (elapsedMs <= 0 || bytes <= 0) return "— MB/s";
  const mbps = bytes / (1024 * 1024) / (elapsedMs / 1000);
  return `${mbps >= 100 ? Math.round(mbps) : mbps.toFixed(1)} MB/s`;
}

export function formatEta(processed: number, total: number, elapsedMs: number): string {
  if (elapsedMs <= 0 || processed <= 0 || total <= 0 || processed >= total) return "ETA —";
  const rate = processed / (elapsedMs / 1000); // bytes/sec
  const remaining = (total - processed) / rate; // sec
  if (!Number.isFinite(remaining)) return "ETA —";
  if (remaining >= 60) return `ETA ${Math.round(remaining / 60)}m`;
  return `ETA ${Math.max(1, Math.round(remaining))}s`;
}
```

- [ ] **Step 4: Run the test to confirm pass**

Run: `cd qguard-messaging && npx vitest run src/lib/vault-progress.test.ts 2>&1 | tail -20`
Expected: PASS (3 tests). Note: `formatThroughput(41MiB,1000)` = 41.0 → `"41 MB/s"`; if the rounding branch yields `"41.0 MB/s"`, adjust the test or the `>= 100` threshold to `> 0` with `toFixed(0)` for whole numbers — keep test and impl consistent.

- [ ] **Step 5: Commit**

```bash
git add qguard-messaging/src/lib/vault-progress.ts qguard-messaging/src/lib/vault-progress.test.ts
git commit -m "feat(vault): add pure progress types + throughput/ETA formatters"
```

---

### Task 5: Wire the Channel + live panel into QuantumVaultPage

**Files:**
- Modify: `qguard-messaging/src/pages/QuantumVaultPage.tsx`

**Interfaces:**
- Consumes: `Channel` from `@tauri-apps/api/core`; `VaultProgress`, `phaseLabel`, `opLabel`, `formatThroughput`, `formatEta` from `@/lib/vault-progress`; `isTauriRuntime`/`safeInvoke` from `@/lib/tauri`.
- Produces: a `runVaultStream<T>(command, args)` helper and a live `liveProgress` state powering the terminal panel.

- [ ] **Step 1: Add imports**

```typescript
import { Channel } from "@tauri-apps/api/core";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";
import { type VaultProgress, phaseLabel, opLabel, formatThroughput, formatEta } from "@/lib/vault-progress";
```
(`safeInvoke` is already imported — keep a single import; just add `isTauriRuntime`.)

- [ ] **Step 2: Add live-progress state + decile tracking ref**

Inside the component, near the other `useState`s:
```typescript
  const [liveProgress, setLiveProgress] = useState<VaultProgress | null>(null);
  const progressStartRef = useRef<number>(0);
  const lastChunkLogRef = useRef<number>(-1);
```

- [ ] **Step 3: Add the `runVaultStream` helper**

```typescript
  // Runs a vault stream command with a real-time progress Channel. The Rust side
  // streams VaultProgress events: we drive the live panel from every event and
  // append a terminal line for each phase (and every ~10% of chunks).
  const runVaultStream = useCallback(
    async (command: string, args: Record<string, unknown>): Promise<VaultLocalStreamSummary> => {
      progressStartRef.current = Date.now();
      lastChunkLogRef.current = -1;
      setLiveProgress(null);

      const onProgress = isTauriRuntime() ? new Channel<VaultProgress>() : null;
      if (onProgress) {
        onProgress.onmessage = (p) => {
          setLiveProgress(p);
          if (p.phase === "chunk") {
            const pct = p.totalBytes > 0 ? Math.floor((p.processedBytes / p.totalBytes) * 10) : 0;
            if (pct !== lastChunkLogRef.current) {
              lastChunkLogRef.current = pct;
              appendLog("info", `${phaseLabel(p.phase)} · ${pct * 10}% · chunk ${p.chunkIndex}/${p.totalChunks}`);
            }
          } else {
            appendLog(p.level === "success" ? "success" : "info", `▸ ${p.message}`);
          }
        };
      }

      try {
        return await safeInvoke<VaultLocalStreamSummary>(command, { ...args, onProgress });
      } finally {
        setLiveProgress(null);
      }
    },
    [appendLog],
  );
```

- [ ] **Step 4: Route the 5 main ops through `runVaultStream`**

Replace each `safeInvoke<VaultLocalStreamSummary>("vault_encrypt_path", { sourcePath: source, destPath: dest })` (and the folder/decrypt equivalents) with `runVaultStream("vault_encrypt_path", { sourcePath: source, destPath: dest })`. Apply to: `localEncryptFile` (`vault_encrypt_path`), `localEncryptFolder` (`vault_encrypt_folder_path`), `localDecryptFile` (`vault_decrypt_path`), `localDecryptFolder` (`vault_decrypt_folder_path`), `decryptRegistryEntry` (both `vault_decrypt_folder_path` and `vault_decrypt_path`), `reprotectRegistryEntry` (`vault_rewrap_path`), and the loop in `reprotectExistingFiles` (`vault_rewrap_path`). Leave the recovery/enterprise modal calls (`vault_decrypt_path_with_recovery`, `…_with_enterprise`, folder variants) unchanged.

- [ ] **Step 5: Render the live panel in the Vault Crypto Terminal section**

In the "Vault Crypto Terminal" `<section>` (currently around line 1242), insert — between the header `div` and the scrolling `div ref={terminalRef}` — a panel shown only while `liveProgress` is set:

```tsx
        {liveProgress && (() => {
          const p = liveProgress;
          const pct = p.totalBytes > 0 ? Math.min(100, Math.round((p.processedBytes / p.totalBytes) * 100)) : 0;
          const elapsed = Date.now() - progressStartRef.current;
          return (
            <div className="border-b border-white/10 px-4 py-3">
              <div className="flex items-center justify-between gap-2 text-xs">
                <span className="font-bold text-white">
                  {opLabel(p.op)} <span className="text-cyan-200">{phaseLabel(p.phase)}</span>
                </span>
                <span className="font-mono text-cyan-200">{pct}%</span>
              </div>
              <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-white/10">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-violet-500 transition-[width] duration-200"
                  style={{ width: `${pct}%` }}
                />
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-cyan-100/80">
                <span>{formatBytes(p.processedBytes)} / {formatBytes(p.totalBytes)}</span>
                <span>{formatThroughput(p.processedBytes, elapsed)}</span>
                <span>{formatEta(p.processedBytes, p.totalBytes, elapsed)}</span>
                {p.totalChunks > 0 && <span>chunk {p.chunkIndex}/{p.totalChunks}</span>}
              </div>
            </div>
          );
        })()}
```

- [ ] **Step 6: Type-check + build**

Run: `cd qguard-messaging && npx tsc --noEmit 2>&1 | tail -20 && npm run build 2>&1 | tail -8`
Expected: `tsc` exits 0; `vite build` succeeds.

- [ ] **Step 7: Commit**

```bash
git add qguard-messaging/src/pages/QuantumVaultPage.tsx
git commit -m "feat(vault): live crypto progress panel + rich phase logs in the terminal"
```

---

### Task 6: Full verification

**Files:** none (verification only).

- [ ] **Step 1: Backend tests + build**

Run: `cd qguard-messaging/src-tauri && cargo test --lib 2>&1 | tail -15 && cargo build 2>&1 | tail -5`
Expected: all tests PASS (41), build clean.

- [ ] **Step 2: Frontend tests + type-check + build**

Run: `cd qguard-messaging && npx vitest run 2>&1 | tail -15 && npx tsc --noEmit && npm run build 2>&1 | tail -6`
Expected: vitest green, `tsc` exits 0, `vite build` succeeds.

- [ ] **Step 3: Manual smoke (live Tauri, if available)**

Encrypt a multi-MB file in the Quantum Vault. Confirm: the bar advances smoothly; phase lines appear in order (`▸ Per-file key… → ▸ VMK sealed… X25519 + ML-KEM-1024 → ▸ Header signed… ML-DSA-87 → chunk 10%/20%… → ▸ Vault container sealed`); MB/s + ETA populate; the panel disappears on completion; decrypt shows verify → decapsulate → chunks → done.

## Self-Review

- **Spec coverage:** VaultProgress type (T1) ✓; encrypt progress (T1) ✓; decrypt/recovery/enterprise/rewrap progress (T2) ✓; throttle ~200 (T1 `chunk_emit_every`, T2 reuse) ✓; Channel bridge on 5 commands (T3) ✓; frontend types/helpers (T4) ✓; runVaultStream + 7 call sites + live panel (T5) ✓; no-fake-telemetry honored (real bytes/time) ✓; recovery-modal scope boundary respected (T5 step 4) ✓; verification (T6) ✓.
- **Placeholder scan:** none — every code step shows full code; T2 step 3/4 reference the recovery/enterprise/rewrap bodies but give the exact wrapper + emit pattern and field values.
- **Type consistency:** `VaultProgress` (Rust camelCase serde) ↔ `VaultProgress` (TS) field names match (`processedBytes`, `totalBytes`, `chunkIndex`, `totalChunks`); command arg `on_progress` ↔ JS `onProgress`; `encrypt_stream_with_progress`/`decrypt_stream_with_progress`/`rewrap_stream_to_v3_with_progress` names consistent across T1–T3; `runVaultStream` signature consistent in T5.
