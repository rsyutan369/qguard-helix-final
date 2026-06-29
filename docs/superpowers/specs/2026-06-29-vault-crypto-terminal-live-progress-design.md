# Vault Crypto Terminal — Live Progress & Telemetry

**Date:** 2026-06-29
**Module:** `qguard-messaging` → Quantum Vault → Vault Crypto Terminal
**Status:** Approved design — ready for implementation plan

## Problem

In the Quantum Vault, the **Vault Crypto Terminal** only logs coarse start/end
lines for encrypt/decrypt operations. There is no live progress, no visibility
into which cryptographic phase is running, and no throughput/ETA. The user wants
a professional, enterprise-grade terminal that shows — **accurately** — what is
happening in the background: which crypto is being applied, real progress while
files/folders are encrypted/decrypted, and a true status.

The platform constitution forbids fabricated telemetry ("Do not generate fake
production metrics… no simulated telemetry in production"). Therefore every value
displayed must be a real measurement sourced from the crypto streamer.

## Current state (discovery)

- `src-tauri/src/vault_stream.rs` streams data in **1 MiB chunks** through the
  hybrid PQC stack (`encrypt_stream`, `decrypt_stream`,
  `decrypt_stream_with_recovery`, `decrypt_stream_with_enterprise`,
  `rewrap_stream_to_v3`). It returns only a final `StreamSummary` — **nothing is
  emitted mid-operation**.
- `src-tauri/src/commands/vault.rs` exposes the Tauri commands; they call the
  stream functions synchronously and return the summary. Today they only call
  `touch_telemetry(..., 100)` once at the end.
- **No Tauri event/channel exists anywhere in the backend** (the app uses
  Supabase SSE and an in-memory chat decryption stream; no `Emitter`/`Channel`).
- Frontend `src/pages/QuantumVaultPage.tsx` keeps `terminalLogs` (append-only)
  and renders them in the "Vault Crypto Terminal" section. Dialogs are opened via
  the guarded `@/lib/tauri-dialog` wrapper. `safeInvoke` (`src/lib/tauri.ts`)
  forwards args straight to `invoke`.
- Versions: Tauri Rust `2`, `@tauri-apps/api` `2.11.1`. `Channel<T>` is available
  in `@tauri-apps/api/core`.

## Crypto phases (real, surfaced as status)

**Encrypt** (`encrypt_stream`): generate per-file FEK (AES-256-GCM 256-bit) →
wrap FEK under the VMK (AES-256-GCM) → seal VMK to the device via X25519 +
ML-KEM-1024 → optional recovery/enterprise VMK wrap → sign header with Ed25519 +
ML-DSA-87 (FIPS 204 L5) → write header → stream chunks (AES-256-GCM per 1 MiB,
AAD-bound to file id + chunk index) → finalize (atomic rename of `.qguard-part`).

**Decrypt** (`decrypt_stream` + variants): read header → verify dual signature
(Ed25519 + ML-DSA-87 for v3, ML-DSA-65 for v1/v2) → decapsulate VMK (X25519 +
ML-KEM-1024) → unwrap FEK from VMK → stream-decrypt chunks (AES-256-GCM, integrity
verified per chunk) → finalize.

**Re-protect** (`rewrap_stream_to_v3`): recover FEK with a device key → re-seal as
v3 (VMK envelope, ML-DSA-87) → copy chunk frames verbatim.

## Design

### Data flow

```
QuantumVaultPage ──Channel<VaultProgress>──► vault.rs command ──&mut FnMut(VaultProgress)──► vault_stream core
       ▲                                                                                          │
       └──────────────── real per-chunk + per-phase events (channel.send) ◄──────────────────────┘
```

All numbers are real: `processed_bytes` / `total_bytes` come from the actual
chunk loop; throughput (MB/s) and ETA are derived **frontend-side** from real
bytes ÷ real wall-clock elapsed (a measurement, not a fabrication).

### Backend (Rust)

1. **`vault_stream.rs`** — add a plain `serde::Serialize` struct (no Tauri dep, so
   the crypto core stays framework-agnostic and unit-testable):

   ```rust
   #[derive(Clone, Debug, Serialize)]
   #[serde(rename_all = "camelCase")]
   pub struct VaultProgress {
       pub op: String,            // "encrypt" | "decrypt" | "rewrap"
       pub phase: String,         // see phases below
       pub message: String,       // human-readable, crypto-specific
       pub processed_bytes: u64,
       pub total_bytes: u64,
       pub chunk_index: u64,
       pub total_chunks: u64,
       pub level: String,         // "info" | "success"
   }
   ```

   Phases: `init`, `fek`, `vmk_wrap`, `recovery_wrap`, `sign`, `header`, `chunk`,
   `verify`, `decapsulate`, `unwrap_fek`, `finalize`, `done`.

2. Add `*_with_progress` variants taking `progress: &mut dyn FnMut(VaultProgress)`
   for `encrypt_stream`, `decrypt_stream`, `decrypt_stream_with_recovery`,
   `decrypt_stream_with_enterprise`, `rewrap_stream_to_v3`, and thread the sink
   through the private `decrypt_chunks` helper. **Keep the existing public
   functions as thin wrappers** that call the `_with_progress` variant with a
   no-op `&mut |_| {}` — so existing tests and any other callers are untouched.

3. Emit phase events (always) and per-chunk events. **Throttle** chunk emission to
   ~200 events max: `emit_every = max(1, total_chunks / 200)`, always emitting the
   final chunk, so the bar is smooth and IPC stays bounded for multi-GB files.

4. **`commands/vault.rs`** — these 5 commands gain
   `on_progress: tauri::ipc::Channel<VaultProgress>`:
   `vault_encrypt_path`, `vault_encrypt_folder_path`, `vault_decrypt_path`,
   `vault_decrypt_folder_path`, `vault_rewrap_path`. Each builds a closure
   `&mut |p| { let _ = on_progress.send(p); }` and calls the `_with_progress`
   variant. Channel send failures are ignored and never affect the crypto result.
   This automatically covers both the main dropzone ops **and** the Explorer row
   decrypt / re-protect actions (same commands).

### Frontend

5. **`src/lib/vault-progress.ts`** (new) — `VaultProgress` TS type mirroring the
   Rust struct + pure helpers: `formatThroughput(bytes, ms)`, `formatEta(...)`,
   `phaseLabel(phase)`, and a `progressLine(progress)` builder for terminal text.

6. **`QuantumVaultPage.tsx`** — a shared `runVaultStream(command, args)` helper:
   - creates a `Channel<VaultProgress>` (`new Channel()` from `@tauri-apps/api/core`),
   - on each message: updates live progress state (drives the bar) and appends a
     terminal line for phase events (always) and chunk events (throttled to ~every
     10% on the frontend so the log isn't flooded),
   - calls `safeInvoke(command, { ...args, onProgress: channel })`,
   - resets live progress in a `finally`.
   All 7 call sites route through it: `localEncryptFile`, `localEncryptFolder`,
   `localDecryptFile`, `localDecryptFolder`, `decryptRegistryEntry` (file+folder),
   `reprotectRegistryEntry`, `reprotectExistingFiles` (loop).

7. **Live panel** rendered inside the Vault Crypto Terminal while an op runs:
   - header: operation ("Encrypting" / "Decrypting" / "Re-protecting") + filename
     + current-phase chip,
   - a cyan gradient progress bar with % overlay,
   - a stats row: `processed / total` (existing `formatBytes`) · `MB/s` · `ETA` ·
     `chunk x / y`,
   - below it the existing color-coded monospace log, now carrying real per-phase
     crypto detail (▸ phase, ✓ success, error in red).
   The panel clears on completion or error.

### Component boundaries

- `vault_stream.rs`: crypto + the `VaultProgress` value type and progress-emitting
  variants. Depends only on serde + existing crypto modules. No Tauri.
- `commands/vault.rs`: bridges `VaultProgress` → Tauri `Channel`. Depends on Tauri.
- `vault-progress.ts`: pure formatting/types. No React, no Tauri.
- `QuantumVaultPage.tsx`: owns the Channel lifecycle, live state, and rendering.

## Error handling

- `channel.send` failures are swallowed (`let _ =`) — crypto correctness is never
  affected by the progress side-channel.
- Operation errors continue to flow through the existing `try/catch` in the page;
  the live panel is cleared in `finally`. Partial `.qguard-part` cleanup is
  unchanged.

## Scope boundary (YAGNI)

The recovery/enterprise **modal** decrypts (`vault_decrypt_path_with_recovery`,
`…_with_enterprise`, folder variants) keep their current start/end logging. They
are not on the main terminal flow; the core already supports progress, so they can
be wired later with no further backend work.

## Testing / verification

- Rust: keep `cargo test --lib` green (currently 39) and add one test asserting
  `encrypt_stream_with_progress` emits a monotonic non-decreasing `processed_bytes`
  ending at `processed_bytes == total_bytes` with the correct `total_chunks`, and
  that the no-op wrapper still round-trips. `cargo build` clean.
- Frontend: `tsc --noEmit` + `vite build` green; no console errors.
- Manual (live Tauri): encrypt a multi-MB file → bar advances smoothly, phase
  lines appear in order (FEK → VMK X25519+ML-KEM-1024 → ML-DSA-87 sign → chunks →
  sealed), MB/s and ETA populate, panel clears at completion.

## Risks

- Per-chunk emission volume on huge files → mitigated by ~200-event throttle.
- Making `on_progress` a required arg means every existing call site must pass a
  channel; all 7 are in `QuantumVaultPage.tsx` and routed through one helper.
- Additive only — no change to the actual encryption/decryption logic.
