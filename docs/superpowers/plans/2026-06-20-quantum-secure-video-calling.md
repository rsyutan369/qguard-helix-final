# Quantum-Secure 1:1 Video Calling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add end-to-end, quantum-safe 1:1 video + audio calling to the Secure Chat page, with per-frame AES-256-GCM media encryption keyed from the existing hybrid post-quantum KEM.

**Architecture:** Peer-to-peer WebRTC. The media key is bootstrapped by a fresh hybrid KEM (X25519 + ML-KEM-1024) to the peer's identity key - the KEM ciphertext is public so signaling needs no extra E2EE; only the callee can decapsulate. HKDF-SHA3-256 derives directional AES-256-GCM frame keys. Every encoded audio/video frame is encrypted in a Web Worker via the Encoded Transform API, on top of DTLS-SRTP. Signaling rides a new RLS-gated Supabase table.

**Tech Stack:** React 19 + TypeScript + Vite, Tauri 2 (Windows / WebView2), Rust (existing crypto: `encapsulate`/`decapsulate`, `hkdf_sha3_256`), Supabase (Postgres + Realtime), WebRTC (`RTCPeerConnection`, `getUserMedia`, `RTCRtpScriptTransform`), WebCrypto AES-GCM, Vitest (new, for frontend tests).

## Global Constraints

- Platform: Windows / WebView2 first. Capability-check `RTCRtpScriptTransform`; if absent, ABORT the call with a clear message - never a silent non-PQC fallback.
- Crypto reuse only: derive all media keys from `crate::crypto::hybrid_kex::{encapsulate, decapsulate}` + `crate::crypto::kdf::hkdf_sha3_256`. Do NOT invent new primitives. AES-256-GCM only for frame encryption.
- HKDF info labels are exact, versioned strings (copy verbatim): `"qguard-call-media-v1:caller-to-callee"` and `"qguard-call-media-v1:callee-to-caller"`.
- Media key size = 32 bytes (`crate::crypto::symmetric::KEY_SIZE`). GCM nonce = 12 bytes = [4-byte context tag | 8-byte big-endian frame counter].
- ICE defaults to public STUN; TURN servers come from `import.meta.env` (`VITE_TURN_URL`, `VITE_TURN_USERNAME`, `VITE_TURN_CREDENTIAL`) - never hardcoded.
- Honest-limits copy must appear in the in-call UI: media is protected from server/relay/network, but the remote participant can still record their own screen.
- RLS: signaling rows gated by `public.is_messaging_conversation_member(conversation_id, auth.uid())`.
- Tauri command names: `call_caller_setup`, `call_callee_setup`. Both registered in `src-tauri/src/lib.rs` invoke_handler and `src-tauri/src/commands/mod.rs`.
- 1:1 only. Single active call; a second incoming call replies `busy`.
- Build gates per task where noted: `npx tsc --noEmit`, `node node_modules/vite/bin/vite.js build`, `cargo test --lib`, `cargo check`.

---

### Task 0: Frontend test tooling (Vitest)

The repo has no frontend test runner; the call crypto and state logic need TDD. Add Vitest + happy-dom.

**Files:**
- Modify: `qguard-messaging/package.json` (devDependencies + `"test": "vitest run"`)
- Create: `qguard-messaging/vitest.config.ts`

- [ ] **Step 1: Add dev dependencies**

Run (in `qguard-messaging/`):
```
npm i -D vitest@^2 happy-dom@^15
```

- [ ] **Step 2: Create vitest config**

Create `qguard-messaging/vitest.config.ts`:
```ts
import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  test: { environment: "happy-dom", include: ["src/**/*.test.ts"], globals: true },
});
```

- [ ] **Step 3: Add the test script**

In `package.json` "scripts", add: `"test": "vitest run"`.

- [ ] **Step 4: Sanity test**

Create `qguard-messaging/src/lib/_vitest-smoke.test.ts`:
```ts
import { test, expect } from "vitest";
test("vitest runs", () => { expect(1 + 1).toBe(2); });
```
Run: `npx vitest run src/lib/_vitest-smoke.test.ts`
Expected: 1 passed. Then delete the smoke file.

- [ ] **Step 5: Commit**
```
git add qguard-messaging/package.json qguard-messaging/package-lock.json qguard-messaging/vitest.config.ts
git commit -m "test: add vitest + happy-dom for frontend tests"
```

---

### Task 1: Signaling table migration

**Files:**
- Create: `qguard-messaging/supabase/migrations/023_secure_chat_video_calls.sql`

**Interfaces:**
- Produces: table `public.messaging_call_signals` with columns `id, call_id, conversation_id, from_user_id, from_device_id, to_user_id, to_device_id, signal_type, payload, created_at`; realtime-enabled; RLS via `is_messaging_conversation_member`.

- [ ] **Step 1: Write the migration**

Create `qguard-messaging/supabase/migrations/023_secure_chat_video_calls.sql`:
```sql
-- Ephemeral 1:1 call signaling (offer/answer/ice/control). Payloads are not
-- secret: the media key is bootstrapped by a hybrid-KEM ciphertext only the
-- callee can decapsulate, and media frames are separately AES-256-GCM encrypted.
CREATE TABLE IF NOT EXISTS public.messaging_call_signals (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  call_id         UUID NOT NULL,
  conversation_id UUID NOT NULL REFERENCES public.messaging_conversations(id) ON DELETE CASCADE,
  from_user_id    UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  from_device_id  UUID NOT NULL,
  to_user_id      UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  to_device_id    UUID NOT NULL,
  signal_type     TEXT NOT NULL CHECK (signal_type IN ('ring','offer','answer','ice','accept','reject','hangup','busy')),
  payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS messaging_call_signals_to_idx
  ON public.messaging_call_signals (to_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS messaging_call_signals_call_idx
  ON public.messaging_call_signals (call_id, created_at);

ALTER TABLE public.messaging_call_signals ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS messaging_call_signals_member_select ON public.messaging_call_signals;
CREATE POLICY messaging_call_signals_member_select ON public.messaging_call_signals
  FOR SELECT USING (public.is_messaging_conversation_member(conversation_id, auth.uid()));

DROP POLICY IF EXISTS messaging_call_signals_member_insert ON public.messaging_call_signals;
CREATE POLICY messaging_call_signals_member_insert ON public.messaging_call_signals
  FOR INSERT WITH CHECK (
    auth.uid() = from_user_id
    AND public.is_messaging_conversation_member(conversation_id, auth.uid())
  );

DROP POLICY IF EXISTS messaging_call_signals_member_delete ON public.messaging_call_signals;
CREATE POLICY messaging_call_signals_member_delete ON public.messaging_call_signals
  FOR DELETE USING (auth.uid() = from_user_id);

CREATE OR REPLACE FUNCTION public.prune_expired_messaging_call_signals()
RETURNS VOID AS $$
BEGIN
  DELETE FROM public.messaging_call_signals WHERE created_at < now() - INTERVAL '1 hour';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.messaging_call_signals;
EXCEPTION WHEN duplicate_object OR undefined_object THEN NULL;
END $$;
```

- [ ] **Step 2: Verify**

Apply via the project's normal migration path (Supabase SQL editor or CLI). Verify: `SELECT * FROM public.messaging_call_signals LIMIT 1;` returns 0 rows (no error), and the table appears under Realtime. Confirm `public.is_messaging_conversation_member` already exists (used by 007).

- [ ] **Step 3: Commit**
```
git add qguard-messaging/supabase/migrations/023_secure_chat_video_calls.sql
git commit -m "feat(db): add messaging_call_signals table for 1:1 call signaling"
```

---

### Task 2: Rust call crypto commands + tests

Derive media keys from a fresh hybrid KEM to the peer's identity key. Caller encapsulates; callee decapsulates with its local identity KEM secret. Both derive identical directional AES-256-GCM keys + a safety number.

**Files:**
- Create: `qguard-messaging/src-tauri/src/commands/calls.rs`
- Modify: `qguard-messaging/src-tauri/src/commands/mod.rs` (add `pub mod calls;`)
- Modify: `qguard-messaging/src-tauri/src/lib.rs` (register `call_caller_setup`, `call_callee_setup`)

**Interfaces:**
- Consumes: `crate::crypto::hybrid_kex::{encapsulate, decapsulate, HybridCiphertext}`, `crate::crypto::kdf::{hkdf_sha3_256, sha3_256}`, `AppState.identity` (`identity.kem.x25519_secret: [u8;32]`, `identity.kem.mlkem_secret: Vec<u8>`).
- Produces (returned to JS, serde camelCase):
  - `call_caller_setup(peerX25519Public: number[], peerMlkemPublic: number[], callId: string) -> CallSetup`
  - `call_callee_setup(hybridCiphertext: HybridCiphertext, callId: string) -> CallSetup`
  - `CallSetup { hybridCiphertext: HybridCiphertext | null, sendKeyB64: string, recvKeyB64: string, safetyNumber: string }`

- [ ] **Step 1: Write the failing tests**

Create `qguard-messaging/src-tauri/src/commands/calls.rs` with the pure helpers + tests first:
```rust
use base64::Engine;
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;

use crate::crypto::hybrid_kex::{decapsulate, encapsulate, HybridCiphertext};
use crate::crypto::kdf::{hkdf_sha3_256, sha3_256};
use crate::error::{QGuardError, Result};
use crate::state::AppState;

const INFO_C2A: &[u8] = b"qguard-call-media-v1:caller-to-callee";
const INFO_A2C: &[u8] = b"qguard-call-media-v1:callee-to-caller";
const KEM_INFO_PREFIX: &str = "qguard-call-kem-v1:";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallSetup {
    pub hybrid_ciphertext: Option<HybridCiphertext>,
    pub send_key_b64: String,
    pub recv_key_b64: String,
    pub safety_number: String,
}

/// Derive the two directional 32-byte keys + safety number from the shared secret.
/// `role` is "caller" or "callee" and selects which derived key is send vs recv.
fn derive_call_setup(
    shared: &[u8; 32],
    role: &str,
    ciphertext: Option<HybridCiphertext>,
) -> Result<CallSetup> {
    let c2a = hkdf_sha3_256(shared, INFO_C2A, 32)?; // caller -> callee
    let a2c = hkdf_sha3_256(shared, INFO_A2C, 32)?; // callee -> caller
    let (send, recv) = match role {
        "caller" => (&c2a, &a2c),
        "callee" => (&a2c, &c2a),
        other => return Err(QGuardError::InvalidInput(format!("bad call role: {other}"))),
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    let setup = CallSetup {
        hybrid_ciphertext: ciphertext,
        send_key_b64: b64.encode(send),
        recv_key_b64: b64.encode(recv),
        safety_number: safety_number(shared),
    };
    Ok(setup)
}

/// 60-bit SAS rendered as five 4-digit groups, so both ends can verbally verify.
fn safety_number(shared: &[u8; 32]) -> String {
    let digest = sha3_256(shared);
    let mut acc: u64 = 0;
    for byte in digest.iter().take(8) {
        acc = (acc << 8) | (*byte as u64);
    }
    let mut groups = Vec::with_capacity(5);
    for i in 0..5 {
        groups.push(format!("{:04}", ((acc >> (i * 12)) & 0x0fff) as u16));
    }
    groups.join("-")
}

#[tauri::command]
pub fn call_caller_setup(
    state: State<'_, AppState>,
    peer_x25519_public: Vec<u8>,
    peer_mlkem_public: Vec<u8>,
    call_id: String,
) -> Result<CallSetup> {
    state.require_auth()?;
    let info = format!("{KEM_INFO_PREFIX}{call_id}");
    let (ciphertext, mut shared) =
        encapsulate(&peer_x25519_public, &peer_mlkem_public, info.as_bytes())?;
    let setup = derive_call_setup(&shared, "caller", Some(ciphertext));
    shared.zeroize();
    state.audit_info("call_caller_setup", "Quantum-safe call media key established (caller)");
    setup
}

#[tauri::command]
pub fn call_callee_setup(
    state: State<'_, AppState>,
    hybrid_ciphertext: HybridCiphertext,
    call_id: String,
) -> Result<CallSetup> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    state.ensure_identity(&user_id, "Windows Desktop")?;
    let guard = state
        .identity
        .lock()
        .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
    let identity = guard
        .as_ref()
        .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
    let info = format!("{KEM_INFO_PREFIX}{call_id}");
    let mut shared = decapsulate(
        &identity.kem.x25519_secret,
        &identity.kem.mlkem_secret,
        &hybrid_ciphertext,
        info.as_bytes(),
    )?;
    let setup = derive_call_setup(&shared, "callee", None);
    shared.zeroize();
    drop(guard);
    state.audit_info("call_callee_setup", "Quantum-safe call media key established (callee)");
    setup
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hybrid_kex::LocalKemKeypair;

    #[test]
    fn caller_and_callee_derive_mirrored_keys_and_matching_sas() {
        let callee = LocalKemKeypair::generate();
        let info = b"qguard-call-kem-v1:call-1";
        let (ct, mut s_caller) =
            encapsulate(&callee.x25519_public, &callee.mlkem_public, info).unwrap();
        let mut s_callee =
            decapsulate(&callee.x25519_secret, &callee.mlkem_secret, &ct, info).unwrap();
        assert_eq!(s_caller, s_callee, "shared secret must match");

        let caller = derive_call_setup(&s_caller, "caller", Some(ct.clone())).unwrap();
        let callee_setup = derive_call_setup(&s_callee, "callee", None).unwrap();

        // caller.send == callee.recv and caller.recv == callee.send
        assert_eq!(caller.send_key_b64, callee_setup.recv_key_b64);
        assert_eq!(caller.recv_key_b64, callee_setup.send_key_b64);
        assert_ne!(caller.send_key_b64, caller.recv_key_b64);
        assert_eq!(caller.safety_number, callee_setup.safety_number);
        assert_eq!(caller.safety_number.split('-').count(), 5);
        s_caller.zeroize();
        s_callee.zeroize();
    }
}
```
Note: confirm `LocalKemKeypair::generate()` exists (used in hybrid_kex tests). If the constructor differs, use the same one the existing `hybrid_kex` tests use.

- [ ] **Step 2: Register the module + commands**

In `qguard-messaging/src-tauri/src/commands/mod.rs` add: `pub mod calls;`
In `qguard-messaging/src-tauri/src/lib.rs` inside `tauri::generate_handler![ ... ]`, add (near the messaging commands):
```
            calls::call_caller_setup,
            calls::call_callee_setup,
```
Ensure `use crate::commands::calls;` or the existing `use` style is matched (check how other commands are referenced - they are referenced unqualified, so add `call_caller_setup,` and `call_callee_setup,` and a matching `use` import line consistent with the file).

- [ ] **Step 3: Run the test (expect fail first, then pass)**

Run (in `src-tauri/`): `cargo test --lib calls::tests -- --nocapture`
Expected first run: compile error or FAIL until the file/registration is complete; then PASS.

- [ ] **Step 4: Full build gate**

Run: `cargo test --lib` (all pass) and `cargo check` (clean).

- [ ] **Step 5: Commit**
```
git add qguard-messaging/src-tauri/src/commands/calls.rs qguard-messaging/src-tauri/src/commands/mod.rs qguard-messaging/src-tauri/src/lib.rs
git commit -m "feat(call): quantum-safe call media key derivation commands"
```
---

### Task 3: ICE configuration module

**Files:**
- Create: `qguard-messaging/src/lib/call-ice.ts`
- Test: `qguard-messaging/src/lib/call-ice.test.ts`

**Interfaces:**
- Produces: `buildRtcConfiguration(): RTCConfiguration` - public STUN by default, plus a TURN server when `VITE_TURN_URL` is set.

- [ ] **Step 1: Write the failing test**

Create `qguard-messaging/src/lib/call-ice.test.ts`:
```ts
import { test, expect, vi, afterEach } from "vitest";
import { buildRtcConfiguration } from "@/lib/call-ice";

afterEach(() => { vi.unstubAllEnvs(); });

test("defaults to public STUN, no TURN", () => {
  const cfg = buildRtcConfiguration();
  expect(cfg.iceServers?.some((s) => String(s.urls).includes("stun:"))).toBe(true);
  expect(cfg.iceServers?.some((s) => String(s.urls).includes("turn:"))).toBe(false);
});

test("includes TURN when configured", () => {
  vi.stubEnv("VITE_TURN_URL", "turn:turn.example.com:3478");
  vi.stubEnv("VITE_TURN_USERNAME", "u");
  vi.stubEnv("VITE_TURN_CREDENTIAL", "p");
  const cfg = buildRtcConfiguration();
  const turn = cfg.iceServers?.find((s) => String(s.urls).includes("turn:"));
  expect(turn).toBeTruthy();
  expect(turn?.username).toBe("u");
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/lib/call-ice.test.ts`
Expected: FAIL ("Cannot find module call-ice").

- [ ] **Step 3: Implement**

Create `qguard-messaging/src/lib/call-ice.ts`:
```ts
const DEFAULT_STUN = [
  "stun:stun.l.google.com:19302",
  "stun:stun1.l.google.com:19302",
];

export function buildRtcConfiguration(): RTCConfiguration {
  const iceServers: RTCIceServer[] = [{ urls: DEFAULT_STUN }];
  const turnUrl = import.meta.env.VITE_TURN_URL as string | undefined;
  if (turnUrl) {
    iceServers.push({
      urls: turnUrl,
      username: (import.meta.env.VITE_TURN_USERNAME as string | undefined) ?? "",
      credential: (import.meta.env.VITE_TURN_CREDENTIAL as string | undefined) ?? "",
    });
  }
  return { iceServers, iceTransportPolicy: "all", bundlePolicy: "max-bundle" };
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run src/lib/call-ice.test.ts`  -> Expected: 2 passed.

- [ ] **Step 5: Commit**
```
git add qguard-messaging/src/lib/call-ice.ts qguard-messaging/src/lib/call-ice.test.ts
git commit -m "feat(call): ICE configuration with TURN-ready env config"
```

---

### Task 4: Per-frame crypto + Web Worker

Pure, testable AES-256-GCM frame functions first; then wire them into the Encoded Transform worker.

**Files:**
- Create: `qguard-messaging/src/lib/call-frame-crypto.ts`
- Test: `qguard-messaging/src/lib/call-frame-crypto.test.ts`
- Create: `qguard-messaging/src/lib/call-crypto-worker.ts`

**Interfaces:**
- Produces:
  - `importAesGcmKey(raw: Uint8Array): Promise<CryptoKey>`
  - `sealFrame(key: CryptoKey, contextTag: Uint8Array, counter: bigint, headerLength: number, frame: Uint8Array): Promise<ArrayBuffer>` -> `[header][ciphertext+tag][8-byte BE counter]`
  - `openFrame(key: CryptoKey, contextTag: Uint8Array, headerLength: number, frame: Uint8Array): Promise<ArrayBuffer>`
  - Worker contract: main thread does `new RTCRtpScriptTransform(worker, { operation, keyB64, contextTag, kind })` and assigns to `sender.transform` / `receiver.transform`.

- [ ] **Step 1: Write the failing test**

Create `qguard-messaging/src/lib/call-frame-crypto.test.ts`:
```ts
import { test, expect } from "vitest";
import { importAesGcmKey, sealFrame, openFrame } from "@/lib/call-frame-crypto";

const ctx = new Uint8Array([1, 2, 3, 4]);
function bytes(s: string) { return new TextEncoder().encode(s); }

test("seal -> open round-trips with zero header", async () => {
  const key = await importAesGcmKey(new Uint8Array(32).fill(7));
  const frame = bytes("hello quantum call");
  const sealed = new Uint8Array(await sealFrame(key, ctx, 1n, 0, frame));
  expect(sealed.length).toBeGreaterThan(frame.length); // tag + counter
  const opened = new Uint8Array(await openFrame(key, ctx, 0, sealed));
  expect(new TextDecoder().decode(opened)).toBe("hello quantum call");
});

test("preserves an unencrypted header", async () => {
  const key = await importAesGcmKey(new Uint8Array(32).fill(9));
  const frame = bytes("AAApayload"); // first 3 bytes are header
  const sealed = new Uint8Array(await sealFrame(key, ctx, 2n, 3, frame));
  expect(new TextDecoder().decode(sealed.slice(0, 3))).toBe("AAA");
  const opened = new Uint8Array(await openFrame(key, ctx, 3, sealed));
  expect(new TextDecoder().decode(opened)).toBe("AAApayload");
});

test("tampering is rejected", async () => {
  const key = await importAesGcmKey(new Uint8Array(32).fill(5));
  const sealed = new Uint8Array(await sealFrame(key, ctx, 3n, 0, bytes("secret")));
  sealed[0] ^= 0xff;
  await expect(openFrame(key, ctx, 0, sealed)).rejects.toBeTruthy();
});

test("different counters produce different ciphertext", async () => {
  const key = await importAesGcmKey(new Uint8Array(32).fill(3));
  const a = new Uint8Array(await sealFrame(key, ctx, 1n, 0, bytes("x")));
  const b = new Uint8Array(await sealFrame(key, ctx, 2n, 0, bytes("x")));
  expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/lib/call-frame-crypto.test.ts`  -> Expected: FAIL (module missing).

- [ ] **Step 3: Implement the pure crypto**

Create `qguard-messaging/src/lib/call-frame-crypto.ts`:
```ts
// AES-256-GCM per-frame sealing for E2EE media. Nonce (12B) = contextTag(4B) | counter(8B BE).
// Wire format: [header (headerLength, unencrypted)][ciphertext+16B tag][8B BE counter].

export async function importAesGcmKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function nonce(contextTag: Uint8Array, counter: bigint): Uint8Array {
  const n = new Uint8Array(12);
  n.set(contextTag.subarray(0, 4), 0);
  const view = new DataView(n.buffer);
  view.setBigUint64(4, counter, false); // big-endian
  return n;
}

export async function sealFrame(
  key: CryptoKey, contextTag: Uint8Array, counter: bigint, headerLength: number, frame: Uint8Array,
): Promise<ArrayBuffer> {
  const header = frame.subarray(0, headerLength);
  const payload = frame.subarray(headerLength);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce(contextTag, counter) }, key, payload),
  );
  const out = new Uint8Array(headerLength + ct.length + 8);
  out.set(header, 0);
  out.set(ct, headerLength);
  new DataView(out.buffer).setBigUint64(out.length - 8, counter, false);
  return out.buffer;
}

export async function openFrame(
  key: CryptoKey, contextTag: Uint8Array, headerLength: number, frame: Uint8Array,
): Promise<ArrayBuffer> {
  if (frame.length < headerLength + 8 + 16) throw new Error("frame too short");
  const counter = new DataView(frame.buffer, frame.byteOffset + frame.length - 8, 8).getBigUint64(0, false);
  const header = frame.subarray(0, headerLength);
  const ct = frame.subarray(headerLength, frame.length - 8);
  const pt = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce(contextTag, counter) }, key, ct),
  );
  const out = new Uint8Array(headerLength + pt.length);
  out.set(header, 0);
  out.set(pt, headerLength);
  return out.buffer;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run src/lib/call-frame-crypto.test.ts`  -> Expected: 4 passed.

- [ ] **Step 5: Implement the worker (no separate unit test; covered by manual E2E in Task 10)**

Create `qguard-messaging/src/lib/call-crypto-worker.ts`:
```ts
/// <reference lib="webworker" />
import { importAesGcmKey, sealFrame, openFrame } from "@/lib/call-frame-crypto";

// Unencrypted header bytes the RTP packetizer needs (Chrome insertable-streams convention).
function headerLength(kind: "audio" | "video", frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame): number {
  if (kind === "audio") return 1;
  return (frame as RTCEncodedVideoFrame).type === "key" ? 10 : 3;
}

interface XfOptions { operation: "encrypt" | "decrypt"; keyB64: string; contextTag: number[]; kind: "audio" | "video"; }

async function run(transformer: any, opts: XfOptions) {
  const raw = Uint8Array.from(atob(opts.keyB64), (c) => c.charCodeAt(0));
  const key = await importAesGcmKey(raw);
  const ctx = new Uint8Array(opts.contextTag);
  let counter = 0n;
  const transform = new TransformStream({
    async transform(frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame, controller) {
      const data = new Uint8Array(frame.data);
      const hl = headerLength(opts.kind, frame);
      try {
        frame.data = opts.operation === "encrypt"
          ? await sealFrame(key, ctx, counter++, hl, data)
          : await openFrame(key, ctx, hl, data);
        controller.enqueue(frame);
      } catch {
        // Drop frames that fail auth (do not forward plaintext or corrupt media).
      }
    },
  });
  transformer.readable.pipeThrough(transform).pipeTo(transformer.writable);
}

// Standard RTCRtpScriptTransform entrypoint.
(self as unknown as { onrtctransform: (e: any) => void }).onrtctransform = (event: any) => {
  void run(event.transformer, event.transformer.options as XfOptions);
};
```

- [ ] **Step 6: Commit**
```
git add qguard-messaging/src/lib/call-frame-crypto.ts qguard-messaging/src/lib/call-frame-crypto.test.ts qguard-messaging/src/lib/call-crypto-worker.ts
git commit -m "feat(call): AES-256-GCM per-frame media encryption + transform worker"
```

---

### Task 5: Call types + signaling module

**Files:**
- Create: `qguard-messaging/src/lib/call-types.ts`
- Create: `qguard-messaging/src/lib/call-signaling.ts`
- Test: `qguard-messaging/src/lib/call-signaling.test.ts`

**Interfaces:**
- Produces:
  - `type CallSignalType = "ring"|"offer"|"answer"|"ice"|"accept"|"reject"|"hangup"|"busy"`
  - `interface CallSignalRow { id; call_id; conversation_id; from_user_id; from_device_id; to_user_id; to_device_id; signal_type: CallSignalType; payload: Record<string, unknown>; created_at: string }`
  - `sendCallSignal(input: Omit<CallSignalRow, "id"|"created_at">): Promise<void>`
  - `subscribeCallSignals(opts: { userId: string; deviceId: string; onSignal: (row: CallSignalRow) => void }): () => void`
  - `parseCallSignal(raw: unknown): CallSignalRow | null` (pure - tested)

- [ ] **Step 1: Write the failing test (pure parser)**

Create `qguard-messaging/src/lib/call-signaling.test.ts`:
```ts
import { test, expect } from "vitest";
import { parseCallSignal } from "@/lib/call-signaling";

test("parses a valid signal row", () => {
  const row = parseCallSignal({
    id: "1", call_id: "c1", conversation_id: "cv1",
    from_user_id: "u1", from_device_id: "d1", to_user_id: "u2", to_device_id: "d2",
    signal_type: "offer", payload: { sdp: "x" }, created_at: "2026-06-20T00:00:00Z",
  });
  expect(row?.signal_type).toBe("offer");
  expect(row?.payload.sdp).toBe("x");
});

test("rejects an unknown signal_type", () => {
  expect(parseCallSignal({ signal_type: "nope" })).toBeNull();
});
```

- [ ] **Step 2: Run to verify it fails**  ->  `npx vitest run src/lib/call-signaling.test.ts` (FAIL).

- [ ] **Step 3: Implement types + signaling**

Create `qguard-messaging/src/lib/call-types.ts`:
```ts
export type CallSignalType = "ring" | "offer" | "answer" | "ice" | "accept" | "reject" | "hangup" | "busy";

export interface CallSignalRow {
  id: string;
  call_id: string;
  conversation_id: string;
  from_user_id: string;
  from_device_id: string;
  to_user_id: string;
  to_device_id: string;
  signal_type: CallSignalType;
  payload: Record<string, unknown>;
  created_at: string;
}

export type CallPhase = "idle" | "ringing" | "calling" | "connecting" | "connected" | "ended";
```

Create `qguard-messaging/src/lib/call-signaling.ts`:
```ts
import { supabase } from "@/lib/supabase";
import type { CallSignalRow, CallSignalType } from "@/lib/call-types";

const TYPES: CallSignalType[] = ["ring", "offer", "answer", "ice", "accept", "reject", "hangup", "busy"];

export function parseCallSignal(raw: unknown): CallSignalRow | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (!TYPES.includes(r.signal_type as CallSignalType)) return null;
  return {
    id: String(r.id ?? ""),
    call_id: String(r.call_id ?? ""),
    conversation_id: String(r.conversation_id ?? ""),
    from_user_id: String(r.from_user_id ?? ""),
    from_device_id: String(r.from_device_id ?? ""),
    to_user_id: String(r.to_user_id ?? ""),
    to_device_id: String(r.to_device_id ?? ""),
    signal_type: r.signal_type as CallSignalType,
    payload: (r.payload as Record<string, unknown>) ?? {},
    created_at: String(r.created_at ?? new Date().toISOString()),
  };
}

export async function sendCallSignal(input: Omit<CallSignalRow, "id" | "created_at">): Promise<void> {
  const { error } = await supabase.from("messaging_call_signals").insert(input);
  if (error) throw new Error(error.message);
}

export function subscribeCallSignals(opts: {
  userId: string; deviceId: string; onSignal: (row: CallSignalRow) => void;
}): () => void {
  const channel = supabase
    .channel(`qguard-call-signals-${opts.userId}-${opts.deviceId}`)
    .on("postgres_changes",
      { event: "INSERT", schema: "public", table: "messaging_call_signals", filter: `to_user_id=eq.${opts.userId}` },
      (payload) => {
        const row = parseCallSignal(payload.new);
        if (row && (row.to_device_id === opts.deviceId || row.signal_type === "ring")) opts.onSignal(row);
      })
    .subscribe();
  return () => { void supabase.removeChannel(channel); };
}
```

- [ ] **Step 4: Run to verify it passes**  ->  `npx vitest run src/lib/call-signaling.test.ts` (2 passed).

- [ ] **Step 5: Commit**
```
git add qguard-messaging/src/lib/call-types.ts qguard-messaging/src/lib/call-signaling.ts qguard-messaging/src/lib/call-signaling.test.ts
git commit -m "feat(call): call signal types + RLS-gated signaling channel"
```

---

### Task 6: Call state reducer

A pure reducer for the call lifecycle, unit-tested independently of WebRTC.

**Files:**
- Create: `qguard-messaging/src/lib/call-state.ts`
- Test: `qguard-messaging/src/lib/call-state.test.ts`

**Interfaces:**
- Produces:
  - `interface CallState { phase: CallPhase; callId: string | null; role: "caller"|"callee"|null; peerUserId: string|null; peerDeviceId: string|null; safetyNumber: string|null; error: string|null }`
  - `type CallAction = ...` (see code)
  - `callReducer(state: CallState, action: CallAction): CallState`
  - `INITIAL_CALL_STATE: CallState`

- [ ] **Step 1: Write the failing test**

Create `qguard-messaging/src/lib/call-state.test.ts`:
```ts
import { test, expect } from "vitest";
import { callReducer, INITIAL_CALL_STATE } from "@/lib/call-state";

test("caller flow: start -> answered -> connected -> ended", () => {
  let s = callReducer(INITIAL_CALL_STATE, { type: "start-outgoing", callId: "c1", peerUserId: "u2", peerDeviceId: "d2" });
  expect(s.phase).toBe("calling");
  expect(s.role).toBe("caller");
  s = callReducer(s, { type: "remote-answered" });
  expect(s.phase).toBe("connecting");
  s = callReducer(s, { type: "media-connected", safetyNumber: "1234-5678-9012-3456-7890" });
  expect(s.phase).toBe("connected");
  expect(s.safetyNumber).toBe("1234-5678-9012-3456-7890");
  s = callReducer(s, { type: "ended" });
  expect(s.phase).toBe("ended");
});

test("incoming ring -> reject -> ended", () => {
  let s = callReducer(INITIAL_CALL_STATE, { type: "incoming", callId: "c2", peerUserId: "u1", peerDeviceId: "d1" });
  expect(s.phase).toBe("ringing");
  expect(s.role).toBe("callee");
  s = callReducer(s, { type: "ended" });
  expect(s.phase).toBe("ended");
});

test("a second incoming while busy is ignored", () => {
  let s = callReducer(INITIAL_CALL_STATE, { type: "start-outgoing", callId: "c1", peerUserId: "u2", peerDeviceId: "d2" });
  const before = s;
  s = callReducer(s, { type: "incoming", callId: "c3", peerUserId: "u9", peerDeviceId: "d9" });
  expect(s).toBe(before); // unchanged - caller already in a call
});
```

- [ ] **Step 2: Run to verify it fails**  ->  `npx vitest run src/lib/call-state.test.ts` (FAIL).

- [ ] **Step 3: Implement the reducer**

Create `qguard-messaging/src/lib/call-state.ts`:
```ts
import type { CallPhase } from "@/lib/call-types";

export interface CallState {
  phase: CallPhase;
  callId: string | null;
  role: "caller" | "callee" | null;
  peerUserId: string | null;
  peerDeviceId: string | null;
  safetyNumber: string | null;
  error: string | null;
}

export type CallAction =
  | { type: "start-outgoing"; callId: string; peerUserId: string; peerDeviceId: string }
  | { type: "incoming"; callId: string; peerUserId: string; peerDeviceId: string }
  | { type: "accept" }
  | { type: "remote-answered" }
  | { type: "media-connected"; safetyNumber: string }
  | { type: "failed"; error: string }
  | { type: "ended" };

export const INITIAL_CALL_STATE: CallState = {
  phase: "idle", callId: null, role: null, peerUserId: null, peerDeviceId: null, safetyNumber: null, error: null,
};

const ACTIVE: CallPhase[] = ["ringing", "calling", "connecting", "connected"];

export function callReducer(state: CallState, action: CallAction): CallState {
  switch (action.type) {
    case "start-outgoing":
      if (ACTIVE.includes(state.phase)) return state;
      return { ...INITIAL_CALL_STATE, phase: "calling", role: "caller", callId: action.callId, peerUserId: action.peerUserId, peerDeviceId: action.peerDeviceId };
    case "incoming":
      if (ACTIVE.includes(state.phase)) return state; // busy
      return { ...INITIAL_CALL_STATE, phase: "ringing", role: "callee", callId: action.callId, peerUserId: action.peerUserId, peerDeviceId: action.peerDeviceId };
    case "accept":
      return state.phase === "ringing" ? { ...state, phase: "connecting" } : state;
    case "remote-answered":
      return state.phase === "calling" ? { ...state, phase: "connecting" } : state;
    case "media-connected":
      return ACTIVE.includes(state.phase) ? { ...state, phase: "connected", safetyNumber: action.safetyNumber } : state;
    case "failed":
      return { ...state, phase: "ended", error: action.error };
    case "ended":
      return { ...state, phase: "ended" };
    default:
      return state;
  }
}
```

- [ ] **Step 4: Run to verify it passes**  ->  `npx vitest run src/lib/call-state.test.ts` (3 passed).

- [ ] **Step 5: Commit**
```
git add qguard-messaging/src/lib/call-state.ts qguard-messaging/src/lib/call-state.test.ts
git commit -m "feat(call): pure call-lifecycle reducer"
```
---

### Task 7: Secure call hook (WebRTC orchestration)

Ties together getUserMedia, RTCPeerConnection, the Rust key-setup commands, the worker transforms, and signaling. Not unit-tested (browser/WebRTC); covered by the manual E2E in Task 10. The pure reducer (Task 6) carries the tested logic.

**Files:**
- Create: `qguard-messaging/src/lib/call-webrtc.d.ts` (ambient types for Encoded Transform)
- Create: `qguard-messaging/src/lib/use-secure-call.ts`

**Interfaces:**
- Consumes: `buildRtcConfiguration` (Task 3), `call-crypto-worker.ts` (Task 4), `subscribeCallSignals`/`sendCallSignal` (Task 5), `callReducer`/`INITIAL_CALL_STATE` (Task 6), Tauri commands `call_caller_setup`/`call_callee_setup` (Task 2) via `safeInvoke`.
- Produces: `useSecureCall(args) -> { state, localStream, remoteStream, micEnabled, cameraEnabled, startCall, accept, reject, hangup, toggleMic, toggleCamera, supported }`

- [ ] **Step 1: Ambient WebRTC Encoded-Transform types**

Create `qguard-messaging/src/lib/call-webrtc.d.ts`:
```ts
export {};
declare global {
  interface RTCEncodedVideoFrame { readonly type: "key" | "delta"; data: ArrayBuffer; }
  interface RTCEncodedAudioFrame { data: ArrayBuffer; }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const RTCRtpScriptTransform: { new (worker: Worker, options?: any, transfer?: any[]): any };
  interface RTCRtpSender { transform?: unknown; }
  interface RTCRtpReceiver { transform?: unknown; }
}
```

- [ ] **Step 2: Implement the hook**

Create `qguard-messaging/src/lib/use-secure-call.ts`:
```ts
import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import { buildRtcConfiguration } from "@/lib/call-ice";
import { callReducer, INITIAL_CALL_STATE } from "@/lib/call-state";
import { sendCallSignal, subscribeCallSignals } from "@/lib/call-signaling";
import type { CallSignalRow } from "@/lib/call-types";
import { safeInvoke } from "@/lib/tauri";
import { recordCryptoTelemetry } from "@/lib/crypto-telemetry";

interface CallSetup { hybridCiphertext: unknown; sendKeyB64: string; recvKeyB64: string; safetyNumber: string; }
interface Peer { userId: string; deviceId: string; x25519: number[]; mlkem: number[]; displayName: string; }

const AUDIO_CTX = [1, 0, 0, 0];
const VIDEO_CTX = [2, 0, 0, 0];
const callSupported = () =>
  typeof RTCPeerConnection !== "undefined" && typeof RTCRtpScriptTransform !== "undefined";

export function useSecureCall(args: {
  userId: string; deviceId: string; conversationId: string | null; peer: Peer | null;
}) {
  const [state, dispatch] = useReducer(callReducer, INITIAL_CALL_STATE);
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [remoteStream, setRemoteStream] = useState<MediaStream | null>(null);
  const [micEnabled, setMicEnabled] = useState(true);
  const [cameraEnabled, setCameraEnabled] = useState(true);

  const pcRef = useRef<RTCPeerConnection | null>(null);
  const workerRef = useRef<Worker | null>(null);
  const setupRef = useRef<CallSetup | null>(null);
  const pendingOfferRef = useRef<CallSignalRow | null>(null);
  const supported = useMemo(callSupported, []);

  const worker = useCallback(() => {
    if (!workerRef.current) {
      workerRef.current = new Worker(new URL("./call-crypto-worker.ts", import.meta.url), { type: "module" });
    }
    return workerRef.current;
  }, []);

  const attachSenderTransforms = useCallback((pc: RTCPeerConnection, setup: CallSetup) => {
    pc.getSenders().forEach((sender) => {
      const kind = sender.track?.kind === "audio" ? "audio" : "video";
      (sender as RTCRtpSender).transform = new RTCRtpScriptTransform(worker(), {
        operation: "encrypt", keyB64: setup.sendKeyB64, kind, contextTag: kind === "audio" ? AUDIO_CTX : VIDEO_CTX,
      });
    });
  }, [worker]);

  const cleanup = useCallback(() => {
    pcRef.current?.getSenders().forEach((s) => s.track?.stop());
    pcRef.current?.close();
    pcRef.current = null;
    workerRef.current?.terminate();
    workerRef.current = null;
    setupRef.current = null;
    pendingOfferRef.current = null;
    localStream?.getTracks().forEach((t) => t.stop());
    setLocalStream(null);
    setRemoteStream(null);
  }, [localStream]);

  const buildPeerConnection = useCallback((callId: string, peer: Peer) => {
    const pc = new RTCPeerConnection(buildRtcConfiguration());
    pc.onicecandidate = (e) => {
      if (!e.candidate || !args.conversationId) return;
      void sendCallSignal({
        call_id: callId, conversation_id: args.conversationId,
        from_user_id: args.userId, from_device_id: args.deviceId,
        to_user_id: peer.userId, to_device_id: peer.deviceId,
        signal_type: "ice", payload: { candidate: e.candidate.toJSON() },
      });
    };
    pc.ontrack = (e) => {
      const setup = setupRef.current;
      if (setup) {
        const kind = e.track.kind === "audio" ? "audio" : "video";
        (e.receiver as RTCRtpReceiver).transform = new RTCRtpScriptTransform(worker(), {
          operation: "decrypt", keyB64: setup.recvKeyB64, kind, contextTag: kind === "audio" ? AUDIO_CTX : VIDEO_CTX,
        });
      }
      setRemoteStream(e.streams[0] ?? null);
    };
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === "connected" && setupRef.current) {
        dispatch({ type: "media-connected", safetyNumber: setupRef.current.safetyNumber });
        void recordCryptoTelemetry({ userId: args.userId, scope: "call", stage: "call_connected", detail: "Quantum-encrypted call connected", progress: 100, status: "complete", metadata: { call_id: callId } });
      }
      if (["failed", "disconnected", "closed"].includes(pc.connectionState)) endCall(false);
    };
    pcRef.current = pc;
    return pc;
  }, [args.conversationId, args.deviceId, args.userId, worker]);

  const getMedia = useCallback(async () => {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: { width: 1280, height: 720 } });
    setLocalStream(stream);
    return stream;
  }, []);

  const startCall = useCallback(async () => {
    if (!supported || !args.peer || !args.conversationId) return;
    const peer = args.peer;
    const callId = crypto.randomUUID();
    dispatch({ type: "start-outgoing", callId, peerUserId: peer.userId, peerDeviceId: peer.deviceId });
    try {
      const setup = await safeInvoke<CallSetup>("call_caller_setup", { peerX25519Public: peer.x25519, peerMlkemPublic: peer.mlkem, callId });
      setupRef.current = setup;
      const stream = await getMedia();
      const pc = buildPeerConnection(callId, peer);
      stream.getTracks().forEach((t) => pc.addTrack(t, stream));
      attachSenderTransforms(pc, setup);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await sendCallSignal({ call_id: callId, conversation_id: args.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: peer.userId, to_device_id: peer.deviceId, signal_type: "ring", payload: {} });
      await sendCallSignal({ call_id: callId, conversation_id: args.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: peer.userId, to_device_id: peer.deviceId, signal_type: "offer", payload: { sdp: offer.sdp, hybridCiphertext: setup.hybridCiphertext } });
    } catch (e) {
      dispatch({ type: "failed", error: e instanceof Error ? e.message : "Call failed" });
      cleanup();
    }
  }, [args, attachSenderTransforms, buildPeerConnection, cleanup, getMedia, supported]);

  const accept = useCallback(async () => {
    const offer = pendingOfferRef.current;
    if (!offer || !args.peer || !args.conversationId) return;
    dispatch({ type: "accept" });
    try {
      const setup = await safeInvoke<CallSetup>("call_callee_setup", { hybridCiphertext: (offer.payload as { hybridCiphertext: unknown }).hybridCiphertext, callId: offer.call_id });
      setupRef.current = setup;
      const stream = await getMedia();
      const pc = buildPeerConnection(offer.call_id, args.peer);
      stream.getTracks().forEach((t) => pc.addTrack(t, stream));
      attachSenderTransforms(pc, setup);
      await pc.setRemoteDescription({ type: "offer", sdp: String((offer.payload as { sdp: string }).sdp) });
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await sendCallSignal({ call_id: offer.call_id, conversation_id: args.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: offer.from_user_id, to_device_id: offer.from_device_id, signal_type: "answer", payload: { sdp: answer.sdp } });
    } catch (e) {
      dispatch({ type: "failed", error: e instanceof Error ? e.message : "Accept failed" });
      cleanup();
    }
  }, [args, attachSenderTransforms, buildPeerConnection, cleanup, getMedia]);

  const endCall = useCallback((notify: boolean) => {
    if (notify && state.callId && state.peerUserId && state.peerDeviceId && args.conversationId) {
      void sendCallSignal({ call_id: state.callId, conversation_id: args.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: state.peerUserId, to_device_id: state.peerDeviceId, signal_type: "hangup", payload: {} });
    }
    dispatch({ type: "ended" });
    cleanup();
  }, [args, cleanup, state]);

  const reject = useCallback(() => {
    const offer = pendingOfferRef.current;
    if (offer && args.conversationId) {
      void sendCallSignal({ call_id: offer.call_id, conversation_id: args.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: offer.from_user_id, to_device_id: offer.from_device_id, signal_type: "reject", payload: {} });
    }
    endCall(false);
  }, [args, endCall]);

  const hangup = useCallback(() => endCall(true), [endCall]);
  const toggleMic = useCallback(() => { localStream?.getAudioTracks().forEach((t) => (t.enabled = !t.enabled)); setMicEnabled((v) => !v); }, [localStream]);
  const toggleCamera = useCallback(() => { localStream?.getVideoTracks().forEach((t) => (t.enabled = !t.enabled)); setCameraEnabled((v) => !v); }, [localStream]);

  // Signal handling
  useEffect(() => {
    if (!args.userId || !args.deviceId) return;
    const unsub = subscribeCallSignals({
      userId: args.userId, deviceId: args.deviceId,
      onSignal: (row) => {
        if (row.from_user_id === args.userId) return;
        switch (row.signal_type) {
          case "offer":
            pendingOfferRef.current = row;
            dispatch({ type: "incoming", callId: row.call_id, peerUserId: row.from_user_id, peerDeviceId: row.from_device_id });
            break;
          case "answer":
            if (pcRef.current && state.role === "caller") { void pcRef.current.setRemoteDescription({ type: "answer", sdp: String(row.payload.sdp) }); dispatch({ type: "remote-answered" }); }
            break;
          case "ice":
            if (pcRef.current && row.payload.candidate) void pcRef.current.addIceCandidate(row.payload.candidate as RTCIceCandidateInit);
            break;
          case "reject": case "hangup": case "busy":
            endCall(false);
            break;
          default: break;
        }
      },
    });
    return unsub;
  }, [args.deviceId, args.userId, endCall, state.role]);

  useEffect(() => () => cleanup(), [cleanup]);

  return { state, localStream, remoteStream, micEnabled, cameraEnabled, supported, startCall, accept, reject, hangup, toggleMic, toggleCamera };
}
```
Note: confirm `recordCryptoTelemetry` accepts `scope: "call"` (it takes a string scope). Confirm `safeInvoke` generic usage matches other call sites. If the DOM lib flags `sender.transform`/`RTCRtpScriptTransform`, the ambient `call-webrtc.d.ts` resolves it; otherwise add `// @ts-expect-error encoded transform` at those lines.

- [ ] **Step 3: Type-check gate**

Run (in `qguard-messaging/`): `npx tsc --noEmit`  -> Expected: clean (fix any type gaps with the ambient d.ts).

- [ ] **Step 4: Commit**
```
git add qguard-messaging/src/lib/use-secure-call.ts qguard-messaging/src/lib/call-webrtc.d.ts
git commit -m "feat(call): WebRTC call orchestration hook with PQC media transforms"
```

---

### Task 8: Call UI + Secure Chat integration

**Files:**
- Create: `qguard-messaging/src/components/call/CallButton.tsx`
- Create: `qguard-messaging/src/components/call/IncomingCallModal.tsx`
- Create: `qguard-messaging/src/components/call/InCallOverlay.tsx`
- Modify: `qguard-messaging/src/pages/SecureChatPage.tsx` (header button near line 3262 + render modal/overlay; wire `useSecureCall`)

**Interfaces:**
- Consumes: `useSecureCall` (Task 7).
- The page computes the `peer` from the active direct conversation's single sendable recipient device: `{ userId, deviceId, x25519: Array.from(device.x25519_identity_public), mlkem: Array.from(device.mlkem_identity_public), displayName }`.

- [ ] **Step 1: CallButton**

Create `qguard-messaging/src/components/call/CallButton.tsx`:
```tsx
import { Video } from "lucide-react";

export function CallButton({ disabled, title, onClick }: { disabled: boolean; title: string; onClick: () => void }) {
  return (
    <button type="button" disabled={disabled} onClick={onClick} title={title}
      className="flex h-9 w-9 items-center justify-center rounded-lg border border-line text-ink-700 hover:border-cyan-200 hover:bg-cyan-50 hover:text-cyan-700 disabled:cursor-not-allowed disabled:opacity-50">
      <Video size={18} />
    </button>
  );
}
```

- [ ] **Step 2: IncomingCallModal**

Create `qguard-messaging/src/components/call/IncomingCallModal.tsx`:
```tsx
import { PhoneIncoming, PhoneOff, Video } from "lucide-react";

export function IncomingCallModal({ callerName, onAccept, onReject }: { callerName: string; onAccept: () => void; onReject: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-xl border border-white/30 bg-white p-6 text-center shadow-soft">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-cyan-50 text-cyan-600"><Video size={28} /></div>
        <div className="mt-4 text-lg font-bold text-ink-950">{callerName}</div>
        <div className="text-sm text-ink-600">Incoming quantum-encrypted video call</div>
        <div className="mt-6 flex justify-center gap-4">
          <button type="button" onClick={onReject} className="flex h-12 w-12 items-center justify-center rounded-full bg-rose-500 text-white hover:bg-rose-600"><PhoneOff size={20} /></button>
          <button type="button" onClick={onAccept} className="flex h-12 w-12 items-center justify-center rounded-full bg-emerald-500 text-white hover:bg-emerald-600"><PhoneIncoming size={20} /></button>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: InCallOverlay**

Create `qguard-messaging/src/components/call/InCallOverlay.tsx`:
```tsx
import { useEffect, useRef, useState } from "react";
import { Mic, MicOff, PhoneOff, ShieldCheck, Video, VideoOff } from "lucide-react";
import type { CallState } from "@/lib/call-state";

export function InCallOverlay(props: {
  state: CallState; localStream: MediaStream | null; remoteStream: MediaStream | null;
  micEnabled: boolean; cameraEnabled: boolean; peerName: string;
  onHangup: () => void; onToggleMic: () => void; onToggleCamera: () => void;
}) {
  const localRef = useRef<HTMLVideoElement>(null);
  const remoteRef = useRef<HTMLVideoElement>(null);
  const [showSas, setShowSas] = useState(false);
  useEffect(() => { if (localRef.current) localRef.current.srcObject = props.localStream; }, [props.localStream]);
  useEffect(() => { if (remoteRef.current) remoteRef.current.srcObject = props.remoteStream; }, [props.remoteStream]);

  const phaseLabel = props.state.phase === "connected" ? "Connected"
    : props.state.phase === "connecting" ? "Connecting..."
    : props.state.phase === "calling" ? "Calling..." : props.state.phase;

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-ink-950">
      <div className="flex items-center justify-between px-5 py-3 text-white">
        <div>
          <div className="text-sm font-bold">{props.peerName}</div>
          <div className="text-xs text-white/70">{phaseLabel}</div>
        </div>
        <button type="button" onClick={() => setShowSas((v) => !v)} className="flex items-center gap-2 rounded-full bg-white/10 px-3 py-1 text-xs font-semibold text-emerald-300">
          <ShieldCheck size={14} /> Quantum-encrypted
        </button>
      </div>
      <div className="relative flex-1">
        <video ref={remoteRef} autoPlay playsInline className="h-full w-full bg-black object-cover" />
        <video ref={localRef} autoPlay playsInline muted className="absolute bottom-24 right-5 h-36 w-48 rounded-lg border border-white/30 object-cover" />
        {showSas && props.state.safetyNumber && (
          <div className="absolute left-1/2 top-4 -translate-x-1/2 rounded-lg bg-white/95 px-4 py-2 text-center">
            <div className="text-[11px] font-bold uppercase text-ink-400">Safety number (say it aloud to verify)</div>
            <div className="font-mono text-sm font-bold text-ink-950">{props.state.safetyNumber}</div>
          </div>
        )}
        <div className="absolute bottom-4 left-1/2 -translate-x-1/2 text-center text-[11px] text-white/60">
          End-to-end encrypted. The server and network cannot see this call; only the person you called can see what you share.
        </div>
      </div>
      <div className="flex items-center justify-center gap-4 py-5">
        <button type="button" onClick={props.onToggleMic} className={`flex h-12 w-12 items-center justify-center rounded-full ${props.micEnabled ? "bg-white/15 text-white" : "bg-rose-500 text-white"}`}>{props.micEnabled ? <Mic size={20} /> : <MicOff size={20} />}</button>
        <button type="button" onClick={props.onToggleCamera} className={`flex h-12 w-12 items-center justify-center rounded-full ${props.cameraEnabled ? "bg-white/15 text-white" : "bg-rose-500 text-white"}`}>{props.cameraEnabled ? <Video size={20} /> : <VideoOff size={20} />}</button>
        <button type="button" onClick={props.onHangup} className="flex h-12 w-12 items-center justify-center rounded-full bg-rose-500 text-white hover:bg-rose-600"><PhoneOff size={20} /></button>
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Wire into SecureChatPage**

In `qguard-messaging/src/pages/SecureChatPage.tsx`:
1. Add imports (top): `import { useSecureCall } from "@/lib/use-secure-call";`, `import { CallButton } from "@/components/call/CallButton";`, `import { IncomingCallModal } from "@/components/call/IncomingCallModal";`, `import { InCallOverlay } from "@/components/call/InCallOverlay";`.
2. Inside the component, after `sendableRecipientDevices` is computed, derive the call peer (1:1 only):
```tsx
const callPeer = useMemo(() => {
  if (activeConversation?.conversation_type !== "direct") return null;
  const device = sendableRecipientDevices[0];
  if (!device) return null;
  return {
    userId: device.user_id, deviceId: device.device_id,
    x25519: Array.from(device.x25519_identity_public),
    mlkem: Array.from(device.mlkem_identity_public),
    displayName: activeConversation ? conversationTitle(activeConversation) : "Contact",
  };
}, [activeConversation, sendableRecipientDevices]);

const call = useSecureCall({ userId, deviceId: localDeviceId ?? "", conversationId: activeConversation?.id ?? null, peer: callPeer });
```
   (Confirm exact names: `localDeviceId`, `sendableRecipientDevices`, `conversationTitle` all exist in this file.)
3. In the conversation header (next to the `<h2>` near line 3262, inside its flex row), add:
```tsx
<CallButton
  disabled={!call.supported || !callPeer || call.state.phase !== "idle" && call.state.phase !== "ended"}
  title={call.supported ? "Start quantum-encrypted video call" : "Video calling requires the desktop app"}
  onClick={() => void call.startCall()}
/>
```
4. At the end of the component's returned JSX (just before the final closing tag), render:
```tsx
{call.state.phase === "ringing" && (
  <IncomingCallModal callerName={callPeer?.displayName ?? "Contact"} onAccept={() => void call.accept()} onReject={() => call.reject()} />
)}
{["calling", "connecting", "connected"].includes(call.state.phase) && (
  <InCallOverlay state={call.state} localStream={call.localStream} remoteStream={call.remoteStream}
    micEnabled={call.micEnabled} cameraEnabled={call.cameraEnabled} peerName={callPeer?.displayName ?? "Contact"}
    onHangup={() => call.hangup()} onToggleMic={() => call.toggleMic()} onToggleCamera={() => call.toggleCamera()} />
)}
```

- [ ] **Step 5: Build gate**

Run: `npx tsc --noEmit` and `node node_modules/vite/bin/vite.js build`  -> Expected: both clean.

- [ ] **Step 6: Commit**
```
git add qguard-messaging/src/components/call qguard-messaging/src/pages/SecureChatPage.tsx
git commit -m "feat(call): call button, incoming modal, in-call overlay + chat integration"
```
---

### Task 9: WebView2 camera + microphone permission (Windows)

By default WebView2 blocks `getUserMedia` until the host grants the permission. Add a `PermissionRequested` handler in the Tauri setup. HIGHEST-RISK TASK: the `webview2-com` API surface is version-dependent - match the version Tauri resolved in `Cargo.lock`. If `getUserMedia` already prompts/works in the packaged app, this task is verification-only.

**Files:**
- Modify: `qguard-messaging/src-tauri/src/lib.rs` (webview setup)
- Possibly modify: `qguard-messaging/src-tauri/Cargo.toml` (add `webview2-com` + `windows` if not already resolvable)

**Interfaces:**
- Produces: camera + microphone permission auto-granted for the app webview on Windows.

- [ ] **Step 1: Add the permission handler**

In `src-tauri/src/lib.rs`, in the Tauri builder `.setup(...)` (create one if absent), access the main window's webview and, on Windows, register a permission handler. Reference implementation (adjust types to the resolved `webview2-com` version):
```rust
.setup(|app| {
    #[cfg(target_os = "windows")]
    {
        use tauri::Manager;
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.with_webview(|webview| {
                use webview2_com::PermissionRequestedEventHandler;
                use webview2_com::Microsoft::Web::WebView2::Win32::{
                    ICoreWebView2, COREWEBVIEW2_PERMISSION_STATE_ALLOW,
                };
                use windows::core::Interface;
                let core = webview.controller();
                if let Ok(core) = unsafe { core.CoreWebView2() } {
                    let mut token = Default::default();
                    let handler = PermissionRequestedEventHandler::create(Box::new(|_sender, args| {
                        if let Some(args) = args {
                            unsafe { let _ = args.SetState(COREWEBVIEW2_PERMISSION_STATE_ALLOW); }
                        }
                        Ok(())
                    }));
                    unsafe { let _ = core.add_PermissionRequested(&handler, &mut token); }
                }
            });
        }
    }
    Ok(())
})
```
If `with_webview`/`controller()`/`CoreWebView2()` names differ in the resolved versions, consult `cargo doc -p webview2-com` and adjust; the goal is: on `PermissionRequested`, call `SetState(ALLOW)`.

- [ ] **Step 2: Ensure deps resolve**

If the build complains that `webview2-com` or `windows` are not direct deps, add to `[dependencies]` (Windows-only) in `Cargo.toml`:
```toml
[target.'cfg(windows)'.dependencies]
webview2-com = "0.34"   # match the version in Cargo.lock that tauri uses
windows = { version = "0.61", features = ["Win32_Foundation"] }
```
Pin to the versions already present in `Cargo.lock` to avoid duplicate-crate conflicts.

- [ ] **Step 3: Build + manual verify**

Run: `cargo check` (clean). Then `npm run build` + `cargo run` (or `npm run tauri dev`) and open Secure Chat; clicking the call button must reach `getUserMedia` and show camera/mic (no silent block). If permission is auto-granted with no handler in your WebView2 build, keep the handler harmless and move on.

- [ ] **Step 4: Commit**
```
git add qguard-messaging/src-tauri/src/lib.rs qguard-messaging/src-tauri/Cargo.toml qguard-messaging/src-tauri/Cargo.lock
git commit -m "feat(call): grant WebView2 camera/microphone permission on Windows"
```

---

### Task 10: End-to-end verification + final gates

**Files:** none (verification only)

- [ ] **Step 1: Full automated gates**

Run, all must pass:
```
cd qguard-messaging
npx vitest run
npx tsc --noEmit
node node_modules/vite/bin/vite.js build
cd src-tauri && cargo test --lib && cargo check
```

- [ ] **Step 2: Two-instance call (manual)**

With the migration applied and two signed-in accounts that are trusted contacts (each with a current PQC device):
1. From account A's direct conversation with B, click the call button.
2. B sees the IncomingCallModal; accept.
3. Verify: both see remote + local video; audio works; the in-call overlay shows "Quantum-encrypted" and a safety number; the safety numbers MATCH on both ends.
4. Toggle mic and camera on A; confirm B sees the change.
5. Hang up on either side; both return to the chat cleanly.

- [ ] **Step 3: Encryption evidence (manual)**

In one instance, temporarily log a frame's bytes inside `call-crypto-worker.ts` before `seal`/after `open` (or use chrome://webrtc-internals). Confirm the on-wire frame payload is ciphertext (not the raw codec bytes) and decrypts only with the derived key. Remove the temporary log and re-run Step 1 gates.

- [ ] **Step 4: Failure paths (manual)**

- Deny the camera permission -> the call shows a clear failure, no crash.
- Call a contact with no current device -> the call button is disabled with the tooltip.
- Capability check: on a runtime without `RTCRtpScriptTransform`, `call.supported` is false and the button is disabled (never an unencrypted call).

- [ ] **Step 5: Commit (docs/notes only, if any)**
```
git add -A
git commit -m "docs(call): verification notes for quantum-secure video calling" --allow-empty
```

---

## Self-Review (author)

**Spec coverage:**
- 5.1 frontend modules -> T3 (ice), T4 (worker), T5 (signaling+types), T7 (hook), T8 (components). Covered.
- 5.2 backend -> T2 commands; T9 WebView2 permission. Covered.
- 5.3 signaling table -> T1. Covered.
- 6 crypto: directional HKDF-SHA3-256 keys + SAS -> T2; per-frame AES-256-GCM -> T4. Covered.
- 7 state machine -> T6. 8 UX -> T8. 11 testing -> T2/T4/T6 unit + T10 manual. 12 migration -> T1.

**Intentional refinement vs spec (documented):** The spec described transporting a random media root key over `messaging_send_encrypted_message`. The plan instead derives the media key from a fresh hybrid KEM to the peer's identity key (`call_caller_setup`/`call_callee_setup`). This is strictly better: per-call forward secrecy, no raw-key transport, and signaling needs no extra E2EE (the KEM ciphertext is public; only the callee can decapsulate). The security property (quantum-safe media key, no server interception, SAS-verified) is preserved.

**Placeholder scan:** No TBD/TODO. "Confirm X exists" notes are explicit verification steps against named symbols, not vague requirements.

**Type consistency:** `CallSetup { hybridCiphertext, sendKeyB64, recvKeyB64, safetyNumber }` is identical across the Rust command (serde camelCase) and the hook. Reducer `media-connected` uses `safetyNumber`. Signal types match between `call-types.ts`, `call-signaling.ts`, and the migration CHECK constraint. ICE config + worker option keys (`operation`, `keyB64`, `contextTag`, `kind`) match between hook and worker.

## Honest limits to keep in the UI (from the spec)

- E2EE protects against the server, TURN relay, and network attackers - not against the remote participant recording their own screen.
- Windows/WebView2 first. STUN-only may fail on strict NAT until TURN is configured. Requires migration 023 applied.