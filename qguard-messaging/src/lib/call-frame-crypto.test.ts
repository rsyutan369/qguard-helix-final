import { test, expect } from "vitest";
import { importAesGcmKey, sealFrame, openFrame, frameCounter, FrameReplayWindow } from "@/lib/call-frame-crypto";

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
test("rewriting the cleartext header is now detected", async () => {
  // The header must travel in the clear for the RTP depacketizer, but that is
  // not a reason to leave it unauthenticated: flipping VP8's keyframe/delta
  // marker cannot recover plaintext, yet it can corrupt or stall a decoder.
  // Binding it as AAD makes any edit fail the tag check.
  const key = await importAesGcmKey(new Uint8Array(32).fill(11));
  const sealed = new Uint8Array(await sealFrame(key, ctx, 4n, 3, bytes("HDRpayload")));
  sealed[1] ^= 0xff; // inside the cleartext header, not the ciphertext
  await expect(openFrame(key, ctx, 3, sealed)).rejects.toBeTruthy();
});

test("rewriting the frame counter is detected", async () => {
  const key = await importAesGcmKey(new Uint8Array(32).fill(13));
  const sealed = new Uint8Array(await sealFrame(key, ctx, 5n, 0, bytes("secret")));
  sealed[sealed.length - 1] ^= 0x01; // last byte of the trailing counter
  await expect(openFrame(key, ctx, 0, sealed)).rejects.toBeTruthy();
});

test("a frame sealed for the other media kind cannot be opened", async () => {
  // Audio and video are separated by the context tag, which is part of the
  // nonce — a cross-kind splice must not authenticate.
  const key = await importAesGcmKey(new Uint8Array(32).fill(17));
  const audioCtx = new Uint8Array([1, 0, 0, 0]);
  const videoCtx = new Uint8Array([2, 0, 0, 0]);
  const sealed = new Uint8Array(await sealFrame(key, audioCtx, 6n, 0, bytes("voice")));
  await expect(openFrame(key, videoCtx, 0, sealed)).rejects.toBeTruthy();
});

// ---------------------------------------------------------------------------
// Anti-replay
//
// A replayed frame is a VALID frame: same key, same counter, same tag, so it
// decrypts perfectly. Only the window can tell it is arriving a second time.
// ---------------------------------------------------------------------------

test("a replayed frame authenticates but is refused by the window", async () => {
  const key = await importAesGcmKey(new Uint8Array(32).fill(23));
  const sealed = new Uint8Array(await sealFrame(key, ctx, 40n, 0, bytes("live audio")));
  // The replay is byte-identical, so AES-GCM has no objection at all.
  expect(new Uint8Array(await openFrame(key, ctx, 0, sealed)).length).toBeGreaterThan(0);

  const window = new FrameReplayWindow();
  const seq = frameCounter(sealed);
  expect(window.check(seq)).toBe(true);
  window.commit(seq);
  expect(window.check(seq)).toBe(false);
});

test("out-of-order frames inside the window are accepted exactly once", () => {
  const window = new FrameReplayWindow();
  for (const seq of [10n, 13n, 11n, 12n]) {
    expect(window.check(seq)).toBe(true);
    window.commit(seq);
  }
  for (const seq of [10n, 11n, 12n, 13n]) expect(window.check(seq)).toBe(false);
  // Still moving forward normally.
  expect(window.check(14n)).toBe(true);
});

test("frames older than the window are refused rather than guessed at", () => {
  const window = new FrameReplayWindow();
  window.commit(0n);
  window.commit(5000n);
  expect(window.check(4999n)).toBe(true);   // just behind the mark
  expect(window.check(4000n)).toBe(false);  // far behind: indistinguishable from a replay
  expect(window.check(5001n)).toBe(true);
});

test("a large forward jump does not resurrect old counters", () => {
  const window = new FrameReplayWindow();
  window.commit(1n);
  window.commit(100000n);
  expect(window.check(1n)).toBe(false);
  expect(window.check(99999n)).toBe(true);
});
