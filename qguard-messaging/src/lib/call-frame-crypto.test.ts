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
