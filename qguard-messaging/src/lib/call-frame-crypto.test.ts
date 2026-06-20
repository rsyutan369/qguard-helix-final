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