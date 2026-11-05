import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const tauriCore = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => tauriCore);

import { coreDigest, coreHmacSha3Hex, coreOpenAttachment, coreSealAttachment, coreSha3Hex } from "@/lib/core-crypto";
import { base64ToBytes, bytesToBase64 } from "@/lib/encoding";

// Outside the app there is no core, so these exercise the browser-preview
// fallback, against the same vectors the Rust module's self-test uses
// (src-tauri/src/crypto/provider/selftest.rs).
const text = (value: string) => new TextEncoder().encode(value);
const hex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const base64Url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

describe("core-crypto (browser fallback)", () => {
  it("digests match FIPS 202 / FIPS 180-4", async () => {
    expect(await coreSha3Hex("abc")).toBe("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    expect(hex(await coreDigest("sha256", "abc"))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("HMAC-SHA3-256 matches the module's known-answer vector", async () => {
    const key = base64Url(text("QGuard HMAC key 0123456789abcdef"));
    expect(await coreHmacSha3Hex(key, "QGuard HMAC-SHA3-256 KAT")).toBe("7ab808cda6547388ab74b12b669787869e168c43adfb401352f6e3c1dbdc5318");
  });

  it("an attachment opens only with its associated data", async () => {
    const aad = text("user/chat-attachments/c/m/file.bin|c|m");
    const { key, iv, sealed } = await coreSealAttachment(text("attachment bytes"), aad);
    expect(key).toHaveLength(32);
    expect(iv).toHaveLength(12);
    expect(sealed).toHaveLength("attachment bytes".length + 16);
    expect(new TextDecoder().decode(await coreOpenAttachment(sealed, key, iv, aad))).toBe("attachment bytes");
    await expect(coreOpenAttachment(sealed, key, iv, text("moved elsewhere"))).rejects.toThrow();
    await expect(coreOpenAttachment(sealed, key, iv, null)).rejects.toThrow();
  });
});

/**
 * In the app every call goes to the core. Android never delivers a raw IPC
 * body, so each argument must be plain JSON — strings, never a Uint8Array.
 * The fake core below answers exactly as `commands::crypto_module` does
 * (base64 in, base64 out), doing the real AES-GCM.
 */
describe("core-crypto (inside the app)", () => {
  const ab = (bytes: Uint8Array) => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

  beforeEach(() => {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
    tauriCore.invoke.mockReset().mockImplementation(async (command: string, args: Record<string, unknown>) => {
      // The regression this guards: a typed array (or anything but JSON scalars) as an argument.
      expect(Object.getPrototypeOf(args)).toBe(Object.prototype);
      for (const value of Object.values(args)) expect(value === null || typeof value === "string").toBe(true);
      if (command === "crypto_digest") {
        expect(args.algorithm).toBe("sha3-256");
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ab(base64ToBytes(args.dataB64 as string))));
        return bytesToBase64(digest);
      }
      if (command === "crypto_attachment_seal") {
        const key = crypto.getRandomValues(new Uint8Array(32));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const cryptoKey = await crypto.subtle.importKey("raw", ab(key), "AES-GCM", false, ["encrypt"]);
        const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: ab(iv), additionalData: ab(base64ToBytes(args.aadB64 as string)) }, cryptoKey, ab(base64ToBytes(args.plaintextB64 as string))));
        return { keyB64: bytesToBase64(key), ivB64: bytesToBase64(iv), sealedB64: bytesToBase64(sealed) };
      }
      if (command === "crypto_attachment_open") {
        const cryptoKey = await crypto.subtle.importKey("raw", ab(base64ToBytes(args.keyB64 as string)), "AES-GCM", false, ["decrypt"]);
        const params = args.aadB64 === null
          ? { name: "AES-GCM", iv: ab(base64ToBytes(args.ivB64 as string)) }
          : { name: "AES-GCM", iv: ab(base64ToBytes(args.ivB64 as string)), additionalData: ab(base64ToBytes(args.aadB64 as string)) };
        return bytesToBase64(new Uint8Array(await crypto.subtle.decrypt(params, cryptoKey, ab(base64ToBytes(args.sealedB64 as string)))));
      }
      if (command === "crypto_hmac_sha3_256") return "ab".repeat(32);
      throw new Error(`unexpected command ${command}`);
    });
  });

  afterEach(() => {
    delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
  });

  it("sends an attachment to the core as base64 and reads the sealed fields back", async () => {
    const big = Uint8Array.from({ length: 70_000 }, (_, index) => (index * 31 + 7) & 0xff); // spans several base64 chunks
    const aad = text("user/chat-attachments/c/m/photo.jpg|c|m");
    const { key, iv, sealed } = await coreSealAttachment(big, aad);
    expect(tauriCore.invoke).toHaveBeenCalledWith("crypto_attachment_seal", { plaintextB64: bytesToBase64(big), aadB64: bytesToBase64(aad) });
    expect([key.length, iv.length, sealed.length]).toEqual([32, 12, big.length + 16]);
    expect(await coreOpenAttachment(sealed, key, iv, aad)).toEqual(big);
    // An attachment from before the AAD binding sends `aadB64: null`.
    await expect(coreOpenAttachment(sealed, key, iv, null)).rejects.toThrow();
    expect(tauriCore.invoke).toHaveBeenLastCalledWith("crypto_attachment_open", expect.objectContaining({ aadB64: null }));
  });

  it("asks the core for digests and MACs with string arguments only", async () => {
    await coreDigest("sha3-256", text("abc"));
    expect(tauriCore.invoke).toHaveBeenCalledWith("crypto_digest", { algorithm: "sha3-256", dataB64: bytesToBase64(text("abc")) });
    expect(await coreHmacSha3Hex("a2V5", "message")).toBe("ab".repeat(32));
    expect(tauriCore.invoke).toHaveBeenLastCalledWith("crypto_hmac_sha3_256", { keyB64url: "a2V5", message: "message" });
  });
});
