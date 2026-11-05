import { invoke } from "@tauri-apps/api/core";
import { hmac } from "@noble/hashes/hmac.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { base64ToBytes, bytesToBase64 } from "@/lib/encoding";

/**
 * Cryptography the WebView needs, done by the app's cryptographic module.
 *
 * Inside the desktop and Android apps every function here calls the Rust core
 * (`commands::crypto_module`), so digests, MACs and attachment encryption run
 * inside the same boundary as everything else — the one FIPS 140-3 can
 * validate (docs/FIPS_140_3.md). The browser preview build has no core and
 * falls back to WebCrypto and @noble/hashes, as it always did.
 *
 * Bytes go to the core as base64 strings in ordinary JSON arguments, never as
 * a raw `Uint8Array` payload: Android's WebView cannot pass a request body to
 * the app, so Tauri sends every Android call as JSON, and desktop does the same
 * once its IPC falls back to postMessage. A raw payload then reaches Rust as an
 * array of numbers, which is what broke attachments ("expected raw bytes").
 *
 * Call-media frame encryption (call-frame-crypto.ts) stays in WebCrypto: it runs
 * per video frame inside WebRTC encoded transforms, where a round trip to the
 * core per frame is not possible. Settings → FIPS 140-3 lists it as outside
 * the module.
 */

export type DigestAlgorithm = "sha3-256" | "sha256";

const encoder = new TextEncoder();

/** The Rust core is reachable (the same test as `isTauriRuntime`, read here so
 *  that code mocking `@/lib/tauri` never routes real crypto to a missing core). */
function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function toBytes(value: string | Uint8Array | ArrayBuffer): Uint8Array {
  if (typeof value === "string") return encoder.encode(value);
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return base64ToBytes(padded);
}

/** A digest of `value`, from the module in the app. */
export async function coreDigest(algorithm: DigestAlgorithm, value: string | Uint8Array | ArrayBuffer): Promise<Uint8Array> {
  const bytes = toBytes(value);
  if (isTauriRuntime()) {
    return base64ToBytes(await invoke<string>("crypto_digest", { algorithm, dataB64: bytesToBase64(bytes) }));
  }
  if (algorithm === "sha3-256") return sha3_256(bytes);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes)));
}

export async function coreSha3Hex(value: string | Uint8Array | ArrayBuffer): Promise<string> {
  return toHex(await coreDigest("sha3-256", value));
}

export async function coreDigestBase64(algorithm: DigestAlgorithm, value: Uint8Array): Promise<string> {
  return bytesToBase64(await coreDigest(algorithm, value));
}

/** HMAC-SHA3-256 (hex) of `message` under a base64url key. */
export async function coreHmacSha3Hex(keyBase64Url: string, message: string): Promise<string> {
  if (isTauriRuntime()) return invoke<string>("crypto_hmac_sha3_256", { keyB64url: keyBase64Url, message });
  return toHex(hmac(sha3_256, fromBase64Url(keyBase64Url), encoder.encode(message)));
}

export interface SealedAttachment {
  /** The raw AES-256 key, to travel inside the end-to-end encrypted message. */
  key: Uint8Array<ArrayBuffer>;
  iv: Uint8Array<ArrayBuffer>;
  /** ciphertext || tag, what is uploaded. */
  sealed: Uint8Array<ArrayBuffer>;
}

interface CoreSealedAttachment {
  keyB64: string;
  ivB64: string;
  sealedB64: string;
}

/** AES-256-GCM with a fresh key and nonce chosen by the module. */
export async function coreSealAttachment(plaintext: Uint8Array, aad: Uint8Array): Promise<SealedAttachment> {
  if (isTauriRuntime()) {
    const out = await invoke<CoreSealedAttachment>("crypto_attachment_seal", {
      plaintextB64: bytesToBase64(plaintext),
      aadB64: bytesToBase64(aad),
    });
    return { key: base64ToBytes(out.keyB64), iv: base64ToBytes(out.ivB64), sealed: base64ToBytes(out.sealedB64) };
  }
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: toArrayBuffer(aad) }, key, toArrayBuffer(plaintext)));
  return { key: new Uint8Array(await crypto.subtle.exportKey("raw", key)), iv, sealed };
}

/** Open an attachment; `aad` is null for attachments sealed before the AAD binding. */
export async function coreOpenAttachment(sealed: Uint8Array, key: Uint8Array, iv: Uint8Array, aad: Uint8Array | null): Promise<Uint8Array<ArrayBuffer>> {
  if (isTauriRuntime()) {
    const plaintext = await invoke<string>("crypto_attachment_open", {
      sealedB64: bytesToBase64(sealed),
      keyB64: bytesToBase64(key),
      ivB64: bytesToBase64(iv),
      aadB64: aad ? bytesToBase64(aad) : null,
    });
    return base64ToBytes(plaintext);
  }
  const cryptoKey = await crypto.subtle.importKey("raw", toArrayBuffer(key), "AES-GCM", false, ["decrypt"]);
  const params = aad ? { name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: toArrayBuffer(aad) } : { name: "AES-GCM", iv: toArrayBuffer(iv) };
  return new Uint8Array(await crypto.subtle.decrypt(params, cryptoKey, toArrayBuffer(sealed)));
}
