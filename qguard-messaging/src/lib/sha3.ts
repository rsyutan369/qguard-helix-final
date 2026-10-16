// SHA3-256 (FIPS 202) for the WebView.
//
// WebCrypto offers SHA-2 only, and the QGuard Helix approved stack names SHA-3
// as the hash. The Rust core already hashes with SHA3-256; this gives the
// WebView the same function for the values it computes itself (audit event
// digests, the asset manifest, rate-limit keys) without a native round trip.
import { sha3_256 } from "@noble/hashes/sha3.js";

function toBytes(value: string | Uint8Array | ArrayBuffer): Uint8Array {
  if (typeof value === "string") return new TextEncoder().encode(value);
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

export function sha3_256Hex(value: string | Uint8Array | ArrayBuffer): string {
  return Array.from(sha3_256(toBytes(value)))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
