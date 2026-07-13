// AES-256-GCM per-frame sealing for E2EE media. Nonce (12B) = contextTag(4B) | counter(8B BE).
// Wire format: [header (headerLength, unencrypted)][ciphertext+16B tag][8B BE counter].

/**
 * Unencrypted leading bytes the RTP (de)packetizer needs — the Chrome
 * insertable-streams convention for VP8 video (10 bytes on a keyframe, 3 on a
 * delta) and Opus audio (1). Shared by every encoded-transform plumbing so the
 * encrypt and decrypt sides always split the frame identically.
 */
export function headerLength(kind: "audio" | "video", frame: { type?: "key" | "delta" }): number {
  if (kind === "audio") return 1;
  return frame.type === "key" ? 10 : 3;
}

export async function importAesGcmKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
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
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce(contextTag, counter) as BufferSource }, key, payload as BufferSource),
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
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce(contextTag, counter) as BufferSource }, key, ct as BufferSource),
  );
  const out = new Uint8Array(headerLength + pt.length);
  out.set(header, 0);
  out.set(pt, headerLength);
  return out.buffer;
}