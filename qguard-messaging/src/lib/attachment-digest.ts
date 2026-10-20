import { sha3_256 } from "@noble/hashes/sha3.js";

/**
 * The transfer checksum of an attachment's CIPHERTEXT. Not the integrity
 * control — that is the AES-256-GCM tag and its associated-data binding — but
 * what turns a truncated or corrupted download into a clear message instead of
 * an opaque AEAD failure.
 *
 * SHA3-256 since roadmap 4.4 (`sha3_b64`). New attachments ALSO carry the old
 * SHA-256 (`sha256_b64`) because builds before the change refuse an attachment
 * without it; drop it once those builds are gone. A receiver checks SHA3 when
 * it is there and falls back to SHA-256 only for attachments sent before it.
 */
export interface AttachmentDigestFields {
  sha3_b64?: string;
  sha256_b64?: string;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function sha3Base64(bytes: Uint8Array): string {
  return toBase64(sha3_256(bytes));
}

export async function sha256Base64(bytes: Uint8Array): Promise<string> {
  const copy = bytes.slice();
  const digest = await crypto.subtle.digest("SHA-256", copy.buffer as ArrayBuffer);
  return toBase64(new Uint8Array(digest));
}

/** Both digests, for a new attachment. */
export async function attachmentDigests(ciphertext: Uint8Array): Promise<Required<AttachmentDigestFields>> {
  return { sha3_b64: sha3Base64(ciphertext), sha256_b64: await sha256Base64(ciphertext) };
}

/** True when the downloaded ciphertext matches the strongest digest the attachment carries. */
export async function attachmentDigestMatches(ciphertext: Uint8Array, fields: AttachmentDigestFields): Promise<boolean> {
  if (fields.sha3_b64) return sha3Base64(ciphertext) === fields.sha3_b64;
  if (fields.sha256_b64) return (await sha256Base64(ciphertext)) === fields.sha256_b64;
  return false;
}
