import { coreDigestBase64 } from "@/lib/core-crypto";

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
 * Both are computed by the app's cryptographic module (lib/core-crypto.ts).
 */
export interface AttachmentDigestFields {
  sha3_b64?: string;
  sha256_b64?: string;
}

export function sha3Base64(bytes: Uint8Array): Promise<string> {
  return coreDigestBase64("sha3-256", bytes);
}

export function sha256Base64(bytes: Uint8Array): Promise<string> {
  return coreDigestBase64("sha256", bytes);
}

/** Both digests, for a new attachment. */
export async function attachmentDigests(ciphertext: Uint8Array): Promise<Required<AttachmentDigestFields>> {
  return { sha3_b64: await sha3Base64(ciphertext), sha256_b64: await sha256Base64(ciphertext) };
}

/** True when the downloaded ciphertext matches the strongest digest the attachment carries. */
export async function attachmentDigestMatches(ciphertext: Uint8Array, fields: AttachmentDigestFields): Promise<boolean> {
  if (fields.sha3_b64) return (await sha3Base64(ciphertext)) === fields.sha3_b64;
  if (fields.sha256_b64) return (await sha256Base64(ciphertext)) === fields.sha256_b64;
  return false;
}
