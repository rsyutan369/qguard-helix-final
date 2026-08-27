import { byteaToBytes } from "@/lib/encoding";

/**
 * The identity fields a sender binds into every message.
 *
 * These are the fields that appear in BOTH `message_aad()` and
 * `message_signable()` in `src-tauri/src/message_crypto.rs`. Reconstructing an
 * envelope for the Rust verifier means reproducing them byte-for-byte; get one
 * wrong and `dual_verify` fails with "Ed25519 signature verification failed".
 */
export interface MessageEnvelopeIdentity {
  message_id: string;
  conversation_id: string;
  sender_user_id: string;
  recipient_user_id: string;
  sender_device_id: string;
  recipient_device_id: string;
  counter: number;
}

/** Prefix + field count of the AAD written by `message_crypto::message_aad`. */
const AAD_PREFIX = "QGM1";
const AAD_FIELDS = 8;

/**
 * Recover the sender's own identity fields from a message's AAD.
 *
 * ---------------------------------------------------------------------------
 * WHY THE AAD, AND NOT THE ROW'S COLUMNS
 * ---------------------------------------------------------------------------
 * `messaging_message_envelopes.sender_device_id` and `recipient_device_id` are
 * declared `REFERENCES messaging_devices(id) ON DELETE SET NULL` (migration
 * 001). Retiring a device therefore rewrites history: Postgres silently nulls
 * those columns in every message that device ever sent or received, including
 * messages signed long before. Rebuilding the signable from them then produced
 * an empty string where the sender had signed a device id, and EVERY affected
 * message failed to decrypt with "Ed25519 signature verification failed" —
 * permanently, and with no way for the user to connect the cause (a device
 * clean-up) to the effect.
 *
 * The AAD does not have that problem, and not by luck:
 *   - it is a `bytea` blob, so no foreign key can rewrite it;
 *   - it is authenticated twice over — covered by `message_signable`, and used
 *     as AES-GCM associated data — so a tampered AAD fails verification and
 *     decryption rather than being believed.
 *
 * So this is the stricter source, not merely the surviving one: the signable is
 * now rebuilt only from bytes the sender actually signed, never from mutable
 * server-side columns that anything with write access could change.
 *
 * Returns `null` when the AAD is absent or not in the expected shape, leaving
 * the caller to fall back to the columns rather than inventing a value.
 */
export function parseMessageAad(aad: unknown): MessageEnvelopeIdentity | null {
  const bytes = byteaToBytes(aad);
  if (bytes.length === 0) return null;

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bytes));
  } catch {
    return null;
  }

  const parts = text.split("|");
  // Exact field count, not "at least": a short read would silently shift every
  // field one position left and produce a confidently wrong identity.
  if (parts.length !== AAD_FIELDS || parts[0] !== AAD_PREFIX) return null;

  const counter = Number(parts[7]);
  if (!Number.isInteger(counter) || counter < 0) return null;

  return {
    message_id: parts[1],
    conversation_id: parts[2],
    sender_user_id: parts[3],
    recipient_user_id: parts[4],
    sender_device_id: parts[5],
    recipient_device_id: parts[6],
    counter,
  };
}
