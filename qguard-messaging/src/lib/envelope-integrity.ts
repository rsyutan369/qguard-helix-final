import { parseMessageAad, type MessageEnvelopeIdentity } from "@/lib/message-envelope-identity";
import { asRecord } from "@/lib/message-envelope-rows";

/**
 * Checks that tie a relay ROW to the envelope its sender actually SIGNED.
 *
 * The relay stores each envelope as a row. Some of a row's fields are covered
 * by the sender's signature (they are inside the AAD: message id, conversation,
 * sender, recipient, counter); the rest are plain columns and JSON that anything
 * able to write to the relay can set. The Rust core verifies the signature, but
 * it is handed the envelope rebuilt from the signed fields — it never sees which
 * row that envelope was found in. So three things were left unchecked:
 *
 *   - REPLAY. An old, genuine envelope copied into a new row (new id, new
 *     timestamp, new grouping id) verified perfectly and was shown as a new
 *     message.
 *   - RELOCATION. A genuine envelope copied into another conversation verified
 *     perfectly and was shown there.
 *   - ATTRIBUTION. The name shown on a message came from unsigned metadata, so
 *     a genuine message could be shown under another person's name.
 *
 * Every row a sender writes uses the signed message id as its primary key, so
 * `row.id === signed.message_id` holds for every genuine row and for no copy.
 */

export interface EnvelopeRowPlacement {
  id: string;
  conversation_id: string;
  recipient_user_id: string;
  aad: unknown;
}

export type EnvelopeRowRejection =
  /** The row is a copy of an envelope that was signed under a different id. */
  | "replayed_copy"
  /** The envelope was signed for a different conversation than the row sits in. */
  | "moved_between_conversations"
  /** The envelope was signed for a different recipient than the row names. */
  | "recipient_mismatch";

export type EnvelopeRowVerdict =
  | { ok: true; signed: MessageEnvelopeIdentity | null }
  | { ok: false; reason: EnvelopeRowRejection; signed: MessageEnvelopeIdentity };

/**
 * Whether a row sits where its envelope was signed to be.
 *
 * A row whose AAD cannot be parsed is passed through with `signed: null`: this
 * check has nothing to compare, and the Rust core — which recomputes the AAD
 * from the envelope's fields and requires an exact match — is what decides
 * whether such an envelope opens at all. It is never reported as position-
 * verified.
 */
export function checkEnvelopeRow(row: EnvelopeRowPlacement): EnvelopeRowVerdict {
  const signed = parseMessageAad(row.aad);
  if (!signed) return { ok: true, signed: null };
  if (signed.message_id !== row.id) return { ok: false, reason: "replayed_copy", signed };
  if (signed.conversation_id !== row.conversation_id) return { ok: false, reason: "moved_between_conversations", signed };
  if (signed.recipient_user_id !== row.recipient_user_id) return { ok: false, reason: "recipient_mismatch", signed };
  return { ok: true, signed };
}

export interface EnvelopeRowScreening<Row> {
  /** Rows that may be decrypted and shown, each at most once. */
  accepted: Row[];
  /** Rows refused, with why. Never shown; reported to the user as a count. */
  rejected: Array<{ row: Row; reason: EnvelopeRowRejection | "duplicate_row" }>;
  /** Ids of accepted rows whose position was verified against their signature. */
  positionVerified: Set<string>;
}

/**
 * Screen a page of rows before any of them is decrypted.
 *
 * Besides {@link checkEnvelopeRow}, a row id may appear only once: the relay
 * answers the query, so "the primary key is unique" is only true of what this
 * client is prepared to accept.
 */
export function screenEnvelopeRows<Row extends EnvelopeRowPlacement>(rows: Row[]): EnvelopeRowScreening<Row> {
  const accepted: Row[] = [];
  const rejected: EnvelopeRowScreening<Row>["rejected"] = [];
  const positionVerified = new Set<string>();
  const seen = new Set<string>();
  for (const row of rows) {
    if (seen.has(row.id)) {
      rejected.push({ row, reason: "duplicate_row" });
      continue;
    }
    seen.add(row.id);
    const verdict = checkEnvelopeRow(row);
    if (!verdict.ok) {
      rejected.push({ row, reason: verdict.reason });
      continue;
    }
    accepted.push(row);
    if (verdict.signed) positionVerified.add(row.id);
  }
  return { accepted, rejected, positionVerified };
}

export interface EnvelopeRowAttribution {
  sender_user_id: string;
  aad: unknown;
  sealed_sender_envelope: unknown;
}

function unsignedOriginalSender(row: EnvelopeRowAttribution): string | null {
  const sealed = asRecord(row.sealed_sender_envelope);
  for (const key of ["sync_original_sender_user_id", "original_sender_user_id"]) {
    const value = sealed[key];
    if (typeof value === "string" && value.trim()) return value;
  }
  return null;
}

/**
 * Whose name goes on a message.
 *
 * The signed sender is the device that SEALED the envelope. That is the author
 * for every envelope except one kind: when one of this account's own devices
 * re-seals a message for another of its devices (trusted-device sync), the
 * envelope is signed by that device, and the real author travels in the
 * `sync_original_sender_user_id` note beside it.
 *
 * That note is not covered by the signature, so it is believed ONLY on an
 * envelope this account's own devices signed. On anyone else's envelope the
 * signed sender is the author, whatever the note says — otherwise a peer (or
 * the relay) could put a third person's name on a message.
 *
 * Residual, stated plainly: on an envelope signed by this account, the note
 * still decides between "me" and "someone else", and the relay could alter it.
 * Closing that needs the original author inside the sealed payload, which is a
 * wire change (see docs/security-limitations.md).
 */
export function attributedSenderUserId(row: EnvelopeRowAttribution, localUserId: string): string {
  const signed = parseMessageAad(row.aad);
  const noted = unsignedOriginalSender(row);
  if (!signed) return noted ?? row.sender_user_id;
  if (signed.sender_user_id === localUserId) return noted ?? signed.sender_user_id;
  return signed.sender_user_id;
}

/** A sentence for the user about rows that were refused, or null for none. */
export function describeRejectedEnvelopes(count: number): string | null {
  if (count <= 0) return null;
  return count === 1
    ? "1 message copy was ignored because it did not match what its sender signed."
    : `${count} message copies were ignored because they did not match what their sender signed.`;
}
