// Pure unread-badge accounting for the dashboard notification bubbles.
//
// The unread bubble on the sidebar chat entry, the conversation-list "N new"
// pill, and the top-bar bell is the count of DISTINCT message groups a user has
// received but not yet read. The subtle part is deciding which messages were
// received FROM A PEER versus authored by the user themselves.
//
// Trusted-device sync (`syncMissingDeviceEnvelopes`) rewraps a decryptable copy
// of a message for a participant's other devices, and that rewrapped envelope's
// `sender_user_id` COLUMN is the *rewrapping* device's user — NOT the original
// author. So a user's own message, rewrapped for their second device, arrives
// with a peer's id in `sender_user_id` and, using the raw column, would be
// mis-counted as an unread inbound message. Worse, it could NEVER clear: the
// read-marking path (deriveReadState) correctly refuses to mark a user's own
// message as read, so `first_read_at` stays null and the bubble sticks forever.
//
// The authoritative author is the sealed-sender original-sender metadata,
// exactly mirroring `originalSenderUserId` in SecureChatPage: prefer the
// sync-preserved original, then the original-envelope field, then the column.

export interface UnreadEnvelope {
  id: string;
  client_message_id?: string | null;
  recipient_user_id: string;
  sender_user_id: string;
  /** Sealed-sender author preserved across a trusted-device sync rewrap. */
  sync_original_sender_user_id?: string | null;
  /** Sealed-sender author stamped on the original (non-rewrapped) envelope. */
  original_sender_user_id?: string | null;
  deleted_at?: string | null;
  expires_at?: string | null;
  lifecycle?: Record<string, unknown> | null;
}

export interface UnreadReadState {
  first_read_at: string | null;
  hidden_at: string | null;
}

/**
 * The true author of a message, resilient to trusted-device sync rewraps.
 * Mirrors `originalSenderUserId` in SecureChatPage so the unread count and the
 * chat's own read-marking agree on who sent a message.
 */
export function effectiveOriginalSender(envelope: UnreadEnvelope): string {
  const sync = envelope.sync_original_sender_user_id;
  if (typeof sync === "string" && sync.trim()) return sync;
  const original = envelope.original_sender_user_id;
  if (typeof original === "string" && original.trim()) return original;
  return envelope.sender_user_id;
}

/** The logical message id a row belongs to (device-copies share one group). */
export function unreadMessageGroupId(envelope: UnreadEnvelope): string {
  return String(envelope.client_message_id ?? envelope.id);
}

/**
 * Distinct unread message-group ids for `userId` within a single conversation.
 *
 * A group counts as unread when an inbound envelope (addressed to me, authored
 * by someone else) has no read/hidden state. Own messages — including the
 * user's own messages rewrapped by a peer for the user's other devices — are
 * excluded via the original-sender check, so they can never hold the bubble.
 * Control envelopes (reactions/edits) and already-expired disappearing messages
 * are never rendered as readable rows and so never keep the bubble alive.
 */
export function countUnreadGroups(
  envelopes: UnreadEnvelope[],
  userId: string,
  readState: (groupId: string) => UnreadReadState | undefined,
  now: number = Date.now(),
): Set<string> {
  const unread = new Set<string>();
  for (const envelope of envelopes) {
    if (envelope.deleted_at) continue;
    if (String(envelope.recipient_user_id) !== userId) continue;
    // The ORIGINAL author decides "from a peer" — never the rewrapping device.
    if (effectiveOriginalSender(envelope) === userId) continue;
    const lifecycle = (envelope.lifecycle ?? {}) as Record<string, unknown>;
    if (lifecycle.control_type) continue;
    const expiresAtMs = envelope.expires_at ? new Date(String(envelope.expires_at)).getTime() : Number.NaN;
    if (Number.isFinite(expiresAtMs) && expiresAtMs <= now) continue;
    const groupId = unreadMessageGroupId(envelope);
    const state = readState(groupId);
    if (!state?.first_read_at && !state?.hidden_at) unread.add(groupId);
  }
  return unread;
}
