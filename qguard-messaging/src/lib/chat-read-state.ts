// Pure decision logic for per-message read/verification state.
//
// This is the heart of the "unread bubble" behaviour: whether a rendered
// message row should be marked read, and — critically — whether that write is a
// NEW read (a null -> timestamp transition). The conversation loader uses the
// `newRead` signal to refresh the unread badges (conversation list, sidebar,
// top-bar bell) exactly once per real change, instead of on every idempotent
// realtime reload. Keeping it pure makes the semantics testable without a live
// Supabase session or the React effect lifecycle around it.

export interface ReadStateMessage {
  /** The original (sealed-sender-unwrapped) sender of the message. */
  senderUserId: string;
  viewOnce: boolean;
  hasAttachment: boolean;
  /** "decrypted" | "failed" | "sealed" — only decrypted rows carry a verdict. */
  status: string;
  authenticated: boolean;
  threatScore: number;
}

export interface ExistingReadState {
  firstReadAt: string | null;
  verificationState: string;
  threatScore: number;
}

export interface ReadStateDecision {
  nextReadAt: string | null;
  nextVerification: string;
  /** The persisted row differs from what we loaded, so it must be written. */
  changed: boolean;
  /** first_read_at transitioned null -> timestamp: a genuinely new read. */
  newRead: boolean;
}

/**
 * Derive the read/verification state a message row should be persisted with.
 *
 * Rendering a peer's row on screen is the read event, so every peer row is
 * marked read — including "failed" and "sealed" stubs, which render as visible
 * rows and must never hold the unread badge hostage when they can't decrypt.
 * The one exception is a DECRYPTED view-once attachment: it only counts as read
 * once the recipient actually opens it, because `first_read_at` doubles as the
 * burn trigger for that ephemeral message. Own messages are never "read".
 * An already-recorded read timestamp is preserved so re-renders never reset it.
 */
export function deriveReadState(
  message: ReadStateMessage,
  existing: ExistingReadState | undefined,
  currentUserId: string,
  readAt: string,
): ReadStateDecision {
  const existingReadAt = existing?.firstReadAt ?? null;
  const isFromPeer = message.senderUserId !== currentUserId;
  const isUnopenedViewOnceAttachment = message.viewOnce && message.hasAttachment;
  const markAsRead = isFromPeer && !isUnopenedViewOnceAttachment;
  const nextReadAt = existingReadAt ?? (markAsRead ? readAt : null);

  const nextVerification = message.status === "decrypted"
    ? (message.authenticated ? "valid" : "tampered")
    : (existing?.verificationState ?? "pending");

  const changed =
    nextReadAt !== existingReadAt ||
    nextVerification !== (existing?.verificationState ?? "pending") ||
    message.threatScore !== (existing?.threatScore ?? 0);

  const newRead = existingReadAt === null && nextReadAt !== null;

  return { nextReadAt, nextVerification, changed, newRead };
}
