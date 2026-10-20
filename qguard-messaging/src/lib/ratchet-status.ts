import { isTauriRuntime, safeInvoke } from "@/lib/tauri";
import type { PublishedSuite } from "@/lib/kem-suite";

/**
 * The post-quantum session ratchet (src-tauri/src/pq_ratchet.rs), as the UI
 * sees it: whether a device advertises it, what the core says about the
 * sessions it holds, and the three commands that manage it.
 *
 * Everything here reports what the Rust core returned. Nothing is inferred:
 * a device "uses the ratchet" only when the core holds a session with it, and
 * a message "came through the ratchet" only when the core opened it from a
 * signed ratchet header.
 */

/** Must match `RATCHET_PROTOCOL` in src-tauri/src/pq_ratchet.rs. */
export const RATCHET_PROTOCOL = "QGuard-PQRatchet-v1";

/**
 * Must match `RATCHET_SESSION_MISSING_MARKER` in
 * src-tauri/src/commands/messaging.rs: the message belongs to a session this
 * device does not hold, which a fresh session from our side repairs.
 */
export const RATCHET_SESSION_MISSING_MARKER = "secure session unavailable";

/** `SessionSummary` from the core. Seconds since the epoch. */
export interface RatchetSessionSummary {
  session_id: string;
  created_at: number;
  last_used_at: number;
  /** A full round trip has happened: per-message forward secrecy and healing are in effect. */
  ratcheted: boolean;
  /** ML-KEM-1024 steps completed after the seeding one. */
  pq_steps: number;
  last_pq_at: number;
  init_combiner: string;
}

/** `RatchetStatus` from the core. */
export interface RatchetStatus {
  enabled: boolean;
  env_override: boolean | null;
  /** False: the session file could not be opened, so nothing can be said. */
  available: boolean;
  protocol: string;
  sessions: Record<string, RatchetSessionSummary>;
}

/** Whether a device's published suite says it accepts ratchet envelopes. */
export function advertisesRatchet(suite: PublishedSuite): boolean {
  return Boolean(suite && typeof suite === "object" && suite.ratchet === RATCHET_PROTOCOL);
}

export function isRatchetSessionMissingError(message: string | null | undefined): boolean {
  return Boolean(message && message.toLowerCase().includes(RATCHET_SESSION_MISSING_MARKER));
}

export async function fetchRatchetStatus(userId: string, peerDeviceIds: string[]): Promise<RatchetStatus | null> {
  if (!isTauriRuntime()) return null;
  return safeInvoke<RatchetStatus>("messaging_ratchet_status", { userId, peerDeviceIds });
}

export async function setRatchetEnabled(userId: string, enabled: boolean): Promise<RatchetStatus> {
  return safeInvoke<RatchetStatus>("messaging_set_ratchet_enabled", { userId, enabled });
}

/** Forget the session(s) with one device, or with every device when none is named. */
export async function resetRatchetSession(userId: string, peerDeviceId: string | null): Promise<boolean> {
  return safeInvoke<boolean>("messaging_reset_ratchet_session", { userId, peerDeviceId });
}

/** One plain sentence for a session, for the Trust Center and the explainer. */
export function describeRatchetSession(summary: RatchetSessionSummary | undefined, now: number = Date.now()): string {
  if (!summary) return "No secure session yet — the next message starts one from this device's published keys.";
  if (!summary.ratcheted) return "Secure session started; it begins advancing per message once they reply.";
  const lastPq = Math.max(0, Math.round((now / 1000 - summary.last_pq_at) / 3600));
  const pq = lastPq < 1 ? "within the last hour" : lastPq < 48 ? `${lastPq} h ago` : `${Math.round(lastPq / 24)} days ago`;
  return `Every message gets its own key, deleted after use. Last post-quantum (ML-KEM-1024) refresh ${pq}.`;
}
