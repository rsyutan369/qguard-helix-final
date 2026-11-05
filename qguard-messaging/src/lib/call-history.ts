// Call history: the API over the Rust core's sealed call log
// (src-tauri/src/call_log.rs) and the pure logic around it.
//
// The core is the source of truth. It stores the history encrypted on this
// device only, validates every entry, computes talk time itself, and refuses to
// list or change the history while Secure Chat is locked. Everything below is
// either a thin call into it or a pure function of what it returned.

import { isTauriRuntime, safeInvoke } from "@/lib/tauri";
import type { CallEndReason, CallMedia } from "@/lib/call-types";

export type CallDirection = "outgoing" | "incoming";
export type CallOutcome = "completed" | "missed" | "declined" | "no_answer" | "busy" | "cancelled" | "failed";

export interface CallRecord {
  id: string;
  direction: CallDirection;
  media: CallMedia;
  group: boolean;
  peerUserIds: string[];
  peerName: string;
  conversationId: string | null;
  outcome: CallOutcome;
  /** Unix milliseconds. */
  startedAt: number;
  answeredAt: number | null;
  endedAt: number;
  durationSecs: number;
  failure: string | null;
  forwardSecret: boolean | null;
  peerVerified: boolean | null;
  seen: boolean;
}

/** What is submitted; the core derives duration and `seen`. */
export type CallRecordInput = Omit<CallRecord, "durationSecs" | "seen">;

/** Fired on `window` whenever the history changes, so badges can refresh. */
export const CALL_LOG_CHANGED = "qguard:call-log-changed";

function announce(): void {
  if (typeof window !== "undefined") window.dispatchEvent(new Event(CALL_LOG_CHANGED));
}

export const callHistory = {
  record: async (record: CallRecordInput) => {
    if (!isTauriRuntime()) return;
    await safeInvoke<void>("call_log_record", { record });
    announce();
  },
  /** Needs Secure Chat unlocked (enforced by the core). */
  list: () => safeInvoke<CallRecord[]>("call_log_list"),
  /** Readable while locked: just a count, like the unread badge. */
  missedCount: () => safeInvoke<number>("call_log_missed_count", undefined, 0),
  markSeen: async () => {
    const changed = await safeInvoke<number>("call_log_mark_seen");
    if (changed > 0) announce();
    return changed;
  },
  remove: async (ids: string[]) => {
    const removed = await safeInvoke<number>("call_log_delete", { ids });
    announce();
    return removed;
  },
  clear: async () => {
    const removed = await safeInvoke<number>("call_log_clear");
    announce();
    return removed;
  },
};

// ---------------------------------------------------------------------------
// How a call ended
// ---------------------------------------------------------------------------

export interface CallEnding {
  role: "caller" | "callee";
  /** Media connected at some point. */
  connected: boolean;
  /** The callee pressed Accept (a callee only). */
  accepted: boolean;
  endReason: CallEndReason | null;
  error: string | null;
}

/**
 * The outcome to record, from the caller's or the callee's side. A call that
 * connected is completed however it later ended; one that did not is named by
 * who ended it and why — never guessed.
 */
export function classifyCallOutcome(ending: CallEnding): CallOutcome {
  if (ending.connected) return "completed";
  if (ending.role === "callee") {
    if (ending.endReason === "local-reject") return "declined";
    // Answered here, but media never connected.
    if (ending.accepted) return "failed";
    // Rang out, or the caller gave up first.
    return "missed";
  }
  switch (ending.endReason) {
    case "remote-declined":
      return "declined";
    case "remote-busy":
      return "busy";
    case "local-hangup":
      return "cancelled";
    case "remote-hangup":
      // The callee's own ring timeout hangs up an unanswered call.
      return "no_answer";
    default:
      break;
  }
  if (ending.error && /no answer/i.test(ending.error)) return "no_answer";
  return "failed";
}

// ---------------------------------------------------------------------------
// Presentation helpers (pure)
// ---------------------------------------------------------------------------

export const OUTCOME_LABEL: Record<CallOutcome, string> = {
  completed: "Completed",
  missed: "Missed",
  declined: "Declined",
  no_answer: "No answer",
  busy: "Busy",
  cancelled: "Cancelled",
  failed: "Failed",
};

/** "Incoming voice call", "Missed video call", "Outgoing group video call"… */
export function describeCall(record: Pick<CallRecord, "direction" | "media" | "group" | "outcome">): string {
  const kind = `${record.group ? "group " : ""}${record.media} call`;
  if (record.outcome === "missed") return `Missed ${kind}`;
  return `${record.direction === "incoming" ? "Incoming" : "Outgoing"} ${kind}`;
}

/** Whether the outcome is a problem worth colouring (missed, failed). */
export function outcomeIsAlert(outcome: CallOutcome): boolean {
  return outcome === "missed" || outcome === "failed";
}

/** 0:42, 12:05, 1:02:09. */
export function formatCallDuration(totalSecs: number): string {
  const secs = Math.max(0, Math.floor(totalSecs));
  const hours = Math.floor(secs / 3600);
  const minutes = Math.floor((secs % 3600) / 60);
  const seconds = secs % 60;
  const mm = hours > 0 ? String(minutes).padStart(2, "0") : String(minutes);
  return `${hours > 0 ? `${hours}:` : ""}${mm}:${String(seconds).padStart(2, "0")}`;
}

/** "3h 12m", "45m", "0m" — a compact total for stats. */
export function formatTalkTime(totalSecs: number): string {
  const minutes = Math.floor(Math.max(0, totalSecs) / 60);
  const hours = Math.floor(minutes / 60);
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  return `${minutes}m`;
}

function startOfDay(ms: number): number {
  const date = new Date(ms);
  date.setHours(0, 0, 0, 0);
  return date.getTime();
}

/** "Today", "Yesterday", "Monday", or "12 Oct 2026". */
export function dayLabel(ms: number, now = Date.now()): string {
  const day = startOfDay(ms);
  const today = startOfDay(now);
  const diffDays = Math.round((today - day) / 86_400_000);
  if (diffDays === 0) return "Today";
  if (diffDays === 1) return "Yesterday";
  if (diffDays > 1 && diffDays < 7) return new Date(ms).toLocaleDateString(undefined, { weekday: "long" });
  return new Date(ms).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

export interface CallDayGroup {
  key: number;
  label: string;
  records: CallRecord[];
}

/** Records (already newest first) grouped by local day, newest day first. */
export function groupCallsByDay(records: CallRecord[], now = Date.now()): CallDayGroup[] {
  const groups: CallDayGroup[] = [];
  for (const record of records) {
    const key = startOfDay(record.startedAt);
    const last = groups[groups.length - 1];
    if (last && last.key === key) last.records.push(record);
    else groups.push({ key, label: dayLabel(record.startedAt, now), records: [record] });
  }
  return groups;
}

export type CallFilter = "all" | "missed" | "incoming" | "outgoing" | "voice" | "video";

export const CALL_FILTERS: Array<{ id: CallFilter; label: string }> = [
  { id: "all", label: "All" },
  { id: "missed", label: "Missed" },
  { id: "incoming", label: "Incoming" },
  { id: "outgoing", label: "Outgoing" },
  { id: "voice", label: "Voice" },
  { id: "video", label: "Video" },
];

export function filterCalls(records: CallRecord[], filter: CallFilter, query: string): CallRecord[] {
  const needle = query.trim().toLocaleLowerCase();
  return records.filter((record) => {
    if (filter === "missed" && record.outcome !== "missed") return false;
    if (filter === "incoming" && record.direction !== "incoming") return false;
    if (filter === "outgoing" && record.direction !== "outgoing") return false;
    if ((filter === "voice" || filter === "video") && record.media !== filter) return false;
    return !needle || record.peerName.toLocaleLowerCase().includes(needle);
  });
}

export interface CallStats {
  /** Calls in the window. */
  total: number;
  missed: number;
  unseenMissed: number;
  /** Seconds of connected talk time in the window. */
  talkSecs: number;
  /** Completed calls in the window, and how many of those were forward secret. */
  connected: number;
  forwardSecret: number;
  /** Completed calls whose peer proved the identity registered for its device. */
  peerVerified: number;
}

/** Figures for the last `days` days, all computed from the records. */
export function callStats(records: CallRecord[], days = 7, now = Date.now()): CallStats {
  const since = startOfDay(now) - (days - 1) * 86_400_000;
  const stats: CallStats = { total: 0, missed: 0, unseenMissed: 0, talkSecs: 0, connected: 0, forwardSecret: 0, peerVerified: 0 };
  for (const record of records) {
    if (record.outcome === "missed" && !record.seen) stats.unseenMissed += 1;
    if (record.startedAt < since) continue;
    stats.total += 1;
    if (record.outcome === "missed") stats.missed += 1;
    if (record.outcome === "completed") {
      stats.connected += 1;
      stats.talkSecs += record.durationSecs;
      if (record.forwardSecret) stats.forwardSecret += 1;
      if (record.peerVerified) stats.peerVerified += 1;
    }
  }
  return stats;
}

/** A direct conversation with exactly this person, if one exists. */
export function directConversationWith<T extends { id: string; conversation_type: string; member_user_ids: string[]; deleted_at?: string | null }>(
  conversations: T[],
  peerUserId: string,
): T | null {
  return (
    conversations.find(
      (conversation) =>
        conversation.conversation_type === "direct"
        && !conversation.deleted_at
        && conversation.member_user_ids.includes(peerUserId),
    ) ?? null
  );
}
