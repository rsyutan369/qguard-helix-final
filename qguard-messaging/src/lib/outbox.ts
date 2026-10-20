/**
 * Store-and-forward outbox (roadmap 9.1). A message sealed while the relay is
 * unreachable is kept — as its sealed envelope rows, never plaintext — in the
 * core's encrypted storage (commands/outbox.rs) and uploaded once the relay
 * answers. On Android the same rows can travel to phones in range first
 * (lib/nearby.ts).
 */
import { safeInvoke } from "@/lib/tauri";

export interface OutboxItem {
  id: string;
  conversationId: string;
  queuedAt: number;
  rows: Array<Record<string, unknown>>;
}

export const OUTBOX_QUEUED_EVENT = "qguard:outbox-queued";
export const OUTBOX_FLUSHED_EVENT = "qguard:outbox-flushed";

/**
 * True when the request never got an answer (offline, DNS, TLS, blocked,
 * timed out) — the only case in which keeping the message for later is right.
 * Anything the database answered (a policy refusal, a constraint) is final.
 */
export function isNetworkFailure(error: unknown): boolean {
  if (!error) return false;
  if (error instanceof TypeError) return true;
  const value = error as { message?: unknown; code?: unknown; name?: unknown; status?: unknown };
  if (value.name === "AbortError") return true;
  const code = typeof value.code === "string" ? value.code : "";
  if (code) return false;
  const message = String(value.message ?? "");
  return /failed to fetch|networkerror|load failed|network request failed|fetch failed|err_internet_disconnected|err_name_not_resolved|timed out|timeout/i.test(message);
}

export async function queueOutbox(item: OutboxItem): Promise<number> {
  const count = await safeInvoke<number>("outbox_put", { item });
  if (typeof window !== "undefined") window.dispatchEvent(new Event(OUTBOX_QUEUED_EVENT));
  return count;
}

export function listOutbox(): Promise<OutboxItem[]> {
  return safeInvoke<OutboxItem[]>("outbox_list", undefined, []);
}

export function removeFromOutbox(id: string): Promise<number> {
  return safeInvoke<number>("outbox_remove", { id });
}

export interface FlushResult {
  sent: number;
  /** Refused by the relay for good, or expired while waiting. */
  dropped: Array<{ id: string; reason: string }>;
  remaining: number;
  /** Stopped because the relay is still unreachable. */
  blocked: boolean;
}

/** Upload what is waiting, oldest first; stop at the first network failure. */
export async function flushOutbox(deps: {
  list: () => Promise<OutboxItem[]>;
  remove: (id: string) => Promise<unknown>;
  insert: (rows: Array<Record<string, unknown>>) => Promise<{ error: unknown }>;
  now?: number;
}): Promise<FlushResult> {
  const now = deps.now ?? Date.now();
  const items = [...await deps.list()].sort((a, b) => a.queuedAt - b.queuedAt);
  const result: FlushResult = { sent: 0, dropped: [], remaining: items.length, blocked: false };
  for (const item of items) {
    // A disappearing message that expired while waiting is never delivered late.
    const rows = item.rows.filter((row) => !row.expires_at || Date.parse(String(row.expires_at)) > now);
    if (rows.length === 0) {
      await deps.remove(item.id);
      result.dropped.push({ id: item.id, reason: "expired while waiting" });
      result.remaining -= 1;
      continue;
    }
    const { error } = await deps.insert(rows);
    if (!error) {
      await deps.remove(item.id);
      result.sent += 1;
      result.remaining -= 1;
      continue;
    }
    if (isNetworkFailure(error)) {
      result.blocked = true;
      break;
    }
    const code = (error as { code?: unknown }).code;
    await deps.remove(item.id);
    result.remaining -= 1;
    if (code === "23505") {
      // Already on the relay (an earlier flush landed before its answer was lost).
      result.sent += 1;
    } else {
      result.dropped.push({ id: item.id, reason: String((error as { message?: unknown }).message ?? "refused by the relay") });
    }
  }
  return result;
}
