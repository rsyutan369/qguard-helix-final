/**
 * Memory-only decrypted-message caches for Secure Chat.
 *
 * Hoisted to module scope so navigating away from the chat page and back does
 * NOT throw away already-decrypted history — re-decrypting every envelope on
 * each visit was a major source of "loading encrypted history..." delay.
 *
 * Security model: plaintext lives only in JS memory of the running app (the
 * same exposure as the previous per-mount refs, just longer-lived). It is
 * wiped when the chat workspace locks, on logout, and whenever the owning
 * user/device changes. Decrypted group names (group-chat.ts) go with them.
 */

import { forgetAssistantOutputs } from "@/lib/ai-assistant";
import { forgetGroupNames } from "@/lib/group-chat";

const messageCache = new Map<string, unknown>();
const controlCache = new Map<string, unknown>();
/**
 * The last rendered thread per conversation, so reopening one can paint from
 * memory instead of waiting on the network.
 *
 * The per-group caches above remove the cost of RE-DECRYPTING, but they are
 * keyed by message group, so there is no way to ask them "what was in this
 * conversation?" without first fetching the envelope list — and that fetch was
 * the thing holding the "Loading encrypted history..." gate up. This map
 * answers that question directly, so the fetch becomes a background
 * reconciliation rather than a precondition for showing anything.
 *
 * Memory only, exactly like the plaintext it holds: history is never written to
 * disk, so a cold start still decrypts from the backend. Bounded so a long
 * session with many threads cannot grow without limit.
 */
const historySnapshots = new Map<string, unknown[]>();
const MAX_SNAPSHOT_CONVERSATIONS = 8;
let ownerUserId: string | null = null;
let ownerDeviceId: string | null = null;

export function chatMessageCache<T>(): Map<string, T> {
  return messageCache as Map<string, T>;
}

export function chatControlCache<T>(): Map<string, T> {
  return controlCache as Map<string, T>;
}

/**
 * The thread last rendered for a conversation, or null when it has never been
 * opened in this session.
 *
 * A copy is returned: the caller hands this straight to React state, and the
 * retained array must not be mutated by whatever happens to it downstream.
 */
export function chatHistorySnapshot<T>(conversationId: string): T[] | null {
  const snapshot = historySnapshots.get(conversationId);
  return snapshot ? ([...snapshot] as T[]) : null;
}

/**
 * Remember the thread just rendered for a conversation.
 *
 * An empty thread is recorded too — "this conversation has no visible messages"
 * is a real, useful answer that should render instantly on reopen instead of
 * showing a spinner that resolves to nothing. Re-setting moves the conversation
 * to the most-recent end of the eviction order.
 */
export function setChatHistorySnapshot<T>(conversationId: string, messages: readonly T[]): void {
  if (!conversationId) return;
  historySnapshots.delete(conversationId);
  historySnapshots.set(conversationId, [...messages]);
  while (historySnapshots.size > MAX_SNAPSHOT_CONVERSATIONS) {
    const oldest = historySnapshots.keys().next();
    if (oldest.done) break;
    historySnapshots.delete(oldest.value);
  }
}

/** Forget one conversation's snapshot (its history was cleared or purged). */
export function clearChatHistorySnapshot(conversationId: string): void {
  historySnapshots.delete(conversationId);
}

/**
 * Bind the caches to their owning user/device. Clears only on a REAL owner
 * change: a different user always wipes; the first device resolution after a
 * remount (same user, device previously unknown) adopts the device silently so
 * the warm cache survives; a genuinely different device wipes.
 */
export function ensureChatCacheOwner(userId: string, deviceId: string | null): void {
  if (ownerUserId !== userId) {
    messageCache.clear();
    controlCache.clear();
    historySnapshots.clear();
    forgetGroupNames();
    forgetAssistantOutputs();
    ownerUserId = userId;
    ownerDeviceId = deviceId;
    return;
  }
  if (deviceId === null || ownerDeviceId === deviceId) return;
  if (ownerDeviceId === null) {
    ownerDeviceId = deviceId;
    return;
  }
  messageCache.clear();
  controlCache.clear();
  historySnapshots.clear();
  forgetGroupNames();
  forgetAssistantOutputs();
  ownerDeviceId = deviceId;
}

/** Wipe all decrypted chat plaintext (workspace lock, logout). */
export function clearChatPlaintextCaches(): void {
  messageCache.clear();
  controlCache.clear();
  historySnapshots.clear();
  forgetGroupNames();
  forgetAssistantOutputs();
  ownerUserId = null;
  ownerDeviceId = null;
}
