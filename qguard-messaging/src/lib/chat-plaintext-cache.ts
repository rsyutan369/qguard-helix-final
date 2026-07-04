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
 * user/device changes.
 */

const messageCache = new Map<string, unknown>();
const controlCache = new Map<string, unknown>();
let ownerUserId: string | null = null;
let ownerDeviceId: string | null = null;

export function chatMessageCache<T>(): Map<string, T> {
  return messageCache as Map<string, T>;
}

export function chatControlCache<T>(): Map<string, T> {
  return controlCache as Map<string, T>;
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
  ownerDeviceId = deviceId;
}

/** Wipe all decrypted chat plaintext (workspace lock, logout). */
export function clearChatPlaintextCaches(): void {
  messageCache.clear();
  controlCache.clear();
  ownerUserId = null;
  ownerDeviceId = null;
}
