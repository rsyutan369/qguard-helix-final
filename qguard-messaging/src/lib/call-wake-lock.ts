/**
 * Keep the screen awake for the duration of a call.
 *
 * On Android the WebView is suspended when the screen turns off: timers stop,
 * the Supabase realtime socket drops, and the peer connection is starved until
 * the ICE agent gives up. So a call that outlives the phone's display timeout
 * dies for a reason that has nothing to do with the network — the user simply
 * stopped touching a screen they were talking into.
 *
 * A screen wake lock is the platform's own answer to this and is exactly what a
 * video call is meant to use. It is best effort by design: the API is missing
 * on some builds, and the browser releases the lock whenever the page is hidden
 * (switching apps, or the user locking the phone deliberately), so the lock is
 * re-acquired on every return to visibility rather than assumed to persist.
 */

interface WakeLockSentinelLike {
  released: boolean;
  release: () => Promise<void>;
  addEventListener?: (type: "release", listener: () => void) => void;
}

interface WakeLockNavigator {
  wakeLock?: { request: (type: "screen") => Promise<WakeLockSentinelLike> };
}

let sentinel: WakeLockSentinelLike | null = null;
let wanted = false;
let acquiring = false;

async function acquire(): Promise<void> {
  const api = (navigator as Navigator & WakeLockNavigator).wakeLock;
  if (!api || acquiring || sentinel) return;
  // The request is rejected outright while the document is hidden; asking then
  // would just burn a promise rejection, and the visibility listener re-tries.
  if (typeof document !== "undefined" && document.visibilityState !== "visible") return;
  acquiring = true;
  try {
    const next = await api.request("screen");
    if (!wanted) {
      void next.release().catch(() => undefined);
      return;
    }
    sentinel = next;
    next.addEventListener?.("release", () => {
      if (sentinel === next) sentinel = null;
    });
  } catch {
    // No wake lock available (unsupported, denied, or not visible). The call
    // still works; it is only more likely to be interrupted by a screen
    // timeout, so this must never surface as a call error.
  } finally {
    acquiring = false;
  }
}

function onVisibility(): void {
  if (!wanted) return;
  if (document.visibilityState === "visible") void acquire();
}

/** Hold the screen awake until `releaseCallWakeLock` is called. Idempotent. */
export function requestCallWakeLock(): void {
  if (wanted) return;
  wanted = true;
  if (typeof document !== "undefined") document.addEventListener("visibilitychange", onVisibility);
  void acquire();
}

/** Release the screen wake lock. Idempotent, and safe to call when never held. */
export function releaseCallWakeLock(): void {
  wanted = false;
  if (typeof document !== "undefined") document.removeEventListener("visibilitychange", onVisibility);
  const held = sentinel;
  sentinel = null;
  if (held && !held.released) void held.release().catch(() => undefined);
}
