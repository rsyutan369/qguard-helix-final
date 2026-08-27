/**
 * Call activity guard
 * ---------------------------------------------------------------------------
 * Tracks whether a quantum-encrypted call is ringing, connecting or live, so
 * the Android app-entry PIN lock does not fire underneath it.
 *
 * `use-app-lock` locks the app the instant `visibilityState` turns hidden. That
 * is the right policy for a messaging app holding decrypted history -- but it
 * is wrong during a call: the moment the user answers, taps the volume keys,
 * or the screen dims, the app would lock, unmount the call overlay and drop a
 * conversation that is already end-to-end encrypted and shows no message
 * content at all.
 *
 * A tiny module-level flag rather than React context on purpose: `use-app-lock`
 * runs ABOVE `CallProvider` in the tree (the provider must survive the lock
 * screen), so it cannot consume the call context without a cycle.
 *
 * Safety: the guard is only ever held while the call engine reports a live
 * phase, and the engine always lands in `idle`/`ended`/`failed`, so it cannot
 * get stuck holding the lock open. When a call ends while the app is still in
 * the background, subscribers re-evaluate and lock immediately.
 */

let callActive = false;
const listeners = new Set<(active: boolean) => void>();

/** True while a call is ringing, connecting or connected on this device. */
export function isCallActive(): boolean {
  return callActive;
}

/** Called by the call engine whenever the call phase enters or leaves a live state. */
export function setCallActive(active: boolean): void {
  if (callActive === active) return;
  callActive = active;
  for (const listener of listeners) {
    try {
      listener(active);
    } catch {
      // A listener must never be able to break call state transitions.
    }
  }
}

/** Subscribe to call-activity transitions. Returns an unsubscribe function. */
export function onCallActivityChange(listener: (active: boolean) => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
