/**
 * When to give up on a call that has been answered but is not connected yet.
 *
 * The engine used to run one fixed 45s wall clock from the moment the ring went
 * out, covering ringing AND connecting. That clock measured the wrong thing.
 * Elapsed time says nothing about whether a connection is still making
 * progress, and the failure it produced was not theoretical: a multi-NIC
 * Windows callee emitted its only usable candidate (its LAN UDP host address)
 * 48s into the call — three seconds after the caller had already given up and
 * torn everything down. The call was seconds from working when it was killed.
 *
 * So the connect phase is timed by PROGRESS instead:
 *
 *   - every sign of life (a candidate gathered, a candidate received from the
 *     peer, an ICE state transition) re-arms a STALL window;
 *   - a CEILING, fixed at the moment the call was answered, bounds the whole
 *     thing so a connection that trickles candidates forever still ends.
 *
 * Keeping the arithmetic here — pure, and away from the peer-connection
 * plumbing — is what makes the give-up policy something that can be reasoned
 * about and tested rather than re-derived from timer callbacks.
 */

/**
 * The timeout to arm after a progress event, or `null` when no new timer should
 * be set.
 *
 * `null` has two distinct meanings, and both are deliberate:
 *   - `ceilingAtMs` is 0 — the call is not in the connect phase at all (it is
 *     still ringing), so the ring's own wall clock must not be disturbed;
 *   - the ceiling has already passed — do NOT re-arm. The timer armed earlier
 *     is the backstop and must be allowed to fire, otherwise progress alone
 *     could keep a hopeless call alive indefinitely.
 */
export function connectDeadlineMs(
  nowMs: number,
  ceilingAtMs: number,
  stallMs: number,
): number | null {
  if (!ceilingAtMs) return null;
  const remaining = ceilingAtMs - nowMs;
  if (remaining <= 0) return null;
  return Math.min(stallMs, remaining);
}
