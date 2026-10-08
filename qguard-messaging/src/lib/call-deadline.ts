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

export interface IceRecoveryInputs {
  /** Media is already flowing — there is nothing to recover. */
  readonly connected: boolean;
  /** The live peer connection already carries a TURN relay. */
  readonly relayInPeerConnection: boolean;
  /** A relay is configured AND has been proven able to allocate. */
  readonly relayProven: boolean;
  readonly restartsUsed: number;
  readonly maxRestarts: number;
}

/**
 * Whether restarting ICE on a still-connecting call can plausibly change the
 * outcome.
 *
 * The restraint is the whole point. An ICE restart abandons the current
 * generation of candidate pairs, so restarting a connection that was merely
 * slow can destroy the handshake that was about to succeed — this codebase has
 * already lost a call to a timer that fired three seconds before the only
 * usable candidate arrived. A restart that re-gathers the SAME servers can only
 * reproduce the same failure, so elapsed time alone is never a reason.
 *
 * New information is. The one condition that genuinely changes the answer is a
 * relay that has since been proven healthy and is not yet in the peer
 * connection: that adds candidate types the failed generation never had. Left
 * to itself, a connecting call keeps its existing generation and the normal
 * progress/stall machinery decides its fate.
 */
export function shouldAttemptIceRecovery(inputs: IceRecoveryInputs): boolean {
  if (inputs.connected) return false;
  if (inputs.restartsUsed >= inputs.maxRestarts) return false;
  // Nothing new to offer: a re-gather on identical servers is pure downside.
  if (!inputs.relayProven) return false;
  if (inputs.relayInPeerConnection) return false;
  return true;
}
