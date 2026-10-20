import type { CallState } from "@/lib/call-state";

export interface CallSecurityLine {
  /** False for something the user should know is weaker than it could be. */
  ok: boolean;
  text: string;
}

/**
 * What can truthfully be said about how a connected call's key was agreed.
 *
 * Built only from what the Rust core reported for THIS call. Before media
 * connects there is nothing to report and this returns an empty list — the
 * screen must not claim a property the call has not yet been shown to have.
 */
export function describeCallSecurity(state: CallState, peerName: string): CallSecurityLine[] {
  if (state.phase !== "connected" || state.forwardSecret === null || state.peerVerified === null) return [];
  const name = peerName.trim() || "The other person";
  const lines: CallSecurityLine[] = [];

  lines.push(state.forwardSecret
    ? { ok: true, text: "Forward secret: part of this call's key was made for this call only and has already been destroyed." }
    : { ok: false, text: `Not forward secret: ${name}'s app is an older version, so this call's key depends only on their device's long-term key. Updating both apps fixes this.` });

  if (state.role === "callee") {
    lines.push(state.peerVerified
      ? { ok: true, text: "Caller verified: this call is signed by the device registered for them." }
      : { ok: false, text: "Caller not verified: nothing proves which device placed this call. Compare the safety number before sharing anything sensitive." });
  } else {
    lines.push(state.peerVerified
      ? { ok: true, text: "Only the device registered for them can decrypt this call." }
      : { ok: false, text: "The answering device could not be verified. Compare the safety number before sharing anything sensitive." });
  }

  // The PERSON, not just the device: only said about a device the core proved
  // holds the recorded keys (an unproven device is covered by the line above).
  const assurance = describeContactAssurance(state, name);
  if (assurance) lines.push(assurance);
  return lines;
}

/** "12 Oct 2026"-style date for a unix-seconds timestamp. */
export function formatVerifiedDate(seconds: number): string {
  return new Date(seconds * 1000).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

/**
 * Whether the user has checked who holds the other device (design §3.4).
 * A voice can be cloned, so "it sounded like them" is not on this list.
 */
export function describeContactAssurance(state: CallState, name: string): CallSecurityLine | null {
  if (state.phase !== "connected" || !state.peerVerified) return null;
  if (state.peerVerifiedAt === null) {
    return {
      ok: false,
      text: `Registered device, but you haven't verified ${name} yet. A cloned voice can't prove who it is — verify them in your chat, or ask a question only they would know.`,
    };
  }
  const when = formatVerifiedDate(state.peerVerifiedAt);
  return state.peerPaired
    ? { ok: true, text: `You verified ${name}'s device on ${when}. Ask them for their phrase to be sure it's still them.` }
    : { ok: true, text: `You verified ${name}'s device on ${when}. A call phrase becomes available once their app has paired with yours.` };
}

/** True when any line is a warning — the badge must not read as fully secure. */
export function callSecurityNeedsAttention(lines: CallSecurityLine[]): boolean {
  return lines.some((line) => !line.ok);
}
