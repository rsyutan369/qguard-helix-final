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
  return lines;
}

/** True when any line is a warning — the badge must not read as fully secure. */
export function callSecurityNeedsAttention(lines: CallSecurityLine[]): boolean {
  return lines.some((line) => !line.ok);
}
