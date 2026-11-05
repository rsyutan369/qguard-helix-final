// Turns the live call state into call-history entries (pure; see
// CallProvider for where it is driven from).
//
// A call is followed from the first phase this device sees (ringing, or
// calling) to "ended", and exactly one entry is produced per call id. The
// outcome comes from classifyCallOutcome — who ended it and why — and the key
// agreement facts only from what the core reported when media connected.

import { classifyCallOutcome, type CallRecordInput } from "@/lib/call-history";
import type { CallState } from "@/lib/call-state";
import type { CallMedia } from "@/lib/call-types";
import type { GroupInvite } from "@/lib/group-call";

export interface CallTrack {
  callId: string;
  role: "caller" | "callee";
  media: CallMedia;
  peerUserId: string;
  conversationId: string | null;
  startedAt: number;
  answeredAt: number | null;
  accepted: boolean;
  forwardSecret: boolean | null;
  peerVerified: boolean | null;
  done: boolean;
}

/**
 * Advance the one-to-one call track with the latest state. Returns the entry to
 * record once the call has ended (and never again for that call).
 */
export function advanceCallTrack(
  track: CallTrack | null,
  state: CallState,
  now: number,
  peerName: string,
): { track: CallTrack | null; record: CallRecordInput | null } {
  if (!state.callId || !state.role || !state.peerUserId) return { track, record: null };
  let current = track;
  if (!current || current.callId !== state.callId) {
    // A call this device never saw live (the provider mounted after it ended)
    // has no start time worth recording.
    if (state.phase === "idle" || state.phase === "ended") return { track, record: null };
    current = {
      callId: state.callId,
      role: state.role,
      media: state.media,
      peerUserId: state.peerUserId,
      conversationId: state.conversationId,
      startedAt: now,
      answeredAt: null,
      accepted: false,
      forwardSecret: null,
      peerVerified: null,
      done: false,
    };
  }
  if (current.done) return { track: current, record: null };
  const next: CallTrack = { ...current };
  if (state.phase === "connecting" && next.role === "callee") next.accepted = true;
  if (state.phase === "connected" && next.answeredAt === null) {
    next.answeredAt = now;
    next.forwardSecret = state.forwardSecret;
    next.peerVerified = state.peerVerified;
  }
  if (state.phase !== "ended") return { track: next, record: null };

  next.done = true;
  const outcome = classifyCallOutcome({
    role: next.role,
    connected: next.answeredAt !== null,
    accepted: next.accepted,
    endReason: state.endReason,
    error: state.error,
  });
  return {
    track: next,
    record: {
      id: next.callId,
      direction: next.role === "caller" ? "outgoing" : "incoming",
      media: next.media,
      group: false,
      peerUserIds: [next.peerUserId],
      peerName,
      conversationId: next.conversationId,
      outcome,
      startedAt: next.startedAt,
      answeredAt: next.answeredAt,
      endedAt: Math.max(now, next.startedAt),
      failure: outcome === "failed" ? state.error : null,
      forwardSecret: next.forwardSecret,
      peerVerified: next.peerVerified,
    },
  };
}

export interface GroupTrack {
  id: string;
  direction: "outgoing" | "incoming";
  peerUserIds: string[];
  conversationId: string;
  startedAt: number;
  answeredAt: number | null;
  done: boolean;
}

export interface GroupView {
  invite: GroupInvite | null;
  /** At least one link's media is connected. */
  connected: boolean;
}

function finishGroup(track: GroupTrack, now: number, declined: boolean, names: Record<string, string>): CallRecordInput {
  const outcome = track.answeredAt !== null
    ? "completed"
    : track.direction === "incoming"
      ? (declined ? "declined" : "missed")
      : "no_answer";
  const peerName = track.peerUserIds.map((id) => names[id] ?? "Group member").join(", ");
  return {
    id: track.id,
    direction: track.direction,
    media: "video",
    group: true,
    peerUserIds: track.peerUserIds,
    peerName,
    conversationId: track.conversationId,
    outcome,
    startedAt: track.startedAt,
    answeredAt: track.answeredAt,
    endedAt: Math.max(now, track.startedAt),
    failure: null,
    forwardSecret: null,
    peerVerified: null,
  };
}

/**
 * Advance the group-call track. A group call is one invite: it starts when
 * the invite appears, is answered when any link connects, and ends when the
 * invite goes away (or is replaced by another).
 */
export function advanceGroupTrack(
  track: GroupTrack | null,
  view: GroupView,
  context: { userId: string; now: number; declined: boolean; names: Record<string, string> },
): { track: GroupTrack | null; records: CallRecordInput[] } {
  const records: CallRecordInput[] = [];
  let current = track;
  if (current && !current.done && (!view.invite || view.invite.id !== current.id)) {
    records.push(finishGroup(current, context.now, context.declined, context.names));
    current = { ...current, done: true };
  }
  if (view.invite && (!current || current.id !== view.invite.id)) {
    current = {
      id: view.invite.id,
      direction: view.invite.inviterUserId === context.userId ? "outgoing" : "incoming",
      peerUserIds: view.invite.members.filter((member) => member !== context.userId),
      conversationId: view.invite.conversationId,
      startedAt: context.now,
      answeredAt: null,
      done: false,
    };
  }
  if (current && !current.done && view.connected && current.answeredAt === null) {
    current = { ...current, answeredAt: context.now };
  }
  return { track: current, records };
}
