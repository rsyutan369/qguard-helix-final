import type { CallEndReason, CallMedia, CallPhase } from "@/lib/call-types";

export interface CallState {
  phase: CallPhase;
  callId: string | null;
  role: "caller" | "callee" | null;
  /** The conversation the call belongs to (null before a call starts). */
  conversationId: string | null;
  /** Voice (microphone only) or video. Fixed for the life of a call. */
  media: CallMedia;
  /** Why an ended call ended, when it ended without an error. */
  endReason: CallEndReason | null;
  peerUserId: string | null;
  peerDeviceId: string | null;
  safetyNumber: string | null;
  /**
   * How this call's key was agreed, as reported by the Rust core once media
   * connects (null until then — never assumed):
   *   - `forwardSecret`: the key also depends on a key pair that existed only
   *     for this call. False when the other side runs a build that predates it.
   *   - `peerVerified`: the other party proved it holds the identity registered
   *     for its device. For an incoming call, false means the caller is unproven.
   */
  forwardSecret: boolean | null;
  peerVerified: boolean | null;
  /**
   * The person, not just the device (null until media connects):
   *   - `peerVerifiedAt`: when the user verified this exact device here by
   *     comparing safety numbers (unix seconds), or null if never;
   *   - `peerPaired`: a challenge phrase can be shown with this device.
   * Both come from this device's own record, checked against the keys the
   * call was agreed with — never from the relay.
   */
  peerVerifiedAt: number | null;
  peerPaired: boolean | null;
  error: string | null;
}

export type CallAction =
  | { type: "start-outgoing"; callId: string; peerUserId: string; peerDeviceId: string; media?: CallMedia; conversationId?: string }
  | { type: "incoming"; callId: string; peerUserId: string; peerDeviceId: string; media?: CallMedia; conversationId?: string }
  | { type: "accept" }
  | { type: "remote-answered" }
  | { type: "media-connected"; safetyNumber: string; forwardSecret?: boolean; peerVerified?: boolean; peerVerifiedAt?: number | null; peerPaired?: boolean }
  | { type: "failed"; error: string }
  | { type: "ended"; reason?: CallEndReason };

export const INITIAL_CALL_STATE: CallState = {
  phase: "idle", callId: null, role: null, conversationId: null, media: "video", endReason: null, peerUserId: null, peerDeviceId: null, safetyNumber: null,
  forwardSecret: null, peerVerified: null, peerVerifiedAt: null, peerPaired: null, error: null,
};

const ACTIVE: CallPhase[] = ["ringing", "calling", "connecting", "connected"];

export function callReducer(state: CallState, action: CallAction): CallState {
  switch (action.type) {
    case "start-outgoing":
      if (ACTIVE.includes(state.phase)) return state;
      return { ...INITIAL_CALL_STATE, phase: "calling", role: "caller", conversationId: action.conversationId ?? null, media: action.media ?? "video", callId: action.callId, peerUserId: action.peerUserId, peerDeviceId: action.peerDeviceId };
    case "incoming":
      if (ACTIVE.includes(state.phase)) return state; // busy
      return { ...INITIAL_CALL_STATE, phase: "ringing", role: "callee", conversationId: action.conversationId ?? null, media: action.media ?? "video", callId: action.callId, peerUserId: action.peerUserId, peerDeviceId: action.peerDeviceId };
    case "accept":
      return state.phase === "ringing" ? { ...state, phase: "connecting" } : state;
    case "remote-answered":
      return state.phase === "calling" ? { ...state, phase: "connecting" } : state;
    case "media-connected":
      return ACTIVE.includes(state.phase)
        ? {
          ...state,
          phase: "connected",
          safetyNumber: action.safetyNumber,
          // Absent means the core did not say — which must read as "not
          // established", never as a default of true.
          forwardSecret: action.forwardSecret ?? false,
          peerVerified: action.peerVerified ?? false,
          peerVerifiedAt: action.peerVerifiedAt ?? null,
          peerPaired: action.peerPaired ?? false,
        }
        : state;
    case "failed":
      return { ...state, phase: "ended", error: action.error, endReason: null };
    case "ended":
      // A second "ended" (a late remote hangup after ours) keeps the first reason.
      if (state.phase === "ended") return state;
      return { ...state, phase: "ended", endReason: action.reason ?? null };
    default:
      return state;
  }
}
