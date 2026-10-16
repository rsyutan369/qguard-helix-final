import type { CallPhase } from "@/lib/call-types";

export interface CallState {
  phase: CallPhase;
  callId: string | null;
  role: "caller" | "callee" | null;
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
  error: string | null;
}

export type CallAction =
  | { type: "start-outgoing"; callId: string; peerUserId: string; peerDeviceId: string }
  | { type: "incoming"; callId: string; peerUserId: string; peerDeviceId: string }
  | { type: "accept" }
  | { type: "remote-answered" }
  | { type: "media-connected"; safetyNumber: string; forwardSecret?: boolean; peerVerified?: boolean }
  | { type: "failed"; error: string }
  | { type: "ended" };

export const INITIAL_CALL_STATE: CallState = {
  phase: "idle", callId: null, role: null, peerUserId: null, peerDeviceId: null, safetyNumber: null,
  forwardSecret: null, peerVerified: null, error: null,
};

const ACTIVE: CallPhase[] = ["ringing", "calling", "connecting", "connected"];

export function callReducer(state: CallState, action: CallAction): CallState {
  switch (action.type) {
    case "start-outgoing":
      if (ACTIVE.includes(state.phase)) return state;
      return { ...INITIAL_CALL_STATE, phase: "calling", role: "caller", callId: action.callId, peerUserId: action.peerUserId, peerDeviceId: action.peerDeviceId };
    case "incoming":
      if (ACTIVE.includes(state.phase)) return state; // busy
      return { ...INITIAL_CALL_STATE, phase: "ringing", role: "callee", callId: action.callId, peerUserId: action.peerUserId, peerDeviceId: action.peerDeviceId };
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
        }
        : state;
    case "failed":
      return { ...state, phase: "ended", error: action.error };
    case "ended":
      return { ...state, phase: "ended" };
    default:
      return state;
  }
}
