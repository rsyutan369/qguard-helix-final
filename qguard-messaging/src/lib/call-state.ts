import type { CallPhase } from "@/lib/call-types";

export interface CallState {
  phase: CallPhase;
  callId: string | null;
  role: "caller" | "callee" | null;
  peerUserId: string | null;
  peerDeviceId: string | null;
  safetyNumber: string | null;
  error: string | null;
}

export type CallAction =
  | { type: "start-outgoing"; callId: string; peerUserId: string; peerDeviceId: string }
  | { type: "incoming"; callId: string; peerUserId: string; peerDeviceId: string }
  | { type: "accept" }
  | { type: "remote-answered" }
  | { type: "media-connected"; safetyNumber: string }
  | { type: "failed"; error: string }
  | { type: "ended" };

export const INITIAL_CALL_STATE: CallState = {
  phase: "idle", callId: null, role: null, peerUserId: null, peerDeviceId: null, safetyNumber: null, error: null,
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
      return ACTIVE.includes(state.phase) ? { ...state, phase: "connected", safetyNumber: action.safetyNumber } : state;
    case "failed":
      return { ...state, phase: "ended", error: action.error };
    case "ended":
      return { ...state, phase: "ended" };
    default:
      return state;
  }
}