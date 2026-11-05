export type CallSignalType = "ring" | "offer" | "answer" | "ice" | "accept" | "reject" | "hangup" | "busy";

export interface CallSignalRow {
  id: string;
  call_id: string;
  conversation_id: string;
  from_user_id: string;
  from_device_id: string;
  to_user_id: string;
  to_device_id: string;
  signal_type: CallSignalType;
  payload: Record<string, unknown>;
  created_at: string;
}

export type CallPhase = "idle" | "ringing" | "calling" | "connecting" | "connected" | "ended";

/**
 * What a call carries. A voice call opens the microphone only; it is agreed and
 * encrypted exactly like a video call (hybrid ML-KEM + X25519 key agreement,
 * AES-256-GCM on every media frame). Sent as `payload.media` on the ring and
 * the offer; absent means video, which is what builds before this sent.
 */
export type CallMedia = "voice" | "video";

/**
 * Why a call ended without an error. Lets the call history say "declined" or
 * "busy" instead of a bare "ended".
 */
export type CallEndReason =
  | "local-hangup"
  | "local-reject"
  | "remote-hangup"
  | "remote-declined"
  | "remote-busy"
  | "connection-lost";

/** The media kind a ring or offer row asks for. */
export function callMediaOf(payload: Record<string, unknown> | null | undefined): CallMedia {
  return payload?.media === "voice" ? "voice" : "video";
}