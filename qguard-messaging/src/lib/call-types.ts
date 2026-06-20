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