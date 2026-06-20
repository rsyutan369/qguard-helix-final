import { supabase } from "@/lib/supabase";
import type { CallSignalRow, CallSignalType } from "@/lib/call-types";

const TYPES: CallSignalType[] = ["ring", "offer", "answer", "ice", "accept", "reject", "hangup", "busy"];

export function parseCallSignal(raw: unknown): CallSignalRow | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (!TYPES.includes(r.signal_type as CallSignalType)) return null;
  return {
    id: String(r.id ?? ""),
    call_id: String(r.call_id ?? ""),
    conversation_id: String(r.conversation_id ?? ""),
    from_user_id: String(r.from_user_id ?? ""),
    from_device_id: String(r.from_device_id ?? ""),
    to_user_id: String(r.to_user_id ?? ""),
    to_device_id: String(r.to_device_id ?? ""),
    signal_type: r.signal_type as CallSignalType,
    payload: (r.payload as Record<string, unknown>) ?? {},
    created_at: String(r.created_at ?? new Date().toISOString()),
  };
}

export async function sendCallSignal(input: Omit<CallSignalRow, "id" | "created_at">): Promise<void> {
  const { error } = await supabase.from("messaging_call_signals").insert(input);
  if (error) throw new Error(error.message);
}

export function subscribeCallSignals(opts: {
  userId: string; deviceId: string; onSignal: (row: CallSignalRow) => void;
}): () => void {
  const channel = supabase
    .channel(`qguard-call-signals-${opts.userId}-${opts.deviceId}`)
    .on("postgres_changes",
      { event: "INSERT", schema: "public", table: "messaging_call_signals", filter: `to_user_id=eq.${opts.userId}` },
      (payload) => {
        const row = parseCallSignal(payload.new);
        if (row && (row.to_device_id === opts.deviceId || row.signal_type === "ring")) opts.onSignal(row);
      })
    .subscribe();
  return () => { void supabase.removeChannel(channel); };
}