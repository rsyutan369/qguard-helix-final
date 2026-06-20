import { supabase } from "@/lib/supabase";

type TelemetryScope = "message" | "vault" | "key" | "upload" | "download" | "verification" | "call";

interface CryptoTelemetryInput {
  userId: string;
  deviceId?: string | null;
  scope: TelemetryScope;
  stage: string;
  detail: string;
  progress: number;
  status?: "started" | "progress" | "verified" | "failed" | "complete";
  metadata?: Record<string, string | number | boolean | null>;
}

export async function recordCryptoTelemetry(input: CryptoTelemetryInput): Promise<void> {
  try {
    await supabase.from("messaging_crypto_telemetry").insert({
      user_id: input.userId,
      device_id: input.deviceId ?? null,
      event_scope: input.scope,
      stage: input.stage,
      detail: input.detail,
      progress: Math.max(0, Math.min(100, Math.round(input.progress))),
      status: input.status ?? "progress",
      redacted_metadata: input.metadata ?? {},
    });
  } catch {
    // Telemetry must never block crypto or reveal plaintext through error surfaces.
  }
}
