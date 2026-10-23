import { sealJson, telemetryPlaceholder } from "@/lib/account-key";
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
    // The detail (often an error message) and the metadata (conversation and
    // device ids) are read only by this account's devices, so they are sealed.
    // The row's own id is the context, so a sealed value cannot be moved to
    // another row. Without a key the detail is withheld, never sent in the clear.
    const id = crypto.randomUUID();
    const sealed = await sealJson("telemetry", id, { detail: input.detail, metadata: input.metadata ?? {} });
    await supabase.from("messaging_crypto_telemetry").insert({
      id,
      user_id: input.userId,
      device_id: input.deviceId ?? null,
      event_scope: input.scope,
      stage: input.stage,
      detail: telemetryPlaceholder(input.stage),
      progress: Math.max(0, Math.min(100, Math.round(input.progress))),
      status: input.status ?? "progress",
      redacted_metadata: sealed ?? {},
    });
  } catch {
    // Telemetry must never block crypto or reveal plaintext through error surfaces.
  }
}
