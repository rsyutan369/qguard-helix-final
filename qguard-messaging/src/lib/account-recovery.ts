// Account-level vault recovery registry (Unify_Syncronization).
//
// One recovery key per QGuard ACCOUNT, valid on every trusted device. The
// registry row (messaging_account_recovery, migration 029) stores only the
// one-way verifier computed on-device in Rust — never the key itself — so any
// signed-in device can:
//   * see that the account already has a recovery key (and steer the user to
//     "enable the existing key" instead of generating a second one),
//   * validate a typed key against the account before enabling it locally,
//   * reset its vault lock with the account key even if this device never
//     stored local recovery material.
// Vault CONTENTS remain device-local and are never synchronized.

import type { SupabaseClient } from "@supabase/supabase-js";

export interface AccountRecoveryRecord {
  mode: "personal" | "enterprise" | "hybrid";
  verifier: string;
  recipientKeyId: string | null;
  configuredAt: string;
}

function isMissingRelation(error: unknown): boolean {
  const raw = [
    (error as { code?: string })?.code,
    (error as { message?: string })?.message,
    (error as { details?: string })?.details,
  ]
    .filter(Boolean)
    .join(" ");
  return raw.includes("PGRST205") || /could not find|does not exist|schema cache|relation/i.test(raw);
}

/**
 * Loads the account's recovery registry row. Returns `null` when the account
 * has no registered key yet, and treats a missing table (migration 029 not
 * applied) as "no registry" so the device-local flow keeps working unchanged.
 */
export async function loadAccountRecovery(
  client: SupabaseClient,
  userId: string,
): Promise<AccountRecoveryRecord | null> {
  const { data, error } = await client
    .from("messaging_account_recovery")
    .select("mode,verifier,recipient_key_id,configured_at")
    .eq("user_id", userId)
    .maybeSingle();
  if (error) {
    if (isMissingRelation(error)) return null;
    throw new Error(error.message || "Account recovery registry could not be loaded.");
  }
  if (!data) return null;
  return {
    mode: String(data.mode) as AccountRecoveryRecord["mode"],
    verifier: String(data.verifier),
    recipientKeyId: data.recipient_key_id ? String(data.recipient_key_id) : null,
    configuredAt: String(data.configured_at),
  };
}

/**
 * Publishes (or refreshes) the account recovery registry row after a local
 * setup/reset. Best-effort by design: a failure never blocks the local setup
 * that already succeeded — the returned notice lets the UI surface it.
 */
export async function publishAccountRecovery(
  client: SupabaseClient,
  userId: string,
  record: { mode: string; verifier: string; recipientKeyId?: string | null },
): Promise<{ ok: boolean; notice: string | null }> {
  const { error } = await client.from("messaging_account_recovery").upsert(
    {
      user_id: userId,
      mode: record.mode,
      verifier: record.verifier,
      recipient_key_id: record.recipientKeyId ?? null,
      updated_at: new Date().toISOString(),
    },
    { onConflict: "user_id" },
  );
  if (!error) return { ok: true, notice: null };
  if (isMissingRelation(error)) {
    return {
      ok: false,
      notice:
        "Recovery is active on this device, but the account registry is unavailable — apply Supabase migration 029 so other devices can validate this key.",
    };
  }
  return { ok: false, notice: error.message || "Account recovery registry could not be updated." };
}
