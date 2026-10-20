import type { SupabaseClient } from "@supabase/supabase-js";
import { sha3_256Hex } from "@/lib/sha3";

/**
 * How an MFA recovery code is stored: a salted hash that Postgres recomputes
 * when the code is used (`consume_qguard_mfa_recovery_code`), so the two sides
 * must agree.
 *
 * SHA3-256 since roadmap 4.4 (migration 037), written as `sha3:<hex>`. Until
 * the server says it accepts that (`qguard_mfa_recovery_hash_schemes`), the
 * app keeps writing SHA-256 — so codes keep working whichever of the app and
 * the migration reaches production first.
 */
export type RecoveryHashScheme = "sha3-256" | "sha256";

export function normalizedRecoveryCode(code: string): string {
  return code.trim().replace(/-/g, "").toUpperCase();
}

export async function recoveryHashScheme(client: Pick<SupabaseClient, "rpc">): Promise<RecoveryHashScheme> {
  try {
    const { data, error } = await client.rpc("qguard_mfa_recovery_hash_schemes");
    if (!error && Array.isArray(data) && data.includes("sha3-256")) return "sha3-256";
  } catch {
    // Function missing (migration 037 not applied): the server only knows SHA-256.
  }
  return "sha256";
}

export async function hashRecoveryCode(salt: string, code: string, scheme: RecoveryHashScheme): Promise<string> {
  const input = salt + normalizedRecoveryCode(code);
  if (scheme === "sha3-256") return `sha3:${sha3_256Hex(input)}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
