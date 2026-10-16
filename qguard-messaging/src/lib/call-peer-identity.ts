import { byteaToBytes } from "@/lib/encoding";
import { supabase } from "@/lib/supabase";
import { isCallableDevice, type CallPeerIdentityPayload } from "@/lib/call-targets";

/**
 * The registered identity of the device an incoming call claims to come from.
 *
 * The callee hands this to the Rust core, which checks the caller's signature
 * over the call against it — that is what makes "who is calling" something
 * proven rather than something a signal row merely says.
 *
 * Returns null when the row cannot be read (offline, the device was removed, or
 * row-level security hides it). The call still connects in that case, but the
 * core reports the caller as unverified and the call screen says so; nothing
 * here ever turns a failed lookup into a verified caller.
 */
export async function fetchCallPeerIdentity(
  userId: string,
  deviceId: string,
): Promise<CallPeerIdentityPayload | null> {
  try {
    const { data, error } = await supabase
      .from("messaging_devices")
      .select("id,user_id,x25519_identity_public,mlkem_identity_public,ed25519_identity_public,mldsa_identity_public,identity_signature")
      .eq("id", deviceId)
      .eq("user_id", userId)
      .maybeSingle();
    if (error || !data) return null;
    return callPeerIdentityFromRow(data as Record<string, unknown>);
  } catch {
    return null;
  }
}

export function callPeerIdentityFromRow(row: Record<string, unknown>): CallPeerIdentityPayload | null {
  const signature = row.identity_signature as { ed25519?: unknown; ml_dsa_65?: unknown } | null;
  const candidate = {
    user_id: String(row.user_id ?? ""),
    device_id: String(row.id ?? ""),
    x25519_identity_public: byteaToBytes(row.x25519_identity_public),
    mlkem_identity_public: byteaToBytes(row.mlkem_identity_public),
    ed25519_identity_public: byteaToBytes(row.ed25519_identity_public),
    mldsa_identity_public: byteaToBytes(row.mldsa_identity_public),
    identity_signature: {
      ed25519: Array.isArray(signature?.ed25519) ? (signature.ed25519 as number[]) : [],
      ml_dsa_65: Array.isArray(signature?.ml_dsa_65) ? (signature.ml_dsa_65 as number[]) : [],
    },
  };
  if (!candidate.user_id || !isCallableDevice(candidate)) return null;
  return candidate;
}
