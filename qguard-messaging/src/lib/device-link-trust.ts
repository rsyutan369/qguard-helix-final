import type { SupabaseClient } from "@supabase/supabase-js";
import { securityEventDetails } from "@/lib/account-key";
import { assessDevicePins, approveDevicePins, type PinnableDevice } from "@/lib/device-pins";
import { verifyLinkProof } from "@/lib/device-link";
import { byteaToBytes } from "@/lib/encoding";
import { sha3_256Hex } from "@/lib/sha3";
import { safeInvoke } from "@/lib/tauri";

/**
 * The approving device's last step of a QR link: trust the new device — but
 * only the device that proved it holds the QR's binding secret.
 *
 * The proof binds the binding secret to the device's SAFETY FINGERPRINT, and
 * the fingerprint used here is the one this device's core computes from the
 * row's identity keys (devices_assess_pins), never the `fingerprint` column.
 * A relay that swapped in a different device would need the binding secret,
 * which it never saw.
 */

export type LinkTrustOutcome =
  | { trusted: true; label: string }
  | { trusted: false; reason: string };

interface DeviceRow {
  id: string;
  user_id: string;
  device_label: string;
  trust_state: string;
  revoked_at: string | null;
  x25519_identity_public: unknown;
  mlkem_identity_public: unknown;
  ed25519_identity_public: unknown;
  mldsa_identity_public: unknown;
  identity_signature: { ed25519: number[]; ml_dsa_65: number[] } | null;
}

function pinnable(row: DeviceRow): PinnableDevice & { label: string } {
  return {
    device_id: row.id,
    user_id: row.user_id,
    label: row.device_label,
    trust_state: row.revoked_at || row.trust_state === "revoked" ? "Revoked" : "Trusted",
    x25519_identity_public: byteaToBytes(row.x25519_identity_public),
    mlkem_identity_public: byteaToBytes(row.mlkem_identity_public),
    ed25519_identity_public: byteaToBytes(row.ed25519_identity_public),
    mldsa_identity_public: byteaToBytes(row.mldsa_identity_public),
    identity_signature: row.identity_signature,
  };
}

export async function trustLinkedDevice(input: {
  client: SupabaseClient;
  userId: string;
  linkId: string;
  bindingSecret: string;
  linkedDeviceId: string;
  linkProof: string | null;
  approverDeviceId: string | null;
}): Promise<LinkTrustOutcome> {
  const { client, userId, linkedDeviceId } = input;
  const { data, error } = await client
    .from("messaging_devices")
    .select("id,user_id,device_label,trust_state,revoked_at,x25519_identity_public,mlkem_identity_public,ed25519_identity_public,mldsa_identity_public,identity_signature")
    .eq("user_id", userId);
  if (error) return { trusted: false, reason: "The device directory couldn't be read." };
  const rows = (data ?? []) as DeviceRow[];
  const target = rows.find((row) => row.id === linkedDeviceId);
  if (!target || target.revoked_at) return { trusted: false, reason: "The new device isn't registered on this account." };

  // Assess the whole account so a first assessment records every device, not just this one.
  const assessment = await assessDevicePins(rows.map(pinnable));
  const verdict = assessment?.verdicts.find((item) => item.deviceId === linkedDeviceId);
  if (!verdict || verdict.standing === "invalid_identity" || verdict.standing === "key_changed" || verdict.standing === "unknown") {
    return { trusted: false, reason: "The new device's identity keys could not be verified." };
  }
  const proven = verifyLinkProof(
    { bindingSecret: input.bindingSecret, linkId: input.linkId, userId, deviceId: linkedDeviceId, fingerprint: verdict.fingerprint },
    input.linkProof,
  );
  if (!proven) return { trusted: false, reason: "The new device couldn't prove it is the one you scanned. Review it in the Device Trust Center before trusting it." };

  const device = pinnable(target);
  await safeInvoke("devices_approve_qr", {
    request: { deviceId: linkedDeviceId, label: target.device_label, fingerprint: verdict.fingerprint },
  }, null);
  if (verdict.standing !== "pinned") await approveDevicePins([device]);

  const { error: trustError } = await client
    .from("messaging_devices")
    .update({ trust_state: "trusted", approved_by_device_id: input.approverDeviceId, revoked_at: null })
    .eq("id", linkedDeviceId)
    .eq("user_id", userId)
    .neq("trust_state", "this_device");
  if (trustError) return { trusted: false, reason: "The device was verified, but its trust state couldn't be saved. Approve it in the Device Trust Center." };

  try {
    const createdAt = new Date().toISOString();
    const metadata = { label: target.device_label, approved_by: input.approverDeviceId, method: "qr_link", proof: "verified" };
    const eventHash = sha3_256Hex(JSON.stringify({ eventType: "device_linked", deviceId: linkedDeviceId, metadata, createdAt }));
    await client.from("messaging_security_events").insert({
      user_id: userId,
      device_id: linkedDeviceId,
      event_type: "device_linked",
      severity: "info",
      encrypted_details: await securityEventDetails(eventHash, metadata),
      event_hash: eventHash,
    });
  } catch {
    // The audit trail must not undo a completed, verified link.
  }
  return { trusted: true, label: target.device_label };
}
