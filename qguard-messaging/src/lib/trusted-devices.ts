import type { SupabaseClient } from "@supabase/supabase-js";
import type { AppLockDevice } from "@/lib/use-app-lock";

export interface TrustedDeviceRow {
  id: string;
  device_id: string;
  device_name: string | null;
  platform: string | null;
  app_version: string | null;
  registered_at: string;
  last_login_at: string | null;
  revoked_at: string | null;
}

export async function upsertTrustedDevice(client: SupabaseClient, userId: string, device: AppLockDevice): Promise<void> {
  await client.from("trusted_devices").upsert(
    {
      user_id: userId,
      device_id: device.deviceId,
      device_name: device.deviceName,
      platform: device.platform,
      app_version: device.appVersion,
      last_login_at: new Date().toISOString(),
      revoked_at: null,
    },
    { onConflict: "user_id,device_id" },
  );
}

export async function listTrustedDevices(client: SupabaseClient, userId: string): Promise<TrustedDeviceRow[]> {
  const { data } = await client
    .from("trusted_devices")
    .select("*")
    .eq("user_id", userId)
    .order("last_login_at", { ascending: false });
  return (data as TrustedDeviceRow[] | null) ?? [];
}

export async function revokeTrustedDevice(client: SupabaseClient, userId: string, deviceId: string): Promise<void> {
  await client
    .from("trusted_devices")
    .update({ revoked_at: new Date().toISOString() })
    .eq("user_id", userId)
    .eq("device_id", deviceId);
}

export async function isDeviceRevoked(client: SupabaseClient, userId: string, deviceId: string): Promise<boolean> {
  const { data } = await client
    .from("trusted_devices")
    .select("revoked_at")
    .eq("user_id", userId)
    .eq("device_id", deviceId)
    .maybeSingle();
  return Boolean((data as { revoked_at: string | null } | null)?.revoked_at);
}
