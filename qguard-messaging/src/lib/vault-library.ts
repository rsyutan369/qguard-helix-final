// Quantum Vault phase 3 — one library across the account's devices.
//
// The Rust core holds the library key ring (inside the sealed vault index) and
// does every seal, open and merge (src-tauri/src/commands/vault_library.rs).
// This module moves opaque rows and objects through Supabase (migration 049):
//
//   key ring:  qv_library_key_wraps — sealed by one of the user's devices to
//              another it has pinned (approved in the Device Trust Center);
//              qv_library_recovery — sealed under the account recovery key, and
//              the election token for who starts the library.
//   document:  a `library_index` cloud object; qv_library_state names the
//              current one. Publishing is compare-and-swap on its revision:
//              a device that has not merged the latest revision is refused,
//              merges, and tries again — it never overwrites another device.

import type { SupabaseClient } from "@supabase/supabase-js";
import { devicesNeedingWrap, rotationDue, type WrapRowLike } from "@/lib/account-key";
import { callPeerIdentityFromRow } from "@/lib/call-peer-identity";
import type { CallPeerIdentityPayload } from "@/lib/call-targets";
import { safeInvoke } from "@/lib/tauri";

export interface LibraryStatus {
  hasRing: boolean;
  epoch: number | null;
  revision: number;
  publishNeeded: boolean;
  recoveryEnvelopeNeeded: boolean;
  /** A personal recovery key is configured on this device. */
  recoveryReady: boolean;
  tombstones: number;
  lastMergeAt: string | null;
  deviceId: string;
}

export interface MergeReport {
  added: number;
  updated: number;
  removed: string[];
  repaired: number;
}

export interface LibraryState {
  revision: number;
  object_id: string | null;
  epoch: number;
  updated_by_device: string | null;
  updated_at: string;
}

export interface LibraryDevice {
  id: string;
  label: string;
  trusted: boolean;
  revoked: boolean;
  isThisDevice: boolean;
  /** Holds the current library epoch: this device, a sender, or an accepted wrap. */
  hasLibraryKey: boolean;
  lastSeenAt: string | null;
}

export interface KeySyncResult {
  status: LibraryStatus;
  devices: LibraryDevice[];
  /** Nothing to join with yet: no library key here and no way to get one. */
  waitingForAccess: boolean;
}

export const libraryCore = {
  status: () => safeInvoke<LibraryStatus>("vault_library_status"),
};

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : typeof error === "object" && error && "message" in error ? String((error as { message: unknown }).message) : String(error);
}

interface DeviceRow extends Record<string, unknown> {
  id: string;
  device_label?: string | null;
  trust_state?: string | null;
  revoked_at?: string | null;
  last_seen_at?: string | null;
}

async function loadDevices(client: SupabaseClient, userId: string): Promise<DeviceRow[]> {
  const { data, error } = await client
    .from("messaging_devices")
    .select("id,user_id,device_label,trust_state,revoked_at,last_seen_at,x25519_identity_public,mlkem_identity_public,ed25519_identity_public,mldsa_identity_public,identity_signature")
    .eq("user_id", userId);
  if (error) throw error;
  return (data ?? []) as DeviceRow[];
}

/** Store the recovery copy of the ring; adopt the stored one if we lost the race. */
async function storeRecoveryCopy(client: SupabaseClient): Promise<LibraryStatus> {
  const envelope = await safeInvoke<{ v: number; epoch: number }>("vault_library_recovery_envelope");
  const { error } = await client.rpc("qv_library_set_recovery", { p_epoch: envelope.epoch, p_envelope: envelope });
  if (!error) {
    await safeInvoke("vault_library_mark_recovery_stored", { epoch: envelope.epoch });
    return libraryCore.status();
  }
  if (!error.message.includes("QV_RECOVERY_EXISTS")) throw error;
  // Another device started this epoch first: take its ring.
  const { data } = await client.from("qv_library_recovery").select("epoch,envelope").maybeSingle();
  if (!data) throw error;
  return safeInvoke<LibraryStatus>("vault_library_accept_recovery", { envelope: data.envelope, recoveryKey: null });
}

/**
 * Bring this device's library key ring up to date: accept a ring sealed to it,
 * join through the recovery copy, start the library if nobody has, rotate when
 * a device that held the key was removed, keep the recovery copy current, and
 * seal the ring to the account's other trusted devices that lack it.
 */
export async function syncLibraryKey(client: SupabaseClient, userId: string): Promise<KeySyncResult> {
  let status = await libraryCore.status();
  const deviceId = status.deviceId;
  const deviceRows = await loadDevices(client, userId);
  const isTrusted = (row: DeviceRow) => !row.revoked_at && (row.trust_state === "trusted" || row.trust_state === "this_device" || row.id === deviceId);
  const trustedIds = deviceRows.filter(isTrusted).map((row) => String(row.id));
  const revokedIds = deviceRows.filter((row) => row.revoked_at || row.trust_state === "revoked").map((row) => String(row.id));
  const identityOf = (id: string): CallPeerIdentityPayload | null => {
    const row = deviceRows.find((candidate) => String(candidate.id) === id);
    return row ? callPeerIdentityFromRow(row) : null;
  };

  const { data: wrapData, error: wrapError } = await client
    .from("qv_library_key_wraps")
    .select("id,from_device_id,to_device_id,epoch,wrap,accepted_at");
  if (wrapError) throw wrapError;
  let wraps = (wrapData ?? []) as Array<WrapRowLike & { id: string; wrap: unknown }>;

  // 1. A ring sealed to this device by another of the user's devices.
  for (const row of wraps) {
    if (String(row.to_device_id) !== deviceId || row.accepted_at) continue;
    const sender = identityOf(String(row.from_device_id));
    if (!sender) continue;
    try {
      status = await safeInvoke<LibraryStatus>("vault_library_accept_wrap", { wrap: row.wrap, sender });
      await client.from("qv_library_key_wraps").update({ accepted_at: new Date().toISOString(), wrap: {} }).eq("id", row.id);
      row.accepted_at = new Date().toISOString();
    } catch {
      // Not from a device this device has recorded as the user's own yet: retried later.
    }
  }

  const { data: recovery } = await client.from("qv_library_recovery").select("epoch,envelope").maybeSingle();
  const { data: libraryState } = await client.from("qv_library_state").select("revision").maybeSingle();

  // 2. Join through the recovery copy with this device's own recovery key.
  if (!status.hasRing && recovery && status.recoveryReady) {
    status = await safeInvoke<LibraryStatus>("vault_library_accept_recovery", { envelope: recovery.envelope, recoveryKey: null });
  }

  // 3. Nobody has started a library: this device does (it needs a recovery key,
  //    so the library can always be recovered). The recovery copy decides a race.
  if (!status.hasRing && !recovery && !libraryState && wraps.length === 0 && status.recoveryReady) {
    await safeInvoke<LibraryStatus>("vault_library_create");
    status = await storeRecoveryCopy(client);
  }

  if (!status.hasRing || status.epoch === null) {
    return { status, devices: describeDevices(deviceRows, deviceId, wraps, status), waitingForAccess: true };
  }

  // 4. A device that was handed the current key has been removed: new epoch.
  if (rotationDue({ selfId: deviceId, trustedIds, revokedIds, rows: wraps, currentEpoch: status.epoch })) {
    status = await safeInvoke<LibraryStatus>("vault_library_rotate");
  }

  // 5. Keep the recovery copy at the current epoch.
  if (status.recoveryEnvelopeNeeded) {
    try {
      status = await storeRecoveryCopy(client);
    } catch {
      // Retried on the next pass.
    }
  }

  // 6. Seal the ring to the user's other trusted devices that lack this epoch.
  const epoch = status.epoch ?? 1;
  for (const targetId of devicesNeedingWrap({ selfId: deviceId, trustedIds, rows: wraps, currentEpoch: epoch })) {
    const target = identityOf(targetId);
    if (!target) continue;
    try {
      const wrap = await safeInvoke<{ epoch: number }>("vault_library_make_wrap", { target });
      const { error } = await client
        .from("qv_library_key_wraps")
        .upsert({ user_id: userId, from_device_id: deviceId, to_device_id: targetId, epoch: wrap.epoch, wrap, accepted_at: null }, { onConflict: "to_device_id,epoch" });
      if (!error) wraps = [...wraps, { id: "", from_device_id: deviceId, to_device_id: targetId, epoch: wrap.epoch, accepted_at: null, wrap }];
    } catch {
      // The core refuses a device this device has not recorded as the user's own.
    }
  }
  return { status, devices: describeDevices(deviceRows, deviceId, wraps, status), waitingForAccess: false };
}

function describeDevices(rows: DeviceRow[], deviceId: string, wraps: WrapRowLike[], status: LibraryStatus): LibraryDevice[] {
  const epoch = status.epoch;
  return rows
    .map((row) => {
      const id = String(row.id);
      const isThisDevice = id === deviceId;
      const holds =
        epoch !== null &&
        (isThisDevice
          ? status.hasRing
          : wraps.some((w) => w.epoch === epoch && ((w.to_device_id === id && w.accepted_at) || w.from_device_id === id)));
      return {
        id,
        label: String(row.device_label ?? (isThisDevice ? "This device" : "Device")),
        trusted: !row.revoked_at && (row.trust_state === "trusted" || row.trust_state === "this_device" || isThisDevice),
        revoked: Boolean(row.revoked_at) || row.trust_state === "revoked",
        isThisDevice,
        hasLibraryKey: holds,
        lastSeenAt: (row.last_seen_at as string | null) ?? null,
      };
    })
    .sort((a, b) => Number(b.isThisDevice) - Number(a.isThisDevice) || a.label.localeCompare(b.label));
}

/**
 * Join the account library on this device with a recovery key the user types
 * (a new device, or after a vault reset). Returns null when the account has no
 * library — the caller then falls back to the older per-device backup.
 */
export async function joinLibraryWithRecoveryKey(client: SupabaseClient, recoveryKey: string): Promise<LibraryStatus | null> {
  const { data, error } = await client.from("qv_library_recovery").select("epoch,envelope").maybeSingle();
  if (error) {
    if (/does not exist|schema cache|PGRST20[25]/i.test(error.message)) return null;
    throw error;
  }
  if (!data) return null;
  return safeInvoke<LibraryStatus>("vault_library_accept_recovery", { envelope: data.envelope, recoveryKey });
}

export async function fetchLibraryState(client: SupabaseClient): Promise<LibraryState | null> {
  const { data, error } = await client.from("qv_library_state").select("revision,object_id,epoch,updated_by_device,updated_at").maybeSingle();
  if (error) throw error;
  return (data as LibraryState | null) ?? null;
}

export function isRevisionConflict(error: unknown): boolean {
  return errorText(error).includes("QV_REVISION_CONFLICT");
}
