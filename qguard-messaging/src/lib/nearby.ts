/**
 * Nearby delivery (roadmap 9.1; Android, Google Play services Nearby
 * Connections — commands/nearby.rs, NearbyRelay.kt). Rows received from a phone
 * in range are sealed envelope rows like any from the relay, and go through
 * the same screening and decryption; nothing here trusts the radio link.
 */
import { safeInvoke } from "@/lib/tauri";

export interface NearbyStatus {
  supported: boolean;
  available: boolean;
  permissionsGranted: boolean;
  running: boolean;
  peers: number;
}

export const NEARBY_ROWS_EVENT = "qguard:nearby-rows";

const UNSUPPORTED: NearbyStatus = { supported: false, available: false, permissionsGranted: false, running: false, peers: 0 };

export function nearbyStatus(): Promise<NearbyStatus> {
  return safeInvoke<NearbyStatus>("nearby_status", undefined, UNSUPPORTED);
}

/** Rows a nearby phone handed over that are sealed to THIS device. */
export function rowsForDevice(rows: Array<Record<string, unknown>>, deviceId: string | null): Array<Record<string, unknown>> {
  if (!deviceId) return [];
  return rows.filter((row) => row && typeof row === "object" && String(row.recipient_device_id ?? "") === deviceId);
}

/** Merge rows by envelope id; relay copies win over nearby ones. */
export function mergeRowsById<T extends { id: string }>(primary: T[], extra: T[]): T[] {
  const seen = new Set(primary.map((row) => row.id));
  return [...primary, ...extra.filter((row) => !seen.has(row.id))];
}
