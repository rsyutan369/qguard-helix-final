import type { CallPeerIdentityPayload } from "@/lib/call-targets";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

/**
 * Device pins, as seen from the UI.
 *
 * The relay is the device directory, and a row it invents is as self-consistent
 * as a real one. The Rust core therefore keeps its own record of which devices
 * belong to whom (`src-tauri/src/device_pins.rs`): devices present the first
 * time a person is seen are recorded; a device that appears later is NEW until
 * the user approves it here; a device id that comes back with different keys is
 * never accepted.
 *
 * The core is what enforces this — it refuses to seal to an unaccepted device
 * and will not report its messages as verified. This module only asks the core
 * for its verdicts, so the UI can keep such devices out of delivery BEFORE the
 * core has to refuse them, and can show the user what needs their decision.
 */

export type DevicePinStanding =
  /** Recorded on this device with these identity keys. */
  | "pinned"
  /** Appeared after this person's devices were first recorded; not approved. */
  | "new"
  /** Same device id, different identity keys than recorded. Never accepted. */
  | "key_changed"
  /** The row's own signature does not verify. Not a device at all. */
  | "invalid_identity"
  /** This device's record could not be opened, so nothing can be said. */
  | "unknown";

/** Mirror of `commands::devices::DevicePinVerdict`. */
export interface DevicePinVerdict {
  userId: string;
  deviceId: string;
  standing: DevicePinStanding;
  /** Computed by the core from the device's keys, never taken from the row. */
  fingerprint: string;
  pinnedAt: string | null;
  source: "first_use" | "approved" | "this_device" | null;
}

/** Mirror of `commands::devices::DevicePinAssessment`. */
export interface DevicePinAssessment {
  available: boolean;
  verdicts: DevicePinVerdict[];
}

export type DevicePinIndex = Map<string, DevicePinVerdict>;

/** The device fields a pin is made from. Structural, so this stays testable. */
export interface PinnableDevice {
  device_id: string;
  user_id: string;
  trust_state?: string;
  x25519_identity_public: number[];
  mlkem_identity_public: number[];
  ed25519_identity_public: number[];
  mldsa_identity_public: number[];
  identity_signature?: { ed25519: number[]; ml_dsa_65: number[] } | null;
}

/**
 * The core's argument for one device, or null for a row that carries no
 * identity to judge (no keys, no signature) or that is already revoked. Such a
 * row is not deliverable anyway and must not become part of anyone's first-use
 * record.
 */
export function pinCandidate(device: PinnableDevice): CallPeerIdentityPayload | null {
  if (!device.device_id || !device.user_id || device.trust_state === "Revoked") return null;
  const signature = device.identity_signature;
  if (!signature?.ed25519?.length || !signature.ml_dsa_65?.length) return null;
  if (
    !device.x25519_identity_public.length
    || !device.mlkem_identity_public.length
    || !device.ed25519_identity_public.length
    || !device.mldsa_identity_public.length
  ) {
    return null;
  }
  return {
    user_id: device.user_id,
    device_id: device.device_id,
    x25519_identity_public: device.x25519_identity_public,
    mlkem_identity_public: device.mlkem_identity_public,
    ed25519_identity_public: device.ed25519_identity_public,
    mldsa_identity_public: device.mldsa_identity_public,
    identity_signature: { ed25519: signature.ed25519, ml_dsa_65: signature.ml_dsa_65 },
  };
}

function candidates(devices: PinnableDevice[]): CallPeerIdentityPayload[] {
  const seen = new Set<string>();
  const list: CallPeerIdentityPayload[] = [];
  for (const device of devices) {
    const candidate = pinCandidate(device);
    if (!candidate) continue;
    // One row per (person, device id, keys). A second row with the same id and
    // DIFFERENT keys is kept on purpose: the core reports it as a key change.
    const key = `${candidate.user_id}:${candidate.device_id}:${foldBytes(candidate)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    list.push(candidate);
  }
  return list;
}

/**
 * Ask the core how these devices stand. Pass every device listed for the
 * people concerned: someone seen for the first time has their whole list
 * recorded as first use, so a partial list would make the rest look new later.
 *
 * Returns null outside the app shell or when the core did not answer — in
 * which case nothing is known, and the core's own refusal remains the gate.
 */
export async function assessDevicePins(devices: PinnableDevice[]): Promise<DevicePinAssessment | null> {
  if (!isTauriRuntime()) return null;
  const list = candidates(devices);
  if (list.length === 0) return { available: true, verdicts: [] };
  try {
    return await safeInvoke<DevicePinAssessment>("devices_assess_pins", { devices: list });
  } catch {
    return null;
  }
}

/** Record the user's approval of the NEW devices among `devices`. */
export async function approveDevicePins(devices: PinnableDevice[]): Promise<DevicePinAssessment> {
  return safeInvoke<DevicePinAssessment>("devices_approve_pins", { devices: candidates(devices) });
}

function foldBytes(candidate: CallPeerIdentityPayload): number {
  // A cheap change detector, NOT a security check: it only decides whether the
  // core needs to be asked again. The core compares SHA3-256 digests.
  let fold = 0x811c9dc5;
  for (const list of [
    candidate.ed25519_identity_public,
    candidate.mldsa_identity_public,
    candidate.x25519_identity_public,
    candidate.mlkem_identity_public,
  ]) {
    for (let index = 0; index < list.length; index += 1) {
      fold ^= list[index] & 0xff;
      fold = Math.imul(fold, 0x01000193) >>> 0;
    }
    fold = Math.imul(fold ^ list.length, 0x01000193) >>> 0;
  }
  return fold;
}

/**
 * A string that changes whenever the set of judgeable devices, or any of their
 * identity keys, changes — so a component can re-ask the core exactly when
 * there is something new to judge, and not on every unrelated refresh.
 */
export function devicePinInputKey(devices: PinnableDevice[]): string {
  return candidates(devices)
    .map((candidate) => `${candidate.user_id}:${candidate.device_id}:${foldBytes(candidate).toString(36)}`)
    .sort()
    .join("|");
}

/** Fold an assessment into an index keyed by device id. */
export function mergeVerdicts(index: DevicePinIndex, assessment: DevicePinAssessment): DevicePinIndex {
  const next = new Map(index);
  // Worst verdict wins when one device id was judged more than once (two rows
  // sharing an id): a pinned row must not hide a key change beside it.
  const severity: Record<DevicePinStanding, number> = {
    pinned: 0,
    unknown: 1,
    new: 2,
    invalid_identity: 3,
    key_changed: 4,
  };
  const fromThisAssessment = new Set<string>();
  for (const verdict of assessment.verdicts) {
    const existing = fromThisAssessment.has(verdict.deviceId) ? next.get(verdict.deviceId) : undefined;
    if (!existing || severity[verdict.standing] > severity[existing.standing]) {
      next.set(verdict.deviceId, verdict);
    }
    fromThisAssessment.add(verdict.deviceId);
  }
  return next;
}

/**
 * Whether a device may be delivered to, as far as the UI knows.
 *
 *   - no verdict at all (not judged yet, or outside the app): allowed here —
 *     the core judges it again when asked to seal, and refuses if it must;
 *   - `unknown` (the record could not be opened): allowed, and the UI says
 *     that device changes cannot be checked right now;
 *   - `new`, `key_changed`, `invalid_identity`: never.
 */
export function isDeliverableStanding(standing: DevicePinStanding | undefined): boolean {
  return standing === undefined || standing === "pinned" || standing === "unknown";
}

export interface DeviceReview<Device extends PinnableDevice> {
  device: Device;
  verdict: DevicePinVerdict;
  /** Whose device it is: this account's own, or a contact's. */
  owner: "self" | "contact";
  /** Only a NEW device can be approved. */
  approvable: boolean;
}

/**
 * The devices that need the user's attention among `devices`, limited to the
 * people in `userIds`: new ones first (they can be acted on), then the ones
 * that are refused outright.
 */
export function pendingDeviceReviews<Device extends PinnableDevice>(
  devices: Device[],
  index: DevicePinIndex,
  userIds: string[],
  localUserId: string,
): DeviceReview<Device>[] {
  const wanted = new Set(userIds);
  const seen = new Set<string>();
  const reviews: DeviceReview<Device>[] = [];
  for (const device of devices) {
    if (!wanted.has(device.user_id) || device.trust_state === "Revoked" || seen.has(device.device_id)) continue;
    const verdict = index.get(device.device_id);
    if (!verdict || isDeliverableStanding(verdict.standing)) continue;
    seen.add(device.device_id);
    reviews.push({
      device,
      verdict,
      owner: device.user_id === localUserId ? "self" : "contact",
      approvable: verdict.standing === "new",
    });
  }
  return reviews.sort((left, right) => Number(right.approvable) - Number(left.approvable));
}

/** True when the core could not open its record for any judged device. */
export function pinsUnavailable(index: DevicePinIndex): boolean {
  for (const verdict of index.values()) {
    if (verdict.standing === "unknown") return true;
  }
  return false;
}
