/**
 * Which of a peer's devices a message is sealed to, and which ones a call rings.
 *
 * A peer is a PERSON. Their account can hold several registered devices, and
 * the sender cannot know which one they are sitting in front of, so delivery
 * has to fan out.
 *
 * The previous selector bucketed candidates by `${user_id}:${device_label}` and
 * kept only the newest device per bucket. That was meant to collapse repeat
 * registrations of the SAME physical machine (a reinstall wipes the keyring and
 * mints a brand-new identity, stranding the old row forever). It did not work,
 * because every platform registered the identical hardcoded label
 * "Windows Desktop" -- Android included. So an entire account collapsed into a
 * single bucket and only the most-recently-seen device was ever addressed:
 *
 *   - a message never reached the peer's other device;
 *   - a call rang the wrong device, so the phone stayed silent while the caller
 *     sat on "Calling..." until the give-up (and, because the safety number is
 *     only derived once media connects, no security code ever appeared).
 *
 * The label was never a sound discriminator. The signal that actually separates
 * a live endpoint from a stranded reinstall is RECENCY: a dead identity stops
 * updating `last_seen_at` the moment it is replaced. So selection is now
 * liveness-based and label-independent -- every device seen inside the policy
 * window is addressed, bounded by a fan-out cap.
 */

/** The device fields selection needs. Declared structurally so this stays pure. */
export interface DeliveryCandidateDevice {
  device_id: string;
  user_id: string;
  last_seen_at: string;
  created_at: string;
  trust_state: string;
}

export interface DeliverySelectionPolicy {
  /** A device not seen within this window is treated as a stranded identity. */
  activeWindowMs: number;
  /** Hard ceiling on fan-out per user, so a churned account cannot blow up a send. */
  maxPerUser: number;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Message delivery. Generous: an envelope sits in the table until the device
 * fetches it, so sealing to a device that has been away for a few weeks is
 * cheap and means the message is waiting when it comes back.
 */
export const MESSAGE_DELIVERY_POLICY: DeliverySelectionPolicy = {
  activeWindowMs: 30 * DAY_MS,
  maxPerUser: 8,
};

/**
 * Call ringing. Tighter: a call is real time, so a device that has not been
 * seen in a week will not answer. Every extra target also costs one hybrid-KEM
 * encapsulation and one signal row on the critical path of a ring, so the cap
 * is lower than for messages.
 */
export const CALL_RING_POLICY: DeliverySelectionPolicy = {
  activeWindowMs: 7 * DAY_MS,
  maxPerUser: 4,
};

export function deviceTime(value: string | null | undefined): number {
  const parsed = new Date(value ?? "").getTime();
  return Number.isFinite(parsed) ? parsed : 0;
}

/**
 * Best-guess ordering: this device first, then the current device, then most
 * recently seen. The head of the list is the peer's most likely endpoint, which
 * still matters (it is the provisional route before anyone answers) -- it is
 * just no longer the ONLY endpoint.
 */
export function compareDeliveryDevices<T extends DeliveryCandidateDevice>(
  a: T,
  b: T,
  localDeviceId: string | null = null,
): number {
  const aLocal = localDeviceId && a.device_id === localDeviceId ? 1 : 0;
  const bLocal = localDeviceId && b.device_id === localDeviceId ? 1 : 0;
  if (aLocal !== bLocal) return bLocal - aLocal;
  const aCurrent = a.trust_state === "ThisDevice" ? 1 : 0;
  const bCurrent = b.trust_state === "ThisDevice" ? 1 : 0;
  if (aCurrent !== bCurrent) return bCurrent - aCurrent;
  const lastSeenDelta = deviceTime(b.last_seen_at) - deviceTime(a.last_seen_at);
  if (lastSeenDelta !== 0) return lastSeenDelta;
  return deviceTime(b.created_at) - deviceTime(a.created_at);
}

/**
 * Pick the devices to address for `userIds`, newest-active first.
 *
 * `devices` must already be filtered to those that CAN be addressed (trusted +
 * publishing a usable key bundle); this function only decides which of the
 * addressable ones are worth addressing.
 *
 * A user whose devices have ALL gone quiet still yields their single freshest
 * device rather than nothing at all -- dropping to zero targets would render a
 * dormant contact permanently unreachable, which is worse than one envelope
 * nobody picks up.
 */
export function selectDeliveryDevices<T extends DeliveryCandidateDevice>(
  devices: T[],
  userIds: string[],
  localDeviceId: string | null = null,
  policy: DeliverySelectionPolicy = MESSAGE_DELIVERY_POLICY,
  now: number = Date.now(),
): T[] {
  const targetUserIds = new Set(userIds.filter(Boolean));
  if (targetUserIds.size === 0) return [];

  const byUser = new Map<string, T[]>();
  const seenDeviceIds = new Set<string>();
  for (const device of devices) {
    if (!device.device_id || !targetUserIds.has(device.user_id)) continue;
    // The same row can arrive twice (a cached list merged with a fresh fetch);
    // addressing it twice would seal a duplicate envelope / ring twice.
    if (seenDeviceIds.has(device.device_id)) continue;
    seenDeviceIds.add(device.device_id);
    const bucket = byUser.get(device.user_id);
    if (bucket) bucket.push(device);
    else byUser.set(device.user_id, [device]);
  }

  const selected: T[] = [];
  for (const userDevices of byUser.values()) {
    const ordered = [...userDevices].sort((a, b) => compareDeliveryDevices(a, b, localDeviceId));
    const active = ordered.filter((device) => now - deviceTime(device.last_seen_at) <= policy.activeWindowMs);
    const chosen = active.length > 0 ? active : ordered.slice(0, 1);
    selected.push(...chosen.slice(0, policy.maxPerUser));
  }

  return selected.sort((a, b) => compareDeliveryDevices(a, b, localDeviceId));
}
