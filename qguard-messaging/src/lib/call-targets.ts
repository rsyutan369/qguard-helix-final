/**
 * Call target construction.
 *
 * A peer is a PERSON, not a device. Their account can have several registered
 * devices (desktop + phone + tablet), and which one they are actually sitting
 * in front of is unknowable to the caller.
 *
 * Message delivery already fans out to every sendable device. Calls used to
 * pick `sendableRecipientDevices[0]` — the device with the most recent
 * `last_seen_at` — and address the ring to that one device only. Call signals
 * are device-addressed (`call-signaling.ts` drops any row whose `to_device_id`
 * is not this device), so if the peer was using any OTHER device it never rang:
 * the caller sat on "Calling…" until the 45s give-up, media never established,
 * and because the safety number is only derived once media connects, the
 * security code never appeared either.
 *
 * So this module hands the call engine EVERY sendable device and lets the
 * engine ring them all, exactly as a phone system forks a call to every
 * registered endpoint.
 */

/**
 * What a `reject` / `busy` / `hangup` from one peer device means for a forked
 * outgoing ring.
 *
 * Once a device has answered, only that device can end the call. Before anyone
 * answers, a decline removes just that device — ending the whole call on the
 * first one is a real failure mode, because `busy` is sent AUTOMATICALLY by any
 * of the peer's devices that happens to be on another call. A peer whose
 * desktop was mid-call could otherwise never be reached on their phone: the
 * desktop's automatic busy would cancel the ring everywhere.
 */
export function applyDecline(
  ringTargetDeviceIds: string[],
  fromDeviceId: string,
  answeredDeviceId: string | null,
): { remaining: string[]; endCall: boolean } {
  if (answeredDeviceId) {
    // Bound call: only the device we are actually talking to can end it.
    return { remaining: ringTargetDeviceIds, endCall: fromDeviceId === answeredDeviceId };
  }
  const remaining = ringTargetDeviceIds.filter((id) => id !== fromDeviceId);
  return { remaining, endCall: remaining.length === 0 };
}

/** The identity material needed to encapsulate a call media key to one device. */
export interface CallPeerDevice {
  deviceId: string;
  x25519: number[];
  mlkem: number[];
  ed25519: number[];
  mldsa: number[];
  identitySignature: { ed25519: number[]; ml_dsa_65: number[] };
}

/** An outgoing-call target: one person, every device they can be reached on. */
export interface CallPeer {
  userId: string;
  displayName: string;
  devices: CallPeerDevice[];
}

/**
 * The device fields this builder needs. Declared structurally rather than
 * importing `TrustedDevice` so the pure logic stays testable without the whole
 * dashboard data model.
 */
export interface CallCandidateDevice {
  user_id: string;
  device_id: string;
  x25519_identity_public: Uint8Array | number[];
  mlkem_identity_public: Uint8Array | number[];
  ed25519_identity_public: Uint8Array | number[];
  mldsa_identity_public: Uint8Array | number[];
  identity_signature?: { ed25519: Uint8Array | number[]; ml_dsa_65: Uint8Array | number[] } | null;
}

function bytes(value: Uint8Array | number[]): number[] {
  return Array.from(value);
}

/**
 * True when this device published everything needed to verify its identity and
 * encapsulate a media key to it. The Rust side refuses to encapsulate without a
 * valid dual signature, so a device missing any of this could never complete a
 * call and must not be rung.
 */
export function isCallableDevice(device: CallCandidateDevice): boolean {
  return Boolean(
    device.device_id
    && device.identity_signature
    && device.identity_signature.ed25519?.length
    && device.identity_signature.ml_dsa_65?.length
    && device.x25519_identity_public.length
    && device.mlkem_identity_public.length
    && device.ed25519_identity_public.length
    && device.mldsa_identity_public.length,
  );
}

/**
 * Build the outgoing-call target from the peer's sendable devices.
 *
 * `candidates` is the SAME list message delivery fans out to, so a device that
 * can receive an encrypted message can also be rung. Order is preserved: the
 * caller's ordering already puts the most-recently-seen device first, which is
 * the best guess at where the peer is — it is just no longer the ONLY device
 * that gets a ring.
 *
 * Returns null when no device can be called, so the UI can keep the call button
 * disabled rather than starting a call that can never connect.
 */
export function buildCallPeer(
  candidates: CallCandidateDevice[],
  displayName: string,
): CallPeer | null {
  const callable = candidates.filter(isCallableDevice);
  if (callable.length === 0) return null;
  const userId = callable[0].user_id;
  // A direct conversation has exactly one other participant; guard anyway so a
  // group/misconfigured list can never ring a third party's devices.
  const devices = callable
    .filter((device) => device.user_id === userId)
    .map<CallPeerDevice>((device) => ({
      deviceId: device.device_id,
      x25519: bytes(device.x25519_identity_public),
      mlkem: bytes(device.mlkem_identity_public),
      ed25519: bytes(device.ed25519_identity_public),
      mldsa: bytes(device.mldsa_identity_public),
      identitySignature: {
        ed25519: bytes(device.identity_signature!.ed25519),
        ml_dsa_65: bytes(device.identity_signature!.ml_dsa_65),
      },
    }));
  return { userId, displayName, devices };
}

/** The `CallPeerIdentity` argument of the Rust call commands. */
export interface CallPeerIdentityPayload {
  user_id: string;
  device_id: string;
  x25519_identity_public: number[];
  mlkem_identity_public: number[];
  ed25519_identity_public: number[];
  mldsa_identity_public: number[];
  identity_signature: { ed25519: number[]; ml_dsa_65: number[] };
}

export function callPeerIdentityPayload(userId: string, device: CallPeerDevice): CallPeerIdentityPayload {
  return {
    user_id: userId,
    device_id: device.deviceId,
    x25519_identity_public: device.x25519,
    mlkem_identity_public: device.mlkem,
    ed25519_identity_public: device.ed25519,
    mldsa_identity_public: device.mldsa,
    identity_signature: device.identitySignature,
  };
}

/**
 * A callee's per-call public key, signed by its device identity (mirror of
 * `commands::calls::CallEphemeralKey`). It rides in the `accept` signal and is
 * what gives the call forward secrecy.
 */
export interface CallEphemeralKey {
  x25519Public: number[];
  mlkemPublic: number[];
  signature: { ed25519: number[]; ml_dsa_65: number[] };
}

function byteList(value: unknown): number[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  const bytes: number[] = [];
  for (const item of value) {
    if (typeof item !== "number" || !Number.isInteger(item) || item < 0 || item > 255) return null;
    bytes.push(item);
  }
  return bytes;
}

/**
 * Read a per-call key out of an `accept` payload.
 *
 * The payload comes from the relay, so this only decides whether it has the
 * SHAPE of a key: whether it is genuine is decided by the Rust core, which
 * checks its signature against the callee's registered identity before
 * anything is encapsulated to it. Returns null when there is no usable key —
 * an `accept` from a build that predates per-call keys has none.
 */
export function parseCallEphemeralKey(value: unknown): CallEphemeralKey | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const signature = record.signature;
  if (!signature || typeof signature !== "object" || Array.isArray(signature)) return null;
  const signatureRecord = signature as Record<string, unknown>;
  const x25519Public = byteList(record.x25519Public);
  const mlkemPublic = byteList(record.mlkemPublic);
  const ed25519 = byteList(signatureRecord.ed25519);
  const mlDsa65 = byteList(signatureRecord.ml_dsa_65);
  if (!x25519Public || !mlkemPublic || !ed25519 || !mlDsa65) return null;
  // X25519 public keys are 32 bytes and ML-KEM-1024 encapsulation keys 1568;
  // anything else is not a key this build would use.
  if (x25519Public.length !== 32 || mlkemPublic.length !== 1568) return null;
  return { x25519Public, mlkemPublic, signature: { ed25519, ml_dsa_65: mlDsa65 } };
}
