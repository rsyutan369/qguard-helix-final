import type { DashboardData, TrustedDevice } from "@/lib/types";
import type { ReactorRing } from "@/components/mobile/HelixReactor";
import { ONE_TIME_PREKEY_TARGET } from "@/lib/security-score";

/**
 * One layer of the cryptographic stack, in the order it is exercised when a
 * message is sent: identity is proven, a hybrid handshake derives a session,
 * the session ratchets forward, and the runtime that holds the keys is itself
 * hardened.
 *
 * The ordering is real, which is why the UI is allowed to number these — it is
 * a pipeline, not a decorative list.
 */
export interface CryptoLayer {
  id: string;
  /** 1-based position in the pipeline. */
  ordinal: number;
  label: string;
  /** Plain-language answer to "what does this layer do for me?" */
  caption: string;
  /** Measured readiness, 0..1. Drives both the gauge arc and the row readout. */
  value: number;
  /** Human readout of the measurement behind `value`. */
  detail: string;
  tone: ReactorRing["tone"];
}

function toneFor(value: number): ReactorRing["tone"] {
  if (value >= 0.999) return "ok";
  if (value >= 0.8) return "info";
  if (value >= 0.5) return "warn";
  return "alert";
}

function ratio(part: number, whole: number): number {
  if (whole <= 0) return 0;
  return Math.max(0, Math.min(1, part / whole));
}

function isActive(device: TrustedDevice): boolean {
  return device.trust_state !== "Revoked";
}

/** A device whose identity is provable with BOTH classical and PQC signatures. */
function hasDualSignedIdentity(device: TrustedDevice): boolean {
  return Boolean(
    device.identity_signature
    && device.x25519_identity_public.length > 0
    && device.mlkem_identity_public.length > 0
    && device.ed25519_identity_public.length > 0
    && device.mldsa_identity_public.length > 0,
  );
}

/** A device that can complete a hybrid X25519 + ML-KEM handshake right now. */
function hasHybridHandshakeMaterial(device: TrustedDevice): boolean {
  const prekey = device.signed_prekey;
  return Boolean(
    prekey
    && prekey.x25519_public.length > 0
    && prekey.mlkem_public.length > 0,
  );
}

/**
 * Derives the four measured layers of the crypto stack from the dashboard
 * snapshot. Single source of truth: the reactor gauge and the pipeline list are
 * both rendered from this one result, so an arc can never disagree with the row
 * printed beside it.
 *
 * Every value is a measurement of material actually present in the account —
 * nothing here is a fixed or assumed reading.
 */
export function buildCryptoStack(data: DashboardData): CryptoLayer[] {
  const myId = data.profile?.id;
  const activeDevices = data.devices.filter((device) => device.user_id === myId && isActive(device));
  const deviceCount = activeDevices.length;

  const identityReady = activeDevices.filter(hasDualSignedIdentity).length;
  const handshakeReady = activeDevices.filter(hasHybridHandshakeMaterial).length;

  const oneTimePool = data.keyInventory.available_one_time_prekeys;
  const sessionValue = ratio(oneTimePool, ONE_TIME_PREKEY_TARGET);

  const checks = data.hardening.checks;
  const runtimeActive = checks.filter((check) => check.status === "active").length;
  const runtimeValue = ratio(runtimeActive, checks.length);

  const identityValue = ratio(identityReady, deviceCount);
  const handshakeValue = ratio(handshakeReady, deviceCount);

  return [
    {
      id: "identity",
      ordinal: 1,
      label: "Identity",
      caption: "Proves this device is really yours",
      value: identityValue,
      detail: deviceCount === 0
        ? "No device registered"
        : `${identityReady}/${deviceCount} dual-signed`,
      tone: deviceCount === 0 ? "alert" : toneFor(identityValue),
    },
    {
      id: "handshake",
      ordinal: 2,
      label: "Handshake",
      caption: "Agrees a key a quantum computer cannot recover",
      value: handshakeValue,
      detail: deviceCount === 0
        ? "No device registered"
        : `${handshakeReady}/${deviceCount} hybrid-ready`,
      tone: deviceCount === 0 ? "alert" : toneFor(handshakeValue),
    },
    {
      id: "session",
      ordinal: 3,
      label: "Session",
      caption: "Keeps past messages unreadable if a key leaks",
      value: sessionValue,
      detail: `${oneTimePool}/${ONE_TIME_PREKEY_TARGET} one-time keys`,
      tone: toneFor(sessionValue),
    },
    {
      id: "runtime",
      ordinal: 4,
      label: "Runtime",
      caption: "Protects the keys while the app is running",
      value: runtimeValue,
      detail: checks.length === 0
        ? "Not measured"
        : `${runtimeActive}/${checks.length} checks active`,
      // An unmeasured runtime is reported as unmeasured, never as a failure.
      tone: checks.length === 0 ? "mute" : toneFor(runtimeValue),
    },
  ];
}

/** Maps the measured stack onto the reactor's concentric arcs. */
export function toReactorRings(layers: CryptoLayer[]): ReactorRing[] {
  return layers.map((layer) => ({
    id: layer.id,
    label: layer.label,
    value: layer.value,
    tone: layer.tone,
  }));
}

/**
 * Verdict caption for the score. Deliberately plain: the number is the
 * headline, this line says what to do about it.
 */
export function scoreVerdict(score: number): { label: string; tone: ReactorRing["tone"] } {
  if (score >= 100) return { label: "Fully protected", tone: "ok" };
  if (score >= 90) return { label: "Protected", tone: "ok" };
  if (score >= 70) return { label: "Review warnings", tone: "warn" };
  return { label: "Action needed", tone: "alert" };
}
