import type { DashboardData, TrustedDevice } from "@/lib/types";
import type { ReactorRing } from "@/components/mobile/HelixReactor";
import { liveHardeningChecks } from "@/lib/security-score";

/**
 * One layer of the cryptographic stack, in the order it is exercised when a
 * message is sent: identity is proven, a hybrid handshake derives the message
 * key, the prekey behind that handshake is rotated and retired so old traffic
 * stops being decryptable, and the runtime that holds the keys is itself
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

/**
 * The measured stack plus the device population it was measured over.
 *
 * The device split is part of the result rather than an internal detail,
 * because the UI has to be able to SAY which devices were measured. Reporting a
 * ratio without saying what the denominator was is how this readout went wrong
 * in the first place.
 */
export interface CryptoPosture {
  layers: CryptoLayer[];
  /** Devices carrying current key material — the population the layers measure. */
  enrolledDevices: number;
  /**
   * Non-revoked device rows with no current handshake material: identities
   * stranded by a reinstall, which can never take part again. Surfaced so the
   * user can retire them, NOT folded into the layer measurements.
   */
  dormantIdentities: number;
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
 * snapshot. Single source of truth for the phone home screen: the reactor gauge
 * and the pipeline list are both rendered from this one result, so an arc can
 * never disagree with the row printed beside it.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE LAYERS ARE MEASURED OVER, AND WHY IT IS NOT "EVERY DEVICE ROW"
 * ---------------------------------------------------------------------------
 * This used to divide by every non-revoked device row on the account, and it
 * made a perfectly healthy account report a failing stack. Reinstalling the app
 * mints a brand-new device identity (the old keyring is gone), so the previous
 * row survives forever with no signed prekey and no way to ever publish one.
 * A real account with two live devices and three stranded rows read
 * "2 of 4 cryptographic layers fully active" while the headline — computed by
 * `buildSecurityPosture`, which does NOT make this mistake — correctly said
 * 100%. Two rival models on one screen, and the pessimistic one was wrong.
 *
 * `security-score.ts` documents the same trap in its own prekey handling
 * ("stale device identities left behind by reinstalls ... make a perfectly
 * healthy device read as awaiting prekey material forever"). This module now
 * follows the same rule and shares that module's hardening filter, so the gauge
 * and the headline are two views of ONE measurement.
 *
 * Nothing is swept under the rug: a stranded identity is not silently dropped,
 * it is counted in `dormantIdentities` and surfaced to the user as its own item
 * with its own action (retire it in Device Trust). It belongs there — a device
 * row that holds no handshake material cannot receive a sealed message and is
 * an inventory-hygiene task, not a weakness in the handshake layer.
 *
 * Every value is a measurement of material actually present in the account —
 * nothing here is a fixed or assumed reading.
 */
export function buildCryptoPosture(data: DashboardData): CryptoPosture {
  const myId = data.profile?.id;
  const activeDevices = data.devices.filter((device) => device.user_id === myId && isActive(device));

  // Enrolled = carries current handshake material, i.e. can actually take part
  // in the protocol today. Everything else on the account is a stranded row.
  const enrolled = activeDevices.filter(hasHybridHandshakeMaterial);
  const dormantIdentities = activeDevices.length - enrolled.length;
  const enrolledCount = enrolled.length;

  const identityReady = enrolled.filter(hasDualSignedIdentity).length;
  // Enrolment is defined BY handshake material, so every enrolled device is
  // hybrid-ready by construction. The layer is still measured rather than
  // hardcoded to 1: if the definition of enrolment ever widens, this keeps
  // reporting the truth instead of a stale assumption.
  const handshakeReady = enrolled.filter(hasHybridHandshakeMaterial).length;

  // The Session layer answers "do past messages stay unreadable if a key
  // leaks?", i.e. forward secrecy. It used to be measured by the size of the
  // one-time prekey pool, which the send path does not use — a full pool said
  // nothing about the claim printed beside it. It is now two real things: a
  // signed prekey is published (messages can be sealed to this device at all),
  // and that prekey is actually being rotated and retired on schedule, as the
  // core reports it. A report that could not measure rotation earns only the
  // first half.
  const signedPrekeyPublished = data.keyInventory.active_signed_prekeys > 0;
  const rotationHealthy = signedPrekeyPublished && data.report?.forward_secrecy_healthy === true;
  const sessionValue = (signedPrekeyPublished ? 0.5 : 0) + (rotationHealthy ? 0.5 : 0);

  // Build-provenance gates (binary pinning, code signing, obfuscation,
  // control-flow flattening, string encryption) are evidence about how the
  // BINARY was produced, not about whether the running cryptography works, and
  // `security-score.ts` already excludes them from live posture for exactly
  // that reason. Counting them here made unmeasurable release metadata read as
  // a cryptographic failure. They remain visible in full on the Quantum
  // Security page, which is where build provenance belongs.
  const checks = liveHardeningChecks(data.hardening);
  const runtimeActive = checks.filter((check) => check.status === "active").length;
  const runtimeValue = ratio(runtimeActive, checks.length);

  const identityValue = ratio(identityReady, enrolledCount);
  const handshakeValue = ratio(handshakeReady, enrolledCount);

  const layers: CryptoLayer[] = [
    {
      id: "identity",
      ordinal: 1,
      label: "Identity",
      caption: "Proves this device is really yours",
      value: identityValue,
      detail: enrolledCount === 0
        ? "No device enrolled"
        : `${identityReady}/${enrolledCount} dual-signed`,
      tone: enrolledCount === 0 ? "alert" : toneFor(identityValue),
    },
    {
      id: "handshake",
      ordinal: 2,
      label: "Handshake",
      caption: "Agrees a key a quantum computer cannot recover",
      value: handshakeValue,
      detail: enrolledCount === 0
        ? "No device enrolled"
        : `${handshakeReady}/${enrolledCount} hybrid-ready`,
      tone: enrolledCount === 0 ? "alert" : toneFor(handshakeValue),
    },
    {
      id: "session",
      ordinal: 3,
      label: "Session",
      caption: "Keeps past messages unreadable if a key leaks",
      value: sessionValue,
      detail: !signedPrekeyPublished
        ? "No signed prekey published"
        : rotationHealthy ? "Prekey rotating daily" : "Prekey rotation not confirmed",
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

  return { layers, enrolledDevices: enrolledCount, dormantIdentities };
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

/** How many of the measured layers are completely ready. */
export function completeLayerCount(layers: CryptoLayer[]): number {
  return layers.filter((layer) => layer.value >= 0.999).length;
}

/**
 * Verdict caption for the score. Deliberately plain: the number is the
 * headline, this line says what to do about it.
 *
 * `layers` is not decoration. The score and the layer measurement are computed
 * from different evidence (the score is weighted and carries event penalties;
 * the layers are stack coverage), so on their own they can print a flat
 * contradiction — which is exactly what shipped: "100% · Fully protected"
 * sitting directly above "2 of 4 cryptographic layers fully active". Passing
 * the layers in makes the strongest claim conditional on the layers actually
 * supporting it, so that contradiction cannot be written again even if some
 * future input drives the two models apart.
 */
export function scoreVerdict(
  score: number,
  layers: CryptoLayer[] = [],
): { label: string; tone: ReactorRing["tone"] } {
  const measured = layers.length;
  const complete = completeLayerCount(layers);
  const everyLayerReady = measured === 0 || complete === measured;
  if (score >= 100 && everyLayerReady) return { label: "Fully protected", tone: "ok" };
  if (score >= 90 && everyLayerReady) return { label: "Protected", tone: "ok" };
  // The score is high but a layer is measurably incomplete: say so rather than
  // rounding the language up to match the number.
  if (score >= 90) return { label: "Review coverage", tone: "warn" };
  if (score >= 70) return { label: "Review warnings", tone: "warn" };
  return { label: "Action needed", tone: "alert" };
}
