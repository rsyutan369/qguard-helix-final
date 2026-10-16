import type { PrekeyStatus } from "@/lib/prekey-hygiene";
import type {
  DashboardSnapshot,
  KeyInventory,
  Profile,
  QuantumSecurityReport,
  SecurityEvent,
  SecurityHardeningCheck,
  SecurityHardeningStatus,
  TelemetryEvent,
  TrustedDevice,
  VaultFileSummary,
} from "@/lib/types";

interface SecurityPostureInput {
  profile: Profile;
  devices: TrustedDevice[];
  vaultFiles: VaultFileSummary[];
  keyInventory: KeyInventory;
  telemetry: TelemetryEvent[];
  securityEvents: SecurityEvent[];
  hardening: SecurityHardeningStatus;
  vaultStorageLabel: string;
  /**
   * Rotation state of this device's prekeys, as read from the Rust core. Null
   * (or absent) when it could not be read — outside the app shell, or the core
   * did not answer. Forward secrecy is then reported as not measured; it is
   * never assumed.
   */
  prekeyStatus?: PrekeyStatus | null;
}

interface SecurityPostureResult {
  snapshot: DashboardSnapshot;
  report: QuantumSecurityReport;
}

// Per-device prekey readiness floors (see buildSecurityPosture). A device can
// receive messages with one active signed prekey and a healthy one-time prekey
// pool; these are NOT multiplied by the number of registered devices.
// (Whether it has FORWARD SECRECY is a different question, answered by
// describeForwardSecrecy from how its prekeys are actually rotating.)
// Exported so every prekey readout uses the same thresholds.
export const SIGNED_PREKEY_MIN = 1;
export const ONE_TIME_PREKEY_MIN = 16;
// Publish target: when the available pool drops below the floor, the device
// replenishes with fresh keys back up to this count.
export const ONE_TIME_PREKEY_TARGET = 24;

const requiredSuite = {
  classicalKex: "X25519",
  pqKem: "ML-KEM-1024",
  kdf: "HKDF-SHA3-256",
  symmetric: "AES-256-GCM",
  classicalSignature: "Ed25519",
  pqSignature: "ML-DSA-65",
};

function normalize(value: unknown): string {
  return String(value ?? "").toUpperCase().replace(/[_\s]+/g, "-");
}

function hasTerm(value: unknown, term: string): boolean {
  return normalize(value).includes(normalize(term));
}

function deviceHasHybridKex(device: TrustedDevice): boolean {
  return device.x25519_identity_public.length === 32
    && device.mlkem_identity_public.length > 0
    && hasTerm(device.pqc_status, requiredSuite.classicalKex)
    && hasTerm(device.pqc_status, requiredSuite.pqKem);
}

function deviceHasHybridSignatures(device: TrustedDevice): boolean {
  return device.ed25519_identity_public.length === 32
    && device.mldsa_identity_public.length > 0
    && Boolean(device.identity_signature?.ed25519?.length)
    && Boolean(device.identity_signature?.ml_dsa_65?.length);
}

function deviceSuiteUsesRequiredStack(device: TrustedDevice): boolean {
  const values = Object.values(device.suite ?? {}).map(normalize).join(" ");
  return hasTerm(values, requiredSuite.kdf)
    && hasTerm(values, requiredSuite.symmetric)
    && hasTerm(values, requiredSuite.classicalKex)
    && hasTerm(values, requiredSuite.pqKem)
    && hasTerm(values, requiredSuite.classicalSignature)
    && hasTerm(values, requiredSuite.pqSignature);
}

function vaultSuiteUsesRequiredStack(file: VaultFileSummary): boolean {
  const suite = file.suite ?? {};
  const values = Object.values(suite).map(normalize).join(" ");
  if (!values) return true;
  return hasTerm(values, requiredSuite.symmetric)
    && hasTerm(values, requiredSuite.kdf)
    && (hasTerm(values, requiredSuite.pqKem) || hasTerm(values, "ML-KEM"))
    && (hasTerm(values, requiredSuite.pqSignature) || hasTerm(values, "ML-DSA"));
}

function isActiveDevice(device: TrustedDevice): boolean {
  return device.trust_state !== "Revoked";
}

function isTrustedDevice(device: TrustedDevice): boolean {
  return device.trust_state === "ThisDevice" || device.trust_state === "Trusted";
}

function isRecentDevice(device: TrustedDevice): boolean {
  const lastSeen = new Date(device.last_seen_at).getTime();
  if (!Number.isFinite(lastSeen)) return false;
  return Date.now() - lastSeen <= 14 * 24 * 60 * 60 * 1000;
}

function scoreRatio(active: number, total: number, weight: number): number {
  if (total <= 0) return 0;
  return Math.round((active / total) * weight);
}

// Release/runtime evidence gates (binary pinning, code signing, obfuscation,
// control-flow flattening, string encryption) are produced only by a hardened
// release build. They must NOT drag the live security posture score or surface
// as dashboard warnings -- they are tracked separately on the Quantum Security
// page (admin only). The live posture reflects the cryptographic stack.
const RELEASE_ONLY_HARDENING_IDS = new Set([
  "binary_integrity_verification",
  "signed_build_verification",
  "code_obfuscation",
  "control_flow_flattening",
  "string_encryption",
]);

/**
 * The checks that describe the RUNNING cryptography, with build-provenance
 * gates removed. Exported because the phone home screen measures its Runtime
 * layer over exactly this set: counting release metadata there made an
 * unmeasurable build gate read as a cryptographic failure.
 */
export function liveHardeningChecks(hardening: SecurityHardeningStatus): SecurityHardeningCheck[] {
  return hardening.checks.filter((check) => !RELEASE_ONLY_HARDENING_IDS.has(check.id));
}

/**
 * Event types that record a SUCCESSFUL, authenticated, user-initiated
 * ADMINISTRATIVE action rather than evidence of a security problem.
 *
 * These are written to the audit chain at `warning` severity by older clients,
 * and that severity was simply wrong: retiring a device is the exact hygiene
 * task the dashboard itself asks the user to perform ("dormant identities ...
 * retire them in Device Trust"), so scoring it as a security warning made the
 * app punish the user for following its own advice. A real account reached the
 * -20 penalty cap purely by cleaning up eight stranded reinstall rows, and read
 * 68% with a perfectly healthy cryptographic stack.
 *
 * The classification lives HERE, on the read side, and not only at the point of
 * writing, for a reason that cannot be worked around: `messaging_security_events`
 * is a tamper-evident hash chain (`event_hash` / `previous_hash`), so the
 * severity of rows already written can never be corrected in place without
 * breaking the chain. The posture engine has to be able to interpret history it
 * is not allowed to rewrite.
 *
 * Nothing is hidden: these events keep their full record in the audit log and on
 * the Device Trust page. They are excluded from the SCORE, not from the ledger.
 */
const ADMINISTRATIVE_EVENT_TYPES = new Set([
  "device_revoked",
  "device_delete_requested",
]);

/**
 * How far back a security event still describes CURRENT posture.
 *
 * Posture is a statement about now. Without a window, one mistyped password
 * deducts its points forever — the score can never recover, which is both wrong
 * and useless as a signal, because a permanently-depressed score stops telling
 * the user anything about today.
 */
export const POSTURE_EVENT_WINDOW_DAYS = 30;

/**
 * Whether an event counts against the live posture score.
 *
 * Severity is read as well as type on purpose: `safety_number_generated` is
 * `info` when the safety number verified and `warning` when it did not, and the
 * failing case is a genuine posture signal. Keying on type alone would lose it.
 */
export function isPostureAffectingEvent(event: SecurityEvent, now: number = Date.now()): boolean {
  if (event.severity !== "warning" && event.severity !== "critical") return false;
  if (ADMINISTRATIVE_EVENT_TYPES.has(event.event_type)) return false;
  const occurredAt = new Date(event.created_at).getTime();
  // An event with no usable timestamp keeps counting rather than being dropped:
  // the window must never become a way for a warning to disappear silently.
  if (!Number.isFinite(occurredAt)) return true;
  return now - occurredAt <= POSTURE_EVENT_WINDOW_DAYS * 24 * 60 * 60 * 1000;
}

/**
 * What can truthfully be said about Secure Chat forward secrecy.
 *
 * Secure Chat has no per-message ratchet: every message is sealed to the
 * recipient device's signed prekey. Forward secrecy comes from replacing that
 * prekey daily and destroying the retired ones once their messages are
 * accounted for — so it holds exactly to the extent that is really happening,
 * which only the device itself can report. The words come from the Rust core
 * (`describe_forward_secrecy`) so every screen says the same thing.
 */
export function describeForwardSecrecy(
  signedPrekeyPublished: boolean,
  prekeyStatus: PrekeyStatus | null | undefined,
): { healthy: boolean; summary: string } {
  if (!prekeyStatus) {
    return {
      healthy: false,
      summary: signedPrekeyPublished
        ? "Not measured: prekey rotation status is only available inside the app"
        : "Awaiting prekey material",
    };
  }
  return { healthy: prekeyStatus.forwardSecrecyHealthy, summary: prekeyStatus.forwardSecrecySummary };
}

function hardeningWarnings(checks: SecurityHardeningCheck[]): string[] {
  return checks
    .filter((check) => check.status !== "active")
    .map((check) => `${check.label}: ${check.detail}`);
}

export function buildSecurityPosture({
  profile,
  devices,
  vaultFiles,
  keyInventory,
  telemetry,
  securityEvents,
  hardening,
  vaultStorageLabel,
  prekeyStatus,
}: SecurityPostureInput): SecurityPostureResult {
  const myDevices = devices.filter((device) => device.user_id === profile.id);
  const activeMyDevices = myDevices.filter(isActiveDevice);
  const trustedMyDevices = activeMyDevices.filter(isTrustedDevice);
  const hybridKexReady = activeMyDevices.some(deviceHasHybridKex);
  const hybridSignatureReady = activeMyDevices.some(deviceHasHybridSignatures);
  const deviceSuiteReady = activeMyDevices.some(deviceSuiteUsesRequiredStack);
  const vaultStackReady = vaultFiles.every(vaultSuiteUsesRequiredStack);
  const requiredSymmetricStackReady = deviceSuiteReady && vaultStackReady;
  // Prekeys are PER DEVICE: each device publishes its own signed prekey (1) and
  // its own one-time-prekey pool. Readiness must therefore be a per-device floor,
  // NOT scaled by the total device count — otherwise stale device identities left
  // behind by reinstalls (each inflating activeMyDevices) make a perfectly healthy
  // device read as "awaiting prekey material" forever.
  const signedPrekeysReady = activeMyDevices.length > 0 && keyInventory.active_signed_prekeys >= SIGNED_PREKEY_MIN;
  const oneTimePrekeysNeeded = ONE_TIME_PREKEY_MIN;
  const oneTimePrekeysReady = keyInventory.available_one_time_prekeys >= oneTimePrekeysNeeded;
  // Read from the device's real rotation state — not inferred from the fact
  // that prekeys exist, which says nothing about whether old ones ever go away.
  const forwardSecrecy = describeForwardSecrecy(signedPrekeysReady, prekeyStatus);
  const forwardSecrecyReady = signedPrekeysReady && forwardSecrecy.healthy;
  const allActiveDevicesTrusted = activeMyDevices.length > 0 && trustedMyDevices.length === activeMyDevices.length;
  const recentHeartbeatReady = activeMyDevices.some(isRecentDevice);
  const liveHardening = liveHardeningChecks(hardening);
  const hardeningActiveCount = liveHardening.filter((check) => check.status === "active").length;
  const hardeningScore = scoreRatio(hardeningActiveCount, liveHardening.length, 35);
  // Only events that say something about CURRENT security state reach the score.
  // See isPostureAffectingEvent: successful administrative actions and events
  // outside the posture window are still fully recorded in the audit log, they
  // just stop standing in for a weakness that is not there.
  const postureEvents = securityEvents.filter((event) => isPostureAffectingEvent(event));
  const warningEvents = postureEvents.filter((event) => event.severity === "warning");
  const criticalEvents = postureEvents.filter((event) => event.severity === "critical");
  const cryptoTelemetryActive = telemetry.some((event) => /crypto|identity|key|vault|encrypt|decrypt|integrity/i.test(`${event.stage} ${event.detail}`));
  const auditChainActive = hardening.checks.some((check) => check.id === "tamper_evident_audit_chain" && check.status === "active");

  let score = 0;
  score += activeMyDevices.length > 0 ? 8 : 0;
  score += hybridKexReady ? 7 : 0;
  score += hybridSignatureReady ? 5 : 0;
  score += requiredSymmetricStackReady ? 5 : 0;
  score += signedPrekeysReady ? 6 : 0;
  score += scoreRatio(Math.min(keyInventory.available_one_time_prekeys, oneTimePrekeysNeeded), oneTimePrekeysNeeded, 5);
  score += forwardSecrecyReady ? 4 : 0;
  score += trustedMyDevices.length > 0 ? 7 : 0;
  score += allActiveDevicesTrusted ? 5 : 0;
  score += recentHeartbeatReady ? 3 : 0;
  score += hardeningScore;
  score += auditChainActive ? 4 : 0;
  score += cryptoTelemetryActive || hardening.checks.length > 0 ? 3 : 0;
  score += warningEvents.length === 0 && criticalEvents.length === 0 ? 3 : 0;

  const eventPenalty = Math.min(20, warningEvents.length * 4 + criticalEvents.length * 12);
  const quantumSafeScore = Math.max(0, Math.min(100, score - eventPenalty));
  const warnings = [
    ...(activeMyDevices.length === 0 ? ["No active device identity is registered for this account"] : []),
    ...(!hybridKexReady ? ["Hybrid key exchange is not fully verified for an active device"] : []),
    ...(!hybridSignatureReady ? ["Hybrid Ed25519 + ML-DSA-65 device signatures are not fully verified"] : []),
    ...(!deviceSuiteReady ? ["Device crypto suite does not fully report X25519, ML-KEM-1024, HKDF-SHA3-256, AES-256-GCM, Ed25519, and ML-DSA-65"] : []),
    ...(!vaultStackReady ? ["One or more vault records do not report the required AES-256-GCM / HKDF-SHA3-256 hybrid suite"] : []),
    ...(!signedPrekeysReady ? ["Signed prekeys are missing or below active device count"] : []),
    ...(!oneTimePrekeysReady ? [`One-time prekeys below readiness target (${keyInventory.available_one_time_prekeys}/${oneTimePrekeysNeeded})`] : []),
    ...(!forwardSecrecyReady ? [`Forward secrecy: ${forwardSecrecy.summary}`] : []),
    ...(!allActiveDevicesTrusted ? ["One or more active devices are pending or suspicious"] : []),
    ...hardeningWarnings(liveHardening),
    ...warningEvents.map((event) => `Security warning: ${event.event_type}`),
    ...criticalEvents.map((event) => `Critical security event: ${event.event_type}`),
  ];

  const algorithms = Array.from(new Set([
    ...keyInventory.algorithms,
    hybridKexReady ? `${requiredSuite.pqKem} + ${requiredSuite.classicalKex}` : "",
    hybridSignatureReady ? `${requiredSuite.pqSignature} + ${requiredSuite.classicalSignature}` : "",
  ].filter(Boolean)));

  const snapshot: DashboardSnapshot = {
    e2ee_status: hybridKexReady && hybridSignatureReady ? "Protected" : activeMyDevices.length > 0 ? "Needs Verification" : "Needs Device",
    pqc_status: hybridKexReady && hybridSignatureReady ? "Hybrid Active" : activeMyDevices.length > 0 ? "Partially Configured" : "Awaiting Keys",
    active_sessions: activeMyDevices.length,
    vault_storage: vaultStorageLabel,
    device_count: trustedMyDevices.length,
    quantum_safe_score: quantumSafeScore,
    hndl_status: hybridKexReady && hybridSignatureReady ? "Enabled" : "Not Ready",
  };

  const report: QuantumSecurityReport = {
    hybrid_session_status: hybridKexReady && hybridSignatureReady ? "Hybrid Active" : activeMyDevices.length > 0 ? "Hybrid Partial" : "No Active Session",
    pqc_algorithm: algorithms.length > 0 ? algorithms.join(" / ") : "No active device keys",
    forward_secrecy: forwardSecrecy.summary,
    forward_secrecy_healthy: forwardSecrecyReady,
    hndl_protection: snapshot.hndl_status,
    quantum_safe_score: snapshot.quantum_safe_score,
    key_rotation_history: securityEvents
      .filter((event) => event.event_type.includes("key") || event.event_type.includes("prekey"))
      .map((event) => `${event.event_type} at ${new Date(event.created_at).toLocaleString()}`),
    warnings,
  };

  return { snapshot, report };
}
