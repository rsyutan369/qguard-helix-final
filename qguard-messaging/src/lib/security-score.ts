import type {
  ConversationSummary,
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
  conversations: ConversationSummary[];
  vaultFiles: VaultFileSummary[];
  keyInventory: KeyInventory;
  telemetry: TelemetryEvent[];
  securityEvents: SecurityEvent[];
  hardening: SecurityHardeningStatus;
  vaultStorageLabel: string;
}

interface SecurityPostureResult {
  snapshot: DashboardSnapshot;
  report: QuantumSecurityReport;
}

// Per-device prekey readiness floors (see buildSecurityPosture). A device is
// forward-secrecy-ready with one active signed prekey and a healthy one-time
// prekey pool; these are NOT multiplied by the number of registered devices.
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

function liveHardeningChecks(hardening: SecurityHardeningStatus): SecurityHardeningCheck[] {
  return hardening.checks.filter((check) => !RELEASE_ONLY_HARDENING_IDS.has(check.id));
}

function hardeningWarnings(checks: SecurityHardeningCheck[]): string[] {
  return checks
    .filter((check) => check.status !== "active")
    .map((check) => `${check.label}: ${check.detail}`);
}

export function buildSecurityPosture({
  profile,
  devices,
  conversations,
  vaultFiles,
  keyInventory,
  telemetry,
  securityEvents,
  hardening,
  vaultStorageLabel,
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
  const forwardSecrecyReady = signedPrekeysReady && (oneTimePrekeysReady || conversations.length > 0);
  const allActiveDevicesTrusted = activeMyDevices.length > 0 && trustedMyDevices.length === activeMyDevices.length;
  const recentHeartbeatReady = activeMyDevices.some(isRecentDevice);
  const liveHardening = liveHardeningChecks(hardening);
  const hardeningActiveCount = liveHardening.filter((check) => check.status === "active").length;
  const hardeningScore = scoreRatio(hardeningActiveCount, liveHardening.length, 35);
  const warningEvents = securityEvents.filter((event) => event.severity === "warning");
  const criticalEvents = securityEvents.filter((event) => event.severity === "critical");
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
    ...(!forwardSecrecyReady ? ["Forward secrecy ratchet material is not ready"] : []),
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
    forward_secrecy: forwardSecrecyReady
      ? "Per-message ratchet keys active"
      : signedPrekeysReady
        ? "Signed prekeys active; replenish one-time prekeys"
        : "Awaiting prekey material",
    hndl_protection: snapshot.hndl_status,
    quantum_safe_score: snapshot.quantum_safe_score,
    key_rotation_history: securityEvents
      .filter((event) => event.event_type.includes("key") || event.event_type.includes("prekey"))
      .map((event) => `${event.event_type} at ${new Date(event.created_at).toLocaleString()}`),
    warnings,
  };

  return { snapshot, report };
}
