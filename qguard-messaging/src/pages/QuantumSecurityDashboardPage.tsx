import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Database,
  Gauge,
  KeyRound,
  Loader2,
  LockKeyhole,
  Radio,
  RefreshCcw,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { CSSProperties } from "react";
import { useMemo, useState } from "react";
import { recordCryptoTelemetry } from "@/lib/crypto-telemetry";
import { isAdminEmail } from "@/lib/admin";
import { ONE_TIME_PREKEY_MIN, SIGNED_PREKEY_MIN } from "@/lib/security-score";
import type { QGuardLiveEvent, QGuardLiveStatus } from "@/lib/live-sse";
import type { DashboardData, SecurityHardeningCheck, TelemetryEvent, TrustedDevice, VaultFileSummary } from "@/lib/types";

interface QuantumSecurityDashboardPageProps {
  userId: string;
  data: DashboardData;
  liveEvents: QGuardLiveEvent[];
  liveStatus: QGuardLiveStatus;
  onRefresh: () => void | Promise<void>;
}

type StatusState = {
  tone: "success" | "warning" | "error" | "info";
  message: string;
} | null;

interface StackEvidenceRow {
  label: string;
  value: string;
  active: boolean;
  detail: string;
}

const requiredSuite = {
  classicalKex: "X25519",
  pqKem: "ML-KEM-1024",
  kdf: "HKDF-SHA3-256",
  symmetric: "AES-256-GCM",
  classicalSignature: "Ed25519",
  pqSignature: "ML-DSA-65",
};

const QUANTUM_LIVE_TABLES = new Set([
  "messaging_devices",
  "messaging_signed_prekeys",
  "messaging_one_time_prekeys",
  "messaging_message_envelopes",
  "messaging_message_user_states",
  "messaging_vault_files",
  "qguard_vault_operations",
  "messaging_crypto_telemetry",
  "messaging_security_events",
]);

const statusAlertTone = {
  success: "border-emerald-200 bg-emerald-50 text-emerald-700",
  warning: "border-amber-200 bg-amber-50 text-amber-700",
  error: "border-rose-200 bg-rose-50 text-rose-600",
  info: "border-cyan-200 bg-cyan-50 text-cyan-700",
};

function normalize(value: unknown): string {
  return String(value ?? "").toUpperCase().replace(/[_\s]+/g, "-");
}

function hasTerm(value: unknown, term: string): boolean {
  return normalize(value).includes(normalize(term));
}

function describeDataError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  const candidate = error as { message?: string; details?: string; hint?: string; code?: string };
  return [candidate.message, candidate.details, candidate.hint, candidate.code].filter(Boolean).join(" ") || "Quantum security operation failed.";
}

function scoreColor(score: number): string {
  if (score >= 95) return "#10b981";
  if (score >= 70) return "#f59e0b";
  return "#f43f5e";
}

function statusTone(status: SecurityHardeningCheck["status"]): string {
  if (status === "active") return "text-emerald-600";
  if (status === "failed") return "text-rose-600";
  return "text-amber-600";
}

function statusText(status: SecurityHardeningCheck["status"]): string {
  if (status === "active") return "Active";
  if (status === "failed") return "Failed";
  return "Review";
}


function liveTone(state: QGuardLiveStatus["state"]): string {
  if (state === "live") return "bg-emerald-50 text-emerald-600";
  if (state === "connecting") return "bg-amber-50 text-amber-600";
  if (state === "fallback") return "bg-cyan-50 text-cyan-700";
  return "bg-rose-50 text-rose-600";
}

function sortTime(value: string | null | undefined): number {
  const parsed = new Date(value ?? "").getTime();
  return Number.isFinite(parsed) ? parsed : 0;
}

function latestIso(values: Array<string | null | undefined>): string | null {
  const latest = values.map(sortTime).filter(Boolean).sort((a, b) => b - a)[0];
  return latest ? new Date(latest).toISOString() : null;
}

function relativeTime(value: string | null | undefined): string {
  if (!value) return "No events yet";
  const time = sortTime(value);
  if (!time) return "Unknown";
  const seconds = Math.max(0, Math.floor((Date.now() - time) / 1000));
  if (seconds < 10) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function cleanLabel(value: string): string {
  return value.replace(/_/g, " ");
}

function isTrustedDevice(device: TrustedDevice): boolean {
  return device.trust_state === "ThisDevice" || device.trust_state === "Trusted";
}

function isActiveDevice(device: TrustedDevice): boolean {
  return device.trust_state !== "Revoked";
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
  const values = Object.values(file.suite ?? {}).map(normalize).join(" ");
  if (!values) return true;
  return hasTerm(values, requiredSuite.symmetric)
    && hasTerm(values, requiredSuite.kdf)
    && (hasTerm(values, requiredSuite.pqKem) || hasTerm(values, "ML-KEM"))
    && (hasTerm(values, requiredSuite.pqSignature) || hasTerm(values, "ML-DSA"));
}

function isQuantumTelemetry(event: TelemetryEvent): boolean {
  return /quantum|pqc|ml-kem|ml-dsa|x25519|ed25519|key|prekey|ratchet|vault|encrypt|decrypt|integrity|hndl|aead/i.test(`${event.stage} ${event.detail}`);
}

function isQuantumLiveEvent(event: QGuardLiveEvent): boolean {
  if (!QUANTUM_LIVE_TABLES.has(event.table)) return false;
  if (event.table === "messaging_crypto_telemetry" || event.table === "messaging_security_events") {
    return /quantum|pqc|ml-kem|ml-dsa|key|prekey|ratchet|vault|encrypt|decrypt|integrity|hndl|security|device/i.test(event.detail);
  }
  return true;
}

function hardeningCheck(hardeningChecks: SecurityHardeningCheck[], id: string): SecurityHardeningCheck | null {
  return hardeningChecks.find((check) => check.id === id) ?? null;
}

export default function QuantumSecurityDashboardPage({ userId, data, liveEvents, liveStatus, onRefresh }: QuantumSecurityDashboardPageProps) {
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<StatusState>(null);
  const { report, hardening, devices, keyInventory, telemetry, securityEvents, vaultFiles } = data;
  const isAdmin = isAdminEmail(data.profile?.email);
  const hardeningChecks = hardening.checks;
  const activeCount = hardeningChecks.filter((check) => check.status === "active").length;
  const totalCount = hardeningChecks.length;
  const allHardeningActive = totalCount > 0 && activeCount === totalCount;
  const inactiveChecks = hardeningChecks.filter((check) => check.status !== "active");
  const binaryHash = hardening.binary_sha3 ? `${hardening.binary_sha3.slice(0, 18)}...${hardening.binary_sha3.slice(-10)}` : "Unavailable";
  // Name the file the hash was taken over. It is not always an executable: an
  // Android release build maps its code straight out of the APK, so the APK is
  // the measured image. A hash with no stated subject is unverifiable.
  const measuredArtifact = hardening.binary_path?.split(/[\\/]/).pop() ?? null;
  const activeMyDevices = useMemo(() => devices.filter((device) => device.user_id === userId && isActiveDevice(device)), [devices, userId]);
  const trustedMyDevices = useMemo(() => activeMyDevices.filter(isTrustedDevice), [activeMyDevices]);
  const hybridKexReady = activeMyDevices.some(deviceHasHybridKex);
  const hybridSignatureReady = activeMyDevices.some(deviceHasHybridSignatures);
  const deviceSuiteReady = activeMyDevices.some(deviceSuiteUsesRequiredStack);
  const vaultStackReady = vaultFiles.every(vaultSuiteUsesRequiredStack);
  // Prekey readiness is a PER-DEVICE floor (this device publishes its own
  // pool), never scaled by the registered device count — stale device rows
  // from reinstalls would make a device-count target unattainable forever.
  // Same thresholds as buildSecurityPosture in security-score.ts.
  const signedPrekeyTarget = SIGNED_PREKEY_MIN;
  const signedPrekeysReady = activeMyDevices.length > 0 && keyInventory.active_signed_prekeys >= signedPrekeyTarget;
  const oneTimePrekeyTarget = ONE_TIME_PREKEY_MIN;
  const oneTimePrekeysReady = keyInventory.available_one_time_prekeys >= oneTimePrekeyTarget;
  const tamperAuditActive = hardeningCheck(hardeningChecks, "tamper_evident_audit_chain")?.status === "active";
  const webIntegrityActive = hardeningCheck(hardeningChecks, "web_asset_integrity")?.status === "active";
  const quantumTelemetry = useMemo(() => telemetry.filter(isQuantumTelemetry).slice(0, 6), [telemetry]);
  const quantumLiveEvents = useMemo(() => liveEvents.filter(isQuantumLiveEvent).slice(0, 6), [liveEvents]);
  const latestSecurityEvent = securityEvents[0] ?? null;
  const latestBackendAt = latestIso([
    liveStatus.lastEventAt,
    quantumTelemetry[0]?.created_at,
    latestSecurityEvent?.created_at,
    ...activeMyDevices.map((device) => device.last_seen_at),
  ]);

  const stackEvidence: StackEvidenceRow[] = [
    {
      label: "Hybrid Key Exchange",
      value: `${requiredSuite.pqKem} + ${requiredSuite.classicalKex}`,
      active: hybridKexReady,
      detail: `${activeMyDevices.filter(deviceHasHybridKex).length}/${Math.max(1, activeMyDevices.length)} active devices publish hybrid identity keys`,
    },
    {
      label: "Hybrid Signatures",
      value: `${requiredSuite.pqSignature} + ${requiredSuite.classicalSignature}`,
      active: hybridSignatureReady,
      detail: `${activeMyDevices.filter(deviceHasHybridSignatures).length}/${Math.max(1, activeMyDevices.length)} active devices publish dual signatures`,
    },
    {
      label: "KDF + AEAD",
      value: `${requiredSuite.kdf} + ${requiredSuite.symmetric}`,
      active: deviceSuiteReady && vaultStackReady,
      detail: vaultStackReady ? "Device and vault suites report the required stack" : "One or more vault records need suite verification",
    },
    {
      label: "Forward Secrecy",
      value: report.forward_secrecy,
      // Rotation actually happening on this device, as the core reports it —
      // not the mere presence of published prekeys.
      active: signedPrekeysReady && report.forward_secrecy_healthy === true,
      detail: `${keyInventory.active_signed_prekeys}/${signedPrekeyTarget} signed prekey published; it is replaced daily and retired ones are destroyed once their messages are accounted for`,
    },
    {
      label: "Tamper Evidence",
      value: "SHA3 hash-chain audit",
      active: tamperAuditActive,
      detail: tamperAuditActive ? "Native audit hash chain verifies" : "Native audit chain is not yet verified in this runtime",
    },
    {
      label: "Web Asset Integrity",
      value: "SHA3-256 asset manifest",
      active: webIntegrityActive,
      detail: hardeningCheck(hardeningChecks, "web_asset_integrity")?.detail ?? "Security manifest pending",
    },
  ];
  const activeStackEvidence = stackEvidence.filter((row) => row.active).length;
  const quantumStackScore = stackEvidence.length > 0 ? Math.round((activeStackEvidence / stackEvidence.length) * 100) : 0;
  const quantumStackComplete = stackEvidence.length > 0 && activeStackEvidence === stackEvidence.length;
  const quantumStackStatus = quantumStackComplete ? "All Active" : `${activeStackEvidence}/${stackEvidence.length} Active`;
  const scoreRingStyle = {
    "--score-color": scoreColor(quantumStackScore),
    background: `conic-gradient(var(--score-color) ${quantumStackScore * 3.6}deg, rgba(148, 163, 184, 0.28) 0deg)`,
  } as CSSProperties;
  const scoreStatus = quantumStackComplete
    ? "100% Quantum Security Protection"
    : `${stackEvidence.length - activeStackEvidence} stack check${stackEvidence.length - activeStackEvidence === 1 ? "" : "s"} need review`;
  const cards: { icon: LucideIcon; label: string; value: string; caption: string; tone: "emerald" | "violet" | "cyan" | "amber" }[] = [
    { icon: Gauge, label: "Quantum-safe Score", value: `${quantumStackScore}%`, caption: scoreStatus, tone: quantumStackScore >= 95 ? "emerald" : "amber" },
    { icon: ShieldCheck, label: "Hybrid Session", value: report.hybrid_session_status, caption: `${trustedMyDevices.length}/${Math.max(1, activeMyDevices.length)} trusted active devices`, tone: hybridKexReady && hybridSignatureReady ? "violet" : "amber" },
    { icon: Zap, label: "HNDL Protection", value: report.hndl_protection, caption: deviceSuiteReady ? "Hybrid non-decrypt-later posture enabled" : "Awaiting full suite evidence", tone: report.hndl_protection === "Enabled" ? "cyan" : "amber" },
    { icon: RefreshCcw, label: "Forward Secrecy", value: report.forward_secrecy, caption: report.forward_secrecy_healthy === true ? "Per rotation period, not per message" : "Needs attention", tone: signedPrekeysReady && report.forward_secrecy_healthy === true ? "emerald" : "amber" },
  ];

  async function recordQuantumTelemetry(stage: string, detail: string, progress: number, statusValue: "started" | "progress" | "verified" | "failed" | "complete") {
    await recordCryptoTelemetry({
      userId,
      scope: "verification",
      stage,
      detail,
      progress,
      status: statusValue,
      metadata: {
        module: "quantum_security",
        live_state: liveStatus.state,
        hardening_active: activeCount,
        hardening_total: totalCount,
      },
    });
  }

  function refreshQuantumSecurity() {
    void (async () => {
      setBusy(true);
      setStatus({ tone: "info", message: "Refreshing quantum posture from runtime hardening, Supabase telemetry, and live SSE state..." });
      try {
        await recordQuantumTelemetry("quantum_posture_refresh_started", "Quantum security refresh requested", 10, "started");
        await Promise.resolve(onRefresh());
        await recordQuantumTelemetry("quantum_posture_refreshed", quantumStackComplete ? "Quantum Security Stack is fully active" : `${stackEvidence.length - activeStackEvidence} stack checks require live evidence`, 100, quantumStackComplete ? "verified" : "progress");
        setStatus({
          tone: quantumStackComplete ? "success" : "warning",
          message: quantumStackComplete ? "Quantum Security Stack is fully active from live runtime evidence." : `Quantum Security refreshed. ${stackEvidence.length - activeStackEvidence} stack check${stackEvidence.length - activeStackEvidence === 1 ? "" : "s"} still need live evidence.`,
        });
      } catch (error) {
        const message = describeDataError(error);
        setStatus({ tone: "error", message });
        await recordQuantumTelemetry("quantum_posture_refresh_failed", message, 100, "failed");
      } finally {
        setBusy(false);
      }
    })();
  }

  function cardIconTone(tone: "emerald" | "violet" | "cyan" | "amber"): string {
    if (tone === "emerald") return "text-emerald-600";
    if (tone === "cyan") return "text-cyan-600";
    if (tone === "amber") return "text-amber-600";
    return "text-violet-600";
  }

  return (
    <div className="grid gap-4">
      <div className="grid gap-4 lg:grid-cols-4">
        {cards.map(({ icon: Icon, label, value, caption, tone }) => (
          <section key={label} className="shell-card p-4">
            <Icon className={cardIconTone(tone)} size={24} />
            <div className="mt-3 text-xs font-semibold text-ink-600">{label}</div>
            <div className="mt-1 text-lg font-bold text-ink-950">{value}</div>
            <div className="mt-1 truncate text-xs text-ink-500">{caption}</div>
          </section>
        ))}
      </div>

      <section className="shell-card grid grid-cols-[minmax(0,1fr)] gap-5 p-5 xl:grid-cols-[320px_1fr]">
        <div className="flex aspect-square items-center justify-center rounded-full p-3" style={scoreRingStyle}>
          <div className="flex h-full w-full items-center justify-center rounded-full bg-white text-center">
            <div>
              <div className="text-4xl font-bold text-emerald-600">{quantumStackScore}</div>
              <div className="text-sm font-semibold text-ink-600">Quantum Score</div>
              <div className="mt-1 px-6 text-xs font-semibold text-ink-500">{scoreStatus}</div>
            </div>
          </div>
        </div>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-bold text-ink-950">Real Quantum Security Stack</h2>
              <div className="mt-1 text-xs text-ink-600">{activeStackEvidence}/{stackEvidence.length} stack evidence checks active</div>
            </div>
            <button onClick={refreshQuantumSecurity} disabled={busy} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm font-semibold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50">
              {busy ? <Loader2 className="animate-spin" size={16} /> : <RefreshCcw size={16} />}
              Refresh
            </button>
          </div>

          <div className="mt-4 grid gap-3">
            {stackEvidence.map((row) => (
              <div key={row.label} className="grid gap-3 rounded-lg border border-line p-3 text-sm md:grid-cols-[190px_1fr_90px]">
                <span className="font-semibold text-ink-950">{row.label}</span>
                <span className="min-w-0">
                  <span className="block truncate font-mono text-xs text-violet-600">{row.value}</span>
                  <span className="mt-1 block truncate text-xs text-ink-500">{row.detail}</span>
                </span>
                <span className={`flex items-center justify-end gap-1 text-sm font-bold ${row.active ? "text-emerald-600" : "text-amber-600"}`}>
                  {row.active ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}
                  {row.active ? "Active" : "Review"}
                </span>
              </div>
            ))}
          </div>
          {status && (
            <div className={`mt-4 rounded-lg border px-3 py-2 text-xs font-semibold ${statusAlertTone[status.tone]}`}>
              {status.message}
            </div>
          )}
        </div>
      </section>

      {isAdmin && (
      <section className="shell-card p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-ink-950">Realtime Quantum Telemetry</h2>
            <div className="mt-1 text-xs text-ink-600">Quantum posture refreshed {relativeTime(latestBackendAt)}</div>
          </div>
          <span className={`status-pill ${liveTone(liveStatus.state)}`}>
            <Radio size={13} />
            {liveStatus.state}
          </span>
        </div>

        <div className="mt-4 grid gap-4 border-y border-line py-3 md:grid-cols-4">
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Live Detail</div>
            <div className="mt-1 truncate text-sm font-semibold text-ink-950">{liveStatus.detail}</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Last Event</div>
            <div className="mt-1 text-sm font-semibold text-ink-950">{relativeTime(liveStatus.lastEventAt)}</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Quantum Telemetry</div>
            <div className="mt-1 text-sm font-semibold text-ink-950">{quantumTelemetry.length} recent records</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Quantum Stack</div>
            <div className={`mt-1 text-sm font-semibold ${quantumStackComplete ? "text-emerald-600" : "text-amber-600"}`}>{quantumStackStatus}</div>
          </div>
        </div>

        <div className="mt-4 grid gap-6 xl:grid-cols-3">
          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-ink-400">
              <Database size={14} />
              Backend Events
            </div>
            {quantumLiveEvents.length === 0 && (
              <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">Live stream connected. No quantum backend changes received yet.</div>
            )}
            <div className="space-y-2">
              {quantumLiveEvents.map((event) => (
                <div key={event.id} className="flex items-center gap-3 border-t border-line pt-2 first:border-t-0 first:pt-0">
                  <span className="h-2 w-2 shrink-0 rounded-full bg-emerald-500" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs font-semibold text-ink-950">{event.detail}</div>
                    <div className="text-[11px] text-ink-400">{event.table} - {event.event.toLowerCase()} - {relativeTime(event.at)}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-ink-400">
              <Activity size={14} />
              Crypto Telemetry
            </div>
            {quantumTelemetry.length === 0 && (
              <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">No quantum telemetry yet.</div>
            )}
            <div className="space-y-2">
              {quantumTelemetry.map((event) => (
                <div key={event.id} className="flex items-center gap-3 border-t border-line pt-2 first:border-t-0 first:pt-0">
                  <span className={`status-pill shrink-0 ${event.progress >= 100 ? "bg-emerald-50 text-emerald-600" : "bg-amber-50 text-amber-600"}`}>{Math.max(0, Math.min(100, Math.round(event.progress)))}%</span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs font-semibold text-ink-950">{cleanLabel(event.stage)}</div>
                    <div className="truncate text-[11px] text-ink-500">{event.detail}</div>
                  </div>
                  <div className="shrink-0 text-[11px] text-ink-400">{relativeTime(event.created_at)}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-ink-400">
              <ShieldAlert size={14} />
              Security Events
            </div>
            {securityEvents.length === 0 && (
              <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">No security events yet.</div>
            )}
            <div className="space-y-2">
              {securityEvents.slice(0, 6).map((event) => (
                <div key={event.id} className="flex items-center gap-3 border-t border-line pt-2 first:border-t-0 first:pt-0">
                  <span className={`status-pill shrink-0 ${event.severity === "critical" ? "bg-rose-50 text-rose-600" : event.severity === "warning" ? "bg-amber-50 text-amber-700" : "bg-emerald-50 text-emerald-600"}`}>{event.severity}</span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs font-semibold text-ink-950">{cleanLabel(event.event_type)}</div>
                    <div className="truncate font-mono text-[11px] text-ink-400">{event.event_hash}</div>
                  </div>
                  <div className="shrink-0 text-[11px] text-ink-400">{relativeTime(event.created_at)}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
      )}

      {isAdmin && (
      <section className="security-hardening-panel rounded-lg border p-5 shadow-tight">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-ink-950">Security Hardening</h2>
            <div className="mt-1 font-mono text-xs text-ink-500">
              Runtime image SHA3-256: {binaryHash}
              {measuredArtifact ? ` (${measuredArtifact})` : ""}
            </div>
          </div>
          <div className={`status-pill ${allHardeningActive ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-700"}`}>
            {allHardeningActive ? <ShieldCheck size={13} /> : <AlertTriangle size={13} />}
            {activeCount}/{totalCount} active
          </div>
        </div>

        <div className="mt-5 divide-y divide-line">
          {hardeningChecks.map((check) => {
            const Icon = check.status === "active" ? CheckCircle2 : AlertTriangle;
            return (
              <div key={check.id} className="grid grid-cols-[minmax(220px,1fr)_100px] gap-4 py-3">
                <div className="min-w-0">
                  <div className="font-semibold text-ink-800">{check.label}</div>
                  <div className="mt-1 truncate text-xs text-ink-500">{check.detail}</div>
                </div>
                <div className={`flex items-center justify-end gap-2 text-sm font-bold ${statusTone(check.status)}`}>
                  <Icon size={16} />
                  {statusText(check.status)}
                </div>
              </div>
            );
          })}
        </div>
      </section>
      )}

      {isAdmin && inactiveChecks.length > 0 && (
        <section className="shell-card border-amber-200 bg-amber-50 p-4">
          <div className="flex items-center gap-2 text-sm font-bold text-amber-700">
            <LockKeyhole size={18} />
            Production Hardening Gate
          </div>
          <div className="mt-1 text-sm text-amber-700">
            {inactiveChecks.length} release/runtime evidence {inactiveChecks.length === 1 ? "check is" : "checks are"} not active. These remain Review until the desktop runtime reports real signing, binary pinning, obfuscation, or string/control-flow protection evidence.
          </div>
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            {inactiveChecks.slice(0, 6).map((check) => (
              <div key={check.id} className="rounded-lg border border-amber-200 bg-white/70 p-3 text-xs text-amber-800">
                <div className="font-bold">{check.label}</div>
                <div className="mt-1">{check.detail}</div>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="shell-card p-5">
        <div className="flex items-center gap-2">
          <KeyRound className="text-violet-600" size={18} />
          <h2 className="text-sm font-bold text-ink-950">Key Rotation History</h2>
        </div>
        <div className="mt-4 grid gap-2">
          {report.key_rotation_history.length === 0 && (
            <div className="rounded-lg border border-line bg-canvas p-4 text-sm text-ink-600">
              No key rotation events have been recorded for this account yet.
            </div>
          )}
          {report.key_rotation_history.map((item, index) => (
            <div key={`${item}-${index}`} className="flex items-center gap-3 rounded-lg border border-line p-3 text-sm">
              <span className="flex h-6 w-6 items-center justify-center rounded-full bg-violet-50 text-xs font-bold text-violet-600">{index + 1}</span>
              <span className="font-semibold text-ink-700">{item}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
