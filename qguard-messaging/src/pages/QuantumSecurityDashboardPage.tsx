import { AlertTriangle, CheckCircle2, Gauge, RefreshCcw, ShieldCheck, Zap } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { CSSProperties } from "react";
import type { QuantumSecurityReport, SecurityHardeningCheck, SecurityHardeningStatus } from "@/lib/types";

interface QuantumSecurityDashboardPageProps {
  report: QuantumSecurityReport;
  hardening: SecurityHardeningStatus;
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

function scoreColor(score: number): string {
  if (score >= 90) return "#10b981";
  if (score >= 70) return "#f59e0b";
  return "#f43f5e";
}

export default function QuantumSecurityDashboardPage({ report, hardening }: QuantumSecurityDashboardPageProps) {
  const cards: { icon: LucideIcon; label: string; value: string; tone: "emerald" | "violet" | "cyan" }[] = [
    { icon: Gauge, label: "Quantum-safe Score", value: `${report.quantum_safe_score}%`, tone: "emerald" },
    { icon: ShieldCheck, label: "Hybrid Session", value: report.hybrid_session_status, tone: "violet" },
    { icon: Zap, label: "HNDL Protection", value: report.hndl_protection, tone: "cyan" },
    { icon: RefreshCcw, label: "Forward Secrecy", value: report.forward_secrecy, tone: "emerald" },
  ];

  const hardeningChecks = hardening.checks;
  const activeCount = hardeningChecks.filter((check) => check.status === "active").length;
  const totalCount = hardeningChecks.length;
  const allHardeningActive = totalCount > 0 && activeCount === totalCount;
  const binaryHash = hardening.binary_sha3 ? `${hardening.binary_sha3.slice(0, 18)}...${hardening.binary_sha3.slice(-10)}` : "Unavailable";
  const scoreRingStyle = {
    "--score-color": scoreColor(report.quantum_safe_score),
    background: `conic-gradient(var(--score-color) ${report.quantum_safe_score * 3.6}deg, rgba(148, 163, 184, 0.28) 0deg)`,
  } as CSSProperties;
  const scoreStatus = report.quantum_safe_score === 100
    ? "100% Quantum Security Protection"
    : `${report.warnings.length} validation item${report.warnings.length === 1 ? "" : "s"} need review`;

  return (
    <div className="grid gap-4">
      <div className="grid grid-cols-4 gap-4">
        {cards.map(({ icon: Icon, label, value, tone }) => (
          <section key={label} className="shell-card p-4">
            <Icon className={tone === "emerald" ? "text-emerald-600" : tone === "cyan" ? "text-cyan-600" : "text-violet-600"} size={24} />
            <div className="mt-3 text-xs font-semibold text-ink-600">{label}</div>
            <div className="mt-1 text-lg font-bold text-ink-950">{value}</div>
          </section>
        ))}
      </div>

      <section className="shell-card grid grid-cols-[320px_1fr] gap-5 p-5">
        <div className="flex aspect-square items-center justify-center rounded-full p-3" style={scoreRingStyle}>
          <div className="flex h-full w-full items-center justify-center rounded-full bg-white text-center">
            <div>
              <div className="text-4xl font-bold text-emerald-600">{report.quantum_safe_score}</div>
              <div className="text-sm font-semibold text-ink-600">Quantum Score</div>
              <div className="mt-1 px-6 text-xs font-semibold text-ink-500">{scoreStatus}</div>
            </div>
          </div>
        </div>
        <div>
          <h2 className="text-sm font-bold text-ink-950">Security Stack</h2>
          <div className="mt-4 grid gap-3">
            {[
              ["PQC Algorithms", report.pqc_algorithm],
              ["Key Derivation", "HKDF-SHA3-256"],
              ["Symmetric Encryption", "AES-256-GCM"],
              ["Signatures", "Ed25519 + ML-DSA-65"],
              ["Forward Secrecy", report.forward_secrecy],
            ].map(([label, value]) => (
              <div key={label} className="flex items-center justify-between rounded-lg border border-line p-3 text-sm">
                <span className="font-semibold text-ink-950">{label}</span>
                <span className="font-mono text-xs text-violet-600">{value}</span>
              </div>
            ))}
          </div>
          {report.warnings.length > 0 && (
            <div className="mt-4 rounded-lg border border-amber-100 bg-amber-50 p-3 text-xs font-semibold text-amber-700">
              {report.warnings.slice(0, 3).join(" | ")}
            </div>
          )}
        </div>
      </section>

      <section className="security-hardening-panel rounded-lg border p-5 shadow-tight">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-ink-950">Security Hardening</h2>
            <div className="mt-1 font-mono text-xs text-ink-500">Runtime binary SHA3-256: {binaryHash}</div>
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

      <section className="shell-card p-5">
        <h2 className="text-sm font-bold text-ink-950">Key Rotation History</h2>
        <div className="mt-4 grid gap-2">
          {report.key_rotation_history.length === 0 && (
            <div className="rounded-lg border border-line bg-canvas p-4 text-sm text-ink-600">
              No key rotation events have been recorded for this account yet.
            </div>
          )}
          {report.key_rotation_history.map((item, index) => (
            <div key={item} className="flex items-center gap-3 rounded-lg border border-line p-3 text-sm">
              <span className="flex h-6 w-6 items-center justify-center rounded-full bg-violet-50 text-xs font-bold text-violet-600">{index + 1}</span>
              <span className="font-semibold text-ink-700">{item}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
