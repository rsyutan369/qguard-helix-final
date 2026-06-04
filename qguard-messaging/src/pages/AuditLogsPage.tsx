import { Activity, Download, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import type { QGuardLiveEvent } from "@/lib/live-sse";
import type { SecurityEvent, TelemetryEvent } from "@/lib/types";
import { safeInvoke } from "@/lib/tauri";

interface AuditLogsPageProps {
  events: TelemetryEvent[];
  securityEvents: SecurityEvent[];
  liveEvents: QGuardLiveEvent[];
}

export default function AuditLogsPage({ events, securityEvents, liveEvents }: AuditLogsPageProps) {
  const [exporting, setExporting] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const rows = useMemo(() => [
    ...events.map((event) => ({
      id: `telemetry-${event.id}`,
      stage: event.stage,
      detail: event.detail,
      progress: `${event.progress}%`,
      integrity: "Telemetry",
      created_at: event.created_at,
    })),
    ...securityEvents.map((event) => ({
      id: `security-${event.id}`,
      stage: event.event_type,
      detail: `Severity ${event.severity}; hash ${event.event_hash}`,
      progress: "100%",
      integrity: event.previous_hash ? "Chained" : "Head",
      created_at: event.created_at,
    })),
    ...liveEvents.slice(0, 30).map((event) => ({
      id: `live-${event.id}`,
      stage: `sse:${event.table}`,
      detail: event.detail,
      progress: "live",
      integrity: "SSE",
      created_at: event.at,
    })),
  ].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()), [events, liveEvents, securityEvents]);

  async function exportReport() {
    setExporting(true);
    setStatus(null);
    try {
      const report = await safeInvoke<Record<string, unknown>>("security_export_report");
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `qguard-security-report-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      setStatus("Security report exported");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setExporting(false);
    }
  }

  return (
    <section className="shell-card overflow-hidden">
      <div className="flex items-center justify-between border-b border-line p-4">
        <div className="flex items-center gap-2">
          <Activity className="text-violet-600" size={20} />
          <h2 className="text-sm font-bold text-ink-950">Message Audit Logs</h2>
        </div>
        <button disabled={exporting} onClick={exportReport} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm font-bold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50">
          <Download size={16} />
          {exporting ? "Exporting" : "Export Security Report"}
        </button>
      </div>
      {status && <div className="border-b border-line bg-cyan-50 px-4 py-2 text-xs font-semibold text-cyan-700">{status}</div>}
      <div className="grid grid-cols-[180px_1fr_120px_120px] border-b border-line bg-canvas px-4 py-3 text-xs font-bold uppercase tracking-wide text-ink-400">
        <span>Stage</span><span>Detail</span><span>Progress</span><span>Integrity</span>
      </div>
      {rows.length === 0 && (
        <div className="p-6 text-center text-sm text-ink-600">No security events are available for this user.</div>
      )}
      {rows.map((event) => (
        <div key={event.id} className="grid grid-cols-[180px_1fr_120px_120px] border-b border-line px-4 py-3 text-sm">
          <span className="truncate font-semibold text-ink-950">{event.stage}</span>
          <span className="truncate text-ink-600">{event.detail}</span>
          <span className="text-violet-600">{event.progress}</span>
          <span className="flex items-center gap-1 text-emerald-600"><ShieldCheck size={14} />{event.integrity}</span>
        </div>
      ))}
      {securityEvents.length > 0 && (
        <div className="border-t border-line bg-canvas p-3 text-xs font-semibold text-ink-600">
          Hash chain heads are rendered from `messaging_security_events`; event details remain encrypted.
        </div>
      )}
    </section>
  );
}
