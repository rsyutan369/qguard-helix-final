import {
  Activity,
  AlertTriangle,
  Check,
  Clock3,
  Database,
  Download,
  FileText,
  Loader2,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { securityEventDetails } from "@/lib/account-key";
import { recordCryptoTelemetry } from "@/lib/crypto-telemetry";
import { useIsAdmin } from "@/lib/admin";
import type { QGuardLiveEvent, QGuardLiveStatus } from "@/lib/live-sse";
import { describeSavedFile, saveFileToDevice } from "@/lib/save-file";
import { supabase } from "@/lib/supabase";
import { safeInvoke } from "@/lib/tauri";
import type { SecurityEvent, TelemetryEvent, TrustedDevice } from "@/lib/types";
import { sha3_256Hex } from "@/lib/sha3";
import { summarizeContactDeviceProtection } from "@/lib/pq-status";

interface AuditLogsPageProps {
  userId: string;
  /** Every device row visible to this account; the report summarizes contacts' ones. */
  devices: TrustedDevice[];
  events: TelemetryEvent[];
  securityEvents: SecurityEvent[];
  liveEvents: QGuardLiveEvent[];
  liveStatus: QGuardLiveStatus;
  onRefresh: () => void | Promise<void>;
}

type StatusState = {
  tone: "success" | "warning" | "error" | "info";
  message: string;
} | null;

type AuditSource = "Telemetry" | "Security" | "Realtime";

interface AuditRow {
  id: string;
  rawId: string;
  source: AuditSource;
  stage: string;
  detail: string;
  progress: string;
  integrity: string;
  created_at: string;
  severity?: SecurityEvent["severity"];
  table?: string;
  event?: string;
}

const statusAlertTone = {
  success: "border-emerald-200 bg-emerald-50 text-emerald-700",
  warning: "border-amber-200 bg-amber-50 text-amber-700",
  error: "border-rose-200 bg-rose-50 text-rose-600",
  info: "border-cyan-200 bg-cyan-50 text-cyan-700",
};

function describeDataError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  const candidate = error as { message?: string; details?: string; hint?: string; code?: string };
  return [candidate.message, candidate.details, candidate.hint, candidate.code].filter(Boolean).join(" ") || "Audit operation failed.";
}

function cleanLabel(value: string): string {
  return value.replace(/_/g, " ");
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

function clampPercent(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function liveTone(state: QGuardLiveStatus["state"]): string {
  if (state === "live") return "bg-emerald-50 text-emerald-600";
  if (state === "connecting") return "bg-amber-50 text-amber-600";
  if (state === "fallback") return "bg-cyan-50 text-cyan-700";
  return "bg-rose-50 text-rose-600";
}

function textTone(value: string): string {
  if (/critical|failed|tampered|error|revoked|broken/i.test(value)) return "text-rose-500";
  if (/warning|fallback|connecting|head|partial|review/i.test(value)) return "text-amber-600";
  return "text-emerald-600";
}

function sourceTone(source: AuditSource): string {
  if (source === "Security") return "bg-violet-50 text-violet-600";
  if (source === "Realtime") return "bg-cyan-50 text-cyan-700";
  return "bg-emerald-50 text-emerald-600";
}

function integrityTone(row: AuditRow): string {
  if (row.severity === "critical") return "text-rose-500";
  if (row.severity === "warning" || /head|live/i.test(row.integrity)) return "text-amber-600";
  return "text-emerald-600";
}


const AUDIT_PAGE_SIZE = 5;

// Only persisted, user-owned sources can be deleted. Realtime rows are ephemeral
// in-memory SSE events with no backing row, so they are intentionally omitted.
const auditDeleteTables: Partial<Record<AuditSource, "messaging_crypto_telemetry" | "messaging_security_events">> = {
  Telemetry: "messaging_crypto_telemetry",
  Security: "messaging_security_events",
};

// Compact, windowed page list (e.g. 1 … 4 5 6 … 24) so a long log never renders
// dozens of page buttons.
function pageWindow(current: number, total: number): Array<number | "ellipsis"> {
  if (total <= 7) return Array.from({ length: total }, (_, index) => index + 1);
  const wanted = [1, current - 1, current, current + 1, total].filter((page) => page >= 1 && page <= total);
  const unique = Array.from(new Set(wanted)).sort((a, b) => a - b);
  const items: Array<number | "ellipsis"> = [];
  let previous = 0;
  for (const page of unique) {
    if (page - previous > 1) items.push("ellipsis");
    items.push(page);
    previous = page;
  }
  return items;
}

export default function AuditLogsPage({ userId, devices, events, securityEvents, liveEvents, liveStatus, onRefresh }: AuditLogsPageProps) {
  const isAdmin = useIsAdmin();
  const [exporting, setExporting] = useState(false);
  const [status, setStatus] = useState<StatusState>(null);

  const rows = useMemo<AuditRow[]>(() => [
    ...events.map((event) => ({
      id: `telemetry-${event.id}`,
      rawId: event.id,
      source: "Telemetry" as const,
      stage: event.stage,
      detail: event.detail,
      progress: `${clampPercent(event.progress)}%`,
      integrity: event.progress >= 100 ? "Telemetry sealed" : "Telemetry pending",
      created_at: event.created_at,
    })),
    ...securityEvents.map((event) => ({
      id: `security-${event.id}`,
      rawId: event.id,
      source: "Security" as const,
      stage: event.event_type,
      detail: event.event_hash,
      progress: "100%",
      integrity: event.previous_hash ? "Hash chained" : "Chain head",
      created_at: event.created_at,
      severity: event.severity,
    })),
    ...liveEvents.slice(0, 50).map((event) => ({
      id: `live-${event.id}`,
      rawId: event.id,
      source: "Realtime" as const,
      stage: event.table,
      detail: event.detail,
      progress: event.event.toLowerCase(),
      integrity: "Live SSE",
      created_at: event.at,
      table: event.table,
      event: event.event,
    })),
  ].sort((a, b) => sortTime(b.created_at) - sortTime(a.created_at)).slice(0, 120), [events, liveEvents, securityEvents]);

  const latestAuditAt = latestIso([
    liveStatus.lastEventAt,
    events[0]?.created_at,
    securityEvents[0]?.created_at,
    liveEvents[0]?.at,
  ]);
  const criticalEvents = securityEvents.filter((event) => event.severity === "critical").length;
  const warningEvents = securityEvents.filter((event) => event.severity === "warning").length;
  const chainedEvents = securityEvents.filter((event) => event.previous_hash).length;
  const completedTelemetry = events.filter((event) => event.progress >= 100).length;
  const chainLabel = securityEvents.length > 0 ? `${chainedEvents}/${securityEvents.length}` : "0/0";
  const integrityPosture = criticalEvents > 0 ? "Review Critical" : warningEvents > 0 ? "Review Warnings" : "Protected";
  const backendEvents = liveEvents.slice(0, 5);
  const latestTelemetry = events.slice(0, 5);
  const latestSecurity = securityEvents.slice(0, 5);

  const [page, setPage] = useState(1);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const totalPages = Math.max(1, Math.ceil(rows.length / AUDIT_PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  useEffect(() => {
    // Keep the page in range as rows shrink (e.g. after a delete).
    if (page !== currentPage) setPage(currentPage);
  }, [page, currentPage]);
  const pageStart = (currentPage - 1) * AUDIT_PAGE_SIZE;
  const pageRows = rows.slice(pageStart, pageStart + AUDIT_PAGE_SIZE);

  async function recordAuditTelemetry(stage: string, detail: string, progress: number, statusValue: "started" | "progress" | "verified" | "failed" | "complete") {
    await recordCryptoTelemetry({
      userId,
      scope: "message",
      stage,
      detail,
      progress,
      status: statusValue,
      metadata: {
        module: "message_audit_logs",
        live_state: liveStatus.state,
      },
    });
  }

  async function logAuditSecurityEvent(
    eventType: string,
    severity: SecurityEvent["severity"],
    metadata: Record<string, string | number | boolean | null>,
  ) {
    try {
      const createdAt = new Date().toISOString();
      const eventHash = sha3_256Hex(JSON.stringify({ eventType, severity, metadata, createdAt }));
      await supabase.from("messaging_security_events").insert({
        user_id: userId,
        device_id: null,
        event_type: eventType,
        severity,
        encrypted_details: await securityEventDetails(eventHash, metadata),
        event_hash: eventHash,
      });
    } catch {
      // Export auditing should never block the user from getting their report.
    }
  }

  function buildAuditReport(reportId: string, desktopReport: Record<string, unknown> | null) {
    return {
      report_id: reportId,
      generated_at: new Date().toISOString(),
      user_id: userId,
      live_status: liveStatus,
      summary: {
        rows: rows.length,
        telemetry_events: events.length,
        completed_telemetry: completedTelemetry,
        security_events: securityEvents.length,
        warning_events: warningEvents,
        critical_events: criticalEvents,
        chained_security_events: chainedEvents,
        live_events: liveEvents.length,
        integrity_posture: integrityPosture,
      },
      // From the suites contacts' trusted devices published: the form the next
      // message to each would be sealed with. Device counts, not conversations.
      contact_device_protection: summarizeContactDeviceProtection(
        devices.filter((device) => device.trust_state === "ThisDevice" || device.trust_state === "Trusted"),
        userId,
      ),
      telemetry: events.map((event) => ({
        id: event.id,
        stage: event.stage,
        detail: event.detail,
        progress: clampPercent(event.progress),
        created_at: event.created_at,
      })),
      security_events: securityEvents.map((event) => ({
        id: event.id,
        event_type: event.event_type,
        severity: event.severity,
        event_hash: event.event_hash,
        previous_hash: event.previous_hash,
        created_at: event.created_at,
      })),
      live_events: liveEvents.map((event) => ({
        id: event.id,
        at: event.at,
        table: event.table,
        event: event.event,
        detail: event.detail,
      })),
      desktop_report: desktopReport,
    };
  }

  async function exportReport() {
    const reportId = crypto.randomUUID();
    setExporting(true);
    setStatus({ tone: "info", message: "Preparing signed audit export..." });
    try {
      await recordAuditTelemetry("audit_export_started", "Security report export requested", 10, "started");
      const desktopReport = await safeInvoke<Record<string, unknown> | null>("security_export_report", undefined, null);
      const report = buildAuditReport(reportId, desktopReport);
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const saved = await saveFileToDevice(
        `qguard-security-report-${new Date().toISOString().replace(/[:.]/g, "-")}.json`,
        blob,
      );
      await logAuditSecurityEvent("audit_report_exported", "info", {
        report_id: reportId,
        rows: rows.length,
        desktop_report: Boolean(desktopReport),
      });
      await recordAuditTelemetry("audit_export_complete", `Exported ${rows.length} audit rows`, 100, "complete");
      setStatus({ tone: "success", message: `${desktopReport ? "Security report exported with desktop attestation." : "Security report exported from current live audit state."} ${describeSavedFile(saved)}.` });
      await Promise.resolve(onRefresh());
    } catch (error) {
      const message = describeDataError(error);
      setStatus({ tone: "error", message });
      await recordAuditTelemetry("audit_export_failed", message, 100, "failed");
    } finally {
      setExporting(false);
    }
  }

  function refreshAuditLogs() {
    void (async () => {
      setStatus({ tone: "info", message: "Refreshing audit stream..." });
      try {
        await Promise.resolve(onRefresh());
        await recordAuditTelemetry("audit_stream_refreshed", "Audit logs refreshed from live backend state", 100, "complete");
        setStatus({ tone: "success", message: "Audit stream refreshed from live backend state." });
      } catch (error) {
        setStatus({ tone: "error", message: describeDataError(error) });
      }
    })();
  }

  async function deleteAuditRow(row: AuditRow) {
    const table = auditDeleteTables[row.source];
    if (!table) return;
    setDeletingId(row.id);
    setStatus({ tone: "info", message: "Deleting audit record..." });
    try {
      // RLS already scopes deletes to the owner; the explicit user_id filter is
      // defense-in-depth so a record can never be removed outside the session user.
      const { error } = await supabase.from(table).delete().eq("id", row.rawId).eq("user_id", userId);
      if (error) throw error;
      setConfirmDeleteId(null);
      setStatus({ tone: "success", message: "Audit record deleted." });
      await Promise.resolve(onRefresh());
    } catch (error) {
      setStatus({ tone: "error", message: describeDataError(error) });
    } finally {
      setDeletingId(null);
    }
  }

  return (
    // grid-cols-[minmax(0,1fr)]: without an explicit track, the wide audit table
    // (min-w inside its scroller) inflates the implicit column past a phone
    // viewport and drags EVERY card with it — the whole page pans sideways
    // instead of the table scrolling inside its own card.
    <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
      <div className="grid gap-4 lg:grid-cols-4">
        <section className="shell-card p-4">
          <ShieldCheck className="text-emerald-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Integrity Posture</div>
          <div className={`mt-1 text-sm font-semibold ${textTone(integrityPosture)}`}>{integrityPosture}</div>
          <div className="mt-1 text-xs text-ink-500">{criticalEvents} critical events</div>
        </section>
        <section className="shell-card p-4">
          <Activity className="text-violet-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Telemetry Rows</div>
          <div className="mt-1 text-sm font-semibold text-emerald-600">{events.length}</div>
          <div className="mt-1 text-xs text-ink-500">{completedTelemetry} completed operations</div>
        </section>
        <section className="shell-card p-4">
          <FileText className="text-cyan-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Hash Chain</div>
          <div className={`mt-1 text-sm font-semibold ${securityEvents.length > 0 ? "text-emerald-600" : "text-amber-600"}`}>{chainLabel} chained</div>
          <div className="mt-1 text-xs text-ink-500">{warningEvents} warnings</div>
        </section>
        <section className="shell-card p-4">
          <Radio className={liveStatus.state === "live" ? "text-emerald-600" : "text-amber-600"} size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Realtime Stream</div>
          <div className={`mt-1 text-sm font-semibold ${textTone(liveStatus.state)}`}>{liveStatus.state}</div>
          <div className="mt-1 truncate text-xs text-ink-500">{relativeTime(latestAuditAt)}</div>
        </section>
      </div>

      {isAdmin && (
      <section className="shell-card p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-ink-950">Realtime Audit Fabric</h2>
            <div className="mt-1 text-xs text-ink-600">Audit state refreshed {relativeTime(latestAuditAt)}</div>
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
            <div className="text-[11px] font-bold uppercase text-ink-400">Merged Rows</div>
            <div className="mt-1 text-sm font-semibold text-ink-950">{rows.length} audit records</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">SSE Events</div>
            <div className="mt-1 text-sm font-semibold text-ink-950">{liveEvents.length} buffered</div>
          </div>
        </div>

        <div className="mt-4 grid gap-6 xl:grid-cols-3">
          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-ink-400">
              <Database size={14} />
              Backend Events
            </div>
            {backendEvents.length === 0 && (
              <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">Live stream connected. No backend audit changes received yet.</div>
            )}
            <div className="space-y-2">
              {backendEvents.map((event) => (
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
            {latestTelemetry.length === 0 && (
              <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">No crypto telemetry yet.</div>
            )}
            <div className="space-y-2">
              {latestTelemetry.map((event) => (
                <div key={event.id} className="flex items-center gap-3 border-t border-line pt-2 first:border-t-0 first:pt-0">
                  <span className={`status-pill shrink-0 ${event.progress >= 100 ? "bg-emerald-50 text-emerald-600" : "bg-amber-50 text-amber-600"}`}>{clampPercent(event.progress)}%</span>
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
              Security Chain
            </div>
            {latestSecurity.length === 0 && (
              <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">No security events yet.</div>
            )}
            <div className="space-y-2">
              {latestSecurity.map((event) => (
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

      <section className="shell-card overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line p-4">
          <div className="flex items-center gap-2">
            <Activity className="text-violet-600" size={20} />
            <h2 className="text-sm font-bold text-ink-950">Message Audit Logs</h2>
          </div>
          <div className="flex flex-wrap gap-2">
            <button disabled={exporting} onClick={refreshAuditLogs} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm font-bold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50">
              <Clock3 size={16} />
              Refresh
            </button>
            <button disabled={exporting} onClick={exportReport} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm font-bold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50">
              {exporting ? <Loader2 className="animate-spin" size={16} /> : <Download size={16} />}
              {exporting ? "Exporting" : "Export Security Report"}
            </button>
          </div>
        </div>

        {status && (
          <div className={`border-b border-line px-4 py-2 text-xs font-semibold ${statusAlertTone[status.tone]}`}>
            {status.message}
          </div>
        )}

        <div className="overflow-x-auto">
          {/* Below lg the 7-column table reflows to a stacked card per event
              (labeled metadata lines) so a phone shows every field without
              sideways scrolling; at lg+ it is the column table. */}
          <div className="lg:min-w-[1080px]">
            <div className="hidden border-b border-line bg-canvas px-4 py-3 text-xs font-bold uppercase tracking-wide text-ink-400 lg:grid lg:grid-cols-[120px_190px_1fr_110px_140px_90px_96px]">
              <span>Source</span>
              <span>Stage</span>
              <span>Detail</span>
              <span>Progress</span>
              <span>Integrity</span>
              <span>Age</span>
              <span className="text-right">Actions</span>
            </div>
            {rows.length === 0 && (
              <div className="p-6 text-center text-sm text-ink-600">No security events are available for this user.</div>
            )}
            {pageRows.map((event) => (
              <div key={event.id} className="flex flex-col gap-1.5 border-b border-line px-4 py-3 text-sm lg:grid lg:grid-cols-[120px_190px_1fr_110px_140px_90px_96px] lg:gap-0">
                <span className="flex items-center justify-between gap-2 lg:block">
                  <span className={`status-pill ${sourceTone(event.source)}`}>{event.source}</span>
                  <span className="text-xs text-ink-400 lg:hidden">{relativeTime(event.created_at)}</span>
                </span>
                <span className="font-semibold text-ink-950 lg:truncate">{cleanLabel(event.stage)}</span>
                <span className="text-ink-600 lg:truncate">{event.detail}</span>
                <span className={event.source === "Realtime" ? "text-cyan-700" : "text-violet-600"}>
                  <span className="font-semibold text-ink-400 lg:hidden">Progress: </span>{event.progress}
                </span>
                <span className={`flex items-center gap-1 ${integrityTone(event)}`}>
                  <ShieldCheck size={14} />
                  {event.integrity}
                </span>
                <span className="hidden text-xs text-ink-400 lg:block">{relativeTime(event.created_at)}</span>
                <span className="flex items-center justify-start lg:justify-end">
                  {!auditDeleteTables[event.source] ? (
                    <span className="text-[11px] text-ink-300">Live</span>
                  ) : deletingId === event.id ? (
                    <Loader2 className="animate-spin text-ink-400" size={16} />
                  ) : confirmDeleteId === event.id ? (
                    <span className="flex items-center gap-1">
                      <button
                        type="button"
                        onClick={() => deleteAuditRow(event)}
                        title="Confirm delete"
                        className="rounded-md bg-rose-50 p-1.5 text-rose-600 hover:bg-rose-100"
                      >
                        <Check size={14} />
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirmDeleteId(null)}
                        title="Cancel"
                        className="rounded-md border border-line p-1.5 text-ink-500 hover:bg-canvas"
                      >
                        <X size={14} />
                      </button>
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setConfirmDeleteId(event.id)}
                      title="Delete record"
                      className="rounded-md border border-line p-1.5 text-ink-500 transition hover:border-rose-200 hover:text-rose-600"
                    >
                      <Trash2 size={14} />
                    </button>
                  )}
                </span>
              </div>
            ))}
          </div>
        </div>

        {rows.length > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line p-3">
            <div className="text-xs text-ink-500">
              Showing {pageStart + 1}-{Math.min(pageStart + AUDIT_PAGE_SIZE, rows.length)} of {rows.length}
            </div>
            {totalPages > 1 && (
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => setPage(currentPage - 1)}
                  disabled={currentPage === 1}
                  className="rounded-md border border-line px-2 py-1 text-xs font-semibold text-ink-600 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Prev
                </button>
                {pageWindow(currentPage, totalPages).map((item, index) =>
                  item === "ellipsis" ? (
                    <span key={`gap-${index}`} className="px-1 text-xs text-ink-400">…</span>
                  ) : (
                    <button
                      type="button"
                      key={item}
                      onClick={() => setPage(item)}
                      className={`min-w-[28px] rounded-md border px-2 py-1 text-xs font-semibold ${item === currentPage ? "border-violet-300 bg-violet-50 text-violet-700" : "border-line text-ink-600 hover:bg-canvas"}`}
                    >
                      {item}
                    </button>
                  ),
                )}
                <button
                  type="button"
                  onClick={() => setPage(currentPage + 1)}
                  disabled={currentPage === totalPages}
                  className="rounded-md border border-line px-2 py-1 text-xs font-semibold text-ink-600 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            )}
          </div>
        )}

        {securityEvents.length > 0 && (
          <div className="border-t border-line bg-canvas p-3 text-xs font-semibold text-ink-600">
            Security events are hash-chained for tamper-evidence, and their details remain encrypted on your device.
          </div>
        )}
      </section>

      {(criticalEvents > 0 || warningEvents > 0) && (
        <section className="shell-card border-amber-200 bg-amber-50 p-4">
          <div className="flex items-center gap-2 text-sm font-bold text-amber-700">
            <AlertTriangle size={18} />
            Audit Review Queue
          </div>
          <div className="mt-1 text-sm text-amber-700">{criticalEvents} critical and {warningEvents} warning events are present in the current user-scoped audit window.</div>
        </section>
      )}
    </div>
  );
}
