'use client';

/**
 * Exposure Assessment History — the History tab for Local and Dev mode.
 *
 * Mounted by `/dashboard/scanner?mode=local&view=history` and `?mode=dev&view=history`.
 *
 * WHAT MAKES THIS TAB TRUSTWORTHY, and what a future change must not break:
 *
 *  • **The detail view renders the SAME components the live results do.** A
 *    recorded assessment is rehydrated into an `ExposureAssessment` on the
 *    server and handed to `ExposureScorecard`, `FindingExplorer`, `CbomViewer`
 *    and the rest. There is no second set of "history" panels that could come to
 *    disagree with the live ones about the same evidence.
 *
 *  • **Every number is counted, never estimated.** The list rows carry the
 *    counts the server derived from the rows that really exist for each scan, so
 *    the list total and the detail total are the same number by construction.
 *
 *  • **An empty panel says why it is empty.** "Not retained" and "nothing
 *    recorded" are rendered as different states, and a failed read is rendered
 *    as a failure — never as a clean, empty history.
 */

import React from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  AlertTriangle,
  ArrowLeft,
  Boxes,
  ChevronRight,
  Clock,
  Database,
  Download,
  FileWarning,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Radio,
  X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { ACCENT, Panel, SectionLabel } from '@/components/quantum-scan/ui';
import { useExposureHistory, type ExposureHistoryDetail } from '@/hooks/use-exposure-history';
import { ExposureReportButton, type ExposureReportAuthor } from './ExposureReportLauncher';
import { exposureRecordFromProvenance } from '@/services/reporting/ExposureReport';
import type { ExposureHistoryEntry, ExposureHistoryMode } from '@/lib/scanner/exposure/history';
import type { FindingSeverity } from '@/lib/scanner/exposure/types';
import { cbomToCsv, cbomToCycloneDx, cbomToJson } from '@/lib/scanner/exposure/cbom';
import {
  CbomViewer,
  CorrelatedExposures,
  CoveragePanel,
  EngineLedger,
  ExposureRecommendations,
  ExposureScorecard,
  FindingExplorer,
  ListTruncationNote,
  QuantumExposureSummary,
  SEVERITY_COLOR,
} from './shared';
import { ScannerIntelligenceSection } from './ScannerIntelligence';
import { ExposureWorkflowGraph } from './ExposureWorkflowGraph';

/* ────────────────────────────────────────────────────────────── formatting ── */

const SEVERITY_ORDER: readonly FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—';
  const at = Date.parse(value);
  if (!Number.isFinite(at)) return '—';
  return new Date(at).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function formatRelative(value: string | null | undefined): string {
  if (!value) return '';
  const at = Date.parse(value);
  if (!Number.isFinite(at)) return '';
  const seconds = Math.max(0, Math.round((Date.now() - at) / 1000));
  if (seconds < 60) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 31) return `${days}d ago`;
  return new Date(at).toLocaleDateString();
}

function formatDuration(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms) || ms < 0) return '—';
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  if (minutes < 60) return rest === 0 ? `${minutes}m` : `${minutes}m ${rest}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

function downloadBlob(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

const STATUS_TONE: Record<string, { color: string; label: string }> = {
  completed: { color: ACCENT.emerald, label: 'Completed' },
  partial: { color: ACCENT.amber, label: 'Completed with gaps' },
  failed: { color: ACCENT.rose, label: 'Failed' },
  cancelled: { color: ACCENT.slate, label: 'Cancelled' },
  queued: { color: ACCENT.blue, label: 'Queued' },
  initializing: { color: ACCENT.blue, label: 'Initializing' },
  discovering: { color: ACCENT.cyan, label: 'Discovering' },
  analyzing: { color: ACCENT.cyan, label: 'Analyzing' },
  correlating: { color: ACCENT.violet, label: 'Correlating' },
  scoring: { color: ACCENT.violet, label: 'Scoring' },
};

function statusTone(status: string) {
  return STATUS_TONE[status] ?? { color: ACCENT.slate, label: status };
}

/* ═══════════════════════════════════════════════════════════════ the panel ══ */

export interface ExposureHistoryPanelProps {
  mode: ExposureHistoryMode;
  /** False while the tab is hidden, so a closed tab holds no SSE connection. */
  active?: boolean;
  /** Take the operator back to the assessment surface to run a new scan. */
  onStartAssessment?: () => void;
  /**
   * When set, a recorded assessment can be reported on, with this author on the
   * cover. The report declares the record's own provenance — which fields were
   * read back, which were recomputed and which the record never held.
   */
  reports?: ExposureReportAuthor;
}

export function ExposureHistoryPanel({ mode, active = true, onStartAssessment, reports }: ExposureHistoryPanelProps) {
  const history = useExposureHistory(mode, { enabled: active });

  const [query, setQuery] = React.useState('');
  const [statusFilter, setStatusFilter] = React.useState<string | null>(null);
  const [originFilter, setOriginFilter] = React.useState<'all' | 'recorded' | 'session'>('all');
  const [openScanId, setOpenScanId] = React.useState<string | null>(null);
  const [detail, setDetail] = React.useState<ExposureHistoryDetail | null>(null);
  const [pendingDelete, setPendingDelete] = React.useState<ExposureHistoryEntry | null>(null);
  const [deleting, setDeleting] = React.useState(false);
  const [deleteError, setDeleteError] = React.useState<string | null>(null);

  const { entries } = history;

  /* ── filtering ────────────────────────────────────────────────────────── */
  const filtered = React.useMemo(() => {
    const needle = query.trim().toLowerCase();
    return entries.filter((entry) => {
      if (originFilter !== 'all' && entry.origin !== originFilter) return false;
      if (statusFilter && entry.status !== statusFilter) return false;
      if (!needle) return true;
      return (
        entry.target.toLowerCase().includes(needle) ||
        entry.profileId.toLowerCase().includes(needle) ||
        entry.scanId.toLowerCase().includes(needle) ||
        entry.engines.some((engine) => engine.toLowerCase().includes(needle))
      );
    });
  }, [entries, query, statusFilter, originFilter]);

  /* Status chips are built from what is actually present, and each carries the
     count it will produce — a facet that offers a filter yielding nothing is a
     defect this platform has fixed before. */
  const statusFacets = React.useMemo(() => {
    const counts = new Map<string, number>();
    for (const entry of entries) {
      if (originFilter !== 'all' && entry.origin !== originFilter) continue;
      counts.set(entry.status, (counts.get(entry.status) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [entries, originFilter]);

  /**
   * The previous recorded assessment of the SAME target, per entry.
   *
   * The delta shown on a row is a comparison of like with like: comparing a
   * repository against an unrelated cluster would produce a number that means
   * nothing. Entries arrive newest-first, so the next entry with the same target
   * is the one before it in time.
   */
  const previousByScanId = React.useMemo(() => {
    const map = new Map<string, ExposureHistoryEntry>();
    const seen = new Map<string, ExposureHistoryEntry>();
    const chronological = [...entries].sort((a, b) => Date.parse(a.startedAt) - Date.parse(b.startedAt));
    for (const entry of chronological) {
      const previous = seen.get(entry.target);
      if (previous) map.set(entry.scanId, previous);
      seen.set(entry.target, entry);
    }
    return map;
  }, [entries]);

  /* ── detail ───────────────────────────────────────────────────────────── */
  const openDetail = React.useCallback(
    async (scanId: string) => {
      setOpenScanId(scanId);
      setDetail(null);
      const loaded = await history.loadDetail(scanId);
      setDetail(loaded);
    },
    [history],
  );

  const closeDetail = React.useCallback(() => {
    setOpenScanId(null);
    setDetail(null);
  }, []);

  const confirmDelete = React.useCallback(async () => {
    if (!pendingDelete) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await history.remove(pendingDelete.scanId);
      if (openScanId === pendingDelete.scanId) closeDetail();
      setPendingDelete(null);
    } catch (error) {
      setDeleteError((error as Error).message);
    } finally {
      setDeleting(false);
    }
  }, [pendingDelete, history, openScanId, closeDetail]);

  const openEntry = openScanId ? entries.find((entry) => entry.scanId === openScanId) ?? null : null;

  return (
    <div className="space-y-5">
      <HistoryHeader
        mode={mode}
        streamOpen={history.streamOpen}
        generatedAt={history.generatedAt}
        loading={history.loading}
        onRefresh={() => void history.refresh()}
      />

      {history.error && (
        <Panel className="border-rose-400/25 bg-rose-500/[0.05]">
          <div className="flex items-start gap-3 px-5 py-3.5">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
            <div className="min-w-0">
              <p className="text-[12.5px] font-bold text-rose-100">The assessment history could not be read</p>
              <p className="mt-1 text-[11.5px] leading-relaxed text-rose-100/75">{history.error}</p>
              <p className="mt-1.5 text-[11.5px] leading-relaxed text-rose-100/60">
                Nothing below is a statement about your estate while this is showing — the list is not an empty history,
                it is an unread one.
              </p>
            </div>
          </div>
        </Panel>
      )}

      <AnimatePresence mode="wait" initial={false}>
        {openScanId ? (
          <motion.div
            key="detail"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.22 }}
            className="space-y-5"
          >
            <HistoryDetailView
              mode={mode}
              entry={openEntry}
              detail={detail}
              previous={openEntry ? previousByScanId.get(openEntry.scanId) ?? null : null}
              loading={history.detailState.loading && history.detailState.scanId === openScanId}
              error={history.detailState.scanId === openScanId ? history.detailState.error : null}
              onBack={closeDetail}
              onDelete={(entry) => setPendingDelete(entry)}
              onRetry={() => void openDetail(openScanId)}
              reports={reports}
            />
          </motion.div>
        ) : (
          <motion.div
            key="list"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.22 }}
            className="space-y-5"
          >
            <HistoryKpis summary={history.summary} mode={mode} />

            <PostureTrend entries={entries} />

            {history.notes.length > 0 && (
              <Panel className="overflow-hidden border-cyan-400/12">
                <ul className="space-y-1.5 px-5 py-3.5">
                  {history.notes.map((note) => (
                    <li key={note} className="flex items-start gap-2 text-[11.5px] leading-relaxed text-slate-400">
                      <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-cyan-400/60" />
                      <span>{note}</span>
                    </li>
                  ))}
                </ul>
              </Panel>
            )}

            <Panel className="overflow-hidden">
              <HistoryFilters
                query={query}
                onQuery={setQuery}
                statusFacets={statusFacets}
                statusFilter={statusFilter}
                onStatus={setStatusFilter}
                originFilter={originFilter}
                onOrigin={setOriginFilter}
                shown={filtered.length}
                total={entries.length}
                hasSession={entries.some((entry) => entry.origin === 'session')}
              />

              {history.loading && entries.length === 0 ? (
                <HistoryLoading />
              ) : filtered.length === 0 ? (
                <HistoryEmpty
                  mode={mode}
                  filtered={entries.length > 0}
                  /* The read failed, so this list is UNREAD, not empty. Saying
                     "no assessment recorded yet" underneath a failure banner
                     would contradict it, and the reassuring half is the half a
                     reader remembers. */
                  unread={Boolean(history.error) && entries.length === 0}
                  onClear={() => {
                    setQuery('');
                    setStatusFilter(null);
                    setOriginFilter('all');
                  }}
                  onRetry={() => void history.refresh()}
                  onStartAssessment={onStartAssessment}
                />
              ) : (
                <>
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[68rem] border-collapse text-left">
                      <thead>
                        <tr className="border-b border-white/[0.06]">
                          {['Assessment', 'Started', 'Status', 'Findings', 'Components', 'Quantum readiness', 'Change', ''].map(
                            (label) => (
                              <th
                                key={label || 'actions'}
                                className="px-4 py-2.5 font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500"
                              >
                                {label}
                              </th>
                            ),
                          )}
                        </tr>
                      </thead>
                      <tbody>
                        {filtered.map((entry) => (
                          <HistoryRow
                            key={entry.scanId}
                            entry={entry}
                            previous={previousByScanId.get(entry.scanId) ?? null}
                            onOpen={() => void openDetail(entry.scanId)}
                            onDelete={() => setPendingDelete(entry)}
                          />
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <ListTruncationNote
                    shown={entries.filter((entry) => entry.origin === 'recorded').length}
                    total={history.total}
                    noun="recorded assessments"
                    rank="most recent"
                  />
                </>
              )}
            </Panel>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {pendingDelete && (
          <DeleteDialog
            entry={pendingDelete}
            deleting={deleting}
            error={deleteError}
            onCancel={() => {
              setPendingDelete(null);
              setDeleteError(null);
            }}
            onConfirm={() => void confirmDelete()}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────── header ── */

function HistoryHeader({
  mode,
  streamOpen,
  generatedAt,
  loading,
  onRefresh,
}: {
  mode: ExposureHistoryMode;
  streamOpen: boolean;
  generatedAt: string | null;
  loading: boolean;
  onRefresh: () => void;
}) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4">
        <div className="flex min-w-0 items-start gap-3">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-cyan-400/25 bg-cyan-400/[0.08] text-cyan-300">
            <Database className="h-4.5 w-4.5" />
          </span>
          <div className="min-w-0">
            <h3 className="text-[14px] font-black text-white">Assessment History</h3>
            <p className="mt-1 text-[12px] leading-relaxed text-slate-400">
              Every {mode === 'local' ? 'Local' : 'Development'} assessment recorded to this tenant, with the findings and
              cryptographic components each one produced. Opening an assessment rebuilds it from its own rows — the same
              evidence, through the same panels, as the day it ran.
            </p>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <span
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 font-mono text-[10px] font-bold uppercase tracking-[0.14em]',
              streamOpen
                ? 'border-emerald-400/25 bg-emerald-400/[0.07] text-emerald-300'
                : 'border-white/[0.08] bg-white/[0.02] text-slate-500',
            )}
            title={
              streamOpen
                ? 'Connected to the live history stream. New assessments appear here as they are recorded.'
                : 'Not connected to the live stream. Use Refresh to re-read the history.'
            }
          >
            <Radio className={cn('h-3 w-3', streamOpen && 'animate-pulse')} />
            {streamOpen ? 'Live' : 'Offline'}
          </span>
          <button
            type="button"
            onClick={onRefresh}
            disabled={loading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11.5px] font-semibold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300 disabled:opacity-50"
          >
            {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            Refresh
          </button>
        </div>
      </div>
      {generatedAt && (
        <p className="border-t border-white/[0.06] px-5 py-2 font-mono text-[10px] text-slate-500">
          Snapshot produced {formatRelative(generatedAt)} · {formatDateTime(generatedAt)}
        </p>
      )}
    </Panel>
  );
}

/* ──────────────────────────────────────────────────────────────────── kpis ── */

function HistoryKpis({
  summary,
  mode,
}: {
  summary: ReturnType<typeof useExposureHistory>['summary'];
  mode: ExposureHistoryMode;
}) {
  if (!summary) return null;

  const tiles: Array<{ label: string; value: string; detail: string; accent: string }> = [
    {
      label: 'Recorded assessments',
      value: String(summary.recorded),
      detail: summary.session > 0 ? `${summary.session} held in session only` : 'All assessments are recorded',
      accent: ACCENT.cyan,
    },
    {
      label: 'Targets assessed',
      value: String(summary.targets),
      detail: summary.lastAt ? `Most recent ${formatRelative(summary.lastAt)}` : 'No assessment recorded yet',
      accent: ACCENT.blue,
    },
    {
      label: 'Findings recorded',
      value: summary.findings.toLocaleString(),
      detail: `${summary.severity.critical} critical · ${summary.severity.high} high`,
      accent: summary.severity.critical > 0 ? ACCENT.rose : ACCENT.slate,
    },
    {
      label: 'Cryptographic components',
      value: summary.components.toLocaleString(),
      detail: 'Counted as components, never as findings',
      accent: ACCENT.violet,
    },
    {
      label: 'Quantum-vulnerable components',
      value: summary.quantumVulnerableComponents.toLocaleString(),
      detail:
        summary.components > 0
          ? `${Math.round((summary.quantumVulnerableComponents / summary.components) * 1000) / 10}% of recorded components`
          : 'No component recorded yet',
      accent: summary.quantumVulnerableComponents > 0 ? ACCENT.rose : ACCENT.emerald,
    },
    {
      label: 'Latest quantum readiness',
      value: summary.latestReadiness === null ? 'Not measured' : `${Math.round(summary.latestReadiness)}%`,
      detail:
        summary.latestReadiness === null
          ? 'No recorded assessment measured a cryptographic component'
          : 'From the most recent assessment that measured components',
      accent: ACCENT.emerald,
    },
  ];

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
      {tiles.map((tile) => (
        <Panel key={tile.label} className="overflow-hidden">
          <div className="px-4 py-3.5">
            <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-slate-500">{tile.label}</p>
            <p className="mt-2 text-[22px] font-black leading-none" style={{ color: tile.accent }}>
              {tile.value}
            </p>
            <p className="mt-2 text-[10.5px] leading-relaxed text-slate-500">{tile.detail}</p>
          </div>
        </Panel>
      ))}
      <span className="sr-only">
        {mode === 'local' ? 'Local' : 'Development'} assessment history totals, counted from recorded rows.
      </span>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── trend ── */

/**
 * Posture over the recorded assessments.
 *
 * One point per assessment that HAS the value — an assessment which never
 * measured a cryptographic component contributes no readiness point rather than
 * a zero, because a zero here reads as "nothing is ready" instead of "nothing
 * was measured".
 */
function PostureTrend({ entries }: { entries: ExposureHistoryEntry[] }) {
  const points = React.useMemo(
    () =>
      [...entries]
        .filter((entry) => entry.origin === 'recorded')
        .sort((a, b) => Date.parse(a.startedAt) - Date.parse(b.startedAt))
        .slice(-24)
        .map((entry) => ({
          scanId: entry.scanId,
          at: entry.startedAt,
          target: entry.target,
          risk: entry.scores?.securityRisk ?? null,
          readiness: entry.quantumReadiness,
          findings: entry.findingCount,
        })),
    [entries],
  );

  const riskPoints = points.filter((point) => point.risk !== null);
  const readinessPoints = points.filter((point) => point.readiness !== null);

  if (points.length < 2 || (riskPoints.length < 2 && readinessPoints.length < 2)) return null;

  const width = 100;
  const height = 34;
  const xFor = (index: number) => (points.length === 1 ? 0 : (index / (points.length - 1)) * width);
  const yFor = (value: number) => height - (Math.max(0, Math.min(100, value)) / 100) * height;

  const pathFor = (series: Array<{ value: number; index: number }>) =>
    series.map((entry, position) => `${position === 0 ? 'M' : 'L'}${xFor(entry.index).toFixed(2)},${yFor(entry.value).toFixed(2)}`).join(' ');

  const riskSeries = points
    .map((point, index) => ({ value: point.risk, index }))
    .filter((entry): entry is { value: number; index: number } => entry.value !== null);
  const readinessSeries = points
    .map((point, index) => ({ value: point.readiness, index }))
    .filter((entry): entry is { value: number; index: number } => entry.value !== null);

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel>Posture Across Recorded Assessments</SectionLabel>
        <div className="flex shrink-0 items-center gap-3 font-mono text-[10px] text-slate-400">
          <span className="inline-flex items-center gap-1.5">
            <span className="h-[2px] w-4 rounded-full" style={{ backgroundColor: ACCENT.rose }} /> Security risk
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-[2px] w-4 rounded-full" style={{ backgroundColor: ACCENT.emerald }} /> Quantum readiness
          </span>
        </div>
      </div>

      <div className="px-5 py-4">
        <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" className="h-28 w-full" role="img"
          aria-label="Security risk and quantum readiness across the recorded assessments, oldest first.">
          {[0, 25, 50, 75, 100].map((line) => (
            <line
              key={line}
              x1={0}
              x2={width}
              y1={yFor(line)}
              y2={yFor(line)}
              stroke="rgba(255,255,255,0.06)"
              strokeWidth={0.3}
            />
          ))}
          {readinessSeries.length > 1 && (
            <path d={pathFor(readinessSeries)} fill="none" stroke={ACCENT.emerald} strokeWidth={0.9} vectorEffect="non-scaling-stroke" />
          )}
          {riskSeries.length > 1 && (
            <path d={pathFor(riskSeries)} fill="none" stroke={ACCENT.rose} strokeWidth={0.9} vectorEffect="non-scaling-stroke" />
          )}
          {riskSeries.map((entry) => (
            <circle key={`risk-${points[entry.index].scanId}`} cx={xFor(entry.index)} cy={yFor(entry.value)} r={0.9} fill={ACCENT.rose} />
          ))}
          {readinessSeries.map((entry) => (
            <circle key={`ready-${points[entry.index].scanId}`} cx={xFor(entry.index)} cy={yFor(entry.value)} r={0.9} fill={ACCENT.emerald} />
          ))}
        </svg>

        <div className="mt-2 flex items-center justify-between font-mono text-[10px] text-slate-500">
          <span>{formatDateTime(points[0].at)}</span>
          <span>
            {points.length} assessment{points.length === 1 ? '' : 's'}
            {riskSeries.length < points.length || readinessSeries.length < points.length
              ? ' · an assessment that did not measure a value contributes no point for it'
              : ''}
          </span>
          <span>{formatDateTime(points[points.length - 1].at)}</span>
        </div>
      </div>
    </Panel>
  );
}

/* ───────────────────────────────────────────────────────────────── filters ── */

function HistoryFilters({
  query,
  onQuery,
  statusFacets,
  statusFilter,
  onStatus,
  originFilter,
  onOrigin,
  shown,
  total,
  hasSession,
}: {
  query: string;
  onQuery: (value: string) => void;
  statusFacets: Array<[string, number]>;
  statusFilter: string | null;
  onStatus: (value: string | null) => void;
  originFilter: 'all' | 'recorded' | 'session';
  onOrigin: (value: 'all' | 'recorded' | 'session') => void;
  shown: number;
  total: number;
  hasSession: boolean;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2.5 border-b border-white/[0.06] px-4 py-3">
      <label className="relative flex min-w-[14rem] flex-1 items-center">
        <Search className="pointer-events-none absolute left-3 h-3.5 w-3.5 text-slate-500" />
        <input
          value={query}
          onChange={(event) => onQuery(event.target.value)}
          placeholder="Search target, profile, engine or scan id"
          className="w-full rounded-lg border border-white/[0.08] bg-white/[0.02] py-1.5 pl-9 pr-3 text-[12px] text-slate-200 outline-none transition-colors placeholder:text-slate-600 focus:border-cyan-400/40"
        />
      </label>

      {hasSession && (
        <div className="flex items-center gap-1">
          {(['all', 'recorded', 'session'] as const).map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => onOrigin(value)}
              className={cn(
                'rounded-lg border px-2.5 py-1.5 font-mono text-[10px] font-bold uppercase tracking-[0.12em] transition-colors',
                originFilter === value
                  ? 'border-cyan-400/35 bg-cyan-400/[0.08] text-cyan-300'
                  : 'border-white/[0.08] text-slate-500 hover:text-slate-300',
              )}
            >
              {value === 'all' ? 'All' : value === 'recorded' ? 'Recorded' : 'Session'}
            </button>
          ))}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-1">
        {statusFacets.map(([status, count]) => (
          <button
            key={status}
            type="button"
            onClick={() => onStatus(statusFilter === status ? null : status)}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[11px] font-semibold transition-colors',
              statusFilter === status
                ? 'border-cyan-400/35 bg-cyan-400/[0.08] text-cyan-300'
                : 'border-white/[0.08] text-slate-400 hover:text-slate-200',
            )}
          >
            <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: statusTone(status).color }} />
            {statusTone(status).label}
            <span className="font-mono text-[10px] text-slate-500">{count}</span>
          </button>
        ))}
      </div>

      <span className="ml-auto shrink-0 font-mono text-[10px] text-slate-500">
        {shown === total ? `${total} assessment${total === 1 ? '' : 's'}` : `${shown} of ${total}`}
      </span>
    </div>
  );
}

/* ───────────────────────────────────────────────────────────────── the row ── */

function SeverityChips({ severity }: { severity: ExposureHistoryEntry['severity'] }) {
  const present = SEVERITY_ORDER.filter((key) => severity[key] > 0);
  if (present.length === 0) return <span className="font-mono text-[11px] text-slate-600">none</span>;
  return (
    <span className="flex flex-wrap items-center gap-1">
      {present.map((key) => (
        <span
          key={key}
          title={`${severity[key]} ${key}`}
          className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold"
          style={{
            color: SEVERITY_COLOR[key],
            borderColor: `${SEVERITY_COLOR[key]}40`,
            backgroundColor: `${SEVERITY_COLOR[key]}12`,
          }}
        >
          {key.charAt(0).toUpperCase()}
          {severity[key]}
        </span>
      ))}
    </span>
  );
}

function DeltaCell({ entry, previous }: { entry: ExposureHistoryEntry; previous: ExposureHistoryEntry | null }) {
  if (!previous) {
    return (
      <span className="font-mono text-[10.5px] text-slate-600" title="No earlier assessment of this target is recorded.">
        first
      </span>
    );
  }

  const findingDelta = entry.findingCount - previous.findingCount;
  const readinessDelta =
    entry.quantumReadiness !== null && previous.quantumReadiness !== null
      ? Math.round((entry.quantumReadiness - previous.quantumReadiness) * 10) / 10
      : null;

  return (
    <span className="flex flex-col gap-0.5 font-mono text-[10.5px] leading-tight">
      <span
        className={cn(findingDelta > 0 ? 'text-rose-300' : findingDelta < 0 ? 'text-emerald-300' : 'text-slate-500')}
        title={`Findings against the previous assessment of ${previous.target} (${formatDateTime(previous.startedAt)}).`}
      >
        {findingDelta > 0 ? '+' : ''}
        {findingDelta} findings
      </span>
      {readinessDelta !== null && (
        <span className={cn(readinessDelta > 0 ? 'text-emerald-300' : readinessDelta < 0 ? 'text-rose-300' : 'text-slate-500')}>
          {readinessDelta > 0 ? '+' : ''}
          {readinessDelta} pts ready
        </span>
      )}
    </span>
  );
}

function HistoryRow({
  entry,
  previous,
  onOpen,
  onDelete,
}: {
  entry: ExposureHistoryEntry;
  previous: ExposureHistoryEntry | null;
  onOpen: () => void;
  onDelete: () => void;
}) {
  const tone = statusTone(entry.status);
  const sessionOnly = entry.origin === 'session';

  return (
    <tr className="group border-b border-white/[0.04] transition-colors last:border-b-0 hover:bg-white/[0.02]">
      <td className="px-4 py-3 align-top">
        <button
          type="button"
          onClick={onOpen}
          disabled={sessionOnly}
          className="flex max-w-[22rem] flex-col items-start gap-1 text-left disabled:cursor-default"
        >
          <span className={cn('truncate text-[12.5px] font-bold', sessionOnly ? 'text-slate-300' : 'text-white group-hover:text-cyan-300')}>
            {entry.target}
          </span>
          <span className="flex flex-wrap items-center gap-1.5 font-mono text-[10px] text-slate-500">
            <span className="rounded border border-white/[0.08] px-1.5 py-0.5">{entry.targetKind}</span>
            <span className="rounded border border-white/[0.08] px-1.5 py-0.5">{entry.profileId}</span>
            <span>{entry.engines.length} engines</span>
            {entry.localOnly && (
              <span className="rounded border border-emerald-400/25 px-1.5 py-0.5 text-emerald-300">local-only</span>
            )}
            {sessionOnly && (
              <span className="rounded border border-amber-400/25 px-1.5 py-0.5 text-amber-300">session only</span>
            )}
          </span>
        </button>
      </td>

      <td className="px-4 py-3 align-top">
        <span className="flex flex-col gap-0.5 text-[11.5px] leading-tight text-slate-300">
          <span>{formatDateTime(entry.startedAt)}</span>
          <span className="font-mono text-[10px] text-slate-500">
            {formatRelative(entry.startedAt)} · {formatDuration(entry.durationMs)}
          </span>
        </span>
      </td>

      <td className="px-4 py-3 align-top">
        <span className="flex flex-col gap-1">
          <span className="inline-flex w-fit items-center gap-1.5 text-[11.5px] font-semibold" style={{ color: tone.color }}>
            <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: tone.color }} />
            {tone.label}
          </span>
          {entry.live?.running && (
            <span className="font-mono text-[10px] text-cyan-300">running · {entry.live.progress}%</span>
          )}
          {entry.coverage.notAssessed > 0 && (
            <span className="font-mono text-[10px] text-amber-300/80" title="Dimensions this assessment could not read.">
              {entry.coverage.notAssessed} not assessed
            </span>
          )}
        </span>
      </td>

      <td className="px-4 py-3 align-top">
        <span className="flex flex-col gap-1">
          <span className="font-mono text-[12.5px] font-bold text-white">{entry.findingCount.toLocaleString()}</span>
          <SeverityChips severity={entry.severity} />
        </span>
      </td>

      <td className="px-4 py-3 align-top">
        <span className="flex flex-col gap-0.5 font-mono text-[11.5px] leading-tight">
          <span className="font-bold text-white">{entry.componentCount.toLocaleString()}</span>
          <span className={entry.quantumVulnerableComponents > 0 ? 'text-rose-300' : 'text-slate-500'}>
            {entry.quantumVulnerableComponents} vulnerable
          </span>
          <span className="text-slate-500">{entry.exposureCount} correlated</span>
        </span>
      </td>

      <td className="px-4 py-3 align-top">
        {entry.quantumReadiness === null ? (
          <span className="font-mono text-[10.5px] text-slate-500" title="This assessment measured no cryptographic component.">
            not measured
          </span>
        ) : (
          <span className="flex flex-col gap-1">
            <span className="font-mono text-[12.5px] font-bold" style={{ color: entry.quantumReadiness >= 60 ? ACCENT.emerald : entry.quantumReadiness >= 30 ? ACCENT.amber : ACCENT.rose }}>
              {Math.round(entry.quantumReadiness)}%
            </span>
            <span className="h-1 w-16 overflow-hidden rounded-full bg-white/[0.06]">
              <span
                className="block h-full rounded-full"
                style={{
                  width: `${Math.max(0, Math.min(100, entry.quantumReadiness))}%`,
                  backgroundColor: entry.quantumReadiness >= 60 ? ACCENT.emerald : entry.quantumReadiness >= 30 ? ACCENT.amber : ACCENT.rose,
                }}
              />
            </span>
          </span>
        )}
      </td>

      <td className="px-4 py-3 align-top">
        <DeltaCell entry={entry} previous={previous} />
      </td>

      <td className="px-4 py-3 align-top text-right">
        <span className="inline-flex items-center gap-1.5">
          {sessionOnly ? (
            <span className="font-mono text-[10px] text-slate-500" title={entry.live?.note}>
              not recorded
            </span>
          ) : (
            <>
              <button
                type="button"
                onClick={onOpen}
                className="inline-flex items-center gap-1 rounded-lg border border-white/[0.08] px-2.5 py-1.5 text-[11px] font-semibold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
              >
                Open <ChevronRight className="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                onClick={onDelete}
                title="Delete this assessment and everything it wrote to the inventory"
                className="grid h-[30px] w-[30px] place-items-center rounded-lg border border-white/[0.08] text-slate-500 transition-colors hover:border-rose-400/30 hover:text-rose-300"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </>
          )}
        </span>
      </td>
    </tr>
  );
}

/* ───────────────────────────────────────────────────────── empty / loading ── */

function HistoryLoading() {
  return (
    <div className="flex items-center justify-center gap-2.5 px-5 py-14 text-slate-500">
      <Loader2 className="h-4 w-4 animate-spin" />
      <span className="text-[12.5px]">Reading the recorded assessments…</span>
    </div>
  );
}

function HistoryEmpty({
  mode,
  filtered,
  unread,
  onClear,
  onRetry,
  onStartAssessment,
}: {
  mode: ExposureHistoryMode;
  filtered: boolean;
  /** True when the list is empty because the read failed, not because nothing is recorded. */
  unread?: boolean;
  onClear: () => void;
  onRetry: () => void;
  onStartAssessment?: () => void;
}) {
  if (unread) {
    return (
      <div className="px-5 py-14 text-center">
        <span className="mx-auto grid h-11 w-11 place-items-center rounded-2xl border border-amber-400/25 bg-amber-400/[0.06] text-amber-300">
          <FileWarning className="h-5 w-5" />
        </span>
        <p className="mt-3 text-[13.5px] font-black text-white">This history could not be read</p>
        <p className="mx-auto mt-2 max-w-lg text-[12px] leading-relaxed text-slate-400">
          This is not a statement that you have no recorded assessments — the read did not complete, so nothing here
          describes your estate. The reason is stated above.
        </p>
        <button
          type="button"
          onClick={onRetry}
          className="mt-4 inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11.5px] font-semibold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Try again
        </button>
      </div>
    );
  }

  if (filtered) {
    return (
      <div className="px-5 py-14 text-center">
        <p className="text-[13px] font-bold text-white">No assessment matches these filters</p>
        <button
          type="button"
          onClick={onClear}
          className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11.5px] font-semibold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
        >
          <X className="h-3.5 w-3.5" /> Clear filters
        </button>
      </div>
    );
  }

  return (
    <div className="px-5 py-14 text-center">
      <span className="mx-auto grid h-11 w-11 place-items-center rounded-2xl border border-white/[0.08] bg-white/[0.02] text-slate-500">
        <Boxes className="h-5 w-5" />
      </span>
      <p className="mt-3 text-[13.5px] font-black text-white">No assessment recorded yet</p>
      <p className="mx-auto mt-2 max-w-lg text-[12px] leading-relaxed text-slate-400">
        {mode === 'local'
          ? 'Local assessments run entirely inside this browser tab. Run one from the Assessment tab, then save it to the platform — saving is what records it here and adds its findings to your inventory.'
          : 'Development assessments run on the platform. Run one from the Assessment tab, then save it to the platform — saving is what records it here and adds its findings to your inventory.'}
      </p>
      {onStartAssessment && (
        <button
          type="button"
          onClick={onStartAssessment}
          className="mt-4 inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-400 to-blue-500 px-4 py-2 text-[12.5px] font-black text-[#04060e] transition-opacity hover:opacity-90"
        >
          Run an assessment <ChevronRight className="h-4 w-4" />
        </button>
      )}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────── detail ── */

function HistoryDetailView({
  mode,
  entry,
  detail,
  previous,
  loading,
  error,
  onBack,
  onDelete,
  onRetry,
  reports,
}: {
  mode: ExposureHistoryMode;
  entry: ExposureHistoryEntry | null;
  detail: ExposureHistoryDetail | null;
  previous: ExposureHistoryEntry | null;
  loading: boolean;
  error: string | null;
  onBack: () => void;
  onDelete: (entry: ExposureHistoryEntry) => void;
  onRetry: () => void;
  reports?: ExposureReportAuthor;
}) {
  const shown = detail?.entry ?? entry;

  return (
    <>
      <Panel className="overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5">
          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              onClick={onBack}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-white/[0.08] px-2.5 py-1.5 text-[11.5px] font-semibold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
            >
              <ArrowLeft className="h-3.5 w-3.5" /> History
            </button>
            <div className="min-w-0">
              <h3 className="truncate text-[14px] font-black text-white">{shown?.target ?? 'Recorded assessment'}</h3>
              {shown && (
                <p className="mt-0.5 font-mono text-[10.5px] text-slate-500">
                  {formatDateTime(shown.startedAt)} · {formatDuration(shown.durationMs)} · profile {shown.profileId} ·{' '}
                  {shown.scanId}
                </p>
              )}
            </div>
          </div>

          <div className="flex shrink-0 flex-wrap items-center gap-2">
            {detail && reports && (
              <ExposureReportButton
                assessment={detail.assessment}
                author={reports}
                record={exposureRecordFromProvenance(detail.provenance)}
              />
            )}
            {detail && <ExportRow detail={detail} />}
            {shown && shown.origin === 'recorded' && (
              <button
                type="button"
                onClick={() => onDelete(shown)}
                className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11.5px] font-semibold text-slate-400 transition-colors hover:border-rose-400/30 hover:text-rose-300"
              >
                <Trash2 className="h-3.5 w-3.5" /> Delete
              </button>
            )}
          </div>
        </div>

        {shown && previous && (
          <div className="flex flex-wrap items-center gap-4 border-t border-white/[0.06] px-5 py-2.5 font-mono text-[10.5px] text-slate-500">
            <span>Compared with the previous assessment of this target ({formatDateTime(previous.startedAt)}):</span>
            <ChangeStat label="findings" current={shown.findingCount} previous={previous.findingCount} invert />
            <ChangeStat label="components" current={shown.componentCount} previous={previous.componentCount} />
            <ChangeStat
              label="vulnerable components"
              current={shown.quantumVulnerableComponents}
              previous={previous.quantumVulnerableComponents}
              invert
            />
            {shown.quantumReadiness !== null && previous.quantumReadiness !== null && (
              <ChangeStat
                label="readiness"
                current={Math.round(shown.quantumReadiness)}
                previous={Math.round(previous.quantumReadiness)}
                suffix="%"
              />
            )}
          </div>
        )}
      </Panel>

      {loading && !detail && (
        <Panel>
          <div className="flex items-center justify-center gap-2.5 px-5 py-14 text-slate-500">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span className="text-[12.5px]">Rebuilding this assessment from its recorded rows…</span>
          </div>
        </Panel>
      )}

      {error && (
        <Panel className="border-rose-400/25 bg-rose-500/[0.05]">
          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5">
            <div className="flex min-w-0 items-start gap-3">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
              <p className="text-[12.5px] leading-relaxed text-rose-100/85">{error}</p>
            </div>
            <button
              type="button"
              onClick={onRetry}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-rose-400/25 px-3 py-1.5 text-[11.5px] font-semibold text-rose-200 transition-colors hover:bg-rose-500/10"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Try again
            </button>
          </div>
        </Panel>
      )}

      {detail && (
        <>
          <ProvenancePanel detail={detail} />

          <ExposureScorecard assessment={detail.assessment} />
          <QuantumExposureSummary assessment={detail.assessment} />
          {detail.assessment.task.runs.length > 0 && (
            <EngineLedger runs={detail.assessment.task.runs} progress={100} status={detail.assessment.task.status} />
          )}
          <ScannerIntelligenceSection assessment={detail.assessment} synced />
          <CorrelatedExposures exposures={detail.assessment.exposures} />
          <FindingExplorer assessment={detail.assessment} />
          <ExposureWorkflowGraph assessment={detail.assessment} mode={mode} />
          <ExposureRecommendations assessment={detail.assessment} />
          <CbomViewer
            components={detail.assessment.cbom}
            onExport={(format) => exportCbom(detail, format)}
          />
          <CoveragePanel coverage={detail.assessment.task.coverage} mode={mode} />
        </>
      )}
    </>
  );
}

function ChangeStat({
  label,
  current,
  previous,
  suffix = '',
  invert = false,
}: {
  label: string;
  current: number;
  previous: number;
  suffix?: string;
  invert?: boolean;
}) {
  const delta = current - previous;
  /* `invert` marks a metric where MORE is worse (findings, vulnerable
     components), so the colour tracks the direction of the risk rather than the
     sign of the number. */
  const better = invert ? delta < 0 : delta > 0;
  const worse = invert ? delta > 0 : delta < 0;

  return (
    <span className="inline-flex items-center gap-1">
      <span className="text-slate-400">{label}</span>
      <span className={cn('font-bold', better ? 'text-emerald-300' : worse ? 'text-rose-300' : 'text-slate-400')}>
        {delta > 0 ? '+' : ''}
        {delta}
        {suffix}
      </span>
      <span className="text-slate-600">
        ({previous}
        {suffix} → {current}
        {suffix})
      </span>
    </span>
  );
}

function exportCbom(detail: ExposureHistoryDetail, format: string) {
  const meta = {
    scanId: detail.entry.scanId,
    target: detail.entry.target,
    generatedAt: detail.assessment.generatedAt,
  };
  const slug = meta.target.replace(/[^a-z0-9.-]/gi, '_');
  if (format === 'csv') downloadBlob(`qguard-cbom-${slug}.csv`, cbomToCsv(detail.assessment.cbom), 'text/csv');
  else if (format === 'cyclonedx')
    downloadBlob(`qguard-cbom-${slug}.cdx.json`, cbomToCycloneDx(detail.assessment.cbom, meta), 'application/json');
  else downloadBlob(`qguard-cbom-${slug}.json`, cbomToJson(detail.assessment.cbom, meta), 'application/json');
}

function ExportRow({ detail }: { detail: ExposureHistoryDetail }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500">Export</span>
      {(['json', 'csv', 'cyclonedx'] as const).map((format) => (
        <button
          key={format}
          type="button"
          onClick={() => exportCbom(detail, format)}
          className="inline-flex items-center gap-1 rounded-lg border border-white/[0.08] px-2.5 py-1.5 text-[11px] font-semibold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
        >
          <Download className="h-3 w-3" />
          {format === 'cyclonedx' ? 'CycloneDX' : format.toUpperCase()}
        </button>
      ))}
    </span>
  );
}

/* ────────────────────────────────────────────────────────────── provenance ── */

/**
 * What this view is, and what it is not.
 *
 * A historical assessment is a RECORD, and a record has edges. This panel names
 * them: which parts were read back verbatim, which were recomputed, and which
 * the record never held — so a reader can never mistake a field the platform
 * did not retain for a field the scan found nothing in.
 */
function ProvenancePanel({ detail }: { detail: ExposureHistoryDetail }) {
  const { provenance } = detail;
  const [open, setOpen] = React.useState(provenance.notRetained.length > 0 || provenance.truncated.length > 0);

  return (
    <Panel className="overflow-hidden border-violet-400/15">
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        className="flex w-full flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3 text-left"
      >
        <SectionLabel accent={ACCENT.violet}>Record Provenance</SectionLabel>
        <span className="flex shrink-0 items-center gap-2 font-mono text-[10px] text-slate-500">
          {provenance.notRetained.length > 0 && (
            <span className="inline-flex items-center gap-1 text-amber-300/85">
              <FileWarning className="h-3 w-3" />
              {provenance.notRetained.length} not retained
            </span>
          )}
          {provenance.truncated.length > 0 && (
            <span className="text-amber-300/85">{provenance.truncated.length} capped</span>
          )}
          <span>record v{provenance.recordVersion}</span>
          <ChevronRight className={cn('h-3.5 w-3.5 transition-transform', open && 'rotate-90')} />
        </span>
      </button>

      {open && (
        <div className="grid grid-cols-[minmax(0,1fr)] gap-4 px-5 py-4 lg:grid-cols-3">
          <div>
            <p className="font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-emerald-300/80">
              Read from the record
            </p>
            <ul className="mt-2 space-y-1">
              {provenance.rehydrated.map((item) => (
                <li key={item} className="flex items-start gap-1.5 text-[11.5px] leading-relaxed text-slate-400">
                  <ShieldCheck className="mt-[3px] h-3 w-3 shrink-0 text-emerald-400/70" />
                  {item}
                </li>
              ))}
            </ul>
          </div>

          <div>
            <p className="font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-cyan-300/80">
              Recomputed from that evidence
            </p>
            <ul className="mt-2 space-y-1">
              {provenance.derived.map((item) => (
                <li key={item} className="flex items-start gap-1.5 text-[11.5px] leading-relaxed text-slate-400">
                  <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-cyan-400/60" />
                  {item}
                </li>
              ))}
            </ul>
            <p className="mt-2 text-[10.5px] leading-relaxed text-slate-500">
              Recomputed with the same functions a live assessment uses, so this view and a live one cannot disagree
              about the same evidence.
            </p>
          </div>

          <div>
            <p className="font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-amber-300/80">
              Not held by this record
            </p>
            {provenance.notRetained.length === 0 && provenance.truncated.length === 0 ? (
              <p className="mt-2 text-[11.5px] leading-relaxed text-slate-400">
                This record holds every field this view reads.
              </p>
            ) : (
              <ul className="mt-2 space-y-1.5">
                {provenance.notRetained.map((item) => (
                  <li key={item.field} className="text-[11.5px] leading-relaxed text-slate-400">
                    <span className="font-bold text-amber-200/90">{item.field}</span> — {item.reason}
                  </li>
                ))}
                {provenance.truncated.map((item) => (
                  <li key={`truncated-${item.field}`} className="text-[11.5px] leading-relaxed text-slate-400">
                    <span className="font-bold text-amber-200/90">{item.field}</span> — {item.note} ({item.kept.toLocaleString()} retained)
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

      <p className="border-t border-white/[0.06] px-5 py-2 font-mono text-[10px] text-slate-500">
        <Clock className="mr-1.5 inline h-3 w-3" />
        Recorded {formatDateTime(provenance.recordedAt)}
      </p>
    </Panel>
  );
}

/* ────────────────────────────────────────────────────────────────── delete ── */

function DeleteDialog({
  entry,
  deleting,
  error,
  onCancel,
  onConfirm,
}: {
  entry: ExposureHistoryEntry;
  deleting: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 grid place-items-center bg-[#04060e]/80 px-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.97, y: 8 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.97, y: 8 }}
        transition={{ duration: 0.18 }}
        className="w-full max-w-lg"
      >
        <Panel className="overflow-hidden border-rose-400/25">
          <div className="flex items-start gap-3 px-5 py-4">
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-rose-400/25 bg-rose-500/[0.08] text-rose-300">
              <ShieldAlert className="h-4.5 w-4.5" />
            </span>
            <div className="min-w-0">
              <h3 className="text-[14px] font-black text-white">Delete this assessment?</h3>
              <p className="mt-1.5 text-[12px] leading-relaxed text-slate-400">
                <strong className="font-bold text-white">{entry.target}</strong>, assessed{' '}
                {formatDateTime(entry.startedAt)}.
              </p>
              <p className="mt-2 text-[12px] leading-relaxed text-slate-400">
                This removes real inventory: {entry.findingCount.toLocaleString()} finding
                {entry.findingCount === 1 ? '' : 's'} and {entry.componentCount.toLocaleString()} cryptographic component
                {entry.componentCount === 1 ? '' : 's'} stop being counted by CBOM, Assets, Crypto Exposure and Quantum
                Readiness. It cannot be undone — re-run the assessment to record it again.
              </p>
              {error && (
                <p className="mt-2.5 rounded-lg border border-rose-400/25 bg-rose-500/[0.07] px-3 py-2 text-[11.5px] text-rose-100/85">
                  {error}
                </p>
              )}
            </div>
          </div>
          <div className="flex items-center justify-end gap-2 border-t border-white/[0.06] px-5 py-3">
            <button
              type="button"
              onClick={onCancel}
              disabled={deleting}
              className="rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11.5px] font-semibold text-slate-300 transition-colors hover:text-white disabled:opacity-50"
            >
              Keep it
            </button>
            <button
              type="button"
              onClick={onConfirm}
              disabled={deleting}
              className="inline-flex items-center gap-1.5 rounded-lg border border-rose-400/30 bg-rose-500/[0.12] px-3 py-1.5 text-[11.5px] font-bold text-rose-200 transition-colors hover:bg-rose-500/20 disabled:opacity-50"
            >
              {deleting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
              Delete assessment
            </button>
          </div>
        </Panel>
      </motion.div>
    </motion.div>
  );
}
