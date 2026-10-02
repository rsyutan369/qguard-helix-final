'use client';

/**
 * Presentational pieces of the Asset Inventory & CBOM page.
 *
 * Every component here RENDERS values from the asset register
 * (`src/lib/assets/asset-register.ts`); none of them computes a count. That is
 * what keeps the page, the Report Studio and every exported document on one set
 * of numbers.
 */

import { useEffect, useState, type ReactNode } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CircleDashed,
  Clock3,
  FileText,
  Filter,
  Globe2,
  Layers,
  Loader2,
  Radio,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  SignalHigh,
  UserX,
  WifiOff,
  X,
  type LucideIcon,
} from 'lucide-react';
import type {
  AssetRegister,
  FreshnessState,
  PqcStatus,
  RegisterBandKey,
  RegisterSort,
  RegisterTotals,
  SeverityOrUnrated,
} from '@/lib/assets/asset-register';
import { PQC_STATUS_META, REGISTER_BANDS, STALE_AFTER_HOURS } from '@/lib/assets/asset-register';
import type { ScannerSnapshotSource, ScannerTransport } from '@/lib/scanner/use-scanner-intelligence';
import { DiscoveryMetric, panelClass, subtlePanelClass } from '../_components/discovery/shell';

/* ------------------------------------------------------------------ */
/* Formatting                                                          */
/* ------------------------------------------------------------------ */

/** A clock that ticks every `intervalMs` — keeps relative ages honest. */
export function useNow(intervalMs: number) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}

export const nf = (value: number) => (Number.isFinite(value) ? value.toLocaleString('en-US') : '—');

export function pctOf(part: number, total: number) {
  return total > 0 ? `${Math.round((part / total) * 1000) / 10}%` : '—';
}

/** "just now" / "12s ago" / "5m ago" / "3h ago" / "8d ago" from a timestamp. */
export function relativeAge(value: string | number | null | undefined, now: number) {
  const ms = typeof value === 'number' ? value : Date.parse(String(value || ''));
  if (!Number.isFinite(ms) || !ms) return null;
  const seconds = Math.max(0, Math.round((now - ms) / 1000));
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function absoluteTime(value: string | null | undefined) {
  if (!value) return 'No timestamp';
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toLocaleString() : 'No timestamp';
}

/* ------------------------------------------------------------------ */
/* Status vocabulary — icon + text, never colour alone                 */
/* ------------------------------------------------------------------ */

export const PQC_STATUS_STYLE: Record<PqcStatus, { icon: LucideIcon; className: string; bar: string }> = {
  'quantum-vulnerable': {
    icon: ShieldAlert,
    className: 'border-red-500/35 bg-red-500/10 text-red-700 dark:border-red-400/40 dark:bg-red-500/12 dark:text-red-200',
    bar: 'bg-red-500',
  },
  'needs-review': {
    icon: ShieldQuestion,
    className: 'border-amber-500/40 bg-amber-500/10 text-amber-800 dark:border-amber-400/40 dark:bg-amber-500/12 dark:text-amber-200',
    bar: 'bg-amber-500',
  },
  'not-measured': {
    icon: CircleDashed,
    className: 'border-slate-400/40 bg-slate-500/10 text-slate-700 dark:border-slate-400/35 dark:bg-slate-500/12 dark:text-slate-200',
    bar: 'bg-slate-400',
  },
  'pqc-ready': {
    icon: ShieldCheck,
    className: 'border-emerald-500/35 bg-emerald-500/10 text-emerald-700 dark:border-emerald-400/40 dark:bg-emerald-500/12 dark:text-emerald-200',
    bar: 'bg-emerald-500',
  },
};

export function StatusBadge({ status, reason, compact = false }: { status: PqcStatus; reason?: string; compact?: boolean }) {
  const style = PQC_STATUS_STYLE[status];
  const Icon = style.icon;
  return (
    <span
      title={reason}
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-2 py-1 text-[10px] font-black uppercase tracking-wider ${style.className}`}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden />
      {compact ? PQC_STATUS_META[status].short : PQC_STATUS_META[status].label}
    </span>
  );
}

export const SEVERITY_STYLE: Record<SeverityOrUnrated, { label: string; glyph: string; chip: string; bar: string }> = {
  critical: { label: 'Critical', glyph: 'C', chip: 'border-red-500/30 bg-red-500/12 text-red-700 dark:text-red-200', bar: 'bg-red-500' },
  high: { label: 'High', glyph: 'H', chip: 'border-orange-500/30 bg-orange-500/12 text-orange-700 dark:text-orange-200', bar: 'bg-orange-500' },
  medium: { label: 'Medium', glyph: 'M', chip: 'border-amber-500/30 bg-amber-500/12 text-amber-800 dark:text-amber-200', bar: 'bg-amber-500' },
  low: { label: 'Low', glyph: 'L', chip: 'border-emerald-500/30 bg-emerald-500/12 text-emerald-700 dark:text-emerald-200', bar: 'bg-emerald-500' },
  unrated: { label: 'Unrated', glyph: '?', chip: 'border-slate-400/30 bg-slate-500/10 text-slate-700 dark:text-slate-200', bar: 'bg-slate-400' },
};

export function SeverityChips({ counts }: { counts: Record<SeverityOrUnrated, number> }) {
  const keys = (['critical', 'high', 'medium', 'low', 'unrated'] as const).filter((key) => counts[key] > 0);
  if (!keys.length) return null;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {keys.map((key) => (
        <span key={key} title={`${counts[key]} ${SEVERITY_STYLE[key].label.toLowerCase()} component${counts[key] === 1 ? '' : 's'}`} className={`rounded border px-1.5 py-0.5 text-[9px] font-black ${SEVERITY_STYLE[key].chip}`}>
          {SEVERITY_STYLE[key].glyph} {counts[key]}
        </span>
      ))}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: SeverityOrUnrated | 'safe' }) {
  if (severity === 'safe') {
    return <span className="inline-flex items-center gap-1 rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-[9px] font-black uppercase text-emerald-700 dark:text-emerald-200"><CheckCircle2 className="h-3 w-3" aria-hidden />Safe</span>;
  }
  const style = SEVERITY_STYLE[severity];
  return <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[9px] font-black uppercase ${style.chip}`}>{style.label}</span>;
}

export function BandPill({ band, score }: { band: { key: RegisterBandKey; label: string; hex: string }; score: number | null }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-[11px] font-black text-[var(--qg-dashboard-text)]">
      <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: band.hex }} aria-hidden />
      {score === null ? 'Not assessed' : `${score}/100`}
      <span className="font-bold text-[var(--qg-text-muted)]">{score === null ? '' : band.label}</span>
    </span>
  );
}

/** Part-to-whole bar: vulnerable / unclassified / PQC-ready, 1px surface gaps. */
export function MiniStack({ vulnerable, unclassified, ready, total, height = 'h-1.5' }: { vulnerable: number; unclassified: number; ready: number; total: number; height?: string }) {
  if (!total) return <div className={`${height} w-full rounded-full bg-[var(--qg-muted-panel)] dark:bg-white/10`} />;
  const parts = [
    { value: vulnerable, className: 'bg-red-500' },
    { value: unclassified, className: 'bg-slate-400' },
    { value: ready, className: 'bg-emerald-500' },
  ].filter((part) => part.value > 0);
  return (
    <div className={`flex ${height} w-full gap-px overflow-hidden rounded-full bg-[var(--qg-muted-panel)] dark:bg-white/10`} role="img" aria-label={`${vulnerable} vulnerable, ${unclassified} unclassified, ${ready} PQC-ready of ${total}`}>
      {parts.map((part, index) => (
        <div key={index} className={part.className} style={{ width: `${(part.value / total) * 100}%` }} />
      ))}
    </div>
  );
}

const FRESHNESS_STYLE: Record<FreshnessState, { dot: string; label: string }> = {
  fresh: { dot: 'bg-emerald-500', label: 'Current' },
  aging: { dot: 'bg-amber-500', label: 'Aging' },
  stale: { dot: 'bg-orange-500', label: 'Stale' },
  unknown: { dot: 'bg-slate-400', label: 'No timestamp' },
};

export function FreshnessLabel({ state, lastScanned, now }: { state: FreshnessState; lastScanned: string | null; now: number }) {
  const age = relativeAge(lastScanned, now);
  return (
    <span title={`${FRESHNESS_STYLE[state].label} — last observed ${absoluteTime(lastScanned)}`} className="inline-flex items-center gap-1.5 whitespace-nowrap text-[11px] text-[var(--qg-dashboard-text-soft)]">
      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${FRESHNESS_STYLE[state].dot}`} aria-hidden />
      {age ?? 'No timestamp'}
      {state === 'stale' ? <span className="font-black uppercase tracking-wider text-orange-600 dark:text-orange-300">stale</span> : null}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Transport status — what the page is actually connected to           */
/* ------------------------------------------------------------------ */

export function TransportStatus({ transport, source, lastVerifiedAt }: { transport: ScannerTransport; source: ScannerSnapshotSource; lastVerifiedAt: string | null }) {
  // Own 5-second clock: the pill's "verified 12s ago" stays current without
  // re-rendering the whole register every few seconds.
  const now = useNow(5000);
  const verified = relativeAge(lastVerifiedAt, now);
  let icon: ReactNode;
  let label: string;
  let tone: string;
  if (transport === 'stream') {
    icon = <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" aria-hidden />;
    label = `Live stream${verified ? ` · verified ${verified}` : ''}`;
    tone = 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300';
  } else if (transport === 'polling') {
    icon = <Radio className="h-3 w-3" aria-hidden />;
    label = `Polling every 8s${verified ? ` · verified ${verified}` : ''}`;
    tone = 'border-amber-500/35 bg-amber-500/10 text-amber-800 dark:text-amber-200';
  } else if (transport === 'manual') {
    icon = <Clock3 className="h-3 w-3" aria-hidden />;
    label = `Live updates paused${verified ? ` · loaded ${verified}` : ''}`;
    tone = 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]';
  } else if (transport === 'offline') {
    icon = <WifiOff className="h-3 w-3" aria-hidden />;
    label = source === 'none' ? 'Offline — no data received' : `Offline — showing ${source === 'cache' ? 'cached' : 'last received'} data`;
    tone = 'border-red-500/35 bg-red-500/10 text-red-700 dark:text-red-300';
  } else {
    icon = <Loader2 className="h-3 w-3 animate-spin" aria-hidden />;
    label = source === 'cache' ? 'Cached view · confirming with server' : 'Connecting to live telemetry';
    tone = 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]';
  }
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 ${tone}`} role="status">
      {icon}
      {label}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* KPI band                                                            */
/* ------------------------------------------------------------------ */

export function RegisterKpis({ register }: { register: AssetRegister }) {
  const t = register.totals;
  const qr = register.qrFigures;
  const criticalHigh = t.vulnerableSeverity.critical + t.vulnerableSeverity.high;
  const topBand = REGISTER_BANDS.find((band) => t.bands[band.key] > 0);
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
      <DiscoveryMetric
        label="Assets"
        value={t.assets}
        detail={`${nf(t.pqcStatus['quantum-vulnerable'])} vulnerable · ${nf(t.pqcStatus['pqc-ready'])} PQC-ready · ${nf(t.pqcStatus['not-measured'] + t.pqcStatus['needs-review'])} to review`}
        icon={Server}
        tone="cyan"
      />
      <DiscoveryMetric
        label="Crypto components"
        value={t.components.total}
        detail={`${nf(t.components.instances)} observations · ${t.classes.length} classes${register.unattributed.components ? ` · +${register.unattributed.components} unattributed` : ''}`}
        icon={Layers}
        tone="amber"
      />
      <DiscoveryMetric
        label="Quantum-vulnerable"
        value={t.components.vulnerable}
        detail={`${pctOf(t.components.vulnerable, t.components.total)} of components${register.qr.state === 'match' ? ' · matches CBOM & QR Engine' : ''}`}
        icon={AlertTriangle}
        tone={t.components.vulnerable ? 'red' : 'green'}
      />
      <DiscoveryMetric
        label="Critical + high"
        value={criticalHigh}
        detail={`${nf(t.vulnerableSeverity.critical)} critical · ${nf(t.vulnerableSeverity.high)} high (component severity)`}
        icon={ShieldAlert}
        tone={criticalHigh ? 'red' : 'green'}
      />
      <DiscoveryMetric
        label="Highest scanner risk"
        value={t.risk.max === null ? '—' : `${t.risk.max}/100`}
        detail={t.risk.max === null ? 'No asset carries risk evidence yet' : `${topBand?.label ?? ''} · ${t.risk.maxAsset} · mean ${t.risk.mean}`}
        icon={SignalHigh}
        tone={t.risk.max === null ? 'muted' : t.risk.max >= 60 ? 'red' : t.risk.max >= 40 ? 'amber' : 'green'}
      />
      <DiscoveryMetric
        label="Quantum readiness (QR Engine)"
        value={qr && qr.hasData && qr.readiness !== null ? `${qr.readiness}/100` : '—'}
        detail={
          qr && qr.hasData && qr.readiness !== null
            ? `${qr.readinessLevel ?? ''} · tenant quantum risk ${qr.risk ?? '—'}/100`
            : qr?.resolved
              ? 'No assessment evidence yet'
              : 'Awaiting the QR Engine'
        }
        icon={ShieldCheck}
        tone={qr && qr.hasData ? 'green' : 'muted'}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Posture overview                                                    */
/* ------------------------------------------------------------------ */

function PanelTitle({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
      <h2 className="text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]">{children}</h2>
      {right}
    </div>
  );
}

function Bar({ label, value, max, className, onClick, active, detail }: { label: string; value: number; max: number; className: string; onClick?: () => void; active?: boolean; detail?: string }) {
  const body = (
    <>
      <span className="w-28 shrink-0 truncate text-left text-[11px] font-bold text-[var(--qg-dashboard-text-soft)]">{label}</span>
      <span className="h-2 flex-1 overflow-hidden rounded-full bg-[var(--qg-muted-panel)] dark:bg-white/10">
        <span className={`block h-full rounded-full ${className}`} style={{ width: `${max ? (value / max) * 100 : 0}%` }} />
      </span>
      <span className="w-16 shrink-0 text-right text-[11px] font-black tabular-nums text-[var(--qg-dashboard-text)]">{nf(value)}{detail ? <span className="ml-1 font-bold text-[var(--qg-text-muted)]">{detail}</span> : null}</span>
    </>
  );
  if (!onClick) return <div className="flex items-center gap-3 py-1">{body}</div>;
  return (
    <button type="button" onClick={onClick} aria-pressed={active} className={`flex w-full items-center gap-3 rounded-md px-1 py-1 transition hover:bg-[var(--qg-muted-panel)] ${active ? 'ring-1 ring-[var(--qg-amber)]/60' : ''}`}>
      {body}
    </button>
  );
}

export function PostureOverview({
  register,
  statusFilter,
  onStatus,
  freshnessFilter,
  onFreshness,
}: {
  register: AssetRegister;
  statusFilter: PqcStatus | null;
  onStatus: (status: PqcStatus | null) => void;
  freshnessFilter: FreshnessState | null;
  onFreshness: (state: FreshnessState | null) => void;
}) {
  const t: RegisterTotals = register.totals;
  const c = t.components;
  const severityMax = Math.max(1, ...(['critical', 'high', 'medium', 'low', 'unrated'] as const).map((k) => t.vulnerableSeverity[k]));
  const statusMax = Math.max(1, ...Object.values(t.pqcStatus));
  return (
    <section className={`${panelClass} grid grid-cols-[minmax(0,1fr)] gap-6 p-5 lg:grid-cols-3`} aria-label="Posture overview">
      <div className="min-w-0">
        <PanelTitle right={<span className="text-[10px] font-mono text-[var(--qg-text-muted)]">{nf(c.total)} components</span>}>Component posture</PanelTitle>
        <MiniStack vulnerable={c.vulnerable} unclassified={c.unclassified} ready={c.pqcReady} total={c.total} height="h-3" />
        <ul className="mt-3 space-y-1 text-[11px]">
          {[
            { label: 'Quantum-vulnerable', value: c.vulnerable, dot: 'bg-red-500' },
            { label: 'Unclassified', value: c.unclassified, dot: 'bg-slate-400' },
            { label: 'PQC-ready', value: c.pqcReady, dot: 'bg-emerald-500' },
          ].map((row) => (
            <li key={row.label} className="flex items-center justify-between gap-2 text-[var(--qg-dashboard-text-soft)]">
              <span className="inline-flex items-center gap-2"><span className={`h-2 w-2 rounded-sm ${row.dot}`} aria-hidden />{row.label}</span>
              <span className="font-black tabular-nums text-[var(--qg-dashboard-text)]">{nf(row.value)} <span className="font-bold text-[var(--qg-text-muted)]">{pctOf(row.value, c.total)}</span></span>
            </li>
          ))}
        </ul>
        {t.classes.length ? (
          <div className="mt-4 space-y-2 border-t border-[var(--qg-card-border)] pt-3">
            <div className="text-[9px] font-black uppercase tracking-widest text-[var(--qg-text-muted)]">By component class</div>
            {t.classes.map((cls) => (
              <div key={cls.key} className="flex items-center gap-3 text-[11px]">
                <span className="w-32 shrink-0 truncate font-bold text-[var(--qg-dashboard-text-soft)]" title={cls.key === 'other' ? 'Counted by the CBOM, but the recorded algorithm names no primitive the decomposer can parse (usually a finding title).' : undefined}>{cls.label}</span>
                <span className="flex-1"><MiniStack vulnerable={cls.vulnerable} unclassified={cls.unclassified} ready={cls.pqcReady} total={cls.components} /></span>
                <span className="w-14 shrink-0 text-right font-black tabular-nums text-[var(--qg-dashboard-text)]">{cls.vulnerable}/{cls.components}</span>
              </div>
            ))}
          </div>
        ) : null}
      </div>

      <div className="min-w-0">
        <PanelTitle right={<span className="text-[10px] font-mono text-[var(--qg-text-muted)]">{nf(c.vulnerable)} vulnerable</span>}>Vulnerable components by severity</PanelTitle>
        {(['critical', 'high', 'medium', 'low', 'unrated'] as const)
          .filter((key) => key !== 'unrated' || t.vulnerableSeverity.unrated > 0)
          .map((key) => (
            <Bar key={key} label={SEVERITY_STYLE[key].label} value={t.vulnerableSeverity[key]} max={severityMax} className={SEVERITY_STYLE[key].bar} />
          ))}
        <p className="mt-3 border-t border-[var(--qg-card-border)] pt-3 text-[10px] leading-relaxed text-[var(--qg-text-muted)]">
          Component-level, the unit the CBOM and the QR Engine count. The scanner also recorded {nf(register.findings.graded)} graded finding{register.findings.graded === 1 ? '' : 's'} across the estate
          and {nf(t.posture.total)} configuration observation{t.posture.total === 1 ? '' : 's'} on these assets — findings describe the estate, they are not components.
        </p>
      </div>

      <div className="min-w-0">
        <PanelTitle right={statusFilter || freshnessFilter ? (
          <button type="button" onClick={() => { onStatus(null); onFreshness(null); }} className="inline-flex items-center gap-1 text-[10px] font-black uppercase text-[var(--qg-amber)]"><X className="h-3 w-3" />Clear</button>
        ) : <span className="text-[10px] font-mono text-[var(--qg-text-muted)]">click to filter</span>}>Asset status</PanelTitle>
        {(['quantum-vulnerable', 'needs-review', 'not-measured', 'pqc-ready'] as const).map((status) => (
          <Bar
            key={status}
            label={PQC_STATUS_META[status].short}
            value={t.pqcStatus[status]}
            max={statusMax}
            className={PQC_STATUS_STYLE[status].bar}
            onClick={() => onStatus(statusFilter === status ? null : status)}
            active={statusFilter === status}
          />
        ))}
        <div className="mt-3 grid grid-cols-2 gap-2 border-t border-[var(--qg-card-border)] pt-3 text-[11px]">
          <button type="button" onClick={() => onFreshness(freshnessFilter === 'stale' ? null : 'stale')} aria-pressed={freshnessFilter === 'stale'} className={`${subtlePanelClass} flex items-center justify-between gap-2 px-2.5 py-2 text-left transition hover:border-[var(--qg-amber)]/45 ${freshnessFilter === 'stale' ? 'ring-1 ring-[var(--qg-amber)]/60' : ''}`}>
            <span className="inline-flex items-center gap-1.5 font-bold text-[var(--qg-dashboard-text-soft)]"><Clock3 className="h-3.5 w-3.5 text-orange-500" aria-hidden />Stale &gt; {STALE_AFTER_HOURS}h</span>
            <span className="font-black tabular-nums">{nf(t.freshness.stale)}</span>
          </button>
          <div className={`${subtlePanelClass} flex items-center justify-between gap-2 px-2.5 py-2`}>
            <span className="inline-flex items-center gap-1.5 font-bold text-[var(--qg-dashboard-text-soft)]"><UserX className="h-3.5 w-3.5 text-amber-500" aria-hidden />No owner</span>
            <span className="font-black tabular-nums">{nf(t.owners.unassigned)}</span>
          </div>
          <div className={`${subtlePanelClass} flex items-center justify-between gap-2 px-2.5 py-2`}>
            <span className="inline-flex items-center gap-1.5 font-bold text-[var(--qg-dashboard-text-soft)]"><Globe2 className="h-3.5 w-3.5 text-cyan-500" aria-hidden />Internet-facing</span>
            <span className="font-black tabular-nums">{nf(t.internetFacing)}</span>
          </div>
          <div className={`${subtlePanelClass} flex items-center justify-between gap-2 px-2.5 py-2`}>
            <span className="inline-flex items-center gap-1.5 font-bold text-[var(--qg-dashboard-text-soft)]"><Radio className="h-3.5 w-3.5 text-emerald-500" aria-hidden />Scanning now</span>
            <span className="font-black tabular-nums">{nf(t.scanning)}</span>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Toolbar                                                             */
/* ------------------------------------------------------------------ */

export const SORT_OPTIONS: Array<{ value: RegisterSort; label: string }> = [
  { value: 'risk', label: 'Highest scanner risk' },
  { value: 'vulnerable', label: 'Most vulnerable components' },
  { value: 'last-scanned', label: 'Most recently scanned' },
  { value: 'name', label: 'Name (A–Z)' },
];

export function RegisterToolbar({
  query,
  onQuery,
  band,
  onBand,
  bandCounts,
  sort,
  onSort,
  shown,
  total,
  onSelectAll,
  allSelected,
  selectedCount,
  onClearSelection,
}: {
  query: string;
  onQuery: (value: string) => void;
  band: RegisterBandKey | null;
  onBand: (value: RegisterBandKey | null) => void;
  bandCounts: Record<RegisterBandKey, number>;
  sort: RegisterSort;
  onSort: (value: RegisterSort) => void;
  shown: number;
  total: number;
  onSelectAll: () => void;
  allSelected: boolean;
  selectedCount: number;
  onClearSelection: () => void;
}) {
  return (
    <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
      <label className="relative min-w-0 flex-1">
        <span className="sr-only">Search assets</span>
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--qg-text-muted)]" aria-hidden />
        <input
          type="search"
          value={query}
          onChange={(event) => onQuery(event.target.value)}
          placeholder="Search assets, owners, algorithms, primitives, evidence…"
          className="w-full rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] py-2.5 pl-10 pr-4 text-sm text-[var(--qg-dashboard-text)] outline-none transition placeholder:text-[var(--qg-text-muted)] focus:border-[var(--qg-amber)]/60"
        />
      </label>
      <div className="flex flex-wrap items-center gap-2">
        <label className="inline-flex items-center gap-2 rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-3 py-2 text-[11px] font-bold text-[var(--qg-dashboard-text-soft)]">
          <Filter className="h-3.5 w-3.5" aria-hidden />
          <span className="sr-only">Risk band</span>
          <select value={band ?? ''} onChange={(event) => onBand((event.target.value || null) as RegisterBandKey | null)} className="bg-transparent text-[11px] font-bold text-[var(--qg-dashboard-text)] outline-none">
            <option value="">All risk bands</option>
            {REGISTER_BANDS.filter((b) => bandCounts[b.key] > 0 || b.key === band).map((b) => (
              <option key={b.key} value={b.key}>{b.label} ({bandCounts[b.key]})</option>
            ))}
          </select>
        </label>
        <label className="inline-flex items-center gap-2 rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-3 py-2 text-[11px] font-bold text-[var(--qg-dashboard-text-soft)]">
          <span className="sr-only">Sort</span>
          <select value={sort} onChange={(event) => onSort(event.target.value as RegisterSort)} className="bg-transparent text-[11px] font-bold text-[var(--qg-dashboard-text)] outline-none">
            {SORT_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
        </label>
        <span className="px-1 text-[11px] font-bold text-[var(--qg-text-muted)]">{shown === total ? `${nf(total)} assets` : `${nf(shown)} of ${nf(total)} assets`}</span>
        <button type="button" onClick={onSelectAll} disabled={shown === 0} className="rounded-lg border border-[var(--qg-card-border)] px-3 py-2 text-[11px] font-black uppercase tracking-wider text-[var(--qg-dashboard-text-soft)] transition hover:border-[var(--qg-amber)]/50 disabled:opacity-40">
          {allSelected ? 'Unselect shown' : `Select ${shown === total ? 'all' : 'shown'}`}
        </button>
        {selectedCount > 0 ? (
          <button type="button" onClick={onClearSelection} className="rounded-lg px-2 py-2 text-[11px] font-black uppercase tracking-wider text-[var(--qg-amber)]">Clear {selectedCount}</button>
        ) : null}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Selection bar + pagination                                          */
/* ------------------------------------------------------------------ */

export function SelectionBar({ count, vulnerable, critical, onReport, onClear }: { count: number; vulnerable: number; critical: number; onReport: () => void; onClear: () => void }) {
  if (count === 0) return null;
  return (
    <div className="sticky bottom-4 z-30 mx-auto flex w-full max-w-3xl flex-wrap items-center justify-between gap-3 rounded-xl border border-[var(--qg-amber)]/40 bg-[var(--qg-card-bg)] px-4 py-3 shadow-[0_18px_50px_rgba(0,0,0,0.35)] backdrop-blur-xl" role="region" aria-label="Selection">
      <div className="text-[12px] text-[var(--qg-dashboard-text)]">
        <span className="font-black">{nf(count)} asset{count === 1 ? '' : 's'} selected</span>
        <span className="ml-2 text-[var(--qg-text-muted)]">{nf(vulnerable)} vulnerable component{vulnerable === 1 ? '' : 's'} · {nf(critical)} critical</span>
      </div>
      <div className="flex items-center gap-2">
        <button type="button" onClick={onClear} className="rounded-md px-3 py-2 text-[11px] font-black uppercase tracking-wider text-[var(--qg-text-muted)] hover:text-[var(--qg-dashboard-text)]">Clear</button>
        <button type="button" onClick={onReport} className="inline-flex items-center gap-2 rounded-md bg-[var(--qg-amber)] px-4 py-2 text-[11px] font-black uppercase tracking-wider text-[var(--qg-on-accent)] transition hover:brightness-110">
          <FileText className="h-4 w-4" aria-hidden /> Generate report
        </button>
      </div>
    </div>
  );
}

function paginationItems(current: number, total: number): Array<number | '…'> {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const keep = new Set([1, 2, total - 1, total, current - 1, current, current + 1]);
  const pages = Array.from(keep).filter((p) => p >= 1 && p <= total).sort((a, b) => a - b);
  const items: Array<number | '…'> = [];
  let previous = 0;
  for (const page of pages) {
    if (page - previous > 1) items.push('…');
    items.push(page);
    previous = page;
  }
  return items;
}

export function Pagination({ page, pageCount, onPage, from, to, total }: { page: number; pageCount: number; onPage: (page: number) => void; from: number; to: number; total: number }) {
  if (pageCount <= 1) return null;
  return (
    <nav className="flex flex-wrap items-center justify-between gap-2" aria-label="Asset pages">
      <span className="text-[11px] text-[var(--qg-text-muted)]">Showing {nf(from)}–{nf(to)} of {nf(total)} assets, in the selected order.</span>
      <div className="flex items-center gap-1">
        <button type="button" onClick={() => onPage(Math.max(1, page - 1))} disabled={page === 1} aria-label="Previous page" className="grid h-8 w-8 place-items-center rounded-md border border-[var(--qg-card-border)] text-[var(--qg-dashboard-text-soft)] disabled:opacity-35"><ChevronLeft className="h-4 w-4" /></button>
        {paginationItems(page, pageCount).map((item, index) =>
          item === '…' ? (
            <span key={`gap-${index}`} className="px-1 text-[11px] text-[var(--qg-text-muted)]">…</span>
          ) : (
            <button key={item} type="button" onClick={() => onPage(item)} aria-current={item === page ? 'page' : undefined} className={`h-8 min-w-8 rounded-md border px-2 text-[11px] font-black ${item === page ? 'border-[var(--qg-amber)]/60 bg-[var(--qg-amber)]/15 text-[var(--qg-amber)]' : 'border-[var(--qg-card-border)] text-[var(--qg-dashboard-text-soft)]'}`}>{item}</button>
          ),
        )}
        <button type="button" onClick={() => onPage(Math.min(pageCount, page + 1))} disabled={page === pageCount} aria-label="Next page" className="grid h-8 w-8 place-items-center rounded-md border border-[var(--qg-card-border)] text-[var(--qg-dashboard-text-soft)] disabled:opacity-35"><ChevronRight className="h-4 w-4" /></button>
      </div>
    </nav>
  );
}
