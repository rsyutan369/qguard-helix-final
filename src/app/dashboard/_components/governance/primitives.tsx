'use client';

/* ==================================================================== */
/* Shared design system for the Enterprise Governance Command Layer.    */
/*                                                                      */
/* Layers on the Observability primitives rather than forking them, so  */
/* a panel edge, a tone or a table cell is the same object here as on   */
/* TLS Telemetry and the Trust suite. What this module adds is the      */
/* vocabulary governance needs and they do not: control status, the     */
/* measured/not-measured distinction, evidence integrity and retention, */
/* the traceability chain, and the reconciliation report.               */
/*                                                                      */
/* ONE RULE RUNS THROUGH ALL OF IT: a number that was not measured is   */
/* rendered as "Not assessed", never as a zero. `ScoreTile` and         */
/* `StatusBadge` enforce that at the component level so no page can     */
/* accidentally print a fabricated 0% or 100%.                          */
/* ==================================================================== */

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  CircleSlash,
  FileCheck2,
  HelpCircle,
  Link2,
  MinusCircle,
  ShieldAlert,
  XCircle,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  Panel,
  PanelEmpty,
  Pill,
  TONE,
  Term,
  fmtNumber,
  fmtPercent,
  relativeTime,
  absoluteTime,
  type Tone,
} from '../observability/primitives';
import {
  CONTROL_DOMAIN_LABEL,
  CONTROL_STATUS_LABEL,
  AUDIT_CATEGORY_LABEL,
  GAP_KIND_LABEL,
  POLICY_CATEGORY_LABEL,
  type AuditCategory,
  type ControlDomain,
  type ControlStatus,
  type FreshnessState,
  type GovernanceScore,
  type GovernanceSeverity,
  type GovernanceTelemetry,
  type GapKind,
  type IntegrityState,
  type PolicyCategory,
  type PolicyEnforcement,
  type ReconciliationReport,
  type RetentionState,
} from '@/lib/governance/types';

export { CONTROL_DOMAIN_LABEL, CONTROL_STATUS_LABEL, AUDIT_CATEGORY_LABEL, GAP_KIND_LABEL, POLICY_CATEGORY_LABEL };

/* ------------------------------------------------------------------ */
/* Shell + motion                                                      */
/* ------------------------------------------------------------------ */

export const GOV_SHELL_CLASS = 'tlspki-shell governance-shell min-h-screen space-y-4 p-3 lg:p-5';

/**
 * Motion here is functional, not decorative: entrances stagger so a dense grid
 * resolves in reading order, and the live dot pulses only while the stream is
 * genuinely open. Everything collapses under `prefers-reduced-motion`.
 */
export const GOV_SHELL_CSS = `
  .governance-shell { background: var(--qg-dashboard-bg, #0a1020); }
  .governance-shell .gov-rise { animation: govRise 380ms cubic-bezier(0.22, 1, 0.36, 1) both; }
  @keyframes govRise { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
  .governance-shell .gov-live-dot { animation: govPulse 2.2s ease-in-out infinite; }
  @keyframes govPulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.35; } }
  .governance-shell .gov-chain::after {
    content: ''; position: absolute; left: 0; right: 0; bottom: -1px; height: 1px;
    background: linear-gradient(90deg, rgba(34,211,238,0.35), transparent);
  }
  .qg-theme-light .governance-shell .gov-unmeasured { color: #64748b !important; }
  @media (prefers-reduced-motion: reduce) {
    .governance-shell *, .governance-shell *::before, .governance-shell *::after {
      animation-duration: 0.001ms !important;
      transition-duration: 0.001ms !important;
    }
  }
`;

export function riseStyle(index: number, step = 40, cap = 12): React.CSSProperties {
  return { animationDelay: `${Math.min(index, cap) * step}ms` };
}

/* ------------------------------------------------------------------ */
/* Status vocabulary                                                   */
/* ------------------------------------------------------------------ */

export const CONTROL_STATUS_TONE: Record<ControlStatus, Tone> = {
  compliant: 'good',
  partial: 'warning',
  'non-compliant': 'critical',
  'not-assessed': 'neutral',
  'not-applicable': 'info',
};

const CONTROL_STATUS_ICON: Record<ControlStatus, LucideIcon> = {
  compliant: CheckCircle2,
  partial: AlertTriangle,
  'non-compliant': XCircle,
  'not-assessed': HelpCircle,
  'not-applicable': MinusCircle,
};

export const CONTROL_STATUS_HINT: Record<ControlStatus, string> = {
  compliant: 'Every in-scope subject satisfies this control.',
  partial: 'Some in-scope subjects satisfy this control and others do not.',
  'non-compliant': 'In-scope subjects fail this control.',
  'not-assessed': 'No tenant evidence exists to judge this control. This is NOT a failure — connect the evidence source to bring it into scope.',
  'not-applicable': 'Scoped out by an approved, time-bound exception. Excluded from the compliance score, but the exception itself is governed.',
};

export function StatusBadge({ status, size = 'md', reason }: { status: ControlStatus; size?: 'sm' | 'md'; reason?: string }) {
  const Icon = CONTROL_STATUS_ICON[status];
  const tone = TONE[CONTROL_STATUS_TONE[status]];
  return (
    <span
      title={reason || CONTROL_STATUS_HINT[status]}
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border font-black uppercase tracking-wider',
        tone.border,
        tone.soft,
        tone.text,
        size === 'sm' ? 'px-1.5 py-0.5 text-[8.5px]' : 'px-2 py-0.5 text-[9.5px]',
      )}
    >
      <Icon className={size === 'sm' ? 'h-2.5 w-2.5' : 'h-3 w-3'} aria-hidden="true" />
      {CONTROL_STATUS_LABEL[status]}
    </span>
  );
}

export const SEVERITY_TONE: Record<GovernanceSeverity, Tone> = {
  critical: 'critical',
  high: 'critical',
  medium: 'warning',
  low: 'neutral',
};

export function SeverityBadge({ severity }: { severity: GovernanceSeverity | null }) {
  if (!severity) return <span className="font-mono text-[10px] text-white/25">—</span>;
  return (
    <Pill tone={SEVERITY_TONE[severity]} className="uppercase">
      {severity}
    </Pill>
  );
}

/* ---- Freshness --------------------------------------------------- */

const FRESHNESS_TONE: Record<FreshnessState, Tone> = {
  fresh: 'good',
  aging: 'warning',
  stale: 'critical',
  unknown: 'neutral',
};

const FRESHNESS_LABEL: Record<FreshnessState, string> = {
  fresh: 'Fresh',
  aging: 'Aging',
  stale: 'Stale',
  unknown: 'Undated',
};

export function FreshnessChip({ state, ageDays }: { state: FreshnessState; ageDays?: number | null }) {
  return (
    <Pill
      tone={FRESHNESS_TONE[state]}
      title={
        state === 'unknown'
          ? 'The source record carries no usable timestamp, so age cannot be established.'
          : `Evidence is ${ageDays ?? '—'} day(s) old. Fresh ≤ 30d, aging ≤ 90d, stale beyond that.`
      }
    >
      {FRESHNESS_LABEL[state]}
      {typeof ageDays === 'number' ? <span className="font-mono opacity-70">{ageDays}d</span> : null}
    </Pill>
  );
}

/* ---- Integrity + retention --------------------------------------- */

const INTEGRITY_TONE: Record<IntegrityState, Tone> = {
  verified: 'good',
  mismatch: 'critical',
  unanchored: 'warning',
  unavailable: 'neutral',
};

const INTEGRITY_LABEL: Record<IntegrityState, string> = {
  verified: 'Verified',
  mismatch: 'Digest mismatch',
  unanchored: 'Not anchored',
  unavailable: 'Unavailable',
};

/**
 * The integrity badge deliberately never says "immutable".
 *
 * A verified digest proves the source record has not changed since it was
 * anchored. It does not make the row immutable and it is not third-party
 * notarisation — the anchor lives in the same database. The tooltip carries the
 * engine's own `assurance` sentence so the claim on screen is exactly the claim
 * the backend can defend.
 */
export function IntegrityBadge({ state, assurance }: { state: IntegrityState; assurance?: string }) {
  return (
    <Pill tone={INTEGRITY_TONE[state]} title={assurance}>
      {INTEGRITY_LABEL[state]}
    </Pill>
  );
}

const RETENTION_TONE: Record<RetentionState, Tone> = {
  active: 'good',
  expiring: 'warning',
  expired: 'critical',
  unspecified: 'neutral',
};

const RETENTION_LABEL: Record<RetentionState, string> = {
  active: 'Retained',
  expiring: 'Expiring',
  expired: 'Past retention',
  unspecified: 'No window',
};

export function RetentionBadge({ state, expiresAt, periodDays }: { state: RetentionState; expiresAt?: string | null; periodDays?: number | null }) {
  return (
    <Pill
      tone={RETENTION_TONE[state]}
      title={
        state === 'unspecified'
          ? 'No retention window applies to this evidence class, or the record has no usable timestamp.'
          : `Platform retention window ${periodDays ?? '—'} days${expiresAt ? ` · expires ${absoluteTime(expiresAt)}` : ''}.`
      }
    >
      {RETENTION_LABEL[state]}
    </Pill>
  );
}

/* ---- Policy enforcement ------------------------------------------- */

const ENFORCEMENT_TONE: Record<PolicyEnforcement, Tone> = {
  enforced: 'good',
  monitored: 'info',
  disabled: 'critical',
};

export function EnforcementBadge({ enforcement }: { enforcement: PolicyEnforcement }) {
  return (
    <Pill
      tone={ENFORCEMENT_TONE[enforcement]}
      title={
        enforcement === 'disabled'
          ? 'This rule is off. Nothing is evaluated against it, so its subjects are unmeasured rather than compliant.'
          : enforcement === 'enforced'
            ? 'Violations of this rule are treated as control failures.'
            : 'Violations are reported but do not fail the control outright.'
      }
    >
      {enforcement}
    </Pill>
  );
}

/* ------------------------------------------------------------------ */
/* Module navigation                                                   */
/* ------------------------------------------------------------------ */

const MODULE_TABS = [
  { path: '/dashboard/compliance', label: 'Compliance', blurb: 'Control coverage, gaps and the evidence behind each status' },
  { path: '/dashboard/quantum-governance', label: 'Quantum Governance', blurb: 'Cryptographic policy, PQC posture and risk appetite' },
  { path: '/dashboard/audit-vault', label: 'Audit Vault', blurb: 'Audit trail, evidence integrity, retention and custody' },
  { path: '/dashboard/regulatory-mapping', label: 'Regulatory Mapping', blurb: 'Frameworks, requirements and their control coverage' },
];

export function GovernanceModuleNav() {
  const { pathname } = useLocation();
  return (
    <nav aria-label="Governance modules" className="flex flex-wrap gap-1.5">
      {MODULE_TABS.map((tab) => {
        const isActive = pathname === tab.path;
        return (
          <Link
            key={tab.path}
            to={tab.path}
            title={tab.blurb}
            aria-current={isActive ? 'page' : undefined}
            className={cn(
              'rounded-lg border px-3 py-1.5 text-[10px] font-black uppercase tracking-wider transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
              isActive
                ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200'
                : 'border-white/12 bg-white/[0.03] text-white/55 hover:bg-white/[0.08] hover:text-white/80',
            )}
          >
            {tab.label}
          </Link>
        );
      })}
    </nav>
  );
}

/* ------------------------------------------------------------------ */
/* Header                                                              */
/* ------------------------------------------------------------------ */

export function LiveDot({ live }: { live: boolean }) {
  return (
    <span
      className={cn('inline-block h-1.5 w-1.5 rounded-full', live ? 'gov-live-dot bg-emerald-400' : 'bg-white/25')}
      aria-hidden="true"
    />
  );
}

/**
 * The connection chip.
 *
 * Reads "Live" only while the stream is genuinely open (§17). A dropped stream
 * shows "Reconnecting" with the last successful sync time, so nothing on the
 * page can be mistaken for current.
 */
export function ConnectionChip({ live, lastSyncedAt, onReconnect }: { live: boolean; lastSyncedAt: string | null; onReconnect: () => void }) {
  return (
    <button
      type="button"
      onClick={onReconnect}
      title={live ? 'Streaming live from the governance model.' : 'The live stream is not connected. Click to re-fetch.'}
      className={cn(
        'inline-flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-[10px] font-black uppercase tracking-wider transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
        live ? 'border-emerald-400/35 bg-emerald-500/10 text-emerald-200' : 'border-amber-400/35 bg-amber-500/10 text-amber-200',
      )}
    >
      <LiveDot live={live} />
      {live ? 'Live' : 'Reconnecting'}
      <span className="font-mono text-[9.5px] font-semibold normal-case tracking-normal opacity-70">
        {lastSyncedAt ? relativeTime(lastSyncedAt) : 'never'}
      </span>
    </button>
  );
}

export function GovernanceHeader({
  icon: Icon,
  title,
  accent,
  subtitle,
  right,
}: {
  icon: LucideIcon;
  title: string;
  accent: string;
  subtitle: string;
  right?: ReactNode;
}) {
  return (
    <header className="flex flex-col gap-3 border-b border-white/10 pb-3.5 xl:flex-row xl:items-end xl:justify-between">
      <div className="flex items-center gap-3">
        <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300 shadow-[0_0_28px_rgba(34,211,238,0.2)]">
          <Icon className="h-5 w-5" aria-hidden="true" />
        </div>
        <div className="min-w-0">
          <h1 className="text-2xl font-black uppercase leading-none tracking-tight text-white lg:text-[26px]">
            {title} <span className="text-cyan-300">{accent}</span>
          </h1>
          <p className="mt-1.5 max-w-3xl text-[12px] font-medium leading-relaxed text-white/45">{subtitle}</p>
        </div>
      </div>
      {right ? <div className="flex flex-wrap items-center gap-2">{right}</div> : null}
    </header>
  );
}

/**
 * Stale banner — shown when the newest governance observation is more than a
 * day old. The page still renders its last good model; this states plainly that
 * the model describes an older estate.
 */
export function StaleBanner({ hours, onRefresh }: { hours: number; onRefresh: () => void }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-400/30 bg-amber-500/[0.07] px-4 py-2.5">
      <p className="flex items-center gap-2 text-[11px] font-semibold text-amber-200">
        <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        Newest governance evidence is {hours}h old. Every status below describes the estate as of then, not as of now.
      </p>
      <button
        type="button"
        onClick={onRefresh}
        className="rounded-md border border-amber-400/40 bg-amber-500/10 px-2.5 py-1 text-[10px] font-black uppercase tracking-wider text-amber-100 transition hover:bg-amber-500/20"
      >
        Re-fetch
      </button>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Score tiles                                                         */
/* ------------------------------------------------------------------ */

const SCORE_TONE: Record<GovernanceScore['tone'], Tone> = {
  good: 'good',
  warning: 'warning',
  critical: 'critical',
  neutral: 'neutral',
};

/**
 * Non-interactive hint marker for use INSIDE a clickable tile.
 *
 * `Term` renders a real <button> so it can be opened by keyboard. Nesting that
 * inside a tile that is itself a <button> or <a> is invalid HTML and React
 * reports it as a hydration error. Where the whole tile is the click target the
 * hint therefore degrades to a native `title` tooltip, which still reaches
 * mouse and screen-reader users without breaking the document.
 */
function HintMark({ hint, label }: { hint: string; label: string }) {
  return (
    <span
      title={hint}
      aria-label={`${label}: ${hint}`}
      role="note"
      className="inline-grid h-3.5 w-3.5 place-items-center rounded-full text-white/35"
    >
      <HelpCircle className="h-3.5 w-3.5" aria-hidden="true" />
    </span>
  );
}

/**
 * A headline number with everything needed to defend it.
 *
 * When `measured` is false the tile renders "Not assessed" and the basis
 * sentence explaining why — it never falls back to 0, which would read as total
 * failure, or to 100, which would read as full compliance.
 */
export function ScoreTile({ score, onOpen }: { score: GovernanceScore; onOpen?: () => void }) {
  const tone = TONE[SCORE_TONE[score.tone]];
  // The tile becomes a <button>/<a> when it is actionable, so the hint must not
  // be a nested <button> — see HintMark.
  const interactive = Boolean(onOpen) || Boolean(score.route);
  const body = (
    <>
      <div className="flex items-center gap-1.5 text-[9.5px] font-black uppercase tracking-[0.12em] text-white/45">
        {score.label}
        {interactive ? <HintMark hint={score.hint} label={score.label} /> : <Term hint={score.hint} label={score.label} />}
      </div>
      <div className={cn('mt-2 text-[26px] font-black leading-none', score.measured ? tone.text : 'gov-unmeasured text-white/35')}>
        {score.measured
          ? score.unit === 'percent'
            ? fmtPercent(score.value)
            : fmtNumber(score.value)
          : 'Not assessed'}
      </div>
      <div className="mt-1.5 line-clamp-2 text-[10px] font-medium leading-snug text-white/40" title={score.basis}>
        {score.basis}
      </div>
      {score.measured && score.denominator > 0 ? (
        <div className="mt-2 h-1 overflow-hidden rounded-full bg-white/10">
          <span
            className="block h-full rounded-full transition-[width] duration-500"
            style={{
              width: `${Math.max(2, Math.min(100, score.unit === 'percent' ? (score.value ?? 0) : (score.numerator / Math.max(1, score.denominator)) * 100))}%`,
              backgroundColor: tone.hex,
            }}
          />
        </div>
      ) : null}
    </>
  );

  if (onOpen) {
    return (
      <button
        type="button"
        onClick={onOpen}
        className="qg-executive-panel gov-rise relative block overflow-hidden rounded-xl p-4 text-left text-white transition hover:-translate-y-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
      >
        {body}
      </button>
    );
  }
  if (score.route) {
    return (
      <Link
        to={score.route}
        className="qg-executive-panel gov-rise relative block overflow-hidden rounded-xl p-4 text-white no-underline transition hover:-translate-y-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
      >
        {body}
      </Link>
    );
  }
  return <div className="qg-executive-panel gov-rise relative overflow-hidden rounded-xl p-4 text-white">{body}</div>;
}

/**
 * Compact counter used for drill-down affordances (§15): "Critical gaps: 27",
 * clicking shows the actual 27 records.
 */
export function CountTile({
  label,
  value,
  detail,
  tone = 'neutral',
  onOpen,
  hint,
  unmeasured,
}: {
  label: string;
  value: number | null;
  detail?: string;
  tone?: Tone;
  onOpen?: () => void;
  hint?: string;
  unmeasured?: boolean;
}) {
  const t = TONE[tone];
  const inner = (
    <>
      <div className="flex items-center gap-1.5 text-[9px] font-black uppercase tracking-[0.12em] text-white/45">
        {label}
        {hint ? (onOpen ? <HintMark hint={hint} label={label} /> : <Term hint={hint} label={label} />) : null}
      </div>
      <div className={cn('mt-1.5 text-[20px] font-black leading-none', unmeasured ? 'text-white/35' : t.text)}>
        {unmeasured ? 'Not measured' : fmtNumber(value)}
      </div>
      {detail ? <div className="mt-1 text-[9.5px] font-medium leading-snug text-white/40">{detail}</div> : null}
    </>
  );
  if (onOpen) {
    return (
      <button
        type="button"
        onClick={onOpen}
        className="qg-executive-panel rounded-lg p-3 text-left transition hover:-translate-y-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
      >
        {inner}
      </button>
    );
  }
  return <div className="qg-executive-panel rounded-lg p-3">{inner}</div>;
}

/* ------------------------------------------------------------------ */
/* Coverage bar — measured vs unmeasured, side by side                 */
/* ------------------------------------------------------------------ */

/**
 * The single most important chart on the Compliance page: it shows compliant,
 * partial, failing and NOT ASSESSED as four distinct segments. Folding
 * "not assessed" into either end is exactly how a compliance dashboard starts
 * lying, so the segment is always drawn.
 */
export function CoverageBar({
  compliant,
  partial,
  failing,
  unassessed,
  notApplicable = 0,
  onSegment,
}: {
  compliant: number;
  partial: number;
  failing: number;
  unassessed: number;
  notApplicable?: number;
  onSegment?: (status: ControlStatus) => void;
}) {
  const segments: Array<{ status: ControlStatus; count: number; tone: Tone }> = [
    { status: 'compliant', count: compliant, tone: 'good' },
    { status: 'partial', count: partial, tone: 'warning' },
    { status: 'non-compliant', count: failing, tone: 'critical' },
    { status: 'not-assessed', count: unassessed, tone: 'neutral' },
    { status: 'not-applicable', count: notApplicable, tone: 'info' },
  ];
  const total = segments.reduce((sum, segment) => sum + segment.count, 0);
  if (!total) return <PanelEmpty>No controls in scope.</PanelEmpty>;

  return (
    <div className="space-y-2.5">
      <div className="flex h-3 overflow-hidden rounded-full border border-white/10 bg-white/5">
        {segments
          .filter((segment) => segment.count > 0)
          .map((segment) => (
            <button
              key={segment.status}
              type="button"
              onClick={onSegment ? () => onSegment(segment.status) : undefined}
              title={`${CONTROL_STATUS_LABEL[segment.status]}: ${segment.count} of ${total}`}
              aria-label={`${CONTROL_STATUS_LABEL[segment.status]}: ${segment.count} of ${total}`}
              className={cn('h-full transition-opacity hover:opacity-80', onSegment ? 'cursor-pointer' : 'cursor-default')}
              style={{ width: `${(segment.count / total) * 100}%`, backgroundColor: TONE[segment.tone].hex }}
            />
          ))}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1.5">
        {segments
          .filter((segment) => segment.count > 0)
          .map((segment) => (
            <button
              key={segment.status}
              type="button"
              onClick={onSegment ? () => onSegment(segment.status) : undefined}
              className="flex items-center gap-1.5 text-[10px] font-semibold text-white/55 transition hover:text-white/85"
            >
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: TONE[segment.tone].hex }} aria-hidden="true" />
              {CONTROL_STATUS_LABEL[segment.status]}
              <span className="font-mono tabular-nums text-white/75">{segment.count}</span>
            </button>
          ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Trend                                                               */
/* ------------------------------------------------------------------ */

export interface TrendSeries {
  key: string;
  label: string;
  tone: Tone;
  value: (point: { evidence: number; auditEvents: number; findingsOpened: number; findingsResolved: number; violations: number }) => number;
}

/**
 * 30-day activity trend.
 *
 * Days outside the observed window are drawn as a hatched "no data" column
 * rather than a zero bar — a zero here would claim "we measured nothing
 * happened", which is a different statement from "we have no observations".
 */
export function ActivityTrend({
  points,
  series,
  height = 96,
}: {
  points: Array<{ label: string; date: string; evidence: number; auditEvents: number; findingsOpened: number; findingsResolved: number; violations: number; observed: boolean }>;
  series: TrendSeries[];
  height?: number;
}) {
  const max = useMemo(
    () => Math.max(1, ...points.flatMap((point) => series.map((entry) => entry.value(point)))),
    [points, series],
  );
  const observed = points.filter((point) => point.observed);
  if (!observed.length) {
    return <PanelEmpty>No dated governance activity has been observed yet.</PanelEmpty>;
  }

  return (
    <div className="space-y-2">
      <div className="flex items-end gap-[3px]" style={{ height }}>
        {points.map((point) => {
          const total = series.reduce((sum, entry) => sum + entry.value(point), 0);
          return (
            <div
              key={point.date}
              className="group relative flex flex-1 flex-col justify-end"
              title={
                point.observed
                  ? `${point.label} — ${series.map((entry) => `${entry.label}: ${entry.value(point)}`).join(' · ')}`
                  : `${point.label} — outside the observed evidence window`
              }
            >
              {point.observed ? (
                total > 0 ? (
                  series
                    .filter((entry) => entry.value(point) > 0)
                    .map((entry) => (
                      <span
                        key={entry.key}
                        className="w-full"
                        style={{
                          height: `${Math.max(2, (entry.value(point) / max) * height)}px`,
                          backgroundColor: TONE[entry.tone].hex,
                        }}
                      />
                    ))
                ) : (
                  <span className="h-[2px] w-full bg-white/12" />
                )
              ) : (
                <span
                  className="w-full rounded-sm"
                  style={{
                    height: `${height}px`,
                    backgroundImage:
                      'repeating-linear-gradient(45deg, rgba(255,255,255,0.05) 0 2px, transparent 2px 5px)',
                  }}
                />
              )}
            </div>
          );
        })}
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap gap-3">
          {series.map((entry) => (
            <span key={entry.key} className="flex items-center gap-1.5 text-[9.5px] font-bold uppercase tracking-wider text-white/45">
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: TONE[entry.tone].hex }} aria-hidden="true" />
              {entry.label}
            </span>
          ))}
          <span className="flex items-center gap-1.5 text-[9.5px] font-bold uppercase tracking-wider text-white/30">
            <span
              className="h-2 w-2 rounded-sm"
              style={{ backgroundImage: 'repeating-linear-gradient(45deg, rgba(255,255,255,0.25) 0 1px, transparent 1px 3px)' }}
              aria-hidden="true"
            />
            No observations
          </span>
        </div>
        <span className="font-mono text-[9.5px] text-white/30">
          {points[0]?.label} – {points[points.length - 1]?.label}
        </span>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Traceability chain (§9, §15)                                        */
/* ------------------------------------------------------------------ */

export interface ChainStep {
  label: string;
  value: string;
  href?: string;
  onClick?: () => void;
  muted?: boolean;
}

/**
 * Renders the §9 chain:
 *   Framework → Requirement → Control → Asset → Finding → Evidence → Audit Event
 *
 * Every step that resolves to a real record is clickable, so a user can walk the
 * chain in either direction without losing context.
 */
export function TraceChain({ steps }: { steps: ChainStep[] }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {steps.map((step, index) => {
        const content = (
          <span
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[10px] font-semibold transition',
              step.muted
                ? 'border-white/8 bg-white/[0.02] text-white/30'
                : 'border-cyan-400/25 bg-cyan-500/[0.07] text-cyan-100 hover:bg-cyan-500/15',
            )}
          >
            <span className="text-[8.5px] font-black uppercase tracking-wider opacity-55">{step.label}</span>
            <span className="max-w-[180px] truncate">{step.value}</span>
          </span>
        );
        return (
          <span key={`${step.label}-${index}`} className="inline-flex items-center gap-1.5">
            {step.href && !step.muted ? (
              <Link to={step.href} className="no-underline">
                {content}
              </Link>
            ) : step.onClick && !step.muted ? (
              <button type="button" onClick={step.onClick} className="focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
                {content}
              </button>
            ) : (
              content
            )}
            {index < steps.length - 1 ? <ArrowRight className="h-3 w-3 shrink-0 text-white/20" aria-hidden="true" /> : null}
          </span>
        );
      })}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Gap card                                                            */
/* ------------------------------------------------------------------ */

const GAP_TONE: Record<GovernanceSeverity, Tone> = SEVERITY_TONE;

export function GapCard({
  gap,
  index,
  onOpen,
}: {
  gap: {
    id: string;
    kind: GapKind;
    title: string;
    detail: string;
    severity: GovernanceSeverity;
    count: number;
    domain: ControlDomain;
    route: string;
    impact: string;
    frameworkIds: string[];
    controlIds: string[];
  };
  index: number;
  onOpen?: () => void;
}) {
  const tone = TONE[GAP_TONE[gap.severity]];
  return (
    <article
      className="gov-rise rounded-xl border border-white/10 bg-white/[0.02] p-3.5 transition hover:border-white/20"
      style={riseStyle(index)}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <Pill tone={GAP_TONE[gap.severity]}>{gap.severity}</Pill>
            <Pill tone="neutral">{GAP_KIND_LABEL[gap.kind]}</Pill>
            <span className="text-[9px] font-black uppercase tracking-wider text-white/35">{CONTROL_DOMAIN_LABEL[gap.domain]}</span>
          </div>
          <h3 className="mt-1.5 text-[12.5px] font-bold leading-snug text-white">{gap.title}</h3>
        </div>
        <span className={cn('shrink-0 font-mono text-[20px] font-black leading-none tabular-nums', tone.text)}>{fmtNumber(gap.count)}</span>
      </div>
      <p className="mt-1.5 text-[11px] leading-relaxed text-white/50">{gap.detail}</p>
      <p className="mt-1.5 flex items-start gap-1.5 text-[10.5px] leading-relaxed text-white/40">
        <ShieldAlert className="mt-[1px] h-3 w-3 shrink-0 text-cyan-300/60" aria-hidden="true" />
        {gap.impact}
      </p>
      <div className="mt-2.5 flex flex-wrap items-center gap-2">
        {onOpen ? (
          <button
            type="button"
            onClick={onOpen}
            className="inline-flex items-center gap-1 rounded-md border border-white/12 bg-white/[0.04] px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-white/65 transition hover:bg-white/[0.08]"
          >
            Inspect <ChevronRight className="h-3 w-3" aria-hidden="true" />
          </button>
        ) : null}
        <Link
          to={gap.route}
          className="inline-flex items-center gap-1 rounded-md border border-cyan-400/30 bg-cyan-500/10 px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 no-underline transition hover:bg-cyan-500/20"
        >
          Remediate <ArrowRight className="h-3 w-3" aria-hidden="true" />
        </Link>
        {gap.frameworkIds.length ? (
          <span className="text-[9.5px] font-semibold text-white/30">
            Affects {gap.frameworkIds.length} framework{gap.frameworkIds.length === 1 ? '' : 's'}
          </span>
        ) : null}
      </div>
    </article>
  );
}

/* ------------------------------------------------------------------ */
/* Basis / provenance line                                             */
/* ------------------------------------------------------------------ */

/** The one-line "how this number was derived" statement under a panel. */
export function Basis({ children }: { children: ReactNode }) {
  return (
    <p className="mt-2.5 flex items-start gap-1.5 border-t border-white/[0.06] pt-2 text-[10px] font-medium leading-relaxed text-white/35">
      <Link2 className="mt-[2px] h-3 w-3 shrink-0 text-cyan-300/50" aria-hidden="true" />
      {children}
    </p>
  );
}

/* ------------------------------------------------------------------ */
/* Reconciliation (§16)                                                */
/* ------------------------------------------------------------------ */

/**
 * The reconciliation report, rendered so the "these pages agree" claim is
 * checkable rather than asserted. Every estate figure names the canonical
 * producer it was mirrored from and the other surfaces that publish it.
 */
export function ReconciliationPanel({ report }: { report: ReconciliationReport }) {
  return (
    <div className="space-y-3">
      {report.discrepancies.length ? (
        <div className="rounded-lg border border-amber-400/30 bg-amber-500/[0.07] p-3">
          <p className="text-[10.5px] font-bold uppercase tracking-wider text-amber-200">
            {report.discrepancies.length} figure(s) differ in scope
          </p>
          <ul className="mt-1.5 space-y-1">
            {report.discrepancies.map((entry) => (
              <li key={entry} className="text-[10.5px] leading-relaxed text-amber-100/80">
                {entry}
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-400/25 bg-emerald-500/[0.06] px-3 py-2">
          <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-300" aria-hidden="true" />
          <p className="text-[10.5px] font-semibold text-emerald-100">
            Every figure reconciles with its canonical source.
          </p>
        </div>
      )}

      <div className="-mx-1 overflow-x-auto px-1">
        <table className="w-full text-left text-[11px]" style={{ minWidth: 720 }}>
          <thead>
            <tr>
              <th className="border-b border-white/10 px-2 py-1.5 text-[9px] font-black uppercase tracking-wider text-white/45">Metric</th>
              <th className="border-b border-white/10 px-2 py-1.5 text-right text-[9px] font-black uppercase tracking-wider text-white/45">Value</th>
              <th className="border-b border-white/10 px-2 py-1.5 text-[9px] font-black uppercase tracking-wider text-white/45">Canonical source</th>
              <th className="border-b border-white/10 px-2 py-1.5 text-[9px] font-black uppercase tracking-wider text-white/45">Also shown on</th>
            </tr>
          </thead>
          <tbody>
            {report.rows.map((row) => (
              <tr key={row.metric} className={row.agrees ? '' : 'bg-amber-500/[0.05]'}>
                <td className="border-b border-white/[0.06] px-2 py-1.5 align-top">
                  <div className="font-semibold text-white/80">{row.metric}</div>
                  <div className="mt-0.5 text-[10px] leading-snug text-white/35">{row.scopeNote}</div>
                </td>
                <td className="border-b border-white/[0.06] px-2 py-1.5 text-right align-top font-mono tabular-nums text-white/85">
                  {row.value === null ? '—' : fmtNumber(row.value)}
                </td>
                <td className="border-b border-white/[0.06] px-2 py-1.5 align-top font-mono text-[10px] text-cyan-200/70">{row.source}</td>
                <td className="border-b border-white/[0.06] px-2 py-1.5 align-top text-[10px] text-white/45">
                  {row.alsoShownOn.join(' · ') || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-[10px] leading-relaxed text-white/35">{report.note}</p>
      <p className="font-mono text-[9.5px] text-white/25">Generated {absoluteTime(report.generatedAt)}</p>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Provenance footer                                                   */
/* ------------------------------------------------------------------ */

const PIPELINE_COPY: Record<GovernanceTelemetry['pipelineStatus'], { label: string; tone: Tone; detail: string }> = {
  live: { label: 'Recent evidence', tone: 'good', detail: 'Governance evidence was recorded within the last 7 days.' },
  'inventory-only': {
    label: 'Inventory only',
    tone: 'warning',
    detail: 'Cryptographic inventory exists but no recent governance evidence has been recorded, so control statuses describe an older estate.',
  },
  'awaiting-evidence': {
    label: 'Awaiting evidence',
    tone: 'warning',
    detail: 'Collectors or connectors are configured but have not produced governance evidence yet.',
  },
  'no-sources': {
    label: 'No evidence sources',
    tone: 'critical',
    detail: 'No collector, connector or scan has been configured, so nothing can be assessed.',
  },
};

export function GovernanceProvenance({ telemetry }: { telemetry: GovernanceTelemetry | null }) {
  if (!telemetry) return null;
  const pipeline = PIPELINE_COPY[telemetry.pipelineStatus];
  const sources = Object.entries(telemetry.sourceCounts).filter(([, count]) => count > 0);

  return (
    <Panel>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-[11px] font-black uppercase tracking-[0.14em] text-white">Evidence provenance</h2>
        <Pill tone={pipeline.tone} title={pipeline.detail}>
          {pipeline.label}
        </Pill>
      </div>
      <p className="mt-2 text-[10.5px] leading-relaxed text-white/40">{pipeline.detail}</p>

      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-3 lg:grid-cols-4">
        {[
          { label: 'Collectors online', value: `${telemetry.agentsOnline}/${telemetry.agentsTotal}` },
          { label: 'Connectors active', value: `${telemetry.connectorsActive}/${telemetry.connectorsTotal}` },
          { label: 'Scans running', value: String(telemetry.runningScans) },
          { label: 'Last scan', value: relativeTime(telemetry.lastScanAt) },
          { label: 'Last runtime event', value: relativeTime(telemetry.lastRuntimeEventAt) },
          { label: 'Last audit event', value: relativeTime(telemetry.lastAuditEventAt) },
          { label: 'Last evidence', value: relativeTime(telemetry.lastEvidenceAt) },
          {
            label: 'Evidence anchoring',
            value: telemetry.anchoringAvailable ? 'Available' : 'Unavailable',
          },
        ].map((entry) => (
          <div key={entry.label}>
            <dt className="text-[9px] font-black uppercase tracking-wider text-white/35">{entry.label}</dt>
            <dd className="mt-0.5 font-mono text-[11px] tabular-nums text-white/70">{entry.value}</dd>
          </div>
        ))}
      </dl>

      {sources.length ? (
        <div className="mt-3 border-t border-white/[0.06] pt-2.5">
          <p className="text-[9px] font-black uppercase tracking-wider text-white/35">Source rows read this window</p>
          <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1">
            {sources.map(([table, count]) => (
              <span key={table} className="font-mono text-[10px] text-white/45">
                {table} <span className="text-white/70">{fmtNumber(count)}</span>
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {telemetry.absentSources.length ? (
        <p className="mt-2 text-[10px] leading-relaxed text-white/35">
          <span className="font-bold uppercase tracking-wider text-amber-300/70">Not available: </span>
          {telemetry.absentSources.join(', ')}. Figures using these sources may be incomplete.
        </p>
      ) : null}

      {telemetry.truncated ? (
        <p className="mt-2 text-[10px] leading-relaxed text-amber-200/70">
          At least one source hit its row cap this window. Headline estate counts come from the canonical assessment, not
          from the number of rows fetched here.
        </p>
      ) : null}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* States                                                              */
/* ------------------------------------------------------------------ */

export function GovernanceSkeleton({ rows = 4, height = 64 }: { rows?: number; height?: number }) {
  return (
    <div className="space-y-2" aria-hidden="true">
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="animate-pulse rounded-lg bg-white/[0.05]" style={{ height }} />
      ))}
    </div>
  );
}

export function ScoreSkeleton({ count = 5 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 xl:grid-cols-5" aria-hidden="true">
      {Array.from({ length: count }).map((_, index) => (
        <div key={index} className="h-[110px] animate-pulse rounded-xl bg-white/[0.05]" />
      ))}
    </div>
  );
}

export function GovernanceError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <Panel className="border-red-500/25">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-start gap-2.5">
          <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-300" aria-hidden="true" />
          <div>
            <h2 className="text-[12px] font-black uppercase tracking-wider text-white">Governance model unavailable</h2>
            <p className="mt-1 text-[11px] leading-relaxed text-white/50">{message}</p>
          </div>
        </div>
        <button
          type="button"
          onClick={onRetry}
          className="rounded-md border border-white/15 bg-white/[0.05] px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-white/70 transition hover:bg-white/[0.1]"
        >
          Retry
        </button>
      </div>
    </Panel>
  );
}

/**
 * Empty state for a tenant with no evidence at all.
 *
 * States plainly that nothing has been assessed — and gives the next action —
 * rather than rendering a dashboard of zeros that reads as total failure.
 */
export function NoEvidenceState({
  title,
  detail,
  actions,
}: {
  title: string;
  detail: string;
  actions: Array<{ label: string; href: string; primary?: boolean }>;
}) {
  return (
    <Panel>
      <div className="flex flex-col items-center gap-3 py-8 text-center">
        <div className="grid h-12 w-12 place-items-center rounded-xl border border-cyan-400/25 bg-cyan-500/10 text-cyan-300">
          <FileCheck2 className="h-5 w-5" aria-hidden="true" />
        </div>
        <div className="max-w-lg">
          <h2 className="text-[14px] font-black uppercase tracking-wider text-white">{title}</h2>
          <p className="mt-2 text-[11.5px] leading-relaxed text-white/45">{detail}</p>
        </div>
        <div className="mt-1 flex flex-wrap justify-center gap-2">
          {actions.map((action) => (
            <Link
              key={action.href}
              to={action.href}
              className={cn(
                'inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-[10.5px] font-black uppercase tracking-wider no-underline transition',
                action.primary
                  ? 'border-cyan-400/40 bg-cyan-500/15 text-cyan-100 hover:bg-cyan-500/25'
                  : 'border-white/12 bg-white/[0.04] text-white/60 hover:bg-white/[0.08]',
              )}
            >
              {action.label} <ArrowRight className="h-3 w-3" aria-hidden="true" />
            </Link>
          ))}
        </div>
      </div>
    </Panel>
  );
}

/** Rendered where a section has data elsewhere but nothing under the filters. */
export function NoMatches({ onClear }: { onClear: () => void }) {
  return (
    <div className="flex min-h-[110px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-white/12 bg-white/[0.02] px-4 text-center">
      <CircleSlash className="h-4 w-4 text-white/25" aria-hidden="true" />
      <p className="text-[11px] font-medium text-white/40">No records match the current filters.</p>
      <button
        type="button"
        onClick={onClear}
        className="rounded-md border border-white/12 bg-white/[0.04] px-2.5 py-1 text-[9.5px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08]"
      >
        Clear filters
      </button>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Filter bar                                                          */
/* ------------------------------------------------------------------ */

export function FilterBar({
  children,
  activeCount,
  onReset,
}: {
  children: ReactNode;
  activeCount: number;
  onReset: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-xl border border-white/10 bg-white/[0.02] p-2.5">
      {children}
      {activeCount > 0 ? (
        <button
          type="button"
          onClick={onReset}
          className="ml-auto rounded-md border border-cyan-400/30 bg-cyan-500/10 px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/20"
        >
          Clear {activeCount}
        </button>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Small utilities re-exported so pages import from one place          */
/* ------------------------------------------------------------------ */

export { Panel, PanelEmpty, Pill, TONE, Term, fmtNumber, fmtPercent, relativeTime, absoluteTime };
export type { Tone };

/** Formats a possibly-null score for a table cell without inventing a zero. */
export function scoreCell(value: number | null, measured: boolean): ReactNode {
  if (!measured || value === null) {
    return <span className="font-mono text-[10.5px] text-white/25" title="Not measured — no tenant evidence for this control.">Not assessed</span>;
  }
  const tone = value >= 90 ? 'good' : value >= 70 ? 'warning' : 'critical';
  return <span className={cn('font-mono text-[11.5px] font-bold tabular-nums', TONE[tone as Tone].text)}>{value}%</span>;
}

/** Copies a digest to the clipboard, with the "copied" acknowledgement inline. */
export function CopyValue({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => {
          setCopied(true);
          if (timer.current) clearTimeout(timer.current);
          timer.current = setTimeout(() => setCopied(false), 1600);
        });
      }}
      title={`Copy ${label || 'value'}`}
      className="max-w-full truncate rounded border border-white/10 bg-black/30 px-1.5 py-0.5 font-mono text-[10px] text-white/60 transition hover:border-cyan-400/30 hover:text-cyan-200"
    >
      {copied ? 'Copied' : value}
    </button>
  );
}
