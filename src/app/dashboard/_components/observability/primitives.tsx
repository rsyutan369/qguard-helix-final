'use client';

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  AlertTriangle,
  ChevronRight,
  HelpCircle,
  Info,
  RefreshCw,
  ShieldCheck,
  WifiOff,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { POSTURE_LABEL } from '@/lib/tls-pki/classify';
import type { PipelineStatus, PqcPosture, RiskLevel, Severity } from '@/lib/tls-pki/types';

/* ------------------------------------------------------------------ */
/* Domain-neutral shapes                                               */
/* ------------------------------------------------------------------ */

/*
 * These primitives serve BOTH the transport suite and Encryption Monitoring,
 * which model evidence with different source unions. Binding the design system
 * to one domain's enum would force the other to widen its own types to satisfy
 * a rendering concern. The components therefore accept the structural minimum
 * they actually read.
 */

export interface EvidenceLike {
  /** Domain-specific source key; unknown values are title-cased for display. */
  source: string;
  recordId: string;
  table: string;
  observedAt: string | null;
  detail: string;
}

export interface TelemetryLike {
  pipelineStatus: PipelineStatus;
  agentsOnline: number;
  agentsTotal: number;
  connectorsActive: number;
  connectorsTotal: number;
  runningScans: number;
  lastScanAt: string | null;
  lastRuntimeEventAt: string | null;
  sourceCounts: Record<string, number>;
  truncated: boolean;
  /** Present on the transport model only. */
  lastCertificateObservationAt?: string | null;
  lastConfigurationChangeAt?: string | null;
  /** Present on the data-protection model only. */
  lastKeyEventAt?: string | null;
  lastVaultActivityAt?: string | null;
  absentSources?: string[];
}

/* ==================================================================== */
/* Shared design system for the TLS & PKI Intelligence Command Center.   */
/* One vocabulary, one panel, one status language across four pages -    */
/* which is what makes them read as a single product rather than four    */
/* dashboards that happen to be adjacent in the sidebar.                 */
/* ==================================================================== */

export const SHELL_CLASS = 'tlspki-shell min-h-screen space-y-4 p-3 lg:p-5';

export const SHELL_CSS = `
  .tlspki-shell { background: var(--qg-dashboard-bg, #0a1020); }
  .qg-theme-light .tlspki-shell [class*="bg-black/"] { background-color: rgba(255,255,255,0.55) !important; }
  .qg-theme-light .tlspki-shell [class*="bg-[#0b1424]"] { background-color: rgba(255,255,255,0.92) !important; }
  .qg-theme-light .tlspki-shell [class*="border-white/"] { border-color: rgba(9,13,22,0.10) !important; }
  .qg-theme-light .tlspki-shell .text-white { color: var(--qg-dashboard-text) !important; }
  .qg-theme-light .tlspki-shell [class*="text-white/"] { color: var(--qg-dashboard-text-soft) !important; }
  .qg-theme-light .tlspki-shell .text-cyan-200,
  .qg-theme-light .tlspki-shell .text-cyan-300 { color: #0e7490 !important; }
  .qg-theme-light .tlspki-shell .text-emerald-200,
  .qg-theme-light .tlspki-shell .text-emerald-300 { color: #047857 !important; }
  .qg-theme-light .tlspki-shell .text-amber-200,
  .qg-theme-light .tlspki-shell .text-amber-300 { color: #b45309 !important; }
  .qg-theme-light .tlspki-shell .text-violet-200,
  .qg-theme-light .tlspki-shell .text-violet-300 { color: #7c3aed !important; }
  .qg-theme-light .tlspki-shell input::placeholder,
  .qg-theme-light .tlspki-shell select { color: var(--qg-dashboard-text) !important; }
  .tlspki-shell table { border-collapse: separate; border-spacing: 0; }
  @media (prefers-reduced-motion: reduce) {
    .tlspki-shell *, .tlspki-shell *::before, .tlspki-shell *::after {
      animation-duration: 0.001ms !important;
      transition-duration: 0.001ms !important;
    }
  }
`;

/* ------------------------------------------------------------------ */
/* Tone                                                                */
/* ------------------------------------------------------------------ */

export type Tone = 'critical' | 'warning' | 'good' | 'info' | 'neutral' | 'ai';

export const TONE: Record<Tone, { text: string; hex: string; soft: string; border: string; dot: string }> = {
  critical: { text: 'text-red-300', hex: '#f87171', soft: 'bg-red-500/10', border: 'border-red-500/30', dot: 'bg-red-400' },
  warning: { text: 'text-amber-300', hex: '#fbbf24', soft: 'bg-amber-500/10', border: 'border-amber-500/30', dot: 'bg-amber-400' },
  good: { text: 'text-emerald-300', hex: '#34d399', soft: 'bg-emerald-500/10', border: 'border-emerald-500/30', dot: 'bg-emerald-400' },
  info: { text: 'text-blue-300', hex: '#60a5fa', soft: 'bg-blue-500/10', border: 'border-blue-500/30', dot: 'bg-blue-400' },
  neutral: { text: 'text-cyan-300', hex: '#22d3ee', soft: 'bg-cyan-500/10', border: 'border-cyan-500/25', dot: 'bg-cyan-400' },
  ai: { text: 'text-violet-300', hex: '#a78bfa', soft: 'bg-violet-500/10', border: 'border-violet-500/30', dot: 'bg-violet-400' },
};

export const POSTURE_TONE: Record<PqcPosture, Tone> = {
  'quantum-safe': 'good',
  'pqc-ready': 'good',
  'hybrid-ready': 'info',
  'migration-required': 'warning',
  'quantum-vulnerable': 'critical',
  legacy: 'critical',
  unknown: 'neutral',
};

export const SEVERITY_TONE: Record<Severity, Tone> = {
  critical: 'critical',
  high: 'critical',
  medium: 'warning',
  low: 'neutral',
};

export const RISK_TONE: Record<RiskLevel, Tone> = {
  critical: 'critical',
  high: 'critical',
  medium: 'warning',
  low: 'good',
  none: 'neutral',
};

/* ------------------------------------------------------------------ */
/* Formatting                                                          */
/* ------------------------------------------------------------------ */

export function fmtNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return '—';
  return new Intl.NumberFormat('en-US').format(Math.round(Number(value)));
}

export function fmtPercent(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return '—';
  return `${Math.round(Number(value))}%`;
}

/** Never renders "0 days" for an unknown expiry - that would read as urgent. */
export function fmtDays(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return 'Not recorded';
  const days = Math.round(Number(value));
  if (days < 0) return `Expired ${Math.abs(days)}d ago`;
  if (days === 0) return 'Expires today';
  return `${days}d`;
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return 'never';
  const diff = Date.now() - then;
  if (diff < 0) return 'just now';
  if (diff < 45_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

export function absoluteTime(iso: string | null | undefined): string {
  if (!iso) return 'Not recorded';
  const then = new Date(iso);
  if (!Number.isFinite(then.getTime())) return 'Not recorded';
  return then.toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/* ------------------------------------------------------------------ */
/* Panel                                                               */
/* ------------------------------------------------------------------ */

export function Panel({ children, className, id }: { children: ReactNode; className?: string; id?: string }) {
  return (
    <section
      id={id}
      className={cn('qg-executive-panel group relative overflow-hidden rounded-xl p-4 text-white lg:p-5', className)}
    >
      {children}
    </section>
  );
}

export function SectionLabel({
  children,
  icon: Icon,
  meta,
  href,
  hint,
}: {
  children: ReactNode;
  icon?: LucideIcon;
  meta?: ReactNode;
  href?: string;
  hint?: string;
}) {
  return (
    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
      <h2 className="flex items-center gap-2 text-[11px] font-black uppercase tracking-[0.14em] text-white">
        {Icon ? <Icon className="h-3.5 w-3.5 text-cyan-300" aria-hidden="true" /> : null}
        {children}
        {hint ? <Term hint={hint} /> : null}
      </h2>
      <div className="flex items-center gap-3 text-[10px] font-bold uppercase tracking-wider text-white/40">
        {meta}
        {href ? (
          <Link to={href} className="inline-flex items-center gap-1 text-cyan-300 hover:text-cyan-200">
            Open <ChevronRight className="h-3 w-3" aria-hidden="true" />
          </Link>
        ) : null}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Tooltip for technical terminology                                   */
/* ------------------------------------------------------------------ */

export function Term({ hint, label }: { hint: string; label?: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);

  return (
    <span ref={ref} className="relative inline-flex">
      <button
        type="button"
        aria-label={label ? `What is ${label}?` : 'Explain this term'}
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        className="inline-grid h-3.5 w-3.5 place-items-center rounded-full text-white/35 transition hover:text-cyan-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
      >
        <HelpCircle className="h-3.5 w-3.5" aria-hidden="true" />
      </button>
      {open ? (
        <span
          role="tooltip"
          className="absolute left-1/2 top-5 z-50 w-64 -translate-x-1/2 rounded-lg border border-white/15 bg-[#0b1424] p-2.5 text-[10.5px] font-medium normal-case leading-relaxed tracking-normal text-white/80 shadow-2xl"
        >
          {hint}
        </span>
      ) : null}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Status badges - one vocabulary everywhere                           */
/* ------------------------------------------------------------------ */

export function Pill({
  tone = 'neutral',
  children,
  className,
  title,
}: {
  tone?: Tone;
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  const t = TONE[tone];
  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[9.5px] font-black uppercase tracking-wider',
        t.border,
        t.soft,
        t.text,
        className,
      )}
    >
      {children}
    </span>
  );
}

export function PostureBadge({ posture, reason }: { posture: PqcPosture; reason?: string }) {
  return (
    <Pill tone={POSTURE_TONE[posture]} title={reason}>
      <span className={cn('h-1.5 w-1.5 rounded-full', TONE[POSTURE_TONE[posture]].dot)} aria-hidden="true" />
      {POSTURE_LABEL[posture]}
    </Pill>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Pill tone={SEVERITY_TONE[severity]}>{severity}</Pill>;
}

/* ---- Data-protection strength (Encryption Monitoring) ------------ */

/**
 * Deliberately a separate vocabulary from `PostureBadge`.
 *
 * A symmetric cipher and a key agreement face different quantum threats:
 * Grover halves the former, Shor breaks the latter. Sharing one badge would
 * force AES-256 to be described in the language of RSA, which is how this
 * platform once published AES-256-GCM as a critical quantum vulnerability.
 */
export type ProtectionStrengthKey = 'quantum-safe' | 'post-quantum' | 'adequate' | 'weakened' | 'quantum-vulnerable' | 'broken' | 'unknown';

export const STRENGTH_TONE: Record<ProtectionStrengthKey, Tone> = {
  'quantum-safe': 'good',
  'post-quantum': 'good',
  adequate: 'info',
  weakened: 'warning',
  // Distinct from `broken`: sound today, Shor-breakable on a CRQC. Matches how
  // the transport pages colour the same primitive.
  'quantum-vulnerable': 'critical',
  broken: 'critical',
  unknown: 'neutral',
};

const STRENGTH_TEXT: Record<ProtectionStrengthKey, string> = {
  'quantum-safe': 'Quantum Safe',
  'post-quantum': 'Post-Quantum',
  adequate: 'Adequate',
  weakened: 'Weakened',
  'quantum-vulnerable': 'Quantum Vulnerable',
  broken: 'Broken',
  unknown: 'Unknown',
};

export function StrengthBadge({ strength, title }: { strength: ProtectionStrengthKey; title?: string }) {
  return (
    <Pill tone={STRENGTH_TONE[strength]} title={title}>
      <span className={cn('h-1.5 w-1.5 rounded-full', TONE[STRENGTH_TONE[strength]].dot)} aria-hidden="true" />
      {STRENGTH_TEXT[strength]}
    </Pill>
  );
}

/** Renders the arithmetic behind a strength verdict, never just the verdict. */
export function SecurityBits({ classical, quantum }: { classical: number | null; quantum: number | null }) {
  if (classical === null && quantum === null) {
    return <span className="font-mono text-[10px] text-white/30">Not quantified</span>;
  }
  return (
    <span className="font-mono text-[10px] text-white/50">
      {classical !== null ? `${classical}-bit classical` : 'classical n/a'}
      {quantum !== null ? ` → ${quantum}-bit post-quantum` : ''}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Freshness + connection state                                        */
/* ------------------------------------------------------------------ */

const PIPELINE_COPY: Record<PipelineStatus, { label: string; tone: Tone; detail: string }> = {
  live: { label: 'Live', tone: 'good', detail: 'Runtime collectors reported within the last 15 minutes.' },
  'scan-running': { label: 'Scan running', tone: 'info', detail: 'A discovery scan is in progress; results appear as it completes.' },
  'inventory-only': {
    label: 'Inventory only',
    tone: 'warning',
    detail: 'Showing stored scan and certificate inventory. No live runtime telemetry is arriving, so nothing here is real-time.',
  },
  stale: { label: 'Stale', tone: 'warning', detail: 'The newest evidence is over 24 hours old. Re-scan or check your collectors.' },
  'awaiting-telemetry': {
    label: 'Awaiting telemetry',
    tone: 'warning',
    detail: 'Collectors are registered but have not reported any TLS or PKI evidence yet.',
  },
  'no-collectors': {
    label: 'No collectors',
    tone: 'neutral',
    detail: 'No agents or cloud connectors are configured, so there is no source of TLS/PKI evidence.',
  },
};

export function FreshnessBar({
  live,
  state,
  generatedAt,
  latestEvidenceAt,
  telemetry,
  onRefresh,
  refreshing,
}: {
  live: boolean;
  state: 'loading' | 'success' | 'error';
  generatedAt: string | null;
  latestEvidenceAt: string | null;
  telemetry: TelemetryLike | null;
  onRefresh: () => void;
  refreshing?: boolean;
}) {
  const pipeline = telemetry ? PIPELINE_COPY[telemetry.pipelineStatus] : null;

  return (
    <div className="flex flex-wrap items-center gap-2">
      {pipeline ? (
        <Pill tone={pipeline.tone} title={pipeline.detail}>
          <span className={cn('h-1.5 w-1.5 rounded-full', TONE[pipeline.tone].dot)} aria-hidden="true" />
          {pipeline.label}
        </Pill>
      ) : null}

      <span
        role="status"
        className={cn(
          'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[9px] font-black uppercase tracking-widest',
          live ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-300' : 'border-amber-400/40 bg-amber-500/10 text-amber-300',
        )}
      >
        <span className={cn('h-1.5 w-1.5 rounded-full', live ? 'animate-pulse bg-emerald-400' : 'bg-amber-300')} aria-hidden="true" />
        {state === 'loading' && !generatedAt ? 'Connecting' : live ? 'Stream connected' : 'Real-time connection unavailable'}
      </span>

      <div className="flex flex-col text-right">
        <span className="font-mono text-[9.5px] text-white/40">Computed {relativeTime(generatedAt)}</span>
        <span className="font-mono text-[9.5px] text-white/30" title={absoluteTime(latestEvidenceAt)}>
          Newest evidence {relativeTime(latestEvidenceAt)}
        </span>
      </div>

      <button
        type="button"
        onClick={onRefresh}
        className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
      >
        <RefreshCw className={cn('h-3.5 w-3.5', refreshing && 'animate-spin')} aria-hidden="true" /> Refresh
      </button>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Cross-page navigation - the four pages are one workflow             */
/* ------------------------------------------------------------------ */

/**
 * The Observability suite.
 *
 * The first four cover TRANSPORT (what is negotiated on the wire); Encryption
 * Monitoring covers DATA PROTECTION (what protects data at rest and in use).
 * They deliberately do not overlap — a TLS cipher suite is counted once, on
 * Protocol Analytics.
 */
const MODULE_TABS = [
  { path: '/dashboard/tls-telemetry', label: 'TLS Telemetry', blurb: 'What transport cryptography is actually running' },
  { path: '/dashboard/pki-visibility', label: 'PKI Visibility', blurb: 'Certificates, issuers and trust chains' },
  { path: '/dashboard/protocol-analytics', label: 'Protocol Analytics', blurb: 'Version, suite and key-agreement distribution' },
  { path: '/dashboard/tls-orchestrator', label: 'TLS Orchestrator', blurb: 'Plan, remediate and verify the change' },
  { path: '/dashboard/encryption-monitoring', label: 'Encryption Monitoring', blurb: 'Data at rest, key material, symmetric and hash primitives' },
];

export function ModuleNav() {
  const { pathname } = useLocation();
  return (
    <nav aria-label="Observability modules" className="flex flex-wrap gap-1.5">
      {MODULE_TABS.map((tab) => {
        const active = pathname === tab.path;
        return (
          <Link
            key={tab.path}
            to={tab.path}
            title={tab.blurb}
            aria-current={active ? 'page' : undefined}
            className={cn(
              'rounded-lg border px-3 py-1.5 text-[10px] font-black uppercase tracking-wider transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
              active
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
/* Page header                                                         */
/* ------------------------------------------------------------------ */

export function PageHeader({
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

/* ------------------------------------------------------------------ */
/* KPI                                                                 */
/* ------------------------------------------------------------------ */

export function Kpi({
  label,
  value,
  detail,
  tone = 'neutral',
  hint,
  href,
  unmeasured,
}: {
  label: string;
  value: string;
  detail?: string;
  tone?: Tone;
  hint?: string;
  href?: string;
  /** Renders the tile as explicitly not measured rather than as a zero. */
  unmeasured?: boolean;
}) {
  const t = TONE[tone];
  const body = (
    <>
      <div className="flex items-center gap-1.5 text-[9.5px] font-black uppercase tracking-[0.12em] text-white/45">
        {label}
        {hint ? <Term hint={hint} label={label} /> : null}
      </div>
      <div className={cn('mt-2 text-[26px] font-black leading-none', unmeasured ? 'text-white/35' : t.text)}>
        {unmeasured ? 'Not measured' : value}
      </div>
      {detail ? <div className="mt-1.5 text-[10px] font-medium leading-snug text-white/40">{detail}</div> : null}
    </>
  );

  if (href) {
    return (
      <Link
        to={href}
        className={cn(
          'qg-executive-panel group relative block overflow-hidden rounded-xl p-4 text-white no-underline transition hover:-translate-y-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
        )}
      >
        {body}
      </Link>
    );
  }
  return <div className="qg-executive-panel relative overflow-hidden rounded-xl p-4 text-white">{body}</div>;
}

/* ------------------------------------------------------------------ */
/* Charts                                                              */
/* ------------------------------------------------------------------ */

export function BarRow({
  label,
  count,
  percent,
  tone = 'neutral',
  suffix,
  onClick,
  title,
}: {
  label: string;
  count: number;
  percent: number;
  tone?: Tone;
  suffix?: ReactNode;
  onClick?: () => void;
  title?: string;
}) {
  const t = TONE[tone];
  const content = (
    <>
      <span className="min-w-0 truncate font-mono text-[11px] text-white/80" title={title || label}>
        {label}
      </span>
      <span className="h-2 overflow-hidden rounded-full bg-white/10">
        <span
          className="block h-full rounded-full transition-[width] duration-500"
          style={{ width: `${Math.max(2, Math.min(100, percent))}%`, backgroundColor: t.hex }}
        />
      </span>
      <span className="text-right font-mono text-[11px] tabular-nums text-white/60">{fmtNumber(count)}</span>
      <span className="w-10 text-right font-mono text-[11px] tabular-nums text-white/40">{fmtPercent(percent)}</span>
      {suffix}
    </>
  );

  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className="grid w-full grid-cols-[minmax(0,1fr)_90px_46px_44px_auto] items-center gap-2 rounded-md px-1 py-1 text-left transition hover:bg-white/[0.05] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70 sm:grid-cols-[minmax(0,1.4fr)_minmax(80px,1fr)_46px_44px_auto]"
      >
        {content}
      </button>
    );
  }
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_90px_46px_44px_auto] items-center gap-2 px-1 py-1 sm:grid-cols-[minmax(0,1.4fr)_minmax(80px,1fr)_46px_44px_auto]">
      {content}
    </div>
  );
}

export function Donut({
  rows,
  size = 148,
  centerLabel,
  centerValue,
}: {
  rows: Array<{ label: string; value: number; hex: string }>;
  size?: number;
  centerLabel?: string;
  centerValue?: string;
}) {
  const total = rows.reduce((sum, row) => sum + row.value, 0);
  const radius = size / 2 - 14;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  if (total <= 0) {
    return (
      <div className="flex h-[148px] items-center justify-center text-[11px] font-semibold text-white/35">Nothing observed yet</div>
    );
  }

  return (
    <div className="flex items-center gap-4">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={centerLabel || 'Distribution'}>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="14" />
        {rows.map((row) => {
          const fraction = row.value / total;
          const dash = fraction * circumference;
          const element = (
            <circle
              key={row.label}
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke={row.hex}
              strokeWidth="14"
              strokeDasharray={`${dash} ${circumference - dash}`}
              strokeDashoffset={-offset}
              transform={`rotate(-90 ${size / 2} ${size / 2})`}
            />
          );
          offset += dash;
          return element;
        })}
        {centerValue ? (
          <>
            <text x="50%" y="47%" textAnchor="middle" className="fill-white" style={{ fontSize: 20, fontWeight: 800 }}>
              {centerValue}
            </text>
            <text x="50%" y="60%" textAnchor="middle" fill="rgba(255,255,255,0.4)" style={{ fontSize: 8.5, fontWeight: 700, letterSpacing: 1 }}>
              {(centerLabel || '').toUpperCase()}
            </text>
          </>
        ) : null}
      </svg>
      <ul className="min-w-0 flex-1 space-y-1.5">
        {rows.map((row) => (
          <li key={row.label} className="flex items-center justify-between gap-2 text-[11px]">
            <span className="flex min-w-0 items-center gap-2">
              <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: row.hex }} aria-hidden="true" />
              <span className="truncate text-white/70">{row.label}</span>
            </span>
            <span className="font-mono tabular-nums text-white/50">
              {fmtNumber(row.value)} · {fmtPercent((row.value / total) * 100)}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Stacked area trend over real daily buckets. */
export function StackedTrend({
  points,
  series,
  height = 130,
  emptyLabel = 'No dated evidence in this window',
}: {
  points: Array<Record<string, number | string>>;
  series: Array<{ key: string; label: string; hex: string }>;
  height?: number;
  emptyLabel?: string;
}) {
  const max = useMemo(() => {
    let value = 0;
    for (const point of points) {
      let sum = 0;
      for (const item of series) sum += Number(point[item.key]) || 0;
      value = Math.max(value, sum);
    }
    return value;
  }, [points, series]);

  if (!points.length || max <= 0) {
    return <div className="flex items-center justify-center py-10 text-[11px] font-semibold text-white/35">{emptyLabel}</div>;
  }

  const width = 640;
  const step = points.length > 1 ? width / (points.length - 1) : width;

  const cumulative = points.map(() => 0);
  const paths = series.map((item) => {
    const upper: string[] = [];
    const lower: string[] = [];
    points.forEach((point, index) => {
      const x = index * step;
      const base = cumulative[index];
      const value = Number(point[item.key]) || 0;
      const top = base + value;
      cumulative[index] = top;
      upper.push(`${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${(height - (top / max) * height).toFixed(1)}`);
      lower.push(`L ${x.toFixed(1)} ${(height - (base / max) * height).toFixed(1)}`);
    });
    return { key: item.key, hex: item.hex, d: `${upper.join(' ')} ${lower.reverse().join(' ')} Z` };
  });

  return (
    <div>
      <svg viewBox={`0 0 ${width} ${height}`} className="h-[130px] w-full" preserveAspectRatio="none" role="img" aria-label="Evidence trend">
        {[0.25, 0.5, 0.75].map((ratio) => (
          <line key={ratio} x1="0" x2={width} y1={height * ratio} y2={height * ratio} stroke="rgba(255,255,255,0.06)" strokeWidth="1" />
        ))}
        {paths.map((path) => (
          <path key={path.key} d={path.d} fill={path.hex} fillOpacity="0.35" stroke={path.hex} strokeWidth="1.5" />
        ))}
      </svg>
      <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
        <ul className="flex flex-wrap gap-3">
          {series.map((item) => (
            <li key={item.key} className="flex items-center gap-1.5 text-[10px] font-semibold text-white/55">
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: item.hex }} aria-hidden="true" /> {item.label}
            </li>
          ))}
        </ul>
        <span className="font-mono text-[9.5px] text-white/30">
          {String(points[0]?.label ?? '')} — {String(points[points.length - 1]?.label ?? '')}
        </span>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Evidence                                                            */
/* ------------------------------------------------------------------ */

const SOURCE_LABEL: Record<string, string> = {
  'runtime-telemetry': 'Runtime telemetry',
  'agent-scan': 'Agent collector',
  'network-scan': 'Network scan',
  'certificate-store': 'Certificate store',
  'crypto-inventory': 'Crypto inventory',
  'scan-finding': 'Scan finding',
  exposure: 'Crypto exposure',
  'security-event': 'Security event',
  'key-store': 'Key store',
  vault: 'Quantum Vault',
};

/** Falls back to a readable label so a new source is never rendered blank. */
function sourceLabel(source: string): string {
  return SOURCE_LABEL[source] || source.replace(/[-_]+/g, ' ').replace(/\w/g, (c) => c.toUpperCase());
}

export function EvidenceList({ evidence, limit = 6 }: { evidence: EvidenceLike[]; limit?: number }) {
  if (!evidence.length) {
    return (
      <p className="rounded-lg border border-dashed border-white/12 bg-white/[0.02] p-3 text-[11px] text-white/40">
        No evidence record is attached to this item.
      </p>
    );
  }
  return (
    <ul className="space-y-1.5">
      {evidence.slice(0, limit).map((ref, index) => (
        <li key={`${ref.table}-${ref.recordId}-${index}`} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <Pill tone="info">{sourceLabel(ref.source)}</Pill>
            <span className="font-mono text-[9.5px] text-white/35" title={absoluteTime(ref.observedAt)}>
              {relativeTime(ref.observedAt)}
            </span>
          </div>
          <p className="mt-1.5 text-[11px] leading-snug text-white/70">{ref.detail}</p>
          <p className="mt-1 font-mono text-[9px] text-white/30">
            {ref.table} · {ref.recordId}
          </p>
        </li>
      ))}
    </ul>
  );
}

/* ------------------------------------------------------------------ */
/* States                                                              */
/* ------------------------------------------------------------------ */

export function Skeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-4" aria-busy="true" aria-live="polite">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <div key={index} className="qg-executive-panel h-[104px] animate-pulse rounded-xl bg-white/[0.03]" />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="qg-executive-panel h-[180px] animate-pulse rounded-xl bg-white/[0.03]" />
      ))}
      <span className="sr-only">Loading TLS and PKI intelligence…</span>
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <Panel className="border border-red-500/25">
      <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center">
        <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-red-500/30 bg-red-500/10 text-red-300">
          <AlertTriangle className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-black uppercase tracking-wider text-white">Unable to load TLS/PKI intelligence</h2>
          <p className="mt-1 text-[12px] leading-relaxed text-white/55">{message}</p>
        </div>
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/40 bg-cyan-500/15 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
        >
          <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" /> Retry
        </button>
      </div>
    </Panel>
  );
}

export function ConnectionLost({ onReconnect, lastSyncedAt }: { onReconnect: () => void; lastSyncedAt: string | null }) {
  return (
    <Panel className="border border-amber-500/25">
      <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center">
        <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-300">
          <WifiOff className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-black uppercase tracking-wider text-white">Real-time connection unavailable</h2>
          <p className="mt-1 text-[12px] leading-relaxed text-white/55">
            Reconnecting automatically with backoff. Figures below are from the last successful sync
            {lastSyncedAt ? ` ${relativeTime(lastSyncedAt)}` : ''} and are not live.
          </p>
        </div>
        <button
          type="button"
          onClick={onReconnect}
          className="inline-flex items-center gap-1.5 rounded-lg border border-amber-400/40 bg-amber-500/15 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-amber-200 transition hover:bg-amber-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
        >
          <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" /> Reconnect now
        </button>
      </div>
    </Panel>
  );
}

/**
 * The honest zero state.
 *
 * Never claims a good posture from an absence of findings; it says what is
 * missing and exactly what the operator has to do to get real data.
 */
export function NoDataState({
  title,
  body,
  telemetry,
}: {
  title: string;
  body: string;
  telemetry: TelemetryLike | null;
}) {
  const steps: Array<{ label: string; href: string; done: boolean; detail: string }> = [
    {
      label: 'Deploy an agent collector',
      href: '/downloads',
      done: Boolean(telemetry && telemetry.agentsTotal > 0),
      detail: telemetry?.agentsTotal
        ? `${telemetry.agentsOnline} of ${telemetry.agentsTotal} agent(s) online`
        : 'Agents report live TLS handshakes and certificates from your hosts.',
    },
    {
      label: 'Connect a cloud account',
      href: '/dashboard/cloud',
      done: Boolean(telemetry && telemetry.connectorsTotal > 0),
      detail: telemetry?.connectorsTotal
        ? `${telemetry.connectorsActive} of ${telemetry.connectorsTotal} connector(s) active`
        : 'Cloud connectors discover managed certificates and load-balancer TLS policy.',
    },
    {
      label: 'Run an authorized scan',
      href: '/dashboard/scanner',
      done: Boolean(telemetry && (telemetry.lastScanAt || telemetry.runningScans > 0)),
      detail: telemetry?.lastScanAt ? `Last scan ${relativeTime(telemetry.lastScanAt)}` : 'Scan your own endpoints to inventory their transport cryptography.',
    },
  ];

  return (
    <Panel>
      <div className="flex flex-col items-start gap-4 lg:flex-row">
        <span className="grid h-12 w-12 shrink-0 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300">
          <Info className="h-6 w-6" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="text-base font-black uppercase tracking-wider text-white">{title}</h2>
          <p className="mt-1.5 max-w-3xl text-[12.5px] leading-relaxed text-white/55">{body}</p>
          <ol className="mt-4 grid gap-2 md:grid-cols-3">
            {steps.map((step, index) => (
              <li key={step.label}>
                <Link
                  to={step.href}
                  className="block h-full rounded-lg border border-white/10 bg-black/25 p-3 no-underline transition hover:border-cyan-400/40 hover:bg-black/40"
                >
                  <div className="flex items-center gap-2">
                    <span
                      className={cn(
                        'grid h-5 w-5 shrink-0 place-items-center rounded-full text-[9px] font-black',
                        step.done ? 'bg-emerald-500/20 text-emerald-300' : 'bg-white/10 text-white/50',
                      )}
                    >
                      {step.done ? <ShieldCheck className="h-3 w-3" aria-hidden="true" /> : index + 1}
                    </span>
                    <span className="text-[11px] font-black uppercase tracking-wider text-white">{step.label}</span>
                  </div>
                  <p className="mt-1.5 text-[10.5px] leading-snug text-white/45">{step.detail}</p>
                </Link>
              </li>
            ))}
          </ol>
        </div>
      </div>
    </Panel>
  );
}

/** Inline empty state for a panel whose section has nothing measured. */
export function PanelEmpty({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-[110px] items-center justify-center rounded-lg border border-dashed border-white/12 bg-white/[0.02] px-4 text-center text-[11px] font-medium leading-relaxed text-white/40">
      {children}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Table shell                                                         */
/* ------------------------------------------------------------------ */

export function TableShell({ children, minWidth = 880 }: { children: ReactNode; minWidth?: number }) {
  return (
    <div className="-mx-1 overflow-x-auto px-1">
      <table className="w-full text-left text-[11.5px]" style={{ minWidth }}>
        {children}
      </table>
    </div>
  );
}

export function Th({ children, className, align = 'left' }: { children: ReactNode; className?: string; align?: 'left' | 'right' | 'center' }) {
  return (
    <th
      scope="col"
      className={cn(
        'sticky top-0 z-10 border-b border-white/10 bg-[#0b1424] px-2.5 py-2 text-[9px] font-black uppercase tracking-[0.12em] text-white/45',
        align === 'right' && 'text-right',
        align === 'center' && 'text-center',
        className,
      )}
    >
      {children}
    </th>
  );
}

export function Td({ children, className, align = 'left' }: { children: ReactNode; className?: string; align?: 'left' | 'right' | 'center' }) {
  return (
    <td className={cn('border-b border-white/[0.06] px-2.5 py-2 align-middle text-white/75', align === 'right' && 'text-right', align === 'center' && 'text-center', className)}>
      {children}
    </td>
  );
}

/* ------------------------------------------------------------------ */
/* Pagination                                                          */
/* ------------------------------------------------------------------ */

export function Pager({
  offset,
  limit,
  total,
  onChange,
}: {
  offset: number;
  limit: number;
  total: number;
  onChange: (offset: number) => void;
}) {
  if (total <= limit) return null;
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(total, offset + limit);
  return (
    <div className="mt-3 flex items-center justify-between gap-3">
      <span className="font-mono text-[10px] text-white/40">
        {fmtNumber(from)}–{fmtNumber(to)} of {fmtNumber(total)}
      </span>
      <div className="flex gap-1.5">
        <button
          type="button"
          disabled={offset <= 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
          className="rounded-md border border-white/12 bg-white/[0.04] px-2.5 py-1 text-[10px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08] disabled:cursor-not-allowed disabled:opacity-35"
        >
          Prev
        </button>
        <button
          type="button"
          disabled={to >= total}
          onClick={() => onChange(offset + limit)}
          className="rounded-md border border-white/12 bg-white/[0.04] px-2.5 py-1 text-[10px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08] disabled:cursor-not-allowed disabled:opacity-35"
        >
          Next
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Drawer                                                              */
/* ------------------------------------------------------------------ */

export function Drawer({ open, title, subtitle, onClose, children }: { open: boolean; title: string; subtitle?: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[60] flex justify-end" role="dialog" aria-modal="true" aria-label={title}>
      <button type="button" aria-label="Close" onClick={onClose} className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <aside className="relative flex h-full w-full max-w-xl flex-col overflow-y-auto border-l border-white/12 bg-[#0b1424] shadow-2xl">
        <header className="sticky top-0 z-10 flex items-start justify-between gap-3 border-b border-white/10 bg-[#0b1424] p-4">
          <div className="min-w-0">
            <h2 className="truncate text-sm font-black uppercase tracking-wider text-white">{title}</h2>
            {subtitle ? <p className="mt-1 truncate font-mono text-[10.5px] text-white/40">{subtitle}</p> : null}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[10px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08]"
          >
            Close
          </button>
        </header>
        <div className="space-y-4 p-4">{children}</div>
      </aside>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Provenance footer - every page states where its numbers came from   */
/* ------------------------------------------------------------------ */

export function ProvenanceFooter({ telemetry }: { telemetry: TelemetryLike | null }) {
  if (!telemetry) return null;
  const entries = Object.entries(telemetry.sourceCounts).filter(([, count]) => count > 0);
  return (
    <Panel>
      <SectionLabel
        icon={Info}
        hint="Every figure on this page is derived from these tenant-scoped tables. Nothing is generated, sampled or assumed."
      >
        Evidence provenance
      </SectionLabel>
      {entries.length === 0 ? (
        <PanelEmpty>No tenant rows were available to this page.</PanelEmpty>
      ) : (
        <ul className="flex flex-wrap gap-1.5">
          {entries.map(([table, count]) => (
            <li key={table} className="rounded-md border border-white/10 bg-black/25 px-2 py-1 font-mono text-[10px] text-white/50">
              {table} <span className="text-cyan-300">{fmtNumber(count)}</span>
            </li>
          ))}
        </ul>
      )}
      {/* Only the freshness clocks the host model actually carries. */}
      <div className="mt-3 grid gap-2 text-[10.5px] text-white/45 sm:grid-cols-2 lg:grid-cols-4">
        <span>Last scan: {relativeTime(telemetry.lastScanAt)}</span>
        <span>Last runtime event: {relativeTime(telemetry.lastRuntimeEventAt)}</span>
        {telemetry.lastCertificateObservationAt !== undefined ? (
          <span>Last certificate observation: {relativeTime(telemetry.lastCertificateObservationAt)}</span>
        ) : null}
        {telemetry.lastConfigurationChangeAt !== undefined ? (
          <span>Last configuration change: {relativeTime(telemetry.lastConfigurationChangeAt)}</span>
        ) : null}
        {telemetry.lastKeyEventAt !== undefined ? <span>Last key event: {relativeTime(telemetry.lastKeyEventAt)}</span> : null}
        {telemetry.lastVaultActivityAt !== undefined ? <span>Last vault activity: {relativeTime(telemetry.lastVaultActivityAt)}</span> : null}
      </div>

      {/*
        Sources that returned nothing, named explicitly. A zero on the page is
        then always attributable to a missing instrument rather than being read
        as a clean result.
      */}
      {telemetry.absentSources && telemetry.absentSources.length ? (
        <div className="mt-3">
          <h3 className="text-[9px] font-black uppercase tracking-wider text-white/35">No rows from</h3>
          <ul className="mt-1.5 flex flex-wrap gap-1.5">
            {telemetry.absentSources.map((table) => (
              <li key={table} className="rounded-md border border-white/10 bg-black/15 px-2 py-1 font-mono text-[10px] text-white/35">
                {table}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {telemetry.truncated ? (
        <p className="mt-3 rounded-lg border border-amber-500/25 bg-amber-500/5 p-2.5 text-[10.5px] leading-relaxed text-amber-200/85">
          A detail query reached its row cap, so counts on this page are a lower bound (&ldquo;at least&rdquo;) for very large estates. Headline
          estate totals still come from exact tenant-wide counts.
        </p>
      ) : null}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Filter bar                                                          */
/* ------------------------------------------------------------------ */

export function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: Array<{ value: string; label: string }>;
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex items-center gap-1.5">
      <span className="text-[9px] font-black uppercase tracking-wider text-white/35">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-md border border-white/12 bg-black/30 px-2 py-1.5 text-[10.5px] font-semibold text-white/80 outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value} className="bg-[#0b1424]">
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (value: string) => void; placeholder: string }) {
  return (
    <input
      type="search"
      value={value}
      onChange={(event) => onChange(event.target.value)}
      placeholder={placeholder}
      aria-label={placeholder}
      className="h-8 min-w-[220px] flex-1 rounded-md border border-white/12 bg-black/30 px-3 text-[11px] font-medium text-white outline-none placeholder:text-white/30 focus-visible:ring-2 focus-visible:ring-cyan-300/70"
    />
  );
}
