'use client';

/**
 * QKMS Command Center — shared shell and vocabulary.
 *
 * Seven pages, one design system, one status language. Anything a page renders
 * about a key — its posture, lifecycle, rotation, custody, risk or compliance —
 * is rendered by a component in this file, so the same key cannot appear with a
 * different label or colour depending on which page is open.
 *
 * Built on `_components/observability/primitives`, the platform's newest
 * dashboard system, rather than a QKMS-only set. Where a primitive carries
 * transport-specific copy (the TLS error and empty states) or a foreign
 * vocabulary (its pipeline-status enum), a QKMS equivalent lives here instead
 * of bending the shared one.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  AlertTriangle,
  BadgeCheck,
  Download,
  FileText,
  Info,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  WifiOff,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  Panel,
  PanelEmpty,
  Pill,
  SectionLabel,
  TONE,
  Term,
  absoluteTime,
  fmtNumber,
  fmtPercent,
  relativeTime,
  type Tone,
} from '../observability/primitives';
import type {
  CustodyClass,
  KeyIndexEntry,
  KeyPqcPosture,
  LifecycleState,
  ManagedKey,
  MigrationGateState,
  MigrationRequirement,
  PipelineStatus,
  QkmsMode,
  QkmsTelemetryHealth,
  RiskLevel,
  RotationJobStatus,
  RotationState,
  Severity,
} from '@/lib/qkms/types';
import { CUSTODY_LABEL, GATE_LABEL, LIFECYCLE_LABEL, ROTATION_JOB_LABEL, ROTATION_LABEL } from '@/lib/qkms/types';
import type { LoadState } from '@/hooks/use-qkms';

export { Panel, PanelEmpty, Pill, SectionLabel, Term, TONE, absoluteTime, fmtNumber, fmtPercent, relativeTime };
export {
  BarRow,
  Donut,
  Drawer,
  EvidenceList,
  FilterSelect,
  Kpi,
  Pager,
  SearchInput,
  StackedTrend,
  TableShell,
  Td,
  Th,
} from '../observability/primitives';
export type { Tone };

export const QKMS_SHELL_CLASS = 'qkms-shell min-h-screen space-y-4 p-3 lg:p-5';

export const QKMS_SHELL_CSS = `
  .qkms-shell { background: var(--qg-dashboard-bg, #0a1020); }
  .qg-theme-light .qkms-shell [class*="bg-black/"] { background-color: rgba(255,255,255,0.55) !important; }
  .qg-theme-light .qkms-shell [class*="bg-[#0b1424]"] { background-color: rgba(255,255,255,0.92) !important; }
  .qg-theme-light .qkms-shell [class*="border-white/"] { border-color: rgba(9,13,22,0.10) !important; }
  .qg-theme-light .qkms-shell .text-white { color: var(--qg-dashboard-text) !important; }
  .qg-theme-light .qkms-shell [class*="text-white/"] { color: var(--qg-dashboard-text-soft) !important; }
  .qg-theme-light .qkms-shell .text-cyan-200,
  .qg-theme-light .qkms-shell .text-cyan-300 { color: #0e7490 !important; }
  .qg-theme-light .qkms-shell .text-emerald-200,
  .qg-theme-light .qkms-shell .text-emerald-300 { color: #047857 !important; }
  .qg-theme-light .qkms-shell .text-amber-200,
  .qg-theme-light .qkms-shell .text-amber-300 { color: #b45309 !important; }
  .qg-theme-light .qkms-shell .text-violet-200,
  .qg-theme-light .qkms-shell .text-violet-300 { color: #7c3aed !important; }
  .qg-theme-light .qkms-shell select,
  .qg-theme-light .qkms-shell input { color: var(--qg-dashboard-text) !important; }
  .qkms-shell table { border-collapse: separate; border-spacing: 0; }
  @media (prefers-reduced-motion: reduce) {
    .qkms-shell *, .qkms-shell *::before, .qkms-shell *::after {
      animation-duration: 0.001ms !important;
      transition-duration: 0.001ms !important;
    }
  }
`;

/* ------------------------------------------------------------------ */
/* Vocabulary — one label and one tone per value, everywhere           */
/* ------------------------------------------------------------------ */

export const POSTURE_LABEL: Record<KeyPqcPosture, string> = {
  'post-quantum': 'Post-Quantum',
  hybrid: 'Hybrid',
  'quantum-resistant-symmetric': 'Quantum-Resistant',
  'weakened-symmetric': 'Weakened',
  'quantum-vulnerable': 'Quantum Vulnerable',
  deprecated: 'Deprecated',
  unknown: 'Unknown',
};

const POSTURE_TONE: Record<KeyPqcPosture, Tone> = {
  'post-quantum': 'good',
  hybrid: 'info',
  'quantum-resistant-symmetric': 'good',
  'weakened-symmetric': 'warning',
  'quantum-vulnerable': 'critical',
  deprecated: 'critical',
  unknown: 'neutral',
};

const LIFECYCLE_TONE: Record<LifecycleState, Tone> = {
  discovered: 'neutral',
  'pending-activation': 'info',
  active: 'good',
  'in-use': 'good',
  'rotation-due': 'warning',
  'rotation-overdue': 'critical',
  rotated: 'good',
  suspended: 'warning',
  expired: 'critical',
  revoked: 'neutral',
  retired: 'neutral',
  decommissioned: 'neutral',
  unknown: 'neutral',
};

const ROTATION_TONE: Record<RotationState, Tone> = {
  healthy: 'good',
  due: 'warning',
  overdue: 'critical',
  'in-progress': 'info',
  failed: 'critical',
  blocked: 'critical',
  'never-rotated': 'warning',
  'not-applicable': 'neutral',
  unknown: 'neutral',
};

const RISK_TONE: Record<RiskLevel, Tone> = {
  critical: 'critical',
  high: 'critical',
  medium: 'warning',
  low: 'good',
  none: 'good',
};

const CUSTODY_TONE: Record<CustodyClass, Tone> = {
  hsm: 'good',
  'cloud-kms': 'good',
  vault: 'info',
  'platform-vault': 'info',
  'software-keystore': 'warning',
  unmanaged: 'critical',
  unknown: 'neutral',
};

const SEVERITY_TONE: Record<Severity, Tone> = {
  critical: 'critical',
  high: 'critical',
  medium: 'warning',
  low: 'neutral',
  info: 'neutral',
};

const GATE_TONE: Record<MigrationGateState, Tone> = {
  BLOCKED: 'critical',
  NOT_READY: 'warning',
  READY: 'good',
  MIGRATION_IN_PROGRESS: 'info',
  MIGRATED: 'good',
  VALIDATION_REQUIRED: 'warning',
};

const REQUIREMENT_LABEL: Record<MigrationRequirement, string> = {
  none: 'No migration',
  monitor: 'Monitor',
  recommended: 'Recommended',
  required: 'Required',
  unknown: 'Unknown',
};

const REQUIREMENT_TONE: Record<MigrationRequirement, Tone> = {
  none: 'good',
  monitor: 'info',
  recommended: 'warning',
  required: 'critical',
  unknown: 'neutral',
};

const JOB_TONE: Record<RotationJobStatus, Tone> = {
  requested: 'info',
  approved: 'info',
  'in-progress': 'info',
  'awaiting-validation': 'warning',
  completed: 'good',
  failed: 'critical',
  cancelled: 'neutral',
};

export function PostureBadge({ posture, reason }: { posture: KeyPqcPosture; reason?: string }) {
  return (
    <Pill tone={POSTURE_TONE[posture]} title={reason}>
      <span className={cn('h-1.5 w-1.5 rounded-full', TONE[POSTURE_TONE[posture]].dot)} aria-hidden="true" />
      {POSTURE_LABEL[posture]}
    </Pill>
  );
}

export function LifecycleBadge({ state, reason }: { state: LifecycleState; reason?: string }) {
  return <Pill tone={LIFECYCLE_TONE[state]} title={reason}>{LIFECYCLE_LABEL[state]}</Pill>;
}

export function RotationBadge({ state, reason }: { state: RotationState; reason?: string }) {
  return <Pill tone={ROTATION_TONE[state]} title={reason}>{ROTATION_LABEL[state]}</Pill>;
}

export function RiskBadge({ level, score }: { level: RiskLevel; score?: number }) {
  return (
    <Pill tone={RISK_TONE[level]}>
      {level === 'none' ? 'Minimal' : level}
      {score !== undefined ? <span className="font-mono tabular-nums">{score}</span> : null}
    </Pill>
  );
}

export function CustodyBadge({ custody, backend }: { custody: CustodyClass; backend?: string }) {
  return <Pill tone={CUSTODY_TONE[custody]} title={backend}>{CUSTODY_LABEL[custody]}</Pill>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Pill tone={SEVERITY_TONE[severity]}>{severity}</Pill>;
}

export function RequirementBadge({ requirement }: { requirement: MigrationRequirement }) {
  return <Pill tone={REQUIREMENT_TONE[requirement]}>{REQUIREMENT_LABEL[requirement]}</Pill>;
}

export function JobStatusBadge({ status }: { status: RotationJobStatus }) {
  return <Pill tone={JOB_TONE[status]}>{ROTATION_JOB_LABEL[status]}</Pill>;
}

export function GateBadge({ state }: { state: MigrationGateState }) {
  return (
    <Pill tone={GATE_TONE[state]}>
      <span className={cn('h-1.5 w-1.5 rounded-full', TONE[GATE_TONE[state]].dot)} aria-hidden="true" />
      {GATE_LABEL[state]}
    </Pill>
  );
}

export const riskTone = (level: RiskLevel): Tone => RISK_TONE[level];
export const postureTone = (posture: KeyPqcPosture): Tone => POSTURE_TONE[posture];
export const severityTone = (severity: Severity): Tone => SEVERITY_TONE[severity];

/**
 * Relative time that works in BOTH directions.
 *
 * The shared `relativeTime` collapses every future timestamp to "just now" —
 * harmless for the transport pages, which only ever render observations, but
 * QKMS renders due dates. A rotation falling due in eleven months was being
 * shown as "just now", which reads as urgent and is the opposite of the truth.
 * The ±45s window is kept in both directions so ordinary clock skew still reads
 * as "just now".
 */
export function whenRelative(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return 'never';
  const diff = then - Date.now();
  const magnitude = Math.abs(diff);
  if (magnitude < 45_000) return 'just now';

  const value = magnitude < 3_600_000
    ? `${Math.floor(magnitude / 60_000)}m`
    : magnitude < 86_400_000
      ? `${Math.floor(magnitude / 3_600_000)}h`
      : `${Math.floor(magnitude / 86_400_000)}d`;

  return diff > 0 ? `in ${value}` : `${value} ago`;
}

/**
 * Render a percentage that the model reports as `null`.
 *
 * `null` means the denominator was empty — there was nothing to measure. It is
 * NOT 0%, and rendering it as 0% is how an estate with no signature keys came
 * to report 0% signature readiness and drag its headline down with a phantom
 * failure.
 */
export function Measured({ value, suffix = '%', fallback = 'Not applicable' }: { value: number | null; suffix?: string; fallback?: string }) {
  if (value === null || value === undefined) {
    return <span className="text-[11px] font-semibold text-white/35">{fallback}</span>;
  }
  return <span className="tabular-nums">{Math.round(value)}{suffix}</span>;
}

/* ------------------------------------------------------------------ */
/* Navigation                                                          */
/* ------------------------------------------------------------------ */

interface NavCounts {
  keys: number;
  violations: number;
  rotationQueue: number;
  criticalRisk: number;
  migrationRequired: number;
}

const MODULE_TABS: Array<{ mode: QkmsMode; path: string; label: string; blurb: string; badge?: keyof NavCounts; badgeTone?: Tone }> = [
  { mode: 'overview', path: '/dashboard/qkms/overview', label: 'Overview', blurb: 'Estate posture, migration gate and what needs attention now' },
  { mode: 'inventory', path: '/dashboard/qkms/inventory', label: 'Inventory', blurb: 'The authoritative register of every discovered key', badge: 'keys', badgeTone: 'neutral' },
  { mode: 'lifecycle', path: '/dashboard/qkms/lifecycle', label: 'Lifecycle', blurb: 'Creation through decommission, age, expiry and orphans' },
  { mode: 'governance', path: '/dashboard/qkms/governance', label: 'Governance', blurb: 'Policies, violations, custody and entropy', badge: 'violations', badgeTone: 'critical' },
  { mode: 'rotation', path: '/dashboard/qkms/rotation', label: 'Rotation', blurb: 'Work orders, queue and post-rotation validation', badge: 'rotationQueue', badgeTone: 'warning' },
  { mode: 'readiness', path: '/dashboard/qkms/readiness', label: 'PQC Readiness', blurb: 'ML-KEM, ML-DSA, SLH-DSA and the migration gate', badge: 'migrationRequired', badgeTone: 'warning' },
  { mode: 'risk-analysis', path: '/dashboard/qkms/risk-analysis', label: 'Risk Analysis', blurb: 'Explainable key risk and the remediation queue', badge: 'criticalRisk', badgeTone: 'critical' },
];

export function QkmsNav({ counts }: { counts: NavCounts | null }) {
  const { pathname } = useLocation();
  return (
    <nav aria-label="QKMS modules" className="flex flex-wrap gap-1.5">
      {MODULE_TABS.map((tab) => {
        const active = pathname === tab.path;
        const badge = tab.badge && counts ? counts[tab.badge] : 0;
        return (
          <Link
            key={tab.path}
            to={tab.path}
            title={tab.blurb}
            aria-current={active ? 'page' : undefined}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-[10px] font-black uppercase tracking-wider transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
              active
                ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200'
                : 'border-white/12 bg-white/[0.03] text-white/55 hover:bg-white/[0.08] hover:text-white/80',
            )}
          >
            {tab.label}
            {badge > 0 ? (
              <span className={cn('rounded-full px-1.5 py-0.5 font-mono text-[9px] tabular-nums', TONE[tab.badgeTone || 'neutral'].soft, TONE[tab.badgeTone || 'neutral'].text)}>
                {fmtNumber(badge)}
              </span>
            ) : null}
          </Link>
        );
      })}
    </nav>
  );
}

/* ------------------------------------------------------------------ */
/* Freshness                                                           */
/* ------------------------------------------------------------------ */

const PIPELINE_COPY: Record<PipelineStatus, { label: string; tone: Tone; detail: string }> = {
  active: { label: 'Live', tone: 'good', detail: 'Three or more key evidence sources reported within the last 7 days.' },
  'scan-running': { label: 'Scan running', tone: 'info', detail: 'A discovery scan is in progress; keys appear as it completes.' },
  partial: { label: 'Partial coverage', tone: 'warning', detail: 'Only some key evidence sources are current. Coverage is incomplete, so absence of a key is not proof it does not exist.' },
  stale: { label: 'Stale', tone: 'warning', detail: 'Key evidence exists but none of it is recent. Re-scan or check your collectors.' },
  'awaiting-key-evidence': { label: 'Awaiting key evidence', tone: 'warning', detail: 'Collectors are registered but have not reported any key material yet.' },
  'no-sources': { label: 'No sources', tone: 'critical', detail: 'No agent, connector or scan has reported anything for this tenant.' },
};

export function QkmsFreshness({
  live,
  state,
  generatedAt,
  latestEvidenceAt,
  telemetry,
  onRefresh,
  refreshing,
}: {
  live: boolean;
  state: LoadState;
  generatedAt: string | null;
  latestEvidenceAt: string | null;
  telemetry: QkmsTelemetryHealth | null;
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
        {state === 'loading' && !generatedAt ? 'Connecting' : live ? 'Live' : 'Real-time connection lost — reconnecting…'}
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
/* States                                                              */
/* ------------------------------------------------------------------ */

export function QkmsSkeleton({ rows = 4 }: { rows?: number }) {
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
      <span className="sr-only">Loading QKMS key intelligence…</span>
    </div>
  );
}

export function QkmsError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <Panel className="border border-red-500/25">
      <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center">
        <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-red-500/30 bg-red-500/10 text-red-300">
          <AlertTriangle className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-black uppercase tracking-wider text-white">Unable to load QKMS intelligence</h2>
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

export function QkmsConnectionLost({ onReconnect, lastSyncedAt }: { onReconnect: () => void; lastSyncedAt: string | null }) {
  return (
    <Panel className="border border-amber-500/25">
      <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center">
        <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-300">
          <WifiOff className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-black uppercase tracking-wider text-white">Real-time connection lost — reconnecting…</h2>
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
 * Never claims a good posture from an absence of keys; it says what is missing
 * and exactly what the operator has to do to build a real key inventory.
 */
export function NoKeysState({ telemetry }: { telemetry: QkmsTelemetryHealth | null }) {
  const steps = [
    {
      label: 'Deploy an agent collector',
      href: '/downloads',
      done: Boolean(telemetry && telemetry.agentsTotal > 0),
      detail: telemetry?.agentsTotal
        ? `${telemetry.agentsOnline} of ${telemetry.agentsTotal} agent(s) online`
        : 'Agents report key stores, certificates and runtime key usage from your hosts.',
    },
    {
      label: 'Connect a cloud account',
      href: '/dashboard/cloud',
      done: Boolean(telemetry && telemetry.connectorsTotal > 0),
      detail: telemetry?.connectorsTotal
        ? `${telemetry.connectorsActive} of ${telemetry.connectorsTotal} connector(s) active`
        : 'Cloud connectors discover managed KMS keys, HSM material and certificates.',
    },
    {
      label: 'Run an authorized scan',
      href: '/dashboard/scanner',
      done: Boolean(telemetry && (telemetry.lastScanAt || telemetry.runningScans > 0)),
      detail: telemetry?.lastScanAt ? `Last scan ${relativeTime(telemetry.lastScanAt)}` : 'Scan your own systems to inventory their cryptographic key material.',
    },
  ];

  return (
    <Panel>
      <div className="flex flex-col items-start gap-4 lg:flex-row">
        <span className="grid h-12 w-12 shrink-0 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300">
          <KeyRound className="h-6 w-6" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="text-base font-black uppercase tracking-wider text-white">No cryptographic keys discovered</h2>
          <p className="mt-1.5 max-w-3xl text-[12.5px] leading-relaxed text-white/55">
            QKMS has no key material to govern for this tenant yet. It will not show sample keys or estimated posture — every
            figure on these pages comes from your own assets, scans and telemetry. Complete a step below to build the inventory.
          </p>
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

/* ------------------------------------------------------------------ */
/* Provenance                                                          */
/* ------------------------------------------------------------------ */

export function QkmsProvenance({ telemetry }: { telemetry: QkmsTelemetryHealth | null }) {
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
      <div className="mt-3 grid gap-2 text-[10.5px] text-white/45 sm:grid-cols-2 lg:grid-cols-3">
        <span>Last scan: {relativeTime(telemetry.lastScanAt)}</span>
        <span>Last runtime event: {relativeTime(telemetry.lastRuntimeEventAt)}</span>
        <span>Last key observation: {relativeTime(telemetry.lastKeyEventAt)}</span>
        <span>Last rotation activity: {relativeTime(telemetry.lastRotationAt)}</span>
        <span>Last policy evaluation: {relativeTime(telemetry.lastPolicyEvaluationAt)}</span>
      </div>
      {telemetry.absentSources.length ? (
        <div className="mt-3">
          <h3 className="text-[9px] font-black uppercase tracking-wider text-white/35">No rows from</h3>
          <ul className="mt-1.5 flex flex-wrap gap-1.5">
            {telemetry.absentSources.map((label) => (
              <li key={label} className="rounded-md border border-white/10 bg-black/15 px-2 py-1 font-mono text-[10px] text-white/35">
                {label}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {telemetry.truncated ? (
        <p className="mt-3 rounded-lg border border-amber-500/25 bg-amber-500/5 p-2.5 text-[10.5px] leading-relaxed text-amber-200/85">
          A detail query reached its row cap, so counts on this page are a lower bound (&ldquo;at least&rdquo;) for very large estates.
        </p>
      ) : null}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Notices                                                             */
/* ------------------------------------------------------------------ */

export function useNotice() {
  const [notice, setNotice] = useState<{ tone: 'good' | 'critical'; message: string } | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const show = useCallback((ok: boolean, message: string) => {
    setNotice({ tone: ok ? 'good' : 'critical', message });
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setNotice(null), 6000);
  }, []);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  return { notice, show, dismiss: () => setNotice(null) };
}

export function Notice({ notice, onDismiss }: { notice: { tone: 'good' | 'critical'; message: string } | null; onDismiss: () => void }) {
  if (!notice) return null;
  const tone = TONE[notice.tone];
  return (
    <div role="status" className={cn('flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-[11.5px] font-semibold', tone.border, tone.soft, tone.text)}>
      <span>{notice.message}</span>
      <button type="button" onClick={onDismiss} className="rounded px-2 py-0.5 text-[9px] font-black uppercase tracking-wider opacity-70 hover:opacity-100">
        Dismiss
      </button>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Page shell                                                          */
/* ------------------------------------------------------------------ */

export function QkmsShell({
  icon: Icon,
  title,
  accent,
  subtitle,
  live,
  state,
  error,
  hasData,
  generatedAt,
  latestEvidenceAt,
  telemetry,
  nav,
  onRefresh,
  onReconnect,
  actions,
  children,
}: {
  icon: LucideIcon;
  title: string;
  accent: string;
  subtitle: string;
  live: boolean;
  state: LoadState;
  error: string | null;
  hasData: boolean;
  generatedAt: string | null;
  latestEvidenceAt: string | null;
  telemetry: QkmsTelemetryHealth | null;
  nav: NavCounts | null;
  onRefresh: () => void;
  onReconnect: () => void;
  actions?: ReactNode;
  children: ReactNode;
}) {
  const firstPaint = state === 'loading' && !generatedAt;

  return (
    <div className={QKMS_SHELL_CLASS}>
      <style>{QKMS_SHELL_CSS}</style>

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
        <div className="flex flex-wrap items-center gap-2">
          {actions}
          <QkmsFreshness
            live={live}
            state={state}
            generatedAt={generatedAt}
            latestEvidenceAt={latestEvidenceAt}
            telemetry={telemetry}
            onRefresh={onRefresh}
            refreshing={state === 'loading'}
          />
        </div>
      </header>

      <QkmsNav counts={nav} />

      {error && state === 'error' ? <QkmsError message={error} onRetry={onReconnect} /> : null}
      {!live && state === 'success' ? <QkmsConnectionLost onReconnect={onReconnect} lastSyncedAt={generatedAt} /> : null}

      {firstPaint ? <QkmsSkeleton /> : !hasData ? <NoKeysState telemetry={telemetry} /> : children}

      {!firstPaint ? <QkmsProvenance telemetry={telemetry} /> : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Key table                                                           */
/* ------------------------------------------------------------------ */

export type KeyColumn =
  | 'key'
  | 'type'
  | 'algorithm'
  | 'owner'
  | 'asset'
  | 'environment'
  | 'custody'
  | 'version'
  | 'posture'
  | 'requirement'
  | 'lifecycle'
  | 'rotation'
  | 'created'
  | 'lastUsed'
  | 'lastRotated'
  | 'expiry'
  | 'violations'
  | 'risk';

const COLUMN_LABEL: Record<KeyColumn, string> = {
  key: 'Key',
  type: 'Type',
  algorithm: 'Algorithm',
  owner: 'Owner',
  asset: 'Asset',
  environment: 'Env',
  custody: 'Custody',
  version: 'Ver',
  posture: 'PQC posture',
  requirement: 'Migration',
  lifecycle: 'Lifecycle',
  rotation: 'Rotation',
  created: 'Created',
  lastUsed: 'Last used',
  lastRotated: 'Last rotated',
  expiry: 'Expires',
  violations: 'Violations',
  risk: 'Risk',
};

/** Columns that map to a server-side sort key. */
const COLUMN_SORT: Partial<Record<KeyColumn, string>> = {
  key: 'label',
  algorithm: 'algorithm',
  owner: 'owner',
  asset: 'asset',
  environment: 'environment',
  version: 'version',
  created: 'created',
  lastRotated: 'rotated',
  expiry: 'expiry',
  violations: 'violations',
  risk: 'risk',
};

function renderCell(key: KeyIndexEntry, column: KeyColumn): ReactNode {
  switch (column) {
    case 'key':
      return (
        <div className="min-w-0">
          <div className="truncate font-semibold text-white" title={key.label}>{key.label}</div>
          <div className="truncate font-mono text-[9.5px] text-white/35" title={key.id}>{key.id}</div>
        </div>
      );
    case 'type': return <span className="text-white/65">{key.keyType}</span>;
    case 'algorithm':
      return (
        <div className="min-w-0">
          <div className="truncate font-mono text-[11px] text-white/80">{key.algorithm}</div>
          {key.family !== key.algorithm ? <div className="truncate text-[9.5px] text-white/35">{key.family}</div> : null}
        </div>
      );
    case 'owner':
      return key.owner
        ? <span className="text-white/70">{key.owner}</span>
        : <span className="text-[10.5px] font-semibold text-amber-300/80">Unassigned</span>;
    case 'asset':
      return key.assetName
        ? <span className="text-white/70">{key.assetName}</span>
        : <span className="text-[10.5px] text-white/30">Unmapped</span>;
    case 'environment': return <span className="text-white/60">{key.environment}</span>;
    case 'custody': return <CustodyBadge custody={key.custody} backend={key.backend} />;
    case 'version': return <span className="font-mono tabular-nums text-white/70">v{key.version}</span>;
    case 'posture': return <PostureBadge posture={key.posture} />;
    case 'requirement': return <RequirementBadge requirement={key.migrationRequirement} />;
    case 'lifecycle': return <LifecycleBadge state={key.lifecycle} />;
    case 'rotation': return <RotationBadge state={key.rotation} />;
    case 'created': return <span className="font-mono text-[10px] text-white/50" title={absoluteTime(key.createdAt)}>{relativeTime(key.createdAt)}</span>;
    case 'lastUsed': return <span className="font-mono text-[10px] text-white/50" title={absoluteTime(key.lastUsedAt)}>{relativeTime(key.lastUsedAt)}</span>;
    case 'lastRotated': return <span className="font-mono text-[10px] text-white/50" title={absoluteTime(key.lastRotatedAt)}>{relativeTime(key.lastRotatedAt)}</span>;
    case 'expiry':
      if (key.daysToExpiry === null) return <span className="text-[10px] text-white/30">No expiry</span>;
      return (
        <span className={cn('font-mono text-[10px] tabular-nums', key.daysToExpiry < 0 ? 'text-red-300' : key.daysToExpiry <= 45 ? 'text-amber-300' : 'text-white/50')} title={absoluteTime(key.expiresAt)}>
          {key.daysToExpiry < 0 ? `${Math.abs(key.daysToExpiry)}d overdue` : `${key.daysToExpiry}d`}
        </span>
      );
    case 'violations':
      return key.violations > 0
        ? <Pill tone="critical">{fmtNumber(key.violations)}</Pill>
        : <span className="text-[10px] text-white/30">None</span>;
    case 'risk': return <RiskBadge level={key.riskLevel} score={key.riskScore} />;
    default: return null;
  }
}

export function KeyTable({
  keys,
  columns,
  onSelect,
  selectedId,
  sort,
  dir,
  onSort,
  emptyMessage,
  minWidth = 1100,
  actions,
}: {
  keys: KeyIndexEntry[];
  columns: KeyColumn[];
  onSelect?: (keyId: string) => void;
  selectedId?: string | null;
  sort?: string;
  dir?: 'asc' | 'desc';
  onSort?: (sortKey: string) => void;
  emptyMessage: string;
  minWidth?: number;
  actions?: (key: KeyIndexEntry) => ReactNode;
}) {
  if (!keys.length) return <PanelEmpty>{emptyMessage}</PanelEmpty>;

  return (
    <div className="-mx-1 overflow-x-auto px-1">
      <table className="w-full text-left text-[11.5px]" style={{ minWidth }}>
        <thead>
          <tr>
            {columns.map((column) => {
              const sortKey = COLUMN_SORT[column];
              const isSorted = sortKey && sort === sortKey;
              return (
                <th
                  key={column}
                  scope="col"
                  className="sticky top-0 z-10 border-b border-white/10 bg-[#0b1424] px-2.5 py-2 text-[9px] font-black uppercase tracking-[0.12em] text-white/45"
                >
                  {sortKey && onSort ? (
                    <button
                      type="button"
                      onClick={() => onSort(sortKey)}
                      className={cn('inline-flex items-center gap-1 uppercase tracking-[0.12em] transition hover:text-cyan-300', isSorted && 'text-cyan-300')}
                    >
                      {COLUMN_LABEL[column]}
                      {isSorted ? <span aria-hidden="true">{dir === 'asc' ? '▲' : '▼'}</span> : null}
                    </button>
                  ) : (
                    COLUMN_LABEL[column]
                  )}
                </th>
              );
            })}
            {actions ? <th scope="col" className="sticky top-0 z-10 border-b border-white/10 bg-[#0b1424] px-2.5 py-2 text-right text-[9px] font-black uppercase tracking-[0.12em] text-white/45">Actions</th> : null}
          </tr>
        </thead>
        <tbody>
          {keys.map((key) => (
            <tr
              key={key.id}
              onClick={onSelect ? () => onSelect(key.id) : undefined}
              className={cn(
                'transition',
                onSelect && 'cursor-pointer hover:bg-white/[0.04]',
                selectedId === key.id && 'bg-cyan-500/10',
              )}
            >
              {columns.map((column) => (
                <td key={column} className="border-b border-white/[0.06] px-2.5 py-2 align-middle text-white/75">
                  {renderCell(key, column)}
                </td>
              ))}
              {actions ? (
                <td className="border-b border-white/[0.06] px-2.5 py-2 text-right align-middle" onClick={(event) => event.stopPropagation()}>
                  {actions(key)}
                </td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Action button                                                       */
/* ------------------------------------------------------------------ */

/**
 * A control that states why it is unavailable rather than silently doing
 * nothing. Section 24 of the brief: no control may appear functional when the
 * backend cannot honour it.
 */
export function ActionButton({
  label,
  icon: Icon,
  onClick,
  disabled,
  disabledReason,
  busy,
  tone = 'neutral',
}: {
  label: string;
  icon?: LucideIcon;
  onClick: () => void;
  disabled?: boolean;
  disabledReason?: string;
  busy?: boolean;
  tone?: Tone;
}) {
  const t = TONE[tone];
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || busy}
      title={disabled ? disabledReason : label}
      aria-disabled={disabled || busy}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-[10px] font-black uppercase tracking-wider transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
        disabled
          ? 'cursor-not-allowed border-white/10 bg-white/[0.02] text-white/25'
          : cn(t.border, t.soft, t.text, 'hover:brightness-125'),
      )}
    >
      {Icon ? <Icon className={cn('h-3.5 w-3.5', busy && 'animate-spin')} aria-hidden="true" /> : null}
      {label}
    </button>
  );
}

/* ------------------------------------------------------------------ */
/* Export                                                              */
/* ------------------------------------------------------------------ */

export type QkmsExportFormat = 'pdf' | 'xlsx' | 'docx' | 'html' | 'csv' | 'json';

/**
 * Real exports, through the platform's own reporting engine.
 *
 * The predecessor's export button called an endpoint that streamed a file body,
 * discarded it and showed a toast — the operator received nothing. This builds
 * a document from the same model the page is rendering and includes a
 * reconciliation table so the reader can verify the document matches the
 * dashboard rather than taking it on trust.
 */
export function useQkmsExport(fetchModel: () => Promise<unknown>) {
  const [busy, setBusy] = useState<QkmsExportFormat | null>(null);

  const run = useCallback(
    async (format: QkmsExportFormat): Promise<{ ok: boolean; message: string }> => {
      setBusy(format);
      try {
        const [{ buildQkmsReport }, { exportInventory, downloadInventory }] = await Promise.all([
          import('./report'),
          import('@/services/reporting/exporters/InventoryExporters'),
        ]);
        const model = (await fetchModel()) as Parameters<typeof buildQkmsReport>[0];
        const report = buildQkmsReport(model);
        const result = await exportInventory(report, format);
        downloadInventory(result);
        return { ok: true, message: `${format.toUpperCase()} export downloaded (${result.filename}).` };
      } catch (error) {
        return { ok: false, message: error instanceof Error ? error.message : 'Export failed' };
      } finally {
        setBusy(null);
      }
    },
    [fetchModel],
  );

  return { busy, run };
}

export function ExportMenu({ onExport, busy }: { onExport: (format: QkmsExportFormat) => void; busy: QkmsExportFormat | null }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);

  const formats: Array<{ value: QkmsExportFormat; label: string }> = useMemo(() => ([
    { value: 'pdf', label: 'PDF report' },
    { value: 'xlsx', label: 'Excel workbook' },
    { value: 'docx', label: 'Word document' },
    { value: 'html', label: 'HTML report' },
    { value: 'csv', label: 'CSV register' },
    { value: 'json', label: 'JSON model' },
  ]), []);

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-haspopup="menu"
        className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
      >
        <Download className={cn('h-3.5 w-3.5', busy && 'animate-pulse')} aria-hidden="true" />
        {busy ? `Building ${busy.toUpperCase()}…` : 'Export'}
      </button>
      {open ? (
        <div role="menu" className="absolute right-0 top-full z-50 mt-1.5 w-48 overflow-hidden rounded-lg border border-white/15 bg-[#0b1424] shadow-2xl">
          {formats.map((format) => (
            <button
              key={format.value}
              type="button"
              role="menuitem"
              onClick={() => { setOpen(false); onExport(format.value); }}
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-[11px] font-semibold text-white/70 transition hover:bg-white/[0.06] hover:text-white"
            >
              <FileText className="h-3.5 w-3.5 text-cyan-300" aria-hidden="true" />
              {format.label}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Small shared bits                                                   */
/* ------------------------------------------------------------------ */

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <div className="rounded-lg border border-white/10 bg-black/25 p-2.5">
      <div className="flex items-center gap-1 text-[9px] font-black uppercase tracking-wider text-white/35">
        {label}
        {hint ? <Term hint={hint} label={label} /> : null}
      </div>
      <div className="mt-1 break-words text-[11.5px] font-semibold text-white/80">{children}</div>
    </div>
  );
}

export function ExplainBox({ tone = 'info', title, children }: { tone?: Tone; title: string; children: ReactNode }) {
  const t = TONE[tone];
  return (
    <div className={cn('rounded-lg border p-3', t.border, t.soft)}>
      <h3 className={cn('text-[10px] font-black uppercase tracking-wider', t.text)}>{title}</h3>
      <div className="mt-1.5 text-[11.5px] leading-relaxed text-white/70">{children}</div>
    </div>
  );
}

export function OwnerPrompt({ current, onSubmit, onCancel, busy }: { current: string | null; onSubmit: (owner: string) => void; onCancel: () => void; busy?: boolean }) {
  const [value, setValue] = useState(current || '');
  return (
    <form
      onSubmit={(event) => { event.preventDefault(); if (value.trim()) onSubmit(value.trim()); }}
      className="flex flex-wrap items-center gap-1.5"
    >
      <input
        autoFocus
        value={value}
        onChange={(event) => setValue(event.target.value)}
        placeholder="Owning team or individual"
        aria-label="Owner"
        maxLength={200}
        className="h-8 min-w-[200px] rounded-md border border-white/12 bg-black/30 px-2.5 text-[11px] text-white outline-none placeholder:text-white/30 focus-visible:ring-2 focus-visible:ring-cyan-300/70"
      />
      <ActionButton label="Save" icon={BadgeCheck} onClick={() => value.trim() && onSubmit(value.trim())} busy={busy} tone="good" />
      <button type="button" onClick={onCancel} className="px-2 text-[10px] font-black uppercase tracking-wider text-white/40 hover:text-white/70">
        Cancel
      </button>
    </form>
  );
}

/** Formats a `ManagedKey` identity line used across drawers and headers. */
export function keySubtitle(key: ManagedKey): string {
  return [key.algorithm, key.keyType, key.assetName || 'Unmapped asset', `v${key.version}`].filter(Boolean).join(' · ');
}
