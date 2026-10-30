'use client';

/* ==================================================================== */
/* Shared design system for the Cryptographic Trust & Telemetry suite.  */
/*                                                                      */
/* Layers on top of the Observability primitives rather than forking    */
/* them, so a severity colour, a panel edge or an empty state is the    */
/* same object here as on TLS Telemetry and PKI Visibility. What this   */
/* module adds is the vocabulary those pages do not have: trust states, */
/* score dials, chain visualisation, cloud posture and the live event   */
/* stream.                                                              */
/* ==================================================================== */

import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { AlertTriangle, ArrowRight, CheckCircle2, HelpCircle, MinusCircle, ShieldAlert, XCircle } from 'lucide-react';
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
  type Tone,
} from '../observability/primitives';
import {
  CLOUD_PROVIDER_LABEL,
  TRUST_NODE_LABEL,
  TRUST_STATE_LABEL,
  type ChainCheck,
  type CloudProviderId,
  type EncryptionState,
  type TrustEvent,
  type TrustNodeKind,
  type TrustScore,
  type TrustState,
} from '@/lib/trust-fabric/types';

/* ------------------------------------------------------------------ */
/* Shell + motion                                                      */
/* ------------------------------------------------------------------ */

export const TRUST_SHELL_CLASS = 'tlspki-shell trustfabric-shell min-h-screen space-y-4 p-3 lg:p-5';

/**
 * The suite's motion layer.
 *
 * Animation here is functional, not decorative: entrances stagger so a dense
 * grid resolves in reading order, the live dot pulses only while the stream is
 * genuinely open, and value changes flash so an operator watching a wall
 * display notices a number moved. Every one of them collapses to a no-op under
 * `prefers-reduced-motion`, which the base shell CSS already enforces globally.
 */
export const TRUST_SHELL_CSS = `
  .trustfabric-shell { --tf-ease: cubic-bezier(0.22, 1, 0.36, 1); }

  @keyframes tf-rise { from { opacity: 0; transform: translate3d(0, 10px, 0); } to { opacity: 1; transform: none; } }
  @keyframes tf-fade { from { opacity: 0; } to { opacity: 1; } }
  @keyframes tf-sweep { from { transform: translateX(-110%); } to { transform: translateX(210%); } }
  @keyframes tf-ring { from { stroke-dashoffset: var(--tf-dash-from, 999); } to { stroke-dashoffset: var(--tf-dash-to, 0); } }
  @keyframes tf-flash { 0% { background-color: rgba(34,211,238,0.22); } 100% { background-color: transparent; } }
  @keyframes tf-pulse-ring { 0% { transform: scale(0.9); opacity: 0.7; } 70% { transform: scale(2.2); opacity: 0; } 100% { opacity: 0; } }
  @keyframes tf-dash { to { stroke-dashoffset: -24; } }

  .trustfabric-shell .tf-rise { animation: tf-rise 460ms var(--tf-ease) both; }
  .trustfabric-shell .tf-fade { animation: tf-fade 320ms ease both; }
  .trustfabric-shell .tf-flash { animation: tf-flash 1100ms ease-out 1; }

  /* Score dial sweep - the arc draws to its measured value on first paint. */
  .trustfabric-shell .tf-dial-arc { animation: tf-ring 900ms var(--tf-ease) both; }

  /* Live indicator: an expanding halo, only rendered while connected. */
  .trustfabric-shell .tf-live-halo { animation: tf-pulse-ring 2.4s ease-out infinite; }

  /* Loading shimmer for skeleton rows. */
  .trustfabric-shell .tf-shimmer { position: relative; overflow: hidden; }
  .trustfabric-shell .tf-shimmer::after {
    content: ''; position: absolute; inset: 0;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.07), transparent);
    animation: tf-sweep 1.6s linear infinite;
  }

  /* Graph edge flow - direction of trust, drawn only on measured links. */
  .trustfabric-shell .tf-edge-flow { stroke-dasharray: 5 7; animation: tf-dash 1.4s linear infinite; }

  .trustfabric-shell .tf-hover-lift { transition: transform 220ms var(--tf-ease), border-color 220ms ease, background-color 220ms ease; }
  .trustfabric-shell .tf-hover-lift:hover { transform: translateY(-2px); }

  .qg-theme-light .trustfabric-shell .tf-node-card { background-color: rgba(255,255,255,0.9) !important; }

  @media (prefers-reduced-motion: reduce) {
    .trustfabric-shell .tf-rise,
    .trustfabric-shell .tf-fade,
    .trustfabric-shell .tf-flash,
    .trustfabric-shell .tf-dial-arc,
    .trustfabric-shell .tf-live-halo,
    .trustfabric-shell .tf-edge-flow,
    .trustfabric-shell .tf-shimmer::after { animation: none !important; }
    .trustfabric-shell .tf-hover-lift:hover { transform: none; }
  }
`;

/** Staggered entrance for a grid of panels, capped so long lists stay snappy. */
export function riseStyle(index: number, step = 45, cap = 10): React.CSSProperties {
  return { animationDelay: `${Math.min(index, cap) * step}ms` };
}

/* ------------------------------------------------------------------ */
/* Trust state vocabulary                                              */
/* ------------------------------------------------------------------ */

export const TRUST_STATE_TONE: Record<TrustState, Tone> = {
  trusted: 'good',
  healthy: 'good',
  'pqc-ready': 'good',
  degraded: 'warning',
  'at-risk': 'warning',
  'migration-required': 'warning',
  'quantum-vulnerable': 'critical',
  critical: 'critical',
  expired: 'critical',
  invalid: 'critical',
  unknown: 'neutral',
};

/** Why a state means what it means - shown on hover everywhere it appears. */
export const TRUST_STATE_HINT: Record<TrustState, string> = {
  trusted: 'Anchored to a collected certificate authority with no open weaknesses.',
  healthy: 'Measured and within policy.',
  'pqc-ready': 'Uses post-quantum or hybrid cryptography.',
  degraded: 'Open weaknesses below high severity, or an incomplete chain.',
  'at-risk': 'High-severity findings, or expiry inside the renewal window.',
  'migration-required': 'Classical cryptography scheduled for replacement.',
  'quantum-vulnerable': 'Classical cryptography that a quantum computer will break.',
  critical: 'Critical findings open, or fewer than seven days of certificate validity.',
  expired: 'Validity window has passed - clients that check expiry reject it.',
  invalid: 'Revoked, self-signed, name-mismatched or weakly signed - a trust check fails while the certificate is still in its validity window.',
  unknown: 'No measurement exists yet. This is not the same as healthy.',
};

export function TrustStateBadge({ state, reason, size = 'md' }: { state: TrustState; reason?: string; size?: 'sm' | 'md' }) {
  const tone = TRUST_STATE_TONE[state];
  const t = TONE[tone];
  return (
    <span
      title={reason || TRUST_STATE_HINT[state]}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border font-black uppercase tracking-wider',
        size === 'sm' ? 'px-1.5 py-0.5 text-[8.5px]' : 'px-2 py-1 text-[9px]',
        t.soft,
        t.border,
        t.text,
      )}
    >
      <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', t.dot)} aria-hidden="true" />
      {TRUST_STATE_LABEL[state]}
    </span>
  );
}

export function NodeKindBadge({ kind }: { kind: TrustNodeKind }) {
  return (
    <span className="inline-flex items-center rounded-md border border-white/12 bg-white/[0.04] px-1.5 py-0.5 text-[8.5px] font-black uppercase tracking-wider text-white/50">
      {TRUST_NODE_LABEL[kind]}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Cross-page navigation - the four pages are one workflow             */
/* ------------------------------------------------------------------ */

const TRUST_TABS = [
  { path: '/dashboard/trust-dashboard', label: 'Trust Dashboard', blurb: 'Estate-wide cryptographic trust posture' },
  { path: '/dashboard/trust-state-discovery', label: 'Trust-State Discovery', blurb: 'What was discovered and how it is related' },
  { path: '/dashboard/certificate-telemetry', label: 'Certificate Telemetry', blurb: 'Certificate lifecycle and chain validation' },
  { path: '/dashboard/multi-cloud-telemetry', label: 'Multi-Cloud Telemetry', blurb: 'Cross-cloud cryptographic visibility' },
];

export function TrustModuleNav() {
  const { pathname } = useLocation();
  return (
    <nav aria-label="Trust and telemetry modules" className="flex flex-wrap gap-1.5">
      {TRUST_TABS.map((tab) => {
        const activeTab = pathname === tab.path;
        return (
          <Link
            key={tab.path}
            to={tab.path}
            title={tab.blurb}
            aria-current={activeTab ? 'page' : undefined}
            className={cn(
              'rounded-lg border px-3 py-1.5 text-[10px] font-black uppercase tracking-wider no-underline transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
              activeTab
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
/* Score dial                                                          */
/* ------------------------------------------------------------------ */

/**
 * A trust score that shows its own confidence.
 *
 * The arc is the value; the faint outer ring is COVERAGE - what share of the
 * population the score was computed over. A 92 drawn on a thin coverage ring is
 * immediately readable as "high score, narrow basis", which is the distinction
 * a single number always loses.
 */
export function ScoreDial({
  score,
  size = 132,
  onSelect,
}: {
  score: TrustScore;
  size?: number;
  onSelect?: () => void;
}) {
  const gradientId = useId();
  const tone = TONE[score.tone];
  const radius = size / 2 - 12;
  const circumference = 2 * Math.PI * radius;
  const value = score.value ?? 0;
  const dashTo = circumference * (1 - value / 100);
  const coverageRadius = radius + 7;
  const coverageCircumference = 2 * Math.PI * coverageRadius;

  const body = (
    <>
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`${score.label}: ${score.measured ? value : 'not measured'}`}>
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor={tone.hex} stopOpacity="0.95" />
              <stop offset="100%" stopColor={tone.hex} stopOpacity="0.45" />
            </linearGradient>
          </defs>

          {/* coverage ring - how much of the estate this score can speak for */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={coverageRadius}
            fill="none"
            stroke="rgba(255,255,255,0.06)"
            strokeWidth={2}
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={coverageRadius}
            fill="none"
            stroke="rgba(255,255,255,0.28)"
            strokeWidth={2}
            strokeDasharray={coverageCircumference}
            strokeDashoffset={coverageCircumference * (1 - Math.max(0, Math.min(100, score.coveragePercent)) / 100)}
            strokeLinecap="round"
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
          />

          {/* track */}
          <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={9} />
          {/* value */}
          {score.measured ? (
            <circle
              className="tf-dial-arc"
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke={`url(#${gradientId})`}
              strokeWidth={9}
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={dashTo}
              transform={`rotate(-90 ${size / 2} ${size / 2})`}
              style={{ ['--tf-dash-from' as string]: `${circumference}`, ['--tf-dash-to' as string]: `${dashTo}` }}
            />
          ) : null}
        </svg>
        <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
          {score.measured ? (
            <>
              <span className={cn('text-[26px] font-black leading-none', tone.text)}>{value}</span>
              <span className="mt-8 text-[8.5px] font-black uppercase tracking-wider text-white/30">of 100</span>
            </>
          ) : (
            <span className="px-4 text-[10px] font-black uppercase leading-tight tracking-wider text-white/35">Not measured</span>
          )}
        </div>
      </div>

      <div className="mt-2 text-center">
        <div className="flex items-center justify-center gap-1 text-[10px] font-black uppercase tracking-wider text-white/70">
          {score.label}
          <Term hint={`${score.basis} Basis: ${score.denominator}.`} label={score.label} />
        </div>
        <p className="mt-1 text-[9.5px] font-medium leading-snug text-white/40">{score.denominator}</p>
      </div>
    </>
  );

  const shared =
    'qg-executive-panel tf-hover-lift relative flex flex-col items-center overflow-hidden rounded-xl p-4 text-white no-underline';

  if (score.href) {
    return (
      <Link to={score.href} title={score.reason} onClick={onSelect} className={cn(shared, 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70')}>
        {body}
      </Link>
    );
  }
  return (
    <div title={score.reason} className={shared}>
      {body}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* KPI tile with drill-down                                            */
/* ------------------------------------------------------------------ */

/**
 * Flashes when its value changes, so a live dashboard shows movement without
 * the operator having to diff it by eye. The flash is suppressed on first paint
 * (there is no "change" to announce) and under reduced motion.
 */
export function LiveValue({ value, className }: { value: string; className?: string }) {
  const [flash, setFlash] = useState(false);
  const previous = useRef<string | null>(null);

  useEffect(() => {
    if (previous.current !== null && previous.current !== value) {
      setFlash(true);
      const timer = setTimeout(() => setFlash(false), 1100);
      return () => clearTimeout(timer);
    }
    previous.current = value;
    return undefined;
  }, [value]);

  useEffect(() => {
    previous.current = value;
  }, [value]);

  return <span className={cn(flash && 'tf-flash rounded px-1', className)}>{value}</span>;
}

export function TrustKpiTile({
  label,
  value,
  detail,
  tone = 'neutral',
  hint,
  href,
  onClick,
  index = 0,
}: {
  label: string;
  value: number | null;
  detail?: string;
  tone?: Tone;
  hint?: string;
  href?: string;
  onClick?: () => void;
  index?: number;
}) {
  const t = TONE[tone];
  const measured = value !== null;

  const body = (
    <>
      <div className="flex items-center gap-1.5 text-[9.5px] font-black uppercase tracking-[0.12em] text-white/45">
        {label}
        {/* Above the stretched control so the explanation stays independently focusable and clickable. */}
        {hint ? <span className="pointer-events-auto relative z-10"><Term hint={hint} label={label} /></span> : null}
      </div>
      <div className={cn('mt-2 text-[26px] font-black leading-none', measured ? t.text : 'text-white/35')}>
        {measured ? <LiveValue value={fmtNumber(value)} /> : 'Not measured'}
      </div>
      {detail ? <div className="mt-1.5 text-[10px] font-medium leading-snug text-white/40">{detail}</div> : null}
      {href || onClick ? (
        <span className="mt-2 inline-flex items-center gap-1 text-[9px] font-black uppercase tracking-wider text-cyan-300/70 opacity-0 transition group-hover:opacity-100">
          Investigate <ArrowRight className="h-3 w-3" aria-hidden="true" />
        </span>
      ) : null}
    </>
  );

  const shared =
    'qg-executive-panel tf-rise tf-hover-lift group relative block overflow-hidden rounded-xl p-4 text-left text-white no-underline focus-within:ring-2 focus-within:ring-cyan-300/70';

  /*
   * Stretched control: the tile is a container and the button / link that
   * makes it clickable is a SIBLING of the body, covering it. Wrapping the body
   * in a <button> or <a> nested the hint's own <button> inside it — invalid
   * HTML that React reports as a hydration error and that breaks keyboard and
   * screen-reader navigation of the hint.
   */
  const stretched = 'absolute inset-0 z-0 rounded-xl focus-visible:outline-none';
  const accessibleName = `${label}: ${measured ? fmtNumber(value) : 'not measured'}${detail ? ` — ${detail}` : ''}`;
  return (
    <div style={riseStyle(index)} className={cn(shared, !onClick && !href && 'cursor-default')}>
      {onClick ? (
        <button type="button" onClick={onClick} aria-label={accessibleName} className={stretched} />
      ) : href ? (
        <Link to={href} aria-label={accessibleName} className={stretched} />
      ) : null}
      <div className="pointer-events-none relative">{body}</div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Live stream indicator                                               */
/* ------------------------------------------------------------------ */

export function LiveDot({ live }: { live: boolean }) {
  return (
    <span className="relative inline-flex h-2 w-2" aria-hidden="true">
      {live ? <span className="tf-live-halo absolute inset-0 rounded-full bg-emerald-400/60" /> : null}
      <span className={cn('relative inline-flex h-2 w-2 rounded-full', live ? 'bg-emerald-400' : 'bg-amber-300')} />
    </span>
  );
}

/**
 * Stale-data banner (section 13).
 *
 * Distinct from the connection indicator on purpose: the stream can be
 * perfectly connected while the underlying evidence is three days old, and an
 * operator must not read a live green dot as fresh data.
 */
export function StaleBanner({ hours, onRefresh }: { hours: number; onRefresh: () => void }) {
  return (
    <div className="tf-fade flex flex-wrap items-center gap-3 rounded-xl border border-amber-500/30 bg-amber-500/[0.07] p-3">
      <AlertTriangle className="h-4 w-4 shrink-0 text-amber-300" aria-hidden="true" />
      <p className="min-w-0 flex-1 text-[11.5px] font-medium leading-relaxed text-amber-100/85">
        <span className="font-black uppercase tracking-wider">Telemetry is stale.</span> No new cryptographic evidence has arrived for{' '}
        {hours} hour{hours === 1 ? '' : 's'}. Everything below reflects the last successful collection, not the present state of the
        estate.
      </p>
      <button
        type="button"
        onClick={onRefresh}
        className="rounded-lg border border-amber-400/40 bg-amber-500/10 px-3 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-amber-200 transition hover:bg-amber-500/20"
      >
        Re-check now
      </button>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Chain check list (section 5)                                        */
/* ------------------------------------------------------------------ */

const CHECK_ICON = {
  pass: CheckCircle2,
  fail: XCircle,
  warn: ShieldAlert,
  'not-evaluated': MinusCircle,
} as const;

const CHECK_TONE: Record<ChainCheck['status'], Tone> = {
  pass: 'good',
  fail: 'critical',
  warn: 'warning',
  'not-evaluated': 'neutral',
};

const CHECK_STATUS_LABEL: Record<ChainCheck['status'], string> = {
  pass: 'Pass',
  fail: 'Fail',
  warn: 'Warning',
  'not-evaluated': 'Not evaluated',
};

export function ChainCheckList({ checks }: { checks: ChainCheck[] }) {
  if (!checks.length) return <PanelEmpty>No validation checks could be run against this certificate.</PanelEmpty>;
  return (
    <ul className="space-y-1.5">
      {checks.map((check, index) => {
        const Icon = CHECK_ICON[check.status];
        const tone = TONE[CHECK_TONE[check.status]];
        return (
          <li
            key={check.key}
            style={riseStyle(index, 30)}
            className={cn('tf-rise flex items-start gap-2.5 rounded-lg border p-2.5', tone.border, tone.soft)}
          >
            <Icon className={cn('mt-0.5 h-3.5 w-3.5 shrink-0', tone.text)} aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[10.5px] font-black uppercase tracking-wider text-white/80">{check.label}</span>
                <span className={cn('text-[9px] font-black uppercase tracking-wider', tone.text)}>
                  {CHECK_STATUS_LABEL[check.status]}
                </span>
              </div>
              <p className="mt-1 text-[10.5px] leading-relaxed text-white/50">{check.detail}</p>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

/* ------------------------------------------------------------------ */
/* Expiry meter                                                        */
/* ------------------------------------------------------------------ */

/**
 * Renders remaining certificate lifetime against the platform's expiry bands.
 * An unknown expiry renders as an explicit "not recorded" bar rather than an
 * empty one, which would read identically to "expires today".
 */
export function ExpiryMeter({ days }: { days: number | null }) {
  if (days === null) {
    return (
      <div className="flex items-center gap-2">
        <div className="h-1.5 w-full rounded-full border border-dashed border-white/20" />
        <span className="shrink-0 text-[9.5px] font-semibold text-white/35">Not recorded</span>
      </div>
    );
  }
  const tone: Tone = days < 0 ? 'critical' : days <= 7 ? 'critical' : days <= 30 ? 'warning' : days <= 60 ? 'info' : 'good';
  const t = TONE[tone];
  // 180 days is the full bar - beyond that the distinction stops mattering.
  const fill = Math.max(2, Math.min(100, ((days < 0 ? 0 : days) / 180) * 100));
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/8">
        <div className={cn('h-full rounded-full transition-[width] duration-700', t.dot)} style={{ width: `${fill}%` }} />
      </div>
      <span className={cn('shrink-0 font-mono text-[9.5px] font-bold', t.text)}>
        {days < 0 ? `-${Math.abs(days)}d` : `${days}d`}
      </span>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Encryption / provider chips                                         */
/* ------------------------------------------------------------------ */

const ENCRYPTION_TONE: Record<EncryptionState, Tone> = {
  encrypted: 'good',
  'partially-encrypted': 'warning',
  unencrypted: 'critical',
  'not-observed': 'neutral',
};

const ENCRYPTION_LABEL: Record<EncryptionState, string> = {
  encrypted: 'Encrypted',
  'partially-encrypted': 'Partial',
  unencrypted: 'Unencrypted',
  'not-observed': 'Not observed',
};

export function EncryptionBadge({ state }: { state: EncryptionState }) {
  const tone = ENCRYPTION_TONE[state];
  return (
    <Pill
      tone={tone}
      title={
        state === 'not-observed'
          ? 'No connector or agent has read this resource’s encryption configuration. This is not the same as unencrypted.'
          : undefined
      }
    >
      {ENCRYPTION_LABEL[state]}
    </Pill>
  );
}

const PROVIDER_ACCENT: Record<CloudProviderId, string> = {
  aws: '#ff9900',
  azure: '#38bdf8',
  gcp: '#34d399',
  kubernetes: '#818cf8',
  'private-cloud': '#94a3b8',
  hybrid: '#a78bfa',
  oracle: '#f87171',
  ibm: '#60a5fa',
  alibaba: '#fb923c',
  digitalocean: '#38bdf8',
  cloudflare: '#fbbf24',
  other: '#22d3ee',
  unattributed: '#64748b',
};

export function ProviderChip({ provider, label }: { provider: CloudProviderId; label?: string }) {
  const accent = PROVIDER_ACCENT[provider] ?? PROVIDER_ACCENT.other;
  return (
    <span
      className="tlspki-ink inline-flex items-center gap-1.5 rounded-md border px-1.5 py-0.5 text-[9px] font-black uppercase tracking-wider"
      style={{ borderColor: `${accent}55`, backgroundColor: `${accent}14`, color: accent }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: accent }} aria-hidden="true" />
      {label || CLOUD_PROVIDER_LABEL[provider]}
    </span>
  );
}

export function providerAccent(provider: CloudProviderId): string {
  return PROVIDER_ACCENT[provider] ?? PROVIDER_ACCENT.other;
}

/* ------------------------------------------------------------------ */
/* Event stream                                                        */
/* ------------------------------------------------------------------ */

const EVENT_TONE: Record<string, Tone> = {
  critical: 'critical',
  high: 'critical',
  medium: 'warning',
  low: 'neutral',
};

/**
 * Live cryptographic event feed.
 *
 * New rows animate in at the top so a change is visible on a wall display
 * without a refresh. Each row is a link into the subject it names, because an
 * event the operator cannot act on is just noise.
 */
export function EventStream({
  events,
  limit = 12,
  emptyLabel = 'No cryptographic trust events have been recorded in the last 30 days.',
}: {
  events: TrustEvent[];
  limit?: number;
  emptyLabel?: string;
}) {
  const shown = useMemo(() => events.slice(0, limit), [events, limit]);
  if (!shown.length) return <PanelEmpty>{emptyLabel}</PanelEmpty>;

  return (
    <ol className="space-y-1.5">
      {shown.map((event, index) => {
        const tone = TONE[EVENT_TONE[event.severity] ?? 'neutral'];
        const row = (
          <>
            <span className={cn('mt-1 h-1.5 w-1.5 shrink-0 rounded-full', tone.dot)} aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                <span className="truncate text-[11.5px] font-bold text-white/85">{event.title}</span>
                <span className="shrink-0 text-[9px] font-black uppercase tracking-wider text-white/30">{event.label}</span>
              </div>
              <p className="mt-0.5 line-clamp-2 text-[10.5px] leading-snug text-white/45">{event.detail}</p>
              <div className="mt-1 flex flex-wrap items-center gap-2 font-mono text-[9.5px] text-white/30">
                <span>{relativeTime(event.at)}</span>
                <span>·</span>
                <span>{event.source}</span>
                {event.region ? (
                  <>
                    <span>·</span>
                    <span>{event.region}</span>
                  </>
                ) : null}
              </div>
            </div>
          </>
        );

        const className = cn(
          'tf-rise tf-hover-lift flex items-start gap-2.5 rounded-lg border border-white/8 bg-black/20 p-2.5 no-underline',
          'hover:border-cyan-400/30 hover:bg-black/35',
        );

        return (
          <li key={event.id} style={riseStyle(index, 35)}>
            {event.subjectHref ? (
              <Link to={event.subjectHref} className={className}>
                {row}
              </Link>
            ) : (
              <div className={cn(className, 'cursor-default')}>{row}</div>
            )}
          </li>
        );
      })}
    </ol>
  );
}

/* ------------------------------------------------------------------ */
/* Reconciliation panel (section 16)                                   */
/* ------------------------------------------------------------------ */

export function ReconciliationPanel({
  report,
  compact = false,
}: {
  report: {
    issues: Array<{ id: string; title: string; detail: string; severity: string; count: number; sourceTable: string; remediation: string; href: string }>;
    crossModule: Array<{ key: string; label: string; value: number; comparedWith: string; comparedValue: number; agrees: boolean; note: string }>;
    dataQuality: number;
    dataQualityMeasured: boolean;
  };
  compact?: boolean;
}) {
  const disagreements = report.crossModule.filter((check) => !check.agrees);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-baseline gap-2">
          <span className="text-[9.5px] font-black uppercase tracking-wider text-white/40">Data quality</span>
          <span
            className={cn(
              'text-[20px] font-black leading-none',
              !report.dataQualityMeasured
                ? 'text-white/35'
                : report.dataQuality >= 80
                  ? 'text-emerald-300'
                  : report.dataQuality >= 55
                    ? 'text-amber-300'
                    : 'text-red-300',
            )}
          >
            {report.dataQualityMeasured ? fmtPercent(report.dataQuality) : 'Not measured'}
          </span>
        </div>
        <Pill tone={disagreements.length === 0 ? 'good' : 'warning'}>
          {report.crossModule.length - disagreements.length}/{report.crossModule.length} cross-module checks agree
        </Pill>
      </div>

      {/* Cross-module agreement - section 7 made visible rather than asserted. */}
      <ul className="grid gap-1.5 sm:grid-cols-2">
        {report.crossModule.map((check) => (
          <li
            key={check.key}
            title={check.note}
            className={cn(
              'flex items-center justify-between gap-2 rounded-lg border px-2.5 py-2',
              check.agrees ? 'border-emerald-500/20 bg-emerald-500/[0.05]' : 'border-amber-500/25 bg-amber-500/[0.06]',
            )}
          >
            <div className="min-w-0">
              <span className="block truncate text-[10.5px] font-bold text-white/75">{check.label}</span>
              <span className="block truncate text-[9.5px] text-white/40">vs {check.comparedWith}</span>
            </div>
            <span className={cn('shrink-0 font-mono text-[11px] font-black', check.agrees ? 'text-emerald-300' : 'text-amber-300')}>
              {fmtNumber(check.value)}
              {check.agrees ? '' : ` / ${fmtNumber(check.comparedValue)}`}
            </span>
          </li>
        ))}
      </ul>

      {report.issues.length === 0 ? (
        <PanelEmpty>No data-quality discrepancies detected across the trust inventory.</PanelEmpty>
      ) : (
        <ul className="space-y-1.5">
          {report.issues.slice(0, compact ? 3 : 12).map((issue, index) => {
            const tone = TONE[EVENT_TONE[issue.severity] ?? 'neutral'];
            return (
              <li key={issue.id} style={riseStyle(index, 35)} className="tf-rise">
                <Link
                  to={issue.href}
                  className={cn(
                    'tf-hover-lift block rounded-lg border p-2.5 no-underline',
                    tone.border,
                    tone.soft,
                    'hover:brightness-125',
                  )}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={cn('text-[10.5px] font-black uppercase tracking-wider', tone.text)}>{issue.title}</span>
                    <span className="rounded bg-black/30 px-1.5 py-0.5 font-mono text-[9px] text-white/50">{issue.count}</span>
                    <span className="font-mono text-[9px] text-white/30">{issue.sourceTable}</span>
                  </div>
                  <p className="mt-1 text-[10.5px] leading-relaxed text-white/50">{issue.detail}</p>
                  {!compact ? (
                    <p className="mt-1 text-[10px] leading-relaxed text-cyan-200/60">
                      <span className="font-black uppercase tracking-wider">Fix:</span> {issue.remediation}
                    </p>
                  ) : null}
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Skeletons                                                           */
/* ------------------------------------------------------------------ */

export function TrustSkeleton({ rows = 4, height = 64 }: { rows?: number; height?: number }) {
  return (
    <div className="space-y-2" role="status" aria-label="Loading">
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="tf-shimmer rounded-lg border border-white/8 bg-white/[0.03]" style={{ height }} />
      ))}
    </div>
  );
}

export function KpiSkeleton({ count = 7 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 xl:grid-cols-7">
      {Array.from({ length: count }).map((_, index) => (
        <div key={index} className="tf-shimmer h-[96px] rounded-xl border border-white/8 bg-white/[0.03]" />
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Section wrapper                                                     */
/* ------------------------------------------------------------------ */

export function TrustPanel({
  children,
  className,
  index = 0,
  id,
}: {
  children: ReactNode;
  className?: string;
  index?: number;
  id?: string;
}) {
  return (
    <div className="tf-rise" style={riseStyle(index)}>
      <Panel id={id} className={className}>
        {children}
      </Panel>
    </div>
  );
}

/** Small inline explainer used where a number needs a denominator stated. */
export function Basis({ children }: { children: ReactNode }) {
  return (
    <p className="mt-2 flex items-start gap-1.5 text-[9.5px] leading-relaxed text-white/30">
      <HelpCircle className="mt-px h-3 w-3 shrink-0" aria-hidden="true" />
      <span>{children}</span>
    </p>
  );
}
