'use client';

import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { AlertTriangle, ChevronRight, RefreshCw, WifiOff } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Panel } from '../executive/primitives';

/**
 * Shared enterprise UI kit for the Intelligence dashboards.
 *
 * Quantum Risk Scoring, Vulnerabilities, Drift Detection and Telemetry
 * Correlation are four views of the same estate, so they must look and behave
 * like one product: the same header, the same live-state vocabulary, the same
 * empty and error states, the same rule that an unmeasured value renders as an
 * em dash rather than a zero.
 *
 * Every component here is presentational. Not one of them computes a number.
 */

/* ------------------------------------------------------------------ */
/* Palette                                                             */
/* ------------------------------------------------------------------ */

export const GREEN = '#34d399';
export const BLUE = '#60a5fa';
export const AMBER = '#fbbf24';
export const ORANGE = '#fb923c';
export const RED = '#f87171';
export const SLATE = '#94a3b8';
export const CYAN = '#22d3ee';
export const VIOLET = '#a78bfa';

/** Risk is never carried by colour alone — every level ships a glyph and a word. */
export const LEVEL_HEX: Record<string, string> = {
  critical: RED,
  high: ORANGE,
  elevated: AMBER,
  medium: AMBER,
  moderate: AMBER,
  low: GREEN,
  minimal: GREEN,
  clear: GREEN,
  unassessed: SLATE,
  unknown: SLATE,
};

export const LEVEL_GLYPH: Record<string, string> = {
  critical: '●',
  high: '●',
  elevated: '◐',
  medium: '◐',
  moderate: '◐',
  low: '✓',
  minimal: '✓',
  clear: '✓',
  unassessed: '?',
  unknown: '?',
};

export function levelHex(level: string | null | undefined): string {
  const key = String(level ?? '').toLowerCase();
  for (const [name, hex] of Object.entries(LEVEL_HEX)) if (key.includes(name)) return hex;
  return SLATE;
}

export function levelGlyph(level: string | null | undefined): string {
  const key = String(level ?? '').toLowerCase();
  for (const [name, glyph] of Object.entries(LEVEL_GLYPH)) if (key.includes(name)) return glyph;
  return '?';
}

/* ------------------------------------------------------------------ */
/* Formatting                                                          */
/* ------------------------------------------------------------------ */

export function fmtInt(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return new Intl.NumberFormat('en-US').format(Math.round(value));
}

export function fmtCompact(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  if (Math.abs(value) >= 1000) return new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(value);
  return fmtInt(value);
}

/** An unmeasured percentage renders as an em dash. Never as 0%. */
export function fmtPct(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return `${Math.round(value)}%`;
}

export function fmtScore(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return String(Math.round(value));
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const then = new Date(iso).getTime();
  if (!Number.isFinite(then)) return 'never';
  const diff = Date.now() - then;
  if (diff < 5000) return 'just now';
  if (diff < 60_000) return `${Math.max(1, Math.floor(diff / 1000))}s ago`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

export function fullTimestamp(iso: string | null | undefined): string {
  if (!iso) return 'Not recorded';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return 'Not recorded';
  return date.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
}

/* ------------------------------------------------------------------ */
/* Shell + theme                                                       */
/* ------------------------------------------------------------------ */

/**
 * Page shell. Owns the dark navy base, the light-theme overrides and the
 * reduced-motion opt-out, so no page has to restate them.
 */
export function IntelShell({ name, children }: { name: string; children: ReactNode }) {
  return (
    <div className={`intel-shell ${name} min-h-screen space-y-4 p-3 lg:p-5`}>
      <style>{`
        .intel-shell { background: var(--qg-dashboard-bg, #0a1020); }
        .qg-theme-light .intel-shell [class*="bg-black/"] { background-color: rgba(255,255,255,0.55) !important; }
        .qg-theme-light .intel-shell [class*="bg-[#0b1424]"] { background-color: rgba(255,255,255,0.92) !important; }
        .qg-theme-light .intel-shell [class*="border-white/"] { border-color: rgba(9,13,22,0.10) !important; }
        .qg-theme-light .intel-shell .text-white { color: var(--qg-dashboard-text) !important; }
        .qg-theme-light .intel-shell [class*="text-white/"] { color: var(--qg-dashboard-text-soft) !important; }
        .qg-theme-light .intel-shell .text-cyan-200,
        .qg-theme-light .intel-shell .text-cyan-300 { color: #0e7490 !important; }
        .qg-theme-light .intel-shell .text-emerald-200,
        .qg-theme-light .intel-shell .text-emerald-300 { color: #047857 !important; }
        .qg-theme-light .intel-shell .text-amber-200,
        .qg-theme-light .intel-shell .text-amber-300 { color: #b45309 !important; }
        .qg-theme-light .intel-shell .text-red-200,
        .qg-theme-light .intel-shell .text-red-300 { color: #dc2626 !important; }
        .qg-theme-light .intel-shell .text-violet-200,
        .qg-theme-light .intel-shell .text-violet-300 { color: #7c3aed !important; }
        .qg-theme-light .intel-shell input::placeholder { color: rgba(9,13,22,0.35) !important; }
        @media (prefers-reduced-motion: reduce) {
          .intel-shell *, .intel-shell *::before, .intel-shell *::after {
            animation-duration: 0.001ms !important;
            transition-duration: 0.001ms !important;
          }
        }
      `}</style>
      {children}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Live status                                                         */
/* ------------------------------------------------------------------ */

/** Mirrors `LiveTransport` in hooks/use-live-resource.ts (kept structural so the kit stays presentational). */
export type LiveTransportState = 'connecting' | 'stream' | 'polling' | 'offline';

export type FreshnessState = 'live' | 'polling' | 'connecting' | 'stale' | 'offline';

/**
 * One reading of "how current is what I am looking at", shared by every page.
 *
 *  live        the server stream is open and re-verified the data recently
 *  polling     the stream is down; REST keeps the page current (honest, amber)
 *  connecting  nothing has answered yet
 *  stale       the last server confirmation is older than `staleAfterMs`
 *  offline     no session / no transport
 *
 * Only `live` may animate: a pulsing dot over data nobody re-verified is the
 * exact "simulated live connection" the platform forbids.
 */
export function freshnessOf(
  transport: LiveTransportState,
  lastVerifiedAt: string | null | undefined,
  staleAfterMs = 90_000,
  now: number = Date.now(),
): FreshnessState {
  if (transport === 'offline') return 'offline';
  if (transport === 'connecting' && !lastVerifiedAt) return 'connecting';
  const verified = lastVerifiedAt ? Date.parse(lastVerifiedAt) : NaN;
  if (Number.isFinite(verified) && now - verified > staleAfterMs) return 'stale';
  if (transport === 'stream') return 'live';
  if (transport === 'polling') return 'polling';
  return 'connecting';
}

const FRESHNESS_COPY: Record<FreshnessState, { label: string; hint: string; tone: string; dot: string }> = {
  live: { label: 'Live', hint: 'Server stream open', tone: 'border-emerald-400/40 bg-emerald-500/10 text-emerald-300', dot: 'bg-emerald-400' },
  polling: { label: 'Polling', hint: 'Live stream reconnecting — refreshed over REST', tone: 'border-amber-400/40 bg-amber-500/10 text-amber-300', dot: 'bg-amber-300' },
  connecting: { label: 'Connecting', hint: 'Waiting for the first server response', tone: 'border-white/15 bg-white/[0.04] text-white/60', dot: 'bg-white/40' },
  stale: { label: 'Stale', hint: 'Not re-verified recently — values may be out of date', tone: 'border-amber-400/40 bg-amber-500/10 text-amber-300', dot: 'bg-amber-300' },
  offline: { label: 'Offline', hint: 'No live connection', tone: 'border-red-400/40 bg-red-500/10 text-red-300', dot: 'bg-red-400' },
};

/**
 * Connection-health chip with the two timestamps that matter: when the data on
 * screen was computed, and when the server last confirmed it is still current.
 */
export function LiveStatus({
  transport, lastVerifiedAt, generatedAt, staleAfterMs, align = 'end',
}: {
  transport: LiveTransportState;
  lastVerifiedAt: string | null;
  generatedAt?: string | null;
  staleAfterMs?: number;
  align?: 'start' | 'end';
}) {
  const state = freshnessOf(transport, lastVerifiedAt, staleAfterMs);
  const copy = FRESHNESS_COPY[state];
  return (
    <div className={cn('flex flex-col', align === 'end' ? 'items-end' : 'items-start')}>
      <span
        role="status"
        aria-live="polite"
        title={copy.hint}
        className={cn('inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-[9px] font-black uppercase tracking-widest', copy.tone)}
      >
        <span className={cn('h-1.5 w-1.5 rounded-full', copy.dot, state === 'live' && 'animate-pulse motion-reduce:animate-none')} aria-hidden="true" />
        {copy.label}
        <span className="sr-only">— {copy.hint}</span>
      </span>
      <span className="mt-1 font-mono text-[9.5px] text-white/35">
        {generatedAt ? <>Computed {relativeTime(generatedAt)}</> : null}
        {generatedAt && lastVerifiedAt ? ' · ' : null}
        {lastVerifiedAt ? <>verified {relativeTime(lastVerifiedAt)}</> : generatedAt ? null : 'Not yet verified'}
      </span>
    </div>
  );
}

export function IntelHeader({
  title, accent, subtitle, icon: Icon, live, lastUpdated, connecting, transport, lastVerifiedAt, children,
}: {
  title: string;
  accent: string;
  subtitle: string;
  icon: LucideIcon;
  /** Legacy boolean status — prefer `transport` + `lastVerifiedAt`. */
  live?: boolean;
  lastUpdated: string | null;
  connecting?: boolean;
  /** When supplied, the header renders the shared `LiveStatus` chip. */
  transport?: LiveTransportState;
  lastVerifiedAt?: string | null;
  children?: ReactNode;
}) {
  return (
    <header className="flex flex-col gap-3 border-b border-white/10 pb-3.5 xl:flex-row xl:items-end xl:justify-between">
      <div className="flex items-center gap-3">
        <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-cyan-400/30 bg-gradient-to-br from-cyan-500/15 to-violet-500/10 text-cyan-300 shadow-[0_0_28px_rgba(34,211,238,0.16)]">
          <Icon className="h-5 w-5" aria-hidden="true" />
        </div>
        <div className="min-w-0">
          <h1 className="text-2xl font-black uppercase leading-none tracking-tight text-white lg:text-[26px]">
            {title} <span className="text-cyan-300">{accent}</span>
          </h1>
          <p className="mt-1.5 max-w-3xl text-[12px] font-medium leading-relaxed text-white/50">{subtitle}</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {transport ? (
          <LiveStatus transport={transport} lastVerifiedAt={lastVerifiedAt ?? null} generatedAt={lastUpdated} />
        ) : (
          <div className="flex flex-col items-end">
            <span
              role="status"
              className={cn(
                'inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-[9px] font-black uppercase tracking-widest',
                live ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-300' : 'border-amber-400/40 bg-amber-500/10 text-amber-300',
              )}
            >
              <span className={cn('h-1.5 w-1.5 rounded-full', live ? 'animate-pulse bg-emerald-400 motion-reduce:animate-none' : 'bg-amber-300')} aria-hidden="true" />
              {connecting ? 'Connecting' : live ? 'Live' : 'Connection lost'}
            </span>
            <span className="mt-1 font-mono text-[9.5px] text-white/30">Last updated: {relativeTime(lastUpdated)}</span>
          </div>
        )}
        {children}
      </div>
    </header>
  );
}

/* ------------------------------------------------------------------ */
/* Module brief — what / why / what next                               */
/* ------------------------------------------------------------------ */

/**
 * The three questions a first-time reader asks before any number means
 * anything: what is this page, why does it matter, and what should I do now.
 * `next` is the single most valuable action the evidence supports right now —
 * computed by the page from its model, never a static marketing line.
 */
export function ModuleBrief({
  what, why, next, scope,
}: {
  what: ReactNode;
  why: ReactNode;
  next: { label: string; detail?: ReactNode; href?: string; onClick?: () => void; tone?: 'action' | 'calm' | 'warning' };
  /** Population the page describes ("across the tenant estate", "last 24h of runtime telemetry"). */
  scope?: ReactNode;
}) {
  const tone = next.tone ?? 'action';
  const nextTone = tone === 'warning'
    ? 'border-amber-400/35 bg-amber-500/[0.07]'
    : tone === 'calm'
      ? 'border-emerald-400/30 bg-emerald-500/[0.06]'
      : 'border-cyan-400/35 bg-cyan-500/[0.07]';
  const cta = next.href ? (
    <a href={next.href} className="mt-2 inline-flex items-center gap-1 text-[10px] font-black uppercase tracking-wider text-cyan-200 no-underline hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
      {next.label}<ChevronRight className="h-3 w-3" aria-hidden="true" />
    </a>
  ) : next.onClick ? (
    <button type="button" onClick={next.onClick} className="mt-2 inline-flex items-center gap-1 text-[10px] font-black uppercase tracking-wider text-cyan-200 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
      {next.label}<ChevronRight className="h-3 w-3" aria-hidden="true" />
    </button>
  ) : (
    <span className="mt-2 inline-block text-[10px] font-black uppercase tracking-wider text-white/60">{next.label}</span>
  );
  return (
    <section aria-label="About this module" className="grid gap-2.5 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.1fr)]">
      <div className="rounded-xl border border-white/10 bg-white/[0.025] p-3.5">
        <div className="text-[8.5px] font-black uppercase tracking-[0.18em] text-cyan-300/80">What you are looking at</div>
        <p className="mt-1.5 text-[11.5px] leading-relaxed text-white/65">{what}</p>
        {scope ? <p className="mt-1.5 text-[10px] leading-relaxed text-white/40">Scope: {scope}</p> : null}
      </div>
      <div className="rounded-xl border border-white/10 bg-white/[0.025] p-3.5">
        <div className="text-[8.5px] font-black uppercase tracking-[0.18em] text-violet-300/80">Why it matters</div>
        <p className="mt-1.5 text-[11.5px] leading-relaxed text-white/65">{why}</p>
      </div>
      <div className={cn('rounded-xl border p-3.5', nextTone)}>
        <div className="text-[8.5px] font-black uppercase tracking-[0.18em] text-white/55">Recommended next step</div>
        {next.detail ? <p className="mt-1.5 text-[11.5px] leading-relaxed text-white/75">{next.detail}</p> : null}
        {cta}
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Evidence sources                                                    */
/* ------------------------------------------------------------------ */

export type SourceHealthState = 'ok' | 'empty' | 'unavailable' | 'not-instrumented' | 'truncated';

const SOURCE_COPY: Record<SourceHealthState, { glyph: string; tone: string; word: string }> = {
  ok: { glyph: '✓', tone: 'text-emerald-300', word: 'read' },
  empty: { glyph: '○', tone: 'text-white/45', word: 'no records' },
  truncated: { glyph: '◐', tone: 'text-amber-300', word: 'capped' },
  unavailable: { glyph: '✕', tone: 'text-red-300', word: 'could not be read' },
  'not-instrumented': { glyph: '–', tone: 'text-white/40', word: 'not instrumented' },
};

/**
 * Which evidence the page actually read. A failed query is not an empty table:
 * when a source is `unavailable` its zeros are not measurements, and the strip
 * says so in words, not only in colour.
 */
export function SourceHealth({ sources, note }: { sources: Array<{ label: string; state: SourceHealthState; detail?: string }>; note?: ReactNode }) {
  const degraded = sources.some((s) => s.state === 'unavailable');
  return (
    <div
      className={cn(
        'flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded-xl border px-3.5 py-2.5',
        degraded ? 'border-red-400/30 bg-red-500/[0.06]' : 'border-white/10 bg-white/[0.02]',
      )}
      aria-label="Evidence sources"
    >
      <span className="text-[8.5px] font-black uppercase tracking-[0.18em] text-white/40">Evidence sources</span>
      {sources.map((source) => {
        const copy = SOURCE_COPY[source.state];
        return (
          <span key={source.label} className="inline-flex items-center gap-1.5 text-[10.5px] text-white/60" title={source.detail || `${source.label}: ${copy.word}`}>
            <span className={cn('font-black', copy.tone)} aria-hidden="true">{copy.glyph}</span>
            {source.label}
            {source.state !== 'ok' ? <span className={cn('text-[9.5px]', copy.tone)}>· {copy.word}</span> : null}
          </span>
        );
      })}
      {degraded ? (
        <span className="w-full text-[10px] leading-relaxed text-red-200/90">
          Some evidence could not be read. Figures that depend on it are incomplete — they are not measurements of zero.
        </span>
      ) : null}
      {note ? <span className="w-full text-[10px] leading-relaxed text-white/40">{note}</span> : null}
    </div>
  );
}

export function HeaderButton({
  onClick, icon: Icon, children, active, disabled, spin,
}: {
  onClick: () => void;
  icon: LucideIcon;
  children: ReactNode;
  active?: boolean;
  disabled?: boolean;
  spin?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-[9px] font-black uppercase tracking-wider transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70 disabled:cursor-not-allowed disabled:opacity-40',
        active ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200' : 'border-white/12 bg-white/[0.04] text-white/60 hover:bg-white/[0.08]',
      )}
    >
      <Icon className={cn('h-3.5 w-3.5', spin && 'animate-spin')} aria-hidden="true" />
      {children}
    </button>
  );
}

export function PrimaryButton({ onClick, icon: Icon, children, spin }: { onClick: () => void; icon: LucideIcon; children: ReactNode; spin?: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
    >
      <Icon className={cn('h-3.5 w-3.5', spin && 'animate-spin')} aria-hidden="true" />
      {children}
    </button>
  );
}

/* ------------------------------------------------------------------ */
/* Tabs                                                                */
/* ------------------------------------------------------------------ */

export function IntelTabs<T extends string>({
  tabs, active, onChange, idPrefix,
}: {
  tabs: Array<{ key: T; label: string; badge?: number }>;
  active: T;
  onChange: (key: T) => void;
  idPrefix: string;
}) {
  return (
    <div role="tablist" aria-label="Views" className="flex flex-wrap gap-1.5 border-b border-white/10 pb-1">
      {tabs.map((tab) => (
        <button
          key={tab.key}
          type="button"
          role="tab"
          id={`${idPrefix}-tab-${tab.key}`}
          aria-selected={active === tab.key}
          aria-controls={`${idPrefix}-panel-${tab.key}`}
          onClick={() => onChange(tab.key)}
          className={cn(
            'rounded-t-lg border-b-2 px-4 py-2 text-[10.5px] font-black uppercase tracking-wider transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
            active === tab.key ? 'border-cyan-400 text-cyan-200' : 'border-transparent text-white/40 hover:text-white/70',
          )}
        >
          {tab.label}
          {tab.badge ? <span className="ml-1.5 rounded-full bg-red-500/20 px-1.5 py-0.5 font-mono text-[9px] text-red-300">{tab.badge}</span> : null}
        </button>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Section heading                                                     */
/* ------------------------------------------------------------------ */

export function SectionHeading({
  title, icon: Icon, meta, action, id,
}: {
  title: string;
  icon: LucideIcon;
  meta?: ReactNode;
  action?: ReactNode;
  id?: string;
}) {
  return (
    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
      <h2 id={id} className="flex items-center gap-2 text-[11px] font-black uppercase tracking-[0.18em] text-white/70">
        <Icon className="h-3.5 w-3.5 text-cyan-300" aria-hidden="true" />
        {title}
        {meta ? <span className="ml-1 font-mono text-[10px] font-medium normal-case tracking-normal text-white/35">{meta}</span> : null}
      </h2>
      {action}
    </div>
  );
}

export function LinkButton({ href, children, tone = 'neutral' }: { href: string; children: ReactNode; tone?: 'neutral' | 'ghost' }) {
  return (
    <a
      href={href}
      className={cn(
        'inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider no-underline transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
        tone === 'neutral'
          ? 'border border-cyan-400/40 bg-cyan-500/10 text-cyan-200 hover:bg-cyan-500/20'
          : 'border border-white/12 bg-white/[0.04] text-white/60 hover:bg-white/[0.08]',
      )}
    >
      {children}
      <ChevronRight className="h-3 w-3" aria-hidden="true" />
    </a>
  );
}

/* ------------------------------------------------------------------ */
/* Data display                                                        */
/* ------------------------------------------------------------------ */

export function KpiCard({
  label, value, unit, detail, color, footnote, href,
}: {
  label: string;
  value: string;
  unit?: string;
  detail: string;
  color: string;
  footnote?: string;
  href?: string;
}) {
  const body = (
    <>
      <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/45">{label}</div>
      <div className="mt-2 flex items-baseline gap-1.5">
        <span className="font-mono text-[30px] font-black leading-none tracking-tight" style={{ color }}>{value}</span>
        {unit ? <span className="font-mono text-[13px] font-black" style={{ color }}>{unit}</span> : null}
      </div>
      <div className="mt-2 text-[10.5px] leading-snug text-white/45">{detail}</div>
      {footnote ? <div className="mt-2 text-[9.5px] leading-snug text-white/30">{footnote}</div> : null}
    </>
  );
  return href ? <Panel className="p-4" href={href} label={label}>{body}</Panel> : <Panel className="p-4">{body}</Panel>;
}

export function Meter({ value, color, label }: { value: number; color: string; label?: string }) {
  return (
    <div
      className="h-1.5 w-full overflow-hidden rounded-full bg-white/8"
      role="meter"
      aria-valuenow={Math.round(value)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={label}
    >
      <div className="h-full rounded-full transition-[width] duration-500" style={{ width: `${Math.max(0, Math.min(100, value))}%`, backgroundColor: color }} />
    </div>
  );
}

/** Score dial. Renders an em dash, not an empty ring, when the score is null. */
export function ScoreDial({
  score, level, size = 136, caption,
}: {
  score: number | null;
  level: string;
  size?: number;
  caption?: string;
}) {
  const hex = score === null ? SLATE : levelHex(level);
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  return (
    <div className="relative grid shrink-0 place-items-center" style={{ width: size, height: size }}>
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90" aria-hidden="true">
        <circle cx="60" cy="60" r={radius} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="9" />
        {score !== null ? (
          <circle
            cx="60" cy="60" r={radius} fill="none" stroke={hex} strokeWidth="9" strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference - (circumference * Math.max(0, Math.min(100, score))) / 100}
            style={{ transition: 'stroke-dashoffset 700ms ease' }}
          />
        ) : null}
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div className="font-mono text-[32px] font-black leading-none" style={{ color: hex }}>{fmtScore(score)}</div>
          <div className="mt-1 text-[9.5px] font-black uppercase tracking-[0.16em]" style={{ color: hex }}>
            {score === null ? 'NO DATA' : level.toUpperCase()}
          </div>
          {caption ? <div className="mt-1 text-[9px] text-white/30">{caption}</div> : null}
        </div>
      </div>
    </div>
  );
}

export function DistributionBars({
  rows, total, unitLabel,
}: {
  rows: Array<{ key: string; label: string; glyph: string; count: number; percent: number }>;
  total: number;
  unitLabel: string;
}) {
  return (
    <div>
      <div className="mb-2 flex items-baseline justify-between">
        <span className="text-[9px] font-black uppercase tracking-[0.16em] text-white/35">{unitLabel}</span>
        <span className="font-mono text-[10px] text-white/35">{fmtInt(total)} total</span>
      </div>
      <dl className="space-y-2.5">
        {rows.map((row) => (
          <div key={row.key} className="grid grid-cols-[minmax(0,1fr)_auto_46px] items-center gap-3">
            <dt className="flex items-center gap-1.5 truncate text-[11.5px] text-white/60">
              <span aria-hidden="true" style={{ color: levelHex(row.key) }}>{row.glyph}</span>
              {row.label}
            </dt>
            <dd className="font-mono text-[10.5px] text-white/35">{fmtInt(row.count)}</dd>
            <dd className="text-right font-mono text-[12px] font-black" style={{ color: levelHex(row.key) }}>{fmtPct(row.percent)}</dd>
            <div className="col-span-3">
              <Meter value={row.percent} color={levelHex(row.key)} label={`${row.label} share`} />
            </div>
          </div>
        ))}
      </dl>
    </div>
  );
}

export function StatusPill({ level, label }: { level: string; label?: string }) {
  const hex = levelHex(level);
  return (
    <span
      className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[9.5px] font-black uppercase tracking-wider"
      style={{ borderColor: `${hex}55`, backgroundColor: `${hex}16`, color: hex }}
    >
      <span aria-hidden="true">{levelGlyph(level)}</span>
      {label ?? level}
    </span>
  );
}

export function EmptyRow({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-white/12 px-4 py-6 text-center text-[11px] leading-relaxed text-white/40">
      {children}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Page states                                                         */
/* ------------------------------------------------------------------ */

export function ConnectionLostBanner({
  lastGoodAt, error, onReconnect, transport, lastVerifiedAt,
}: {
  lastGoodAt: string | null;
  error: string | null;
  onReconnect: () => void;
  /** With `polling`, the page is still being refreshed over REST — say so instead of "connection lost". */
  transport?: LiveTransportState;
  lastVerifiedAt?: string | null;
}) {
  const polling = transport === 'polling';
  return (
    <div role="alert" className="flex flex-wrap items-center gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3">
      <WifiOff className="h-4 w-4 shrink-0 text-amber-300" aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <div className="text-[11.5px] font-black text-amber-200">
          {polling
            ? 'Live stream interrupted — the page is refreshed over REST while it reconnects'
            : 'Connection lost — this is the last successful sync, not live data'}
        </div>
        <div className="truncate text-[10px] text-white/45">
          Computed {relativeTime(lastGoodAt)}
          {lastVerifiedAt ? ` · last verified ${relativeTime(lastVerifiedAt)}` : ''}
          {error ? ` · ${error}` : ''}
        </div>
      </div>
      <button
        type="button"
        onClick={onReconnect}
        className="rounded border border-amber-400/40 bg-amber-500/10 px-3 py-1.5 text-[9px] font-black uppercase tracking-wider text-amber-200 transition hover:bg-amber-500/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-300/70"
      >
        Reconnect
      </button>
    </div>
  );
}

export function HardErrorPanel({ title, message, error, onRetry }: { title: string; message: string; error: string | null; onRetry: () => void }) {
  return (
    <Panel className="p-8 text-center">
      <AlertTriangle className="mx-auto h-8 w-8 text-red-400" aria-hidden="true" />
      <h2 className="mt-3 text-[16px] font-black text-white">{title}</h2>
      <p className="mx-auto mt-1.5 max-w-lg text-[11.5px] leading-relaxed text-white/45">{message}</p>
      {error ? <p className="mx-auto mt-2 max-w-lg rounded-lg border border-white/10 bg-black/25 p-2.5 font-mono text-[10px] text-red-300">{error}</p> : null}
      <div className="mt-4 flex flex-wrap justify-center gap-2">
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200"
        >
          <RefreshCw className="h-3 w-3" aria-hidden="true" /> Retry
        </button>
        <a href="/dashboard/quantum-readiness" className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/5 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60 no-underline">
          View Quantum Readiness
        </a>
      </div>
    </Panel>
  );
}

export function NoEvidenceState({
  icon: Icon, title, body, bullets, actions,
}: {
  icon: LucideIcon;
  title: string;
  body: string;
  bullets?: string[];
  actions: Array<{ href: string; label: string; primary?: boolean }>;
}) {
  return (
    <Panel className="p-8 text-center">
      <Icon className="mx-auto h-9 w-9 text-cyan-300/60" aria-hidden="true" />
      <h2 className="mt-3 text-[18px] font-black text-white">{title}</h2>
      <p className="mx-auto mt-2 max-w-2xl text-[12px] leading-relaxed text-white/50">{body}</p>
      {bullets?.length ? (
        <div className="mx-auto mt-4 max-w-2xl rounded-xl border border-white/10 bg-black/25 p-4 text-left">
          <ul className="space-y-1.5 text-[11px] leading-relaxed text-white/50">
            {bullets.map((bullet, index) => <li key={index}>· {bullet}</li>)}
          </ul>
        </div>
      ) : null}
      <div className="mt-5 flex flex-wrap justify-center gap-2">
        {actions.map((action) => (
          <a
            key={action.href}
            href={action.href}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg px-4 py-2.5 text-[10px] font-black uppercase tracking-wider no-underline transition',
              action.primary
                ? 'border border-cyan-400/50 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25'
                : 'border border-white/12 bg-white/5 text-white/60 hover:bg-white/10',
            )}
          >
            {action.label}
          </a>
        ))}
      </div>
    </Panel>
  );
}

export function SkeletonGrid({ cards = 5, panels = 2 }: { cards?: number; panels?: number }) {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2.5 lg:grid-cols-3 xl:grid-cols-5">
        {Array.from({ length: cards }).map((_, index) => <div key={index} className="h-[118px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />)}
      </div>
      <div className={cn('grid gap-4', panels > 1 && 'xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]')}>
        {Array.from({ length: panels }).map((_, index) => <div key={index} className="h-[300px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />)}
      </div>
      <div className="h-[320px] animate-pulse rounded-xl border border-white/10 bg-white/[0.03]" />
    </div>
  );
}

/** Provenance footnote — states which module owns a number. */
export function SourceNote({ children }: { children: ReactNode }) {
  return <p className="px-1 pb-2 text-[10px] leading-relaxed text-white/25">{children}</p>;
}
