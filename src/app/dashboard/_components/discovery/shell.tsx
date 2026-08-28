'use client';

/**
 * Discovery-suite shell — the CBOM Explorer design language, extracted.
 *
 * CBOM Explorer, Assets & CBOM and Shadow Crypto are one workflow (discover →
 * inventory → investigate), so they must look like one product. This module is
 * the single definition of that look: the page frame, header, tab rail, metric
 * tile, panel and empty/truncation states.
 *
 * Everything is expressed in the platform `--qg-*` theme tokens, so these pages
 * follow the dashboard's light/dark themes exactly as CBOM does rather than
 * carrying a private palette. CBOM itself is deliberately NOT refactored onto
 * this module: it is the reference implementation, and changing it to adopt an
 * extraction of itself would risk the very page the others are matching.
 */

import { Fragment, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ExternalLink, Info, Sparkles, type LucideIcon } from 'lucide-react';

/* ------------------------------------------------------------------ */
/* Surfaces                                                           */
/* ------------------------------------------------------------------ */

export const panelClass =
  'relative overflow-hidden rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] shadow-[var(--qg-panel-shadow)] backdrop-blur-xl transition-all duration-300';

export const subtlePanelClass =
  'rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)]';

export const inputClass =
  'w-full rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] py-2 pl-9 pr-3 text-sm text-[var(--qg-dashboard-text)] outline-none transition placeholder:text-[var(--qg-text-muted)] focus:border-[var(--qg-amber)]/50';

export function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={`${panelClass} ${className || ''}`}>{children}</div>;
}

export function numberFmt(value: number) {
  return Number.isFinite(value) ? value.toLocaleString('en-US') : '0';
}

/* ------------------------------------------------------------------ */
/* Page frame                                                         */
/* ------------------------------------------------------------------ */

/** The CBOM background: two theme-tinted radials over the dashboard gradient. */
export const DISCOVERY_PAGE_BACKGROUND =
  'radial-gradient(circle at 18% 8%, color-mix(in srgb, var(--qg-cyan) 14%, transparent), transparent 34%), radial-gradient(circle at 82% 18%, color-mix(in srgb, var(--qg-amber) 10%, transparent), transparent 30%), linear-gradient(180deg, var(--qg-dashboard-bg), var(--qg-dashboard-bg-soft))';

export function DiscoveryPage({ children }: { children: ReactNode }) {
  return (
    <div
      className="min-h-screen space-y-4 p-4 text-[var(--qg-dashboard-text)] md:p-6"
      style={{ background: DISCOVERY_PAGE_BACKGROUND }}
    >
      {children}
    </div>
  );
}

/**
 * Page header.
 *
 * `connected` drives the live-telemetry pill. It reports the STREAM, so it is
 * deliberately paired with `measuredAt`: a connected socket over a three-week
 * old assessment is not a live picture of the estate, and showing only the
 * former is how a stale page reads as current.
 */
export function DiscoveryHeader({
  title,
  subtitle,
  connected,
  measuredAt,
  reconciledNote,
  actions,
}: {
  title: string;
  subtitle: string;
  connected: boolean;
  measuredAt?: string | null;
  reconciledNote?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-black tracking-tight text-[var(--qg-dashboard-text)] md:text-3xl">{title}</h1>
          <Info className="h-4 w-4 text-[var(--qg-text-muted)]" />
        </div>
        <p className="mt-1 text-sm text-[var(--qg-dashboard-text-soft)]">{subtitle}</p>
        <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] font-black uppercase tracking-widest">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 ${
              connected
                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]'
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-[var(--qg-text-muted)]'}`} />
            {connected ? 'Live Telemetry' : 'Cached'}
          </span>
          <FreshnessPill measuredAt={measuredAt} />
          {reconciledNote ? (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--qg-cyan)]/25 bg-[var(--qg-cyan)]/10 px-2 py-0.5 text-[var(--qg-cyan)]">
              <Sparkles className="h-3 w-3" /> {reconciledNote}
            </span>
          ) : null}
        </div>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}

/**
 * Age of the underlying measurement, in words.
 *
 * Renders "No scan timestamp" rather than nothing when there is none: silence
 * would let the reader assume the data is current, which is the assumption this
 * pill exists to prevent. Amber past the platform staleness threshold.
 */
export function FreshnessPill({ measuredAt }: { measuredAt?: string | null }) {
  if (!measuredAt) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-2 py-0.5 text-[var(--qg-text-muted)]">
        No scan timestamp
      </span>
    );
  }
  const ms = new Date(measuredAt).getTime();
  if (!Number.isFinite(ms)) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-2 py-0.5 text-[var(--qg-text-muted)]">
        Scan time unreadable
      </span>
    );
  }
  const hours = Math.max(0, (Date.now() - ms) / 36e5);
  const stale = hours > 72;
  const label =
    hours < 1 ? 'Scanned < 1h ago' : hours < 48 ? `Scanned ${Math.round(hours)}h ago` : `Scanned ${Math.round(hours / 24)}d ago`;
  return (
    <span
      title={`Underlying scan measured ${new Date(ms).toLocaleString()}`}
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 ${
        stale
          ? 'border-[var(--qg-amber)]/45 bg-[var(--qg-amber)]/12 text-[var(--qg-amber)]'
          : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]'
      }`}
    >
      {label}
    </span>
  );
}

/** Amber banner shown when the estate has not been re-measured recently. */
export function StaleAssessmentBanner({ measuredAt }: { measuredAt?: string | null }) {
  if (!measuredAt) return null;
  const ms = new Date(measuredAt).getTime();
  if (!Number.isFinite(ms)) return null;
  const hours = (Date.now() - ms) / 36e5;
  if (hours <= 72) return null;
  const days = Math.round(hours / 24);
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-md border border-[var(--qg-amber)]/30 bg-[var(--qg-amber)]/[0.08] px-4 py-3 text-sm text-[var(--qg-dashboard-text)]">
      <span className="font-bold">This inventory was last measured {days} day{days === 1 ? '' : 's'} ago.</span>
      <span className="text-[var(--qg-dashboard-text-soft)]">
        Assets added, retired or re-keyed since then are not reflected below.
      </span>
      <Link to="/dashboard/scanner" className="font-black text-[var(--qg-amber)] no-underline underline-offset-2 hover:underline">
        Run a discovery scan
      </Link>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Tab rail                                                           */
/* ------------------------------------------------------------------ */

export function DiscoveryTabs<T extends string>({
  tabs,
  active,
  onChange,
  right,
}: {
  tabs: readonly T[];
  active: T;
  onChange: (tab: T) => void;
  right?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-3 border-b border-[var(--qg-card-border)] pb-3 xl:flex-row xl:items-center xl:justify-between">
      <nav className="flex gap-1 overflow-x-auto" aria-label="Sections">
        {tabs.map((tab) => (
          <button
            type="button"
            key={tab}
            onClick={() => onChange(tab)}
            aria-current={active === tab ? 'page' : undefined}
            className={`whitespace-nowrap border-b-2 px-3 py-2 text-xs font-bold transition ${
              active === tab
                ? 'border-[var(--qg-amber)] text-[var(--qg-amber)]'
                : 'border-transparent text-[var(--qg-text-muted)] hover:text-[var(--qg-dashboard-text)]'
            }`}
          >
            {tab}
          </button>
        ))}
      </nav>
      {right ? <div className="flex flex-wrap items-center gap-2">{right}</div> : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Tiles and states                                                   */
/* ------------------------------------------------------------------ */

export type MetricTone = 'cyan' | 'amber' | 'green' | 'red' | 'blue' | 'muted';

export function DiscoveryMetric({
  label,
  value,
  detail,
  icon: Icon,
  tone = 'cyan',
}: {
  label: string;
  value: string | number;
  detail: string;
  icon: LucideIcon;
  tone?: MetricTone;
}) {
  const toneClass =
    tone === 'green' ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300' :
    tone === 'red' ? 'border-red-500/25 bg-red-500/10 text-red-600 dark:text-red-300' :
    tone === 'amber' ? 'border-[var(--qg-amber)]/35 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)]' :
    tone === 'blue' ? 'border-blue-500/25 bg-blue-500/10 text-blue-600 dark:text-blue-300' :
    tone === 'muted' ? 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]' :
    'border-cyan-500/25 bg-cyan-500/10 text-cyan-600 dark:text-cyan-300';

  return (
    <div className={`${subtlePanelClass} p-4`}>
      <div className="flex items-center gap-3">
        <span className={`grid h-10 w-10 shrink-0 place-items-center rounded-md border ${toneClass}`}>
          <Icon className="h-4 w-4" />
        </span>
        <div className="min-w-0">
          <div className="text-[10px] font-black uppercase tracking-wider text-[var(--qg-text-muted)]">{label}</div>
          <div className="text-xl font-black text-[var(--qg-dashboard-text)]">
            {typeof value === 'number' ? numberFmt(value) : value}
          </div>
          <div className="mt-0.5 text-[10px] text-[var(--qg-text-muted)]">{detail}</div>
        </div>
      </div>
    </div>
  );
}

export function DiscoveryAction({
  label,
  detail,
  icon: Icon,
  to,
  onClick,
}: {
  label: string;
  detail: string;
  icon: LucideIcon;
  to?: string;
  onClick?: () => void;
}) {
  const content = (
    <Fragment>
      <span className="grid h-9 w-9 shrink-0 place-items-center rounded-md border border-[var(--qg-amber)]/30 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)]">
        <Icon className="h-4 w-4" />
      </span>
      <span className="min-w-0">
        <span className="block text-sm font-black text-[var(--qg-dashboard-text)]">{label}</span>
        <span className="block text-[10px] text-[var(--qg-text-muted)]">{detail}</span>
      </span>
      <ExternalLink className="ml-auto h-3.5 w-3.5 shrink-0 text-[var(--qg-text-muted)]" />
    </Fragment>
  );
  const className =
    'flex w-full items-center gap-3 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-3 py-3 text-left transition hover:border-[var(--qg-amber)]/45 hover:bg-[var(--qg-card-bg)]';
  if (to) return <Link to={to} className={className}>{content}</Link>;
  return <button type="button" onClick={onClick} className={className}>{content}</button>;
}

export function DiscoveryEmpty({ label, hint }: { label: string; hint?: string }) {
  return (
    <div className="grid min-h-[120px] place-items-center rounded-md border border-dashed border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-4 text-center">
      <div>
        <div className="text-xs font-bold text-[var(--qg-text-muted)]">{label}</div>
        {hint ? <div className="mt-1 text-[10px] text-[var(--qg-text-muted)]">{hint}</div> : null}
      </div>
    </div>
  );
}

export function SectionHeading({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
      <h2 className="text-[11px] font-black uppercase tracking-[0.16em] text-[var(--qg-dashboard-text-soft)]">{children}</h2>
      {right}
    </div>
  );
}

/**
 * Discloses that a panel shows only the head of a longer list.
 *
 * Renders nothing when the list fits. `rank` names WHY these are the ones
 * shown — "showing 8 of 40" without an ordering still misleads, because the
 * reader assumes the eight that matter most are the eight present.
 */
export function TruncationNote({
  shown,
  total,
  noun,
  rank,
  to,
}: {
  shown: number;
  total: number;
  noun: string;
  rank?: string;
  to?: string;
}) {
  if (!Number.isFinite(total) || total <= shown) return null;
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 pt-2 text-[10px] text-[var(--qg-text-muted)]">
      <span>
        Showing {rank ? `the ${numberFmt(shown)} ${rank}` : numberFmt(shown)} of {numberFmt(total)} {noun}.
      </span>
      {to ? (
        <Link to={to} className="font-black text-[var(--qg-cyan)] no-underline hover:underline">
          View all
        </Link>
      ) : null}
    </div>
  );
}
