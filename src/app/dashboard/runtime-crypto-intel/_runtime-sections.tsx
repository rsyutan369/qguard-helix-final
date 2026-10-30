'use client';

import type { ReactNode } from 'react';
import {
  Activity, AlertTriangle, ArrowUpRight, CheckCircle2, ChevronRight, Clock, Cpu,
  Gauge, Radio, Search, ShieldAlert, ShieldCheck, Sparkles, Timer, X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Panel } from '../_components/executive/primitives';
import { TIME_WINDOWS, type QuantumStatus, type RiskLevel } from '@/lib/runtime-crypto/runtime-intelligence';
import type {
  HndlCard, MigrationVerification, PqcAdoption, QuantumRiskCard, RuntimeConfiguration,
  RuntimeCryptoIntelligence, RuntimeEvent, RuntimeIssue, RuntimeKpis, RuntimeSecurityStatus,
  RuntimeTelemetryState, SophiaInsight,
} from '@/lib/runtime-crypto/runtime-intelligence';
import {
  AMBER, BLUE, CYAN, GREEN, RED, RISK_GLYPH, RISK_HEX, RISK_LABEL, SLATE, STATE_HEX,
  STATUS_HEX, clockTime, fmtCompact, fmtInt, fmtPct, relativeTime,
  type RuntimeFilters,
} from './_runtime-lib';

/* ================================================================== */
/* Shared bits                                                         */
/* ================================================================== */

export function SectionHeading({
  id, title, icon: Icon, action, meta,
}: {
  id?: string;
  title: string;
  icon: typeof Activity;
  action?: ReactNode;
  meta?: ReactNode;
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

function LinkButton({ href, children, tone = 'neutral' }: { href: string; children: ReactNode; tone?: 'neutral' | 'ghost' }) {
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

/** Coloured pill that always pairs its colour with a glyph and a word. */
function StatusPill({ status, label, glyph }: { status: QuantumStatus; label: string; glyph: string }) {
  const hex = STATUS_HEX[status];
  return (
    <span
      className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[9.5px] font-black uppercase tracking-wider"
      style={{ borderColor: `${hex}55`, backgroundColor: `${hex}16`, color: hex }}
    >
      <span aria-hidden="true">{glyph}</span>
      {label}
    </span>
  );
}

function RiskPill({ risk }: { risk: RiskLevel }) {
  const hex = RISK_HEX[risk];
  return (
    <span
      className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[9.5px] font-black uppercase tracking-wider"
      style={{ borderColor: `${hex}55`, backgroundColor: `${hex}16`, color: hex }}
    >
      <span aria-hidden="true">{RISK_GLYPH[risk]}</span>
      {RISK_LABEL[risk]}
    </span>
  );
}

function Meter({ value, color, label }: { value: number; color: string; label?: string }) {
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

export function EmptyRow({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-white/12 px-4 py-6 text-center text-[11px] leading-relaxed text-white/40">
      {children}
    </div>
  );
}

/* ================================================================== */
/* 1. KPI strip (§3) — five cards, nothing more                        */
/* ================================================================== */

function KpiCard({
  label, value, unit, detail, color, emphasis,
}: {
  label: string;
  value: string;
  unit?: string;
  detail: string;
  color: string;
  emphasis?: ReactNode;
}) {
  return (
    <Panel className="p-4">
      <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/45">{label}</div>
      <div className="mt-2 flex items-baseline gap-1.5">
        <span className="font-mono text-[30px] font-black leading-none tracking-tight" style={{ color }}>{value}</span>
        {unit ? <span className="font-mono text-[13px] font-black" style={{ color }}>{unit}</span> : null}
      </div>
      <div className="mt-2 text-[10.5px] leading-snug text-white/45">{detail}</div>
      {emphasis ? <div className="mt-2">{emphasis}</div> : null}
    </Panel>
  );
}

export function RuntimeKpiStrip({ kpis, windowLabel }: { kpis: RuntimeKpis; windowLabel: string }) {
  return (
    <section aria-label="Runtime key metrics" className="grid grid-cols-2 gap-2.5 lg:grid-cols-3 xl:grid-cols-5">
      <KpiCard
        label="Crypto Activity"
        value={fmtCompact(kpis.activity)}
        color={CYAN}
        detail={`${kpis.activityLabel} · ${windowLabel.toLowerCase()}`}
        emphasis={
          <span className="text-[9.5px] leading-snug text-white/30">
            Distinct cryptographic observations, de-duplicated by the collector.
          </span>
        }
      />
      <KpiCard label="Quantum Safe" value={fmtPct(kpis.quantumSafePct)} color={GREEN} detail="of runtime observations" />
      <KpiCard label="Hybrid PQC" value={fmtPct(kpis.hybridPct)} color={BLUE} detail="of runtime observations" />
      <KpiCard label="Quantum Risk" value={fmtPct(kpis.vulnerablePct)} color={RED} detail="vulnerable observations" />
      <KpiCard
        label="Active Issues"
        value={fmtInt(kpis.activeIssues)}
        color={kpis.criticalIssues > 0 ? RED : kpis.activeIssues > 0 ? AMBER : GREEN}
        detail={kpis.activeIssues === 0 ? 'no open runtime findings' : `${kpis.criticalIssues} critical`}
      />
    </section>
  );
}

/* ================================================================== */
/* 2. Runtime security status (§4)                                     */
/* ================================================================== */

export function RuntimeSecurityStatusCard({
  status, onExplain,
}: {
  status: RuntimeSecurityStatus;
  onExplain: () => void;
}) {
  const hex = STATE_HEX[status.state];
  const score = status.score;
  const circumference = 2 * Math.PI * 54;

  return (
    <Panel className="p-5">
      <SectionHeading
        title="Runtime Security Status"
        icon={Gauge}
        action={
          <button
            type="button"
            onClick={onExplain}
            className="rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-white/55 transition hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
          >
            How is this calculated?
          </button>
        }
      />

      <div className="flex flex-col items-center gap-5 sm:flex-row sm:items-center">
        <div className="relative grid h-[136px] w-[136px] shrink-0 place-items-center">
          <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90" aria-hidden="true">
            <circle cx="60" cy="60" r="54" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="9" />
            {score !== null ? (
              <circle
                cx="60" cy="60" r="54" fill="none" stroke={hex} strokeWidth="9" strokeLinecap="round"
                strokeDasharray={circumference}
                strokeDashoffset={circumference - (circumference * score) / 100}
                style={{ transition: 'stroke-dashoffset 700ms ease' }}
              />
            ) : null}
          </svg>
          <div className="absolute inset-0 grid place-items-center text-center">
            <div>
              <div className="font-mono text-[34px] font-black leading-none" style={{ color: score === null ? SLATE : hex }}>
                {score === null ? '—' : `${score}%`}
              </div>
              <div className="mt-1 text-[9.5px] font-black uppercase tracking-[0.16em]" style={{ color: score === null ? SLATE : hex }}>
                {status.stateLabel}
              </div>
            </div>
          </div>
        </div>

        <div className="min-w-0 flex-1">
          <p className="text-[12.5px] leading-relaxed text-white/60">{status.headline}</p>
          <dl className="mt-4 space-y-2.5">
            {status.mix.map((row) => (
              <div key={row.key} className="grid grid-cols-[minmax(0,1fr)_auto_52px] items-center gap-3">
                <dt className="flex items-center gap-1.5 truncate text-[11.5px] text-white/60">
                  <span aria-hidden="true" style={{ color: STATUS_HEX[row.key] }}>{row.glyph}</span>
                  {row.label}
                </dt>
                <dd className="font-mono text-[10.5px] text-white/35">{fmtInt(row.count)}</dd>
                <dd className="text-right font-mono text-[12px] font-black" style={{ color: STATUS_HEX[row.key] }}>
                  {fmtPct(row.percent)}
                </dd>
                <div className="col-span-3">
                  <Meter value={row.percent} color={STATUS_HEX[row.key]} label={`${row.label} share of runtime observations`} />
                </div>
              </div>
            ))}
          </dl>
        </div>
      </div>
    </Panel>
  );
}

/* ================================================================== */
/* 3. Quantum risk (§12)                                               */
/* ================================================================== */

const BREAKDOWN_HEX: Record<string, string> = { critical: RED, high: '#fb923c', medium: AMBER, low: GREEN };

export function QuantumRiskPanel({ card }: { card: QuantumRiskCard }) {
  const level = card.level?.toUpperCase() || 'UNKNOWN';
  const hex = /CRITICAL|SEVERE/.test(level) ? RED : /HIGH/.test(level) ? '#fb923c' : /MEDIUM|MODERATE|ELEVATED/.test(level) ? AMBER : GREEN;

  return (
    <Panel className="flex h-full flex-col p-5">
      <SectionHeading title="Quantum Risk" icon={ShieldAlert} />
      <div className="flex items-baseline gap-2">
        <span className="font-mono text-[28px] font-black leading-none" style={{ color: hex }}>{level}</span>
        <span className="font-mono text-[11px] text-white/35">{card.score}/100</span>
      </div>
      <p className="mt-2.5 text-[12px] leading-relaxed text-white/55">{card.headline}</p>

      <div className="mt-4 space-y-2">
        <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/35">Assets by worst runtime finding</div>
        {card.breakdown.map((row) => (
          <div key={row.key} className="flex items-center justify-between rounded-lg border border-white/8 bg-white/[0.02] px-3 py-1.5">
            <span className="flex items-center gap-2 text-[11.5px] text-white/60">
              <span aria-hidden="true" style={{ color: BREAKDOWN_HEX[row.key] }}>{row.glyph}</span>
              {row.label}
            </span>
            <span className="font-mono text-[13px] font-black" style={{ color: BREAKDOWN_HEX[row.key] }}>{fmtInt(row.count)}</span>
          </div>
        ))}
      </div>

      <div className="mt-auto pt-4">
        <LinkButton href={card.href}>View Quantum Risks</LinkButton>
      </div>
    </Panel>
  );
}

/* ================================================================== */
/* 4. Live cryptographic activity (§5)                                 */
/* ================================================================== */

export function LiveCryptoActivity({
  events, total, onSelect, live, windowLabel, compact,
}: {
  events: RuntimeEvent[];
  total: number;
  onSelect: (event: RuntimeEvent) => void;
  live: boolean;
  windowLabel: string;
  compact?: boolean;
}) {
  const rows = compact ? events.slice(0, 12) : events;

  return (
    <Panel className="p-5">
      <SectionHeading
        title="Live Cryptographic Activity"
        icon={Activity}
        meta={`${fmtInt(rows.length)} of ${fmtInt(total)} · ${windowLabel.toLowerCase()}`}
        action={
          <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[9px] font-black uppercase tracking-widest', live ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-300' : 'border-white/12 bg-white/5 text-white/40')}>
            <span className={cn('h-1.5 w-1.5 rounded-full', live ? 'animate-pulse bg-emerald-400' : 'bg-white/40')} aria-hidden="true" />
            {live ? 'Streaming' : 'Paused'}
          </span>
        }
      />

      {rows.length === 0 ? (
        <EmptyRow>No cryptographic activity matched the current filters in this period.</EmptyRow>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] border-collapse text-left">
            <caption className="sr-only">Runtime cryptographic observations, newest first. Select a row to open its details.</caption>
            <thead>
              <tr className="border-b border-white/10 text-[9px] font-black uppercase tracking-[0.14em] text-white/35">
                <th scope="col" className="py-2 pr-3 font-black">Time</th>
                <th scope="col" className="py-2 pr-3 font-black">Application</th>
                <th scope="col" className="py-2 pr-3 font-black">Operation</th>
                <th scope="col" className="py-2 pr-3 font-black">Algorithm</th>
                <th scope="col" className="py-2 pr-3 font-black">Status</th>
                <th scope="col" className="py-2 font-black text-right">Priority</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((event) => (
                <tr
                  key={event.id}
                  tabIndex={0}
                  role="button"
                  onClick={() => onSelect(event)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelect(event);
                    }
                  }}
                  className="cursor-pointer border-b border-white/5 outline-none transition last:border-0 hover:bg-white/[0.04] focus-visible:bg-white/[0.06] focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-cyan-300/70"
                  aria-label={`${event.assetName}, ${event.operation}, ${event.algorithm}, ${event.statusLabel}`}
                >
                  <td className="py-2.5 pr-3 font-mono text-[11px] text-white/45">{clockTime(event.observedAt)}</td>
                  <td className="max-w-[190px] truncate py-2.5 pr-3 text-[12px] font-semibold text-white/85">{event.assetName}</td>
                  <td className="py-2.5 pr-3 text-[11.5px] text-white/55">{event.operation}</td>
                  <td className="max-w-[210px] truncate py-2.5 pr-3 font-mono text-[11px] text-white/70">{event.algorithm}</td>
                  <td className="py-2.5 pr-3">
                    <StatusPill status={event.quantumStatus} label={event.statusLabel} glyph={event.statusGlyph} />
                  </td>
                  <td className="py-2.5 text-right font-mono text-[12px] font-black" style={{ color: RISK_HEX[event.risk] }}>
                    {event.riskScore}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

/* ================================================================== */
/* 5. Attention required (§7)                                          */
/* ================================================================== */

function IssueRow({ issue, onSelect }: { issue: RuntimeIssue; onSelect: (issue: RuntimeIssue) => void }) {
  const hex = RISK_HEX[issue.severity];
  return (
    <div className="flex flex-wrap items-start gap-3 rounded-lg border border-white/8 bg-white/[0.02] p-3 transition hover:border-white/15">
      <span className="mt-0.5 text-[13px] leading-none" style={{ color: hex }} aria-hidden="true">{RISK_GLYPH[issue.severity]}</span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[12.5px] font-black text-white/90">{issue.title}</span>
          <RiskPill risk={issue.severity} />
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-white/45">
          <span className="font-semibold text-white/65">{issue.assetName}</span>
          {issue.environment && issue.environment !== 'unspecified' ? <span>· {issue.environment}</span> : null}
          <span>· {fmtInt(issue.observations)} observation{issue.observations === 1 ? '' : 's'}</span>
          <span>· last seen {relativeTime(issue.lastSeen)}</span>
        </div>
        <p className="mt-1.5 text-[11.5px] leading-relaxed text-white/50">{issue.recommendedAction}</p>
      </div>
      <div className="flex shrink-0 gap-1.5">
        <button
          type="button"
          onClick={() => onSelect(issue)}
          className="rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
        >
          {issue.actionLabel}
        </button>
      </div>
    </div>
  );
}

export function AttentionRequired({
  issues, totalIssues, onSelect, onSeeAll,
}: {
  issues: RuntimeIssue[];
  totalIssues: number;
  onSelect: (issue: RuntimeIssue) => void;
  onSeeAll: () => void;
}) {
  return (
    <Panel className="p-5">
      <SectionHeading
        title="Attention Required"
        icon={AlertTriangle}
        meta={totalIssues > issues.length ? `top ${issues.length} of ${totalIssues}` : undefined}
        action={
          totalIssues > issues.length ? (
            <button
              type="button"
              onClick={onSeeAll}
              className="rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
            >
              View all risks
            </button>
          ) : undefined
        }
      />
      {issues.length === 0 ? (
        <div className="rounded-lg border border-emerald-400/25 bg-emerald-500/[0.06] px-4 py-6 text-center">
          <CheckCircle2 className="mx-auto h-6 w-6 text-emerald-300" aria-hidden="true" />
          <div className="mt-2 text-[12.5px] font-black text-emerald-200">No Runtime Risks</div>
          <p className="mx-auto mt-1 max-w-md text-[11.5px] leading-relaxed text-white/45">
            No significant cryptographic risks were detected during the selected period.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {issues.map((issue) => <IssueRow key={issue.id} issue={issue} onSelect={onSelect} />)}
        </div>
      )}
    </Panel>
  );
}

/* ================================================================== */
/* 6. PQC adoption (§9)                                                */
/* ================================================================== */

export function PqcAdoptionPanel({ adoption }: { adoption: PqcAdoption }) {
  const safe = adoption.runtimeSafePct;
  const hybrid = adoption.runtimeHybridPct;
  const classical = adoption.runtimeClassicalPct;
  const unknown = adoption.runtimeUnknownPct;
  const measured = safe !== null;
  const postQuantum = measured ? (safe ?? 0) + (hybrid ?? 0) : null;

  return (
    <Panel className="flex h-full flex-col p-5">
      <SectionHeading title="Post-Quantum Adoption" icon={ShieldCheck} />

      {!measured ? (
        <EmptyRow>No runtime observations in this period, so runtime adoption cannot be measured.</EmptyRow>
      ) : (
        <>
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-[30px] font-black leading-none text-emerald-300">{fmtPct(postQuantum)}</span>
            <span className="text-[11px] text-white/45">post-quantum at runtime</span>
          </div>

          <div className="mt-3 flex h-3 w-full overflow-hidden rounded-full bg-white/8" role="img" aria-label={`Runtime mix: quantum safe ${safe}%, hybrid ${hybrid}%, classical ${classical}%, unknown ${unknown}%`}>
            <div style={{ width: `${safe}%`, backgroundColor: GREEN }} />
            <div style={{ width: `${hybrid}%`, backgroundColor: BLUE }} />
            <div style={{ width: `${classical}%`, backgroundColor: RED }} />
            <div style={{ width: `${unknown}%`, backgroundColor: SLATE }} />
          </div>

          <ul className="mt-3 space-y-1.5">
            {[
              ['Quantum Safe', safe, GREEN, '✓'],
              ['Hybrid PQC', hybrid, BLUE, '✓'],
              ['Classical / Vulnerable', classical, RED, '●'],
              ['Unknown', unknown, SLATE, '⚠'],
            ].map(([label, value, hex, glyph]) => (
              <li key={String(label)} className="flex items-center justify-between text-[11.5px]">
                <span className="flex items-center gap-1.5 text-white/55">
                  <span aria-hidden="true" style={{ color: String(hex) }}>{String(glyph)}</span>
                  {String(label)}
                </span>
                <span className="font-mono font-black" style={{ color: String(hex) }}>{fmtPct(value as number)}</span>
              </li>
            ))}
          </ul>

          {adoption.trend ? (
            <div className="mt-3 flex items-center gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
              <ArrowUpRight className={cn('h-3.5 w-3.5', adoption.trend.deltaPct >= 0 ? 'text-emerald-300' : 'rotate-90 text-red-300')} aria-hidden="true" />
              <span className="text-[11.5px] font-black" style={{ color: adoption.trend.deltaPct >= 0 ? GREEN : RED }}>{adoption.trend.label}</span>
              <span className="text-[10px] text-white/35">{adoption.trend.basis}</span>
            </div>
          ) : null}
        </>
      )}

      <div className="mt-4 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2.5">
        <div className="flex items-center justify-between">
          <span className="text-[10.5px] text-white/50">{adoption.estateLabel}</span>
          <span className="font-mono text-[14px] font-black text-cyan-300">{fmtPct(adoption.estateAdoptionPct)}</span>
        </div>
        <Meter value={adoption.estateAdoptionPct} color={CYAN} label="Estate-wide PQC adoption" />
      </div>

      <p className="mt-3 text-[10px] leading-relaxed text-white/30">{adoption.basis}</p>

      <div className="mt-auto pt-3">
        <LinkButton href="/dashboard/quantum-readiness" tone="ghost">View Quantum Readiness</LinkButton>
      </div>
    </Panel>
  );
}

/* ================================================================== */
/* 7. Runtime configuration — expected vs actual (§10)                 */
/* ================================================================== */

const CONFIG_STATUS_HEX: Record<RuntimeConfiguration['status'], string> = {
  matching: GREEN,
  drift: RED,
  partial: AMBER,
};

const CONFIG_STATUS_GLYPH: Record<RuntimeConfiguration['status'], string> = {
  matching: '✓',
  drift: '●',
  partial: '⚠',
};

const LINE_GLYPH: Record<'match' | 'drift' | 'not-observed', string> = {
  match: '✓',
  drift: '●',
  'not-observed': '·',
};

const LINE_HEX: Record<'match' | 'drift' | 'not-observed', string> = {
  match: GREEN,
  drift: RED,
  'not-observed': SLATE,
};

export function RuntimeConfigurationPanel({ configurations }: { configurations: RuntimeConfiguration[] }) {
  return (
    <Panel className="p-5">
      <SectionHeading
        title="Runtime Configuration"
        icon={Cpu}
        meta="expected vs actual"
        action={<LinkButton href="/dashboard/migration-planner" tone="ghost">Migration Planner</LinkButton>}
      />

      {configurations.length === 0 ? (
        <EmptyRow>
          No asset emitted enough transport telemetry in this period to compare against an expected cryptographic stack.
        </EmptyRow>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {configurations.map((configuration) => (
            <div key={`${configuration.assetId ?? configuration.assetName}`} className="rounded-xl border border-white/10 bg-black/20 p-4">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="truncate text-[12.5px] font-black text-white/90">{configuration.assetName}</div>
                  <div className="mt-0.5 text-[10px] text-white/35">
                    {configuration.baselineLabel} · {fmtInt(configuration.observations)} observation{configuration.observations === 1 ? '' : 's'}
                  </div>
                </div>
                <span
                  className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[9px] font-black uppercase tracking-wider"
                  style={{
                    borderColor: `${CONFIG_STATUS_HEX[configuration.status]}55`,
                    backgroundColor: `${CONFIG_STATUS_HEX[configuration.status]}16`,
                    color: CONFIG_STATUS_HEX[configuration.status],
                  }}
                >
                  <span aria-hidden="true">{CONFIG_STATUS_GLYPH[configuration.status]}</span>
                  {configuration.statusLabel}
                </span>
              </div>

              <table className="mt-3 w-full border-collapse text-left">
                <caption className="sr-only">Expected versus actual cryptographic configuration for {configuration.assetName}</caption>
                <thead>
                  <tr className="text-[8.5px] font-black uppercase tracking-[0.14em] text-white/30">
                    <th scope="col" className="py-1 pr-2 font-black">Layer</th>
                    <th scope="col" className="py-1 pr-2 font-black">Expected</th>
                    <th scope="col" className="py-1 font-black">Actual</th>
                  </tr>
                </thead>
                <tbody>
                  {configuration.lines.map((line) => (
                    <tr key={line.label} className="border-t border-white/5">
                      <td className="py-1.5 pr-2 text-[10.5px] text-white/45">{line.label}</td>
                      <td className="py-1.5 pr-2 font-mono text-[10.5px] text-white/55">{line.expected}</td>
                      <td className="py-1.5 font-mono text-[10.5px]" style={{ color: LINE_HEX[line.match] }}>
                        <span aria-hidden="true">{LINE_GLYPH[line.match]}</span>{' '}
                        {line.actual ?? 'not observed'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* ================================================================== */
/* 8. Migration verification (§11)                                     */
/* ================================================================== */

const VERIFY_HEX: Record<MigrationVerification['status'], string> = {
  confirmed: GREEN,
  'fallback-detected': RED,
  'not-observed': SLATE,
};

const VERIFY_GLYPH: Record<MigrationVerification['status'], string> = {
  confirmed: '✓',
  'fallback-detected': '●',
  'not-observed': '·',
};

export function MigrationVerificationPanel({ rows }: { rows: MigrationVerification[] }) {
  return (
    <Panel className="p-5">
      <SectionHeading
        title="PQC Migration Verification"
        icon={CheckCircle2}
        meta="runtime confirmation"
        action={<LinkButton href="/dashboard/live-migration" tone="ghost">Live Migration</LinkButton>}
      />

      {rows.length === 0 ? (
        <EmptyRow>No migration has completed yet, so there is nothing to verify at runtime.</EmptyRow>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {rows.map((row) => (
            <div key={row.jobId} className="rounded-xl border border-white/10 bg-black/20 p-4">
              <div className="truncate text-[12.5px] font-black text-white/90">{row.assetName}</div>
              <div className="mt-0.5 text-[10px] text-white/35">Completed {relativeTime(row.completedAt)}</div>

              <div className="mt-3 flex items-center gap-2 text-[11px]">
                <span className="rounded border border-white/10 bg-white/[0.03] px-2 py-1 font-mono text-white/45">{row.before ?? 'not recorded'}</span>
                <ChevronRight className="h-3 w-3 shrink-0 text-white/25" aria-hidden="true" />
                <span className="truncate rounded border border-cyan-400/30 bg-cyan-500/10 px-2 py-1 font-mono text-cyan-200">{row.after}</span>
              </div>

              <dl className="mt-3 grid grid-cols-2 gap-2">
                <div className="rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-2">
                  <dt className="text-[8.5px] font-black uppercase tracking-wider text-white/30">Verified</dt>
                  <dd className="font-mono text-[15px] font-black text-white/85">{fmtInt(row.sessionsVerified)}</dd>
                </div>
                <div className="rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-2">
                  <dt className="text-[8.5px] font-black uppercase tracking-wider text-white/30">Fallbacks</dt>
                  <dd className="font-mono text-[15px] font-black" style={{ color: row.fallbacks > 0 ? RED : GREEN }}>{fmtInt(row.fallbacks)}</dd>
                </div>
              </dl>

              <div
                className="mt-3 inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[9px] font-black uppercase tracking-wider"
                style={{ borderColor: `${VERIFY_HEX[row.status]}55`, backgroundColor: `${VERIFY_HEX[row.status]}16`, color: VERIFY_HEX[row.status] }}
              >
                <span aria-hidden="true">{VERIFY_GLYPH[row.status]}</span>
                {row.statusLabel}
              </div>
              <p className="mt-2 text-[10.5px] leading-relaxed text-white/40">{row.detail}</p>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* ================================================================== */
/* 9. Harvest-now risk (§13)                                           */
/* ================================================================== */

export function HndlRiskPanel({ card }: { card: HndlCard }) {
  return (
    <Panel className="flex h-full flex-col p-5">
      <SectionHeading title="Harvest-Now Risk" icon={Timer} />
      <div className="flex items-baseline gap-2">
        <span className="font-mono text-[30px] font-black leading-none" style={{ color: card.highRiskAssets > 0 ? RED : GREEN }}>
          {fmtInt(card.highRiskAssets)}
        </span>
        <span className="text-[11.5px] text-white/45">high-risk asset{card.highRiskAssets === 1 ? '' : 's'}</span>
      </div>
      <p className="mt-2.5 text-[12px] leading-relaxed text-white/55">{card.headline}</p>

      {card.topAsset ? (
        <div className="mt-3 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2.5">
          <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/30">Highest risk</div>
          <div className="mt-1 truncate text-[12px] font-black text-white/85">{card.topAsset.name}</div>
          <p className="mt-1 text-[10.5px] leading-relaxed text-white/40">{card.topAsset.reason}</p>
        </div>
      ) : null}

      <div className="mt-3 flex items-center justify-between rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
        <span className="text-[10.5px] text-white/45">Estate HNDL risk (Quantum Readiness)</span>
        <span className="font-mono text-[13px] font-black text-cyan-300">{card.score}/100 · {card.level}</span>
      </div>

      <div className="mt-auto pt-4">
        <LinkButton href={card.href}>View HNDL Risks</LinkButton>
      </div>
    </Panel>
  );
}

/* ================================================================== */
/* 10. Sophia insight (§14)                                            */
/* ================================================================== */

export function SophiaInsightPanel({
  insight, onAsk,
}: {
  insight: SophiaInsight;
  onAsk: (question: string) => void;
}) {
  return (
    <Panel className="flex h-full flex-col border-violet-400/20 p-5">
      <SectionHeading title="Sophia's Insight" icon={Sparkles} />

      <div className="flex items-start gap-3">
        <div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-violet-400/30 bg-violet-500/10 text-violet-300" aria-hidden="true">
          <Sparkles className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <div className="text-[12.5px] font-black text-violet-200">{insight.headline}</div>
          <p className="mt-1.5 text-[12px] leading-relaxed text-white/60">{insight.body}</p>
        </div>
      </div>

      <div className="mt-3 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2.5">
        <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/30">Recommended</div>
        <p className="mt-1 text-[11.5px] leading-relaxed text-white/65">{insight.recommendation}</p>
      </div>

      {insight.evidence.length ? (
        <details className="mt-3 group">
          <summary className="cursor-pointer list-none text-[10px] font-black uppercase tracking-wider text-violet-300/70 outline-none transition hover:text-violet-200 focus-visible:ring-2 focus-visible:ring-violet-300/70">
            Show the evidence
          </summary>
          <ul className="mt-2 space-y-1 border-l border-violet-400/20 pl-3">
            {insight.evidence.map((line, index) => (
              <li key={index} className="text-[10.5px] leading-relaxed text-white/40">{line}</li>
            ))}
          </ul>
        </details>
      ) : null}

      <div className="mt-auto flex flex-wrap gap-2 pt-4">
        <button
          type="button"
          onClick={() => onAsk(insight.question)}
          className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/45 bg-violet-500/12 px-3 py-2 text-[9.5px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/22 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-violet-300/70"
        >
          <Sparkles className="h-3.5 w-3.5" aria-hidden="true" /> Ask Sophia
        </button>
        {insight.hasFinding ? <LinkButton href={insight.actionHref} tone="ghost">Investigate</LinkButton> : null}
      </div>
    </Panel>
  );
}

/* ================================================================== */
/* 11. Filters + search (§15, §16)                                     */
/* ================================================================== */

function Select({
  label, value, options, onChange,
}: {
  label: string;
  value: string;
  options: Array<{ value: string; label: string }>;
  onChange: (value: string) => void;
}) {
  const id = `runtime-filter-${label.toLowerCase().replace(/\s+/g, '-')}`;
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <label htmlFor={id} className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/35">{label}</label>
      <select
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-lg border border-white/12 bg-[#0b1424] px-2.5 py-1.5 text-[11px] font-semibold text-white/80 outline-none transition focus-visible:border-cyan-400/50 focus-visible:ring-2 focus-visible:ring-cyan-300/40"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
    </div>
  );
}

export function RuntimeFilterBar({
  filters, environments, onChange, onClear, resultCount, resultLabel,
}: {
  filters: RuntimeFilters;
  environments: string[];
  onChange: (patch: Partial<RuntimeFilters>) => void;
  onClear: () => void;
  resultCount: number;
  resultLabel: string;
}) {
  return (
    <Panel className="p-4">
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex min-w-[220px] flex-1 flex-col gap-1">
          <label htmlFor="runtime-search" className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/35">Search</label>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/30" aria-hidden="true" />
            <input
              id="runtime-search"
              type="search"
              value={filters.search}
              onChange={(event) => onChange({ search: event.target.value })}
              placeholder="Search applications, algorithms, certificates…"
              className="w-full rounded-lg border border-white/12 bg-[#0b1424] py-1.5 pl-8 pr-2.5 text-[11.5px] text-white/85 outline-none transition placeholder:text-white/25 focus-visible:border-cyan-400/50 focus-visible:ring-2 focus-visible:ring-cyan-300/40"
            />
          </div>
        </div>

        <Select
          label="Environment"
          value={filters.environment}
          onChange={(value) => onChange({ environment: value })}
          options={[{ value: 'all', label: 'All' }, ...environments.map((env) => ({ value: env, label: env.charAt(0).toUpperCase() + env.slice(1) }))]}
        />
        <Select
          label="Risk"
          value={filters.risk}
          onChange={(value) => onChange({ risk: value as RuntimeFilters['risk'] })}
          options={[
            { value: 'all', label: 'All' },
            { value: 'critical', label: 'Critical' },
            { value: 'high', label: 'High' },
            { value: 'medium', label: 'Attention' },
            { value: 'low', label: 'Low' },
          ]}
        />
        <Select
          label="Quantum Status"
          value={filters.status}
          onChange={(value) => onChange({ status: value as RuntimeFilters['status'] })}
          options={[
            { value: 'all', label: 'All' },
            { value: 'safe', label: 'Quantum Safe' },
            { value: 'hybrid', label: 'Hybrid PQC' },
            { value: 'vulnerable', label: 'Vulnerable' },
            { value: 'unknown', label: 'Needs Review' },
          ]}
        />
        <Select
          label="Time"
          value={filters.window}
          onChange={(value) => onChange({ window: value as RuntimeFilters['window'] })}
          options={TIME_WINDOWS.map((option) => ({ value: option.key, label: option.label }))}
        />

        <div className="flex items-center gap-2 pb-0.5">
          <span className="font-mono text-[10px] text-white/35">{fmtInt(resultCount)} {resultLabel}</span>
          <button
            type="button"
            onClick={onClear}
            className="inline-flex items-center gap-1 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-white/55 transition hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
          >
            <X className="h-3 w-3" aria-hidden="true" /> Clear
          </button>
        </div>
      </div>
    </Panel>
  );
}

/* ================================================================== */
/* 12. Telemetry states (§27)                                          */
/* ================================================================== */

/**
 * The no-data state.
 *
 * Two very different situations produce zero runtime events, and they need
 * opposite advice: an estate with nothing enrolled must DEPLOY a collector; an
 * estate whose collector is enrolled but silent must FIX the one it has. Telling
 * the second user to "connect a telemetry source" sends them to install a second
 * broken agent.
 */
export function NoTelemetryState({
  discovery, telemetry,
}: {
  discovery: RuntimeCryptoIntelligence['discovery'];
  telemetry: RuntimeTelemetryState;
}) {
  const silent = telemetry.collectorState === 'registered-silent';
  return (
    <Panel className="p-8 text-center">
      <Radio className="mx-auto h-9 w-9 text-cyan-300/60" aria-hidden="true" />
      <h2 className="mt-3 text-[18px] font-black text-white">
        {silent ? 'Collector Enrolled — Not Reporting' : 'No Collector Configured'}
      </h2>
      <p className="mx-auto mt-2 max-w-2xl text-[12px] leading-relaxed text-white/50">
        {silent ? (
          <>
            {fmtInt(telemetry.totalAgents)} collector agent{telemetry.totalAgents === 1 ? '' : 's'} and{' '}
            {fmtInt(telemetry.connectors)} cloud connector{telemetry.connectors === 1 ? '' : 's'} are registered for this
            environment, but none has ever sent a cryptographic event. The pipeline is configured and not delivering —
            check the collector rather than enrolling another.
          </>
        ) : (
          <>
            No collector agent or cloud connector has been configured for this environment, so QGuard Helix cannot
            observe what cryptography is actually executing. Nothing on this page is estimated or simulated.
          </>
        )}
      </p>

      <div className="mx-auto mt-4 max-w-2xl rounded-xl border border-cyan-400/20 bg-cyan-500/[0.06] p-4 text-left">
        <div className="text-[9px] font-black uppercase tracking-[0.16em] text-cyan-300/80">
          {silent ? 'How to diagnose it' : 'How to start runtime monitoring'}
        </div>
        <ol className="mt-2 space-y-1.5 text-[11.5px] leading-relaxed text-white/55">
          {silent ? (
            <>
              <li>1. Open Agents Collector (Discovery → PQC Scanner) and check the collector's last-seen time and enrolment status.</li>
              <li>2. Confirm the agent process is running on the host and its token has not been revoked or rotated.</li>
              <li>3. Confirm the host has outbound access to the QGuard ingest endpoint.</li>
              <li>4. Events appear here within seconds of the first successful report.</li>
            </>
          ) : (
            <>
              <li>1. Open <span className="font-semibold text-white/75">Scanner → Agents</span> and enrol a collector agent, or connect a cloud provider.</li>
              <li>2. The agent observes live TLS handshakes, signing operations and cryptographic library calls on its host.</li>
              <li>3. It posts them to QGuard Helix, which classifies each observation as quantum-safe, hybrid or vulnerable.</li>
              <li>4. This page then shows what is executing — and whether it matches what your migration plan expects.</li>
            </>
          )}
        </ol>
        <p className="mt-2.5 text-[10px] leading-relaxed text-white/30">
          Discovery scans tell you what cryptography <span className="font-semibold text-white/50">exists</span>. Only a
          collector tells you what is <span className="font-semibold text-white/50">running</span>.
        </p>
      </div>

      <div className="mx-auto mt-5 max-w-3xl rounded-xl border border-white/10 bg-black/25 p-4 text-left">
        <div className="text-[9px] font-black uppercase tracking-[0.16em] text-cyan-300/70">What discovery already knows</div>
        <p className="mt-1 text-[10.5px] leading-relaxed text-white/35">{discovery.note}</p>
        <dl className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-5">
          {[
            ['Assets', discovery.assetsAssessed],
            ['Crypto components', discovery.cryptoComponents],
            ['Vulnerable', discovery.vulnerableComponents],
            ['Certificates', discovery.certificatesAnalyzed],
            ['PQC adoption', `${discovery.pqcAdoptionPct}%`],
          ].map(([label, value]) => (
            <div key={String(label)} className="rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-2">
              <dt className="text-[8.5px] font-black uppercase tracking-wider text-white/30">{String(label)}</dt>
              <dd className="font-mono text-[16px] font-black text-white/85">{typeof value === 'number' ? fmtInt(value) : String(value)}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div className="mt-5 flex flex-wrap justify-center gap-2">
        <a
          href="/dashboard/agents"
          className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-4 py-2.5 text-[10px] font-black uppercase tracking-wider text-cyan-200 no-underline transition hover:bg-cyan-500/25"
        >
          {silent ? 'Check Collector Status' : 'Deploy a Collector Agent'}
        </a>
        <a
          href="/dashboard/cbom"
          className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/5 px-4 py-2.5 text-[10px] font-black uppercase tracking-wider text-white/60 no-underline transition hover:bg-white/10"
        >
          View CBOM
        </a>
      </div>
    </Panel>
  );
}

export function WindowEmptyNotice({
  telemetry, onWiden,
}: {
  telemetry: RuntimeTelemetryState;
  onWiden: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3">
      <Clock className="h-4 w-4 shrink-0 text-amber-300" aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <div className="text-[11.5px] font-black text-amber-200">No cryptographic activity in the selected period</div>
        <div className="text-[10px] text-white/45">
          This tenant has {fmtInt(telemetry.totalRuntimeEvents)} runtime observation(s); the most recent was {relativeTime(telemetry.latestEventAt)}
          {telemetry.activeAgents === 0 && telemetry.totalAgents > 0 ? ' — no collector has reported in the last 15 minutes.' : '.'}
        </div>
      </div>
      <button
        type="button"
        onClick={onWiden}
        className="rounded border border-amber-400/40 bg-amber-500/10 px-3 py-1.5 text-[9px] font-black uppercase tracking-wider text-amber-200 transition hover:bg-amber-500/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-300/70"
      >
        Widen to 30 days
      </button>
    </div>
  );
}

/* ================================================================== */
/* 13. Coverage strip                                                  */
/* ================================================================== */

export function CoverageStrip({ telemetry }: { telemetry: RuntimeTelemetryState }) {
  const cells: Array<[string, string]> = [
    ['Assets observed', fmtInt(telemetry.coveredAssets)],
    ['Collectors reporting', `${fmtInt(telemetry.activeAgents)}/${fmtInt(telemetry.totalAgents)}`],
    ['Cloud connectors', fmtInt(telemetry.connectors)],
    ['Latest observation', relativeTime(telemetry.latestEventAt)],
  ];
  return (
    <Panel className="p-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {cells.map(([label, value]) => (
          <div key={label}>
            <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">{label}</div>
            <div className="mt-1 font-mono text-[15px] font-black text-white/85">{value}</div>
          </div>
        ))}
      </div>
      {telemetry.sources.length ? (
        <div className="mt-3 flex flex-wrap gap-2 border-t border-white/8 pt-3">
          {telemetry.sources.map((source) => (
            <span key={source.label} className="rounded-full border border-white/10 bg-white/[0.03] px-2.5 py-1 text-[9.5px] text-white/45">
              {source.label} <span className="font-mono text-white/65">{fmtInt(source.count)}</span> · {source.percent}%
            </span>
          ))}
        </div>
      ) : null}
    </Panel>
  );
}

/* ================================================================== */
/* 14. Risks workspace (Risks tab)                                     */
/* ================================================================== */

export function RisksWorkspace({
  issues, onSelect,
}: {
  issues: RuntimeIssue[];
  onSelect: (issue: RuntimeIssue) => void;
}) {
  const bySeverity: Array<[RiskLevel, RuntimeIssue[]]> = (['critical', 'high', 'medium', 'low'] as RiskLevel[]).map((level) => [
    level,
    issues.filter((issue) => issue.severity === level),
  ]);

  return (
    <Panel className="p-5">
      <SectionHeading title="Runtime Findings" icon={ShieldAlert} meta={`${fmtInt(issues.length)} open`} />
      {issues.length === 0 ? (
        <div className="rounded-lg border border-emerald-400/25 bg-emerald-500/[0.06] px-4 py-8 text-center">
          <CheckCircle2 className="mx-auto h-7 w-7 text-emerald-300" aria-hidden="true" />
          <div className="mt-2 text-[13px] font-black text-emerald-200">No Runtime Risks</div>
          <p className="mx-auto mt-1 max-w-md text-[11.5px] leading-relaxed text-white/45">
            No significant cryptographic risks were detected during the selected period.
          </p>
        </div>
      ) : (
        <div className="space-y-5">
          {bySeverity.map(([level, rows]) =>
            rows.length ? (
              <div key={level}>
                <div className="mb-2 flex items-center gap-2 text-[9.5px] font-black uppercase tracking-[0.16em]" style={{ color: RISK_HEX[level] }}>
                  <span aria-hidden="true">{RISK_GLYPH[level]}</span>
                  {RISK_LABEL[level]}
                  <span className="font-mono text-white/30">{fmtInt(rows.length)}</span>
                </div>
                <div className="space-y-2">
                  {rows.map((issue) => <IssueRow key={issue.id} issue={issue} onSelect={onSelect} />)}
                </div>
              </div>
            ) : null,
          )}
        </div>
      )}
    </Panel>
  );
}

/* ================================================================== */
/* 15. Score explainer                                                 */
/* ================================================================== */

export function ScoreExplainer({
  status, open, onClose,
}: {
  status: RuntimeSecurityStatus;
  open: boolean;
  onClose: () => void;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4" role="dialog" aria-modal="true" aria-label="How the runtime security score is calculated">
      <div className="w-full max-w-lg rounded-2xl border border-white/12 bg-[#0b1424] p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <h2 className="text-[15px] font-black text-white">How the runtime security score is calculated</h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-white/12 bg-white/[0.04] p-1.5 text-white/50 transition hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
            aria-label="Close"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
        <p className="mt-3 text-[12px] leading-relaxed text-white/60">{status.basis}</p>
        <ul className="mt-4 space-y-1.5 text-[11.5px] leading-relaxed text-white/50">
          <li>· <span className="font-black text-emerald-300">Quantum Safe</span> scores 100 — a NIST post-quantum primitive.</li>
          <li>· <span className="font-black text-blue-300">Hybrid PQC</span> scores 85 — secure, but a transition state rather than the destination.</li>
          <li>· <span className="font-black text-slate-300">Unknown</span> scores 50 — unmeasured cryptography can never read as safe.</li>
          <li>· <span className="font-black text-red-300">Quantum Vulnerable</span> scores 0.</li>
          <li>· Open findings apply a bounded penalty of at most 15 points; the current penalty is <span className="font-mono font-black text-white/80">{status.penaltyApplied}</span>.</li>
        </ul>
        <p className="mt-4 rounded-lg border border-white/10 bg-black/25 p-3 text-[10.5px] leading-relaxed text-white/40">
          The score describes what was OBSERVED at runtime in the selected period. Estate-wide posture — which includes
          cryptography that exists but was not observed executing — is published by Quantum Readiness.
        </p>
      </div>
    </div>
  );
}
