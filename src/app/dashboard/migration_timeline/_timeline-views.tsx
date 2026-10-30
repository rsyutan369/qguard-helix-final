'use client';

import { useState } from 'react';
import { CalendarRange, ChevronDown, ChevronRight, GitBranch, History, TrendingUp } from 'lucide-react';
import { cn } from '@/lib/utils';
import { DISPLAY_STATUS_LABEL, type OrchestrationSnapshot, type PlanScheduleState } from '@/lib/migration/orchestration-model';
import { Panel } from '../_components/executive/primitives';
import { EmptyRow, SectionHeading, fmtInt, fmtPct, fullTimestamp, relativeTime } from '../_components/intel/kit';
import { DISPLAY_TONE, TONE_BAR, TONE_CHIP, TONE_TEXT, StatusBadge } from '../pqc-orchestration/_orch-ui';
import { WINDOW_LABEL, type ChronologyDay, type MarkerKind, type TimeWindow, type TimelineModel } from './_timeline-lib';

/* ------------------------------------------------------------------ */
/* Schedule (Gantt)                                                    */
/* ------------------------------------------------------------------ */

const MARKER_COPY: Record<MarkerKind, { glyph: string; tone: string }> = {
  recorded: { glyph: '●', tone: 'text-white/55' },
  approved: { glyph: '✓', tone: 'text-blue-300' },
  scheduled: { glyph: '◆', tone: 'text-violet-300' },
  'first-start': { glyph: '▶', tone: 'text-cyan-300' },
  'last-completion': { glyph: '■', tone: 'text-emerald-300' },
};

const SCHEDULE_COPY: Record<PlanScheduleState, { label: string; chip: string }> = {
  'not-recorded': { label: 'No schedule recorded', chip: TONE_CHIP.slate },
  upcoming: { label: '◆ Scheduled · upcoming', chip: TONE_CHIP.violet },
  started: { label: '▶ Started', chip: TONE_CHIP.cyan },
  overdue: { label: '! Scheduled start passed', chip: TONE_CHIP.amber },
};

const BAR_CAP = 14;
const WINDOWS: TimeWindow[] = ['all', '90d', '30d', '7d'];

export function ScheduleGantt({
  model, window, onWindow, onOpen,
}: {
  model: TimelineModel;
  window: TimeWindow;
  onWindow: (w: TimeWindow) => void;
  onOpen: (jobId: string) => void;
}) {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const toggle = (id: string) => setCollapsed((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });

  return (
    <Panel className="p-4 sm:p-5">
      <SectionHeading
        id="tl-schedule"
        title="Migration schedule"
        icon={CalendarRange}
        meta={`${fmtInt(model.shown)} job${model.shown === 1 ? '' : 's'} placed${model.truncated ? ` · ${fmtInt(model.listed)} most urgent of ${fmtInt(model.total)} listed` : ''}`}
        action={(
          <div role="group" aria-label="Time window" className="inline-flex rounded-lg border border-white/12 bg-white/[0.03] p-0.5">
            {WINDOWS.map((w) => (
              <button
                key={w}
                type="button"
                aria-pressed={window === w}
                onClick={() => onWindow(w)}
                className={cn('min-h-[30px] rounded-md px-2.5 text-[9.5px] font-black uppercase tracking-wider transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70', window === w ? 'bg-cyan-500/15 text-cyan-200' : 'text-white/50 hover:text-white/75')}
              >
                {WINDOW_LABEL[w]}
              </button>
            ))}
          </div>
        )}
      />

      {model.scheduleRecorded === 0 ? (
        <p className="mb-3 rounded-lg border border-violet-400/25 bg-violet-500/[0.06] px-3 py-2 text-[11px] leading-relaxed text-white/65">
          <span className="font-black text-violet-300">No schedule is recorded.</span>{' '}
          {model.planCount ? `None of the ${fmtInt(model.planCount)} plan${model.planCount === 1 ? '' : 's'} records a scheduled start` : 'No plan records a scheduled start'}, and the platform records no target completion date.
          Bars therefore show recorded activity — when each job was recorded, started and finished — not a planned schedule, and nothing is called overdue.
        </p>
      ) : model.overduePlans > 0 ? (
        <p className="mb-3 rounded-lg border border-amber-400/30 bg-amber-500/[0.07] px-3 py-2 text-[11px] leading-relaxed text-amber-200">
          ! {fmtInt(model.overduePlans)} plan{model.overduePlans === 1 ? '' : 's'} passed {model.overduePlans === 1 ? 'its' : 'their'} recorded scheduled start with no job started.
        </p>
      ) : null}

      <Legend />

      {!model.domain ? (
        <EmptyRow>No recorded job matches these filters{model.outsideWindow ? ` — ${fmtInt(model.outsideWindow)} finished before the ${WINDOW_LABEL[window].toLowerCase()} window` : ''}.</EmptyRow>
      ) : (
        <div className="mt-3">
          {/* Axis */}
          <div className="grid grid-cols-[minmax(0,1fr)] md:grid-cols-[220px_minmax(0,1fr)]">
            <div className="hidden md:block" />
            <div className="relative h-6 border-b border-white/10" aria-hidden="true">
              {model.ticks.map((tick) => (
                <span key={tick.at} className="absolute top-0 -translate-x-1/2 whitespace-nowrap font-mono text-[9px] text-white/45" style={{ left: `${tick.pct}%` }}>{tick.label}</span>
              ))}
            </div>
          </div>

          <div className="divide-y divide-white/8">
            {model.lanes.map((lane) => {
              const open = !collapsed.has(lane.id);
              const plan = lane.plan;
              const bars = lane.bars.slice(0, BAR_CAP);
              return (
                <section key={lane.id} aria-label={`${lane.title} lane`} className="py-2">
                  <div className="grid grid-cols-[minmax(0,1fr)] items-center gap-1 md:grid-cols-[220px_minmax(0,1fr)]">
                    <button
                      type="button"
                      aria-expanded={open}
                      onClick={() => toggle(lane.id)}
                      className="flex min-h-[34px] items-center gap-1.5 rounded-md pr-2 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
                    >
                      {open ? <ChevronDown className="h-3.5 w-3.5 shrink-0 text-white/45" aria-hidden="true" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0 text-white/45" aria-hidden="true" />}
                      <span className="min-w-0">
                        <span className="block truncate text-[11.5px] font-black text-white/85">{lane.title}</span>
                        <span className="block truncate text-[9.5px] text-white/45">
                          {plan
                            ? `${fmtInt(plan.jobs)} job${plan.jobs === 1 ? '' : 's'} · ${fmtPct(plan.completionPct)} completed · ${fmtPct(plan.verifiedPct)} verified`
                            : `${fmtInt(lane.bars.length + lane.hidden)} listed job${lane.bars.length + lane.hidden === 1 ? '' : 's'} · per-finding remediation`}
                        </span>
                      </span>
                    </button>
                    <div className="relative h-7 rounded-md bg-white/[0.02]">
                      <NowLine pct={model.nowPct} />
                      {lane.markers.map((marker) => (
                        <span
                          key={`${marker.kind}-${marker.at}`}
                          title={`${marker.label} · ${fullTimestamp(new Date(marker.at).toISOString())}`}
                          className={cn('absolute top-1/2 -translate-x-1/2 -translate-y-1/2 text-[11px] font-black', MARKER_COPY[marker.kind].tone, marker.kind === 'scheduled' && lane.schedule === 'overdue' && 'text-amber-300')}
                          style={{ left: `${marker.pct}%` }}
                        >
                          <span aria-hidden="true">{MARKER_COPY[marker.kind].glyph}</span>
                          <span className="sr-only">{marker.label}, {fullTimestamp(new Date(marker.at).toISOString())}</span>
                        </span>
                      ))}
                      {plan && lane.schedule ? (
                        <span className={cn('absolute right-1 top-1/2 hidden -translate-y-1/2 rounded-full border px-2 py-0.5 text-[8.5px] font-black uppercase tracking-wider sm:inline-block', SCHEDULE_COPY[lane.schedule].chip)}>
                          {SCHEDULE_COPY[lane.schedule].label}
                        </span>
                      ) : null}
                    </div>
                  </div>

                  {open ? (
                    <ul className="mt-1 space-y-1">
                      {bars.map((bar) => {
                        const tone = DISPLAY_TONE[bar.display];
                        const width = Math.max(bar.endPct - bar.startPct, 0.9);
                        const waiting = bar.startKind === 'created';
                        const label = `${bar.name} — ${DISPLAY_STATUS_LABEL[bar.display]}. ${waiting ? 'Never started; recorded' : 'Started'} ${fullTimestamp(new Date(bar.startAt).toISOString())}, ${bar.endKind === 'completed' ? 'completed' : bar.endKind === 'now' ? 'still open' : 'last updated'} ${bar.endKind === 'now' ? 'now' : fullTimestamp(new Date(bar.endAt).toISOString())}.`;
                        return (
                          <li key={bar.jobId} className="grid grid-cols-[minmax(0,1fr)] items-center gap-1 md:grid-cols-[220px_minmax(0,1fr)]">
                            <div className="flex min-w-0 items-center gap-1.5 pl-5">
                              <span className={cn('text-[10px]', TONE_TEXT[tone.tone])} aria-hidden="true">{tone.glyph}</span>
                              <span className="truncate text-[10.5px] text-white/70">{bar.assetName}</span>
                              {bar.phaseIndex ? <span className="shrink-0 rounded border border-white/12 px-1 font-mono text-[8.5px] text-white/50" title={bar.phaseName || undefined}>P{bar.phaseIndex}</span> : null}
                            </div>
                            <div className="relative h-6">
                              <NowLine pct={model.nowPct} faint />
                              <button
                                type="button"
                                onClick={() => onOpen(bar.jobId)}
                                aria-label={label}
                                title={label}
                                className={cn(
                                  'absolute top-1/2 h-3.5 -translate-y-1/2 rounded-sm border transition hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/80',
                                  waiting ? 'border-dashed bg-transparent' : TONE_BAR[tone.tone],
                                  waiting && TONE_BAR[tone.tone].split(' ').filter((c) => c.startsWith('border-')).join(' '),
                                  bar.clipped && 'rounded-l-none border-l-0',
                                )}
                                style={{ left: `${bar.startPct}%`, width: `${width}%` }}
                              />
                              {bar.verifiedPct !== null ? (
                                <span className="pointer-events-none absolute top-1/2 -translate-x-1/2 -translate-y-1/2 text-[10px] font-black text-emerald-300" style={{ left: `${bar.verifiedPct}%` }} aria-hidden="true">✓</span>
                              ) : null}
                            </div>
                          </li>
                        );
                      })}
                      {lane.bars.length > bars.length ? (
                        <li className="pl-5 text-[10px] text-white/45">+ {fmtInt(lane.bars.length - bars.length)} more in this lane — see the Jobs tab.</li>
                      ) : null}
                      {lane.hidden > 0 ? (
                        <li className="pl-5 text-[10px] text-white/40">{fmtInt(lane.hidden)} listed job{lane.hidden === 1 ? '' : 's'} hidden by the current filter or window.</li>
                      ) : null}
                    </ul>
                  ) : null}
                </section>
              );
            })}
          </div>
        </div>
      )}
    </Panel>
  );
}

function NowLine({ pct, faint }: { pct: number | null; faint?: boolean }) {
  if (pct === null) return null;
  return (
    <span className={cn('pointer-events-none absolute inset-y-0 w-px', faint ? 'bg-cyan-300/25' : 'bg-cyan-300/70')} style={{ left: `${pct}%` }} aria-hidden="true">
      {!faint ? <span className="absolute -top-0.5 left-1 font-mono text-[8px] font-black uppercase text-cyan-300">now</span> : null}
    </span>
  );
}

function Legend() {
  const items: Array<{ label: string; className: string; dashed?: boolean }> = [
    { label: 'Running', className: TONE_BAR.cyan },
    { label: 'Completed · unverified', className: TONE_BAR.amber },
    { label: 'Verified', className: TONE_BAR.emerald },
    { label: 'Failed / validation failed', className: TONE_BAR.red },
    { label: 'Held / blocked', className: TONE_BAR.orange },
    { label: 'Never started (waiting since recorded)', className: TONE_BAR.blue, dashed: true },
  ];
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[10px] text-white/55" aria-label="Legend">
      {items.map((item) => (
        <span key={item.label} className="inline-flex items-center gap-1.5">
          <span className={cn('inline-block h-2.5 w-5 rounded-sm border', item.dashed ? 'border-dashed bg-transparent' : '', item.dashed ? item.className.split(' ').filter((c) => c.startsWith('border-')).join(' ') : item.className)} aria-hidden="true" />
          {item.label}
        </span>
      ))}
      <span className="inline-flex items-center gap-1.5"><span className="text-emerald-300" aria-hidden="true">✓</span> validation passed</span>
      <span className="inline-flex items-center gap-1.5"><span className="text-blue-300" aria-hidden="true">✓</span> plan approved</span>
      <span className="inline-flex items-center gap-1.5"><span className="text-violet-300" aria-hidden="true">◆</span> recorded scheduled start</span>
      <span className="inline-flex items-center gap-1.5"><span className="inline-block h-3 w-px bg-cyan-300/70" aria-hidden="true" /> now</span>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Chronology                                                          */
/* ------------------------------------------------------------------ */

const CHRONO_TONE: Record<string, string> = {
  good: 'text-emerald-300', warning: 'text-amber-300', critical: 'text-red-300', info: 'text-blue-300', neutral: 'text-white/55',
};
const CHRONO_GLYPH: Record<string, string> = {
  recorded: '●', approved: '✓', scheduled: '◆', started: '▶', completed: '■', verified: '✓', failed: '✕', event: '·',
};

export function ChronologyPanel({ days, total, capped, onOpen }: { days: ChronologyDay[]; total: number; capped: boolean; onOpen: (jobId: string) => void }) {
  if (!days.length) return <EmptyRow>No recorded activity matches the current filters.</EmptyRow>;
  return (
    <div>
      <SectionHeading title="Activity chronology" icon={History} meta={`${fmtInt(total)} recorded milestone${total === 1 ? '' : 's'}${capped ? ' · newest 160 shown' : ''}`} />
      <p className="mb-3 text-[10.5px] leading-relaxed text-white/50">
        Every timestamp the platform wrote for these jobs and plans — recorded, approved, started, completed, verified, failed — plus the migration event log. Newest first.
      </p>
      <ol className="space-y-4">
        {days.map((day) => (
          <li key={day.day}>
            <div className="mb-1.5 font-mono text-[10px] font-black uppercase tracking-wider text-white/45">
              {new Date(`${day.day}T00:00:00Z`).toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' })}
            </div>
            <ol className="space-y-1 border-l border-white/10 pl-3">
              {day.entries.map((entry) => {
                const content = (
                  <>
                    <span className={cn('mt-0.5 shrink-0 text-[11px] font-black', CHRONO_TONE[entry.tone])} aria-hidden="true">{CHRONO_GLYPH[entry.kind]}</span>
                    <span className="min-w-0 flex-1">
                      <span className="block text-[11.5px] leading-snug text-white/80">{entry.title}</span>
                      <span className="block text-[10px] leading-snug text-white/50">{entry.detail}</span>
                    </span>
                    <span className="shrink-0 font-mono text-[9.5px] text-white/45" title={fullTimestamp(new Date(entry.at).toISOString())}>
                      {new Date(entry.at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })}
                    </span>
                  </>
                );
                return (
                  <li key={entry.id}>
                    {entry.jobId ? (
                      <button type="button" onClick={() => onOpen(entry.jobId!)} className="flex w-full items-start gap-2 rounded-md px-2 py-1.5 text-left transition hover:bg-white/[0.04] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
                        {content}
                      </button>
                    ) : <div className="flex items-start gap-2 px-2 py-1.5">{content}</div>}
                  </li>
                );
              })}
            </ol>
          </li>
        ))}
      </ol>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Plans & recorded phase order                                        */
/* ------------------------------------------------------------------ */

export function PhasesPanel({ snapshot, planId }: { snapshot: OrchestrationSnapshot; planId: string | null }) {
  const plans = snapshot.plans.filter((plan) => !planId || plan.id === planId);
  if (!plans.length) return <EmptyRow>No migration plan is recorded. Per-finding remediation jobs (Harvest Now) have no plan or phase order.</EmptyRow>;
  return (
    <div>
      <SectionHeading title="Plans, phases and recorded dependencies" icon={GitBranch} meta={`${fmtInt(plans.length)} plan${plans.length === 1 ? '' : 's'}`} />
      <p className="mb-3 text-[10.5px] leading-relaxed text-white/50">
        Dependencies are shown only where recorded: the phase order the Migration Planner wrote on each job, the phase gate (a later phase waits for the prior one to be approved), and plan approval. Nothing is inferred.
      </p>
      <div className="space-y-3">
        {plans.map((plan) => {
          const phases = plan.phaseOrder ?? [];
          return (
            <div key={plan.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-3.5">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="truncate text-[12.5px] font-black text-white/85">{plan.name || `Plan ${plan.id.slice(0, 8)}`}</div>
                  <div className="text-[10px] text-white/45">
                    {plan.planStatus ? `Recorded status "${plan.planStatus}" · ` : ''}
                    {plan.approval === 'approved' ? `approved${plan.approvedBy ? ` by ${plan.approvedBy}` : ''}${plan.approvedAt ? ` ${relativeTime(plan.approvedAt)}` : ''}` : !plan.readable ? 'approval unreadable' : plan.approval === 'rejected' ? 'rejected' : 'not approved'}
                    {plan.scheduledAt ? ` · scheduled start ${fullTimestamp(plan.scheduledAt)}` : ' · no scheduled start recorded'}
                  </div>
                </div>
                <div className="flex flex-wrap gap-1.5 text-[9.5px] font-black">
                  <span className={cn('rounded-full border px-2 py-0.5', TONE_CHIP.cyan)}>{fmtPct(plan.completionPct)} completed</span>
                  <span className={cn('rounded-full border px-2 py-0.5', TONE_CHIP.emerald)}>{fmtPct(plan.verifiedPct)} verified</span>
                  {plan.failed ? <span className={cn('rounded-full border px-2 py-0.5', TONE_CHIP.red)}>{fmtInt(plan.failed)} failed</span> : null}
                </div>
              </div>
              {phases.length ? (
                <ol className="mt-3 flex flex-wrap items-stretch gap-1.5" aria-label="Recorded phase order">
                  {phases.map((phase, index) => {
                    const done = phase.jobs > 0 && phase.verified === phase.jobs;
                    const tone = phase.failed ? 'red' : done ? 'emerald' : phase.open > 0 && phase.waitingForPrior === phase.open ? 'blue' : phase.completed === phase.jobs ? 'amber' : 'cyan';
                    return (
                      <li key={phase.index} className="flex items-center gap-1.5">
                        {index > 0 ? (
                          <span className="text-[10px] text-white/40" title={phase.gateRequired ? 'Recorded gate: starts after the prior phase is approved' : 'Recorded order'}>
                            {phase.gateRequired ? '→ gate →' : '→'}
                          </span>
                        ) : null}
                        <span className={cn('rounded-lg border px-2.5 py-1.5 text-[10.5px]', TONE_CHIP[tone])}>
                          <span className="font-black">Phase {phase.index}</span>{phase.name ? ` · ${phase.name}` : ''}
                          <span className="block font-mono text-[9.5px] text-white/60">
                            {phase.jobs} job{phase.jobs === 1 ? '' : 's'} · {phase.verified} verified · {phase.open} open{phase.waitingForPrior ? ` (${phase.waitingForPrior} held for gate)` : ''}
                          </span>
                        </span>
                      </li>
                    );
                  })}
                </ol>
              ) : (
                <p className="mt-2 text-[10.5px] text-white/45">No phase order is recorded on this plan's jobs.</p>
              )}
              <div className="mt-2 flex flex-wrap gap-1.5">
                {Object.entries(plan.phases).map(([phase, count]) => (
                  <span key={phase} className="rounded border border-white/10 px-1.5 py-0.5 font-mono text-[9.5px] text-white/55">{phase} {count}</span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Throughput — daily completions (14 days, UTC)                       */
/* ------------------------------------------------------------------ */

export function ThroughputPanel({ snapshot }: { snapshot: OrchestrationSnapshot }) {
  const days = snapshot.throughput;
  const max = Math.max(1, ...days.map((d) => Math.max(d.completed, d.failed)));
  const totals = days.reduce((acc, d) => ({ completed: acc.completed + d.completed, verified: acc.verified + d.verified, failed: acc.failed + d.failed }), { completed: 0, verified: 0, failed: 0 });
  return (
    <div>
      <SectionHeading title="Completions per day" icon={TrendingUp} meta="last 14 days · UTC" />
      <p className="mb-3 text-[10.5px] leading-relaxed text-white/50">
        {fmtInt(totals.completed)} completed ({fmtInt(totals.verified)} verified) and {fmtInt(totals.failed)} failed in 14 days. Days are bucketed by the recorded completion (or last update, for failures). Verified is a subset of completed.
      </p>
      {!days.length ? <EmptyRow>No throughput series was published.</EmptyRow> : (
        <ol className="flex h-36 items-end gap-1" aria-label="Daily completions">
          {days.map((d) => (
            <li key={d.date} className="flex h-full flex-1 flex-col items-center justify-end gap-1" aria-label={`${d.date}: ${d.completed} completed, ${d.verified} verified, ${d.failed} failed`}>
              <div className="flex h-full w-full items-end justify-center gap-0.5">
                <div className="relative w-1/2 rounded-t-sm border border-amber-600 bg-amber-400/40" style={{ height: `${(d.completed / max) * 100}%`, minHeight: d.completed ? 3 : 0 }}>
                  <div className="absolute inset-x-0 bottom-0 rounded-t-sm bg-emerald-400/90" style={{ height: d.completed ? `${(d.verified / d.completed) * 100}%` : 0 }} />
                </div>
                <div className="w-1/3 rounded-t-sm border border-red-600 bg-red-400/80" style={{ height: `${(d.failed / max) * 100}%`, minHeight: d.failed ? 3 : 0 }} />
              </div>
              <span className="font-mono text-[8px] text-white/45">{d.date.slice(8)}</span>
            </li>
          ))}
        </ol>
      )}
      <div className="mt-2 flex flex-wrap gap-3 text-[10px] text-white/55">
        <span className="inline-flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-sm border border-amber-600 bg-amber-400/40" aria-hidden="true" /> completed (unverified part)</span>
        <span className="inline-flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-sm bg-emerald-400/90" aria-hidden="true" /> verified</span>
        <span className="inline-flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-sm border border-red-600 bg-red-400/80" aria-hidden="true" /> failed</span>
      </div>
    </div>
  );
}

export { StatusBadge };
