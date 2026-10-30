'use client';

/**
 * Presentational components shared by PQC Orchestration (the FLOW view) and
 * Migration Timeline (the TIME view). Nothing here computes a number: counts
 * and statuses come from `orchestration-model` and the pages' pure libs.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode, type RefObject } from 'react';
import { ArrowRight, ChevronLeft, ChevronRight, Command as CommandIcon, CornerDownLeft, Search, Server } from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  DISPLAY_STATUS_LABEL, JOB_DISPLAY_STATUSES, jobDisplayStatus,
  type JobDisplayStatus, type NextActionSummary, type OrchestrationJob, type OrchestrationSnapshot, type PathCheck,
} from '@/lib/migration/orchestration-model';
import type { GateState, OperationalGate } from '@/lib/migration/operational-workflow';
import { EmptyRow, SectionHeading, fmtInt, fullTimestamp, relativeTime, type SourceHealthState } from '../_components/intel/kit';

/* ------------------------------------------------------------------ */
/* Tone vocabulary (class-based so the light-theme bridge applies)     */
/* ------------------------------------------------------------------ */

export type ToneKey = 'emerald' | 'amber' | 'red' | 'cyan' | 'violet' | 'blue' | 'orange' | 'slate';

export const TONE_CHIP: Record<ToneKey, string> = {
  emerald: 'text-emerald-300 border-emerald-400/35 bg-emerald-500/10',
  amber: 'text-amber-300 border-amber-400/35 bg-amber-500/10',
  red: 'text-red-300 border-red-400/35 bg-red-500/10',
  cyan: 'text-cyan-300 border-cyan-400/35 bg-cyan-500/10',
  violet: 'text-violet-300 border-violet-400/35 bg-violet-500/10',
  blue: 'text-blue-300 border-blue-400/35 bg-blue-500/10',
  orange: 'text-orange-300 border-orange-400/35 bg-orange-500/10',
  slate: 'text-white/60 border-white/15 bg-white/[0.04]',
};

export const TONE_TEXT: Record<ToneKey, string> = {
  emerald: 'text-emerald-300', amber: 'text-amber-300', red: 'text-red-300', cyan: 'text-cyan-300',
  violet: 'text-violet-300', blue: 'text-blue-300', orange: 'text-orange-300', slate: 'text-white/60',
};

/** Bar fills carry a darker outline so they hold ≥3:1 against either theme. */
export const TONE_BAR: Record<ToneKey, string> = {
  emerald: 'bg-emerald-400/85 border-emerald-600',
  amber: 'bg-amber-400/85 border-amber-600',
  red: 'bg-red-400/85 border-red-600',
  cyan: 'bg-cyan-400/85 border-cyan-600',
  violet: 'bg-violet-400/85 border-violet-600',
  blue: 'bg-blue-400/70 border-blue-600',
  orange: 'bg-orange-400/85 border-orange-600',
  slate: 'bg-slate-400/60 border-slate-500',
};

export const DISPLAY_TONE: Record<JobDisplayStatus, { tone: ToneKey; glyph: string }> = {
  'awaiting-approval': { tone: 'blue', glyph: '◷' },
  rejected: { tone: 'red', glyph: '✕' },
  'not-released': { tone: 'blue', glyph: '‖' },
  blocked: { tone: 'orange', glyph: '■' },
  ready: { tone: 'blue', glyph: '○' },
  running: { tone: 'cyan', glyph: '▶' },
  'executor-silent': { tone: 'red', glyph: '!' },
  validating: { tone: 'cyan', glyph: '◐' },
  paused: { tone: 'amber', glyph: '‖' },
  failed: { tone: 'red', glyph: '✕' },
  'completed-unverified': { tone: 'amber', glyph: '◑' },
  'validation-failed': { tone: 'red', glyph: '✕' },
  verified: { tone: 'emerald', glyph: '✓' },
  rollback: { tone: 'violet', glyph: '↺' },
  cancelled: { tone: 'slate', glyph: '–' },
};

/** Page-scoped light-theme remap for the two hues the shared IntelShell bridge does not cover. */
export function OrchThemeBridge({ scope }: { scope: string }) {
  return (
    <style>{`
      .qg-theme-light .${scope} .text-blue-300 { color: #1d4ed8 !important; }
      .qg-theme-light .${scope} .text-orange-300 { color: #c2410c !important; }
      .${scope}:fullscreen { background: var(--qg-dashboard-bg, #0a1020); overflow-y: auto; }
    `}</style>
  );
}

/* ------------------------------------------------------------------ */
/* Badges                                                              */
/* ------------------------------------------------------------------ */

export function StatusBadge({ status, className }: { status: JobDisplayStatus; className?: string }) {
  const { tone, glyph } = DISPLAY_TONE[status];
  return (
    <span className={cn('inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-[9.5px] font-black uppercase tracking-wider', TONE_CHIP[tone], className)}>
      <span aria-hidden="true">{glyph}</span>
      {DISPLAY_STATUS_LABEL[status]}
    </span>
  );
}

const GATE_COPY: Record<GateState, { glyph: string; tone: ToneKey; word: string }> = {
  pass: { glyph: '✓', tone: 'emerald', word: 'passed' },
  pending: { glyph: '…', tone: 'blue', word: 'pending' },
  fail: { glyph: '✕', tone: 'red', word: 'failing' },
  unknown: { glyph: '?', tone: 'slate', word: 'unknown' },
};

/** The four shared gates (approval / dispatch / executor / execution). */
export function GateStrip({ gates, compact = false }: { gates: OperationalGate[]; compact?: boolean }) {
  if (compact) {
    return (
      <span className="inline-flex items-center gap-1" aria-label={gates.map((g) => `${g.label} ${GATE_COPY[g.state].word}`).join(', ')}>
        {gates.map((gate) => {
          const copy = GATE_COPY[gate.state];
          return (
            <span key={gate.id} title={`${gate.label}: ${gate.detail}`} className={cn('inline-flex h-5 min-w-[22px] items-center justify-center gap-0.5 rounded border px-1 text-[9px] font-black', TONE_CHIP[copy.tone])}>
              <span aria-hidden="true">{gate.label.slice(0, 2)}</span>
              <span aria-hidden="true">{copy.glyph}</span>
            </span>
          );
        })}
      </span>
    );
  }
  return (
    <ol className="grid gap-1.5 sm:grid-cols-2">
      {gates.map((gate, index) => {
        const copy = GATE_COPY[gate.state];
        return (
          <li key={gate.id} className={cn('rounded-lg border px-3 py-2', TONE_CHIP[copy.tone])}>
            <div className="flex items-center justify-between gap-2 text-[9px] font-black uppercase tracking-[0.14em]">
              <span>{index + 1}. {gate.label}</span>
              <span><span aria-hidden="true">{copy.glyph}</span> {copy.word}</span>
            </div>
            <p className="mt-1 text-[11px] leading-snug text-white/70">{gate.detail}</p>
          </li>
        );
      })}
    </ol>
  );
}

const PATH_COPY: Record<PathCheck, { label: string; glyph: string; tone: ToneKey }> = {
  consistent: { label: 'Role consistent', glyph: '✓', tone: 'emerald' },
  'role-mismatch': { label: 'Role mismatch', glyph: '✕', tone: 'red' },
  unverifiable: { label: 'Role unverifiable', glyph: '?', tone: 'slate' },
};

export function PathBadge({ check, note }: { check: PathCheck; note?: string }) {
  const copy = PATH_COPY[check];
  return (
    <span title={note} className={cn('inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-[9px] font-black uppercase tracking-wider', TONE_CHIP[copy.tone])}>
      <span aria-hidden="true">{copy.glyph}</span>{copy.label}
    </span>
  );
}

export function PathLine({ job }: { job: Pick<OrchestrationJob, 'fromAlgorithm' | 'targetAlgorithm'> }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1 font-mono text-[10.5px]">
      <span className={job.fromAlgorithm ? 'text-white/70' : 'text-white/40'}>{job.fromAlgorithm || 'source not recorded'}</span>
      <ArrowRight className="h-3 w-3 text-white/40" aria-hidden="true" />
      <span className={job.targetAlgorithm ? 'text-cyan-300' : 'text-white/40'}>{job.targetAlgorithm || 'target not recorded'}</span>
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Ranked next actions                                                 */
/* ------------------------------------------------------------------ */

const ACTION_TONE: Record<NextActionSummary['tone'], { tone: ToneKey; glyph: string }> = {
  critical: { tone: 'red', glyph: '!' },
  warning: { tone: 'amber', glyph: '◑' },
  action: { tone: 'cyan', glyph: '→' },
  calm: { tone: 'emerald', glyph: '✓' },
};

export function NextActionsList({
  actions, unavailableReason, limit = 6, onFocus,
}: {
  actions: NextActionSummary[] | null;
  unavailableReason?: string | null;
  limit?: number;
  /** Filter the page's job list to the jobs an action covers. */
  onFocus?: (key: NextActionSummary['key']) => void;
}) {
  if (!actions) return <EmptyRow>{unavailableReason || 'Next actions are not available.'}</EmptyRow>;
  if (!actions.length) return <EmptyRow>No migration jobs are recorded, so nothing is waiting on an operator.</EmptyRow>;
  const shown = actions.slice(0, limit);
  return (
    <ol className="space-y-2">
      {shown.map((action) => {
        const tone = ACTION_TONE[action.tone];
        return (
          <li key={action.key} className={cn('rounded-xl border p-3', TONE_CHIP[tone.tone].replace(/text-\S+/, ''))}>
            <div className="flex items-start gap-2.5">
              <span className={cn('mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full border font-mono text-[10px] font-black', TONE_CHIP[tone.tone])} aria-hidden="true">{action.rank}</span>
              <div className="min-w-0 flex-1">
                <div className={cn('text-[12px] font-black leading-snug', TONE_TEXT[tone.tone])}>
                  <span className="sr-only">{action.tone === 'calm' ? 'No action needed: ' : 'Action: '}</span>
                  {action.title}
                </div>
                <p className="mt-1 text-[11px] leading-relaxed text-white/60">{action.detail}</p>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  {onFocus ? (
                    <button type="button" onClick={() => onFocus(action.key)} className="rounded-md border border-white/12 bg-white/[0.04] px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-white/65 transition hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
                      Show {fmtInt(action.count)} job{action.count === 1 ? '' : 's'}
                    </button>
                  ) : null}
                  <a href={action.href} className="inline-flex items-center gap-1 rounded-md border border-cyan-400/40 bg-cyan-500/10 px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 no-underline hover:bg-cyan-500/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
                    {action.hrefLabel}<ChevronRight className="h-3 w-3" aria-hidden="true" />
                  </a>
                </div>
              </div>
            </div>
          </li>
        );
      })}
      {actions.length > shown.length ? (
        <li className="text-[10px] text-white/45">+ {actions.length - shown.length} more lower-priority group{actions.length - shown.length === 1 ? '' : 's'} in the job list.</li>
      ) : null}
    </ol>
  );
}

/* ------------------------------------------------------------------ */
/* Job table (search · status filter · sort · pagination)              */
/* ------------------------------------------------------------------ */

type SortKey = 'urgency' | 'updated' | 'name' | 'progress';
const PAGE_SIZE = 12;

function durationText(job: OrchestrationJob): string {
  if (!job.startedAt || !job.completedAt) return '—';
  const seconds = (Date.parse(job.completedAt) - Date.parse(job.startedAt)) / 1000;
  if (!Number.isFinite(seconds) || seconds <= 0) return '—';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

export function JobTable({
  jobs, onOpen, variant, caption, emptyText, statusFilter, onStatusFilter, idPrefix,
}: {
  jobs: OrchestrationJob[];
  onOpen: (id: string) => void;
  variant: 'flow' | 'time';
  caption: ReactNode;
  emptyText: ReactNode;
  statusFilter: JobDisplayStatus | 'all';
  onStatusFilter: (status: JobDisplayStatus | 'all') => void;
  idPrefix: string;
}) {
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<SortKey>('urgency');
  const [page, setPage] = useState(0);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = jobs.filter((job) => (statusFilter === 'all' || jobDisplayStatus(job) === statusFilter)
      && (!q || `${job.name} ${job.assetName} ${job.fromAlgorithm || ''} ${job.targetAlgorithm || ''} ${job.executor.assignedAgent || ''}`.toLowerCase().includes(q)));
    if (sort === 'urgency') return list; // the model already ranks most urgent first
    const copy = [...list];
    if (sort === 'updated') copy.sort((a, b) => (Date.parse(b.updatedAt || '') || 0) - (Date.parse(a.updatedAt || '') || 0));
    if (sort === 'name') copy.sort((a, b) => a.name.localeCompare(b.name));
    if (sort === 'progress') copy.sort((a, b) => (b.progress ?? -1) - (a.progress ?? -1));
    return copy;
  }, [jobs, query, statusFilter, sort]);

  useEffect(() => { setPage(0); }, [query, statusFilter, sort, jobs]);
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = filtered.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);
  const present = useMemo(() => new Set(jobs.map((job) => jobDisplayStatus(job))), [jobs]);

  const onKey = (event: ReactKeyboardEvent, id: string) => {
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onOpen(id); }
  };

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-end gap-2">
        <label className="relative min-w-[200px] flex-1">
          <span className="sr-only">Search jobs</span>
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/40" aria-hidden="true" />
          <input
            id={`${idPrefix}-search`}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search job, asset, algorithm, agent…"
            className="w-full rounded-lg border border-white/12 bg-[#0b1424] py-2 pl-8 pr-2.5 text-[11.5px] text-white/85 outline-none placeholder:text-white/35 focus-visible:border-cyan-400/50 focus-visible:ring-2 focus-visible:ring-cyan-300/40"
          />
        </label>
        <label className="text-[9px] font-black uppercase tracking-wider text-white/45">
          Status
          <select
            value={statusFilter}
            onChange={(e) => onStatusFilter(e.target.value as JobDisplayStatus | 'all')}
            className="mt-1 block rounded-lg border border-white/12 bg-[#0b1424] px-2 py-2 text-[11px] normal-case tracking-normal text-white/80 outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/40"
          >
            <option value="all">All statuses</option>
            {JOB_DISPLAY_STATUSES.filter((s) => present.has(s) || s === statusFilter).map((s) => <option key={s} value={s}>{DISPLAY_STATUS_LABEL[s]}</option>)}
          </select>
        </label>
        <label className="text-[9px] font-black uppercase tracking-wider text-white/45">
          Sort
          <select
            value={sort}
            onChange={(e) => setSort(e.target.value as SortKey)}
            className="mt-1 block rounded-lg border border-white/12 bg-[#0b1424] px-2 py-2 text-[11px] normal-case tracking-normal text-white/80 outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/40"
          >
            <option value="urgency">Most urgent first</option>
            <option value="updated">Recently updated</option>
            <option value="name">Name</option>
            <option value="progress">Executor progress</option>
          </select>
        </label>
      </div>
      <p className="mb-2 text-[10px] leading-relaxed text-white/45">{caption} · {fmtInt(filtered.length)} match{filtered.length === 1 ? '' : 'es'}</p>

      {filtered.length === 0 ? <EmptyRow>{emptyText}</EmptyRow> : (
        <div className="overflow-x-auto rounded-xl border border-white/10">
          <table className="w-full min-w-[760px] border-collapse text-left text-[11px]">
            <thead className="bg-white/[0.03] text-[8.5px] font-black uppercase tracking-[0.14em] text-white/45">
              <tr>
                <th scope="col" className="px-3 py-2.5">Job · asset</th>
                <th scope="col" className="px-3 py-2.5">Status</th>
                {variant === 'flow' ? (
                  <>
                    <th scope="col" className="px-3 py-2.5">Gates</th>
                    <th scope="col" className="px-3 py-2.5">Migration path</th>
                    <th scope="col" className="px-3 py-2.5">Executor</th>
                  </>
                ) : (
                  <>
                    <th scope="col" className="px-3 py-2.5">Plan phase</th>
                    <th scope="col" className="px-3 py-2.5">Started</th>
                    <th scope="col" className="px-3 py-2.5">Completed</th>
                    <th scope="col" className="px-3 py-2.5">Duration</th>
                  </>
                )}
                <th scope="col" className="px-3 py-2.5">Updated</th>
              </tr>
            </thead>
            <tbody>
              {current.map((job) => {
                const display = jobDisplayStatus(job);
                return (
                  <tr
                    key={job.id}
                    role="button"
                    tabIndex={0}
                    aria-label={`Open ${job.name}: ${DISPLAY_STATUS_LABEL[display]}`}
                    onClick={() => onOpen(job.id)}
                    onKeyDown={(e) => onKey(e, job.id)}
                    className="cursor-pointer border-t border-white/8 align-top transition hover:bg-white/[0.035] focus-visible:bg-white/[0.05] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-300/60"
                  >
                    <td className="max-w-[260px] px-3 py-2.5">
                      <div className="truncate font-bold text-white/85">{job.name}</div>
                      <div className="truncate text-[10px] text-white/45">{job.assetName} · {job.sourceLabel}</div>
                    </td>
                    <td className="px-3 py-2.5">
                      <StatusBadge status={display} />
                      {job.progress !== null && (display === 'running' || display === 'validating' || display === 'executor-silent') ? (
                        <div className="mt-1 font-mono text-[9.5px] text-white/45">executor reports {job.progress}%</div>
                      ) : null}
                    </td>
                    {variant === 'flow' ? (
                      <>
                        <td className="px-3 py-2.5"><GateStrip gates={job.gates} compact /></td>
                        <td className="px-3 py-2.5">
                          <PathLine job={job} />
                          <div className="mt-1"><PathBadge check={job.pathCheck} note={job.pathNote} /></div>
                        </td>
                        <td className="px-3 py-2.5 text-white/65">
                          {job.executor.assignedAgent ? (
                            <>
                              <div className="truncate">{job.executor.assignedAgent}</div>
                              <div className={cn('text-[10px]', job.executor.online === false ? 'text-red-300' : job.executor.online ? 'text-emerald-300' : 'text-white/45')}>
                                {job.executor.online === null ? '? state unknown' : job.executor.online ? '● checking in' : '! not checking in'}
                              </div>
                            </>
                          ) : <span className="text-white/40">Not claimed</span>}
                        </td>
                      </>
                    ) : (
                      <>
                        <td className="px-3 py-2.5 text-white/65">
                          {job.sequence?.phaseIndex
                            ? <>Phase {job.sequence.phaseIndex}{job.sequence.totalPhases ? ` of ${job.sequence.totalPhases}` : ''}<div className="truncate text-[10px] text-white/45">{job.sequence.phaseName}</div></>
                            : <span className="text-white/40">{job.planId ? 'Not recorded' : 'No plan'}</span>}
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[10.5px] text-white/65" title={fullTimestamp(job.startedAt)}>{job.startedAt ? relativeTime(job.startedAt) : <span className="text-white/40">not started</span>}</td>
                        <td className="px-3 py-2.5 font-mono text-[10.5px] text-white/65" title={fullTimestamp(job.completedAt)}>{job.completedAt ? relativeTime(job.completedAt) : '—'}</td>
                        <td className="px-3 py-2.5 font-mono text-[10.5px] text-white/65">{durationText(job)}</td>
                      </>
                    )}
                    <td className="px-3 py-2.5 font-mono text-[10.5px] text-white/50" title={fullTimestamp(job.updatedAt)}>{relativeTime(job.updatedAt)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {pages > 1 ? (
        <nav aria-label="Job list pages" className="mt-3 flex items-center justify-between gap-2 text-[10px] text-white/50">
          <span>Page {page + 1} of {pages}</span>
          <span className="flex gap-1.5">
            <button type="button" disabled={page === 0} onClick={() => setPage((p) => Math.max(0, p - 1))} className="inline-flex min-h-[34px] items-center gap-1 rounded-lg border border-white/12 bg-white/[0.04] px-3 font-black uppercase tracking-wider disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
              <ChevronLeft className="h-3 w-3" aria-hidden="true" /> Prev
            </button>
            <button type="button" disabled={page >= pages - 1} onClick={() => setPage((p) => Math.min(pages - 1, p + 1))} className="inline-flex min-h-[34px] items-center gap-1 rounded-lg border border-white/12 bg-white/[0.04] px-3 font-black uppercase tracking-wider disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
              Next <ChevronRight className="h-3 w-3" aria-hidden="true" />
            </button>
          </span>
        </nav>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Executor fleet                                                      */
/* ------------------------------------------------------------------ */

export function FleetPanel({ snapshot }: { snapshot: OrchestrationSnapshot }) {
  const e = snapshot.metrics.executors;
  const unreadable = !e.fleetReadable;
  const stat = (label: string, value: number | null, hint: string) => (
    <div className="rounded-lg border border-white/10 bg-white/[0.025] p-3">
      <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/45">{label}</div>
      <div className="mt-1 font-mono text-[20px] font-black text-white/85">{fmtInt(value)}</div>
      <div className="mt-0.5 text-[10px] leading-snug text-white/45">{value === null ? 'Fleet could not be read' : hint}</div>
    </div>
  );
  return (
    <div>
      <SectionHeading title="Executor fleet" icon={Server} meta={unreadable ? 'unreadable' : `${fmtInt(e.enrolled)} enrolled`} />
      {unreadable ? (
        <p className="mb-3 rounded-lg border border-red-400/30 bg-red-500/[0.06] px-3 py-2 text-[11px] text-red-200">
          The agent fleet could not be read. Executor state is unknown — it is not reported as "no agents".
        </p>
      ) : null}
      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        {stat('Online', e.online, 'checked in within the heartbeat window')}
        {stat('Migration-capable', e.migrationCapable, 'Migration Operator with migration authority')}
        {stat('Remediation-capable', e.remediationCapable, 'Patcher or Operator with remediation authority')}
        {stat('Silent executions', snapshot.metrics.staleExecutions, 'running on an agent that stopped checking in')}
      </div>
      {snapshot.agents.length ? (
        <div className="mt-3 overflow-x-auto rounded-xl border border-white/10">
          <table className="w-full min-w-[560px] text-left text-[11px]">
            <thead className="bg-white/[0.03] text-[8.5px] font-black uppercase tracking-[0.14em] text-white/45">
              <tr><th scope="col" className="px-3 py-2">Agent</th><th scope="col" className="px-3 py-2">Role</th><th scope="col" className="px-3 py-2">Heartbeat</th><th scope="col" className="px-3 py-2">Executing jobs</th></tr>
            </thead>
            <tbody>
              {snapshot.agents.map((agent) => (
                <tr key={agent.id} className="border-t border-white/8">
                  <td className="px-3 py-2 font-bold text-white/80">{agent.name}</td>
                  <td className="px-3 py-2 capitalize text-white/60">{agent.role || 'unknown'}</td>
                  <td className={cn('px-3 py-2', agent.online ? 'text-emerald-300' : 'text-amber-300')}>
                    {agent.online ? '● online' : '○ not checking in'} <span className="text-white/45">· {relativeTime(agent.lastSeenAt)}</span>
                  </td>
                  <td className="px-3 py-2 font-mono text-white/70">{fmtInt(agent.assignedJobs)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : !unreadable ? (
        <div className="mt-3"><EmptyRow>No agent is enrolled. Approved work cannot be claimed until a Migration Operator (cutovers) or Patcher (remediation) is installed from the Agent Center.</EmptyRow></div>
      ) : null}
      <a href="/downloads" className="mt-3 inline-flex items-center gap-1 text-[10px] font-black uppercase tracking-wider text-cyan-200 no-underline hover:underline">Agent Center <ChevronRight className="h-3 w-3" aria-hidden="true" /></a>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Command palette + fullscreen                                        */
/* ------------------------------------------------------------------ */

export interface PaletteCommand {
  id: string;
  label: string;
  hint?: string;
  run: () => void;
}

export function useCommandPaletteHotkey(setOpen: (fn: (open: boolean) => boolean) => void) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setOpen((open) => !open);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [setOpen]);
}

export function CommandPalette({ open, onClose, commands }: { open: boolean; onClose: () => void; commands: PaletteCommand[] }) {
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? commands.filter((c) => `${c.label} ${c.hint || ''}`.toLowerCase().includes(q)) : commands;
  }, [query, commands]);

  useEffect(() => {
    if (!open) return;
    setQuery('');
    setActive(0);
    const t = setTimeout(() => inputRef.current?.focus(), 20);
    return () => clearTimeout(t);
  }, [open]);
  useEffect(() => { setActive(0); }, [query]);

  const runAt = useCallback((index: number) => {
    const cmd = filtered[index];
    if (cmd) { onClose(); cmd.run(); }
  }, [filtered, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[80] bg-black/60" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div role="dialog" aria-modal="true" aria-label="Command palette" className="mx-auto mt-[14vh] w-[min(560px,calc(100vw-2rem))] overflow-hidden rounded-xl border border-white/12 bg-[#0b1424] shadow-2xl">
        <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
          <CommandIcon className="h-4 w-4 text-cyan-300" aria-hidden="true" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') { e.preventDefault(); onClose(); }
              if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(filtered.length - 1, a + 1)); }
              if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(0, a - 1)); }
              if (e.key === 'Enter') { e.preventDefault(); runAt(active); }
            }}
            aria-label="Search commands"
            placeholder="Jump to a section, filter, open a module…"
            className="flex-1 bg-transparent text-[13px] text-white outline-none placeholder:text-white/35"
          />
          <kbd className="rounded border border-white/15 px-1.5 py-0.5 text-[9px] font-black uppercase text-white/45">Esc</kbd>
        </div>
        <ul className="max-h-[340px] overflow-y-auto p-2" role="listbox" aria-label="Commands">
          {filtered.length === 0 ? <li className="py-6 text-center text-[11px] text-white/45">No matching commands.</li> : filtered.map((cmd, index) => (
            <li key={cmd.id} role="option" aria-selected={index === active}>
              <button
                type="button"
                onMouseEnter={() => setActive(index)}
                onClick={() => runAt(index)}
                className={cn('flex w-full items-center justify-between gap-3 rounded-lg px-3 py-2 text-left text-[11.5px] transition', index === active ? 'bg-cyan-500/15 text-cyan-200' : 'text-white/70 hover:bg-white/[0.05]')}
              >
                <span>{cmd.label}</span>
                <span className="flex items-center gap-2 text-[9px] font-black uppercase tracking-wider text-white/40">
                  {cmd.hint}{index === active ? <CornerDownLeft className="h-3 w-3 text-cyan-300" aria-hidden="true" /> : null}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function useFullscreen(ref: RefObject<HTMLElement | null>) {
  const [isFullscreen, setIsFullscreen] = useState(false);
  useEffect(() => {
    const handler = () => setIsFullscreen(Boolean(document.fullscreenElement));
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);
  const toggle = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    if (!document.fullscreenElement) void el.requestFullscreen?.().catch(() => undefined);
    else void document.exitFullscreen?.().catch(() => undefined);
  }, [ref]);
  return { isFullscreen, toggle };
}

/** Evidence-source rows for the shared `SourceHealth` strip (a failed read is not an empty table). */
export function sourceRows(data: OrchestrationSnapshot): Array<{ label: string; state: SourceHealthState; detail?: string }> {
  const s = data.sources;
  return [
    { label: 'Migration jobs', state: s.jobs === 'unavailable' ? 'unavailable' : data.jobsTruncated ? 'truncated' : data.metrics.total ? 'ok' : 'empty' },
    { label: 'Plan approvals', state: s.plans },
    { label: 'Plan dates', state: s.schedules ?? 'not-instrumented', detail: s.schedules ? undefined : 'Not published by this server version' },
    { label: 'Validation records', state: s.validations },
    { label: 'Event log', state: s.events },
    { label: 'Agent fleet', state: s.agents },
    { label: 'Asset names', state: s.assets },
  ];
}

/** Small labelled stat used inside hero side panels. */
export function MiniStat({ label, value, hint, tone = 'slate' }: { label: string; value: string; hint?: string; tone?: ToneKey }) {
  return (
    <div className="rounded-lg border border-white/10 bg-white/[0.025] px-3 py-2">
      <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/45">{label}</div>
      <div className={cn('mt-0.5 font-mono text-[16px] font-black', TONE_TEXT[tone])}>{value}</div>
      {hint ? <div className="text-[10px] leading-snug text-white/45">{hint}</div> : null}
    </div>
  );
}
