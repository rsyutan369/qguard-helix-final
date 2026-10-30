'use client';

/**
 * Algorithm-transition matrix and configuration-change log.
 *
 * Presentational only: lanes, status counts and recorded changes are computed
 * by `buildCryptoAgilityIntelligence`. A lane groups every algorithm by the
 * cryptographic JOB it does, because the approved target depends on the role —
 * ML-KEM (FIPS 203) establishes keys, ML-DSA (FIPS 204) / SLH-DSA (FIPS 205)
 * sign — and a status strip that sums to the replaceability matrix.
 */
import { ArrowRight, History, Repeat } from 'lucide-react';
import { cn } from '@/lib/utils';
import type {
  AlgorithmStatus, AlgorithmStatusSummary, ChangeTracking, ConfigurationChange, TransitionLane,
} from '@/lib/crypto-agility/agility-intelligence';
import { ALGORITHM_STATUS_LABEL, EVIDENCE_UNAVAILABLE } from '@/lib/crypto-agility/agility-intelligence';
import { ALGORITHM_STATUS_GLYPH, ALGORITHM_STATUS_TONE, Chip, SectionCard } from './_agility-sections';
import { absoluteTime, numberFmt, relativeTime } from './_agility-lib';

const STATUS_BAR: Record<AlgorithmStatus, string> = {
  unsupported: 'bg-red-400/85',
  deprecated: 'bg-amber-400/85',
  configured: 'bg-cyan-400/70',
  approved: 'bg-emerald-400/85',
  detected: 'bg-slate-400/60',
  unknown: 'bg-slate-500/40',
};

const STATUS_ORDER: AlgorithmStatus[] = ['unsupported', 'deprecated', 'detected', 'unknown', 'configured', 'approved'];

export function AlgorithmTransitions({
  lanes, statuses, excludedFindingTitles, onFilterAlgorithmStatus,
}: {
  lanes: TransitionLane[];
  statuses: AlgorithmStatusSummary[];
  excludedFindingTitles: number;
  onFilterAlgorithmStatus?: (status: AlgorithmStatus) => void;
}) {
  const totalAlgorithms = statuses.reduce((sum, s) => sum + s.algorithms, 0);
  const needsTransition = statuses.filter((s) => s.status === 'unsupported' || s.status === 'deprecated').reduce((sum, s) => sum + s.algorithms, 0);
  return (
    <SectionCard
      id="transitions"
      title="Algorithm Transition Matrix"
      icon={Repeat}
      right={<Chip tone={needsTransition ? 'warning' : totalAlgorithms ? 'good' : 'neutral'}>{needsTransition ? `${needsTransition} need a transition` : totalAlgorithms ? 'No transition required' : 'No algorithms'}</Chip>}
    >
      <p className="mb-3 text-[10.5px] leading-relaxed text-white/50">
        Every distinct algorithm carries exactly one status. Approved means on the approved list <em>and</em> observed in operation (scan, served certificate or runtime);
        an approved algorithm evidenced only in code or configuration is <strong className="text-white/70">Configured</strong>. No status here makes an asset PQC-ready.
      </p>

      <dl className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6">
        {STATUS_ORDER.map((status) => {
          const row = statuses.find((s) => s.status === status);
          const count = row?.algorithms ?? 0;
          const body = (
            <>
              <dt className="flex items-center gap-1.5 text-[9px] font-black uppercase tracking-[0.14em] text-white/50">
                <span aria-hidden="true">{ALGORITHM_STATUS_GLYPH[status]}</span>{ALGORITHM_STATUS_LABEL[status]}
              </dt>
              <dd className="mt-1 font-mono text-[20px] font-black text-white/85">{numberFmt(count)}</dd>
              <dd className="text-[9.5px] text-white/40">{numberFmt(row?.instances ?? 0)} instance(s)</dd>
            </>
          );
          return onFilterAlgorithmStatus && count ? (
            <button key={status} type="button" onClick={() => onFilterAlgorithmStatus(status)} title={row?.definition} className="rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-left transition hover:bg-white/[0.05] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
              {body}
            </button>
          ) : (
            <div key={status} title={row?.definition} className="rounded-lg border border-white/10 bg-black/20 px-3 py-2">{body}</div>
          );
        })}
      </dl>
      {totalAlgorithms ? (
        <div className="mt-2 flex h-2 w-full overflow-hidden rounded-full bg-white/[0.06]" role="img" aria-label={statuses.map((s) => `${s.label}: ${s.algorithms}`).join(', ')}>
          {STATUS_ORDER.map((status) => {
            const count = statuses.find((s) => s.status === status)?.algorithms ?? 0;
            return count ? <div key={status} className={STATUS_BAR[status]} style={{ width: `${(count / totalAlgorithms) * 100}%` }} /> : null;
          })}
        </div>
      ) : null}

      {lanes.length === 0 ? (
        <p className="mt-4 rounded-lg border border-dashed border-white/12 px-4 py-6 text-center text-[11px] text-white/45">
          No cryptographic primitive has been resolved from tenant evidence yet. Run a discovery scan to populate the matrix.
        </p>
      ) : (
        <ol className="mt-4 space-y-2">
          {lanes.map((lane) => {
            const statusesInLane = STATUS_ORDER.filter((s) => lane.byStatus[s] > 0);
            return (
              <li key={lane.role} className={cn('rounded-xl border p-3', lane.needsTransition ? 'border-amber-400/25 bg-amber-500/[0.03]' : 'border-white/10 bg-white/[0.02]')}>
                <div className="grid gap-2 md:grid-cols-[minmax(0,1.1fr)_auto_minmax(0,1fr)] md:items-center">
                  <div className="min-w-0">
                    <div className="text-[11.5px] font-black text-white/85">{lane.label}</div>
                    <div className="text-[10px] text-white/45">
                      {numberFmt(lane.algorithms)} algorithm(s) · {numberFmt(lane.instances)} instance(s) · {numberFmt(lane.assets)} asset(s)
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {statusesInLane.map((status) => (
                        <Chip key={status} tone={ALGORITHM_STATUS_TONE[status]} glyph={ALGORITHM_STATUS_GLYPH[status]}>
                          {numberFmt(lane.byStatus[status])} {ALGORITHM_STATUS_LABEL[status]}
                        </Chip>
                      ))}
                    </div>
                  </div>
                  <ArrowRight className="hidden h-4 w-4 text-white/30 md:block" aria-hidden="true" />
                  <div className="min-w-0">
                    <div className="text-[8.5px] font-black uppercase tracking-[0.14em] text-white/40">Approved target</div>
                    <div className="font-mono text-[11px] font-bold text-cyan-300">{lane.target ?? 'Determine the role first'}</div>
                    {lane.standard ? <div className="text-[9.5px] text-white/40">{lane.standard}</div> : null}
                  </div>
                </div>
                {lane.needsTransition ? (
                  <p className="mt-2 text-[10px] leading-relaxed text-white/55">
                    {numberFmt(lane.needsTransition)} instance(s) are deprecated or prohibited
                    {lane.blockedAssets ? <> — <strong className="text-red-300">{numberFmt(lane.blockedAssets)} asset(s)</strong> running them are Rigid or Blocked, so the swap needs code, architecture or provider work first.</> : '.'}
                  </p>
                ) : null}
              </li>
            );
          })}
        </ol>
      )}
      {excludedFindingTitles ? (
        <p className="mt-3 text-[10px] text-white/40">{numberFmt(excludedFindingTitles)} recorded value(s) were scanner finding titles rather than algorithms and are excluded.</p>
      ) : null}
    </SectionCard>
  );
}

const CHANGE_COPY: Record<ConfigurationChange['kind'], { label: string; tone: 'good' | 'warning' | 'critical' | 'info' | 'neutral'; glyph: string }> = {
  'migration-completed': { label: 'Migration completed', tone: 'info', glyph: '◑' },
  'migration-failed': { label: 'Migration failed', tone: 'critical', glyph: '✕' },
  'migration-in-progress': { label: 'In progress', tone: 'info', glyph: '▶' },
  'config-event': { label: 'Configuration event', tone: 'neutral', glyph: '•' },
  'runtime-observation': { label: 'Runtime observation', tone: 'neutral', glyph: '•' },
};

export function ChangeTrackingPanel({ tracking }: { tracking: ChangeTracking }) {
  return (
    <SectionCard
      id="change-tracking"
      title="Recorded Cryptographic Changes"
      icon={History}
      right={<Chip tone="neutral">{tracking.total ? `${numberFmt(tracking.total)} recorded · last ${relativeTime(tracking.lastChangeAt)}` : 'None recorded'}</Chip>}
    >
      <p className="mb-3 text-[10.5px] leading-relaxed text-white/50">{tracking.note}</p>
      {tracking.changes.length === 0 ? (
        <p className="rounded-lg border border-dashed border-white/12 px-4 py-6 text-center text-[11px] text-white/45">
          Changes appear here when Live Migration executes a job or a cryptographic configuration event is logged. Nothing is inferred.
        </p>
      ) : (
        <ol className="space-y-1.5">
          {tracking.changes.slice(0, 12).map((change) => {
            const copy = CHANGE_COPY[change.kind];
            const verified = change.kind === 'migration-completed' ? change.validated : null;
            return (
              <li key={change.id} className="grid grid-cols-[minmax(0,1fr)_auto] gap-3 rounded-lg border border-white/8 bg-black/20 px-3 py-2">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Chip tone={verified === false ? 'warning' : verified ? 'good' : copy.tone} glyph={verified === false ? '◑' : verified ? '✓' : copy.glyph}>
                      {verified === true ? 'Completed · verified' : verified === false ? 'Completed · not verified' : copy.label}
                    </Chip>
                    <a href={change.route} className="truncate text-[11px] font-bold text-white/80 no-underline hover:underline">{change.asset}</a>
                  </div>
                  <div className="mt-0.5 text-[10px] leading-snug text-white/50">{change.detail}</div>
                  <div className="mt-0.5 text-[9px] uppercase tracking-wider text-white/30">{change.source}{change.algorithm && change.algorithm !== EVIDENCE_UNAVAILABLE ? ` · ${change.algorithm}` : ''}</div>
                </div>
                <div className="text-right font-mono text-[10px] text-white/45" title={absoluteTime(change.at)}>{relativeTime(change.at)}</div>
              </li>
            );
          })}
        </ol>
      )}
      {tracking.sources.length ? <p className="mt-2 text-[9.5px] text-white/35">Sources: {tracking.sources.join(' · ')}</p> : null}
    </SectionCard>
  );
}
