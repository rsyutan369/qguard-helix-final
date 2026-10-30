'use client';

import { useCallback, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  CalendarRange, Command as CommandIcon, Download, Maximize2, Minimize2, RefreshCw, Sparkles, X,
} from 'lucide-react';
import { askSophia } from '@/lib/sophia-bridge';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { useMigrationOrchestrator } from '@/hooks/use-migration-orchestrator';
import { downloadJsonFile } from '@/hooks/use-live-resource';
import { nextActionKey, type JobDisplayStatus, type NextActionKey } from '@/lib/migration/orchestration-model';
import { Panel } from '../_components/executive/primitives';
import {
  AMBER, CYAN, ConnectionLostBanner, GREEN, HardErrorPanel, HeaderButton, IntelHeader, IntelShell, IntelTabs,
  KpiCard, ModuleBrief, NoEvidenceState, PrimaryButton, RED, SLATE, SkeletonGrid, SourceHealth, SourceNote,
  fmtInt, fmtPct,
} from '../_components/intel/kit';
import { exactCounts } from '../pqc-orchestration/_flow-lib';
import {
  CommandPalette, JobTable, NextActionsList, OrchThemeBridge, sourceRows, useCommandPaletteHotkey, useFullscreen, type PaletteCommand,
} from '../pqc-orchestration/_orch-ui';
import { JobDrawer } from '../pqc-orchestration/_job-drawer';
import { DEFAULT_TIMELINE_FILTERS, buildChronology, buildTimeline, type TimeWindow } from './_timeline-lib';
import { ChronologyPanel, PhasesPanel, ScheduleGantt, ThroughputPanel } from './_timeline-views';

type TabKey = 'chronology' | 'phases' | 'jobs' | 'throughput';

/**
 * Migration Timeline — the TIME view of real migration work.
 *
 * Reads only the orchestration snapshot (migration_jobs, plans, validation
 * logs, events, agents). It replaced a "Migration Operations Center" whose
 * waves, NIST phase gates, Digital Twin, health scores, risk burn-down,
 * dependency graph and timeline cards were derived from scanner percentages
 * and fixed offsets — and whose orchestration panels never showed a job,
 * because the orchestrator's select failed on a non-existent column.
 *
 * Its sibling, PQC Orchestration, is the FLOW view (which gate holds each
 * job); this page answers WHEN: what was recorded, started, finished and
 * verified, and what must happen next.
 */
export default function MigrationTimeline() {
  const { data, state, error, transport, lastVerifiedAt, refresh } = useMigrationOrchestrator();
  const [searchParams, setSearchParams] = useSearchParams();
  const planId = searchParams.get('planId');

  const [tab, setTab] = useState<TabKey>('chronology');
  const [timeWindow, setTimeWindow] = useState<TimeWindow>('all');
  const [statusFilter, setStatusFilter] = useState<JobDisplayStatus | 'all'>('all');
  const [actionFilter, setActionFilter] = useState<NextActionKey | null>(null);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const { isFullscreen, toggle: toggleFullscreen } = useFullscreen(rootRef);
  useCommandPaletteHotkey(setPaletteOpen);

  const answered = Boolean(data.generatedAt);
  const now = Date.now();
  const filters = useMemo(() => ({ ...DEFAULT_TIMELINE_FILTERS, window: timeWindow, status: statusFilter, planId }), [timeWindow, statusFilter, planId]);
  const model = useMemo(() => buildTimeline(data, filters, now), [data, filters]); // eslint-disable-line react-hooks/exhaustive-deps
  const chronology = useMemo(() => buildChronology(data, { planId, search: '' }, now), [data, planId]); // eslint-disable-line react-hooks/exhaustive-deps
  const counts = useMemo(() => exactCounts(data), [data]);
  const planName = planId ? data.plans.find((plan) => plan.id === planId)?.name || `Plan ${planId.slice(0, 8)}` : null;

  const tableJobs = useMemo(() => data.jobs.filter((job) => (!planId || job.planId === planId) && (!actionFilter || nextActionKey(job) === actionFilter)), [data.jobs, planId, actionFilter]);
  const activeAction = actionFilter ? counts.nextActions?.find((action) => action.key === actionFilter) ?? null : null;

  const doRefresh = useCallback(async () => {
    setRefreshing(true);
    try { await refresh({ force: true }); } finally { setRefreshing(false); }
  }, [refresh]);

  const exportModel = useCallback(() => {
    downloadJsonFile('qguard-migration-timeline', {
      exportedAt: new Date().toISOString(),
      page: 'Migration Timeline',
      scope: data.scopeNote,
      filters: { planId, window: timeWindow, status: statusFilter },
      snapshot: data,
    });
  }, [data, planId, timeWindow, statusFilter]);

  const ask = useCallback(() => {
    const m = data.metrics;
    askSophia(
      'Which of my migration jobs are stalled, failed or completed but unverified, and what should happen next?',
      `Migration Timeline: ${m.total} operational jobs, ${m.completed} completed (${m.verified} verified, ${m.completedUnverified} unverified, ${m.completedValidationFailed} validation failed), ${m.phases.failed} failed, ${m.staleExecutions} silent executors, ${data.plans.length} plans, ${m.overduePlans ?? 0} past their recorded scheduled start.`,
    );
  }, [data]);

  const focusAction = useCallback((key: NextActionKey) => {
    setActionFilter(key);
    setStatusFilter('all');
    setTab('jobs');
    document.getElementById('tl-tabs')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, []);

  const clearPlan = useCallback(() => {
    const next = new URLSearchParams(searchParams);
    next.delete('planId');
    setSearchParams(next);
  }, [searchParams, setSearchParams]);

  const commands: PaletteCommand[] = useMemo(() => [
    { id: 'refresh', label: 'Refresh the orchestration snapshot', hint: 'sync', run: () => void doRefresh() },
    { id: 'export', label: 'Export the timeline model (JSON)', hint: 'export', run: exportModel },
    { id: 'fullscreen', label: isFullscreen ? 'Exit full screen' : 'Full screen', hint: 'view', run: toggleFullscreen },
    { id: 'schedule', label: 'Jump to the migration schedule', hint: 'section', run: () => document.getElementById('tl-schedule')?.scrollIntoView({ behavior: 'smooth' }) },
    ...(['chronology', 'phases', 'jobs', 'throughput'] as TabKey[]).map((key) => ({ id: `tab-${key}`, label: `Open the ${key} tab`, hint: 'tab', run: () => { setTab(key); document.getElementById('tl-tabs')?.scrollIntoView({ behavior: 'smooth' }); } })),
    ...(['7d', '30d', '90d', 'all'] as TimeWindow[]).map((w) => ({ id: `window-${w}`, label: `Time window: ${w === 'all' ? 'all recorded' : w}`, hint: 'filter', run: () => setTimeWindow(w) })),
    { id: 'failed', label: 'Show failed jobs', hint: 'filter', run: () => { setStatusFilter('failed'); setTab('jobs'); } },
    { id: 'unverified', label: 'Show completed but unverified jobs', hint: 'filter', run: () => { setStatusFilter('completed-unverified'); setTab('jobs'); } },
    { id: 'live', label: 'Open Live Migration', hint: 'module', run: () => { window.location.href = '/dashboard/live-migration'; } },
    { id: 'planner', label: 'Open Migration Planner', hint: 'module', run: () => { window.location.href = '/dashboard/migration-planner'; } },
    { id: 'orchestration', label: 'Open PQC Orchestration (flow view)', hint: 'module', run: () => { window.location.href = '/dashboard/pqc-orchestration'; } },
    { id: 'agents', label: 'Open Agent Center', hint: 'module', run: () => { window.location.href = '/downloads'; } },
  ], [doRefresh, exportModel, isFullscreen, toggleFullscreen]);

  const m = data.metrics;
  const inScope = m.total - m.phases.cancelled;
  const inFlight = m.phases.executing + m.phases.validating;
  const waiting = m.phases['awaiting-approval'] + m.phases.blocked + m.phases.ready + m.phases.paused;
  const top = counts.nextActions?.[0] ?? null;

  const showSkeleton = state === 'loading' && !answered;
  const showHardError = state === 'error' && !answered;
  const empty = answered && !data.hasData;

  return (
    <IntelShell name="timeline-shell">
      <div ref={rootRef} className="timeline-shell space-y-4">
        <OrchThemeBridge scope="timeline-shell" />
        <WorkflowRail activeStage="execution" />

        <IntelHeader
          title="Migration"
          accent="Timeline"
          subtitle="When your real migration work was recorded, approved, started, finished and verified — and what has to happen next."
          icon={CalendarRange}
          transport={transport}
          lastVerifiedAt={lastVerifiedAt}
          lastUpdated={answered ? data.generatedAt : null}
        >
          <HeaderButton onClick={() => setPaletteOpen(true)} icon={CommandIcon}>⌘K</HeaderButton>
          <button
            type="button"
            onClick={ask}
            className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/45 bg-violet-500/12 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/22 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-violet-300/70"
          >
            <Sparkles className="h-3.5 w-3.5" aria-hidden="true" /> Ask Sophia
          </button>
          <HeaderButton onClick={exportModel} icon={Download} disabled={!answered}>Export</HeaderButton>
          <HeaderButton onClick={toggleFullscreen} icon={isFullscreen ? Minimize2 : Maximize2}>{isFullscreen ? 'Exit' : 'Full screen'}</HeaderButton>
          <PrimaryButton onClick={() => void doRefresh()} icon={RefreshCw} spin={refreshing}>Refresh</PrimaryButton>
        </IntelHeader>

        {answered && transport !== 'stream' ? (
          <ConnectionLostBanner lastGoodAt={data.generatedAt} error={error} onReconnect={() => void doRefresh()} transport={transport} lastVerifiedAt={lastVerifiedAt} />
        ) : null}

        {showHardError ? (
          <HardErrorPanel
            title="Migration Timeline Unavailable"
            message="The orchestration snapshot could not be read. No dates or progress are shown rather than presenting an empty schedule as fact."
            error={error}
            onRetry={() => void doRefresh()}
          />
        ) : null}

        {showSkeleton ? <SkeletonGrid cards={6} panels={2} /> : null}

        {planId && answered ? (
          <div className="flex flex-wrap items-center gap-2 rounded-xl border border-cyan-400/30 bg-cyan-500/[0.06] px-3 py-2 text-[11px] text-white/70">
            <span className="font-black uppercase tracking-wider text-cyan-300">Plan filter</span>
            <span>{planName}{data.plans.some((plan) => plan.id === planId) ? '' : ' — no operational job references this plan'}</span>
            <button type="button" onClick={clearPlan} className="ml-auto inline-flex min-h-[30px] items-center gap-1 rounded-md border border-white/12 px-2 text-[9.5px] font-black uppercase tracking-wider text-white/60 hover:bg-white/[0.06] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
              <X className="h-3 w-3" aria-hidden="true" /> Show all plans
            </button>
          </div>
        ) : null}

        {empty ? (
          <NoEvidenceState
            icon={CalendarRange}
            title="No Migration Work Recorded Yet"
            body={`The timeline places real migration jobs on a time axis. None is recorded for this tenant${m.simulationsExcluded ? ` — ${m.simulationsExcluded} sandbox simulation(s) exist, but simulations never reach an agent and are not shown here` : ''}.`}
            bullets={[
              'Create a migration plan from your scanned assets in the Migration Planner — each selected asset becomes a migration job.',
              'Record an approval decision on the plan. No agent takes work until a named person approves it.',
              'Install a Migration Operator agent from the Agent Center so approved cutovers can be claimed and executed.',
              'Start execution in Live Migration. Each job then appears here when it is started, completed and verified.',
            ]}
            actions={[
              { href: '/dashboard/migration-planner', label: 'Open Migration Planner', primary: true },
              { href: '/downloads', label: 'Agent Center' },
              { href: '/dashboard/live-migration', label: 'Live Migration' },
            ]}
          />
        ) : null}

        {answered && data.hasData ? (
          <>
            <ModuleBrief
              what={<>Every recorded migration plan and job on one time axis — when it was recorded, approved, started and finished, and whether the change was verified.</>}
              why={<>A completed job is not a migrated asset. The time view shows whether work is moving, where it has stalled, and which recorded dates have passed — so the next decision is made on evidence, not on an estimate.</>}
              next={top
                ? { label: top.hrefLabel, href: top.href, detail: <><strong className="text-white/90">{top.title}.</strong> {top.detail}</>, tone: top.tone === 'calm' ? 'calm' : top.tone === 'action' ? 'action' : 'warning' }
                : { label: 'Live Migration', href: '/dashboard/live-migration', detail: counts.reason || 'Open Live Migration to follow the current work.' }}
              scope={<>{data.scopeNote}{data.jobsTruncated ? ' The job list is capped at the 2,000 most recently updated rows.' : ''}</>}
            />

            <section aria-label="Timeline metrics" className="grid grid-cols-2 gap-2.5 lg:grid-cols-3 xl:grid-cols-6">
              <KpiCard label="Completed" value={fmtPct(m.completionPct)} detail={`${fmtInt(m.completed)} of ${fmtInt(inScope)} jobs (cancelled excluded)`} color={CYAN} footnote="executor-reported; not proof of migration" />
              <KpiCard label="Verified" value={fmtPct(m.verifiedPct)} detail={`${fmtInt(m.verified)} with a passing validation record`} color={GREEN} footnote={`of the same ${fmtInt(inScope)} jobs`} />
              <KpiCard label="Unverified completions" value={fmtInt(m.completedUnverified + m.completedValidationFailed)} detail={`${fmtInt(m.completedUnverified)} no passing record · ${fmtInt(m.completedValidationFailed)} validation failed`} color={m.completedUnverified + m.completedValidationFailed > 0 ? AMBER : GREEN} />
              <KpiCard label="In flight" value={fmtInt(inFlight)} detail={`running or validating on an agent · ${fmtInt(m.staleExecutions)} executor silent`} color={m.staleExecutions > 0 ? RED : CYAN} />
              <KpiCard label="Waiting" value={fmtInt(waiting)} detail={`${fmtInt(m.phases['awaiting-approval'])} approval · ${fmtInt(m.phases.blocked)} blocked/held · ${fmtInt(m.phases.ready)} ready · ${fmtInt(m.phases.paused)} paused`} color={waiting > 0 ? AMBER : GREEN} />
              <KpiCard
                label="Recorded schedule"
                value={data.plans.length ? `${fmtInt(model.scheduleRecorded)}/${fmtInt(data.plans.length)}` : '—'}
                detail={data.plans.length ? `plans with a scheduled start · ${fmtInt(m.overduePlans ?? 0)} passed with nothing started` : 'no migration plan recorded'}
                color={(m.overduePlans ?? 0) > 0 ? AMBER : SLATE}
                footnote="no target completion date is recorded by the platform"
              />
            </section>

            <div className="grid grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-[minmax(0,1.7fr)_minmax(0,1fr)]">
              <ScheduleGantt model={model} window={timeWindow} onWindow={setTimeWindow} onOpen={setSelectedJobId} />
              <Panel className="p-4 sm:p-5">
                <h2 className="mb-1 text-[11px] font-black uppercase tracking-[0.18em] text-white/70">What must happen next — and why</h2>
                <p className="mb-3 text-[10.5px] leading-relaxed text-white/50">Ranked by urgency over every operational job. Each job counts once, under the first rule it meets.</p>
                <NextActionsList actions={counts.nextActions} unavailableReason={counts.reason} onFocus={focusAction} />
              </Panel>
            </div>

            <div id="tl-tabs">
              <IntelTabs<TabKey>
                idPrefix="tl"
                active={tab}
                onChange={setTab}
                tabs={[
                  { key: 'chronology', label: 'Chronology' },
                  { key: 'phases', label: 'Plans & phases' },
                  { key: 'jobs', label: 'Jobs', badge: m.phases.failed + m.staleExecutions + m.completedValidationFailed || undefined },
                  { key: 'throughput', label: 'Throughput' },
                ]}
              />
              <div role="tabpanel" id={`tl-panel-${tab}`} aria-labelledby={`tl-tab-${tab}`} className="pt-3">
                <Panel className="p-4 sm:p-5">
                  {tab === 'chronology' ? <ChronologyPanel days={chronology.days} total={chronology.total} capped={chronology.capped} onOpen={setSelectedJobId} /> : null}
                  {tab === 'phases' ? <PhasesPanel snapshot={data} planId={planId} /> : null}
                  {tab === 'throughput' ? <ThroughputPanel snapshot={data} /> : null}
                  {tab === 'jobs' ? (
                    <>
                      {activeAction ? (
                        <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-500/[0.06] px-3 py-2 text-[11px] text-white/70">
                          <span className="font-black text-cyan-300">Showing:</span> {activeAction.title}
                          <button type="button" onClick={() => setActionFilter(null)} className="ml-auto inline-flex items-center gap-1 rounded-md border border-white/12 px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-white/60 hover:bg-white/[0.06]">
                            <X className="h-3 w-3" aria-hidden="true" /> Clear
                          </button>
                        </div>
                      ) : null}
                      <JobTable
                        idPrefix="tl-jobs"
                        jobs={tableJobs}
                        onOpen={setSelectedJobId}
                        variant="time"
                        statusFilter={statusFilter}
                        onStatusFilter={setStatusFilter}
                        caption={<>{fmtInt(tableJobs.length)} listed job{tableJobs.length === 1 ? '' : 's'}{data.jobsListed < m.total ? ` (the ${fmtInt(data.jobsListed)} most urgent of ${fmtInt(m.total)})` : ''}</>}
                        emptyText="No listed job matches these filters."
                      />
                    </>
                  ) : null}
                </Panel>
              </div>
            </div>
          </>
        ) : null}

        {answered ? (
          <SourceHealth
            sources={sourceRows(data)}
            note={<>Only recorded timestamps are placed: job recorded / started / completed, validation passed, plan approval and the plan's recorded scheduled start. {data.jobsTruncated ? 'The job read was capped at 2,000 rows.' : ''}</>}
          />
        ) : null}

        <SourceNote>
          Job, plan, validation and event records come from the PQC orchestration snapshot (migration_jobs, migration_plans, migration_validation_logs, migration_events, scanner_agents) — the same model PQC Orchestration renders. Changes are executed and validated through Live Migration; this page never writes.
        </SourceNote>

        <JobDrawer jobId={selectedJobId} jobs={data.jobs} onClose={() => setSelectedJobId(null)} />
        <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} commands={commands} />
      </div>
    </IntelShell>
  );
}
