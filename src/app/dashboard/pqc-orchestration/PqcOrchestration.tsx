'use client';

import { useCallback, useMemo, useRef, useState } from 'react';
import {
  ArrowRight, Command as CommandIcon, Download, GitBranch, Maximize2, Minimize2, RefreshCw, Sparkles, Workflow, X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { askSophia } from '@/lib/sophia-bridge';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';
import { useMigrationOrchestrator } from '@/hooks/use-migration-orchestrator';
import { downloadJsonFile } from '@/hooks/use-live-resource';
import { nextActionKey, type JobDisplayStatus, type NextActionKey } from '@/lib/migration/orchestration-model';
import { Panel } from '../_components/executive/primitives';
import {
  AMBER, CYAN, ConnectionLostBanner, EmptyRow, GREEN, HardErrorPanel, HeaderButton, IntelHeader, IntelShell, IntelTabs,
  KpiCard, ModuleBrief, NoEvidenceState, PrimaryButton, RED, SectionHeading, SkeletonGrid, SourceHealth, SourceNote,
  fmtInt, fmtPct,
} from '../_components/intel/kit';
import { buildFlowStages, exactCounts, jobsForStage, pathPairs, type FlowStage, type FlowStageId, type FlowTone } from './_flow-lib';
import {
  CommandPalette, FleetPanel, JobTable, NextActionsList, OrchThemeBridge, PathBadge, TONE_CHIP, TONE_TEXT,
  sourceRows, useCommandPaletteHotkey, useFullscreen, type PaletteCommand, type ToneKey,
} from './_orch-ui';
import { JobDrawer } from './_job-drawer';

type TabKey = 'jobs' | 'paths' | 'fleet';

const FLOW_TONE: Record<FlowTone, { tone: ToneKey; glyph: string; word: string }> = {
  good: { tone: 'emerald', glyph: '✓', word: 'healthy' },
  active: { tone: 'cyan', glyph: '▶', word: 'in progress' },
  attention: { tone: 'amber', glyph: '!', word: 'needs attention' },
  idle: { tone: 'slate', glyph: '○', word: 'nothing here' },
  unknown: { tone: 'slate', glyph: '?', word: 'not available' },
};

/**
 * PQC Orchestration — the FLOW view of real migration work.
 *
 * DISCOVER → ASSESS → PLAN → APPROVE → EXECUTE → VALIDATE → MONITOR, each
 * stage counted from evidence: the scanner snapshot for the estate stages and
 * the orchestration snapshot (migration_jobs, plans, validation logs, agents)
 * for the job stages. It replaced a 13-stage pipeline marked complete from
 * scanner percentages, a fixed DAG, a generated CAB record, a template
 * "marketplace", invented policies and a scheduler with a fabricated change
 * freeze — none of which read a migration job.
 *
 * The page is read-only. Approval happens in the Migration Planner; execution,
 * retry and rollback happen in Live Migration, which re-checks approval.
 * Migration Timeline is the TIME view over the same snapshot.
 */
export default function PqcOrchestration() {
  const { data, state, error, transport, lastVerifiedAt, refresh, reconnect } = useMigrationOrchestrator();
  const scanner = useScannerIntelligence();

  const [tab, setTab] = useState<TabKey>('jobs');
  const [stageFilter, setStageFilter] = useState<FlowStageId | null>(null);
  const [statusFilter, setStatusFilter] = useState<JobDisplayStatus | 'all'>('all');
  const [actionFilter, setActionFilter] = useState<NextActionKey | null>(null);
  const [pathFilter, setPathFilter] = useState<string[] | null>(null);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const { isFullscreen, toggle: toggleFullscreen } = useFullscreen(rootRef);
  useCommandPaletteHotkey(setPaletteOpen);

  const answered = Boolean(data.generatedAt);
  const counts = useMemo(() => exactCounts(data), [data]);
  const estate = useMemo(() => ({
    resolved: scanner.resolved,
    error: scanner.error,
    totalAssets: scanner.data.summary.totalAssets,
    vulnerableAssets: scanner.data.summary.vulnerableAssets,
    totalComponents: scanner.data.summary.totalComponents,
    vulnerableComponents: scanner.data.summary.vulnerableComponents,
    pqcReadyComponents: scanner.data.summary.pqcReadyComponents,
    completedScans: scanner.data.summary.completedScans,
  }), [scanner.resolved, scanner.error, scanner.data.summary]);
  const stages = useMemo(() => buildFlowStages(data, estate), [data, estate]);
  const paths = useMemo(() => pathPairs(data.jobs), [data.jobs]);
  const activeStage = stageFilter ? stages.find((s) => s.id === stageFilter) ?? null : null;
  const activeAction = actionFilter ? counts.nextActions?.find((action) => action.key === actionFilter) ?? null : null;

  const tableJobs = useMemo(() => {
    let jobs = activeStage ? jobsForStage(data.jobs, activeStage.filter) : data.jobs;
    if (actionFilter) jobs = jobs.filter((job) => nextActionKey(job) === actionFilter);
    if (pathFilter) {
      const ids = new Set(pathFilter);
      jobs = jobs.filter((job) => ids.has(job.id));
    }
    return jobs;
  }, [data.jobs, activeStage, actionFilter, pathFilter]);

  const doRefresh = useCallback(async () => {
    setRefreshing(true);
    try { await Promise.all([refresh({ force: true }), scanner.refresh()]); } finally { setRefreshing(false); }
  }, [refresh, scanner]);

  const exportModel = useCallback(() => {
    downloadJsonFile('qguard-pqc-orchestration', {
      exportedAt: new Date().toISOString(),
      page: 'PQC Orchestration',
      scope: data.scopeNote,
      lifecycle: stages.map(({ id, label, unit, value, reason, source }) => ({ id, label, unit, value, reason, source })),
      snapshot: data,
    });
  }, [data, stages]);

  const ask = useCallback(() => {
    const m = data.metrics;
    askSophia(
      'Where is my PQC migration work held up, and what is the single most valuable next step?',
      `PQC Orchestration: ${m.total} operational jobs across ${m.assets.total} assets; ${m.awaitingApproval} awaiting approval, ${m.blocked} blocked, ${m.phases.executing} executing, ${m.completedUnverified} completed but unverified, ${m.completedValidationFailed} validation failed, ${m.phases.failed} failed, ${m.staleExecutions} silent executors, ${m.openRoleMismatches ?? 0} open role mismatches. Executors online: ${m.executors.online ?? 'unknown'}.`,
    );
  }, [data]);

  const clearFilters = useCallback(() => {
    setStageFilter(null);
    setActionFilter(null);
    setPathFilter(null);
    setStatusFilter('all');
  }, []);

  const scrollToTabs = () => document.getElementById('orch-tabs')?.scrollIntoView({ behavior: 'smooth', block: 'start' });

  const focusStage = useCallback((stage: FlowStage) => {
    if (!stage.filter) return;
    setStageFilter((current) => (current === stage.id ? null : stage.id));
    setActionFilter(null);
    setPathFilter(null);
    setStatusFilter('all');
    setTab('jobs');
  }, []);

  const focusAction = useCallback((key: NextActionKey) => {
    setActionFilter(key);
    setStageFilter(null);
    setPathFilter(null);
    setStatusFilter('all');
    setTab('jobs');
    scrollToTabs();
  }, []);

  const focusPath = useCallback((jobIds: string[]) => {
    setPathFilter(jobIds);
    setStageFilter(null);
    setActionFilter(null);
    setStatusFilter('all');
    setTab('jobs');
    scrollToTabs();
  }, []);

  const commands: PaletteCommand[] = useMemo(() => [
    { id: 'refresh', label: 'Refresh the orchestration and scanner snapshots', hint: 'sync', run: () => void doRefresh() },
    { id: 'export', label: 'Export the orchestration model (JSON)', hint: 'export', run: exportModel },
    { id: 'fullscreen', label: isFullscreen ? 'Exit full screen' : 'Full screen', hint: 'view', run: toggleFullscreen },
    ...stages.filter((s) => s.filter).map((s) => ({ id: `stage-${s.id}`, label: `Show jobs in ${s.label}`, hint: 'stage', run: () => { focusStage(s); scrollToTabs(); } })),
    { id: 'tab-paths', label: 'Open migration paths (role check)', hint: 'tab', run: () => { setTab('paths'); scrollToTabs(); } },
    { id: 'tab-fleet', label: 'Open the executor fleet', hint: 'tab', run: () => { setTab('fleet'); scrollToTabs(); } },
    { id: 'failed', label: 'Show failed jobs', hint: 'filter', run: () => { clearFilters(); setStatusFilter('failed'); setTab('jobs'); scrollToTabs(); } },
    { id: 'unverified', label: 'Show completed but unverified jobs', hint: 'filter', run: () => { clearFilters(); setStatusFilter('completed-unverified'); setTab('jobs'); scrollToTabs(); } },
    { id: 'clear', label: 'Clear every filter', hint: 'filter', run: clearFilters },
    { id: 'live', label: 'Open Live Migration', hint: 'module', run: () => { window.location.href = '/dashboard/live-migration'; } },
    { id: 'planner', label: 'Open Migration Planner', hint: 'module', run: () => { window.location.href = '/dashboard/migration-planner'; } },
    { id: 'timeline', label: 'Open Migration Timeline (time view)', hint: 'module', run: () => { window.location.href = '/dashboard/migration-timeline'; } },
    { id: 'agents', label: 'Open Agent Center', hint: 'module', run: () => { window.location.href = '/downloads'; } },
  ], [doRefresh, exportModel, isFullscreen, toggleFullscreen, stages, focusStage, clearFilters]);

  const m = data.metrics;
  const d = counts.display;
  const top = counts.nextActions?.[0] ?? null;
  const roleMismatches = m.openRoleMismatches ?? m.pathChecks?.['role-mismatch'] ?? null;
  const onlineExecutors = m.executors.online;
  const filterLabel = activeAction
    ? activeAction.title
    : activeStage
      ? `${activeStage.label} — ${activeStage.unit}`
      : pathFilter
        ? `${fmtInt(pathFilter.length)} job(s) on one migration path`
        : null;

  const showSkeleton = state === 'loading' && !answered;
  const jobsUnavailable = answered && data.sources.jobs === 'unavailable';
  const showHardError = (state === 'error' && !answered) || jobsUnavailable;
  const empty = answered && !jobsUnavailable && !data.hasData;

  return (
    <IntelShell name="orch-shell">
      <div ref={rootRef} className="orch-shell space-y-4">
        <OrchThemeBridge scope="orch-shell" />
        <WorkflowRail activeStage="execution" />

        <IntelHeader
          title="PQC"
          accent="Orchestration"
          subtitle="Which gate holds each piece of real migration work — from discovery through approval, execution, validation and monitoring."
          icon={Workflow}
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
          <ConnectionLostBanner lastGoodAt={data.generatedAt} error={error} onReconnect={reconnect} transport={transport} lastVerifiedAt={lastVerifiedAt} />
        ) : null}

        {showHardError ? (
          <HardErrorPanel
            title="PQC Orchestration Unavailable"
            message="The orchestration snapshot could not be read. No stage counts are shown rather than presenting an empty pipeline as fact."
            error={error}
            onRetry={() => void doRefresh()}
          />
        ) : null}

        {showSkeleton ? <SkeletonGrid cards={6} panels={2} /> : null}

        {empty ? (
          <NoEvidenceState
            icon={Workflow}
            title="No Migration Work to Orchestrate Yet"
            body={`Orchestration follows real migration jobs through approval, an agent and validation. None is recorded for this tenant${m.simulationsExcluded ? ` — ${m.simulationsExcluded} sandbox simulation(s) exist, but simulations never reach an agent and are not counted here` : ''}.`}
            bullets={[
              estate.resolved && !estate.error
                ? `The scanner has inventoried ${fmtInt(estate.totalAssets)} asset(s), ${fmtInt(estate.vulnerableAssets)} with quantum-vulnerable cryptography.`
                : 'Run a scan first so there is an inventory of quantum-vulnerable assets to plan from.',
              'Create a migration plan in the Migration Planner — each selected asset becomes a migration job.',
              'Record an approval decision. No agent takes work until a named person approves it.',
              'Install a Migration Operator agent from the Agent Center, then start execution in Live Migration.',
            ]}
            actions={[
              { href: '/dashboard/migration-planner', label: 'Open Migration Planner', primary: true },
              { href: '/dashboard/scanner', label: 'Scanner' },
              { href: '/downloads', label: 'Agent Center' },
            ]}
          />
        ) : null}

        {answered && !jobsUnavailable && data.hasData ? (
          <>
            <ModuleBrief
              what={<>Your migration lifecycle as a flow. The first two stages count <em>assets</em> from the scanner; the rest count <em>migration jobs</em>, and every job sits in exactly one stage.</>}
              why={<>Work stalls at gates, not in charts: an unapproved plan, a missing agent, a completion nobody verified. Seeing which gate holds each job tells you who has to act — and nothing here is marked done until a validation record says so.</>}
              next={top
                ? { label: top.hrefLabel, href: top.href, detail: <><strong className="text-white/90">{top.title}.</strong> {top.detail}</>, tone: top.tone === 'calm' ? 'calm' : top.tone === 'action' ? 'action' : 'warning' }
                : { label: 'Live Migration', href: '/dashboard/live-migration', detail: counts.reason || 'Open Live Migration to follow the current work.' }}
              scope={<>{data.scopeNote}{data.jobsTruncated ? ' The job list is capped at the 2,000 most recently updated rows; stage counts are computed over every job.' : ''}</>}
            />

            <section aria-label="Orchestration metrics" className="grid grid-cols-2 gap-2.5 lg:grid-cols-3 xl:grid-cols-6">
              <KpiCard label="Operational jobs" value={fmtInt(m.total)} detail={`${fmtInt(m.assets.total)} asset(s) · ${fmtInt(m.simulationsExcluded)} simulation(s) excluded`} color={CYAN} />
              <KpiCard label="Awaiting approval" value={fmtInt(m.awaitingApproval)} detail="no agent takes work until a named person approves" color={m.awaitingApproval > 0 ? AMBER : GREEN} />
              <KpiCard label="Executing" value={fmtInt(m.phases.executing + m.phases.validating)} detail={`${fmtInt(m.staleExecutions)} on a silent executor`} color={m.staleExecutions > 0 ? RED : CYAN} />
              <KpiCard label="Verified" value={fmtPct(m.verifiedPct)} detail={`${fmtInt(m.verified)} of ${fmtInt(m.total - m.phases.cancelled)} jobs have a passing validation`} color={GREEN} footnote={`${fmtInt(m.completedUnverified + m.completedValidationFailed)} completed but not verified`} />
              <KpiCard label="Failed" value={fmtInt(m.phases.failed + m.completedValidationFailed)} detail={`${fmtInt(m.phases.failed)} execution · ${fmtInt(m.completedValidationFailed)} validation · ${fmtInt(m.retryEligible)} retry-eligible`} color={m.phases.failed + m.completedValidationFailed > 0 ? RED : GREEN} />
              <KpiCard
                label="Executors online"
                value={m.executors.fleetReadable ? fmtInt(onlineExecutors) : '—'}
                detail={m.executors.fleetReadable ? `${fmtInt(m.executors.migrationCapable)} migration-capable · ${fmtInt(m.executors.enrolled)} enrolled` : 'agent fleet could not be read'}
                color={!m.executors.fleetReadable ? AMBER : (onlineExecutors ?? 0) > 0 ? GREEN : AMBER}
              />
            </section>

            <Panel className="p-4 sm:p-5">
              <SectionHeading
                title="Migration lifecycle"
                icon={GitBranch}
                meta={counts.basis === 'server' ? 'counted over every operational job' : counts.basis === 'listed' ? 'counted over the complete job list' : 'job stages unavailable'}
                action={filterLabel ? (
                  <button type="button" onClick={clearFilters} className="inline-flex min-h-[30px] items-center gap-1 rounded-md border border-white/12 px-2 text-[9.5px] font-black uppercase tracking-wider text-white/60 hover:bg-white/[0.06] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
                    <X className="h-3 w-3" aria-hidden="true" /> Clear filter
                  </button>
                ) : null}
              />
              <ol className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7">
                {stages.map((stage, index) => {
                  const tone = FLOW_TONE[stage.tone];
                  const selected = stageFilter === stage.id;
                  const body = (
                    <>
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[9px] font-black uppercase tracking-[0.16em] text-white/50">{index + 1}. {stage.label}</span>
                        <span className={cn('inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[8.5px] font-black uppercase tracking-wider', TONE_CHIP[tone.tone])}>
                          <span aria-hidden="true">{tone.glyph}</span>{tone.word}
                        </span>
                      </div>
                      <div className="mt-1 text-[10.5px] text-white/55">{stage.question}</div>
                      <div className={cn('mt-2 font-mono text-[26px] font-black leading-none', stage.value === null ? 'text-white/35' : TONE_TEXT[tone.tone])}>{fmtInt(stage.value)}</div>
                      <div className="mt-1 text-[10px] leading-snug text-white/50">{stage.value === null ? stage.reason : stage.unit}</div>
                      <dl className="mt-2 space-y-0.5 border-t border-white/8 pt-2">
                        {stage.breakdown.map((row) => (
                          <div key={row.label} className="flex items-baseline justify-between gap-2 text-[10px]">
                            <dt className="truncate text-white/45">{row.label}</dt>
                            <dd className={cn('font-mono font-bold', row.tone && row.value ? TONE_TEXT[FLOW_TONE[row.tone].tone] : 'text-white/65')}>{fmtInt(row.value)}</dd>
                          </div>
                        ))}
                      </dl>
                      <div className="mt-2 text-[8.5px] font-black uppercase tracking-wider text-white/35">Source: {stage.source}</div>
                    </>
                  );
                  return (
                    <li key={stage.id} className="relative">
                      {stage.filter ? (
                        <button
                          type="button"
                          onClick={() => focusStage(stage)}
                          aria-pressed={selected}
                          title={stage.explanation}
                          className={cn(
                            'h-full w-full rounded-xl border p-3 text-left transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
                            selected ? 'border-cyan-400/60 bg-cyan-500/[0.09]' : 'border-white/10 bg-white/[0.025] hover:bg-white/[0.05]',
                          )}
                        >
                          {body}
                        </button>
                      ) : (
                        <a href={stage.href} title={stage.explanation} className="block h-full rounded-xl border border-white/10 bg-white/[0.025] p-3 no-underline transition hover:bg-white/[0.05] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
                          {body}
                        </a>
                      )}
                      {index < stages.length - 1 ? (
                        <ArrowRight className="absolute -right-2.5 top-1/2 z-10 hidden h-4 w-4 -translate-y-1/2 text-white/25 xl:block" aria-hidden="true" />
                      ) : null}
                    </li>
                  );
                })}
              </ol>
              {activeStage ? (
                <p className="mt-3 rounded-lg border border-cyan-400/25 bg-cyan-500/[0.05] px-3 py-2 text-[11px] leading-relaxed text-white/65">
                  <strong className="text-cyan-200">{activeStage.label}:</strong> {activeStage.explanation}{' '}
                  <a href={activeStage.href} className="font-black text-cyan-200 no-underline hover:underline">{activeStage.hrefLabel} →</a>
                </p>
              ) : (
                <p className="mt-3 text-[10px] leading-relaxed text-white/40">
                  Select a job stage to filter the job list. Discover and Assess count assets and open the module that owns them.
                </p>
              )}
            </Panel>

            <div className="grid grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
              <Panel className="p-4 sm:p-5">
                <h2 className="mb-1 text-[11px] font-black uppercase tracking-[0.18em] text-white/70">What must happen next — and why</h2>
                <p className="mb-3 text-[10.5px] leading-relaxed text-white/50">Ranked by urgency over every operational job. Each job counts once, under the first rule it meets.</p>
                <NextActionsList actions={counts.nextActions} unavailableReason={counts.reason} onFocus={focusAction} />
              </Panel>
              <Panel className="p-4 sm:p-5">
                <h2 className="mb-1 text-[11px] font-black uppercase tracking-[0.18em] text-white/70">Gate summary</h2>
                <p className="mb-3 text-[10.5px] leading-relaxed text-white/50">The four gates every job passes, in order. A count is jobs held at that gate now.</p>
                <ol className="space-y-2">
                  {[
                    { label: 'Approval', value: d ? d['awaiting-approval'] + d.rejected : null, hint: 'awaiting a decision or rejected', href: '/dashboard/migration-planner', cta: 'Migration Planner' },
                    { label: 'Dispatch', value: d ? d.blocked + d['not-released'] : null, hint: 'refused by the agent poll or held at a later phase', href: '/dashboard/live-migration', cta: 'Live Migration' },
                    { label: 'Executor', value: d ? d.ready : null, hint: 'approved and released, waiting for an agent to claim', href: '/downloads', cta: 'Agent Center' },
                    { label: 'Execution & validation', value: d ? d.running + d.validating + d['executor-silent'] + d.paused + d['completed-unverified'] : null, hint: 'running, paused, or completed without a passing validation', href: '/dashboard/live-migration', cta: 'Live Migration' },
                  ].map((gate, index) => (
                    <li key={gate.label} className="flex items-center gap-3 rounded-lg border border-white/10 bg-white/[0.025] px-3 py-2">
                      <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full border border-white/15 font-mono text-[10px] font-black text-white/60" aria-hidden="true">{index + 1}</span>
                      <div className="min-w-0 flex-1">
                        <div className="text-[11.5px] font-black text-white/80">{gate.label}</div>
                        <div className="text-[10px] text-white/45">{gate.hint}</div>
                      </div>
                      <span className={cn('font-mono text-[18px] font-black', gate.value ? 'text-amber-300' : 'text-white/45')}>{fmtInt(gate.value)}</span>
                      <a href={gate.href} className="hidden text-[9px] font-black uppercase tracking-wider text-cyan-200 no-underline hover:underline sm:inline">{gate.cta} →</a>
                    </li>
                  ))}
                </ol>
                {roleMismatches ? (
                  <p className="mt-3 rounded-lg border border-red-400/30 bg-red-500/[0.06] px-3 py-2 text-[11px] leading-relaxed text-red-200">
                    {fmtInt(roleMismatches)} open job(s) target an algorithm with the wrong role — for example ML-KEM (key establishment) replacing a signature. See Migration paths.
                  </p>
                ) : null}
              </Panel>
            </div>

            <div id="orch-tabs">
              <IntelTabs<TabKey>
                idPrefix="orch"
                active={tab}
                onChange={setTab}
                tabs={[
                  { key: 'jobs', label: 'Jobs', badge: m.phases.failed + m.staleExecutions + m.completedValidationFailed || undefined },
                  { key: 'paths', label: 'Migration paths', badge: roleMismatches || undefined },
                  { key: 'fleet', label: 'Executor fleet' },
                ]}
              />
              <div role="tabpanel" id={`orch-panel-${tab}`} aria-labelledby={`orch-tab-${tab}`} className="pt-3">
                <Panel className="p-4 sm:p-5">
                  {tab === 'jobs' ? (
                    <>
                      {filterLabel ? (
                        <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-500/[0.06] px-3 py-2 text-[11px] text-white/70">
                          <span className="font-black text-cyan-300">Showing:</span> {filterLabel}
                          <button type="button" onClick={clearFilters} className="ml-auto inline-flex items-center gap-1 rounded-md border border-white/12 px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-white/60 hover:bg-white/[0.06]">
                            <X className="h-3 w-3" aria-hidden="true" /> Clear
                          </button>
                        </div>
                      ) : null}
                      <JobTable
                        idPrefix="orch-jobs"
                        jobs={tableJobs}
                        onOpen={setSelectedJobId}
                        variant="flow"
                        statusFilter={statusFilter}
                        onStatusFilter={setStatusFilter}
                        caption={<>{fmtInt(tableJobs.length)} listed job{tableJobs.length === 1 ? '' : 's'}{data.jobsListed < m.total ? ` (the ${fmtInt(data.jobsListed)} most urgent of ${fmtInt(m.total)})` : ''}</>}
                        emptyText="No listed job matches these filters."
                      />
                    </>
                  ) : null}
                  {tab === 'paths' ? (
                    <div>
                      <SectionHeading title="Migration paths" icon={ArrowRight} meta={`${fmtInt(paths.length)} distinct source → target path(s) among listed jobs`} />
                      <p className="mb-3 text-[10.5px] leading-relaxed text-white/50">
                        Each path is checked for cryptographic role: ML-KEM (FIPS 203) establishes keys; ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) sign. A target that plays a different role from what it replaces is a planning defect.
                      </p>
                      {paths.length === 0 ? <EmptyRow>No listed job records a migration path.</EmptyRow> : (
                        <div className="overflow-x-auto rounded-xl border border-white/10">
                          <table className="w-full min-w-[640px] text-left text-[11px]">
                            <thead className="bg-white/[0.03] text-[8.5px] font-black uppercase tracking-[0.14em] text-white/45">
                              <tr>
                                <th scope="col" className="px-3 py-2.5">From</th>
                                <th scope="col" className="px-3 py-2.5">To</th>
                                <th scope="col" className="px-3 py-2.5">Role check</th>
                                <th scope="col" className="px-3 py-2.5">Jobs (open)</th>
                                <th scope="col" className="px-3 py-2.5"><span className="sr-only">Show jobs</span></th>
                              </tr>
                            </thead>
                            <tbody>
                              {paths.map((path) => (
                                <tr key={`${path.from}-${path.to}-${path.check}`} className="border-t border-white/8 align-top">
                                  <td className="px-3 py-2.5 font-mono text-white/70">{path.from}</td>
                                  <td className="px-3 py-2.5 font-mono text-cyan-300">{path.to}</td>
                                  <td className="px-3 py-2.5">
                                    <PathBadge check={path.check} note={path.note} />
                                    <div className="mt-1 max-w-[320px] text-[10px] leading-snug text-white/45">{path.note}</div>
                                  </td>
                                  <td className="px-3 py-2.5 font-mono text-white/70">{fmtInt(path.jobs)} <span className="text-white/45">({fmtInt(path.openJobs)})</span></td>
                                  <td className="px-3 py-2.5 text-right">
                                    <button type="button" onClick={() => focusPath(path.jobIds)} className="rounded-md border border-white/12 bg-white/[0.04] px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-white/65 hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
                                      Show jobs
                                    </button>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  ) : null}
                  {tab === 'fleet' ? <FleetPanel snapshot={data} /> : null}
                </Panel>
              </div>
            </div>
          </>
        ) : null}

        {answered ? (
          <SourceHealth
            sources={[
              ...sourceRows(data),
              { label: 'Scanner estate', state: scanner.error ? 'unavailable' : scanner.resolved ? (estate.totalAssets ? 'ok' : 'empty') : 'not-instrumented', detail: scanner.error || undefined },
            ]}
            note={<>Discover and Assess count assets from the scanner; every other stage counts operational migration jobs. Sandbox simulations are excluded.</>}
          />
        ) : null}

        <SourceNote>
          Job, plan, validation, event and agent records come from the PQC orchestration snapshot (migration_jobs, migration_plans, migration_validation_logs, migration_events, scanner_agents) — the same model Migration Timeline renders. This page never writes: approve in the Migration Planner, execute, retry and roll back in Live Migration.
        </SourceNote>

        <JobDrawer jobId={selectedJobId} jobs={data.jobs} onClose={() => setSelectedJobId(null)} />
        <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} commands={commands} />
      </div>
    </IntelShell>
  );
}
