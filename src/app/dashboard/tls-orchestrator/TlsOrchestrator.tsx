'use client';

import { useCallback, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  CheckCircle2,
  ClipboardList,
  GitCompare,
  ListChecks,
  Network,
  Play,
  Radar,
  ShieldCheck,
  Workflow,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import {
  useTlsOrchestrator,
  useTlsOrchestratorActions,
  useTlsPkiDetail,
  usePagedResource,
  type EndpointDetail,
  type EndpointSummary,
} from '@/hooks/use-tls-pki';
import type { OrchestrationItem, OrchestrationStatus } from '@/lib/tls-pki/types';
import { PostureStrip } from '../_components/observability/TlsPostureStrip';
import { EndpointInvestigation } from '../tls-telemetry/TlsTelemetry';
import {
  ConnectionLost,
  Drawer,
  ErrorState,
  EvidenceList,
  FilterSelect,
  FreshnessBar,
  Kpi,
  ModuleNav,
  NoDataState,
  PageHeader,
  Pager,
  Panel,
  PanelEmpty,
  Pill,
  ProvenanceFooter,
  SearchInput,
  SectionLabel,
  SeverityBadge,
  SHELL_CLASS,
  SHELL_CSS,
  Skeleton,
  TableShell,
  Td,
  Th,
  RISK_TONE,
  absoluteTime,
  fmtNumber,
  fmtPercent,
  relativeTime,
  type Tone,
} from '../_components/observability/primitives';

/**
 * TLS Orchestrator — the operational control plane.
 *
 * It does not discover anything of its own: it consumes the findings the other
 * three modules produced and turns each into a concrete change with a target,
 * a standard and a real execution path.
 *
 * The no-fake-functionality rule (brief section 22) is enforced structurally.
 * Each work item carries an `availableActions` list computed on the SERVER from
 * what the backend can genuinely do for that item, and this page renders only
 * those buttons:
 *
 *   queue / unqueue  POST or DELETE on the Migration Planner's own queue.
 *                    The planner and this page therefore share one queue; there
 *                    is no second writer that could disagree.
 *   plan             POST /api/v1/migration-planner/plans — submits a real plan
 *                    for approval.
 *   rescan           Navigates to the Scanner with the target prefilled. Scans
 *                    require explicit per-target authorisation, so this page
 *                    hands over rather than starting one silently.
 *   evidence         Opens the underlying rows.
 *
 * There is deliberately no "apply configuration" button: the platform does not
 * push TLS configuration to customer endpoints, and a button that pretended to
 * would be the worst possible lie on a security console.
 */

const PAGE_SIZE = 25;

const STATUS_META: Record<OrchestrationStatus, { label: string; tone: Tone }> = {
  'not-started': { label: 'Not started', tone: 'neutral' },
  planned: { label: 'Planned', tone: 'info' },
  ready: { label: 'Ready', tone: 'info' },
  'in-progress': { label: 'In progress', tone: 'ai' },
  validating: { label: 'Validating', tone: 'ai' },
  completed: { label: 'Completed', tone: 'good' },
  failed: { label: 'Failed', tone: 'critical' },
  'rolled-back': { label: 'Rolled back', tone: 'warning' },
};

const ACTION_LABEL: Record<OrchestrationItem['action'], string> = {
  'tls-upgrade': 'TLS upgrade',
  'certificate-replacement': 'Certificate replacement',
  'cipher-update': 'Cipher update',
  'key-exchange-migration': 'Key exchange migration',
  'hybrid-tls-enablement': 'Hybrid TLS enablement',
  'pqc-migration': 'PQC migration',
  'configuration-remediation': 'Configuration remediation',
};

export default function TlsOrchestrator() {
  const { data, state, error, live, lastSyncedAt, refresh, reconnect } = useTlsOrchestrator();
  const { loadEndpoint, loading: detailLoading } = useTlsPkiDetail('orchestrator');
  const { queueAsset, unqueueAsset, prioritizeQueue, submitPlan, actionState, actionError, pendingId, resetAction } =
    useTlsOrchestratorActions(() => void refresh(true));

  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const [action, setAction] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<OrchestrationItem | null>(null);
  const [detail, setDetail] = useState<EndpointDetail | null>(null);

  const revision = useMemo(() => Date.parse(data?.generatedAt || '') || 0, [data?.generatedAt]);
  const query = useMemo(
    () => ({ search, status, action, severity, limit: PAGE_SIZE, offset }),
    [search, status, action, severity, offset],
  );
  const { rows: items, total: itemTotal, loading: tableLoading } = usePagedResource<OrchestrationItem>(
    'orchestrator',
    '/queue',
    'items',
    query,
    revision,
  );

  const endpointById = useMemo(() => {
    const map = new Map<string, EndpointSummary>();
    for (const endpoint of data?.endpointIndex ?? []) map.set(endpoint.id, endpoint);
    return map;
  }, [data?.endpointIndex]);

  const openEndpoint = useCallback(
    async (id: string) => {
      const result = await loadEndpoint(id);
      if (result) {
        setSelected(null);
        setDetail(result);
      }
    },
    [loadEndpoint],
  );

  const showSkeleton = state === 'loading' && !data;
  const showHardError = state === 'error' && !data;
  const connectionLost = Boolean(data && !live && state !== 'loading');

  if (showSkeleton) {
    return (
      <div className={SHELL_CLASS}>
        <style>{SHELL_CSS}</style>
        <Skeleton />
      </div>
    );
  }

  if (showHardError) {
    return (
      <div className={SHELL_CLASS}>
        <style>{SHELL_CSS}</style>
        <ErrorState message={error || 'The TLS orchestrator service did not respond.'} onRetry={reconnect} />
      </div>
    );
  }

  const orchestration = data?.orchestration;

  return (
    <div className={SHELL_CLASS}>
      <style>{SHELL_CSS}</style>
      <WorkflowRail activeStage="remediation" />

      <PageHeader
        icon={Network}
        title="TLS"
        accent="Orchestrator"
        subtitle="The control plane for transport remediation: every item below is a concrete change derived from measured evidence, with a target algorithm, a standard, and a real execution path through the Migration Planner."
        right={
          <FreshnessBar
            live={live}
            state={state}
            generatedAt={data?.generatedAt ?? null}
            latestEvidenceAt={data?.latestEvidenceAt ?? null}
            telemetry={data?.telemetry ?? null}
            onRefresh={() => void refresh(true)}
            refreshing={state === 'loading'}
          />
        }
      />

      <ModuleNav />

      {connectionLost ? <ConnectionLost onReconnect={reconnect} lastSyncedAt={lastSyncedAt} /> : null}
      {error && data ? (
        <p className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-[11px] text-red-200/85">{error}</p>
      ) : null}
      {actionError ? (
        <p className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-[11px] text-red-200/85">
          {actionError}{' '}
          <button type="button" onClick={resetAction} className="underline">
            dismiss
          </button>
        </p>
      ) : null}

      {data && !data.hasData ? (
        <NoDataState
          title="Nothing to orchestrate yet"
          body="The orchestrator consumes findings from TLS Telemetry, PKI Visibility and Protocol Analytics. Until those modules have measured evidence, there is no change to plan."
          telemetry={data.telemetry}
        />
      ) : null}

      {data && orchestration ? (
        <>
          <PostureStrip posture={data.posture} totals={{ endpoints: data.totals.endpoints, certificates: data.totals.certificates }} />

          {/* ---- Headline ------------------------------------------- */}
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Kpi
              label="Remediation items"
              value={fmtNumber(data.totals.orchestrationItems)}
              detail={`Across ${fmtNumber(data.posture.remediationRequiredEndpoints)} endpoint(s) requiring change`}
              tone={data.totals.orchestrationItems ? 'warning' : 'good'}
              hint="One item per required change per endpoint. An endpoint needing both a protocol upgrade and a certificate replacement produces two items, because they are two separate operations with different owners."
            />
            <Kpi
              label="Queued for migration"
              value={fmtNumber(orchestration.queueDepth)}
              detail="Shared with the Migration Planner queue"
              tone={orchestration.queueDepth ? 'info' : 'neutral'}
              hint="This is the Migration Planner's own queue, read and written through its API. The two pages cannot hold different queues."
              href="/dashboard/migration-planner"
            />
            <Kpi
              label="Active migration jobs"
              value={fmtNumber(orchestration.activeJobs.filter((job) => /running|in_progress|validating|queued|pending/i.test(job.status)).length)}
              detail={`${fmtNumber(orchestration.activeJobs.length)} job(s) touch TLS/PKI assets`}
              tone={orchestration.activeJobs.length ? 'ai' : 'neutral'}
              hint="Real rows from migration_jobs, filtered to assets that carry TLS or PKI evidence."
              href="/dashboard/live_migration_ops"
            />
            <Kpi
              label="Validated changes"
              value={fmtNumber(orchestration.validation.validated)}
              detail={
                orchestration.validation.failed
                  ? `${fmtNumber(orchestration.validation.failed)} failed · ${fmtNumber(orchestration.validation.pending)} pending`
                  : `${fmtNumber(orchestration.validation.pending)} pending validation`
              }
              tone={orchestration.validation.failed ? 'critical' : orchestration.validation.validated ? 'good' : 'neutral'}
              hint="Validation records attached to migration jobs on these assets. An unvalidated change is never shown as complete."
            />
          </div>

          {/* ---- Status board --------------------------------------- */}
          <Panel>
            <SectionLabel
              icon={Workflow}
              hint="Lifecycle position of every remediation item, derived from real migration jobs and the shared queue — not from a wizard step counter."
            >
              Remediation status
            </SectionLabel>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 xl:grid-cols-8">
              {(Object.keys(STATUS_META) as OrchestrationStatus[]).map((key) => {
                const meta = STATUS_META[key];
                const count = orchestration.statusCounts[key] ?? 0;
                const active = status === key;
                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => {
                      setStatus(active ? 'all' : key);
                      setOffset(0);
                    }}
                    aria-pressed={active}
                    className={cn(
                      'rounded-lg border p-3 text-left transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
                      active ? 'border-cyan-400/50 bg-cyan-500/10' : 'border-white/10 bg-black/25 hover:border-white/20',
                    )}
                  >
                    <div className="text-[9px] font-black uppercase tracking-wider text-white/40">{meta.label}</div>
                    <div className={cn('mt-1 text-[20px] font-black leading-none', count ? '' : 'text-white/30')}>{fmtNumber(count)}</div>
                  </button>
                );
              })}
            </div>
          </Panel>

          {/* ---- Migration queue ------------------------------------ */}
          <Panel>
            <SectionLabel
              icon={ListChecks}
              meta={`${fmtNumber(itemTotal)} item(s)`}
              hint="Ordered by priority: severity, internet exposure, endpoint risk and the asset's own priority score from the Migration Planner."
            >
              Migration queue
            </SectionLabel>

            <div className="mb-3 flex flex-wrap items-center gap-2">
              <SearchInput
                value={search}
                onChange={(value) => {
                  setSearch(value);
                  setOffset(0);
                }}
                placeholder="Search asset, host or change"
              />
              <FilterSelect
                label="Status"
                value={status}
                onChange={(value) => {
                  setStatus(value);
                  setOffset(0);
                }}
                options={[
                  { value: 'all', label: 'All' },
                  ...(Object.keys(STATUS_META) as OrchestrationStatus[]).map((key) => ({ value: key, label: STATUS_META[key].label })),
                ]}
              />
              <FilterSelect
                label="Action"
                value={action}
                onChange={(value) => {
                  setAction(value);
                  setOffset(0);
                }}
                options={[
                  { value: 'all', label: 'All' },
                  ...(Object.keys(ACTION_LABEL) as Array<OrchestrationItem['action']>).map((key) => ({ value: key, label: ACTION_LABEL[key] })),
                ]}
              />
              <FilterSelect
                label="Severity"
                value={severity}
                onChange={(value) => {
                  setSeverity(value);
                  setOffset(0);
                }}
                options={[
                  { value: 'all', label: 'All' },
                  { value: 'critical', label: 'Critical' },
                  { value: 'high', label: 'High' },
                  { value: 'medium', label: 'Medium' },
                  { value: 'low', label: 'Low' },
                ]}
              />
              <button
                type="button"
                onClick={() => void prioritizeQueue()}
                disabled={actionState === 'busy' || orchestration.queueDepth === 0}
                title="Reorders the shared Migration Planner queue by the platform's own priority score."
                className="ml-auto inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[9.5px] font-black uppercase tracking-wider text-white/70 transition hover:bg-white/[0.08] disabled:cursor-not-allowed disabled:opacity-35"
              >
                <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" /> Apply recommended order
              </button>
              <button
                type="button"
                onClick={() => void submitPlan(`TLS/PKI remediation — ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}`)}
                disabled={actionState === 'busy' || orchestration.queueDepth === 0}
                title="Submits a real migration plan for approval through the Migration Planner API."
                className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/40 bg-cyan-500/15 px-3 py-2 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-35"
              >
                <ClipboardList className="h-3.5 w-3.5" aria-hidden="true" /> Submit plan for approval
              </button>
            </div>

            {items.length === 0 ? (
              <PanelEmpty>
                {tableLoading
                  ? 'Loading remediation items…'
                  : data.totals.orchestrationItems === 0
                    ? 'No endpoint currently requires a transport change based on the evidence collected. Coverage matters here — see the posture strip above.'
                    : 'No item matches these filters.'}
              </PanelEmpty>
            ) : (
              <TableShell minWidth={1180}>
                <thead>
                  <tr>
                    <Th align="right">#</Th>
                    <Th>Asset / endpoint</Th>
                    <Th>Required change</Th>
                    <Th>Current</Th>
                    <Th>Target</Th>
                    <Th>Status</Th>
                    <Th align="center">Severity</Th>
                    <Th align="right">Effort</Th>
                    <Th align="right">Actions</Th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item, index) => (
                    <tr key={item.id} className="transition hover:bg-white/[0.04]">
                      <Td align="right">
                        <span className="font-mono text-[10px] text-white/30">{offset + index + 1}</span>
                      </Td>
                      <Td>
                        <button
                          type="button"
                          onClick={() => setSelected(item)}
                          className="text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
                        >
                          <span className="block max-w-[190px] truncate font-semibold text-white">{item.assetName}</span>
                          <span className="block max-w-[190px] truncate font-mono text-[9.5px] text-white/35">
                            {item.host} · {item.environment}
                            {item.internetFacing ? ' · internet-facing' : ''}
                          </span>
                        </button>
                      </Td>
                      <Td>
                        <span className="block max-w-[190px] truncate font-semibold text-white/85" title={item.changeSummary}>
                          {item.actionLabel}
                        </span>
                        <span className="block font-mono text-[9px] text-white/30">{item.standard}</span>
                      </Td>
                      <Td>
                        <span className="block max-w-[150px] truncate font-mono text-[10px] text-amber-200/80" title={item.currentState}>
                          {item.currentState}
                        </span>
                      </Td>
                      <Td>
                        <span className="block max-w-[170px] truncate font-mono text-[10px] text-emerald-200/80" title={item.targetState}>
                          {item.targetState}
                        </span>
                      </Td>
                      <Td>
                        <Pill tone={STATUS_META[item.status].tone}>{STATUS_META[item.status].label}</Pill>
                        {item.progressPct > 0 && item.progressPct < 100 ? (
                          <span className="mt-1 block font-mono text-[9px] text-white/35">{fmtPercent(item.progressPct)}</span>
                        ) : null}
                      </Td>
                      <Td align="center">
                        <SeverityBadge severity={item.severity} />
                      </Td>
                      <Td align="right">
                        <span className="font-mono text-[10px] text-white/50">
                          {item.estimatedEffortHours ? `${fmtNumber(item.estimatedEffortHours)}h` : '—'}
                        </span>
                      </Td>
                      <Td align="right">
                        <ItemActions
                          item={item}
                          busy={actionState === 'busy' && pendingId === item.assetId}
                          onQueue={() => item.assetId && void queueAsset(item.assetId)}
                          onUnqueue={() => item.assetId && void unqueueAsset(item.assetId)}
                          onEvidence={() => setSelected(item)}
                        />
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </TableShell>
            )}
            <Pager offset={offset} limit={PAGE_SIZE} total={itemTotal} onChange={setOffset} />
          </Panel>

          {/* ---- Jobs + plans --------------------------------------- */}
          <div className="grid gap-3 xl:grid-cols-2">
            <Panel>
              <SectionLabel icon={Play} href="/dashboard/live_migration_ops" hint="Live rows from migration_jobs for assets carrying TLS or PKI evidence.">
                Execution — migration jobs
              </SectionLabel>
              {orchestration.activeJobs.length === 0 ? (
                <PanelEmpty>No migration job has been created for a TLS or PKI asset yet.</PanelEmpty>
              ) : (
                <TableShell minWidth={560}>
                  <thead>
                    <tr>
                      <Th>Asset</Th>
                      <Th>Type</Th>
                      <Th>Target</Th>
                      <Th>Status</Th>
                      <Th align="right">Progress</Th>
                      <Th align="right">Updated</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {orchestration.activeJobs.slice(0, 10).map((job) => (
                      <tr key={job.id}>
                        <Td>
                          <span className="block max-w-[160px] truncate text-white/80">{job.assetName}</span>
                        </Td>
                        <Td>
                          <span className="text-[10.5px] text-white/60">{job.jobType}</span>
                        </Td>
                        <Td>
                          <span className="font-mono text-[10px] text-white/60">{job.targetAlgorithm}</span>
                        </Td>
                        <Td>
                          <span className="text-[10.5px] text-white/70">{job.status.replace(/_/g, ' ')}</span>
                        </Td>
                        <Td align="right">{fmtPercent(job.progress)}</Td>
                        <Td align="right">
                          <span className="font-mono text-[10px] text-white/40" title={absoluteTime(job.updatedAt)}>
                            {relativeTime(job.updatedAt)}
                          </span>
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </TableShell>
              )}
            </Panel>

            <Panel>
              <SectionLabel icon={ClipboardList} href="/dashboard/migration-planner" hint="Submitted migration plans and their approval state.">
                Plans and approval
              </SectionLabel>
              {orchestration.plans.length === 0 ? (
                <PanelEmpty>No migration plan has been submitted. Queue endpoints above, then submit a plan for approval.</PanelEmpty>
              ) : (
                <ul className="space-y-1.5">
                  {orchestration.plans.slice(0, 8).map((plan) => (
                    <li key={plan.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-white/10 bg-black/25 p-2.5">
                      <div className="min-w-0">
                        <span className="block truncate text-[11.5px] font-semibold text-white">{plan.name}</span>
                        <span className="font-mono text-[9.5px] text-white/35">
                          {plan.assetCount} asset(s) · updated {relativeTime(plan.updatedAt)}
                        </span>
                      </div>
                      <Pill
                        tone={
                          plan.status === 'approved'
                            ? 'good'
                            : plan.status === 'rejected'
                              ? 'critical'
                              : plan.status === 'pending_approval'
                                ? 'warning'
                                : 'neutral'
                        }
                      >
                        {plan.status.replace(/_/g, ' ')}
                      </Pill>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>

          {/* ---- Configuration drift -------------------------------- */}
          <Panel>
            <SectionLabel
              icon={GitCompare}
              hint="A drift row requires a security event that recorded BOTH a previous and a current value. Where no such record exists the platform says so rather than implying stability."
            >
              Configuration drift
            </SectionLabel>
            {orchestration.drift.length === 0 ? (
              <PanelEmpty>
                {orchestration.driftMeasured
                  ? 'No transport configuration change with a recorded before/after value in this window.'
                  : 'No source records configuration changes, so drift cannot be measured — this is not a statement that nothing changed.'}
              </PanelEmpty>
            ) : (
              <TableShell minWidth={780}>
                <thead>
                  <tr>
                    <Th>Asset</Th>
                    <Th>Change</Th>
                    <Th>Previous</Th>
                    <Th>Current</Th>
                    <Th align="center">Severity</Th>
                    <Th align="right">Detected</Th>
                  </tr>
                </thead>
                <tbody>
                  {orchestration.drift.slice(0, 12).map((row) => (
                    <tr key={row.id}>
                      <Td>
                        <span className="block max-w-[160px] truncate text-white/80">{row.assetName}</span>
                      </Td>
                      <Td>
                        <span className="block max-w-[220px] truncate text-[10.5px] text-white/65" title={row.detail}>
                          {row.detail}
                        </span>
                      </Td>
                      <Td>
                        <span className="font-mono text-[10px] text-amber-200/80">{row.previous}</span>
                      </Td>
                      <Td>
                        <span className="font-mono text-[10px] text-emerald-200/80">{row.current}</span>
                      </Td>
                      <Td align="center">
                        <SeverityBadge severity={row.severity} />
                      </Td>
                      <Td align="right">
                        <span className="font-mono text-[10px] text-white/40">{relativeTime(row.detectedAt)}</span>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </TableShell>
            )}
          </Panel>

          {/* ---- Workflow handoffs ---------------------------------- */}
          <Panel>
            <SectionLabel icon={Radar} hint="Discover → Analyze → Prioritize → Orchestrate → Migrate → Validate. Each step opens the module that owns it.">
              Continue the workflow
            </SectionLabel>
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
              {[
                { to: '/dashboard/migration-planner', label: 'Migration Planner', detail: 'Sequence the queued assets and build the plan.' },
                { to: '/dashboard/live_migration_ops', label: 'Live Migration Ops', detail: 'Execute approved changes with snapshots and rollback.' },
                { to: '/dashboard/scanner', label: 'Re-scan', detail: 'Re-measure an endpoint after the change lands.' },
                { to: '/dashboard/quantum-certification', label: 'Certification', detail: 'Turn verified remediation into signed evidence.' },
              ].map((link) => (
                <Link
                  key={link.to}
                  to={link.to}
                  className="rounded-lg border border-white/10 bg-black/25 p-3 no-underline transition hover:border-cyan-400/40 hover:bg-black/40"
                >
                  <div className="flex items-center gap-1.5 text-[11px] font-black uppercase tracking-wider text-white">
                    {link.label} <CheckCircle2 className="h-3 w-3 text-cyan-300" aria-hidden="true" />
                  </div>
                  <p className="mt-1.5 text-[10.5px] leading-snug text-white/45">{link.detail}</p>
                </Link>
              ))}
            </div>
          </Panel>

          <ProvenanceFooter telemetry={data.telemetry} />
        </>
      ) : null}

      {/* ---- Work item drawer ------------------------------------- */}
      <Drawer
        open={Boolean(selected)}
        title={selected?.actionLabel ?? 'Remediation item'}
        subtitle={selected ? `${selected.assetName} · ${selected.host}` : undefined}
        onClose={() => setSelected(null)}
      >
        {selected ? (
          <ItemDetail
            item={selected}
            endpoint={endpointById.get(selected.endpointId) ?? null}
            busy={actionState === 'busy' && pendingId === selected.assetId}
            onQueue={() => selected.assetId && void queueAsset(selected.assetId)}
            onUnqueue={() => selected.assetId && void unqueueAsset(selected.assetId)}
            onInvestigate={() => void openEndpoint(selected.endpointId)}
          />
        ) : null}
      </Drawer>

      {/* ---- Endpoint investigation ------------------------------- */}
      <Drawer
        open={Boolean(detail)}
        title={detail?.endpoint.name ?? 'Endpoint'}
        subtitle={detail ? `${detail.endpoint.host}${detail.endpoint.port ? `:${detail.endpoint.port}` : ''}` : undefined}
        onClose={() => setDetail(null)}
      >
        {detailLoading && !detail ? <PanelEmpty>Loading evidence…</PanelEmpty> : null}
        {detail ? <EndpointInvestigation detail={detail} /> : null}
      </Drawer>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Row actions - rendered only where the backend really supports them  */
/* ------------------------------------------------------------------ */

function ItemActions({
  item,
  busy,
  onQueue,
  onUnqueue,
  onEvidence,
}: {
  item: OrchestrationItem;
  busy: boolean;
  onQueue: () => void;
  onUnqueue: () => void;
  onEvidence: () => void;
}) {
  const can = (name: OrchestrationItem['availableActions'][number]) => item.availableActions.includes(name);
  const base =
    'rounded-md border px-2 py-1 text-[9px] font-black uppercase tracking-wider transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70 disabled:cursor-not-allowed disabled:opacity-40';

  return (
    <div className="flex justify-end gap-1">
      {can('queue') ? (
        <button type="button" onClick={onQueue} disabled={busy} className={cn(base, 'border-cyan-400/35 bg-cyan-500/10 text-cyan-200 hover:bg-cyan-500/20')}>
          {busy ? '…' : 'Queue'}
        </button>
      ) : null}
      {can('unqueue') ? (
        <button type="button" onClick={onUnqueue} disabled={busy} className={cn(base, 'border-white/12 bg-white/[0.04] text-white/60 hover:bg-white/[0.08]')}>
          {busy ? '…' : 'Unqueue'}
        </button>
      ) : null}
      {can('rescan') ? (
        <Link
          to={`/dashboard/scanner?target=${encodeURIComponent(item.host)}`}
          title="Opens the Scanner with this target prefilled. Scans require explicit per-target authorisation, so they are never started from here silently."
          className={cn(base, 'border-white/12 bg-white/[0.04] text-white/60 no-underline hover:bg-white/[0.08]')}
        >
          Re-scan
        </Link>
      ) : null}
      <button type="button" onClick={onEvidence} className={cn(base, 'border-white/12 bg-white/[0.04] text-white/60 hover:bg-white/[0.08]')}>
        Evidence
      </button>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Work item detail                                                    */
/* ------------------------------------------------------------------ */

function ItemDetail({
  item,
  endpoint,
  busy,
  onQueue,
  onUnqueue,
  onInvestigate,
}: {
  item: OrchestrationItem;
  endpoint: EndpointSummary | null;
  busy: boolean;
  onQueue: () => void;
  onUnqueue: () => void;
  onInvestigate: () => void;
}) {
  return (
    <>
      <section className="rounded-lg border border-white/10 bg-black/25 p-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <Pill tone={STATUS_META[item.status].tone}>{STATUS_META[item.status].label}</Pill>
          <SeverityBadge severity={item.severity} />
          <Pill tone="info">{item.standard}</Pill>
          {endpoint ? <Pill tone={RISK_TONE[endpoint.riskLevel]}>Endpoint risk {endpoint.riskScore}</Pill> : null}
          {item.internetFacing ? <Pill tone="warning">Internet-facing</Pill> : null}
        </div>
        <p className="mt-2.5 text-[12px] leading-relaxed text-white/75">{item.changeSummary}</p>
        <p className="mt-2 text-[11px] leading-relaxed text-white/45">{item.statusDetail}</p>

        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          <div className="rounded-md border border-amber-500/25 bg-amber-500/5 p-2.5">
            <div className="text-[9px] font-black uppercase tracking-wider text-amber-300/70">Currently observed</div>
            <div className="mt-1 break-words font-mono text-[11px] text-amber-100/90">{item.currentState}</div>
          </div>
          <div className="rounded-md border border-emerald-500/25 bg-emerald-500/5 p-2.5">
            <div className="text-[9px] font-black uppercase tracking-wider text-emerald-300/70">Target state</div>
            <div className="mt-1 break-words font-mono text-[11px] text-emerald-100/90">{item.targetState}</div>
          </div>
        </div>

        <dl className="mt-3 grid grid-cols-2 gap-2 text-[10.5px]">
          <div>
            <dt className="text-white/35">Priority score</dt>
            <dd className="text-white/75">{item.priority}</dd>
          </div>
          <div>
            <dt className="text-white/35">Blast radius</dt>
            <dd className="text-white/75">{item.blastRadius ? `${fmtNumber(item.blastRadius)} dependent asset(s)` : 'Not mapped'}</dd>
          </div>
          <div>
            <dt className="text-white/35">Estimated effort</dt>
            <dd className="text-white/75">{item.estimatedEffortHours ? `${fmtNumber(item.estimatedEffortHours)} hours` : 'Not estimated'}</dd>
          </div>
          <div>
            <dt className="text-white/35">Last change</dt>
            <dd className="text-white/75">{item.lastChangeAt ? absoluteTime(item.lastChangeAt) : 'None recorded'}</dd>
          </div>
        </dl>

        {item.blockedReason ? (
          <p className="mt-3 rounded-lg border border-amber-500/25 bg-amber-500/5 p-2.5 text-[10.5px] leading-relaxed text-amber-200/85">
            {item.blockedReason}
          </p>
        ) : null}
      </section>

      <section>
        <h3 className="mb-2 text-[10px] font-black uppercase tracking-wider text-white/40">Supporting evidence</h3>
        <EvidenceList evidence={item.evidence} />
      </section>

      <div className="flex flex-wrap gap-2">
        {item.availableActions.includes('queue') ? (
          <button
            type="button"
            onClick={onQueue}
            disabled={busy}
            className="rounded-lg border border-cyan-400/40 bg-cyan-500/15 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25 disabled:opacity-40"
          >
            {busy ? 'Queueing…' : 'Queue for migration'}
          </button>
        ) : null}
        {item.availableActions.includes('unqueue') ? (
          <button
            type="button"
            onClick={onUnqueue}
            disabled={busy}
            className="rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/70 transition hover:bg-white/[0.08] disabled:opacity-40"
          >
            {busy ? 'Removing…' : 'Remove from queue'}
          </button>
        ) : null}
        <button
          type="button"
          onClick={onInvestigate}
          className="rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/70 transition hover:bg-white/[0.08]"
        >
          Investigate endpoint
        </button>
        {item.availableActions.includes('rescan') ? (
          <Link
            to={`/dashboard/scanner?target=${encodeURIComponent(item.host)}`}
            className="rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/70 no-underline transition hover:bg-white/[0.08]"
          >
            Open in Scanner
          </Link>
        ) : null}
        {item.assetId ? (
          <Link
            to="/dashboard/migration-planner"
            className="rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/70 no-underline transition hover:bg-white/[0.08]"
          >
            Migration Planner
          </Link>
        ) : null}
      </div>
    </>
  );
}
