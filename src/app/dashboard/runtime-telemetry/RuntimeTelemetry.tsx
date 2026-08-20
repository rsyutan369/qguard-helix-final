'use client';

import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Antenna,
  Boxes,
  Gauge,
  Radio,
  RefreshCw,
  Route,
  ServerCog,
  ShieldQuestion,
  Timer,
  WifiOff,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { usePipelineTable, useRuntimeTelemetry } from '@/hooks/use-runtime-telemetry';
import { formatDuration } from '@/lib/telemetry-pipeline/intelligence';
import type { CollectorRecord, CoverageRecord, HealthState, PipelineFinding, SourceHealth } from '@/lib/telemetry-pipeline/types';
import {
  ConnectionLost,
  ErrorState,
  FilterSelect,
  Kpi,
  ModuleNav,
  PageHeader,
  Pager,
  Panel,
  PanelEmpty,
  Pill,
  SearchInput,
  SectionLabel,
  SeverityBadge,
  SHELL_CLASS,
  SHELL_CSS,
  Skeleton,
  StackedTrend,
  TableShell,
  Td,
  Term,
  Th,
  TONE,
  absoluteTime,
  fmtNumber,
  fmtPercent,
  relativeTime,
  type Tone,
} from '../_components/observability/primitives';

/**
 * Runtime Telemetry — the pipeline health console.
 *
 * Every other dashboard answers a question about the ESTATE. This one answers a
 * question about the dashboards: how complete, how fresh and how trustworthy is
 * the evidence they are all reading?
 *
 * It deliberately does not restate Runtime Cryptographic Intelligence, which
 * owns "what cryptography is running and is it quantum-safe". This page owns the
 * layer beneath — collectors, ingestion, freshness, attribution and coverage —
 * and is where a suspicious figure elsewhere gets explained.
 */

const PAGE_SIZE = 20;

const HEALTH_TONE: Record<HealthState, Tone> = {
  healthy: 'good',
  degraded: 'warning',
  stale: 'warning',
  silent: 'critical',
  absent: 'neutral',
};

const HEALTH_LABEL: Record<HealthState, string> = {
  healthy: 'Healthy',
  degraded: 'Degraded',
  stale: 'Stale',
  silent: 'Silent',
  absent: 'No data',
};

const SERIES_PALETTE = [TONE.neutral.hex, TONE.info.hex, TONE.ai.hex, TONE.good.hex, TONE.warning.hex, '#f472b6'];

const STAGE_LABEL: Record<PipelineFinding['stage'], string> = {
  collection: 'Collection',
  ingestion: 'Ingestion',
  attribution: 'Attribution',
  freshness: 'Freshness',
  quality: 'Quality',
};

export default function RuntimeTelemetry() {
  const { data, state, error, live, lastSyncedAt, refresh, reconnect } = useRuntimeTelemetry();

  const [coverageSearch, setCoverageSearch] = useState('');
  const [coverageHealth, setCoverageHealth] = useState('all');
  const [coverageOffset, setCoverageOffset] = useState(0);
  const [findingStage, setFindingStage] = useState('all');
  const [findingSeverity, setFindingSeverity] = useState('all');

  const revision = useMemo(() => Date.parse(data?.generatedAt || '') || 0, [data?.generatedAt]);

  const coverageQuery = useMemo(
    () => ({ search: coverageSearch, health: coverageHealth, limit: PAGE_SIZE, offset: coverageOffset }),
    [coverageSearch, coverageHealth, coverageOffset],
  );
  const { rows: coverageRows, total: coverageTotal, loading: coverageLoading } = usePipelineTable<CoverageRecord>(
    '/coverage',
    'records',
    coverageQuery,
    revision,
  );

  const findingQuery = useMemo(
    () => ({ stage: findingStage, severity: findingSeverity, limit: 50, offset: 0 }),
    [findingStage, findingSeverity],
  );
  const { rows: findings } = usePipelineTable<PipelineFinding>('/findings', 'findings', findingQuery, revision);

  const throughput = useMemo(() => {
    if (!data?.throughput?.length) return { points: [], series: [] as Array<{ key: string; label: string; hex: string }> };
    const keys = Object.keys(data.throughput[0].bySource);
    return {
      points: data.throughput.map((point) => ({ label: point.label, ...point.bySource })),
      series: keys.map((key, index) => ({ key, label: key, hex: SERIES_PALETTE[index % SERIES_PALETTE.length] })),
    };
  }, [data?.throughput]);

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
        <ErrorState message={error || 'The telemetry pipeline service did not respond.'} onRetry={reconnect} />
      </div>
    );
  }

  return (
    <div className={SHELL_CLASS}>
      <style>{SHELL_CSS}</style>
      <WorkflowRail activeStage="monitoring" />

      <PageHeader
        icon={Antenna}
        title="Runtime"
        accent="Telemetry"
        subtitle="The health of the evidence pipeline itself — collectors, ingestion lag, source freshness, attribution and coverage. This is the page that tells you how much to trust every other number in the platform."
        right={
          <PipelineFreshness
            live={live}
            state={state}
            generatedAt={data?.generatedAt ?? null}
            latestEvidenceAt={data?.latestEvidenceAt ?? null}
            healthState={data?.posture.healthState ?? null}
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

      {data && !data.hasData ? (
        <Panel>
          <div className="flex flex-col items-start gap-4 lg:flex-row">
            <span className="grid h-12 w-12 shrink-0 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300">
              <ShieldQuestion className="h-6 w-6" aria-hidden="true" />
            </span>
            <div className="min-w-0 flex-1">
              <h2 className="text-base font-black uppercase tracking-wider text-white">No telemetry pipeline to report on</h2>
              <p className="mt-1.5 max-w-3xl text-[12.5px] leading-relaxed text-white/55">
                No collector is registered and no source has produced a row. Every figure elsewhere in the platform is currently derived from
                nothing — which is a very different statement from a clean result.
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                <Link
                  to="/downloads"
                  className="rounded-lg border border-cyan-400/40 bg-cyan-500/15 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-cyan-200 no-underline"
                >
                  Deploy a collector
                </Link>
                <Link
                  to="/dashboard/scanner"
                  className="rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/70 no-underline"
                >
                  Run a scan
                </Link>
              </div>
            </div>
          </div>
        </Panel>
      ) : null}

      {data ? (
        <>
          {/* ---- Pipeline posture ----------------------------------- */}
          <Panel>
            <SectionLabel
              icon={Gauge}
              meta={<span className="normal-case tracking-normal">Collection · Ingestion · Freshness · Attribution</span>}
              hint="A composite of four equally-weighted dimensions: are collectors reporting, are sources fresh, is evidence attributable, and is it well-formed. Deliberately not weighted towards collectors — a tenant can be healthily fed by scans alone."
            >
              Pipeline health
            </SectionLabel>

            <div className="grid gap-3 lg:grid-cols-[auto_1fr]">
              <div className="flex items-center gap-4">
                <HealthDial score={data.posture.pipelineHealthScore} state={data.posture.healthState} />
              </div>
              <div className="min-w-0">
                <p className="text-[13px] font-semibold leading-relaxed text-white/80">{data.posture.headline}</p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  <Pill tone={data.posture.collectorsOnline ? 'good' : 'critical'}>
                    Collectors {fmtNumber(data.posture.collectorsOnline)}/{fmtNumber(data.posture.collectorsTotal)}
                  </Pill>
                  <Pill tone={data.posture.connectorsActive ? 'good' : 'neutral'}>
                    Connectors {fmtNumber(data.posture.connectorsActive)}/{fmtNumber(data.posture.connectorsTotal)}
                  </Pill>
                  <Pill tone={data.posture.sourcesHealthy === data.posture.sourcesTotal ? 'good' : 'warning'}>
                    Sources fresh {fmtNumber(data.posture.sourcesHealthy)}/{fmtNumber(data.posture.sourcesTotal)}
                  </Pill>
                  {data.posture.sourcesAbsent ? <Pill tone="neutral">No data from {fmtNumber(data.posture.sourcesAbsent)}</Pill> : null}
                  <Pill tone={data.posture.coveragePercent >= 80 ? 'good' : 'warning'}>
                    Asset coverage {fmtPercent(data.posture.coveragePercent)}
                  </Pill>
                  <Pill tone={data.posture.qualityScore >= 80 ? 'good' : 'warning'}>Signal quality {fmtPercent(data.posture.qualityScore)}</Pill>
                  {data.posture.stalestSource ? (
                    <Pill tone="neutral" title={`Stalest source: ${data.posture.stalestSource}`}>
                      Stalest {data.posture.stalestSource} · {data.posture.stalestAgeMs !== null ? formatDuration(data.posture.stalestAgeMs) : '—'}
                    </Pill>
                  ) : null}
                </div>
              </div>
            </div>
          </Panel>

          {/* ---- Headline ------------------------------------------- */}
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Kpi
              label="Events last 24h"
              value={fmtNumber(data.posture.eventsLast24h)}
              detail={`${fmtNumber(data.posture.eventsLast7d)} in the last 7 days`}
              tone={data.posture.eventsLast24h ? 'neutral' : 'warning'}
              hint="Rows persisted across every tracked source in the window, counted per table — never a flattened cross-table array."
            />
            <Kpi
              label="Ingestion lag (p50)"
              value={data.ingestion.p50Ms !== null ? formatDuration(data.ingestion.p50Ms) : '—'}
              detail={
                data.ingestion.measured
                  ? `p95 ${data.ingestion.p95Ms !== null ? formatDuration(data.ingestion.p95Ms) : '—'} · ${fmtNumber(data.ingestion.samples)} sample(s)`
                  : 'No source carries both an observed and a persisted time'
              }
              tone={data.ingestion.p95Ms !== null && data.ingestion.p95Ms > 60_000 ? 'warning' : 'good'}
              unmeasured={!data.ingestion.measured}
              hint="Measured per row as persisted-time minus observed-time. This is how far behind reality a 'live' view actually is."
            />
            <Kpi
              label="Collectors reporting"
              value={`${fmtNumber(data.posture.collectorsOnline)} / ${fmtNumber(data.posture.collectorsTotal)}`}
              detail={
                data.fleet.measured
                  ? `${fmtNumber(data.fleet.heartbeatsTotal)} heartbeat(s) received`
                  : 'No collector registered — scan-only tenant'
              }
              tone={data.posture.collectorsOnline ? 'good' : 'critical'}
              unmeasured={!data.fleet.measured}
              hint="Health is derived from evidence, not from the stored status column — a row can say 'online' while nothing has arrived for days."
              href="/downloads"
            />
            <Kpi
              label="Unattributed evidence"
              value={fmtPercent(data.coverage.unattributedPercent)}
              detail={`${fmtNumber(data.coverage.unattributedEvents)} row(s) carry no asset binding`}
              tone={data.coverage.unattributedPercent > 25 ? 'warning' : 'good'}
              hint="Evidence with no asset id cannot be rolled up per asset, so it is excluded from asset posture everywhere in the platform."
            />
          </div>

          {/* ---- Pipeline stages ------------------------------------ */}
          <Panel>
            <SectionLabel icon={Route} hint="Where evidence enters, how it is attributed, and what consumes it. Each stage reports its own measured state.">
              Pipeline stages
            </SectionLabel>
            <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
              <StageCard
                icon={Radio}
                title="Collect"
                value={data.fleet.measured ? `${fmtNumber(data.fleet.healthy)}/${fmtNumber(data.fleet.total)} collectors` : 'Scan-only'}
                detail={
                  data.fleet.measured
                    ? `${fmtNumber(data.fleet.heartbeatsTotal)} heartbeat(s), ${fmtNumber(data.fleet.silent)} silent collector(s)`
                    : 'Evidence arrives from authorized scans rather than a resident collector.'
                }
                tone={data.fleet.measured ? (data.fleet.healthy ? 'good' : 'critical') : 'neutral'}
              />
              <StageCard
                icon={Timer}
                title="Ingest"
                value={data.ingestion.p50Ms !== null ? `${formatDuration(data.ingestion.p50Ms)} p50` : 'Not measured'}
                detail={
                  data.ingestion.negativeSamples
                    ? `${fmtNumber(data.ingestion.negativeSamples)} row(s) show clock skew — persisted before observed.`
                    : `${fmtNumber(data.ingestion.samples)} row(s) carried both timestamps.`
                }
                tone={data.ingestion.negativeSamples ? 'warning' : data.ingestion.measured ? 'good' : 'neutral'}
              />
              <StageCard
                icon={Boxes}
                title="Attribute"
                value={fmtPercent(100 - data.coverage.unattributedPercent)}
                detail={`${fmtNumber(data.fleet.unattributableEvents)} collector event(s) carry no collector id.`}
                tone={data.coverage.unattributedPercent > 25 || data.fleet.unattributableEvents ? 'warning' : 'good'}
              />
              <StageCard
                icon={Activity}
                title="Consume"
                value={`${fmtNumber(data.posture.sourcesHealthy)}/${fmtNumber(data.posture.sourcesTotal)} fresh`}
                detail={`${fmtNumber(data.posture.sourcesAbsent)} source(s) have produced nothing at all.`}
                tone={data.posture.sourcesHealthy === data.posture.sourcesTotal ? 'good' : 'warning'}
              />
            </div>
          </Panel>

          {/* ---- Throughput + ingestion lag ------------------------- */}
          <div className="grid gap-3 xl:grid-cols-[1.5fr_1fr]">
            <Panel>
              <SectionLabel icon={Activity} meta="Last 14 days" hint="Rows persisted per day per source, from real timestamps. A flat day means nothing was collected, not that nothing happened.">
                Ingestion throughput
              </SectionLabel>
              <StackedTrend
                points={throughput.points as unknown as Array<Record<string, string | number>>}
                series={throughput.series}
                emptyLabel="No dated rows in the last 14 days"
              />
            </Panel>

            <Panel>
              <SectionLabel
                icon={Timer}
                hint="Time between a collector observing something and the platform persisting it. Computed per row; sources that record only one timestamp cannot contribute."
              >
                Ingestion lag by source
              </SectionLabel>
              {!data.ingestion.measured ? (
                <PanelEmpty>
                  No source records both an observation time and a persistence time, so ingestion lag cannot be measured on this tenant.
                </PanelEmpty>
              ) : (
                <TableShell minWidth={420}>
                  <thead>
                    <tr>
                      <Th>Source</Th>
                      <Th align="right">Samples</Th>
                      <Th align="right">p50</Th>
                      <Th align="right">p95</Th>
                      <Th align="right">Max</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.ingestion.bySource.map((row) => (
                      <tr key={row.source}>
                        <Td>
                          <span className="text-[11px] text-white/80">{row.source}</span>
                        </Td>
                        <Td align="right">{fmtNumber(row.samples)}</Td>
                        <Td align="right">
                          <span className="font-mono text-[10.5px]">{formatDuration(row.p50Ms)}</span>
                        </Td>
                        <Td align="right">
                          <span className={cn('font-mono text-[10.5px]', row.p95Ms > 60_000 && 'text-amber-300')}>{formatDuration(row.p95Ms)}</span>
                        </Td>
                        <Td align="right">
                          <span className="font-mono text-[10.5px] text-white/50">{formatDuration(row.maxMs)}</span>
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </TableShell>
              )}
              {data.ingestion.negativeSamples ? (
                <p className="mt-3 rounded-lg border border-amber-500/25 bg-amber-500/5 p-2.5 text-[10.5px] leading-relaxed text-amber-200/85">
                  {fmtNumber(data.ingestion.negativeSamples)} row(s) were persisted at a time earlier than they were observed — a collector clock
                  disagrees with the platform. Those rows are excluded from the figures above rather than averaged in.
                </p>
              ) : null}
            </Panel>
          </div>

          {/* ---- Collector fleet ------------------------------------ */}
          <Panel>
            <SectionLabel
              icon={ServerCog}
              href="/downloads"
              meta={data.fleet.measured ? `${fmtNumber(data.fleet.total)} registered` : undefined}
              hint="Health is derived from heartbeats and attributed events, so it can — and here does — disagree with the status stored on the agent row."
            >
              Collector fleet
            </SectionLabel>

            {!data.fleet.measured ? (
              <PanelEmpty>
                No collector is registered. Evidence reaches the platform from authorized scans only, which means posture is a point-in-time
                snapshot rather than continuous monitoring.
              </PanelEmpty>
            ) : (
              <TableShell minWidth={980}>
                <thead>
                  <tr>
                    <Th>Collector</Th>
                    <Th>Platform</Th>
                    <Th>Reported status</Th>
                    <Th>Measured health</Th>
                    <Th align="right">Heartbeats</Th>
                    <Th align="right">Attributed events</Th>
                    <Th align="right">Last contact</Th>
                  </tr>
                </thead>
                <tbody>
                  {data.fleet.collectors.map((collector: CollectorRecord) => (
                    <tr key={collector.id} className="transition hover:bg-white/[0.04]">
                      <Td>
                        <span className="block max-w-[220px] truncate font-semibold text-white">{collector.name}</span>
                        <span className="block max-w-[220px] truncate font-mono text-[9.5px] text-white/35">
                          {collector.hostname} · {collector.environment}
                        </span>
                      </Td>
                      <Td>
                        <span className="text-[10.5px] text-white/60">{collector.platform}</span>
                      </Td>
                      <Td>
                        <span className="font-mono text-[10.5px] text-white/50">{collector.reportedStatus}</span>
                      </Td>
                      <Td>
                        <Pill tone={HEALTH_TONE[collector.health]} title={collector.healthReason}>
                          {HEALTH_LABEL[collector.health]}
                        </Pill>
                      </Td>
                      <Td align="right">
                        <span className={cn('font-mono text-[10.5px]', collector.heartbeatsReceived === 0 && 'text-red-300')}>
                          {fmtNumber(collector.heartbeatsReceived)}
                        </span>
                      </Td>
                      <Td align="right">
                        <span className={cn('font-mono text-[10.5px]', collector.eventsAttributed === 0 && 'text-white/35')}>
                          {fmtNumber(collector.eventsAttributed)}
                        </span>
                      </Td>
                      <Td align="right">
                        <span className="font-mono text-[10px] text-white/50" title={absoluteTime(collector.lastSeenAt)}>
                          {collector.lastSeenAt ? relativeTime(collector.lastSeenAt) : 'never'}
                        </span>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </TableShell>
            )}

            {data.fleet.collectors.some((collector) => collector.health !== 'healthy') ? (
              <ul className="mt-3 space-y-1.5">
                {data.fleet.collectors
                  .filter((collector) => collector.health !== 'healthy')
                  .map((collector) => (
                    <li key={`${collector.id}-why`} className="rounded-lg border border-white/10 bg-black/25 p-2.5 text-[10.5px] leading-relaxed text-white/60">
                      <strong className="text-white/85">{collector.name}:</strong> {collector.healthReason}
                    </li>
                  ))}
              </ul>
            ) : null}

            {data.fleet.unattributableEvents ? (
              <p className="mt-3 rounded-lg border border-amber-500/25 bg-amber-500/5 p-2.5 text-[10.5px] leading-relaxed text-amber-200/85">
                <strong className="font-black uppercase tracking-wider">Attribution gap.</strong> {fmtNumber(data.fleet.unattributableEvents)}{' '}
                event(s) arrived from a collector-class source without a collector id
                {data.fleet.unregisteredSources.length ? ` (${data.fleet.unregisteredSources.join(', ')})` : ''}. They are real evidence, but they
                cannot be traced back to the collector that produced them.
              </p>
            ) : null}
          </Panel>

          {/* ---- Source health -------------------------------------- */}
          <Panel>
            <SectionLabel
              icon={Boxes}
              meta={`${fmtNumber(data.posture.sourcesHealthy)} of ${fmtNumber(data.posture.sourcesTotal)} fresh`}
              hint="Each source is judged against its own freshness window — a heartbeat is stale after 15 minutes, a certificate inventory after a week. 'Feeds' shows what a stale row degrades."
            >
              Source freshness
            </SectionLabel>
            <TableShell minWidth={1060}>
              <thead>
                <tr>
                  <Th>Source</Th>
                  <Th align="right">Rows</Th>
                  <Th>Health</Th>
                  <Th align="right">Newest row</Th>
                  <Th align="right">Window</Th>
                  <Th>Feeds</Th>
                </tr>
              </thead>
              <tbody>
                {data.sources.map((source: SourceHealth) => (
                  <tr key={source.key} className="transition hover:bg-white/[0.04]">
                    <Td>
                      <span className="block font-semibold text-white">{source.label}</span>
                      <span className="block font-mono text-[9px] text-white/30">{source.key}</span>
                    </Td>
                    <Td align="right">
                      <span className={cn('font-mono text-[10.5px]', source.rows === 0 && 'text-white/30')}>
                        {source.truncated ? `≥${fmtNumber(source.rows)}` : fmtNumber(source.rows)}
                      </span>
                    </Td>
                    <Td>
                      <Pill tone={HEALTH_TONE[source.health]} title={source.detail}>
                        {HEALTH_LABEL[source.health]}
                      </Pill>
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[10px] text-white/50" title={absoluteTime(source.lastEventAt)}>
                        {source.ageMs !== null ? `${formatDuration(source.ageMs)} ago` : 'never'}
                      </span>
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[10px] text-white/35">{formatDuration(source.thresholdMs)}</span>
                    </Td>
                    <Td>
                      <span className="block max-w-[280px] truncate text-[10px] text-white/45" title={source.feeds.join(', ')}>
                        {source.feeds.join(', ')}
                      </span>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </TableShell>
            {data.truncated ? (
              <p className="mt-3 rounded-lg border border-amber-500/25 bg-amber-500/5 p-2.5 text-[10.5px] leading-relaxed text-amber-200/85">
                A source reached its fetch cap, so its row count is shown as a lower bound (≥). Lag and quality percentages are computed over the
                fetched window rather than the whole table.
              </p>
            ) : null}
          </Panel>

          {/* ---- Signal quality ------------------------------------- */}
          <Panel>
            <SectionLabel
              icon={AlertTriangle}
              meta={`Score ${fmtPercent(data.quality.score)}`}
              hint="Structural defects in the evidence itself. The score is 100 minus the WORST single issue rate, not the sum — one row can exhibit several issues at once."
            >
              Signal quality
            </SectionLabel>
            {!data.quality.measured ? (
              <PanelEmpty>No runtime or agent rows to examine, so signal quality cannot be assessed.</PanelEmpty>
            ) : data.quality.issues.length === 0 ? (
              <PanelEmpty>
                No structural defect found across {fmtNumber(data.quality.rowsExamined)} examined row(s). Evidence is attributable, timestamped and
                well-formed.
              </PanelEmpty>
            ) : (
              <ul className="space-y-2">
                {data.quality.issues.map((issue) => (
                  <li key={issue.id} className="rounded-lg border border-white/10 bg-black/25 p-3">
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="min-w-0">
                        <h3 className="text-[12px] font-black text-white">{issue.label}</h3>
                        <p className="mt-1 font-mono text-[10px] text-white/40">
                          {fmtNumber(issue.count)} of {fmtNumber(issue.examined)} examined · {fmtPercent(issue.percent)}
                        </p>
                      </div>
                      <SeverityBadge severity={issue.severity} />
                    </div>
                    <p className="mt-2 text-[11px] leading-relaxed text-white/60">{issue.consequence}</p>
                    <p className="mt-1.5 text-[11px] leading-relaxed text-cyan-200/70">{issue.remediation}</p>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          {/* ---- Coverage ------------------------------------------- */}
          <Panel>
            <SectionLabel
              icon={Radio}
              meta={`${fmtNumber(data.coverage.assetsReporting)} of ${fmtNumber(data.coverage.assetsTotal)} reporting`}
              hint="An asset producing no telemetry shows an absence of findings on every other dashboard. That is not the same as a clean result, and this table is where the difference is visible."
            >
              Asset coverage
            </SectionLabel>

            <div className="mb-3 flex flex-wrap items-center gap-2">
              <SearchInput
                value={coverageSearch}
                onChange={(value) => {
                  setCoverageSearch(value);
                  setCoverageOffset(0);
                }}
                placeholder="Search asset, environment or source"
              />
              <FilterSelect
                label="Health"
                value={coverageHealth}
                onChange={(value) => {
                  setCoverageHealth(value);
                  setCoverageOffset(0);
                }}
                options={[
                  { value: 'all', label: 'All' },
                  { value: 'healthy', label: 'Reporting' },
                  { value: 'stale', label: 'Stale' },
                  { value: 'silent', label: 'Silent' },
                  { value: 'absent', label: 'No evidence' },
                ]}
              />
            </div>

            {coverageRows.length === 0 ? (
              <PanelEmpty>{coverageLoading ? 'Loading assets…' : 'No asset matches these filters.'}</PanelEmpty>
            ) : (
              <TableShell minWidth={760}>
                <thead>
                  <tr>
                    <Th>Asset</Th>
                    <Th>Environment</Th>
                    <Th>Sources reporting</Th>
                    <Th align="right">Rows</Th>
                    <Th>State</Th>
                    <Th align="right">Newest evidence</Th>
                  </tr>
                </thead>
                <tbody>
                  {coverageRows.map((record) => (
                    <tr key={record.assetId} className="transition hover:bg-white/[0.04]">
                      <Td>
                        <span className="block max-w-[220px] truncate font-semibold text-white">{record.assetName}</span>
                      </Td>
                      <Td>
                        <span className="text-[10.5px] text-white/55">{record.environment}</span>
                      </Td>
                      <Td>
                        {record.sources.length ? (
                          <span className="flex flex-wrap gap-1">
                            {record.sources.map((source) => (
                              <Pill key={source} tone="info">
                                {source}
                              </Pill>
                            ))}
                          </span>
                        ) : (
                          <span className="text-[10.5px] text-white/35">None</span>
                        )}
                      </Td>
                      <Td align="right">
                        <span className={cn('font-mono text-[10.5px]', record.events === 0 && 'text-white/30')}>{fmtNumber(record.events)}</span>
                      </Td>
                      <Td>
                        <Pill tone={HEALTH_TONE[record.health]}>{HEALTH_LABEL[record.health]}</Pill>
                      </Td>
                      <Td align="right">
                        <span className="font-mono text-[10px] text-white/50" title={absoluteTime(record.lastEvidenceAt)}>
                          {record.lastEvidenceAt ? relativeTime(record.lastEvidenceAt) : 'never'}
                        </span>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </TableShell>
            )}
            <Pager offset={coverageOffset} limit={PAGE_SIZE} total={coverageTotal} onChange={setCoverageOffset} />

            {data.coverage.unattributedEvents ? (
              <p className="mt-3 rounded-lg border border-white/10 bg-black/25 p-2.5 text-[10.5px] leading-relaxed text-white/50">
                A further {fmtNumber(data.coverage.unattributedEvents)} row(s) ({fmtPercent(data.coverage.unattributedPercent)}) carry no asset
                binding at all, so they belong to no row above. They are counted in source totals but contribute to no asset&rsquo;s posture.
              </p>
            ) : null}
          </Panel>

          {/* ---- Findings ------------------------------------------- */}
          <Panel>
            <SectionLabel
              icon={AlertTriangle}
              meta={`${fmtNumber(data.totals.findings)} open`}
              hint="Pipeline defects, each naming the dashboards it degrades. Fixing these is what makes every other page trustworthy."
            >
              Pipeline findings
            </SectionLabel>

            <div className="mb-3 flex flex-wrap items-center gap-2">
              <FilterSelect
                label="Stage"
                value={findingStage}
                onChange={setFindingStage}
                options={[
                  { value: 'all', label: 'All' },
                  ...(Object.keys(STAGE_LABEL) as Array<PipelineFinding['stage']>).map((key) => ({ value: key, label: STAGE_LABEL[key] })),
                ]}
              />
              <FilterSelect
                label="Severity"
                value={findingSeverity}
                onChange={setFindingSeverity}
                options={[
                  { value: 'all', label: 'All' },
                  { value: 'critical', label: 'Critical' },
                  { value: 'high', label: 'High' },
                  { value: 'medium', label: 'Medium' },
                  { value: 'low', label: 'Low' },
                ]}
              />
            </div>

            {findings.length === 0 ? (
              <PanelEmpty>No pipeline finding is open. Collectors, freshness, attribution and quality are all within tolerance.</PanelEmpty>
            ) : (
              <ul className="space-y-2">
                {findings.map((finding) => (
                  <li key={finding.id} className="rounded-lg border border-white/10 bg-black/25 p-3">
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="min-w-0">
                        <h3 className="text-[12px] font-black text-white">{finding.title}</h3>
                        <p className="mt-1 font-mono text-[10px] text-white/40">{finding.observed}</p>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <SeverityBadge severity={finding.severity} />
                        <Pill tone="neutral">{STAGE_LABEL[finding.stage]}</Pill>
                      </div>
                    </div>
                    <p className="mt-2 text-[11px] leading-relaxed text-white/60">{finding.detail}</p>
                    <p className="mt-1.5 text-[11px] leading-relaxed text-cyan-200/70">{finding.remediation}</p>
                    <div className="mt-2 flex flex-wrap items-center gap-2">
                      <span className="text-[9.5px] font-black uppercase tracking-wider text-white/30">Degrades</span>
                      {finding.affects.map((target) => (
                        <Pill key={target} tone="warning">
                          {target}
                        </Pill>
                      ))}
                      {finding.actionHref ? (
                        <Link
                          to={finding.actionHref}
                          className="ml-auto rounded-md border border-cyan-400/35 bg-cyan-500/10 px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 no-underline hover:bg-cyan-500/20"
                        >
                          {finding.actionLabel}
                        </Link>
                      ) : null}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          {/* ---- Provenance ----------------------------------------- */}
          <Panel>
            <SectionLabel icon={Boxes} hint="Rows actually consulted to build this page. This table IS the provenance footer for the whole platform.">
              Rows consulted
            </SectionLabel>
            <ul className="flex flex-wrap gap-1.5">
              {Object.entries(data.sourceCounts).map(([table, count]) => (
                <li
                  key={table}
                  className={cn(
                    'rounded-md border px-2 py-1 font-mono text-[10px]',
                    count > 0 ? 'border-white/10 bg-black/25 text-white/50' : 'border-white/8 bg-black/15 text-white/30',
                  )}
                >
                  {table} <span className={count > 0 ? 'text-cyan-300' : 'text-white/25'}>{fmtNumber(count)}</span>
                </li>
              ))}
            </ul>
            <p className="mt-3 text-[10.5px] leading-relaxed text-white/40">
              Runtime Telemetry reports on the pipeline. For what the cryptography in these events actually means, see{' '}
              <Link to="/dashboard/runtime-crypto-intel" className="text-cyan-300 hover:text-cyan-200">
                Runtime Cryptographic Intelligence
              </Link>
              .
            </p>
          </Panel>
        </>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Header freshness                                                    */
/* ------------------------------------------------------------------ */

/**
 * A dedicated header rather than the shared `FreshnessBar`.
 *
 * The shared component reports pipeline status as background context for a page
 * about the estate. Here the pipeline IS the subject, so reusing it would mean
 * synthesising fields this model does not have (last scan, running scans) just
 * to satisfy a prop shape — inventing data on the one page whose purpose is to
 * expose invented data.
 */
function PipelineFreshness({
  live,
  state,
  generatedAt,
  latestEvidenceAt,
  healthState,
  onRefresh,
  refreshing,
}: {
  live: boolean;
  state: 'loading' | 'success' | 'error';
  generatedAt: string | null;
  latestEvidenceAt: string | null;
  healthState: HealthState | null;
  onRefresh: () => void;
  refreshing?: boolean;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {healthState ? (
        <Pill tone={HEALTH_TONE[healthState]}>
          <span className={cn('h-1.5 w-1.5 rounded-full', TONE[HEALTH_TONE[healthState]].dot)} aria-hidden="true" />
          Pipeline {HEALTH_LABEL[healthState]}
        </Pill>
      ) : null}

      <span
        role="status"
        className={cn(
          'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[9px] font-black uppercase tracking-widest',
          live ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-300' : 'border-amber-400/40 bg-amber-500/10 text-amber-300',
        )}
      >
        {live ? (
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" aria-hidden="true" />
        ) : (
          <WifiOff className="h-3 w-3" aria-hidden="true" />
        )}
        {state === 'loading' && !generatedAt ? 'Connecting' : live ? 'Stream connected' : 'Real-time connection unavailable'}
      </span>

      <div className="flex flex-col text-right">
        <span className="font-mono text-[9.5px] text-white/40">Computed {relativeTime(generatedAt)}</span>
        <span className="font-mono text-[9.5px] text-white/30" title={absoluteTime(latestEvidenceAt)}>
          Newest row {relativeTime(latestEvidenceAt)}
        </span>
      </div>

      <button
        type="button"
        onClick={onRefresh}
        className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
      >
        <RefreshCw className={cn('h-3.5 w-3.5', refreshing && 'animate-spin')} aria-hidden="true" /> Refresh
      </button>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Health dial                                                         */
/* ------------------------------------------------------------------ */

function HealthDial({ score, state }: { score: number; state: HealthState }) {
  const tone = HEALTH_TONE[state];
  const size = 132;
  const radius = size / 2 - 12;
  const circumference = 2 * Math.PI * radius;
  const dash = (Math.max(0, Math.min(100, score)) / 100) * circumference;

  return (
    <div className="relative">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Pipeline health ${score} of 100`}>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="12" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={TONE[tone].hex}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference - dash}`}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
        <text x="50%" y="47%" textAnchor="middle" className="fill-white" style={{ fontSize: 30, fontWeight: 800 }}>
          {Math.round(score)}
        </text>
        <text x="50%" y="62%" textAnchor="middle" fill="rgba(255,255,255,0.4)" style={{ fontSize: 8.5, fontWeight: 700, letterSpacing: 1 }}>
          PIPELINE HEALTH
        </text>
      </svg>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Stage card                                                          */
/* ------------------------------------------------------------------ */

function StageCard({
  icon: Icon,
  title,
  value,
  detail,
  tone,
}: {
  icon: typeof Radio;
  title: string;
  value: string;
  detail: string;
  tone: Tone;
}) {
  return (
    <div className="rounded-lg border border-white/10 bg-black/25 p-3">
      <div className="flex items-center gap-2">
        <span className={cn('grid h-7 w-7 place-items-center rounded-md border', TONE[tone].border, TONE[tone].soft, TONE[tone].text)}>
          <Icon className="h-3.5 w-3.5" aria-hidden="true" />
        </span>
        <span className="text-[10px] font-black uppercase tracking-wider text-white/45">{title}</span>
      </div>
      <div className={cn('mt-2 text-[17px] font-black leading-none', TONE[tone].text)}>{value}</div>
      <p className="mt-1.5 text-[10px] leading-snug text-white/40">{detail}</p>
    </div>
  );
}
