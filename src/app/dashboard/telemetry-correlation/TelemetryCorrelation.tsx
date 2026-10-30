'use client';

import { useCallback, useMemo, useState } from 'react';
import {
  AlertTriangle, Antenna, EyeOff, Filter, GitMerge, LayoutList, Network,
  RefreshCw, Search, Sparkles, X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { askSophia } from '@/lib/sophia-bridge';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { Panel } from '../_components/executive/primitives';
import { useTelemetryCorrelation } from '@/hooks/use-telemetry-correlation';
import {
  EMPTY_CORRELATION_FILTERS, filterObservations,
  type CorrelationFilters, type CorrelationIntelligence, type SourceHealth,
} from '@/lib/telemetry/correlation-intelligence';
import {
  AMBER, BLUE, ConnectionLostBanner, DistributionBars, EmptyRow, GREEN, HardErrorPanel,
  HeaderButton, IntelHeader, IntelShell, IntelTabs, KpiCard, LinkButton, NoEvidenceState,
  PrimaryButton, RED, SLATE, ScoreDial, SectionHeading, SkeletonGrid, SourceNote, StatusPill,
  fmtInt, fmtPct, relativeTime,
} from '../_components/intel/kit';
import { ModuleBrief, SourceHealth as EvidenceSources } from '../_components/intel/kit';
import { correlationNextStep } from '../_components/intel/next-steps';

type TabKey = 'coverage' | 'conflicts' | 'observations';

const HEALTH_HEX: Record<SourceHealth, string> = { reporting: GREEN, stale: AMBER, silent: RED };
const HEALTH_LABEL: Record<SourceHealth, string> = { reporting: 'Reporting', stale: 'Stale', silent: 'Silent' };
const HEALTH_GLYPH: Record<SourceHealth, string> = { reporting: '✓', stale: '◐', silent: '●' };

const CLASS_HEX: Record<string, string> = { safe: GREEN, hybrid: BLUE, vulnerable: RED, unknown: SLATE };

/**
 * Telemetry Correlation.
 *
 * Answers what no single telemetry source can: how much of the estate can we
 * actually see, which observations did two independent channels confirm, and —
 * the reason this page exists — where do two sources DISAGREE about the same
 * asset's cryptography?
 *
 * Coverage is measured against the real asset inventory, so the blind-spot list
 * is a first-class citizen rather than a footnote. And no score is published
 * until a source has reported: the implementation this replaces added a
 * constant 52, so an estate the platform was blind to scored 52/100 and read as
 * merely mediocre.
 */
export default function TelemetryCorrelation() {
  const { data, state, error, transport, lastVerifiedAt, lastGoodAt, refreshing, refresh, reconnect } = useTelemetryCorrelation();
  const nextStep = useMemo(() => (data ? correlationNextStep(data) : null), [data]);

  const [tab, setTab] = useState<TabKey>('coverage');
  const [filters, setFilters] = useState<CorrelationFilters>(EMPTY_CORRELATION_FILTERS);
  const [showFilters, setShowFilters] = useState(false);

  const observations = useMemo(() => (data ? filterObservations(data.observations, filters) : []), [data, filters]);
  const ask = useCallback((question: string) => askSophia(question, sophiaContext(data)), [data]);
  const patch = useCallback((next: Partial<CorrelationFilters>) => setFilters((c) => ({ ...c, ...next })), []);

  const showSkeleton = state === 'loading' && !data;
  const showHardError = state === 'error' && !data;
  const noTelemetry = Boolean(data && !data.hasTelemetry);

  return (
    <IntelShell name="corr-shell">
      <WorkflowRail activeStage="monitoring" />

      <IntelHeader
        title="Telemetry"
        accent="Correlation"
        subtitle="See how much of the estate your telemetry actually covers, which observations two independent sources confirm, and where they disagree."
        icon={Network}
        transport={transport}
        lastVerifiedAt={lastVerifiedAt}
        lastUpdated={data?.generatedAt ?? null}
      >
        <HeaderButton onClick={() => setShowFilters((v) => !v)} icon={Filter} active={showFilters}>Filters</HeaderButton>
        <button
          type="button"
          onClick={() => ask('How much of my estate does telemetry actually cover, and are any sources disagreeing?')}
          className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/45 bg-violet-500/12 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/22"
        >
          <Sparkles className="h-3.5 w-3.5" aria-hidden="true" /> Ask Sophia
        </button>
        <PrimaryButton onClick={() => void refresh(true)} icon={RefreshCw} spin={refreshing}>Refresh</PrimaryButton>
      </IntelHeader>

      {data && transport !== 'stream' ? (
        <ConnectionLostBanner lastGoodAt={lastGoodAt} error={error} onReconnect={reconnect} transport={transport} lastVerifiedAt={lastVerifiedAt} />
      ) : null}

      {showHardError ? (
        <HardErrorPanel
          title="Telemetry Correlation Unavailable"
          message="QGuard Helix could not read the telemetry channels. No values are shown rather than presenting zeros as fact."
          error={error}
          onRetry={reconnect}
        />
      ) : null}

      {showSkeleton ? <SkeletonGrid cards={5} panels={2} /> : null}

      {noTelemetry && data ? (
        <NoEvidenceState
          icon={Antenna}
          title="No Telemetry Source Reporting"
          body="No scanner, collector agent or cloud connector has reported for this environment. QGuard Helix cannot see this estate — which is not the same as the estate being safe, so no coverage score is published."
          bullets={[
            'Run the PQC Scanner to establish the discovery channel.',
            'Deploy a collector agent for runtime cryptographic telemetry.',
            'Connect a cloud provider so managed assets report their cryptography.',
            'With two or more channels reporting, this page confirms observations independently and surfaces disagreement between them.',
          ]}
          actions={[
            { href: '/dashboard/scanner', label: 'Run a Scan', primary: true },
            { href: '/dashboard/agents', label: 'Deploy an Agent' },
          ]}
        />
      ) : null}

      {data && data.hasTelemetry ? (
        <>
          {nextStep ? (
            <ModuleBrief
              what={<>Which telemetry channels — scanner, collector agents, cloud connectors, runtime — observe each asset, which observations two independent sources confirm, and where they disagree.</>}
              why={<>A single source can be wrong or silent. Coverage you cannot corroborate is an assumption; an asset no source observes is a blind spot, not a safe asset; and two sources reporting different algorithms means one of them is describing the past.</>}
              next={{ label: nextStep.label, href: nextStep.href, detail: nextStep.detail, tone: nextStep.tone }}
              scope={<>{data.kpis.assetsCovered} of {data.kpis.assetsTotal} asset(s) observed by at least one of {data.kpis.totalSources} source(s); {data.kpis.corroboratedAssets} corroborated by two or more.</>}
            />
          ) : null}

          <section aria-label="Telemetry metrics" className="grid grid-cols-2 gap-2.5 lg:grid-cols-3 xl:grid-cols-5">
            <KpiCard
              label="Active Sources"
              value={`${fmtInt(data.kpis.activeSources)}/${fmtInt(data.kpis.totalSources)}`}
              detail="reporting or recently seen"
              color={data.kpis.activeSources > 0 ? GREEN : RED}
            />
            <KpiCard
              label="Assets Covered"
              value={`${fmtInt(data.kpis.assetsCovered)}/${fmtInt(data.kpis.assetsTotal)}`}
              detail="observed by any channel"
              color={data.kpis.assetsCovered === data.kpis.assetsTotal ? GREEN : AMBER}
            />
            <KpiCard label="Corroborated" value={fmtInt(data.kpis.corroboratedAssets)} detail="confirmed by 2+ channels" color={BLUE} />
            <KpiCard
              label="Blind Spots"
              value={fmtInt(data.kpis.blindSpots)}
              detail="no telemetry at all"
              color={data.kpis.blindSpots > 0 ? RED : GREEN}
              footnote={data.kpis.blindSpots > 0 ? 'posture unknown, not safe' : undefined}
            />
            <KpiCard
              label="Conflicts"
              value={fmtInt(data.kpis.conflicts)}
              detail="sources disagree"
              color={data.kpis.conflicts > 0 ? RED : GREEN}
            />
          </section>

          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
            <Panel className="p-5">
              <SectionHeading title="Telemetry Coverage" icon={Network} />
              <div className="flex flex-col items-center gap-5 sm:flex-row">
                <ScoreDial score={data.coverageScore.score} level={data.coverageScore.level} />
                <div className="min-w-0 flex-1">
                  <p className="text-[13px] font-semibold leading-relaxed text-white/75">{data.coverageScore.statement}</p>
                  <div className="mt-3 rounded-lg border border-white/10 bg-black/25 p-3">
                    <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">How this is calculated</div>
                    <p className="mt-1 text-[11px] leading-relaxed text-white/50">{data.coverageScore.basis}</p>
                  </div>
                </div>
              </div>
            </Panel>

            <Panel className="p-5">
              <SectionHeading title="Coverage Tiers" icon={LayoutList} />
              <DistributionBars
                rows={data.coverage.map((c) => ({
                  key: c.key === 'corroborated' ? 'low' : c.key === 'single-source' ? 'medium' : 'unassessed',
                  label: c.label,
                  glyph: c.glyph,
                  count: c.count,
                  percent: c.percent,
                }))}
                total={data.kpis.assetsTotal}
                unitLabel="Discovered assets"
              />
              <ul className="mt-4 space-y-1.5 border-t border-white/8 pt-3">
                {data.coverage.map((c) => (
                  <li key={c.key} className="text-[10px] leading-relaxed text-white/35">
                    <span className="font-black text-white/55">{c.label}:</span> {c.detail}
                  </li>
                ))}
              </ul>
            </Panel>
          </div>

          <Panel className="p-5">
            <SectionHeading title="Telemetry Sources" icon={Antenna} meta={`${fmtInt(data.sources.length)} registered`} />
            {data.sources.length === 0 ? (
              <EmptyRow>No telemetry source is registered for this environment.</EmptyRow>
            ) : (
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {data.sources.map((source) => (
                  <div key={source.id} className="rounded-xl border border-white/10 bg-black/20 p-4">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="truncate text-[12.5px] font-black text-white/90">{source.name}</div>
                        <div className="mt-0.5 text-[9.5px] text-white/35">{source.kindLabel}</div>
                      </div>
                      <span
                        className="inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2 py-0.5 text-[8.5px] font-black uppercase tracking-wider"
                        style={{ borderColor: `${HEALTH_HEX[source.health]}55`, backgroundColor: `${HEALTH_HEX[source.health]}16`, color: HEALTH_HEX[source.health] }}
                      >
                        <span aria-hidden="true">{HEALTH_GLYPH[source.health]}</span>
                        {HEALTH_LABEL[source.health]}
                      </span>
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-2">
                      <div className="rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-2">
                        <div className="text-[8px] font-black uppercase tracking-wider text-white/30">Observations</div>
                        <div className="font-mono text-[15px] font-black text-white/85">{fmtInt(source.observations)}</div>
                      </div>
                      <div className="rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-2">
                        <div className="text-[8px] font-black uppercase tracking-wider text-white/30">Assets seen</div>
                        <div className="font-mono text-[15px] font-black text-white/85">{fmtInt(source.assetsObserved)}</div>
                      </div>
                    </div>
                    <div className="mt-2 text-[10px] text-white/35">Last seen {relativeTime(source.lastSeenAt)}</div>
                    <div className="mt-0.5 truncate text-[9.5px] text-white/25">{source.detail}</div>
                  </div>
                ))}
              </div>
            )}
          </Panel>

          <IntelTabs<TabKey>
            idPrefix="corr"
            active={tab}
            onChange={setTab}
            tabs={[
              { key: 'coverage' as TabKey, label: 'Blind Spots', badge: data.kpis.blindSpots || undefined },
              { key: 'conflicts' as TabKey, label: 'Conflicts', badge: data.kpis.conflicts || undefined },
              { key: 'observations' as TabKey, label: 'Observations' },
            ]}
          />

          {tab === 'coverage' ? (
            <div id="corr-panel-coverage" role="tabpanel" aria-labelledby="corr-tab-coverage" className="space-y-4">
              <Panel className="p-5">
                <SectionHeading
                  title="Blind Spots"
                  icon={EyeOff}
                  meta={`${fmtInt(data.blindSpots.length)} asset(s) with no telemetry`}
                  action={<LinkButton href="/dashboard/scanner">Scan these assets</LinkButton>}
                />
                {data.blindSpots.length === 0 ? (
                  <div className="rounded-lg border border-emerald-400/25 bg-emerald-500/[0.06] px-4 py-6 text-center">
                    <div className="text-[12.5px] font-black text-emerald-200">Full telemetry coverage</div>
                    <p className="mx-auto mt-1 max-w-md text-[11.5px] leading-relaxed text-white/45">
                      Every discovered asset is observed by at least one telemetry channel.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {data.blindSpots.map((spot) => (
                      <div key={spot.assetId} className="flex flex-wrap items-start gap-3 rounded-lg border border-white/8 bg-white/[0.02] p-3">
                        <EyeOff className="mt-0.5 h-4 w-4 shrink-0 text-red-300" aria-hidden="true" />
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-[12.5px] font-black text-white/90">{spot.assetName}</span>
                            {spot.internetFacing ? <StatusPill level="critical" label="Internet-facing" /> : null}
                          </div>
                          <div className="mt-0.5 flex flex-wrap gap-x-2 text-[10.5px] text-white/40">
                            <span>{spot.type}</span>
                            <span>· {spot.environment}</span>
                            <span>· {spot.businessCriticality}</span>
                          </div>
                          <p className="mt-1.5 text-[11px] leading-relaxed text-white/45">{spot.why}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Panel>
            </div>
          ) : null}

          {tab === 'conflicts' ? (
            <div id="corr-panel-conflicts" role="tabpanel" aria-labelledby="corr-tab-conflicts" className="space-y-4">
              <Panel className="p-5">
                <SectionHeading title="Source Disagreement" icon={GitMerge} meta={`${fmtInt(data.conflicts.length)} conflict(s)`} />
                {data.conflicts.length === 0 ? (
                  <div className="rounded-lg border border-emerald-400/25 bg-emerald-500/[0.06] px-4 py-6 text-center">
                    <div className="text-[12.5px] font-black text-emerald-200">No source disagreement</div>
                    <p className="mx-auto mt-1 max-w-lg text-[11.5px] leading-relaxed text-white/45">
                      Every asset seen by two or more channels is reported consistently by all of them.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {data.conflicts.map((conflict) => (
                      <div key={conflict.id} className="rounded-xl border border-white/10 bg-black/20 p-4">
                        <div className="flex flex-wrap items-start gap-3">
                          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" aria-hidden="true" />
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="text-[12.5px] font-black text-white/90">{conflict.summary}</span>
                              <StatusPill level={conflict.severity} />
                              {conflict.environment !== 'unspecified' ? (
                                <span className="text-[10px] text-white/35">{conflict.environment}</span>
                              ) : null}
                            </div>
                            <p className="mt-1.5 text-[11.5px] leading-relaxed text-white/55">{conflict.why}</p>

                            <div className="mt-3 overflow-x-auto">
                              <table className="w-full min-w-[420px] border-collapse text-left">
                                <caption className="sr-only">What each source reported for {conflict.assetName}</caption>
                                <thead>
                                  <tr className="text-[8.5px] font-black uppercase tracking-[0.14em] text-white/30">
                                    <th scope="col" className="py-1 pr-3 font-black">Source</th>
                                    <th scope="col" className="py-1 pr-3 font-black">Reported</th>
                                    <th scope="col" className="py-1 pr-3 font-black">Verdict</th>
                                    <th scope="col" className="py-1 font-black">Observed</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {conflict.readings.map((reading, i) => (
                                    <tr key={i} className="border-t border-white/5">
                                      <td className="py-1.5 pr-3 text-[11px] text-white/60">{reading.source}</td>
                                      <td className="py-1.5 pr-3 font-mono text-[10.5px] text-white/70">{reading.algorithm}</td>
                                      <td className="py-1.5 pr-3 text-[10.5px] font-black" style={{ color: CLASS_HEX[reading.quantumClass] }}>
                                        {reading.quantumClass}
                                      </td>
                                      <td className="py-1.5 text-[10px] text-white/35">{relativeTime(reading.observedAt)}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>

                            <div className="mt-3 rounded-lg border border-cyan-400/25 bg-cyan-500/[0.07] px-3 py-2">
                              <div className="text-[8.5px] font-black uppercase tracking-wider text-cyan-300/80">Recommended action</div>
                              <p className="mt-0.5 text-[11.5px] leading-relaxed text-white/75">{conflict.recommendedAction}</p>
                            </div>
                            <div className="mt-2.5"><LinkButton href={conflict.href} tone="ghost">Open asset</LinkButton></div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Panel>
            </div>
          ) : null}

          {tab === 'observations' ? (
            <div id="corr-panel-observations" role="tabpanel" aria-labelledby="corr-tab-observations" className="space-y-4">
              {showFilters ? (
                <FilterBar data={data} filters={filters} onChange={patch} onClear={() => setFilters(EMPTY_CORRELATION_FILTERS)} count={observations.length} />
              ) : null}
              <Panel className="p-5">
                <SectionHeading title="Correlated Observations" icon={GitMerge} meta={`${fmtInt(observations.length)} of ${fmtInt(data.observations.length)}`} />
                {observations.length === 0 ? (
                  <EmptyRow>No observation matched the current filters.</EmptyRow>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[700px] border-collapse text-left">
                      <caption className="sr-only">Cryptographic observations ranked by how many independent channels confirmed them</caption>
                      <thead>
                        <tr className="border-b border-white/10 text-[8.5px] font-black uppercase tracking-[0.14em] text-white/35">
                          <th scope="col" className="py-2 pr-3 font-black">Asset</th>
                          <th scope="col" className="py-2 pr-3 font-black">Algorithm</th>
                          <th scope="col" className="py-2 pr-3 font-black">Verdict</th>
                          <th scope="col" className="py-2 pr-3 font-black">Confirmed by</th>
                          <th scope="col" className="py-2 pr-3 font-black text-right">Sightings</th>
                          <th scope="col" className="py-2 font-black">Last seen</th>
                        </tr>
                      </thead>
                      <tbody>
                        {observations.map((row) => (
                          <tr key={row.id} className="border-b border-white/5 last:border-0">
                            <td className="max-w-[200px] truncate py-2.5 pr-3 text-[12px] font-semibold text-white/85">{row.assetName}</td>
                            <td className="max-w-[180px] truncate py-2.5 pr-3 font-mono text-[11px] text-white/70">{row.algorithm}</td>
                            <td className="py-2.5 pr-3 text-[10.5px] font-black" style={{ color: CLASS_HEX[row.quantumClass] }}>{row.quantumClass}</td>
                            <td className="py-2.5 pr-3">
                              <div className="flex flex-wrap gap-1">
                                {row.sources.map((s) => (
                                  <span key={s} className={cn('rounded border px-1.5 py-0.5 text-[9px]', row.sourceCount >= 2 ? 'border-blue-400/30 bg-blue-500/10 text-blue-200' : 'border-white/10 bg-white/[0.03] text-white/50')}>{s}</span>
                                ))}
                              </div>
                            </td>
                            <td className="py-2.5 pr-3 text-right font-mono text-[11.5px] text-white/60">{fmtInt(row.observations)}</td>
                            <td className="py-2.5 text-[10.5px] text-white/40">{relativeTime(row.lastSeenAt)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Panel>
            </div>
          ) : null}

          {data.reads?.length ? <EvidenceSources sources={data.reads} /> : null}
          <SourceNote>{data.evidence.note}</SourceNote>
        </>
      ) : null}
    </IntelShell>
  );
}

function FilterBar({
  data, filters, onChange, onClear, count,
}: {
  data: CorrelationIntelligence;
  filters: CorrelationFilters;
  onChange: (n: Partial<CorrelationFilters>) => void;
  onClear: () => void;
  count: number;
}) {
  const select = (label: string, key: keyof CorrelationFilters, options: string[]) => (
    <div className="flex min-w-0 flex-col gap-1">
      <label htmlFor={`corr-${key}`} className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/35">{label}</label>
      <select
        id={`corr-${key}`}
        value={filters[key] as string}
        onChange={(e) => onChange({ [key]: e.target.value } as Partial<CorrelationFilters>)}
        className="rounded-lg border border-white/12 bg-[#0b1424] px-2.5 py-1.5 text-[11px] font-semibold text-white/80 outline-none transition focus-visible:border-cyan-400/50 focus-visible:ring-2 focus-visible:ring-cyan-300/40"
      >
        <option value="all">All</option>
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    </div>
  );
  return (
    <Panel className="p-4">
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex min-w-[220px] flex-1 flex-col gap-1">
          <label htmlFor="corr-search" className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/35">Search</label>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/30" aria-hidden="true" />
            <input
              id="corr-search"
              type="search"
              value={filters.search}
              onChange={(e) => onChange({ search: e.target.value })}
              placeholder="Search assets, algorithms, sources…"
              className="w-full rounded-lg border border-white/12 bg-[#0b1424] py-1.5 pl-8 pr-2.5 text-[11.5px] text-white/85 outline-none transition placeholder:text-white/25 focus-visible:border-cyan-400/50 focus-visible:ring-2 focus-visible:ring-cyan-300/40"
            />
          </div>
        </div>
        {select('Environment', 'environment', data.filters.environments)}
        {select('Source', 'source', data.filters.sources)}
        {select('Confirmation', 'tier', ['corroborated', 'single-source'])}
        <div className="flex items-center gap-2 pb-0.5">
          <span className="font-mono text-[10px] text-white/35">{fmtInt(count)} observations</span>
          <button type="button" onClick={onClear} className="inline-flex items-center gap-1 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-white/55 transition hover:bg-white/[0.08]">
            <X className="h-3 w-3" aria-hidden="true" /> Clear
          </button>
        </div>
      </div>
    </Panel>
  );
}

function sophiaContext(data: CorrelationIntelligence | null): string {
  if (!data) return 'Telemetry Correlation — no data loaded.';
  if (!data.hasTelemetry) return 'Telemetry Correlation — no source has reported, so coverage cannot be measured.';
  return [
    'Page: Telemetry Correlation.',
    `Coverage ${data.coverageScore.score ?? 'n/a'}/100 (${data.coverageScore.level}).`,
    `${data.kpis.assetsCovered} of ${data.kpis.assetsTotal} asset(s) covered, ${data.kpis.corroboratedAssets} corroborated by 2+ channels, ${data.kpis.blindSpots} blind spot(s).`,
    `${data.kpis.activeSources} of ${data.kpis.totalSources} source(s) reporting.`,
    data.kpis.conflicts > 0 ? `${data.kpis.conflicts} source conflict(s): ${data.conflicts[0]?.summary}.` : 'No source disagreement.',
  ].join(' ');
}
