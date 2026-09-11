'use client';

import { useCallback, useMemo, useState } from 'react';
import {
  ArrowRight, Filter, GitCompare, History, LayoutList, RefreshCw, ScanLine,
  Search, Sparkles, TrendingDown, X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { askSophia } from '@/lib/sophia-bridge';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { Panel } from '../_components/executive/primitives';
import { useDriftDetection } from '@/hooks/use-drift-detection';
import {
  CLASS_LABEL, EMPTY_DRIFT_FILTERS, filterDriftEvents,
  type DriftClass, type DriftEvent, type DriftFilters, type DriftIntelligence,
} from '@/lib/drift/drift-intelligence';
import {
  AMBER, ConnectionLostBanner, DistributionBars, EmptyRow, GREEN, HardErrorPanel, HeaderButton,
  IntelHeader, IntelShell, IntelTabs, KpiCard, LinkButton, NoEvidenceState, PrimaryButton, RED,
  ScoreDial, SectionHeading, SkeletonGrid, SourceNote, StatusPill,
  fmtInt, fullTimestamp, relativeTime,
} from '../_components/intel/kit';

type TabKey = 'changes' | 'assets' | 'baseline';

/** Drift classes carry their own colour vocabulary — not a severity scale. */
const CLASS_HEX: Record<DriftClass, string> = {
  regression: RED,
  improvement: GREEN,
  planned: '#60a5fa',
  coverage: '#94a3b8',
  persistent: '#94a3b8',
};

/**
 * Cryptographic Drift Detection.
 *
 * Answers one question the other pages cannot: WHAT CHANGED, and was it
 * supposed to?
 *
 * Drift needs a baseline, so this page refuses to report drift until two
 * completed scans exist — the first scan's findings are an inventory, not a set
 * of changes. And a change explained by an approved migration is reported as
 * PLANNED, because counting successful remediation as drift trains operators to
 * ignore the alert that matters.
 */
export default function DriftDetection() {
  const { data, state, error, live, lastGoodAt, refresh, reconnect } = useDriftDetection();

  const [tab, setTab] = useState<TabKey>('changes');
  const [filters, setFilters] = useState<DriftFilters>(EMPTY_DRIFT_FILTERS);
  const [showFilters, setShowFilters] = useState(false);
  const [selected, setSelected] = useState<DriftEvent | null>(null);

  const events = useMemo(() => (data ? filterDriftEvents(data.events, filters) : []), [data, filters]);
  const ask = useCallback((question: string) => askSophia(question, sophiaContext(data)), [data]);
  const patch = useCallback((next: Partial<DriftFilters>) => setFilters((c) => ({ ...c, ...next })), []);

  const showSkeleton = state === 'loading' && !data;
  const showHardError = state === 'error' && !data;
  const noBaseline = Boolean(data && !data.hasBaseline);

  return (
    <IntelShell name="drift-shell">
      <WorkflowRail activeStage="monitoring" />

      <IntelHeader
        title="Cryptographic"
        accent="Drift Detection"
        subtitle="See what changed in your cryptography since the last scan, whether the change was planned, and what needs attention."
        icon={GitCompare}
        live={live}
        lastUpdated={data?.generatedAt ?? lastGoodAt}
        connecting={state === 'loading' && !data}
      >
        <HeaderButton onClick={() => setShowFilters((v) => !v)} icon={Filter} active={showFilters}>Filters</HeaderButton>
        <button
          type="button"
          onClick={() => ask('What changed in my cryptography since the last scan, and was any of it unplanned?')}
          className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/45 bg-violet-500/12 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/22"
        >
          <Sparkles className="h-3.5 w-3.5" aria-hidden="true" /> Ask Sophia
        </button>
        <PrimaryButton onClick={() => void refresh(true)} icon={RefreshCw} spin={state === 'loading'}>Refresh</PrimaryButton>
      </IntelHeader>

      {data && !live && state !== 'loading' ? (
        <ConnectionLostBanner lastGoodAt={lastGoodAt} error={error} onReconnect={reconnect} />
      ) : null}

      {showHardError ? (
        <HardErrorPanel
          title="Drift Assessment Unavailable"
          message="QGuard Helix could not compare your scan history. No values are shown rather than presenting zeros as fact."
          error={error}
          onRetry={reconnect}
        />
      ) : null}

      {showSkeleton ? <SkeletonGrid cards={4} panels={2} /> : null}

      {noBaseline && data ? (
        <NoEvidenceState
          icon={ScanLine}
          title="No Baseline to Compare Against"
          body={data.baseline.note}
          bullets={[
            'Drift is change from a known baseline — it needs two observations of the same estate at two points in time.',
            'The findings from a single scan are an inventory, not a set of changes; they are shown on Quantum Risk Analysis.',
            'Once a second scan completes, this page reports what appeared, what disappeared, and which changes an approved migration explains.',
          ]}
          actions={[
            { href: '/dashboard/scanner', label: 'Run a Scan', primary: true },
            { href: '/dashboard/quantum-readiness/risk-analysis', label: 'Quantum Risk Analysis' },
          ]}
        />
      ) : null}

      {data && data.hasBaseline ? (
        <>
          <section aria-label="Drift metrics" className="grid grid-cols-2 gap-2.5 lg:grid-cols-3 xl:grid-cols-6">
            <KpiCard label="Regressions" value={fmtInt(data.kpis.regressions)} detail="unplanned, posture worsened" color={data.kpis.regressions > 0 ? RED : GREEN} />
            <KpiCard label="Improvements" value={fmtInt(data.kpis.improvements)} detail="unplanned, posture improved" color={GREEN} />
            <KpiCard label="Planned" value={fmtInt(data.kpis.planned)} detail="explained by a migration" color="#60a5fa" footnote="not counted as drift" />
            <KpiCard label="Unplanned" value={fmtInt(data.kpis.unplannedChanges)} detail="changes with no approved plan" color={data.kpis.unplannedChanges > 0 ? AMBER : GREEN} />
            <KpiCard label="Assets Changed" value={fmtInt(data.kpis.assetsChanged)} detail="since the baseline scan" color="#22d3ee" />
            <KpiCard label="Runtime Downgrades" value={fmtInt(data.kpis.runtimeDowngrades)} detail="observed by the collector" color={data.kpis.runtimeDowngrades > 0 ? RED : GREEN} />
          </section>

          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
            <StabilityPanel data={data} />
            <Panel className="p-5">
              <SectionHeading title="Change Breakdown" icon={LayoutList} />
              <DistributionBars
                rows={data.summary.map((r) => ({ key: r.key, label: r.label, glyph: r.glyph, count: r.count, percent: r.percent }))}
                total={data.events.length}
                unitLabel="Detected changes"
              />
              <p className="mt-4 border-t border-white/8 pt-3 text-[10px] leading-relaxed text-white/30">
                Planned changes are shown for completeness but excluded from the unplanned-change count. A successful
                migration is the system working, not drift.
              </p>
            </Panel>
          </div>

          <IntelTabs<TabKey>
            idPrefix="drift"
            active={tab}
            onChange={setTab}
            tabs={[
              { key: 'changes' as TabKey, label: 'Changes', badge: data.kpis.regressions || undefined },
              { key: 'assets' as TabKey, label: 'By Asset' },
              { key: 'baseline' as TabKey, label: 'Baseline' },
            ]}
          />

          {showFilters ? (
            <FilterBar data={data} filters={filters} onChange={patch} onClear={() => setFilters(EMPTY_DRIFT_FILTERS)} count={events.length} />
          ) : null}

          {tab === 'changes' ? (
            <div id="drift-panel-changes" role="tabpanel" aria-labelledby="drift-tab-changes" className="space-y-4">
              <Panel className="p-5">
                <SectionHeading title="Detected Changes" icon={GitCompare} meta={`${fmtInt(events.length)} of ${fmtInt(data.events.length)}`} />
                {events.length === 0 ? (
                  <EmptyRow>
                    {data.events.length === 0
                      ? 'No cryptographic change was detected between the two most recent scans.'
                      : 'No change matched the current filters.'}
                  </EmptyRow>
                ) : (
                  <div className="space-y-2">
                    {events.map((event) => <ChangeRow key={event.id} event={event} onSelect={setSelected} />)}
                  </div>
                )}
              </Panel>
            </div>
          ) : null}

          {tab === 'assets' ? (
            <div id="drift-panel-assets" role="tabpanel" aria-labelledby="drift-tab-assets" className="space-y-4">
              <Panel className="p-5">
                <SectionHeading title="Change by Asset" icon={LayoutList} meta={`${fmtInt(data.byAsset.length)} assets`} />
                {data.byAsset.length === 0 ? (
                  <EmptyRow>No asset changed between the two most recent scans.</EmptyRow>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[600px] border-collapse text-left">
                      <caption className="sr-only">Assets ranked by unplanned regression count</caption>
                      <thead>
                        <tr className="border-b border-white/10 text-[8.5px] font-black uppercase tracking-[0.14em] text-white/35">
                          <th scope="col" className="py-2 pr-3 font-black">Asset</th>
                          <th scope="col" className="py-2 pr-3 font-black">Environment</th>
                          <th scope="col" className="py-2 pr-3 font-black text-right">Regressions</th>
                          <th scope="col" className="py-2 pr-3 font-black text-right">Improvements</th>
                          <th scope="col" className="py-2 pr-3 font-black text-right">Planned</th>
                          <th scope="col" className="py-2 font-black text-right">Net</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.byAsset.map((row) => (
                          <tr key={row.assetName} className="border-b border-white/5 last:border-0">
                            <td className="max-w-[220px] truncate py-2.5 pr-3 text-[12px] font-semibold text-white/85">{row.assetName}</td>
                            <td className="py-2.5 pr-3 text-[11px] text-white/50">{row.environment}</td>
                            <td className="py-2.5 pr-3 text-right font-mono text-[11.5px]" style={{ color: row.regressions > 0 ? RED : 'rgba(255,255,255,0.4)' }}>{fmtInt(row.regressions)}</td>
                            <td className="py-2.5 pr-3 text-right font-mono text-[11.5px]" style={{ color: row.improvements > 0 ? GREEN : 'rgba(255,255,255,0.4)' }}>{fmtInt(row.improvements)}</td>
                            <td className="py-2.5 pr-3 text-right font-mono text-[11.5px] text-blue-300">{fmtInt(row.planned)}</td>
                            <td className="py-2.5 text-right font-mono text-[12px] font-black" style={{ color: row.netChange < 0 ? RED : row.netChange > 0 ? GREEN : 'rgba(255,255,255,0.4)' }}>
                              {row.netChange > 0 ? '+' : ''}{row.netChange}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Panel>
            </div>
          ) : null}

          {tab === 'baseline' ? (
            <div id="drift-panel-baseline" role="tabpanel" aria-labelledby="drift-tab-baseline" className="space-y-4">
              <Panel className="p-5">
                <SectionHeading title="Comparison Window" icon={History} />
                <div className="grid gap-3 md:grid-cols-2">
                  {([
                    ['Baseline scan', data.baseline.baselineSessionId, data.baseline.baselineAt],
                    ['Current scan', data.baseline.currentSessionId, data.baseline.currentAt],
                  ] as Array<[string, string | null, string | null]>).map(([label, id, at]) => (
                    <div key={label} className="rounded-xl border border-white/10 bg-black/20 p-4">
                      <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">{label}</div>
                      <div className="mt-1 font-mono text-[12px] text-white/75">{id ? id.slice(0, 8) : '—'}</div>
                      <div className="mt-1 text-[11px] text-white/45">{fullTimestamp(at)}</div>
                      <div className="mt-0.5 text-[10px] text-white/30">{relativeTime(at)}</div>
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-[11px] leading-relaxed text-white/45">{data.baseline.note}</p>
                <div className="mt-2 text-[10px] text-white/30">
                  {fmtInt(data.baseline.totalSessions)} scan session(s) recorded; the two most recent completed scans are compared.
                </div>
              </Panel>

              {data.postureDelta ? (
                <Panel className="p-5">
                  <SectionHeading title="Posture Movement" icon={TrendingDown} meta="baseline → current" />
                  <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                    {([
                      ['Findings at baseline', fmtInt(data.postureDelta.baselineFindings), 'rgba(255,255,255,0.75)'],
                      ['Findings now', fmtInt(data.postureDelta.currentFindings), data.postureDelta.delta > 0 ? RED : GREEN],
                      ['Vulnerable at baseline', fmtInt(data.postureDelta.baselineVulnerable), 'rgba(255,255,255,0.75)'],
                      ['Vulnerable now', fmtInt(data.postureDelta.currentVulnerable), data.postureDelta.currentVulnerable > data.postureDelta.baselineVulnerable ? RED : GREEN],
                    ] as Array<[string, string, string]>).map(([label, value, hex]) => (
                      <div key={label} className="rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2.5">
                        <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">{label}</div>
                        <div className="mt-1 font-mono text-[20px] font-black" style={{ color: hex }}>{value}</div>
                      </div>
                    ))}
                  </div>
                  <p className="mt-3 text-[10px] leading-relaxed text-white/30">
                    Two measured points, not a trend line. Vulnerability is classified by the shared cipher-suite
                    decomposer, so an algorithm reads the same here as on every other page.
                  </p>
                </Panel>
              ) : null}
            </div>
          ) : null}

          <SourceNote>{data.evidence.note}</SourceNote>
        </>
      ) : null}

      <ChangeDrawer event={selected} onClose={() => setSelected(null)} onAsk={ask} />
    </IntelShell>
  );
}

/* ================================================================== */

function StabilityPanel({ data }: { data: DriftIntelligence }) {
  const s = data.stability;
  return (
    <Panel className="p-5">
      <SectionHeading title="Cryptographic Stability" icon={GitCompare} meta={`baseline ${relativeTime(data.baseline.baselineAt)}`} />
      <div className="flex flex-col items-center gap-5 sm:flex-row">
        <ScoreDial score={s.score} level={s.level} />
        <div className="min-w-0 flex-1">
          <p className="text-[13px] font-semibold leading-relaxed text-white/75">{s.statement}</p>
          <div className="mt-3 rounded-lg border border-white/10 bg-black/25 p-3">
            <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">How this is calculated</div>
            <p className="mt-1 text-[11px] leading-relaxed text-white/50">{s.basis}</p>
          </div>
        </div>
      </div>
    </Panel>
  );
}

function ChangeRow({ event, onSelect }: { event: DriftEvent; onSelect: (e: DriftEvent) => void }) {
  const hex = CLASS_HEX[event.driftClass];
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onSelect(event)}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(event); } }}
      className="cursor-pointer rounded-lg border border-white/8 bg-white/[0.02] p-3 outline-none transition hover:border-white/15 focus-visible:ring-2 focus-visible:ring-cyan-300/70"
      aria-label={`${CLASS_LABEL[event.driftClass]}: ${event.summary}`}
    >
      <div className="flex flex-wrap items-start gap-3">
        <span className="mt-0.5 text-[13px] leading-none" style={{ color: hex }} aria-hidden="true">
          {event.driftClass === 'regression' ? '●' : event.driftClass === 'improvement' ? '✓' : event.driftClass === 'coverage' ? '◇' : '◐'}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[12.5px] font-black text-white/90">{event.summary}</span>
            <span
              className="rounded-full border px-2 py-0.5 text-[8.5px] font-black uppercase tracking-wider"
              style={{ borderColor: `${hex}55`, backgroundColor: `${hex}16`, color: hex }}
            >
              {CLASS_LABEL[event.driftClass]}
            </span>
            {event.driftClass === 'regression' ? <StatusPill level={event.severity} /> : null}
          </div>

          <div className="mt-1.5 flex flex-wrap items-center gap-2 font-mono text-[10.5px]">
            <span className={cn(event.before ? 'text-white/55' : 'text-white/25')}>{event.before ?? 'not present'}</span>
            <ArrowRight className="h-3 w-3 text-white/25" aria-hidden="true" />
            <span className={cn(event.after ? 'text-white/80' : 'text-white/25')}>{event.after ?? 'no longer detected'}</span>
          </div>

          <div className="mt-1 flex flex-wrap gap-x-2 text-[10.5px] text-white/40">
            <span className="font-semibold text-white/60">{event.assetName}</span>
            {event.environment !== 'unspecified' ? <span>· {event.environment}</span> : null}
            <span>· {relativeTime(event.detectedAt)}</span>
            {event.explainedBy ? <span>· explained by {event.explainedBy}</span> : null}
          </div>
        </div>
      </div>
    </div>
  );
}

function FilterBar({
  data, filters, onChange, onClear, count,
}: {
  data: DriftIntelligence;
  filters: DriftFilters;
  onChange: (n: Partial<DriftFilters>) => void;
  onClear: () => void;
  count: number;
}) {
  const select = (label: string, key: keyof DriftFilters, options: string[]) => (
    <div className="flex min-w-0 flex-col gap-1">
      <label htmlFor={`drift-${key}`} className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/35">{label}</label>
      <select
        id={`drift-${key}`}
        value={filters[key] as string}
        onChange={(e) => onChange({ [key]: e.target.value } as Partial<DriftFilters>)}
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
          <label htmlFor="drift-search" className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/35">Search</label>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/30" aria-hidden="true" />
            <input
              id="drift-search"
              type="search"
              value={filters.search}
              onChange={(e) => onChange({ search: e.target.value })}
              placeholder="Search assets, algorithms…"
              className="w-full rounded-lg border border-white/12 bg-[#0b1424] py-1.5 pl-8 pr-2.5 text-[11.5px] text-white/85 outline-none transition placeholder:text-white/25 focus-visible:border-cyan-400/50 focus-visible:ring-2 focus-visible:ring-cyan-300/40"
            />
          </div>
        </div>
        {select('Change type', 'driftClass', data.filters.classes)}
        {select('Environment', 'environment', data.filters.environments)}
        {select('Severity', 'severity', ['critical', 'high', 'medium', 'low'])}
        <div className="flex items-center gap-2 pb-0.5">
          <span className="font-mono text-[10px] text-white/35">{fmtInt(count)} changes</span>
          <button type="button" onClick={onClear} className="inline-flex items-center gap-1 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-white/55 transition hover:bg-white/[0.08]">
            <X className="h-3 w-3" aria-hidden="true" /> Clear
          </button>
        </div>
      </div>
    </Panel>
  );
}

function ChangeDrawer({ event, onClose, onAsk }: { event: DriftEvent | null; onClose: () => void; onAsk: (q: string) => void }) {
  if (!event) return null;
  const hex = CLASS_HEX[event.driftClass];
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/55" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div role="dialog" aria-modal="true" aria-label={`Change detail: ${event.summary}`} className="flex h-full w-full max-w-[500px] flex-col overflow-y-auto border-l border-white/12 bg-[#0b1424] shadow-2xl">
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-white/10 bg-[#0b1424]/95 px-5 py-4 backdrop-blur">
          <div className="min-w-0">
            <h2 className="text-[15px] font-black leading-snug text-white">{event.summary}</h2>
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <span className="rounded-full border px-2 py-0.5 text-[8.5px] font-black uppercase tracking-wider" style={{ borderColor: `${hex}55`, backgroundColor: `${hex}16`, color: hex }}>
                {CLASS_LABEL[event.driftClass]}
              </span>
              {event.driftClass === 'regression' ? <StatusPill level={event.severity} /> : null}
            </div>
          </div>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded-lg border border-white/12 bg-white/[0.04] p-1.5 text-white/50 transition hover:bg-white/[0.08]">
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="space-y-4 px-5 py-5">
          <div className="rounded-xl border border-white/10 bg-black/20 p-4">
            <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">Before → After</div>
            <div className="mt-2 flex flex-wrap items-center gap-2 font-mono text-[12px]">
              <span className={cn('rounded border px-2 py-1', event.before ? 'border-white/10 bg-white/[0.03] text-white/60' : 'border-white/5 text-white/25')}>
                {event.before ?? 'not present'}
              </span>
              <ArrowRight className="h-3.5 w-3.5 text-white/25" aria-hidden="true" />
              <span className={cn('rounded border px-2 py-1', event.after ? 'border-cyan-400/30 bg-cyan-500/10 text-cyan-200' : 'border-white/5 text-white/25')}>
                {event.after ?? 'no longer detected'}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            {([
              ['Asset', event.assetName],
              ['Environment', event.environment],
              ['Owner', event.owner],
              ['Detected', relativeTime(event.detectedAt)],
            ] as Array<[string, string]>).map(([label, value]) => (
              <div key={label}>
                <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">{label}</div>
                <div className="mt-0.5 text-[12px] text-white/80">{value}</div>
              </div>
            ))}
          </div>

          <div>
            <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">Why it matters</div>
            <p className="mt-1 text-[12px] leading-relaxed text-white/60">{event.why}</p>
          </div>

          <div className="rounded-xl border border-cyan-400/25 bg-cyan-500/[0.07] p-3.5">
            <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-cyan-300/80">Recommended action</div>
            <p className="mt-1 text-[12px] leading-relaxed text-white/80">{event.recommendedAction}</p>
          </div>

          {event.explainedBy ? (
            <div className="rounded-xl border border-blue-400/25 bg-blue-500/[0.07] p-3.5">
              <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-blue-300/80">Planned change</div>
              <p className="mt-1 text-[11.5px] leading-relaxed text-white/70">
                This change is explained by {event.explainedBy}, so it is not counted as drift.
              </p>
            </div>
          ) : null}

          {event.evidence.length ? (
            <div className="rounded-xl border border-white/10 bg-black/20 p-3.5">
              <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">Evidence</div>
              <ul className="mt-2 space-y-1">
                {event.evidence.map((line, i) => <li key={i} className="text-[11px] leading-relaxed text-white/45">· {line}</li>)}
              </ul>
            </div>
          ) : null}

          <div className="flex flex-wrap gap-2 border-t border-white/8 pt-3">
            <LinkButton href={event.href}>Open asset</LinkButton>
            <LinkButton href="/dashboard/runtime-crypto-intel" tone="ghost">Runtime telemetry</LinkButton>
            <LinkButton href="/dashboard/quantum-readiness/risk-analysis" tone="ghost">Risk Analysis</LinkButton>
            <button
              type="button"
              onClick={() => onAsk(`On ${event.assetName}, ${event.summary}. Was this change expected, and what should I do about it?`)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/45 bg-violet-500/12 px-3 py-2 text-[9.5px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/22"
            >
              <Sparkles className="h-3.5 w-3.5" aria-hidden="true" /> Ask Sophia
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function sophiaContext(data: DriftIntelligence | null): string {
  if (!data) return 'Drift Detection — no data loaded.';
  if (!data.hasBaseline) return 'Drift Detection — no baseline yet; fewer than two completed scans exist, so no drift can be measured.';
  return [
    'Page: Cryptographic Drift Detection.',
    `Comparing scan ${data.baseline.baselineSessionId?.slice(0, 8)} (${data.baseline.baselineAt}) with ${data.baseline.currentSessionId?.slice(0, 8)} (${data.baseline.currentAt}).`,
    `Stability ${data.stability.score ?? 'n/a'}/100 (${data.stability.level}).`,
    `${data.kpis.regressions} regression(s), ${data.kpis.improvements} unplanned improvement(s), ${data.kpis.planned} planned change(s), ${data.kpis.runtimeDowngrades} runtime downgrade(s).`,
    data.events[0] ? `Most important: ${data.events[0].summary}.` : 'No change detected.',
  ].join(' ');
}
