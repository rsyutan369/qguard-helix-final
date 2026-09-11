'use client';

import { useCallback, useMemo, useState } from 'react';
import {
  Activity, AlertTriangle, Download, Filter, Flame, Gauge, Layers, ListTree,
  RefreshCw, ScanLine, Search, Sparkles, Target, TrendingDown, X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { askSophia } from '@/lib/sophia-bridge';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { Panel } from '../_components/executive/primitives';
import { useQuantumRisk } from '@/hooks/use-quantum-risk';
import {
  EMPTY_RISK_FILTERS, filterRiskAssets,
  type RiskAssetFilters, type RiskAssetRow, type QuantumRiskIntelligence,
} from '@/lib/quantum-risk/risk-intelligence';
import {
  AMBER, ConnectionLostBanner, DistributionBars, EmptyRow, GREEN, HardErrorPanel, HeaderButton,
  IntelHeader, IntelShell, IntelTabs, KpiCard, LinkButton, Meter, NoEvidenceState, PrimaryButton,
  RED, ScoreDial, SectionHeading, SkeletonGrid, SourceNote, StatusPill,
  fmtInt, fmtPct, fmtScore, levelHex, relativeTime,
} from '../_components/intel/kit';

type TabKey = 'overview' | 'assets' | 'drivers';

/**
 * Quantum Risk Scoring.
 *
 * The decomposition layer for the platform's quantum risk score. It answers
 * four questions and links out for everything else:
 *
 *     How exposed are we?   → the canonical score, read from Quantum Readiness
 *     Where does it live?   → per-asset decomposition from the shared portfolio
 *     What drives it?       → the snapshot's own evidence-based factors
 *     What would move it?   → projected reduction scenarios
 *
 * The headline is READ, never computed here. Every number on this page traces
 * to either the Quantum Readiness snapshot or the asset-intelligence portfolio,
 * and the provenance is printed on the page so a reader can check.
 */
export default function QuantumRiskScoring() {
  const { data, state, error, live, lastGoodAt, refresh, reconnect } = useQuantumRisk();

  const [tab, setTab] = useState<TabKey>('overview');
  const [filters, setFilters] = useState<RiskAssetFilters>(EMPTY_RISK_FILTERS);
  const [showFilters, setShowFilters] = useState(false);
  const [selected, setSelected] = useState<RiskAssetRow | null>(null);

  const assets = useMemo(() => (data ? filterRiskAssets(data.assets, filters) : []), [data, filters]);

  const ask = useCallback(
    (question: string) => askSophia(question, sophiaContext(data)),
    [data],
  );

  const patch = useCallback((next: Partial<RiskAssetFilters>) => setFilters((current) => ({ ...current, ...next })), []);
  const clear = useCallback(() => setFilters(EMPTY_RISK_FILTERS), []);

  const exportCsv = useCallback(() => {
    if (!data) return;
    const header = [
      '# QGuard Helix — Quantum Risk Scoring',
      `# Headline quantum risk: ${data.headline.score}/100 (${data.headline.level}) — source: Quantum Readiness snapshot`,
      `# Filters: environment=${filters.environment}, owner=${filters.owner}, criticality=${filters.criticality}, level=${filters.level}${filters.search.trim() ? `, search="${filters.search.trim()}"` : ''}`,
      `# Rows: ${assets.length} of ${data.assets.length}`,
    ].join('\n');
    const columns = ['Asset', 'Type', 'Environment', 'Owner', 'Criticality', 'Internet Facing', 'State', 'Risk Score', 'Risk Level', 'HNDL', 'Posture', 'Vulnerable Components', 'Blast Radius', 'Migration Status'];
    const cell = (v: unknown) => {
      const t = v === null || v === undefined ? '' : String(v);
      return /[",\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t;
    };
    const body = assets.map((row) => [
      row.name, row.type, row.environment, row.owner, row.businessCriticality, row.internetFacing ? 'yes' : 'no',
      row.state, row.riskScore ?? 'not assessed', row.riskLevel, row.hndlScore, row.postureLabel,
      row.vulnerableComponentCount, row.blastRadius, row.migrationStatus,
    ].map(cell).join(','));
    const blob = new Blob([`${header}\n${columns.join(',')}\n${body.join('\n')}\n`], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `qguard-quantum-risk-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [data, assets, filters]);

  const showSkeleton = state === 'loading' && !data;
  const showHardError = state === 'error' && !data;
  const showEmpty = Boolean(data && !data.hasData);

  return (
    <IntelShell name="qrs-shell">
      <WorkflowRail activeStage="assessment" />

      <IntelHeader
        title="Quantum"
        accent="Risk Scoring"
        subtitle="See how exposed the estate is to a cryptographically relevant quantum computer, which assets carry that exposure, what drives it, and what would reduce it."
        icon={Target}
        live={live}
        lastUpdated={data?.generatedAt ?? lastGoodAt}
        connecting={state === 'loading' && !data}
      >
        <HeaderButton onClick={() => setShowFilters((v) => !v)} icon={Filter} active={showFilters}>Filters</HeaderButton>
        <HeaderButton onClick={exportCsv} icon={Download} disabled={!data || assets.length === 0}>Export</HeaderButton>
        <button
          type="button"
          onClick={() => ask('Explain my quantum risk score: what is driving it and what should I fix first?')}
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
          title="Quantum Risk Assessment Unavailable"
          message="QGuard Helix could not retrieve the risk assessment. No values are shown rather than presenting zeros as fact."
          error={error}
          onRetry={reconnect}
        />
      ) : null}

      {showSkeleton ? <SkeletonGrid cards={5} panels={2} /> : null}

      {showEmpty && data ? (
        <NoEvidenceState
          icon={ScanLine}
          title="No Cryptographic Assessment Yet"
          body="QGuard Helix has not assessed this environment's cryptography, so there is no quantum risk score to publish. Nothing here is estimated."
          bullets={[
            'Discover assets and their cryptographic components with the PQC Scanner.',
            'The Quantum Readiness engine then publishes the canonical quantum risk, HNDL and exposure scores.',
            'This page decomposes those scores per asset, per factor and per remediation scenario.',
          ]}
          actions={[
            { href: '/dashboard/scanner', label: 'Run a Scan', primary: true },
            { href: '/dashboard/quantum-readiness', label: 'Quantum Readiness' },
          ]}
        />
      ) : null}

      {data && data.hasData ? (
        <>
          <IntelTabs<TabKey>
            idPrefix="qrs"
            active={tab}
            onChange={setTab}
            tabs={[
              { key: 'overview' as TabKey, label: 'Overview' },
              { key: 'assets' as TabKey, label: 'Assets' },
              { key: 'drivers' as TabKey, label: 'Drivers' },
            ]}
          />

          {showFilters ? (
            <RiskFilterBar data={data} filters={filters} onChange={patch} onClear={clear} count={assets.length} />
          ) : null}

          {tab === 'overview' ? (
            <div id="qrs-panel-overview" role="tabpanel" aria-labelledby="qrs-tab-overview" className="space-y-4">
              <section aria-label="Canonical risk scores" className="grid grid-cols-2 gap-2.5 lg:grid-cols-3 xl:grid-cols-5">
                {data.scoreCards.map((card) => (
                  <KpiCard
                    key={card.key}
                    label={card.label}
                    value={fmtScore(card.score)}
                    unit={card.score === null ? undefined : '/100'}
                    detail={card.detail}
                    color={card.score === null ? '#94a3b8' : levelHex(card.level)}
                    footnote={card.level}
                    href={card.href}
                  />
                ))}
              </section>

              <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
                <HeadlinePanel data={data} />
                <Panel className="p-5">
                  <SectionHeading title="Finding Severity" icon={Layers} meta="from Quantum Readiness" />
                  <DistributionBars
                    rows={data.findingDistribution}
                    total={data.findingDistribution.reduce((s, r) => s + r.count, 0)}
                    unitLabel="Open cryptographic findings"
                  />
                  <div className="mt-5 border-t border-white/8 pt-4">
                    <DistributionBars
                      rows={data.assetDistribution}
                      total={data.assetDistribution.reduce((s, r) => s + r.count, 0)}
                      unitLabel="Assets by their own risk level"
                    />
                  </div>
                </Panel>
              </div>

              <FactorsPanel data={data} />
              <ScenariosPanel data={data} />

              <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
                <HeatmapPanel data={data} />
                <CriticalFindingsPanel data={data} />
              </div>

              <TrendPanel data={data} />
            </div>
          ) : null}

          {tab === 'assets' ? (
            <div id="qrs-panel-assets" role="tabpanel" aria-labelledby="qrs-tab-assets" className="space-y-4">
              <CoveragePanel data={data} />
              <AssetTable rows={assets} total={data.assets.length} onSelect={setSelected} />
            </div>
          ) : null}

          {tab === 'drivers' ? (
            <div id="qrs-panel-drivers" role="tabpanel" aria-labelledby="qrs-tab-drivers" className="space-y-4">
              <FactorsPanel data={data} expanded />
              <ScenariosPanel data={data} />
              <CriticalFindingsPanel data={data} />
            </div>
          ) : null}

          <SourceNote>{data.evidence.note}</SourceNote>
        </>
      ) : null}

      <AssetDrawer asset={selected} onClose={() => setSelected(null)} onAsk={ask} />
    </IntelShell>
  );
}

/* ================================================================== */
/* Panels                                                              */
/* ================================================================== */

function HeadlinePanel({ data }: { data: QuantumRiskIntelligence }) {
  return (
    <Panel className="p-5">
      <SectionHeading title="Quantum Risk" icon={Gauge} meta={`assessed ${relativeTime(data.lastAssessmentAt)}`} />
      <div className="flex flex-col items-center gap-5 sm:flex-row">
        <ScoreDial score={data.headline.score} level={data.headline.level} />
        <div className="min-w-0 flex-1">
          <p className="text-[13px] font-semibold leading-relaxed text-white/75">{data.headline.statement}</p>
          <div className="mt-3 rounded-lg border border-cyan-400/20 bg-cyan-500/[0.06] p-3">
            <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-cyan-300/80">Where this number comes from</div>
            <p className="mt-1 text-[11px] leading-relaxed text-white/55">{data.headline.basis}</p>
          </div>
        </div>
      </div>
    </Panel>
  );
}

function FactorsPanel({ data, expanded }: { data: QuantumRiskIntelligence; expanded?: boolean }) {
  return (
    <Panel className="p-5">
      <SectionHeading
        title="What Drives the Score"
        icon={ListTree}
        meta="evidence-based factors"
        action={<LinkButton href="/dashboard/quantum-readiness" tone="ghost">Quantum Readiness</LinkButton>}
      />
      {data.factors.length === 0 ? (
        <EmptyRow>No risk factors have been computed for this environment yet.</EmptyRow>
      ) : (
        <div className={cn('grid gap-3', expanded ? 'lg:grid-cols-2' : 'lg:grid-cols-2 xl:grid-cols-3')}>
          {data.factors.map((factor) => (
            <div key={factor.key} className="rounded-xl border border-white/10 bg-black/20 p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-[12.5px] font-black text-white/90">{factor.label}</div>
                  <div className="mt-0.5 text-[9.5px] text-white/35">{factor.contributionPct}% of total factor weight</div>
                </div>
                <div className="text-right">
                  <div className="font-mono text-[20px] font-black leading-none" style={{ color: levelHex(factor.level) }}>{factor.score}</div>
                  <div className="mt-0.5 text-[8.5px] font-black uppercase tracking-wider" style={{ color: levelHex(factor.level) }}>{factor.level}</div>
                </div>
              </div>
              <div className="mt-2.5"><Meter value={factor.score} color={levelHex(factor.level)} label={`${factor.label} score`} /></div>
              <p className="mt-3 text-[11px] leading-relaxed text-white/50">{factor.what}</p>
              {expanded ? (
                <p className="mt-2 text-[10px] leading-relaxed text-white/30">Measured from: {factor.evidence}</p>
              ) : null}
              <div className="mt-3 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
                <div className="text-[8.5px] font-black uppercase tracking-wider text-white/30">Action</div>
                <p className="mt-0.5 text-[11px] leading-relaxed text-white/60">{factor.action}</p>
              </div>
              <div className="mt-2.5"><LinkButton href={factor.actionHref} tone="ghost">Open</LinkButton></div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function ScenariosPanel({ data }: { data: QuantumRiskIntelligence }) {
  return (
    <Panel className="p-5">
      <SectionHeading title="What Would Reduce It" icon={TrendingDown} meta="projected, not simulated" />
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {data.scenarios.map((scenario) => {
          const applicable = scenario.assetsAffected > 0;
          return (
            <div key={scenario.key} className={cn('rounded-xl border p-4', applicable ? 'border-white/10 bg-black/20' : 'border-white/5 bg-black/10')}>
              <div className="text-[12px] font-black leading-snug text-white/90">{scenario.label}</div>
              <p className="mt-1.5 text-[10.5px] leading-relaxed text-white/45">{scenario.detail}</p>
              {applicable ? (
                <>
                  <div className="mt-3 flex items-baseline gap-2">
                    <span className="font-mono text-[24px] font-black leading-none text-emerald-300">−{scenario.reductionPoints}</span>
                    <span className="text-[10px] text-white/40">points → {scenario.projectedRisk}/100</span>
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-white/35">
                    <span>{fmtInt(scenario.assetsAffected)} asset(s)</span>
                    <span>· {scenario.effort} effort</span>
                  </div>
                </>
              ) : (
                <div className="mt-3 text-[10.5px] text-white/30">Not applicable — no asset in this environment matches.</div>
              )}
              <div className="mt-3"><LinkButton href={scenario.href} tone={applicable ? 'neutral' : 'ghost'}>Plan</LinkButton></div>
            </div>
          );
        })}
      </div>
      <p className="mt-3 text-[9.5px] leading-relaxed text-white/25">
        Projections remove the vulnerable-component share of the named assets and rescale the published headline. They
        are arithmetic on measured evidence, not a simulation — the Migration Sandbox owns simulation and validation.
      </p>
    </Panel>
  );
}

function HeatmapPanel({ data }: { data: QuantumRiskIntelligence }) {
  return (
    <Panel className="p-5">
      <SectionHeading title="Risk Concentration" icon={Flame} meta="environment × criticality" />
      {data.heatmap.length === 0 ? (
        <EmptyRow>No assets available to map.</EmptyRow>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[440px] border-collapse text-left">
            <caption className="sr-only">Average risk by environment and business criticality</caption>
            <thead>
              <tr className="border-b border-white/10 text-[8.5px] font-black uppercase tracking-[0.14em] text-white/35">
                <th scope="col" className="py-2 pr-3 font-black">Environment</th>
                <th scope="col" className="py-2 pr-3 font-black">Criticality</th>
                <th scope="col" className="py-2 pr-3 font-black text-right">Assets</th>
                <th scope="col" className="py-2 pr-3 font-black text-right">Avg risk</th>
                <th scope="col" className="py-2 font-black">Worst</th>
              </tr>
            </thead>
            <tbody>
              {data.heatmap.map((cell) => (
                <tr key={`${cell.environment}-${cell.criticality}`} className="border-b border-white/5 last:border-0">
                  <td className="py-2 pr-3 text-[11.5px] text-white/70">{cell.environment}</td>
                  <td className="py-2 pr-3 text-[11.5px] text-white/50">{cell.criticality}</td>
                  <td className="py-2 pr-3 text-right font-mono text-[11.5px] text-white/70">{fmtInt(cell.assets)}</td>
                  <td className="py-2 pr-3 text-right font-mono text-[12px] font-black" style={{ color: cell.averageRisk === null ? '#94a3b8' : levelHex(cell.worstLevel) }}>
                    {fmtScore(cell.averageRisk)}
                  </td>
                  <td className="py-2"><StatusPill level={cell.worstLevel} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function CriticalFindingsPanel({ data }: { data: QuantumRiskIntelligence }) {
  return (
    <Panel className="p-5">
      <SectionHeading
        title="Critical & High Findings"
        icon={AlertTriangle}
        meta={`${fmtInt(data.criticalFindings.length)} shown`}
        action={<LinkButton href="/dashboard/quantum-readiness/risk-analysis" tone="ghost">Quantum Risk Analysis</LinkButton>}
      />
      {data.criticalFindings.length === 0 ? (
        <EmptyRow>No critical or high cryptographic findings are open for this environment.</EmptyRow>
      ) : (
        <div className="space-y-2">
          {data.criticalFindings.slice(0, 8).map((finding) => (
            <div key={finding.id} className="flex flex-wrap items-start gap-3 rounded-lg border border-white/8 bg-white/[0.02] p-3">
              <StatusPill level={finding.severity} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-[12px] font-black text-white/85">{finding.title}</div>
                <div className="mt-0.5 flex flex-wrap gap-x-2 text-[10.5px] text-white/40">
                  <span className="font-semibold text-white/60">{finding.asset}</span>
                  {finding.algorithm ? <span>· {finding.algorithm}</span> : null}
                  {finding.detectedAt ? <span>· {relativeTime(finding.detectedAt)}</span> : null}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function TrendPanel({ data }: { data: QuantumRiskIntelligence }) {
  const points = data.trend;
  if (!points.length) {
    return (
      <Panel className="p-5">
        <SectionHeading title="Risk Trend" icon={Activity} />
        <EmptyRow>Only one completed scan exists, so there is no trend to plot yet. Run another scan to establish a trend.</EmptyRow>
      </Panel>
    );
  }
  const max = 100;
  const width = 100;
  const path = points
    .map((point, index) => `${index === 0 ? 'M' : 'L'} ${(index / Math.max(1, points.length - 1)) * width} ${40 - (point.risk / max) * 40}`)
    .join(' ');
  return (
    <Panel className="p-5">
      <SectionHeading title="Risk Trend" icon={Activity} meta={`${points.length} completed scan(s)`} />
      <svg viewBox={`0 0 ${width} 44`} preserveAspectRatio="none" className="h-24 w-full" role="img" aria-label={`Quantum risk across ${points.length} completed scans`}>
        <path d={path} fill="none" stroke={RED} strokeWidth="1.2" vectorEffect="non-scaling-stroke" />
      </svg>
      <div className="mt-1 flex justify-between text-[9px] text-white/30">
        <span>{points[0]?.label}</span>
        <span>{points[points.length - 1]?.label}</span>
      </div>
    </Panel>
  );
}

function CoveragePanel({ data }: { data: QuantumRiskIntelligence }) {
  const c = data.coverage;
  return (
    <Panel className="p-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {([
          ['Assets discovered', fmtInt(c.assetsAssessed)],
          ['With crypto evidence', fmtInt(c.assetsWithEvidence)],
          ['Not assessed', fmtInt(c.assetsUnassessed)],
          ['Assessment coverage', fmtPct(c.coveragePct)],
        ] as Array<[string, string]>).map(([label, value]) => (
          <div key={label}>
            <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">{label}</div>
            <div className="mt-1 font-mono text-[16px] font-black text-white/85">{value}</div>
          </div>
        ))}
      </div>
      <p className="mt-3 border-t border-white/8 pt-3 text-[10px] leading-relaxed text-white/35">{c.note}</p>
    </Panel>
  );
}

function AssetTable({ rows, total, onSelect }: { rows: RiskAssetRow[]; total: number; onSelect: (row: RiskAssetRow) => void }) {
  return (
    <Panel className="p-5">
      <SectionHeading title="Asset Risk" icon={Layers} meta={`${fmtInt(rows.length)} of ${fmtInt(total)}`} />
      {rows.length === 0 ? (
        <EmptyRow>No asset matched the current filters.</EmptyRow>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[820px] border-collapse text-left">
            <caption className="sr-only">Assets ranked by measured quantum risk. Select a row for its decomposition.</caption>
            <thead>
              <tr className="border-b border-white/10 text-[8.5px] font-black uppercase tracking-[0.14em] text-white/35">
                <th scope="col" className="py-2 pr-3 font-black">Asset</th>
                <th scope="col" className="py-2 pr-3 font-black">Environment</th>
                <th scope="col" className="py-2 pr-3 font-black">Owner</th>
                <th scope="col" className="py-2 pr-3 font-black">Posture</th>
                <th scope="col" className="py-2 pr-3 font-black text-right">Vulnerable</th>
                <th scope="col" className="py-2 pr-3 font-black text-right">HNDL</th>
                <th scope="col" className="py-2 pr-3 font-black text-right">Risk</th>
                <th scope="col" className="py-2 font-black">Level</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.id}
                  tabIndex={0}
                  role="button"
                  onClick={() => onSelect(row)}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(row); } }}
                  className="cursor-pointer border-b border-white/5 outline-none transition last:border-0 hover:bg-white/[0.04] focus-visible:bg-white/[0.06] focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-cyan-300/70"
                  aria-label={`${row.name}, ${row.riskLevel}`}
                >
                  <td className="max-w-[220px] py-2.5 pr-3">
                    <div className="truncate text-[12px] font-semibold text-white/85">{row.name}</div>
                    <div className="truncate text-[9.5px] text-white/30">
                      {row.type}{row.internetFacing ? ' · internet-facing' : ''}{row.businessCriticality !== 'unspecified' ? ` · ${row.businessCriticality}` : ''}
                    </div>
                  </td>
                  <td className="py-2.5 pr-3 text-[11px] text-white/50">{row.environment}</td>
                  <td className="max-w-[140px] truncate py-2.5 pr-3 text-[11px] text-white/50">{row.owner}</td>
                  <td className="py-2.5 pr-3 text-[11px] text-white/60">{row.postureLabel}</td>
                  <td className="py-2.5 pr-3 text-right font-mono text-[11.5px] text-white/70">{fmtInt(row.vulnerableComponentCount)}</td>
                  <td className="py-2.5 pr-3 text-right font-mono text-[11.5px] text-white/70">{fmtScore(row.hndlScore)}</td>
                  <td className="py-2.5 pr-3 text-right font-mono text-[13px] font-black" style={{ color: row.riskScore === null ? '#94a3b8' : levelHex(row.riskLevel) }}>
                    {fmtScore(row.riskScore)}
                  </td>
                  <td className="py-2.5"><StatusPill level={row.state === 'unassessed' ? 'unassessed' : row.riskLevel} label={row.riskLevel} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function RiskFilterBar({
  data, filters, onChange, onClear, count,
}: {
  data: QuantumRiskIntelligence;
  filters: RiskAssetFilters;
  onChange: (next: Partial<RiskAssetFilters>) => void;
  onClear: () => void;
  count: number;
}) {
  const select = (label: string, key: keyof RiskAssetFilters, options: string[]) => (
    <div className="flex min-w-0 flex-col gap-1">
      <label htmlFor={`qrs-${key}`} className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/35">{label}</label>
      <select
        id={`qrs-${key}`}
        value={filters[key] as string}
        onChange={(e) => onChange({ [key]: e.target.value } as Partial<RiskAssetFilters>)}
        className="rounded-lg border border-white/12 bg-[#0b1424] px-2.5 py-1.5 text-[11px] font-semibold text-white/80 outline-none transition focus-visible:border-cyan-400/50 focus-visible:ring-2 focus-visible:ring-cyan-300/40"
      >
        <option value="all">All</option>
        {options.map((option) => <option key={option} value={option}>{option}</option>)}
      </select>
    </div>
  );

  return (
    <Panel className="p-4">
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex min-w-[220px] flex-1 flex-col gap-1">
          <label htmlFor="qrs-search" className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/35">Search</label>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/30" aria-hidden="true" />
            <input
              id="qrs-search"
              type="search"
              value={filters.search}
              onChange={(e) => onChange({ search: e.target.value })}
              placeholder="Search assets, owners, algorithms…"
              className="w-full rounded-lg border border-white/12 bg-[#0b1424] py-1.5 pl-8 pr-2.5 text-[11.5px] text-white/85 outline-none transition placeholder:text-white/25 focus-visible:border-cyan-400/50 focus-visible:ring-2 focus-visible:ring-cyan-300/40"
            />
          </div>
        </div>
        {select('Environment', 'environment', data.filters.environments)}
        {select('Owner', 'owner', data.filters.owners)}
        {select('Criticality', 'criticality', data.filters.criticalities)}
        {select('Risk level', 'level', ['critical', 'high', 'elevated', 'low', 'unassessed'])}
        <div className="flex items-center gap-2 pb-0.5">
          <span className="font-mono text-[10px] text-white/35">{fmtInt(count)} assets</span>
          <button
            type="button"
            onClick={onClear}
            className="inline-flex items-center gap-1 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-white/55 transition hover:bg-white/[0.08]"
          >
            <X className="h-3 w-3" aria-hidden="true" /> Clear
          </button>
        </div>
      </div>
    </Panel>
  );
}

/* ================================================================== */
/* Drawer                                                              */
/* ================================================================== */

function AssetDrawer({ asset, onClose, onAsk }: { asset: RiskAssetRow | null; onClose: () => void; onAsk: (q: string) => void }) {
  if (!asset) return null;
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/55" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div role="dialog" aria-modal="true" aria-label={`Risk detail for ${asset.name}`} className="flex h-full w-full max-w-[500px] flex-col overflow-y-auto border-l border-white/12 bg-[#0b1424] shadow-2xl">
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-white/10 bg-[#0b1424]/95 px-5 py-4 backdrop-blur">
          <div className="min-w-0">
            <h2 className="truncate text-[16px] font-black text-white">{asset.name}</h2>
            <div className="mt-0.5 text-[10px] uppercase tracking-wider text-white/35">
              {asset.type} · {asset.environment} · {asset.owner}
            </div>
          </div>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded-lg border border-white/12 bg-white/[0.04] p-1.5 text-white/50 transition hover:bg-white/[0.08]">
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="space-y-4 px-5 py-5">
          {asset.state === 'unassessed' ? (
            <div className="rounded-xl border border-white/10 bg-black/20 p-4 text-center">
              <div className="text-[12.5px] font-black text-white/80">Not assessed</div>
              <p className="mt-1.5 text-[11.5px] leading-relaxed text-white/45">
                No cryptographic evidence has been collected for this asset, so it carries no risk score. It is excluded
                from every average rather than counted as low risk.
              </p>
              <div className="mt-3"><LinkButton href="/dashboard/scanner">Scan this asset</LinkButton></div>
            </div>
          ) : (
            <>
              <div className="flex items-center gap-4">
                <ScoreDial score={asset.riskScore} level={asset.riskLevel} size={104} />
                <div className="min-w-0 flex-1 space-y-2">
                  {([
                    ['Posture', asset.postureLabel],
                    ['HNDL score', `${asset.hndlScore}/100`],
                    ['Blast radius', `${asset.blastRadius} dependent(s)`],
                    ['Migration', `${asset.migrationStatus} (${asset.migrationProgressPct}%)`],
                  ] as Array<[string, string]>).map(([label, value]) => (
                    <div key={label} className="flex items-baseline justify-between gap-2">
                      <span className="text-[10.5px] text-white/40">{label}</span>
                      <span className="text-[11.5px] font-semibold text-white/80">{value}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-4 gap-2">
                {([
                  ['Critical', asset.severityCounts.critical, RED],
                  ['High', asset.severityCounts.high, '#fb923c'],
                  ['Medium', asset.severityCounts.medium, AMBER],
                  ['Low', asset.severityCounts.low, GREEN],
                ] as Array<[string, number, string]>).map(([label, count, hex]) => (
                  <div key={label} className="rounded-lg border border-white/8 bg-white/[0.02] px-2 py-2 text-center">
                    <div className="font-mono text-[16px] font-black" style={{ color: hex }}>{fmtInt(count)}</div>
                    <div className="mt-0.5 text-[8px] font-black uppercase tracking-wider text-white/30">{label}</div>
                  </div>
                ))}
              </div>

              {asset.topAlgorithms.length ? (
                <div>
                  <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">Observed algorithms</div>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {asset.topAlgorithms.map((algorithm) => (
                      <span key={algorithm} className="rounded border border-white/10 bg-white/[0.03] px-2 py-1 font-mono text-[10px] text-white/65">{algorithm}</span>
                    ))}
                  </div>
                </div>
              ) : null}

              {asset.drivers.length ? (
                <div className="rounded-xl border border-white/10 bg-black/20 p-3.5">
                  <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/30">Why this score</div>
                  <ul className="mt-2 space-y-1.5">
                    {asset.drivers.map((driver, index) => (
                      <li key={index} className="flex items-start justify-between gap-3 text-[11px]">
                        <span className="min-w-0 flex-1">
                          <span className="text-white/65">{driver.label}</span>
                          {driver.evidence ? <span className="block text-[10px] leading-relaxed text-white/30">{driver.evidence}</span> : null}
                        </span>
                        <span className={cn('shrink-0 font-mono font-black', driver.contribution >= 0 ? 'text-amber-300' : 'text-emerald-300')}>
                          {driver.contribution > 0 ? '+' : ''}{driver.contribution}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}

              <div className="rounded-xl border border-cyan-400/25 bg-cyan-500/[0.07] p-3.5">
                <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-cyan-300/80">Recommended</div>
                <p className="mt-1 text-[12px] leading-relaxed text-white/80">{asset.recommendation}</p>
              </div>
            </>
          )}

          <div className="flex flex-wrap gap-2 border-t border-white/8 pt-3">
            <LinkButton href={asset.href}>Open in Planner</LinkButton>
            <LinkButton href="/dashboard/harvest-now" tone="ghost">HNDL Risk</LinkButton>
            <LinkButton href="/dashboard/cbom" tone="ghost">CBOM</LinkButton>
            <button
              type="button"
              onClick={() => onAsk(`Explain the quantum risk on ${asset.name}: what drives its score and what is the safest migration path?`)}
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

/* ================================================================== */
/* Sophia grounding                                                    */
/* ================================================================== */

function sophiaContext(data: QuantumRiskIntelligence | null): string {
  if (!data) return 'Quantum Risk Scoring — no data loaded.';
  return [
    'Page: Quantum Risk Scoring.',
    `Quantum risk ${data.headline.score}/100 (${data.headline.level}), read from the Quantum Readiness snapshot.`,
    `HNDL ${data.scoreCards.find((c) => c.key === 'hndl')?.score ?? 'n/a'}, crypto exposure ${data.scoreCards.find((c) => c.key === 'crypto-exposure')?.score ?? 'n/a'}, PQC adoption ${data.scoreCards.find((c) => c.key === 'pqc-adoption')?.score ?? 'n/a'}%.`,
    `Assets: ${data.coverage.assetsWithEvidence} assessed of ${data.coverage.assetsAssessed} discovered.`,
    `Top factors: ${data.factors.slice(0, 3).map((f) => `${f.label} ${f.score}`).join(', ')}.`,
    data.assets[0] ? `Highest-risk asset: ${data.assets[0].name} (${data.assets[0].riskScore ?? 'unassessed'}).` : '',
  ].filter(Boolean).join(' ');
}
