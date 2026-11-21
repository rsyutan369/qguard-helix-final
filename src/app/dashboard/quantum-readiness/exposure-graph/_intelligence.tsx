'use client';

import { Fragment } from 'react';
import { Blocks, Bot, Building2, GitMerge, Layers, Link2, OctagonAlert, Sparkles } from 'lucide-react';
import type { ExposureIntelligence, PriorityLabel } from '@/types/exposure-graph';
import { Badge, EmptyState, Panel, Ring, SectionTitle, ViewAllLink, integerFmt, BLUE, CYAN, EMERALD, ORANGE, RED, VIOLET } from '../_shared';
import { POSTURE_COLOR, POSTURE_LABEL, PRIORITY_COLOR } from './_common';

/* ------------------------------------------------------------------ */
/* Migration Dependency Intelligence™                                  */
/* ------------------------------------------------------------------ */

export function MigrationOrderSection({
  data,
  onSelectNode,
}: {
  data: ExposureIntelligence;
  onSelectNode: (id: string) => void;
}) {
  const { waves, clusters, blockers } = data.migrationOrder;
  return (
    <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
      <Panel className="p-5 xl:col-span-7">
        <SectionTitle suffix={<Badge color={BLUE}>{waves.length} wave(s)</Badge>}>
          <span className="inline-flex items-center gap-2"><Layers className="h-4 w-4 text-blue-300" /> Recommended Migration Order</span>
        </SectionTitle>
        {waves.length ? (
          <div className="space-y-2.5">
            {waves.map((wave) => (
              <div key={wave.wave} className="rounded-md border border-white/8 bg-white/[0.02] p-3 transition hover:border-blue-400/30">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className="grid h-7 w-7 shrink-0 place-items-center rounded-full border border-blue-400/40 bg-blue-500/15 font-mono text-xs font-bold text-blue-200">
                      {wave.wave}
                    </span>
                    <span className="text-xs font-bold text-white">{wave.tierLabel}</span>
                  </div>
                  <span className="text-[10px] text-white/40">{wave.nodes.length} asset(s) in wave</span>
                </div>
                <p className="mt-1.5 text-[11px] leading-relaxed text-white/45">{wave.rationale}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {wave.nodes.map((node) => (
                    <button
                      key={node.id}
                      type="button"
                      onClick={() => onSelectNode(node.id)}
                      className="inline-flex items-center gap-1.5 rounded border border-white/10 bg-black/25 px-2 py-1 text-[10px] text-white/70 transition hover:border-blue-400/40 hover:text-blue-200"
                    >
                      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: POSTURE_COLOR[node.posture] }} />
                      <span className="max-w-[160px] truncate">{node.label}</span>
                      {node.dependents > 0 ? <span className="font-mono text-white/35">{node.dependents}⇠</span> : null}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            label={data.hasData ? 'Entire estate is PQC-ready — no migration waves pending.' : 'No migration sequencing available yet.'}
            hint={data.hasData ? undefined : 'Discover assets and dependencies to generate the recommended order.'}
          />
        )}
      </Panel>

      <div className="space-y-4 xl:col-span-5">
        <Panel className="p-5">
          <SectionTitle suffix={<Badge color={VIOLET}>{clusters.length}</Badge>}>
            <span className="inline-flex items-center gap-2"><GitMerge className="h-4 w-4 text-violet-300" /> Must Migrate Together</span>
          </SectionTitle>
          {clusters.length ? (
            <div className="space-y-2.5">
              {clusters.map((cluster) => (
                <div key={cluster.id} className="rounded-md border border-violet-400/15 bg-violet-400/[0.04] p-3">
                  <div className="flex flex-wrap gap-1.5">
                    {cluster.nodes.map((node) => (
                      <button
                        key={node.id}
                        type="button"
                        onClick={() => onSelectNode(node.id)}
                        className="inline-flex items-center gap-1.5 rounded border border-white/10 bg-black/25 px-2 py-1 text-[10px] text-white/70 transition hover:border-violet-400/40"
                      >
                        <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: POSTURE_COLOR[node.posture] }} />
                        <span className="max-w-[140px] truncate">{node.label}</span>
                      </button>
                    ))}
                  </div>
                  <p className="mt-1.5 text-[11px] leading-relaxed text-white/45">{cluster.reason}</p>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState label="No coupled migration groups detected." hint="Mutual TLS / shared certificate chains create coupled groups." />
          )}
        </Panel>

        <Panel className="p-5">
          <SectionTitle suffix={<Badge color={RED}>{blockers.length}</Badge>}>
            <span className="inline-flex items-center gap-2"><OctagonAlert className="h-4 w-4 text-red-300" /> Migration Blockers</span>
          </SectionTitle>
          {blockers.length ? (
            <div className="space-y-2">
              {blockers.map((blocker) => (
                <button
                  key={blocker.id}
                  type="button"
                  onClick={() => onSelectNode(blocker.id)}
                  className="w-full rounded-md border border-red-400/15 bg-red-400/[0.04] p-3 text-left transition hover:border-red-400/35"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-xs font-bold text-white/85">{blocker.label}</span>
                    <span className="shrink-0 font-mono text-[10px] text-red-300">{integerFmt(blocker.blockedDependents)} blocked</span>
                  </div>
                  <p className="mt-1 text-[11px] leading-relaxed text-white/45">{blocker.reason}</p>
                </button>
              ))}
            </div>
          ) : (
            <EmptyState label="No blocking dependencies detected." hint="Vulnerable trust anchors, KMS gaps and vendor delays appear here." />
          )}
        </Panel>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Third-Party Dependency Analysis                                     */
/* ------------------------------------------------------------------ */

export function ThirdPartySection({ data, onSelectNode }: { data: ExposureIntelligence; onSelectNode: (id: string) => void }) {
  const rows = data.thirdParty;
  return (
    <Panel className="p-5">
      <SectionTitle suffix={<Badge color={CYAN}>{rows.length} dependenc{rows.length === 1 ? 'y' : 'ies'}</Badge>}>
        <span className="inline-flex items-center gap-2"><Building2 className="h-4 w-4 text-cyan-300" /> Third-Party Dependency Analysis</span>
      </SectionTitle>
      {rows.length ? (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[880px] text-left text-[11px]">
            <thead>
              <tr className="border-b border-white/8 text-[9px] font-black uppercase tracking-wide text-white/40">
                <th className="pb-2 pr-3">Vendor / Service</th>
                <th className="pb-2 pr-3">Category</th>
                <th className="pb-2 pr-3">Connected Assets</th>
                <th className="pb-2 pr-3">Cryptography Observed</th>
                <th className="pb-2 pr-3">TLS</th>
                <th className="pb-2 pr-3">Quantum Readiness</th>
                <th className="pb-2 pr-3">Risk</th>
                <th className="pb-2">Migration Compatibility</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} className="border-b border-white/[0.04] transition hover:bg-white/[0.02]">
                  <td className="py-2.5 pr-3">
                    {row.connectedAssets > 0 ? (
                      <button type="button" onClick={() => onSelectNode(row.id)} className="max-w-[190px] truncate text-left font-bold text-white/85 transition hover:text-cyan-200">
                        {row.vendor}
                      </button>
                    ) : <span className="font-bold text-white/85">{row.vendor}</span>}
                    {row.certificate ? <div className="text-[10px] text-white/35">{row.certificate}</div> : null}
                  </td>
                  <td className="py-2.5 pr-3 text-white/55">{row.category}</td>
                  <td className="py-2.5 pr-3">
                    <span className="font-mono text-white/75">{integerFmt(row.connectedAssets)}</span>
                    {row.connectedAssetNames.length ? (
                      <div className="max-w-[180px] truncate text-[10px] text-white/35">{row.connectedAssetNames.join(', ')}</div>
                    ) : null}
                  </td>
                  <td className="py-2.5 pr-3">
                    {row.algorithms.length ? (
                      <div className="flex max-w-[200px] flex-wrap gap-1">
                        {row.algorithms.slice(0, 3).map((algorithm) => (
                          <span key={algorithm} className="rounded border border-white/10 bg-white/[0.03] px-1 py-0.5 font-mono text-[9.5px] text-white/60">{algorithm}</span>
                        ))}
                        {row.algorithms.length > 3 ? <span className="text-[9.5px] text-white/35">+{row.algorithms.length - 3}</span> : null}
                      </div>
                    ) : (
                      <span className="text-white/30">Not observed</span>
                    )}
                  </td>
                  <td className="py-2.5 pr-3 font-mono text-white/55">{row.tlsVersion || '—'}</td>
                  <td className="py-2.5 pr-3"><Badge color={POSTURE_COLOR[row.readiness]}>{POSTURE_LABEL[row.readiness]}</Badge></td>
                  <td className="py-2.5 pr-3"><Badge color={row.riskLevel === 'Unknown' ? POSTURE_COLOR.unknown : PRIORITY_COLOR[row.riskLevel]}>{row.riskLevel}</Badge></td>
                  <td className="py-2.5 max-w-[220px] text-white/50">{row.migrationCompatibility}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState
          label="No third-party dependencies discovered yet."
          hint="External CAs, cloud connectors and outbound service traffic populate this analysis automatically."
        />
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Risk Prioritization                                                 */
/* ------------------------------------------------------------------ */

export function RiskPrioritizationSection({ data, onSelectNode }: { data: ExposureIntelligence; onSelectNode: (id: string) => void }) {
  const rows = data.riskPrioritization;
  return (
    <Panel className="p-5">
      <SectionTitle suffix={<Badge color={ORANGE}>Top {rows.length}</Badge>}>
        <span className="inline-flex items-center gap-2"><Blocks className="h-4 w-4 text-orange-300" /> Migration Risk Prioritization</span>
      </SectionTitle>
      {rows.length ? (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[840px] text-left text-[11px]">
            <thead>
              <tr className="border-b border-white/8 text-[9px] font-black uppercase tracking-wide text-white/40">
                <th className="pb-2 pr-3">Asset</th>
                <th className="pb-2 pr-3">Environment</th>
                <th className="pb-2 pr-3">Posture</th>
                <th className="pb-2 pr-3">Priority</th>
                <th className="pb-2 pr-3">Priority score</th>
                <th className="pb-2 pr-3">Dependents</th>
                <th className="pb-2">Priority Drivers</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} className="border-b border-white/[0.04] transition hover:bg-white/[0.02]">
                  <td className="py-2.5 pr-3">
                    <button type="button" onClick={() => onSelectNode(row.id)} className="max-w-[200px] truncate text-left font-bold text-white/85 transition hover:text-cyan-200">
                      {row.label}
                    </button>
                  </td>
                  <td className="py-2.5 pr-3 text-white/55">{row.environment}</td>
                  <td className="py-2.5 pr-3">
                    <span className="inline-flex items-center gap-1.5 text-white/65">
                      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: POSTURE_COLOR[row.posture] }} />
                      {POSTURE_LABEL[row.posture]}
                    </span>
                  </td>
                  <td className="py-2.5 pr-3"><Badge color={PRIORITY_COLOR[row.priority]}>{row.priority}</Badge></td>
                  <td className="py-2.5 pr-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-white/75">{row.priorityScore}</span>
                      <div className="h-1 w-14 overflow-hidden rounded-full bg-white/5">
                        <div className="h-full rounded-full" style={{ width: `${row.priorityScore}%`, backgroundColor: PRIORITY_COLOR[row.priority] }} />
                      </div>
                    </div>
                  </td>
                  <td className="py-2.5 pr-3 font-mono text-white/55">{integerFmt(row.dependents)}</td>
                  <td className="py-2.5 max-w-[300px] text-white/45">{row.drivers.join(' · ') || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState label="No prioritisation data yet." hint="Run a discovery scan to compute migration priorities." />
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* AI Migration Advisor™                                               */
/* ------------------------------------------------------------------ */

const SEVERITY_BADGE: Record<string, string> = { critical: RED, high: ORANGE, medium: '#FBBF24', low: EMERALD };

export function AdvisorSection({ data }: { data: ExposureIntelligence }) {
  const { recommendations, estimates } = data.advisor;
  const impactColor: Record<PriorityLabel, string> = PRIORITY_COLOR;
  return (
    <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
      <Panel className="p-5 xl:col-span-8">
        <SectionTitle suffix={<ViewAllLink to="/dashboard/quantum-readiness/ai-migration-advisor">Full Advisor</ViewAllLink>}>
          <span className="inline-flex items-center gap-2"><Bot className="h-4 w-4 text-cyan-300" /> AI Migration Advisor™ — Graph Recommendations</span>
        </SectionTitle>
        {recommendations.length ? (
          <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-2">
            {recommendations.map((rec) => (
              <div key={rec.id} className="rounded-md border border-white/8 bg-white/[0.02] p-3 transition hover:border-cyan-400/30">
                <div className="flex items-start justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 text-[9px] font-black uppercase tracking-wide text-white/40">
                    <Sparkles className="h-3 w-3 text-cyan-300/80" /> {rec.category}
                  </span>
                  <Badge color={SEVERITY_BADGE[rec.severity] || CYAN}>{rec.severity}</Badge>
                </div>
                <div className="mt-1.5 text-xs font-bold text-white/90">{rec.title}</div>
                <p className="mt-1 text-[11px] leading-relaxed text-white/50">{rec.detail}</p>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            label={data.hasData ? 'No recommendations from the loaded evidence.' : 'No evidence available for recommendations yet.'}
            hint={data.hasData ? undefined : 'Run a discovery scan to generate graph-aware migration guidance.'}
          />
        )}
      </Panel>

      <Panel className="p-5 xl:col-span-4">
        <SectionTitle>
          <span className="inline-flex items-center gap-2"><Link2 className="h-4 w-4 text-blue-300" /> Migration Estimates</span>
        </SectionTitle>
        {data.summary.assessmentMeasured ? <div className="space-y-3">
          <div className="flex items-center justify-around">
            <div className="flex flex-col items-center gap-1">
              <Ring value={estimates.migrationComplexity} color={estimates.migrationComplexity >= 60 ? RED : estimates.migrationComplexity >= 35 ? ORANGE : EMERALD} size={70} stroke={8}>
                <span className="text-sm font-bold text-white">{estimates.migrationComplexity}</span>
              </Ring>
              <span className="text-[9px] font-black uppercase tracking-wide text-white/45">Complexity · {estimates.complexityLevel}</span>
            </div>
            {data.summary.trustRelationships > 0 && <div className="flex flex-col items-center gap-1">
              <Ring value={estimates.compatibilityScorePct} color={estimates.compatibilityScorePct >= 70 ? EMERALD : estimates.compatibilityScorePct >= 40 ? ORANGE : RED} size={70} stroke={8}>
                <span className="text-sm font-bold text-white">{estimates.compatibilityScorePct}%</span>
              </Ring>
              <span className="text-[9px] font-black uppercase tracking-wide text-white/45">PQC or hybrid at both ends</span>
            </div>}
          </div>
          {(
            [
              { label: 'Business Impact', value: estimates.businessImpact, color: impactColor[estimates.businessImpact] },
              { label: 'Estimated Duration', value: estimates.estimatedDurationWeeks ? `${integerFmt(estimates.estimatedDurationWeeks)} weeks` : '—', color: CYAN },
              { label: 'Estimated Workstreams', value: estimates.parallelWorkstreams ? integerFmt(estimates.parallelWorkstreams) : '—', color: CYAN },
            ] as Array<{ label: string; value: string; color: string }>
          ).map((row) => (
            <Fragment key={row.label}>
              <div className="flex items-center justify-between rounded-md border border-white/8 bg-black/20 px-3 py-2 text-[11px]">
                <span className="text-white/45">{row.label}</span>
                <span className="font-bold" style={{ color: row.color }}>{row.value}</span>
              </div>
            </Fragment>
          ))}
          <p className="text-[10px] leading-relaxed text-white/35">
            Planning estimates use the Quantum Readiness Assessment and recorded dependency links.
          </p>
        </div> : <EmptyState label="Run a readiness assessment to populate migration estimates." />}
      </Panel>
    </section>
  );
}
