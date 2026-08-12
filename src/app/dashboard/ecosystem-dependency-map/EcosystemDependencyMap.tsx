'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, ArrowRight, BadgeCheck, FlaskConical, Globe2, HelpCircle, Layers,
  Link2, Network, Radar, Route, ShieldAlert, Sparkles, Target,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { WorkflowRail } from '@/components/workflow/WorkflowRail'
import { useEcosystemMap } from '@/hooks/use-external-trust'
import {
  DEPENDENCY_LABEL, NODE_KIND_LABEL, READINESS_LABEL, RISK_LABEL,
  type EcosystemNode, type EcosystemNodeKind, type Readiness, type RiskLevel,
} from '@/lib/ecosystem/external-trust-intelligence'
import {
  AskSophiaButton, Block, Chip, Drawer, DrawerLink, EmptyState, ErrorState, Field,
  KpiStrip, PageHeader, ProvenanceFooter, ReadinessChip, RiskChip, SectionCard,
  SkeletonPage, SuiteRail, numberFmt, relativeTime, useQueryParam,
} from '../_components/external-trust/_shared'
import { EcosystemGraph, type GraphFilters } from './_graph'

/**
 * Ecosystem Dependency Map.
 *
 * One job: **Explore → Select Dependency → Analyze Blast Radius**.
 *
 * A dependency intelligence view, not a decorative graph: every node carries the
 * evidence that produced it, and blast radius traverses only relationships that
 * actually exist in tenant data. Undocumented relationships are surfaced as
 * unknowns rather than silently omitted.
 */

export default function EcosystemDependencyMap() {
  const focusParam = useQueryParam('focus')
  const [focusId, setFocusId] = useState<string | null>(focusParam || null)
  const { data, state, error, live, lastGoodAt, refresh } = useEcosystemMap(focusId)

  const [selected, setSelected] = useState<EcosystemNode | null>(null)
  const [filters, setFilters] = useState<GraphFilters>({
    kinds: new Set<EcosystemNodeKind>(),
    criticality: 'all',
    readiness: 'all',
    search: '',
    maxDepth: 3,
  })
  const [panel, setPanel] = useState<'spof' | 'bottlenecks' | 'unknowns'>('spof')

  useEffect(() => { if (focusParam) setFocusId(focusParam) }, [focusParam])

  const patchFilters = useCallback((patch: Partial<GraphFilters>) => setFilters((current) => ({ ...current, ...patch })), [])

  const highlighted = useMemo(() => {
    if (!data?.blastRadius) return null
    return new Set([data.blastRadius.nodeId, ...data.blastRadius.affectedNodeIds])
  }, [data?.blastRadius])

  const selectNode = useCallback((node: EcosystemNode | null) => {
    setSelected(node)
    setFocusId(node?.id ?? null)
  }, [])

  if (state === 'error' && !data) {
    return (
      <div className="min-h-screen space-y-4 p-3 lg:p-5">
        <SuiteRail current="ecosystem" />
        <ErrorState message={error || 'Unknown error'} onRetry={() => void refresh(true)} lastGoodAt={lastGoodAt} />
      </div>
    )
  }

  const blast = data?.blastRadius ?? null

  return (
    <div className="external-trust-shell min-h-screen space-y-4 p-3 lg:p-5">
      <style>{`
        .external-trust-shell { background: var(--qg-dashboard-bg, #0a1020); }
        @media (prefers-reduced-motion: reduce) {
          .external-trust-shell *, .external-trust-shell *::before, .external-trust-shell *::after {
            animation-duration: 0.001ms !important; transition-duration: 0.001ms !important;
          }
        }
      `}</style>

      <WorkflowRail activeStage="assessment" />
      <SuiteRail current="ecosystem" />

      <PageHeader
        title="Ecosystem Dependency Map"
        subtitle="Understand the external vendors, services, platforms, identity systems, APIs, PKI, and trust relationships that influence cryptographic migration."
        icon={Globe2}
        live={live}
        generatedAt={data?.generatedAt}
        refreshing={state === 'loading'}
        onRefresh={() => void refresh(true)}
        sophiaPrompt="What are our most critical external dependencies, and which one has the largest migration blast radius?"
      />

      {state === 'loading' && !data ? <SkeletonPage rows={3} /> : data && (
        <>
          <KpiStrip items={[
            { key: 'external', label: 'External Dependencies', value: numberFmt(data.summary.externalDependencies), detail: `${numberFmt(data.nodes.length)} nodes mapped`, tone: 'neutral' },
            { key: 'critical', label: 'Critical Dependencies', value: numberFmt(data.summary.criticalDependencies), detail: 'critical risk or criticality', tone: data.summary.criticalDependencies ? 'critical' : 'good' },
            { key: 'vendors', label: 'Vendor Dependencies', value: numberFmt(data.summary.vendorDependencies), detail: 'attributed suppliers', tone: 'info' },
            { key: 'spof', label: 'Single Points of Failure', value: numberFmt(data.summary.singlePointsOfFailure), detail: 'concentrated + fragile', tone: data.summary.singlePointsOfFailure ? 'warning' : 'good', onClick: () => setPanel('spof') },
            { key: 'unknown', label: 'Unknown Dependencies', value: numberFmt(data.summary.unknownDependencies), detail: 'insufficient evidence', tone: 'info', onClick: () => setPanel('unknowns') },
            { key: 'blockers', label: 'Migration Blockers', value: numberFmt(data.summary.migrationBlockers), detail: 'gating dependent assets', tone: data.summary.migrationBlockers ? 'critical' : 'good', onClick: () => setPanel('bottlenecks') },
          ]} />

          <SectionCard
            title="Dependency Graph" icon={Network}
            right={focusId && (
              <button type="button" onClick={() => { setFocusId(null); setSelected(null) }}
                className="rounded border border-white/10 bg-white/5 px-2 py-1 text-[9px] font-black uppercase tracking-wider text-white/55 hover:text-cyan-300">
                Clear focus
              </button>
            )}
          >
            <EcosystemGraph
              nodes={data.nodes} edges={data.edges} focusId={focusId} highlighted={highlighted}
              filters={filters} onFiltersChange={patchFilters} onSelect={selectNode}
            />
          </SectionCard>

          {/* Blast radius */}
          <SectionCard
            title="Blast Radius Analysis" icon={Target}
            right={blast ? <Chip tone="warning">{numberFmt(blast.affectedNodeIds.length)} affected</Chip> : <Chip tone="info">Select a node</Chip>}
          >
            {!blast ? (
              <EmptyState icon={Target} title="Select a dependency to analyze"
                detail="Choose any node in the graph above. QGuard Helix traverses the relationships recorded in your tenant evidence and reports exactly what changes if that dependency changes." />
            ) : (
              <>
                <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4 lg:grid-cols-7">
                  {[
                    ['Direct', blast.directDependencies], ['Indirect', blast.indirectDependencies],
                    ['Applications', blast.applicationsAffected], ['Business Services', blast.businessServices],
                    ['Trust Relationships', blast.trustRelationships], ['Migration Plans', blast.migrationPlans],
                    ['Critical Services', blast.criticalServices],
                  ].map(([label, value]) => (
                    <div key={String(label)} className="rounded-lg border border-white/8 bg-black/25 px-2.5 py-2">
                      <div className="text-[8px] font-black uppercase tracking-wider text-white/40">{label}</div>
                      <div className="mt-1 font-mono text-[18px] font-black text-white">{numberFmt(Number(value))}</div>
                    </div>
                  ))}
                </div>
                <p className="mt-2.5 text-[10px] leading-relaxed text-white/40">{blast.basis}</p>
                {data.dependencyChain.length > 1 && (
                  <div className="mt-3">
                    <div className="mb-1.5 text-[9px] font-black uppercase tracking-[0.16em] text-white/40">Cascading dependency chain</div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      {data.dependencyChain.slice(0, 10).map((step, index) => (
                        <span key={step.nodeId} className="flex items-center gap-1.5">
                          <span className="rounded border border-white/10 bg-black/25 px-2 py-1 text-[9.5px] text-white/65" title={`${NODE_KIND_LABEL[step.kind]} · depth ${step.depth}`}>
                            {step.label}
                          </span>
                          {index < Math.min(9, data.dependencyChain.length - 1) && <ArrowRight className="h-3 w-3 text-white/25" />}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </SectionCard>

          {/* Intelligence panels */}
          <SectionCard
            title="Dependency Intelligence" icon={Radar}
            right={
              <div className="flex gap-1">
                {([['spof', 'Single Points of Failure'], ['bottlenecks', 'Migration Bottlenecks'], ['unknowns', 'Unknown Dependencies']] as const).map(([key, label]) => (
                  <button key={key} type="button" onClick={() => setPanel(key)} aria-pressed={panel === key}
                    className={cn('rounded border px-2 py-1 text-[8.5px] font-black uppercase tracking-wider transition',
                      panel === key ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200' : 'border-white/10 bg-white/5 text-white/45 hover:text-cyan-300')}>
                    {label}
                  </button>
                ))}
              </div>
            }
          >
            {panel === 'spof' && (
              data.singlePointsOfFailure.length === 0 ? (
                <EmptyState icon={ShieldAlert} title="No single point of failure detected"
                  detail="A dependency is only flagged when it both concentrates multiple consumers AND shows fragility (no alternative, weak readiness, or missing evidence). Neither condition alone qualifies." />
              ) : (
                <div className="space-y-2">
                  {data.singlePointsOfFailure.map((spof) => (
                    <button key={spof.nodeId} type="button"
                      onClick={() => { const node = data.nodes.find((candidate) => candidate.id === spof.nodeId); if (node) selectNode(node) }}
                      className="w-full rounded-lg border border-white/8 bg-white/[0.015] p-3 text-left transition hover:border-cyan-400/30">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-[12px] font-black text-white/90">{spof.label}</span>
                        <div className="flex items-center gap-1.5">
                          <Chip tone="info">{NODE_KIND_LABEL[spof.kind]}</Chip>
                          <RiskChip value={spof.risk} />
                        </div>
                      </div>
                      <ul className="mt-1.5 space-y-0.5">
                        {spof.reasons.map((reason, index) => (
                          <li key={index} className="text-[10px] leading-relaxed text-white/50">· {reason}</li>
                        ))}
                      </ul>
                      <div className="mt-1.5 text-[9px] text-white/30">{spof.basis}</div>
                    </button>
                  ))}
                </div>
              )
            )}

            {panel === 'bottlenecks' && (
              data.bottlenecks.length === 0 ? (
                <EmptyState icon={Layers} title="No migration bottleneck detected"
                  detail="No external dependency is currently gating tenant assets from migrating." />
              ) : (
                <div className="space-y-2">
                  {data.bottlenecks.map((bottleneck) => (
                    <div key={bottleneck.nodeId} className="rounded-lg border border-white/8 bg-white/[0.015] p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-[12px] font-black text-white/90">
                          {bottleneck.label} currently prevents PQC migration for {numberFmt(bottleneck.blockedAssets)} asset(s)
                        </span>
                        <RiskChip value={bottleneck.risk} />
                      </div>
                      <p className="mt-1 text-[10.5px] leading-relaxed text-white/50">{bottleneck.reason}</p>
                      <div className="mt-1.5 grid gap-2 sm:grid-cols-3">
                        <Field label="Vendor status" value={READINESS_LABEL[bottleneck.vendorStatus]} />
                        <Field label="Evidence" value={bottleneck.evidenceState} />
                        <Field label="Alternatives observed" value={bottleneck.alternatives.length ? bottleneck.alternatives.join(', ') : 'None in this estate'} />
                      </div>
                      {bottleneck.affectedAssetNames.length > 0 && (
                        <div className="mt-1.5 flex flex-wrap gap-1">
                          {bottleneck.affectedAssetNames.map((name) => (
                            <span key={name} className="rounded border border-white/10 bg-black/25 px-2 py-0.5 font-mono text-[9px] text-white/50">{name}</span>
                          ))}
                        </div>
                      )}
                      <div className="mt-2 flex flex-wrap gap-2">
                        <DrawerLink href={bottleneck.route} primary>View Vendor Readiness</DrawerLink>
                        <DrawerLink href={`/dashboard/hybrid-crypto-lab${bottleneck.vendorId ? `?vendor=${encodeURIComponent(bottleneck.vendorId)}` : ''}`}>
                          <FlaskConical className="h-3 w-3" /> Run Hybrid Test
                        </DrawerLink>
                        <span className="inline-flex items-center text-[10px] text-white/40">{bottleneck.recommendedAction}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )
            )}

            {panel === 'unknowns' && (
              data.unknowns.length === 0 ? (
                <EmptyState icon={HelpCircle} title="No unknown dependencies"
                  detail="Every discovered dependency carries enough evidence to be assessed." />
              ) : (
                <>
                  <div className="mb-2 rounded-lg border border-amber-500/25 bg-amber-500/[0.07] p-2.5 text-[10.5px] leading-relaxed text-white/55">
                    <AlertTriangle className="mr-1.5 inline h-3.5 w-3.5 text-amber-300" />
                    {numberFmt(data.unknowns.length)} relationship(s) have insufficient evidence. Undocumented trust and dependency relationships are the most common source of migration failure — they are listed rather than omitted.
                  </div>
                  <div className="max-h-[320px] space-y-1 overflow-y-auto pr-1 scrollbar-thin">
                    {data.unknowns.map((unknown) => (
                      <div key={unknown.id} className="rounded-lg border border-white/8 bg-white/[0.015] px-3 py-2">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="truncate text-[11px] font-bold text-white/80">{unknown.label}</span>
                          <Chip tone="info">{NODE_KIND_LABEL[unknown.kind]}</Chip>
                        </div>
                        <div className="mt-0.5 text-[9.5px] leading-relaxed text-white/40">{unknown.reason}</div>
                        <div className="mt-0.5 text-[9.5px] text-cyan-300/60">{unknown.recommendedAction}</div>
                      </div>
                    ))}
                  </div>
                </>
              )
            )}
          </SectionCard>

          {/* Recommendations */}
          {data.recommendations.length > 0 && (
            <SectionCard title="Ecosystem Recommendations" icon={Sparkles} right={<Chip tone="ai">{data.recommendations.length}</Chip>}>
              <div className="space-y-2">
                {data.recommendations.map((recommendation) => (
                  <div key={recommendation.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-violet-400/20 bg-violet-500/[0.05] p-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <Sparkles className="h-3 w-3 shrink-0 text-violet-300" />
                        <span className="truncate text-[11.5px] font-black text-white/90">{recommendation.title}</span>
                        <RiskChip value={recommendation.risk} />
                      </div>
                      <p className="mt-1 text-[10.5px] leading-relaxed text-white/50">{recommendation.detail}</p>
                    </div>
                    <DrawerLink href={recommendation.route} primary>{recommendation.action}</DrawerLink>
                  </div>
                ))}
              </div>
            </SectionCard>
          )}

          <ProvenanceFooter evidence={data.evidence} generatedAt={data.generatedAt}
            extra={`${numberFmt(data.edges.filter((edge) => edge.explicit).length)} explicit / ${numberFmt(data.edges.filter((edge) => !edge.explicit).length)} inferred edges`} />
        </>
      )}

      {/* Node detail drawer */}
      <Drawer
        open={Boolean(selected)}
        title={selected?.label || ''}
        subtitle={selected ? `${NODE_KIND_LABEL[selected.kind]} · ${selected.external ? 'external' : 'internal'}` : ''}
        tone={selected ? (selected.risk === 'critical' ? 'critical' : selected.risk === 'high' ? 'warning' : 'neutral') : 'neutral'}
        onClose={() => setSelected(null)}
        footer={selected && (
          <div className="flex flex-wrap gap-2">
            {selected.vendorId && (
              <DrawerLink href={`/dashboard/vendor-pqc-readiness?vendor=${encodeURIComponent(selected.vendorId)}`} primary>
                <BadgeCheck className="h-3 w-3" /> View Vendor Readiness
              </DrawerLink>
            )}
            <DrawerLink href="/dashboard/trust-chain-analyzer"><Link2 className="h-3 w-3" /> Analyze Trust</DrawerLink>
            <DrawerLink href="/dashboard/hybrid-crypto-lab"><FlaskConical className="h-3 w-3" /> Test Configuration</DrawerLink>
            <DrawerLink href={selected.route}>Open source module</DrawerLink>
            <AskSophiaButton question={`In our ecosystem dependency map, what depends on "${selected.label}" and what breaks if it changes?`} context="Ecosystem Dependency Map" />
          </div>
        )}
      >
        {selected && (
          <>
            <div className="flex flex-wrap gap-1.5">
              <ReadinessChip value={selected.readiness} />
              <RiskChip value={selected.risk} />
              <Chip tone="info">{DEPENDENCY_LABEL[selected.dependencyKind]}</Chip>
              {selected.external && <Chip tone="warning">External</Chip>}
            </div>

            <Block title="Identity">
              <div className="grid grid-cols-2 gap-2">
                <Field label="Type" value={NODE_KIND_LABEL[selected.kind]} />
                <Field label="Owner" value={selected.owner} />
                <Field label="Environment" value={selected.environment} />
                <Field label="Criticality" value={RISK_LABEL[selected.criticality]} />
              </div>
            </Block>

            <Block title="Detail">
              <p className="rounded-lg border border-white/8 bg-black/25 p-2.5 text-[10.5px] leading-relaxed text-white/55">{selected.detail}</p>
            </Block>

            {selected.algorithms.length > 0 && (
              <Block title="Cryptography">
                <div className="rounded-lg border border-white/8 bg-black/25 p-2.5 font-mono text-[10px] text-white/70">
                  {selected.algorithms.join(', ')}
                </div>
              </Block>
            )}

            {blast && blast.nodeId === selected.id && (
              <Block title="Blast Radius">
                <div className="grid grid-cols-2 gap-2">
                  <Field label="Direct" value={numberFmt(blast.directDependencies)} mono />
                  <Field label="Indirect" value={numberFmt(blast.indirectDependencies)} mono />
                  <Field label="Applications" value={numberFmt(blast.applicationsAffected)} mono />
                  <Field label="Migration plans" value={numberFmt(blast.migrationPlans)} mono />
                </div>
              </Block>
            )}

            <Block title="Evidence">
              <div className="rounded-lg border border-white/8 bg-black/25 p-2.5">
                <div className="flex flex-wrap gap-1">
                  {selected.evidenceSources.map((source) => (
                    <span key={source} className="rounded border border-white/10 bg-white/5 px-2 py-0.5 text-[9px] text-white/55">{source}</span>
                  ))}
                </div>
                <div className="mt-1.5 text-[9.5px] text-white/35">
                  {selected.assetIds.length} tenant asset(s) transit this node.
                  {!selected.hasEvidence && ' No cryptographic evidence has been observed here — its behaviour under migration is undetermined.'}
                </div>
              </div>
            </Block>
          </>
        )}
      </Drawer>
    </div>
  )
}
