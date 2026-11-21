'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, ArrowRight, BadgeCheck, FileWarning, FlaskConical, GitCompare,
  Globe2, Link2, Network, Route, ShieldCheck,
} from 'lucide-react'
import type { WorkflowNode } from '@/components/trust-workflow/graph-model'
import { TrustGraph } from './TrustGraph'
import { cn } from '@/lib/utils'
import { WorkflowRail } from '@/components/workflow/WorkflowRail'
import { useTrustChains } from '@/hooks/use-external-trust'
import {
  TRUST_FINDING_LABEL, TRUST_NODE_LABEL, RISK_LABEL,
  type TrustChain, type TrustFinding, type TrustNode,
} from '@/lib/ecosystem/external-trust-intelligence'
import {
  AskSophiaButton, Block, Chip, Drawer, DrawerLink, EmptyState, ErrorState, Field,
  KpiStrip, PageHeader, ProvenanceFooter, RiskChip, SearchInput, SectionCard, Select,
  SkeletonPage, SuiteRail, TrustChip, dateFmt, numberFmt, scoreFmt, suiteHref,
  useQueryParam,
} from '../_components/external-trust/_shared'

/**
 * Trust Chain Analyzer.
 *
 * One job: **Select Chain → Analyze Trust → Compare Migration**.
 *
 * Chains are built only from discovered certificates and their recorded issuer
 * relationships — no chain is ever synthesised. The proposed post-quantum chain
 * is labelled a PROPOSAL and states plainly that CA support is unverified.
 */

function ChainLadder({ nodes, title, tone }: { nodes: TrustNode[]; title: string; tone: 'current' | 'proposed' }) {
  return (
    <div className={cn('rounded-lg border p-3', tone === 'proposed' ? 'border-cyan-400/25 bg-cyan-500/[0.05]' : 'border-white/8 bg-black/25')}>
      <div className={cn('mb-2 text-[9px] font-black uppercase tracking-[0.16em]', tone === 'proposed' ? 'text-cyan-300' : 'text-white/40')}>{title}</div>
      <div className="space-y-1">
        {[...nodes].reverse().map((node, index) => (
          <div key={node.id} className="flex items-center gap-2">
            <span className="w-4 shrink-0 text-center font-mono text-[8px] text-white/25">{index + 1}</span>
            <div className="min-w-0 flex-1 rounded border border-white/8 bg-white/[0.03] px-2.5 py-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-[10.5px] font-bold text-white/80" title={node.label}>{node.label}</span>
                <span className="shrink-0 text-[8px] font-black uppercase tracking-wider text-white/35">{TRUST_NODE_LABEL[node.kind]}</span>
              </div>
              <div className="mt-0.5 truncate font-mono text-[9px] text-cyan-300/60">{node.detail}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function TrustChainAnalyzer() {
  const vendorParam = useQueryParam('vendor')
  const assetParam = useQueryParam('asset')
  const focusParam = useQueryParam('focus')
  const { data, state, error, live, lastGoodAt, refresh, refreshing } = useTrustChains()

  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState('all')
  const [stateFilter, setStateFilter] = useState('all')
  const [activeChainId, setActiveChainId] = useState<string | null>(null)
  const [compare, setCompare] = useState(false)
  const [findingDrawer, setFindingDrawer] = useState<TrustFinding | null>(null)
  // Cross-page context lands on its entity in the graph: an explicit node,
  // else the asset, else the vendor that operates the chain's CA.
  const [graphFocus, setGraphFocus] = useState<string | null>(
    focusParam || (assetParam ? `asset:${assetParam}` : vendorParam ? `vendor:${vendorParam}` : null),
  )
  const filtersActive = Boolean(search.trim()) || riskFilter !== 'all' || stateFilter !== 'all'

  const chains = useMemo(() => {
    if (!data) return []
    const term = search.trim().toLowerCase()
    return data.chains.filter((chain) => {
      if (vendorParam && chain.vendorId !== vendorParam) return false
      if (assetParam && !chain.assetIds.includes(assetParam)) return false
      if (term && !`${chain.name} ${chain.certificate?.issuer ?? ''} ${chain.assetNames.join(' ')}`.toLowerCase().includes(term)) return false
      if (riskFilter !== 'all' && chain.risk !== riskFilter) return false
      if (stateFilter !== 'all' && chain.state !== stateFilter) return false
      return true
    })
  }, [data, search, riskFilter, stateFilter, vendorParam, assetParam])

  useEffect(() => {
    if (!chains.length) { setActiveChainId(null); return }
    if (chains.some((chain) => chain.id === activeChainId)) return
    setActiveChainId(chains[0].id)
  }, [chains, activeChainId])

  /** Graph selection drives the chain detail below it. */
  const onGraphSelect = useCallback((node: WorkflowNode | null) => {
    if (!node) return
    if (node.kind === 'certificate') setActiveChainId(`chain-${node.id.slice('cert:'.length)}`)
    else if (node.entity?.type === 'asset') {
      const match = chains.find((candidate) => candidate.assetIds.includes(node.entity!.id))
      if (match) setActiveChainId(match.id)
    }
  }, [chains])

  const chain: TrustChain | null = useMemo(
    () => chains.find((candidate) => candidate.id === activeChainId) ?? chains[0] ?? null,
    [chains, activeChainId],
  )

  const chainFindings = useMemo(
    () => (data && chain ? data.findings.filter((finding) => finding.chainId === chain.id) : []),
    [data, chain],
  )

  if (state === 'error' && !data) {
    return (
      <div className="min-h-screen space-y-4 p-3 lg:p-5">
        <SuiteRail current="trust" />
        <ErrorState message={error || 'Unknown error'} onRetry={() => void refresh(true)} lastGoodAt={lastGoodAt} />
      </div>
    )
  }

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
      <SuiteRail current="trust" context={{ vendor: chain?.vendorId ?? (vendorParam || null), asset: chain?.assetIds[0] ?? (assetParam || null) }} />

      <PageHeader
        title="Trust Chain Analyzer"
        subtitle="Analyze certificates, PKI, trust anchors, federation, and cryptographic trust relationships before migration."
        icon={Link2}
        live={live}
        generatedAt={data?.generatedAt}
        refreshing={refreshing || state === 'loading'}
        onRefresh={() => void refresh(true)}
        sophiaPrompt="Which trust chains are hardest to migrate, and which certificates create the most PQC migration risk?"
      />

      {error && data && <ErrorState message={error} onRetry={() => void refresh(true)} lastGoodAt={lastGoodAt} />}

      {state === 'loading' && !data ? <SkeletonPage rows={3} /> : data && (
        <>
          <KpiStrip items={[
            { key: 'chains', label: 'Trust Chains', value: numberFmt(data.summary.chains), detail: 'discovered from certificates', tone: 'neutral' },
            { key: 'critical', label: 'Critical Chains', value: numberFmt(data.summary.criticalChains), detail: 'critical or high risk', tone: data.summary.criticalChains ? 'critical' : 'good' },
            { key: 'expiring', label: 'Expiring Certificates', value: numberFmt(data.summary.expiringCertificates), detail: 'within 30 days', tone: data.summary.expiringCertificates ? 'warning' : 'good' },
            { key: 'legacy', label: 'Legacy Algorithms', value: numberFmt(data.summary.legacyAlgorithms), detail: 'weak or quantum-vulnerable', tone: data.summary.legacyAlgorithms ? 'warning' : 'good' },
            { key: 'external', label: 'External Trust Deps', value: numberFmt(data.summary.externalTrustDependencies), detail: 'externally operated issuers', tone: 'info' },
            { key: 'unknown', label: 'Unknown Relationships', value: numberFmt(data.summary.unknownRelationships), detail: 'insufficient evidence', tone: 'info' },
          ]} />

          {/* Trust graph — shares its filters with the chain list below */}
          <SectionCard
            id="trust-graph" title="Trust Graph" icon={Network}
            right={<span className="font-mono text-[9px] uppercase tracking-widest text-white/30">{numberFmt(chains.length)} / {numberFmt(data.chains.length)} chains</span>}
          >
            <div className="mb-3 flex flex-wrap items-center gap-2" role="group" aria-label="Chain filters — applied to the graph and the chain list">
              <SearchInput value={search} onChange={setSearch} label="Filter chains" placeholder="Filter by subject, issuer, asset…" />
              <Select label="Risk" value={riskFilter} onChange={setRiskFilter}
                options={[['all', 'All risk'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['unknown', 'Unknown']]} />
              <Select label="Trust state" value={stateFilter} onChange={setStateFilter}
                options={[['all', 'All states'], ['trusted', 'Trusted'], ['valid', 'Valid'], ['expiring', 'Expiring'], ['weak', 'Weak'], ['broken', 'Broken'], ['unknown', 'Unknown']]} />
              {filtersActive && (
                <button type="button" onClick={() => { setSearch(''); setRiskFilter('all'); setStateFilter('all') }}
                  className="rounded-lg border border-white/12 bg-white/5 px-2.5 py-1.5 text-[9px] font-black uppercase tracking-wider text-white/60">Clear</button>
              )}
              {vendorParam && (
                <span className="rounded border border-cyan-400/25 bg-cyan-500/10 px-2.5 py-1.5 text-[9.5px] text-cyan-200">
                  Vendor context: chains whose CA this vendor operates. <a href="/dashboard/trust-chain-analyzer" className="underline">Show all</a>
                </span>
              )}
              {assetParam && (
                <span className="rounded border border-cyan-400/25 bg-cyan-500/10 px-2.5 py-1.5 text-[9.5px] text-cyan-200">
                  Selected asset only. <a href="/dashboard/trust-chain-analyzer" className="underline">Show all chains</a>
                </span>
              )}
            </div>
            <TrustGraph
              chains={chains}
              findings={data.findings}
              certificates={data.certificates}
              generatedAt={data.generatedAt}
              status="ready"
              error={error}
              onRetry={() => void refresh(true)}
              focusNodeId={graphFocus}
              onSelectNode={onGraphSelect}
              filtered={filtersActive || Boolean(vendorParam || assetParam)}
            />
            <p className="mt-2 text-[10px] leading-relaxed text-white/35">
              Arrows follow trust delegation: anchor → certificate authority → certificate → relying system. Dashed elements are inferred (for example a root that was not captured). Use <b>Trace</b> to explain why a path is trusted, untrusted or unknown.
            </p>
          </SectionCard>

          {/* Trust agility — the number shared with Crypto Agility */}
          <SectionCard
            title="Trust Agility" icon={ShieldCheck}
            right={<DrawerLink href="/dashboard/crypto-agility">Open Crypto Agility <ArrowRight className="h-3 w-3" /></DrawerLink>}
          >
            <div className="grid gap-4 lg:grid-cols-[220px_minmax(0,1fr)]">
              <div className="rounded-lg border border-white/8 bg-black/25 p-3 text-center">
                <div className="font-mono text-[34px] font-black leading-none text-white">{scoreFmt(data.agility.score)}</div>
                <div className="mt-1 text-[10px] font-black uppercase tracking-widest text-cyan-300">{data.agility.level}</div>
                <div className="mt-1.5 text-[9px] text-white/35">Coverage {data.agility.coverage}%</div>
              </div>
              <div className="space-y-1.5">
                {data.agility.breakdown.map((row) => (
                  <div key={row.key} className="grid grid-cols-[minmax(0,1fr)_minmax(0,120px)_46px] items-center gap-3" title={row.basis}>
                    <span className="truncate text-[10.5px] font-bold text-white/70">{row.label}</span>
                    {row.score === null ? (
                      <span className="rounded border border-white/10 bg-white/5 px-2 py-0.5 text-center text-[8.5px] font-black uppercase tracking-wider text-white/45">Insufficient Evidence</span>
                    ) : (
                      <span className="h-2 overflow-hidden rounded-full bg-white/8">
                        <span className="block h-full rounded-full bg-cyan-400/70 transition-all duration-700" style={{ width: `${row.score}%` }} />
                      </span>
                    )}
                    <span className="text-right font-mono text-[10px] text-white/55">{row.score === null ? '—' : row.score}</span>
                  </div>
                ))}
              </div>
            </div>
            <p className="mt-3 border-t border-white/8 pt-2.5 text-[10px] leading-relaxed text-white/35">
              {data.agility.basis} This is the same value the Crypto Agility page publishes as its Trust Agility domain — one model, two views.
            </p>
          </SectionCard>

          {data.chains.length === 0 ? (
            <SectionCard title="Trust Chains" icon={Route}>
              <EmptyState icon={Link2} title="No Trust Chains"
                detail="No trust-chain evidence is available for this environment. Chains are built from discovered certificates and their recorded issuers — none are synthesised."
                cta={{ label: 'Analyze Trust State', href: '/dashboard/trust-state-discovery' }} />
            </SectionCard>
          ) : (
            <div className="grid gap-4 xl:grid-cols-[360px_minmax(0,1fr)]">
              {/* Chain selector */}
              <SectionCard title="Trust Chains" icon={Route}
                right={<span className="font-mono text-[9px] uppercase tracking-widest text-white/30">{numberFmt(chains.length)}</span>}>
                {(filtersActive || vendorParam || assetParam) && (
                  <div className="mb-2 rounded border border-cyan-400/25 bg-cyan-500/10 px-2.5 py-1.5 text-[9.5px] text-cyan-200">
                    Filtered by the Trust Graph controls. <a href="#trust-graph" className="underline">Adjust</a>
                  </div>
                )}
                {chains.length === 0 ? (
                  <EmptyState icon={Route} title="No chains match" detail="Adjust the filters to see the full set." />
                ) : (
                  <div className="max-h-[520px] space-y-1.5 overflow-y-auto pr-1 scrollbar-thin">
                    {chains.map((candidate) => (
                      <button key={candidate.id} type="button"
                        onClick={() => { setActiveChainId(candidate.id); setGraphFocus(`cert:${candidate.id.slice('chain-'.length)}`) }}
                        className={cn('w-full rounded-lg border p-2.5 text-left transition',
                          candidate.id === chain?.id ? 'border-cyan-400/50 bg-cyan-500/10' : 'border-white/8 bg-white/[0.015] hover:border-white/20')}>
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate text-[11px] font-black text-white/85" title={candidate.name}>{candidate.name}</span>
                          <RiskChip value={candidate.risk} />
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-1.5">
                          <TrustChip value={candidate.state} />
                          {candidate.external && <Chip tone="info">External CA</Chip>}
                        </div>
                        <div className="mt-1 truncate text-[9px] text-white/35">
                          {candidate.certificate?.issuer || 'Issuer not recorded'}
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </SectionCard>

              {/* Chain detail */}
              <div className="space-y-4">
                {chain && (
                  <>
                    <SectionCard
                      title={compare ? 'Current vs Proposed Chain' : 'Trust Chain'} icon={GitCompare}
                      right={
                        <button type="button" onClick={() => setCompare((value) => !value)}
                          className={cn('rounded border px-2.5 py-1 text-[9px] font-black uppercase tracking-wider transition',
                            compare ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200' : 'border-white/10 bg-white/5 text-white/55 hover:text-cyan-300')}>
                          <GitCompare className="mr-1 inline h-3 w-3" />{compare ? 'Show current only' : 'Compare Current vs Proposed'}
                        </button>
                      }
                    >
                      <div className="mb-3 flex flex-wrap items-center gap-2">
                        <span className="text-[13px] font-black text-white">{chain.name}</span>
                        <TrustChip value={chain.state} />
                        <RiskChip value={chain.risk} />
                        {chain.vendorId && <Chip tone="info">Vendor dependency</Chip>}
                      </div>

                      <div className={cn('grid gap-3', compare && 'lg:grid-cols-2')}>
                        <ChainLadder nodes={chain.nodes} title="Current" tone="current" />
                        {compare && <ChainLadder nodes={chain.proposed.nodes} title="Proposed (post-quantum)" tone="proposed" />}
                      </div>

                      {compare && (
                        <div className={cn('mt-3 rounded-lg border p-3',
                          chain.proposed.feasibility === 'supported' ? 'border-emerald-500/25 bg-emerald-500/[0.06]' : 'border-amber-500/25 bg-amber-500/[0.07]')}>
                          <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wider text-amber-200">
                            <AlertTriangle className="h-3 w-3" />
                            {chain.proposed.feasibility === 'supported' ? 'Already post-quantum' : chain.proposed.feasibility === 'requires-ca-support' ? 'Requires CA support — unverified' : 'Feasibility unknown'}
                          </div>
                          <p className="mt-1 text-[10.5px] leading-relaxed text-white/55">{chain.proposed.note}</p>
                        </div>
                      )}

                      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
                        {[
                          ['Applications', chain.migrationImpact.applications], ['Services', chain.migrationImpact.services],
                          ['Certificates', chain.migrationImpact.certificates], ['Trust anchors', chain.migrationImpact.trustAnchors],
                          ['Vendor deps', chain.migrationImpact.vendorDependencies], ['Issues', chain.migrationImpact.compatibilityIssues.length],
                        ].map(([label, value]) => (
                          <div key={String(label)} className="rounded-lg border border-white/8 bg-black/25 px-2.5 py-2">
                            <div className="text-[8px] font-black uppercase tracking-wider text-white/40">{label}</div>
                            <div className="mt-0.5 font-mono text-[15px] font-black text-white">{numberFmt(Number(value))}</div>
                          </div>
                        ))}
                      </div>
                      {chain.migrationImpact.compatibilityIssues.length > 0 && (
                        <ul className="mt-2 space-y-1">
                          {chain.migrationImpact.compatibilityIssues.map((issue, index) => (
                            <li key={index} className="text-[10px] leading-relaxed text-amber-200/80">· {issue}</li>
                          ))}
                        </ul>
                      )}

                      <div className="mt-3 flex flex-wrap gap-2 border-t border-white/8 pt-3">
                        <DrawerLink href={`/dashboard/ecosystem-dependency-map${chain.assetIds[0] ? `?focus=${encodeURIComponent(`asset:${chain.assetIds[0]}`)}` : ''}`} primary>
                          <Globe2 className="h-3 w-3" /> View Ecosystem Impact
                        </DrawerLink>
                        <DrawerLink href={`/dashboard/hybrid-crypto-lab${chain.assetIds[0] ? `?asset=${encodeURIComponent(chain.assetIds[0])}` : ''}`}>
                          <FlaskConical className="h-3 w-3" /> Validate Proposed Configuration
                        </DrawerLink>
                        <DrawerLink href="/dashboard/migration-planner">Create Migration Plan</DrawerLink>
                        {chain.vendorId && (
                          <DrawerLink href={`/dashboard/vendor-pqc-readiness?vendor=${encodeURIComponent(chain.vendorId)}`}>
                            <BadgeCheck className="h-3 w-3" /> Request Vendor Evidence
                          </DrawerLink>
                        )}
                        <AskSophiaButton question={`Analyze the trust chain "${chain.name}": what makes it hard to migrate to a post-quantum certificate?`} context="Trust Chain Analyzer" />
                      </div>
                      <p className="mt-2 text-[9.5px] text-white/30">{chain.basis}</p>
                    </SectionCard>

                    {/* Certificate detail */}
                    {chain.certificate && (
                      <SectionCard title="Certificate Detail" icon={ShieldCheck}>
                        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                          <Field label="Subject" value={chain.certificate.subject} />
                          <Field label="Issuer" value={chain.certificate.issuer} />
                          <Field label="Trust anchor" value={chain.certificate.trustAnchor} />
                          <Field label="Public key algorithm" value={chain.certificate.publicKeyAlgorithm} mono />
                          <Field label="Signature algorithm" value={chain.certificate.signatureAlgorithm} mono />
                          <Field label="Key size" value={chain.certificate.keySize ? `${chain.certificate.keySize}-bit` : 'Unknown'} mono />
                          <Field label="Valid from" value={dateFmt(chain.certificate.notBefore)} />
                          <Field label="Valid to" value={dateFmt(chain.certificate.notAfter)} />
                          <Field label="Days to expiry" value={chain.certificate.daysToExpiry === null ? 'Unknown' : String(chain.certificate.daysToExpiry)} mono />
                          <Field label="Renewal" value={chain.certificate.renewalMechanism} />
                          <Field label="Owner" value={chain.certificate.owner} />
                          <Field label="Environment" value={chain.certificate.environment} />
                        </div>
                        <p className="mt-2 text-[9.5px] leading-relaxed text-white/30">
                          {chain.certificate.basis} No private key or secret material is ever read or displayed.
                        </p>
                      </SectionCard>
                    )}

                    {/* Findings */}
                    <SectionCard title="Trust Findings" icon={FileWarning}
                      right={<Chip tone={chainFindings.length ? 'warning' : 'good'}>{numberFmt(chainFindings.length)} on this chain</Chip>}>
                      {chainFindings.length === 0 ? (
                        <EmptyState icon={ShieldCheck} title="No findings on this chain"
                          detail="Nothing in the available certificate evidence flags this chain. Coverage depends on what has been discovered." />
                      ) : (
                        <div className="space-y-1.5">
                          {chainFindings.map((finding) => (
                            <button key={finding.id} type="button" onClick={() => setFindingDrawer(finding)}
                              className="grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-3 rounded-lg border border-white/8 bg-white/[0.015] p-2.5 text-left transition hover:border-cyan-400/30">
                              <FileWarning className={cn('mt-0.5 h-4 w-4 shrink-0',
                                finding.severity === 'critical' ? 'text-red-400' : finding.severity === 'high' ? 'text-amber-400' : 'text-cyan-300')} />
                              <div className="min-w-0">
                                <div className="flex flex-wrap items-center gap-1.5">
                                  <span className="truncate text-[11px] font-black text-white/85">{TRUST_FINDING_LABEL[finding.kind]}</span>
                                  <RiskChip value={finding.severity} />
                                </div>
                                <div className="mt-0.5 truncate text-[9.5px] text-white/45">{finding.evidence}</div>
                              </div>
                              <ArrowRight className="h-3.5 w-3.5 shrink-0 text-white/20" />
                            </button>
                          ))}
                        </div>
                      )}
                    </SectionCard>
                  </>
                )}
              </div>
            </div>
          )}

          {/* All findings across chains */}
          {data.findings.length > 0 && (
            <SectionCard title="All Trust Findings" icon={AlertTriangle} right={<Chip tone="warning">{numberFmt(data.findings.length)}</Chip>}>
              <div className="max-h-[340px] space-y-1 overflow-y-auto pr-1 scrollbar-thin">
                {data.findings.slice(0, 80).map((finding) => (
                  <button key={finding.id} type="button" onClick={() => setFindingDrawer(finding)}
                    className="flex w-full items-center justify-between gap-3 rounded-lg border border-white/6 bg-white/[0.015] px-3 py-2 text-left transition hover:border-cyan-400/25">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="truncate text-[10.5px] font-bold text-white/80">{finding.title}</span>
                        <RiskChip value={finding.severity} />
                      </div>
                      <div className="mt-0.5 truncate text-[9px] text-white/35">{finding.evidence} · {finding.evidenceSource}</div>
                    </div>
                    <ArrowRight className="h-3.5 w-3.5 shrink-0 text-white/20" />
                  </button>
                ))}
              </div>
            </SectionCard>
          )}

          <ProvenanceFooter evidence={data.evidence} generatedAt={data.generatedAt}
            extra={`${numberFmt(data.certificates.length)} certificate(s) analyzed`} />
        </>
      )}

      <Drawer
        open={Boolean(findingDrawer)}
        title={findingDrawer ? TRUST_FINDING_LABEL[findingDrawer.kind] : ''}
        subtitle={findingDrawer?.evidenceSource || ''}
        tone={findingDrawer?.severity === 'critical' ? 'critical' : findingDrawer?.severity === 'high' ? 'warning' : 'neutral'}
        onClose={() => setFindingDrawer(null)}
        footer={findingDrawer && (
          <div className="flex flex-wrap gap-2">
            <DrawerLink href={findingDrawer.route} primary>Open module <ArrowRight className="h-3 w-3" /></DrawerLink>
            <DrawerLink href="/dashboard/hybrid-crypto-lab"><FlaskConical className="h-3 w-3" /> Run Hybrid Test</DrawerLink>
            <AskSophiaButton question={`Explain this trust finding: ${findingDrawer.title} — ${findingDrawer.evidence}`} context="Trust Chain Analyzer" />
          </div>
        )}
      >
        {findingDrawer && (
          <>
            <div className="flex flex-wrap gap-1.5">
              <RiskChip value={findingDrawer.severity} />
              <Chip tone="info">{TRUST_FINDING_LABEL[findingDrawer.kind]}</Chip>
            </div>
            <Block title="Evidence">
              <div className="rounded-lg border border-white/8 bg-black/30 p-2.5">
                <div className="break-words font-mono text-[10.5px] text-cyan-300/80">{findingDrawer.evidence}</div>
                <div className="mt-1 text-[9px] uppercase tracking-wider text-white/30">Source: {findingDrawer.evidenceSource}</div>
              </div>
            </Block>
            <Block title="Recommended action">
              <p className="rounded-lg border border-cyan-400/20 bg-cyan-500/[0.05] p-2.5 text-[10.5px] leading-relaxed text-white/65">{findingDrawer.recommendedAction}</p>
            </Block>
            {findingDrawer.affectedAssetNames.length > 0 && (
              <Block title="Affected assets">
                <div className="flex flex-wrap gap-1">
                  {findingDrawer.affectedAssetNames.map((name) => (
                    <span key={name} className="rounded border border-white/10 bg-black/25 px-2 py-1 font-mono text-[9.5px] text-white/55">{name}</span>
                  ))}
                </div>
              </Block>
            )}
          </>
        )}
      </Drawer>
    </div>
  )
}
