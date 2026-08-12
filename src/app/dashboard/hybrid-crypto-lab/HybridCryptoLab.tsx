'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, ArrowRight, BadgeCheck, Beaker, CheckCircle2, Download, FileCheck2,
  FlaskConical, Globe2, Link2, Loader2, Play, ShieldAlert, Sparkles, Wand2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { WorkflowRail } from '@/components/workflow/WorkflowRail'
import { useExternalTrustActions, useHybridLab } from '@/hooks/use-external-trust'
import {
  EXECUTION_MODE_LABEL, EXPERIMENT_LABEL, HASH_OPTIONS, KDF_OPTIONS, KEY_EXCHANGE_OPTIONS,
  SIGNATURE_OPTIONS, SYMMETRIC_OPTIONS, validateExperimentConfiguration,
  type ExecutionMode, type ExperimentConfiguration, type ExperimentRecord, type ExperimentTarget,
} from '@/lib/ecosystem/external-trust-intelligence'
import {
  AskSophiaButton, Block, CapabilityNotice, Chip, Drawer, DrawerLink, EmptyState,
  ErrorState, Field, KpiStrip, OutcomeChip, PageHeader, ProvenanceFooter, RiskChip,
  SearchInput, SectionCard, Select, SkeletonPage, SuiteRail, VerdictChip, csvCell,
  dateFmt, downloadTextFile, numberFmt, relativeTime, useQueryParam,
} from '../_components/external-trust/_shared'

/**
 * Hybrid Crypto Lab.
 *
 * One job: **Configure → Test → Analyze → Generate Evidence**.
 *
 * The lab does NOT implement cryptography in the browser. It submits an
 * experiment specification to the backend, which either projects over stored
 * evidence (simulation) or performs a READ-ONLY TLS handshake probe against a
 * public host (controlled test). No mode mutates production, and every result
 * is labelled experimental.
 */

const DEFAULT_CONFIG: ExperimentConfiguration = {
  protocol: 'TLS 1.3',
  keyExchange: 'X25519+ML-KEM-768',
  signature: 'Ed25519+ML-DSA-65',
  symmetric: 'AES-256-GCM',
  kdf: 'HKDF-SHA3-256',
  hash: 'SHA3-256',
}

type Step = 1 | 2 | 3 | 4

export default function HybridCryptoLab() {
  const vendorParam = useQueryParam('vendor')
  const assetParam = useQueryParam('asset')
  const { data, state, error, live, lastGoodAt, refresh } = useHybridLab()
  const { runExperiment, generateEvidence, loadRecommendation } = useExternalTrustActions()

  const [step, setStep] = useState<Step>(1)
  const [targetId, setTargetId] = useState('')
  const [targetSearch, setTargetSearch] = useState('')
  const [config, setConfig] = useState<ExperimentConfiguration>(DEFAULT_CONFIG)
  const [mode, setMode] = useState<ExecutionMode>('simulation')
  const [observed, setObserved] = useState<{ algorithms: string[]; protocols: string[] } | null>(null)
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<ExperimentRecord | null>(null)
  const [persistNote, setPersistNote] = useState<string | null>(null)
  const [runError, setRunError] = useState<string | null>(null)
  const [historyFilter, setHistoryFilter] = useState('all')
  const [detail, setDetail] = useState<ExperimentRecord | null>(null)
  const [compareIds, setCompareIds] = useState<string[]>([])
  const [evidenceNote, setEvidenceNote] = useState<string | null>(null)

  const targets = useMemo(() => {
    if (!data) return []
    const term = targetSearch.trim().toLowerCase()
    return data.targets.filter((target) => {
      if (vendorParam && target.vendorId !== vendorParam) return false
      if (assetParam && target.assetId !== assetParam) return false
      if (term && !`${target.label} ${target.host}`.toLowerCase().includes(term)) return false
      return true
    })
  }, [data, targetSearch, vendorParam, assetParam])

  const target: ExperimentTarget | null = useMemo(
    () => targets.find((candidate) => candidate.id === targetId) ?? null,
    [targets, targetId],
  )

  // A cross-page link preselects the target so the user lands mid-flow.
  useEffect(() => {
    if (targetId || !targets.length) return
    setTargetId(targets[0].id)
  }, [targets, targetId])

  useEffect(() => {
    if (!targetId) return
    let active = true
    void loadRecommendation(targetId)
      .then((payload) => {
        if (!active) return
        setObserved(payload.observed)
        setConfig(payload.recommended as unknown as ExperimentConfiguration)
      })
      .catch(() => { if (active) setObserved(null) })
    return () => { active = false }
  }, [targetId, loadRecommendation])

  const configIssues = useMemo(() => validateExperimentConfiguration(config), [config])

  /** "Create Experiment" sends the user to step 1 of the builder, not nowhere. */
  const openBuilder = useCallback(() => {
    setStep(1)
    document.getElementById('experiment-builder')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [])

  const run = useCallback(async () => {
    if (!target) return
    setRunning(true)
    setRunError(null)
    setPersistNote(null)
    setEvidenceNote(null)
    try {
      const payload = await runExperiment({ targetId: target.id, executionMode: mode, configuration: config as unknown as Record<string, string> })
      // No cast: the API returns the SAME ExperimentRecord the history returns.
      // A cast here previously hid the fact that it did not.
      setResult(payload.experiment)
      if (!payload.persisted && payload.persistenceNote) setPersistNote(payload.persistenceNote)
      setStep(4)
      await refresh(true)
    } catch (err) {
      setRunError(err instanceof Error ? err.message : 'Experiment failed')
    } finally {
      setRunning(false)
    }
  }, [target, mode, config, runExperiment, refresh])

  const history = useMemo(() => {
    if (!data) return []
    return data.experiments.filter((experiment) => historyFilter === 'all' || experiment.outcome === historyFilter)
  }, [data, historyFilter])

  const comparison = useMemo(
    () => (data ? compareIds.map((id) => data.experiments.find((experiment) => experiment.id === id)).filter(Boolean) as ExperimentRecord[] : []),
    [data, compareIds],
  )

  const resultChecks = result?.checks ?? []
  const resultFindings = result?.findings ?? []

  const exportHistory = () => {
    if (!data) return
    const header = ['Date', 'Target', 'Host', 'Environment', 'Mode', 'Key Exchange', 'Signature', 'Outcome', 'Risk', 'Duration (ms)', 'Evidence']
    const lines = data.experiments.map((experiment) => [
      experiment.createdAt, experiment.target.label, experiment.target.host, experiment.target.environment,
      experiment.executionMode, experiment.proposedConfiguration.keyExchange, experiment.proposedConfiguration.signature,
      EXPERIMENT_LABEL[experiment.outcome], experiment.risk, experiment.durationMs, experiment.evidenceGenerated ? 'generated' : 'none',
    ].map(csvCell).join(','))
    downloadTextFile(`qguard-hybrid-lab-${new Date().toISOString().slice(0, 10)}.csv`, [header.map(csvCell).join(','), ...lines].join('\n'), 'text/csv;charset=utf-8')
  }

  if (state === 'error' && !data) {
    return (
      <div className="min-h-screen space-y-4 p-3 lg:p-5">
        <SuiteRail current="lab" />
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
      <SuiteRail current="lab" />

      <PageHeader
        title="Hybrid Crypto Lab"
        subtitle="Safely evaluate hybrid cryptographic configurations and compatibility before production migration."
        icon={FlaskConical}
        live={live}
        generatedAt={data?.generatedAt}
        refreshing={state === 'loading'}
        onRefresh={() => void refresh(true)}
        sophiaPrompt="What hybrid configuration should we test next, and what dependencies should I validate before production?"
        actions={
          <button type="button" onClick={exportHistory} disabled={!data?.experiments.length}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60 transition hover:border-cyan-400/40 hover:text-cyan-300 disabled:opacity-40">
            <Download className="h-3.5 w-3.5" /> Export
          </button>
        }
      />

      {state === 'loading' && !data ? <SkeletonPage rows={3} /> : data && (
        <>
          <KpiStrip items={[
            { key: 'experiments', label: 'Experiments', value: numberFmt(data.summary.experiments), detail: 'recorded runs', tone: 'neutral' },
            { key: 'passed', label: 'Passed', value: numberFmt(data.summary.passed), detail: 'all dimensions pass', tone: 'good', onClick: () => setHistoryFilter('passed') },
            { key: 'conditional', label: 'Conditional', value: numberFmt(data.summary.conditional), detail: 'passed with warnings', tone: 'warning', onClick: () => setHistoryFilter('conditional') },
            { key: 'failed', label: 'Failed', value: numberFmt(data.summary.failed), detail: 'blocking failure', tone: data.summary.failed ? 'critical' : 'good', onClick: () => setHistoryFilter('failed') },
            { key: 'issues', label: 'Compatibility Issues', value: numberFmt(data.summary.compatibilityIssues), detail: 'across all experiments', tone: 'warning' },
            { key: 'evidence', label: 'Evidence Generated', value: numberFmt(data.summary.evidenceGenerated), detail: 'experimental records', tone: 'info' },
          ]} />

          {!data.persistenceAvailable && (
            <CapabilityNotice
              title="Experiment history is not provisioned"
              detail="Experiments will still run and return results, but cannot be retained until supabase/external-trust-schema.sql is applied. Nothing is fabricated in the meantime."
            />
          )}

          {/* Safe execution model */}
          <div className="grid gap-2 sm:grid-cols-3">
            {([
              ['Simulation', 'No production impact. Projects over stored tenant evidence; opens no connection.', 'good'],
              ['Controlled Test', 'Read-only TLS handshake probe against a public host, behind the platform SSRF guard.', 'warning'],
              ['Production', 'Never executed from this page. Production change happens only through Live Migration Operations.', 'critical'],
            ] as const).map(([label, detailText, tone]) => (
              <div key={label} className={cn('rounded-lg border px-3 py-2',
                tone === 'good' ? 'border-emerald-500/25 bg-emerald-500/[0.05]' : tone === 'warning' ? 'border-amber-500/25 bg-amber-500/[0.05]' : 'border-red-500/25 bg-red-500/[0.05]')}>
                <div className="text-[9.5px] font-black uppercase tracking-wider text-white/70">{label}</div>
                <div className="mt-0.5 text-[9.5px] leading-relaxed text-white/45">{detailText}</div>
              </div>
            ))}
          </div>

          {data.targets.length === 0 ? (
            <SectionCard title="Experiment Builder" icon={Beaker}>
              <EmptyState icon={FlaskConical} title="No Experiments"
                detail="No hybrid cryptographic experiments have been performed, and no testable target has been discovered. Targets come from discovered assets with a resolvable hostname and from observed vendor surfaces."
                cta={{ label: 'Run Discovery', href: '/dashboard/scanner' }} />
            </SectionCard>
          ) : (
            <SectionCard
              id="experiment-builder"
              title="Experiment Builder" icon={Beaker}
              right={
                <div className="flex items-center gap-1">
                  {([1, 2, 3, 4] as Step[]).map((value) => (
                    <button key={value} type="button" onClick={() => setStep(value)}
                      className={cn('grid h-6 w-6 place-items-center rounded border text-[9px] font-black transition',
                        step === value ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200' : 'border-white/10 bg-white/5 text-white/40')}>
                      {value}
                    </button>
                  ))}
                </div>
              }
            >
              {/* Step 1 — Target */}
              {step === 1 && (
                <div className="space-y-3">
                  <div className="text-[11px] font-black uppercase tracking-wider text-white/60">Step 1 — Select target</div>
                  <SearchInput value={targetSearch} onChange={setTargetSearch} label="Search targets" placeholder="Search assets, vendors, hosts…" />
                  <div className="max-h-[260px] space-y-1 overflow-y-auto pr-1 scrollbar-thin">
                    {targets.map((candidate) => (
                      <button key={candidate.id} type="button" onClick={() => setTargetId(candidate.id)}
                        className={cn('flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2 text-left transition',
                          candidate.id === targetId ? 'border-cyan-400/50 bg-cyan-500/10' : 'border-white/8 bg-white/[0.015] hover:border-white/20')}>
                        <div className="min-w-0">
                          <div className="truncate text-[11px] font-black text-white/85">{candidate.label}</div>
                          <div className="truncate font-mono text-[9px] text-white/40">{candidate.host}:{candidate.port} · {candidate.environment}</div>
                        </div>
                        <Chip tone="info">{candidate.kind}</Chip>
                      </button>
                    ))}
                    {targets.length === 0 && <EmptyState icon={FlaskConical} title="No matching target" detail="Adjust the search or clear the vendor/asset filter." />}
                  </div>
                  <button type="button" disabled={!target} onClick={() => setStep(2)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200 disabled:opacity-40">
                    Next: current configuration <ArrowRight className="h-3 w-3" />
                  </button>
                </div>
              )}

              {/* Step 2 — Current configuration */}
              {step === 2 && target && (
                <div className="space-y-3">
                  <div className="text-[11px] font-black uppercase tracking-wider text-white/60">Step 2 — Current configuration (observed)</div>
                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                    <Field label="Target" value={target.label} />
                    <Field label="Host" value={`${target.host}:${target.port}`} mono />
                    <Field label="Environment" value={target.environment} />
                    <Field label="Observed protocols" value={observed?.protocols.length ? observed.protocols.join(', ') : 'Not observed'} mono />
                    <Field label="Observed algorithms" value={observed?.algorithms.length ? observed.algorithms.slice(0, 4).join(', ') : 'Not observed'} mono />
                    <Field label="Provider/library" value={observed?.algorithms.length ? 'From CBOM evidence' : 'Not observed'} />
                  </div>
                  {!observed?.algorithms.length && !observed?.protocols.length && (
                    <div className="rounded-lg border border-amber-500/25 bg-amber-500/[0.07] p-2.5 text-[10px] leading-relaxed text-white/55">
                      <AlertTriangle className="mr-1.5 inline h-3.5 w-3.5 text-amber-300" />
                      No stored cryptographic evidence for this target. A simulation would have nothing to project over — run a controlled test to measure it directly, or scan the asset first.
                    </div>
                  )}
                  <div className="flex gap-2">
                    <button type="button" onClick={() => setStep(1)} className="rounded-lg border border-white/12 bg-white/5 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60">Back</button>
                    <button type="button" onClick={() => setStep(3)} className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200">
                      Next: proposed configuration <ArrowRight className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              )}

              {/* Step 3 — Proposed configuration */}
              {step === 3 && target && (
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="text-[11px] font-black uppercase tracking-wider text-white/60">Step 3 — Proposed configuration</div>
                    <button type="button" onClick={() => setConfig(DEFAULT_CONFIG)}
                      className="inline-flex items-center gap-1.5 rounded border border-white/12 bg-white/5 px-2.5 py-1 text-[9px] font-black uppercase tracking-wider text-white/60">
                      <Wand2 className="h-3 w-3" /> Platform recommended
                    </button>
                  </div>

                  <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                    <ConfigSelect label="Protocol" value={config.protocol} options={['TLS 1.3', 'TLS 1.2']}
                      onChange={(value) => setConfig((current) => ({ ...current, protocol: value as ExperimentConfiguration['protocol'] }))} />
                    <ConfigSelect label="Key establishment" value={config.keyExchange} options={[...KEY_EXCHANGE_OPTIONS]}
                      onChange={(value) => setConfig((current) => ({ ...current, keyExchange: value as ExperimentConfiguration['keyExchange'] }))} />
                    <ConfigSelect label="Signature" value={config.signature} options={[...SIGNATURE_OPTIONS]}
                      onChange={(value) => setConfig((current) => ({ ...current, signature: value as ExperimentConfiguration['signature'] }))} />
                    <ConfigSelect label="Symmetric" value={config.symmetric} options={[...SYMMETRIC_OPTIONS]}
                      onChange={(value) => setConfig((current) => ({ ...current, symmetric: value as ExperimentConfiguration['symmetric'] }))} />
                    <ConfigSelect label="KDF" value={config.kdf} options={[...KDF_OPTIONS]}
                      onChange={(value) => setConfig((current) => ({ ...current, kdf: value as ExperimentConfiguration['kdf'] }))} />
                    <ConfigSelect label="Hash" value={config.hash} options={[...HASH_OPTIONS]}
                      onChange={(value) => setConfig((current) => ({ ...current, hash: value as ExperimentConfiguration['hash'] }))} />
                  </div>

                  <p className="text-[9.5px] leading-relaxed text-white/35">
                    Options are restricted by algorithm purpose: ML-KEM performs key establishment only, ML-DSA signs only. Invalid combinations are rejected rather than offered.
                  </p>

                  {configIssues.length > 0 && (
                    <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-2.5">
                      <div className="text-[10px] font-black uppercase tracking-wider text-red-200">Configuration is not valid</div>
                      <ul className="mt-1 space-y-0.5">
                        {configIssues.map((issue, index) => (
                          <li key={index} className="text-[10px] leading-relaxed text-white/60">· {issue.message}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div>
                    <div className="mb-1.5 text-[9px] font-black uppercase tracking-widest text-white/40">Execution mode</div>
                    <div className="grid gap-2 sm:grid-cols-2">
                      {(['simulation', 'controlled-test'] as ExecutionMode[]).map((value) => (
                        <button key={value} type="button" onClick={() => setMode(value)}
                          className={cn('rounded-lg border px-3 py-2 text-left transition',
                            mode === value ? 'border-cyan-400/50 bg-cyan-500/10' : 'border-white/8 bg-white/[0.015] hover:border-white/20')}>
                          <div className="text-[10px] font-black uppercase tracking-wider text-white/75">{value === 'simulation' ? 'Simulation' : 'Controlled Test'}</div>
                          <div className="mt-0.5 text-[9.5px] leading-relaxed text-white/45">{EXECUTION_MODE_LABEL[value]}</div>
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <button type="button" onClick={() => setStep(2)} className="rounded-lg border border-white/12 bg-white/5 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60">Back</button>
                    <button type="button" disabled={running || configIssues.length > 0} onClick={() => void run()}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-4 py-2 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 disabled:opacity-40">
                      {running ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />} Run Experiment
                    </button>
                  </div>
                  {runError && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-2.5 text-[10.5px] text-red-200">{runError}</div>}
                </div>
              )}

              {/* Step 4 — Result */}
              {step === 4 && (
                result ? (
                  <div className="space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-black uppercase tracking-wider text-white/60">Result</span>
                        <OutcomeChip value={result.outcome} />
                        <RiskChip value={result.risk} />
                      </div>
                      <span className="font-mono text-[9px] text-white/35">{result.durationMs}ms · {result.executionMode}</span>
                    </div>

                    <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                      {resultChecks.map((check) => (
                        <div key={check.key} className="rounded-lg border border-white/8 bg-black/25 px-2.5 py-2">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-[9px] font-black uppercase tracking-wider text-white/50">{check.label}</span>
                            <VerdictChip value={check.verdict} />
                          </div>
                          <div className="mt-1 text-[9px] leading-relaxed text-white/45">{check.detail}</div>
                          <div className={cn('mt-1 text-[8px] font-black uppercase tracking-wider',
                            check.method === 'measured' ? 'text-emerald-300/70' : check.method === 'evidence-derived' ? 'text-cyan-300/60' : 'text-white/25')}>
                            {check.method === 'measured' ? '● measured' : check.method === 'evidence-derived' ? '◐ evidence-derived' : '○ not evaluated'}
                          </div>
                        </div>
                      ))}
                    </div>

                    {resultFindings.length > 0 && (
                      <Block title="Failure analysis">
                        <div className="space-y-2">
                          {resultFindings.map((finding) => (
                            <div key={finding.id} className="rounded-lg border border-red-500/25 bg-red-500/[0.06] p-3">
                              <div className="flex flex-wrap items-center gap-1.5">
                                <ShieldAlert className="h-3.5 w-3.5 text-red-300" />
                                <span className="text-[11px] font-black text-white/90">{finding.title}</span>
                                <RiskChip value={finding.severity} />
                                <Chip tone="info">{finding.component}</Chip>
                              </div>
                              <div className="mt-1.5 grid gap-1.5 sm:grid-cols-2">
                                <Field label="Evidence" value={finding.evidence} />
                                <Field label="Likely cause" value={finding.likelyCause} />
                              </div>
                              <p className="mt-1.5 text-[10.5px] leading-relaxed text-cyan-200/80">{finding.recommendedAction}</p>
                              <div className="mt-2 flex flex-wrap gap-2">
                                <DrawerLink href={finding.route} primary>Open module <ArrowRight className="h-3 w-3" /></DrawerLink>
                                <DrawerLink href="/dashboard/trust-chain-analyzer"><Link2 className="h-3 w-3" /> Analyze Trust Chain</DrawerLink>
                                <DrawerLink href="/dashboard/ecosystem-dependency-map"><Globe2 className="h-3 w-3" /> View Dependencies</DrawerLink>
                                <DrawerLink href="/dashboard/migration-planner">Create Migration Task</DrawerLink>
                              </div>
                            </div>
                          ))}
                        </div>
                      </Block>
                    )}

                    <div className="rounded-lg border border-amber-500/25 bg-amber-500/[0.07] p-2.5">
                      <div className="text-[10px] font-black uppercase tracking-wider text-amber-200">Experimental Evidence — Production Validation Required</div>
                      <p className="mt-1 text-[10px] leading-relaxed text-white/55">{result.basis}</p>
                    </div>

                    {persistNote && <CapabilityNotice title="Result not stored" detail={persistNote} />}
                    {evidenceNote && (
                      <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-[10.5px] text-emerald-200">{evidenceNote}</div>
                    )}

                    <div className="flex flex-wrap gap-2">
                      <button type="button" onClick={() => setStep(3)} className="rounded-lg border border-white/12 bg-white/5 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/60">Adjust configuration</button>
                      {data.persistenceAvailable && result.id && !result.id.startsWith('ephemeral') && (
                        <button type="button" onClick={async () => {
                          try {
                            const payload = await generateEvidence(result.id)
                            setEvidenceNote(`${payload.disclaimer}. Evidence record ${payload.evidenceId} created.`)
                            await refresh(true)
                          } catch (err) {
                            setRunError(err instanceof Error ? err.message : 'Evidence generation failed')
                          }
                        }}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200">
                          <FileCheck2 className="h-3 w-3" /> Generate Evidence
                        </button>
                      )}
                      <DrawerLink href="/dashboard/migration-planner">Create Migration Plan</DrawerLink>
                      <AskSophiaButton question={`Why did this hybrid test on ${result.target.label} return "${EXPERIMENT_LABEL[result.outcome]}"? What should we test next?`} context="Hybrid Crypto Lab" />
                    </div>
                  </div>
                ) : (
                  <EmptyState icon={Beaker} title="No result yet" detail="Configure and run an experiment to see per-dimension verdicts." />
                )
              )}
            </SectionCard>
          )}

          {/* History */}
          <SectionCard
            title="Experiment History" icon={FlaskConical}
            right={
              <div className="flex items-center gap-2">
                <Select label="Outcome" value={historyFilter} onChange={setHistoryFilter}
                  options={[['all', 'All outcomes'], ['passed', 'Passed'], ['passed-with-warnings', 'Passed with Warnings'], ['conditional', 'Conditional'], ['failed', 'Failed'], ['not-evaluated', 'Not Evaluated']]} />
                <span className="font-mono text-[9px] uppercase tracking-widest text-white/30">{numberFmt(history.length)}</span>
              </div>
            }
          >
            {data.experiments.length === 0 ? (
              <EmptyState icon={FlaskConical} title="No Experiments"
                detail="No hybrid cryptographic experiments have been performed."
                cta={{ label: 'Create Experiment', onClick: openBuilder }} />
            ) : history.length === 0 ? (
              // A filter that matches nothing must say so. Rendering the bare
              // header row reads as "the history is gone", not "0 of 4 match".
              <EmptyState icon={FlaskConical} title="No experiments match this filter"
                detail={`None of the ${numberFmt(data.experiments.length)} recorded experiment(s) ended in "${EXPERIMENT_LABEL[historyFilter as keyof typeof EXPERIMENT_LABEL] ?? historyFilter}".`}
                cta={{ label: 'Show all outcomes', onClick: () => setHistoryFilter('all') }} />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[860px] border-collapse text-left">
                  <caption className="sr-only">Experiment history with date, target, configuration, execution mode, result and risk.</caption>
                  <thead>
                    <tr className="border-b border-white/10">
                      <th scope="col" className="w-8 px-2 py-2"><span className="sr-only">Compare</span></th>
                      {['Date', 'Target', 'Configuration', 'Mode', 'Result', 'Risk', 'Evidence'].map((label) => (
                        <th key={label} scope="col" className="px-2.5 py-2 text-[8.5px] font-black uppercase tracking-[0.14em] text-cyan-300/70">{label}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {history.map((experiment) => (
                      <tr key={experiment.id} className="cursor-pointer transition hover:bg-cyan-500/[0.05]" onClick={() => setDetail(experiment)}>
                        <td className="px-2 py-2" onClick={(event) => event.stopPropagation()}>
                          <input type="checkbox" aria-label={`Compare ${experiment.target.label}`}
                            checked={compareIds.includes(experiment.id)}
                            onChange={() => setCompareIds((current) =>
                              current.includes(experiment.id) ? current.filter((id) => id !== experiment.id) : [...current, experiment.id].slice(-2))}
                            className="h-3 w-3 accent-cyan-400" />
                        </td>
                        <td className="px-2.5 py-2 font-mono text-[10px] text-white/50">{relativeTime(experiment.createdAt)}</td>
                        <td className="px-2.5 py-2">
                          <div className="max-w-[180px] truncate text-[10.5px] font-bold text-white/80">{experiment.target.label}</div>
                          <div className="truncate font-mono text-[9px] text-white/35">{experiment.target.host}</div>
                        </td>
                        <td className="px-2.5 py-2">
                          <div className="max-w-[220px] truncate font-mono text-[9.5px] text-cyan-300/70">
                            {experiment.proposedConfiguration.keyExchange} · {experiment.proposedConfiguration.signature}
                          </div>
                        </td>
                        <td className="px-2.5 py-2"><Chip tone={experiment.executionMode === 'controlled-test' ? 'warning' : 'good'}>{experiment.executionMode}</Chip></td>
                        <td className="px-2.5 py-2"><OutcomeChip value={experiment.outcome} /></td>
                        <td className="px-2.5 py-2"><RiskChip value={experiment.risk} /></td>
                        <td className="px-2.5 py-2">
                          {experiment.evidenceGenerated ? <Chip tone="good" glyph="✓">Generated</Chip> : <span className="text-[9.5px] text-white/30">—</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {comparison.length === 2 && (
              <div className="mt-3 rounded-lg border border-cyan-400/25 bg-cyan-500/[0.05] p-3">
                <div className="mb-2 text-[10px] font-black uppercase tracking-wider text-cyan-200">Experiment comparison</div>
                <div className="grid gap-2 sm:grid-cols-2">
                  {comparison.map((experiment) => (
                    <div key={experiment.id} className="rounded-lg border border-white/8 bg-black/25 p-2.5">
                      <div className="truncate text-[10.5px] font-black text-white/85">{experiment.target.label}</div>
                      <div className="mt-1 space-y-0.5 text-[9.5px] text-white/50">
                        <div>Key exchange: <span className="font-mono text-cyan-300/70">{experiment.proposedConfiguration.keyExchange}</span></div>
                        <div>Signature: <span className="font-mono text-cyan-300/70">{experiment.proposedConfiguration.signature}</span></div>
                        <div>Mode: {experiment.executionMode}</div>
                        <div>Findings: {experiment.findings.length}</div>
                      </div>
                      <div className="mt-1.5 flex gap-1.5"><OutcomeChip value={experiment.outcome} /><RiskChip value={experiment.risk} /></div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </SectionCard>

          <ProvenanceFooter evidence={data.evidence} generatedAt={data.generatedAt}
            extra={`${numberFmt(data.targets.length)} testable target(s)`} />
        </>
      )}

      <Drawer
        open={Boolean(detail)}
        title={detail?.target.label || ''}
        subtitle={detail ? `${detail.executionMode} · ${relativeTime(detail.createdAt)}` : ''}
        tone={detail?.outcome === 'failed' ? 'critical' : detail?.outcome === 'passed' ? 'good' : 'warning'}
        onClose={() => setDetail(null)}
        footer={detail && (
          <div className="flex flex-wrap gap-2">
            <DrawerLink href="/dashboard/trust-chain-analyzer" primary><Link2 className="h-3 w-3" /> Analyze Trust Chain</DrawerLink>
            <DrawerLink href="/dashboard/ecosystem-dependency-map"><Globe2 className="h-3 w-3" /> Analyze Dependency</DrawerLink>
            <DrawerLink href="/dashboard/migration-planner">Create Migration Plan</DrawerLink>
            <AskSophiaButton question={`Explain the result of the hybrid experiment on ${detail.target.label}.`} context="Hybrid Crypto Lab" />
          </div>
        )}
      >
        {detail && (
          <>
            <div className="flex flex-wrap gap-1.5">
              <OutcomeChip value={detail.outcome} />
              <RiskChip value={detail.risk} />
              <Chip tone={detail.executionMode === 'controlled-test' ? 'warning' : 'good'}>{detail.executionMode}</Chip>
            </div>
            <Block title="Configuration">
              <div className="grid grid-cols-2 gap-2">
                <Field label="Protocol" value={detail.proposedConfiguration.protocol} mono />
                <Field label="Key establishment" value={detail.proposedConfiguration.keyExchange} mono />
                <Field label="Signature" value={detail.proposedConfiguration.signature} mono />
                <Field label="Symmetric" value={detail.proposedConfiguration.symmetric} mono />
                <Field label="KDF" value={detail.proposedConfiguration.kdf} mono />
                <Field label="Hash" value={detail.proposedConfiguration.hash} mono />
              </div>
            </Block>
            {detail.checks.length > 0 && (
              <Block title="Checks">
                <div className="space-y-1">
                  {detail.checks.map((check) => (
                    <div key={check.key} className="flex items-center justify-between gap-2 rounded-lg border border-white/8 bg-black/25 px-2.5 py-1.5">
                      <span className="text-[10px] text-white/70">{check.label}</span>
                      <VerdictChip value={check.verdict} />
                    </div>
                  ))}
                </div>
              </Block>
            )}
            <Block title="Basis">
              <p className="rounded-lg border border-white/8 bg-black/25 p-2.5 text-[10px] leading-relaxed text-white/45">{detail.basis}</p>
            </Block>
          </>
        )}
      </Drawer>
    </div>
  )
}

function ConfigSelect({ label, value, options, onChange }: {
  label: string; value: string; options: string[]; onChange: (value: string) => void
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-[8px] font-black uppercase tracking-widest text-cyan-300/60">{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)} aria-label={label}
        className="h-8 w-full rounded-lg border border-white/10 bg-black/30 px-2 text-[10.5px] text-white/80 focus:border-cyan-400/50 focus:outline-none">
        {options.map((option) => <option key={option} value={option} className="bg-[#0b1120]">{option}</option>)}
      </select>
    </label>
  )
}
