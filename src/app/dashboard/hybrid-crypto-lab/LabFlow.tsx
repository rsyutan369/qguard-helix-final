'use client'

import { useCallback, useMemo } from 'react'
import { BadgeCheck, Download, Link2, Loader2, Play } from 'lucide-react'
import {
  DetailFacts, DetailLink, DetailSection, StatusPill, VendorTrustWorkflowCanvas,
  type DetailContext,
} from '@/components/trust-workflow/VendorTrustWorkflowCanvas'
import {
  ALGORITHM_ROLE, LAB_MODE_PROFILE, buildLabGraph, checkStatus, latestExperimentFor, modeOf,
  type LabMode,
} from '@/components/trust-workflow/graph-builders'
import { STATUS_META, type WorkflowNode, type WorkflowStatus } from '@/components/trust-workflow/graph-model'
import {
  EXPERIMENT_LABEL, RISK_LABEL,
  type ConfigValidationIssue, type ExecutionMode, type ExperimentConfiguration, type ExperimentOutcome,
  type ExperimentRecord, type ExperimentTarget,
} from '@/lib/ecosystem/external-trust-intelligence'
import { relativeTime, suiteHref } from '../_components/external-trust/_shared'

/**
 * Cryptographic workflow for the selected target and profile.
 *
 * Node colours come ONLY from a recorded experiment for this exact target and
 * key-establishment/signature profile. With no such experiment every step
 * reads "Not tested" — the picture never implies a handshake that did not run.
 */

const MODE_LABEL: Record<LabMode, string> = { classical: 'Classical', hybrid: 'Hybrid', 'post-quantum': 'Post-Quantum' }
const MODE_HINT: Record<LabMode, string> = {
  classical: 'X25519 key agreement · Ed25519 signatures — quantum-vulnerable baseline',
  hybrid: 'X25519 + ML-KEM-768 key establishment · Ed25519 + ML-DSA-65 signatures',
  'post-quantum': 'ML-KEM-768 key encapsulation · ML-DSA-65 signatures only',
}

const OUTCOME_STATUS: Record<ExperimentOutcome, WorkflowStatus> = {
  passed: 'verified', 'passed-with-warnings': 'attention', conditional: 'attention', failed: 'critical', 'not-evaluated': 'unknown',
}

const COMPONENT_FOR_CHECK: Record<string, string[]> = {
  protocol: ['Protocol'], crypto: ['Key exchange'], certificate: ['Certificate'], 'trust-chain': ['Certificate'],
  vendor: ['Vendor'], policy: [], application: [], session: [], telemetry: [], client: [],
}

export interface LabFlowProps {
  targets: ExperimentTarget[]
  target: ExperimentTarget | null
  onTargetChange: (id: string) => void
  config: ExperimentConfiguration
  onConfigChange: (config: ExperimentConfiguration) => void
  executionMode: ExecutionMode
  onExecutionModeChange: (mode: ExecutionMode) => void
  experiments: ExperimentRecord[]
  latestResult: ExperimentRecord | null
  observed: { algorithms: string[]; protocols: string[] } | null
  configIssues: ConfigValidationIssue[]
  running: boolean
  runError: string | null
  onRun: () => void
}

export function LabFlow({
  targets, target, onTargetChange, config, onConfigChange, executionMode, onExecutionModeChange,
  experiments, latestResult, observed, configIssues, running, runError, onRun,
}: LabFlowProps) {
  const mode = modeOf(config)
  // History plus an unstored (ephemeral) result from this session, newest first.
  const pool = useMemo(
    () => (latestResult && !experiments.some((experiment) => experiment.id === latestResult.id) ? [latestResult, ...experiments] : experiments),
    [experiments, latestResult],
  )
  const experiment = useMemo(() => (target ? latestExperimentFor(pool, target.id, config) : null), [pool, target, config])
  const graph = useMemo(
    () => buildLabGraph({ config, target, experiment, executionMode }),
    [config, target, experiment, executionMode],
  )

  const setMode = (next: LabMode) => onConfigChange({ ...config, ...LAB_MODE_PROFILE[next], protocol: 'TLS 1.3' })

  const exportReport = () => {
    if (!experiment) return
    const report = {
      exportedAt: new Date().toISOString(),
      disclaimer: 'Laboratory result — production validation is still required.',
      target: experiment.target,
      executionMode: experiment.executionMode,
      createdAt: experiment.createdAt,
      configuration: experiment.proposedConfiguration,
      outcome: experiment.outcome,
      risk: experiment.risk,
      durationMs: experiment.durationMs,
      checks: experiment.checks,
      findings: experiment.findings,
      probe: experiment.probe,
      basis: experiment.basis,
    }
    const anchor = document.createElement('a')
    anchor.href = `data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(report, null, 2))}`
    anchor.download = `qguard-lab-report-${experiment.target.host}-${experiment.createdAt.slice(0, 10)}.json`
    anchor.click()
  }

  const renderNodeDetail = useCallback((node: WorkflowNode, _context: DetailContext) => {
    const checkKey = node.entity?.id ?? ''
    const check = experiment?.checks.find((candidate) => candidate.key === checkKey)
    const verdict = checkStatus(check, Boolean(experiment))
    const probe = experiment?.probe ?? null
    const related = experiment?.findings.filter((finding) => (COMPONENT_FOR_CHECK[checkKey] ?? []).includes(finding.component)) ?? []
    const role = ALGORITHM_ROLE[node.label]
    return (
      <>
        {role && (
          <DetailSection title="Role in the handshake">
            <p className="qg-wf__text">{role}</p>
          </DetailSection>
        )}
        <DetailSection title="Test evidence">
          {experiment ? (
            <>
              <StatusPill status={verdict.status} label={verdict.label} />
              <p className="qg-wf__text" style={{ marginTop: 6 }}>{check?.detail ?? 'This step is not covered by a recorded check.'}</p>
              <p className="qg-wf__text-muted" style={{ marginTop: 4 }}>
                {experiment.executionMode === 'controlled-test' ? 'Controlled test' : 'Simulation'} · {relativeTime(experiment.createdAt)} · method {check?.method ?? 'n/a'}
              </p>
            </>
          ) : (
            <p className="qg-wf__text">Not tested. No experiment has been recorded for this target with the {mode === 'custom' ? 'current' : MODE_LABEL[mode].toLowerCase()} profile — run one to see a real verdict.</p>
          )}
        </DetailSection>
        {probe?.measured && checkKey === 'protocol' && (
          <DetailFacts items={[
            ['Negotiated', probe.negotiatedProtocol ?? 'Not recorded', true],
            ['Supported', probe.supportedProtocols.join(', ') || '—', true],
            ['Legacy offered', probe.legacyProtocols.join(', ') || 'None', true],
            ['Forward secrecy', probe.forwardSecrecy ? 'Yes' : 'No'],
          ]} />
        )}
        {probe?.measured && checkKey === 'crypto' && (
          <DetailFacts items={[
            ['PQ groups probed', probe.hybridProbed ? 'Yes' : 'No — TLS 1.3 unavailable'],
            ['Hybrid accepted', probe.hybridGroups.join(', ') || 'None', true],
            ['Pure KEM accepted', probe.pureKemGroups.join(', ') || 'None', true],
            ['Not offerable locally', probe.untestableGroups.join(', ') || 'None', true],
          ]} />
        )}
        {probe?.measured && checkKey === 'certificate' && (
          <DetailFacts items={[
            ['Served algorithm', probe.certificateAlgorithm ?? 'Not recorded', true],
            ['Issuer', probe.certificateIssuer ?? 'Not recorded'],
            ['Days to expiry', probe.certificateDaysToExpiry === null ? 'Unknown' : String(probe.certificateDaysToExpiry), true],
          ]} />
        )}
        {probe && !probe.measured && probe.error && (
          <p className="qg-wf__text-muted">Probe did not complete: {probe.error}</p>
        )}
        {related.length > 0 && (
          <DetailSection title="Findings">
            <div className="qg-wf__list">
              {related.map((finding) => (
                <div key={finding.id} className="qg-wf__row" style={{ alignItems: 'flex-start' }}>
                  <span className="qg-wf__row-main" style={{ whiteSpace: 'normal' }}>
                    <StatusPill status={finding.severity === 'critical' ? 'critical' : 'attention'} label={`${RISK_LABEL[finding.severity]} · ${finding.title}`} />
                    <span className="qg-wf__text" style={{ display: 'block', marginTop: 4, whiteSpace: 'normal' }}>{finding.likelyCause}</span>
                    <span className="qg-wf__text-muted" style={{ display: 'block', whiteSpace: 'normal' }}>→ {finding.recommendedAction}</span>
                  </span>
                </div>
              ))}
            </div>
          </DetailSection>
        )}
        {target && (checkKey === 'certificate' || checkKey === 'trust-chain') && (
          <div className="flex flex-wrap gap-1.5">
            <DetailLink primary href={suiteHref('trust', { asset: target.assetId, vendor: target.vendorId })}><Link2 /> Analyze trust chain</DetailLink>
          </div>
        )}
        {target?.vendorId && node.kind === 'vendor' && (
          <div className="flex flex-wrap gap-1.5">
            <DetailLink primary href={suiteHref('vendor', { vendor: target.vendorId })}><BadgeCheck /> Vendor readiness</DetailLink>
          </div>
        )}
      </>
    )
  }, [experiment, mode, target])

  const comparison = (['classical', 'hybrid', 'post-quantum'] as LabMode[]).map((candidate) => ({
    mode: candidate,
    experiment: target ? latestExperimentFor(pool, target.id, LAB_MODE_PROFILE[candidate]) : null,
  }))

  return (
    <div className="space-y-3">
      <VendorTrustWorkflowCanvas
        graph={graph}
        ariaLabel="Cryptographic handshake workflow"
        status="ready"
        height={600}
        exportName="qguard-hybrid-lab-flow"
        renderNodeDetail={renderNodeDetail}
        empty={{ title: 'No target selected', detail: 'Choose a discovered target to see its handshake workflow.' }}
        toolbarExtras={(
          <>
            <div className="qg-wf__toolbar-group" role="radiogroup" aria-label="Cryptographic mode">
              {(Object.keys(MODE_LABEL) as LabMode[]).map((value) => (
                <button key={value} type="button" role="radio" aria-checked={mode === value} aria-label={`${MODE_LABEL[value]} mode`}
                  className="qg-wf__btn" title={MODE_HINT[value]} onClick={() => setMode(value)}>
                  {MODE_LABEL[value]}
                </button>
              ))}
              {mode === 'custom' && <span className="qg-wf__btn" aria-pressed="true">Custom</span>}
            </div>
            <label>
              <span className="sr-only">Target</span>
              <select className="qg-wf__select" value={target?.id ?? ''} onChange={(event) => onTargetChange(event.target.value)} aria-label="Test target">
                {!target && <option value="">Select a target…</option>}
                {targets.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.label}</option>)}
              </select>
            </label>
            <label>
              <span className="sr-only">Execution mode</span>
              <select className="qg-wf__select" value={executionMode} onChange={(event) => onExecutionModeChange(event.target.value as ExecutionMode)} aria-label="Execution mode">
                <option value="simulation">Simulation (no connection)</option>
                <option value="controlled-test">Controlled test (read-only probe)</option>
              </select>
            </label>
            <button type="button" className="qg-wf__btn qg-wf__btn--primary" disabled={!target || running || configIssues.length > 0} onClick={onRun}>
              {running ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <Play className="h-3.5 w-3.5" aria-hidden="true" />}
              Run test
            </button>
            <button type="button" className="qg-wf__btn" disabled={!experiment} onClick={exportReport} title="Export the shown test as a JSON report">
              <Download className="h-3.5 w-3.5" aria-hidden="true" /> Report
            </button>
          </>
        )}
      />

      {runError && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-2.5 text-[10.5px] text-red-200">{runError}</div>}
      {configIssues.length > 0 && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-2.5 text-[10.5px] text-red-200">
          {configIssues.map((issue) => issue.message).join(' ')}
        </div>
      )}

      <div className="grid gap-2 lg:grid-cols-3">
        {comparison.map(({ mode: candidate, experiment: record }) => (
          <button key={candidate} type="button" onClick={() => setMode(candidate)}
            className="rounded-lg border border-white/8 bg-white/[0.02] p-3 text-left transition hover:border-cyan-400/30"
            aria-pressed={mode === candidate}
            aria-label={`${MODE_LABEL[candidate]} profile: ${record ? EXPERIMENT_LABEL[record.outcome] : 'not tested'} — show this profile`}>
            <div className="flex items-center justify-between gap-2">
              <span className="text-[10px] font-black uppercase tracking-wider text-white/70">{MODE_LABEL[candidate]}</span>
              <StatusPill status={record ? OUTCOME_STATUS[record.outcome] : 'unknown'} label={record ? EXPERIMENT_LABEL[record.outcome] : 'Not tested'} />
            </div>
            <div className="mt-1 text-[9.5px] text-white/40">{MODE_HINT[candidate]}</div>
            {record ? (
              <>
                <div className="mt-2 flex flex-wrap gap-1">
                  {record.checks.map((check) => {
                    const status = checkStatus(check, true).status
                    return (
                      <span key={check.key} title={check.detail}
                        className="inline-flex items-center gap-1 rounded border border-white/10 px-1.5 py-0.5 text-[8.5px] font-bold text-white/60">
                        <span aria-hidden="true" style={{ color: STATUS_META[status].color }}>{STATUS_META[status].glyph}</span>{check.label}
                      </span>
                    )
                  })}
                </div>
                <div className="mt-1.5 font-mono text-[9px] text-white/35">{record.executionMode} · {relativeTime(record.createdAt)} · {record.durationMs}ms</div>
              </>
            ) : (
              <div className="mt-2 text-[9.5px] text-white/35">No recorded experiment for this target with this profile.</div>
            )}
          </button>
        ))}
      </div>

      <div className="grid gap-2 md:grid-cols-2">
        <div className="rounded-lg border border-white/8 bg-white/[0.02] p-3">
          <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/40">Observed on this target today</div>
          <div className="mt-1.5 font-mono text-[10px] text-white/65">
            {observed && (observed.algorithms.length || observed.protocols.length)
              ? [...observed.protocols, ...observed.algorithms].slice(0, 10).join(' · ')
              : 'No stored cryptographic evidence for this target — a controlled test measures it directly.'}
          </div>
        </div>
        <div className="rounded-lg border border-white/8 bg-white/[0.02] p-3">
          <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/40">What this lab can test</div>
          <p className="mt-1.5 text-[10px] leading-relaxed text-white/50">
            Key establishment: X25519, ML-KEM-768, X25519 + ML-KEM-768. Signatures: Ed25519, ML-DSA-65, Ed25519 + ML-DSA-65. Symmetric: AES-256-GCM.
            Not offered by the test engine: ML-KEM-1024, SLH-DSA and RSA/ECDSA signature profiles — classical algorithms observed on a target are shown as evidence only.
          </p>
        </div>
      </div>
    </div>
  )
}
