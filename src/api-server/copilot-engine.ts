// Sophia — deep-reasoning, cross-module investigation engine.
//
// Consultant pipeline (per Qguard_Wiki/AI_Sophia_Upgrade): sanitize → intent
// detection → OBJECTIVE INFERENCE (what the user actually wants) → question
// expansion → full CROSS-MODULE investigation → evidence correlation into one
// TenantIntelligence view → dependency / relationship / risk reasoning →
// mode-specific deep synthesis (migration strategy w/ dependency-safe order,
// prioritization w/ WHY, executive assessment, certification gap analysis,
// risk explanation) → proactive findings → structured natural-language answer.
//
// Fully deterministic and evidence-grounded: every statement traces to a tool
// run over the authenticated tenant's live data. Sophia never answers from
// static pretrained "knowledge" about the tenant and never fabricates metrics;
// when evidence is missing she says so and names what to scan/configure.
// Standards citations come from the curated catalog in copilot-knowledge.ts.

import {
  detectIntents,
  planForIntents,
  inferObjective,
  expandQuestion,
  sanitizePrompt,
  modulePath,
  moduleLabel,
  STANDARDS,
} from './copilot-knowledge'
import {
  liveBuilders,
  runTool,
  type CopilotBuilders,
  type ToolContext,
  type ToolExecution,
  type ToolResult,
} from './copilot-tools'
import type {
  CopilotAgentId,
  CopilotAnswer,
  CopilotAnswerMode,
  CopilotEvidence,
  CopilotInsight,
  CopilotIntent,
  CopilotMemoryState,
  CopilotMigrationStrategy,
  CopilotNextAction,
  CopilotObjectiveKind,
  CopilotProactiveFinding,
  CopilotRecommendation,
  CopilotRelatedPage,
  CopilotRisk,
  CopilotRiskLevel,
  CopilotRiskOutlook,
  CopilotStreamEvent,
  CopilotToolRun,
} from '@/types/copilot'

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function str(v: unknown): string { return typeof v === 'string' ? v : v == null ? '' : String(v) }
function num(v: unknown): number { const n = Number(v); return Number.isFinite(n) ? n : 0 }
function rec(v: unknown): Record<string, unknown> { return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {} }
function arr(v: unknown): unknown[] { return Array.isArray(v) ? v : [] }
function clamp(n: number, lo = 0, hi = 100): number { return Math.max(lo, Math.min(hi, n)) }

const RISK_RANK: Record<CopilotRiskLevel, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

function maxRisk(a: CopilotRiskLevel, b: CopilotRiskLevel): CopilotRiskLevel {
  return RISK_RANK[a] >= RISK_RANK[b] ? a : b
}

let idCounter = 0
function nextId(): string {
  idCounter = (idCounter + 1) % 1_000_000
  return `sophia-${Date.now().toString(36)}-${idCounter.toString(36)}`
}

/* ------------------------------------------------------------------ */
/* Intent → tool plan                                                  */
/* ------------------------------------------------------------------ */

const INTENT_TOOLS: Record<CopilotIntent, string[]> = {
  asset_status: ['getAssets', 'searchAssets', 'getRiskAnalysis'],
  migration_status: ['getMigrationStatus', 'getMigrationJobs', 'getSnapshots'],
  remediation: ['getPendingRemediation', 'generateRecommendations'],
  risk_analysis: ['getRiskScore', 'getRiskAnalysis', 'getBlastRadius'],
  certification: ['getCertificationStatus', 'getCertificationEligibility', 'getPendingRemediation'],
  reports: ['getReports', 'generateExecutiveReport'],
  compliance: ['getComplianceStatus', 'getNISTScore', 'getCNSACompliance'],
  pki: ['getCertificates', 'getCertificateAuthorities', 'getCertificateChains'],
  tls: ['getCertificates', 'getCryptoInventory', 'getLiveTelemetry'],
  ssh: ['searchAssets', 'getCryptoInventory'],
  cbom: ['getCBOM', 'getAlgorithms', 'getLibraries'],
  scanner: ['getLatestScans', 'getFindings'],
  exposure_graph: ['getExposureGraph', 'getTrustChains', 'getDependencies', 'getBlastRadius'],
  telemetry: ['getLiveTelemetry', 'getCollectorsStatus', 'getAgentHealth', 'getHeartbeat', 'getConnectorStatus'],
  threat_intelligence: ['getHarvestNowExposure', 'getRiskScore', 'getFindings'],
  executive_dashboard: ['getQuantumReadiness', 'generateExecutiveReport', 'getMigrationStatus'],
  harvest_now: ['getHarvestNowExposure', 'getLiveTelemetry'],
  quantum_readiness: ['getQuantumReadiness', 'getCertificationEligibility', 'getReadinessHistory'],
  snapshots_rollback: ['getSnapshots', 'getMigrationJobs'],
  platform_help: [],
}

/** Explicit operational verbs → operate-class tools (RBAC still applies). */
const ACTION_TRIGGERS: Array<{ pattern: RegExp; tool: string }> = [
  { pattern: /approve .*(remediation|action|fix)/i, tool: 'approveRemediation' },
  { pattern: /reject .*(remediation|action|fix)/i, tool: 'rejectRemediation' },
  { pattern: /(create|take|capture) .*snapshot/i, tool: 'createSnapshot' },
  { pattern: /restore .*snapshot|snapshot .*restore/i, tool: 'restoreSnapshot' },
  { pattern: /roll ?back .*(migration|job)|revert .*migration/i, tool: 'rollbackMigration' },
  { pattern: /roll ?back .*(asset|server|host)/i, tool: 'rollbackAsset' },
  { pattern: /simulat(e|ion)/i, tool: 'simulateMigration' },
  { pattern: /generate .*(executive|board) .*(report|summary)|executive report/i, tool: 'generateExecutiveReport' },
];

/**
 * The full-platform investigation set. Every consultative question runs these
 * (read-only, all roles) so Sophia correlates across the whole platform rather
 * than answering from one module. This is cheap: most tools read the same
 * per-tenant single-flight-cached builders (snapshot / exposure / remediation /
 * workflow / certification / HNDL), so the fan-out collapses to a handful of
 * distinct computations within the 15s window plus a few direct table reads.
 */
const INVESTIGATION_TOOLS: string[] = [
  'getQuantumReadiness', 'getRiskScore', 'getRiskAnalysis',
  'getCBOM', 'getAlgorithms',
  'getExposureGraph', 'getBlastRadius', 'getDependencies', 'getTrustChains',
  'getHarvestNowExposure',
  'getMigrationStatus', 'getMigrationJobs', 'getSnapshots',
  'getCertificates', 'getPendingRemediation', 'getCertificationEligibility',
  'getComplianceStatus', 'getLiveTelemetry', 'getCollectorsStatus', 'getAssets',
]

export interface ExecutionPlan {
  intents: CopilotIntent[]
  agents: CopilotAgentId[]
  modules: string[]
  tools: string[]
  args: Record<string, unknown>
  followUp: boolean
  mode: CopilotAnswerMode
  objectiveKind: CopilotObjectiveKind
  objective: string
  expansion: string[]
}

const ALL_AGENTS: CopilotAgentId[] = [
  'asset_intelligence', 'risk_analyst', 'migration_advisor', 'pki_expert',
  'compliance_advisor', 'threat_intelligence', 'telemetry_agent', 'executive_advisor',
]

/** Pure planner — exported for offline verification. */
export function planQuery(question: string, memory: CopilotMemoryState): ExecutionPlan {
  const detection = detectIntents(question, memory.focusIntents)
  const objective = inferObjective(question, detection.intents)
  const { modules, agents } = planForIntents(detection.intents)

  const tools: string[] = []
  for (const intent of detection.intents) {
    for (const tool of INTENT_TOOLS[intent] || []) {
      if (!tools.includes(tool)) tools.push(tool)
    }
  }

  // Deep investigation: consultative objectives search the whole platform.
  let agentSet = new Set<CopilotAgentId>(agents)
  if (objective.investigate) {
    for (const tool of INVESTIGATION_TOOLS) if (!tools.includes(tool)) tools.push(tool)
    ALL_AGENTS.forEach((a) => agentSet.add(a))
  }

  // Explicit operational verbs still add their operate-class tool (RBAC applies).
  for (const trigger of ACTION_TRIGGERS) {
    if (trigger.pattern.test(question) && !tools.includes(trigger.tool)) tools.push(trigger.tool)
  }

  // Argument extraction — simple, transparent filters carried to the tools.
  const args: Record<string, unknown> = { query: question.slice(0, 160) }
  if (/internet[- ]facing|public[- ]facing|externally exposed/i.test(question)) args.internetFacing = true
  if (/\bcritical\b/i.test(question)) args.criticality = 'critical'
  if (detection.followUp && memory.focusEntity) args.asset = memory.focusEntity

  const modeModules = objective.investigate
    ? [...new Set([...modules, 'quantum_readiness', 'risk_analysis', 'exposure_graph', 'live_migration', 'pki', 'compliance'])]
    : modules

  return {
    intents: detection.intents,
    agents: [...agentSet],
    modules: modeModules,
    // Investigations may consult up to 22 tools; focused lookups stay at 9.
    tools: tools.slice(0, objective.investigate ? 22 : 9),
    args,
    followUp: detection.followUp,
    mode: objective.investigate ? 'investigate' : 'direct',
    objectiveKind: objective.kind,
    objective: objective.objective,
    expansion: expandQuestion(question, detection.intents),
  }
}

/* ------------------------------------------------------------------ */
/* Specialist agents — synthesis over tool results                     */
/* ------------------------------------------------------------------ */

interface AgentContribution {
  findings: string[]
  recommendations: CopilotRecommendation[]
  risk: CopilotRisk
}

interface SynthBundle {
  tool: (name: string) => ToolResult | null
  question: string
}

const NO_RISK: CopilotRisk = { level: 'info', drivers: [] }

function riskFromScore(score: number): CopilotRiskLevel {
  if (score >= 75) return 'critical'
  if (score >= 55) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

const AGENT_SYNTH: Record<CopilotAgentId, (b: SynthBundle) => AgentContribution> = {
  asset_intelligence(b) {
    const findings: string[] = []
    const recommendations: CopilotRecommendation[] = []
    let risk = NO_RISK
    const assets = b.tool('getAssets') || b.tool('searchAssets')
    const search = b.tool('searchAssets')
    const cbom = b.tool('getCBOM') || b.tool('getCryptoInventory')
    const scans = b.tool('getLatestScans')
    const findingsTool = b.tool('getFindings')

    if (search && num(search.data.matched) >= 0 && /which|search|find|show/i.test(b.question)) {
      findings.push(`${num(search.data.matched)} asset(s) match the requested filter.`)
    } else if (assets) {
      findings.push(`The inventory holds ${num(assets.data.total)} asset(s); ${num(assets.data.internetFacing)} are internet-facing.`)
    }
    if (cbom) {
      const vulnerable = num(cbom.data.vulnerableComponents ?? cbom.data.vulnerable)
      const total = num(cbom.data.cryptoComponents ?? cbom.data.total)
      if (total > 0) findings.push(`CBOM: ${total} cryptographic component(s), ${vulnerable} quantum-vulnerable.`)
      if (vulnerable > 0) {
        risk = { level: riskFromScore((vulnerable / Math.max(1, total)) * 100), drivers: [`${vulnerable} quantum-vulnerable crypto component(s)`], score: clamp(Math.round((vulnerable / Math.max(1, total)) * 100)) }
        recommendations.push({
          title: 'Replace quantum-vulnerable algorithms',
          detail: `Migrate the ${vulnerable} vulnerable component(s) to ML-KEM (key establishment) and ML-DSA (signatures); use hybrid X25519+ML-KEM where peers lag.`,
          priority: vulnerable > 10 ? 'immediate' : 'high',
          standards: [STANDARDS.FIPS_203, STANDARDS.FIPS_204, STANDARDS.SP_800_131A],
          deepLink: modulePath('remediation'),
        })
      }
    }
    if (scans && scans.status === 'empty') {
      recommendations.push({
        title: 'Run a discovery scan',
        detail: 'No scans found — run the PQC Scanner so the inventory, CBOM and readiness engines have real evidence to analyze.',
        priority: 'high',
        standards: [STANDARDS.NIST_CSF],
        deepLink: modulePath('scanner'),
      })
    }
    if (findingsTool) {
      const sev = rec(findingsTool.data.severityCounts)
      if (num(sev.critical) > 0) {
        findings.push(`Scanner reports ${num(sev.critical)} critical finding(s).`)
        risk = { level: 'critical', drivers: [...risk.drivers, `${num(sev.critical)} critical scanner finding(s)`], score: Math.max(num(risk.score), 80) }
      }
    }
    return { findings, recommendations, risk }
  },

  migration_advisor(b) {
    const findings: string[] = []
    const recommendations: CopilotRecommendation[] = []
    let risk = NO_RISK
    const wf = b.tool('getMigrationStatus')
    const jobs = b.tool('getMigrationJobs')
    const snaps = b.tool('getSnapshots')
    const pending = b.tool('getPendingRemediation')

    if (wf) {
      findings.push(`Migration workflow is ${num(wf.data.overallProgressPct)}% complete (stage: ${str(wf.data.currentStageId) || 'not started'}).`)
      const next = rec(wf.data.nextAction)
      if (str(next.label)) {
        recommendations.push({
          title: `Next migration step: ${str(next.label)}`,
          detail: str(next.detail) || 'Follow the workflow rail to keep the migration on its validated path.',
          priority: 'high',
          standards: [STANDARDS.SP_1800_38],
          deepLink: str(next.path) || modulePath('live_migration'),
        })
      }
    }
    if (jobs) {
      const failed = arr(jobs.data.failed).length
      const active = arr(jobs.data.active).length
      if (active) findings.push(`${active} migration job(s) are active right now.`)
      if (failed) {
        findings.push(`${failed} migration job(s) have failed and need attention.`)
        risk = { level: failed > 2 ? 'high' : 'medium', drivers: [`${failed} failed migration job(s)`] }
        recommendations.push({
          title: 'Review failed migrations',
          detail: 'Inspect failed jobs in Live Migration Ops; pre-migration snapshots enable safe rollback before retrying.',
          priority: 'immediate',
          standards: [STANDARDS.SP_1800_38],
          deepLink: modulePath('live_migration'),
        })
      }
    }
    if (snaps) {
      const restorable = num(rec(snaps.data.summary).restorable)
      findings.push(restorable > 0
        ? `${restorable} integrity-verified snapshot(s) are restorable for rollback.`
        : 'No restorable snapshots yet — pre-migration snapshots are created automatically when jobs start.')
    }
    if (pending && num(pending.data.pendingCount) > 0 && /migrate/i.test(b.question)) {
      findings.push(`${num(pending.data.pendingCount)} remediation action(s) feed the migration queue.`)
    }
    return { findings, recommendations, risk }
  },

  pki_expert(b) {
    const findings: string[] = []
    const recommendations: CopilotRecommendation[] = []
    let risk = NO_RISK
    const certs = b.tool('getCertificates')
    const cas = b.tool('getCertificateAuthorities')
    const chains = b.tool('getCertificateChains')

    if (certs) {
      const vulnerable = num(certs.data.quantumVulnerable)
      const expired = num(certs.data.expired)
      const expiring = num(certs.data.expiringSoon)
      const total = num(certs.data.total)
      findings.push(`PKI: ${total} certificate(s) — ${vulnerable} quantum-vulnerable, ${expired} expired, ${expiring} expiring soon.`)
      const drivers: string[] = []
      if (vulnerable > 0) drivers.push(`${vulnerable} quantum-vulnerable certificate(s)`)
      if (expired > 0) drivers.push(`${expired} expired certificate(s)`)
      if (drivers.length) {
        risk = { level: expired > 0 || vulnerable > 5 ? 'high' : 'medium', drivers }
        recommendations.push({
          title: 'Modernize the certificate estate',
          detail: 'Reissue RSA/ECDSA certificates with ML-DSA (or hybrid) chains, starting with expired and internet-facing endpoints; enforce automated rotation per key-management guidance.',
          priority: expired > 0 ? 'immediate' : 'high',
          standards: [STANDARDS.FIPS_204, STANDARDS.SP_800_57, STANDARDS.CNSA_2],
          deepLink: modulePath('pki'),
        })
      }
    }
    if (cas && arr(rec(cas.data).authorities).length) {
      findings.push(`${arr(rec(cas.data).authorities).length} certificate authorit(y/ies) anchor the estate.`)
    }
    if (chains && /chain|trust/i.test(b.question)) {
      findings.push(`Issuer chains resolved for ${arr(rec(chains.data).chains).length} authorit(y/ies).`)
    }
    return { findings, recommendations, risk }
  },

  risk_analyst(b) {
    const findings: string[] = []
    const recommendations: CopilotRecommendation[] = []
    let risk = NO_RISK
    const score = b.tool('getRiskScore')
    const analysis = b.tool('getRiskAnalysis')
    const blast = b.tool('getBlastRadius')
    const exposure = b.tool('getExposureGraph')
    const hndl = b.tool('getHarvestNowExposure')

    if (score) {
      const quantumRisk = num(score.data.quantumRisk)
      findings.push(`Quantum risk is ${quantumRisk}/100 (${str(rec(score.data.levels).risk) || riskFromScore(quantumRisk)}); HNDL risk ${num(score.data.hndlRisk)}/100.`)
      risk = { level: riskFromScore(quantumRisk), score: quantumRisk, drivers: [] }
    }
    if (analysis) {
      const dist = rec(analysis.data.distribution)
      if (num(dist.critical) + num(dist.high) > 0) {
        risk = { ...risk, level: maxRisk(risk.level, num(dist.critical) > 0 ? 'critical' : 'high'), drivers: [...risk.drivers, `${num(dist.critical)} critical / ${num(dist.high)} high risk asset(s)`] }
        findings.push(`Risk distribution: ${num(dist.critical)} critical, ${num(dist.high)} high, ${num(dist.medium)} medium, ${num(dist.low)} low.`)
      }
      const top = arr(analysis.data.topRiskAssets) as Array<Record<string, unknown>>
      if (top.length) findings.push(`Highest-risk asset: ${str(top[0].name) || str(top[0].id)}.`)
    }
    if (blast && blast.status === 'ok') {
      const blastData = rec(blast.data.blast)
      findings.push(`Blast radius of ${str(blast.data.asset)}: ${num(blastData.totalAffected)} dependent asset(s) (${num(blastData.internetFacing)} internet-facing).`)
      if (num(blastData.totalAffected) > 5) {
        recommendations.push({
          title: `Prioritize ${str(blast.data.asset)} in the migration order`,
          detail: 'Its failure or compromise propagates across a wide dependency set — migrating it early collapses downstream risk.',
          priority: 'high',
          standards: [STANDARDS.NIST_CSF, STANDARDS.CIS_V8],
          deepLink: modulePath('exposure_graph'),
        })
      }
    }
    if (exposure) {
      const s = rec(exposure.data.summary)
      if (num(s.quantumVulnerable) > 0) {
        findings.push(`Exposure graph: ${num(s.quantumVulnerable)} quantum-vulnerable asset(s), ${num(exposure.data.blockers)} migration blocker(s), ${num(exposure.data.thirdParty)} third-party dependenc(y/ies).`)
      }
    }
    if (hndl) {
      const banner = rec(hndl.data.banner)
      if (str(banner.level || banner.severity)) {
        risk = { ...risk, level: maxRisk(risk.level, /critical|severe/i.test(str(banner.level || banner.severity)) ? 'critical' : 'high'), drivers: [...risk.drivers, 'Harvest-Now-Decrypt-Later exposure on long-lived data'] }
      }
      recommendations.push({
        title: 'Close the Harvest-Now window',
        detail: 'Traffic recorded today is decryptable once a CRQC exists. Prioritize forward secrecy plus hybrid X25519+ML-KEM on internet-facing TLS.',
        priority: 'immediate',
        standards: [STANDARDS.FIPS_203, STANDARDS.IETF_HYBRID, STANDARDS.CNSA_2],
        deepLink: modulePath('harvest_now'),
      })
    }
    return { findings, recommendations, risk }
  },

  compliance_advisor(b) {
    const findings: string[] = []
    const recommendations: CopilotRecommendation[] = []
    let risk = NO_RISK
    const status = b.tool('getComplianceStatus')
    const nist = b.tool('getNISTScore')
    const cnsa = b.tool('getCNSACompliance')
    const cert = b.tool('getCertificationStatus')
    const eligibility = b.tool('getCertificationEligibility')

    if (status) {
      const frameworks = arr(status.data.frameworks) as Array<Record<string, unknown>>
      const aligned = frameworks.filter((f) => str(f.status) === 'aligned').length
      findings.push(`Framework posture: ${aligned}/${frameworks.length} aligned (${frameworks.map((f) => `${str(f.framework).split(' (')[0]}: ${str(f.status)}`).slice(0, 3).join('; ')}).`)
    }
    if (nist) {
      findings.push(`NIST PQC alignment — FIPS 203 ×${num(nist.data.fips203Components)}, FIPS 204 ×${num(nist.data.fips204Components)}, FIPS 205 ×${num(nist.data.fips205Components)} adopted component(s).`)
    }
    if (cnsa) {
      const met = num(cnsa.data.met)
      const total = num(cnsa.data.total)
      findings.push(`CNSA 2.0 transition: ${met}/${total} requirement check(s) met.`)
      if (met < total && cnsa.status !== 'empty') {
        risk = { level: 'medium', drivers: [`${total - met} CNSA 2.0 gap(s)`] }
        recommendations.push({
          title: 'Advance the CNSA 2.0 transition',
          detail: 'Adopt ML-KEM-1024 / ML-DSA-87 with AES-256 and SHA-384+ to satisfy the remaining CNSA 2.0 requirements.',
          priority: 'high',
          standards: [STANDARDS.CNSA_2, STANDARDS.FIPS_203, STANDARDS.FIPS_204],
          deepLink: modulePath('compliance'),
        })
      }
    }
    if (cert) {
      findings.push(cert.data.certified === true
        ? `Quantum Trust Certification is active (${str(rec(cert.data.certificate as Record<string, unknown>).levelLabel) || 'certified'}).`
        : 'Quantum Trust Certification has not been achieved yet.')
    }
    if (eligibility && eligibility.data.eligible !== true) {
      const unmet = arr(eligibility.data.unmet) as Array<Record<string, unknown>>
      if (unmet.length) {
        findings.push(`Certification blockers: ${unmet.slice(0, 3).map((c) => str(c.label || c.id)).join('; ')}${unmet.length > 3 ? '…' : ''}.`)
        recommendations.push({
          title: 'Clear the certification blockers',
          detail: `Certification readiness is ${num(eligibility.data.certificationReadinessPct)}% — work the Remediation Engine ladder; each completed action raises the readiness score toward eligibility.`,
          priority: 'high',
          standards: [STANDARDS.NIST_CSF, STANDARDS.ISO_27001],
          deepLink: modulePath('remediation'),
        })
        risk = { level: maxRisk(risk.level, 'medium'), drivers: [...risk.drivers, `${unmet.length} unmet certification criteria`] }
      }
    }
    return { findings, recommendations, risk }
  },

  executive_advisor(b) {
    const findings: string[] = []
    const recommendations: CopilotRecommendation[] = []
    const readiness = b.tool('getQuantumReadiness')
    const report = b.tool('generateExecutiveReport')
    const wf = b.tool('getMigrationStatus')

    // Never report a fabricated posture when there is no assessment data — the
    // readiness tool returns 'empty' until a scan has run.
    if (readiness && readiness.status === 'ok') {
      const scores = rec(readiness.data.scores)
      const inventory = rec(readiness.data.inventory)
      findings.push(`Executive posture: quantum readiness ${num(scores.quantumReadiness)}/100, PQC adoption ${num(scores.pqcAdoption)}%, ${num(inventory.assetsAssessed)} asset(s) under management.`)
    } else if (readiness && readiness.status === 'empty') {
      recommendations.push({
        title: 'Run a discovery scan to establish a baseline',
        detail: 'No assessment data exists yet, so I can’t report readiness metrics. Run the PQC Scanner (or connect a cloud connector / collector) and I’ll build the executive posture from real evidence.',
        priority: 'high',
        standards: [STANDARDS.NIST_CSF],
        deepLink: modulePath('scanner'),
      })
    }
    if (report && report.status === 'ok') {
      const estimates = rec(report.data.estimates)
      findings.push(`Executive report composed — migration estimate ${num(estimates.migrationTimelineWeeks)} week(s)${num(estimates.migrationCostUsd) ? `, ~$${Math.round(num(estimates.migrationCostUsd)).toLocaleString()}` : ''}.`)
      recommendations.push({
        title: 'Export the executive report',
        detail: 'The full board-ready report (PDF/DOCX with certification summary and readiness ladder) is available in the Report Center.',
        priority: 'medium',
        standards: [STANDARDS.NIST_CSF],
        deepLink: modulePath('reports'),
      })
    }
    if (wf) findings.push(`Migration program progress: ${num(wf.data.overallProgressPct)}%.`)
    return { findings, recommendations, risk: NO_RISK }
  },

  telemetry_agent(b) {
    const findings: string[] = []
    const recommendations: CopilotRecommendation[] = []
    let risk = NO_RISK
    const live = b.tool('getLiveTelemetry')
    const fleet = b.tool('getCollectorsStatus')
    const health = b.tool('getAgentHealth')
    const heartbeat = b.tool('getHeartbeat')
    const connectors = b.tool('getConnectorStatus')

    if (live) {
      findings.push(`Runtime telemetry: ${num(live.data.recentEvents)} recent event(s) — ${num(live.data.legacyEvents)} legacy crypto, ${num(live.data.pqcEvents)} PQC, ${num(live.data.hndlFlagged)} HNDL-flagged.`)
      if (num(live.data.legacyEvents) > 0) {
        risk = { level: 'medium', drivers: [`${num(live.data.legacyEvents)} legacy-crypto runtime event(s)`] }
      }
    }
    if (fleet) {
      const online = num(fleet.data.online)
      const total = num(fleet.data.fleet)
      findings.push(total > 0 ? `Collector fleet: ${online}/${total} agent(s) online.` : 'No collector agents enrolled yet.')
      if (total > 0 && online < total) {
        recommendations.push({
          title: 'Recover offline collectors',
          detail: `${total - online} agent(s) have missed their heartbeat window — offline collectors create blind spots in discovery and runtime telemetry.`,
          priority: 'high',
          standards: [STANDARDS.CIS_V8],
          deepLink: modulePath('collectors'),
        })
        risk = { level: maxRisk(risk.level, 'medium'), drivers: [...risk.drivers, `${total - online} offline collector agent(s)`] }
      }
      if (total === 0) {
        recommendations.push({
          title: 'Deploy collector agents',
          detail: 'Enroll collectors on key hosts to stream real heartbeats, discovery evidence and runtime crypto telemetry.',
          priority: 'medium',
          standards: [STANDARDS.NIST_CSF],
          deepLink: modulePath('collectors'),
        })
      }
    }
    if (health && !fleet) findings.push(`Agent status: ${JSON.stringify(rec(health.data.byStatus))}.`)
    if (heartbeat && str(rec(heartbeat.data).latestHeartbeat)) findings.push(`Latest heartbeat: ${str(rec(heartbeat.data).latestHeartbeat)}.`)
    if (connectors && num(rec(connectors.data).unhealthy) > 0) {
      findings.push(`${num(rec(connectors.data).unhealthy)} cloud connector(s) report an unhealthy status.`)
    }
    return { findings, recommendations, risk }
  },

  threat_intelligence(b) {
    const findings: string[] = []
    const recommendations: CopilotRecommendation[] = []
    let risk = NO_RISK
    const hndl = b.tool('getHarvestNowExposure')
    const score = b.tool('getRiskScore')

    if (hndl) {
      const future = rec(hndl.data.futureDecryptable)
      const fs = rec(hndl.data.forwardSecrecy)
      const banner = rec(hndl.data.banner)
      if (str(banner.headline || banner.message)) findings.push(str(banner.headline || banner.message))
      if (Object.keys(future).length) findings.push('Data recorded today without quantum-safe key establishment remains decryptable once a cryptanalytically relevant quantum computer exists.')
      if (Object.keys(fs).length) findings.push('Forward-secrecy coverage determines how much captured traffic stays protected — see the HNDL forward-secrecy panel for per-endpoint state.')
      risk = { level: 'high', drivers: ['HNDL: long-lived sensitive data under legacy key establishment'] }
    }
    if (score && num(score.data.hndlRisk) >= 55) {
      risk = { level: maxRisk(risk.level, 'high'), score: num(score.data.hndlRisk), drivers: [...risk.drivers, `HNDL risk score ${num(score.data.hndlRisk)}/100`] }
    }
    // Standards-based background (clearly non-tenant): the accepted migration driver.
    findings.push('Context (industry guidance, not tenant telemetry): NIST finalized FIPS 203/204/205 in 2024 and CNSA 2.0 targets full national-security-system PQC transition by 2033 — regulated enterprises are expected to migrate well before a CRQC arrives.')
    recommendations.push({
      title: 'Track the PQC standards clock',
      detail: 'Align the migration roadmap to CNSA 2.0 milestones and NIST SP 800-131A algorithm sunsets rather than CRQC speculation.',
      priority: 'medium',
      standards: [STANDARDS.CNSA_2, STANDARDS.SP_800_131A, STANDARDS.ETSI_QSC],
      deepLink: modulePath('harvest_now'),
    })
    return { findings, recommendations, risk }
  },

  coordinator(b) {
    const findings: string[] = []
    if (/what can you|help|sophia|copilot/i.test(b.question)) {
      findings.push('I am Sophia, the QGuard Helix AI Security Copilot. Ask me about assets, scans, CBOM, the exposure graph, quantum readiness, HNDL, migrations, snapshots and rollback, remediation, certificates and PKI, telemetry and collectors, compliance, certification, or executive reporting — every answer is built from your tenant’s live data with evidence and deep links.')
    }
    return { findings, recommendations: [], risk: NO_RISK }
  },
}

/* ================================================================== */
/* DEEP REASONING — cross-module correlation + consultant synthesis    */
/* ================================================================== */

/** One correlated view of the tenant, assembled from every investigation tool. */
interface TenantIntelligence {
  hasData: boolean
  readiness: number | null
  readinessLevel: string
  pqcAdoption: number | null
  quantumRisk: number | null
  hndlRisk: number | null
  riskLevel: CopilotRiskLevel
  riskDist: { critical: number; high: number; medium: number; low: number }
  assetsTotal: number | null
  internetFacing: number | null
  cryptoComponents: number | null
  vulnerableComponents: number | null
  pqcReadyComponents: number | null
  topRiskAssets: string[]
  blast: { asset: string; totalAffected: number; internetFacing: number; direct: number; trustChain: number } | null
  exposure: { quantumVulnerable: number; trustRelationships: number; criticalTrust: number; thirdParty: number; blockers: number; certificateChains: number; internetFacing: number } | null
  hndl: { level: string; headline: string } | null
  migration: { progressPct: number; stage: string; certReadinessPct: number; nextLabel: string; nextPath: string; nextDetail: string } | null
  jobs: { total: number; active: number; failed: number } | null
  snapshots: { total: number; restorable: number; autoRollbacks: number; schemaReady: boolean } | null
  certs: { total: number; quantumVulnerable: number; expired: number; expiringSoon: number; issuers: number } | null
  remediation: { pending: number; criticalBlockers: number; quickWins: number; readinessPct: number } | null
  certification: { eligible: boolean; unmet: string[]; readinessPct: number } | null
  telemetry: { legacy: number; pqc: number; hndlFlagged: number } | null
  collectors: { fleet: number; online: number } | null
  compliance: { aligned: number; total: number; frameworks: Array<{ framework: string; status: string }> } | null
  dependencies: { thirdParty: number } | null
}

function numOrNull(v: unknown): number | null {
  const n = Number(v)
  return Number.isFinite(n) ? n : null
}

/** Correlate every tool result into one intelligence view (no fabrication). */
function extractIntelligence(toolData: Map<string, ToolResult>): TenantIntelligence {
  const pick = (name: string) => toolData.get(name) || null
  const d = (r: ToolResult | null) => (r ? rec(r.data) : {})
  const okData = (name: string) => {
    const r = pick(name)
    return r && r.status === 'ok' ? rec(r.data) : null
  }

  const readinessData = okData('getQuantumReadiness')
  const scores = rec(readinessData?.scores)
  const inventory = rec(readinessData?.inventory)
  const riskScore = okData('getRiskScore')
  const riskAnalysis = okData('getRiskAnalysis')
  const cbom = okData('getCBOM') || okData('getCryptoInventory')
  const exposureData = okData('getExposureGraph')
  const blastData = okData('getBlastRadius')
  const depsData = okData('getDependencies')
  const trustData = okData('getTrustChains')
  const hndlData = okData('getHarvestNowExposure')
  const migData = okData('getMigrationStatus')
  const jobsData = okData('getMigrationJobs')
  const snapData = okData('getSnapshots')
  const certData = okData('getCertificates')
  const remData = okData('getPendingRemediation')
  const certifData = okData('getCertificationEligibility')
  const complianceData = okData('getComplianceStatus')
  const teleData = okData('getLiveTelemetry')
  const collectorsData = okData('getCollectorsStatus')
  const assetsData = okData('getAssets')

  const quantumRisk = riskScore ? numOrNull(riskScore.quantumRisk) : numOrNull(scores.quantumRisk)
  const hndlRisk = riskScore ? numOrNull(riskScore.hndlRisk) : numOrNull(scores.hndlRisk)
  const riskDist = { critical: num(rec(riskAnalysis?.distribution).critical), high: num(rec(riskAnalysis?.distribution).high), medium: num(rec(riskAnalysis?.distribution).medium), low: num(rec(riskAnalysis?.distribution).low) }

  let riskLevel: CopilotRiskLevel = 'info'
  if (quantumRisk != null) riskLevel = riskFromScore(quantumRisk)
  else if (riskDist.critical > 0) riskLevel = 'critical'
  else if (riskDist.high > 0) riskLevel = 'high'
  else if (riskDist.medium > 0) riskLevel = 'medium'

  const exposureSummary = rec(exposureData?.summary)
  const blast = blastData ? rec(blastData.blast) : null
  const banner = rec(hndlData?.banner)
  const nextAction = rec(migData?.nextAction)

  const hasData = Boolean(
    readinessData?.hasData ||
    (assetsData && num(assetsData.total) > 0) ||
    (cbom && num(cbom.cryptoComponents ?? cbom.total) > 0) ||
    (certData && num(certData.total) > 0),
  )

  return {
    hasData,
    readiness: numOrNull(scores.quantumReadiness),
    readinessLevel: str(scores.quantumReadinessLevel) || 'unknown',
    pqcAdoption: numOrNull(scores.pqcAdoption),
    quantumRisk,
    hndlRisk,
    riskLevel,
    riskDist,
    assetsTotal: assetsData ? numOrNull(assetsData.total) : numOrNull(inventory.assetsAssessed),
    internetFacing: assetsData ? numOrNull(assetsData.internetFacing) : (exposureData ? numOrNull(exposureSummary.internetFacingAssets) : null),
    cryptoComponents: cbom ? numOrNull(cbom.cryptoComponents ?? cbom.total) : numOrNull(inventory.cryptoComponents),
    vulnerableComponents: cbom ? numOrNull(cbom.vulnerableComponents ?? cbom.vulnerable) : numOrNull(inventory.vulnerableComponents),
    pqcReadyComponents: cbom ? numOrNull(cbom.pqcReadyComponents) : numOrNull(inventory.pqcReadyComponents),
    topRiskAssets: (arr(riskAnalysis?.topRiskAssets) as Array<Record<string, unknown>>).map((a) => str(a.name) || str(a.id)).filter(Boolean).slice(0, 6),
    blast: blast && Object.keys(blast).length ? {
      asset: str(blastData?.asset), totalAffected: num(blast.totalAffected), internetFacing: num(blast.internetFacing),
      direct: arr(blast.direct).length, trustChain: arr(blast.trustChain).length,
    } : null,
    exposure: exposureData ? {
      quantumVulnerable: num(exposureSummary.quantumVulnerable), trustRelationships: num(exposureSummary.trustRelationships),
      criticalTrust: num(exposureSummary.criticalTrustRelationships), thirdParty: num(exposureData.thirdParty ?? exposureSummary.thirdPartyDependencies),
      blockers: num(exposureData.blockers), certificateChains: num(exposureSummary.certificateChains), internetFacing: num(exposureSummary.internetFacingAssets),
    } : null,
    hndl: hndlData ? { level: str(banner.level || banner.severity) || 'assessed', headline: str(banner.headline || banner.message) } : null,
    migration: migData ? {
      progressPct: num(migData.overallProgressPct), stage: str(migData.currentStageId) || 'not started',
      certReadinessPct: num(migData.certificationReadinessPct), nextLabel: str(nextAction.label), nextPath: str(nextAction.path), nextDetail: str(nextAction.detail),
    } : null,
    jobs: jobsData ? { total: num(jobsData.total), active: arr(jobsData.active).length, failed: arr(jobsData.failed).length } : null,
    snapshots: snapData ? {
      total: num(rec(snapData.summary).total), restorable: num(rec(snapData.summary).restorable),
      autoRollbacks: num(rec(snapData.summary).automaticRollbacks), schemaReady: snapData.schemaReady === true,
    } : null,
    certs: certData ? {
      total: num(certData.total), quantumVulnerable: num(certData.quantumVulnerable),
      expired: num(certData.expired), expiringSoon: num(certData.expiringSoon), issuers: arr(rec(trustData).chains).length,
    } : null,
    remediation: remData ? {
      pending: num(remData.pendingCount), criticalBlockers: num(remData.criticalBlockers),
      quickWins: num(remData.quickWins), readinessPct: num(remData.certificationReadinessPct),
    } : null,
    certification: certifData ? {
      eligible: certifData.eligible === true,
      unmet: (arr(certifData.unmet) as Array<Record<string, unknown>>).map((c) => str(c.label || c.id)).filter(Boolean).slice(0, 8),
      readinessPct: num(certifData.certificationReadinessPct),
    } : null,
    telemetry: teleData ? { legacy: num(teleData.legacyEvents), pqc: num(teleData.pqcEvents), hndlFlagged: num(teleData.hndlFlagged) } : null,
    collectors: collectorsData ? { fleet: num(collectorsData.fleet), online: num(collectorsData.online) } : null,
    compliance: complianceData ? {
      frameworks: (arr(complianceData.frameworks) as Array<Record<string, unknown>>).map((f) => ({ framework: str(f.framework), status: str(f.status) })),
      aligned: (arr(complianceData.frameworks) as Array<Record<string, unknown>>).filter((f) => str(f.status) === 'aligned').length,
      total: arr(complianceData.frameworks).length,
    } : null,
    dependencies: depsData ? { thirdParty: num(depsData.thirdPartyCount ?? depsData.thirdParty) } : null,
  }
}

/* ---- Proactive intelligence — things noticed while investigating ---- */

function detectProactiveFindings(intel: TenantIntelligence): CopilotProactiveFinding[] {
  const out: CopilotProactiveFinding[] = []
  if (intel.certs) {
    if (intel.certs.expired > 0) out.push({ severity: 'high', text: `${intel.certs.expired} certificate(s) have already expired — expired certificates break trust chains and can derail a migration mid-flight.`, module: 'PKI Visibility', deepLink: modulePath('pki') })
    else if (intel.certs.expiringSoon > 0) out.push({ severity: 'medium', text: `${intel.certs.expiringSoon} certificate(s) expire soon — rotate them to ML-DSA or hybrid chains on renewal so you migrate once, not twice.`, module: 'PKI Visibility', deepLink: modulePath('pki') })
  }
  if (intel.collectors && intel.collectors.fleet > 0 && intel.collectors.online < intel.collectors.fleet) {
    out.push({ severity: 'medium', text: `${intel.collectors.fleet - intel.collectors.online} collector agent(s) are offline — assets they cover may be missing from this analysis, creating migration blind spots.`, module: 'Agent Collectors', deepLink: modulePath('collectors') })
  }
  if (intel.jobs && intel.jobs.failed > 0) {
    out.push({ severity: 'high', text: `${intel.jobs.failed} migration job(s) have failed — resolve or roll these back before starting new work to avoid mixed-crypto state.`, module: 'Live Migration Ops', deepLink: modulePath('live_migration') })
  }
  if (intel.migration && intel.migration.progressPct > 0 && intel.migration.progressPct < 100 && intel.snapshots && intel.snapshots.restorable === 0) {
    out.push({ severity: 'high', text: 'A migration is in progress but there are no restorable snapshots — capture one before the next stage so any failure is fully reversible.', module: 'Live Migration Ops', deepLink: modulePath('live_migration') })
  }
  if (intel.remediation && intel.remediation.criticalBlockers > 0) {
    out.push({ severity: 'high', text: `${intel.remediation.criticalBlockers} critical remediation blocker(s) are gating your certification/migration readiness.`, module: 'Quantum Remediation Engine™', deepLink: modulePath('remediation') })
  }
  const order: CopilotRiskLevel[] = ['critical', 'high', 'medium', 'low', 'info']
  return out.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity)).slice(0, 5)
}

/* ---- Dependency-safe migration strategy (canonical PQC order) ------- */

function buildMigrationStrategy(intel: TenantIntelligence): CopilotMigrationStrategy {
  const ifCount = intel.internetFacing ?? 0
  const certCount = intel.certs?.total ?? 0
  const steps = [
    {
      order: 1, title: 'PKI hierarchy & root trust anchors',
      rationale: `Upgrade root/intermediate trust first so every dependent system keeps trusting re-issued certificates. ${certCount ? `You have ${certCount} certificate(s) anchored to these roots.` : ''}`.trim(),
      breaksIf: 'If leaf/endpoint certificates are migrated before the roots and chains, clients fail path validation → authentication outages.',
      deepLink: modulePath('pki'),
    },
    {
      order: 2, title: 'Certificate chains & issuing CAs',
      rationale: 'Intermediate chains must present ML-DSA (or hybrid) before endpoints rely on them, so the chain validates end-to-end.',
      breaksIf: 'Endpoints trusting old intermediates will reject upgraded leaf certificates.',
      deepLink: modulePath('pki'),
    },
    {
      order: 3, title: 'Key management (QKMS)',
      rationale: 'Rotate signing/KEM keys to ML-KEM / ML-DSA so newly issued certificates and sessions are quantum-safe at the source.',
      breaksIf: 'New certificates signed with legacy keys inherit quantum vulnerability — you would migrate twice.',
      deepLink: modulePath('sophia'),
    },
    {
      order: 4, title: 'Internet-facing TLS endpoints',
      rationale: `Your highest Harvest-Now-Decrypt-Later exposure. ${ifCount ? `${ifCount} internet-facing asset(s) are recording traffic that becomes decryptable once a CRQC exists.` : ''} Enable hybrid X25519+ML-KEM for compatibility.`.trim(),
      breaksIf: 'Deploying pure PQC (not hybrid) breaks handshakes with peers that lack PQC support — use hybrid to stay interoperable.',
      deepLink: modulePath('live_migration'),
    },
    {
      order: 5, title: 'Internal APIs & service mesh',
      rationale: 'East-west traffic behind the edge — migrate after the perimeter is quantum-safe.',
      deepLink: modulePath('live_migration'),
    },
    {
      order: 6, title: 'SSH infrastructure',
      rationale: 'Move host and user keys to PQC/hybrid; rotate authorized keys as part of the change.',
      deepLink: modulePath('assets'),
    },
    {
      order: 7, title: 'VPN gateways',
      rationale: 'Upgrade tunnel key exchange to ML-KEM once endpoints negotiate hybrid.',
      deepLink: modulePath('live_migration'),
    },
    {
      order: 8, title: 'Clients & endpoints',
      rationale: 'Last — once servers negotiate hybrid, roll client support so both sides prefer quantum-safe suites.',
      deepLink: modulePath('live_migration'),
    },
  ]
  const estimatedEffortPct = intel.migration ? Math.max(0, 100 - intel.migration.progressPct) : undefined
  const timeline = intel.exposure || intel.vulnerableComponents
    ? `${(intel.vulnerableComponents ?? 0) > 40 ? '12–20' : (intel.vulnerableComponents ?? 0) > 10 ? '8–14' : '4–8'} weeks at ${Math.max(2, Math.min(6, Math.ceil(((intel.vulnerableComponents ?? 8) / 12))))} parallel workstreams (evidence-based estimate)`
    : undefined
  return { steps, estimatedEffortPct, estimatedTimeline: timeline }
}

/* ---- Result of a deep synthesis pass -------------------------------- */

interface DeepSynthesis {
  summary: string
  objective: string
  keyFindings: string[]
  reasoning: string[]
  rootCause?: string
  businessImpact?: string
  technicalAnalysis?: string[]
  migrationStrategy?: CopilotMigrationStrategy
  dependencies?: string[]
  potentialBreakages?: string[]
  rollbackStrategy?: string
  riskOutlook?: CopilotRiskOutlook
  complianceAlignment?: string[]
  recommendations: CopilotRecommendation[]
  nextActions: CopilotNextAction[]
  risk: CopilotRisk
}

function riskLabel(level: CopilotRiskLevel): string {
  return level.charAt(0).toUpperCase() + level.slice(1)
}

function dependencyHighlights(intel: TenantIntelligence): string[] {
  const out: string[] = []
  if (intel.exposure) {
    if (intel.exposure.trustRelationships > 0) out.push(`${intel.exposure.trustRelationships} trust relationship(s) mapped${intel.exposure.criticalTrust > 0 ? `, ${intel.exposure.criticalTrust} critical` : ''}.`)
    if (intel.exposure.certificateChains > 0) out.push(`${intel.exposure.certificateChains} certificate chain(s) anchor authentication.`)
    if (intel.exposure.thirdParty > 0) out.push(`${intel.exposure.thirdParty} third-party dependenc(y/ies) sit in your trust paths — coordinate their PQC readiness.`)
    if (intel.exposure.blockers > 0) out.push(`${intel.exposure.blockers} migration blocker(s) identified in the exposure graph.`)
  }
  if (intel.blast && intel.blast.totalAffected > 0) out.push(`${intel.blast.asset} has the largest blast radius: ${intel.blast.totalAffected} dependent asset(s)${intel.blast.internetFacing ? `, ${intel.blast.internetFacing} internet-facing` : ''}.`)
  if (intel.dependencies && intel.dependencies.thirdParty > 0 && !out.some((s) => s.includes('third-party'))) out.push(`${intel.dependencies.thirdParty} third-party dependenc(y/ies) in scope.`)
  return out.slice(0, 6)
}

function rollbackGuidance(intel: TenantIntelligence): string {
  if (!intel.snapshots) return 'Create an integrity-verified snapshot of each asset’s crypto-state before changing it; QGuard’s auto-rollback restores the last valid snapshot if validation fails.'
  if (!intel.snapshots.schemaReady) return 'Snapshot storage is not fully configured yet — apply the snapshot schema so pre-migration backups and auto-rollback are available before you start.'
  if (intel.snapshots.restorable === 0) return 'You have no restorable snapshots. Capture a pre-migration snapshot before the next stage so any failure is fully reversible; auto-rollback will restore it on validation failure.'
  return `You have ${intel.snapshots.restorable} restorable snapshot(s). Keep capturing one before each stage; auto-rollback restores the last valid snapshot automatically if a stage fails validation.`
}

function pqcComplianceAlignment(): string[] {
  return [
    `${STANDARDS.FIPS_203} — ML-KEM for quantum-safe key establishment`,
    `${STANDARDS.FIPS_204} — ML-DSA for signatures/certificates`,
    `${STANDARDS.FIPS_205} — SLH-DSA where stateless hash-based signatures fit`,
    `${STANDARDS.CNSA_2} — national-security algorithm suite transition`,
    `${STANDARDS.SP_800_208} — stateful hash-based signature guidance`,
  ]
}

/* ---- Mode composers ------------------------------------------------- */

function composeMigrationGuidance(intel: TenantIntelligence, objective: string): DeepSynthesis {
  const strategy = buildMigrationStrategy(intel)
  const keyFindings: string[] = []
  if (intel.assetsTotal != null) keyFindings.push(`${intel.assetsTotal} asset(s) in inventory${intel.internetFacing != null ? `, ${intel.internetFacing} internet-facing` : ''}.`)
  if (intel.vulnerableComponents != null) keyFindings.push(`${intel.vulnerableComponents} quantum-vulnerable cryptographic component(s)${intel.cryptoComponents != null ? ` of ${intel.cryptoComponents}` : ''} (PQC adoption ${intel.pqcAdoption ?? 0}%).`)
  if (intel.migration) keyFindings.push(`Migration workflow is ${intel.migration.progressPct}% complete at the "${intel.migration.stage}" stage.`)
  if (intel.jobs) keyFindings.push(`${intel.jobs.active} active and ${intel.jobs.failed} failed migration job(s).`)
  if (intel.snapshots) keyFindings.push(`${intel.snapshots.restorable} restorable snapshot(s) available for rollback.`)
  if (intel.hndl) keyFindings.push(`Harvest-Now exposure: ${intel.hndl.level}${intel.hndl.headline ? ` — ${intel.hndl.headline}` : ''}.`)

  const lead = intel.internetFacing && intel.internetFacing > 0
    ? `Migrate your internet-facing TLS infrastructure and the PKI it depends on first — it carries the highest Harvest-Now-Decrypt-Later exposure and anchors trust for everything downstream.`
    : `Start with your PKI and key management, then work outward to endpoints — upgrading trust roots first keeps dependent systems working as you migrate.`
  const state = intel.migration ? ` Your migration is already ${intel.migration.progressPct}% complete at the "${intel.migration.stage}" stage, so I’ve tailored the remaining order to your live state.` : ''
  const summary = `${lead}${state} The dependency-safe order below upgrades trust from the roots outward so nothing loses trust mid-migration, and I’ve flagged what breaks if the order is reversed.`

  const reasoning = [
    'Objective: provide a HOW — a prioritized, dependency-safe migration strategy — not just a status number.',
    'Correlated inventory, CBOM, exposure graph, trust chains, certificates, migration workflow, jobs and snapshots to reason over dependencies.',
    'Applied the canonical PQC migration order (roots → chains → keys → internet-facing TLS → internal → SSH/VPN → clients) so upgraded certificates are always trusted by their dependents.',
  ]

  const recommendations: CopilotRecommendation[] = [{
    title: intel.snapshots && intel.snapshots.restorable === 0 ? 'Snapshot before you continue' : 'Generate a migration plan for this order',
    detail: intel.snapshots && intel.snapshots.restorable === 0
      ? 'No restorable snapshot exists. Capture a pre-migration snapshot, then generate a migration plan that follows the roots-first order above.'
      : 'Turn this dependency-safe order into an executable plan with validation checkpoints and rollback at each stage.',
    priority: 'high',
    standards: [STANDARDS.SP_1800_38, STANDARDS.FIPS_203, STANDARDS.FIPS_204],
    deepLink: modulePath('migration_planner'),
  }]

  const riskOutlook: CopilotRiskOutlook | undefined = intel.riskLevel !== 'info'
    ? { before: intel.riskLevel, after: 'low', detail: `Completing this migration removes the legacy key establishment and signatures driving today’s ${riskLabel(intel.riskLevel)} quantum risk, reducing residual risk to Low once hybrid/PQC is deployed end-to-end.` }
    : undefined

  return {
    summary, objective, keyFindings, reasoning,
    businessImpact: intel.internetFacing && intel.internetFacing > 0
      ? 'Internet-facing systems recording sensitive traffic today are the clearest business exposure: that traffic is harvestable now and decryptable once a quantum computer exists. Migrating them first protects the highest-value data and customer-facing authentication.'
      : 'Migrating trust roots first protects authentication continuity across the estate, avoiding outages that would otherwise interrupt business services.',
    technicalAnalysis: [
      'Use hybrid key establishment (X25519 + ML-KEM) on TLS so peers without PQC still negotiate successfully while quantum-safe protection is added.',
      'Re-issue certificates with ML-DSA (or hybrid) signatures from upgraded intermediates; verify full chain validation before cutover.',
      intel.certs && intel.certs.total > 0 ? `${intel.certs.total} certificate(s) are in scope${intel.certs.quantumVulnerable ? ` (${intel.certs.quantumVulnerable} quantum-vulnerable)` : ''}; sequence their re-issuance from roots down.` : 'Discover certificates and their issuers so re-issuance can be sequenced from the roots down.',
    ].filter(Boolean),
    migrationStrategy: strategy,
    dependencies: dependencyHighlights(intel),
    potentialBreakages: [
      'Migrating endpoint/leaf certificates before their root and intermediate chains → path-validation and authentication failures.',
      'Deploying pure PQC (non-hybrid) TLS to peers lacking PQC support → handshake failures; use hybrid to stay interoperable.',
      'Rotating keys after issuing certificates → new certificates inherit legacy-key vulnerability, forcing a second migration.',
    ],
    rollbackStrategy: rollbackGuidance(intel),
    riskOutlook,
    complianceAlignment: pqcComplianceAlignment(),
    recommendations,
    nextActions: [
      { label: 'Generate a Migration Plan', path: modulePath('migration_planner'), reason: 'Turn this dependency-safe order into an executable, validated plan.' },
      { label: 'Review the Exposure Graph', path: modulePath('exposure_graph'), reason: 'See the live dependency/trust paths behind this order.' },
    ],
    risk: { level: intel.riskLevel, score: intel.quantumRisk ?? undefined, drivers: [`${intel.vulnerableComponents ?? 0} quantum-vulnerable component(s)`, intel.internetFacing ? `${intel.internetFacing} internet-facing asset(s)` : ''].filter(Boolean) },
  }
}

function composePrioritization(intel: TenantIntelligence, objective: string): DeepSynthesis {
  // Rank: internet-facing + quantum-vulnerable + biggest blast radius first.
  const priorities: Array<{ title: string; why: string }> = []
  if (intel.blast && intel.blast.totalAffected > 0) {
    priorities.push({ title: intel.blast.asset || 'Highest-blast-radius asset', why: `largest blast radius — ${intel.blast.totalAffected} dependent asset(s)${intel.blast.internetFacing ? `, ${intel.blast.internetFacing} internet-facing` : ''}; a failure or compromise here propagates widely.` })
  }
  for (const name of intel.topRiskAssets) {
    if (!priorities.some((p) => p.title === name)) priorities.push({ title: name, why: 'ranked among your highest quantum-risk assets by the risk engine.' })
    if (priorities.length >= 5) break
  }
  // Always anchor on the crypto-domain order even without per-asset detail.
  const strategy = buildMigrationStrategy(intel)

  const keyFindings: string[] = []
  if (intel.riskDist.critical + intel.riskDist.high > 0) keyFindings.push(`Risk distribution: ${intel.riskDist.critical} critical, ${intel.riskDist.high} high, ${intel.riskDist.medium} medium, ${intel.riskDist.low} low.`)
  if (intel.internetFacing != null) keyFindings.push(`${intel.internetFacing} internet-facing asset(s) — first in line for Harvest-Now exposure.`)
  if (intel.hndl) keyFindings.push(`HNDL exposure: ${intel.hndl.level}.`)
  if (intel.vulnerableComponents != null) keyFindings.push(`${intel.vulnerableComponents} quantum-vulnerable component(s) to replace.`)

  const topName = priorities[0]?.title
  const summary = topName
    ? `Migrate ${topName} first — ${priorities[0].why} After that, work down the risk-and-dependency order below: internet-facing TLS and the PKI beneath it, then internal services, SSH, VPN and clients. The order is driven by exposure (internet-facing + Harvest-Now), blast radius, and trust dependencies — not by asset name.`
    : `Prioritize by exposure and dependency, not inventory order: migrate internet-facing TLS and its PKI first (highest Harvest-Now exposure and trust anchor), then internal services, SSH, VPN and clients.`

  return {
    summary, objective, keyFindings,
    reasoning: [
      'Objective: prioritization — decide what to migrate first and WHY.',
      'Ranked candidates by internet-facing exposure, per-asset quantum risk, Harvest-Now exposure and blast radius (single points of failure), then reconciled with dependency order.',
      'Confirmed the order against trust chains so no asset loses trust by being migrated ahead of the roots it depends on.',
    ],
    businessImpact: 'Front-loading the highest-exposure, highest-blast-radius assets removes the most business risk earliest and protects the data most likely to be harvested today.',
    technicalAnalysis: priorities.slice(0, 5).map((p, i) => `${i + 1}. ${p.title} — ${p.why}`),
    migrationStrategy: strategy,
    dependencies: dependencyHighlights(intel),
    potentialBreakages: [
      'Migrating a high-risk leaf asset before its trust roots → authentication failures; keep the roots-first order within each priority tier.',
    ],
    rollbackStrategy: rollbackGuidance(intel),
    riskOutlook: intel.riskLevel !== 'info' ? { before: intel.riskLevel, after: 'medium', detail: 'Clearing the top-priority assets moves the estate off its worst exposure; residual risk drops further as the remaining tiers complete.' } : undefined,
    complianceAlignment: pqcComplianceAlignment(),
    recommendations: [{
      title: 'Open the Migration Planner with this priority order',
      detail: 'Sequence the top assets first, then follow the roots-first crypto-domain order for the remainder.',
      priority: 'high', standards: [STANDARDS.SP_1800_38], deepLink: modulePath('migration_planner'),
    }],
    nextActions: [
      { label: 'Open Risk Analysis', path: modulePath('risk_analysis'), reason: 'See the per-asset risk drivers behind this ranking.' },
      { label: 'Open the Exposure Graph', path: modulePath('exposure_graph'), reason: 'Inspect blast radius and single points of failure.' },
    ],
    risk: { level: intel.riskLevel, score: intel.quantumRisk ?? undefined, drivers: [`${intel.riskDist.critical} critical / ${intel.riskDist.high} high-risk asset(s)`] },
  }
}

function composeExecutive(intel: TenantIntelligence, objective: string): DeepSynthesis {
  const keyFindings: string[] = []
  if (intel.readiness != null) keyFindings.push(`Quantum readiness ${intel.readiness}/100 (${intel.readinessLevel}).`)
  if (intel.pqcAdoption != null) keyFindings.push(`PQC adoption ${intel.pqcAdoption}%${intel.vulnerableComponents != null ? `; ${intel.vulnerableComponents} quantum-vulnerable component(s) remain` : ''}.`)
  if (intel.quantumRisk != null) keyFindings.push(`Quantum risk ${intel.quantumRisk}/100${intel.hndlRisk != null ? `, Harvest-Now risk ${intel.hndlRisk}/100` : ''}.`)
  if (intel.migration) keyFindings.push(`Migration program ${intel.migration.progressPct}% complete.`)
  if (intel.certification) keyFindings.push(intel.certification.eligible ? 'Eligible for Quantum Trust Certification.' : `${intel.certification.unmet.length} certification criteria still unmet.`)

  const verdict = intel.readiness == null ? 'not yet measurable'
    : intel.readiness >= 75 ? 'strong' : intel.readiness >= 50 ? 'developing' : intel.readiness >= 25 ? 'early' : 'nascent'
  const summary = intel.readiness == null
    ? 'I can’t give an executive readiness verdict yet because there’s no assessment data. Run a discovery scan (or connect a collector/cloud connector) and I’ll build the posture from real evidence.'
    : `Your quantum readiness is ${verdict} at ${intel.readiness}/100. The main drivers are ${intel.vulnerableComponents ?? 0} quantum-vulnerable component(s) and ${intel.pqcAdoption ?? 0}% PQC adoption, against a quantum-risk score of ${intel.quantumRisk ?? 'n/a'}/100${intel.hndlRisk != null ? ` and Harvest-Now risk of ${intel.hndlRisk}/100` : ''}. ${intel.migration ? `Migration is ${intel.migration.progressPct}% underway. ` : ''}The fastest path to a higher score is to clear the vulnerable components on your internet-facing systems first, then close the certification gaps.`

  return {
    summary, objective, keyFindings,
    reasoning: [
      'Objective: an executive readiness assessment — where you stand and what moves the needle.',
      'Correlated readiness scoring, risk, HNDL, CBOM adoption, migration progress and certification eligibility into one posture.',
      'Identified the highest-leverage drivers so the recommendation improves the score fastest.',
    ],
    businessImpact: intel.hndl ? 'Harvest-Now exposure means sensitive data in transit today can be decrypted later — the board-level risk is future disclosure of data captured now, which is why readiness is a present-tense concern, not a future one.' : 'Readiness gaps translate to regulatory and continuity risk as PQC mandates take effect; closing them protects compliance standing and customer trust.',
    technicalAnalysis: [
      intel.vulnerableComponents != null ? `Replace the ${intel.vulnerableComponents} vulnerable component(s) with ML-KEM/ML-DSA; use hybrid where peers lag.` : 'Run discovery to enumerate vulnerable components.',
      intel.certification && !intel.certification.eligible ? `Certification readiness is ${intel.certification.readinessPct}% — closing the ${intel.certification.unmet.length} unmet criteria raises both the certificate level and the readiness score.` : '',
    ].filter(Boolean),
    dependencies: dependencyHighlights(intel),
    rollbackStrategy: rollbackGuidance(intel),
    riskOutlook: intel.riskLevel !== 'info' ? { before: intel.riskLevel, after: 'low', detail: 'Executing the recommended remediation moves readiness up and quantum risk down toward Low.' } : undefined,
    complianceAlignment: pqcComplianceAlignment(),
    recommendations: [{
      title: 'Generate the executive readiness report',
      detail: 'Produce the board-ready report (readiness ladder, certification summary, effort/cost) from this live posture.',
      priority: 'medium', standards: [STANDARDS.NIST_CSF], deepLink: modulePath('reports'),
    }],
    nextActions: [
      { label: 'Open the Executive Dashboard', path: modulePath('executive'), reason: 'Track readiness and business risk over time.' },
      { label: 'Open the Remediation Engine', path: modulePath('remediation'), reason: 'Work the highest-leverage actions to raise readiness.' },
    ],
    risk: { level: intel.riskLevel, score: intel.quantumRisk ?? undefined, drivers: [`readiness ${intel.readiness ?? 'n/a'}/100`, `${intel.vulnerableComponents ?? 0} vulnerable component(s)`] },
  }
}

function composeGapAnalysis(intel: TenantIntelligence, objective: string): DeepSynthesis {
  const cert = intel.certification
  const unmet = cert?.unmet ?? []
  const summary = !cert
    ? 'I couldn’t read your certification eligibility — apply the certification schema / run an assessment and I’ll pinpoint the exact blockers.'
    : cert.eligible
      ? 'You already meet the certification criteria. If you haven’t been issued a certificate, generate one from the Certification engine — the evidence is in place.'
      : `Certification is blocked by ${unmet.length} unmet criteri${unmet.length === 1 ? 'on' : 'a'}${unmet.length ? `: ${unmet.slice(0, 4).join('; ')}${unmet.length > 4 ? '…' : ''}` : ''}. Your certification readiness is ${cert.readinessPct}%. The root cause is insufficient PQC adoption and evidence coverage on the assets that back those criteria — each remediation action you complete raises the readiness score toward eligibility.`

  return {
    summary, objective,
    keyFindings: [
      cert ? `Certification readiness ${cert.readinessPct}% — ${cert.eligible ? 'eligible' : `${unmet.length} criteria unmet`}.` : 'Certification eligibility unavailable.',
      intel.vulnerableComponents != null ? `${intel.vulnerableComponents} quantum-vulnerable component(s) still count against the criteria.` : '',
      intel.remediation ? `${intel.remediation.pending} pending remediation action(s), ${intel.remediation.criticalBlockers} critical blocker(s), ${intel.remediation.quickWins} quick win(s).` : '',
    ].filter(Boolean),
    reasoning: [
      'Objective: gap analysis — identify exactly what is blocking certification and the fastest path to close it.',
      'Cross-referenced certification eligibility criteria against CBOM posture, remediation readiness and evidence coverage.',
      'Ordered the fixes by marginal readiness gain so certification is reached with the least work.',
    ],
    rootCause: cert && !cert.eligible
      ? `The unmet criteria trace back to legacy cryptography still present (${intel.vulnerableComponents ?? 'unknown'} vulnerable component(s)) and gaps in the evidence that proves PQC controls are in force. Certification is evidence-gated, so both the crypto and its proof must be in place.`
      : undefined,
    businessImpact: 'Certification is the external proof of quantum-safe posture for customers, auditors and regulators — closing these gaps unlocks that attestation and the trust/marketing value that comes with it.',
    technicalAnalysis: unmet.slice(0, 6).map((c) => `Unmet: ${c} — resolve via the mapped remediation action(s).`),
    dependencies: dependencyHighlights(intel),
    rollbackStrategy: rollbackGuidance(intel),
    riskOutlook: cert && !cert.eligible ? { before: intel.riskLevel === 'info' ? 'medium' : intel.riskLevel, after: 'low', detail: `Closing the ${unmet.length} criteria raises readiness from ${cert.readinessPct}% toward eligibility and lowers residual risk.` } : undefined,
    complianceAlignment: [`${STANDARDS.NIST_CSF} — governance evidence`, `${STANDARDS.ISO_27001} — control evidence`, ...pqcComplianceAlignment().slice(0, 3)],
    recommendations: [{
      title: 'Work the remediation readiness ladder',
      detail: `Each completed action raises certification readiness${cert ? ` from ${cert.readinessPct}%` : ''}; start with the critical blockers, then the quick wins.`,
      priority: 'high', standards: [STANDARDS.NIST_CSF], deepLink: modulePath('remediation'),
    }],
    nextActions: [
      { label: 'Open Certification', path: modulePath('certification'), reason: 'See the criteria and current eligibility.' },
      { label: 'Open the Remediation Engine', path: modulePath('remediation'), reason: 'Close the blocking criteria in the highest-gain order.' },
    ],
    risk: { level: intel.riskLevel === 'info' ? 'medium' : intel.riskLevel, drivers: [`${unmet.length} unmet certification criteria`] },
  }
}

function composeExplain(intel: TenantIntelligence, objective: string): DeepSynthesis {
  const drivers: string[] = []
  if (intel.internetFacing) drivers.push(`internet-facing exposure (${intel.internetFacing} asset(s))`)
  if (intel.vulnerableComponents) drivers.push(`${intel.vulnerableComponents} quantum-vulnerable cryptographic component(s)`)
  if (intel.hndl) drivers.push('Harvest-Now-Decrypt-Later exposure on long-lived data')
  if (intel.blast && intel.blast.totalAffected > 0) drivers.push(`large blast radius (${intel.blast.totalAffected} dependents)`)
  if (intel.certs && intel.certs.quantumVulnerable) drivers.push(`${intel.certs.quantumVulnerable} quantum-vulnerable certificate(s)`)

  const summary = drivers.length
    ? `The risk is driven by ${drivers.slice(0, 3).join(', ')}. In plain terms: quantum-vulnerable algorithms (RSA/ECC) protecting internet-facing, high-dependency systems mean traffic captured today can be decrypted once a quantum computer exists, and a single weak trust anchor can cascade across everything that depends on it. That combination of exposure × vulnerability × blast radius is what elevates the risk.`
    : 'I need more evidence to explain the risk precisely — run a discovery scan so I can attribute the risk to specific assets, algorithms and dependencies.'

  return {
    summary, objective,
    keyFindings: [
      intel.quantumRisk != null ? `Quantum risk ${intel.quantumRisk}/100 (${riskLabel(intel.riskLevel)}).` : '',
      intel.riskDist.critical + intel.riskDist.high > 0 ? `${intel.riskDist.critical} critical / ${intel.riskDist.high} high-risk asset(s).` : '',
      intel.hndl ? `HNDL exposure: ${intel.hndl.level}.` : '',
    ].filter(Boolean),
    reasoning: [
      'Objective: explain the reasoning — WHY, HOW, root cause and impact — not just the score.',
      'Attributed the risk to concrete drivers: algorithm vulnerability, internet exposure, dependency blast radius and Harvest-Now.',
      'Translated the technical drivers into security, business and compliance impact.',
    ],
    rootCause: `Legacy public-key cryptography (RSA/ECC/DH) is mathematically breakable by a large quantum computer via Shor’s algorithm. Where that crypto sits on exposed, high-dependency assets, the theoretical weakness becomes concrete, high-impact risk.`,
    businessImpact: intel.hndl ? 'Data harvested today (recorded traffic, stored ciphertext) becomes readable in the future — the business risk is delayed disclosure of information that is sensitive now.' : 'Compromise of a high-blast-radius asset can cascade authentication failures or breaches across dependent systems.',
    technicalAnalysis: [
      'Shor’s algorithm breaks RSA/ECC/DH; Grover’s halves symmetric strength (AES-256 stays safe, AES-128 weakens).',
      'Mitigation is ML-KEM (key establishment) + ML-DSA/SLH-DSA (signatures), deployed hybrid for interoperability.',
      intel.blast ? `${intel.blast.asset}’s ${intel.blast.totalAffected} dependents mean its compromise propagates — migrate it early.` : '',
    ].filter(Boolean),
    dependencies: dependencyHighlights(intel),
    complianceAlignment: pqcComplianceAlignment(),
    recommendations: [{
      title: 'Reduce the top risk drivers first',
      detail: 'Replace vulnerable algorithms on internet-facing, high-blast-radius assets with ML-KEM/ML-DSA (hybrid), starting from the trust roots.',
      priority: 'high', standards: [STANDARDS.FIPS_203, STANDARDS.FIPS_204, STANDARDS.CNSA_2], deepLink: modulePath('remediation'),
    }],
    nextActions: [
      { label: 'Open Risk Analysis', path: modulePath('risk_analysis'), reason: 'Drill into the per-asset risk drivers.' },
      { label: 'Open the Exposure Graph', path: modulePath('exposure_graph'), reason: 'See the dependency/blast-radius paths.' },
    ],
    risk: { level: intel.riskLevel, score: intel.quantumRisk ?? undefined, drivers: drivers.slice(0, 5) },
  }
}

function composeGeneralDeep(intel: TenantIntelligence, objective: string): DeepSynthesis {
  // Executive-style synthesis as the default for other consultative questions.
  return composeExecutive(intel, objective)
}

function synthesizeDeep(kind: CopilotObjectiveKind, intel: TenantIntelligence, objective: string): DeepSynthesis {
  switch (kind) {
    case 'guidance': return composeMigrationGuidance(intel, objective)
    case 'prioritization': return composePrioritization(intel, objective)
    case 'executive': return composeExecutive(intel, objective)
    case 'gap_analysis': return composeGapAnalysis(intel, objective)
    case 'explain': return composeExplain(intel, objective)
    default: return composeGeneralDeep(intel, objective)
  }
}

/* ------------------------------------------------------------------ */
/* Answer composition                                                  */
/* ------------------------------------------------------------------ */

const INTENT_FOLLOW_UPS: Partial<Record<CopilotIntent, string[]>> = {
  asset_status: ['Which of these assets are internet-facing?', 'Show the blast radius of the riskiest asset.'],
  migration_status: ['What should I migrate next?', 'Do I have restorable snapshots?'],
  remediation: ['Which remediation gives the biggest certification gain?', 'Show the critical blockers.'],
  risk_analysis: ['Which assets drive the critical risk?', 'How do I reduce HNDL exposure?'],
  certification: ['What exactly is blocking certification?', 'How do I reach the next level?'],
  compliance: ['How close am I to CNSA 2.0?', 'Show my NIST PQC alignment.'],
  pki: ['Which certificates expire in the next 90 days?', 'Which issuers anchor my trust chains?'],
  quantum_readiness: ['What raises my readiness score fastest?', 'Generate an executive report.'],
  harvest_now: ['Which endpoints lack forward secrecy?', 'What reduces HNDL exposure fastest?'],
  telemetry: ['Which collectors are offline?', 'Show recent legacy-crypto events.'],
  exposure_graph: ['Show my third-party dependencies.', 'Which trust chains are critical?'],
  scanner: ['Show critical findings.', 'Which algorithms were discovered?'],
}

export interface ComposeInput {
  question: string
  plan: ExecutionPlan
  executions: ToolExecution[]
  lastAssessmentAt?: string | null
}

/** Pure answer composer — exported for offline verification. */
export function composeAnswer(input: ComposeInput): CopilotAnswer {
  const { plan, executions } = input
  const toolData = new Map<string, ToolResult>()
  const toolRuns: CopilotToolRun[] = []
  for (const execution of executions) {
    toolRuns.push(execution.run)
    if (execution.result) toolData.set(execution.run.tool, execution.result)
  }

  const bundle: SynthBundle = {
    tool: (name) => toolData.get(name) || null,
    question: input.question,
  }

  // Specialist-agent contributions — always gathered (they carry evidence-linked
  // recommendations and per-module risk). In investigate mode the deep synthesis
  // leads and these enrich; in direct mode they compose the answer.
  const findings: string[] = []
  const agentRecommendations: CopilotRecommendation[] = []
  let agentRisk: CopilotRisk = { level: 'info', drivers: [] }
  for (const agentId of plan.agents) {
    const synth = AGENT_SYNTH[agentId]
    if (!synth) continue
    const contribution = synth(bundle)
    findings.push(...contribution.findings)
    agentRecommendations.push(...contribution.recommendations)
    if (RISK_RANK[contribution.risk.level] > RISK_RANK[agentRisk.level]) {
      agentRisk = { ...contribution.risk, drivers: [...agentRisk.drivers, ...contribution.risk.drivers] }
    } else {
      agentRisk = { ...agentRisk, drivers: [...agentRisk.drivers, ...contribution.risk.drivers] }
    }
  }
  agentRisk.drivers = [...new Set(agentRisk.drivers)].slice(0, 6)

  // Evidence: merged from every successful tool run.
  const evidence: CopilotEvidence[] = []
  for (const result of toolData.values()) evidence.push(...result.evidence)

  // Prepared human-in-the-loop actions always surface as next actions.
  const preparedActions: CopilotNextAction[] = []
  for (const [name, result] of toolData) {
    const data = rec(result.data)
    if (data.prepared === true) {
      preparedActions.push({ label: `Confirm ${str(data.action) || name}`, path: str(data.deepLink) || '/dashboard', reason: str(data.summary).slice(0, 160) })
    }
  }

  const relatedPages: CopilotRelatedPage[] = plan.modules.slice(0, 6).map((id) => ({ label: moduleLabel(id), path: modulePath(id) }))

  // Confidence — coverage × data availability × freshness. Deterministic and explained.
  const okRuns = toolRuns.filter((r) => r.status === 'ok').length
  const emptyRuns = toolRuns.filter((r) => r.status === 'empty').length
  const errorRuns = toolRuns.filter((r) => r.status === 'error').length
  const deniedRuns = toolRuns.filter((r) => r.status === 'denied').length
  const attempted = toolRuns.length || 1
  let confidenceScore = 40 + Math.round((okRuns / attempted) * 40)
  if (evidence.length >= 3) confidenceScore += 8
  if (evidence.length >= 8) confidenceScore += 4
  if (input.lastAssessmentAt) {
    const ageH = (Date.now() - new Date(input.lastAssessmentAt).getTime()) / 36e5
    if (Number.isFinite(ageH) && ageH <= 24) confidenceScore += 8
  }
  confidenceScore -= errorRuns * 10
  if (okRuns === 0 && emptyRuns > 0) confidenceScore = 30
  confidenceScore = clamp(confidenceScore, 5, 98)
  const confidenceBasis = `Correlated ${okRuns}/${attempted} data source(s)${errorRuns ? `, ${errorRuns} failed` : ''}${emptyRuns ? `, ${emptyRuns} with no data yet` : ''}${deniedRuns ? `, ${deniedRuns} beyond your role` : ''}; freshness ${input.lastAssessmentAt ? new Date(input.lastAssessmentAt).toISOString().slice(0, 16).replace('T', ' ') : 'unknown'}`

  const followUps = [...new Set([...(plan.objectiveKind === 'guidance' ? ['What could break during this migration?', 'Do I have snapshots to roll back to?'] : []), ...plan.intents.flatMap((i) => INTENT_FOLLOW_UPS[i] || [])])].slice(0, 4)

  const dedupeRecs = (recs: CopilotRecommendation[]): CopilotRecommendation[] => {
    const seen = new Set<string>()
    return recs.filter((r) => (seen.has(r.title) ? false : (seen.add(r.title), true))).slice(0, 6)
  }

  /* ---- Investigate mode: deep, correlated, consultant-grade answer ---- */
  if (plan.mode === 'investigate') {
    const intel = extractIntelligence(toolData)
    const proactive = detectProactiveFindings(intel)

    // Honest no-data path — never fabricate a strategy/metrics.
    if (!intel.hasData) {
      const missing: string[] = []
      if (emptyRuns) missing.push('no assessment/scan data yet')
      const summary = `I ran a full investigation across ${okRuns + emptyRuns} module(s), but there isn’t enough live evidence in your tenant yet to answer this deeply. ${plan.objective} To get a real, tenant-specific answer, run a discovery scan or connect a collector/cloud connector — then I can correlate assets, CBOM, exposure, certificates and migration state. I only report evidence, never estimates.`
      return {
        id: nextId(), intents: plan.intents, agents: plan.agents, summary,
        reasoning: [
          `Objective inferred: ${plan.objectiveKind} — ${plan.objective}`,
          `Investigated ${attempted} tool(s) across ${plan.modules.length} module(s); ${emptyRuns} returned no data yet.`,
          'Withholding a strategy/metrics because the supporting evidence is not present (no fabrication).',
        ],
        evidence: evidence.slice(0, 12), recommendations: [{
          title: 'Run a discovery scan to unlock deep analysis',
          detail: 'Scan your assets (or connect a collector / cloud connector). Once there’s live crypto evidence, I’ll produce the full strategy, prioritization and risk reasoning.',
          priority: 'high', standards: [STANDARDS.NIST_CSF], deepLink: modulePath('scanner'),
        }],
        risk: { level: 'info', drivers: [] },
        nextActions: [...preparedActions, { label: 'Run a discovery scan', path: modulePath('scanner'), reason: 'Generate the evidence Sophia needs.' }].slice(0, 5),
        relatedPages, standards: [STANDARDS.NIST_CSF],
        confidence: { score: Math.min(confidenceScore, 35), basis: confidenceBasis },
        toolRuns, followUps: ['What data does Sophia need?', 'How do I run a scan?'],
        mode: 'investigate', objectiveKind: plan.objectiveKind, objective: plan.objective,
        keyFindings: ['No live cryptographic evidence found for this tenant yet.'],
        proactiveFindings: proactive,
        generatedAt: new Date().toISOString(),
      }
    }

    const deep = synthesizeDeep(plan.objectiveKind, intel, plan.objective)
    const recommendations = dedupeRecs([...deep.recommendations, ...agentRecommendations])
    const risk = RISK_RANK[deep.risk.level] >= RISK_RANK[agentRisk.level]
      ? { ...deep.risk, drivers: [...new Set([...deep.risk.drivers, ...agentRisk.drivers])].slice(0, 6) }
      : { ...agentRisk, drivers: [...new Set([...agentRisk.drivers, ...deep.risk.drivers])].slice(0, 6) }

    const nextActions: CopilotNextAction[] = []
    for (const a of [...preparedActions, ...deep.nextActions]) {
      if (!nextActions.some((x) => x.path === a.path)) nextActions.push(a)
    }

    const standards = [...new Set([...(deep.complianceAlignment?.flatMap((s) => s.split(' — ')[0]) || []), ...recommendations.flatMap((r) => r.standards)])].slice(0, 8)

    const reasoning = [
      `Objective inferred: ${plan.objectiveKind} — ${plan.objective}`,
      `Deep investigation across ${okRuns} live module(s): ${plan.modules.map((m) => moduleLabel(m)).slice(0, 8).join(', ')}.`,
      `Also examined: ${plan.expansion.slice(0, 6).join('; ')}.`,
      ...deep.reasoning,
      ...toolRuns.filter((r) => r.status === 'error').slice(0, 2).map((r) => `Note: ${r.tool} → error${r.note ? ` (${r.note})` : ''}.`),
    ]

    return {
      id: nextId(), intents: plan.intents, agents: plan.agents,
      summary: deep.summary,
      reasoning,
      evidence: evidence.slice(0, 14),
      recommendations,
      risk,
      nextActions: nextActions.slice(0, 6),
      relatedPages,
      standards,
      confidence: { score: confidenceScore, basis: confidenceBasis },
      toolRuns,
      followUps,
      generatedAt: new Date().toISOString(),
      // Deep-reasoning fields:
      mode: 'investigate',
      objectiveKind: plan.objectiveKind,
      objective: deep.objective,
      keyFindings: (deep.keyFindings || []).slice(0, 8),
      rootCause: deep.rootCause,
      businessImpact: deep.businessImpact,
      technicalAnalysis: deep.technicalAnalysis,
      migrationStrategy: deep.migrationStrategy,
      dependencies: deep.dependencies,
      potentialBreakages: deep.potentialBreakages,
      rollbackStrategy: deep.rollbackStrategy,
      riskOutlook: deep.riskOutlook,
      complianceAlignment: deep.complianceAlignment,
      proactiveFindings: proactive,
    }
  }

  /* ---- Direct mode: focused lookup answered from the agent synthesis ---- */
  const nextActions: CopilotNextAction[] = [...preparedActions]
  for (const recItem of agentRecommendations.slice(0, 3)) {
    if (recItem.deepLink && !nextActions.some((a) => a.path === recItem.deepLink)) {
      nextActions.push({ label: recItem.title, path: recItem.deepLink, reason: recItem.detail.slice(0, 160) })
    }
  }

  let summary: string
  if (findings.length) {
    summary = findings.slice(0, 3).join(' ')
  } else if (emptyRuns === attempted && attempted > 0) {
    summary = 'No live data exists yet for this question. Connect a scanner, collector or cloud connector and run a discovery scan — I only report evidence, never estimates.'
  } else {
    summary = 'I could not derive an evidence-backed answer for this question. Try one of the suggested questions, or ask about a specific module.'
  }

  const reasoning = [
    `Detected intent(s): ${plan.intents.join(', ')}${plan.followUp ? ' (follow-up to the previous question)' : ''}.`,
    `Consulted ${attempted} platform tool(s) across ${plan.modules.length} module(s): ${plan.modules.map((m) => moduleLabel(m)).join(', ') || '—'}.`,
    ...toolRuns.filter((r) => r.status !== 'ok').slice(0, 3).map((r) => `Note: ${r.tool} → ${r.status}${r.note ? ` (${r.note})` : ''}.`),
  ]

  const standards = [...new Set(agentRecommendations.flatMap((r) => r.standards))].slice(0, 8)

  return {
    id: nextId(),
    intents: plan.intents,
    agents: plan.agents,
    summary,
    reasoning,
    evidence: evidence.slice(0, 12),
    recommendations: dedupeRecs(agentRecommendations),
    risk: agentRisk,
    nextActions: nextActions.slice(0, 5),
    relatedPages,
    standards,
    confidence: { score: confidenceScore, basis: confidenceBasis },
    toolRuns,
    followUps,
    generatedAt: new Date().toISOString(),
    mode: 'direct',
    objectiveKind: plan.objectiveKind,
  }
}

/** Answer used when the sanitizer blocks a prompt — no tools are executed. */
export function blockedAnswer(reasons: string[]): CopilotAnswer {
  return {
    id: nextId(),
    intents: [],
    agents: ['coordinator'],
    summary: 'I can’t help with that request. It was flagged by the copilot’s safety layer (' + reasons.join('; ') + '). I only analyze your own tenant’s data, never reveal secrets or system internals, and never execute raw queries.',
    reasoning: ['Prompt-injection protection blocked this request before any data access.'],
    evidence: [],
    recommendations: [],
    risk: { level: 'info', drivers: [] },
    nextActions: [],
    relatedPages: [],
    standards: [STANDARDS.OWASP_ASVS],
    confidence: { score: 98, basis: 'Deterministic security policy' },
    toolRuns: [],
    followUps: ['Am I quantum ready?', 'Show my most vulnerable assets.'],
    blocked: 'prompt_injection',
    generatedAt: new Date().toISOString(),
  }
}

/* ------------------------------------------------------------------ */
/* Coordinator — full query execution with streaming callbacks         */
/* ------------------------------------------------------------------ */

export interface QueryOutcome {
  answer: CopilotAnswer
  memory: CopilotMemoryState
}

export async function runCopilotQuery(
  ctx: ToolContext,
  rawQuestion: string,
  memory: CopilotMemoryState,
  emit: (event: CopilotStreamEvent) => void,
  deps: CopilotBuilders = liveBuilders,
): Promise<QueryOutcome> {
  emit({ type: 'stage', stage: 'thinking', label: 'Sophia is thinking…' })

  const sanitized = sanitizePrompt(rawQuestion)
  if (sanitized.blocked) {
    const answer = blockedAnswer(sanitized.reasons)
    emit({ type: 'answer', answer })
    emit({ type: 'done' })
    return { answer, memory: { ...memory, turns: memory.turns + 1 } }
  }

  const plan = planQuery(sanitized.text, memory)
  emit({ type: 'stage', stage: 'intent', label: `Understood your objective: ${plan.objective}` })
  if (plan.mode === 'investigate') {
    emit({ type: 'stage', stage: 'expanding', label: `Expanding the question — also examining: ${plan.expansion.slice(0, 4).join(', ')}` })
    emit({ type: 'stage', stage: 'investigating', label: `Running a full cross-module investigation (${plan.tools.length} sources across ${plan.modules.length} modules)…` })
  } else {
    emit({ type: 'stage', stage: 'planning', label: `Consulting ${plan.tools.length} tool(s) across ${plan.modules.map((m) => moduleLabel(m)).join(', ') || 'the platform'}` })
  }

  const executions: ToolExecution[] = []
  await Promise.all(plan.tools.map(async (tool) => {
    emit({ type: 'stage', stage: 'reading', label: `Reading ${tool}…` })
    const execution = await runTool(tool, ctx, plan.args, deps)
    executions.push(execution)
    emit({ type: 'tool', run: execution.run })
  }))

  if (plan.mode === 'investigate') {
    emit({ type: 'stage', stage: 'correlating', label: 'Correlating evidence across every module (dependencies, trust chains, blast radius)…' })
    emit({ type: 'stage', stage: 'analyzing', label: 'Reasoning over risk, root cause and migration impact…' })
  } else {
    emit({ type: 'stage', stage: 'reasoning', label: 'Correlating evidence across modules…' })
  }

  // Freshness for confidence: prefer the QR snapshot's assessment time.
  let lastAssessmentAt: string | null = null
  const readiness = executions.find((e) => e.run.tool === 'getQuantumReadiness')?.result
  if (readiness) lastAssessmentAt = str(rec(readiness.data).lastAssessmentAt) || null

  emit({ type: 'stage', stage: 'generating', label: plan.mode === 'investigate' ? 'Writing the consultant-grade analysis…' : 'Generating the evidence-based answer…' })
  const answer = composeAnswer({ question: sanitized.text, plan, executions, lastAssessmentAt })
  emit({ type: 'answer', answer })
  emit({ type: 'done' })

  // Update conversation memory for follow-ups.
  const focusAssets: string[] = []
  for (const item of answer.evidence) {
    if (/asset/i.test(item.label) && item.detail) focusAssets.push(item.detail.slice(0, 60))
  }
  const blastExec = executions.find((e) => e.run.tool === 'getBlastRadius')?.result
  const focusEntity = blastExec ? str(rec(blastExec.data).asset) : memory.focusEntity

  return {
    answer,
    memory: {
      focusIntents: answer.intents.length ? answer.intents : memory.focusIntents,
      focusAssets: focusAssets.slice(0, 5),
      focusEntity: focusEntity || undefined,
      lastSummary: answer.summary.slice(0, 240),
      currentPage: memory.currentPage,
      turns: memory.turns + 1,
    },
  }
}

/* ------------------------------------------------------------------ */
/* Proactive insights                                                  */
/* ------------------------------------------------------------------ */

export async function buildInsights(ctx: ToolContext, deps: CopilotBuilders = liveBuilders): Promise<CopilotInsight[]> {
  const insights: CopilotInsight[] = []
  const push = (severity: CopilotRiskLevel, title: string, detail: string, moduleId: string, evidenceLine: string) => {
    insights.push({ id: `insight-${insights.length + 1}`, severity, title, detail, deepLink: modulePath(moduleId), module: moduleLabel(moduleId), evidence: evidenceLine })
  }

  const [snapshotResult, certsResult, fleetResult, jobsResult, eligibilityResult] = await Promise.allSettled([
    deps.snapshot(ctx.token, ctx.userId),
    runTool('getCertificates', ctx, {}, deps),
    runTool('getCollectorsStatus', ctx, {}, deps),
    runTool('getMigrationJobs', ctx, {}, deps),
    runTool('getCertificationEligibility', ctx, {}, deps),
  ])

  if (snapshotResult.status === 'fulfilled') {
    const snapshot = snapshotResult.value
    const scores = rec(snapshot.scores)
    const inventory = rec(snapshot.inventory)
    const dist = rec(snapshot.riskDistribution)
    if (!snapshot.hasData) {
      push('info', 'No assessment data yet', 'Run a discovery scan so readiness, risk and remediation intelligence can be computed from real evidence.', 'scanner', 'Quantum Readiness snapshot: hasData=false')
    } else {
      if (num(dist.critical) > 0) push('critical', `${num(dist.critical)} critical-risk asset(s)`, 'These assets combine quantum-vulnerable crypto with high exposure — review them first.', 'risk_analysis', `Risk distribution: ${num(dist.critical)} critical`)
      if (num(scores.hndlRisk) >= 55) push('high', `HNDL risk is ${num(scores.hndlRisk)}/100`, 'Long-lived data under legacy key establishment is exposed to Harvest-Now-Decrypt-Later capture.', 'harvest_now', `HNDL risk score ${num(scores.hndlRisk)}`)
      if (num(inventory.vulnerableComponents) > 0) push('high', `${num(inventory.vulnerableComponents)} quantum-vulnerable component(s)`, 'Replace RSA/ECC with ML-KEM / ML-DSA per FIPS 203/204; use hybrid where peers lag.', 'cbom', `CBOM vulnerable=${num(inventory.vulnerableComponents)}`)
    }
  }

  if (certsResult.status === 'fulfilled' && certsResult.value.result) {
    const data = rec(certsResult.value.result.data)
    if (num(data.expired) > 0) push('high', `${num(data.expired)} expired certificate(s)`, 'Expired certificates break trust chains and mask crypto posture — reissue with quantum-safe or hybrid chains.', 'pki', `certificates expired=${num(data.expired)}`)
    else if (num(data.expiringSoon) > 0) push('medium', `${num(data.expiringSoon)} certificate(s) expiring soon`, 'Rotate ahead of expiry and prefer ML-DSA or hybrid issuance on renewal.', 'pki', `certificates expiringSoon=${num(data.expiringSoon)}`)
  }

  if (fleetResult.status === 'fulfilled' && fleetResult.value.result) {
    const data = rec(fleetResult.value.result.data)
    if (num(data.fleet) > 0 && num(data.online) < num(data.fleet)) {
      push('medium', `${num(data.fleet) - num(data.online)} collector agent(s) offline`, 'Offline collectors create discovery and telemetry blind spots.', 'collectors', `fleet ${num(data.online)}/${num(data.fleet)} online`)
    }
  }

  if (jobsResult.status === 'fulfilled' && jobsResult.value.result) {
    const data = rec(jobsResult.value.result.data)
    const failed = arr(data.failed).length
    if (failed > 0) push('high', `${failed} failed migration job(s)`, 'Failed migrations may leave assets in mixed crypto state — review and roll back or retry from snapshots.', 'live_migration', `migration_jobs failed=${failed}`)
  }

  if (eligibilityResult.status === 'fulfilled' && eligibilityResult.value.result) {
    const data = rec(eligibilityResult.value.result.data)
    if (data.eligible !== true && arr(data.unmet).length > 0) {
      push('medium', 'Certification blockers present', `${arr(data.unmet).length} criteria unmet — readiness ${num(data.certificationReadinessPct)}%. The Remediation Engine ladder shows the fastest path.`, 'remediation', `unmet criteria=${arr(data.unmet).length}`)
    }
  }

  const severityOrder: CopilotRiskLevel[] = ['critical', 'high', 'medium', 'low', 'info']
  return insights.sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)).slice(0, 8)
}
