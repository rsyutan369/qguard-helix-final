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
  extractQueryFilter,
  sanitizePrompt,
  modulePath,
  moduleLabel,
  STANDARDS,
  type QueryFilter,
} from './copilot-knowledge'
import {
  liveBuilders,
  runTool,
  TOOL_REGISTRY,
  type AssetView,
  type CopilotBuilders,
  type ToolContext,
  type ToolExecution,
  type ToolResult,
} from './copilot-tools'
import {
  answerFocus,
  finalizeFocus,
  FOCUS_SPECS,
  focusLabel,
  focusTools,
  resolveFocus,
  type FocusAnswer,
  type FocusId,
  type SourceStatus,
} from './copilot-answers'
import type {
  CopilotAgentId,
  CopilotAnswer,
  CopilotAnswerGrounding,
  CopilotAnswerMode,
  CopilotEvidence,
  CopilotFigure,
  CopilotFigureChange,
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

/**
 * User-facing name for a data source. Everything shown to the user speaks in
 * platform-module labels ("Assets & CBOM", "Risk Analysis") — raw tool
 * identifiers (getAssets, searchAssets…) are backend internals and never
 * appear in stage labels or reasoning.
 */
function sourceLabel(tool: string): string {
  const moduleId = TOOL_REGISTRY[tool]?.module
  return moduleId ? moduleLabel(moduleId) : 'the platform'
}

const STATUS_PHRASE: Record<string, string> = {
  ok: 'returned data',
  empty: 'has no data yet',
  error: 'was unavailable',
  denied: 'is outside your role permissions',
}

/** Deduplicated, user-facing notes for non-ok sources (no tool names). */
function sourceNotes(toolRuns: CopilotToolRun[], statuses: string[], max: number): string[] {
  const notes = toolRuns
    .filter((r) => statuses.includes(r.status))
    .map((r) => `Note: ${r.source || sourceLabel(r.tool)} ${STATUS_PHRASE[r.status] || 'did not respond'}.`)
  return [...new Set(notes)].slice(0, max)
}

/* ------------------------------------------------------------------ */
/* Intent → tool plan                                                  */
/* ------------------------------------------------------------------ */

const INTENT_TOOLS: Record<CopilotIntent, string[]> = {
  asset_status: ['getAssets', 'searchAssets', 'getRiskAnalysis', 'getCryptoInventory'],
  migration_status: ['getMigrationStatus', 'getMigrationJobs', 'getSnapshots', 'explainFindingOwnership'],
  remediation: ['getPendingRemediation', 'generateRecommendations', 'explainFindingOwnership'],
  risk_analysis: ['getRiskScore', 'getRiskAnalysis', 'getBlastRadius', 'explainFindingOwnership'],
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
  executive_dashboard: ['getQuantumReadiness', 'generateExecutiveReport', 'getMigrationStatus', 'explainFindingOwnership'],
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
  'explainFindingOwnership',
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
  /** The topic specialist that owns this question (null → cross-module agents). */
  focus: FocusId | null
  filter: QueryFilter
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
  const filter = extractQueryFilter(question)
  // The topic specialist that owns the question. Its sources are pinned ahead
  // of every other tool so the planner's cap can never drop them.
  const focus = resolveFocus(question, detection.intents, objective.kind, filter)
  const pinned: string[] = [...focusTools(focus)]
  // Entity linking: any word that might name one of the tenant's records is
  // resolved against the REAL asset register ("status of orders-db").
  if (filter.mentions.length && !pinned.includes('getAssetRegister')) pinned.push('getAssetRegister')

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

  // Shared Responsibility ownership questions ("who owns this?", "why can't I
  // fix this?", "is this provider-managed?") always consult the ownership model.
  if (/who owns|ownership|shared responsibility|responsible party|provider[- ]managed|provider[- ]controlled|customer[- ]controlled|ecosystem[- ]dependent|whose responsib|why can'?t (i|we) (fix|remediate|migrate)|can (i|we|the customer) (fix|remediate|migrate)|out of my control|not my fault/i.test(question)) {
    if (!tools.includes('explainFindingOwnership')) tools.unshift('explainFindingOwnership')
  }

  // Argument extraction — simple, transparent filters carried to the tools.
  // Only real entity/attribute terms become a search filter; question words
  // ("show my most vulnerable assets") never do — asking a question is not a
  // name filter, and treating it as one produced contradictory "0 match"
  // answers over live risk data.
  const args: Record<string, unknown> = {
    query: filter.query,
    algorithms: filter.algorithms,
    algorithmLabels: filter.algorithmLabels,
    entity: filter.entity,
    wantsOwner: filter.wantsOwner,
    mentions: filter.mentions,
    question,
    withinDays: filter.withinDays,
  }
  if (filter.internetFacing) args.internetFacing = true
  if (filter.criticality) args.criticality = filter.criticality
  if (detection.followUp && memory.focusEntity) args.asset = memory.focusEntity

  // An algorithm named in the question is a CBOM lookup, not an asset-name
  // search: "which systems use RSA" must read the cryptographic inventory and
  // join back to the owning asset. Without this the question fell through to
  // searchAssets, which can only match an asset literally named "rsa" and so
  // always answered "no assets match that filter".
  if (filter.algorithms.length) {
    if (!tools.includes('findAssetsUsingAlgorithm')) tools.unshift('findAssetsUsingAlgorithm')
    for (const tool of ['getAlgorithms', 'getCryptoInventory']) {
      if (!tools.includes(tool)) tools.push(tool)
    }
    if (filter.wantsOwner && !tools.includes('explainFindingOwnership')) tools.push('explainFindingOwnership')
  }

  const modeModules = objective.investigate
    ? [...new Set([...modules, 'quantum_readiness', 'risk_analysis', 'exposure_graph', 'live_migration', 'pki', 'compliance'])]
    : modules

  // Investigations may consult up to 24 sources; focused lookups stay at 10.
  // Pinned (specialist) sources always come first.
  const cap = objective.investigate ? 24 : 10
  const ordered = [...pinned, ...tools.filter((t) => !pinned.includes(t))]

  return {
    intents: detection.intents,
    agents: [...agentSet],
    modules: focus ? [...new Set([...modeModules, ...focusTools(focus).map((t) => TOOL_REGISTRY[t]?.module).filter(Boolean) as string[]])] : modeModules,
    tools: ordered.slice(0, Math.max(cap, pinned.length)),
    args,
    followUp: detection.followUp,
    mode: objective.investigate ? 'investigate' : 'direct',
    objectiveKind: objective.kind,
    // A specialist states the objective precisely; the generic inference is
    // the fallback ("a focused status readout for a specific area" told the
    // user nothing about what was understood).
    objective: focus ? FOCUS_SPECS[focus].objective : objective.objective,
    expansion: expandQuestion(question, detection.intents),
    focus,
    filter,
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

    // An algorithm question is answered from the cryptographic inventory, which
    // is where algorithms live. This branch runs FIRST because it is the
    // specific answer the user asked for; the generic inventory summary below
    // is only a fallback.
    const algoUse = b.tool('findAssetsUsingAlgorithm')
    let algorithmAnswered = false
    if (algoUse && Array.isArray(algoUse.data.families) && (algoUse.data.families as unknown[]).length) {
      algorithmAnswered = true
      const labels = (algoUse.data.algorithmLabels as string[] | undefined)?.join(', ') || 'the requested algorithm'
      const rows = (algoUse.data.assets as Array<Record<string, unknown>> | undefined) || []
      const matched = num(algoUse.data.matchedAssets)
      const components = num(algoUse.data.components)
      const certificates = num(algoUse.data.certificates)
      const scoped = algoUse.data.assetsBeforeScope != null && num(algoUse.data.assetsBeforeScope) !== matched

      if (components + certificates === 0) {
        // Absence of a RECORD is not absence of the algorithm in reality — say
        // exactly what was searched so the user can judge coverage.
        findings.push(`No ${labels} usage is recorded in the cryptographic inventory. This reflects what discovery has measured, not a guarantee that ${labels} is absent — run a scan on anything not yet covered.`)
      } else {
        const where = matched === 1 ? '1 asset' : `${matched} assets`
        findings.push(
          `${labels}: ${components} cryptographic component(s)` +
          (certificates ? ` and ${certificates} certificate(s)` : '') +
          ` across ${where}` +
          (scoped ? ` (${num(algoUse.data.assetsBeforeScope)} before the requested scope filter)` : '') + '.',
        )
        if (num(algoUse.data.unattributed) > 0) {
          findings.push(`${num(algoUse.data.unattributed)} ${labels} record(s) are not linked to an asset, so they are counted in the component total but cannot be attributed to an owner.`)
        }
        // Name the assets and their owners — this IS the question when the user
        // asked "who owns them?".
        for (const row of rows.slice(0, 8)) {
          const owner = str(row.owner) || 'no owner recorded'
          const tags = [
            row.internetFacing === true ? 'internet-facing' : null,
            str(row.criticality) ? `${str(row.criticality)} criticality` : null,
            str(row.environment) || null,
          ].filter(Boolean).join(' · ')
          findings.push(`${str(row.name) || 'unnamed asset'} — owner: ${owner}${tags ? ` (${tags})` : ''}; ${num(row.components)} component(s)${num(row.certificates) ? `, ${num(row.certificates)} certificate(s)` : ''}.`)
        }
        if (rows.length > 8) findings.push(`…and ${rows.length - 8} more asset(s) in the CBOM Explorer.`)
        if (num(algoUse.data.ownersUnknown) > 0) {
          findings.push(`${num(algoUse.data.ownersUnknown)} of these assets have no service owner recorded — assign one so remediation has an accountable team.`)
          recommendations.push({
            title: 'Assign service owners to unowned assets',
            detail: `${num(algoUse.data.ownersUnknown)} asset(s) carrying ${labels} have no owner in the inventory, so no team is accountable for migrating them.`,
            priority: 'medium',
            standards: [STANDARDS.NIST_CSF],
            deepLink: modulePath('assets'),
          })
        }
      }
    }

    // Only report a match count when a REAL filter was applied. A question
    // with no extractable filter ("show my most vulnerable assets") is a
    // status/ranking request — answer from the inventory, never "0 match".
    // A name filter that matched nothing NEVER dead-ends the answer: it says
    // what was searched and then still reports the inventory, because "no
    // asset is named X" is not an answer to "which assets use X".
    if (!algorithmAnswered && search && search.data.filtered === true && /which|search|find|show|list/i.test(b.question)) {
      const matched = num(search.data.matched)
      if (matched > 0) {
        findings.push(`${matched} asset(s) match the requested filter.`)
      } else {
        const total = assets ? num(assets.data.total) : 0
        findings.push(
          `No asset name, type or environment matches "${str(search.data.query)}"` +
          (total > 0 ? `; the inventory holds ${total} asset(s) overall` : '') + '.',
        )
        if (total > 0) findings.push(`The inventory holds ${total} asset(s); ${num(assets && assets.data.internetFacing)} are internet-facing.`)
      }
    } else if (!algorithmAnswered && assets) {
      findings.push(`The inventory holds ${num(assets.data.total)} asset(s); ${num(assets.data.internetFacing)} are internet-facing.`)
    }
    if (cbom) {
      const vulnerable = num(cbom.data.vulnerableComponents ?? cbom.data.vulnerable)
      const total = num(cbom.data.cryptoComponents ?? cbom.data.total)
      // Assets and components are different units. Stating them side by side
      // without that sentence is what let "4 assets / 178 components" read as a
      // contradiction rather than as an inventory and its contents.
      if (total > 0) {
        const assetTotal = assets ? num(assets.data.total) : 0
        findings.push(
          `CBOM: ${total} cryptographic component(s), ${vulnerable} quantum-vulnerable` +
          (assetTotal > 0 ? ` — these are components discovered ACROSS the ${assetTotal} asset(s), not ${total} separate systems` : '') + '.',
        )
        // The CBOM counts cryptography. Scanner findings live in the same table
        // but are reported as findings, so state the difference rather than
        // letting the smaller component total look like missing data.
        const excluded = num(cbom.data.findingRowsExcluded)
        if (excluded > 0) {
          findings.push(`A further ${excluded} inventory row(s) are scanner findings rather than cryptographic components — they are counted in Risk Analysis and Vulnerabilities, not in the CBOM total.`)
        }
      }
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
      findings.push(`Migration workflow is ${num(wf.data.overallProgressPct)}% complete (stage: ${str(wf.data.currentStageLabel) || str(wf.data.currentStageId) || 'not started'}).`)
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
      // The distribution counts scanner FINDINGS (per-instance severity), not
      // assets — labeling it "assets" contradicted the inventory count.
      const dist = rec(analysis.data.distribution)
      if (num(dist.critical) + num(dist.high) > 0) {
        risk = { ...risk, level: maxRisk(risk.level, num(dist.critical) > 0 ? 'critical' : 'high'), drivers: [...risk.drivers, `${num(dist.critical)} critical / ${num(dist.high)} high-severity finding(s)`] }
        findings.push(`Scan findings by severity: ${num(dist.critical)} critical, ${num(dist.high)} high, ${num(dist.medium)} medium, ${num(dist.low)} low.`)
      }
      const top = arr(analysis.data.topRiskAssets) as Array<Record<string, unknown>>
      const topName = top.length ? str(top[0].asset) || str(top[0].name) || str(top[0].id) : ''
      if (topName) findings.push(`Highest-risk asset: ${topName}${num(top[0]?.riskScore) ? ` (risk score ${num(top[0].riskScore)}/100)` : ''}.`)
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
      // Escalate only from the MEASURED threat level (Critical/High); a
      // Guarded or Elevated tenant is not raised to "high" by the mere
      // presence of the HNDL module.
      const threat = str(hndl.data.threatLevel)
      if (hndl.data.hasData === true && /critical|high/i.test(threat)) {
        risk = { ...risk, level: maxRisk(risk.level, /critical/i.test(threat) ? 'critical' : 'high'), drivers: [...risk.drivers, `HNDL threat level ${threat} (${num(hndl.data.hndlScore)}/100)`] }
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

    if (hndl && hndl.data.hasData === true) {
      const fs = rec(hndl.data.forwardSecrecy)
      const threat = str(hndl.data.threatLevel)
      if (str(hndl.data.headline)) findings.push(str(hndl.data.headline))
      if (fs.hasEvidence === true) {
        findings.push(`Forward secrecy covers ${num(fs.coveragePct)}% of ${num(fs.componentsMeasured)} measured key exchange(s); ${num(fs.componentsWithoutPfs)} lack it.`)
      }
      // The level comes from the measured threat level — it was hardcoded to
      // "high" for every tenant, including ones the HNDL module rates Guarded.
      const level: CopilotRiskLevel = /critical/i.test(threat) ? 'critical' : /high/i.test(threat) ? 'high' : /elevated/i.test(threat) ? 'medium' : 'low'
      risk = { level, drivers: [`HNDL threat level ${threat || 'unrated'} (${num(hndl.data.hndlScore)}/100)`] }
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
  topRiskAssets: Array<{ name: string; riskScore: number; status: string }>
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
  // The tools now publish these under their real names (threatLevel/headline,
  // nextAction.label/path mapped from title/route, unmet criteria labelled
  // from `criterion`) — see copilot-tools for the drift each one fixed.
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
    // buildSnapshot emits the asset name under `asset` (not `name`) — reading
    // the wrong key silently erased every ranked asset name from answers.
    topRiskAssets: (arr(riskAnalysis?.topRiskAssets) as Array<Record<string, unknown>>)
      .map((a) => ({ name: str(a.asset) || str(a.name) || str(a.id), riskScore: num(a.riskScore), status: str(a.status) }))
      .filter((a) => Boolean(a.name))
      .slice(0, 6),
    blast: blast && Object.keys(blast).length ? {
      asset: str(blastData?.asset), totalAffected: num(blast.totalAffected), internetFacing: num(blast.internetFacing),
      direct: arr(blast.direct).length, trustChain: arr(blast.trustChain).length,
    } : null,
    exposure: exposureData ? {
      quantumVulnerable: num(exposureSummary.quantumVulnerable), trustRelationships: num(exposureSummary.trustRelationships),
      criticalTrust: num(exposureSummary.criticalTrustRelationships), thirdParty: num(exposureData.thirdParty ?? exposureSummary.thirdPartyDependencies),
      blockers: num(exposureData.blockers), certificateChains: num(exposureSummary.certificateChains), internetFacing: num(exposureSummary.internetFacingAssets),
    } : null,
    hndl: hndlData && hndlData.hasData === true ? { level: str(hndlData.threatLevel) || 'unrated', headline: str(hndlData.headline) } : null,
    migration: migData ? {
      progressPct: num(migData.overallProgressPct), stage: str(migData.currentStageLabel) || str(migData.currentStageId) || 'not started',
      certReadinessPct: num(migData.certificationReadinessPct), nextLabel: str(nextAction.label), nextPath: str(nextAction.path), nextDetail: str(nextAction.detail),
    } : null,
    jobs: jobsData ? { total: num(jobsData.total), active: arr(jobsData.active).length, failed: arr(jobsData.failed).length } : null,
    snapshots: snapData ? {
      total: num(rec(snapData.summary).total), restorable: num(rec(snapData.summary).restorable),
      autoRollbacks: num(rec(snapData.summary).automaticRollbacks), schemaReady: snapData.schemaReady === true,
    } : null,
    certs: certData ? {
      total: num(certData.total), quantumVulnerable: num(certData.quantumVulnerable),
      expired: num(certData.expired), expiringSoon: num(certData.expiringSoon), issuers: arr(certData.issuers).length,
    } : null,
    remediation: remData ? {
      pending: num(remData.pendingCount), criticalBlockers: num(remData.criticalBlockers),
      quickWins: num(remData.quickWins), readinessPct: num(remData.certificationReadinessPct),
    } : null,
    certification: certifData ? {
      eligible: certifData.eligible === true,
      unmet: (arr(certifData.requiredUnmet ?? certifData.unmet) as Array<Record<string, unknown>>).map((c) => str(c.label || c.id)).filter(Boolean).slice(0, 8),
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
    out.push({ severity: 'medium', text: `${intel.collectors.fleet - intel.collectors.online} collector agent(s) are offline — assets they cover may be missing from this analysis, creating migration blind spots.`, module: 'Agents Collector', deepLink: modulePath('collectors') })
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
  for (const asset of intel.topRiskAssets) {
    if (!priorities.some((p) => p.title === asset.name)) {
      priorities.push({ title: asset.name, why: `risk score ${asset.riskScore}/100${asset.status ? ` (${asset.status})` : ''} — ranked by the risk engine from live scan, CBOM and exposure evidence.` })
    }
    if (priorities.length >= 5) break
  }
  // Always anchor on the crypto-domain order even without per-asset detail.
  const strategy = buildMigrationStrategy(intel)

  const keyFindings: string[] = []
  if (intel.assetsTotal != null) keyFindings.push(`${intel.assetsTotal} asset(s) in inventory${intel.topRiskAssets.length ? `; ${intel.topRiskAssets.filter((a) => /vulnerable/i.test(a.status)).length || intel.topRiskAssets.length} ranked at elevated risk` : ''}.`)
  if (intel.riskDist.critical + intel.riskDist.high > 0) keyFindings.push(`Scan findings by severity: ${intel.riskDist.critical} critical, ${intel.riskDist.high} high, ${intel.riskDist.medium} medium, ${intel.riskDist.low} low.`)
  if (intel.internetFacing != null) keyFindings.push(`${intel.internetFacing} internet-facing asset(s) — first in line for Harvest-Now exposure.`)
  if (intel.hndl) keyFindings.push(`HNDL exposure: ${intel.hndl.level}.`)
  if (intel.vulnerableComponents != null) keyFindings.push(`${intel.vulnerableComponents} quantum-vulnerable component(s) to replace.`)

  const rankedLine = intel.topRiskAssets.length
    ? ` Ranked by live risk score: ${intel.topRiskAssets.slice(0, 5).map((a) => `${a.name} (${a.riskScore}/100${a.status ? ` · ${a.status}` : ''})`).join(', ')}.`
    : ''
  const topName = priorities[0]?.title
  const summary = topName
    ? `Your highest-priority asset is ${topName} — ${priorities[0].why}${rankedLine} Work down the risk-and-dependency order below: internet-facing TLS and the PKI beneath it, then internal services, SSH, VPN and clients. The order is driven by exposure (internet-facing + Harvest-Now), blast radius, and trust dependencies — not by asset name.`
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
    risk: { level: intel.riskLevel, score: intel.quantumRisk ?? undefined, drivers: [`${intel.riskDist.critical} critical / ${intel.riskDist.high} high-severity finding(s)`] },
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
      intel.riskDist.critical + intel.riskDist.high > 0 ? `${intel.riskDist.critical} critical / ${intel.riskDist.high} high-severity finding(s).` : '',
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

/** The most recent value Sophia reported for each figure key (tenant-scoped). */
export type PriorFigures = Record<string, { value: number; at: string }>

export interface ComposeInput {
  question: string
  plan: ExecutionPlan
  executions: ToolExecution[]
  lastAssessmentAt?: string | null
  priorFigures?: PriorFigures
}

/** A repeat question within this window says nothing new about change. */
const CHANGE_MIN_AGE_MS = 10 * 60 * 1000

/**
 * Longitudinal memory — what moved since Sophia last reported the same
 * measured figure to this tenant. Only measured values are compared; a figure
 * with no earlier reading produces nothing rather than an invented baseline.
 */
export function computeChanges(figures: CopilotFigure[], prior: PriorFigures | undefined, now = Date.now()): CopilotFigureChange[] {
  if (!prior) return []
  const out: CopilotFigureChange[] = []
  for (const f of figures) {
    const p = prior[f.key]
    if (!p || !Number.isFinite(p.value)) continue
    const age = now - new Date(p.at).getTime()
    if (!Number.isFinite(age) || age < CHANGE_MIN_AGE_MS) continue
    const delta = Math.round((f.value - p.value) * 10) / 10
    const direction: CopilotFigureChange['direction'] = delta === 0 ? 'unchanged'
      : f.better === 'neutral' ? 'changed'
        : (delta < 0) === (f.better === 'lower') ? 'improved' : 'worsened'
    out.push({ key: f.key, label: f.label, previous: p.value, current: f.value, delta, unit: f.unit, direction, since: p.at })
  }
  return out
}

/** Headline figures of a cross-module (non-specialist) answer. */
function intelFigures(intel: TenantIntelligence): CopilotFigure[] {
  const out: CopilotFigure[] = []
  if (intel.readiness != null) out.push({ key: 'readiness.score', label: 'Quantum readiness', value: intel.readiness, unit: '/100', better: 'higher', source: 'Quantum Readiness Assessment Engine™' })
  if (intel.quantumRisk != null) out.push({ key: 'risk.quantum', label: 'Quantum risk', value: intel.quantumRisk, unit: '/100', better: 'lower', source: 'Quantum Risk Analysis' })
  if (intel.vulnerableComponents != null) out.push({ key: 'cbom.vulnerable', label: 'Quantum-vulnerable components', value: intel.vulnerableComponents, better: 'lower', source: 'CBOM Explorer' })
  if (intel.remediation) out.push({ key: 'remediation.pending', label: 'Pending remediation actions', value: intel.remediation.pending, better: 'lower', source: 'Quantum Remediation Engine™' })
  if (intel.certification) out.push({ key: 'certification.readinessPct', label: 'Certification readiness', value: intel.certification.readinessPct, unit: '%', better: 'higher', source: 'Quantum Remediation Engine™' })
  return out
}

/*
 * Which deep-investigation narratives belong with which topic. A deep
 * composer reasons about ONE subject (migration order, certification gaps,
 * readiness…); attaching its narrative to a different topic is how "Summarize
 * my compliance posture" came back as a readiness briefing.
 */
const NARRATIVE_FOR_FOCUS: Partial<Record<FocusId, CopilotObjectiveKind[]>> = {
  certification_gap: ['gap_analysis'],
  certification_next_level: ['gap_analysis'],
  critical_blockers: ['gap_analysis'],
  readiness: ['executive', 'explain'],
  readiness_blockers: ['gap_analysis', 'explain'],
  hndl_exposure: ['explain'],
  hndl_reduction: ['guidance'],
  critical_findings: ['explain'],
  migration_priority: ['prioritization', 'guidance'],
  most_vulnerable_assets: ['prioritization', 'explain'],
  remediation_queue: ['prioritization', 'guidance'],
}

/** Topics whose answers benefit from the dependency-safe migration order and rollback plan. */
const MIGRATION_CONTEXT_FOCUS = new Set<FocusId>(['migration_priority', 'remediation_queue', 'hndl_reduction', 'migration_effort', 'most_vulnerable_assets'])

function focusConfidence(fa: FocusAnswer, focus: FocusId, runs: CopilotToolRun[], lastAssessmentAt?: string | null): number {
  if (fa.unavailable) return 25
  const own = focusTools(focus)
  const okOwn = own.filter((t) => runs.some((r) => r.tool === t && r.status === 'ok')).length
  let score = 55 + Math.round((okOwn / Math.max(1, own.length)) * 33)
  if (lastAssessmentAt) {
    const ageH = (Date.now() - new Date(lastAssessmentAt).getTime()) / 36e5
    if (Number.isFinite(ageH) && ageH <= 24) score += 8
    else if (Number.isFinite(ageH) && ageH > 72) score -= 12
  }
  score -= runs.filter((r) => r.status === 'error').length * 3
  if (fa.noData) score = Math.min(score, 60)
  return clamp(score, 5, 96)
}

/**
 * Plain-language data-freshness statement. Sophia reports the age of the
 * evidence she answered from, and flags anything older than 72 hours as no
 * longer a statement about current production posture.
 */
function describeFreshness(lastAssessmentAt?: string | null): { sentence: string; stale: boolean; ageHours: number | null } {
  if (!lastAssessmentAt) {
    return { sentence: 'Data freshness: no assessment timestamp is recorded, so I cannot tell you how current this evidence is.', stale: false, ageHours: null }
  }
  const ms = new Date(lastAssessmentAt).getTime()
  if (!Number.isFinite(ms)) {
    return { sentence: 'Data freshness: the assessment timestamp is unreadable, so I cannot tell you how current this evidence is.', stale: false, ageHours: null }
  }
  const ageHours = Math.max(0, (Date.now() - ms) / 36e5)
  const human = ageHours < 1 ? 'less than an hour ago'
    : ageHours < 48 ? `${Math.round(ageHours)} hour(s) ago`
    : `${Math.round(ageHours / 24)} day(s) ago`
  const stale = ageHours > 72
  return {
    sentence: stale
      ? `Data freshness: this answer is based on the last assessment, generated ${human}. That is old enough that it may no longer describe current production posture.`
      : `Data freshness: based on the last assessment, generated ${human}.`,
    stale,
    ageHours,
  }
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

  /* ---- Topic specialist: the module that owns the topic answers it ---- */
  const register = toolData.get('getAssetRegister')
  const assetScope = register ? (arr(register.data.matched) as AssetView[]) : []
  const focus = finalizeFocus(plan.focus, assetScope)
  if (focus) {
    const statusOf = (name: string): SourceStatus => (toolRuns.find((r) => r.tool === name)?.status as SourceStatus | undefined) || 'missing'
    const fa = answerFocus(focus, {
      question: input.question,
      filter: plan.filter,
      tool: (name) => toolData.get(name) || null,
      status: statusOf,
      assetScope,
    })
    const freshness = describeFreshness(input.lastAssessmentAt)

    // Investigations still correlate the wider platform — but only the
    // sections that belong to this topic are attached.
    const intel = plan.mode === 'investigate' ? extractIntelligence(toolData) : null
    const deep = intel && intel.hasData && !fa.unavailable ? synthesizeDeep(plan.objectiveKind, intel, fa.objective) : null
    const narrative = deep && (NARRATIVE_FOR_FOCUS[focus] || []).includes(plan.objectiveKind) ? deep : null
    const migrationContext = MIGRATION_CONTEXT_FOCUS.has(focus)

    // Evidence from the specialist's own sources leads.
    const own = new Set(focusTools(focus))
    const ownEvidence: CopilotEvidence[] = []
    const otherEvidence: CopilotEvidence[] = []
    for (const [name, result] of toolData) (own.has(name) ? ownEvidence : otherEvidence).push(...result.evidence)

    const nextActions: CopilotNextAction[] = []
    for (const a of [...preparedActions, ...fa.nextActions, ...(narrative?.nextActions || [])]) {
      if (!nextActions.some((x) => x.path === a.path)) nextActions.push(a)
    }
    const recommendations = dedupeRecs([...fa.recommendations, ...(narrative?.recommendations || [])])
    const figures = fa.figures
    const grounding: CopilotAnswerGrounding = fa.unavailable ? 'none' : 'focused'
    const sources = [...new Set([...own].map((t) => sourceLabel(t)))]

    return {
      id: nextId(),
      intents: plan.intents,
      agents: plan.agents,
      summary: fa.headline,
      reasoning: [
        `Routed to the ${focusLabel(focus)} specialist${assetScope.length ? `, scoped to ${assetScope.map((a) => a.name).join(', ')}` : ''}.`,
        `Answered from the topic's system of record: ${sources.join(', ')}.`,
        freshness.sentence,
        ...(deep ? [`Correlated ${okRuns} live source(s) across the platform for dependencies, rollback and proactive findings.`] : []),
        ...sourceNotes(toolRuns, ['error', 'denied'], 3),
      ],
      evidence: [...ownEvidence, ...otherEvidence].slice(0, 14),
      recommendations,
      risk: fa.risk || agentRisk,
      nextActions: nextActions.slice(0, 6),
      relatedPages,
      standards: [...new Set([...recommendations.flatMap((r) => r.standards), ...(narrative?.complianceAlignment?.map((s) => s.split(' — ')[0]) || [])])].slice(0, 8),
      confidence: {
        score: focusConfidence(fa, focus, toolRuns, input.lastAssessmentAt),
        basis: `${focusLabel(focus)} specialist · ${confidenceBasis}`,
      },
      toolRuns,
      followUps,
      generatedAt: new Date().toISOString(),
      mode: plan.mode,
      objectiveKind: plan.objectiveKind,
      objective: fa.objective,
      keyFindings: fa.keyFindings.slice(0, 10),
      focus,
      focusLabel: focusLabel(focus),
      grounding,
      entities: fa.entities,
      figures,
      changes: computeChanges(figures, input.priorFigures),
      rootCause: fa.rootCause ?? narrative?.rootCause,
      businessImpact: narrative?.businessImpact,
      technicalAnalysis: narrative?.technicalAnalysis,
      migrationStrategy: migrationContext && deep ? deep.migrationStrategy : undefined,
      dependencies: migrationContext || focus === 'blast_radius' ? deep?.dependencies : undefined,
      potentialBreakages: migrationContext ? deep?.potentialBreakages : undefined,
      rollbackStrategy: migrationContext ? deep?.rollbackStrategy : undefined,
      riskOutlook: narrative?.riskOutlook,
      proactiveFindings: intel && !fa.unavailable ? detectProactiveFindings(intel) : undefined,
    }
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
        grounding: 'none',
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
      ...sourceNotes(toolRuns, ['error'], 2),
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
      grounding: 'correlated',
      figures: intelFigures(intel),
      changes: computeChanges(intelFigures(intel), input.priorFigures),
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
  let grounding: CopilotAnswerGrounding
  if (findings.length) {
    // The summary is the headline; the FULL findings list is carried on
    // keyFindings so nothing is silently dropped. Truncating to three here was
    // discarding the per-asset ownership lines that answered questions like
    // "…and who owns them?" — the user saw one asset and never learned the
    // others existed.
    summary = findings.slice(0, 3).join(' ')
    grounding = 'correlated'
  } else if (emptyRuns === attempted && attempted > 0) {
    summary = 'No live data exists yet for this question. Connect a scanner, collector or cloud connector and run a discovery scan — I only report evidence, never estimates.'
    grounding = 'none'
  } else if (evidence.length) {
    // Never dead-end while evidence is sitting right there. "I could not
    // derive an evidence-backed answer" was printed directly above an
    // evidence card reading "6 pending remediation actions". With no
    // specialist for the exact question, restate what each source returned.
    summary = `I don't have a dedicated specialist for that exact question, so here is what each source I consulted reports: ${evidence.slice(0, 4).map((e) => `${e.module} — ${e.label}: ${e.value}${e.detail ? ` (${e.detail})` : ''}`).join('; ')}. Ask about one of these areas for a ranked, detailed answer.`
    grounding = 'digest'
  } else {
    summary = 'None of the sources I consulted returned evidence for this question, so I have nothing grounded to tell you — I don\'t guess. Try one of the suggested questions, or ask about a specific area such as remediation, certificates, assets or compliance.'
    grounding = 'none'
  }

  /* Data freshness must be STATED, not merely folded into a confidence score.
     An answer built on a three-week-old assessment is not a statement about
     production today, and the user has to be told which one they are reading. */
  const freshness = describeFreshness(input.lastAssessmentAt)
  const reasoning = [
    `Detected intent(s): ${plan.intents.join(', ')}${plan.followUp ? ' (follow-up to the previous question)' : ''}.`,
    `Consulted ${attempted} data source(s) across ${plan.modules.length} module(s): ${plan.modules.map((m) => moduleLabel(m)).join(', ') || '—'}.`,
    freshness.sentence,
    ...sourceNotes(toolRuns, ['empty', 'error', 'denied'], 3),
  ]
  if (freshness.stale) {
    agentRecommendations.push({
      title: 'Re-scan before treating this as current posture',
      detail: `${freshness.sentence} Run a discovery scan so the inventory, CBOM and readiness engines reflect today's estate.`,
      priority: 'medium',
      standards: [STANDARDS.NIST_CSF],
      deepLink: modulePath('scanner'),
    })
  }

  const standards = [...new Set(agentRecommendations.flatMap((r) => r.standards))].slice(0, 8)

  return {
    id: nextId(),
    intents: plan.intents,
    agents: plan.agents,
    summary,
    reasoning,
    // Everything the agents established, in order — the summary shows the first
    // three, this carries the rest (per-asset rows, owners, caveats).
    keyFindings: findings.slice(0, 24),
    evidence: evidence.slice(0, 12),
    recommendations: dedupeRecs(agentRecommendations),
    risk: agentRisk,
    nextActions: nextActions.slice(0, 5),
    relatedPages,
    standards,
    // Confidence is confidence in THIS ANSWER, not in the tools having run:
    // a dead-end answer was shown at 88% because every source had responded.
    confidence: {
      score: grounding === 'none' ? Math.min(confidenceScore, 30) : grounding === 'digest' ? Math.min(confidenceScore, 55) : confidenceScore,
      basis: `${grounding === 'digest' ? 'Source digest (no topic specialist) · ' : grounding === 'none' ? 'No grounded evidence · ' : ''}${confidenceBasis}`,
    },
    toolRuns,
    followUps,
    generatedAt: new Date().toISOString(),
    mode: 'direct',
    objectiveKind: plan.objectiveKind,
    objective: plan.objective,
    grounding,
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
  /** No specialist or agent could ground an answer — logged so coverage can grow. */
  knowledgeGap: boolean
}

export interface QueryOptions {
  /** Figures Sophia previously reported to this tenant, for change tracking. */
  priorFigures?: PriorFigures
}

export async function runCopilotQuery(
  ctx: ToolContext,
  rawQuestion: string,
  memory: CopilotMemoryState,
  emit: (event: CopilotStreamEvent) => void,
  deps: CopilotBuilders = liveBuilders,
  options: QueryOptions = {},
): Promise<QueryOutcome> {
  emit({ type: 'stage', stage: 'thinking', label: 'Sophia is thinking…' })

  const sanitized = sanitizePrompt(rawQuestion)
  if (sanitized.blocked) {
    const answer = blockedAnswer(sanitized.reasons)
    emit({ type: 'answer', answer })
    emit({ type: 'done' })
    return { answer, memory: { ...memory, turns: memory.turns + 1 }, knowledgeGap: false }
  }

  const plan = planQuery(sanitized.text, memory)
  emit({ type: 'stage', stage: 'intent', label: `Understood your objective: ${plan.objective}` })
  if (plan.focus) {
    emit({ type: 'stage', stage: 'planning', label: `Routing to the ${focusLabel(plan.focus)} specialist — reading ${[...new Set(focusTools(plan.focus).map(sourceLabel))].join(', ')}…` })
  }
  if (plan.mode === 'investigate') {
    emit({ type: 'stage', stage: 'expanding', label: `Expanding the question — also examining: ${plan.expansion.slice(0, 4).join(', ')}` })
    emit({ type: 'stage', stage: 'investigating', label: `Running a full cross-module investigation (${plan.tools.length} sources across ${plan.modules.length} modules)…` })
  } else {
    emit({ type: 'stage', stage: 'planning', label: `Searching ${plan.modules.map((m) => moduleLabel(m)).join(', ') || 'the platform'}…` })
  }

  const executions: ToolExecution[] = []
  await Promise.all(plan.tools.map(async (tool) => {
    emit({ type: 'stage', stage: 'reading', label: `Searching ${sourceLabel(tool)}…` })
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

  /* Freshness must describe the evidence THIS answer was built from. Reading it
     only from getQuantumReadiness meant any question that did not consult the
     QR snapshot — an asset or CBOM question, for example — reported "no
     assessment timestamp is recorded" even though every source it DID use
     carried an observation time. Prefer the QR assessment time, then fall back
     to the newest observedAt across the evidence actually gathered. */
  /* The age stated is the age of the PRIMARY evidence — the specialist's own
     sources, or the planner's first source. Taking the newest timestamp across
     every source let one freshly computed side-source (a snapshot rollup) make
     21-day-old primary evidence read as current. */
  const newestObserved = (only?: string[]): number => {
    let newest = 0
    for (const execution of executions) {
      if (only && !only.includes(execution.run.tool)) continue
      // A failed or denied tool has result === null — it contributed no
      // evidence and must not crash the freshness scan.
      for (const item of execution.result?.evidence || []) {
        const ms = item.observedAt ? new Date(item.observedAt).getTime() : 0
        if (Number.isFinite(ms) && ms > newest) newest = ms
      }
    }
    return newest
  }
  let lastAssessmentAt: string | null = null
  const primary = plan.focus ? focusTools(plan.focus) : plan.tools.slice(0, 1)
  const primaryAt = newestObserved(primary)
  if (primaryAt > 0) lastAssessmentAt = new Date(primaryAt).toISOString()
  if (!lastAssessmentAt) {
    const readiness = executions.find((e) => e.run.tool === 'getQuantumReadiness')?.result
    if (readiness) lastAssessmentAt = str(rec(readiness.data).lastAssessmentAt) || null
  }
  if (!lastAssessmentAt) {
    const newest = newestObserved()
    if (newest > 0) lastAssessmentAt = new Date(newest).toISOString()
  }

  emit({ type: 'stage', stage: 'generating', label: plan.mode === 'investigate' ? 'Writing the consultant-grade analysis…' : 'Generating the evidence-based answer…' })
  const answer = composeAnswer({ question: sanitized.text, plan, executions, lastAssessmentAt, priorFigures: options.priorFigures })
  emit({ type: 'answer', answer })
  emit({ type: 'done' })

  // Update conversation memory for follow-ups.
  const focusAssets: string[] = []
  for (const item of answer.evidence) {
    if (/asset/i.test(item.label) && item.detail) focusAssets.push(item.detail.slice(0, 60))
  }
  // A named asset becomes the follow-up focus ("…and what depends on it?").
  const registerExec = executions.find((e) => e.run.tool === 'getAssetRegister')?.result
  const linked = registerExec ? (arr(registerExec.data.matched) as AssetView[]) : []
  const blastExec = executions.find((e) => e.run.tool === 'getBlastRadius')?.result
  const focusEntity = linked[0]?.name || (blastExec ? str(rec(blastExec.data).asset) : memory.focusEntity)

  return {
    knowledgeGap: answer.grounding === 'digest' || answer.grounding === 'none',
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
      if (num(dist.critical) > 0) push('critical', `${num(dist.critical)} critical finding(s)`, 'These scan findings combine quantum-vulnerable crypto with high exposure — review the affected assets first.', 'risk_analysis', `Finding severity distribution: ${num(dist.critical)} critical`)
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
