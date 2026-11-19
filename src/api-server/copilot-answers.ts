// Sophia — topic specialists ("focus answerers").
//
// A question has a TOPIC ("what is pending remediation?" is about the
// remediation queue) and a SHAPE ("which …" wants the records, "how many …"
// wants a count, "why …" wants the reasoning). The generic agents answered a
// topic from whichever tools happened to run and never listed records, so
// "What is pending remediation?" dead-ended with "I could not derive an
// evidence-backed answer" beside an evidence card reading "6 pending
// remediation actions", and "Which endpoints lack forward secrecy?" was
// answered with a pointer to another page.
//
// Each specialist owns ONE topic: it names the tools that hold the topic's
// canonical data, reads them through their typed contracts, and returns a
// direct answer, the named records, the measured figures and the next step.
// PURE — no Supabase / Express — so tools/sophia-question-audit.ts runs the
// exact code the gateway runs.

import { algorithmFamily, modulePath, STANDARDS, type QueryFilter } from './copilot-knowledge'
import type { AssetView, CertificateView, PendingActionRow, ToolResult } from './copilot-tools'
import type {
  CopilotEntityRow,
  CopilotEntityTable,
  CopilotFigure,
  CopilotIntent,
  CopilotNextAction,
  CopilotObjectiveKind,
  CopilotRecommendation,
  CopilotRisk,
  CopilotRiskLevel,
  CopilotTone,
} from '@/types/copilot'

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function str(v: unknown): string { return typeof v === 'string' ? v : v == null ? '' : String(v) }
function num(v: unknown): number { const n = Number(v); return Number.isFinite(n) ? n : 0 }
function rec(v: unknown): Record<string, unknown> { return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {} }
function arr<T = Record<string, unknown>>(v: unknown): T[] { return Array.isArray(v) ? (v as T[]) : [] }

/** "1 action is" / "6 actions are" — counts always carry their unit. */
function count(n: number, singular: string, plural = `${singular}s`): string {
  return `${n} ${n === 1 ? singular : plural}`
}

function isAre(n: number): string { return n === 1 ? 'is' : 'are' }

/** "a", "a and b", "a, b and c", "a, b, c and 2 more". */
function list(items: string[], max = 3): string {
  const head = items.slice(0, max)
  if (!head.length) return ''
  const rest = items.length - head.length
  if (rest > 0) return `${head.join(', ')} and ${rest} more`
  if (head.length === 1) return head[0]
  return `${head.slice(0, -1).join(', ')} and ${head[head.length - 1]}`
}

/** Engine text often ends in a period; drop it before embedding mid-sentence. */
function clause(text: string): string {
  return String(text || '').trim().replace(/[.\s]+$/, '')
}

function weeks(n: number): string {
  const rounded = Math.round(n * 10) / 10
  return `${rounded} week${rounded === 1 ? '' : 's'}`
}

function ago(iso: string | null | undefined): string {
  const ms = iso ? new Date(iso).getTime() : NaN
  if (!Number.isFinite(ms)) return 'at an unrecorded time'
  const hours = Math.max(0, (Date.now() - ms) / 36e5)
  if (hours < 1) return 'less than an hour ago'
  if (hours < 48) return `${Math.round(hours)} hour(s) ago`
  return `${Math.round(hours / 24)} day(s) ago`
}

function dateOnly(iso: string | null | undefined): string {
  const ms = iso ? new Date(iso).getTime() : NaN
  return Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 10) : '—'
}

const PRIORITY_TONE: Record<string, CopilotTone> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' }

function riskFromLevel(level: string): CopilotRiskLevel {
  const l = level.toLowerCase()
  if (/critical|severe/.test(l)) return 'critical'
  if (/high|elevated/.test(l)) return 'high'
  if (/medium|moderate|guarded/.test(l)) return 'medium'
  if (/low|minimal/.test(l)) return 'low'
  return 'info'
}

function riskFromScore(score: number): CopilotRiskLevel {
  if (score >= 75) return 'critical'
  if (score >= 55) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

/* ------------------------------------------------------------------ */
/* Focus catalog                                                       */
/* ------------------------------------------------------------------ */

export type FocusId =
  | 'remediation_queue'
  | 'remediation_gain'
  | 'critical_blockers'
  | 'migration_priority'
  | 'certification_gap'
  | 'certification_next_level'
  | 'readiness'
  | 'readiness_blockers'
  | 'hndl_exposure'
  | 'forward_secrecy'
  | 'future_decryptable'
  | 'hndl_reduction'
  | 'compliance_posture'
  | 'cnsa'
  | 'nist_alignment'
  | 'certificates'
  | 'certificate_issuers'
  | 'algorithms'
  | 'asset_dossier'
  | 'assets_list'
  | 'most_vulnerable_assets'
  | 'blast_radius'
  | 'dependencies'
  | 'third_parties'
  | 'critical_findings'
  | 'scan_summary'
  | 'migration_jobs'
  | 'migration_blockers'
  | 'migration_effort'
  | 'snapshots'
  | 'collectors'
  | 'runtime_events'

interface FocusSpec {
  label: string
  /** Tools holding the topic's canonical data — always planned for this focus. */
  tools: string[]
  /** Plain statement of what the user wants, shown as "What you're asking". */
  objective: string
}

export const FOCUS_SPECS: Record<FocusId, FocusSpec> = {
  remediation_queue: { label: 'Remediation queue', tools: ['getPendingRemediation'], objective: 'You want to know which remediation actions are still open, in what order to work them, and what each one fixes.' },
  remediation_gain: { label: 'Highest-gain remediation', tools: ['getPendingRemediation'], objective: 'You want the remediation actions that raise your certification readiness the most for the least effort.' },
  critical_blockers: { label: 'Critical blockers', tools: ['getPendingRemediation', 'getCertificationEligibility'], objective: 'You want the critical items blocking progress — the highest-priority open actions and any unmet certification criteria.' },
  migration_priority: { label: 'Migration priority', tools: ['getPendingRemediation', 'getAssetRegister'], objective: 'You want to know what to migrate first and why — a ranked order grounded in your live evidence.' },
  certification_gap: { label: 'Certification gap analysis', tools: ['getCertificationEligibility', 'getCertificationStatus'], objective: 'You want to know whether you can be certified and, if not, exactly which criteria are unmet and how to close them.' },
  certification_next_level: { label: 'Next certification level', tools: ['getCertificationEligibility', 'getCertificationStatus'], objective: 'You want the path from your current certification standing to the next level.' },
  readiness: { label: 'Quantum readiness', tools: ['getQuantumReadiness', 'getCertificationEligibility'], objective: 'You want a verdict on your quantum readiness — the score, what drives it and what moves it.' },
  readiness_blockers: { label: 'Readiness blockers', tools: ['getQuantumReadiness', 'getPendingRemediation'], objective: 'You want to know what is holding your readiness score down and which actions raise it.' },
  hndl_exposure: { label: 'Harvest-Now-Decrypt-Later exposure', tools: ['getHarvestNowExposure'], objective: 'You want your Harvest-Now-Decrypt-Later exposure — how much captured traffic becomes readable once a quantum computer exists.' },
  forward_secrecy: { label: 'Forward secrecy gaps', tools: ['getHarvestNowExposure'], objective: 'You want the endpoints whose key exchange lacks forward secrecy.' },
  future_decryptable: { label: 'Future-decryptable data', tools: ['getHarvestNowExposure'], objective: 'You want to know how much of your data would be decryptable once a cryptographically relevant quantum computer exists.' },
  hndl_reduction: { label: 'HNDL reduction', tools: ['getHarvestNowExposure', 'getPendingRemediation'], objective: 'You want the actions that reduce your Harvest-Now-Decrypt-Later exposure fastest.' },
  compliance_posture: { label: 'Compliance posture', tools: ['getComplianceStatus', 'getCNSACompliance', 'getNISTScore', 'getCertificationStatus'], objective: 'You want a summary of your compliance posture across the frameworks the platform tracks.' },
  cnsa: { label: 'CNSA 2.0 alignment', tools: ['getCNSACompliance'], objective: 'You want to know how close you are to the NSA CNSA 2.0 algorithm suite.' },
  nist_alignment: { label: 'NIST PQC alignment', tools: ['getNISTScore', 'getQuantumReadiness'], objective: 'You want your alignment with the NIST post-quantum standards (FIPS 203/204/205).' },
  certificates: { label: 'Certificate inventory', tools: ['getCertificates'], objective: 'You want the specific certificates that are expired, expiring, weak or quantum-vulnerable.' },
  certificate_issuers: { label: 'Certificate issuers', tools: ['getCertificates'], objective: 'You want the certificate authorities your trust chains depend on.' },
  algorithms: { label: 'Algorithm inventory', tools: ['getAlgorithms', 'getCBOM'], objective: 'You want the cryptographic algorithms discovered in your estate and which of them are quantum-vulnerable.' },
  asset_dossier: { label: 'Asset status', tools: ['getAssetRegister', 'getPendingRemediation', 'getCertificates'], objective: 'You want the real, current status of a specific asset.' },
  assets_list: { label: 'Asset register', tools: ['getAssetRegister'], objective: 'You want the specific assets that match your criteria, with their current status.' },
  most_vulnerable_assets: { label: 'Most vulnerable assets', tools: ['getAssetRegister'], objective: 'You want your most vulnerable assets identified and ranked, with why each ranks where it does.' },
  blast_radius: { label: 'Blast radius', tools: ['getBlastRadius', 'getAssetRegister'], objective: 'You want to know what depends on an asset — what breaks or is exposed if it is compromised or changed.' },
  dependencies: { label: 'Dependencies & trust relationships', tools: ['getExposureGraph', 'getTrustChains', 'getDependencies', 'getBlastRadius'], objective: 'You want the dependency and trust relationships across your estate.' },
  third_parties: { label: 'Third-party dependencies', tools: ['getDependencies'], objective: 'You want the third-party and vendor dependencies in your trust paths and their PQC readiness.' },
  critical_findings: { label: 'Critical findings', tools: ['getRiskAnalysis'], objective: 'You want the critical findings, what they are and why each one matters.' },
  scan_summary: { label: 'Latest scan', tools: ['getLatestScans', 'getRiskAnalysis'], objective: 'You want a summary of what your latest scans found.' },
  migration_jobs: { label: 'Migration jobs', tools: ['getMigrationJobs', 'getMigrationStatus'], objective: 'You want the migrations that are running, queued or failed.' },
  migration_blockers: { label: 'Migration blockers', tools: ['getExposureGraph', 'getPendingRemediation', 'getMigrationJobs', 'explainFindingOwnership'], objective: 'You want what is blocking your migration — dependencies, systems that cannot support PQC, and failed jobs.' },
  migration_effort: { label: 'Migration effort', tools: ['getPendingRemediation', 'getMigrationStatus'], objective: 'You want an estimate of the effort and time the remaining migration work needs.' },
  snapshots: { label: 'Snapshots & rollback', tools: ['getSnapshots'], objective: 'You want to know whether you have integrity-verified snapshots to roll back to.' },
  collectors: { label: 'Collector fleet', tools: ['getCollectorsStatus'], objective: 'You want the health of your collector agents — which are online and which are offline.' },
  runtime_events: { label: 'Runtime crypto events', tools: ['getLiveTelemetry'], objective: 'You want the recent runtime cryptographic events your collectors observed.' },
}

/**
 * Which topic is the question about? Ordered most-specific first — "which
 * endpoints lack forward secrecy" must reach forward_secrecy before the generic
 * asset list, and "what is blocking a higher readiness level" must reach
 * readiness_blockers before certification. Returns null when no specialist
 * owns the topic (the engine's cross-module agents answer those).
 */
export function resolveFocus(question: string, intents: CopilotIntent[], objectiveKind: CopilotObjectiveKind, filter: QueryFilter): FocusId | null {
  const q = String(question || '').toLowerCase()
  const has = (re: RegExp) => re.test(q)
  const certCtx = has(/certif|quantum trust/) || intents.includes('certification')
  const remediationCtx = has(/remediat|action|fix|playbook/) || intents.includes('remediation')
  const migrationCtx = has(/migrat|cutover|rollout/) || intents.includes('migration_status')

  // An algorithm-USAGE question ("which systems use RSA?") is answered by the
  // CBOM join (findAssetsUsingAlgorithm). But naming a standard is not asking
  // where an algorithm runs: "Show my NIST PQC alignment" matched the "PQC"
  // umbrella and was sent to the usage path. Topic vocabulary wins.
  const topicWords = /\bnist\b|\bcnsa\b|complian|readiness|\bready\b|certif|harvest|\bhndl\b|forward[- ]secrecy|adoption|alignment/
  if (filter.algorithms.length && filter.entity !== 'certificate' && !has(topicWords)) return null

  // Harvest-Now — specific sub-questions first.
  if (has(/forward[- ]secrecy|\bpfs\b|ephemeral key/)) return 'forward_secrecy'
  if (has(/future[- ]?decrypt|decryptable|how much (of )?(my )?data|\bterabytes?\b|\btb\b/)) return 'future_decryptable'
  if (has(/(reduce|lower|decrease|shrink|mitigate|close|cut|fix)\w*.{0,40}(hndl|harvest)|(hndl|harvest)[^?]{0,40}(fastest|quickest|reduce)/)) return 'hndl_reduction'
  if (has(/harvest[- ]now|\bhndl\b|decrypt[- ]later/)) return 'hndl_exposure'

  // Certification.
  if (certCtx && has(/next (certification )?level|higher (certification )?level|reach (the )?(next|higher|gold|silver|platinum|diamond)|level up|upgrade (my )?certif/)) return 'certification_next_level'
  if (certCtx && has(/\bwhy\b|block|gap|eligib|not (been )?(achiev|certif|issued)|unmet|missing|stopping|preventing|am i certif|can i (be )?certif/)) return 'certification_gap'

  // Readiness.
  if (has(/(blocking|holding (me |us )?back|stopping|preventing|keeping|limiting|capping).{0,40}(readiness|ready|score)|higher readiness|raise (my )?readiness level/)) return 'readiness_blockers'
  if (has(/(raises?|improves?|boosts?|increases?).{0,40}(readiness|score).{0,30}(fast|quick|most)|biggest (certification )?gain|most (certification )?gain|highest[- ]gain|quick[- ]wins?/)) return 'remediation_gain'
  if (has(/quantum[- ]read(y|iness)|\bam i (quantum |pqc )?ready\b|readiness (score|level)|\bpqc[- ]read(y|iness)\b|how ready/)) return 'readiness'

  // Compliance.
  if (has(/\bcnsa\b/)) return 'cnsa'
  if (has(/\bnist\b|fips[- ]?20[345]/) && !has(/complian/)) return 'nist_alignment'
  if (has(/complian|regulat|\bframeworks?\b|audit[- ]read|iso[- ]?27001|pci[- ]?dss|hipaa|soc ?2/)) return 'compliance_posture'

  // Certificates / PKI.
  if (has(/\bissuers?\b|issuing|certificate authorit|\bcas\b|trust anchors?|root ca/)) return 'certificate_issuers'
  if (filter.entity === 'certificate' || has(/\bcertificates?\b|\bcerts?\b|\bx\.?509\b/)) return 'certificates'

  // Remediation.
  if (has(/critical blockers?|critical (remediation )?actions?|show (the |my )?blockers/) && !migrationCtx) return 'critical_blockers'
  if (has(/(migrate|fix|remediate|upgrade|start|tackle|work on)\w*.{0,25}\b(first|next)\b|what should (i|we) (migrate|do|fix|remediate)|where (do|should) (i|we) (start|begin)|\bprioriti[sz]/)) return 'migration_priority'
  if (remediationCtx && !migrationCtx) return 'remediation_queue'

  // Migration operations.
  if (has(/snapshots?|roll ?back|restore point|revert/)) return 'snapshots'
  if (migrationCtx && has(/blockers?|blocking|blocked|stopping|prevent|can'?t (be )?migrat/)) return 'migration_blockers'
  if (has(/\beffort\b|how long|\bestimate|how many weeks|\btimeline\b/) && (migrationCtx || remediationCtx || has(/estimate/))) return 'migration_effort'
  if (has(/(active|failed|running|queued|stuck) migrations?|migration jobs?|\bjobs?\b.{0,15}(fail|run|queue)/)) return 'migration_jobs'

  // Operations / telemetry.
  if (has(/\bcollectors?\b|\bagents?\b|heartbeats?|\boffline\b|\bfleet\b/)) return 'collectors'
  if (has(/runtime|legacy[- ]crypto events?|telemetry events?|recent events/)) return 'runtime_events'

  // Findings.
  if (has(/(critical|high)[- ](severity )?findings?|findings?[^?]{0,25}critical|critical (issues|vulnerabilit|exposures)/)) return 'critical_findings'
  if (has(/(latest|last|recent|most recent) scans?|scan (results|findings|summary)|summar\w*[^?]{0,25}scan/)) return 'scan_summary'

  // Graph / dependencies.
  if (has(/blast radius|what (breaks|would break|depends on)|dependents? of/)) return 'blast_radius'
  if (has(/third[- ]part|\bvendors?\b|\bsuppliers?\b|supply chain/)) return 'third_parties'
  if (has(/dependenc|relationships?|trust chains?|trust paths?/)) return 'dependencies'

  // Algorithms (no family named — that case returned above).
  if (has(/\balgorithms?\b|cipher suites?|\bciphers?\b/)) return 'algorithms'

  // Assets.
  if (has(/\b(most|top|highest|worst|biggest)\b.{0,40}\b(vulnerable|risk|risky|critical|exposed|at risk)|riskiest|weakest|carry the most|drives? the (critical |most )?risk/)) return 'most_vulnerable_assets'
  if (has(/\b(which|list|show|what)\b.{0,40}\b(assets?|systems?|servers?|hosts?|endpoints?|applications?|services?|domains?)\b/) || filter.internetFacing) return 'assets_list'

  void objectiveKind
  return null
}

/* ------------------------------------------------------------------ */
/* Specialist contract                                                 */
/* ------------------------------------------------------------------ */

export type SourceStatus = 'ok' | 'empty' | 'error' | 'denied' | 'missing'

export interface FocusInput {
  question: string
  filter: QueryFilter
  tool: (name: string) => ToolResult | null
  status: (name: string) => SourceStatus
  /** Assets the question named, linked against the real register (may be empty). */
  assetScope: AssetView[]
}

export interface FocusAnswer {
  headline: string
  objective: string
  keyFindings: string[]
  entities: CopilotEntityTable[]
  recommendations: CopilotRecommendation[]
  nextActions: CopilotNextAction[]
  risk?: CopilotRisk
  figures: CopilotFigure[]
  /** Evidence-derived root cause, when the topic has one (gap questions). */
  rootCause?: string
  /** The module owning the topic could not be read — nothing below is a guess. */
  unavailable?: boolean
  /** The module was read but holds no evidence yet. */
  noData?: boolean
}

function base(focus: FocusId): Pick<FocusAnswer, 'objective' | 'keyFindings' | 'entities' | 'recommendations' | 'nextActions' | 'figures'> {
  return { objective: FOCUS_SPECS[focus].objective, keyFindings: [], entities: [], recommendations: [], nextActions: [], figures: [] }
}

/**
 * The topic's owning source could not be read. Say so plainly and stop —
 * answering from a neighbouring module would present a guess as the answer.
 */
function unavailable(d: FocusInput, focus: FocusId, toolName: string, moduleLabel: string, moduleId: string, what: string): FocusAnswer {
  const reason = d.status(toolName) === 'denied'
    ? `your role does not have access to ${moduleLabel}`
    : `${moduleLabel} did not respond`
  return {
    ...base(focus),
    headline: `I can't tell you ${what} right now: ${reason}. I won't substitute an estimate from another module — retry in a moment or open ${moduleLabel} directly.`,
    nextActions: [{ label: `Open ${moduleLabel}`, path: modulePath(moduleId), reason: `${moduleLabel} holds the authoritative answer.` }],
    risk: { level: 'info', drivers: [] },
    unavailable: true,
  }
}

function figure(key: string, label: string, value: number, better: CopilotFigure['better'], source: string, unit?: string): CopilotFigure {
  return { key, label, value, better, source, unit }
}

/** Keep only rows about the asset(s) the question named. */
function scoped<T>(rows: T[], scope: AssetView[], assetOf: (row: T) => string | null | undefined): T[] {
  if (!scope.length) return rows
  const names = new Set(scope.map((a) => a.name.toLowerCase()))
  return rows.filter((row) => names.has(str(assetOf(row)).toLowerCase()))
}

function scopeNote(scope: AssetView[]): string {
  return scope.length ? ` for ${list(scope.map((a) => a.name))}` : ''
}

/* ------------------------------------------------------------------ */
/* Remediation                                                         */
/* ------------------------------------------------------------------ */

const REMEDIATION_COLUMNS = [
  { key: 'rank', label: '#', align: 'right' as const },
  { key: 'asset', label: 'Asset' },
  { key: 'problem', label: 'Issue' },
  { key: 'fix', label: 'Recommended fix' },
  { key: 'priority', label: 'Priority' },
  { key: 'gain', label: 'Readiness gain', align: 'right' as const },
  { key: 'effort', label: 'Effort', align: 'right' as const },
  { key: 'owner', label: 'Owner' },
]

function actionRow(a: PendingActionRow): CopilotEntityRow {
  return {
    cells: {
      rank: a.rank,
      asset: a.asset,
      problem: a.problem,
      fix: a.recommendation,
      priority: a.priority,
      gain: a.certificationGainPct > 0 ? `+${a.certificationGainPct} pts` : '—',
      effort: weeks(a.effortWeeks),
      owner: a.owner || 'Unassigned',
    },
    tone: PRIORITY_TONE[a.priority] || 'neutral',
    deepLink: a.route,
  }
}

function actionTable(title: string, rows: PendingActionRow[], total: number, note?: string): CopilotEntityTable {
  return {
    title,
    unit: 'remediation action',
    columns: REMEDIATION_COLUMNS,
    rows: rows.slice(0, 12).map(actionRow),
    total,
    source: 'Quantum Remediation Engine™',
    deepLink: modulePath('remediation'),
    note,
  }
}

function why(a: PendingActionRow): string {
  const reasons: string[] = [`${a.priority} priority (score ${a.priorityScore}/100)`]
  if (a.internetFacing) reasons.push('internet-facing')
  if (a.hndlRelevant) reasons.push('exposed to Harvest-Now-Decrypt-Later capture')
  if (a.certificationGainPct > 0) reasons.push(`+${a.certificationGainPct} pts certification readiness`)
  if (a.requiresReplacement) reasons.push('the system cannot support PQC and must be replaced')
  return reasons.join(', ')
}

interface QueueView {
  data: Record<string, unknown>
  rows: PendingActionRow[]
  total: number
  byPriority: Record<string, number>
}

function readQueue(d: FocusInput): QueueView | null {
  const r = d.tool('getPendingRemediation')
  if (!r) return null
  // Engine sentences end in a period; normalised once so every composer can
  // embed them mid-sentence without "…ML-KEM-768).. It is".
  const all = arr<PendingActionRow>(r.data.pending).map((a) => ({ ...a, recommendation: clause(a.recommendation), problem: clause(a.problem) }))
  const rows = scoped(all, d.assetScope, (a) => a.asset)
  const byPriority = d.assetScope.length
    ? rows.reduce<Record<string, number>>((acc, a) => ({ ...acc, [a.priority]: (acc[a.priority] || 0) + 1 }), { critical: 0, high: 0, medium: 0, low: 0 })
    : { critical: 0, high: 0, medium: 0, low: 0, ...rec(r.data.byPriority) } as Record<string, number>
  return { data: r.data, rows, total: d.assetScope.length ? rows.length : num(r.data.pendingCount), byPriority }
}

function remediationFigures(v: QueueView): CopilotFigure[] {
  return [
    figure('remediation.pending', 'Pending remediation actions', v.total, 'lower', 'Quantum Remediation Engine™'),
    figure('remediation.critical', 'Critical-priority actions', num(v.byPriority.critical), 'lower', 'Quantum Remediation Engine™'),
    figure('certification.readinessPct', 'Certification readiness', num(v.data.certificationReadinessPct), 'higher', 'Quantum Remediation Engine™', '%'),
  ]
}

function queueEmpty(focus: FocusId, v: QueueView, scope: AssetView[]): FocusAnswer {
  const noEvidence = v.data.hasData === false
  return {
    ...base(focus),
    headline: noEvidence
      ? 'There is no remediation queue yet because there is no assessment evidence — run a discovery scan and the Remediation Engine will rank the actions from what it finds.'
      : `Nothing is pending${scopeNote(scope)}: the latest evidence leaves no open remediation action.${num(v.data.resolvedCount) ? ` ${count(num(v.data.resolvedCount), 'migration job')} completed so far.` : ''} New findings from the next scan will appear here automatically.`,
    nextActions: [{ label: noEvidence ? 'Run a discovery scan' : 'Open the Remediation Engine', path: modulePath(noEvidence ? 'scanner' : 'remediation'), reason: noEvidence ? 'Generate the evidence the queue is built from.' : 'Review resolved and upcoming work.' }],
    figures: noEvidence ? [] : remediationFigures(v),
    risk: { level: 'info', drivers: [] },
    noData: noEvidence,
  }
}

function composeRemediationQueue(d: FocusInput): FocusAnswer {
  const v = readQueue(d)
  if (!v) return unavailable(d, 'remediation_queue', 'getPendingRemediation', 'the Quantum Remediation Engine™', 'remediation', 'what remediation is pending')
  if (!v.rows.length) return queueEmpty('remediation_queue', v, d.assetScope)
  const top = v.rows[0]
  const bp = v.byPriority
  const inProgress = v.rows.filter((a) => a.status === 'in_progress').length
  const quickWins = v.rows.filter((a) => a.quickWin).length
  const replacements = v.rows.filter((a) => a.requiresReplacement).length
  const data = v.data

  const headline =
    `${count(v.total, 'remediation action')} ${isAre(v.total)} pending${scopeNote(d.assetScope)} — ${num(bp.critical)} critical, ${num(bp.high)} high, ${num(bp.medium)} medium and ${num(bp.low)} low priority` +
    `${inProgress ? `; ${inProgress} already in progress` : ''}. ` +
    `First in the queue: ${top.asset} — ${top.problem}. Fix: ${top.recommendation}, about ${weeks(top.effortWeeks)}${top.certificationGainPct > 0 ? ` for +${top.certificationGainPct} pts certification readiness` : ''}.` +
    `${quickWins ? ` ${count(quickWins, 'action is a quick win', 'actions are quick wins')}.` : ''}`

  const keyFindings = [
    `Queue by priority: ${num(bp.critical)} critical · ${num(bp.high)} high · ${num(bp.medium)} medium · ${num(bp.low)} low.`,
    `Status: ${count(v.rows.filter((a) => a.status === 'open').length, 'action')} open, ${inProgress} in progress${num(data.resolvedCount) ? `, ${count(num(data.resolvedCount), 'migration job')} completed` : ''}.`,
    `Certification readiness is ${num(data.certificationReadinessPct)}% today${data.certificationEligible === true ? ' — you already meet the certification criteria' : ''}.`,
  ]
  if (!d.assetScope.length && num(data.estimatedCompletionWeeks) > 0) {
    keyFindings.push(`The Remediation Engine estimates about ${weeks(num(data.totalEffortWeeks))} of effort — roughly ${weeks(num(data.estimatedCompletionWeeks))} of calendar time with ${count(num(data.parallelWorkstreams) || 1, 'parallel workstream')}.`)
  }
  if (replacements) keyFindings.push(`${count(replacements, 'system')} cannot support post-quantum cryptography and must be replaced rather than reconfigured.`)
  if (top.breakingChangeWarning) keyFindings.push(`Watch out on #1: ${top.breakingChangeWarning}`)

  const recommendations: CopilotRecommendation[] = [{
    title: `Start with #1: ${top.asset}`,
    detail: `${top.recommendation} → target ${top.targetState}. Ranked first because of ${why(top)}. Rollback: ${top.rollback}`,
    priority: top.priority === 'critical' ? 'immediate' : top.priority === 'high' ? 'high' : 'medium',
    standards: top.standards.length ? top.standards : [STANDARDS.FIPS_203, STANDARDS.FIPS_204],
    deepLink: top.route,
  }]
  if (quickWins) {
    recommendations.push({
      title: `Clear the ${count(quickWins, 'quick win')}`,
      detail: 'Low-effort actions with a measurable certification-readiness gain — the cheapest progress in the queue.',
      priority: 'high',
      standards: [STANDARDS.NIST_CSF],
      deepLink: modulePath('remediation'),
    })
  }

  return {
    ...base('remediation_queue'),
    headline,
    keyFindings,
    entities: [actionTable(`Pending remediation${scopeNote(d.assetScope)} — in execution order`, v.rows, v.total, 'Order is the Remediation Engine\'s Q-REMEDY ranking; readiness gains are its simulation, confirmed only by a rescan.')],
    recommendations,
    nextActions: [
      { label: 'Open the Remediation Engine', path: modulePath('remediation'), reason: 'Work the queue with validation checkpoints and rollback.' },
      { label: 'Plan the migration', path: modulePath('migration_planner'), reason: 'Sequence these actions into waves.' },
    ],
    risk: { level: num(bp.critical) ? 'critical' : num(bp.high) ? 'high' : 'medium', drivers: [`${count(v.total, 'pending remediation action')}`, ...(num(bp.critical) ? [`${num(bp.critical)} critical-priority`] : [])] },
    figures: remediationFigures(v),
  }
}

function composeRemediationGain(d: FocusInput): FocusAnswer {
  const v = readQueue(d)
  if (!v) return unavailable(d, 'remediation_gain', 'getPendingRemediation', 'the Quantum Remediation Engine™', 'remediation', 'which remediation raises readiness the most')
  if (!v.rows.length) return queueEmpty('remediation_gain', v, d.assetScope)
  const ranked = [...v.rows].sort((a, b) => b.certificationGainPct - a.certificationGainPct || a.effortWeeks - b.effortWeeks)
  const top = ranked[0]
  const current = num(v.data.certificationReadinessPct)
  const withGain = ranked.filter((a) => a.certificationGainPct > 0)
  const quickWins = ranked.filter((a) => a.quickWin)

  const headline = withGain.length
    ? `The biggest single gain is ${top.asset}: ${top.recommendation} — +${top.certificationGainPct} pts, taking certification readiness from ${current}% toward ${top.projectedReadinessPct}% for about ${weeks(top.effortWeeks)} of effort.` +
      `${quickWins.length ? ` ${count(quickWins.length, 'quick win')} (${list(quickWins.map((a) => a.asset), 3)}) ${quickWins.length === 1 ? 'gives' : 'give'} the best gain per week.` : ''}`
    : `No single open action moves certification readiness on its own right now (${current}%): every open action's simulated gain is 0, which means the remaining criteria need NEW evidence — a rescan after fixes — rather than one more change. The queue below is in priority order instead.`

  return {
    ...base('remediation_gain'),
    headline,
    keyFindings: [
      `Current certification readiness: ${current}%.`,
      `${count(withGain.length, 'open action')} ${withGain.length === 1 ? 'has' : 'have'} a measurable simulated readiness gain; ${count(quickWins.length, 'is a quick win', 'are quick wins')}.`,
      'Gains come from the Remediation Engine\'s marginal-gain simulation (Q-REMEDY); the live score only moves when a rescan confirms the fix.',
    ],
    entities: [actionTable('Remediation ranked by certification gain', withGain.length ? ranked : v.rows, v.total)],
    recommendations: withGain.length ? [{
      title: `Do ${top.asset} first for the largest gain`,
      detail: `${top.recommendation} (+${top.certificationGainPct} pts, ${weeks(top.effortWeeks)}). ${top.breakingChangeWarning || ''}`.trim(),
      priority: 'high',
      standards: top.standards.length ? top.standards : [STANDARDS.NIST_CSF],
      deepLink: top.route,
    }] : [],
    nextActions: [{ label: 'Open the readiness ladder', path: modulePath('remediation'), reason: 'See the projected readiness after each action.' }],
    risk: { level: 'medium', drivers: [`certification readiness ${current}%`] },
    figures: remediationFigures(v),
  }
}

function composeCriticalBlockers(d: FocusInput): FocusAnswer {
  const v = readQueue(d)
  const elig = d.tool('getCertificationEligibility')
  if (!v && !elig) return unavailable(d, 'critical_blockers', 'getPendingRemediation', 'the Quantum Remediation Engine™', 'remediation', 'what the critical blockers are')
  const critical = v ? v.rows.filter((a) => a.priority === 'critical') : []
  const requiredUnmet = arr<{ label: string; required: string; actual: string; remediation: string }>(elig?.data.requiredUnmet)
  const parts: string[] = []
  if (v) {
    parts.push(critical.length
      ? `${count(critical.length, 'remediation action')} ${isAre(critical.length)} in the critical priority band: ${list(critical.map((a) => `${a.asset} (${a.problem})`), 3)}.`
      : v.rows.length
        ? `No open remediation action is in the critical priority band. The highest-priority open action is ${v.rows[0].asset} — ${v.rows[0].problem} (${v.rows[0].priority}).`
        : 'The remediation queue is empty.')
  }
  if (elig) {
    parts.push(requiredUnmet.length
      ? `Certification is blocked by ${count(requiredUnmet.length, 'required criterion', 'required criteria')}: ${list(requiredUnmet.map((c) => `${c.label} (needs ${c.required}, measured ${c.actual})`), 3)}.`
      : elig.data.eligible === true ? 'No certification criterion is blocking — you are eligible.' : '')
  }
  return {
    ...base('critical_blockers'),
    headline: parts.filter(Boolean).join(' '),
    keyFindings: v ? [`Queue by priority: ${num(v.byPriority.critical)} critical · ${num(v.byPriority.high)} high · ${num(v.byPriority.medium)} medium · ${num(v.byPriority.low)} low.`] : [],
    entities: [
      ...(v && (critical.length || v.rows.length) ? [actionTable(critical.length ? 'Critical-priority actions' : 'Highest-priority open actions', critical.length ? critical : v.rows, critical.length || v.total)] : []),
      ...(requiredUnmet.length ? [criteriaTable(requiredUnmet.map((c) => ({ ...c, met: false })), 'Unmet required certification criteria')] : []),
    ],
    recommendations: critical.length ? [{
      title: `Resolve ${critical[0].asset} first`,
      detail: `${critical[0].recommendation}. ${why(critical[0])}.`,
      priority: 'immediate',
      standards: critical[0].standards.length ? critical[0].standards : [STANDARDS.NIST_CSF],
      deepLink: critical[0].route,
    }] : [],
    nextActions: [{ label: 'Open the Remediation Engine', path: modulePath('remediation'), reason: 'Work the blockers in order.' }],
    risk: { level: critical.length ? 'critical' : requiredUnmet.length ? 'high' : 'medium', drivers: [`${critical.length} critical action(s)`, `${requiredUnmet.length} unmet required criteria`] },
    figures: v ? remediationFigures(v) : [],
  }
}

function composeMigrationPriority(d: FocusInput): FocusAnswer {
  const v = readQueue(d)
  if (!v) return unavailable(d, 'migration_priority', 'getPendingRemediation', 'the Quantum Remediation Engine™', 'remediation', 'what to migrate first')
  if (!v.rows.length) return queueEmpty('migration_priority', v, d.assetScope)
  const order = v.rows.slice(0, 5)
  const [first, ...rest] = order
  const headline =
    `Start with ${first.asset} — ${first.problem}. It ranks first because of ${why(first)}. ` +
    `${rest.length ? `Then ${list(rest.map((a) => `${a.asset} (${a.problem})`), 4)}.` : ''} ` +
    'Inside each step, keep the dependency-safe order below: trust roots and issuing CAs before the endpoints that rely on them.'
  return {
    ...base('migration_priority'),
    headline: headline.replace(/\s+/g, ' ').trim(),
    keyFindings: order.map((a, i) => `${i + 1}. ${a.asset} — ${a.recommendation} (${why(a)}).`),
    entities: [actionTable('Migration order — highest priority first', v.rows, v.total, 'Ranked by the Remediation Engine from severity, certification impact, business criticality, internet exposure, HNDL relevance, data sensitivity, blast radius and compliance impact.')],
    recommendations: [{
      title: `Migrate ${first.asset} first`,
      detail: `${first.recommendation} → ${first.targetState}. ${first.breakingChangeWarning || ''} Rollback: ${first.rollback}`.replace(/\s+/g, ' ').trim(),
      priority: first.priority === 'critical' ? 'immediate' : 'high',
      standards: first.standards.length ? first.standards : [STANDARDS.SP_1800_38],
      deepLink: first.route,
    }],
    nextActions: [
      { label: 'Open the Migration Planner', path: modulePath('migration_planner'), reason: 'Turn this order into waves with validation checkpoints.' },
      { label: 'Open the Remediation Engine', path: modulePath('remediation'), reason: 'See the full ranking and each action\'s playbook.' },
    ],
    risk: { level: num(v.byPriority.critical) ? 'critical' : 'high', drivers: [`${count(v.total, 'pending action')}`] },
    figures: remediationFigures(v),
  }
}

/* ------------------------------------------------------------------ */
/* Certification                                                       */
/* ------------------------------------------------------------------ */

interface CriterionView { label: string; required: string; actual: string; met: boolean; remediation?: string; severity?: string }

function criteriaTable(criteria: CriterionView[], title = 'Certification criteria'): CopilotEntityTable {
  const ordered = [...criteria].sort((a, b) => Number(a.met) - Number(b.met))
  return {
    title,
    unit: 'criterion',
    columns: [
      { key: 'criterion', label: 'Criterion' },
      { key: 'required', label: 'Required' },
      { key: 'actual', label: 'Measured' },
      { key: 'status', label: 'Status' },
      { key: 'close', label: 'How to close it' },
    ],
    rows: ordered.map((c) => ({
      cells: { criterion: c.label, required: c.required, actual: c.actual, status: c.met ? 'Met' : 'Unmet', close: c.met ? '—' : c.remediation || '—' },
      tone: c.met ? 'good' : c.severity === 'advisory' ? 'medium' : 'high',
      deepLink: modulePath('certification'),
    })),
    total: criteria.length,
    source: 'Quantum Trust Certification™',
    deepLink: modulePath('certification'),
  }
}

function certificationFigures(data: Record<string, unknown>): CopilotFigure[] {
  return [
    figure('certification.requiredMet', 'Required certification criteria met', num(data.requiredMet), 'higher', 'Quantum Trust Certification™'),
    figure('certification.readinessPct', 'Certification readiness', num(data.certificationReadinessPct), 'higher', 'Quantum Remediation Engine™', '%'),
  ]
}

function composeCertificationGap(d: FocusInput): FocusAnswer {
  const r = d.tool('getCertificationEligibility')
  if (!r) return unavailable(d, 'certification_gap', 'getCertificationEligibility', 'Quantum Trust Certification™', 'certification', 'what is blocking certification')
  const data = r.data
  const criteria = arr<CriterionView>(data.criteria)
  const requiredUnmet = arr<CriterionView>(data.requiredUnmet)
  const gaps = arr<{ requirement: string; recommendedSolution: string; relatedAssets: string[]; estimatedScoreIncreasePct: number; estimatedCompletionWeeks: number; route: string }>(data.gaps)
  const status = d.tool('getCertificationStatus')
  const certified = status?.data.certified === true
  const certificate = rec(status?.data.certificate)
  const met = num(data.requiredMet)
  const total = num(data.requiredTotal)
  const readiness = num(data.certificationReadinessPct)
  const eta = str(data.estimatedCertificationDate)

  if (!criteria.length) {
    return {
      ...base('certification_gap'),
      headline: 'No certification criteria have been evaluated yet, so I can\'t tell you what is blocking certification. Run a discovery scan — eligibility is decided from measured evidence only.',
      nextActions: [{ label: 'Run a discovery scan', path: modulePath('scanner'), reason: 'Eligibility needs measured evidence.' }],
      risk: { level: 'info', drivers: [] },
      noData: true,
    }
  }

  const headline = data.eligible === true
    ? `Yes — all ${total} required criteria are met${certified ? ` and a ${str(certificate.levelLabel) || 'Quantum Trust'} certificate is active (trust score ${num(certificate.trustScore)})` : '. No certificate is active yet: issue it from Quantum Trust Certification — eligibility is already proven by measured evidence'}.`
    : `Not yet — ${met} of ${total} required criteria are met. ${requiredUnmet.length ? `Blocking: ${list(requiredUnmet.map((c) => `${c.label} (needs ${c.required}, measured ${c.actual})`), 3)}.` : ''} Certification readiness is ${readiness}%${eta ? `; if the current remediation queue is completed, the Remediation Engine projects eligibility around ${dateOnly(eta)} (a projection — eligibility is only granted from a rescan).` : '.'}`

  const recommendations: CopilotRecommendation[] = gaps.slice(0, 3).map((g) => ({
    title: `Close: ${g.requirement}`,
    detail: `${clause(g.recommendedSolution)}.${g.relatedAssets.length ? ` Assets: ${list(g.relatedAssets, 4)}.` : ''}${g.estimatedScoreIncreasePct ? ` Projected +${g.estimatedScoreIncreasePct} pts in ~${weeks(g.estimatedCompletionWeeks)}.` : ''}`,
    priority: 'high' as const,
    standards: [STANDARDS.NIST_CSF, STANDARDS.FIPS_203, STANDARDS.FIPS_204],
    deepLink: g.route,
  }))

  return {
    ...base('certification_gap'),
    headline: headline.replace(/\s+/g, ' ').trim(),
    keyFindings: [
      `${met}/${total} required criteria met${data.issuable === true && data.eligible !== true ? ' — enough evidence for a Bronze "Initial Readiness" attestation, which records the gaps rather than claiming quantum safety' : ''}.`,
      `Certification readiness: ${readiness}%.`,
      ...(str(data.levelLabel) ? [`Current standing: ${str(data.levelLabel)}.`] : []),
    ],
    entities: [criteriaTable(criteria)],
    recommendations,
    nextActions: [
      { label: 'Open Quantum Trust Certification', path: modulePath('certification'), reason: 'See each criterion and its evidence.' },
      { label: 'Open the Remediation Engine', path: modulePath('remediation'), reason: 'Work the actions that close the unmet criteria.' },
    ],
    risk: { level: data.eligible === true ? 'low' : requiredUnmet.length > 3 ? 'high' : 'medium', drivers: [`${requiredUnmet.length} unmet required criteria`] },
    figures: certificationFigures(data),
    rootCause: data.eligible === true || !requiredUnmet.length ? undefined
      : `${count(requiredUnmet.length, 'required criterion measures', 'required criteria measure')} outside policy: ${list(requiredUnmet.map((c) => `${c.label} is ${c.actual} against a requirement of ${c.required}`), 4)}. Certification is evidence-gated, so each gap closes only when the underlying cryptography changes AND a rescan measures the change.`,
  }
}

const LEVEL_ORDER = ['bronze', 'silver', 'gold', 'platinum', 'diamond']

function composeCertificationNextLevel(d: FocusInput): FocusAnswer {
  const r = d.tool('getCertificationEligibility')
  if (!r) return unavailable(d, 'certification_next_level', 'getCertificationEligibility', 'Quantum Trust Certification™', 'certification', 'how to reach the next certification level')
  const data = r.data
  const status = d.tool('getCertificationStatus')
  const certificate = rec(status?.data.certificate)
  const currentLevel = str(certificate.level) || ''
  const currentLabel = str(certificate.levelLabel) || str(data.levelLabel) || 'not certified'
  const nextLevel = currentLevel ? LEVEL_ORDER[LEVEL_ORDER.indexOf(currentLevel) + 1] : null
  const requiredUnmet = arr<CriterionView>(data.requiredUnmet)
  const ladder = arr<{ stage: string; actionTitle: string; readinessPct: number; gainPct: number; effortWeeks: number }>(data.ladder)
  const readiness = num(data.certificationReadinessPct)

  const headline = data.eligible === true
    ? `You meet every required criterion (standing: ${currentLabel}).${nextLevel ? ` Higher levels such as ${nextLevel[0].toUpperCase()}${nextLevel.slice(1)} are granted from a stronger measured trust score — keep adopting ML-KEM / ML-DSA and closing advisory criteria, then re-certify.` : ''}`
    : `Your current standing is ${currentLabel}. The next step is full eligibility: close ${count(requiredUnmet.length, 'unmet required criterion', 'unmet required criteria')} (${list(requiredUnmet.map((c) => c.label), 4)}). Certification readiness is ${readiness}%; the readiness ladder below shows the order that closes the gap fastest.`

  return {
    ...base('certification_next_level'),
    headline,
    keyFindings: [
      `Required criteria met: ${num(data.requiredMet)}/${num(data.requiredTotal)}.`,
      `Certification readiness: ${readiness}%.`,
      'Every rung is a Remediation Engine projection; a level is only granted from measured evidence after a rescan.',
    ],
    entities: [
      ...(ladder.length ? [{
        title: 'Readiness ladder — projected path to eligibility',
        unit: 'step',
        columns: [
          { key: 'stage', label: 'Stage' },
          { key: 'action', label: 'Action' },
          { key: 'readiness', label: 'Readiness', align: 'right' as const },
          { key: 'gain', label: 'Gain', align: 'right' as const },
          { key: 'effort', label: 'Effort', align: 'right' as const },
        ],
        rows: ladder.map((s) => ({ cells: { stage: s.stage, action: s.actionTitle, readiness: `${s.readinessPct}%`, gain: s.gainPct ? `+${s.gainPct}` : '—', effort: s.effortWeeks ? weeks(s.effortWeeks) : '—' }, tone: 'neutral' as CopilotTone, deepLink: modulePath('remediation') })),
        total: ladder.length,
        source: 'Quantum Remediation Engine™',
        deepLink: modulePath('remediation'),
      }] : []),
      ...(requiredUnmet.length ? [criteriaTable(requiredUnmet.map((c) => ({ ...c, met: false })), 'Criteria to close for the next level')] : []),
    ],
    recommendations: requiredUnmet.slice(0, 2).map((c) => ({
      title: `Close: ${c.label}`,
      detail: `${clause(c.remediation || 'Work the mapped remediation actions')} (needs ${c.required}, measured ${c.actual}).`,
      priority: 'high' as const,
      standards: [STANDARDS.NIST_CSF],
      deepLink: modulePath('remediation'),
    })),
    nextActions: [{ label: 'Open Quantum Trust Certification', path: modulePath('certification'), reason: 'Track the criteria and issue the certificate once eligible.' }],
    risk: { level: data.eligible === true ? 'low' : 'medium', drivers: [`${requiredUnmet.length} unmet required criteria`] },
    figures: certificationFigures(data),
  }
}

/* ------------------------------------------------------------------ */
/* Readiness                                                           */
/* ------------------------------------------------------------------ */

function readinessFigures(scores: Record<string, unknown>, inventory: Record<string, unknown>): CopilotFigure[] {
  return [
    figure('readiness.score', 'Quantum readiness', num(scores.quantumReadiness), 'higher', 'Quantum Readiness Assessment Engine™', '/100'),
    figure('readiness.pqcAdoption', 'PQC adoption', num(scores.pqcAdoption), 'higher', 'Quantum Readiness Assessment Engine™', '%'),
    figure('cbom.vulnerable', 'Quantum-vulnerable components', num(inventory.vulnerableComponents), 'lower', 'CBOM Explorer'),
    figure('risk.quantum', 'Quantum risk', num(scores.quantumRisk), 'lower', 'Quantum Risk Analysis', '/100'),
  ]
}

function composeReadiness(d: FocusInput): FocusAnswer {
  const r = d.tool('getQuantumReadiness')
  if (!r) return unavailable(d, 'readiness', 'getQuantumReadiness', 'the Quantum Readiness Assessment Engine™', 'quantum_readiness', 'your quantum readiness')
  if (r.data.hasData !== true) {
    return {
      ...base('readiness'),
      headline: 'I can\'t give a readiness verdict yet: there is no assessment evidence. Run a discovery scan (or connect a collector / cloud connector) — readiness is only ever computed from what was measured.',
      nextActions: [{ label: 'Run a discovery scan', path: modulePath('scanner'), reason: 'Readiness needs measured evidence.' }],
      risk: { level: 'info', drivers: [] },
      noData: true,
    }
  }
  const scores = rec(r.data.scores)
  const inventory = rec(r.data.inventory)
  const factors = arr<{ label: string; score: number }>(r.data.readinessFactors)
  const elig = d.tool('getCertificationEligibility')
  const eligible = elig?.data.eligible === true
  const readiness = num(scores.quantumReadiness)
  const weakest = [...factors].sort((a, b) => a.score - b.score).slice(0, 2)
  const components = num(inventory.cryptoComponents)
  const vulnerable = num(inventory.vulnerableComponents)

  const verdict = eligible
    ? 'Yes — you meet every required certification criterion'
    : 'Not yet'
  const headline =
    `${verdict}: quantum readiness is ${readiness}/100 (${str(scores.quantumReadinessLevel) || 'unrated'}). ` +
    `${vulnerable} of your ${components} cryptographic components ${isAre(vulnerable)} quantum-vulnerable and PQC adoption is ${num(scores.pqcAdoption)}%. ` +
    `${weakest.length ? `The weakest readiness factors are ${list(weakest.map((f) => `${f.label} (${f.score}/100)`), 2)}.` : ''}`

  return {
    ...base('readiness'),
    headline: headline.replace(/\s+/g, ' ').trim(),
    keyFindings: [
      `Quantum readiness ${readiness}/100 (${str(scores.quantumReadinessLevel) || 'unrated'}); PQC adoption ${num(scores.pqcAdoption)}%.`,
      `Quantum risk ${num(scores.quantumRisk)}/100 (${str(scores.quantumRiskLevel) || 'unrated'}); Harvest-Now risk ${num(scores.hndlRisk)}/100.`,
      `${num(inventory.assetsAssessed)} asset(s) assessed; ${num(inventory.quantumVulnerableAssets)} quantum-vulnerable, ${num(inventory.pqcReadyAssets)} PQC-ready.`,
      ...(elig ? [`Certification: ${num(elig.data.requiredMet)}/${num(elig.data.requiredTotal)} required criteria met.`] : []),
      ...(r.data.lastAssessmentAt ? [`Assessed ${ago(str(r.data.lastAssessmentAt))}.`] : []),
    ],
    entities: factors.length ? [{
      title: 'Readiness factors',
      unit: 'factor',
      columns: [{ key: 'factor', label: 'Factor' }, { key: 'score', label: 'Score', align: 'right' }],
      rows: [...factors].sort((a, b) => a.score - b.score).map((f) => ({ cells: { factor: f.label, score: `${f.score}/100` }, tone: f.score >= 70 ? 'good' : f.score >= 40 ? 'medium' : 'high' })),
      total: factors.length,
      source: 'Quantum Readiness Assessment Engine™',
      deepLink: modulePath('quantum_readiness'),
    }] : [],
    recommendations: weakest.length ? [{
      title: `Lift ${weakest[0].label}`,
      detail: `It is your weakest readiness factor at ${weakest[0].score}/100. Replacing quantum-vulnerable components with ML-KEM (key establishment) and ML-DSA (signatures) raises PQC adoption and the component factors together.`,
      priority: 'high',
      standards: [STANDARDS.FIPS_203, STANDARDS.FIPS_204],
      deepLink: modulePath('remediation'),
    }] : [],
    nextActions: [
      { label: 'Open the Quantum Readiness Engine', path: modulePath('quantum_readiness'), reason: 'See every factor and its evidence.' },
      { label: 'What raises my readiness fastest?', path: modulePath('remediation'), reason: 'The highest-gain actions.' },
    ],
    risk: { level: riskFromScore(num(scores.quantumRisk)), score: num(scores.quantumRisk), drivers: [`readiness ${readiness}/100`, `${count(vulnerable, 'vulnerable component')}`] },
    figures: readinessFigures(scores, inventory),
  }
}

function composeReadinessBlockers(d: FocusInput): FocusAnswer {
  const r = d.tool('getQuantumReadiness')
  if (!r) return unavailable(d, 'readiness_blockers', 'getQuantumReadiness', 'the Quantum Readiness Assessment Engine™', 'quantum_readiness', 'what is holding your readiness down')
  if (r.data.hasData !== true) return composeReadiness(d)
  const scores = rec(r.data.scores)
  const inventory = rec(r.data.inventory)
  const factors = [...arr<{ label: string; score: number }>(r.data.readinessFactors)].sort((a, b) => a.score - b.score)
  const v = readQueue(d)
  const byGain = v ? [...v.rows].sort((a, b) => b.certificationGainPct - a.certificationGainPct).filter((a) => a.certificationGainPct > 0).slice(0, 5) : []
  const headline =
    `Readiness is ${num(scores.quantumReadiness)}/100. It is held down most by ${list(factors.slice(0, 3).map((f) => `${f.label} (${f.score}/100)`), 3)}. ` +
    `${num(inventory.vulnerableComponents)} quantum-vulnerable component(s) and ${num(scores.pqcAdoption)}% PQC adoption are the underlying cause. ` +
    `${byGain.length ? `The actions that lift it most: ${list(byGain.map((a) => `${a.asset} (+${a.certificationGainPct} pts)`), 3)}.` : ''}`
  return {
    ...base('readiness_blockers'),
    headline: headline.replace(/\s+/g, ' ').trim(),
    keyFindings: factors.slice(0, 4).map((f) => `${f.label}: ${f.score}/100.`),
    entities: [
      {
        title: 'Readiness factors — weakest first',
        unit: 'factor',
        columns: [{ key: 'factor', label: 'Factor' }, { key: 'score', label: 'Score', align: 'right' }],
        rows: factors.map((f) => ({ cells: { factor: f.label, score: `${f.score}/100` }, tone: f.score >= 70 ? 'good' : f.score >= 40 ? 'medium' : 'high' })),
        total: factors.length,
        source: 'Quantum Readiness Assessment Engine™',
        deepLink: modulePath('quantum_readiness'),
      },
      ...(byGain.length && v ? [actionTable('Actions that raise readiness most', byGain, byGain.length)] : []),
    ],
    recommendations: [],
    nextActions: [{ label: 'Open the Remediation Engine', path: modulePath('remediation'), reason: 'Work the highest-gain actions.' }],
    risk: { level: riskFromScore(num(scores.quantumRisk)), score: num(scores.quantumRisk), drivers: factors.slice(0, 2).map((f) => `${f.label} ${f.score}/100`) },
    figures: readinessFigures(scores, inventory),
  }
}

/* ------------------------------------------------------------------ */
/* Harvest Now, Decrypt Later                                          */
/* ------------------------------------------------------------------ */

interface HndlView {
  data: Record<string, unknown>
  fs: Record<string, unknown>
  future: Record<string, unknown>
}

function readHndl(d: FocusInput): HndlView | null {
  const r = d.tool('getHarvestNowExposure')
  if (!r) return null
  return { data: r.data, fs: rec(r.data.forwardSecrecy), future: rec(r.data.futureDecryptable) }
}

function hndlNoData(focus: FocusId): FocusAnswer {
  return {
    ...base(focus),
    headline: 'Harvest-Now-Decrypt-Later exposure has not been measured yet — there is no scan evidence. This is not a pass: run a discovery scan so key exchange, forward secrecy and data lifetimes can be assessed.',
    nextActions: [{ label: 'Run a discovery scan', path: modulePath('scanner'), reason: 'HNDL exposure is derived from measured key exchange.' }],
    risk: { level: 'info', drivers: [] },
    noData: true,
  }
}

function hndlFigures(h: HndlView): CopilotFigure[] {
  const out = [figure('hndl.score', 'HNDL risk', num(h.data.hndlScore), 'lower', 'Harvest Now (HNDL)', '/100')]
  if (h.fs.hasEvidence === true) out.push(figure('hndl.forwardSecrecyPct', 'Forward-secrecy coverage', num(h.fs.coveragePct), 'higher', 'Harvest Now (HNDL)', '%'))
  return out
}

function composeHndlExposure(d: FocusInput): FocusAnswer {
  const h = readHndl(d)
  if (!h) return unavailable(d, 'hndl_exposure', 'getHarvestNowExposure', 'Harvest Now (HNDL)', 'harvest_now', 'your Harvest-Now-Decrypt-Later exposure')
  if (h.data.hasData !== true) return hndlNoData('hndl_exposure')
  const findings = arr<{ asset: string; algorithm: string; severity: string; dataLifetimeLabel: string; riskWindow: string; exceedsCrqc: boolean }>(h.data.topFindings)
  const beyondCrqc = findings.filter((f) => f.exceedsCrqc)
  const fsLine = h.fs.hasEvidence === true
    ? `Forward secrecy covers ${num(h.fs.coveragePct)}% of the ${num(h.fs.componentsMeasured)} key-agreement observations; ${num(h.fs.componentsWithoutPfs)} ${num(h.fs.componentsWithoutPfs) === 1 ? 'lacks' : 'lack'} it across ${count(num(h.fs.assetsWithoutPfs), 'asset')}.`
    : 'Forward secrecy has not been measured (no key-agreement observations recorded).'
  const headline =
    `Your Harvest-Now-Decrypt-Later threat level is ${str(h.data.threatLevel)} — HNDL risk ${num(h.data.hndlScore)}/100 (${str(h.data.hndlLevel)}). ` +
    `${count(num(h.data.criticalExposures), 'critical quantum-vulnerable exposure')} ${num(h.data.criticalExposures) === 1 ? 'is' : 'are'} recording traffic an adversary can store today and decrypt once a quantum computer exists. ${fsLine}` +
    `${beyondCrqc.length ? ` ${count(beyondCrqc.length, 'exposure')} protect${beyondCrqc.length === 1 ? 's' : ''} data whose confidentiality lifetime outlasts the quantum-risk window.` : ''}`
  return {
    ...base('hndl_exposure'),
    headline: headline.replace(/\s+/g, ' ').trim(),
    keyFindings: [
      `Quantum exposure window: ${str(h.data.exposureWindow)}; planning deadline ${num(h.data.migrationDeadlineYear)} (${count(num(h.data.yearsToDeadline), 'year')} away).`,
      fsLine,
      ...(h.future.hasEvidence === true ? [`Modelled (not measured): about ${num(h.future.projectedDecryptableTb)} TB of an estimated ${num(h.future.totalDataAtRiskTb)} TB in scope would be decryptable; ${num(h.future.vulnerableSharePct)}% of components are quantum-vulnerable (measured).`] : []),
    ],
    entities: findings.length ? [{
      title: 'Highest HNDL exposures',
      unit: 'exposure',
      columns: [
        { key: 'asset', label: 'Asset' },
        { key: 'algorithm', label: 'Algorithm' },
        { key: 'severity', label: 'Severity' },
        { key: 'lifetime', label: 'Data lifetime' },
        { key: 'window', label: 'Risk window' },
      ],
      rows: findings.map((f) => ({ cells: { asset: f.asset, algorithm: f.algorithm, severity: f.severity, lifetime: f.dataLifetimeLabel, window: f.riskWindow }, tone: f.exceedsCrqc ? 'critical' : PRIORITY_TONE[String(f.severity).toLowerCase()] || 'high', deepLink: modulePath('harvest_now') })),
      total: findings.length,
      source: 'Harvest Now (HNDL)',
      deepLink: modulePath('harvest_now'),
    }] : [],
    recommendations: [{
      title: 'Close the Harvest-Now window on internet-facing TLS',
      detail: 'Deploy hybrid key establishment (X25519 + ML-KEM-768) and enforce forward-secret suites — traffic captured after the change is no longer future-decryptable.',
      priority: 'immediate',
      standards: [STANDARDS.FIPS_203, STANDARDS.IETF_HYBRID, STANDARDS.CNSA_2],
      deepLink: modulePath('harvest_now'),
    }],
    nextActions: [{ label: 'Open Harvest Now (HNDL)', path: modulePath('harvest_now'), reason: 'Per-asset exposure, data lifetimes and forward secrecy.' }],
    risk: { level: riskFromLevel(str(h.data.threatLevel)), score: num(h.data.hndlScore), drivers: [`HNDL risk ${num(h.data.hndlScore)}/100`, `${num(h.data.criticalExposures)} critical exposure(s)`] },
    figures: hndlFigures(h),
  }
}

function composeForwardSecrecy(d: FocusInput): FocusAnswer {
  const h = readHndl(d)
  if (!h) return unavailable(d, 'forward_secrecy', 'getHarvestNowExposure', 'Harvest Now (HNDL)', 'harvest_now', 'which endpoints lack forward secrecy')
  if (h.data.hasData !== true || h.fs.hasEvidence !== true) {
    return {
      ...hndlNoData('forward_secrecy'),
      headline: 'Forward secrecy has not been measured: no key-agreement observations are recorded for your estate. That is an absence of evidence, not a pass — run an authorized TLS scan to measure it.',
    }
  }
  const rows = scoped(arr<{ asset: string; algorithm: string; protocol: string; reason: string }>(h.fs.topUnprotected), d.assetScope, (r) => r.asset)
  const breakdown = arr<{ type: string; count: number }>(h.fs.nonPfsBreakdown)
  const without = num(h.fs.componentsWithoutPfs)
  const headline = without === 0
    ? `Every measured key exchange is forward-secret: ${num(h.fs.componentsMeasured)} key-agreement observation(s), 100% coverage.`
    : `${count(num(h.fs.assetsWithoutPfs), 'asset')} ${num(h.fs.assetsWithoutPfs) === 1 ? 'uses' : 'use'} key exchange without forward secrecy — ${without} of ${num(h.fs.componentsMeasured)} key-agreement observations (coverage ${num(h.fs.coveragePct)}%). ` +
      `${rows.length ? `Affected: ${list(rows.map((r) => `${r.asset} (${r.algorithm})`), 4)}. ` : ''}` +
      'Sessions recorded from these endpoints stay decryptable if their long-term key is ever recovered — by theft today or by a quantum computer later.'
  return {
    ...base('forward_secrecy'),
    headline: headline.replace(/\s+/g, ' ').trim(),
    keyFindings: [
      String(h.fs.basis || ''),
      ...breakdown.slice(0, 4).map((b) => `${b.type}: ${b.count} observation(s).`),
    ].filter(Boolean),
    entities: rows.length ? [{
      title: 'Key exchange without forward secrecy',
      unit: 'observation',
      columns: [{ key: 'asset', label: 'Asset' }, { key: 'algorithm', label: 'Key exchange' }, { key: 'protocol', label: 'Protocol' }, { key: 'reason', label: 'Why it matters' }],
      rows: rows.map((r) => ({ cells: { asset: r.asset, algorithm: r.algorithm, protocol: r.protocol, reason: r.reason }, tone: 'high', deepLink: modulePath('harvest_now') })),
      total: without,
      source: 'Harvest Now (HNDL)',
      deepLink: modulePath('harvest_now'),
      note: rows.length < without ? `Showing the ${rows.length} highest-impact observations of ${without}.` : undefined,
    }] : [],
    recommendations: without ? [{
      title: 'Enforce ephemeral key exchange',
      detail: 'Disable static-RSA / static-DH key exchange; allow only ECDHE or X25519 suites, and add ML-KEM hybrid (X25519MLKEM768) so new sessions are quantum-safe too.',
      priority: 'immediate',
      standards: [STANDARDS.IETF_HYBRID, STANDARDS.FIPS_203, STANDARDS.SP_800_131A],
      deepLink: modulePath('harvest_now'),
    }] : [],
    nextActions: [{ label: 'Open Harvest Now (HNDL)', path: modulePath('harvest_now'), reason: 'Forward-secrecy panel with every observation.' }],
    risk: { level: without ? 'high' : 'low', drivers: without ? [`${without} key exchange(s) without forward secrecy`] : [] },
    figures: hndlFigures(h),
  }
}

function composeFutureDecryptable(d: FocusInput): FocusAnswer {
  const h = readHndl(d)
  if (!h) return unavailable(d, 'future_decryptable', 'getHarvestNowExposure', 'Harvest Now (HNDL)', 'harvest_now', 'how much of your data is future-decryptable')
  if (h.data.hasData !== true || h.future.hasEvidence !== true) return hndlNoData('future_decryptable')
  const headline =
    `Measured: ${num(h.future.vulnerableSharePct)}% of your cryptographic components are quantum-vulnerable. ` +
    `Modelled: of an estimated ${num(h.future.totalDataAtRiskTb)} TB of data in scope, about ${num(h.future.projectedDecryptableTb)} TB would be decryptable once a cryptographically relevant quantum computer exists. ` +
    'The terabyte figures are a model built from per-asset-class volume assumptions × the measured vulnerable share — a sizing aid, not a measurement of your data.'
  return {
    ...base('future_decryptable'),
    headline,
    keyFindings: [
      `HNDL risk ${num(h.data.hndlScore)}/100 (${str(h.data.hndlLevel)}); threat level ${str(h.data.threatLevel)}.`,
      `Quantum exposure window: ${str(h.data.exposureWindow)}.`,
    ],
    entities: [],
    recommendations: [{
      title: 'Shrink the decryptable share at the source',
      detail: 'Every component moved to ML-KEM hybrid key establishment lowers the vulnerable share — the only measured input to this estimate.',
      priority: 'high',
      standards: [STANDARDS.FIPS_203, STANDARDS.IETF_HYBRID],
      deepLink: modulePath('harvest_now'),
    }],
    nextActions: [{ label: 'Open Harvest Now (HNDL)', path: modulePath('harvest_now'), reason: 'See the model inputs and data lifetimes.' }],
    risk: { level: riskFromLevel(str(h.data.threatLevel)), score: num(h.data.hndlScore), drivers: [`${num(h.future.vulnerableSharePct)}% vulnerable components`] },
    figures: hndlFigures(h),
  }
}

function composeHndlReduction(d: FocusInput): FocusAnswer {
  const h = readHndl(d)
  const v = readQueue(d)
  if (!h && !v) return unavailable(d, 'hndl_reduction', 'getHarvestNowExposure', 'Harvest Now (HNDL)', 'harvest_now', 'what reduces your HNDL exposure fastest')
  if (h && h.data.hasData !== true) return hndlNoData('hndl_reduction')
  const hndlActions = v ? v.rows.filter((a) => a.hndlRelevant) : []
  const modelled = arr<{ label: string; riskReductionPct: number; effort: string; affectedAssets: number }>(h?.data.modelledActions)
  const top = hndlActions[0]
  const headline = top
    ? `Fastest measured path: ${top.asset} — ${top.recommendation}. It is the highest-ranked HNDL-relevant action (${why(top)}). ` +
      `${hndlActions.length > 1 ? `Then ${list(hndlActions.slice(1, 4).map((a) => a.asset), 3)}. ` : ''}` +
      `${h && h.fs.hasEvidence === true && num(h.fs.componentsWithoutPfs) ? `Enforcing forward secrecy on the ${num(h.fs.componentsWithoutPfs)} non-forward-secret key exchange(s) is the cheapest immediate reduction.` : ''}`
    : 'No open remediation action is HNDL-relevant in the current queue. The HNDL module\'s modelled levers are listed below — they are estimates, not measured gains.'
  return {
    ...base('hndl_reduction'),
    headline: headline.replace(/\s+/g, ' ').trim(),
    keyFindings: [
      ...(h ? [`Current HNDL risk: ${num(h.data.hndlScore)}/100 (${str(h.data.threatLevel)}).`] : []),
      ...(modelled.length ? [`HNDL module levers (modelled estimates): ${list(modelled.map((m) => `${m.label} ~${Math.round(m.riskReductionPct)}%`), 4)}.`] : []),
    ],
    entities: hndlActions.length ? [actionTable('HNDL-relevant remediation — in execution order', hndlActions, hndlActions.length)] : [],
    recommendations: top ? [{
      title: `Start with ${top.asset}`,
      detail: `${top.recommendation} → ${top.targetState}.`,
      priority: 'immediate',
      standards: top.standards.length ? top.standards : [STANDARDS.FIPS_203, STANDARDS.IETF_HYBRID],
      deepLink: top.route,
    }] : [],
    nextActions: [{ label: 'Open Harvest Now (HNDL)', path: modulePath('harvest_now'), reason: 'Exposure matrix and remediation center.' }],
    risk: h ? { level: riskFromLevel(str(h.data.threatLevel)), score: num(h.data.hndlScore), drivers: [`${hndlActions.length} HNDL-relevant action(s)`] } : undefined,
    figures: h ? hndlFigures(h) : [],
  }
}

/* ------------------------------------------------------------------ */
/* Compliance                                                          */
/* ------------------------------------------------------------------ */

const METHODOLOGY_NOTE = 'Review the scope and coverage of your mapped controls. The observations do not establish compliance or module validation.'

function composeCompliance(d: FocusInput): FocusAnswer {
  const status = d.tool('getComplianceStatus')
  if (!status) return unavailable(d, 'compliance_posture', 'getComplianceStatus', 'the Compliance Center', 'compliance', 'your compliance posture')
  const frameworks = arr<{ framework: string; status: string; signal: string }>(status.data.frameworks)
  const aligned = frameworks.filter((f) => f.status === 'mapped checks met')
  const cnsa = d.tool('getCNSACompliance')
  const nist = d.tool('getNISTScore')
  const cert = d.tool('getCertificationStatus')
  const headline =
    `Governance evidence: ${list(frameworks.map((f) => `${f.framework.split(' (')[0]} — ${f.status}`), 4)}. ` +
    `${cnsa && cnsa.data.dataAvailable === true ? `CNSA 2.0: ${num(cnsa.data.met)}/${num(cnsa.data.total)} selected algorithm signals observed. ` : ''}` +
    `${cert ? (cert.data.certified === true ? 'Quantum Trust Certification is active. ' : 'Quantum Trust Certification has not been issued. ') : ''}` +
    METHODOLOGY_NOTE
  return {
    ...base('compliance_posture'),
    headline: headline.replace(/\s+/g, ' ').trim(),
    keyFindings: [
      ...(nist ? [`NIST PQC adoption: FIPS 203 ×${num(nist.data.fips203Components)}, FIPS 204 ×${num(nist.data.fips204Components)}, FIPS 205 ×${num(nist.data.fips205Components)} component(s); ${num(nist.data.vulnerableComponents)} quantum-vulnerable component(s) remain.`] : []),
      ...frameworks.filter((f) => f.status !== 'mapped checks met').map((f) => `${f.framework}: ${f.status} (${f.signal}).`),
    ],
    entities: [{
      title: 'Framework posture',
      unit: 'framework',
      columns: [{ key: 'framework', label: 'Framework' }, { key: 'status', label: 'Status' }, { key: 'signal', label: 'Evidence signal' }],
      rows: frameworks.map((f) => ({ cells: { framework: f.framework, status: f.status, signal: f.signal }, tone: f.status === 'mapped checks met' ? 'good' : /gap/.test(f.status) ? 'high' : 'medium', deepLink: modulePath('compliance') })),
      total: frameworks.length,
      source: 'Compliance Center',
      deepLink: modulePath('compliance'),
      note: METHODOLOGY_NOTE,
    }],
    recommendations: [],
    nextActions: [{ label: 'Open the Compliance Center', path: modulePath('compliance'), reason: 'Per-control evidence and mappings.' }],
    risk: { level: aligned.length === frameworks.length ? 'low' : 'medium', drivers: frameworks.filter((f) => f.status !== 'mapped checks met').map((f) => `${f.framework.split(' (')[0]}: ${f.status}`).slice(0, 3) },
    figures: [
      figure('compliance.aligned', 'Framework mappings with all checks met', aligned.length, 'higher', 'Compliance Center'),
      ...(cnsa && cnsa.data.dataAvailable === true ? [figure('compliance.cnsaMet', 'CNSA 2.0 algorithm signals observed', num(cnsa.data.met), 'higher', 'Compliance Center')] : []),
    ],
  }
}

function composeCnsa(d: FocusInput): FocusAnswer {
  const r = d.tool('getCNSACompliance')
  if (!r) return unavailable(d, 'cnsa', 'getCNSACompliance', 'the Compliance Center', 'compliance', 'your CNSA 2.0 alignment')
  if (r.data.dataAvailable !== true) {
    return { ...base('cnsa'), headline: 'CNSA 2.0 alignment has not been measured: there is no cryptographic inventory yet. Run a discovery scan first.', risk: { level: 'info', drivers: [] }, noData: true, nextActions: [{ label: 'Run a discovery scan', path: modulePath('scanner'), reason: 'CNSA checks read the algorithm inventory.' }] }
  }
  const checks = arr<{ requirement: string; met: boolean }>(r.data.checks)
  const missing = checks.filter((c) => !c.met)
  return {
    ...base('cnsa'),
    headline: missing.length
      ? `The inventory records ${num(r.data.met)} of ${num(r.data.total)} selected CNSA 2.0 algorithm signals. Not observed: ${list(missing.map((c) => c.requirement), 5)}.`
      : `All ${num(r.data.total)} selected CNSA 2.0 algorithm signals appeared in the inventory.`,
    keyFindings: ['CNSA 2.0 applies to National Security Systems. Inventory presence does not show applicable system scope, usage coverage, conformance, or compliance.'],
    entities: [{
      title: 'CNSA 2.0 algorithm observations',
      unit: 'check',
      columns: [{ key: 'requirement', label: 'Requirement' }, { key: 'status', label: 'Status' }],
      rows: checks.map((c) => ({ cells: { requirement: c.requirement, status: c.met ? 'Observed' : 'Not observed' }, tone: c.met ? 'good' : 'high', deepLink: modulePath('compliance') })),
      total: checks.length,
      source: 'Compliance Center',
      deepLink: modulePath('compliance'),
    }],
    recommendations: missing.length ? [{
      title: 'Confirm the applicable policy',
      detail: 'If you operate National Security Systems, verify the applicable profile and schedule with your security authority, then check deployment coverage.',
      priority: 'high',
      standards: [STANDARDS.CNSA_2, STANDARDS.FIPS_203, STANDARDS.FIPS_204],
      deepLink: modulePath('compliance'),
    }] : [],
    nextActions: [{ label: 'Open the Compliance Center', path: modulePath('compliance'), reason: 'Track the CNSA 2.0 transition.' }],
    risk: { level: missing.length ? 'medium' : 'low', drivers: missing.length ? [`${missing.length} selected signals not observed`] : [] },
    figures: [figure('compliance.cnsaMet', 'CNSA 2.0 algorithm signals observed', num(r.data.met), 'higher', 'Compliance Center')],
  }
}

function composeNist(d: FocusInput): FocusAnswer {
  const r = d.tool('getNISTScore')
  if (!r) return unavailable(d, 'nist_alignment', 'getNISTScore', 'the Compliance Center', 'compliance', 'your NIST PQC alignment')
  const data = r.data
  const adopted = num(data.fips203Components) + num(data.fips204Components) + num(data.fips205Components)
  return {
    ...base('nist_alignment'),
    headline:
      `NIST post-quantum adoption: FIPS 203 (ML-KEM) in ${count(num(data.fips203Components), 'component')}, FIPS 204 (ML-DSA) in ${num(data.fips204Components)}, FIPS 205 (SLH-DSA) in ${num(data.fips205Components)}. ` +
      `${num(data.vulnerableComponents)} quantum-vulnerable component(s) still need replacing; PQC adoption is ${num(data.pqcAdoption)}% and readiness ${num(data.readiness)}/100.` +
      `${adopted === 0 ? ' No standardized PQC algorithm label was found in the queried inventory.' : ''}`,
    keyFindings: ['ML-KEM is for key establishment; ML-DSA and SLH-DSA are for signatures. An inventory label alone does not establish conformance or FIPS module validation.'],
    entities: [{
      title: 'NIST post-quantum standards — adoption in your inventory',
      unit: 'standard',
      columns: [{ key: 'standard', label: 'Standard' }, { key: 'algorithm', label: 'Algorithm' }, { key: 'role', label: 'Replaces' }, { key: 'components', label: 'Components', align: 'right' }],
      rows: [
        { standard: 'FIPS 203', algorithm: 'ML-KEM', role: 'RSA / ECDH key establishment', components: num(data.fips203Components) },
        { standard: 'FIPS 204', algorithm: 'ML-DSA', role: 'RSA / ECDSA signatures', components: num(data.fips204Components) },
        { standard: 'FIPS 205', algorithm: 'SLH-DSA', role: 'Signatures (stateless hash-based)', components: num(data.fips205Components) },
      ].map((s) => ({ cells: s, tone: s.components > 0 ? 'good' as CopilotTone : 'neutral' as CopilotTone, deepLink: modulePath('compliance') })),
      total: 3,
      source: 'Compliance Center',
      deepLink: modulePath('compliance'),
    }],
    recommendations: [{
      title: adopted ? 'Extend ML-KEM / ML-DSA coverage' : 'Introduce ML-KEM and ML-DSA',
      detail: 'Start with hybrid key establishment (X25519 + ML-KEM-768) on internet-facing TLS, then ML-DSA certificate chains from the roots down.',
      priority: 'high',
      standards: [STANDARDS.FIPS_203, STANDARDS.FIPS_204, STANDARDS.FIPS_205],
      deepLink: modulePath('remediation'),
    }],
    nextActions: [{ label: 'Open the Compliance Center', path: modulePath('compliance'), reason: 'NIST alignment evidence.' }],
    risk: { level: num(data.vulnerableComponents) ? 'medium' : 'low', drivers: [`${num(data.vulnerableComponents)} vulnerable component(s)`] },
    figures: [
      figure('readiness.pqcAdoption', 'PQC adoption', num(data.pqcAdoption), 'higher', 'Quantum Readiness Assessment Engine™', '%'),
      figure('cbom.vulnerable', 'Quantum-vulnerable components', num(data.vulnerableComponents), 'lower', 'CBOM Explorer'),
    ],
  }
}

/* ------------------------------------------------------------------ */
/* Certificates                                                        */
/* ------------------------------------------------------------------ */

function certStatus(c: CertificateView): string {
  if (c.expired) return `Expired ${Math.abs(c.daysRemaining ?? 0)} d ago`
  const parts: string[] = []
  if (c.expiringSoon && c.daysRemaining !== null) parts.push(`Expires in ${c.daysRemaining} d`)
  if (c.weakReasons.length) parts.push(`Weak: ${c.weakReasons[0]}`)
  if (c.quantum === 'vulnerable') parts.push('Quantum-vulnerable')
  if (c.quantum === 'unknown') parts.push('PQC status unknown')
  return parts.join(' · ') || 'OK'
}

function composeCertificates(d: FocusInput): FocusAnswer {
  const r = d.tool('getCertificates')
  if (!r) return unavailable(d, 'certificates', 'getCertificates', 'PKI Visibility', 'pki', 'which certificates need attention')
  const data = r.data
  const total = num(data.total)
  if (total === 0) {
    return { ...base('certificates'), headline: 'No certificates are recorded in your inventory yet — run a TLS / PKI scan to discover them. This is an absence of evidence, not a clean bill of health.', risk: { level: 'info', drivers: [] }, noData: true, nextActions: [{ label: 'Run a discovery scan', path: modulePath('scanner'), reason: 'Certificates are discovered by scanning.' }] }
  }
  const q = d.question.toLowerCase()
  const wantsExpiry = /expir|renew|valid until|lifetime/.test(q) || num(data.withinDays) > 0
  const wantsWeak = /\bweak|sha-?1|md5|key size|short key/.test(q)
  const wantsQuantum = /quantum|pqc|vulnerab|rsa|ecdsa|ecc/.test(q)
  const none = !wantsExpiry && !wantsWeak && !wantsQuantum
  const pick: CertificateView[] = []
  const add = (items: CertificateView[]) => { for (const c of items) if (!pick.some((p) => p.name === c.name && p.notAfter === c.notAfter)) pick.push(c) }
  if (wantsExpiry || none) { add(arr<CertificateView>(data.expiredList)); add(arr<CertificateView>(data.expiringList)) }
  if (wantsWeak || none) add(arr<CertificateView>(data.weakList))
  if (wantsQuantum || none) add(arr<CertificateView>(data.vulnerableList))
  const rows = scoped(pick, d.assetScope, (c) => c.asset)
  const windowDays = num(data.withinDays)
  const parts: string[] = []
  if (wantsExpiry || none) parts.push(`${num(data.expired)} expired and ${num(data.expiringSoon)} expiring ${windowDays ? `within ${windowDays} days` : 'soon'}`)
  if (wantsWeak || none) parts.push(`${num(data.weak)} weak (short keys or SHA-1/MD5 signatures)`)
  if (wantsQuantum || none) parts.push(`${num(data.quantumVulnerable)} quantum-vulnerable (RSA/ECC signatures)`)
  const headline =
    `Of your ${count(total, 'certificate')}${scopeNote(d.assetScope)}: ${list(parts, 3)}. ` +
    `${rows.length ? `Most urgent: ${list(rows.slice(0, 3).map((c) => `${c.name}${c.asset ? ` on ${c.asset}` : ''} (${certStatus(c)})`), 3)}.` : 'None match those conditions.'}` +
    `${num(data.quantumUnknown) ? ` ${num(data.quantumUnknown)} certificate(s) have no recorded PQC status and are reported as unknown, not as safe.` : ''}`
  return {
    ...base('certificates'),
    headline: headline.replace(/\s+/g, ' ').trim(),
    keyFindings: [
      `${total} certificate(s) in inventory; ${num(data.expired)} expired, ${num(data.expiringSoon)} expiring${windowDays ? ` within ${windowDays} days` : ' soon'}, ${num(data.weak)} weak, ${num(data.quantumVulnerable)} quantum-vulnerable.`,
    ],
    entities: rows.length ? [{
      title: 'Certificates needing attention',
      unit: 'certificate',
      columns: [
        { key: 'name', label: 'Certificate' },
        { key: 'asset', label: 'Asset' },
        { key: 'algorithm', label: 'Algorithm' },
        { key: 'expires', label: 'Expires' },
        { key: 'status', label: 'Status' },
        { key: 'issuer', label: 'Issuer' },
      ],
      rows: rows.slice(0, 25).map((c) => ({
        cells: { name: c.name, asset: c.asset || '—', algorithm: `${c.algorithm}${c.keySize ? ` (${c.keySize})` : ''}`, expires: dateOnly(c.notAfter), status: certStatus(c), issuer: c.issuer },
        tone: c.expired ? 'critical' : c.weakReasons.length ? 'high' : c.expiringSoon ? 'medium' : c.quantum === 'vulnerable' ? 'medium' : 'neutral',
        deepLink: modulePath('pki'),
      })),
      total: rows.length,
      source: 'PKI Visibility',
      deepLink: modulePath('pki'),
    }] : [],
    recommendations: [{
      title: num(data.expired) ? 'Replace the expired certificates now' : 'Re-issue on renewal with ML-DSA or hybrid chains',
      detail: 'Renew from an upgraded issuing CA so you migrate each certificate once: ML-DSA (FIPS 204) or a hybrid chain, roots and intermediates first.',
      priority: num(data.expired) ? 'immediate' : 'high',
      standards: [STANDARDS.FIPS_204, STANDARDS.SP_800_57, STANDARDS.CNSA_2],
      deepLink: modulePath('pki'),
    }],
    nextActions: [{ label: 'Open PKI Visibility', path: modulePath('pki'), reason: 'Every certificate with chain and expiry.' }],
    risk: { level: num(data.expired) ? 'high' : num(data.weak) ? 'high' : num(data.quantumVulnerable) ? 'medium' : 'low', drivers: [`${num(data.expired)} expired`, `${num(data.quantumVulnerable)} quantum-vulnerable`] },
    figures: [
      figure('pki.expired', 'Expired certificates', num(data.expired), 'lower', 'PKI Visibility'),
      figure('pki.quantumVulnerable', 'Quantum-vulnerable certificates', num(data.quantumVulnerable), 'lower', 'PKI Visibility'),
    ],
  }
}

function composeCertificateIssuers(d: FocusInput): FocusAnswer {
  const r = d.tool('getCertificates')
  if (!r) return unavailable(d, 'certificate_issuers', 'getCertificates', 'PKI Visibility', 'pki', 'which issuers anchor your trust chains')
  const issuers = arr<{ issuer: string; certificates: number; quantumSafe: number }>(r.data.issuers)
  if (!issuers.length) return { ...base('certificate_issuers'), headline: 'No certificates — and therefore no issuers — are recorded yet. Run a TLS / PKI scan to map your trust anchors.', noData: true, risk: { level: 'info', drivers: [] } }
  const top = issuers[0]
  return {
    ...base('certificate_issuers'),
    headline: `${count(issuers.length, 'certificate authority', 'certificate authorities')} anchor your certificates. The largest is ${top.issuer} with ${count(top.certificates, 'certificate')} (${top.quantumSafe} quantum-safe). Migrating an issuing CA to ML-DSA first keeps every certificate it issues trusted through the change.`,
    keyFindings: issuers.slice(0, 5).map((i) => `${i.issuer}: ${i.certificates} certificate(s), ${i.quantumSafe} quantum-safe.`),
    entities: [{
      title: 'Issuing authorities',
      unit: 'issuer',
      columns: [{ key: 'issuer', label: 'Issuer' }, { key: 'certificates', label: 'Certificates', align: 'right' }, { key: 'safe', label: 'Quantum-safe', align: 'right' }],
      rows: issuers.map((i) => ({ cells: { issuer: i.issuer, certificates: i.certificates, safe: i.quantumSafe }, tone: i.quantumSafe === i.certificates ? 'good' : 'medium', deepLink: modulePath('pki') })),
      total: issuers.length,
      source: 'PKI Visibility',
      deepLink: modulePath('pki'),
    }],
    recommendations: [{
      title: `Upgrade ${top.issuer} first`,
      detail: 'Roots and issuing CAs migrate before the leaf certificates that chain to them — otherwise clients fail path validation.',
      priority: 'high',
      standards: [STANDARDS.FIPS_204, STANDARDS.SP_800_57],
      deepLink: modulePath('pki'),
    }],
    nextActions: [{ label: 'Open PKI Visibility', path: modulePath('pki'), reason: 'Chains and trust anchors.' }],
    figures: [],
  }
}

/* ------------------------------------------------------------------ */
/* Algorithms                                                          */
/* ------------------------------------------------------------------ */

function composeAlgorithms(d: FocusInput): FocusAnswer {
  const r = d.tool('getAlgorithms')
  if (!r) return unavailable(d, 'algorithms', 'getAlgorithms', 'CBOM Explorer', 'cbom', 'which algorithms were discovered')
  const algos = arr<{ algorithm: string; count: number; vulnerable: number; quantumSafe: number }>(r.data.algorithms)
  const excluded = num(r.data.policyRowsExcluded)
  if (!algos.length) {
    return { ...base('algorithms'), headline: `No cryptographic algorithm is recorded in your inventory yet${excluded ? ` (${excluded} inventory row(s) are scanner findings, not algorithms)` : ''}. Run a discovery scan to build the CBOM.`, noData: true, risk: { level: 'info', drivers: [] } }
  }
  const wantsVulnerable = /vulnerab|quantum|weak|risk|unsafe|legacy/.test(d.question.toLowerCase())
  const vulnerable = algos.filter((a) => a.vulnerable > 0)
  const shown = wantsVulnerable ? vulnerable : algos
  const cbom = d.tool('getCBOM')
  const headline = wantsVulnerable
    ? `${count(vulnerable.length, 'algorithm')} of the ${algos.length} observed carry quantum-vulnerable components: ${list(vulnerable.map((a) => `${a.algorithm} (${a.vulnerable} component${a.vulnerable === 1 ? '' : 's'})`), 5)}.`
    : `${count(algos.length, 'distinct algorithm')} ${algos.length === 1 ? 'is' : 'are'} in use; the most common are ${list(algos.slice(0, 4).map((a) => `${a.algorithm} (${a.count})`), 4)}. ${count(vulnerable.length, 'of them carries', 'of them carry')} quantum-vulnerable components.`
  return {
    ...base('algorithms'),
    headline: `${headline}${cbom ? ` Across the CBOM: ${num(cbom.data.cryptoComponents)} components, ${num(cbom.data.vulnerableComponents)} quantum-vulnerable, ${num(cbom.data.pqcReadyComponents)} PQC-ready.` : ''}`,
    keyFindings: [
      'RSA, ECDSA/EdDSA and (EC)DH are breakable by Shor\'s algorithm on a large quantum computer; AES-256 and SHA-384+ remain strong (Grover only halves symmetric strength).',
      ...(excluded ? [`${excluded} inventory row(s) are scanner findings (e.g. "No Certificate Pinning"), excluded because they are not algorithms.`] : []),
    ],
    entities: [{
      title: wantsVulnerable ? 'Quantum-vulnerable algorithms' : 'Algorithms observed',
      unit: 'algorithm',
      columns: [
        { key: 'algorithm', label: 'Algorithm' },
        { key: 'count', label: 'Components', align: 'right' },
        { key: 'vulnerable', label: 'Quantum-vulnerable', align: 'right' },
        { key: 'safe', label: 'PQC-safe', align: 'right' },
      ],
      rows: shown.map((a) => ({ cells: { algorithm: a.algorithm, count: a.count, vulnerable: a.vulnerable, safe: a.quantumSafe }, tone: a.vulnerable > 0 ? 'high' : a.quantumSafe > 0 ? 'good' : 'neutral', deepLink: modulePath('cbom') })),
      total: shown.length,
      source: 'CBOM Explorer',
      deepLink: modulePath('cbom'),
    }],
    recommendations: vulnerable.length ? [{
      title: 'Replace the vulnerable primitives by role',
      detail: 'Key establishment → ML-KEM (FIPS 203), signatures → ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); run hybrid where peers lag.',
      priority: 'high',
      standards: [STANDARDS.FIPS_203, STANDARDS.FIPS_204, STANDARDS.FIPS_205],
      deepLink: modulePath('cbom'),
    }] : [],
    nextActions: [{ label: 'Open CBOM Explorer', path: modulePath('cbom'), reason: 'Every component by algorithm.' }],
    risk: { level: vulnerable.length ? 'high' : 'low', drivers: vulnerable.length ? [`${vulnerable.length} vulnerable algorithm(s)`] : [] },
    figures: cbom ? [figure('cbom.vulnerable', 'Quantum-vulnerable components', num(cbom.data.vulnerableComponents), 'lower', 'CBOM Explorer')] : [],
  }
}

/* ------------------------------------------------------------------ */
/* Assets                                                              */
/* ------------------------------------------------------------------ */

const PQC_TONE: Record<string, CopilotTone> = { 'quantum-vulnerable': 'high', 'needs-review': 'medium', 'not-measured': 'neutral', 'pqc-ready': 'good' }

function assetTable(title: string, rows: AssetView[], total: number, note?: string): CopilotEntityTable {
  return {
    title,
    unit: 'asset',
    columns: [
      { key: 'name', label: 'Asset' },
      { key: 'status', label: 'PQC status' },
      { key: 'risk', label: 'Risk', align: 'right' },
      { key: 'vulnerable', label: 'Vulnerable / components', align: 'right' },
      { key: 'exposure', label: 'Exposure' },
      { key: 'owner', label: 'Owner' },
      { key: 'scanned', label: 'Last scanned' },
    ],
    rows: rows.slice(0, 20).map((a) => ({
      cells: {
        name: a.name,
        status: a.pqcStatusLabel,
        risk: a.riskScore === null ? 'Not assessed' : `${a.riskScore}/100`,
        vulnerable: `${a.components.vulnerable} / ${a.components.total}`,
        exposure: a.internetFacing ? 'Internet-facing' : 'Internal',
        owner: a.owner || 'Unassigned',
        scanned: a.freshness,
      },
      tone: PQC_TONE[a.pqcStatus] || 'neutral',
      deepLink: modulePath('assets'),
    })),
    total,
    source: 'Assets & CBOM',
    deepLink: modulePath('assets'),
    note,
  }
}

function registerFigures(data: Record<string, unknown>): CopilotFigure[] {
  const pqc = rec(data.pqcStatus)
  return [
    figure('assets.total', 'Assets in the register', num(data.totalAssets), 'neutral', 'Assets & CBOM'),
    figure('assets.vulnerable', 'Quantum-vulnerable assets', num(pqc['quantum-vulnerable']), 'lower', 'Assets & CBOM'),
    figure('assets.pqcReady', 'PQC-ready assets', num(pqc['pqc-ready']), 'higher', 'Assets & CBOM'),
  ]
}

function describeAsset(a: AssetView): string {
  const risk = a.riskScore === null ? 'Its risk is not assessed' : `It carries risk ${a.riskScore}/100 (${a.riskBand})`
  // Only the VULNERABLE primitives are named here — listing every algorithm
  // after "are quantum-vulnerable" put AES-256-GCM in that list.
  const vulnerable = [...new Set(a.vulnerableComponents.map((c) => c.riskBearing || c.name))]
  return `${a.name} is ${a.pqcStatusLabel.toLowerCase()} — ${clause(a.pqcStatusReason)}. ${risk}${vulnerable.length ? `; the quantum-vulnerable primitives are ${list(vulnerable, 4)}` : ''}.`
}

function composeAssetDossier(d: FocusInput): FocusAnswer {
  const register = d.tool('getAssetRegister')
  if (!register) return unavailable(d, 'asset_dossier', 'getAssetRegister', 'Assets & CBOM', 'assets', 'that asset\'s status')
  const matched = d.assetScope.length ? d.assetScope : arr<AssetView>(register.data.matched)
  if (!matched.length) return composeAssetsList(d)
  const a = matched[0]
  const queue = readQueue({ ...d, assetScope: [a] })
  const certs = d.tool('getCertificates')
  const assetCerts = arr<CertificateView>(certs?.data.sample).filter((c) => c.asset === a.name)
  const keyFindings = [
    `Owner: ${a.owner || 'not recorded — assign one so remediation has an accountable team'}. ${a.internetFacing ? 'Internet-facing' : 'Internal'}${a.environment ? ` · ${a.environment}` : ''}${a.criticality ? ` · ${a.criticality} criticality` : ''}${a.tlsVersion ? ` · ${a.tlsVersion}` : ''}.`,
    `Last scanned ${a.freshness}${a.freshnessState === 'stale' ? ' — stale; rescan before treating this as current' : ''}${a.scanning ? ' (a scan is running now)' : ''}.`,
    ...(a.lifecycle ? [`Migration lifecycle: ${a.lifecycle.label}; ${count(a.lifecycle.openActions, 'open action')}; validation ${a.lifecycle.validationStatus}.`] : []),
    ...(queue ? [queue.rows.length ? `${count(queue.rows.length, 'remediation action')} pending — first: ${queue.rows[0].recommendation} (${queue.rows[0].priority}).` : 'No remediation action is pending for this asset.'] : []),
    ...(assetCerts.length ? [`${count(assetCerts.length, 'certificate')}: ${list(assetCerts.map((c) => `${c.name} (${certStatus(c)})`), 3)}.`] : []),
  ]
  const others = matched.slice(1)
  return {
    ...base('asset_dossier'),
    headline: `${describeAsset(a)}${others.length ? ` I also matched ${list(others.map((o) => o.name), 3)} — ask about one by name for its detail.` : ''}`,
    keyFindings,
    entities: [
      ...(a.vulnerableComponents.length ? [{
        title: `${a.name} — quantum-vulnerable components`,
        unit: 'component',
        columns: [
          { key: 'name', label: 'Component' },
          { key: 'risk', label: 'Risk-bearing primitive' },
          { key: 'severity', label: 'Severity' },
          { key: 'target', label: 'PQC replacement' },
        ],
        rows: a.vulnerableComponents.map((c) => ({ cells: { name: c.name, risk: c.riskBearing, severity: c.severity, target: c.pqcReplacement || '—' }, tone: PRIORITY_TONE[c.severity] || 'high', deepLink: modulePath('assets') })),
        total: a.components.vulnerable,
        source: 'Assets & CBOM',
        deepLink: modulePath('assets'),
      }] : []),
      ...(queue && queue.rows.length ? [actionTable(`${a.name} — pending remediation`, queue.rows, queue.rows.length)] : []),
    ],
    recommendations: queue && queue.rows.length ? [{
      title: `Next step for ${a.name}`,
      detail: `${queue.rows[0].recommendation} → ${queue.rows[0].targetState}. Rollback: ${queue.rows[0].rollback}`,
      priority: queue.rows[0].priority === 'critical' ? 'immediate' : 'high',
      standards: queue.rows[0].standards.length ? queue.rows[0].standards : [STANDARDS.FIPS_203],
      deepLink: queue.rows[0].route,
    }] : a.pqcStatus === 'not-measured' ? [{
      title: `Scan ${a.name}`,
      detail: 'Its cryptography has not been measured, so its PQC status is unknown — not safe.',
      priority: 'high',
      standards: [STANDARDS.NIST_CSF],
      deepLink: modulePath('scanner'),
    }] : [],
    nextActions: [{ label: 'Open Assets & CBOM', path: modulePath('assets'), reason: `Full register row for ${a.name}.` }],
    risk: { level: a.riskScore === null ? 'info' : riskFromScore(a.riskScore), score: a.riskScore ?? undefined, drivers: [`${a.components.vulnerable} vulnerable component(s)`, a.internetFacing ? 'internet-facing' : ''].filter(Boolean) },
    figures: [
      figure(`asset.${a.id}.vulnerableComponents`, `${a.name}: vulnerable components`, a.components.vulnerable, 'lower', 'Assets & CBOM'),
      ...(a.riskScore !== null ? [figure(`asset.${a.id}.risk`, `${a.name}: risk score`, a.riskScore, 'lower', 'Assets & CBOM', '/100')] : []),
    ],
  }
}

function composeAssetsList(d: FocusInput): FocusAnswer {
  const r = d.tool('getAssetRegister')
  if (!r) return unavailable(d, 'assets_list', 'getAssetRegister', 'Assets & CBOM', 'assets', 'which assets match')
  const all = arr<AssetView>(r.data.rows)
  if (!all.length) return { ...base('assets_list'), headline: 'Your asset register is empty — no asset has been discovered yet. Run a discovery scan or connect a cloud connector.', noData: true, risk: { level: 'info', drivers: [] }, nextActions: [{ label: 'Run a discovery scan', path: modulePath('scanner'), reason: 'Discover assets.' }] }
  const q = d.question.toLowerCase()
  // Each criterion carries its predicate in both numbers, so the sentence
  // agrees with its count ("1 asset has no owner", "2 assets are internet-facing").
  const criteria: Array<{ label: string; phrase: (n: number) => string; test: (a: AssetView) => boolean }> = []
  const be = (n: number, rest: string) => `${isAre(n)} ${rest}`
  const have = (n: number, rest: string) => `${n === 1 ? 'has' : 'have'} ${rest}`
  if (d.filter.internetFacing || /internet|public|external/.test(q)) criteria.push({ label: 'internet-facing', phrase: (n) => be(n, 'internet-facing'), test: (a) => a.internetFacing })
  if (/no owner|unowned|without (an )?owner|unassigned|who owns/.test(q)) criteria.push({ label: 'no owner recorded', phrase: (n) => have(n, 'no owner recorded'), test: (a) => !a.owner })
  if (/pqc[- ]ready|quantum[- ]safe|migrated/.test(q)) criteria.push({ label: 'PQC-ready (scanner-validated)', phrase: (n) => be(n, 'PQC-ready (scanner-validated)'), test: (a) => a.pqcStatus === 'pqc-ready' })
  if (/not (been )?(measured|scanned|assessed)|unassessed|unscanned|never scanned/.test(q)) criteria.push({ label: 'not yet measured', phrase: (n) => be(n, 'not yet measured'), test: (a) => a.pqcStatus === 'not-measured' })
  if (/stale|out of date|outdated/.test(q)) criteria.push({ label: 'stale scan', phrase: (n) => have(n, n === 1 ? 'a stale scan' : 'stale scans'), test: (a) => a.freshnessState === 'stale' })
  if (/vulnerable|at risk|exposed/.test(q) && !/pqc[- ]ready/.test(q)) criteria.push({ label: 'quantum-vulnerable', phrase: (n) => be(n, 'quantum-vulnerable'), test: (a) => a.pqcStatus === 'quantum-vulnerable' })
  const rows = all.filter((a) => criteria.every((c) => c.test(a)))
  const scope = criteria.map((c) => c.label).join(' + ')
  const total = criteria.length ? rows.length : num(r.data.totalAssets)
  const pqc = rec(r.data.pqcStatus)
  const headline = criteria.length
    ? rows.length
      ? `${count(rows.length, 'asset')} ${criteria.map((c) => c.phrase(rows.length)).join(' and ')}: ${list(rows.map((a) => a.name), 6)}.`
      : `None of your ${count(num(r.data.totalAssets), 'asset')} match (${scope}) — every asset in the register was checked.`
    : `Your register holds ${count(num(r.data.totalAssets), 'asset')}: ${num(pqc['quantum-vulnerable'])} quantum-vulnerable, ${num(pqc['needs-review'])} needing review, ${num(pqc['not-measured'])} not yet measured and ${num(pqc['pqc-ready'])} PQC-ready; ${num(r.data.internetFacing)} ${isAre(num(r.data.internetFacing))} internet-facing.`
  return {
    ...base('assets_list'),
    headline,
    keyFindings: [
      `Owners: ${num(rec(r.data.owners).assigned)} assigned, ${num(rec(r.data.owners).unassigned)} unassigned.`,
      `Scan freshness: ${num(rec(r.data.freshness).fresh)} fresh, ${num(rec(r.data.freshness).aging)} aging, ${num(rec(r.data.freshness).stale)} stale, ${num(rec(r.data.freshness).unknown)} unknown.`,
    ],
    entities: (criteria.length ? rows : all).length ? [assetTable(criteria.length ? `Assets — ${scope}` : 'Asset register (highest risk first)', criteria.length ? rows : all, total)] : [],
    recommendations: [],
    nextActions: [{ label: 'Open Assets & CBOM', path: modulePath('assets'), reason: 'Filter and export the full register.' }],
    risk: { level: num(pqc['quantum-vulnerable']) ? 'high' : 'low', drivers: [`${num(pqc['quantum-vulnerable'])} quantum-vulnerable asset(s)`] },
    figures: registerFigures(r.data),
  }
}

function composeMostVulnerable(d: FocusInput): FocusAnswer {
  const r = d.tool('getAssetRegister')
  if (!r) return unavailable(d, 'most_vulnerable_assets', 'getAssetRegister', 'Assets & CBOM', 'assets', 'which assets are most vulnerable')
  const all = arr<AssetView>(r.data.rows)
  const assessed = all.filter((a) => a.riskScore !== null && (a.pqcStatus === 'quantum-vulnerable' || a.components.vulnerable > 0 || (a.riskScore ?? 0) > 0))
  if (!assessed.length) {
    const unmeasured = all.filter((a) => a.pqcStatus === 'not-measured').length
    return {
      ...base('most_vulnerable_assets'),
      headline: all.length
        ? `None of your ${count(all.length, 'asset')} has measured quantum-vulnerable cryptography${unmeasured ? `, but ${unmeasured} ${isAre(unmeasured)} not measured yet — their status is unknown, not safe` : ''}.`
        : 'Your asset register is empty — run a discovery scan first.',
      noData: !all.length,
      risk: { level: unmeasured ? 'medium' : 'low', drivers: [] },
      figures: registerFigures(r.data),
      nextActions: [{ label: 'Open Assets & CBOM', path: modulePath('assets'), reason: 'Review every asset.' }],
    }
  }
  const ranked = assessed.slice(0, 10)
  const [top, ...rest] = ranked
  const headline =
    `Your most vulnerable asset is ${top.name}: risk ${top.riskScore}/100 (${top.riskBand}), ${top.pqcStatusLabel.toLowerCase()}, with ${top.components.vulnerable} of ${top.components.total} components quantum-vulnerable${top.internetFacing ? ' and internet-facing' : ''}. ` +
    `${rest.length ? `Next: ${list(rest.slice(0, 4).map((a) => `${a.name} (${a.riskScore}/100)`), 4)}.` : ''}`
  const unmeasured = all.filter((a) => a.pqcStatus === 'not-measured')
  return {
    ...base('most_vulnerable_assets'),
    headline: headline.trim(),
    keyFindings: [
      ...ranked.slice(0, 5).map((a, i) => {
        const vulnerable = [...new Set(a.vulnerableComponents.map((c) => c.riskBearing || c.name))]
        return `${i + 1}. ${a.name} — ${a.riskScore}/100; ${count(a.components.vulnerable, 'vulnerable component')}${vulnerable.length ? ` (${list(vulnerable, 3)})` : ''}; ${a.internetFacing ? 'internet-facing' : 'internal'}; owner ${a.owner || 'unassigned'}.`
      }),
      ...(unmeasured.length ? [`${count(unmeasured.length, 'asset')} ${isAre(unmeasured.length)} not measured yet and cannot be ranked: ${list(unmeasured.map((a) => a.name), 3)}.`] : []),
    ],
    entities: [assetTable('Assets ranked by risk', ranked, assessed.length, 'Risk and PQC status are the Assets page\'s own values for each asset.')],
    recommendations: [{
      title: `Remediate ${top.name} first`,
      detail: `Replace its ${top.components.vulnerable} quantum-vulnerable component(s) with ML-KEM / ML-DSA (hybrid where peers lag)${top.internetFacing ? ' — it is internet-facing, so its traffic is exposed to Harvest-Now capture today' : ''}.`,
      priority: (top.riskScore ?? 0) >= 75 ? 'immediate' : 'high',
      standards: [STANDARDS.FIPS_203, STANDARDS.FIPS_204],
      deepLink: modulePath('remediation'),
    }],
    nextActions: [
      { label: 'Open Assets & CBOM', path: modulePath('assets'), reason: 'Per-asset components and evidence.' },
      { label: 'Show the blast radius', path: modulePath('exposure_graph'), reason: 'What depends on the riskiest asset.' },
    ],
    risk: { level: riskFromScore(top.riskScore ?? 0), score: top.riskScore ?? undefined, drivers: [`${top.name} ${top.riskScore}/100`] },
    figures: registerFigures(r.data),
  }
}

/* ------------------------------------------------------------------ */
/* Graph, dependencies                                                 */
/* ------------------------------------------------------------------ */

function composeBlastRadius(d: FocusInput): FocusAnswer {
  // An empty graph is reported as such before anything is read from the
  // result — an empty result still carries a (blank) payload.
  if (d.status('getBlastRadius') === 'empty' && !str(d.tool('getBlastRadius')?.data.asset)) {
    return { ...base('blast_radius'), headline: 'There is no dependency graph yet (or the asset you named is not in it), so a blast radius cannot be computed — record asset relationships or run discovery that maps dependencies.', noData: true, risk: { level: 'info', drivers: [] } }
  }
  const r = d.tool('getBlastRadius')
  if (!r) return unavailable(d, 'blast_radius', 'getBlastRadius', 'the Quantum Exposure Graph™', 'exposure_graph', 'the blast radius')
  const blast = rec(r.data.blast)
  const direct = arr<string>(r.data.directNames)
  const indirect = arr<string>(r.data.indirectNames)
  const trust = arr<string>(r.data.trustChainNames)
  const total = num(blast.totalAffected)
  const headline = total
    // direct + indirect partition the affected set; "via trust chains" is an
    // overlapping attribute of those same assets, not a third group.
    ? `${str(r.data.asset)}${num(r.data.riskScore) ? ` (risk ${num(r.data.riskScore)}/100)` : ''} has a blast radius of ${count(total, 'dependent asset')}: ${direct.length} direct and ${indirect.length} indirect${trust.length ? `, ${trust.length} of them reached through trust chains` : ''}; ${num(blast.internetFacing)} ${isAre(num(blast.internetFacing))} internet-facing. ${direct.length ? `Directly affected: ${list(direct, 5)}.` : ''}`
    : `${str(r.data.asset)} has no recorded dependents — changing or losing it does not propagate through the mapped graph. (Unmapped relationships are not visible to this analysis.)`
  // A node reached directly AND through a trust edge is one affected asset,
  // not two — listing it twice showed 4 rows for a blast radius of 2.
  const seen = new Set<string>()
  const rows: CopilotEntityRow[] = []
  const addRows = (names: string[], path: string, tone: CopilotTone) => {
    for (const n of names) {
      if (seen.has(n)) continue
      seen.add(n)
      rows.push({ cells: { asset: n, path }, tone })
    }
  }
  addRows(direct, 'Direct dependency', 'high')
  addRows(trust, 'Trust chain', 'medium')
  addRows(indirect, 'Indirect', 'low')
  return {
    ...base('blast_radius'),
    headline: headline.trim(),
    keyFindings: [`Environments affected: ${list(arr<string>(blast.environments), 5) || 'not recorded'}.`, `${num(blast.businessCritical)} business-critical dependent(s).`],
    entities: rows.length ? [{ title: `What depends on ${str(r.data.asset)}`, unit: 'asset', columns: [{ key: 'asset', label: 'Asset' }, { key: 'path', label: 'Relationship' }], rows, total, source: 'Quantum Exposure Graph™', deepLink: modulePath('exposure_graph') }] : [],
    recommendations: total > 5 ? [{
      title: `Migrate ${str(r.data.asset)} early, with a snapshot`,
      detail: 'A wide dependency set means its change propagates — capture a pre-migration snapshot and validate dependents at each stage.',
      priority: 'high',
      standards: [STANDARDS.NIST_CSF, STANDARDS.SP_1800_38],
      deepLink: modulePath('exposure_graph'),
    }] : [],
    nextActions: [{ label: 'Open the Exposure Graph', path: modulePath('exposure_graph'), reason: 'Explore the dependency paths.' }],
    risk: { level: total > 10 ? 'high' : total > 3 ? 'medium' : 'low', drivers: [`${total} dependent(s)`] },
    figures: [],
  }
}

function composeDependencies(d: FocusInput): FocusAnswer {
  const g = d.tool('getExposureGraph')
  if (!g) return unavailable(d, 'dependencies', 'getExposureGraph', 'the Quantum Exposure Graph™', 'exposure_graph', 'your dependency and trust relationships')
  const s = rec(g.data.summary)
  const deps = d.tool('getDependencies')
  const third = arr<{ vendor: string; category: string; connectedAssets: number; readiness: string; riskLevel: string }>(deps?.data.thirdParty)
  const blast = d.tool('getBlastRadius')
  return {
    ...base('dependencies'),
    headline:
      `Your graph maps ${count(num(s.trustRelationships), 'trust relationship')} across ${count(num(s.totalAssets), 'asset')} — ${num(s.criticalTrustRelationships)} critical, ${count(num(s.certificateChains), 'certificate chain')} anchoring authentication, and ${count(third.length || num(s.thirdPartyDependencies), 'third-party dependency', 'third-party dependencies')}. ` +
      `${blast && str(blast.data.asset) && num(rec(blast.data.blast).totalAffected) > 0 ? `The widest blast radius is ${str(blast.data.asset)} with ${count(num(rec(blast.data.blast).totalAffected), 'dependent')}.` : ''}`,
    keyFindings: [
      `${num(s.quantumVulnerable)} quantum-vulnerable asset(s) sit in these paths; ${num(g.data.blockers)} migration blocker(s) identified.`,
      ...(num(s.trustRelationships) === 0 ? ['No relationships are recorded yet — the graph can only show what discovery or your inventory has mapped.'] : []),
    ],
    entities: third.length ? [{
      title: 'Third-party dependencies',
      unit: 'dependency',
      columns: [{ key: 'vendor', label: 'Vendor' }, { key: 'category', label: 'Category' }, { key: 'assets', label: 'Connected assets', align: 'right' }, { key: 'readiness', label: 'PQC readiness' }, { key: 'risk', label: 'Risk' }],
      rows: third.map((t) => ({ cells: { vendor: t.vendor, category: t.category, assets: t.connectedAssets, readiness: t.readiness, risk: t.riskLevel }, tone: PRIORITY_TONE[String(t.riskLevel).toLowerCase()] || 'neutral', deepLink: modulePath('exposure_graph') })),
      total: third.length,
      source: 'Quantum Exposure Graph™',
      deepLink: modulePath('exposure_graph'),
    }] : [],
    recommendations: [],
    nextActions: [{ label: 'Open the Exposure Graph', path: modulePath('exposure_graph'), reason: 'Interactive dependency and trust paths.' }],
    risk: { level: num(s.criticalTrustRelationships) ? 'high' : 'medium', drivers: [`${num(s.criticalTrustRelationships)} critical trust relationship(s)`] },
    figures: [],
  }
}

function composeThirdParties(d: FocusInput): FocusAnswer {
  const r = d.tool('getDependencies')
  if (!r) return unavailable(d, 'third_parties', 'getDependencies', 'the Quantum Exposure Graph™', 'exposure_graph', 'your third-party dependencies')
  const third = arr<{ vendor: string; category: string; connectedAssets: number; connectedAssetNames: string[]; readiness: string; riskLevel: string; migrationCompatibility: string }>(r.data.thirdParty)
  if (!third.length) return { ...base('third_parties'), headline: 'No third-party dependency is recorded in your trust paths. That reflects what discovery has mapped — vendors reached only through unmapped integrations are not visible here.', risk: { level: 'info', drivers: [] }, noData: true }
  const notReady = third.filter((t) => !/pqc|ready|safe/i.test(t.readiness))
  return {
    ...base('third_parties'),
    headline: `${count(num(r.data.thirdPartyCount) || third.length, 'third-party dependency', 'third-party dependencies')} ${(num(r.data.thirdPartyCount) || third.length) === 1 ? 'sits' : 'sit'} in your trust paths${notReady.length ? `; ${notReady.length} ${isAre(notReady.length)} not yet PQC-ready (${list(notReady.map((t) => t.vendor), 4)})` : ''}. Your migration depends on their readiness — coordinate hybrid support before cutting over the assets that connect to them.`,
    keyFindings: third.slice(0, 5).map((t) => `${t.vendor} (${t.category}) — ${t.connectedAssets} connected asset(s)${t.connectedAssetNames?.length ? `: ${list(t.connectedAssetNames, 3)}` : ''}; readiness ${t.readiness}.`),
    entities: [{
      title: 'Third-party dependencies',
      unit: 'dependency',
      columns: [{ key: 'vendor', label: 'Vendor' }, { key: 'category', label: 'Category' }, { key: 'assets', label: 'Connected assets', align: 'right' }, { key: 'readiness', label: 'PQC readiness' }, { key: 'compat', label: 'Migration compatibility' }],
      rows: third.map((t) => ({ cells: { vendor: t.vendor, category: t.category, assets: t.connectedAssets, readiness: t.readiness, compat: t.migrationCompatibility }, tone: PRIORITY_TONE[String(t.riskLevel).toLowerCase()] || 'neutral', deepLink: modulePath('exposure_graph') })),
      total: num(r.data.thirdPartyCount) || third.length,
      source: 'Quantum Exposure Graph™',
      deepLink: modulePath('exposure_graph'),
    }],
    recommendations: notReady.length ? [{
      title: 'Engage the not-ready vendors',
      detail: `Request PQC roadmaps and hybrid (X25519 + ML-KEM) support from ${list(notReady.map((t) => t.vendor), 3)}.`,
      priority: 'medium',
      standards: [STANDARDS.IETF_HYBRID, STANDARDS.NIST_CSF],
      deepLink: modulePath('exposure_graph'),
    }] : [],
    nextActions: [{ label: 'Open the Exposure Graph', path: modulePath('exposure_graph'), reason: 'Vendor paths and blast radius.' }],
    risk: { level: notReady.length ? 'medium' : 'low', drivers: [`${notReady.length} not-ready vendor(s)`] },
    figures: [],
  }
}

/* ------------------------------------------------------------------ */
/* Findings & scans                                                    */
/* ------------------------------------------------------------------ */

function whyAlgorithm(algorithm: string, title: string): string {
  const family = algorithmFamily(algorithm || title)
  if (['rsa', 'ecdsa', 'ecdh', 'dh', 'dsa'].includes(family)) return 'Public-key cryptography breakable by Shor\'s algorithm — recorded traffic is harvestable now.'
  if (['sha1', 'md5'].includes(family)) return 'Collision-broken hash — already weak without a quantum computer.'
  if (['3des', 'des', 'rc4'].includes(family)) return 'Classically weak cipher — deprecated today.'
  return 'Rated critical by the scanner from the observed configuration.'
}

function composeCriticalFindings(d: FocusInput): FocusAnswer {
  const r = d.tool('getRiskAnalysis')
  if (!r) return unavailable(d, 'critical_findings', 'getRiskAnalysis', 'Quantum Risk Analysis', 'risk_analysis', 'which findings are critical')
  const dist = rec(r.data.distribution)
  const findings = scoped(arr<{ title: string; asset: string; algorithm: string; severity: string; instances: number; environment: string }>(r.data.criticalFindings), d.assetScope, (f) => f.asset)
  const critical = num(dist.critical)
  if (!critical && !num(dist.high) && !findings.length) {
    return { ...base('critical_findings'), headline: 'No critical or high-severity findings are recorded in the latest evidence.', risk: { level: 'low', drivers: [] }, figures: [figure('findings.critical', 'Critical findings', 0, 'lower', 'Quantum Risk Analysis')] }
  }
  return {
    ...base('critical_findings'),
    headline:
      `${count(critical, 'critical finding')} and ${num(dist.high)} high-severity finding(s) are open${scopeNote(d.assetScope)} (${num(dist.medium)} medium, ${num(dist.low)} low). ` +
      `${findings.length ? `The critical/high evidence consolidates to ${count(findings.length, 'distinct exposure')}, led by ${list(findings.slice(0, 3).map((f) => `${f.title || f.algorithm} on ${f.asset}`), 3)}.` : ''}`,
    keyFindings: [...new Set(findings.slice(0, 5).map((f) => `${f.algorithm || f.title}: ${whyAlgorithm(f.algorithm, f.title)}`))],
    entities: findings.length ? [{
      title: 'Critical and high findings (consolidated)',
      unit: 'finding',
      columns: [
        { key: 'finding', label: 'Finding' },
        { key: 'asset', label: 'Asset' },
        { key: 'severity', label: 'Severity' },
        { key: 'instances', label: 'Instances', align: 'right' },
        { key: 'why', label: 'Why it matters' },
      ],
      rows: findings.map((f) => ({ cells: { finding: f.title || f.algorithm, asset: f.asset, severity: f.severity, instances: f.instances, why: whyAlgorithm(f.algorithm, f.title) }, tone: PRIORITY_TONE[String(f.severity).toLowerCase()] || 'high', deepLink: modulePath('risk_analysis') })),
      total: findings.length,
      source: 'Quantum Risk Analysis',
      deepLink: modulePath('risk_analysis'),
      note: 'Findings are counted per consolidated exposure (one algorithm on one asset), with the raw instance count shown.',
    }] : [],
    recommendations: [],
    nextActions: [{ label: 'Open Quantum Risk Analysis', path: modulePath('risk_analysis'), reason: 'Every finding with its evidence.' }],
    risk: { level: critical ? 'critical' : 'high', drivers: [`${critical} critical / ${num(dist.high)} high finding(s)`] },
    figures: [figure('findings.critical', 'Critical findings', critical, 'lower', 'Quantum Risk Analysis'), figure('findings.high', 'High-severity findings', num(dist.high), 'lower', 'Quantum Risk Analysis')],
  }
}

function composeScanSummary(d: FocusInput): FocusAnswer {
  const scans = d.tool('getLatestScans')
  const risk = d.tool('getRiskAnalysis')
  if (!scans && !risk) return unavailable(d, 'scan_summary', 'getLatestScans', 'the PQC Scanner', 'scanner', 'what your latest scans found')
  const sessions = arr<{ status: string; findings_count: number; total_assets: number; scanned_assets: number; completed_at: string; created_at: string }>(scans?.data.sessions)
  if (!sessions.length) return { ...base('scan_summary'), headline: 'No scans have been run yet — run a discovery scan from the PQC Scanner to build your inventory.', noData: true, risk: { level: 'info', drivers: [] }, nextActions: [{ label: 'Open the PQC Scanner', path: modulePath('scanner'), reason: 'Start a discovery scan.' }] }
  const latest = sessions[0]
  const dist = rec(risk?.data.distribution)
  return {
    ...base('scan_summary'),
    headline:
      `Your latest scan ${latest.completed_at ? `completed ${ago(latest.completed_at)}` : `(${latest.status}) started ${ago(latest.created_at)}`} and recorded ${count(num(latest.findings_count), 'finding')} across ${count(num(latest.scanned_assets) || num(latest.total_assets), 'asset')}. ` +
      `${risk ? `Estate-wide the open findings are ${num(dist.critical)} critical, ${num(dist.high)} high, ${num(dist.medium)} medium and ${num(dist.low)} low.` : ''}`,
    keyFindings: [`${count(sessions.length, 'recent scan session')} on record.`],
    entities: [{
      title: 'Recent scans',
      unit: 'scan',
      columns: [{ key: 'when', label: 'Started' }, { key: 'status', label: 'Status' }, { key: 'assets', label: 'Assets', align: 'right' }, { key: 'findings', label: 'Findings', align: 'right' }],
      rows: sessions.slice(0, 10).map((s) => ({ cells: { when: dateOnly(s.created_at), status: s.status, assets: num(s.scanned_assets) || num(s.total_assets), findings: num(s.findings_count) }, tone: /fail|error/i.test(s.status) ? 'high' : 'neutral', deepLink: modulePath('scanner') })),
      total: sessions.length,
      source: 'PQC Scanner',
      deepLink: modulePath('scanner'),
    }],
    recommendations: [],
    nextActions: [{ label: 'Open the PQC Scanner', path: modulePath('scanner'), reason: 'Scan history and findings.' }],
    risk: { level: num(dist.critical) ? 'critical' : num(dist.high) ? 'high' : 'medium', drivers: [] },
    figures: risk ? [figure('findings.critical', 'Critical findings', num(dist.critical), 'lower', 'Quantum Risk Analysis')] : [],
  }
}

/* ------------------------------------------------------------------ */
/* Migration operations                                                */
/* ------------------------------------------------------------------ */

interface JobRow { id: string; name: string; job_type: string; status: string; target_algorithm: string; updated_at: string; created_at: string }

function jobTable(title: string, jobs: JobRow[]): CopilotEntityTable {
  return {
    title,
    unit: 'migration job',
    columns: [{ key: 'name', label: 'Job' }, { key: 'type', label: 'Type' }, { key: 'status', label: 'Status' }, { key: 'target', label: 'Target' }, { key: 'updated', label: 'Updated' }],
    rows: jobs.map((j) => ({ cells: { name: j.name || j.id.slice(0, 8), type: j.job_type || '—', status: j.status, target: j.target_algorithm || '—', updated: dateOnly(j.updated_at || j.created_at) }, tone: /fail|error|reject/i.test(j.status) ? 'critical' : 'neutral', deepLink: modulePath('live_migration') })),
    total: jobs.length,
    source: 'Live Migration Ops',
    deepLink: modulePath('live_migration'),
  }
}

function composeMigrationJobs(d: FocusInput): FocusAnswer {
  const r = d.tool('getMigrationJobs')
  if (!r) return unavailable(d, 'migration_jobs', 'getMigrationJobs', 'Live Migration Ops', 'live_migration', 'which migrations are running or failed')
  const active = arr<JobRow>(r.data.active)
  const failed = arr<JobRow>(r.data.failed)
  const wf = d.tool('getMigrationStatus')
  const total = num(r.data.total)
  const headline = total === 0
    ? 'No migration jobs have been created yet.'
    : `${count(active.length, 'migration job')} ${isAre(active.length)} active and ${failed.length} failed, out of ${count(total, 'job')} on record.${failed.length ? ` Failed: ${list(failed.map((j) => j.name || j.id.slice(0, 8)), 3)} — resolve or roll these back before starting new work, to avoid a mixed-crypto state.` : ''}`
  return {
    ...base('migration_jobs'),
    headline,
    keyFindings: [
      `By status: ${Object.entries(rec(r.data.byStatus)).map(([k, n]) => `${k} ${num(n)}`).join(' · ') || 'none'}.`,
      ...(wf ? [`Migration workflow: ${num(wf.data.overallProgressPct)}% complete at "${str(wf.data.currentStageLabel)}".`] : []),
    ],
    entities: [
      ...(failed.length ? [jobTable('Failed migration jobs', failed)] : []),
      ...(active.length ? [jobTable('Active migration jobs', active)] : []),
    ],
    recommendations: failed.length ? [{
      title: 'Review the failed jobs',
      detail: 'Inspect each failure in Live Migration Ops; restore from its pre-migration snapshot before retrying.',
      priority: 'immediate',
      standards: [STANDARDS.SP_1800_38],
      deepLink: modulePath('live_migration'),
    }] : [],
    nextActions: [{ label: 'Open Live Migration Ops', path: modulePath('live_migration'), reason: 'Job detail, logs and rollback.' }],
    risk: { level: failed.length > 2 ? 'high' : failed.length ? 'medium' : 'low', drivers: failed.length ? [`${failed.length} failed job(s)`] : [] },
    figures: [figure('migration.failedJobs', 'Failed migration jobs', failed.length, 'lower', 'Live Migration Ops'), figure('migration.activeJobs', 'Active migration jobs', active.length, 'neutral', 'Live Migration Ops')],
  }
}

function composeMigrationBlockers(d: FocusInput): FocusAnswer {
  const graph = d.tool('getExposureGraph')
  const v = readQueue(d)
  const jobs = d.tool('getMigrationJobs')
  const ownership = d.tool('explainFindingOwnership')
  if (!graph && !v && !jobs) return unavailable(d, 'migration_blockers', 'getExposureGraph', 'the Quantum Exposure Graph™', 'exposure_graph', 'what is blocking your migration')
  const blockers = arr<{ label: string; reason: string; blockedDependents: number }>(graph?.data.blockerList)
  const replacements = v ? v.rows.filter((a) => a.requiresReplacement) : []
  const failed = arr<JobRow>(jobs?.data.failed)
  const waiting = num(rec(ownership?.data.ownershipBreakdown).waitingOnDependency)
  const rows: CopilotEntityRow[] = [
    ...blockers.map((b) => ({ cells: { blocker: b.label, kind: 'Dependency', detail: `${b.reason}${b.blockedDependents ? ` — blocks ${b.blockedDependents} dependent(s)` : ''}` }, tone: 'high' as CopilotTone, deepLink: modulePath('exposure_graph') })),
    ...replacements.map((a) => ({ cells: { blocker: a.asset, kind: 'Needs replacement', detail: `${a.problem} — the system cannot support PQC` }, tone: 'high' as CopilotTone, deepLink: a.route })),
    ...failed.map((j) => ({ cells: { blocker: j.name || j.id.slice(0, 8), kind: 'Failed job', detail: `status ${j.status}` }, tone: 'critical' as CopilotTone, deepLink: modulePath('live_migration') })),
  ]
  const parts = [
    blockers.length ? `${count(blockers.length, 'dependency blocker')} in the exposure graph` : '',
    replacements.length ? `${count(replacements.length, 'system')} that cannot support PQC and must be replaced` : '',
    failed.length ? `${count(failed.length, 'failed migration job')}` : '',
    waiting ? `${count(waiting, 'finding')} waiting on a provider or ecosystem dependency` : '',
  ].filter(Boolean)
  return {
    ...base('migration_blockers'),
    headline: parts.length
      ? `Your migration is held up by ${list(parts, 4)}.${rows.length ? ` First to resolve: ${str(rows[0].cells.blocker)} (${str(rows[0].cells.kind).toLowerCase()}).` : ''}`
      : 'Nothing in the current evidence is blocking migration: no dependency blocker, no system that needs replacement and no failed job.',
    keyFindings: waiting ? [`${waiting} finding(s) depend on a provider or ecosystem party — see Migration Intelligence for who can act.`] : [],
    entities: rows.length ? [{ title: 'Migration blockers', unit: 'blocker', columns: [{ key: 'blocker', label: 'Blocker' }, { key: 'kind', label: 'Kind' }, { key: 'detail', label: 'Detail' }], rows, total: rows.length, source: 'Exposure Graph · Remediation · Live Migration', deepLink: modulePath('exposure_graph') }] : [],
    recommendations: [],
    nextActions: [
      { label: 'Open the Exposure Graph', path: modulePath('exposure_graph'), reason: 'Dependency blockers.' },
      { label: 'Open Migration Intelligence', path: modulePath('migration_intelligence'), reason: 'Who owns each dependency.' },
    ],
    risk: { level: rows.length ? 'high' : 'low', drivers: parts },
    figures: [figure('migration.blockers', 'Migration blockers', rows.length, 'lower', 'Exposure Graph')],
  }
}

function composeMigrationEffort(d: FocusInput): FocusAnswer {
  const v = readQueue(d)
  if (!v) return unavailable(d, 'migration_effort', 'getPendingRemediation', 'the Quantum Remediation Engine™', 'remediation', 'how much effort the migration needs')
  if (!v.rows.length) return queueEmpty('migration_effort', v, d.assetScope)
  const wf = d.tool('getMigrationStatus')
  const effort = num(v.data.totalEffortWeeks)
  const calendar = num(v.data.estimatedCompletionWeeks)
  const streams = num(v.data.parallelWorkstreams) || 1
  const eta = str(v.data.estimatedCertificationDate)
  const byEffort = [...v.rows].sort((a, b) => b.effortWeeks - a.effortWeeks)
  return {
    ...base('migration_effort'),
    headline:
      `The remaining work is ${count(v.total, 'remediation action')}, estimated at about ${weeks(effort)} of engineering effort — roughly ${weeks(calendar)} of calendar time with ${count(streams, 'parallel workstream')}. ` +
      `${wf ? `The migration workflow is ${num(wf.data.overallProgressPct)}% complete. ` : ''}` +
      `${eta && v.data.certificationEligible !== true ? `Completing it projects certification eligibility around ${dateOnly(eta)}. ` : ''}` +
      'These are the Remediation Engine\'s effort-model estimates, not commitments.',
    keyFindings: [
      `Largest items: ${list(byEffort.slice(0, 3).map((a) => `${a.asset} (${weeks(a.effortWeeks)})`), 3)}.`,
      `${count(v.rows.filter((a) => a.quickWin).length, 'quick win')} can be done in 1.5 weeks or less each.`,
    ],
    entities: [actionTable('Remaining work — largest effort first', byEffort, v.total)],
    recommendations: [],
    nextActions: [{ label: 'Open the Migration Planner', path: modulePath('migration_planner'), reason: 'Plan waves and staffing.' }],
    risk: { level: 'medium', drivers: [`${weeks(effort)} effort`] },
    figures: [...remediationFigures(v), figure('migration.effortWeeks', 'Remaining effort (weeks)', effort, 'lower', 'Quantum Remediation Engine™', 'wk')],
  }
}

function composeSnapshots(d: FocusInput): FocusAnswer {
  const r = d.tool('getSnapshots')
  if (!r) return unavailable(d, 'snapshots', 'getSnapshots', 'Live Migration Ops', 'live_migration', 'whether you have snapshots to roll back to')
  if (r.data.schemaReady === false) {
    return { ...base('snapshots'), headline: 'Snapshot storage is not configured yet (the snapshot schema has not been applied), so no rollback point exists. Apply it before starting a migration so every stage is reversible.', risk: { level: 'high', drivers: ['no rollback capability'] }, noData: true, nextActions: [{ label: 'Open Live Migration Ops', path: modulePath('live_migration'), reason: 'Snapshot setup.' }] }
  }
  const summary = rec(r.data.summary)
  const snaps = arr<{ snapshotId: string; assetName: string; status: string; integrityVerified: boolean; restoreExecutable: boolean; restoreBlockedReason: string | null; createdAt: string }>(r.data.snapshots)
  const restorable = snaps.filter((s) => s.status === 'restorable')
  const executable = restorable.filter((s) => s.restoreExecutable)
  const total = num(summary.total)
  const headline = total === 0
    ? 'You have no snapshots yet. A pre-migration snapshot is captured when a migration job starts — or take one manually before changing anything.'
    : `You have ${count(num(summary.restorable), 'restorable snapshot')} of ${total}; ${executable.length} can be restored automatically right now${restorable.length > executable.length ? ` (${restorable.length - executable.length} need a manual restore: ${str(restorable.find((s) => !s.restoreExecutable)?.restoreBlockedReason) || 'no executor available'})` : ''}. Integrity is re-verified with SHA3-256 before any restore.${num(summary.automaticRollbacks) ? ` ${count(num(summary.automaticRollbacks), 'automatic rollback')} ${num(summary.automaticRollbacks) === 1 ? 'has' : 'have'} run.` : ''}`
  return {
    ...base('snapshots'),
    headline,
    keyFindings: [`Latest snapshot: ${summary.latestSnapshotAt ? ago(str(summary.latestSnapshotAt)) : 'none'}.`, `${snaps.filter((s) => !s.integrityVerified).length} snapshot(s) failed integrity re-verification.`],
    entities: snaps.length ? [{
      title: 'Snapshots',
      unit: 'snapshot',
      columns: [{ key: 'asset', label: 'Asset' }, { key: 'status', label: 'Status' }, { key: 'integrity', label: 'Integrity' }, { key: 'restore', label: 'Restore' }, { key: 'created', label: 'Created' }],
      rows: snaps.slice(0, 15).map((s) => ({ cells: { asset: s.assetName, status: s.status, integrity: s.integrityVerified ? 'Verified' : 'FAILED', restore: s.restoreExecutable ? 'Automatic' : s.restoreBlockedReason || 'Manual', created: dateOnly(s.createdAt) }, tone: !s.integrityVerified ? 'critical' : s.status === 'restorable' ? 'good' : 'neutral', deepLink: modulePath('live_migration') })),
      total,
      source: 'Live Migration Ops',
      deepLink: modulePath('live_migration'),
    }] : [],
    recommendations: total === 0 ? [{ title: 'Capture a snapshot before the next change', detail: 'An integrity-hashed crypto-state backup makes the change fully reversible.', priority: 'high', standards: [STANDARDS.SP_1800_38], deepLink: modulePath('live_migration') }] : [],
    nextActions: [{ label: 'Open Live Migration Ops', path: modulePath('live_migration'), reason: 'Snapshots and rollback.' }],
    risk: { level: num(summary.restorable) ? 'low' : 'medium', drivers: [] },
    figures: [figure('snapshots.restorable', 'Restorable snapshots', num(summary.restorable), 'higher', 'Live Migration Ops')],
  }
}

/* ------------------------------------------------------------------ */
/* Operations                                                          */
/* ------------------------------------------------------------------ */

function composeCollectors(d: FocusInput): FocusAnswer {
  const r = d.tool('getCollectorsStatus')
  if (!r) return unavailable(d, 'collectors', 'getCollectorsStatus', 'Agents Collector', 'collectors', 'the health of your collectors')
  const fleet = num(r.data.fleet)
  const agents = arr<{ name: string; hostname: string | null; platform: string | null; version: string | null; online: boolean; lastSeenAt: string | null }>(r.data.agents)
  const offline = agents.filter((a) => !a.online)
  if (fleet === 0) {
    return { ...base('collectors'), headline: 'No collector agents are enrolled. Discovery relies on remote scans only — enroll collectors on key hosts for runtime telemetry and internal visibility.', risk: { level: 'medium', drivers: ['no collectors'] }, noData: true, nextActions: [{ label: 'Open Agents Collector', path: modulePath('collectors'), reason: 'Enroll an agent.' }] }
  }
  return {
    ...base('collectors'),
    headline: offline.length
      ? `${num(r.data.online)} of ${count(fleet, 'collector')} ${isAre(num(r.data.online))} online; ${offline.length} ${isAre(offline.length)} offline (no heartbeat in ${num(r.data.onlineWindowMinutes)} minutes): ${list(offline.map((a) => `${a.name} — last seen ${a.lastSeenAt ? ago(a.lastSeenAt) : 'never'}`), 4)}. Assets they cover may be missing from current results.`
      : `All ${count(fleet, 'collector')} ${isAre(fleet)} online and heartbeating within the last ${num(r.data.onlineWindowMinutes)} minutes.`,
    keyFindings: [],
    entities: [{
      title: 'Collector fleet',
      unit: 'agent',
      columns: [{ key: 'name', label: 'Agent' }, { key: 'host', label: 'Host' }, { key: 'platform', label: 'Platform' }, { key: 'status', label: 'Status' }, { key: 'seen', label: 'Last heartbeat' }],
      rows: agents.map((a) => ({ cells: { name: a.name, host: a.hostname || '—', platform: a.platform || '—', status: a.online ? 'Online' : 'Offline', seen: a.lastSeenAt ? ago(a.lastSeenAt) : 'never' }, tone: a.online ? 'good' : 'high', deepLink: modulePath('collectors') })),
      total: fleet,
      source: 'Agents Collector',
      deepLink: modulePath('collectors'),
    }],
    recommendations: offline.length ? [{ title: 'Recover the offline collectors', detail: 'Check the agent service and network path on each host; offline collectors create blind spots in discovery and runtime telemetry.', priority: 'high', standards: [STANDARDS.CIS_V8], deepLink: modulePath('collectors') }] : [],
    nextActions: [{ label: 'Open Agents Collector', path: modulePath('collectors'), reason: 'Heartbeats, versions and health.' }],
    risk: { level: offline.length ? 'medium' : 'low', drivers: offline.length ? [`${offline.length} offline collector(s)`] : [] },
    figures: [figure('collectors.offline', 'Offline collectors', offline.length, 'lower', 'Agents Collector'), figure('collectors.fleet', 'Enrolled collectors', fleet, 'neutral', 'Agents Collector')],
  }
}

function composeRuntimeEvents(d: FocusInput): FocusAnswer {
  const r = d.tool('getLiveTelemetry')
  if (!r) return unavailable(d, 'runtime_events', 'getLiveTelemetry', 'Runtime Telemetry', 'telemetry', 'your recent runtime crypto events')
  const events = num(r.data.recentEvents)
  const recent = arr<{ algorithm: string; severity: string; is_legacy: boolean; is_pqc: boolean; hndl_risk: boolean; observed_at: string }>(r.data.recent)
  const wantsLegacy = /legacy|weak|vulnerab/.test(d.question.toLowerCase())
  const shown = wantsLegacy ? recent.filter((e) => e.is_legacy) : recent
  if (!events) return { ...base('runtime_events'), headline: 'No runtime cryptographic events have been recorded — runtime telemetry needs an enrolled collector with runtime capture.', noData: true, risk: { level: 'info', drivers: [] }, nextActions: [{ label: 'Open Agents Collector', path: modulePath('collectors'), reason: 'Enable runtime capture.' }] }
  return {
    ...base('runtime_events'),
    headline: `Your collectors recorded ${count(events, 'recent runtime crypto event')}: ${num(r.data.legacyEvents)} using legacy cryptography, ${num(r.data.pqcEvents)} post-quantum, ${num(r.data.hndlFlagged)} flagged for Harvest-Now exposure. Latest ${ago(str(r.data.latestAt))}.`,
    keyFindings: [],
    entities: shown.length ? [{
      title: wantsLegacy ? 'Recent legacy-crypto events' : 'Recent runtime events',
      unit: 'event',
      columns: [{ key: 'when', label: 'Observed' }, { key: 'algorithm', label: 'Algorithm' }, { key: 'class', label: 'Class' }, { key: 'severity', label: 'Severity' }],
      rows: shown.slice(0, 20).map((e) => ({ cells: { when: ago(e.observed_at), algorithm: e.algorithm || '—', class: e.is_pqc ? 'Post-quantum' : e.is_legacy ? 'Legacy' : 'Other', severity: e.severity || '—' }, tone: e.is_legacy ? 'high' : e.is_pqc ? 'good' : 'neutral', deepLink: modulePath('telemetry') })),
      total: wantsLegacy ? num(r.data.legacyEvents) : events,
      source: 'Runtime Telemetry',
      deepLink: modulePath('telemetry'),
    }] : [],
    recommendations: [],
    nextActions: [{ label: 'Open Runtime Crypto Intel', path: modulePath('telemetry'), reason: 'The live event stream.' }],
    risk: { level: num(r.data.legacyEvents) ? 'medium' : 'low', drivers: num(r.data.legacyEvents) ? [`${num(r.data.legacyEvents)} legacy-crypto event(s)`] : [] },
    figures: [figure('runtime.legacyEvents', 'Legacy-crypto runtime events', num(r.data.legacyEvents), 'lower', 'Runtime Telemetry')],
  }
}

/* ------------------------------------------------------------------ */
/* Dispatcher                                                          */
/* ------------------------------------------------------------------ */

const COMPOSERS: Record<FocusId, (d: FocusInput) => FocusAnswer> = {
  remediation_queue: composeRemediationQueue,
  remediation_gain: composeRemediationGain,
  critical_blockers: composeCriticalBlockers,
  migration_priority: composeMigrationPriority,
  certification_gap: composeCertificationGap,
  certification_next_level: composeCertificationNextLevel,
  readiness: composeReadiness,
  readiness_blockers: composeReadinessBlockers,
  hndl_exposure: composeHndlExposure,
  forward_secrecy: composeForwardSecrecy,
  future_decryptable: composeFutureDecryptable,
  hndl_reduction: composeHndlReduction,
  compliance_posture: composeCompliance,
  cnsa: composeCnsa,
  nist_alignment: composeNist,
  certificates: composeCertificates,
  certificate_issuers: composeCertificateIssuers,
  algorithms: composeAlgorithms,
  asset_dossier: composeAssetDossier,
  assets_list: composeAssetsList,
  most_vulnerable_assets: composeMostVulnerable,
  blast_radius: composeBlastRadius,
  dependencies: composeDependencies,
  third_parties: composeThirdParties,
  critical_findings: composeCriticalFindings,
  scan_summary: composeScanSummary,
  migration_jobs: composeMigrationJobs,
  migration_blockers: composeMigrationBlockers,
  migration_effort: composeMigrationEffort,
  snapshots: composeSnapshots,
  collectors: composeCollectors,
  runtime_events: composeRuntimeEvents,
}

/** Topics where naming an asset means "tell me about that asset". */
const ASSET_OVERRIDABLE: Array<FocusId | null> = [null, 'readiness', 'assets_list', 'most_vulnerable_assets']

/**
 * Final focus once the asset register has been consulted: a question that
 * names a real asset and is not about another topic becomes that asset's
 * status. Topic questions naming an asset ("pending remediation for orders-db")
 * keep their topic and are SCOPED to the asset instead.
 */
export function finalizeFocus(planned: FocusId | null, assetScope: AssetView[]): FocusId | null {
  if (assetScope.length && ASSET_OVERRIDABLE.includes(planned)) return 'asset_dossier'
  return planned
}

export function answerFocus(focus: FocusId, input: FocusInput): FocusAnswer {
  return COMPOSERS[focus](input)
}

export function focusLabel(focus: FocusId): string {
  return FOCUS_SPECS[focus].label
}

export function focusTools(focus: FocusId | null): string[] {
  return focus ? FOCUS_SPECS[focus].tools : []
}
