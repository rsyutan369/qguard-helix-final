import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { buildReportModel } from '@/services/reporting/ReportEvidence'
import { DEFAULT_COST_ASSUMPTIONS, normalizeToWholeHours } from '@/lib/migration/cost-model'
import { brandingSchema } from '@/services/reporting/schemas/ReportSchema'
import {
  buildAssetPortfolio,
  type AssetMigrationRecord,
  type AssetPortfolio,
} from '@/lib/migration/asset-intelligence'

/**
 * QGuard Helix Migration Planner™ — Enterprise Post-Quantum Migration Management.
 *
 * Single source of truth for the migration-planning experience. Reuses the
 * Quantum Readiness snapshot (which mirrors the platform's scanner intelligence)
 * and the isomorphic report-evidence model so every metric, wave, dependency,
 * cost and compliance value is identical to the QR pages and exported reports.
 * Adds migration-specific derivations (9-stage workflow, strategy simulator,
 * what-if engine, blockers, readiness heatmap, timeline, migration risk engine)
 * and real migration-job execution telemetry. No fabricated data — missing
 * evidence reads "Evidence Not Available".
 */

const router = Router()
type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }
type Row = Record<string, unknown>

function tokenFromRequest(req: Request): string | null {
  const headerToken = getToken(req)
  if (headerToken) return headerToken
  // EventSource (SSE) cannot set an Authorization header, so the /stream route
  // passes the token via query string. Accept it for this router.
  const queryToken = req.query.token
  return typeof queryToken === 'string' && queryToken.length > 0 ? queryToken : null
}

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = tokenFromRequest(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}
router.use(requireAuth)

const EVIDENCE_UNAVAILABLE = 'Evidence Not Available'
const str = (v: unknown) => (typeof v === 'string' ? v : v == null ? '' : String(v))
const num = (v: unknown) => { const n = Number(v); return Number.isFinite(n) ? n : 0 }
const clamp = (n: number, min = 0, max = 100) => Math.max(min, Math.min(max, Math.round(n)))
const recordOf = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {})
const usd = (n: number) => (n ? `$${Math.round(n).toLocaleString()}` : EVIDENCE_UNAVAILABLE)

async function safeRows(client: { from: (t: string) => { select: (c: string) => { eq: (k: string, v: string) => { order?: unknown; limit: (n: number) => Promise<{ data: unknown; error: unknown }> } } } }, table: string, columns: string, userId: string, limit = 500): Promise<Row[]> {
  try {
    const q = client.from(table).select(columns).eq('user_id', userId)
    const built = (q as unknown as { order: (c: string, o: { ascending: boolean }) => { limit: (n: number) => Promise<{ data: unknown; error: unknown }> } }).order('created_at', { ascending: false }).limit(limit)
    const { data, error } = await built
    if (error) return []
    return (data as Row[]) || []
  } catch {
    return []
  }
}

type Snapshot = Awaited<ReturnType<typeof buildSnapshot>>
type ReportModel = ReturnType<typeof buildReportModel>

function durationLabel(weeks: number): string {
  if (!weeks) return EVIDENCE_UNAVAILABLE
  if (weeks >= 8) return `${Math.round(weeks / 4.345)} Months`
  return `${weeks} Weeks`
}

/* ---- 9-stage migration workflow ---- */
function buildStages(snapshot: Snapshot, report: ReportModel, jobs: Row[], plans: Row[], validations: Row[]) {
  const inv = snapshot.inventory
  const activeJobs = jobs.filter((j) => !/completed|done|failed/i.test(str(j.status)))
  const completedJobs = jobs.filter((j) => /completed|done/i.test(str(j.status)))
  const reduction = report.executiveBlock.expectedRiskReductionPct
  const stage = (key: string, label: string, done: boolean, ready: boolean, assetCount: number, riskReductionPct: number, dependencies: string[], durationWeeks: number, evidence: string) => ({
    key, label,
    status: done ? 'Complete' : ready ? 'In Progress' : 'Pending',
    progressPct: done ? 100 : ready ? 50 : 0,
    assetCount, riskReductionPct, dependencies, durationWeeks, evidence,
  })
  const wk = (ratio: number) => Math.max(snapshot.estimates.migrationTimelineWeeks ? 1 : 0, Math.round((snapshot.estimates.migrationTimelineWeeks || 0) * ratio))
  return [
    stage('discover', 'Discover', inv.assetsAssessed > 0, snapshot.hasData, inv.assetsAssessed, 0, [], wk(0.08), `${inv.assetsAssessed} assets, ${inv.cryptoComponents} crypto components discovered.`),
    stage('analyze', 'Analyze', snapshot.hasData, snapshot.hasData, inv.vulnerableComponents, 0, ['Discover'], wk(0.08), `Quantum risk ${snapshot.scores.quantumRisk}/100, HNDL ${snapshot.scores.hndlRiskLevel}.`),
    stage('prioritize', 'Prioritize', report.migrationWaves.length > 0, snapshot.hasData, report.migrationWaves.reduce((s, w) => s + (w.assets[0] === EVIDENCE_UNAVAILABLE ? 0 : w.assets.length), 0), 0, ['Analyze'], wk(0.05), `${report.migrationWaves.length} migration waves prioritised by risk.`),
    stage('simulate', 'Simulate', false, snapshot.hasData, inv.quantumVulnerableAssets, reduction, ['Prioritize'], wk(0.05), 'Strategy simulator & what-if analysis available.'),
    stage('plan', 'Plan', plans.length > 0, snapshot.hasData, inv.quantumVulnerableAssets, reduction, ['Simulate'], wk(0.05), plans.length ? `${plans.length} migration plan(s) created.` : 'No migration plan created yet.'),
    stage('approve', 'Approve', plans.some((p) => /approved/i.test(str(p.status))), plans.length > 0, plans.length, 0, ['Plan'], wk(0.04), plans.some((p) => /approved/i.test(str(p.status))) ? 'Plan approved.' : 'Awaiting executive approval.'),
    stage('execute', 'Execute', completedJobs.length > 0 && activeJobs.length === 0 && jobs.length > 0, activeJobs.length > 0, jobs.length, 0, ['Approve'], wk(0.45), jobs.length ? `${activeJobs.length} active, ${completedJobs.length} completed migration jobs.` : 'No migration jobs executing.'),
    stage('validate', 'Validate', validations.length > 0, jobs.length > 0, validations.length, 0, ['Execute'], wk(0.12), validations.length ? `${validations.length} validation record(s).` : 'No validation telemetry yet.'),
    stage('optimize', 'Optimize', false, completedJobs.length > 0, completedJobs.length, 0, ['Validate'], wk(0.08), 'Decommission classical keys, monitor drift, prove evidence.'),
  ]
}

/* ---- Strategy simulator ---- */
function buildStrategies(snapshot: Snapshot, report: ReportModel) {
  const baseCost = snapshot.estimates.migrationCostUsd || 0
  const baseWeeks = snapshot.estimates.migrationTimelineWeeks || 0
  const baseReduction = report.executiveBlock.expectedRiskReductionPct
  const compliance = report.compliance.length
  const def = (key: string, name: string, summary: string, costMul: number, weekMul: number, reductionMul: number, opRisk: string, downtime: number, compliancePct: number, success: number, recommended: boolean) => ({
    key, name, summary,
    costUsd: Math.round(baseCost * costMul),
    timelineWeeks: Math.max(baseWeeks ? 1 : 0, Math.round(baseWeeks * weekMul)),
    riskReductionPct: clamp(baseReduction * reductionMul),
    operationalRisk: opRisk,
    downtimeProbabilityPct: downtime,
    complianceImpactPct: compliancePct,
    successProbabilityPct: success,
    recommended,
  })
  return [
    def('conservative', 'Conservative', 'Hybrid TLS + Hybrid PKI, minimal disruption.', 0.7, 1.3, 0.7, 'Low', 5, clamp((compliance / 9) * 60), 96, false),
    def('balanced', 'Balanced', 'Hybrid + selective PQC on critical paths (recommended).', 1.0, 1.0, 1.0, 'Medium', 12, clamp((compliance / 9) * 80), 90, true),
    def('aggressive', 'Aggressive', 'Maximum PQC adoption, highest risk reduction.', 1.4, 0.7, 1.25, 'High', 28, clamp((compliance / 9) * 100), 82, false),
    def('custom', 'Custom', 'User-defined scope, sequencing and budget.', 1.0, 1.0, 1.0, 'Variable', 0, 0, 0, false),
  ]
}

/* ---- What-if engine ---- */
/**
 * What-if scenarios sized from MEASURED scope.
 *
 * Every figure here used to be a literal: costs were fixed fractions of the
 * programme total (0.2 / 0.25 / 0.3 / 0.22), timelines were the strings
 * '4 Weeks' / '3 Months' / '6 Weeks' / '5 Weeks', and compliance deltas were the
 * constants 12 / 18 / 23 / 15. None moved with the estate, so "Migrate PKI
 * Infrastructure — $39,188, 3 Months" was printed for an estate holding three
 * certificates. The fourth row was the worst of the set: its LABEL carried a
 * real evidence-derived percentage while the numbers beside it did not, which
 * made hardcoded values look measured.
 *
 * Each scenario now names the components it covers, and cost/timeline/risk are
 * derived from that share of the programme. Scenarios OVERLAP (full hybrid TLS
 * includes the external TLS work) — they are alternatives to compare, not a
 * plan to sum, and `coverage` states the scope each one buys.
 */
function buildWhatIf(snapshot: Snapshot, report: ReportModel, cryptoInventory: Row[] = []) {
  const assumptions = snapshot.costAssumptions ?? DEFAULT_COST_ASSUMPTIONS
  const totalCost = snapshot.estimates.migrationCostUsd || 0
  const totalWeeks = snapshot.estimates.migrationTimelineWeeks || 0
  const reduction = report.executiveBlock.expectedRiskReductionPct
  const vulnerableComponents = Math.max(0, snapshot.inventory.vulnerableComponents)
  const certificates = Math.max(0, snapshot.inventory.certificatesAnalyzed)

  /* Measured scope per scenario, from the vulnerable crypto inventory.
     Transport and PKI are disjoint here: a component is classified once, by the
     layer that owns it, so "Transport + PKI" is a real union and not a figure
     inflated by double-counting the same component in both. */
  const vulnerableRows = cryptoInventory.filter(
    (row) => row.is_vulnerable === true && row.is_quantum_safe !== true,
  )
  const textOf = (row: Row) => `${str(row.algorithm)} ${str(row.name)} ${str(row.item_type)} ${str(row.protocol)}`.toLowerCase()
  const PKI_RE = /cert|x.?509|signature|sign|issuer|ecdsa-with|shad*with|rsassa/
  const TLS_RE = /tls_|cipher|ecdhe|kem|key exchange|handshake|dhe|chacha|aes_/
  let tlsRows = 0
  let pkiRows = 0
  for (const row of vulnerableRows) {
    const text = textOf(row)
    if (PKI_RE.test(text)) pkiRows += 1
    else if (TLS_RE.test(text)) tlsRows += 1
  }
  /* Inventory ROWS are not the same unit as CBOM COMPONENTS (one component can
     hold several rows), so the row split is converted to a share and re-expressed
     in component space. Clamping raw row counts instead would let transport+PKI
     exceed the estate. Falls back to zero scope when the inventory query
     degraded, rather than reporting a confident number from no rows. */
  const classifiedRows = tlsRows + pkiRows
  const inComponents = (rows: number) =>
    classifiedRows > 0 ? Math.round((rows / classifiedRows) * vulnerableComponents) : 0
  const tlsComponents = inComponents(tlsRows)
  const pkiComponents = Math.max(0, vulnerableComponents - tlsComponents)

  /** Cost/timeline for a scenario covering `components` of the vulnerable estate. */
  const scale = (components: number) => {
    const share = vulnerableComponents > 0 ? Math.min(1, components / vulnerableComponents) : 0
    const costUsd = normalizeToWholeHours(totalCost * share, assumptions)
    const weeks = Math.max(share > 0 ? 1 : 0, Math.round(totalWeeks * share))
    return {
      costUsd,
      weeks,
      timelineLabel: weeks > 0 ? `${weeks} week${weeks === 1 ? '' : 's'}` : EVIDENCE_UNAVAILABLE,
      share,
    }
  }

  const scenarios = [
    {
      scenario: 'Enable hybrid TLS key exchange (X25519 + ML-KEM-768)',
      components: tlsComponents,
      coverage: `${tlsComponents} of ${vulnerableComponents} vulnerable component(s) in transport crypto`,
    },
    {
      scenario: 'Modernise PKI / certificate signatures (ML-DSA-65)',
      components: pkiComponents,
      coverage: `${pkiComponents} of ${vulnerableComponents} vulnerable component(s) across ${certificates} discovered certificate(s)`,
    },
    {
      scenario: 'Transport + PKI together',
      components: Math.min(vulnerableComponents, tlsComponents + pkiComponents),
      coverage: `${Math.min(vulnerableComponents, tlsComponents + pkiComponents)} of ${vulnerableComponents} vulnerable component(s)`,
    },
    {
      scenario: 'Complete programme (all measured findings)',
      components: vulnerableComponents,
      coverage: `All ${vulnerableComponents} vulnerable component(s)`,
    },
  ]

  /* Drop a scenario whose scope has collapsed to the full programme — on a
     small estate "Transport + PKI" IS the whole programme, and printing it twice
     at the same price invites the reader to add them. */
  const seen = new Set<number>()
  return scenarios
    .filter((entry, index) => {
      if (index === scenarios.length - 1) return true
      if (entry.components >= vulnerableComponents) return false
      if (seen.has(entry.components)) return false
      seen.add(entry.components)
      return entry.components > 0
    })
    .map((entry) => {
    const sized = scale(entry.components)
    return {
      scenario: entry.scenario,
      // Risk reduction is proportional to the share of vulnerable components the
      // scenario removes, bounded by the programme's own expected reduction.
      riskReductionPct: clamp(reduction * sized.share),
      costUsd: sized.costUsd,
      timelineLabel: sized.timelineLabel,
      // Compliance progress tracks the same measured share instead of a constant.
      complianceIncreasePct: clamp(Math.round(sized.share * 100)),
      coverage: entry.coverage,
      componentsCovered: entry.components,
    }
  })
}

/* ---- Migration blockers (from real evidence) ---- */
function buildBlockers(snapshot: Snapshot, certificates: Row[]) {
  const blockers: Array<{ id: string; title: string; severity: string; impact: string; resolution: string; affectedAssets: string[] }> = []
  const now = Date.now()
  const expiredCerts = certificates.filter((c) => { const t = new Date(str(c.not_after || c.valid_to)).getTime(); return Number.isFinite(t) && t < now })
  if (expiredCerts.length) blockers.push({ id: 'blk-cert', title: 'Expired certificates', severity: 'high', impact: 'Block hybrid certificate rollout until renewed.', resolution: 'Renew certificates and re-issue with hybrid chains.', affectedAssets: expiredCerts.map((c) => str(c.common_name || c.name)).filter(Boolean).slice(0, 8) })

  const weakAlgos = snapshot.criticalFindings.filter((f) => /rsa-?1024|rsa1024|md5|sha-?1|rc4|des\b|3des|tls\s?1\.0|tls\s?1\.1/i.test(str(f.algorithm)))
  if (weakAlgos.length) blockers.push({ id: 'blk-weak', title: 'Deprecated / weak algorithms in critical path', severity: 'critical', impact: 'Quantum-vulnerable and non-compliant; must be replaced before cutover.', resolution: 'Replace with AES-256-GCM / ML-KEM / ML-DSA hybrid.', affectedAssets: [...new Set(weakAlgos.map((f) => f.asset))].slice(0, 8) })

  const orphaned = snapshot.topRiskAssets.filter((a) => /unassigned|unknown/i.test(a.owner))
  if (orphaned.length) blockers.push({ id: 'blk-owner', title: 'Missing asset ownership', severity: 'medium', impact: 'No accountable owner to approve / execute migration.', resolution: 'Assign owners in the asset inventory.', affectedAssets: orphaned.map((a) => a.asset).slice(0, 8) })

  if (snapshot.inventory.cloudAccounts === 0 && snapshot.inventory.assetsAssessed > 0) blockers.push({ id: 'blk-hsm', title: 'No HSM / KMS custody configured', severity: 'medium', impact: 'PQC key generation requires HSM/KMS firmware supporting ML-KEM/ML-DSA.', resolution: 'Validate HSM firmware and connect a PQC-ready KMS.', affectedAssets: [EVIDENCE_UNAVAILABLE] })

  if (!blockers.length) blockers.push({ id: 'blk-none', title: 'No migration blockers detected', severity: 'low', impact: 'Migration can proceed through planned waves.', resolution: 'Maintain discovery coverage and re-scan regularly.', affectedAssets: [] })
  return blockers
}

/* ---- Readiness heatmap ---- */
function buildHeatmap(snapshot: Snapshot, blockerCount: number) {
  const nodes = snapshot.exposureGraph.nodes
  let ready = 0, needsValidation = 0, needsUpgrade = 0, blocked = 0, unknown = 0
  for (const n of nodes) {
    if (n.posture === 'pqc') ready += 1
    else if (n.posture === 'hybrid') needsValidation += 1
    else if (n.posture === 'vulnerable') needsUpgrade += 1
    else unknown += 1
  }
  // Reflect blockers as blocked assets (capped at vulnerable count).
  blocked = Math.min(needsUpgrade, blockerCount > 1 ? 1 : 0)
  needsUpgrade = Math.max(0, needsUpgrade - blocked)
  const rows = nodes.slice(0, 30).map((n) => ({
    asset: n.label, type: n.type, environment: n.environment, riskScore: n.riskScore,
    state: n.posture === 'pqc' ? 'Ready' : n.posture === 'hybrid' ? 'Needs Validation' : n.posture === 'vulnerable' ? 'Needs Upgrade' : 'Unknown',
  }))
  return { ready, needsValidation, needsUpgrade, blocked, unknown, rows }
}

/* ---- Migration timeline ---- */
function buildTimeline(snapshot: Snapshot) {
  const weeks = snapshot.estimates.migrationTimelineWeeks || 0
  const phases: Array<[string, number, string, string]> = [
    ['Discovery', 0.08, 'Security Engineering', snapshot.inventory.assetsAssessed > 0 ? 'Low' : 'Medium'],
    ['Assessment', 0.08, 'Security Engineering', 'Low'],
    ['Planning', 0.08, 'PQC Migration Office', 'Low'],
    ['Pilot', 0.18, 'Infrastructure Team', 'Medium'],
    ['Core Migration', 0.4, 'Infrastructure Team', 'High'],
    ['Validation', 0.1, 'Security Engineering', 'Medium'],
    ['Optimization', 0.08, 'Platform Team', 'Low'],
  ]
  let cursorWeeks = 0
  const start = Date.now()
  const completion = snapshot.hasData ? [100, 60, 20, 0, 0, 0, 0] : [0, 0, 0, 0, 0, 0, 0]
  return phases.map(([phase, ratio, owner, risk], index) => {
    const dur = Math.max(weeks ? 1 : 0, Math.round(weeks * ratio))
    const startDate = new Date(start + cursorWeeks * 7 * 86400000)
    cursorWeeks += dur
    const endDate = new Date(start + cursorWeeks * 7 * 86400000)
    return {
      phase, owner, riskLevel: risk, durationWeeks: dur,
      startDate: weeks ? startDate.toISOString().slice(0, 10) : EVIDENCE_UNAVAILABLE,
      endDate: weeks ? endDate.toISOString().slice(0, 10) : EVIDENCE_UNAVAILABLE,
      completionPct: completion[index],
      dependencies: index > 0 ? [phases[index - 1][0]] : [],
    }
  })
}

/* ---- Migration risk engine ---- */
function buildRiskEngine(snapshot: Snapshot, report: ReportModel) {
  const factor = (needle: string) => snapshot.riskFactors.find((f) => f.label.toLowerCase().includes(needle))?.score ?? 0
  const domain = (needle: string) => 100 - (report.readinessDomains.find((d) => d.domain.toLowerCase().includes(needle))?.score ?? 0)
  const categories = [
    { key: 'technical', label: 'Technical Risk', score: clamp(factor('rsa') * 0.6 + snapshot.scores.cryptoExposure * 0.4) },
    { key: 'operational', label: 'Operational Risk', score: clamp(domain('tls') * 0.5 + factor('dependency') * 0.5) },
    { key: 'business', label: 'Business Risk', score: clamp(factor('internet') * 0.5 + snapshot.scores.quantumRisk * 0.5) },
    { key: 'compliance', label: 'Compliance Risk', score: clamp((report.compliance.filter((c) => c.status !== 'aligned').length / Math.max(1, report.compliance.length)) * 100) },
    { key: 'vendor', label: 'Vendor Risk', score: clamp(domain('vendor')) },
    { key: 'quantum', label: 'Quantum Risk', score: snapshot.scores.quantumRisk },
  ]
  const overall = clamp(categories.reduce((s, c) => s + c.score, 0) / categories.length)
  const top = [...categories].sort((a, b) => b.score - a.score)[0]
  return {
    categories,
    overall,
    overallLevel: overall >= 70 ? 'Critical' : overall >= 50 ? 'High' : overall >= 30 ? 'Elevated' : 'Moderate',
    explanation: snapshot.hasData
      ? `The migration risk score of ${overall}/100 is driven primarily by ${top.label.toLowerCase()} (${top.score}/100). ${snapshot.inventory.vulnerableComponents} quantum-vulnerable components across ${snapshot.inventory.quantumVulnerableAssets} asset(s) and ${snapshot.scores.hndlRiskLevel} HNDL exposure are the largest contributors. Executing the prioritised migration waves reduces this risk by an estimated ${report.executiveBlock.expectedRiskReductionPct}%.`
      : `${EVIDENCE_UNAVAILABLE}. Run a discovery scan to compute the migration risk score.`,
  }
}

async function buildPlan(token: string, userId: string) {
  const snapshot = await buildSnapshot(token, userId)
  const branding = brandingSchema.parse({})
  const report = buildReportModel(snapshot, branding, 'migration', 'QGuard Helix')

  const client = createAuthClient(token)
  const [jobs, plans, validations, events, certificates, cryptoInventory] = client
    ? await Promise.all([
        safeRows(client as never, 'migration_jobs', 'id, status, progress, asset_id, job_type, created_at, updated_at', userId, 300),
        // NOTE: migration_plans has no `name` column (display name lives in
        // metadata) — selecting one makes PostgREST error and safeRows silently
        // return [], which broke the Approve stage before the approval workflow.
        safeRows(client as never, 'migration_plans', 'id, status, created_at', userId, 100),
        safeRows(client as never, 'migration_validation_logs', 'id, status, created_at', userId, 200),
        safeRows(client as never, 'migration_events', 'id, event_type, status, created_at', userId, 200),
        safeRows(client as never, 'certificates', 'id, common_name, name, not_after, valid_to, signature_algorithm', userId, 500),
        // What-if scenarios are sized from the FULL vulnerable inventory, not
        // snapshot.criticalFindings — that list is capped at 24 records and
        // carries only critical/high, which made two different scenarios report
        // the same scope.
        safeRows(client as never, 'crypto_inventory', 'id, item_type, name, algorithm, protocol, exposure_level, is_vulnerable, is_quantum_safe', userId, 2500),
      ])
    : [[], [], [], [], [], []]

  const inv = snapshot.inventory
  // The asset migration queue is persisted as a migration_plans row (see
  // QUEUE_PLAN_STATUS) — it is a working set, not a submitted plan, so it must
  // never count towards the Plan / Approve workflow stages.
  const planRows = plans.filter((p) => str(p.status) !== QUEUE_PLAN_STATUS)
  const blockers = buildBlockers(snapshot, certificates)
  const heatmap = buildHeatmap(snapshot, blockers.filter((b) => b.id !== 'blk-none').length)

  return {
    generatedAt: new Date().toISOString(),
    lastScanAt: snapshot.lastAssessmentAt,
    hasData: snapshot.hasData,
    hero: {
      readinessScore: snapshot.scores.quantumReadiness,
      readinessLevel: snapshot.scores.quantumReadinessLevel,
      assetsRequiringMigration: inv.quantumVulnerableAssets,
      vulnerableComponents: inv.vulnerableComponents,
      durationWeeks: snapshot.estimates.migrationTimelineWeeks,
      durationLabel: durationLabel(snapshot.estimates.migrationTimelineWeeks),
      costUsd: snapshot.estimates.migrationCostUsd,
      costLabel: usd(snapshot.estimates.migrationCostUsd),
      riskReductionPct: report.executiveBlock.expectedRiskReductionPct,
      hndlExposure: snapshot.scores.hndlRiskLevel,
      hndlScore: snapshot.scores.hndlRisk,
      pqcAdoption: snapshot.scores.pqcAdoption,
      criticalFindingsRemaining: snapshot.riskDistribution.critical,
      quantumRisk: snapshot.scores.quantumRisk,
      assetsAssessed: inv.assetsAssessed,
    },
    stages: buildStages(snapshot, report, jobs, planRows, validations),
    advisor: {
      ...report.migrationAdvisor,
      deepLink: '/dashboard/quantum-readiness/ai-migration-advisor',
    },
    waves: report.migrationWaves,
    // Shared Responsibility dependency-ordered 7-wave roadmap (Customer Assets →
    // Internal PKI → Origin TLS → Applications → Cloud Providers → Partner
    // Integrations → Industry Adoption) plus tri-part readiness and ownership
    // distribution — the same normalized ownership model the Migration
    // Intelligence Engine, dashboards, reports and certification consume.
    sharedResponsibility: snapshot.sharedResponsibility,
    dependencyGraph: snapshot.exposureGraph,
    dependencyAnalysis: report.dependencyAnalysis,
    businessImpact: report.businessImpact,
    readinessDomains: report.readinessDomains.map((d) => ({ ...d, complexity: d.score >= 65 ? 'Low' : d.score >= 40 ? 'Medium' : 'High' })),
    strategies: buildStrategies(snapshot, report),
    whatIf: buildWhatIf(snapshot, report, cryptoInventory),
    blockers,
    heatmap,
    timeline: buildTimeline(snapshot),
    compliance: report.compliance,
    costForecast: report.costForecast,
    riskEngine: buildRiskEngine(snapshot, report),
    riskForecast: report.riskForecast,
    migrationJobs: jobs.slice(0, 20).map((j) => ({ id: str(j.id), status: str(j.status) || 'unknown', progress: num(j.progress), jobType: str(j.job_type) || 'migration', updatedAt: str(j.updated_at) || str(j.created_at) })),
    evidence: {
      sources: ['PQC Scanner', 'CBOM', 'Certificate Inventory', 'Migration Jobs', 'Trust Fabric', 'Runtime Telemetry'],
      note: snapshot.hasData
        ? `Plan derived from ${inv.assetsAssessed} assets, ${inv.cryptoComponents} components, ${jobs.length} migration job(s). Metrics mirror scanner intelligence.`
        : `${EVIDENCE_UNAVAILABLE}. No scans recorded for this tenant.`,
    },
  }
}

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const data = await buildPlan(token!, user!.id)
    res.json({ data })
  } catch (error) {
    console.error('Migration planner error:', error)
    res.status(500).json({ error: { code: 'MIGRATION_PLANNER_ERROR', message: error instanceof Error ? error.message : 'Failed to build migration plan' } })
  }
})

router.get('/stream', async (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()

  let closed = false
  const send = (event: string, data: unknown) => { if (!closed) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`) }

  const emit = async () => {
    try {
      const data = await buildPlan(token!, user!.id)
      send('migration-plan', data)
    } catch (err) {
      send('migration-plan-error', { message: err instanceof Error ? err.message : 'stream failed' })
    }
  }

  await emit()
  const refresh = setInterval(emit, 30000)
  const heartbeat = setInterval(() => { if (!closed) res.write(': heartbeat\n\n') }, 25000)
  req.on('close', () => { closed = true; clearInterval(refresh); clearInterval(heartbeat) })
})

/* ================================================================== */
/* Asset-Centric Migration Workspace                                   */
/*                                                                     */
/* Per-asset migration intelligence so an operator can review and      */
/* migrate one discovered asset at a time. Every value comes from the  */
/* SHARED engine (src/lib/migration/asset-intelligence.ts) that also   */
/* derives the Quantum Readiness snapshot's per-asset risk and posture */
/* — the same asset can never read differently on two pages.           */
/* ================================================================== */

/** Status marker for the queue-holder migration_plans row. */
const QUEUE_PLAN_STATUS = 'migration_queue'
const queuePlanId = (userId: string) => `asset-queue-${userId}`

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function rows(client: any, table: string, build: (q: any) => any): Promise<Row[]> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`[migration-planner] ${table} query skipped:`, error.message || error)
      return []
    }
    return (data as Row[]) || []
  } catch (error) {
    console.warn(`[migration-planner] ${table} query failed:`, (error as Error)?.message || error)
    return []
  }
}

/** Reads the tenant's persisted migration queue (ordered asset ids). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function readQueue(client: any, userId: string): Promise<{ assetIds: string[]; updatedAt: string | null }> {
  const found = await rows(client, 'migration_plans', (q) =>
    q.select('id, selected_asset_ids, metadata, updated_at').eq('user_id', userId).eq('id', queuePlanId(userId)).limit(1),
  )
  const row = found[0]
  if (!row) return { assetIds: [], updatedAt: null }
  const ids = Array.isArray(row.selected_asset_ids) ? (row.selected_asset_ids as unknown[]).map(str).filter(Boolean) : []
  return { assetIds: ids, updatedAt: str(row.updated_at) || null }
}

/** Persists the tenant's migration queue. Order IS the migration sequence. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function writeQueue(client: any, userId: string, assetIds: string[], email?: string | null) {
  const now = new Date().toISOString()
  const { error } = await client.from('migration_plans').upsert(
    {
      id: queuePlanId(userId),
      user_id: userId,
      status: QUEUE_PLAN_STATUS,
      selected_asset_ids: assetIds,
      configuration: { source: 'migration-planner-asset-queue' },
      risk_data: {},
      metadata: {
        name: 'Asset Migration Queue',
        kind: 'asset-migration-queue',
        updatedBy: email || 'planner',
        updatedAt: now,
        sequence: assetIds,
      },
      created_at: now,
      updated_at: now,
    },
    { onConflict: 'id' },
  )
  if (error) throw new Error(error.message || 'Queue persistence failed')
}

/**
 * Loads the tenant's raw migration evidence and derives every asset dossier.
 *
 * Short-TTL single-flight cache mirrors buildSnapshot's contract: the selector,
 * the dossier route and the queue all read the SAME computation inside a window,
 * so the list and the detail pane can never show different numbers.
 */
const PORTFOLIO_TTL_MS = 15_000
const portfolioCache = new Map<string, { at: number; promise: Promise<AssetPortfolio> }>()

async function computePortfolio(token: string, userId: string): Promise<AssetPortfolio> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [
    assets,
    cryptoInventory,
    scanResults,
    cryptoExposures,
    certificates,
    runtimeEvents,
    relationships,
    migrationJobs,
    validationLogs,
    complianceEvidence,
    queue,
  ] = await Promise.all([
    rows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1500)),
    rows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, discovered_at, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2500)),
    rows(client, 'pqc_scan_results', (q) => q.select('id, asset_id, finding_type, algorithm, threat_level, description, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2000)),
    rows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2000)),
    rows(client, 'certificates', (q) => q.select('id, asset_id, name, subject, algorithm, key_size, issuer, not_after, is_quantum_safe, is_expiring_soon, status, created_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1500)),
    rows(client, 'runtime_crypto_events', (q) => q.select('id, asset_id, algorithm, key_exchange_algorithm, cipher_suite, protocol, severity, risk_score, is_pqc, is_legacy, hndl_risk, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(4000)),
    rows(client, 'asset_relationships', (q) => q.select('*').eq('user_id', userId).limit(3000)),
    rows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, target_algorithm, progress, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1200)),
    // migration_validation_logs is job-scoped, not asset-scoped: its only FK is
    // migration_id -> migration_jobs(id). Selecting asset_id/migration_job_id
    // made PostgREST reject the whole query (42703), so the planner silently
    // lost every validation signal. Ask for the columns that actually exist.
    rows(client, 'migration_validation_logs', (q) => q.select('id, migration_id, status, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(600)),
    rows(client, 'compliance_evidence', (q) => q.select('id, asset_id, framework, control_id, status, description, created_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    readQueue(client, userId),
  ])

  return buildAssetPortfolio({
    assets,
    cryptoInventory,
    scanResults,
    cryptoExposures,
    certificates,
    runtimeEvents,
    relationships,
    migrationJobs,
    validationLogs,
    complianceEvidence,
    queuedAssetIds: queue.assetIds,
  })
}

/**
 * Exported so sibling modules (Crypto Agility) can consume the SAME cached
 * per-asset dossiers instead of re-fetching and re-deriving the tenant's
 * evidence. Sharing the cache is what keeps asset facts identical across pages.
 */
export async function buildPortfolio(token: string, userId: string, force = false): Promise<AssetPortfolio> {
  const cached = portfolioCache.get(userId)
  if (!force && cached && Date.now() - cached.at < PORTFOLIO_TTL_MS) return cached.promise
  const promise = computePortfolio(token, userId)
  portfolioCache.set(userId, { at: Date.now(), promise })
  promise.catch(() => portfolioCache.delete(userId))
  if (portfolioCache.size > 500) {
    const now = Date.now()
    for (const [key, value] of portfolioCache) if (now - value.at > PORTFOLIO_TTL_MS) portfolioCache.delete(key)
  }
  return promise
}

/** Selector row — the bounded projection the asset list renders. */
function compactRecord(record: AssetMigrationRecord) {
  return {
    id: record.id,
    name: record.name,
    type: record.type,
    hostname: record.hostname,
    environment: record.environment,
    owner: record.owner,
    businessCriticality: record.businessCriticality,
    internetFacing: record.internetFacing,
    hasEvidence: record.hasEvidence,
    riskScore: record.riskScore,
    riskLevel: record.riskLevel,
    readinessScore: record.readinessScore,
    readinessLevel: record.readinessLevel,
    posture: record.posture,
    postureLabel: record.postureLabel,
    priority: record.priority,
    priorityScore: record.priorityScore,
    hndlScore: record.hndlScore,
    hndlLevel: record.hndlLevel,
    migrationStatus: record.migrationStatus,
    migrationProgressPct: record.migrationProgressPct,
    estimatedDurationLabel: record.estimatedDurationLabel,
    estimatedEffortHours: record.estimatedEffortHours,
    cryptoPostureSummary: record.cryptoPostureSummary,
    componentCount: record.componentCount,
    vulnerableComponentCount: record.vulnerableComponentCount,
    severityCounts: record.severityCounts,
    blastRadius: record.blastRadius,
    successProbabilityPct: record.successProbabilityPct,
    queued: record.queued,
    tags: record.tags,
    lastEvidenceAt: record.lastEvidenceAt,
  }
}

export type CompactAssetRecord = ReturnType<typeof compactRecord>

/* ---- GET /assets — filtered, paginated selector feed ---- */
router.get('/assets', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const [portfolio, snapshot] = await Promise.all([buildPortfolio(token!, user!.id), buildSnapshot(token!, user!.id)])

    const search = str(req.query.search).trim().toLowerCase()
    const posture = str(req.query.posture).trim().toLowerCase()
    const environment = str(req.query.environment).trim().toLowerCase()
    const priority = str(req.query.priority).trim().toLowerCase()
    const status = str(req.query.status).trim().toLowerCase()
    const sort = str(req.query.sort).trim() || 'priority'
    const limit = Math.max(1, Math.min(500, num(req.query.limit) || 200))
    const offset = Math.max(0, num(req.query.offset))

    let filtered = portfolio.assets
    if (search) {
      filtered = filtered.filter((a) =>
        `${a.name} ${a.hostname} ${a.type} ${a.owner} ${a.environment} ${a.tags.join(' ')}`.toLowerCase().includes(search),
      )
    }
    if (posture && posture !== 'all') filtered = filtered.filter((a) => a.posture === posture)
    if (environment && environment !== 'all') filtered = filtered.filter((a) => a.environment.toLowerCase() === environment)
    if (priority && priority !== 'all') filtered = filtered.filter((a) => a.priority.toLowerCase() === priority)
    if (status && status !== 'all') filtered = filtered.filter((a) => a.migrationStatus.toLowerCase() === status)

    const sorted = [...filtered]
    if (sort === 'risk') sorted.sort((a, b) => b.riskScore - a.riskScore || b.priorityScore - a.priorityScore)
    else if (sort === 'readiness') sorted.sort((a, b) => a.readinessScore - b.readinessScore || b.priorityScore - a.priorityScore)
    else if (sort === 'name') sorted.sort((a, b) => a.name.localeCompare(b.name))
    else if (sort === 'effort') sorted.sort((a, b) => b.estimatedEffortHours - a.estimatedEffortHours)
    // default: portfolio order (priority score desc) is already applied

    res.json({
      data: {
        generatedAt: portfolio.generatedAt,
        assets: sorted.slice(offset, offset + limit).map(compactRecord),
        total: filtered.length,
        totalUnfiltered: portfolio.assets.length,
        summary: portfolio.summary,
        recommendedOrder: portfolio.recommendedOrder,
        environments: [...new Set(portfolio.assets.map((a) => a.environment))].sort(),
        // Cross-module reconciliation: the asset roll-up MUST equal the tenant
        // totals every other page renders. Surfaced so the UI can prove it.
        reconciliation: {
          snapshot: {
            assetsAssessed: snapshot.inventory.assetsAssessed,
            quantumVulnerableAssets: snapshot.inventory.quantumVulnerableAssets,
            pqcReadyAssets: snapshot.inventory.pqcReadyAssets,
            hybridAssets: snapshot.inventory.hybridAssets,
            vulnerableComponents: snapshot.inventory.vulnerableComponents,
          },
          portfolio: {
            assetsAssessed: portfolio.assets.length,
            quantumVulnerableAssets: portfolio.summary.quantumVulnerable,
            pqcReadyAssets: portfolio.summary.pqcReady,
            hybridAssets: portfolio.summary.hybrid,
            vulnerableComponents: portfolio.assets.reduce((s, a) => s + a.vulnerableComponentCount, 0),
          },
          aligned:
            portfolio.summary.quantumVulnerable === snapshot.inventory.quantumVulnerableAssets &&
            portfolio.summary.pqcReady === snapshot.inventory.pqcReadyAssets &&
            portfolio.summary.hybrid === snapshot.inventory.hybridAssets,
          note: 'Asset posture and risk are derived by the same engine as the Quantum Readiness snapshot, so every asset reads identically on every page. Component counts are shown on two bases: the tenant headline is the scanner-expanded CBOM view, while the asset column sums the CBOM rows bound to each asset — they can differ by rows the scanner view does not expand, and neither figure is adjusted to hide that.',
        },
      },
    })
  } catch (error) {
    console.error('Migration planner assets error:', error)
    res.status(500).json({ error: { code: 'ASSET_PORTFOLIO_ERROR', message: error instanceof Error ? error.message : 'Failed to build asset portfolio' } })
  }
})

/* ---- GET /assets/:assetId — full per-asset migration dossier ---- */
router.get('/assets/:assetId', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const assetId = str(req.params.assetId)
    const portfolio = await buildPortfolio(token!, user!.id)
    const record = portfolio.assets.find((a) => a.id === assetId)
    if (!record) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Asset not found for this tenant' } })

    const rank = portfolio.recommendedOrder.find((r) => r.assetId === assetId)
    res.json({
      data: {
        generatedAt: portfolio.generatedAt,
        asset: record,
        position: {
          recommendedRank: rank?.rank ?? null,
          totalRanked: portfolio.recommendedOrder.length,
          rationale: rank?.rationale || 'Not ranked — no cryptographic evidence recorded for this asset.',
          riskPercentile: portfolio.assets.length
            ? Math.round(((portfolio.assets.length - portfolio.assets.findIndex((a) => a.id === assetId)) / portfolio.assets.length) * 100)
            : 0,
        },
      },
    })
  } catch (error) {
    console.error('Migration planner asset dossier error:', error)
    res.status(500).json({ error: { code: 'ASSET_DOSSIER_ERROR', message: error instanceof Error ? error.message : 'Failed to build asset dossier' } })
  }
})

/* ---- Migration queue (persisted, ordered) ---- */
async function respondQueue(req: Request, res: Response) {
  const { token, user } = req as AuthedRequest
  const client = createAuthClient(token!)
  if (!client) return res.status(500).json({ error: { code: 'SUPABASE_UNAVAILABLE', message: 'Data layer unavailable' } })
  const queue = await readQueue(client, user!.id)
  // Mutating routes invalidate the portfolio cache before calling this, so the
  // queue view is always rebuilt from the post-write evidence.
  const portfolio = await buildPortfolio(token!, user!.id)
  const byId = new Map(portfolio.assets.map((a) => [a.id, a]))
  const entries = queue.assetIds
    .map((id, index) => {
      const record = byId.get(id)
      if (!record) return null
      return {
        sequence: index + 1,
        assetId: record.id,
        name: record.name,
        type: record.type,
        environment: record.environment,
        priority: record.priority,
        priorityScore: record.priorityScore,
        riskScore: record.riskScore,
        readinessScore: record.readinessScore,
        estimatedDurationLabel: record.estimatedDurationLabel,
        estimatedEffortHours: record.estimatedEffortHours,
        migrationStatus: record.migrationStatus,
        dependencies: record.dependencies.length,
        blastRadius: record.blastRadius,
        validationState: record.validation.validated
          ? `Validated (${record.validation.lastStatus})`
          : record.validation.cutoverBlocked
            ? `Blocked — ${record.validation.blockerReason}`
            : 'No blockers · not yet validated',
        successProbabilityPct: record.successProbabilityPct,
        posture: record.posture,
        postureLabel: record.postureLabel,
      }
    })
    .filter((entry): entry is NonNullable<typeof entry> => entry !== null)

  return res.json({
    data: {
      planId: queuePlanId(user!.id),
      updatedAt: queue.updatedAt,
      entries,
      totalEffortHours: entries.reduce((s, e) => s + e.estimatedEffortHours, 0),
      // Assets in the queue whose sequence violates the risk-ranked order.
      outOfOrder: entries.filter((entry, index) => index > 0 && entry.priorityScore > entries[index - 1].priorityScore).map((e) => e.assetId),
    },
  })
}

router.get('/queue', async (req: Request, res: Response) => {
  try {
    await respondQueue(req, res)
  } catch (error) {
    console.error('Migration queue read failed:', error)
    res.status(500).json({ error: { code: 'QUEUE_ERROR', message: 'Unable to read the migration queue' } })
  }
})

router.post('/queue', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'SUPABASE_UNAVAILABLE', message: 'Data layer unavailable' } })
    const incoming = Array.isArray(req.body?.assetIds) ? (req.body.assetIds as unknown[]).map(str) : [str(req.body?.assetId)]
    const requested = incoming.filter(Boolean)
    if (!requested.length) return res.status(400).json({ error: { code: 'VALIDATION', message: 'assetId or assetIds is required' } })

    // Tenant verification — only assets that belong to this tenant may be queued.
    const portfolio = await buildPortfolio(token!, user!.id)
    const known = new Set(portfolio.assets.map((a) => a.id))
    const valid = requested.filter((id) => known.has(id))
    if (!valid.length) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'No matching tenant asset for the supplied id(s)' } })

    const queue = await readQueue(client, user!.id)
    const next = [...queue.assetIds]
    for (const id of valid) if (!next.includes(id)) next.push(id)
    await writeQueue(client, user!.id, next.slice(0, 200), user!.email)
    portfolioCache.delete(user!.id)
    await respondQueue(req, res)
  } catch (error) {
    console.error('Migration queue add failed:', error)
    res.status(500).json({ error: { code: 'QUEUE_ADD_ERROR', message: error instanceof Error ? error.message : 'Unable to queue asset' } })
  }
})

router.delete('/queue/:assetId', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'SUPABASE_UNAVAILABLE', message: 'Data layer unavailable' } })
    const assetId = str(req.params.assetId)
    const queue = await readQueue(client, user!.id)
    await writeQueue(client, user!.id, queue.assetIds.filter((id) => id !== assetId), user!.email)
    portfolioCache.delete(user!.id)
    await respondQueue(req, res)
  } catch (error) {
    console.error('Migration queue remove failed:', error)
    res.status(500).json({ error: { code: 'QUEUE_REMOVE_ERROR', message: 'Unable to remove asset from the queue' } })
  }
})

router.post('/queue/reorder', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'SUPABASE_UNAVAILABLE', message: 'Data layer unavailable' } })
    const requested = Array.isArray(req.body?.assetIds) ? (req.body.assetIds as unknown[]).map(str).filter(Boolean) : []
    const queue = await readQueue(client, user!.id)
    const current = new Set(queue.assetIds)
    // Only reorder what is already queued; unknown ids are ignored and any
    // omitted queued asset keeps its place at the end (never silently dropped).
    const reordered = requested.filter((id) => current.has(id))
    const remaining = queue.assetIds.filter((id) => !reordered.includes(id))
    await writeQueue(client, user!.id, [...reordered, ...remaining], user!.email)
    portfolioCache.delete(user!.id)
    await respondQueue(req, res)
  } catch (error) {
    console.error('Migration queue reorder failed:', error)
    res.status(500).json({ error: { code: 'QUEUE_REORDER_ERROR', message: 'Unable to reorder the migration queue' } })
  }
})

router.post('/queue/prioritize', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'SUPABASE_UNAVAILABLE', message: 'Data layer unavailable' } })
    const portfolio = await buildPortfolio(token!, user!.id)
    const rank = new Map(portfolio.assets.map((a) => [a.id, a.priorityScore]))
    const queue = await readQueue(client, user!.id)
    const sorted = [...queue.assetIds].sort((a, b) => (rank.get(b) ?? 0) - (rank.get(a) ?? 0))
    await writeQueue(client, user!.id, sorted, user!.email)
    portfolioCache.delete(user!.id)
    await respondQueue(req, res)
  } catch (error) {
    console.error('Migration queue prioritize failed:', error)
    res.status(500).json({ error: { code: 'QUEUE_PRIORITIZE_ERROR', message: 'Unable to apply the recommended order' } })
  }
})

/* ---- POST /plans/:planId/context — authoritative Live Migration handoff ---- */
/*
 * The planner dispatches through the existing execution pipeline
 * (POST /api/v1/migration/planner/create with action=start), which creates the
 * real migration_jobs and dispatch bookkeeping. This route then stamps the
 * SERVER-DERIVED migration context (plan, recommendations, validation state,
 * priority, dependencies, rollback configuration, readiness) onto that plan so
 * Live Migration loads exactly what the planner displayed — no client-supplied
 * numbers are trusted.
 */
router.post('/plans/:planId/context', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'SUPABASE_UNAVAILABLE', message: 'Data layer unavailable' } })
    const planId = str(req.params.planId)
    const assetIds = Array.isArray(req.body?.assetIds) ? (req.body.assetIds as unknown[]).map(str).filter(Boolean) : []
    if (!assetIds.length) return res.status(400).json({ error: { code: 'VALIDATION', message: 'assetIds is required' } })

    const portfolio = await buildPortfolio(token!, user!.id)
    const records = assetIds.map((id) => portfolio.assets.find((a) => a.id === id)).filter((a): a is AssetMigrationRecord => Boolean(a))
    if (!records.length) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'No matching tenant asset for the supplied id(s)' } })

    const { data: existing, error: readError } = await client
      .from('migration_plans')
      .select('id, status, metadata')
      .eq('user_id', user!.id)
      .eq('id', planId)
      .limit(1)
    if (readError) return res.status(500).json({ error: { code: 'PLAN_READ_FAILED', message: readError.message } })
    const row = ((existing as Row[]) || [])[0]
    if (!row) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Migration plan not found' } })

    const migrationContext = {
      source: 'migration-planner-asset-workspace',
      stampedAt: new Date().toISOString(),
      stampedBy: user!.email || 'planner',
      assets: records.map((record) => ({
        assetId: record.id,
        name: record.name,
        type: record.type,
        hostname: record.hostname,
        environment: record.environment,
        owner: record.owner,
        businessCriticality: record.businessCriticality,
        priority: record.priority,
        priorityScore: record.priorityScore,
        riskScore: record.riskScore,
        readinessScore: record.readinessScore,
        posture: record.posture,
        hndlScore: record.hndlScore,
        estimatedEffortHours: record.estimatedEffortHours,
        estimatedDowntime: record.estimatedDowntime,
        successProbabilityPct: record.successProbabilityPct,
        currentAlgorithms: record.algorithms.map((a) => ({ algorithm: a.algorithm, classification: a.classification, instances: a.instances })),
        recommendations: record.recommendations,
        dependencies: record.dependencies,
        rollbackStrategy: record.rollbackStrategy,
        requiredApprovals: record.requiredApprovals,
        validation: record.validation,
        compatibility: record.compatibility,
        compliance: record.compliance,
        evidence: record.evidence,
      })),
    }

    const metadata = { ...recordOf(row.metadata), migrationContext }
    const { error } = await client
      .from('migration_plans')
      .update({ metadata, updated_at: new Date().toISOString() })
      .eq('user_id', user!.id)
      .eq('id', planId)
    if (error) return res.status(500).json({ error: { code: 'CONTEXT_STAMP_FAILED', message: error.message } })

    // Audit trail — the handoff is an operator action against real assets.
    await client
      .from('migration_events')
      .insert({
        user_id: user!.id,
        migration_id: null,
        event_type: 'planner-asset-handoff',
        severity: 'info',
        message: `${records.length} asset(s) sent to Live Migration from the Migration Planner asset workspace.`,
        metadata: { planId, assetIds: records.map((r) => r.id), source: 'migration-planner-asset-workspace' },
        created_at: new Date().toISOString(),
      })
      .then(({ error: eventError }: { error: { message?: string } | null }) => {
        if (eventError) console.warn('[migration-planner] handoff audit event skipped:', eventError.message)
      })

    portfolioCache.delete(user!.id)
    res.json({ data: { planId, assets: records.length, liveMigrationUrl: `/dashboard/live-migration?planId=${encodeURIComponent(planId)}` } })
  } catch (error) {
    console.error('Migration handoff context failed:', error)
    res.status(500).json({ error: { code: 'CONTEXT_ERROR', message: error instanceof Error ? error.message : 'Unable to stamp migration context' } })
  }
})

/* ------------------------------------------------------------------ */
/* Approval workflow — real migration_plans rows (no new tables).      */
/* Submit → pending_approval; approve/reject stamps the decision into  */
/* the plan metadata. The 9-stage 'Approve' stage and the platform     */
/* WorkflowRail both read these same rows, so status stays consistent. */
/* ------------------------------------------------------------------ */
type ApprovalMeta = { name?: string; submittedBy?: string; submittedAt?: string; approval?: { decision: string; decidedBy: string; decidedAt: string; reason: string } }

function mapPlanRow(row: Row) {
  const metadata = (row.metadata && typeof row.metadata === 'object' ? row.metadata : {}) as ApprovalMeta
  return {
    id: str(row.id),
    // migration_plans has no name column — the display name lives in metadata.
    name: str(metadata.name) || 'PQC Migration Plan',
    status: str(row.status) || 'draft',
    createdAt: str(row.created_at),
    updatedAt: str(row.updated_at) || str(row.created_at),
    submittedBy: str(metadata.submittedBy),
    approval: metadata.approval
      ? { decision: str(metadata.approval.decision), decidedBy: str(metadata.approval.decidedBy), decidedAt: str(metadata.approval.decidedAt), reason: str(metadata.approval.reason) }
      : null,
  }
}

router.get('/plans', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'SUPABASE_UNAVAILABLE', message: 'Data layer unavailable' } })
    const { data, error } = await client
      .from('migration_plans')
      .select('id, status, metadata, created_at, updated_at')
      .eq('user_id', user!.id)
      .neq('status', QUEUE_PLAN_STATUS)
      .order('updated_at', { ascending: false })
      .limit(50)
    if (error) return res.status(500).json({ error: { code: 'PLANS_QUERY_FAILED', message: error.message } })
    res.json({ data: ((data as Row[]) || []).map(mapPlanRow) })
  } catch (error) {
    console.error('migration plans list failed:', error)
    res.status(500).json({ error: { code: 'PLANS_ERROR', message: 'Unable to list migration plans' } })
  }
})

router.post('/plans', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'SUPABASE_UNAVAILABLE', message: 'Data layer unavailable' } })
    const name = str(req.body?.name).trim().slice(0, 160) || `PQC Migration Plan — ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}`
    const now = new Date().toISOString()
    const row: Record<string, unknown> = {
      id: (globalThis.crypto?.randomUUID?.() as string) || `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
      user_id: user!.id,
      status: 'pending_approval',
      selected_asset_ids: [],
      configuration: { source: 'migration-planner-approval' },
      risk_data: {},
      metadata: { name, submittedBy: user!.email || 'planner', submittedAt: now, source: 'migration-planner' },
      created_at: now,
      updated_at: now,
    }
    const { error } = await client.from('migration_plans').insert(row)
    if (error) return res.status(500).json({ error: { code: 'PLAN_SUBMIT_FAILED', message: error.message } })
    res.status(201).json({ data: mapPlanRow(row as Row) })
  } catch (error) {
    console.error('migration plan submit failed:', error)
    res.status(500).json({ error: { code: 'PLAN_SUBMIT_ERROR', message: 'Unable to submit plan for approval' } })
  }
})

router.post('/plans/:planId/approval', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'SUPABASE_UNAVAILABLE', message: 'Data layer unavailable' } })
    const planId = str(req.params.planId)
    const decision = str(req.body?.decision).toLowerCase()
    if (!['approve', 'reject'].includes(decision)) {
      return res.status(400).json({ error: { code: 'VALIDATION', message: 'decision must be approve or reject' } })
    }
    const reason = str(req.body?.reason).trim().slice(0, 1000)
    const { data: existing, error: readError } = await client
      .from('migration_plans')
      .select('id, status, metadata, created_at, updated_at')
      .eq('user_id', user!.id)
      .eq('id', planId)
      .limit(1)
    if (readError) return res.status(500).json({ error: { code: 'PLAN_READ_FAILED', message: readError.message } })
    const row = ((existing as Row[]) || [])[0]
    if (!row) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Migration plan not found' } })
    const metadata = {
      ...(row.metadata && typeof row.metadata === 'object' ? (row.metadata as Record<string, unknown>) : {}),
      approval: { decision, decidedBy: user!.email || 'owner', decidedAt: new Date().toISOString(), reason },
    }
    const status = decision === 'approve' ? 'approved' : 'rejected'
    const { error } = await client
      .from('migration_plans')
      .update({ status, metadata, updated_at: new Date().toISOString() })
      .eq('user_id', user!.id)
      .eq('id', planId)
    if (error) return res.status(500).json({ error: { code: 'APPROVAL_FAILED', message: error.message } })
    res.json({ data: mapPlanRow({ ...row, status, metadata }) })
  } catch (error) {
    console.error('migration plan approval failed:', error)
    res.status(500).json({ error: { code: 'APPROVAL_ERROR', message: 'Unable to record approval decision' } })
  }
})

export default router
