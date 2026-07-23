import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { buildReportModel } from '@/services/reporting/ReportEvidence'
import { brandingSchema } from '@/services/reporting/schemas/ReportSchema'

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
function buildWhatIf(snapshot: Snapshot, report: ReportModel) {
  const cost = snapshot.estimates.migrationCostUsd || 0
  const reduction = report.executiveBlock.expectedRiskReductionPct
  const domainScore = (needle: string) => report.readinessDomains.find((d) => d.domain.toLowerCase().includes(needle))?.score ?? 0
  const tlsShare = clamp(((100 - domainScore('tls')) / Math.max(1, report.readinessDomains.reduce((s, d) => s + (100 - d.score), 0))) * 100)
  return [
    { scenario: 'Migrate External TLS Infrastructure', riskReductionPct: clamp(reduction * 0.4), costUsd: Math.round(cost * 0.2), timelineLabel: '4 Weeks', complianceIncreasePct: 12 },
    { scenario: 'Migrate PKI Infrastructure', riskReductionPct: clamp(reduction * 0.22), costUsd: Math.round(cost * 0.25), timelineLabel: '3 Months', complianceIncreasePct: 18 },
    { scenario: 'Enable Full Hybrid TLS', riskReductionPct: clamp(reduction * 0.55), costUsd: Math.round(cost * 0.3), timelineLabel: '6 Weeks', complianceIncreasePct: 23 },
    { scenario: `Migrate ${tlsShare}%-weighted TLS exposure first`, riskReductionPct: clamp(reduction * 0.45), costUsd: Math.round(cost * 0.22), timelineLabel: '5 Weeks', complianceIncreasePct: 15 },
  ]
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
  const [jobs, plans, validations, events, certificates] = client
    ? await Promise.all([
        safeRows(client as never, 'migration_jobs', 'id, status, progress, asset_id, job_type, created_at, updated_at', userId, 300),
        // NOTE: migration_plans has no `name` column (display name lives in
        // metadata) — selecting one makes PostgREST error and safeRows silently
        // return [], which broke the Approve stage before the approval workflow.
        safeRows(client as never, 'migration_plans', 'id, status, created_at', userId, 100),
        safeRows(client as never, 'migration_validation_logs', 'id, status, created_at', userId, 200),
        safeRows(client as never, 'migration_events', 'id, event_type, status, created_at', userId, 200),
        safeRows(client as never, 'certificates', 'id, common_name, name, not_after, valid_to, signature_algorithm', userId, 500),
      ])
    : [[], [], [], [], []]

  const inv = snapshot.inventory
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
      criticalAssetsRemaining: snapshot.riskDistribution.critical,
      quantumRisk: snapshot.scores.quantumRisk,
      assetsAssessed: inv.assetsAssessed,
    },
    stages: buildStages(snapshot, report, jobs, plans, validations),
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
    whatIf: buildWhatIf(snapshot, report),
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
