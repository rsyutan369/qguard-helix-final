import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { assembleEvidence, buildRemediationPlan, type RemediationEvidence } from './quantum-remediation'
import type { RemediationPlan } from '@/types/quantum-remediation'
import type {
  MigrationWorkflowState,
  WorkflowAssetState,
  WorkflowNextAction,
  WorkflowStage,
  WorkflowStageId,
  WorkflowStageStatus,
} from '@/types/migration-workflow'

/**
 * Post-Quantum Migration Workflow™ engine.
 *
 * Computes the platform-wide, state-driven lifecycle
 * (Discovery → CBOM → Assessment → Risk → Remediation → Planning → Approval →
 * Execution → Validation → Monitoring → Certification) from the SAME evidence
 * sources the individual modules render — the Q-REMEDY remediation plan,
 * migration plans/jobs/validation logs and the certificate registry — so the
 * WorkflowRail every dashboard embeds can never disagree with the page it
 * sits on.
 *
 * The full evidence assembly is heavy (~seconds), and the rail is embedded on
 * ten pages, so results are cached per user for a short TTL; any page load
 * inside the window reuses the computed state.
 */

const router = Router()
const CACHE_TTL_MS = 30_000
const stateCache = new Map<string, { at: number; state: MigrationWorkflowState }>()

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = getToken(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}
router.use(requireAuth)

function str(value: unknown): string {
  return typeof value === 'string' ? value : value == null ? '' : String(value)
}
function clampPct(value: number): number {
  return Math.max(0, Math.min(100, Math.round(Number.isFinite(value) ? value : 0)))
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function safeRows(client: any, table: string, build: (query: any) => any): Promise<Record<string, unknown>[]> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) return []
    return (data as Record<string, unknown>[]) || []
  } catch {
    return []
  }
}

const STAGE_LABELS: Record<WorkflowStageId, { label: string; short: string; route: string }> = {
  discovery: { label: 'Asset Discovery', short: 'Discover', route: '/dashboard/assets' },
  cbom: { label: 'Cryptographic Inventory (CBOM)', short: 'CBOM', route: '/dashboard/cbom' },
  assessment: { label: 'Quantum Readiness Assessment', short: 'Assess', route: '/dashboard/quantum-readiness' },
  risk: { label: 'Risk Prioritization', short: 'Risk', route: '/dashboard/quantum-readiness/risk-analysis' },
  remediation: { label: 'AI Remediation', short: 'Remediate', route: '/dashboard/quantum-readiness/remediation' },
  planning: { label: 'Migration Planning', short: 'Plan', route: '/dashboard/migration-planner' },
  approval: { label: 'Approval Workflow', short: 'Approve', route: '/dashboard/migration-planner' },
  execution: { label: 'Live Migration', short: 'Execute', route: '/dashboard/live-migration' },
  validation: { label: 'Validation & Verification', short: 'Validate', route: '/dashboard/live-migration' },
  monitoring: { label: 'Continuous Monitoring', short: 'Monitor', route: '/dashboard/runtime-crypto-intel' },
  certification: { label: 'Quantum Trust Certification', short: 'Certify', route: '/dashboard/quantum-certification' },
}

function makeStage(id: WorkflowStageId, status: WorkflowStageStatus, progressPct: number, kpi: string, detail: string): WorkflowStage {
  const meta = STAGE_LABELS[id]
  return { id, label: meta.label, shortLabel: meta.short, status, progressPct: clampPct(progressPct), kpi, detail, route: meta.route }
}

export interface WorkflowInputs {
  evidence: RemediationEvidence
  plan: RemediationPlan
  assetCount: number
  scanSessions: number
  plans: Array<{ id: string; status: string }>
  validations: Array<{ status: string }>
  certificates: Array<{ status: string; level: string; expiresAt: string }>
}

/** Pure derivation — offline-testable. */
export function deriveWorkflowState(inputs: WorkflowInputs): MigrationWorkflowState {
  const { evidence, plan } = inputs
  const m = evidence.measures
  const hasData = evidence.hasData
  const totalFindings = m.critical + m.high + m.medium + m.low
  const openActions = plan.progress.openActions
  const totalActions = plan.progress.totalActions

  const runningJobs = evidence.migrationJobs.filter((j) => /running|in_progress|active|executing/i.test(j.status))
  const completedJobs = evidence.migrationJobs.filter((j) => /complete|succeed|done|validated/i.test(j.status))
  const totalJobs = evidence.migrationJobs.length

  const approvedPlans = inputs.plans.filter((p) => /approved/i.test(p.status))
  const rejectedPlans = inputs.plans.filter((p) => /reject/i.test(p.status))
  const passedValidations = inputs.validations.filter((v) => /pass|success|valid|ok|complete/i.test(str(v.status)))

  const activeCert = inputs.certificates.find((c) => c.status === 'active') || null
  const suspendedCert = inputs.certificates.find((c) => c.status === 'suspended') || null

  const stages: WorkflowStage[] = [
    makeStage(
      'discovery',
      inputs.assetCount > 0 ? 'complete' : 'pending',
      inputs.assetCount > 0 ? 100 : 0,
      `${inputs.assetCount} asset${inputs.assetCount === 1 ? '' : 's'}`,
      inputs.assetCount > 0 ? 'Asset inventory populated from discovery evidence.' : 'Run a discovery scan to populate the asset inventory.',
    ),
    makeStage(
      'cbom',
      m.totalComponents > 0 ? 'complete' : 'pending',
      m.totalComponents > 0 ? 100 : 0,
      `${m.totalComponents} component${m.totalComponents === 1 ? '' : 's'}`,
      m.totalComponents > 0 ? 'Cryptographic Bill of Materials generated from scans.' : 'No cryptographic components inventoried yet.',
    ),
    makeStage(
      'assessment',
      hasData ? 'complete' : 'pending',
      hasData ? 100 : 0,
      hasData ? `Readiness ${evidence.scores.quantumReadiness}/100` : 'Not assessed',
      hasData ? 'Quantum Readiness scores computed from live evidence.' : 'Assessment requires discovery evidence.',
    ),
    makeStage(
      'risk',
      totalFindings > 0 ? 'complete' : hasData ? 'active' : 'pending',
      totalFindings > 0 ? 100 : 0,
      `${m.critical} critical · ${totalFindings} finding${totalFindings === 1 ? '' : 's'}`,
      totalFindings > 0 ? 'Findings graded and prioritized by severity.' : 'No graded findings yet.',
    ),
    makeStage(
      'remediation',
      !hasData ? 'pending' : openActions === 0 && totalActions === 0 && plan.certificationEligible ? 'complete' : openActions === 0 && totalActions === 0 ? 'active' : 'active',
      totalActions > 0 ? ((totalActions - openActions) / totalActions) * 100 : plan.certificationEligible ? 100 : hasData ? plan.certificationReadinessPct : 0,
      `${openActions} open action${openActions === 1 ? '' : 's'}`,
      totalActions > 0 ? `Q-REMEDY queue: ${plan.queues.critical} critical / ${plan.queues.high} high priority.` : 'Remediation queue is clear.',
    ),
    makeStage(
      'planning',
      inputs.plans.length > 0 ? 'complete' : hasData ? 'active' : 'pending',
      inputs.plans.length > 0 ? 100 : 0,
      `${inputs.plans.length} plan${inputs.plans.length === 1 ? '' : 's'}`,
      inputs.plans.length > 0 ? 'Migration plan(s) drafted in the Migration Planner.' : 'Create a migration plan from the remediation roadmap.',
    ),
    makeStage(
      'approval',
      approvedPlans.length > 0 ? 'complete' : rejectedPlans.length > 0 && approvedPlans.length === 0 ? 'blocked' : inputs.plans.length > 0 ? 'active' : 'pending',
      approvedPlans.length > 0 ? 100 : 0,
      approvedPlans.length > 0 ? `${approvedPlans.length} approved` : inputs.plans.length > 0 ? 'Awaiting approval' : 'No plan submitted',
      approvedPlans.length > 0
        ? 'Executive approval recorded on the migration plan.'
        : rejectedPlans.length > 0
          ? 'Latest plan was rejected — revise and resubmit.'
          : 'Submit the migration plan for approval in the Migration Planner.',
    ),
    makeStage(
      'execution',
      runningJobs.length > 0 ? 'active' : completedJobs.length > 0 ? 'complete' : approvedPlans.length > 0 ? 'active' : 'pending',
      totalJobs > 0 ? (completedJobs.length / totalJobs) * 100 : 0,
      `${completedJobs.length}/${totalJobs} job${totalJobs === 1 ? '' : 's'}`,
      runningJobs.length > 0
        ? `${runningJobs.length} migration job(s) executing now.`
        : completedJobs.length > 0
          ? 'Migration jobs completed — validate and rescan.'
          : 'Execute approved migrations through Live Migration Operations.',
    ),
    makeStage(
      'validation',
      passedValidations.length > 0 ? 'complete' : completedJobs.length > 0 ? 'active' : 'pending',
      inputs.validations.length > 0 ? (passedValidations.length / inputs.validations.length) * 100 : 0,
      `${passedValidations.length}/${inputs.validations.length} validation${inputs.validations.length === 1 ? '' : 's'}`,
      passedValidations.length > 0 ? 'Migration validation checks recorded.' : 'Run validation after each migration, then rescan.',
    ),
    makeStage(
      'monitoring',
      // "Live" requires telemetry to be CURRENT, not merely to exist. Testing
      // `runtimeMeasured` alone claimed "streaming — continuously monitored" on
      // a tenant whose newest runtime event was 15 hours old and whose only
      // collector had never sent a heartbeat — a claim Runtime Telemetry
      // contradicts from the same evidence.
      m.runtimeFresh || m.runtimeMeasured ? 'active' : inputs.scanSessions >= 2 ? 'active' : 'pending',
      m.runtimeFresh ? 100 : m.runtimeMeasured ? 70 : inputs.scanSessions >= 2 ? 60 : 0,
      m.runtimeFresh
        ? 'Runtime telemetry live'
        : m.runtimeMeasured
          ? 'Runtime telemetry stale'
          : `${inputs.scanSessions} scan session${inputs.scanSessions === 1 ? '' : 's'}`,
      m.runtimeFresh
        ? 'Runtime cryptographic telemetry is streaming — posture is continuously monitored.'
        : m.runtimeMeasured
          ? 'Runtime telemetry has been received but is no longer current. Check collector health in Runtime Telemetry.'
          : 'Connect runtime telemetry for continuous cryptographic monitoring.',
    ),
    makeStage(
      'certification',
      activeCert ? 'complete' : suspendedCert ? 'blocked' : plan.certificationEligible ? 'active' : 'pending',
      activeCert ? 100 : plan.certificationReadinessPct,
      activeCert ? `Certified — ${activeCert.level}` : suspendedCert ? 'Suspended (drift)' : `${plan.certificationReadinessPct}% ready`,
      activeCert
        ? 'Quantum Trust Certificate™ active and continuously re-validated.'
        : suspendedCert
          ? 'Certificate suspended by continuous monitoring — remediate the drift and reinstate.'
          : plan.certificationEligible
            ? 'All criteria pass — issue the Quantum Trust Certificate™.'
            : `${plan.requiredMet}/${plan.requiredTotal} certification criteria met.`,
    ),
  ]

  // Current stage = first stage that still needs work. A healthy 'active'
  // monitoring stage counts as satisfied (monitoring never completes by design).
  const currentStage =
    stages.find((s) => (s.id === 'monitoring' ? s.status === 'pending' : s.status !== 'complete')) || stages[stages.length - 1]

  const overallProgressPct = clampPct(stages.reduce((sum, s) => sum + s.progressPct, 0) / stages.length)

  const nextAction = deriveNextAction(currentStage.id, plan, inputs)

  // Per-asset lifecycle position (evidence assets, highest risk first).
  const actionsByAsset = new Map<string, { open: number; inProgress: number; gain: number }>()
  for (const action of plan.actions) {
    const entry = actionsByAsset.get(action.asset) || { open: 0, inProgress: 0, gain: 0 }
    if (action.status === 'in_progress') entry.inProgress += 1
    else if (action.status === 'open') entry.open += 1
    entry.gain += action.certificationGainPct
    actionsByAsset.set(action.asset, entry)
  }
  const jobsByAssetId = new Map<string, string>()
  for (const job of evidence.migrationJobs) {
    if (!job.assetId) continue
    const current = jobsByAssetId.get(job.assetId)
    if (/running|in_progress|active|executing/i.test(job.status)) jobsByAssetId.set(job.assetId, 'running')
    else if (!current && /complete|succeed|done|validated/i.test(job.status)) jobsByAssetId.set(job.assetId, 'completed')
  }

  const assetStates: WorkflowAssetState[] = [...evidence.assets]
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 200)
    .map((asset) => {
      const actions = actionsByAsset.get(asset.name) || { open: 0, inProgress: 0, gain: 0 }
      const jobState = jobsByAssetId.get(asset.id) || 'none'
      const migrationStatus: WorkflowAssetState['migrationStatus'] =
        jobState === 'running' ? 'running' : jobState === 'completed' ? 'completed' : approvedPlans.length > 0 && actions.open > 0 ? 'planned' : 'none'
      let stageId: WorkflowStageId
      if (actions.inProgress > 0 || jobState === 'running') stageId = 'execution'
      else if (actions.open > 0) stageId = approvedPlans.length > 0 ? 'execution' : 'remediation'
      else if (jobState === 'completed') stageId = 'validation'
      else stageId = 'monitoring'
      const validationStatus =
        actions.open === 0 && actions.inProgress === 0
          ? jobState === 'completed'
            ? 'Verified by rescan'
            : 'Quantum-safe (monitored)'
          : jobState === 'completed'
            ? 'Pending rescan'
            : '—'
      return {
        asset: asset.name,
        stageId,
        stageLabel: STAGE_LABELS[stageId].label,
        riskScore: asset.riskScore,
        openActions: actions.open + actions.inProgress,
        migrationStatus,
        validationStatus,
        certificationImpactPct: Math.round(actions.gain * 10) / 10,
      }
    })

  const lifecycleCounts = new Map<WorkflowStageId, number>()
  for (const state of assetStates) lifecycleCounts.set(state.stageId, (lifecycleCounts.get(state.stageId) || 0) + 1)
  const assetLifecycle = (['remediation', 'execution', 'validation', 'monitoring'] as WorkflowStageId[]).map((stageId) => ({
    stageId,
    label: STAGE_LABELS[stageId].label,
    count: lifecycleCounts.get(stageId) || 0,
  }))

  return {
    generatedAt: new Date().toISOString(),
    hasData,
    overallProgressPct,
    currentStageId: currentStage.id,
    stages,
    nextAction,
    certificationReadinessPct: plan.certificationReadinessPct,
    certificationEligible: plan.certificationEligible,
    assetLifecycle,
    assetStates,
  }
}

function deriveNextAction(stageId: WorkflowStageId, plan: RemediationPlan, inputs: WorkflowInputs): WorkflowNextAction {
  switch (stageId) {
    case 'discovery':
    case 'cbom':
    case 'assessment':
      return { stageId, title: 'Run a PQC discovery scan', detail: 'Populate the asset inventory and CBOM with real cryptographic evidence.', route: '/dashboard/scanner' }
    case 'risk':
      return { stageId, title: 'Review graded findings', detail: 'Prioritize the discovered cryptographic exposure by severity and business impact.', route: '/dashboard/quantum-readiness/risk-analysis' }
    case 'remediation': {
      const first = plan.actions.find((a) => a.status === 'open')
      return first
        ? { stageId, title: `Fix #${first.rank}: ${first.asset}`, detail: `${first.recommendation} (+${first.certificationGainPct}% certification readiness)`, route: '/dashboard/quantum-readiness/remediation' }
        : { stageId, title: 'Open the remediation roadmap', detail: 'Review the Q-REMEDY queue and certification gaps.', route: '/dashboard/quantum-readiness/remediation' }
    }
    case 'planning':
      return { stageId, title: 'Draft the migration plan', detail: 'Sequence the remediation queue into migration waves in the Migration Planner.', route: '/dashboard/migration-planner' }
    case 'approval':
      return inputs.plans.length > 0
        ? { stageId, title: 'Approve the migration plan', detail: 'Record executive approval so execution can begin.', route: '/dashboard/migration-planner' }
        : { stageId, title: 'Submit the plan for approval', detail: 'Create and submit the migration plan from the Migration Planner.', route: '/dashboard/migration-planner' }
    case 'execution':
      return { stageId, title: 'Execute approved migrations', detail: 'Orchestrate migration jobs through Live Migration Operations.', route: '/dashboard/live-migration' }
    case 'validation':
      return { stageId, title: 'Validate and rescan', detail: 'Verify each migration, then rescan so the readiness score reflects the change.', route: '/dashboard/scanner' }
    case 'monitoring':
      return { stageId, title: 'Connect runtime telemetry', detail: 'Enable continuous cryptographic monitoring across the estate.', route: '/dashboard/runtime-crypto-intel' }
    case 'certification':
    default:
      return plan.certificationEligible
        ? { stageId: 'certification', title: 'Issue the Quantum Trust Certificate™', detail: 'All required criteria pass from measured evidence.', route: '/dashboard/quantum-certification' }
        : { stageId: 'certification', title: 'Close the remaining certification criteria', detail: `${plan.requiredMet}/${plan.requiredTotal} criteria met — follow the remediation roadmap.`, route: '/dashboard/quantum-readiness/remediation' }
  }
}

/* ------------------------------------------------------------------ */
/* Live assembly (cached)                                              */
/* ------------------------------------------------------------------ */
export async function buildWorkflowState(token: string, userId: string): Promise<MigrationWorkflowState> {
  const cached = stateCache.get(userId)
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.state

  const evidence = await assembleEvidence(token, userId)
  const plan = buildRemediationPlan(evidence)
  const client = createAuthClient(token)

  let assetCount = evidence.assets.length
  let scanSessions = 0
  let plans: WorkflowInputs['plans'] = []
  let validations: WorkflowInputs['validations'] = []
  let certificates: WorkflowInputs['certificates'] = []
  if (client) {
    const [assetHead, sessionHead, planRows, validationRows, certRows] = await Promise.all([
      client.from('assets').select('id', { count: 'exact', head: true }).eq('user_id', userId),
      client.from('pqc_scan_sessions').select('id', { count: 'exact', head: true }).eq('user_id', userId),
      safeRows(client, 'migration_plans', (q) => q.select('id, status').eq('user_id', userId).order('updated_at', { ascending: false }).limit(100)),
      safeRows(client, 'migration_validation_logs', (q) => q.select('status').eq('user_id', userId).order('created_at', { ascending: false }).limit(200)),
      safeRows(client, 'quantum_trust_certificates', (q) => q.select('status, level, expires_at').eq('user_id', userId).order('issued_at', { ascending: false }).limit(10)),
    ])
    if (typeof assetHead.count === 'number') assetCount = Math.max(assetCount, assetHead.count)
    if (typeof sessionHead.count === 'number') scanSessions = sessionHead.count
    // 'migration_queue' rows hold the Migration Planner's asset queue (a working
    // set, not a submitted plan) — they must never advance the Plan/Approve stages.
    plans = planRows.map((p) => ({ id: str(p.id), status: str(p.status) })).filter((p) => p.status !== 'migration_queue')
    validations = validationRows.map((v) => ({ status: str(v.status) }))
    certificates = certRows.map((c) => ({ status: str(c.status), level: str(c.level), expiresAt: str(c.expires_at) }))
  }

  const state = deriveWorkflowState({ evidence, plan, assetCount, scanSessions, plans, validations, certificates })
  stateCache.set(userId, { at: Date.now(), state })
  if (stateCache.size > 500) {
    for (const [key, value] of stateCache) if (Date.now() - value.at > CACHE_TTL_MS) stateCache.delete(key)
  }
  return state
}

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    res.json({ data: await buildWorkflowState(token!, user!.id) })
  } catch (error) {
    console.error('migration-workflow failed:', error)
    res.status(500).json({ error: { code: 'WORKFLOW_ERROR', message: 'Unable to compute workflow state' } })
  }
})

export default router
