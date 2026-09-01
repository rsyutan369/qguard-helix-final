/**
 * Executive Command Center snapshot.
 *
 * Powers the redesigned /dashboard (Enterprise Quantum Security Command Center).
 * Built ON TOP of the canonical, 15s single-flight cached Quantum Readiness
 * snapshot (buildSnapshot) so every headline number — risk score, readiness,
 * inventory, exposure graph, risk trend — matches the rest of the platform
 * (QR pages, reports, exposure graph). Only the guideline-specific aggregations
 * that the canonical snapshot does not expose (asset-type inventory, migration
 * pipeline stages, compliance framework rollup, modelled business impact,
 * threat-intel rollups, live platform runtime telemetry) are computed here —
 * all from the same real, tenant-scoped tables the existing builders query.
 *
 * No fabricated telemetry. Where a signal has no source, counts read 0 and the
 * UI shows honest empty / setup states. Business impact is a DISCLOSED model
 * over real asset counts, flagged `modeled: true` with its assumptions attached.
 */
import { createAuthClient } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import {
  DEFAULT_COST_ASSUMPTIONS,
  buildFinancialExposure,
  describeCostAssumptions,
} from '@/lib/migration/cost-model'
import { buildWorkflowState } from './migration-workflow'

type Row = Record<string, any>
type Snapshot = Awaited<ReturnType<typeof buildSnapshot>>

/**
 * Canonical builders the executive snapshot ALIGNS to are injected so this
 * module never imports back into dashboard.ts (no cycle). loadCompliance wraps
 * buildComplianceDashboardSnapshot (which lives in dashboard.ts) so the Compliance
 * Score + frameworks MATCH the Compliance dashboard exactly.
 */
export interface ExecutiveDeps {
  loadCompliance?: () => Promise<any | null>
}

/* ------------------------------------------------------------------ */
/* Small local utilities (self-contained; no cross-module coupling)   */
/* ------------------------------------------------------------------ */

function str(v: unknown): string {
  return typeof v === 'string' ? v : v == null ? '' : String(v)
}
function num(v: unknown): number {
  const n = Number(v)
  return Number.isFinite(n) ? n : 0
}
function dateMs(v: unknown): number {
  const ms = new Date(str(v)).getTime()
  return Number.isFinite(ms) ? ms : 0
}
function clampPct(v: number): number {
  if (!Number.isFinite(v)) return 0
  return Math.max(0, Math.min(100, Math.round(v)))
}
function pct(value: number, total: number): number {
  return total > 0 ? clampPct((value / total) * 100) : 0
}
function severityRank(s: unknown): number {
  const v = str(s).toLowerCase()
  if (v.includes('critical')) return 4
  if (v.includes('high')) return 3
  if (v.includes('medium') || v.includes('moderate') || v.includes('warning')) return 2
  if (v.includes('low')) return 1
  return 0
}
function recordOf(v: unknown): Row {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Row) : {}
}

const STAGE_LABELS: Record<string, string> = {
  discovery: 'Discovery', cbom: 'CBOM', assessment: 'Assessment', risk: 'Risk Analysis',
  remediation: 'Remediation', planning: 'Planning', approval: 'Approval', execution: 'Migration',
  validation: 'Validation', monitoring: 'Monitoring', certification: 'Certification',
}
function titleCaseStage(id: string): string {
  return STAGE_LABELS[id] || id.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

async function safeRows(client: any, table: string, build: (q: any) => any): Promise<Row[]> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) return []
    return data || []
  } catch {
    return []
  }
}
async function exactCount(client: any, table: string, userId: string, build?: (q: any) => any): Promise<number> {
  try {
    let q = client.from(table).select('id', { count: 'exact', head: true }).eq('user_id', userId)
    if (build) q = build(q)
    const { count, error } = await q
    return error ? 0 : num(count)
  } catch {
    return 0
  }
}

/* ------------------------------------------------------------------ */
/* Canonical asset-inventory categories (guideline-defined)           */
/* ------------------------------------------------------------------ */

type CategoryKey =
  | 'servers' | 'applications' | 'containers' | 'certificates' | 'cloud_accounts'
  | 'users' | 'databases' | 'secrets' | 'clusters' | 'kubernetes'
  | 'virtual_machines' | 'iot' | 'identity_providers' | 'network_devices'

const CATEGORY_LABELS: Record<CategoryKey, string> = {
  servers: 'Servers',
  applications: 'Applications',
  containers: 'Containers',
  certificates: 'Certificates',
  cloud_accounts: 'Cloud Accounts',
  users: 'Users',
  databases: 'Databases',
  secrets: 'Secrets',
  clusters: 'Clusters',
  kubernetes: 'Kubernetes',
  virtual_machines: 'Virtual Machines',
  iot: 'IoT',
  identity_providers: 'Identity Providers',
  network_devices: 'Network Devices',
}

/** Map a free-form asset.type string onto a canonical inventory category. */
function categorizeAssetType(type: string): CategoryKey {
  const t = type.toLowerCase()
  if (/kubernetes|k8s/.test(t)) return 'kubernetes'
  if (/cluster/.test(t)) return 'clusters'
  if (/container|docker|pod|image/.test(t)) return 'containers'
  if (/\bvm\b|virtual.?machine|hypervisor|instance/.test(t)) return 'virtual_machines'
  if (/database|db|postgres|mysql|mongo|redis|sql|datastore/.test(t)) return 'databases'
  if (/secret|vault|key.?store|credential/.test(t)) return 'secrets'
  if (/cert/.test(t)) return 'certificates'
  if (/cloud|aws|azure|gcp|account|subscription|tenant/.test(t)) return 'cloud_accounts'
  if (/user|person|human|employee/.test(t)) return 'users'
  if (/idp|identity.?provider|oauth|oidc|saml|okta|entra|directory|ldap/.test(t)) return 'identity_providers'
  if (/iot|device|sensor|embedded|firmware/.test(t)) return 'iot'
  if (/router|switch|firewall|gateway|network|load.?balancer|vpn/.test(t)) return 'network_devices'
  if (/app|service|api|web|site|function|lambda|workload/.test(t)) return 'applications'
  return 'servers'
}

/* ------------------------------------------------------------------ */
/* Compliance frameworks (guideline set) — evidence-driven, else      */
/* readiness-modelled with a clear `modeled` flag.                    */
/* ------------------------------------------------------------------ */

const FRAMEWORKS: Array<{ id: string; name: string; aliases: RegExp; totalControls: number }> = [
  { id: 'nist-pqc', name: 'NIST PQC', aliases: /nist|fips 203|fips 204|fips 205|ml-kem|ml-dsa|slh-dsa|800-208|800-131/i, totalControls: 12 },
  { id: 'fips-140-3', name: 'FIPS 140-3', aliases: /fips.?140/i, totalControls: 11 },
  { id: 'cnsa-2', name: 'CNSA 2.0', aliases: /cnsa/i, totalControls: 8 },
  { id: 'pci-dss', name: 'PCI DSS', aliases: /pci/i, totalControls: 12 },
  { id: 'iso-27001', name: 'ISO 27001', aliases: /iso.?27001|iso\/iec 27001/i, totalControls: 14 },
  { id: 'soc-2', name: 'SOC 2', aliases: /soc.?2/i, totalControls: 5 },
  { id: 'nis2', name: 'NIS2', aliases: /nis.?2/i, totalControls: 10 },
  { id: 'cyber-essentials', name: 'Cyber Essentials', aliases: /cyber.?essentials/i, totalControls: 5 },
]

function complianceStatusScore(status: unknown): number {
  const s = str(status).toLowerCase()
  if (/pass|compliant|met|satisfied|approved|verified/.test(s)) return 100
  if (/partial|in.?progress|review|pending/.test(s)) return 55
  if (/fail|non.?compliant|missing|gap|open/.test(s)) return 10
  return 40
}

/* ------------------------------------------------------------------ */
/* Sparkline helpers — built ONLY from real series                    */
/* ------------------------------------------------------------------ */

/** N-day rolling count buckets from a list of timestamps. */
function dailyBuckets(timestamps: number[], days = 7): number[] {
  const now = new Date()
  now.setHours(0, 0, 0, 0)
  const start = now.getTime() - (days - 1) * 86400000
  const buckets = new Array(days).fill(0)
  for (const ts of timestamps) {
    if (ts < start) continue
    const idx = Math.floor((ts - start) / 86400000)
    if (idx >= 0 && idx < days) buckets[idx] += 1
  }
  return buckets
}

/* ------------------------------------------------------------------ */
/* Builder                                                            */
/* ------------------------------------------------------------------ */

export interface ExecutiveSnapshot {
  generatedAt: string
  hasData: boolean
  lastAssessmentAt: string | null
  narrative: any
  kpis: any[]
  pipeline: any
  compliance: any
  businessImpact: any
  assetInventory: any
  threatIntel: any
  runtime: any
  exposureGraph: Snapshot['exposureGraph']
  riskTrend: Snapshot['riskTrend']
  topRiskAssets: Snapshot['topRiskAssets']
  scores: Snapshot['scores']
  inventory: Snapshot['inventory']
  recommendedActions: Snapshot['recommendedActions']
}

async function computeExecutive(token: string, userId: string, deps: ExecutiveDeps): Promise<ExecutiveSnapshot> {
  const startedAt = process.hrtime.bigint()
  const cpuBefore = process.cpuUsage()

  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  // Canonical models (all cached / reused) + supplementary tenant-scoped queries.
  // workflow → aligns Migration Progress with Migration Planner / WorkflowRail.
  // complianceSnap → aligns Compliance Score + frameworks with the Compliance page.
  // Failures never break the endpoint (fall back to readiness-derived values).
  const [
    snap,
    workflow,
    complianceSnap,
    assets,
    migrationJobs,
    complianceEvidence,
    runtimeEvents,
    vulnerabilities,
    scannerAgents,
    heartbeats,
    inventoryItems,
    certificates,
    connectorAccounts,
    scanResults,
    scanSessions,
    assetsTotal,
  ] = await Promise.all([
    buildSnapshot(token, userId),
    buildWorkflowState(token, userId).catch(() => null),
    (deps.loadCompliance ? deps.loadCompliance().catch(() => null) : Promise.resolve(null)),
    safeRows(client, 'assets', (q) => q.select('id, name, type, criticality, status, metadata, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(5000)),
    safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, name, job_type, status, progress, started_at, completed_at, updated_at, created_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2000)),
    safeRows(client, 'compliance_evidence', (q) => q.select('id, framework, control_id, status, updated_at, created_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2000)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, severity, risk_score, algorithm, asset_name, host, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(4000)),
    safeRows(client, 'vulnerabilities', (q) => q.select('id, title, severity, status, source, metadata, updated_at, created_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(2000)),
    safeRows(client, 'scanner_agents', (q) => q.select('id, status, last_seen_at, revoked_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(500)),
    safeRows(client, 'agent_heartbeats', (q) => q.select('id, status, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(500)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, item_type, is_vulnerable, is_quantum_safe').eq('user_id', userId).limit(4000)),
    safeRows(client, 'certificates', (q) => q.select('id, status, not_after, is_expiring_soon, is_quantum_safe').eq('user_id', userId).limit(2000)),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, status').eq('user_id', userId).limit(400)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, threat_level, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(4000)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, findings_count, total_assets, scanned_assets, completed_at, updated_at, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(200)),
    exactCount(client, 'assets', userId),
  ])

  const now = Date.now()
  const scores = snap.scores
  const inv = snap.inventory
  const hasData = snap.hasData

  /* ---- Asset inventory by canonical category ---------------------- */
  const activeAssets = assets.filter((a) => !['archived', 'deleted', 'retired'].includes(str(a.status).toLowerCase()))
  const totalAssets = Math.max(activeAssets.length, num(assetsTotal), inv.assetsAssessed)
  const categoryCounts = new Map<CategoryKey, { count: number; atRisk: number }>()
  const bumpCat = (key: CategoryKey, atRisk = false) => {
    const cur = categoryCounts.get(key) || { count: 0, atRisk: 0 }
    cur.count += 1
    if (atRisk) cur.atRisk += 1
    categoryCounts.set(key, cur)
  }
  // Approximate per-asset risk from criticality (real per-asset risk lives in the
  // canonical snapshot but is not exposed per id; criticality is a truthful proxy).
  for (const a of activeAssets) {
    const key = categorizeAssetType(str(a.type))
    const crit = str(a.criticality).toLowerCase()
    bumpCat(key, crit === 'critical' || crit === 'high')
  }
  // Certificates & secrets & cloud accounts come from their authoritative tables.
  const certAtRisk = certificates.filter((c) => !c.is_quantum_safe || c.is_expiring_soon).length
  if (certificates.length) categoryCounts.set('certificates', { count: certificates.length, atRisk: certAtRisk })
  const secretItems = inventoryItems.filter((i) => /secret|key|credential/.test(str(i.item_type).toLowerCase()))
  if (secretItems.length) {
    categoryCounts.set('secrets', {
      count: secretItems.length,
      atRisk: secretItems.filter((i) => i.is_vulnerable && !i.is_quantum_safe).length,
    })
  }
  if (connectorAccounts.length) {
    categoryCounts.set('cloud_accounts', {
      count: connectorAccounts.length,
      atRisk: connectorAccounts.filter((c) => !['connected', 'active', 'healthy'].includes(str(c.status).toLowerCase())).length,
    })
  }
  const categories = (Object.keys(CATEGORY_LABELS) as CategoryKey[]).map((key) => {
    const c = categoryCounts.get(key) || { count: 0, atRisk: 0 }
    return { key, label: CATEGORY_LABELS[key], count: c.count, atRisk: c.atRisk }
  })

  /* ---- Migration pipeline — sourced from the canonical migration ---
   * workflow (buildWorkflowState) so Migration Progress MATCHES the Migration
   * Planner, WorkflowRail (10 dashboards) and Live Migration. Its 11-stage
   * lifecycle is grouped into the 6 guideline stages; every % comes from the
   * workflow, never re-derived here. */
  const jobStatus = (j: Row) => str(j.status).toLowerCase().replace(/\s+/g, '_')
  const completedJobs = migrationJobs.filter((j) => /complete|done|success/.test(jobStatus(j)))
  const runningJobs = migrationJobs.filter((j) => /run|progress|migrat|execut/.test(jobStatus(j)))
  const assessedAssets = inv.assetsAssessed
  const migratedAssets = inv.pqcReadyAssets
  const wfStages: Row[] = Array.isArray(workflow?.stages) ? workflow!.stages : []
  const stagePct = (id: string): number => {
    const s = wfStages.find((x) => str(x.id) === id)
    return s ? clampPct(num(s.progressPct)) : 0
  }
  const avgPct = (...ids: string[]) => clampPct(ids.reduce((sum, id) => sum + stagePct(id), 0) / Math.max(1, ids.length))
  const pipelineStages = workflow
    ? [
        { key: 'discovery', label: 'Discovery', completion: stagePct('discovery'), remaining: Math.max(0, totalAssets - assessedAssets) },
        { key: 'assessment', label: 'Assessment', completion: avgPct('cbom', 'assessment', 'risk'), remaining: Math.max(0, totalAssets - assessedAssets) },
        { key: 'planning', label: 'Planning', completion: avgPct('remediation', 'planning', 'approval'), remaining: snap.recommendedActions.length },
        { key: 'migration', label: 'Migration', completion: stagePct('execution'), remaining: runningJobs.length + Math.max(0, inv.quantumVulnerableAssets - migratedAssets) },
        { key: 'validation', label: 'Validation', completion: stagePct('validation'), remaining: stagePct('validation') >= 100 ? 0 : completedJobs.length },
        { key: 'certified', label: 'Certified', completion: clampPct(num(workflow!.certificationReadinessPct ?? stagePct('certification'))), remaining: Math.max(0, inv.quantumVulnerableAssets) },
      ]
    : // Fallback (workflow unavailable): derive from posture so numbers stay sane.
      [
        { key: 'discovery', label: 'Discovery', completion: totalAssets > 0 ? pct(assessedAssets, totalAssets) : hasData ? 100 : 0, remaining: Math.max(0, totalAssets - assessedAssets) },
        { key: 'assessment', label: 'Assessment', completion: hasData ? snap.assessmentProgress : 0, remaining: Math.max(0, totalAssets - assessedAssets) },
        { key: 'planning', label: 'Planning', completion: migrationJobs.length ? clampPct(100 - scores.migrationEffort) : (snap.recommendedActions.length ? 40 : 0), remaining: snap.recommendedActions.length },
        { key: 'migration', label: 'Migration', completion: pct(completedJobs.length, Math.max(1, migrationJobs.length)), remaining: runningJobs.length },
        { key: 'validation', label: 'Validation', completion: pct(completedJobs.length, Math.max(1, migrationJobs.length || 1)), remaining: 0 },
        { key: 'certified', label: 'Certified', completion: pct(migratedAssets, Math.max(1, inv.pqcReadyAssets + inv.hybridAssets + inv.quantumVulnerableAssets)), remaining: Math.max(0, inv.quantumVulnerableAssets) },
      ]
  // Overall progress = the workflow's own canonical figure (matches Migration Planner).
  const overallCompletion = workflow
    ? clampPct(num(workflow.overallProgressPct))
    : clampPct(pipelineStages.reduce((sum, s) => sum + s.completion, 0) / pipelineStages.length)
  const bottleneck = workflow?.currentStageId
    ? titleCaseStage(str(workflow.currentStageId))
    : (pipelineStages.find((s) => s.completion < 60)?.label || (hasData ? 'On track' : 'Awaiting discovery'))
  const certificationReadiness = workflow ? clampPct(num(workflow.certificationReadinessPct)) : 0

  /* ---- Compliance — sourced from the canonical Compliance snapshot -
   * (buildComplianceDashboardSnapshot) so Compliance Score + frameworks MATCH
   * the Compliance dashboard exactly. Falls back to a clearly-flagged
   * readiness model only when that snapshot is unavailable. */
  const evidenceCountByFramework = new Map<string, { count: number; controls: Set<string> }>()
  for (const ev of complianceEvidence) {
    const label = str(ev.framework)
    const fw = FRAMEWORKS.find((f) => f.aliases.test(label))
    const key = fw ? fw.id : label.toLowerCase()
    const cur = evidenceCountByFramework.get(key) || { count: 0, controls: new Set<string>() }
    cur.count += 1
    if (ev.control_id) cur.controls.add(str(ev.control_id))
    evidenceCountByFramework.set(key, cur)
  }
  const cMetrics = complianceSnap?.metrics
  const cAlignment: Row[] = Array.isArray(complianceSnap?.frameworkAlignment) ? complianceSnap!.frameworkAlignment : []
  const readinessBaseline = scores.quantumReadiness
  let complianceOverall: number
  let complianceFrameworks: Array<{ id: string; name: string; progress: number; evidenceCount: number; missingControls: number; modeled: boolean }>
  if (cMetrics && cAlignment.length) {
    complianceOverall = clampPct(num(cMetrics.complianceScore))
    // Distinct aligned frameworks can alias-collapse to the same canonical id
    // (e.g. "NIST SP 800-208" and "NIST PQC / FIPS 203" both match the nist-pqc
    // alias). They are separate rows, so guarantee unique ids — a duplicate id
    // is a React key collision in the compliance strip.
    const usedFrameworkIds = new Set<string>()
    complianceFrameworks = cAlignment.map((fw, i) => {
      const name = str(fw.name)
      const match = FRAMEWORKS.find((f) => f.aliases.test(name))
      const ev = evidenceCountByFramework.get(match ? match.id : name.toLowerCase())
      const progress = clampPct(num(fw.score))
      const total = match?.totalControls || 12
      let id = match?.id || `fw-${i}`
      if (usedFrameworkIds.has(id)) id = `${id}-${i}`
      usedFrameworkIds.add(id)
      return {
        id,
        name,
        progress,
        evidenceCount: ev?.count || 0,
        missingControls: Math.max(0, total - (ev?.controls.size ?? Math.round((progress / 100) * total))),
        modeled: !(ev && ev.count > 0),
      }
    })
  } else {
    // Fallback: readiness-modelled 8-framework view (flagged modeled).
    complianceFrameworks = FRAMEWORKS.map((fw) => {
      const factor = fw.id === 'nist-pqc' || fw.id === 'fips-140-3' || fw.id === 'cnsa-2' ? 1 : 0.82
      const progress = hasData ? clampPct(readinessBaseline * factor) : 0
      const ev = evidenceCountByFramework.get(fw.id)
      return {
        id: fw.id, name: fw.name, progress,
        evidenceCount: ev?.count || 0,
        missingControls: fw.totalControls - Math.round((progress / 100) * fw.totalControls),
        modeled: !(ev && ev.count > 0),
      }
    })
    complianceOverall = clampPct(complianceFrameworks.reduce((s, f) => s + f.progress, 0) / complianceFrameworks.length)
  }

  /* ---- Threat intelligence rollups (real signals + honest empties) */
  const hndl = runtimeEvents.filter((e) => e.hndl_risk === true).length
  const legacyCrypto = runtimeEvents.filter((e) => e.is_legacy === true).length
  const downgrade = runtimeEvents.filter((e) => e.downgrade_detected === true).length
  const shadowCrypto = runtimeEvents.filter((e) => e.shadow_crypto === true).length
  const openVulns = vulnerabilities.filter((v) => !['resolved', 'remediated', 'false_positive', 'accepted', 'closed'].includes(str(v.status).toLowerCase()))
  const kev = openVulns.filter((v) => {
    const meta = recordOf(v.metadata)
    return meta.kev === true || meta.knownExploited === true || /kev|known.?exploited|actively.?exploited/i.test(`${str(v.source)} ${JSON.stringify(meta)}`)
  }).length
  const cves = openVulns.filter((v) => /cve-\d{4}-\d+/i.test(`${str(v.title)} ${str(v.source)} ${JSON.stringify(recordOf(v.metadata))}`)).length
  const epssValues = openVulns
    .map((v) => num(recordOf(v.metadata).epss))
    .filter((n) => n > 0)
  const epssMax = epssValues.length ? Math.round(Math.max(...epssValues) * 100) : 0
  // Quantum threat model: Shor breaks RSA/ECC/DH signatures & KEX; Grover halves
  // symmetric strength. Derived from the canonical vulnerable-component share.
  const shorAtRisk = inv.vulnerableComponents
  const groverWeakened = inventoryItems.filter((i) => /aes-128|3des|sha-1|sha1|md5/i.test(str(i.item_type))).length
  const threatFeeds = openVulns
    .filter((v) => severityRank(v.severity) >= 3)
    .slice(0, 8)
    .map((v) => ({
      id: str(v.id),
      title: str(v.title) || 'Security finding',
      severity: str(v.severity).toLowerCase() || 'high',
      source: str(v.source) || 'telemetry',
      at: str(v.updated_at) || str(v.created_at),
    }))

  /* ---- Live platform runtime telemetry (REAL, process-level) ------ */
  const heartbeatWindow = now - 10 * 60 * 1000
  const onlineAgents = scannerAgents.filter((a) => {
    if (a.revoked_at || str(a.status).toLowerCase() === 'revoked') return false
    return /active|online|healthy|running|connected/.test(str(a.status).toLowerCase()) || dateMs(a.last_seen_at || a.updated_at) >= heartbeatWindow
  }).length
  const freshHeartbeats = heartbeats.filter((h) => dateMs(h.observed_at || h.created_at) >= heartbeatWindow).length
  const events24h = runtimeEvents.filter((e) => dateMs(e.observed_at || e.created_at) >= now - 86400000).length
  const queueDepth = runningJobs.length + migrationJobs.filter((j) => /pending|queued/.test(jobStatus(j))).length
  const activeScanSessions = scanSessions.filter((s) => ['pending', 'queued', 'running', 'analyzing'].includes(str(s.status).toLowerCase())).length
  const mem = process.memoryUsage()
  const cpuAfter = process.cpuUsage(cpuBefore)
  const buildMs = Number(process.hrtime.bigint() - startedAt) / 1e6
  const runtime = {
    events24h,
    totalEvents: runtimeEvents.length,
    queueDepth,
    activeWorkers: onlineAgents,
    totalWorkers: scannerAgents.length,
    freshHeartbeats,
    activeScans: activeScanSessions,
    scanThroughput: scanResults.filter((r) => dateMs(r.created_at) >= now - 3600000).length, // findings/hour
    /*
     * Measured-vs-absent, so the panel can tell "we observed nothing" apart
     * from "nothing is observing". A tenant with no collector saw
     * `0 events · 0 queue · 0/0 workers`, which reads as a healthy quiet
     * system rather than an unmonitored one.
     *
     * `sseHealth: 'operational'` used to sit here as a hardcoded literal — it
     * was never rendered and never reflected the actual stream, so it is gone
     * rather than replaced with a guess. The UI already shows real connection
     * state from the client's own SSE subscription.
     */
    measured: runtimeEvents.length > 0,
    agentsEnrolled: scannerAgents.length > 0,
    // REAL platform-process telemetry (this API server), not fabricated per-host gauges.
    process: {
      cpuMs: Math.round((cpuAfter.user + cpuAfter.system) / 1000),
      heapUsedMb: Math.round((mem.heapUsed / 1048576) * 10) / 10,
      rssMb: Math.round((mem.rss / 1048576) * 10) / 10,
      aggregationLatencyMs: Math.round(buildMs),
    },
  }

  /* ---- Critical / at-risk assets --------------------------------- *
   * "Critical Assets" = quantum-vulnerable assets from the CANONICAL snapshot
   * (matches Quantum Readiness "Quantum-Vulnerable Assets" and the red nodes in
   * the exposure graph). This is what "critical" means for crypto risk — NOT the
   * often-unpopulated `assets.criticality` business tag, which previously made
   * the card read 0 next to 86 high-risk findings. */
  const vulnerableAssets = inv.quantumVulnerableAssets
  const criticalAssets = vulnerableAssets
  // Business-criticality TAG (separate concept: business importance). Used only to
  // weight the financial model; may legitimately be 0 when assets aren't tagged.
  const missionCriticalTagged = activeAssets.filter((a) => ['critical', 'high'].includes(str(a.criticality).toLowerCase())).length

  /* ---- Business impact (DISCLOSED model over real counts) --------- */
  const applications = categoryCounts.get('applications')?.count || 0
  const applicationsAtRisk = categoryCounts.get('applications')?.atRisk || 0
  /* Per-asset value weights come from the tenant's own assumptions and the model
     is shared with the Migration Planner — the two pages used to run separate
     value models and print contradicting figures (exposure $80,000 beside a
     "risk-reduction value" of $352,688). One model, one set of numbers. */
  const costAssumptions = snap.costAssumptions ?? DEFAULT_COST_ASSUMPTIONS
  const VALUE_PER_CRITICAL = costAssumptions.valuePerCriticalAssetUsd
  const VALUE_PER_STANDARD = costAssumptions.valuePerStandardAssetUsd
  const exposure = snap.businessValue ?? buildFinancialExposure(
    { vulnerableAssets, taggedCriticalAssets: missionCriticalTagged, pqcReadyAssets: inv.pqcReadyAssets },
    costAssumptions,
  )
  const criticalVulnerable = exposure.criticalVulnerableAssets
  const standardVulnerable = exposure.standardVulnerableAssets
  const financialExposure = exposure.financialExposureUsd
  const revenueProtected = exposure.revenueProtectedUsd
  const businessImpact = {
    modeled: true,
    financialExposure,
    revenueProtected,
    // Displayed as "Critical Assets at Risk" — the quantum-vulnerable count.
    missionCriticalAssets: criticalAssets,
    taggedCriticalAssets: missionCriticalTagged,
    applicationsAtRisk,
    applications,
    operationalImpact: scores.migrationComplexity, // 0-100 index
    estimatedDowntimeHours: Math.round(vulnerableAssets * 0.25 * 10) / 10, // ~15 min planned cutover/asset
    riskTrendDelta: snap.riskTrend.length >= 2 ? snap.riskTrend[snap.riskTrend.length - 1].risk - snap.riskTrend[snap.riskTrend.length - 2].risk : 0,
    projectedRoiPct: financialExposure > 0 ? clampPct((financialExposure / Math.max(1, snap.estimates.migrationCostUsd || financialExposure)) * 100) : 0,
    migrationCostUsd: snap.estimates.migrationCostUsd,
    assumptions: `${describeCostAssumptions(costAssumptions)} Cutover ~15 min/asset.`,
    // Untagged estates value every asset at the STANDARD rate, which understates
    // exposure — say so rather than letting the figure imply full coverage.
    criticalityTagged: exposure.criticalityTagged,
  }

  /* ---- KPI cards (12) — real values, trends, targets, sparklines -- */
  const runtimeTs = runtimeEvents.map((e) => dateMs(e.observed_at || e.created_at)).filter(Boolean)
  const scanTs = scanResults.map((r) => dateMs(r.created_at)).filter(Boolean)
  const riskSeries = snap.riskTrend.map((t) => t.risk)
  const readinessSeries = snap.riskTrend.map((t) => t.readiness)
  const findingSeries = dailyBuckets(scanTs.length ? scanTs : runtimeTs)
  const eventSeries = dailyBuckets(runtimeTs)
  const trendOf = (series: number[], lowerBetter: boolean) => {
    if (series.length < 2) return { deltaPercent: 0, trend: 'flat' as const }
    const prev = series[series.length - 2]
    const curr = series[series.length - 1]
    if (prev === 0 && curr === 0) return { deltaPercent: 0, trend: 'flat' as const }
    const raw = prev === 0 ? 100 : Math.round(((curr - prev) / Math.abs(prev)) * 100)
    const improving = lowerBetter ? curr < prev : curr > prev
    return { deltaPercent: Math.abs(raw), trend: (curr === prev ? 'flat' : improving ? 'down' : 'up') as 'up' | 'down' | 'flat' }
  }
  const riskTrendInfo = trendOf(riskSeries, true)
  const readinessTrendInfo = trendOf(readinessSeries, false)
  const openFindings = snap.riskDistribution.critical + snap.riskDistribution.high + snap.riskDistribution.medium + snap.riskDistribution.low
  const certCoverage = totalAssets > 0 ? pct(certificates.length, totalAssets) : 0
  // AI confidence = evidence-coverage of the assessment (real signal breadth).
  const aiConfidence = clampPct(snap.assessmentProgress * 0.6 + (inv.cryptoComponents > 0 ? 40 : 0))
  // Runtime health is a MEASURED signal: only meaningful when runtime crypto
  // telemetry exists. With no runtime events we report `unmeasured` (UI shows
  // "no telemetry"), never a misleading 0%.
  const runtimeMeasured = runtimeEvents.length > 0
  const runtimeHealth = runtimeMeasured ? clampPct(100 - pct(legacyCrypto + downgrade + shadowCrypto, runtimeEvents.length)) : 0
  const lastUpdated = snap.lastAssessmentAt || snap.generatedAt

  const kpis = [
    {
      id: 'quantum-risk', label: 'Quantum Risk Score', value: scores.quantumRisk, unit: '/100', format: 'score',
      direction: 'lower-better', target: 20, targetLabel: 'Below 20', ...riskTrendInfo,
      level: scores.quantumRiskLevel, sparkline: riskSeries, lastUpdated, route: '/dashboard/quantum-risk-scoring',
      hint: 'Composite quantum exposure — lower is safer.',
    },
    {
      id: 'critical-assets', label: 'Critical Assets', value: criticalAssets, unit: '', format: 'count',
      direction: 'lower-better', target: 0, targetLabel: 'Zero at risk', deltaPercent: 0, trend: 'flat',
      level: criticalAssets > 0 ? 'high' : 'low',
      sparkline: [], lastUpdated, route: '/dashboard/vulnerabilities', hint: 'Quantum-vulnerable assets (matches Quantum Readiness).',
    },
    {
      id: 'quantum-ready', label: 'Quantum Ready Assets', value: inv.pqcReadyAssets, unit: '', format: 'count',
      direction: 'higher-better', target: totalAssets, targetLabel: `of ${totalAssets}`, ...readinessTrendInfo,
      sparkline: readinessSeries, lastUpdated, route: '/dashboard/quantum-readiness', hint: 'Assets validated PQC-ready.',
    },
    {
      id: 'migration-progress', label: 'Migration Progress', value: overallCompletion, unit: '%', format: 'percent',
      direction: 'higher-better', target: 100, targetLabel: '100%', ...readinessTrendInfo,
      sparkline: readinessSeries, lastUpdated, route: '/dashboard/migration-planner', hint: 'Canonical migration lifecycle — matches Migration Planner.',
    },
    {
      id: 'compliance', label: 'Compliance Score', value: complianceOverall, unit: '%', format: 'percent',
      direction: 'higher-better', target: 100, targetLabel: '100%', deltaPercent: 0, trend: 'flat',
      sparkline: readinessSeries, lastUpdated, route: '/dashboard/compliance', hint: 'Matches the Compliance dashboard.',
    },
    {
      id: 'open-findings', label: 'Open Findings', value: openFindings, unit: '', format: 'count',
      direction: 'lower-better', target: 0, targetLabel: 'Zero open', ...trendOf(findingSeries, true),
      sparkline: findingSeries, lastUpdated, route: '/dashboard/vulnerabilities', hint: 'Unresolved cryptographic findings.',
    },
    {
      id: 'hndl-risk', label: 'Harvest Now Risk', value: scores.hndlRisk, unit: '/100', format: 'score',
      direction: 'lower-better', target: 20, targetLabel: 'Below 20', deltaPercent: 0, trend: 'flat',
      level: scores.hndlRiskLevel, sparkline: eventSeries, lastUpdated, route: '/dashboard/harvest-now',
      hint: 'Harvest-Now-Decrypt-Later exposure.',
    },
    {
      id: 'ai-confidence', label: 'AI Confidence', value: aiConfidence, unit: '%', format: 'percent',
      direction: 'higher-better', target: 90, targetLabel: 'Above 90%', deltaPercent: 0, trend: 'flat',
      sparkline: [], lastUpdated, route: '/dashboard/sophia', hint: 'Evidence breadth behind AI insights.',
    },
    {
      id: 'runtime-health', label: 'Runtime Health', value: runtimeHealth, unit: '%', format: 'percent',
      direction: 'higher-better', target: 100, targetLabel: runtimeMeasured ? '100%' : 'Connect telemetry',
      ...(runtimeMeasured ? trendOf(eventSeries.map((n) => 100 - n), false) : { deltaPercent: 0, trend: 'flat' as const }),
      unmeasured: !runtimeMeasured,
      sparkline: runtimeMeasured ? eventSeries : [], lastUpdated, route: '/dashboard/runtime-telemetry',
      hint: runtimeMeasured ? 'Clean runtime crypto observations.' : 'No runtime telemetry yet — deploy an agent to measure.',
    },
    {
      id: 'cert-coverage', label: 'Certificate Coverage', value: certCoverage, unit: '%', format: 'percent',
      direction: 'higher-better', target: 100, targetLabel: '100%', deltaPercent: 0, trend: 'flat',
      sparkline: [], lastUpdated, route: '/dashboard/certificate-telemetry', hint: 'Assets with certificate visibility.',
    },
    {
      id: 'crypto-inventory', label: 'Cryptographic Inventory', value: inv.cryptoComponents, unit: '', format: 'count',
      direction: 'higher-better', target: 0, targetLabel: 'Full CBOM', deltaPercent: 0, trend: 'flat',
      sparkline: [], lastUpdated, route: '/dashboard/cbom', hint: 'Discovered CBOM components.',
    },
    {
      id: 'business-risk', label: 'Business Risk', value: financialExposure, unit: 'USD', format: 'currency',
      direction: 'lower-better', target: 0, targetLabel: '$0 exposed', deltaPercent: Math.abs(businessImpact.riskTrendDelta),
      trend: businessImpact.riskTrendDelta < 0 ? 'down' : businessImpact.riskTrendDelta > 0 ? 'up' : 'flat',
      sparkline: riskSeries, lastUpdated, route: '/dashboard/revenue-intelligence', hint: 'Modelled financial exposure.', modeled: true,
    },
  ]

  /* ---- Executive AI narrative ------------------------------------ */
  const criticalFindingCount = snap.riskDistribution.critical
  const highFindingCount = snap.riskDistribution.high
  const remediationHours = Math.round(
    (snap.recommendedActions.slice(0, 6).reduce((sum, r) => {
      const sev = str(r.severity).toLowerCase()
      return sum + (sev === 'critical' ? 24 : sev === 'high' ? 12 : 6)
    }, 0)) * 10,
  ) / 10
  const topPriority = snap.recommendedActions[0] || null
  const facts = [
    { id: 'critical-assets', label: 'Critical assets', value: criticalAssets, tone: criticalAssets > 0 ? 'critical' : 'good' },
    { id: 'high-findings', label: 'High-risk findings', value: criticalFindingCount + highFindingCount, tone: (criticalFindingCount + highFindingCount) > 0 ? 'warning' : 'good' },
    { id: 'risk-trend', label: 'Risk trend', value: riskTrendInfo.trend === 'down' ? `improved ${riskTrendInfo.deltaPercent}%` : riskTrendInfo.trend === 'up' ? `up ${riskTrendInfo.deltaPercent}%` : 'stable', tone: riskTrendInfo.trend === 'down' ? 'good' : riskTrendInfo.trend === 'up' ? 'warning' : 'neutral' },
    { id: 'migration', label: 'Migration progress', value: `${overallCompletion}%`, tone: overallCompletion >= 50 ? 'good' : 'neutral' },
    { id: 'remediation', label: 'Est. quick remediation', value: remediationHours > 0 ? `${remediationHours} hrs` : 'None pending', tone: 'neutral' },
    { id: 'timeline', label: 'Migration timeline', value: snap.estimates.migrationTimelineWeeks > 0 ? `${snap.estimates.migrationTimelineWeeks} wks` : 'Complete', tone: 'neutral' },
  ]
  const narrative = {
    posture: scores.quantumReadinessLevel,
    readinessScore: scores.quantumReadiness,
    riskScore: scores.quantumRisk,
    riskLevel: scores.quantumRiskLevel,
    hasData,
    facts,
    priority: topPriority
      ? { title: topPriority.title, detail: topPriority.detail, severity: topPriority.severity, route: topPriority.route }
      : hasData
        ? { title: 'Maintain quantum-safe posture', detail: 'No critical actions pending. Continue monitoring for cryptographic drift.', severity: 'low', route: '/dashboard/drift_detection' }
        : { title: 'Run your first PQC discovery scan', detail: 'Discover cryptographic assets to begin the quantum readiness assessment.', severity: 'medium', route: '/dashboard/scanner' },
    confidence: aiConfidence,
    summary: hasData
      ? `Your environment has ${criticalAssets} quantum-vulnerable asset${criticalAssets === 1 ? '' : 's'} and ${criticalFindingCount + highFindingCount} high-risk cryptographic finding${(criticalFindingCount + highFindingCount) === 1 ? '' : 's'}. Quantum risk is ${scores.quantumRisk}/100 (${scores.quantumRiskLevel}) and migration is ${overallCompletion}% complete.`
      : 'No cryptographic telemetry yet. Run a PQC discovery scan or connect an integration to populate your command center.',
  }

  return {
    generatedAt: new Date().toISOString(),
    hasData,
    lastAssessmentAt: snap.lastAssessmentAt,
    narrative,
    kpis,
    pipeline: { stages: pipelineStages, overallCompletion, remainingAssets: Math.max(0, totalAssets - migratedAssets), estimatedFinishWeeks: snap.estimates.migrationTimelineWeeks, bottleneck, certificationReadiness },
    compliance: { overall: complianceOverall, frameworks: complianceFrameworks },
    businessImpact,
    assetInventory: { total: totalAssets, categories },
    threatIntel: {
      hndl, legacyCrypto, downgrade, shadowCrypto,
      kev, cves, epssMax,
      shorAtRisk, groverWeakened,
      quantumVulnerable: inv.quantumVulnerableAssets,
      feeds: threatFeeds,
      hasThreatFeed: threatFeeds.length > 0,
    },
    runtime,
    exposureGraph: snap.exposureGraph,
    riskTrend: snap.riskTrend,
    topRiskAssets: snap.topRiskAssets,
    scores,
    inventory: inv,
    recommendedActions: snap.recommendedActions,
  }
}

/* ------------------------------------------------------------------ */
/* Per-tenant 15s single-flight cache (same pattern as buildSnapshot) */
/* ------------------------------------------------------------------ */

const EXEC_CACHE_TTL_MS = 15_000
const execCache = new Map<string, { at: number; promise: Promise<ExecutiveSnapshot> }>()

export function buildExecutiveSnapshot(token: string, userId: string, deps: ExecutiveDeps = {}): Promise<ExecutiveSnapshot> {
  const cached = execCache.get(userId)
  if (cached && Date.now() - cached.at < EXEC_CACHE_TTL_MS) return cached.promise
  const promise = computeExecutive(token, userId, deps)
  execCache.set(userId, { at: Date.now(), promise })
  promise.catch(() => execCache.delete(userId))
  if (execCache.size > 500) {
    const now = Date.now()
    for (const [key, value] of execCache) if (now - value.at > EXEC_CACHE_TTL_MS) execCache.delete(key)
  }
  return promise
}
