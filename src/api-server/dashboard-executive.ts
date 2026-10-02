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
import { buildScannerIntelligence } from './scanner'
import { findAlgorithm, parseKeySize } from '@/lib/crypto/knowledge-base/algorithms'
import { quantumVerdict } from '@/lib/crypto/knowledge-base/classify'

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
/* Framework id aliases — used ONLY to give each governance framework a      */
/* stable id. Scores, gaps and coverage come from the governance model.       */
/* ------------------------------------------------------------------ */

const FRAMEWORKS: Array<{ id: string; name: string; aliases: RegExp }> = [
  { id: 'nist-pqc', name: 'NIST PQC', aliases: /nist|fips 203|fips 204|fips 205|ml-kem|ml-dsa|slh-dsa|800-208|800-131/i },
  { id: 'fips-140-3', name: 'FIPS 140-3', aliases: /fips.?140/i },
  { id: 'cnsa-2', name: 'CNSA 2.0', aliases: /cnsa/i },
  { id: 'pci-dss', name: 'PCI DSS', aliases: /pci/i },
  { id: 'iso-27001', name: 'ISO 27001', aliases: /iso.?27001|iso\/iec 27001/i },
  { id: 'soc-2', name: 'SOC 2', aliases: /soc.?2/i },
  { id: 'nis2', name: 'NIS2', aliases: /nis.?2/i },
  { id: 'cyber-essentials', name: 'Cyber Essentials', aliases: /cyber.?essentials/i },
]

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
    intel,
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
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, status, not_after, is_expiring_soon, is_quantum_safe').eq('user_id', userId).limit(2000)),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, status').eq('user_id', userId).limit(400)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, threat_level, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(4000)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, findings_count, total_assets, scanned_assets, completed_at, updated_at, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(200)),
    exactCount(client, 'assets', userId),
    // Canonical CBOM (15s single-flight cache, already warmed by buildSnapshot):
    // the Shor / Grover tiles classify ITS components, not raw inventory rows.
    buildScannerIntelligence(token, userId).catch(() => null),
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
  /* "At risk" is the SHARED posture model's verdict — quantum-vulnerable —
     rolled up by asset type in the canonical snapshot. It used to be the
     business-criticality TAG ("criticality is a truthful proxy"), which is a
     statement about importance, not exposure: an untagged quantum-vulnerable
     web application read "Applications 1 · 0 at risk" directly beside a
     Quantum-Vulnerable Assets KPI of 1. */
  for (const a of activeAssets) bumpCat(categorizeAssetType(str(a.type)))
  for (const entry of snap.assetTypePosture ?? []) {
    const key = categorizeAssetType(str(entry.type))
    const current = categoryCounts.get(key)
    if (!current) continue
    current.atRisk = Math.min(current.count, current.atRisk + num(entry.quantumVulnerable))
  }
  // Certificates & secrets & cloud accounts come from their authoritative tables.
  const certAtRisk = certificates.filter((c) => !c.is_quantum_safe || c.is_expiring_soon).length
  if (certificates.length) categoryCounts.set('certificates', { count: certificates.length, atRisk: certAtRisk })
  /* Matched on the WHOLE item type. A substring test for "key" filed every
     `key-exchange` component (ECDHE, X25519) under Secrets — a tenant holding
     no secrets at all read "Secrets 2 · 2 at risk". */
  const SECRET_ITEM_TYPE = /^(secret|credential|password|token|api[-_ ]?key|private[-_ ]?key|ssh[-_ ]?key|signing[-_ ]?key|key[-_ ]?material)s?$/
  const secretItems = inventoryItems.filter((i) => SECRET_ITEM_TYPE.test(str(i.item_type).trim().toLowerCase()))
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
        /* Certification READINESS, not certification: 62% here means the
           evidence is 62% of the way to a certifiable state, while nothing has
           been certified. Labelled "Certified" it read as 62% done. */
        { key: 'certified', label: 'Cert. Readiness', completion: clampPct(num(workflow!.certificationReadinessPct ?? stagePct('certification'))), remaining: Math.max(0, inv.quantumVulnerableAssets) },
      ]
    : // Fallback (workflow unavailable): derive from posture so numbers stay sane.
      [
        { key: 'discovery', label: 'Discovery', completion: totalAssets > 0 ? pct(assessedAssets, totalAssets) : hasData ? 100 : 0, remaining: Math.max(0, totalAssets - assessedAssets) },
        { key: 'assessment', label: 'Assessment', completion: hasData ? snap.assessmentProgress : 0, remaining: Math.max(0, totalAssets - assessedAssets) },
        { key: 'planning', label: 'Planning', completion: migrationJobs.length ? clampPct(100 - scores.migrationEffort) : (snap.recommendedActions.length ? 40 : 0), remaining: snap.recommendedActions.length },
        { key: 'migration', label: 'Migration', completion: pct(completedJobs.length, Math.max(1, migrationJobs.length)), remaining: runningJobs.length },
        { key: 'validation', label: 'Validation', completion: pct(completedJobs.length, Math.max(1, migrationJobs.length || 1)), remaining: 0 },
        { key: 'certified', label: 'Cert. Readiness', completion: pct(migratedAssets, Math.max(1, inv.pqcReadyAssets + inv.hybridAssets + inv.quantumVulnerableAssets)), remaining: Math.max(0, inv.quantumVulnerableAssets) },
      ]
  // Overall progress = the workflow's own canonical figure (matches Migration Planner).
  const overallCompletion = workflow
    ? clampPct(num(workflow.overallProgressPct))
    : clampPct(pipelineStages.reduce((sum, s) => sum + s.completion, 0) / pipelineStages.length)
  const bottleneck = workflow?.currentStageId
    ? titleCaseStage(str(workflow.currentStageId))
    : (pipelineStages.find((s) => s.completion < 60)?.label || (hasData ? 'On track' : 'Awaiting discovery'))
  const certificationReadiness = workflow ? clampPct(num(workflow.certificationReadinessPct)) : 0

  /* ---- Compliance — the canonical governance model, or nothing ----
   * Score and frameworks come from the governance control engine (the
   * Compliance dashboard's own model), so the two pages cannot disagree.
   *
   * Each framework now carries its MEASURED requirement counts: gaps are the
   * failing + partially-met requirements, coverage is measured / total. This
   * used to divide the score into an invented per-framework control total
   * ("12 controls" for any NIST framework) and label every framework
   * "modelled" whenever no manual attestation row existed.
   *
   * When the governance model is unavailable there is NO fallback: the old
   * path fabricated eight frameworks as readiness × 0.82 — the exact
   * fabrication the governance projection exists to prevent. The strip says
   * the model is unavailable instead. */
  const cMetrics = complianceSnap?.metrics
  const cAlignment: Row[] = Array.isArray(complianceSnap?.frameworkAlignment) ? complianceSnap!.frameworkAlignment : []
  const complianceMeasured = Boolean(cMetrics) && cMetrics!.complianceMeasured !== false && cAlignment.length > 0
  const complianceOverall = complianceMeasured ? clampPct(num(cMetrics!.complianceScore)) : 0
  const attestedByFramework = new Map<string, number>()
  for (const ev of complianceEvidence) {
    const label = str(ev.framework).toLowerCase()
    if (label) attestedByFramework.set(label, (attestedByFramework.get(label) || 0) + 1)
  }
  const usedFrameworkIds = new Set<string>()
  const complianceFrameworks = (complianceMeasured ? cAlignment : []).map((fw, i) => {
    const name = str(fw.name)
    const match = FRAMEWORKS.find((f) => f.aliases.test(name))
    // Distinct frameworks can alias-collapse to one canonical id (every NIST
    // publication matches the nist alias) — ids stay unique for React keys.
    let id = match?.id || `fw-${i}`
    if (usedFrameworkIds.has(id)) id = `${id}-${i}`
    usedFrameworkIds.add(id)
    const requirementsTotal = num(fw.requirementsTotal)
    const requirementsMeasured = num(fw.requirementsMeasured)
    return {
      id,
      name,
      progress: clampPct(num(fw.score)),
      evidenceCount: num(fw.evidenceCount),
      attestedEvidenceCount: num(fw.attestedEvidenceCount) || attestedByFramework.get(name.toLowerCase()) || 0,
      gaps: num(fw.requirementsFailing) + num(fw.requirementsPartial),
      requirementsTotal,
      requirementsMeasured,
      coverage: requirementsTotal > 0 ? clampPct((requirementsMeasured / requirementsTotal) * 100) : 0,
      modeled: false,
    }
  })

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
  /* Quantum threat model over the CANONICAL CBOM, classified by the Crypto
     Knowledge Base.
     • Shor-at-Risk: vulnerable components whose primitive Shor's algorithm
       breaks outright (RSA, ECC, DH). This used to be ALL vulnerable
       components, so a TLS protocol version and an AES-256-GCM suite were
       counted as Shor targets.
     • Grover-Weakened: symmetric/hash primitives left below the 128-bit
       post-quantum margin (AES-128, SHA-1…). This used to regex the
       `item_type` column — "algorithm", "protocol" — so it could never match
       and always read 0 whatever the estate held. */
  const cbomEntries: Row[] = Array.isArray(intel?.cbom?.entries) ? intel.cbom.entries : []
  let shorAtRisk = 0
  let groverWeakened = 0
  for (const entry of cbomEntries) {
    const algorithmLabel = str(entry.algorithm)
    const definition = findAlgorithm(algorithmLabel)
    if (!definition) continue
    if (definition.shorBroken) {
      if (entry.isVulnerable && !entry.isQuantumSafe) shorAtRisk += 1
      continue
    }
    if (definition.groverAffected) {
      const verdict = quantumVerdict({ algorithm: definition, role: 'unknown', keySize: parseKeySize(algorithmLabel, definition) })
      if (verdict.effectiveStrength !== null && verdict.effectiveStrength < 128) groverWeakened += 1
    }
  }
  /* The feed is the canonical critical/high findings (the set Quantum
     Readiness → Risk Analysis lists, where the feed links) — not the derived
     `vulnerabilities` bucket rows, whose titles are the bucket they were filed
     under ("Rule (App Crypto)", "Runtime Crypto Exposure" on a tenant with no
     runtime telemetry at all). */
  const threatFeeds = (snap.criticalFindings || [])
    .slice()
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || dateMs(b.detectedAt) - dateMs(a.detectedAt))
    .map((finding) => ({
      id: str(finding.id),
      title: str(finding.title).replace(/\s+detected$/i, '') || 'Security finding',
      severity: str(finding.severity).toLowerCase() || 'high',
      source: str(finding.asset) || 'scanner',
      at: str(finding.detectedAt),
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

  /* ---- UNIT-AWARE HEADLINE ---------------------------------------- *
   * An asset count and a component count are different measurements, and a
   * tenant can hold one without the other: an edge scan produces real
   * cryptography with no asset inventory behind it.
   *
   * The snapshot used to paper over that by copying the component counts into
   * the asset fields, so a tenant with ZERO assets published "28 critical
   * assets". That substitution is gone (see quantum-readiness.ts), which leaves
   * the honest question: what should this card show when there is cryptography
   * but no inventory?
   *
   * Not a fabricated asset count, and not a bare 0 that hides real exposure —
   * the same measurement under its OWN label. The card switches unit, states
   * which unit it is reporting, and routes to the page that owns it.
   */
  const hasAssetInventory = totalAssets > 0
  /* Labelled as what it counts. "Critical Assets" read as a SEVERITY claim —
     "1 critical asset" beside a finding set holding zero critical findings —
     when the number is the posture verdict: assets the shared model rates
     quantum-vulnerable. */
  const criticalHeadline = hasAssetInventory
    ? {
        label: 'Quantum-Vulnerable Assets',
        value: vulnerableAssets,
        unitLabel: 'assets',
        hint: 'Assets the shared posture model rates quantum-vulnerable (matches Quantum Readiness).',
        route: '/dashboard/quantum-readiness/risk-analysis',
      }
    : {
        label: 'Quantum-Vulnerable Components',
        value: inv.vulnerableComponents,
        unitLabel: 'components',
        hint: 'No asset inventory yet — reporting the unit that was actually measured: vulnerable CBOM components.',
        route: '/dashboard/cbom',
      }
  const readyHeadline = hasAssetInventory
    ? {
        label: 'Quantum Ready Assets',
        value: inv.pqcReadyAssets,
        target: totalAssets,
        targetLabel: `of ${totalAssets}`,
        hint: 'Assets validated PQC-ready.',
        route: '/dashboard/quantum-readiness',
      }
    : {
        label: 'PQC-Ready Components',
        value: inv.pqcReadyComponents ?? 0,
        target: inv.cryptoComponents,
        targetLabel: `of ${inv.cryptoComponents}`,
        hint: 'No asset inventory yet — reporting PQC-ready CBOM components, the unit that was measured.',
        route: '/dashboard/cbom',
      }

  /* ---- Business impact (DISCLOSED model over real counts) --------- */
  const applications = categoryCounts.get('applications')?.count || 0
  const applicationsAtRisk = categoryCounts.get('applications')?.atRisk || 0
  /* Per-asset value weights come from the tenant's own assumptions and the model
     is shared with the Migration Planner — the two pages used to run separate
     value models and print contradicting figures (exposure $80,000 beside a
     "risk-reduction value" of $352,688). One model, one set of numbers. */
  const costAssumptions = snap.costAssumptions ?? DEFAULT_COST_ASSUMPTIONS
  const exposure = snap.businessValue ?? buildFinancialExposure(
    { vulnerableAssets, taggedCriticalAssets: missionCriticalTagged, pqcReadyAssets: inv.pqcReadyAssets },
    costAssumptions,
  )
  const financialExposure = exposure.financialExposureUsd
  const revenueProtected = exposure.revenueProtectedUsd
  const migrationCostUsd = num(snap.estimates.migrationCostUsd)
  /* ROI = (loss avoided − cost) / cost, where the loss avoided is at most the
     modelled exposure — so this is an UPPER BOUND, and it can be negative. It
     used to be exposure ÷ cost clamped to 100%, which is neither a return nor
     bounded honestly: $40,000 of exposure against a $31,350 programme printed
     "Projected ROI 100%" (the true ceiling is 28%). `null` when either side is
     unmodelled, rendered "Not modelled" — never a 0% that reads as "no return". */
  const projectedRoiPct = financialExposure > 0 && migrationCostUsd > 0
    ? Math.round(((financialExposure - migrationCostUsd) / migrationCostUsd) * 100)
    : null
  const businessImpact = {
    modeled: true,
    financialExposure,
    revenueProtected,
    // Displayed as "Quantum-Vulnerable Assets" — the shared posture verdict.
    missionCriticalAssets: criticalAssets,
    taggedCriticalAssets: missionCriticalTagged,
    applicationsAtRisk,
    applications,
    operationalImpact: scores.migrationComplexity, // 0-100 index
    estimatedDowntimeHours: Math.round(vulnerableAssets * 0.25 * 10) / 10, // ~15 min planned cutover/asset
    /* No stored history of the modelled exposure exists, so there is no trend
       to report. This used to difference the per-session "findings per asset"
       series — a different metric — and publish it as the exposure trend. */
    riskTrendDelta: null as number | null,
    projectedRoiPct,
    migrationCostUsd,
    assumptions: `${describeCostAssumptions(costAssumptions)} Cutover ~15 min/asset. ROI is an upper bound: loss avoided cannot exceed the modelled exposure.`,
    // Untagged estates value every asset at the STANDARD rate, which understates
    // exposure — say so rather than letting the figure imply full coverage.
    criticalityTagged: exposure.criticalityTagged,
  }

  /* ---- KPI cards (12) ----------------------------------------------
   * TRENDS AND SPARKLINES ARE ONLY EVER THE METRIC'S OWN HISTORY.
   *
   * The platform stores no history of these scores. The cards used to borrow
   * a series anyway: Quantum Risk, Quantum Ready, Migration Progress,
   * Compliance and Business Risk all drew `riskTrend` — a per-session
   * "findings per asset" ratio, a DIFFERENT metric (it read risk 100 beside a
   * Quantum Risk Score of 57) — and derived their "improved/worse %" from it;
   * Harvest Now drew the runtime-event count; Open Findings drew raw scan rows
   * per day. Each card now carries `trendBasis: 'none'` and, where it helps, a
   * `breakdown` of the value it shows — real composition, not a borrowed line.
   */
  const openFindings = snap.riskDistribution.critical + snap.riskDistribution.high + snap.riskDistribution.medium + snap.riskDistribution.low
  /* Coverage is ASSETS WITH a certificate over assets — not certificate rows
     over assets, which reads 100% for one asset holding two certificates and
     none on the other. */
  const estateAssetIds = new Set(activeAssets.map((a) => str(a.id)))
  const assetsWithCertificates = new Set(certificates.map((c) => str(c.asset_id)).filter((id) => estateAssetIds.has(id))).size
  const certCoverage = totalAssets > 0 ? pct(assetsWithCertificates, totalAssets) : 0
  /* Evidence coverage — which of the seven evidence sources the assessment
     actually holds. This used to be "AI Confidence" = coverage × 0.6 + a flat
     40 points for having any CBOM, a constant presented as a measurement. */
  const evidenceSources: Array<{ id: string; label: string; present: boolean }> = Array.isArray(snap.evidenceSources) ? snap.evidenceSources : []
  const presentSources = evidenceSources.filter((source) => source.present)
  const missingSources = evidenceSources.filter((source) => !source.present)
  const evidenceCoverage = snap.assessmentProgress
  // Runtime health is a MEASURED signal: only meaningful when runtime crypto
  // telemetry exists. With no runtime events we report `unmeasured` (UI shows
  // "no telemetry"), never a misleading 0%.
  const runtimeMeasured = runtimeEvents.length > 0
  const runtimeHealth = runtimeMeasured ? clampPct(100 - pct(legacyCrypto + downgrade + shadowCrypto, runtimeEvents.length)) : 0
  const lastUpdated = snap.lastAssessmentAt || snap.generatedAt
  const noHistory = { deltaPercent: 0, trend: 'flat' as const, trendBasis: 'none' as const, sparkline: [] as number[] }
  const otherAssets = Math.max(0, totalAssets - inv.quantumVulnerableAssets - inv.pqcReadyAssets)
  const assetPostureBreakdown = [
    { label: 'Quantum-vulnerable', value: inv.quantumVulnerableAssets, tone: 'critical' },
    { label: 'PQC-ready', value: inv.pqcReadyAssets, tone: 'good' },
    { label: 'Other / unassessed', value: otherAssets, tone: 'neutral' },
  ]
  const executionStarted = stagePct('execution') > 0 || completedJobs.length > 0 || runningJobs.length > 0

  const kpis = [
    {
      id: 'quantum-risk', label: 'Quantum Risk Score', value: scores.quantumRisk, unit: '/100', format: 'score',
      direction: 'lower-better', target: 20, targetLabel: 'Below 20', ...noHistory,
      level: scores.quantumRiskLevel, lastUpdated, route: '/dashboard/quantum-risk-scoring',
      hint: 'Composite quantum exposure (severity pressure, vulnerable-component share, internet exposure) — lower is safer.',
    },
    {
      id: 'critical-assets', label: criticalHeadline.label, value: criticalHeadline.value, unit: '', format: 'count',
      direction: 'lower-better', target: 0, targetLabel: `Zero ${criticalHeadline.unitLabel} at risk`, ...noHistory,
      level: criticalHeadline.value > 0 ? 'high' : 'low',
      breakdown: hasAssetInventory ? assetPostureBreakdown : undefined,
      lastUpdated, route: criticalHeadline.route, hint: criticalHeadline.hint,
    },
    {
      id: 'quantum-ready', label: readyHeadline.label, value: readyHeadline.value, unit: '', format: 'count',
      direction: 'higher-better', target: readyHeadline.target, targetLabel: readyHeadline.targetLabel, ...noHistory,
      breakdown: hasAssetInventory ? assetPostureBreakdown : undefined,
      lastUpdated, route: readyHeadline.route, hint: readyHeadline.hint,
    },
    {
      id: 'migration-progress', label: 'Migration Lifecycle', value: overallCompletion, unit: '%', format: 'percent',
      direction: 'higher-better', target: 100, targetLabel: '100%', ...noHistory,
      breakdown: wfStages.length
        ? [
            { label: 'Complete', value: wfStages.filter((s) => str(s.status) === 'complete').length, tone: 'good' },
            { label: 'Active', value: wfStages.filter((s) => str(s.status) === 'active').length, tone: 'info' },
            { label: 'Pending', value: wfStages.filter((s) => !['complete', 'active'].includes(str(s.status))).length, tone: 'neutral' },
          ]
        : undefined,
      lastUpdated, route: '/dashboard/migration-planner',
      hint: `Progress through the 11-stage migration lifecycle (matches Migration Planner)${workflow?.currentStageId ? ` — current stage: ${titleCaseStage(str(workflow.currentStageId))}` : ''}.${executionStarted ? '' : ' Migration execution has not started.'}`,
    },
    {
      id: 'compliance', label: 'Compliance Score', value: complianceOverall, unit: '%', format: 'percent',
      direction: 'higher-better', target: 100, targetLabel: complianceMeasured ? '100%' : 'Model unavailable', ...noHistory,
      unmeasured: !complianceMeasured,
      lastUpdated, route: '/dashboard/compliance',
      hint: complianceMeasured
        ? `Matches the Compliance dashboard — scored over measured controls across ${complianceFrameworks.length} framework${complianceFrameworks.length === 1 ? '' : 's'}.`
        : 'The governance control model returned no measured framework, so no compliance score is published.',
    },
    {
      id: 'open-findings', label: 'Open Findings', value: openFindings, unit: '', format: 'count',
      direction: 'lower-better', target: 0, targetLabel: 'Zero open', ...noHistory,
      breakdown: [
        { label: 'Critical', value: snap.riskDistribution.critical, tone: 'critical' },
        { label: 'High', value: snap.riskDistribution.high, tone: 'warning' },
        { label: 'Medium', value: snap.riskDistribution.medium, tone: 'info' },
        { label: 'Low', value: snap.riskDistribution.low, tone: 'neutral' },
      ],
      lastUpdated, route: '/dashboard/quantum-readiness/risk-analysis', hint: 'Unresolved cryptographic findings, merged across storage copies (matches Risk Analysis).',
    },
    {
      id: 'hndl-risk', label: 'Harvest Now Risk', value: scores.hndlRisk, unit: '/100', format: 'score',
      direction: 'lower-better', target: 20, targetLabel: 'Below 20', ...noHistory,
      level: scores.hndlRiskLevel, lastUpdated, route: '/dashboard/harvest-now',
      hint: runtimeMeasured
        ? 'Harvest-Now-Decrypt-Later exposure from vulnerable key exchange, runtime HNDL signals and internet exposure.'
        : 'Harvest-Now-Decrypt-Later exposure from vulnerable key exchange and internet exposure. Runtime HNDL signals are not measured — no collector enrolled.',
    },
    {
      id: 'evidence-coverage', label: 'Evidence Coverage', value: evidenceCoverage, unit: '%', format: 'percent',
      direction: 'higher-better', target: 100, targetLabel: `${presentSources.length} of ${evidenceSources.length} sources`, ...noHistory,
      breakdown: evidenceSources.length
        ? [
            { label: 'Present', value: presentSources.length, tone: 'good' },
            { label: 'Missing', value: missingSources.length, tone: 'neutral' },
          ]
        : undefined,
      lastUpdated, route: '/dashboard/quantum-readiness',
      hint: missingSources.length
        ? `Evidence behind every score on this page. Missing: ${missingSources.map((source) => source.label).join(', ')}.`
        : 'Every evidence source is present.',
    },
    {
      id: 'runtime-health', label: 'Runtime Health', value: runtimeHealth, unit: '%', format: 'percent',
      direction: 'higher-better', target: 100, targetLabel: runtimeMeasured ? '100%' : 'Connect telemetry', ...noHistory,
      unmeasured: !runtimeMeasured,
      lastUpdated, route: '/dashboard/runtime-telemetry',
      hint: runtimeMeasured ? 'Share of runtime crypto observations with no legacy, downgrade or shadow-crypto signal.' : 'No runtime telemetry yet — deploy an agent to measure.',
    },
    {
      id: 'cert-coverage', label: 'Certificate Coverage', value: certCoverage, unit: '%', format: 'percent',
      direction: 'higher-better', target: 100, targetLabel: '100%', ...noHistory,
      breakdown: totalAssets > 0
        ? [
            { label: 'With certificate', value: assetsWithCertificates, tone: 'good' },
            { label: 'Without', value: Math.max(0, totalAssets - assetsWithCertificates), tone: 'neutral' },
          ]
        : undefined,
      lastUpdated, route: '/dashboard/certificate-telemetry', hint: `Assets presenting at least one inventoried certificate (${assetsWithCertificates} of ${totalAssets}).`,
    },
    {
      id: 'crypto-inventory', label: 'Cryptographic Inventory', value: inv.cryptoComponents, unit: '', format: 'count',
      direction: 'higher-better', target: 0, targetLabel: 'Full CBOM', ...noHistory,
      breakdown: [
        { label: 'Quantum-vulnerable', value: inv.vulnerableComponents, tone: 'critical' },
        { label: 'PQC-ready', value: num(inv.pqcReadyComponents), tone: 'good' },
        { label: 'Unclassified', value: Math.max(0, inv.cryptoComponents - inv.vulnerableComponents - num(inv.pqcReadyComponents)), tone: 'neutral' },
      ],
      lastUpdated, route: '/dashboard/cbom', hint: 'Canonical CBOM components (matches the CBOM page) — instances of one component are counted once.',
    },
    {
      id: 'business-risk', label: 'Business Risk', value: financialExposure, unit: 'USD', format: 'currency',
      direction: 'lower-better', target: 0, targetLabel: '$0 exposed', ...noHistory,
      lastUpdated, route: '/dashboard/revenue-intelligence', hint: 'Modelled financial exposure over quantum-vulnerable assets — planning assumptions, not measured loss.', modeled: true,
    },
  ]

  /* ---- Executive AI narrative ------------------------------------ */
  const criticalFindingCount = snap.riskDistribution.critical
  const highFindingCount = snap.riskDistribution.high
  const topPriority = snap.recommendedActions[0] || null
  const currentStage = workflow?.currentStageId ? titleCaseStage(str(workflow.currentStageId)) : null
  const facts = [
    /* Same unit-awareness as the KPI card: the executive facts row must not
       label a component count as an asset count either. */
    { id: 'critical-assets', label: criticalHeadline.label, value: criticalHeadline.value, tone: criticalHeadline.value > 0 ? 'critical' : 'good' },
    { id: 'high-findings', label: 'Critical + high findings', value: criticalFindingCount + highFindingCount, tone: (criticalFindingCount + highFindingCount) > 0 ? 'warning' : 'good' },
    /* Freshness, not a trend: with no stored score history "Risk trend: stable"
       asserted a comparison that was never made. How old the evidence is IS
       measured, and it is what an executive needs before trusting the rest. */
    { id: 'last-assessment', label: 'Last assessment', value: snap.lastAssessmentAt ? snap.lastAssessmentAt : 'Never', tone: 'neutral', format: 'relative-time' },
    { id: 'migration', label: 'Migration lifecycle', value: `${overallCompletion}%`, tone: overallCompletion >= 50 ? 'good' : 'neutral', hint: currentStage ? `Current stage: ${currentStage}` : undefined },
    { id: 'evidence', label: 'Evidence coverage', value: `${presentSources.length} of ${evidenceSources.length} sources`, tone: missingSources.length === 0 ? 'good' : 'neutral' },
    { id: 'timeline', label: 'Est. migration timeline', value: snap.estimates.migrationTimelineWeeks > 0 ? `${snap.estimates.migrationTimelineWeeks} wks` : hasData ? 'No remaining scope' : '—', tone: 'neutral', modeled: true, hint: 'Planning estimate from remaining vulnerable components and migration complexity.' },
  ]
  const migrationSentence = executionStarted
    ? `the migration lifecycle is ${overallCompletion}% complete${currentStage ? ` (current stage: ${currentStage})` : ''}`
    : `the migration lifecycle is ${overallCompletion}% through its stages${currentStage ? ` (current stage: ${currentStage})` : ''} — no cryptography has been migrated yet`
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
    evidenceCoverage: {
      pct: evidenceCoverage,
      present: presentSources.length,
      total: evidenceSources.length,
      missing: missingSources.map((source) => source.label),
    },
    summary: hasData
      ? `Your environment has ${criticalAssets} quantum-vulnerable asset${criticalAssets === 1 ? '' : 's'} and ${criticalFindingCount + highFindingCount} critical or high cryptographic finding${(criticalFindingCount + highFindingCount) === 1 ? '' : 's'}. Quantum risk is ${scores.quantumRisk}/100 (${scores.quantumRiskLevel}), and ${migrationSentence}.`
      : 'No cryptographic telemetry yet. Run a PQC discovery scan or connect an integration to populate your command center.',
  }

  return {
    generatedAt: new Date().toISOString(),
    hasData,
    lastAssessmentAt: snap.lastAssessmentAt,
    narrative,
    kpis,
    pipeline: { stages: pipelineStages, overallCompletion, remainingAssets: Math.max(0, totalAssets - migratedAssets), estimatedFinishWeeks: snap.estimates.migrationTimelineWeeks, bottleneck, certificationReadiness },
    compliance: { overall: complianceOverall, measured: complianceMeasured, frameworks: complianceFrameworks },
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
