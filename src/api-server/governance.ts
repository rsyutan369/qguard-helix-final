/**
 * Enterprise Governance Command Layer — the one backend behind four pages.
 *
 *   /api/v1/dashboard/compliance          Compliance Command Center
 *   /api/v1/dashboard/quantum-governance  Quantum & Crypto Governance
 *   /api/v1/dashboard/audit-vault         Audit & Evidence Vault
 *   /api/v1/dashboard/regulatory-mapping  Regulatory Mapping
 *
 * Before this module the four ran on two unrelated builders: three of them
 * shared `governance-dashboard.ts`, which ignored its own `kind` parameter and
 * returned the SAME payload for all three, and Compliance ran a separate
 * builder in `dashboard.ts` whose framework scores fell back to the overall
 * compliance score whenever a framework had no evidence — inventing a number
 * per framework. Both are replaced here by one evaluated control model.
 *
 * CACHING CONTRACT (matches buildSnapshot / buildPortfolio / buildTrustFabricModel)
 * -------------------------------------------------------------------------------
 * Only the fetch + derivation is cached, per tenant, for 15 seconds. Every open
 * dashboard and every SSE push of a tenant collapses onto that one computation,
 * so N pages cost the same as one AND cannot disagree within the window.
 * Failures are never cached.
 *
 * TENANT ISOLATION
 * ----------------
 * Every query runs through the caller's own RLS-scoped client and is filtered on
 * `user_id` from the VERIFIED token — never from a client-supplied parameter.
 */

import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { createSingleFlightCache } from '@/lib/single-flight-cache'
import { buildSnapshot } from './quantum-readiness'
import { buildPortfolio } from './migration-planner'
import {
  buildGovernanceIntelligence,
  contentDigest,
  failingSubjectsFor,
  allViolationsFor,
  buildSubjects,
  severityOrder,
  CONTROL_BY_ID,
  FRAMEWORK_BY_ID,
  REQUIREMENT_BY_ID,
  type CanonicalSnapshot,
  type ControlEvaluationInputs,
  type ControlRecord,
  type EvidenceRecord,
  type GovernanceIntelligence,
  type GovernanceInputs,
  type PolicyEvaluationContext,
  type PortfolioAsset,
} from '@/lib/governance'

type Row = Record<string, unknown>

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

export type GovernanceView = 'compliance' | 'quantum' | 'audit' | 'regulatory'

const VIEW_LABEL: Record<GovernanceView, string> = {
  compliance: 'Compliance Command Center',
  quantum: 'Quantum Governance',
  audit: 'Audit Vault',
  regulatory: 'Regulatory Mapping',
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : value === null || value === undefined ? '' : String(value).trim()
}

function num(value: unknown, fallback = 0): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

interface FetchOutcome {
  rows: Row[]
  /** True when the query hit its cap — the caller must not treat length as a total. */
  capped: boolean
  /** True when the table answered at all (a missing table returns false). */
  available: boolean
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function fetchRows(client: any, table: string, limit: number, build: (query: any) => any): Promise<FetchOutcome> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      // A missing table (42P01) or unknown column (42703) must degrade to "not
      // available" rather than to an empty array that reads as "measured zero".
      console.warn(`[governance] ${table} query skipped:`, error.message || error)
      return { rows: [], capped: false, available: false }
    }
    const rows = (data as Row[]) || []
    return { rows, capped: rows.length >= limit, available: true }
  } catch (error) {
    console.warn(`[governance] ${table} query failed:`, (error as Error)?.message || error)
    return { rows: [], capped: false, available: false }
  }
}

/* ------------------------------------------------------------------ */
/* Auth                                                                */
/* ------------------------------------------------------------------ */

/**
 * The hooks stream over fetch + ReadableStream with an Authorization header, so
 * the bearer token never enters a URL. The `?token=` fallback exists only so an
 * already-open legacy tab does not hard-fail across a deploy.
 */
function tokenFromRequest(req: Request): string | null {
  const header = getToken(req)
  if (header) return header
  const query = req.query.token
  return typeof query === 'string' && query.length > 0 ? query : null
}

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = tokenFromRequest(req)
  if (!token) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }
  const user = await getServerUser(token)
  if (!user) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  }
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}

/* ------------------------------------------------------------------ */
/* Row caps                                                            */
/* ------------------------------------------------------------------ */

const CAP = {
  assets: 2000,
  cryptoInventory: 3000,
  certificates: 1500,
  generatedKeys: 1500,
  runtimeEvents: 3000,
  vaultFiles: 1500,
  scanSessions: 300,
  scanResults: 2500,
  cryptoExposures: 2000,
  vulnerabilities: 1500,
  scannerAlerts: 1500,
  scannerEvidence: 1500,
  scannerAgents: 400,
  connectorAccounts: 400,
  agentHeartbeats: 800,
  migrationJobs: 1500,
  migrationPlans: 400,
  migrationEvents: 1200,
  complianceEvidence: 1500,
  auditLogs: 2500,
  vaultAuditLogs: 2000,
  securityEvents: 1500,
  userSecurityEvents: 800,
  authEvents: 800,
  governancePolicies: 200,
  evidenceAnchors: 4000,
  controlAssessments: 200,
} as const

/* ------------------------------------------------------------------ */
/* Model                                                               */
/* ------------------------------------------------------------------ */

const MODEL_TTL_MS = 15_000
// Single-flight per tenant. Governance is the widest fan-out on the platform
// (~54 queries once buildSnapshot and buildPortfolio are folded in), so a
// duplicated build was the single largest contributor to the connect-timeout
// storm. See lib/single-flight-cache.ts.
const modelCache = createSingleFlightCache<GovernanceIntelligence>(MODEL_TTL_MS)

/**
 * Re-derives the control evaluation inputs for the paged drill-down routes.
 *
 * The dashboard payload carries only a bounded sample of failing subjects per
 * control; a user paging through all of them needs the full evaluation. Rather
 * than storing every subject in the cached model (which would make the payload
 * unbounded on a large estate), the drill-down rebuilds the inputs from the
 * SAME cached model so the rows it returns are guaranteed to match the counts
 * the dashboard rendered.
 */
const rawCache = new Map<string, { at: number; inputs: GovernanceInputs }>()

async function computeModel(token: string, userId: string): Promise<GovernanceIntelligence> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  // Canonical estate truth first. Both are themselves cached per tenant on the
  // same 15s window, so asking for them here is nearly free — and it is what
  // guarantees these four pages agree with Quantum Readiness, Assets, CBOM,
  // Migration Planner, the Executive Command Center and every report.
  const [snapshot, portfolio] = await Promise.all([buildSnapshot(token, userId), buildPortfolio(token, userId)])

  const [
    assets,
    cryptoInventory,
    certificates,
    generatedKeys,
    runtimeEvents,
    vaultFiles,
    scanSessions,
    scanResults,
    cryptoExposures,
    vulnerabilities,
    scannerAlerts,
    scannerEvidence,
    scannerAgents,
    connectorAccounts,
    agentHeartbeats,
    migrationJobs,
    migrationPlans,
    migrationEvents,
    complianceEvidence,
    auditLogs,
    vaultAuditLogs,
    securityEvents,
    userSecurityEvents,
    authEvents,
    governancePolicies,
    evidenceAnchors,
    controlAssessments,
  ] = await Promise.all([
    fetchRows(client, 'assets', CAP.assets, (q) =>
      q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(CAP.assets),
    ),
    fetchRows(client, 'crypto_inventory', CAP.cryptoInventory, (q) =>
      q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(CAP.cryptoInventory),
    ),
    fetchRows(client, 'certificates', CAP.certificates, (q) =>
      q.select('id, asset_id, name, subject, issuer, algorithm, key_size, status, not_after, is_quantum_safe, is_expiring_soon, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(CAP.certificates),
    ),
    fetchRows(client, 'generated_keys', CAP.generatedKeys, (q) =>
      q.select('id, algorithm, bit_length, entropy_source, quality_score, status, expires_at, revoked_at, rotated_from, label, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(CAP.generatedKeys),
    ),
    fetchRows(client, 'runtime_crypto_events', CAP.runtimeEvents, (q) =>
      q.select('id, agent_id, asset_id, asset_name, host, source_type, event_type, operation_type, severity, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(CAP.runtimeEvents),
    ),
    fetchRows(client, 'vault_files', CAP.vaultFiles, (q) =>
      q.select('id, original_filename, mime_type, original_size, encryption_status, encryption_algorithm, signature_status, key_rotation_status, is_deleted, is_latest, uploaded_at, encrypted_at, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(CAP.vaultFiles),
    ),
    fetchRows(client, 'pqc_scan_sessions', CAP.scanSessions, (q) =>
      q.select('id, status, progress, total_assets, scanned_assets, findings_count, target_scope, started_at, completed_at, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(CAP.scanSessions),
    ),
    fetchRows(client, 'pqc_scan_results', CAP.scanResults, (q) =>
      q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(CAP.scanResults),
    ),
    fetchRows(client, 'crypto_exposures', CAP.cryptoExposures, (q) =>
      q.select('id, asset_id, exposure_type, severity, description, detected_value, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(CAP.cryptoExposures),
    ),
    fetchRows(client, 'vulnerabilities', CAP.vulnerabilities, (q) =>
      q.select('id, asset_id, title, description, severity, status, source, cvss_score, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(CAP.vulnerabilities),
    ),
    fetchRows(client, 'scanner_alerts', CAP.scannerAlerts, (q) =>
      q.select('id, agent_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(CAP.scannerAlerts),
    ),
    fetchRows(client, 'scanner_evidence', CAP.scannerEvidence, (q) =>
      q.select('id, asset_name, asset_type, host, target, evidence_type, source_type, observed_algorithm, protocol, key_size, confidence, observed_at, processed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(CAP.scannerEvidence),
    ),
    fetchRows(client, 'scanner_agents', CAP.scannerAgents, (q) =>
      q.select('id, name, status, hostname, platform, last_seen_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(CAP.scannerAgents),
    ),
    fetchRows(client, 'connector_accounts', CAP.connectorAccounts, (q) =>
      q.select('id, provider, display_name, status, capabilities, last_sync_at, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(CAP.connectorAccounts),
    ),
    fetchRows(client, 'agent_heartbeats', CAP.agentHeartbeats, (q) =>
      q.select('id, agent_id, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(CAP.agentHeartbeats),
    ),
    fetchRows(client, 'migration_jobs', CAP.migrationJobs, (q) =>
      q.select('id, asset_id, name, job_type, status, target_algorithm, progress, metadata, started_at, completed_at, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(CAP.migrationJobs),
    ),
    fetchRows(client, 'migration_plans', CAP.migrationPlans, (q) =>
      q.select('id, name, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(CAP.migrationPlans),
    ),
    fetchRows(client, 'migration_events', CAP.migrationEvents, (q) =>
      q.select('id, migration_id, event_type, message, severity, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(CAP.migrationEvents),
    ),
    fetchRows(client, 'compliance_evidence', CAP.complianceEvidence, (q) =>
      q.select('id, asset_id, framework, control_id, evidence_type, description, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(CAP.complianceEvidence),
    ),
    fetchRows(client, 'audit_logs', CAP.auditLogs, (q) =>
      q.select('id, action, entity_type, entity_id, details, ip_address, user_agent, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(CAP.auditLogs),
    ),
    fetchRows(client, 'vault_audit_logs', CAP.vaultAuditLogs, (q) =>
      q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(CAP.vaultAuditLogs),
    ),
    fetchRows(client, 'security_events', CAP.securityEvents, (q) =>
      q.select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(CAP.securityEvents),
    ),
    fetchRows(client, 'user_security_events', CAP.userSecurityEvents, (q) =>
      q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(CAP.userSecurityEvents),
    ),
    fetchRows(client, 'auth_events', CAP.authEvents, (q) =>
      q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(CAP.authEvents),
    ),
    fetchRows(client, 'governance_policies', CAP.governancePolicies, (q) =>
      q.select('id, policy_id, enforcement, severity, parameters, note, updated_by, created_at, updated_at').eq('user_id', userId).limit(CAP.governancePolicies),
    ),
    fetchRows(client, 'governance_evidence_anchors', CAP.evidenceAnchors, (q) =>
      q.select('id, evidence_id, digest, first_digest, algorithm, anchored_at, reanchored_at, reanchor_count, created_at').eq('user_id', userId).limit(CAP.evidenceAnchors),
    ),
    fetchRows(client, 'governance_control_assessments', CAP.controlAssessments, (q) =>
      q.select('id, control_id, owner, owner_email, review_note, attested_at, attested_by, exception_reason, exception_approved_by, exception_approved_at, exception_expires_at, created_at, updated_at').eq('user_id', userId).limit(CAP.controlAssessments),
    ),
  ])

  const outcomes: Array<[string, FetchOutcome]> = [
    ['assets', assets],
    ['crypto_inventory', cryptoInventory],
    ['certificates', certificates],
    ['generated_keys', generatedKeys],
    ['runtime_crypto_events', runtimeEvents],
    ['vault_files', vaultFiles],
    ['pqc_scan_sessions', scanSessions],
    ['pqc_scan_results', scanResults],
    ['crypto_exposures', cryptoExposures],
    ['vulnerabilities', vulnerabilities],
    ['scanner_alerts', scannerAlerts],
    ['scanner_evidence', scannerEvidence],
    ['scanner_agents', scannerAgents],
    ['connector_accounts', connectorAccounts],
    ['migration_jobs', migrationJobs],
    ['migration_plans', migrationPlans],
    ['migration_events', migrationEvents],
    ['compliance_evidence', complianceEvidence],
    ['audit_logs', auditLogs],
    ['vault_audit_logs', vaultAuditLogs],
    ['security_events', securityEvents],
    ['auth_events', authEvents],
  ]

  const sourceCounts: Record<string, number> = {}
  const absentSources: string[] = []
  for (const [name, outcome] of outcomes) {
    sourceCounts[name] = outcome.rows.length
    if (!outcome.available) absentSources.push(name)
  }
  const truncated = outcomes.some(([, outcome]) => outcome.capped)

  const canonical: CanonicalSnapshot = {
    hasData: snapshot.hasData,
    scores: {
      quantumReadiness: snapshot.scores.quantumReadiness,
      quantumRisk: snapshot.scores.quantumRisk,
      pqcAdoption: snapshot.scores.pqcAdoption,
    },
    inventory: {
      assetsAssessed: snapshot.inventory.assetsAssessed,
      certificatesAnalyzed: snapshot.inventory.certificatesAnalyzed,
      keysDiscovered: snapshot.inventory.keysDiscovered,
      cryptoComponents: snapshot.inventory.cryptoComponents,
      vulnerableComponents: snapshot.inventory.vulnerableComponents,
      pqcReadyComponents: snapshot.inventory.pqcReadyComponents,
      quantumVulnerableAssets: snapshot.inventory.quantumVulnerableAssets,
      pqcReadyAssets: snapshot.inventory.pqcReadyAssets,
      hybridAssets: snapshot.inventory.hybridAssets,
    },
    riskDistribution: snapshot.riskDistribution,
    telemetry: {
      latestRuntimeEventAt: snapshot.telemetry.latestRuntimeEventAt ?? null,
      latestEventAt: snapshot.telemetry.latestEventAt ?? null,
    },
  }

  const portfolioAssets: PortfolioAsset[] = portfolio.assets.map((asset) => ({
    id: asset.id,
    name: asset.name,
    type: asset.type,
    environment: asset.environment,
    owner: asset.owner,
    businessCriticality: asset.businessCriticality,
    internetFacing: asset.internetFacing,
    riskScore: asset.riskScore,
    readinessScore: asset.readinessScore,
    posture: asset.posture,
    postureLabel: asset.postureLabel,
    severityCounts: asset.severityCounts,
    lastEvidenceAt: asset.lastEvidenceAt,
  }))

  const inputs: GovernanceInputs = {
    snapshot: canonical,
    portfolioAssets,
    assets: assets.rows,
    cryptoInventory: cryptoInventory.rows,
    certificates: certificates.rows,
    generatedKeys: generatedKeys.rows,
    runtimeEvents: runtimeEvents.rows,
    vaultFiles: vaultFiles.rows,
    scanSessions: scanSessions.rows,
    scanResults: scanResults.rows,
    cryptoExposures: cryptoExposures.rows,
    vulnerabilities: vulnerabilities.rows,
    scannerAlerts: scannerAlerts.rows,
    scannerEvidence: scannerEvidence.rows,
    scannerAgents: scannerAgents.rows,
    connectorAccounts: connectorAccounts.rows,
    agentHeartbeats: agentHeartbeats.rows,
    migrationJobs: migrationJobs.rows,
    migrationPlans: migrationPlans.rows,
    migrationEvents: migrationEvents.rows,
    complianceEvidence: complianceEvidence.rows,
    auditLogs: auditLogs.rows,
    vaultAuditLogs: vaultAuditLogs.rows,
    securityEvents: securityEvents.rows,
    userSecurityEvents: userSecurityEvents.rows,
    authEvents: authEvents.rows,
    // `null` (not `[]`) when the store is unavailable, so integrity reports
    // "unavailable" instead of a false "unanchored / verified".
    policyOverrides: governancePolicies.available ? governancePolicies.rows : null,
    evidenceAnchors: evidenceAnchors.available ? evidenceAnchors.rows : null,
    controlAssessments: controlAssessments.available ? controlAssessments.rows : null,
    truncated,
    sourceCounts,
    absentSources,
  }

  rawCache.set(userId, { at: Date.now(), inputs })
  if (rawCache.size > 200) {
    const now = Date.now()
    for (const [key, value] of rawCache) if (now - value.at > MODEL_TTL_MS * 4) rawCache.delete(key)
  }

  return buildGovernanceIntelligence(inputs)
}

export async function buildGovernanceModel(token: string, userId: string, force = false): Promise<GovernanceIntelligence> {
  return modelCache.get(userId, () => computeModel(token, userId), force)
}

/** Drops the tenant's cached model so the next read reflects a just-made write. */
export function invalidateGovernanceModel(userId: string) {
  modelCache.delete(userId)
  rawCache.delete(userId)
}

/**
 * Compatibility projection for the Executive Command Center.
 *
 * `dashboard-executive.ts` reads `metrics.complianceScore` and
 * `frameworkAlignment[]` to render its compliance strip. Serving them from the
 * governance model — rather than from the retired builder — is what keeps the
 * Executive page and the Compliance page showing the same score. Frameworks with
 * no measured control are OMITTED rather than given the overall score, which is
 * exactly the fabrication the retired builder produced.
 */
export async function buildExecutiveComplianceProjection(token: string, userId: string) {
  const model = await buildGovernanceModel(token, userId)
  return {
    metrics: {
      complianceScore: model.scores.compliance.value ?? 0,
      complianceMeasured: model.scores.compliance.measured,
      controlCoverage: model.scores.controlCoverage.value ?? 0,
    },
    /* The requirement counts travel WITH the score, so the executive strip can
       state measured gaps (failing + partial requirements) and coverage instead
       of dividing the score into an invented per-framework control total. */
    frameworkAlignment: model.frameworks
      .filter((framework) => framework.measured && framework.score !== null)
      .map((framework) => ({
        name: framework.name,
        score: framework.score as number,
        requirementsTotal: framework.requirementsTotal,
        requirementsMeasured: framework.requirementsMeasured,
        requirementsCompliant: framework.requirementsCompliant,
        requirementsPartial: framework.requirementsPartial,
        requirementsFailing: framework.requirementsFailing,
        requirementsUnassessed: framework.requirementsUnassessed,
        coverage: framework.coverage,
        evidenceCount: framework.evidenceCount,
        attestedEvidenceCount: framework.attestedEvidenceCount,
      })),
  }
}

/* ------------------------------------------------------------------ */
/* Filtering + paging                                                  */
/* ------------------------------------------------------------------ */

function active(value: unknown): string {
  const text = str(value).toLowerCase()
  return text && text !== 'all' ? text : ''
}

function paginate<T>(rows: T[], req: Request): { rows: T[]; total: number; limit: number; offset: number } {
  const limit = Math.max(1, Math.min(200, num(req.query.limit, 50)))
  const offset = Math.max(0, num(req.query.offset, 0))
  return { rows: rows.slice(offset, offset + limit), total: rows.length, limit, offset }
}

function withinRange(at: string | null, range: string): boolean {
  if (!range) return true
  const days = range === '24h' ? 1 : range === '7d' ? 7 : range === '30d' ? 30 : range === '90d' ? 90 : range === '1y' ? 365 : 0
  if (!days) return true
  const parsed = Date.parse(at || '')
  if (!Number.isFinite(parsed)) return false
  return Date.now() - parsed <= days * 86_400_000
}

function matchesSearch(haystack: string, search: string): boolean {
  return !search || haystack.toLowerCase().includes(search)
}

function filterControls(controls: ControlRecord[], req: Request): ControlRecord[] {
  const search = active(req.query.search)
  const status = active(req.query.status)
  const domain = active(req.query.domain)
  const framework = str(req.query.framework)
  const requirement = str(req.query.requirement)
  const severity = active(req.query.severity)
  const owner = active(req.query.owner)
  const freshness = active(req.query.freshness)

  return controls.filter((control) => {
    if (status && control.status !== status) return false
    if (domain && control.domain !== domain) return false
    if (framework && framework !== 'all' && !control.frameworkIds.includes(framework)) return false
    if (requirement && requirement !== 'all' && !control.requirementIds.includes(requirement)) return false
    if (severity && control.severity !== severity) return false
    if (owner && (control.owner || 'unassigned').toLowerCase() !== owner) return false
    if (freshness && control.evidenceFreshness !== freshness) return false
    return matchesSearch(`${control.code} ${control.title} ${control.objective} ${control.basis}`, search)
  })
}

function filterEvidence(evidence: EvidenceRecord[], req: Request): EvidenceRecord[] {
  const search = active(req.query.search)
  const kind = active(req.query.kind)
  const outcome = active(req.query.outcome)
  const integrity = active(req.query.integrity)
  const retention = active(req.query.retention)
  const freshness = active(req.query.freshness)
  const framework = str(req.query.framework)
  const control = str(req.query.control)
  const asset = str(req.query.asset)
  const range = active(req.query.range)

  return evidence.filter((record) => {
    if (kind && record.kind !== kind) return false
    if (outcome && record.outcome !== outcome) return false
    if (integrity && record.integrity.state !== integrity) return false
    if (retention && record.retention.state !== retention) return false
    if (freshness && record.freshness !== freshness) return false
    if (framework && framework !== 'all' && !record.frameworkIds.includes(framework)) return false
    if (control && control !== 'all' && !record.controlIds.includes(control)) return false
    if (asset && record.assetId !== asset) return false
    if (!withinRange(record.occurredAt, range)) return false
    return matchesSearch(`${record.title} ${record.description} ${record.source.table} ${record.assetName || ''} ${record.actor}`, search)
  })
}

function filterAuditEvents(events: GovernanceIntelligence['auditEvents'], req: Request) {
  const search = active(req.query.search)
  const category = active(req.query.category)
  const outcome = active(req.query.outcome)
  const severity = active(req.query.severity)
  const actorType = active(req.query.actorType)
  const asset = str(req.query.asset)
  const range = active(req.query.range)

  return events.filter((event) => {
    if (category && event.category !== category) return false
    if (outcome && event.outcome !== outcome) return false
    if (severity && event.severity !== severity) return false
    if (actorType && event.actorType !== actorType) return false
    if (asset && event.assetId !== asset) return false
    if (!withinRange(event.at, range)) return false
    return matchesSearch(`${event.action} ${event.subject} ${event.detail} ${event.actor} ${event.source.table}`, search)
  })
}

function filterAssets(assets: GovernanceIntelligence['assets'], req: Request) {
  const search = active(req.query.search)
  const status = active(req.query.status)
  const environment = active(req.query.environment)
  const owner = active(req.query.owner)
  const criticality = active(req.query.criticality)
  const exposure = active(req.query.exposure)
  const control = str(req.query.control)

  return assets.filter((asset) => {
    if (status && asset.status !== status) return false
    if (environment && asset.environment.toLowerCase() !== environment) return false
    if (owner && asset.owner.toLowerCase() !== owner) return false
    if (criticality && asset.criticality.toLowerCase() !== criticality) return false
    if (exposure === 'internet' && !asset.internetFacing) return false
    if (exposure === 'internal' && asset.internetFacing) return false
    if (control && control !== 'all' && !asset.failingControlIds.includes(control)) return false
    return matchesSearch(`${asset.name} ${asset.type} ${asset.owner} ${asset.environment}`, search)
  })
}

function filterRequirements(requirements: GovernanceIntelligence['requirements'], req: Request) {
  const search = active(req.query.search)
  const framework = str(req.query.framework)
  const status = active(req.query.status)

  return requirements.filter((requirement) => {
    if (framework && framework !== 'all' && requirement.frameworkId !== framework) return false
    if (status && requirement.status !== status) return false
    return matchesSearch(`${requirement.code} ${requirement.title} ${requirement.summary}`, search)
  })
}

function filterGaps(gaps: GovernanceIntelligence['gaps'], req: Request) {
  const search = active(req.query.search)
  const kind = active(req.query.kind)
  const severity = active(req.query.severity)
  const domain = active(req.query.domain)
  const framework = str(req.query.framework)

  return gaps.filter((gap) => {
    if (kind && gap.kind !== kind) return false
    if (severity && gap.severity !== severity) return false
    if (domain && gap.domain !== domain) return false
    if (framework && framework !== 'all' && !gap.frameworkIds.includes(framework)) return false
    return matchesSearch(`${gap.title} ${gap.detail} ${gap.impact}`, search)
  })
}

/* ------------------------------------------------------------------ */
/* Projections — bounded payloads, one per page                        */
/* ------------------------------------------------------------------ */

/** Rows shipped in the first paint. Deeper pages come from the paging routes. */
const PAGE = { controls: 40, evidence: 50, audit: 60, gaps: 24, assets: 40, requirements: 60, policies: 40 } as const

/** Fields every page shares, so the header is identical on all four. */
function commonEnvelope(model: GovernanceIntelligence) {
  return {
    generatedAt: model.generatedAt,
    latestEvidenceAt: model.latestEvidenceAt,
    hasData: model.hasData,
    stale: model.stale,
    staleSinceHours: model.staleSinceHours,
    scores: model.scores,
    totals: model.totals,
    telemetry: model.telemetry,
    facets: model.facets,
    reconciliation: model.reconciliation,
  }
}

/** Control summary for cross-page tables — the full record is one fetch away. */
function controlSummary(control: ControlRecord) {
  return {
    id: control.id,
    code: control.code,
    title: control.title,
    domain: control.domain,
    status: control.status,
    score: control.score,
    measured: control.measured,
    severity: control.severity,
    population: control.population,
    satisfied: control.satisfied,
    failing: control.failing,
    owner: control.owner,
    ownerSource: control.ownerSource,
    frameworkIds: control.frameworkIds,
    requirementIds: control.requirementIds,
    affectedAssetCount: control.affectedAssetCount,
    lastValidatedAt: control.lastValidatedAt,
    evidenceFreshness: control.evidenceFreshness,
    evidenceAgeDays: control.evidenceAgeDays,
    remediationRoute: control.remediationRoute,
    basis: control.basis,
    weight: control.weight,
    hasException: Boolean(control.exception),
  }
}

export type ControlSummary = ReturnType<typeof controlSummary>

export function projectView(model: GovernanceIntelligence, view: GovernanceView) {
  const base = commonEnvelope(model)

  switch (view) {
    case 'compliance':
      return {
        ...base,
        view: 'compliance' as const,
        /* Executive strip + control management + gap analysis. */
        controls: model.controls
          .slice()
          .sort((a, b) => statusRank(a.status) - statusRank(b.status) || b.weight - a.weight)
          .slice(0, PAGE.controls)
          .map(controlSummary),
        controlIndex: model.controls.map((control) => ({ id: control.id, code: control.code, title: control.title, status: control.status, domain: control.domain })),
        gaps: model.gaps.slice(0, PAGE.gaps),
        frameworks: model.frameworks,
        assets: model.assets.slice(0, PAGE.assets),
        evidence: model.evidence.slice(0, 24),
        trend: model.trend,
        domainRollup: domainRollup(model),
        /* Every framework's requirement coverage, for the drill-down tree. */
        requirementSummary: model.requirements.map((requirement) => ({
          id: requirement.id,
          frameworkId: requirement.frameworkId,
          code: requirement.code,
          title: requirement.title,
          status: requirement.status,
          score: requirement.score,
          measured: requirement.measured,
        })),
      }

    case 'quantum':
      return {
        ...base,
        view: 'quantum' as const,
        policies: model.policies.slice(0, PAGE.policies),
        /* Quantum + algorithm + key + transport controls are this page's scope. */
        controls: model.controls
          .filter((control) => ['quantum', 'algorithm', 'key', 'transport', 'certificate', 'data', 'governance'].includes(control.domain))
          .slice()
          .sort((a, b) => statusRank(a.status) - statusRank(b.status) || b.weight - a.weight)
          .map(controlSummary),
        gaps: model.gaps.filter((gap) => gap.domain !== 'audit').slice(0, PAGE.gaps),
        assets: model.assets.slice(0, PAGE.assets),
        trend: model.trend,
        domainRollup: domainRollup(model),
        /* Canonical estate posture, mirrored so this page cannot drift. */
        posture: {
          cryptoComponents: model.totals.cryptoComponents,
          vulnerableComponents: model.totals.vulnerableComponents,
          pqcReadyComponents: model.totals.pqcReadyComponents,
          certificates: model.totals.certificates,
          keys: model.totals.keys,
          criticalFindings: model.totals.criticalFindings,
        },
      }

    case 'audit':
      return {
        ...base,
        view: 'audit' as const,
        auditEvents: model.auditEvents.slice(0, PAGE.audit),
        evidence: model.evidence.slice(0, PAGE.evidence),
        /* Audit + evidence controls scope this page. */
        controls: model.controls.filter((control) => control.domain === 'audit').map(controlSummary),
        gaps: model.gaps.filter((gap) => gap.domain === 'audit' || gap.kind === 'stale-evidence' || gap.kind === 'expired-evidence').slice(0, PAGE.gaps),
        trend: model.trend,
        /* Integrity + retention rollups the vault header renders. */
        integrity: integrityRollup(model),
        retention: retentionRollup(model),
        custodyRollup: custodyRollup(model),
      }

    case 'regulatory':
      return {
        ...base,
        view: 'regulatory' as const,
        frameworks: model.frameworks,
        requirements: model.requirements.slice(0, PAGE.requirements),
        controls: model.controls.map(controlSummary),
        gaps: model.gaps.slice(0, PAGE.gaps),
        evidence: model.evidence.filter((record) => record.kind === 'attestation').slice(0, 30),
        assets: model.assets.slice(0, PAGE.assets),
        trend: model.trend,
      }
  }
}

function statusRank(status: ControlRecord['status']): number {
  if (status === 'non-compliant') return 0
  if (status === 'partial') return 1
  if (status === 'not-assessed') return 2
  if (status === 'compliant') return 3
  return 4
}

function domainRollup(model: GovernanceIntelligence) {
  const domains = [...new Set(model.controls.map((control) => control.domain))]
  return domains
    .map((domain) => {
      const scoped = model.controls.filter((control) => control.domain === domain)
      const measured = scoped.filter((control) => control.measured && control.score !== null && control.status !== 'not-applicable')
      const weight = measured.reduce((sum, control) => sum + control.weight, 0)
      return {
        domain,
        controls: scoped.length,
        measured: measured.length,
        compliant: scoped.filter((control) => control.status === 'compliant').length,
        failing: scoped.filter((control) => control.status === 'non-compliant' || control.status === 'partial').length,
        unassessed: scoped.filter((control) => control.status === 'not-assessed').length,
        score: weight > 0 ? Math.round(measured.reduce((sum, control) => sum + (control.score ?? 0) * control.weight, 0) / weight) : null,
        failingSubjects: scoped.reduce((sum, control) => sum + control.failing, 0),
      }
    })
    .sort((a, b) => (a.score ?? 101) - (b.score ?? 101))
}

function integrityRollup(model: GovernanceIntelligence) {
  const counts = { verified: 0, mismatch: 0, unanchored: 0, unavailable: 0 }
  for (const record of model.evidence) counts[record.integrity.state] += 1
  return {
    ...counts,
    total: model.evidence.length,
    available: model.telemetry.anchoringAvailable,
    /* The honest one-line claim the header renders. */
    claim: !model.telemetry.anchoringAvailable
      ? 'Evidence anchoring is unavailable in this environment — integrity cannot be established.'
      : counts.mismatch > 0
        ? `${counts.mismatch} anchored record(s) no longer match their anchored digest — the source changed after anchoring.`
        : counts.verified > 0
          ? `${counts.verified} record(s) verify against a digest anchored at first observation. Tamper-evident, not immutable.`
          : 'No evidence has been anchored yet, so modification would not be detectable.',
  }
}

function retentionRollup(model: GovernanceIntelligence) {
  const counts = { active: 0, expiring: 0, expired: 0, unspecified: 0 }
  for (const record of model.evidence) counts[record.retention.state] += 1
  return { ...counts, total: model.evidence.length }
}

function custodyRollup(model: GovernanceIntelligence) {
  const byCollector = new Map<string, number>()
  for (const record of model.evidence) {
    byCollector.set(record.source.collector, (byCollector.get(record.source.collector) || 0) + 1)
  }
  return [...byCollector.entries()]
    .map(([collector, count]) => ({ collector, count }))
    .sort((a, b) => b.count - a.count)
}

/* ------------------------------------------------------------------ */
/* Drill-down input reconstruction                                     */
/* ------------------------------------------------------------------ */

/**
 * Rebuilds the control-evaluation inputs from the cached raw rows.
 *
 * The paged control drill-down needs the FULL failing-subject list, which the
 * dashboard payload deliberately truncates. Rebuilding from the cached inputs
 * (rather than re-querying) guarantees the paged rows come from the same
 * snapshot that produced the counts on screen.
 */
async function evaluationInputsFor(token: string, userId: string): Promise<{ model: GovernanceIntelligence; controlInputs: ControlEvaluationInputs; policyContext: PolicyEvaluationContext; raw: GovernanceInputs } | null> {
  const model = await buildGovernanceModel(token, userId)
  const cached = rawCache.get(userId)
  if (!cached) return null
  const raw = cached.inputs
  const subjects = buildSubjects({
    assets: raw.assets,
    cryptoInventory: raw.cryptoInventory,
    certificates: raw.certificates,
    generatedKeys: raw.generatedKeys,
    runtimeEvents: raw.runtimeEvents,
    vaultFiles: raw.vaultFiles,
  })
  const policyContext: PolicyEvaluationContext = {
    subjects,
    now: Date.parse(model.generatedAt) || Date.now(),
    quantumRisk: raw.snapshot.hasData ? raw.snapshot.scores.quantumRisk : null,
    hasEstateEvidence: raw.snapshot.hasData,
  }
  const controlInputs: ControlEvaluationInputs = {
    now: policyContext.now,
    snapshot: raw.snapshot,
    subjects,
    policies: model.policies,
    evidence: model.evidence,
    assets: raw.assets,
    scanSessions: raw.scanSessions,
    scanResults: raw.scanResults,
    vulnerabilities: raw.vulnerabilities,
    scannerAlerts: raw.scannerAlerts,
    cryptoExposures: raw.cryptoExposures,
    scannerAgents: raw.scannerAgents,
    connectorAccounts: raw.connectorAccounts,
    agentHeartbeats: raw.agentHeartbeats,
    migrationJobs: raw.migrationJobs,
    migrationPlans: raw.migrationPlans,
    auditLogs: raw.auditLogs,
    vaultAuditLogs: raw.vaultAuditLogs,
    securityEvents: raw.securityEvents,
    authEvents: raw.authEvents,
    complianceEvidence: raw.complianceEvidence,
    assessments: raw.controlAssessments,
    anchoringAvailable: raw.evidenceAnchors !== null,
  }
  return { model, controlInputs, policyContext, raw }
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

function buildRouter(view: GovernanceView): Router {
  const router = Router()
  router.use(requireAuth)

  const model = (req: AuthedRequest, force = false) => buildGovernanceModel(req.token!, req.user!.id, force)

  const fail = (res: Response, error: unknown, message: string) => {
    console.error(`[governance:${view}] ${message}:`, error)
    res.status(500).json({
      error: { code: 'GOVERNANCE_ERROR', message: error instanceof Error ? error.message : message },
    })
  }

  /* ---- GET / — the view payload ---------------------------------- */
  router.get('/', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req, str(req.query.refresh) === '1')
      res.json({ data: projectView(data, view) })
    } catch (error) {
      fail(res, error, `failed to compute ${VIEW_LABEL[view]}`)
    }
  })

  /**
   * GET /stream — Server-Sent Events carrying the WHOLE view payload.
   *
   * The client replaces state atomically rather than patching, which is what
   * stops the KPI strip, the tables and the charts from disagreeing mid-update.
   * Every connected client of a tenant collapses onto the one cached model, and
   * identical frames are suppressed so an idle dashboard costs nothing.
   */
  router.get('/stream', async (req: AuthedRequest, res: Response) => {
    res.status(200)
    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache, no-transform')
    res.setHeader('Connection', 'keep-alive')
    res.setHeader('X-Accel-Buffering', 'no')
    res.flushHeaders?.()

    let closed = false
    const send = (event: string, data: unknown) => {
      if (closed) return
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
    }

    send('connected', { at: new Date().toISOString(), view })

    let lastGeneratedAt = ''
    const push = async () => {
      try {
        const data = await model(req)
        if (data.generatedAt === lastGeneratedAt) return
        lastGeneratedAt = data.generatedAt
        send('governance', projectView(data, view))
      } catch (error) {
        send('governance-error', { message: error instanceof Error ? error.message : 'Governance telemetry unavailable' })
      }
    }

    void push()
    const interval = setInterval(() => void push(), 10_000)
    const heartbeat = setInterval(() => {
      if (!closed) res.write(': heartbeat\n\n')
    }, 25_000)

    req.on('close', () => {
      closed = true
      clearInterval(interval)
      clearInterval(heartbeat)
    })
  })

  /* ---- Controls -------------------------------------------------- */
  router.get('/controls', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const filtered = filterControls(data.controls, req)
      const sort = str(req.query.sort)
      const sorted = filtered.slice().sort((a, b) => {
        if (sort === 'score') return (a.score ?? 101) - (b.score ?? 101)
        if (sort === 'failing') return b.failing - a.failing
        if (sort === 'code') return a.code.localeCompare(b.code)
        return statusRank(a.status) - statusRank(b.status) || b.weight - a.weight
      })
      const page = paginate(sorted, req)
      res.json({ data: { controls: page.rows.map(controlSummary), total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      fail(res, error, 'failed to load controls')
    }
  })

  /**
   * One control with everything needed to defend or fix its status: the
   * requirements and frameworks that depend on it, the evidence that supports
   * it, the assets it implicates, and the policy rules behind it. This is the
   * "KPI → control → requirement → asset → finding → evidence" path from §15.
   */
  router.get('/controls/:id', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const id = str(req.params.id)
      const control = data.controls.find((candidate) => candidate.id === id)
      if (!control) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Control not found' } })

      const requirements = data.requirements.filter((requirement) => control.requirementIds.includes(requirement.id))
      const frameworks = data.frameworks.filter((framework) => control.frameworkIds.includes(framework.id))
      const evidence = data.evidence.filter((record) => record.controlIds.includes(id)).slice(0, 60)
      const policies = data.policies.filter((policy) => policy.controlIds.includes(id))
      const assets = data.assets.filter((asset) => asset.failingControlIds.includes(id)).slice(0, 60)
      const auditEvents = data.auditEvents.filter((event) => event.controlIds.includes(id)).slice(0, 30)
      const gaps = data.gaps.filter((gap) => gap.controlIds.includes(id))

      res.json({
        data: {
          control,
          definition: CONTROL_BY_ID.get(id) ?? null,
          requirements,
          frameworks,
          evidence,
          policies,
          assets,
          auditEvents,
          gaps,
        },
      })
    } catch (error) {
      fail(res, error, 'failed to load control detail')
    }
  })

  /** Every failing subject for one control — the full list, paged. */
  router.get('/controls/:id/subjects', async (req: AuthedRequest, res: Response) => {
    try {
      const context = await evaluationInputsFor(req.token!, req.user!.id)
      if (!context) return res.status(503).json({ error: { code: 'MODEL_UNAVAILABLE', message: 'Governance model is rebuilding; retry shortly' } })
      const id = str(req.params.id)
      if (!CONTROL_BY_ID.has(id)) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Control not found' } })

      const search = active(req.query.search)
      const severity = active(req.query.severity)
      const subjects = failingSubjectsFor(id, context.controlInputs)
        .filter((subject) => (!severity || subject.severity === severity) && matchesSearch(`${subject.label} ${subject.reason} ${subject.type}`, search))
        .sort((a, b) => severityOrder(b.severity || 'low') - severityOrder(a.severity || 'low'))
      const page = paginate(subjects, req)
      res.json({ data: { subjects: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      fail(res, error, 'failed to load control subjects')
    }
  })

  /* ---- Frameworks + requirements ---------------------------------- */
  router.get('/frameworks', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      res.json({ data: { frameworks: data.frameworks, total: data.frameworks.length } })
    } catch (error) {
      fail(res, error, 'failed to load frameworks')
    }
  })

  router.get('/frameworks/:id', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const id = str(req.params.id)
      const framework = data.frameworks.find((candidate) => candidate.id === id)
      if (!framework) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Framework not found' } })

      const requirements = data.requirements.filter((requirement) => requirement.frameworkId === id)
      const controlIds = new Set(requirements.flatMap((requirement) => requirement.controlIds))
      const controls = data.controls.filter((control) => controlIds.has(control.id))
      res.json({
        data: {
          framework,
          definition: FRAMEWORK_BY_ID.get(id) ?? null,
          requirements,
          controls: controls.map(controlSummary),
          evidence: data.evidence.filter((record) => record.frameworkIds.includes(id)).slice(0, 60),
          gaps: data.gaps.filter((gap) => gap.frameworkIds.includes(id)),
        },
      })
    } catch (error) {
      fail(res, error, 'failed to load framework detail')
    }
  })

  router.get('/requirements', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const page = paginate(filterRequirements(data.requirements, req), req)
      res.json({ data: { requirements: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      fail(res, error, 'failed to load requirements')
    }
  })

  router.get('/requirements/:id', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const id = decodeURIComponent(str(req.params.id))
      const requirement = data.requirements.find((candidate) => candidate.id === id)
      if (!requirement) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Requirement not found' } })
      const controls = data.controls.filter((control) => requirement.controlIds.includes(control.id))
      res.json({
        data: {
          requirement,
          definition: REQUIREMENT_BY_ID.get(id) ?? null,
          framework: data.frameworks.find((candidate) => candidate.id === requirement.frameworkId) ?? null,
          controls: controls.map(controlSummary),
          evidence: data.evidence.filter((record) => record.requirementIds.includes(id)).slice(0, 60),
        },
      })
    } catch (error) {
      fail(res, error, 'failed to load requirement detail')
    }
  })

  /* ---- Evidence ---------------------------------------------------- */
  router.get('/evidence', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const page = paginate(filterEvidence(data.evidence, req), req)
      res.json({ data: { evidence: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      fail(res, error, 'failed to load evidence')
    }
  })

  router.get('/evidence/:id', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const id = decodeURIComponent(str(req.params.id))
      const record = data.evidence.find((candidate) => candidate.id === id)
      if (!record) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Evidence record not found' } })
      res.json({
        data: {
          evidence: record,
          controls: data.controls.filter((control) => record.controlIds.includes(control.id)).map(controlSummary),
          requirements: data.requirements.filter((requirement) => record.requirementIds.includes(requirement.id)),
          frameworks: data.frameworks.filter((framework) => record.frameworkIds.includes(framework.id)),
          asset: record.assetId ? data.assets.find((asset) => asset.assetId === record.assetId) ?? null : null,
          auditEvents: data.auditEvents.filter((event) => event.evidenceId === id).slice(0, 20),
        },
      })
    } catch (error) {
      fail(res, error, 'failed to load evidence detail')
    }
  })

  /**
   * POST /evidence/anchor — writes the SHA3-256 content digest of the selected
   * evidence so later modification of the source row becomes detectable.
   *
   * Anchoring is an explicit governance ACT, not a background side effect: the
   * user is asserting "this is the evidence as of now". Re-anchoring a changed
   * record keeps the original digest (enforced by a database trigger) and
   * increments a re-anchor counter, so a change can never be quietly erased.
   */
  router.post('/evidence/anchor', async (req: AuthedRequest, res: Response) => {
    try {
      const client = createAuthClient(req.token!)
      if (!client) throw new Error('Database connection failed')
      const data = await model(req)

      const requested = Array.isArray(req.body?.evidenceIds) ? (req.body.evidenceIds as unknown[]).map((id) => str(id)).filter(Boolean) : []
      const scope = str(req.body?.scope)
      // Bounded: anchoring is a write per record, so a single request never
      // fans out beyond a page-sized batch.
      const MAX_BATCH = 500
      const targets = (requested.length
        ? data.evidence.filter((record) => requested.includes(record.id))
        : scope === 'unanchored'
          ? data.evidence.filter((record) => record.integrity.state === 'unanchored')
          : data.evidence
      ).slice(0, MAX_BATCH)

      if (!targets.length) {
        return res.json({ data: { anchored: 0, reanchored: 0, message: 'Nothing to anchor.' } })
      }

      const rows = targets.map((record) => ({
        user_id: req.user!.id,
        evidence_id: record.id,
        evidence_kind: record.kind,
        source_table: record.source.table,
        source_record_id: record.source.recordId,
        algorithm: 'SHA3-256',
        digest: record.integrity.digest,
        first_digest: record.integrity.digest,
        anchored_by: str(req.user!.email) || 'tenant user',
      }))

      const { error } = await client.from('governance_evidence_anchors').upsert(rows, { onConflict: 'user_id,evidence_id' })
      if (error) {
        if (/relation .* does not exist|42P01/i.test(error.message || '')) {
          return res.status(503).json({
            error: {
              code: 'ANCHOR_STORE_UNAVAILABLE',
              message: 'The evidence anchor store is not available. Apply supabase/governance-schema.sql to enable tamper-evident anchoring.',
            },
          })
        }
        throw error
      }

      const alreadyAnchored = targets.filter((record) => record.integrity.state !== 'unanchored').length
      invalidateGovernanceModel(req.user!.id)
      res.json({
        data: {
          anchored: targets.length - alreadyAnchored,
          reanchored: alreadyAnchored,
          total: targets.length,
          message: `${targets.length} evidence record(s) anchored with a SHA3-256 content digest. Later modification of the source record will now be detectable.`,
        },
      })
    } catch (error) {
      fail(res, error, 'failed to anchor evidence')
    }
  })

  /**
   * POST /evidence/verify — recomputes the digest for one record and reports the
   * comparison against its anchor. Separate from the model read so a user can
   * demand a fresh verification rather than trusting a cached one.
   */
  router.post('/evidence/verify', async (req: AuthedRequest, res: Response) => {
    try {
      const client = createAuthClient(req.token!)
      if (!client) throw new Error('Database connection failed')
      const id = str(req.body?.evidenceId)
      if (!id) return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'evidenceId is required' } })

      const data = await buildGovernanceModel(req.token!, req.user!.id, true)
      const record = data.evidence.find((candidate) => candidate.id === id)
      if (!record) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Evidence record not found' } })

      const { data: anchorRows, error } = await client
        .from('governance_evidence_anchors')
        .select('digest, first_digest, anchored_at, reanchored_at, reanchor_count')
        .eq('user_id', req.user!.id)
        .eq('evidence_id', id)
        .limit(1)
      if (error && !/42P01/.test(error.code || '')) throw error

      const anchor = (anchorRows || [])[0] as Row | undefined
      res.json({
        data: {
          evidenceId: id,
          recomputedDigest: record.integrity.digest,
          anchoredDigest: anchor ? str(anchor.digest) : null,
          firstDigest: anchor ? str(anchor.first_digest) : null,
          anchoredAt: anchor ? str(anchor.anchored_at) : null,
          reanchorCount: anchor ? num(anchor.reanchor_count) : 0,
          state: record.integrity.state,
          assurance: record.integrity.assurance,
          verifiedAt: new Date().toISOString(),
        },
      })
    } catch (error) {
      fail(res, error, 'failed to verify evidence')
    }
  })

  /* ---- Audit events ------------------------------------------------ */
  router.get('/audit-events', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const page = paginate(filterAuditEvents(data.auditEvents, req), req)
      res.json({ data: { auditEvents: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      fail(res, error, 'failed to load audit events')
    }
  })

  router.get('/audit-events/:id', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const id = decodeURIComponent(str(req.params.id))
      const event = data.auditEvents.find((candidate) => candidate.id === id)
      if (!event) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Audit event not found' } })
      res.json({
        data: {
          event,
          evidence: event.evidenceId ? data.evidence.find((record) => record.id === event.evidenceId) ?? null : null,
          controls: data.controls.filter((control) => event.controlIds.includes(control.id)).map(controlSummary),
          asset: event.assetId ? data.assets.find((asset) => asset.assetId === event.assetId) ?? null : null,
          related: data.auditEvents
            .filter((candidate) => candidate.id !== id && (candidate.assetId === event.assetId || candidate.source.table === event.source.table))
            .slice(0, 12),
        },
      })
    } catch (error) {
      fail(res, error, 'failed to load audit event detail')
    }
  })

  /* ---- Policies ---------------------------------------------------- */
  router.get('/policies', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const search = active(req.query.search)
      const category = active(req.query.category)
      const enforcement = active(req.query.enforcement)
      const filtered = data.policies.filter((policy) => {
        if (category && policy.category !== category) return false
        if (enforcement && policy.enforcement !== enforcement) return false
        return matchesSearch(`${policy.title} ${policy.rationale} ${policy.standard}`, search)
      })
      const page = paginate(filtered, req)
      res.json({ data: { policies: page.rows, total: page.total, limit: page.limit, offset: page.offset, storeAvailable: data.telemetry.policyStoreAvailable } })
    } catch (error) {
      fail(res, error, 'failed to load policies')
    }
  })

  /** Every violation for one policy rule — the full list, paged. */
  router.get('/policies/:id/violations', async (req: AuthedRequest, res: Response) => {
    try {
      const context = await evaluationInputsFor(req.token!, req.user!.id)
      if (!context) return res.status(503).json({ error: { code: 'MODEL_UNAVAILABLE', message: 'Governance model is rebuilding; retry shortly' } })
      const id = str(req.params.id)
      const search = active(req.query.search)
      const severity = active(req.query.severity)
      const violations = allViolationsFor(id, context.policyContext, context.raw.policyOverrides)
        .filter((item) => (!severity || item.severity === severity) && matchesSearch(`${item.subject} ${item.observed} ${item.detail}`, search))
        .sort((a, b) => severityOrder(b.severity) - severityOrder(a.severity))
      const page = paginate(violations, req)
      res.json({ data: { violations: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      fail(res, error, 'failed to load policy violations')
    }
  })

  /**
   * PATCH /policies/:id — persists a tenant override for one policy rule.
   *
   * Only enforcement, severity and the rule's OWN declared parameters can be
   * changed; unknown keys are dropped by the evaluator. The write is
   * tenant-scoped through the caller's RLS client and recorded in the audit log.
   */
  router.patch('/policies/:id', async (req: AuthedRequest, res: Response) => {
    try {
      const client = createAuthClient(req.token!)
      if (!client) throw new Error('Database connection failed')
      const id = str(req.params.id)
      const data = await model(req)
      const policy = data.policies.find((candidate) => candidate.id === id)
      if (!policy) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Policy rule not found' } })

      const enforcement = str(req.body?.enforcement)
      const severity = str(req.body?.severity)
      if (enforcement && !['enforced', 'monitored', 'disabled'].includes(enforcement)) {
        return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'enforcement must be enforced, monitored or disabled' } })
      }
      if (severity && !['critical', 'high', 'medium', 'low'].includes(severity)) {
        return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'severity must be critical, high, medium or low' } })
      }

      // Accept only parameters this rule declares, coerced to the declared type.
      const declared = new Map(policy.parameters.map((parameter) => [parameter.key, parameter]))
      const incoming = (req.body?.parameters && typeof req.body.parameters === 'object' ? req.body.parameters : {}) as Record<string, unknown>
      const parameters: Record<string, unknown> = {}
      for (const [key, value] of Object.entries(incoming)) {
        const parameter = declared.get(key)
        if (!parameter) continue
        if (parameter.type === 'number' && Number.isFinite(Number(value))) parameters[key] = Number(value)
        else if (parameter.type === 'boolean' && typeof value === 'boolean') parameters[key] = value
        else if (parameter.type === 'string-list' && Array.isArray(value)) parameters[key] = value.map((entry) => str(entry)).filter(Boolean)
      }

      const { error } = await client.from('governance_policies').upsert(
        {
          user_id: req.user!.id,
          policy_id: id,
          enforcement: enforcement || policy.enforcement,
          severity: severity || policy.severity,
          parameters: Object.keys(parameters).length
            ? { ...Object.fromEntries(policy.parameters.map((parameter) => [parameter.key, parameter.value])), ...parameters }
            : Object.fromEntries(policy.parameters.map((parameter) => [parameter.key, parameter.value])),
          note: str(req.body?.note),
          updated_by: str(req.user!.email) || 'tenant user',
        },
        { onConflict: 'user_id,policy_id' },
      )
      if (error) {
        if (/relation .* does not exist|42P01/i.test(error.message || '')) {
          return res.status(503).json({
            error: {
              code: 'POLICY_STORE_UNAVAILABLE',
              message: 'The governance policy store is not available. Apply supabase/governance-schema.sql to enable tenant policy overrides.',
            },
          })
        }
        throw error
      }

      // Governance changes are themselves auditable (§7 "Policy changes").
      await client.from('audit_logs').insert({
        user_id: req.user!.id,
        action: 'governance_policy_updated',
        entity_type: 'governance_policy',
        entity_id: null,
        details: { policyId: id, enforcement: enforcement || policy.enforcement, severity: severity || policy.severity, parameters },
      }).then(
        () => undefined,
        (auditError: unknown) => console.warn('[governance] policy audit write skipped:', auditError),
      )

      invalidateGovernanceModel(req.user!.id)
      const refreshed = await buildGovernanceModel(req.token!, req.user!.id, true)
      res.json({ data: { policy: refreshed.policies.find((candidate) => candidate.id === id) ?? null } })
    } catch (error) {
      fail(res, error, 'failed to update policy rule')
    }
  })

  /* ---- Control assessment (owner / exception) ----------------------- */
  router.patch('/controls/:id/assessment', async (req: AuthedRequest, res: Response) => {
    try {
      const client = createAuthClient(req.token!)
      if (!client) throw new Error('Database connection failed')
      const id = str(req.params.id)
      if (!CONTROL_BY_ID.has(id)) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Control not found' } })

      const exceptionReason = str(req.body?.exceptionReason)
      const exceptionApprovedBy = str(req.body?.exceptionApprovedBy)
      const exceptionExpiresAt = str(req.body?.exceptionExpiresAt)
      // An exception scopes a control OUT of the compliance score, so it may not
      // be recorded without an approver and an expiry. This is the guard that
      // stops "not applicable" from becoming a way to hide a failing control.
      if (exceptionReason && (!exceptionApprovedBy || !exceptionExpiresAt)) {
        return res.status(400).json({
          error: {
            code: 'EXCEPTION_REQUIRES_APPROVAL',
            message: 'A control exception must record both an approver and an expiry date.',
          },
        })
      }
      if (exceptionExpiresAt && !Number.isFinite(Date.parse(exceptionExpiresAt))) {
        return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'exceptionExpiresAt must be a valid date' } })
      }

      const { error } = await client.from('governance_control_assessments').upsert(
        {
          user_id: req.user!.id,
          control_id: id,
          owner: str(req.body?.owner),
          owner_email: str(req.body?.ownerEmail),
          review_note: str(req.body?.reviewNote),
          attested_at: req.body?.attest === true ? new Date().toISOString() : null,
          attested_by: req.body?.attest === true ? str(req.user!.email) || 'tenant user' : '',
          exception_reason: exceptionReason,
          exception_approved_by: exceptionApprovedBy,
          exception_approved_at: exceptionReason ? new Date().toISOString() : null,
          exception_expires_at: exceptionExpiresAt || null,
        },
        { onConflict: 'user_id,control_id' },
      )
      if (error) {
        if (/relation .* does not exist|42P01/i.test(error.message || '')) {
          return res.status(503).json({
            error: {
              code: 'ASSESSMENT_STORE_UNAVAILABLE',
              message: 'The control assessment store is not available. Apply supabase/governance-schema.sql to enable ownership and exceptions.',
            },
          })
        }
        throw error
      }

      await client.from('audit_logs').insert({
        user_id: req.user!.id,
        action: exceptionReason ? 'governance_control_exception_recorded' : 'governance_control_assessment_updated',
        entity_type: 'governance_control',
        entity_id: null,
        details: { controlId: id, owner: str(req.body?.owner), exceptionReason, exceptionApprovedBy, exceptionExpiresAt },
      }).then(
        () => undefined,
        (auditError: unknown) => console.warn('[governance] assessment audit write skipped:', auditError),
      )

      invalidateGovernanceModel(req.user!.id)
      const refreshed = await buildGovernanceModel(req.token!, req.user!.id, true)
      res.json({ data: { control: refreshed.controls.find((candidate) => candidate.id === id) ?? null } })
    } catch (error) {
      fail(res, error, 'failed to update control assessment')
    }
  })

  /* ---- Gaps, assets, reconciliation --------------------------------- */
  router.get('/gaps', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const page = paginate(filterGaps(data.gaps, req), req)
      res.json({ data: { gaps: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      fail(res, error, 'failed to load gaps')
    }
  })

  router.get('/assets', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const page = paginate(filterAssets(data.assets, req), req)
      res.json({ data: { assets: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      fail(res, error, 'failed to load asset compliance')
    }
  })

  router.get('/assets/:id', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const id = str(req.params.id)
      const asset = data.assets.find((candidate) => candidate.assetId === id)
      if (!asset) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Asset not found' } })
      res.json({
        data: {
          asset,
          failingControls: data.controls.filter((control) => asset.failingControlIds.includes(control.id)).map(controlSummary),
          evidence: data.evidence.filter((record) => record.assetId === id).slice(0, 60),
          auditEvents: data.auditEvents.filter((event) => event.assetId === id).slice(0, 30),
          gaps: data.gaps.filter((gap) => gap.assetIds.includes(id)),
        },
      })
    } catch (error) {
      fail(res, error, 'failed to load asset compliance detail')
    }
  })

  /** §16: the reconciliation report, on its own route for the drawer. */
  router.get('/reconciliation', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      res.json({ data: data.reconciliation })
    } catch (error) {
      fail(res, error, 'failed to load reconciliation report')
    }
  })

  router.post('/invalidate', (req: AuthedRequest, res: Response) => {
    invalidateGovernanceModel(req.user!.id)
    res.json({ data: { invalidated: true } })
  })

  return router
}

export const complianceRoutes = buildRouter('compliance')
export const quantumGovernanceRoutes = buildRouter('quantum')
export const auditVaultRoutes = buildRouter('audit')
export const regulatoryMappingRoutes = buildRouter('regulatory')

export { contentDigest }
