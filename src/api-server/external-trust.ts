import { Router, Request, Response, NextFunction } from 'express'
import { payloadFingerprint, streamLiveSnapshot } from './live-snapshot-stream'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import {
  buildExternalTrustIntelligence,
  computeDependencyChain,
  computeEcosystemBlastRadius,
  recommendConfiguration,
  toExperimentRecord,
  validateExperimentConfiguration,
  type EcosystemNode,
  type ExperimentCheck,
  type ExperimentConfiguration,
  type ExperimentFinding,
  type ExperimentOutcome,
  type ExperimentTarget,
  type ExecutionMode,
  type ExternalTrustInputs,
  type ExternalTrustIntelligence,
  type RiskLevel,
} from '@/lib/ecosystem/external-trust-intelligence'
import type { Row } from '@/lib/migration/asset-intelligence'
import { checkHostSyntax, verifyPublicHost } from '@/lib/scanner/public-scan/safe-dns'
import { runTlsEngine } from '@/lib/scanner/public-scan/engines/tls-engine'
import { runCertificateEngine } from '@/lib/scanner/public-scan/engines/certificate-engine'

/**
 * QGuard Helix — External Trust & Ecosystem Suite API.
 *
 * Serves FOUR pages from ONE cached computation so they cannot disagree:
 *
 *   GET /vendors    → Vendor PQC Readiness
 *   GET /ecosystem  → Ecosystem Dependency Map
 *   GET /trust      → Trust Chain Analyzer
 *   GET /lab        → Hybrid Crypto Lab
 *
 * Write paths:
 *   POST  /vendors/:vendorId/evidence-requests
 *   PATCH /evidence-requests/:id
 *   POST  /lab/experiments               (runs a REAL read-only TLS/cert probe)
 *   POST  /lab/experiments/:id/evidence
 *
 * Safety model for the lab (§53):
 *   - `simulation`      projects over stored evidence and opens no connection.
 *   - `controlled-test` performs a READ-ONLY TLS handshake probe, behind the
 *     same SSRF guard the public scanner uses (private/loopback/reserved
 *     addresses are refused).
 *   - Nothing here mutates a production system, ever.
 */

const router = Router()

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

function tokenFromRequest(req: Request): string | null {
  const headerToken = getToken(req)
  if (headerToken) return headerToken
  // Legacy EventSource clients still use this exact endpoint.
  if (req.path !== '/stream') return null
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

const str = (value: unknown) => (typeof value === 'string' ? value : value == null ? '' : String(value))
const num = (value: unknown) => { const parsed = Number(value); return Number.isFinite(parsed) ? parsed : 0 }

/**
 * Tenant-scoped read that degrades to an empty set instead of failing the page.
 *
 * A selected column that does not exist makes PostgREST reject the WHOLE query
 * (42703), which would otherwise surface as "no evidence" — a wrong answer that
 * looks like a valid one. That class of bug is called out explicitly here so it
 * is visible in the logs rather than silently swallowed.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function safeRows(client: any, table: string, build: (query: any) => any): Promise<Row[]> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      const code = String((error as { code?: string }).code || '')
      if (code === '42703') {
        console.error(
          `External trust ${table} query selected a column that does not exist (42703): ${error.message}. ` +
          'The whole query was rejected — this table will read as EMPTY until the select list is corrected.',
        )
      } else {
        console.warn(`External trust ${table} query skipped:`, error.message || error)
      }
      return []
    }
    return (data as Row[]) || []
  } catch (error) {
    console.warn(`External trust ${table} query failed:`, (error as Error)?.message || error)
    return []
  }
}

/**
 * Probes whether an optional table exists.
 *
 * Uses a REAL select, not a HEAD/count probe: with `head: true` a missing table
 * does not reliably surface an error through the client, which previously made
 * an unapplied schema report as "available" and the write path fail later with
 * an opaque 500.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function tableAvailable(client: any, table: string): Promise<boolean> {
  try {
    const { error } = await client.from(table).select('id').limit(1)
    if (!error) return true
    const code = String((error as { code?: string }).code || '')
    // PGRST205 = unknown table in the schema cache; 42P01 = undefined_table.
    if (code === 'PGRST205' || code === '42P01') return false
    // Any other error (e.g. RLS) still means the table exists.
    return true
  } catch {
    return false
  }
}

/* ------------------------------------------------------------------ */
/* Shared single-flight cache                                          */
/* ------------------------------------------------------------------ */

interface CachedTrust {
  intelligence: ExternalTrustIntelligence
  migrationJobAssetIds: Set<string>
  persistence: { evidenceRequests: boolean; experiments: boolean }
}

const TTL_MS = 15_000
const cache = new Map<string, { at: number; promise: Promise<CachedTrust> }>()

async function compute(token: string, userId: string): Promise<CachedTrust> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [evidenceRequestsAvailable, experimentsAvailable] = await Promise.all([
    tableAvailable(client, 'vendor_evidence_requests'),
    tableAvailable(client, 'hybrid_crypto_experiments'),
  ])

  const [
    assets, assetRelationships, certificates, cryptoInventory, cryptoExposures,
    scanResults, scannerEvidence, scannerAlerts, runtimeEvents, connectorAccounts,
    vendorAssessments, trustFindings, migrationJobs, complianceEvidence,
    evidenceRequests, experiments,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) => q.select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1500)),
    safeRows(client, 'asset_relationships', (q) => q.select('*').eq('user_id', userId).limit(3000)),
    // NOTE: `certificates` has no `signature_algorithm` column. Selecting one
    // made PostgREST reject the entire query, so every trust chain read as
    // absent on a tenant that actually holds 31 certificates. The signature
    // algorithm is derived from `algorithm`/metadata by the engine instead.
    safeRows(client, 'certificates', (q) => q.select('id, asset_id, name, subject, algorithm, key_size, issuer, serial_number, not_before, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(1500)),
    safeRows(client, 'crypto_inventory', (q) => q.select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(2500)),
    safeRows(client, 'crypto_exposures', (q) => q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2000)),
    safeRows(client, 'pqc_scan_results', (q) => q.select('id, asset_id, finding_type, algorithm, threat_level, description, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2000)),
    safeRows(client, 'scanner_evidence', (q) => q.select('id, source_type, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, key_size, package_name, confidence, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(2500)),
    safeRows(client, 'scanner_alerts', (q) => q.select('id, severity, category, title, message, recommendation, status, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1200)),
    safeRows(client, 'runtime_crypto_events', (q) => q.select('id, asset_id, asset_name, host, port, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, severity, is_pqc, is_legacy, hndl_risk, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(3000)),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, provider_account_id, display_name, status, last_sync_at, metadata, created_at, updated_at').eq('user_id', userId).limit(500)),
    safeRows(client, 'vendor_assessments', (q) => q.select('id, vendor_name, category, readiness_status, score, support, exposure_summary, contract_status, timeline, questionnaire_status, evidence, metadata, last_assessed_at, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(600)),
    safeRows(client, 'trust_state_findings', (q) => q.select('id, asset_id, category, severity, title, detail, gate_impact, status, owner, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(800)),
    safeRows(client, 'migration_jobs', (q) => q.select('id, asset_id, status, job_type, target_algorithm, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    safeRows(client, 'compliance_evidence', (q) => q.select('id, asset_id, framework, control_id, status, evidence_type, description, metadata, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(800)),
    evidenceRequestsAvailable
      ? safeRows(client, 'vendor_evidence_requests', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(600))
      : Promise.resolve([] as Row[]),
    experimentsAvailable
      ? safeRows(client, 'hybrid_crypto_experiments', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(300))
      : Promise.resolve([] as Row[]),
  ])

  const inputs: ExternalTrustInputs = {
    assets, assetRelationships, certificates, cryptoInventory, cryptoExposures,
    scanResults, scannerEvidence, scannerAlerts, runtimeEvents, connectorAccounts,
    vendorAssessments, trustFindings, migrationJobs, complianceEvidence,
    evidenceRequests, experiments,
  }

  const intelligence = buildExternalTrustIntelligence(inputs)
  intelligence.vendors.persistenceAvailable = evidenceRequestsAvailable
  intelligence.lab.persistenceAvailable = experimentsAvailable

  return {
    intelligence,
    migrationJobAssetIds: new Set(migrationJobs.map((job) => str(job.asset_id)).filter(Boolean)),
    persistence: { evidenceRequests: evidenceRequestsAvailable, experiments: experimentsAvailable },
  }
}

export async function buildExternalTrust(token: string, userId: string, force = false): Promise<CachedTrust> {
  const cached = cache.get(userId)
  if (!force && cached && Date.now() - cached.at < TTL_MS) return cached.promise
  const promise = compute(token, userId)
  cache.set(userId, { at: Date.now(), promise })
  promise.catch(() => cache.delete(userId))
  if (cache.size > 500) {
    const now = Date.now()
    for (const [key, value] of cache) if (now - value.at > TTL_MS) cache.delete(key)
  }
  return promise
}

function invalidate(userId: string) {
  cache.delete(userId)
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * Records a privileged action in the tenant's audit trail (§69). Never fatal.
 *
 * Uses the real `audit_logs` shape (action / entity_type / entity_id / details).
 * `entity_id` is a UUID column, so slug identifiers (vendor ids) are carried in
 * `details` rather than coerced into a column that would reject them.
 */
async function audit(
  token: string, userId: string, email: string | null | undefined,
  action: string, entityType: string, entityId: string,
  result: 'success' | 'failure', detail: Record<string, unknown>,
) {
  try {
    const client = createAuthClient(token)
    if (!client) return
    await client.from('audit_logs').insert({
      user_id: userId,
      action,
      entity_type: entityType,
      entity_id: UUID_RE.test(entityId) ? entityId : null,
      // Never record credentials or evidence bodies — metadata only.
      details: { ...detail, entityRef: entityId, actor: email || userId, result, module: 'external-trust' },
    })
  } catch (error) {
    console.warn('External trust audit write skipped:', (error as Error)?.message || error)
  }
}

/* ================================================================== */
/* Read routes                                                         */
/* ================================================================== */

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const { intelligence } = await buildExternalTrust(token!, user!.id, str(req.query.refresh) === '1')
    res.json({ data: intelligence })
  } catch (error) {
    console.error('External trust aggregation error:', error)
    res.status(500).json({ error: { code: 'EXTERNAL_TRUST_ERROR', message: 'Failed to compute external trust intelligence' } })
  }
})

/** Shared envelope so every page renders the same provenance footer. */
function envelope(intelligence: ExternalTrustIntelligence) {
  return {
    generatedAt: intelligence.generatedAt,
    hasData: intelligence.hasData,
    evidence: intelligence.evidence,
  }
}

router.get('/vendors', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const { intelligence } = await buildExternalTrust(token!, user!.id)
    const vendors = intelligence.vendors

    const search = str(req.query.search).trim().toLowerCase()
    const readiness = str(req.query.readiness).trim().toLowerCase()
    const risk = str(req.query.risk).trim().toLowerCase()
    const evidence = str(req.query.evidence).trim().toLowerCase()
    const owner = str(req.query.owner).trim().toLowerCase()
    const criticality = str(req.query.criticality).trim().toLowerCase()
    const support = str(req.query.support).trim().toLowerCase()

    let records = vendors.records
    if (search) {
      records = records.filter((vendor) =>
        `${vendor.name} ${vendor.category} ${vendor.services.join(' ')} ${vendor.businessOwner} ${vendor.observedHosts.join(' ')}`.toLowerCase().includes(search))
    }
    if (readiness && readiness !== 'all') records = records.filter((vendor) => vendor.readiness === readiness)
    if (risk && risk !== 'all') records = records.filter((vendor) => vendor.risk === risk)
    if (evidence && evidence !== 'all') records = records.filter((vendor) => vendor.evidenceState === evidence)
    if (owner && owner !== 'all') records = records.filter((vendor) => vendor.businessOwner.toLowerCase() === owner)
    if (criticality && criticality !== 'all') records = records.filter((vendor) => vendor.criticality === criticality)
    if (support && support !== 'all') records = records.filter((vendor) => vendor.migrationSupport === support)

    const limit = Math.max(1, Math.min(500, num(req.query.limit) || 200))
    const offset = Math.max(0, num(req.query.offset))

    res.json({
      data: {
        ...envelope(intelligence),
        records: records.slice(offset, offset + limit),
        total: records.length,
        totalUnfiltered: vendors.records.length,
        summary: vendors.summary,
        distribution: vendors.distribution,
        evidenceRequests: vendors.evidenceRequests,
        persistenceAvailable: vendors.persistenceAvailable,
        filters: {
          owners: [...new Set(vendors.records.map((vendor) => vendor.businessOwner))].sort(),
          categories: [...new Set(vendors.records.map((vendor) => vendor.category))].sort(),
        },
      },
    })
  } catch (error) {
    console.error('External trust vendor feed error:', error)
    res.status(500).json({ error: { code: 'VENDOR_FEED_ERROR', message: 'Failed to load vendor readiness' } })
  }
})

router.get('/ecosystem', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const { intelligence, migrationJobAssetIds } = await buildExternalTrust(token!, user!.id)
    const ecosystem = intelligence.ecosystem

    const focus = str(req.query.focus).trim()
    const blastRadius = focus
      ? computeEcosystemBlastRadius(ecosystem.nodes, ecosystem.edges, focus, migrationJobAssetIds)
      : null
    const chain = focus ? computeDependencyChain(ecosystem.nodes, ecosystem.edges, focus) : []

    res.json({
      data: {
        ...envelope(intelligence),
        ...ecosystem,
        focus: focus || null,
        blastRadius,
        dependencyChain: chain,
      },
    })
  } catch (error) {
    console.error('External trust ecosystem error:', error)
    res.status(500).json({ error: { code: 'ECOSYSTEM_ERROR', message: 'Failed to load the ecosystem dependency map' } })
  }
})

async function trustChainsSnapshot(req: AuthedRequest, force = false) {
  const { intelligence } = await buildExternalTrust(req.token!, req.user!.id, force)
  return { ...envelope(intelligence), ...intelligence.trust }
}

router.get('/trust', async (req: Request, res: Response) => {
  try {
    const data = await trustChainsSnapshot(req as AuthedRequest, str(req.query.refresh) === '1')
    res.json({ data: { ...data, fingerprint: payloadFingerprint(data) } })
  } catch (error) {
    console.error('External trust chain error:', error)
    res.status(500).json({ error: { code: 'TRUST_ERROR', message: 'Failed to load trust chains' } })
  }
})

router.get('/trust/stream', (req: Request, res: Response) => {
  streamLiveSnapshot(req, res, {
    event: 'trust-chains',
    intervalMs: 10_000,
    build: () => trustChainsSnapshot(req as AuthedRequest),
  })
})

router.get('/lab', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const { intelligence } = await buildExternalTrust(token!, user!.id)
    res.json({ data: { ...envelope(intelligence), ...intelligence.lab } })
  } catch (error) {
    console.error('External trust lab error:', error)
    res.status(500).json({ error: { code: 'LAB_ERROR', message: 'Failed to load the hybrid crypto lab' } })
  }
})

/** SSE — one cached computation shared by every connected client of a tenant. */
router.get('/stream', async (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
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

  send('connected', { at: new Date().toISOString() })

  const push = async () => {
    try {
      const { intelligence } = await buildExternalTrust(token!, user!.id)
      send('external-trust-update', intelligence)
    } catch (error) {
      send('external-trust-error', { message: error instanceof Error ? error.message : 'Snapshot unavailable' })
    }
  }

  void push()
  const interval = setInterval(() => void push(), 20_000)
  const heartbeat = setInterval(() => { if (!closed) res.write(': heartbeat\n\n') }, 25_000)

  req.on('close', () => {
    closed = true
    clearInterval(interval)
    clearInterval(heartbeat)
  })
})

/* ================================================================== */
/* Evidence request workflow                                           */
/* ================================================================== */

const VALID_REQUEST_TYPES = new Set([
  'pqc-roadmap', 'algorithm-support-matrix', 'tls-pqc-statement', 'certificate-roadmap',
  'key-management-roadmap', 'crypto-architecture', 'migration-timeline',
  'product-version-support', 'security-compliance-docs',
])
const VALID_STAGES = new Set(['requested', 'vendor-responded', 'evidence-received', 'under-review', 'accepted', 'rejected'])

router.post('/vendors/:vendorId/evidence-requests', async (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  const vendorId = str(req.params.vendorId)
  try {
    const { intelligence, persistence } = await buildExternalTrust(token!, user!.id)
    if (!persistence.evidenceRequests) {
      return res.status(503).json({
        error: {
          code: 'PERSISTENCE_UNAVAILABLE',
          message: 'The evidence request workflow requires supabase/external-trust-schema.sql to be applied to this project.',
        },
      })
    }

    const vendor = intelligence.vendors.records.find((record) => record.id === vendorId)
    if (!vendor) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Vendor not found for this tenant' } })
    }

    const requestType = str(req.body?.requestType)
    if (!VALID_REQUEST_TYPES.has(requestType)) {
      return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: `Unsupported request type. Supported: ${[...VALID_REQUEST_TYPES].join(', ')}` } })
    }

    const dueAt = str(req.body?.dueAt)
    if (dueAt && !Number.isFinite(new Date(dueAt).getTime())) {
      return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'dueAt must be a valid ISO date' } })
    }

    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

    const { data, error } = await client
      .from('vendor_evidence_requests')
      .insert({
        user_id: user!.id,
        vendor_id: vendor.id,
        vendor_name: vendor.name,
        request_type: requestType,
        stage: 'requested',
        owner: str(req.body?.owner) || user!.email || 'Unassigned',
        due_at: dueAt || null,
        notes: str(req.body?.notes).slice(0, 2000) || null,
      })
      .select('*')
      .single()

    if (error) {
      await audit(token!, user!.id, user!.email, 'vendor.evidence_request.create', 'vendor', vendor.id, 'failure', { requestType, error: error.message })
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Failed to record the evidence request' } })
    }

    await audit(token!, user!.id, user!.email, 'vendor.evidence_request.create', 'vendor', vendor.id, 'success', { requestType, requestId: str(data?.id), dueAt: dueAt || null })
    invalidate(user!.id)
    res.status(201).json({ data })
  } catch (error) {
    console.error('Evidence request creation error:', error)
    res.status(500).json({ error: { code: 'EVIDENCE_REQUEST_ERROR', message: 'Failed to create the evidence request' } })
  }
})

router.patch('/evidence-requests/:id', async (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  const id = str(req.params.id)
  try {
    const stage = str(req.body?.stage)
    if (stage && !VALID_STAGES.has(stage)) {
      return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: `Unsupported stage. Supported: ${[...VALID_STAGES].join(', ')}` } })
    }

    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

    const patch: Record<string, unknown> = { updated_at: new Date().toISOString() }
    if (stage) {
      patch.stage = stage
      if (stage === 'vendor-responded' || stage === 'evidence-received') patch.responded_at = new Date().toISOString()
      if (stage === 'accepted' || stage === 'rejected') {
        patch.reviewed_at = new Date().toISOString()
        patch.reviewer = str(req.body?.reviewer) || user!.email || 'Unassigned'
      }
    }
    if (req.body?.responseSummary !== undefined) patch.response_summary = str(req.body.responseSummary).slice(0, 4000)
    if (req.body?.evidenceRef !== undefined) patch.evidence_ref = str(req.body.evidenceRef).slice(0, 1000)
    if (req.body?.notes !== undefined) patch.notes = str(req.body.notes).slice(0, 2000)
    if (req.body?.owner !== undefined) patch.owner = str(req.body.owner).slice(0, 255)

    // RLS scopes the row to the caller; the explicit user_id match is belt and braces.
    const { data, error } = await client
      .from('vendor_evidence_requests')
      .update(patch)
      .eq('id', id)
      .eq('user_id', user!.id)
      .select('*')
      .maybeSingle()

    if (error) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Failed to update the evidence request' } })
    if (!data) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Evidence request not found for this tenant' } })

    await audit(token!, user!.id, user!.email, 'vendor.evidence_request.update', 'evidence_request', id, 'success', { stage: stage || 'unchanged' })
    invalidate(user!.id)
    res.json({ data })
  } catch (error) {
    console.error('Evidence request update error:', error)
    res.status(500).json({ error: { code: 'EVIDENCE_REQUEST_ERROR', message: 'Failed to update the evidence request' } })
  }
})

/* ================================================================== */
/* Hybrid Crypto Lab                                                   */
/* ================================================================== */

interface ProbeOutcome {
  measured: boolean
  negotiatedProtocol: string | null
  supportedProtocols: string[]
  legacyProtocols: string[]
  hybridGroups: string[]
  pureKemGroups: string[]
  hybridProbed: boolean
  untestableGroups: string[]
  forwardSecrecy: boolean
  certificateAlgorithm: string | null
  certificateIssuer: string | null
  certificateDaysToExpiry: number | null
  chainLength: number
  error: string | null
}

/** READ-ONLY live probe. Opens a TLS handshake; never sends application data. */
async function probeTarget(host: string, port: number): Promise<ProbeOutcome> {
  const empty: ProbeOutcome = {
    measured: false, negotiatedProtocol: null, supportedProtocols: [], legacyProtocols: [],
    hybridGroups: [], pureKemGroups: [], hybridProbed: false, untestableGroups: [],
    forwardSecrecy: false, certificateAlgorithm: null, certificateIssuer: null,
    certificateDaysToExpiry: null, chainLength: 0, error: null,
  }

  const syntax = checkHostSyntax(host)
  if (!syntax.ok) return { ...empty, error: syntax.message || 'Target host is not permitted.' }
  const verdict = await verifyPublicHost(host)
  if (!verdict.ok) return { ...empty, error: verdict.message || 'Target host resolved to a non-public address.' }

  try {
    const [tls, certificate] = await Promise.all([
      runTlsEngine(host, port),
      runCertificateEngine(host, port),
    ])
    const tlsData = tls.data
    const certData = certificate.data
    const notAfter = certData.validTo ? new Date(certData.validTo).getTime() : null
    return {
      measured: Boolean(tlsData.handshake),
      negotiatedProtocol: tlsData.negotiatedProtocol,
      supportedProtocols: tlsData.supportedProtocols || [],
      legacyProtocols: tlsData.legacyProtocols || [],
      hybridGroups: tlsData.hybridGroups || [],
      pureKemGroups: tlsData.pureKemGroups || [],
      hybridProbed: Boolean(tlsData.hybridProbed),
      untestableGroups: tlsData.untestableGroups || [],
      forwardSecrecy: Boolean(tlsData.forwardSecrecy),
      certificateAlgorithm: certData.publicKeyAlgorithm || certData.signatureAlgorithm || null,
      certificateIssuer: certData.issuerCommonName || certData.issuerOrganization || null,
      certificateDaysToExpiry: notAfter ? Math.round((notAfter - Date.now()) / 86400000) : null,
      chainLength: certData.chainDepth || (Array.isArray(certData.chain) ? certData.chain.length : 0),
      error: tlsData.error,
    }
  } catch (error) {
    return { ...empty, error: error instanceof Error ? error.message : 'Probe failed' }
  }
}

/**
 * Turns a probe (or the absence of one) into per-dimension verdicts.
 *
 * `method` is carried on every check so the UI can distinguish a MEASURED pass
 * from an evidence-derived inference — the two must never look identical.
 */
function evaluateExperiment(
  proposed: ExperimentConfiguration,
  probe: ProbeOutcome | null,
  context: {
    target: ExperimentTarget
    vendorReadiness: string | null
    vendorName: string | null
    storedAlgorithms: string[]
    storedProtocols: string[]
    certificateIssuer: string | null
    certificateQuantumSafe: boolean | null
  },
): { checks: ExperimentCheck[]; findings: ExperimentFinding[]; outcome: ExperimentOutcome; risk: RiskLevel } {
  const checks: ExperimentCheck[] = []
  const findings: ExperimentFinding[] = []

  const addFinding = (
    id: string, title: string, severity: RiskLevel, component: string,
    evidence: string, likelyCause: string, action: string, route: string, deps: string[] = [],
  ) => findings.push({ id, title, severity, component, evidence, likelyCause, affectedDependencies: deps, recommendedAction: action, route })

  /* ---- Protocol ---- */
  if (probe?.measured) {
    const supports13 = (probe.supportedProtocols || []).some((protocol) => /1\.3/.test(protocol)) || /1\.3/.test(probe.negotiatedProtocol || '')
    checks.push({
      key: 'protocol', label: 'Protocol', method: 'measured',
      verdict: supports13 ? 'pass' : 'fail',
      detail: supports13
        ? `Negotiated ${probe.negotiatedProtocol}; TLS 1.3 is available, which the proposed key exchange requires.`
        : `Endpoint negotiated ${probe.negotiatedProtocol || 'no TLS 1.3'}${probe.legacyProtocols.length ? ` and still offers ${probe.legacyProtocols.join(', ')}` : ''}. Hybrid groups cannot negotiate below TLS 1.3.`,
    })
    if (!supports13) {
      addFinding('f-protocol', 'TLS 1.3 is not available on this endpoint', 'critical', 'Protocol',
        `Measured protocols: ${probe.supportedProtocols.join(', ') || 'none negotiated'}.`,
        'The endpoint terminates on a stack that does not offer TLS 1.3.',
        'Raise the transport floor to TLS 1.3 before attempting a hybrid key exchange.', '/dashboard/protocol-analytics')
    }
  } else {
    const supports13 = context.storedProtocols.some((protocol) => /1\.3/.test(protocol))
    checks.push({
      key: 'protocol', label: 'Protocol',
      method: context.storedProtocols.length ? 'evidence-derived' : 'not-evaluated',
      verdict: context.storedProtocols.length ? (supports13 ? 'pass' : 'fail') : 'unknown',
      detail: context.storedProtocols.length
        ? `From stored evidence: ${context.storedProtocols.join(', ')}. No live handshake was performed.`
        : 'No transport evidence and no live probe — protocol support is undetermined.',
    })
  }

  /* ---- Crypto (the hybrid key exchange itself) ---- */
  const wantsHybrid = /ML-KEM/i.test(proposed.keyExchange)
  if (probe?.measured && probe.hybridProbed) {
    const negotiated = probe.hybridGroups.length > 0 || probe.pureKemGroups.length > 0
    checks.push({
      key: 'crypto', label: 'Crypto', method: 'measured',
      verdict: !wantsHybrid ? 'pass' : negotiated ? 'pass' : 'fail',
      detail: negotiated
        ? `Endpoint accepted ${[...probe.hybridGroups, ...probe.pureKemGroups].join(', ')}.`
        : `Endpoint refused every post-quantum named group offered${probe.untestableGroups.length ? ` (${probe.untestableGroups.length} group(s) could not be offered by the local TLS build and were not measured)` : ''}.`,
    })
    if (wantsHybrid && !negotiated) {
      addFinding('f-crypto', 'Endpoint does not accept a post-quantum named group', 'high', 'Key exchange',
        `Probed hybrid groups were refused; ${probe.hybridGroups.length} accepted.`,
        'The server-side TLS stack has no ML-KEM support enabled.',
        'Enable X25519MLKEM768 on the terminating stack, or upgrade the provider that terminates this endpoint.',
        '/dashboard/vendor-pqc-readiness')
    }
  } else if (probe?.measured && !probe.hybridProbed) {
    checks.push({
      key: 'crypto', label: 'Crypto', method: 'measured', verdict: 'fail',
      detail: 'Hybrid group probing was skipped because the endpoint does not negotiate TLS 1.3 — the groups are genuinely unavailable here, not merely untested.',
    })
  } else {
    const hasPqcEvidence = context.storedAlgorithms.some((algorithm) => /ML-KEM|ML-DSA|KYBER|DILITHIUM/i.test(algorithm))
    checks.push({
      key: 'crypto', label: 'Crypto',
      method: context.storedAlgorithms.length ? 'evidence-derived' : 'not-evaluated',
      verdict: context.storedAlgorithms.length ? (hasPqcEvidence ? 'pass' : 'unknown') : 'unknown',
      detail: context.storedAlgorithms.length
        ? `Stored evidence shows ${context.storedAlgorithms.slice(0, 4).join(', ')}. Whether the endpoint would accept the proposed group was not measured.`
        : 'No cryptographic evidence and no live probe — the proposed key exchange was not evaluated.',
    })
  }

  /* ---- Certificate ---- */
  const certAlgorithm = probe?.certificateAlgorithm || null
  if (probe?.measured && certAlgorithm) {
    const classical = /RSA|ECDSA|ECC|DSA/i.test(certAlgorithm)
    checks.push({
      key: 'certificate', label: 'Certificate', method: 'measured',
      verdict: classical ? 'fail' : 'pass',
      detail: `Served certificate uses ${certAlgorithm}${probe.certificateIssuer ? `, issued by ${probe.certificateIssuer}` : ''}${probe.certificateDaysToExpiry !== null ? `, ${probe.certificateDaysToExpiry} day(s) to expiry` : ''}.`,
    })
    if (classical) {
      addFinding('f-certificate', 'Certificate compatibility issue detected', 'high', 'Certificate',
        `Current: ${certAlgorithm}. Target: ${proposed.signature}.`,
        'The certificate chain is classical; the proposed signature requires re-issuance from a PQC-capable CA.',
        'Analyze the affected trust chains before attempting migration.', '/dashboard/trust-chain-analyzer')
    }
  } else {
    checks.push({
      key: 'certificate', label: 'Certificate',
      method: context.certificateQuantumSafe === null ? 'not-evaluated' : 'evidence-derived',
      verdict: context.certificateQuantumSafe === null ? 'unknown' : context.certificateQuantumSafe ? 'pass' : 'fail',
      detail: context.certificateQuantumSafe === null
        ? 'No certificate evidence for this target and no live probe.'
        : `Stored certificate evidence${context.certificateIssuer ? ` (issuer ${context.certificateIssuer})` : ''} is ${context.certificateQuantumSafe ? 'post-quantum capable' : 'classical'}.`,
    })
  }

  /* ---- Trust chain ---- */
  checks.push({
    key: 'trust-chain', label: 'Trust Chain',
    method: probe?.measured && probe.chainLength ? 'measured' : context.certificateIssuer ? 'evidence-derived' : 'not-evaluated',
    verdict: probe?.measured && probe.chainLength
      ? 'pass'
      : context.certificateIssuer ? 'unknown' : 'unknown',
    detail: probe?.measured && probe.chainLength
      ? `Chain of ${probe.chainLength} certificate(s) validated during the probe. Whether the issuer can sign ML-DSA was NOT tested.`
      : context.certificateIssuer
        ? `Chain terminates at ${context.certificateIssuer}. PQC signing capability of that CA is unverified.`
        : 'No trust chain evidence available for this target.',
  })

  /* ---- Application ---- */
  checks.push({
    key: 'application', label: 'Application', method: 'not-evaluated', verdict: 'unknown',
    detail: 'Application-layer behaviour under the proposed configuration cannot be observed from a transport probe. Validate in the Migration Sandbox before production.',
  })

  /* ---- Vendor ---- */
  if (context.vendorName) {
    const ready = context.vendorReadiness === 'ready' || context.vendorReadiness === 'hybrid-ready'
    checks.push({
      key: 'vendor', label: 'Vendor', method: 'evidence-derived',
      verdict: ready ? 'pass' : context.vendorReadiness === 'unknown' ? 'unknown' : 'fail',
      detail: `${context.vendorName} measured readiness is ${context.vendorReadiness}.`,
    })
    if (!ready && context.vendorReadiness !== 'unknown') {
      addFinding('f-vendor', `${context.vendorName} does not yet support the proposed configuration`, 'medium', 'Vendor',
        `Measured vendor readiness: ${context.vendorReadiness}.`,
        'The provider terminating this dependency has not shipped post-quantum support.',
        'Request a PQC roadmap and track the commitment before scheduling migration.',
        `/dashboard/vendor-pqc-readiness?vendor=${encodeURIComponent(context.target.vendorId || '')}`)
    }
  } else {
    checks.push({ key: 'vendor', label: 'Vendor', method: 'not-evaluated', verdict: 'unknown', detail: 'No vendor is attributed to this target.' })
  }

  /* ---- Policy ---- */
  const policyIssues = validateExperimentConfiguration(proposed)
  checks.push({
    key: 'policy', label: 'Policy', method: 'evidence-derived',
    verdict: policyIssues.length ? 'fail' : 'pass',
    detail: policyIssues.length
      ? policyIssues.map((issue) => issue.message).join(' ')
      : `Proposed configuration matches the platform mandatory PQC stack (${proposed.keyExchange}, ${proposed.signature}, ${proposed.symmetric}, ${proposed.kdf}).`,
  })

  /* ---- Outcome ---- */
  const failed = checks.filter((check) => check.verdict === 'fail')
  const unknown = checks.filter((check) => check.verdict === 'unknown')
  const criticalFailure = findings.some((finding) => finding.severity === 'critical')

  let outcome: ExperimentOutcome
  if (failed.length && criticalFailure) outcome = 'failed'
  else if (failed.length) outcome = 'conditional'
  else if (unknown.length >= 3) outcome = 'conditional'
  else if (unknown.length) outcome = 'passed-with-warnings'
  else outcome = 'passed'
  if (!probe?.measured && !context.storedAlgorithms.length && !context.storedProtocols.length) outcome = 'not-evaluated'

  const risk: RiskLevel = criticalFailure ? 'critical' : failed.length ? 'high' : unknown.length >= 3 ? 'medium' : 'low'

  return { checks, findings, outcome, risk }
}

router.post('/lab/experiments', async (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  const startedAt = Date.now()
  try {
    const { intelligence, persistence } = await buildExternalTrust(token!, user!.id)

    const targetId = str(req.body?.targetId)
    const target = intelligence.lab.targets.find((candidate) => candidate.id === targetId)
    if (!target) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found in this tenant’s discovered inventory' } })
    }

    const requestedMode = str(req.body?.executionMode) || 'simulation'
    if (requestedMode !== 'simulation' && requestedMode !== 'controlled-test') {
      return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'executionMode must be "simulation" or "controlled-test"' } })
    }
    const executionMode = requestedMode as ExecutionMode

    const proposed: ExperimentConfiguration = {
      protocol: (str(req.body?.configuration?.protocol) || 'TLS 1.3') as ExperimentConfiguration['protocol'],
      keyExchange: (str(req.body?.configuration?.keyExchange) || 'X25519+ML-KEM-768') as ExperimentConfiguration['keyExchange'],
      signature: (str(req.body?.configuration?.signature) || 'Ed25519+ML-DSA-65') as ExperimentConfiguration['signature'],
      symmetric: (str(req.body?.configuration?.symmetric) || 'AES-256-GCM') as ExperimentConfiguration['symmetric'],
      kdf: (str(req.body?.configuration?.kdf) || 'HKDF-SHA3-256') as ExperimentConfiguration['kdf'],
      hash: (str(req.body?.configuration?.hash) || 'SHA3-256') as ExperimentConfiguration['hash'],
    }

    // Invalid combinations are refused before anything runs — the lab must never
    // demonstrate an algorithm being used for a purpose it cannot serve.
    const configIssues = validateExperimentConfiguration(proposed)
    if (configIssues.length) {
      return res.status(400).json({
        error: { code: 'INVALID_CONFIGURATION', message: 'The proposed configuration is not valid.', issues: configIssues },
      })
    }

    /* ---- Gather this target's stored evidence ---- */
    const vendor = target.vendorId ? intelligence.vendors.records.find((record) => record.id === target.vendorId) : null
    const trustCert = intelligence.trust.certificates.find((certificate) =>
      (target.assetId && certificate.assetId === target.assetId) || certificate.subject.toLowerCase() === target.host)
    const ecosystemNode = intelligence.ecosystem.nodes.find((node) => node.assetIds.includes(target.assetId || ''))
    const storedAlgorithms = [
      ...(ecosystemNode?.algorithms || []),
      ...(vendor?.position.currentAlgorithms || []),
      ...(trustCert ? [trustCert.publicKeyAlgorithm] : []),
    ].filter(Boolean)
    const storedProtocols = intelligence.ecosystem.nodes
      .filter((node) => node.kind === 'protocol' && node.assetIds.includes(target.assetId || ''))
      .map((node) => node.label)

    /* ---- Execute ---- */
    let probe: ProbeOutcome | null = null
    if (executionMode === 'controlled-test') {
      probe = await probeTarget(target.host, target.port)
      if (probe.error && !probe.measured) {
        // A refused/blocked probe is reported honestly, not silently downgraded.
        await audit(token!, user!.id, user!.email, 'lab.experiment.probe_blocked', 'experiment', target.id, 'failure', { host: target.host, reason: probe.error })
      }
    }

    const evaluation = evaluateExperiment(proposed, probe, {
      target,
      vendorReadiness: vendor?.assessedReadiness ?? null,
      vendorName: vendor?.name ?? null,
      storedAlgorithms,
      storedProtocols,
      certificateIssuer: trustCert?.issuer ?? null,
      certificateQuantumSafe: trustCert ? trustCert.quantumSafe : null,
    })

    const durationMs = Date.now() - startedAt
    const basis = probe?.measured
      ? `Controlled test: read-only TLS handshake against ${target.host}:${target.port}. ${probe.hybridProbed ? 'Post-quantum named groups were probed.' : 'Post-quantum group probing was skipped because TLS 1.3 was not negotiated.'} Laboratory result — production validation is still required.`
      : executionMode === 'controlled-test'
        ? `Controlled test could not complete against ${target.host}:${target.port}${probe?.error ? ` (${probe.error})` : ''}. Verdicts fall back to stored evidence and are labelled accordingly.`
        : `Simulation: projected from stored tenant evidence only. No connection was made to ${target.host}. Laboratory result — production validation is still required.`

    const record = {
      user_id: user!.id,
      asset_id: target.assetId,
      target_label: target.label,
      target_host: target.host,
      target_port: target.port,
      environment: target.environment,
      vendor_id: target.vendorId,
      execution_mode: executionMode,
      outcome: evaluation.outcome,
      risk: evaluation.risk,
      duration_ms: durationMs,
      payload: {
        target,
        currentConfiguration: {
          observed: [...new Set([...storedAlgorithms, ...storedProtocols])].slice(0, 12),
          protocol: probe?.negotiatedProtocol || storedProtocols[0],
        },
        proposedConfiguration: proposed,
      },
      result: { checks: evaluation.checks, findings: evaluation.findings, basis, probe: probe ? { ...probe } : null },
      created_by: user!.email || user!.id,
    }

    if (!persistence.experiments) {
      // The experiment still RAN and its result is returned; only the history
      // cannot be stored. The caller is told plainly rather than silently losing it.
      // Mapped through toExperimentRecord so an unstored result is the SAME
      // shape the history returns — the UI has one contract, not two.
      return res.status(200).json({
        data: {
          experiment: toExperimentRecord({ ...record, id: `ephemeral-${startedAt}`, created_at: new Date().toISOString() }),
          persisted: false,
          persistenceNote: 'Result returned but not stored: apply supabase/external-trust-schema.sql to retain experiment history.',
        },
      })
    }

    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

    const { data, error } = await client.from('hybrid_crypto_experiments').insert(record).select('*').single()
    if (error) {
      console.error('Experiment persistence error:', error)
      return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Experiment ran but the result could not be stored' } })
    }

    await audit(token!, user!.id, user!.email, 'lab.experiment.run', 'experiment', str(data?.id), 'success', {
      target: target.label, host: target.host, executionMode, outcome: evaluation.outcome, durationMs,
    })
    invalidate(user!.id)
    res.status(201).json({ data: { experiment: toExperimentRecord(data as Row), persisted: true } })
  } catch (error) {
    console.error('Lab experiment error:', error)
    res.status(500).json({ error: { code: 'EXPERIMENT_ERROR', message: 'Failed to run the experiment' } })
  }
})

router.post('/lab/experiments/:id/evidence', async (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  const id = str(req.params.id)
  try {
    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Database connection failed' } })

    const { data: experiment, error: readError } = await client
      .from('hybrid_crypto_experiments')
      .select('*').eq('id', id).eq('user_id', user!.id).maybeSingle()

    if (readError) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Failed to read the experiment' } })
    if (!experiment) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Experiment not found for this tenant' } })

    const { data: evidence, error: writeError } = await client
      .from('compliance_evidence')
      .insert({
        user_id: user!.id,
        // asset_id is deliberately left null so laboratory evidence never
        // appears as an audited control on an asset dossier.
        asset_id: null,
        framework: 'QGuard Hybrid Crypto Lab',
        control_id: `experiment-${id}`,
        evidence_type: 'hybrid-crypto-experiment',
        status: 'experimental',
        description: `Experimental Evidence — Production Validation Required. ${str(experiment.target_label)} · ${str(experiment.execution_mode)} · outcome ${str(experiment.outcome)}.`,
        metadata: {
          experimentId: id,
          target: { label: str(experiment.target_label), host: str(experiment.target_host), environment: str(experiment.environment) },
          executionMode: str(experiment.execution_mode),
          outcome: str(experiment.outcome),
          risk: str(experiment.risk),
          configuration: (experiment.payload as Record<string, unknown>)?.proposedConfiguration ?? null,
          result: experiment.result ?? null,
          generatedAt: new Date().toISOString(),
          disclaimer: 'Laboratory result. This does not constitute proof of production security.',
        },
      })
      .select('id').single()

    if (writeError) return res.status(500).json({ error: { code: 'DB_ERROR', message: 'Failed to record the evidence' } })

    await client.from('hybrid_crypto_experiments')
      .update({ evidence_id: evidence.id, updated_at: new Date().toISOString() })
      .eq('id', id).eq('user_id', user!.id)

    await audit(token!, user!.id, user!.email, 'lab.experiment.evidence', 'experiment', id, 'success', { evidenceId: str(evidence.id) })
    invalidate(user!.id)
    res.status(201).json({ data: { evidenceId: evidence.id, disclaimer: 'Experimental Evidence — Production Validation Required' } })
  } catch (error) {
    console.error('Experiment evidence error:', error)
    res.status(500).json({ error: { code: 'EVIDENCE_ERROR', message: 'Failed to generate evidence' } })
  }
})

/** Recommended configuration for a target, derived from its observed crypto. */
router.get('/lab/targets/:targetId/recommendation', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const { intelligence } = await buildExternalTrust(token!, user!.id)
    const target = intelligence.lab.targets.find((candidate) => candidate.id === str(req.params.targetId))
    if (!target) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found' } })

    const node = intelligence.ecosystem.nodes.find((candidate) => candidate.assetIds.includes(target.assetId || ''))
    const protocols = intelligence.ecosystem.nodes
      .filter((candidate) => candidate.kind === 'protocol' && candidate.assetIds.includes(target.assetId || ''))
      .map((candidate) => candidate.label)

    res.json({
      data: {
        target,
        observed: { algorithms: node?.algorithms || [], protocols },
        recommended: recommendConfiguration(node?.algorithms || [], protocols),
      },
    })
  } catch (error) {
    console.error('Lab recommendation error:', error)
    res.status(500).json({ error: { code: 'RECOMMENDATION_ERROR', message: 'Failed to build a recommendation' } })
  }
})

export default router
export type { EcosystemNode }
