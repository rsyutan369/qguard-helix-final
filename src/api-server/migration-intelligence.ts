import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { buildScannerIntelligence, scannerFindingsForAsset } from './scanner'
import { buildSharedResponsibility } from '@/lib/shared-responsibility'
import type {
  OwnershipFinding,
  SharedResponsibilityIntelligence,
} from '@/lib/shared-responsibility'
import { buildOwnershipInputs, OWNERSHIP_INPUT_LIMIT } from './shared-responsibility-inputs'
import { payloadFingerprint, streamLiveSnapshot } from './live-snapshot-stream'
import { createSingleFlightCache } from '@/lib/single-flight-cache'
import { normaliseAsset, OWNER_SOURCE_LABEL } from '@/lib/estate/model'
import type { MigrationAssetOption, MigrationAssetScope, MigrationIntelligenceCoverage } from '@/lib/migration/intelligence-scope'

/**
 * Shared Responsibility Quantum Migration Intelligence Engine™ — aggregation router.
 *
 * Reads the canonical, tenant-scoped `buildSnapshot` + `buildScannerIntelligence`
 * caches plus the tenant's connected accounts, adapts them into normalized
 * ownership-finding inputs, and runs the pure Shared Responsibility module. The
 * result classifies every cryptographic finding into customer / provider /
 * ecosystem domains with provider attribution, edge-vs-origin TLS intelligence,
 * a migration-dependency graph, tri-part readiness and a 7-wave roadmap.
 *
 * Evidence-driven only: attribution is derived from existing tenant evidence
 * (never network probing), and unmatched findings stay honestly unattributed.
 *
 * Auth: header-only Bearer (the SSE stream is read via fetch()+ReadableStream on
 * the client, so the access token is never placed in the URL). Tenant isolation
 * is inherited from the underlying tenant-scoped snapshot/intelligence caches.
 * Access tier (Basic+) is enforced centrally by `subscriptionGateway`.
 */

const router = Router()

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string; scopeAsset?: string }

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = getToken(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  const asset = req.query.asset
  if (asset !== undefined && (typeof asset !== 'string' || !/^[a-zA-Z0-9_.:-]{1,180}$/.test(asset))) {
    return res.status(400).json({ error: { code: 'INVALID_ASSET', message: 'Invalid asset selection' } })
  }
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  ;(req as AuthedRequest).scopeAsset = asset as string | undefined
  res.setHeader('Cache-Control', 'private, no-store')
  next()
}
router.use(requireAuth)

const str = (v: unknown) => (typeof v === 'string' ? v : v == null ? '' : String(v))
const UUID = /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i
const dateOrNull = (value: unknown) => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value : null
type Scanner = Awaited<ReturnType<typeof buildScannerIntelligence>>
type ScannerAsset = Scanner['assets']['assets'][number]
type AuthClient = NonNullable<ReturnType<typeof createAuthClient>>

class IntelligenceError extends Error {
  constructor(readonly status: number, message: string) { super(message) }
}

function assetOption(raw: ScannerAsset): MigrationAssetOption {
  const asset = normaliseAsset({ ...raw, service_owner: raw.serviceOwner })
  return { id: asset.id, name: asset.name, type: asset.type || null, environment: asset.environmentRaw || null, owner: asset.owner }
}

async function loadConnectorProviders(client: AuthClient, userId: string): Promise<string[]> {
  const { data, error } = await client.from('connector_accounts').select('provider').eq('user_id', userId).limit(400)
  if (error) throw error
  return (data || []).map((r) => str(r.provider)).filter(Boolean)
}

async function loadRelationships(client: AuthClient, userId: string, id: string): Promise<MigrationAssetScope['relationships']> {
  const { data, count, error } = await client.from('asset_relationships')
    .select('id, source_asset_id, target_asset_id, relationship_type, created_at', { count: 'exact' })
    .eq('user_id', userId).or(`source_asset_id.eq.${id},target_asset_id.eq.${id}`)
    .order('created_at', { ascending: false }).order('id').limit(30)
  if (error) throw error
  const edges = data || []
  const peers = [...new Set(edges.map((row) => str(row.source_asset_id === id ? row.target_asset_id : row.source_asset_id)).filter((peer) => UUID.test(peer) && peer !== id))]
  const names = new Map<string, string>()
  if (peers.length) {
    const result = await client.from('assets').select('id, name').eq('user_id', userId).in('id', peers)
    if (result.error) throw result.error
    for (const peer of result.data || []) names.set(peer.id, peer.name)
  }
  return { state: 'available', total: count, rows: edges.flatMap((edge) => {
    const outgoing = edge.source_asset_id === id
    const assetId = str(outgoing ? edge.target_asset_id : edge.source_asset_id)
    const assetName = names.get(assetId)
    return assetName ? [{ id: edge.id, assetId, assetName, direction: outgoing ? 'outgoing' : 'incoming', type: edge.relationship_type || null, recordedAt: dateOrNull(edge.created_at) }] : []
  }) }
}

async function loadJobs(client: AuthClient, userId: string, assetId: string): Promise<MigrationAssetScope['jobs']> {
  const { data, count, error } = await client.from('migration_jobs')
    .select('id, name, job_type, status, target_algorithm, started_at, completed_at, updated_at', { count: 'exact' })
    .eq('user_id', userId).eq('asset_id', assetId).order('updated_at', { ascending: false }).order('id').limit(5)
  if (error) throw error
  return { state: 'available', total: count, rows: (data || []).map((row) => ({
    id: row.id, name: row.name, type: row.job_type, status: row.status, target: row.target_algorithm || null,
    startedAt: dateOrNull(row.started_at), completedAt: dateOrNull(row.completed_at), updatedAt: dateOrNull(row.updated_at),
  })) }
}

async function loadAssetScope(client: AuthClient, userId: string, raw: ScannerAsset): Promise<MigrationAssetScope> {
  const asset = normaliseAsset({ ...raw, service_owner: raw.serviceOwner })
  const linked = UUID.test(asset.id)
  const [relationships, jobs] = await Promise.allSettled([
    linked ? loadRelationships(client, userId, asset.id) : null,
    linked ? loadJobs(client, userId, asset.id) : null,
  ])
  const scanSource = raw.lastScannedSource === 'evidence' || raw.lastScannedSource === 'scan-record' ? raw.lastScannedSource : null
  return {
    ...assetOption(raw),
    ownerSource: asset.ownerSource ? OWNER_SOURCE_LABEL[asset.ownerSource] : null,
    businessService: asset.service,
    inventoryStatus: asset.status,
    scanStatus: raw.complianceStatus || null,
    lastScannedAt: scanSource ? dateOrNull(raw.lastScanned) : null,
    lastScannedSource: scanSource,
    relationships: relationships.status === 'fulfilled' && relationships.value ? relationships.value : { state: linked ? 'unavailable' : 'no-record', total: null, rows: [] },
    jobs: jobs.status === 'fulfilled' && jobs.value ? jobs.value : { state: linked ? 'unavailable' : 'no-record', total: null, rows: [] },
  }
}

interface IntelligenceBundle {
  intelligence: SharedResponsibilityIntelligence
  findingsById: Map<string, OwnershipFinding>
  /** The wire payload — ONE object per computation, so REST and every open
   *  stream send the same thing and its fingerprint is hashed once. */
  payload: SharedResponsibilityIntelligence & {
    baseline: { quantumReadiness: number; quantumReadinessLevel: string } | null
    assetScope: MigrationAssetScope | null
    coverage: MigrationIntelligenceCoverage
    sourceCheckedAt: string | null
  }
}

async function computeMigrationIntelligence(token: string, userId: string, assetId?: string, refresh = false): Promise<IntelligenceBundle> {
  const client = createAuthClient(token)
  if (!client) throw new IntelligenceError(503, 'Asset database is unavailable')
  const [intelResult, snapshotResult, connectorResult] = await Promise.allSettled([
    buildScannerIntelligence(token, userId, { refresh }),
    assetId ? null : buildSnapshot(token, userId, undefined, refresh),
    loadConnectorProviders(client, userId),
  ])
  const intel = intelResult.status === 'fulfilled' ? intelResult.value : null
  const snapshot = snapshotResult.status === 'fulfilled' ? snapshotResult.value : null
  const connectors = connectorResult.status === 'fulfilled' ? connectorResult.value : []
  const asset = assetId ? intel?.assets.assets.find((row) => row.id === assetId) : undefined
  if (assetId && !asset) {
    if (!intel || intel.mode !== 'database') throw new IntelligenceError(503, 'The selected asset could not be checked in the inventory')
    throw new IntelligenceError(404, 'The selected asset is unavailable in the current inventory window')
  }
  const scannerFindings = asset ? scannerFindingsForAsset(asset) : intel?.findings ?? []
  const fallback = !asset && !scannerFindings.length && Boolean(snapshot?.criticalFindings.length)
  if (!asset && intel?.mode !== 'database' && !scannerFindings.length && !fallback) {
    throw new IntelligenceError(503, 'Scan evidence is temporarily unavailable')
  }
  const inputs = buildOwnershipInputs({ assets: { assets: asset ? [asset] : intel?.assets.assets ?? [] }, findings: scannerFindings }, fallback ? snapshot : null)
  const scores = snapshot?.hasData && !asset ? snapshot.scores : null
  const baseline = scores ? { quantumReadiness: scores.quantumReadiness, quantumReadinessLevel: scores.quantumReadinessLevel } : null
  const assetScope = asset ? await loadAssetScope(client, userId, asset) : null
  const intelligence = buildSharedResponsibility(inputs, {
    context: { connectorProviders: connectors },
    baselineOverall: baseline?.quantumReadiness,
    maxFindings: inputs.length,
  })
  const findingsById = new Map(intelligence.findings.map((finding) => [finding.id, finding]))
  const coverage: MigrationIntelligenceCoverage = {
    source: fallback ? 'readiness-fallback' : intel?.mode === 'database' ? 'scanner' : 'partial-scanner',
    scannerFindings: fallback ? null : scannerFindings.length,
    readiness: baseline ? 'assessment' : 'estimate',
    providerConnectorsAvailable: connectorResult.status === 'fulfilled',
  }
  const sourceCheckedAt = (fallback ? snapshot?.generatedAt : intel?.generatedAt) ?? null
  return { intelligence, findingsById, payload: { ...intelligence, findings: intelligence.findings.slice(0, 200), baseline, assetScope, coverage, sourceCheckedAt } }
}

/**
 * Per-tenant short-TTL single-flight cache. Collapses the dashboard's fetch/SSE
 * fan-out into one computation per window and gives every consumer the SAME
 * authoritative model within it. Failures are never cached.
 */
const cache = createSingleFlightCache<IntelligenceBundle>(12_000)

function buildMigrationIntelligence(req: Request, refresh = false): Promise<IntelligenceBundle> {
  const { user, token, scopeAsset } = req as AuthedRequest
  const key = JSON.stringify([user!.id, scopeAsset ?? null])
  return cache.get(key, () => computeMigrationIntelligence(token!, user!.id, scopeAsset, refresh), refresh)
}

function sendError(res: Response, error: unknown) {
  const status = error instanceof IntelligenceError ? error.status : 500
  const message = error instanceof IntelligenceError ? error.message : 'Migration intelligence is temporarily unavailable'
  res.status(status).json({ error: { code: status === 404 ? 'ASSET_NOT_FOUND' : 'MIGRATION_INTELLIGENCE_FAILED', message } })
}

router.get('/assets', async (req, res) => {
  const { token, user } = req as AuthedRequest
  try {
    const intel = await buildScannerIntelligence(token!, user!.id)
    const window = intel.assets.assets
    if (intel.mode !== 'database' && !window.length) throw new IntelligenceError(503, 'Asset inventory is temporarily unavailable')
    const term = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 120).toLowerCase() : ''
    const offset = Math.min(window.length, Math.max(0, Math.floor(Number(req.query.offset) || 0)))
    const matches = window.map(assetOption).filter((asset) => [asset.name, asset.owner, asset.environment, asset.type].some((value) => value?.toLowerCase().includes(term)))
      .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id))
    res.json({ assets: matches.slice(offset, offset + 20), total: matches.length, partial: intel.mode !== 'database' })
  } catch (error) { sendError(res, error) }
})

router.get('/', async (req: Request, res: Response) => {
  try {
    const { payload } = await buildMigrationIntelligence(req, req.query.refresh === '1')
    res.json({ ...payload, fingerprint: payloadFingerprint(payload) })
  } catch (error) {
    sendError(res, error)
  }
})

router.get('/matrix', async (req: Request, res: Response) => {
  try {
    const { intelligence } = await buildMigrationIntelligence(req)
    res.json({ generatedAt: intelligence.generatedAt, hasData: intelligence.hasData, matrix: intelligence.matrix })
  } catch (error) {
    sendError(res, error)
  }
})

router.get('/waves', async (req: Request, res: Response) => {
  try {
    const { intelligence } = await buildMigrationIntelligence(req)
    res.json({ generatedAt: intelligence.generatedAt, hasData: intelligence.hasData, waves: intelligence.waves })
  } catch (error) {
    sendError(res, error)
  }
})

router.get('/finding/:id', async (req: Request, res: Response) => {
  try {
    const { findingsById } = await buildMigrationIntelligence(req)
    const finding = findingsById.get(req.params.id)
    if (!finding) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Finding not found in current intelligence window' } })
    res.json({ finding })
  } catch (error) {
    sendError(res, error)
  }
})

/**
 * Live stream, on the platform's shared snapshot contract: a full frame first
 * and whenever the CONTENT changes, a few-byte `-unchanged` frame otherwise, and
 * `-error` with the stream left open when a build fails. This route used to
 * re-send the whole model (~290 KB for a two-asset tenant) every 30 s to every
 * open tab whether or not anything had changed, and kept computing under an
 * expired token until the client noticed.
 */
router.get('/stream', (req: Request, res: Response) => {
  streamLiveSnapshot(req, res, {
    event: 'migration-intelligence',
    build: async () => {
      try { return (await buildMigrationIntelligence(req)).payload }
      catch (error) { throw new Error(error instanceof IntelligenceError ? error.message : 'Migration intelligence is temporarily unavailable') }
    },
    intervalMs: 15_000,
  })
})

export default router
