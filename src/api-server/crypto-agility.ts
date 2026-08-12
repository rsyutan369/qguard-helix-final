import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { buildPortfolio } from './migration-planner'
import {
  buildCryptoAgilityIntelligence,
  deriveAgilityDerivations,
  previewChangeImpact,
  type AgilityInputs,
  type CryptoAgilityIntelligence,
} from '@/lib/crypto-agility/agility-intelligence'
import type { Row } from '@/lib/migration/asset-intelligence'

/**
 * QGuard Helix — Crypto Agility Command Center™ aggregation router.
 *
 * Answers ONE question the other modules do not: how quickly and safely can this
 * organisation CHANGE its cryptography?
 *
 * Reuse contract (no duplicated derivation, no duplicated fetching):
 *   - Per-asset dossiers come from the Migration Planner's cached portfolio,
 *     which is built by the SHARED asset-intelligence engine.
 *   - Tenant totals, shared-responsibility ownership and posture come from the
 *     cached Quantum Readiness snapshot.
 *   - Only agility-specific raw rows (libraries, exposures, runtime, keys,
 *     connectors, policy exceptions) are fetched here.
 *   - Simulation is NOT implemented here: the sandbox digital twin owns it
 *     (POST /api/v1/sandbox/simulate). This router serves the deterministic
 *     pre-flight impact projection the UI shows before handing off.
 *
 * Every query is tenant-scoped (user_id) through the caller's own RLS-bound
 * client. A missing table degrades to an empty set — never to fabricated data.
 */

const router = Router()

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

function tokenFromRequest(req: Request): string | null {
  const headerToken = getToken(req)
  if (headerToken) return headerToken
  // EventSource cannot set an Authorization header, so /stream passes the token
  // via query string. Accepted for this router only.
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

const str = (v: unknown) => (typeof v === 'string' ? v : v == null ? '' : String(v))
const num = (v: unknown) => {
  const n = Number(v)
  return Number.isFinite(n) ? n : 0
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function safeRows(client: any, table: string, build: (query: any) => any): Promise<Row[]> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`Crypto agility ${table} query skipped:`, error.message || error)
      return []
    }
    return (data as Row[]) || []
  } catch (error) {
    console.warn(`Crypto agility ${table} query failed:`, (error as Error)?.message || error)
    return []
  }
}

/* ------------------------------------------------------------------ */
/* Shared single-flight cache                                          */
/* ------------------------------------------------------------------ */

/**
 * Mirrors the platform contract used by buildSnapshot / buildPortfolio: one
 * computation per tenant per window, so the page, its SSE refreshes and the
 * asset feed all read the SAME intelligence and can never disagree. Failures
 * are never cached.
 */
const AGILITY_TTL_MS = 15_000
const agilityCache = new Map<string, { at: number; promise: Promise<CryptoAgilityIntelligence> }>()
const inputsCache = new Map<string, { at: number; promise: Promise<AgilityInputs> }>()

async function loadInputs(token: string, userId: string): Promise<AgilityInputs> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [portfolio, snapshot] = await Promise.all([buildPortfolio(token, userId), buildSnapshot(token, userId)])

  const [
    cryptoInventory,
    cryptoExposures,
    certificates,
    runtimeEvents,
    generatedKeys,
    migrationJobs,
    scanSessions,
    securityEvents,
    connectorAccounts,
    relationships,
    policyExceptions,
  ] = await Promise.all([
    // metadata is required here (and not in the planner) because code-location
    // evidence is what distinguishes embedded cryptography from configuration.
    safeRows(client, 'crypto_inventory', (q) =>
      q
        .select('id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at')
        .eq('user_id', userId)
        .order('discovered_at', { ascending: false })
        .limit(2500),
    ),
    safeRows(client, 'crypto_exposures', (q) =>
      q.select('id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(2000),
    ),
    safeRows(client, 'certificates', (q) =>
      q.select('id, asset_id, name, subject, algorithm, key_size, issuer, not_after, is_quantum_safe, status, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1500),
    ),
    safeRows(client, 'runtime_crypto_events', (q) =>
      q.select('id, asset_id, asset_name, algorithm, protocol, cipher_suite, severity, risk_score, is_pqc, is_legacy, hndl_risk, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(3000),
    ),
    safeRows(client, 'generated_keys', (q) => q.select('id, algorithm, bit_length, status, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(1000)),
    safeRows(client, 'migration_jobs', (q) =>
      q.select('id, asset_id, name, job_type, status, target_algorithm, progress, created_at, updated_at').eq('user_id', userId).order('updated_at', { ascending: false }).limit(600),
    ),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, status, findings_count, completed_at, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(120)),
    safeRows(client, 'security_events', (q) =>
      q.select('id, event_type, severity, message, resource_name, resource_type, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(200),
    ),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, status').eq('user_id', userId).limit(400)),
    safeRows(client, 'asset_relationships', (q) => q.select('*').eq('user_id', userId).limit(3000)),
    // Optional governance table — absent tenants degrade to no exceptions.
    safeRows(client, 'quantum_governance_exceptions', (q) =>
      q.select('id, policy_violated, justification, expiration_date, status, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(100),
    ),
  ])

  return {
    assets: portfolio.assets,
    portfolioSummary: portfolio.summary,
    snapshot: {
      hasData: snapshot.hasData,
      lastAssessmentAt: snapshot.lastAssessmentAt,
      scores: {
        quantumReadiness: snapshot.scores.quantumReadiness,
        pqcAdoption: snapshot.scores.pqcAdoption,
        quantumRisk: snapshot.scores.quantumRisk,
        hndlRisk: snapshot.scores.hndlRisk,
      },
      inventory: {
        assetsAssessed: snapshot.inventory.assetsAssessed,
        cryptoComponents: snapshot.inventory.cryptoComponents,
        vulnerableComponents: snapshot.inventory.vulnerableComponents,
        pqcReadyComponents: snapshot.inventory.pqcReadyComponents,
        certificatesAnalyzed: snapshot.inventory.certificatesAnalyzed,
        keysDiscovered: snapshot.inventory.keysDiscovered,
        trustRelationships: snapshot.inventory.trustRelationships,
        cloudAccounts: snapshot.inventory.cloudAccounts,
        domainsScanned: snapshot.inventory.domainsScanned,
      },
      sharedResponsibility: snapshot.sharedResponsibility,
    },
    cryptoInventory,
    cryptoExposures,
    certificates,
    runtimeEvents,
    generatedKeys,
    migrationJobs,
    scanSessions,
    securityEvents,
    connectorAccounts,
    relationships,
    policyExceptions,
  }
}

function cachedInputs(token: string, userId: string, force = false): Promise<AgilityInputs> {
  const cached = inputsCache.get(userId)
  if (!force && cached && Date.now() - cached.at < AGILITY_TTL_MS) return cached.promise
  const promise = loadInputs(token, userId)
  inputsCache.set(userId, { at: Date.now(), promise })
  promise.catch(() => inputsCache.delete(userId))
  if (inputsCache.size > 500) {
    const now = Date.now()
    for (const [key, value] of inputsCache) if (now - value.at > AGILITY_TTL_MS) inputsCache.delete(key)
  }
  return promise
}

export async function buildAgility(token: string, userId: string, force = false): Promise<CryptoAgilityIntelligence> {
  const cached = agilityCache.get(userId)
  if (!force && cached && Date.now() - cached.at < AGILITY_TTL_MS) return cached.promise
  const promise = cachedInputs(token, userId, force).then((inputs) => buildCryptoAgilityIntelligence(inputs))
  agilityCache.set(userId, { at: Date.now(), promise })
  promise.catch(() => agilityCache.delete(userId))
  if (agilityCache.size > 500) {
    const now = Date.now()
    for (const [key, value] of agilityCache) if (now - value.at > AGILITY_TTL_MS) agilityCache.delete(key)
  }
  return promise
}

/* ------------------------------------------------------------------ */
/* Routes                                                              */
/* ------------------------------------------------------------------ */

/** GET / — the full Crypto Agility intelligence snapshot. */
router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const force = str(req.query.refresh) === '1'
    const intelligence = await buildAgility(token!, user!.id, force)
    res.json({ data: intelligence })
  } catch (error) {
    console.error('Crypto agility aggregation error:', error)
    res.status(500).json({
      error: {
        code: 'CRYPTO_AGILITY_ERROR',
        message: 'Failed to compute the crypto agility assessment',
      },
    })
  }
})

/**
 * GET /stream — Server-Sent Events.
 *
 * Pushes a fresh snapshot on an interval bounded BELOW the cache TTL's cost:
 * every connected client of a tenant collapses onto the one cached computation,
 * so N open dashboards cost the same as one.
 */
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
      const intelligence = await buildAgility(token!, user!.id)
      send('agility-update', intelligence)
    } catch (error) {
      send('agility-error', { message: error instanceof Error ? error.message : 'Snapshot unavailable' })
    }
  }

  void push()
  const interval = setInterval(() => void push(), 20_000)
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': heartbeat\n\n')
  }, 25_000)

  req.on('close', () => {
    closed = true
    clearInterval(interval)
    clearInterval(heartbeat)
  })
})

/**
 * GET /assets — filtered, sorted, paginated agility asset feed.
 *
 * Server-side filtering keeps large estates responsive: the browser never
 * receives more than one page of rows.
 */
router.get('/assets', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const intelligence = await buildAgility(token!, user!.id)

    const search = str(req.query.search).trim().toLowerCase()
    const state = str(req.query.state).trim().toLowerCase()
    const readiness = str(req.query.readiness).trim().toLowerCase()
    const environment = str(req.query.environment).trim().toLowerCase()
    const owner = str(req.query.owner).trim().toLowerCase()
    const controlDomain = str(req.query.controlDomain).trim().toLowerCase()
    const replaceability = str(req.query.replaceability).trim().toLowerCase()
    const sort = str(req.query.sort).trim() || 'agility'
    const limit = Math.max(1, Math.min(500, num(req.query.limit) || 100))
    const offset = Math.max(0, num(req.query.offset))

    let rows = intelligence.assets
    if (search) {
      rows = rows.filter((r) =>
        `${r.name} ${r.type} ${r.owner} ${r.environment} ${r.currentAlgorithms.join(' ')} ${r.targetAlgorithms.join(' ')}`.toLowerCase().includes(search),
      )
    }
    if (state && state !== 'all') rows = rows.filter((r) => r.agilityState === state)
    if (readiness && readiness !== 'all') rows = rows.filter((r) => r.readiness === readiness)
    if (environment && environment !== 'all') rows = rows.filter((r) => r.environment.toLowerCase() === environment)
    if (owner && owner !== 'all') rows = rows.filter((r) => r.owner.toLowerCase() === owner)
    if (controlDomain && controlDomain !== 'all') rows = rows.filter((r) => r.controlDomain === controlDomain)
    if (replaceability && replaceability !== 'all') rows = rows.filter((r) => r.replaceability === replaceability)

    const sorted = [...rows]
    if (sort === 'risk') sorted.sort((a, b) => b.riskScore - a.riskScore)
    else if (sort === 'dependencies') sorted.sort((a, b) => b.dependencies - a.dependencies)
    else if (sort === 'name') sorted.sort((a, b) => a.name.localeCompare(b.name))
    else if (sort === 'blockers') sorted.sort((a, b) => b.blockers - a.blockers || b.couplingFindings - a.couplingFindings)
    // default 'agility': least agile first, unknowns last (unknown ≠ safe, but
    // an unmeasured asset must not outrank a measured blocker).
    else
      sorted.sort((a, b) => {
        const av = a.agilityScore ?? 999
        const bv = b.agilityScore ?? 999
        return av - bv || b.dependencies - a.dependencies
      })

    res.json({
      data: {
        generatedAt: intelligence.generatedAt,
        assets: sorted.slice(offset, offset + limit),
        total: rows.length,
        totalUnfiltered: intelligence.assets.length,
        distribution: intelligence.distribution,
        filters: intelligence.filters,
      },
    })
  } catch (error) {
    console.error('Crypto agility asset feed error:', error)
    res.status(500).json({ error: { code: 'CRYPTO_AGILITY_ASSETS_ERROR', message: 'Failed to load the crypto agility asset feed' } })
  }
})

/**
 * POST /impact — deterministic pre-flight projection for a proposed change.
 *
 * This is NOT a simulation. It projects the blast radius over evidence already
 * held, so the operator can decide whether to hand the change to the Migration
 * Sandbox digital twin (POST /api/v1/sandbox/simulate), which owns execution.
 */
router.post('/impact', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const assetId = str(req.body?.assetId).trim()
    if (!assetId) {
      return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'assetId is required' } })
    }
    const fromAlgorithm = str(req.body?.fromAlgorithm).trim() || undefined
    const toAlgorithm = str(req.body?.toAlgorithm).trim() || undefined

    const inputs = await cachedInputs(token!, user!.id)
    // Ownership check: the asset must belong to the caller's own portfolio,
    // which is built exclusively from their RLS-scoped rows.
    if (!inputs.assets.some((a) => a.id === assetId)) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Asset not found in your scanned inventory' } })
    }

    const derivations = deriveAgilityDerivations(inputs)
    const preview = previewChangeImpact(inputs, derivations, assetId, fromAlgorithm, toAlgorithm)
    if (!preview) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Asset not found in your scanned inventory' } })
    }

    res.json({
      data: {
        preview,
        // Where the real simulation runs — the UI hands off to this, it never
        // simulates locally.
        simulationEndpoint: '/api/v1/sandbox/simulate',
        simulationModule: '/dashboard/migration-sandbox',
      },
    })
  } catch (error) {
    console.error('Crypto agility impact preview error:', error)
    res.status(500).json({ error: { code: 'CRYPTO_AGILITY_IMPACT_ERROR', message: 'Failed to compute the change impact preview' } })
  }
})

export default router
