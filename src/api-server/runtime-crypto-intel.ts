import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { buildPortfolio } from './migration-planner'
import {
  buildRuntimeCryptoIntelligence,
  windowFor,
  type RuntimeCryptoIntelligence,
  type RuntimeIntelInputs,
  type TimeWindowKey,
} from '@/lib/runtime-crypto/runtime-intelligence'
import type { Row } from '@/lib/migration/asset-intelligence'

/**
 * QGuard Helix — Runtime Cryptographic Intelligence aggregation router.
 *
 * Serves the runtime VISIBILITY layer: what cryptography is actually executing,
 * whether it is quantum-safe, what is wrong, what to fix first, and whether a
 * migration really changed runtime behaviour.
 *
 * Reuse contract (no duplicated derivation, no duplicated fetching):
 *   - Estate posture, PQC adoption and the quantum / HNDL risk scores come from
 *     the cached Quantum Readiness snapshot, so this page can never disagree
 *     with Quantum Readiness, Harvest Now, the planner or the reports.
 *   - Per-asset criticality, exposure, dossier and migration state come from the
 *     Migration Planner's cached portfolio (the shared asset-intelligence engine).
 *   - Only runtime-specific rows are fetched here.
 *   - The derivation itself lives in the pure isomorphic engine so the server,
 *     the browser and the offline check tool read one model.
 *
 * Every query is tenant-scoped through the caller's own RLS-bound client. A
 * missing table degrades to an empty set — never to fabricated telemetry.
 */

const router = Router()

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

function tokenFromRequest(req: Request): string | null {
  const headerToken = getToken(req)
  if (headerToken) return headerToken
  // EventSource cannot set an Authorization header. The dashboard hook streams
  // over fetch() WITH a header, so this fallback exists only for compatibility
  // with any client that cannot.
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

/** Row cap for the runtime event query. Reported to the engine so it can
 *  suppress month-over-month claims that a truncated window would distort. */
const RUNTIME_EVENT_CAP = 5000

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function safeRows(client: any, table: string, build: (query: any) => any): Promise<Row[]> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`Runtime crypto intel ${table} query skipped:`, error.message || error)
      return []
    }
    return (data as Row[]) || []
  } catch (error) {
    console.warn(`Runtime crypto intel ${table} query failed:`, (error as Error)?.message || error)
    return []
  }
}

/* ------------------------------------------------------------------ */
/* Shared single-flight input cache                                    */
/* ------------------------------------------------------------------ */

type RuntimeInputBundle = Omit<RuntimeIntelInputs, 'window' | 'eventLimit' | 'now'>

/**
 * Mirrors the platform contract used by buildSnapshot / buildPortfolio: one
 * fetch per tenant per window, so the page, its SSE refreshes and the paged
 * event feed all read the SAME evidence and cannot disagree. The derivation is
 * pure and cheap, so only the FETCH is cached — each request may then project a
 * different time window from the same rows at no extra database cost.
 * Failures are never cached.
 */
const INPUT_TTL_MS = 15_000
const inputCache = new Map<string, { at: number; promise: Promise<RuntimeInputBundle> }>()

async function loadInputs(token: string, userId: string): Promise<RuntimeInputBundle> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [snapshot, portfolio] = await Promise.all([buildSnapshot(token, userId), buildPortfolio(token, userId)])

  const [runtimeEvents, migrationJobs, scannerAgents, connectorAccounts] = await Promise.all([
    safeRows(client, 'runtime_crypto_events', (q) =>
      q
        .select(
          'id, agent_id, connector_account_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, port, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, certificate_fingerprint, package_name, package_version, process_name, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at',
        )
        .eq('user_id', userId)
        .order('observed_at', { ascending: false })
        .limit(RUNTIME_EVENT_CAP),
    ),
    safeRows(client, 'migration_jobs', (q) =>
      q
        .select('id, asset_id, name, job_type, status, target_algorithm, strategy, progress, metadata, started_at, completed_at, created_at, updated_at')
        .eq('user_id', userId)
        .order('updated_at', { ascending: false })
        .limit(400),
    ),
    safeRows(client, 'scanner_agents', (q) =>
      q.select('id, name, status, hostname, platform, last_seen_at, created_at, updated_at').eq('user_id', userId).limit(250),
    ),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, status').eq('user_id', userId).limit(400)),
  ])

  return {
    snapshot: {
      hasData: snapshot.hasData,
      lastAssessmentAt: snapshot.lastAssessmentAt,
      scores: {
        quantumReadiness: snapshot.scores.quantumReadiness,
        pqcAdoption: snapshot.scores.pqcAdoption,
        quantumRisk: snapshot.scores.quantumRisk,
        quantumRiskLevel: snapshot.scores.quantumRiskLevel,
        hndlRisk: snapshot.scores.hndlRisk,
        hndlRiskLevel: snapshot.scores.hndlRiskLevel,
      },
      inventory: {
        assetsAssessed: snapshot.inventory.assetsAssessed,
        cryptoComponents: snapshot.inventory.cryptoComponents,
        vulnerableComponents: snapshot.inventory.vulnerableComponents,
        certificatesAnalyzed: snapshot.inventory.certificatesAnalyzed,
      },
    },
    assets: portfolio.assets,
    runtimeEvents,
    migrationJobs,
    scannerAgents,
    connectorAccounts,
    runtimeEventsTruncated: runtimeEvents.length >= RUNTIME_EVENT_CAP,
  }
}

function cachedInputs(token: string, userId: string, force = false): Promise<RuntimeInputBundle> {
  const cached = inputCache.get(userId)
  if (!force && cached && Date.now() - cached.at < INPUT_TTL_MS) return cached.promise
  const promise = loadInputs(token, userId)
  inputCache.set(userId, { at: Date.now(), promise })
  promise.catch(() => inputCache.delete(userId))
  if (inputCache.size > 500) {
    const now = Date.now()
    for (const [key, value] of inputCache) if (now - value.at > INPUT_TTL_MS) inputCache.delete(key)
  }
  return promise
}

export async function buildRuntimeIntel(
  token: string,
  userId: string,
  options: { window?: TimeWindowKey; eventLimit?: number; force?: boolean } = {},
): Promise<RuntimeCryptoIntelligence> {
  const inputs = await cachedInputs(token, userId, options.force)
  return buildRuntimeCryptoIntelligence({
    ...inputs,
    window: options.window,
    eventLimit: options.eventLimit,
  })
}

function windowParam(req: Request): TimeWindowKey {
  return windowFor(str(req.query.window)).key
}

/* ------------------------------------------------------------------ */
/* Routes                                                              */
/* ------------------------------------------------------------------ */

/** GET / — the full Runtime Cryptographic Intelligence model. */
router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const data = await buildRuntimeIntel(token!, user!.id, {
      window: windowParam(req),
      eventLimit: num(req.query.limit) || undefined,
      force: str(req.query.refresh) === '1',
    })
    res.json({ data })
  } catch (error) {
    console.error('Runtime crypto intelligence error:', error)
    res.status(500).json({
      error: { code: 'RUNTIME_INTEL_ERROR', message: 'Failed to compute runtime cryptographic intelligence' },
    })
  }
})

/**
 * GET /stream — Server-Sent Events.
 *
 * Every connected client of a tenant collapses onto the one cached fetch, so N
 * open dashboards cost the same as one. The frame carries the whole model; the
 * client replaces state atomically rather than patching, which is what keeps
 * KPI cards, the activity table and the risk list from ever disagreeing
 * mid-update.
 */
router.get('/stream', async (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  const window = windowParam(req)
  const eventLimit = num(req.query.limit) || undefined

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
      const data = await buildRuntimeIntel(token!, user!.id, { window, eventLimit })
      send('runtime-intel', data)
    } catch (error) {
      send('runtime-error', { message: error instanceof Error ? error.message : 'Runtime telemetry unavailable' })
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

/**
 * GET /events — server-side filtered, searched and paginated activity feed.
 *
 * The Activity tab never downloads thousands of events to display twenty (§26);
 * filtering and paging happen here, against the cached model.
 */
router.get('/events', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const intelligence = await buildRuntimeIntel(token!, user!.id, { window: windowParam(req), eventLimit: 500 })

    const search = str(req.query.search).trim().toLowerCase()
    const environment = str(req.query.environment).trim().toLowerCase()
    const risk = str(req.query.risk).trim().toLowerCase()
    const status = str(req.query.status).trim().toLowerCase()
    const limit = Math.max(1, Math.min(200, num(req.query.limit) || 50))
    const offset = Math.max(0, num(req.query.offset))

    const filtered = intelligence.events.filter((event) => {
      if (environment && environment !== 'all' && event.environment.toLowerCase() !== environment) return false
      if (risk && risk !== 'all' && event.risk !== risk) return false
      if (status && status !== 'all' && event.quantumStatus !== status) return false
      if (search) {
        const haystack = `${event.assetName} ${event.algorithm} ${event.observedValue} ${event.operation} ${event.technical.host ?? ''} ${event.technical.cipherSuite ?? ''} ${event.technical.certificateFingerprint ?? ''}`.toLowerCase()
        if (!haystack.includes(search)) return false
      }
      return true
    })

    res.json({
      data: {
        events: filtered.slice(offset, offset + limit),
        total: filtered.length,
        offset,
        limit,
        window: intelligence.window,
      },
    })
  } catch (error) {
    console.error('Runtime crypto intelligence events error:', error)
    res.status(500).json({ error: { code: 'RUNTIME_INTEL_ERROR', message: 'Failed to load runtime activity' } })
  }
})

/**
 * GET /events/:id — lazily loaded detail for one observation (§29).
 *
 * The dashboard payload deliberately does not ship every technical field for
 * every row; the drawer fetches the one it needs when the user opens it.
 */
router.get('/events/:id', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const intelligence = await buildRuntimeIntel(token!, user!.id, { window: '30d', eventLimit: 500 })
    const event = intelligence.events.find((row) => row.id === req.params.id)
    if (!event) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Runtime observation not found' } })
    res.json({ data: event })
  } catch (error) {
    console.error('Runtime crypto intelligence event detail error:', error)
    res.status(500).json({ error: { code: 'RUNTIME_INTEL_ERROR', message: 'Failed to load observation detail' } })
  }
})

export default router
