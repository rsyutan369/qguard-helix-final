import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildPortfolio } from './migration-planner'
import { buildCorrelationIntelligence, type CorrelationIntelligence } from '@/lib/telemetry/correlation-intelligence'
import type { Row } from '@/lib/migration/asset-intelligence'

/**
 * QGuard Helix — Telemetry Correlation router.
 *
 * Reads the independent observation channels — scanner evidence, runtime crypto
 * telemetry and the discovered CBOM — plus the source registries (collector
 * agents, cloud connectors, scan sessions), and hands them to the pure engine.
 *
 * Coverage is measured against the SHARED asset portfolio, not against whatever
 * happened to report. That is the difference between "we see 90% of what we
 * see" and "we see 30% of the estate", and it is why the blind-spot list is the
 * most important thing on the page.
 */

const router = Router()

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

function tokenFromRequest(req: Request): string | null {
  const headerToken = getToken(req)
  if (headerToken) return headerToken
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function safeRows(client: any, table: string, build: (query: any) => any): Promise<Row[]> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`Telemetry correlation ${table} query skipped:`, error.message || error)
      return []
    }
    return (data as Row[]) || []
  } catch (error) {
    console.warn(`Telemetry correlation ${table} query failed:`, (error as Error)?.message || error)
    return []
  }
}

const CACHE_TTL_MS = 15_000
const cache = new Map<string, { at: number; promise: Promise<CorrelationIntelligence> }>()

async function compute(token: string, userId: string, force: boolean): Promise<CorrelationIntelligence> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  const [portfolio, scannerEvidence, runtimeEvents, cryptoInventory, scannerAgents, connectorAccounts, scanSessions] = await Promise.all([
    buildPortfolio(token, userId, force),
    safeRows(client, 'scanner_evidence', (q) =>
      q.select('id, agent_id, connector_account_id, source_type, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, key_size, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(3000),
    ),
    safeRows(client, 'runtime_crypto_events', (q) =>
      q.select('id, agent_id, connector_account_id, asset_id, asset_name, host, protocol, cipher_suite, key_exchange_algorithm, algorithm, observed_at, created_at').eq('user_id', userId).order('observed_at', { ascending: false }).limit(3000),
    ),
    safeRows(client, 'crypto_inventory', (q) =>
      q.select('id, asset_id, item_type, name, algorithm, protocol, discovered_at, created_at').eq('user_id', userId).order('discovered_at', { ascending: false }).limit(3000),
    ),
    safeRows(client, 'scanner_agents', (q) =>
      q.select('id, name, status, hostname, platform, last_seen_at, created_at, updated_at').eq('user_id', userId).limit(250),
    ),
    safeRows(client, 'connector_accounts', (q) => q.select('id, provider, status').eq('user_id', userId).limit(400)),
    safeRows(client, 'pqc_scan_sessions', (q) =>
      q.select('id, status, completed_at, created_at').eq('user_id', userId).order('completed_at', { ascending: false }).limit(60),
    ),
  ])

  return buildCorrelationIntelligence({
    assets: portfolio.assets,
    scannerEvidence,
    runtimeEvents,
    cryptoInventory,
    scannerAgents,
    connectorAccounts,
    scanSessions,
  })
}

export async function buildCorrelation(token: string, userId: string, force = false): Promise<CorrelationIntelligence> {
  const cached = cache.get(userId)
  if (!force && cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.promise
  const promise = compute(token, userId, force)
  cache.set(userId, { at: Date.now(), promise })
  promise.catch(() => cache.delete(userId))
  if (cache.size > 500) {
    const now = Date.now()
    for (const [key, value] of cache) if (now - value.at > CACHE_TTL_MS) cache.delete(key)
  }
  return promise
}

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    res.json({ data: await buildCorrelation(token!, user!.id, str(req.query.refresh) === '1') })
  } catch (error) {
    console.error('Telemetry correlation error:', error)
    res.status(500).json({ error: { code: 'CORRELATION_ERROR', message: 'Failed to compute telemetry correlation' } })
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
  const send = (event: string, data: unknown) => {
    if (!closed) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  }
  send('connected', { at: new Date().toISOString() })

  const push = async () => {
    try {
      send('correlation', await buildCorrelation(token!, user!.id))
    } catch (error) {
      send('correlation-error', { message: error instanceof Error ? error.message : 'Telemetry correlation unavailable' })
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

export default router
