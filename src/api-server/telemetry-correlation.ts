import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildPortfolio } from './migration-planner'
import { buildCorrelationIntelligence, type CorrelationIntelligence } from '@/lib/telemetry/correlation-intelligence'
import type { Row } from '@/lib/migration/asset-intelligence'
import { streamLiveSnapshot } from './live-snapshot-stream'
import { createSourceLedger } from './source-ledger'

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

/*
 * Authorization header only. The subscription gateway reads the header, so a
 * `?token=` fallback let a request skip the Pro gate — and wrote the bearer
 * token into access logs and browser history. The page streams over fetch().
 */
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

const str = (v: unknown) => (typeof v === 'string' ? v : v == null ? '' : String(v))


const CACHE_TTL_MS = 15_000
const cache = new Map<string, { at: number; promise: Promise<CorrelationIntelligence> }>()

async function compute(token: string, userId: string, force: boolean): Promise<CorrelationIntelligence> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')
  const ledger = createSourceLedger('Telemetry correlation')

  const [portfolio, scannerEvidence, runtimeEvents, cryptoInventory, scannerAgents, connectorAccounts, scanSessions] = await Promise.all([
    buildPortfolio(token, userId, force),
    ledger.read(client, 'scanner_evidence', 'Scanner evidence', 3000, (q) =>
      q.select('id, agent_id, connector_account_id, source_type, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, key_size, raw_evidence, observed_at, created_at', { count: 'exact' }).eq('user_id', userId).order('observed_at', { ascending: false }).limit(3000),
    ),
    ledger.read(client, 'runtime_crypto_events', 'Runtime telemetry', 3000, (q) =>
      q.select('id, agent_id, connector_account_id, asset_id, asset_name, event_type, host, port, protocol, cipher_suite, key_exchange_algorithm, algorithm, metadata, observed_at, created_at', { count: 'exact' }).eq('user_id', userId).order('observed_at', { ascending: false }).limit(3000),
    ),
    ledger.read(client, 'crypto_inventory', 'CBOM components', 3000, (q) =>
      q.select('id, asset_id, item_type, name, algorithm, protocol, metadata, discovered_at, created_at', { count: 'exact' }).eq('user_id', userId).order('discovered_at', { ascending: false }).limit(3000),
    ),
    ledger.read(client, 'scanner_agents', 'Agent fleet', 250, (q) =>
      q.select('id, name, status, hostname, platform, last_seen_at, created_at, updated_at', { count: 'exact' }).eq('user_id', userId).limit(250),
    ),
    ledger.read(client, 'connector_accounts', 'Connectors', 400, (q) => q.select('id, provider, status', { count: 'exact' }).eq('user_id', userId).limit(400)),
    ledger.read(client, 'pqc_scan_sessions', 'Scan sessions', 60, (q) =>
      q.select('id, status, completed_at, created_at', { count: 'exact' }).eq('user_id', userId).order('completed_at', { ascending: false }).limit(60),
    ),
  ])

  return {
    ...buildCorrelationIntelligence({
      assets: portfolio.assets,
      scannerEvidence,
      runtimeEvents,
      cryptoInventory,
      scannerAgents,
      connectorAccounts,
      scanSessions,
    }),
    reads: ledger.reads,
  }
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

/** Full frame when the correlation changes, `correlation-unchanged` otherwise (live-snapshot-stream contract). */
router.get('/stream', (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  streamLiveSnapshot(req, res, { event: 'correlation', build: () => buildCorrelation(token!, user!.id), intervalMs: 20_000 })
})

export default router
