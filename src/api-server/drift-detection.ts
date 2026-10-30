import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildPortfolio } from './migration-planner'
import { buildDriftIntelligence, type DriftIntelligence } from '@/lib/drift/drift-intelligence'
import type { Row } from '@/lib/migration/asset-intelligence'
import { streamLiveSnapshot } from './live-snapshot-stream'
import { createSourceLedger } from './source-ledger'
import { SIMULATION_MARKER_SELECT } from '@/lib/migration/job-safety'

/**
 * QGuard Helix — Cryptographic Drift Detection router.
 *
 * Fetches only what a BASELINE COMPARISON needs: completed scan sessions, the
 * graded findings that carry `scan_session_id`, runtime downgrade telemetry and
 * the migration jobs that separate planned change from drift.
 *
 * The implementation this replaces queried nine tables and keyword-matched
 * their rows for the word "drift" — so it re-published the vulnerability
 * inventory under a different noun and never compared anything to anything.
 * Everything that page showed already existed on Quantum Risk Analysis.
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
const cache = new Map<string, { at: number; promise: Promise<DriftIntelligence> }>()

async function compute(token: string, userId: string, force: boolean): Promise<DriftIntelligence> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')
  const ledger = createSourceLedger('Drift detection')

  const [portfolio, scanSessions, scanResults, runtimeEvents, migrationJobs] = await Promise.all([
    buildPortfolio(token, userId, force),
    ledger.read(client, 'pqc_scan_sessions', 'Scan sessions', 60, (q) =>
      q.select('id, status, total_assets, scanned_assets, findings_count, started_at, completed_at, created_at').eq('user_id', userId).order('completed_at', { ascending: false }).limit(60),
    ),
    // Bounded to the findings of the sessions we can actually compare. Ordered
    // newest-first so a truncated result keeps the two most recent sessions.
    ledger.read(client, 'pqc_scan_results', 'Scan findings', 4000, (q) =>
      q.select('id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(4000),
    ),
    ledger.read(client, 'runtime_crypto_events', 'Runtime telemetry', 1000, (q) =>
      q.select('id, asset_id, asset_name, host, algorithm, key_exchange_algorithm, downgrade_detected, observed_at, created_at').eq('user_id', userId).eq('downgrade_detected', true).order('observed_at', { ascending: false }).limit(1000),
    ),
    ledger.read(client, 'migration_jobs', 'Migration jobs', 400, (q) =>
      q.select(`id, asset_id, name, job_type, status, target_algorithm, completed_at, updated_at, created_at, ${SIMULATION_MARKER_SELECT}`).eq('user_id', userId).order('updated_at', { ascending: false }).limit(400),
    ),
  ])

  return {
    ...buildDriftIntelligence({
      scanSessions,
      scanResults,
      runtimeEvents,
      migrationJobs,
      assets: portfolio.assets,
    }),
    reads: ledger.reads,
  }
}

export async function buildDrift(token: string, userId: string, force = false): Promise<DriftIntelligence> {
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
    res.json({ data: await buildDrift(token!, user!.id, str(req.query.refresh) === '1') })
  } catch (error) {
    console.error('Drift detection error:', error)
    res.status(500).json({ error: { code: 'DRIFT_ERROR', message: 'Failed to compute cryptographic drift' } })
  }
})

/** Full frame when the comparison changes, `drift-unchanged` otherwise (live-snapshot-stream contract). */
router.get('/stream', (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  streamLiveSnapshot(req, res, { event: 'drift', build: () => buildDrift(token!, user!.id), intervalMs: 20_000 })
})

export default router
