import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { buildScannerIntelligence } from './scanner'
import { buildSharedResponsibility } from '@/lib/shared-responsibility'
import type {
  OwnershipFinding,
  SharedResponsibilityIntelligence,
} from '@/lib/shared-responsibility'
import { buildOwnershipInputs } from './shared-responsibility-inputs'

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

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

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
const recordOf = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}

async function loadConnectorProviders(token: string, userId: string): Promise<string[]> {
  try {
    const client = createAuthClient(token)
    if (!client) return []
    const { data, error } = await client
      .from('connector_accounts')
      .select('provider')
      .eq('user_id', userId)
      .limit(400)
    if (error || !Array.isArray(data)) return []
    return (data as Record<string, unknown>[]).map((r) => str(r.provider)).filter(Boolean)
  } catch {
    return []
  }
}

interface IntelligenceBundle {
  intelligence: SharedResponsibilityIntelligence
  findingsById: Map<string, OwnershipFinding>
  baseline: { quantumReadiness: number; quantumReadinessLevel: string }
}

async function computeMigrationIntelligence(token: string, userId: string): Promise<IntelligenceBundle> {
  const [snapshotRes, intelRes, connectorProviders] = await Promise.allSettled([
    buildSnapshot(token, userId),
    buildScannerIntelligence(token, userId),
    loadConnectorProviders(token, userId),
  ])

  const snapshot = snapshotRes.status === 'fulfilled' ? snapshotRes.value : {}
  const intel = intelRes.status === 'fulfilled' ? intelRes.value : {}
  const connectors = connectorProviders.status === 'fulfilled' ? connectorProviders.value : []

  const scores = recordOf(recordOf(snapshot).scores)
  const baselineOverall = Number(scores.quantumReadiness)

  const inputs = buildOwnershipInputs(intel, snapshot)

  const intelligence = buildSharedResponsibility(inputs, {
    context: { connectorProviders: connectors },
    baselineOverall: Number.isFinite(baselineOverall) ? baselineOverall : undefined,
    maxFindings: 200,
  })

  const findingsById = new Map<string, OwnershipFinding>()
  for (const f of intelligence.findings) findingsById.set(f.id, f)

  return {
    intelligence,
    findingsById,
    baseline: {
      quantumReadiness: Number.isFinite(baselineOverall) ? Math.round(baselineOverall) : intelligence.readiness.overall.score,
      quantumReadinessLevel: str(scores.quantumReadinessLevel) || intelligence.readiness.overall.level,
    },
  }
}

/**
 * Per-tenant short-TTL single-flight cache. Collapses the dashboard's fetch/SSE
 * fan-out into one computation per window and gives every consumer the SAME
 * authoritative model within it. Failures are never cached.
 */
const CACHE_TTL_MS = 15_000
const cache = new Map<string, { at: number; promise: Promise<IntelligenceBundle> }>()

function buildMigrationIntelligence(token: string, userId: string): Promise<IntelligenceBundle> {
  const cached = cache.get(userId)
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.promise
  const promise = computeMigrationIntelligence(token, userId)
  cache.set(userId, { at: Date.now(), promise })
  promise.catch(() => cache.delete(userId))
  if (cache.size > 500) {
    const now = Date.now()
    for (const [key, value] of cache) if (now - value.at > CACHE_TTL_MS) cache.delete(key)
  }
  return promise
}

router.get('/', async (req: Request, res: Response) => {
  const { user, token } = req as AuthedRequest
  try {
    const { intelligence, baseline } = await buildMigrationIntelligence(token!, user!.id)
    res.json({ ...intelligence, baseline })
  } catch (error) {
    res.status(500).json({ error: { code: 'MIGRATION_INTELLIGENCE_FAILED', message: (error as Error)?.message || 'Failed to build migration intelligence' } })
  }
})

router.get('/matrix', async (req: Request, res: Response) => {
  const { user, token } = req as AuthedRequest
  try {
    const { intelligence } = await buildMigrationIntelligence(token!, user!.id)
    res.json({ generatedAt: intelligence.generatedAt, hasData: intelligence.hasData, matrix: intelligence.matrix })
  } catch (error) {
    res.status(500).json({ error: { code: 'MIGRATION_INTELLIGENCE_FAILED', message: (error as Error)?.message || 'Failed to build matrix' } })
  }
})

router.get('/waves', async (req: Request, res: Response) => {
  const { user, token } = req as AuthedRequest
  try {
    const { intelligence } = await buildMigrationIntelligence(token!, user!.id)
    res.json({ generatedAt: intelligence.generatedAt, hasData: intelligence.hasData, waves: intelligence.waves })
  } catch (error) {
    res.status(500).json({ error: { code: 'MIGRATION_INTELLIGENCE_FAILED', message: (error as Error)?.message || 'Failed to build waves' } })
  }
})

router.get('/finding/:id', async (req: Request, res: Response) => {
  const { user, token } = req as AuthedRequest
  try {
    const { findingsById } = await buildMigrationIntelligence(token!, user!.id)
    const finding = findingsById.get(req.params.id)
    if (!finding) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Finding not found in current intelligence window' } })
    res.json({ finding })
  } catch (error) {
    res.status(500).json({ error: { code: 'MIGRATION_INTELLIGENCE_FAILED', message: (error as Error)?.message || 'Failed to load finding' } })
  }
})

router.get('/stream', async (req: Request, res: Response) => {
  const { user, token } = req as AuthedRequest
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  // Matches every other SSE route: tells buffering proxies to stream through.
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()

  let closed = false
  const emit = async () => {
    if (closed) return
    try {
      const { intelligence, baseline } = await buildMigrationIntelligence(token!, user!.id)
      if (!closed) res.write(`event: migration-intelligence\ndata: ${JSON.stringify({ ...intelligence, baseline })}\n\n`)
    } catch (error) {
      if (!closed) res.write(`event: error\ndata: ${JSON.stringify({ message: (error as Error)?.message || 'stream error' })}\n\n`)
    }
  }

  await emit()
  const refresh = setInterval(emit, 30000)
  const heartbeat = setInterval(() => { if (!closed) res.write(': heartbeat\n\n') }, 25000)
  req.on('close', () => { closed = true; clearInterval(refresh); clearInterval(heartbeat) })
})

export default router
