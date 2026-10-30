import { Router, Request, Response, NextFunction } from 'express'
import { getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { buildPortfolio } from './migration-planner'
import {
  buildQuantumRiskIntelligence,
  type QuantumRiskIntelligence,
} from '@/lib/quantum-risk/risk-intelligence'
import { streamLiveSnapshot } from './live-snapshot-stream'
import { createSourceLedger } from './source-ledger'

/**
 * QGuard Helix — Quantum Risk Scoring aggregation router.
 *
 * Fetches NOTHING of its own. Both of its inputs are already-cached, canonical
 * platform models:
 *
 *   - `buildSnapshot`  — the Quantum Readiness snapshot, which owns the quantum
 *     risk, HNDL, crypto-exposure, readiness and PQC-adoption scores, the risk
 *     distribution, the risk factors, the critical findings and the trend.
 *   - `buildPortfolio` — the shared asset-intelligence portfolio, which owns
 *     per-asset risk, posture, HNDL, blast radius and migration state.
 *
 * That is deliberate and is the whole point of the refactor. The previous
 * implementation issued its own eleven queries and computed a rival quantum
 * risk score, so the page dedicated to quantum risk was the one surface that
 * disagreed with the platform's quantum risk. With no independent fetch and no
 * independent headline, disagreement is now structurally impossible.
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

/*
 * Per-tenant single-flight over the (already cached) upstream models, so the
 * page, its stream and the asset feed project ONE object per window — which is
 * also what lets the stream's fingerprint be computed once, not per client.
 */
const TTL_MS = 10_000
const cache = new Map<string, { at: number; promise: Promise<QuantumRiskIntelligence> }>()

export function buildQuantumRisk(token: string, userId: string, force = false): Promise<QuantumRiskIntelligence> {
  const cached = cache.get(userId)
  if (!force && cached && Date.now() - cached.at < TTL_MS) return cached.promise
  const promise = computeQuantumRisk(token, userId, force)
  cache.set(userId, { at: Date.now(), promise })
  promise.catch(() => cache.delete(userId))
  if (cache.size > 500) {
    const now = Date.now()
    for (const [key, value] of cache) if (now - value.at > TTL_MS) cache.delete(key)
  }
  return promise
}

async function computeQuantumRisk(token: string, userId: string, force: boolean): Promise<QuantumRiskIntelligence> {
  const [snapshot, portfolio] = await Promise.all([buildSnapshot(token, userId), buildPortfolio(token, userId, force)])
  // No direct table read here: both inputs are upstream models that throw on
  // failure (a 500 + hard-error panel), so what reaches this point was read.
  const ledger = createSourceLedger('Quantum risk')
  ledger.note('quantum_readiness', 'Quantum Readiness assessment', snapshot.hasData ? 'ok' : 'empty', snapshot.inventory.assetsAssessed, snapshot.hasData ? `${snapshot.inventory.assetsAssessed} asset(s) assessed.` : 'No assessment recorded yet.')
  ledger.note('asset_portfolio', 'Asset portfolio', portfolio.assets.length ? 'ok' : 'empty', portfolio.assets.length, portfolio.assets.length ? `${portfolio.assets.length} asset(s) read.` : 'No asset recorded.')
  const model = buildQuantumRiskIntelligence({
    snapshot: {
      hasData: snapshot.hasData,
      lastAssessmentAt: snapshot.lastAssessmentAt,
      scores: {
        quantumRisk: snapshot.scores.quantumRisk,
        quantumRiskLevel: snapshot.scores.quantumRiskLevel,
        hndlRisk: snapshot.scores.hndlRisk,
        hndlRiskLevel: snapshot.scores.hndlRiskLevel,
        cryptoExposure: snapshot.scores.cryptoExposure,
        cryptoExposureLevel: snapshot.scores.cryptoExposureLevel,
        quantumReadiness: snapshot.scores.quantumReadiness,
        quantumReadinessLevel: snapshot.scores.quantumReadinessLevel,
        pqcAdoption: snapshot.scores.pqcAdoption,
      },
      inventory: {
        assetsAssessed: snapshot.inventory.assetsAssessed,
        cryptoComponents: snapshot.inventory.cryptoComponents,
        vulnerableComponents: snapshot.inventory.vulnerableComponents,
        quantumVulnerableAssets: snapshot.inventory.quantumVulnerableAssets,
        certificatesAnalyzed: snapshot.inventory.certificatesAnalyzed,
      },
      riskDistribution: snapshot.riskDistribution,
      riskFactors: snapshot.riskFactors,
      criticalFindings: snapshot.criticalFindings as unknown as Array<Record<string, unknown>>,
      riskTrend: snapshot.riskTrend,
    },
    assets: portfolio.assets,
  })
  return { ...model, reads: ledger.reads }
}

/* ------------------------------------------------------------------ */
/* Routes                                                              */
/* ------------------------------------------------------------------ */

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const data = await buildQuantumRisk(token!, user!.id, str(req.query.refresh) === '1')
    res.json({ data })
  } catch (error) {
    console.error('Quantum risk scoring error:', error)
    res.status(500).json({ error: { code: 'QUANTUM_RISK_ERROR', message: 'Failed to compute the quantum risk assessment' } })
  }
})

/**
 * GET /stream — Server-Sent Events.
 *
 * Both upstream models are per-tenant single-flight cached, so every connected
 * dashboard of a tenant collapses onto one computation per window.
 */
router.get('/stream', (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  streamLiveSnapshot(req, res, { event: 'quantum-risk', build: () => buildQuantumRisk(token!, user!.id), intervalMs: 15_000 })
})

/** GET /assets — server-side filtered, paginated asset risk feed (§26). */
router.get('/assets', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const intelligence = await buildQuantumRisk(token!, user!.id)

    const search = str(req.query.search).trim().toLowerCase()
    const environment = str(req.query.environment).trim().toLowerCase()
    const owner = str(req.query.owner).trim()
    const criticality = str(req.query.criticality).trim().toLowerCase()
    const level = str(req.query.level).trim().toLowerCase()
    const limit = Math.max(1, Math.min(200, Number(req.query.limit) || 50))
    const offset = Math.max(0, Number(req.query.offset) || 0)

    const filtered = intelligence.assets.filter((row) => {
      if (environment && environment !== 'all' && row.environment.toLowerCase() !== environment) return false
      if (owner && owner !== 'all' && row.owner !== owner) return false
      if (criticality && criticality !== 'all' && row.businessCriticality.toLowerCase() !== criticality) return false
      if (level && level !== 'all') {
        if (level === 'unassessed') {
          if (row.state !== 'unassessed') return false
        } else if (row.state !== 'assessed' || !row.riskLevel.toLowerCase().includes(level)) return false
      }
      if (search && !`${row.name} ${row.type} ${row.owner} ${row.topAlgorithms.join(' ')}`.toLowerCase().includes(search)) return false
      return true
    })

    res.json({ data: { assets: filtered.slice(offset, offset + limit), total: filtered.length, offset, limit } })
  } catch (error) {
    console.error('Quantum risk asset feed error:', error)
    res.status(500).json({ error: { code: 'QUANTUM_RISK_ERROR', message: 'Failed to load the asset risk feed' } })
  }
})

export default router
