import { Router, Request, Response, NextFunction } from 'express'
import { getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { buildPortfolio } from './migration-planner'
import {
  buildQuantumRiskIntelligence,
  type QuantumRiskIntelligence,
} from '@/lib/quantum-risk/risk-intelligence'

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

export async function buildQuantumRisk(token: string, userId: string, force = false): Promise<QuantumRiskIntelligence> {
  const [snapshot, portfolio] = await Promise.all([buildSnapshot(token, userId), buildPortfolio(token, userId, force)])
  return buildQuantumRiskIntelligence({
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
      send('quantum-risk', await buildQuantumRisk(token!, user!.id))
    } catch (error) {
      send('quantum-risk-error', { message: error instanceof Error ? error.message : 'Risk assessment unavailable' })
    }
  }

  void push()
  const interval = setInterval(() => void push(), 15_000)
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': heartbeat\n\n')
  }, 25_000)

  req.on('close', () => {
    closed = true
    clearInterval(interval)
    clearInterval(heartbeat)
  })
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
