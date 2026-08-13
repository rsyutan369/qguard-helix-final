/**
 * Tenant migration-cost assumptions — loader + `/api/v1/cost-assumptions` router.
 *
 * Every currency figure on the Migration Planner, Quantum Readiness Executive,
 * AI Migration Advisor and Executive Command Center is a planning estimate built
 * on the assumptions this module resolves. The maths lives in the pure
 * `src/lib/migration/cost-model.ts`; this file only handles persistence, tenant
 * isolation and validation.
 *
 * Degradation: `supabase/migration-cost-assumptions-schema.sql` may not be
 * applied yet. A missing table must NOT break every cost surface, so a failed
 * read falls back to the published defaults — and reports `source: 'default'`,
 * so the UI still tells the truth about where the numbers came from rather than
 * silently presenting defaults as the tenant's own.
 */
import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import {
  COST_ASSUMPTION_LIMITS,
  DEFAULT_COST_ASSUMPTIONS,
  describeCostAssumptions,
  resolveCostAssumptions,
  type CostAssumptions,
} from '@/lib/migration/cost-model'

const TABLE = 'migration_cost_assumptions'
const CACHE_TTL_MS = 15_000

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

const cache = new Map<string, { at: number; value: CostAssumptions }>()

export function invalidateCostAssumptions(userId: string) {
  cache.delete(userId)
}

/**
 * Resolve a tenant's assumptions, falling back to defaults on any failure.
 *
 * Shares the 15s single-flight window the snapshot caches use so a dashboard
 * that fans out to several endpoints does not re-read this row per request.
 */
export async function loadCostAssumptions(token: string, userId: string): Promise<CostAssumptions> {
  const cached = cache.get(userId)
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.value

  let value: CostAssumptions = { ...DEFAULT_COST_ASSUMPTIONS }
  try {
    const client = createAuthClient(token)
    if (client) {
      const { data, error } = await client.from(TABLE).select('*').eq('user_id', userId).maybeSingle()
      if (error) {
        // 42P01 = table missing (schema not applied yet). Anything else is a
        // real fault worth a log line, but neither may take the page down.
        console.warn(`[cost-assumptions] read skipped (${error.code || 'unknown'}): ${error.message || error}`)
      } else if (data) {
        value = resolveCostAssumptions(data as Record<string, unknown>)
      }
    }
  } catch (error) {
    console.warn('[cost-assumptions] read failed:', (error as Error)?.message || error)
  }

  cache.set(userId, { at: Date.now(), value })
  if (cache.size > 500) {
    const now = Date.now()
    for (const [key, entry] of cache) if (now - entry.at > CACHE_TTL_MS) cache.delete(key)
  }
  return value
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

const router = Router()

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

function payload(assumptions: CostAssumptions, persisted: boolean) {
  return {
    assumptions,
    defaults: DEFAULT_COST_ASSUMPTIONS,
    limits: COST_ASSUMPTION_LIMITS,
    disclosure: describeCostAssumptions(assumptions),
    persisted,
  }
}

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const assumptions = await loadCostAssumptions(token!, user!.id)
    res.json({ data: payload(assumptions, assumptions.source === 'tenant') })
  } catch (error) {
    res.status(500).json({
      error: { code: 'COST_ASSUMPTIONS_ERROR', message: error instanceof Error ? error.message : 'Failed to load cost assumptions' },
    })
  }
})

/** Numeric field or null. Rejects junk rather than silently coercing it to a
 *  default — a silently-ignored rate would show the tenant a number they
 *  believe they changed. */
function parseField(raw: unknown, name: string, limits: { min: number; max: number }, errors: string[]): number | null | undefined {
  if (raw === undefined) return undefined
  if (raw === null || raw === '') return null
  const value = Number(raw)
  if (!Number.isFinite(value)) {
    errors.push(`${name} must be a number`)
    return undefined
  }
  if (value < limits.min || value > limits.max) {
    errors.push(`${name} must be between ${limits.min} and ${limits.max}`)
    return undefined
  }
  return value
}

router.put('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const body = (req.body || {}) as Record<string, unknown>
    const errors: string[] = []

    const blended = parseField(body.blendedRateUsd, 'blendedRateUsd', COST_ASSUMPTION_LIMITS.blendedRateUsd, errors)
    const hours = parseField(body.hoursPerWeek, 'hoursPerWeek', COST_ASSUMPTION_LIMITS.hoursPerWeek, errors)
    const critical = parseField(body.valuePerCriticalAssetUsd, 'valuePerCriticalAssetUsd', COST_ASSUMPTION_LIMITS.valuePerCriticalAssetUsd, errors)
    const standard = parseField(body.valuePerStandardAssetUsd, 'valuePerStandardAssetUsd', COST_ASSUMPTION_LIMITS.valuePerStandardAssetUsd, errors)
    const budget = parseField(body.budgetUsd, 'budgetUsd', COST_ASSUMPTION_LIMITS.budgetUsd, errors)

    if (errors.length) {
      return res.status(400).json({ error: { code: 'INVALID_ASSUMPTIONS', message: errors.join('; ') } })
    }

    const currency = typeof body.currency === 'string' && body.currency.trim() ? body.currency.trim().toUpperCase().slice(0, 8) : 'USD'

    const row: Record<string, unknown> = { user_id: user!.id, currency, updated_at: new Date().toISOString() }
    // `undefined` = field absent from the request (leave as-is); `null` = the
    // tenant explicitly cleared it back to the published default.
    if (blended !== undefined) row.blended_rate_usd = blended
    if (hours !== undefined) row.hours_per_week = hours
    if (critical !== undefined) row.value_per_critical_asset_usd = critical
    if (standard !== undefined) row.value_per_standard_asset_usd = standard
    if (budget !== undefined) row.budget_usd = budget

    const client = createAuthClient(token!)
    if (!client) return res.status(500).json({ error: { code: 'NO_CLIENT', message: 'Database client unavailable' } })

    const { data, error } = await client.from(TABLE).upsert(row, { onConflict: 'user_id' }).select('*').maybeSingle()
    if (error) {
      // PostgREST reports an unknown relation as PGRST205 ("could not find the
      // table in the schema cache"), not the Postgres 42P01 you would expect —
      // checking only 42P01 surfaced "schema not applied" as a generic 500.
      const missingTable =
        String(error.code) === '42P01' ||
        String(error.code) === 'PGRST205' ||
        /could not find the table/i.test(String(error.message || ''))
      return res.status(missingTable ? 503 : 500).json({
        error: {
          code: missingTable ? 'SCHEMA_NOT_APPLIED' : 'COST_ASSUMPTIONS_WRITE_FAILED',
          message: missingTable
            ? 'Cost assumptions storage is not provisioned yet. Apply supabase/migration-cost-assumptions-schema.sql.'
            : error.message || 'Failed to save cost assumptions',
        },
      })
    }

    invalidateCostAssumptions(user!.id)
    const assumptions = resolveCostAssumptions((data as Record<string, unknown>) || row)
    cache.set(user!.id, { at: Date.now(), value: assumptions })
    res.json({ data: payload(assumptions, true) })
  } catch (error) {
    res.status(500).json({
      error: { code: 'COST_ASSUMPTIONS_ERROR', message: error instanceof Error ? error.message : 'Failed to save cost assumptions' },
    })
  }
})

/** Clear every override and return to the published defaults. */
router.delete('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    if (client) await client.from(TABLE).delete().eq('user_id', user!.id)
    invalidateCostAssumptions(user!.id)
    res.json({ data: payload({ ...DEFAULT_COST_ASSUMPTIONS }, false) })
  } catch (error) {
    res.status(500).json({
      error: { code: 'COST_ASSUMPTIONS_ERROR', message: error instanceof Error ? error.message : 'Failed to reset cost assumptions' },
    })
  }
})

export default router
