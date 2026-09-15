/**
 * Reprice EXISTING PayPal billing plans to match src/lib/billing/plan-pricing.ts.
 *
 * A PayPal plan carries its own price, so changing the price in code is not
 * enough: buyers redirected to PayPal keep seeing the amount stored on the plan
 * until the plan itself is updated. This tool reads every PAYPAL_PLAN_* id from
 * .env, compares the live price to our catalog, and (with --apply) calls
 * POST /v1/billing/plans/{id}/update-pricing-schemes.
 *
 * Usage:
 *   npx tsx tools/paypal-update-pricing.ts                 # dry run, all tiers
 *   npx tsx tools/paypal-update-pricing.ts --tier Starter  # limit to one tier
 *   npx tsx tools/paypal-update-pricing.ts --apply         # write the changes
 *
 * Respects PAYPAL_ENV=sandbox|live (default live).
 *
 * Note on existing subscribers: PayPal applies a new pricing scheme from the
 * subscriber's NEXT billing cycle. Price DECREASES apply automatically; an
 * increase can require buyer consent, which PayPal requests on its side.
 */
import 'dotenv/config'
import { PLAN_PRICING, PLAN_TIERS, planChargeAmount, type PlanCycle, type PlanTier } from '../src/lib/billing/plan-pricing'

const ENV = String(process.env.PAYPAL_ENV || 'live').toLowerCase() === 'sandbox' ? 'sandbox' : 'live'
const BASE = ENV === 'sandbox' ? 'https://api-m.sandbox.paypal.com' : 'https://api-m.paypal.com'
const CLIENT_ID = process.env.PAYPAL_CLIENT_ID || ''
const SECRET = process.env.PAYPAL_SECRET_KEY || process.env.PAYPAL_CLIENT_SECRET || ''

const APPLY = process.argv.includes('--apply')
const TIER_ARG = (() => {
  const index = process.argv.indexOf('--tier')
  if (index === -1) return null
  const raw = String(process.argv[index + 1] || '').toLowerCase()
  return PLAN_TIERS.find((tier) => tier.toLowerCase() === raw) || null
})()

const CYCLES: PlanCycle[] = ['monthly', 'yearly']

async function getToken(): Promise<string> {
  const auth = Buffer.from(`${CLIENT_ID}:${SECRET}`).toString('base64')
  const res = await fetch(`${BASE}/v1/oauth2/token`, {
    method: 'POST',
    headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials',
  })
  const json: any = await res.json().catch(() => ({}))
  if (!res.ok || !json?.access_token) {
    throw new Error(`Authentication failed (HTTP ${res.status}): ${JSON.stringify(json)}`)
  }
  return json.access_token
}

async function getPlan(planId: string, token: string): Promise<any> {
  const res = await fetch(`${BASE}/v1/billing/plans/${encodeURIComponent(planId)}`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  const json: any = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(`GET plan ${planId} failed (HTTP ${res.status}): ${JSON.stringify(json)}`)
  return json
}

async function updatePricing(planId: string, sequence: number, value: string, token: string): Promise<void> {
  const res = await fetch(`${BASE}/v1/billing/plans/${encodeURIComponent(planId)}/update-pricing-schemes`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      pricing_schemes: [
        {
          billing_cycle_sequence: sequence,
          pricing_scheme: { fixed_price: { value, currency_code: 'USD' } },
        },
      ],
    }),
  })
  if (res.status === 204 || res.ok) return
  const json: any = await res.json().catch(() => ({}))
  throw new Error(`update-pricing-schemes ${planId} failed (HTTP ${res.status}): ${JSON.stringify(json)}`)
}

/** True when two PayPal money strings are the same amount ("1.0" === "1.00"). */
function sameAmount(a: string, b: string): boolean {
  const left = Number(a)
  const right = Number(b)
  if (!Number.isFinite(left) || !Number.isFinite(right)) return false
  return Math.round(left * 100) === Math.round(right * 100)
}

async function main(): Promise<void> {
  if (!CLIENT_ID || !SECRET) {
    console.error('ERROR: PAYPAL_CLIENT_ID / PAYPAL_SECRET_KEY are missing from .env')
    process.exit(1)
  }

  const tiers: PlanTier[] = TIER_ARG ? [TIER_ARG] : PLAN_TIERS
  console.log(`[paypal-pricing] Environment: ${ENV} (${BASE})`)
  console.log(`[paypal-pricing] Mode: ${APPLY ? 'APPLY (writes to PayPal)' : 'dry run (no changes)'}`)
  console.log(`[paypal-pricing] Tiers: ${tiers.join(', ')}\n`)

  const token = await getToken()
  let changed = 0
  let missing = 0
  let alreadyCorrect = 0

  for (const tier of tiers) {
    for (const cycle of CYCLES) {
      const key = `PAYPAL_PLAN_${tier.toUpperCase()}_${cycle.toUpperCase()}`
      const planId = process.env[key] || ''
      const expected = planChargeAmount(tier, cycle).toFixed(2)
      const unit = cycle === 'yearly' ? 'yr' : 'mo'

      if (!planId) {
        console.log(`  ${tier} ${cycle}: SKIPPED — ${key} is not set in .env`)
        missing += 1
        continue
      }

      const plan = await getPlan(planId, token)
      const regular = (plan.billing_cycles || []).find((entry: any) => entry?.tenure_type === 'REGULAR')
        || (plan.billing_cycles || [])[0]
      const current = String(regular?.pricing_scheme?.fixed_price?.value ?? '')
      const sequence = Number(regular?.sequence ?? 1)

      // PayPal returns amounts unpadded ("1.0"), so compare numerically.
      if (sameAmount(current, expected)) {
        console.log(`  ${tier} ${cycle}: OK — already $${expected}/${unit} (${planId}, status ${plan.status})`)
        alreadyCorrect += 1
        continue
      }

      console.log(`  ${tier} ${cycle}: $${current || '?'} -> $${expected}/${unit} (${planId}, status ${plan.status})`)
      if (APPLY) {
        await updatePricing(planId, sequence, expected, token)
        const after = await getPlan(planId, token)
        const afterRegular = (after.billing_cycles || []).find((entry: any) => entry?.tenure_type === 'REGULAR')
          || (after.billing_cycles || [])[0]
        const afterValue = String(afterRegular?.pricing_scheme?.fixed_price?.value ?? '')
        if (!sameAmount(afterValue, expected)) {
          throw new Error(`${tier} ${cycle}: PayPal still reports $${afterValue} after update`)
        }
        console.log(`    verified on PayPal: $${afterValue}/${unit}`)
      }
      changed += 1
    }
  }

  console.log(`\n[paypal-pricing] ${APPLY ? 'updated' : 'would update'}: ${changed}; already correct: ${alreadyCorrect}; missing plan id: ${missing}`)
  if (!APPLY && changed > 0) console.log('[paypal-pricing] Re-run with --apply to write these to PayPal.')
  console.log(`[paypal-pricing] Catalog: ${PLAN_TIERS.map((tier) => `${tier} $${PLAN_PRICING[tier].monthly}/mo, $${PLAN_PRICING[tier].yearlyPerMonth * 12}/yr`).join(' | ')}`)
}

main().catch((err) => {
  console.error('[paypal-pricing] ERROR:', err instanceof Error ? err.message : err)
  process.exit(1)
})
