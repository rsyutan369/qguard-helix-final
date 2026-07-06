/**
 * One-time PayPal provisioning.
 *
 * Creates a single PayPal Product and 8 subscription billing plans
 * (4 tiers x monthly/yearly) using the credentials in .env, then prints the
 * PAYPAL_PLAN_* env lines to paste into .env.
 *
 * Creating plans does NOT charge anyone — it only defines the plans. Nobody is
 * billed until a buyer approves a subscription.
 *
 * Usage:  npx tsx tools/paypal-setup.ts
 *
 * Respects PAYPAL_ENV=sandbox|live (default live). Pricing mirrors the landing
 * pricing section (src/pages/Landing.tsx). Yearly bills the discounted monthly
 * rate x 12, once per year.
 */
import 'dotenv/config'

const ENV = String(process.env.PAYPAL_ENV || 'live').toLowerCase() === 'sandbox' ? 'sandbox' : 'live'
const BASE = ENV === 'sandbox' ? 'https://api-m.sandbox.paypal.com' : 'https://api-m.paypal.com'
const CLIENT_ID = process.env.PAYPAL_CLIENT_ID || ''
const SECRET = process.env.PAYPAL_SECRET_KEY || process.env.PAYPAL_CLIENT_SECRET || ''

const TIERS = [
  { name: 'Starter', monthly: 3, yearlyPerMonth: 3 },
  { name: 'Basic', monthly: 8, yearlyPerMonth: 5 },
  { name: 'Pro', monthly: 30, yearlyPerMonth: 20 },
  { name: 'Elite', monthly: 199, yearlyPerMonth: 150 },
] as const

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

async function post(pathname: string, token: string, body: unknown, requestId: string): Promise<any> {
  const res = await fetch(`${BASE}${pathname}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'PayPal-Request-Id': requestId,
    },
    body: JSON.stringify(body),
  })
  const json: any = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(`${pathname} failed (HTTP ${res.status}): ${JSON.stringify(json)}`)
  }
  return json
}

async function main(): Promise<void> {
  if (!CLIENT_ID || !SECRET) {
    console.error('ERROR: PAYPAL_CLIENT_ID / PAYPAL_SECRET_KEY are missing from .env')
    process.exit(1)
  }

  console.log(`[paypal-setup] Environment: ${ENV} (${BASE})`)
  const token = await getToken()
  console.log('[paypal-setup] Authenticated OK')

  const product = await post(
    '/v1/catalogs/products',
    token,
    {
      name: 'QGuard Helix',
      description: 'QGuard Helix Post-Quantum Cryptography platform subscription',
      type: 'SERVICE',
      category: 'SOFTWARE',
    },
    `qguard-product-${Date.now()}`,
  )
  console.log(`[paypal-setup] Product created: ${product.id}`)

  const envLines: string[] = [`PAYPAL_ENV=${ENV}`]

  for (const tier of TIERS) {
    for (const cycle of ['monthly', 'yearly'] as const) {
      const isYearly = cycle === 'yearly'
      const value = isYearly ? tier.yearlyPerMonth * 12 : tier.monthly
      const plan = await post(
        '/v1/billing/plans',
        token,
        {
          product_id: product.id,
          name: `QGuard ${tier.name} ${isYearly ? 'Yearly' : 'Monthly'}`,
          description: `QGuard Helix ${tier.name} plan billed ${isYearly ? 'annually' : 'monthly'}`,
          status: 'ACTIVE',
          billing_cycles: [
            {
              frequency: { interval_unit: isYearly ? 'YEAR' : 'MONTH', interval_count: 1 },
              tenure_type: 'REGULAR',
              sequence: 1,
              total_cycles: 0,
              pricing_scheme: { fixed_price: { value: value.toFixed(2), currency_code: 'USD' } },
            },
          ],
          payment_preferences: {
            auto_bill_outstanding: true,
            setup_fee_failure_action: 'CONTINUE',
            payment_failure_threshold: 2,
          },
        },
        `qguard-${tier.name}-${cycle}-${Date.now()}`,
      )
      const key = `PAYPAL_PLAN_${tier.name.toUpperCase()}_${cycle.toUpperCase()}`
      console.log(`[paypal-setup]   ${tier.name} ${cycle}: ${plan.id}  ($${value.toFixed(2)}/${isYearly ? 'yr' : 'mo'})`)
      envLines.push(`${key}=${plan.id}`)
    }
  }

  console.log('\n================ Add these lines to your .env ================\n')
  console.log(envLines.join('\n'))
  console.log('\n=============================================================\n')
}

main().catch((err) => {
  console.error('[paypal-setup] ERROR:', err instanceof Error ? err.message : err)
  process.exit(1)
})
