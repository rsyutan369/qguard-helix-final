/**
 * Offline + live checks for the `billing` Edge Function.
 *
 *   npx tsx tools/billing-edge-check.ts          # pure logic (no network)
 *   npx tsx tools/billing-edge-check.ts --live   # also probe the deployed function
 *
 * The logic module is runtime-agnostic precisely so it can be exercised here
 * under Node without a Deno toolchain. The live probe never sends a user token
 * or a PayPal signature: it proves routing, CORS and the auth/verification
 * gates, not payment flows.
 */
import assert from 'node:assert/strict'
import {
  activationRow,
  appOrigin,
  approvalLink,
  bearerToken,
  configurationReport,
  invoiceRow,
  isPaypalSubscriptionId,
  mapPaypalStatus,
  normalizeCycle,
  normalizeTier,
  planInfoFromId,
  routeOf,
  webhookVerificationBody,
} from '../supabase/functions/billing/logic'

const results: Array<{ name: string; ok: boolean; detail?: string }> = []
function check(name: string, fn: () => void) {
  try {
    fn()
    results.push({ name, ok: true })
  } catch (error) {
    results.push({ name, ok: false, detail: error instanceof Error ? error.message : String(error) })
  }
}

const USER = '5b0c6f7e-1c2d-4e5f-8a9b-0c1d2e3f4a5b'
const ENV: Record<string, string> = {
  PAYPAL_CLIENT_ID: 'client',
  PAYPAL_SECRET_KEY: 'secret',
  PAYPAL_PLAN_STARTER_MONTHLY: 'P-STARTER-M',
  PAYPAL_PLAN_STARTER_YEARLY: 'P-STARTER-Y',
  PAYPAL_PLAN_PRO_MONTHLY: 'P-PRO-M',
}
const env = (key: string) => ENV[key]

check('routes resolve with or without the gateway prefix', () => {
  assert.equal(routeOf('/billing/api/v1/paypal/subscribe'), '/api/v1/paypal/subscribe')
  assert.equal(routeOf('/functions/v1/billing/api/v1/paypal/subscribe'), '/api/v1/paypal/subscribe')
  // The literal word "billing" inside the route must survive.
  assert.equal(routeOf('/billing/api/v1/billing/subscription/actions'), '/api/v1/billing/subscription/actions')
  assert.equal(routeOf('/billing'), '/')
  assert.equal(routeOf('/billing/health/'), '/health')
})

check('tiers and cycles normalise the way the Express API does', () => {
  assert.equal(normalizeTier('pro'), 'Pro')
  assert.equal(normalizeTier(' Elite '), 'Elite')
  assert.equal(normalizeTier('platinum'), null)
  assert.equal(normalizeCycle('yearly'), 'yearly')
  assert.equal(normalizeCycle('annual'), 'yearly')
  assert.equal(normalizeCycle(undefined), 'monthly')
})

check('plan ids map back to tier + cycle and nothing else', () => {
  assert.deepEqual(planInfoFromId(env, 'P-PRO-M'), { tier: 'Pro', cycle: 'monthly' })
  assert.deepEqual(planInfoFromId(env, 'P-STARTER-Y'), { tier: 'Starter', cycle: 'yearly' })
  assert.equal(planInfoFromId(env, 'P-UNKNOWN'), null)
  assert.equal(planInfoFromId(env, undefined), null)
})

check('health report exposes booleans only — never ids or secrets', () => {
  const report = configurationReport(env)
  const text = JSON.stringify(report)
  assert.equal(report.configured, true)
  assert.equal(report.plans.pro_monthly, true)
  assert.equal(report.plans.elite_yearly, false)
  for (const value of Object.values(ENV)) assert.ok(!text.includes(value), `health leaked ${value}`)
})

check('return URLs use a fixed origin, never a request header', () => {
  assert.equal(appOrigin(() => undefined), 'https://qguardhelix.com')
  assert.equal(appOrigin((key) => (key === 'APP_ORIGIN' ? 'https://example.test/' : undefined)), 'https://example.test')
})

check('only a Bearer header yields a token', () => {
  assert.equal(bearerToken('Bearer abc'), 'abc')
  assert.equal(bearerToken('bearer abc'), null)
  assert.equal(bearerToken('Bearer '), null)
  assert.equal(bearerToken(null), null)
})

check('PayPal statuses map onto the database vocabulary', () => {
  assert.equal(mapPaypalStatus('ACTIVE'), 'active')
  assert.equal(mapPaypalStatus('APPROVAL_PENDING'), 'incomplete')
  assert.equal(mapPaypalStatus('CANCELLED'), 'cancelled')
  assert.equal(mapPaypalStatus('weird'), null)
})

check('subscription references are validated before reaching PayPal', () => {
  assert.equal(isPaypalSubscriptionId('I-BW452GLLEP1G'), true)
  assert.equal(isPaypalSubscriptionId('I-../../v1/oauth2'), false)
  assert.equal(isPaypalSubscriptionId(''), false)
})

check('activation binds to custom_id and a plan this service sells', () => {
  const resource = {
    id: 'I-ABCDEF123456',
    custom_id: USER,
    plan_id: 'P-PRO-M',
    start_time: '2026-09-21T00:00:00Z',
    billing_info: { next_billing_time: '2026-10-21T00:00:00Z' },
  }
  const activation = activationRow(env, resource, '2026-09-21T01:00:00.000Z')
  assert.ok(activation)
  assert.equal(activation.userId, USER)
  assert.equal(activation.row.plan, 'Pro')
  assert.equal(activation.row.billing_cycle, 'monthly')
  assert.equal(activation.row.status, 'active')
  assert.equal(activation.row.renewal_date, '2026-10-21T00:00:00Z')
  assert.equal(activationRow(env, { ...resource, custom_id: 'not-a-user' }, 'now'), null)
  assert.equal(activationRow(env, { ...resource, plan_id: 'P-SOMEONE-ELSES' }, 'now'), null)
})

check('invoice rows carry the sale id and cents', () => {
  const row = invoiceRow(
    { id: 'SALE-1', amount: { total: '30.00', currency: 'usd' }, create_time: '2026-09-21T00:00:00Z', billing_agreement_id: 'I-X' },
    { user_id: USER, plan: 'Pro' },
    'now',
  )
  assert.equal(row.provider_invoice_id, 'SALE-1')
  assert.equal(row.amount_paid_cents, 3000)
  assert.equal(row.currency, 'USD')
})

check('webhook verification embeds the raw event byte-for-byte', () => {
  const raw = '{"id":"WH-1","amount":1.50,"z":1,"a":2}'
  const headers = new Map([['paypal-auth-algo', 'SHA256withRSA'], ['paypal-transmission-id', 'T"1']])
  const body = webhookVerificationBody({ get: (name) => headers.get(name) ?? null }, 'WEBHOOK', raw)
  assert.ok(body.endsWith(`"webhook_event":${raw}}`), 'raw event was re-serialised')
  const parsed = JSON.parse(body)
  assert.equal(parsed.webhook_id, 'WEBHOOK')
  assert.equal(parsed.transmission_id, 'T"1')
  assert.equal(parsed.cert_url, '')
})

check('approval links are read from PayPal link lists', () => {
  assert.equal(approvalLink({ links: [{ rel: 'self', href: 'x' }, { rel: 'approve', href: 'https://www.paypal.com/a' }] }), 'https://www.paypal.com/a')
  assert.equal(approvalLink({}), null)
})

async function live() {
  const base = 'https://xsbdlahuecadzfajlvis.supabase.co/functions/v1/billing'
  const origin = 'http://tauri.localhost'

  const preflight = await fetch(`${base}/api/v1/paypal/subscribe`, {
    method: 'OPTIONS',
    headers: { Origin: origin, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'authorization,content-type' },
  })
  check('live: CORS preflight from the desktop webview origin succeeds', () => {
    assert.ok(preflight.status === 204 || preflight.status === 200, `status ${preflight.status}`)
    assert.equal(preflight.headers.get('access-control-allow-origin'), '*')
    assert.match(preflight.headers.get('access-control-allow-headers') ?? '', /authorization/)
  })

  const health = await fetch(`${base}/health`)
  const healthBody = await health.json().catch(() => ({}))
  check('live: health answers with configuration booleans', () => {
    assert.equal(health.status, 200)
    assert.equal(typeof healthBody?.data?.configured, 'boolean')
  })
  console.log('   health:', JSON.stringify(healthBody?.data))

  const anonymous = await fetch(`${base}/api/v1/paypal/subscribe`, {
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/json' },
    body: JSON.stringify({ plan: 'Pro', cycle: 'monthly' }),
  })
  const anonymousBody = await anonymous.json().catch(() => ({}))
  check('live: subscribe without a session is refused (401, JSON, CORS)', () => {
    assert.equal(anonymous.status, 401)
    assert.equal(anonymousBody?.error?.code, 'UNAUTHORIZED')
    assert.equal(anonymous.headers.get('access-control-allow-origin'), '*')
  })

  const forged = await fetch(`${base}/api/v1/paypal/subscribe`, {
    method: 'POST',
    headers: { Authorization: 'Bearer not-a-real-token', 'Content-Type': 'application/json' },
    body: '{}',
  })
  check('live: a forged token is refused', () => assert.equal(forged.status, 401))

  const webhook = await fetch(`${base}/api/v1/paypal/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: 'WH-FORGED', event_type: 'BILLING.SUBSCRIPTION.ACTIVATED', resource: { custom_id: USER } }),
  })
  const webhookBody = await webhook.json().catch(() => ({}))
  check('live: an unsigned webhook changes nothing', () => {
    assert.equal(webhook.status, 200)
    assert.equal(webhookBody?.verified, false)
  })

  const unknown = await fetch(`${base}/api/v1/nope`, { method: 'POST' })
  check('live: unknown routes are 404, not a crash', () => assert.equal(unknown.status, 404))
}

async function main() {
  if (process.argv.includes('--live')) await live()
  let failed = 0
  for (const result of results) {
    console.log(`${result.ok ? 'PASS' : 'FAIL'}  ${result.name}${result.detail ? `\n      ${result.detail}` : ''}`)
    if (!result.ok) failed += 1
  }
  console.log(`\n${results.length - failed}/${results.length} checks passed`)
  process.exit(failed ? 1 : 0)
}

void main()
