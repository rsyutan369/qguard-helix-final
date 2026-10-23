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
import { generateKeyPairSync, verify as verifySignature } from 'node:crypto'
import { PLAN_PRICING } from '../src/lib/billing/plan-pricing'
import { REFUND_POLICY } from '../src/lib/site-identity'
import {
  invoiceRowFromTransaction,
  moneyBackRefundCancels,
  reconcileAction,
  refundCancellationPatch,
  refundInvoicePatch,
  REFUND_PROCESSING_GRACE_DAYS,
  REFUND_WINDOW_DAYS,
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
  base64Url,
  cycleForPlayBasePlan,
  isPlayConfigured,
  mapPlayState,
  parseRtdnMessage,
  pemToDer,
  PLAY_LIST_PRICING,
  playJwtSigningInput,
  PlayPurchaseError,
  playProductIdFor,
  playServiceAccount,
  playSubscriptionRows,
  tierForPlayProduct,
  timingSafeEqualText,
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

// ---- Google Play (roadmap 4.6) ----------------------------------------------

const PLAY_ENV: Record<string, string> = {
  GOOGLE_PLAY_PACKAGE_NAME: 'com.qguard.messaging',
  GOOGLE_PLAY_SA_EMAIL: 'play@project.iam.gserviceaccount.com',
  GOOGLE_PLAY_SA_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\\nAAAA\\n-----END PRIVATE KEY-----',
  PLAY_PRODUCT_PRO: 'qguard_pro_v2',
}
const playEnv = (key: string) => PLAY_ENV[key]
const TOKEN_HASH = 'ab'.repeat(32)

function playResource(overrides: Record<string, any> = {}) {
  return {
    subscriptionState: 'SUBSCRIPTION_STATE_ACTIVE',
    startTime: '2026-10-01T00:00:00Z',
    latestOrderId: 'GPA.1234-5678',
    acknowledgementState: 'ACKNOWLEDGEMENT_STATE_PENDING',
    externalAccountIdentifiers: { obfuscatedExternalAccountId: USER },
    lineItems: [{ productId: 'qguard_starter', expiryTime: '2026-11-01T00:00:00Z', offerDetails: { basePlanId: 'monthly' } }],
    ...overrides,
  }
}

check('refund window constants match the published Refund Policy', () => {
  assert.equal(REFUND_WINDOW_DAYS, REFUND_POLICY.initialWindowDays)
  // 10 business days never spans more than 14 calendar days.
  assert.ok(REFUND_PROCESSING_GRACE_DAYS >= Math.ceil((REFUND_POLICY.processingDays / 5) * 7))
})

check('only a full money-back refund of the first payment cancels the subscription', () => {
  const base = {
    eventType: 'PAYMENT.SALE.REFUNDED',
    amountPaidCents: 3000,
    refundedCents: 3000,
    paymentDate: '2026-10-01T00:00:00Z',
    refundedAt: '2026-10-04T00:00:00Z',
    isFirstPayment: true,
  }
  assert.equal(moneyBackRefundCancels(base), true)
  // Requested on day 7, issued within the processing allowance.
  assert.equal(moneyBackRefundCancels({ ...base, refundedAt: '2026-10-19T00:00:00Z' }), true)
  // Negative controls.
  assert.equal(moneyBackRefundCancels({ ...base, refundedCents: 1500 }), false, 'partial refund')
  assert.equal(moneyBackRefundCancels({ ...base, isFirstPayment: false }), false, 'renewal refund (goodwill)')
  assert.equal(moneyBackRefundCancels({ ...base, refundedAt: '2026-11-15T00:00:00Z' }), false, 'outside the window')
  assert.equal(moneyBackRefundCancels({ ...base, eventType: 'PAYMENT.SALE.REVERSED' }), false, 'reversal is not a refund')
  assert.equal(moneyBackRefundCancels({ ...base, amountPaidCents: 0, refundedCents: 0 }), false, 'nothing was paid')
  assert.equal(moneyBackRefundCancels({ ...base, paymentDate: null }), false, 'unknown payment date')
  // Cumulative partial refunds that reach the full amount count as full.
  const first = refundInvoicePatch({ amount_paid_cents: 3000, metadata: {} }, { id: 'R1', amount: { total: '10.00' } }, 'PAYMENT.SALE.REFUNDED', '2026-10-02T00:00:00Z')
  const second = refundInvoicePatch({ amount_paid_cents: 3000, metadata: first.patch.metadata as Record<string, unknown> }, { id: 'R2', amount: { total: '20.00' } }, 'PAYMENT.SALE.REFUNDED', '2026-10-03T00:00:00Z')
  assert.equal((second.patch.metadata as Record<string, unknown>).refundedCents, 3000)
})

check('a refund cancellation ends access now and keeps the first cancel time', () => {
  const now = '2026-10-04T00:00:00.000Z'
  assert.deepEqual(refundCancellationPatch(null, now), { status: 'cancelled', auto_renew: false, cancel_at_period_end: true, cancelled_at: now, updated_at: now })
  assert.equal(refundCancellationPatch({ cancelled_at: '2026-10-02T00:00:00Z' }, now).cancelled_at, '2026-10-02T00:00:00Z')
})

check('reconcile repairs only real drift between PayPal and the local row', () => {
  const env = (key: string) => ENV[key]
  const local = { plan: 'Pro', status: 'active', renewal_date: '2026-11-01T10:00:00Z', cancel_at_period_end: false }
  const remote = { status: 'ACTIVE', plan_id: 'P-PRO-M', billing_info: { next_billing_time: '2026-11-01T10:00:00.000Z' } }
  assert.equal(reconcileAction(env, local, remote), null, 'in agreement (same instant, different formatting)')
  assert.equal(reconcileAction(env, { ...local, status: 'past_due' }, remote), 'sync', 'payment recovered')
  assert.equal(reconcileAction(env, local, { ...remote, plan_id: 'P-STARTER-M' }), 'sync', 'plan changed')
  assert.equal(reconcileAction(env, local, { ...remote, billing_info: { next_billing_time: '2026-12-01T10:00:00Z' } }), 'sync', 'renewed')
  assert.equal(reconcileAction(env, local, { ...remote, status: 'CANCELLED' }), 'cancelled')
  assert.equal(reconcileAction(env, { ...local, cancel_at_period_end: true }, { ...remote, status: 'CANCELLED' }), null, 'cancellation already recorded')
  assert.equal(reconcileAction(env, local, { ...remote, status: 'SUSPENDED' }), 'suspended')
  assert.equal(reconcileAction(env, { ...local, status: 'expired' }, { ...remote, status: 'EXPIRED' }), null)
  assert.equal(reconcileAction(env, local, { ...remote, status: 'APPROVAL_PENDING' }), null, 'not yet approved')
})

check('reconciled payments become the same invoice row the webhook writes', () => {
  const sub = { user_id: USER, plan: 'Pro' }
  const tx = { id: '7XY12345AB678901C', status: 'COMPLETED', time: '2026-10-01T10:00:00Z', amount_with_breakdown: { gross_amount: { currency_code: 'USD', value: '30.00' } } }
  const fromTx = invoiceRowFromTransaction(tx, sub, 'I-ABCDEF123456', '2026-10-05T00:00:00Z')
  const fromWebhook = invoiceRow({ id: tx.id, amount: { total: '30.00', currency: 'USD' }, create_time: tx.time, billing_agreement_id: 'I-ABCDEF123456' }, sub, '2026-10-05T00:00:00Z')
  assert.deepEqual(fromTx, fromWebhook)
  assert.equal(invoiceRowFromTransaction({ ...tx, status: 'DECLINED' }, sub, 'I-ABCDEF123456', '2026-10-05T00:00:00Z'), null)
  assert.equal(invoiceRowFromTransaction({ ...tx, id: '' }, sub, 'I-ABCDEF123456', '2026-10-05T00:00:00Z'), null)
})

check('play: list prices are exactly the platform catalog', () => {
  assert.deepEqual(PLAY_LIST_PRICING, PLAN_PRICING)
})

check('play: configured only with a package AND a service account; health shows booleans only', () => {
  assert.equal(isPlayConfigured(playEnv), true)
  assert.equal(isPlayConfigured((key) => (key === 'GOOGLE_PLAY_PACKAGE_NAME' ? 'x' : undefined)), false)
  assert.equal(isPlayConfigured(env), false)
  assert.equal(playServiceAccount(playEnv)?.privateKey.includes('\n'), true, 'escaped newlines are restored')
  const report = configurationReport(playEnv)
  assert.equal(report.playVerification, true)
  assert.equal(report.playRtdn, false)
  const text = JSON.stringify(report)
  for (const value of Object.values(PLAY_ENV)) assert.ok(!text.includes(value), `health leaked ${value}`)
  assert.equal(configurationReport(env).playVerification, false)
})

check('play: products, overrides and base plans map like the Express API', () => {
  assert.equal(playProductIdFor(playEnv, 'Starter'), 'qguard_starter')
  assert.equal(playProductIdFor(playEnv, 'Pro'), 'qguard_pro_v2')
  assert.equal(tierForPlayProduct(playEnv, 'qguard_pro_v2'), 'Pro')
  assert.equal(tierForPlayProduct(playEnv, 'qguard_pro'), null, 'an overridden id replaces the default')
  assert.equal(cycleForPlayBasePlan('yearly'), 'annual')
  assert.equal(cycleForPlayBasePlan('annual-plan'), 'annual')
  assert.equal(cycleForPlayBasePlan('monthly'), 'monthly')
  assert.equal(cycleForPlayBasePlan(undefined), 'monthly')
})

check('play: subscription states keep entitlement exactly when Play policy says', () => {
  assert.deepEqual(mapPlayState('SUBSCRIPTION_STATE_ACTIVE'), { status: 'active', entitled: true, autoRenew: true })
  assert.deepEqual(mapPlayState('SUBSCRIPTION_STATE_IN_GRACE_PERIOD'), { status: 'pending_renewal', entitled: true, autoRenew: true })
  assert.deepEqual(mapPlayState('SUBSCRIPTION_STATE_CANCELED'), { status: 'active', entitled: true, autoRenew: false })
  assert.equal(mapPlayState('SUBSCRIPTION_STATE_ON_HOLD').entitled, false)
  assert.equal(mapPlayState('SUBSCRIPTION_STATE_PAUSED').entitled, false)
  assert.deepEqual(mapPlayState('SUBSCRIPTION_STATE_EXPIRED'), { status: 'expired', entitled: false, autoRenew: false })
  assert.deepEqual(mapPlayState('SOMETHING_NEW'), { status: 'incomplete', entitled: false, autoRenew: false })
})

check('play: a verified purchase becomes the account row and a list-price invoice', () => {
  const applied = playSubscriptionRows(playEnv, playResource(), TOKEN_HASH, USER, '2026-10-19T00:00:00Z')
  assert.equal(applied.userId, USER)
  assert.equal(applied.tier, 'Starter')
  assert.equal(applied.subscription.provider, 'google_play')
  assert.equal(applied.subscription.provider_subscription_id, TOKEN_HASH)
  assert.equal(applied.subscription.current_period_end, '2026-11-01T00:00:00Z')
  assert.equal(applied.invoice?.amount_paid_cents, 100)
  assert.equal(applied.invoice?.provider_invoice_id, 'GPA.1234-5678')
  const yearly = playSubscriptionRows(playEnv, playResource({ lineItems: [{ productId: 'qguard_pro_v2', offerDetails: { basePlanId: 'yearly' } }] }), TOKEN_HASH, USER, 'now')
  assert.equal(yearly.invoice?.amount_paid_cents, 20 * 12 * 100, 'a yearly plan is billed once at 12x the monthly-equivalent')
  const expired = playSubscriptionRows(playEnv, playResource({ subscriptionState: 'SUBSCRIPTION_STATE_EXPIRED' }), TOKEN_HASH, USER, 'now')
  assert.equal(expired.invoice, null, 'no payment is recorded for a purchase that grants nothing')
  assert.equal(expired.subscription.status, 'expired')
})

check('play: purchases bound to another account, to nobody, or for an unknown product are refused', () => {
  const code = (fn: () => unknown) => {
    try { fn(); return null } catch (error) { return error instanceof PlayPurchaseError ? error.code : String(error) }
  }
  const other = '00000000-0000-4000-8000-000000000000'
  assert.equal(code(() => playSubscriptionRows(playEnv, playResource(), TOKEN_HASH, other, 'now')), 'ACCOUNT_MISMATCH')
  assert.equal(code(() => playSubscriptionRows(playEnv, playResource({ externalAccountIdentifiers: {} }), TOKEN_HASH, null, 'now')), 'NOT_BOUND')
  assert.equal(code(() => playSubscriptionRows(playEnv, playResource({ lineItems: [{ productId: 'other_app_sub' }] }), TOKEN_HASH, USER, 'now')), 'UNKNOWN_PRODUCT')
  // RTDN (no caller) trusts the binding Google recorded.
  assert.equal(playSubscriptionRows(playEnv, playResource(), TOKEN_HASH, null, 'now').userId, USER)
})

check('play: RTDN envelopes decode, junk is ignored, the secret compares in constant time', () => {
  const payload = { packageName: 'com.qguard.messaging', subscriptionNotification: { notificationType: 2, purchaseToken: 'tok' } }
  const body = { message: { messageId: 'm-1', data: Buffer.from(JSON.stringify(payload)).toString('base64') } }
  assert.deepEqual(parseRtdnMessage(body), { messageId: 'm-1', payload })
  assert.equal(parseRtdnMessage({ message: { data: '%%%' } }), null)
  assert.equal(parseRtdnMessage({}), null)
  assert.equal(timingSafeEqualText('secret', 'secret'), true)
  assert.equal(timingSafeEqualText('secret', 'secreT'), false)
  assert.equal(timingSafeEqualText('secret', 'secret!'), false)
})

async function playJwtRoundTrip() {
  // A real RSA key in the PEM form Google issues; signed the way index.ts
  // signs (WebCrypto RSASSA-PKCS1-v1_5 / SHA-256), verified independently.
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const key = await crypto.subtle.importKey('pkcs8', new Uint8Array(pemToDer(pem)), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign'])
  const input = playJwtSigningInput('play@project.iam.gserviceaccount.com', 1_800_000_000)
  const signature = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(input)))
  check('play: the service-account JWT is a valid RS256 token Google can verify', () => {
    const [header, claims] = input.split('.')
    assert.deepEqual(JSON.parse(Buffer.from(header, 'base64url').toString()), { alg: 'RS256', typ: 'JWT' })
    const decoded = JSON.parse(Buffer.from(claims, 'base64url').toString())
    assert.equal(decoded.scope, 'https://www.googleapis.com/auth/androidpublisher')
    assert.equal(decoded.aud, 'https://oauth2.googleapis.com/token')
    assert.equal(decoded.exp - decoded.iat, 3600)
    const jwtSignature = Buffer.from(base64Url(signature), 'base64url')
    assert.ok(verifySignature('RSA-SHA256', Buffer.from(input), publicKey, jwtSignature))
    assert.ok(!verifySignature('RSA-SHA256', Buffer.from(input + 'x'), publicKey, jwtSignature))
  })
}

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
  await playJwtRoundTrip()
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
