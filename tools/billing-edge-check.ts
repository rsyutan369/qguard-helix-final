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
  decodeJwt,
  decryptPurchaseToken,
  encryptPurchaseToken,
  inboxClaimDecision,
  isAccessGranting,
  isPlausiblePurchaseToken,
  isPlayConfigured,
  listPriceCents,
  mapPlayState,
  parseRtdnMessage,
  pemToDer,
  PLAY_LIST_PRICING,
  PLAY_NOTIFICATION_TYPES,
  playAccountIdFor,
  playBindingMatches,
  playFacts,
  playInvoiceRow,
  playJwtSigningInput,
  playMayReplaceRow,
  playNotificationAuditAction,
  PlayPurchaseError,
  playProductCatalog,
  playProductIdFor,
  playProductInfo,
  playServiceAccount,
  playSubscriptionRow,
  pubsubClaimsProblem,
  rowGrantsAccess,
  RTDN_MAX_ATTEMPTS,
  sanitizeRtdnPayload,
  timingSafeEqualText,
  tokenEncryptionKeyBytes,
} from '../supabase/functions/billing/logic'
import { ENTITLEMENT_CATALOG, entitlementsForTier } from '../supabase/functions/billing/entitlements'
import { resolveRequiredTier } from '../src/lib/subscription-access'
import { readFileSync } from 'node:fs'
import { buildBillingOps } from '../src/lib/billing/billing-ops'

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
  PLAY_PRODUCT_PRO_YEARLY: 'qh_pro_yearly_v2',
}
const playEnv = (key: string) => PLAY_ENV[key]
const TOKEN_HASH = 'ab'.repeat(32)

function playResource(overrides: Record<string, any> = {}) {
  return {
    subscriptionState: 'SUBSCRIPTION_STATE_ACTIVE',
    startTime: '2026-10-01T00:00:00Z',
    latestOrderId: 'GPA.0000-STALE',
    acknowledgementState: 'ACKNOWLEDGEMENT_STATE_PENDING',
    externalAccountIdentifiers: { obfuscatedExternalAccountId: USER },
    lineItems: [{
      productId: 'qh_starter_monthly',
      expiryTime: '2026-11-01T00:00:00Z',
      latestSuccessfulOrderId: 'GPA.1234-5678',
      offerDetails: { basePlanId: 'monthly' },
      autoRenewingPlan: { autoRenewEnabled: true, recurringPrice: { currencyCode: 'EUR', units: '0', nanos: 990000000 } },
    }],
    ...overrides,
  }
}

check('no money-back guarantee is published; first-payment refunds still end the plan', () => {
  assert.equal(REFUND_POLICY.moneyBackGuarantee, false)
  assert.ok(REFUND_WINDOW_DAYS > 0)
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

check('play: USD list prices match the monthly and annual catalog', () => {
  assert.deepEqual(PLAY_LIST_PRICING, PLAN_PRICING)
  assert.deepEqual(
    Object.fromEntries(Object.entries(PLAN_PRICING).map(([tier, price]) => [tier, [price.monthly, price.yearlyPerMonth * 12]])),
    { Starter: [1, 12], Basic: [8, 60], Pro: [30, 240], Elite: [199, 1800] },
  )
  assert.equal(listPriceCents('Elite', 'annual'), 180_000)
  assert.equal(listPriceCents('Basic', 'monthly'), 800)
})

check('play: configured only with a package AND a service account; health shows booleans only', () => {
  assert.equal(isPlayConfigured(playEnv), true)
  assert.equal(isPlayConfigured((key) => (key === 'GOOGLE_PLAY_PACKAGE_NAME' ? 'x' : undefined)), false)
  assert.equal(isPlayConfigured(env), false)
  assert.equal(playServiceAccount(playEnv)?.privateKey.includes('\n'), true, 'escaped newlines are restored')
  const report = configurationReport(playEnv)
  assert.equal(report.playVerification, true)
  assert.equal(report.playRtdn, false)
  assert.equal(report.playTokenEncryption, false)
  const text = JSON.stringify(report)
  for (const value of Object.values(PLAY_ENV)) assert.ok(!text.includes(value), `health leaked ${value}`)
  assert.equal(configurationReport(env).playVerification, false)
})

check('play: the 8 products are qh_<tier>_<period>, remappable per product', () => {
  assert.deepEqual(playProductCatalog(() => undefined).map((entry) => entry.productId), [
    'qh_starter_monthly', 'qh_starter_yearly', 'qh_basic_monthly', 'qh_basic_yearly',
    'qh_pro_monthly', 'qh_pro_yearly', 'qh_elite_monthly', 'qh_elite_yearly',
  ])
  assert.equal(playProductIdFor(playEnv, 'Pro', 'yearly'), 'qh_pro_yearly_v2')
  assert.deepEqual(playProductInfo(playEnv, 'qh_pro_yearly_v2'), { tier: 'Pro', cycle: 'annual' })
  assert.equal(playProductInfo(playEnv, 'qh_pro_yearly'), null, 'an overridden id replaces the default')
  assert.deepEqual(playProductInfo(playEnv, 'qh_elite_monthly'), { tier: 'Elite', cycle: 'monthly' })
  assert.equal(playProductInfo(playEnv, 'qguard_starter'), null, 'retired ids grant nothing')
})

check('play: subscription states grant access exactly when Play policy says', () => {
  const now = Date.parse('2026-11-12T00:00:00Z')
  assert.equal(mapPlayState('SUBSCRIPTION_STATE_ACTIVE').entitled, true)
  assert.deepEqual(mapPlayState('SUBSCRIPTION_STATE_IN_GRACE_PERIOD'), { status: 'pending_renewal', entitled: true, autoRenew: true, paymentIssue: true })
  // Cancelled = renewal off; access continues to the paid-through time, then ends.
  assert.deepEqual(mapPlayState('SUBSCRIPTION_STATE_CANCELED', '2026-12-01T00:00:00Z', now), { status: 'active', entitled: true, autoRenew: false, paymentIssue: false })
  assert.equal(mapPlayState('SUBSCRIPTION_STATE_CANCELED', '2026-11-01T00:00:00Z', now).status, 'expired')
  assert.deepEqual(mapPlayState('SUBSCRIPTION_STATE_ON_HOLD'), { status: 'past_due', entitled: false, autoRenew: true, paymentIssue: true })
  assert.equal(mapPlayState('SUBSCRIPTION_STATE_PAUSED').entitled, false)
  assert.equal(mapPlayState('SUBSCRIPTION_STATE_EXPIRED').status, 'expired')
  // A pending purchase is NEVER access.
  assert.deepEqual(mapPlayState('SUBSCRIPTION_STATE_PENDING'), { status: 'incomplete', entitled: false, autoRenew: false, paymentIssue: false })
  assert.equal(mapPlayState('SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED').entitled, false)
  assert.equal(mapPlayState('SOMETHING_NEW').entitled, false)
})

check('play: a verified purchase becomes the account row and an invoice at Google\'s recurring price', () => {
  const now = Date.parse('2026-10-19T00:00:00Z')
  const facts = playFacts(playEnv, playResource(), now)
  assert.equal(facts.tier, 'Starter')
  assert.equal(facts.cycle, 'monthly')
  assert.equal(facts.orderId, 'GPA.1234-5678')
  assert.deepEqual(facts.price, { cents: 99, currency: 'EUR', source: 'play_recurring_price' })
  const row = playSubscriptionRow(facts, { userId: USER, tokenHash: TOKEN_HASH, tokenEncrypted: 'v1.x.y', linkedTokenHash: null }, null, '2026-10-19T00:00:00Z')
  assert.equal(row.provider, 'google_play')
  assert.equal(row.provider_subscription_id, TOKEN_HASH)
  assert.equal(row.product_id, 'qh_starter_monthly')
  assert.equal(row.current_period_end, '2026-11-01T00:00:00Z')
  assert.equal(row.renewal_date, '2026-11-01T00:00:00Z')
  assert.equal(row.cancel_at_period_end, false)
  assert.equal(row.acknowledgement_state, 'pending')
  assert.equal(row.purchase_token_encrypted, 'v1.x.y')
  const invoice = playInvoiceRow(facts, USER, TOKEN_HASH, '2026-10-19T00:00:00Z')
  assert.equal(invoice?.amount_paid_cents, 99)
  assert.equal(invoice?.currency, 'EUR')
  assert.equal(invoice?.provider_invoice_id, 'GPA.1234-5678')
  // Without a reported price the catalog list price is used and labelled.
  const listed = playFacts(playEnv, playResource({ lineItems: [{ productId: 'qh_elite_yearly', expiryTime: '2027-10-01T00:00:00Z', latestSuccessfulOrderId: 'GPA.9' }] }), now)
  assert.deepEqual(listed.price, { cents: 180_000, currency: 'USD', source: 'catalog_list_price' })
  assert.equal(listed.orderId, 'GPA.9', 'line-item order id wins over the deprecated top-level one')
  const pending = playFacts(playEnv, playResource({ subscriptionState: 'SUBSCRIPTION_STATE_PENDING' }), now)
  assert.equal(playInvoiceRow(pending, USER, TOKEN_HASH, 'now'), null, 'no payment is recorded for a pending purchase')
})

check('play: license-tester purchases are recorded at zero and flagged complimentary', () => {
  const facts = playFacts(playEnv, playResource({ testPurchase: {} }), Date.parse('2026-10-19T00:00:00Z'))
  assert.equal(facts.testPurchase, true)
  const row = playSubscriptionRow(facts, { userId: USER, tokenHash: TOKEN_HASH, tokenEncrypted: null, linkedTokenHash: null }, null, 'now')
  assert.equal(row.amount_cents, 0)
  assert.equal((row.metadata as Record<string, unknown>).complimentary, true)
  assert.equal(playInvoiceRow(facts, USER, TOKEN_HASH, 'now')?.amount_paid_cents, 0)
})

check('play: cancellation keeps access until expiry and records why', () => {
  const facts = playFacts(playEnv, playResource({
    subscriptionState: 'SUBSCRIPTION_STATE_CANCELED',
    canceledStateContext: { userInitiatedCancellation: {} },
  }), Date.parse('2026-10-19T00:00:00Z'))
  const row = playSubscriptionRow(facts, { userId: USER, tokenHash: TOKEN_HASH, tokenEncrypted: null, linkedTokenHash: null }, { cancelled_at: '2026-10-10T00:00:00Z' }, '2026-10-19T00:00:00Z')
  assert.equal(row.status, 'active')
  assert.equal(row.cancel_at_period_end, true)
  assert.equal(row.auto_renew, false)
  assert.equal(row.renewal_date, null, 'no renewal date is shown for a cancelled plan')
  assert.equal(row.cancel_reason, 'user')
  assert.equal(row.cancelled_at, '2026-10-10T00:00:00Z', 'the first cancel time is kept')
})

check('play: unknown products and empty resources are refused', () => {
  const code = (fn: () => unknown) => {
    try { fn(); return null } catch (error) { return error instanceof PlayPurchaseError ? error.code : String(error) }
  }
  assert.equal(code(() => playFacts(playEnv, playResource({ lineItems: [{ productId: 'other_app_sub' }] }))), 'UNKNOWN_PRODUCT')
  assert.equal(code(() => playFacts(playEnv, playResource({ lineItems: [] }))), 'NO_LINE_ITEM')
})

async function playAsyncChecks() {
  const hashed = await playAccountIdFor(USER)
  check('play: the obfuscated account id is a 64-hex hash, never the raw user id', () => {
    assert.match(hashed, /^[0-9a-f]{64}$/)
    assert.notEqual(hashed, USER)
  })
  const matches = {
    hashed: await playBindingMatches(hashed, USER),
    legacy: await playBindingMatches(USER, USER),
    other: await playBindingMatches(await playAccountIdFor('00000000-0000-4000-8000-000000000000'), USER),
    empty: await playBindingMatches('', USER),
  }
  check('play: a purchase binds only to the account that made it', () => {
    assert.deepEqual(matches, { hashed: true, legacy: true, other: false, empty: false })
  })

  const key = crypto.getRandomValues(new Uint8Array(32))
  const sealed = await encryptPurchaseToken(key, 'opaque.purchase-token_123')
  const opened = await decryptPurchaseToken(key, sealed)
  let tampered = 'opened'
  try {
    const parts = sealed.split('.')
    await decryptPurchaseToken(key, `${parts[0]}.${parts[1]}.${parts[2].slice(0, -2)}AA`)
  } catch {
    tampered = 'rejected'
  }
  let wrongKey = 'opened'
  try {
    await decryptPurchaseToken(crypto.getRandomValues(new Uint8Array(32)), sealed)
  } catch {
    wrongKey = 'rejected'
  }
  check('play: purchase tokens are sealed with AES-256-GCM and tamper-evident', () => {
    assert.equal(opened, 'opaque.purchase-token_123')
    assert.ok(!sealed.includes('purchase-token'))
    assert.equal(tampered, 'rejected')
    assert.equal(wrongKey, 'rejected')
    const keyEnv = (name: string) => (name === 'PLAY_TOKEN_ENCRYPTION_KEY' ? Buffer.from(key).toString('base64') : undefined)
    assert.equal(tokenEncryptionKeyBytes(keyEnv)?.length, 32)
    assert.equal(tokenEncryptionKeyBytes((name) => (name === 'PLAY_TOKEN_ENCRYPTION_KEY' ? 'c2hvcnQ=' : undefined)), null, 'a short key is refused')
  })
}

check('play: a replaced or stale token never overwrites the current plan', () => {
  const now = Date.parse('2026-11-12T00:00:00Z')
  const current = { provider: 'google_play', provider_subscription_id: 'new', linked_purchase_token_hash: 'old', status: 'active', current_period_end: '2026-12-01T00:00:00Z' }
  assert.equal(playMayReplaceRow(current, { tokenHash: 'new', entitled: false }, now), true, 'same token always applies')
  assert.equal(playMayReplaceRow(current, { tokenHash: 'old', entitled: false }, now), false, 'EXPIRED for the replaced token is ignored')
  assert.equal(playMayReplaceRow(current, { tokenHash: 'old', entitled: true }, now), false)
  assert.equal(playMayReplaceRow(current, { tokenHash: 'other', entitled: true }, now), true, 'a new entitled purchase replaces')
  assert.equal(playMayReplaceRow(current, { tokenHash: 'other', entitled: false }, now), false, 'a lapsed foreign token cannot lock the account')
  assert.equal(playMayReplaceRow({ ...current, status: 'expired' }, { tokenHash: 'other', entitled: false }, now), true)
  assert.equal(playMayReplaceRow(null, { tokenHash: 'x', entitled: false }, now), true)
})

check('access rule: no trial, provider-aware grace (mirrors SQL qguard_subscription_access_until)', () => {
  const now = Date.parse('2026-11-12T12:00:00Z')
  assert.equal(rowGrantsAccess({ provider: 'manual', status: 'trial', current_period_end: null }, now), false)
  assert.equal(rowGrantsAccess({ provider: 'manual', status: 'active', current_period_end: null }, now), true)
  assert.equal(rowGrantsAccess({ provider: 'google_play', status: 'active', current_period_end: '2026-11-12T11:30:00Z' }, now), true, '30 min tolerance for RTDN latency')
  assert.equal(rowGrantsAccess({ provider: 'google_play', status: 'active', current_period_end: '2026-11-12T10:00:00Z' }, now), false)
  assert.equal(rowGrantsAccess({ provider: 'paypal', status: 'active', current_period_end: '2026-11-10T12:00:00Z' }, now), true, 'PayPal renewal lag')
  assert.equal(rowGrantsAccess({ provider: 'paypal', status: 'past_due', current_period_end: '2026-12-10T12:00:00Z' }, now), false)
  assert.equal(isAccessGranting('trial'), false)
  const sql = readFileSync(new URL('../supabase/google-play-billing-v2.sql', import.meta.url), 'utf8')
  assert.match(sql, /WHEN p_provider = 'google_play' THEN p_period_end \+ INTERVAL '1 hour'/)
  assert.match(sql, /ELSE p_period_end \+ INTERVAL '72 hours'/)
  assert.match(sql, /NOT IN \('active', 'pending_renewal'\) THEN NULL/)
})

check('entitlements: strict ladder, every tier includes the ones below', () => {
  assert.equal(entitlementsForTier('Starter').length, 10)
  assert.equal(entitlementsForTier('Basic').length, 20)
  assert.equal(entitlementsForTier('Pro').length, 30)
  assert.equal(entitlementsForTier('Elite').length, ENTITLEMENT_CATALOG.length)
  assert.ok(entitlementsForTier('Basic').includes('quantum_messaging'), 'Basic includes Starter messaging (owner decision 2026-11-12)')
  assert.ok(!entitlementsForTier('Pro').includes('qkms'))
  assert.ok(!entitlementsForTier('Pro').includes('compliance_control_mapping'))
  assert.ok(entitlementsForTier('Elite').includes('qkms'))
  assert.deepEqual(entitlementsForTier('free'), [], 'there is no free tier')
  assert.deepEqual(entitlementsForTier(null), [])
})

check('entitlements: the SQL seed matches entitlements.ts key for key', () => {
  const sql = readFileSync(new URL('../supabase/google-play-billing-v2.sql', import.meta.url), 'utf8')
  const seeded = [...sql.matchAll(/\('([a-z_0-9]+)', '(Starter|Basic|Pro|Elite)', '[^']+', \d+\)/g)].map((m) => `${m[1]}:${m[2]}`).sort()
  const catalog = ENTITLEMENT_CATALOG.map((entry) => `${entry.key}:${entry.minTier}`).sort()
  assert.deepEqual(seeded, catalog)
})

check('entitlements: web route gating agrees with the catalog (maintain current access)', () => {
  for (const entry of ENTITLEMENT_CATALOG) {
    for (const route of entry.routes ?? []) {
      assert.equal(resolveRequiredTier(route), entry.minTier.toLowerCase(), `${entry.key} ${route}`)
    }
  }
})

check('entitlements: SQL product seed = 8 Play + 8 PayPal at the catalog prices', () => {
  const sql = readFileSync(new URL('../supabase/google-play-billing-v2.sql', import.meta.url), 'utf8')
  const rows = [...sql.matchAll(/\('((?:qh|paypal)_[a-z]+_(?:monthly|yearly))',\s+'(google_play|paypal)',\s+'(\w+)',\s+'(monthly|yearly)',\s+([\d.]+),/g)]
  assert.equal(rows.length, 16)
  for (const [, productId, platform, tier, period, price] of rows) {
    const expected = listPriceCents(tier as 'Starter', period as 'monthly') / 100
    assert.equal(Number(price), expected, productId)
    if (platform === 'google_play') assert.equal(productId, playProductIdFor(() => undefined, tier as 'Starter', period as 'monthly'))
  }
})

check('play: RTDN envelopes decode; tokens never reach storage; types map to lifecycle events', () => {
  const payload = { packageName: 'com.qguard.messaging', subscriptionNotification: { notificationType: 2, purchaseToken: 'tok' } }
  const body = { message: { messageId: 'm-1', data: Buffer.from(JSON.stringify(payload)).toString('base64') } }
  assert.deepEqual(parseRtdnMessage(body), { messageId: 'm-1', payload })
  assert.equal(parseRtdnMessage({ message: { data: '%%%' } }), null)
  assert.equal(parseRtdnMessage({}), null)
  const clean = sanitizeRtdnPayload({ ...payload, voidedPurchaseNotification: { purchaseToken: 'tok2', orderId: 'GPA.1' } })
  assert.ok(!JSON.stringify(clean).includes('tok'), 'no token in the stored payload')
  assert.equal((clean.voidedPurchaseNotification as Record<string, unknown>).orderId, 'GPA.1')
  assert.equal(payload.subscriptionNotification.purchaseToken, 'tok', 'the live payload is not mutated')
  assert.equal(playNotificationAuditAction(2), 'subscription.renewed')
  assert.equal(playNotificationAuditAction(12), 'subscription.revoked')
  assert.equal(playNotificationAuditAction(13), 'subscription.expired')
  assert.equal(playNotificationAuditAction(5), 'subscription.on_hold')
  assert.equal(playNotificationAuditAction(19), null, 'price-change notices only re-sync')
  assert.equal(PLAY_NOTIFICATION_TYPES[20], 'SUBSCRIPTION_PENDING_PURCHASE_CANCELED')
  assert.equal(timingSafeEqualText('secret', 'secret'), true)
  assert.equal(timingSafeEqualText('secret', 'secreT'), false)
})

check('play: the RTDN inbox claims, retries, then dead-letters', () => {
  const now = Date.parse('2026-11-12T00:00:00Z')
  assert.equal(inboxClaimDecision(null, now), 'run')
  assert.equal(inboxClaimDecision({ status: 'processed' }, now), 'duplicate')
  assert.equal(inboxClaimDecision({ status: 'failed', attempts: 3 }, now), 'run')
  assert.equal(inboxClaimDecision({ status: 'failed', attempts: RTDN_MAX_ATTEMPTS }, now), 'dead-letter')
  assert.equal(inboxClaimDecision({ status: 'dead_letter' }, now), 'dead-letter')
  assert.equal(inboxClaimDecision({ status: 'processing', claimed_at: new Date(now - 10_000).toISOString() }, now), 'in-progress')
  assert.equal(inboxClaimDecision({ status: 'processing', claimed_at: new Date(now - 10 * 60_000).toISOString() }, now), 'run', 'a crashed claim goes stale')
})

check('play: Pub/Sub OIDC claims are checked for issuer, audience, expiry and signer', () => {
  const now = 1_800_000_000
  const good = { iss: 'https://accounts.google.com', aud: 'https://billing.example/rtdn', exp: now + 600, iat: now - 5, email: 'push@proj.iam.gserviceaccount.com', email_verified: true }
  const expected = { audience: 'https://billing.example/rtdn', email: 'push@proj.iam.gserviceaccount.com' }
  assert.equal(pubsubClaimsProblem(good, expected, now), null)
  assert.equal(pubsubClaimsProblem({ ...good, iss: 'https://evil.example' }, expected, now), 'issuer')
  assert.equal(pubsubClaimsProblem({ ...good, aud: 'https://other' }, expected, now), 'audience')
  assert.equal(pubsubClaimsProblem({ ...good, exp: now - 3600 }, expected, now), 'expired', 'a replayed old token is refused')
  assert.equal(pubsubClaimsProblem({ ...good, email: 'someone@else.com' }, expected, now), 'email')
  assert.equal(pubsubClaimsProblem({ ...good, email_verified: false }, expected, now), 'email_unverified')
  assert.equal(pubsubClaimsProblem({ ...good, email: 'x' }, { ...expected, email: null }, now), null, 'signer check is optional')
  const jwt = `${base64Url(JSON.stringify({ alg: 'RS256', kid: 'k1' }))}.${base64Url(JSON.stringify(good))}.${base64Url('sig')}`
  assert.equal(decodeJwt(jwt)?.header.kid, 'k1')
  assert.equal(decodeJwt('not.a.jwt.at.all'), null)
})

check('billing ops: inbox health and lifecycle counts come only from real rows', () => {
  const now = new Date('2026-11-12T12:00:00Z')
  const empty = buildBillingOps({ now, inbox: [], auditEvents: [], subscriptions: [] })
  assert.equal(empty.inbox.rtdnSeen, false, 'an empty inbox is reported as never seen, not as healthy')
  const row = (id: string, status: string, received: string, error: string | null = null) => ({ id, event_id: id, notification_type: 'SUBSCRIPTION_RENEWED', status, attempts: 1, received_at: received, claimed_at: received, processed_at: null, last_error: error })
  const ops = buildBillingOps({
    now,
    inbox: [
      row('rtdn_1', 'processed', '2026-11-11T00:00:00Z'),
      row('rtdn_2', 'failed', '2026-11-10T00:00:00Z', 'Google Play API 503'),
      row('rtdn_3', 'dead_letter', '2026-09-01T00:00:00Z', 'UNBOUND'),
      row('verify_abc', 'processed', '2026-11-11T00:00:00Z'),
    ],
    auditEvents: [
      { action: 'subscription.renewed', created_at: '2026-11-01T00:00:00Z' },
      { action: 'subscription.renewed', created_at: '2026-08-01T00:00:00Z' },
      { action: 'subscription.revoked', created_at: '2026-11-02T00:00:00Z' },
      { action: 'purchase.rejected', created_at: '2026-11-03T00:00:00Z' },
      { action: null, created_at: '2026-11-03T00:00:00Z' },
    ],
    subscriptions: [{ provider: 'google_play', status: 'past_due' }, { provider: 'paypal', status: 'pending_renewal' }, { provider: 'paypal', status: 'active' }],
  })
  assert.deepEqual(
    { seen: ops.inbox.rtdnSeen, received: ops.inbox.received, processed: ops.inbox.processed, failed: ops.inbox.failed, dead: ops.inbox.deadLetter, oldest: ops.inbox.oldestUnprocessedAt },
    { seen: true, received: 2, processed: 1, failed: 1, dead: 1, oldest: '2026-11-10T00:00:00Z' },
    'verification ledger rows are not RTDN messages; only the 30-day window counts as received',
  )
  assert.equal(ops.inbox.lastError, 'Google Play API 503')
  assert.equal(ops.lifecycle.renewals, 1, 'outside the window is not counted')
  assert.equal(ops.lifecycle.revocations, 1)
  assert.equal(ops.verification.rejected, 1)
  assert.deepEqual(ops.paymentIssues, { googlePlay: 1, paypal: 1, other: 0 })
})

check('play: purchase tokens are validated before use', () => {
  assert.equal(isPlausiblePurchaseToken('a'.repeat(40)), true)
  assert.equal(isPlausiblePurchaseToken('short'), false)
  assert.equal(isPlausiblePurchaseToken('a'.repeat(30) + ' <script>'), false)
  assert.equal(isPlausiblePurchaseToken(42), false)
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
  // The project the apps are built against (root .env), never a hard-coded ref.
  const supabaseUrl = process.env.VITE_SUPABASE_URL
    || readFileSync(new URL('../.env', import.meta.url), 'utf8').match(/^VITE_SUPABASE_URL=["']?([^"'\r\n]+)/m)?.[1]
  if (!supabaseUrl) throw new Error('VITE_SUPABASE_URL is not set')
  const base = `${supabaseUrl.replace(/\/+$/, '')}/functions/v1/billing`
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

  const catalog = await fetch(`${base}/api/v1/subscriptions/catalog?platform=google_play`)
  const catalogBody = await catalog.json().catch(() => ({}))
  check('live: public catalog lists the 8 Play products at the confirmed prices, no trial', () => {
    assert.equal(catalog.status, 200)
    const products = catalogBody?.data?.products ?? []
    assert.equal(products.length, 8)
    for (const product of products) {
      assert.equal(product.listPrice.amount * 100, listPriceCents(product.tier, product.billingPeriod), product.productId)
      assert.equal(product.productId, playProductIdFor(() => undefined, product.tier, product.billingPeriod))
    }
    assert.deepEqual(catalogBody.data.rules, { freeTier: false, freeTrial: false, annualDiscount: true, moneyBackGuarantee: false })
    assert.equal(catalogBody.data.tiers.length, 4)
  })

  for (const [method, path] of [['GET', '/api/v1/subscriptions/me'], ['GET', '/api/v1/subscriptions/entitlements'], ['GET', '/api/v1/subscriptions/history'], ['POST', '/api/v1/subscriptions/verify'], ['POST', '/api/v1/subscriptions/restore']]) {
    const response = await fetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: method === 'POST' ? '{}' : undefined })
    check(`live: ${method} ${path} without a session is refused (401)`, () => assert.equal(response.status, 401))
  }

  const rtdnBody = JSON.stringify({ message: { messageId: 'forged-1', data: Buffer.from(JSON.stringify({ packageName: 'com.qguard.messaging', subscriptionNotification: { notificationType: 4, purchaseToken: 'x'.repeat(40) } })).toString('base64') } })
  for (const path of ['/api/v1/webhooks/google-play/rtdn', '/api/v1/play-billing/rtdn']) {
    const forgedRtdn = await fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer forged.jwt.token' }, body: rtdnBody })
    check(`live: an unauthenticated RTDN push to ${path} changes nothing`, () => assert.ok([401, 503].includes(forgedRtdn.status), `status ${forgedRtdn.status}`))
  }

  const unknown = await fetch(`${base}/api/v1/nope`, { method: 'POST' })
  check('live: unknown routes are 404, not a crash', () => assert.equal(unknown.status, 404))
}

async function main() {
  await playJwtRoundTrip()
  await playAsyncChecks()
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
