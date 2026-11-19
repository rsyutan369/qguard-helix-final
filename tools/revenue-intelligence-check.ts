/**
 * Revenue Intelligence — offline model proof + live end-to-end checks.
 *
 *   npx tsx tools/revenue-intelligence-check.ts          # pure model + webhook rules (no network)
 *   npx tsx tools/revenue-intelligence-check.ts --live   # + running API (default http://localhost:3000) and the real database
 *
 * The offline half runs the ONE revenue model (src/lib/billing/revenue-model.ts)
 * over a fixture whose every expected figure is computed by hand below, plus
 * negative controls (empty estate, one month of history, UTC boundary, CSV
 * injection). The live half proves what reading code cannot: owner gating,
 * audit rows actually landing, exports, the SSE stream, the RLS holes staying
 * closed, and Admin > Plans & Billing publishing the SAME MRR.
 *
 * Live mode writes only audit rows (the check's own exports/views — they are
 * real actions and stay in the audit trail) and a same-value profile update.
 */
import 'dotenv/config'
import assert from 'node:assert/strict'
import { createClient, type SupabaseClient } from '@supabase/supabase-js'
import {
  buildRevenueModel,
  classifySubscription,
  CYCLE_CHANGE_ACTION,
  PLAN_CHANGE_ACTIONS,
  planChangeAuditAction,
  subscriptionEndedAt,
  subscriptionMrrCents,
  toRevenueSnapshot,
  type InvoiceRecord,
  type RevenueModelInput,
  type SubscriptionRecord,
} from '@/lib/billing/revenue-model'
import { csvCell, buildReportRows } from '@/api-server/revenue'
import {
  activationAuditAction,
  BILLING_AUDIT,
  cancellationPatch,
  failedPaymentInvoiceRow,
  isCancellationRecorded,
  planChangeAction,
  refundInvoicePatch,
  webhookClaimDecision,
  WEBHOOK_CLAIM_STALE_MS,
} from '../supabase/functions/billing/logic'

function serviceClient(url: string, key: string) {
  return createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } })
}
type ServiceClient = ReturnType<typeof serviceClient>

const results: Array<{ name: string; ok: boolean; detail?: string }> = []
async function check(name: string, fn: () => void | Promise<void>) {
  try {
    await fn()
    results.push({ name, ok: true })
  } catch (error) {
    results.push({ name, ok: false, detail: error instanceof Error ? error.message : String(error) })
  }
}

// ---------------------------------------------------------------------------
// Fixture (now = 2026-09-22 12:00 UTC)
// ---------------------------------------------------------------------------

const NOW = new Date('2026-09-22T12:00:00.000Z')
const U = {
  a: '00000000-0000-4000-8000-00000000000a',
  b: '00000000-0000-4000-8000-00000000000b',
  c: '00000000-0000-4000-8000-00000000000c',
  d: '00000000-0000-4000-8000-00000000000d',
  e: '00000000-0000-4000-8000-00000000000e',
  f: '00000000-0000-4000-8000-00000000000f',
}

function sub(partial: Partial<SubscriptionRecord> & Pick<SubscriptionRecord, 'id' | 'user_id'>): SubscriptionRecord {
  return {
    provider: 'paypal', plan: 'Pro', status: 'active', billing_cycle: 'monthly', auto_renew: true, cancel_at_period_end: false,
    renewal_date: null, current_period_end: null, cancelled_at: null, created_at: '2026-06-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
    amount_cents: null, currency: 'USD', metadata: {}, ...partial,
  }
}
function inv(partial: Partial<InvoiceRecord> & Pick<InvoiceRecord, 'id' | 'user_id' | 'payment_date'>): InvoiceRecord {
  return {
    invoice_id: partial.id, amount_paid_cents: 3000, currency: 'USD', payment_method_summary: 'PayPal', subscription_plan: 'Pro',
    status: 'paid', created_at: partial.payment_date as string, updated_at: partial.payment_date, metadata: {}, tax_cents: 0, ...partial,
  }
}

const fixture: RevenueModelInput = {
  now: NOW,
  subscriptions: [
    sub({ id: 's-a', user_id: U.a, plan: 'Pro', created_at: '2026-06-01T00:00:00Z' }),
    sub({ id: 's-b', user_id: U.b, plan: 'Basic', billing_cycle: 'annual', created_at: '2026-07-10T00:00:00Z' }),
    sub({ id: 's-c', user_id: U.c, plan: 'Starter', status: 'cancelled', auto_renew: false, created_at: '2026-05-01T00:00:00Z', cancelled_at: '2026-09-05T00:00:00Z', updated_at: '2026-09-05T00:00:00Z' }),
    sub({ id: 's-d', user_id: U.d, plan: 'Pro', provider: 'manual_test', created_at: '2026-09-17T00:00:00Z' }),
    sub({ id: 's-e', user_id: U.e, plan: 'Elite', provider: null, amount_cents: 19900, created_at: '2026-08-01T00:00:00Z' }),
    sub({ id: 's-f', user_id: U.f, plan: 'Pro', provider: 'google_play', created_at: '2026-09-15T00:00:00Z' }),
  ],
  invoices: [
    inv({ id: 'a1', user_id: U.a, payment_date: '2026-06-01T10:00:00Z' }),
    inv({ id: 'a2', user_id: U.a, payment_date: '2026-07-01T10:00:00Z', status: 'refunded', metadata: { refundedCents: 1000, refundedAt: '2026-07-15T10:00:00Z' } }),
    inv({ id: 'a3', user_id: U.a, payment_date: '2026-08-01T10:00:00Z' }),
    inv({ id: 'a4', user_id: U.a, payment_date: '2026-09-01T10:00:00Z' }),
    inv({ id: 'a-failed', user_id: U.a, payment_date: '2026-09-10T10:00:00Z', status: 'failed' }),
    inv({ id: 'b1', user_id: U.b, payment_date: '2026-07-10T10:00:00Z', amount_paid_cents: 6000, subscription_plan: 'Basic' }),
    inv({ id: 'c1', user_id: U.c, payment_date: '2026-05-01T10:00:00Z', amount_paid_cents: 100, subscription_plan: 'Starter' }),
    inv({ id: 'c2', user_id: U.c, payment_date: '2026-06-01T10:00:00Z', amount_paid_cents: 100, subscription_plan: 'Starter' }),
    inv({ id: 'c3', user_id: U.c, payment_date: '2026-07-01T10:00:00Z', amount_paid_cents: 100, subscription_plan: 'Starter' }),
    inv({ id: 'c4', user_id: U.c, payment_date: '2026-08-01T10:00:00Z', amount_paid_cents: 100, subscription_plan: 'Starter', status: 'refunded', metadata: { refundedAt: '2026-09-03T10:00:00Z' } }),
    inv({ id: 'eur', user_id: U.f, payment_date: '2026-09-16T10:00:00Z', amount_paid_cents: 2500, currency: 'EUR', payment_method_summary: 'Google Play' }),
    inv({ id: 'pend', user_id: U.b, payment_date: '2026-09-20T10:00:00Z', status: 'pending', subscription_plan: 'Basic' }),
  ],
  profiles: [
    { id: U.a, email: 'a@example.com', created_at: '2026-05-20T00:00:00Z' },
    { id: U.b, email: 'b@example.com', created_at: '2026-07-09T00:00:00Z' },
    { id: U.c, email: 'c@example.com', created_at: '2026-04-30T00:00:00Z' },
    { id: U.d, email: 'qa@example.com', created_at: '2026-09-17T00:00:00Z' },
    { id: U.e, email: 'e@example.com', created_at: '2026-08-01T00:00:00Z' },
    { id: U.f, email: 'f@example.com', created_at: '2026-09-15T00:00:00Z' },
    { id: '00000000-0000-4000-8000-000000000099', email: 'free@example.com', created_at: '2026-09-21T00:00:00Z' },
  ],
  auditEvents: [
    { id: 'ev1', user_id: U.a, action: PLAN_CHANGE_ACTIONS.upgraded, message: 'Plan changed', created_at: '2026-09-10T00:00:00Z' },
    { id: 'ev2', user_id: U.a, action: 'paypal.subscription.revise_requested', message: 'request, not a change', created_at: '2026-09-09T00:00:00Z' },
    { id: 'ev3', user_id: U.c, action: PLAN_CHANGE_ACTIONS.downgraded, message: 'old', created_at: '2026-07-01T00:00:00Z' },
  ],
  notifications: [],
  coverage: [],
}

async function offline() {
  await check('classification: provider-billed vs manual vs complimentary', () => {
    assert.equal(classifySubscription({ provider: 'paypal', metadata: {} }).revenueClass, 'provider')
    assert.equal(classifySubscription({ provider: 'google_play', metadata: {} }).revenueClass, 'provider')
    assert.equal(classifySubscription({ provider: 'manual_test', metadata: {} }).revenueClass, 'complimentary')
    assert.equal(classifySubscription({ provider: null, metadata: { source: 'qguard_account_bootstrap' } }).revenueClass, 'complimentary')
    assert.equal(classifySubscription({ provider: 'paypal', metadata: { complimentary: true } }).revenueClass, 'complimentary')
    assert.equal(classifySubscription({ provider: null, metadata: {} }).revenueClass, 'manual')
  })

  await check('MRR contribution: catalog, annual ÷ 12, contract override, and every exclusion', () => {
    const base = fixture.subscriptions[0]
    assert.equal(subscriptionMrrCents(base), 3000)
    assert.equal(subscriptionMrrCents({ ...base, billing_cycle: 'annual' }), 2000, 'annual charge remains 24000 / 12')
    assert.equal(subscriptionMrrCents({ ...base, amount_cents: 5000 }), 5000)
    assert.equal(subscriptionMrrCents({ ...base, status: 'cancelled' }), 0)
    assert.equal(subscriptionMrrCents({ ...base, status: 'past_due' }), 0)
    assert.equal(subscriptionMrrCents({ ...base, provider: 'manual_test' }), 0, 'QA seed must not be revenue')
    assert.equal(subscriptionMrrCents({ ...base, provider: null, amount_cents: 19900 }), 0, 'hand-managed rows are not provider-billed')
    assert.equal(subscriptionMrrCents({ ...base, currency: 'EUR' }), 0, 'no FX: a EUR price is not summed as USD')
    assert.equal(subscriptionMrrCents({ ...base, status: 'pending_renewal' }), 3000)
    assert.equal(subscriptionMrrCents({ ...base, status: 'trial' }), 0, 'no trials exist: trial is not access')
  })

  const model = buildRevenueModel(fixture)

  await check('fixture: MRR / ARR / paying customers (A 3000 + B 6000/12 + F 3000)', () => {
    assert.equal(model.kpis.mrrCents, 6500)
    assert.equal(model.kpis.arrCents, 78000)
    assert.equal(model.kpis.payingCustomers, 3)
    assert.equal(model.subscriptionAnalytics.byClass.complimentary, 1)
    assert.equal(model.subscriptionAnalytics.byClass.manual, 1)
    assert.equal(model.subscriptionAnalytics.manualContractMonthlyCents, 19900)
  })

  await check('fixture: gross / refunds (partial + full) / net, USD only', () => {
    assert.equal(model.kpis.grossRevenueCents, 18400)
    assert.equal(model.kpis.refundedCents, 1100)
    assert.equal(model.kpis.netRevenueCents, 17300)
    assert.deepEqual(model.currencyExclusions, [{ currency: 'EUR', invoices: 1, cents: 2500 }])
  })

  await check('fixture: refunds recognised on the refund date (UTC months)', () => {
    const month = (key: string) => model.timeline.find((bucket) => bucket.month === key)!
    assert.equal(month('2026-07').netCents, 8100, 'July: 9100 collected − 1000 partial refund')
    assert.equal(month('2026-08').netCents, 3100, 'August keeps the charge refunded in September')
    assert.equal(month('2026-09').netCents, 2900, 'September: 3000 − 100 refund')
    assert.equal(model.windows.thisMonthCents, 2900)
    assert.equal(model.windows.lastMonthCents, 3100)
  })

  await check('fixture: payment outcomes and success rate (refunded charges were collected)', () => {
    assert.equal(model.paymentAnalytics.successful, 8)
    assert.equal(model.paymentAnalytics.refunds, 2)
    assert.equal(model.paymentAnalytics.failed, 1)
    assert.equal(model.paymentAnalytics.pending, 1)
    assert.equal(model.paymentAnalytics.successRatePct, 90.9)
    assert.equal(model.paymentAnalytics.averagePaymentCents, 2044)
    assert.equal(model.paymentAnalytics.failedAttemptCents, 3000)
  })

  await check('fixture: churn base excludes accounts younger than the window', () => {
    assert.deepEqual(model.subscriptionAnalytics.churnWindow, { churned: 1, base: 3, days: 30 })
    assert.equal(model.kpis.churnPct, 33.3)
    assert.equal(model.kpis.retentionPct, 66.7)
    assert.equal(model.kpis.arpuCents, 2167, '6500 MRR / 3 paying customers')
    assert.equal(model.kpis.ltvCents, 6508, 'ARPU 2167 / churn 0.333')
  })

  await check('fixture: health = weighted mean of the four measured components', () => {
    assert.equal(model.subscriptionAnalytics.health.measuredWeightPct, 100)
    assert.equal(model.kpis.subscriptionHealthScore, 84)
  })

  await check('fixture: plan changes counted by exact action, 30-day window, requests ignored', () => {
    assert.equal(model.subscriptionAnalytics.upgrades30d, 1)
    assert.equal(model.subscriptionAnalytics.downgrades30d, 0)
  })

  await check('MRR movement: a plan change with no recorded from-plan is NOT guessed (A 3000 + B 500 + C 100 → 6500)', () => {
    const movement = model.mrrMovement
    assert.equal(movement.startingMrrCents, 3600)
    assert.equal(movement.newMrrCents, 3000, 'F: Google Play Pro created inside the window')
    assert.equal(movement.expansionMrrCents, 0)
    assert.equal(movement.contractionMrrCents, 0)
    assert.equal(movement.churnedMrrCents, 100, 'C: Starter cancelled inside the window')
    assert.equal(movement.endingMrrCents, 6500)
    assert.equal(movement.unpricedChanges, 1)
    assert.equal(movement.nrrPct, 97.2, '(3600 − 100) / 3600')
    assert.equal(model.kpis.nrrPct, 97.2)
  })

  await check('MRR movement: upgrade expands MRR and switching Basic to annual contracts it', () => {
    const moved = buildRevenueModel({
      ...fixture,
      auditEvents: [
        { id: 'm1', user_id: U.a, action: PLAN_CHANGE_ACTIONS.upgraded, message: 'Basic → Pro', created_at: '2026-09-10T00:00:00Z', metadata: { fromPlan: 'Basic', toPlan: 'Pro' } },
        { id: 'm2', user_id: U.b, action: CYCLE_CHANGE_ACTION, message: 'monthly → annual', created_at: '2026-09-01T00:00:00Z', metadata: { fromCycle: 'monthly', toCycle: 'annual' } },
        { id: 'm3', user_id: U.c, action: PLAN_CHANGE_ACTIONS.downgraded, message: 'outside the window', created_at: '2026-07-01T00:00:00Z', metadata: { fromPlan: 'Pro', toPlan: 'Starter' } },
      ],
    }).mrrMovement
    assert.equal(moved.startingMrrCents, 1700, 'A was Basic (800) + B was Basic monthly (800) + C Starter (100)')
    assert.equal(moved.expansionMrrCents, 2200, 'A: 800 → 3000')
    assert.equal(moved.contractionMrrCents, 300, 'B: 800 → 6000/12 = 500')
    assert.equal(moved.churnedMrrCents, 100)
    assert.equal(moved.newMrrCents, 3000)
    assert.equal(moved.startingMrrCents + moved.newMrrCents + moved.expansionMrrCents - moved.contractionMrrCents - moved.churnedMrrCents, 6500)
    assert.equal(moved.nrrPct, 205.9, '(1700 + 2200 − 300 − 100) / 1700')
    assert.equal(moved.grrPct, 76.5, '(1700 − 300 − 100) / 1700')
    assert.equal(moved.revenueChurnPct, 5.9, '100 / 1700')
    assert.equal(moved.pricedChanges, 2)
    assert.equal(moved.unpricedChanges, 0)
  })

  await check('MRR movement: no MRR 30 days ago → retention is null, never 0% or 100%', () => {
    const young = buildRevenueModel({ ...fixture, subscriptions: [fixture.subscriptions[5]], auditEvents: [] })
    assert.equal(young.mrrMovement.startingMrrCents, 0)
    assert.equal(young.mrrMovement.nrrPct, null)
    assert.equal(young.mrrMovement.grrPct, null)
    assert.ok(young.reconciliation.ok)
  })

  await check('fixture: growth compares COMPLETED months (Aug vs Jul), never the partial month', () => {
    assert.equal(model.kpis.revenueGrowthPct, -61.7)
  })

  await check('fixture: every cross-page reconciliation invariant holds', () => {
    const failed = model.reconciliation.checks.filter((entry) => !entry.ok)
    assert.equal(failed.length, 0, failed.map((entry) => `${entry.id}: expected ${entry.expected} got ${entry.actual}`).join('; '))
    assert.ok(model.reconciliation.checks.length >= 10)
  })

  await check('fixture: forecast uses completed months only; 4 months = low confidence + 1 backtest point', () => {
    assert.equal(model.forecast.historyMonths, 4)
    assert.equal(model.forecast.firstEvidenceMonth, '2026-05')
    assert.equal(model.forecast.confidence, 'low')
    assert.ok(model.forecast.revenueProjectionAvailable)
    assert.equal(model.forecast.backtest.points.length, 1)
    assert.equal(model.forecast.backtest.points[0].month, '2026-08')
    assert.equal(model.forecast.horizon.length, 6)
    assert.ok(model.forecast.horizon[0].isCurrentMonth)
    assert.equal(model.forecast.horizon[0].actualToDateCents, 2900)
    assert.ok(model.forecast.mrrProjectionAvailable)
    const [conservative, base, optimistic] = model.forecast.scenarios.map((scenario) => scenario.month6MrrCents as number)
    assert.ok(conservative <= base && base <= optimistic, 'scenario bands must be ordered')
    assert.equal(model.forecast.projectedArrCents, base * 12)
  })

  await check('negative control: one month of history withholds every projection', () => {
    const young = buildRevenueModel({
      ...fixture,
      // 28 days old: one completed month (August) and no 30-day churn base yet.
      subscriptions: [sub({ id: 'y', user_id: U.a, created_at: '2026-08-25T00:00:00Z' })],
      invoices: [inv({ id: 'y1', user_id: U.a, payment_date: '2026-08-25T00:00:00Z' })],
      auditEvents: [],
    })
    assert.equal(young.forecast.historyMonths, 1)
    assert.equal(young.forecast.confidence, 'insufficient-history')
    assert.equal(young.forecast.revenueProjectionAvailable, false)
    assert.ok(young.forecast.horizon.every((month) => month.projectedNetCents === null))
    assert.equal(young.kpis.churnPct, null, 'an empty 30-day base is "not measurable", not 0% churn')
    assert.equal(young.forecast.projectedArrCents, null)
    assert.equal(young.forecast.mrrProjectionAvailable, false)
  })

  await check('negative control: empty estate renders unmeasured as null, never 0/100', () => {
    const empty = buildRevenueModel({ ...fixture, subscriptions: [], invoices: [], auditEvents: [] })
    assert.equal(empty.hasData, false)
    assert.equal(empty.kpis.arpuCents, null)
    assert.equal(empty.kpis.ltvCents, null)
    assert.equal(empty.kpis.subscriptionHealthScore, null)
    assert.equal(empty.kpis.churnPct, null)
    assert.equal(empty.paymentAnalytics.successRatePct, null)
    assert.equal(empty.paymentAnalytics.averagePaymentCents, null)
    assert.equal(empty.kpis.revenueGrowthPct, null)
    assert.ok(empty.reconciliation.ok)
  })

  await check('negative control: QA-seeded estate (the live database shape) has ZERO revenue', () => {
    const qa = buildRevenueModel({
      ...fixture,
      subscriptions: ['Starter', 'Basic', 'Pro'].map((plan, index) => sub({ id: `qa${index}`, user_id: `00000000-0000-4000-8000-00000000010${index}`, plan, provider: 'manual_test', created_at: '2026-09-17T00:00:00Z' })),
      invoices: [],
      auditEvents: [],
    })
    assert.equal(qa.kpis.mrrCents, 0, 'the pre-fix dashboard showed $39.00 MRR here')
    assert.equal(qa.kpis.arrCents, 0)
    assert.equal(qa.kpis.subscriptionHealthScore, null, 'the pre-fix dashboard scored this 75')
    assert.equal(qa.subscriptionAnalytics.byClass.complimentary, 3)
    assert.equal(qa.forecast.projectedArrCents, null, 'the pre-fix forecast projected $468 ARR')
  })

  await check('health redistributes weight when a component is unmeasured', () => {
    const noPayments = buildRevenueModel({ ...fixture, invoices: [] })
    const payment = noPayments.subscriptionAnalytics.health.components.find((component) => component.key === 'paymentSuccess')!
    assert.equal(payment.valuePct, null)
    assert.equal(noPayments.subscriptionAnalytics.health.measuredWeightPct, 75)
  })

  await check('UTC boundary: 23:30 UTC on Aug 31 is August, not September', () => {
    const edge = buildRevenueModel({
      ...fixture,
      now: new Date('2026-09-01T00:30:00Z'),
      invoices: [inv({ id: 'edge', user_id: U.a, payment_date: '2026-08-31T23:30:00Z' })],
    })
    assert.equal(edge.windows.thisMonthCents, 0)
    assert.equal(edge.windows.lastMonthCents, 3000)
    assert.equal(edge.windows.todayCents, 0)
    assert.equal(edge.windows.yesterdayCents, 3000)
  })

  await check('snapshot bounds ledgers but never totals', () => {
    const snapshot = toRevenueSnapshot(model, 2)
    assert.equal(snapshot.customers.length, 2)
    assert.equal(snapshot.ledgerTotals.customers, model.customers.length)
    assert.equal(snapshot.kpis.netRevenueCents, model.kpis.netRevenueCents)
  })

  await check('exports read the FULL model (every subscriber, every invoice)', () => {
    assert.equal(buildReportRows(model, 'subscriptions').rows.length, fixture.subscriptions.length)
    assert.equal(buildReportRows(model, 'payments').rows.length, fixture.invoices.length)
    assert.equal(buildReportRows(model, 'revenue').rows.length, 12)
  })

  await check('CSV cells neutralise spreadsheet formulas (CSV injection)', () => {
    assert.equal(csvCell('=HYPERLINK("http://x","y")'), `"'=HYPERLINK(""http://x"",""y"")"`)
    assert.equal(csvCell('+1 555'), "'+1 555")
    assert.equal(csvCell('@SUM(A1)'), "'@SUM(A1)")
    assert.equal(csvCell('-2+3'), "'-2+3")
    assert.equal(csvCell(-5), '-5', 'a numeric cell is data, not a formula')
    assert.equal(csvCell('alice@example.com'), 'alice@example.com')
    assert.equal(csvCell(null), '')
  })

  await check('writer/reader contract: webhook plan-change actions = the actions the model counts', () => {
    assert.equal(BILLING_AUDIT.upgraded, PLAN_CHANGE_ACTIONS.upgraded)
    assert.equal(BILLING_AUDIT.downgraded, PLAN_CHANGE_ACTIONS.downgraded)
    const tiers = ['Starter', 'Basic', 'Pro', 'Elite']
    for (const from of tiers) for (const to of tiers) assert.equal(planChangeAction(from, to), planChangeAuditAction(from, to), `${from} -> ${to}`)
  })

  await check('webhook: activation audit fires once (confirm + webhook = one event)', () => {
    assert.equal(activationAuditAction(null, { plan: 'Pro', providerSubscriptionId: 'I-1' }), BILLING_AUDIT.activated)
    assert.equal(activationAuditAction({ plan: 'Pro', status: 'active', provider_subscription_id: 'I-1' }, { plan: 'Pro', providerSubscriptionId: 'I-1' }), null)
    assert.equal(activationAuditAction({ plan: 'Basic', status: 'active', provider_subscription_id: 'I-1' }, { plan: 'Pro', providerSubscriptionId: 'I-2' }), BILLING_AUDIT.upgraded)
    assert.equal(activationAuditAction({ plan: 'Elite', status: 'cancelled', provider_subscription_id: 'I-1' }, { plan: 'Pro', providerSubscriptionId: 'I-2' }), BILLING_AUDIT.activated)
  })

  await check('webhook: failed payment becomes a FAILED invoice with a stable reference', () => {
    const resource = { id: 'I-SUB', billing_info: { last_failed_payment: { amount: { currency_code: 'USD', value: '30.00' }, time: '2026-09-10T10:00:00Z', reason_code: 'PAYMENT_DENIED' } } }
    const row = failedPaymentInvoiceRow(resource, { user_id: U.a, plan: 'Pro' }, NOW.toISOString())!
    assert.equal(row.status, 'failed')
    assert.equal(row.amount_paid_cents, 3000)
    assert.equal(row.provider_invoice_id, 'failed:I-SUB:2026-09-10T10:00:00Z')
    assert.equal(failedPaymentInvoiceRow(resource, { user_id: U.a, plan: 'Pro' }, 'later')!.provider_invoice_id, row.provider_invoice_id, 'redelivery maps to the same row')
  })

  await check('webhook: refunds accumulate by id, partial + reversal, never double-count', () => {
    const first = refundInvoicePatch({ amount_paid_cents: 3000, metadata: {} }, { id: 'R1', amount: { total: '10.00' }, create_time: '2026-09-02T00:00:00Z' }, 'PAYMENT.SALE.REFUNDED', NOW.toISOString())
    assert.equal(first.isNew, true)
    assert.equal((first.patch.metadata as any).refundedCents, 1000)
    const again = refundInvoicePatch({ amount_paid_cents: 3000, metadata: first.patch.metadata as any }, { id: 'R1', amount: { total: '10.00' } }, 'PAYMENT.SALE.REFUNDED', NOW.toISOString())
    assert.equal(again.isNew, false)
    const second = refundInvoicePatch({ amount_paid_cents: 3000, metadata: first.patch.metadata as any }, { id: 'R2', amount: { total: '5.00' }, create_time: '2026-09-04T00:00:00Z' }, 'PAYMENT.SALE.REFUNDED', NOW.toISOString())
    assert.equal((second.patch.metadata as any).refundedCents, 1500)
    assert.equal((second.patch.metadata as any).refundedAt, '2026-09-04T00:00:00Z')
    const reversal = refundInvoicePatch({ amount_paid_cents: 3000, metadata: {} }, { id: 'SALE-1' }, 'PAYMENT.SALE.REVERSED', NOW.toISOString())
    assert.equal((reversal.patch.metadata as any).refundedCents, 3000)
  })

  await check('cancellation keeps paid access until period end; no paid period = immediate', () => {
    const now = NOW.toISOString()
    const future = '2026-10-15T00:00:00Z'
    const kept = cancellationPatch({ status: 'active', current_period_end: future }, now)
    assert.equal(kept.accessUntil, future)
    assert.equal('status' in kept.patch, false, 'status must stay access-granting until the period ends')
    assert.equal(kept.patch.cancel_at_period_end, true)
    assert.equal(kept.patch.auto_renew, false)
    assert.equal(cancellationPatch({ status: 'active', current_period_end: '2026-09-01T00:00:00Z' }, now).patch.status, 'cancelled', 'period already over')
    assert.equal(cancellationPatch({ status: 'past_due', current_period_end: future }, now).patch.status, 'cancelled', 'an unpaid period grants nothing')
    assert.equal(cancellationPatch({ status: 'active', current_period_end: null }, now).patch.status, 'cancelled', 'no known period end')
    assert.equal(cancellationPatch(null, now).patch.status, 'cancelled')
    assert.equal(isCancellationRecorded({ status: 'active', cancel_at_period_end: true, cancelled_at: now }), true)
    assert.equal(isCancellationRecorded({ status: 'active', cancel_at_period_end: false, cancelled_at: null }), false)
    assert.equal(isCancellationRecorded({ status: 'cancelled' }), true)
  })

  await check('period-end cancellation: counted in MRR (at risk) until it ends, churns on its period-end date', () => {
    const ending = sub({ id: 'x', user_id: U.a, auto_renew: false, cancel_at_period_end: true, cancelled_at: '2026-09-10T00:00:00Z', current_period_end: '2026-10-01T00:00:00Z', created_at: '2026-06-01T00:00:00Z' })
    const live = buildRevenueModel({ ...fixture, subscriptions: [ending], invoices: [], auditEvents: [] })
    assert.equal(live.kpis.mrrCents, 3000)
    assert.equal(live.kpis.mrrAtRiskCents, 3000)
    assert.equal(live.subscriptionAnalytics.endingAtPeriodEnd, 1)
    assert.equal(live.subscriptionAnalytics.churnWindow.churned, 0)
    const expired = { ...ending, status: 'cancelled', updated_at: '2026-10-01T00:07:00Z' }
    assert.equal(subscriptionEndedAt(expired), Date.parse('2026-10-01T00:00:00Z'), 'ended at the period end, not the cancel click')
    const legacy = { ...ending, status: 'cancelled', updated_at: '2026-09-10T00:00:00Z' }
    assert.equal(subscriptionEndedAt(legacy), Date.parse('2026-09-10T00:00:00Z'), 'an immediately-revoked row ended when it was written')
  })

  await check('webhook: claim ledger decisions (run / duplicate / in-progress / stale)', () => {
    const now = NOW.getTime()
    assert.equal(webhookClaimDecision(null, now), 'run')
    assert.equal(webhookClaimDecision({ status: 'processed' }, now), 'duplicate')
    assert.equal(webhookClaimDecision({ status: null }, now), 'duplicate', 'legacy rows default to processed')
    assert.equal(webhookClaimDecision({ status: 'failed' }, now), 'run')
    assert.equal(webhookClaimDecision({ status: 'processing', claimed_at: new Date(now - 5_000).toISOString() }, now), 'in-progress')
    assert.equal(webhookClaimDecision({ status: 'processing', claimed_at: new Date(now - WEBHOOK_CLAIM_STALE_MS - 1).toISOString() }, now), 'run')
  })
}

// ---------------------------------------------------------------------------
// Live
// ---------------------------------------------------------------------------

async function live() {
  const BASE = process.env.REVENUE_CHECK_BASE || 'http://localhost:3000'
  const URL_ = process.env.VITE_SUPABASE_URL || ''
  const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
  const ANON = process.env.VITE_SUPABASE_ANON_KEY || ''
  const OWNER = process.env.REVENUE_CHECK_OWNER || 'zachmatthew369@gmail.com'
  const USER = process.env.REVENUE_CHECK_USER || 'threathunter369@gmail.com'
  if (!URL_ || !SERVICE || !ANON) throw new Error('Missing VITE_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / VITE_SUPABASE_ANON_KEY')
  const admin = serviceClient(URL_, SERVICE)

  async function sessionFor(email: string): Promise<{ token: string; userId: string }> {
    const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
    if (error) throw new Error(`generateLink(${email}): ${error.message}`)
    const anon = createClient(URL_, ANON, { auth: { persistSession: false, autoRefreshToken: false } })
    const { data, error: otpError } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
    if (otpError || !data.session) throw new Error(`verifyOtp(${email}): ${otpError?.message}`)
    mintedSessions.push(anon)
    return { token: data.session.access_token, userId: data.user!.id }
  }
  const auditCount = async (action: string, since: string) => {
    const { count } = await admin.from('admin_audit_events').select('id', { count: 'exact', head: true }).eq('action', action).gte('created_at', since)
    return count || 0
  }

  const owner = await sessionFor(OWNER)
  const user = await sessionFor(USER)
  const startedAt = new Date(Date.now() - 1000).toISOString()
  const get = (path: string, token?: string) => fetch(`${BASE}${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} })

  const snapResponse = await get('/api/v1/revenue/snapshot?fresh=1', owner.token)
  const snapshot = (await snapResponse.json()).data
  await check('live: owner snapshot 200 with a passing reconciliation', () => {
    assert.equal(snapResponse.status, 200)
    assert.ok(snapshot.reconciliation.ok, JSON.stringify(snapshot.reconciliation.checks.filter((c: any) => !c.ok)))
    assert.equal(snapshot.timezone, 'UTC')
    assert.equal(snapshot.coverage.unavailableTables.length, 0, `unreadable: ${snapshot.coverage.unavailableTables}`)
  })

  // Independent recomputation from raw rows, NOT via the model: provider-billed,
  // access-granting, USD, catalog/contract price.
  const { data: rawSubs } = await admin.from('billing_subscriptions').select('provider,plan,status,billing_cycle,amount_cents,currency,metadata')
  const catalogMonthly: Record<string, [number, number]> = { Starter: [100, 100], Basic: [800, 500], Pro: [3000, 2000], Elite: [19900, 15000] }
  const expectedMrr = (rawSubs || []).reduce((sum: number, row: any) => {
    const billed = ['paypal', 'google_play', 'stripe', 'apple'].includes(String(row.provider || '').toLowerCase()) && !row.metadata?.complimentary
    const granting = ['active', 'trial', 'pending_renewal'].includes(String(row.status || '').toLowerCase())
    if (!billed || !granting || String(row.currency || 'USD').toUpperCase() !== 'USD') return sum
    const annual = /annual|year/i.test(String(row.billing_cycle))
    const contract = Number(row.amount_cents) > 0 ? Number(row.amount_cents) : null
    return sum + (contract !== null ? (annual ? Math.round(contract / 12) : contract) : (catalogMonthly[row.plan]?.[annual ? 1 : 0] ?? 0))
  }, 0)
  await check('live: MRR equals an independent recomputation from the raw rows', () => {
    assert.equal(snapshot.kpis.mrrCents, expectedMrr)
  })

  const adminSubs = await get('/api/v1/admin/billing?limit=1', owner.token)
  const adminBody = await adminSubs.json().catch(() => ({}))
  await check('live: Admin > Plans & Billing publishes the SAME MRR and access count', () => {
    assert.equal(adminSubs.status, 200)
    assert.equal(adminBody.data.stats.mrrCents, snapshot.kpis.mrrCents)
    const accessGranting = snapshot.subscriptionAnalytics.active + snapshot.subscriptionAnalytics.trial + snapshot.subscriptionAnalytics.pendingRenewal
    assert.equal(adminBody.data.stats.grantingAccess, accessGranting)
  })

  const forbidden = await get('/api/v1/revenue/snapshot', user.token)
  await check('live: a non-owner is refused (403) and the attempt is audited', async () => {
    assert.equal(forbidden.status, 403)
    // The denial AUDIT is throttled to one row per user per minute (the refusal
    // itself never is), so look back across the throttle window.
    const throttleWindowStart = new Date(Date.parse(startedAt) - 61_000).toISOString()
    assert.ok(await auditCount('revenue.access_denied', throttleWindowStart) >= 1, 'no revenue.access_denied audit row')
  })
  await check('live: no token → 401; forged token → 401', async () => {
    assert.equal((await get('/api/v1/revenue/snapshot')).status, 401)
    assert.equal((await get('/api/v1/revenue/snapshot', 'forged.token.value')).status, 401)
  })
  await check('live: the session token is refused in a query string outside /stream', async () => {
    assert.equal((await fetch(`${BASE}/api/v1/revenue/export?report=summary&format=csv&token=${owner.token}`)).status, 401)
    assert.equal((await fetch(`${BASE}/api/v1/revenue/snapshot?token=${owner.token}`)).status, 401)
  })

  const exportResponse = await get('/api/v1/revenue/export?report=subscriptions&format=csv', owner.token)
  // Read BYTES: Response.text() decodes UTF-8 and silently drops a leading BOM.
  const exportBytes = new Uint8Array(await exportResponse.arrayBuffer())
  const exportText = new TextDecoder().decode(exportBytes)
  await check('live: CSV export — full ledger, BOM, no-store, audited', async () => {
    assert.equal(exportResponse.status, 200)
    assert.deepEqual(Array.from(exportBytes.slice(0, 3)), [0xef, 0xbb, 0xbf], 'missing UTF-8 BOM')
    assert.equal(exportResponse.headers.get('cache-control'), 'no-store')
    assert.equal(Number(exportResponse.headers.get('x-report-rows')), snapshot.ledgerTotals.subscribers)
    assert.equal(exportText.trim().split('\r\n').length - 1, snapshot.ledgerTotals.subscribers)
    assert.ok(await auditCount('revenue.export', startedAt) >= 1, 'no revenue.export audit row')
  })
  await check('live: export validation (bad report / bad format → 400)', async () => {
    assert.equal((await get('/api/v1/revenue/export?report=nope', owner.token)).status, 400)
    assert.equal((await get('/api/v1/revenue/export?report=summary&format=xml', owner.token)).status, 400)
  })

  const someCustomer = snapshot.customers[0]
  await check('live: customer detail — valid, invalid id, unknown id', async () => {
    assert.equal((await get('/api/v1/revenue/customers/not-a-uuid', owner.token)).status, 400)
    assert.equal((await get('/api/v1/revenue/customers/00000000-0000-4000-8000-00000000dead', owner.token)).status, 404)
    assert.equal((await get(`/api/v1/revenue/customers/${user.userId}`, user.token)).status, 403, 'a customer cannot read even their own record here')
    if (someCustomer) {
      const detail = await get(`/api/v1/revenue/customers/${someCustomer.userId}`, owner.token)
      const body = await detail.json()
      assert.equal(detail.status, 200)
      assert.equal(body.data.customer.lifetimeNetCents, someCustomer.lifetimeNetCents, 'detail and ledger must agree')
      assert.ok(await auditCount('revenue.customer.viewed', startedAt) >= 1, 'no revenue.customer.viewed audit row')
    }
  })

  await check('live: SSE stream delivers connected + snapshot via a ticket; JWT-in-URL and forged tickets are refused', async () => {
    const bad = await fetch(`${BASE}/api/v1/revenue/stream?ticket=forged`)
    assert.equal(bad.status, 401)
    const jwtInUrl = await fetch(`${BASE}/api/v1/revenue/stream?token=${encodeURIComponent(owner.token)}`)
    assert.equal(jwtInUrl.status, 401, 'the session JWT must never be accepted in a URL')
    const minted = await fetch(`${BASE}/api/v1/stream-tickets`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${owner.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ stream: 'revenue' }),
    })
    const ticket = ((await minted.json()) as any).data
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 20_000)
    const response = await fetch(`${BASE}${ticket.path}?ticket=${encodeURIComponent(ticket.ticket)}`, { signal: controller.signal })
    assert.equal(response.status, 200)
    assert.match(String(response.headers.get('content-type')), /text\/event-stream/)
    const reader = response.body!.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    const seen = new Set<string>()
    try {
      while (!(seen.has('revenue-connected') && seen.has('revenue-snapshot'))) {
        const { value, done } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        for (const match of buffer.matchAll(/^event: (.+)$/gm)) seen.add(match[1].trim())
      }
    } finally {
      clearTimeout(timer)
      controller.abort()
    }
    assert.ok(seen.has('revenue-connected'), 'no revenue-connected frame')
    assert.ok(seen.has('revenue-snapshot'), 'no revenue-snapshot frame')
  })

  // ---- RLS: the entitlement holes stay closed -------------------------------
  const asUser = createClient(URL_, ANON, { global: { headers: { Authorization: `Bearer ${user.token}` } }, auth: { persistSession: false } })
  const { data: own } = await asUser.from('billing_subscriptions').select('id,plan,status').maybeSingle()
  await check('live: a user cannot rewrite their own subscription row (was: ALLOWED)', async () => {
    assert.ok(own, 'test user has no subscription row to probe')
    const { data: updated } = await asUser.from('billing_subscriptions').update({ plan: 'Elite' }).eq('id', own!.id).select('id')
    assert.equal((updated || []).length, 0, 'UPDATE reached the row')
    const { data: after } = await admin.from('billing_subscriptions').select('plan').eq('id', own!.id).single()
    assert.equal(after!.plan, own!.plan, 'plan changed!')
    const { error: insertError } = await asUser.from('billing_subscriptions').insert({ user_id: user.userId, subscription_id: `probe_${Date.now()}`, plan: 'Elite', status: 'active' })
    assert.ok(insertError, 'INSERT was accepted')
  })
  await check('live: a user cannot raise their own profile tier; ordinary profile edits still work', async () => {
    const { data: profile } = await asUser.from('profiles').select('tier,name').eq('id', user.userId).single()
    const { error: tierError } = await asUser.from('profiles').update({ tier: 'elite' }).eq('id', user.userId)
    assert.ok(tierError && /managed by the platform/.test(tierError.message), `tier write not refused: ${tierError?.message}`)
    const { error: nameError } = await asUser.from('profiles').update({ name: profile!.name }).eq('id', user.userId)
    assert.equal(nameError, null, `same-value name update refused: ${nameError?.message}`)
    const { data: after } = await admin.from('profiles').select('tier').eq('id', user.userId).single()
    assert.equal(after!.tier, profile!.tier)
  })
  await check('live: the access role (Copilot/Admin RBAC) is not self-assignable; Admin can still set it', async () => {
    const { data: before } = await admin.from('profiles').select('role,job_title').eq('id', user.userId).single() as { data: any }
    const { error: directError } = await asUser.from('profiles').update({ role: 'infrastructure_admin' }).eq('id', user.userId)
    assert.ok(directError && /managed by the platform/.test(directError.message), `direct role write not refused: ${directError?.message}`)
    const put = await fetch(`${BASE}/api/v1/profile`, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${user.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'admin', jobTitle: before.job_title ?? '' }),
    })
    assert.equal(put.status, 200, `profile save failed: HTTP ${put.status}`)
    const { data: afterPut } = await admin.from('profiles').select('role').eq('id', user.userId).single() as { data: any }
    assert.equal(afterPut.role, before.role, 'PUT /api/v1/profile changed the access role')
    const { error: adminError } = await admin.from('profiles').update({ role: 'auditor' }).eq('id', user.userId)
    assert.equal(adminError, null, `service role could not assign a role: ${adminError?.message}`)
    await admin.from('profiles').update({ role: before.role }).eq('id', user.userId)
  })

  if (process.argv.includes('--mutate')) await mutate({ admin, owner, get, BASE, URL_, ANON, sessionFor })

  await check('live: opening Settings > Billing never creates an entitlement row', async () => {
    const before = await admin.from('billing_subscriptions').select('id', { count: 'exact', head: true }).eq('user_id', owner.userId)
    const bundle = await get('/api/v1/billing', owner.token)
    const body = await bundle.json().catch(() => ({}))
    const after = await admin.from('billing_subscriptions').select('id', { count: 'exact', head: true }).eq('user_id', owner.userId)
    assert.equal(bundle.status, 200)
    assert.equal(after.count, before.count, 'GET /api/v1/billing inserted a subscription')
    if (!before.count) {
      assert.equal(body.data.subscription.status, 'incomplete', 'a missing row must not read as active')
      const cancel = await fetch(`${BASE}/api/v1/billing/subscription/actions`, { method: 'POST', headers: { Authorization: `Bearer ${owner.token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'cancel' }) })
      assert.equal(cancel.status, 409, 'cancel with no subscription must be 409 NO_SUBSCRIPTION')
    }
  })
}

/**
 * `--mutate`: Admin → database → User UI → Revenue, end to end, on a QA
 * (manual_test) subscription, restored afterwards. Also proves the provider
 * guard with a temporary PayPal-provider row for the owner that is deleted at
 * the end. The PayPal cancel probe uses a subscription id PayPal does not know,
 * so PayPal refuses it and the admin action must FAIL CLOSED (nothing changes).
 */
async function mutate(ctx: {
  admin: ServiceClient
  owner: { token: string; userId: string }
  get: (path: string, token?: string) => Promise<Response>
  BASE: string
  URL_: string
  ANON: string
  sessionFor: (email: string) => Promise<{ token: string; userId: string }>
}) {
  const { admin, owner, BASE } = ctx
  const QA = process.env.REVENUE_CHECK_QA || 'cybersniper26@gmail.com'
  const qa = await ctx.sessionFor(QA)
  const post = (path: string, body: unknown) => fetch(`${BASE}${path}`, { method: 'POST', headers: { Authorization: `Bearer ${owner.token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  const { data: qaSub } = await admin.from('billing_subscriptions').select('id,status,plan,provider,billing_cycle,current_period_end').eq('user_id', qa.userId).single() as { data: any }
  // Admin plan changes go through Manage plan (the one subscription writer); the
  // original period end is passed back so re-activation does not move it.
  const managePlan = (action: string) => post(`/api/v1/admin/users/${qa.userId}/subscription`, {
    action, plan: qaSub.plan, interval: qaSub.billing_cycle, ...(action === 'activate' && qaSub.current_period_end ? { expiresAt: qaSub.current_period_end } : {}),
  })
  const since = new Date(Date.now() - 1000).toISOString()

  await check('mutate: Admin deactivate → suspended (was a CHECK violation), User UI sees it, Revenue counts it', async () => {
    assert.equal(qaSub.provider, 'manual_test', 'refusing to mutate a non-QA subscription')
    const response = await managePlan('deactivate')
    assert.equal(response.status, 200, `deactivate answered ${response.status}: ${await response.clone().text()}`)
    const asQa = createClient(ctx.URL_, ctx.ANON, { global: { headers: { Authorization: `Bearer ${qa.token}` } }, auth: { persistSession: false } })
    const { data: seenByUser } = await asQa.from('billing_subscriptions').select('status').eq('user_id', qa.userId).single() as { data: any }
    assert.equal(seenByUser.status, 'suspended', 'the customer (RLS read, as use-subscription does) must see the admin change')
    const snap = (await (await ctx.get('/api/v1/revenue/snapshot?fresh=1', owner.token)).json()).data
    assert.ok(snap.subscriptionAnalytics.suspended >= 1)
    assert.ok(snap.reconciliation.ok)
  })

  await check('mutate: Admin activate restores access; both changes land in the CUSTOMER billing trail + notifications', async () => {
    const response = await managePlan('activate')
    assert.equal(response.status, 200, `activate answered ${response.status}: ${await response.clone().text()}`)
    const { data: restored } = await admin.from('billing_subscriptions').select('status,current_period_end').eq('id', qaSub.id).single() as { data: any }
    assert.equal(restored.status, qaSub.status)
    assert.equal(Date.parse(restored.current_period_end), Date.parse(qaSub.current_period_end), 'period end moved')
    const { data: trail } = await admin.from('billing_audit_events').select('action,metadata').eq('user_id', qa.userId).gte('created_at', since) as { data: any[] }
    const actions = (trail || []).map((row) => row.action)
    assert.ok(actions.includes('subscription.suspended') && actions.includes('subscription.activated'), `trail: ${actions.join(', ')}`)
    assert.ok((trail || []).every((row) => row.metadata?.source === 'admin' && row.metadata?.actorEmail), 'admin attribution missing')
    const { count } = await admin.from('billing_notifications').select('id', { count: 'exact', head: true }).eq('user_id', qa.userId).gte('created_at', since)
    assert.ok((count || 0) >= 2, 'customer was not notified')
  })

  // Cancellation keeps paid access until period end — through the DEPLOYED
  // billing Edge Function and through the Express twin — then is restored.
  const cancelVia = async (label: string, url: string) => {
    await check(`mutate: customer cancel via ${label} keeps access until period end (QA row restored)`, async () => {
      const { data: before } = await admin.from('billing_subscriptions').select('status,auto_renew,cancel_at_period_end,cancelled_at,current_period_end').eq('user_id', qa.userId).single() as { data: any }
      assert.ok(before.current_period_end && Date.parse(before.current_period_end) > Date.now(), 'QA row needs a future period end')
      try {
        const response = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${qa.token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'cancel' }) })
        const body = await response.json().catch(() => ({}))
        assert.equal(response.status, 200, `cancel answered ${response.status}: ${JSON.stringify(body).slice(0, 200)}`)
        assert.equal(Date.parse(body.data.accessUntil), Date.parse(before.current_period_end), 'response must state the access end')
        const { data: after } = await admin.from('billing_subscriptions').select('status,auto_renew,cancel_at_period_end,cancelled_at').eq('user_id', qa.userId).single() as { data: any }
        assert.equal(after.status, before.status, 'status must stay access-granting until the period ends')
        assert.equal(after.cancel_at_period_end, true)
        assert.equal(after.auto_renew, false)
        assert.ok(after.cancelled_at, 'cancellation time not recorded')
        const again = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${qa.token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'cancel' }) })
        assert.equal(again.status, 200, 'a second cancel must be an idempotent no-op')
      } finally {
        await admin.from('billing_subscriptions').update({ status: before.status, auto_renew: before.auto_renew, cancel_at_period_end: before.cancel_at_period_end, cancelled_at: before.cancelled_at }).eq('user_id', qa.userId)
      }
    })
  }
  await cancelVia('billing Edge Function (deployed)', `${ctx.URL_}/functions/v1/billing/api/v1/billing/subscription/actions`)
  await cancelVia('Express /api/v1/billing', `${BASE}/api/v1/billing/subscription/actions`)

  const probeId = `I-QGCHECK${Date.now().toString(36).toUpperCase()}`
  const { data: existingOwnerSub } = await admin.from('billing_subscriptions').select('id').eq('user_id', owner.userId).maybeSingle()
  if (existingOwnerSub) {
    results.push({ name: 'mutate: provider guard', ok: false, detail: 'owner already has a subscription row; refusing to overwrite it' })
    return
  }
  const { data: temp, error: tempError } = await admin.from('billing_subscriptions').insert({
    user_id: owner.userId, subscription_id: probeId, provider: 'paypal', provider_subscription_id: probeId,
    plan: 'Pro', status: 'active', billing_cycle: 'monthly', auto_renew: true, metadata: { revenueCheckProbe: true },
  }).select('id').single() as { data: any; error: any }
  try {
    await check('mutate: a provider-billed row counts toward MRR on BOTH Revenue and Admin', async () => {
      assert.equal(tempError, null, tempError?.message)
      const snap = (await (await ctx.get('/api/v1/revenue/snapshot?fresh=1', owner.token)).json()).data
      assert.equal(snap.kpis.mrrCents, 3000, 'Revenue Intelligence MRR')
      // A row written straight to the table (as a provider webhook does) bypasses the
      // admin write-path invalidation; Admin models are cached for 5s, so allow that window.
      let adminMrr = -1
      for (let attempt = 0; attempt < 8 && adminMrr !== 3000; attempt += 1) {
        if (attempt) await new Promise((resolve) => setTimeout(resolve, 1000))
        adminMrr = (await (await ctx.get('/api/v1/admin/billing?limit=1', owner.token)).json()).data.stats.mrrCents
      }
      assert.equal(adminMrr, 3000, 'Admin > Plans & Billing MRR (within the 5s model cache window)')
    })
    await check('mutate: Admin cannot change a PayPal-billed plan terms (409 PROVIDER_MANAGED)', async () => {
      const response = await post(`/api/v1/admin/subscriptions/${temp.id}/actions`, { action: 'extend', days: 30 })
      assert.equal(response.status, 409)
      assert.equal((await response.json()).error.code, 'PROVIDER_MANAGED')
    })
    await check('mutate: Admin cancel FAILS CLOSED when PayPal refuses (row stays active)', async () => {
      const response = await post(`/api/v1/admin/subscriptions/${temp.id}/actions`, { action: 'cancel' })
      assert.equal(response.status, 502, `expected 502, got ${response.status}`)
      const { data: still } = await admin.from('billing_subscriptions').select('status').eq('id', temp.id).single() as { data: any }
      assert.equal(still.status, 'active', 'marked cancelled while PayPal would keep billing')
    })
  } finally {
    if (temp?.id) await admin.from('billing_subscriptions').delete().eq('id', temp.id)
  }
}

/**
 * Every magic-link session this check mints is revoked at the end — leaked
 * test sessions inflate the Admin > Security "session sprawl" control.
 */
const mintedSessions: SupabaseClient[] = []

async function main() {
  await offline()
  if (process.argv.includes('--live')) {
    try {
      await live()
    } catch (error) {
      results.push({ name: 'live: setup', ok: false, detail: error instanceof Error ? error.message : String(error) })
    } finally {
      await Promise.all(mintedSessions.map((client) => client.auth.signOut({ scope: 'local' }).catch(() => undefined)))
    }
  }
  let failed = 0
  for (const result of results) {
    console.log(`${result.ok ? 'PASS' : 'FAIL'}  ${result.name}${result.detail ? `\n      ${result.detail}` : ''}`)
    if (!result.ok) failed += 1
  }
  console.log(`\n${results.length - failed}/${results.length} checks passed`)
  process.exit(failed ? 1 : 0)
}

void main()
