/**
 * Render cases for tools/revenue-intelligence-render-check.ts (which loads this
 * file through Vite's SSR loader — run that, not this).
 *
 * Renders every page through the REAL components with the provider value a
 * browser would hold, in each state the provider can be in: loading, first-load
 * error, stale-with-error, empty estate, QA-only estate and a populated estate.
 */
import assert from 'node:assert/strict'
import type { ReactElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import { buildRevenueModel, toRevenueSnapshot, type InvoiceRecord, type SubscriptionRecord } from '@/lib/billing/revenue-model'
import { RevenueContext, type RevenueContextValue } from '@/app/dashboard/revenue-intelligence/_shared'
import OverviewPage from '@/app/dashboard/revenue-intelligence/page'
import RevenuePage from '@/app/dashboard/revenue-intelligence/revenue/page'
import SubscriptionsPage from '@/app/dashboard/revenue-intelligence/subscriptions/page'
import CustomersPage from '@/app/dashboard/revenue-intelligence/customers/page'
import PaymentsPage from '@/app/dashboard/revenue-intelligence/payments/page'
import ForecastPage from '@/app/dashboard/revenue-intelligence/forecast/page'

const PAGES: Array<[string, string, () => ReactElement]> = [
  ['overview', '/dashboard/revenue-intelligence', () => <OverviewPage />],
  ['revenue', '/dashboard/revenue-intelligence/revenue', () => <RevenuePage />],
  ['subscriptions', '/dashboard/revenue-intelligence/subscriptions', () => <SubscriptionsPage />],
  ['customers', '/dashboard/revenue-intelligence/customers', () => <CustomersPage />],
  ['payments', '/dashboard/revenue-intelligence/payments', () => <PaymentsPage />],
  ['forecast', '/dashboard/revenue-intelligence/forecast', () => <ForecastPage />],
]

const NOW = new Date('2026-09-22T12:00:00.000Z')
const sub = (id: string, user: string, extra: Partial<SubscriptionRecord> = {}): SubscriptionRecord => ({
  id, user_id: user, provider: 'paypal', plan: 'Pro', status: 'active', billing_cycle: 'monthly', auto_renew: true, cancel_at_period_end: false,
  renewal_date: '2026-10-01T00:00:00Z', current_period_end: '2026-10-01T00:00:00Z', cancelled_at: null, created_at: '2026-04-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
  amount_cents: null, currency: 'USD', metadata: {}, ...extra,
})
const inv = (id: string, user: string, date: string, extra: Partial<InvoiceRecord> = {}): InvoiceRecord => ({
  id, user_id: user, invoice_id: `SALE-${id}`, payment_date: date, amount_paid_cents: 3000, currency: 'USD', payment_method_summary: 'PayPal',
  subscription_plan: 'Pro', status: 'paid', created_at: date, updated_at: date, metadata: {}, tax_cents: 0, ...extra,
})
const USERS = Array.from({ length: 4 }, (_, index) => `00000000-0000-4000-8000-00000000000${index + 1}`)

const populated = toRevenueSnapshot(buildRevenueModel({
  now: NOW,
  subscriptions: [
    sub('s1', USERS[0]),
    sub('s2', USERS[1], { plan: 'Basic', billing_cycle: 'annual' }),
    sub('s3', USERS[2], { status: 'cancelled', cancelled_at: '2026-09-10T00:00:00Z', created_at: '2026-05-01T00:00:00Z' }),
    sub('s4', USERS[3], { provider: 'manual_test', created_at: '2026-09-17T00:00:00Z' }),
  ],
  invoices: [
    ...['2026-04-01', '2026-05-01', '2026-06-01', '2026-07-01', '2026-08-01', '2026-09-01'].map((date, index) => inv(`a${index}`, USERS[0], `${date}T10:00:00Z`)),
    inv('b1', USERS[1], '2026-06-15T10:00:00Z', { amount_paid_cents: 6000, subscription_plan: 'Basic' }),
    inv('c1', USERS[2], '2026-05-01T10:00:00Z', { status: 'refunded', metadata: { refundedAt: '2026-05-20T00:00:00Z' } }),
    inv('f1', USERS[0], '2026-09-12T10:00:00Z', { status: 'failed' }),
  ],
  profiles: USERS.map((id, index) => ({ id, email: `user${index}@example.com`, created_at: '2026-03-01T00:00:00Z' })),
  auditEvents: [{ id: 'e1', user_id: USERS[0], action: 'payment.succeeded', message: 'Payment received', created_at: '2026-09-01T10:00:01Z' }],
  notifications: [{ id: 'n1', user_id: USERS[0], type: 'billing', severity: 'critical', title: 'Subscription past due', message: 'A payment failed', created_at: '2026-09-12T10:00:00Z' }],
  coverage: [],
}))

const empty = toRevenueSnapshot(buildRevenueModel({ now: NOW, subscriptions: [], invoices: [], profiles: [], auditEvents: [], notifications: [], coverage: [] }))
const qaOnly = toRevenueSnapshot(buildRevenueModel({
  now: NOW,
  subscriptions: ['Starter', 'Basic', 'Pro'].map((plan, index) => sub(`q${index}`, USERS[index], { plan, provider: 'manual_test', created_at: '2026-09-17T00:00:00Z' })),
  invoices: [], profiles: USERS.map((id) => ({ id, email: `${id}@example.com`, created_at: '2026-09-17T00:00:00Z' })), auditEvents: [], notifications: [], coverage: [],
}))

function context(partial: Partial<RevenueContextValue>): RevenueContextValue {
  return {
    snapshot: null, status: 'loading', error: null, stream: 'connecting', lastFrameAt: null, refreshing: false,
    refresh: async () => undefined, exportReport: async () => undefined, exportState: null, dismissExport: () => undefined, openCustomer: () => undefined,
    ...partial,
  }
}

function render(path: string, page: () => ReactElement, value: RevenueContextValue): string {
  return renderToStaticMarkup(
    <MemoryRouter initialEntries={[path]}>
      <RevenueContext.Provider value={value}>{page()}</RevenueContext.Provider>
    </MemoryRouter>,
  )
}

const text = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/&#x27;/g, "'").replace(/\s+/g, ' ')

export async function run(): Promise<number> {
  const results: Array<{ name: string; ok: boolean; detail?: string }> = []
  function check(name: string, fn: () => void) {
    try {
      fn()
      results.push({ name, ok: true })
    } catch (error) {
      results.push({ name, ok: false, detail: error instanceof Error ? error.message.slice(0, 400) : String(error) })
    }
  }

  for (const [name, path, page] of PAGES) {
    check(`${name}: loading shows a skeleton, never a dashboard of $0.00`, () => {
      const html = text(render(path, page, context({ status: 'loading' })))
      assert.match(html, /Reading billing subscriptions/)
      assert.doesNotMatch(html, /\$0\.00/)
    })
    check(`${name}: first-load failure shows the error and a Retry, no figures`, () => {
      const html = text(render(path, page, context({ status: 'error', error: 'Revenue API answered HTTP 500' })))
      assert.match(html, /could not be loaded/)
      assert.match(html, /Retry/)
      assert.doesNotMatch(html, /\$0\.00/)
    })
    check(`${name}: a later failure keeps the last snapshot with a warning`, () => {
      const html = text(render(path, page, context({ status: 'ready', snapshot: populated, error: 'stream dropped', stream: 'reconnecting' })))
      assert.match(html, /Showing the last successful snapshot/)
      assert.match(html, /Reconnecting/)
    })
    check(`${name}: empty estate renders unmeasured as —, with the setup notice`, () => {
      const html = text(render(path, page, context({ status: 'ready', snapshot: empty, stream: 'live' })))
      assert.match(html, /No billing evidence yet/)
      assert.match(html, /checks pass/)
    })
    check(`${name}: QA-only estate discloses the excluded subscriptions`, () => {
      const html = text(render(path, page, context({ status: 'ready', snapshot: qaOnly, stream: 'live' })))
      assert.match(html, /3 subscriptions are excluded from revenue/)
    })
    check(`${name}: populated estate renders without a reconciliation mismatch`, () => {
      const html = text(render(path, page, context({ status: 'ready', snapshot: populated, stream: 'live' })))
      assert.match(html, /Cross-page reconciliation: \d+\/\d+ checks pass/)
      assert.doesNotMatch(html, /undefined|NaN/)
    })
  }

  check('overview: MRR KPI shows the model value; QA estate shows — with the reason', () => {
    const html = text(render(PAGES[0][1], PAGES[0][2], context({ status: 'ready', snapshot: populated, stream: 'live' })))
    assert.ok(html.includes(`MRR`) && html.includes('$35.00'), 'expected MRR $35.00 (Pro $30 + Basic annual $5)')
    const qa = text(render(PAGES[0][1], PAGES[0][2], context({ status: 'ready', snapshot: qaOnly, stream: 'live' })))
    assert.match(qa, /No provider-billed subscription yet/)
    assert.doesNotMatch(qa, /\$39\.00/, 'the pre-fix dashboard showed $39.00 MRR for three QA seeds')
  })
  check('payments: the failed attempt is visible and excluded from revenue', () => {
    const html = text(render(PAGES[4][1], PAGES[4][2], context({ status: 'ready', snapshot: populated, stream: 'live' })))
    assert.match(html, /attempted, not collected/)
    assert.match(html, /failed/i)
  })
  check('forecast: projections and assumptions are labelled, never presented as actuals', () => {
    const html = text(render(PAGES[5][1], PAGES[5][2], context({ status: 'ready', snapshot: populated, stream: 'live' })))
    assert.match(html, /forecast, not actual revenue/)
    assert.match(html, /measured/)
    assert.match(html, /assumption/)
    const qa = text(render(PAGES[5][1], PAGES[5][2], context({ status: 'ready', snapshot: qaOnly, stream: 'live' })))
    assert.match(qa, /Forecast withheld/)
  })
  check('stale stream is announced, not shown as Live', () => {
    const html = text(render(PAGES[0][1], PAGES[0][2], context({ status: 'ready', snapshot: populated, stream: 'stale' })))
    assert.match(html, /Stale — no update in 40s/)
  })

  let failed = 0
  for (const result of results) {
    console.log(`${result.ok ? 'PASS' : 'FAIL'}  ${result.name}${result.detail ? `\n      ${result.detail}` : ''}`)
    if (!result.ok) failed += 1
  }
  console.log(`\n${results.length - failed}/${results.length} render checks passed`)
  return failed ? 1 : 0
}
