/**
 * Revenue Intelligence model — the ONE place every revenue, subscription,
 * customer, payment and forecast figure is computed.
 *
 * Pure and dependency-free (plan catalog + access rule only; no Express, no
 * Supabase, no browser APIs) so that:
 *   - src/api-server/revenue.ts serves it (snapshot, SSE, exports, detail),
 *   - src/api-server/admin.ts reads the SAME MRR rule for Plans & Billing,
 *   - the frontend imports its TYPES (the wire contract cannot drift),
 *   - tools/revenue-intelligence-check.ts proves it offline with fixtures.
 *
 * Accounting rules (each one is a decision, stated once):
 *   1. MRR counts only PROVIDER-BILLED subscriptions (PayPal, Google Play,
 *      Stripe, Apple) in an access-granting status. Test/QA/complimentary
 *      grants and subscriptions created by hand in the Admin console are NOT
 *      revenue — no payment provider has ever charged them. They are counted
 *      and disclosed separately, never folded into MRR.
 *   2. Cash figures come from billing_invoices in the reporting currency
 *      (USD). Invoices in another currency are disclosed and excluded from
 *      USD totals: there is no FX source, and summing EUR into USD is wrong.
 *   3. A refund is recognised at the time it happened, for the amount that
 *      was refunded (partial refunds supported via metadata.refundedCents).
 *   4. All calendar windows are UTC. Server-local time made "This Month" and
 *      the monthly timeline disagree whenever the server was not on UTC.
 *   5. Unmeasured is null, never 0 and never 100. Composite scores exclude
 *      unmeasured components and redistribute their weight.
 *   6. Forecasts use COMPLETED months only, never the partial current month,
 *      and every projection states whether its inputs are measured or assumed.
 */
import { PLAN_TIERS, planChargeCents, type PlanTier } from './plan-pricing'
import { isAccessGrantingStatus } from '../subscription-access'
import { buildBillingOps, type BillingOps, type InboxRecord } from './billing-ops'

// ---------------------------------------------------------------------------
// Raw rows (the subset of columns the model reads)
// ---------------------------------------------------------------------------

export interface SubscriptionRecord {
  id: string
  user_id: string
  subscription_id?: string | null
  provider: string | null
  plan: string | null
  status: string | null
  billing_cycle: string | null
  auto_renew: boolean | null
  cancel_at_period_end: boolean | null
  renewal_date: string | null
  current_period_start?: string | null
  current_period_end: string | null
  cancelled_at: string | null
  created_at: string
  updated_at: string | null
  amount_cents?: number | string | null
  currency?: string | null
  metadata?: Record<string, unknown> | null
}

export interface InvoiceRecord {
  id: string
  user_id: string
  invoice_id: string | null
  provider_invoice_id?: string | null
  transaction_id?: string | null
  payment_date: string | null
  amount_paid_cents: number | string | null
  tax_cents?: number | string | null
  currency: string | null
  payment_method_summary: string | null
  subscription_plan: string | null
  status: string | null
  created_at: string
  updated_at?: string | null
  metadata?: Record<string, unknown> | null
}

export interface ProfileRecord {
  id: string
  email: string | null
  name?: string | null
  full_name?: string | null
  tier?: string | null
  created_at: string | null
}

export interface AuditRecord {
  id: string
  user_id: string | null
  action: string | null
  message: string | null
  created_at: string
  metadata?: Record<string, unknown> | null
}

export interface NotificationRecord {
  id: string
  user_id: string | null
  type: string | null
  severity: string | null
  title: string | null
  message: string | null
  created_at: string
}

/** How completely a source table was read. `truncated` means a ceiling was hit. */
export interface SourceCoverage {
  table: string
  rows: number
  available: boolean
  truncated: boolean
  error: string | null
}

export interface RevenueModelInput {
  now: Date
  subscriptions: SubscriptionRecord[]
  invoices: InvoiceRecord[]
  profiles: ProfileRecord[]
  auditEvents: AuditRecord[]
  notifications: NotificationRecord[]
  /** Google Play RTDN inbox + verification ledger (play_webhook_events); optional for older callers. */
  billingInbox?: InboxRecord[]
  coverage: SourceCoverage[]
}

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

export const REPORTING_CURRENCY = 'USD'
export const REPORTING_TIMEZONE = 'UTC'
const DAY_MS = 86_400_000

export type RevenueClass = 'provider' | 'manual' | 'complimentary'

/** Payment providers that actually charge the customer. */
export const PROVIDER_BILLED = new Set(['paypal', 'google_play', 'stripe', 'apple'])
/** Grants that no provider ever charged: QA seeds, comps, demos. */
export const COMPLIMENTARY_PROVIDERS = new Set(['manual_test', 'test', 'qa', 'comp', 'complimentary', 'demo', 'internal', 'sandbox'])

/**
 * Canonical billing audit actions the revenue model counts. The writers
 * (supabase/functions/billing/logic.ts BILLING_AUDIT, admin.ts) emit exactly
 * these strings; tools/revenue-intelligence-check.ts asserts the two agree.
 */
export const PLAN_CHANGE_ACTIONS = {
  upgraded: 'subscription.upgraded',
  downgraded: 'subscription.downgraded',
} as const
/** A monthly <-> annual switch: the monthly-equivalent price moves with it. */
export const CYCLE_CHANGE_ACTION = 'subscription.cycle_changed'
export const MRR_MOVEMENT_DAYS = 30


export function normalizePlanTier(value: unknown): PlanTier | null {
  const text = String(value ?? '').trim().toLowerCase()
  return PLAN_TIERS.find((tier) => tier.toLowerCase() === text) ?? null
}

/** The audit action a plan move represents (null when the tier did not change). */
export function planChangeAuditAction(fromPlan: unknown, toPlan: unknown): (typeof PLAN_CHANGE_ACTIONS)[keyof typeof PLAN_CHANGE_ACTIONS] | null {
  const from = normalizePlanTier(fromPlan)
  const to = normalizePlanTier(toPlan)
  if (!from || !to || from === to) return null
  return PLAN_TIERS.indexOf(to) > PLAN_TIERS.indexOf(from) ? PLAN_CHANGE_ACTIONS.upgraded : PLAN_CHANGE_ACTIONS.downgraded
}

export function isAnnualCycle(cycle: unknown): boolean {
  const text = String(cycle ?? '').toLowerCase()
  return text.includes('annual') || text.includes('year')
}

function lower(value: unknown): string {
  return String(value ?? '').trim().toLowerCase()
}

function toMs(value: unknown): number | null {
  if (!value) return null
  const ms = Date.parse(String(value))
  return Number.isFinite(ms) ? ms : null
}

function toCents(value: unknown): number {
  const num = Number(value)
  return Number.isFinite(num) ? Math.round(num) : 0
}

function meta(record: { metadata?: Record<string, unknown> | null }): Record<string, unknown> {
  const value = record?.metadata
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function round1(value: number): number {
  return Math.round(value * 10) / 10
}

// ---------------------------------------------------------------------------
// Subscription rules
// ---------------------------------------------------------------------------

export function classifySubscription(sub: Pick<SubscriptionRecord, 'provider' | 'metadata'>): { revenueClass: RevenueClass; reason: string } {
  const provider = lower(sub.provider)
  const metadata = meta(sub)
  if (COMPLIMENTARY_PROVIDERS.has(provider)) {
    return { revenueClass: 'complimentary', reason: `Provider "${provider}" is a test/complimentary grant — never charged` }
  }
  if (metadata.complimentary === true || metadata.comp === true) {
    return { revenueClass: 'complimentary', reason: 'Flagged complimentary in subscription metadata' }
  }
  if (metadata.source === 'qguard_account_bootstrap') {
    return { revenueClass: 'complimentary', reason: 'Bootstrap row created by the billing API — never charged' }
  }
  if (PROVIDER_BILLED.has(provider)) {
    return { revenueClass: 'provider', reason: `Billed by ${providerLabel(provider)}` }
  }
  return {
    revenueClass: 'manual',
    reason: 'Managed by hand (Admin console) — no payment provider has charged it, so it is excluded from MRR',
  }
}

export function providerLabel(provider: unknown): string {
  const value = lower(provider)
  if (value === 'paypal') return 'PayPal'
  if (value === 'google_play') return 'Google Play'
  if (value === 'stripe') return 'Stripe'
  if (value === 'apple') return 'Apple App Store'
  if (!value) return 'Manual'
  if (value === 'manual_test') return 'Manual (test)'
  return value.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

export function subscriptionCurrency(sub: Pick<SubscriptionRecord, 'currency'>): string {
  return String(sub.currency || REPORTING_CURRENCY).trim().toUpperCase() || REPORTING_CURRENCY
}

/**
 * Per-cycle charge. An explicit contracted `amount_cents` wins (set by the
 * Admin console for negotiated deals); otherwise the list price from the plan
 * catalog. Returns `priceSource` so a reader can tell which one answered.
 */
export function subscriptionChargeCents(sub: Pick<SubscriptionRecord, 'plan' | 'billing_cycle' | 'amount_cents'>): { cents: number; priceSource: 'contract' | 'catalog' | 'unknown' } {
  const contracted = toCents(sub.amount_cents)
  if (contracted > 0) return { cents: contracted, priceSource: 'contract' }
  const tier = normalizePlanTier(sub.plan)
  if (!tier) return { cents: 0, priceSource: 'unknown' }
  return { cents: planChargeCents(tier, isAnnualCycle(sub.billing_cycle) ? 'yearly' : 'monthly'), priceSource: 'catalog' }
}

/** Monthly-equivalent value of the subscription's price (annual ÷ 12). */
export function subscriptionMonthlyValueCents(sub: Pick<SubscriptionRecord, 'plan' | 'billing_cycle' | 'amount_cents'>): number {
  const { cents } = subscriptionChargeCents(sub)
  return isAnnualCycle(sub.billing_cycle) ? Math.round(cents / 12) : cents
}

/**
 * The MRR a subscription contributes RIGHT NOW. Zero unless it is
 * provider-billed, access-granting and priced in the reporting currency.
 * This is the rule admin.ts uses too, so both screens show one MRR.
 */
export function subscriptionMrrCents(sub: SubscriptionRecord): number {
  if (!isAccessGrantingStatus(sub.status)) return 0
  if (classifySubscription(sub).revenueClass !== 'provider') return 0
  if (subscriptionCurrency(sub) !== REPORTING_CURRENCY) return 0
  return subscriptionMonthlyValueCents(sub)
}

/**
 * When the subscription stopped granting access (null while it still does).
 * A cancellation at period end keeps access until current_period_end, so that
 * — not the day the customer clicked cancel — is when it churned. Never later
 * than the moment the row was last written: a row that no longer grants
 * access has ended by then.
 */
export function subscriptionEndedAt(sub: SubscriptionRecord): number | null {
  if (isAccessGrantingStatus(sub.status)) return null
  const candidates = sub.cancel_at_period_end
    ? [sub.current_period_end, sub.cancelled_at, sub.updated_at, sub.created_at]
    : [sub.cancelled_at, sub.current_period_end, sub.updated_at, sub.created_at]
  const ended = candidates.map(toMs).find((ms): ms is number => ms !== null) ?? null
  const recorded = toMs(sub.updated_at)
  return ended !== null && recorded !== null ? Math.min(ended, recorded) : ended
}

// ---------------------------------------------------------------------------
// Invoice rules
// ---------------------------------------------------------------------------

export function invoiceCurrency(invoice: Pick<InvoiceRecord, 'currency'>): string {
  return String(invoice.currency || REPORTING_CURRENCY).trim().toUpperCase() || REPORTING_CURRENCY
}

export function invoiceAmountCents(invoice: Pick<InvoiceRecord, 'amount_paid_cents'>): number {
  return Math.max(0, toCents(invoice.amount_paid_cents))
}

/** Amount refunded on a refunded invoice (partial refunds via metadata.refundedCents). */
export function invoiceRefundCents(invoice: InvoiceRecord): number {
  if (lower(invoice.status) !== 'refunded') return 0
  const amount = invoiceAmountCents(invoice)
  const recorded = toCents(meta(invoice).refundedCents)
  return recorded > 0 ? Math.min(recorded, amount) : amount
}

export function invoicePaidAt(invoice: InvoiceRecord): number | null {
  return toMs(invoice.payment_date) ?? toMs(invoice.created_at)
}

export function invoiceRefundedAt(invoice: InvoiceRecord): number | null {
  if (lower(invoice.status) !== 'refunded') return null
  return toMs(meta(invoice).refundedAt) ?? toMs(invoice.updated_at) ?? invoicePaidAt(invoice)
}

/** A charge the provider collected (a later refund does not un-collect it). */
function isCollected(invoice: InvoiceRecord): boolean {
  const status = lower(invoice.status)
  return status === 'paid' || status === 'refunded'
}

// ---------------------------------------------------------------------------
// UTC calendar
// ---------------------------------------------------------------------------

export function utcMonthKey(ms: number): string {
  const date = new Date(ms)
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`
}

export function monthStartMs(key: string): number {
  const [year, month] = key.split('-').map(Number)
  return Date.UTC(year, (month || 1) - 1, 1)
}

function addMonths(key: string, delta: number): string {
  const [year, month] = key.split('-').map(Number)
  return utcMonthKey(Date.UTC(year, (month || 1) - 1 + delta, 1))
}

export function monthLabel(key: string): string {
  return new Date(monthStartMs(key)).toLocaleDateString('en-US', { month: 'short', year: 'numeric', timeZone: 'UTC' })
}

export function utcWindowStarts(nowMs: number) {
  const now = new Date(nowMs)
  const y = now.getUTCFullYear()
  const m = now.getUTCMonth()
  const d = now.getUTCDate()
  const startOfDay = Date.UTC(y, m, d)
  const mondayOffset = (now.getUTCDay() + 6) % 7
  return {
    startOfDay,
    startOfYesterday: startOfDay - DAY_MS,
    startOfWeek: startOfDay - mondayOffset * DAY_MS,
    startOfMonth: Date.UTC(y, m, 1),
    startOfLastMonth: Date.UTC(y, m - 1, 1),
    startOfQuarter: Date.UTC(y, Math.floor(m / 3) * 3, 1),
    startOfYear: Date.UTC(y, 0, 1),
    startOf12Months: Date.UTC(y, m - 11, 1),
  }
}

// ---------------------------------------------------------------------------
// Forecast math
// ---------------------------------------------------------------------------

/** Least-squares line through (0..n-1, series). Null below two points. */
export function linearFit(series: number[]): { slope: number; intercept: number } | null {
  const n = series.length
  if (n < 2) return null
  const meanX = (n - 1) / 2
  const meanY = series.reduce((sum, value) => sum + value, 0) / n
  let numerator = 0
  let denominator = 0
  for (let index = 0; index < n; index += 1) {
    numerator += (index - meanX) * (series[index] - meanY)
    denominator += (index - meanX) ** 2
  }
  const slope = denominator === 0 ? 0 : numerator / denominator
  return { slope, intercept: meanY - slope * meanX }
}

/** Project `periods` values after the series. Negative revenue floors at 0. */
export function linearProjection(series: number[], periods: number): number[] | null {
  const fit = linearFit(series)
  if (!fit) return null
  const out: number[] = []
  for (let step = 1; step <= periods; step += 1) {
    out.push(Math.max(0, Math.round(fit.intercept + fit.slope * (series.length - 1 + step))))
  }
  return out
}

export const FORECAST_MIN_MONTHS = 3
export const FORECAST_HORIZON = 6

export const FORECAST_SCENARIOS = [
  { key: 'conservative', label: 'Conservative', newMultiplier: 0.5, churnMultiplier: 1.5 },
  { key: 'base', label: 'Base (measured)', newMultiplier: 1, churnMultiplier: 1 },
  { key: 'optimistic', label: 'Optimistic', newMultiplier: 1.5, churnMultiplier: 0.5 },
] as const

/** MRR_k = MRR_{k-1} × (1 − churn) + newMRR — the standard retention model. */
export function projectRecurring(baseline: number, monthlyChurnRate: number, monthlyNew: number, periods: number): number[] {
  const out: number[] = []
  let current = baseline
  for (let step = 0; step < periods; step += 1) {
    current = Math.max(0, current * (1 - monthlyChurnRate) + monthlyNew)
    out.push(Math.round(current))
  }
  return out
}

// ---------------------------------------------------------------------------
// Output contract
// ---------------------------------------------------------------------------

export interface TimelineBucket {
  month: string
  label: string
  /** false for the current (partial) month */
  complete: boolean
  grossCents: number
  refundedCents: number
  netCents: number
  payments: number
  failedPayments: number
  newSubscriptions: number
  churnedSubscriptions: number
  newSignups: number
  newMrrCents: number
  /** MRR reconstructed at month end from subscription start/end dates at current price */
  endingMrrCents: number
}

export interface HealthComponent {
  key: 'activeShare' | 'renewalIntent' | 'paymentSuccess' | 'retention'
  label: string
  weight: number
  valuePct: number | null
  reason: string | null
}

export interface CustomerRow {
  userId: string
  email: string | null
  name: string | null
  plan: string | null
  status: string | null
  revenueClass: RevenueClass | null
  provider: string | null
  billingCycle: string | null
  since: string | null
  renewalDate: string | null
  lifetimeNetCents: number
  paidInvoices: number
  failedPayments: number
  lastPaymentAt: string | null
  mrrCents: number
}

export interface SubscriberRow {
  id: string
  userId: string
  email: string | null
  plan: string | null
  status: string | null
  revenueClass: RevenueClass
  classReason: string
  provider: string | null
  providerLabel: string
  billingCycle: string | null
  autoRenew: boolean
  cancelAtPeriodEnd: boolean
  since: string
  renewalDate: string | null
  mrrCents: number
  monthlyValueCents: number
  priceSource: 'contract' | 'catalog' | 'unknown'
  currency: string
  updatedAt: string | null
}

export interface InvoiceLedgerRow {
  id: string
  invoiceId: string
  userId: string
  email: string | null
  plan: string | null
  amountCents: number
  refundedCents: number
  currency: string
  inReportingCurrency: boolean
  method: string | null
  status: string
  paidAt: string | null
  refundedAt: string | null
  transactionId: string | null
}

export interface ActivityEntry {
  id: string
  at: string
  kind: 'audit' | 'payment' | 'refund' | 'failure'
  title: string
  detail: string
  userId: string | null
  email: string | null
  amountCents: number | null
  severity: 'info' | 'success' | 'warning' | 'critical'
}

export interface AlertEntry {
  id: string
  at: string
  type: string
  severity: 'info' | 'success' | 'warning' | 'critical'
  title: string
  message: string
  userId: string | null
  email: string | null
}

/**
 * How MRR moved over the trailing window. The five movements always satisfy
 *   starting + new + expansion − contraction − churned = ending (= MRR today),
 * which the reconciliation asserts on every build.
 */
export interface MrrMovement {
  windowDays: number
  /** MRR of provider-billed subscriptions that were live when the window opened */
  startingMrrCents: number
  /** Provider-billed subscriptions created inside the window and still granting access */
  newMrrCents: number
  /** Upgrades (and cycle switches that raised the monthly-equivalent price) */
  expansionMrrCents: number
  /** Downgrades (and cycle switches that lowered the monthly-equivalent price) */
  contractionMrrCents: number
  /** Subscriptions live at the window start that have since stopped granting access */
  churnedMrrCents: number
  endingMrrCents: number
  netNewMrrCents: number
  /** (starting + expansion − contraction − churned) ÷ starting. Null when starting MRR is 0. */
  nrrPct: number | null
  /** (starting − contraction − churned) ÷ starting. Null when starting MRR is 0. */
  grrPct: number | null
  revenueChurnPct: number | null
  newSubscriptions: number
  churnedSubscriptions: number
  /** Plan / cycle changes re-priced from the audit trail */
  pricedChanges: number
  /** Changes that could not be re-priced (negotiated price, or no from-plan recorded) — counted as no movement */
  unpricedChanges: number
}

export interface ReconciliationCheck {
  id: string
  label: string
  expected: number
  actual: number
  ok: boolean
}

export interface ForecastMonth {
  month: string
  label: string
  isCurrentMonth: boolean
  /** Actual net revenue recorded so far in this month (current month only) */
  actualToDateCents: number | null
  projectedNetCents: number | null
  projectedMrrCents: number | null
  projectedMrrLowCents: number | null
  projectedMrrHighCents: number | null
  projectedSubscribers: number | null
}

export interface ForecastAssumption {
  label: string
  value: string
  kind: 'measured' | 'assumption' | 'derived'
  detail: string
}

export interface RevenueForecast {
  methodology: string[]
  confidence: 'insufficient-history' | 'low' | 'medium' | 'high'
  confidenceReason: string
  historyMonths: number
  firstEvidenceMonth: string | null
  revenueProjectionAvailable: boolean
  revenueProjectionReason: string | null
  mrrProjectionAvailable: boolean
  mrrProjectionReason: string | null
  horizon: ForecastMonth[]
  revenueTrendCentsPerMonth: number | null
  projectedArrCents: number | null
  scenarios: Array<{ key: string; label: string; newMultiplier: number; churnMultiplier: number; month6MrrCents: number | null; month6ArrCents: number | null }>
  assumptions: ForecastAssumption[]
  backtest: {
    points: Array<{ month: string; label: string; predictedCents: number; actualCents: number; absErrorPct: number | null }>
    mapePct: number | null
    reason: string | null
  }
}

export interface RevenueModel {
  generatedAt: string
  reportingCurrency: string
  timezone: string
  hasData: boolean
  hasRevenueEvidence: boolean
  coverage: { tables: SourceCoverage[]; complete: boolean; unavailableTables: string[]; truncatedTables: string[] }
  kpis: {
    grossRevenueCents: number
    refundedCents: number
    netRevenueCents: number
    mrrCents: number
    arrCents: number
    arpuCents: number | null
    ltvCents: number | null
    /** Last completed month vs the one before it */
    revenueGrowthPct: number | null
    /** Month-to-date vs the same number of days last month */
    mtdGrowthPct: number | null
    payingSubscribers: number
    payingCustomers: number
    subscriptionHealthScore: number | null
    churnPct: number | null
    retentionPct: number | null
    mrrAtRiskCents: number
    /** Net revenue retention over the trailing 30 days (null until there is starting MRR) */
    nrrPct: number | null
  }
  mrrMovement: MrrMovement
  windows: {
    todayCents: number
    yesterdayCents: number
    thisWeekCents: number
    thisMonthCents: number
    lastMonthCents: number
    thisQuarterCents: number
    thisYearCents: number
    last12MonthsCents: number
    allTimeCents: number
  }
  timeline: TimelineBucket[]
  revenueByProvider: Array<{ label: string; cents: number; count: number }>
  revenueByPlan: Array<{ label: string; cents: number; count: number }>
  revenueByCurrency: Array<{ currency: string; cents: number; count: number; inReportingCurrency: boolean }>
  currencyExclusions: Array<{ currency: string; invoices: number; cents: number }>
  paymentAnalytics: {
    successful: number
    failed: number
    refunds: number
    pending: number
    attempted: number
    successRatePct: number | null
    averagePaymentCents: number | null
    failedAttemptCents: number
    refundedCents: number
    totalRecords: number
  }
  subscriptionAnalytics: {
    total: number
    byClass: Record<RevenueClass, number>
    accessGrantingByClass: Record<RevenueClass, number>
    active: number
    trial: number
    pendingRenewal: number
    pastDue: number
    suspended: number
    cancelled: number
    expired: number
    incomplete: number
    otherStatus: number
    payingActive: number
    renewing: number
    endingAtPeriodEnd: number
    renewalRatePct: number | null
    upgrades30d: number
    downgrades30d: number
    churnPct: number | null
    retentionPct: number | null
    churnWindow: { churned: number; base: number; days: number }
    healthScore: number | null
    healthReason: string | null
    health: { components: HealthComponent[]; measuredWeightPct: number }
    planBreakdown: Array<{ plan: string; total: number; accessGranting: number; paying: number; trial: number; cancelled: number; mrrCents: number; collectedCents: number }>
    manualContractMonthlyCents: number
  }
  customerAnalytics: {
    registeredUsers: number
    customersWithBilling: number
    payingCustomers: number
    lapsedCustomers: number
    complimentaryAccounts: number
    manualAccounts: number
    trialUsers: number
    cancelledCustomers: number
    newSignups30d: number
    signupGrowthPct: number | null
    enterpriseCustomers: number
    arpuCents: number | null
    ltvCents: number | null
    averageLifetimeValueCents: number | null
  }
  customers: CustomerRow[]
  subscribers: SubscriberRow[]
  invoices: InvoiceLedgerRow[]
  activity: ActivityEntry[]
  alerts: AlertEntry[]
  forecast: RevenueForecast
  reconciliation: { ok: boolean; checks: ReconciliationCheck[] }
  dataGaps: Array<{ metric: string; reason: string }>
  /** Store lifecycle + RTDN pipeline health (billing-ops.ts). */
  billingOps: BillingOps
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

const HEALTH_WEIGHTS: Array<Pick<HealthComponent, 'key' | 'label' | 'weight'>> = [
  { key: 'activeShare', label: 'Active share of billed subscriptions', weight: 30 },
  { key: 'renewalIntent', label: 'Renewal intent (auto-renew on)', weight: 25 },
  { key: 'paymentSuccess', label: 'Payment success rate', weight: 25 },
  { key: 'retention', label: '30-day retention', weight: 20 },
]

function severityOf(value: unknown): 'info' | 'success' | 'warning' | 'critical' {
  const text = lower(value)
  return text === 'success' || text === 'warning' || text === 'critical' ? text : 'info'
}

function humanizeAction(action: unknown): string {
  const text = String(action || 'billing event').replace(/[._]/g, ' ').trim()
  return text.charAt(0).toUpperCase() + text.slice(1)
}

function pct(numerator: number, denominator: number): number | null {
  return denominator > 0 ? round1((numerator / denominator) * 100) : null
}

function growth(current: number, previous: number): number | null {
  return previous > 0 ? round1(((current - previous) / previous) * 100) : null
}

export function buildRevenueModel(input: RevenueModelInput): RevenueModel {
  const nowMs = input.now.getTime()
  const starts = utcWindowStarts(nowMs)
  const currentMonth = utcMonthKey(nowMs)
  const profiles = input.profiles
  const profileById = new Map(profiles.map((profile) => [String(profile.id), profile]))
  const emailOf = (userId: string | null | undefined) => (userId ? profileById.get(String(userId))?.email ?? null : null)
  const nameOf = (userId: string) => {
    const profile = profileById.get(userId)
    return profile?.full_name || profile?.name || null
  }

  // ---- Subscriptions ------------------------------------------------------
  const subs = input.subscriptions.map((sub) => {
    const cls = classifySubscription(sub)
    const status = lower(sub.status)
    const charge = subscriptionChargeCents(sub)
    return {
      sub,
      status,
      revenueClass: cls.revenueClass,
      classReason: cls.reason,
      granting: isAccessGrantingStatus(status),
      mrrCents: subscriptionMrrCents(sub),
      monthlyValueCents: isAnnualCycle(sub.billing_cycle) ? Math.round(charge.cents / 12) : charge.cents,
      priceSource: charge.priceSource,
      createdMs: toMs(sub.created_at) ?? nowMs,
      endedMs: subscriptionEndedAt(sub),
    }
  })
  const billed = subs.filter((entry) => entry.revenueClass === 'provider')
  // `incomplete` = a checkout that never activated (PayPal APPROVAL_PENDING).
  // It was never a live subscription, so it cannot be a new one or churn.
  const billedLive = billed.filter((entry) => entry.status !== 'incomplete')
  const billedGranting = billed.filter((entry) => entry.granting)
  const mrrCents = subs.reduce((sum, entry) => sum + entry.mrrCents, 0)
  const arrCents = mrrCents * 12
  const payingCustomerIds = new Set(billedGranting.filter((entry) => entry.mrrCents > 0).map((entry) => entry.sub.user_id))
  const mrrAtRiskCents = billedGranting
    .filter((entry) => entry.sub.cancel_at_period_end || !entry.sub.auto_renew)
    .reduce((sum, entry) => sum + entry.mrrCents, 0)

  const statusCount = (status: string) => subs.filter((entry) => entry.status === status).length
  const KNOWN_STATUSES = ['active', 'trial', 'pending_renewal', 'past_due', 'suspended', 'cancelled', 'expired', 'incomplete']
  const byClass: Record<RevenueClass, number> = { provider: 0, manual: 0, complimentary: 0 }
  const grantingByClass: Record<RevenueClass, number> = { provider: 0, manual: 0, complimentary: 0 }
  for (const entry of subs) {
    byClass[entry.revenueClass] += 1
    if (entry.granting) grantingByClass[entry.revenueClass] += 1
  }

  // Churn over the trailing 30 days: billed subscriptions that were live at the
  // window start and have since ended. Subscriptions younger than the window
  // are not in the base — a 3-day-old account cannot have "retained" 30 days.
  const churnWindowStart = nowMs - 30 * DAY_MS
  const churnBase = billedLive.filter((entry) => entry.createdMs < churnWindowStart && (entry.endedMs === null || entry.endedMs >= churnWindowStart))
  const churned = churnBase.filter((entry) => entry.endedMs !== null && entry.endedMs <= nowMs)
  const churnPct = pct(churned.length, churnBase.length)
  const retentionPct = churnPct === null ? null : round1(100 - churnPct)

  const renewing = billedGranting.filter((entry) => entry.sub.auto_renew && !entry.sub.cancel_at_period_end).length
  const renewalRatePct = pct(renewing, billedGranting.length)

  const upgradeCutoff = nowMs - 30 * DAY_MS
  const recentAudit = input.auditEvents.filter((event) => (toMs(event.created_at) ?? 0) >= upgradeCutoff)
  const upgrades30d = recentAudit.filter((event) => event.action === PLAN_CHANGE_ACTIONS.upgraded).length
  const downgrades30d = recentAudit.filter((event) => event.action === PLAN_CHANGE_ACTIONS.downgraded).length

  // ---- MRR movement (trailing 30 days) --------------------------------------
  // Each subscription that was live when the window opened is walked BACK
  // through its plan / cycle changes (billing_audit_events carry fromPlan and
  // fromCycle) to the list price it had at the window start. The difference
  // is expansion or contraction; a row that stopped granting access is churn.
  const movementStart = nowMs - MRR_MOVEMENT_DAYS * DAY_MS
  const listMonthlyCents = (plan: unknown, cycle: unknown): number | null => {
    const tier = normalizePlanTier(plan)
    if (!tier) return null
    const annual = isAnnualCycle(cycle)
    const cents = planChargeCents(tier, annual ? 'yearly' : 'monthly')
    return annual ? Math.round(cents / 12) : cents
  }
  const changesByUser = new Map<string, AuditRecord[]>()
  for (const event of input.auditEvents) {
    const at = toMs(event.created_at)
    if (!event.user_id || at === null || at < movementStart || at > nowMs) continue
    if (event.action !== PLAN_CHANGE_ACTIONS.upgraded && event.action !== PLAN_CHANGE_ACTIONS.downgraded && event.action !== CYCLE_CHANGE_ACTION) continue
    const list = changesByUser.get(event.user_id) || []
    list.push(event)
    changesByUser.set(event.user_id, list)
  }
  const usdBilledLive = billedLive.filter((entry) => subscriptionCurrency(entry.sub) === REPORTING_CURRENCY)
  const movementBase = usdBilledLive.filter((entry) => entry.createdMs < movementStart && (entry.endedMs === null || entry.endedMs >= movementStart))
  const movementNew = usdBilledLive.filter((entry) => entry.createdMs >= movementStart && entry.granting)
  let startingMrrCents = 0
  let expansionMrrCents = 0
  let contractionMrrCents = 0
  let churnedMrrCents = 0
  let churnedInMovement = 0
  let pricedChanges = 0
  let unpricedChanges = 0
  for (const entry of movementBase) {
    const endValue = entry.monthlyValueCents
    let startValue = endValue
    const changes = (changesByUser.get(entry.sub.user_id) || []).sort((a, b) => (toMs(b.created_at) ?? 0) - (toMs(a.created_at) ?? 0))
    if (changes.length > 0) {
      let plan: unknown = entry.sub.plan
      let cycle: unknown = entry.sub.billing_cycle
      let priced = entry.priceSource === 'catalog'
      for (const change of changes) {
        const details = meta(change)
        if (change.action === CYCLE_CHANGE_ACTION) {
          if (details.fromCycle) cycle = details.fromCycle
          else priced = false
        } else if (normalizePlanTier(details.fromPlan)) {
          plan = details.fromPlan
        } else {
          priced = false
        }
      }
      const repriced = priced ? listMonthlyCents(plan, cycle) : null
      if (repriced === null) unpricedChanges += changes.length
      else {
        startValue = repriced
        pricedChanges += changes.length
      }
    }
    startingMrrCents += startValue
    if (endValue > startValue) expansionMrrCents += endValue - startValue
    else contractionMrrCents += startValue - endValue
    if (entry.endedMs !== null) {
      churnedMrrCents += endValue
      churnedInMovement += 1
    }
  }
  const newMrrCents = movementNew.reduce((sum, entry) => sum + entry.mrrCents, 0)
  const retainedMrrCents = startingMrrCents + expansionMrrCents - contractionMrrCents - churnedMrrCents
  const mrrMovement: MrrMovement = {
    windowDays: MRR_MOVEMENT_DAYS,
    startingMrrCents,
    newMrrCents,
    expansionMrrCents,
    contractionMrrCents,
    churnedMrrCents,
    endingMrrCents: mrrCents,
    netNewMrrCents: mrrCents - startingMrrCents,
    nrrPct: pct(retainedMrrCents, startingMrrCents),
    grrPct: pct(startingMrrCents - contractionMrrCents - churnedMrrCents, startingMrrCents),
    revenueChurnPct: pct(churnedMrrCents, startingMrrCents),
    newSubscriptions: movementNew.length,
    churnedSubscriptions: churnedInMovement,
    pricedChanges,
    unpricedChanges,
  }

  // ---- Invoices -----------------------------------------------------------
  const invoiceRows = input.invoices.map((invoice) => {
    const currency = invoiceCurrency(invoice)
    return {
      invoice,
      status: lower(invoice.status),
      currency,
      usd: currency === REPORTING_CURRENCY,
      amountCents: invoiceAmountCents(invoice),
      refundCents: invoiceRefundCents(invoice),
      paidAt: invoicePaidAt(invoice),
      refundedAt: invoiceRefundedAt(invoice),
    }
  })
  const usdInvoices = invoiceRows.filter((row) => row.usd)
  const collectedUsd = usdInvoices.filter((row) => isCollected(row.invoice))
  const grossRevenueCents = collectedUsd.reduce((sum, row) => sum + row.amountCents, 0)
  const refundedCents = usdInvoices.reduce((sum, row) => sum + row.refundCents, 0)
  const netRevenueCents = grossRevenueCents - refundedCents

  /** Net USD recognised in [from, to): charges by payment time, refunds by refund time. */
  const netBetween = (fromMs: number, toMs: number = Number.POSITIVE_INFINITY) => {
    let cents = 0
    for (const row of collectedUsd) {
      if (row.paidAt !== null && row.paidAt >= fromMs && row.paidAt < toMs) cents += row.amountCents
    }
    for (const row of usdInvoices) {
      if (row.refundCents > 0 && row.refundedAt !== null && row.refundedAt >= fromMs && row.refundedAt < toMs) cents -= row.refundCents
    }
    return cents
  }

  const windows = {
    todayCents: netBetween(starts.startOfDay),
    yesterdayCents: netBetween(starts.startOfYesterday, starts.startOfDay),
    thisWeekCents: netBetween(starts.startOfWeek),
    thisMonthCents: netBetween(starts.startOfMonth),
    lastMonthCents: netBetween(starts.startOfLastMonth, starts.startOfMonth),
    thisQuarterCents: netBetween(starts.startOfQuarter),
    thisYearCents: netBetween(starts.startOfYear),
    last12MonthsCents: netBetween(starts.startOf12Months),
    allTimeCents: netRevenueCents,
  }

  // ---- Monthly timeline (UTC, last 12 months) ------------------------------
  const monthKeys: string[] = []
  for (let offset = 11; offset >= 0; offset -= 1) monthKeys.push(addMonths(currentMonth, -offset))
  const timeline: TimelineBucket[] = monthKeys.map((key) => {
    const from = monthStartMs(key)
    const to = key === currentMonth ? nowMs + 1 : monthStartMs(addMonths(key, 1))
    const monthEnd = key === currentMonth ? nowMs : to
    let gross = 0
    let payments = 0
    for (const row of collectedUsd) {
      if (row.paidAt !== null && row.paidAt >= from && row.paidAt < to) {
        gross += row.amountCents
        payments += 1
      }
    }
    let refunded = 0
    for (const row of usdInvoices) {
      if (row.refundCents > 0 && row.refundedAt !== null && row.refundedAt >= from && row.refundedAt < to) refunded += row.refundCents
    }
    const failedPayments = invoiceRows.filter((row) => row.status === 'failed' && row.paidAt !== null && row.paidAt >= from && row.paidAt < to).length
    const created = billedLive.filter((entry) => entry.createdMs >= from && entry.createdMs < to)
    const churnedInMonth = billedLive.filter((entry) => entry.endedMs !== null && entry.endedMs >= from && entry.endedMs < to).length
    const endingMrrCents = billedLive
      .filter((entry) => entry.createdMs < monthEnd && (entry.endedMs === null || entry.endedMs >= monthEnd) && subscriptionCurrency(entry.sub) === REPORTING_CURRENCY)
      .reduce((sum, entry) => sum + entry.monthlyValueCents, 0)
    const newSignups = profiles.filter((profile) => {
      const at = toMs(profile.created_at)
      return at !== null && at >= from && at < to
    }).length
    return {
      month: key,
      label: monthLabel(key),
      complete: key !== currentMonth,
      grossCents: gross,
      refundedCents: refunded,
      netCents: gross - refunded,
      payments,
      failedPayments,
      newSubscriptions: created.length,
      churnedSubscriptions: churnedInMonth,
      newSignups,
      newMrrCents: created.filter((entry) => subscriptionCurrency(entry.sub) === REPORTING_CURRENCY).reduce((sum, entry) => sum + entry.monthlyValueCents, 0),
      endingMrrCents,
    }
  })

  const completed = timeline.filter((bucket) => bucket.complete)
  const lastComplete = completed[completed.length - 1]
  const priorComplete = completed[completed.length - 2]
  const revenueGrowthPct = lastComplete && priorComplete ? growth(lastComplete.netCents, priorComplete.netCents) : null
  const daysIntoMonth = Math.floor((nowMs - starts.startOfMonth) / DAY_MS) + 1
  const lastMonthSameSpan = netBetween(starts.startOfLastMonth, Math.min(starts.startOfLastMonth + daysIntoMonth * DAY_MS, starts.startOfMonth))
  const mtdGrowthPct = growth(windows.thisMonthCents, lastMonthSameSpan)

  // ---- Breakdowns -----------------------------------------------------------
  const group = (rows: typeof collectedUsd, keyOf: (row: (typeof collectedUsd)[number]) => string) => {
    const grouped = new Map<string, { cents: number; count: number }>()
    for (const row of rows) {
      const key = keyOf(row) || 'Other'
      const entry = grouped.get(key) || { cents: 0, count: 0 }
      entry.cents += row.amountCents
      entry.count += 1
      grouped.set(key, entry)
    }
    return Array.from(grouped.entries())
      .map(([label, value]) => ({ label, cents: value.cents, count: value.count }))
      .sort((a, b) => b.cents - a.cents || a.label.localeCompare(b.label))
  }
  const revenueByProvider = group(collectedUsd, (row) => row.invoice.payment_method_summary || 'Other')
  const revenueByPlan = group(collectedUsd, (row) => normalizePlanTier(row.invoice.subscription_plan) || 'Other')

  const currencyGroups = new Map<string, { cents: number; count: number }>()
  for (const row of invoiceRows.filter((entry) => isCollected(entry.invoice))) {
    const entry = currencyGroups.get(row.currency) || { cents: 0, count: 0 }
    entry.cents += row.amountCents
    entry.count += 1
    currencyGroups.set(row.currency, entry)
  }
  const revenueByCurrency = Array.from(currencyGroups.entries())
    .map(([currency, value]) => ({ currency, cents: value.cents, count: value.count, inReportingCurrency: currency === REPORTING_CURRENCY }))
    .sort((a, b) => Number(b.inReportingCurrency) - Number(a.inReportingCurrency) || b.count - a.count)
  const currencyExclusions = revenueByCurrency
    .filter((entry) => !entry.inReportingCurrency)
    .map((entry) => ({ currency: entry.currency, invoices: entry.count, cents: entry.cents }))

  // ---- Payments ---------------------------------------------------------------
  const countStatus = (status: string) => invoiceRows.filter((row) => row.status === status).length
  const successful = countStatus('paid')
  const refunds = countStatus('refunded')
  const failed = countStatus('failed')
  const pending = countStatus('pending')
  const collectedCount = successful + refunds
  const attempted = collectedCount + failed
  const paymentAnalytics = {
    successful,
    failed,
    refunds,
    pending,
    attempted,
    successRatePct: pct(collectedCount, attempted),
    averagePaymentCents: collectedUsd.length > 0 ? Math.round(grossRevenueCents / collectedUsd.length) : null,
    failedAttemptCents: usdInvoices.filter((row) => row.status === 'failed').reduce((sum, row) => sum + row.amountCents, 0),
    refundedCents,
    totalRecords: invoiceRows.length,
  }

  // ---- Health (weights redistributed over MEASURED components only) ----------
  const components: HealthComponent[] = HEALTH_WEIGHTS.map((spec) => {
    if (spec.key === 'activeShare') {
      return { ...spec, valuePct: pct(billedGranting.length, billedLive.length), reason: billedLive.length ? null : 'No provider-billed subscriptions yet' }
    }
    if (spec.key === 'renewalIntent') {
      return { ...spec, valuePct: renewalRatePct, reason: renewalRatePct === null ? 'No active provider-billed subscriptions' : null }
    }
    if (spec.key === 'paymentSuccess') {
      return { ...spec, valuePct: paymentAnalytics.successRatePct, reason: paymentAnalytics.successRatePct === null ? 'No payment attempts recorded yet' : null }
    }
    return { ...spec, valuePct: retentionPct, reason: retentionPct === null ? 'Needs billed subscriptions older than 30 days' : null }
  })
  const measured = components.filter((component) => component.valuePct !== null)
  const measuredWeight = measured.reduce((sum, component) => sum + component.weight, 0)
  const healthScore = measured.length > 0 && measuredWeight > 0
    ? Math.round(measured.reduce((sum, component) => sum + (component.valuePct as number) * component.weight, 0) / measuredWeight)
    : null
  const healthReason = healthScore === null ? 'No provider-billed subscription or payment evidence to score yet' : null

  const planBreakdown = PLAN_TIERS.map((plan) => {
    const ofPlan = subs.filter((entry) => normalizePlanTier(entry.sub.plan) === plan)
    return {
      plan,
      total: ofPlan.length,
      accessGranting: ofPlan.filter((entry) => entry.granting).length,
      paying: ofPlan.filter((entry) => entry.mrrCents > 0).length,
      trial: ofPlan.filter((entry) => entry.status === 'trial').length,
      cancelled: ofPlan.filter((entry) => entry.status === 'cancelled').length,
      mrrCents: ofPlan.reduce((sum, entry) => sum + entry.mrrCents, 0),
      collectedCents: revenueByPlan.find((entry) => entry.label === plan)?.cents ?? 0,
    }
  })

  const subscriptionAnalytics = {
    total: subs.length,
    byClass,
    accessGrantingByClass: grantingByClass,
    active: statusCount('active'),
    trial: statusCount('trial'),
    pendingRenewal: statusCount('pending_renewal'),
    pastDue: statusCount('past_due'),
    suspended: statusCount('suspended'),
    cancelled: statusCount('cancelled'),
    expired: statusCount('expired'),
    incomplete: statusCount('incomplete'),
    otherStatus: subs.filter((entry) => !KNOWN_STATUSES.includes(entry.status)).length,
    payingActive: billedGranting.filter((entry) => entry.mrrCents > 0).length,
    renewing,
    endingAtPeriodEnd: billedGranting.filter((entry) => entry.sub.cancel_at_period_end).length,
    renewalRatePct,
    upgrades30d,
    downgrades30d,
    churnPct,
    retentionPct,
    churnWindow: { churned: churned.length, base: churnBase.length, days: 30 },
    healthScore,
    healthReason,
    health: { components, measuredWeightPct: measuredWeight },
    planBreakdown,
    manualContractMonthlyCents: subs
      .filter((entry) => entry.revenueClass === 'manual' && entry.granting)
      .reduce((sum, entry) => sum + entry.monthlyValueCents, 0),
  }

  // ---- Customers --------------------------------------------------------------
  const subByUser = new Map<string, (typeof subs)[number]>()
  for (const entry of subs) {
    const existing = subByUser.get(entry.sub.user_id)
    if (!existing || (toMs(entry.sub.updated_at) ?? 0) > (toMs(existing.sub.updated_at) ?? 0)) subByUser.set(entry.sub.user_id, entry)
  }
  const invoicesByUser = new Map<string, typeof invoiceRows>()
  for (const row of invoiceRows) {
    const list = invoicesByUser.get(row.invoice.user_id) || []
    list.push(row)
    invoicesByUser.set(row.invoice.user_id, list)
  }
  const customerIds = new Set<string>([...subByUser.keys(), ...invoicesByUser.keys()])
  const customers: CustomerRow[] = Array.from(customerIds).map((userId) => {
    const entry = subByUser.get(userId)
    const own = invoicesByUser.get(userId) || []
    const usdOwn = own.filter((row) => row.usd)
    const lifetimeNetCents = usdOwn.filter((row) => isCollected(row.invoice)).reduce((sum, row) => sum + row.amountCents, 0)
      - usdOwn.reduce((sum, row) => sum + row.refundCents, 0)
    const lastPayment = own
      .filter((row) => isCollected(row.invoice) && row.paidAt !== null)
      .sort((a, b) => (b.paidAt as number) - (a.paidAt as number))[0]
    return {
      userId,
      email: emailOf(userId),
      name: nameOf(userId),
      plan: entry?.sub.plan ?? null,
      status: entry?.sub.status ?? null,
      revenueClass: entry?.revenueClass ?? null,
      provider: entry?.sub.provider ?? null,
      billingCycle: entry?.sub.billing_cycle ?? null,
      since: entry?.sub.created_at ?? profileById.get(userId)?.created_at ?? null,
      renewalDate: entry?.sub.renewal_date ?? entry?.sub.current_period_end ?? null,
      lifetimeNetCents,
      paidInvoices: own.filter((row) => isCollected(row.invoice)).length,
      failedPayments: own.filter((row) => row.status === 'failed').length,
      lastPaymentAt: lastPayment?.paidAt ? new Date(lastPayment.paidAt).toISOString() : null,
      mrrCents: entry?.mrrCents ?? 0,
    }
  }).sort((a, b) => b.lifetimeNetCents - a.lifetimeNetCents || (toMs(b.since) ?? 0) - (toMs(a.since) ?? 0))

  const everPaidIds = new Set(invoiceRows.filter((row) => isCollected(row.invoice)).map((row) => row.invoice.user_id))
  const billedEverIds = new Set(billedLive.map((entry) => entry.sub.user_id))
  const customersWithBilling = new Set([...everPaidIds, ...billedEverIds]).size
  const newSignups30d = profiles.filter((profile) => (toMs(profile.created_at) ?? 0) >= nowMs - 30 * DAY_MS).length
  const priorSignups30d = profiles.filter((profile) => {
    const at = toMs(profile.created_at) ?? 0
    return at >= nowMs - 60 * DAY_MS && at < nowMs - 30 * DAY_MS
  }).length
  const arpuCents = payingCustomerIds.size > 0 ? Math.round(mrrCents / payingCustomerIds.size) : null
  const ltvCents = arpuCents !== null && churnPct !== null && churnPct > 0 ? Math.round(arpuCents / (churnPct / 100)) : null

  const customerAnalytics = {
    registeredUsers: profiles.length,
    customersWithBilling,
    payingCustomers: payingCustomerIds.size,
    lapsedCustomers: Array.from(new Set([...everPaidIds, ...billedEverIds])).filter((id) => !payingCustomerIds.has(id)).length,
    complimentaryAccounts: new Set(subs.filter((entry) => entry.revenueClass === 'complimentary' && entry.granting).map((entry) => entry.sub.user_id)).size,
    manualAccounts: new Set(subs.filter((entry) => entry.revenueClass === 'manual' && entry.granting).map((entry) => entry.sub.user_id)).size,
    trialUsers: new Set(subs.filter((entry) => entry.status === 'trial').map((entry) => entry.sub.user_id)).size,
    cancelledCustomers: new Set(billed.filter((entry) => entry.status === 'cancelled' || entry.status === 'expired').map((entry) => entry.sub.user_id)).size,
    newSignups30d,
    signupGrowthPct: growth(newSignups30d, priorSignups30d),
    enterpriseCustomers: new Set(billedGranting.filter((entry) => normalizePlanTier(entry.sub.plan) === 'Elite').map((entry) => entry.sub.user_id)).size,
    arpuCents,
    ltvCents,
    averageLifetimeValueCents: everPaidIds.size > 0 ? Math.round(netRevenueCents / everPaidIds.size) : null,
  }

  const subscribers: SubscriberRow[] = subs
    .map((entry) => ({
      id: entry.sub.id,
      userId: entry.sub.user_id,
      email: emailOf(entry.sub.user_id),
      plan: entry.sub.plan,
      status: entry.sub.status,
      revenueClass: entry.revenueClass,
      classReason: entry.classReason,
      provider: entry.sub.provider,
      providerLabel: providerLabel(entry.sub.provider),
      billingCycle: entry.sub.billing_cycle,
      autoRenew: Boolean(entry.sub.auto_renew),
      cancelAtPeriodEnd: Boolean(entry.sub.cancel_at_period_end),
      since: entry.sub.created_at,
      renewalDate: entry.sub.renewal_date ?? entry.sub.current_period_end ?? null,
      mrrCents: entry.mrrCents,
      monthlyValueCents: entry.monthlyValueCents,
      priceSource: entry.priceSource,
      currency: subscriptionCurrency(entry.sub),
      updatedAt: entry.sub.updated_at,
    }))
    .sort((a, b) => (toMs(b.updatedAt) ?? 0) - (toMs(a.updatedAt) ?? 0))

  const invoices: InvoiceLedgerRow[] = invoiceRows
    .map((row) => ({
      id: row.invoice.id,
      invoiceId: row.invoice.invoice_id || row.invoice.id,
      userId: row.invoice.user_id,
      email: emailOf(row.invoice.user_id),
      plan: row.invoice.subscription_plan,
      amountCents: row.amountCents,
      refundedCents: row.refundCents,
      currency: row.currency,
      inReportingCurrency: row.usd,
      method: row.invoice.payment_method_summary,
      status: row.status || 'pending',
      paidAt: row.paidAt !== null ? new Date(row.paidAt).toISOString() : null,
      refundedAt: row.refundedAt !== null ? new Date(row.refundedAt).toISOString() : null,
      transactionId: row.invoice.transaction_id ?? null,
    }))
    .sort((a, b) => (toMs(b.paidAt) ?? 0) - (toMs(a.paidAt) ?? 0))

  // ---- Activity + alerts --------------------------------------------------------
  const activity: ActivityEntry[] = [
    ...input.auditEvents.map((event) => ({
      id: `audit:${event.id}`,
      at: event.created_at,
      kind: 'audit' as const,
      title: humanizeAction(event.action),
      detail: String(event.message || ''),
      userId: event.user_id,
      email: emailOf(event.user_id),
      amountCents: null,
      severity: /failed|past_due|suspend|expired/.test(lower(event.action)) ? 'critical' as const
        : /cancel|refund|downgrad|ended/.test(lower(event.action)) ? 'warning' as const : 'info' as const,
    })),
    ...invoiceRows.flatMap((row) => {
      const entries: ActivityEntry[] = []
      const email = emailOf(row.invoice.user_id)
      const plan = row.invoice.subscription_plan || 'subscription'
      const reference = row.invoice.invoice_id || row.invoice.id
      if (row.paidAt !== null) {
        entries.push({
          id: `invoice:${row.invoice.id}`,
          at: new Date(row.paidAt).toISOString(),
          kind: row.status === 'failed' ? 'failure' : 'payment',
          title: row.status === 'failed' ? `Payment failed — ${plan}` : row.status === 'pending' ? `Payment pending — ${plan}` : `Payment received — ${plan}`,
          detail: `${row.invoice.payment_method_summary || 'Payment'} · ${reference}`,
          userId: row.invoice.user_id,
          email,
          amountCents: row.amountCents,
          severity: row.status === 'failed' ? 'critical' : row.status === 'pending' ? 'warning' : 'success',
        })
      }
      if (row.refundCents > 0 && row.refundedAt !== null) {
        entries.push({
          id: `refund:${row.invoice.id}`,
          at: new Date(row.refundedAt).toISOString(),
          kind: 'refund',
          title: `Refund issued — ${plan}`,
          detail: `${row.invoice.payment_method_summary || 'Payment'} · ${reference}`,
          userId: row.invoice.user_id,
          email,
          amountCents: -row.refundCents,
          severity: 'warning',
        })
      }
      return entries
    }),
  ]
    .filter((entry) => toMs(entry.at) !== null)
    .sort((a, b) => (toMs(b.at) as number) - (toMs(a.at) as number))
    .slice(0, 60)

  const alerts: AlertEntry[] = input.notifications
    .map((notification) => ({
      id: String(notification.id),
      at: notification.created_at,
      type: String(notification.type || 'billing'),
      severity: severityOf(notification.severity),
      title: String(notification.title || ''),
      message: String(notification.message || ''),
      userId: notification.user_id,
      email: emailOf(notification.user_id),
    }))
    .sort((a, b) => (toMs(b.at) ?? 0) - (toMs(a.at) ?? 0))

  // ---- Forecast -------------------------------------------------------------------
  const forecast = buildForecast({
    timeline,
    currentMonth,
    mrrCents,
    payingSubscribers: subscriptionAnalytics.payingActive,
    churnPct,
    thisMonthCents: windows.thisMonthCents,
  })

  // ---- Coverage + disclosures ---------------------------------------------------------
  const unavailableTables = input.coverage.filter((entry) => !entry.available).map((entry) => entry.table)
  const truncatedTables = input.coverage.filter((entry) => entry.truncated).map((entry) => entry.table)

  const dataGaps: Array<{ metric: string; reason: string }> = [
    { metric: 'Revenue by Country / Geography', reason: 'Customer country is not captured at checkout. Add billing-address capture (PayPal payer country / Play regionCode) to unlock geographic analytics.' },
    { metric: 'CAC / Burn Rate / Profit Margin / EBITDA', reason: 'Requires acquisition-spend and operating-cost inputs the platform does not track. Connect a cost source to compute these.' },
    { metric: 'DAU / MAU / Sessions', reason: 'Product usage telemetry is not wired into billing analytics.' },
    { metric: 'Revenue by Product (Helix vs Messaging)', reason: 'Plans are platform-wide tiers; invoices carry no per-product line items, so revenue cannot be split by product without inventing an allocation.' },
    { metric: 'Stripe / Apple App Store', reason: 'Not integrated. Revenue covers PayPal and Google Play payments recorded in billing_invoices.' },
  ]
  if (invoiceRows.some((row) => lower(row.invoice.payment_method_summary) === 'google play')) {
    dataGaps.push({ metric: 'Google Play settled amounts', reason: 'Google Play subscriptionsv2 does not return the charged amount; Play invoices carry the catalog list price (USD), not the settled amount net of Google fees and local taxes.' })
  }
  if (invoiceRows.length > 0 && invoiceRows.every((row) => toCents(row.invoice.tax_cents) === 0)) {
    dataGaps.push({ metric: 'Sales tax / VAT', reason: 'No invoice records a tax amount — tax is not captured from the payment providers yet.' })
  }

  // ---- Reconciliation (cross-page invariants, asserted every build) ------------------
  const sum = (values: number[]) => values.reduce((total, value) => total + value, 0)
  const checks: ReconciliationCheck[] = [
    { id: 'mrr-by-plan', label: 'MRR by plan sums to MRR', expected: mrrCents, actual: sum(planBreakdown.map((plan) => plan.mrrCents)) },
    { id: 'provider-revenue', label: 'Revenue by provider sums to gross revenue', expected: grossRevenueCents, actual: sum(revenueByProvider.map((row) => row.cents)) },
    { id: 'plan-revenue', label: 'Revenue by plan sums to gross revenue', expected: grossRevenueCents, actual: sum(revenueByPlan.map((row) => row.cents)) },
    { id: 'customer-ledger', label: 'Customer lifetime revenue sums to net revenue', expected: netRevenueCents, actual: sum(customers.map((row) => row.lifetimeNetCents)) },
    { id: 'all-time-window', label: 'All-time window equals net revenue', expected: netRevenueCents, actual: windows.allTimeCents },
    { id: 'timeline-12m', label: '12-month timeline sums to trailing-12-month window', expected: windows.last12MonthsCents, actual: sum(timeline.map((bucket) => bucket.netCents)) },
    { id: 'payment-outcomes', label: 'Payment outcomes sum to payment records', expected: paymentAnalytics.totalRecords, actual: successful + failed + refunds + pending + invoiceRows.filter((row) => !['paid', 'failed', 'refunded', 'pending'].includes(row.status)).length },
    { id: 'subscription-classes', label: 'Billed + manual + complimentary = all subscriptions', expected: subs.length, actual: byClass.provider + byClass.manual + byClass.complimentary },
    { id: 'subscription-statuses', label: 'Status board sums to all subscriptions', expected: subs.length, actual: KNOWN_STATUSES.reduce((total, status) => total + statusCount(status), 0) + subscriptionAnalytics.otherStatus },
    { id: 'paying-customers', label: 'Paying customers match paying subscribers', expected: subscriptionAnalytics.payingActive, actual: payingCustomerIds.size },
    { id: 'mrr-movement', label: 'Starting MRR + new + expansion − contraction − churned = MRR', expected: mrrCents, actual: startingMrrCents + newMrrCents + expansionMrrCents - contractionMrrCents - churnedMrrCents },
  ].map((check) => ({ ...check, ok: check.expected === check.actual }))

  return {
    billingOps: buildBillingOps({ now: input.now, inbox: input.billingInbox ?? [], auditEvents: input.auditEvents, subscriptions: input.subscriptions }),
    generatedAt: input.now.toISOString(),
    reportingCurrency: REPORTING_CURRENCY,
    timezone: REPORTING_TIMEZONE,
    hasData: subs.length > 0 || invoiceRows.length > 0,
    hasRevenueEvidence: billed.length > 0 || collectedUsd.length > 0,
    coverage: {
      tables: input.coverage,
      complete: unavailableTables.length === 0 && truncatedTables.length === 0,
      unavailableTables,
      truncatedTables,
    },
    kpis: {
      grossRevenueCents,
      refundedCents,
      netRevenueCents,
      mrrCents,
      arrCents,
      arpuCents,
      ltvCents,
      revenueGrowthPct,
      mtdGrowthPct,
      payingSubscribers: subscriptionAnalytics.payingActive,
      payingCustomers: payingCustomerIds.size,
      subscriptionHealthScore: healthScore,
      churnPct,
      retentionPct,
      mrrAtRiskCents,
      nrrPct: mrrMovement.nrrPct,
    },
    mrrMovement,
    windows,
    timeline,
    revenueByProvider,
    revenueByPlan,
    revenueByCurrency,
    currencyExclusions,
    paymentAnalytics,
    subscriptionAnalytics,
    customerAnalytics,
    customers,
    subscribers,
    invoices,
    activity,
    alerts,
    forecast,
    reconciliation: { ok: checks.every((check) => check.ok), checks },
    dataGaps,
  }
}

function buildForecast(input: {
  timeline: TimelineBucket[]
  currentMonth: string
  mrrCents: number
  payingSubscribers: number
  churnPct: number | null
  thisMonthCents: number
}): RevenueForecast {
  const completed = input.timeline.filter((bucket) => bucket.complete)
  const firstEvidenceIndex = completed.findIndex((bucket) => bucket.payments > 0 || bucket.netCents !== 0 || bucket.newSubscriptions > 0 || bucket.endingMrrCents > 0)
  const history = firstEvidenceIndex === -1 ? [] : completed.slice(firstEvidenceIndex)
  const historyMonths = history.length
  const netSeries = history.map((bucket) => bucket.netCents)

  const horizonKeys: string[] = []
  for (let step = 0; step < FORECAST_HORIZON; step += 1) horizonKeys.push(addMonths(input.currentMonth, step))

  // Revenue: linear trend over completed months.
  const revenueProjectionAvailable = historyMonths >= FORECAST_MIN_MONTHS
  const revenueProjection = revenueProjectionAvailable ? linearProjection(netSeries, FORECAST_HORIZON) : null
  const fit = revenueProjectionAvailable ? linearFit(netSeries) : null

  // Recurring: retention model driven by MEASURED churn + measured new MRR.
  const churnRate = input.churnPct === null ? null : input.churnPct / 100
  const recent = history.slice(-3)
  const avgNewMrr = recent.length ? recent.reduce((sum, bucket) => sum + bucket.newMrrCents, 0) / recent.length : null
  const avgNewSubs = recent.length ? recent.reduce((sum, bucket) => sum + bucket.newSubscriptions, 0) / recent.length : null
  const mrrProjectionAvailable = churnRate !== null && avgNewMrr !== null && historyMonths >= 1
  const mrrProjectionReason = mrrProjectionAvailable
    ? null
    : churnRate === null
      ? 'Churn is not measurable yet — it needs provider-billed subscriptions older than 30 days.'
      : 'No completed month of provider-billed subscription history yet.'

  const project = (newMultiplier: number, churnMultiplier: number) =>
    mrrProjectionAvailable
      ? projectRecurring(input.mrrCents, Math.min(1, (churnRate as number) * churnMultiplier), (avgNewMrr as number) * newMultiplier, FORECAST_HORIZON)
      : null
  const base = project(1, 1)
  const low = project(0.5, 1.5)
  const high = project(1.5, 0.5)
  const subscriberProjection = mrrProjectionAvailable
    ? projectRecurring(input.payingSubscribers, churnRate as number, avgNewSubs as number, FORECAST_HORIZON)
    : null

  const horizon: ForecastMonth[] = horizonKeys.map((key, index) => ({
    month: key,
    label: monthLabel(key),
    isCurrentMonth: key === input.currentMonth,
    actualToDateCents: key === input.currentMonth ? input.thisMonthCents : null,
    projectedNetCents: revenueProjection ? revenueProjection[index] : null,
    projectedMrrCents: base ? base[index] : null,
    projectedMrrLowCents: low ? low[index] : null,
    projectedMrrHighCents: high ? high[index] : null,
    projectedSubscribers: subscriberProjection ? subscriberProjection[index] : null,
  }))

  // Accuracy: one-step-ahead backtest over the history we already have.
  const points: RevenueForecast['backtest']['points'] = []
  for (let k = FORECAST_MIN_MONTHS; k < historyMonths; k += 1) {
    const predicted = linearProjection(netSeries.slice(0, k), 1)
    if (!predicted) continue
    const actual = netSeries[k]
    points.push({
      month: history[k].month,
      label: history[k].label,
      predictedCents: predicted[0],
      actualCents: actual,
      absErrorPct: actual !== 0 ? round1((Math.abs(predicted[0] - actual) / Math.abs(actual)) * 100) : null,
    })
  }
  const scored = points.filter((point) => point.absErrorPct !== null)
  const mapePct = scored.length ? round1(scored.reduce((sum, point) => sum + (point.absErrorPct as number), 0) / scored.length) : null

  const confidence: RevenueForecast['confidence'] = historyMonths < FORECAST_MIN_MONTHS
    ? 'insufficient-history'
    : historyMonths < 6
      ? 'low'
      : historyMonths >= 12 && mapePct !== null && mapePct <= 20
        ? 'high'
        : 'medium'
  const confidenceReason = confidence === 'insufficient-history'
    ? `${historyMonths} completed month${historyMonths === 1 ? '' : 's'} of billing history — projections need at least ${FORECAST_MIN_MONTHS}.`
    : confidence === 'low'
      ? `${historyMonths} completed months of history; a trend over fewer than 6 points is volatile.`
      : confidence === 'high'
        ? `${historyMonths} months of history and a backtest error of ${mapePct}%.`
        : mapePct !== null
          ? `${historyMonths} months of history; backtest error ${mapePct}%.`
          : `${historyMonths} months of history.`

  const assumptions: ForecastAssumption[] = [
    { label: 'Baseline MRR', value: `${(input.mrrCents / 100).toFixed(2)} USD`, kind: 'measured', detail: 'Provider-billed, access-granting subscriptions today.' },
    { label: 'Monthly churn', value: input.churnPct === null ? 'Not measurable yet' : `${input.churnPct}%`, kind: 'measured', detail: 'Trailing 30 days, billed subscriptions only.' },
    { label: 'New MRR per month', value: avgNewMrr === null ? 'No history' : `${(avgNewMrr / 100).toFixed(2)} USD`, kind: 'derived', detail: `Average over the last ${recent.length || 0} completed month(s), at current plan prices.` },
    { label: 'Revenue trend', value: fit ? `${(fit.slope / 100).toFixed(2)} USD / month` : 'Not enough history', kind: 'derived', detail: 'Least-squares slope of completed-month net revenue.' },
    { label: 'Scenario multipliers', value: 'New ×0.5 / ×1 / ×1.5 · Churn ×1.5 / ×1 / ×0.5', kind: 'assumption', detail: 'Conservative / base / optimistic bands are assumptions for planning, not measurements.' },
  ]

  return {
    methodology: [
      'Revenue projection: least-squares linear trend of net revenue over COMPLETED months only — the partial current month is never used as a data point.',
      'MRR projection: MRR(next) = MRR × (1 − measured monthly churn) + average new MRR of recent completed months.',
      'Scenario bands vary new MRR and churn by stated multipliers; they are assumptions, not forecasts of fact.',
      'Accuracy: every month with enough prior history is re-predicted from the months before it and compared with what actually happened.',
      'Historical month-end MRR is reconstructed from subscription start/end dates at current plan prices.',
    ],
    confidence,
    confidenceReason,
    historyMonths,
    firstEvidenceMonth: history[0]?.month ?? null,
    revenueProjectionAvailable,
    revenueProjectionReason: revenueProjectionAvailable ? null : confidenceReason,
    mrrProjectionAvailable,
    mrrProjectionReason,
    horizon,
    revenueTrendCentsPerMonth: fit ? Math.round(fit.slope) : null,
    projectedArrCents: base ? base[base.length - 1] * 12 : null,
    scenarios: FORECAST_SCENARIOS.map((scenario) => {
      const series = project(scenario.newMultiplier, scenario.churnMultiplier)
      const month6 = series ? series[series.length - 1] : null
      return { ...scenario, month6MrrCents: month6, month6ArrCents: month6 === null ? null : month6 * 12 }
    }),
    assumptions,
    backtest: {
      points,
      mapePct,
      reason: points.length ? null : `Backtesting needs at least ${FORECAST_MIN_MONTHS + 1} completed months of history.`,
    },
  }
}

// ---------------------------------------------------------------------------
// Wire snapshot (ledgers bounded, totals always complete)
// ---------------------------------------------------------------------------

export const SNAPSHOT_LEDGER_LIMIT = 500

export type RevenueSnapshot = Omit<RevenueModel, 'customers' | 'subscribers' | 'invoices'> & {
  customers: CustomerRow[]
  subscribers: SubscriberRow[]
  invoices: InvoiceLedgerRow[]
  ledgerTotals: { customers: number; subscribers: number; invoices: number; limit: number }
}

/**
 * The SSE/REST payload. KPIs are always computed over the full dataset; only
 * the row ledgers are bounded, and `ledgerTotals` says by how much, so a table
 * can say "showing 500 of 2,340" instead of silently looking complete.
 * Exports read the full model, never this trimmed view.
 */
export function toRevenueSnapshot(model: RevenueModel, limit = SNAPSHOT_LEDGER_LIMIT): RevenueSnapshot {
  return {
    ...model,
    customers: model.customers.slice(0, limit),
    subscribers: model.subscribers.slice(0, limit),
    invoices: model.invoices.slice(0, limit),
    alerts: model.alerts.slice(0, 60),
    ledgerTotals: { customers: model.customers.length, subscribers: model.subscribers.length, invoices: model.invoices.length, limit },
  }
}
