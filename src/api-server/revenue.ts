import { Router, Request, Response, NextFunction } from 'express'
import type { SupabaseClient, User } from '@supabase/supabase-js'
import { getServerUser, getServiceClient, getToken } from '@/lib/supabase-server'
import { isOwnerEmail } from '@/lib/admin-access'
import { PLAN_PRICING } from './paypal'

/**
 * Revenue Intelligence™ — owner-only financial analytics service.
 *
 * Aggregates the REAL billing evidence this platform already produces —
 * billing_subscriptions (PayPal webhook + Google Play verify/RTDN + manual),
 * billing_invoices, billing_notifications, billing_audit_events — into one
 * executive snapshot: revenue windows, MRR/ARR, plan & provider breakdowns,
 * customer analytics, payment analytics, a deterministic forecast, and a live
 * activity feed. Consumed by /dashboard/revenue-intelligence.
 *
 * Data honesty (CLAUDE.md): every number traces to a real row. Metrics whose
 * evidence the platform does not collect (geography, CAC/burn, DAU/sessions,
 * Stripe) are returned as explicit nulls/empty with `dataGaps` notes so the UI
 * renders setup guidance instead of fabricated figures. The forecast is a
 * linear trend of actual invoiced revenue and says so.
 *
 * Security: every route (including SSE and exports) passes requireOwner —
 * verified Supabase JWT + owner-email allowlist, mirroring /api/v1/admin.
 */

const router = Router()

interface OwnerRequest extends Request {
  ownerUser?: User
  ownerDb?: SupabaseClient
}

function jsonError(res: Response, status: number, code: string, message: string) {
  return res.status(status).json({ error: { code, message } })
}

function readQueryToken(req: Request): string | null {
  const raw = req.query?.token
  return typeof raw === 'string' && raw.length > 0 ? raw : null
}

// The SSE stream is the ONLY route allowed to authenticate via a query-string
// token, because EventSource cannot send an Authorization header. Every other
// route (snapshot, export) must use the header so the session JWT never lands
// in a URL, access log, browser history entry or Referer header.
function isStreamRequest(req: Request): boolean {
  const path = (req.originalUrl || req.url || '').split('?')[0]
  return path.endsWith('/stream')
}

async function requireOwner(req: OwnerRequest, res: Response, next: NextFunction) {
  const token = getToken(req) || (isStreamRequest(req) ? readQueryToken(req) : null)
  if (!token) return jsonError(res, 401, 'UNAUTHORIZED', 'Owner session token required')
  const user = await getServerUser(token)
  if (!user) return jsonError(res, 401, 'UNAUTHORIZED', 'Invalid or expired owner session')
  if (!isOwnerEmail(user.email)) {
    return jsonError(res, 403, 'FORBIDDEN', 'Revenue Intelligence is restricted to the QGuardHelix owner')
  }
  const db = getServiceClient()
  if (!db) return jsonError(res, 503, 'CONFIG_ERROR', 'Supabase service role is not configured')
  req.ownerUser = user
  req.ownerDb = db
  next()
}

router.use(requireOwner)

// ---------------------------------------------------------------------------
// Snapshot assembly
// ---------------------------------------------------------------------------

type PlanTier = 'Starter' | 'Basic' | 'Pro' | 'Elite'
const PLANS: PlanTier[] = ['Starter', 'Basic', 'Pro', 'Elite']
const ACCESS_STATUSES = new Set(['active', 'trial', 'pending_renewal'])

interface SubscriptionRow {
  id: string
  user_id: string
  subscription_id: string
  provider: string | null
  plan: string
  status: string
  billing_cycle: string
  auto_renew: boolean
  cancel_at_period_end: boolean
  renewal_date: string | null
  current_period_start: string | null
  current_period_end: string | null
  cancelled_at: string | null
  created_at: string
  updated_at: string
}

interface InvoiceRow {
  id: string
  user_id: string
  invoice_id: string
  transaction_id: string | null
  payment_date: string | null
  amount_paid_cents: number
  tax_cents: number
  currency: string
  payment_method_summary: string | null
  subscription_plan: string
  status: string
  created_at: string
}

function monthKey(date: Date): string {
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`
}

function monthLabel(key: string): string {
  const [year, month] = key.split('-').map(Number)
  return new Date(Date.UTC(year, (month || 1) - 1, 1)).toLocaleDateString('en-US', { month: 'short', year: 'numeric', timeZone: 'UTC' })
}

function lastMonths(count: number): string[] {
  const keys: string[] = []
  const now = new Date()
  for (let index = count - 1; index >= 0; index -= 1) {
    keys.push(monthKey(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - index, 1))))
  }
  return keys
}

/** Monthly-equivalent recurring value of a subscription (our own catalog). */
function mrrContributionCents(plan: string, cycle: string): number {
  const pricing = PLAN_PRICING[plan as PlanTier]
  if (!pricing) return 0
  const monthly = String(cycle).toLowerCase() === 'annual' ? pricing.yearlyPerMonth : pricing.monthly
  return Math.round(monthly * 100)
}

/** Least-squares linear regression over a numeric series → projections. */
export function linearForecast(series: number[], periods: number): { projections: number[]; slope: number } {
  const n = series.length
  if (n === 0) return { projections: Array(periods).fill(0), slope: 0 }
  if (n === 1) return { projections: Array(periods).fill(series[0]), slope: 0 }
  const meanX = (n - 1) / 2
  const meanY = series.reduce((sum, value) => sum + value, 0) / n
  let numerator = 0
  let denominator = 0
  for (let index = 0; index < n; index += 1) {
    numerator += (index - meanX) * (series[index] - meanY)
    denominator += (index - meanX) ** 2
  }
  const slope = denominator === 0 ? 0 : numerator / denominator
  const intercept = meanY - slope * meanX
  const projections: number[] = []
  for (let step = 1; step <= periods; step += 1) {
    projections.push(Math.max(0, Math.round(intercept + slope * (n - 1 + step))))
  }
  return { projections, slope }
}

async function buildRevenueSnapshot(db: SupabaseClient) {
  const unavailable: string[] = []
  const now = new Date()
  const nowIso = now.toISOString()

  const [subsResult, invoicesResult, notificationsResult, auditResult, profilesResult] = await Promise.all([
    db.from('billing_subscriptions').select('id,user_id,subscription_id,provider,plan,status,billing_cycle,auto_renew,cancel_at_period_end,renewal_date,current_period_start,current_period_end,cancelled_at,created_at,updated_at').order('updated_at', { ascending: false }).limit(5000),
    db.from('billing_invoices').select('id,user_id,invoice_id,transaction_id,payment_date,amount_paid_cents,tax_cents,currency,payment_method_summary,subscription_plan,status,created_at').order('created_at', { ascending: false }).limit(10000),
    db.from('billing_notifications').select('id,user_id,type,severity,title,message,created_at').order('created_at', { ascending: false }).limit(40),
    db.from('billing_audit_events').select('id,user_id,action,message,created_at').order('created_at', { ascending: false }).limit(40),
    db.from('profiles').select('id,email,name,tier,created_at').limit(20000),
  ])

  const subs: SubscriptionRow[] = (subsResult.error ? [] : (subsResult.data as SubscriptionRow[])) || []
  if (subsResult.error) unavailable.push('billing_subscriptions')
  const invoices: InvoiceRow[] = (invoicesResult.error ? [] : (invoicesResult.data as InvoiceRow[])) || []
  if (invoicesResult.error) unavailable.push('billing_invoices')
  const notifications = (notificationsResult.error ? [] : notificationsResult.data) || []
  if (notificationsResult.error) unavailable.push('billing_notifications')
  const audit = (auditResult.error ? [] : auditResult.data) || []
  if (auditResult.error) unavailable.push('billing_audit_events')
  const profiles = (profilesResult.error ? [] : profilesResult.data) || []
  if (profilesResult.error) unavailable.push('profiles')

  const profileById = new Map<string, { email: string | null; name: string | null; tier: string | null; created_at: string | null }>()
  for (const profile of profiles as any[]) {
    profileById.set(String(profile.id), {
      email: profile.email ?? null,
      name: profile.name ?? null,
      tier: profile.tier ?? null,
      created_at: profile.created_at ?? null,
    })
  }

  // ---- Payment / invoice analytics -------------------------------------
  const paid = invoices.filter((invoice) => invoice.status === 'paid')
  const refunded = invoices.filter((invoice) => invoice.status === 'refunded')
  const failed = invoices.filter((invoice) => invoice.status === 'failed')
  const pending = invoices.filter((invoice) => invoice.status === 'pending')

  const sumCents = (rows: InvoiceRow[]) => rows.reduce((sum, row) => sum + (Number(row.amount_paid_cents) || 0), 0)
  const grossCents = sumCents(paid) + sumCents(refunded) // charged, incl. later refunds
  const refundedCents = sumCents(refunded)
  const netCents = grossCents - refundedCents

  const invoiceTime = (invoice: InvoiceRow) => new Date(invoice.payment_date || invoice.created_at).getTime()
  const windowNet = (fromMs: number, toMs: number = Number.POSITIVE_INFINITY) => {
    let cents = 0
    for (const invoice of paid) {
      const at = invoiceTime(invoice)
      if (at >= fromMs && at < toMs) cents += Number(invoice.amount_paid_cents) || 0
    }
    for (const invoice of refunded) {
      const at = invoiceTime(invoice)
      if (at >= fromMs && at < toMs) cents -= Number(invoice.amount_paid_cents) || 0
    }
    return cents
  }

  const startOfDay = new Date(now); startOfDay.setHours(0, 0, 0, 0)
  const startOfYesterday = new Date(startOfDay.getTime() - 24 * 3600_000)
  const startOfWeek = new Date(startOfDay)
  startOfWeek.setDate(startOfWeek.getDate() - ((startOfWeek.getDay() + 6) % 7)) // Monday
  const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1)
  const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1)
  const startOfQuarter = new Date(now.getFullYear(), Math.floor(now.getMonth() / 3) * 3, 1)
  const startOfYear = new Date(now.getFullYear(), 0, 1)

  const windows = {
    todayCents: windowNet(startOfDay.getTime()),
    yesterdayCents: windowNet(startOfYesterday.getTime(), startOfDay.getTime()),
    thisWeekCents: windowNet(startOfWeek.getTime()),
    thisMonthCents: windowNet(startOfMonth.getTime()),
    lastMonthCents: windowNet(startOfLastMonth.getTime(), startOfMonth.getTime()),
    thisQuarterCents: windowNet(startOfQuarter.getTime()),
    thisYearCents: windowNet(startOfYear.getTime()),
    allTimeCents: netCents,
  }

  // Monthly timeline (last 12 months) — revenue + volume + subscriber adds.
  const monthKeys = lastMonths(12)
  const timelineByKey = new Map(monthKeys.map((key) => [key, { month: key, label: monthLabel(key), grossCents: 0, refundedCents: 0, netCents: 0, payments: 0, newSubscriptions: 0, newCustomers: 0 }]))
  for (const invoice of [...paid, ...refunded]) {
    const key = monthKey(new Date(invoice.payment_date || invoice.created_at))
    const bucket = timelineByKey.get(key)
    if (!bucket) continue
    const cents = Number(invoice.amount_paid_cents) || 0
    if (invoice.status === 'paid') { bucket.grossCents += cents; bucket.netCents += cents; bucket.payments += 1 }
    else { bucket.refundedCents += cents; bucket.netCents -= cents }
  }
  for (const sub of subs) {
    const bucket = timelineByKey.get(monthKey(new Date(sub.created_at)))
    if (bucket) bucket.newSubscriptions += 1
  }
  for (const profile of profiles as any[]) {
    if (!profile.created_at) continue
    const bucket = timelineByKey.get(monthKey(new Date(profile.created_at)))
    if (bucket) bucket.newCustomers += 1
  }
  const timeline = monthKeys.map((key) => timelineByKey.get(key)!)

  const revenueGrowthPct = windows.lastMonthCents > 0
    ? Math.round(((windows.thisMonthCents - windows.lastMonthCents) / windows.lastMonthCents) * 1000) / 10
    : null

  // Provider + plan + currency breakdowns from invoices.
  const groupCents = (rows: InvoiceRow[], keyOf: (row: InvoiceRow) => string) => {
    const grouped = new Map<string, { cents: number; count: number }>()
    for (const row of rows) {
      const key = keyOf(row) || 'Other'
      const entry = grouped.get(key) || { cents: 0, count: 0 }
      entry.cents += Number(row.amount_paid_cents) || 0
      entry.count += 1
      grouped.set(key, entry)
    }
    return Array.from(grouped.entries())
      .map(([label, value]) => ({ label, cents: value.cents, count: value.count }))
      .sort((a, b) => b.cents - a.cents)
  }
  const revenueByProvider = groupCents(paid, (row) => row.payment_method_summary || 'Other')
  const revenueByPlanInvoiced = groupCents(paid, (row) => row.subscription_plan || 'Other')
  const revenueByCurrency = groupCents(paid, (row) => String(row.currency || 'USD').toUpperCase())

  const totalPayments = paid.length + failed.length + refunded.length + pending.length
  const paymentAnalytics = {
    successful: paid.length,
    failed: failed.length,
    refunds: refunded.length,
    pending: pending.length,
    successRatePct: paid.length + failed.length > 0 ? Math.round((paid.length / (paid.length + failed.length)) * 1000) / 10 : null,
    averagePaymentCents: paid.length > 0 ? Math.round(sumCents(paid) / paid.length) : 0,
    totalPayments,
    refundedCents,
  }

  // ---- Subscription analytics ------------------------------------------
  const statusCount = (status: string) => subs.filter((sub) => String(sub.status).toLowerCase() === status).length
  const activeish = subs.filter((sub) => ACCESS_STATUSES.has(String(sub.status).toLowerCase()))
  const mrrCents = activeish.reduce((sum, sub) => sum + mrrContributionCents(sub.plan, sub.billing_cycle), 0)
  const arrCents = mrrCents * 12

  const planBreakdown = PLANS.map((plan) => {
    const ofPlan = subs.filter((sub) => sub.plan === plan)
    const activeOfPlan = ofPlan.filter((sub) => ACCESS_STATUSES.has(String(sub.status).toLowerCase()))
    return {
      plan,
      total: ofPlan.length,
      active: activeOfPlan.length,
      trial: ofPlan.filter((sub) => String(sub.status).toLowerCase() === 'trial').length,
      cancelled: ofPlan.filter((sub) => String(sub.status).toLowerCase() === 'cancelled').length,
      mrrCents: activeOfPlan.reduce((sum, sub) => sum + mrrContributionCents(sub.plan, sub.billing_cycle), 0),
      invoicedCents: revenueByPlanInvoiced.find((entry) => entry.label === plan)?.cents ?? 0,
    }
  })

  const cancelledLast30 = subs.filter((sub) => sub.cancelled_at && now.getTime() - new Date(sub.cancelled_at).getTime() < 30 * 24 * 3600_000).length
  const churnBase = activeish.length + cancelledLast30
  const churnPct = churnBase > 0 ? Math.round((cancelledLast30 / churnBase) * 1000) / 10 : null
  const retentionPct = churnPct === null ? null : Math.round((100 - churnPct) * 10) / 10

  const activeCustomerIds = new Set(activeish.map((sub) => sub.user_id))
  const arpuCents = activeCustomerIds.size > 0 ? Math.round(mrrCents / activeCustomerIds.size) : 0
  // LTV = ARPU / monthly churn rate. Needs real churn history — null until it exists.
  const ltvCents = churnPct !== null && churnPct > 0 ? Math.round(arpuCents / (churnPct / 100)) : null

  const upgrades30 = (audit as any[]).filter((event) => String(event.action || '').includes('upgrade') && now.getTime() - new Date(event.created_at).getTime() < 30 * 24 * 3600_000).length
  const downgrades30 = (audit as any[]).filter((event) => String(event.action || '').includes('downgrade') && now.getTime() - new Date(event.created_at).getTime() < 30 * 24 * 3600_000).length

  const renewalRatePct = activeish.length > 0 ? Math.round((activeish.filter((sub) => sub.auto_renew && !sub.cancel_at_period_end).length / activeish.length) * 1000) / 10 : null

  // Evidence-based composite (weights documented in the UI tooltip):
  // 30% active share, 25% renewal intent, 25% payment success, 20% retention.
  const healthComponents = {
    activeSharePct: subs.length > 0 ? (activeish.length / subs.length) * 100 : 0,
    renewalPct: renewalRatePct ?? 0,
    paymentSuccessPct: paymentAnalytics.successRatePct ?? (paid.length > 0 ? 100 : 0),
    retentionPct: retentionPct ?? (activeish.length > 0 ? 100 : 0),
  }
  const subscriptionHealthScore = subs.length === 0 ? null : Math.round(
    healthComponents.activeSharePct * 0.3
    + healthComponents.renewalPct * 0.25
    + healthComponents.paymentSuccessPct * 0.25
    + healthComponents.retentionPct * 0.2,
  )

  const subscriptionAnalytics = {
    total: subs.length,
    active: statusCount('active'),
    trial: statusCount('trial'),
    pendingRenewal: statusCount('pending_renewal'),
    pastDue: statusCount('past_due'),
    suspended: statusCount('suspended'),
    cancelled: statusCount('cancelled'),
    expired: statusCount('expired'),
    incomplete: statusCount('incomplete'),
    renewing: activeish.filter((sub) => sub.auto_renew && !sub.cancel_at_period_end).length,
    endingAtPeriodEnd: subs.filter((sub) => sub.cancel_at_period_end && ACCESS_STATUSES.has(String(sub.status).toLowerCase())).length,
    renewalRatePct,
    upgrades30d: upgrades30,
    downgrades30d: downgrades30,
    churnPct,
    retentionPct,
    healthScore: subscriptionHealthScore,
    healthComponents,
    planBreakdown,
  }

  // ---- Customer analytics -----------------------------------------------
  const customerIds = new Set<string>([...subs.map((sub) => sub.user_id), ...invoices.map((invoice) => invoice.user_id)])
  const newCustomers30 = (profiles as any[]).filter((profile) => profile.created_at && now.getTime() - new Date(profile.created_at).getTime() < 30 * 24 * 3600_000).length
  const paidByUser = new Map<string, number>()
  for (const invoice of paid) paidByUser.set(invoice.user_id, (paidByUser.get(invoice.user_id) || 0) + (Number(invoice.amount_paid_cents) || 0))
  for (const invoice of refunded) paidByUser.set(invoice.user_id, (paidByUser.get(invoice.user_id) || 0) - (Number(invoice.amount_paid_cents) || 0))

  const subByUser = new Map(subs.map((sub) => [sub.user_id, sub]))
  const customers = Array.from(customerIds)
    .map((userId) => {
      const profile = profileById.get(userId)
      const sub = subByUser.get(userId)
      return {
        userId,
        email: profile?.email ?? null,
        name: profile?.name ?? null,
        plan: sub?.plan ?? null,
        status: sub?.status ?? null,
        provider: sub?.provider ?? null,
        billingCycle: sub?.billing_cycle ?? null,
        since: sub?.created_at ?? profile?.created_at ?? null,
        renewalDate: sub?.renewal_date ?? sub?.current_period_end ?? null,
        lifetimeCents: paidByUser.get(userId) || 0,
      }
    })
    .sort((a, b) => b.lifetimeCents - a.lifetimeCents)
    .slice(0, 200)

  const customerAnalytics = {
    totalUsers: profiles.length,
    totalCustomers: customerIds.size,
    activeCustomers: activeCustomerIds.size,
    inactiveCustomers: Math.max(0, customerIds.size - activeCustomerIds.size),
    trialUsers: statusCount('trial'),
    cancelledCustomers: statusCount('cancelled') + statusCount('expired'),
    newCustomers30d: newCustomers30,
    enterpriseCustomers: subs.filter((sub) => sub.plan === 'Elite' && ACCESS_STATUSES.has(String(sub.status).toLowerCase())).length,
    arpuCents,
    ltvCents,
    averageCustomerValueCents: customerIds.size > 0 ? Math.round(netCents / customerIds.size) : 0,
    customerGrowthPct: (() => {
      const [previous, current] = [timeline[timeline.length - 2], timeline[timeline.length - 1]]
      if (!previous || previous.newCustomers === 0) return null
      return Math.round(((current.newCustomers - previous.newCustomers) / previous.newCustomers) * 1000) / 10
    })(),
  }

  // ---- Activity feed + alerts -------------------------------------------
  const activity = [
    ...(audit as any[]).map((event) => ({
      at: event.created_at as string,
      kind: 'audit' as const,
      title: String(event.action || 'billing event').replace(/[._]/g, ' '),
      detail: String(event.message || ''),
      amountCents: null as number | null,
      severity: 'info',
    })),
    ...invoices.slice(0, 20).map((invoice) => ({
      at: invoice.payment_date || invoice.created_at,
      kind: 'payment' as const,
      title: invoice.status === 'paid' ? `Payment received — ${invoice.subscription_plan}` : `Payment ${invoice.status} — ${invoice.subscription_plan}`,
      detail: `${invoice.payment_method_summary || 'Payment'} · ${invoice.invoice_id}`,
      amountCents: Number(invoice.amount_paid_cents) || 0,
      severity: invoice.status === 'paid' ? 'success' : invoice.status === 'failed' ? 'critical' : 'warning',
    })),
  ]
    .filter((entry) => entry.at)
    .sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime())
    .slice(0, 20)

  const alerts = (notifications as any[]).map((notification) => ({
    id: String(notification.id),
    at: notification.created_at as string,
    type: String(notification.type || 'billing'),
    severity: String(notification.severity || 'info'),
    title: String(notification.title || ''),
    message: String(notification.message || ''),
  }))

  // ---- Forecast (deterministic, methodology disclosed) -------------------
  const netSeries = timeline.map((bucket) => bucket.netCents)
  const observedMonths = netSeries.filter((value, index) => value !== 0 || timeline[index].payments > 0).length
  const revenueForecast = linearForecast(netSeries.slice(-Math.max(observedMonths, 2)), 6)
  const subSeries = timeline.map((bucket) => bucket.newSubscriptions)
  const subscriberForecast = linearForecast(subSeries.slice(-Math.max(observedMonths, 2)), 6)
  const forecastMonths = (() => {
    const keys: string[] = []
    for (let step = 1; step <= 6; step += 1) {
      keys.push(monthKey(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + step, 1))))
    }
    return keys
  })()
  const monthlyGrowthRate = windows.lastMonthCents > 0 ? (windows.thisMonthCents - windows.lastMonthCents) / windows.lastMonthCents : 0
  const forecast = {
    methodology: 'Least-squares linear trend of actual invoiced net revenue and subscription adds over the observed months. Deterministic and evidence-based — not a guarantee.',
    confidence: observedMonths >= 6 ? 'medium' : observedMonths >= 3 ? 'low' : 'insufficient-history',
    observedMonths,
    horizon: forecastMonths.map((key, index) => ({
      month: key,
      label: monthLabel(key),
      projectedNetCents: revenueForecast.projections[index] ?? 0,
      projectedNewSubscriptions: subscriberForecast.projections[index] ?? 0,
      projectedMrrCents: Math.max(0, Math.round(mrrCents * (1 + monthlyGrowthRate) ** (index + 1))),
    })),
    projectedArrCents: Math.max(0, Math.round(mrrCents * (1 + monthlyGrowthRate) ** 6)) * 12,
  }

  // Metrics this platform has NO evidence for yet — surfaced as gaps, never faked.
  const dataGaps = [
    { metric: 'Revenue by Country / Geography', reason: 'Customer country is not collected at checkout yet. Add billing-address capture (PayPal payer country / Play RTDN regionCode) to unlock geographic analytics.' },
    { metric: 'CAC / Burn Rate / Profit Margin / EBITDA', reason: 'Requires acquisition-spend and operating-cost inputs which the platform does not track. Connect a cost source to compute these.' },
    { metric: 'DAU / MAU / Sessions', reason: 'Product usage telemetry is not wired into billing analytics yet.' },
    { metric: 'Stripe / Apple App Store', reason: 'Not integrated. Revenue shown covers PayPal, Google Play, and manual/enterprise entries recorded in billing.' },
  ]

  const latestInvoices = invoices.slice(0, 200).map((invoice) => ({
    id: invoice.id,
    invoiceId: invoice.invoice_id,
    userId: invoice.user_id,
    email: profileById.get(invoice.user_id)?.email ?? null,
    plan: invoice.subscription_plan,
    amountCents: Number(invoice.amount_paid_cents) || 0,
    currency: String(invoice.currency || 'USD').toUpperCase(),
    method: invoice.payment_method_summary,
    status: invoice.status,
    at: invoice.payment_date || invoice.created_at,
  }))

  const subscribers = subs.slice(0, 200).map((sub) => ({
    id: sub.id,
    userId: sub.user_id,
    email: profileById.get(sub.user_id)?.email ?? null,
    plan: sub.plan,
    status: sub.status,
    provider: sub.provider,
    billingCycle: sub.billing_cycle,
    autoRenew: sub.auto_renew,
    cancelAtPeriodEnd: sub.cancel_at_period_end,
    since: sub.created_at,
    renewalDate: sub.renewal_date ?? sub.current_period_end,
    mrrCents: ACCESS_STATUSES.has(String(sub.status).toLowerCase()) ? mrrContributionCents(sub.plan, sub.billing_cycle) : 0,
  }))

  return {
    generatedAt: nowIso,
    hasData: subs.length > 0 || invoices.length > 0,
    unavailableTables: unavailable,
    dataGaps,
    kpis: {
      totalRevenueCents: netCents,
      grossRevenueCents: grossCents,
      netRevenueCents: netCents,
      refundedCents,
      lifetimeRevenueCents: netCents,
      mrrCents,
      arrCents,
      arpuCents,
      ltvCents,
      revenueGrowthPct,
      activeSubscribers: activeish.length,
      subscriptionHealthScore,
      churnPct,
      retentionPct,
    },
    windows,
    timeline,
    revenueByProvider,
    revenueByPlanInvoiced,
    revenueByCurrency,
    paymentAnalytics,
    subscriptionAnalytics,
    customerAnalytics,
    customers,
    subscribers,
    invoices: latestInvoices,
    activity,
    alerts,
    forecast,
  }
}

export type RevenueSnapshot = Awaited<ReturnType<typeof buildRevenueSnapshot>>

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

router.get('/snapshot', async (req: OwnerRequest, res: Response) => {
  try {
    const snapshot = await buildRevenueSnapshot(req.ownerDb!)
    return res.json({ data: snapshot })
  } catch (err) {
    console.error('[revenue] snapshot error:', err)
    return jsonError(res, 500, 'REVENUE_SNAPSHOT_FAILED', err instanceof Error ? err.message : 'Failed to build revenue snapshot')
  }
})

/** Live stream: full snapshot every 10s + heartbeat, mirroring /admin/stream. */
router.get('/stream', async (req: OwnerRequest, res: Response) => {
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

  send('revenue-connected', { owner: req.ownerUser!.email, timestamp: new Date().toISOString() })

  const push = async () => {
    try {
      send('revenue-snapshot', await buildRevenueSnapshot(req.ownerDb!))
    } catch (err) {
      send('revenue-error', { message: err instanceof Error ? err.message : 'Revenue stream update failed' })
    }
  }

  await push()
  const interval = setInterval(push, 10_000)
  const heartbeat = setInterval(() => send('revenue-heartbeat', { timestamp: new Date().toISOString() }), 30_000)
  req.on('close', () => {
    closed = true
    clearInterval(interval)
    clearInterval(heartbeat)
  })
})

// ---- Report exports (CSV opens directly in Excel; JSON for integrations) ----

type ReportKind = 'revenue' | 'subscriptions' | 'payments' | 'customers' | 'summary'

function toCsv(headers: string[], rows: Array<Array<string | number | null>>): string {
  const escape = (value: string | number | null) => {
    const text = value === null || value === undefined ? '' : String(value)
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
  }
  return [headers.map(escape).join(','), ...rows.map((row) => row.map(escape).join(','))].join('\n')
}

const usd = (cents: number | null) => (cents === null ? null : (cents / 100).toFixed(2))

export function buildReportRows(snapshot: RevenueSnapshot, report: ReportKind): { headers: string[]; rows: Array<Array<string | number | null>> } {
  switch (report) {
    case 'revenue':
      return {
        headers: ['Month', 'Gross Revenue (USD)', 'Refunded (USD)', 'Net Revenue (USD)', 'Payments', 'New Subscriptions', 'New Customers'],
        rows: snapshot.timeline.map((bucket) => [bucket.label, usd(bucket.grossCents), usd(bucket.refundedCents), usd(bucket.netCents), bucket.payments, bucket.newSubscriptions, bucket.newCustomers]),
      }
    case 'subscriptions':
      return {
        headers: ['Email', 'Plan', 'Status', 'Provider', 'Billing Cycle', 'Auto Renew', 'Since', 'Renewal Date', 'MRR (USD)'],
        rows: snapshot.subscribers.map((sub) => [sub.email, sub.plan, sub.status, sub.provider, sub.billingCycle, sub.autoRenew ? 'yes' : 'no', sub.since, sub.renewalDate, usd(sub.mrrCents)]),
      }
    case 'payments':
      return {
        headers: ['Date', 'Invoice', 'Email', 'Plan', 'Amount (USD)', 'Currency', 'Method', 'Status'],
        rows: snapshot.invoices.map((invoice) => [invoice.at, invoice.invoiceId, invoice.email, invoice.plan, usd(invoice.amountCents), invoice.currency, invoice.method, invoice.status]),
      }
    case 'customers':
      return {
        headers: ['Email', 'Name', 'Plan', 'Status', 'Provider', 'Customer Since', 'Renewal Date', 'Lifetime Revenue (USD)'],
        rows: snapshot.customers.map((customer) => [customer.email, customer.name, customer.plan, customer.status, customer.provider, customer.since, customer.renewalDate, usd(customer.lifetimeCents)]),
      }
    case 'summary':
    default:
      return {
        headers: ['Metric', 'Value'],
        rows: [
          ['Generated At', snapshot.generatedAt],
          ['Total (Net) Revenue USD', usd(snapshot.kpis.netRevenueCents)],
          ['Gross Revenue USD', usd(snapshot.kpis.grossRevenueCents)],
          ['Refunded USD', usd(snapshot.kpis.refundedCents)],
          ['MRR USD', usd(snapshot.kpis.mrrCents)],
          ['ARR USD', usd(snapshot.kpis.arrCents)],
          ['ARPU USD', usd(snapshot.kpis.arpuCents)],
          ['LTV USD', usd(snapshot.kpis.ltvCents)],
          ['Active Subscribers', snapshot.kpis.activeSubscribers],
          ['Churn % (30d)', snapshot.kpis.churnPct],
          ['Retention %', snapshot.kpis.retentionPct],
          ['Revenue Growth % (MoM)', snapshot.kpis.revenueGrowthPct],
          ['Subscription Health Score', snapshot.kpis.subscriptionHealthScore],
          ['Payment Success Rate %', snapshot.paymentAnalytics.successRatePct],
          ['Today USD', usd(snapshot.windows.todayCents)],
          ['This Week USD', usd(snapshot.windows.thisWeekCents)],
          ['This Month USD', usd(snapshot.windows.thisMonthCents)],
          ['This Year USD', usd(snapshot.windows.thisYearCents)],
        ],
      }
  }
}

router.get('/export', async (req: OwnerRequest, res: Response) => {
  const report = (String(req.query.report || 'summary') as ReportKind)
  const format = String(req.query.format || 'csv').toLowerCase()
  if (!['revenue', 'subscriptions', 'payments', 'customers', 'summary'].includes(report)) {
    return jsonError(res, 400, 'INVALID_REPORT', 'Unknown report kind')
  }
  // Financial exports must never be cached by a proxy/browser or leak a
  // referrer to a downstream origin.
  res.setHeader('Cache-Control', 'no-store')
  res.setHeader('Referrer-Policy', 'no-referrer')
  try {
    const snapshot = await buildRevenueSnapshot(req.ownerDb!)
    const stamp = new Date().toISOString().slice(0, 10)
    if (format === 'json') {
      res.setHeader('Content-Disposition', `attachment; filename="qguard-${report}-report-${stamp}.json"`)
      const { headers, rows } = buildReportRows(snapshot, report)
      return res.json({ report, generatedAt: snapshot.generatedAt, headers, rows, snapshotKpis: snapshot.kpis })
    }
    const { headers, rows } = buildReportRows(snapshot, report)
    res.setHeader('Content-Type', 'text/csv; charset=utf-8')
    res.setHeader('Content-Disposition', `attachment; filename="qguard-${report}-report-${stamp}.csv"`)
    return res.send(toCsv(headers, rows))
  } catch (err) {
    console.error('[revenue] export error:', err)
    return jsonError(res, 500, 'REVENUE_EXPORT_FAILED', 'Failed to build the report')
  }
})

export default router
