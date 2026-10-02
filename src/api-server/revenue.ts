import { Router, Request, Response, NextFunction } from 'express'
import { createHash } from 'node:crypto'
import type { SupabaseClient, User } from '@supabase/supabase-js'
import { getServerUser, getServiceClient, getToken } from '@/lib/supabase-server'
import { isOwnerEmail } from '@/lib/admin-access'
import {
  buildRevenueModel,
  toRevenueSnapshot,
  type AuditRecord,
  type InvoiceRecord,
  type NotificationRecord,
  type ProfileRecord,
  type RevenueModel,
  type SourceCoverage,
  type SubscriptionRecord,
} from '@/lib/billing/revenue-model'
import { trustedClientIp } from './runtime/client-ip'

/**
 * Revenue Intelligence™ — owner-only financial analytics service.
 *
 * Every figure is computed by `buildRevenueModel` (src/lib/billing/
 * revenue-model.ts) from the REAL billing rows the PayPal webhook, the Google
 * Play verify/RTDN flow and the Admin console write. This router only reads
 * those rows, caches the model, and serves it:
 *
 *   GET /snapshot             the model, ledgers bounded (totals complete)
 *   GET /stream               SSE: snapshot on change + heartbeat
 *   GET /export               csv|json × summary|revenue|subscriptions|customers|payments (FULL data)
 *   GET /customers/:userId    one customer's subscription, invoices, audit trail
 *
 * Security: every route passes requireOwner (verified Supabase JWT + owner
 * email allowlist). Reads use the service role because RLS hides other users'
 * billing rows from any user token, including the owner's. Sensitive reads
 * (exports, customer detail, stream sessions) and refused access attempts are
 * written to admin_audit_events, the same audit sink the Admin console uses.
 */

const router = Router()

interface OwnerRequest extends Request {
  ownerUser?: User
  ownerToken?: string
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
// route must use the header so the session JWT never lands in a URL, access
// log, browser history entry or Referer header.
function isStreamRequest(req: Request): boolean {
  const path = (req.originalUrl || req.url || '').split('?')[0]
  return path.endsWith('/stream')
}

function clientIp(req: Request): string | null {
  const trusted = trustedClientIp(req)
  if (trusted) return trusted
  const forwarded = req.headers['x-forwarded-for']
  const first = (Array.isArray(forwarded) ? forwarded[0] : forwarded)?.split(',')[0]?.trim()
  return first || req.socket?.remoteAddress || null
}

/**
 * Append a row to admin_audit_events. Failures are LOGGED, never swallowed:
 * supabase-js reports a failed insert in `{ error }`, not as a throw, so a bare
 * try/catch would lose the audit record without a trace.
 */
async function recordRevenueAudit(
  db: SupabaseClient | null | undefined,
  actor: User | null | undefined,
  req: Request,
  action: string,
  entityType: string,
  entityId: string | null,
  details: Record<string, unknown> = {},
) {
  const client = db || getServiceClient()
  if (!client) {
    console.error(`[revenue] audit ${action} not recorded: service client unavailable`)
    return
  }
  try {
    const { error } = await client.from('admin_audit_events').insert({
      actor_user_id: actor?.id ?? null,
      actor_email: actor?.email ?? null,
      action,
      entity_type: entityType,
      entity_id: entityId,
      ip_address: clientIp(req),
      user_agent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'].slice(0, 400) : null,
      details: { ...details, path: (req.originalUrl || '').split('?')[0] },
    })
    if (error) console.error(`[revenue] audit ${action} not recorded:`, error.message)
  } catch (err) {
    console.error(`[revenue] audit ${action} not recorded:`, err instanceof Error ? err.message : err)
  }
}

async function requireOwner(req: OwnerRequest, res: Response, next: NextFunction) {
  const token = getToken(req) || (isStreamRequest(req) ? readQueryToken(req) : null)
  if (!token) return jsonError(res, 401, 'UNAUTHORIZED', 'Owner session token required')
  const user = await getServerUser(token)
  if (!user) return jsonError(res, 401, 'UNAUTHORIZED', 'Invalid or expired owner session')
  if (!isOwnerEmail(user.email)) {
    // Every refusal is enforced; the AUDIT row is throttled to one per user
    // per minute so a scripted client cannot flood admin_audit_events.
    if (!rateLimited(`denied-audit:${user.id}`, 1, 60_000)) {
      await recordRevenueAudit(null, user, req, 'revenue.access_denied', 'revenue_intelligence', null, { reason: 'not_owner' })
    }
    return jsonError(res, 403, 'FORBIDDEN', 'Revenue Intelligence is restricted to the QGuardHelix owner')
  }
  const db = getServiceClient()
  if (!db) return jsonError(res, 503, 'CONFIG_ERROR', 'Supabase service role is not configured')
  req.ownerUser = user
  req.ownerToken = token
  req.ownerDb = db
  next()
}

router.use(requireOwner)

// ---------------------------------------------------------------------------
// Rate limiting (in-memory sliding window)
// ---------------------------------------------------------------------------

const rateBuckets = new Map<string, number[]>()

function rateLimited(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now()
  if (rateBuckets.size > 5_000) {
    for (const [bucket, hits] of rateBuckets) if (!hits.some((at) => now - at < 3_600_000)) rateBuckets.delete(bucket)
  }
  const hits = (rateBuckets.get(key) || []).filter((at) => now - at < windowMs)
  if (hits.length >= limit) {
    rateBuckets.set(key, hits)
    return true
  }
  hits.push(now)
  rateBuckets.set(key, hits)
  return false
}

// ---------------------------------------------------------------------------
// Data access — paged, bounded, and honest about what it could not read
// ---------------------------------------------------------------------------

// PostgREST caps a response at its `max_rows` (1000 on Supabase), whatever
// `.limit()` asks for. A single `.limit(5000)` therefore returned at most 1000
// rows and every KPI above that silently undercounted. Read in pages instead,
// up to an explicit ceiling, and report when the ceiling is reached.
const PAGE_SIZE = 1000

async function readAll<T>(
  db: SupabaseClient,
  table: string,
  select: string,
  options: { orderBy: string; ascending?: boolean; maxRows: number; since?: { column: string; iso: string } },
): Promise<{ rows: T[]; coverage: SourceCoverage }> {
  // Pages are ordered by the requested column THEN id, so a row updated
  // mid-read cannot shift across a page boundary and be read twice or
  // skipped; the id map below is the backstop.
  const byId = new Map<string, T>()
  const rows: T[] = []
  let error: string | null = null
  for (let from = 0; from < options.maxRows; from += PAGE_SIZE) {
    const to = Math.min(from + PAGE_SIZE, options.maxRows) - 1
    let query = db.from(table).select(select).order(options.orderBy, { ascending: options.ascending ?? false })
    if (options.orderBy !== 'id') query = query.order('id', { ascending: true })
    if (options.since) query = query.gte(options.since.column, options.since.iso)
    const { data, error: queryError } = await query.range(from, to)
    if (queryError) {
      error = queryError.message
      break
    }
    const page = (data || []) as T[]
    for (const row of page) {
      const id = String((row as { id?: unknown }).id ?? '')
      if (!id || !byId.has(id)) {
        if (id) byId.set(id, row)
        rows.push(row)
      }
    }
    if (page.length < to - from + 1) break
  }
  if (error) console.warn(`[revenue] ${table} read failed: ${error}`)
  return {
    rows,
    coverage: {
      table,
      rows: rows.length,
      available: error === null,
      truncated: error === null && rows.length >= options.maxRows,
      error,
    },
  }
}

const SUBSCRIPTION_COLUMNS = 'id,user_id,subscription_id,provider,plan,status,billing_cycle,auto_renew,cancel_at_period_end,renewal_date,current_period_start,current_period_end,cancelled_at,created_at,updated_at,amount_cents,currency,metadata'
const INVOICE_COLUMNS = 'id,user_id,invoice_id,provider_invoice_id,transaction_id,payment_date,amount_paid_cents,tax_cents,currency,payment_method_summary,subscription_plan,status,created_at,updated_at,metadata'

async function loadRevenueModel(db: SupabaseClient): Promise<RevenueModel> {
  const now = new Date()
  const since90d = new Date(now.getTime() - 90 * 86_400_000).toISOString()
  const [subscriptions, invoices, profiles, audit, notifications] = await Promise.all([
    // Full reads page on the immutable primary key; the model re-sorts.
    readAll<SubscriptionRecord>(db, 'billing_subscriptions', SUBSCRIPTION_COLUMNS, { orderBy: 'id', ascending: true, maxRows: 50_000 }),
    readAll<InvoiceRecord>(db, 'billing_invoices', INVOICE_COLUMNS, { orderBy: 'id', ascending: true, maxRows: 100_000 }),
    readAll<ProfileRecord>(db, 'profiles', 'id,email,name,full_name,tier,created_at', { orderBy: 'id', ascending: true, maxRows: 100_000 }),
    readAll<AuditRecord>(db, 'billing_audit_events', 'id,user_id,action,message,created_at,metadata', { orderBy: 'created_at', maxRows: 5_000, since: { column: 'created_at', iso: since90d } }),
    readAll<NotificationRecord>(db, 'billing_notifications', 'id,user_id,type,severity,title,message,created_at', { orderBy: 'created_at', maxRows: 200 }),
  ])
  // billing_audit_events and billing_notifications are read as a bounded
  // recent window by design (90 days / latest 200); hitting that bound is not
  // an accuracy fault for the KPIs, which never depend on them.
  const recentWindow = (coverage: SourceCoverage): SourceCoverage => ({ ...coverage, truncated: false })
  return buildRevenueModel({
    now,
    subscriptions: subscriptions.rows,
    invoices: invoices.rows,
    profiles: profiles.rows,
    auditEvents: audit.rows,
    notifications: notifications.rows,
    coverage: [subscriptions.coverage, invoices.coverage, profiles.coverage, recentWindow(audit.coverage), recentWindow(notifications.coverage)],
  })
}

// One build serves every open dashboard, SSE tick and export for a short TTL.
// Concurrent callers share the in-flight promise (single-flight), so N open
// tabs cost one set of queries, not N.
const MODEL_TTL_MS = 5_000
let cachedModel: { model: RevenueModel; at: number } | null = null
let inFlight: Promise<RevenueModel> | null = null

async function getRevenueModel(db: SupabaseClient, options: { fresh?: boolean } = {}): Promise<RevenueModel> {
  if (!options.fresh && cachedModel && Date.now() - cachedModel.at < MODEL_TTL_MS) return cachedModel.model
  if (inFlight) return inFlight
  inFlight = loadRevenueModel(db)
    .then((model) => {
      cachedModel = { model, at: Date.now() }
      return model
    })
    .finally(() => {
      inFlight = null
    })
  return inFlight
}

function fingerprint(value: unknown): string {
  const { generatedAt: _ignored, ...rest } = value as Record<string, unknown>
  return createHash('sha1').update(JSON.stringify(rest)).digest('hex')
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

router.get('/snapshot', async (req: OwnerRequest, res: Response) => {
  try {
    const model = await getRevenueModel(req.ownerDb!, { fresh: req.query.fresh === '1' })
    res.setHeader('Cache-Control', 'no-store')
    return res.json({ data: toRevenueSnapshot(model) })
  } catch (err) {
    console.error('[revenue] snapshot error:', err)
    return jsonError(res, 500, 'REVENUE_SNAPSHOT_FAILED', 'The revenue snapshot could not be built. Check the API server log for the database error.')
  }
})

const MAX_STREAMS_PER_OWNER = 6
const openStreams = new Map<string, number>()
const STREAM_PUSH_MS = 10_000
const STREAM_HEARTBEAT_MS = 25_000

/**
 * Live stream. Sends `revenue-snapshot` only when the data changed (otherwise
 * a `revenue-heartbeat` carrying the build time), re-verifies the session on
 * every tick and closes with `revenue-reauth` when the token expires — an
 * EventSource opened with a token must not outlive that token.
 */
router.get('/stream', async (req: OwnerRequest, res: Response) => {
  const ownerId = req.ownerUser!.id
  const current = openStreams.get(ownerId) || 0
  if (current >= MAX_STREAMS_PER_OWNER) {
    return jsonError(res, 429, 'TOO_MANY_STREAMS', `At most ${MAX_STREAMS_PER_OWNER} live revenue streams per owner session`)
  }
  openStreams.set(ownerId, current + 1)

  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()

  let closed = false
  let lastFingerprint: string | null = null
  let pushTimer: ReturnType<typeof setInterval> | undefined
  let heartbeatTimer: ReturnType<typeof setInterval> | undefined

  const cleanup = () => {
    if (closed) return
    closed = true
    if (pushTimer) clearInterval(pushTimer)
    if (heartbeatTimer) clearInterval(heartbeatTimer)
    const remaining = (openStreams.get(ownerId) || 1) - 1
    if (remaining <= 0) openStreams.delete(ownerId)
    else openStreams.set(ownerId, remaining)
  }
  // Registered BEFORE the first await: a client that disconnects during the
  // initial build must still release its timers and its stream slot.
  req.on('close', cleanup)

  const send = (event: string, data: unknown) => {
    if (closed) return
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  }

  const push = async () => {
    if (closed) return
    const stillValid = await getServerUser(req.ownerToken!)
    if (!stillValid) {
      send('revenue-reauth', { reason: 'session_expired', timestamp: new Date().toISOString() })
      cleanup()
      res.end()
      return
    }
    try {
      const snapshot = toRevenueSnapshot(await getRevenueModel(req.ownerDb!))
      const next = fingerprint(snapshot)
      if (next !== lastFingerprint) {
        lastFingerprint = next
        send('revenue-snapshot', snapshot)
      } else {
        send('revenue-heartbeat', { generatedAt: snapshot.generatedAt, timestamp: new Date().toISOString() })
      }
    } catch (err) {
      console.error('[revenue] stream update failed:', err)
      send('revenue-error', { message: 'Live revenue update failed — retrying on the next tick', timestamp: new Date().toISOString() })
    }
  }

  send('revenue-connected', { timestamp: new Date().toISOString(), pushIntervalMs: STREAM_PUSH_MS })
  void recordRevenueAudit(req.ownerDb, req.ownerUser, req, 'revenue.stream.connected', 'revenue_intelligence', null)
  await push()
  if (closed) return
  pushTimer = setInterval(() => void push(), STREAM_PUSH_MS)
  heartbeatTimer = setInterval(() => send('revenue-heartbeat', { timestamp: new Date().toISOString() }), STREAM_HEARTBEAT_MS)
})

// ---- Customer detail --------------------------------------------------------

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

router.get('/customers/:userId', async (req: OwnerRequest, res: Response) => {
  const userId = String(req.params.userId || '')
  if (!UUID_RE.test(userId)) return jsonError(res, 400, 'INVALID_CUSTOMER_ID', 'Customer id must be a UUID')
  if (rateLimited(`detail:${req.ownerUser!.id}`, 120, 60_000)) {
    return jsonError(res, 429, 'RATE_LIMITED', 'Too many customer lookups — wait a minute and retry')
  }
  const db = req.ownerDb!
  try {
    const [profile, subscription, invoices, audit, notifications] = await Promise.all([
      db.from('profiles').select('id,email,name,full_name,tier,created_at').eq('id', userId).maybeSingle(),
      db.from('billing_subscriptions').select(SUBSCRIPTION_COLUMNS).eq('user_id', userId).order('updated_at', { ascending: false }),
      db.from('billing_invoices').select(INVOICE_COLUMNS).eq('user_id', userId).order('created_at', { ascending: false }).limit(500),
      db.from('billing_audit_events').select('id,user_id,action,message,created_at,metadata').eq('user_id', userId).order('created_at', { ascending: false }).limit(200),
      db.from('billing_notifications').select('id,user_id,type,severity,title,message,created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(100),
    ])
    const failure = [profile, subscription, invoices, audit, notifications].find((result) => result.error)
    if (failure?.error) throw new Error(failure.error.message)
    if (!profile.data && !(subscription.data || []).length && !(invoices.data || []).length) {
      return jsonError(res, 404, 'CUSTOMER_NOT_FOUND', 'No account or billing record exists for this customer')
    }

    // Run the SAME model over this customer's rows so every per-customer
    // figure (lifetime revenue, MRR, classification) matches the dashboards.
    const model = buildRevenueModel({
      now: new Date(),
      subscriptions: (subscription.data || []) as unknown as SubscriptionRecord[],
      invoices: (invoices.data || []) as unknown as InvoiceRecord[],
      profiles: profile.data ? [profile.data as ProfileRecord] : [],
      auditEvents: (audit.data || []) as AuditRecord[],
      notifications: (notifications.data || []) as NotificationRecord[],
      coverage: [],
    })

    await recordRevenueAudit(db, req.ownerUser, req, 'revenue.customer.viewed', 'customer', userId, {
      invoices: model.invoices.length,
    })
    res.setHeader('Cache-Control', 'no-store')
    return res.json({
      data: {
        userId,
        profile: profile.data
          ? { email: profile.data.email ?? null, name: profile.data.full_name || profile.data.name || null, tier: profile.data.tier ?? null, createdAt: profile.data.created_at ?? null }
          : null,
        customer: model.customers[0] ?? null,
        subscriptions: model.subscribers,
        invoices: model.invoices,
        activity: model.activity,
        notifications: model.alerts,
        invoicesTruncated: (invoices.data || []).length >= 500,
      },
    })
  } catch (err) {
    console.error('[revenue] customer detail error:', err)
    return jsonError(res, 500, 'CUSTOMER_DETAIL_FAILED', 'The customer record could not be loaded')
  }
})

// ---- Report exports ---------------------------------------------------------

type ReportKind = 'revenue' | 'subscriptions' | 'payments' | 'customers' | 'summary'
const REPORTS: ReportKind[] = ['revenue', 'subscriptions', 'payments', 'customers', 'summary']
const FORMATS = ['csv', 'json'] as const

/**
 * CSV cell encoding. Besides quoting, a cell that begins with = + - @ TAB or
 * CR is prefixed with an apostrophe: customer names and emails are
 * user-controlled, and a name like `=HYPERLINK(...)` would otherwise execute
 * as a formula when the owner opens the export in Excel (CSV injection).
 */
export function csvCell(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return ''
  let text = String(value)
  if (typeof value === 'string' && /^[=+\-@\t\r]/.test(text)) text = `'${text}`
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}

export function toCsv(headers: string[], rows: Array<Array<string | number | null>>): string {
  return [headers.map(csvCell).join(','), ...rows.map((row) => row.map(csvCell).join(','))].join('\r\n')
}

const usd = (cents: number | null) => (cents === null ? null : (cents / 100).toFixed(2))

export function buildReportRows(model: RevenueModel, report: ReportKind): { headers: string[]; rows: Array<Array<string | number | null>> } {
  switch (report) {
    case 'revenue':
      return {
        headers: ['Month (UTC)', 'Complete', 'Gross Revenue (USD)', 'Refunded (USD)', 'Net Revenue (USD)', 'Payments', 'Failed Payments', 'New Billed Subscriptions', 'Churned Subscriptions', 'New Sign-ups', 'Month-end MRR (USD, reconstructed)'],
        rows: model.timeline.map((bucket) => [bucket.label, bucket.complete ? 'yes' : 'month to date', usd(bucket.grossCents), usd(bucket.refundedCents), usd(bucket.netCents), bucket.payments, bucket.failedPayments, bucket.newSubscriptions, bucket.churnedSubscriptions, bucket.newSignups, usd(bucket.endingMrrCents)]),
      }
    case 'subscriptions':
      return {
        headers: ['Subscription ID', 'Email', 'Plan', 'Status', 'Revenue Class', 'Provider', 'Billing Cycle', 'Auto Renew', 'Ends At Period End', 'Since', 'Renewal Date', 'Monthly Value (USD)', 'Price Source', 'MRR Contribution (USD)'],
        rows: model.subscribers.map((sub) => [sub.id, sub.email, sub.plan, sub.status, sub.revenueClass, sub.providerLabel, sub.billingCycle, sub.autoRenew ? 'yes' : 'no', sub.cancelAtPeriodEnd ? 'yes' : 'no', sub.since, sub.renewalDate, usd(sub.monthlyValueCents), sub.priceSource, usd(sub.mrrCents)]),
      }
    case 'payments':
      return {
        headers: ['Paid At (UTC)', 'Invoice', 'Transaction', 'Email', 'Plan', 'Amount', 'Refunded', 'Currency', 'In USD Totals', 'Method', 'Status', 'Refunded At (UTC)'],
        rows: model.invoices.map((invoice) => [invoice.paidAt, invoice.invoiceId, invoice.transactionId, invoice.email, invoice.plan, (invoice.amountCents / 100).toFixed(2), (invoice.refundedCents / 100).toFixed(2), invoice.currency, invoice.inReportingCurrency ? 'yes' : 'no', invoice.method, invoice.status, invoice.refundedAt]),
      }
    case 'customers':
      return {
        headers: ['User ID', 'Email', 'Name', 'Plan', 'Status', 'Revenue Class', 'Provider', 'Customer Since', 'Renewal Date', 'Paid Invoices', 'Failed Payments', 'Last Payment (UTC)', 'MRR (USD)', 'Lifetime Net Revenue (USD)'],
        rows: model.customers.map((customer) => [customer.userId, customer.email, customer.name, customer.plan, customer.status, customer.revenueClass, customer.provider, customer.since, customer.renewalDate, customer.paidInvoices, customer.failedPayments, customer.lastPaymentAt, usd(customer.mrrCents), usd(customer.lifetimeNetCents)]),
      }
    case 'summary':
    default:
      return {
        headers: ['Metric', 'Value', 'Basis'],
        rows: [
          ['Generated At', model.generatedAt, 'UTC'],
          ['Gross Revenue (USD)', usd(model.kpis.grossRevenueCents), 'Collected payments, all time'],
          ['Refunded (USD)', usd(model.kpis.refundedCents), 'Recognised at refund time'],
          ['Net Revenue (USD)', usd(model.kpis.netRevenueCents), 'Gross − refunds'],
          ['MRR (USD)', usd(model.kpis.mrrCents), 'Provider-billed, access-granting subscriptions'],
          ['ARR (USD)', usd(model.kpis.arrCents), 'MRR × 12'],
          ['ARPU (USD)', usd(model.kpis.arpuCents), 'MRR ÷ paying customers'],
          ['LTV (USD)', usd(model.kpis.ltvCents), 'ARPU ÷ monthly churn'],
          ['Paying Subscribers', model.kpis.payingSubscribers, 'Provider-billed, access-granting'],
          ['Churn % (30d)', model.kpis.churnPct, `${model.subscriptionAnalytics.churnWindow.churned} of ${model.subscriptionAnalytics.churnWindow.base} billed subscriptions`],
          ['Retention % (30d)', model.kpis.retentionPct, '100 − churn'],
          ['Revenue Growth % (last complete month)', model.kpis.revenueGrowthPct, 'vs the month before'],
          ['Subscription Health Score', model.kpis.subscriptionHealthScore, `${model.subscriptionAnalytics.health.measuredWeightPct}% of weight measured`],
          ['Payment Success Rate %', model.paymentAnalytics.successRatePct, `${model.paymentAnalytics.attempted} attempts`],
          ['Complimentary / test subscriptions', model.subscriptionAnalytics.byClass.complimentary, 'Excluded from revenue'],
          ['Manually managed subscriptions', model.subscriptionAnalytics.byClass.manual, 'Excluded from MRR (not provider-billed)'],
          ['Today (USD)', usd(model.windows.todayCents), 'UTC day'],
          ['This Week (USD)', usd(model.windows.thisWeekCents), 'UTC, from Monday'],
          ['This Month (USD)', usd(model.windows.thisMonthCents), 'UTC month to date'],
          ['This Year (USD)', usd(model.windows.thisYearCents), 'UTC year to date'],
          ['Reconciliation', model.reconciliation.ok ? 'all checks pass' : 'MISMATCH', model.reconciliation.checks.filter((check) => !check.ok).map((check) => check.label).join('; ') || `${model.reconciliation.checks.length} checks`],
        ],
      }
  }
}

router.get('/export', async (req: OwnerRequest, res: Response) => {
  const report = String(req.query.report || 'summary') as ReportKind
  const format = String(req.query.format || 'csv').toLowerCase() as (typeof FORMATS)[number]
  if (!REPORTS.includes(report)) return jsonError(res, 400, 'INVALID_REPORT', 'Unknown report kind')
  if (!FORMATS.includes(format)) return jsonError(res, 400, 'INVALID_FORMAT', 'Format must be csv or json')
  if (rateLimited(`export:${req.ownerUser!.id}`, 30, 60_000)) {
    return jsonError(res, 429, 'RATE_LIMITED', 'Too many exports — wait a minute and retry')
  }
  // Financial exports must never be cached by a proxy/browser or leak a
  // referrer to a downstream origin.
  res.setHeader('Cache-Control', 'no-store')
  res.setHeader('Referrer-Policy', 'no-referrer')
  try {
    // Exports read the FULL model, never the bounded snapshot ledgers.
    const model = await getRevenueModel(req.ownerDb!)
    const { headers, rows } = buildReportRows(model, report)
    const stamp = model.generatedAt.slice(0, 10)
    const filename = `qguard-${report}-report-${stamp}.${format}`
    await recordRevenueAudit(req.ownerDb, req.ownerUser, req, 'revenue.export', 'revenue_report', report, {
      report,
      format,
      rows: rows.length,
      generatedAt: model.generatedAt,
    })
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`)
    res.setHeader('X-Report-Rows', String(rows.length))
    if (format === 'json') {
      return res.json({ report, generatedAt: model.generatedAt, reportingCurrency: model.reportingCurrency, timezone: model.timezone, headers, rows, kpis: model.kpis, coverage: model.coverage })
    }
    res.setHeader('Content-Type', 'text/csv; charset=utf-8')
    // BOM so Excel opens UTF-8 (names with accents) correctly.
    return res.send(`﻿${toCsv(headers, rows)}`)
  } catch (err) {
    console.error('[revenue] export error:', err)
    return jsonError(res, 500, 'REVENUE_EXPORT_FAILED', 'Failed to build the report')
  }
})

export default router
