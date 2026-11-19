import { Router, Request, Response } from 'express'
import { timingSafeEqual } from 'node:crypto'
import type { SupabaseClient } from '@supabase/supabase-js'
import { getServerUser, getServiceClient } from '@/lib/supabase-server'
import {
  activationAuditAction,
  BILLING_AUDIT,
  cancellationPatch,
  isCancellationRecorded,
  isPaypalSubscriptionId,
  failedPaymentInvoiceRow,
  invoiceRow,
  moneyBackRefundCancels,
  planChangeAction,
  refundCancellationPatch,
  refundInvoicePatch,
  statusAuditAction,
  webhookClaimDecision,
} from '../../supabase/functions/billing/logic'

/**
 * PayPal recurring-subscription provider.
 *
 * Buyers reach this from the landing pricing section AFTER signing in (the
 * /checkout flow) or from the in-dashboard billing settings. The PayPal SECRET
 * is used ONLY server-side to fetch an OAuth token and create/cancel
 * subscriptions — it is never sent to the browser; the frontend only receives
 * an approval URL to redirect to.
 *
 * Identity is always taken from the authenticated session (never the request
 * body): custom_id === the verified Supabase user id. The webhook is the single
 * source of activation — it writes to billing_subscriptions / profiles.tier /
 * billing_invoices, which the existing Settings SSE + Admin dashboard already
 * render. Plan ids are provisioned once via tools/paypal-setup.ts.
 */

const router = Router()

type Tier = 'Starter' | 'Basic' | 'Pro' | 'Elite'
type Cycle = 'monthly' | 'yearly'
type DbCycle = 'monthly' | 'annual'

export const PAYPAL_TIERS: Tier[] = ['Starter', 'Basic', 'Pro', 'Elite']

// Source of truth: src/lib/billing/plan-pricing.ts (mirrors the landing pricing
// section). Yearly plans bill the discounted monthly rate x 12, once per year.
export { PLAN_PRICING } from '@/lib/billing/plan-pricing'

// ---- Config (read lazily; process.env may be populated after module import) ----

function paypalBase(): string {
  const env = String(process.env.PAYPAL_ENV || 'live').toLowerCase()
  return env === 'sandbox' ? 'https://api-m.sandbox.paypal.com' : 'https://api-m.paypal.com'
}

function clientId(): string {
  return process.env.PAYPAL_CLIENT_ID || ''
}

function clientSecret(): string {
  return process.env.PAYPAL_SECRET_KEY || process.env.PAYPAL_CLIENT_SECRET || ''
}

export function isPaypalConfigured(): boolean {
  return Boolean(clientId() && clientSecret())
}

function planEnvKey(tier: Tier, cycle: Cycle): string {
  return `PAYPAL_PLAN_${tier.toUpperCase()}_${cycle.toUpperCase()}`
}

function planIdFor(tier: Tier, cycle: Cycle): string | null {
  return process.env[planEnvKey(tier, cycle)] || null
}

function planInfoFromId(planId?: string): { tier: Tier; cycle: Cycle } | null {
  if (!planId) return null
  for (const tier of PAYPAL_TIERS) {
    for (const cycle of ['monthly', 'yearly'] as Cycle[]) {
      if (planIdFor(tier, cycle) === planId) return { tier, cycle }
    }
  }
  return null
}

// ---- Helpers ----

function jsonError(res: Response, status: number, code: string, message: string) {
  return res.status(status).json({ error: { code, message } })
}

export function normalizeTier(value: unknown): Tier | null {
  const text = String(value || '').trim().toLowerCase()
  if (text === 'starter') return 'Starter'
  if (text === 'basic') return 'Basic'
  if (text === 'pro') return 'Pro'
  if (text === 'elite') return 'Elite'
  return null
}

export function normalizeCycle(value: unknown): Cycle {
  const text = String(value || '').toLowerCase()
  return text.startsWith('year') || text === 'annual' ? 'yearly' : 'monthly'
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
}

function extractToken(req: Request): string | null {
  // Header only — never a ?token= query param. This endpoint has no EventSource
  // carrier, so accepting the session token in the URL would only risk leaking
  // it into server logs, browser history, and Referer headers.
  const authHeader = req.headers.authorization
  return authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null
}

/**
 * Resolve the public origin used to build PayPal return/cancel URLs.
 *
 * Security: never trust the Host / X-Forwarded-Host header for an
 * externally-consumed redirect URL — host-header injection would let an
 * attacker point the post-approval redirect at their own domain. Prefer an
 * explicitly configured origin; only fall back to the request host for
 * localhost dev. Returns null when it cannot be resolved safely so callers can
 * fail closed.
 */
export function resolveOrigin(req: Request): string | null {
  const configured = process.env.APP_ORIGIN || process.env.PUBLIC_APP_ORIGIN || process.env.VITE_APP_ORIGIN
  if (configured) return configured.replace(/\/$/, '')

  const host = req.headers.host || ''
  if (/^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(host)) {
    const protocol = String(req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0]
    return `${protocol}://${host}`.replace(/\/$/, '')
  }
  return null
}

// ---- PayPal REST client ----

let cachedToken: { token: string; expiresAt: number } | null = null

async function getAccessToken(): Promise<string> {
  if (!isPaypalConfigured()) {
    throw new Error('PayPal is not configured (missing PAYPAL_CLIENT_ID / PAYPAL_SECRET_KEY)')
  }
  const now = Date.now()
  if (cachedToken && cachedToken.expiresAt > now + 60_000) return cachedToken.token

  const auth = Buffer.from(`${clientId()}:${clientSecret()}`).toString('base64')
  const response = await fetch(`${paypalBase()}/v1/oauth2/token`, {
    method: 'POST',
    headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials',
  })
  const json: any = await response.json().catch(() => ({}))
  if (!response.ok || !json?.access_token) {
    throw new Error(json?.error_description || json?.error || `PayPal auth failed (HTTP ${response.status})`)
  }
  cachedToken = { token: json.access_token, expiresAt: now + (Number(json.expires_in) || 3000) * 1000 }
  return cachedToken.token
}

async function paypalFetch(
  pathname: string,
  init: { method?: string; body?: unknown; headers?: Record<string, string> } = {},
): Promise<any> {
  const token = await getAccessToken()
  const response = await fetch(`${paypalBase()}${pathname}`, {
    method: init.method || 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  })
  const text = await response.text()
  let json: any = {}
  if (text) {
    try {
      json = JSON.parse(text)
    } catch {
      json = {}
    }
  }
  if (!response.ok) {
    const message = json?.message || json?.error_description || `PayPal request failed (HTTP ${response.status})`
    const error = new Error(message) as Error & { status?: number; details?: unknown }
    error.status = response.status
    error.details = json?.details
    throw error
  }
  return json
}

// ---- Exported operations (shared by /subscribe and the dashboard billing actions) ----

/**
 * Create a PayPal subscription for an authenticated user and return the
 * approval URL. `userId` MUST come from a verified session, never the request
 * body — it is attached as custom_id so the webhook can attribute activation.
 */
export async function createSubscription(opts: {
  userId: string
  email?: string | null
  tier: Tier
  cycle: Cycle
  returnUrl: string
  cancelUrl: string
}): Promise<{ approvalUrl: string; subscriptionId: string }> {
  const planId = planIdFor(opts.tier, opts.cycle)
  if (!planId) {
    const error = new Error(
      `PayPal plan is not configured for ${opts.tier} ${opts.cycle}. Run tools/paypal-setup.ts and set ${planEnvKey(opts.tier, opts.cycle)}.`,
    ) as Error & { code?: string }
    error.code = 'PLAN_NOT_CONFIGURED'
    throw error
  }

  const subscription = await paypalFetch('/v1/billing/subscriptions', {
    method: 'POST',
    headers: { 'PayPal-Request-Id': `qguard-sub-${opts.userId}-${opts.tier}-${opts.cycle}-${Date.now()}` },
    body: {
      plan_id: planId,
      custom_id: opts.userId,
      subscriber: opts.email ? { email_address: opts.email } : undefined,
      application_context: {
        brand_name: 'QGuard Helix',
        locale: 'en-US',
        shipping_preference: 'NO_SHIPPING',
        user_action: 'SUBSCRIBE_NOW',
        payment_method: { payer_selected: 'PAYPAL', payee_preferred: 'IMMEDIATE_PAYMENT_REQUIRED' },
        return_url: opts.returnUrl,
        cancel_url: opts.cancelUrl,
      },
    },
  })

  const approval = Array.isArray(subscription?.links)
    ? subscription.links.find((link: any) => link?.rel === 'approve')
    : null
  if (!approval?.href) {
    const error = new Error('PayPal did not return an approval URL') as Error & { code?: string }
    error.code = 'NO_APPROVAL_URL'
    throw error
  }
  return { approvalUrl: approval.href, subscriptionId: subscription.id }
}

export async function cancelSubscription(providerSubscriptionId: string, reason = 'User requested cancellation'): Promise<void> {
  if (!providerSubscriptionId) return
  await paypalFetch(`/v1/billing/subscriptions/${encodeURIComponent(providerSubscriptionId)}/cancel`, {
    method: 'POST',
    body: { reason },
  })
}

async function getRemoteSubscription(providerSubscriptionId: string): Promise<any> {
  return paypalFetch(`/v1/billing/subscriptions/${encodeURIComponent(providerSubscriptionId)}`, { method: 'GET' })
}

/**
 * Change the plan of an EXISTING subscription in place (PayPal handles
 * proration and keeps the same subscription id — no cancel/re-create, so no
 * double-billing window). Returns an approval URL when PayPal requires the
 * buyer to re-approve (e.g. a price increase), otherwise null (applied
 * immediately; the BILLING.SUBSCRIPTION.UPDATED webhook syncs our record).
 */
export async function reviseSubscription(opts: {
  providerSubscriptionId: string
  tier: Tier
  cycle: Cycle
  returnUrl: string
  cancelUrl: string
}): Promise<{ approvalUrl: string | null }> {
  const planId = planIdFor(opts.tier, opts.cycle)
  if (!planId) {
    const error = new Error(
      `PayPal plan is not configured for ${opts.tier} ${opts.cycle}. Run tools/paypal-setup.ts and set ${planEnvKey(opts.tier, opts.cycle)}.`,
    ) as Error & { code?: string }
    error.code = 'PLAN_NOT_CONFIGURED'
    throw error
  }

  const result = await paypalFetch(`/v1/billing/subscriptions/${encodeURIComponent(opts.providerSubscriptionId)}/revise`, {
    method: 'POST',
    body: {
      plan_id: planId,
      application_context: {
        brand_name: 'QGuard Helix',
        locale: 'en-US',
        shipping_preference: 'NO_SHIPPING',
        user_action: 'SUBSCRIBE_NOW',
        return_url: opts.returnUrl,
        cancel_url: opts.cancelUrl,
      },
    },
  })

  const approval = Array.isArray(result?.links) ? result.links.find((link: any) => link?.rel === 'approve') : null
  return { approvalUrl: approval?.href || null }
}

// ---- Routes ----

/** Non-sensitive readiness probe (booleans only, never secrets or ids). */
router.get('/config', (_req: Request, res: Response) => {
  const plans: Record<string, boolean> = {}
  for (const tier of PAYPAL_TIERS) {
    for (const cycle of ['monthly', 'yearly'] as Cycle[]) {
      plans[`${tier.toLowerCase()}_${cycle}`] = Boolean(planIdFor(tier, cycle))
    }
  }
  return res.json({
    data: {
      configured: isPaypalConfigured(),
      env: String(process.env.PAYPAL_ENV || 'live').toLowerCase() === 'sandbox' ? 'sandbox' : 'live',
      plans,
    },
  })
})

/**
 * Authenticated: create a subscription for the signed-in user and return the
 * PayPal approval URL the browser should redirect to.
 */
router.post('/subscribe', async (req: Request, res: Response) => {
  try {
    if (!isPaypalConfigured()) {
      return jsonError(res, 503, 'PAYPAL_NOT_CONFIGURED', 'PayPal is not configured on the server')
    }
    const token = extractToken(req)
    if (!token) return jsonError(res, 401, 'UNAUTHORIZED', 'Sign in to start a subscription')
    const user = await getServerUser(token)
    if (!user) return jsonError(res, 401, 'UNAUTHORIZED', 'Invalid or expired session')

    const tier = normalizeTier(req.body?.plan)
    if (!tier) return jsonError(res, 400, 'INVALID_PLAN', 'Unknown or missing plan')
    const cycle = normalizeCycle(req.body?.cycle ?? req.body?.billingPeriod)

    const base = resolveOrigin(req)
    if (!base) {
      return jsonError(
        res,
        503,
        'APP_ORIGIN_NOT_CONFIGURED',
        'Set APP_ORIGIN to the public site URL so PayPal return URLs can be built safely.',
      )
    }

    const result = await createSubscription({
      userId: user.id,
      email: user.email,
      tier,
      cycle,
      returnUrl: `${base}/subscription/thank-you?plan=${tier}&cycle=${cycle}`,
      cancelUrl: `${base}/dashboard/settings?tab=billing&subscription=cancelled`,
    })

    return res.json({ data: { approvalUrl: result.approvalUrl, subscriptionId: result.subscriptionId, plan: tier, cycle } })
  } catch (err: any) {
    if (err?.code === 'PLAN_NOT_CONFIGURED') return jsonError(res, 503, 'PLAN_NOT_CONFIGURED', err.message)
    console.error('[paypal] subscribe error:', err?.message || err)
    return jsonError(res, 502, 'PAYPAL_SUBSCRIBE_FAILED', err?.message || 'Failed to create PayPal subscription')
  }
})

// ---- Webhook ----

async function verifyWebhook(req: Request): Promise<boolean> {
  const webhookId = process.env.PAYPAL_WEBHOOK_ID
  if (!webhookId) return false
  const headers = req.headers
  try {
    const result = await paypalFetch('/v1/notifications/verify-webhook-signature', {
      method: 'POST',
      body: {
        auth_algo: headers['paypal-auth-algo'],
        cert_url: headers['paypal-cert-url'],
        transmission_id: headers['paypal-transmission-id'],
        transmission_sig: headers['paypal-transmission-sig'],
        transmission_time: headers['paypal-transmission-time'],
        webhook_id: webhookId,
        webhook_event: req.body,
      },
    })
    return result?.verification_status === 'SUCCESS'
  } catch (err) {
    console.error('[paypal] webhook verification error:', err)
    return false
  }
}

/**
 * Claim a delivery BEFORE any side effect runs — the same protocol as the
 * `billing` Edge Function (webhookClaimDecision in logic.ts). The unique
 * event_id makes the first insert the claim; a redelivery skips (processed),
 * backs off (running) or re-claims with a compare-and-set (failed or stale).
 */
async function claimWebhookEvent(
  db: SupabaseClient,
  eventId: string,
  eventType: string,
  resource: any,
  raw: unknown,
): Promise<'run' | 'duplicate' | 'in-progress'> {
  const nowIso = new Date().toISOString()
  const { error } = await db.from('paypal_webhook_events').insert({
    event_id: eventId,
    event_type: eventType,
    resource_id: resource?.id || resource?.billing_agreement_id || null,
    user_id: isUuid(resource?.custom_id) ? resource.custom_id : null,
    raw,
    status: 'processing',
    claimed_at: nowIso,
    attempts: 1,
  })
  if (!error) return 'run'
  if ((error as { code?: string }).code !== '23505') throw new Error(`webhook claim failed: ${error.message}`)

  const { data: existing, error: readError } = await db
    .from('paypal_webhook_events')
    .select('status, claimed_at, processed_at, attempts')
    .eq('event_id', eventId)
    .maybeSingle()
  if (readError) throw new Error(`webhook claim read failed: ${readError.message}`)
  const decision = webhookClaimDecision(existing, Date.now())
  if (decision !== 'run' || !existing) return decision

  let reclaim = db
    .from('paypal_webhook_events')
    .update({ status: 'processing', claimed_at: nowIso, attempts: (Number(existing.attempts) || 0) + 1 })
    .eq('event_id', eventId)
    .eq('status', existing.status)
  reclaim = existing.claimed_at ? reclaim.eq('claimed_at', existing.claimed_at) : reclaim.is('claimed_at', null)
  const { data: reclaimed, error: reclaimError } = await reclaim.select('event_id')
  if (reclaimError) throw new Error(`webhook re-claim failed: ${reclaimError.message}`)
  return reclaimed && reclaimed.length > 0 ? 'run' : 'in-progress'
}

async function bestEffort(operation: () => any): Promise<void> {
  try {
    await operation()
  } catch (err) {
    console.error('[paypal] webhook side-effect failed:', err)
  }
}

/** Audit rows never fail the delivery, but a failed write is LOGGED, not swallowed. */
async function audit(db: SupabaseClient, userId: string, action: string, message: string, metadata: Record<string, unknown>) {
  await bestEffort(async () => {
    const { error } = await db.from('billing_audit_events').insert({ user_id: userId, action, message, metadata })
    if (error) throw new Error(`${action}: ${error.message}`)
  })
}

async function notify(db: SupabaseClient, userId: string, type: string, severity: string, title: string, message: string) {
  await bestEffort(async () => {
    const { error } = await db.from('billing_notifications').insert({ user_id: userId, type, severity, title, message })
    if (error) throw new Error(error.message)
  })
}

type DbStatus = 'active' | 'trial' | 'expired' | 'suspended' | 'pending_renewal' | 'cancelled' | 'past_due' | 'incomplete'

/**
 * Run a Supabase write and throw if it errors. Used for the CRITICAL rows the
 * webhook must persist (subscription state, tier, invoices). A throw bubbles to
 * the webhook handler, which returns 5xx so PayPal redelivers the event —
 * activation is never silently lost. Optional side-effects (notifications,
 * audit) stay on bestEffort so they can't fail the whole delivery.
 */
async function mustSucceed(op: PromiseLike<{ error: unknown }>, label: string): Promise<void> {
  const { error } = await op
  if (error) {
    const message = (error as any)?.message || (error as any)?.code || 'database error'
    throw new Error(`${label} failed: ${message}`)
  }
}

function mapPaypalStatus(status?: string): DbStatus | null {
  switch (String(status || '').toUpperCase()) {
    case 'ACTIVE':
      return 'active'
    case 'SUSPENDED':
      return 'suspended'
    case 'CANCELLED':
      return 'cancelled'
    case 'EXPIRED':
      return 'expired'
    case 'APPROVAL_PENDING':
    case 'APPROVED':
      return 'incomplete'
    default:
      return null
  }
}

/** Select-then-insert by provider_invoice_id (the partial unique index rejects ON CONFLICT, 42P10). */
async function insertInvoiceOnce(db: SupabaseClient, row: Record<string, unknown>, label: string): Promise<boolean> {
  const reference = row.provider_invoice_id as string | null
  if (reference) {
    const { data: existing, error } = await db.from('billing_invoices').select('id').eq('provider_invoice_id', reference).maybeSingle()
    if (error) throw new Error(`${label} lookup failed: ${error.message}`)
    if (existing?.id) return false
  }
  const { error } = await db.from('billing_invoices').insert(row)
  // 23505: a concurrent delivery recorded the same row first.
  if (error && (error as { code?: string }).code === '23505') return false
  if (error) throw new Error(`${label} failed: ${error.message}`)
  return true
}

async function subscriptionByProviderId(db: SupabaseClient, providerSubscriptionId: string) {
  const { data } = await db
    .from('billing_subscriptions')
    .select('user_id, plan, status, billing_cycle, current_period_end, cancel_at_period_end, cancelled_at')
    .eq('provider_subscription_id', providerSubscriptionId)
    .maybeSingle()
  return data as {
    user_id: string
    plan: string
    status: string
    billing_cycle: string | null
    current_period_end: string | null
    cancel_at_period_end: boolean | null
    cancelled_at: string | null
  } | null
}

async function activateSubscription(db: SupabaseClient, resource: any): Promise<void> {
  const userId = resource?.custom_id
  if (!isUuid(userId)) return
  const info = planInfoFromId(resource?.plan_id)
  if (!info) return

  const providerSubId: string | null = resource?.id || null
  const dbCycle: DbCycle = info.cycle === 'yearly' ? 'annual' : 'monthly'
  const nextBilling = resource?.billing_info?.next_billing_time || null
  const nowIso = new Date().toISOString()

  const { data: previous } = await db
    .from('billing_subscriptions')
    .select('plan, status, provider, provider_subscription_id')
    .eq('user_id', userId)
    .maybeSingle()

  // Cancel a prior PayPal subscription that this one supersedes (plan change),
  // to avoid double-billing the customer.
  await bestEffort(async () => {
    const prior = previous?.provider_subscription_id
    if (previous?.provider === 'paypal' && prior && providerSubId && prior !== providerSubId) {
      await cancelSubscription(prior, 'Superseded by a new QGuard subscription').catch(() => undefined)
    }
  })

  await mustSucceed(
    db.from('billing_subscriptions').upsert(
      {
        user_id: userId,
        subscription_id: providerSubId || `paypal_${Date.now()}`,
        provider: 'paypal',
        provider_subscription_id: providerSubId,
        plan: info.tier,
        status: 'active',
        billing_cycle: dbCycle,
        auto_renew: true,
        cancel_at_period_end: false,
        current_period_start: resource?.start_time || nowIso,
        current_period_end: nextBilling,
        renewal_date: nextBilling,
        cancelled_at: null,
        metadata: { paypalPlanId: resource?.plan_id || null, payerEmail: resource?.subscriber?.email_address || null },
        updated_at: nowIso,
      },
      { onConflict: 'user_id' },
    ),
    'subscription activation',
  )

  await mustSucceed(
    db.from('profiles').update({ tier: info.tier.toLowerCase(), updated_at: nowIso }).eq('id', userId),
    'profile tier activation',
  )

  // Audit + notify only on a real transition — a redelivered ACTIVATED for the
  // subscription we already hold active is a re-statement, not an event.
  const action = activationAuditAction(previous, { plan: info.tier, providerSubscriptionId: providerSubId })
  if (!action) return
  const verb = action === BILLING_AUDIT.upgraded ? 'upgrade is active' : action === BILLING_AUDIT.downgraded ? 'plan change is active' : 'is now active'
  await notify(db, userId, 'subscription', 'success', action === BILLING_AUDIT.activated ? 'Subscription activated' : 'Plan changed', `Your ${info.tier} (${dbCycle}) subscription ${verb} via PayPal.`)
  await audit(db, userId, action, `PayPal subscription ${action.split('.')[1]}: ${previous?.plan && previous.plan !== info.tier ? `${previous.plan} → ` : ''}${info.tier} ${dbCycle}`, {
    providerSubscriptionId: providerSubId,
    planId: resource?.plan_id || null,
    fromPlan: previous?.plan ?? null,
    toPlan: info.tier,
    source: 'paypal.webhook',
  })
}

async function recordPayment(db: SupabaseClient, resource: any): Promise<void> {
  const subId: string | null = resource?.billing_agreement_id || null
  if (!subId) return

  const sub = await subscriptionByProviderId(db, subId)
  if (!sub?.user_id) return

  // A redelivered PAYMENT.SALE.COMPLETED must never overwrite the row — it
  // would flip an already-refunded invoice back to "paid".
  const invoice = invoiceRow(resource, sub, new Date().toISOString())
  const inserted = await insertInvoiceOnce(db, invoice, 'invoice recording')
  if (inserted) {
    await audit(db, sub.user_id, BILLING_AUDIT.paymentSucceeded, `Payment received: ${sub.plan} ${(Number(invoice.amount_paid_cents) / 100).toFixed(2)} ${invoice.currency}`, {
      saleId: invoice.provider_invoice_id,
      amountCents: invoice.amount_paid_cents,
      currency: invoice.currency,
      providerSubscriptionId: subId,
      source: 'paypal.webhook',
    })
  }

  // Refresh the renewal date from PayPal after a successful recurring payment.
  await bestEffort(async () => {
    const details = await getRemoteSubscription(subId)
    const nextBilling = details?.billing_info?.next_billing_time
    if (nextBilling) {
      await db
        .from('billing_subscriptions')
        .update({ renewal_date: nextBilling, current_period_end: nextBilling, status: 'active', updated_at: new Date().toISOString() })
        .eq('provider_subscription_id', subId)
    }
  })
}

async function updateSubscriptionStatus(
  db: SupabaseClient,
  resource: any,
  status: 'cancelled' | 'suspended' | 'expired' | 'past_due',
): Promise<void> {
  const subId: string | null = resource?.id || null
  if (!subId) return
  const nowIso = new Date().toISOString()
  const sub = await subscriptionByProviderId(db, subId)

  // Every failed attempt is its own payment record (PayPal retries a failed
  // charge several times while the subscription stays past_due).
  if (status === 'past_due' && sub?.user_id) {
    const failedRow = failedPaymentInvoiceRow(resource, sub, nowIso)
    if (failedRow && await insertInvoiceOnce(db, failedRow, 'failed payment recording')) {
      await audit(db, sub.user_id, BILLING_AUDIT.paymentFailed, `Payment failed: ${sub.plan} ${(Number(failedRow.amount_paid_cents) / 100).toFixed(2)} ${failedRow.currency}`, {
        reference: failedRow.provider_invoice_id,
        attemptedCents: failedRow.amount_paid_cents,
        providerSubscriptionId: subId,
        source: 'paypal.webhook',
      })
    }
  }

  if (status === 'cancelled') {
    // PayPal has stopped billing; the customer keeps the period already paid
    // for and the scheduled expiry ends access at current_period_end.
    if (isCancellationRecorded(sub)) return
    const { patch: cancelPatch, accessUntil } = cancellationPatch(sub, nowIso)
    await mustSucceed(db.from('billing_subscriptions').update(cancelPatch).eq('provider_subscription_id', subId), 'subscription cancellation')
    if (sub?.user_id) {
      await notify(db, sub.user_id, 'subscription', 'warning', 'Subscription cancelled', accessUntil
        ? `Your ${sub.plan} subscription is cancelled and will not renew. You keep access until ${accessUntil.slice(0, 10)}.`
        : `Your ${sub.plan} subscription is now cancelled.`)
      await audit(db, sub.user_id, BILLING_AUDIT.cancelled, accessUntil ? `PayPal subscription cancelled; access until ${accessUntil}` : 'PayPal subscription cancelled', {
        fromStatus: sub.status,
        toStatus: accessUntil ? sub.status : 'cancelled',
        accessUntil,
        plan: sub.plan,
        providerSubscriptionId: subId,
        source: 'paypal.webhook',
      })
    }
    return
  }

  // A redelivered status the row already holds changes nothing.
  if (sub && String(sub.status).toLowerCase() === status) return

  const patch: Record<string, unknown> = { status, updated_at: nowIso }
  if (status === 'suspended' || status === 'expired') {
    patch.auto_renew = false
  }
  // past_due keeps auto_renew — PayPal continues its own dunning/retry cycle.

  await mustSucceed(
    db.from('billing_subscriptions').update(patch).eq('provider_subscription_id', subId),
    'subscription status update',
  )

  if (sub?.user_id) {
    await notify(
      db,
      sub.user_id,
      'subscription',
      'critical',
      `Subscription ${status.replace('_', ' ')}`,
      status === 'past_due'
        ? `A payment for your ${sub.plan} subscription failed. Please update your PayPal payment method to avoid interruption.`
        : `Your ${sub.plan} subscription is now ${status}.`,
    )
    await audit(db, sub.user_id, statusAuditAction(status), `PayPal subscription ${status.replace('_', ' ')}`, {
      fromStatus: sub.status,
      toStatus: status,
      plan: sub.plan,
      providerSubscriptionId: subId,
      source: 'paypal.webhook',
    })
  }
}

/** True when no earlier charge of the same PayPal subscription was recorded. */
async function isFirstPayment(db: SupabaseClient, invoice: { id: string; user_id: string; payment_date: string | null }, subscriptionId: string): Promise<boolean> {
  if (!invoice.payment_date) return false
  const { data, error } = await db
    .from('billing_invoices')
    .select('id')
    .eq('user_id', invoice.user_id)
    .eq('metadata->>subscriptionId', subscriptionId)
    .in('status', ['paid', 'refunded'])
    .lt('payment_date', invoice.payment_date)
    .neq('id', invoice.id)
    .limit(1)
  if (error) throw new Error(`first payment lookup failed: ${error.message}`)
  return !data || data.length === 0
}

/** Full refund of the first payment: stop PayPal billing and end access (same rule as the billing Edge Function). */
async function cancelForRefund(db: SupabaseClient, subscriptionId: string, userId: string, refundCents: number, currency: string): Promise<void> {
  const sub = await subscriptionByProviderId(db, subscriptionId)
  if (!sub || sub.user_id !== userId || String(sub.status).toLowerCase() === 'cancelled') return
  if (!sub.cancel_at_period_end) {
    try {
      await cancelSubscription(subscriptionId, 'First payment refunded in full')
    } catch (err: any) {
      // 422: already cancelled at PayPal. Anything else means PayPal would keep billing.
      if (err?.status !== 422) throw err
    }
  }
  const nowIso = new Date().toISOString()
  await mustSucceed(
    db.from('billing_subscriptions').update(refundCancellationPatch(sub, nowIso)).eq('provider_subscription_id', subscriptionId),
    'refund cancellation',
  )
  await notify(db, userId, 'subscription', 'warning', 'Subscription cancelled after refund',
    `Your ${sub.plan} payment was refunded (${(refundCents / 100).toFixed(2)} ${currency}), so the subscription is cancelled and will not renew.`)
  await audit(db, userId, BILLING_AUDIT.cancelled, 'Subscription cancelled: first payment refunded in full', {
    providerSubscriptionId: subscriptionId,
    fromStatus: sub.status,
    toStatus: 'cancelled',
    plan: sub.plan,
    refundCents,
    source: 'paypal.refund',
  })
}

async function recordRefund(db: SupabaseClient, resource: any, eventType: string): Promise<void> {
  const saleId: string | null = resource?.sale_id || resource?.id || null
  if (!saleId) return
  const { data: invoice, error } = await db
    .from('billing_invoices')
    .select('id, user_id, amount_paid_cents, currency, subscription_plan, payment_date, metadata')
    .eq('provider_invoice_id', saleId)
    .maybeSingle()
  if (error) throw new Error(`refund invoice lookup failed: ${error.message}`)
  if (!invoice) {
    console.warn(`[paypal] ${eventType} for unknown sale ${saleId} — no invoice to refund`)
    return
  }
  const nowIso = new Date().toISOString()
  const refund = refundInvoicePatch(invoice, resource, eventType, nowIso)
  if (!refund.isNew) return
  // Cancel BEFORE marking the invoice refunded: a failure is retried by PayPal's redelivery.
  const subscriptionId = invoice.metadata?.subscriptionId
  if (isPaypalSubscriptionId(subscriptionId)) {
    const refundedCents = Number(refund.patch.metadata && (refund.patch.metadata as Record<string, unknown>).refundedCents) || 0
    const cancels = moneyBackRefundCancels({
      eventType,
      amountPaidCents: invoice.amount_paid_cents,
      refundedCents,
      paymentDate: invoice.payment_date,
      refundedAt: resource?.create_time || nowIso,
      isFirstPayment: refundedCents > 0 && await isFirstPayment(db, invoice, subscriptionId),
    })
    if (cancels) await cancelForRefund(db, subscriptionId, invoice.user_id, refundedCents, invoice.currency)
  }
  await mustSucceed(db.from('billing_invoices').update(refund.patch).eq('id', invoice.id), 'invoice refund')
  await notify(db, invoice.user_id, 'billing', 'warning', 'Payment refunded', `${(refund.refundCents / 100).toFixed(2)} ${invoice.currency} of a ${invoice.subscription_plan} payment was refunded.`)
  await audit(db, invoice.user_id, BILLING_AUDIT.paymentRefunded, `Refund recorded: ${(refund.refundCents / 100).toFixed(2)} ${invoice.currency}`, {
    saleId,
    refundId: refund.refundId,
    refundCents: refund.refundCents,
    reversal: eventType === 'PAYMENT.SALE.REVERSED',
    source: 'paypal.webhook',
  })
}

async function syncSubscriptionUpdate(db: SupabaseClient, resource: any): Promise<void> {
  const subId: string | null = resource?.id || null
  if (!subId) return

  const sub = await subscriptionByProviderId(db, subId)
  if (!sub) return // unknown subscription — nothing to sync (not a failure)

  const info = planInfoFromId(resource?.plan_id)
  const mapped = mapPaypalStatus(resource?.status)
  const nextBilling = resource?.billing_info?.next_billing_time || null

  const patch: Record<string, unknown> = { updated_at: new Date().toISOString() }
  if (info) {
    patch.plan = info.tier
    patch.billing_cycle = info.cycle === 'yearly' ? 'annual' : 'monthly'
  }
  if (mapped) patch.status = mapped
  if (nextBilling) {
    patch.renewal_date = nextBilling
    patch.current_period_end = nextBilling
  }

  await mustSucceed(
    db.from('billing_subscriptions').update(patch).eq('provider_subscription_id', subId),
    'subscription update sync',
  )

  const base = { providerSubscriptionId: subId, source: 'paypal.webhook' }
  const planAction = info ? planChangeAction(sub.plan, info.tier) : null
  if (info && planAction) {
    await mustSucceed(
      db.from('profiles').update({ tier: info.tier.toLowerCase(), updated_at: new Date().toISOString() }).eq('id', sub.user_id),
      'profile tier sync',
    )
    await notify(db, sub.user_id, 'subscription', 'success', 'Plan changed', `Your subscription is now ${info.tier}.`)
    await audit(db, sub.user_id, planAction, `Plan changed: ${sub.plan} → ${info.tier}`, { ...base, fromPlan: sub.plan, toPlan: info.tier })
  }
  const nextCycle = info ? (info.cycle === 'yearly' ? 'annual' : 'monthly') : null
  if (nextCycle && sub.billing_cycle && nextCycle !== sub.billing_cycle) {
    await audit(db, sub.user_id, BILLING_AUDIT.cycleChanged, `Billing cycle changed: ${sub.billing_cycle} → ${nextCycle}`, { ...base, fromCycle: sub.billing_cycle, toCycle: nextCycle })
  }
  if (mapped && mapped !== String(sub.status).toLowerCase()) {
    await audit(db, sub.user_id, BILLING_AUDIT.statusChanged, `Subscription status: ${sub.status} → ${mapped}`, { ...base, fromStatus: sub.status, toStatus: mapped })
  }
}

router.post('/webhook', async (req: Request, res: Response) => {
  // A verified event is CLAIMED first, handled, then marked processed. A failed
  // handler marks the claim failed and returns 5xx so PayPal redelivers it —
  // activation/records are never silently dropped, and never run twice at once.
  const verified = await verifyWebhook(req)
  if (!verified) {
    console.warn('[paypal] webhook not verified (is PAYPAL_WEBHOOK_ID set?) — ignoring side effects')
    return res.status(200).json({ received: true, verified: false })
  }

  const db = getServiceClient()
  if (!db) {
    // Transient/config problem — ask PayPal to retry rather than dropping it.
    return res.status(503).json({ received: false, error: 'service_client_unavailable' })
  }

  const event = req.body || {}
  const eventId = String(event.id || '')
  const type = String(event.event_type || '')
  const resource = event.resource || {}
  if (!eventId) return res.status(400).json({ received: false, error: 'missing_event_id' })

  let claim: 'run' | 'duplicate' | 'in-progress'
  try {
    claim = await claimWebhookEvent(db, eventId, type, resource, event)
  } catch (err) {
    console.error('[paypal] webhook ledger unavailable:', err)
    return res.status(503).json({ received: false, error: 'webhook_ledger_unavailable' })
  }
  if (claim === 'duplicate') return res.status(200).json({ received: true, duplicate: true })
  if (claim === 'in-progress') return res.status(409).json({ received: false, error: 'event_in_progress' })

  try {
    switch (type) {
      case 'BILLING.SUBSCRIPTION.ACTIVATED':
        await activateSubscription(db, resource)
        break
      case 'BILLING.SUBSCRIPTION.UPDATED':
        await syncSubscriptionUpdate(db, resource)
        break
      case 'PAYMENT.SALE.COMPLETED':
        await recordPayment(db, resource)
        break
      case 'PAYMENT.SALE.REFUNDED':
      case 'PAYMENT.SALE.REVERSED':
        await recordRefund(db, resource, type)
        break
      case 'BILLING.SUBSCRIPTION.PAYMENT.FAILED':
        await updateSubscriptionStatus(db, resource, 'past_due')
        break
      case 'BILLING.SUBSCRIPTION.CANCELLED':
        await updateSubscriptionStatus(db, resource, 'cancelled')
        break
      case 'BILLING.SUBSCRIPTION.SUSPENDED':
        await updateSubscriptionStatus(db, resource, 'suspended')
        break
      case 'BILLING.SUBSCRIPTION.EXPIRED':
        await updateSubscriptionStatus(db, resource, 'expired')
        break
      default:
        break
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    console.error(`[paypal] webhook handling failed for ${type} (${eventId}), asking PayPal to retry:`, message)
    await bestEffort(async () => {
      const { error } = await db.from('paypal_webhook_events').update({ status: 'failed', last_error: message.slice(0, 500) }).eq('event_id', eventId)
      if (error) throw new Error(error.message)
    })
    return res.status(500).json({ received: false, error: 'processing_failed' })
  }

  await bestEffort(async () => {
    const { error } = await db
      .from('paypal_webhook_events')
      .update({ status: 'processed', processed_at: new Date().toISOString(), last_error: null })
      .eq('event_id', eventId)
    if (error) throw new Error(error.message)
  })

  return res.status(200).json({ received: true, verified: true })
})

// ---- Reconciliation (drift repair for missed webhooks) ----

/**
 * Poll PayPal for every locally-known active-ish PayPal subscription and repair
 * any drift (status, plan, renewal date) versus our database. Idempotent and
 * safe to run on a schedule. Returns a summary for observability.
 */
export async function reconcilePaypalSubscriptions(limit = 500): Promise<{ checked: number; updated: number; errors: number }> {
  const db = getServiceClient()
  if (!db) throw new Error('Supabase service client is not configured')

  const { data, error } = await db
    .from('billing_subscriptions')
    .select('id, user_id, plan, status, provider_subscription_id, renewal_date')
    .eq('provider', 'paypal')
    .not('provider_subscription_id', 'is', null)
    .in('status', ['active', 'past_due', 'suspended', 'pending_renewal', 'incomplete'])
    .limit(limit)
  if (error) throw new Error(`reconcile query failed: ${error.message}`)

  let checked = 0
  let updated = 0
  let errors = 0

  for (const row of data || []) {
    checked += 1
    try {
      const remote = await getRemoteSubscription(row.provider_subscription_id)
      const mapped = mapPaypalStatus(remote?.status)
      const nextBilling = remote?.billing_info?.next_billing_time || null
      const info = planInfoFromId(remote?.plan_id)

      const patch: Record<string, unknown> = {}
      if (mapped && mapped !== row.status) patch.status = mapped
      if (nextBilling && nextBilling !== row.renewal_date) {
        patch.renewal_date = nextBilling
        patch.current_period_end = nextBilling
      }
      if (info && info.tier !== row.plan) {
        patch.plan = info.tier
        patch.billing_cycle = info.cycle === 'yearly' ? 'annual' : 'monthly'
      }

      if (Object.keys(patch).length > 0) {
        patch.updated_at = new Date().toISOString()
        const { error: upErr } = await db.from('billing_subscriptions').update(patch).eq('id', row.id)
        if (upErr) throw new Error(upErr.message)
        if (patch.plan) {
          await db
            .from('profiles')
            .update({ tier: String(patch.plan).toLowerCase(), updated_at: new Date().toISOString() })
            .eq('id', row.user_id)
        }
        updated += 1
      }
    } catch (err) {
      errors += 1
      console.error('[paypal] reconcile failed for', row.provider_subscription_id, err)
    }
  }

  return { checked, updated, errors }
}

function timingSafeEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  return ab.length === bb.length && timingSafeEqual(ab, bb)
}

/**
 * Secret-guarded reconciliation trigger for an external scheduler/cron.
 * Enable by setting PAYPAL_RECONCILE_SECRET; call with header
 * `X-Reconcile-Secret: <secret>` (or `Authorization: Bearer <secret>`).
 */
router.post('/reconcile', async (req: Request, res: Response) => {
  const secret = process.env.PAYPAL_RECONCILE_SECRET
  if (!secret) return jsonError(res, 503, 'RECONCILE_DISABLED', 'Reconciliation is disabled (set PAYPAL_RECONCILE_SECRET)')

  const headerSecret = req.headers['x-reconcile-secret']
  const bearer = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : ''
  const provided = typeof headerSecret === 'string' && headerSecret ? headerSecret : bearer
  if (!provided || !timingSafeEquals(provided, secret)) {
    return jsonError(res, 401, 'UNAUTHORIZED', 'Invalid reconcile secret')
  }

  try {
    const summary = await reconcilePaypalSubscriptions()
    return res.json({ data: summary })
  } catch (err: any) {
    console.error('[paypal] reconcile error:', err?.message || err)
    return jsonError(res, 500, 'RECONCILE_FAILED', err?.message || 'Reconciliation failed')
  }
})

export default router
