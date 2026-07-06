import { Router, Request, Response } from 'express'
import { timingSafeEqual } from 'node:crypto'
import type { SupabaseClient } from '@supabase/supabase-js'
import { getServerUser, getServiceClient } from '@/lib/supabase-server'

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

// Source of truth: src/pages/Landing.tsx PRICING_PLANS.
// Yearly plans bill the discounted monthly rate x 12, charged once per year.
export const PLAN_PRICING: Record<Tier, { monthly: number; yearlyPerMonth: number }> = {
  Starter: { monthly: 3, yearlyPerMonth: 3 },
  Basic: { monthly: 8, yearlyPerMonth: 5 },
  Pro: { monthly: 30, yearlyPerMonth: 20 },
  Elite: { monthly: 199, yearlyPerMonth: 150 },
}

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

async function alreadyProcessed(db: SupabaseClient, eventId: string): Promise<boolean> {
  if (!eventId) return false
  try {
    const { data } = await db.from('paypal_webhook_events').select('event_id').eq('event_id', eventId).maybeSingle()
    return Boolean(data)
  } catch {
    return false
  }
}

async function markProcessed(db: SupabaseClient, eventId: string, eventType: string, resourceId: string | null, userId: string | null, raw: unknown) {
  if (!eventId) return
  try {
    await db.from('paypal_webhook_events').insert({
      event_id: eventId,
      event_type: eventType,
      resource_id: resourceId,
      user_id: userId,
      raw,
    })
  } catch {
    // Table not installed or duplicate — safe to ignore.
  }
}

async function bestEffort(operation: () => any): Promise<void> {
  try {
    await operation()
  } catch (err) {
    console.error('[paypal] webhook side-effect failed:', err)
  }
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

async function activateSubscription(db: SupabaseClient, resource: any): Promise<void> {
  const userId = resource?.custom_id
  if (!isUuid(userId)) return
  const info = planInfoFromId(resource?.plan_id)
  if (!info) return

  const providerSubId: string | null = resource?.id || null
  const dbCycle: DbCycle = info.cycle === 'yearly' ? 'annual' : 'monthly'
  const nextBilling = resource?.billing_info?.next_billing_time || null
  const nowIso = new Date().toISOString()

  // Cancel a prior PayPal subscription that this one supersedes (plan change),
  // to avoid double-billing the customer.
  await bestEffort(async () => {
    const { data: existing } = await db
      .from('billing_subscriptions')
      .select('provider, provider_subscription_id')
      .eq('user_id', userId)
      .maybeSingle()
    const prior = existing?.provider_subscription_id
    if (existing?.provider === 'paypal' && prior && providerSubId && prior !== providerSubId) {
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

  await bestEffort(() =>
    db.from('billing_notifications').insert({
      user_id: userId,
      type: 'subscription',
      severity: 'success',
      title: 'Subscription activated',
      message: `Your ${info.tier} (${dbCycle}) subscription is now active via PayPal.`,
    }),
  )

  await bestEffort(() =>
    db.from('billing_audit_events').insert({
      user_id: userId,
      action: 'paypal.subscription.activated',
      message: `PayPal subscription activated: ${info.tier} ${dbCycle}`,
      metadata: { providerSubscriptionId: providerSubId, planId: resource?.plan_id || null },
    }),
  )
}

async function recordPayment(db: SupabaseClient, resource: any): Promise<void> {
  const subId: string | null = resource?.billing_agreement_id || null
  if (!subId) return

  const { data: sub } = await db
    .from('billing_subscriptions')
    .select('user_id, plan')
    .eq('provider_subscription_id', subId)
    .maybeSingle()
  if (!sub?.user_id) return

  const amount = resource?.amount || {}
  const gross = amount?.total ?? amount?.value ?? '0'
  const currency = amount?.currency ?? amount?.currency_code ?? 'USD'
  const paidCents = Math.round(Number(gross) * 100) || 0

  await mustSucceed(
    db.from('billing_invoices').upsert(
      {
        user_id: sub.user_id,
        invoice_id: resource?.id || `paypal_${Date.now()}`,
        provider_invoice_id: resource?.id || null,
        transaction_id: resource?.id || null,
        amount_paid_cents: paidCents,
        tax_cents: 0,
        currency: String(currency).toUpperCase(),
        status: 'paid',
        payment_method_summary: 'PayPal',
        subscription_plan: sub.plan,
        payment_date: resource?.create_time || new Date().toISOString(),
        metadata: { paypalSaleId: resource?.id || null, subscriptionId: subId },
      },
      { onConflict: 'provider_invoice_id' },
    ),
    'invoice recording',
  )

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

  const { data: sub } = await db
    .from('billing_subscriptions')
    .select('user_id, plan')
    .eq('provider_subscription_id', subId)
    .maybeSingle()

  const patch: Record<string, unknown> = { status, updated_at: nowIso }
  if (status === 'cancelled') {
    patch.auto_renew = false
    patch.cancel_at_period_end = true
    patch.cancelled_at = nowIso
  } else if (status === 'suspended' || status === 'expired') {
    patch.auto_renew = false
  }
  // past_due keeps auto_renew — PayPal continues its own dunning/retry cycle.

  await mustSucceed(
    db.from('billing_subscriptions').update(patch).eq('provider_subscription_id', subId),
    'subscription status update',
  )

  if (sub?.user_id) {
    await bestEffort(() =>
      db.from('billing_notifications').insert({
        user_id: sub.user_id,
        type: 'subscription',
        severity: status === 'cancelled' ? 'warning' : 'critical',
        title: `Subscription ${status.replace('_', ' ')}`,
        message: status === 'past_due'
          ? `A payment for your ${sub.plan} subscription failed. Please update your PayPal payment method to avoid interruption.`
          : `Your ${sub.plan} subscription is now ${status}.`,
      }),
    )
  }
}

async function recordRefund(db: SupabaseClient, resource: any): Promise<void> {
  const subId: string | null = resource?.billing_agreement_id || null
  const saleId: string | null = resource?.sale_id || resource?.id || null

  if (saleId) {
    await mustSucceed(
      db.from('billing_invoices').update({ status: 'refunded', updated_at: new Date().toISOString() }).eq('provider_invoice_id', saleId),
      'invoice refund',
    )
  }

  if (subId) {
    const { data: sub } = await db
      .from('billing_subscriptions')
      .select('user_id, plan')
      .eq('provider_subscription_id', subId)
      .maybeSingle()
    if (sub?.user_id) {
      await bestEffort(() =>
        db.from('billing_notifications').insert({
          user_id: sub.user_id,
          type: 'billing',
          severity: 'warning',
          title: 'Payment refunded',
          message: `A payment for your ${sub.plan} subscription was refunded.`,
        }),
      )
    }
  }
}

async function syncSubscriptionUpdate(db: SupabaseClient, resource: any): Promise<void> {
  const subId: string | null = resource?.id || null
  if (!subId) return

  const { data: sub } = await db
    .from('billing_subscriptions')
    .select('user_id, plan')
    .eq('provider_subscription_id', subId)
    .maybeSingle()
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

  if (info && sub.user_id && info.tier !== sub.plan) {
    await mustSucceed(
      db.from('profiles').update({ tier: info.tier.toLowerCase(), updated_at: new Date().toISOString() }).eq('id', sub.user_id),
      'profile tier sync',
    )
  }
}

router.post('/webhook', async (req: Request, res: Response) => {
  // A verified event whose side-effects FAIL returns 5xx (below) so PayPal
  // redelivers it — activation/records are never silently dropped. The event is
  // marked processed only after successful handling, so a retry re-runs it.
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

  if (await alreadyProcessed(db, eventId)) {
    return res.status(200).json({ received: true, duplicate: true })
  }

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
        await recordRefund(db, resource)
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
    // A critical write failed — do NOT mark processed; return 5xx so PayPal
    // redelivers and we get another chance to persist it.
    console.error(`[paypal] webhook handling failed for ${type} (${eventId}), asking PayPal to retry:`, err)
    return res.status(500).json({ received: false, error: 'processing_failed' })
  }

  const resourceId = resource?.id || resource?.billing_agreement_id || null
  const userId = isUuid(resource?.custom_id) ? resource.custom_id : null
  await markProcessed(db, eventId, type, resourceId, userId, event)

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
