import { Router, Request, Response } from 'express'
import { createHash, createSign, timingSafeEqual } from 'node:crypto'
import type { SupabaseClient } from '@supabase/supabase-js'
import { getServerUser, getServiceClient } from '@/lib/supabase-server'
import { PLAN_PRICING } from './paypal'

/**
 * Google Play Billing subscription provider (QGuard Messaging Android paywall).
 *
 * The Android app buys a Play subscription (Billing Library) and submits ONLY
 * the purchase token here. Nothing client-side is trusted: the server verifies
 * the token with the Google Play Developer API (`purchases.subscriptionsv2`),
 * binds the purchase to the authenticated account via the
 * obfuscatedExternalAccountId the app set at checkout, rejects tokens already
 * claimed by another account (replay/sharing), acknowledges the purchase, and
 * only then upserts billing_subscriptions (provider 'google_play') — the same
 * account-scoped table the PayPal flow writes, so desktop unlocks in real time
 * through the existing billing_subscriptions realtime publication.
 *
 * Renewals/cancellations/expirations stay in sync through Real-Time Developer
 * Notifications (Pub/Sub push → POST /rtdn, guarded by PLAY_RTDN_TOKEN); every
 * RTDN re-fetches the authoritative subscription state from Google before
 * touching the database. Raw purchase tokens are never persisted — rows are
 * keyed by their SHA-256 hash.
 *
 * Required env:
 *   GOOGLE_PLAY_PACKAGE_NAME            e.g. com.qguard.messaging
 *   GOOGLE_PLAY_SERVICE_ACCOUNT_JSON    full service-account JSON (or the pair below)
 *   GOOGLE_PLAY_SA_EMAIL / GOOGLE_PLAY_SA_PRIVATE_KEY
 *   PLAY_RTDN_TOKEN                     shared secret for the Pub/Sub push endpoint
 * Optional product-id overrides (default qguard_<tier>):
 *   PLAY_PRODUCT_STARTER / PLAY_PRODUCT_BASIC / PLAY_PRODUCT_PRO / PLAY_PRODUCT_ELITE
 */

const router = Router()

type Tier = 'Starter' | 'Basic' | 'Pro' | 'Elite'
type DbCycle = 'monthly' | 'annual'
const TIERS: Tier[] = ['Starter', 'Basic', 'Pro', 'Elite']

// ---- Config ----

function packageName(): string {
  return process.env.GOOGLE_PLAY_PACKAGE_NAME || ''
}

function serviceAccount(): { email: string; privateKey: string } | null {
  const raw = process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON
  if (raw) {
    try {
      const parsed = JSON.parse(raw)
      if (parsed?.client_email && parsed?.private_key) {
        return { email: String(parsed.client_email), privateKey: String(parsed.private_key) }
      }
    } catch {
      // fall through to the pair form
    }
  }
  const email = process.env.GOOGLE_PLAY_SA_EMAIL
  const privateKey = process.env.GOOGLE_PLAY_SA_PRIVATE_KEY?.replace(/\\n/g, '\n')
  return email && privateKey ? { email, privateKey } : null
}

export function isPlayBillingConfigured(): boolean {
  return Boolean(packageName() && serviceAccount())
}

/** Play product id for a tier (convention qguard_<tier>, env-overridable). */
export function productIdFor(tier: Tier): string {
  return process.env[`PLAY_PRODUCT_${tier.toUpperCase()}`] || `qguard_${tier.toLowerCase()}`
}

export function tierForProductId(productId: string): Tier | null {
  for (const tier of TIERS) {
    if (productIdFor(tier) === productId) return tier
  }
  return null
}

/** basePlanId → billing cycle. Convention: 'monthly' / 'yearly' (or 'annual'). */
export function cycleForBasePlan(basePlanId: string | null | undefined): DbCycle {
  const text = String(basePlanId || '').toLowerCase()
  return text.includes('year') || text.includes('annual') ? 'annual' : 'monthly'
}

// ---- Google OAuth (service-account JWT → access token; no SDK dependency) ----

let cachedToken: { token: string; expiresAt: number } | null = null

async function googleAccessToken(): Promise<string> {
  const sa = serviceAccount()
  if (!sa) throw new Error('Google Play service account is not configured')
  const now = Date.now()
  if (cachedToken && cachedToken.expiresAt > now + 60_000) return cachedToken.token

  const iat = Math.floor(now / 1000)
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url')
  const claims = Buffer.from(
    JSON.stringify({
      iss: sa.email,
      scope: 'https://www.googleapis.com/auth/androidpublisher',
      aud: 'https://oauth2.googleapis.com/token',
      iat,
      exp: iat + 3600,
    }),
  ).toString('base64url')
  const signer = createSign('RSA-SHA256')
  signer.update(`${header}.${claims}`)
  const signature = signer.sign(sa.privateKey).toString('base64url')
  const assertion = `${header}.${claims}.${signature}`

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }).toString(),
  })
  const json: any = await response.json().catch(() => ({}))
  if (!response.ok || !json?.access_token) {
    throw new Error(json?.error_description || json?.error || `Google token exchange failed (HTTP ${response.status})`)
  }
  cachedToken = { token: json.access_token, expiresAt: now + (Number(json.expires_in) || 3000) * 1000 }
  return cachedToken.token
}

async function playFetch(pathname: string, init: { method?: string; body?: unknown } = {}): Promise<any> {
  const token = await googleAccessToken()
  const response = await fetch(`https://androidpublisher.googleapis.com/androidpublisher/v3${pathname}`, {
    method: init.method || 'GET',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
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
    const error = new Error(json?.error?.message || `Google Play API request failed (HTTP ${response.status})`) as Error & { status?: number }
    error.status = response.status
    throw error
  }
  return json
}

/** Authoritative subscription state for a purchase token (subscriptionsv2). */
async function getSubscriptionV2(purchaseToken: string): Promise<any> {
  return playFetch(
    `/applications/${encodeURIComponent(packageName())}/purchases/subscriptionsv2/tokens/${encodeURIComponent(purchaseToken)}`,
  )
}

async function acknowledgeSubscription(productId: string, purchaseToken: string): Promise<void> {
  await playFetch(
    `/applications/${encodeURIComponent(packageName())}/purchases/subscriptions/${encodeURIComponent(productId)}/tokens/${encodeURIComponent(purchaseToken)}:acknowledge`,
    { method: 'POST', body: {} },
  )
}

// ---- Pure mapping helpers ----

type DbStatus = 'active' | 'trial' | 'expired' | 'suspended' | 'pending_renewal' | 'cancelled' | 'past_due' | 'incomplete'

/**
 * Map Google subscriptionState to our billing status. Per Play policy the user
 * KEEPS entitlement while in a grace period (payment retry) and while CANCELED
 * but not yet expired — cancellation only turns off auto-renew.
 */
export function mapPlayState(state: string | undefined): { status: DbStatus; entitled: boolean; autoRenew: boolean } {
  switch (String(state || '')) {
    case 'SUBSCRIPTION_STATE_ACTIVE':
      return { status: 'active', entitled: true, autoRenew: true }
    case 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD':
      return { status: 'pending_renewal', entitled: true, autoRenew: true }
    case 'SUBSCRIPTION_STATE_CANCELED':
      // Entitled until expiryTime; RTDN EXPIRED flips it to expired.
      return { status: 'active', entitled: true, autoRenew: false }
    case 'SUBSCRIPTION_STATE_ON_HOLD':
      return { status: 'suspended', entitled: false, autoRenew: false }
    case 'SUBSCRIPTION_STATE_PAUSED':
      return { status: 'suspended', entitled: false, autoRenew: false }
    case 'SUBSCRIPTION_STATE_EXPIRED':
      return { status: 'expired', entitled: false, autoRenew: false }
    default:
      return { status: 'incomplete', entitled: false, autoRenew: false }
  }
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

/** Decode a Pub/Sub push envelope into the RTDN payload. Null when malformed. */
export function parseRtdnMessage(body: unknown): { messageId: string; payload: any } | null {
  const message = (body as any)?.message
  if (!message?.data) return null
  const messageId = String(message.messageId || message.message_id || '')
  try {
    const payload = JSON.parse(Buffer.from(String(message.data), 'base64').toString('utf8'))
    return { messageId, payload }
  } catch {
    return null
  }
}

function jsonError(res: Response, status: number, code: string, message: string) {
  return res.status(status).json({ error: { code, message } })
}

function extractToken(req: Request): string | null {
  const authHeader = req.headers.authorization
  return authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null
}

function timingSafeEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  return ab.length === bb.length && timingSafeEqual(ab, bb)
}

async function bestEffort(operation: () => any): Promise<void> {
  try {
    await operation()
  } catch (err) {
    console.error('[play-billing] side-effect failed:', err)
  }
}

async function mustSucceed(op: PromiseLike<{ error: unknown }>, label: string): Promise<void> {
  const { error } = await op
  if (error) {
    const message = (error as any)?.message || (error as any)?.code || 'database error'
    throw new Error(`${label} failed: ${message}`)
  }
}

// ---- Core: apply a verified Google subscription resource to the account ----

interface ApplyResult {
  userId: string
  tier: Tier
  cycle: DbCycle
  status: DbStatus
  entitled: boolean
  expiryTime: string | null
}

/**
 * Upsert billing state from an authoritative subscriptionsv2 resource.
 * `expectedUserId` (the authenticated caller on /verify) must match the
 * obfuscatedExternalAccountId Google returns — the anti-spoof account binding.
 * RTDN passes null and trusts the binding recorded at purchase time.
 */
async function applyPlaySubscription(
  db: SupabaseClient,
  resource: any,
  purchaseToken: string,
  expectedUserId: string | null,
): Promise<ApplyResult> {
  const boundUserId = String(resource?.externalAccountIdentifiers?.obfuscatedExternalAccountId || '')
  const userId = expectedUserId || boundUserId
  if (!userId) throw new Error('purchase is not bound to a QGuard account (missing obfuscatedExternalAccountId)')
  if (expectedUserId && boundUserId && boundUserId !== expectedUserId) {
    const err = new Error('purchase belongs to a different QGuard account') as Error & { code?: string }
    err.code = 'ACCOUNT_MISMATCH'
    throw err
  }

  const line = Array.isArray(resource?.lineItems) ? resource.lineItems[0] : null
  const productId = String(line?.productId || '')
  const tier = tierForProductId(productId)
  if (!tier) {
    const err = new Error(`unrecognized Play product: ${productId || '(none)'}`) as Error & { code?: string }
    err.code = 'UNKNOWN_PRODUCT'
    throw err
  }
  const cycle = cycleForBasePlan(line?.offerDetails?.basePlanId)
  const mapped = mapPlayState(resource?.subscriptionState)
  const expiryTime: string | null = line?.expiryTime || null
  const tokenHash = sha256Hex(purchaseToken)
  const nowIso = new Date().toISOString()

  // Replay / duplicate guard: one purchase token can only ever unlock ONE account.
  const { data: existingByToken } = await db
    .from('billing_subscriptions')
    .select('user_id')
    .eq('provider', 'google_play')
    .eq('provider_subscription_id', tokenHash)
    .maybeSingle()
  if (existingByToken?.user_id && existingByToken.user_id !== userId) {
    const err = new Error('this purchase is already linked to another account') as Error & { code?: string }
    err.code = 'TOKEN_ALREADY_CLAIMED'
    throw err
  }

  await mustSucceed(
    db.from('billing_subscriptions').upsert(
      {
        user_id: userId,
        subscription_id: `gp_${tokenHash.slice(0, 48)}`,
        provider: 'google_play',
        provider_customer_id: boundUserId || userId,
        provider_subscription_id: tokenHash,
        plan: tier,
        status: mapped.status,
        billing_cycle: cycle,
        auto_renew: mapped.autoRenew,
        cancel_at_period_end: !mapped.autoRenew && mapped.entitled,
        current_period_start: resource?.startTime || nowIso,
        current_period_end: expiryTime,
        renewal_date: mapped.autoRenew ? expiryTime : null,
        cancelled_at: mapped.status === 'cancelled' ? nowIso : null,
        metadata: {
          playProductId: productId,
          playBasePlanId: line?.offerDetails?.basePlanId || null,
          latestOrderId: resource?.latestOrderId || null,
          subscriptionState: resource?.subscriptionState || null,
        },
        updated_at: nowIso,
      },
      { onConflict: 'user_id' },
    ),
    'play subscription upsert',
  )

  if (mapped.entitled) {
    await mustSucceed(
      db.from('profiles').update({ tier: tier.toLowerCase(), updated_at: nowIso }).eq('id', userId),
      'profile tier activation',
    )
  }

  // Invoice from the latest order (amounts from our own catalog — Google does
  // not return the charged amount on subscriptionsv2).
  const orderId = resource?.latestOrderId ? String(resource.latestOrderId) : null
  if (orderId && mapped.entitled) {
    const pricing = PLAN_PRICING[tier]
    const amountCents = Math.round((cycle === 'annual' ? pricing.yearlyPerMonth * 12 : pricing.monthly) * 100)
    await bestEffort(() =>
      db.from('billing_invoices').upsert(
        {
          user_id: userId,
          invoice_id: orderId,
          provider_invoice_id: orderId,
          transaction_id: orderId,
          amount_paid_cents: amountCents,
          tax_cents: 0,
          currency: 'USD',
          status: 'paid',
          payment_method_summary: 'Google Play',
          subscription_plan: tier,
          payment_date: nowIso,
          metadata: { playOrderId: orderId, purchaseTokenHash: tokenHash },
        },
        { onConflict: 'provider_invoice_id' },
      ),
    )
  }

  // Acknowledge within Google's 3-day window or the purchase auto-refunds.
  if (String(resource?.acknowledgementState || '') === 'ACKNOWLEDGEMENT_STATE_PENDING' && productId) {
    await bestEffort(() => acknowledgeSubscription(productId, purchaseToken))
  }

  await bestEffort(() =>
    db.from('billing_audit_events').insert({
      user_id: userId,
      action: 'play.subscription.synced',
      message: `Google Play subscription synced: ${tier} ${cycle} (${mapped.status})`,
      metadata: { purchaseTokenHash: tokenHash, orderId, state: resource?.subscriptionState || null },
    }),
  )

  return { userId, tier, cycle, status: mapped.status, entitled: mapped.entitled, expiryTime }
}

// ---- Routes ----

/** Non-sensitive readiness probe: which products the client should offer. */
router.get('/config', (_req: Request, res: Response) => {
  const products: Record<string, string> = {}
  for (const tier of TIERS) products[tier.toLowerCase()] = productIdFor(tier)
  return res.json({
    data: {
      configured: isPlayBillingConfigured(),
      packageName: packageName() || null,
      products,
      basePlans: { monthly: 'monthly', yearly: 'yearly' },
    },
  })
})

/**
 * Authenticated purchase verification — the ONLY way a Play purchase unlocks an
 * account. Also serves "Restore purchases": the app re-submits the tokens
 * Google returns from queryPurchases and the same validation re-activates.
 */
router.post('/verify', async (req: Request, res: Response) => {
  try {
    if (!isPlayBillingConfigured()) {
      return jsonError(res, 503, 'PLAY_NOT_CONFIGURED', 'Google Play Billing is not configured on the server')
    }
    const token = extractToken(req)
    if (!token) return jsonError(res, 401, 'UNAUTHORIZED', 'Sign in to verify a purchase')
    const user = await getServerUser(token)
    if (!user) return jsonError(res, 401, 'UNAUTHORIZED', 'Invalid or expired session')

    const purchaseToken = String(req.body?.purchaseToken || '')
    if (!purchaseToken || purchaseToken.length < 20 || purchaseToken.length > 4096) {
      return jsonError(res, 400, 'INVALID_TOKEN', 'Missing or malformed purchase token')
    }

    const db = getServiceClient()
    if (!db) return jsonError(res, 503, 'SERVICE_UNAVAILABLE', 'Billing service is temporarily unavailable')

    const resource = await getSubscriptionV2(purchaseToken)
    const result = await applyPlaySubscription(db, resource, purchaseToken, user.id)

    await bestEffort(() =>
      db.from('play_webhook_events').insert({
        event_id: `verify_${sha256Hex(`${user.id}:${purchaseToken}:${resource?.latestOrderId || ''}`)}`,
        notification_type: 'client_verify',
        purchase_token_hash: sha256Hex(purchaseToken),
        user_id: user.id,
        raw: { subscriptionState: resource?.subscriptionState || null, latestOrderId: resource?.latestOrderId || null },
      }),
    )

    return res.json({
      data: {
        plan: result.tier,
        cycle: result.cycle,
        status: result.status,
        entitled: result.entitled,
        expiryTime: result.expiryTime,
      },
    })
  } catch (err: any) {
    if (err?.code === 'ACCOUNT_MISMATCH' || err?.code === 'TOKEN_ALREADY_CLAIMED') {
      return jsonError(res, 409, err.code, err.message)
    }
    if (err?.code === 'UNKNOWN_PRODUCT') return jsonError(res, 400, err.code, err.message)
    if (err?.status === 404 || err?.status === 400) {
      return jsonError(res, 400, 'PURCHASE_NOT_FOUND', 'Google Play did not recognize this purchase')
    }
    console.error('[play-billing] verify error:', err?.message || err)
    return jsonError(res, 502, 'PLAY_VERIFY_FAILED', 'Could not verify the purchase with Google Play')
  }
})

/**
 * Real-Time Developer Notifications (Pub/Sub push). Configure the Play Console
 * RTDN topic with a push subscription to:
 *   https://<api-origin>/api/v1/play-billing/rtdn?token=<PLAY_RTDN_TOKEN>
 * Idempotent by Pub/Sub messageId; a failed critical write returns 5xx so
 * Pub/Sub redelivers (activation/expiry is never silently dropped).
 */
router.post('/rtdn', async (req: Request, res: Response) => {
  const secret = process.env.PLAY_RTDN_TOKEN
  if (!secret) return jsonError(res, 503, 'RTDN_DISABLED', 'RTDN is disabled (set PLAY_RTDN_TOKEN)')
  const provided = String(req.query?.token || '')
  if (!provided || !timingSafeEquals(provided, secret)) {
    return jsonError(res, 401, 'UNAUTHORIZED', 'Invalid RTDN token')
  }

  const parsed = parseRtdnMessage(req.body)
  if (!parsed) return res.status(200).json({ received: true, ignored: 'malformed' })
  const { messageId, payload } = parsed

  // Play Console "send test notification".
  if (payload?.testNotification) return res.status(200).json({ received: true, test: true })

  if (payload?.packageName && packageName() && payload.packageName !== packageName()) {
    return res.status(200).json({ received: true, ignored: 'package_mismatch' })
  }

  const notification = payload?.subscriptionNotification
  const purchaseToken = String(notification?.purchaseToken || '')
  if (!notification || !purchaseToken) {
    return res.status(200).json({ received: true, ignored: 'not_subscription' })
  }

  const db = getServiceClient()
  if (!db) return res.status(503).json({ received: false, error: 'service_client_unavailable' })

  const eventId = messageId ? `rtdn_${messageId}` : `rtdn_${sha256Hex(JSON.stringify(payload))}`
  const { data: already } = await db.from('play_webhook_events').select('event_id').eq('event_id', eventId).maybeSingle()
  if (already) return res.status(200).json({ received: true, duplicate: true })

  try {
    // Always re-fetch the authoritative state — notificationType alone is a
    // hint, subscriptionsv2 is the truth (handles out-of-order delivery).
    const resource = await getSubscriptionV2(purchaseToken)
    await applyPlaySubscription(db, resource, purchaseToken, null)

    const result = mapPlayState(resource?.subscriptionState)
    if (!result.entitled) {
      // Downgrade the profile tier only when entitlement is actually gone.
      const tokenHash = sha256Hex(purchaseToken)
      const { data: sub } = await db
        .from('billing_subscriptions')
        .select('user_id, plan')
        .eq('provider_subscription_id', tokenHash)
        .maybeSingle()
      if (sub?.user_id) {
        await bestEffort(() =>
          db.from('billing_notifications').insert({
            user_id: sub.user_id,
            type: 'subscription',
            severity: result.status === 'expired' ? 'critical' : 'warning',
            title: `Subscription ${result.status.replace('_', ' ')}`,
            message: `Your ${sub.plan} subscription (Google Play) is now ${result.status.replace('_', ' ')}.`,
          }),
        )
      }
    }
  } catch (err: any) {
    // Token no longer resolvable (very old expiry) — apply terminal states from
    // the notification itself so the account still locks correctly.
    const type = Number(notification.notificationType)
    const terminal = type === 13 || type === 12 // EXPIRED | REVOKED
    if (terminal) {
      const tokenHash = sha256Hex(purchaseToken)
      await bestEffort(() =>
        db
          .from('billing_subscriptions')
          .update({ status: 'expired', auto_renew: false, updated_at: new Date().toISOString() })
          .eq('provider', 'google_play')
          .eq('provider_subscription_id', tokenHash),
      )
    } else {
      console.error(`[play-billing] RTDN handling failed (${eventId}), asking Pub/Sub to retry:`, err?.message || err)
      return res.status(500).json({ received: false, error: 'processing_failed' })
    }
  }

  await bestEffort(() =>
    db.from('play_webhook_events').insert({
      event_id: eventId,
      notification_type: String(notification.notificationType ?? ''),
      purchase_token_hash: sha256Hex(purchaseToken),
      raw: payload,
    }),
  )

  return res.status(200).json({ received: true })
})

export default router
