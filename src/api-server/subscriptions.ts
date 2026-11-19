import { Router, Request, Response, NextFunction } from 'express'
import type { SupabaseClient, User } from '@supabase/supabase-js'
import { getServerUser, getServiceClient, getToken } from '@/lib/supabase-server'
import { cancelSubscription as cancelPaypalSubscription, isPaypalConfigured } from './paypal'
import {
  BillingHttpError,
  effectiveEntitlements,
  ensurePlayAccount,
  handleRtdn,
  platformParam,
  reconcilePlay,
  restorePurchases,
  type ServiceDeps,
  subscriptionCatalog,
  subscriptionHistory,
  subscriptionSummary,
  verifyPurchase,
} from '../../supabase/functions/billing/play-service'
import { timingSafeEqualText } from '../../supabase/functions/billing/logic'

/**
 * Subscription API (Express) — Google Play purchase verification, restore,
 * RTDN lifecycle and the account-facing subscription reads.
 *
 * Mounted at /api/v1/subscriptions and /api/v1/webhooks/google-play. Every
 * rule lives in supabase/functions/billing/play-service.ts, which the billing
 * Edge Function runs too, so a self-hosted Express deployment and the Edge
 * deployment verify purchases and compute entitlements identically.
 *
 *   GET  /api/v1/subscriptions/catalog          public: plans, products, tier entitlements
 *   GET  /api/v1/subscriptions/me               auth: verified subscription + playAccountId
 *   GET  /api/v1/subscriptions/entitlements     auth: effective entitlement keys
 *   GET  /api/v1/subscriptions/history          auth: invoices + lifecycle events
 *   POST /api/v1/subscriptions/verify           auth: verify a Google Play purchase token
 *   POST /api/v1/subscriptions/restore          auth: re-verify the device's Play purchases
 *   POST /api/v1/subscriptions/reconcile        scheduler: X-Reconcile-Secret
 *   POST /api/v1/webhooks/google-play/rtdn      Pub/Sub push (OIDC and/or shared secret) — no user JWT
 *
 * Identity always comes from the verified Supabase JWT, never from the body.
 */

interface AuthedRequest extends Request {
  billingUser?: User
}

function serviceDeps(db: SupabaseClient): ServiceDeps {
  return {
    env: (key: string) => process.env[key],
    db,
    cancelPaypalSubscription: async (subscriptionId: string, reason: string) => {
      if (!isPaypalConfigured()) return
      await cancelPaypalSubscription(subscriptionId, reason)
    },
  }
}

function sendError(res: Response, error: unknown) {
  if (error instanceof BillingHttpError) {
    return res.status(error.status).json({ error: { code: error.code, message: error.message } })
  }
  console.error('[subscriptions]', error instanceof Error ? error.message : error)
  return res.status(500).json({ error: { code: 'BILLING_ERROR', message: 'The billing service could not complete the request' } })
}

function requireDb(res: Response): SupabaseClient | null {
  const db = getServiceClient()
  if (!db) {
    res.status(503).json({ error: { code: 'SERVICE_UNAVAILABLE', message: 'Billing storage is not configured' } })
    return null
  }
  return db
}

async function requireUser(req: AuthedRequest, res: Response, next: NextFunction) {
  const token = getToken(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Sign in to manage your subscription' } })
  const user = await getServerUser(token).catch(() => null)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Your session has expired — sign in again' } })
  req.billingUser = user
  return next()
}

export const subscriptionRoutes = Router()

subscriptionRoutes.get('/catalog', async (req: Request, res: Response) => {
  const db = requireDb(res)
  if (!db) return
  try {
    res.set('Cache-Control', 'public, max-age=300')
    return res.json({ data: await subscriptionCatalog(serviceDeps(db), platformParam(String(req.query.platform ?? ''))) })
  } catch (error) {
    return sendError(res, error)
  }
})

subscriptionRoutes.get('/me', requireUser, async (req: AuthedRequest, res: Response) => {
  const db = requireDb(res)
  if (!db) return
  try {
    const userId = req.billingUser!.id
    const summary = await subscriptionSummary(serviceDeps(db), userId)
    const playAccountId = await ensurePlayAccount(db, userId)
    res.set('Cache-Control', 'no-store')
    return res.json({ data: { ...summary, playAccountId } })
  } catch (error) {
    return sendError(res, error)
  }
})

subscriptionRoutes.get('/entitlements', requireUser, async (req: AuthedRequest, res: Response) => {
  const db = requireDb(res)
  if (!db) return
  try {
    res.set('Cache-Control', 'no-store')
    return res.json({ data: await effectiveEntitlements(serviceDeps(db), req.billingUser!.id) })
  } catch (error) {
    return sendError(res, error)
  }
})

subscriptionRoutes.get('/history', requireUser, async (req: AuthedRequest, res: Response) => {
  const db = requireDb(res)
  if (!db) return
  try {
    res.set('Cache-Control', 'no-store')
    return res.json({ data: await subscriptionHistory(serviceDeps(db), req.billingUser!.id) })
  } catch (error) {
    return sendError(res, error)
  }
})

subscriptionRoutes.post('/verify', requireUser, async (req: AuthedRequest, res: Response) => {
  const db = requireDb(res)
  if (!db) return
  try {
    return res.json({ data: await verifyPurchase(serviceDeps(db), req.billingUser!.id, req.body?.purchaseToken) })
  } catch (error) {
    return sendError(res, error)
  }
})

subscriptionRoutes.post('/restore', requireUser, async (req: AuthedRequest, res: Response) => {
  const db = requireDb(res)
  if (!db) return
  try {
    return res.json({ data: await restorePurchases(serviceDeps(db), req.billingUser!.id, req.body?.purchaseTokens) })
  } catch (error) {
    return sendError(res, error)
  }
})

/** Scheduler-only Play reconciliation (same secret as the PayPal sweep). */
subscriptionRoutes.post('/reconcile', async (req: Request, res: Response) => {
  const secret = (process.env.PAYPAL_RECONCILE_SECRET || '').trim()
  if (!secret) return res.status(503).json({ error: { code: 'RECONCILE_DISABLED', message: 'Set PAYPAL_RECONCILE_SECRET' } })
  const provided = String(req.headers['x-reconcile-secret'] || '')
  if (!provided || !timingSafeEqualText(provided, secret)) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid reconcile secret' } })
  const db = requireDb(res)
  if (!db) return
  try {
    return res.json({ data: await reconcilePlay(serviceDeps(db)) })
  } catch (error) {
    return sendError(res, error)
  }
})

/** Express adapter for the shared RTDN handler (used by both mount points). */
export async function rtdnHandler(req: Request, res: Response) {
  const db = requireDb(res)
  if (!db) return
  try {
    const url = `${req.protocol}://${req.get('host') || 'localhost'}${req.originalUrl}`
    const result = await handleRtdn(serviceDeps(db), { url, authorization: req.get('authorization') ?? null, body: req.body })
    return res.status(result.status).json(result.body)
  } catch (error) {
    // An unexpected failure must make Pub/Sub redeliver, never drop the event.
    console.error('[subscriptions] rtdn', error instanceof Error ? error.message : error)
    return res.status(500).json({ received: false, error: 'processing_failed' })
  }
}

export const googlePlayWebhookRoutes = Router()
googlePlayWebhookRoutes.post('/rtdn', rtdnHandler)

export default subscriptionRoutes
