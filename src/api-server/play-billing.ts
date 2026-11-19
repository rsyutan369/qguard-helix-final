import { Router, Request, Response } from 'express'
import { getServerUser, getServiceClient, getToken } from '@/lib/supabase-server'
import { BillingHttpError, verifyPurchase } from '../../supabase/functions/billing/play-service'
import { isPlayConfigured, playPackageName, playProductCatalog } from '../../supabase/functions/billing/logic'
import { rtdnHandler } from './subscriptions'

/**
 * Legacy Google Play paths (/api/v1/play-billing/*), kept so builds released
 * before 2026-11-12 keep working. They are thin aliases: verification and RTDN
 * run the shared service (supabase/functions/billing/play-service.ts) exactly
 * like /api/v1/subscriptions/verify and /api/v1/webhooks/google-play/rtdn.
 */

const env = (key: string) => process.env[key]
const router = Router()

/** Non-sensitive readiness probe: which products the client should offer. */
router.get('/config', (_req: Request, res: Response) => {
  return res.json({
    data: {
      configured: isPlayConfigured(env),
      packageName: playPackageName(env) || null,
      products: playProductCatalog(env),
    },
  })
})

router.post('/verify', async (req: Request, res: Response) => {
  const token = getToken(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Sign in to verify a purchase' } })
  const user = await getServerUser(token).catch(() => null)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Your session has expired — sign in again' } })
  const db = getServiceClient()
  if (!db) return res.status(503).json({ error: { code: 'SERVICE_UNAVAILABLE', message: 'Billing storage is not configured' } })
  try {
    return res.json({ data: await verifyPurchase({ env, db }, user.id, req.body?.purchaseToken) })
  } catch (error) {
    if (error instanceof BillingHttpError) return res.status(error.status).json({ error: { code: error.code, message: error.message } })
    console.error('[play-billing] verify', error instanceof Error ? error.message : error)
    return res.status(500).json({ error: { code: 'BILLING_ERROR', message: 'The billing service could not complete the request' } })
  }
})

router.post('/rtdn', rtdnHandler)

export default router
