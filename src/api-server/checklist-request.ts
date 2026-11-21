import { Router } from 'express'
import { DEMO_EMAIL_PATTERN } from '@/lib/demo-request'
import { invalidChecklistEmail } from '@/lib/checklist-request'
import { readClientIp } from './runtime/client-ip'
import { recordWebsiteSubmission } from './website-submissions'

export function createChecklistRequestRouter(record = recordWebsiteSubmission) {
  const router = Router()
  const clients = new Map<string, number>()
  const windowMs = 10 * 60_000
  let windowStart = 0
  let count = 0

  router.post('/', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store')
    const body = req.body ?? {}
    if (typeof body.website === 'string' && body.website.trim()) {
      return res.status(400).json({ error: { message: 'The checklist request could not be verified.' } })
    }

    const read = (key: string, limit: number) => {
      const value = typeof body[key] === 'string' ? body[key].trim() : ''
      return value.length <= limit && !/[\u0000-\u001f\u007f]/.test(value) ? value : ''
    }
    const firstName = read('firstName', 100)
    const lastName = read('lastName', 100)
    const email = read('workEmail', 254).toLowerCase()
    const company = read('company', 160)
    const title = read('title', 160)
    const country = read('country', 100)

    if (!firstName || !lastName || !DEMO_EMAIL_PATTERN.test(email) || invalidChecklistEmail(email) ||
        !company || !title || !country || body.consent !== true) {
      return res.status(400).json({ error: { message: 'Enter valid business details and consent before downloading.' } })
    }

    const now = Date.now()
    if (now - windowStart >= windowMs) {
      windowStart = now
      count = 0
      clients.clear()
    }
    const ip = readClientIp(req)
    const attempts = clients.get(ip) ?? 0
    if (attempts >= 10 || count >= 300) {
      res.setHeader('Retry-After', String(Math.ceil((windowStart + windowMs - now) / 1000)))
      return res.status(429).json({ error: { message: 'Too many checklist requests. Please try again shortly.' } })
    }
    count++
    clients.set(ip, attempts + 1)

    try {
      await record({
        kind: 'pqc-checklist', source: 'checklist', name: `${firstName} ${lastName}`,
        email, organization: company, details: { title, country, communicationsConsent: true },
        email_status: 'not_applicable',
      })
      return res.status(201).json({ ok: true })
    } catch {
      console.warn('[checklist-request] submission storage unavailable')
      return res.status(503).json({ error: { message: 'Could not record your checklist request. Please try again.' } })
    }
  })
  return router
}

export default createChecklistRequestRouter()
