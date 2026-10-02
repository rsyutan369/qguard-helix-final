import { Router, Request, Response } from 'express'
import { getServiceClient } from '@/lib/supabase-server'
import { isOwnerEmail } from '@/lib/admin-access'
import { trustedClientIp } from './runtime/client-ip'

/**
 * Public registration endpoint.
 *
 * Client-side `supabase.auth.signUp` sends a confirmation email through
 * Supabase's BUILT-IN mailer, which is capped at ~2 emails/hour — a handful of
 * registrations returns 429 "email rate limit exceeded" and locks everyone out
 * of /register for the rest of the hour. Creating the account server-side with
 * the service role sends no email at all, so registration cannot be starved by
 * the mailer quota.
 *
 * SECURITY — server-side auto-confirm marks an address verified WITHOUT proving
 * the registrant owns the inbox (account squatting / impersonation). It is
 * therefore:
 *   - OFF by default in production (must be explicitly enabled), ON in
 *     non-production for local development. When off, this endpoint reports 503
 *     and the client falls back to the standard confirmation-email signup flow.
 *   - Never allowed to mint a PRIVILEGED account (the owner email and any
 *     admin-role address are refused here and must be provisioned deliberately).
 * Configure custom SMTP in Supabase (Auth → SMTP) and keep this off to send
 * real confirmation emails at proper quota.
 */
function autoConfirmEnabled(): boolean {
  const flag = String(process.env.REGISTRATION_AUTO_CONFIRM || '').toLowerCase()
  if (flag === 'true') return true
  if (flag === 'false') return false
  // Unset: safe-by-default in production, convenient in local/dev.
  return process.env.NODE_ENV !== 'production'
}

const router = Router()

// Anti-abuse. Rate limiting keys on the REAL immediate peer
// (`req.socket.remoteAddress`), never on X-Forwarded-For: the mounted server
// sets `trust proxy: true`, so `req.ip`/XFF is attacker-spoofable and a client
// could rotate the header to uncap itself. A separate GLOBAL cap ensures that
// even many distinct peers cannot mass-create accounts through this
// unauthenticated endpoint.
const RATE_WINDOW_MS = 15 * 60 * 1000
const RATE_MAX_PER_PEER = 8
const RATE_MAX_GLOBAL = 60
const attemptsByPeer = new Map<string, number[]>()
let globalAttempts: number[] = []

function peerRateLimited(peer: string): boolean {
  const now = Date.now()
  const attempts = (attemptsByPeer.get(peer) || []).filter((at) => now - at < RATE_WINDOW_MS)
  if (attempts.length >= RATE_MAX_PER_PEER) {
    attemptsByPeer.set(peer, attempts)
    return true
  }
  attempts.push(now)
  attemptsByPeer.set(peer, attempts)
  if (attemptsByPeer.size > 5000) {
    for (const [key, value] of attemptsByPeer) {
      if (value.every((at) => now - at >= RATE_WINDOW_MS)) attemptsByPeer.delete(key)
    }
  }
  return false
}

function globalRateLimited(): boolean {
  const now = Date.now()
  globalAttempts = globalAttempts.filter((at) => now - at < RATE_WINDOW_MS)
  if (globalAttempts.length >= RATE_MAX_GLOBAL) return true
  globalAttempts.push(now)
  return false
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/
// Matches the /register page's client-side policy (min 6). Longer input is
// allowed up to a sane bound so bcrypt-side limits are never hit.
const PASSWORD_MIN = 6
const PASSWORD_MAX = 128

function badRequest(res: Response, message: string) {
  return res.status(400).json({ error: { code: 'INVALID_INPUT', message } })
}

router.post('/register', async (req: Request, res: Response) => {
  try {
    // Real peer address only — NOT req.ip/X-Forwarded-For (spoofable under
    // `trust proxy: true`). Behind a real proxy every request shares the
    // proxy's socket address, which would turn the per-peer limit into ONE
    // platform-wide bucket; a deployment that locks its origin to Cloudflare
    // therefore names the header that proxy guarantees (TRUSTED_CLIENT_IP_HEADER).
    const peer = trustedClientIp(req) || req.socket.remoteAddress || 'unknown'
    if (peerRateLimited(peer) || globalRateLimited()) {
      return res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many registration attempts. Try again in a few minutes.' } })
    }

    const body = (req.body ?? {}) as Record<string, unknown>
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : ''
    const password = typeof body.password === 'string' ? body.password : ''
    const name = typeof body.name === 'string' ? body.name.trim().slice(0, 120) : ''

    if (!EMAIL_PATTERN.test(email) || email.length > 254) {
      return badRequest(res, 'A valid email address is required.')
    }
    if (password.length < PASSWORD_MIN) {
      return badRequest(res, `Password must be at least ${PASSWORD_MIN} characters.`)
    }
    if (password.length > PASSWORD_MAX) {
      return badRequest(res, 'Password is too long.')
    }

    // Privileged accounts (owner / platform admins) grant elevated access by
    // EMAIL, so they must never be self-served through this endpoint — that
    // would let an attacker squat the address before the real operator and,
    // under auto-confirm, receive a pre-verified privileged login. Provision
    // these deliberately (Supabase dashboard / admin tooling).
    if (isOwnerEmail(email)) {
      return res.status(403).json({ error: { code: 'EMAIL_NOT_ALLOWED', message: 'This email address cannot be registered here. Contact your administrator.' } })
    }

    const autoConfirm = autoConfirmEnabled()
    if (!autoConfirm) {
      // Verification required and no server-side confirmation mailer here — let
      // the client fall back to the standard Supabase signup flow, which sends
      // a real confirmation email through the configured (custom SMTP) mailer.
      return res.status(503).json({ error: { code: 'CONFIRMATION_REQUIRED', message: 'Email confirmation is required for this deployment.' } })
    }

    const admin = getServiceClient()
    if (!admin) {
      // No service key on this deployment — the client falls back to the
      // standard Supabase signup flow.
      return res.status(503).json({ error: { code: 'REGISTRATION_UNAVAILABLE', message: 'Server-side registration is not configured.' } })
    }

    const { data, error } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: name ? { full_name: name } : undefined,
    })

    if (error) {
      const message = String(error.message || '')
      if (/already (been )?registered|already exists|email_exists/i.test(message) || (error as { code?: string }).code === 'email_exists') {
        return res.status(409).json({ error: { code: 'EMAIL_EXISTS', message: 'An account with this email already exists. Sign in instead.' } })
      }
      console.error('Registration createUser failed:', message)
      return res.status(500).json({ error: { code: 'REGISTRATION_FAILED', message: 'Registration failed. Please try again.' } })
    }

    const userId = data.user?.id
    if (userId) {
      // Audit trail (non-fatal): registrations are security-relevant events.
      try {
        await admin.from('security_events').insert({
          user_id: userId,
          event_type: 'account_registered',
          severity: 'info',
          message: 'Account created via server-side registration endpoint',
          metadata: { source: 'api.auth.register' },
        })
      } catch {
        // Audit insert must never fail a successful registration.
      }
    }

    return res.status(201).json({ data: { userId } })
  } catch (error: unknown) {
    console.error('Registration endpoint error:', error)
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Registration failed. Please try again.' } })
  }
})

export default router
