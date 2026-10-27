/**
 * QGuard Helix — Request Demo delivery (POST /api/v1/demo-request).
 *
 * The landing page's Request Demo modal posts here; the request is emailed to
 * the sales inbox (info@qguardhelix.com, or DEMO_REQUEST_TO) over SMTP, with
 * the visitor's address as Reply-To so the team answers them directly.
 *
 * Unauthenticated by design, so it is mounted before the subscription gateway
 * and carries its own protections:
 *  - the shared validator (src/lib/demo-request.ts); every header-bound field
 *    is single-line, so nothing a visitor types can add a mail header
 *  - plain-text email only: nothing a visitor types is ever rendered as HTML
 *  - a hidden honeypot field: a bot that fills it is told "sent" and nothing is
 *  - a per-client limit and a global hourly cap, so the endpoint cannot be
 *    used to flood the inbox
 *  - privacy-first logging: the outcome only, never the visitor's details
 *
 * No SMTP configured → 503 DEMO_EMAIL_NOT_CONFIGURED with the inbox address,
 * and the modal tells the visitor to email it. A request is never reported as
 * sent unless the mail server accepted it.
 */

import { Router, type Request, type Response } from 'express'
import nodemailer from 'nodemailer'
import {
  DEMO_EMAIL_PATTERN,
  DEMO_REQUEST_INBOX,
  demoStageLabel,
  validateDemoRequest,
  type DemoRequestInput,
} from '@/lib/demo-request'
import { readClientIp } from './runtime/client-ip'

// ─── Configuration ────────────────────────────────────────────────────────────

const CLIENT_WINDOW_MS = 10 * 60 * 1000
const GLOBAL_WINDOW_MS = 60 * 60 * 1000
const MAX_TRACKED_CLIENTS = 5_000
const SUBJECT_MAX_CHARS = 180

export interface DemoEmail {
  to: string
  from: string
  replyTo: { name: string; address: string }
  subject: string
  text: string
}

/** Resolves once the mail server has accepted the message; rejects otherwise. */
export type DemoEmailSender = (email: DemoEmail) => Promise<void>

export interface DemoRequestRouterConfig {
  /** null = delivery not configured: requests are refused with the inbox to write to. */
  sender?: DemoEmailSender | null
  from?: string
  to?: string
  /** Requests one client may send per 10 minutes. Env: DEMO_REQUEST_MAX_PER_CLIENT. */
  maxPerClient?: number
  /** Requests accepted from everyone per hour. Env: DEMO_REQUEST_MAX_PER_HOUR. */
  maxPerHour?: number
  now?: () => number
}

/** A positive integer from the environment, clamped, or the default. */
function envInt(name: string, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(process.env[name] ?? '', 10)
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback
}

/**
 * SMTP delivery from the environment:
 *   SMTP_HOST, SMTP_PORT (465), SMTP_SECURE (true on 465), SMTP_USER, SMTP_PASS,
 *   SMTP_FROM (defaults to SMTP_USER), DEMO_REQUEST_TO (defaults to the inbox).
 * Port 587 uses STARTTLS and refuses to continue in plaintext unless
 * SMTP_REQUIRE_TLS=false (a local test mail server only).
 */
export function demoRequestConfigFromEnv(): DemoRequestRouterConfig {
  const configuredTo = (process.env.DEMO_REQUEST_TO || '').trim()
  const to = DEMO_EMAIL_PATTERN.test(configuredTo) ? configuredTo : DEMO_REQUEST_INBOX
  const host = (process.env.SMTP_HOST || '').trim()
  const user = (process.env.SMTP_USER || '').trim()
  const from = (process.env.SMTP_FROM || '').trim() || user
  const limits = {
    maxPerClient: envInt('DEMO_REQUEST_MAX_PER_CLIENT', 3, 1, 100),
    maxPerHour: envInt('DEMO_REQUEST_MAX_PER_HOUR', 60, 1, 10_000),
  }
  if (!host || !from) return { sender: null, to, from, ...limits }

  const port = envInt('SMTP_PORT', 465, 1, 65_535)
  const secure = process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : port === 465
  const transport = nodemailer.createTransport({
    host,
    port,
    secure,
    requireTLS: !secure && process.env.SMTP_REQUIRE_TLS !== 'false',
    auth: user ? { user, pass: process.env.SMTP_PASS || '' } : undefined,
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
    disableFileAccess: true,
    disableUrlAccess: true,
  })
  return {
    sender: async (email) => {
      await transport.sendMail(email)
    },
    to,
    from,
    ...limits,
  }
}

// ─── Message ──────────────────────────────────────────────────────────────────

export function composeDemoEmail(request: DemoRequestInput, envelope: { to: string; from: string }, at: Date): DemoEmail {
  const subject = `Demo request: ${request.organization} — ${request.name}`
  const text = [
    'New demo request from the Qguard Helix website.',
    '',
    `Name:               ${request.name}`,
    `Work email:         ${request.email}`,
    `Organization:       ${request.organization}`,
    `PQC migration:      ${demoStageLabel(request.stage)}`,
    `Readiness playbook: ${request.whitepaper ? 'Requested — send the Post-Quantum Readiness Playbook' : 'Not requested'}`,
    `Submitted:          ${at.toISOString()}`,
    '',
    'Message:',
    request.message || '(no message)',
    '',
    '—',
    `Reply to this email to answer ${request.name} directly.`,
  ].join('\n')
  return {
    to: envelope.to,
    from: envelope.from,
    replyTo: { name: request.name, address: request.email },
    subject: subject.length > SUBJECT_MAX_CHARS ? `${subject.slice(0, SUBJECT_MAX_CHARS - 1)}…` : subject,
    text,
  }
}

// ─── Router ───────────────────────────────────────────────────────────────────

interface RateWindow {
  count: number
  start: number
}

export function createDemoRequestRouter(config: DemoRequestRouterConfig = {}): Router {
  const sender = config.sender ?? null
  const to = config.to || DEMO_REQUEST_INBOX
  const from = config.from || ''
  const maxPerClient = config.maxPerClient ?? 3
  const maxPerHour = config.maxPerHour ?? 60
  const now = config.now ?? Date.now

  const clients = new Map<string, RateWindow>()
  const global: RateWindow = { count: 0, start: 0 }

  /** Seconds until this client and the global window both have room, or 0. */
  const retryAfter = (client: string, at: number): number => {
    const entry = clients.get(client)
    if (entry && at - entry.start < CLIENT_WINDOW_MS && entry.count >= maxPerClient) {
      return Math.max(1, Math.ceil((CLIENT_WINDOW_MS - (at - entry.start)) / 1000))
    }
    if (at - global.start < GLOBAL_WINDOW_MS && global.count >= maxPerHour) {
      return Math.max(1, Math.ceil((GLOBAL_WINDOW_MS - (at - global.start)) / 1000))
    }
    return 0
  }

  const charge = (client: string, at: number, delta: 1 | -1): void => {
    if (delta === 1 && clients.size > MAX_TRACKED_CLIENTS) {
      for (const [key, entry] of clients) {
        if (at - entry.start >= CLIENT_WINDOW_MS) clients.delete(key)
      }
    }
    const entry = clients.get(client)
    if (!entry || at - entry.start >= CLIENT_WINDOW_MS) {
      if (delta === 1) clients.set(client, { count: 1, start: at })
    } else {
      entry.count = Math.max(0, entry.count + delta)
    }
    if (at - global.start >= GLOBAL_WINDOW_MS) {
      if (delta === 1) {
        global.count = 1
        global.start = at
      }
    } else {
      global.count = Math.max(0, global.count + delta)
    }
  }

  const router = Router()

  router.post('/', async (req: Request, res: Response) => {
    const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body)
      ? (req.body as Record<string, unknown>)
      : {}

    // Honeypot: a person never sees this field, so only a bot fills it in.
    if (typeof body.website === 'string' && body.website.trim()) {
      res.json({ ok: true, inbox: to })
      return
    }

    const parsed = validateDemoRequest(body)
    if (parsed.ok === false) {
      res.status(400).json({ error: { code: 'INVALID_DEMO_REQUEST', message: parsed.message, field: parsed.field } })
      return
    }

    if (!sender || !from) {
      res.status(503).json({
        error: {
          code: 'DEMO_EMAIL_NOT_CONFIGURED',
          message: `Online booking is not available right now. Email ${to} and we will schedule your demo.`,
          inbox: to,
        },
      })
      return
    }

    const client = readClientIp(req)
    const at = now()
    const wait = retryAfter(client, at)
    if (wait > 0) {
      res.setHeader('Retry-After', String(wait))
      res.status(429).json({
        error: {
          code: 'RATE_LIMITED',
          message: `Too many requests right now. Try again in ${Math.ceil(wait / 60)} minute(s), or email ${to}.`,
          inbox: to,
        },
      })
      return
    }

    charge(client, at, 1)
    try {
      await sender(composeDemoEmail(parsed.value, { to, from }, new Date(at)))
      console.info('[demo-request] delivered')
      res.json({ ok: true, inbox: to })
    } catch (error) {
      // A delivery failure is ours, not the visitor's: give the attempt back.
      charge(client, at, -1)
      const detail = error as { code?: unknown; responseCode?: unknown }
      console.warn(`[demo-request] delivery failed (code=${String(detail?.code ?? 'unknown')}, smtp=${String(detail?.responseCode ?? '-')})`)
      res.status(502).json({
        error: {
          code: 'DEMO_EMAIL_FAILED',
          message: `Your request could not be sent. Please try again, or email ${to}.`,
          inbox: to,
        },
      })
    }
  })

  return router
}

export default createDemoRequestRouter(demoRequestConfigFromEnv())
