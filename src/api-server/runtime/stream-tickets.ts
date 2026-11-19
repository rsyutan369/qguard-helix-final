import { randomBytes } from 'node:crypto'
import { Router, type Request, type Response } from 'express'
import { getServerUser, getToken } from '@/lib/supabase-server'

/**
 * Short-lived, single-use SSE stream tickets.
 *
 * EventSource cannot send an Authorization header, so streams used to be
 * opened with `?token=<Supabase JWT>` — putting a bearer token that is valid
 * for an hour into URLs, access logs, proxy logs and browser history. Now:
 *
 *   1. the client POSTs /api/v1/stream-tickets { stream } WITH the header,
 *   2. gets back an opaque random ticket (256 bits, valid 60 s, one use,
 *      bound to that user AND that one stream path),
 *   3. opens EventSource('/api/v1/<x>/stream?ticket=<ticket>').
 *
 * The JWT never leaves the server-side map. The stream route redeems the
 * ticket for the token and keeps re-verifying that token on every tick, so a
 * signed-out or expired session still stops the stream.
 *
 * In-memory by design: the API runs as ONE replica (deploy/k8s/base/
 * deployment.yaml). Scaling out needs a shared store or sticky sessions.
 */

export const STREAM_PATHS = {
  admin: '/api/v1/admin/stream',
  revenue: '/api/v1/revenue/stream',
  profile: '/api/v1/profile/stream',
  billing: '/api/v1/billing/stream',
} as const

export type StreamName = keyof typeof STREAM_PATHS

export const STREAM_TICKET_TTL_MS = 60_000
const MAX_TICKETS = 10_000
const MAX_OUTSTANDING_PER_USER = 20

interface TicketEntry {
  userId: string
  token: string
  path: string
  expiresAt: number
}

const tickets = new Map<string, TicketEntry>()

function sweep(now = Date.now()) {
  for (const [ticket, entry] of tickets) if (entry.expiresAt <= now) tickets.delete(ticket)
}

export function issueStreamTicket(userId: string, token: string, stream: StreamName): { ticket: string; expiresAt: string; path: string } {
  const now = Date.now()
  sweep(now)
  // Bound memory and per-user outstanding tickets (a client that keeps
  // minting without connecting only displaces its own oldest tickets).
  const own = [...tickets.entries()].filter(([, entry]) => entry.userId === userId)
  if (own.length >= MAX_OUTSTANDING_PER_USER) {
    own.sort((a, b) => a[1].expiresAt - b[1].expiresAt)
    for (const [ticket] of own.slice(0, own.length - MAX_OUTSTANDING_PER_USER + 1)) tickets.delete(ticket)
  }
  if (tickets.size >= MAX_TICKETS) {
    const oldest = tickets.keys().next().value
    if (oldest) tickets.delete(oldest)
  }
  const ticket = randomBytes(32).toString('base64url')
  const path = STREAM_PATHS[stream]
  const expiresAt = now + STREAM_TICKET_TTL_MS
  tickets.set(ticket, { userId, token, path, expiresAt })
  return { ticket, expiresAt: new Date(expiresAt).toISOString(), path }
}

/** Consume a ticket for `path`. Null when unknown, used, expired or for another stream. */
export function redeemStreamTicket(ticket: string, path: string): { userId: string; token: string } | null {
  if (!ticket || ticket.length > 128) return null
  const entry = tickets.get(ticket)
  if (!entry) return null
  tickets.delete(ticket) // single use, even when the path does not match
  if (entry.expiresAt <= Date.now() || entry.path !== path) return null
  return { userId: entry.userId, token: entry.token }
}

/**
 * The bearer token for a stream request: Authorization header first (server
 * clients, tools), else a redeemed `?ticket=`. A raw `?token=` is never read.
 */
export function streamTokenFromRequest(req: Request): string | null {
  const header = getToken(req)
  if (header) return header
  const raw = req.query?.ticket
  if (typeof raw !== 'string' || !raw) return null
  const path = (req.originalUrl || req.url || '').split('?')[0].replace(/\/+$/, '')
  return redeemStreamTicket(raw, path)?.token ?? null
}

/** Test hook: outstanding ticket count. */
export function outstandingStreamTickets(): number {
  sweep()
  return tickets.size
}

const router = Router()

router.post('/', async (req: Request, res: Response) => {
  const token = getToken(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authorization header required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired session' } })
  const stream = String((req.body as Record<string, unknown> | undefined)?.stream || '') as StreamName
  if (!Object.prototype.hasOwnProperty.call(STREAM_PATHS, stream)) {
    return res.status(400).json({ error: { code: 'INVALID_STREAM', message: `stream must be one of ${Object.keys(STREAM_PATHS).join(', ')}` } })
  }
  // Authorisation for the stream itself (owner-only admin/revenue) is still
  // enforced by that stream's own route when the ticket is redeemed.
  res.setHeader('Cache-Control', 'no-store')
  return res.json({ data: issueStreamTicket(user.id, token, stream) })
})

export default router
