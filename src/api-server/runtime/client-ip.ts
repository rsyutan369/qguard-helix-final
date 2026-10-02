import type { Request } from 'express'
import { isIP } from 'node:net'

/**
 * The client address as asserted by a proxy the operator trusts, or null.
 *
 * Behind Cloudflare → DigitalOcean load balancer → pod, the socket peer is the
 * load balancer and the LEFTMOST X-Forwarded-For entry is whatever the client
 * sent, so neither identifies a visitor. Cloudflare sets `CF-Connecting-IP` to
 * the real client and overwrites any value the client supplied — but that
 * header is only trustworthy when the origin refuses traffic that did not come
 * through Cloudflare (DO load-balancer firewall allow-list of Cloudflare
 * ranges). So it is opt-in: set TRUSTED_CLIENT_IP_HEADER=cf-connecting-ip in
 * the deployment once that lock is in place.
 *
 * Unset (local development, `npm run dev`), this returns null and every caller
 * keeps its existing address logic unchanged.
 */
export function trustedClientIp(req: Request): string | null {
  const headerName = (process.env.TRUSTED_CLIENT_IP_HEADER || '').trim().toLowerCase()
  if (!headerName) return null
  const raw = req.headers[headerName]
  const value = (Array.isArray(raw) ? raw[0] : raw || '').split(',')[0].trim()
  return value && isIP(value) ? value : null
}
