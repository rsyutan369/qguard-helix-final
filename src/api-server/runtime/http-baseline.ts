import type { NextFunction, Request, Response } from 'express'

/**
 * The HTTP baseline every QGuard API process applies, whatever it serves:
 * HTTPS enforcement, response security headers and the CORS allow-list.
 *
 * Shared by the full platform API (src/api-server/index.ts) and the public
 * API (src/api-server/public-api.ts), so the two can never drift apart on
 * transport security.
 */

export const HSTS_HEADER = 'max-age=63072000; includeSubDomains; preload'

/** API responses are data, never documents: nothing may load or frame them. */
export const API_CSP = [
  "default-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
].join('; ')

export function isLocalRequest(req: Request): boolean {
  const host = (req.headers.host || '').split(':')[0].toLowerCase()
  return host === 'localhost' || host === '127.0.0.1' || host === '::1'
}

export function isHttpsRequest(req: Request): boolean {
  const forwardedProto = req.headers['x-forwarded-proto']
  const proto = Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto
  return req.secure || req.protocol === 'https' || String(proto || '').split(',')[0].trim() === 'https'
}

export function shouldEnforceHttps(req: Request): boolean {
  const strictMode = process.env.NODE_ENV === 'production' ||
    process.env.FORCE_HTTPS === 'true' ||
    process.env.ENFORCE_HTTPS === 'true'

  return strictMode && !isLocalRequest(req) && !isHttpsRequest(req)
}

/** The request presents an agent credential (deployed agents, generated installers). */
export function carriesAgentCredential(req: Request): boolean {
  return typeof req.headers['x-qguard-agent-token'] === 'string' ||
    (typeof req.headers['x-qguard-agent-id'] === 'string' && typeof req.headers.authorization === 'string')
}

function peerIsLoopback(req: Request): boolean {
  const peer = (req.socket?.remoteAddress || '').replace(/^::ffff:/, '')
  return peer === '127.0.0.1' || peer === '::1'
}

/**
 * Plain HTTP in production: redirect reads, refuse writes — and refuse agent
 * credentials outright. Redirecting an agent would only teach it to retry
 * after its token already crossed the network in the clear. The local
 * exemption for agents needs a loopback PEER as well as a local Host header,
 * because the Host header is whatever the client chose to send.
 */
export function enforceHttps(req: Request, res: Response, next: NextFunction): void {
  const strictMode = process.env.NODE_ENV === 'production' || process.env.FORCE_HTTPS === 'true' || process.env.ENFORCE_HTTPS === 'true'
  if (strictMode && carriesAgentCredential(req) && !isHttpsRequest(req) && !(isLocalRequest(req) && peerIsLoopback(req))) {
    res.status(426).json({
      error: {
        code: 'AGENT_HTTPS_REQUIRED',
        message: 'Agent credentials are accepted over HTTPS only. This request crossed the network in plaintext: rotate the agent token in the Agent Center and point the agent at the HTTPS control-plane URL.',
      },
    })
    return
  }
  if (!shouldEnforceHttps(req)) {
    next()
    return
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    res.redirect(308, `https://${req.headers.host}${req.originalUrl}`)
    return
  }

  res.status(426).json({
    error: {
      code: 'HTTPS_REQUIRED',
      message: 'Secure share operations require HTTPS.',
    },
  })
}

export function securityHeaders(req: Request, res: Response, next: NextFunction): void {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()')
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin')
  res.setHeader('X-DNS-Prefetch-Control', 'off')
  res.setHeader('Content-Security-Policy', API_CSP)
  if (process.env.NODE_ENV === 'production' || isHttpsRequest(req)) {
    res.setHeader('Strict-Transport-Security', HSTS_HEADER)
  }
  next()
}

/**
 * The request's Origin when it may call this API, else null: the same host, an
 * origin listed in APP_ORIGIN / VITE_APP_ORIGIN / PUBLIC_APP_ORIGIN /
 * ALLOWED_ORIGINS, or a single-label wildcard pattern from those lists.
 */
export function allowedOrigin(req: Request): string | null {
  const origin = req.headers.origin
  if (!origin) return null

  const host = req.headers.host
  try {
    const originUrl = new URL(origin)
    if (host && originUrl.host === host) return origin

    const configured = [
      process.env.APP_ORIGIN,
      process.env.VITE_APP_ORIGIN,
      process.env.PUBLIC_APP_ORIGIN,
      process.env.ALLOWED_ORIGINS,
    ]
      .filter(Boolean)
      .flatMap((value) => String(value).split(','))
      .map((value) => value.trim())
      .filter(Boolean)

    if (configured.includes(origin)) return origin
    // Optional single-label wildcard (e.g. https://qguard-helix-*.vercel.app for
    // preview deployments against a STAGING API). `*` never spans a dot, so a
    // pattern cannot be widened to an attacker-controlled parent domain.
    for (const pattern of configured) {
      if (!pattern.includes('*')) continue
      const expression = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[a-z0-9-]+')
      if (new RegExp(`^${expression}$`, 'i').test(origin)) return origin
    }
  } catch {
    return null
  }

  return null
}

/**
 * Same-origin CORS by default. Cross-origin API access is enabled via
 * APP_ORIGIN / VITE_APP_ORIGIN / PUBLIC_APP_ORIGIN / ALLOWED_ORIGINS.
 */
export function corsPolicy(req: Request, res: Response, next: NextFunction): void {
  const origin = req.headers.origin
  const originAllowed = allowedOrigin(req)
  if (originAllowed) {
    res.setHeader('Access-Control-Allow-Origin', originAllowed)
    res.setHeader('Vary', 'Origin')
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-QGuard-Device-Id, X-QGuard-Refresh-Token, X-QGuard-Agent-Id, X-QGuard-Agent-Token')
  // Only relevant to a split-origin deployment (SPA on Vercel calling
  // api.<domain> directly): lets the SPA read export filenames/row counts and
  // caches preflights so Bearer-authenticated calls are not doubled.
  res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition, X-Report-Rows, Retry-After, X-Request-Id')
  res.setHeader('Access-Control-Max-Age', '600')
  if (req.method === 'OPTIONS') {
    if (origin && !originAllowed) {
      res.sendStatus(403)
      return
    }
    res.sendStatus(204)
    return
  }
  next()
}
