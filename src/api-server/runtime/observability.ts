import type { NextFunction, Request, Response } from 'express'
import { randomUUID } from 'node:crypto'
import { buildInfo } from './lifecycle'

/**
 * Request correlation + structured access logging.
 *
 * - Every API response carries `X-Request-Id`. An inbound id from a proxy is
 *   reused only when it looks like an opaque token (bounded charset/length), so
 *   a client cannot inject log-forging content through it.
 * - The JSON access log is OFF unless ACCESS_LOG=true (the Kubernetes
 *   ConfigMap enables it), so `npm run dev` output is unchanged.
 * - Query strings are logged with credential-bearing parameters redacted: the
 *   SSE streams authenticate with `?token=<JWT>`, and an access log must never
 *   become a replayable token store.
 */

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/
const SENSITIVE_QUERY_KEYS = new Set([
  'token', 'access_token', 'refresh_token', 'id_token', 'apikey', 'api_key', 'key',
  'secret', 'signature', 'sig', 'password', 'code', 'jwt', 'auth',
])

export function redactUrl(originalUrl: string): string {
  const queryIndex = originalUrl.indexOf('?')
  if (queryIndex === -1) return originalUrl
  const path = originalUrl.slice(0, queryIndex)
  const params = new URLSearchParams(originalUrl.slice(queryIndex + 1))
  const redacted: string[] = []
  for (const [key, value] of params) {
    const safe = SENSITIVE_QUERY_KEYS.has(key.toLowerCase()) ? '[REDACTED]' : value
    redacted.push(`${encodeURIComponent(key)}=${safe === '[REDACTED]' ? safe : encodeURIComponent(safe)}`)
  }
  return redacted.length ? `${path}?${redacted.join('&')}` : path
}

type RequestWithId = Request & { requestId?: string }

export function requestContext(req: Request, res: Response, next: NextFunction) {
  const inbound = req.headers['x-request-id']
  const candidate = Array.isArray(inbound) ? inbound[0] : inbound
  const requestId = candidate && REQUEST_ID_PATTERN.test(candidate) ? candidate : randomUUID()
  ;(req as RequestWithId).requestId = requestId
  res.setHeader('X-Request-Id', requestId)

  if (process.env.ACCESS_LOG === 'true') {
    const startedAt = process.hrtime.bigint()
    res.on('finish', () => {
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6
      logEvent(res.statusCode >= 500 ? 'error' : 'info', 'http_request', {
        requestId,
        method: req.method,
        path: redactUrl(req.originalUrl || req.url || ''),
        status: res.statusCode,
        durationMs: Math.round(durationMs),
        contentType: res.getHeader('content-type') || null,
      })
    })
  }
  next()
}

/** One JSON line per event on stdout/stderr — the format log shippers expect. */
export function logEvent(level: 'info' | 'warn' | 'error', event: string, fields: Record<string, unknown> = {}) {
  const info = buildInfo()
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    event,
    service: 'qguard-api',
    version: info.version,
    commit: info.commit,
    ...fields,
  })
  if (level === 'error') console.error(line)
  else if (level === 'warn') console.warn(line)
  else console.log(line)
}
