import { createHash } from 'node:crypto'
import type { Request, Response } from 'express'

/**
 * Live snapshot streaming for dashboard routers (SSE, text/event-stream).
 *
 * Five Quantum Readiness surfaces (readiness, exposure graph, harvest-now,
 * remediation, certification) each re-sent their FULL payload on a timer
 * whether or not anything had changed, per open tab — and the readiness pages
 * had no stream of their own at all: they refetched the whole snapshot every
 * time an unrelated 8-second key-count pulse fired. This module is the one
 * implementation of the contract the scanner stream already proved
 * (issue #44 in qguard-common-issues-fixes):
 *
 *   • `<event>`            full payload, sent first and whenever CONTENT changes
 *   • `<event>-unchanged`  `{ fingerprint, generatedAt, checkedAt }` — content
 *                           is unchanged, with the model's original watermark
 *   • `<event>-error`      `{ message }` — the build failed; the stream stays open
 *
 * The fingerprint excludes `generatedAt` / `checkedAt` (they change on every
 * recompute even when nothing else did) and is memoised per payload OBJECT: builders sit
 * behind 15s single-flight caches, so N open tabs hash one object once.
 */

const fingerprints = new WeakMap<object, string>()
const VOLATILE_KEYS = new Set(['generatedAt', 'checkedAt', 'sourceCheckedAt', 'fingerprint'])

export function payloadFingerprint(data: unknown): string {
  if (data && typeof data === 'object') {
    const cached = fingerprints.get(data)
    if (cached) return cached
  }
  // Build-time stamps are excluded at EVERY depth: nested models (the shared
  // responsibility rollup, for one) carry their own `generatedAt`, and a single
  // one of them would make every recompute look like news.
  const fingerprint = createHash('sha1')
    .update(JSON.stringify(data ?? null, (key, value) => (VOLATILE_KEYS.has(key) ? undefined : value)))
    .digest('hex')
  if (data && typeof data === 'object') fingerprints.set(data, fingerprint)
  return fingerprint
}

export interface LiveSnapshotStreamOptions<T> {
  /** SSE event name for full frames; `-unchanged` / `-error` are derived from it. */
  event: string
  build: () => Promise<T>
  /** Re-check cadence. Builders are cached, so this is a cache read most ticks. */
  intervalMs: number
  heartbeatMs?: number
}

/**
 * `exp` (ms) of the bearer token this stream was opened with, or null.
 * The signature was verified by the auth middleware; this only reads the claim.
 */
export function bearerExpiryMs(req: Request): number | null {
  const header = String(req.headers?.authorization || '')
  const token = header.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : ''
  const payload = token.split('.')[1]
  if (!payload) return null
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { exp?: unknown }
    return typeof claims.exp === 'number' ? claims.exp * 1000 : null
  } catch {
    return null
  }
}

export function streamLiveSnapshot<T extends object>(req: Request, res: Response, options: LiveSnapshotStreamOptions<T>): void {
  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'private, no-store, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()

  let closed = false
  let emitting = false
  let lastFingerprint = ''
  const expiresAt = bearerExpiryMs(req)
  const write = (event: string, data: unknown) => {
    if (!closed) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  }
  const stop = () => {
    closed = true
    clearInterval(tick)
    clearInterval(heartbeat)
  }

  const emit = async () => {
    // A build slower than the tick must not stack a second one behind it.
    if (closed || emitting) return
    // Every build runs under the token the stream was opened with. Once it has
    // expired, each read fails authentication. End the stream so the client
    // reconnects with its rotated token instead of erroring here every tick.
    if (expiresAt !== null && Date.now() >= expiresAt) {
      write(`${options.event}-error`, { message: 'Session token expired — reconnecting', code: 'SESSION_EXPIRED' })
      stop()
      res.end()
      return
    }
    emitting = true
    try {
      const data = await options.build()
      if (closed) return
      const fingerprint = payloadFingerprint(data)
      const model = data as { generatedAt?: unknown; sourceCheckedAt?: unknown; checkedAt?: unknown }
      const generatedAt = model.generatedAt ?? null
      const checkedAt = model.sourceCheckedAt ?? model.checkedAt ?? generatedAt
      if (fingerprint === lastFingerprint) {
        write(`${options.event}-unchanged`, { fingerprint, generatedAt, checkedAt })
        return
      }
      lastFingerprint = fingerprint
      write(options.event, { ...data, fingerprint })
    } catch (err) {
      write(`${options.event}-error`, { message: err instanceof Error ? err.message : 'Live stream build failed' })
    } finally {
      emitting = false
    }
  }

  // Timers exist before the first emit, which may call stop() synchronously.
  const tick = setInterval(() => void emit(), options.intervalMs)
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': heartbeat\n\n')
  }, options.heartbeatMs ?? 20_000)
  req.on('close', stop)
  void emit()
}
