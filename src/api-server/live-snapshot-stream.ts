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
 *   • `<event>-unchanged`  `{ fingerprint, generatedAt, checkedAt }` — proof the
 *                           server re-checked the estate, at a few bytes a tick
 *   • `<event>-error`      `{ message }` — the build failed; the stream stays open
 *
 * The fingerprint excludes `generatedAt` / `checkedAt` (they change on every
 * recompute even when nothing else did) and is memoised per payload OBJECT: builders sit
 * behind 15s single-flight caches, so N open tabs hash one object once.
 */

const fingerprints = new WeakMap<object, string>()
const VOLATILE_KEYS = new Set(['generatedAt', 'checkedAt', 'fingerprint'])

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

export function streamLiveSnapshot<T extends object>(req: Request, res: Response, options: LiveSnapshotStreamOptions<T>): void {
  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()

  let closed = false
  let emitting = false
  let lastFingerprint = ''
  const write = (event: string, data: unknown) => {
    if (!closed) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  }

  const emit = async () => {
    // A build slower than the tick must not stack a second one behind it.
    if (closed || emitting) return
    emitting = true
    try {
      const data = await options.build()
      if (closed) return
      const fingerprint = payloadFingerprint(data)
      const generatedAt = (data as { generatedAt?: unknown }).generatedAt ?? null
      if (fingerprint === lastFingerprint) {
        write(`${options.event}-unchanged`, { fingerprint, generatedAt, checkedAt: new Date().toISOString() })
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

  void emit()
  const tick = setInterval(() => void emit(), options.intervalMs)
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': heartbeat\n\n')
  }, options.heartbeatMs ?? 20_000)
  req.on('close', () => {
    closed = true
    clearInterval(tick)
    clearInterval(heartbeat)
  })
}
