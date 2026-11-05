/**
 * Bounded, connection-reusing, retrying transport for ALL server-side Supabase
 * traffic.
 *
 * ROOT CAUSE THIS FIXES
 * ---------------------
 * Node's global `fetch` (undici) keeps an UNBOUNDED connection pool per origin:
 * every in-flight request that cannot grab a free pooled socket opens a brand
 * new TCP + TLS connection. Each dashboard builder here fans out 12-54
 * concurrent PostgREST queries (governance alone is ~54 once buildSnapshot and
 * buildPortfolio are folded in), and ~30 SSE streams re-push on 8-30s timers.
 * Peak concurrency against the Supabase origin therefore reached 150-300+
 * SIMULTANEOUS TLS handshakes. Past roughly 100, handshakes queue longer than
 * undici's 10s connect timeout and the request dies as:
 *
 *     TypeError: fetch failed
 *       cause: ConnectTimeoutError: Connect Timeout Error
 *              (attempted addresses: 104.18.38.10:443, timeout: 10000ms)
 *              code: 'UND_ERR_CONNECT_TIMEOUT'
 *
 * Measured against this project's Supabase origin (single query, warm pool
 * ~80ms; raw TCP connect 56ms — the link itself was never the problem):
 *
 *     unbounded, 150 concurrent  ->  46/150 FAILED   (10.7s)
 *     unbounded, 300 concurrent  -> 204/300 FAILED   (10.7s)
 *     bounded @16, 300 queries   ->   0/300 failed   ( 1.7s)
 *
 * This is a CORRECTNESS fix before it is a performance one. Every `safeRows`
 * helper in the API server degrades a failed query to "table unavailable", so
 * these timeouts never surfaced as errors — they surfaced as silently EMPTY
 * dashboards and as KPIs that disagreed between panels depending on which
 * queries happened to lose the race. The abandoned handshakes also starved the
 * event loop, which is why public scans overran their 45s engine budget and
 * reported `grade N/A`.
 *
 * WHY A GATE AND NOT "FEWER QUERIES"
 * ----------------------------------
 * The queries are all genuinely needed — they are the estate truth the
 * dashboards are contractually built from. The defect is that they were issued
 * with no ceiling. Serialising them through a bounded, KEEP-ALIVE pool is both
 * correct and strictly faster than the unbounded burst, because reused sockets
 * skip the TLS handshake entirely.
 *
 * SCOPE
 * -----
 * Deliberately wired only into the Supabase client factories, so the scanner's
 * outbound probing (raw `tls.connect`, and its own HTTP fetches to scan
 * targets) is untouched and keeps its full concurrency.
 */

/** Concurrent in-flight requests allowed against the Supabase origin. */
const MAX_CONCURRENCY = readPositiveInt(process.env.SUPABASE_MAX_SOCKETS, 16)

/** Per-attempt ceiling. A hung request must never hold a slot indefinitely. */
const REQUEST_TIMEOUT_MS = readPositiveInt(process.env.SUPABASE_REQUEST_TIMEOUT_MS, 30_000)

/** Total attempts (1 = no retry) for a transient, safely-retryable failure. */
const MAX_ATTEMPTS = readPositiveInt(process.env.SUPABASE_MAX_ATTEMPTS, 3)

function readPositiveInt(raw: string | undefined, fallback: number): number {
  const parsed = Number(raw)
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback
}

/* ------------------------------------------------------------------ */
/* Concurrency gate                                                    */
/* ------------------------------------------------------------------ */

let active = 0
const waiters: Array<() => void> = []

function acquire(): Promise<void> {
  if (active < MAX_CONCURRENCY) {
    active += 1
    return Promise.resolve()
  }
  return new Promise<void>((resolve) => {
    waiters.push(() => {
      active += 1
      resolve()
    })
  })
}

function release(): void {
  active -= 1
  const next = waiters.shift()
  if (next) next()
}

/** Observability for the health endpoint: is the gate saturated right now? */
export function supabaseTransportStats() {
  return { active, queued: waiters.length, limit: MAX_CONCURRENCY }
}

/* ------------------------------------------------------------------ */
/* Retry classification                                                */
/* ------------------------------------------------------------------ */

/**
 * Errors where the request provably never reached the server, so replaying it
 * cannot duplicate a write. These are connection-establishment failures.
 */
const PRE_CONNECT_CODES = new Set([
  'UND_ERR_CONNECT_TIMEOUT',
  'ECONNREFUSED',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ETIMEDOUT',
])

/**
 * Errors that may have occurred AFTER the request was sent. Replaying these is
 * only safe for methods with no side effects.
 */
const POST_CONNECT_CODES = new Set([
  'ECONNRESET',
  'EPIPE',
  'UND_ERR_SOCKET',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
])

const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

function errorCode(error: unknown): string {
  const err = error as { code?: unknown; cause?: { code?: unknown } } | null
  const direct = err?.code
  if (typeof direct === 'string') return direct
  const nested = err?.cause?.code
  return typeof nested === 'string' ? nested : ''
}

/**
 * A body can only be replayed if it is a value we can hand to `fetch` twice.
 * Streams are single-shot, so a request carrying one is never retried.
 */
function bodyIsReplayable(body: unknown): boolean {
  return (
    body === null ||
    body === undefined ||
    typeof body === 'string' ||
    body instanceof Uint8Array ||
    body instanceof ArrayBuffer ||
    body instanceof URLSearchParams
  )
}

function shouldRetry(error: unknown, method: string, body: unknown): boolean {
  if (!bodyIsReplayable(body)) return false
  const code = errorCode(error)
  if (PRE_CONNECT_CODES.has(code)) return true
  return POST_CONNECT_CODES.has(code) && IDEMPOTENT_METHODS.has(method)
}

/** Exponential backoff with jitter, so a burst does not retry in lockstep. */
function backoffMs(attempt: number): number {
  return Math.round(150 * 2 ** (attempt - 1) * (1 + Math.random()))
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

/* ------------------------------------------------------------------ */
/* Transport                                                           */
/* ------------------------------------------------------------------ */

/**
 * Drop-in `fetch` for `createClient(url, key, { global: { fetch } })`.
 *
 * Bounds concurrency, reuses keep-alive sockets, applies a per-attempt timeout,
 * and retries genuinely transient connection failures. The signature matches
 * the global `fetch` exactly so supabase-js (PostgREST, GoTrue, Storage,
 * Functions) can use it unchanged.
 */
export const supabaseFetch: typeof fetch = async (input, init) => {
  const request = input instanceof Request ? input : null
  const method = (init?.method ?? request?.method ?? 'GET').toUpperCase()
  const body = init?.body ?? request?.body
  const callerSignal = init?.signal ?? request?.signal

  let lastError: unknown
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
    callerSignal?.throwIfAborted()
    await acquire()
    const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    // Honour a caller-supplied signal without discarding our own ceiling.
    const signal = callerSignal ? AbortSignal.any([callerSignal, timeout]) : timeout
    try {
      callerSignal?.throwIfAborted()
      const response = await fetch(input as RequestInfo, { ...init, signal })
      // fetch resolves at HEADERS, before PostgREST consumes the JSON body.
      // Keep finite JSON reads inside the retry/gate boundary: a socket closed
      // mid-body otherwise escapes as "TypeError: terminated" with no retry.
      // Clone preserves the original response (URL, headers, body) for callers.
      // Storage downloads and event streams keep their streaming behavior.
      if (response.body && /\bapplication\/(?:[\w.-]+\+)?json\b/i.test(response.headers.get('content-type') || '')) {
        await response.clone().arrayBuffer()
      }
      return response
    } catch (error) {
      lastError = error
      // A caller-initiated abort is intent, not a transient fault.
      if (callerSignal?.aborted) throw error
      if (attempt >= MAX_ATTEMPTS || !shouldRetry(error, method, body)) throw error
    } finally {
      release()
    }
    await sleep(backoffMs(attempt))
  }

  throw lastError
}
