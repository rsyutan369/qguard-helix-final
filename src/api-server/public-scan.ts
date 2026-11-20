import { json, Router, type NextFunction, type Request, type Response } from 'express'
import { randomUUID } from 'node:crypto'
import net from 'node:net'
import { validateAsset } from '@/lib/scanner/asset-validator'
import { assessPublicTarget, quantumStageDetail } from '@/lib/scanner/public-scan/assess'
import { ScanCancelledError, tlsStageDetail, type ObservationSink } from '@/lib/scanner/public-scan/engines'
import type { PublicScanReport, PublicScanStage } from '@/lib/scanner/public-scan/types'
import { trustedClientIp } from './runtime/client-ip'
import { allowedOrigin } from './runtime/http-baseline'
import { authenticatePublicScan, type PublicScanAccount } from './public-scan-account'
import type { PublicScanUsage } from '@/lib/public-scan-usage'
import { checkHostSyntax, verifyPublicHost } from '@/lib/scanner/public-scan/safe-dns'
import { PublicScanCoordinator, type CoordinatorOptions, type QueueEvent, type QueueTarget } from './public-scan-queue'

// ─── Limits ───────────────────────────────────────────────────────────────────

/**
 * Two budgets, and the difference between them is the point.
 *
 * `SCAN_BUDGET_MS` is what the ENGINES are told they have. They treat it as a
 * degrade-by time: when it expires they return what they measured and mark the
 * rest inconclusive, so the visitor always gets a report with its limits stated.
 *
 * `SCAN_TIMEOUT_MS` is a backstop for a bug, not a scanning strategy. It exists
 * only so a wedged promise cannot hold a connection open forever. Reaching it
 * means something is wrong with the scanner, not with the target. It now also
 * ABORTS the scan, so its capacity slot is genuinely released.
 *
 * The previous single 75s timeout was both at once, which is why a slow endpoint
 * produced a 75-second wait ending in an error: the engines had no idea a
 * deadline existed, ran past it, and the race rejected everything they had
 * already measured.
 */
const SCAN_BUDGET_MS = 45_000
const SCAN_TIMEOUT_MS = 90_000
const CACHE_TTL_MS = 10 * 60 * 1000
/**
 * The streaming endpoint serves cached results for far less time than the
 * one-shot API. A cache hit replays a finished assessment in a single frame,
 * which is the correct answer for a JSON caller and a misleading one for a
 * visitor watching a live assessment: it looks like the scan ran in a second.
 */
const STREAM_CACHE_TTL_MS = 45 * 1000
const CACHE_MAX_ENTRIES = 400
const RATE_LIMIT_WINDOW_MS = 60_000
const RATE_LIMIT_MAX_TRACKED_IPS = 5_000
const MAX_PENDING_CHECKS = 48
const REQUEST_BUDGET_MS = 115_000
const MAX_STREAM_BUFFER_BYTES = 256 * 1024
const ALLOWED_PORTS = new Set([443, 8443, 9443, 4443, 10443])
/** How long a scan nobody is watching survives — a reload or reconnect keeps its place. */
const ABANDON_GRACE_MS = 4_000

/** A positive integer from the environment, clamped, or the default. */
function envInt(name: string, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(process.env[name] ?? '', 10)
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback
}

function resolveTarget(raw: unknown): { target: QueueTarget } | { error: { code: string; message: string } } {
  const input = typeof raw === 'string' ? raw.trim() : ''
  if (!input || input.length > 269 || /[\s@]/u.test(input)) {
    return { error: { code: 'INVALID_TARGET', message: 'Enter a domain or HTTPS URL up to 269 characters, without credentials.' } }
  }

  const validated = validateAsset(input)
  if (!validated.valid || validated.type === 'subnet' ||
    (validated.protocol !== null && validated.protocol !== 'https')) {
    return { error: { code: 'INVALID_TARGET', message: 'Enter a valid domain or HTTPS URL to assess.' } }
  }

  const host = validated.host.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '')
  const port = validated.port ?? 443
  if (!ALLOWED_PORTS.has(port)) {
    return { error: { code: 'UNSUPPORTED_PORT', message: 'Use HTTPS on port 443, 8443, 9443, 4443, or 10443.' } }
  }

  const verdict = checkHostSyntax(host)
  if (!verdict.ok) return { error: { code: verdict.code!, message: verdict.message! } }
  const domain = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u
  if (!net.isIP(host) && (host.length > 253 || !domain.test(host))) {
    return { error: { code: 'INVALID_TARGET', message: 'Enter a fully qualified domain such as example.com.' } }
  }

  // Shared scans and results describe the origin. Do not retain paths or queries.
  const authority = net.isIPv6(host) ? `[${host}]` : host
  return { target: { input: `https://${authority}${port === 443 ? '' : `:${port}`}`, host, port, key: `${authority}:${port}` } }
}

export interface PublicScanRouterConfig {
  /** Scans running at once. Env: PUBLIC_SCAN_MAX_CONCURRENT. */
  maxConcurrent?: number
  /** Scans allowed to wait for a slot. Env: PUBLIC_SCAN_MAX_QUEUE. */
  maxQueue?: number
  /**
   * Scans one client may have created and not finished, enforced only when a
   * new one would have to wait. Env: PUBLIC_SCAN_MAX_ACTIVE_PER_CLIENT.
   */
  maxActivePerClient?: number
  /** NEW scans one client may start per minute. Env: PUBLIC_SCAN_RATE_LIMIT_PER_MINUTE. */
  rateLimitPerMinute?: number
  abandonGraceMs?: number
  scanTimeoutMs?: number
  initialScanEstimateMs?: number
  /**
   * The assessment itself. Defaults to the real engines; the load check
   * injects a synthetic scan so a thousand concurrent visitors can be driven
   * through the REAL HTTP layer without a thousand real third-party scans.
   */
  run?: CoordinatorOptions['run']
  /** Privacy-first outcome logging. On by default. */
  log?: boolean
  /** Dependencies overridden by isolated HTTP integration checks. */
  authenticate?: (token: string) => Promise<PublicScanAccount | null>
  verifyTarget?: typeof verifyPublicHost
}

/**
 * Capacity and fairness, per process. Tunable without a code change because the
 * right numbers depend on the host — docs/deployment/02-ENVIRONMENT.md gives
 * the measured basis for each default.
 */
export function publicScanLimitsFromEnv(): Required<Pick<PublicScanRouterConfig, 'maxConcurrent' | 'maxQueue' | 'maxActivePerClient' | 'rateLimitPerMinute'>> {
  return {
    maxConcurrent: envInt('PUBLIC_SCAN_MAX_CONCURRENT', 6, 1, 64),
    maxQueue: envInt('PUBLIC_SCAN_MAX_QUEUE', 500, 0, 10_000),
    maxActivePerClient: envInt('PUBLIC_SCAN_MAX_ACTIVE_PER_CLIENT', 3, 1, 20),
    rateLimitPerMinute: envInt('PUBLIC_SCAN_RATE_LIMIT_PER_MINUTE', 5, 1, 1_000),
  }
}

/** SSE event name for each coordinator event. */
const STREAM_EVENT: Record<QueueEvent['type'], string> = {
  queued: 'scan-queued',
  started: 'scan-started',
  shared: 'scan-shared',
  stage: 'stage',
  observation: 'observation',
  complete: 'scan-complete',
  failed: 'error',
}

interface CacheEntry {
  report: PublicScanReport
  storedAt: number
  expiresAt: number
}

interface RateEntry {
  count: number
  windowStart: number
}

export function createPublicScanRouter(config: PublicScanRouterConfig = {}): Router {
  const limits = { ...publicScanLimitsFromEnv(), ...stripUndefined(config) }
  const log = config.log ?? true
  const router = Router()

  // ── rate limiting ─────────────────────────────────────────────────────────

  const rateBuckets = new Map<string, RateEntry>()
  let authInFlight = 0
  let preflights = 0
  let quotaReads = 0
  const rejectionLogs = new Map<string, { at: number; suppressed: number }>()

  const rateLimit = (key: string, max: number, charge = true): number => {
    const now = Date.now()
    let entry = rateBuckets.get(key)
    if (!entry || now - entry.windowStart >= RATE_LIMIT_WINDOW_MS) {
      if (rateBuckets.size >= RATE_LIMIT_MAX_TRACKED_IPS && !rateBuckets.has(key)) {
        for (const [id, bucket] of rateBuckets) {
          if (now - bucket.windowStart >= RATE_LIMIT_WINDOW_MS) rateBuckets.delete(id)
        }
        if (rateBuckets.size >= RATE_LIMIT_MAX_TRACKED_IPS) return 60
      }
      entry = { count: 0, windowStart: now }
      if (charge) rateBuckets.set(key, entry)
    }
    if (entry.count >= max) return Math.max(1, Math.ceil((RATE_LIMIT_WINDOW_MS - now + entry.windowStart) / 1000))
    if (charge) entry.count += 1
    return 0
  }

  const resultCache = new Map<string, CacheEntry>()

  /**
   * `maxAgeMs` lets a caller demand a fresher entry than the cache's own TTL.
   * The stream uses it to keep a live assessment live; the one-shot JSON API
   * takes the full TTL.
   */
  const readCache = (key: string, maxAgeMs = CACHE_TTL_MS): PublicScanReport | null => {
    const entry = resultCache.get(key)
    if (!entry) return null
    const now = Date.now()
    if (entry.expiresAt < now) {
      resultCache.delete(key)
      return null
    }
    if (now - entry.storedAt > maxAgeMs) return null
    return { ...entry.report, cached: true }
  }

  const writeCache = (key: string, report: PublicScanReport): void => {
    if (resultCache.size >= CACHE_MAX_ENTRIES) {
      const oldest = resultCache.keys().next().value
      if (oldest) resultCache.delete(oldest)
    }
    resultCache.set(key, { report, storedAt: Date.now(), expiresAt: Date.now() + CACHE_TTL_MS })
  }

  // ── coordinator ───────────────────────────────────────────────────────────

  /* One per router: the waiting line, the shared jobs and the capacity cap
     live here. See `public-scan-queue.ts` for the rules and the measurements
     that motivated them. */
  const coordinator = new PublicScanCoordinator({
    maxConcurrent: limits.maxConcurrent,
    maxQueue: limits.maxQueue,
    maxActivePerClient: limits.maxActivePerClient,
    timeoutMs: config.scanTimeoutMs ?? SCAN_TIMEOUT_MS,
    abandonGraceMs: config.abandonGraceMs ?? ABANDON_GRACE_MS,
    initialScanEstimateMs: config.initialScanEstimateMs ?? 15_000,
    run:
      config.run ??
      ((target, hooks) =>
        assessPublicTarget({
          input: target.input,
          host: target.host,
          port: target.port,
          onStage: hooks.onStage,
          onObservation: hooks.onObservation as ObservationSink,
          budgetMs: SCAN_BUDGET_MS,
          signal: hooks.signal,
        })),
    isCancellation: (error) => error instanceof ScanCancelledError,
    onReport: (target, report, durationMs) => {
      if (!report.unreachable) writeCache(target.key, report)
      if (!log) return
      // Privacy-first logging: target host + outcome only, no client identifiers.
      console.info(
        `[public-scan] ${target.host}:${target.port} → ` +
          (report.unreachable
            ? `unreachable (${report.reachability.state})`
            : `grade ${report.executive.grade}, pq ${report.executive.postQuantumReadiness ?? 'n/a'}%`) +
          `, ${durationMs}ms`,
      )
    },
    onFailure: (target, _message, durationMs) => {
      if (log) console.warn(`[public-scan] ${target.host}:${target.port} → failed after ${durationMs}ms`)
    },
  })

  const reject = (res: Response, status: number, code: string, message: string,
    retryAfterSeconds?: number, usage?: PublicScanUsage) => {
    if (res.destroyed || res.writableEnded) return
    if (log) {
      const previous = rejectionLogs.get(code)
      const now = Date.now()
      if (!previous || now - previous.at >= 5_000) {
        console.warn('[public-scan] rejected', { code, status, suppressed: previous?.suppressed ?? 0 })
        rejectionLogs.set(code, { at: now, suppressed: 0 })
      } else previous.suppressed += 1
    }
    if (retryAfterSeconds) res.setHeader('Retry-After', String(retryAfterSeconds))
    res.status(status).json({ error: { code, message, retryAfterSeconds }, usage })
  }

  const unavailable = (res: Response) => reject(res, 503, 'SERVICE_UNAVAILABLE', 'Public Scan is temporarily unavailable. Try again shortly.')
  const throttled = (res: Response, seconds: number) =>
    reject(res, 429, 'RATE_LIMITED', 'Too many requests. Wait before trying again.', seconds)

  const scanBody = json({ limit: '1kb', inflate: false })
  const readScanBody = (req: Request, res: Response, next: NextFunction) => {
    const timeout = setTimeout(() => res.destroy(), 10_000)
    const clear = () => clearTimeout(timeout)
    res.once('close', clear)
    scanBody(req, res, (error?: unknown) => {
      clear()
      res.removeListener('close', clear)
      next(error)
    })
  }

  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'private, no-store, no-transform')
    if (req.headers.origin && !allowedOrigin(req)) {
      reject(res, 403, 'ORIGIN_NOT_ALLOWED', 'This origin is not allowed.')
      return
    }

    const ip = trustedClientIp(req) ?? req.socket.remoteAddress ?? 'unknown'
    const failures = `failed:${ip}`
    const retry = rateLimit(failures, 8, false) || rateLimit(`requests:${ip}`, 120)
    if (retry) {
      throttled(res, retry)
      return
    }
    res.locals.failureBucket = failures
    next()
  })

  async function route(req: Request, res: Response, mode: 'usage' | 'json' | 'stream') {
    const authorization = req.get('authorization') ?? ''
    const token = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(authorization)?.[1]
    const unauthorized = () => {
      rateLimit(res.locals.failureBucket, 8)
      res.setHeader('WWW-Authenticate', 'Bearer')
      reject(res, 401, 'AUTH_REQUIRED', 'Sign in with a verified Qguard Helix account to run an assessment.')
    }
    if (!token || token.length > 4096) return unauthorized()
    if (authInFlight >= MAX_PENDING_CHECKS) return unavailable(res)

    authInFlight += 1
    let account: PublicScanAccount | null
    try {
      account = await (config.authenticate ?? authenticatePublicScan)(token)
    } catch {
      return unavailable(res)
    } finally {
      authInFlight -= 1
    }
    if (res.destroyed) return
    if (!account) return unauthorized()

    if (mode === 'usage') {
      if (quotaReads >= MAX_PENDING_CHECKS) return unavailable(res)
      quotaReads += 1
      try {
        const { usage } = await account.quota('usage')
        if (!res.destroyed) res.json({ data: usage })
      } finally {
        quotaReads -= 1
      }
      return
    }

    if (!req.is('application/json') || !req.body || Object.keys(req.body).length !== 1) {
      return reject(res, 400, 'INVALID_REQUEST', 'Send a JSON object containing only the target.')
    }
    const resolved = resolveTarget(req.body.target)
    if ('error' in resolved) return reject(res, 400, resolved.error.code, resolved.error.message)

    const attemptRetry = rateLimit(`scan:${account.id}`, limits.rateLimitPerMinute)
    if (attemptRetry) return throttled(res, attemptRetry)

    const { target } = resolved
    const scanId = randomUUID()
    const deadline = Date.now() + REQUEST_BUDGET_MS
    if (preflights >= MAX_PENDING_CHECKS) return unavailable(res)
    preflights += 1
    let preparing = true
    let shouldRelease = true
    try {
      const { status, usage } = await account.quota('reserve', scanId)
      shouldRelease = status === 'ok'
      if (status === 'exhausted') {
        reject(res, 429, 'DAILY_LIMIT_REACHED', 'You have used all 3 assessments for this UTC day.',
          Math.max(1, Math.ceil((Date.parse(usage.resetAt) - Date.now()) / 1000)), usage)
        return
      }
      if (status === 'active') {
        reject(res, 409, 'SCAN_IN_PROGRESS', 'An assessment is already running for your account.', undefined, usage)
        return
      }
      if (status !== 'ok') return unavailable(res)
      if (res.destroyed) return

      const verdict = await (config.verifyTarget ?? verifyPublicHost)(target.host)
      preflights -= 1
      preparing = false
      if (res.destroyed) return
      if (!verdict.ok) return reject(res, 400, verdict.code ?? 'INVALID_TARGET', verdict.message ?? 'Target is unavailable.')

      const cached = readCache(target.key, mode === 'stream' ? STREAM_CACHE_TTL_MS : CACHE_TTL_MS)
      const streaming = mode === 'stream'
      const write = (event: string, payload: unknown) => {
        if (res.writableEnded || res.destroyed) return
        if (res.writableLength > MAX_STREAM_BUFFER_BYTES) {
          res.destroy()
          return
        }
        res.write(`event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`)
      }
      const openStream = () => {
        res.setHeader('Content-Type', 'text/event-stream')
        res.setHeader('X-Accel-Buffering', 'no')
        res.flushHeaders()
        write('scan-start', { target: target.host, port: target.port })
      }

      type Outcome = { type: 'complete'; report: PublicScanReport } | { type: 'failed' | 'closed' }
      let outcome: Outcome
      if (cached) {
        if (streaming) {
          openStream()
          for (const stage of cached.evidence ? cachedStages(cached) : []) write('stage', { stage })
        }
        outcome = { type: 'complete', report: cached }
      } else {
        let settle!: (value: Outcome) => void
        const terminal = new Promise<Outcome>((resolve) => { settle = resolve })
        const held: QueueEvent[] = []
        let open = false
        const deliver = (event: QueueEvent) => {
          if (event.type === 'complete' || event.type === 'failed') {
            settle(event)
          } else if (streaming) {
            if (open) write(STREAM_EVENT[event.type], event.type === 'observation' ? event.observation : event)
            else held.push(event)
          }
        }
        const admission = coordinator.subscribe(target, account.id, deliver, { allowQueue: streaming })
        if (admission.admitted === false) {
          reject(res, admission.code === 'CLIENT_BUSY' ? 429 : 503, admission.code,
            'The scanner is at capacity. Try again shortly.', admission.retryAfterSeconds)
          return
        }
        const onClose = () => settle({ type: 'closed' })
        res.once('close', onClose)
        const timer = setTimeout(() => settle({ type: 'failed' }), Math.max(0, deadline - Date.now()))
        const heartbeat = streaming ? setInterval(() => {
          if (res.writableLength > MAX_STREAM_BUFFER_BYTES) res.destroy()
          else if (!res.destroyed && !res.writableEnded) res.write(': heartbeat\n\n')
        }, 15_000) : null
        try {
          if (streaming) {
            openStream()
            open = true
            for (const event of held) deliver(event)
          }
          outcome = await terminal
        } finally {
          clearTimeout(timer)
          if (heartbeat) clearInterval(heartbeat)
          res.removeListener('close', onClose)
          admission.unsubscribe()
        }
      }

      if (outcome.type === 'closed') return
      const operation = outcome.type === 'complete' && !outcome.report.unreachable && !cached ? 'complete' : 'release'
      // Release is conditional on the row still being pending, including when
      // the completion transaction succeeded but its HTTP response was lost.
      const updated = await account.quota(operation, scanId)
      shouldRelease = false
      if (updated.status !== 'ok') throw new Error('Scan reservation expired')
      if (res.destroyed) return
      if (streaming) {
        if (outcome.type === 'complete') write('scan-complete', { report: outcome.report, usage: updated.usage })
        else write('error', { code: 'SCAN_FAILED', message: 'The assessment could not be completed.', usage: updated.usage })
        res.end()
      } else if (outcome.type === 'complete') {
        res.json({ data: outcome.report, usage: updated.usage })
      } else {
        reject(res, 502, 'SCAN_FAILED', 'The assessment could not be completed.', undefined, updated.usage)
      }
    } finally {
      if (preparing) preflights -= 1
      if (shouldRelease) {
        await account.quota('release', scanId).catch(() => {
          if (log) console.warn('[public-scan] reservation release failed')
        })
      }
    }
  }

  const handle = (mode: 'usage' | 'json' | 'stream') => (req: Request, res: Response) => {
    void route(req, res, mode).catch(() => {
      if (res.destroyed || res.writableEnded) return
      if (res.headersSent) {
        if (log) console.warn('[public-scan] stream interrupted')
        res.end('event: error\ndata: {"message":"The assessment could not be saved. Refresh your allowance before trying again."}\n\n')
      } else unavailable(res)
    })
  }

  /** Scanner capability disclosure — what the public scanner does and does not do. */
  router.get('/capabilities', (_req, res) => {
    res.json({
      data: {
        name: 'Public Quantum Exposure Assessment',
        version: '1.1.0',
        authentication: 'required',
        modules: ['dns', 'tls', 'certificate', 'headers', 'quantum', 'report'],
        analyzed: [
          'TLS protocol and cipher negotiation',
          'Served X.509 certificate chain',
          'Certificate Transparency and OCSP metadata',
          'Public DNS records and CAA issuance policy',
          'HTTP transport-security headers',
        ],
        notAnalyzed: [
          'Source code and repositories',
          'Internal infrastructure and cloud workloads',
          'Private PKI, key management and HSMs',
          'Databases and storage encryption',
          'Cryptographic governance and compliance evidence',
        ],
        limits: {
          scansPerDayPerAccount: 3,
          resetTimezone: 'UTC',
          scanRequestsPerMinutePerAccount: limits.rateLimitPerMinute,
          activeScansPerAccount: 1,
          concurrentScans: limits.maxConcurrent,
          queueCapacity: limits.maxQueue,
          scanBudgetSeconds: SCAN_BUDGET_MS / 1000,
          scanTimeoutSeconds: (config.scanTimeoutMs ?? SCAN_TIMEOUT_MS) / 1000,
          cacheTtlSeconds: CACHE_TTL_MS / 1000,
          supportedPorts: [...ALLOWED_PORTS],
        },
        /* Live load of THIS process, so an operator (or the load check) can see
           the line without reading logs. Counts only — never a target or a
           client. */
        load: coordinator.stats(),
      },
    })
  })

  router.get('/usage', handle('usage'))
  router.post('/', readScanBody, handle('json'))
  router.post('/stream', readScanBody, handle('stream'))
  router.all('/stream', (_req, res) => {
    res.setHeader('Allow', 'POST')
    res.setHeader('Cache-Control', 'no-store')
    reject(res, 405, 'METHOD_NOT_ALLOWED', 'Use an authenticated POST request to start an assessment.')
  })
  router.use((error: { type?: string }, _req: Request, res: Response, _next: unknown) => {
    res.setHeader('Cache-Control', 'no-store')
    if (error.type === 'entity.too.large') reject(res, 413, 'PAYLOAD_TOO_LARGE', 'The scan request is too large.')
    else reject(res, 400, 'INVALID_REQUEST', 'Send a valid JSON scan request.')
  })

  return router
}

function stripUndefined<T extends object>(value: T): Partial<T> {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined)) as Partial<T>
}

/**
 * Replay the workflow rail for a cached report so a cache hit still renders the
 * six completed stages instead of an empty progress panel.
 */
function cachedStages(report: PublicScanReport): PublicScanStage[] {
  const { evidence, executive } = report
  const certificate = evidence.certificateExtras
  /* The replay must reproduce the SAME states the live run emitted. When the port
     never answered, three of these modules were `unavailable`, not `failed` — a
     cache hit that repainted them red would contradict the live rail for the
     identical assessment. */
  const unreachable = report.unreachable
  const reason = report.reachability?.detail ?? 'Endpoint did not answer'
  const transportHeaders = evidence.http.headers.filter(
    (header) => header.name !== 'strict-transport-security' && header.applicable !== false,
  )
  const transportHardened = transportHeaders.filter((header) => header.secure).length
  // Older cached reports predate the flag; a scored readiness implies assessment.
  const cryptoAssessed = evidence.engines?.crypto?.data?.assessed ?? executive.postQuantumReadiness !== null
  return [
    {
      key: 'dns',
      label: 'DNS Resolution',
      description: 'Resolving public records and CAA policy',
      state: evidence.dns.addressCount ? 'complete' : 'failed',
      detail: `${evidence.dns.addressCount} address${evidence.dns.addressCount === 1 ? '' : 'es'}, CAA ${
        evidence.dns.caaQueryable && evidence.dns.caaClimbComplete
          ? evidence.dns.caaPresent
            ? 'present'
            : 'absent'
          : 'unknown'
      }`,
    },
    {
      key: 'tls',
      label: 'TLS Handshake',
      description: 'Negotiating protocols and cipher suites',
      state: unreachable ? 'unavailable' : report.degraded ? 'failed' : 'complete',
      // The live stage line's own wording (`tlsStageDetail`), so a cache hit
      // cannot say "classical groups only" about a probe that never settled.
      detail: unreachable
        ? reason
        : tlsStageDetail({
            negotiatedProtocol: evidence.tls?.tlsVersion ?? null,
            hybridGroups: evidence.keyAgreement.hybridGroups,
            pureKemGroups: evidence.keyAgreement.pureKemGroups,
            hybridSettled: evidence.keyAgreement.hybridSettled,
            supportedProtocols: evidence.tls?.supportedProtocols ?? [],
          }),
    },
    {
      key: 'certificate',
      label: 'Certificate Collection',
      description: 'Reading the served X.509 chain',
      state: certificate ? 'complete' : unreachable ? 'unavailable' : 'failed',
      detail: certificate
        ? `${certificate.sanCount} SAN${certificate.sanCount === 1 ? '' : 's'} · chain depth ${certificate.chainDepth}`
        : unreachable
          ? `Not collected — ${reason}`
          : 'Certificate chain unavailable',
    },
    {
      key: 'headers',
      label: 'Security Header Analysis',
      description: 'Inspecting HTTP transport controls',
      state: evidence.http.reachable ? 'complete' : unreachable ? 'unavailable' : 'failed',
      // The `http-security` row's population — HSTS and superseded headers are
      // not in it — exactly as the live stage line counts it.
      detail: evidence.http.reachable
        ? `HTTP ${evidence.http.statusCode} · ${transportHardened}/${transportHeaders.length} hardened`
        : unreachable
          ? `Not collected — ${reason}`
          : 'Origin unreachable',
    },
    {
      key: 'quantum',
      label: 'Quantum Assessment',
      description: 'Scoring post-quantum exposure',
      /* The engine's own assessed/not-assessed verdict decides the state, as it
         does live. Keying it off the readiness turned a completed module whose
         hybrid probe merely did not settle into "no cryptographic evidence was
         collected" — untrue for a run with a handshake and a chain. */
      state: cryptoAssessed ? 'complete' : 'unavailable',
      detail: cryptoAssessed
        ? quantumStageDetail(executive)
        : (evidence.engines?.crypto?.data?.notAssessedReason ?? 'Not assessed — no cryptographic evidence was collected.'),
    },
    {
      key: 'report',
      label: 'Executive Report',
      description: 'Composing the executive assessment',
      state: 'complete',
      detail: `Cached result from ${new Date(report.completedAt).toUTCString().replace('GMT', 'UTC')}`,
    },
  ]
}

/** The process-wide public scan router, configured from the environment. */
export default createPublicScanRouter()
