/**
 * QGuard Helix — Public Quantum Exposure Assessment™ API
 *
 * Unauthenticated, edge-only scanner. Mounted BEFORE the subscription gateway
 * so anonymous visitors can run an assessment without an account.
 *
 * Security posture for an open endpoint:
 *  - strict input validation + sanitisation (reuses the scanner asset validator)
 *  - SSRF protection: private/loopback/link-local targets are refused, and the
 *    reused TLS analyzer re-validates every resolved address
 *  - per-client rate limiting on NEW scans, a per-client cap on active scans,
 *    and a global concurrency cap with a bounded, fair waiting line
 *  - one shared scan per target, and no scan for a visitor who has left
 *  - hard scan timeout
 *  - short-lived result cache keyed by host:port (cuts repeat load and abuse)
 *  - privacy-first logging: only host + outcome, never client identifiers
 */

import { Router, type Request, type Response } from 'express'
import net from 'node:net'
import { validateAsset } from '@/lib/scanner/asset-validator'
import { assessPublicTarget } from '@/lib/scanner/public-scan/assess'
import { ScanCancelledError, type ObservationSink } from '@/lib/scanner/public-scan/engines'
import type { PublicScanReport, PublicScanStage } from '@/lib/scanner/public-scan/types'
import { trustedClientIp } from './runtime/client-ip'
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
const ALLOWED_PORTS = new Set([443, 8443, 9443, 4443, 10443])
/** How long a scan nobody is watching survives — a reload or reconnect keeps its place. */
const ABANDON_GRACE_MS = 4_000

/** A positive integer from the environment, clamped, or the default. */
function envInt(name: string, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(process.env[name] ?? '', 10)
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback
}

const BLOCKED_HOST_SUFFIXES = ['.local', '.internal', '.localdomain', '.home.arpa', '.lan']
const BLOCKED_HOSTS = new Set(['localhost', 'ip6-localhost', 'metadata.google.internal', 'instance-data'])
const PRIVATE_IP_PATTERNS = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^0\./,
  /^169\.254\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^::1$/,
  /^fc00:/i,
  /^fd00:/i,
  /^fe80:/i,
]

// ─── Client identity ──────────────────────────────────────────────────────────

/**
 * The client a rate limit and an active-scan cap are charged to.
 *
 * Trustworthy only when `TRUSTED_CLIENT_IP_HEADER` names a header the edge
 * guarantees. Without it the fallback is the leftmost `X-Forwarded-For`, which
 * any caller can set — the deployment config warns about exactly this.
 */
function readClientIp(req: Request): string {
  const trusted = trustedClientIp(req)
  if (trusted) return trusted
  const forwarded = req.headers['x-forwarded-for']
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim()
  const realIp = req.headers['x-real-ip']
  if (typeof realIp === 'string' && realIp.trim()) return realIp.trim()
  return req.ip || req.socket.remoteAddress || 'unknown'
}

// ─── Target resolution ────────────────────────────────────────────────────────

function resolveTarget(raw: unknown): { target: QueueTarget } | { error: { code: string; message: string } } {
  if (typeof raw !== 'string' || !raw.trim()) {
    return { error: { code: 'MISSING_TARGET', message: 'Enter a domain or https:// URL to assess.' } }
  }
  if (raw.length > 253 + 16) {
    return { error: { code: 'TARGET_TOO_LONG', message: 'Target exceeds the maximum hostname length.' } }
  }

  const validated = validateAsset(raw)
  if (!validated.valid) {
    return { error: { code: 'INVALID_TARGET', message: validated.error || 'Target is not a valid domain or URL.' } }
  }
  if (validated.type === 'subnet') {
    return { error: { code: 'UNSUPPORTED_TARGET', message: 'Subnet ranges are not supported by the public scanner.' } }
  }
  if (validated.protocol === 'ssh' || validated.protocol === 'git') {
    return { error: { code: 'UNSUPPORTED_TARGET', message: 'The public scanner assesses HTTPS endpoints only.' } }
  }

  const host = validated.host.toLowerCase()
  const port = validated.port ?? 443

  if (!ALLOWED_PORTS.has(port)) {
    return {
      error: {
        code: 'UNSUPPORTED_PORT',
        message: `Port ${port} is not assessed by the public scanner. Supported: ${[...ALLOWED_PORTS].join(', ')}.`,
      },
    }
  }
  if (BLOCKED_HOSTS.has(host) || BLOCKED_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
    return { error: { code: 'PRIVATE_TARGET', message: 'Internal and loopback hostnames cannot be assessed publicly.' } }
  }
  if (net.isIP(host) && PRIVATE_IP_PATTERNS.some((pattern) => pattern.test(host))) {
    return { error: { code: 'PRIVATE_TARGET', message: 'Private and reserved IP ranges cannot be assessed publicly.' } }
  }
  if (!net.isIP(host) && !host.includes('.')) {
    return { error: { code: 'INVALID_TARGET', message: 'Enter a fully-qualified domain such as example.com.' } }
  }

  return { target: { input: raw.trim(), host, port, key: `${host}:${port}` } }
}

// ─── The router ───────────────────────────────────────────────────────────────

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

  /**
   * Would one more NEW scan for this client fit in its window? Checking and
   * charging are separate on purpose: the limit used to be charged before the
   * capacity check and before the cache, so a visitor retrying through "busy"
   * spent their whole minute on refusals, and a cache hit — which costs nothing
   * — still counted. Only a scan this client actually starts is charged now.
   */
  const peekRateLimit = (ip: string): { allowed: boolean; retryAfterSeconds: number } => {
    const now = Date.now()
    const entry = rateBuckets.get(ip)
    if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS || entry.count < limits.rateLimitPerMinute) {
      return { allowed: true, retryAfterSeconds: 0 }
    }
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil((RATE_LIMIT_WINDOW_MS - (now - entry.windowStart)) / 1000)),
    }
  }

  const chargeRateLimit = (ip: string): void => {
    const now = Date.now()
    if (rateBuckets.size > RATE_LIMIT_MAX_TRACKED_IPS) {
      for (const [key, entry] of rateBuckets) {
        if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS) rateBuckets.delete(key)
      }
    }
    const entry = rateBuckets.get(ip)
    if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
      rateBuckets.set(ip, { count: 1, windowStart: now })
      return
    }
    entry.count += 1
  }

  // ── result cache ──────────────────────────────────────────────────────────

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
      writeCache(target.key, report)
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
    onFailure: (target, message, durationMs) => {
      if (log) console.warn(`[public-scan] ${target.host}:${target.port} → failed after ${durationMs}ms: ${message}`)
    },
  })

  /**
   * Admit one request: join the job already running for this target, or —
   * rate limit permitting — create one (running or queued). The limit is
   * charged only when a scan is actually created for this client.
   */
  const admit = (
    target: QueueTarget,
    clientId: string,
    send: (event: QueueEvent) => void,
    allowQueue: boolean,
  ):
    | { admitted: true; unsubscribe: () => void }
    | { admitted: false; status: number; code: string; message: string; retryAfterSeconds: number } => {
    if (!coordinator.has(target.key)) {
      const limit = peekRateLimit(clientId)
      if (!limit.allowed) {
        return {
          admitted: false,
          status: 429,
          code: 'RATE_LIMITED',
          message: `Each visitor may start ${limits.rateLimitPerMinute} new assessments per minute. You can start another in ${limit.retryAfterSeconds}s — viewing a site someone else is already assessing does not count.`,
          retryAfterSeconds: limit.retryAfterSeconds,
        }
      }
    }
    const admission = coordinator.subscribe(target, clientId, send, { allowQueue })
    if (admission.admitted === false) {
      return {
        admitted: false,
        status: admission.code === 'CLIENT_BUSY' ? 429 : 503,
        code: admission.code,
        message: admission.message,
        retryAfterSeconds: admission.retryAfterSeconds,
      }
    }
    if (admission.created) chargeRateLimit(clientId)
    return { admitted: true, unsubscribe: admission.unsubscribe }
  }

  // ── routes ────────────────────────────────────────────────────────────────

  /** Scanner capability disclosure — what the public scanner does and does not do. */
  router.get('/capabilities', (_req, res) => {
    res.json({
      data: {
        name: 'Public Quantum Exposure Assessment',
        version: '1.1.0',
        authentication: 'none',
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
          scansPerMinutePerClient: limits.rateLimitPerMinute,
          activeScansPerClient: limits.maxActivePerClient,
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

  /**
   * One-shot assessment. Returns the complete report as JSON.
   *
   * For scripts, not people: it joins a scan already running for the target or
   * starts one if a slot is free, but it never waits in the line — a busy
   * server answers 503 with `Retry-After`, which a script handles better than a
   * held connection.
   */
  router.post('/', async (req: Request, res: Response) => {
    const resolved = resolveTarget(req.body?.target)
    if ('error' in resolved) {
      res.status(400).json({ error: resolved.error })
      return
    }

    const cached = readCache(resolved.target.key)
    if (cached) {
      res.setHeader('Cache-Control', 'public, max-age=60')
      res.json({ data: cached })
      return
    }

    let settle: (event: QueueEvent) => void = () => undefined
    const outcome = new Promise<QueueEvent>((resolve) => {
      settle = resolve
    })
    const admission = admit(
      resolved.target,
      readClientIp(req),
      (event) => {
        if (event.type === 'complete' || event.type === 'failed') settle(event)
      },
      false,
    )
    if (admission.admitted === false) {
      res.setHeader('Retry-After', String(admission.retryAfterSeconds))
      res.status(admission.status).json({
        error: { code: admission.code, message: admission.message, retryAfterSeconds: admission.retryAfterSeconds },
      })
      return
    }
    // The caller hanging up is the same signal as a visitor closing the tab.
    res.on('close', () => admission.unsubscribe())

    const event = await outcome
    if (res.writableEnded || res.destroyed) return
    if (event.type === 'complete') {
      res.setHeader('Cache-Control', 'public, max-age=60')
      res.json({ data: event.report })
    } else if (event.type === 'failed') {
      res.status(502).json({ error: { code: 'SCAN_FAILED', message: event.message } })
    }
  })

  /**
   * Streaming assessment (SSE).
   *
   * Events, in order: `scan-start`; then either `scan-queued` (repeated as the
   * line moves) followed by `scan-started`, or `scan-started` at once;
   * `scan-shared` when the visitor joined a scan someone else started; `stage`
   * and `observation` as measurements land; finally `scan-complete` or `error`.
   *
   * A refusal — invalid target, rate limit, full line — is delivered IN the
   * stream as `scan-refused` when the caller is an EventSource. A browser
   * cannot read the body of a non-200 event-stream response, so every refusal
   * used to surface as "Connection to the assessment service was lost".
   * Callers that do not ask for `text/event-stream` still receive the HTTP
   * status and JSON body.
   */
  router.get('/stream', (req: Request, res: Response) => {
    const wantsStream = String(req.headers.accept ?? '').includes('text/event-stream')

    const openStream = () => {
      res.status(200)
      res.setHeader('Content-Type', 'text/event-stream')
      res.setHeader('Cache-Control', 'no-cache, no-transform')
      res.setHeader('Connection', 'keep-alive')
      res.setHeader('X-Accel-Buffering', 'no')
      res.flushHeaders?.()
    }
    const write = (event: string, payload: unknown) => {
      if (!res.writableEnded) res.write(`event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`)
    }

    const refuse = (status: number, code: string, message: string, retryAfterSeconds?: number) => {
      if (retryAfterSeconds) res.setHeader('Retry-After', String(retryAfterSeconds))
      if (!wantsStream) {
        res.status(status).json({ error: { code, message, ...(retryAfterSeconds ? { retryAfterSeconds } : {}) } })
        return
      }
      openStream()
      /* A finished stream is reconnected by EventSource after `retry` ms. The
         client closes on this event; the long retry is the belt to those
         braces, so a refusal can never become a reconnect loop against a busy
         server. */
      res.write('retry: 86400000\n\n')
      write('scan-refused', { code, status, message, retryAfterSeconds: retryAfterSeconds ?? null, timestamp: new Date().toISOString() })
      res.end()
    }

    const resolved = resolveTarget(req.query.target)
    if ('error' in resolved) {
      refuse(400, resolved.error.code, resolved.error.message)
      return
    }
    const { target } = resolved

    /* A very recent result is served before any gate: it costs nothing, so it
       is neither refused when the scanner is busy nor charged to the visitor. */
    const cached = readCache(target.key, STREAM_CACHE_TTL_MS)
    if (cached) {
      openStream()
      write('scan-start', { target: target.host, port: target.port, timestamp: new Date().toISOString() })
      for (const stage of cached.evidence ? cachedStages(cached) : []) {
        write('stage', { stage, timestamp: new Date().toISOString() })
      }
      write('scan-complete', { report: cached, timestamp: new Date().toISOString() })
      res.end()
      return
    }

    /* Events can arrive during admission itself (a queue position, a late
       joiner's replay), before the response is open — so they are held and
       flushed once it is. */
    let open = false
    const held: QueueEvent[] = []
    let heartbeat: ReturnType<typeof setInterval> | null = null
    const finish = () => {
      if (heartbeat) clearInterval(heartbeat)
      heartbeat = null
      if (!res.writableEnded) res.end()
    }
    const deliver = (event: QueueEvent) => {
      const name = STREAM_EVENT[event.type]
      const timestamp = new Date().toISOString()
      switch (event.type) {
        case 'stage':
          write(name, { stage: event.stage, timestamp })
          break
        case 'observation':
          write(name, event.observation)
          break
        case 'complete':
          write(name, { report: event.report, timestamp })
          finish()
          break
        case 'failed':
          write(name, { code: 'SCAN_FAILED', message: event.message, timestamp })
          finish()
          break
        case 'queued':
          write(name, {
            position: event.position,
            queueLength: event.queueLength,
            estimatedWaitSeconds: event.estimatedWaitSeconds,
            running: event.running,
            capacity: event.capacity,
            timestamp,
          })
          break
        case 'shared':
          write(name, { viewers: event.viewers, state: event.state, timestamp })
          break
        case 'started':
          write(name, { timestamp })
          break
      }
    }

    const admission = admit(target, readClientIp(req), (event) => (open ? deliver(event) : held.push(event)), true)
    if (admission.admitted === false) {
      refuse(admission.status, admission.code, admission.message, admission.retryAfterSeconds)
      return
    }

    openStream()
    open = true
    write('scan-start', { target: target.host, port: target.port, timestamp: new Date().toISOString() })
    for (const event of held.splice(0)) deliver(event)
    heartbeat = setInterval(() => {
      if (!res.writableEnded) res.write(': heartbeat\n\n')
    }, 15_000)

    /* `res` 'close' — not `req` — fires when the visitor goes away: on a GET
       the request side can finish long before the connection does. Leaving
       releases this viewer; the coordinator stops the scan once nobody is
       left. */
    res.on('close', () => {
      finish()
      admission.unsubscribe()
    })
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
      detail: unreachable
        ? reason
        : `${evidence.tls?.tlsVersion ?? 'n/a'} · ${
            evidence.keyAgreement.hybridGroups.length
              ? `hybrid PQ (${evidence.keyAgreement.hybridGroups[0]})`
              : 'classical groups only'
          }`,
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
      detail: evidence.http.reachable
        ? `HTTP ${evidence.http.statusCode} · ${evidence.http.headers.filter((h) => h.secure).length}/${evidence.http.headers.length} hardened`
        : unreachable
          ? `Not collected — ${reason}`
          : 'Origin unreachable',
    },
    {
      key: 'quantum',
      label: 'Quantum Assessment',
      description: 'Scoring post-quantum exposure',
      state: executive.postQuantumReadiness === null ? 'unavailable' : 'complete',
      detail:
        executive.postQuantumReadiness === null
          ? 'Not assessed — no cryptographic evidence was collected.'
          : `PQ readiness ${executive.postQuantumReadiness}% · encryption ${executive.encryptionScore ?? '—'}/100`,
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
