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
 *  - per-IP token bucket rate limiting + a global in-flight concurrency cap
 *  - hard scan timeout
 *  - short-lived result cache keyed by host:port (cuts repeat load and abuse)
 *  - privacy-first logging: only host + outcome, never client identifiers
 */

import { Router, type Request, type Response } from 'express'
import net from 'node:net'
import { validateAsset } from '@/lib/scanner/asset-validator'
import { assessPublicTarget } from '@/lib/scanner/public-scan/assess'
import type { ObservationSink } from '@/lib/scanner/public-scan/engines'
import type { PublicScanReport, PublicScanStage } from '@/lib/scanner/public-scan/types'

const router = Router()

// ─── Limits ───────────────────────────────────────────────────────────────────

/**
 * Two budgets, and the difference between them is the point.
 *
 * `SCAN_BUDGET_MS` is what the ENGINES are told they have. They treat it as a
 * degrade-by time: when it expires they return what they measured and mark the
 * rest inconclusive, so the visitor always gets a report with its limits stated.
 * A healthy endpoint finishes in 3-6s and never comes near it.
 *
 * `SCAN_TIMEOUT_MS` is a backstop for a bug, not a scanning strategy. It exists
 * only so a wedged promise cannot hold a connection open forever. Reaching it
 * means something is wrong with the scanner, not with the target.
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
 * Rate limiting, not caching, is the abuse control for the stream.
 */
const STREAM_CACHE_TTL_MS = 45 * 1000
const CACHE_MAX_ENTRIES = 400
const RATE_LIMIT_WINDOW_MS = 60_000
const RATE_LIMIT_MAX_SCANS = 5
const RATE_LIMIT_MAX_TRACKED_IPS = 5_000
const MAX_CONCURRENT_SCANS = 6
const ALLOWED_PORTS = new Set([443, 8443, 9443, 4443, 10443])

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

// ─── Rate limiting ────────────────────────────────────────────────────────────

interface RateEntry {
  count: number
  windowStart: number
}

const rateBuckets = new Map<string, RateEntry>()

function readClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for']
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim()
  const realIp = req.headers['x-real-ip']
  if (typeof realIp === 'string' && realIp.trim()) return realIp.trim()
  return req.ip || req.socket.remoteAddress || 'unknown'
}

function checkRateLimit(ip: string): { allowed: boolean; retryAfterSeconds: number; remaining: number } {
  const now = Date.now()

  if (rateBuckets.size > RATE_LIMIT_MAX_TRACKED_IPS) {
    for (const [key, entry] of rateBuckets) {
      if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS) rateBuckets.delete(key)
    }
  }

  const entry = rateBuckets.get(ip)
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateBuckets.set(ip, { count: 1, windowStart: now })
    return { allowed: true, retryAfterSeconds: 0, remaining: RATE_LIMIT_MAX_SCANS - 1 }
  }

  entry.count += 1
  if (entry.count > RATE_LIMIT_MAX_SCANS) {
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil((RATE_LIMIT_WINDOW_MS - (now - entry.windowStart)) / 1000),
      remaining: 0,
    }
  }
  return { allowed: true, retryAfterSeconds: 0, remaining: RATE_LIMIT_MAX_SCANS - entry.count }
}

// ─── Result cache ─────────────────────────────────────────────────────────────

interface CacheEntry {
  report: PublicScanReport
  storedAt: number
  expiresAt: number
}

const resultCache = new Map<string, CacheEntry>()

/**
 * `maxAgeMs` lets a caller demand a fresher entry than the cache's own TTL.
 * The stream uses it to keep a live assessment live; the one-shot JSON API
 * takes the full TTL.
 */
function readCache(key: string, maxAgeMs = CACHE_TTL_MS): PublicScanReport | null {
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

function writeCache(key: string, report: PublicScanReport): void {
  if (resultCache.size >= CACHE_MAX_ENTRIES) {
    const oldest = resultCache.keys().next().value
    if (oldest) resultCache.delete(oldest)
  }
  resultCache.set(key, { report, storedAt: Date.now(), expiresAt: Date.now() + CACHE_TTL_MS })
}

// ─── Concurrency guard ────────────────────────────────────────────────────────

let inFlight = 0

// ─── Target resolution ────────────────────────────────────────────────────────

interface ResolvedTarget {
  input: string
  host: string
  port: number
  cacheKey: string
}

function resolveTarget(raw: unknown): { target: ResolvedTarget } | { error: { code: string; message: string } } {
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

  return { target: { input: raw.trim(), host, port, cacheKey: `${host}:${port}` } }
}

// ─── Scan execution ───────────────────────────────────────────────────────────

async function runScan(
  target: ResolvedTarget,
  onStage?: (stage: PublicScanStage) => void,
  onObservation?: ObservationSink,
): Promise<PublicScanReport> {
  inFlight += 1
  const startedAt = Date.now()
  try {
    const report = await Promise.race([
      assessPublicTarget({
        input: target.input,
        host: target.host,
        port: target.port,
        onStage,
        onObservation,
        budgetMs: SCAN_BUDGET_MS,
      }),
      new Promise<never>((_resolve, reject) =>
        setTimeout(() => reject(new Error('Assessment exceeded the public scan time budget.')), SCAN_TIMEOUT_MS),
      ),
    ])
    writeCache(target.cacheKey, report)
    // Privacy-first logging: target host + outcome only, no client identifiers.
    console.info(
      `[public-scan] ${target.host}:${target.port} → ` +
        (report.unreachable
          ? `unreachable (${report.reachability.state})`
          : `grade ${report.executive.grade}, pq ${report.executive.postQuantumReadiness ?? 'n/a'}%`) +
        `, ${Date.now() - startedAt}ms`,
    )
    return report
  } finally {
    inFlight -= 1
  }
}

// ─── Routes ───────────────────────────────────────────────────────────────────

/** Scanner capability disclosure — what the public scanner does and does not do. */
router.get('/capabilities', (_req, res) => {
  res.json({
    data: {
      name: 'Public Quantum Exposure Assessment',
      version: '1.0.0',
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
        scansPerMinutePerClient: RATE_LIMIT_MAX_SCANS,
        scanBudgetSeconds: SCAN_BUDGET_MS / 1000,
        scanTimeoutSeconds: SCAN_TIMEOUT_MS / 1000,
        cacheTtlSeconds: CACHE_TTL_MS / 1000,
        supportedPorts: [...ALLOWED_PORTS],
      },
    },
  })
})

/** One-shot assessment. Returns the complete report as JSON. */
router.post('/', async (req: Request, res: Response) => {
  const resolved = resolveTarget(req.body?.target)
  if ('error' in resolved) {
    res.status(400).json({ error: resolved.error })
    return
  }

  const cached = readCache(resolved.target.cacheKey)
  if (cached) {
    res.setHeader('Cache-Control', 'public, max-age=60')
    res.json({ data: cached })
    return
  }

  const limit = checkRateLimit(readClientIp(req))
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfterSeconds))
    res.status(429).json({
      error: {
        code: 'RATE_LIMITED',
        message: `Public assessments are limited to ${RATE_LIMIT_MAX_SCANS} per minute. Try again in ${limit.retryAfterSeconds}s.`,
      },
    })
    return
  }

  if (inFlight >= MAX_CONCURRENT_SCANS) {
    res.setHeader('Retry-After', '10')
    res.status(503).json({
      error: { code: 'SCANNER_BUSY', message: 'The public scanner is at capacity. Please retry in a few seconds.' },
    })
    return
  }

  try {
    const report = await runScan(resolved.target)
    res.setHeader('Cache-Control', 'public, max-age=60')
    res.json({ data: report })
  } catch (err) {
    res.status(502).json({ error: { code: 'SCAN_FAILED', message: (err as Error).message } })
  }
})

/**
 * Streaming assessment (SSE). Emits `stage` events for the live workflow rail,
 * then a single `scan-complete` carrying the full report.
 */
router.get('/stream', async (req: Request, res: Response) => {
  const resolved = resolveTarget(req.query.target)
  if ('error' in resolved) {
    res.status(400).json({ error: resolved.error })
    return
  }

  const limit = checkRateLimit(readClientIp(req))
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfterSeconds))
    res.status(429).json({
      error: {
        code: 'RATE_LIMITED',
        message: `Public assessments are limited to ${RATE_LIMIT_MAX_SCANS} per minute. Try again in ${limit.retryAfterSeconds}s.`,
      },
    })
    return
  }

  if (inFlight >= MAX_CONCURRENT_SCANS) {
    res.setHeader('Retry-After', '10')
    res.status(503).json({
      error: { code: 'SCANNER_BUSY', message: 'The public scanner is at capacity. Please retry in a few seconds.' },
    })
    return
  }

  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()

  let closed = false
  req.on('close', () => {
    closed = true
  })

  const send = (event: string, payload: unknown) => {
    if (closed) return
    res.write(`event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`)
  }

  const heartbeat = setInterval(() => {
    if (!closed) res.write(': heartbeat\n\n')
  }, 15_000)

  send('scan-start', {
    target: resolved.target.host,
    port: resolved.target.port,
    timestamp: new Date().toISOString(),
  })

  try {
    // Only a very recent result short-circuits the stream — see
    // STREAM_CACHE_TTL_MS. Anything older is re-measured live.
    const cached = readCache(resolved.target.cacheKey, STREAM_CACHE_TTL_MS)
    if (cached) {
      for (const stage of cached.evidence ? cachedStages(cached) : []) {
        send('stage', { stage, timestamp: new Date().toISOString() })
      }
      send('scan-complete', { report: cached, timestamp: new Date().toISOString() })
      return
    }

    const report = await runScan(
      resolved.target,
      (stage) => {
        send('stage', { stage, timestamp: new Date().toISOString() })
      },
      // Each observation is written the instant the measurement completes, so
      // the hero fills in over the real duration of the assessment instead of
      // in one burst when the report is composed.
      (observation) => {
        send('observation', observation)
      },
    )
    send('scan-complete', { report, timestamp: new Date().toISOString() })
  } catch (err) {
    send('error', {
      code: 'SCAN_FAILED',
      message: (err as Error).message,
      timestamp: new Date().toISOString(),
    })
  } finally {
    clearInterval(heartbeat)
    if (!closed) res.end()
  }
})

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
        evidence.dns.caaQueryable ? (evidence.dns.caaPresent ? 'present' : 'absent') : 'unknown'
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

export default router
