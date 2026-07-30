/**
 * QGuard Helix — HTTP Security Engine
 *
 * Analyses the full OWASP transport-security header set, plus HSTS preload
 * eligibility and infrastructure fingerprinting (CDN / WAF / cloud / proxy).
 *
 * TRANSPORT RESILIENCE
 * --------------------
 * This engine deliberately does NOT use `fetch()`. Node's fetch enforces
 * certificate validation and rejects the connection outright on an expired,
 * self-signed or untrusted chain — which are precisely the targets whose
 * headers an assessment most needs to read. The result was HSTS and every other
 * header reporting "Not observable" for a reason that had nothing to do with
 * the headers themselves.
 *
 * It uses `https.request` with a permissive agent instead: the chain verdict is
 * captured separately by the certificate engine, and no request body or
 * credential is ever sent, so reading response headers over an untrusted chain
 * carries no risk to anyone.
 */

import https from 'node:https'
import http from 'node:http'
import net from 'node:net'
import { URL } from 'node:url'
import { canFollowRedirect, checkHostSyntax, safeLookup } from '../safe-dns'
import {
  type ControlStatus,
  type Evidence,
  type EngineResult,
  clampScore,
  retryTransient,
  runEngine,
} from './contract'

const HTTP_TIMEOUT = 8_000
const MAX_REDIRECTS = 5

/** OWASP Secure Headers, grouped by how strongly they are expected. */
export type HeaderGroup = 'Critical' | 'Recommended' | 'Optional'

interface HeaderSpec {
  name: string
  group: HeaderGroup
  purpose: string
  recommendation: string
  /** Returns null when present-and-acceptable, or a reason when weak. */
  weakness?: (value: string) => string | null
}

const HEADER_SPECS: HeaderSpec[] = [
  {
    name: 'strict-transport-security',
    group: 'Critical',
    purpose: 'Forces HTTPS on every subsequent visit.',
    recommendation: 'Send max-age of at least one year with includeSubDomains and preload.',
    weakness: (value) => {
      const maxAge = Number.parseInt(value.match(/max-age\s*=\s*"?(\d+)/i)?.[1] || '0', 10)
      if (maxAge < 31_536_000) return `max-age=${maxAge} is below the one-year (31536000) recommendation`
      if (!/includeSubDomains/i.test(value)) return 'includeSubDomains is not set'
      return null
    },
  },
  {
    name: 'content-security-policy',
    group: 'Critical',
    purpose: 'Restricts which resources the page may load.',
    recommendation: 'Publish a Content-Security-Policy with a restrictive default-src.',
    weakness: (value) =>
      /unsafe-inline|unsafe-eval/i.test(value)
        ? 'policy allows unsafe-inline or unsafe-eval'
        : /default-src/i.test(value)
          ? null
          : 'no default-src directive',
  },
  {
    name: 'x-content-type-options',
    group: 'Critical',
    purpose: 'Stops MIME-type sniffing.',
    recommendation: 'Send X-Content-Type-Options: nosniff on every response.',
    weakness: (value) => (/nosniff/i.test(value) ? null : `unexpected value "${value}"`),
  },
  {
    name: 'x-frame-options',
    group: 'Recommended',
    purpose: 'Prevents the page being framed (clickjacking).',
    recommendation: 'Set X-Frame-Options: DENY, or CSP frame-ancestors.',
    weakness: (value) =>
      /^(deny|sameorigin)$/i.test(value.trim()) ? null : `unexpected value "${value}"`,
  },
  {
    name: 'referrer-policy',
    group: 'Recommended',
    purpose: 'Controls how much referrer data leaks cross-origin.',
    recommendation: 'Set Referrer-Policy to strict-origin-when-cross-origin or stricter.',
    weakness: (value) =>
      /no-referrer|strict-origin|same-origin/i.test(value) ? null : `weak policy "${value}"`,
  },
  {
    name: 'permissions-policy',
    group: 'Recommended',
    purpose: 'Restricts access to powerful browser features.',
    recommendation: 'Declare a Permissions-Policy limiting camera, microphone and geolocation.',
  },
  {
    name: 'cross-origin-opener-policy',
    group: 'Optional',
    purpose: 'Isolates the browsing context (Spectre mitigation).',
    recommendation: 'Set Cross-Origin-Opener-Policy: same-origin.',
    weakness: (value) => (/same-origin/i.test(value) ? null : `weaker value "${value}"`),
  },
  {
    name: 'cross-origin-embedder-policy',
    group: 'Optional',
    purpose: 'Requires explicit opt-in for cross-origin resources.',
    recommendation: 'Set Cross-Origin-Embedder-Policy: require-corp for full isolation.',
  },
  {
    name: 'cross-origin-resource-policy',
    group: 'Optional',
    purpose: 'Controls which origins may embed this resource.',
    recommendation: 'Set Cross-Origin-Resource-Policy: same-origin or same-site.',
  },
]

export interface SecurityHeaderResult {
  name: string
  group: HeaderGroup
  present: boolean
  value: string | null
  /** Healthy | Warning | Not Supported (absent) | Unknown (origin unreachable). */
  status: ControlStatus
  purpose: string
  weakness: string | null
  recommendation: string
}

export interface HstsAnalysis {
  present: boolean
  status: ControlStatus
  raw: string | null
  maxAge: number | null
  includeSubDomains: boolean
  preload: boolean
  /** Meets the hstspreload.org submission requirements. */
  preloadEligible: boolean
  preloadBlockers: string[]
}

export interface HttpFingerprint {
  server: string | null
  poweredBy: string | null
  cdn: string | null
  waf: string | null
  cloudProvider: string | null
  reverseProxy: string | null
  /** Header names that gave the infrastructure away, for the evidence line. */
  signals: string[]
}

export interface HttpIntelligence {
  reachable: boolean
  statusCode: number | null
  httpVersion: string | null
  finalUrl: string | null
  redirected: boolean
  redirectChain: string[]
  redirectedToHttps: boolean
  /** True when plain HTTP on :80 redirects to HTTPS. */
  httpToHttpsRedirect: boolean | null
  responseMs: number | null
  headers: SecurityHeaderResult[]
  rawHeaderNames: string[]
  hsts: HstsAnalysis
  fingerprint: HttpFingerprint
  cookies: Array<{ name: string; secure: boolean; httpOnly: boolean; sameSite: string | null }>
  error: string | null
}

function emptyHsts(status: ControlStatus): HstsAnalysis {
  return {
    present: false,
    status,
    raw: null,
    maxAge: null,
    includeSubDomains: false,
    preload: false,
    preloadEligible: false,
    preloadBlockers: [],
  }
}

function emptyHttp(error: string | null): HttpIntelligence {
  return {
    reachable: false,
    statusCode: null,
    httpVersion: null,
    finalUrl: null,
    redirected: false,
    redirectChain: [],
    redirectedToHttps: false,
    httpToHttpsRedirect: null,
    responseMs: null,
    headers: HEADER_SPECS.map((spec) => ({
      name: spec.name,
      group: spec.group,
      present: false,
      value: null,
      // Origin unreachable ⇒ Unknown, never "missing".
      status: 'Unknown' as ControlStatus,
      purpose: spec.purpose,
      weakness: null,
      recommendation: spec.recommendation,
    })),
    rawHeaderNames: [],
    hsts: emptyHsts('Unknown'),
    fingerprint: {
      server: null,
      poweredBy: null,
      cdn: null,
      waf: null,
      cloudProvider: null,
      reverseProxy: null,
      signals: [],
    },
    cookies: [],
    error,
  }
}

// ─── Raw request (permissive TLS so broken-chain hosts still answer) ─────────

interface RawResponse {
  statusCode: number
  httpVersion: string
  headers: http.IncomingHttpHeaders
  url: string
  elapsedMs: number
}

function rawRequest(target: string, method: 'GET' | 'HEAD' = 'GET'): Promise<RawResponse | null> {
  return new Promise((resolve) => {
    let settled = false
    const startedAt = Date.now()
    const finish = (value: RawResponse | null) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(value)
    }

    let url: URL
    try {
      url = new URL(target)
    } catch {
      resolve(null)
      return
    }

    const transport = url.protocol === 'http:' ? http : https
    const options: https.RequestOptions = {
      method,
      host: url.hostname,
      port: url.port || (url.protocol === 'http:' ? 80 : 443),
      path: `${url.pathname}${url.search}`,
      servername: net.isIP(url.hostname) ? undefined : url.hostname,
      lookup: safeLookup,
      headers: {
        // Identify honestly; some WAFs serve a different header set to
        // unidentified clients, which would misrepresent the target.
        'User-Agent': 'QGuard-PublicScanner/2.0 (+https://qguard.io/public-scan)',
        Accept: 'text/html,application/xhtml+xml',
        'Accept-Encoding': 'identity',
        Connection: 'close',
      },
      // nosemgrep: bypass-tls-verification -- assessment probe, not a client.
      // Header analysis must work against expired / self-signed / untrusted
      // endpoints; refusing them would report "Not observable" for a property
      // that is plainly observable. No body or credential is ever sent, and the
      // chain verdict is captured independently by the certificate engine.
      rejectUnauthorized: false,
      timeout: HTTP_TIMEOUT,
    }

    const request = transport.request(options, (response) => {
      // Headers are all this engine needs; drain and close immediately.
      response.resume()
      finish({
        statusCode: response.statusCode ?? 0,
        httpVersion: response.httpVersion,
        headers: response.headers,
        url: target,
        elapsedMs: Date.now() - startedAt,
      })
      request.destroy()
    })

    request.on('error', () => finish(null))
    request.on('timeout', () => {
      request.destroy()
      finish(null)
    })
    request.end()

    const timer = setTimeout(() => {
      request.destroy()
      finish(null)
    }, HTTP_TIMEOUT)
  })
}

/**
 * Follow redirects manually so the whole chain is recorded as evidence.
 *
 * Every hop is re-validated before it is followed. Redirect following is an SSRF
 * vector in its own right, and a cheaper one than DNS trickery: a target that
 * passed validation can simply answer `302 Location: http://169.254.169.254/`
 * and, unchecked, its response headers would be folded into the report. The
 * per-hop guard covers what the pinned `lookup` cannot — a literal private IP
 * (Node skips `lookup` when the host is already an address), a non-HTTP scheme,
 * and an off-limits port. A blocked hop is reported as the end of the chain, not
 * as a failure, so the assessment still returns what it legitimately observed.
 */
async function requestFollowing(
  start: string,
): Promise<{ response: RawResponse | null; chain: string[]; blockedRedirect: string | null }> {
  const chain: string[] = []
  let current = start

  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    const response = await retryTransient(
      () => rawRequest(current),
      (value) => value !== null,
    )
    if (!response) return { response: null, chain, blockedRedirect: null }

    const location = response.headers.location
    const isRedirect = response.statusCode >= 300 && response.statusCode < 400 && location
    if (!isRedirect) return { response: { ...response, url: current }, chain, blockedRedirect: null }

    let next: string
    try {
      next = new URL(String(location), current).toString()
    } catch {
      return { response: { ...response, url: current }, chain, blockedRedirect: null }
    }
    const allowed = canFollowRedirect(next)
    if (!allowed.ok) {
      return { response: { ...response, url: current }, chain, blockedRedirect: next }
    }
    // A redirect loop is a real finding, not a reason to hang.
    if (chain.includes(next)) return { response: { ...response, url: current }, chain, blockedRedirect: null }
    chain.push(next)
    current = next
  }

  return { response: null, chain, blockedRedirect: null }
}

// ─── HSTS ─────────────────────────────────────────────────────────────────────

export function analyzeHsts(raw: string | undefined, host: string): HstsAnalysis {
  if (!raw) {
    return { ...emptyHsts('Not Supported'), preloadBlockers: ['No Strict-Transport-Security header returned'] }
  }

  const maxAge = Number.parseInt(raw.match(/max-age\s*=\s*"?(\d+)/i)?.[1] || '0', 10)
  const includeSubDomains = /includeSubDomains/i.test(raw)
  const preload = /preload/i.test(raw)

  // hstspreload.org submission requirements.
  const blockers: string[] = []
  if (maxAge < 31_536_000) blockers.push(`max-age must be at least 31536000 (found ${maxAge})`)
  if (!includeSubDomains) blockers.push('includeSubDomains directive required')
  if (!preload) blockers.push('preload directive required')
  if (host.split('.').filter(Boolean).length > 2) {
    blockers.push('preload list accepts registrable domains, not subdomains')
  }

  const status: ControlStatus =
    maxAge >= 31_536_000 && includeSubDomains ? 'Healthy' : maxAge > 0 ? 'Warning' : 'Critical'

  return {
    present: true,
    status,
    raw,
    maxAge,
    includeSubDomains,
    preload,
    preloadEligible: blockers.length === 0,
    preloadBlockers: blockers,
  }
}

// ─── Infrastructure fingerprinting ────────────────────────────────────────────

const CDN_SIGNATURES: Array<{ name: string; headers: string[]; serverPattern?: RegExp }> = [
  { name: 'Cloudflare', headers: ['cf-ray', 'cf-cache-status'], serverPattern: /cloudflare/i },
  { name: 'Fastly', headers: ['x-served-by', 'x-fastly-request-id'], serverPattern: /fastly/i },
  { name: 'Akamai', headers: ['x-akamai-transformed', 'akamai-grn'], serverPattern: /akamai/i },
  { name: 'Amazon CloudFront', headers: ['x-amz-cf-id', 'x-amz-cf-pop'], serverPattern: /cloudfront/i },
  { name: 'Google Cloud CDN', headers: ['x-goog-generation'], serverPattern: /^gws$|google frontend/i },
  { name: 'Azure Front Door', headers: ['x-azure-ref', 'x-msedge-ref'] },
  { name: 'Vercel', headers: ['x-vercel-id', 'x-vercel-cache'] },
  { name: 'Netlify', headers: ['x-nf-request-id'] },
  { name: 'Sucuri', headers: ['x-sucuri-id'] },
  { name: 'Imperva', headers: ['x-iinfo'] },
]

const WAF_SIGNATURES: Array<{ name: string; headers: string[] }> = [
  { name: 'Cloudflare WAF', headers: ['cf-ray'] },
  { name: 'AWS WAF', headers: ['x-amzn-waf-action'] },
  { name: 'Imperva Incapsula', headers: ['x-iinfo', 'x-cdn'] },
  { name: 'Sucuri CloudProxy', headers: ['x-sucuri-id'] },
  { name: 'F5 BIG-IP', headers: ['x-wa-info'] },
]

const CLOUD_SIGNATURES: Array<{ name: string; headers: string[]; serverPattern?: RegExp }> = [
  { name: 'Amazon Web Services', headers: ['x-amz-request-id', 'x-amz-id-2'], serverPattern: /amazons3|awselb/i },
  { name: 'Microsoft Azure', headers: ['x-azure-ref', 'x-ms-request-id'] },
  { name: 'Google Cloud', headers: ['x-goog-generation'], serverPattern: /google frontend|gfe/i },
]

const PROXY_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: 'nginx', pattern: /nginx/i },
  { name: 'Apache', pattern: /apache/i },
  { name: 'Envoy', pattern: /envoy/i },
  { name: 'HAProxy', pattern: /haproxy/i },
  { name: 'LiteSpeed', pattern: /litespeed/i },
  { name: 'Microsoft-IIS', pattern: /iis/i },
  { name: 'Caddy', pattern: /caddy/i },
]

export function fingerprint(headers: http.IncomingHttpHeaders): HttpFingerprint {
  const present = new Set(Object.keys(headers).map((name) => name.toLowerCase()))
  const server = typeof headers.server === 'string' ? headers.server : null
  const signals: string[] = []

  const matchBy = <T extends { name: string; headers: string[]; serverPattern?: RegExp }>(
    signatures: T[],
  ): string | null => {
    for (const signature of signatures) {
      const hit = signature.headers.find((header) => present.has(header))
      if (hit) {
        signals.push(hit)
        return signature.name
      }
      if (signature.serverPattern && server && signature.serverPattern.test(server)) {
        signals.push('server')
        return signature.name
      }
    }
    return null
  }

  const cdn = matchBy(CDN_SIGNATURES)
  const waf = matchBy(WAF_SIGNATURES)
  const cloudProvider = matchBy(CLOUD_SIGNATURES)
  const reverseProxy = server ? PROXY_PATTERNS.find((entry) => entry.pattern.test(server))?.name ?? null : null

  return {
    server,
    poweredBy: typeof headers['x-powered-by'] === 'string' ? headers['x-powered-by'] : null,
    cdn,
    waf,
    cloudProvider,
    reverseProxy,
    signals: Array.from(new Set(signals)),
  }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

export async function runHttpEngine(host: string, port: number): Promise<EngineResult<HttpIntelligence>> {
  return runEngine('http-security', emptyHttp(null), async () => {
    const base = port === 443 ? `https://${host}` : `https://${host}:${port}`
    const evidence: Evidence[] = []
    const notes: string[] = []

    const { response, chain } = await requestFollowing(base)

    if (!response) {
      const data = emptyHttp('HTTPS origin did not respond')
      notes.push('Origin unreachable over HTTPS; header controls report Unknown, not missing.')
      return { data, ok: false, confidence: 0, evidence, notes, error: data.error }
    }

    const headerValue = (name: string): string | undefined => {
      const value = response.headers[name]
      return Array.isArray(value) ? value.join(', ') : value
    }

    const headers: SecurityHeaderResult[] = HEADER_SPECS.map((spec) => {
      const value = headerValue(spec.name) ?? null
      if (value === null) {
        return {
          name: spec.name,
          group: spec.group,
          present: false,
          value: null,
          // The origin answered, so absence is a genuine "expected but absent".
          status: 'Not Supported' as ControlStatus,
          purpose: spec.purpose,
          weakness: null,
          recommendation: spec.recommendation,
        }
      }
      const weakness = spec.weakness?.(value) ?? null
      return {
        name: spec.name,
        group: spec.group,
        present: true,
        value,
        status: (weakness ? 'Warning' : 'Healthy') as ControlStatus,
        purpose: spec.purpose,
        weakness,
        recommendation: weakness ? spec.recommendation : '',
      }
    })

    const hsts = analyzeHsts(headerValue('strict-transport-security'), host)

    // Does plain HTTP redirect to HTTPS? Answered by asking, not assumed.
    const plainHttp = await rawRequest(`http://${host}`, 'HEAD')
    const httpToHttpsRedirect = plainHttp
      ? plainHttp.statusCode >= 300 &&
        plainHttp.statusCode < 400 &&
        String(plainHttp.headers.location ?? '').startsWith('https://')
      : null

    const setCookie = response.headers['set-cookie'] ?? []
    const cookies = (Array.isArray(setCookie) ? setCookie : [setCookie]).slice(0, 10).map((cookie) => {
      const text = String(cookie)
      return {
        name: text.split('=')[0]?.trim() ?? 'cookie',
        secure: /;\s*secure/i.test(text),
        httpOnly: /;\s*httponly/i.test(text),
        sameSite: text.match(/;\s*samesite\s*=\s*(\w+)/i)?.[1] ?? null,
      }
    })

    const data: HttpIntelligence = {
      reachable: true,
      statusCode: response.statusCode,
      httpVersion: response.httpVersion,
      finalUrl: response.url,
      redirected: chain.length > 0,
      redirectChain: chain,
      redirectedToHttps: response.url.startsWith('https://'),
      httpToHttpsRedirect,
      responseMs: response.elapsedMs,
      headers,
      rawHeaderNames: Object.keys(response.headers).sort(),
      hsts,
      fingerprint: fingerprint(response.headers),
      cookies,
      error: null,
    }

    evidence.push({
      label: 'HTTP response',
      observedValue: `HTTP/${response.httpVersion} ${response.statusCode} in ${response.elapsedMs} ms`,
      detectionMethod: 'HTTP response metadata',
      evidenceSource: response.url,
      confidence: 100,
    })
    evidence.push({
      label: 'Strict-Transport-Security',
      observedValue: hsts.raw ?? 'header not returned',
      detectionMethod: 'HTTP response header',
      evidenceSource: response.url,
      confidence: 100,
    })
    for (const header of headers.filter((entry) => entry.present)) {
      evidence.push({
        label: header.name,
        observedValue: header.value ?? '',
        detectionMethod: 'HTTP response header',
        evidenceSource: response.url,
        confidence: 100,
      })
    }
    if (data.fingerprint.cdn || data.fingerprint.waf || data.fingerprint.cloudProvider) {
      evidence.push({
        label: 'Infrastructure',
        observedValue: [data.fingerprint.cdn, data.fingerprint.waf, data.fingerprint.cloudProvider]
          .filter(Boolean)
          .join(' · '),
        detectionMethod: 'HTTP response metadata',
        evidenceSource: `headers: ${data.fingerprint.signals.join(', ') || 'server'}`,
        confidence: data.fingerprint.signals.length ? 90 : 60,
      })
    }
    if (chain.length) {
      notes.push(`Followed ${chain.length} redirect${chain.length === 1 ? '' : 's'} to ${response.url}.`)
    }

    return { data, ok: true, confidence: clampScore(100), evidence, notes, error: null }
  })
}

export { emptyHttp, HEADER_SPECS }
