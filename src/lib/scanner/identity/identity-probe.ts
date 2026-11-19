/**
 * Identity Discovery — the network probe runner.
 *
 * Separated from `identity-discovery.ts` on purpose: that module is a pure
 * parser with no I/O, so it stays offline-testable. This module does the
 * fetching and hands the raw documents over.
 *
 * ── Probe discipline ───────────────────────────────────────────────────────
 * Every path probed here is defined by a published specification (OpenID
 * Connect Discovery 1.0, RFC 8414, SAML 2.0 metadata), so a hit is meaningful
 * and a miss is proof of absence rather than a failed guess. The runner does
 * not crawl, does not enumerate, and does not follow links found in responses.
 *
 * ── Bounded cost ───────────────────────────────────────────────────────────
 * At most `IDENTITY_PROBE_PLAN.length` requests per host plus one JWKS fetch
 * per discovered provider. Named-group probing once consumed 85-97% of every
 * scan in this codebase; identity discovery is deliberately kept to a handful
 * of requests with a short timeout so it never becomes the new bottleneck.
 */

import {
  IDENTITY_PROBE_PLAN,
  assembleIdentityDiscovery,
  type IdentityDiscoveryResult,
  type RawProbe,
} from './identity-discovery'
import { requestPublicWebResource } from '../public-scan/public-http'

const PROBE_TIMEOUT_MS = 6000
const MAX_BODY_BYTES = 512 * 1024

export interface ProbeOutcome {
  url: string
  method: string
  httpStatus: number | null
  /** found | not-found | unparseable | error */
  outcome: 'found' | 'not-found' | 'unparseable' | 'error'
  detail: string | null
  observedAt: string
}

export interface IdentityProbeReport extends IdentityDiscoveryResult {
  /** Every probe that ran, including the ones that found nothing. */
  probes: ProbeOutcome[]
  host: string
}

export interface FetchedDocument {
  status: number | null
  body: unknown
  error: string | null
}

/**
 * A probe that never got an HTTP response (timeout, DNS, TLS, refused) is an
 * `error`: it proves nothing about the host. Only a probe that DID answer with
 * a body we could not use is `unparseable`. Folding timeouts into
 * `unparseable` let a dead host read as "answered, but not identity metadata",
 * which the Discovery page would then present as proof of absence.
 */
export function probeOutcome(fetched: FetchedDocument): ProbeOutcome['outcome'] {
  if (fetched.body) return 'found'
  if (fetched.status === null) return 'error'
  return fetched.error ? 'unparseable' : 'not-found'
}

/**
 * Fetch one document.
 *
 * Public HTTPS redirects support regional identity providers. Only JSON/XML
 * documents count as discovery evidence.
 */
async function fetchDocument(url: string, expect: 'json' | 'xml'): Promise<FetchedDocument> {
  try {
    const response = await requestPublicWebResource(url, {
      method: 'GET',
      accept: expect === 'json' ? 'application/json' : 'application/samlmetadata+xml, application/xml, text/xml',
      userAgent: 'QGuard-Scanner/2.4 (identity-discovery)',
      timeoutMs: PROBE_TIMEOUT_MS,
      bodyLimit: MAX_BODY_BYTES,
      requireHttps: true,
    })

    // 401/403 answered, but refused: the document may exist behind an access
    // policy or WAF. Recording it as "not found" would claim absence unproven.
    if (response.status === 401 || response.status === 403) {
      return { status: response.status, body: null, error: `${ACCESS_DENIED_PREFIX} (HTTP ${response.status}) — presence not determined` }
    }
    if (!response.ok) return { status: response.status, body: null, error: null }

    const contentType = String(response.headers.get('content-type') ?? '').toLowerCase()
    const text = response.body

    if (expect === 'json') {
      // A catch-all SPA route answers 200 with HTML for any path. Parsing that
      // as a discovery document is how a CDN becomes an identity provider.
      if (contentType.includes('text/html') || /^\s*</.test(text)) {
        return { status: response.status, body: null, error: 'Response was HTML, not a JSON discovery document' }
      }
      try {
        return { status: response.status, body: JSON.parse(text), error: null }
      } catch {
        return { status: response.status, body: null, error: 'Response was not valid JSON' }
      }
    }

    if (!/<[^>]+EntityDescriptor/i.test(text)) {
      return { status: response.status, body: null, error: 'Response did not contain SAML metadata' }
    }
    return { status: response.status, body: text, error: null }
  } catch (error) {
    return { status: null, body: null, error: describeFetchError(error) }
  }
}

/** Prefix the Discovery verdict logic keys on for refused probes. */
export const ACCESS_DENIED_PREFIX = 'Access denied'

const NETWORK_CAUSES: Array<[RegExp, string]> = [
  [/CERT_HAS_EXPIRED/, 'TLS certificate has expired'],
  [/ERR_TLS_CERT_ALTNAME_INVALID|HOSTNAME_MISMATCH/, 'TLS certificate does not match the hostname'],
  [/SELF_SIGNED|UNABLE_TO_VERIFY|UNABLE_TO_GET_ISSUER|CERT_UNTRUSTED|CERT_REVOKED/, 'TLS certificate is not trusted'],
  [/ENOTFOUND|EAI_AGAIN/, 'DNS lookup failed'],
  [/ECONNREFUSED/, 'connection refused'],
  [/ECONNRESET|UND_ERR_SOCKET/, 'connection reset by the host'],
  [/ETIMEDOUT|UND_ERR_CONNECT_TIMEOUT/, 'connection timed out'],
]

/**
 * Translate direct Node networking errors and wrapped transport errors to
 * evidence that explains why a probe could not read the document.
 */
export function describeFetchError(error: unknown): string {
  const err = error as { name?: string; code?: string; message?: string; cause?: { code?: string; message?: string } } | null
  if (err?.name === 'AbortError' || err?.name === 'TimeoutError') return 'Probe timed out'
  const networkCode = err?.cause?.code ?? err?.code
  const code = `${networkCode ?? ''} ${err?.cause?.message ?? ''}`
  for (const [pattern, label] of NETWORK_CAUSES) if (pattern.test(code)) return label
  return networkCode ? `Network error (${networkCode})` : err?.message || 'Probe failed'
}

function originFor(hostname: string): string {
  const clean = String(hostname || '').trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '')
  return `https://${clean}`
}

/**
 * Run identity discovery against one host.
 *
 * Two rounds by necessity: the well-known documents name their own `jwks_uri`,
 * so the JWKS can only be fetched after the discovery document is read.
 *
 * The JWKS URL is taken from the document rather than guessed, and is gated by
 * `isSafePublicJwksUrl`. An earlier version required the JWKS to share the
 * probed host, which sounded prudent and was wrong: major providers publish
 * their JWKS on a sibling domain (Google's `accounts.google.com` points at
 * `www.googleapis.com`), so the guard silently discarded the very keys that
 * decide the provider's posture — a live probe returned "0 keys" for a provider
 * with published RSA keys. The real risk is SSRF, so the guard now blocks
 * private, loopback, link-local and cloud-metadata destinations instead.
 */
export async function probeIdentityInfrastructure(hostname: string): Promise<IdentityProbeReport> {
  const origin = originFor(hostname)
  const host = origin.replace(/^https:\/\//, '')
  const probes: ProbeOutcome[] = []
  const raw: RawProbe[] = []
  const at = () => new Date().toISOString()

  /* ---- Round 1: well-known documents ------------------------------- */
  const round1 = await Promise.all(
    IDENTITY_PROBE_PLAN.map(async (plan) => {
      const url = `${origin}${plan.path}`
      const expect = plan.method === 'saml-metadata' ? 'xml' : 'json'
      const fetched = await fetchDocument(url, expect)
      return { plan, url, fetched }
    }),
  )

  for (const { plan, url, fetched } of round1) {
    const observedAt = at()
    raw.push({ url, method: plan.method, httpStatus: fetched.status, body: fetched.body, observedAt })
    probes.push({
      url,
      method: plan.method,
      httpStatus: fetched.status,
      outcome: probeOutcome(fetched),
      detail: fetched.error,
      observedAt,
    })
  }

  /* ---- Round 2: the JWKS each document actually names ---------------- */
  const interim = assembleIdentityDiscovery(raw)
  const jwksUrls = Array.from(
    new Set(
      interim.providers
        .map((provider) => provider.jwksUri)
        .filter((uri): uri is string => Boolean(uri) && isSafePublicJwksUrl(uri!)),
    ),
  )

  const round2 = await Promise.all(
    jwksUrls.map(async (url) => ({ url, fetched: await fetchDocument(url, 'json') })),
  )
  for (const { url, fetched } of round2) {
    const observedAt = at()
    raw.push({ url, method: 'jwks', httpStatus: fetched.status, body: fetched.body, observedAt })
    probes.push({
      url,
      method: 'jwks',
      httpStatus: fetched.status,
      outcome: probeOutcome(fetched),
      detail: fetched.error,
      observedAt,
    })
  }

  const result = assembleIdentityDiscovery(raw)
  return { ...result, probes, host }
}

/**
 * SSRF guard for a `jwks_uri` taken from a probed document.
 *
 * A discovery document is attacker-controllable input: whoever runs the probed
 * host chooses the `jwks_uri`, so following it blindly turns the scanner into a
 * request proxy pointed wherever they like — classically at cloud metadata
 * (169.254.169.254) or an internal service.
 *
 * The guard is therefore about DESTINATION, not about matching the probed host:
 *
 *   - HTTPS only. A plaintext JWKS is not authenticated in transit.
 *   - Named hosts only. An IP literal is never how a real provider publishes a
 *     JWKS, and IP literals are how metadata and internal endpoints are reached.
 *   - No loopback, private, link-local, unique-local or reserved space.
 *   - No internal-only TLDs, and no bare single-label hostnames, which resolve
 *     against the scanner's own search domain.
 *
 * Cross-origin is explicitly ALLOWED, because it is the normal, documented
 * arrangement for real identity providers.
 */
const BLOCKED_HOST_PATTERNS: RegExp[] = [
  /^localhost$/i,
  /\.localhost$/i,
  /\.local$/i,
  /\.internal$/i,
  /\.intranet$/i,
  /\.corp$/i,
  /\.home$/i,
  /\.lan$/i,
  /^metadata(\.|$)/i,
]

function isIpLiteral(host: string): boolean {
  // IPv4, or an IPv6 literal which URL parsing surfaces in brackets.
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':') || /^\[.*\]$/.test(host)
}

export function isSafePublicJwksUrl(url: string): boolean {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return false
  }
  if (parsed.protocol !== 'https:') return false

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (!host) return false
  // A bare single-label name resolves via the scanner host's search domain,
  // which is an internal destination by another route.
  if (!host.includes('.')) return false
  if (isIpLiteral(host)) return false
  for (const pattern of BLOCKED_HOST_PATTERNS) if (pattern.test(host)) return false
  return true
}
