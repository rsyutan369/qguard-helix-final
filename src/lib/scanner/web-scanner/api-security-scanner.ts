/**
 * QGuard Web Scanner — API Security Scanner
 * Probes API endpoints and analyzes security headers for quantum readiness
 */

import type { ApiSecurityResult, SecurityHeader, ApiSecurityFinding, ThreatLevel } from './types'
import { requestPublicWebResource } from '../public-scan/public-http'

const FETCH_TIMEOUT = 5_000
const MAX_BODY_SIZE = 1_000_000
const INSPECTED_RESPONSE_BODIES = new Set([
  '/.well-known/jwks.json',
  '/.well-known/openid-configuration',
  '/.well-known/security.txt',
])

// Common API paths to probe
const API_PATHS = [
  '/',
  '/api',
  '/api/v1',
  '/api/v2',
  '/graphql',
  '/.well-known/openid-configuration',
  '/oauth/token',
  '/oauth/authorize',
  '/health',
  '/healthz',
  '/.well-known/jwks.json',
  '/.well-known/security.txt',
  '/robots.txt',
  '/sitemap.xml',
]

// Security headers to check
const SECURITY_HEADERS: {
  name: string
  required: boolean
  recommendation: string
}[] = [
  {
    name: 'strict-transport-security',
    required: true,
    recommendation: 'Enable HSTS with includeSubDomains and preload directives (min 1 year max-age)',
  },
  {
    name: 'content-security-policy',
    required: true,
    recommendation: 'Implement Content-Security-Policy to prevent XSS and injection attacks',
  },
  {
    name: 'x-frame-options',
    required: true,
    recommendation: 'Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking',
  },
  {
    name: 'x-content-type-options',
    required: true,
    recommendation: 'Set X-Content-Type-Options: nosniff to prevent MIME type confusion',
  },
  {
    name: 'x-xss-protection',
    required: false,
    recommendation: 'Consider using Content-Security-Policy instead of X-XSS-Protection',
  },
  {
    name: 'referrer-policy',
    required: false,
    recommendation: 'Set Referrer-Policy to no-referrer or strict-origin-when-cross-origin',
  },
  {
    name: 'permissions-policy',
    required: false,
    recommendation: 'Define Permissions-Policy to restrict browser feature access',
  },
  {
    name: 'cross-origin-opener-policy',
    required: false,
    recommendation: 'Set Cross-Origin-Opener-Policy to same-origin for process isolation',
  },
  {
    name: 'cross-origin-resource-policy',
    required: false,
    recommendation: 'Set Cross-Origin-Resource-Policy to same-origin or same-site',
  },
  {
    name: 'cross-origin-embedder-policy',
    required: false,
    recommendation: 'Set Cross-Origin-Embedder-Policy for enhanced isolation',
  },
]

/**
 * Safe fetch with timeout for API probing
 */
async function probeFetch(url: string, readBody = false) {
  try {
    return await requestPublicWebResource(url, {
      method: 'GET',
      accept: 'application/json, text/html',
      timeoutMs: FETCH_TIMEOUT,
      bodyLimit: readBody ? MAX_BODY_SIZE : undefined,
    })
  } catch {
    return null
  }
}

/**
 * Analyze security headers from a response
 */
function analyzeSecurityHeaders(headers: Headers): SecurityHeader[] {
  return SECURITY_HEADERS.map(header => {
    const value = headers.get(header.name)
    const present = value !== null
    let secure = present

    // Additional security checks
    if (header.name === 'strict-transport-security' && value) {
      const maxAge = parseInt(value.match(/max-age=(\d+)/)?.[1] || '0')
      secure = maxAge >= 31536000 // At least 1 year
    }

    if (header.name === 'x-frame-options' && value) {
      secure = value.toUpperCase() === 'DENY' || value.toUpperCase() === 'SAMEORIGIN'
    }

    return {
      name: header.name,
      value,
      present,
      secure: present ? secure : false,
      recommendation: present ? (secure ? '' : `Strengthen ${header.name} configuration`) : header.recommendation,
    }
  })
}

/**
 * Analyze JWKS endpoint for quantum-vulnerable algorithms
 */
function analyzeJwks(jwksData: Record<string, unknown>): ApiSecurityFinding[] {
  const findings: ApiSecurityFinding[] = []

  if (!jwksData || !Array.isArray(jwksData.keys)) return findings

  for (const key of jwksData.keys) {
    const kty = key.kty as string
    const alg = key.alg as string
    const kid = key.kid as string || 'unknown'

    if (kty === 'RSA') {
      findings.push({
        endpoint: '/.well-known/jwks.json',
        findingType: 'JWT RSA Key',
        algorithm: `RSA ${alg || 'key'} (kid: ${kid})`,
        threatLevel: 'HIGH',
        description: 'RSA key in JWKS — quantum-vulnerable JWT signing via Shor\'s algorithm',
        recommendation: 'Migrate JWT signing to ML-DSA (Dilithium) or hybrid algorithm',
      })
    }

    if (kty === 'EC') {
      const crv = key.crv as string || 'unknown'
      findings.push({
        endpoint: '/.well-known/jwks.json',
        findingType: 'JWT EC Key',
        algorithm: `ECDSA ${crv} (kid: ${kid})`,
        threatLevel: 'HIGH',
        description: `ECDSA ${crv} key in JWKS — quantum-vulnerable via Shor\'s algorithm`,
        recommendation: 'Migrate to ML-DSA (Dilithium) for JWT signing',
      })
    }
  }

  return findings
}

/**
 * Analyze OpenID Connect configuration for crypto details
 */
function analyzeOidcConfig(config: Record<string, unknown>): ApiSecurityFinding[] {
  const findings: ApiSecurityFinding[] = []

  const signingAlgs = config.id_token_signing_alg_values_supported as string[] | undefined
  if (signingAlgs) {
    for (const alg of signingAlgs) {
      if (['RS256', 'RS384', 'RS512'].includes(alg)) {
        findings.push({
          endpoint: '/.well-known/openid-configuration',
          findingType: 'OIDC RSA Signing',
          algorithm: alg,
          threatLevel: 'HIGH',
          description: `OpenID Connect supports ${alg} (RSA-based signing) — quantum-vulnerable`,
          recommendation: 'Add PQC signing algorithm support to OpenID Connect configuration',
        })
      }
      if (['ES256', 'ES384', 'ES512'].includes(alg)) {
        findings.push({
          endpoint: '/.well-known/openid-configuration',
          findingType: 'OIDC ECDSA Signing',
          algorithm: alg,
          threatLevel: 'HIGH',
          description: `OpenID Connect supports ${alg} (ECDSA-based signing) — quantum-vulnerable`,
          recommendation: 'Migrate to ML-DSA-based token signing',
        })
      }
    }
  }

  return findings
}

/**
 * Response headers read by the edge HTTP engine, offered as a fallback.
 *
 * WHY A FALLBACK IS NEEDED
 * ------------------------
 * `probeFetch` uses Node's `fetch()`, which enforces certificate validation and
 * refuses to connect over an expired, self-signed or untrusted chain. Those are
 * exactly the targets whose headers matter most, and the refusal made every
 * header render "Not observed" on the dashboard for a reason that had nothing
 * to do with the target's headers. The edge engine reads the same response over
 * a permissive agent (no body, no credential, chain verdict captured separately
 * by the certificate engine), so its observation is used when fetch is blocked.
 *
 * This is a fallback, not a replacement: when `fetch` succeeds the live response
 * is authoritative, because it also carries cookies and the endpoint probes.
 */
export interface EdgeHeaderObservation {
  reachable: boolean
  headers: Array<{ name: string; value: string | null; present: boolean; status: string }>
  server: string | null
  poweredBy: string | null
}

/** Map the edge engine's header verdicts onto this scanner's header shape. */
function headersFromEdge(edge: EdgeHeaderObservation): SecurityHeader[] {
  return SECURITY_HEADERS.map((spec) => {
    const observed = edge.headers.find((header) => header.name === spec.name)
    const present = Boolean(observed?.present)
    return {
      name: spec.name,
      value: observed?.value ?? null,
      present,
      // The edge engine grades each header against the same OWASP guidance this
      // scanner does; `Healthy` is its "configured and adequate" verdict.
      secure: present && observed?.status === 'Healthy',
      recommendation: present
        ? observed?.status === 'Healthy'
          ? ''
          : `Strengthen ${spec.name} configuration`
        : spec.recommendation,
    }
  })
}

/**
 * Scan a target's API endpoints for security and cryptographic issues
 */
export async function scanApiSecurity(
  hostname: string,
  edge?: EdgeHeaderObservation | null,
): Promise<ApiSecurityResult> {
  const securityHeaders: SecurityHeader[] = []
  const apiFindings: ApiSecurityFinding[] = []
  let endpointsProbed = 0

  const baseUrl = `https://${hostname}`

  // Step 1: Probe the main page and collect security headers
  const mainResponse = await probeFetch(baseUrl)
  if (!mainResponse && edge?.reachable) {
    // fetch() was blocked by the chain, but the origin demonstrably answered.
    // Report what was actually read rather than an unmeasured blank.
    endpointsProbed++
    const headers = headersFromEdge(edge)
    securityHeaders.push(...headers)

    const hsts = headers.find((header) => header.name === 'strict-transport-security')
    if (!hsts?.present) {
      apiFindings.push({
        endpoint: '/',
        findingType: 'Missing HSTS',
        algorithm: 'HSTS',
        threatLevel: 'MEDIUM',
        description: 'Strict-Transport-Security header missing — increases protocol downgrade attack surface',
        recommendation: 'Enable HSTS with includeSubDomains and preload',
      })
    }
    if (edge.server) {
      apiFindings.push({
        endpoint: '/',
        findingType: 'Server Header Disclosure',
        algorithm: 'Information Disclosure',
        threatLevel: 'LOW',
        description: `Server header exposes: "${edge.server}" — aids reconnaissance`,
        recommendation: 'Remove or minimize server header information',
      })
    }
    if (edge.poweredBy) {
      apiFindings.push({
        endpoint: '/',
        findingType: 'X-Powered-By Disclosure',
        algorithm: 'Information Disclosure',
        threatLevel: 'LOW',
        description: `X-Powered-By header exposes: "${edge.poweredBy}" — reveals technology stack`,
        recommendation: 'Remove X-Powered-By header to reduce reconnaissance surface',
      })
    }
  }
  if (mainResponse) {
    endpointsProbed++
    const headers = analyzeSecurityHeaders(mainResponse.headers)
    securityHeaders.push(...headers)

    // Check for missing HSTS (critical for quantum security)
    const hsts = headers.find(h => h.name === 'strict-transport-security')
    if (!hsts?.present) {
      apiFindings.push({
        endpoint: '/',
        findingType: 'Missing HSTS',
        algorithm: 'HSTS',
        threatLevel: 'MEDIUM',
        description: 'Strict-Transport-Security header missing — increases protocol downgrade attack surface',
        recommendation: 'Enable HSTS with includeSubDomains and preload',
      })
    }

    // Check for server header information disclosure
    const serverHeader = mainResponse.headers.get('server')
    if (serverHeader) {
      apiFindings.push({
        endpoint: '/',
        findingType: 'Server Header Disclosure',
        algorithm: 'Information Disclosure',
        threatLevel: 'LOW',
        description: `Server header exposes: "${serverHeader}" — aids reconnaissance`,
        recommendation: 'Remove or minimize server header information',
      })
    }

    // Check for X-Powered-By disclosure
    const poweredBy = mainResponse.headers.get('x-powered-by')
    if (poweredBy) {
      apiFindings.push({
        endpoint: '/',
        findingType: 'X-Powered-By Disclosure',
        algorithm: 'Information Disclosure',
        threatLevel: 'LOW',
        description: `X-Powered-By header exposes: "${poweredBy}" — reveals technology stack`,
        recommendation: 'Remove X-Powered-By header to reduce reconnaissance surface',
      })
    }

    // Check for insecure cookie configuration
    const setCookie = mainResponse.headers.get('set-cookie')
    if (setCookie) {
      const hasSecure = setCookie.toLowerCase().includes('secure')
      const hasHttpOnly = setCookie.toLowerCase().includes('httponly')
      const hasSameSite = setCookie.toLowerCase().includes('samesite')
      if (!hasSecure || !hasHttpOnly) {
        apiFindings.push({
          endpoint: '/',
          findingType: 'Insecure Cookie Configuration',
          algorithm: 'Cookie Security',
          threatLevel: 'MEDIUM',
          description: `Cookies missing security flags: ${!hasSecure ? 'Secure ' : ''}${!hasHttpOnly ? 'HttpOnly ' : ''}${!hasSameSite ? 'SameSite' : ''}`.trim(),
          recommendation: 'Set Secure, HttpOnly, and SameSite=Strict on all sensitive cookies',
        })
      }
    }
  }

  // Step 2: Probe API endpoints in parallel. Running these serially can exceed
  // the module timeout on hosts that drop connections or have flaky DNS.
  const endpointResponses = await Promise.all(
    API_PATHS
      .filter((path) => path !== '/')
      .map(async (path) => {
        const url = `${baseUrl}${path}`
        const response = await probeFetch(url, INSPECTED_RESPONSE_BODIES.has(path))
        return { path, url, response }
      })
  )

  for (const { path, url, response } of endpointResponses) {
    if (!response) continue
    endpointsProbed++

    // Check for GraphQL introspection
    if (path === '/graphql' && response.status !== 404) {
      // Try introspection query
      try {
        const gqlResponse = await probeFetch(`${url}?query={__schema{types{name}}}`)
        if (gqlResponse && gqlResponse.ok) {
          apiFindings.push({
            endpoint: path,
            findingType: 'GraphQL Introspection Enabled',
            algorithm: 'GraphQL',
            threatLevel: 'MEDIUM',
            description: 'GraphQL introspection is enabled — exposes API schema to attackers',
            recommendation: 'Disable GraphQL introspection in production',
          })
        }
      } catch {
        // Ignore introspection check failures
      }
    }

    // Check JWKS endpoint
    if (path === '/.well-known/jwks.json' && response.ok) {
      try {
        const jwksData = JSON.parse(response.body)
        const jwksFindings = analyzeJwks(jwksData as Record<string, unknown>)
        apiFindings.push(...jwksFindings)
      } catch {
        // Ignore JSON parse errors
      }
    }

    // Check OpenID Configuration
    if (path === '/.well-known/openid-configuration' && response.ok) {
      try {
        const oidcData = JSON.parse(response.body)
        const oidcFindings = analyzeOidcConfig(oidcData as Record<string, unknown>)
        apiFindings.push(...oidcFindings)
      } catch {
        // Ignore JSON parse errors
      }
    }

    // Check security.txt for contact/encryption info
    if (path === '/.well-known/security.txt' && response.ok) {
      try {
        const secTxt = response.body
        if (secTxt.includes('PGP') || secTxt.includes('pgp') || secTxt.includes('gpg')) {
          apiFindings.push({
            endpoint: path,
            findingType: 'PGP Key in Security.txt',
            algorithm: 'PGP/GPG',
            threatLevel: 'MEDIUM',
            description: 'Security.txt references PGP encryption — PGP typically uses quantum-vulnerable RSA/ECC',
            recommendation: 'Consider publishing PQC-ready encryption contact alongside PGP key',
          })
        }
      } catch {
        // Ignore text parse errors
      }
    }

    // Check OAuth endpoints for token signing details
    if ((path === '/oauth/token' || path === '/oauth/authorize') && response.status !== 404) {
      // The fact that these endpoints exist means OAuth is in use
      apiFindings.push({
        endpoint: path,
        findingType: 'OAuth Endpoint Detected',
        algorithm: 'OAuth',
        threatLevel: 'MEDIUM',
        description: 'OAuth endpoint detected — OAuth tokens typically use RSA/ECDSA signing (quantum-vulnerable)',
        recommendation: 'Prepare OAuth token signing migration to ML-DSA (Dilithium) when library support is available',
      })
    }
  }

  return {
    hostname,
    endpointsProbed,
    securityHeaders,
    apiFindings,
  }
}
