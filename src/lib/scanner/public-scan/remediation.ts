/**
 * QGuard Helix — Platform-tailored remediation.
 *
 * A recommendation that says "enable HSTS" is correct and useless. The operator
 * still has to work out *where*. This module turns the HTTP fingerprint the scan
 * already collected — CDN, reverse proxy, cloud provider — into the concrete
 * place the change is actually made.
 *
 * HONESTY RULES
 * -------------
 * 1. The platform is only ever what the fingerprint OBSERVED. There is no
 *    guessing, no "most sites use nginx" default. When nothing is detected the
 *    remediation is the generic one and says so.
 * 2. Detection is a hint, not a fact about the origin. A Cloudflare `cf-ray`
 *    proves traffic is served through Cloudflare; it says nothing about what is
 *    behind it. So the copy names the surface it is confident about ("at your
 *    Cloudflare zone") and never claims to know the origin stack.
 * 3. Directives are the real ones for that platform. A wrong config snippet is
 *    worse than no snippet — it costs the reader a failed change window.
 *
 * The strings are intentionally short: this is a "where to look", not a runbook.
 */

import type { HttpFingerprint } from './engines/http-engine'

/** The remediation surfaces we can speak concretely about. */
export type RemediationPlatform =
  | 'cloudflare'
  | 'fastly'
  | 'akamai'
  | 'cloudfront'
  | 'azure-front-door'
  | 'vercel'
  | 'netlify'
  | 'aws-alb'
  | 'nginx'
  | 'apache'
  | 'iis'
  | 'litespeed'
  | 'caddy'
  | 'envoy'
  | 'haproxy'
  | 'generic'

export interface DetectedPlatform {
  key: RemediationPlatform
  /** Display name, e.g. "Cloudflare". `null` when nothing was detected. */
  label: string | null
  /** The header(s) that gave it away — provenance for the claim. */
  basis: string | null
  /**
   * True when the detected surface terminates TLS in front of the origin. Those
   * platforms own the TLS and header configuration, so the advice is precise.
   */
  isEdge: boolean
}

/** Fixes an operator can be pointed at, keyed by control. */
export type RemediationTopic =
  | 'hsts'
  | 'ocsp-stapling'
  | 'tls-version'
  | 'cipher-suite'
  | 'hybrid-kex'
  | 'security-headers'
  | 'forward-secrecy'

const NO_PLATFORM: DetectedPlatform = { key: 'generic', label: null, basis: null, isEdge: false }

/**
 * Resolve the fingerprint to one remediation surface.
 *
 * Edge platforms win over origin software: when a request is served through
 * Cloudflare, the TLS settings a reader needs to change are Cloudflare's, even
 * if the `server` header still says nginx.
 */
export function detectPlatform(fingerprint: HttpFingerprint | null | undefined): DetectedPlatform {
  if (!fingerprint) return NO_PLATFORM

  const basis = fingerprint.signals.length ? fingerprint.signals.join(', ') : null

  const edge: Array<[string, RemediationPlatform]> = [
    ['Cloudflare', 'cloudflare'],
    ['Fastly', 'fastly'],
    ['Akamai', 'akamai'],
    ['Amazon CloudFront', 'cloudfront'],
    ['Azure Front Door', 'azure-front-door'],
    ['Vercel', 'vercel'],
    ['Netlify', 'netlify'],
  ]
  for (const [name, key] of edge) {
    if (fingerprint.cdn === name) return { key, label: name, basis, isEdge: true }
  }

  // AWS load balancers announce themselves in `server`, not as a CDN.
  if (/awselb/i.test(fingerprint.server ?? '')) {
    return { key: 'aws-alb', label: 'AWS Elastic Load Balancer', basis: fingerprint.server, isEdge: true }
  }

  const origin: Array<[string, RemediationPlatform]> = [
    ['nginx', 'nginx'],
    ['Apache', 'apache'],
    ['Microsoft-IIS', 'iis'],
    ['LiteSpeed', 'litespeed'],
    ['Caddy', 'caddy'],
    ['Envoy', 'envoy'],
    ['HAProxy', 'haproxy'],
  ]
  for (const [name, key] of origin) {
    if (fingerprint.reverseProxy === name) {
      return { key, label: name, basis: fingerprint.server, isEdge: false }
    }
  }

  return NO_PLATFORM
}

/** Where the change is made, per platform. Used for the `effort` line. */
const SURFACE: Record<RemediationPlatform, string> = {
  cloudflare: 'Cloudflare dashboard / API',
  fastly: 'Fastly service configuration',
  akamai: 'Akamai property configuration',
  cloudfront: 'CloudFront distribution / response-headers policy',
  'azure-front-door': 'Azure Front Door rules engine',
  vercel: 'vercel.json headers',
  netlify: 'netlify.toml / _headers',
  'aws-alb': 'ALB listener + target response headers',
  nginx: 'nginx server block',
  apache: 'Apache vhost / .htaccess',
  iis: 'IIS site configuration',
  litespeed: 'LiteSpeed configuration',
  caddy: 'Caddyfile',
  envoy: 'Envoy listener filter',
  haproxy: 'HAProxy frontend',
  generic: 'TLS terminator / origin configuration',
}

/**
 * Concrete remediation text per (platform, topic).
 *
 * Only pairs we can state accurately are filled in. A missing pair falls through
 * to the generic line rather than inventing a directive for a platform whose
 * configuration model we would be guessing at.
 */
const PLAYBOOK: Partial<Record<RemediationPlatform, Partial<Record<RemediationTopic, string>>>> = {
  cloudflare: {
    hsts: 'SSL/TLS → Edge Certificates → HTTP Strict Transport Security. Set max-age to 12 months and enable "Apply HSTS to subdomains" before requesting preload.',
    'tls-version': 'SSL/TLS → Edge Certificates → Minimum TLS Version: set to TLS 1.2 (or 1.3), which disables TLS 1.0/1.1 at the edge.',
    'hybrid-kex': 'Hybrid ML-KEM key agreement is enabled by default on Cloudflare’s edge for TLS 1.3 — if it was not observed, check whether a custom cipher/curve policy on the zone is overriding it.',
    'security-headers': 'Rules → Transform Rules → Modify Response Header, or a Workers response-header handler, to add the missing headers at the edge.',
    'ocsp-stapling': 'Cloudflare staples automatically where the CA supports it; a missing staple usually means the certificate’s CA has retired OCSP rather than a zone misconfiguration.',
    'cipher-suite': 'SSL/TLS → Edge Certificates → Cipher Suites: select a modern AEAD-only profile to drop static-RSA key transport.',
  },
  fastly: {
    hsts: 'Add a `Strict-Transport-Security` response header in the service VCL (`set resp.http.Strict-Transport-Security = ...`) and activate a new version.',
    'security-headers': 'Set the missing headers in `vcl_deliver` on your service, then activate the version.',
    'tls-version': 'Configure the TLS profile on the service to a minimum of TLS 1.2 in the Fastly TLS settings.',
  },
  akamai: {
    hsts: 'Property Manager → Behaviors → HTTP Strict Transport Security; set max-age and includeSubDomains, then activate the property.',
    'security-headers': 'Property Manager → Behaviors → Modify Outgoing Response Header, then activate the property.',
    'tls-version': 'Property Manager → TLS protocol settings: raise the minimum negotiated version to TLS 1.2.',
  },
  cloudfront: {
    hsts: 'Attach a Response Headers Policy with `strictTransportSecurity` (12-month max-age, includeSubDomains) to the distribution behaviour.',
    'security-headers': 'Use a CloudFront Response Headers Policy — it covers CSP, X-Content-Type-Options, Referrer-Policy and frame options without touching the origin.',
    'tls-version': 'Set the distribution’s Security Policy to TLSv1.2_2021, which removes TLS 1.0/1.1 and the legacy suites.',
    'cipher-suite': 'Security Policy TLSv1.2_2021 on the distribution drops the static-RSA suites.',
  },
  'azure-front-door': {
    hsts: 'Rules engine → add a response-header action for `Strict-Transport-Security`.',
    'security-headers': 'Rules engine → Modify response header actions for each missing header.',
    'tls-version': 'Set the custom domain’s minimum TLS version to 1.2 in the Front Door endpoint settings.',
  },
  vercel: {
    hsts: 'Add the header under `headers` in `vercel.json` with `max-age=31536000; includeSubDomains; preload`.',
    'security-headers': 'Add the missing headers to the `headers` array in `vercel.json` (or `next.config.js` headers()).',
  },
  netlify: {
    hsts: 'Add `Strict-Transport-Security` under `[[headers]]` in `netlify.toml` or in the `_headers` file.',
    'security-headers': 'Declare the missing headers under `[[headers]]` in `netlify.toml`.',
  },
  'aws-alb': {
    'tls-version': 'Update the HTTPS listener’s security policy to `ELBSecurityPolicy-TLS13-1-2-2021-06`, which removes TLS 1.0/1.1.',
    'cipher-suite': 'Use `ELBSecurityPolicy-TLS13-1-2-2021-06` on the listener — it excludes static-RSA key transport.',
    hsts: 'ALB does not add response headers; set `Strict-Transport-Security` at the target application or put CloudFront in front.',
    'security-headers': 'ALB cannot inject response headers — set them at the target application, or add a CloudFront Response Headers Policy in front.',
  },
  nginx: {
    hsts: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
    'ocsp-stapling': 'ssl_stapling on; ssl_stapling_verify on; plus ssl_trusted_certificate pointing at the issuer chain.',
    'tls-version': 'ssl_protocols TLSv1.2 TLSv1.3;  — remove TLSv1 and TLSv1.1 from the directive.',
    'cipher-suite': 'Set ssl_ciphers to an ECDHE-only AEAD list and ssl_prefer_server_ciphers off; for TLS 1.3.',
    'security-headers': 'Add the missing headers with `add_header ... always;` in the server block so they are sent on error responses too.',
    'hybrid-kex': 'Requires nginx built against OpenSSL 3.5+; then set `ssl_ecdh_curve X25519MLKEM768:X25519:P-256;`.',
    'forward-secrecy': 'Remove non-ECDHE suites from ssl_ciphers so no static-RSA key transport remains negotiable.',
  },
  apache: {
    hsts: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
    'ocsp-stapling': 'SSLUseStapling On plus SSLStaplingCache "shmcb:logs/ssl_stapling(32768)" at server scope.',
    'tls-version': 'SSLProtocol -all +TLSv1.2 +TLSv1.3',
    'cipher-suite': 'SSLCipherSuite with an ECDHE-only AEAD list, and SSLHonorCipherOrder on.',
    'security-headers': 'Use `Header always set ...` in the vhost so headers are present on error responses as well.',
    'forward-secrecy': 'Drop the aRSA key-transport suites from SSLCipherSuite (e.g. append `!kRSA`).',
  },
  iis: {
    hsts: 'Configure HSTS on the site binding (IIS 10 1709+), or add a `<customHeaders>` entry in web.config.',
    'tls-version': 'Disable TLS 1.0/1.1 under HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols, then reboot.',
    'security-headers': 'Add the missing headers under `<system.webServer><httpProtocol><customHeaders>` in web.config.',
    'ocsp-stapling': 'Enabled by default in IIS on Windows Server; verify the issuer chain is installed in the machine store.',
    'cipher-suite': 'Adjust the SCHANNEL cipher-suite order via Group Policy to an ECDHE AEAD-only list.',
  },
  litespeed: {
    hsts: 'Add the header under the vhost’s Context → Response Headers.',
    'tls-version': 'Set the SSL protocol version to TLS 1.2 + 1.3 in the listener’s SSL settings.',
  },
  caddy: {
    hsts: 'header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
    'security-headers': 'Declare the missing headers in a `header` block in the Caddyfile.',
    'tls-version': 'tls { protocols tls1.2 tls1.3 }',
  },
  envoy: {
    'security-headers': 'Add the headers via `response_headers_to_add` on the route or virtual host.',
    'tls-version': 'Set `tls_minimum_protocol_version: TLSv1_2` on the downstream TLS context.',
  },
  haproxy: {
    hsts: 'http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
    'tls-version': 'Add `ssl-min-ver TLSv1.2` to the bind line.',
    'security-headers': 'Use `http-response set-header` on the frontend for each missing header.',
  },
}

/**
 * Platform-specific remediation for a topic, or `null` when nothing accurate
 * can be said. Null is a valid answer — the recommendation still carries its
 * generic `nextStep`.
 */
export function remediationFor(
  platform: DetectedPlatform,
  topic: RemediationTopic,
): string | null {
  const entry = PLAYBOOK[platform.key]?.[topic]
  if (!entry) return null
  const attribution = platform.label
    ? `${platform.label} detected${platform.basis ? ` (${platform.basis})` : ''}: `
    : ''
  return `${attribution}${entry}`
}

/** Where the change is made — used verbatim as a recommendation's `effort`. */
export function effortFor(platform: DetectedPlatform, fallback: string): string {
  return platform.label ? SURFACE[platform.key] : fallback
}
