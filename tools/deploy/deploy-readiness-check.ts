/**
 * Deployment-readiness regression check (hermetic: no network, no Supabase).
 *
 *   npm run check:deploy
 *
 * Verifies the production-deployment layer added for the Vercel + DOKS +
 * Supabase topology, so a later edit cannot silently break it:
 *   1. split-origin API routing (src/lib/api-origin-core.ts)
 *   2. access-log redaction of credential query parameters
 *   3. production configuration preflight (fail-safe on missing/unsafe config)
 *   4. trusted client-IP resolution is opt-in
 *   5. liveness/readiness probes (incl. drain) served ahead of HTTPS enforcement
 *   6. vercel.json routing/security invariants
 *   7. .env.example carries names only (no committed secrets)
 *   8. Kubernetes manifests keep their safety invariants
 */
import express from 'express'
import { readFileSync } from 'node:fs'
import type { AddressInfo } from 'node:net'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { normaliseApiOrigin, resolveApiUrl } from '../../src/lib/api-origin-core'
import { redactUrl, requestContext } from '../../src/api-server/runtime/observability'
import { checkProductionConfig } from '../../src/api-server/runtime/config'
import { trustedClientIp } from '../../src/api-server/runtime/client-ip'
import { healthProbeRoutes } from '../../src/api-server/runtime/health'
import { beginDrain } from '../../src/api-server/runtime/lifecycle'
import { requiredTierForPath } from '../../src/api-server/subscription-guard'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')
const read = (relative: string) => readFileSync(path.join(root, relative), 'utf8')

let passed = 0
const failures: string[] = []
function check(name: string, condition: boolean, detail = '') {
  if (condition) passed += 1
  else failures.push(`${name}${detail ? ` — ${detail}` : ''}`)
}

// 1. Split-origin API routing ------------------------------------------------
{
  const page = 'https://qguardhelix.com/dashboard/scanner?x=1'
  const api = normaliseApiOrigin('https://api.qguardhelix.com/')
  check('api origin normalised', api === 'https://api.qguardhelix.com', String(api))
  check('api origin rejects non-http', normaliseApiOrigin('javascript:alert(1)') === null)
  check('api origin unset → null', normaliseApiOrigin('') === null && normaliseApiOrigin(undefined) === null)
  check('relative /api rewritten', resolveApiUrl('/api/v1/health?token=a', api, page) === 'https://api.qguardhelix.com/api/v1/health?token=a')
  check('absolute same-origin /api rewritten', resolveApiUrl('https://qguardhelix.com/api/v1/x', api, page) === 'https://api.qguardhelix.com/api/v1/x')
  check('non-api path untouched', resolveApiUrl('/assets/app.js', api, page) === '/assets/app.js')
  check('/apix not treated as /api/', resolveApiUrl('/apix/v1', api, page) === '/apix/v1')
  check('cross-origin untouched', resolveApiUrl('https://xyz.supabase.co/rest/v1/assets', api, page) === 'https://xyz.supabase.co/rest/v1/assets')
  check('no origin configured → unchanged', resolveApiUrl('/api/v1/health', null, page) === '/api/v1/health')
}

// 2. Redaction ------------------------------------------------------------------
{
  const out = redactUrl('/api/v1/metrics/stream?token=eyJhbGciOi.xx.yy&range=30d')
  check('token redacted', !out.includes('eyJ') && out.includes('token=[REDACTED]'), out)
  check('benign params kept', out.includes('range=30d'), out)
  check('path without query unchanged', redactUrl('/api/v1/health') === '/api/v1/health')
  check('SSE ticket redacted', redactUrl('/api/v1/admin/stream?ticket=fixture') === '/api/v1/admin/stream?ticket=[REDACTED]')
}

{
  check('QKMS aliases retain Elite access requirements',
    requiredTierForPath('/api/v1/dashboard/qkms/keys') === 'elite' && requiredTierForPath('/API/QkMs/') === 'elite')
  check('legacy dashboard orchestration routes retain their module tiers',
    requiredTierForPath('/api/v1/dashboard/migration-sandbox/') === 'basic' &&
    requiredTierForPath('/api/v1/dashboard/harvest-now/defense') === 'basic' &&
    requiredTierForPath('/api/v1/dashboard/pqc-orchestration/jobs') === 'pro')
  check('separate dashboard paths retain access policy', requiredTierForPath('/api/v1/dashboard/qkms-other') === null)
}

// 3. Production configuration preflight ------------------------------------------
{
  const complete = {
    VITE_SUPABASE_URL: 'https://example.supabase.co',
    VITE_SUPABASE_ANON_KEY: 'anon',
    SUPABASE_SERVICE_ROLE_KEY: 'service',
    APP_ORIGIN: 'https://qguardhelix.com',
    QGUARD_CONTROL_PLANE_URL: 'https://api.qguardhelix.com',
    QGUARD_ENVIRONMENT: 'production',
    PUBLIC_APP_URL: 'https://qguardhelix.com',
  }
  check('complete config has no errors', checkProductionConfig(complete).errors.length === 0, JSON.stringify(checkProductionConfig(complete).errors))
  const empty = checkProductionConfig({})
  check('missing service key is an error', empty.errors.some((e) => e.includes('SUPABASE_SERVICE_ROLE_KEY')))
  check('missing APP_ORIGIN is an error', empty.errors.some((e) => e.includes('APP_ORIGIN')))
  check('missing control plane is an error', empty.errors.some((e) => e.includes('QGUARD_CONTROL_PLANE_URL')))
  check('plaintext control plane rejected', checkProductionConfig({ ...complete, QGUARD_CONTROL_PLANE_URL: 'http://api.qguardhelix.com' }).errors.length > 0)
  check('auto-confirm refused', checkProductionConfig({ ...complete, REGISTRATION_AUTO_CONFIRM: 'true' }).errors.length > 0)
  check('shadow enforcement refused', checkProductionConfig({ ...complete, SUBSCRIPTION_ENFORCEMENT: 'shadow' }).errors.length > 0)
  check('fallback project refused', checkProductionConfig({ ...complete, SUPABASE_FALLBACK_SERVICE_ROLE_KEY: 'x' }).errors.length > 0)
  check('platform repo token refused', checkProductionConfig({ ...complete, GITHUB_TOKEN: 'x' }).errors.length > 0)
  const overridden = checkProductionConfig({ ...complete, GITHUB_TOKEN: 'x', QGUARD_ALLOW_UNSAFE_CONFIG: 'true' })
  check('explicit override downgrades unsafe to warning', overridden.errors.length === 0 && overridden.warnings.some((w) => w.includes('GITHUB_TOKEN')))
  check('override never waives REQUIRED', checkProductionConfig({ QGUARD_ALLOW_UNSAFE_CONFIG: 'true' }).errors.length > 0)
  const noSecretValues = JSON.stringify(checkProductionConfig({ ...complete, GITHUB_TOKEN: 'ghp_SECRETVALUE' }))
  check('preflight never echoes values', !noSecretValues.includes('ghp_SECRETVALUE'))
  const overCeiling = checkProductionConfig({ ...complete, PUBLIC_SCAN_MAX_CONCURRENT: '64' })
  check('public scan concurrency above the measured ceiling warns', overCeiling.warnings.some((w) => w.includes('PUBLIC_SCAN_MAX_CONCURRENT=64')) && overCeiling.errors.length === checkProductionConfig(complete).errors.length)
}

// 4. Trusted client IP --------------------------------------------------------------
{
  const req = (headers: Record<string, string>) => ({ headers } as unknown as express.Request)
  const previous = process.env.TRUSTED_CLIENT_IP_HEADER
  delete process.env.TRUSTED_CLIENT_IP_HEADER
  check('unset → null (legacy behaviour)', trustedClientIp(req({ 'cf-connecting-ip': '203.0.113.9' })) === null)
  process.env.TRUSTED_CLIENT_IP_HEADER = 'cf-connecting-ip'
  check('configured header used', trustedClientIp(req({ 'cf-connecting-ip': '203.0.113.9' })) === '203.0.113.9')
  check('non-IP value ignored', trustedClientIp(req({ 'cf-connecting-ip': 'not-an-ip' })) === null)
  if (previous === undefined) delete process.env.TRUSTED_CLIENT_IP_HEADER
  else process.env.TRUSTED_CLIENT_IP_HEADER = previous
}

// 5. Probes ---------------------------------------------------------------------------
async function probeChecks() {
  const saved = { url: process.env.VITE_SUPABASE_URL, anon: process.env.VITE_SUPABASE_ANON_KEY, svc: process.env.SUPABASE_SERVICE_ROLE_KEY }
  delete process.env.VITE_SUPABASE_URL
  delete process.env.VITE_SUPABASE_ANON_KEY
  delete process.env.SUPABASE_SERVICE_ROLE_KEY
  const app = express()
  app.use(requestContext)
  app.use(healthProbeRoutes)
  const server = app.listen(0, '127.0.0.1')
  await new Promise((resolve) => server.once('listening', resolve))
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  try {
    const live = await fetch(`${base}/api/v1/healthz`)
    check('healthz 200', live.status === 200, String(live.status))
    check('request id header present', Boolean(live.headers.get('x-request-id')))
    const unready = await fetch(`${base}/api/v1/readyz`)
    const unreadyBody = (await unready.json()) as { status?: string; build?: Record<string, unknown> }
    check('readyz 503 when Supabase config missing', unready.status === 503 && unreadyBody.status === 'misconfigured', `${unready.status} ${unreadyBody.status}`)
    check('readyz does not disclose runtime versions', !('openssl' in (unreadyBody.build || {})) && !('node' in (unreadyBody.build || {})))
    beginDrain()
    const draining = await fetch(`${base}/api/v1/readyz`)
    check('readyz 503 while draining', draining.status === 503 && ((await draining.json()) as { status?: string }).status === 'draining')
    const stillLive = await fetch(`${base}/api/v1/healthz`)
    check('healthz stays 200 while draining', stillLive.status === 200)
  } finally {
    server.closeAllConnections()
    await new Promise((resolve) => server.close(resolve))
    if (saved.url) process.env.VITE_SUPABASE_URL = saved.url
    if (saved.anon) process.env.VITE_SUPABASE_ANON_KEY = saved.anon
    if (saved.svc) process.env.SUPABASE_SERVICE_ROLE_KEY = saved.svc
  }
  const index = read('src/api-server/index.ts')
  const probesAt = index.indexOf('app.use(healthProbeRoutes)')
  const httpsAt = index.indexOf('app.use(enforceHttps)')
  check('probes mounted before HTTPS enforcement', probesAt > 0 && httpsAt > 0 && probesAt < httpsAt)
  const publicApi = read('src/api-server/public-api.ts')
  const publicProbesAt = publicApi.indexOf('app.use(publicHealthRoutes())')
  const publicHttpsAt = publicApi.indexOf('app.use(enforceHttps)')
  check('public API probes mounted before HTTPS enforcement', publicProbesAt > 0 && publicHttpsAt > 0 && publicProbesAt < publicHttpsAt)
}

// 6. vercel.json -------------------------------------------------------------------------
{
  const vercel = JSON.parse(read('vercel.json')) as {
    rewrites?: Array<{ source: string; destination: string }>
    redirects?: Array<{ source: string }>
    headers?: Array<{ source: string; headers: Array<{ key: string; value: string }> }>
    buildCommand?: string
  }
  const rewrites = vercel.rewrites || []
  check('api rewrite is first', rewrites[0]?.source === '/api/:path*' && /^https:\/\//.test(rewrites[0]?.destination || ''))
  check('SPA fallback is last and excludes api/assets', rewrites[rewrites.length - 1]?.destination === '/index.html' && rewrites[rewrites.length - 1]?.source.includes('(?!api/|assets/)'))
  check('installer path redirected', (vercel.redirects || []).some((r) => r.source === '/downloads/QGuard-Messaging-Setup.exe'))
  check('build prunes gated artefacts', (vercel.buildCommand || '').includes('prune-static-output'))
  const apiHeaders = (vercel.headers || []).find((h) => h.source === '/api/(.*)')
  check('CDN caching of proxied API disabled', Boolean(apiHeaders?.headers.some((h) => h.key === 'x-vercel-enable-rewrite-caching' && h.value === '0')))
  const global = (vercel.headers || []).find((h) => h.source === '/(.*)')
  check('HSTS + frame-ancestors kept', Boolean(global?.headers.some((h) => h.key === 'Strict-Transport-Security')) && Boolean(global?.headers.some((h) => h.value.includes("frame-ancestors 'none'"))))
}

// 7. .env.example is names-only ------------------------------------------------------------
{
  const example = read('.env.example')
  const assigned = example
    .split(/\r?\n/)
    .filter((line) => /^[A-Z0-9_]+=\S/.test(line))
  check('.env.example assigns no values', assigned.length === 0, assigned.map((l) => l.split('=')[0]).join(', '))
  check('.env.example contains no JWT', !/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/.test(example))
}

// 8. Kubernetes invariants ------------------------------------------------------------------
{
  const deployment = read('deploy/k8s/base/deployment.yaml')
  const config = read('deploy/k8s/base/configmap.yaml')
  const service = read('deploy/k8s/base/service.yaml')
  const policy = read('deploy/k8s/base/networkpolicy.yaml')
  check('replicas pinned to 1 (per-process state)', /\n  replicas: 1\n/.test(deployment))
  check('probes target healthz/readyz', deployment.includes('/api/v1/healthz') && deployment.includes('/api/v1/readyz'))
  check('pod runs non-root, read-only root fs', deployment.includes('runAsNonRoot: true') && deployment.includes('readOnlyRootFilesystem: true'))
  check('service-account token not mounted', deployment.includes('automountServiceAccountToken: false'))
  check('NODE_ENV production + auto-confirm off', config.includes('NODE_ENV: "production"') && config.includes('REGISTRATION_AUTO_CONFIRM: "false"'))
  check('HTTP load balancer type pinned', service.includes('do-loadbalancer-type: "REGIONAL"'))
  check('metadata service blocked', policy.includes('169.254.0.0/16') && policy.includes('10.0.0.0/8'))
  const grace = Number(/terminationGracePeriodSeconds: (\d+)/.exec(deployment)?.[1] || 0)
  const drainMs = Number(/SHUTDOWN_DRAIN_MS: "(\d+)"/.exec(config)?.[1] || 0)
  check('grace period covers preStop + delay + drain', grace * 1000 > 10_000 + 5_000 + drainMs, `${grace}s vs ${drainMs}ms`)
  const publicScanConcurrency = Number(/PUBLIC_SCAN_MAX_CONCURRENT: "(\d+)"/.exec(config)?.[1] || 0)
  check('public scan capacity set, within the measured ceiling (48)', publicScanConcurrency >= 1 && publicScanConcurrency <= 48, `${publicScanConcurrency}`)
}

await probeChecks()

// exitCode rather than process.exit(): exiting while fetch's keep-alive sockets
// are closing trips a libuv assertion on Windows. The loop drains on its own.
if (failures.length) {
  console.error(`\n✗ ${failures.length} deployment-readiness check(s) failed:`)
  for (const failure of failures) console.error(`  - ${failure}`)
  console.error(`  (${passed} passed)`)
  process.exitCode = 1
} else {
  console.log(`✓ ${passed} deployment-readiness checks passed`)
}
