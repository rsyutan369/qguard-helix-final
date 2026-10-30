/**
 * LIVE probe for the seven Intelligence & Operations dashboards' APIs.
 *
 *   npx tsx tools/intel-ops-live-probe.ts [baseUrl]
 *
 * Needs the dev server (default http://localhost:3000) and service-role creds in
 * .env. Sessions are minted with admin magic links for two SEEDED QA accounts
 * (tools/seed-test-subscriptions.ts) and signed out at the end:
 *   PRO      teslagreat101@gmail.com   (override: PROBE_PRO_EMAIL)
 *   STARTER  cybersniper26@gmail.com   (override: PROBE_STARTER_EMAIL)
 *
 * For every endpoint it proves, against the running server and real database:
 *   • no credentials                → 401
 *   • Pro, Authorization header     → 200 with a model carrying generatedAt
 *   • Starter, Authorization header → 403 SUBSCRIPTION_REQUIRED (the gate works)
 *   • Starter, ?token= (no header)  → 401 — before the fix this returned 200:
 *     the gateway skips header-less requests and the router accepted the query
 *     token, so any plan could read a Pro module.
 *   • the stream answers 200, its first event is the full model, and the next
 *     tick is `<event>-unchanged` when nothing changed (fingerprint contract).
 *   • GET /migration-orchestrator/jobs/<unknown id> → 404 (tenant-scoped detail).
 * It also cross-checks that the orchestration model's phase counts partition
 * its total on the live tenant, and that the snapshot has no fabricated
 * scheduler fields.
 */
import 'dotenv/config'
import { createClient, type SupabaseClient } from '@supabase/supabase-js'

const BASE = process.argv[2] || 'http://localhost:3000'
const URL = process.env.VITE_SUPABASE_URL || ''
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
const ANON_KEY = process.env.VITE_SUPABASE_ANON_KEY || ''
const PRO_EMAIL = process.env.PROBE_PRO_EMAIL || 'teslagreat101@gmail.com'
const STARTER_EMAIL = process.env.PROBE_STARTER_EMAIL || 'cybersniper26@gmail.com'

if (!URL || !SERVICE_KEY || !ANON_KEY) {
  console.error('Missing VITE_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / VITE_SUPABASE_ANON_KEY in .env')
  process.exit(1)
}

const admin = createClient(URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } })

let failures = 0
function assert(name: string, ok: boolean, detail = '') {
  if (!ok) failures += 1
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`)
}

const clients: SupabaseClient[] = []
/** A real user session; one throwaway client per sign-in (verifyOtp signs in the client it runs on). */
async function sessionFor(email: string): Promise<string> {
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
  if (error) throw new Error(`generateLink(${email}): ${error.message}`)
  const hashed = (link as unknown as { properties?: { hashed_token?: string } })?.properties?.hashed_token
  const anon = createClient(URL, ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data, error: otpErr } = await anon.auth.verifyOtp({ token_hash: hashed || '', type: 'magiclink' })
  if (otpErr || !data.session) throw new Error(`verifyOtp(${email}): ${otpErr?.message || 'no session'}`)
  clients.push(anon)
  return data.session.access_token
}

async function call(path: string, auth: { header?: string; query?: string }) {
  const url = auth.query ? `${BASE}${path}${path.includes('?') ? '&' : '?'}token=${encodeURIComponent(auth.query)}` : `${BASE}${path}`
  const res = await fetch(url, { headers: auth.header ? { Authorization: `Bearer ${auth.header}` } : {} })
  const body = await res.json().catch(() => ({}))
  return { status: res.status, body: body as Record<string, any> }
}

/** Read SSE frames for up to `ms`, returning the event names in order. */
async function streamEvents(path: string, token: string, ms: number, wanted: number) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), ms)
  const names: string[] = []
  let status = 0
  let firstPayload: Record<string, unknown> | null = null
  try {
    const res = await fetch(`${BASE}${path}`, { headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' }, signal: controller.signal })
    status = res.status
    if (!res.body) return { status, names, firstPayload }
    const reader = res.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    while (names.length < wanted) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, '\n')
      let boundary = buffer.indexOf('\n\n')
      while (boundary !== -1) {
        const frame = buffer.slice(0, boundary)
        buffer = buffer.slice(boundary + 2)
        boundary = buffer.indexOf('\n\n')
        const name = /^event: (.+)$/m.exec(frame)?.[1]
        const data = /^data: (.+)$/m.exec(frame)?.[1]
        if (!name) continue
        names.push(name)
        if (!firstPayload && data) { try { firstPayload = JSON.parse(data) } catch { /* ignore */ } }
      }
    }
  } catch {
    /* aborted at the deadline */
  } finally {
    clearTimeout(timer)
    controller.abort()
  }
  return { status, names, firstPayload }
}

const ENDPOINTS = [
  { name: 'Orchestration', path: '/api/v1/migration-orchestrator', event: 'orchestrator', intervalMs: 10_000 },
  { name: 'Crypto Agility', path: '/api/v1/crypto-agility', event: 'agility-update', intervalMs: 20_000 },
  { name: 'Runtime Crypto Intel', path: '/api/v1/runtime-crypto-intel', event: 'runtime-intel', intervalMs: 10_000, query: 'window=24h' },
  { name: 'Telemetry Correlation', path: '/api/v1/dashboard/telemetry-correlation', event: 'correlation', intervalMs: 20_000 },
  { name: 'Drift Detection', path: '/api/v1/dashboard/drift', event: 'drift', intervalMs: 20_000 },
  { name: 'Quantum Risk Scoring', path: '/api/v1/dashboard/quantum-risk-scoring', event: 'quantum-risk', intervalMs: 15_000 },
]

async function main() {
  console.log(`\n=== intel-ops live probe (${BASE}) ===`)
  const pro = await sessionFor(PRO_EMAIL)
  const starter = await sessionFor(STARTER_EMAIL)

  for (const endpoint of ENDPOINTS) {
    const path = endpoint.query ? `${endpoint.path}?${endpoint.query}` : endpoint.path
    console.log(`\n[${endpoint.name}] ${path}`)
    const anon = await call(path, {})
    assert('no credentials → 401', anon.status === 401, `${anon.status}`)
    const ok = await call(path, { header: pro })
    assert('Pro + header → 200 with a model', ok.status === 200 && typeof ok.body?.data?.generatedAt === 'string', `${ok.status}`)
    const gated = await call(path, { header: starter })
    assert('Starter + header → 403 SUBSCRIPTION_REQUIRED', gated.status === 403 && gated.body?.error?.code === 'SUBSCRIPTION_REQUIRED', `${gated.status} ${gated.body?.error?.code ?? ''}`)
    const bypass = await call(path, { query: starter })
    assert('Starter + ?token= (no header) → 401 (gate bypass closed)', bypass.status === 401, `${bypass.status}`)
    const proQuery = await call(path, { query: pro })
    assert('Pro + ?token= (no header) → 401 (no token in URLs)', proQuery.status === 401, `${proQuery.status}`)
    // Every page except orchestration publishes its read outcomes (`reads`, or
    // `sources` on Crypto Agility). A select naming a missing column, or a bad
    // JSON-key projection, shows up here as `unavailable` instead of as zeros.
    const reads = (ok.body?.data?.reads ?? (Array.isArray(ok.body?.data?.sources) && ok.body.data.sources[0]?.state ? ok.body.data.sources : null)) as Array<{ key: string; state: string }> | null
    if (endpoint.path !== '/api/v1/migration-orchestrator') {
      assert('read outcomes are published', Array.isArray(reads) && reads.length > 0, reads ? `${reads.length} source(s)` : 'none')
      const failed = (reads || []).filter((r) => r.state === 'unavailable').map((r) => r.key)
      assert('every source read succeeded against the live schema', failed.length === 0, failed.length ? `unavailable: ${failed.join(', ')}` : (reads || []).map((r) => `${r.key}:${r.state}`).join(' '))
    }
  }

  console.log('\n[streams] first frame + unchanged tick (read in parallel)')
  const streams = await Promise.all(ENDPOINTS.map(async (endpoint) => {
    const path = `${endpoint.path}/stream${endpoint.query ? `?${endpoint.query}` : ''}`
    return { endpoint, result: await streamEvents(path, pro, endpoint.intervalMs + 8_000, 2) }
  }))
  for (const { endpoint, result } of streams) {
    assert(`${endpoint.name}: stream 200, first frame '${endpoint.event}'`, result.status === 200 && result.names[0] === endpoint.event, `${result.status} ${result.names.join(', ')}`)
    const second = result.names[1]
    assert(`${endpoint.name}: next tick is '${endpoint.event}-unchanged' or a real change`, second === `${endpoint.event}-unchanged` || second === endpoint.event, second ?? 'no second frame')
    assert(`${endpoint.name}: full frame carries a fingerprint`, typeof result.firstPayload?.fingerprint === 'string')
  }

  console.log('\n[orchestration model] live tenant invariants')
  const orch = (await call('/api/v1/migration-orchestrator', { header: pro })).body?.data
  if (orch?.metrics) {
    const phaseSum = Object.values(orch.metrics.phases as Record<string, number>).reduce((a, b) => a + b, 0)
    assert('phase counts partition the operational total', phaseSum === orch.metrics.total, `${phaseSum}/${orch.metrics.total}`)
    assert('verified ≤ completed ≤ total', orch.metrics.verified <= orch.metrics.completed && orch.metrics.completed <= orch.metrics.total, `${orch.metrics.verified}/${orch.metrics.completed}/${orch.metrics.total}`)
    assert('no fabricated scheduler fields (config / scaleTier / workerUtilizationPct)', !('config' in orch) && !('scaleTier' in orch) && !('workerUtilizationPct' in orch.metrics))
    assert('every evidence source was read', Object.values(orch.sources as Record<string, string>).every((s) => s === 'ok'), JSON.stringify(orch.sources))
    console.log(`        tenant: ${orch.metrics.total} operational job(s), ${orch.metrics.simulationsExcluded} simulation(s) excluded, ${orch.plans?.length ?? 0} plan(s)`)
  } else {
    assert('orchestration snapshot readable', false, 'no metrics')
  }
  const missing = await call('/api/v1/migration-orchestrator/jobs/00000000-0000-4000-8000-00000000dead', { header: pro })
  assert('job detail for an unknown id → 404', missing.status === 404, `${missing.status}`)
  const bad = await call('/api/v1/migration-orchestrator/jobs/not-a-uuid%20;drop', { header: pro })
  assert('job detail rejects a malformed id → 400', bad.status === 400, `${bad.status}`)

  for (const client of clients) await client.auth.signOut().catch(() => undefined)
  console.log(`\n${failures === 0 ? 'ALL LIVE PROBES PASSED' : `${failures} LIVE PROBE(S) FAILED`} (sessions signed out)\n`)
  process.exitCode = failures === 0 ? 0 : 1
}

main().catch(async (error) => {
  for (const client of clients) await client.auth.signOut().catch(() => undefined)
  console.error(error)
  process.exitCode = 1
})
