/**
 * Cross-module transport + security contract for the seven Intelligence &
 * Operations dashboards (Migration Timeline, PQC Orchestration, Crypto Agility,
 * Runtime Crypto Intelligence, Telemetry Correlation, Drift Detection, Quantum
 * Risk Scoring).
 *
 *   npx tsx tools/intel-ops-contract-check.ts
 *
 * Offline. Pins the defects found in the 2026-10-27 audit:
 *  [1] `?token=` query auth on the routers. The subscription gateway reads ONLY
 *      the Authorization header and lets a header-less request through to the
 *      router (so the router can answer 401). A router that then accepts
 *      `?token=` serves a Pro module to any authenticated plan — and writes the
 *      bearer token into access logs and browser history.
 *  [2] Hand-copied SSE readers / EventSource in the page hooks (double download
 *      on mount, every frame applied, token in the URL for Crypto Agility).
 *  [3] Full payload re-sent on every tick: streams must use the fingerprinted
 *      live-snapshot contract (`<event>` on change, `<event>-unchanged` otherwise).
 *  [4] Both tiers of gating cover every page and API (route + API Pro).
 */
import { readFileSync } from 'node:fs'
import { EventEmitter } from 'node:events'
import { payloadFingerprint, streamLiveSnapshot } from '../src/api-server/live-snapshot-stream'
import { resolveRequiredTier } from '../src/lib/subscription-access'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}
const read = (p: string) => readFileSync(p, 'utf8')
const code = (p: string) => read(p).replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')

const PAGES = [
  { name: 'Migration Timeline', route: '/dashboard/migration-timeline', router: 'src/api-server/migration-orchestrator.ts', api: '/api/v1/migration-orchestrator', hook: 'src/hooks/use-migration-orchestrator.ts', event: 'orchestrator' },
  { name: 'PQC Orchestration', route: '/dashboard/pqc-orchestration', router: 'src/api-server/migration-orchestrator.ts', api: '/api/v1/migration-orchestrator', hook: 'src/hooks/use-migration-orchestrator.ts', event: 'orchestrator' },
  { name: 'Crypto Agility', route: '/dashboard/crypto-agility', router: 'src/api-server/crypto-agility.ts', api: '/api/v1/crypto-agility', hook: 'src/hooks/use-crypto-agility.ts', event: 'agility-update' },
  { name: 'Runtime Crypto Intelligence', route: '/dashboard/runtime-crypto-intel', router: 'src/api-server/runtime-crypto-intel.ts', api: '/api/v1/runtime-crypto-intel', hook: 'src/hooks/use-runtime-crypto-intel.ts', event: 'runtime-intel' },
  { name: 'Telemetry Correlation', route: '/dashboard/telemetry-correlation', router: 'src/api-server/telemetry-correlation.ts', api: '/api/v1/dashboard/telemetry-correlation', hook: 'src/hooks/use-telemetry-correlation.ts', event: 'correlation' },
  { name: 'Drift Detection', route: '/dashboard/drift', router: 'src/api-server/drift-detection.ts', api: '/api/v1/dashboard/drift', hook: 'src/hooks/use-drift-detection.ts', event: 'drift' },
  { name: 'Quantum Risk Scoring', route: '/dashboard/quantum-risk-scoring', router: 'src/api-server/quantum-risk-intel.ts', api: '/api/v1/dashboard/quantum-risk-scoring', hook: 'src/hooks/use-quantum-risk.ts', event: 'quantum-risk' },
]

/* ------------------------------------------------------------------ */
console.log('\n[1] Routers: Authorization header only')
const gateway = code('src/api-server/subscription-guard.ts')
assert(/const token = getToken\(req\)/.test(gateway) && /req\.query\.token/.test(gateway),
  'gateway gates both header credentials and legacy query credentials')
for (const router of Array.from(new Set(PAGES.map((p) => p.router)))) {
  const src = code(router)
  assert(!/req\.query\.token/.test(src), `${router}: no ?token= fallback`)
  assert(/const token = getToken\(req\)/.test(src), `${router}: requireAuth reads getToken(req)`)
}
const mountSrc = code('src/api-server/index.ts')
for (const page of PAGES) {
  assert(mountSrc.includes(`app.use('${page.api}'`), `${page.name}: router mounted at ${page.api}`)
}

/* ------------------------------------------------------------------ */
console.log('\n[2] Hooks: one live client, no EventSource, no token in a URL')
for (const hook of Array.from(new Set(PAGES.map((p) => p.hook)))) {
  const src = code(hook)
  assert(!/EventSource/.test(src) && !/token=/.test(src), `${hook}: no EventSource / token= in a URL`)
  assert(/useLive(Resource|Model)\b/.test(src), `${hook}: wraps the shared use-live-resource client`)
  assert(!/getReader\(\)/.test(src), `${hook}: no hand-copied stream reader`)
}
const liveSrc = code('src/hooks/use-live-resource.ts')
assert(/Authorization: `Bearer \$\{token\}`, Accept: 'text\/event-stream'/.test(liveSrc), 'live client streams with the Authorization header')
assert(/channel\(`\$\{channelPrefix\}-\$\{table\}-\$\{userId\}-\$\{instance\}`\)/.test(liveSrc) && /const instance = nextChannelSeq\+\+/.test(liveSrc),
  'realtime channels are keyed per user AND per hook instance (old drift/QRS topics were global; a duplicate topic throws on .on())')
for (const page of PAGES) {
  assert(read(page.hook).includes(`event: '${page.event}'`), `${page.name}: hook listens for '${page.event}'`)
}

/* ------------------------------------------------------------------ */
console.log('\n[3] Streams: fingerprinted live-snapshot contract')
for (const page of PAGES) {
  const src = code(page.router)
  assert(new RegExp(`streamLiveSnapshot\\(req, res, \\{[\\s\\S]*?event: '${page.event}'`).test(src), `${page.name}: /stream uses streamLiveSnapshot('${page.event}')`)
  assert(!/res\.write\(`event:/.test(src), `${page.name}: router writes no hand-rolled SSE frames`)
}

class FakeRes extends EventEmitter {
  frames: string[] = []
  statusCode = 0
  status(code: number) { this.statusCode = code; return this }
  setHeader() { return this }
  flushHeaders() {}
  write(chunk: string) { this.frames.push(chunk); return true }
}

async function streamProbe() {
  const req = new EventEmitter()
  const res = new FakeRes()
  let calls = 0
  const payloads = [
    { generatedAt: '2026-10-27T10:00:00Z', total: 3, nested: { generatedAt: 'a' } },
    { generatedAt: '2026-10-27T10:00:10Z', total: 3, nested: { generatedAt: 'b' } }, // only build stamps differ
    { generatedAt: '2026-10-27T10:00:20Z', total: 4, nested: { generatedAt: 'c' } }, // content changed
  ]
  streamLiveSnapshot(req as never, res as never, {
    event: 'probe',
    build: async () => payloads[Math.min(calls++, payloads.length - 1)],
    intervalMs: 25,
    heartbeatMs: 10_000,
  })
  await new Promise((resolve) => setTimeout(resolve, 95))
  req.emit('close')
  const names = res.frames.map((frame) => /^event: ([^\n]+)/.exec(frame)?.[1]).filter(Boolean)
  assert(res.statusCode === 200, 'stream answers 200 (refusals travel in-stream)')
  assert(names[0] === 'probe', 'first frame is the full payload', names.join(', '))
  assert(names[1] === 'probe-unchanged', 'a recompute that only moved generatedAt (at any depth) is "-unchanged"')
  assert(names[2] === 'probe', 'a content change sends a full frame again')
  const first = JSON.parse(res.frames[0].split('data: ')[1])
  assert(typeof first.fingerprint === 'string' && first.fingerprint.length === 40, 'full frames carry the fingerprint the client de-dups on')
  assert(payloadFingerprint({ a: 1, generatedAt: 'x' }) === payloadFingerprint({ a: 1, generatedAt: 'y' }), 'fingerprint ignores generatedAt')
  const count = res.frames.length
  await new Promise((resolve) => setTimeout(resolve, 60))
  assert(res.frames.length === count, 'no frames after the client disconnects (timers cleared)')
}

/* ------------------------------------------------------------------ */
console.log('\n[4] Gating: every page route and API is Pro')
const apiTiers = Array.from(read('src/api-server/subscription-guard.ts').matchAll(/\{ prefix: '([^']+)', tier: '([a-z]+)' \}/g)).map((m) => ({ prefix: m[1], tier: m[2] }))
for (const page of PAGES) {
  const rule = apiTiers.find((r) => page.api === r.prefix || page.api.startsWith(`${r.prefix}/`))
  assert(rule?.tier === 'pro', `${page.name}: API ${page.api} requires pro`, rule ? rule.tier : 'no rule')
  assert(resolveRequiredTier(page.route) === 'pro', `${page.name}: route ${page.route} requires pro`, resolveRequiredTier(page.route))
}

/* ------------------------------------------------------------------ */
console.log('\n[5] Reads: a failed query is recorded, never handed on as an empty table')
for (const router of ['src/api-server/crypto-agility.ts', 'src/api-server/runtime-crypto-intel.ts', 'src/api-server/telemetry-correlation.ts', 'src/api-server/drift-detection.ts', 'src/api-server/quantum-risk-intel.ts']) {
  const src = code(router)
  assert(!/function safeRows\b/.test(src), `${router}: no silent safeRows`)
  assert(/createSourceLedger\(/.test(src) && /ledger\.reads/.test(src), `${router}: reads through the source ledger and publishes the outcomes`)
}
const { createSourceLedger } = await import('../src/api-server/source-ledger')
const fakeClient = { from: () => ({}) }
const ledger = createSourceLedger('contract-check')
const silenced = console.warn
console.warn = () => undefined
const failedRows = await ledger.read(fakeClient, 'migration_jobs', 'Migration jobs', 10, async () => ({ data: null, error: { message: '42703: column migration_jobs.criticality does not exist' } }))
const thrownRows = await ledger.read(fakeClient, 'scanner_agents', 'Agent fleet', 10, async () => { throw new Error('network down') })
const cappedRows = await ledger.read(fakeClient, 'runtime_crypto_events', 'Runtime telemetry', 2, async () => ({ data: [{ id: 1 }, { id: 2 }], error: null }))
await ledger.read(fakeClient, 'certificates', 'Certificates', 10, async () => ({ data: [], error: null }))
console.warn = silenced
const stateOf = (key: string) => ledger.reads.find((r) => r.key === key)?.state
assert(failedRows.length === 0 && stateOf('migration_jobs') === 'unavailable', 'a PostgREST error (e.g. 42703) is recorded as unavailable, not as an empty table', stateOf('migration_jobs'))
assert(thrownRows.length === 0 && stateOf('scanner_agents') === 'unavailable', 'a thrown read is recorded as unavailable', stateOf('scanner_agents'))
assert(cappedRows.length === 2 && stateOf('runtime_crypto_events') === 'truncated', 'a read that hits its cap is recorded as truncated', stateOf('runtime_crypto_events'))
assert(stateOf('certificates') === 'empty', 'a successful read with no rows is empty, distinct from unavailable', stateOf('certificates'))
assert(ledger.reads.map((r) => r.key).join(',') === 'migration_jobs,scanner_agents,runtime_crypto_events,certificates', 'outcomes are published in issue order')

/* ------------------------------------------------------------------ */
console.log('\n[6] Simulations: never an operational change on any page')
const { isSimulationRow } = await import('../src/lib/migration/job-safety')
assert(isSimulationRow({ job_type: 'tls_migration', sandbox_mode: 'true' }), 'a projected sandbox marker is a simulation')
assert(isSimulationRow({ job_type: 'tls_migration', metadata: { dryRun: true } }), 'a metadata dry run is a simulation')
assert(!isSimulationRow({ job_type: 'tls_migration', status: 'completed' }), 'an ordinary job is operational')
for (const [file, label] of [
  ['src/lib/drift/drift-intelligence.ts', 'Drift: a simulation never explains drift'],
  ['src/lib/runtime-crypto/runtime-intelligence.ts', 'Runtime: simulations never await runtime confirmation'],
  ['src/lib/crypto-agility/agility-intelligence.ts', 'Crypto Agility: simulations never count as a change'],
] as const) {
  assert(/isSimulationRow\(/.test(code(file)), label)
}
for (const router of ['src/api-server/drift-detection.ts', 'src/api-server/crypto-agility.ts']) {
  assert(/SIMULATION_MARKER_SELECT/.test(code(router)), `${router}: projects the simulation markers it filters on`)
}

/* ------------------------------------------------------------------ */
console.log('\n[7] Pages: shared live status, module brief and evidence sources')
const PAGE_FILES: Record<string, string> = {
  'Migration Timeline': 'src/app/dashboard/migration_timeline/MigrationTimeline.tsx',
  'PQC Orchestration': 'src/app/dashboard/pqc-orchestration/PqcOrchestration.tsx',
  'Crypto Agility': 'src/app/dashboard/crypto-agility/CryptoAgility.tsx',
  'Runtime Crypto Intelligence': 'src/app/dashboard/runtime-crypto-intel/RuntimeCryptoIntel.tsx',
  'Telemetry Correlation': 'src/app/dashboard/telemetry-correlation/TelemetryCorrelation.tsx',
  'Drift Detection': 'src/app/dashboard/drift_detection/DriftDetection.tsx',
  'Quantum Risk Scoring': 'src/app/dashboard/quantum-risk-scoring/QuantumRiskScoring.tsx',
}
for (const [name, file] of Object.entries(PAGE_FILES)) {
  const src = code(file)
  assert(/transport=\{transport\}/.test(src), `${name}: status chip driven by the live transport`)
  assert(/<ModuleBrief\b/.test(src), `${name}: renders the what / why / next-step brief`)
  assert(/<(SourceHealth|EvidenceSources)\b/.test(src), `${name}: renders the evidence-sources strip`)
  assert(!/live \? 'Live'|'Connection lost'/.test(src), `${name}: no hand-built live chip`)
}

await streamProbe()

console.log(`\n${failures === 0 ? 'ALL INTEL-OPS CONTRACT CHECKS PASSED' : `${failures} CHECK(S) FAILED`}\n`)
process.exitCode = failures === 0 ? 0 : 1
