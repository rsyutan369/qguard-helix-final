/**
 * Estate intelligence — scale and integrity check.
 *
 *     npx tsx tools/estate-scale-check.ts [assets=5000]
 *
 * Builds a deterministic synthetic estate (NOT tenant data — a fixture), runs
 * the same pure engine the API serves, and asserts:
 *   1. every actionable finding is routed to exactly one fix (nothing counted twice or lost);
 *   2. certificates are merged by fingerprint;
 *   3. progress, map, ownership and Sankey totals reconcile with the fix totals;
 *   4. validation is evidence-based (completed ≠ validated without a later rescan);
 *   5. every graph the canvas receives is bounded, whatever the estate size;
 *   6. the whole build stays fast enough to serve from a 30 s cache.
 */
import { buildEstateModel, ROOT_CAUSE_LIMIT, NEIGHBOURHOOD_LIMIT, type Row } from '../src/lib/estate'

const ASSETS = Number(process.argv[2]) || 5000
let failures = 0
const check = (label: string, ok: boolean, detail = '') => {
  if (!ok) failures += 1
  console.log(`  ${ok ? '✓' : '✗'} ${label}${detail ? ` — ${detail}` : ''}`)
}

/* ---------------- deterministic fixture ---------------- */
let seed = 42
const rand = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648 }
const pick = <T,>(items: T[]) => items[Math.floor(rand() * items.length)]
const NOW = Date.UTC(2026, 10, 13)
const day = 86400000

const envs = ['prod', 'production', 'staging', 'dev', 'qa', '']
const owners = ['payments-team', 'identity-team', 'platform-sre', 'data-eng', 'web-frontend', '']
const services = ['Payments', 'Customer Portal', 'Identity', 'Data Lake', 'Internal Tools']
const assets: Row[] = []
for (let i = 0; i < ASSETS; i += 1) {
  const owner = pick(owners)
  assets.push({
    id: `a-${i}`, name: i % 3 === 0 ? `svc-${i}.corp.example` : `host-${i}`, type: pick(['web_application', 'api', 'server', 'database', 'load_balancer']),
    environment: pick(envs), service_owner: owner || null, criticality: pick(['critical', 'high', 'medium', 'low', null]),
    metadata: owner ? {} : rand() < 0.3 ? { tags: { team: 'tagged-team' } } : {}, ...(rand() < 0.5 ? {} : {}),
  })
  ;(assets[i].metadata as Record<string, unknown>).business_service = pick(services)
}

const inventory: Row[] = []
const algos: Array<[string, string, number | null, string]> = [
  // algorithm, item_type, key size, role hint
  ['ECDHE', 'key_exchange', 256, 'key-exchange'],
  ['RSA', 'signature', 2048, 'signature'],
  ['RSA', 'key', 4096, 'signature'],
  ['ECDSA', 'signature', 256, 'signature'],
  ['SHA-1', 'hash', null, 'hashing'],
  ['AES-256-GCM', 'cipher', 256, 'encryption'],
  ['ML-KEM-768', 'key_exchange', null, 'key-exchange'],
  ['RSA', 'algorithm', 2048, ''],
  ['NotARealAlgo', 'algorithm', null, ''],
]
for (const asset of assets) {
  const count = 3 + Math.floor(rand() * 10)
  for (let j = 0; j < count; j += 1) {
    const [algorithm, itemType, keySize, role] = pick(algos)
    const lib = rand() < 0.08 ? pick(['openssl-1.1.1', 'bouncycastle-1.68']) : ''
    inventory.push({
      id: `inv-${inventory.length}`, asset_id: asset.id, item_type: lib ? 'library' : itemType, name: lib || algorithm, algorithm, key_size: keySize,
      metadata: { ...(role ? { role } : {}), ...(lib ? { package_name: lib } : {}) },
      discovered_at: new Date(NOW - Math.floor(rand() * 700) * day).toISOString(),
    })
  }
}

// 1,200 unique certificates, many deployed on several assets (≈ 3 records each).
const certificates: Row[] = []
const issuers = ['CN=Corp-Issuing-01,O=Example', 'CN=Corp-Issuing-02,O=Example', "CN=R3,O=Let's Encrypt", 'CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc']
const UNIQUE_CERTS = Math.max(10, Math.round(ASSETS * 0.24))
for (let c = 0; c < UNIQUE_CERTS; c += 1) {
  const deployments = 1 + Math.floor(rand() * 5)
  const issuer = pick(issuers)
  const algorithm = rand() < 0.9 ? pick(['RSA', 'ECDSA']) : 'ML-DSA-65'
  for (let d = 0; d < deployments; d += 1) {
    certificates.push({
      id: `cert-${certificates.length}`, asset_id: `a-${Math.floor(rand() * ASSETS)}`, subject: `CN=svc-${c}.corp.example,OU=Platform`, issuer,
      algorithm, key_size: algorithm === 'RSA' ? 2048 : algorithm === 'ECDSA' ? 256 : null, serial_number: `sn-${c}`,
      not_after: new Date(NOW + 200 * day).toISOString(), fp: `ab${c.toString(16).padStart(8, '0')}`,
      updated_at: new Date(NOW - 400 * day).toISOString(),
    })
  }
}

// Migration jobs on ~15 % of assets, with every phase represented.
const migrationJobs: Row[] = []
for (let i = 0; i < ASSETS; i += 7) {
  migrationJobs.push({ id: `job-${i}`, asset_id: `a-${i}`, status: pick(['queued', 'awaiting_agent', 'running', 'completed', 'failed', 'cancelled']), updated_at: new Date(NOW - 30 * day).toISOString() })
}

// Explicit validation cases on three dedicated assets.
const validation = [
  { id: 'v-validated', scanAfter: true, stillVulnerable: false },
  { id: 'v-regressed', scanAfter: true, stillVulnerable: true },
  { id: 'v-awaiting', scanAfter: false, stillVulnerable: false },
]
for (const v of validation) {
  assets.push({ id: v.id, name: v.id, type: 'server', environment: 'prod', service_owner: 'platform-sre', metadata: {} })
  migrationJobs.push({ id: `job-${v.id}`, asset_id: v.id, status: 'completed', updated_at: new Date(NOW - 10 * day).toISOString() })
  inventory.push({ id: `inv-${v.id}-old`, asset_id: v.id, item_type: 'signature', name: 'RSA', algorithm: 'RSA', key_size: 2048, metadata: { role: 'signature' }, discovered_at: new Date(NOW - 60 * day).toISOString() })
  if (v.scanAfter) {
    inventory.push(v.stillVulnerable
      ? { id: `inv-${v.id}-new`, asset_id: v.id, item_type: 'signature', name: 'RSA', algorithm: 'RSA', key_size: 2048, metadata: { role: 'signature' }, discovered_at: new Date(NOW - 2 * day).toISOString() }
      : { id: `inv-${v.id}-new`, asset_id: v.id, item_type: 'signature', name: 'ML-DSA-65', algorithm: 'ML-DSA-65', key_size: null, metadata: { role: 'signature' }, discovered_at: new Date(NOW - 2 * day).toISOString() })
  }
}

const relationships: Row[] = Array.from({ length: ASSETS }, (_, i) => ({ source_asset_id: `a-${i}`, target_asset_id: `a-${(i * 7 + 3) % ASSETS}`, relationship_type: 'depends-on' }))

console.log(`\nEstate fixture: ${assets.length} assets · ${inventory.length} inventory rows · ${certificates.length} certificate records · ${migrationJobs.length} jobs\n`)

/* ---------------- build ---------------- */
const started = performance.now()
const model = buildEstateModel({ assets, inventory, certificates, relationships, migrationJobs, coverage: [], now: NOW })
const overview = model.overview()
const buildMs = Math.round(performance.now() - started)
const s = overview.summary

console.log('[1] Routing — one finding, one fix')
const actionable = model.observations.filter((o) => o.actionability === 'quantum' || o.actionability === 'classical').length
const inventoryRouted = overview.clusters.filter((c) => c.kind !== 'ca-reissue').reduce((sum, c) => sum + c.observations, 0)
check('every actionable inventory finding lands in exactly one fix (or is covered by its certificate)', inventoryRouted + s.coveredByCertificate === actionable, `${inventoryRouted} routed + ${s.coveredByCertificate} covered = ${actionable}`)
const caMemberships = overview.clusters.filter((c) => c.kind === 'ca-reissue').reduce((sum, c) => sum + c.observations, 0)
const certDeployments = model.certificates.filter((c) => c.actionability === 'quantum' || c.actionability === 'classical').reduce((sum, c) => sum + c.assetIds.size, 0)
check('every vulnerable certificate deployment lands in its issuer\'s re-issue fix', caMemberships === certDeployments, `${caMemberships} = ${certDeployments}`)
check('unrecognised algorithms are reported, never silently dropped', s.unclassifiedObservations > 0 && s.unclassifiedObservations + s.classifiedObservations === inventory.length)
check('PQC (ML-KEM / ML-DSA) is never routed to a fix', !overview.clusters.some((c) => c.algorithms.some((a) => /ML-KEM|ML-DSA/i.test(a))))

console.log('\n[2] Fingerprint merging')
check('certificates merge by fingerprint', s.uniqueCertificates === UNIQUE_CERTS, `${s.certificateRecords} records → ${s.uniqueCertificates} unique (fixture has ${UNIQUE_CERTS})`)
check('reused certificates are counted', s.reusedCertificates > 0, `${s.reusedCertificates} deployed on >1 asset`)
check('component identity collapses repeats', s.uniqueComponents < s.classifiedObservations, `${s.classifiedObservations} findings → ${s.uniqueComponents} unique components`)

console.log('\n[3] Totals reconcile')
const progressOk = overview.clusters.every((c) => Object.values(c.progress).reduce((a, b) => a + b, 0) === c.assets)
check('each fix: progress buckets sum to its asset count', progressOk)
const memberships = overview.clusters.reduce((sum, c) => sum + c.assets, 0)
check('open + validated work items = all asset × fix pairs', s.openWorkItems + s.validatedWorkItems === memberships, `${s.openWorkItems} + ${s.validatedWorkItems} = ${memberships}`)
const sankeyStatus = overview.sankey.links.filter((l) => overview.sankey.nodes[l.target].column === 2).reduce((sum, l) => sum + l.value, 0)
check('Sankey status column = all asset × fix pairs', sankeyStatus === memberships && overview.sankey.total === memberships)
for (const dimension of ['owner', 'service', 'environment', 'type'] as const) {
  const total = overview.maps[dimension].reduce((sum, g) => sum + g.assets, 0)
  check(`estate map by ${dimension} covers every asset once`, total === s.assets, `${total} = ${s.assets}`)
}
const ownershipTotal = overview.ownership.rows.reduce((sum, r) => sum + r.assets, 0) + overview.ownership.unowned.assets
check('ownership rows + unowned = all assets', ownershipTotal === s.assets)
const last = overview.burndown.points.at(-1)
check('burndown ends at the open backlog (dated items)', !!last && last.open <= overview.burndown.openNow && overview.burndown.openNow === s.openWorkItems, `last point ${last?.open} · open ${overview.burndown.openNow}`)
check('fix ranks are 1..n in priority order', overview.clusters.every((c, i) => c.priorityRank === i + 1 && (i === 0 || overview.clusters[i - 1].priority >= c.priority)))

console.log('\n[4] Validation is evidence-based')
const signing = overview.clusters.find((c) => c.kind === 'signing-keys' && c.rootCause.label === 'RSA-2048')
const statusOf = (assetId: string) => (signing ? model.stateById.get(signing.id)?.members.get(assetId)?.status : undefined)
check('completed job + clean rescan → validated', statusOf('v-validated') === 'validated', String(statusOf('v-validated')))
check('completed job + rescan still vulnerable → regressed', statusOf('v-regressed') === 'regressed', String(statusOf('v-regressed')))
check('completed job + no rescan → awaiting validation', statusOf('v-awaiting') === 'awaiting-validation', String(statusOf('v-awaiting')))

console.log('\n[4b] Regressions found on live tenant data')
const tiny = buildEstateModel({
  now: NOW, coverage: [], relationships: [], migrationJobs: [],
  assets: [{ id: 't1', name: 'edge.example.com', type: 'web_application', environment: 'prod', metadata: {} }],
  inventory: [
    { id: 'r1', asset_id: 't1', item_type: 'cipher_suite', name: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', algorithm: 'ECDSA', key_size: 256, metadata: { role: 'tls' }, discovered_at: new Date(NOW).toISOString() },
    { id: 'r2', asset_id: 't1', item_type: 'key_exchange', name: 'ECDHE', algorithm: 'ECDHE', key_size: 256, metadata: { role: 'tls' }, discovered_at: new Date(NOW).toISOString() },
  ],
  certificates: [{ id: 'c1', asset_id: 't1', subject: 'edge.example.com', issuer: 'GB, Greater Manchester, Salford, Sectigo Limited, Sectigo RSA Domain Validation Secure Server CA', algorithm: 'RSA', key_size: 2048, serial_number: 's1' }],
}).overview()
const kex = tiny.clusters.filter((c) => c.kind === 'key-exchange')
check('ECDSA seen in a TLS suite is a signing-key fix, never an ML-KEM key-exchange fix', !kex.some((c) => c.algorithms.some((a) => /ECDSA/i.test(a))) && tiny.clusters.some((c) => c.kind === 'signing-keys' && c.algorithms.some((a) => /ECDSA/i.test(a))), tiny.clusters.map((c) => `${c.kind}:${c.algorithms.join('/')}`).join(', '))
check('ECDHE in TLS is a key-exchange fix', kex.some((c) => c.algorithms.some((a) => /ECDH/i.test(a))))
const ca = tiny.clusters.find((c) => c.kind === 'ca-reissue')
check('bare-value issuer resolves to the CA name, not the country', ca?.rootCause.label === 'Sectigo RSA Domain Validation Secure Server CA', String(ca?.rootCause.label))

console.log('\n[5] Bounded graphs')
const root = model.graph('root-cause')!
check(`root-cause map shows ≤ ${ROOT_CAUSE_LIMIT} fixes`, root.nodes.filter((n) => n.kind === 'fix').length <= ROOT_CAUSE_LIMIT, `${root.nodes.length} nodes / ${root.edges.length} edges`)
const biggest = [...overview.clusters].sort((a, b) => b.assets - a.assets)[0]
const hood = model.graph('neighbourhood', `fix:${biggest.id}`)!
check(`largest fix neighbourhood shows ≤ ${NEIGHBOURHOOD_LIMIT} assets and says so`, hood.nodes.filter((n) => n.kind === 'asset').length <= NEIGHBOURHOOD_LIMIT && (biggest.assets <= NEIGHBOURHOOD_LIMIT || hood.notices.length > 0), `${biggest.assets} members → ${hood.nodes.length} nodes`)
const assetHood = model.graph('neighbourhood', 'asset:a-0')!
check('asset neighbourhood is bounded', assetHood.nodes.length <= 80, `${assetHood.nodes.length} nodes`)
const edgesValid = [root, hood, assetHood].every((g) => { const ids = new Set(g.nodes.map((n) => n.id)); return g.edges.every((e) => ids.has(e.source) && ids.has(e.target)) })
check('every edge points at a node in the same graph', edgesValid)
const detail = model.clusterDetail(biggest.id, { limit: 50 })!
check('fix member list is paged', detail.members.length === Math.min(50, biggest.assets) && detail.total === biggest.assets)
check('campaign waves stay within the planner queue limit (200)', detail.campaign.waves.every((w) => w.assets <= 200), `${detail.campaign.waves.length} waves, size ${detail.campaign.waveSize}`)
const waveTotal = detail.campaign.waves.reduce((sum, w) => sum + w.assets, 0)
check('waves cover exactly the assets that still need a job', waveTotal === biggest.progress.open + biggest.progress.failed + biggest.progress.regressed)
const payloadKb = Math.round(JSON.stringify(overview).length / 1024)
check('overview payload stays small', payloadKb < 1500, `${payloadKb} KB`)

console.log('\n[6] Performance')
check('build + overview under 5 s', buildMs < 5000, `${buildMs} ms`)

console.log(`\nTop fixes:`)
for (const c of overview.clusters.slice(0, 5)) console.log(`  #${c.priorityRank} [${c.priority}] ${c.title} — ${c.assets} assets, ${c.deadline.label}`)
console.log(`\n${failures === 0 ? '✓ ESTATE INTELLIGENCE HOLDS' : `✗ ${failures} CHECK(S) FAILED`}\n`)
process.exit(failures === 0 ? 0 : 1)
