/**
 * Estate Exposure Workflow — accuracy suite.
 *
 *     npx tsx tools/estate-workflow-check.ts
 *
 * /dashboard now draws the estate as a relationship graph, and a graph is the
 * easiest place in a platform to publish something nobody measured: a node is
 * small, unlabelled and persuasive, and an invented edge between two real
 * assets looks exactly like a discovered one.
 *
 * So every claim the projection makes is asserted here against its source rows:
 * that it adds nothing, drops nothing silently, never converts absence into
 * safety, never re-derives a score that belongs to the shared model, and never
 * draws a relationship that is not a row.
 *
 * Pure: no DOM, no network, no database. The projection is a function, so its
 * properties can be proven rather than eyeballed on one tenant's data.
 */
import { readFileSync } from 'node:fs'
import { buildEstateWorkflowGraph, ESTATE_LENSES, type EstateWorkflowInput } from '../src/lib/dashboard/estate-workflow'
import { WORKFLOW_LENSES, focusScope, projectLens } from '../src/lib/scanner/exposure/workflow-graph'

let failures = 0
let checks = 0

function assert(condition: boolean, label: string, detail = '') {
  checks += 1
  if (condition) {
    console.log(`  PASS  ${label}`)
    return
  }
  failures += 1
  console.log(`  FAIL  ${label}${detail ? `\n        ${detail}` : ''}`)
}

function section(title: string) {
  console.log(`\n${title}`)
}

/* ─────────────────────────────────────────────────────────────── the fixture ── */

/**
 * A tenant with every shape that has ever produced a wrong number:
 * an assessed asset, an UNASSESSED asset, a resolved vulnerability that must
 * not count, a relationship pointing at an asset that does not exist, a
 * certificate that has already expired, and an inventory row with no exposure
 * level recorded.
 */
function fixture(): EstateWorkflowInput {
  const yesterday = new Date(Date.now() - 86400000).toISOString()
  const longAgo = new Date(Date.now() - 400 * 86400000).toISOString()
  const soon = new Date(Date.now() + 10 * 86400000).toISOString()

  return {
    assets: [
      { id: 'a1', name: 'edge-gateway', type: 'gateway', environment: 'production', criticality: 'high', status: 'active' },
      { id: 'a2', name: 'billing-db', type: 'database', environment: 'production', criticality: 'critical', status: 'active' },
      // Never scanned. Must NOT read as healthy.
      { id: 'a3', name: 'lab-host', type: 'server', environment: 'lab', criticality: 'low', status: 'active' },
    ],
    relationships: [
      { source_asset_id: 'a1', target_asset_id: 'a2', relationship_type: 'depends_on' },
      // Dangling: the target is not in the estate. Must be dropped, not drawn.
      { source_asset_id: 'a1', target_asset_id: 'ghost', relationship_type: 'depends_on' },
    ],
    inventory: [
      { id: 'c1', asset_id: 'a1', algorithm: 'RSA-2048', protocol: 'TLS', is_vulnerable: true, exposure_level: 'high', discovered_at: yesterday },
      // No exposure level recorded → unclassified, not clean.
      { id: 'c2', asset_id: 'a2', algorithm: 'AES-256-GCM', protocol: 'AT_REST', is_quantum_safe: true, discovered_at: yesterday },
    ],
    exposures: [
      { id: 'e1', asset_id: 'a1', exposure_type: 'Legacy key exchange', severity: 'critical', created_at: yesterday },
    ],
    vulnerabilities: [
      { id: 'v1', asset_id: 'a2', title: 'Weak cipher suite offered', severity: 'high', status: 'open', created_at: yesterday },
      // Closed. Not current exposure — must be excluded.
      { id: 'v2', asset_id: 'a2', title: 'Old finding', severity: 'critical', status: 'resolved', created_at: longAgo },
    ],
    certificates: [
      { id: 'k1', asset_id: 'a1', common_name: 'edge.example.com', algorithm: 'SHA256withRSA', not_after: longAgo, status: 'active' },
      { id: 'k2', asset_id: 'a2', common_name: 'billing.internal', algorithm: 'SHA256withRSA', not_after: soon, status: 'active' },
    ],
    scanResults: [
      { id: 'r1', asset_id: 'a1', algorithm: 'RSA-2048', threat_level: 'critical', remediation: 'Migrate to ML-KEM-768 hybrid key exchange', created_at: yesterday },
      // A scanner FINDING TITLE sitting in the `algorithm` column. It must not
      // become an algorithm node — it is a sentence, not a primitive.
      { id: 'r3', asset_id: 'a1', algorithm: 'Weak RSA Key Size', threat_level: 'high', remediation: 'Migrate to ML-KEM-768 hybrid key exchange', created_at: yesterday },
      { id: 'r2', asset_id: 'a2', algorithm: 'ECDHE-P256', threat_level: 'high', remediation: 'Migrate to ML-KEM-768 hybrid key exchange', created_at: yesterday },
    ],
    sessions: [
      { id: 's1', status: 'completed', findings_count: 3, started_at: yesterday, completed_at: yesterday, created_at: yesterday },
    ],
    runtimeEvents: [],
    assetRisk: new Map([['a1', 82], ['a2', 47]]),
    assetPosture: new Map([['a1', 'vulnerable'], ['a2', 'hybrid']]),
  }
}

const input = fixture()
const graph = buildEstateWorkflowGraph(input)
const byId = new Map(graph.nodes.map((node) => [node.id, node]))
const nodesOf = (kind: string) => graph.nodes.filter((node) => node.kind === kind)

console.log('Estate Exposure Workflow — accuracy\n===================================')

/* ------------------------------------------------------------------ */
section('1. Derived rows ENRICH, they never ADD')
assert(
  nodesOf('asset').length === input.assets.length,
  'every asset is projected, and no asset is invented',
  `${nodesOf('asset').length} nodes vs ${input.assets.length} rows`,
)
assert(
  nodesOf('component').length === input.inventory.length,
  'CBOM components match the inventory exactly',
)
assert(
  nodesOf('certificate').length === input.certificates.length,
  'certificates match the certificate estate exactly',
)
assert(
  graph.reconciliation.findingsProjected === graph.reconciliation.findingsInAssessment,
  'the reconciliation line balances — projected findings == source findings',
  `${graph.reconciliation.findingsProjected} vs ${graph.reconciliation.findingsInAssessment}`,
)
const algorithmLabels = new Set(nodesOf('algorithm').map((node) => node.label.toUpperCase()))
const sourceAlgorithms = new Set(
  [...input.inventory, ...input.certificates, ...input.scanResults]
    .map((row) => String(row.algorithm ?? '').trim().toUpperCase())
    .filter(Boolean),
)
assert(
  [...algorithmLabels].every((label) => sourceAlgorithms.has(label)),
  'every algorithm node names an algorithm some row actually recorded',
  [...algorithmLabels].filter((l) => !sourceAlgorithms.has(l)).join(', '),
)

/* ------------------------------------------------------------------ */
section('2. A closed finding is not current exposure')
assert(
  !graph.nodes.some((node) => node.id === 'finding:vuln:v2'),
  'a resolved vulnerability is excluded from the graph',
)
assert(
  graph.reconciliation.findingsInAssessment === 2,
  'the reconciliation denominator counts only OPEN findings, so the line balances honestly',
  `got ${graph.reconciliation.findingsInAssessment}`,
)

/* ------------------------------------------------------------------ */
section('3. Absence is not safety')
const unassessed = byId.get('asset:a3')
assert(unassessed !== undefined, 'the never-scanned asset is still drawn — it is part of the estate')
assert(unassessed?.severity === null, 'an unassessed asset carries severity null, never info', `got ${unassessed?.severity}`)
assert(unassessed?.detection === 'unknown', 'its detection method is unknown, not observed')
assert(unassessed?.state === 'Not assessed', 'it is labelled "Not assessed"')
assert(
  unassessed?.facts.some((fact) => fact.label === 'Risk score' && fact.value === 'Not assessed'),
  'no risk score is printed for it — a 0 would read as "no risk" on something nobody measured',
  unassessed?.facts.find((f) => f.label === 'Risk score')?.value,
)
assert(unassessed?.quantumStatus === null, 'and no quantum posture is asserted for it')
const unclassified = byId.get('component:c2')
assert(
  unclassified?.severity === null,
  'an inventory row with no exposure level is unclassified, not clean',
  `got ${unclassified?.severity}`,
)

/* ------------------------------------------------------------------ */
section('4. Risk is NOT recomputed — it comes from the shared model')
const a1 = byId.get('asset:a1')
assert(
  a1?.facts.some((fact) => fact.label === 'Risk score' && fact.value === '82/100'),
  'the asset prints the score the shared posture model supplied, unchanged',
  a1?.facts.find((f) => f.label === 'Risk score')?.value,
)
assert(
  a1?.quantumStatus === 'vulnerable',
  'and the posture the shared model supplied, unchanged',
)
const source = readFileSync('src/lib/dashboard/estate-workflow.ts', 'utf8')
assert(
  !/riskScore\s*=\s*\d|\+\s*3\b|score\s*\+=/.test(source),
  'the module contains no private scoring of its own',
)

/* ------------------------------------------------------------------ */
section('5. Topology is observed, never inferred')
const connects = graph.edges.filter((edge) => edge.kind === 'connects')
assert(connects.length === 1, 'only the relationship row that names two REAL assets is drawn', `${connects.length} edges`)
assert(
  connects[0]?.source === 'asset:a1' && connects[0]?.target === 'asset:a2',
  'and it points exactly where the row said',
)
assert(
  !graph.edges.some((edge) => edge.target.includes('ghost')),
  'a relationship pointing at an asset outside the estate is dropped, not drawn to a phantom',
)
assert(graph.estate.relationships === 1, 'the estate summary reports the projected relationship count')
const nodeIds = new Set(graph.nodes.map((node) => node.id))
const dangling = graph.edges.filter((edge) => !nodeIds.has(edge.source) || !nodeIds.has(edge.target))
assert(dangling.length === 0, 'no edge references a node that is not in the graph', `${dangling.length} dangling`)

/* ------------------------------------------------------------------ */
section('6. A scan result is not a third finding register')
/*
 * `pqc_scan_results` records observations that the two finding registers
 * already account for. Projecting it as findings too would inflate the count on
 * a page whose whole job is to state the estate's real exposure.
 */
assert(
  nodesOf('finding').length === 2,
  'scan results contribute algorithms and remediation text, never finding nodes',
  `${nodesOf('finding').length} finding nodes`,
)

/* ------------------------------------------------------------------ */
section('7. Measured facts drive severity')
const expired = byId.get('certificate:k1')
const expiring = byId.get('certificate:k2')
assert(expired?.severity === 'critical', 'an expired certificate is critical', `got ${expired?.severity}`)
assert(expiring?.severity === 'high', 'a certificate inside 30 days is high', `got ${expiring?.severity}`)
assert(
  expired?.facts.some((fact) => fact.label === 'Validity' && fact.value.includes('Expired')),
  'and the inspector states how long ago it expired',
)

/* ------------------------------------------------------------------ */
section('8. Remediation is recorded, not composed')
const remediation = nodesOf('remediation')
assert(remediation.length === 1, 'identical recorded actions collapse into one node', `${remediation.length} nodes`)
assert(
  remediation[0]?.facts.some((fact) => fact.label === 'Assets it applies to' && fact.value === '2'),
  'and it states how many assets it applies to',
)
assert(
  remediation[0]?.detection === 'inferred',
  'grouping an action across observations is a conclusion, so the node is marked inferred',
)

/* ------------------------------------------------------------------ */
section('9. Severity never softens on the way up')
const a1Node = byId.get('asset:a1')
assert(
  a1Node?.severity === 'critical',
  'an asset inherits the WORST severity of its findings',
  `got ${a1Node?.severity}`,
)
const rsa = nodesOf('algorithm').find((node) => node.label.toUpperCase().includes('RSA-2048'))
assert(rsa?.quantumStatus === 'vulnerable', 'RSA is classified quantum-vulnerable')
const aes = nodesOf('algorithm').find((node) => node.label.toUpperCase().includes('AES-256'))
assert(aes?.quantumStatus === 'resistant', 'AES-256 is classified quantum-resistant')
assert(
  !nodesOf('algorithm').some((node) => node.quantumStatus === 'resistant' && /RSA|ECDH|DSA/i.test(node.label)),
  'no classical algorithm is ever classified resistant',
)

/* ------------------------------------------------------------------ */
section('10. The estate summary agrees with the nodes')
assert(graph.estate.assets === 3, 'asset total matches the source rows')
assert(graph.estate.assessedAssets === 2, 'assessed count matches the assets carrying evidence')
assert(graph.estate.unassessedAssets === 1, 'and the remainder is reported as unassessed, not hidden')
assert(
  graph.estate.assessedAssets + graph.estate.unassessedAssets === graph.estate.assets,
  'the two partition the estate — nothing is dropped between them',
)

/* ------------------------------------------------------------------ */
section('11. Bounded, and honest about it')
assert(
  graph.truncation.truncated === false,
  'a small estate reports no truncation',
)
const big = fixture()
big.vulnerabilities = Array.from({ length: 400 }, (_, index) => ({
  id: `v${index}`,
  asset_id: 'a1',
  title: `Finding ${index}`,
  severity: index === 399 ? 'critical' : 'low',
  status: 'open',
  created_at: new Date().toISOString(),
}))
const bounded = buildEstateWorkflowGraph(big)
assert(bounded.truncation.truncated, 'a large estate reports that it was capped')
assert(
  bounded.nodes.some((node) => node.label === 'Finding 399'),
  'the cap keeps the CRITICAL finding — it never drops the worst evidence to fit',
)
assert(
  bounded.reconciliation.findingsInAssessment > bounded.reconciliation.findingsProjected,
  'and the reconciliation line shows the gap rather than hiding it',
  `${bounded.reconciliation.findingsProjected} of ${bounded.reconciliation.findingsInAssessment}`,
)

/* ------------------------------------------------------------------ */
section('12. The page actually swapped, and the two projections share one loader')
const page = readFileSync('src/app/dashboard/page.tsx', 'utf8')
assert(!page.includes('QuantumExposureMap'), 'the Exposure Graph panel is gone from /dashboard')
assert(!page.includes('NodeInspector'), 'the Node Inspector panel is gone from /dashboard')
assert(page.includes('ExposureWorkflowGraph'), 'the Exposure Workflow renders in their place')
assert(page.includes('ESTATE_LENSES'), 'and it uses the estate lens set, not the assessment one')

/*
 * The two projections must read ONE row loader. Two query sets over one tenant
 * is precisely how two panels on the same page come to report a different
 * number of assets, and the whole point of this feature is that they cannot.
 */
const api = readFileSync('src/api-server/dashboard.ts', 'utf8')
const loaderCalls = (api.match(/await loadEstateRows\(/g) || []).length
assert(
  loaderCalls >= 2,
  'both /exposure-map and /estate-workflow call the SAME row loader',
  `${loaderCalls} call site(s)`,
)
assert(
  (api.match(/async function loadEstateRows/g) || []).length === 1,
  'and there is exactly one loader to call',
)
/*
 * Neither estate projection may issue a query of its own. Other endpoints in
 * this file legitimately read the same tables for their own purposes — what
 * matters is that the two things rendered SIDE BY SIDE on /dashboard read one
 * set of rows, so the assertion is scoped to their bodies rather than to the
 * whole file.
 */
/** Slice a declaration's own body: from its marker to the next closing brace
    at column 0 (`}` for a function, `})` for a route). Returns null when the
    declaration is not present at all, which is itself a failure. */
function bodyAfter(marker: string): string | null {
  const start = api.indexOf(marker)
  if (start < 0) return null
  const rest = api.slice(start)
  const ends = [rest.indexOf('\n}\n'), rest.indexOf('\n})\n')].filter((index) => index > 0)
  return ends.length === 0 ? rest : rest.slice(0, Math.min(...ends))
}

for (const [marker, name] of [
  ['async function buildExposureMapFallback', '/exposure-map'],
  ["router.get('/estate-workflow'", '/estate-workflow'],
] as const) {
  const body = bodyAfter(marker)
  assert(
    body !== null && !body.includes('safeRows('),
    `${name} issues no query of its own — it reads the shared loader`,
  )
}

/* ------------------------------------------------------------------ */
section('12b. Finding titles are not cryptography')
/*
 * `crypto_inventory.algorithm` and `pqc_scan_results.algorithm` carry scanner
 * finding TITLES alongside real primitives — "Weak RSA Key Size" sits in the
 * same column as "RSA-2048". Projecting a title as an algorithm publishes an
 * entity that is not cryptography, and an operator who clicks it gets a
 * sentence where a primitive should be.
 */
const algorithmNodeLabels = nodesOf('algorithm').map((node) => node.label)
assert(
  !algorithmNodeLabels.some((label) => /weak|no |missing|expired|deprecated|insecure/i.test(label)),
  'no algorithm node is a scanner finding title',
  algorithmNodeLabels.filter((l) => /weak|no |missing/i.test(l)).join(', '),
)
assert(
  graph.estate.rejectedAlgorithmLabels > 0,
  'rejected finding titles are COUNTED, so a lower algorithm total reads as a rejection rather than missing data',
  `${graph.estate.rejectedAlgorithmLabels} rejected`,
)
assert(
  algorithmNodeLabels.includes('RSA-2048'),
  'and a real primitive in the same column is still projected',
)
/*
 * The component count must come from the SHARED predicate the canonical
 * snapshot uses, or /dashboard publishes a third number for one table.
 */
const moduleSource = readFileSync('src/lib/dashboard/estate-workflow.ts', 'utf8')
assert(
  moduleSource.includes('isCryptographicComponent') && moduleSource.includes('isCryptographicPrimitive'),
  'the projection reuses the platform predicates rather than re-deriving them',
)
assert(
  !moduleSource.includes('of input.inventory'),
  'every inventory read goes through the filtered rows — no raw read can slip a finding row into the CBOM count',
)

/* ------------------------------------------------------------------ */
section('12c. A degraded read is disclosed, never silent')
assert(
  graph.estate.persistence === 'database',
  'a database-backed build reports the database as its source',
)
const memoryBuild = buildEstateWorkflowGraph({ ...fixture(), persistence: 'memory' })
assert(
  memoryBuild.estate.persistence === 'memory',
  'a memory-backed build reports it, so the UI can say the estate is not durable',
)
const dashboardPage = readFileSync('src/app/dashboard/page.tsx', 'utf8')
assert(
  dashboardPage.includes("persistence === 'memory'") && dashboardPage.includes('local scan cache'),
  'and /dashboard renders that disclosure rather than presenting a degraded read as the estate',
)

/* ------------------------------------------------------------------ */
section('12d. Page-wide accuracy invariants')
/*
 * These guard the four defects the /dashboard audit found. They are file
 * assertions rather than data assertions because each one is a RULE about how a
 * number may be produced, and a rule is only worth anything if re-introducing
 * the old shortcut fails the build.
 */
const qr = readFileSync('src/api-server/quantum-readiness.ts', 'utf8')
assert(
  !/quantumVulnerableAssets\s*=\s*vulnerable/.test(qr),
  'no component count is ever assigned into the ASSET fields',
  'the assetsAssessed===0 fallback substituted CBOM components for assets',
)
assert(
  qr.includes('readScannerMemoryRows') && qr.includes("persistence: 'database' | 'memory'"),
  'the canonical snapshot reads the same degraded store the intel view reads, and reports which one answered',
)

const exec = readFileSync('src/api-server/dashboard-executive.ts', 'utf8')
assert(
  exec.includes('criticalHeadline') && exec.includes('Quantum-Vulnerable Components'),
  'the executive headline is UNIT-AWARE — it never labels a component count as an asset count',
)

const dash = readFileSync('src/api-server/dashboard.ts', 'utf8')
assert(
  dash.includes('buildSnapshot(token, user.id)') && /recommendations\.length === 0/.test(dash),
  'an empty recommendations list falls back to the canonical actions before it is published as "nothing to do"',
)

const recsPanel = readFileSync('src/app/dashboard/_components/executive/AiRecommendations.tsx', 'utf8')
assert(
  !recsPanel.includes('posture is stable'),
  'the recommendations empty state makes no claim about posture',
)
assert(
  !recsPanel.includes('text-emerald-400/50'),
  'and it is not painted as a pass — absence is not safety',
)

const timeline = readFileSync('src/app/dashboard/_components/executive/ThreatTimeline.tsx', 'utf8')
assert(
  timeline.includes('No security events recorded') && timeline.includes('not an assessment of your posture'),
  'an empty event stream is distinguished from an empty filter, and neither is phrased as a verdict',
)

/* ------------------------------------------------------------------ */
section('12e. Asset focus — a view, never a recount')
/*
 * Focusing one asset must keep that asset's WHOLE story and nothing else. The
 * trap is the shared algorithm: RSA-2048 sits on both assets, so a naive
 * traversal crosses it and pulls the entire estate back in, leaving a filter
 * that appears to do nothing.
 */
const scopeA1 = focusScope(graph, new Set(['asset:a1']), 'asset')
assert(scopeA1.has('asset:a1'), 'the focused asset is in scope')
assert(!scopeA1.has('asset:a2'), 'the OTHER asset is not — traversal stops at another entity of the focus kind')
assert(scopeA1.has('finding:exposure:e1'), 'a finding observed on the focused asset is in scope')
assert(!scopeA1.has('finding:vuln:v1'), 'a finding belonging only to the other asset is not')
assert(scopeA1.has('component:c1'), 'a component the focused asset hosts is in scope')
assert(scopeA1.has('certificate:k1'), 'a certificate it presents is in scope')
assert(scopeA1.has('scan:s1'), 'the scan session that assessed it is in scope')

const scopeA2 = focusScope(graph, new Set(['asset:a2']), 'asset')
/* Both certificates are signed with SHA256withRSA, so that node is genuinely
   shared between the two assets — the exact case a naive traversal gets wrong. */
const sharedNode = nodesOf('algorithm').find((node) => node.label.toUpperCase().includes('SHA256WITHRSA'))
assert(sharedNode !== undefined, 'the fixture really does contain an algorithm on BOTH assets')
assert(
  sharedNode !== undefined && scopeA1.has(sharedNode.id),
  'a shared algorithm appears under the focused asset',
)
assert(
  sharedNode !== undefined && scopeA2.has(sharedNode.id),
  'and under the other one too — it is genuinely on both, so both must show it',
)
assert(
  !scopeA2.has('asset:a1'),
  'but sharing an algorithm never drags the other asset back into scope',
)

const bothScope = focusScope(graph, new Set(['asset:a1', 'asset:a2']), 'asset')
assert(
  bothScope.has('asset:a1') && bothScope.has('asset:a2'),
  'focusing several entities keeps all of them',
)
assert(
  focusScope(graph, new Set<string>(), 'asset').size === 0,
  'an empty focus scopes nothing — the caller treats that as "show everything"',
)

/* The projection must honour the focus, and must be identical to the unfocused
   projection when no focus is set. */
const lensDef = ESTATE_LENSES[0]
const projectionArgs = {
  lens: lensDef,
  hiddenKinds: new Set<never>(),
  showInferred: true,
  grouping: lensDef.groupBy,
  query: '',
  hiddenSeverities: new Set<never>(),
}
const unfocused = projectLens(graph, projectionArgs)
const focused = projectLens(graph, { ...projectionArgs, focusIds: new Set(['asset:a1']), focusKind: 'asset' })
assert(
  focused.nodes.length < unfocused.nodes.length,
  'a focused projection is smaller than the unfocused one',
  `${focused.nodes.length} vs ${unfocused.nodes.length}`,
)
assert(
  !focused.nodes.some((node) => node.id === 'asset:a2'),
  'and it contains no node outside the focused subgraph',
)
assert(
  projectLens(graph, { ...projectionArgs, focusIds: new Set<string>(), focusKind: 'asset' }).nodes.length ===
    unfocused.nodes.length,
  'an empty focus set changes nothing',
)
assert(
  focused.edges.every((edge) => focused.nodes.some((n) => n.id === edge.source) && focused.nodes.some((n) => n.id === edge.target)),
  'no edge in a focused projection dangles',
)

/* Focus is a VIEW: the reconciliation totals still describe the whole estate,
   and the UI must say a focus is active rather than let a subset be read as
   the tenant's full exposure. */
const renderer = readFileSync('src/components/exposure/ExposureWorkflowGraph.tsx', 'utf8')
assert(renderer.includes('FocusPanel'), 'the renderer offers a focus picker')
assert(
  renderer.includes('the canvas shows that subset and everything attached to it') &&
    renderer.includes('still describe the whole estate'),
  'and discloses, when a focus is active, that the totals above are not what is drawn',
)
assert(
  readFileSync('src/app/dashboard/page.tsx', 'utf8').includes('focusKind="asset"'),
  '/dashboard focuses on assets',
)

/* ------------------------------------------------------------------ */
section('13. Lens integrity')
assert(ESTATE_LENSES.length >= 6, 'the estate ships a full lens set')
const lensKinds = new Set(ESTATE_LENSES.flatMap((lens) => lens.kinds))
assert(
  [...lensKinds].every((kind) => kind in graph.counts),
  'every kind a lens admits exists in the graph vocabulary',
)
assert(
  ESTATE_LENSES.every((lens) => lens.description.length > 40),
  'each lens explains what it is showing, so a reader is never guessing',
)
assert(
  new Set(ESTATE_LENSES.map((lens) => lens.id)).size === ESTATE_LENSES.length,
  'lens ids are unique',
)
assert(
  WORKFLOW_LENSES.length === 8,
  'the assessment lens set is untouched — Local and Dev render exactly as before',
  `${WORKFLOW_LENSES.length} lenses`,
)

console.log(`\n${checks - failures}/${checks} checks passed`)
if (failures > 0) {
  console.log(`${failures} FAILED`)
  process.exit(1)
}
