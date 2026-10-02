/**
 * Estate Exposure Workflow — accuracy suite.
 *
 *     npx tsx tools/estate-workflow-check.ts
 *
 * /dashboard draws the estate as a relationship graph, and a graph is the
 * easiest place in a platform to publish something nobody measured: a node is
 * small, unlabelled and persuasive, and an invented edge between two real
 * assets looks exactly like a discovered one.
 *
 * So every claim the projection makes is asserted here against its inputs:
 * that it counts the SAME canonical findings and CBOM the KPI cards count, adds
 * nothing, drops nothing silently, never converts absence into safety, never
 * lends one entity's severity to another, never re-derives a score that belongs
 * to the shared model, and never draws a relationship that is not a row.
 *
 * Pure: no DOM, no network, no database. The projection is a function, so its
 * properties can be proven rather than eyeballed on one tenant's data.
 */
import { readFileSync } from 'node:fs'
import {
  buildEstateWorkflowGraph,
  ESTATE_GROUPINGS,
  ESTATE_LENSES,
  groupRecommendedActions,
  quantumVerdictFor,
  type EstateComponentInput,
  type EstateFindingInput,
  type EstateWorkflowInput,
} from '../src/lib/dashboard/estate-workflow'
import { WORKFLOW_LENSES, focusScope, projectLens } from '../src/lib/scanner/exposure/workflow-graph'
import { DEPRECATED_PROTOCOL_RE, statusFromThreat } from '../src/api-server/scanner'

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

/** Strip comments — the comment that RECORDS a removed defect must not trip the check that forbids it. */
const code = (path: string) =>
  readFileSync(path, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')

/* ─────────────────────────────────────────────────────────────── the fixture ── */

function finding(partial: Partial<EstateFindingInput> & Pick<EstateFindingInput, 'id' | 'title' | 'threatLevel'>): EstateFindingInput {
  return {
    assetId: '',
    category: 'crypto_review',
    status: 'Quantum-vulnerable',
    description: `${partial.title} observed`,
    recommendation: '',
    evidence: 'Recorded by the scanner.',
    location: 'edge.example.com',
    detectedAt: new Date(Date.now() - 86400000).toISOString(),
    observations: 2,
    sources: ['web-scanner', 'crypto_exposures'],
    ownership: 'customer',
    keySize: null,
    ...partial,
  }
}

function component(partial: Partial<EstateComponentInput> & Pick<EstateComponentInput, 'id' | 'algorithm'>): EstateComponentInput {
  return {
    assetId: '',
    name: partial.algorithm,
    type: 'algorithm',
    isVulnerable: false,
    isQuantumSafe: false,
    riskSeverity: '',
    instances: 1,
    detectionMethod: 'scanner',
    lastSeen: null,
    replacement: null,
    ...partial,
  }
}

/**
 * A tenant with every shape that has ever produced a wrong number on
 * /dashboard: a PQC-ready confirmation beside open findings, a finding that
 * cannot be linked to an asset, an asset nobody scanned, a "no action
 * required" recommendation, a placeholder recommendation, a component recorded
 * with many instances, the same key named two ways, an expired certificate, a
 * relationship to an asset that does not exist, and PQC algorithms sitting on
 * an asset whose other findings are high.
 */
function fixture(): EstateWorkflowInput {
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
    findings: [
      finding({ id: 'f1', assetId: 'a1', title: 'RSA-2048', category: 'rsa', threatLevel: 'CRITICAL', recommendation: 'Migrate to ML-KEM-768 hybrid key exchange' }),
      finding({ id: 'f2', assetId: 'a1', title: 'Missing CSP', threatLevel: 'MEDIUM', status: 'Misconfigured', recommendation: 'Deploy a Content-Security-Policy header' }),
      finding({ id: 'f3', assetId: 'a2', title: 'ECDHE-P256', category: 'ecc', threatLevel: 'HIGH', recommendation: 'Migrate to ML-KEM-768 hybrid key exchange' }),
      // "No action required" is not an action.
      finding({ id: 'f4', assetId: 'a2', title: 'TLSv1.3', category: 'weak_tls', threatLevel: 'LOW', recommendation: 'No action required. TLS 1.3 is current.' }),
      // A placeholder the writers substitute when no narrative exists.
      finding({ id: 'f5', assetId: 'a2', title: 'HNDL Exposure', threatLevel: 'HIGH', recommendation: 'Create a PQC remediation plan for this exposure.' }),
      // Resolves to no inventoried asset — kept, reported unlinked, never guessed.
      finding({ id: 'f6', assetId: '', title: 'Weak HSTS Config', threatLevel: 'LOW', location: 'unknown.example.net', recommendation: 'Set HSTS max-age to one year' }),
      // PQC-ready confirmation — evidence, NOT exposure.
      finding({ id: 'f7', assetId: 'a2', title: 'ML-KEM', category: 'Web Crypto (Post-Quantum)', threatLevel: 'SAFE', status: 'PQC-ready' }),
    ],
    components: [
      component({ id: 'c1', assetId: 'a1', algorithm: 'RSA-2048', isVulnerable: true, riskSeverity: 'critical', instances: 3 }),
      component({ id: 'c2', assetId: 'a2', algorithm: 'AES-256-GCM', isQuantumSafe: true, riskSeverity: 'safe' }),
      component({ id: 'c3', assetId: 'a2', algorithm: 'ML-KEM', type: 'library', isQuantumSafe: true, riskSeverity: 'safe', instances: 35 }),
      component({ id: 'c4', assetId: 'a2', algorithm: 'ECDSA P-256 (Certificate)', type: 'certificate', isVulnerable: true, riskSeverity: 'high' }),
      // Tenant says vulnerable; the knowledge base says the primitive is resistant.
      component({ id: 'c5', assetId: 'a1', algorithm: 'TLS_AES_256_GCM_SHA384', isVulnerable: true, riskSeverity: 'moderate' }),
      // A finding TITLE filed as a component — no algorithm node may come of it.
      component({ id: 'c6', assetId: 'a2', algorithm: 'ECDSA Certificate Detected', type: 'certificate', isVulnerable: true, riskSeverity: 'high' }),
    ],
    certificates: [
      { id: 'k1', asset_id: 'a1', subject: 'edge.example.com', issuer: 'Example CA', algorithm: 'SHA256withRSA', not_after: longAgo, status: 'active' },
      // Same key as component c4, recorded without the writer's qualifier.
      { id: 'k2', asset_id: 'a2', subject: 'billing.internal', issuer: 'Internal CA', algorithm: 'ECDSA P-256', not_after: soon, status: 'active' },
    ],
    scanLinks: [
      { scan_session_id: 's1', asset_id: 'a1' },
      { scan_session_id: 's1', asset_id: 'a2' },
    ],
    sessions: [
      { id: 's1', status: 'completed', target_scope: 'https://edge.example.com/', findings_count: 120, started_at: longAgo, completed_at: longAgo, created_at: longAgo },
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
const algorithmNamed = (label: string) => nodesOf('algorithm').find((node) => node.label.toUpperCase() === label.toUpperCase())

console.log('Estate Exposure Workflow — accuracy\n===================================')

/* ------------------------------------------------------------------ */
section('1. One finding set, one CBOM — the same canonical sets the KPIs count')
const openInput = input.findings.filter((f) => f.threatLevel !== 'SAFE')
assert(
  nodesOf('finding').length === openInput.length,
  'every OPEN canonical finding is one node — no second register is projected beside it',
  `${nodesOf('finding').length} nodes vs ${openInput.length} open findings`,
)
assert(!byId.has('finding:f7'), 'a PQC-ready confirmation is not drawn as a finding')
assert(graph.estate.pqcConfirmations === 1, 'and it is COUNTED, so the smaller finding total is explained', `${graph.estate.pqcConfirmations}`)
assert(graph.estate.openFindings === openInput.length, 'the estate reports the open-finding total the Open Findings KPI prints')
assert(
  nodesOf('component').length === input.components.length,
  'one node per canonical CBOM component — never one per inventory instance',
  `${nodesOf('component').length} nodes vs ${input.components.length} components`,
)
assert(
  graph.estate.componentInstances === input.components.reduce((sum, c) => sum + c.instances, 0),
  'the recorded instances are summed and reported beside the component count',
  `${graph.estate.componentInstances}`,
)
assert(
  graph.reconciliation.findingsProjected === graph.reconciliation.findingsInAssessment &&
    graph.reconciliation.componentsProjected === graph.reconciliation.componentsInAssessment,
  'the reconciliation line balances against the canonical totals',
)
assert(
  graph.reconciliation.exposuresInAssessment === 0 && graph.reconciliation.exposuresProjected === 0,
  'no "correlated exposure" count is claimed for a projection that draws none',
)
assert(byId.get('component:c1')?.weight === 3, 'a component is sized by its recorded instances')

/* ------------------------------------------------------------------ */
section('2. An unlinked finding is kept and stated, never attached to a guess')
assert(byId.has('finding:f6'), 'the unlinked finding is still drawn — it is real exposure')
assert(
  !graph.edges.some((edge) => edge.source === 'finding:f6' && edge.kind === 'observed-at'),
  'but it is attached to no asset',
)
assert(graph.estate.unlinkedFindings === 1, 'and the estate reports how many could not be linked')

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
)
assert(unassessed?.quantumStatus === null, 'and no quantum posture is asserted for it')
assert(byId.get('component:c2')?.severity === null, 'a PQC-ready component carries no severity')

/* ------------------------------------------------------------------ */
section('4. Risk is NOT recomputed — it comes from the shared model')
const a1 = byId.get('asset:a1')
assert(
  a1?.facts.some((fact) => fact.label === 'Risk score' && fact.value === '82/100'),
  'the asset prints the score the shared posture model supplied, unchanged',
  a1?.facts.find((f) => f.label === 'Risk score')?.value,
)
assert(a1?.quantumStatus === 'vulnerable', 'and the posture the shared model supplied, unchanged')
const moduleCode = code('src/lib/dashboard/estate-workflow.ts')
assert(!/riskScore\s*=\s*\d|\+\s*3\b|score\s*\+=/.test(moduleCode), 'the module contains no private scoring of its own')

/* ------------------------------------------------------------------ */
section('5. Severity belongs to its OWN evidence')
/*
 * ML-KEM and AES-256 sit on an asset whose other findings are high. They used
 * to inherit that severity, so the Cryptography lens grouped post-quantum
 * algorithms under HIGH, and every remediation — "No action required"
 * included — read HIGH with every finding on the asset attached.
 */
assert(algorithmNamed('ML-KEM')?.severity === null, 'ML-KEM carries no severity — no finding concerns it', `${algorithmNamed('ML-KEM')?.severity}`)
assert(algorithmNamed('AES-256-GCM')?.severity === null, 'AES-256-GCM carries no severity — no finding concerns it')
assert(algorithmNamed('RSA-2048')?.severity === 'critical', 'RSA-2048 carries the severity of the finding about IT')
assert(
  (algorithmNamed('RSA-2048')?.findingIds ?? []).join() === 'f1',
  'and only that finding is attached — not every finding on its asset',
)
assert(byId.get('asset:a1')?.severity === 'critical', 'an asset inherits the WORST severity of its own findings')

const remediation = nodesOf('remediation')
const hybrid = remediation.find((node) => node.facts.some((fact) => fact.value.includes('ML-KEM-768 hybrid')))
assert(hybrid !== undefined, 'identical recorded actions collapse into one remediation node')
assert(
  hybrid?.findingIds.slice().sort().join() === 'f1,f3',
  'a remediation closes exactly the findings that recorded it',
  hybrid?.findingIds.join(),
)
assert(hybrid?.severity === 'critical', 'and carries the worst severity among THOSE findings')
assert(
  !remediation.some((node) => /no action required|create a pqc remediation plan/i.test(node.facts.map((f) => f.value).join(' '))),
  '"No action required" and placeholder text are never drawn as actions',
)
assert(graph.estate.nonActionRecommendations === 2, 'and they are counted, so the gap is explained', `${graph.estate.nonActionRecommendations}`)
assert(remediation.every((node) => node.detection === 'inferred'), 'grouping actions is a conclusion, so remediation nodes are inferred')

/* ------------------------------------------------------------------ */
section('6. One derivation of "what to do next"')
const grouped = groupRecommendedActions(input.findings)
assert(
  grouped.actions.length === remediation.length,
  'the Remediation lens and the AI Recommendations panel read the SAME grouping',
  `${grouped.actions.length} vs ${remediation.length}`,
)
assert(grouped.actions[0]?.severity === 'critical', 'actions are ranked worst-first')
const dash = code('src/api-server/dashboard.ts')
assert(dash.includes('groupRecommendedActions(canonical.findings)'), '/recommendations derives its finding actions from that grouping')

/* ------------------------------------------------------------------ */
section('7. Quantum verdicts come from the Crypto Knowledge Base')
const verdicts: Array<[string, string]> = [
  ['RSA-2048', 'vulnerable'],
  ['ECDHE-P256', 'vulnerable'],
  ['SHA256withRSA', 'vulnerable'],
  ['AES-256-GCM', 'resistant'],
  ['TLS_AES_256_GCM_SHA384', 'resistant'],
  ['ML-KEM', 'pqc'],
  ['Hybrid ML-KEM', 'hybrid'],
  ['X25519MLKEM768', 'hybrid'],
  ['TLSv1.3', 'not-applicable'],
  ['Some Vendor Cipher', 'unknown'],
]
for (const [label, expected] of verdicts) {
  assert(quantumVerdictFor(label) === expected, `${label} → ${expected}`, `got ${quantumVerdictFor(label)}`)
}
assert(!/function quantumOfAlgorithm/.test(moduleCode), 'the private regex classifier is gone')
assert(
  !nodesOf('algorithm').some((node) => node.quantumStatus === 'resistant' && /RSA|ECDH|ECDSA|DSA/i.test(node.label)),
  'no classical public-key algorithm is ever classified resistant',
)
const suite = byId.get('component:c5')
assert(
  suite?.quantumStatus === 'vulnerable' && suite.facts.some((fact) => fact.label === 'Knowledge-base verdict'),
  'where the recorded verdict and the knowledge base disagree, BOTH are shown',
)

/* ------------------------------------------------------------------ */
section('8. Algorithms: primitives only, one node per primitive')
const algorithmLabels = nodesOf('algorithm').map((node) => node.label)
assert(!algorithmLabels.some((label) => /detected|missing|weak|exposure/i.test(label)), 'no algorithm node is a scanner finding title', algorithmLabels.join(', '))
assert(graph.estate.rejectedAlgorithmLabels > 0, 'rejected titles are COUNTED, so a lower algorithm total reads as a rejection')
assert(
  nodesOf('algorithm').filter((node) => /^ECDSA P-256/i.test(node.label)).length === 1,
  '"ECDSA P-256" and "ECDSA P-256 (Certificate)" are ONE node — the qualifier is the writer\'s, not the primitive\'s',
)

/* ------------------------------------------------------------------ */
section('9. Topology is observed, never inferred')
const connects = graph.edges.filter((edge) => edge.kind === 'connects')
assert(connects.length === 1, 'only the relationship row that names two REAL assets is drawn', `${connects.length} edges`)
assert(!graph.edges.some((edge) => edge.target.includes('ghost')), 'a relationship to an asset outside the estate is dropped')
const assessed = graph.edges.filter((edge) => edge.kind === 'assessed')
assert(
  assessed.length === 2 && assessed.every((edge) => edge.detection === 'observed'),
  'a session links to exactly the assets its recorded results name — observed',
)
assert(!assessed.some((edge) => edge.target === 'asset:a3'), 'and never to an asset it did not assess')
const noLinks = buildEstateWorkflowGraph({ ...fixture(), scanLinks: [] })
assert(
  noLinks.edges.filter((edge) => edge.kind === 'assessed').every((edge) => edge.detection === 'inferred'),
  'when the store records no link, the fallback root edge is marked INFERRED',
)
const nodeIds = new Set(graph.nodes.map((node) => node.id))
assert(graph.edges.every((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target)), 'no edge references a node that is not in the graph')
assert(
  byId.get('scan:s1')?.facts.some((fact) => fact.label === 'Observations recorded' && fact.value === '120'),
  'the session count is labelled as observations — it is not the open-finding total',
)

/* ------------------------------------------------------------------ */
section('10. Measured facts drive certificate severity')
assert(byId.get('certificate:k1')?.severity === 'critical', 'an expired certificate is critical')
assert(byId.get('certificate:k2')?.severity === 'high', 'a certificate inside 30 days is high')
assert(
  byId.get('certificate:k1')?.facts.some((fact) => fact.label === 'Validity' && fact.value.includes('Expired')),
  'and the inspector states how long ago it expired',
)
const loader = dash.slice(dash.indexOf('async function loadEstateRows'), dash.indexOf('async function loadCanonicalEstate'))
assert(
  loader.includes("'certificates'") && !loader.includes('common_name'),
  'the estate certificate query names only columns that exist (common_name made it fail silently)',
)

/* ------------------------------------------------------------------ */
section('11. Every grouping offered is one the graph populates')
assert(ESTATE_LENSES.every((lens) => ESTATE_GROUPINGS.includes(lens.groupBy)), 'every lens opens on a grouping the estate offers')
for (const grouping of ESTATE_GROUPINGS.filter((g) => g !== 'none')) {
  assert(graph.clusters.some((cluster) => cluster.grouping === grouping), `"${grouping}" grouping has clusters to draw`)
}
assert(
  graph.nodes.every((node) => node.groups.severity && node.groups.kind),
  'every node belongs to a severity group and a type group — Risk and Type never draw an empty canvas',
)
assert(
  graph.clusters.some((cluster) => cluster.grouping === 'severity' && cluster.label === 'No finding attached' && cluster.severity === null),
  'nodes with no finding are grouped under "No finding attached", never under a passing band',
)

/* ------------------------------------------------------------------ */
section('12. The inspector opens the real finding sheet')
assert(graph.findingCorpus.length === nodesOf('finding').length, 'every drawn finding has a finding-sheet record')
assert(
  nodesOf('finding').every((node) => graph.findingCorpus.some((f) => f.id === node.findingIds[0] && f.severity === node.severity)),
  'with the same id and severity as its node',
)
assert(
  (byId.get('asset:a1')?.findingIds ?? []).every((id) => graph.findingCorpus.some((f) => f.id === id)),
  'an asset\'s attached findings resolve in the corpus, so "Attached findings" lists them',
)

/* ------------------------------------------------------------------ */
section('13. Bounded, and honest about it')
assert(graph.truncation.truncated === false, 'a small estate reports no truncation')
const big = fixture()
big.findings = Array.from({ length: 400 }, (_, index) =>
  finding({ id: `b${index}`, assetId: 'a1', title: `Finding ${index}`, threatLevel: index === 399 ? 'CRITICAL' : 'LOW' }),
)
const bounded = buildEstateWorkflowGraph(big)
assert(bounded.truncation.truncated, 'a large estate reports that it was capped')
assert(bounded.nodes.some((node) => node.label === 'Finding 399'), 'the cap keeps the CRITICAL finding')
assert(
  bounded.reconciliation.findingsInAssessment > bounded.reconciliation.findingsProjected,
  'and the reconciliation line shows the gap rather than hiding it',
)

/* ------------------------------------------------------------------ */
section('14. The page and the route are wired to the canonical sets')
const page = code('src/app/dashboard/page.tsx')
assert(!page.includes('QuantumExposureMap') && !page.includes('NodeInspector'), 'the old Exposure Graph + Node Inspector are gone from /dashboard')
assert(page.includes('ExposureWorkflowGraph') && page.includes('ESTATE_LENSES') && page.includes('ESTATE_GROUPINGS'), 'the workflow renders with the estate lenses and groupings')
assert(page.includes('findingCorpus'), 'the page hands the inspector the finding corpus')
assert(page.includes('workflowFailed'), 'a failed build is distinguished from an empty estate')
assert(page.includes('focusKind="asset"'), '/dashboard focuses on assets')

function bodyAfter(marker: string): string | null {
  const start = dash.indexOf(marker)
  if (start < 0) return null
  const rest = dash.slice(start)
  const ends = [rest.indexOf('\n}\n'), rest.indexOf('\n})\n')].filter((index) => index > 0)
  return ends.length === 0 ? rest : rest.slice(0, Math.min(...ends))
}
const route = bodyAfter("router.get('/estate-workflow'")
assert(route !== null && route.includes('loadEstateRows(') && route.includes('loadCanonicalEstate('), '/estate-workflow reads the shared loader AND the canonical sets')
assert(route !== null && !route.includes('safeRows('), 'and issues no query of its own')
assert(
  route !== null && !/vulnerabilities:\s*rows\.vulnerabilities|inventory:\s*rows\.inventory/.test(route),
  'the raw vulnerability and inventory registers are never handed to the projection',
)
assert(
  (dash.match(/async function loadEstateRows/g) || []).length === 1 && (dash.match(/await loadEstateRows\(/g) || []).length >= 2,
  'there is exactly one estate loader and both estate projections call it',
)

/* ------------------------------------------------------------------ */
section('15. A degraded read is disclosed, never silent')
assert(graph.estate.persistence === 'database', 'a database-backed build reports the database as its source')
assert(buildEstateWorkflowGraph({ ...fixture(), persistence: 'memory' }).estate.persistence === 'memory', 'a memory-backed build reports it')
assert(page.includes("persistence === 'memory'") && page.includes('local scan cache'), 'and /dashboard renders that disclosure')

/* ------------------------------------------------------------------ */
section('16. Page-wide accuracy invariants')
const qr = code('src/api-server/quantum-readiness.ts')
assert(!/quantumVulnerableAssets\s*=\s*vulnerable/.test(qr), 'no component count is ever assigned into the ASSET fields')
assert(qr.includes('readScannerMemoryRows'), 'the canonical snapshot reads the same degraded store the intel view reads')
const exec = code('src/api-server/dashboard-executive.ts')
assert(exec.includes('criticalHeadline') && exec.includes('Quantum-Vulnerable Components'), 'the executive headline is UNIT-AWARE')
assert(dash.includes('buildSnapshot(token, user.id)') && /recommendations\.length === 0/.test(dash), 'an empty recommendations list falls back to the canonical actions')
const recsPanel = code('src/app/dashboard/_components/executive/AiRecommendations.tsx')
assert(!recsPanel.includes('posture is stable') && !recsPanel.includes('text-emerald-400/50'), 'the recommendations empty state makes no claim about posture')
const timeline = readFileSync('src/app/dashboard/_components/executive/ThreatTimeline.tsx', 'utf8')
assert(
  timeline.includes('No security events recorded') && timeline.includes('not an assessment of your posture'),
  'an empty event stream is distinguished from an empty filter, and neither is phrased as a verdict',
)
const rollup = code('src/lib/shared-responsibility/rollup.ts')
assert(
  /const open = findings\.filter\(\(f\) => f\.severity !== 'safe'\)/.test(rollup) && /const actionable = open\.filter/.test(rollup),
  'Shared Responsibility "Actionable Now" counts OPEN findings — a PQC-ready confirmation is not work',
)

/* ------------------------------------------------------------------ */
section('17. A current protocol is never "Legacy/deprecated"')
for (const [label, deprecated] of [['TLSv1.3', false], ['TLSv1.2', false], ['TLS 1.3', false], ['TLSv1', true], ['TLSv1.0', true], ['TLSv1.1', true], ['SSLv3', true], ['OpenSSL 3.0', false]] as const) {
  assert(DEPRECATED_PROTOCOL_RE.test(label.toLowerCase()) === deprecated, `${label} ${deprecated ? 'is' : 'is not'} a deprecated protocol`)
}
assert(statusFromThreat('LOW', 'TLSv1.3') !== 'Legacy/deprecated', 'the scanner no longer files TLSv1.3 as Legacy/deprecated')

/* ------------------------------------------------------------------ */
section('18. Asset focus — a view, never a recount')
const scopeA1 = focusScope(graph, new Set(['asset:a1']), 'asset')
assert(scopeA1.has('asset:a1') && !scopeA1.has('asset:a2'), 'focus keeps its asset and stops at the other')
assert(scopeA1.has('finding:f1') && !scopeA1.has('finding:f3'), 'its findings are in scope; the other asset\'s are not')
assert(scopeA1.has('component:c1') && scopeA1.has('certificate:k1') && scopeA1.has('scan:s1'), 'its components, certificates and session are in scope')
const scopeA2 = focusScope(graph, new Set(['asset:a2']), 'asset')
const shared = byId.get('remediation:1')
assert(shared !== undefined && scopeA1.has(shared.id) && scopeA2.has(shared.id), 'an action shared by both assets appears under each')
assert(!scopeA2.has('asset:a1'), 'but sharing it never drags the other asset back into scope')
assert(focusScope(graph, new Set<string>(), 'asset').size === 0, 'an empty focus scopes nothing')
const lensDef = ESTATE_LENSES[0]
const args = { lens: lensDef, hiddenKinds: new Set<never>(), showInferred: true, grouping: lensDef.groupBy, query: '', hiddenSeverities: new Set<never>() }
const unfocused = projectLens(graph, args)
const focused = projectLens(graph, { ...args, focusIds: new Set(['asset:a1']), focusKind: 'asset' })
assert(focused.nodes.length < unfocused.nodes.length && !focused.nodes.some((n) => n.id === 'asset:a2'), 'a focused projection is a strict subset')
assert(
  focused.edges.every((edge) => focused.nodes.some((n) => n.id === edge.source) && focused.nodes.some((n) => n.id === edge.target)),
  'no edge in a focused projection dangles',
)
assert(unfocused.clusters.length > 0, 'the default lens grouping draws clusters')
const renderer = readFileSync('src/components/exposure/ExposureWorkflowGraph.tsx', 'utf8')
assert(renderer.includes('FocusPanel') && renderer.includes('still describe the whole estate'), 'the renderer discloses an active focus')
assert(renderer.includes('groupings.includes(lens.groupBy)'), 'a lens grouping the view does not offer falls back to none, never to a dead button')

/* ------------------------------------------------------------------ */
section('19. Lens integrity')
assert(ESTATE_LENSES.length >= 6, 'the estate ships a full lens set')
assert(ESTATE_LENSES.flatMap((lens) => lens.kinds).every((kind) => kind in graph.counts), 'every kind a lens admits exists in the vocabulary')
assert(ESTATE_LENSES.every((lens) => lens.description.length > 40), 'each lens explains what it shows')
assert(new Set(ESTATE_LENSES.map((lens) => lens.id)).size === ESTATE_LENSES.length, 'lens ids are unique')
assert(WORKFLOW_LENSES.length === 8, 'the assessment lens set is untouched — Local and Dev render exactly as before')

console.log(`\n${checks - failures}/${checks} checks passed`)
if (failures > 0) {
  console.log(`${failures} FAILED`)
  process.exit(1)
}
