/**
 * Sophia — AI Security Copilot™: ground-truth answer-accuracy regression suite.
 *
 * Where `tools/copilot-check.ts` proves the copilot's SECURITY properties
 * (tenant scoping, RBAC, injection, rate limits), this suite proves its ANSWER
 * properties: that what Sophia says matches what the tenant's data actually
 * contains.
 *
 *     npx tsx tools/sophia-check.ts
 *
 * The fixture is the reported production tenant, reproduced exactly:
 *   4 assets · 178 cryptographic components · 160 quantum-vulnerable
 *
 * Every assertion below guards a defect that was actually shipped. The headline
 * one: asking
 *
 *     "Which internet-facing systems still use RSA and who owns them?"
 *
 * answered "No assets match that filter." The question was parsed into an asset
 * NAME filter of "system still use" — generic verbs survived the stopword list,
 * the token list was truncated by sentence position so "RSA" (the only
 * discriminating term) was dropped, and the surviving garbage was matched with
 * ILIKE against assets.name. An algorithm is not an asset name, so that search
 * could only ever return zero.
 */
import {
  extractQueryFilter,
  extractAssetFilter,
  detectAlgorithmFamilies,
  detectEntityKind,
} from '../src/api-server/copilot-knowledge'
import { TOOL_REGISTRY, runTool, type CopilotBuilders, type ToolContext } from '../src/api-server/copilot-tools'

/** runTool returns { run, result }; every assertion here is about the result. */
async function callTool(name: string, c: ToolContext, args: Record<string, unknown>, b: CopilotBuilders) {
  const out = await runTool(name, c, args, b)
  return (out as unknown as { result: { status: string; data: Record<string, unknown>; note?: string } }).result
}
import { planQuery, runCopilotQuery } from '../src/api-server/copilot-engine'
import { EMPTY_MEMORY } from '../src/types/copilot'
import type { ExposureIntelligence } from '../src/types/exposure-graph'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

const USER_ID = 'tenant-user-42'
const NOW = new Date().toISOString()

/* ------------------------------------------------------------------ */
/* GROUND TRUTH — the reported tenant, to the record                   */
/* ------------------------------------------------------------------ */

const GT_ASSETS = [
  { id: 'a-web', name: 'checkout-web', type: 'web', environment: 'public', service_owner: 'Payments Platform', criticality: 'critical', status: 'active', metadata: { internet_facing: true } },
  { id: 'a-api', name: 'partner-api', type: 'api', environment: 'public', service_owner: '', criticality: 'high', status: 'active', metadata: { internet_facing: true } },
  { id: 'a-db', name: 'orders-db', type: 'database', environment: 'internal', service_owner: 'Data Engineering', criticality: 'high', status: 'active', metadata: {} },
  { id: 'a-bat', name: 'nightly-batch', type: 'job', environment: 'internal', service_owner: 'Data Engineering', criticality: 'medium', status: 'active', metadata: {} },
]

/**
 * 178 components, 160 quantum-vulnerable — the exact reported totals.
 * RSA lives on three assets; two of those are internet-facing. ECDSA lives on
 * one internal asset. ML-KEM components exist so a PQC question has a positive
 * answer to find. Twelve components are deliberately orphaned (no asset_id) to
 * prove they are reported as unattributed rather than silently dropped.
 */
function buildInventory(): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = []
  const push = (assetId: string, algorithm: string, itemType: string, vulnerable: boolean, n: number) => {
    for (let i = 0; i < n; i += 1) {
      rows.push({
        id: `ci-${rows.length}`, user_id: USER_ID, asset_id: assetId,
        name: `${itemType}: ${algorithm}`, item_type: itemType, algorithm,
        key_size: algorithm.includes('2048') ? 2048 : 256, protocol: 'TLS 1.2',
        exposure_level: vulnerable ? 'high' : 'low',
        is_vulnerable: vulnerable, is_quantum_safe: !vulnerable,
        created_at: NOW, updated_at: NOW,
      })
    }
  }
  push('a-web', 'RSA-2048', 'Cipher Suite', true, 40)
  push('a-api', 'RSA-2048', 'Key Exchange', true, 30)
  push('a-db', 'RSA-4096', 'Certificate Signature', true, 20)
  push('a-db', 'ECDSA-P256', 'Signature', true, 28)
  push('a-bat', '3DES', 'Symmetric Encryption', true, 30)
  push('', 'RSA-2048', 'Cipher Suite', true, 12)        // orphaned — no asset link
  push('a-web', 'ML-KEM-768', 'Key Exchange', false, 10)
  push('a-api', 'AES-256-GCM', 'Symmetric Encryption', false, 8)
  return rows
}
const GT_INVENTORY = buildInventory()
const GT_TOTAL_COMPONENTS = GT_INVENTORY.length            // 178
const GT_VULNERABLE = GT_INVENTORY.filter((r) => r.is_vulnerable === true).length // 160

const GT_CERTS = [
  { id: 'c-1', user_id: USER_ID, asset_id: 'a-web', name: 'checkout-web TLS', algorithm: 'RSA-2048', key_size: 2048, issuer: 'Internal CA', not_after: new Date(Date.now() + 86400000 * 200).toISOString(), created_at: NOW, updated_at: NOW },
  { id: 'c-2', user_id: USER_ID, asset_id: 'a-db', name: 'orders-db TLS', algorithm: 'ECDSA-P256', key_size: 256, issuer: 'Internal CA', not_after: new Date(Date.now() + 86400000 * 90).toISOString(), created_at: NOW, updated_at: NOW },
]

console.log(`\nGROUND TRUTH — ${GT_ASSETS.length} assets · ${GT_TOTAL_COMPONENTS} components · ${GT_VULNERABLE} quantum-vulnerable`)

/* ------------------------------------------------------------------ */
/* Mock client serving exactly that ground truth                       */
/* ------------------------------------------------------------------ */

function rowsFor(table: string): Record<string, unknown>[] {
  switch (table) {
    case 'assets': return GT_ASSETS.map((a) => ({ ...a, user_id: USER_ID, created_at: NOW, updated_at: NOW }))
    case 'crypto_inventory': return GT_INVENTORY
    case 'certificates': return GT_CERTS
    default: return []
  }
}

function makeClient(recorder: Array<{ table: string; eqs: Array<[string, unknown]> }> = [], asOf?: string) {
  const stamp = (rows: Record<string, unknown>[]) =>
    asOf ? rows.map((row) => ({ ...row, created_at: asOf, updated_at: asOf })) : rows
  const makeQuery = (table: string) => {
    const state = { table, eqs: [] as Array<[string, unknown]>, head: false }
    /* Counts must honour the .eq() filters, or a head-count of
       crypto_inventory filtered to is_vulnerable=true would return the whole
       table and the fixture could never catch a wrong vulnerable count. */
    const applyEqs = (rows: Record<string, unknown>[]) =>
      stamp(rows.filter((row) => state.eqs.every(([col, val]) => col === 'user_id' || row[col] === val)))
    const settle = () => {
      recorder.push(state)
      return Promise.resolve(state.head
        ? { count: applyEqs(rowsFor(table)).length, error: null, data: null }
        : { data: applyEqs(rowsFor(table)), error: null })
    }
    const q: Record<string, unknown> = {}
    const chain = () => q
    q.select = (_c: unknown, opts?: { head?: boolean }) => { if (opts?.head) state.head = true; return q }
    q.eq = (col: string, val: unknown) => { state.eqs.push([col, val]); return q }
    q.or = chain; q.in = chain; q.is = chain; q.neq = chain; q.order = chain; q.gte = chain; q.lte = chain
    q.limit = () => settle()
    q.maybeSingle = () => { recorder.push(state); return Promise.resolve({ data: stamp(rowsFor(table))[0] || null, error: null }) }
    q.single = () => { recorder.push(state); return Promise.resolve({ data: stamp(rowsFor(table))[0] || null, error: null }) }
    q.then = (res: (v: unknown) => unknown, rej?: (e: unknown) => unknown) => settle().then(res, rej)
    return q
  }
  return { from: (table: string) => makeQuery(table) }
}

const mockExposure = {
  generatedAt: NOW, lastAssessmentAt: NOW, hasData: true,
  summary: { totalAssets: 4, quantumVulnerable: 4, hybridAssets: 0, pqcReadyAssets: 0, migrationInProgress: 0, unknownPosture: 0, thirdPartyDependencies: 0, trustRelationships: 2, criticalTrustRelationships: 1, internetFacingAssets: 2, highRiskAssets: 3, legacyCryptoAssets: 4, certificateChains: 2, pkiObjects: 2, maxBlastRadius: 2, migrationReadinessScore: 20, quantumReadinessScore: 22, quantumRiskScore: 90 },
  graph: { nodes: [], edges: [] }, thirdParty: [],
  migrationOrder: { waves: [], clusters: [], blockers: [] },
  advisor: { recommendations: [], estimates: {} as never },
  riskPrioritization: [], evidence: { sources: ['assets'], note: 'ground truth' },
} as unknown as ExposureIntelligence

const builders: CopilotBuilders = {
  snapshot: async () => ({
    hasData: true, lastAssessmentAt: NOW,
    scores: { quantumReadiness: 22, quantumReadinessLevel: 'critical', quantumRisk: 90, quantumRiskLevel: 'critical', hndlRisk: 85, hndlRiskLevel: 'critical', cryptoExposure: 88, pqcAdoption: 10 },
    inventory: { assetsAssessed: 4, certificatesAnalyzed: 2, keysDiscovered: 0, trustRelationships: 2, cryptoComponents: GT_TOTAL_COMPONENTS, vulnerableComponents: GT_VULNERABLE, pqcReadyComponents: 18, quantumVulnerableAssets: 4 },
    riskDistribution: { critical: 18, high: 49, medium: 36, low: 19 },
    riskTrend: [], topRiskAssets: [{ asset: 'checkout-web', assetType: 'web', environment: 'public', owner: 'Payments Platform', riskScore: 92, status: 'Quantum-Vulnerable' }],
    riskFactors: [], criticalFindings: [], recommendedActions: [],
    estimates: { migrationTimelineWeeks: 16, migrationCostUsd: 180000, parallelWorkstreams: 2 },
  }),
  scannerIntel: async () => ({ summary: { totalComponents: GT_TOTAL_COMPONENTS, vulnerableComponents: GT_VULNERABLE, pqcReadyComponents: 18, totalAssets: 4, vulnerableAssets: 4 }, severityCounts: { critical: 18, high: 49, medium: 36, low: 19, safe: 18 }, findings: [] }),
  exposure: async () => mockExposure,
  remediationPlan: async () => ({ certificationReadinessPct: 18, actions: [], queues: { critical: 0, high: 0, medium: 0, low: 0 }, quickWins: [], criticalBlockers: [] }),
  certification: async () => ({ certificate: null, certificates: [], schemaReady: true, renewal: {}, eligibility: { eligible: false, summary: 'Not eligible', criteria: [] } }),
  hndl: async () => ({ summary: {}, assets: [] }),
  workflow: async () => ({ stages: [], currentStage: null }),
  snapshots: async () => ({ snapshots: [], summary: {} }),
} as unknown as CopilotBuilders

const ctx: ToolContext = { token: 't', userId: USER_ID, email: 'u@example.com', role: 'owner', tier: 'elite', client: makeClient() }

/* ================================================================== */
async function main() {
  /* ---------------------------------------------------------------- */
  console.log('\n[1] The reported question no longer becomes a nonsense name filter')
  const Q = 'Which internet-facing systems still use RSA and who owns them?'
  const f = extractQueryFilter(Q)
  assert(f.query === '', 'no asset-NAME filter is produced from a question about an algorithm', `query=${JSON.stringify(f.query)}`)
  assert(!/system|still|use/.test(f.query), 'generic verbs and nouns never survive as a filter')
  assert(f.algorithms.includes('rsa'), 'RSA is recognised as an ALGORITHM entity', `[${f.algorithms}]`)
  assert(f.internetFacing === true, 'the internet-facing scope is captured')
  assert(f.wantsOwner === true, '"who owns them" is recognised as an ownership question')
  assert(f.entity === 'asset', 'the answer unit is the ASSET', f.entity)

  console.log('\n[2] Algorithm vocabulary resolves to canonical families')
  assert(detectAlgorithmFamilies('Where am I using RSA?').includes('rsa'), 'RSA')
  assert(detectAlgorithmFamilies('Which systems use SHA-1?').includes('sha1'), 'SHA-1 (not matched as SHA-2)')
  const ecc = detectAlgorithmFamilies('How much ECC do I have?')
  assert(ecc.includes('ecdsa') && ecc.includes('ecdh'), 'ECC expands to BOTH signature and key-agreement families', `[${ecc}]`)
  const dsaOnly = detectAlgorithmFamilies('Which assets use ECDSA?')
  assert(dsaOnly.includes('ecdsa') && !dsaOnly.includes('dsa'), 'ECDSA is not mis-parsed as classical DSA', `[${dsaOnly}]`)
  const mldsa = detectAlgorithmFamilies('Do I use ML-DSA anywhere?')
  assert(mldsa.includes('ml-dsa') && !mldsa.includes('dsa'), 'ML-DSA is not mis-parsed as classical DSA', `[${mldsa}]`)
  assert(detectAlgorithmFamilies('Which systems use 3DES?').includes('3des'), '3DES is not mis-parsed as DES')
  assert(detectAlgorithmFamilies('what is my quantum readiness?').length === 0, 'a non-algorithm question names no algorithm')

  console.log('\n[3] Real identifiers survive; ranking is by selectivity, not word order')
  assert(extractAssetFilter('Show me web-01') === 'web-01', 'a concrete asset name survives')
  const multi = extractQueryFilter('Which internet-facing hosts still use RSA on api.prod.example.com?')
  assert(multi.query.includes('api.prod.example.com'), 'an FQDN outranks generic words', `query=${JSON.stringify(multi.query)}`)
  assert(multi.algorithms.includes('rsa'), 'the algorithm is still lifted out alongside it')

  console.log('\n[4] Entity kinds are distinguished (assets ≠ components ≠ certificates)')
  assert(detectEntityKind('which certificates use RSA?') === 'certificate', 'certificate question')
  assert(detectEntityKind('how many CBOM components do I have?') === 'component', 'component question')
  assert(detectEntityKind('which systems are affected?') === 'asset', 'asset question')
  assert(detectEntityKind('what findings are open?') === 'finding', 'finding question')

  console.log('\n[5] The planner routes an algorithm question to the CBOM join')
  const plan = planQuery(Q, { ...EMPTY_MEMORY })
  assert(plan.tools.includes('findAssetsUsingAlgorithm'), 'findAssetsUsingAlgorithm is planned')
  assert(Array.isArray(plan.args.algorithms) && (plan.args.algorithms as string[]).includes('rsa'), 'the algorithm family reaches the tool args')
  assert(plan.args.internetFacing === true, 'the internet-facing scope reaches the tool args')
  assert(plan.args.query === '', 'no name filter is forwarded')

  console.log('\n[6] findAssetsUsingAlgorithm resolves algorithm → asset → owner')
  assert(Boolean(TOOL_REGISTRY.findAssetsUsingAlgorithm), 'the tool is registered')
  const rsaAll = await callTool('findAssetsUsingAlgorithm', ctx, { algorithms: ['rsa'] }, builders)
  assert(rsaAll.status === 'ok', 'tool runs')
  // 40 (web) + 30 (api) + 20 (db RSA-4096) + 12 orphaned = 102 components; 1 cert.
  assert(rsaAll.data.components === 102, 'every RSA component is found, including RSA-4096', `${rsaAll.data.components}`)
  assert(rsaAll.data.certificates === 1, 'RSA certificates are found too', `${rsaAll.data.certificates}`)
  assert(rsaAll.data.unattributed === 12, 'orphaned components are reported, not silently dropped', `${rsaAll.data.unattributed}`)
  assert(rsaAll.data.matchedAssets === 3, 'RSA resolves to the 3 assets that actually carry it', `${rsaAll.data.matchedAssets}`)
  const names = (rsaAll.data.assets as Array<{ name: string; owner: string | null }>).map((a) => a.name)
  assert(names.includes('checkout-web') && names.includes('partner-api') && names.includes('orders-db'), 'the right assets are named', names.join(', '))
  assert(!names.includes('nightly-batch'), 'an asset with no RSA is NOT included (it carries 3DES)')

  console.log('\n[7] The internet-facing scope is applied to the joined result')
  const rsaEdge = await callTool('findAssetsUsingAlgorithm', ctx, { algorithms: ['rsa'], internetFacing: true }, builders)
  assert(rsaEdge.data.matchedAssets === 2, 'only the 2 internet-facing RSA assets remain', `${rsaEdge.data.matchedAssets}`)
  assert(rsaEdge.data.assetsBeforeScope === 3, 'the pre-scope total is preserved so the answer can state both')
  const edgeRows = rsaEdge.data.assets as Array<{ name: string; owner: string | null; internetFacing: boolean }>
  assert(edgeRows.every((r) => r.internetFacing), 'every returned asset really is internet-facing')
  assert(edgeRows.find((r) => r.name === 'checkout-web')?.owner === 'Payments Platform', 'the real owner is reported')
  assert(rsaEdge.data.ownersUnknown === 1, 'the asset with no service_owner is counted as unowned, not invented', `${rsaEdge.data.ownersUnknown}`)

  console.log('\n[8] Family matching never confuses related algorithm names')
  const ecdsa = await callTool('findAssetsUsingAlgorithm', ctx, { algorithms: ['ecdsa'] }, builders)
  assert(ecdsa.data.components === 28, 'ECDSA finds only ECDSA components', `${ecdsa.data.components}`)
  const dsa = await callTool('findAssetsUsingAlgorithm', ctx, { algorithms: ['dsa'] }, builders)
  assert(dsa.data.components === 0, 'classical DSA does NOT match ECDSA rows', `${dsa.data.components}`)
  const mlkem = await callTool('findAssetsUsingAlgorithm', ctx, { algorithms: ['ml-kem'] }, builders)
  assert(mlkem.data.components === 10, 'ML-KEM components are found', `${mlkem.data.components}`)
  const des = await callTool('findAssetsUsingAlgorithm', ctx, { algorithms: ['des'] }, builders)
  assert(des.data.components === 0, 'DES does NOT match 3DES rows', `${des.data.components}`)

  console.log('\n[9] An algorithm with no records says so — it never claims absence as safety')
  const md5 = await callTool('findAssetsUsingAlgorithm', ctx, { algorithms: ['md5'] }, builders)
  assert(md5.data.components === 0 && md5.status !== 'error', 'MD5 returns zero cleanly')
  assert(typeof md5.note === 'string' && /no md5/i.test(md5.note), 'the note names what was searched', md5.note || '')

  console.log('\n[10] End-to-end: the reported question now gets a real answer')
  const outcome = await runCopilotQuery(ctx, Q, { ...EMPTY_MEMORY }, () => {}, builders)
  const answerText = (a: typeof outcome.answer) => [
    a.summary,
    ...(a.keyFindings || []),
    ...(a.reasoning || []),
    ...(a.evidence || []).map((e) => `${e.label} ${e.value} ${e.detail || ''}`),
    ...(a.recommendations || []).map((r) => `${r.title} ${r.detail}`),
  ].join(' ')
  const text = answerText(outcome.answer)
  assert(!/no assets match that filter/i.test(text), 'the dead-end answer is gone', text.slice(0, 90))
  assert(/RSA/i.test(text), 'the answer talks about RSA')
  assert(/checkout-web/.test(text), 'the answer NAMES the affected asset')
  assert(/Payments Platform/.test(text), 'the answer NAMES the owner — this is what "who owns them" asked')
  assert(/partner-api/.test(text), 'the second internet-facing RSA asset is named too')
  assert(!/nightly-batch/.test(text), 'an unaffected internal asset is not listed as an RSA user')
  assert(/no owner recorded|no service owner/i.test(text), 'the unowned asset is flagged as unowned rather than given a made-up owner')

  console.log('\n[11] Entity units are never conflated (4 assets ≠ 178 components)')
  const counts = await runCopilotQuery(ctx, 'How many assets and crypto components do I have?', { ...EMPTY_MEMORY }, () => {}, builders)
  const ctext = answerText(counts.answer)
  assert(/\b4\b/.test(ctext), `the real asset count (4) is reported`)
  assert(new RegExp(`\\b${GT_TOTAL_COMPONENTS}\\b`).test(ctext), `the real component count (${GT_TOTAL_COMPONENTS}) is reported`)
  assert(new RegExp(`\\b${GT_VULNERABLE}\\b`).test(ctext), `the real vulnerable count (${GT_VULNERABLE}) is reported`)
  assert(/across|not \d+ separate/i.test(ctext), 'the answer explains components are ACROSS assets, not separate systems')

  console.log('\n[12] Data freshness is stated, and staleness is called out')
  const freshText = answerText(outcome.answer)
  assert(/data freshness/i.test(freshText), 'every answer states how fresh its evidence is')
  assert(/generated (less than an hour|\d+ (hour|day))/i.test(freshText), 'the age is expressed in human terms', (freshText.match(/Data freshness:[^.]*\./i) || [''])[0])
  assert(!/may no longer describe current production/i.test(freshText), 'fresh data is NOT flagged stale')

  /* Staleness is a property of the DATA, so age the records themselves rather
     than the snapshot header — that is what a tenant who has not scanned in
     three weeks actually looks like. */
  const staleCtx: ToolContext = { ...ctx, client: makeClient([], new Date(Date.now() - 86400000 * 21).toISOString()) }
  const staleOutcome = await runCopilotQuery(staleCtx, Q, { ...EMPTY_MEMORY }, () => {}, builders)
  const staleText = answerText(staleOutcome.answer)
  assert(/may no longer describe current production/i.test(staleText), 'a 21-day-old assessment IS flagged as stale')
  assert(/21 day\(s\) ago/.test(staleText), 'the real age is reported, not a vague "old"')
  assert(
    (staleOutcome.answer.recommendations || []).some((r) => /re-scan/i.test(r.title)),
    'stale data produces a re-scan recommendation',
  )
  assert(
    staleOutcome.answer.confidence.score <= outcome.answer.confidence.score,
    'stale evidence never scores higher confidence than fresh evidence',
    `${staleOutcome.answer.confidence.score} vs ${outcome.answer.confidence.score}`,
  )

  console.log('\n[13] Tenant isolation holds on the new tool')
  const recorder: Array<{ table: string; eqs: Array<[string, unknown]> }> = []
  const scopedCtx: ToolContext = { ...ctx, client: makeClient(recorder) }
  await callTool('findAssetsUsingAlgorithm', scopedCtx, { algorithms: ['rsa'] }, builders)
  assert(recorder.length > 0, 'the tool queried the database', `${recorder.length} queries`)
  assert(
    recorder.every((q) => q.eqs.some(([col, val]) => col === 'user_id' && val === USER_ID)),
    'EVERY query pins user_id to the authenticated tenant',
    recorder.map((q) => q.table).join(', '),
  )

  console.log(failures === 0 ? '\n✓ ALL SOPHIA ANSWER-ACCURACY CHECKS PASSED\n' : `\n${failures} CHECK(S) FAILED ✗\n`)
  process.exit(failures === 0 ? 0 : 1)
}

void main()
