/**
 * Offline duplicate audit for the Shared Responsibility matrix and the
 * Quantum Readiness evidence tables.
 *
 * Reproduces the exact duplication observed in a real tenant export
 * (executive-report-2026-07-26-v1.1.pdf, pages 9-10): the scanner records one
 * cryptographic exposure through several detection channels, so the ownership
 * matrix printed byte-identical rows AND two contradictory recommended actions
 * for the same finding.
 *
 * Asserts, without a DB or a server:
 *  - the ownership matrix emits no duplicate rendered rows
 *  - one exposure on one asset consolidates to one row with a true instance count
 *  - the conflicting "migrate" / "ML-KEM hybrid" actions resolve deterministically
 *  - the classified finding TOTALS are untouched (consolidation is presentational)
 *  - collapseCriticalFindings merges detection-channel variants of one asset
 *  - no export table prints a duplicate row
 *
 *   npx tsx tools/report-dedup-check.ts
 */
import { buildSharedResponsibility } from '../src/lib/shared-responsibility'
import type { OwnershipFindingInput } from '../src/lib/shared-responsibility'
import { collapseCriticalFindings } from '../src/api-server/critical-findings'
import { buildReportModel } from '../src/services/reporting/ReportEvidence'
import { exportReport } from '../src/services/reporting/ReportExporter'
import { playbookRows } from '../src/services/reporting/ReportPlaybook'
import { brandingSchema } from '../src/services/reporting/schemas/ReportSchema'

// Inlined snapshot skeleton — importing the value from _shared pulls in the
// Supabase client, which needs Vite env (unavailable under tsx).
const EMPTY_SNAPSHOT = {
  generatedAt: null, lastAssessmentAt: null, assessmentProgress: 0, assessmentStatus: 'not_started', hasData: false,
  scores: { quantumReadiness: 0, quantumReadinessLevel: 'Not Started', quantumRisk: 0, quantumRiskLevel: 'Minimal', hndlRisk: 0, hndlRiskLevel: 'Minimal', cryptoExposure: 0, cryptoExposureLevel: 'Minimal', migrationComplexity: 0, migrationComplexityLevel: 'Minimal', migrationEffort: 0, pqcAdoption: 0 },
  inventory: { assetsAssessed: 0, certificatesAnalyzed: 0, keysDiscovered: 0, trustRelationships: 0, domainsScanned: 0, identitiesAnalyzed: 0, cloudAccounts: 0, dataRepositories: 0, pqcReadyAssets: 0, hybridAssets: 0, quantumVulnerableAssets: 0, cryptoComponents: 0, vulnerableComponents: 0, pqcReadyComponents: 0 },
  riskDistribution: { critical: 0, high: 0, medium: 0, low: 0 },
  readinessFactors: [], riskFactors: [], criticalFindings: [], recommendedActions: [], topRiskAssets: [],
  exposureGraph: { nodes: [], edges: [] }, riskTrend: [], estimates: { migrationTimelineWeeks: 0, migrationCostUsd: 0 },
  telemetry: { runtimeEvents: 0, scanResults: 0, scanSessions: 0, securityEvents: 0, certificates: 0, keys: 0, assets: 0, connectors: 0, latestEventAt: null },
}

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

/* ------------------------------------------------------------------ */
/* Real-shaped fixture: one host, one exposure set, three detection    */
/* channels — exactly what produced the duplicate rows in production.  */
/* ------------------------------------------------------------------ */
const CIPHERS = [
  'TLS_RSA_WITH_AES_256_CBC_SHA',
  'TLS_RSA_WITH_AES_128_CBC_SHA',
  'TLS_RSA_WITH_AES_256_GCM_SHA384',
  'TLS_RSA_WITH_AES_128_GCM_SHA256',
]
const CHANNELS: Array<{ location: string; category: string; evidence: string }> = [
  { location: 'qguardhelix.com', category: 'TLS Cipher Suite', evidence: 'handshake' },
  { location: 'Cipher Suite - https://qguardhelix.com', category: 'Cipher Suite', evidence: 'catalog' },
  { location: 'qguardhelix.com:443', category: 'Transport', evidence: 'port-probe' },
]

const inputs: OwnershipFindingInput[] = []
let n = 0
for (const algorithm of CIPHERS) {
  for (const channel of CHANNELS) {
    inputs.push({
      id: `raw-${n++}`,
      title: `${algorithm} — ${channel.location}`,
      algorithm,
      category: channel.category,
      location: channel.location,
      assetName: channel.location,
      assetType: 'web-application',
      host: 'qguardhelix.com',
      severity: 'CRITICAL',
      metadata: { evidence: channel.evidence },
    })
  }
}
// Non-host detection channel — a different evidence source, must stay separate.
inputs.push({
  id: `raw-${n++}`,
  title: 'No Forward Secrecy — Detection Rule TLS-006',
  algorithm: 'No Forward Secrecy',
  category: 'Detection Rule',
  location: 'Detection Rule TLS-006',
  assetName: 'Detection Rule TLS-006',
  severity: 'CRITICAL',
})
inputs.push({
  id: `raw-${n++}`,
  title: 'No Forward Secrecy — qguardhelix.com',
  algorithm: 'No Forward Secrecy',
  category: 'TLS Cipher Suite',
  location: 'qguardhelix.com',
  assetName: 'qguardhelix.com',
  assetType: 'web-application',
  severity: 'CRITICAL',
})
// A certificate SIGNATURE finding — must be routed to ML-DSA, never ML-KEM.
inputs.push({
  id: `raw-${n++}`,
  title: 'ECDSA P-256 (Certificate) — qguardhelix.com',
  algorithm: 'ECDSA P-256 (Certificate)',
  category: 'Certificate Signature',
  location: 'qguardhelix.com',
  assetName: 'qguardhelix.com',
  assetType: 'web-application',
  severity: 'HIGH',
})
// A second real asset — consolidation must never merge across assets.
inputs.push({
  id: `raw-${n++}`,
  title: 'TLS_RSA_WITH_AES_256_CBC_SHA — api.qguardhelix.com',
  algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  category: 'TLS Cipher Suite',
  location: 'api.qguardhelix.com',
  assetName: 'api.qguardhelix.com',
  assetType: 'api-gateway',
  severity: 'HIGH',
})

console.log(`\n[1] Ownership matrix consolidation (${inputs.length} raw scanner instances)`)
const sr = buildSharedResponsibility(inputs)
const rendered = sr.matrix.map((m) => [m.finding, m.asset, m.owner, m.action, m.priority, m.status].join(' | '))
const seen = new Map<string, number>()
for (const row of rendered) seen.set(row, (seen.get(row) || 0) + 1)
const dupes = [...seen.entries()].filter(([, c]) => c > 1)
assert(dupes.length === 0, 'matrix prints no duplicate rendered rows', `${rendered.length} rows, ${seen.size} unique`)
if (dupes.length) for (const [row, c] of dupes.slice(0, 5)) console.log(`      x${c}  ${row}`)

const cbc = sr.matrix.filter((m) => m.finding === 'TLS_RSA_WITH_AES_256_CBC_SHA')
assert(cbc.length === 2, 'one exposure x two assets = two rows (never merged across assets)', `${cbc.length} rows`)
const root = cbc.find((m) => m.asset === 'qguardhelix.com')
assert(!!root && root.occurrences === 3, 'three detection channels collapse into one row with occurrences=3', `occurrences=${root?.occurrences}`)
assert(
  !!root && root.detectionLabels.length === 3,
  'the merged raw detection labels are retained for traceability',
  root?.detectionLabels.join(', '),
)

const actions = new Set(sr.matrix.filter((m) => m.finding === 'TLS_RSA_WITH_AES_256_CBC_SHA' && m.asset === 'qguardhelix.com').map((m) => m.action))
assert(actions.size === 1, 'the same exposure carries exactly one recommended action', [...actions].join(' || ').slice(0, 80))
assert([...actions][0]?.includes('ML-KEM hybrid') === true, 'conflict resolves to the transport-specific ML-KEM action')

const fsRows = sr.matrix.filter((m) => m.finding === 'No Forward Secrecy')
assert(fsRows.length === 2, 'a non-host detection channel is NOT silently merged into a host', `${fsRows.length} rows`)
assert(
  fsRows.some((m) => m.asset === 'Detection Rule TLS-006'),
  'a non-host evidence label keeps its original casing',
  fsRows.map((m) => m.asset).join(' / '),
)

console.log('\n[1b] Recommended actions name the correct NIST primitive class')
// ML-KEM (FIPS 203) is key establishment and can never replace a signature.
// `isTransportFinding` matches the word "certificate", so signature findings
// used to be handed the ML-KEM key-exchange action.
const signatureRows = sr.matrix.filter((m) => /ecdsa|signature|certificate/i.test(m.finding))
const kexRows = sr.matrix.filter((m) => /^TLS_/i.test(m.finding))
assert(
  signatureRows.every((m) => !/ML-KEM/i.test(m.action)),
  'no signature finding is told to migrate to ML-KEM',
  signatureRows.map((m) => m.finding).join(', ') || 'none in fixture',
)
assert(kexRows.length > 0 && kexRows.every((m) => /ML-KEM/i.test(m.action)), 'cipher-suite findings are routed to ML-KEM (FIPS 203)', `${kexRows.length} row(s)`)

console.log('\n[2] Totals are untouched — consolidation is presentational only')
assert(sr.totals.findings === inputs.length, 'classified finding total equals the raw input count', `${sr.totals.findings} of ${inputs.length}`)
assert(
  sr.domainDistribution.customer + sr.domainDistribution.provider + sr.domainDistribution.ecosystem === inputs.length,
  'ownership distribution still sums to every classified finding',
)
assert(
  sr.matrix.reduce((sum, m) => sum + m.occurrences, 0) === inputs.length,
  'matrix occurrences reconcile exactly with the raw instances',
  `${sr.matrix.reduce((s, m) => s + m.occurrences, 0)} of ${inputs.length}`,
)

console.log('\n[3] Quantum Readiness critical-findings collapse')
const rawFindings = [
  ...CIPHERS.flatMap((algorithm) =>
    CHANNELS.map((c, i) => ({
      id: `cf-${algorithm}-${i}`,
      title: `${algorithm} detected`,
      asset: c.location,
      assetType: 'asset',
      environment: 'unknown',
      severity: 'critical',
      algorithm,
      detectedAt: `2026-07-2${i}T00:00:00.000Z`,
      instances: 1,
    })),
  ),
  {
    id: 'cf-api',
    title: 'TLS_RSA_WITH_AES_256_CBC_SHA detected',
    asset: 'api.qguardhelix.com',
    assetType: 'asset',
    environment: 'production',
    severity: 'high',
    algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA',
    detectedAt: '2026-07-20T00:00:00.000Z',
    instances: 1,
  },
  // Distinct root causes so the report builds several playbooks — the hoisting
  // pass only has repetition to remove when more than one playbook exists.
  ...[
    ['No Forward Secrecy', 'critical'],
    ['ECDSA Certificate Detected', 'high'],
    ['ecdsa-with-SHA256', 'high'],
    ['No Hybrid Crypto', 'critical'],
    ['Wide Crypto Attack Surface', 'high'],
    ['Long-Term Data Risk', 'high'],
  ].map(([algorithm, severity], i) => ({
    id: `cf-extra-${i}`,
    title: `${algorithm} detected`,
    asset: 'qguardhelix.com',
    assetType: 'asset',
    environment: 'unknown',
    severity,
    algorithm,
    detectedAt: '2026-07-21T00:00:00.000Z',
    instances: 1,
  })),
]
const collapsed = collapseCriticalFindings(rawFindings)
assert(collapsed.length === rawFindings.length - 8, 'detection-channel variants collapse per algorithm+asset', `${rawFindings.length} raw -> ${collapsed.length} records`)
const first = collapsed.find((f) => f.algorithm === CIPHERS[0] && f.asset === 'qguardhelix.com')
assert(!!first && first.instances === 3, 'collapsed record reports its true instance count', `instances=${first?.instances}`)
assert(!!first && first.locations.length === 3, 'every raw detection location is retained', first?.locations.join(', '))
assert(first?.detectedAt === '2026-07-20T00:00:00.000Z', 'earliest detection timestamp is preserved', String(first?.detectedAt))
assert(
  collapsed.reduce((sum, f) => sum + f.instances, 0) === rawFindings.length,
  'instance counts reconcile with the raw finding rows',
)
const renderedFindings = collapsed.map((f) => [f.title, f.algorithm, f.asset, f.environment, f.severity].join(' | '))
assert(new Set(renderedFindings).size === renderedFindings.length, 'evidence table prints no duplicate rendered rows')

/* ------------------------------------------------------------------ */
/* End-to-end: build the report model and export every format          */
/* ------------------------------------------------------------------ */
async function reportChecks() {
  console.log('\n[4] Report model — presentation consolidation')
  const branding = brandingSchema.parse({ companyName: 'QGuard Helix' })
  const snapshot = {
    ...EMPTY_SNAPSHOT,
    hasData: true,
    generatedAt: new Date().toISOString(),
    lastAssessmentAt: new Date().toISOString(),
    assessmentStatus: 'complete',
    assessmentProgress: 100,
    scores: { ...EMPTY_SNAPSHOT.scores, quantumReadiness: 26, quantumRisk: 58, hndlRisk: 62, pqcAdoption: 12 },
    inventory: { ...EMPTY_SNAPSHOT.inventory, assetsAssessed: 2, quantumVulnerableAssets: 2, cryptoComponents: 140, vulnerableComponents: 38, pqcReadyComponents: 17 },
    riskDistribution: { critical: 12, high: 4, medium: 6, low: 3 },
    readinessFactors: [{ label: 'TLS / Protocol Maturity', score: 22 }, { label: 'PKI Readiness', score: 18 }],
    criticalFindings: collapsed,
    estimates: { migrationTimelineWeeks: 26, migrationCostUsd: 163020 },
    sharedResponsibility: sr,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any

  const report = buildReportModel(snapshot, branding, 'executive', 'Dedup Probe')

  const srReport = report.sharedResponsibility
  const reportMatrixRows = srReport.matrix.map((m) => [m.finding, m.asset, m.owner, m.action, m.priority, m.status].join(' | '))
  assert(new Set(reportMatrixRows).size === reportMatrixRows.length, 'report SR matrix has no duplicate rows', `${reportMatrixRows.length} rows`)
  assert(srReport.matrixInstances === inputs.length, 'report matrix reports the raw instance total', `${srReport.matrixInstances} instances`)

  const controls = report.playbookStandardControls
  const hoisted = controls.sharedKeys.length * Math.max(0, report.playbookDetail.length - 1)
  assert(controls.rows.length > 0, 'change controls shared by every playbook are hoisted', `${controls.sharedKeys.length} control row(s) x ${controls.applies} playbooks`)
  assert(hoisted > 0, 'hoisting removes repeated playbook rows from the document', `${hoisted} repeated row(s) removed`)
  const perPlaybook = playbookRows(report.playbookDetail[0], controls.sharedKeys).map((r) => r[0])
  assert(!perPlaybook.some((label) => controls.rows.some((c) => c.step === label)), 'no hoisted control is also printed per playbook')

  const integrity = report.reportValidation.checks.find((c) => c.check === 'Presentation Integrity Verified')
  assert(!!integrity, 'Report Validation includes the presentation-integrity check')
  assert(integrity?.status === 'pass', 'presentation-integrity check passes', integrity?.detail.slice(0, 110))

  console.log('\n[5] Every export format renders without duplicate rows')
  const { writeFileSync, mkdirSync } = await import('node:fs')
  mkdirSync('.report-smoke', { recursive: true })
  for (const fmt of ['html', 'pdf', 'docx', 'xlsx', 'csv', 'pptx', 'json'] as const) {
    const result = await exportReport(report, fmt)
    const bytes = Buffer.from(await result.blob.arrayBuffer())
    writeFileSync(`.report-smoke/dedup-out.${fmt}`, bytes)
    assert(bytes.byteLength > 0, `${fmt} export produced`, `${bytes.byteLength.toLocaleString()} bytes`)
  }

  // The HTML export is the full text surface — audit every rendered DATA row,
  // scoped PER TABLE. Column headers (<th>) legitimately repeat once per table,
  // and two self-contained runbooks may legitimately share a field value (both
  // migrating to TLS 1.3 + hybrid). A row repeated INSIDE one table is the
  // defect this fix targets.
  const html = Buffer.from(await (await exportReport(report, 'html')).blob.arrayBuffer()).toString('utf8')
  const tableRe = /<table[^>]*>([\s\S]*?)<\/table>/g
  let totalRows = 0
  let dupRowCount = 0
  const offenders: Array<[string, number]> = []
  let t: RegExpExecArray | null
  while ((t = tableRe.exec(html))) {
    const counts = new Map<string, number>()
    const rowRe = /<tr[^>]*>([\s\S]*?)<\/tr>/g
    let m: RegExpExecArray | null
    while ((m = rowRe.exec(t[1]))) {
      if (m[1].includes('<th')) continue
      const text = m[1].replace(/<[^>]+>/g, '|').replace(/\s+/g, ' ').trim()
      if (!text || /^\|+$/.test(text)) continue
      totalRows += 1
      counts.set(text, (counts.get(text) || 0) + 1)
    }
    for (const [row, c] of counts) {
      if (c > 1) {
        dupRowCount += c - 1;
        offenders.push([row, c]);
      }
    }
  }
  assert(dupRowCount === 0, 'no table in the rendered HTML report repeats a row', `${totalRows} data rows audited`)
  if (dupRowCount) for (const [row, c] of offenders.slice(0, 8)) console.log(`      x${c}  ${row.slice(0, 140)}`)

  console.log(`\n${failures === 0 ? 'PASS' : `FAIL (${failures})`} — report/dashboard deduplication check\n`)
  process.exit(failures === 0 ? 0 : 1)
}

reportChecks().catch((e) => {
  console.error('DEDUP CHECK FAILED:', e)
  process.exit(1)
})
