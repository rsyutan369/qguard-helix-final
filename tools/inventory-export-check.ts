/**
 * Inventory export model checks.
 *
 * The contract this guards: an export must agree with the dashboard it was
 * launched from. Every document carries a Reconciliation table, and these
 * assertions verify the builder produces it correctly — including the cases
 * where it must NOT claim a match (a filtered export is deliberately smaller
 * than the estate, and saying "MATCH" there would be a false assurance).
 *
 *   npx tsx tools/inventory-export-check.ts
 */
import {
  buildInventoryReport,
  isCryptographicComponent,
  type AssetRow,
  type CbomRow,
  type InventorySummary,
} from '../src/services/reporting/InventoryReport'
import { sanitizeForWinAnsi } from '../src/services/reporting/exporters/pdf-text'

let passed = 0
const failures: string[] = []
const check = (name: string, actual: unknown, expected: unknown) => {
  if (actual === expected) { passed += 1; return }
  failures.push(`${name}\n     expected: ${JSON.stringify(expected)}\n     actual:   ${JSON.stringify(actual)}`)
}
const ok = (name: string, condition: boolean) => check(name, condition, true)

/* ---- Fixtures modelled on the live tenant ---- */

const SUMMARY: InventorySummary = {
  totalAssets: 2,
  totalComponents: 6,
  vulnerableAssets: 2,
  // 4, not 3: the platform flags policy rows (c6 "No OCSP Stapling") vulnerable too,
  // so the estate count spans cryptographic AND posture rows. The reconciliation
  // table compares against every exported row, which is what makes a genuine
  // dashboard/export divergence show up as REVIEW.
  vulnerableComponents: 4,
  pqcReadyComponents: 2,
  criticalFindings: 4,
  totalFindings: 6,
  riskScore: 23,
  qScore: 77,
}

const ASSETS: AssetRow[] = [
  {
    id: 'a1', name: 'www.cloudflare.com', type: 'web_application', url: 'https://www.cloudflare.com/',
    riskLevel: 'critical', riskScore: 100, qScore: 20, complianceStatus: 'Non-compliant', status: 'active',
    lastScanned: '2026-08-12T06:11:44Z', findingsCount: 4, vulnerableCount: 3,
    cryptography: ['TLS_RSA_WITH_AES_256_CBC_SHA', 'ML-KEM-768 (FIPS 203)'],
  },
  {
    id: 'a2', name: 'test.openquantumsafe.org', type: 'web_application', url: 'https://test.openquantumsafe.org/',
    riskLevel: 'high', riskScore: 75, qScore: 63, complianceStatus: 'Partial', status: 'active',
    lastScanned: '2026-08-12T06:11:44Z', findingsCount: 2, vulnerableCount: 1,
    cryptography: ['TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'],
  },
]

const CBOM: CbomRow[] = [
  { id: 'c1', component: 'Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA', type: 'algorithm', algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', status: 'Quantum-vulnerable', isVulnerable: true, isQuantumSafe: false, instances: 2, sourceAsset: 'www.cloudflare.com', sourceAssetId: 'a1' },
  { id: 'c2', component: 'Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA', type: 'algorithm', algorithm: 'TLS_RSA_WITH_AES_128_CBC_SHA', status: 'Quantum-vulnerable', isVulnerable: true, isQuantumSafe: false, instances: 2, sourceAsset: 'www.cloudflare.com', sourceAssetId: 'a1' },
  { id: 'c3', component: 'Certificate: ECDSA P-256 (Certificate)', type: 'certificate', algorithm: 'ECDSA P-256', status: 'Quantum-vulnerable', isVulnerable: true, isQuantumSafe: false, instances: 1, sourceAsset: 'test.openquantumsafe.org', sourceAssetId: 'a2' },
  { id: 'c4', component: 'Post-Quantum Key Agreement: ML-KEM-768 (FIPS 203)', type: 'algorithm', algorithm: 'ML-KEM-768', status: 'PQC-ready', isVulnerable: false, isQuantumSafe: true, instances: 1, sourceAsset: 'www.cloudflare.com', sourceAssetId: 'a1' },
  { id: 'c5', component: 'Symmetric Encryption: AES-256-GCM', type: 'algorithm', algorithm: 'AES-256-GCM', status: 'PQC-ready', isVulnerable: false, isQuantumSafe: true, instances: 3, sourceAsset: 'www.cloudflare.com', sourceAssetId: 'a1' },
  // Policy row — must never be counted as an algorithm.
  { id: 'c6', component: 'Rule (Certificate Risk): No OCSP Stapling', type: 'certificate', algorithm: 'No OCSP Stapling', status: 'Review', isVulnerable: true, isQuantumSafe: false, instances: 2, sourceAsset: 'www.cloudflare.com', sourceAssetId: 'a1', riskSeverity: 'low' },
]

const base = {
  summary: SUMMARY,
  assets: ASSETS,
  cbom: CBOM,
  totalAssetsBeforeFilter: ASSETS.length,
  totalCbomBeforeFilter: CBOM.length,
  generatedAt: '2026-08-12T10:00:00Z',
  lastScanAt: '2026-08-12T06:11:44Z',
}

/* ---- Policy vs cryptography split ---- */

check('cipher suite is cryptography', isCryptographicComponent(CBOM[0]), true)
check('certificate is cryptography', isCryptographicComponent(CBOM[2]), true)
check('PQ key agreement is cryptography', isCryptographicComponent(CBOM[3]), true)
check('rule row is NOT cryptography', isCryptographicComponent(CBOM[5]), false)

/* ---- Assets export ---- */

const assetsReport = buildInventoryReport({ ...base, kind: 'assets' })

check('assets title', assetsReport.meta.title, 'Asset Inventory Report')
const assetTable = assetsReport.tables.find((t) => t.title === 'Asset Inventory')
ok('asset inventory table present', Boolean(assetTable))
check('one row per asset', assetTable?.rows.length, ASSETS.length)
check('asset row names the asset', assetTable?.rows[0][0], 'www.cloudflare.com')
ok('asset table has no empty header', (assetTable?.columns ?? []).every((c) => String(c).trim().length > 0))

const perAsset = assetsReport.tables.find((t) => t.title === 'Cryptography Observed Per Asset')
check('per-asset crypto rows == total algorithms listed', perAsset?.rows.length, 3)

// Policy rows are tabled, but separately from the algorithm tables.
const cryptoTable = assetsReport.tables.find((t) => /Cryptographic Components|Bill of Materials/.test(t.title))
const postureTable = assetsReport.tables.find((t) => t.title === 'Configuration & Policy Observations')
check('cryptographic components exclude the policy row', cryptoTable?.rows.length, 5)
check('policy row is tabled separately', postureTable?.rows.length, 1)
ok(
  'no policy row leaked into the algorithm table',
  !(cryptoTable?.rows ?? []).some((row) => String(row[0]).includes('No OCSP Stapling')),
)

/* ---- Reconciliation ---- */

const recon = (report: ReturnType<typeof buildInventoryReport>, metric: string) =>
  report.reconciliation.find((r) => r.metric === metric)

ok('unfiltered export reconciles assets', recon(assetsReport, 'Assets discovered')?.matches === true)
ok('unfiltered export reconciles components', recon(assetsReport, 'Crypto components')?.matches === true)
ok('unfiltered export reconciles vulnerable', recon(assetsReport, 'Quantum-vulnerable components')?.matches === true)
ok('unfiltered export reconciles PQC-ready', recon(assetsReport, 'PQC-ready components')?.matches === true)
ok('crypto + posture always sums to total', recon(assetsReport, 'Cryptographic vs posture rows')?.matches === true)
ok('every reconciliation row matches on a clean export', assetsReport.reconciliation.every((r) => r.matches))

/* ---- CBOM export ---- */

const cbomReport = buildInventoryReport({ ...base, kind: 'cbom' })
check('cbom title', cbomReport.meta.title, 'Cryptographic Bill of Materials (CBOM)')
const algoTable = cbomReport.tables.find((t) => t.title === 'Algorithm Summary')
ok('algorithm summary present', Boolean(algoTable))
// 5 cryptographic rows -> 5 distinct algorithms here.
check('algorithm summary excludes policy rows', algoTable?.rows.length, 5)
const aesRow = algoTable?.rows.find((r) => r[0] === 'AES-256-GCM')
check('instance counts are carried, not row counts', aesRow?.[2], '3')
check('cbom KPI names PQC-ready', cbomReport.kpis[1].label, 'PQC-Ready')
ok('cbom has no asset-inventory table', !cbomReport.tables.some((t) => t.title === 'Asset Inventory'))

/* ---- Filtered export must NOT claim estate-wide agreement ---- */

const filtered = buildInventoryReport({
  ...base,
  kind: 'cbom',
  cbom: CBOM.slice(0, 2),
  filtered: true,
  filterDescription: 'status = vulnerable',
})
ok('filtered export omits estate reconciliation', !recon(filtered, 'Crypto components'))
ok('filtered export still reconciles its own split', recon(filtered, 'Cryptographic vs posture rows')?.matches === true)
ok('filtered scope note says so', /Filtered view/.test(filtered.meta.scopeNote))
ok('filtered note warns about omitted rows', filtered.notes.some((n) => /FILTERED export/.test(n)))
ok('filter description is carried', /status = vulnerable/.test(filtered.meta.scopeNote))

/* ---- Empty estate ---- */

const empty = buildInventoryReport({
  kind: 'assets',
  summary: { totalAssets: 0, totalComponents: 0, vulnerableAssets: 0, vulnerableComponents: 0, pqcReadyComponents: 0, criticalFindings: 0, totalFindings: 0, riskScore: 0, qScore: 0 },
  assets: [],
  cbom: [],
  totalAssetsBeforeFilter: 0,
  totalCbomBeforeFilter: 0,
})
check('empty export still produces the register table', empty.tables[0]?.title, 'Asset Inventory')
check('empty register has no rows', empty.tables[0]?.rows.length, 0)
ok('empty export invents no algorithm table', !empty.tables.some((t) => t.title === 'Algorithm Summary'))
ok('empty export still reconciles', empty.reconciliation.every((r) => r.matches))

/* ---- Provenance is always published ---- */

for (const report of [assetsReport, cbomReport, filtered, empty]) {
  ok(`provenance present (${report.meta.kind})`, report.meta.provenance.includes('authorized scanner intelligence'))
  ok(`no-simulation note present (${report.meta.kind})`, report.notes.some((n) => /No value is simulated/.test(n)))
}


/* ---- WinAnsi safety (reported: PDF export died on "→" 0x2192) ---------- */
{
  // pdf-lib StandardFonts encode CP1252; ANY code point outside Latin-1 throws
  // at draw time and kills the whole export, not just the offending cell.
  const outsideLatin1 = /[^\x20-\xFF]/
  const cases: Array<[string, string]> = [
    ['RSA-2048 → ML-KEM-768', 'RSA-2048 -> ML-KEM-768'],
    ['Risk ↓ 31%', 'Risk v 31%'],
    ['QGuard Helix™', 'QGuard Helix(TM)'],
    ['≥ 80 and ≤ 100', '>= 80 and <= 100'],
    ['a — b', 'a - b'],
    ['“quoted”', '"quoted"'],
    ['bullet • point', 'bullet - point'],
    ['✓ verified', 'Yes verified'],
  ]
  for (const [input, expected] of cases) {
    check(`sanitize ${JSON.stringify(input)}`, sanitizeForWinAnsi(input), expected)
  }

  // Nothing the builder emits may reach pdf-lib un-encodable.
  const everyString: string[] = []
  for (const report of [assetsReport, cbomReport, filtered, empty]) {
    everyString.push(report.meta.title, report.meta.subtitle, report.meta.scopeNote, report.meta.provenance, ...report.notes)
    for (const kpi of report.kpis) everyString.push(kpi.label, kpi.value, kpi.detail ?? '')
    for (const table of report.tables) {
      everyString.push(table.title, ...table.columns.map(String))
      for (const row of table.rows) everyString.push(...row.map(String))
    }
  }
  const unsafe = everyString.filter((value) => outsideLatin1.test(sanitizeForWinAnsi(value)))
  ok(`sanitised output is WinAnsi-safe across ${everyString.length} strings`, unsafe.length === 0)

  // Emoji / CJK have no ASCII equivalent and must be dropped, not passed through.
  ok('unmappable glyphs are dropped', !outsideLatin1.test(sanitizeForWinAnsi('scan 🔐 完了')))
  check('sanitize handles null', sanitizeForWinAnsi(null), '')
  check('sanitize collapses newlines', sanitizeForWinAnsi('a\nb\tc'), 'a b c')
}

if (failures.length) {
  console.error(`\n✗ ${failures.length} failed after WinAnsi checks\n`)
  for (const failure of failures) console.error(`  ✗ ${failure}\n`)
  process.exit(1)
}
console.log(`✓ inventory-export (incl. WinAnsi): ${passed} checks passed`)
