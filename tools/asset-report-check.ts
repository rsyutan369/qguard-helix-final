/**
 * Asset & CBOM report invariants — OFFLINE (no server, no database).
 *
 *   npx tsx tools/asset-report-check.ts
 *
 * Builds the three report templates from a fixture register and renders every
 * format in Node, asserting the contracts the Assets page export must keep:
 *
 *   §1 scope honesty — a 1-asset selection reports 1 asset and ITS components,
 *      never the estate (the old export printed estate KPIs over a selection)
 *   §2 reconciliation — exported rows == dashboard figures; estate + QR rows
 *      only for a full-estate scope, and all MATCH
 *   §3 consolidation preserves the vulnerable total
 *   §4 validation — WARN on stale evidence, FAIL on an empty scope
 *   §5 NIST roles — no signature/certificate row carries a KEM-only target
 *   §6 integrity — the SHA3-256 seal recomputes; the token carries it
 *   §7 no fabricated cost/timeline figures in the narrative
 *   §8 every format renders, structurally sound, for every template
 *   §9 a large estate builds within a bounded time
 */
import JSZip from 'jszip'
import ExcelJS from 'exceljs'
import { PDFDocument } from 'pdf-lib'
import { UnsecuredJWT } from 'jose'
import { partitionAssetInventory } from '../src/lib/scanner/asset-components'
import { algorithmFamily } from '../src/lib/governance/subjects'
import { buildAssetRegister, type AssetRegister } from '../src/lib/assets/asset-register'
import { ASSET_REPORT_TEMPLATES, buildAssetReport, canonicalAssetReport, consolidateExposures } from '../src/services/reporting/AssetReport'
import { sha3Hex } from '../src/services/reporting/ReportIntegrity'
import { ASSET_REPORT_LOGO_MAX_BYTES, assetReportLogoSchema, brandingSchema } from '../src/services/reporting/schemas/ReportSchema'
import { exportDocument, DOCUMENT_FORMATS } from '../src/services/reporting/exporters/DocumentExporters'
import type { InventoryReport } from '../src/services/reporting/InventoryReport'

let passed = 0
const failures: string[] = []
function check(name: string, actual: unknown, expected: unknown) {
  if (JSON.stringify(actual) === JSON.stringify(expected)) {
    passed += 1
    return
  }
  failures.push(`${name}\n     expected: ${JSON.stringify(expected)}\n     actual:   ${JSON.stringify(actual)}`)
}
const ok = (name: string, condition: boolean, detail = '') => check(detail ? `${name} (${detail})` : name, condition, true)

const NOW = Date.parse('2026-09-25T06:00:00Z')
const hoursAgo = (h: number) => new Date(NOW - h * 36e5).toISOString()
const branding = brandingSchema.parse({ companyName: 'Acme Corp', reportOwner: 'CISO Office' })

const maxLogo = Buffer.alloc(ASSET_REPORT_LOGO_MAX_BYTES).toString('base64')
ok('report accepts a PNG at the logo size limit', assetReportLogoSchema.safeParse(`data:image/png;base64,${maxLogo}`).success)
ok('report accepts a JPEG at the logo size limit', assetReportLogoSchema.safeParse(`data:image/jpeg;base64,${maxLogo}`).success)
const oversizedLogo = Buffer.alloc(ASSET_REPORT_LOGO_MAX_BYTES + 1).toString('base64')
ok('report rejects a logo one byte over the limit', !assetReportLogoSchema.safeParse(`data:image/png;base64,${oversizedLogo}`).success)
ok('report rejects unsupported logo formats', !assetReportLogoSchema.safeParse('data:image/svg+xml;base64,AAAA').success)

/* ------------------------------------------------------------------ */
/* Fixture register                                                    */
/* ------------------------------------------------------------------ */

let seq = 0
type InvOptions = {
  item_type?: string
  key_size?: number | null
  exposure_level?: string
  is_vulnerable?: boolean
  is_quantum_safe?: boolean
  created_at?: string
  metadata?: Record<string, unknown>
}
const inv = (asset: string, name: string, algorithm: string, o: InvOptions = {}) => ({
  id: `r${(seq += 1)}`,
  asset_id: asset,
  name,
  algorithm,
  item_type: o.item_type ?? 'algorithm',
  key_size: o.key_size ?? null,
  exposure_level: o.exposure_level ?? (o.is_quantum_safe ? 'safe' : 'high'),
  is_vulnerable: o.is_vulnerable ?? !o.is_quantum_safe,
  is_quantum_safe: o.is_quantum_safe ?? false,
  created_at: o.created_at ?? hoursAgo(200),
  metadata: o.metadata ?? {},
})

function assetPayload(id: string, name: string, rows: ReturnType<typeof inv>[], o: Record<string, unknown> = {}) {
  const part = partitionAssetInventory(rows, algorithmFamily)
  return {
    id,
    name,
    type: 'web_application',
    url: `https://${name}/`,
    cryptoInventory: part.components,
    postureObservations: part.posture,
    riskScore: o.riskScore ?? 50,
    lastScanned: o.lastScanned ?? hoursAgo(200),
    lastScannedSource: 'evidence',
    status: 'active',
    owner: o.owner ?? null,
    internetFacing: o.internetFacing ?? true,
    vulnerabilities: new Array(6).fill({}),
    metadata: { riskScore: o.riskScore ?? 50 },
  }
}

function fixtureRegister(fresh = false): AssetRegister {
  const age = fresh ? 2 : 200
  const A = [
    inv('A', 'Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', { exposure_level: 'critical', created_at: hoursAgo(age), metadata: { pqcReplacement: 'ML-KEM-768 or ML-KEM hybrid key exchange', recommendation: 'Migrate to PQC hybrid cipher suites', evidence: 'cipher-enum: Cipher Suite → https://a.example.com/' } }),
    inv('A', 'Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', { exposure_level: 'high', created_at: hoursAgo(age) }),
    inv('A', 'Certificate Signature: sha256WithRSAEncryption (Signature)', 'sha256WithRSAEncryption', { item_type: 'certificate', exposure_level: 'high', created_at: hoursAgo(age), metadata: { pqcReplacement: 'ML-KEM-768 (FIPS 203)' } }),
    inv('A', 'Rule (App Crypto): Wide Crypto Attack Surface', 'Wide Crypto Attack Surface', { exposure_level: 'medium', created_at: hoursAgo(age) }),
  ]
  const B = [
    inv('B', 'Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', { exposure_level: 'critical', created_at: hoursAgo(age) }),
    inv('B', 'Post-Quantum Key Agreement: X25519MLKEM768', 'X25519MLKEM768', { is_quantum_safe: true, created_at: hoursAgo(age) }),
  ]
  const C = [inv('C', 'Symmetric Encryption: AES-256-GCM', 'AES-256-GCM', { is_quantum_safe: true, created_at: hoursAgo(age) })]
  const assets = [
    assetPayload('A', 'a.example.com', A, { riskScore: 68, lastScanned: hoursAgo(age) }),
    assetPayload('B', 'b.example.com', B, { riskScore: 44, lastScanned: hoursAgo(age), owner: 'Payments' }),
    assetPayload('C', 'c.example.com', C, { riskScore: 8, lastScanned: hoursAgo(age), owner: 'Platform' }),
  ]
  return buildAssetRegister({
    snapshot: {
      generatedAt: new Date(NOW).toISOString(),
      summary: { totalAssets: 3, totalComponents: 6, vulnerableComponents: 4, pqcReadyComponents: 2, vulnerableAssets: 2, totalFindings: 9 },
      severityCounts: { critical: 2, high: 2, medium: 1, low: 0, safe: 2 },
      assets: { assets },
      history: { history: [] },
    },
    qr: { resolved: true, hasData: true, readiness: 41, readinessLevel: 'Early Stage', risk: 57, components: 6, vulnerableComponents: 4 },
    now: NOW,
  })
}

const register = fixtureRegister()
const rowA = register.rows.find((r) => r.id === 'A')!
const build = (rows = register.rows, template: 'executive' | 'technical' | 'remediation' = 'executive', scopeType: 'all' | 'selection' = 'all', reg = register) =>
  buildAssetReport({ register: reg, rows, scope: { type: scopeType, description: scopeType === 'all' ? 'the full estate' : `${rows.length} selected asset(s)` }, template, branding, generatedBy: 'check@qguard', generatedAt: new Date(NOW).toISOString() })

/* ------------------------------------------------------------------ */
console.log('\n[1] Scope honesty')
const single = build([rowA], 'executive', 'selection')
const kpi = (r: InventoryReport, label: string) => r.document!.summary.highlights.find((h) => h.label === label)?.value
check('a 1-asset selection reports 1 asset', kpi(single, 'Assets in scope'), '1')
check('…and that asset\'s components (3), not the estate\'s (6)', kpi(single, 'Crypto components'), '3')
check('…and its vulnerable components (3)', kpi(single, 'Quantum-vulnerable'), '3')
ok('cover scope line names the selection against the estate', /1 asset of 3/.test(single.document!.cover.scopeLine), single.document!.cover.scopeLine)
const full = build()
check('full estate reports 3 assets', kpi(full, 'Assets in scope'), '3')

/* ------------------------------------------------------------------ */
console.log('[2] Reconciliation')
ok('selection: every reconciliation row MATCHes', single.reconciliation.every((r) => r.matches))
ok('selection: no estate-headline rows (a subset is not a mismatch)', !single.reconciliation.some((r) => /headline|Quantum Readiness Engine/.test(r.metric)))
ok('full estate: estate + QR rows present', full.reconciliation.some((r) => /CBOM headline/.test(r.metric)) && full.reconciliation.some((r) => /Quantum Readiness Engine/.test(r.metric)))
ok('full estate: every reconciliation row MATCHes', full.reconciliation.every((r) => r.matches), full.reconciliation.filter((r) => !r.matches).map((r) => r.metric).join('; '))

/* ------------------------------------------------------------------ */
console.log('[3] Consolidation preserves totals')
const exposures = consolidateExposures(register.rows)
const vulnerable = register.rows.reduce((s, r) => s + r.components.vulnerable, 0)
check('Σ exposure components == vulnerable components', exposures.reduce((s, e) => s + e.components, 0), vulnerable)
const rsa = exposures.find((e) => /RSA key transport/.test(e.riskBearing))
check('one root cause shared by two assets appears once, with both assets', rsa?.assets, ['a.example.com', 'b.example.com'])

/* ------------------------------------------------------------------ */
console.log('[4] Validation gates')
check('stale evidence → WARN', full.document!.validation.status, 'warn')
const freshReport = build(fixtureRegister(true).rows, 'executive', 'all', fixtureRegister(true))
ok('fresh evidence → no stale warning', !freshReport.document!.validation.checks.some((c) => c.check === 'Evidence is current' && c.status !== 'pass'))
const empty = buildAssetReport({ register, rows: [], scope: { type: 'selection', description: 'nothing' }, template: 'executive', branding, generatedBy: 'x' })
check('empty scope → FAIL', empty.document!.validation.status, 'fail')
ok('every structural check passes on a real scope', full.document!.validation.checks.filter((c) => !['Evidence is current', 'Quantum Readiness Engine agreement', 'Estate figures reconcile with the CBOM', 'Every counted component names a parseable primitive', 'No contradictory posture flags'].includes(c.check)).every((c) => c.status === 'pass'))

/* ------------------------------------------------------------------ */
console.log('[5] NIST roles in every table')
for (const template of ['executive', 'technical', 'remediation'] as const) {
  const report = build(register.rows, template)
  const tables = [
    ...report.tables,
    ...report.document!.sections.flatMap((s) => s.blocks.flatMap((b) => (b.type === 'table' ? [b.table] : b.type === 'dossier' ? b.dossier.tables.map((t) => t.table) : []))),
  ]
  const bad: string[] = []
  for (const t of tables) {
    const target = t.columns.findIndex((c) => /PQC target/i.test(c))
    const component = t.columns.findIndex((c) => /^Component$/i.test(c))
    if (target < 0 || component < 0) continue
    for (const row of t.rows) if (/Signature|Certificate/i.test(String(row[component])) && /ML-?KEM/i.test(String(row[target])) && !/ML-?DSA|SLH-?DSA/i.test(String(row[target]))) bad.push(`${t.title}: ${row[component]} -> ${row[target]}`)
  }
  check(`${template}: no signature/certificate row with a KEM-only target`, bad, [])
}
ok('the corrected target is disclosed in the full CBOM export', full.tables.find((t) => t.title === 'Cryptographic Bill of Materials')!.rows.some((r) => String(r[10]).startsWith('Corrected')))

/* ------------------------------------------------------------------ */
console.log('[6] Integrity seal')
check('SHA3-256 recomputes from the exported JSON', sha3Hex(canonicalAssetReport(JSON.parse(JSON.stringify(full)))), full.integrity!.hash)
const claims = UnsecuredJWT.decode(full.integrity!.verificationToken).payload as Record<string, unknown>
check('token carries the digest + id', [claims.hash, claims.reportId, claims.kind], [full.integrity!.hash, full.meta.reportId, 'asset-inventory'])
check('the document copy is the same seal', full.document!.integrity, full.integrity)
const tampered = JSON.parse(JSON.stringify(full))
tampered.kpis[0].value = '999'
ok('negative control: tampering changes the digest', sha3Hex(canonicalAssetReport(tampered)) !== full.integrity!.hash)

/* ------------------------------------------------------------------ */
console.log('[7] No fabricated cost or timeline')
for (const template of ['executive', 'technical', 'remediation'] as const) {
  const text = JSON.stringify(build(register.rows, template).document!.summary)
  ok(`${template}: no currency figures in the executive summary`, !/\$\s?\d/.test(text))
}

/* ------------------------------------------------------------------ */
console.log('[8] Every format renders for every template')
for (const spec of ASSET_REPORT_TEMPLATES) {
  const report = build(register.rows, spec.key)
  for (const format of DOCUMENT_FORMATS) {
    try {
      const { blob, filename } = await exportDocument(report, format)
      const bytes = Buffer.from(await blob.arrayBuffer())
      ok(`${spec.key}.${format} non-empty`, bytes.length > 1000, `${bytes.length} bytes`)
      ok(`${spec.key}.${format} filename`, filename.startsWith(`qguard-asset-${spec.key}-report-`) && filename.endsWith(`.${format}`), filename)
      if (format === 'pdf') {
        const pdf = await PDFDocument.load(bytes)
        const orientations = pdf.getPages().map((p) => (p.getSize().width > p.getSize().height ? 'L' : 'P')).join('')
        ok(`${spec.key}.pdf has a cover + contents + body`, pdf.getPageCount() >= 4, `${pdf.getPageCount()} pages`)
        if (spec.key === 'technical') ok('technical.pdf prints the wide registers landscape', orientations.includes('L'), orientations)
      }
      if (format === 'docx') {
        const xml = await (await JSZip.loadAsync(bytes)).file('word/document.xml')!.async('string')
        ok(`${spec.key}.docx carries the headline`, xml.includes('require modernization'))
      }
      if (format === 'xlsx') {
        const wb = new ExcelJS.Workbook()
        await wb.xlsx.load(bytes)
        check(`${spec.key}.xlsx register rows`, (wb.getWorksheet('Asset Register')?.rowCount ?? 0) - 1, register.rows.length)
      }
      if (format === 'pptx') {
        const slides = Object.keys((await JSZip.loadAsync(bytes)).files).filter((f) => /^ppt\/slides\/slide\d+\.xml$/.test(f)).length
        ok(`${spec.key}.pptx slides`, slides >= 6, `${slides}`)
      }
      if (format === 'html') {
        const html = bytes.toString('utf8')
        ok(`${spec.key}.html seal + QR`, html.includes(report.integrity!.hash) && html.includes('Report verification QR code'))
        ok(`${spec.key}.html makes no external requests`, !/<(script|link|img)[^>]+(src|href)="https?:/i.test(html))
      }
      if (format === 'csv') ok(`${spec.key}.csv BOM + provenance`, bytes[0] === 0xef && bytes.toString('utf8').includes(report.integrity!.hash))
      if (format === 'json') check(`${spec.key}.json round-trips the model`, JSON.parse(bytes.toString('utf8')).meta.reportId, report.meta.reportId)
    } catch (err) {
      failures.push(`${spec.key}.${format} threw: ${(err as Error).message}`)
    }
  }
}

/* ------------------------------------------------------------------ */
console.log('[9] A large estate builds in bounded time')
const bigAssets = Array.from({ length: 600 }, (_, i) => {
  const rows = Array.from({ length: 18 }, (_, j) => inv(`X${i}`, `Cipher Suite: TLS_ECDHE_RSA_WITH_AES_${j % 2 ? 128 : 256}_GCM_SHA${j % 3 ? 256 : 384}_${j}`, `TLS_ECDHE_RSA_WITH_AES_${j % 2 ? 128 : 256}_GCM_SHA${j % 3 ? 256 : 384}`, { exposure_level: j % 4 ? 'high' : 'critical' }))
  return assetPayload(`X${i}`, `host-${i}.example.com`, rows, { riskScore: (i * 7) % 100 })
})
const t0 = Date.now()
const big = buildAssetRegister({ snapshot: { summary: { totalAssets: 600, totalComponents: 600 * 18, vulnerableComponents: 600 * 18, pqcReadyComponents: 0, vulnerableAssets: 600 }, assets: { assets: bigAssets } }, now: NOW })
const bigReport = buildAssetReport({ register: big, rows: big.rows, scope: { type: 'all', description: 'the full estate' }, template: 'technical', branding, generatedBy: 'x' })
const elapsed = Date.now() - t0
ok('600 assets × 18 components: register + technical report < 8s', elapsed < 8000, `${elapsed} ms`)
check('…and it reconciles', bigReport.reconciliation.every((r) => r.matches), true)
check('…with every component in the CBOM export', bigReport.tables.find((t) => t.title === 'Cryptographic Bill of Materials')!.rows.length, 600 * 18)

console.log('')
if (failures.length) {
  console.log(`✗ ${failures.length} FAILED, ${passed} passed\n`)
  for (const f of failures) console.log(`  ✗ ${f}`)
  process.exit(1)
}
console.log(`✓ ASSET REPORTS HOLD — ${passed} checks passed\n`)
