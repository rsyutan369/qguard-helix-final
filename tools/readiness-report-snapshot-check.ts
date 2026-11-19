import assert from 'node:assert/strict'
import { writeFile } from 'node:fs/promises'
import { buildReadinessReportModel } from '../src/api-server/readiness-report-model'
import { ownsReportOrganization, readinessReportDigest } from '../src/api-server/report-snapshot-store'
import { exportReadinessReport } from '../src/services/reporting/ReadinessDocument'
import { brandingSchema, REPORT_FORMATS, type ReportProvenance } from '../src/services/reporting/schemas/ReportSchema'

const owner = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
const first = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const second = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const at = '2026-11-17T04:00:00.000Z'
const asset = (id: string, name: string) => ({ id, name, registrationSource: 'registered', componentCount: 1, pqcStatus: 'Quantum-vulnerable' })
const component = (id: string, sourceAssetId: string, algorithm: string) => ({ id, sourceAssetId, algorithm, isVulnerable: true })
const scanner = {
  assets: { assets: [asset(first, 'Fixture primary'), asset(second, 'Fixture secondary')] },
  cbom: { entries: [component('component-1', first, 'RSA'), component('component-2', second, 'ECDH')] },
  findings: [],
  summary: { totalAssets: 2, totalComponents: 2 },
  generatedAt: at,
  sourceCoverage: ['assets', 'crypto_inventory', 'pqc_scan_results', 'pqc_scan_sessions', 'crypto_exposures', 'vulnerabilities']
    .map((source) => ({ source, status: 'available', detail: 'Test fixture only.' })),
} as unknown as Parameters<typeof buildReadinessReportModel>[0]['scanner']
const provenance: ReportProvenance = {
  reportId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', workspaceOwnerId: owner, organizationId: null,
  snapshotAt: at, assetInventoryVersion: 'inventory-fixture', cbomVersion: 'cbom-fixture',
  assessmentId: null, validationStatus: 'validated', dataCompleteness: [],
}
const build = (assetIds: string[] | null) => buildReadinessReportModel({
  scanner, assessment: null, assetIds, branding: brandingSchema.parse({}), kind: 'technical', generatedBy: 'Test fixture', provenance,
})
const captured = build(null)
const scoped = build([first])
assert.equal(captured.scope.totalAssetCount, 2)
assert.equal(scoped.scope.selectedAssetCount, 1)
assert.equal(scoped.tables.find((table) => table.title === 'Cryptographic bill of materials')?.rows.length, 1)
assert(!JSON.stringify(scoped).includes(second))
assert.throws(() => build(['missing']))
assert.equal(captured.provenance.validationStatus, 'incomplete')
assert.equal(ownsReportOrganization(first, [second]), false)
assert.equal(ownsReportOrganization(first, [first]), true)
const digest = readinessReportDigest(captured)
const stored = JSON.parse(JSON.stringify(captured, (_, value) =>
  value && typeof value === 'object' && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value).reverse())
    : value,
))
assert.equal(readinessReportDigest(stored), digest)
assert.notEqual(readinessReportDigest({ ...stored, executiveSummary: 'Changed' }), digest)
scanner.assets.assets.pop()
assert.equal(captured.scope.totalAssetCount, 2)
assert.equal(build(null).scope.totalAssetCount, 1)

for (const format of REPORT_FORMATS) {
  const { blob } = await exportReadinessReport(captured, format)
  assert(blob.size > 100, `Expected nonempty ${format} export`)
  if (['csv', 'json', 'html'].includes(format)) {
    const content = await blob.text()
    assert(content.includes('Fixture secondary') && content.includes('cbom-fixture'))
    assert(content.includes(provenance.reportId))
  }
  if (format === 'pdf' && process.argv[2]) await writeFile(process.argv[2], new Uint8Array(await blob.arrayBuffer()))
  console.log(`PASS ${format} (${blob.size} bytes)`)
}
console.log('PASS scoped evidence, historical model, canonical digest and organization access predicate')
