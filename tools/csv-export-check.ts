import assert from 'node:assert/strict'
import { csvCell, quotedCsvCell } from '../src/lib/csv'
import { cbomToCsv } from '../src/lib/scanner/exposure/cbom'
import type { CbomComponent } from '../src/lib/scanner/exposure/types'
import { exportInventory } from '../src/services/reporting/exporters/InventoryExporters'

assert.equal(csvCell('service-a'), 'service-a')
assert.equal(csvCell('TLS, "hybrid"'), '"TLS, ""hybrid"""')
assert.equal(csvCell('line 1\r\nline 2'), '"line 1\r\nline 2"')
assert.equal(csvCell(-25), '-25')
assert.equal(csvCell(null), '')
assert.equal(csvCell('  =notes'), "'  =notes")
assert.equal(csvCell('  \tlabel'), "'  \tlabel")
assert.equal(csvCell('＠label'), "'＠label")
assert.equal(quotedCsvCell('=archive.ts'), "\"'=archive.ts\"")

const component: CbomComponent = {
  id: 'component-1',
  algorithm: 'AES-256-GCM',
  canonicalAlgorithm: 'AES-256-GCM',
  keySize: 256,
  file: '=archive.ts',
  usage: 'encryption',
  confidence: 'high',
  detection: 'observed',
  quantumStatus: 'resistant',
  layer: 'source',
  evidence: [],
}
const [cbomHeading, cbomRow] = cbomToCsv([component]).split('\n')
assert.ok(cbomHeading.startsWith('Component ID,Algorithm,Canonical Algorithm,Key Size,'))
assert.ok(cbomRow.includes(",\"'=archive.ts\","))
assert.ok(cbomRow.includes(',"256",'))

const report = await exportInventory({
  meta: {
    kind: 'assets',
    title: 'Asset inventory',
    subtitle: '',
    generatedAt: '2026-11-17T00:00:00.000Z',
    companyName: 'Audit fixture',
    classification: '',
    scopeNote: '',
    provenance: '',
  },
  kpis: [],
  tables: [{
    title: 'Inventory',
    columns: ['Asset', 'Delta', 'Note'],
    rows: [['  =item', -25, 'TLS, "hybrid"']],
  }],
  reconciliation: [],
  notes: [],
}, 'csv')
assert.equal(report.filename, 'qguard-asset-inventory-2026-11-17.csv')
assert.equal(await report.blob.text(), [
  '# Inventory',
  'Asset,Delta,Note',
  "'  =item,-25,\"TLS, \"\"hybrid\"\"\"",
  '',
].join('\n'))
console.log('CSV formatting and text-cell protection checks passed')
