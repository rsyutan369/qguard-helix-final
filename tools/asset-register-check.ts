/**
 * Asset register invariants — OFFLINE.
 *
 *   npx tsx tools/asset-register-check.ts
 *
 * Pins the rules behind /dashboard/assets (src/lib/assets/asset-register.ts and
 * src/lib/scanner/asset-components.ts). Every fixture encodes a defect found in
 * the 2026-09-25 audit, with a negative control where one applies:
 *
 *   §1  scanner FINDINGS stored in crypto_inventory are never components
 *       (one asset read "20 vulnerable of 25" under a headline of 8 of 12)
 *   §2  the per-asset grouping IS the CBOM grouping → Σ rows == CBOM headline
 *   §3  PQC-ready only when every measured component is quantum-safe
 *   §4  an asset with no evidence is "Not Assessed", never a green band
 *   §5  freshness comes from evidence time, not snapshot compute time
 *   §6  a stored ML-KEM target on a signature/certificate is corrected
 *   §7  totals for a SUBSET are computed from that subset (report scope honesty)
 *   §8  reconciliation reports divergence instead of hiding it
 *   §9  live scans and workflow lifecycle attach to the right asset
 *   §10 filter / sort
 */
import { partitionAssetInventory, cbomComponentKey } from '../src/lib/scanner/asset-components'
import { algorithmFamily } from '../src/lib/governance/subjects'
import {
  buildAssetRegister,
  filterRows,
  resolvePqcTarget,
  sortRows,
  summarizeRows,
  STALE_AFTER_HOURS,
  type RegisterSnapshotInput,
} from '../src/lib/assets/asset-register'

let passed = 0
const failures: string[] = []
function check(name: string, actual: unknown, expected: unknown) {
  if (JSON.stringify(actual) === JSON.stringify(expected)) {
    passed += 1
    return
  }
  failures.push(`${name}\n     expected: ${JSON.stringify(expected)}\n     actual:   ${JSON.stringify(actual)}`)
}
const ok = (name: string, condition: boolean) => check(name, condition, true)

const NOW = Date.parse('2026-09-25T06:00:00Z')
const hoursAgo = (h: number) => new Date(NOW - h * 36e5).toISOString()

/* ------------------------------------------------------------------ */
/* Fixtures modelled on the live tenants                               */
/* ------------------------------------------------------------------ */

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
  id: `${asset}-${name}`,
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

// Asset A — the "20 of 25" shape: 3 real components + 2 findings in crypto_inventory.
const A_ROWS = [
  inv('A', 'Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', { exposure_level: 'critical', metadata: { pqcReplacement: 'ML-KEM-768 or ML-KEM hybrid key exchange' } }),
  inv('A', 'Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', { exposure_level: 'critical', created_at: hoursAgo(190) }), // second observation, same component
  inv('A', 'Certificate Signature: sha256WithRSAEncryption (Signature)', 'sha256WithRSAEncryption', { item_type: 'certificate', exposure_level: 'high', metadata: { pqcReplacement: 'ML-KEM-768 (FIPS 203)' } }),
  inv('A', 'Post-Quantum Key Agreement: ML-KEM-768 (FIPS 203)', 'ML-KEM-768', { is_quantum_safe: true }),
  inv('A', 'Rule (App Crypto): Wide Crypto Attack Surface', 'Wide Crypto Attack Surface', { exposure_level: 'medium' }),
  inv('A', 'Certificate Revocation: No OCSP Stapling', 'No OCSP Stapling', { exposure_level: 'low' }),
]

/* ------------------------------------------------------------------ */
console.log('\n[1] Findings stored in crypto_inventory are never components')
const partA = partitionAssetInventory(A_ROWS, algorithmFamily)
check('3 real components (the duplicate suite observation groups into one)', partA.counts.components, 3)
check('2 finding rows become posture observations', partA.counts.posture, 2)
check('posture names', partA.posture.map((p) => p.name).sort(), ['Certificate Revocation: No OCSP Stapling', 'Rule (App Crypto): Wide Crypto Attack Surface'])
check('vulnerable counts cryptography only (negative control: the finding rows are vulnerable too)', partA.counts.vulnerable, 2)
check('the duplicate observation is counted as an instance, not a component', partA.components.find((c) => c.algorithm === 'TLS_RSA_WITH_AES_256_CBC_SHA')?.instances, 2)
check('partition sums', partA.counts.vulnerable + partA.counts.pqcReady + partA.counts.unclassified, partA.counts.components)

/* ------------------------------------------------------------------ */
console.log('[2] The per-asset grouping is the CBOM grouping')
const cbomKeys = new Set(A_ROWS.filter((r) => partA.components.some((c) => cbomComponentKey(c) === cbomComponentKey(r))).map(cbomComponentKey))
check('every component key is a CBOM key', cbomKeys.size, partA.counts.components)

/* ------------------------------------------------------------------ */
const snapshot = (assets: unknown[], summary: Record<string, number>, history: unknown[] = []): RegisterSnapshotInput => ({
  generatedAt: new Date(NOW).toISOString(),
  summary,
  severityCounts: { critical: 3, high: 4, medium: 2, low: 1, safe: 2 },
  assets: { assets },
  history: { history },
})

const assetPayload = (id: string, name: string, rows: ReturnType<typeof inv>[], o: Record<string, unknown> = {}) => {
  const part = partitionAssetInventory(rows, algorithmFamily)
  return {
    id,
    name,
    type: o.type ?? 'web_application',
    url: o.url ?? `https://${name}/`,
    cryptoInventory: o.legacy ? rows : part.components,
    postureObservations: o.legacy ? undefined : part.posture,
    riskScore: o.riskScore ?? 55,
    lastScanned: 'lastScanned' in o ? o.lastScanned : hoursAgo(200),
    lastScannedSource: o.lastScannedSource ?? 'evidence',
    status: 'active',
    owner: o.owner ?? null,
    internetFacing: o.internetFacing ?? true,
    vulnerabilities: o.vulnerabilities ?? new Array(o.signals ?? 5).fill({}),
    metadata: o.metadata ?? { riskScore: o.riskScore ?? 55 },
  }
}

const B_ROWS = [
  inv('B', 'Symmetric Encryption: AES-256-GCM', 'AES-256-GCM', { is_quantum_safe: true, created_at: hoursAgo(2) }),
  inv('B', 'Post-Quantum Key Agreement: X25519MLKEM768', 'X25519MLKEM768', { is_quantum_safe: true, created_at: hoursAgo(2) }),
]
const C_ROWS = [inv('C', 'Protocol: TLSv1.3', 'TLSv1.3', { is_vulnerable: false, is_quantum_safe: false, exposure_level: 'low', created_at: hoursAgo(30) })]

const assets = [
  assetPayload('A', 'a.example.com', A_ROWS, { riskScore: 68 }),
  assetPayload('B', 'b.example.com', B_ROWS, { riskScore: 12, lastScanned: hoursAgo(2), owner: 'Platform team' }),
  assetPayload('C', 'c.example.com', C_ROWS, { riskScore: 30, lastScanned: hoursAgo(30) }),
  // D — nothing measured, no evidence at all.
  // The API falls back to the asset ROW time when there is no evidence
  // (`lastScannedSource: 'asset-record'`) — that must not read as a scan.
  assetPayload('D', 'd.internal', [], { riskScore: 0, lastScanned: hoursAgo(3), lastScannedSource: 'asset-record', signals: 0, metadata: {}, internetFacing: false }),
]
const headline = { totalAssets: 4, totalComponents: 6, vulnerableComponents: 2, pqcReadyComponents: 3, vulnerableAssets: 1, totalFindings: 12, activeScans: 0 }
const register = buildAssetRegister({
  snapshot: snapshot(assets, headline, [{ status: 'running', target: 'https://b.example.com/', liveProgress: 45 }]),
  qr: { resolved: true, hasData: true, readiness: 41, readinessLevel: 'Early Stage', risk: 57, components: 6, vulnerableComponents: 2 },
  workflowStates: [{ asset: 'a.example.com', stageId: 'remediation', stageLabel: 'AI Remediation', openActions: 4, validationStatus: 'Pending rescan' }],
  now: NOW,
})
const row = (id: string) => register.rows.find((r) => r.id === id)!

/* ------------------------------------------------------------------ */
console.log('[3] PQC status is decided only from measured components')
check('A is quantum-vulnerable', row('A').pqcStatus, 'quantum-vulnerable')
check('B (every component quantum-safe) is PQC-ready', row('B').pqcStatus, 'pqc-ready')
check('C (unclassified component) needs review — never "ready"', row('C').pqcStatus, 'needs-review')
check('D (nothing measured) is not measured — never "ready"', row('D').pqcStatus, 'not-measured')
ok('A reason quotes the counts', row('A').pqcStatusReason.startsWith('2 of 3 measured components'))

/* ------------------------------------------------------------------ */
console.log('[4] Unmeasured risk is "Not Assessed", not a green band')
check('D risk score is null', row('D').riskScore, null)
check('D band is unassessed', row('D').risk.key, 'unassessed')
check('A band from the canonical table (68 → High)', row('A').risk.label, 'High')
check('B band (12 → Low)', row('B').risk.label, 'Low')

/* ------------------------------------------------------------------ */
console.log('[5] Freshness is measured from evidence time')
check('A (200h) is stale', row('A').freshness.state, 'stale')
check('B (2h) is fresh', row('B').freshness.state, 'fresh')
check('C (30h) is aging', row('C').freshness.state, 'aging')
check('D (record time only, never scanned) has no scan timestamp', row('D').freshness.state, 'unknown')
check('negative control: D does not read as "scanned 3 hours ago"', row('D').lastScanned, null)
check('register measuredAt = newest evidence, not snapshot compute time', register.measuredAt, hoursAgo(2))
ok(`stale threshold is the platform's ${STALE_AFTER_HOURS}h`, STALE_AFTER_HOURS === 72)

/* ------------------------------------------------------------------ */
console.log('[6] PQC targets respect NIST roles')
const sig = row('A').componentList.find((c) => c.algorithm === 'sha256WithRSAEncryption')!
check('a stored ML-KEM target on a certificate signature is corrected', sig.pqcTargetSource, 'corrected')
ok('…to an ML-DSA target', /ML-DSA/.test(sig.pqcReplacement || ''))
const suite = row('A').componentList.find((c) => c.algorithm === 'TLS_RSA_WITH_AES_256_CBC_SHA')!
check('negative control: an ML-KEM target on a key-exchange suite is kept', suite.pqcTargetSource, 'scanner')
check('a vulnerable component with no stored target gets the canonical one', resolvePqcTarget('signature', 'ECDSA P-256', null, 'vulnerable').source, 'derived')
check('a PQC-ready component needs no target', resolvePqcTarget('key-exchange', 'ML-KEM-768', null, 'pqc-ready').source, 'none')
check('an ML-DSA target on a key exchange is corrected the other way', resolvePqcTarget('key-exchange', 'ECDHE', 'ML-DSA-65', 'vulnerable').source, 'corrected')
const anyKemOnSignature = register.rows.flatMap((r) => r.componentList).filter((c) => (c.componentClass === 'signature' || c.componentClass === 'certificate') && /ML-?KEM/i.test(c.pqcReplacement || '') && !/ML-?DSA|SLH-?DSA/i.test(c.pqcReplacement || ''))
check('no signature or certificate component carries a KEM-only target', anyKemOnSignature.length, 0)

/* ------------------------------------------------------------------ */
console.log('[7] Totals for a subset come from the subset')
const all = summarizeRows(register.rows)
const subset = summarizeRows([row('A')])
check('estate components', all.components.total, 6)
check('subset components (NOT the estate figure)', subset.components.total, 3)
check('subset assets', subset.assets, 1)
check('subset vulnerable', subset.components.vulnerable, 2)
check('subset severity sums to its vulnerable count', subset.vulnerableSeverity.critical + subset.vulnerableSeverity.high + subset.vulnerableSeverity.medium + subset.vulnerableSeverity.low + subset.vulnerableSeverity.unrated, 2)
check('status partition covers every asset', Object.values(all.pqcStatus).reduce((a, b) => a + b, 0), 4)
check('owners: 1 assigned, 3 unassigned', all.owners, { assigned: 1, unassigned: 3 })

/* ------------------------------------------------------------------ */
console.log('[8] Reconciliation states divergence instead of hiding it')
ok('every check matches when the headline agrees', register.checks.every((c) => c.status === 'match'))
check('QR agreement', register.qr.state, 'match')
const diverged = buildAssetRegister({ snapshot: snapshot(assets, { ...headline, totalComponents: 9, vulnerableComponents: 5 }), qr: { resolved: true, hasData: true, readiness: 41, readinessLevel: 'Early Stage', risk: 57, components: 11, vulnerableComponents: 7 }, now: NOW })
check('negative control: 3 CBOM components on no asset are reported as unattributed', diverged.unattributed.components, 3)
check('…and the component check still reconciles once unattributed are counted', diverged.checks.find((c) => c.id === 'components')?.status, 'match')
check('negative control: a QR Engine that disagrees is "diverged", not substituted', diverged.qr.state, 'diverged')
const awaiting = buildAssetRegister({ snapshot: snapshot(assets, headline), qr: { resolved: false, hasData: false, readiness: null, readinessLevel: null, risk: null, components: null, vulnerableComponents: null }, now: NOW })
check('an unanswered QR Engine reads "awaiting", never "reconciled"', awaiting.qr.state, 'awaiting')

// A cached snapshot from before the API split still carries finding rows.
const legacy = buildAssetRegister({ snapshot: snapshot([assetPayload('A', 'a.example.com', A_ROWS, { legacy: true })], { totalAssets: 1, totalComponents: 3, vulnerableComponents: 2, pqcReadyComponents: 1, vulnerableAssets: 1 }), now: NOW })
check('a legacy payload is repartitioned client-side: findings are not components', legacy.rows[0].components.total <= 4 && legacy.rows[0].posture.total >= 2, true)

/* ------------------------------------------------------------------ */
console.log('[9] Live scans and lifecycle attach to the right asset')
check('B is scanning (target host match)', row('B').scanning, { active: true, progress: 45, status: 'running' })
check('A is not scanning', row('A').scanning.active, false)
check('A lifecycle uses the workflow\'s own stage label', row('A').lifecycle?.label, 'AI Remediation')
check('C has no lifecycle', row('C').lifecycle, null)

/* ------------------------------------------------------------------ */
console.log('[10] Filter and sort')
check('status filter', filterRows(register.rows, { statuses: ['pqc-ready'] }).map((r) => r.id), ['B'])
check('a linked asset limits the current view', filterRows(register.rows, { assetId: 'B' }).map((r) => r.id), ['B'])
check('a linked asset still respects the other filters', filterRows(register.rows, { assetId: 'B', freshness: ['stale'] }).map((r) => r.id), [])
check('search reaches owners', filterRows(register.rows, { query: 'platform team' }).map((r) => r.id), ['B'])
check('search reaches risk-bearing primitives', filterRows(register.rows, { query: 'RSA key transport' }).map((r) => r.id), ['A'])
check('freshness filter', filterRows(register.rows, { freshness: ['stale'] }).map((r) => r.id), ['A'])
check('risk sort: highest first, unassessed last', sortRows(register.rows, 'risk').map((r) => r.id), ['A', 'C', 'B', 'D'])
check('last-scanned sort', sortRows(register.rows, 'last-scanned').map((r) => r.id)[0], 'B')

console.log('')
if (failures.length) {
  console.log(`✗ ${failures.length} FAILED, ${passed} passed\n`)
  for (const f of failures) console.log(`  ✗ ${f}`)
  process.exit(1)
}
console.log(`✓ ASSET REGISTER HOLDS — ${passed} checks passed\n`)
