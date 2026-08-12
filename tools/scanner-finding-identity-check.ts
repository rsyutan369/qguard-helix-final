/**
 * Scanner finding identity + CBOM/Assets presentation — offline invariant check.
 *
 * Exercises the PURE modules (no Supabase / server required) behind the numbers
 * `/dashboard/cbom` and `/dashboard/assets` render, and pins the defects that
 * were found live on a real two-asset tenant:
 *
 *   1. The four STORAGE VIEWS of one observation collapse to one finding.
 *      (`totalFindings` read 255 for 66 real observations because the merge key
 *      started with `source` — the one field guaranteed to differ between them.)
 *   2. Genuinely different observations still stay separate — the merge must not
 *      buy its lower count by discarding evidence.
 *   3. Narrative text survives a merge: the strongest-severity copy is often the
 *      terse one.
 *   4. CBOM component figures PARTITION the estate (ready + in-progress +
 *      not-ready == total), and at-risk is a SUBSET, never a fourth slice added
 *      to a findings count.
 *   5. The algorithm distribution's denominator is the whole measured
 *      population, not the top-N slice sum.
 *   6. Policy/configuration observations are not charted as algorithms.
 *
 * Run: npx tsx tools/scanner-finding-identity-check.ts
 */

import {
  dedupeGradedObservations,
  findingIdentityKey,
  namesCryptography,
  findingSubject,
  normalizeFindingSubject,
  richerText,
} from '../src/lib/scanner/finding-identity'
import { riskBandFor, riskScoreFromLoad } from '../src/lib/migration/asset-intelligence'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

/* ------------------------------------------------------------------ */
/* 1. Subject normalization                                            */
/* ------------------------------------------------------------------ */
console.log('\n1. Subject normalization — every location shape the writers emit')

assert(normalizeFindingSubject('www.cloudflare.com') === 'www.cloudflare.com', 'bare hostname')
assert(normalizeFindingSubject('https://www.cloudflare.com/') === 'www.cloudflare.com', 'URL with scheme and trailing slash')
assert(normalizeFindingSubject('Cipher Suite — https://www.cloudflare.com/') === 'www.cloudflare.com', '"<label> — <url>" session form')
assert(normalizeFindingSubject('Certificate — tls-v1-2.badssl.com') === 'tls-v1-2.badssl.com', '"<label> — <host>" session form')
assert(normalizeFindingSubject('tls-v1-2.badssl.com:443') === 'tls-v1-2.badssl.com', 'port stripped')
assert(normalizeFindingSubject('10.4.2.9') === '10.4.2.9', 'IPv4 target')
// NEGATIVE controls — these carry no target and must not masquerade as one.
assert(normalizeFindingSubject('Detection Rule TLS-008') === '', 'rule id is NOT a subject')
assert(normalizeFindingSubject('Mapped scanner asset') === '', 'placeholder location is NOT a subject')
assert(normalizeFindingSubject('') === '', 'empty location')

assert(
  findingSubject({ location: 'Detection Rule TLS-008', scanTarget: 'https://www.cloudflare.com/' }) === 'www.cloudflare.com',
  'subject-less location falls back to the scan target',
)
assert(
  findingSubject({ location: 'Detection Rule TLS-008', scanTarget: '' }) === 'detection rule tls-008',
  'with no scan target either, the raw location is kept rather than collapsing every rule together',
)

/* ------------------------------------------------------------------ */
/* 2. One observation, four storage views                              */
/* ------------------------------------------------------------------ */
console.log('\n2. Storage views of ONE observation share an identity')

// Verbatim shapes captured from the live tenant.
const oneCipherSuite = [
  { algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', category: 'rsa', location: 'www.cloudflare.com', detectionMethod: 'cipher-enum', source: 'crypto_exposures', scanTarget: 'https://www.cloudflare.com/' },
  { algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', category: 'Cipher Suite', location: 'www.cloudflare.com', detectionMethod: 'cipher-enum', source: 'pqc_scan_results', scanTarget: 'https://www.cloudflare.com/' },
  { algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', category: 'algorithm', location: 'www.cloudflare.com', detectionMethod: 'cipher-enum', source: 'web-scanner', scanTarget: 'https://www.cloudflare.com/' },
  { algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', category: 'Cipher Suite', location: 'Cipher Suite — https://www.cloudflare.com/', detectionMethod: 'cipher-enum', source: 'web-scanner', scanTarget: 'https://www.cloudflare.com/' },
]
const cipherKeys = new Set(oneCipherSuite.map(findingIdentityKey))
assert(cipherKeys.size === 1, 'four storage views of one cipher suite → one key', `got ${cipherKeys.size}`)

const oneRule = [
  { algorithm: 'Deprecated SSL/TLS Version', category: 'Rule (Tls Config)', location: 'Detection Rule TLS-008', detectionMethod: 'risk-calculation', source: 'web-scanner', scanTarget: 'tls-v1-2.badssl.com' },
  { algorithm: 'Deprecated SSL/TLS Version', category: 'protocol', location: 'tls-v1-2.badssl.com', detectionMethod: 'risk-calculation', source: 'crypto_exposures', scanTarget: 'tls-v1-2.badssl.com' },
]
assert(new Set(oneRule.map(findingIdentityKey)).size === 1, 'a rule finding and its asset copy → one key')

// A detection method that is really a table name must not split the group.
assert(
  findingIdentityKey({ algorithm: 'RSA-2048', location: 'a.example.com', detectionMethod: 'crypto_exposures' }) ===
    findingIdentityKey({ algorithm: 'RSA-2048', location: 'a.example.com', detectionMethod: 'scanner-evidence' }),
  'storage-name detection methods are neutralised',
)

/* ------------------------------------------------------------------ */
/* 3. NEGATIVE controls — the merge must not over-collapse             */
/* ------------------------------------------------------------------ */
console.log('\n3. Distinct observations stay distinct')

const distinct = [
  { algorithm: 'RSA-2048', location: 'a.example.com', detectionMethod: 'cert-analysis' },
  { algorithm: 'RSA-2048', location: 'b.example.com', detectionMethod: 'cert-analysis' },   // different host
  { algorithm: 'RSA-2048', location: 'a.example.com', detectionMethod: 'cipher-enum' },     // different measurement
  { algorithm: 'ECDSA-P256', location: 'a.example.com', detectionMethod: 'cert-analysis' }, // different algorithm
]
assert(new Set(distinct.map(findingIdentityKey)).size === 4, 'host / method / algorithm each remain discriminating')

assert(
  findingIdentityKey({ algorithm: 'Quantum-Vulnerable OIDs', location: 'Detection Rule CERT-008', scanTarget: 'a.example.com', detectionMethod: 'risk-calculation' }) !==
    findingIdentityKey({ algorithm: 'Quantum-Vulnerable OIDs', location: 'Detection Rule CERT-008', scanTarget: 'b.example.com', detectionMethod: 'risk-calculation' }),
  'the SAME rule on two different assets stays two findings',
)

/* ------------------------------------------------------------------ */
/* 4. Narrative preservation                                           */
/* ------------------------------------------------------------------ */
console.log('\n4. Merging keeps the informative text')

assert(
  richerText('Stored scanner result', "ECDHE + ECDSA — both ECC-based, breakable by Shor's algorithm") ===
    "ECDHE + ECDSA — both ECC-based, breakable by Shor's algorithm",
  'analyst text beats a placeholder',
)
assert(
  richerText("ECDHE + ECDSA — both ECC-based, breakable by Shor's algorithm", 'Stored scanner result') ===
    "ECDHE + ECDSA — both ECC-based, breakable by Shor's algorithm",
  'placeholder never overwrites analyst text (order independent)',
)
assert(richerText('', 'Short but real') === 'Short but real', 'empty loses to real text')
assert(richerText('Short', 'A considerably longer explanation') === 'A considerably longer explanation', 'longer of two real strings wins')

/* ------------------------------------------------------------------ */
/* 5. CBOM component partition + at-risk scope                         */
/* ------------------------------------------------------------------ */
console.log('\n5. CBOM component figures partition the estate')

// Mirrors the derivation in CbomExplorer.tsx.
function cbomFigures(stats: { totalComponents: number; pqcReadyComponents: number; quantumVulnerableComponents: number }) {
  const totalComponents = stats.totalComponents
  const pqcReady = stats.pqcReadyComponents
  const notPqcReady = stats.quantumVulnerableComponents
  const inProgress = Math.max(0, totalComponents - pqcReady - notPqcReady)
  return { totalComponents, pqcReady, notPqcReady, inProgress }
}

for (const stats of [
  { totalComponents: 66, pqcReadyComponents: 4, quantumVulnerableComponents: 62 }, // the live tenant
  { totalComponents: 40, pqcReadyComponents: 10, quantumVulnerableComponents: 12 }, // with in-progress rows
  { totalComponents: 0, pqcReadyComponents: 0, quantumVulnerableComponents: 0 },    // empty estate
]) {
  const f = cbomFigures(stats)
  assert(
    f.pqcReady + f.inProgress + f.notPqcReady === f.totalComponents,
    `partition holds for ${stats.totalComponents} components`,
    `${f.pqcReady}+${f.inProgress}+${f.notPqcReady}`,
  )
}

// At-risk is a component count and a SUBSET of not-PQC-ready. The regression it
// guards: `atRisk = vulnerableComponents + criticalFindings` reported 100 on a
// 66-component estate, which the legend then rendered as "At Risk 100%".
const entries = [
  { isVulnerable: true, riskSeverity: 'critical' },
  { isVulnerable: true, riskSeverity: 'high' },
  { isVulnerable: true, riskSeverity: 'moderate' },
  { isVulnerable: true, riskSeverity: 'low' },
  { isVulnerable: false, riskSeverity: 'safe' },
]
const rank = (s: string) => (s.includes('critical') ? 4 : s.includes('high') ? 3 : s.includes('medium') || s.includes('moderate') ? 2 : s.includes('low') ? 1 : 2)
const atRiskComponents = entries.filter((e) => e.isVulnerable && rank(e.riskSeverity) >= 2).length
assert(atRiskComponents === 3, 'at-risk counts vulnerable components graded Medium+', String(atRiskComponents))
assert(atRiskComponents <= entries.length, 'at-risk can never exceed the component universe')
assert(atRiskComponents <= entries.filter((e) => e.isVulnerable).length, 'at-risk is a subset of not-PQC-ready')

/* ------------------------------------------------------------------ */
/* 6. Algorithm distribution denominator + posture split               */
/* ------------------------------------------------------------------ */
console.log('\n6. Algorithm distribution')

// Real component labels from the live tenant.
assert(namesCryptography('Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA'), 'cipher suite is cryptography')
assert(namesCryptography('Key Exchange (Harvest Now Decrypt Later): X25519MLKEM768'), 'parenthesised qualifier is stripped')
assert(namesCryptography('Certificate Signature: ecdsa-with-SHA256 (Signature)'), 'certificate signature is cryptography')
assert(!namesCryptography('Rule (Certificate Risk): No Certificate Pinning'), 'rule row is NOT an algorithm')
assert(!namesCryptography('API Security: Information Disclosure'), 'API posture row is NOT an algorithm')
assert(!namesCryptography('NIST Compliance: Grade C'), 'compliance grade is NOT an algorithm')
assert(!namesCryptography('Certificate Revocation: No OCSP Stapling'), 'revocation posture is NOT an algorithm')
assert(!namesCryptography('Something The Scanner Adds Later: X'), 'unknown class defaults to posture, never to algorithm')

function buildAlgorithmDistribution(rows: Array<{ algorithm: string; instances?: number }>, limit = 6) {
  const grouped = new Map<string, number>()
  let total = 0
  rows.forEach((row) => {
    const count = Number(row.instances || 1)
    total += count
    grouped.set(row.algorithm, (grouped.get(row.algorithm) || 0) + count)
  })
  const ranked = Array.from(grouped, ([algorithm, count]) => ({ algorithm, count })).sort((a, b) => b.count - a.count)
  const top = ranked.slice(0, limit)
  const remainder = total - top.reduce((sum, item) => sum + item.count, 0)
  const slices = remainder > 0 ? [...top, { algorithm: `Other (${ranked.length - top.length} more)`, count: remainder }] : top
  return { slices, total, distinct: ranked.length }
}

const algorithmRows = Array.from({ length: 22 }, (_, i) => ({ algorithm: `ALG-${i}`, instances: i < 6 ? 2 : 1 }))
const dist = buildAlgorithmDistribution(algorithmRows)
const sliceSum = dist.slices.reduce((sum, s) => sum + s.count, 0)
assert(dist.total === 28, 'denominator is the whole measured population', String(dist.total))
assert(sliceSum === dist.total, 'slices account for every instance (remainder becomes an explicit "Other")', `${sliceSum} vs ${dist.total}`)
assert(dist.distinct === 22, 'distinct algorithm count is reported alongside the chart')
assert(dist.slices.length === 7, 'top 6 plus one "Other" slice')

// The regression: percentages computed against the top-N sum instead of the
// whole population made 2 of 66 read as 16.7%.
const topOnlySum = dist.slices.slice(0, 6).reduce((sum, s) => sum + s.count, 0)
assert(topOnlySum !== dist.total, 'top-N sum is NOT the denominator', `${topOnlySum} vs ${dist.total}`)

/* ------------------------------------------------------------------ */
/* 7. Migration Sandbox — graded observations counted ONCE              */
/* ------------------------------------------------------------------ */
console.log('\n7. Migration Sandbox graded observations')

// One cipher suite as the three tables the sandbox reads store it. Summing
// their severity counts (the old behaviour) reported 3; it is 1 observation.
const sandboxRows = [
  { algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', subject: 'www.cloudflare.com', detectionMethod: '', severity: 'critical' },              // crypto_exposures
  { algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', subject: 'www.cloudflare.com', detectionMethod: 'cipher-enum', severity: 'high' },       // pqc_scan_results
  { algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', subject: 'www.cloudflare.com', detectionMethod: 'crypto_exposures', severity: 'high' },  // scanner_alerts
  { algorithm: 'RSA-2048', subject: 'tls-v1-2.badssl.com', detectionMethod: 'cert-analysis', severity: 'high' },
  { algorithm: 'RSA-2048', subject: 'www.cloudflare.com', detectionMethod: 'cert-analysis', severity: 'medium' },
]
const graded = dedupeGradedObservations(sandboxRows)
assert(graded.total === 3, 'five rows across three tables → three observations', String(graded.total))
assert(graded.critical === 1, 'strongest severity wins the merge', `${graded.critical} critical`)
assert(graded.critical + graded.high + graded.medium + graded.low === graded.total, 'severity buckets partition the observations')
// The regression: naive summation.
const naiveCritical = sandboxRows.filter((r) => r.severity === 'critical').length
const naiveHigh = sandboxRows.filter((r) => r.severity === 'high').length
assert(naiveCritical + naiveHigh > graded.critical + graded.high, 'naive per-table summation over-counts', `${naiveCritical + naiveHigh} vs ${graded.critical + graded.high}`)
assert(dedupeGradedObservations([]).total === 0, 'empty tenant → zero observations, not NaN')

/* ------------------------------------------------------------------ */
/* 8. Risk score direction + scale                                     */
/* ------------------------------------------------------------------ */
console.log('\n8. Quantum risk direction and banding')

// The Migration Sandbox published `100 - (critical*15 + high*8 + …)` under the
// name `riskScore`: a higher-is-better POSTURE measure with a risk name, which
// saturated to 0 for any real estate and contradicted the QR Engine's 75/High
// for the same tenant.
const oldPosture = (critical: number, high: number) => Math.max(0, Math.min(100, 100 - (critical * 15 + high * 8)))
assert(oldPosture(7, 0) === 0 && oldPosture(22, 50) === 0, 'the OLD formula saturates — 7 criticals and 22 criticals both read 0')
assert(oldPosture(0, 0) === 100, 'the OLD formula was higher-is-better despite its name')

const derivedRisk = (critical: number, high: number, medium: number) =>
  riskScoreFromLoad(critical * 3 + high * 1.2 + medium * 0.4)
assert(derivedRisk(0, 0, 0) === 0, 'a clean estate is 0 risk (lower is better)')
assert(derivedRisk(13, 30, 11) > derivedRisk(2, 4, 1), 'more exposure means MORE risk, not less')
assert(derivedRisk(13, 30, 11) < 100, 'a real estate does not peg the scale', String(derivedRisk(13, 30, 11)))
// Strictly increasing and never saturating - the property the old linear
// penalty lacked, which is why 7 criticals and 22 criticals both read 0.
// Must still discriminate across the whole plausible enterprise range — the
// property the old linear penalty lacked, which is why 7 criticals and 22
// criticals both read 0.
assert(derivedRisk(50, 100, 50) < 100, 'a very large estate still discriminates', String(derivedRisk(50, 100, 50)))
assert(derivedRisk(60, 0, 0) > derivedRisk(30, 0, 0) && derivedRisk(120, 0, 0) > derivedRisk(60, 0, 0), 'strictly increasing at every magnitude')
// Bands come from the shared table, never a local ladder.
assert(riskBandFor(75).label === 'High', 'banding is delegated to RISK_BANDS', riskBandFor(75).label)
assert(riskBandFor(0).label === 'Minimal' && riskBandFor(85).label === 'Critical', 'band ends resolve correctly')

/* ------------------------------------------------------------------ */
/* 9. Sandbox simulation seeding + PQC target resolved by USAGE         */
/* ------------------------------------------------------------------ */
console.log('\n9. Simulation seeding picks real cryptography')

// A live sandbox run produced "[DRY RUN] tls-v1-2.badssl.com (No CAA Issuance
// Policy → ML-KEM-768)": the first vulnerable inventory row happened to be a
// DNS policy finding, and it was handed a key-encapsulation mechanism.
const inventoryRows = [
  { name: 'DNS Security: No CAA Issuance Policy', algorithm: 'No CAA Issuance Policy', is_vulnerable: true },
  { name: 'Rule (Tls Config): Deprecated SSL/TLS Version', algorithm: 'Deprecated SSL/TLS Version', is_vulnerable: true },
  { name: 'Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA', algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA', is_vulnerable: true },
]
const seedRow = inventoryRows.find((r) => namesCryptography(r.name) && r.algorithm)
assert(seedRow?.algorithm === 'TLS_RSA_WITH_AES_256_CBC_SHA', 'seeding skips policy rows for the first real algorithm', String(seedRow?.algorithm))
assert(!namesCryptography('DNS Security: No CAA Issuance Policy'), 'a DNS policy row is NOT a source algorithm')
assert(inventoryRows.filter((r) => namesCryptography(r.name)).length === 1, 'only one of three vulnerable rows names cryptography')

// FIPS 203 is key establishment ONLY; authentication takes FIPS 204/205.
// Mirrors pqcAlgoRec in src/api-server/sandbox.ts.
const pqcTarget = (from: string, context = '') => {
  const v = `${from} ${context}`.toLowerCase()
  if (v.includes('sha1') || v.includes('sha-1') || v.includes('md5') || v.includes('hash')) return 'SHA3-256'
  if (v.includes('ecdsa') || v.includes('dsa') || v.includes('sign') || v.includes('certificate')) return 'ML-DSA-65'
  if (v.includes('ecdh') || v.includes('x25519') || v.includes('dh')) return 'X25519 + ML-KEM-768 hybrid'
  if (v.includes('rsa') || v.includes('key exchange') || v.includes('cipher suite') || v.includes('tls')) return 'ML-KEM-768'
  if (v.includes('aes-128') || v.includes('3des') || v.includes('rc4') || v.includes('des')) return 'AES-256-GCM'
  return 'PQC target pending classification'
}
assert(pqcTarget('TLS_RSA_WITH_AES_256_CBC_SHA', 'cipher suite') === 'ML-KEM-768', 'key establishment → FIPS 203')
assert(pqcTarget('ECDSA P-256 (Certificate)', 'certificate tls_endpoint') === 'ML-DSA-65', 'a certificate on a TLS asset takes FIPS 204, NOT a KEM')
assert(pqcTarget('sha256WithRSAEncryption (Signature)', 'certificate signature') === 'ML-DSA-65', 'signatures never resolve to ML-KEM')
assert(pqcTarget('ECDHE prime256v1', 'key exchange') === 'X25519 + ML-KEM-768 hybrid', 'ECDHE → hybrid key agreement')
assert(!/ML-KEM/.test(pqcTarget('No CAA Issuance Policy', 'dns security')), 'an unclassifiable source is NOT handed a KEM', pqcTarget('No CAA Issuance Policy', 'dns security'))

/* ------------------------------------------------------------------ */
console.log(`\n${failures === 0 ? '✓ ALL CHECKS PASSED' : `✗ ${failures} CHECK(S) FAILED`}\n`)
process.exit(failures === 0 ? 0 : 1)
