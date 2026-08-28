/**
 * CBOM component integrity — a component is CRYPTOGRAPHY, not a finding.
 *
 *     npx tsx tools/cbom-component-integrity-check.ts
 *
 * `crypto_inventory` is written by three producers, and one of them stores a
 * FINDING in the same shape as a cryptographic component: `scanner.ts` sets
 * `algorithm: finding.algorithm` for EVERY rule it fires, so policy rules land
 * as rows with algorithm "No Certificate Pinning" or "Regulatory Compliance
 * Gap". They are also written `is_vulnerable: true`.
 *
 * Counting them as components inflated BOTH sides of the quantum-vulnerable
 * ratio that drives the readiness score, the risk score, remediation,
 * certification and every report. A measured tenant published
 *
 *     "178 cryptographic components, 160 quantum-vulnerable"   (90%)
 *
 * where the cryptography itself was 77 components / 59 vulnerable (77%).
 *
 * Nothing is lost by excluding them: `persistResult` writes the same finding to
 * `pqc_scan_results` and `crypto_exposures`, which is what Risk Analysis and
 * Vulnerabilities read. This suite pins BOTH directions — findings must be
 * excluded, and real cryptography must never be.
 */
import { isCryptographicComponent, namesCryptography, observationClass } from '../src/lib/scanner/finding-identity'
import { algorithmFamily } from '../src/lib/governance/subjects'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

const isCrypto = (row: Record<string, unknown>) => isCryptographicComponent(row, algorithmFamily)

/* ------------------------------------------------------------------ */
console.log('\n[1] Real cryptography is ALWAYS counted')

/** Every row shape the three producers actually write. */
const CRYPTO_ROWS: Array<[string, Record<string, unknown>]> = [
  ['web scanner — cipher suite', { name: 'Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA', algorithm: 'TLS_RSA_WITH_AES_128_CBC_SHA', item_type: 'algorithm' }],
  ['web scanner — ECDHE suite', { name: 'Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', algorithm: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', item_type: 'algorithm' }],
  ['web scanner — protocol', { name: 'Protocol: TLSv1.2', algorithm: 'TLSV1.2', item_type: 'protocol' }],
  ['web scanner — protocol 1.3', { name: 'Protocol: TLSv1.3', algorithm: 'TLSV1.3', item_type: 'protocol' }],
  ['web scanner — X.509 signature', { name: 'Certificate Signature: sha256WithRSAEncryption', algorithm: 'sha256WithRSAEncryption', item_type: 'certificate' }],
  ['web scanner — key exchange', { name: 'Key Exchange: ECDHE-P256', algorithm: 'ECDHE-P256', item_type: 'key-exchange' }],
  ['web scanner — hash', { name: 'Hash: SHA-256', algorithm: 'SHA-256', item_type: 'hash' }],
  ['agent — key_exchange (underscore)', { name: 'key_exchange: RSA-2048', algorithm: 'RSA-2048', item_type: 'key-exchange' }],
  ['agent — ssh host key', { name: 'ssh: ssh-ed25519', algorithm: 'ssh-ed25519', item_type: 'algorithm' }],
  ['agent — PQC-ready row', { name: 'PQC-ready: ML-KEM-768', algorithm: 'ML-KEM-768', item_type: 'algorithm' }],
  ['agent — hybrid group', { name: 'library: openssl', algorithm: 'X25519MLKEM768', item_type: 'library' }],
  ['certificate with no algorithm yet', { name: 'Certificate: leaf', algorithm: '', item_type: 'certificate' }],
  ['legacy symmetric', { name: 'Symmetric Encryption: 3DES', algorithm: '3DES', item_type: 'algorithm' }],
  ['KDF', { name: 'KDF: HKDF-SHA256', algorithm: 'HKDF-SHA256', item_type: 'kdf' }],
]
for (const [label, row] of CRYPTO_ROWS) assert(isCrypto(row), `counted: ${label}`, String(row.algorithm || row.name))

/* ------------------------------------------------------------------ */
console.log('\n[2] Scanner findings are NEVER counted as components')

/** Verbatim from the reported tenant's algorithm distribution. */
const FINDING_ROWS: Array<[string, Record<string, unknown>]> = [
  ['No Certificate Pinning', { name: 'certificate-risk: No Certificate Pinning', algorithm: 'No Certificate Pinning', item_type: 'certificate' }],
  ['Information Disclosure', { name: 'info-risk: Information Disclosure', algorithm: 'Information Disclosure', item_type: 'algorithm' }],
  ['Regulatory Compliance Gap', { name: 'compliance-risk: Regulatory Compliance Gap', algorithm: 'Regulatory Compliance Gap', item_type: 'algorithm' }],
  ['Quantum-Vulnerable OIDs', { name: 'certificate-risk: Quantum-Vulnerable OIDs', algorithm: 'Quantum-Vulnerable OIDs', item_type: 'certificate' }],
  ['No PQC Certificate', { name: 'certificate-risk: No PQC Certificate', algorithm: 'No PQC Certificate', item_type: 'certificate' }],
  ['No OCSP Stapling', { name: 'transport-risk: No OCSP Stapling', algorithm: 'No OCSP Stapling', item_type: 'protocol' }],
  ['Missing HSTS header', { name: 'header-risk: Missing HSTS Header', algorithm: 'Missing HSTS Header', item_type: 'algorithm' }],
  ['No certificate transparency', { name: 'certificate-risk: No Certificate Transparency', algorithm: 'No Certificate Transparency', item_type: 'certificate' }],
]
for (const [label, row] of FINDING_ROWS) assert(!isCrypto(row), `excluded: ${label}`)

/* ------------------------------------------------------------------ */
console.log('\n[3] The agent collector\'s underscore prefix is understood')
assert(observationClass('key_exchange: RSA-2048') === 'key exchange', 'key_exchange normalises to "key exchange"', observationClass('key_exchange: RSA-2048'))
assert(namesCryptography('key_exchange: RSA-2048'), 'so an agent-collected key exchange names cryptography')
assert(namesCryptography('Key Exchange: RSA-2048'), 'and the web scanner spelling still does')
assert(!namesCryptography('certificate-risk: No Certificate Pinning'), 'a finding category still does not')

/* ------------------------------------------------------------------ */
console.log('\n[4] The reported tenant reconciles')

/* 178 rows: 77 cryptography, 101 findings — the exact split measured live. */
const TENANT_ROWS: Record<string, unknown>[] = []
const add = (row: Record<string, unknown>, n: number) => { for (let i = 0; i < n; i += 1) TENANT_ROWS.push({ ...row, id: `r-${TENANT_ROWS.length}` }) }
add({ name: 'Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA', algorithm: 'TLS_RSA_WITH_AES_128_CBC_SHA', is_vulnerable: true }, 24)
add({ name: 'Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', algorithm: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', is_vulnerable: true }, 20)
add({ name: 'Certificate Signature: sha256WithRSAEncryption', algorithm: 'sha256WithRSAEncryption', is_vulnerable: true }, 15)
add({ name: 'Protocol: TLSv1.2', algorithm: 'TLSV1.2', is_vulnerable: false }, 10)
add({ name: 'Protocol: TLSv1.3', algorithm: 'TLSV1.3', is_vulnerable: false }, 8)
add({ name: 'certificate-risk: No Certificate Pinning', algorithm: 'No Certificate Pinning', is_vulnerable: true }, 40)
add({ name: 'compliance-risk: Regulatory Compliance Gap', algorithm: 'Regulatory Compliance Gap', is_vulnerable: true }, 35)
add({ name: 'transport-risk: No OCSP Stapling', algorithm: 'No OCSP Stapling', is_vulnerable: true }, 26)

const components = TENANT_ROWS.filter(isCrypto)
const findings = TENANT_ROWS.filter((r) => !isCrypto(r))
const vulnComponents = components.filter((r) => r.is_vulnerable === true).length
const vulnAllRows = TENANT_ROWS.filter((r) => r.is_vulnerable === true).length

assert(TENANT_ROWS.length === 178, 'the fixture is the reported 178 rows', `${TENANT_ROWS.length}`)
assert(components.length === 77, 'exactly 77 are cryptographic components', `${components.length}`)
assert(findings.length === 101, 'exactly 101 are scanner findings', `${findings.length}`)
assert(components.length + findings.length === TENANT_ROWS.length, 'the split reconciles to the row total — nothing is dropped')
assert(vulnAllRows === 160, 'counting every row reproduces the old inflated 160', `${vulnAllRows}`)
assert(vulnComponents === 59, 'counting only cryptography gives 59 vulnerable components', `${vulnComponents}`)

const oldPct = Math.round((vulnAllRows / TENANT_ROWS.length) * 100)
const newPct = Math.round((vulnComponents / components.length) * 100)
assert(oldPct === 90, 'the old ratio was 90% vulnerable', `${oldPct}%`)
assert(newPct === 77, 'the corrected ratio is 77% vulnerable', `${newPct}%`)
assert(newPct < oldPct, 'excluding findings LOWERS the vulnerable share — the score was pessimistic, not optimistic')

/* ------------------------------------------------------------------ */
console.log('\n[5] Absence of evidence is never treated as cryptography')
assert(!isCrypto({ name: '', algorithm: '', item_type: '' }), 'an empty row is not a component')
assert(!isCrypto({ name: 'unknown', algorithm: 'unknown', item_type: 'algorithm' }), 'a literal "unknown" is not a component')
assert(!isCrypto({ name: 'note: reviewed manually', algorithm: 'reviewed manually', item_type: 'algorithm' }), 'free text is not a component')

console.log(
  failures === 0
    ? '\n✓ CBOM COMPONENT INTEGRITY HOLDS — components are cryptography, findings are findings\n'
    : `\n${failures} CHECK(S) FAILED ✗\n`,
)
process.exit(failures === 0 ? 0 : 1)
