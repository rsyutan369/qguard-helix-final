/**
 * Offline verification for Migration Snapshot Management™.
 *
 * Exercises the security-critical pure logic without a DB:
 *  - crypto-state capture pulls real algorithms/TLS/certs/keys from evidence rows
 *  - the SHA3-256 integrity hash is deterministic (stable across key order)
 *  - ANY tamper with the captured state changes the hash (restore is gated on
 *    recomputing this same hash, so a modified snapshot cannot be restored)
 *  - size accounting is real (bytes of the canonical payload)
 *
 * No server / Supabase required:  npx tsx tools/snapshot-check.ts
 */
import { canonicalize, deriveCryptoState, hashState } from '../src/api-server/migration-snapshots'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

const inventory = [
  { algorithm: 'RSA-2048', key_size: 2048, protocol: 'TLS 1.2', item_type: 'TLS Cipher Suite', is_quantum_safe: false, exposure_level: 'critical' },
  { algorithm: 'ECDH-P256', key_size: 256, protocol: 'TLS 1.2', item_type: 'Key Exchange', is_quantum_safe: false, exposure_level: 'high' },
  { algorithm: 'AES-128-CBC', key_size: 128, protocol: '', item_type: 'Symmetric', is_quantum_safe: false, exposure_level: 'medium' },
]
const certs = [
  { name: 'api.customer.com', algorithm: 'RSA-2048', key_size: 2048, issuer: 'Internal CA', not_after: '2026-12-31T00:00:00Z' },
  { name: 'gateway.customer.com', algorithm: 'ECDSA-P256', key_size: 256, issuer: 'Internal CA', not_after: '2027-06-30T00:00:00Z' },
]
const keys = [
  { algorithm: 'RSA', bit_length: 4096, status: 'active' },
  { algorithm: 'Ed25519', bit_length: 256, status: 'active' },
]
const jobMeta = { fromAlgo: 'RSA-2048', filePath: '/etc/nginx/conf', configurationVersion: 'v3', tlsGroup: 'secp256r1' }

console.log('\n[1] Crypto-state capture (real evidence → snapshot state)')
const state = deriveCryptoState(inventory, certs, keys, jobMeta, 'asset-web-01')
assert(state.algorithms.includes('RSA-2048') && state.algorithms.includes('ECDSA-P256'), 'captures inventory + certificate algorithms', `${state.algorithms.length} algos`)
assert(state.tls.version === 'TLS 1.2' && state.tls.group === 'secp256r1', 'captures TLS version + group')
assert(state.tls.cipherSuites.includes('RSA-2048') && state.tls.cipherSuites.includes('ECDH-P256'), 'captures TLS cipher/KEX suites')
assert(state.certificates.length === 2 && state.certificates[0].notAfter === '2026-12-31T00:00:00Z', 'captures certificate metadata (name/algo/expiry)')
assert(state.keys.length === 2 && state.pki.issuers.includes('Internal CA'), 'captures keys + PKI issuers')
assert(state.configuration.paths.includes('/etc/nginx/conf'), 'captures configuration paths from job metadata')
assert(state.componentCount === inventory.length + certs.length + keys.length, 'component count = inventory + certs + keys', `${state.componentCount}`)

console.log('\n[2] SHA3-256 integrity — deterministic + key-order stable')
const h1 = hashState(state)
const h2 = hashState(JSON.parse(JSON.stringify(state)))
assert(h1.hash === h2.hash && h1.hash.length === 64, 'same state → same 64-hex hash', h1.hash.slice(0, 16) + '…')
// Key order must not matter (canonical sorted-key JSON).
const reordered = { componentCount: state.componentCount, keys: state.keys, algorithms: state.algorithms, certificates: state.certificates, tls: state.tls, pki: state.pki, configuration: state.configuration }
assert(canonicalize(reordered) === canonicalize(state), 'canonical form is key-order independent')
assert(h1.bytes > 0, 'size accounting is real (canonical byte length)', `${h1.bytes} bytes`)

console.log('\n[3] Tamper detection — the restore integrity gate')
const tamperCases = [
  ['algorithm swap', { ...state, algorithms: [...state.algorithms, 'ML-KEM-768'] }],
  ['cert expiry edit', { ...state, certificates: state.certificates.map((c, i) => (i === 0 ? { ...c, notAfter: '2099-01-01T00:00:00Z' } : c)) }],
  ['tls downgrade', { ...state, tls: { ...state.tls, version: 'TLS 1.0' } }],
  ['component count', { ...state, componentCount: state.componentCount + 1 }],
] as const
for (const [label, mutated] of tamperCases) {
  assert(hashState(mutated as typeof state).hash !== h1.hash, `tampering "${label}" breaks the integrity hash → restore blocked`)
}

console.log('\n[4] Empty asset (no evidence) — honest empty state')
const empty = deriveCryptoState([], [], [], {}, null)
assert(empty.algorithms.length === 0 && empty.certificates.length === 0 && empty.componentCount === 0, 'no evidence → empty captured state (no fabrication)')
assert(hashState(empty).hash.length === 64, 'empty state still hashes deterministically')

console.log(`\n${failures === 0 ? 'ALL SNAPSHOT CHECKS PASSED ✓' : `${failures} CHECK(S) FAILED ✗`}\n`)
process.exit(failures === 0 ? 0 : 1)
