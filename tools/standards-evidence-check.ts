import assert from 'node:assert/strict'
import serviceRecords from '../src/api-server/service-records'
import { matchesCnsa2Primitive } from '../src/lib/encryption/strength'
import { isUnverifiedIssuanceRecord } from '../src/lib/crypto/issuance-evidence'
import { deadlineFor } from '../src/lib/estate/clusters'

// The unavailable handler must stop before any provider or persistence call.
// Invoke it in isolation; the production routes retain their auth middleware.
const routes = serviceRecords.stack as unknown as Array<{
  route?: { path: string; methods: { post?: boolean }; stack: Array<{ handle: (...args: any[]) => unknown }> }
}>
for (const [path, body] of [
  ['/keys', { algorithm: 'ML-KEM', rotatedFrom: 'old-key' }],
  ['/pki', { common_name: 'fixture.invalid' }],
  ['/qrng/generate/stream', { action: 'key' }],
  ['/qrng/generate/stream', { action: 'GENERATE-KEY' }],
  ['/qrng/generate/stream', { action: 'pki' }],
  ['/qrng/generate/stream', { action: 'generate-pki' }],
] as const) {
  const route = routes.find((entry) => entry.route?.path === path && entry.route.methods.post)?.route
  assert.equal(route?.stack.length, 2, `Expected auth and handler on POST ${path}`)
  let status: number | undefined
  let payload: unknown
  const response = { status(code: number) { status = code; return this }, json(value: unknown) { payload = value; return this } }
  await route!.stack[1].handle({ body }, response)
  assert.equal(status, 503)
  assert.deepEqual(Object.keys(payload as object), ['error'])
  assert.equal((payload as { error: { code: string } }).error.code, 'CRYPTO_ISSUANCE_UNAVAILABLE')
}

assert.equal(isUnverifiedIssuanceRecord({ algorithm: 'ML-KEM', entropy_source: 'QRNG', quality_score: '0.99200' }), true)
assert.equal(isUnverifiedIssuanceRecord({ algorithm: 'PKI-ML-DSA-65' }), true)
assert.equal(isUnverifiedIssuanceRecord({ algorithm: 'ML-KEM-1024', entropy_source: 'CSPRNG' }), false)
assert.equal(matchesCnsa2Primitive('ChaCha20-Poly1305', 'symmetric'), false)
assert.equal(matchesCnsa2Primitive('SHA3-512', 'hash'), false)
assert.equal(matchesCnsa2Primitive('HMAC-SHA-512', 'mac'), false)
assert.equal(matchesCnsa2Primitive('SHA-512/256', 'hash'), false)
assert.equal(matchesCnsa2Primitive('AES-256-GCM', 'symmetric'), true)
assert.equal(matchesCnsa2Primitive('SHA-512', 'hash'), true)
assert.equal(deadlineFor([{ algorithm: 'ECDSA', classical: false }]).year, 2030)
assert.equal(deadlineFor([{ algorithm: 'SM2', classical: false }]).year, null)
assert.equal(deadlineFor([{ algorithm: 'SHA-1', classical: true }]).year, 0)
console.log('PASS issuance stops without evidence, legacy markers are recognized, and algorithm observations do not overstate standards scope')
