/**
 * Checks for the QGuard Messaging → Helix evidence derivation (messenger
 * roadmap 10.1): what each device's published suite becomes, and how Helix's
 * own anatomy parser grades it. Run: `npm run check:messaging-posture`.
 */
import { analyzeCryptoObservation } from '../src/lib/crypto/suite-anatomy'
import {
  MESSAGING_EVIDENCE_TYPE,
  messagingDeviceEvidence,
  messagingKeyEstablishment,
  messagingSignature,
} from '../src/lib/messaging-posture-evidence'

let failures = 0
let total = 0
function check(name: string, condition: boolean, detail?: unknown) {
  total += 1
  if (!condition) failures += 1
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${name}${condition || detail === undefined ? '' : `  → ${JSON.stringify(detail)}`}`)
}

const CURRENT = {
  classical_kex: 'X25519', pq_kem: 'ML-KEM-1024', pq_kem_standard: 'FIPS-203', kem_combiner: 'QGuard-HybridKEM-v2',
  classical_signature: 'Ed25519', pq_signature: 'ML-DSA-65', symmetric: 'AES-256-GCM', kdf: 'HKDF-SHA3-256',
}
const PRE_FIPS = { ...CURRENT, pq_kem_standard: undefined, kem_combiner: undefined }
const NOW = '2026-10-20T00:00:00.000Z'

// Key establishment.
check('FIPS 203 device → hybrid X25519 + ML-KEM-1024', messagingKeyEstablishment(CURRENT).algorithm === 'X25519 + ML-KEM-1024')
const legacy = messagingKeyEstablishment(PRE_FIPS)
check('NEG pre-FIPS Kyber device is NOT reported as post-quantum', legacy.algorithm === 'X25519' && Boolean(legacy.note), legacy)
check('NEG device with no PQ KEM → classical', messagingKeyEstablishment({ classical_kex: 'X25519' }).algorithm === 'X25519')
check('signature pair is named as a hybrid', messagingSignature(CURRENT) === 'Ed25519 + ML-DSA-65')

// Helix's own parser agrees with the grading.
const hybridKex = analyzeCryptoObservation({ algorithm: 'X25519 + ML-KEM-1024', name: 'X25519 + ML-KEM-1024', protocol: 'qguard-messaging' }, true)
check('Helix parser: hybrid key establishment is hybrid', hybridKex.quantumClass === 'hybrid', hybridKex)
const hybridSig = analyzeCryptoObservation({ algorithm: 'Ed25519 + ML-DSA-65', name: 'Ed25519 + ML-DSA-65', protocol: 'qguard-messaging' }, true)
check('Helix parser: hybrid signature is hybrid (not overstated as pure PQ)', hybridSig.quantumClass === 'hybrid', hybridSig)
const classicalKex = analyzeCryptoObservation({ algorithm: 'X25519', name: 'X25519', protocol: 'qguard-messaging' }, true)
check('NEG Helix parser: a pre-FIPS device is graded vulnerable', classicalKex.quantumClass === 'vulnerable', classicalKex)

// Device selection and shape.
const rows = messagingDeviceEvidence([
  { id: 'dev-1', device_label: 'Laptop', suite: CURRENT, trust_state: 'this_device', revoked_at: null },
  { id: 'dev-2', device_label: 'Old phone', suite: PRE_FIPS, trust_state: 'trusted', revoked_at: null },
  { id: 'dev-3', device_label: 'Revoked', suite: CURRENT, trust_state: 'revoked', revoked_at: null },
  { id: 'dev-4', device_label: 'Retired', suite: CURRENT, trust_state: 'trusted', revoked_at: '2026-10-01T00:00:00.000Z' },
], NOW)
check('NEG revoked and retired devices are left out', !rows.some((row) => /Revoked|Retired/.test(row.assetName)))
check('four primitives per active device', rows.filter((row) => row.target === 'qguard-messaging:device:dev-1').length === 4)
check('every row is a messaging evidence row with a target', rows.every((row) => row.evidenceType === MESSAGING_EVIDENCE_TYPE && row.target.startsWith('qguard-messaging:device:')))
check('the old phone is reported with its classical grade', rows.some((row) => row.assetName.includes('Old phone') && row.observedAlgorithm === 'X25519'))
const leaked = JSON.stringify(rows)
check('NEG nothing but suite metadata is exported', !/plaintext|message|contact|conversation/i.test(leaked.replace(/message-encryption/g, '')))
check('an empty account yields nothing', messagingDeviceEvidence([], NOW).length === 0)

console.log(`\n${total - failures}/${total} passed`)
if (failures > 0) process.exit(1)
