/**
 * Root-cause classifier checks.
 *
 * The regression this guards: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` was
 * filed under `weak-key-exchange` because the classifier substring-matched
 * `dhe` and `ecdh`, publishing a forward-secret suite as "No ephemeral key
 * exchange". Every case below is a real string this tenant's scanner produced.
 *
 *   npx tsx tools/crypto-root-cause-check.ts
 */
import {
  classifyCryptoRootCause,
  isClassicalKeyExchange,
  isWeakKeyExchange,
  rootCauseHaystack,
} from '../src/lib/crypto-root-cause'

let passed = 0
const failures: string[] = []

function check(name: string, actual: unknown, expected: unknown) {
  if (actual === expected) {
    passed += 1
    return
  }
  failures.push(`${name}\n     expected: ${JSON.stringify(expected)}\n     actual:   ${JSON.stringify(actual)}`)
}

function ruleFor(input: Parameters<typeof classifyCryptoRootCause>[0]) {
  return classifyCryptoRootCause(input)?.ruleId ?? null
}

/* ── Ephemeral suites are NOT weak key exchange ──────────────────────────── */

const EPHEMERAL_OBSERVATIONS = [
  {
    algorithm: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    category: 'algorithm',
    description: "ECDHE + ECDSA — both ECC-based, fully breakable by Shor's algorithm",
  },
  {
    algorithm: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    category: 'algorithm',
    description: 'ECDHE key exchange + RSA auth — quantum-vulnerable key exchange and certificate',
  },
  {
    algorithm: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    category: 'algorithm',
    description: 'ECDHE key exchange + RSA auth — both components quantum-vulnerable',
  },
  {
    algorithm: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305',
    category: 'Cipher Suite',
    description: 'Forward-secret AEAD suite with classical ECDHE key agreement',
  },
  {
    algorithm: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    category: 'Cipher Suite',
    description: 'Ephemeral finite-field Diffie-Hellman key agreement',
  },
]

for (const observation of EPHEMERAL_OBSERVATIONS) {
  const haystack = rootCauseHaystack(observation)
  check(`${observation.algorithm} is not weak key exchange`, isWeakKeyExchange(haystack), false)
  check(`${observation.algorithm} is classical key exchange`, isClassicalKeyExchange(haystack), true)
  check(`${observation.algorithm} rule`, ruleFor(observation), 'classical-key-exchange')

  // The load-bearing assertion: whatever bucket it lands in must never claim
  // the suite has no ephemeral key exchange.
  const description = classifyCryptoRootCause(observation)?.description ?? ''
  check(
    `${observation.algorithm} description does not deny forward secrecy`,
    /no ephemeral|no forward secrecy/i.test(description),
    false,
  )
}

/* ── Static RSA key transport IS weak key exchange ───────────────────────── */

const STATIC_RSA_OBSERVATIONS = [
  {
    algorithm: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    category: 'algorithm',
    description: "RSA key exchange — no forward secrecy + quantum-vulnerable via Shor's algorithm",
  },
  {
    algorithm: 'TLS_RSA_WITH_AES_256_CBC_SHA',
    category: 'algorithm',
    description: 'RSA key exchange with CBC mode — quantum-vulnerable + legacy MAC',
  },
  {
    algorithm: 'TLS_RSA_WITH_AES_128_CBC_SHA',
    category: 'algorithm',
    description: 'RSA key exchange with CBC mode and SHA-1 MAC — multiple vulnerabilities',
  },
]

for (const observation of STATIC_RSA_OBSERVATIONS) {
  check(`${observation.algorithm} is weak key exchange`, isWeakKeyExchange(rootCauseHaystack(observation)), true)
  check(`${observation.algorithm} rule`, ruleFor(observation), 'weak-key-exchange')
}

// Static RSA wins even when an ephemeral suite is named in the same text: an
// attacker negotiates the weakest path the endpoint accepts, not the best one.
check(
  'mixed offer keeps the weak verdict',
  ruleFor({
    algorithm: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
    description: 'Endpoint also offers TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, but static RSA is accepted',
  }),
  'weak-key-exchange',
)

check(
  'explicit no-forward-secrecy verdict',
  ruleFor({ title: 'No Forward Secrecy', description: 'No ephemeral key exchange was offered by this endpoint' }),
  'weak-key-exchange',
)

check(
  'anonymous DH is weak',
  ruleFor({ algorithm: 'TLS_DH_anon_WITH_AES_128_CBC_SHA', description: 'Anonymous Diffie-Hellman' }),
  'weak-key-exchange',
)

/* ── Hybrid / PQC is not a key-exchange root cause at all ────────────────── */

check(
  'hybrid X25519MLKEM768 is not a key-exchange defect',
  ruleFor({ algorithm: 'X25519MLKEM768', category: 'Key Exchange', description: 'Hybrid post-quantum key agreement negotiated (ML-KEM-768)' }),
  null,
)
check(
  'ML-KEM-768 is not a key-exchange defect',
  ruleFor({ algorithm: 'ML-KEM-768', description: 'FIPS 203 key encapsulation in use' }),
  null,
)

/* ── Substring traps in the other buckets ────────────────────────────────── */

// "OpenSSL 3.5+" appears in remediation text across the platform. A bare `ssl`
// match filed those findings as legacy-protocol evidence.
check(
  'OpenSSL in remediation text is not a legacy protocol finding',
  ruleFor({
    algorithm: 'ECDSA P-256',
    category: 'Certificate',
    description: 'Certificate uses ECDSA P-256',
    recommendation: 'Upgrade the origin crypto library (e.g. OpenSSL 3.5+) and deploy an ML-KEM hybrid key exchange',
  }),
  'certificate-risk',
)
check('SSLv3 is still caught', ruleFor({ description: 'Endpoint negotiated SSLv3' }), 'legacy-tls-protocol')
check('TLS 1.0 is still caught', ruleFor({ description: 'TLS 1.0 is supported by the endpoint' }), 'legacy-tls-protocol')

// A bare `des` match fired on "described"/"designed" in analyst prose.
check(
  '"described" is not a DES cipher finding',
  ruleFor({ algorithm: 'AES-256-GCM', category: 'Symmetric Encryption', description: 'Symmetric encryption as described in the policy baseline is compliant' }),
  null,
)
check('3DES is still caught', ruleFor({ algorithm: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', description: '3DES cipher' }), 'weak-key-exchange')
check('bare CBC suite is caught', ruleFor({ algorithm: 'AES-128-CBC', category: 'Symmetric Encryption', description: 'CBC mode without AEAD' }), 'weak-cipher-suite')

/* ── Stable rule ids (downstream fingerprints depend on them) ────────────── */

check('weak-key-exchange id is stable', classifyCryptoRootCause({ algorithm: 'TLS_RSA_WITH_AES_128_GCM_SHA256' })?.ruleId, 'weak-key-exchange')
check('certificate id is stable', classifyCryptoRootCause({ description: 'certificate expiring' })?.ruleId, 'certificate-risk')

/* ── Report ──────────────────────────────────────────────────────────────── */

if (failures.length) {
  console.error(`\n✗ ${failures.length} failed, ${passed} passed\n`)
  for (const failure of failures) console.error(`  ✗ ${failure}\n`)
  process.exit(1)
}
console.log(`✓ crypto-root-cause: ${passed} checks passed`)
