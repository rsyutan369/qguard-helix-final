/**
 * Offline accuracy check for the agent remediation pipeline.
 *
 * It answers the question a code read cannot: given the evidence the agent
 * actually collects, does the Collector classify it correctly, does the Patcher
 * write the mandatory stack, and does the Validator let a SUCCESSFUL
 * remediation through instead of rolling it back?
 *
 * Every case here is a defect that was live in the pipeline. The first block is
 * the one that mattered most: the agent scored its own post-patch success
 * attestation as a CRITICAL protocol downgrade, because the classifier ran
 * substring regexes over the stringified record and the attestation embeds
 * MANDATORY_PQC_STACK (which contains "ML-DSA-65", "classicalFallback" and
 * "oqs-openssl"). Validation therefore failed and the correct configuration was
 * automatically rolled back to its vulnerable state.
 *
 * Run: npx tsx tools/agent-remediation-check.ts
 */

import { classifyAgentEvidence } from '../src/lib/crypto/agent-evidence-verdict'
import {
  MANDATORY_PQC_STACK,
  MANDATORY_PQC_CONFIG_VALUES,
  mandatoryPqcStackMetadata,
  matchesMandatoryConfigValue,
} from '../src/lib/crypto/mandatory-pqc-stack'

let passed = 0
let failed = 0
const failures: string[] = []

function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  if (ok) {
    passed += 1
  } else {
    failed += 1
    failures.push(`${label}\n      expected ${JSON.stringify(expected)}\n      actual   ${JSON.stringify(actual)}`)
  }
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`)
}

function section(title: string) {
  console.log(`\n${title}\n${'-'.repeat(title.length)}`)
}

/* ── 1. The self-rollback defect ────────────────────────────────────────── */

section('1. Post-patch success attestation must validate as SAFE')

/* Byte-identical to positiveConfigValidationEvidence() in tools/qguard-agent/agent.ts. */
const attestation = {
  evidenceType: 'config-reference',
  assetName: 'web-01',
  assetType: 'network_protocol',
  filePath: '/etc/ssh/sshd_config',
  observedAlgorithm: 'No active HNDL crypto reference detected',
  rawEvidence: {
    remediationValidation: true,
    hndlRisk: false,
    validationMethod: 'authorized local config rescan',
    redacted: true,
    mandatoryPqcStack: MANDATORY_PQC_STACK,
    cryptographicStack: mandatoryPqcStackMetadata('ML-KEM-768', 'network_protocol tls upgrade'),
  },
}

const attested = classifyAgentEvidence(attestation)
check('attestation is not flagged as a protocol downgrade', attested.downgradeDetected, false)
check('attestation is not flagged as legacy cryptography', attested.isLegacy, false)
check('attestation carries no residual HNDL risk', attested.hndlRisk, false)
check('attestation severity is safe (was: critical)', attested.severity, 'safe')
console.log(`        rationale: ${attested.rationale}`)

/* The exact gate agent.ts applies: validationFromEvidence() counts a record as
   remaining risk when hndlRisk || downgradeDetected || (isLegacy && high/critical). */
function remainsRisky(v: ReturnType<typeof classifyAgentEvidence>) {
  return v.hndlRisk || v.downgradeDetected || (v.isLegacy && (v.severity === 'critical' || v.severity === 'high'))
}
check('validation gate passes, so no rollback is triggered', remainsRisky(attested), false)

/* ── 2. NIST post-quantum standards must not read as legacy ─────────────── */

section('2. FIPS 203/204/205 primitives classified correctly')

const pqCases: Array<[string, Record<string, unknown>, { isPqc: boolean; isLegacy: boolean; severity: string }]> = [
  ['ML-DSA-65 certificate (FIPS 204)', { evidenceType: 'tls-certificate', observedAlgorithm: 'ML-DSA-65', host: 'web-01' }, { isPqc: true, isLegacy: false, severity: 'safe' }],
  ['ML-KEM-768 key exchange (FIPS 203)', { evidenceType: 'tls-protocol', observedAlgorithm: 'ML-KEM-768', host: 'web-01' }, { isPqc: true, isLegacy: false, severity: 'safe' }],
  ['SLH-DSA-SHA2-128s (FIPS 205)', { evidenceType: 'tls-certificate', observedAlgorithm: 'SLH-DSA-SHA2-128s', host: 'web-01' }, { isPqc: true, isLegacy: false, severity: 'safe' }],
  ['X25519MLKEM768 hybrid group', { evidenceType: 'tls-protocol', observedAlgorithm: 'X25519MLKEM768', host: 'web-01' }, { isPqc: true, isLegacy: false, severity: 'safe' }],
  ['AES-256-GCM bulk cipher', { evidenceType: 'tls-cipher', observedAlgorithm: 'AES-256-GCM', host: 'web-01' }, { isPqc: false, isLegacy: false, severity: 'safe' }],
]

for (const [label, evidence, expect] of pqCases) {
  const v = classifyAgentEvidence(evidence as never)
  check(`${label}: isPqc`, v.isPqc, expect.isPqc)
  check(`${label}: isLegacy`, v.isLegacy, expect.isLegacy)
  check(`${label}: severity`, v.severity, expect.severity)
}

/* ── 3. Genuine risk must still be reported ─────────────────────────────── */

section('3. Genuinely vulnerable cryptography is still escalated')

const rsa = classifyAgentEvidence({ evidenceType: 'tls-certificate', observedAlgorithm: 'RSA-2048', host: 'web-01', keySize: 2048 })
check('RSA-2048 on a network target is legacy', rsa.isLegacy, true)
check('RSA-2048 on a network target carries HNDL risk', rsa.hndlRisk, true)
check('RSA-2048 on a network target is critical', rsa.severity, 'critical')

const rsa1024 = classifyAgentEvidence({ evidenceType: 'tls-certificate', observedAlgorithm: 'RSA-1024', host: 'web-01', keySize: 1024 })
check('RSA-1024 undersized modulus is critical', rsa1024.severity, 'critical')

const tls10 = classifyAgentEvidence({ evidenceType: 'tls-protocol', observedAlgorithm: 'TLS 1.0', host: 'web-01' })
check('TLS 1.0 is a real downgrade', tls10.downgradeDetected, true)
check('TLS 1.0 is critical', tls10.severity, 'critical')

const sha1 = classifyAgentEvidence({ evidenceType: 'tls-certificate', observedAlgorithm: 'SHA-1', host: 'web-01' })
check('SHA-1 is legacy', sha1.isLegacy, true)

/* ── 4. Records that name no primitive must not be scored as one ────────── */

section('4. Library rows and finding titles are not algorithms')

const openssl = classifyAgentEvidence({ evidenceType: 'crypto-library', observedAlgorithm: 'OpenSSL 3.5', packageName: 'openssl', host: 'web-01' })
check('OpenSSL library row is not a protocol downgrade', openssl.downgradeDetected, false)
check('OpenSSL library row is not legacy cryptography', openssl.isLegacy, false)
check('OpenSSL library row is not critical (was: critical)', openssl.severity, 'moderate')

const tls13 = classifyAgentEvidence({ evidenceType: 'tls-protocol', observedAlgorithm: 'TLS 1.3', host: 'web-01' })
check('TLS 1.3 is not a downgrade', tls13.downgradeDetected, false)

/* ── 5. Elliptic-curve key sizes are not undersized moduli ──────────────── */

section('5. A 256-bit EC key is the recommended size, not a weakness')

const p256 = classifyAgentEvidence({ evidenceType: 'tls-certificate', observedAlgorithm: 'ECDSA-P256', keySize: 256, host: 'web-01' })
check('ECDSA P-256 is quantum-vulnerable (correct)', p256.isLegacy, true)
check('ECDSA P-256 rationale does not claim an undersized modulus', /modulus/.test(p256.rationale), false)

const ed = classifyAgentEvidence({ evidenceType: 'tls-certificate', observedAlgorithm: 'Ed25519', keySize: 256 })
check('Ed25519 off-network is high, not critical', ed.severity, 'high')

/* ── 6. The Patcher writes the mandatory stack ──────────────────────────── */

section('6. Patcher target values match the mandatory PQC stack')

check('TLS groups are the hybrid ML-KEM group', MANDATORY_PQC_CONFIG_VALUES.tlsGroups, 'X25519MLKEM768:X25519')
const patchedGroups = classifyAgentEvidence({ evidenceType: 'tls-protocol', observedAlgorithm: 'X25519MLKEM768', host: 'web-01' })
check('the value the Patcher writes re-reads as post-quantum', patchedGroups.isPqc, true)
check('the value the Patcher writes does not re-read as risk', remainsRisky(patchedGroups), false)

const patchedSig = classifyAgentEvidence({ evidenceType: 'tls-certificate', observedAlgorithm: MANDATORY_PQC_STACK.signatures.primary, host: 'web-01' })
check(`mandatory signature ${MANDATORY_PQC_STACK.signatures.primary} re-reads as post-quantum`, patchedSig.isPqc, true)
check('mandatory signature does not re-read as risk', remainsRisky(patchedSig), false)

/* ── 7. The full loop: patch -> rescan -> validate ──────────────────────── */

section('7. A successfully patched file must re-read as remediated')

/*
 * The lines the Patcher writes, paired with the algorithm the config detector
 * records for them. Every one of these was previously reduced to its CLASSICAL
 * half, because the X25519 and Ed25519 rules were ordered ahead of the PQC
 * rules and the detector stops at the first match.
 */
const patchedLines: Array<[string, string, string]> = [
  ['TLS_GROUPS=' + MANDATORY_PQC_CONFIG_VALUES.tlsGroups, 'X25519MLKEM768', 'hybrid TLS group'],
  ['KEM_ALGORITHM=' + MANDATORY_PQC_CONFIG_VALUES.kemAlgorithm, 'ML-KEM-768', 'PQC KEM'],
  ['SIGNATURE_ALGORITHM=' + MANDATORY_PQC_CONFIG_VALUES.signatureAlgorithm, 'Ed25519 + ML-DSA-65', 'hybrid signature'],
  ['SYMMETRIC_CIPHER=' + MANDATORY_PQC_CONFIG_VALUES.symmetricCipher, 'AES-256', 'bulk cipher'],
  ['ssl_ecdh_curve ' + MANDATORY_PQC_CONFIG_VALUES.tlsGroups + ';', 'X25519MLKEM768', 'nginx curve'],
  ['KexAlgorithms ' + MANDATORY_PQC_CONFIG_VALUES.sshKexAlgorithms, 'X25519MLKEM768', 'SSH kex'],
  ['HostKeyAlgorithms ' + MANDATORY_PQC_CONFIG_VALUES.sshHostKeyAlgorithms, 'RSA-2048', 'SSH host key (accepted residual)'],
]

let remainingRisk = 0
for (const [line, detected, what] of patchedLines) {
  const conformant = matchesMandatoryConfigValue(line)
  const verdict = classifyAgentEvidence({
    evidenceType: 'config-reference',
    observedAlgorithm: detected,
    rawEvidence: conformant ? { policyConformant: true, policyKey: conformant.key } : {},
  })
  /* The exact gate validationFromEvidence() applies, policy-conformant rows first. */
  const counts = conformant ? false : remainsRisky(verdict)
  if (counts) remainingRisk += 1
  check(`${what}: patched value does not fail validation`, counts, false)
}
check('riskCount after a successful patch is zero, so no rollback fires', remainingRisk, 0)

section('8. A FAILED patch must still fail validation')

/* If the patch did not land, the old values are still there and must be caught. */
const unpatched: Array<[string, string]> = [
  ['TLS_GROUPS=X25519', 'X25519'],
  ['ssl_protocols TLSv1.0;', 'TLS-1.0'],
  ['HostKeyAlgorithms ssh-rsa', 'RSA-2048'],
]
for (const [line, detected] of unpatched) {
  const conformant = matchesMandatoryConfigValue(line)
  check(`unpatched "${line}" is not mistaken for the approved value`, conformant, null)
  const verdict = classifyAgentEvidence({ evidenceType: 'config-reference', observedAlgorithm: detected, host: 'web-01' })
  check(`unpatched "${line}" still counts as remaining risk`, remainsRisky(verdict), true)
}

section('9. SSH directives receive SSH syntax, not TLS group syntax')

check('SSH KexAlgorithms is not the TLS group list', MANDATORY_PQC_CONFIG_VALUES.sshKexAlgorithms === MANDATORY_PQC_CONFIG_VALUES.tlsGroups, false)
check('SSH KexAlgorithms names an OpenSSH hybrid kex', /mlkem768x25519-sha256|sntrup761x25519/.test(MANDATORY_PQC_CONFIG_VALUES.sshKexAlgorithms), true)
check('SSH KexAlgorithms is comma-separated, not colon-separated', MANDATORY_PQC_CONFIG_VALUES.sshKexAlgorithms.includes(':'), false)
check('the SSH host-key residual is stated, not hidden', MANDATORY_PQC_STACK.ssh.hostKeyResidual.length > 40, true)

/* ── Summary ────────────────────────────────────────────────────────────── */

console.log(`\n${'='.repeat(72)}`)
console.log(`agent remediation check: ${passed} passed, ${failed} failed`)
if (failed) {
  console.log('\nFailures:')
  for (const item of failures) console.log(`  - ${item}`)
  process.exit(1)
}
console.log('All assertions passed.')
