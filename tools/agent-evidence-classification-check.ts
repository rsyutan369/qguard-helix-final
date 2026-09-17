/**
 * Offline accuracy check for the SCANNER half of the agent pipeline.
 *
 * Agent evidence reaches the inventory through `scanEvidenceWithModules`, which
 * had no test at all. It substring-matched over the whole raw evidence JSON, and
 * on real evidence that produced:
 *
 *   ECDSA P-256 cert issued by "…TLS RSA SHA256…CA"  → RSA-1024 CRITICAL
 *   Ed25519 cert with subject "Mersault Ltd"          → RSA-1024 CRITICAL
 *   hybrid key exchange X25519MLKEM768                → classical X25519
 *   OpenSSH mlkem768x25519-sha256                     → classical X25519
 *   TLS_AES_256_GCM_SHA384                            → a "TLS-1.3 medium" finding
 *
 * while a separate rule wrote a quantum-SAFE row for any evidence whose JSON
 * contained "pqc" or "hybrid". This check pins the canonical classifier and the
 * profile mapping to the truth for every case, positive and negative.
 *
 * No server or database:  npx tsx tools/agent-evidence-classification-check.ts
 */
import { readFileSync } from 'node:fs'
import { analyzeCryptoObservation } from '../src/lib/crypto/suite-anatomy'
import { scanEvidenceWithModules } from '../src/lib/scanner/scanner_2/modules'
import { classifyAgentEvidence } from '../src/lib/crypto/agent-evidence-verdict'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

/* ------------------------------------------------------------------ */
console.log('\n[1] The canonical classifier names every primitive the agent emits')

const anatomyCases: Array<[string, string, string]> = [
  // hybrid key agreement — every IANA TLS group and both OpenSSH methods
  ['X25519MLKEM768', 'hybrid', 'key-exchange'],
  ['SecP256r1MLKEM768', 'hybrid', 'key-exchange'],
  ['SecP384r1MLKEM1024', 'hybrid', 'key-exchange'],
  ['mlkem768x25519-sha256', 'hybrid', 'key-exchange'],
  ['sntrup761x25519-sha512@openssh.com', 'hybrid', 'key-exchange'],
  // classical key agreement (HNDL-exposed)
  ['X25519', 'vulnerable', 'key-exchange'],
  ['ECDHE-P-256', 'vulnerable', 'key-exchange'],
  ['ecdh-sha2-nistp256', 'vulnerable', 'key-exchange'],
  ['diffie-hellman-group14-sha256', 'vulnerable', 'key-exchange'],
  // signatures
  ['RSA-3072', 'vulnerable', 'signature'],
  ['ECDSA-P521', 'vulnerable', 'signature'],
  ['ECDSA-secp256k1', 'vulnerable', 'signature'],
  ['Ed448', 'vulnerable', 'signature'],
  ['rsa-sha2-512', 'vulnerable', 'signature'],
  ['ssh-dss', 'vulnerable', 'signature'],
  ['ML-DSA-65', 'safe', 'signature'],
  ['SLH-DSA-SHA2-128S', 'safe', 'signature'],
  ['Ed25519 + ML-DSA-65', 'hybrid', 'signature'],
  // JOSE (identity)
  ['RS256', 'vulnerable', 'signature'],
  ['PS384', 'vulnerable', 'signature'],
  ['ES384', 'vulnerable', 'signature'],
  ['EdDSA', 'vulnerable', 'signature'],
  ['HS256', 'safe', 'hash'],
  // SAML signature methods as the agent names them
  ['sha256WithRSAEncryption', 'vulnerable', 'signature'],
  ['ecdsa-with-SHA256', 'vulnerable', 'signature'],
  // suites, protocols, symmetric
  ['TLS_AES_256_GCM_SHA384', 'safe', 'cipher-suite'],
  ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'vulnerable', 'cipher-suite'],
  ['TLS-1.3', 'unknown', 'protocol'],
  ['TLS-1.0', 'unknown', 'protocol'],
  ['RC4', 'vulnerable', 'symmetric'],
  ['AES-256', 'safe', 'symmetric'],
  // not cryptography in use
  ['OQS provider', 'unknown', 'policy'],
  ['Encrypted private key (algorithm not readable)', 'unknown', 'policy'],
  ['PQC_ENABLED', 'unknown', 'policy'],
]
for (const [name, quantumClass, kind] of anatomyCases) {
  const a = analyzeCryptoObservation({ algorithm: name, name }, true)
  assert(a.quantumClass === quantumClass && a.kind === kind, `${name} → ${quantumClass} ${kind}`, `got ${a.quantumClass} ${a.kind} (${a.family})`)
}

/* ------------------------------------------------------------------ */
console.log('\n[2] Evidence → inventory profile, from structured fields only')

const base = { sourceType: 'local-agent', assetName: 'host', confidence: 'high', observedAt: new Date().toISOString() }
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const profileOf = (evidence: Record<string, unknown>) => scanEvidenceWithModules([{ ...base, id: 'e1', ...evidence } as any], 'check').map((f) => f.detectedAlgorithm).join(',') || '(none)'

const profileCases: Array<[string, Record<string, unknown>, string]> = [
  ['ECDSA leaf issued by an RSA-named CA', { evidenceType: 'certificate-file', observedAlgorithm: 'ECDSA-P256', keySize: 256, rawEvidence: { issuer: 'CN=Global G2 TLS RSA SHA256 2020 CA1' } }, 'ECDSA-P256'],
  ['Ed25519 cert whose subject contains "rsa"', { evidenceType: 'tls-certificate', observedAlgorithm: 'Ed25519', keySize: 256, rawEvidence: { subject: 'CN=Mersault Ltd' } }, 'Ed25519'],
  ['P-256 curve size is not an RSA modulus', { evidenceType: 'tls-certificate', observedAlgorithm: 'ECDSA-P256', keySize: 256 }, 'ECDSA-P256'],
  ['hybrid TLS key exchange', { evidenceType: 'tls-key-exchange', observedAlgorithm: 'X25519MLKEM768' }, '(none)'],
  ['hybrid SSH key exchange', { evidenceType: 'ssh-metadata', observedAlgorithm: 'mlkem768x25519-sha256', protocol: 'SSH' }, '(none)'],
  ['classical TLS key exchange', { evidenceType: 'tls-key-exchange', observedAlgorithm: 'X25519' }, 'X25519'],
  ['classical P-384 key exchange', { evidenceType: 'tls-key-exchange', observedAlgorithm: 'ECDHE-P-384' }, 'ECC-P384'],
  ['ML-DSA-65 certificate', { evidenceType: 'certificate-file', observedAlgorithm: 'ML-DSA-65' }, '(none)'],
  ['RSA-1024 key file', { evidenceType: 'key-file', observedAlgorithm: 'RSA-1024', keySize: 1024 }, 'RSA-1024'],
  ['JWKS RS256 key', { evidenceType: 'jwt-algorithm', observedAlgorithm: 'RS256', keySize: 2048 }, 'RSA-2048'],
  ['TLS 1.3 AES-256 suite is not a "TLS-1.3 medium" finding', { evidenceType: 'tls-cipher', observedAlgorithm: 'TLS_AES_256_GCM_SHA384' }, 'AES-256'],
  ['a dependency never becomes an algorithm finding', { evidenceType: 'crypto-library', observedAlgorithm: 'node-rsa', packageName: 'node-rsa' }, '(none)'],
  ['an OQS provider mention is not ML-KEM in use', { evidenceType: 'config-reference', observedAlgorithm: 'OQS provider' }, '(none)'],
  ['an unreadable key is not a finding', { evidenceType: 'key-file', observedAlgorithm: 'Encrypted private key (algorithm not readable)' }, '(none)'],
]
for (const [label, evidence, want] of profileCases) {
  const got = profileOf(evidence)
  assert(got === want, label, `got ${got}, want ${want}`)
}

/* ------------------------------------------------------------------ */
console.log('\n[3] The agent\'s own verdict (used to validate its patches) reads composites canonically')

const verdict = (observedAlgorithm: string, extra: Record<string, unknown> = {}) =>
  classifyAgentEvidence({ evidenceType: 'config-reference', observedAlgorithm, ...extra })

assert(verdict('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256').isLegacy === true, 'a classical ECDHE-RSA suite is NOT judged quantum resistant (the knowledge base read it as AES)')
assert(verdict('rsa-sha2-512').isLegacy === true, 'rsa-sha2-512 is an RSA signature, not a SHA-2 hash')
assert(verdict('X25519MLKEM768').isPqc === true && verdict('X25519MLKEM768').isLegacy === false, 'X25519MLKEM768 is post-quantum hybrid')
assert(verdict('mlkem768x25519-sha256').isPqc === true, 'mlkem768x25519-sha256 is post-quantum hybrid')
assert(verdict('RSA-3072').isLegacy === true, 'a plain primitive still uses the knowledge base (RSA-3072 is Shor-broken)')
assert(verdict('ML-DSA-65').isPqc === true, 'ML-DSA-65 is post-quantum')

/* ------------------------------------------------------------------ */
console.log('\n[4] The inventory writer has one quantum verdict, from the evidence that produced the finding')

const scannerSrc = readFileSync('src/api-server/agent-scanner.ts', 'utf8')
assert(!/function isPqcReadyEvidence/.test(scannerSrc), 'the substring "pqc/hybrid anywhere in the JSON" rule is gone')
assert(/is_quantum_safe: verdict\.quantumSafe/.test(scannerSrc), 'is_quantum_safe comes from the canonical verdict (no profile is ever "safe")')
assert(!/is_quantum_safe: finding\.threatLevel === 'safe'/.test(scannerSrc), 'the always-false threatLevel test is gone')
assert(/if \(verdict\.vulnerable\) \{/.test(scannerSrc), 'quantum exposures are written only for vulnerable primitives')
assert(/item\.id && item\.id === finding\.target\.id/.test(scannerSrc), 'a finding is matched to ITS evidence by id, not to the first evidence on the host')
assert(/'certificate-file'\) && item\.certificateFingerprint/.test(scannerSrc), 'certificates read from disk materialise into the certificates inventory')

const agentSrc = readFileSync('tools/qguard-agent/agent.ts', 'utf8')
assert(/async function scanTlsKeyExchange/.test(agentSrc), 'the agent measures the TLS key-exchange group')
assert(/if \(hybridUntestable\) return \[\]/.test(agentSrc), 'an untestable hybrid probe publishes nothing rather than "classical only"')
assert(/async function scanCryptoMaterialFile/.test(agentSrc) && /function keyEvidenceFromPem/.test(agentSrc), 'the agent collects certificate files and key metadata')
assert(/keyMaterialTransmitted: false/.test(agentSrc) && !/export\(\{ type: 'pkcs8'/.test(agentSrc), 'key collection never exports private key material')
assert(/async function scanIdentityFile/.test(agentSrc), 'the agent collects JWKS and SAML identity signing material')
assert(/if \(remediationFilePathFromJob\(job\)\) return 'local_configuration'/.test(agentSrc), 'a job naming a local file patches locally, whatever words its path contains')

const bundle = readFileSync('tools/qguard-agent/dist/qguard-agent.cjs', 'utf8')
assert(/scanTlsKeyExchange/.test(bundle) && /scanCryptoMaterialFile/.test(bundle) && /scanIdentityFile/.test(bundle), 'the PUBLISHED bundle contains the new collectors')

/* ------------------------------------------------------------------ */
console.log(`\n${failures === 0 ? 'PASS' : `FAIL (${failures})`} — agent evidence classification\n`)
process.exitCode = failures === 0 ? 0 : 1
