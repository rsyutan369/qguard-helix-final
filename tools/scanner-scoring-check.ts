/**
 * Dashboard Scanner — scoring, labelling and colour accuracy.
 *
 *   npx tsx tools/scanner-scoring-check.ts
 *
 * Offline and deterministic: every input below is a synthetic evidence bundle,
 * so this runs without a network, a database or a live target.
 *
 * WHAT IT PINS, AND WHY EACH ASSERTION EARNED ITS PLACE
 * ----------------------------------------------------
 * A live hybrid endpoint (www.cloudflare.com, negotiating X25519MLKEM768) was
 * reported as "Transport & Ciphers · Critical 39", "Certificates & Keys ·
 * Critical 25" and "Quantum Posture · Critical 32" under a composite of 71
 * ("C+ · Fair"). Four independent defects produced that, and each has both a
 * POSITIVE control (the fix works) and a NEGATIVE control (it did not become a
 * blanket pass) below:
 *
 *  1. The measured key agreement never reached the scoring model. `calculateRiskScore`
 *     was called without the edge bundle, so the published categories fell back to
 *     `tlsResult.keyExchange` — the literal string "ECDHE (TLS 1.3 key_share)"
 *     that Node reports for EVERY TLS 1.3 handshake — and scored a hybrid
 *     endpoint as classical three separate times over.
 *  2. The hero cards ran a SECOND scoring model (a severity mean over findings)
 *     while the gauge ran the published weighted one, so one scan published two
 *     incompatible verdicts.
 *  3. One certificate produced five HIGH findings for two facts, because every
 *     parsed OID was emitted alongside the dedicated key and signature findings
 *     that already reported it.
 *  4. ML-KEM (FIPS 203) was recommended as the replacement for certificate keys.
 *     ML-KEM cannot sign; following that advice yields a certificate that cannot
 *     authenticate.
 *
 * The negative controls are the important half. A "fix" that simply stopped
 * penalising things would satisfy every positive assertion here and be far worse
 * than the bug.
 */

import { analyzeCipherSuites } from '../src/lib/scanner/web-scanner/cipher-suite-analyzer'
import { leafRestatedOids } from '../src/lib/scanner/web-scanner/certificate-parser'
import {
  measuredKeyAgreement,
  UNPROBED_KEY_AGREEMENT,
  type EdgeIntelligence,
} from '../src/lib/scanner/web-scanner/edge-intelligence-model'
import { OID_DATABASE, pqcReplacementFor } from '../src/lib/scanner/web-scanner/oid-database'
import { buildPublishedCategories, publishedPostureScore } from '../src/lib/scanner/web-scanner/published-scoring'
import { DETECTION_RULES } from '../src/lib/scanner/web-scanner/detection-rules'
import { scoreToGrade } from '../src/lib/scanner/public-scan/grading-model'
import {
  PQ_SENSITIVE_CATEGORY_KEYS,
  SCANNER_NODE_CATEGORIES,
  scoreNodesFromCategories,
  type ScoreComponent,
} from '../src/app/dashboard/scanner_dashboard/_intel'
import type { CertificateInfo, TlsAnalysisResult } from '../src/lib/scanner/web-scanner/types'

let failures = 0
function assert(condition: boolean, label: string) {
  if (condition) {
    console.log(`  ok   ${label}`)
  } else {
    failures += 1
    console.log(`  FAIL ${label}`)
  }
}
function section(title: string) {
  console.log(`\n=== ${title} ===`)
}

/* ─────────────────────────────────────────────────────────── fixtures ────── */

/**
 * The socket's view of a TLS 1.3 handshake, verbatim.
 *
 * `keyExchange` is the generic label and `negotiatedCurve` is null because
 * `getEphemeralKeyInfo()` returns `{}` for TLS 1.3. This fixture is the whole
 * point: it is IDENTICAL for a classical endpoint and a hybrid one, so anything
 * that reads a PQ verdict out of it is guessing.
 */
const TLS13: TlsAnalysisResult = {
  tlsVersion: 'TLSv1.3',
  cipherSuite: 'TLS_AES_256_GCM_SHA384',
  keyExchange: 'ECDHE (TLS 1.3 key_share)',
  negotiatedCurve: null,
  ephemeralKeyType: null,
  ephemeralKeySize: null,
  signatureAlgorithm: 'ecdsa_secp256r1_sha256',
  supportedProtocols: ['TLSv1.2', 'TLSv1.3'],
  cipherSuites: [],
} as unknown as TlsAnalysisResult

/** The same handshake, on an endpoint that also still accepts static-RSA key transport. */
const TLS13_WITH_STATIC_RSA: TlsAnalysisResult = {
  ...TLS13,
  cipherSuites: [
    { name: 'TLS_RSA_WITH_AES_256_GCM_SHA384', standardName: 'TLS_RSA_WITH_AES_256_GCM_SHA384', category: 'rsa-kex', keyExchange: 'RSA', quantumVulnerable: true },
    { name: 'TLS_AES_256_GCM_SHA384', standardName: 'TLS_AES_256_GCM_SHA384', category: 'tls13', keyExchange: 'ECDHE/DHE (negotiated)', quantumVulnerable: true },
  ],
} as unknown as TlsAnalysisResult

const CERT: CertificateInfo = {
  subject: { CN: 'www.example.com' },
  issuer: { CN: 'Example CA' },
  publicKeyAlgorithm: 'ECDSA P-256',
  publicKeySize: 256,
  signatureAlgorithm: 'ecdsa-with-SHA256',
  signatureOid: '1.2.840.10045.4.3.2',
  publicKeyOid: '1.2.840.10045.2.1',
  publicKeyCurveOid: '1.2.840.10045.3.1.7',
  validFrom: new Date(Date.now() - 18 * 86400000).toISOString(),
  validTo: new Date(Date.now() + 72 * 86400000).toISOString(),
  serialNumber: '01',
  fingerprint: 'aa:bb',
  isExpired: false,
  isSelfSigned: false,
  chain: [],
  detectedOids: [],
} as unknown as CertificateInfo

/**
 * Build an edge bundle. `mode` selects the three states that must stay
 * distinguishable: a measured hybrid accept, a measured refusal, and no probe at
 * all. Collapsing the last two is the failure the honesty contract forbids.
 */
function edge(mode: 'hybrid' | 'refused' | 'unprobed'): EdgeIntelligence {
  const probed = mode !== 'unprobed'
  const hybrid = mode === 'hybrid'
  return {
    host: 'www.example.com',
    port: 443,
    probedAt: new Date().toISOString(),
    durationMs: 4200,
    confidence: 92,
    notes: [],
    pqKeyAgreement: {
      value: hybrid ? 'Applied' : probed ? 'Not offered' : 'Not probed',
      state: hybrid ? 'pass' : probed ? 'fail' : 'unknown',
      detail: '',
      evidence: [],
      hybridGroups: hybrid ? ['X25519MLKEM768'] : [],
      pureKemGroups: [],
      classicalGroups: hybrid ? [] : ['X25519'],
      primaryGroup: hybrid ? 'X25519MLKEM768' : null,
      kemParameterSets: hybrid ? ['ML-KEM-768'] : [],
      classicalComponent: hybrid ? 'X25519 (Curve25519 ECDHE)' : null,
      postQuantumComponent: hybrid ? 'ML-KEM-768 (FIPS 203)' : null,
      probed,
      hybridProbed: probed,
      handshakes: probed ? 9 : 0,
      inconclusiveGroups: [],
      unstableGroups: [],
      untestableGroups: [],
      confidence: probed ? 96 : 0,
    },
    transport: {
      negotiatedProtocol: 'TLSv1.3',
      supportedProtocols: ['TLSv1.2', 'TLSv1.3'],
      legacyProtocols: [],
      negotiatedCipher: 'TLS_AES_256_GCM_SHA384',
      keyExchange: 'ECDHE (TLS 1.3 key_share)',
      forwardSecrecy: true,
      forwardSecrecyBasis: '',
      staticRsaAccepted: false,
      alpn: 'h2',
      alpnOffered: ['h2', 'http/1.1'],
      http2: true,
      alpnProbed: true,
      sessionTickets: true,
      sessionReuse: true,
      handshakeMs: 40,
      error: null,
    },
    certificate: {
      probed: true,
      ocspStapled: false,
      ocspResponderState: 'reachable',
      ocspResponderDetail: null,
      ocspUri: 'http://ocsp.example.com',
      mustStaple: false,
      crlDistributionPoints: [],
      sctPresent: true,
      sctCount: 2,
      subjectAltNames: ['www.example.com'],
      sanCount: 1,
      isWildcard: false,
      chainDepth: 3,
      chainTrusted: true,
      trustError: null,
      hostnameMatches: true,
      daysRemaining: 72,
      validityDays: 90,
      error: null,
    },
    dns: {
      probed: true,
      addresses: ['203.0.113.10'],
      addressCount: 1,
      caaQueryable: true,
      caaPresent: true,
      caaRecords: ['0 issue "example-ca.com"'],
      caaSource: 'dns',
      caaAtName: 'example.com',
      caaClimbComplete: true,
      dnssecQueryable: true,
      dnssecSigned: false,
      dnssecValidated: false,
      spf: null,
      dmarc: null,
      transports: ['udp'],
      resolvedVia: 'system',
      error: null,
    },
    http: {
      probed: true,
      reachable: true,
      statusCode: 200,
      httpVersion: 'h2',
      hsts: {
        present: true,
        status: 'enforced',
        raw: 'max-age=31536000; includeSubDomains',
        maxAge: 31536000,
        includeSubDomains: true,
        preload: false,
        preloadEligible: false,
        preloadBlockers: [],
      },
      headers: [],
      hardenedCount: 0,
      applicableCount: 0,
      fingerprint: { server: null, poweredBy: null, cdn: null, waf: null, cloudProvider: null, reverseProxy: null, signals: [] },
      error: null,
    },
    quantum: {
      hybridObserved: hybrid,
      pqSignatureObserved: false,
      keyExchange: hybrid ? 'X25519MLKEM768' : 'X25519',
      keyExchangeClass: hybrid ? 'hybrid' : 'classical',
      forwardSecrecy: 'Yes',
      kemParameterSets: hybrid ? ['ML-KEM-768'] : [],
      postQuantumReadiness: hybrid ? 81 : 20,
      readinessReasons: [],
      quantumRisk: hybrid ? 'Low' : 'High',
      quantumRiskScore: hybrid ? 20 : 80,
      riskFactors: [],
      vulnerability: hybrid ? 'Hybrid-protected' : 'High Risk',
      vulnerabilityReason: '',
      migrationTargets: [],
    },
  } as unknown as EdgeIntelligence
}

function categories(tls: TlsAnalysisResult, e: EdgeIntelligence | null) {
  return buildPublishedCategories({
    tlsResult: tls,
    certInfo: CERT,
    apiResult: null,
    repoResult: null,
    webCryptoResult: null,
    ruleResults: [],
    findings: [],
    edgeIntelligence: e,
  })
}
const scoreOf = (rows: ReturnType<typeof categories>, key: string) => rows.find((row) => row.key === key)

/* ───────────────────────────────── 1. measured PQ reaches the model ──────── */

section('1. The measured key agreement decides the score, not the socket label')

const hybridRows = categories(TLS13, edge('hybrid'))
const refusedRows = categories(TLS13, edge('refused'))
const unprobedRows = categories(TLS13, null)

assert(
  scoreOf(hybridRows, 'key-exchange')?.score === 100,
  `hybrid: key exchange scores 100 (${scoreOf(hybridRows, 'key-exchange')?.score})`,
)
assert(
  String(scoreOf(hybridRows, 'key-exchange')?.observed).includes('X25519MLKEM768'),
  'hybrid: the observed value names the measured group, not "ECDHE (TLS 1.3 key_share)"',
)
assert(
  (scoreOf(hybridRows, 'post-quantum-readiness')?.score ?? 0) >= 55,
  `hybrid: PQ readiness carries the 55-point hybrid allowance (${scoreOf(hybridRows, 'post-quantum-readiness')?.score})`,
)

/* NEGATIVE CONTROL — the identical socket fixture with no accepted group must
   still score classical. If these pass at 100 the fix is a blanket pass. */
assert(
  scoreOf(refusedRows, 'key-exchange')?.score === 70,
  `refused: classical ECDHE still scores 70 (${scoreOf(refusedRows, 'key-exchange')?.score})`,
)
assert(
  (scoreOf(refusedRows, 'post-quantum-readiness')?.score ?? 100) < 55,
  `refused: no hybrid allowance is awarded (${scoreOf(refusedRows, 'post-quantum-readiness')?.score})`,
)
assert(
  scoreOf(unprobedRows, 'key-exchange')?.score === 70,
  `unprobed: absence of a probe is never read as a hybrid accept (${scoreOf(unprobedRows, 'key-exchange')?.score})`,
)
assert(
  publishedPostureScore(hybridRows) > publishedPostureScore(refusedRows),
  `having migrated raises the composite (${publishedPostureScore(hybridRows)} vs ${publishedPostureScore(refusedRows)})`,
)

/* The algorithm census must not count the hybrid group against itself. */
const census = String(scoreOf(hybridRows, 'cryptographic-algorithms')?.observed)
assert(
  (scoreOf(hybridRows, 'cryptographic-algorithms')?.score ?? 0) >
    (scoreOf(refusedRows, 'cryptographic-algorithms')?.score ?? 0),
  `hybrid: the algorithm census credits the measured group (${census})`,
)

/* Edge-measured controls are now scored rather than permanently inapplicable. */
assert(scoreOf(hybridRows, 'certificate-transparency')?.applicable === true, 'CT is scored from the edge reading')
assert(scoreOf(hybridRows, 'ocsp-stapling')?.applicable === true, 'OCSP stapling is scored from the edge reading')
assert(scoreOf(hybridRows, 'dns-caa')?.applicable === true, 'DNS CAA is scored from the edge reading')
assert(
  scoreOf(unprobedRows, 'certificate-transparency')?.applicable === false,
  'without an edge probe those three are INAPPLICABLE, never a failing zero',
)
assert(
  scoreOf(unprobedRows, 'ocsp-stapling')?.score === 0 && scoreOf(unprobedRows, 'ocsp-stapling')?.applicable === false,
  'an inapplicable category never contributes its placeholder zero to the mean',
)

/* ─────────────────── 2. a hybrid group never excuses static RSA ──────────── */

section('2. Hybrid key agreement does NOT offset static-RSA key transport')

const hybridPlusStaticRsa = categories(TLS13_WITH_STATIC_RSA, edge('hybrid'))
assert(
  (scoreOf(hybridPlusStaticRsa, 'cipher-suites')?.score ?? 100) <= 50,
  `static RSA still costs the cipher-suite category (${scoreOf(hybridPlusStaticRsa, 'cipher-suites')?.score})`,
)
assert(
  scoreOf(hybridPlusStaticRsa, 'forward-secrecy')?.score === 70,
  `forward secrecy is capped while static RSA is accepted (${scoreOf(hybridPlusStaticRsa, 'forward-secrecy')?.score})`,
)
assert(
  String(scoreOf(hybridPlusStaticRsa, 'cipher-suites')?.observed).includes('static RSA accepted'),
  'the operator is told static RSA is the reason',
)

/* ────────────────── 3. TLS 1.3 suites are rated against the group ────────── */

section('3. Cipher-suite ratings follow the measured group, TLS 1.2 ratings do not')

const names = ['TLS_AES_256_GCM_SHA384', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256']
const withHybrid = analyzeCipherSuites(names, 'TLSv1.3', measuredKeyAgreement(edge('hybrid')))
const withoutProbe = analyzeCipherSuites(names, 'TLSv1.3', UNPROBED_KEY_AGREEMENT)

const tls13Hybrid = withHybrid.find((suite) => suite.category === 'tls13')!
const tls13Unprobed = withoutProbe.find((suite) => suite.category === 'tls13')!
assert(
  tls13Hybrid.quantumVulnerable === false && tls13Hybrid.riskLevel === 'SAFE',
  `TLS 1.3 suite under a measured hybrid group is SAFE (${tls13Hybrid.riskLevel})`,
)
assert(
  tls13Hybrid.keyExchange === 'X25519MLKEM768',
  `the suite names the group it actually negotiated (${tls13Hybrid.keyExchange})`,
)
assert(
  tls13Unprobed.quantumVulnerable === true && tls13Unprobed.riskLevel === 'MEDIUM',
  `NEGATIVE: unprobed TLS 1.3 keeps the classical assumption (${tls13Unprobed.riskLevel})`,
)

/* NEGATIVE CONTROL — ML-KEM lives only in the TLS 1.3 key_share, so no TLS 1.2
   suite may be softened by it. A session forced onto one of these has no
   post-quantum protection at all. */
const staticRsaSuite = withHybrid.find((suite) => suite.category === 'rsa-kex')!
const ecdheRsaSuite = withHybrid.find((suite) => suite.category === 'ecdhe-rsa')!
assert(
  staticRsaSuite.riskLevel === 'CRITICAL' && staticRsaSuite.quantumVulnerable,
  `static-RSA suite stays CRITICAL under a hybrid group (${staticRsaSuite.riskLevel})`,
)
assert(
  ecdheRsaSuite.riskLevel === 'HIGH' && ecdheRsaSuite.quantumVulnerable,
  `ECDHE-RSA suite stays HIGH under a hybrid group (${ecdheRsaSuite.riskLevel})`,
)

/* ──────────────────────── 4. one certificate fact, one finding ───────────── */

section('4. Certificate observations are deduplicated at source')

const restated = leafRestatedOids(CERT)
assert(restated.has('1.2.840.10045.2.1'), 'the leaf key algorithm OID (ecPublicKey) is a restatement')
assert(restated.has('1.2.840.10045.3.1.7'), 'the leaf curve OID (secp256r1) is a restatement')
assert(restated.has('1.2.840.10045.4.3.2'), 'the leaf signature OID (ecdsa-with-SHA256) is a restatement')
assert(restated.size === 3, `exactly the three restated OIDs, nothing else (${restated.size})`)

/* NEGATIVE CONTROL — an OID that is NOT the leaf's own must still be reported.
   A chain member signed with SHA-1, or an RSA key transport OID in an extension,
   is a new fact and suppressing it would hide real exposure. */
assert(!restated.has('1.2.840.113549.1.1.5'), 'an unrelated OID (sha1WithRSA) is NOT suppressed')
const unparsed = leafRestatedOids({ publicKeyOid: null, publicKeyCurveOid: null, signatureOid: '' })
assert(unparsed.size === 0, 'a certificate whose DER did not parse suppresses nothing')

/* ───────────────── 5. ML-KEM is never recommended for authentication ─────── */

section('5. FIPS 203 vs FIPS 204 — ML-KEM can never replace a signing key')

/* The invariant is about primitives that CAN authenticate. A key-establishment-only
   OID (RSAES-OAEP, dhKeyAgreement) correctly answers ML-KEM whatever role is asked
   for, because it cannot sign in the first place — asserting otherwise would demand
   a signature target for something that never produces a signature. */
const signingCapable = OID_DATABASE.filter((entry) => (entry.role ?? 'other') !== 'key-establishment')
const kemInSignatureRole = signingCapable.filter((entry) =>
  /ML-KEM/i.test(pqcReplacementFor(entry, 'signature')),
)
assert(
  kemInSignatureRole.length === 0,
  `no signing-capable OID recommends ML-KEM for authentication (${kemInSignatureRole.map((e) => e.name).join(', ') || 'none'})`,
)
assert(
  OID_DATABASE.some((entry) => entry.role === 'dual'),
  'the dual-use OIDs are actually classified — an all-`other` database would pass the sweep vacuously',
)

/* POSITIVE — the dual-use OIDs resolve to the right standard in each role. */
const ecPublicKey = OID_DATABASE.find((entry) => entry.name === 'ecPublicKey')!
assert(
  pqcReplacementFor(ecPublicKey, 'signature').includes('ML-DSA'),
  `ecPublicKey in a certificate → ML-DSA (${pqcReplacementFor(ecPublicKey, 'signature')})`,
)
assert(
  pqcReplacementFor(ecPublicKey, 'key-establishment').includes('ML-KEM'),
  `the same OID doing ECDH → ML-KEM (${pqcReplacementFor(ecPublicKey, 'key-establishment')})`,
)
const dh = OID_DATABASE.find((entry) => entry.name === 'dhKeyAgreement')!
assert(
  pqcReplacementFor(dh, 'signature').includes('ML-KEM'),
  'a key-establishment-only OID stays ML-KEM whatever role is asked for — DH cannot sign either',
)

/* The detection rules carried the same inversion in their remediation copy. */
const certRules = DETECTION_RULES.filter((rule) => rule.category === 'certificate-risk')
const kemCertRules = certRules.filter((rule) => /ML-KEM[^.]*certificate/i.test(rule.remediation))
assert(
  kemCertRules.length === 0,
  `no certificate rule prescribes an ML-KEM certificate (${kemCertRules.map((r) => r.id).join(', ') || 'none'})`,
)

/* ──────────── 6. one model: surface cards cannot contradict the gauge ────── */

section('6. Surface scores are a projection of the composite, not a second model')

const components: ScoreComponent[] = hybridRows.map((row) => ({
  key: row.key,
  label: row.label,
  weight: row.weight,
  score: row.applicable ? row.score : null,
  observed: row.observed,
  description: row.label,
  postQuantumRelevant: PQ_SENSITIVE_CATEGORY_KEYS.has(row.key),
}))
const nodeScores = scoreNodesFromCategories(components)
const composite = publishedPostureScore(hybridRows)

/* Re-aggregating the surface scores by their own category weights must return
   the composite. If it does not, the cards and the gauge are describing the
   same run with two different models — the exact defect this replaced. */
let weighted = 0
let weight = 0
for (const [node, keys] of Object.entries(SCANNER_NODE_CATEGORIES)) {
  const nodeWeight = keys
    .map((key) => components.find((component) => component.key === key))
    .filter((component) => component && component.score !== null)
    .reduce((sum, component) => sum + component!.weight, 0)
  if (nodeWeight === 0 || nodeScores[node] === undefined) continue
  weighted += nodeScores[node] * nodeWeight
  weight += nodeWeight
}
const reaggregated = Math.round(weighted / weight)
assert(
  Math.abs(reaggregated - composite) <= 1,
  `surface scores re-aggregate to the composite (${reaggregated} vs ${composite}, rounding only)`,
)

/* A surface the published model cannot measure gets NO number — never an
   averaged stand-in. */
assert(nodeScores.identity === undefined, 'identity has no published category and therefore no posture score')

/* The end-to-end statement of the original report: a hybrid endpoint's transport
   surface must no longer grade Critical purely for having been measured. */
const transportScore = nodeScores.transport ?? 0
const transportGrade = scoreToGrade(transportScore)
assert(
  transportGrade.rating !== 'Critical',
  `hybrid transport is not graded Critical (${transportScore}/100 · ${transportGrade.grade} · ${transportGrade.rating})`,
)

/* NEGATIVE CONTROL — the same surface with static RSA accepted MUST still fall,
   because that is a genuine exposure the hybrid group does not cover. */
const rsaComponents: ScoreComponent[] = hybridPlusStaticRsa.map((row) => ({
  key: row.key,
  label: row.label,
  weight: row.weight,
  score: row.applicable ? row.score : null,
  observed: row.observed,
  description: row.label,
  postQuantumRelevant: PQ_SENSITIVE_CATEGORY_KEYS.has(row.key),
}))
const rsaTransport = scoreNodesFromCategories(rsaComponents).transport ?? 0
assert(
  rsaTransport < transportScore,
  `accepting static RSA still lowers the transport surface (${rsaTransport} vs ${transportScore})`,
)

console.log(
  `\n${failures === 0 ? 'PASS' : 'FAIL'} — ${failures} failure(s).` +
    `\nhybrid composite ${composite}/100 · transport ${transportScore} · certificates ${nodeScores.certificates} · posture ${nodeScores.posture}\n`,
)
process.exit(failures === 0 ? 0 : 1)
