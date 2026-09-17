/**
 * Offline verification for the Dashboard Scanner's assessment intelligence.
 *
 * Drives the pure derivations in src/app/dashboard/scanner_dashboard/_intel.ts
 * with a synthetic-but-realistic scan payload — shaped exactly like what
 * /api/v1/scanner/stream emits on `scan-complete` — and asserts that:
 *
 *   • every derived value traces to the input evidence,
 *   • the composite score, the decomposition and the grade agree with each
 *     other (the decomposition's weighted mean reproduces the composite),
 *   • node evidence panels render real measurements per surface,
 *   • an EMPTY scan yields explicit Unknown / "not measured" states rather than
 *     zeros, fabricated scores or invented recommendations.
 *
 * No server or Supabase required.
 *
 *   npx tsx tools/scanner-dashboard-check.ts
 */
import {
  buildAssessment,
  buildNodeEvidence,
  nodeScoreScopes,
  pqcRole,
  scoreNodesFromCategories,
  SCANNER_NODE_CATEGORIES,
  SCANNER_NODE_BLUEPRINTS,
  type AssessmentInput,
} from '../src/app/dashboard/scanner_dashboard/_intel'
import { buildAlgorithmCensus } from '../src/lib/scanner/web-scanner/algorithm-census'
import {
  classifyQuantumVulnerability,
  measuredKeyAgreement,
} from '../src/lib/scanner/web-scanner/edge-intelligence-model'
import { buildPublishedCategories } from '../src/lib/scanner/web-scanner/published-scoring'
import type {
  DefensiveFinding,
  EnterpriseScanner2,
  ModuleState,
  ScanResultRecord,
} from '../src/app/dashboard/scanner_dashboard/_types'

let failures = 0
function assert(condition: boolean, label: string) {
  if (condition) {
    console.log(`  ok   ${label}`)
  } else {
    failures += 1
    console.log(`  FAIL ${label}`)
  }
}

const NOW = new Date().toISOString()

/* ------------------------------------------------------------------ fixtures */

const FINDINGS: DefensiveFinding[] = [
  { id: 'f1', algorithm: 'RSA-2048', category: 'Certificate', location: 'test.example.org:443', threatLevel: 'HIGH', status: 'Quantum-vulnerable', description: 'RSA key exchange', recommendation: 'Migrate to ML-DSA', pqcReplacement: 'ML-DSA-65', keySize: 2048, evidence: 'certificate: leaf', detectionMethod: 'certificate-scan', source: 'web-scanner' },
  { id: 'f2', algorithm: 'TLSv1.0', category: 'Protocol Support', location: 'test.example.org:443', threatLevel: 'CRITICAL', status: 'Legacy', description: 'Deprecated protocol accepted', recommendation: 'Disable TLS 1.0', pqcReplacement: null, keySize: null, evidence: 'tls: probe', detectionMethod: 'tls-scan', source: 'web-scanner' },
  { id: 'f3', algorithm: 'TLS_AES_256_GCM_SHA384', category: 'Cipher Suite', location: 'test.example.org:443', threatLevel: 'SAFE', status: 'PQC-ready', description: 'AEAD suite', recommendation: 'None', pqcReplacement: null, keySize: null, evidence: 'tls: suite', detectionMethod: 'cipher-scan', source: 'web-scanner' },
  { id: 'f4', algorithm: 'ssh-rsa', category: 'SSH Host Key', location: 'bastion.example.org:22', threatLevel: 'HIGH', status: 'Quantum-vulnerable', description: 'RSA host key', recommendation: 'Rotate to Ed25519', pqcReplacement: null, keySize: 2048, evidence: 'ssh: banner', detectionMethod: 'ssh-scan', source: 'web-scanner' },
  { id: 'f5', algorithm: 'Strict-Transport-Security', category: 'Security Headers', location: 'https://test.example.org', threatLevel: 'LOW', status: 'Present', description: 'HSTS present', recommendation: 'Add preload', pqcReplacement: null, keySize: null, evidence: 'http: header', detectionMethod: 'api-scan', source: 'web-scanner' },
]

const RESULTS: ScanResultRecord[] = [
  {
    scanId: 'scan-1',
    target: 'https://test.example.org',
    targetType: 'https',
    durationMs: 9040,
    status: 'completed',
    // riskScore is 100 - the published weighted posture:
    // (45*18 + 35*15 + 80*12 + 70*12 + 70*10 + 0*8 + 80*5 + 40*5 + 15*3) / 88 = 50.9 -> 51
    riskScore: 49,
    qScore: 51,
    tlsVersion: 'TLSv1.3',
    certificateInfo: {
      subject: { CN: 'test.example.org' },
      issuer: { CN: 'Example CA R3', O: 'Example Trust' },
      publicKeyAlgorithm: 'ECDSA',
      publicKeySize: 256,
      signatureAlgorithm: 'sha256WithRSAEncryption',
      validFrom: '2026-01-01T00:00:00.000Z',
      validTo: '2026-12-01T00:00:00.000Z',
      isExpired: false,
      isSelfSigned: false,
      chain: [
        { subject: 'test.example.org', issuer: 'Example CA R3', signatureAlgorithm: 'sha256WithRSA', publicKeyAlgorithm: 'ECDSA', publicKeySize: 256, validTo: '2026-12-01T00:00:00.000Z', isExpired: false },
        { subject: 'Example CA R3', issuer: 'Example Root', signatureAlgorithm: 'sha256WithRSA', publicKeyAlgorithm: 'RSA', publicKeySize: 2048, validTo: '2030-01-01T00:00:00.000Z', isExpired: false },
      ],
    },
    metadata: {
      tlsAnalysis: {
        tlsVersion: 'TLSv1.3',
        cipherSuite: 'TLS_AES_256_GCM_SHA384',
        keyExchange: 'ECDHE',
        signatureAlgorithm: 'ecdsa_secp256r1_sha256',
        supportedProtocols: ['TLSv1.0', 'TLSv1.2', 'TLSv1.3'],
        negotiatedCurve: 'X25519',
        ephemeralKeyType: 'X25519',
        ephemeralKeySize: 253,
        cipherSuites: [
          { name: 'TLS_AES_256_GCM_SHA384', encryption: 'AES-256-GCM', quantumVulnerable: false },
          { name: 'TLS_RSA_WITH_AES_128_CBC_SHA', encryption: 'AES-128-CBC', category: 'rsa-kex', quantumVulnerable: true },
        ],
      },
      apiSecurityResult: {
        hostname: 'test.example.org',
        endpointsProbed: 6,
        securityHeaders: [
          { name: 'Strict-Transport-Security', value: 'max-age=63072000', present: true, secure: true },
          { name: 'Content-Security-Policy', value: 'default-src *', present: true, secure: false },
          { name: 'X-Frame-Options', value: null, present: false, secure: false },
        ],
      },
      riskBreakdown: { certificateRisk: 28, tlsConfigRisk: 55, cipherSuiteRisk: 35, appCryptoRisk: 40, pqcReadiness: 82 },
      riskBreakdownApplicable: { certificateRisk: true, tlsConfigRisk: true, cipherSuiteRisk: true, appCryptoRisk: true, pqcReadiness: true },
      // The platform's published twelve-category model, exactly as the scanner
      // now emits it. Three public-edge probes are inapplicable here because the
      // authenticated scanner does not perform them.
      scoreCategories: [
        { key: 'tls-configuration', label: 'TLS Configuration', weight: 18, score: 45, applicable: true, observed: 'TLSv1.0, TLSv1.2, TLSv1.3' },
        { key: 'cipher-suites', label: 'Cipher Suites', weight: 15, score: 35, applicable: true, observed: 'TLS_AES_256_GCM_SHA384 · static RSA accepted' },
        { key: 'certificates', label: 'Certificates', weight: 12, score: 80, applicable: true, observed: 'ECDSA 256 · 334-day lifetime' },
        { key: 'key-exchange', label: 'Key Exchange', weight: 12, score: 70, applicable: true, observed: 'ECDHE (X25519)' },
        { key: 'forward-secrecy', label: 'Forward Secrecy', weight: 10, score: 70, applicable: true, observed: 'ECDHE · 1 static-RSA suite(s) still accepted' },
        { key: 'http-security-headers', label: 'HTTP Security Headers', weight: 8, score: 0, applicable: true, observed: '0/2 transport headers hardened' },
        { key: 'hsts', label: 'HSTS', weight: 5, score: 80, applicable: true, observed: 'enforced' },
        { key: 'ocsp-stapling', label: 'OCSP Stapling', weight: 5, score: 0, applicable: false, observed: 'not observable from an authenticated network scan' },
        { key: 'certificate-transparency', label: 'Certificate Transparency', weight: 3, score: 0, applicable: false, observed: 'not observable from an authenticated network scan' },
        { key: 'dns-caa', label: 'DNS CAA', weight: 4, score: 0, applicable: false, observed: 'not observable from an authenticated network scan' },
        { key: 'cryptographic-algorithms', label: 'Cryptographic Algorithms', weight: 5, score: 40, applicable: true, observed: '10 algorithms observed · 4 quantum-safe' },
        { key: 'post-quantum-readiness', label: 'Post-Quantum Readiness', weight: 3, score: 15, applicable: true, observed: '15% readiness' },
      ],
      riskMeasuredWeight: 88,
      scanConfidence: { confidence: 75, label: 'High', factors: ['TLS analysis completed', 'Certificate parsed'] },
    },
  },
]

const SCANNER2: EnterpriseScanner2 = {
  hndlRisks: [
    { id: 'h1', targetName: 'test.example.org', algorithm: 'RSA-2048', dataType: 'session keys', exposurePeriod: '10 years', riskExplanation: 'Shor-breakable', mitigationAction: 'Deploy ML-KEM', urgencyLevel: 'immediate', estimatedQDayImpact: 'full session recovery' },
    { id: 'h2', targetName: 'bastion.example.org', algorithm: 'ssh-rsa', dataType: 'admin traffic', exposurePeriod: '8 years', riskExplanation: 'Shor-breakable', mitigationAction: 'Rotate host key', urgencyLevel: 'soon', estimatedQDayImpact: 'credential recovery' },
  ],
  attackAssessment: {
    riskScore: 64,
    classification: 'HIGH',
    detectedAssets: { certificates: 2, protocols: 3 },
    estimatedBreakWindow: { earliest: 2030, latest: 2035 },
    attackCorrelations: [{ id: 'c1', source: 'test.example.org', sourceType: 'endpoint', finding: 'RSA-2048', chain: 'harvest → decrypt', riskLevel: 'HIGH' }],
  },
  quantumRiskScore: { overall: 64, level: 'vulnerable', criticalCount: 1, highCount: 2, moderateCount: 0, lowCount: 1, totalFindings: 5, hndlRiskCount: 2 },
  quantumReadiness: { score: 20, label: 'Early', color: '#f59e0b', assetsRequiringMigration: { certificates: 2 }, totalAssets: 5, quantumSafeAssets: 1 },
  migrationRecommendations: [
    { classicalAlgorithm: 'RSA-2048', recommendedPQC: 'ML-KEM-768', alternativePQC: ['FrodoKEM', 'HQC'], migrationType: 'Key Exchange Replacement', migrationComplexity: 'HIGH', migrationSteps: ['Inventory RSA-2048 keys', 'Deploy hybrid ML-KEM', 'Reissue certificates'], nistStandard: 'FIPS 203 (ML-KEM)', estimatedEffort: '4-8 weeks' },
  ],
}

function moduleState(id: string, name: string, status: ModuleState['status'], findings = 0, reason: string | null = null): ModuleState {
  return {
    id,
    name,
    status,
    target: 'https://test.example.org',
    startedAt: NOW,
    completedAt: status === 'Running' ? null : NOW,
    durationMs: status === 'Running' ? null : 120,
    findingsCount: findings,
    error: status === 'Failed' ? 'boom' : null,
    // The ledger contract: a Skipped ALWAYS carries the reason it did not apply.
    reason: status === 'Skipped' ? (reason ?? 'no SSH target was authorized for this run') : reason,
    notApplicable: status === 'Skipped',
  }
}

const MODULES: ModuleState[] = [
  moduleState('target-validation', 'Target Authorization & Validation', 'Completed', 1),
  moduleState('asset-inventory-synchronizer', 'Asset inventory synchronizer', 'Completed', 1),
  moduleState('scanner2-module-registry', 'Scanner_2 module registry', 'Completed'),
  moduleState('tls-protocol-scanner', 'TLS protocol scanner', 'Completed', 1),
  moduleState('cipher-suite-scanner', 'Cipher suite scanner', 'Completed', 1),
  moduleState('key-exchange-scanner', 'Key exchange scanner', 'Completed'),
  moduleState('certificate-scanner', 'Certificate scanner', 'Completed', 1),
  moduleState('signature-algorithm-scanner', 'Signature algorithm scanner', 'No findings'),
  moduleState('hash-algorithm-scanner', 'Hash algorithm scanner', 'No findings'),
  moduleState('ssh-host-key-scanner', 'SSH host key scanner', 'Completed', 1),
  moduleState(
    'jwt-signing-scanner',
    'JWT signing algorithm scanner',
    'Skipped',
    0,
    'token and header analysis needs an HTTP endpoint (target types: ssh)',
  ),
  moduleState('cbom-generator', 'CBOM generator', 'Completed', 4),
  moduleState('risk-scoring-engine', 'Risk scoring engine', 'Completed', 5),
]

const ESTATE = { totalAssets: 2, totalFindings: 5, criticalFindings: 1, highFindings: 2, vulnerableAssets: 2, vulnerableComponents: 4, pqcReadiness: 20, riskScore: 49 }

const POPULATED: AssessmentInput = {
  status: 'completed',
  // buildSummary() averages the per-target published scores, so with one target
  // the summary risk IS that target's overall (49) and qScore is 51.
  summary: { targetsScanned: 2, totalFindings: 5, critical: 1, high: 2, medium: 0, low: 1, safe: 1, vulnerable: 4, pqcReady: 1, riskScore: 49, qScore: 51 },
  findings: FINDINGS,
  modules: MODULES,
  results: RESULTS,
  scanner2: SCANNER2,
  targets: ['https://test.example.org', 'ssh://bastion.example.org:22'],
  completedAt: NOW,
  estate: ESTATE,
  linked: { cbom: 4, assets: 2, exposures: 3 },
  provenance: 'Live scan evidence',
}

const EMPTY: AssessmentInput = {
  status: 'idle',
  summary: null,
  findings: [],
  modules: [],
  results: [],
  scanner2: null,
  targets: [],
  completedAt: null,
  estate: { totalAssets: 0, totalFindings: 0, criticalFindings: 0, highFindings: 0, vulnerableAssets: 0, vulnerableComponents: 0, pqcReadiness: 0, riskScore: 0 },
  linked: { cbom: 0, assets: 0, exposures: 0 },
  provenance: 'No evidence yet',
}

/* ------------------------------------------------------------------- checks */

function verifyPopulated() {
  const a = buildAssessment(POPULATED)
  console.log('\n=== Populated scan — every value traces to evidence ===')

  assert(a.hasEvidence === true, 'hasEvidence=true')
  assert(a.executive.encryptionScore === 51, `Composite score is the backend qScore (${a.executive.encryptionScore})`)
  assert(a.executive.gradeable === true && a.executive.grade !== '—', `Grade issued: ${a.executive.grade} (${a.executive.gradeLabel})`)

  /* The decomposition must reproduce the composite it sits under. The backend's
     summary risk score is the MEAN of the per-target weighted scores, and the
     decomposition is the weighted mean of the per-target components — the two
     operations commute, so when the summary came from the weighted model these
     are the same number. */
  assert(a.scoreComponents.length === 12, `All twelve published categories are listed (${a.scoreComponents.length})`)
  const measured = a.scoreComponents.filter((c) => c.score !== null)
  assert(measured.length === 9, `Nine measured, three public-edge probes excluded (${measured.length})`)
  const unprobed = a.scoreComponents.filter((c) => c.score === null).map((c) => c.key).sort()
  assert(
    unprobed.join(',') === 'certificate-transparency,dns-caa,ocsp-stapling',
    `The excluded three are the public-edge probes (${unprobed.join(', ')})`,
  )
  assert(
    a.scoreComponents.every((c) => c.score !== null || c.observed.includes('not observable')),
    'Every excluded category states why it was excluded',
  )
  assert(a.decompositionScore === 51, `Decomposition weighted mean over the measured 88 (${a.decompositionScore})`)
  assert(a.decompositionAgrees === true, `Decomposition reconciles with the composite (${a.decompositionScore} vs ${a.executive.encryptionScore})`)

  assert(a.executive.confidence === 75, `Confidence read from scanConfidence (${a.executive.confidence})`)
  assert(a.executive.businessRisk === 'High' || a.executive.businessRisk === 'Critical', `Critical finding floors business risk (${a.executive.businessRisk})`)
  assert(a.executive.migrationComplexity === 'High', `Migration complexity from the migration engine (${a.executive.migrationComplexity})`)
  assert(
    a.executive.postQuantumReadiness === 15,
    `PQ readiness is the published model's category, not the finding share (${a.executive.postQuantumReadiness}%)`,
  )

  const surfaceOf = (key: string) => a.attackSurface.find((item) => item.key === key)

  // Every control /public-scan reports must have a row here too.
  for (const key of [
    'internet-facing', 'tls-service', 'certificate-chain', 'names-covered', 'tls-version',
    'cipher', 'chain-trust', 'key-exchange', 'pq-key-agreement', 'hsts', 'ocsp-stapling',
    'certificate-transparency', 'dns-caa', 'dnssec', 'alpn', 'quantum-risk', 'edge-infrastructure',
  ]) {
    assert(surfaceOf(key) !== undefined, `Attack surface reports "${key}"`)
  }

  assert(surfaceOf('pfs')?.status === 'partial', `Forward secrecy downgraded for accepted static RSA (${surfaceOf('pfs')?.value})`)
  assert(surfaceOf('cert-validity')?.status !== 'unknown', `Certificate validity is reported (${surfaceOf('cert-validity')?.value})`)
  assert(surfaceOf('chain-trust')?.value === 'Pass', `Chain trust is reported (${surfaceOf('chain-trust')?.value})`)
  assert(surfaceOf('cert-key')?.value === 'ECDSA 256-bit', `Certificate key is not duplicated (${surfaceOf('cert-key')?.value})`)
  // HSTS is scored on its own row, so the header ratio excludes it.
  assert(surfaceOf('headers')?.value === '0/2 hardened', `Headers read from the probe, HSTS excluded (${surfaceOf('headers')?.value})`)
  assert(surfaceOf('hsts')?.value === 'Enforced', `HSTS has its own row (${surfaceOf('hsts')?.value})`)
  assert(surfaceOf('cipher')?.value === 'Static RSA accepted', `Cipher row flags accepted static RSA (${surfaceOf('cipher')?.value})`)
  assert(surfaceOf('tls-version')?.value === 'TLSv1.3 + legacy', `TLS row flags legacy protocols (${surfaceOf('tls-version')?.value})`)
  assert(surfaceOf('quantum-risk')?.value === 'High', `Quantum risk from the Scanner_2 assessment (${surfaceOf('quantum-risk')?.value})`)

  /* Controls with no evidence attached must claim no verdict — never pass or
     fail. Asserted on the CONTRACT (status is `unknown`, the value is an
     explicit non-verdict, and the row says why) rather than on one exact
     string: this fixture carries no `edgeIntelligence`, and the phrasing for
     that case is "Not measured" while an edge phase that ran but could not
     reach a control reports "Not probed". Pinning the literal made the check
     fail on a wording change that did not weaken the contract at all. */
  const NON_VERDICTS = ['Not probed', 'Not measured', 'Unknown']
  for (const key of ['ocsp-stapling', 'certificate-transparency', 'dns-caa', 'dnssec', 'alpn', 'edge-infrastructure']) {
    const row = surfaceOf(key)
    assert(
      row?.status === 'unknown' && NON_VERDICTS.includes(row.value) && Boolean(row.detail),
      `"${key}" claims no verdict it did not earn (${row?.value} / ${row?.status})`,
    )
  }
  const tlsItem = a.attackSurface.find((item) => item.key === 'tls-version')
  assert(
    tlsItem?.value === 'TLSv1.3 + legacy' && tlsItem.status === 'fail',
    `TLS row reports the negotiated version AND that legacy protocols are still accepted (${tlsItem?.value})`,
  )

  assert(a.intelligence.keyExchange.includes('ECDHE') && a.intelligence.keyExchange.includes('X25519'), `Key exchange from the TLS analysis (${a.intelligence.keyExchange})`)
  /* "Partial", not "Enabled": this endpoint negotiated TLS 1.3 (forward secret
     by construction) but ALSO accepts a static-RSA suite, and a session steered
     onto that suite has no ephemeral secret at all. The surface row and the
     intelligence row must read the same word, and that word is the capped one. */
  assert(a.intelligence.forwardSecrecy === 'Partial', `Intelligence forward secrecy agrees with the surface (${a.intelligence.forwardSecrecy})`)
  /* A hybrid group would not rescue it either — and the verdict must say so
     rather than reporting the endpoint as protected. Here nothing hybrid was
     measured, so the verdict is plainly Vulnerable. */
  assert(
    a.intelligence.quantumVulnerability === 'Vulnerable',
    `Quantum verdict follows the measured transport, not the suite name (${a.intelligence.quantumVulnerability})`,
  )
  assert(a.intelligence.scanner2Readiness?.score === 20, 'Scanner_2 readiness reported separately, not blended')

  const algorithmNames = a.intelligence.observedAlgorithms.map((entry) => entry.name)
  assert(algorithmNames.includes('ECDSA'), `Observed algorithms include the certificate key (${algorithmNames.join(', ')})`)
  assert(algorithmNames.includes('AES-256-GCM'), 'Observed algorithms include a real symmetric algorithm')
  assert(
    !algorithmNames.some((name) => /^no /i.test(name) || name.includes(':')),
    'No detection-rule titles leak into Observed Algorithms',
  )

  assert(a.recommendations.length === 1 && a.recommendations[0].standard === 'FIPS 203 (ML-KEM)', 'Recommendation carries the real NIST standard')
  assert(a.recommendations[0].steps.length === 3, 'Recommendation carries the real migration steps')
  assert(a.hndl.immediate === 1 && a.hndl.soon === 1, `HNDL urgency split from the analyzer (${a.hndl.immediate}/${a.hndl.soon})`)
  assert(a.hndl.window?.earliest === 2030 && a.hndl.window?.latest === 2035, 'Break window from the attack assessment')

  const footprintCbom = a.footprint.metrics.find((m) => m.key === 'cbom')
  assert(footprintCbom?.value === 4, `CBOM footprint counted from linked records (${footprintCbom?.value})`)

  assert(a.scope.notAnalyzed.some((item) => item.includes('JWT')), 'Skipped module named in "not analyzed"')
  assert(
    a.scope.notAnalyzed.some((item) => item.includes('token and header analysis')),
    `"Not analyzed" carries the scanner's own reason, not a generic caption (${a.scope.notAnalyzed[0]})`,
  )
}

/* ---------------------------------------------------------- module ledger -- */

/**
 * The Discovery Workflow regression suite at the assessment layer.
 *
 * These assertions encode the contract the reported bug violated: coverage is
 * measured against the modules that COULD apply, a run with an unreported
 * module is not graded, and every non-measuring module explains itself.
 */
function verifyModuleLedgerContract() {
  console.log('\n=== Module ledger — coverage, grading and reasons ===')

  const a = buildAssessment(POPULATED)

  /* 12 of the 13 fixture modules measured; the JWT module is not applicable and
     is excluded from the denominator rather than counted as a miss. Counting it
     produced a permanent ~92% ceiling on every scan that legitimately skipped a
     module. */
  assert(
    a.executive.evidenceCoverage === 100,
    `Not-applicable modules are excluded from coverage, not counted as gaps (${a.executive.evidenceCoverage}%)`,
  )
  assert(a.executive.gradeable === true, 'A fully-reported run is gradeable')

  const jwtCoverage = a.coverage.find((item) => item.key === 'identity')
  assert(jwtCoverage?.status === 'pass', `A surface whose only gap is inapplicable still passes (${jwtCoverage?.status})`)
  assert(
    (jwtCoverage?.detail ?? '').includes('not applicable'),
    `Discovery Coverage names the inapplicable module (${jwtCoverage?.detail})`,
  )
  assert(
    (jwtCoverage?.detail ?? '').includes('1/1 applicable'),
    `Coverage is stated against applicable modules (${jwtCoverage?.detail})`,
  )

  /* THE REGRESSION. A run cut short leaves modules at `Queued`. That is an
     incomplete assessment, and it must NOT be graded — this is exactly the
     state that produced "SCAN COMPLETE · Grade A · 96%" on a scan that had run
     six of twenty-three modules. */
  const truncated = buildAssessment({
    ...POPULATED,
    modules: [
      ...MODULES.slice(0, 4),
      moduleState('cipher-suite-scanner', 'Cipher suite scanner', 'Queued'),
      moduleState('key-exchange-scanner', 'Key exchange scanner', 'Queued'),
      moduleState('certificate-scanner', 'Certificate scanner', 'Queued'),
    ],
  })
  assert(truncated.executive.gradeable === false, 'A run with unreported modules is NOT graded')
  assert(truncated.executive.grade === '—', `No grade letter is issued (${truncated.executive.grade})`)
  assert(
    truncated.executive.gradeLabel === 'Incomplete run',
    `The headline says why, instead of claiming a rating (${truncated.executive.gradeLabel})`,
  )
  assert(
    truncated.executive.gradeDetail.includes('never reported'),
    `The detail names the execution gap (${truncated.executive.gradeDetail})`,
  )
  assert(
    truncated.scope.notAnalyzed.some((item) => item.includes('never reported')),
    'Assessment Scope lists the modules that never reported',
  )
  assert(
    truncated.coverage.some((item) => item.key === 'unreported'),
    'Discovery Coverage raises an explicit "Unreported modules" row',
  )
  assert(
    truncated.executive.businessRisk === 'Not assessable',
    `Business risk is withheld on an incomplete run (${truncated.executive.businessRisk})`,
  )

  /* A surface whose modules ALL legitimately did not apply reports "no coverage
     to claim" rather than a passing grade on zero measurements. */
  const repoOnly = buildAssessment({
    ...POPULATED,
    modules: [
      moduleState('target-validation', 'Target Authorization & Validation', 'Completed', 1),
      moduleState('tls-protocol-scanner', 'TLS protocol scanner', 'Skipped', 0, 'no TLS endpoint was in scope for this run'),
      moduleState('cipher-suite-scanner', 'Cipher suite scanner', 'Skipped', 0, 'no TLS endpoint was in scope for this run'),
      moduleState('key-exchange-scanner', 'Key exchange scanner', 'Skipped', 0, 'no TLS endpoint was in scope for this run'),
    ],
  })
  const transportCoverage = repoOnly.coverage.find((item) => item.key === 'transport')
  assert(
    transportCoverage?.status === 'unknown',
    `An entirely inapplicable surface is Unknown, never Pass (${transportCoverage?.status})`,
  )
  assert(
    (transportCoverage?.detail ?? '').includes('no TLS endpoint'),
    `It states the scanner's reason (${transportCoverage?.detail})`,
  )
}

/* -------------------------------------------------- single source of truth -- */

/**
 * The panels the operator listed must never describe two different
 * populations. `buildAssessment` picks ONE scope and every number follows it.
 */
function verifySingleSourceOfTruth() {
  console.log('\n=== One evidence scope across every panel ===')

  const a = buildAssessment(POPULATED)
  const footprint = (key: string) => a.footprint.metrics.find((metric) => metric.key === key)?.value

  // Scan scope: the summary answers every headline, the estate snapshot none.
  /* The tile counts CRYPTOGRAPHIC COMPONENTS, not every finding — a
     detection-rule observation ("Regulatory Compliance Gap") is a statement
     about the estate, not an inventory row, and counting it here is what made
     this tile irreconcilable with the CBOM page for the same scan. */
  assert(footprint('components') === a.footprint.components.total, `Estate Footprint components = the derived component count (${footprint('components')})`)
  assert(
    a.footprint.components.total + a.footprint.components.policyFindings === POPULATED.findings.length,
    `Components + policy findings account for the scan total (${a.footprint.components.total} + ${a.footprint.components.policyFindings} of ${POPULATED.findings.length})`,
  )
  assert(footprint('assets') === POPULATED.summary!.targetsScanned, `Estate Footprint assets = targets scanned (${footprint('assets')})`)
  assert(a.target.count === POPULATED.summary!.targetsScanned, 'Assessment Scope target count comes from the same summary')
  assert(
    a.executive.businessRiskDetail.includes(String(POPULATED.summary!.critical)),
    `Business risk quotes the scan's critical count, not the estate's (${a.executive.businessRiskDetail})`,
  )
  assert(
    a.executive.businessRiskDetail.includes('this assessment'),
    'The risk statement names the scope it is describing',
  )
  assert(
    a.footprint.exposureLevel.includes(String(a.footprint.components.vulnerable)),
    `Exposure level counts the scan's vulnerable COMPONENTS, the same population as the tile (${a.footprint.exposureLevel})`,
  )

  /* Estate scope: with no scan in view EVERY number switches together. The bug
     was a per-field `summary?.x ?? estate.x` fallback, which let one panel read
     the scan and the next read the estate. */
  const estateOnly = buildAssessment({
    ...POPULATED,
    status: 'idle',
    summary: null,
    results: [],
    modules: [],
    estate: { totalAssets: 6, totalFindings: 174, criticalFindings: 106, highFindings: 41, vulnerableAssets: 6, vulnerableComponents: 120, pqcReadiness: 12, riskScore: 61 },
  })
  const estateFootprint = (key: string) => estateOnly.footprint.metrics.find((metric) => metric.key === key)?.value
  /* Estate scope holds totals, not rows — there is nothing to classify, so the
     snapshot total is reported as the observation total it is. */
  assert(estateFootprint('components') === 174, `Estate scope: components from the snapshot (${estateFootprint('components')})`)
  assert(
    estateOnly.footprint.metrics.find((metric) => metric.key === 'components')?.countedFrom.includes('Scanner Intelligence snapshot') ?? false,
    'Estate scope names the snapshot it counted from',
  )
  assert(estateFootprint('assets') === 6, `Estate scope: assets from the snapshot (${estateFootprint('assets')})`)
  assert(estateOnly.executive.encryptionScore === 39, `Estate scope: score is 100 - estate risk (${estateOnly.executive.encryptionScore})`)
  assert(
    estateOnly.executive.businessRiskDetail.includes('106') && estateOnly.executive.businessRiskDetail.includes('tenant estate'),
    `Estate scope: risk quotes the estate's critical count and says so (${estateOnly.executive.businessRiskDetail})`,
  )
  assert(
    estateOnly.executive.businessRisk === 'Critical',
    `Estate scope: 106 criticals cannot yield a benign band (${estateOnly.executive.businessRisk})`,
  )

  /* The exact contradiction from the report: a Grade A headline beside 106 open
     critical findings. Whichever scope is in force, the grade and the critical
     count must come from it. */
  assert(
    !(estateOnly.executive.grade === 'A' && estateOnly.executive.businessRiskDetail.includes('106')),
    'A top grade can never sit beside an estate-scoped critical count',
  )
}

function verifyNodeEvidence() {
  console.log('\n=== Node evidence — real measurements per surface ===')
  /* The decomposition the surface scores are projected from — the SAME array the
     Encryption Score panel renders, taken from the assessment rather than
     rebuilt, because rebuilding it is precisely how the cards and the gauge
     drifted apart. */
  const scoreComponents = buildAssessment(POPULATED).scoreComponents
  const base = { results: RESULTS, findings: FINDINGS, modules: MODULES, scanner2: SCANNER2, targets: POPULATED.targets, linked: POPULATED.linked, scoreComponents }

  const transport = buildNodeEvidence('transport', base)
  assert(transport.rows.some((r) => r.label === 'Negotiated protocol' && r.value === 'TLSv1.3'), 'transport: negotiated protocol')
  assert(transport.rows.some((r) => r.label === 'Protocols accepted' && r.value.includes('TLSv1.0')), 'transport: legacy protocol surfaced')
  /* BOTH accepted suites are quantum-vulnerable here, and the count says so.
     It used to read "1", because it trusted the per-suite `quantumVulnerable`
     flag — which is set from the suite NAME and therefore called
     TLS_AES_256_GCM_SHA384 safe even though this handshake negotiated it over
     the classical X25519 group. The count and the locus row now run the one
     decomposer against the one measured group, so they cannot disagree about
     the same suite. */
  assert(
    transport.rows.some((r) => r.label === 'Suites enumerated' && r.value.includes('2 quantum-vulnerable')),
    `transport: quantum-vulnerable suites counted from the measured group (${transport.rows.find((r) => r.label === 'Suites enumerated')?.value})`,
  )
  const locusRow = transport.rows.find((r) => r.label.startsWith('Quantum exposure locus'))
  assert(Boolean(locusRow) && locusRow!.label.includes('negotiated suite'), 'transport: the locus row states the scope it describes')
  assert(
    Boolean(locusRow) && locusRow!.value.includes('Key agreement'),
    `transport: the locus agrees with the count for the negotiated suite (${locusRow?.value})`,
  )
  /* Forward secrecy replaced the raw "Ephemeral key" readout: the presence of
     ephemeral key material is the mechanism, forward secrecy is the security
     property, and the panel must state the property. */
  assert(transport.rows.some((r) => r.label === 'Forward secrecy'), 'transport: forward secrecy is stated')
  /* The key-agreement row must exist and must never be silently absent — this
     is the row that used to print "ECDHE (TLS 1.3 key_share)" over a measured
     hybrid ML-KEM group. */
  assert(transport.rows.some((r) => r.label === 'Key agreement'), 'transport: key agreement is stated')
  assert(
    transport.rows.some((r) => r.label === 'Post-quantum key agreement'),
    'transport: post-quantum key agreement has its own row',
  )
  /* Static-RSA acceptance is the one transport fact a hybrid key agreement does
     NOT mitigate, so it is stated explicitly rather than left in a suite list. */
  assert(transport.rows.some((r) => r.label === 'Static RSA accepted'), 'transport: static RSA acceptance is stated')
  assert(transport.modules.length === 3, `transport: 3 modules attributed (${transport.modules.length})`)

  const certificates = buildNodeEvidence('certificates', base)
  assert(certificates.rows.some((r) => r.label === 'Public key' && r.value === 'ECDSA 256'), 'certificates: public key')
  assert(certificates.rows.some((r) => r.label === 'Issuer' && r.value === 'Example CA R3'), 'certificates: issuer CN')
  assert(certificates.rows.some((r) => r.label === 'Chain' && r.value === '2 certificate(s)'), 'certificates: chain depth')
  assert(certificates.rows.some((r) => r.label === 'Validity' && r.value.includes('day')), 'certificates: days remaining computed')

  const code = buildNodeEvidence('code', base)
  /* "0/2", not "1/3": HSTS is reported on its own row on the Observed Attack
     Surface and now leaves this tally too, so the two panels state one
     measurement. They read "2/10" and "1/8" for the same scan before this. */
  assert(code.rows.some((r) => r.label === 'Security headers' && r.value === '0/2 hardened'), `code: header hardening counted (${code.rows.find((r) => r.label === 'Security headers')?.value})`)
  assert(code.rows.some((r) => r.label === 'API endpoints probed' && r.value === '6'), 'code: endpoints probed')

  const posture = buildNodeEvidence('posture', base)
  /* The label must NAME its source and population. This card carries up to three
     "readiness"-shaped numbers over different populations, and labelling them all
     "Quantum readiness" is what made the panel look self-contradictory. */
  assert(
    posture.rows.some((r) => r.label === 'Migration readiness · Scanner_2' && r.value.startsWith('20%')),
    'posture: Scanner_2 migration readiness names its source and population',
  )
  /* The row must never call an observation an asset. `totalAssets` used to hold
     the FINDING count, so a single-asset scan reported "3 of 16 inventoried
     asset(s)". */
  const readinessRow = posture.rows.find((r) => r.label === 'Migration readiness · Scanner_2')
  assert(
    Boolean(readinessRow) && !/inventoried asset/i.test(readinessRow!.detail ?? ''),
    `posture: readiness does not describe observations as inventoried assets (${readinessRow?.detail})`,
  )
  /* The harvest-now row counts observations, and states the asset population
     separately. It read "8 asset(s)" on a one-asset tenant. */
  const hndlRow = posture.rows.find((r) => r.label === 'Harvest-now exposure')
  assert(
    Boolean(hndlRow) && /observation/.test(hndlRow!.value) && !/asset\(s\)/.test(hndlRow!.value),
    `posture: harvest-now counts observations, not assets (${hndlRow?.value})`,
  )
  assert(posture.rows.some((r) => r.label === 'Break window' && r.value === '2030–2035'), 'posture: break window')
  assert(posture.rows.some((r) => r.label === 'Harvest-now exposure' && r.value.includes('1 immediate')), 'posture: HNDL urgency')

  const identity = buildNodeEvidence('identity', base)
  assert(identity.rows.some((r) => r.label === 'SSH host keys' && r.value === 'ssh-rsa'), 'identity: SSH host key')

  const discovery = buildNodeEvidence('discovery', base)
  assert(discovery.rows.some((r) => r.label === 'Scan duration' && r.value === '9.0 s'), 'discovery: real scan duration')

  /* Surface scores are a PROJECTION of the published decomposition, so they exist
     exactly where that model has an applicable category — never wherever findings
     happened to land. */
  const scores = scoreNodesFromCategories(scoreComponents)
  assert(scores.transport !== undefined && scores.certificates !== undefined, 'node scores exist for measured surfaces')
  assert(
    scores.identity === undefined,
    `identity has no published category, so it must carry no posture score (${scores.identity})`,
  )
  assert(
    identity.scoreBasis.includes('no category for this surface'),
    'identity states WHY it is unscored rather than showing a blank',
  )

  /* THE CONTRADICTION THIS WHOLE MODEL EXISTS TO PREVENT.
     Every surface score must be reproducible from the same weighted categories
     that produced the composite, so a card can never grade a run differently
     from the gauge it surrounds. */
  const componentsByKey = new Map(scoreComponents.map((component) => [component.key, component]))
  for (const [node, categories] of Object.entries(SCANNER_NODE_CATEGORIES)) {
    const measured = categories
      .map((key) => componentsByKey.get(key))
      .filter((component) => component && component.score !== null)
    if (measured.length === 0) {
      assert(scores[node] === undefined, `${node}: no measured category ⇒ no score (${scores[node]})`)
      continue
    }
    const weight = measured.reduce((sum, c) => sum + c!.weight, 0)
    const expected = Math.round(measured.reduce((sum, c) => sum + c!.score! * c!.weight, 0) / weight)
    assert(scores[node] === expected, `${node}: score is the published weighted mean (${scores[node]} vs ${expected})`)
  }

  /* Each published category belongs to exactly one surface: no measurement is
     counted twice across cards, and none is silently dropped. */
  const mapped = Object.values(SCANNER_NODE_CATEGORIES).flat()
  assert(new Set(mapped).size === mapped.length, 'no published category is claimed by two surfaces')
  for (const component of scoreComponents) {
    assert(mapped.includes(component.key), `published category "${component.key}" is claimed by a surface`)
  }

  // Every blueprint key must be routable — a card with no module mapping would
  // never light up.
  for (const blueprint of SCANNER_NODE_BLUEPRINTS) {
    const evidence = buildNodeEvidence(blueprint.key, base)
    assert(evidence.rows.length > 0 || evidence.emptyReason !== null, `${blueprint.key}: has rows or an explicit reason`)
  }
}

/** A summary rebuilt from stored finding severities aggregates differently from
 *  the per-target weighted model. The page must SAY so rather than silently
 *  showing one number under a decomposition that implies another. */
function verifyDivergentSummary() {
  console.log('\n=== Divergent summary — reconciliation is surfaced, not hidden ===')
  const a = buildAssessment({
    ...POPULATED,
    // buildSummaryFromStoredFindings(): 1*18 + 2*10 + 0*5 + 1*2 = 40
    summary: { ...POPULATED.summary!, riskScore: 40, qScore: 60 },
  })
  assert(a.executive.encryptionScore === 60, `Composite still the backend qScore (${a.executive.encryptionScore})`)
  assert(a.decompositionScore === 51, `Decomposition still the published model (${a.decompositionScore})`)
  assert(a.decompositionAgrees === false, 'Divergence is flagged for the UI to explain')
}

/** The bug that made /dashboard/scanner disagree with /public-scan: a dimension
 *  the scan never measured was scored as a PERFECT posture and pulled the
 *  composite up. It must be excluded and its weight redistributed. */
function verifyUnmeasuredDimensionExcluded() {
  console.log('\n=== Unmeasured category is excluded, not scored 100 ===')
  const noHttpEvidence: AssessmentInput = {
    ...POPULATED,
    results: [
      {
        ...RESULTS[0],
        metadata: {
          ...RESULTS[0].metadata,
          apiSecurityResult: null,
          // No HTTP response, so headers and HSTS join the three public-edge
          // probes as inapplicable: 88 - 8 - 5 = 75 of weight remains.
          scoreCategories: (RESULTS[0].metadata!.scoreCategories ?? []).map((category) =>
            category.key === 'http-security-headers' || category.key === 'hsts'
              ? { ...category, score: 0, applicable: false, observed: 'not observable from an authenticated network scan' }
              : category,
          ),
          riskMeasuredWeight: 75,
        },
      },
    ],
  }
  const a = buildAssessment(noHttpEvidence)
  const headerCategory = a.scoreComponents.find((c) => c.key === 'http-security-headers')
  assert(headerCategory?.score === null, `Unprobed headers report "not measured", not 100 (${headerCategory?.score})`)
  assert(a.scoreComponents.length === 12, 'All twelve categories are still listed')
  // (45*18 + 35*15 + 80*12 + 70*12 + 70*10 + 40*5 + 15*3) / 75 = 4080/75 = 54.4 -> 54
  assert(a.decompositionScore === 54, `Weight redistributed over the measured 75 (${a.decompositionScore}, expected 54)`)
  const measuredWeights = a.scoreComponents.filter((c) => c.score !== null).reduce((sum, c) => sum + c.weight, 0)
  assert(measuredWeights === 75, `Only 75 of 100 weight contributed (${measuredWeights})`)
}

function verifyEmpty() {
  const a = buildAssessment(EMPTY)
  console.log('\n=== Empty tenant — no fabricated values ===')
  assert(a.hasEvidence === false, 'hasEvidence=false')
  assert(a.executive.gradeable === false && a.executive.grade === '—', 'Grade withheld, not defaulted to F')
  assert(a.executive.businessRisk === 'Not assessable', `Business risk not assessable (${a.executive.businessRisk})`)
  assert(a.executive.migrationComplexity === 'Unknown', 'Migration complexity Unknown')
  assert(a.scoreComponents.every((c) => c.score === null), 'Every category reports "not measured", never 0')
  assert(a.recommendations.length === 0, 'No generic recommendations invented')
  assert(a.intelligence.observedAlgorithms.length === 0, 'No algorithms invented')
  assert(a.intelligence.quantumVulnerability === 'Unknown', 'Quantum vulnerability Unknown')
  assert(a.attackSurface.every((item) => item.status === 'unknown'), 'Every unmeasured surface control is Unknown, never fail')
  assert(a.hndl.window === null, 'No break window modelled without evidence')
  assert(a.decompositionScore === null, 'No decomposition score without a measured model')

  const evidence = buildNodeEvidence('transport', { results: [], findings: [], modules: [], scanner2: null, targets: [], linked: { cbom: 0, assets: 0, exposures: 0 }, scoreComponents: a.scoreComponents })
  assert(evidence.rows.length === 0 && evidence.emptyReason !== null, 'Node panel states why it is empty')
  assert(evidence.score === null, 'No node score without measurements')
}


/* ─────────────────────────────── the twelve lower panels: one population ── */

/**
 * Cross-panel reconciliation for the result stack below the discovery ring.
 *
 * Every assertion here is a contradiction that shipped: two panels describing
 * the same measurement with different numbers, or a sentence describing a
 * different population from the number it is attached to.
 */
function verifyLowerPanels() {
  console.log('\n=== Lower panels — one population, one number ===')
  const a = buildAssessment(POPULATED)

  /* ── Static RSA: counted once ──────────────────────────────────────────
     The Observed Attack Surface row matched `/(^|_)RSA_WITH/`, which also
     matches `TLS_ECDHE_RSA_WITH_…` — a forward-secret suite. It published
     "6 static-RSA key-transport suite(s)" while Transport & Ciphers, matching
     on the parsed key exchange, published "4". */
  const cipherRow = a.attackSurface.find((item) => item.key === 'cipher')
  const transport = buildNodeEvidence('transport', {
    results: RESULTS, findings: FINDINGS, modules: MODULES, scanner2: SCANNER2,
    targets: POPULATED.targets, linked: POPULATED.linked, scoreComponents: a.scoreComponents,
  })
  const staticRsaRow = transport.rows.find((row) => row.label === 'Static RSA accepted')
  const surfaceCount = Number(cipherRow?.detail.match(/(\d+) static-RSA/)?.[1] ?? -1)
  const panelCount = Number(staticRsaRow?.value.match(/(\d+) suite/)?.[1] ?? -1)
  assert(
    surfaceCount === panelCount,
    `Static-RSA suites are counted once for the whole page (surface=${surfaceCount}, panel=${panelCount})`,
  )
  assert(
    !/ECDHE/i.test(cipherRow?.detail ?? '') || surfaceCount === panelCount,
    'A forward-secret ECDHE_RSA suite is never counted as static RSA key transport',
  )

  /* ── HTTP security headers: one model ──────────────────────────────────
     The Code & Dependencies row counted every probed header including HSTS;
     the attack-surface row counts the edge model's APPLICABLE set with HSTS on
     its own row. The same scan read "2/10 hardened" and "1/8 hardened". */
  const headerRow = a.attackSurface.find((item) => item.key === 'headers')
  const code = buildNodeEvidence('code', {
    results: RESULTS, findings: FINDINGS, modules: MODULES, scanner2: SCANNER2,
    targets: POPULATED.targets, linked: POPULATED.linked, scoreComponents: a.scoreComponents,
  })
  const codeHeaderRow = code.rows.find((row) => row.label === 'Security headers')
  assert(
    Boolean(headerRow) && Boolean(codeHeaderRow) && headerRow!.value === codeHeaderRow!.value,
    `Header hardening is one measurement (surface="${headerRow?.value}", code="${codeHeaderRow?.value}")`,
  )

  /* ── Observed Algorithms never contradicts the Key Exchange verdict ────
     `tls.keyExchange` degrades to the literal "ECDHE (TLS 1.3 key_share)" on
     every TLS 1.3 endpoint, and adding it published a quantum-vulnerable key
     agreement on the same panel whose verdict read hybrid-protected. */
  assert(
    a.intelligence.observedAlgorithms.every((entry) => !/key_share/i.test(entry.name)),
    `The socket's TLS 1.3 placeholder is never published as an observed algorithm (${a.intelligence.observedAlgorithms.map((e) => e.name).join(', ')})`,
  )

  /* ── Components are cryptography, not every finding ────────────────────
     "Crypto Components" printed the raw finding total, so detection-rule
     observations ("Regulatory Compliance Gap") were counted as inventory and
     the tile could not be reconciled against CBOM for the same scan. */
  const componentTile = a.footprint.metrics.find((metric) => metric.key === 'components')
  assert(
    componentTile?.value === a.footprint.components.total,
    `The component tile reads the derived component count (${componentTile?.value} vs ${a.footprint.components.total})`,
  )
  assert(
    a.footprint.components.total + a.footprint.components.policyFindings === FINDINGS.length,
    `Components + policy findings account for every finding (${a.footprint.components.total} + ${a.footprint.components.policyFindings} vs ${FINDINGS.length})`,
  )
  assert(
    a.footprint.components.vulnerable <= a.footprint.components.total,
    'Quantum-vulnerable components cannot exceed the component population',
  )

  /* ── Recommendations join through the rule that produced them ──────────
     `affected` used a raw substring match while the recommendation came from
     the Scanner_2 normalizer, so every card reported 0 affected and printed
     "no finding in the current view uses it" — contradicting its own
     existence. */
  for (const recommendation of a.recommendations) {
    assert(
      !/no finding in the current view uses it/i.test(recommendation.businessImpact) || recommendation.affected === 0,
      `"${recommendation.title}" does not deny the evidence that generated it`,
    )
  }
  assert(
    a.recommendations.every((recommendation) => !/^Replace (.+) with \1/i.test(recommendation.title)),
    'No card recommends replacing an algorithm with itself',
  )
  assert(
    a.recommendations.every((recommendation) => !/no migration needed/i.test(recommendation.rationale)),
    'A "No Migration Needed" catalogue entry never occupies a recommendation card',
  )

  /* ── The timeline states what its number measures ──────────────────────
     "78% ready" was captioned "A majority of discovered components are already
     quantum-safe" on a scan whose footprint counted most components
     vulnerable. */
  const migrationPhase = a.timeline.find((phase) => phase.key === 'migration')
  assert(
    Boolean(migrationPhase) && !/majority of discovered components/i.test(migrationPhase!.description),
    'The migration phase does not describe a readiness score as a share of components',
  )

  /* ── Plural forms ─────────────────────────────────────────────────────────
     The previous pattern tested `observations\b(?= in this assessment resolve)`,
     which fires on the CORRECT plural ("2 observations … resolve") and never on
     the defect it was written for ("1 observation … resolve"). It was inverted,
     so it failed a well-formed sentence while the malformed one it was guarding
     sailed past. Each clause below names one specific disagreement between a
     count and the verb or noun that follows it. */
  const counted = `${a.executive.migrationComplexityDetail} ${a.recommendations
    .map((row) => row.businessImpact)
    .join(' ')}`
  const grammarDefects: Array<[RegExp, string]> = [
    [/familys/, 'pluralised "family" as "familys"'],
    [/\b1 (observations|algorithm families|assets|components|findings)\b/, 'a count of 1 with a plural noun'],
    [/\b1 [a-z]+(?: [a-z]+)? (resolve|require|are|have)\b/, 'a count of 1 with a plural verb'],
    [/\b(?!1\b)\d+ [a-z]+(?: [a-z]+)? (resolves|requires)\b/, 'a count above 1 with a singular verb'],
  ]
  for (const [pattern, description] of grammarDefects) {
    assert(!pattern.test(counted), `Counted nouns agree with their verbs — no ${description}`)
  }
}

verifyPopulated()
verifyModuleLedgerContract()
verifySingleSourceOfTruth()
verifyNodeEvidence()
verifyDivergentSummary()
verifyUnmeasuredDimensionExcluded()
verifyLowerPanels()
verifyEmpty()
/* ===========================================================================
   Cross-panel accuracy audit, round 2.

   One invariant per finding in tasks/todo.md. Each was reproduced against a
   live scan of the reported target before it was written; none is hypothetical.
   =========================================================================== */

function verifyCrossPanelAudit() {
  console.log('\n=== Cross-panel accuracy audit ===')

  /* -- R1. A negative post-quantum verdict needs a measured refusal -------- */
  const settledRefusal = measuredKeyAgreement({
    pqKeyAgreement: {
      hybridGroups: [], pureKemGroups: [], classicalGroups: ['X25519'], primaryGroup: null,
      kemParameterSets: [], classicalComponent: null, postQuantumComponent: null,
      probed: true, hybridProbed: true,
      hybridGroupsSettled: ['X25519MLKEM768'], hybridGroupsInconclusive: [],
      handshakes: 9, inconclusiveGroups: [], unstableGroups: [], untestableGroups: [],
      confidence: 100, value: 'Not offered', state: 'fail', detail: '', evidence: [],
    },
  } as never)
  const throttled = measuredKeyAgreement({
    pqKeyAgreement: {
      hybridGroups: [], pureKemGroups: [], classicalGroups: ['X25519'], primaryGroup: null,
      kemParameterSets: [], classicalComponent: null, postQuantumComponent: null,
      probed: true, hybridProbed: true,
      hybridGroupsSettled: [], hybridGroupsInconclusive: ['X25519MLKEM768', 'SecP256r1MLKEM768'],
      handshakes: 4, inconclusiveGroups: ['X25519MLKEM768', 'SecP256r1MLKEM768'],
      unstableGroups: [], untestableGroups: [],
      confidence: 40, value: 'Not measured', state: 'unknown', detail: '', evidence: [],
    },
  } as never)
  assert(settledRefusal.hybridSettled, 'A conclusively refused hybrid group counts as settled')
  assert(
    !throttled.hybridSettled,
    'A hybrid probe that never settled is NOT a refusal - the root cause of the reported screenshot',
  )
  assert(
    classifyQuantumVulnerability({
      hasTransportEvidence: true, hybridObserved: false, pqSignatureObserved: false,
      quantumRisk: 'Critical', hybridProbed: true, hybridMeasured: false, supportsTls13: true,
    }).vulnerability === 'Unknown',
    'An unsettled hybrid probe withholds the quantum verdict instead of publishing "Vulnerable"',
  )
  assert(
    classifyQuantumVulnerability({
      hasTransportEvidence: true, hybridObserved: false, pqSignatureObserved: false,
      quantumRisk: 'Critical', hybridProbed: true, hybridMeasured: true, supportsTls13: true,
    }).vulnerability === 'Vulnerable',
    'NEGATIVE CONTROL - a measured refusal still publishes "Vulnerable"',
  )

  /* The readiness category is excluded, never scored from a missing hybrid
     signal that carries 55 of its 100 points. */
  /* The edge bundle a throttled run leaves behind: classical groups settled,
     every hybrid group inconclusive. Hoisted because the degraded end-to-end
     assertion below has to attach the SAME bundle to the scan record — without
     it the assessment takes its "no transport evidence at all" fallback, which
     is a different code path answering a different question. */
  const UNSETTLED_EDGE = {
    transport: { supportedProtocols: ['TLSv1.2', 'TLSv1.3'], legacyProtocols: [], staticRsaAccepted: false },
    certificate: { probed: false },
    dns: { probed: false },
    http: {
      headers: [], hsts: { present: false, status: '', maxAge: null },
      fingerprint: {
        server: null, poweredBy: null, cdn: null, waf: null, cloudProvider: null,
        reverseProxy: null, signals: [],
      },
      probed: false, reachable: false, error: null,
    },
    quantum: {
      pqSignatureObserved: false, postQuantumReadiness: 6, readinessReasons: [],
      riskFactors: [], migrationTargets: [], vulnerability: 'Unknown', vulnerabilityReason: '',
      hybridObserved: false, keyExchange: 'ECDHE (X25519)', forwardSecrecy: 'Enabled',
    },
    pqKeyAgreement: {
      hybridGroups: [], pureKemGroups: [], classicalGroups: ['X25519'], primaryGroup: null,
      kemParameterSets: [], classicalComponent: null, postQuantumComponent: null,
      probed: true, hybridProbed: true,
      hybridGroupsSettled: [], hybridGroupsInconclusive: ['X25519MLKEM768'],
      handshakes: 4, inconclusiveGroups: ['X25519MLKEM768'], unstableGroups: [], untestableGroups: [],
      confidence: 40, value: 'Not measured', state: 'unknown', detail: '', evidence: [],
    },
  }

  const unsettledCategories = buildPublishedCategories({
    tlsResult: {
      tlsVersion: 'TLSv1.3', cipherSuite: 'TLS_AES_256_GCM_SHA384',
      keyExchange: 'ECDHE (TLS 1.3 key_share)', signatureAlgorithm: 'sha256WithRSAEncryption',
      supportedProtocols: ['TLSv1.2', 'TLSv1.3'], protocolSupport: [], negotiatedCurve: null,
      serverName: 'example.test', peerCertificate: null, cipherSuites: [],
      ephemeralKeyType: null, ephemeralKeySize: null,
    } as never,
    certInfo: null, apiResult: null, repoResult: null, webCryptoResult: null,
    ruleResults: [], findings: [],
    edgeIntelligence: UNSETTLED_EDGE as never,
  })
  const readinessRow = unsettledCategories.find((row) => row.key === 'post-quantum-readiness')!
  assert(
    !readinessRow.applicable,
    'Post-Quantum Readiness is excluded - not scored 0 - when the hybrid probe never settled',
  )
  assert(
    /did not settle/i.test(readinessRow.observed),
    'The exclusion states why, so the row never reads as a silent zero',
  )
  const kexRow = unsettledCategories.find((row) => row.key === 'key-exchange')!
  assert(
    !/offered in isolation and refused/i.test(kexRow.observed),
    'The Key Exchange row does not claim a refusal that was never measured',
  )

  /* -- R2. One observation, one owner ------------------------------------- */
  const legacyCensus = buildAlgorithmCensus({
    observations: [
      {
        tls: {
          keyExchange: null, negotiatedCurve: null, signatureAlgorithm: null,
          cipherSuites: [], supportedProtocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'],
        },
        certificate: { publicKeyAlgorithm: 'RSA', signatureAlgorithm: 'sha256WithRSAEncryption', chain: [] },
        keyAgreement: {
          probed: true, hybrid: true, kemApplied: true,
          group: 'X25519MLKEM768',
          classicalComponent: 'X25519 (Curve25519 ECDHE)', postQuantumComponent: 'ML-KEM-768 (FIPS 203)',
          kemParameterSets: ['ML-KEM-768'],
        },
      },
    ],
    patterns: [],
  })
  assert(
    legacyCensus.classicallyBroken.length === 0,
    'Deprecated PROTOCOLS are not counted as classically broken ALGORITHMS',
  )
  assert(
    legacyCensus.legacyProtocols.length === 2,
    `Legacy protocols are still reported as context (${legacyCensus.legacyProtocols.join(', ')})`,
  )
  assert(
    /scored under TLS Configuration/i.test(legacyCensus.summary),
    'The census hands the protocol penalty to the category that owns it, by name',
  )
  assert(
    legacyCensus.score !== null && legacyCensus.score > 0,
    `A hybrid endpoint with legacy protocols no longer scores 0 for its algorithms (${legacyCensus.score})`,
  )

  /* -- R3. One algorithm, one row ----------------------------------------- */
  const mlkemRows = legacyCensus.entries.filter((entry) => /^ML-KEM-768/i.test(entry.name))
  assert(
    mlkemRows.length === 1,
    `ML-KEM-768 and "ML-KEM-768 (FIPS 203)" are one algorithm, not two (${mlkemRows.map((r) => r.name).join(' | ')})`,
  )
  assert(
    mlkemRows[0]?.name === 'ML-KEM-768 (FIPS 203)',
    'The surviving row keeps the more informative spelling, with its standard',
  )
  assert(
    legacyCensus.observed === legacyCensus.entries.length,
    'The declared total is the row count - the panel and the score row cannot disagree',
  )

  /* -- R5. The two flanks reproduce the gauge ------------------------------ */
  const a = buildAssessment(POPULATED)
  const split = a.postureSplit
  assert(
    split.classical.weightShare + split.postQuantum.weightShare === 100,
    `Classical and post-quantum weight shares are taken over the measured model and sum to 100 (${split.classical.weightShare} + ${split.postQuantum.weightShare})`,
  )
  if (split.classical.score !== null && split.postQuantum.score !== null && a.decompositionScore !== null) {
    const recomposed = Math.round(
      (split.classical.score * split.classical.weightShare + split.postQuantum.score * split.postQuantum.weightShare) /
        100,
    )
    assert(
      Math.abs(recomposed - a.decompositionScore) <= 1,
      `The two flanks re-aggregate to the gauge (${recomposed} vs ${a.decompositionScore}, rounding only)`,
    )
  }

  /* -- R6. Every decomposition row says what it measures ------------------- */
  assert(
    a.scoreComponents.every((component) => component.description.trim().length > 0),
    'Every published category carries the description of what it measures',
  )
  const pqRows = a.scoreComponents.filter((component) => component.postQuantumRelevant).map((c) => c.key)
  assert(
    pqRows.includes('key-exchange') && pqRows.includes('post-quantum-readiness'),
    'The rows that carry the post-quantum verdict are marked as such',
  )
  assert(
    !pqRows.includes('tls-configuration'),
    'TLS Configuration is NOT marked post-quantum - it scores the protocol version, the prerequisite rather than the evidence',
  )

  /* -- R7. A node score names the categories it projects ------------------- */
  const scopes = nodeScoreScopes(a.scoreComponents)
  for (const [node, score] of Object.entries(a.nodeScores)) {
    assert(
      typeof scopes[node] === 'string' && scopes[node].length > 0,
      `Node "${node}" publishes ${score} and names what it projects (${scopes[node] ?? 'MISSING'})`,
    )
  }
  assert(
    scopes.identity === undefined,
    'A surface with no published category has no score and therefore no scope caption',
  )

  /* -- R8. A KEM never stands in for a signature --------------------------- */
  assert(pqcRole('ML-KEM-768 (FIPS 203)') === 'key-establishment', 'ML-KEM is key establishment')
  assert(pqcRole('ML-DSA-65 (FIPS 204)') === 'signature', 'ML-DSA is a signature scheme')
  for (const name of ['FrodoKEM', 'BIKE', 'HQC', 'Classic McEliece', 'NTRU']) {
    assert(pqcRole(name) === 'key-establishment', `${name} is classified as key establishment`)
  }
  for (const name of ['Falcon-512', 'SPHINCS+-SHA2-128f', 'XMSS', 'SLH-DSA-SHA2-128s']) {
    assert(pqcRole(name) === 'signature', `${name} is classified as a signature scheme`)
  }
  for (const card of a.recommendations) {
    const named = card.title.replace(/^Replace\s+.*?\s+with\s+/i, '').replace(/^Retire\s+.*?\s+-+\s+/i, '')
    const targetRole = pqcRole(named)
    if (!targetRole) continue
    const offered = card.rationale.split('alternatives:')[1] ?? ''
    const crossRole = offered
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry && entry !== 'none published')
      .filter((entry) => {
        const role = pqcRole(entry)
        return role !== null && role !== targetRole
      })
    assert(
      crossRole.length === 0,
      `"${card.title}" offers no cross-role alternative${crossRole.length ? ` (${crossRole.join(', ')})` : ''}`,
    )
  }
  /* -- R10. The negotiated version is not the accepted set ---------------- */
  const unenumerated = buildPublishedCategories({
    tlsResult: {
      tlsVersion: 'TLSv1.3', cipherSuite: 'TLS_AES_128_GCM_SHA256',
      keyExchange: 'ECDHE (TLS 1.3 key_share)', signatureAlgorithm: 'sha256WithRSAEncryption',
      // The per-version probe returned nothing: the endpoint throttled it.
      supportedProtocols: [], protocolSupport: [], negotiatedCurve: null,
      serverName: 'example.test', peerCertificate: null, cipherSuites: [],
      ephemeralKeyType: null, ephemeralKeySize: null,
    } as never,
    certInfo: null, apiResult: null, repoResult: null, webCryptoResult: null,
    ruleResults: [], findings: [], edgeIntelligence: null,
  })
  const tlsRow = unenumerated.find((row) => row.key === 'tls-configuration')!
  assert(
    !tlsRow.applicable,
    'TLS Configuration is withheld when per-version probing returned no list - one handshake cannot rule the other versions out',
  )
  assert(
    /not established|were not established|returned no accepted protocol list/i.test(tlsRow.observed),
    'The withheld TLS Configuration row states why',
  )
  const enumerated = buildPublishedCategories({
    tlsResult: {
      tlsVersion: 'TLSv1.3', cipherSuite: 'TLS_AES_128_GCM_SHA256',
      keyExchange: 'ECDHE (TLS 1.3 key_share)', signatureAlgorithm: 'sha256WithRSAEncryption',
      supportedProtocols: ['TLSv1.3'], protocolSupport: [], negotiatedCurve: null,
      serverName: 'example.test', peerCertificate: null, cipherSuites: [],
      ephemeralKeyType: null, ephemeralKeySize: null,
    } as never,
    certInfo: null, apiResult: null, repoResult: null, webCryptoResult: null,
    ruleResults: [], findings: [], edgeIntelligence: null,
  })
  const tlsRowEnumerated = enumerated.find((row) => row.key === 'tls-configuration')!
  assert(
    tlsRowEnumerated.applicable && tlsRowEnumerated.score === 100,
    `NEGATIVE CONTROL - an enumerated TLS-1.3-only endpoint still scores 100 (${tlsRowEnumerated.score})`,
  )

  /* -- R11. One readiness number per page --------------------------------- */
  /* The two panels describe different POPULATIONS when there is no edge
     measurement — "Endpoint PQ Readiness" has no endpoint to report on, while
     the executive tile can still fall back to an estate-wide share. So the
     contract is not "both always show a number"; it is that the endpoint panel
     may never be MORE confident than the model, and never silent without a
     reason when the model was silent too. */
  assert(
    !(a.executive.postQuantumReadiness === null && a.intelligence.postQuantumReadiness !== null),
    'The endpoint panel never publishes a readiness number the published model withheld',
  )
  if (a.executive.postQuantumReadiness !== null && a.intelligence.postQuantumReadiness !== null) {
    assert(
      a.executive.postQuantumReadiness === a.intelligence.postQuantumReadiness.score,
      `Both panels publish the same readiness number (${a.executive.postQuantumReadiness} vs ${a.intelligence.postQuantumReadiness.score})`,
    )
  }
  assert(
    a.executive.postQuantumReadiness !== null || a.intelligence.postQuantumReadinessReason !== null,
    'A withheld readiness always carries its reason, never a blank',
  )

  /* And the degraded case end to end: the model withholds, so the panel does. */
  const degradedResults = [
    {
      ...POPULATED.results[0],
      metadata: {
        ...POPULATED.results[0].metadata,
        scoreCategories: unsettledCategories,
        edgeIntelligence: UNSETTLED_EDGE,
      },
    },
  ]
  const degraded = buildAssessment({ ...POPULATED, results: degradedResults } as AssessmentInput)
  assert(
    degraded.executive.postQuantumReadiness === null,
    'An unsettled hybrid probe withholds the executive readiness tile',
  )
  assert(
    degraded.intelligence.postQuantumReadiness === null,
    'and the Cryptographic Intelligence panel with it - the 6% beside a "not measured" category is gone',
  )
  assert(
    typeof degraded.intelligence.postQuantumReadinessReason === 'string' &&
      /did not settle/i.test(degraded.intelligence.postQuantumReadinessReason),
    'The panel states the reason the model itself gives for the silence',
  )
  /* And the third place the same number surfaces: the Quantum Posture card's
     own evidence row, which calls itself "the published category". */
  const posture = buildNodeEvidence('posture', {
    results: degradedResults,
    findings: POPULATED.findings,
    modules: POPULATED.modules,
    scanner2: POPULATED.scanner2,
    targets: POPULATED.targets,
    linked: POPULATED.linked,
    scoreComponents: degraded.scoreComponents,
  } as never)
  const readinessRowOnCard = posture.rows.find((row) => row.label === 'PQ readiness · this endpoint')
  assert(
    !readinessRowOnCard || readinessRowOnCard.value === 'Not measured',
    `The Quantum Posture card's readiness row is silent too, not "6%" (${readinessRowOnCard?.value ?? 'absent'})`,
  )
}

verifyCrossPanelAudit()

console.log(failures === 0 ? '\nAll Dashboard Scanner intelligence checks passed.' : `\n${failures} check(s) FAILED`)
process.exit(failures === 0 ? 0 : 1)
