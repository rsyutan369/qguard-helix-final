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
  scoreNodes,
  SCANNER_NODE_BLUEPRINTS,
  type AssessmentInput,
} from '../src/app/dashboard/scanner_dashboard/_intel'
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
    // riskScore is the backend's weighted overall for this target:
    // 28*.25 + 55*.25 + 35*.20 + 40*.15 + 82*.15 = 46.05 -> 46
    riskScore: 46,
    qScore: 54,
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
      riskMeasuredWeight: 100,
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

function moduleState(id: string, name: string, status: ModuleState['status'], findings = 0): ModuleState {
  return { id, name, status, target: 'https://test.example.org', startedAt: NOW, completedAt: status === 'Running' ? null : NOW, durationMs: status === 'Running' ? null : 120, findingsCount: findings, error: status === 'Failed' ? 'boom' : null }
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
  moduleState('jwt-signing-scanner', 'JWT signing algorithm scanner', 'Skipped'),
  moduleState('cbom-generator', 'CBOM generator', 'Completed', 4),
  moduleState('risk-scoring-engine', 'Risk scoring engine', 'Completed', 5),
]

const ESTATE = { totalAssets: 2, totalFindings: 5, criticalFindings: 1, vulnerableAssets: 2, pqcReadiness: 20, riskScore: 46 }

const POPULATED: AssessmentInput = {
  status: 'completed',
  // buildSummary() averages the per-target weighted risk scores, so with one
  // target the summary risk IS that target's overall (46) and qScore is 54.
  summary: { targetsScanned: 2, totalFindings: 5, critical: 1, high: 2, medium: 0, low: 1, safe: 1, vulnerable: 4, pqcReady: 1, riskScore: 46, qScore: 54 },
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
  estate: { totalAssets: 0, totalFindings: 0, criticalFindings: 0, vulnerableAssets: 0, pqcReadiness: 0, riskScore: 0 },
  linked: { cbom: 0, assets: 0, exposures: 0 },
  provenance: 'No evidence yet',
}

/* ------------------------------------------------------------------- checks */

function verifyPopulated() {
  const a = buildAssessment(POPULATED)
  console.log('\n=== Populated scan — every value traces to evidence ===')

  assert(a.hasEvidence === true, 'hasEvidence=true')
  assert(a.executive.encryptionScore === 54, `Composite score is the backend qScore (${a.executive.encryptionScore})`)
  assert(a.executive.gradeable === true && a.executive.grade !== '—', `Grade issued: ${a.executive.grade} (${a.executive.gradeLabel})`)

  /* The decomposition must reproduce the composite it sits under. The backend's
     summary risk score is the MEAN of the per-target weighted scores, and the
     decomposition is the weighted mean of the per-target components — the two
     operations commute, so when the summary came from the weighted model these
     are the same number. */
  const measured = a.scoreComponents.filter((c) => c.score !== null)
  assert(measured.length === 5, `All 5 published categories measured (${measured.length})`)
  assert(a.decompositionScore === 54, `Decomposition weighted mean (${a.decompositionScore})`)
  assert(a.decompositionAgrees === true, `Decomposition reconciles with the composite (${a.decompositionScore} vs ${a.executive.encryptionScore})`)

  assert(a.executive.confidence === 75, `Confidence read from scanConfidence (${a.executive.confidence})`)
  assert(a.executive.businessRisk === 'High' || a.executive.businessRisk === 'Critical', `Critical finding floors business risk (${a.executive.businessRisk})`)
  assert(a.executive.migrationComplexity === 'High', `Migration complexity from the migration engine (${a.executive.migrationComplexity})`)
  assert(a.executive.postQuantumReadiness === 20, `PQ readiness = pqcReady/total (${a.executive.postQuantumReadiness}%)`)

  const pfs = a.attackSurface.find((item) => item.key === 'pfs')
  assert(
    pfs?.value === 'Partial - static RSA accepted' && pfs.status === 'partial',
    `Forward secrecy downgraded because static-RSA suites are accepted (${pfs?.value})`,
  )

  const validity = a.attackSurface.find((item) => item.key === 'cert-validity')
  assert(validity !== undefined && validity.status !== 'unknown', `Certificate validity is reported (${validity?.value})`)
  const chainTrust = a.attackSurface.find((item) => item.key === 'chain-trust')
  assert(chainTrust?.value.startsWith('Trusted'), `Chain trust is reported (${chainTrust?.value})`)
  const certKey = a.attackSurface.find((item) => item.key === 'cert-key')
  assert(certKey?.value === 'ECDSA 256-bit', `Certificate key is not duplicated (${certKey?.value})`)
  const headerItem = a.attackSurface.find((item) => item.key === 'headers')
  assert(headerItem?.value === '1/3 hardened', `Headers read from the probe, not finding rows (${headerItem?.value})`)
  const tlsItem = a.attackSurface.find((item) => item.key === 'tls-version')
  assert(tlsItem?.value === 'TLSv1.3', `TLS protocol read from the analyzer (${tlsItem?.value})`)

  assert(a.intelligence.keyExchange.includes('ECDHE') && a.intelligence.keyExchange.includes('X25519'), `Key exchange from the TLS analysis (${a.intelligence.keyExchange})`)
  assert(a.intelligence.forwardSecrecy === 'Enabled', `Intelligence forward secrecy agrees with the surface (${a.intelligence.forwardSecrecy})`)
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
}

function verifyNodeEvidence() {
  console.log('\n=== Node evidence — real measurements per surface ===')
  const base = { results: RESULTS, findings: FINDINGS, modules: MODULES, scanner2: SCANNER2, targets: POPULATED.targets, linked: POPULATED.linked }

  const transport = buildNodeEvidence('transport', base)
  assert(transport.rows.some((r) => r.label === 'Negotiated protocol' && r.value === 'TLSv1.3'), 'transport: negotiated protocol')
  assert(transport.rows.some((r) => r.label === 'Protocols accepted' && r.value.includes('TLSv1.0')), 'transport: legacy protocol surfaced')
  assert(transport.rows.some((r) => r.label === 'Suites enumerated' && r.value.includes('1 quantum-vulnerable')), 'transport: quantum-vulnerable suite counted')
  assert(transport.rows.some((r) => r.label === 'Ephemeral key' && r.value.includes('X25519')), 'transport: ephemeral key')
  assert(transport.modules.length === 3, `transport: 3 modules attributed (${transport.modules.length})`)

  const certificates = buildNodeEvidence('certificates', base)
  assert(certificates.rows.some((r) => r.label === 'Public key' && r.value === 'ECDSA 256'), 'certificates: public key')
  assert(certificates.rows.some((r) => r.label === 'Issuer' && r.value === 'Example CA R3'), 'certificates: issuer CN')
  assert(certificates.rows.some((r) => r.label === 'Chain' && r.value === '2 certificate(s)'), 'certificates: chain depth')
  assert(certificates.rows.some((r) => r.label === 'Validity' && r.value.includes('day')), 'certificates: days remaining computed')

  const code = buildNodeEvidence('code', base)
  assert(code.rows.some((r) => r.label === 'Security headers' && r.value === '1/3 hardened'), 'code: header hardening counted')
  assert(code.rows.some((r) => r.label === 'API endpoints probed' && r.value === '6'), 'code: endpoints probed')

  const posture = buildNodeEvidence('posture', base)
  assert(posture.rows.some((r) => r.label === 'Quantum readiness' && r.value.startsWith('20%')), 'posture: Scanner_2 readiness')
  assert(posture.rows.some((r) => r.label === 'Break window' && r.value === '2030–2035'), 'posture: break window')
  assert(posture.rows.some((r) => r.label === 'Harvest-now exposure' && r.value.includes('1 immediate')), 'posture: HNDL urgency')

  const identity = buildNodeEvidence('identity', base)
  assert(identity.rows.some((r) => r.label === 'SSH host keys' && r.value === 'ssh-rsa'), 'identity: SSH host key')

  const discovery = buildNodeEvidence('discovery', base)
  assert(discovery.rows.some((r) => r.label === 'Scan duration' && r.value === '9.0 s'), 'discovery: real scan duration')

  // Node posture scores must exist only where findings were routed.
  const scores = scoreNodes(FINDINGS)
  assert(scores.transport !== undefined && scores.certificates !== undefined, 'node scores exist for measured surfaces')
  assert(scores.posture === undefined, 'no node score invented for a surface with no findings')

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
  assert(a.decompositionScore === 54, `Decomposition still the weighted model (${a.decompositionScore})`)
  assert(a.decompositionAgrees === false, 'Divergence is flagged for the UI to explain')
}

/** The bug that made /dashboard/scanner disagree with /public-scan: a dimension
 *  the scan never measured was scored as a PERFECT posture and pulled the
 *  composite up. It must be excluded and its weight redistributed. */
function verifyUnmeasuredDimensionExcluded() {
  console.log('\n=== Unmeasured dimension is excluded, not scored 100 ===')
  const withoutAppCrypto: AssessmentInput = {
    ...POPULATED,
    results: [
      {
        ...RESULTS[0],
        metadata: {
          ...RESULTS[0].metadata,
          apiSecurityResult: null,
          riskBreakdown: { certificateRisk: 60, tlsConfigRisk: 55, cipherSuiteRisk: 75, appCryptoRisk: 0, pqcReadiness: 100 },
          riskBreakdownApplicable: { certificateRisk: true, tlsConfigRisk: true, cipherSuiteRisk: true, appCryptoRisk: false, pqcReadiness: true },
          riskMeasuredWeight: 85,
        },
      },
    ],
  }
  const a = buildAssessment(withoutAppCrypto)
  const appCrypto = a.scoreComponents.find((c) => c.key === 'appCryptoRisk')
  assert(appCrypto?.score === null, `Application Cryptography reports "not measured", not 100 (${appCrypto?.score})`)
  assert(appCrypto?.observed.startsWith('Not measured'), 'The row states why it was excluded')
  // (100-60)*25 + (100-55)*25 + (100-75)*20 + (100-100)*15 = 1000+1125+500+0 = 2625 / 85
  assert(a.decompositionScore === 31, `Weight redistributed over the measured 85 (${a.decompositionScore}, expected 31)`)
  const measuredWeights = a.scoreComponents.filter((c) => c.score !== null).reduce((sum, c) => sum + c.weight, 0)
  assert(measuredWeights === 85, `Only 85 of 100 weight contributed (${measuredWeights})`)
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

  const evidence = buildNodeEvidence('transport', { results: [], findings: [], modules: [], scanner2: null, targets: [], linked: { cbom: 0, assets: 0, exposures: 0 } })
  assert(evidence.rows.length === 0 && evidence.emptyReason !== null, 'Node panel states why it is empty')
  assert(evidence.score === null, 'No node score without measurements')
}

verifyPopulated()
verifyNodeEvidence()
verifyDivergentSummary()
verifyUnmeasuredDimensionExcluded()
verifyEmpty()
console.log(failures === 0 ? '\nAll Dashboard Scanner intelligence checks passed.' : `\n${failures} check(s) FAILED`)
process.exit(failures === 0 ? 0 : 1)
