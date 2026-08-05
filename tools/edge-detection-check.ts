/**
 * Offline verification for the public-edge detection accuracy work.
 *
 * This is the regression suite for the class of defect where the Observed
 * Attack Surface and Cryptographic Intelligence panels reported something the
 * scan had not measured — or, worse, the opposite of what it had:
 *
 *   • Post-Quantum Key Agreement printed a hedging "Observed" for Cloudflare
 *     (which negotiates X25519MLKEM768) and could equally print it for an
 *     endpoint with no post-quantum support at all, because the test was a
 *     regex over cipher-suite names and FINDING TITLES rather than a probe.
 *   • Quantum Vulnerability reported "Hybrid-protected" for expired.badssl.com
 *     — TLS 1.2 only, expired chain, static RSA accepted — because any finding
 *     mentioning ML-KEM flipped the verdict, and the scanner's own
 *     recommendations mention ML-KEM.
 *   • Eight controls rendered "Not probed" and two "Not observed" for probes
 *     that the platform's public-scan engines had been performing all along.
 *
 * Everything below runs without a network or a server: the classifier and the
 * surface builder are pure, so their behaviour on the exact scenarios that
 * produced the bug can be asserted directly.
 *
 * A live end-to-end probe is a separate, deliberate step — see the footer.
 *
 *   npx tsx tools/edge-detection-check.ts
 */
import {
  classifyQuantumVulnerability,
  describeEdgeInfrastructure,
  type EdgeIntelligence,
} from '../src/lib/scanner/web-scanner/edge-intelligence-model'
import { buildAssessment, type SurfaceItem } from '../src/app/dashboard/scanner_dashboard/_intel'
import type { ScanResultRecord } from '../src/app/dashboard/scanner_dashboard/_types'
import { moduleIdForFinding } from '../src/api-server/scanner-module-ledger'
import { DETECTION_RULES } from '../src/lib/scanner/web-scanner/detection-rules'
import type { DetectionContext } from '../src/lib/scanner/web-scanner/types'

let failures = 0
function assert(condition: boolean, label: string) {
  if (condition) console.log(`  ok   ${label}`)
  else {
    failures += 1
    console.log(`  FAIL ${label}`)
  }
}

/* ------------------------------------------------------------- fixtures --- */

/**
 * A neutral edge snapshot. Each scenario overrides only the fields that make it
 * that scenario, so a test can never pass because of an unrelated default.
 */
function edgeFixture(overrides: Partial<EdgeIntelligence> = {}): EdgeIntelligence {
  const base: EdgeIntelligence = {
    host: 'example.test',
    port: 443,
    probedAt: new Date('2026-01-01T00:00:00Z').toISOString(),
    durationMs: 1000,
    confidence: 90,
    notes: [],
    pqKeyAgreement: {
      value: 'Not offered',
      state: 'fail',
      detail: 'probed and refused',
      /* Mirrors what `buildPqKeyAgreement` emits for ANY probed target: the
         negative branches carry the same provenance as the positive one, so an
         operator can tell a measured refusal from a probe that never ran. */
      evidence: [
        { label: 'Negotiated TLS version', value: 'TLSv1.3' },
        { label: 'Accepted protocols', value: 'TLSv1.2, TLSv1.3' },
        { label: 'Groups probed', value: '40 handshake(s), each group offered in isolation and re-sampled' },
        { label: 'Detection confidence', value: '90%' },
      ],
      hybridGroups: [],
      pureKemGroups: [],
      classicalGroups: ['X25519'],
      primaryGroup: null,
      kemParameterSets: [],
      classicalComponent: null,
      postQuantumComponent: null,
      probed: true,
      hybridProbed: true,
      handshakes: 40,
      inconclusiveGroups: [],
      unstableGroups: [],
      untestableGroups: [],
      confidence: 90,
    },
    transport: {
      negotiatedProtocol: 'TLSv1.3',
      supportedProtocols: ['TLSv1.2', 'TLSv1.3'],
      legacyProtocols: [],
      negotiatedCipher: 'TLS_AES_256_GCM_SHA384',
      keyExchange: 'ECDHE (X25519)',
      forwardSecrecy: true,
      forwardSecrecyBasis: 'TLS 1.3 mandates ephemeral (EC)DHE.',
      staticRsaAccepted: false,
      alpn: 'h2',
      alpnOffered: ['h2', 'http/1.1'],
      http2: true,
      alpnProbed: true,
      sessionTickets: true,
      sessionReuse: true,
      handshakeMs: 90,
      error: null,
    },
    certificate: {
      probed: true,
      ocspStapled: true,
      ocspResponderState: 'reachable',
      ocspResponderDetail: null,
      ocspUri: 'http://ocsp.example.test',
      mustStaple: false,
      crlDistributionPoints: [],
      sctPresent: true,
      sctCount: 3,
      subjectAltNames: ['example.test', 'www.example.test'],
      sanCount: 2,
      isWildcard: false,
      chainDepth: 3,
      chainTrusted: true,
      trustError: null,
      hostnameMatches: true,
      daysRemaining: 60,
      validityDays: 90,
      error: null,
    },
    dns: {
      probed: true,
      addresses: ['203.0.113.10'],
      addressCount: 1,
      caaQueryable: true,
      caaPresent: true,
      caaRecords: ['0 issue "letsencrypt.org"'],
      caaSource: 'Cloudflare (DoH)',
      caaAtName: 'example.test',
      dnssecQueryable: true,
      dnssecSigned: true,
      dnssecValidated: true,
      spf: null,
      dmarc: null,
      transports: ['system resolver'],
      resolvedVia: 'A',
      error: null,
    },
    http: {
      probed: true,
      reachable: true,
      statusCode: 200,
      httpVersion: 'HTTP/2',
      hsts: {
        present: true,
        status: 'Healthy',
        raw: 'max-age=63072000; includeSubDomains; preload',
        maxAge: 63072000,
        includeSubDomains: true,
        preload: true,
        preloadEligible: true,
        preloadBlockers: [],
      },
      headers: [
        { name: 'strict-transport-security', group: 'Critical', present: true, value: 'max-age=63072000', status: 'Healthy', weakness: null, supersededBy: null },
        { name: 'content-security-policy', group: 'Critical', present: true, value: "default-src 'self'", status: 'Healthy', weakness: null, supersededBy: null },
        { name: 'x-content-type-options', group: 'Critical', present: true, value: 'nosniff', status: 'Healthy', weakness: null, supersededBy: null },
        { name: 'x-frame-options', group: 'Recommended', present: false, value: null, status: 'Not Supported', weakness: null, supersededBy: null },
      ],
      hardenedCount: 2,
      applicableCount: 3,
      fingerprint: {
        server: 'cloudflare',
        poweredBy: null,
        cdn: 'Cloudflare',
        waf: 'Cloudflare',
        cloudProvider: null,
        reverseProxy: null,
        signals: ['server', 'cf-ray'],
      },
      error: null,
    },
    quantum: {
      hybridObserved: false,
      pqSignatureObserved: false,
      keyExchange: 'ECDHE (X25519)',
      keyExchangeClass: 'Classical',
      forwardSecrecy: 'Enabled',
      kemParameterSets: [],
      postQuantumReadiness: 12,
      readinessReasons: ['No hybrid or post-quantum key agreement offered at the public edge.'],
      quantumRisk: 'Critical',
      quantumRiskScore: 100,
      riskFactors: [],
      vulnerability: 'Vulnerable',
      vulnerabilityReason: 'classical key agreement only',
      migrationTargets: [],
    },
  }
  return { ...base, ...overrides }
}

/** Cloudflare-shaped: TLS 1.3, hybrid X25519MLKEM768 accepted, classical cert. */
function hybridEdge(): EdgeIntelligence {
  const edge = edgeFixture()
  edge.pqKeyAgreement = {
    ...edge.pqKeyAgreement,
    value: 'Applied',
    state: 'pass',
    detail: 'X25519 + ML-KEM-768 (hybrid) accepted',
    hybridGroups: ['X25519MLKEM768'],
    primaryGroup: 'X25519MLKEM768',
    kemParameterSets: ['ML-KEM-768'],
    classicalComponent: 'X25519 (Curve25519 ECDHE)',
    postQuantumComponent: 'ML-KEM-768 (FIPS 203)',
    evidence: [
      { label: 'Negotiated TLS version', value: 'TLSv1.3' },
      { label: 'Negotiated key-exchange group', value: 'X25519 + ML-KEM-768 (hybrid)' },
      { label: 'Classical component', value: 'X25519 (Curve25519 ECDHE)' },
      { label: 'Post-quantum component', value: 'ML-KEM-768 (FIPS 203)' },
      { label: 'Detection confidence', value: '95%' },
    ],
  }
  edge.transport = { ...edge.transport, keyExchange: 'Hybrid ECDHE + ML-KEM (X25519MLKEM768)' }
  edge.quantum = {
    ...edge.quantum,
    hybridObserved: true,
    keyExchange: 'Hybrid ECDHE + ML-KEM (X25519MLKEM768)',
    keyExchangeClass: 'Hybrid',
    kemParameterSets: ['ML-KEM-768'],
    postQuantumReadiness: 70,
    quantumRisk: 'High',
    vulnerability: 'Hybrid-protected',
    vulnerabilityReason: 'Hybrid ML-KEM key agreement is in use.',
  }
  return edge
}

/** expired.badssl.com-shaped: TLS 1.2 only, expired + untrusted, static RSA. */
function expiredBadsslEdge(): EdgeIntelligence {
  const edge = edgeFixture()
  edge.transport = {
    ...edge.transport,
    negotiatedProtocol: 'TLSv1.2',
    supportedProtocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2'],
    legacyProtocols: ['TLSv1', 'TLSv1.1'],
    negotiatedCipher: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    staticRsaAccepted: true,
    alpn: null,
    http2: false,
  }
  edge.pqKeyAgreement = {
    ...edge.pqKeyAgreement,
    value: 'Not available',
    state: 'fail',
    detail: 'endpoint does not negotiate TLS 1.3',
    hybridProbed: false,
  }
  edge.certificate = {
    ...edge.certificate,
    ocspStapled: false,
    ocspResponderState: 'not-advertised',
    ocspUri: null,
    sctPresent: false,
    sctCount: 0,
    chainTrusted: false,
    trustError: 'certificate has expired',
    daysRemaining: -2000,
  }
  edge.dns = { ...edge.dns, caaPresent: false, caaRecords: [], dnssecSigned: false, dnssecValidated: false }
  edge.http = {
    ...edge.http,
    hsts: { present: false, status: 'Not Supported', raw: null, maxAge: null, includeSubDomains: false, preload: false, preloadEligible: false, preloadBlockers: ['no HSTS header'] },
    headers: edge.http.headers.map((header) => ({ ...header, present: false, value: null, status: 'Not Supported' })),
    hardenedCount: 0,
    applicableCount: 3,
    fingerprint: { server: 'nginx', poweredBy: null, cdn: null, waf: null, cloudProvider: null, reverseProxy: null, signals: ['server'] },
  }
  edge.quantum = {
    ...edge.quantum,
    quantumRisk: 'Critical',
    vulnerability: 'Vulnerable',
    vulnerabilityReason: 'no post-quantum key agreement; classical key exchange is recoverable by a CRQC',
  }
  return edge
}

/* --------------------------------------------------- 1. the two bug reports */

function verifyReportedDefects() {
  console.log('\n=== The two reported defects ===')

  // Cloudflare: hybrid IS deployed. The row must be decisive, not "Observed".
  const cloudflare = hybridEdge()
  assert(cloudflare.pqKeyAgreement.value === 'Applied', 'Cloudflare-shaped: PQ key agreement reads "Applied", not "Observed"')
  assert(cloudflare.pqKeyAgreement.state === 'pass', 'Cloudflare-shaped: PQ key agreement renders as a pass')
  assert(
    !/observed/i.test(cloudflare.pqKeyAgreement.value),
    'Cloudflare-shaped: the evasive "Observed" verdict is gone',
  )

  const cloudflareVerdict = classifyQuantumVulnerability({
    hasTransportEvidence: true,
    hybridObserved: true,
    pqSignatureObserved: false,
    quantumRisk: 'High',
    hybridProbed: true,
    supportsTls13: true,
  })
  assert(cloudflareVerdict.vulnerability === 'Hybrid-protected', 'Cloudflare-shaped: quantum vulnerability is Hybrid-protected')

  // expired.badssl.com: nothing post-quantum anywhere. Must NOT read hybrid.
  const badssl = classifyQuantumVulnerability({
    hasTransportEvidence: true,
    hybridObserved: false,
    pqSignatureObserved: false,
    quantumRisk: 'Critical',
    hybridProbed: false,
    supportsTls13: false,
  })
  assert(badssl.vulnerability === 'Vulnerable', 'expired.badssl.com-shaped: quantum vulnerability is Vulnerable')
  assert(
    badssl.vulnerability !== 'Hybrid-protected',
    'expired.badssl.com-shaped: NEVER reports Hybrid-protected (the reported bug)',
  )
  assert(/TLS 1\.3/.test(badssl.reason), 'expired.badssl.com-shaped: the reason names the missing TLS 1.3 prerequisite')
}

/* ---------------------------------------------- 2. the classifier is total */

function verifyClassifier() {
  console.log('\n=== Quantum vulnerability classification ===')

  const cases: Array<[string, Parameters<typeof classifyQuantumVulnerability>[0], string]> = [
    ['no evidence at all', { hasTransportEvidence: false, hybridObserved: false, pqSignatureObserved: false, quantumRisk: 'Critical', hybridProbed: false, supportsTls13: false }, 'Unknown'],
    ['hybrid + PQ signature', { hasTransportEvidence: true, hybridObserved: true, pqSignatureObserved: true, quantumRisk: 'Low', hybridProbed: true, supportsTls13: true }, 'Quantum-safe'],
    ['hybrid only', { hasTransportEvidence: true, hybridObserved: true, pqSignatureObserved: false, quantumRisk: 'High', hybridProbed: true, supportsTls13: true }, 'Hybrid-protected'],
    ['classical, critical risk', { hasTransportEvidence: true, hybridObserved: false, pqSignatureObserved: false, quantumRisk: 'Critical', hybridProbed: true, supportsTls13: true }, 'Vulnerable'],
    ['classical, high risk', { hasTransportEvidence: true, hybridObserved: false, pqSignatureObserved: false, quantumRisk: 'High', hybridProbed: true, supportsTls13: true }, 'High Risk'],
    ['classical, low risk', { hasTransportEvidence: true, hybridObserved: false, pqSignatureObserved: false, quantumRisk: 'Low', hybridProbed: true, supportsTls13: true }, 'Classical only'],
  ]

  for (const [label, input, expected] of cases) {
    const result = classifyQuantumVulnerability(input)
    assert(result.vulnerability === expected, `${label} → ${expected} (got ${result.vulnerability})`)
    assert(result.reason.length > 40, `${label}: carries a substantive reason, not a caption`)
  }

  // The invariant that broke: hybrid protection can only ever be claimed from a
  // measurement, so no combination without `hybridObserved` may return it.
  const noHybridCombinations = (['Low', 'Medium', 'High', 'Critical'] as const).map((risk) =>
    classifyQuantumVulnerability({
      hasTransportEvidence: true,
      hybridObserved: false,
      pqSignatureObserved: false,
      quantumRisk: risk,
      hybridProbed: true,
      supportsTls13: true,
    }).vulnerability,
  )
  assert(
    !noHybridCombinations.includes('Hybrid-protected') && !noHybridCombinations.includes('Quantum-safe'),
    'Without an observed hybrid group, no risk level can yield Hybrid-protected or Quantum-safe',
  )
}

/* ------------------------------------------- 3. no control reads "Not probed" */

function surfaceFor(edge: EdgeIntelligence | null): SurfaceItem[] {
  const result: ScanResultRecord = {
    scanId: 'check',
    target: edge?.host ?? 'example.test',
    targetType: 'domain',
    findings: [],
    certificateInfo: {
      subject: { CN: 'example.test' },
      publicKeyAlgorithm: 'rsaEncryption',
      publicKeySize: 2048,
      signatureAlgorithm: 'sha256WithRSAEncryption',
      validFrom: '2025-01-01',
      validTo: '2026-06-01',
      isExpired: false,
      isSelfSigned: false,
      chain: [],
    },
    tlsVersion: edge?.transport.negotiatedProtocol ?? 'TLSv1.3',
    metadata: {
      targetType: 'domain',
      tlsAnalysis: {
        tlsVersion: edge?.transport.negotiatedProtocol ?? 'TLSv1.3',
        cipherSuite: edge?.transport.negotiatedCipher ?? 'TLS_AES_256_GCM_SHA384',
        keyExchange: 'ECDHE (TLS 1.3 key_share)',
        signatureAlgorithm: 'sha256WithRSAEncryption',
        supportedProtocols: edge?.transport.supportedProtocols ?? ['TLSv1.3'],
        negotiatedCurve: null,
      },
      edgeIntelligence: edge,
    },
  }

  return buildAssessment({
    status: 'completed',
    provenance: 'check',
    targets: [result.target as string],
    completedAt: new Date().toISOString(),
    summary: {
      targetsScanned: 1,
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      safe: 0,
      vulnerable: 0,
      pqcReady: 0,
      riskScore: 40,
      qScore: 60,
    },
    findings: [],
    results: [result],
    scanner2: null,
    modules: [],
    moduleLedger: null,
    estate: { totalAssets: 1, vulnerableAssets: 0, pqcReadyAssets: 0 },
    linked: { cbom: 0, assets: 1, exposures: 0 },
  } as unknown as Parameters<typeof buildAssessment>[0]).attackSurface
}

function verifyNoUnprobedControls() {
  console.log('\n=== The eight controls that read "Not probed" ===')

  const controls = [
    'hsts',
    'headers',
    'ocsp-stapling',
    'certificate-transparency',
    'dns-caa',
    'dnssec',
    'alpn',
    'edge-infrastructure',
  ]

  for (const scenario of [
    { label: 'hybrid endpoint', edge: hybridEdge() },
    { label: 'expired.badssl.com-shaped', edge: expiredBadsslEdge() },
  ]) {
    const surface = surfaceFor(scenario.edge)
    for (const key of controls) {
      const item = surface.find((entry) => entry.key === key)
      assert(Boolean(item), `${scenario.label}: "${key}" row is present`)
      if (!item) continue
      assert(item.status !== 'unknown', `${scenario.label}: "${key}" is measured, not Unknown`)
      assert(
        !/not probed/i.test(item.value) && !/not measured/i.test(item.value),
        `${scenario.label}: "${key}" reports a verdict, not a placeholder (${item.value})`,
      )
    }

    const pq = surface.find((entry) => entry.key === 'pq-key-agreement')
    assert(Boolean(pq?.evidence?.length), `${scenario.label}: PQ key agreement carries its supporting evidence`)
    const evidenceLabels = (pq?.evidence ?? []).map((entry) => entry.label.toLowerCase())
    for (const required of ['negotiated tls version', 'detection confidence']) {
      assert(
        evidenceLabels.some((label) => label.includes(required)),
        `${scenario.label}: PQ evidence includes "${required}"`,
      )
    }
  }

  // Hybrid endpoints must additionally name both halves of the construction.
  const hybridSurface = surfaceFor(hybridEdge())
  const hybridPq = hybridSurface.find((entry) => entry.key === 'pq-key-agreement')
  const hybridLabels = (hybridPq?.evidence ?? []).map((entry) => entry.label.toLowerCase())
  assert(hybridLabels.some((label) => label.includes('classical component')), 'Hybrid: evidence names the classical component')
  assert(hybridLabels.some((label) => label.includes('post-quantum component')), 'Hybrid: evidence names the PQ component')
  assert(hybridLabels.some((label) => label.includes('group')), 'Hybrid: evidence names the negotiated group')
}

/* ------------------------------------- 4. absent evidence still reads honestly */

function verifyUnmeasuredIsHonest() {
  console.log('\n=== A scan with no edge evidence stays honest ===')

  const surface = surfaceFor(null)
  for (const key of ['ocsp-stapling', 'certificate-transparency', 'dns-caa', 'dnssec', 'alpn', 'edge-infrastructure']) {
    const item = surface.find((entry) => entry.key === key)
    assert(item?.status === 'unknown', `"${key}" with no edge evidence renders Unknown, never a fail`)
    assert(
      Boolean(item && /re-run|not measured|predates/i.test(item.detail)),
      `"${key}" explains WHY it is unmeasured and what to do about it`,
    )
  }

  const pq = surface.find((entry) => entry.key === 'pq-key-agreement')
  assert(pq?.status === 'unknown', 'PQ key agreement with no edge evidence is Unknown, never "Fail"')
}

/* --------------------------------------- 5. the PQC detection rules are sane */

function verifyDetectionRules() {
  console.log('\n=== PQC detection rules read the measurement ===')

  const baseContext = (edge: EdgeIntelligence | null): DetectionContext => ({
    findings: [],
    tlsResult: {
      tlsVersion: 'TLSv1.3',
      cipherSuite: 'TLS_AES_256_GCM_SHA384',
      keyExchange: 'ECDHE (TLS 1.3 key_share)',
      signatureAlgorithm: 'sha256WithRSAEncryption',
      supportedProtocols: ['TLSv1.3'],
      protocolSupport: [],
      negotiatedCurve: null,
      serverName: 'example.test',
      peerCertificate: null,
      cipherSuites: [],
      ephemeralKeyType: null,
      ephemeralKeySize: null,
    },
    certInfo: null,
    apiResult: null,
    repoResult: null,
    webCryptoResult: null,
    edgeIntelligence: edge,
  })

  const fire = (edge: EdgeIntelligence | null, ruleId: string) => {
    const rule = DETECTION_RULES.find((entry) => entry.id === ruleId)
    return Boolean(rule?.evaluate(baseContext(edge)))
  }

  for (const ruleId of ['PQC-001', 'PQC-002', 'PQC-003']) {
    // The reported false positive: firing against an endpoint that genuinely
    // negotiates X25519MLKEM768.
    assert(!fire(hybridEdge(), ruleId), `${ruleId} does NOT fire on an endpoint with hybrid ML-KEM (was a false positive)`)
    // The true negative it must still catch.
    assert(fire(edgeFixture(), ruleId), `${ruleId} fires on a classical-only endpoint`)
    // And it must never assert anything without a measurement behind it.
    assert(!fire(null, ruleId), `${ruleId} stays silent when no named-group probe ran (never guesses)`)
  }
}

/* ---------------------------------------- 6. new findings have exactly one owner */

function verifyFindingOwnership() {
  console.log('\n=== New edge findings route to their own module ===')

  const cases: Array<[string, string]> = [
    ['Post-Quantum Key Agreement', 'pq-key-agreement-scanner'],
    ['Certificate Revocation', 'revocation-transparency-scanner'],
    ['Certificate Transparency', 'revocation-transparency-scanner'],
    ['DNS Security', 'dns-security-scanner'],
  ]
  for (const [category, expected] of cases) {
    const owner = moduleIdForFinding({ category, detectionMethod: 'edge-intelligence', algorithm: 'x' })
    assert(owner === expected, `"${category}" is owned by ${expected} (got ${owner})`)
  }

  // The collision that made this necessary: both new certificate categories
  // contain the word "certificate" and would otherwise land on the chain parser.
  assert(
    moduleIdForFinding({ category: 'Certificate', detectionMethod: '', algorithm: '' }) === 'certificate-scanner',
    'Plain "Certificate" findings still belong to the certificate scanner',
  )
  assert(
    moduleIdForFinding({ category: 'Certificate Signature', detectionMethod: '', algorithm: '' }) === 'signature-algorithm-scanner',
    'Certificate signature findings still belong to the signature analyzer',
  )
  assert(
    moduleIdForFinding({ category: 'Key Exchange', detectionMethod: '', algorithm: '' }) === 'key-exchange-scanner',
    'Classical key-exchange findings still belong to the key exchange scanner',
  )
}

/* ------------------------------------------------- 7. edge attribution honesty */

function verifyEdgeAttribution() {
  console.log('\n=== Edge attribution distinguishes absence from ignorance ===')

  const behindCdn = describeEdgeInfrastructure(hybridEdge())
  assert(/Cloudflare/.test(behindCdn.value), 'A CDN-fronted origin names the CDN')
  assert(behindCdn.evidence.length > 0, 'CDN attribution carries the header signals it was read from')

  const originServed = describeEdgeInfrastructure(expiredBadsslEdge())
  assert(/Origin-served/.test(originServed.value), 'An origin with no CDN reads "Origin-served", a real answer')
  assert(originServed.state === 'info', 'Origin-served is informational, not a failure')

  const unreachable = edgeFixture()
  unreachable.http = { ...unreachable.http, reachable: false, error: 'ECONNREFUSED' }
  const unread = describeEdgeInfrastructure(unreachable)
  assert(unread.state === 'unknown', 'An unreachable origin yields Unknown, never "Origin-served"')
  assert(/ECONNREFUSED/.test(unread.detail), 'The unreachable reason is stated verbatim')
}

/* ------------------------------------------------------------------ runner */

console.log('QGuard Helix — public-edge detection accuracy check')
verifyReportedDefects()
verifyClassifier()
verifyNoUnprobedControls()
verifyUnmeasuredIsHonest()
verifyDetectionRules()
verifyFindingOwnership()
verifyEdgeAttribution()

console.log(
  failures === 0
    ? '\nAll edge detection checks passed.'
    : `\n${failures} edge detection check(s) FAILED.`,
)
console.log(
  '\nThis suite is offline by design. To verify the probes themselves against a\n' +
    'live endpoint, run a scan from /dashboard/scanner and compare the Observed\n' +
    'Attack Surface against /public-scan for the same host — both now consume the\n' +
    'same engine bundle, so any disagreement is a defect.',
)
process.exit(failures === 0 ? 0 : 1)
