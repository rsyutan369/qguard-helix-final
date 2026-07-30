/**
 * QGuard Helix — Public Quantum Exposure Assessment™
 * Pure assessment engine.
 *
 * Every function here is deterministic and side-effect free: it takes the raw
 * edge evidence collected by `edge-probe.ts` + the reused web-scanner TLS result
 * and produces the executive report. No network, no database, no clock beyond
 * the caller-supplied timestamps — which makes the whole scoring model unit
 * testable (see tools/public-scan-check.ts).
 *
 * ACCURACY CONTRACT
 * -----------------
 * 1. Nothing is reported that the edge cannot prove. Anything requiring internal
 *    visibility is emitted as an explicit `Unknown` with the reason.
 * 2. Post-quantum readiness is 0 unless a hybrid/PQ group or PQ signature is
 *    actually observed — "modern TLS" is never post-quantum readiness.
 * 3. Numbers shown to the user are either counted or reproducible from the
 *    published scoring model. There are no hand-assigned magnitudes.
 * 4. Every panel is a projection of `buildControlStates`, so the same control
 *    cannot report different verdicts in different cards.
 */

import type { CertificateInfo, CipherSuiteDetail, ThreatLevel } from '../web-scanner/types'
import { buildControlStates, findControl, resolveForwardSecrecy, resolveKeyExchange } from './controls'
import { buildScoreCategories, CLASSICAL_CATEGORY_KEYS, RISK_ORDER, scoreToGrade } from './grading-model'
import type {
  AssessmentScope,
  AttackSurfaceItem,
  ComplexityBand,
  ControlState,
  CryptoIntelligence,
  ExecutiveSummary,
  FootprintEstimate,
  FootprintMetric,
  GovernanceItem,
  HandshakeStep,
  PublicFinding,
  PublicScanEvidence,
  Recommendation,
  RiskBand,
  ScoreComponent,
  SecurityGrade,
  SophiaAssessment,
  SurfaceStatus,
  TimelinePhase,
} from './types'

export { resolveForwardSecrecy, resolveKeyExchange, buildControlStates }

const clamp = (value: number, min = 0, max = 100) => Math.max(min, Math.min(max, Math.round(value)))

/** Named hybrid / post-quantum TLS groups observable in a handshake. */
const PQ_GROUP_PATTERNS = [
  /x25519(?:mlkem|kyber)/i,
  /ml[-_]?kem/i,
  /kyber/i,
  /secp\d+r1mlkem/i,
  /frodo/i,
  /bike/i,
  /hqc/i,
]

const PQ_SIGNATURE_PATTERNS = [/ml[-_]?dsa/i, /dilithium/i, /slh[-_]?dsa/i, /sphincs/i, /falcon/i]

function isPostQuantumGroup(value: string | null | undefined): boolean {
  return Boolean(value) && PQ_GROUP_PATTERNS.some((pattern) => pattern.test(value as string))
}

function isPostQuantumSignature(value: string | null | undefined): boolean {
  return Boolean(value) && PQ_SIGNATURE_PATTERNS.some((pattern) => pattern.test(value as string))
}

/** The ML-KEM parameter set carried by each hybrid group, per the TLS registry. */
const HYBRID_GROUP_KEM: Record<string, string> = {
  X25519MLKEM768: 'ML-KEM-768',
  SecP256r1MLKEM768: 'ML-KEM-768',
  SecP384r1MLKEM1024: 'ML-KEM-1024',
}

// ─── Score components (projection of the weighted controls) ───────────────────

/**
 * The Encryption Score decomposition: the published 12-category weighted
 * model (grading-model.ts), computed from the same control states that back
 * the findings table and attack-surface list — so a category's score can
 * always be traced back to the granular evidence it summarises.
 */
export function buildScoreComponents(evidence: PublicScanEvidence): ScoreComponent[] {
  const controls = buildControlStates(evidence)
  const pq = computePostQuantumReadiness(evidence)
  return buildScoreCategories(evidence, controls, pq.score)
}

/**
 * Weighted mean over the *observable* dimensions only. Weight from dimensions
 * that could not be measured is redistributed across the rest, so an
 * unobservable control never silently drags the grade down.
 *
 * Generic over whatever `components` array is passed in — callers use it both
 * for the full 12-category published model (→ the graded "encryption score")
 * and for an arbitrary subset (→ the "classical-only" sub-metric), so the same
 * weighted-mean math backs every score shown in the report.
 */
export function computeClassicalScore(components: ScoreComponent[]): number {
  const scored = components.filter((component) => component.applicable)
  const totalWeight = scored.reduce((sum, component) => sum + component.weight, 0)
  if (!totalWeight) return 0
  const weighted = scored.reduce((sum, component) => sum + component.score * component.weight, 0)
  return clamp(weighted / totalWeight)
}

// ─── Post-quantum readiness ───────────────────────────────────────────────────

/**
 * Post-quantum readiness observable at the edge. Deliberately conservative:
 * a site scores 0 unless a hybrid/PQ group or PQ signature actually appears.
 * Crypto-agility signals earn a small "ready to move" allowance, never a
 * readiness claim.
 */
export function computePostQuantumReadiness(evidence: PublicScanEvidence): {
  score: number
  hybridObserved: boolean
  pqSignatureObserved: boolean
  reasons: string[]
} {
  const { tls, certificate, certificateExtras, keyAgreement } = evidence
  const reasons: string[] = []

  const hybridObserved =
    keyAgreement.hybridGroups.length > 0 ||
    isPostQuantumGroup(tls?.negotiatedCurve) ||
    isPostQuantumGroup(tls?.keyExchange) ||
    isPostQuantumGroup(tls?.cipherSuite)
  const pqSignatureObserved =
    isPostQuantumSignature(certificate?.signatureAlgorithm) ||
    isPostQuantumSignature(certificate?.publicKeyAlgorithm) ||
    isPostQuantumSignature(tls?.signatureAlgorithm)

  let score = 0

  if (hybridObserved) {
    score += 55
    reasons.push(
      keyAgreement.hybridGroups.length
        ? `Hybrid post-quantum key agreement accepted: ${keyAgreement.hybridGroups.join(', ')}.`
        : 'Hybrid post-quantum key agreement negotiated in the TLS handshake.',
    )
  } else {
    reasons.push('No hybrid or post-quantum key agreement offered at the public edge.')
  }

  if (pqSignatureObserved) {
    score += 30
    reasons.push('Post-quantum signature algorithm present in the served certificate chain.')
  } else {
    reasons.push('Certificate chain is signed with classical algorithms only.')
  }

  // Crypto-agility allowance — capability to move, not readiness itself.
  const protocols = tls?.supportedProtocols ?? []
  if (protocols.includes('TLSv1.3')) {
    score += 12
    reasons.push('TLS 1.3 is the protocol PQ hybrid groups deploy on — the prerequisite is met.')
  }
  if (certificateExtras && certificateExtras.validityDays > 0 && certificateExtras.validityDays <= 100) {
    score += 8
    reasons.push('Short-lived automated certificates enable fast algorithm rollover.')
  }
  if (certificateExtras?.signedCertificateTimestamps) {
    score += 3
    reasons.push('Certificate Transparency participation supports auditable re-issuance.')
  }
  if (evidence.http.headers.find((header) => header.name === 'strict-transport-security')?.secure) {
    score += 3
    reasons.push('Enforced HTTPS narrows the downgrade path during a hybrid rollout.')
  }

  return { score: clamp(score), hybridObserved, pqSignatureObserved, reasons }
}

// ─── Executive summary ────────────────────────────────────────────────────────

export function computeConfidence(evidence: PublicScanEvidence): { score: number; factors: string[] } {
  const factors: string[] = []
  let score = 100

  if (!evidence.tls) {
    score -= 45
    factors.push('TLS handshake did not complete')
  } else {
    factors.push('TLS handshake completed')
  }
  if (!evidence.certificate) {
    score -= 20
    factors.push('Certificate chain unavailable')
  } else {
    factors.push('X.509 chain parsed')
  }
  if (!evidence.http.reachable) {
    score -= 15
    factors.push('HTTP origin unreachable')
  } else {
    factors.push('HTTP transport headers read')
  }
  if (evidence.dns.error) {
    score -= 12
    factors.push('DNS records incomplete')
  } else {
    factors.push('Public DNS resolved')
  }
  if (!evidence.certificateExtras) {
    score -= 8
    factors.push('OCSP/CT extensions unreadable')
  } else {
    factors.push('OCSP + Certificate Transparency inspected')
  }
  if ((evidence.tls?.protocolSupport?.length ?? 0) < 4) {
    score -= 5
    factors.push('Partial protocol enumeration')
  }
  if (!evidence.keyAgreement.probed) {
    score -= 6
    factors.push('Named key-agreement groups not probed')
  } else {
    factors.push('Named key-agreement groups probed (incl. hybrid ML-KEM)')
  }
  if (!evidence.dns.caaQueryable) {
    score -= 4
    factors.push('CAA issuance policy not queryable')
  }

  return { score: clamp(score, 10, 99), factors }
}

/**
 * Minimum share of the declared scoring weight that must be observable before a
 * letter grade is meaningful. Below this the report withholds the grade instead
 * of publishing a score derived from one or two surviving dimensions.
 */
export const MIN_GRADEABLE_COVERAGE = 40

export function computeEvidenceCoverage(components: ScoreComponent[]): number {
  const total = components.reduce((sum, component) => sum + component.weight, 0)
  if (!total) return 0
  const observed = components
    .filter((component) => component.applicable)
    .reduce((sum, component) => sum + component.weight, 0)
  return clamp((observed / total) * 100)
}

/**
 * `components` is the full 12-category published model (grading-model.ts).
 * Two numbers come out of the same weighted-mean function over two different
 * slices of it:
 *   - `encryptionScore` = weighted mean over ALL 12 categories. This is the
 *     "Overall Score" the published Score-to-Grade Mapping maps to a letter
 *     grade — the grade badge, the gauge and the risk level are all derived
 *     from THIS number, never from classicalScore.
 *   - `classicalScore` = weighted mean over the 10 non-PQ categories only,
 *     renormalized among themselves. An informative sub-metric shown next to
 *     the gauge; it never drives the grade.
 */
export function buildExecutiveSummary(
  evidence: PublicScanEvidence,
  components: ScoreComponent[],
  findings: PublicFinding[],
): ExecutiveSummary {
  const encryptionScore = computeClassicalScore(components)
  const classicalComponents = components.filter((component) => CLASSICAL_CATEGORY_KEYS.includes(component.key))
  const classicalScore = computeClassicalScore(classicalComponents)
  const pq = computePostQuantumReadiness(evidence)
  const evidenceCoverage = computeEvidenceCoverage(components)
  const gradeable = evidenceCoverage >= MIN_GRADEABLE_COVERAGE
  const graded = scoreToGrade(encryptionScore)
  const grade: SecurityGrade = gradeable ? graded.grade : 'N/A'
  const gradeLabel = gradeable ? graded.rating : 'Insufficient evidence'
  const gradeColor = gradeable ? graded.color : '#94a3b8'
  const confidence = computeConfidence(evidence)

  const criticalCount = findings.filter((finding) => finding.severity === 'CRITICAL').length
  const highCount = findings.filter((finding) => finding.severity === 'HIGH').length

  // Risk level comes straight from the published Score-to-Grade Mapping — the
  // same table the "How the Grading Works" reference documents — with one
  // safety escalation on top: a genuinely critical finding (an expired
  // certificate, a chain that fails verification) must never be hidden behind
  // a decent aggregate score, so it raises the floor to at least "High".
  let businessRisk: RiskBand = gradeable ? graded.riskLevel : 'Not assessable'
  if (gradeable && criticalCount > 0 && RISK_ORDER.indexOf(businessRisk) < RISK_ORDER.indexOf('High')) {
    businessRisk = 'High'
  }
  const businessRiskDetail = !gradeable
    ? 'Too little of the public edge responded to draw a risk conclusion.'
    : criticalCount > 0
      ? `${criticalCount} critical edge exposure${criticalCount === 1 ? '' : 's'} require immediate action.`
      : highCount >= 1
        ? `${highCount} high-severity weakness${highCount === 1 ? '' : 'es'} observed on the public edge.`
        : graded.meaning

  // Migration complexity from the breadth of the observable edge, stated as the
  // count of distinct items that would have to change.
  const sanCount = evidence.certificateExtras?.sanCount ?? 0
  const chainDepth = evidence.certificateExtras?.chainDepth ?? 0
  const protocolSpread = evidence.tls?.supportedProtocols.length ?? 0
  const complexityPoints =
    (sanCount > 50 ? 3 : sanCount > 10 ? 2 : sanCount > 3 ? 1 : 0) +
    (chainDepth > 3 ? 1 : 0) +
    (protocolSpread > 2 ? 1 : 0) +
    (evidence.dns.addressCount > 4 ? 1 : 0) +
    (pq.hybridObserved ? -1 : 1)

  let migrationComplexity: ComplexityBand = 'Low'
  if (!gradeable) migrationComplexity = 'Unknown'
  else if (complexityPoints >= 5) migrationComplexity = 'Very High'
  else if (complexityPoints >= 3) migrationComplexity = 'High'
  else if (complexityPoints >= 1) migrationComplexity = 'Medium'

  return {
    grade,
    gradeLabel,
    gradeDetail: !gradeable
      ? `Only ${evidenceCoverage}% of the assessed dimensions responded — a grade would be misleading.`
      : graded.meaning,
    gradeColor,
    classicalScore,
    postQuantumReadiness: pq.score,
    encryptionScore,
    encryptionBand: gradeable ? graded.rating : 'Unrated',
    businessRisk,
    businessRiskDetail,
    migrationComplexity,
    migrationComplexityDetail: gradeable
      ? `Scoped from ${sanCount} covered name${sanCount === 1 ? '' : 's'}, ${chainDepth} chain certificate${chainDepth === 1 ? '' : 's'} and ${protocolSpread} accepted protocol${protocolSpread === 1 ? '' : 's'}.`
      : 'Public footprint could not be enumerated.',
    confidence: confidence.score,
    confidenceDetail:
      confidence.score >= 90
        ? 'High confidence in data accuracy.'
        : confidence.score >= 70
          ? 'Good confidence; some probes were incomplete.'
          : 'Limited confidence — several probes could not complete.',
    confidenceFactors: confidence.factors,
    evidenceCoverage,
    gradeable,
    scope: 'Public Internet Edge',
  }
}

// ─── Handshake visualization ──────────────────────────────────────────────────

/**
 * Every step reports what was actually observed on the scanner's own
 * connection, with the measurement source named in `detail` and real wall-clock
 * timings where the probe recorded them. Nothing here is a decorative caption.
 */
export function buildHandshakeSteps(evidence: PublicScanEvidence): HandshakeStep[] {
  const { tls, certificate, certificateExtras, http, keyAgreement, timing, dns } = evidence
  const acceptedGroups = [...keyAgreement.hybridGroups, ...keyAgreement.classicalGroups]

  return [
    {
      key: 'dns',
      label: 'Name Resolution',
      value: dns.addressCount ? `${dns.addressCount} address${dns.addressCount === 1 ? '' : 'es'}` : 'unresolved',
      detail: dns.addresses.length
        ? `First: ${dns.addresses[0]} · via ${dns.resolvedVia}`
        : dns.error || 'No public A/AAAA records',
      observed: dns.addressCount > 0,
      timingMs: null,
    },
    {
      key: 'tcp',
      label: 'TCP Connect',
      value: timing.tcpConnectMs !== null ? `${timing.tcpConnectMs} ms` : 'not measured',
      detail: `Port ${evidence.port} · measured on the assessment socket`,
      observed: timing.tcpConnectMs !== null,
      timingMs: timing.tcpConnectMs,
    },
    {
      key: 'client-hello',
      label: 'Client Hello',
      value: tls ? 'TLS 1.0–1.3 offered' : 'no response',
      detail: acceptedGroups.length
        ? `Groups accepted when offered alone: ${acceptedGroups.join(', ')}`
        : 'Named-group probe did not complete',
      observed: Boolean(tls),
      timingMs: null,
    },
    {
      key: 'server-hello',
      label: 'Server Hello',
      value: tls?.tlsVersion || 'no response',
      detail: tls?.supportedProtocols.length
        ? `Accepts: ${tls.supportedProtocols.join(', ')}`
        : 'Protocol enumeration unavailable',
      observed: Boolean(tls),
      timingMs: timing.tlsHandshakeMs,
    },
    {
      key: 'cipher',
      label: 'Cipher Negotiation',
      value: tls?.cipherSuite || 'unknown',
      detail: evidence.cipherSuites.length
        ? `${evidence.cipherSuites.length} suite${evidence.cipherSuites.length === 1 ? '' : 's'} confirmed by probe`
        : 'Negotiated suite only',
      observed: Boolean(tls?.cipherSuite),
      timingMs: null,
    },
    {
      key: 'certificate',
      label: 'Certificate Exchange',
      value: certificate?.publicKeyAlgorithm || 'not presented',
      detail: certificateExtras
        ? `Chain depth ${certificateExtras.chainDepth} · ${certificateExtras.sanCount} SAN${certificateExtras.sanCount === 1 ? '' : 's'} · ${certificateExtras.chainTrusted ? 'chain verified' : 'chain NOT verified'}`
        : 'Chain metadata unavailable',
      observed: Boolean(certificate),
      timingMs: null,
    },
    {
      key: 'key-exchange',
      label: 'Key Exchange',
      value: resolveKeyExchange(evidence),
      detail: resolveForwardSecrecy(evidence).basis,
      observed: resolveKeyExchange(evidence) !== 'unknown',
      timingMs: null,
    },
    {
      key: 'session',
      label: 'Session Established',
      value:
        timing.totalMs !== null ? `${timing.totalMs} ms to secure` : tls ? 'established' : 'not established',
      detail: [
        evidence.alpn ? `ALPN ${evidence.alpn}` : 'ALPN not negotiated',
        http.reachable ? `HTTP ${http.statusCode} in ${http.responseMs} ms` : 'HTTP origin unreachable',
      ].join(' · '),
      observed: Boolean(tls),
      timingMs: timing.totalMs,
    },
  ]
}

// ─── Findings (projection of the control states) ──────────────────────────────

export function buildFindings(evidence: PublicScanEvidence): PublicFinding[] {
  return toFindings(buildControlStates(evidence))
}

export function toFindings(controls: ControlState[]): PublicFinding[] {
  return controls
    .filter((control) => control.inFindings)
    .map((control) => ({
      id: control.key,
      control: control.control,
      finding: control.finding,
      status: control.status,
      severity: control.severity,
      businessImpact: control.businessImpact,
      quantumImpact: control.quantumImpact,
      nextStep: control.nextStep,
      evidence: control.evidence,
    }))
}

// ─── Attack surface (projection of the same control states) ───────────────────

/**
 * Seven-state status → attack-surface dot. `Not Supported` is a real failure
 * (the control was expected and is absent); `Unknown`, `Not Observable` and
 * `Not Applicable` are all "no verdict" and must never render as a failure.
 */
const STATUS_TO_SURFACE: Record<string, SurfaceStatus> = {
  Healthy: 'pass',
  Warning: 'partial',
  Critical: 'fail',
  'Not Supported': 'fail',
  Unknown: 'unknown',
  'Not Observable': 'unknown',
  'Not Applicable': 'unknown',
}

export function buildAttackSurface(evidence: PublicScanEvidence): AttackSurfaceItem[] {
  return toAttackSurface(buildControlStates(evidence))
}

export function toAttackSurface(controls: ControlState[]): AttackSurfaceItem[] {
  return controls
    .filter((control) => control.inAttackSurface)
    .map((control) => ({
      key: control.key,
      label: control.shortLabel,
      value: control.value,
      // Inventory rows report what exists rather than pass/fail, so they render
      // as neutral info. Everything else carries the control's real verdict —
      // including controls scored outside the classical model, such as
      // post-quantum key agreement.
      status: control.isInventory
        ? control.status === 'Unknown'
          ? 'unknown'
          : 'info'
        : STATUS_TO_SURFACE[control.status] ?? 'unknown',
      detail: control.detail,
    }))
}

// ─── Cryptographic intelligence ───────────────────────────────────────────────

export function buildIntelligence(evidence: PublicScanEvidence, confidence: number): CryptoIntelligence {
  const { tls, certificate, keyAgreement } = evidence
  const pq = computePostQuantumReadiness(evidence)
  const observedAlgorithms: CryptoIntelligence['observedAlgorithms'] = []

  // Symmetric AEAD — named from the negotiated suite. Grover halves the
  // effective key strength, so a 128-bit cipher is reported at its real
  // post-quantum margin rather than waved through as "quantum-safe".
  const cipher = tls?.cipherSuite || ''
  if (/AES_256_GCM|AES256-GCM/i.test(cipher)) {
    observedAlgorithms.push({
      name: 'AES-256-GCM',
      role: 'Symmetric encryption · 128-bit PQ margin',
      quantumVulnerable: false,
    })
  } else if (/AES_128_GCM|AES128-GCM/i.test(cipher)) {
    observedAlgorithms.push({
      name: 'AES-128-GCM',
      role: 'Symmetric encryption · 64-bit PQ margin',
      quantumVulnerable: true,
    })
  } else if (/CHACHA20/i.test(cipher)) {
    observedAlgorithms.push({
      name: 'ChaCha20-Poly1305',
      role: 'Symmetric encryption · 128-bit PQ margin',
      quantumVulnerable: false,
    })
  }

  if (certificate) {
    observedAlgorithms.push({
      name: certificate.publicKeyAlgorithm,
      role: 'Certificate public key',
      quantumVulnerable: !isPostQuantumSignature(certificate.publicKeyAlgorithm),
    })
    const hashMatch = certificate.signatureAlgorithm.match(/SHA-?(1|224|256|384|512)/i)
    if (hashMatch) {
      const bits = hashMatch[1]
      observedAlgorithms.push({
        name: bits === '1' ? 'SHA-1' : `SHA-${bits}`,
        role:
          bits === '1'
            ? 'Signature hash · collision-broken classically'
            : `Signature hash · ${Math.floor(Number(bits) / 2)}-bit PQ margin`,
        quantumVulnerable: bits === '1' || bits === '224',
      })
    }
  }

  if (tls?.tlsVersion) {
    observedAlgorithms.push({
      name: tls.tlsVersion.replace('TLSv', 'TLS '),
      role: 'Negotiated transport protocol',
      quantumVulnerable: false,
    })
  }

  // Name the KEM actually accepted, not a generic one.
  for (const group of keyAgreement.hybridGroups) {
    observedAlgorithms.push({
      name: HYBRID_GROUP_KEM[group] ?? 'ML-KEM',
      role: `Hybrid key encapsulation · ${group}`,
      quantumVulnerable: false,
    })
  }

  const kex = resolveKeyExchange(evidence)
  const fs = resolveForwardSecrecy(evidence)
  const forwardSecrecy: CryptoIntelligence['forwardSecrecy'] = fs.enabled
    ? evidence.cipherSuites.some((suite) => suite.category === 'rsa-kex')
      ? 'Partial'
      : 'Enabled'
    : 'Not observed'

  // Migration targets are only listed for primitives this scan actually saw.
  const migrationTargets: CryptoIntelligence['migrationTargets'] = []
  if (!pq.hybridObserved && tls) {
    migrationTargets.push({
      name: 'ML-KEM-768',
      standard: 'FIPS 203',
      replaces: keyAgreement.classicalGroups[0] || kex.split(' (')[0] || 'classical key exchange',
    })
  }
  if (!pq.pqSignatureObserved && certificate) {
    const isEc = /ec|ecdsa|prime|p-2|p-3/i.test(certificate.publicKeyAlgorithm)
    const level5 = (isEc && certificate.publicKeySize >= 384) || (!isEc && certificate.publicKeySize >= 7680)
    migrationTargets.push({
      name: level5 ? 'ML-DSA-87' : 'ML-DSA-65',
      standard: 'FIPS 204',
      replaces: `${certificate.publicKeyAlgorithm} leaf signature`,
    })
  }
  if (!migrationTargets.length) {
    migrationTargets.push({
      name: 'Sustain hybrid deployment',
      standard: 'NIST SP 1800-38C',
      replaces: 'no classical-only primitive observed at the edge',
    })
  }

  return {
    observedAlgorithms,
    keyExchange: kex,
    forwardSecrecy,
    quantumVulnerability: pq.hybridObserved
      ? pq.pqSignatureObserved
        ? 'Quantum-safe'
        : 'Hybrid-protected'
      : 'Vulnerable',
    quantumVulnerabilityReason: pq.reasons[0],
    migrationTargets,
    confidence,
  }
}

// ─── Quantum exposure timeline ────────────────────────────────────────────────

export function buildTimeline(evidence: PublicScanEvidence): TimelinePhase[] {
  const pq = computePostQuantumReadiness(evidence)
  const groups = evidence.keyAgreement.hybridGroups.join(', ')
  return [
    {
      key: 'today',
      title: 'Today',
      description: pq.hybridObserved
        ? `Hybrid post-quantum key agreement (${groups}) protects new sessions.`
        : 'Strong classical cryptography in place, with no quantum protection.',
      state: 'now',
      horizon: 'Now',
    },
    {
      key: 'harvest',
      title: 'Harvest Now',
      description: pq.hybridObserved
        ? 'Recorded sessions are protected by ML-KEM; only pre-rollout captures remain exposed.'
        : 'Adversaries can record today’s encrypted traffic and store it for future decryption.',
      state: pq.hybridObserved ? 'future' : 'active',
      horizon: 'Ongoing',
    },
    {
      key: 'crqc',
      title: 'Quantum Computer Available',
      description: 'A cryptographically relevant quantum computer breaks RSA and ECC key exchange.',
      state: 'future',
      horizon: 'Est. 2030–2035',
    },
    {
      key: 'decryption',
      title: 'Potential Decryption Risk',
      description: pq.hybridObserved
        ? 'Only traffic captured before the hybrid rollout becomes readable.'
        : 'Harvested sessions from today become readable retroactively.',
      state: 'future',
      horizon: 'Post-CRQC',
    },
    {
      key: 'migration',
      title: 'Recommended Migration',
      description: 'Begin hybrid PQC rollout so long-lived data stops accumulating exposure.',
      state: pq.hybridObserved ? 'now' : 'target',
      horizon: 'NIST target: 2030',
    },
    {
      key: 'hybrid',
      title: 'Hybrid TLS Deployment',
      description: 'X25519 + ML-KEM-768 combines classical and post-quantum key agreement.',
      state: pq.hybridObserved ? 'now' : 'target',
      horizon: pq.hybridObserved ? 'Deployed' : 'Available today',
    },
    {
      key: 'full-pqc',
      title: 'Full PQC Adoption',
      description: 'ML-KEM and ML-DSA across certificates, transport and signing — quantum-resilient.',
      state: pq.pqSignatureObserved && pq.hybridObserved ? 'now' : 'target',
      horizon: 'NIST deadline: 2035',
    },
  ]
}

// ─── Recommendations ──────────────────────────────────────────────────────────

/** Composite encryption score for a given classical/post-quantum pair. */
function composite(classicalScore: number, pqScore: number): number {
  return clamp(classicalScore * 0.6 + pqScore * 0.4)
}

/**
 * Modelled point gain on the composite encryption score if a single scoring
 * dimension were brought to passing, holding everything else constant.
 *
 * This replaces the hand-assigned "risk reduction" numbers that used to sit on
 * each recommendation: the figure now comes from re-running the same published
 * scoring model the report already shows, so a reader can reproduce it from the
 * score-decomposition table.
 */
function gainFromDimension(
  evidence: PublicScanEvidence,
  components: ScoreComponent[],
  key: string,
): number {
  const pqScore = computePostQuantumReadiness(evidence).score
  const current = composite(computeClassicalScore(components), pqScore)
  const improved = components.map((component) =>
    component.key === key ? { ...component, score: 100, applicable: true } : component,
  )
  return Math.max(0, composite(computeClassicalScore(improved), pqScore) - current)
}

/**
 * Modelled gain from a change that alters the *evidence* rather than one score
 * dimension — enabling a hybrid group, or moving to a PQ certificate. The
 * synthetic evidence is fed back through the real scorers so both halves of the
 * composite move exactly as they would in a re-scan.
 */
function gainFromEvidence(
  evidence: PublicScanEvidence,
  components: ScoreComponent[],
  mutate: (draft: PublicScanEvidence) => PublicScanEvidence,
): number {
  const current = composite(computeClassicalScore(components), computePostQuantumReadiness(evidence).score)
  const next = mutate(evidence)
  const nextComponents = buildScoreComponents(next)
  return Math.max(
    0,
    composite(computeClassicalScore(nextComponents), computePostQuantumReadiness(next).score) - current,
  )
}

export function buildRecommendations(
  evidence: PublicScanEvidence,
  controls: ControlState[],
  components: ScoreComponent[],
): Recommendation[] {
  const pq = computePostQuantumReadiness(evidence)
  const recommendations: Recommendation[] = []

  const modelled = (
    gain: number,
    dimension: string,
  ): Pick<Recommendation, 'scoreGain' | 'scoreGainTarget' | 'scoreGainBasis'> => ({
    scoreGain: Math.round(gain),
    scoreGainTarget: 'encryption',
    scoreGainBasis: `Modelled by re-scoring with ${dimension} at its passing value; all other dimensions held constant.`,
  })

  /** A control only generates a recommendation when it actually failed. */
  const needsAction = (key: string) => {
    const state = findControl(controls, key)
    if (!state) return null
    return state.status === 'Critical' || state.status === 'Not Supported' || state.status === 'Warning' ? state : null
  }

  const tlsState = needsAction('tls-version')
  if (tlsState) {
    recommendations.push({
      id: 'disable-legacy-tls',
      title: 'Disable deprecated TLS 1.0/1.1 and enforce TLS 1.3',
      priority: 'Critical',
      businessImpact: 'Removes downgrade paths and clears a common audit finding.',
      effort: 'Configuration change',
      ...modelled(gainFromDimension(evidence, components, 'tls-configuration'), 'TLS Configuration'),
      rationale: tlsState.evidence,
    })
  }

  if (!pq.hybridObserved && evidence.tls && evidence.keyAgreement.probed) {
    recommendations.push({
      id: 'hybrid-kex',
      title: 'Adopt hybrid post-quantum key exchange (X25519MLKEM768)',
      priority: 'Critical',
      businessImpact: 'Stops new traffic from accumulating harvest-now-decrypt-later exposure.',
      effort: 'TLS terminator / CDN setting',
      ...modelled(
        gainFromEvidence(evidence, components, (draft) => ({
          ...draft,
          keyAgreement: {
            ...draft.keyAgreement,
            hybridGroups: ['X25519MLKEM768'],
            primaryGroup: 'X25519MLKEM768',
            forwardSecrecy: true,
          },
        })),
        'a hybrid ML-KEM group accepted',
      ),
      rationale: 'No hybrid or post-quantum group was accepted during the named-group probe.',
    })
  }

  if (!pq.pqSignatureObserved && evidence.certificate) {
    recommendations.push({
      id: 'pq-signature-roadmap',
      title: 'Prepare a post-quantum certificate roadmap with your CA',
      priority: 'High',
      businessImpact: 'Aligns certificate issuance with the FIPS 204 signature standard.',
      effort: 'Depends on CA availability',
      ...modelled(
        gainFromEvidence(evidence, components, (draft) => ({
          ...draft,
          certificate: draft.certificate
            ? { ...draft.certificate, signatureAlgorithm: 'ML-DSA-65' }
            : draft.certificate,
        })),
        'a post-quantum signature on the served chain',
      ),
      rationale: `The served chain is signed with ${evidence.certificate.signatureAlgorithm}.`,
    })
  }

  const fsState = needsAction('forward-secrecy')
  if (fsState) {
    recommendations.push({
      id: 'forward-secrecy',
      title: 'Require ephemeral key agreement on every accepted suite',
      priority: 'High',
      businessImpact: 'Prevents a single key compromise from unlocking recorded traffic.',
      effort: 'Cipher-suite policy change',
      ...modelled(gainFromDimension(evidence, components, 'forward-secrecy'), 'Forward Secrecy'),
      rationale: fsState.evidence,
    })
  }

  const cipherState = needsAction('cipher-suite')
  if (cipherState) {
    recommendations.push({
      id: 'strengthen-cipher-suites',
      title: 'Remove static-RSA suites and prefer 256-bit AEAD',
      priority: 'High',
      businessImpact: 'Eliminates suites without forward secrecy and restores a 128-bit post-quantum margin.',
      effort: 'Cipher-suite policy change',
      ...modelled(gainFromDimension(evidence, components, 'cipher-suites'), 'Cipher Suites'),
      rationale: cipherState.evidence,
    })
  }

  const caaState = findControl(controls, 'dns-caa')
  if (caaState?.status === 'Not Supported') {
    recommendations.push({
      id: 'enable-caa',
      title: 'Publish DNS CAA records restricting certificate issuance',
      priority: 'Medium',
      businessImpact: 'Blocks unauthorised CAs from issuing for your domain.',
      effort: 'DNS record change',
      ...modelled(gainFromDimension(evidence, components, 'dns-caa'), 'DNS CAA'),
      rationale: caaState.evidence,
    })
  }

  const hstsState = needsAction('hsts')
  if (hstsState && hstsState.status !== 'Unknown') {
    recommendations.push({
      id: 'enable-hsts',
      title: 'Enforce HSTS with includeSubDomains and preload',
      priority: 'Medium',
      businessImpact: 'Removes the plaintext first-contact window for returning users.',
      effort: 'Response-header change',
      ...modelled(gainFromDimension(evidence, components, 'hsts'), 'HSTS'),
      rationale: hstsState.evidence,
    })
  }

  const headerState = needsAction('http-security')
  if (headerState) {
    recommendations.push({
      id: 'harden-http-headers',
      title: 'Complete the transport-security header set',
      priority: 'Medium',
      businessImpact: 'Closes gaps that let transport protections be bypassed in-page.',
      effort: 'Response-header change',
      ...modelled(gainFromDimension(evidence, components, 'http-security-headers'), 'HTTP Security Headers'),
      rationale: headerState.evidence,
    })
  }

  const ocspState = needsAction('ocsp-stapling')
  if (ocspState) {
    recommendations.push({
      id: 'enable-ocsp-stapling',
      title: 'Enable OCSP stapling at the TLS terminator',
      priority: 'Low',
      businessImpact: 'Removes a CA round-trip from every new client connection.',
      effort: 'TLS terminator setting',
      ...modelled(gainFromDimension(evidence, components, 'ocsp-stapling'), 'OCSP Stapling'),
      rationale: ocspState.evidence,
    })
  }

  const lifetimeState = needsAction('certificate-lifetime')
  if (lifetimeState) {
    recommendations.push({
      id: 'certificate-automation',
      title: 'Automate certificate lifecycle and shorten issued lifetimes',
      priority: 'Medium',
      businessImpact: 'Prevents outages and makes algorithm rollover a routine operation.',
      effort: 'ACME / lifecycle automation',
      ...modelled(gainFromDimension(evidence, components, 'certificates'), 'Certificates'),
      rationale: lifetimeState.evidence,
    })
  }

  // Always last, and deliberately unscored: this scan cannot measure the thing
  // it is recommending, so it must not attach a number to it.
  const tail: Recommendation = {
    id: 'internal-inventory',
    title: 'Validate the internal cryptographic inventory (CBOM)',
    priority: 'High',
    businessImpact: 'The public edge is a fraction of the estate; internal crypto drives the real migration cost.',
    effort: 'Enterprise assessment',
    scoreGain: null,
    scoreGainTarget: null,
    scoreGainBasis: 'Not scored — this scan cannot observe the internal estate.',
    rationale: 'Source code, internal PKI, key management and workloads cannot be observed from the Internet.',
  }

  return [...recommendations.sort((a, b) => (b.scoreGain ?? 0) - (a.scoreGain ?? 0)), tail]
}

// ─── Governance (unknown by construction) ─────────────────────────────────────

const GOVERNANCE_REASON = 'Cannot be validated through public observation. Requires Enterprise Assessment.'

export function buildGovernance(): GovernanceItem[] {
  return [
    { key: 'policies', label: 'Cryptographic Policies', status: 'Unknown', reason: GOVERNANCE_REASON },
    { key: 'approvals', label: 'Approval Workflow', status: 'Unknown', reason: GOVERNANCE_REASON },
    { key: 'audit-trail', label: 'Audit Trail', status: 'Unknown', reason: GOVERNANCE_REASON },
    { key: 'inventory', label: 'Crypto Inventory', status: 'Unknown', reason: GOVERNANCE_REASON },
    { key: 'key-lifecycle', label: 'Key Lifecycle', status: 'Unknown', reason: GOVERNANCE_REASON },
    { key: 'compliance', label: 'Compliance Evidence', status: 'Unknown', reason: GOVERNANCE_REASON },
  ]
}

// ─── Counted public footprint ─────────────────────────────────────────────────

/**
 * Every tile is a direct count of something this scan observed, with the
 * observation named. A public scan cannot see application counts or crypto-asset
 * inventories, so it does not publish them — the items that genuinely require an
 * authenticated assessment are listed by name instead of guessed at with a
 * number.
 */
export function buildFootprint(evidence: PublicScanEvidence): FootprintEstimate {
  const extras = evidence.certificateExtras
  const sans = extras?.subjectAltNames ?? []
  const wildcards = sans.filter((san) => san.startsWith('*.'))
  const registrable = new Set(sans.map((san) => registrableFromName(san.replace(/^\*\./, ''))).filter(Boolean))

  const metrics: FootprintMetric[] = [
    {
      key: 'names',
      label: 'DNS Names Covered',
      value: sans.length,
      countedFrom: 'subjectAltName entries on the served leaf certificate',
      isLowerBound: true,
    },
    {
      key: 'domains',
      label: 'Registrable Domains',
      value: registrable.size,
      countedFrom: 'distinct registrable domains across those names',
      isLowerBound: true,
    },
    {
      key: 'wildcards',
      label: 'Wildcard Names',
      value: wildcards.length,
      countedFrom: 'SAN entries beginning with *.',
      isLowerBound: false,
    },
    {
      key: 'chain',
      label: 'Chain Certificates',
      value: extras?.chainDepth ?? 0,
      countedFrom: 'certificates presented in the TLS chain (leaf + intermediates)',
      isLowerBound: false,
    },
    {
      key: 'addresses',
      label: 'Public IP Addresses',
      value: evidence.dns.addressCount,
      countedFrom: 'A / AAAA records resolved for the scanned host',
      isLowerBound: true,
    },
    {
      key: 'protocols',
      label: 'TLS Versions Accepted',
      value: evidence.tls?.supportedProtocols.length ?? 0,
      countedFrom: 'per-version handshake probes against the endpoint',
      isLowerBound: false,
    },
    {
      key: 'suites',
      label: 'Cipher Suites Confirmed',
      value: evidence.cipherSuites.length,
      countedFrom: 'individual cipher-suite probes that completed a handshake',
      isLowerBound: true,
    },
    {
      key: 'groups',
      label: 'Key-Agreement Groups',
      value: evidence.keyAgreement.hybridGroups.length + evidence.keyAgreement.classicalGroups.length,
      countedFrom: 'named groups accepted when offered in isolation',
      isLowerBound: true,
    },
  ]

  return {
    metrics,
    exposureLevel: 'Internet Facing (Edge Only)',
    recommendedAssessment: 'Enterprise Discovery & Assessment',
    basis:
      'These are counts of what this scan observed at the public edge, not estimates of your estate. Values marked as a lower bound are floors — more exist behind the edge that a public scan cannot enumerate.',
    notCounted: [
      'Applications and services without a public certificate',
      'Internal hostnames, private PKI and issuing CAs',
      'Keys, HSMs and key-management inventory',
      'Cryptography inside source code and dependencies',
      'Database, storage and backup encryption',
      'Machine identities, tokens and service meshes',
    ],
  }
}

function registrableFromName(name: string): string {
  const labels = name.split('.').filter(Boolean)
  if (labels.length <= 2) return labels.join('.')
  const twoPart = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac'])
  const tail = labels.slice(-3)
  if (tail[1] && twoPart.has(tail[1]) && tail[2] && tail[2].length <= 3) return tail.join('.')
  return labels.slice(-2).join('.')
}

// ─── Sophia narrative ─────────────────────────────────────────────────────────

/**
 * The narrative restates values already shown elsewhere in the report; it never
 * introduces a number of its own, so it cannot contradict the other panels.
 */
export function buildSophia(evidence: PublicScanEvidence, summary: ExecutiveSummary): SophiaAssessment {
  const pq = computePostQuantumReadiness(evidence)
  const tlsVersion = evidence.tls?.tlsVersion?.replace('TLSv', 'TLS ') ?? 'no TLS'
  const certAlg = evidence.certificate?.publicKeyAlgorithm ?? 'an unreadable certificate'

  const posture = !summary.gradeable
    ? 'an edge that did not respond to enough probes to characterise'
    : summary.classicalScore >= 85
      ? 'strong classical cryptographic hygiene'
      : summary.classicalScore >= 65
        ? 'workable classical cryptography with specific hardening gaps'
        : 'material weaknesses in its public cryptographic configuration'

  const quantumClause = pq.hybridObserved
    ? `Hybrid post-quantum key agreement (${evidence.keyAgreement.hybridGroups.join(', ')}) is accepted at the edge, which places this endpoint ahead of most Internet-facing infrastructure. The certificate chain, however, is still anchored on ${certAlg}.`
    : `Key agreement remains ${resolveKeyExchange(evidence)} and the chain is anchored on ${certAlg}, so traffic captured today stays decryptable once a cryptographically relevant quantum computer exists.`

  const scoreClause = summary.gradeable
    ? `Post-quantum readiness measured at the edge is ${summary.postQuantumReadiness}%, against a classical transport score of ${summary.classicalScore} — a composite encryption score of ${summary.encryptionScore}/100.`
    : `Only ${summary.evidenceCoverage}% of the assessed dimensions responded, so no grade is published for this target.`

  return {
    headline: `${posture.charAt(0).toUpperCase()}${posture.slice(1)} on the public edge`,
    narrative: `Based on the observed ${tlsVersion} handshake, this organization demonstrates ${posture}. ${quantumClause} ${scoreClause}`,
    cannotValidate: [
      'Source code cryptography',
      'Internal PKI and certificate authorities',
      'Key management and HSM usage',
      'Database and storage encryption',
      'Cloud workloads and service meshes',
      'Identity tokens and machine identities',
      'Cryptographic governance and policy',
      'Compliance evidence and audit trails',
    ],
    recommendation:
      'A full Enterprise Assessment is required to validate post-quantum readiness and compliance across the whole estate.',
  }
}

// ─── Scope disclosure ─────────────────────────────────────────────────────────

export function buildScope(): AssessmentScope {
  return {
    analyzed: [
      'TLS protocol and cipher negotiation',
      'Named key-agreement groups, including hybrid ML-KEM',
      'Served X.509 certificate chain and trust validation',
      'Certificate Transparency and OCSP metadata',
      'Public DNS records and CAA issuance policy',
      'HTTP transport-security headers',
    ],
    notAnalyzed: [
      'Source code and repositories',
      'Internal infrastructure and networks',
      'Cloud workloads and containers',
      'Private PKI and certificate authorities',
      'Key management systems and HSMs',
      'Databases and storage encryption',
      'Enterprise cryptographic governance',
    ],
    statement:
      'This assessment analyzes publicly observable TLS, certificate, DNS and HTTP security metadata exposed by Internet-facing services. It does not inspect source code, internal infrastructure, cloud workloads, private PKI, key management systems, databases, or enterprise cryptographic governance. Authenticated Enterprise Discovery is required for complete visibility.',
  }
}

// ─── Severity ordering helper (shared with the UI) ────────────────────────────

export const SEVERITY_RANK: Record<ThreatLevel, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  SAFE: 1,
}

export function sortFindings(findings: PublicFinding[]): PublicFinding[] {
  return [...findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
}

export type { CertificateInfo, CipherSuiteDetail }
