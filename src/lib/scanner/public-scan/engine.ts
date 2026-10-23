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
import { censusFor, publishedPostQuantumReadiness, tls13ProvablyAbsent } from '../published-categories'
import { buildControlStates, findControl, resolveForwardSecrecy, resolveKeyExchange, symmetricStrength } from './controls'
import { CLASSICAL_CATEGORY_KEYS, RISK_ORDER, scoreToGrade } from './grading-model'
import { buildScoreCategories, toPublishedCategoryEvidence } from './score-categories'
import { detectPlatform, effortFor, remediationFor, type RemediationTopic } from './remediation'
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

// The group → ML-KEM parameter-set map used to be duplicated here. It now lives
// only in the TLS engine (`HYBRID_GROUP_KEM` in engines/tls-engine.ts), which is
// where the groups are actually probed, and the Cryptographic Intelligence panel
// reads the engine's catalogue rather than re-deriving names from a second copy.

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

/** How the hybrid key-agreement question was answered on this run. */
export type PostQuantumKeyAgreementState = 'hybrid' | 'pure-kem' | 'classical' | 'not-measured'

/**
 * Post-quantum readiness observable at the edge — a PROJECTION of the published
 * model's `post-quantum-readiness` category, never a second computation of it.
 *
 * This function used to feed `postQuantumReadinessFromSignals` from its own
 * reading of the evidence, while the score decomposition fed the same model from
 * `published-categories.ts`. The two readings differed on three signals (an
 * unsettled hybrid probe, standalone ML-KEM, and what "hardened HSTS" means), so
 * the Executive Summary published 26% beside a decomposition row reading "not
 * scored" for the same endpoint. There is now exactly one opinion: the shared
 * model's, read through the same adapter the decomposition uses.
 */
export function computePostQuantumReadiness(evidence: PublicScanEvidence): {
  /**
   * 0-100. Meaningless when `measured` is false — no consumer may publish it as
   * a percentage then: 55 of its 100 points come from hybrid key agreement, so
   * an unmeasured hybrid signal scores near 0 by construction and that is a
   * verdict this scan did not earn.
   */
  score: number
  /** False when the shared model withheld the category (see `unmeasuredReason`). */
  measured: boolean
  /** A hybrid ECDHE + ML-KEM group was accepted. */
  hybridObserved: boolean
  /** Standalone ML-KEM accepted with no hybrid group: post-quantum, no classical hedge. */
  pureKemObserved: boolean
  pqSignatureObserved: boolean
  /** The endpoint's measured protocol list excludes TLS 1.3, so hybrid is impossible. */
  tls13Absent: boolean
  keyAgreementState: PostQuantumKeyAgreementState
  reasons: string[]
} {
  const published = toPublishedCategoryEvidence(evidence)
  const shared = publishedPostQuantumReadiness(published)
  const { keyAgreement } = evidence
  const hybridObserved = keyAgreement.hybridGroups.length > 0
  const pureKemGroups = keyAgreement.pureKemGroups ?? []
  const pureKemObserved = !hybridObserved && pureKemGroups.length > 0
  const pqSignatureObserved = published.pqSignatureObserved
  const tls13Absent = tls13ProvablyAbsent(published.transport)

  if (!shared) {
    const reason =
      !published.transport.handshakeCompleted && !published.certificate
        ? 'Post-quantum readiness was not measured: no TLS handshake completed, so named key-agreement groups could not be offered to this endpoint.'
        : keyAgreement.probed
          ? 'Post-quantum readiness was not scored: no hybrid ML-KEM group reached a conclusive verdict on this run (group probing is the first thing many endpoints throttle), and hybrid key agreement carries 55 of its 100 points. Re-run the assessment to settle it.'
          : 'Post-quantum readiness was not scored: named key-agreement groups were not probed on this run, and hybrid key agreement carries 55 of its 100 points.'
    return {
      score: 0,
      measured: false,
      hybridObserved,
      pureKemObserved,
      pqSignatureObserved,
      tls13Absent,
      keyAgreementState: 'not-measured',
      reasons: [reason],
    }
  }

  /* The shared model words its first reason generically ("Hybrid post-quantum
     key agreement negotiated…" / "No hybrid … offered"). The public surface
     knows exactly which case it measured, so it states that instead. */
  const keyAgreementReason = hybridObserved
    ? `Hybrid post-quantum key agreement accepted: ${keyAgreement.hybridGroups.join(', ')}.`
    : pureKemObserved
      ? `Standalone ML-KEM key agreement accepted (${pureKemGroups.join(', ')}) — post-quantum, but with no classical hedge.`
      : tls13Absent
        ? 'No hybrid key agreement is possible: the endpoint does not offer TLS 1.3, where ML-KEM groups are defined.'
        : 'No hybrid or post-quantum key-agreement group was accepted when each was offered in isolation.'

  return {
    score: shared.score,
    measured: true,
    hybridObserved,
    pureKemObserved,
    pqSignatureObserved,
    tls13Absent,
    keyAgreementState: hybridObserved ? 'hybrid' : pureKemObserved ? 'pure-kem' : 'classical',
    reasons: [keyAgreementReason, ...shared.reasons.slice(1)],
  }
}

/**
 * The short form of the readiness state, for the Executive Summary card and the
 * hero — one sentence per measured case, so neither surface words it alone.
 */
function postQuantumDetail(pq: ReturnType<typeof computePostQuantumReadiness>, handshake: boolean): string {
  switch (pq.keyAgreementState) {
    case 'hybrid':
      return pq.pqSignatureObserved
        ? 'Hybrid ML-KEM key agreement and a post-quantum certificate signature observed.'
        : 'Hybrid ML-KEM key agreement accepted; the certificate signature is still classical.'
    case 'pure-kem':
      return 'Standalone ML-KEM accepted — post-quantum key agreement, but no classical hedge.'
    case 'classical':
      return pq.tls13Absent
        ? 'TLS 1.3 is not offered, so hybrid ML-KEM cannot be negotiated — enable TLS 1.3 first.'
        : 'No hybrid ML-KEM group was accepted — plan hybrid key agreement.'
    default:
      return !handshake
        ? 'No handshake completed, so key-agreement groups could not be offered.'
        : 'Hybrid ML-KEM support was not settled on this run, so readiness is not scored.'
  }
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
  } else if (computePostQuantumReadiness(evidence).measured) {
    factors.push('Named key-agreement groups probed (incl. hybrid ML-KEM)')
  } else {
    /* "Probed (incl. hybrid ML-KEM)" claimed the hybrid answer on a run where
       the hybrid groups never settled — the one signal readiness depends on. */
    score -= 4
    factors.push('Named key-agreement groups probed; hybrid ML-KEM did not settle')
  }
  if (!evidence.dns.caaQueryable) {
    score -= 4
    factors.push('CAA issuance policy not queryable')
  } else if (!evidence.dns.caaClimbComplete) {
    /* The leaf name answered but the climb to the registrable domain did not
       complete, so issuance policy is undetermined — the same confidence cost
       as an unqueryable name, because the same question is unanswered. */
    score -= 4
    factors.push('CAA issuance policy undetermined (climb to the registrable domain did not complete)')
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
  const rawEncryptionScore = computeClassicalScore(components)
  const classicalComponents = components.filter((component) => CLASSICAL_CATEGORY_KEYS.includes(component.key))
  const rawClassicalScore = computeClassicalScore(classicalComponents)
  const pq = computePostQuantumReadiness(evidence)
  const evidenceCoverage = computeEvidenceCoverage(components)
  const gradeable = evidenceCoverage >= MIN_GRADEABLE_COVERAGE
  const graded = scoreToGrade(rawEncryptionScore)

  /* Below the coverage floor the grade was already withheld — but the two scores
     it is derived from were still published as 0, and 0 is the worst MEASURED
     value on a higher-is-better scale. The gauge duly pointed at 0 and its
     legend said "Critical" underneath a badge that said "N/A · Insufficient
     evidence". Withholding the grade and publishing its inputs is not a partial
     fix; it is the same claim made twice, once honestly and once not. */
  const encryptionScore = gradeable ? rawEncryptionScore : null
  const classicalScore = gradeable ? rawClassicalScore : null
  /* PQ readiness is withheld on its own evidence, not on the composite's: the
     named-group probe is what measures it, and `computePostQuantumReadiness`
     reports whether that probe ran. */
  const postQuantumReadiness = pq.measured ? pq.score : null
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
      ? `${criticalCount} critical edge exposure${criticalCount === 1 ? ' requires' : 's require'} immediate action.`
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
    postQuantumReadiness,
    postQuantumKeyAgreement: pq.keyAgreementState,
    postQuantumSignatureObserved: pq.pqSignatureObserved,
    postQuantumDetail: postQuantumDetail(pq, Boolean(evidence.tls)),
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
  const acceptedGroups = [
    ...keyAgreement.hybridGroups,
    ...(keyAgreement.pureKemGroups ?? []),
    ...keyAgreement.classicalGroups,
  ]
  // Handshakes the named-group phase actually spent — provenance for the
  // Client Hello step, counted by the probe rather than assumed.
  const groupHandshakes = evidence.engines?.tls?.data?.groupHandshakes ?? 0

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
    /* The reachability preflight measures this directly, so the step reports a
       real number even when the TLS session probe never got far enough to time
       one — and, when the port refused or dropped the connection, it reports
       exactly which of those happened instead of a bare "not measured". */
    (() => {
      const reach = evidence.engines?.reachability?.data
      const connectMs = timing.tcpConnectMs ?? reach?.tcpConnectMs ?? null
      return {
        key: 'tcp',
        label: 'TCP Connect',
        value: connectMs !== null ? `${connectMs} ms` : (reach?.state ?? 'not measured'),
        detail:
          connectMs !== null
            ? `Port ${evidence.port} · measured on the assessment socket`
            : (reach?.detail ?? `Port ${evidence.port} did not answer`),
        observed: connectMs !== null,
        timingMs: connectMs,
      }
    })(),
    {
      key: 'client-hello',
      // What the SCANNER offered. Previously the static string "TLS 1.0–1.3
      // offered", which stayed on screen even for an endpoint where the probe
      // never got that far, and told the reader nothing about this scan.
      label: 'Client Hello',
      value: tls
        ? groupHandshakes
          ? `${groupHandshakes} isolated group probes`
          : 'single-group probe unavailable'
        : 'no response',
      detail: acceptedGroups.length
        ? `Accepted when offered alone: ${acceptedGroups.join(', ')}`
        : keyAgreement.probed
          ? 'Every offered group was refused or answered inconsistently'
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
/** The ONE control-status -> attack-surface-tone mapping. Exported so the
 *  verification harness asserts against this table rather than keeping a second
 *  copy that drifts from it (which is how a missing 'High' key went unnoticed
 *  on both sides at once). */
export const STATUS_TO_SURFACE: Record<string, SurfaceStatus> = {
  Healthy: 'pass',
  Warning: 'partial',
  /* The Attack Surface has only pass/partial/fail, so a HIGH-severity control
     lands on 'fail' alongside Critical. Omitting this key let the lookup fall
     through to 'unknown', which painted tls-version and cipher-suite grey on
     the Attack Surface while the Findings table showed them as failures. */
  High: 'fail',
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

  /**
   * ONE algorithm inventory, not two.
   *
   * This panel used to re-derive its own list from the same raw evidence the
   * Cryptographic Intelligence Engine had already catalogued — and the two
   * disagreed. The engine catalogues every accepted named group and every
   * accepted protocol version; this panel only ever emitted the negotiated
   * ones. The `cryptographic-algorithms` score category counts the ENGINE's
   * array, so the Encryption Score could state "7 algorithms observed" beside
   * a panel listing four of them. Projecting the engine catalogue makes the
   * count, the classification and the score one fact with one source.
   */
  /* …and the array that category counts is now the shared ALGORITHM CENSUS
     (`censusFor`), not the engine catalogue. When the category moved to the
     census, this panel kept listing the catalogue, so cloudflare.com's score row
     read "14 algorithms observed" above a panel listing 8. The census is
     documented as "the number every panel must quote"; the panel now lists it. */
  const census = censusFor(toPublishedCategoryEvidence(evidence))
  const CENSUS_CLASSIFICATION: Record<string, string> = {
    'post-quantum': 'Post-Quantum',
    'quantum-vulnerable': 'Quantum-vulnerable',
    'grover-affected': 'Grover-affected',
    protocol: 'Protocol',
    unclassified: 'Unclassified',
  }
  const observedAlgorithms: CryptoIntelligence['observedAlgorithms'] = census.entries.map((entry) => ({
    name: entry.name,
    role: entry.role,
    quantumVulnerable: entry.quantumVulnerable,
    classification: entry.classicallyBroken
      ? 'Classically broken'
      : entry.legacyProtocol
        ? 'Deprecated protocol'
        : entry.belowPqMargin
          ? 'Below the 128-bit PQ margin'
          : (CENSUS_CLASSIFICATION[entry.cls] ?? entry.cls),
    evidenceSource: 'algorithm census — TLS handshake, served chain and named-group probe',
  }))

  const kex = resolveKeyExchange(evidence)
  const fs = resolveForwardSecrecy(evidence)
  /* Three states, not two. The `!evidence.tls` branch is the one that matters:
     without a handshake there is nothing to observe, and saying "Not observed"
     there claims a measurement that never happened — while the Forward Secrecy
     control on the same report correctly said "Unknown". One fact, one answer. */
  const forwardSecrecy: CryptoIntelligence['forwardSecrecy'] = !evidence.tls
    ? 'Not measured'
    : fs.enabled
      ? evidence.cipherSuites.some((suite) => suite.category === 'rsa-kex')
        ? 'Partial'
        : 'Enabled'
      : 'Not observed'

  // Migration targets are only listed for primitives this scan actually saw.
  // Standalone ML-KEM is already the FIPS 203 target, so it is not re-proposed.
  const migrationTargets: CryptoIntelligence['migrationTargets'] = []
  if (!pq.hybridObserved && !pq.pureKemObserved && tls) {
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
  /* Only claim "sustain hybrid" when hybrid was actually observed. The
     unconditional fallback this replaces fired on an endpoint where nothing at
     all was measured, telling the reader to maintain a hybrid group the scan had
     never seen and citing "no classical-only primitive observed at the edge" —
     technically true, because NOTHING was observed at the edge. */
  if (!migrationTargets.length && pq.hybridObserved) {
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
    /* `Unknown` is reported when the key-agreement dimension was never probed.
       Reporting `Vulnerable` there stated a measured verdict about an endpoint
       that had refused every connection — and paired it with the reason "No
       hybrid or post-quantum key agreement offered", which reads as an
       observation about the target rather than about the scan. */
    quantumVulnerability: !pq.measured
      ? 'Unknown'
      : pq.hybridObserved || pq.pureKemObserved
        ? pq.pqSignatureObserved
          ? 'Quantum-safe'
          : pq.hybridObserved
            ? 'Hybrid-protected'
            : 'PQ-protected'
        : 'Vulnerable',
    quantumVulnerabilityReason: pq.reasons[0],
    migrationTargets,
    confidence,
  }
}

// ─── Quantum exposure timeline ────────────────────────────────────────────────

/**
 * The timeline is THIS endpoint's exposure story, not a generic PQC explainer.
 *
 * Every phase that can be tied to an observation now is: the "Today" line
 * describes the posture actually measured (it used to congratulate a failing
 * endpoint on "strong classical cryptography" regardless of score), and the
 * hybrid phase names the group this endpoint actually accepts instead of always
 * printing X25519MLKEM768.
 *
 * Two horizons — the CRQC estimate and the NIST dates — are external facts, not
 * measurements, and they are labelled as such rather than presented as findings
 * about the target.
 */
export function buildTimeline(evidence: PublicScanEvidence): TimelinePhase[] {
  const pq = computePostQuantumReadiness(evidence)
  const hybridGroups = evidence.keyAgreement.hybridGroups
  const pureKem = evidence.keyAgreement.pureKemGroups ?? []
  const groups = hybridGroups.join(', ')
  const kex = resolveKeyExchange(evidence)
  const certificateAlgorithm = evidence.certificate?.publicKeyAlgorithm ?? null
  const legacyProtocols = (evidence.tls?.supportedProtocols ?? []).filter((protocol) =>
    /TLSv1$|TLSv1\.1|SSL/i.test(protocol),
  )

  /* Nothing on this timeline may describe THIS endpoint when nothing about it was
     measured. The un-gated version rendered "Key agreement is unknown with no
     post-quantum group offered — classical protection only" and "Sessions
     harvested today become readable once unknown is broken" — a harvest-now
     narrative built around the literal string "unknown", asserting classical
     exposure for an endpoint that never completed a handshake.

     The three forward-looking phases (CRQC horizon, hybrid availability, full
     PQC adoption) are industry context and stay as they are; the four that make
     claims about the target are replaced with what actually happened. */
  const measured = pq.measured
  /* Two different reasons for "not measured", and they must not share copy:
     with no handshake nothing about the endpoint is known, but an unsettled
     hybrid probe still observed the classical key agreement and the chain. */
  const handshake = Boolean(evidence.tls)
  /* Post-quantum KEY AGREEMENT — hybrid or standalone ML-KEM — is what decides
     harvest-now exposure. Standalone ML-KEM is not hybrid (no classical hedge),
     but recorded sessions are no more decryptable by a CRQC than hybrid ones. */
  const pqKex = pq.hybridObserved || pq.pureKemObserved
  const pqGroups = pq.hybridObserved ? groups : pureKem.join(', ')

  // The "Today" line states what was measured about this endpoint.
  const todayDescription = !handshake
    ? `No handshake completed against this endpoint, so its key agreement and certificate chain are unknown. Nothing on this timeline below is a measurement of this target.`
    : !measured
      ? `Key agreement observed on this run is ${kex}; whether a hybrid ML-KEM group is also accepted did not settle, so post-quantum protection is not claimed either way.`
      : pq.hybridObserved
        ? `Hybrid post-quantum key agreement (${groups}) protects new sessions; the chain is still signed with ${certificateAlgorithm ?? 'a classical algorithm'}.`
        : legacyProtocols.length
          ? `Key agreement is ${kex}, and deprecated ${legacyProtocols.join('/')} is still accepted — no quantum protection, and a live downgrade path.`
          : pureKem.length
            ? `Standalone ${pureKem.join(', ')} protects new sessions with post-quantum key agreement, but no hybrid group is offered, so there is no classical hedge.`
            : `Key agreement is ${kex} with no post-quantum group offered — classical protection only.`

  return [
    {
      key: 'today',
      title: 'Today',
      description: todayDescription,
      state: 'now',
      horizon: 'Now',
    },
    {
      key: 'harvest',
      title: 'Harvest Now',
      description: !handshake
        ? 'Whether traffic to this endpoint is harvestable cannot be determined without observing its key agreement.'
        : !measured
          ? `Sessions negotiated with ${kex} can be recorded today; whether clients that offer hybrid ML-KEM are protected was not settled on this run.`
          : pqKex
            ? `Recorded sessions are protected by ML-KEM (${pqGroups}); only captures from before this rollout remain exposed.`
            : `Traffic protected by ${kex} can be recorded today and stored until it is decryptable.`,
      state: !measured ? 'future' : pqKex ? 'future' : 'active',
      horizon: 'Ongoing',
    },
    {
      key: 'crqc',
      title: 'Quantum Computer Available',
      description:
        'A cryptographically relevant quantum computer breaks RSA and ECC key exchange. This horizon is an external forecast, not a measurement of this endpoint — NIST IR 8547 plans the transition around it rather than predicting a date.',
      state: 'future',
      horizon: 'Forecast · NIST IR 8547',
    },
    {
      key: 'decryption',
      title: 'Potential Decryption Risk',
      description: !handshake
        ? 'Not assessable — the key agreement protecting this endpoint’s sessions was never observed.'
        : !measured
          ? `Sessions negotiated with ${kex.split(' (')[0]} become readable once it is broken; post-quantum coverage for hybrid-capable clients was not settled on this run.`
          : pqKex
            ? 'Only traffic captured before the ML-KEM rollout becomes readable.'
            : `Sessions harvested today become readable once ${kex.split(' (')[0]} is broken.`,
      state: 'future',
      horizon: 'Post-CRQC',
    },
    {
      key: 'migration',
      title: 'Recommended Migration',
      description: !handshake
        ? 'Restore reachability on this port, or assess the service from inside the network, before a migration position can be recommended for it. NIST IR 8547 deprecates 112-bit classical key establishment from 2030 regardless.'
        : !measured
          ? 'Re-run the assessment to settle hybrid ML-KEM support before committing to a migration position for this endpoint. NIST IR 8547 deprecates 112-bit classical key establishment from 2030.'
          : pqKex
            ? 'Post-quantum key agreement is live at this edge; extend the same rollout to internal services and machine identities. NIST IR 8547 deprecates 112-bit classical key establishment from 2030.'
            : pq.tls13Absent
              ? 'Enable TLS 1.3 — the prerequisite for any hybrid ML-KEM group — then begin the hybrid PQC rollout. NIST IR 8547 deprecates 112-bit classical key establishment (RSA-2048, ECC P-256) from 2030.'
              : 'Begin hybrid PQC rollout so long-lived data stops accumulating exposure. NIST IR 8547 deprecates 112-bit classical key establishment (RSA-2048, ECC P-256) from 2030.',
      state: pqKex ? 'now' : 'target',
      horizon: 'Deprecated 2030 · NIST IR 8547',
    },
    {
      key: 'hybrid',
      title: 'Hybrid TLS Deployment',
      description: pq.hybridObserved
        ? `${groups} accepted — classical and ML-KEM (FIPS 203) key agreement combined on this endpoint.`
        : 'A hybrid group combines classical ECDHE with ML-KEM (FIPS 203), so a break in either alone does not expose the session.',
      state: pq.hybridObserved ? 'now' : 'target',
      horizon: pq.hybridObserved ? 'Deployed here' : 'Available today',
    },
    {
      key: 'full-pqc',
      title: 'Full PQC Adoption',
      description: pq.pqSignatureObserved && pqKex
        ? 'ML-KEM (FIPS 203) key agreement and a post-quantum signature (FIPS 204/205) are both present on this endpoint.'
        : pqKex
          ? `Key agreement is post-quantum; the remaining gap is the ${certificateAlgorithm ?? 'classical'} certificate signature. NIST IR 8547 disallows 112-bit classical signatures after 2035.`
          : 'ML-KEM (FIPS 203) and ML-DSA (FIPS 204) across certificates, transport and signing. NIST IR 8547 disallows 112-bit classical algorithms after 2035.',
      state: pq.pqSignatureObserved && pqKex ? 'now' : 'target',
      horizon: 'Disallowed 2035 · NIST IR 8547',
    },
  ]
}

// ─── Recommendations ──────────────────────────────────────────────────────────

/**
 * A recommendation's priority IS the severity of the finding it responds to.
 *
 * The two used to be assigned independently, so the Findings table read "TLS
 * Version · High" while the recommendation fixing it read "Critical" — two
 * urgency claims about one observation on the same screen. The certificate
 * recommendation was already reconciled this way; every finding-driven
 * recommendation now is.
 */
const PRIORITY_FOR_SEVERITY: Record<ThreatLevel, Recommendation['priority']> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  SAFE: 'Low',
}

/**
 * Modelled point gain on the ENCRYPTION SCORE — the number the gauge and the
 * grade show — if one change were made, every other observation held constant.
 *
 * This used to be measured on a private composite, `classical × 0.6 + PQ × 0.4`,
 * that appears nowhere else in the report. Post-quantum readiness carries 3 of
 * the published model's 100 points but 40 of that composite's, so "Adopt hybrid
 * key exchange" was published at +26 on expired.badssl.com, where the graded
 * score actually moves by a fraction of that — and Sophia quoted the +26 as the
 * headline. The change is now applied to the EVIDENCE and re-scored by the same
 * twelve-category model the grade comes from, so a re-scan after the change
 * would land on the modelled number.
 */
function gainFromEvidence(
  evidence: PublicScanEvidence,
  components: ScoreComponent[],
  mutate: (draft: PublicScanEvidence) => PublicScanEvidence,
): number {
  const current = computeClassicalScore(components)
  const next = computeClassicalScore(buildScoreComponents(mutate(evidence)))
  return Math.max(0, next - current)
}

/**
 * Gain from bringing one category to `passing`, for a change no evidence field
 * models (a header set, a CAA RRset, a stapled response). Only used for
 * categories no other category reads from, so nothing coupled is missed.
 */
function categoryGain(components: ScoreComponent[], key: string, passing: number): number {
  const current = computeClassicalScore(components)
  const improved = components.map((component) =>
    component.key === key ? { ...component, score: passing, applicable: true } : component,
  )
  return Math.max(0, computeClassicalScore(improved) - current)
}

/* ── Evidence mutations: each one models a single operator change. ───────── */

const isLegacyTls = (protocol: string) => protocol === 'TLSv1' || protocol === 'TLSv1.1'

/**
 * TLS 1.3 offered. The hybrid probe is marked settled on a refusal, so enabling
 * the protocol does not turn a measured readiness into an unmeasured one by
 * opening a question the model would then have to leave unanswered.
 */
function withTls13(draft: PublicScanEvidence): PublicScanEvidence {
  if (!draft.tls || draft.tls.supportedProtocols.includes('TLSv1.3')) return draft
  return {
    ...draft,
    tls: { ...draft.tls, supportedProtocols: [...draft.tls.supportedProtocols, 'TLSv1.3'] },
    keyAgreement: { ...draft.keyAgreement, probed: true, hybridSettled: true },
  }
}

function withoutLegacyTls(draft: PublicScanEvidence): PublicScanEvidence {
  const next = withTls13(draft)
  if (!next.tls) return next
  return { ...next, tls: { ...next.tls, supportedProtocols: next.tls.supportedProtocols.filter((p) => !isLegacyTls(p)) } }
}

function withHybridGroup(draft: PublicScanEvidence): PublicScanEvidence {
  const next = withTls13(draft)
  return {
    ...next,
    keyAgreement: {
      ...next.keyAgreement,
      probed: true,
      hybridSettled: true,
      hybridGroups: ['X25519MLKEM768'],
      primaryGroup: 'X25519MLKEM768',
      forwardSecrecy: true,
    },
  }
}

function withPostQuantumCertificate(draft: PublicScanEvidence): PublicScanEvidence {
  if (!draft.certificate) return draft
  return {
    ...draft,
    certificate: { ...draft.certificate, publicKeyAlgorithm: 'ML-DSA-65', signatureAlgorithm: 'ML-DSA-65' },
  }
}

/** Every accepted suite ephemeral: static-RSA key transport removed. */
function withEphemeralSuitesOnly(draft: PublicScanEvidence): PublicScanEvidence {
  return {
    ...draft,
    cipherSuites: draft.cipherSuites.filter((suite) => suite.category !== 'rsa-kex'),
    keyAgreement: { ...draft.keyAgreement, forwardSecrecy: true },
  }
}

/** The 256-bit variant of the negotiated AEAD suite (Grover leaves a 128-bit margin). */
function withAes256(draft: PublicScanEvidence): PublicScanEvidence {
  const suite = draft.tls?.cipherSuite
  if (!draft.tls || !suite || symmetricStrength(suite) !== 128) return draft
  const upgraded = suite
    .replace(/AES_128_GCM_SHA256/g, 'AES_256_GCM_SHA384')
    .replace(/AES128-GCM-SHA256/g, 'AES256-GCM-SHA384')
    .replace(/_128_/g, '_256_')
    .replace(/AES128/g, 'AES256')
  return { ...draft, tls: { ...draft.tls, cipherSuite: upgraded } }
}

function withHardenedHsts(draft: PublicScanEvidence): PublicScanEvidence {
  const http = draft.engines?.http
  if (!http) return draft
  const hsts = http.data.hsts
  return {
    ...draft,
    engines: {
      ...draft.engines,
      http: {
        ...http,
        data: {
          ...http.data,
          hsts: { ...hsts, present: true, maxAge: Math.max(hsts.maxAge ?? 0, 31_536_000), includeSubDomains: true },
        },
      },
    },
  }
}

/** A like-for-like reissue: same key type, trusted chain, full lifetime ahead. */
function withReissuedCertificate(draft: PublicScanEvidence, lifetimeDays?: number): PublicScanEvidence {
  if (!draft.certificate) return draft
  const extras = draft.certificateExtras
  const validityDays = lifetimeDays ?? extras?.validityDays ?? 90
  return {
    ...draft,
    certificate: {
      ...draft.certificate,
      isExpired: false,
      isSelfSigned: false,
      chain: (draft.certificate.chain ?? []).map((entry) => ({ ...entry, isExpired: false })),
    },
    certificateExtras: extras
      ? { ...extras, chainTrusted: true, trustError: null, validityDays, daysRemaining: validityDays }
      : extras,
  }
}

export function buildRecommendations(
  evidence: PublicScanEvidence,
  controls: ControlState[],
  components: ScoreComponent[],
): Recommendation[] {
  const pq = computePostQuantumReadiness(evidence)
  const recommendations: Recommendation[] = []
  /* A gain is a statement about the encryption score. When the score itself is
     withheld (too little of the edge answered), there is nothing to add points
     to, and a "+6" beside a "—" gauge would be a number with no referent. */
  const scored = computeEvidenceCoverage(components) >= MIN_GRADEABLE_COVERAGE

  // The platform is read from the fingerprint this scan collected — never
  // assumed. When nothing was detected both helpers fall back to generic text.
  const platform = detectPlatform(evidence.engines?.http?.data?.fingerprint)
  const platformEffort = (fallback: string) => effortFor(platform, fallback)
  const platformRemediation = (topic: RemediationTopic) => remediationFor(platform, topic)

  const modelled = (
    gain: number,
    change: string,
  ): Pick<Recommendation, 'scoreGain' | 'scoreGainTarget' | 'scoreGainBasis'> =>
    scored
      ? {
          scoreGain: Math.round(gain),
          scoreGainTarget: 'encryption',
          scoreGainBasis: `Modelled by re-running the published 12-category scoring model with ${change}; every other observation held constant.`,
        }
      : {
          scoreGain: null,
          scoreGainTarget: null,
          scoreGainBasis: 'Not scored — the encryption score is withheld for this assessment, so there is no score to add points to.',
        }

  /** A control only generates a recommendation when it actually failed. */
  const needsAction = (key: string) => {
    const state = findControl(controls, key)
    if (!state) return null
    /* 'High' joins the actionable set: it is the tier a CRITICAL-looking
       control is reconciled to when its severity is HIGH (see reconcileStatus),
       so omitting it would silently drop those recommendations. */
    return state.status === 'Critical' || state.status === 'High'
      || state.status === 'Not Supported' || state.status === 'Warning' ? state : null
  }
  const priorityOf = (state: ControlState) => PRIORITY_FOR_SEVERITY[state.severity] ?? 'Low'

  const tlsState = needsAction('tls-version')
  if (tlsState) {
    const tls13Missing = !evidence.tls?.supportedProtocols.includes('TLSv1.3')
    recommendations.push({
      id: 'disable-legacy-tls',
      title: tls13Missing
        ? 'Disable deprecated TLS 1.0/1.1 and enable TLS 1.3'
        : 'Disable deprecated TLS 1.0/1.1',
      priority: priorityOf(tlsState),
      businessImpact: 'Removes downgrade paths and clears a common audit finding.',
      effort: platformEffort('Configuration change'),
      ...modelled(
        gainFromEvidence(evidence, components, withoutLegacyTls),
        tls13Missing ? 'TLS 1.0/1.1 refused and TLS 1.3 offered' : 'TLS 1.0/1.1 refused',
      ),
      rationale: tlsState.evidence,
      remediation: platformRemediation('tls-version'),
    })
  }

  /* Hybrid key agreement is recommended only on a MEASURED absence — the
     `pq-key-agreement` control's "Not Supported" or standalone-ML-KEM verdict.
     It used to fire whenever no hybrid group happened to be in the accepted
     list, including runs where the hybrid probe never settled, and told the
     reader "no hybrid group was accepted during the named-group probe" about a
     probe that had reached no answer. */
  const pqState = findControl(controls, 'pq-key-agreement')
  if (pqState && evidence.tls && (pqState.status === 'Not Supported' || pq.pureKemObserved)) {
    recommendations.push({
      id: 'hybrid-kex',
      title: pq.pureKemObserved
        ? 'Offer hybrid X25519MLKEM768 alongside standalone ML-KEM'
        : pq.tls13Absent
          ? 'Enable TLS 1.3 and adopt hybrid post-quantum key exchange (X25519MLKEM768)'
          : 'Adopt hybrid post-quantum key exchange (X25519MLKEM768)',
      priority: priorityOf(pqState),
      businessImpact: pq.pureKemObserved
        ? 'Adds a classical hedge to the post-quantum key agreement already in place.'
        : 'Stops new traffic from accumulating harvest-now-decrypt-later exposure.',
      effort: platformEffort('TLS terminator / CDN setting'),
      ...modelled(
        gainFromEvidence(evidence, components, withHybridGroup),
        pq.tls13Absent ? 'TLS 1.3 offered and a hybrid ML-KEM group accepted' : 'a hybrid ML-KEM group accepted',
      ),
      rationale: pqState.evidence,
      remediation: platformRemediation('hybrid-kex'),
    })
  }

  const certificateAlgorithmState = findControl(controls, 'certificate-algorithm')
  if (!pq.pqSignatureObserved && evidence.certificate) {
    recommendations.push({
      id: 'pq-signature-roadmap',
      title: 'Prepare a post-quantum certificate roadmap with your CA',
      // A classical leaf is a MEDIUM finding; a broken one (expired, sub-2048
      // RSA) is answered by the certificate-replacement card, not this one.
      priority:
        certificateAlgorithmState && certificateAlgorithmState.severity !== 'CRITICAL'
          ? priorityOf(certificateAlgorithmState)
          : 'Medium',
      businessImpact: 'Aligns certificate issuance with the FIPS 204 signature standard.',
      effort: 'Depends on CA availability',
      ...modelled(
        gainFromEvidence(evidence, components, withPostQuantumCertificate),
        'an ML-DSA-65 leaf key and signature on the served chain',
      ),
      rationale: `The served chain is signed with ${evidence.certificate.signatureAlgorithm}.`,
    })
  }

  /**
   * ONE recommendation for static-RSA key transport, not two.
   *
   * "Remove static-RSA suites" (cipher-suite) and "Require ephemeral key
   * agreement on every accepted suite" (forward-secrecy) were emitted together
   * for the same root cause, so the page listed one configuration change twice
   * and summed its benefit twice. The forward-secrecy control is the consequence
   * of the cipher-suite one whenever static RSA is the reason it is partial.
   */
  const cipherState = needsAction('cipher-suite')
  const fsState = needsAction('forward-secrecy')
  const staticRsa = evidence.cipherSuites.some((suite) => suite.category === 'rsa-kex')
  const noForwardSecrecy = Boolean(fsState) && !resolveForwardSecrecy(evidence).enabled
  const aes128 = symmetricStrength(evidence.tls?.cipherSuite) === 128
  if (staticRsa || noForwardSecrecy) {
    const driver = [cipherState, fsState]
      .filter((state): state is ControlState => Boolean(state))
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])[0]
    recommendations.push({
      id: 'strengthen-cipher-suites',
      title: `${noForwardSecrecy ? 'Require ephemeral (EC)DHE key agreement on every accepted suite' : 'Remove static-RSA key-transport suites'}${aes128 ? ' and prefer 256-bit AEAD' : ''}`,
      priority: driver ? priorityOf(driver) : 'High',
      businessImpact: 'Every accepted suite becomes forward secret, so one server-key compromise no longer unlocks recorded traffic.',
      effort: platformEffort('Cipher-suite policy change'),
      ...modelled(
        gainFromEvidence(evidence, components, (draft) => withAes256(withEphemeralSuitesOnly(draft))),
        `static-RSA suites refused${aes128 ? ' and a 256-bit AEAD negotiated' : ''}`,
      ),
      rationale: (cipherState ?? fsState)!.evidence,
      remediation: platformRemediation(noForwardSecrecy && !staticRsa ? 'forward-secrecy' : 'cipher-suite'),
    })
  } else if (cipherState && aes128) {
    recommendations.push({
      id: 'prefer-aes-256',
      title: 'Prefer 256-bit AEAD cipher suites',
      priority: priorityOf(cipherState),
      businessImpact: 'Restores a 128-bit post-quantum margin on the symmetric layer (Grover halves key strength).',
      effort: platformEffort('Cipher-suite policy change'),
      ...modelled(gainFromEvidence(evidence, components, withAes256), 'a 256-bit AEAD negotiated'),
      rationale: cipherState.evidence,
      remediation: platformRemediation('cipher-suite'),
    })
  }

  const caaState = findControl(controls, 'dns-caa')
  if (caaState?.status === 'Not Supported') {
    recommendations.push({
      id: 'enable-caa',
      title: 'Publish DNS CAA records restricting certificate issuance',
      priority: priorityOf(caaState),
      businessImpact: 'Blocks unauthorised CAs from issuing for your domain.',
      effort: 'DNS record change',
      ...modelled(categoryGain(components, 'dns-caa', 100), 'a CAA RRset published'),
      rationale: caaState.evidence,
    })
  }

  /**
   * HSTS — the title states the actual gap.
   *
   * This used to be a fixed "Enforce HSTS with includeSubDomains and preload"
   * on every non-perfect policy, which told an operator already sending a
   * one-year includeSubDomains policy to go and do the thing they had done, and
   * pushed preload at names that are not eligible for it. The control now
   * carries the specific next step; the recommendation quotes it.
   */
  const hstsState = needsAction('hsts')
  if (hstsState && hstsState.status !== 'Unknown') {
    const hstsDetail = evidence.engines?.http?.data?.hsts
    const absent = !hstsDetail?.present
    recommendations.push({
      id: 'enable-hsts',
      title: absent
        ? 'Enable HSTS to remove the plaintext first-contact window'
        : !hstsDetail?.includeSubDomains
          ? 'Extend the HSTS policy to subdomains'
          : 'Raise the HSTS max-age to a full year',
      priority: priorityOf(hstsState),
      businessImpact: absent
        ? 'Removes the plaintext first-contact window for returning users.'
        : !hstsDetail?.includeSubDomains
          ? 'Closes the downgrade path that remains on every subdomain of this name.'
          : 'Keeps returning users pinned to HTTPS for a full year between visits.',
      effort: platformEffort('Response-header change'),
      ...modelled(
        gainFromEvidence(evidence, components, withHardenedHsts),
        'Strict-Transport-Security: max-age=31536000; includeSubDomains',
      ),
      rationale: `${hstsState.evidence} — ${hstsState.nextStep}`,
      remediation: platformRemediation('hsts'),
    })
  }

  const headerState = needsAction('http-security')
  if (headerState) {
    recommendations.push({
      id: 'harden-http-headers',
      title: 'Complete the transport-security header set',
      priority: priorityOf(headerState),
      businessImpact: 'Closes gaps that let transport protections be bypassed in-page.',
      effort: platformEffort('Response-header change'),
      ...modelled(categoryGain(components, 'http-security-headers', 100), 'every assessed transport header hardened'),
      rationale: headerState.evidence,
      remediation: platformRemediation('security-headers'),
    })
  }

  /**
   * OCSP stapling — only when the certificate actually advertises a responder.
   *
   * `needsAction` already skips `Not Applicable`, but the condition is written
   * out because it is the whole point: stapling is physically impossible
   * without an AIA OCSP URI, and recommending it to a Let's Encrypt or
   * Cloudflare endpoint (whose CAs have retired OCSP in favour of short-lived
   * certificates + CT) is advice the operator cannot act on. That was a false
   * positive, not a finding.
   */
  const ocspState = needsAction('ocsp-stapling')
  const ocspResponderAdvertised = Boolean(evidence.certificateExtras?.ocspUri)
  if (ocspState && ocspResponderAdvertised) {
    const responderUnreachable = evidence.certificateExtras?.ocspResponderState === 'unreachable'
    recommendations.push({
      id: 'enable-ocsp-stapling',
      title: responderUnreachable
        ? 'Enable OCSP stapling — the advertised responder is not answering'
        : 'Enable OCSP stapling at the TLS terminator',
      priority: priorityOf(ocspState),
      businessImpact: responderUnreachable
        ? 'Clients that soft-fail revocation are currently performing no revocation check for this endpoint.'
        : 'Removes a CA round-trip from every new client connection.',
      effort: platformEffort('TLS terminator setting'),
      ...modelled(categoryGain(components, 'ocsp-stapling', 100), 'an OCSP response stapled in the handshake'),
      rationale: ocspState.evidence,
      remediation: platformRemediation('ocsp-stapling'),
    })
  }

  /**
   * Certificate validity, graded by what actually failed.
   *
   * This used to emit one Medium-priority "automate the lifecycle" card for
   * every certificate problem — including an expired certificate and a chain
   * that does not verify. Those are not lifecycle-hygiene suggestions: the
   * endpoint is broken for every visitor right now. The priority now comes from
   * the finding the card responds to, so it can never disagree with that row.
   */
  const extras = evidence.certificateExtras
  const expired = extras ? extras.daysRemaining <= 0 : false
  const untrusted = extras ? !extras.chainTrusted : false
  const expiringSoon = extras ? extras.daysRemaining > 0 && extras.daysRemaining <= 14 : false
  const lifetimeState = needsAction('certificate-lifetime')
  const issuerState = findControl(controls, 'certificate-issuer')
  /* A CRITICAL hostname mismatch used to produce no recommendation at all:
     Node's chain verdict (`authorized`) is independent of RFC 6125 name
     matching, so a trusted chain for the wrong name skipped every branch. */
  const hostnameState = findControl(controls, 'hostname-coverage')
  const hostnameMismatch = hostnameState?.status === 'Critical'

  if (untrusted || expired || hostnameMismatch) {
    const driver = expired ? (lifetimeState ?? issuerState) : untrusted ? issuerState : hostnameState
    const replace = modelled(
      gainFromEvidence(evidence, components, (draft) => withReissuedCertificate(draft)),
      'a valid, publicly trusted reissue of the same key type',
    )
    recommendations.push({
      id: 'certificate-replace',
      title: expired
        ? 'Replace the expired certificate immediately'
        : untrusted
          ? 'Replace the certificate — the served chain does not verify'
          : 'Reissue the certificate to cover this hostname',
      priority: driver ? priorityOf(driver) : 'Critical',
      businessImpact: expired
        ? 'The certificate has already expired: every browser is showing an interstitial and clients are failing to connect.'
        : untrusted
          ? 'The served chain does not verify against the public trust store, so clients cannot authenticate this endpoint.'
          : 'Every browser shows a name-mismatch error and refuses the connection for this hostname.',
      effort: 'Immediate reissue',
      /* Hostname coverage is reported, not graded — none of the twelve
         categories reads it — so a mismatch-only reissue has no modelled gain
         to state. "+0" beside a Critical card would read as "this does not
         matter"; "Not scored" says what is actually true. */
      ...(!expired && !untrusted && replace.scoreGain === 0
        ? {
            scoreGain: null,
            scoreGainTarget: null,
            scoreGainBasis: 'Not scored — hostname coverage is reported but is not one of the twelve graded categories.',
          }
        : replace),
      rationale:
        extras && !extras.chainTrusted && extras.trustError
          ? `Chain verification failed: ${extras.trustError}.`
          : expired
            ? (lifetimeState?.evidence ?? 'Served certificate is past its notAfter date.')
            : (hostnameState?.evidence ?? 'The certificate does not cover the scanned name.'),
    })
  } else if (expiringSoon && lifetimeState) {
    recommendations.push({
      id: 'certificate-renew',
      title: 'Renew the certificate before it expires',
      priority: priorityOf(lifetimeState),
      businessImpact: 'An expiry-driven outage takes the endpoint down for every client at once.',
      effort: 'Reissue + deploy',
      ...modelled(
        gainFromEvidence(evidence, components, (draft) => withReissuedCertificate(draft)),
        'the certificate renewed for its full lifetime',
      ),
      rationale: lifetimeState.evidence,
    })
  } else if (lifetimeState) {
    recommendations.push({
      id: 'certificate-automation',
      title: 'Automate certificate lifecycle and shorten issued lifetimes',
      priority: priorityOf(lifetimeState),
      businessImpact: 'Prevents outages and makes algorithm rollover a routine operation.',
      effort: 'ACME / lifecycle automation',
      ...modelled(
        gainFromEvidence(evidence, components, (draft) => withReissuedCertificate(draft, 90)),
        'a freshly issued 90-day certificate',
      ),
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

  /**
   * Priority first, modelled gain second.
   *
   * Sorting by score gain alone put a Medium card above a High one on the same
   * screen where both carry a priority badge — the reader sees "Medium" ranked
   * over "High" and has to decide which signal to believe. Priority is the
   * urgency statement, the modelled gain breaks ties within it, and the unscored
   * internal-inventory card stays last by construction.
   */
  const PRIORITY_ORDER: Record<Recommendation['priority'], number> = {
    Critical: 0,
    High: 1,
    Medium: 2,
    Low: 3,
  }
  const ordered = [...recommendations].sort(
    (a, b) =>
      PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority] ||
      (b.scoreGain ?? 0) - (a.scoreGain ?? 0),
  )

  return [...ordered, tail]
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
      value:
        evidence.keyAgreement.hybridGroups.length +
        (evidence.keyAgreement.pureKemGroups?.length ?? 0) +
        evidence.keyAgreement.classicalGroups.length,
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
export function buildSophia(
  evidence: PublicScanEvidence,
  summary: ExecutiveSummary,
  findings: PublicFinding[] = [],
  recommendations: Recommendation[] = [],
): SophiaAssessment {
  const pq = computePostQuantumReadiness(evidence)
  const tlsVersion = evidence.tls?.tlsVersion?.replace('TLSv', 'TLS ') ?? 'no TLS'
  const certAlg = evidence.certificate?.publicKeyAlgorithm ?? 'an unreadable certificate'

  /**
   * Posture is keyed to the PUBLISHED GRADE, not to classicalScore.
   *
   * It used to read off `classicalScore` with its own 85/65 cut points, which
   * meant Sophia could open with "strong classical cryptographic hygiene" on a
   * report whose badge said C — two panels describing the same endpoint in
   * opposite terms. `gradeLabel` is the same rating the badge, the gauge legend
   * and the risk band already use, so this cannot drift from them.
   */
  const posture = !summary.gradeable
    ? 'an edge that did not respond to enough probes to characterise'
    : summary.gradeLabel === 'Elite' || summary.gradeLabel === 'Excellent'
      ? 'strong classical cryptographic hygiene'
      : summary.gradeLabel === 'Good'
        ? 'solid classical cryptography with a small number of hardening gaps'
        : summary.gradeLabel === 'Fair'
          ? 'workable classical cryptography with specific hardening gaps'
          : 'material weaknesses in its public cryptographic configuration'

  /* The harvest-now-decrypt-later claim is a statement about OBSERVED key
     agreement. Asserting it for an endpoint that never completed a handshake
     described cryptography the scan had not seen — so when the probe never ran,
     Sophia says what actually happened instead. */
  /* "Not measured" has two causes and they must not share a sentence: with no
     handshake nothing about the target is known, but an unsettled hybrid probe
     still observed the classical key agreement and the certificate chain. */
  const quantumClause = !evidence.tls && !pq.measured
    ? `No TLS handshake completed against this endpoint, so its key agreement, certificate chain and post-quantum posture are all unassessed. Nothing here should be read as a finding about the target's cryptography — only about its availability.`
    : !pq.measured
      ? `Key agreement observed on this run is ${resolveKeyExchange(evidence)} and the chain is anchored on ${certAlg}; whether a hybrid ML-KEM group is also accepted did not settle, so no post-quantum claim is made either way.`
      : pq.hybridObserved
        ? `Hybrid post-quantum key agreement (${evidence.keyAgreement.hybridGroups.join(', ')}) is accepted at the edge, which places this endpoint ahead of most Internet-facing infrastructure. The certificate chain, however, is still anchored on ${certAlg}.`
        : pq.pureKemObserved
          ? `Standalone ML-KEM key agreement (${(evidence.keyAgreement.pureKemGroups ?? []).join(', ')}) is accepted at the edge, so recorded sessions resist a quantum adversary — but with no classical hedge, and the chain is still anchored on ${certAlg}.`
          : `Key agreement remains ${resolveKeyExchange(evidence)} and the chain is anchored on ${certAlg}, so traffic captured today stays decryptable once a cryptographically relevant quantum computer exists.`

  const scoreClause = summary.gradeable
    ? `${
        summary.postQuantumReadiness === null
          ? 'Post-quantum readiness was not scored on this run'
          : `Post-quantum readiness measured at the edge is ${summary.postQuantumReadiness}%`
      }, against a classical transport score of ${summary.classicalScore} — a composite encryption score of ${summary.encryptionScore}/100, graded ${summary.grade}.`
    : `Only ${summary.evidenceCoverage}% of the assessed dimensions responded, so no grade is published for this target.`

  /**
   * The narrative names the actual worst findings and the actual first action.
   * Both are read from the arrays the Findings and Recommendations panels
   * render, so Sophia cannot cite a problem the report does not list, or a
   * priority the recommendations table disagrees with.
   */
  const blocking = findings.filter(
    (finding) => finding.severity === 'CRITICAL' || finding.severity === 'HIGH',
  )
  /* "Highest-value" is a claim about the modelled gains, so it is chosen BY the
     gains. Taking the first card in priority order let Sophia call a +6 card the
     single highest-value change on a page that also showed a +8 one. Ties keep
     the priority order the Recommendations panel renders. */
  const topAction =
    recommendations
      .filter((recommendation) => (recommendation.scoreGain ?? 0) > 0)
      .reduce<Recommendation | null>(
        (best, recommendation) =>
          !best || (recommendation.scoreGain ?? 0) > (best.scoreGain ?? 0) ? recommendation : best,
        null,
      )

  const findingsClause = !summary.gradeable
    ? ''
    : blocking.length
      ? ` The assessment raised ${blocking.length} finding${blocking.length === 1 ? '' : 's'} at high severity or above — ${blocking
          .slice(0, 3)
          .map((finding) => finding.control)
          .join(', ')}${blocking.length > 3 ? ` and ${blocking.length - 3} more` : ''}.`
      : ' No high or critical severity findings were raised against the observable edge.'

  const actionClause = topAction
    ? ` The highest-value change modelled here is "${topAction.title}", at +${topAction.scoreGain} points on the encryption score.`
    : ''

  const unreachable = evidence.engines?.reachability?.data?.reachable === false
  const opener = unreachable
    ? `Port ${evidence.port} did not accept a TCP connection, so no cryptographic evidence was collected.`
    : `Based on the observed ${tlsVersion} handshake, this organization demonstrates ${posture}.`

  return {
    headline: unreachable
      ? `Endpoint did not answer on port ${evidence.port}`
      : `${posture.charAt(0).toUpperCase()}${posture.slice(1)} on the public edge`,
    narrative: `${opener} ${quantumClause} ${scoreClause}${findingsClause}${actionClause}`,
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
