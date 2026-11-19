/**
 * QGuard Web Scanner — Public Edge Intelligence
 *
 * WHY THIS EXISTS
 * ---------------
 * The Dashboard Scanner's Observed Attack Surface reported eight controls as
 * "Not probed" — OCSP stapling, Certificate Transparency, CAA, DNSSEC, ALPN and
 * edge attribution — and two more as "Not observed" (HSTS, HTTP security
 * headers). None of that was a display bug. Two real gaps produced it:
 *
 *  1. The authenticated orchestrator genuinely did not perform those probes. It
 *     ran `analyzeTls` (protocols + cipher suites) and nothing else at the edge,
 *     while /public-scan has had a complete DNS / certificate-extension / HTTP
 *     engine set for exactly these controls the whole time.
 *  2. `api-security-scanner` reads headers with Node's `fetch()`, which REFUSES
 *     to connect over an expired, self-signed or otherwise untrusted chain. On
 *     precisely the targets whose headers an assessment most needs to read
 *     (expired.badssl.com being the canonical case) every probe returned null,
 *     so the header rows rendered "Not observed" for a reason that had nothing
 *     to do with the target's headers.
 *
 * Post-quantum key agreement had a third, worse defect: it was INFERRED from
 * substrings ("does the negotiated suite name contain ml-kem?"). Node does not
 * expose the negotiated TLS 1.3 group, and TLS 1.3 suite names carry no
 * key-exchange token at all, so that test could never return true from a real
 * handshake — and when a finding title happened to mention ML-KEM it returned
 * true for endpoints that had no post-quantum support whatsoever.
 *
 * THE FIX IS REUSE, NOT REIMPLEMENTATION
 * --------------------------------------
 * This module runs the SAME public-scan engine bundle /public-scan runs, over
 * the same code path, and flattens it into a bounded, JSON-safe snapshot that
 * persists with the scan result. Two consequences that matter:
 *
 *   • A host assessed on /public-scan and on /dashboard/scanner is measured by
 *     one engine, so the two surfaces cannot disagree about it.
 *   • Post-quantum support becomes a MEASUREMENT — each hybrid group offered in
 *     isolation under a TLS 1.3 floor and re-sampled for agreement — instead of
 *     a guess, which is what lets the panel say "Applied" rather than the
 *     evasive "Observed" it used to print.
 *
 * Nothing here invents a value. Every field is either an engine observation or
 * an explicit "not measured, and here is why".
 *
 * The evidence SHAPE and the pure derivations over it live in
 * `edge-intelligence-model.ts`, which the dashboard imports directly. This file
 * is the Node-only collector: it opens sockets, so nothing in the browser may
 * import it.
 */

import {
  runScanEngines,
  type ScanEvidenceBundle,
  type OrchestratorOptions,
} from '../public-scan/engines'
import {
  describeKeyExchange,
  GROUP_LABELS,
  HYBRID_GROUP_COMPONENTS,
  HYBRID_GROUP_KEM,
} from '../public-scan/engines/tls-engine'
import type { ObservationSink } from '../public-scan/engines/contract'
import type { TlsAnalysisResult } from './types'
import {
  classifyQuantumVulnerability,
  type EdgeIntelligence,
  type EdgePostQuantumKeyAgreement,
} from './edge-intelligence-model'

/* Re-exported so existing consumers keep one import path for the whole
   subsystem, while the model stays independently importable from the client. */
export * from './edge-intelligence-model'

/* ────────────────────────────────────────────────────────── bounded output ── */

/**
 * Caps on every list that leaves this module.
 *
 * The snapshot is persisted per target in the scan session's JSONB metadata and
 * re-read by the dashboard on every history load. Unbounded arrays (a busy apex
 * can publish 30+ TXT records, a large certificate 100+ SANs) would grow the row
 * without adding a single decision-relevant fact. Headline COUNTS are always
 * exact; only the displayed detail is capped, and the count says so.
 */
const MAX_SANS = 12
const MAX_CAA = 8
const MAX_ADDRESSES = 6
const MAX_SIGNALS = 8
const MAX_CRL = 4
const MAX_NOTES = 12
const MAX_REASONS = 8

const cap = <T>(values: readonly T[], limit: number): T[] => values.slice(0, limit)

/* ───────────────────────────────────────────────── post-quantum verdict ───── */

/**
 * The post-quantum key-agreement verdict.
 *
 * The old row printed "Observed" whenever anything anywhere mentioned ML-KEM —
 * a hedge that told the operator nothing and, worse, was reachable from a
 * finding TITLE rather than a handshake. The vocabulary here is decisive
 * because the measurement behind it is:
 *
 *   Applied        a hybrid group was accepted, proven by offering it alone
 *                  under a TLS 1.3 floor and re-sampling for agreement.
 *   PQ-only        standalone ML-KEM accepted, no classical hedge. Deliberately
 *                  NOT called hybrid: if ML-KEM is ever broken there is nothing
 *                  underneath it, so it is a different posture, not a better one.
 *   Not offered    probed and refused. A real negative result.
 *   Not available  the endpoint does not negotiate TLS 1.3, where these groups
 *                  are defined. Answered from evidence in hand, not by guessing.
 *   Unknown        no handshake completed, so nothing is claimed either way.
 */
function buildPqKeyAgreement(bundle: ScanEvidenceBundle): EdgePostQuantumKeyAgreement {
  const tls = bundle.tls.data
  const handshake = tls.handshake
  const hybrid = tls.hybridGroups
  const pureKem = tls.pureKemGroups
  const supportsTls13 =
    tls.supportedProtocols.includes('TLSv1.3') || tls.negotiatedProtocol === 'TLSv1.3'

  const primary = hybrid[0] ?? pureKem[0] ?? null
  const components = primary ? HYBRID_GROUP_COMPONENTS[primary] ?? null : null
  const kemSets = Array.from(
    new Set([...hybrid, ...pureKem].map((group) => HYBRID_GROUP_KEM[group] ?? groupKemLabel(group)).filter(Boolean)),
  )

  const base = {
    hybridGroups: hybrid,
    pureKemGroups: pureKem,
    classicalGroups: tls.classicalGroups,
    primaryGroup: primary,
    kemParameterSets: kemSets,
    classicalComponent: components?.classical ?? null,
    postQuantumComponent: components?.postQuantum ?? kemSets[0] ?? null,
    probed: tls.groupsProbed,
    hybridProbed: tls.hybridProbed,
    hybridGroupsSettled: tls.hybridGroupsSettled,
    hybridGroupsInconclusive: tls.hybridGroupsInconclusive,
    handshakes: tls.groupHandshakes,
    inconclusiveGroups: tls.inconclusiveGroups,
    unstableGroups: tls.unstableGroups,
    untestableGroups: tls.untestableGroups,
    confidence: bundle.tls.confidence,
  }

  /* Evidence is assembled once and shown on every branch — including the
     negative ones. "Not offered" is a claim about the endpoint and has to carry
     the same provenance as "Applied", or the operator cannot tell a measured
     refusal from a probe that never ran. */
  const evidence: Array<{ label: string; value: string }> = []
  if (handshake || tls.groupsProbed) {
    evidence.push({
      label: 'Negotiated TLS version',
      value: tls.negotiatedProtocol ?? 'no handshake completed',
    })
    evidence.push({
      label: 'Accepted protocols',
      value: tls.supportedProtocols.join(', ') || 'none',
    })
  }
  if (primary) {
    evidence.push({ label: 'Negotiated key-exchange group', value: GROUP_LABELS[primary] ?? primary })
    if (components) {
      evidence.push({ label: 'Hybrid construction', value: `${primary} (RFC 8446 key_share)` })
      evidence.push({ label: 'Classical component', value: components.classical })
      evidence.push({ label: 'Post-quantum component', value: components.postQuantum })
    } else {
      evidence.push({ label: 'Post-quantum component', value: kemSets.join(', ') || primary })
    }
  } else if (tls.classicalGroups.length) {
    evidence.push({
      label: 'Accepted classical groups',
      value: tls.classicalGroups.map((group) => GROUP_LABELS[group] ?? group).join(', '),
    })
  }
  if (tls.groupsProbed) {
    evidence.push({
      label: 'Groups probed',
      value: `${base.handshakes} handshake(s), each group offered in isolation and re-sampled`,
    })
  }
  if (tls.unstableGroups.length) {
    evidence.push({
      label: 'Unstable measurements',
      value: `${tls.unstableGroups.join(', ')} — endpoint answered inconsistently; majority of three taken`,
    })
  }
  if (tls.inconclusiveGroups.length) {
    evidence.push({
      label: 'Inconclusive',
      value: `${tls.inconclusiveGroups.join(', ')} — no claim made either way`,
    })
  }
  evidence.push({ label: 'Detection confidence', value: `${bundle.tls.confidence}%` })

  if (!handshake && !tls.groupsProbed) {
    return {
      ...base,
      value: 'Unknown',
      state: 'unknown',
      /* Scoped to THIS engine's probe.
         The old wording said "No TLS handshake completed", which appeared on the
         dashboard directly beneath a negotiated TLS 1.3 suite, a 5-certificate
         chain and an 85-day validity — all measured by the socket analyser,
         which had completed a handshake perfectly well. What actually failed is
         the named-group probe, which needs one handshake PER GROUP and is the
         first thing to time out. Saying so is both accurate and more useful. */
      detail:
        tls.error
          ? `Named key-agreement groups could not be probed (${tls.error}), so post-quantum key agreement was not measured. Group probing opens one handshake per group and is separate from the main TLS observation. This is "not measured", not "not supported".`
          : 'Named key-agreement groups were not probed, so post-quantum key agreement was not measured. This is "not measured", not "not supported".',
      evidence,
    }
  }

  if (hybrid.length) {
    const label = GROUP_LABELS[hybrid[0]] ?? hybrid[0]
    return {
      ...base,
      value: 'Applied',
      state: 'pass',
      detail:
        `Hybrid post-quantum key agreement is live on this endpoint: ${label} was accepted when offered in isolation under a TLS 1.3 floor` +
        `${base.handshakes ? `, confirmed across ${base.handshakes} handshake(s)` : ''}. ` +
        `${components ? `${components.classical} protects the session classically and ${components.postQuantum} defeats harvest-now-decrypt-later.` : ''}`,
      evidence,
    }
  }

  if (pureKem.length) {
    return {
      ...base,
      value: 'PQ-only',
      state: 'partial',
      detail:
        `Standalone ML-KEM accepted (${pureKem.join(', ')}) with no classical hedge. Post-quantum key agreement IS in use, but a break in ML-KEM would leave nothing underneath it — reported separately from hybrid deployment rather than counted as it.`,
      evidence,
    }
  }

  if (!supportsTls13) {
    return {
      ...base,
      value: 'Not available',
      state: 'fail',
      detail:
        'Hybrid ML-KEM groups exist only in the TLS 1.3 key_share extension, and this endpoint does not negotiate TLS 1.3. They are therefore unsupported here — answered from the protocol probe, not left untested. Enabling TLS 1.3 is the prerequisite for any post-quantum key agreement.',
      evidence,
    }
  }

  /* ── The negative branch, gated on evidence ───────────────────────────────
     "Not offered" is a claim about the ENDPOINT, and it is the claim every
     post-quantum number on the page is built on: the key-exchange category
     drops 100 -> 70, the readiness model forfeits its 55-point hybrid
     allowance, the quantum verdict flips to Vulnerable and the migration
     engine starts recommending a primitive the endpoint may already run.

     An empty `hybridGroups` does not establish it. A group that was budget-
     skipped, throttled into a reset, ignored by the server or unsupported by
     the scanner's own OpenSSL build lands in `inconclusiveGroups`, and reading
     that as a refusal is how an endpoint measured at X25519MLKEM768 came to be
     published as "offered in isolation and refused". A refusal has to be
     measured before it can be reported. */
  const settled = tls.hybridGroupsSettled ?? []
  const unsettled = tls.hybridGroupsInconclusive ?? []
  if (settled.length === 0) {
    return {
      ...base,
      value: 'Not measured',
      state: 'unknown',
      detail:
        `No hybrid ML-KEM group reached a conclusive verdict on this run${
          unsettled.length ? ` — ${unsettled.join(', ')} ${unsettled.length === 1 ? 'was' : 'were'} offered but never settled` : ''
        }. Group probing opens one handshake per group and is the first thing an endpoint throttles, so this is "not measured", not "not supported". Re-run the scan to settle it; nothing is claimed about post-quantum key agreement either way.`,
      evidence,
    }
  }

  return {
    ...base,
    value: 'Not offered',
    state: 'fail',
    detail:
      `${settled.length === 1 ? 'The' : 'Every'} hybrid ML-KEM group that settled (${settled.join(', ')}) was offered in isolation under a TLS 1.3 floor and refused${base.handshakes ? ` across ${base.handshakes} handshake(s)` : ''}. Session secrets rest on classical key agreement alone and are recoverable by a future CRQC from traffic recorded today.` +
      (unsettled.length
        ? ` ${unsettled.join(', ')} never settled and ${unsettled.length === 1 ? 'is' : 'are'} excluded from this verdict.`
        : ''),
    evidence,
  }
}

/** ML-KEM parameter set for a standalone group name (`MLKEM768` → ML-KEM-768). */
function groupKemLabel(group: string): string {
  const match = group.match(/MLKEM(\d+)/i)
  return match ? `ML-KEM-${match[1]}` : ''
}


/* ─────────────────────────────────────────────────────────────── collection ─ */

/** What `collectEdgeIntelligence` returns alongside the snapshot. */
export interface EdgeIntelligenceResult {
  intelligence: EdgeIntelligence
  /**
   * The primary handshake, so the orchestrator can consume it as its own TLS
   * evidence rather than re-running `analyzeTls` and doubling the socket count
   * against the target. One handshake set, one answer.
   */
  handshake: TlsAnalysisResult | null
  bundle: ScanEvidenceBundle
}

/**
 * Probe the public edge and flatten the evidence bundle.
 *
 * Runs the identical engine set /public-scan runs — DNS (over UDP/53 with a
 * DNS-over-HTTPS fallback so CAA and DNSSEC answer on networks that block port
 * 53), HTTP over a permissive agent (so headers are readable on untrusted
 * chains), the TLS engine including per-group post-quantum probing, the
 * certificate engine including OCSP and SCT extraction, and the cryptographic
 * intelligence engine.
 */
export async function collectEdgeIntelligence(
  host: string,
  port: number,
  onObservation?: ObservationSink,
  /**
   * Wall-clock budget for this target's edge probing. A multi-target run
   * divides its own budget across the queue and passes each target its share,
   * so twenty-five assets cannot compound into a scan nobody waits for.
   */
  budgetMs?: number,
  evidence?: Pick<OrchestratorOptions, 'onHttpEvidence' | 'onCertificateEvidence'>,
): Promise<EdgeIntelligenceResult> {
  const startedAt = Date.now()
  const bundle = await runScanEngines({ host, port, onObservation, budgetMs, ...evidence })

  const tls = bundle.tls.data
  const cert = bundle.certificate.data
  const dns = bundle.dns.data
  const http = bundle.http.data
  const crypto = bundle.crypto.data

  /* Evidence is evidence wherever it came from.
     ------------------------------------------------------------------------
     This used to be `Boolean(tls.handshake)` — the EDGE prober's own handshake
     — so a timed-out group probe produced verdict "Unknown" while the same
     response still carried quantum risk factors and migration targets derived
     from a certificate chain that HAD been parsed. The page then showed
     "Quantum Vulnerability: Unknown" directly beside "Certificate public key
     ECDSA P-256 — HIGH" and an ML-DSA-65 migration target at 80% confidence.
     Either the exposure is unknown or it is high; it cannot be both.

     A parsed certificate is quantum-relevant evidence in its own right: the
     leaf's public key and signature are exactly what a CRQC breaks. So the
     verdict is licensed by either source. */
  const hasCertificateEvidence = crypto.riskFactors.length > 0 || cert.chainDepth > 0
  const hasTransportEvidence = Boolean(tls.handshake) || hasCertificateEvidence
  const supportsTls13 =
    tls.supportedProtocols.includes('TLSv1.3') || tls.negotiatedProtocol === 'TLSv1.3'

  const verdict = classifyQuantumVulnerability({
    hasTransportEvidence,
    hybridObserved: crypto.hybridObserved,
    pqSignatureObserved: crypto.pqSignatureObserved,
    quantumRisk: crypto.quantumRisk,
    hybridProbed: tls.hybridProbed,
    /* Settled, not merely attempted. `hybridProbed` is `supportsTls13` and
       says nothing about whether the groups answered. */
    hybridMeasured: (tls.hybridGroupsSettled ?? []).length > 0,
    supportsTls13,
    /* Critical factors OTHER than the key exchange. When hybrid is deployed the
       key-exchange factor is already Low, so anything still rated Critical here
       is a downgrade path the hybrid group does not cover — exactly the caveat
       a reassuring headline would otherwise bury. */
    residualCriticalFactors: crypto.riskFactors
      .filter((factor) => factor.impact === 'Critical' && factor.factor !== 'Key exchange')
      .map((factor) => factor.factor.toLowerCase()),
  })

  // HSTS is scored on its own control, so the transport-header tally excludes
  // it — the same denominator `http-security` in controls.ts uses, which is why
  // this surface and /public-scan can never print different ratios for one host.
  const transportHeaders = http.headers.filter(
    (header) => header.name !== 'strict-transport-security' && header.status !== 'Not Applicable',
  )

  const intelligence: EdgeIntelligence = {
    host,
    port,
    probedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    confidence: bundle.confidence,
    notes: cap(bundle.notes, MAX_NOTES),
    pqKeyAgreement: buildPqKeyAgreement(bundle),
    transport: {
      negotiatedProtocol: tls.negotiatedProtocol,
      supportedProtocols: tls.supportedProtocols,
      legacyProtocols: tls.legacyProtocols,
      negotiatedCipher: tls.negotiatedCipher,
      keyExchange: describeKeyExchange(tls),
      forwardSecrecy: tls.forwardSecrecy,
      forwardSecrecyBasis: tls.forwardSecrecyBasis,
      staticRsaAccepted: tls.staticRsaAccepted,
      alpn: tls.alpn,
      alpnOffered: tls.alpnOffered,
      http2: tls.http2,
      // ALPN is only unknown when no handshake happened at all. A completed
      // handshake that returns no protocol means the server declined our offer,
      // which is a measured absence and must not read as "not probed".
      alpnProbed: hasTransportEvidence,
      sessionTickets: tls.sessionTickets,
      sessionReuse: tls.sessionReuse,
      handshakeMs: tls.timing.tlsHandshakeMs,
      error: tls.error,
    },
    certificate: {
      probed: Boolean(cert.certificate) || bundle.certificate.ok,
      fingerprintSha256: cert.certificate?.fingerprint ?? null,
      ocspStapled: cert.ocspStapled,
      ocspResponderState: cert.ocspResponderState,
      ocspResponderDetail: cert.ocspResponderDetail,
      ocspUri: cert.ocspUri,
      mustStaple: cert.mustStaple,
      crlDistributionPoints: cap(cert.crlDistributionPoints, MAX_CRL),
      sctPresent: cert.signedCertificateTimestamps,
      sctCount: cert.sctCount,
      subjectAltNames: cap(cert.subjectAltNames, MAX_SANS),
      sanCount: cert.sanCount,
      isWildcard: cert.isWildcard,
      chainDepth: cert.chainDepth,
      chainTrusted: cert.chainTrusted,
      trustError: cert.trustError,
      hostnameMatches: cert.hostnameMatches,
      daysRemaining: cert.daysRemaining,
      validityDays: cert.validityDays,
      error: cert.error,
    },
    dns: {
      probed: bundle.dns.ok || dns.addressCount > 0 || dns.caaQueryable || dns.dnssecQueryable,
      addresses: cap(dns.addresses, MAX_ADDRESSES),
      addressCount: dns.addressCount,
      caaQueryable: dns.caaQueryable,
      caaPresent: dns.caaPresent,
      caaRecords: cap(dns.caaRecords.map((record) => record.raw), MAX_CAA),
      caaSource: dns.caaSource,
      caaAtName: dns.caaAtName,
      caaClimbComplete: dns.caaClimbComplete,
      dnssecQueryable: dns.dnssecQueryable,
      dnssecSigned: dns.dnssecSigned,
      dnssecValidated: dns.dnssecValidated,
      spf: dns.spf,
      dmarc: dns.dmarc,
      transports: dns.transports,
      resolvedVia: dns.resolvedVia,
      error: dns.error,
    },
    http: {
      probed: true,
      reachable: http.reachable,
      finalUrl: http.finalUrl,
      statusCode: http.statusCode,
      httpVersion: http.httpVersion,
      hsts: {
        present: http.hsts.present,
        status: http.hsts.status,
        raw: http.hsts.raw,
        maxAge: http.hsts.maxAge,
        includeSubDomains: http.hsts.includeSubDomains,
        preload: http.hsts.preload,
        preloadEligible: http.hsts.preloadEligible,
        preloadBlockers: http.hsts.preloadBlockers,
      },
      headers: http.headers.map((header) => ({
        name: header.name,
        group: header.group,
        present: header.present,
        value: header.value,
        status: header.status,
        weakness: header.weakness,
        supersededBy: header.supersededBy ?? null,
      })),
      hardenedCount: transportHeaders.filter((header) => header.status === 'Healthy').length,
      applicableCount: transportHeaders.length,
      fingerprint: {
        server: http.fingerprint.server,
        poweredBy: http.fingerprint.poweredBy,
        cdn: http.fingerprint.cdn,
        waf: http.fingerprint.waf,
        cloudProvider: http.fingerprint.cloudProvider,
        reverseProxy: http.fingerprint.reverseProxy,
        signals: cap(http.fingerprint.signals, MAX_SIGNALS),
      },
      error: http.error,
    },
    quantum: {
      hybridObserved: crypto.hybridObserved,
      pqSignatureObserved: crypto.pqSignatureObserved,
      keyExchange: crypto.keyExchange,
      keyExchangeClass: crypto.keyExchangeClass,
      forwardSecrecy: crypto.forwardSecrecy,
      kemParameterSets: crypto.kemParameterSets,
      postQuantumReadiness: crypto.postQuantumReadiness,
      readinessReasons: cap(crypto.readinessReasons, MAX_REASONS),
      quantumRisk: crypto.quantumRisk,
      quantumRiskScore: crypto.quantumRiskScore,
      riskFactors: crypto.riskFactors.map((factor) => ({
        factor: factor.factor,
        observed: factor.observed,
        impact: factor.impact,
        explanation: factor.explanation,
      })),
      vulnerability: verdict.vulnerability,
      vulnerabilityReason: verdict.reason,
      migrationTargets: crypto.migrationTargets,
    },
  }

  return { intelligence, handshake: tls.handshake, bundle }
}

