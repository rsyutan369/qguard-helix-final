/**
 * QGuard Web Scanner — ADAPTER onto the platform's published scoring model.
 *
 * WHAT THIS IS NOW
 * Every category ladder that used to live here has moved to
 * `src/lib/scanner/published-categories.ts`, which /public-scan also delegates
 * to. This file holds no scoring opinions whatsoever; it normalises the
 * authenticated scanner's evidence into `PublishedCategoryEvidence` and hands it
 * over.
 *
 * WHY
 * The ladders here and the ones in `grading-model.buildScoreCategories` were two
 * implementations of ONE published model, and they drifted. Fed byte-identical
 * evidence for test.openquantumsafe.org they disagreed on six of twelve
 * categories and published B · Good against B- · Fair for the same endpoint at
 * the same moment. The resolution of each disagreement is documented at the top
 * of `published-categories.ts`; what matters here is that this surface can no
 * longer form an opinion of its own.
 *
 * WHAT THIS SCANNER CAN AND CANNOT SEE
 * A category is `applicable: false` — excluded from the weighted mean with its
 * weight redistributed, never scored 0 — whenever the evidence behind it was not
 * collected for this target. That is the difference between "we looked and it is
 * absent" and "we did not look". The adapter below is responsible for reporting
 * absence of EVIDENCE honestly; the shared module decides what absence means.
 *
 * WHY `edgeIntelligence` IS NOT OPTIONAL SUGAR
 * Node's `getEphemeralKeyInfo()` is empty for TLS 1.3, so `tlsResult.keyExchange`
 * reads `"ECDHE (TLS 1.3 key_share)"` on EVERY modern endpoint. Scoring the key
 * exchange, the algorithm census and post-quantum readiness from that label
 * scored a live X25519MLKEM768 endpoint as classical — the headline, the category
 * bars and every surface card derived from them were all wrong together, and
 * consistently so, which is why it read as a design choice rather than a bug.
 * Measured evidence is passed in and takes precedence over the socket label
 * wherever the two disagree.
 */
import { SCORE_CATEGORY_DEFS, weightedCategoryScore } from '../public-scan/grading-model'
import {
  buildPublishedCategorySet,
  classifySuite,
  type PublishedCategory,
  type PublishedCategoryEvidence,
  type SuiteObservation,
} from '../published-categories'
import {
  headerTally,
  measuredKeyAgreement,
  type EdgeDnsSurface,
  type EdgeIntelligence,
} from './edge-intelligence-model'
import { reconcileTransport } from './transport-truth'
import type {
  ApiSecurityResult,
  CertificateInfo,
  DetectionRuleResult,
  GitRepoScanResult,
  TlsAnalysisResult,
  WebCryptoScanResult,
  WebScanFinding,
} from './types'

/** Re-exported under this surface's historical name. One shape, one source. */
export type PublishedScoreCategory = PublishedCategory

export interface PublishedScoringInput {
  tlsResult: TlsAnalysisResult | null
  certInfo: CertificateInfo | null
  apiResult: ApiSecurityResult | null
  repoResult: GitRepoScanResult | null
  webCryptoResult: WebCryptoScanResult | null
  ruleResults: DetectionRuleResult[]
  findings: WebScanFinding[]
  /**
   * The public-edge measurement for this target, when the edge phase ran.
   *
   * Optional in the TYPE only so historical callers keep compiling; every
   * category treats its absence as "not measured" rather than as a negative
   * result, so omitting it can never manufacture a passing score.
   */
  edgeIntelligence?: EdgeIntelligence | null
}

const PQ_SIGNATURE_PATTERN = /ml-dsa|slh-dsa|dilithium|sphincs|falcon/i

/* ─── Evidence normalisation ────────────────────────────────────────────────
   Each helper answers one question: what did this pipeline actually observe?
   None of them decides what an observation is WORTH. */

/** Symmetric strength of the negotiated AEAD, for the shared Grover margin. */
function symmetricBits(cipherSuite: string | null | undefined): number | null {
  if (!cipherSuite) return null
  if (/_256_|AES256|CHACHA20/i.test(cipherSuite)) return 256
  if (/_128_|AES128/i.test(cipherSuite)) return 128
  return null
}

function suiteObservations(tls: TlsAnalysisResult | null): SuiteObservation[] {
  return (tls?.cipherSuites ?? []).map((suite) => classifySuite(suite.name, suite.category))
}

function certificateValidityDays(cert: CertificateInfo | null): number | null {
  if (!cert?.validFrom || !cert?.validTo) return null
  const from = Date.parse(cert.validFrom)
  const to = Date.parse(cert.validTo)
  if (!Number.isFinite(from) || !Number.isFinite(to)) return null
  return Math.max(0, Math.round((to - from) / 86400000))
}

function daysRemaining(cert: CertificateInfo | null, edge: EdgeIntelligence | null): number | null {
  if (cert?.validTo) {
    const to = Date.parse(cert.validTo)
    if (Number.isFinite(to)) return Math.round((to - Date.now()) / 86400000)
  }
  return edge?.certificate?.probed ? edge.certificate.daysRemaining : null
}

/**
 * The published `dns-caa` category, exported on its own.
 *
 * It is the ONLY category behind the Asset Discovery surface, so whatever this
 * returns IS that card — and a wrong negative here renders a surface whose five
 * modules all reported cleanly as Critical 0. It delegates to the shared ladder
 * rather than restating it, so `tools/scanner-result-alignment-check.ts` pins
 * the real code path in both directions.
 */
export function dnsCaaCategory(
  dns: EdgeDnsSurface | null,
): { score: number; observed: string } | null {
  const row = buildPublishedCategorySet(
    toCategoryEvidence({
      tlsResult: null,
      certInfo: null,
      apiResult: null,
      repoResult: null,
      webCryptoResult: null,
      ruleResults: [],
      findings: [],
      edgeIntelligence: dns ? ({ dns } as unknown as EdgeIntelligence) : null,
    }),
  ).find((category) => category.key === 'dns-caa')
  if (!row || !row.applicable) return null
  return { score: row.score, observed: row.observed }
}

/**
 * Flatten authenticated scan evidence into the shared category input.
 *
 * Every field here is a MEASUREMENT or an explicit "not measured" — no defaults
 * that read as negatives, no socket labels standing in for probe results.
 */
function toCategoryEvidence(input: PublishedScoringInput): PublishedCategoryEvidence {
  const { tlsResult, certInfo, apiResult } = input
  const edge = input.edgeIntelligence ?? null
  const kem = measuredKeyAgreement(edge)
  /* EVERY sub-surface is guarded, not just `edge` itself.
     An `edgeIntelligence` record missing one of its six sub-objects used to take
     the whole page down with "Cannot read properties of undefined" — and this
     module is also reached with a deliberately partial bundle by
     `dnsCaaCategory`, which has a CAA surface and nothing else. A missing
     sub-surface is "not measured", which every category below already knows how
     to render. */
  const edgeCert = edge?.certificate
  const truth = reconcileTransport(tlsResult, edge, kem)

  /* The edge engine probes every version individually; the socket only ever
     knows the one it negotiated. Where both have an answer the probed list is
     the stronger evidence and wins — and where NEITHER enumerated, the list
     stays null so the shared ladder excludes the category rather than scoring
     one negotiated version as though it ruled the others out. */
  const probedProtocols = edge?.transport?.supportedProtocols ?? []
  const socketProtocols = tlsResult?.supportedProtocols ?? []
  const acceptedProtocols = probedProtocols.length
    ? probedProtocols
    : socketProtocols.length
      ? socketProtocols
      : null

  const tally = headerTally(edge?.http, apiResult?.securityHeaders)

  /* HSTS: the edge model parses the directive set; the authenticated header
     list only knows present/secure. Prefer the parsed reading and fall back to
     a presence-only one, which the shared ladder scores conservatively. */
  const edgeHsts = edge?.http?.probed ? edge.http.hsts : null
  const apiHsts = apiResult?.securityHeaders?.find(
    (header) => header.name.toLowerCase() === 'strict-transport-security',
  )
  const hstsObserved = Boolean(edgeHsts) || Boolean(apiResult?.securityHeaders?.length)
  const hstsRaw = edgeHsts?.raw ?? apiHsts?.value ?? null
  const parsedMaxAge = hstsRaw ? Number(/max-age=(\d+)/i.exec(hstsRaw)?.[1] ?? NaN) : NaN

  return {
    transport: {
      handshakeCompleted: Boolean(tlsResult) || truth.handshakeCompleted,
      acceptedProtocols,
      negotiatedProtocol: edge?.transport?.negotiatedProtocol ?? tlsResult?.tlsVersion ?? null,
      negotiatedSuite: tlsResult?.cipherSuite || edge?.transport?.negotiatedCipher || null,
      enumeratedSuites: suiteObservations(tlsResult),
      staticRsaAccepted: truth.staticRsaAccepted.measured ? truth.staticRsaAccepted.value : null,
      symmetricBits: symmetricBits(tlsResult?.cipherSuite ?? edge?.transport?.negotiatedCipher),
      forwardSecrecy: {
        measured: truth.forwardSecrecy.measured,
        value: truth.forwardSecrecy.value,
      },
    },
    certificate: certInfo
      ? {
          publicKeyAlgorithm: certInfo.publicKeyAlgorithm,
          publicKeySize: certInfo.publicKeySize || null,
          signatureAlgorithm: certInfo.signatureAlgorithm,
          isExpired: Boolean(certInfo.isExpired),
          isSelfSigned: Boolean(certInfo.isSelfSigned),
          chainTrusted: edgeCert?.probed ? edgeCert.chainTrusted : null,
          chainHasExpiredEntry: (certInfo.chain ?? []).some((entry) => entry.isExpired),
          validityDays: certificateValidityDays(certInfo) ?? edgeCert?.validityDays ?? null,
          daysRemaining: daysRemaining(certInfo, edge),
        }
      : null,
    keyAgreement: {
      probed: kem.probed,
      hybridSettled: kem.hybridSettled,
      hybrid: kem.hybrid,
      pureKem: kem.pureKem,
      group: kem.group,
      classicalComponent: kem.classicalComponent,
      postQuantumComponent: kem.postQuantumComponent,
      handshakes: kem.handshakes || null,
      classicalObserved: Boolean(edge?.pqKeyAgreement?.probed && edge.pqKeyAgreement.classicalGroups?.length),
      socketLabel: tlsResult?.keyExchange || edge?.transport?.keyExchange || null,
      negotiatedCurve: tlsResult?.negotiatedCurve ?? null,
    },
    revocation: edgeCert?.probed
      ? {
          probed: true,
          advertisesResponder: Boolean(edgeCert.ocspUri),
          stapled: edgeCert.ocspStapled,
          mustStaple: edgeCert.mustStaple,
          responderDead: edgeCert.ocspResponderState === 'unreachable',
        }
      : null,
    transparency: edgeCert?.probed ? { probed: true, sctCount: edgeCert.sctCount } : null,
    caa: edge?.dns?.probed
      ? {
          probed: true,
          queryable: edge.dns.caaQueryable,
          climbComplete: edge.dns.caaClimbComplete,
          present: edge.dns.caaPresent,
          recordCount: edge.dns.caaRecords.length,
          atName: edge.dns.caaAtName,
        }
      : null,
    headers: { hardened: tally.hardened, applicable: tally.applicable },
    hsts: hstsObserved
      ? {
          observed: true,
          present: edgeHsts ? edgeHsts.present : Boolean(apiHsts?.present),
          maxAgeSeconds: edgeHsts?.maxAge ?? (Number.isFinite(parsedMaxAge) ? parsedMaxAge : null),
          includeSubDomains:
            edgeHsts?.includeSubDomains ?? /includeSubDomains/i.test(hstsRaw ?? ''),
          preload: edgeHsts?.preload ?? /preload/i.test(hstsRaw ?? ''),
        }
      : null,
    algorithmSources: {
      tls: tlsResult,
      certificate: certInfo,
      patterns: [...(input.repoResult?.patterns ?? []), ...(input.webCryptoResult?.patterns ?? [])],
    },
    pqSignatureObserved:
      edge?.quantum?.pqSignatureObserved === true ||
      PQ_SIGNATURE_PATTERN.test(
        `${certInfo?.signatureAlgorithm ?? ''} ${certInfo?.publicKeyAlgorithm ?? ''} ${
          tlsResult?.signatureAlgorithm ?? ''
        }`,
      ),
  }
}

/**
 * Build all twelve published categories from authenticated scan evidence.
 *
 * A pure delegation — the ladders live in `published-categories.ts` and are the
 * same ones /public-scan walks.
 */
export function buildPublishedCategories(input: PublishedScoringInput): PublishedScoreCategory[] {
  return buildPublishedCategorySet(toCategoryEvidence(input))
}

/**
 * The composite posture (0-100, higher is better) over the published model.
 * Exposure — what the rest of the scanner persists as `riskScore` — is
 * `100 - this`.
 */
export function publishedPostureScore(categories: PublishedScoreCategory[]): number {
  return weightedCategoryScore(categories)
}

/** Re-exported so existing importers of the weight table keep one source. */
export { SCORE_CATEGORY_DEFS }
