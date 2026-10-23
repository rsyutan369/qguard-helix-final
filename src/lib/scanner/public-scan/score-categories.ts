/**
 * /public-scan — ADAPTER onto the platform's published scoring model.
 *
 * WHAT THIS IS
 * `buildScoreCategories` used to live in `grading-model.ts` and carry its own
 * twelve ladders. Those ladders have moved to
 * `src/lib/scanner/published-categories.ts`, which /dashboard/scanner also
 * delegates to. This file holds no scoring opinions; it flattens public-edge
 * evidence into `PublishedCategoryEvidence` and hands it over.
 *
 * WHY IT MOVED OUT OF grading-model.ts
 * `grading-model.ts` is the published STANDARD — the weight table, the grade
 * table, the post-quantum model — and `published-categories.ts` imports it. An
 * adapter that imports both therefore cannot live inside either, or the module
 * graph closes a cycle. Keeping the standard free of adapters is also the point:
 * the standard is what both surfaces agree on, and an adapter is where one
 * surface's evidence happens to be shaped.
 *
 * WHY IT MATTERS
 * Fed byte-identical evidence for test.openquantumsafe.org, the old
 * `buildScoreCategories` and the dashboard's `buildPublishedCategories`
 * disagreed on six of twelve categories and published B · Good against
 * B- · Fair for the same endpoint at the same moment. Each disagreement is
 * resolved, on the merits, at the top of `published-categories.ts`.
 *
 * ONE MORE CONTRACT WORTH KNOWING
 * The granular `ControlState.score` values still exist and still drive the
 * controls panel's status vocabulary, but they no longer feed the categories.
 * Where a control's STATUS and the shared ladder could disagree — OCSP stapling
 * is the live example — the control already says "Not applicable", which is the
 * same verdict the ladder reaches. If you add a control, check both.
 */
import {
  buildPublishedCategorySet,
  classifySuite,
  type PublishedCategoryEvidence,
  type SuiteObservation,
} from '../published-categories'
import { resolveKeyExchange } from './controls'
import type { ControlState, PublicScanEvidence, ScoreComponent } from './types'

const PQ_SIGNATURE_PATTERN = /ml[-_]?dsa|slh[-_]?dsa|dilithium|sphincs|falcon/i

/** Symmetric strength of the negotiated AEAD, for the shared Grover margin. */
function symmetricBits(cipherSuite: string | null | undefined): number | null {
  if (!cipherSuite) return null
  if (/_256_|AES256|CHACHA20/i.test(cipherSuite)) return 256
  if (/_128_|AES128/i.test(cipherSuite)) return 128
  return null
}

function suiteObservations(evidence: PublicScanEvidence): SuiteObservation[] {
  return (evidence.cipherSuites ?? []).map((suite) => classifySuite(suite.name, suite.category))
}

/**
 * Flatten public-edge evidence into the shared category input.
 *
 * Every field is a MEASUREMENT or an explicit "not measured". The one place
 * that needed care is `forwardSecrecy`: `KeyAgreementEvidence.forwardSecrecy` is
 * a plain boolean, so it reads `false` both when ephemeral key agreement was
 * ruled out and when nothing was probed. TLS 1.3 settles it by construction
 * (RFC 8446 removed every static key exchange), and below 1.3 it is only a
 * measurement once a handshake completed.
 */
export function toPublishedCategoryEvidence(
  evidence: PublicScanEvidence,
): PublishedCategoryEvidence {
  const tls = evidence.tls
  const cert = evidence.certificate
  const extras = evidence.certificateExtras
  const ka = evidence.keyAgreement
  const http = evidence.http
  const hstsDetail = evidence.engines?.http?.data?.hsts ?? null

  const protocols = tls?.supportedProtocols ?? []
  const handshakeCompleted = tls !== null
  const tls13 = protocols.includes('TLSv1.3') || tls?.tlsVersion === 'TLSv1.3'

  /* HSTS is scored on its own category, and headers whose protection is
     delivered by another header (X-Frame-Options superseded by CSP
     frame-ancestors) are dropped from BOTH sides of the ratio — counting them
     would fail a site for omitting a header browsers ignore. */
  const scorable = (http.headers ?? []).filter(
    (header) => header.name !== 'strict-transport-security' && header.applicable !== false,
  )
  const hardened = scorable.filter((header) => header.secure).length

  return {
    transport: {
      handshakeCompleted,
      acceptedProtocols: protocols.length ? protocols : null,
      negotiatedProtocol: tls?.tlsVersion ?? null,
      negotiatedSuite: tls?.cipherSuite ?? null,
      enumeratedSuites: suiteObservations(evidence),
      staticRsaAccepted: handshakeCompleted
        ? (evidence.cipherSuites ?? []).some((suite) => suite.category === 'rsa-kex')
        : null,
      symmetricBits: symmetricBits(tls?.cipherSuite),
      forwardSecrecy: {
        /* TLS 1.3 is forward secret BY CONSTRUCTION — a protocol fact, not a
           probe result. Below 1.3 the flag is a measurement only once a
           handshake completed; with no handshake it is an absent answer, and
           publishing `false` from one would be the strongest possible negative
           drawn from zero evidence. */
        measured: handshakeCompleted,
        value: handshakeCompleted ? tls13 || ka.forwardSecrecy : null,
      },
    },
    certificate: cert
      ? {
          publicKeyAlgorithm: cert.publicKeyAlgorithm,
          publicKeySize: cert.publicKeySize || null,
          signatureAlgorithm: cert.signatureAlgorithm,
          isExpired: Boolean(cert.isExpired),
          isSelfSigned: Boolean(cert.isSelfSigned),
          chainTrusted: extras ? extras.chainTrusted : null,
          chainHasExpiredEntry: (cert.chain ?? []).some((entry) => entry.isExpired),
          validityDays: extras?.validityDays ?? null,
          daysRemaining: extras?.daysRemaining ?? null,
        }
      : null,
    keyAgreement: {
      probed: ka.probed,
      hybridSettled: ka.hybridSettled,
      hybrid: ka.hybridGroups.length > 0,
      pureKem: ka.hybridGroups.length === 0 && ka.pureKemGroups.length > 0,
      group: ka.primaryGroup,
      classicalComponent: null,
      postQuantumComponent: null,
      handshakes: null,
      classicalObserved: ka.classicalGroups.length > 0,
      socketLabel: handshakeCompleted ? resolveKeyExchange(evidence) : null,
      negotiatedCurve: tls?.negotiatedCurve ?? null,
    },
    revocation: extras
      ? {
          probed: true,
          advertisesResponder: Boolean(extras.ocspUri),
          stapled: extras.ocspStapled,
          mustStaple: extras.mustStaple,
          responderDead: extras.ocspResponderState === 'unreachable',
        }
      : null,
    transparency: extras ? { probed: true, sctCount: extras.sctCount } : null,
    caa: evidence.dns.resolverAvailable
      ? {
          probed: true,
          queryable: evidence.dns.caaQueryable,
          climbComplete: evidence.dns.caaClimbComplete,
          present: evidence.dns.caaPresent,
          recordCount: evidence.dns.caaRecords.length,
          atName: null,
        }
      : null,
    headers: http.reachable
      ? { hardened, applicable: scorable.length }
      : { hardened: null, applicable: null },
    hsts: http.reachable
      ? {
          observed: true,
          present: Boolean(hstsDetail?.present),
          maxAgeSeconds: hstsDetail?.maxAge ?? null,
          includeSubDomains: Boolean(hstsDetail?.includeSubDomains),
          preload: Boolean(hstsDetail?.preload),
        }
      : null,
    algorithmSources: { tls, certificate: cert, patterns: [] },
    pqSignatureObserved: PQ_SIGNATURE_PATTERN.test(
      `${cert?.signatureAlgorithm ?? ''} ${cert?.publicKeyAlgorithm ?? ''} ${
        tls?.signatureAlgorithm ?? ''
      }`,
    ),
  }
}

/**
 * The published 12-category weighted model, computed from live public-edge
 * evidence.
 *
 * `controls` and `postQuantumReadinessScore` are no longer read — post-quantum
 * readiness is derived inside the shared model from the same signals the
 * dashboard feeds it, which is what closed the last 3-point gap between the two
 * surfaces. Both parameters are retained so the existing call sites and check
 * tools keep their shape, and so a future adapter can reach for a control
 * without a signature change.
 */
export function buildScoreCategories(
  evidence: PublicScanEvidence,
  _controls?: ControlState[],
  _postQuantumReadinessScore?: number,
): ScoreComponent[] {
  return buildPublishedCategorySet(toPublishedCategoryEvidence(evidence))
}
