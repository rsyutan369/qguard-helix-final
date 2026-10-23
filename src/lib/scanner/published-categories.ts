/**
 * THE twelve published grading categories — one implementation, every surface.
 *
 * ── Why this module exists ──────────────────────────────────────────────────
 *
 * `SCORE_CATEGORY_DEFS` declares twelve weighted categories and
 * `weightedCategoryScore` aggregates them, so both surfaces already shared the
 * published STANDARD. What they did not share was the SCORING: the categories
 * were implemented twice, once per pipeline —
 *
 *   /public-scan          grading-model.ts     `buildScoreCategories`
 *   /dashboard/scanner    published-scoring.ts `buildPublishedCategories`
 *
 * — and the two implementations drifted. A live scan of test.openquantumsafe.org
 * fed IDENTICAL evidence into both (TLSv1.2 + TLSv1.3 accepted, X25519MLKEM768
 * accepted across 17 handshakes, ECDSA P-256 leaf on an 89-day lifetime, 2 SCTs,
 * no OCSP responder advertised, no CAA RRset, 0 of 8 transport headers hardened)
 * and they published six different answers:
 *
 *   category                    public   scanner
 *   tls-configuration    w18      100      90
 *   certificates         w12      100      80
 *   hsts                  w5       55      50
 *   ocsp-stapling         w5      n/a      40
 *   cryptographic-algos   w5       71      44
 *   post-quantum-readin.  w3       78      81
 *   ─────────────────────────────────────────
 *   composite                      83      75
 *   grade                      B · Good  B- · Fair
 *
 * Nothing about the endpoint differed. Two opinions about one model is a
 * violation of the platform's first data-integrity rule — a value is computed
 * ONCE and read everywhere else — so the two functions above are now thin
 * ADAPTERS that normalise their own evidence into {@link PublishedCategoryEvidence}
 * and delegate here. Drift is structurally impossible: there is one ladder per
 * category and both surfaces walk it.
 *
 * ── How each disagreement was resolved ──────────────────────────────────────
 *
 * Consistency alone is not accuracy, so each of the six was settled on the
 * merits rather than by picking a side:
 *
 *   tls-configuration   The dashboard's ladder. 100 asserts "TLS 1.3 only";
 *                       an endpoint that also accepts TLS 1.2 is a strong,
 *                       standards-compliant deployment but not maximal
 *                       hardening, and the public ladder could not express the
 *                       difference at all.
 *
 *   certificates        The public reading. The dashboard deducted 20 points
 *                       for an elliptic-curve key — a QUANTUM penalty inside a
 *                       category the published model defines as "Validity,
 *                       chain quality, key size, algorithms, expiration".
 *                       Quantum exposure is already scored by
 *                       `cryptographic-algorithms` (w5) and
 *                       `post-quantum-readiness` (w3); charging it a third time
 *                       here (w12) triple-counted it and made a valid, trusted,
 *                       short-lived chain look like a defect. Classical key
 *                       STRENGTH is still scored — RSA-2048 is ~112-bit, under
 *                       the 128-bit floor — because that is key size, which the
 *                       category does own.
 *
 *   hsts                The public ladder, which grades on the actual max-age
 *                       rather than collapsing every imperfect policy to one
 *                       "weak" value.
 *
 *   ocsp-stapling       The public reading, and the clearest defect of the six.
 *                       This leaf advertises NO OCSP responder, so stapling is
 *                       not something it is failing to do — it is something it
 *                       cannot do. The dashboard scored it 40/100 anyway, which
 *                       is an unmeasurable control rendered as a failing one.
 *                       Not applicable, weight redistributed.
 *
 *   crypto-algorithms   The dashboard reading, via `buildAlgorithmCensus`. The
 *                       public scorer took the post-quantum share over EVERY
 *                       catalogued algorithm including TLS 1.2, TLS 1.3,
 *                       AES-256-GCM and SHA-384, awarding each 55 points as
 *                       "Classical" — inflating a post-quantum measure with
 *                       primitives that are not quantum-vulnerable and not
 *                       migration candidates. The census takes the share over
 *                       asymmetric primitives only, and says so.
 *
 *   post-quantum-readi. Neither: both already delegate to the shared
 *                       `postQuantumReadinessFromSignals`, and the gap was in
 *                       the SIGNALS. The dashboard granted the model's
 *                       "hardened HSTS" allowance on `maxAge !== null` — i.e.
 *                       to any HSTS header at all — while its own `hsts`
 *                       category scored that same header 50/100 "weak max-age".
 *                       Hardened now means what the HSTS category says it
 *                       means: a full-year policy covering subdomains.
 *
 * ── The contract ────────────────────────────────────────────────────────────
 *
 * Every scorer returns `null` for "not measured", NEVER a zero. A null category
 * is excluded from the weighted mean and its weight redistributed across the
 * rest (`weightedCategoryScore`). Zero is a measured verdict and means the
 * control was looked for, found, and found wanting. Conflating the two is how
 * an endpoint gets punished for evidence nobody collected — and, in the
 * mirror-image failure, how an unprobed dimension gets to flatter a target with
 * a silent 100.
 *
 * This module is PURE: no sockets, no Supabase, no Express. Both the server
 * pipelines and the browser bundles import it.
 */
import {
  SCORE_CATEGORY_DEFS,
  postQuantumReadinessFromSignals,
} from './public-scan/grading-model'
import { buildAlgorithmCensus } from './web-scanner/algorithm-census'
import { HYBRID_GROUP_COMPONENTS, kemParameterSetsFor } from './named-groups'

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)))

/** The HSTS preload floor, in seconds. */
const ONE_YEAR_SECONDS = 31_536_000

/* ─── The normalised evidence shape ─────────────────────────────────────────
   Deliberately primitive — booleans, numbers and strings rather than either
   pipeline's own result objects. An adapter that has to flatten its evidence
   into this shape cannot accidentally smuggle a pipeline-specific fallback into
   the scoring, which is exactly how the two implementations drifted. */

export interface SuiteObservation {
  name: string
  /** Static-RSA key transport: no forward secrecy, no post-quantum hedge. */
  staticRsa: boolean
  /** A classically broken primitive — 3DES, DES, RC4, NULL, EXPORT, MD5. */
  weak: boolean
  /** CBC mode: mac-then-encrypt rather than AEAD. */
  cbc: boolean
}

/**
 * Classify one enumerated cipher suite — THE predicate, used by both adapters.
 *
 * It exists because the two adapters each had their own. The dashboard tested
 * the suite NAME for broken primitives; the public side additionally promoted
 * anything its analyser had tagged `riskLevel: HIGH` to "weak", which on a
 * TLS 1.3-only endpoint caught `TLS_AES_128_GCM_SHA256` — a perfectly sound
 * AEAD suite — and cost the endpoint a 40-point penalty the other surface never
 * applied. Same two suites, same handshake, 60 against 100.
 *
 * A 128-bit AEAD is a real post-quantum consideration, but it is not a BROKEN
 * suite. It is carried by the Grover margin on the negotiated suite and named
 * explicitly in the algorithm census; charging it here as well would be the
 * same primitive counted twice.
 */
export function classifySuite(name: string, category?: string | null): SuiteObservation {
  return {
    name,
    /* Static RSA key transport is RSA IMMEDIATELY after the protocol prefix —
       `TLS_RSA_WITH_…` (and RSA-PSK, which transports the same way). The old
       `(^|_)RSA_WITH` also matched the `_RSA_WITH` inside `TLS_ECDHE_RSA_WITH_…`,
       which is ephemeral ECDHE AUTHENTICATED by RSA — forward secret, and the
       most common suite family on the Internet. Every RSA-certificate endpoint
       was charged the 50-point static-RSA penalty and a "partial" forward
       secrecy, while the Findings table (which reads the probe's category)
       correctly called the same suites Healthy. OpenSSL-style names carry no
       key-exchange prefix, so the probe's category still decides those. */
    staticRsa: /^(?:TLS|SSL)_RSA_/i.test(name) || category === 'rsa-kex',
    weak: /3DES|_DES_|RC4|NULL|EXPORT|MD5|_anon_/i.test(name),
    cbc: /CBC/i.test(name),
  }
}

export interface CertificateObservation {
  publicKeyAlgorithm: string
  /** Key size in bits; null when the probe could not read it. */
  publicKeySize: number | null
  signatureAlgorithm: string
  isExpired: boolean
  isSelfSigned: boolean
  /**
   * Chain verification verdict against the system trust store. `null` means
   * verification was never attempted — not that it failed.
   */
  chainTrusted: boolean | null
  chainHasExpiredEntry: boolean
  /** Issued lifetime in days (notAfter − notBefore). */
  validityDays: number | null
  /** Days until expiry. Zero or negative once expired; null when unknown. */
  daysRemaining: number | null
}

export interface TransportObservation {
  /** A TLS handshake completed. Nothing below is scorable without it. */
  handshakeCompleted: boolean
  /**
   * The versions this endpoint ACCEPTS, from per-version probing. `null` when
   * the enumeration never settled — the one version a socket negotiated cannot
   * rule the others out, and scoring it as though it could published a perfect
   * 100 for an endpoint that also accepted TLS 1.0.
   */
  acceptedProtocols: string[] | null
  negotiatedProtocol: string | null
  negotiatedSuite: string | null
  enumeratedSuites: SuiteObservation[]
  /** Measured acceptance of static-RSA key transport; null when unprobed. */
  staticRsaAccepted: boolean | null
  /** Symmetric strength of the negotiated AEAD, for the Grover margin. */
  symmetricBits: number | null
  /** Tri-state: `value` is meaningless unless `measured`. */
  forwardSecrecy: { measured: boolean; value: boolean | null }
}

export interface KeyAgreementObservation {
  /** Named-group probing ran at all. */
  probed: boolean
  /** The HYBRID groups specifically reached a terminal answer. */
  hybridSettled: boolean
  hybrid: boolean
  /** Standalone ML-KEM — post-quantum with no classical hedge. */
  pureKem: boolean
  group: string | null
  classicalComponent: string | null
  postQuantumComponent: string | null
  handshakes: number | null
  /** Classical named groups were accepted. */
  classicalObserved: boolean
  /** The socket's own key-exchange label, consulted only as a last resort. */
  socketLabel: string | null
  negotiatedCurve: string | null
}

export interface PublishedCategoryEvidence {
  transport: TransportObservation
  certificate: CertificateObservation | null
  keyAgreement: KeyAgreementObservation
  /** Null when the certificate was never probed for revocation metadata. */
  revocation: {
    probed: boolean
    /** The leaf carries an AIA OCSP URI. Without one, stapling is impossible. */
    advertisesResponder: boolean
    stapled: boolean
    mustStaple: boolean
    /** It advertised a responder and the responder did not answer. */
    responderDead: boolean
  } | null
  transparency: { probed: boolean; sctCount: number } | null
  caa: {
    probed: boolean
    queryable: boolean
    /** The RFC 8659 climb reached the registrable domain. */
    climbComplete: boolean
    present: boolean
    recordCount: number
    atName: string | null
  } | null
  /**
   * Raw material for the algorithm census, which is taken HERE rather than by
   * each adapter.
   *
   * The adapters used to run `buildAlgorithmCensus` themselves and hand over a
   * finished score, and they fed it different key-agreement primitives for the
   * same handshake — one passed the registry group name `X25519MLKEM768`, the
   * other the parameter set `ML-KEM-768` — so the Cryptographic Algorithms
   * category came out 33 on one surface and 40 on the other. A census is a
   * derivation, and derivations belong on this side of the boundary.
   */
  algorithmSources: {
    tls: Parameters<typeof buildAlgorithmCensus>[0]['observations'][number]['tls']
    certificate: Parameters<typeof buildAlgorithmCensus>[0]['observations'][number]['certificate']
    /** Repository / client-bundle pattern hits, for targets with no transport. */
    patterns: Array<{ algorithm?: string | null }>
  }
  /** Transport-security response headers, excluding HSTS. */
  headers: { hardened: number | null; applicable: number | null }
  hsts: {
    observed: boolean
    present: boolean
    maxAgeSeconds: number | null
    includeSubDomains: boolean
    preload: boolean
  } | null
  /** A post-quantum signature appears in the served chain. */
  pqSignatureObserved: boolean
}

/**
 * The algorithm census for this evidence — ONE construction, both surfaces.
 *
 * The key-agreement half is rebuilt from the measured group rather than taken
 * from whatever shape the pipeline happened to carry, so an endpoint that
 * negotiated `X25519MLKEM768` contributes the same primitives whichever surface
 * observed it.
 */
export function censusFor(e: PublishedCategoryEvidence) {
  const k = e.keyAgreement
  const groups = k.group ? [k.group] : []
  const components = k.group ? HYBRID_GROUP_COMPONENTS[k.group] : undefined
  return buildAlgorithmCensus({
    observations: [
      {
        tls: e.algorithmSources.tls,
        certificate: e.algorithmSources.certificate,
        keyAgreement: {
          probed: k.probed,
          kemApplied: k.hybrid || k.pureKem,
          hybrid: k.hybrid,
          group: k.group,
          classicalComponent: k.classicalComponent ?? components?.classical ?? null,
          postQuantumComponent: k.postQuantumComponent ?? components?.postQuantum ?? null,
          kemParameterSets: kemParameterSetsFor(groups),
        },
      },
    ],
    patterns: e.algorithmSources.patterns,
  })
}

export interface PublishedCategory {
  key: string
  label: string
  weight: number
  /** 0-100 posture. MEANINGLESS unless `applicable`. */
  score: number
  applicable: boolean
  /** The measurement this score was read from, rendered verbatim in the UI. */
  observed: string
  /** The published description of what this category grades. */
  detail: string
}

type Scored = { score: number; observed: string } | null

/* ─── Category scorers ──────────────────────────────────────────────────────
   One ladder each. Every `return null` states that the evidence for this
   category was not collected, and carries its reason via EXCLUSION_REASON. */

/**
 * TLS Configuration (w18) — the protocol versions the endpoint ACCEPTS.
 *
 * 100 asserts "TLS 1.3 only". An endpoint that also accepts TLS 1.2 is a
 * correct, NIST-compliant, Mozilla-"Intermediate" deployment — strong, but one
 * hardening step short of the maximum, which is what grade A- (90) says.
 */
function tlsConfiguration(t: TransportObservation): Scored {
  if (!t.handshakeCompleted) return null
  const protocols = t.acceptedProtocols
  /* THE NEGOTIATED VERSION IS NOT THE ACCEPTED SET. An endpoint that throttles
     per-version enumeration answers the first handshake and refuses the rest;
     falling back to the one version it negotiated scored TLS 1.3 as a perfect
     100 for a host that also accepted TLS 1.0. Excluded, weight redistributed. */
  if (!protocols || protocols.length === 0) return null

  const observed = protocols.join(', ')
  if (protocols.some((p) => /SSLv2|SSLv3/i.test(p))) return { score: 0, observed }
  if (protocols.some((p) => /^TLSv1(\.0)?$|^TLSv1\.1$/i.test(p))) return { score: 45, observed }
  if (protocols.includes('TLSv1.3')) {
    return { score: protocols.includes('TLSv1.2') ? 90 : 100, observed }
  }
  if (protocols.includes('TLSv1.2')) return { score: 70, observed }
  return { score: 45, observed }
}

/**
 * Cipher Suites (w15) — the negotiated suite AND everything else still accepted.
 *
 * Static-RSA key transport is the one penalty a hybrid key agreement must never
 * offset: ML-KEM lives only in the TLS 1.3 key_share, so a client that
 * negotiates one of those suites gets a session with neither forward secrecy
 * nor any post-quantum protection at all.
 */
function cipherSuites(t: TransportObservation): Scored {
  if (!t.handshakeCompleted) return null
  const negotiated = t.negotiatedSuite ?? ''
  const suites = t.enumeratedSuites
  if (!negotiated && suites.length === 0) return null

  let score = 100
  if (negotiated) {
    if (!/GCM|CHACHA20|POLY1305|CCM/i.test(negotiated)) score -= 20
    if (/3DES|_DES_|RC4|NULL|EXPORT|MD5/i.test(negotiated)) score -= 40
    if (/CBC/i.test(negotiated)) score -= 20
  }

  const staticRsa = suites.filter((s) => s.staticRsa)
  const weak = suites.filter((s) => s.weak)
  const cbc = suites.filter((s) => s.cbc)
  const staticRsaAccepted = staticRsa.length > 0 || t.staticRsaAccepted === true
  if (staticRsaAccepted) score -= 50
  if (weak.length) score -= 40
  else if (cbc.length) score -= 15

  /* Grover halves symmetric strength: a 128-bit AEAD leaves a 64-bit
     post-quantum margin, which is not quantum-safe and must cost points. */
  if (t.symmetricBits === 128) score -= 15

  const observed = [
    negotiated || `${suites.length} suite(s) enumerated`,
    negotiated && suites.length ? `${suites.length} suite(s) enumerated` : '',
    staticRsaAccepted ? 'static RSA accepted' : '',
    t.symmetricBits === 128 ? '128-bit AEAD, 64-bit Grover margin' : '',
  ]
    .filter(Boolean)
    .join(' · ')
  return { score: clamp(score), observed }
}

/**
 * Certificates (w12) — validity, chain quality, key SIZE, signature algorithm,
 * expiration and lifecycle hygiene. Blended 65% algorithm/trust, 35% lifecycle,
 * matching the published decomposition.
 *
 * NOT scored here: whether the key is classical rather than post-quantum. That
 * is what `cryptographic-algorithms` and `post-quantum-readiness` measure, and
 * deducting for it here charged one fact to three categories.
 */
function certificates(cert: CertificateObservation | null): Scored {
  if (!cert) return null

  let algorithm = 100
  if (cert.isExpired) algorithm -= 60
  if (cert.isSelfSigned) algorithm -= 30
  else if (cert.chainTrusted === false) algorithm -= 40
  if (/sha-?1|md5/i.test(cert.signatureAlgorithm || '')) algorithm -= 45
  if (cert.chainHasExpiredEntry) algorithm -= 20

  /* Classical key strength, measured against the 128-bit floor.
     ORDER MATTERS, AND IT IS NOT COSMETIC. "ecdsa" contains "dsa", so a
     finite-field test placed first captures every elliptic-curve key and then
     compares its 256-bit modulus to RSA's 2048-bit floor — which scored a
     perfectly healthy P-256 leaf as if it were a 256-bit RSA key. Curve keys
     are classified first, and each family is judged on its own scale. */
  const alg = (cert.publicKeyAlgorithm || '').toLowerCase()
  const bits = cert.publicKeySize ?? 0
  if (/ml-dsa|slh-dsa|dilithium|sphincs|falcon/i.test(alg)) {
    /* Post-quantum signature key: no classical strength deduction applies. */
  } else if (/ec|ed25519|ed448|x25519|x448|curve/.test(alg)) {
    /* Curve size is roughly twice the security level: P-256 → 128-bit, which
       meets the floor. Below ~224 bits the curve is under 112-bit security. */
    if (bits > 0 && bits < 224) algorithm -= 40
  } else if (/rsa|dsa|dh/.test(alg)) {
    /* RSA/DSA/DH moduli: 2048 → ~112-bit (under the floor), 3072 → ~128-bit.
       Sub-2048 carries the same weight as expiry, and for the same reason — a
       factorable key and an expired one both mean the certificate cannot do the
       job it is presented for. Scored lighter, excellent rotation hygiene pulled
       a 1024-bit leaf back up to a "Fair" grade. */
    if (bits > 0 && bits < 2048) algorithm -= 60
    else if (bits > 0 && bits < 3072) algorithm -= 10
  } else if (alg) {
    algorithm -= 15 // unrecognised key type — its strength cannot be vouched for
  }
  algorithm = clamp(algorithm)

  /* Lifecycle: short automated lifetimes enable fast algorithm rollover, and a
     certificate close to expiry is an operational risk regardless of strength. */
  let lifecycle: number | null = null
  const validityDays = cert.validityDays
  if (validityDays !== null && validityDays > 0) {
    lifecycle = 0
    if (validityDays <= 100) lifecycle += 60
    else if (validityDays <= 200) lifecycle += 45
    else if (validityDays <= 400) lifecycle += 30
    else lifecycle += 15
    /* An EXPIRED certificate has no remaining life, whatever the field says.
       Reading `daysRemaining` without this guard let an expired leaf collect the
       full rotation-hygiene allowance and climb back to a passing grade on the
       strength of how short its (already elapsed) lifetime was. */
    const remaining = cert.isExpired ? 0 : cert.daysRemaining
    if (remaining === null) lifecycle += 40 // unknown expiry is not an expiring one
    else if (remaining > 30) lifecycle += 40
    else if (remaining > 14) lifecycle += 20
    lifecycle = clamp(lifecycle)
  }

  const score = lifecycle === null ? algorithm : clamp(algorithm * 0.65 + lifecycle * 0.35)
  const observed = [
    cert.publicKeyAlgorithm,
    cert.publicKeySize ? `${cert.publicKeySize}-bit` : '',
    validityDays !== null ? `${validityDays}-day lifetime` : '',
    cert.isExpired ? 'EXPIRED' : '',
    cert.isSelfSigned ? 'self-signed' : cert.chainTrusted === false ? 'chain not trusted' : '',
  ]
    .filter(Boolean)
    .join(' · ')
  return { score, observed }
}

/**
 * Key Exchange (w12) — WHICH mechanism was negotiated, not merely whether
 * ephemeral key agreement is present at all (that is Forward Secrecy).
 *
 * The MEASURED group decides. A TLS 1.3 socket label is a protocol guarantee
 * ("some ephemeral (EC)DHE group was used", RFC 8446), never a statement about
 * which group — reading it as one scored live hybrid endpoints 70/100.
 */
function keyExchange(t: TransportObservation, k: KeyAgreementObservation): Scored {
  if (!t.handshakeCompleted) return null

  if (k.hybrid) {
    const components =
      k.classicalComponent && k.postQuantumComponent
        ? ` — ${k.classicalComponent} + ${k.postQuantumComponent}`
        : ''
    const across = k.handshakes ? `, accepted in isolation across ${k.handshakes} handshake(s)` : ''
    return { score: 100, observed: `${k.group ?? 'hybrid group'}${components}${across}` }
  }
  if (k.pureKem) {
    /* Real post-quantum key agreement with no classical hedge: a flaw in the
       lattice assumption has no fallback. Strong, not perfect. */
    return { score: 90, observed: `${k.group ?? 'ML-KEM'} — post-quantum only, no classical hedge` }
  }

  /* Only a SETTLED hybrid probe licenses the refusal sentence. Classical groups
     settle first and cheapest, so phrasing this off `probed` printed "every
     hybrid ML-KEM group was offered and refused" for endpoints whose hybrid
     probes had merely been throttled. An endpoint with no TLS 1.3 is settled by
     its protocol list: hybrid groups exist only in the 1.3 key_share, so the
     probe is skipped and "did not settle" would understate a known negative. */
  const suffix = tls13ProvablyAbsent(t)
    ? ' · TLS 1.3 is not offered, so no hybrid ML-KEM group can be negotiated'
    : k.hybridSettled
      ? ' · every hybrid ML-KEM group was offered in isolation and refused'
      : k.probed
        ? ' · hybrid ML-KEM groups did not settle on this run, so no post-quantum claim is made either way'
        : ''
  const observed = `${k.socketLabel || 'not observed'}${
    k.negotiatedCurve ? ` (${k.negotiatedCurve})` : ''
  }${suffix}`

  const kex = `${k.socketLabel ?? ''} ${k.negotiatedCurve ?? ''} ${t.negotiatedSuite ?? ''}`
  if (/ml-kem|kyber/i.test(kex)) return { score: 100, observed }
  if (k.classicalObserved) return { score: 70, observed }
  if (/ECDHE|X25519|X448|ffdhe/i.test(kex)) return { score: 70, observed }
  if (/DHE/i.test(kex)) return { score: 55, observed }
  if (/(^|[^A-Z])RSA([^A-Z]|$)|rsa-kex/i.test(kex)) return { score: 15, observed }
  /* TLS 1.3 guarantees ephemeral key agreement even when the named-group probe
     could not resolve WHICH group — no implementation exposes it for 1.3. */
  return { score: t.negotiatedProtocol === 'TLSv1.3' ? 65 : 30, observed }
}

/** Forward Secrecy (w10) — whether EVERY session the endpoint agrees to is forward secret. */
function forwardSecrecy(t: TransportObservation, k: KeyAgreementObservation): Scored {
  if (!t.handshakeCompleted) return null
  /* Not measured redistributes the weight, the same treatment every other
     unmeasured dimension gets. Scoring an unmeasured control 100 was the half
     of the old contradiction that flattered the target. */
  if (!t.forwardSecrecy.measured) return null
  if (t.forwardSecrecy.value !== true) return { score: 0, observed: 'no ephemeral key agreement' }

  const label = k.group ?? k.socketLabel ?? 'ephemeral'
  const staticRsa = t.enumeratedSuites.filter((s) => s.staticRsa)
  const staticRsaAccepted = staticRsa.length > 0 || t.staticRsaAccepted === true
  /* Preferring ECDHE while still accepting static-RSA key transport is not full
     forward secrecy — a client that asks for those suites gets none. */
  return staticRsaAccepted
    ? {
        score: 70,
        observed: `${label} · ${staticRsa.length || 'some'} static-RSA suite(s) still accepted`,
      }
    : { score: 100, observed: `${label}${k.negotiatedCurve ? ` (${k.negotiatedCurve})` : ''}` }
}

/** HTTP Security Headers (w8) — transport-security response headers, HSTS excluded. */
function httpSecurityHeaders(e: PublishedCategoryEvidence): Scored {
  const { hardened, applicable } = e.headers
  if (hardened === null || applicable === null || applicable === 0) return null
  return {
    score: clamp((hardened / applicable) * 100),
    observed: `${hardened}/${applicable} transport headers hardened`,
  }
}

/**
 * HSTS (w5) — graduated on the actual policy, because "present, 30 days, no
 * subdomain coverage" and "absent" are materially different risks.
 */
function hsts(e: PublishedCategoryEvidence): Scored {
  const h = e.hsts
  if (!h || !h.observed) return null
  if (!h.present) return { score: 0, observed: 'absent' }

  const maxAge = h.maxAgeSeconds ?? 0
  const score =
    maxAge >= ONE_YEAR_SECONDS && h.includeSubDomains
      ? h.preload
        ? 100
        : 95
      : maxAge >= ONE_YEAR_SECONDS
        ? 75
        : maxAge >= 86_400 * 30
          ? 55
          : maxAge > 0
            ? 30
            : 10

  const observed = [
    `max-age=${maxAge}`,
    h.includeSubDomains ? 'includeSubDomains' : '',
    h.preload ? 'preload' : '',
  ]
    .filter(Boolean)
    .join(' · ')
  return { score, observed }
}

/**
 * Whether the HSTS policy is HARDENED — the signal the post-quantum readiness
 * model awards its crypto-agility allowance for.
 *
 * Defined off the SAME thresholds the `hsts` category scores on, so one header
 * cannot be "weak max-age" to one category and "enforced" to another. That
 * contradiction is precisely what made one surface read 81% readiness where the
 * other read 78% on identical evidence.
 */
function hstsHardened(e: PublishedCategoryEvidence): boolean {
  const h = e.hsts
  if (!h?.observed || !h.present) return false
  return (h.maxAgeSeconds ?? 0) >= ONE_YEAR_SECONDS && h.includeSubDomains
}

/**
 * OCSP Stapling (w5).
 *
 * A certificate that advertises NO responder cannot staple one. That is not a
 * control it is failing — it is a control that does not apply, and modern
 * deployments deliberately replace it with short lifetimes and Certificate
 * Transparency. Scoring it as a partial failure punished the endpoint for an
 * architecture the industry now recommends.
 */
function ocspStapling(e: PublishedCategoryEvidence): Scored {
  const r = e.revocation
  if (!r?.probed) return null
  if (r.stapled) return { score: 100, observed: 'stapled in the handshake' }
  if (!r.advertisesResponder) return null
  /* A must-staple certificate that does not staple is a hard failure: relying
     parties are instructed to refuse the connection outright. */
  if (r.mustStaple) return { score: 0, observed: 'must-staple asserted but no response stapled' }
  if (r.responderDead) {
    return { score: 10, observed: 'not stapled, and the advertised responder did not answer' }
  }
  return { score: 40, observed: 'not stapled — responder reachable off-path' }
}

/** Certificate Transparency (w3). Chrome's policy floor is two independent logs. */
function certificateTransparency(e: PublishedCategoryEvidence): Scored {
  const ct = e.transparency
  if (!ct?.probed) return null
  if (ct.sctCount <= 0) {
    return { score: 0, observed: 'no SCTs in the certificate, handshake or stapled response' }
  }
  return { score: ct.sctCount >= 2 ? 100 : 70, observed: `${ct.sctCount} SCT(s)` }
}

/**
 * DNS CAA (w4).
 *
 * AN ABANDONED CLIMB IS NOT A NEGATIVE. RFC 8659 resolves issuance policy at
 * the name and then up to the registrable domain, so "no RRset at
 * www.example.com" establishes nothing until example.com has been asked.
 */
function dnsCaa(e: PublishedCategoryEvidence): Scored {
  const caa = e.caa
  if (!caa?.probed || !caa.queryable) return null
  if (!caa.climbComplete) return null
  if (!caa.present) return { score: 0, observed: 'no CAA record — any CA may issue for this name' }
  return {
    score: 100,
    observed: `${caa.recordCount} CAA record(s)${caa.atName ? ` at ${caa.atName}` : ''}`,
  }
}

/**
 * Cryptographic Algorithms (w5) — the post-quantum share of the observed
 * asymmetric material, from the one census.
 *
 * The share is deliberately NOT taken over every catalogued algorithm: AES-256,
 * SHA-384 and a protocol version are observations, not migration candidates,
 * and counting them diluted a post-quantum measure with primitives that have no
 * post-quantum story to tell.
 */
function cryptographicAlgorithms(e: PublishedCategoryEvidence): Scored {
  const census = censusFor(e)
  if (census.observed === 0) return null
  if (census.score === null) return null
  return { score: clamp(census.score), observed: census.summary }
}

/* ─── Assembly ──────────────────────────────────────────────────────────── */

/** Why a category carries no score. Travels with the exclusion so the UI never guesses. */
const EXCLUSION_REASON: Record<string, (e: PublishedCategoryEvidence) => string> = {
  'tls-configuration': (e) =>
    e.transport.handshakeCompleted
      ? 'per-version probing returned no accepted protocol list, so the versions this endpoint accepts were not established — the one version the socket negotiated cannot rule the others out'
      : 'no TLS handshake completed',
  'cipher-suites': () => 'no TLS handshake completed',
  certificates: () => 'no certificate could be read from this endpoint',
  'key-exchange': () => 'no TLS handshake completed',
  'forward-secrecy': (e) =>
    e.transport.handshakeCompleted
      ? 'neither the protocol version nor the named-group probe established whether every accepted session is forward secret'
      : 'no TLS handshake completed',
  'http-security-headers': () => 'no HTTP response was read from this endpoint',
  hsts: () => 'no HTTP response was read from this endpoint',
  'ocsp-stapling': (e) =>
    e.revocation?.probed
      ? 'not applicable — the certificate advertises no OCSP responder, so a response cannot be stapled; this deployment relies on certificate lifetime and Certificate Transparency instead'
      : 'the certificate was not probed for revocation metadata',
  'certificate-transparency': () => 'the certificate was not probed for Certificate Transparency',
  'dns-caa': (e) =>
    e.caa?.probed && e.caa.queryable && !e.caa.climbComplete
      ? 'the RFC 8659 climb to the registrable domain did not complete, so no issuance policy was established either way'
      : 'CAA records could not be queried for this name',
  'cryptographic-algorithms': (e) =>
    censusFor(e).observed > 0
      ? 'algorithms were observed but none of them is asymmetric, so a post-quantum share is not defined over this population'
      : 'no cryptographic material was observed on this target',
  'post-quantum-readiness': (e) =>
    e.transport.handshakeCompleted || e.certificate
      ? e.keyAgreement.probed
        ? 'hybrid ML-KEM group probing did not settle on this run, and hybrid deployment carries 55 of this category’s 100 points — a readiness figure without it would be a guess'
        : 'named key-agreement groups were not probed on this run, and hybrid deployment carries 55 of this category’s 100 points — a readiness figure without it would be a guess'
      : 'no TLS handshake completed and no certificate was read, so there was nothing to assess readiness from',
}

/**
 * The endpoint's accepted-protocol list was measured and does not include
 * TLS 1.3 — so no hybrid ML-KEM group can be negotiated, whatever the group
 * probe did. A measured negative, not an unknown: both scanners skip the hybrid
 * probe on such an endpoint, and reading that skip as "did not settle" withheld
 * the readiness score on expired.badssl.com while its own findings table said
 * "Not offered — the endpoint does not negotiate TLS 1.3".
 */
export function tls13ProvablyAbsent(t: TransportObservation): boolean {
  if (!t.handshakeCompleted || !t.acceptedProtocols?.length) return false
  return !t.acceptedProtocols.includes('TLSv1.3') && t.negotiatedProtocol !== 'TLSv1.3'
}

/**
 * Post-quantum readiness, scored from the shared model on signals derived HERE
 * so both surfaces feed it identically.
 *
 * Returns null — excluded, weight redistributed — when the hybrid probe never
 * settled. Feeding `hybridObserved: false` in that case is not a conservative
 * default: it is an unmeasured dimension scored as a negative one, and it is
 * what turned a 73% endpoint into 6% on a throttled run.
 */
export function publishedPostQuantumReadiness(
  e: PublishedCategoryEvidence,
): { score: number; reasons: string[] } | null {
  const t = e.transport
  const k = e.keyAgreement
  if (!t.handshakeCompleted && !e.certificate) return null
  /* The hybrid signal must be MEASURED before the model can speak, because it
     carries 55 of the 100 points. Three ways it is: a hybrid/ML-KEM group was
     accepted, the hybrid probe settled on a refusal, or the endpoint provably
     offers no TLS 1.3 (hybrid groups exist only in its key_share). A probe that
     never ran, or ran and did not settle, measured nothing — scoring it as a
     refusal is what turned a 73% endpoint into 6% on a throttled run. */
  const hybridMeasured = k.hybrid || k.pureKem || (k.probed && k.hybridSettled) || tls13ProvablyAbsent(t)
  if (!hybridMeasured) return null

  return postQuantumReadinessFromSignals({
    hybridObserved: k.hybrid || k.pureKem,
    pqSignatureObserved: e.pqSignatureObserved,
    tls13Offered:
      (t.acceptedProtocols ?? []).includes('TLSv1.3') || t.negotiatedProtocol === 'TLSv1.3',
    certificateValidityDays: e.certificate?.validityDays ?? null,
    certificateTransparency: Boolean(e.transparency?.probed && e.transparency.sctCount > 0),
    hstsEnforced: hstsHardened(e),
  })
}

/**
 * Build all twelve published categories from normalised evidence.
 *
 * THE one implementation. `grading-model.buildScoreCategories` (/public-scan)
 * and `published-scoring.buildPublishedCategories` (/dashboard/scanner) are
 * adapters over it and hold no ladders of their own.
 */
export function buildPublishedCategorySet(e: PublishedCategoryEvidence): PublishedCategory[] {
  const pq = publishedPostQuantumReadiness(e)

  const measured: Record<string, Scored> = {
    'tls-configuration': tlsConfiguration(e.transport),
    'cipher-suites': cipherSuites(e.transport),
    certificates: certificates(e.certificate),
    'key-exchange': keyExchange(e.transport, e.keyAgreement),
    'forward-secrecy': forwardSecrecy(e.transport, e.keyAgreement),
    'http-security-headers': httpSecurityHeaders(e),
    hsts: hsts(e),
    'ocsp-stapling': ocspStapling(e),
    'certificate-transparency': certificateTransparency(e),
    'dns-caa': dnsCaa(e),
    'cryptographic-algorithms': cryptographicAlgorithms(e),
    'post-quantum-readiness': pq
      ? {
          score: pq.score,
          observed: `${pq.score}% readiness · ${
            pq.reasons.slice(0, 2).join(' · ') || 'measured from the observed surface'
          }`,
        }
      : null,
  }

  return SCORE_CATEGORY_DEFS.map((def) => {
    const row = measured[def.key] ?? null
    return {
      key: def.key,
      label: def.label,
      weight: def.weight,
      score: row?.score ?? 0,
      applicable: row !== null,
      observed: row?.observed ?? EXCLUSION_REASON[def.key]?.(e) ?? 'not observed',
      detail: def.description,
    }
  })
}
