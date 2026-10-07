/**
 * SURFACE PARITY — /public-scan and /dashboard/scanner publish ONE answer.
 *
 *   npx tsx tools/surface-parity-check.ts
 *
 * Offline. No server, no Supabase, no network.
 *
 * ── The defect this pins ────────────────────────────────────────────────────
 *
 * A live scan of test.openquantumsafe.org produced, from IDENTICAL evidence,
 * two different reports of the same endpoint at the same moment:
 *
 *                               /public-scan    /dashboard/scanner
 *   headline                    81 · B · Good   76 · B- · Fair
 *   TLS / Transport card        Excellent  96   Review     97
 *   Certificates card           Elite     100   At Risk    73
 *   Quantum card                Good       89   At Risk    67
 *
 * Both surfaces had measured TLSv1.2 + TLSv1.3, X25519MLKEM768 accepted in
 * isolation, an ECDSA P-256 leaf on an 89-day lifetime, 2 SCTs, no advertised
 * OCSP responder and no CAA RRset. Nothing about the endpoint differed — the
 * twelve published categories were simply implemented twice and had drifted.
 *
 * ── What this asserts ───────────────────────────────────────────────────────
 *
 *   1. ONE SCORER. Both adapters, fed equivalent evidence for one host, produce
 *      identical scores and identical applicability for all twelve categories.
 *      This is the test that fails the moment someone adds a second ladder.
 *
 *   2. UNMEASURED IS NOT ZERO, AND NOT A PASS. Each category that can be
 *      unmeasured is driven to that state and must come back inapplicable with
 *      a reason — never 0, never 100.
 *
 *   3. THE RESOLVED DISAGREEMENTS STAY RESOLVED. One assertion per defect, in
 *      both directions, because a suppression that fires unconditionally passes
 *      a one-sided test while silencing real exposure.
 *
 *   4. THE NODE RINGS PARTITION THE SAME MODEL. Every published category is
 *      claimed exactly once per ring, so no measurement is double-counted
 *      across cards or silently dropped — and the cards both pages share
 *      project the same categories, so "Certificates" cannot mean one thing on
 *      one page and another on the other.
 */
import {
  buildPublishedCategorySet,
  censusFor,
  type PublishedCategoryEvidence,
} from '../src/lib/scanner/published-categories'
import { toPublishedCategoryEvidence } from '../src/lib/scanner/public-scan/score-categories'
import { buildPublishedCategories } from '../src/lib/scanner/web-scanner/published-scoring'
import {
  SCORE_CATEGORY_DEFS,
  scoreToGrade,
  weightedCategoryScore,
} from '../src/lib/scanner/public-scan/grading-model'
import { NODE_SCORE_CATEGORIES } from '../src/app/public-scan/_qve/event-derivation'
import { SCANNER_NODE_CATEGORIES } from '../src/app/dashboard/scanner_dashboard/_intel'

let failures = 0
let passes = 0

function assert(condition: boolean, label: string, detail = ''): void {
  if (condition) {
    passes += 1
    console.log(`  ok   ${label}`)
  } else {
    failures += 1
    console.log(`  FAIL ${label}${detail ? `\n         ${detail}` : ''}`)
  }
}

function section(title: string): void {
  console.log(`\n${title}`)
}

/* ══════════════ The reference endpoint, in both evidence dialects ══════════ */

/**
 * test.openquantumsafe.org as both pipelines actually measured it on
 * 2026-10-05. Kept as literal observations rather than a recorded scan so the
 * assertions below read as statements about the endpoint, not about a blob.
 */
const OBSERVED = {
  protocols: ['TLSv1.2', 'TLSv1.3'],
  suite: 'TLS_AES_256_GCM_SHA384',
  hybridGroup: 'X25519MLKEM768',
  handshakes: 17,
  certAlgorithm: 'ECDSA P-256',
  certBits: 256,
  certSignature: 'ecdsa-with-SHA384',
  validityDays: 89,
  daysRemaining: 51,
  sctCount: 2,
  hstsMaxAge: 2_592_000, // 30 days — present, not hardened
  headersHardened: 0,
  headersApplicable: 8,
  censusObserved: 13,
  censusScore: 44, // 4 of 9 asymmetric primitives post-quantum
}

/** The shared evidence shape, as the PUBLIC adapter would produce it. */
function publicDialect(): PublishedCategoryEvidence {
  return toPublishedCategoryEvidence({
    tls: {
      tlsVersion: 'TLSv1.3',
      supportedProtocols: OBSERVED.protocols,
      cipherSuite: OBSERVED.suite,
      cipherSuites: [],
      keyExchange: 'ECDHE (TLS 1.3 key_share)',
      negotiatedCurve: null,
      signatureAlgorithm: OBSERVED.certSignature,
    },
    certificate: {
      publicKeyAlgorithm: OBSERVED.certAlgorithm,
      publicKeySize: OBSERVED.certBits,
      signatureAlgorithm: OBSERVED.certSignature,
      isExpired: false,
      isSelfSigned: false,
      chain: [],
    },
    certificateExtras: {
      ocspStapled: false,
      ocspUri: null,
      ocspResponderState: 'not-advertised',
      mustStaple: false,
      signedCertificateTimestamps: true,
      sctCount: OBSERVED.sctCount,
      validityDays: OBSERVED.validityDays,
      daysRemaining: OBSERVED.daysRemaining,
      chainTrusted: true,
    },
    cipherSuites: [],
    keyAgreement: {
      probed: true,
      hybridGroups: [OBSERVED.hybridGroup],
      pureKemGroups: [],
      classicalGroups: ['X25519'],
      primaryGroup: OBSERVED.hybridGroup,
      forwardSecrecy: true,
    },
    dns: {
      resolverAvailable: true,
      caaQueryable: true,
      caaClimbComplete: true,
      caaPresent: false,
      caaRecords: [],
    },
    http: {
      reachable: true,
      headers: Array.from({ length: OBSERVED.headersApplicable }, (_, i) => ({
        name: `header-${i}`,
        present: false,
        secure: false,
        applicable: true,
      })).concat([
        {
          name: 'strict-transport-security',
          present: true,
          secure: false,
          applicable: true,
        } as never,
      ]),
    },
    engines: {
      http: {
        data: {
          hsts: {
            present: true,
            maxAge: OBSERVED.hstsMaxAge,
            includeSubDomains: false,
            preload: false,
            preloadBlockers: [],
          },
        },
      },
    },
  } as never)
}

/** The same endpoint, as the DASHBOARD adapter would produce it. */
function dashboardCategories() {
  return buildPublishedCategories({
    tlsResult: {
      tlsVersion: 'TLSv1.3',
      supportedProtocols: OBSERVED.protocols,
      cipherSuite: OBSERVED.suite,
      cipherSuites: [],
      keyExchange: 'ECDHE (TLS 1.3 key_share)',
      negotiatedCurve: null,
      signatureAlgorithm: OBSERVED.certSignature,
    },
    certInfo: {
      publicKeyAlgorithm: OBSERVED.certAlgorithm,
      publicKeySize: OBSERVED.certBits,
      signatureAlgorithm: OBSERVED.certSignature,
      isExpired: false,
      isSelfSigned: false,
      chain: [],
      validFrom: new Date(Date.now() - (OBSERVED.validityDays - OBSERVED.daysRemaining) * 864e5).toISOString(),
      validTo: new Date(Date.now() + OBSERVED.daysRemaining * 864e5).toISOString(),
    },
    apiResult: null,
    repoResult: null,
    webCryptoResult: null,
    ruleResults: [],
    findings: [],
    edgeIntelligence: {
      transport: {
        negotiatedProtocol: 'TLSv1.3',
        supportedProtocols: OBSERVED.protocols,
        negotiatedCipher: OBSERVED.suite,
        keyExchange: 'ECDHE (TLS 1.3 key_share)',
        forwardSecrecy: true,
        staticRsaAccepted: false,
      },
      certificate: {
        probed: true,
        ocspStapled: false,
        ocspUri: null,
        ocspResponderState: 'not-advertised',
        mustStaple: false,
        sctPresent: true,
        sctCount: OBSERVED.sctCount,
        chainTrusted: true,
        daysRemaining: OBSERVED.daysRemaining,
        validityDays: OBSERVED.validityDays,
      },
      dns: {
        probed: true,
        caaQueryable: true,
        caaClimbComplete: true,
        caaPresent: false,
        caaRecords: [],
        caaAtName: null,
      },
      http: {
        probed: true,
        reachable: true,
        hsts: {
          present: true,
          status: 'present',
          raw: `max-age=${OBSERVED.hstsMaxAge}`,
          maxAge: OBSERVED.hstsMaxAge,
          includeSubDomains: false,
          preload: false,
        },
        hardenedCount: OBSERVED.headersHardened,
        applicableCount: OBSERVED.headersApplicable,
        headers: [],
      },
      pqKeyAgreement: {
        probed: true,
        /* `measuredKeyAgreement` requires a settled PASS before it will publish
           a hybrid verdict — a partial result means the prober saw an accept it
           could not reproduce. Omitting it here is how this fixture first
           scored the reference hybrid endpoint 70/100. */
        state: 'pass',
        hybridGroups: [OBSERVED.hybridGroup],
        pureKemGroups: [],
        refusedHybridGroups: ['SecP256r1MLKEM768'],
        classicalGroups: ['X25519'],
        primaryGroup: OBSERVED.hybridGroup,
        classicalComponent: 'X25519 (Curve25519 ECDHE)',
        postQuantumComponent: 'ML-KEM-768 (FIPS 203)',
        kemParameterSets: ['ML-KEM-768'],
        handshakes: OBSERVED.handshakes,
        confidence: 95,
      },
      quantum: { pqSignatureObserved: false },
    },
  } as never)
}

/* ══════════════════ 1. One scorer — the surfaces agree ═════════════════════ */

section('1. The two adapters publish ONE answer for one endpoint')

const pub = buildPublishedCategorySet(publicDialect())
const dash = dashboardCategories()
const pubByKey = new Map(pub.map((c) => [c.key, c]))
const dashByKey = new Map(dash.map((c) => [c.key, c]))

for (const def of SCORE_CATEGORY_DEFS) {
  const p = pubByKey.get(def.key)
  const d = dashByKey.get(def.key)
  assert(
    Boolean(p) && Boolean(d) && p!.applicable === d!.applicable,
    `${def.key}: both surfaces agree on applicability`,
    `public ${p?.applicable} vs scanner ${d?.applicable}`,
  )
  if (p?.applicable && d?.applicable) {
    assert(
      p.score === d.score,
      `${def.key}: both surfaces score ${p.score}`,
      `public ${p.score} vs scanner ${d.score}`,
    )
  }
}

const pubComposite = weightedCategoryScore(pub)
const dashComposite = weightedCategoryScore(dash)
assert(
  pubComposite === dashComposite,
  `one composite for one host (${pubComposite})`,
  `public ${pubComposite} vs scanner ${dashComposite}`,
)
assert(
  scoreToGrade(pubComposite).grade === scoreToGrade(dashComposite).grade,
  `one grade for one host (${scoreToGrade(pubComposite).grade} · ${scoreToGrade(pubComposite).rating})`,
)

/* ══════════ 2. The six resolved disagreements, pinned both ways ════════════ */

section('2. Each resolved disagreement stays resolved')

const base = publicDialect()
const scoreOf = (e: PublishedCategoryEvidence, key: string) =>
  buildPublishedCategorySet(e).find((c) => c.key === key)!

/* -- TLS 1.2 alongside 1.3 is strong but not maximal ---------------------- */
assert(
  scoreOf(base, 'tls-configuration').score === 90,
  'TLS 1.3 + TLS 1.2 scores 90, not 100 — 100 asserts "TLS 1.3 only"',
  `got ${scoreOf(base, 'tls-configuration').score}`,
)
assert(
  scoreOf(
    { ...base, transport: { ...base.transport, acceptedProtocols: ['TLSv1.3'] } },
    'tls-configuration',
  ).score === 100,
  'and TLS 1.3 alone still earns 100 — the deduction is for 1.2, not a blanket cap',
)
assert(
  scoreOf(
    { ...base, transport: { ...base.transport, acceptedProtocols: ['TLSv1', 'TLSv1.2', 'TLSv1.3'] } },
    'tls-configuration',
  ).score === 45,
  'and a legacy protocol still collapses the category',
)

/* -- Quantum exposure is not charged to the Certificates category --------- */
assert(
  scoreOf(base, 'certificates').score === 100,
  'a valid, trusted, short-lived ECDSA P-256 chain scores 100 — classical is not a certificate defect',
  `got ${scoreOf(base, 'certificates').score}`,
)
assert(
  scoreOf(
    {
      ...base,
      certificate: { ...base.certificate!, publicKeyAlgorithm: 'RSA', publicKeySize: 1024 },
    },
    'certificates',
  ).score < 70,
  'but a 1024-bit RSA key still fails it — key SIZE is this category’s business',
)
assert(
  scoreOf({ ...base, certificate: { ...base.certificate!, isExpired: true } }, 'certificates').score <
    50,
  'and an expired chain still collapses it',
)

/* -- OCSP stapling is inapplicable without an advertised responder -------- */
const ocspAbsent = scoreOf(base, 'ocsp-stapling')
assert(
  !ocspAbsent.applicable,
  'no advertised OCSP responder ⇒ NOT APPLICABLE, weight redistributed',
  `got applicable=${ocspAbsent.applicable} score=${ocspAbsent.score}`,
)
assert(
  /advertises no OCSP responder/.test(ocspAbsent.observed),
  'and the exclusion carries its reason, so the UI never has to guess',
)
assert(
  scoreOf(
    { ...base, revocation: { ...base.revocation!, advertisesResponder: true } },
    'ocsp-stapling',
  ).applicable,
  'but a certificate that DOES advertise a responder and does not staple is scored',
)
assert(
  scoreOf(
    {
      ...base,
      revocation: { ...base.revocation!, advertisesResponder: true, mustStaple: true },
    },
    'ocsp-stapling',
  ).score === 0,
  'and a must-staple certificate that does not staple is still a hard zero',
)

/* -- The post-quantum share is taken over migration candidates only ------- */
assert(
  scoreOf(base, 'cryptographic-algorithms').score === censusFor(base).score,
  'the algorithm census decides this category — not a partial-credit sweep over every observed primitive',
  `category ${scoreOf(base, 'cryptographic-algorithms').score} vs census ${censusFor(base).score}`,
)
assert(
  /asymmetric/.test(scoreOf(base, 'cryptographic-algorithms').observed),
  'and it states the population the share was taken over',
  scoreOf(base, 'cryptographic-algorithms').observed,
)
assert(
  !scoreOf(
    {
      ...base,
      /* A handshake that produced only symmetric and protocol material: observed,
         but with no asymmetric primitive the post-quantum share is not defined. */
      algorithmSources: { tls: { cipherSuites: [{ encryption: 'AES-256-GCM' }] }, certificate: null, patterns: [] },
      certificate: null,
      keyAgreement: { ...base.keyAgreement, probed: false, hybrid: false, pureKem: false, group: null },
    },
    'cryptographic-algorithms',
  ).applicable,
  'and a population with no asymmetric primitive is excluded, not scored 0',
)

/* -- "Hardened HSTS" means one thing on this page ------------------------- */
const weakHsts = scoreOf(base, 'hsts')
assert(
  weakHsts.score === 55,
  'a 30-day HSTS policy scores 55 — graduated, not collapsed to one "weak" value',
  `got ${weakHsts.score}`,
)
assert(
  scoreOf(base, 'post-quantum-readiness').score === 78,
  'and it earns NO crypto-agility allowance: readiness is 78, not 81',
  `got ${scoreOf(base, 'post-quantum-readiness').score}`,
)
assert(
  scoreOf(
    {
      ...base,
      hsts: { ...base.hsts!, maxAgeSeconds: 31_536_000, includeSubDomains: true },
    },
    'post-quantum-readiness',
  ).score === 81,
  'while a full-year policy covering subdomains does earn it — the allowance is real, not disabled',
)

/* ══════════════ 3. Unmeasured is neither zero nor a pass ═══════════════════ */

section('3. Unmeasured renders as unmeasured, in every category that can be')

const unmeasured: Array<[string, PublishedCategoryEvidence]> = [
  ['tls-configuration', { ...base, transport: { ...base.transport, acceptedProtocols: null } }],
  ['forward-secrecy', { ...base, transport: { ...base.transport, forwardSecrecy: { measured: false, value: null } } }],
  ['certificates', { ...base, certificate: null }],
  ['ocsp-stapling', { ...base, revocation: null }],
  ['certificate-transparency', { ...base, transparency: null }],
  ['dns-caa', { ...base, caa: null }],
  ['dns-caa', { ...base, caa: { ...base.caa!, climbComplete: false } }],
  ['http-security-headers', { ...base, headers: { hardened: null, applicable: null } }],
  ['hsts', { ...base, hsts: null }],
  [
    'cryptographic-algorithms',
    {
      ...base,
      algorithmSources: { tls: null, certificate: null, patterns: [] },
      certificate: null,
      keyAgreement: { ...base.keyAgreement, probed: false, hybrid: false, pureKem: false, group: null },
    },
  ],
  [
    'post-quantum-readiness',
    {
      ...base,
      keyAgreement: { ...base.keyAgreement, hybrid: false, pureKem: false, hybridSettled: false },
    },
  ],
]

for (const [key, evidence] of unmeasured) {
  const row = scoreOf(evidence, key)
  assert(!row.applicable, `${key}: unmeasured ⇒ inapplicable`, `score=${row.score}`)
  assert(
    row.observed.length > 20 && row.observed !== 'not observed',
    `${key}: and the exclusion states WHY`,
    row.observed,
  )
}

/* -- A measured absence is still a measured zero -------------------------- */
assert(
  scoreOf(base, 'dns-caa').applicable && scoreOf(base, 'dns-caa').score === 0,
  'a COMPLETED CAA climb that found nothing is a measured 0, not an exclusion',
)
assert(
  scoreOf(base, 'http-security-headers').applicable &&
    scoreOf(base, 'http-security-headers').score === 0,
  'and 0 of 8 headers hardened is a measured 0 too',
)

/* ═════════════ 4. The node rings partition one model ══════════════════════ */

section('4. The hero rings partition the published model, once each')

for (const [ring, name] of [
  [NODE_SCORE_CATEGORIES as Record<string, readonly string[]>, '/public-scan'],
  [SCANNER_NODE_CATEGORIES, '/dashboard/scanner'],
] as const) {
  const claimed = Object.values(ring).flat()
  const unique = new Set(claimed)
  assert(claimed.length === unique.size, `${name}: no category is claimed by two cards`)
  const missing = SCORE_CATEGORY_DEFS.filter((def) => !unique.has(def.key)).map((def) => def.key)
  assert(missing.length === 0, `${name}: every published category reaches a card`, missing.join(', '))
}

/* -- The cards both pages share describe the same categories -------------- */
const SHARED_CARDS: Array<[string, string, string]> = [
  ['dns', 'discovery', 'DNS / Asset Discovery'],
  ['tls', 'transport', 'TLS / Transport'],
  ['headers', 'code', 'Headers / Code & Dependencies'],
]
for (const [publicNode, scannerNode, label] of SHARED_CARDS) {
  const a = [...(NODE_SCORE_CATEGORIES as Record<string, readonly string[]>)[publicNode]].sort()
  const b = [...SCANNER_NODE_CATEGORIES[scannerNode]].sort()
  assert(
    JSON.stringify(a) === JSON.stringify(b),
    `${label}: same categories on both pages`,
    `${a.join('+')} vs ${b.join('+')}`,
  )
}

/* The quantum card is the one that must include the hybrid key agreement, or it
   cannot report a hybrid deployment at all — the defect that published
   "Quantum Posture · At Risk 67" for the reference post-quantum endpoint. */
assert(
  (NODE_SCORE_CATEGORIES as Record<string, readonly string[]>).quantum.includes('key-exchange') &&
    SCANNER_NODE_CATEGORIES.posture.includes('key-exchange'),
  'the quantum card carries key-exchange on BOTH pages',
)
assert(
  !SCANNER_NODE_CATEGORIES.transport.includes('key-exchange'),
  'and Transport no longer banks the score its key agreement earned',
)

/* Certificates: the scanner folds OCSP into its certificate card because it has
   no separate OCSP surface. That is legitimate — but only while OCSP is scored
   identically on both, which section 1 asserts. */
const pubCert = [...(NODE_SCORE_CATEGORIES as Record<string, readonly string[]>).certificate].sort()
const dashCert = [...SCANNER_NODE_CATEGORIES.certificates].sort()
assert(
  dashCert.filter((key) => key !== 'ocsp-stapling').join() === pubCert.join(),
  'Certificates differs between the rings ONLY by the OCSP card /public-scan renders separately',
  `${pubCert.join('+')} vs ${dashCert.join('+')}`,
)

/* ══════════════════════════ Projected card scores ═════════════════════════ */

section('5. The hero cards both pages share land on the same number')

function project(ring: Record<string, readonly string[]>, node: string, cats: typeof pub) {
  const byKey = new Map(cats.map((c) => [c.key, c]))
  let weighted = 0
  let weight = 0
  for (const key of ring[node] ?? []) {
    const c = byKey.get(key)
    if (!c?.applicable) continue
    weighted += c.score * c.weight
    weight += c.weight
  }
  return weight ? Math.round(weighted / weight) : null
}

const PAIRS: Array<[string, string, string]> = [
  ['dns', 'discovery', 'DNS / Asset Discovery'],
  ['tls', 'transport', 'TLS / Transport'],
  ['certificate', 'certificates', 'Certificates'],
  ['headers', 'code', 'Headers / Code'],
  ['quantum', 'posture', 'Quantum'],
]
for (const [publicNode, scannerNode, label] of PAIRS) {
  const a = project(NODE_SCORE_CATEGORIES as Record<string, readonly string[]>, publicNode, pub)
  const b = project(SCANNER_NODE_CATEGORIES, scannerNode, dash)
  const rating = a === null ? 'not measured' : scoreToGrade(a).rating
  assert(a === b, `${label}: ${a} · ${rating} on both pages`, `public ${a} vs scanner ${b}`)
}

/* The reference post-quantum endpoint must not read as a quantum risk. */
const quantumCard = project(SCANNER_NODE_CATEGORIES, 'posture', dash)!
assert(
  quantumCard >= 80,
  `a live X25519MLKEM768 endpoint reads ${quantumCard} · ${scoreToGrade(quantumCard).rating} on the quantum card`,
  `got ${quantumCard}`,
)

/* ════════════════════════════════ Result ══════════════════════════════════ */

console.log(`\n${passes} passed, ${failures} failed`)
if (failures > 0) process.exit(1)
