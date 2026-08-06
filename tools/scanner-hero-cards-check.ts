/**
 * Offline verification for the Scanner hero cards.
 *
 * Covers the two contracts the hero cards broke:
 *
 *   1. STATE CONSISTENCY — a node card's label, accent colour and badge are
 *      three views of ONE resolved state. There is no reachable node for which
 *      `resolveNodeVerdict` returns a reassuring word in an alarming colour (or
 *      the reverse). This is asserted exhaustively over the whole node state
 *      space, not on a handful of examples, because the bug it replaces was
 *      produced by a combination nobody thought to try.
 *
 *   2. POST-QUANTUM HONESTY — when the edge engine has MEASURED hybrid ML-KEM
 *      key agreement, the rules that describe classical key exchange and
 *      harvest-now exposure must not fire, and when it has measured its
 *      absence they must. Both directions are asserted: a suppression that
 *      fires unconditionally would pass a one-sided test while silencing real
 *      exposure.
 *
 * No server, no Supabase, no network.
 *
 *   npx tsx tools/scanner-hero-cards-check.ts
 */
import {
  bandForScore,
  contrastRatio,
  hexToRgb,
  readableOnDark,
  resolveNodeVerdict,
  QVE_COLOR,
  type QveNode,
  type QveNodeState,
  type ScanEventSeverity,
} from '../src/app/public-scan/_qve/types'
import { RISK_COLOR, SCORE_GRADE_TABLE, scoreToGrade } from '../src/lib/scanner/public-scan/grading-model'
import type { RiskBand } from '../src/lib/scanner/public-scan/types'
import { evaluateDetectionRules } from '../src/lib/scanner/web-scanner/detection-rules'
import type { DetectionContext } from '../src/lib/scanner/web-scanner/types'

let failures = 0
function assert(condition: boolean, label: string) {
  if (condition) {
    console.log(`  ok   ${label}`)
  } else {
    failures += 1
    console.log(`  FAIL ${label}`)
  }
}

/* ══════════════════════════════ 1. state consistency ═══════════════════════ */

const NODE_STATES: QveNodeState[] = ['idle', 'scanning', 'unmeasured', 'pass', 'warning', 'critical', 'failed']
const SEVERITIES: ScanEventSeverity[] = ['none', 'info', 'low', 'medium', 'high', 'critical']
const SCORES: Array<number | null> = [null, 0, 12, 25, 49, 55, 62, 78, 88, 97, 100]

/**
 * Risk band implied by a colour, DERIVED from the published tables rather than
 * hand-listed. A hard-coded hex set silently stops testing the thing it is for
 * the moment the palette moves — which is exactly how the cards came to paint a
 * grade-F surface amber while this file still reported green.
 */
const RISK_OF_COLOR = new Map<string, RiskBand>()
const noteColor = (color: string, band: RiskBand) => {
  // Both the published hex and the hero's legibility-raised version of it, or
  // the sweep below would recognise none of the colours the cards actually
  // render and would silently pass by testing nothing.
  if (!RISK_OF_COLOR.has(color)) RISK_OF_COLOR.set(color, band)
  const onDark = readableOnDark(color)
  if (!RISK_OF_COLOR.has(onDark)) RISK_OF_COLOR.set(onDark, band)
}
for (const row of SCORE_GRADE_TABLE) noteColor(row.color, row.riskLevel)
for (const [band, color] of Object.entries(RISK_COLOR)) noteColor(color, band as RiskBand)

const isReassuringColor = (color: string) => {
  const risk = RISK_OF_COLOR.get(color)
  return risk === 'Very Low' || risk === 'Low' || color === QVE_COLOR.pass
}
const isAlarmingColor = (color: string) => {
  const risk = RISK_OF_COLOR.get(color)
  return risk === 'High' || risk === 'Critical' || color === QVE_COLOR.critical
}

/** Words that promise the operator nothing is wrong. */
const REASSURING_LABELS = new Set(['Secure', 'Elite', 'Excellent', 'Good'])
/** Words that demand attention. */
const ALARMING_LABELS = new Set(['Critical', 'At Risk', 'Failed', 'Weak'])
/* "Fair" and "Review" are deliberately in NEITHER set: the published model puts
   them at Moderate/Elevated risk, which is neither a promise nor an alarm, and
   forcing them into one made the test assert a claim the grading table does not. */

function makeNode(state: QveNodeState, severity: ScanEventSeverity, score: number | null, hasEvidence: boolean): QveNode {
  return {
    key: 'transport',
    title: 'Transport & Ciphers',
    state,
    // The free-text phrase is deliberately hostile: the old code rendered THIS
    // in the accent colour, which is how "Secure" ended up painted red.
    verdict: 'Secure',
    lines: ['TLS protocol scanner: 1 finding'],
    progress: 100,
    severity,
    updatedAt: Date.now(),
    postQuantum: false,
    hasEvidence,
    score,
    // Derived from the module under test rather than a second copy of the
    // thresholds — a duplicated ladder here would let the two drift apart and
    // still report green.
    band: score === null ? null : bandForScore(score),
  }
}

console.log('\n=== 1. Hero card state consistency (exhaustive) ===')

let combinations = 0
let contradictions: string[] = []
let labelSet = new Set<string>()

for (const state of NODE_STATES) {
  for (const severity of SEVERITIES) {
    for (const score of SCORES) {
      for (const hasEvidence of [true, false]) {
        combinations += 1
        const node = makeNode(state, severity, score, hasEvidence)
        const verdict = resolveNodeVerdict(node)
        labelSet.add(verdict.label)

        const reassuringWord = REASSURING_LABELS.has(verdict.label)
        const alarmingWord = ALARMING_LABELS.has(verdict.label)
        const reassuringColor = isReassuringColor(verdict.color)
        const alarmingColor = isAlarmingColor(verdict.color)

        if (reassuringWord && alarmingColor) {
          contradictions.push(`"${verdict.label}" in alarming ${verdict.color} (state=${state} sev=${severity} score=${score} evidence=${hasEvidence})`)
        }
        if (alarmingWord && reassuringColor) {
          contradictions.push(`"${verdict.label}" in reassuring ${verdict.color} (state=${state} sev=${severity} score=${score} evidence=${hasEvidence})`)
        }
        if (!verdict.basis || verdict.basis.length < 10) {
          contradictions.push(`no basis for state=${state} sev=${severity}`)
        }
      }
    }
  }
}

assert(combinations === 924, `exhaustive sweep covered every node state (${combinations} combinations)`)
assert(contradictions.length === 0, `no label/colour contradiction in any combination${contradictions.length ? ` — ${contradictions.slice(0, 3).join(' | ')}` : ''}`)

/* The specific shape that was reported: a clean-looking free-text verdict on a
   surface whose accumulated evidence is critical. */
const reportedBug = resolveNodeVerdict(makeNode('pass', 'critical', 12, true))
assert(reportedBug.label === 'Critical', `a surface with CRITICAL evidence is labelled "Critical", not its last module's word (got "${reportedBug.label}")`)
assert(isAlarmingColor(reportedBug.color), 'and is coloured critical')
assert(reportedBug.alert === true, 'and carries alert chrome')

/* HIGH must be distinguishable from CRITICAL — "At Risk" is a different verdict
   and the guidelines require a distinct state.
   Asserted on a surface whose SCORE is strong, because that is where severity is
   the only differentiator. On a surface already measured at grade F the two
   correctly converge: both are Critical, and the published model is what says
   so — see the score-alignment block below. */
const high = resolveNodeVerdict(makeNode('pass', 'high', 92, true))
const critical = resolveNodeVerdict(makeNode('pass', 'critical', 92, true))
assert(high.label === 'At Risk', `HIGH evidence reads "At Risk" (got "${high.label}")`)
assert(isAlarmingColor(high.color), 'At Risk uses an alarming tone')
// Compared against the resolver's own output for a CRITICAL node rather than
// against the colour constant, so this stays a runtime check instead of a
// comparison TypeScript can discharge from the literal types.
assert(high.color !== critical.color, 'At Risk is visually distinct from Critical')
assert(high.label !== critical.label, 'and verbally distinct from Critical')

/* "Measured nothing" must never be painted as a pass. */
const unmeasured = resolveNodeVerdict(makeNode('pass', 'none', null, false))
assert(unmeasured.label === 'Not measured', `a settled surface with no evidence reads "Not measured" (got "${unmeasured.label}")`)
assert(!isReassuringColor(unmeasured.color), 'and is NOT painted the same green as a measured pass')

/* A genuinely clean surface still reads clean. */
const clean = resolveNodeVerdict(makeNode('pass', 'low', 97, true))
assert(!isAlarmingColor(clean.color), `a clean measured surface is not alarmed (label="${clean.label}")`)
assert(REASSURING_LABELS.has(clean.label), 'and carries a reassuring word')

/* Lifecycle states outrank evidence. */
assert(resolveNodeVerdict(makeNode('scanning', 'critical', null, false)).label === 'Scanning', 'a running surface reads Scanning')
assert(resolveNodeVerdict(makeNode('failed', 'none', null, true)).label === 'Failed', 'a failed module reads Failed')
assert(resolveNodeVerdict(makeNode('idle', 'none', null, false)).color === QVE_COLOR.idle, 'an idle surface is idle-coloured')

/* A module that declined to measure the surface settles it as Not applicable —
   it must NOT leave the card spinning on a scan that has finished, and must
   not be painted as a pass. */
const declined = resolveNodeVerdict(makeNode('unmeasured', 'info', null, true))
assert(declined.label === 'Not applicable', `a declined surface reads "Not applicable" (got "${declined.label}")`)
assert(declined.label !== 'Scanning', 'and never keeps a spinner after the scan settles')
assert(!isReassuringColor(declined.color), 'and is not painted as a pass')

/* ── The card must agree with "How the Grading Works" ──────────────────────
   This block replaces an earlier contract that capped a degraded aggregate at an
   amber "Review". That rule was written to stop a mean over duplicated findings
   from manufacturing alarm, but it also meant a surface MEASURED at 8/100 —
   grade F, Critical, dark red in the published table — rendered as an amber
   Review card with an amber beam. A published model the product ships a
   reference sheet for cannot be contradicted by the cards beside it.

   The replacement contract: a scored surface carries the published RATING for
   its score and that grade's own COLOUR, and severity may only ESCALATE it. */
const SCORE_ALIGNMENT_SAMPLES = [0, 12, 25, 49, 55, 62, 68, 72, 78, 82, 88, 92, 96, 99]
const misaligned = SCORE_ALIGNMENT_SAMPLES.filter((score) => {
  const verdict = resolveNodeVerdict(makeNode('pass', 'low', score, true))
  const grade = scoreToGrade(score)
  // `readableOnDark` raises the published colour's luminance for the dark hero
  // and touches nothing else, so the card colour must be exactly that transform
  // of the grade's own colour — never an independently chosen one.
  return verdict.label !== grade.rating || verdict.color !== readableOnDark(grade.color)
})
assert(
  misaligned.length === 0,
  `a scored surface carries its published rating and grade colour${misaligned.length ? ` — mismatched at ${misaligned.join(', ')}` : ''}`,
)

/* The specific regression the user reported. */
const gradeF = resolveNodeVerdict(makeNode('pass', 'medium', 8, true))
assert(gradeF.label === 'Critical', `a surface measured at 8/100 reads "Critical", not "Review" (got "${gradeF.label}")`)
assert(isAlarmingColor(gradeF.color), 'and is painted an alarming colour, not amber')
assert(gradeF.color === readableOnDark(scoreToGrade(8).color), 'and that colour is the published grade-F colour, made legible on the hero')
assert(
  contrastRatio(hexToRgb(gradeF.color), [7, 13, 27]) >= 4.5,
  'and the verdict label clears the 4.5:1 contrast floor on the card',
)

/* Severity may only ever escalate a scored verdict — never soften it. A card
   that reads calmer than EITHER its own score or its worst finding is the whole
   class of bug this file exists to catch. */
/* Ranked on the RATING ladder rather than via the colour, because two grades can
   legitimately share a colour (C and C- are both #f97316 at different risk
   levels) — a colour→risk lookup is lossy and would report a false failure. */
const SEVERITY_RANK: Record<string, number> = { Elite: 0, Excellent: 1, Good: 2, Fair: 3, Review: 3, Weak: 4, 'At Risk': 4, Critical: 5 }
const softened: string[] = []
for (const score of SCORE_ALIGNMENT_SAMPLES) {
  const scoreRating = scoreToGrade(score).rating
  for (const severity of ['none', 'low', 'medium', 'high', 'critical'] as ScanEventSeverity[]) {
    const verdict = resolveNodeVerdict(makeNode('pass', severity, score, true))
    const shown = SEVERITY_RANK[verdict.label]
    if (shown !== undefined && shown < SEVERITY_RANK[scoreRating]) {
      softened.push(`score ${score} (${scoreRating}) shown as "${verdict.label}" with severity ${severity}`)
    }
  }
}
assert(softened.length === 0, `severity never softens a scored verdict${softened.length ? ` — ${softened.slice(0, 3).join(' | ')}` : ''}`)

/* ═══════════════════════ 2. post-quantum honesty ═══════════════════════════ */

console.log('\n=== 2. Measured hybrid ML-KEM is honoured ===')

/** Edge intelligence shaped exactly like `collectEdgeIntelligence` returns. */
function edgeWith(pq: { hybrid: string[]; pure: string[]; state: 'pass' | 'fail' }) {
  return {
    host: 'www.example.com',
    port: 443,
    probedAt: new Date().toISOString(),
    durationMs: 900,
    confidence: 90,
    notes: [],
    pqKeyAgreement: {
      label: 'Post-quantum key agreement',
      value: pq.state === 'pass' ? 'Applied' : 'Not offered',
      state: pq.state,
      detail: 'probe detail',
      evidence: [],
      hybridGroups: pq.hybrid,
      pureKemGroups: pq.pure,
      classicalGroups: ['X25519'],
      primaryGroup: pq.hybrid[0] ?? pq.pure[0] ?? null,
      kemParameterSets: pq.hybrid.length || pq.pure.length ? ['ML-KEM-768'] : [],
      classicalComponent: 'X25519 (Curve25519 ECDHE)',
      postQuantumComponent: pq.hybrid.length || pq.pure.length ? 'ML-KEM-768 (FIPS 203)' : null,
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
      keyExchange: 'ECDHE (TLS 1.3 key_share)',
      forwardSecrecy: true,
      forwardSecrecyBasis: 'TLS 1.3 mandates ephemeral key agreement',
      staticRsaAccepted: false,
      alpn: 'h2',
      alpnOffered: ['h2', 'http/1.1'],
      alpnProbed: true,
      sessionTickets: true,
      sessionReuse: true,
      handshakeMs: 101,
      error: null,
    },
    quantum: {
      hybridObserved: pq.state === 'pass' && pq.hybrid.length > 0,
      pqSignatureObserved: false,
      keyExchange: 'ECDHE',
      keyExchangeClass: 'classical',
      forwardSecrecy: 'Yes',
      kemParameterSets: [],
      postQuantumReadiness: pq.state === 'pass' ? 72 : 18,
      readinessReasons: [],
      quantumRisk: (pq.state === 'pass' ? 'Medium' : 'High') as 'Medium' | 'High',
      quantumRiskScore: 40,
      riskFactors: [],
      vulnerability: 'Signature-only' as never,
      vulnerabilityReason: 'reason',
      migrationTargets: [],
    },
  } as unknown as NonNullable<DetectionContext['edgeIntelligence']>
}

/** The TLS shape the rules read — the generic TLS 1.3 label Node produces. */
const TLS_13 = {
  tlsVersion: 'TLSv1.3',
  cipherSuite: 'TLS_AES_256_GCM_SHA384',
  keyExchange: 'ECDHE (TLS 1.3 key_share)',
  signatureAlgorithm: 'ecdsa-with-SHA256',
  supportedProtocols: ['TLSv1.2', 'TLSv1.3'],
  protocolSupport: [],
  negotiatedCurve: null,
  cipherSuites: [],
  ephemeralKeyType: 'ECDHE',
  ephemeralKeySize: null,
  forwardSecrecy: true,
  peerCertificate: null,
} as unknown as NonNullable<DetectionContext['tlsResult']>

const CERT = {
  publicKeyAlgorithm: 'ECDSA P-256',
  publicKeySize: 256,
  signatureAlgorithm: 'ecdsa-with-SHA256',
  validFrom: new Date(Date.now() - 30 * 86400000).toISOString(),
  validTo: new Date(Date.now() + 73 * 86400000).toISOString(),
  isExpired: false,
  isSelfSigned: false,
  subject: { CN: 'www.example.com' },
  issuer: { CN: 'WE1' },
  chain: [],
} as unknown as NonNullable<DetectionContext['certInfo']>

function contextFor(edge: NonNullable<DetectionContext['edgeIntelligence']> | null): DetectionContext {
  return {
    tlsResult: TLS_13,
    certInfo: CERT,
    findings: [],
    repoResult: null,
    webCryptoResult: null,
    apiResult: null,
    cipherSuites: [],
    edgeIntelligence: edge,
  } as unknown as DetectionContext
}

const hybridRules = evaluateDetectionRules(contextFor(edgeWith({ hybrid: ['X25519MLKEM768'], pure: [], state: 'pass' })))
const hybridIds = new Set(hybridRules.map((rule) => rule.ruleId))

assert(!hybridIds.has('TLS-003'), 'TLS-003 does NOT fire when hybrid ML-KEM key agreement is measured')
assert(!hybridIds.has('HNDL-001'), 'HNDL-001 does NOT report harvest-now exposure when the key agreement is hybrid')
assert(!hybridIds.has('HNDL-003'), 'HNDL-003 does NOT claim "no hybrid crypto" when hybrid crypto was measured')

/* NEGATIVE CONTROL — the same rules must still fire on a classical endpoint.
   Without this, a suppression bug that silenced them unconditionally would
   pass the assertions above. */
console.log('\n=== 3. Negative control: classical endpoint still reported ===')

const classicalRules = evaluateDetectionRules(contextFor(edgeWith({ hybrid: [], pure: [], state: 'fail' })))
const classicalIds = new Set(classicalRules.map((rule) => rule.ruleId))

assert(classicalIds.has('TLS-003'), 'TLS-003 DOES fire when no hybrid group was accepted')
assert(classicalIds.has('HNDL-001'), 'HNDL-001 DOES report harvest-now exposure on a classical-only key agreement')

/* A scan with no edge measurement at all must behave like the classical case —
   absence of evidence is not evidence of post-quantum readiness. */
const unprobedRules = evaluateDetectionRules(contextFor(null))
const unprobedIds = new Set(unprobedRules.map((rule) => rule.ruleId))
assert(unprobedIds.has('TLS-003'), 'an UNPROBED endpoint is not credited with post-quantum key agreement (TLS-003 fires)')
assert(unprobedIds.has('HNDL-001'), 'an UNPROBED endpoint is not credited with harvest-now protection (HNDL-001 fires)')

/* Certificate exposure is a separate surface and must survive either way: a
   hybrid key agreement does nothing for a classical certificate. */
assert(hybridIds.has('CERT-003'), 'ECDSA certificate exposure is STILL reported on a hybrid-protected endpoint')

console.log(
  `\n${failures === 0 ? 'PASS' : 'FAIL'} — ${failures} failure(s). ` +
  `${combinations} node-state combinations, labels observed: ${[...labelSet].sort().join(', ')}\n`,
)
process.exit(failures === 0 ? 0 : 1)
