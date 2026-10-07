/**
 * Offline verification for the three contracts a www.cloudflare.com scan broke.
 *
 * Reported symptom: an endpoint with a live hybrid ML-KEM key agreement, a
 * valid 3-certificate chain and an 11-record CAA policy rendered
 *
 *   ASSET DISCOVERY       Critical  0     (scope: DNS CAA)
 *   TRANSPORT & CIPHERS   Critical  74
 *   CERTIFICATES & KEYS   At Risk   73
 *   CODE & DEPENDENCIES   Fair      73
 *   POST-QUANTUM READINESS  81%  "Controls largely in place"
 *   POST-QUANTUM POSTURE    51   "Migration outstanding"
 *
 * Three independent contracts, each asserted in both directions — a suppression
 * that fires unconditionally passes a one-sided test while silencing real
 * exposure, which is how the static-RSA reading nearly got "fixed" away.
 *
 *   1. CAA IS A TREE WALK, AND AN INCOMPLETE WALK IS NOT A NEGATIVE.
 *      RFC 8659 resolves issuance policy at the name and then up to the
 *      registrable domain. `www.cloudflare.com` holds no CAA RRset; the policy
 *      that governs it lives on `cloudflare.com`. Abandoning the climb on a
 *      time budget and publishing "no CAA records" is a fabricated measurement,
 *      and `dns-caa` is the ONLY category behind the Asset Discovery surface,
 *      so that one fabrication painted the whole surface Critical 0.
 *
 *   2. THE WORD AND THE NUMBER ON A NODE CARD ARE TWO STATEMENTS.
 *      The label is the worst finding severity; the number is the measured
 *      posture projected from the published categories. Painting the number in
 *      the label's colour asserts they are one statement — which is how 74
 *      (grade C, Fair, moderate risk) came to be printed in critical red beside
 *      the word "Critical", and how 73 read "At Risk" on one card and "Fair" on
 *      the card beside it.
 *
 *   3. TWO POST-QUANTUM NUMBERS, TWO VOCABULARIES.
 *      The Executive Summary publishes the Post-Quantum Readiness CATEGORY; the
 *      Encryption Score publishes the post-quantum WEIGHT SLICE of the composite
 *      (Cryptographic Algorithms + Post-Quantum Readiness). Both are correct and
 *      they are not the same measurement — so they must not share one caption
 *      ladder, or the page states "Controls largely in place" and "Migration
 *      outstanding" about post-quantum cryptography at the same time.
 *
 * No server, no Supabase, no network.
 *
 *   npx tsx tools/scanner-result-alignment-check.ts
 */
import {
  resolveCaaClimb,
  type CaaClimbAnswer,
} from '../src/lib/scanner/public-scan/engines/dns-engine'
import { dnsCaaCategory } from '../src/lib/scanner/web-scanner/published-scoring'
import {
  nodePostureTone,
  resolveNodeVerdict,
  type QveNode,
  type QveNodeState,
  type ScanEventSeverity,
} from '../src/app/public-scan/_qve/types'
import { scoreToGrade } from '../src/lib/scanner/public-scan/grading-model'
import {
  postQuantumReadinessCaption,
  postQuantumPostureCaption,
} from '../src/app/dashboard/scanner_dashboard/_intel'
import type { EdgeDnsSurface } from '../src/lib/scanner/web-scanner/edge-intelligence-model'

let failures = 0
function assert(condition: boolean, label: string) {
  if (condition) {
    console.log(`  ok   ${label}`)
  } else {
    failures += 1
    console.log(`  FAIL ${label}`)
  }
}

const record = (value: string) => ({ flags: 0, tag: 'issue', value, raw: `0 issue "${value}"` })

/* ══════════════════════ 1. CAA climb completeness ══════════════════════════ */

console.log('\n1. CAA is resolved up the tree, and an abandoned climb is unmeasured')

{
  /* The live failure, exactly: the leaf name answered NODATA and the budget ran
     out before the registrable domain was asked. The apex holds the policy. */
  const abandoned = resolveCaaClimb([
    { name: 'www.cloudflare.com', answered: true, records: [], source: 'Cloudflare (DoH)' },
  ], 'cloudflare.com')
  assert(abandoned.queryable, 'a leaf NODATA answer is still an answer (queryable)')
  assert(!abandoned.climbComplete, 'climb that never reached the registrable domain is incomplete')
  assert(!abandoned.present, 'no records were found')

  const reached = resolveCaaClimb([
    { name: 'www.cloudflare.com', answered: true, records: [], source: 'Cloudflare (DoH)' },
    { name: 'cloudflare.com', answered: true, records: [record('pki.goog')], source: 'Cloudflare (DoH)' },
  ], 'cloudflare.com')
  assert(reached.climbComplete, 'climb that reached the registrable domain is complete')
  assert(reached.present, 'the apex policy governs the leaf name')
  assert(reached.atName === 'cloudflare.com', 'the policy is attributed to the name that holds it')

  /* A genuine absence must still be reportable, or the fix silences real
     exposure — the negative control for contract 1. */
  const genuinelyAbsent = resolveCaaClimb([
    { name: 'www.example.com', answered: true, records: [], source: 'system resolver' },
    { name: 'example.com', answered: true, records: [], source: 'system resolver' },
  ], 'example.com')
  assert(genuinelyAbsent.climbComplete, 'an apex that authoritatively answers NODATA completes the climb')
  assert(!genuinelyAbsent.present, 'a completed climb with no RRset anywhere IS a measured absence')

  /* Closest name wins (RFC 8659 §3): a leaf RRset overrides the apex. */
  const leafOverrides = resolveCaaClimb([
    { name: 'www.example.com', answered: true, records: [record('letsencrypt.org')], source: 'system resolver' },
    { name: 'example.com', answered: true, records: [record('digicert.com')], source: 'system resolver' },
  ], 'example.com')
  assert(leafOverrides.atName === 'www.example.com', 'the closest name with an RRset wins')
  assert(
    leafOverrides.records.map((r) => r.value).join() === 'letsencrypt.org',
    'the leaf RRset is published, not the apex one',
  )

  const nothingAnswered = resolveCaaClimb([
    { name: 'www.example.com', answered: false, records: [], source: null },
    { name: 'example.com', answered: false, records: [], source: null },
  ], 'example.com')
  assert(!nothingAnswered.queryable, 'no transport answered — not queryable')
  assert(!nothingAnswered.climbComplete, 'no transport answered — climb incomplete')

  /* An apex target has nothing above it, so one answer completes the climb. */
  const apexTarget = resolveCaaClimb([
    { name: 'example.com', answered: true, records: [], source: 'system resolver' },
  ], 'example.com')
  assert(apexTarget.climbComplete, 'a target that IS the registrable domain completes in one query')
}

console.log('\n   …and the published category refuses to score an incomplete climb')

{
  const dns = (over: Partial<EdgeDnsSurface>): EdgeDnsSurface => ({
    probed: true,
    addresses: ['104.16.123.96'],
    addressCount: 1,
    caaQueryable: true,
    caaPresent: false,
    caaClimbComplete: true,
    caaRecords: [],
    caaSource: 'Cloudflare (DoH)',
    caaAtName: 'cloudflare.com',
    dnssecQueryable: true,
    dnssecSigned: true,
    dnssecValidated: true,
    spf: null,
    dmarc: null,
    transports: ['DoH'],
    resolvedVia: 'A (DoH)',
    error: null,
    ...over,
  })

  assert(
    dnsCaaCategory(dns({ caaClimbComplete: false, caaAtName: 'www.cloudflare.com' })) === null,
    'an abandoned climb is EXCLUDED from the model, not scored 0',
  )
  assert(
    dnsCaaCategory(dns({ caaClimbComplete: true }))?.score === 0,
    'a completed climb with no RRset scores 0 (the negative control)',
  )
  assert(
    dnsCaaCategory(dns({ caaPresent: true, caaRecords: ['0 issue "pki.goog"'] }))?.score === 100,
    'a published policy scores 100',
  )
  assert(dnsCaaCategory(dns({ caaQueryable: false })) === null, 'an unqueryable name is excluded')
  assert(dnsCaaCategory(null) === null, 'no edge evidence is excluded')
}

/* ══════════════ 2. the word and the number are two statements ══════════════ */

console.log('\n2. A node card paints its posture number in that number\'s own grade colour')

{
  const node = (over: Partial<QveNode>): QveNode =>
    ({
      key: 'transport',
      title: 'Transport & Ciphers',
      state: 'critical' as QveNodeState,
      severity: 'critical' as ScanEventSeverity,
      score: 74,
      scoreScope: 'TLS configuration + cipher suites',
      verdict: 'Legacy exposed',
      hasEvidence: true,
      lines: ['TLS protocol scanner: 2 findings'],
      progress: 100,
      updatedAt: 1,
      unmeasuredReason: null,
      ...over,
    }) as QveNode

  const SEVERITIES: ScanEventSeverity[] = ['none', 'info', 'low', 'medium', 'high', 'critical']
  const SCORES = [0, 12, 35, 51, 60, 65, 70, 73, 74, 80, 88, 97, 100]

  let swept = 0
  let divergent = 0
  for (const severity of SEVERITIES) {
    for (const score of SCORES) {
      const n = node({ severity, score, state: 'pass' })
      const tone = nodePostureTone(n)
      const expected = scoreToGrade(score).rating
      /* The number's colour is the published colour for ITS OWN grade, on every
         reachable combination — never the verdict's. Asserted over the whole
         space because the bug was produced by a pairing nobody thought to try:
         a CRITICAL finding on a surface measuring 74. */
      assert(
        tone === nodePostureTone(node({ severity: 'none', score, state: 'pass' })),
        `posture tone for ${score} is independent of severity (${severity})`,
      )
      swept += 1
      if (tone !== resolveNodeVerdict(n).color) divergent += 1
      if (expected !== resolveNodeVerdict(n).label) {
        /* When the two disagree, that disagreement must be VISIBLE. */
        assert(tone !== resolveNodeVerdict(n).color, `${score} (${expected}) is not painted as "${resolveNodeVerdict(n).label}"`)
      }
    }
  }
  assert(swept === SEVERITIES.length * SCORES.length, `swept the whole severity x score space (${swept})`)
  assert(divergent > 0, 'the sweep actually contains cards where the two statements differ')

  /* The reported screen, verbatim: three cards, two identical numbers, three
     different words. Each number must carry its own grade's colour. */
  const transport = node({ severity: 'critical', score: 74, state: 'pass' })
  const certificates = node({ key: 'certificates', severity: 'high', score: 73, state: 'pass' })
  const code = node({ key: 'code', severity: 'low', score: 73, state: 'pass' })
  assert(resolveNodeVerdict(transport).label === 'Critical', 'Transport label is Critical (worst finding)')
  assert(resolveNodeVerdict(certificates).label === 'At Risk', 'Certificates label is At Risk (worst finding)')
  assert(resolveNodeVerdict(code).label === 'Fair', 'Code label is Fair (measured posture)')
  assert(
    nodePostureTone(certificates) === nodePostureTone(code),
    'two cards showing 73 paint that 73 the same colour, whatever their findings say',
  )
  assert(
    nodePostureTone(transport) !== resolveNodeVerdict(transport).color,
    '74 is not painted critical red',
  )
}

/* ═══════════════ 3. two post-quantum numbers, two vocabularies ═════════════ */

console.log('\n3. The two post-quantum numbers never share a caption ladder')

{
  const readiness = postQuantumReadinessCaption(81)
  const posture = postQuantumPostureCaption(51)
  assert(readiness.headline !== posture.headline, 'the two tiles do not use the same phrase at 81 / 51')

  /* The real contradiction was both tiles running `score >= 60 ? A : B`, so one
     page asserted A and B about post-quantum cryptography at once. Swept across
     the whole range: the two ladders must never be able to collide. */
  let collisions = 0
  for (let a = 0; a <= 100; a += 1) {
    for (let b = 0; b <= 100; b += 1) {
      if (postQuantumReadinessCaption(a).headline === postQuantumPostureCaption(b).headline) collisions += 1
    }
  }
  assert(collisions === 0, 'no (readiness, posture) pair produces the same headline phrase')

  assert(
    /categor/i.test(readiness.scope),
    'the readiness tile names itself as the published category',
  )
  assert(
    /weight|slice|composite/i.test(posture.scope),
    'the posture tile names itself as the weight slice of the composite',
  )
  assert(
    postQuantumReadinessCaption(null).headline === 'Not scored',
    'a withheld readiness renders as Not scored, never a number',
  )
}

console.log(failures === 0 ? '\nAll alignment contracts hold.\n' : `\n${failures} FAILED\n`)
process.exit(failures === 0 ? 0 : 1)
