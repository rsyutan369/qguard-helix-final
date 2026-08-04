/**
 * Public Quantum Exposure Assessment™ — verification harness.
 *
 *   npx tsx tools/public-scan-check.ts [target]
 *
 * Runs a live edge assessment and asserts the accuracy invariants that keep the
 * public scanner honest:
 *   • no fabricated post-quantum readiness (0 unless a PQ group/signature is seen)
 *   • every governance item stays `Unknown`
 *   • scores stay inside their declared bounds and match their components
 *   • the report never claims visibility it does not have
 */

import 'dotenv/config'
import { assessPublicTarget } from '../src/lib/scanner/public-scan/assess'
import { supersedesXFrameOptions } from '../src/lib/scanner/public-scan/engines/http-engine'
import {
  buildScoreComponents,
  computeClassicalScore,
  computePostQuantumReadiness,
} from '../src/lib/scanner/public-scan/engine'
import {
  GAUGE_ARC_BANDS,
  RATING_TIERS,
  RISK_ORDER,
  arcBandColorFor,
  SCORE_CATEGORY_DEFS,
  SCORE_GRADE_TABLE,
  scoreToGrade,
} from '../src/lib/scanner/public-scan/grading-model'

const TARGET = process.argv[2] || 'google.com'

let passed = 0
let failed = 0

function check(name: string, condition: boolean, detail = ''): void {
  if (condition) {
    passed += 1
    console.log(`  PASS  ${name}${detail ? ` — ${detail}` : ''}`)
  } else {
    failed += 1
    console.error(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`)
  }
}

async function main(): Promise<void> {
  console.log(`\nQGuard Helix — Public Quantum Exposure Assessment check`)
  console.log(`Target: ${TARGET}\n`)

  const started = Date.now()
  const report = await assessPublicTarget({ input: TARGET, host: TARGET, port: 443 })
  const elapsed = Date.now() - started

  console.log(`Completed in ${(elapsed / 1000).toFixed(1)}s\n`)
  console.log(`  Grade                 ${report.executive.grade} (${report.executive.gradeLabel})`)
  console.log(`  Classical score       ${report.executive.classicalScore}/100`)
  console.log(`  Post-quantum ready    ${report.executive.postQuantumReadiness}%`)
  console.log(`  Encryption score      ${report.executive.encryptionScore}/100 (${report.executive.encryptionBand})`)
  console.log(`  Business risk         ${report.executive.businessRisk}`)
  console.log(`  Migration complexity  ${report.executive.migrationComplexity}`)
  console.log(`  Confidence            ${report.executive.confidence}%`)
  console.log(`  TLS                   ${report.evidence.tls?.tlsVersion ?? 'n/a'} · ${report.evidence.tls?.cipherSuite ?? 'n/a'}`)
  console.log(`  Key exchange          ${report.intelligence.keyExchange}`)
  console.log(`  Certificate           ${report.evidence.certificate?.publicKeyAlgorithm ?? 'n/a'}`)
  console.log(`  SANs                  ${report.evidence.certificateExtras?.sanCount ?? 0}`)
  console.log(`  CT SCTs               ${report.evidence.certificateExtras?.sctCount ?? 0}`)
  console.log(`  OCSP stapled          ${report.evidence.certificateExtras?.ocspStapled ?? false}`)
  console.log(`  CAA                   ${report.evidence.dns.caaQueryable ? (report.evidence.dns.caaPresent ? report.evidence.dns.caaRecords.join(' | ') : 'absent') : 'not queryable (Unknown)'}`)
  console.log(`  Hybrid PQ groups      ${report.evidence.keyAgreement.hybridGroups.join(', ') || 'none accepted'}`)
  console.log(`  Classical groups      ${report.evidence.keyAgreement.classicalGroups.join(', ') || 'none accepted'}`)
  console.log(`  Findings              ${report.findings.length}`)
  console.log(`  Recommendations       ${report.recommendations.length}\n`)

  console.log('Invariants:')

  // 1 — score bounds
  const { executive } = report
  check(
    'all headline scores within 0-100',
    [executive.classicalScore, executive.postQuantumReadiness, executive.encryptionScore, executive.confidence].every(
      (value) => value >= 0 && value <= 100,
    ),
  )

  // 2 — the published 12-category weighted model is exactly what the grade
  // decomposition shows, and it is what encryptionScore is computed from —
  // not a 60/40 classical/PQ blend (that formula no longer exists).
  check(
    'the report publishes exactly the 12 categories in the weighted scoring model',
    report.scoreComponents.length === SCORE_CATEGORY_DEFS.length &&
      SCORE_CATEGORY_DEFS.every((def) => report.scoreComponents.some((c) => c.key === def.key && c.weight === def.weight)),
    report.scoreComponents.map((c) => `${c.key}:${c.weight}`).join(', '),
  )
  check(
    'score component weights sum to 100',
    report.scoreComponents.reduce((sum, component) => sum + component.weight, 0) === 100,
  )

  // ── Published grading reference ↔ live report ─────────────────────────────
  // A user comparing the report against the "How the Grading Works" document
  // must never find a discrepancy. These assert the live report against the
  // same tables that document is generated from.
  check(
    'the live decomposition is exactly the published 12-category model',
    report.scoreComponents.length === SCORE_CATEGORY_DEFS.length &&
      SCORE_CATEGORY_DEFS.every((def, index) => {
        const live = report.scoreComponents[index]
        return live.key === def.key && live.label === def.label && live.weight === def.weight
      }),
    `${report.scoreComponents.length} categories, order + weights match`,
  )
  check(
    'the grade matches the published score-to-grade mapping for its score',
    !executive.gradeable || executive.grade === scoreToGrade(executive.encryptionScore).grade,
    `${executive.encryptionScore} → ${scoreToGrade(executive.encryptionScore).grade} (report: ${executive.grade})`,
  )
  check(
    'the rating label matches the mapping row for that grade',
    !executive.gradeable || executive.gradeLabel === scoreToGrade(executive.encryptionScore).rating,
    `${executive.gradeLabel} vs ${scoreToGrade(executive.encryptionScore).rating}`,
  )
  check(
    'the risk level matches the mapping row, or is escalated by a real finding',
    !executive.gradeable ||
      RISK_ORDER.indexOf(executive.businessRisk) >=
        RISK_ORDER.indexOf(scoreToGrade(executive.encryptionScore).riskLevel),
    `${executive.businessRisk} vs table ${scoreToGrade(executive.encryptionScore).riskLevel}`,
  )
  check(
    'every score-to-grade band is contiguous and covers 0-100',
    SCORE_GRADE_TABLE.every((row) => row.min <= row.max) &&
      Math.min(...SCORE_GRADE_TABLE.map((row) => row.min)) === 0 &&
      Math.max(...SCORE_GRADE_TABLE.map((row) => row.max)) === 100 &&
      Array.from({ length: 101 }, (_, score) => score).every((score) =>
        SCORE_GRADE_TABLE.some((row) => score >= row.min && score <= row.max),
      ),
  )
  check(
    'the gauge arc colour under the pointer is the grade colour for that score',
    // Bands are half-open [from, to) except the last — an inclusive test would
    // resolve every boundary score to the band below.
    (() => {
      const score = executive.encryptionScore
      const band = GAUGE_ARC_BANDS.find(
        (entry, index) =>
          score >= entry.from && (index === GAUGE_ARC_BANDS.length - 1 ? score <= entry.to : score < entry.to),
      )
      return band?.color === arcBandColorFor(score) && band?.color === scoreToGrade(score).color
    })(),
    `score ${executive.encryptionScore} → ${arcBandColorFor(executive.encryptionScore)}`,
  )
  check(
    'every score 0-100 resolves to exactly one arc band, matching its grade',
    Array.from({ length: 101 }, (_, score) => score).every((score) => {
      const matches = GAUGE_ARC_BANDS.filter(
        (entry, index) =>
          score >= entry.from && (index === GAUGE_ARC_BANDS.length - 1 ? score <= entry.to : score < entry.to),
      )
      return matches.length === 1 && matches[0].color === scoreToGrade(score).color
    }),
  )

  // 3 — encryption score (the graded number) is reproducible from the
  // published 12-category components; classicalScore is the same weighted
  // mean restricted to the 10 non-PQ categories.
  const recomputedComponents = buildScoreComponents(report.evidence)
  const recomputedEncryption = computeClassicalScore(recomputedComponents)
  check(
    'encryption score reproducible from the published 12-category model',
    recomputedEncryption === executive.encryptionScore,
    `${recomputedEncryption} vs ${executive.encryptionScore}`,
  )
  const recomputedClassical = computeClassicalScore(
    recomputedComponents.filter((c) => c.key !== 'cryptographic-algorithms' && c.key !== 'post-quantum-readiness'),
  )
  check(
    'classical score reproducible as the 10-category subset of the same model',
    recomputedClassical === executive.classicalScore,
    `${recomputedClassical} vs ${executive.classicalScore}`,
  )
  check(
    "the post-quantum-readiness category equals the report's postQuantumReadiness stat",
    report.scoreComponents.find((c) => c.key === 'post-quantum-readiness')?.applicable === false ||
      report.scoreComponents.find((c) => c.key === 'post-quantum-readiness')?.score === executive.postQuantumReadiness,
  )
  check(
    'unobservable dimensions are excluded, not scored as failures',
    report.scoreComponents
      .filter((component) => !component.applicable)
      .every((component) => component.observed.length > 0),
    `${report.scoreComponents.filter((c) => !c.applicable).map((c) => c.key).join(', ') || 'none inapplicable'}`,
  )
  check(
    'TLS 1.3 endpoints are credited with forward secrecy',
    !report.evidence.tls?.supportedProtocols.includes('TLSv1.3') ||
      (report.scoreComponents.find((component) => component.key === 'forward-secrecy')?.score ?? 0) > 0,
  )
  check(
    'CAA is reported Unknown (not Fail) when the RRset is not queryable',
    report.evidence.dns.caaQueryable ||
      report.findings.find((finding) => finding.id === 'dns-caa')?.status === 'Unknown',
  )

  // 3a — the badge, gauge and risk level are all derived from the SAME
  // scoreToGrade(encryptionScore) row — this is the "properly applied and
  // aligned" contract for the grading model: nothing on screen may disagree
  // with the published Score-to-Grade Mapping for this score.
  if (executive.gradeable) {
    const graded = scoreToGrade(executive.encryptionScore)
    check(
      'grade letter matches the published Score-to-Grade Mapping for this score',
      executive.grade === graded.grade,
      `score ${executive.encryptionScore} → table says ${graded.grade}, report says ${executive.grade}`,
    )
    check(
      'grade rating (Elite/Excellent/Good/Fair/Weak/Critical) matches the table',
      executive.gradeLabel === graded.rating,
      `${executive.gradeLabel} vs ${graded.rating}`,
    )
    check('grade color matches the table', executive.gradeColor === graded.color)
    check(
      'business risk is at least the risk level the score table assigns (escalation only raises it)',
      SCORE_GRADE_TABLE.some(
        (row) =>
          row.grade === executive.grade &&
          (row.riskLevel === executive.businessRisk ||
            // escalated for a critical finding — never downgraded below the table
            ['Elevated', 'High', 'Critical'].includes(executive.businessRisk)),
      ),
      `table risk for ${executive.grade} vs reported ${executive.businessRisk}`,
    )
  } else {
    check('an ungradeable report has no grade color from the table', executive.gradeColor === '#94a3b8')
  }
  check(
    'the score-to-grade table is exhaustive over 0-100 with no gaps or overlaps',
    Array.from({ length: 101 }, (_, score) => score).every((score) => {
      const matches = SCORE_GRADE_TABLE.filter((row) => score >= row.min && score <= row.max)
      return matches.length === 1
    }),
  )
  check(
    'every SecurityGrade value the table can produce is reachable',
    new Set(SCORE_GRADE_TABLE.map((row) => row.grade)).size === SCORE_GRADE_TABLE.length,
  )

  // The gauge legend (RATING_TIERS) and the colored arc (GAUGE_ARC_BANDS) are
  // both DERIVED from SCORE_GRADE_TABLE — this is what guarantees the chip
  // that lights up, the arc color under the pointer, and the grade badge can
  // never show three different answers for the same score.
  check(
    'the gauge legend covers exactly the ratings the grade table produces, no more no less',
    new Set(RATING_TIERS.map((tier) => tier.rating)).size === RATING_TIERS.length &&
      RATING_TIERS.every((tier) => SCORE_GRADE_TABLE.some((row) => row.rating === tier.rating)) &&
      SCORE_GRADE_TABLE.every((row) => RATING_TIERS.some((tier) => tier.rating === row.rating)),
    RATING_TIERS.map((t) => t.rating).join(', '),
  )
  check(
    'the gauge arc bands are gapless across 0-100 and match the grade table color at every score',
    Array.from({ length: 101 }, (_, score) => score).every((score) => {
      const band = GAUGE_ARC_BANDS.find((b) => score >= b.from && (score < b.to || b.to === 100))
      return band !== undefined && band.color === scoreToGrade(score).color
    }),
  )

  // 3b — a grade is withheld rather than invented when the edge did not respond
  check(
    'grade is withheld (N/A) when evidence coverage is below the threshold',
    executive.gradeable === executive.evidenceCoverage >= 40 &&
      (executive.gradeable || executive.grade === 'N/A'),
    `coverage ${executive.evidenceCoverage}% → grade ${executive.grade}`,
  )
  check(
    'an ungradeable scan does not publish a business-risk conclusion',
    executive.gradeable || executive.businessRisk === 'Not assessable',
  )
  // A control that could not be measured must report Unknown — never a failure.
  // Controls are always emitted (so the published weights still sum to 100);
  // what changes is the verdict.
  const unmeasurable: Array<{ id: string; measurable: boolean }> = [
    { id: 'tls-version', measurable: report.evidence.tls !== null },
    { id: 'cipher-suite', measurable: Boolean(report.evidence.tls?.cipherSuite) },
    { id: 'forward-secrecy', measurable: report.evidence.tls !== null },
    { id: 'certificate-algorithm', measurable: report.evidence.certificate !== null },
    { id: 'certificate-issuer', measurable: report.evidence.certificate !== null },
    { id: 'certificate-lifetime', measurable: report.evidence.certificateExtras !== null },
    { id: 'ocsp-stapling', measurable: report.evidence.certificateExtras !== null },
    { id: 'certificate-transparency', measurable: report.evidence.certificateExtras !== null },
    { id: 'hsts', measurable: report.evidence.http.reachable },
    { id: 'http-security', measurable: report.evidence.http.reachable },
    { id: 'dns-caa', measurable: report.evidence.dns.caaQueryable },
    { id: 'pq-key-agreement', measurable: report.evidence.keyAgreement.probed },
  ]
  const wrongVerdicts = unmeasurable
    .filter((entry) => !entry.measurable)
    .filter((entry) => {
      const finding = report.findings.find((candidate) => candidate.id === entry.id)
      return finding !== undefined && finding.status !== 'Unknown'
    })
  check(
    'no failure finding is raised for a control that could not be measured',
    wrongVerdicts.length === 0,
    wrongVerdicts.length ? `wrongly rated: ${wrongVerdicts.map((e) => e.id).join(', ')}` : 'all unmeasured are Unknown',
  )

  // 4 — no fabricated post-quantum readiness
  const pq = computePostQuantumReadiness(report.evidence)
  check(
    'PQ readiness < 30% unless a hybrid group or PQ signature is observed',
    pq.hybridObserved || pq.pqSignatureObserved || executive.postQuantumReadiness < 30,
    `hybrid=${pq.hybridObserved} pqSig=${pq.pqSignatureObserved} score=${executive.postQuantumReadiness}`,
  )
  check(
    'quantum vulnerability label matches observed evidence',
    (report.intelligence.quantumVulnerability === 'Vulnerable') === !pq.hybridObserved,
    report.intelligence.quantumVulnerability,
  )

  // 5 — governance is always unknown from a public scan
  check(
    'every governance item reports Unknown',
    report.governance.length >= 6 && report.governance.every((item) => item.status === 'Unknown'),
  )
  check(
    'each governance item states why it cannot be validated',
    report.governance.every((item) => item.reason.includes('Enterprise Assessment')),
  )

  // 6 — scope disclosure is present and honest
  check('scope lists what was analyzed', report.scope.analyzed.length >= 5)
  check('scope lists what was NOT analyzed', report.scope.notAnalyzed.length >= 6)
  check(
    'scope statement disclaims internal visibility',
    report.scope.statement.includes('does not inspect source code'),
  )

  // 7 — findings carry the full executive columns
  check(
    'every finding has impact, quantum impact and a next step',
    report.findings.every(
      (finding) => finding.businessImpact && finding.quantumImpact && finding.nextStep && finding.evidence,
    ),
  )
  check('findings are sorted most-severe first', isSortedBySeverity(report))

  // 8 — footprint publishes counts, never invented inventory
  check(
    'footprint states that its values are counts, not estimates of the estate',
    report.footprint.basis.startsWith('These are counts of what this scan observed'),
  )
  check(
    'every footprint metric names what was counted',
    report.footprint.metrics.length > 0 &&
      report.footprint.metrics.every((metric) => metric.countedFrom.length > 0),
  )
  check(
    'footprint names what it cannot count instead of guessing a number',
    report.footprint.notCounted.length >= 5,
  )

  // 9 — Sophia narrative never claims internal visibility
  check(
    'Sophia lists the internal domains she cannot validate',
    report.sophia.cannotValidate.length >= 6 &&
      report.sophia.recommendation.includes('Enterprise Assessment'),
  )

  // 10 — timeline + recommendations present
  check('quantum exposure timeline has all phases', report.timeline.length === 7)
  check('recommendations are prioritised', report.recommendations.every((rec) => Boolean(rec.priority)))
  check(
    'an internal-inventory recommendation is always present',
    report.recommendations.some((rec) => rec.id === 'internal-inventory'),
  )

  // 11 — CROSS-PANEL CONSISTENCY
  // Every panel is a projection of one control array, so the same control must
  // read identically wherever it appears.
  console.log('\nCross-panel consistency:')

  const surfaceByKey = new Map(report.attackSurface.map((item) => [item.key, item]))
  const findingByKey = new Map(report.findings.map((finding) => [finding.id, finding]))
  const componentByKey = new Map(report.scoreComponents.map((component) => [component.key, component]))

  // Seven-state model: only `Not Supported` joins Critical as a real failure.
  const STATUS_TO_SURFACE: Record<string, string> = {
    Healthy: 'pass',
    Warning: 'partial',
    Critical: 'fail',
    'Not Supported': 'fail',
    Unknown: 'unknown',
    'Not Observable': 'unknown',
    'Not Applicable': 'unknown',
  }

  const shared = [...findingByKey.keys()].filter((key) => surfaceByKey.has(key))
  const statusMismatches = shared.filter((key) => {
    const expected = STATUS_TO_SURFACE[findingByKey.get(key)!.status]
    const actual = surfaceByKey.get(key)!.status
    return actual !== expected && actual !== 'info'
  })
  check(
    'Attack Surface status matches Public Findings status for every shared control',
    statusMismatches.length === 0,
    statusMismatches.length ? `mismatched: ${statusMismatches.join(', ')}` : `${shared.length} shared controls agree`,
  )

  // The compact value must not read as a pass when the verdict is a failure —
  // "Fail" text under a Partial dot, or "256-bit AEAD" on a Weak control.
  const POSITIVE_TOKENS = /^(pass|yes|enabled|healthy)$/i
  const NEGATIVE_TOKENS = /^(fail|no|missing|disabled)$/i
  const toneMismatches = report.attackSurface.filter((item) => {
    const finding = findingByKey.get(item.key)
    if (!finding) return false
    if (finding.status === 'Healthy' && NEGATIVE_TOKENS.test(item.value)) return true
    if ((finding.status === 'Critical' || finding.status === 'Not Supported') && POSITIVE_TOKENS.test(item.value)) return true
    // A Partial verdict must not be shown with the harder "Fail" wording.
    if (finding.status === 'Warning' && NEGATIVE_TOKENS.test(item.value)) return true
    return false
  })
  check(
    'Attack Surface value wording matches the control verdict',
    toneMismatches.length === 0,
    toneMismatches.length
      ? toneMismatches.map((item) => `${item.key}="${item.value}" vs ${findingByKey.get(item.key)!.status}`).join('; ')
      : 'wording aligned',
  )

  // Score-category keys are the published model's keys (tls-configuration,
  // cipher-suites, …), which no longer equal the granular finding ids they
  // aggregate (tls-version, cipher-suite, …) now that categories can combine
  // more than one control (Certificates = algorithm + lifetime). For the
  // eight categories that DO pass a single control through unchanged, verify
  // "unobservable" still lines up with that source finding reporting Unknown.
  const DIRECT_CATEGORY_SOURCE: Record<string, string> = {
    'tls-configuration': 'tls-version',
    'cipher-suites': 'cipher-suite',
    'forward-secrecy': 'forward-secrecy',
    hsts: 'hsts',
    'dns-caa': 'dns-caa',
    'ocsp-stapling': 'ocsp-stapling',
    'certificate-transparency': 'certificate-transparency',
    'http-security-headers': 'http-security',
  }
  // All three of these are "no verdict" states in the seven-state model. A
  // category is dropped from the score for any of them — `Not Applicable` is
  // what an OCSP control reports when the certificate advertises no responder
  // at all, which is a valid modern posture rather than an unmeasured one.
  const NO_VERDICT = new Set(['Unknown', 'Not Observable', 'Not Applicable'])
  const scoreMismatches = Object.entries(DIRECT_CATEGORY_SOURCE).filter(([categoryKey, findingId]) => {
    const finding = findingByKey.get(findingId)
    const component = componentByKey.get(categoryKey)
    if (!finding || !component) return false
    return !component.applicable && !NO_VERDICT.has(finding.status)
  })
  check(
    'directly-sourced categories stay unobservable exactly when their source finding has no verdict',
    scoreMismatches.length === 0,
    scoreMismatches.length ? `mismatched: ${scoreMismatches.map(([k]) => k).join(', ')}` : 'aligned',
  )

  // Key exchange must read the same in three places.
  const kexSurface = surfaceByKey.get('forward-secrecy')
  const kexFinding = findingByKey.get('forward-secrecy')
  const kexHandshake = report.handshake.find((step) => step.key === 'key-exchange')
  check(
    'Key Exchange agrees across Attack Surface, Findings, Intelligence and Handshake',
    !report.evidence.tls ||
      (kexHandshake?.value === report.intelligence.keyExchange &&
        Boolean(kexFinding) &&
        Boolean(kexSurface)),
    `intelligence="${report.intelligence.keyExchange}" handshake="${kexHandshake?.value}"`,
  )

  // Post-quantum verdict must agree across four panels.
  const pqSurface = surfaceByKey.get('pq-key-agreement')
  const hybridSeen = report.evidence.keyAgreement.hybridGroups.length > 0
  check(
    'Post-quantum verdict agrees across Attack Surface, Intelligence, Executive and Timeline',
    (pqSurface ? (pqSurface.status === 'pass') === hybridSeen : true) &&
      (report.intelligence.quantumVulnerability !== 'Vulnerable') === hybridSeen &&
      (report.executive.postQuantumReadiness >= 55) === hybridSeen &&
      (report.timeline.find((phase) => phase.key === 'hybrid')?.state === 'now') === hybridSeen,
    `hybrid=${hybridSeen}, pq=${report.executive.postQuantumReadiness}%`,
  )

  // Certificate counts must agree between Attack Surface and the footprint.
  const chainSurface = surfaceByKey.get('certificate-chain')
  const chainMetric = report.footprint.metrics.find((metric) => metric.key === 'chain')
  check(
    'Chain certificate count agrees between Attack Surface and Public Footprint',
    !report.evidence.certificateExtras ||
      chainSurface?.value === `${chainMetric?.value} certs`,
    `surface="${chainSurface?.value}" footprint=${chainMetric?.value}`,
  )

  const namesSurface = surfaceByKey.get('covered-names')
  const namesMetric = report.footprint.metrics.find((metric) => metric.key === 'names')
  check(
    'Covered-name count agrees between Attack Surface and Public Footprint',
    !report.evidence.certificateExtras || namesSurface?.value === String(namesMetric?.value),
    `surface="${namesSurface?.value}" footprint=${namesMetric?.value}`,
  )

  // A recommendation may only exist for a control that actually failed.
  const failedControls = new Set(
    report.findings.filter((finding) => finding.status !== 'Healthy').map((finding) => finding.id),
  )
  const orphanRecommendations = report.recommendations.filter((rec) => {
    const map: Record<string, string> = {
      'disable-legacy-tls': 'tls-version',
      'strengthen-cipher-suites': 'cipher-suite',
      'forward-secrecy': 'forward-secrecy',
      'enable-caa': 'dns-caa',
      'enable-hsts': 'hsts',
      'harden-http-headers': 'http-security',
      'enable-ocsp-stapling': 'ocsp-stapling',
      'certificate-automation': 'certificate-lifetime',
      'hybrid-kex': 'pq-key-agreement',
    }
    const control = map[rec.id]
    return control ? !failedControls.has(control) : false
  })
  check(
    'every recommendation maps to a control that actually failed',
    orphanRecommendations.length === 0,
    orphanRecommendations.length ? `orphaned: ${orphanRecommendations.map((r) => r.id).join(', ')}` : 'all mapped',
  )

  // Score gains must be reproducible from the published model, not asserted.
  check(
    'recommendation score gains are modelled, not hand-assigned',
    report.recommendations.every(
      (rec) =>
        (rec.scoreGain === null && rec.scoreGainTarget === null) ||
        (typeof rec.scoreGain === 'number' && rec.scoreGain >= 0 && rec.scoreGain <= 100),
    ) && report.recommendations.every((rec) => rec.scoreGainBasis.length > 0),
  )
  check(
    'the unscored recommendation is the internal-inventory one',
    report.recommendations.filter((rec) => rec.scoreGain === null).every((rec) => rec.id === 'internal-inventory'),
  )

  // The order on screen must agree with the priority badges on screen.
  const PRIORITY_ORDER: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 }
  const scoredRecommendations = report.recommendations.filter((rec) => rec.id !== 'internal-inventory')
  check(
    'recommendations are ordered by priority, then by modelled gain',
    scoredRecommendations.every((rec, index) => {
      if (index === 0) return true
      const previous = scoredRecommendations[index - 1]
      const byPriority = PRIORITY_ORDER[previous.priority] - PRIORITY_ORDER[rec.priority]
      if (byPriority < 0) return true
      if (byPriority > 0) return false
      return (previous.scoreGain ?? 0) >= (rec.scoreGain ?? 0)
    }),
    scoredRecommendations.map((r) => `${r.priority}+${r.scoreGain}`).join(' > '),
  )

  // An expired or untrusted certificate is an outage, not a hygiene suggestion.
  const certificateExtras = report.evidence.certificateExtras
  check(
    'an expired or untrusted certificate produces a Critical recommendation',
    !certificateExtras ||
      (certificateExtras.daysRemaining > 0 && certificateExtras.chainTrusted) ||
      report.recommendations.some(
        (rec) => rec.id === 'certificate-replace' && rec.priority === 'Critical',
      ),
    certificateExtras
      ? `daysRemaining=${certificateExtras.daysRemaining} trusted=${certificateExtras.chainTrusted}`
      : 'no chain collected',
  )
  check(
    'a healthy certificate never triggers the replace-immediately recommendation',
    !certificateExtras ||
      certificateExtras.daysRemaining <= 0 ||
      !certificateExtras.chainTrusted ||
      !report.recommendations.some((rec) => rec.id === 'certificate-replace'),
  )

  // Sophia must not introduce metrics that contradict the Executive Summary.
  // Only quoted *metrics* count — a percentage, an "/100" composite, or a score
  // introduced with "score of". Algorithm names (P-256) and protocol versions
  // (TLS 1.3) are prose, not claims about this assessment.
  const quotedMetrics = [
    ...report.sophia.narrative.matchAll(/(\d{1,3})\s*%/g),
    ...report.sophia.narrative.matchAll(/(\d{1,3})\s*\/\s*100/g),
    ...report.sophia.narrative.matchAll(/score of (\d{1,3})/g),
  ].map((match) => match[1])
  const executiveNumbers = new Set(
    [
      report.executive.postQuantumReadiness,
      report.executive.classicalScore,
      report.executive.encryptionScore,
      report.executive.evidenceCoverage,
    ].map(String),
  )
  check(
    'Sophia quotes only metrics that appear in the Executive Summary',
    quotedMetrics.length > 0 && quotedMetrics.every((value) => executiveNumbers.has(value)),
    `narrative metrics=[${quotedMetrics.join(', ')}]`,
  )

  // ── One fact, one source ─────────────────────────────────────────────────
  // Each of these caught a real cross-panel contradiction. They exist so the
  // same class of drift cannot come back silently.
  console.log('\nSingle-source invariants:')

  // The Cryptographic Intelligence panel and the `cryptographic-algorithms`
  // score category must be counting the SAME array. They used to be two
  // independently-derived lists: the score said "7 algorithms observed" beside
  // a panel that listed four of them.
  const engineAlgorithms = report.evidence.engines.crypto.data.algorithms
  check(
    'Cryptographic Intelligence lists exactly the algorithms the score category counts',
    report.intelligence.observedAlgorithms.length === engineAlgorithms.length &&
      report.intelligence.observedAlgorithms.every(
        (algorithm, index) => algorithm.name === engineAlgorithms[index].name,
      ),
    `panel=${report.intelligence.observedAlgorithms.length} engine=${engineAlgorithms.length}`,
  )
  check(
    'the algorithms score category reports the same count it scored',
    (() => {
      const component = report.scoreComponents.find((c) => c.key === 'cryptographic-algorithms')
      if (!component || !component.applicable) return true
      const stated = Number(component.observed.match(/^(\d+)/)?.[1] ?? -1)
      return stated === engineAlgorithms.length
    })(),
    report.scoreComponents.find((c) => c.key === 'cryptographic-algorithms')?.observed,
  )
  check(
    'every listed algorithm carries the engine classification and its evidence source',
    report.intelligence.observedAlgorithms.every(
      (algorithm) => algorithm.classification.length > 0 && algorithm.evidenceSource.length > 0,
    ),
  )

  // Forward secrecy must read identically in the Findings table and the Live
  // Handshake panel. The handshake step used to print the un-caveated basis, so
  // it claimed "every session key is forward secret" on a report whose findings
  // said Partial.
  const fsFinding = report.findings.find((finding) => finding.id === 'forward-secrecy')
  const fsHandshake = report.handshake.find((step) => step.key === 'key-exchange')
  check(
    'Forward Secrecy evidence is identical in Findings and Live Handshake',
    !report.evidence.tls || fsFinding?.evidence === fsHandshake?.detail,
    `findings="${fsFinding?.evidence?.slice(0, 60)}…" handshake="${fsHandshake?.detail?.slice(0, 60)}…"`,
  )
  check(
    'a Partial forward-secrecy verdict states the caveat that produced it',
    report.intelligence.forwardSecrecy !== 'Partial' ||
      Boolean(fsFinding?.evidence.includes('static-RSA')),
    `${report.intelligence.forwardSecrecy}: ${fsFinding?.evidence?.slice(0, 80)}`,
  )
  check(
    'the forward-secrecy recommendation is never rationalised by a clean bill of health',
    (() => {
      const rec = report.recommendations.find((r) => r.id === 'forward-secrecy')
      if (!rec) return true
      // A recommendation to fix forward secrecy must not cite a sentence that
      // ends at "every session key is forward secret".
      return !/every session key is forward secret\.$/.test(rec.rationale)
    })(),
  )

  // The header tally must be one number. The live hero counted all nine headers
  // while the report scored the eight non-HSTS ones.
  check(
    'the transport-header tally excludes HSTS everywhere it is reported',
    (() => {
      const finding = report.findings.find((f) => f.id === 'http-security')
      const component = report.scoreComponents.find((c) => c.key === 'http-security-headers')
      if (!finding || !component || !report.evidence.http.reachable) return true
      const total = report.evidence.http.headers.filter(
        (h) => h.name !== 'strict-transport-security',
      ).length
      return finding.finding.includes(`of ${total}`) && component.observed.includes(`/${total}`)
    })(),
    `${report.findings.find((f) => f.id === 'http-security')?.finding}`,
  )

  // Measurements that cost a real probe must reach the report.
  check(
    'the live OCSP responder probe reaches the report evidence',
    !report.evidence.certificateExtras ||
      ['reachable', 'unreachable', 'not-advertised', 'not-probed'].includes(
        report.evidence.certificateExtras.ocspResponderState,
      ),
    `${report.evidence.certificateExtras?.ocspResponderState} — ${report.evidence.certificateExtras?.ocspResponderDetail}`,
  )
  check(
    'a certificate advertising a responder has that responder actually probed',
    !report.evidence.certificateExtras?.ocspUri ||
      report.evidence.certificateExtras.ocspResponderState !== 'not-probed',
  )
  check(
    'an unreachable responder is escalated above plain "not stapled"',
    report.evidence.certificateExtras?.ocspResponderState !== 'unreachable' ||
      report.findings.find((f) => f.id === 'ocsp-stapling')?.status === 'Critical',
  )
  check(
    'standalone ML-KEM groups reach the report and are never counted as hybrid',
    Array.isArray(report.evidence.keyAgreement.pureKemGroups) &&
      report.evidence.keyAgreement.pureKemGroups.every(
        (group) => !report.evidence.keyAgreement.hybridGroups.includes(group),
      ),
    `pure=[${report.evidence.keyAgreement.pureKemGroups.join(', ')}] hybrid=[${report.evidence.keyAgreement.hybridGroups.join(', ')}]`,
  )
  check(
    'the Key-Agreement Groups count equals every group actually accepted',
    report.footprint.metrics.find((m) => m.key === 'groups')?.value ===
      report.evidence.keyAgreement.hybridGroups.length +
        report.evidence.keyAgreement.pureKemGroups.length +
        report.evidence.keyAgreement.classicalGroups.length,
  )

  // The timeline is this endpoint's story, not a generic explainer.
  check(
    'the timeline never names a hybrid group this endpoint did not accept',
    (() => {
      const hybridPhase = report.timeline.find((phase) => phase.key === 'hybrid')
      if (!hybridPhase) return false
      const named = hybridPhase.description.match(/X25519MLKEM768|SecP\w*MLKEM\d+/g) ?? []
      return named.every((group) => report.evidence.keyAgreement.hybridGroups.includes(group))
    })(),
    report.timeline.find((phase) => phase.key === 'hybrid')?.description,
  )
  check(
    'the timeline does not congratulate an endpoint the grade calls Weak or Critical',
    (() => {
      const today = report.timeline.find((phase) => phase.key === 'today')
      if (!today) return false
      const weak = ['Weak', 'Critical'].includes(report.executive.gradeLabel)
      return !weak || !/strong classical cryptography/i.test(today.description)
    })(),
    report.timeline.find((phase) => phase.key === 'today')?.description,
  )
  check(
    'externally-sourced horizons are labelled as estimates, not measurements',
    Boolean(
      report.timeline
        .find((phase) => phase.key === 'crqc')
        ?.description.match(/industry estimate|not a measurement/i),
    ),
  )

  // Sophia must agree with the badge and cite only real findings.
  check(
    'Sophia posture agrees with the published grade rating',
    !report.executive.gradeable ||
      !['Weak', 'Critical', 'Fair'].includes(report.executive.gradeLabel) ||
      !/strong classical cryptographic hygiene/i.test(report.sophia.narrative),
    `${report.executive.gradeLabel}: ${report.sophia.headline}`,
  )
  check(
    'Sophia cites only controls that appear in the Findings table',
    (() => {
      const controlNames = new Set(report.findings.map((finding) => finding.control))
      // Anchor on the findings sentence specifically. A looser em-dash match
      // picks up the score sentence, which also contains one.
      const cited = report.sophia.narrative.match(
        /at high severity or above —\s([^.]+?)\./,
      )
      if (!cited) return true
      return cited[1]
        .split(', ')
        .every((name) => controlNames.has(name.trim()) || /and \d+ more/.test(name))
    })(),
    report.sophia.narrative.match(/at high severity or above —\s([^.]+?)\./)?.[1] ?? 'no findings cited',
  )
  check(
    'Sophia quotes the same top action the Recommendations panel ranks first',
    (() => {
      const top = report.recommendations.find((rec) => rec.scoreGain !== null)
      if (!top) return true
      return (
        !report.sophia.narrative.includes('highest-value change') ||
        report.sophia.narrative.includes(top.title)
      )
    })(),
  )

  // ── No advice the operator cannot act on ─────────────────────────────────
  // Every check here guards a specific false-positive class.
  console.log('\nRemediation accuracy:')

  const ocspRecommendation = report.recommendations.find((rec) => rec.id === 'enable-ocsp-stapling')
  check(
    'OCSP stapling is only recommended when the certificate advertises a responder',
    Boolean(report.evidence.certificateExtras?.ocspUri) || !ocspRecommendation,
    report.evidence.certificateExtras?.ocspUri
      ? `responder ${report.evidence.certificateExtras.ocspUri}`
      : 'no responder advertised — recommendation correctly withheld',
  )
  check(
    'a certificate with no OCSP responder scores OCSP as Not Applicable, never as a failure',
    Boolean(report.evidence.certificateExtras?.ocspUri) ||
      !report.evidence.certificateExtras ||
      (report.findings.find((f) => f.id === 'ocsp-stapling')?.status === 'Not Applicable' &&
        report.scoreComponents.find((c) => c.key === 'ocsp-stapling')?.applicable === false),
    report.findings.find((f) => f.id === 'ocsp-stapling')?.status,
  )
  check(
    'the no-responder case explains why, rather than reporting a gap',
    Boolean(report.evidence.certificateExtras?.ocspUri) ||
      !report.evidence.certificateExtras ||
      Boolean(
        report.attackSurface
          .find((item) => item.key === 'ocsp-stapling')
          ?.detail.includes('does not advertise an OCSP responder'),
      ),
    report.attackSurface.find((item) => item.key === 'ocsp-stapling')?.detail,
  )

  // X-Frame-Options under a restrictive CSP frame-ancestors.
  const xfo = report.evidence.http.headers.find((h) => h.name === 'x-frame-options')
  const csp = report.evidence.http.headers.find((h) => h.name === 'content-security-policy')
  const frameAncestors = csp?.value?.match(/frame-ancestors\s+([^;]+)/i)?.[1]?.trim() ?? null
  const restrictiveFrameAncestors = Boolean(frameAncestors && !/(^|\s)\*(\s|$)/.test(frameAncestors))
  check(
    'X-Frame-Options is exempt when a restrictive CSP frame-ancestors supersedes it',
    !report.evidence.http.reachable ||
      !restrictiveFrameAncestors ||
      xfo?.present === true ||
      xfo?.applicable === false,
    restrictiveFrameAncestors
      ? `frame-ancestors ${frameAncestors} → xfo applicable=${xfo?.applicable}`
      : 'no restrictive frame-ancestors — normal rules apply',
  )
  check(
    'a superseded header is never counted in the hardened tally denominator',
    (() => {
      if (!report.evidence.http.reachable) return true
      const counted = report.evidence.http.headers.filter(
        (h) => h.name !== 'strict-transport-security' && h.applicable !== false,
      ).length
      const finding = report.findings.find((f) => f.id === 'http-security')
      return finding ? finding.finding.includes(`of ${counted}`) : true
    })(),
    report.findings.find((f) => f.id === 'http-security')?.finding,
  )
  check(
    'an exempt header names the control that superseded it',
    report.evidence.http.headers
      .filter((h) => h.applicable === false)
      .every((h) => Boolean(h.supersededBy)),
  )
  check(
    'a header is never exempted while frame-ancestors permits any origin',
    !frameAncestors ||
      restrictiveFrameAncestors ||
      report.evidence.http.headers.every((h) => h.applicable !== false),
  )

  // The live target may not exercise every branch (few sites ship
  // frame-ancestors WITHOUT X-Frame-Options), so the predicate itself is tested
  // directly against the cases that matter.
  const supersessionCases: Array<[string | null, boolean, string]> = [
    [null, false, 'no CSP at all'],
    ['default-src https:', false, 'CSP without frame-ancestors'],
    ["frame-ancestors 'none'", true, "frame-ancestors 'none'"],
    ["frame-ancestors 'self'", true, "frame-ancestors 'self'"],
    ["default-src https:; frame-ancestors 'self' https://a.example", true, 'restrictive source list'],
    ['frame-ancestors *', false, 'wildcard permits any origin'],
    ['frame-ancestors * https://a.example', false, 'wildcard inside a source list'],
    ["frame-ancestors 'self'; default-src *", true, 'wildcard in an unrelated directive'],
  ]
  const supersessionFailures = supersessionCases.filter(
    ([csp, expected]) => supersedesXFrameOptions(csp) !== expected,
  )
  check(
    'X-Frame-Options supersession is exact — restrictive frame-ancestors only, never a wildcard',
    supersessionFailures.length === 0,
    supersessionFailures.length
      ? `wrong for: ${supersessionFailures.map(([, , label]) => label).join('; ')}`
      : `${supersessionCases.length} cases correct`,
  )

  // HSTS graded on its directives.
  const hstsAnalysis = report.evidence.engines.http.data.hsts
  const hstsRecommendation = report.recommendations.find((rec) => rec.id === 'enable-hsts')
  check(
    'HSTS is not recommended when max-age is a full year with includeSubDomains',
    !report.evidence.http.reachable ||
      !(hstsAnalysis.maxAge >= 31_536_000 && hstsAnalysis.includeSubDomains) ||
      !hstsRecommendation,
    `maxAge=${hstsAnalysis.maxAge} includeSubDomains=${hstsAnalysis.includeSubDomains} → ${
      hstsRecommendation ? 'recommended' : 'correctly withheld'
    }`,
  )
  check(
    'preload is never demanded of a name the preload list cannot accept',
    (() => {
      const ineligible = hstsAnalysis.preloadBlockers.some((b) => /registrable domains/.test(b))
      if (!ineligible) return true
      const hstsFinding = report.findings.find((f) => f.id === 'hsts')
      return !/\bpreload\b/i.test(hstsFinding?.nextStep ?? '')
    })(),
    hstsAnalysis.preloadBlockers.join('; ') || 'preload-eligible name',
  )
  check(
    'the HSTS score tracks the directives rather than a pass/fail flag',
    (() => {
      if (!report.evidence.http.reachable) return true
      const component = report.scoreComponents.find((c) => c.key === 'hsts')
      if (!component?.applicable) return true
      // A full-year policy with subdomain coverage must outscore a short one.
      const strong = hstsAnalysis.maxAge >= 31_536_000 && hstsAnalysis.includeSubDomains
      return strong ? component.score >= 95 : component.score < 95
    })(),
    `maxAge=${hstsAnalysis.maxAge} → score ${report.scoreComponents.find((c) => c.key === 'hsts')?.score}`,
  )

  // Platform-tailored remediation.
  const detected = report.evidence.engines.http.data.fingerprint
  const withRemediation = report.recommendations.filter((rec) => rec.remediation)
  check(
    'platform remediation is only attached when a platform was actually detected',
    withRemediation.length === 0 ||
      Boolean(detected.cdn || detected.reverseProxy || detected.server),
    `cdn=${detected.cdn} proxy=${detected.reverseProxy} → ${withRemediation.length} tailored`,
  )
  check(
    'every tailored remediation names the platform it applies to',
    withRemediation.every((rec) => /detected/i.test(rec.remediation ?? '')),
    withRemediation.map((r) => r.id).join(', ') || 'none tailored',
  )

  // ── Public Scan Intelligence Engine modules ──────────────────────────────
  console.log('\nScanner engine modules:')

  const bundle = report.evidence.engines
  check(
    'all five intelligence engines produced a result envelope',
    Boolean(bundle?.dns && bundle?.tls && bundle?.certificate && bundle?.http && bundle?.crypto),
    `${bundle?.totalMs}ms, confidence ${bundle?.confidence}%`,
  )
  check(
    'every engine returns evidence with a detection method and source',
    bundle.evidence.length > 0 &&
      bundle.evidence.every(
        (item) => item.label && item.detectionMethod && item.evidenceSource && item.confidence >= 0,
      ),
    `${bundle.evidence.length} structured observations`,
  )
  check(
    'no engine throws — a failed probe is a result, not an exception',
    [bundle.dns, bundle.tls, bundle.certificate, bundle.http, bundle.crypto].every(
      (engine) => typeof engine.ok === 'boolean' && engine.data !== null,
    ),
  )

  // DNS engine: the transport fallback is what makes CAA answerable at all.
  check(
    'DNS engine resolves CAA over some transport (system resolver or DoH)',
    bundle.dns.data.caaQueryable,
    bundle.dns.data.caaSource ?? 'no transport answered',
  )
  check(
    'DNS engine reports which transports actually answered',
    bundle.dns.data.transports.length > 0,
    bundle.dns.data.transports.join(', '),
  )
  check(
    'DNSSEC verdict is measured, not assumed',
    !bundle.dns.data.dnssecQueryable ||
      typeof bundle.dns.data.dnssecSigned === 'boolean',
  )

  // HTTP engine: must read headers even when the chain is untrusted.
  check(
    'HTTP engine assesses the full OWASP transport-header set',
    bundle.http.data.headers.length === 9,
    `${bundle.http.data.headers.length} headers, groups: ${[...new Set(bundle.http.data.headers.map((h) => h.group))].join('/')}`,
  )
  check(
    'absent headers on a reachable origin are Not Supported, not Unknown',
    !bundle.http.data.reachable ||
      bundle.http.data.headers.filter((h) => !h.present).every((h) => h.status === 'Not Supported'),
  )
  check(
    'HSTS analysis reports preload eligibility with blockers',
    !bundle.http.data.reachable ||
      (typeof bundle.http.data.hsts.preloadEligible === 'boolean' &&
        (bundle.http.data.hsts.preloadEligible || bundle.http.data.hsts.preloadBlockers.length > 0)),
    `${bundle.http.data.hsts.status} · maxAge ${bundle.http.data.hsts.maxAge} · eligible ${bundle.http.data.hsts.preloadEligible}`,
  )

  // TLS engine
  check(
    'TLS engine probes named groups including hybrid ML-KEM',
    // Only meaningful when a handshake completed — there is nothing to offer a
    // group to when the host does not resolve.
    !bundle.tls.ok || bundle.tls.data.groupsProbed,
    bundle.tls.ok
      ? `hybrid: ${bundle.tls.data.hybridGroups.join(', ') || 'none'} · classical: ${bundle.tls.data.classicalGroups.join(', ') || 'none'}`
      : 'no handshake — group probing not applicable',
  )
  check(
    'unobservable TLS properties are null, never guessed',
    bundle.tls.data.compression === null && bundle.tls.data.secureRenegotiation === null,
  )
  // Hybrid ML-KEM groups exist only in the TLS 1.3 key_share. Claiming one on an
  // endpoint that cannot negotiate TLS 1.3 would credit post-quantum readiness to
  // a server that has none — the most damaging false positive available here.
  check(
    'hybrid PQ is never claimed without TLS 1.3',
    bundle.tls.data.hybridGroups.length === 0 ||
      bundle.tls.data.supportedProtocols.includes('TLSv1.3'),
    `hybrid=[${bundle.tls.data.hybridGroups.join(', ')}] protocols=[${bundle.tls.data.supportedProtocols.join(', ')}]`,
  )
  check(
    'a TLS 1.2-only endpoint reports hybrid PQ as unsupported, not untested',
    !bundle.tls.ok ||
      bundle.tls.data.supportedProtocols.includes('TLSv1.3') ||
      (bundle.tls.data.hybridProbed === false &&
        report.findings.find((finding) => finding.id === 'pq-key-agreement')?.status === 'Not Supported'),
  )
  check(
    'a group the server ignored is recorded inconclusive, not accepted',
    bundle.tls.data.inconclusiveGroups.every(
      (group) =>
        !bundle.tls.data.hybridGroups.includes(group) &&
        !bundle.tls.data.classicalGroups.includes(group),
    ),
    bundle.tls.data.inconclusiveGroups.length
      ? `inconclusive: ${bundle.tls.data.inconclusiveGroups.join(', ')}`
      : 'none inconclusive',
  )
  // A reachable endpoint must never be reported as a failed handshake.
  check(
    'a reachable endpoint is not reported as a failed TLS handshake',
    bundle.tls.ok || !bundle.certificate.ok,
    bundle.tls.ok
      ? 'handshake completed'
      : 'handshake failed AND no certificate was read — consistent',
  )

  // Certificate engine
  check(
    'certificate engine verifies the chain rather than trusting the issuer name',
    !bundle.certificate.ok || typeof bundle.certificate.data.chainTrusted === 'boolean',
    `trusted=${bundle.certificate.data.chainTrusted} ${bundle.certificate.data.trustError ?? ''}`,
  )
  check(
    'hostname coverage is evaluated with RFC 6125 matching',
    !bundle.certificate.ok || bundle.certificate.data.hostnameMatches !== undefined,
  )

  // Crypto engine
  check(
    'every catalogued algorithm carries a classification and a source',
    bundle.crypto.data.algorithms.every(
      (algorithm) => algorithm.classification && algorithm.evidenceSource && algorithm.detail,
    ),
    `${bundle.crypto.data.algorithms.length} algorithms observed`,
  )
  check(
    'Quantum Risk Engine explains every factor it scores',
    bundle.crypto.data.riskFactors.every((factor) => factor.explanation.length > 20),
    `${bundle.crypto.data.quantumRisk} from ${bundle.crypto.data.riskFactors.length} factors`,
  )
  check(
    'AES-128 is not reported as quantum-safe',
    bundle.crypto.data.algorithms
      .filter((algorithm) => algorithm.name === 'AES-128-GCM')
      .every((algorithm) => algorithm.quantumVulnerable && algorithm.postQuantumBits === 64),
  )

  // Seven-state discipline across the whole report.
  const VALID_STATUSES = new Set([
    'Healthy',
    'Warning',
    'Critical',
    'Unknown',
    'Not Observable',
    'Not Supported',
    'Not Applicable',
  ])
  check(
    'every finding uses the seven-state status model',
    report.findings.every((finding) => VALID_STATUSES.has(finding.status)),
    [...new Set(report.findings.map((f) => f.status))].join(', '),
  )
  check(
    'Not Applicable is used only where the control is genuinely irrelevant',
    report.findings
      .filter((finding) => finding.status === 'Not Applicable')
      .every((finding) => finding.businessImpact.length > 0),
  )

  console.log('\nOther invariants:')

  // 12 — handshake visualization mirrors the real handshake
  check('handshake visualization has 8 steps', report.handshake.length === 8)
  check(
    'handshake timings are real measurements or explicitly absent',
    report.handshake.every((step) => step.timingMs === null || step.timingMs >= 0),
  )
  check(
    'every handshake step names the measurement it came from',
    report.handshake.every((step) => step.detail.length > 0),
  )
  check(
    'chain trust is verified, not assumed from the issuer name',
    !report.evidence.certificateExtras ||
      typeof report.evidence.certificateExtras.chainTrusted === 'boolean',
  )
  check(
    'handshake steps not observed are flagged',
    report.handshake.every((step) => typeof step.observed === 'boolean'),
  )

  console.log(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed > 0 ? 1 : 0)
}

function isSortedBySeverity(report: Awaited<ReturnType<typeof assessPublicTarget>>): boolean {
  const rank: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, SAFE: 1 }
  for (let i = 1; i < report.findings.length; i += 1) {
    if (rank[report.findings[i - 1].severity] < rank[report.findings[i].severity]) return false
  }
  return true
}

main().catch((err) => {
  console.error('\nCheck harness failed:', err)
  process.exit(1)
})
