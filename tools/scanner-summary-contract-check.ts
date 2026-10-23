/**
 * Scanner summary-contract regression suite.
 *
 * Pins the defect class found in the 2026-09-15 Scanner Web deep audit:
 * `pqc_scan_sessions.metadata.summary` has TWO writers with two different
 * shapes, and the Scanner history payload accepted whichever object was
 * truthy. A partial agent summary therefore travelled into the Web scanner
 * dashboard as if it were a web-scan summary, and `clamp(summary.qScore)` over
 * `undefined` published **NaN** as the tenant's encryption score — graded
 * "F · Critical", printed as "NaN/100" and "NaN% ready".
 *
 *   npx tsx tools/scanner-summary-contract-check.ts
 */
import { reconcileStoredSummary } from '@/api-server/scanner'
import { buildAssessment, type AssessmentInput } from '@/app/dashboard/scanner_dashboard/_intel'

let failures = 0
function assert(condition: boolean, label: string) {
  if (condition) console.log(`  ok   ${label}`)
  else { failures += 1; console.log(`  FAIL ${label}`) }
}

/* VERBATIM `metadata.summary` of a real pqc_scan_sessions row written by
   agent-scanner.ts before the contract was enforced. */
const LEGACY_AGENT_SUMMARY = {
  low: 0, high: 4, safe: 0, medium: 3, critical: 0, totalFindings: 7, pqcReadyEvidence: 0,
}

/* The eleven fields every consumer of a scan summary assumes exist. */
const CONTRACT = [
  'targetsScanned', 'totalFindings', 'critical', 'high', 'medium', 'low',
  'safe', 'vulnerable', 'pqcReady', 'riskScore', 'qScore',
] as const

const finding = (threatLevel: string, status: string) => ({
  id: `f-${Math.random().toString(36).slice(2, 8)}`,
  threatLevel, status, algorithm: 'RSA-2048', category: 'Certificate',
}) as never

function verifyReconciliation() {
  console.log('\n=== 1. A partial stored summary is COMPLETED, never passed through ===')
  const storedFindings = [
    finding('HIGH', 'Quantum-vulnerable'), finding('HIGH', 'Quantum-vulnerable'),
    finding('HIGH', 'Quantum-vulnerable'), finding('HIGH', 'Legacy/deprecated'),
    finding('MEDIUM', 'Misconfigured'), finding('MEDIUM', 'Misconfigured'),
    finding('MEDIUM', 'Quantum-vulnerable'),
  ]
  const summary = reconcileStoredSummary(LEGACY_AGENT_SUMMARY, storedFindings)

  for (const field of CONTRACT) {
    assert(
      Number.isFinite(Number((summary as Record<string, unknown>)[field])),
      `"${field}" is a finite number (${(summary as Record<string, unknown>)[field]})`,
    )
  }
  // 0*18 + 4*10 + 3*5 + 0*2 = 55
  assert(summary.riskScore === 55, `riskScore derived from the stored severities (${summary.riskScore})`)
  assert(summary.qScore === 45, `qScore is 100 - riskScore (${summary.qScore})`)
  assert(summary.high === 4, `the stored severity census is PRESERVED, not recomputed (${summary.high})`)
  assert(summary.vulnerable === 7, `"vulnerable" is counted from the session's own findings (${summary.vulnerable})`)

  console.log('\n=== 2. A complete web-scan summary is preserved byte-for-byte ===')
  const web = {
    targetsScanned: 2, totalFindings: 5, critical: 1, high: 2, medium: 0, low: 1,
    safe: 1, vulnerable: 4, pqcReady: 1, riskScore: 49, qScore: 51,
  }
  const passed = reconcileStoredSummary(web, storedFindings)
  for (const field of CONTRACT) {
    assert(
      (passed as Record<string, number>)[field] === (web as Record<string, number>)[field],
      `"${field}" unchanged for a web-scan summary (${(passed as Record<string, number>)[field]})`,
    )
  }

  console.log('\n=== 3. No stored summary at all still yields the contract ===')
  const derived = reconcileStoredSummary(null, storedFindings)
  assert(CONTRACT.every((f) => Number.isFinite(Number((derived as Record<string, unknown>)[f]))),
    'a session with no stored summary is summarised from its findings')

  console.log('\n=== 4. pqcReadyEvidence is read as pqcReady ===')
  const withEvidence = reconcileStoredSummary({ ...LEGACY_AGENT_SUMMARY, pqcReadyEvidence: 3 }, storedFindings)
  assert(withEvidence.pqcReady === 3, `the agent's own field name is honoured (${withEvidence.pqcReady})`)
}

/* --------------------------------------------------------------------------
   The dashboard's second line of defence: even handed a malformed summary it
   must report "not scored", never a number it did not measure.
   -------------------------------------------------------------------------- */
const INPUT = (overrides: Partial<AssessmentInput>): AssessmentInput => ({
  status: 'idle',
  summary: null,
  findings: [] as never,
  modules: [] as never,
  results: [] as never,
  scanner2: null,
  targets: [],
  completedAt: null,
  estate: {
    totalAssets: 3, totalFindings: 7, criticalFindings: 0, highFindings: 4,
    vulnerableAssets: 1, vulnerableComponents: 4, pqcReadiness: 0, riskScore: 26,
  },
  linked: { cbom: 0, assets: 0, exposures: 0 },
  provenance: 'test',
  ...overrides,
})

function verifyNoFabricatedNumbers() {
  console.log('\n=== 5. A summary with no score is NOT graded ===')
  const a = buildAssessment(INPUT({ summary: LEGACY_AGENT_SUMMARY as never }))
  /* Stronger than "never NaN": an unscored summary publishes NO score. It used to
     publish a fallback 0, which the gauge, the Live Dashboard and Sophia printed
     as a measured worst-possible posture. */
  assert(a.executive.encryptionScore === null, `an unscored summary publishes no score — null, never NaN or 0 (${a.executive.encryptionScore})`)
  assert(a.executive.classicalScore === null, `nor a classical half (${a.executive.classicalScore})`)
  assert(a.executive.gradeable === false, 'an unscored summary is not gradeable')
  assert(a.executive.grade === '—', `no letter grade is invented (${a.executive.grade})`)
  assert(
    a.executive.businessRisk === 'Not assessable',
    `business risk is withheld, not defaulted to Critical (${a.executive.businessRisk})`,
  )

  console.log('\n=== 6. Every rendered string is free of NaN/undefined ===')
  const rendered = [
    ...a.timeline.flatMap((phase) => [phase.horizon, phase.description, phase.title]),
    a.executive.businessRiskDetail, a.executive.gradeDetail, a.executive.confidenceDetail,
    a.footprint.exposureLevel, a.footprint.basis,
    ...a.footprint.metrics.map((metric) => `${metric.label}:${metric.value}`),
    a.target.label, String(a.target.count),
  ]
  const bad = rendered.filter((text) => /\bNaN\b|\bundefined\b|\bnull\b/.test(String(text)))
  assert(bad.length === 0, `no panel string contains NaN/undefined/null (${bad.slice(0, 3).join(' | ') || 'clean'})`)
  assert(
    a.timeline.find((p) => p.key === 'today')!.horizon === 'Not scored',
    `the timeline says "Not scored" rather than printing a number (${a.timeline.find((p) => p.key === 'today')!.horizon})`,
  )
  assert(
    a.timeline.find((p) => p.key === 'migration')!.horizon === 'Not measured',
    `a withheld readiness reads "Not measured", never "NaN% ready" or "0% ready"`,
  )

  console.log('\n=== 7. Estate scope reports the REAL high count, not a constant 0 ===')
  const estate = buildAssessment(INPUT({
    status: 'completed',
    estate: {
      totalAssets: 4, totalFindings: 12, criticalFindings: 0, highFindings: 5,
      vulnerableAssets: 2, vulnerableComponents: 6, pqcReadiness: 15, riskScore: 35,
    },
  }))
  assert(
    /5 high-severity findings/.test(estate.executive.businessRiskDetail),
    `the estate's high findings are stated (${estate.executive.businessRiskDetail})`,
  )
  assert(
    !/No critical or high-severity/.test(estate.executive.businessRiskDetail),
    'an estate with open high findings is never told it has none',
  )

  console.log('\n=== 8. A fully quantum-safe estate is not labelled vulnerable ===')
  const safe = buildAssessment(INPUT({
    status: 'completed',
    estate: {
      totalAssets: 2, totalFindings: 6, criticalFindings: 0, highFindings: 0,
      vulnerableAssets: 0, vulnerableComponents: 0, pqcReadiness: 100, riskScore: 0,
    },
  }))
  assert(
    safe.intelligence.quantumVulnerability !== 'Vulnerable',
    `an estate with zero vulnerable components is not "Vulnerable" (${safe.intelligence.quantumVulnerability})`,
  )
  assert(
    /No critical or high-severity/.test(safe.executive.businessRiskDetail),
    'and a genuinely clean estate still says so',
  )
}

/* --------------------------------------------------------------------------
   A partially-collected edge measurement must not crash the page.
   -------------------------------------------------------------------------- */
function verifyPartialEdgeIsSurvivable() {
  console.log('\n=== 9. A partial edgeIntelligence record renders instead of crashing ===')
  const subObjects = ['pqKeyAgreement', 'transport', 'certificate', 'dns', 'http', 'quantum']
  for (const missing of subObjects) {
    const edge: Record<string, unknown> = {
      host: 'x.example', port: 443, probedAt: new Date().toISOString(), durationMs: 10,
      confidence: 50, notes: [],
    }
    for (const key of subObjects) if (key !== missing) edge[key] = {}
    let ok = true
    try {
      buildAssessment(INPUT({
        status: 'completed',
        summary: {
          targetsScanned: 1, totalFindings: 1, critical: 0, high: 1, medium: 0, low: 0,
          safe: 0, vulnerable: 1, pqcReady: 0, riskScore: 10, qScore: 90,
        } as never,
        results: [{ target: 'x.example', metadata: { edgeIntelligence: edge } }] as never,
      }))
    } catch {
      ok = false
    }
    assert(ok, `edgeIntelligence missing "${missing}" does not throw`)
  }
}

verifyReconciliation()
verifyNoFabricatedNumbers()
verifyPartialEdgeIsSurvivable()

console.log(
  failures === 0
    ? '\nAll scanner summary-contract checks passed.'
    : `\n${failures} scanner summary-contract check(s) FAILED.`,
)
process.exitCode = failures === 0 ? 0 : 1
