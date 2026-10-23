/**
 * /dashboard/scanner — cross-panel alignment, verified on REAL scan evidence.
 *
 *   npx tsx tools/scanner-dashboard-alignment-check.ts [host ...]
 *
 * The audit of 2026-10-23 ran the real pipeline against www.cloudflare.com and
 * found the page's panels disagreeing with each other:
 *
 *   • Hero "Crypto Components 23 · Vulnerable 19" above an Estate Footprint of
 *     16 components, 12 quantum-vulnerable.
 *   • Business Risk from a private 90/80/65/50/35 ladder, contradicting the
 *     published grade table the panel itself opens ("How the Grading Works").
 *   • Live Dashboard "Risk Level" (80/60/40 on exposure) and "PQC Readiness"
 *     (share of SAFE findings) beside different answers on the Assessment tab.
 *   • "Retire RSA-2048" at priority High above "the most severe is rated CRITICAL".
 *   • OCSP "Not stapled" (amber) for a certificate advertising no responder.
 *   • Quantum Risk "High" here and "Critical" on /public-scan for the same host.
 *   • "Classical Encryption" captioning the COMPOSITE when the classical half was
 *     not measured; a withheld score published as 0.
 *
 * Each host is assessed through the real orchestrator → module ledger →
 * Scanner_2 pass → `buildAssessment`, then re-derived into a two-target run, a
 * live (unsettled) run and an estate-scope view, so every rule is exercised on
 * complete, realistic evidence.
 */
import { executeWebScan } from '@/lib/scanner/web-scanner/scan-orchestrator'
import type { SSEEvent, WebScanTargetType } from '@/lib/scanner/web-scanner/types'
import {
  SCANNER_MODULE_CATALOG,
  classifyModuleOutcome,
  mapWebModule,
  moduleApplicability,
  moduleIdForFinding,
} from '@/api-server/scanner-module-ledger'
import { runEnterpriseScanner2Pass, normalizeWebResult } from '@/api-server/scanner'
import { buildAssessment, type AssessmentInput, type ScannerAssessment } from '@/app/dashboard/scanner_dashboard/_intel'
import { RISK_ORDER, scoreToGrade } from '@/lib/scanner/public-scan/grading-model'

let passed = 0
let failed = 0
const failures: string[] = []
function check(label: string, condition: boolean, detail = ''): void {
  if (condition) {
    passed += 1
    return
  }
  failed += 1
  failures.push(`${label}${detail ? ` — ${detail}` : ''}`)
}

/* ═══════════════════════════════════════════ the real pipeline, per host ═══ */

async function liveInput(target: string, targetType: WebScanTargetType = 'domain'): Promise<AssessmentInput> {
  const modules = SCANNER_MODULE_CATALOG.map((m) => ({
    id: m.id, name: m.name, status: 'Queued' as string, findingsCount: 0,
    reason: null as string | null, error: null as string | null, durationMs: 0,
  }))
  const byId = new Map(modules.map((m) => [m.id, m]))

  const result = await executeWebScan(target, targetType, (event: SSEEvent) => {
    const type = String(event.type)
    if (type !== 'module-start' && type !== 'module-complete') return
    const raw = event as unknown as Record<string, unknown>
    const canonical = mapWebModule(raw.moduleId as string, raw.moduleName as string, raw.phase as string)
    const m = canonical ? byId.get(canonical) : undefined
    if (!m) return
    if (type === 'module-start') { if (m.status === 'Queued') m.status = 'Running'; return }
    const outcome = classifyModuleOutcome(
      typeof raw.error === 'string' ? raw.error : null,
      typeof raw.findingCount === 'number' ? raw.findingCount : 0,
    )
    if ((m.status === 'Completed' || m.status === 'No findings') && outcome.status === 'Skipped') return
    m.status = outcome.status; m.reason = outcome.reason; m.error = outcome.error
  })

  const record = normalizeWebResult(result, new Date().toISOString()) as unknown as Record<string, unknown> & { findings: Array<Record<string, unknown>> }
  const findings = record.findings
  for (const finding of findings) {
    const owner = byId.get(moduleIdForFinding(finding as never)); if (!owner) continue
    owner.findingsCount += 1
    if (owner.status === 'Skipped' || owner.status === 'Queued' || owner.status === 'Running') { owner.status = 'Completed'; owner.reason = null }
  }
  for (const id of ['target-validation', 'cbom-generator', 'scanner2-module-registry', 'scanner2-fingerprint-matcher',
    'scanner2-detection-rules', 'scanner2-hndl-analyzer', 'scanner2-correlation-engine', 'scanner2-pqc-migration-engine',
    'scanner2-risk-qscore-engine', 'risk-scoring-engine', 'crypto-exposure-graph-builder', 'asset-inventory-synchronizer',
    'audit-history-logger']) {
    const m = byId.get(id); if (m && m.status === 'Queued') m.status = m.findingsCount > 0 ? 'Completed' : 'No findings'
  }
  const applicability = moduleApplicability([{ type: targetType }] as never) as Record<string, string | undefined>
  for (const m of modules) {
    if (m.status !== 'Queued' && m.status !== 'Running') continue
    const reason = applicability[m.id]
    if (reason) { m.status = 'Skipped'; m.reason = reason; continue }
    m.status = 'Failed'; m.error = 'Module did not report a terminal state'; m.reason = m.error
  }
  const authorized = { raw: target, normalized: result.target, displayName: result.target, type: targetType, protocol: 'https', host: result.target, port: 443 }
  const scanner2 = runEnterpriseScanner2Pass([{ target: authorized as never, result: record as never }])
  const sev = (level: string) => findings.filter((f) => f.threatLevel === level).length
  const summary = {
    targetsScanned: 1, totalFindings: findings.length, critical: sev('CRITICAL'), high: sev('HIGH'),
    medium: sev('MEDIUM'), low: sev('LOW'), safe: sev('SAFE'),
    vulnerable: findings.filter((f) => ['Quantum-vulnerable', 'Legacy/deprecated', 'Misconfigured'].includes(String(f.status))).length,
    pqcReady: sev('SAFE'), riskScore: result.overallRiskScore, qScore: Math.max(0, 100 - result.overallRiskScore),
  }
  return {
    status: 'completed' as never, summary: summary as never, findings: findings as never, modules: modules as never,
    results: [record as never], scanner2: scanner2 as never, targets: [result.target], completedAt: String(record.completedAt),
    estate: {
      totalAssets: 7, totalFindings: 140, criticalFindings: 9, highFindings: 21, vulnerableAssets: 4,
      vulnerableComponents: 63, pqcReadiness: 12, riskScore: 41,
    },
    linked: { cbom: 0, assets: 1, exposures: 0 }, provenance: 'Live scan evidence',
  }
}

/** Two real scans as one run — the shape a multi-target queue produces. */
function combine(a: AssessmentInput, b: AssessmentInput): AssessmentInput {
  const sa = a.summary as unknown as Record<string, number>
  const sb = b.summary as unknown as Record<string, number>
  const sum = (key: string) => (sa[key] ?? 0) + (sb[key] ?? 0)
  return {
    ...a,
    summary: {
      targetsScanned: 2, totalFindings: sum('totalFindings'), critical: sum('critical'), high: sum('high'),
      medium: sum('medium'), low: sum('low'), safe: sum('safe'), vulnerable: sum('vulnerable'), pqcReady: sum('pqcReady'),
      riskScore: Math.round((sa.riskScore + sb.riskScore) / 2), qScore: Math.round((sa.qScore + sb.qScore) / 2),
    } as never,
    findings: [...a.findings, ...b.findings],
    results: [...a.results, ...b.results],
    targets: [...a.targets, ...b.targets],
  }
}

/* ══════════════════════════════════════════════════════ cross-panel rules ═══ */

const THREAT_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, SAFE: 0 }
const PRIORITY: Record<string, string> = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', SAFE: 'Low' }

function assertAssessment(name: string, input: AssessmentInput, a: ScannerAssessment): void {
  const tag = (label: string) => `[${name}] ${label}`
  const ex = a.executive

  /* ── One score, withheld exactly when the grade is ───────────────────── */
  check(tag('a withheld grade publishes no score'), ex.gradeable ? ex.encryptionScore !== null : ex.encryptionScore === null, String(ex.encryptionScore))
  check(
    tag('"Classical Encryption" is the classical half or nothing — never the composite'),
    ex.classicalScore === null || ex.classicalScore === a.postureSplit.classical.score,
    `${ex.classicalScore} vs slice ${a.postureSplit.classical.score}`,
  )
  if (ex.gradeable && ex.encryptionScore !== null) {
    check(tag('grade letter is the published table for the score'), ex.grade === scoreToGrade(ex.encryptionScore).grade, `${ex.grade} @ ${ex.encryptionScore}`)
    /* Business risk: the published table, floored at High by a critical finding. */
    const table = scoreToGrade(ex.encryptionScore).riskLevel
    const expected = a.counters.critical > 0 && RISK_ORDER.indexOf(table) < RISK_ORDER.indexOf('High') ? 'High' : table
    check(tag('business risk is the published risk level (critical floor High)'), ex.businessRisk === expected, `${ex.businessRisk} vs ${expected}`)
  }

  /* ── One set of counts ─────────────────────────────────────────────────── */
  const tile = (key: string) => a.footprint.metrics.find((metric) => metric.key === key)
  check(tag('hero/Live "components" == Estate Footprint tile'), a.counters.components === tile('components')?.value, `${a.counters.components} vs ${tile('components')?.value}`)
  check(tag('components label == Estate Footprint label'), a.counters.componentsLabel === tile('components')?.label)
  check(tag('assets == Estate Footprint "Assets Scanned"'), a.counters.assets === tile('assets')?.value)
  if (a.counters.scope === 'scan') {
    check(tag('hero "Vulnerable" == the Estate Footprint\'s quantum-vulnerable components'), a.footprint.exposureLevel === 'Not assessed' || a.footprint.exposureLevel.includes(`${a.counters.vulnerableComponents} quantum-vulnerable component`), a.footprint.exposureLevel)
    const perTarget = input.results.filter((r) => ((r as { findings?: Array<{ threatLevel: string }> }).findings ?? []).some((f) => f.threatLevel !== 'SAFE')).length
    check(tag('vulnerable assets are counted per target'), a.counters.vulnerableAssets === perTarget, `${a.counters.vulnerableAssets} vs ${perTarget}`)
    check(tag('vulnerable assets never exceed assets'), (a.counters.vulnerableAssets ?? 0) <= a.counters.assets)
    /* A RECORDED run: history strips each result's findings (they are returned
       once at the entry level). Counting over those empty arrays published
       "Vulnerable Assets 0" beside four critical findings on the live page. */
    const recorded = { ...input, results: input.results.map((r) => ({ ...(r as object), findings: undefined })) as never }
    const ra = buildAssessment(recorded)
    const expectedRecorded = ra.counters.assets === 1 ? ((input.summary as unknown as { vulnerable: number }).vulnerable > 0 ? 1 : 0) : null
    check(tag('a recorded run never counts vulnerable assets over stripped findings'), ra.counters.vulnerableAssets === expectedRecorded, `${ra.counters.vulnerableAssets} vs ${expectedRecorded}`)
  }

  /* ── Recommendations speak the findings' severity ────────────────────── */
  for (const card of a.recommendations) {
    check(tag(`"${card.title}" is grounded in this assessment`), card.affected > 0)
    const worst = (card.businessImpact.match(/most severe is rated (\w+)/) ?? [])[1]
    if (worst) check(tag(`"${card.title}" priority is its worst observation`), card.priority === PRIORITY[worst], `${card.priority} vs ${worst}`)
  }
  const families = Number((ex.migrationComplexityDetail.match(/^(\d+) algorithm famil/) ?? [])[1] ?? NaN)
  if (Number.isFinite(families)) {
    check(tag('Migration Complexity counts the families the Recommendations panel lists'), families === a.recommendations.length, `${families} vs ${a.recommendations.length} cards`)
  }

  /* ── Attack surface rows agree with the model and with /public-scan ──── */
  /* The per-endpoint panels read ONE target's edge evidence while the
     decomposition aggregates every target, so on a multi-target run the two may
     legitimately differ — and the panels must say which target they describe.
     This is the rule that caught a two-target run reading OCSP "Not applicable"
     (target 1) beside an OCSP category scored 40 (target 2) with no scope stated. */
  check(
    tag('per-endpoint panels declare the target they describe'),
    a.surfaceTarget.of === input.results.length &&
      (input.results.length === 0 || a.surfaceTarget.target === (input.results[0] as { target?: string }).target),
    JSON.stringify(a.surfaceTarget),
  )
  const ocspRow = a.attackSurface.find((row) => row.key === 'ocsp-stapling')
  const ocspCategory = a.scoreComponents.find((c) => c.key === 'ocsp-stapling')
  if (ocspRow && ocspCategory && input.results.length === 1) {
    check(
      tag('OCSP row and decomposition agree on applicability'),
      ocspCategory.score === null ? ocspRow.status === 'unknown' : ocspRow.status !== 'unknown',
      `row ${ocspRow.value}/${ocspRow.status} · category ${ocspCategory.score}`,
    )
  }
  const riskRow = a.attackSurface.find((row) => row.key === 'quantum-risk')
  const edgeLevels = input.results
    .map((r) => (r as { metadata?: { edgeIntelligence?: { quantum?: { quantumRisk?: string | null } } } }).metadata?.edgeIntelligence?.quantum?.quantumRisk)
    .filter((level): level is string => Boolean(level))
  if (riskRow && edgeLevels.length) {
    const rank: Record<string, number> = { Low: 0, Medium: 1, High: 2, Critical: 3 }
    const worst = edgeLevels.reduce((w, level) => (rank[level] > rank[w] ? level : w))
    check(tag('Quantum Risk is the worst measured edge verdict (the /public-scan classification)'), riskRow.value === worst, `${riskRow.value} vs ${worst}`)
  }

  /* ── Nothing renders a fabricated or broken value ───────────────────── */
  const rendered = [
    ex.gradeDetail, ex.businessRiskDetail, ex.migrationComplexityDetail, a.footprint.exposureLevel,
    ...a.timeline.flatMap((phase) => [phase.horizon, phase.description]),
    ...a.attackSurface.map((row) => `${row.value} ${row.detail}`),
  ].join(' | ')
  check(tag('no NaN/undefined/null rendered'), !/NaN|undefined|\bnull\b/.test(rendered), rendered.match(/.{0,50}(NaN|undefined|\bnull\b).{0,30}/)?.[0])
}

async function main(): Promise<void> {
  console.log('\n/dashboard/scanner cross-panel alignment\n')
  const hosts = process.argv.slice(2).length ? process.argv.slice(2) : ['www.cloudflare.com', 'expired.badssl.com']
  const inputs: AssessmentInput[] = []
  for (const host of hosts) {
    const started = Date.now()
    const input = await liveInput(host)
    const a = buildAssessment(input)
    console.log(`  assessed ${host} in ${((Date.now() - started) / 1000).toFixed(1)}s · ${a.executive.grade} ${a.executive.encryptionScore} · risk ${a.executive.businessRisk}`)
    inputs.push(input)
    assertAssessment(`${host} · completed`, input, a)

    const live = { ...input, status: 'running' as never }
    const la = buildAssessment(live)
    check(`[${host} · live] a running scan is not graded`, !la.executive.gradeable && la.executive.encryptionScore === null)
    assertAssessment(`${host} · live`, live, la)

    const estate = { ...input, summary: null, results: [], modules: [], provenance: 'Tenant Scanner Intelligence' }
    const ea = buildAssessment(estate)
    check(`[${host} · estate] estate scope counts the snapshot`, ea.counters.scope === 'estate' && ea.counters.findings === 140 && ea.counters.vulnerableAssets === 4)
    assertAssessment(`${host} · estate`, estate, ea)
  }
  if (inputs.length >= 2) {
    const combined = combine(inputs[0], inputs[1])
    assertAssessment('two-target run', combined, buildAssessment(combined))
  }

  if (failures.length) {
    console.log(`\n${failures.length} failure(s):`)
    for (const failure of failures) console.log(`  FAIL ${failure}`)
  }
  console.log(`\n${passed} passed, ${failed} failed`)
  process.exit(failed ? 1 : 0)
}

void main().catch((error) => {
  console.error(error)
  process.exit(1)
})
