/**
 * LIVE panel audit — every Dashboard Scanner card and panel row, from one real scan.
 *
 * Runs the actual pipeline (web orchestrator → module ledger → Scanner_2 pass →
 * `buildAssessment` → `buildNodeEvidence`) and prints what each of the six
 * surfaces would render, side by side, so cross-panel contradictions are visible
 * without a browser. The offline check tools assert individual rules; this shows
 * the whole page against a real endpoint.
 *
 * It exists because a scan of www.google.com published, on one page:
 *
 *   Transport & Ciphers   Quantum exposure locus: None identified in the suite
 *   Transport & Ciphers   Suites enumerated: 8 accepted · 8 quantum-vulnerable
 *   Transport & Ciphers   Static RSA accepted: Yes · 4 suite(s)
 *   Quantum Posture       Quantum vulnerability: Hybrid-protected
 *   Quantum Posture       Harvest-now exposure: 8 asset(s) · key agreement protected
 *   Quantum Posture       Asset readiness · Scanner_2: 19% · Critical Risk
 *   Quantum Posture       Risk aggregate · Scanner_2: 749 · moderate-risk
 *   Identity & Tokens     "nothing to read"  +  JWT signing scanner: 2 findings
 *
 * None of which could be seen from any single unit test.
 *
 *   npx tsx tools/scanner-panel-audit.ts [target] [type]
 */
import { executeWebScan } from '@/lib/scanner/web-scanner/scan-orchestrator'
import type { SSEEvent, WebScanTargetType, WebScanCompleteResult } from '@/lib/scanner/web-scanner/types'
import {
  SCANNER_MODULE_CATALOG, classifyModuleOutcome, mapWebModule, moduleApplicability, moduleIdForFinding,
} from '@/api-server/scanner-module-ledger'
import { buildAssessment, buildNodeEvidence, SCANNER_NODE_BLUEPRINTS } from '@/app/dashboard/scanner_dashboard/_intel'
import { runEnterpriseScanner2Pass, normalizeWebResult } from '@/api-server/scanner'

const target = process.argv[2] || 'www.google.com'
const targetType = (process.argv[3] as WebScanTargetType) || 'domain'

async function main() {
  const startedAt = new Date().toISOString()
  const modules = SCANNER_MODULE_CATALOG.map((m) => ({
    id: m.id, name: m.name, status: 'Queued' as any, findingsCount: 0,
    reason: null as any, error: null as any, durationMs: 0,
  }))
  const byId = new Map(modules.map((m) => [m.id, m]))

  const result: WebScanCompleteResult = await executeWebScan(target, targetType, (event: SSEEvent) => {
    const type = String(event.type)
    if (type !== 'module-start' && type !== 'module-complete') return
    const canonical = mapWebModule((event as any).moduleId, (event as any).moduleName, (event as any).phase)
    if (!canonical) return
    const m = byId.get(canonical); if (!m) return
    if (type === 'module-start') { if (m.status === 'Queued') m.status = 'Running'; return }
    const outcome = classifyModuleOutcome(
      typeof (event as any).error === 'string' ? (event as any).error : null,
      typeof (event as any).findingCount === 'number' ? (event as any).findingCount : 0,
    )
    if ((m.status === 'Completed' || m.status === 'No findings') && outcome.status === 'Skipped') return
    m.status = outcome.status; m.reason = outcome.reason; m.error = outcome.error
  })

  const record: any = normalizeWebResult(result, startedAt)
  const findings: any[] = record.findings

  for (const f of findings) {
    const owner = byId.get(moduleIdForFinding(f as any)); if (!owner) continue
    owner.findingsCount += 1
    if (owner.status === 'Skipped' || owner.status === 'Queued' || owner.status === 'Running') {
      owner.status = 'Completed'; owner.reason = null
    }
  }
  for (const id of ['target-validation', 'cbom-generator', 'scanner2-module-registry', 'scanner2-fingerprint-matcher',
    'scanner2-detection-rules', 'scanner2-hndl-analyzer', 'scanner2-correlation-engine',
    'scanner2-pqc-migration-engine', 'scanner2-risk-qscore-engine', 'risk-scoring-engine',
    'crypto-exposure-graph-builder', 'asset-inventory-synchronizer', 'audit-history-logger']) {
    const m = byId.get(id)!; if (m.status === 'Queued') m.status = m.findingsCount > 0 ? 'Completed' : 'No findings'
  }
  const applicability = moduleApplicability([{ type: targetType }] as any)
  for (const m of modules) {
    if (m.status !== 'Queued' && m.status !== 'Running') continue
    const reason = (applicability as any)[m.id]
    if (reason) { m.status = 'Skipped'; m.reason = reason; continue }
    m.status = 'Failed'; m.error = 'Module did not report a terminal state'; m.reason = m.error
  }

  const authorized: any = {
    raw: target, normalized: result.target, displayName: result.target,
    type: targetType, protocol: 'https', host: result.target, port: 443,
  }
  const scanner2: any = runEnterpriseScanner2Pass([{ target: authorized, result: record }])

  const sev = (l: string) => findings.filter((f) => f.threatLevel === l).length
  const summary: any = {
    targetsScanned: 1, totalFindings: findings.length, critical: sev('CRITICAL'), high: sev('HIGH'),
    medium: sev('MEDIUM'), low: sev('LOW'), safe: sev('SAFE'),
    vulnerable: findings.filter((f) => ['Quantum-vulnerable', 'Legacy/deprecated', 'Misconfigured'].includes(f.status)).length,
    pqcReady: sev('SAFE'), riskScore: result.overallRiskScore, qScore: Math.max(0, 100 - result.overallRiskScore),
  }

  const assessment: any = buildAssessment({
    status: 'completed' as any, summary, findings: findings as any, modules: modules as any,
    results: [record], scanner2, targets: [result.target], completedAt: record.completedAt,
    estate: {
      totalAssets: 1, totalFindings: findings.length, criticalFindings: summary.critical,
      vulnerableAssets: 1, pqcReadiness: 0, riskScore: result.overallRiskScore,
    },
    linked: { cbom: 0, assets: 1, exposures: 0 }, provenance: 'Live scan evidence',
  })

  console.log('\n================== COMPOSITE ==================')
  console.log('grade           :', assessment.executive?.grade, '| encryptionScore:', assessment.executive?.encryptionScore)
  console.log('postQuantumReadiness:', JSON.stringify(assessment.executive?.postQuantumReadiness))
  console.log('quantumVulnerability:', assessment.executive?.quantumVulnerability)
  console.log('forwardSecrecy  :', assessment.executive?.forwardSecrecy)
  console.log('\nscoreComponents:')
  for (const c of assessment.scoreComponents) {
    console.log(`   ${String(c.key).padEnd(26)} score=${String(c.score).padStart(5)} weight=${String(c.weight).padStart(3)}  ${c.label}`)
  }
  console.log('\nnodeScores      :', JSON.stringify(assessment.nodeScores))
  console.log('summary         :', JSON.stringify(summary))

  console.log('\n================== NODE PANELS ==================')
  for (const bp of SCANNER_NODE_BLUEPRINTS) {
    const ev: any = buildNodeEvidence(bp.key, {
      results: [record], findings: findings as any, modules: modules as any, scanner2,
      targets: [result.target], linked: { cbom: 0, assets: 1, exposures: 0 },
      scoreComponents: assessment.scoreComponents,
    })
    console.log(`\n--- ${bp.title}  [score=${assessment.nodeScores[bp.key] ?? 'none'}] ---`)
    if (ev.emptyReason) console.log('   EMPTY:', ev.emptyReason)
    for (const r of ev.rows ?? []) console.log(`   ${String(r.label).padEnd(32)} ${String(r.value)}`)
    for (const m of ev.modules ?? []) console.log(`   · ${String(m.name).padEnd(40)} ${m.status} (${m.findings})`)
  }

  /* ── The twelve lower panels, in render order ─────────────────────────── */
  const ex = assessment.executive
  console.log('\n================== 1. EXECUTIVE SUMMARY ==================')
  console.log('   grade            ', `${ex.grade} · ${ex.gradeLabel} (gradeable=${ex.gradeable})`)
  console.log('   gradeDetail      ', ex.gradeDetail)
  console.log('   encryptionScore  ', ex.encryptionScore)
  console.log('   classicalScore   ', ex.classicalScore)
  console.log('   postQuantum      ', ex.postQuantumReadiness === null ? `NOT SCORED — ${ex.postQuantumReadinessReason}` : `${ex.postQuantumReadiness}%`)
  console.log('   evidenceCoverage ', `${ex.evidenceCoverage}%`)
  console.log('   businessRisk     ', `${ex.businessRisk} — ${ex.businessRiskDetail}`)
  console.log('   migrationComplex ', `${ex.migrationComplexity} — ${ex.migrationComplexityDetail}`)
  console.log('   confidence       ', `${ex.confidence}% — ${ex.confidenceDetail}`)
  console.log('   target           ', JSON.stringify(assessment.target), '| provenance:', assessment.provenance)

  console.log('\n================== 2. ENCRYPTION SCORE ==================')
  console.log('   composite        ', ex.encryptionScore, '| decomposition:', assessment.decompositionScore, '| agrees:', assessment.decompositionAgrees)
  let wsum = 0, w = 0
  for (const c of assessment.scoreComponents) {
    if (c.score !== null) { wsum += c.score * c.weight; w += c.weight }
    console.log(`   ${String(c.label).padEnd(28)} ${c.score === null ? 'NOT MEASURED' : String(c.score).padStart(3) + '/100'}  weight=${String(c.weight).padStart(3)}  ${(c as any).detail ?? ''}`)
  }
  console.log('   >> recomputed weighted mean:', w ? (wsum / w).toFixed(2) : 'n/a', ' (measured weight', w, 'of', assessment.scoreComponents.reduce((a: number, c: any) => a + c.weight, 0), ')')

  console.log('\n================== 3. OBSERVED ATTACK SURFACE ==================')
  for (const item of assessment.attackSurface) {
    console.log(`   ${String(item.label).padEnd(26)} ${String(item.value).padEnd(34)} [${item.status}]`)
    console.log(`      ${item.detail}`)
  }

  console.log('\n================== 4. CRYPTOGRAPHIC INTELLIGENCE ==================')
  const intel = assessment.intelligence
  console.log('   keyExchange      ', intel.keyExchange)
  console.log('   forwardSecrecy   ', intel.forwardSecrecy)
  console.log('   quantumVulnerab. ', intel.quantumVulnerability)
  console.log('      reason        ', intel.quantumVulnerabilityReason)
  console.log('   endpoint PQ      ', intel.postQuantumReadiness ? `${intel.postQuantumReadiness.score}%` : 'null')
  console.log('   scanner2Readiness', JSON.stringify(intel.scanner2Readiness))
  console.log('   confidence       ', intel.confidence)
  console.log('   observedAlgorithms:')
  for (const a of intel.observedAlgorithms) console.log(`      ${String(a.name).padEnd(30)} ${String(a.role).padEnd(24)} qv=${a.quantumVulnerable} x${a.count}`)
  console.log('   quantumRiskFactors:')
  for (const f of intel.quantumRiskFactors) console.log(`      ${String(f.factor).padEnd(26)} ${String(f.observed).padEnd(34)} ${f.impact}`)
  console.log('   migrationTargets :', JSON.stringify(intel.migrationTargets))

  console.log('\n================== 5. MODULE EXECUTION FLOW ==================')
  const byStatus: Record<string, number> = {}
  for (const m of modules) byStatus[m.status] = (byStatus[m.status] ?? 0) + 1
  console.log('   status tally     ', JSON.stringify(byStatus), '| catalog:', modules.length)
  console.log('   findings summed  ', modules.reduce((a, m) => a + m.findingsCount, 0), 'vs assessment total', findings.length)

  console.log('\n================== 6. CRYPTOGRAPHIC FINDINGS ==================')
  const tally: Record<string, number> = {}
  for (const f of findings) tally[f.threatLevel] = (tally[f.threatLevel] ?? 0) + 1
  console.log('   table rows       ', findings.length, JSON.stringify(tally))
  console.log('   summary says     ', `C${summary.critical} H${summary.high} M${summary.medium} L${summary.low} S${summary.safe} = ${summary.totalFindings}`)
  console.log('   vulnerable       ', summary.vulnerable, '| pqcReady:', summary.pqcReady)

  console.log('\n================== 7. QUANTUM EXPOSURE TIMELINE ==================')
  for (const phase of assessment.timeline) console.log(`   ${JSON.stringify(phase)}`)
  console.log('   hndl             ', JSON.stringify(assessment.hndl))

  console.log('\n================== 8. EXECUTIVE RECOMMENDATIONS ==================')
  for (const r of assessment.recommendations) {
    console.log(`   [${r.priority}] ${r.title}   (affected=${r.affected}, effort=${r.effort}, standard=${r.standard})`)
    console.log(`      impact   : ${r.businessImpact}`)
    console.log(`      rationale: ${r.rationale}`)
    console.log(`      steps    : ${(r.steps ?? []).join(' | ')}`)
  }

  console.log('\n================== 9. ESTATE FOOTPRINT ==================')
  for (const m of assessment.footprint.metrics) console.log(`   ${String(m.label).padEnd(20)} ${String(m.value).padStart(5)}   ${m.countedFrom}`)
  console.log('   exposureLevel    ', assessment.footprint.exposureLevel)
  console.log('   basis            ', assessment.footprint.basis)

  console.log('\n================== 10. DISCOVERY COVERAGE ==================')
  for (const c of assessment.coverage) console.log(`   ${String(c.label).padEnd(28)} [${String(c.status).padEnd(7)}] ${c.detail}`)

  console.log('\n================== 12. ASSESSMENT SCOPE ==================')
  console.log('   analyzed         ', assessment.scope.analyzed.length, 'module(s)')
  for (const line of assessment.scope.analyzed) console.log(`      + ${line}`)
  console.log('   notAnalyzed      ', assessment.scope.notAnalyzed.length)
  for (const line of assessment.scope.notAnalyzed) console.log(`      - ${line}`)


  console.log('\n================== SCANNER_2 ==================')
  console.log('observed/enriched:', scanner2.observedFindings.length, '/', scanner2.enrichedFindings.length, ' of', findings.length, 'web findings')
  console.log('quantumReadiness :', JSON.stringify(scanner2.quantumReadiness))
  console.log('quantumRiskScore :', JSON.stringify({ overall: scanner2.quantumRiskScore.overall, level: scanner2.quantumRiskScore.level, breakdown: scanner2.quantumRiskScore.breakdown, C: scanner2.quantumRiskScore.criticalCount, H: scanner2.quantumRiskScore.highCount, M: scanner2.quantumRiskScore.moderateCount, L: scanner2.quantumRiskScore.lowCount, total: scanner2.quantumRiskScore.totalFindings }))
  console.log('riskScore spread :', JSON.stringify(scanner2.enrichedFindings.map((f: any) => f.riskScore)))
  console.log('hndlRisks        :', scanner2.hndlRisks.length, JSON.stringify(scanner2.hndlRisks.map((h: any) => ({ t: h.targetName, a: h.algorithm, u: h.urgencyLevel }))))
  console.log('attack           :', JSON.stringify(scanner2.attackAssessment?.estimatedBreakWindow), scanner2.attackAssessment?.classification, 'chains=' + scanner2.attackAssessment?.attackCorrelations?.length)

  console.log('\n================== RAW TRANSPORT ==================')
  console.log('tls.supportedProtocols:', JSON.stringify(result.tlsAnalysis?.supportedProtocols))
  console.log('tls.cipherSuites:')
  for (const s of result.tlsAnalysis?.cipherSuites ?? []) {
    console.log(`   ${String(s.standardName).padEnd(46)} kx=${String((s as any).keyExchange).padEnd(22)} qv=${(s as any).quantumVulnerable} cat=${(s as any).category}`)
  }
  const edge: any = (result as any).edgeIntelligence
  console.log('edge.pqKeyAgreement:', JSON.stringify(edge?.pqKeyAgreement))
  console.log('edge.quantum:', JSON.stringify(edge?.quantum))
  console.log('edge.transport.staticRsaAccepted:', edge?.transport?.staticRsaAccepted, '| legacyProtocols:', JSON.stringify(edge?.transport?.legacyProtocols))
}
main().catch((e) => { console.error(e); process.exit(1) })
