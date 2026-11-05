import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
import { buildReportModel } from '../src/services/reporting/ReportEvidence'
import { brandingSchema } from '../src/services/reporting/schemas/ReportSchema'

const url = process.env.VITE_SUPABASE_URL || ''
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
const anonKey = process.env.VITE_SUPABASE_ANON_KEY || ''
const ORIGIN = process.env.REPORT_CHECK_ORIGIN || 'http://localhost:3000'

async function main() {
  const admin = createClient(url, serviceKey, { auth: { persistSession: false } })
  // Account must be Basic tier or higher — the subscription gateway 403s the
  // quantum-readiness module for Starter accounts.
  const { data: link } = await admin.auth.admin.generateLink({ type: 'magiclink', email: process.env.REPORT_CHECK_EMAIL || 'zachmatthew369@gmail.com' })
  const tokenHash = (link!.properties as { hashed_token?: string }).hashed_token!
  const anon = createClient(url, anonKey, { auth: { persistSession: false } })
  const { data } = await anon.auth.verifyOtp({ type: 'magiclink', token_hash: tokenHash })
  const tok = data.session!.access_token
  const qrResponse = await fetch(`${ORIGIN}/api/v1/quantum-readiness`, { headers: { Authorization: `Bearer ${tok}` } })
  const qrBody = await qrResponse.json().catch(() => ({}))
  // A Starter account is refused this module (403): say so instead of crashing on `undefined.scores`.
  if (!qrResponse.ok || !qrBody.data) throw new Error(`quantum-readiness snapshot unavailable: HTTP ${qrResponse.status} ${qrBody?.error?.message || ''} — use a Basic+ account (REPORT_CHECK_EMAIL)`)
  const snapshot = qrBody.data

  const branding = brandingSchema.parse({})
  const r = buildReportModel(snapshot, branding, 'executive', 'Report Check')

  const pass = (cond: boolean, msg: string) => console.log(`${cond ? '✓' : '✗'} ${msg}`)
  console.log('=== Reports_Enhancements_3 phase checks ===')
  // Phase 1
  // Evidence-filtered: sparse tenants legitimately yield fewer than 9 domains.
  const contribSum = r.riskMethodology.weights.reduce((s, w) => s + w.contributionPct, 0)
  pass(r.riskMethodology.weights.length >= 3 && r.riskMethodology.weights.length <= 9 && Math.abs(contribSum - 100) <= 2, `Phase1 Risk Methodology: ${r.riskMethodology.weights.length} domains, contributions sum=${contribSum} (top: ${r.riskMethodology.topDriver})`)
  // Phase 2
  pass(!!r.advisorValidation.primaryExposureDomain && r.advisorValidation.why.length > 20, `Phase2 Advisor Validation: primary=${r.advisorValidation.primaryExposureDomain}, findings=${r.advisorValidation.topContributingFindings.length}`)
  // Phase 3
  pass(r.costBreakdown.lines.every((l) => /hrs ×/.test(l.formula) || l.formula === 'Evidence Not Available') && r.costBreakdown.totalUsd > 0, `Phase3 Cost Breakdown: ${r.costBreakdown.lines.length} lines, totalHours=${r.costBreakdown.totalHours}, total=$${r.costBreakdown.totalUsd}`)
  // Phase 4 adaptive waves
  pass(r.migrationWaves.length === 3, `Phase4 Adaptive Waves (single asset → 3): ${r.migrationWaves.length} waves [${r.migrationWaves.map((w) => w.name).join(', ')}]`)
  // Phase 5
  pass(r.assetCriticality.length > 0, `Phase5 Asset Criticality: ${r.assetCriticality.length} assets (e.g. ${r.assetCriticality[0]?.asset} biz=${r.assetCriticality[0]?.businessCriticality} internet=${r.assetCriticality[0]?.internetFacing})`)
  // Phase 6
  pass(r.impactReasons.length === 5 && r.impactReasons.every((x) => x.reason.length > 5), `Phase6 Business Impact reasons: ${r.impactReasons.length}`)
  // Phase 7
  pass(r.findingGroups.length > 0 && r.findingGroups[0].occurrences >= 1, `Phase7 Finding Dedup: ${r.findingGroups.length} groups; top "${r.findingGroups[0]?.title}" occ=${r.findingGroups[0]?.occurrences} assets=${r.findingGroups[0]?.affectedAssets}`)
  // Phase 8
  pass(r.migrationConfidence.overallPct >= 0 && r.migrationConfidence.factors.length === 8, `Phase8 Migration Confidence: ${r.migrationConfidence.overallPct}% (${r.migrationConfidence.factors.length} factors)`)
  // Phase 9
  const scanner = r.evidenceConfidence.find((e) => e.source === 'Scanner')
  pass(r.evidenceConfidence.length === 8 && (scanner?.confidencePct || 0) === 100, `Phase9 Evidence Confidence: ${r.evidenceConfidence.length} sources, Scanner=${scanner?.confidencePct}%`)
  // Phase 10
  pass(r.executiveDecisions.length >= 3, `Phase10 Executive Decisions: ${r.executiveDecisions.length} (${r.executiveDecisions.map((d) => d.type).join(', ')})`)
  // Phase 11
  pass(r.playbookDetail.length > 0 && r.playbookDetail[0].executionSteps.length >= 3, `Phase11 Playbook Detail: ${r.playbookDetail.length} playbooks, steps=${r.playbookDetail[0]?.executionSteps.length}`)
  // Phase 12
  const last = r.waveSimulation[r.waveSimulation.length - 1]
  pass(r.waveSimulation.length >= 2 && /Entire Program/.test(last.label), `Phase12 Wave Simulation: ${r.waveSimulation.length} scenarios; final "${last.label}" readiness ${last.readinessFrom}→${last.readinessTo}, risk ${last.riskFrom}→${last.riskTo}`)
  // Phase 13
  pass(r.governanceGates.length === 4, `Phase13 Governance Gates: ${r.governanceGates.length}`)
  // Phase 14
  pass(r.explainability.length >= 4 && r.explainability.every((x) => x.what && x.how && x.evidence && x.why && x.action), `Phase14 Explainability: ${r.explainability.length} metrics (what/how/evidence/why/action)`)

  console.log('\n=== Data consistency (report vs QR snapshot) ===')
  pass(r.riskMethodology.overall === snapshot.scores.quantumRisk, `risk overall ${r.riskMethodology.overall} == QR ${snapshot.scores.quantumRisk}`)
  pass(r.kpis.some((k) => String(k.value) === String(snapshot.inventory.vulnerableComponents)), `vulnerable components ${snapshot.inventory.vulnerableComponents} present in KPIs`)
  // Since Improvements_01 #2 the "Entire Program" row lands on the RESIDUAL risk
  // (below the migration target) after Validation/Optimization/Governance.
  pass(last.riskTo === r.riskForecast.residualRisk && last.riskTo <= r.executiveBlock.targetRisk && last.readinessTo === r.executiveBlock.targetReadiness, `program sim lands on residual risk ${last.riskTo} (≤ target ${r.executiveBlock.targetRisk}), readiness=${r.executiveBlock.targetReadiness}`)

  console.log('\n=== Improvements_02 live checks ===')
  const measured = snapshot.telemetry.runtimeEvents > 0
  const runtimeFactor = r.readinessMethodology.factors.find((f) => /runtime/i.test(f.factor))
  pass(!!runtimeFactor && runtimeFactor.measured === measured && (measured || runtimeFactor.score === 'Not Measured'), `I2#1 Runtime visibility consistent with telemetry (events=${snapshot.telemetry.runtimeEvents} → ${runtimeFactor?.score})`)
  const readinessSum = Math.round(r.readinessMethodology.factors.reduce((s, f) => s + f.contribution, 0))
  pass(Math.abs(readinessSum - r.readinessMethodology.overall) <= 1, `I2#3 Readiness methodology: Σ contributions ${readinessSum} ≈ overall ${r.readinessMethodology.overall} (needs dev-server restart if the readiness formula changed)`)
  pass(r.roiAnalysis.lines.length >= 6 && r.roiAnalysis.investmentUsd === r.costForecast.totalUsd, `I2#4 ROI: ${r.roiAnalysis.roiMultiple}× on $${r.roiAnalysis.investmentUsd.toLocaleString()}`)
  pass(r.resourceLoading.length > 0 && r.resourceLoading.every((x) => x.allocationPct > 0 && x.allocationPct <= 100), `I2#5 Resource loading: ${r.resourceLoading.length} team(s)`)
  pass(r.assetIntelligence.length > 0, `I2#6 Asset intelligence: ${r.assetIntelligence.length} asset profile(s)`)
  pass(r.compliance.every((c) => c.targetPct > 0 && c.gapPct === Math.max(0, c.targetPct - c.currentPct)), `I2#7 Compliance gap tracking on ${r.compliance.length} frameworks`)
  pass(r.executiveBlock.topBusinessRisks.length >= 3, `I2#8 Top business risks: ${r.executiveBlock.topBusinessRisks.map((b) => b.risk).join(' | ')}`)
  pass(r.benchmarking.rows.length === 5 && r.benchmarking.rows[0].readiness === snapshot.scores.quantumReadiness, `I2#9 Benchmarking: org=${r.benchmarking.rows[0]?.readiness} vs avg=${r.benchmarking.rows[1]?.readiness}`)
  // 7 checks since R7 added "Target Reconciliation Verified".
  // Count-agnostic: the validation list grows (it is 8 checks as of 2026-11-04).
  pass(r.reportValidation.checks.length >= 7 && r.reportValidation.overall === 'PASS' && r.reportValidation.checks.every((c) => c.status === 'pass'), `I2#10 Report validation: ${r.reportValidation.overall} (${r.reportValidation.checks.filter((c) => c.status === 'pass').length}/${r.reportValidation.checks.length})`)
  for (const c of r.reportValidation.checks.filter((x) => x.status === 'fail')) console.log(`    ✗ failing check: ${c.check} — ${c.detail}`)
  const pillarSum = Math.round(r.readinessIndex.pillars.reduce((s, p) => s + p.contribution, 0))
  pass(r.readinessIndex.pillars.length === 8 && Math.abs(pillarSum - r.readinessIndex.overall) <= 1, `I2#11 Readiness index: Σ pillar contributions ${pillarSum} ≈ overall ${r.readinessIndex.overall}`)
  pass(r.cryptoPolicy.profiles.length === 3 && !JSON.stringify(r).includes('Ed25519 + ML-DSA-65'), `I2#12 Policy-driven algorithms (active: ${r.cryptoPolicy.activeProfile})`)

  console.log('\n=== Improvements_04 live checks ===')
  const program = r.waveSimulation[r.waveSimulation.length - 1]
  pass(r.confidenceSummary.migrationForecastConfidencePct === (program?.confidencePct ?? 0), `I4#1 Forecast confidence ${r.confidenceSummary.migrationForecastConfidencePct}% == programme sim ${program?.confidencePct}%`)
  pass(r.readinessProgression.length === r.waveSimulation.length + 1 && r.readinessProgression[0]?.readiness === snapshot.scores.quantumReadiness, `I4#2 Readiness progression: ${r.readinessProgression.map((s) => s.readiness).join(' → ')}`)
  const ar0 = r.assetReadiness[0]
  pass(!!ar0 && !!ar0.pqcStatus && !!ar0.hndlExposure && !!ar0.criticality, `I4#3/#7 Asset inventory enrichment: ${ar0?.asset} crit=${ar0?.criticality} pqc=${ar0?.pqcStatus}`)
  pass(r.costBreakdown.totalFte > 0 && /engineer-weeks/.test(r.costBreakdown.effortNote), `I4#4 Effort: ${r.costBreakdown.totalHours} hrs ≈ ${r.costBreakdown.totalEngineerWeeks} eng-wks ≈ ${r.costBreakdown.totalFte} FTE`)
  pass(r.riskAcceptance.every((x) => x.approver && /pending/i.test(x.approvalStatus)), `I4#5 Risk-owner approvals pending sign-off on ${r.riskAcceptance.length} entries`)
  pass(r.playbookDetail.every((p) => p.estimatedDowntime !== 'Evidence Not Available' && p.slaImpact !== 'Evidence Not Available'), `I4#6 Playbook ops fields on ${r.playbookDetail.length} playbooks`)
  pass(r.certification.criteria.length === 6 && r.certification.overallReadiness === snapshot.scores.quantumReadiness, `I4#9 Certification: "${r.certification.certificationStatus}" (${r.certification.criteria.filter((c) => c.met).length}/6 criteria met)`)

  console.log('\n=== Improvements_05 live checks ===')
  // NOTE: buildReportModel without a scope block uses inventory.assetsAssessed as
  // the canonical count; via the Report Center (buildReport) the scope universe
  // drives it. Both paths are internally consistent by construction.
  const assetDef = r.definitions.find((d) => d.term === 'Asset')
  const canonical = r.scope.totalAssetCount || snapshot.inventory.assetsAssessed
  pass(!!assetDef && assetDef.definition.includes(`${canonical} discovered asset`) && r.certification.scopeStatement.includes(`${canonical} discovered asset`) && r.executiveSummary.includes(`identified ${canonical} cryptographic asset`), `I5#1 Canonical asset count ${canonical} across definitions/summary/certification`)
  pass(r.evidence.sources.length + r.evidence.unavailableSources.length === r.evidenceConfidence.length && r.evidence.unavailableSources.every((s) => (r.evidenceConfidence.find((e) => e.source === s)?.confidencePct || 0) === 0), `I5#2 Evidence split: ${r.evidence.sources.join(', ')} | unavailable: ${r.evidence.unavailableSources.join(', ') || 'none'}`)
  const msArr = r.certification.milestones
  pass(msArr.length === r.roadmap.length + 1 && /Certification Eligibility/.test(msArr[msArr.length - 1]?.milestone || ''), `I5#4 Milestones: ${msArr.slice(0, 3).map((m) => `${m.milestone} [${m.window}]`).join(' | ')} …`)
  pass(r.decisionPackage.length >= 7, `I5#5 Decision package: ${r.decisionPackage.map((d) => `${d.item}=${d.value}`).join(' | ')}`)
  pass(/\(\d+\.\d%\)/.test(r.evidence.notes), `I5#6 Severity %: ${r.evidence.notes.slice(0, 120)}…`)
}
main().catch((e) => { console.error(e); process.exit(1) })
