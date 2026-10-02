/**
 * Executive Command Center (`/dashboard`) — evidence-honesty check.
 *
 *     npx tsx tools/executive-dashboard-check.ts
 *
 * The Command Center is the first screen an executive sees, and it aggregates
 * twelve panels drawn from different tables. Two failure modes matter more here
 * than anywhere else:
 *
 *  1. **Absence rendered as health.** A tenant with no collector saw
 *     `0 events · 0 queue · 0/0 workers` in Live Runtime Telemetry — identical
 *     to a quiet, well-monitored estate. Nothing told the reader that nothing
 *     was measuring.
 *
 *  2. **Fabricated status.** `sseHealth: 'operational'` sat in the payload as a
 *     hardcoded literal — it never reflected the stream and was never even
 *     rendered.
 *
 * Everything the Command Center shows must trace to the canonical builders
 * (`buildSnapshot`, `buildWorkflowState`, the compliance snapshot) or to a
 * tenant-scoped table, and anything modelled must say so.
 */
import { readFileSync } from 'node:fs'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

const api = readFileSync('src/api-server/dashboard-executive.ts', 'utf8')
/*
 * Comments are stripped before scanning for fabricated literals. The comment
 * that RECORDS a removed fabrication would otherwise trip the check that
 * enforces its removal.
 */
const apiCode = api
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/^\s*\/\/.*$/gm, '')
const hook = readFileSync('src/hooks/use-dashboard.ts', 'utf8')
const runtimePanel = readFileSync('src/app/dashboard/_components/executive/RuntimeTelemetry.tsx', 'utf8')
const kpiGrid = readFileSync('src/app/dashboard/_components/executive/KpiGrid.tsx', 'utf8')
const compliance = readFileSync('src/app/dashboard/_components/executive/ComplianceStrip.tsx', 'utf8')
const impact = readFileSync('src/app/dashboard/_components/executive/BusinessImpact.tsx', 'utf8')
const timeline = readFileSync('src/app/dashboard/_components/executive/ThreatTimeline.tsx', 'utf8')

/* ------------------------------------------------------------------ */
console.log('\n[1] No fabricated status literals in the payload')
assert(!apiCode.includes("sseHealth"), 'the hardcoded sseHealth literal is gone from the payload')
assert(
  !/:\s*'(operational|nominal|healthy)'\s*,/.test(apiCode),
  'no panel status is asserted as a constant rather than measured',
)

/* ------------------------------------------------------------------ */
console.log('\n[2] Runtime telemetry distinguishes measured from absent')
assert(api.includes('measured: runtimeEvents.length > 0'), 'the API reports whether runtime events exist at all')
assert(api.includes('agentsEnrolled: scannerAgents.length > 0'), 'the API reports whether any collector is enrolled')
assert(/measured: boolean/.test(hook), 'the client type carries the measured flag')
assert(/agentsEnrolled: boolean/.test(hook), 'the client type carries the enrolment flag')

assert(runtimePanel.includes('const measured = Boolean(r?.measured)'), 'the panel reads the measured flag')
assert(runtimePanel.includes('const enrolled = Boolean(r?.agentsEnrolled)'), 'the panel reads the enrolment flag')
assert(
  /Events \/ 24h', value: estate\(/.test(runtimePanel),
  'estate cells render "—" rather than 0 when nothing is measuring',
)
assert(
  runtimePanel.includes('No collector enrolled.'),
  'an un-instrumented tenant is told why the estate cells are blank',
)
assert(
  runtimePanel.includes('has not reported a cryptographic event yet'),
  'an enrolled-but-silent collector is distinguished from an absent one',
)
/*
 * The platform-process cells are this API server's own process telemetry, so
 * they are real regardless of tenant instrumentation and must NOT be blanked.
 */
assert(
  /CPU \(server\)', value: `\$\{fmtNumber\(r\?\.process\.cpuMs/.test(runtimePanel),
  'platform-process cells stay populated — they never depended on tenant telemetry',
)

/* ------------------------------------------------------------------ */
console.log('\n[3] KPI cards surface unmeasured rather than a false zero')
assert(kpiGrid.includes("if (kpi.unmeasured) return '—'"), 'an unmeasured KPI renders an em dash, not 0')
assert(kpiGrid.includes("if (kpi.unmeasured) return 'neutral'"), 'an unmeasured KPI takes no good/bad tone')
assert(
  api.includes('unmeasured: !runtimeMeasured'),
  'Runtime Health is flagged unmeasured when no runtime evidence exists',
)

/* ------------------------------------------------------------------ */
console.log('\n[4] Modelled figures are declared, never presented as measured')
assert(api.includes('modeled: true'), 'the business-impact block declares itself modelled')
assert(api.includes('assumptions:'), 'and carries its assumptions')
assert(impact.includes('Modelling assumptions'), 'the panel exposes those assumptions to the reader')
assert(impact.includes('{data.assumptions}'), 'and prints the real assumption text')
/* Compliance is the governance model's MEASURED frameworks — or nothing. The
   old strip divided each score into an invented control total and, when the
   model was unavailable, fabricated eight frameworks as readiness × 0.82. */
assert(
  compliance.includes('requirementsMeasured') && compliance.includes('No framework has a measured control yet'),
  'each framework states how much of it was measured, and an unmeasured estate says so instead of estimating',
)
assert(
  !/readinessBaseline|totalControls/.test(apiCode) && api.includes('requirementsFailing'),
  'no readiness-modelled fallback and no invented control totals — gaps are measured failing + partial requirements',
)

/* ------------------------------------------------------------------ */
console.log('\n[5] Headline numbers come from the canonical engines')
for (const [needle, why] of [
  ['buildSnapshot(token, userId)', 'risk, readiness and inventory reuse the Quantum Readiness snapshot'],
  ['buildWorkflowState(token, userId)', 'migration progress reuses the canonical workflow state'],
  ['deps.loadCompliance', 'the compliance score reuses the Compliance dashboard snapshot'],
] as const) {
  assert(api.includes(needle), why, needle)
}
assert(
  api.includes('const criticalAssets = vulnerableAssets'),
  'Critical Assets is the canonical quantum-vulnerable asset count, not a local re-count',
)

/* ------------------------------------------------------------------ */
console.log('\n[6] Every direct table read is tenant-scoped')
/*
 * Each safeRows/exactCount call sits on one line in this file, so scanning by
 * line is exact — a multi-line regex was matching only the first call and
 * reporting "1 read scoped" while eleven others went unchecked.
 */
const readLines = apiCode.split('\n').filter((l) => l.includes('safeRows(client,'))
assert(readLines.length >= 10, 'the executive snapshot reads the tenant tables it needs', `${readLines.length} read(s)`)
const unscoped = readLines
  .filter((l) => !l.includes(".eq('user_id', userId)"))
  .map((l) => (l.match(/safeRows\(client, '([a-z_]+)'/) || [])[1] || l.trim().slice(0, 40))
assert(
  unscoped.length === 0,
  'EVERY table read pins user_id — defence in depth on top of RLS',
  unscoped.join(', ') || `${readLines.length} scoped`,
)
const counts = apiCode.split('\n').filter((l) => l.includes('exactCount(client,'))
assert(
  counts.every((l) => l.includes('userId')),
  'every exact head-count is tenant-scoped too',
  `${counts.length} count(s)`,
)

/* ------------------------------------------------------------------ */
console.log('\n[6b] Accuracy invariants from the 2026-09-24 audit')
const primitives = readFileSync('src/app/dashboard/_components/executive/primitives.tsx', 'utf8')
const threatIntel = readFileSync('src/app/dashboard/_components/executive/ThreatIntel.tsx', 'utf8')
/* Comments RECORD the removed wording ("It used to say Sophia-ranked"), so the
   UI sources are scanned with comments stripped — see the note on apiCode. */
const stripComments = (text: string) => text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
const recsPanel = stripComments(readFileSync('src/app/dashboard/_components/executive/AiRecommendations.tsx', 'utf8'))
const page = stripComments(readFileSync('src/app/dashboard/page.tsx', 'utf8'))
const dash = readFileSync('src/api-server/dashboard.ts', 'utf8')
assert(
  !/sparkline:\s*(riskSeries|readinessSeries|eventSeries|findingSeries)/.test(apiCode) && !apiCode.includes('dailyBuckets'),
  'no KPI borrows another metric\'s series as its sparkline',
)
assert(
  apiCode.includes("trendBasis: 'none'") && primitives.includes("basis === 'none'") && primitives.includes('no prior baseline'),
  'with no stored history a KPI says "no prior baseline" — never "stable"',
)
assert(
  !/assessmentProgress \* 0\.6/.test(apiCode) && api.includes('evidenceSources'),
  'evidence coverage is the share of named evidence sources — no flat +40 "AI confidence" constant',
)
assert(
  !/\/secret\|key\|credential\/\.test/.test(apiCode) && /SECRET_ITEM_TYPE = \/\^/.test(api),
  'Secrets match the WHOLE item type — key-exchange components are not secrets',
)
assert(
  !/bumpCat\(key, crit === 'critical'/.test(apiCode) && api.includes('snap.assetTypePosture'),
  'Asset Inventory "at risk" is the shared posture verdict, not the business-criticality tag',
)
assert(
  !/shorAtRisk = inv\.vulnerableComponents/.test(apiCode) && api.includes('definition.shorBroken'),
  'Shor-at-Risk counts only components whose primitive Shor breaks (knowledge base), not every vulnerable component',
)
assert(
  !/item_type\)\)\)\.length/.test(apiCode) && api.includes('effectiveStrength < 128'),
  'Grover-Weakened classifies the algorithm (effective strength), not the item_type column',
)
assert(
  api.includes('assetsWithCertificates') && !/pct\(certificates\.length, totalAssets\)/.test(apiCode),
  'Certificate Coverage counts assets WITH a certificate, not certificate rows',
)
assert(
  !/clampPct\(\(financialExposure \/ /.test(apiCode) && api.includes('(financialExposure - migrationCostUsd) / migrationCostUsd'),
  'ROI is (loss avoided − cost) ÷ cost and is not clamped to 100%',
)
assert(
  api.includes('snap.criticalFindings') && !/openVulns\s*\.filter\(\(v\) => severityRank\(v\.severity\) >= 3\)/.test(apiCode),
  'the threat feed is the canonical critical/high finding set, not derived backlog bucket rows',
)
assert(threatIntel.includes("measured ? fmtNumber(c.value) : '—'"), 'runtime-sourced threat tiles read "—" without a collector')
assert(
  !recsPanel.includes('Sophia-ranked') && (recsPanel.match(/<TruncationNote/g) || []).length === 1,
  'recommendations claim no model ranking, and disclose truncation ONCE (not inside every card)',
)
assert(
  dash.includes('groupRecommendedActions(canonical.findings)') && !/for \(const vuln of \(vulnerabilities \|\| \[\]\)/.test(dash),
  'recommendations come from the canonical findings grouped by recorded action — no derived-bucket duplicates',
)
assert(
  /\\bhigh\\b/.test(dash) && !/text\.includes\('critical'\) \|\| text\.includes\('high'\)/.test(dash),
  'event severity keeps HIGH as its own tier — never folded into critical',
)
assert(
  !page.includes('Live monitoring') && page.includes('No runtime collector') && !page.includes('FIPS 140-3 Aligned'),
  'the header separates connection state from estate monitoring, and the footer makes no unevidenced compliance claim',
)

/* ------------------------------------------------------------------ */
console.log('\n[7] Filters run before render bounds')
/*
 * Slicing before filtering makes the severity tabs describe only whatever fell
 * inside the render window — "Critical" would under-report on a busy estate.
 */
const matchingIdx = timeline.indexOf('const matching = useMemo')
const sliceIdx = timeline.indexOf('matching.slice(0, 60)')
assert(matchingIdx > 0 && sliceIdx > matchingIdx, 'the Threat Timeline filters the full set, then bounds the render')
assert(
  /total=\{matching\.length\}/.test(timeline),
  'its disclosure counts the FILTERED total, not the rendered slice',
)

console.log(
  failures === 0
    ? '\n✓ COMMAND CENTER INTEGRITY HOLDS — nothing fabricated, absence never reads as health\n'
    : `\n${failures} CHECK(S) FAILED ✗\n`,
)
process.exit(failures === 0 ? 0 : 1)
