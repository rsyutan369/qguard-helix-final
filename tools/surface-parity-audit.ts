/**
 * SURFACE PARITY — LIVE. One real host through BOTH pipelines, side by side.
 *
 *   npx tsx tools/surface-parity-audit.ts [host]
 *
 * `tools/surface-parity-check.ts` asserts the contracts offline against fixed
 * evidence. This runs the actual engines against a real endpoint and prints
 * every published category from each, so a disagreement is visible without a
 * browser — which is how the original defect was found and the only way to
 * catch one that lives in an ADAPTER rather than in the shared ladders.
 *
 * Reference readings (2026-10-05, after unification):
 *
 *   test.openquantumsafe.org   79 · B- · Fair       0 of 12 disagree
 *   cloudflare.com             69 · C  · Fair       0 of 12 disagree
 *   example.com                56 · D  · Weak       0 of 12 disagree
 *   expired.badssl.com         32 · F  · Critical   0 of 12 disagree
 *
 * A non-zero disagreement count is a defect. Note that a public probe which
 * times out legitimately produces fewer MEASURED categories than the
 * authenticated scan — check the "measured weight" line before chasing a
 * difference that is really an evidence gap.
 */
import 'dotenv/config'
import { assessPublicTarget } from '../src/lib/scanner/public-scan/assess'
import { executeWebScan } from '../src/lib/scanner/web-scanner/scan-orchestrator'
import { SCORE_CATEGORY_DEFS, scoreToGrade, weightedCategoryScore } from '../src/lib/scanner/public-scan/grading-model'
import { NODE_SCORE_CATEGORIES } from '../src/app/public-scan/_qve/event-derivation'
import { SCANNER_NODE_CATEGORIES } from '../src/app/dashboard/scanner_dashboard/_intel'
import type { SSEEvent } from '../src/lib/scanner/web-scanner/types'

const TARGET = process.argv[2] || 'test.openquantumsafe.org'

function pad(s: string, n: number) { return (s + ' '.repeat(n)).slice(0, n) }
function cell(score: number | null, applicable: boolean) {
  return applicable ? pad(String(score), 6) : pad('n/a', 6)
}

async function main() {
  console.log(`\n═══ SURFACE PARITY DIAGNOSTIC — ${TARGET} ═══\n`)

  console.log('→ running /public-scan pipeline (assessPublicTarget)…')
  const report = await assessPublicTarget({ input: TARGET, host: TARGET, port: 443 })

  console.log('→ running /dashboard/scanner pipeline (executeWebScan)…')
  const web = await executeWebScan(TARGET, 'domain', (_e: SSEEvent) => {})

  const pub = new Map(report.scoreComponents.map((c) => [c.key, c]))
  const dash = new Map((web.scoreCategories ?? []).map((c) => [c.key, c]))

  console.log('\n┌─ TWELVE PUBLISHED CATEGORIES ─────────────────────────────────────────────────')
  console.log(`│ ${pad('category', 28)}${pad('w', 4)}${pad('public', 7)}${pad('scanner', 8)} delta  observed`)
  console.log('├───────────────────────────────────────────────────────────────────────────────')
  let diffs = 0
  for (const def of SCORE_CATEGORY_DEFS) {
    const p = pub.get(def.key)
    const d = dash.get(def.key)
    const pOk = Boolean(p?.applicable)
    const dOk = Boolean(d?.applicable)
    const pv = pOk ? p!.score : null
    const dv = dOk ? d!.score : null
    let delta = ''
    if (pOk !== dOk) { delta = 'APPLIC'; diffs++ }
    else if (pOk && dOk && pv !== dv) { delta = String((dv as number) - (pv as number)).padStart(5); diffs++ }
    console.log(
      `│ ${pad(def.key, 28)}${pad(String(def.weight), 4)}${cell(pv, pOk)} ${cell(dv, dOk)} ${pad(delta, 7)}`,
    )
    console.log(`│ ${' '.repeat(28)}  pub: ${p?.observed ?? '—'}`)
    console.log(`│ ${' '.repeat(28)}  dsh: ${d?.observed ?? '—'}`)
  }
  console.log('└───────────────────────────────────────────────────────────────────────────────')
  console.log(`  ${diffs} of 12 categories disagree\n`)

  const pubComposite = weightedCategoryScore(report.scoreComponents.map((c) => ({ score: c.score, weight: c.weight, applicable: c.applicable })))
  const dashComposite = weightedCategoryScore((web.scoreCategories ?? []).map((c) => ({ score: c.score, weight: c.weight, applicable: c.applicable })))
  console.log(`  public composite : ${pubComposite}  ${scoreToGrade(pubComposite).grade} · ${scoreToGrade(pubComposite).rating}`)
  console.log(`  scanner composite: ${dashComposite}  ${scoreToGrade(dashComposite).grade} · ${scoreToGrade(dashComposite).rating}`)
  console.log(`  scanner overallRiskScore -> qScore: ${100 - web.overallRiskScore}`)
  console.log(`  measured weight  : public ${report.scoreComponents.filter(c=>c.applicable).reduce((s,c)=>s+c.weight,0)} / scanner ${web.riskMeasuredWeight}\n`)

  function project(ring: Record<string, readonly string[]>, src: Map<string, any>) {
    const out: Record<string, { score: number | null; cats: string }> = {}
    for (const [node, cats] of Object.entries(ring)) {
      let weighted = 0, weight = 0
      const used: string[] = []
      for (const key of cats) {
        const c = src.get(key)
        if (!c || !c.applicable) continue
        weighted += c.score * c.weight; weight += c.weight; used.push(`${key}=${c.score}`)
      }
      out[node] = { score: weight ? Math.round(weighted / weight) : null, cats: used.join(' ') }
    }
    return out
  }

  const pubNodes = project(NODE_SCORE_CATEGORIES as any, pub)
  const dashNodes = project(SCANNER_NODE_CATEGORIES, dash)

  console.log('┌─ NODE CARD PROJECTIONS (different rings!) ────────────────────────────────────')
  console.log('│ /public-scan')
  for (const [n, v] of Object.entries(pubNodes)) {
    const g = v.score === null ? '—' : `${scoreToGrade(v.score).rating}`
    console.log(`│   ${pad(n, 14)}${pad(String(v.score ?? 'n/a'), 6)}${pad(g, 12)} [${v.cats}]`)
  }
  console.log('│ /dashboard/scanner')
  for (const [n, v] of Object.entries(dashNodes)) {
    const g = v.score === null ? '—' : `${scoreToGrade(v.score).rating}`
    console.log(`│   ${pad(n, 14)}${pad(String(v.score ?? 'n/a'), 6)}${pad(g, 12)} [${v.cats}]`)
  }
  console.log('└───────────────────────────────────────────────────────────────────────────────\n')

  console.log('EDGE EVIDENCE (scanner):', JSON.stringify({
    ocspUri: web.edgeIntelligence?.certificate?.ocspUri ?? null,
    ocspStapled: web.edgeIntelligence?.certificate?.ocspStapled ?? null,
    mustStaple: web.edgeIntelligence?.certificate?.mustStaple ?? null,
    sctCount: web.edgeIntelligence?.certificate?.sctCount ?? null,
    caaPresent: web.edgeIntelligence?.dns?.caaPresent ?? null,
    caaClimbComplete: (web.edgeIntelligence?.dns as any)?.caaClimbComplete ?? null,
    protocols: web.edgeIntelligence?.transport?.supportedProtocols ?? null,
    hybrid: web.edgeIntelligence?.pqKeyAgreement?.hybridGroups ?? null,
  }, null, 2))
  console.log('\nPUBLIC EVIDENCE:', JSON.stringify({
    ocspUri: report.evidence.certificateExtras?.ocspUri ?? null,
    ocspStapled: report.evidence.certificateExtras?.ocspStapled ?? null,
    validityDays: report.evidence.certificateExtras?.validityDays ?? null,
    sctCount: report.evidence.certificateExtras?.sctCount ?? null,
    protocols: report.evidence.tls?.supportedProtocols ?? null,
    hybrid: report.evidence.keyAgreement?.hybridGroups ?? null,
    certAlg: report.evidence.certificate?.publicKeyAlgorithm ?? null,
  }, null, 2))
}

main().catch((e) => { console.error(e); process.exit(1) })
