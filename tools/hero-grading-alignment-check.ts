/**
 * Hero card ↔ "How the Grading Works" alignment.
 *
 * Runs a REAL public assessment and asserts that every hero node card carries
 * the rating and the colour the published Security Grade Reference assigns to
 * that card's own score — the sheet the product ships and the cards beside it
 * must not disagree.
 *
 *   npx tsx tools/hero-grading-alignment-check.ts expired.badssl.com
 */

import { assessPublicTarget } from '../src/lib/scanner/public-scan/assess'
import { nodeScoresFromReport, NODE_SCORE_CATEGORIES } from '../src/app/public-scan/_qve/event-derivation'
import {
  contrastRatio,
  hexToRgb,
  readableOnDark,
  resolveNodeVerdict,
  type QveNode,
  type QveNodeKey,
} from '../src/app/public-scan/_qve/types'
import { scoreToGrade } from '../src/lib/scanner/public-scan/grading-model'

/** The hero card fill the verdict label is rendered on. */
const HERO_SURFACE: [number, number, number] = [7, 13, 27]

const TARGET = process.argv[2] || 'expired.badssl.com'

let failures = 0
function assert(condition: boolean, label: string) {
  if (condition) console.log(`  ok   ${label}`)
  else {
    failures += 1
    console.log(`  FAIL ${label}`)
  }
}

/** A settled node exactly as the store builds one after `settle`. */
function settledNode(key: QveNodeKey, score: number): QveNode {
  return {
    key,
    title: key.toUpperCase(),
    state: 'pass',
    verdict: 'Reviewed',
    lines: ['evidence line'],
    progress: 100,
    severity: 'low',
    updatedAt: Date.now(),
    postQuantum: false,
    hasEvidence: true,
    score,
    band: null,
  }
}

async function main() {
  console.log(`\nQGuard Helix — hero card grading alignment`)
  console.log(`Target: ${TARGET}\n`)

  const report = await assessPublicTarget({ input: TARGET, host: TARGET, port: 443, budgetMs: 45_000 })
  const scores = nodeScoresFromReport(report)
  const overall = scoreToGrade(report.executive.encryptionScore)

  console.log(`  Overall  ${report.executive.encryptionScore}/100 → ${overall.grade} · ${overall.rating} · ${overall.color}\n`)

  for (const key of Object.keys(NODE_SCORE_CATEGORIES)) {
    const score = scores[key as QveNodeKey]
    if (score === undefined) {
      console.log(`  --   ${key.padEnd(12)} not scored (no measured category) — card shows "Not measured"`)
      continue
    }
    const grade = scoreToGrade(score)
    const verdict = resolveNodeVerdict(settledNode(key, score))
    console.log(
      `       ${key.padEnd(12)} ${String(score).padStart(3)}/100 → ${grade.grade.padEnd(2)} ${grade.rating.padEnd(9)} card="${verdict.label}" ${verdict.color} (published ${grade.color}, ${contrastRatio(hexToRgb(verdict.color), HERO_SURFACE).toFixed(1)}:1)`,
    )
    assert(verdict.label === grade.rating, `${key}: card label matches the published rating for ${score}`)
    // The card renders the published grade colour raised to a legible luminance
    // on the dark hero (hue and saturation untouched) — asserted as exactly that
    // transform of the published value, so it cannot become an arbitrary colour.
    assert(
      verdict.color === readableOnDark(grade.color),
      `${key}: card colour is the published grade colour, made legible on the hero`,
    )
    assert(
      contrastRatio(hexToRgb(verdict.color), HERO_SURFACE) >= 4.5,
      `${key}: the verdict label clears the 4.5:1 contrast floor`,
    )
  }

  console.log(
    failures === 0
      ? `\nPASS — every scored hero card agrees with the published grading model.\n`
      : `\nFAIL — ${failures} mismatch(es).\n`,
  )
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
