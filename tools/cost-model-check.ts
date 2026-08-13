/**
 * Cost & business-value model checks.
 *
 * The regressions these guard, all of which shipped to screen:
 *   - "Projected Risk-Reduction Value" was `cost × reductionPct × 3`, which
 *     collapsed to a constant 2.25 × cost and claimed a return 4.4× larger than
 *     the exposure the platform itself computed.
 *   - HSM and Cloud/KMS were budgeted on a tenant with zero keys and zero cloud
 *     accounts — 18% of the programme assigned to hardware never discovered.
 *   - Per-line costs had to keep summing to the displayed total.
 *
 *   npx tsx tools/cost-model-check.ts
 */
import {
  COST_ASSUMPTION_LIMITS,
  DEFAULT_COST_ASSUMPTIONS,
  allocateCostCategories,
  buildBudgetVariance,
  buildFinancialExposure,
  describeCostAssumptions,
  migrationCostUsd,
  normalizeToWholeHours,
  projectedRiskReductionValueUsd,
  resolveCostAssumptions,
} from '../src/lib/migration/cost-model'

let passed = 0
const failures: string[] = []

function check(name: string, actual: unknown, expected: unknown) {
  if (actual === expected) {
    passed += 1
    return
  }
  failures.push(`${name}\n     expected: ${JSON.stringify(expected)}\n     actual:   ${JSON.stringify(actual)}`)
}
function ok(name: string, condition: boolean) {
  check(name, condition, true)
}

/* ── Risk-reduction value can never exceed exposure ──────────────────────── */

check('value is a fraction of exposure', projectedRiskReductionValueUsd(80_000, 74), 59_200)
check('value is capped at exposure', projectedRiskReductionValueUsd(80_000, 150), 80_000)
check('no exposure ⇒ no claimed value', projectedRiskReductionValueUsd(0, 74), 0)
check('no reduction ⇒ no claimed value', projectedRiskReductionValueUsd(80_000, 0), 0)
check('negative reduction is floored', projectedRiskReductionValueUsd(80_000, -20), 0)

// The specific defect: the old model returned 352,688 against an exposure of
// 80,000. Whatever the inputs, value must never outrun exposure.
for (const exposure of [0, 1_000, 80_000, 5_000_000]) {
  for (const reduction of [0, 25, 74, 75, 99, 100]) {
    ok(
      `value ≤ exposure (exposure=${exposure}, reduction=${reduction})`,
      projectedRiskReductionValueUsd(exposure, reduction) <= exposure,
    )
  }
}

/* ── Exposure model — shared by planner and executive ────────────────────── */

const untagged = buildFinancialExposure(
  { vulnerableAssets: 2, taggedCriticalAssets: 0, pqcReadyAssets: 0 },
  DEFAULT_COST_ASSUMPTIONS,
)
check('untagged estate values at the standard rate', untagged.financialExposureUsd, 80_000)
check('untagged estate is flagged as untagged', untagged.criticalityTagged, false)
check('untagged estate has no critical-valued assets', untagged.criticalVulnerableAssets, 0)

const tagged = buildFinancialExposure(
  { vulnerableAssets: 3, taggedCriticalAssets: 1, pqcReadyAssets: 0 },
  DEFAULT_COST_ASSUMPTIONS,
)
check('mixed estate = 1 critical + 2 standard', tagged.financialExposureUsd, 250_000 + 2 * 40_000)
check('mixed estate reports tagging', tagged.criticalityTagged, true)

// Tenant values must actually move the model.
const cheap = resolveCostAssumptions({ valuePerStandardAssetUsd: 10_000 })
check('tenant asset value is honoured', buildFinancialExposure({ vulnerableAssets: 2, taggedCriticalAssets: 0, pqcReadyAssets: 0 }, cheap).financialExposureUsd, 20_000)

/* ── Categories: unmeasured is excluded, never costed ────────────────────── */

const noInfra = allocateCostCategories({
  vulnerableComponents: 36,
  certificatesAnalyzed: 3,
  keysDiscovered: 0,
  cloudAccounts: 0,
  assetsAssessed: 2,
})
ok('HSM excluded with zero keys', noInfra.excluded.some((e) => e.category === 'HSM'))
ok('Cloud/KMS excluded with zero cloud accounts', noInfra.excluded.some((e) => e.category === 'Cloud / KMS'))
ok('PKI retained when certificates exist', noInfra.applicable.some((e) => e.category === 'PKI & Certificate Modernization'))
ok('every exclusion carries a reason', noInfra.excluded.every((e) => e.reason.length > 0))
check(
  'applicable weights renormalise to 1',
  Math.round(noInfra.applicable.reduce((sum, e) => sum + e.weight, 0) * 1e6) / 1e6,
  1,
)

const fullInfra = allocateCostCategories({
  vulnerableComponents: 100,
  certificatesAnalyzed: 12,
  keysDiscovered: 40,
  cloudAccounts: 3,
  assetsAssessed: 20,
})
check('nothing excluded when every source is connected', fullInfra.excluded.length, 0)
check('all eight categories costed', fullInfra.applicable.length, 8)

/* ── Line items must sum to the displayed total ──────────────────────────── */

function forecastTotals(evidence: Parameters<typeof allocateCostCategories>[0], rawTotal: number, rate: number) {
  const totalHours = Math.max(1, Math.round(rawTotal / rate))
  const { applicable } = allocateCostCategories(evidence)
  const alloc = applicable.map((entry) => ({ hours: Math.round(totalHours * entry.weight) }))
  const remainder = totalHours - alloc.reduce((sum, a) => sum + a.hours, 0)
  if (remainder !== 0 && alloc.length) {
    const largest = alloc.reduce((mi, a, i, arr) => (a.hours > arr[mi].hours ? i : mi), 0)
    alloc[largest].hours = Math.max(0, alloc[largest].hours + remainder)
  }
  const sumHours = alloc.reduce((sum, a) => sum + a.hours, 0)
  return { totalHours, sumHours, sumUsd: sumHours * rate }
}

for (const raw of [150_480, 156_750, 1_000_000, 8_415]) {
  const t = forecastTotals(
    { vulnerableComponents: 36, certificatesAnalyzed: 3, keysDiscovered: 0, cloudAccounts: 0, assetsAssessed: 2 },
    raw,
    165,
  )
  check(`Σ line hours == total hours (raw=${raw})`, t.sumHours, t.totalHours)
  check(`Σ line cost == normalised total (raw=${raw})`, t.sumUsd, normalizeToWholeHours(raw, DEFAULT_COST_ASSUMPTIONS))
}

/* ── Labour ──────────────────────────────────────────────────────────────── */

check('cost = weeks × lanes × hrs × rate', migrationCostUsd(24, 1, DEFAULT_COST_ASSUMPTIONS), 24 * 1 * 38 * 165)
check('parallel lanes multiply cost', migrationCostUsd(10, 3, DEFAULT_COST_ASSUMPTIONS), 10 * 3 * 38 * 165)
check('no timeline ⇒ no cost', migrationCostUsd(0, 1, DEFAULT_COST_ASSUMPTIONS), 0)
check(
  'tenant rate moves the total',
  migrationCostUsd(24, 1, resolveCostAssumptions({ blendedRateUsd: 200, hoursPerWeek: 40 })),
  24 * 40 * 200,
)

/* ── Assumption resolution ───────────────────────────────────────────────── */

check('no row ⇒ defaults', resolveCostAssumptions(null).source, 'default')
check('any override ⇒ tenant', resolveCostAssumptions({ blendedRateUsd: 200 }).source, 'tenant')
check('snake_case columns resolve', resolveCostAssumptions({ blended_rate_usd: 210 }).blendedRateUsd, 210)
check('unset budget stays null, not zero', resolveCostAssumptions({ blendedRateUsd: 200 }).budgetUsd, null)
check('explicit zero budget is preserved', resolveCostAssumptions({ budgetUsd: 0 }).budgetUsd, 0)
check('rate above max clamps', resolveCostAssumptions({ blendedRateUsd: 999_999 }).blendedRateUsd, COST_ASSUMPTION_LIMITS.blendedRateUsd.max)
check('rate below min clamps', resolveCostAssumptions({ blendedRateUsd: -5 }).blendedRateUsd, COST_ASSUMPTION_LIMITS.blendedRateUsd.min)
check('garbage falls back to default', resolveCostAssumptions({ blendedRateUsd: 'abc' }).blendedRateUsd, 165)

// Provenance must survive a serialise/re-resolve round trip: the API returns an
// already-resolved object and the client re-resolves it. Inferring 'supplied'
// from field presence made defaults claim to be the tenant's own values.
check('re-resolving defaults stays default', resolveCostAssumptions({ ...DEFAULT_COST_ASSUMPTIONS } as unknown as Record<string, unknown>).source, 'default')
check('re-resolving tenant stays tenant', resolveCostAssumptions({ ...resolveCostAssumptions({ blendedRateUsd: 200 }) } as unknown as Record<string, unknown>).source, 'tenant')
check('round-tripped rate is preserved', resolveCostAssumptions({ ...resolveCostAssumptions({ blendedRateUsd: 200 }) } as unknown as Record<string, unknown>).blendedRateUsd, 200)

/* ── Budget variance ─────────────────────────────────────────────────────── */

check('no budget ⇒ no variance panel', buildBudgetVariance(150_480, DEFAULT_COST_ASSUMPTIONS), null)
const over = buildBudgetVariance(150_480, resolveCostAssumptions({ budgetUsd: 100_000 }))
check('over budget detected', over?.status, 'over-budget')
check('over-budget variance', over?.varianceUsd, 50_480)
const within = buildBudgetVariance(150_480, resolveCostAssumptions({ budgetUsd: 200_000 }))
check('within budget detected', within?.status, 'within-budget')
ok('within-budget variance is negative', (within?.varianceUsd ?? 0) < 0)

/* ── Disclosure ──────────────────────────────────────────────────────────── */

const defaultDisclosure = describeCostAssumptions(DEFAULT_COST_ASSUMPTIONS)
ok('defaults are labelled as defaults', /default planning assumptions/i.test(defaultDisclosure))
ok('disclosure names the rate', defaultDisclosure.includes('$165/hr'))
ok('disclosure names hours/week', defaultDisclosure.includes('38 productive'))
ok('disclosure disclaims measurement', /not measured spend/i.test(defaultDisclosure))
ok(
  'tenant values are labelled as theirs',
  /your organisation/i.test(describeCostAssumptions(resolveCostAssumptions({ blendedRateUsd: 200 }))),
)
ok(
  'budget appears in the disclosure once set',
  describeCostAssumptions(resolveCostAssumptions({ budgetUsd: 250_000 })).includes('$250,000'),
)

/* ── Report ──────────────────────────────────────────────────────────────── */

if (failures.length) {
  console.error(`\n✗ ${failures.length} failed, ${passed} passed\n`)
  for (const failure of failures) console.error(`  ✗ ${failure}\n`)
  process.exit(1)
}
console.log(`✓ cost-model: ${passed} checks passed`)
