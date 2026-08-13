/**
 * Migration cost & business-value model — ONE implementation, every surface.
 *
 * Pure and dependency-free (no Express, no Supabase) so the API, the report
 * engine, the dashboards and `tools/cost-model-check.ts` share one set of
 * numbers instead of each holding an opinion.
 *
 * ── Why this module exists ──────────────────────────────────────────────────
 * Three cost/value models used to run in parallel and disagree on screen:
 *
 *   Migration Planner   "Projected Risk-Reduction Value  $352,688"
 *   Executive dashboard "Financial Exposure  $80,000 · Projected ROI  51%"
 *
 * The planner figure was `totalCost × reductionPct × 3` — the `× 3` an uncited
 * constant. Because `reductionPct` saturates at 75% for any tenant whose
 * quantumRisk exceeds 40, that expression collapsed to a fixed **2.25 × cost**
 * for essentially every tenant: a constant ratio presented as an analysis. It
 * also claimed a return 4.4× larger than the total exposure the platform itself
 * computed, which cannot be true — you cannot avoid more loss than you are
 * exposed to.
 *
 * Value now comes from ONE place (`buildFinancialExposure`) and risk-reduction
 * value is a fraction OF that exposure, hard-capped by it.
 *
 * ── Assumptions are inputs, not facts ───────────────────────────────────────
 * Every constant here is a planning assumption a tenant can override, and each
 * one is published with the figure it produces (`describeCostAssumptions`) so a
 * reader can see what the number rests on. Defaults are conservative industry
 * planning figures — they are NOT measurements, and nothing in this module may
 * be presented as telemetry.
 */

export type CostAssumptionSource = 'default' | 'tenant'

export interface CostAssumptions {
  /** Blended engineer cost per hour, in `currency`. */
  blendedRateUsd: number
  /** Productive engineering hours per person per week. */
  hoursPerWeek: number
  /** Planning value of one business-critical asset (breach / outage exposure). */
  valuePerCriticalAssetUsd: number
  /** Planning value of one standard asset. */
  valuePerStandardAssetUsd: number
  /** Tenant's own approved budget. `null` = not supplied; never invent one. */
  budgetUsd: number | null
  currency: string
  source: CostAssumptionSource
  updatedAt: string | null
}

export const DEFAULT_COST_ASSUMPTIONS: CostAssumptions = {
  blendedRateUsd: 165,
  hoursPerWeek: 38,
  valuePerCriticalAssetUsd: 250_000,
  valuePerStandardAssetUsd: 40_000,
  budgetUsd: null,
  currency: 'USD',
  source: 'default',
  updatedAt: null,
}

/** Bounds keep a typo (or a hostile payload) from producing an absurd forecast. */
export const COST_ASSUMPTION_LIMITS = {
  blendedRateUsd: { min: 1, max: 2_000 },
  hoursPerWeek: { min: 1, max: 80 },
  valuePerCriticalAssetUsd: { min: 0, max: 1_000_000_000 },
  valuePerStandardAssetUsd: { min: 0, max: 1_000_000_000 },
  budgetUsd: { min: 0, max: 10_000_000_000 },
} as const

const isFiniteNumber = (value: unknown): value is number =>
  typeof value === 'number' ? Number.isFinite(value) : Number.isFinite(Number(value)) && String(value).trim() !== ''

function bounded(value: unknown, fallback: number, limits: { min: number; max: number }): number {
  if (value === null || value === undefined || value === '') return fallback
  if (!isFiniteNumber(value)) return fallback
  return Math.min(limits.max, Math.max(limits.min, Number(value)))
}

/**
 * Coerce a stored row (or a request body) into usable assumptions.
 *
 * Any field the tenant has not set falls back to the published default, and the
 * result reports whether ANY field came from the tenant so the UI can say
 * "your assumptions" rather than implying the defaults were chosen.
 */
export function resolveCostAssumptions(stored: Record<string, unknown> | null | undefined): CostAssumptions {
  if (!stored || typeof stored !== 'object') return { ...DEFAULT_COST_ASSUMPTIONS }

  const pick = (...keys: string[]) => {
    for (const key of keys) {
      const value = (stored as Record<string, unknown>)[key]
      if (value !== undefined && value !== null && value !== '') return value
    }
    return undefined
  }

  const rate = pick('blendedRateUsd', 'blended_rate_usd')
  const hours = pick('hoursPerWeek', 'hours_per_week')
  const critical = pick('valuePerCriticalAssetUsd', 'value_per_critical_asset_usd')
  const standard = pick('valuePerStandardAssetUsd', 'value_per_standard_asset_usd')
  const budget = pick('budgetUsd', 'budget_usd')
  const currency = pick('currency')
  const updatedAt = pick('updatedAt', 'updated_at')

  /* Provenance must survive a round trip. The API serialises an already-resolved
     object (every field populated) and the client re-resolves it; inferring
     `supplied` from field presence alone then flipped `source` to 'tenant' and
     the Executive page told a tenant "Your organisation's assumptions" for
     values they never set. An explicit `source` on the input always wins. */
  const declaredSource = pick('source')
  const supplied =
    declaredSource === 'tenant' ||
    declaredSource === 'default'
      ? declaredSource === 'tenant'
      : [rate, hours, critical, standard, budget].some((value) => value !== undefined)

  return {
    blendedRateUsd: Math.round(bounded(rate, DEFAULT_COST_ASSUMPTIONS.blendedRateUsd, COST_ASSUMPTION_LIMITS.blendedRateUsd)),
    hoursPerWeek: Math.round(bounded(hours, DEFAULT_COST_ASSUMPTIONS.hoursPerWeek, COST_ASSUMPTION_LIMITS.hoursPerWeek)),
    valuePerCriticalAssetUsd: Math.round(
      bounded(critical, DEFAULT_COST_ASSUMPTIONS.valuePerCriticalAssetUsd, COST_ASSUMPTION_LIMITS.valuePerCriticalAssetUsd),
    ),
    valuePerStandardAssetUsd: Math.round(
      bounded(standard, DEFAULT_COST_ASSUMPTIONS.valuePerStandardAssetUsd, COST_ASSUMPTION_LIMITS.valuePerStandardAssetUsd),
    ),
    budgetUsd:
      budget === undefined || budget === null || budget === ''
        ? null
        : Math.round(bounded(budget, 0, COST_ASSUMPTION_LIMITS.budgetUsd)),
    currency: typeof currency === 'string' && currency.trim() ? currency.trim().toUpperCase().slice(0, 8) : 'USD',
    source: supplied ? 'tenant' : 'default',
    updatedAt: typeof updatedAt === 'string' && updatedAt ? updatedAt : null,
  }
}

/* ------------------------------------------------------------------ */
/* Financial exposure — the single value model                         */
/* ------------------------------------------------------------------ */

export interface ExposureInput {
  /** Quantum-vulnerable assets (canonical snapshot count). */
  vulnerableAssets: number
  /** Assets carrying a business-criticality tag of critical/high. */
  taggedCriticalAssets: number
  /** Assets already PQC-ready. */
  pqcReadyAssets: number
}

export interface FinancialExposure {
  /** Loss exposure attributable to assets that are still quantum-vulnerable. */
  financialExposureUsd: number
  /** Value already protected by assets that are PQC-ready. */
  revenueProtectedUsd: number
  criticalVulnerableAssets: number
  standardVulnerableAssets: number
  /** False when no asset carries a business-criticality tag, so every vulnerable
   *  asset was valued at the STANDARD rate. Consumers must disclose this rather
   *  than implying the estate contains no critical systems. */
  criticalityTagged: boolean
}

/**
 * Exposure over real asset counts and published per-asset values.
 *
 * Note the deliberate asymmetry with crypto risk: "critical" here is the
 * BUSINESS-criticality tag, not the quantum-vulnerability verdict. An untagged
 * estate values every asset at the standard rate — which understates exposure,
 * the safe direction, and `criticalityTagged` says so.
 */
export function buildFinancialExposure(input: ExposureInput, assumptions: CostAssumptions): FinancialExposure {
  const vulnerableAssets = Math.max(0, Math.round(input.vulnerableAssets || 0))
  const taggedCriticalAssets = Math.max(0, Math.round(input.taggedCriticalAssets || 0))
  const pqcReadyAssets = Math.max(0, Math.round(input.pqcReadyAssets || 0))

  const criticalVulnerableAssets = Math.min(vulnerableAssets, taggedCriticalAssets)
  const standardVulnerableAssets = Math.max(0, vulnerableAssets - criticalVulnerableAssets)

  const financialExposureUsd =
    criticalVulnerableAssets * assumptions.valuePerCriticalAssetUsd +
    standardVulnerableAssets * assumptions.valuePerStandardAssetUsd

  const revenueProtectedUsd =
    pqcReadyAssets * assumptions.valuePerStandardAssetUsd +
    Math.min(pqcReadyAssets, taggedCriticalAssets) *
      Math.max(0, assumptions.valuePerCriticalAssetUsd - assumptions.valuePerStandardAssetUsd)

  return {
    financialExposureUsd,
    revenueProtectedUsd,
    criticalVulnerableAssets,
    standardVulnerableAssets,
    criticalityTagged: taggedCriticalAssets > 0,
  }
}

/**
 * Value of the risk the programme removes.
 *
 * A fraction OF measured exposure, never a multiple of what the programme
 * costs, and hard-capped at exposure: avoided loss cannot exceed the loss you
 * were exposed to. Returns 0 when exposure is 0 — with nothing valued there is
 * nothing to claim, and a zero here must render as "not modelled", never as a
 * promise of no benefit.
 */
export function projectedRiskReductionValueUsd(exposureUsd: number, reductionPct: number): number {
  if (!(exposureUsd > 0) || !(reductionPct > 0)) return 0
  const fraction = Math.min(100, Math.max(0, reductionPct)) / 100
  return Math.min(Math.round(exposureUsd), Math.round(exposureUsd * fraction))
}

/* ------------------------------------------------------------------ */
/* Labour                                                              */
/* ------------------------------------------------------------------ */

/** Programme cost = calendar weeks × parallel lanes × hours/week × rate. */
export function migrationCostUsd(
  timelineWeeks: number,
  parallelWorkstreams: number,
  assumptions: CostAssumptions,
): number {
  if (!(timelineWeeks > 0)) return 0
  const lanes = Math.max(1, Math.round(parallelWorkstreams || 1))
  return Math.round(timelineWeeks * lanes * assumptions.hoursPerWeek * assumptions.blendedRateUsd)
}

/** Budget normalised to whole labour-hours, so no surface prints a cost that
 *  is not an exact `hours × rate` product. */
export function normalizeToWholeHours(rawUsd: number, assumptions: CostAssumptions): number {
  const rate = assumptions.blendedRateUsd
  return rawUsd > 0 ? Math.max(1, Math.round(rawUsd / rate)) * rate : 0
}

/* ------------------------------------------------------------------ */
/* Cost categories — measured vs not measured                          */
/* ------------------------------------------------------------------ */

export interface CostCategoryDefinition {
  category: string
  /** Share of programme labour when this category applies. */
  weight: number
  /**
   * Inventory this category spends against. When the evidence key resolves to
   * zero the category is EXCLUDED and its weight redistributed — a budget line
   * for hardware the scan never found is a fabricated number, and Rule 3 of the
   * data-integrity contract requires "not measured" to render as such with a
   * reason rather than as a figure.
   */
  requires?: { key: keyof CostEvidence; label: string; route?: string }
}

export interface CostEvidence {
  vulnerableComponents: number
  certificatesAnalyzed: number
  keysDiscovered: number
  cloudAccounts: number
  assetsAssessed: number
}

export const COST_CATEGORIES: CostCategoryDefinition[] = [
  { category: 'Infrastructure / TLS Upgrades', weight: 0.22 },
  {
    category: 'PKI & Certificate Modernization',
    weight: 0.18,
    requires: { key: 'certificatesAnalyzed', label: 'certificate inventory', route: '/dashboard/pki-visibility' },
  },
  {
    category: 'Cloud / KMS',
    weight: 0.1,
    requires: { key: 'cloudAccounts', label: 'connected cloud accounts', route: '/dashboard/settings' },
  },
  {
    category: 'HSM',
    weight: 0.08,
    requires: { key: 'keysDiscovered', label: 'key inventory (QKMS)', route: '/dashboard/qkms/overview' },
  },
  { category: 'Validation & Testing', weight: 0.12 },
  { category: 'Staff Time & Training', weight: 0.18 },
  { category: 'Consulting', weight: 0.06 },
  { category: 'Operations & Support', weight: 0.06 },
]

export interface CostAllocation {
  applicable: Array<{ category: string; weight: number }>
  excluded: Array<{ category: string; reason: string; route?: string }>
}

/**
 * Split the categories into those the evidence supports and those it does not,
 * renormalising the applicable weights back to 1 so the total is unchanged and
 * the surviving lines still sum to it exactly.
 */
export function allocateCostCategories(evidence: CostEvidence): CostAllocation {
  const applicable: CostAllocation['applicable'] = []
  const excluded: CostAllocation['excluded'] = []

  for (const definition of COST_CATEGORIES) {
    const requirement = definition.requires
    const measured = requirement ? Number(evidence[requirement.key] || 0) > 0 : true
    if (measured) applicable.push({ category: definition.category, weight: definition.weight })
    else
      excluded.push({
        category: definition.category,
        reason: `No ${requirement!.label} discovered — not costed`,
        route: requirement!.route,
      })
  }

  // Everything excluded (no evidence at all): fall back to the full set rather
  // than returning a zero forecast, and let the caller's hasData gate decide.
  if (!applicable.length) return { applicable: COST_CATEGORIES.map((c) => ({ category: c.category, weight: c.weight })), excluded: [] }

  const totalWeight = applicable.reduce((sum, entry) => sum + entry.weight, 0) || 1
  return {
    applicable: applicable.map((entry) => ({ ...entry, weight: entry.weight / totalWeight })),
    excluded,
  }
}

/* ------------------------------------------------------------------ */
/* Disclosure                                                          */
/* ------------------------------------------------------------------ */

export function formatUsd(value: number, currency = 'USD'): string {
  const rounded = Math.round(value || 0)
  return currency === 'USD' ? `$${rounded.toLocaleString('en-US')}` : `${rounded.toLocaleString('en-US')} ${currency}`
}

/**
 * The line every cost surface prints beside its figures. A planning estimate
 * that does not show its inputs is indistinguishable from a measurement.
 */
export function describeCostAssumptions(assumptions: CostAssumptions): string {
  const origin =
    assumptions.source === 'tenant'
      ? 'Your organisation’s assumptions'
      : 'Default planning assumptions (editable)'
  const budget = assumptions.budgetUsd !== null ? ` Approved budget ${formatUsd(assumptions.budgetUsd, assumptions.currency)}.` : ''
  return (
    `${origin}: blended engineer rate ${formatUsd(assumptions.blendedRateUsd, assumptions.currency)}/hr, ` +
    `${assumptions.hoursPerWeek} productive hrs/week, per-asset value ` +
    `${formatUsd(assumptions.valuePerCriticalAssetUsd, assumptions.currency)} business-critical / ` +
    `${formatUsd(assumptions.valuePerStandardAssetUsd, assumptions.currency)} standard.${budget} ` +
    `Planning estimate over measured asset counts — not measured spend or revenue.`
  )
}

export interface BudgetVariance {
  budgetUsd: number
  estimateUsd: number
  varianceUsd: number
  variancePct: number
  status: 'within-budget' | 'over-budget'
}

/** Only meaningful once a tenant supplies a budget; returns null otherwise. */
export function buildBudgetVariance(estimateUsd: number, assumptions: CostAssumptions): BudgetVariance | null {
  if (assumptions.budgetUsd === null || !(assumptions.budgetUsd > 0)) return null
  const varianceUsd = Math.round(estimateUsd - assumptions.budgetUsd)
  return {
    budgetUsd: assumptions.budgetUsd,
    estimateUsd: Math.round(estimateUsd),
    varianceUsd,
    variancePct: Math.round((varianceUsd / assumptions.budgetUsd) * 100),
    status: varianceUsd > 0 ? 'over-budget' : 'within-budget',
  }
}
