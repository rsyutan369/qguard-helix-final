/**
 * Quantum Risk Scoring — the pure derivation engine.
 *
 * ── The rule this module exists to enforce ─────────────────────────────────
 * A page called "Quantum Risk Scoring" must publish THE platform's quantum risk
 * score. Not a second one.
 *
 * The implementation this replaces computed its own headline:
 *
 *     quantumRisk = assetAverage*0.42 + highestScore*0.38 + hndlExposure*0.14 + penalty
 *
 * while Quantum Readiness, Harvest Now, the Migration Planner, the certification
 * engine and every report published `snapshot.scores.quantumRisk`. Two scales,
 * one name — so the page dedicated to quantum risk was the one page that
 * disagreed with the platform about quantum risk.
 *
 * Here the headline is READ, never computed. What this engine adds is the thing
 * the snapshot does NOT provide: the decomposition — which assets carry the
 * score, which factors drive it, what would move it, and the evidence behind
 * each claim. Every decomposition is required to reconcile with the headline it
 * decomposes.
 *
 * ── Three inherited traps, closed here ─────────────────────────────────────
 *
 * 1. NO SCORE FLOORS. The old model gave an asset with zero findings a score of
 *    18 for being business-critical, and gave any tenant with one HNDL finding
 *    `clamp(42 + …)`. Criticality is an AMPLIFIER of measured risk, never a
 *    source of it: an asset with no cryptographic evidence has no risk score at
 *    all (`null`), and is reported as unassessed.
 *
 * 2. NO SUBSTRING BUCKETING. The old risk factors matched
 *    `/key|rotation|vault|entropy/` and `/tls|protocol|ssl|cipher/` against
 *    concatenated finding text, so "OpenSSL" scored as an SSL protocol problem
 *    and anything containing "key" became a key-management issue. Factors here
 *    come from the snapshot's own evidence-based factor set.
 *
 * 3. NO TAUTOLOGIES. The old PQC-adoption factor carried
 *    `|| (!pqcAdoptionScore && observations.length > 0)`, which made EVERY
 *    finding match that factor whenever adoption was zero.
 *
 * Pure and dependency-free so the server, the browser and
 * `tools/quantum-risk-check.ts` all read one model.
 */

import {
  EVIDENCE_UNAVAILABLE,
  clamp,
  levelFromRisk,
  num,
  str,
  type AssetMigrationRecord,
} from '@/lib/migration/asset-intelligence'

/* ================================================================== */
/* Vocabulary                                                          */
/* ================================================================== */

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low'

export type ScoreSource = 'quantum-readiness-snapshot' | 'asset-intelligence-portfolio'

/** Assets with no cryptographic evidence are UNASSESSED, never "low risk". */
export type AssessmentState = 'assessed' | 'unassessed'

export interface ScoreCard {
  key: string
  label: string
  /** null = not measurable from the available evidence. Never rendered as 0. */
  score: number | null
  level: string
  detail: string
  /** Which module owns this number — shown so a reader can trace it. */
  source: ScoreSource
  href: string
}

export interface RiskFactorRow {
  key: string
  label: string
  score: number
  level: string
  /** Share of the headline this factor accounts for, normalised across factors. */
  contributionPct: number
  what: string
  evidence: string
  action: string
  actionHref: string
}

export interface RiskAssetRow {
  id: string
  name: string
  type: string
  environment: string
  owner: string
  businessCriticality: string
  internetFacing: boolean
  state: AssessmentState
  /** null when the asset has no cryptographic evidence at all. */
  riskScore: number | null
  riskLevel: string
  hndlScore: number
  posture: string
  postureLabel: string
  migrationStatus: string
  migrationProgressPct: number
  blastRadius: number
  componentCount: number
  vulnerableComponentCount: number
  severityCounts: { critical: number; high: number; medium: number; low: number }
  topAlgorithms: string[]
  /** Why this asset scores what it scores — from the shared posture engine. */
  drivers: Array<{ label: string; contribution: number; evidence: string }>
  recommendation: string
  href: string
}

export interface DistributionRow {
  key: string
  label: string
  glyph: string
  count: number
  percent: number
}

export interface RiskScenario {
  key: string
  label: string
  detail: string
  assetsAffected: number
  /** Projected headline AFTER the action, using the same weighting as the model. */
  projectedRisk: number
  reductionPoints: number
  effort: string
  href: string
}

export interface RiskHeatCell {
  environment: string
  criticality: string
  assets: number
  /** null when no asset in the cell carries cryptographic evidence. */
  averageRisk: number | null
  worstLevel: string
}

export interface CriticalFindingRow {
  id: string
  title: string
  asset: string
  severity: string
  algorithm: string
  detail: string
  detectedAt: string | null
}

export interface RiskTrendPoint {
  label: string
  risk: number
  readiness: number
}

export interface QuantumRiskIntelligence {
  generatedAt: string
  hasData: boolean
  lastAssessmentAt: string | null
  /** The canonical headline, read from the snapshot. */
  headline: {
    score: number
    level: string
    statement: string
    source: ScoreSource
    basis: string
  }
  scoreCards: ScoreCard[]
  factors: RiskFactorRow[]
  /** Findings bucketed by severity — the snapshot's own distribution. */
  findingDistribution: DistributionRow[]
  /** Assets bucketed by their own risk level. A DIFFERENT unit, labelled as such. */
  assetDistribution: DistributionRow[]
  assets: RiskAssetRow[]
  heatmap: RiskHeatCell[]
  scenarios: RiskScenario[]
  criticalFindings: CriticalFindingRow[]
  trend: RiskTrendPoint[]
  coverage: {
    assetsAssessed: number
    assetsWithEvidence: number
    assetsUnassessed: number
    coveragePct: number
    note: string
  }
  filters: { environments: string[]; owners: string[]; criticalities: string[] }
  evidence: { sources: string[]; note: string }
}

/* ================================================================== */
/* Inputs                                                              */
/* ================================================================== */

export interface RiskSnapshotFacts {
  hasData: boolean
  lastAssessmentAt: string | null
  scores: {
    quantumRisk: number
    quantumRiskLevel: string
    hndlRisk: number
    hndlRiskLevel: string
    cryptoExposure: number
    cryptoExposureLevel: string
    quantumReadiness: number
    quantumReadinessLevel: string
    pqcAdoption: number
  }
  inventory: {
    assetsAssessed: number
    cryptoComponents: number
    vulnerableComponents: number
    quantumVulnerableAssets: number
    certificatesAnalyzed: number
  }
  riskDistribution: { critical: number; high: number; medium: number; low: number }
  riskFactors: Array<{ label: string; score: number; severity: string }>
  criticalFindings: Array<Record<string, unknown>>
  riskTrend: Array<{ label: string; risk: number; readiness: number }>
}

export interface QuantumRiskInputs {
  snapshot: RiskSnapshotFacts
  assets: AssetMigrationRecord[]
  now?: number
}

/* ================================================================== */
/* Helpers                                                             */
/* ================================================================== */

const pct = (part: number, total: number) => (total > 0 ? Math.round((part / total) * 100) : 0)

const LEVEL_GLYPH: Record<string, string> = {
  critical: '●',
  high: '●',
  medium: '◐',
  low: '✓',
  unassessed: '?',
}

/**
 * An asset carries a risk score only if something was actually measured on it.
 * `hasEvidence` comes from the shared asset-intelligence engine, which sets it
 * from real components, findings, certificates and runtime observations.
 */
function assessmentState(asset: AssetMigrationRecord): AssessmentState {
  return asset.hasEvidence ? 'assessed' : 'unassessed'
}

/**
 * Factor guidance. Each canonical factor gets a plain-language explanation, the
 * evidence it is computed from, and the one action that moves it — so the page
 * answers "what should I do" rather than only "how bad is it".
 */
const FACTOR_GUIDE: Record<string, { what: string; evidence: string; action: string; href: string }> = {
  'RSA / ECC Exposure': {
    what: 'The share of discovered cryptography that uses RSA or elliptic-curve primitives, both broken by Shor\'s algorithm.',
    evidence: 'Cryptographic components classified vulnerable across the CBOM.',
    action: 'Migrate key establishment to ML-KEM-768 and signatures to ML-DSA-65.',
    href: '/dashboard/migration-planner',
  },
  'HNDL Exposure': {
    what: 'How much long-lived confidential data is protected by a key agreement a future quantum computer can break.',
    evidence: 'Classical key exchange on assets holding data whose confidentiality outlives the CRQC horizon.',
    action: 'Enable hybrid key exchange on the affected transport first.',
    href: '/dashboard/harvest-now',
  },
  'Internet-Facing Exposure': {
    what: 'How much of the vulnerable cryptography is reachable from outside the perimeter.',
    evidence: 'Assets marked internet-facing that still carry quantum-vulnerable cryptography.',
    action: 'Prioritise edge and gateway assets in the migration sequence.',
    href: '/dashboard/exposure-graph',
  },
  'Critical Asset Dependency': {
    what: 'How deeply the vulnerable cryptography is embedded in the dependency graph — the blast radius of a change.',
    evidence: 'Trust and dependency relationships between assets carrying vulnerable cryptography.',
    action: 'Simulate the change in the Migration Sandbox before cutover.',
    href: '/dashboard/migration-sandbox',
  },
  'Severity Pressure': {
    what: 'How concentrated the estate\'s findings are at critical and high severity.',
    evidence: 'Severity distribution of open cryptographic findings.',
    action: 'Clear the critical findings queue in the Remediation Engine.',
    href: '/dashboard/quantum-remediation',
  },
}

/* ================================================================== */
/* Engine                                                              */
/* ================================================================== */

export function buildQuantumRiskIntelligence(inputs: QuantumRiskInputs): QuantumRiskIntelligence {
  const now = inputs.now ?? Date.now()
  const { snapshot } = inputs
  const portfolio = inputs.assets

  /* ---- Headline: read, never computed ------------------------------ */
  const headline = {
    score: snapshot.scores.quantumRisk,
    level: snapshot.scores.quantumRiskLevel,
    statement: snapshot.hasData
      ? `${snapshot.inventory.quantumVulnerableAssets} of ${snapshot.inventory.assetsAssessed} assessed asset(s) carry quantum-vulnerable cryptography.`
      : 'No cryptographic assessment has been recorded for this environment yet.',
    source: 'quantum-readiness-snapshot' as ScoreSource,
    basis:
      'This is the platform quantum risk score published by the Quantum Readiness engine. Every module — Harvest Now, the Migration Planner, the certification engine and the reports — reads the same number, so this page can never disagree with them. What is added below is the decomposition: which assets carry it, which factors drive it and what moves it.',
  }

  /* ---- Score cards: all canonical ----------------------------------- */
  const scoreCards: ScoreCard[] = [
    {
      key: 'quantum-risk',
      label: 'Quantum Risk',
      score: snapshot.hasData ? snapshot.scores.quantumRisk : null,
      level: snapshot.scores.quantumRiskLevel,
      detail: 'Overall exposure to a cryptographically relevant quantum computer',
      source: 'quantum-readiness-snapshot',
      href: '/dashboard/quantum-readiness',
    },
    {
      key: 'hndl',
      label: 'Harvest-Now Risk',
      score: snapshot.hasData ? snapshot.scores.hndlRisk : null,
      level: snapshot.scores.hndlRiskLevel,
      detail: 'Data capturable today and decryptable later',
      source: 'quantum-readiness-snapshot',
      href: '/dashboard/harvest-now',
    },
    {
      key: 'crypto-exposure',
      label: 'Crypto Exposure',
      score: snapshot.hasData ? snapshot.scores.cryptoExposure : null,
      level: snapshot.scores.cryptoExposureLevel,
      detail: 'Breadth of quantum-vulnerable cryptography in the estate',
      source: 'quantum-readiness-snapshot',
      href: '/dashboard/cbom',
    },
    {
      key: 'readiness',
      label: 'Quantum Readiness',
      score: snapshot.hasData ? snapshot.scores.quantumReadiness : null,
      level: snapshot.scores.quantumReadinessLevel,
      detail: 'How far the migration has progressed',
      source: 'quantum-readiness-snapshot',
      href: '/dashboard/quantum-readiness',
    },
    {
      key: 'pqc-adoption',
      label: 'PQC Adoption',
      score: snapshot.hasData ? snapshot.scores.pqcAdoption : null,
      level: levelFromRisk(100 - snapshot.scores.pqcAdoption),
      detail: 'Share of discovered cryptography already post-quantum',
      source: 'quantum-readiness-snapshot',
      href: '/dashboard/quantum-readiness',
    },
  ]

  /* ---- Factors: canonical set, enriched with guidance --------------- */
  const factorTotal = snapshot.riskFactors.reduce((sum, factor) => sum + Math.max(0, factor.score), 0)
  const factors: RiskFactorRow[] = snapshot.riskFactors.map((factor) => {
    const guide = FACTOR_GUIDE[factor.label] ?? {
      what: 'A measured contributor to the estate\'s quantum risk.',
      evidence: 'Derived by the Quantum Readiness engine from tenant evidence.',
      action: 'Review the underlying findings.',
      href: '/dashboard/quantum-readiness',
    }
    return {
      key: factor.label.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      label: factor.label,
      score: factor.score,
      level: factor.severity,
      // Share of the summed factor weight. States how much of the picture each
      // factor accounts for WITHOUT pretending to be an exact causal split of
      // the headline, which the snapshot does not publish.
      contributionPct: factorTotal > 0 ? Math.round((Math.max(0, factor.score) / factorTotal) * 100) : 0,
      what: guide.what,
      evidence: guide.evidence,
      action: guide.action,
      actionHref: guide.href,
    }
  })

  /* ---- Finding distribution: canonical ------------------------------ */
  const dist = snapshot.riskDistribution
  const findingTotal = dist.critical + dist.high + dist.medium + dist.low
  const findingDistribution: DistributionRow[] = (
    [
      ['critical', 'Critical', dist.critical],
      ['high', 'High', dist.high],
      ['medium', 'Medium', dist.medium],
      ['low', 'Low', dist.low],
    ] as Array<[string, string, number]>
  ).map(([key, label, count]) => ({
    key,
    label,
    glyph: LEVEL_GLYPH[key] ?? '·',
    count,
    percent: pct(count, findingTotal),
  }))

  /* ---- Per-asset decomposition -------------------------------------- */
  const assets: RiskAssetRow[] = portfolio.map((asset) => {
    const state = assessmentState(asset)
    return {
      id: asset.id,
      name: asset.name,
      type: asset.type,
      environment: asset.environment || 'unspecified',
      owner: asset.owner || 'Unassigned',
      businessCriticality: asset.businessCriticality || 'unspecified',
      internetFacing: asset.internetFacing,
      state,
      // An asset with no cryptographic evidence has NO risk score. Publishing 0
      // would read as "measured and safe"; publishing a criticality-derived
      // number would invent risk from an attribute.
      riskScore: state === 'assessed' ? Math.round(asset.riskScore) : null,
      riskLevel: state === 'assessed' ? asset.riskLevel : 'Not Assessed',
      hndlScore: Math.round(asset.hndlScore),
      posture: asset.posture,
      postureLabel: asset.postureLabel,
      migrationStatus: asset.migrationStatus,
      migrationProgressPct: Math.round(asset.migrationProgressPct),
      blastRadius: asset.blastRadius,
      componentCount: asset.componentCount,
      vulnerableComponentCount: asset.vulnerableComponentCount,
      severityCounts: asset.severityCounts,
      topAlgorithms: asset.algorithms.slice(0, 4).map((row) => row.algorithm),
      drivers: asset.priorityFactors.map((factor) => ({
        label: factor.label,
        contribution: Math.round(factor.contribution),
        evidence: factor.evidence,
      })),
      recommendation: asset.recommendations[0]?.title ?? (state === 'assessed' ? 'No remediation recorded for this asset.' : 'Run a cryptographic scan to assess this asset.'),
      href: `/dashboard/migration-planner?asset=${encodeURIComponent(asset.id)}`,
    }
  })

  const assessed = assets.filter((asset) => asset.state === 'assessed')

  /* ---- Asset distribution ------------------------------------------- */
  const bucket = (level: string) => {
    const normalised = level.toLowerCase()
    if (normalised.includes('critical')) return 'critical'
    if (normalised.includes('high')) return 'high'
    if (normalised.includes('elevated') || normalised.includes('moderate') || normalised.includes('medium')) return 'medium'
    return 'low'
  }
  const assetBuckets: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const asset of assessed) assetBuckets[bucket(asset.riskLevel)] += 1
  const unassessed = assets.length - assessed.length
  const assetDistribution: DistributionRow[] = [
    { key: 'critical', label: 'Critical', glyph: '●', count: assetBuckets.critical, percent: pct(assetBuckets.critical, assets.length) },
    { key: 'high', label: 'High', glyph: '●', count: assetBuckets.high, percent: pct(assetBuckets.high, assets.length) },
    { key: 'medium', label: 'Elevated', glyph: '◐', count: assetBuckets.medium, percent: pct(assetBuckets.medium, assets.length) },
    { key: 'low', label: 'Low', glyph: '✓', count: assetBuckets.low, percent: pct(assetBuckets.low, assets.length) },
    { key: 'unassessed', label: 'Not Assessed', glyph: '?', count: unassessed, percent: pct(unassessed, assets.length) },
  ]

  /* ---- Heatmap: environment × criticality ---------------------------- */
  const heatIndex = new Map<string, { assets: RiskAssetRow[] }>()
  for (const asset of assets) {
    const key = `${asset.environment}::${asset.businessCriticality}`
    const entry = heatIndex.get(key) ?? { assets: [] }
    entry.assets.push(asset)
    heatIndex.set(key, entry)
  }
  const heatmap: RiskHeatCell[] = Array.from(heatIndex.entries())
    .map(([key, entry]) => {
      const [environment, criticality] = key.split('::')
      const scored = entry.assets.filter((asset) => asset.riskScore !== null)
      const worst = scored.reduce((acc, asset) => Math.max(acc, asset.riskScore ?? 0), 0)
      return {
        environment,
        criticality,
        assets: entry.assets.length,
        averageRisk: scored.length ? Math.round(scored.reduce((sum, asset) => sum + (asset.riskScore ?? 0), 0) / scored.length) : null,
        worstLevel: scored.length ? levelFromRisk(worst) : 'Not Assessed',
      }
    })
    .sort((a, b) => (b.averageRisk ?? -1) - (a.averageRisk ?? -1))

  /* ---- Scenarios ------------------------------------------------------ */
  const scenarios = buildScenarios(headline.score, assessed, snapshot)

  /* ---- Critical findings: canonical ----------------------------------- */
  const criticalFindings: CriticalFindingRow[] = snapshot.criticalFindings.slice(0, 20).map((finding, index) => ({
    id: str(finding.id) || `finding-${index}`,
    title: str(finding.title) || str(finding.finding) || 'Cryptographic finding',
    asset: str(finding.asset) || str(finding.assetName) || 'Unattributed',
    severity: str(finding.severity) || str(finding.threatLevel) || 'high',
    algorithm: str(finding.algorithm) || '',
    detail: str(finding.description) || str(finding.detail) || '',
    detectedAt: str(finding.detectedAt) || str(finding.created_at) || null,
  }))

  /* ---- Coverage -------------------------------------------------------- */
  const coverage = {
    assetsAssessed: assets.length,
    assetsWithEvidence: assessed.length,
    assetsUnassessed: unassessed,
    coveragePct: pct(assessed.length, assets.length),
    note:
      unassessed > 0
        ? `${unassessed} asset(s) carry no cryptographic evidence and are excluded from every risk average rather than scored as low risk.`
        : 'Every discovered asset carries cryptographic evidence.',
  }

  return {
    generatedAt: new Date(now).toISOString(),
    hasData: snapshot.hasData,
    lastAssessmentAt: snapshot.lastAssessmentAt,
    headline,
    scoreCards,
    factors,
    findingDistribution,
    assetDistribution,
    assets: assets.sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1) || a.name.localeCompare(b.name)),
    heatmap,
    scenarios,
    criticalFindings,
    trend: snapshot.riskTrend,
    coverage,
    filters: {
      environments: Array.from(new Set(assets.map((a) => a.environment).filter((v) => v && v !== 'unspecified'))).sort(),
      owners: Array.from(new Set(assets.map((a) => a.owner).filter((v) => v && v !== 'Unassigned'))).sort(),
      criticalities: Array.from(new Set(assets.map((a) => a.businessCriticality).filter((v) => v && v !== 'unspecified'))).sort(),
    },
    evidence: {
      sources: ['Quantum Readiness Snapshot', 'Asset Intelligence Portfolio', 'PQC Scanner', 'CBOM / Crypto Inventory'],
      note: snapshot.hasData
        ? `Headline scores are read from the Quantum Readiness snapshot (${snapshot.inventory.assetsAssessed} assets, ${snapshot.inventory.cryptoComponents} crypto components, ${snapshot.inventory.certificatesAnalyzed} certificates). Per-asset decomposition comes from the shared asset-intelligence engine that also backs the Migration Planner, so an asset reads identically on both pages.`
        : `${EVIDENCE_UNAVAILABLE}. No scans, assets or cryptographic inventory recorded for this tenant.`,
    },
  }
}

/* ================================================================== */
/* Scenarios                                                           */
/* ================================================================== */

/**
 * Projected risk reduction.
 *
 * These are PROJECTIONS, and the model says so: each scenario removes the
 * vulnerable-component contribution of a named set of assets and rescales the
 * headline by the resulting change in vulnerable share. It never claims a
 * simulated or validated outcome — the Migration Sandbox owns simulation.
 *
 * A scenario with no assets in scope is still returned, with zero reduction, so
 * the UI can show it as not applicable instead of silently dropping it.
 */
function buildScenarios(headlineScore: number, assessed: RiskAssetRow[], snapshot: RiskSnapshotFacts): RiskScenario[] {
  const totalVulnerable = assessed.reduce((sum, asset) => sum + asset.vulnerableComponentCount, 0)

  const project = (assets: RiskAssetRow[]): { projected: number; reduction: number } => {
    if (!assets.length || totalVulnerable <= 0) return { projected: headlineScore, reduction: 0 }
    const removed = assets.reduce((sum, asset) => sum + asset.vulnerableComponentCount, 0)
    const share = Math.min(1, removed / totalVulnerable)
    const projected = Math.round(clamp(headlineScore * (1 - share)))
    return { projected, reduction: Math.max(0, headlineScore - projected) }
  }

  const internetFacing = assessed.filter((asset) => asset.internetFacing && asset.vulnerableComponentCount > 0)
  const criticalAssets = assessed.filter((asset) => /critical/i.test(asset.businessCriticality) && asset.vulnerableComponentCount > 0)
  const topFive = [...assessed].filter((a) => a.vulnerableComponentCount > 0).sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0)).slice(0, 5)
  const hndlAssets = assessed.filter((asset) => asset.hndlScore >= 60 && asset.vulnerableComponentCount > 0)

  const definitions: Array<{ key: string; label: string; detail: string; rows: RiskAssetRow[]; effort: string; href: string }> = [
    {
      key: 'top-five',
      label: 'Remediate the top 5 highest-risk assets',
      detail: 'Migrate the five assets carrying the most measured risk to the approved post-quantum stack.',
      rows: topFive,
      effort: 'Medium',
      href: '/dashboard/migration-planner',
    },
    {
      key: 'internet-facing',
      label: 'Remediate all internet-facing assets',
      detail: 'Close the externally reachable attack surface first — it is the part an adversary can capture today.',
      rows: internetFacing,
      effort: 'High',
      href: '/dashboard/exposure-graph',
    },
    {
      key: 'critical-tier',
      label: 'Remediate business-critical assets',
      detail: 'Clear quantum-vulnerable cryptography from every asset classified business-critical.',
      rows: criticalAssets,
      effort: 'High',
      href: '/dashboard/migration-planner',
    },
    {
      key: 'hndl',
      label: 'Close harvest-now exposure',
      detail: 'Enable hybrid key agreement on the assets whose data outlives the quantum horizon.',
      rows: hndlAssets,
      effort: 'Medium',
      href: '/dashboard/harvest-now',
    },
  ]

  return definitions
    .map((definition) => {
      const { projected, reduction } = project(definition.rows)
      return {
        key: definition.key,
        label: definition.label,
        detail: definition.detail,
        assetsAffected: definition.rows.length,
        projectedRisk: projected,
        reductionPoints: reduction,
        effort: definition.effort,
        href: definition.href,
      }
    })
    .sort((a, b) => b.reductionPoints - a.reductionPoints || b.assetsAffected - a.assetsAffected)
}

/* ================================================================== */
/* Client-side filtering (shared by the page and the server feed)      */
/* ================================================================== */

export interface RiskAssetFilters {
  environment: string
  owner: string
  criticality: string
  level: string
  search: string
}

export const EMPTY_RISK_FILTERS: RiskAssetFilters = {
  environment: 'all',
  owner: 'all',
  criticality: 'all',
  level: 'all',
  search: '',
}

export function filterRiskAssets(rows: RiskAssetRow[], filters: RiskAssetFilters): RiskAssetRow[] {
  const search = filters.search.trim().toLowerCase()
  return rows.filter((row) => {
    if (filters.environment !== 'all' && row.environment !== filters.environment) return false
    if (filters.owner !== 'all' && row.owner !== filters.owner) return false
    if (filters.criticality !== 'all' && row.businessCriticality !== filters.criticality) return false
    if (filters.level !== 'all') {
      if (filters.level === 'unassessed') {
        if (row.state !== 'unassessed') return false
      } else if (row.state !== 'assessed' || !row.riskLevel.toLowerCase().includes(filters.level)) {
        return false
      }
    }
    if (search) {
      const haystack = `${row.name} ${row.type} ${row.owner} ${row.environment} ${row.topAlgorithms.join(' ')}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })
}

/** Bounded numeric guard used by the check tool and the UI alike. */
export function riskBand(score: number | null): RiskLevel | 'unassessed' {
  if (score === null) return 'unassessed'
  const value = num(score)
  if (value >= 75) return 'critical'
  if (value >= 50) return 'high'
  if (value >= 25) return 'medium'
  return 'low'
}
