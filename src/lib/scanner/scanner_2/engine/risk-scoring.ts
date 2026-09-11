/**
 * QGuard Quantum Risk Scoring Engine
 * Calculates risk scores on a 0-1000 scale (higher = safer).
 */

import type { ScanFinding, QuantumRiskScore, QScoreTrend } from '@/types/scanner.types'
import type { QuantumThreatLevel } from '@/types/quantum.types'

// ─── Constants ─────────────────────────────────────────────────

/** Category weights used in the weighted overall score calculation. */
const CATEGORY_WEIGHTS = {
  devices: 0.20,
  networks: 0.20,
  cloud: 0.15,
  blockchain: 0.10,
  telecom: 0.10,
  applications: 0.15,
  infrastructure: 0.10,
} as const

/**
 * Score shown for a category this run did not observe.
 *
 * THIS IS A DISPLAY PLACEHOLDER ONLY — it never enters `overall`.
 *
 * It used to be 850 AND to carry its full weight into the weighted mean, which
 * inverted the platform's "unmeasured is not zero" rule into something worse:
 * unmeasured read as GOOD. A web scan reaches `networks` and `applications`
 * only, so devices, cloud, blockchain, telecom and infrastructure — 0.65 of the
 * total weight — were a constant describing nothing. A real Google endpoint
 * measured networks 440 / applications 720 and still published
 * "749 · moderate-risk", because 65% of that number was the constant. That is
 * the row operators saw beside a Critical grade on every other panel.
 *
 * Unmeasured categories now leave the denominator entirely (see below), exactly
 * as the published grading model already redistributes weight for inapplicable
 * categories.
 */
const UNMEASURED_CATEGORY_DISPLAY_SCORE = 0

/** Module ID prefix mappings to categories. */
const NETWORK_PREFIXES = ['network-', 'tls-', 'cert-', 'vpn-', 'ssh-', 'dns-']
const BLOCKCHAIN_PREFIXES = ['blockchain-', 'crypto-', 'smart-', 'web3-']
const TELECOM_PREFIXES = ['telecom-', 'mobile-', 'satellite-', 'secure-messaging-']

// ─── Category Classification ──────────────────────────────────

type CategoryKey = keyof typeof CATEGORY_WEIGHTS

/**
 * Determine the risk category for a finding based on its moduleId prefix.
 */
function classifyFinding(finding: ScanFinding): CategoryKey {
  const id = finding.moduleId

  if (id.startsWith('device-')) return 'devices'

  for (const prefix of NETWORK_PREFIXES) {
    if (id.startsWith(prefix)) return 'networks'
  }

  if (id.startsWith('cloud-')) return 'cloud'

  for (const prefix of BLOCKCHAIN_PREFIXES) {
    if (id.startsWith(prefix)) return 'blockchain'
  }

  for (const prefix of TELECOM_PREFIXES) {
    if (id.startsWith(prefix)) return 'telecom'
  }

  if (id.startsWith('infra-') || id.startsWith('infrastructure-')) {
    return 'infrastructure'
  }

  // Default: application-level findings
  return 'applications'
}

// ─── Score Calculation ─────────────────────────────────────────

/**
 * Calculate the quantum risk score for a set of scan findings.
 * Returns a QuantumRiskScore on the 0-1000 scale.
 */
export function calculateQuantumRiskScore(
  findings: ScanFinding[]
): QuantumRiskScore {
  // Group findings by category
  const categoryFindings: Record<CategoryKey, ScanFinding[]> = {
    devices: [],
    networks: [],
    cloud: [],
    blockchain: [],
    telecom: [],
    applications: [],
    infrastructure: [],
  }

  let criticalCount = 0
  let highCount = 0
  let moderateCount = 0
  let lowCount = 0
  let hndlRiskCount = 0

  for (const finding of findings) {
    const category = classifyFinding(finding)
    categoryFindings[category].push(finding)

    switch (finding.severity) {
      case 'critical':
        criticalCount++
        break
      case 'high':
        highCount++
        break
      case 'moderate':
        moderateCount++
        break
      case 'low':
        lowCount++
        break
    }

    if (finding.isHNDLRisk) {
      hndlRiskCount++
    }
  }

  // Calculate per-category scores. A category with no findings was not
  // observed on this run and is recorded as unmeasured, never as a score.
  const breakdown = {} as QuantumRiskScore['breakdown']
  const categories = Object.keys(CATEGORY_WEIGHTS) as CategoryKey[]
  const measuredCategories: CategoryKey[] = []

  for (const category of categories) {
    const catFindings = categoryFindings[category]
    if (catFindings.length === 0) {
      breakdown[category] = UNMEASURED_CATEGORY_DISPLAY_SCORE
      continue
    }
    measuredCategories.push(category)
    const avgRisk =
      catFindings.reduce((sum, f) => sum + f.riskScore, 0) / catFindings.length
    // Score = 1000 minus average risk (clamped to 0-1000). `riskScore` is
    // Scanner_2's 0-1000 scale; see `riskScoreToScanner2Severity`.
    breakdown[category] = Math.max(0, Math.min(1000, Math.round(1000 - avgRisk)))
  }

  /* Weighted over the MEASURED categories only, with the unmeasured weight
     redistributed. Averaging in a placeholder for a category nobody scanned
     publishes a posture the platform never measured — and because the
     placeholder was a passing 850, it published a *better* posture the less the
     scan covered. */
  const measuredWeight = measuredCategories.reduce((sum, category) => sum + CATEGORY_WEIGHTS[category], 0)
  let overall = 0
  if (measuredWeight > 0) {
    for (const category of measuredCategories) {
      overall += breakdown[category] * CATEGORY_WEIGHTS[category]
    }
    overall = Math.max(0, Math.min(1000, Math.round(overall / measuredWeight)))
  }

  const level = scoreToRiskLevel(overall)
  const trend = generateTrend(overall)

  return {
    overall,
    level,
    breakdown,
    criticalCount,
    highCount,
    moderateCount,
    lowCount,
    totalFindings: findings.length,
    hndlRiskCount,
    lastScanAt: new Date().toISOString(),
    trend,
    measuredCategories,
    measuredWeight: Number(measuredWeight.toFixed(4)),
  }
}

// ─── Risk Level Mapping ────────────────────────────────────────

/**
 * Map a 0-1000 score to a risk level.
 *
 * 900-1000 -> quantum-safe
 * 700-899  -> moderate-risk
 * 400-699  -> vulnerable
 * 0-399    -> critical-risk
 */
export function scoreToRiskLevel(
  score: number
): 'quantum-safe' | 'moderate-risk' | 'vulnerable' | 'critical-risk' {
  if (score >= 900) return 'quantum-safe'
  if (score >= 700) return 'moderate-risk'
  if (score >= 400) return 'vulnerable'
  return 'critical-risk'
}

/**
 * Return a color string appropriate for the risk level.
 */
export function getRiskColor(score: number): string {
  const level = scoreToRiskLevel(score)
  switch (level) {
    case 'quantum-safe':
      return '#22c55e' // green
    case 'moderate-risk':
      return '#3b82f6' // blue
    case 'vulnerable':
      return '#eab308' // yellow
    case 'critical-risk':
      return '#ef4444' // red
  }
}

/**
 * Return a human-readable label for the score.
 */
export function getRiskLabel(score: number): string {
  const level = scoreToRiskLevel(score)
  switch (level) {
    case 'quantum-safe':
      return 'Quantum Safe'
    case 'moderate-risk':
      return 'Moderate Risk'
    case 'vulnerable':
      return 'Vulnerable'
    case 'critical-risk':
      return 'Critical Risk'
  }
}

// ─── Trend Generation ──────────────────────────────────────────

/**
 * Generate a 30-day trend array based on the current score.
 * Simulates historical variation around the current value.
 */
export function generateTrend(currentScore: number): QScoreTrend[] {
  const trend: QScoreTrend[] = []
  const now = new Date()

  // Use a deterministic seed based on the score for consistent results
  let seed = currentScore + 42

  function seededRandom(): number {
    seed = (seed * 16807 + 0) % 2147483647
    return (seed - 1) / 2147483646
  }

  for (let i = 29; i >= 0; i--) {
    const date = new Date(now)
    date.setDate(date.getDate() - i)

    // Variance decreases as we approach the current date
    const distanceFactor = i / 29
    const maxVariance = 80 * distanceFactor + 10
    const variance = (seededRandom() - 0.5) * 2 * maxVariance

    // Trend upward toward current score
    const baseScore = currentScore - (distanceFactor * 60) + variance
    const dayScore = Math.max(0, Math.min(1000, Math.round(baseScore)))

    trend.push({
      date: date.toISOString().split('T')[0],
      score: i === 0 ? currentScore : dayScore,
    })
  }

  return trend
}

// ─── Legacy Conversion ─────────────────────────────────────────

/**
 * Convert an old 0-100 Q-Score to the new 0-1000 scale.
 * Applies a linear mapping: newScore = oldScore * 10.
 */
export function convertLegacyQScore(qscoreOverall: number): number {
  const clamped = Math.max(0, Math.min(100, qscoreOverall))
  return Math.round(clamped * 10)
}
