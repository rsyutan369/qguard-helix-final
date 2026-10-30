/**
 * "Recommended next step" for the Intelligence pages that render the shared
 * `ModuleBrief`. Each function reads only its page's model and returns the
 * single most valuable action the evidence supports, in a fixed, documented
 * order. A failed evidence read always comes first: acting on figures built
 * from a table that could not be read would be acting on a guess.
 */
import type { CorrelationIntelligence } from '@/lib/telemetry/correlation-intelligence'
import type { DriftIntelligence } from '@/lib/drift/drift-intelligence'
import type { QuantumRiskIntelligence } from '@/lib/quantum-risk/risk-intelligence'
import type { SourceRead } from '@/lib/source-read'

export interface NextStep {
  label: string
  detail: string
  href: string
  tone: 'action' | 'warning' | 'calm'
}

function unreadableStep(reads: SourceRead[] | undefined, page: string): NextStep | null {
  const failed = (reads || []).filter((read) => read.state === 'unavailable')
  if (!failed.length) return null
  return {
    label: 'Refresh',
    href: page,
    tone: 'warning',
    detail: `${failed.map((read) => read.label).join(', ')} could not be read on the last refresh. Figures that depend on ${failed.length === 1 ? 'it' : 'them'} are incomplete, not zero — refresh before acting on them.`,
  }
}

/** Telemetry Correlation: unreadable source → silent source → conflict → exposed blind spot → any blind spot → calm. */
export function correlationNextStep(data: CorrelationIntelligence): NextStep {
  const unreadable = unreadableStep(data.reads, '/dashboard/telemetry-correlation')
  if (unreadable) return unreadable
  const silent = data.sources.filter((source) => source.health === 'silent' && source.lastSeenAt)
  if (silent.length) {
    return {
      label: 'Agent Center',
      href: '/downloads',
      tone: 'warning',
      detail: `${silent.length} telemetry source(s) stopped reporting (first: ${silent[0].name}). Assets only they observed are now unwatched — reconnect them before trusting coverage.`,
    }
  }
  const conflict = data.conflicts.find((c) => c.severity === 'critical' || c.severity === 'high') ?? data.conflicts[0]
  if (conflict) {
    return {
      label: 'Investigate the conflict',
      href: conflict.href,
      tone: conflict.severity === 'medium' ? 'action' : 'warning',
      detail: `${conflict.assetName}: ${conflict.summary} ${conflict.recommendedAction}`,
    }
  }
  const exposed = data.blindSpots.find((spot) => spot.internetFacing) ?? data.blindSpots[0]
  if (exposed) {
    return {
      label: 'Extend coverage',
      href: exposed.href,
      tone: exposed.internetFacing ? 'warning' : 'action',
      detail: `${data.blindSpots.length} asset(s) have no telemetry from any source${exposed.internetFacing ? `, including internet-facing ${exposed.assetName}` : ` (first: ${exposed.assetName})`}. ${exposed.why}`,
    }
  }
  return {
    label: 'Runtime Crypto Intelligence',
    href: '/dashboard/runtime-crypto-intel',
    tone: 'calm',
    detail: `Every assessed asset is observed by at least one source and no two sources disagree. ${data.kpis.corroboratedAssets} asset(s) are corroborated by more than one.`,
  }
}

/** Drift Detection: unreadable source → no baseline → regression → runtime downgrade → unplanned change → calm. */
export function driftNextStep(data: DriftIntelligence): NextStep {
  const unreadable = unreadableStep(data.reads, '/dashboard/drift')
  if (unreadable) return unreadable
  if (!data.baseline.available) {
    return {
      label: 'Run a scan',
      href: '/dashboard/scanner',
      tone: 'action',
      detail: `Drift needs two completed scans to compare; ${data.baseline.sessionsCompared} ${data.baseline.sessionsCompared === 1 ? 'is' : 'are'} available. Run another scan to establish the baseline.`,
    }
  }
  const regression = data.events.find((event) => event.driftClass === 'regression' && (event.severity === 'critical' || event.severity === 'high'))
    ?? data.events.find((event) => event.driftClass === 'regression')
  if (regression) {
    return {
      label: 'Open the asset',
      href: regression.href,
      tone: 'warning',
      detail: `${data.kpis.regressions} regression(s) since the baseline. Most severe: ${regression.summary} on ${regression.assetName}. ${regression.recommendedAction}`,
    }
  }
  if (data.kpis.runtimeDowngrades > 0) {
    return {
      label: 'Runtime Crypto Intelligence',
      href: '/dashboard/runtime-crypto-intel',
      tone: 'warning',
      detail: `${data.kpis.runtimeDowngrades} runtime downgrade(s) observed — sessions negotiated weaker cryptography than the endpoint supports.`,
    }
  }
  if (data.kpis.unplannedChanges > 0) {
    return {
      label: 'Review changes',
      href: '/dashboard/drift',
      tone: 'action',
      detail: `${data.kpis.unplannedChanges} change(s) since the baseline are not explained by any migration job. Confirm each was intended.`,
    }
  }
  return {
    label: 'Migration Timeline',
    href: '/dashboard/migration-timeline',
    tone: 'calm',
    detail: `No regression between the two most recent scans${data.kpis.improvements ? `; ${data.kpis.improvements} improvement(s) recorded` : ''}. Keep scanning on a schedule so drift stays measurable.`,
  }
}

/** Quantum Risk Scoring: unreadable source → nothing assessed → coverage gap on critical assets → top risk asset → calm. */
export function quantumRiskNextStep(data: QuantumRiskIntelligence): NextStep {
  const unreadable = unreadableStep(data.reads, '/dashboard/quantum-risk-scoring')
  if (unreadable) return unreadable
  if (!data.coverage.assetsAssessed) {
    return { label: 'Run a scan', href: '/dashboard/scanner', tone: 'action', detail: 'No asset has a quantum risk assessment yet. A scan inventories the cryptography the score is computed from.' }
  }
  const top = data.assets
    .filter((asset) => asset.state === 'assessed' && asset.riskScore !== null)
    .sort((a, b) => (b.riskScore as number) - (a.riskScore as number))[0]
  if (data.coverage.assetsUnassessed > 0 && data.coverage.coveragePct < 50) {
    return {
      label: 'Close the coverage gap',
      href: '/dashboard/scanner',
      tone: 'action',
      detail: `${data.coverage.assetsUnassessed} asset(s) have no cryptographic evidence, so the score describes only ${data.coverage.coveragePct}% of the estate. Unknown is not safe.`,
    }
  }
  if (top && (top.riskScore as number) >= 60) {
    return {
      label: 'Plan the migration',
      href: top.href,
      tone: 'warning',
      detail: `${top.name} carries the highest quantum risk (${top.riskScore}/100, ${top.riskLevel}). ${top.recommendation}`,
    }
  }
  if (data.coverage.assetsUnassessed > 0) {
    return {
      label: 'Extend coverage',
      href: '/dashboard/scanner',
      tone: 'action',
      detail: `${data.coverage.assetsUnassessed} asset(s) are not yet assessed — their risk is unknown, not low.`,
    }
  }
  return {
    label: 'Migration Planner',
    href: '/dashboard/migration-planner',
    tone: 'calm',
    detail: `Every recorded asset is assessed and none scores high risk. Keep migrating the remaining quantum-vulnerable cryptography in plan order.`,
  }
}
