/**
 * Shared Responsibility rollup.
 *
 * Aggregates classified ownership findings into the `SharedResponsibilityIntelligence`
 * model consumed by the Migration Intelligence dashboard, the Executive strip,
 * reports, certification and the migration planner: per-domain distribution,
 * the Shared Responsibility Matrix, tri-part readiness scores, the 7-wave
 * dependency-ordered roadmap, blockers and widget counters.
 */

import { classifyFinding } from './classify'
import type {
  AttributionContext,
  DomainReadiness,
  FindingPriority,
  MigrationWave,
  OwnershipFinding,
  ProviderBreakdownRow,
  ResponsibilityDomain,
  SeverityBucket,
  SharedResponsibilityIntelligence,
  SharedResponsibilityMatrixRow,
  OwnershipFindingInput,
} from './types'

export interface BuildOptions {
  context?: AttributionContext
  /** Overall readiness baseline (e.g. snapshot.scores.quantumReadiness). */
  baselineOverall?: number
  maxFindings?: number
  maxMatrix?: number
  maxBlockers?: number
}

const PRIORITY_RANK: Record<FindingPriority, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
}

function levelFromReadiness(score: number): string {
  if (score >= 85) return 'Quantum-Ready'
  if (score >= 65) return 'Advanced'
  if (score >= 45) return 'Developing'
  if (score >= 25) return 'Early Stage'
  if (score > 0) return 'Initial'
  return 'Not Started'
}

function customerReadinessFromSeverity(severity: OwnershipFinding['severity']): number {
  switch (severity) {
    case 'critical':
      return 12
    case 'high':
      return 30
    case 'medium':
      return 55
    case 'low':
      return 78
    default:
      return 96
  }
}

function roadmapReadiness(status: OwnershipFinding['attribution']['pqRoadmapStatus']): number {
  switch (status) {
    case 'shipping':
      return 90
    case 'in_progress':
      return 65
    case 'announced':
      return 50
    case 'not_applicable':
      return 60
    default:
      return 35
  }
}

function isWaiting(finding: OwnershipFinding): boolean {
  return finding.migrationDependencyStatus.startsWith('waiting_')
}

function domainReadiness(
  findings: OwnershipFinding[],
  domain: ResponsibilityDomain,
  hasData: boolean,
): DomainReadiness {
  const subset = findings.filter((f) => f.domain === domain)
  const total = subset.length
  if (!hasData) {
    return { domain, score: 0, level: 'Not Started', total: 0, resolved: 0, actionable: 0, blocked: 0 }
  }
  if (total === 0) {
    return { domain, score: 100, level: 'Quantum-Ready', total: 0, resolved: 0, actionable: 0, blocked: 0 }
  }
  const contributions = subset.map((f) =>
    domain === 'customer' ? customerReadinessFromSeverity(f.severity) : roadmapReadiness(f.attribution.pqRoadmapStatus),
  )
  const score = Math.round(contributions.reduce((a, b) => a + b, 0) / total)
  const resolved = subset.filter((f) => f.severity === 'safe').length
  const actionable = subset.filter((f) => f.customerActionable !== 'no').length
  const blocked = subset.filter((f) => f.migrationDependencyStatus !== 'ready').length
  return { domain, score, level: levelFromReadiness(score), total, resolved, actionable, blocked }
}

function emptySeverityBucket(): SeverityBucket {
  return { critical: 0, high: 0, medium: 0, low: 0 }
}

function addSeverity(bucket: SeverityBucket, severity: OwnershipFinding['severity']): void {
  if (severity === 'critical') bucket.critical += 1
  else if (severity === 'high') bucket.high += 1
  else if (severity === 'medium') bucket.medium += 1
  else if (severity === 'low') bucket.low += 1
}

/** Expand a finding into matrix rows — provider-fronted TLS yields edge + origin. */
function matrixRowsFor(finding: OwnershipFinding): SharedResponsibilityMatrixRow[] {
  if (finding.edgeOrigin && finding.edgeOrigin.isProviderFronted && finding.edgeOrigin.edge && finding.edgeOrigin.origin) {
    const edge = finding.edgeOrigin.edge
    const origin = finding.edgeOrigin.origin
    return [
      {
        findingId: `${finding.id}:edge`,
        finding: `Edge TLS — ${finding.asset}`,
        owner: edge.owner,
        action: 'Monitor provider roadmap',
        priority: 'informational',
        status: 'Provider Managed',
        domain: 'provider',
        customerActionable: 'no',
        migrationDependencyStatus: finding.migrationDependencyStatus,
      },
      {
        findingId: `${finding.id}:origin`,
        finding: `Origin TLS — ${finding.asset}`,
        owner: origin.owner,
        action: 'Replace with ML-KEM hybrid',
        priority: finding.severity === 'critical' || finding.severity === 'high' ? 'high' : 'medium',
        status: 'Action Required',
        domain: 'customer',
        customerActionable: 'yes',
        migrationDependencyStatus: 'ready',
      },
    ]
  }
  return [
    {
      findingId: finding.id,
      finding: finding.title,
      owner: finding.ownerType,
      action: finding.recommendedAction,
      priority: finding.priority,
      status: finding.status,
      domain: finding.domain,
      customerActionable: finding.customerActionable,
      migrationDependencyStatus: finding.migrationDependencyStatus,
    },
  ]
}

const WAVE_META: { wave: number; name: string; domain: ResponsibilityDomain | 'mixed'; description: string; timeline: string; dependency: MigrationWave['dependencyStatus'] }[] = [
  { wave: 1, name: 'Customer Assets', domain: 'customer', description: 'Directly-owned assets, endpoints and local key material.', timeline: '1–2 weeks', dependency: 'ready' },
  { wave: 2, name: 'Internal PKI', domain: 'customer', description: 'Private CAs, certificates, keystores and HSM/KMS material.', timeline: '2–4 weeks', dependency: 'ready' },
  { wave: 3, name: 'Origin TLS', domain: 'customer', description: 'Customer-controlled origin TLS behind any provider edge.', timeline: '2–4 weeks', dependency: 'ready' },
  { wave: 4, name: 'Applications', domain: 'customer', description: 'Application signing, JWT/token issuance, APIs and services.', timeline: '3–6 weeks', dependency: 'ready' },
  { wave: 5, name: 'Cloud Providers', domain: 'provider', description: 'Provider-managed edge, load balancers, managed databases and platforms.', timeline: 'Provider-dependent', dependency: 'waiting_provider' },
  { wave: 6, name: 'Partner Integrations', domain: 'provider', description: 'SaaS, identity, payment and communication vendor dependencies.', timeline: 'Vendor-dependent', dependency: 'waiting_vendor' },
  { wave: 7, name: 'Industry Adoption', domain: 'ecosystem', description: 'Browsers, operating systems, hardware and standards bodies.', timeline: 'Ecosystem-dependent', dependency: 'waiting_standards' },
]

function waveFor(finding: OwnershipFinding): number {
  if (finding.domain === 'ecosystem') return 7
  if (finding.domain === 'provider') {
    return ['saas', 'identity_provider', 'payment', 'communications'].includes(finding.attribution.category) ? 6 : 5
  }
  const hay = `${finding.algorithm} ${finding.assetType} ${finding.title}`.toLowerCase()
  if (/pki|certificate|\bcert\b|keystore|hsm|kms|\bkey\b/.test(hay)) return 2
  if (/tls|ssl|https|origin|cipher|handshake/.test(hay)) return 3
  if (/jwt|token|oauth|oidc|api|app|service|web|code sign|signing/.test(hay)) return 4
  return 1
}

/** Build the full Shared Responsibility intelligence aggregate. */
export function buildSharedResponsibility(
  inputs: OwnershipFindingInput[],
  options: BuildOptions = {},
): SharedResponsibilityIntelligence {
  const context = options.context ?? {}
  const maxFindings = options.maxFindings ?? 150
  const maxMatrix = options.maxMatrix ?? 250
  const maxBlockers = options.maxBlockers ?? 50

  const findings = inputs.map((input) => classifyFinding(input, context))
  const hasData = findings.length > 0

  const byDomain = (d: ResponsibilityDomain) => findings.filter((f) => f.domain === d)
  const customer = byDomain('customer')
  const provider = byDomain('provider')
  const ecosystem = byDomain('ecosystem')

  const actionable = findings.filter((f) => f.domain === 'customer' && f.customerActionable !== 'no')
  const waiting = findings.filter((f) => isWaiting(f))
  const blocked = findings.filter((f) => f.migrationDependencyStatus === 'blocked' || (f.domain === 'customer' && f.customerActionable === 'no'))
  const resolved = findings.filter((f) => f.severity === 'safe')

  // Tri-part readiness.
  const custReadiness = domainReadiness(findings, 'customer', hasData)
  const provReadiness = domainReadiness(findings, 'provider', hasData)
  const ecoReadiness = domainReadiness(findings, 'ecosystem', hasData)
  const overallScore = hasData
    ? typeof options.baselineOverall === 'number'
      ? Math.round(options.baselineOverall)
      : Math.round(
          (custReadiness.score * customer.length + provReadiness.score * provider.length + ecoReadiness.score * ecosystem.length) /
            Math.max(1, findings.length),
        )
    : 0

  // Severity distribution per domain (stacked bar).
  const severityByDomain = { customer: emptySeverityBucket(), provider: emptySeverityBucket(), ecosystem: emptySeverityBucket() }
  for (const f of findings) addSeverity(severityByDomain[f.domain], f.severity)

  // Matrix (bounded).
  const matrix: SharedResponsibilityMatrixRow[] = []
  const sortedForMatrix = [...findings].sort(
    (a, b) => PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority] || b.quantumRiskScore - a.quantumRiskScore,
  )
  for (const f of sortedForMatrix) {
    if (matrix.length >= maxMatrix) break
    for (const row of matrixRowsFor(f)) {
      if (matrix.length >= maxMatrix) break
      matrix.push(row)
    }
  }

  // Provider breakdown.
  const providerGroups = new Map<string, { rows: OwnershipFinding[]; sample: OwnershipFinding }>()
  for (const f of findings) {
    if (!f.attribution.attributed || !f.attribution.providerId) continue
    const key = f.attribution.providerId
    const group = providerGroups.get(key)
    if (group) group.rows.push(f)
    else providerGroups.set(key, { rows: [f], sample: f })
  }
  const providerBreakdown: ProviderBreakdownRow[] = Array.from(providerGroups.entries())
    .map(([id, { rows, sample }]) => ({
      providerId: id,
      name: sample.attribution.providerName,
      domain: sample.attribution.domain,
      category: sample.attribution.category,
      count: rows.length,
      pqRoadmapStatus: sample.attribution.pqRoadmapStatus,
      customerInfluence: sample.attribution.customerInfluence,
      avgConfidence: Math.round(rows.reduce((a, r) => a + r.attribution.confidence, 0) / rows.length),
      reference: sample.attribution.reference,
    }))
    .sort((a, b) => b.count - a.count)

  // 7-wave roadmap.
  const waveCounts = new Map<number, OwnershipFinding[]>()
  for (const f of findings) {
    const w = waveFor(f)
    const arr = waveCounts.get(w) ?? []
    arr.push(f)
    waveCounts.set(w, arr)
  }
  const waves: MigrationWave[] = WAVE_META.map((meta) => {
    const items = waveCounts.get(meta.wave) ?? []
    const isCustomer = meta.domain === 'customer'
    const status: MigrationWave['status'] = items.length === 0 ? 'complete' : isCustomer ? 'ready' : 'waiting'
    const blockedBy = isCustomer ? null : meta.domain === 'provider' ? 'Provider / vendor roadmap' : 'Standards / ecosystem adoption'
    return {
      wave: meta.wave,
      name: meta.name,
      domain: meta.domain,
      description: meta.description,
      findingCount: items.length,
      status,
      dependencyStatus: meta.dependency,
      estimatedTimeline: meta.timeline,
      blockedBy,
    }
  })

  // Blockers — high-impact findings gated on an upstream dependency.
  const blockers = findings
    .filter((f) => f.migrationDependencyStatus !== 'ready' && (f.severity === 'critical' || f.severity === 'high'))
    .sort((a, b) => PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority] || b.quantumRiskScore - a.quantumRiskScore)
    .slice(0, maxBlockers)

  // Widget counters.
  const vendorCategories = new Set(['saas', 'identity_provider', 'payment', 'communications'])
  const cloudCategories = new Set(['cdn_edge', 'cloud_certificate', 'load_balancer', 'managed_database', 'managed_kubernetes', 'hosting_platform'])
  const widgets = {
    customerFindings: customer.length,
    providerFindings: provider.length,
    vendorFindings: findings.filter((f) => vendorCategories.has(f.attribution.category)).length,
    browserDependencies: findings.filter((f) => f.attribution.category === 'browser').length,
    cloudDependencies: findings.filter((f) => cloudCategories.has(f.attribution.category)).length,
    migrationBlockers: blockers.length,
    actionableFindings: actionable.length,
    waitingDependencies: waiting.length,
    migrationProgress: overallScore,
    providerReadiness: provReadiness.score,
  }

  // Edge/origin aggregate.
  const providerFronted = findings.filter((f) => f.edgeOrigin?.isProviderFronted)
  const edgeOrigin = {
    providerFrontedAssets: providerFronted.length,
    edgeManaged: providerFronted.length,
    originCustomerControlled: providerFronted.length,
    summary: providerFronted.length
      ? `${providerFronted.length} asset(s) are provider-fronted: the edge is provider-managed while the origin remains customer-controlled and directly actionable.`
      : 'No provider-fronted TLS detected — transport findings are customer-controlled end to end.',
  }

  // Attribution honesty summary.
  const attributed = findings.filter((f) => f.attribution.attributed)
  const attribution = {
    attributed: attributed.length,
    unattributed: findings.length - attributed.length,
    avgConfidence: findings.length ? Math.round(findings.reduce((a, f) => a + f.attribution.confidence, 0) / findings.length) : 0,
  }

  const boundedFindings = sortedForMatrix.slice(0, maxFindings)

  return {
    generatedAt: new Date().toISOString(),
    hasData,
    totals: {
      findings: findings.length,
      customer: customer.length,
      provider: provider.length,
      ecosystem: ecosystem.length,
      actionable: actionable.length,
      waiting: waiting.length,
      blocked: blocked.length,
      resolved: resolved.length,
    },
    readiness: {
      overall: { domain: 'overall', score: overallScore, level: levelFromReadiness(overallScore), total: findings.length, resolved: resolved.length, actionable: actionable.length, blocked: blocked.length },
      customer: custReadiness,
      provider: provReadiness,
      ecosystem: ecoReadiness,
    },
    domainDistribution: { customer: customer.length, provider: provider.length, ecosystem: ecosystem.length },
    severityByDomain,
    matrix,
    findings: boundedFindings,
    blockers,
    waves,
    widgets,
    providerBreakdown,
    edgeOrigin,
    attribution,
  }
}
