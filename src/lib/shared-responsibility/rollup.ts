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
  // A resolved (PQC-ready) observation is not work: it is neither actionable
  // nor blocked. Counting it made "actionable" include what is already done.
  const actionable = subset.filter((f) => f.severity !== 'safe' && f.customerActionable !== 'no').length
  const blocked = subset.filter((f) => f.severity !== 'safe' && f.migrationDependencyStatus !== 'ready').length
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

/* ------------------------------------------------------------------ */
/* Matrix consolidation                                                */
/* ------------------------------------------------------------------ */

const SEVERITY_RANK: Record<OwnershipFinding['severity'], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  safe: 0,
}

/**
 * Canonical asset label for grouping.
 *
 * The scanner records the same host through several detection channels, so one
 * asset arrives as `example.com`, `example.com:443`, `https://example.com` and
 * `Cipher Suite - https://example.com`. Reduce all of those to the bare host so
 * one exposure on one asset consolidates into one ownership row. Labels that
 * carry no host (e.g. `Detection Rule TLS-006`) are kept verbatim — they are a
 * different evidence channel and must not be silently merged into a host.
 */
export function canonicalAssetLabel(raw: string): string {
  const value = String(raw ?? '').trim()
  if (!value) return ''
  const host = value
    .toLowerCase()
    .replace(/^[a-z0-9 /&+-]*?\s-\s/, '') // strip a leading "Category - " prefix
    .match(/(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}/)
  return host ? host[0] : value.toLowerCase()
}

/**
 * Display label for a grouped asset: the canonical host when one was found
 * (hostnames are case-insensitive, so the lowercase form is correct), otherwise
 * the original label verbatim — lowercasing `Detection Rule TLS-006` into
 * `detection rule tls-006` would corrupt an evidence identifier.
 */
export function assetDisplayLabel(raw: string): string {
  const value = String(raw ?? '').trim()
  if (!value) return ''
  const canonical = canonicalAssetLabel(value)
  return canonical === value.toLowerCase() ? value : canonical
}

/**
 * Grouping identity for one cryptographic exposure: the algorithm when the
 * scanner recorded one, otherwise the finding title with its trailing
 * ` — <location>` suffix removed (that suffix is the asset, which the group
 * tracks separately).
 */
function findingStem(finding: OwnershipFinding): string {
  const algorithm = String(finding.algorithm ?? '').trim()
  if (algorithm) return algorithm
  return String(finding.title ?? '')
    .split(/\s[—–-]\s/)[0]
    .trim() || 'Cryptographic finding'
}

interface MatrixSeed extends SharedResponsibilityMatrixRow {
  /** Grouping key — never rendered. */
  groupKey: string
  /** How specific the row's recommended action is (see `actionSpecificity`). */
  specificity: number
}

/** Expand a finding into matrix seeds — provider-fronted TLS yields edge + origin. */
function matrixSeedsFor(finding: OwnershipFinding): MatrixSeed[] {
  const rawAsset = finding.asset || 'Unknown asset'
  const assetKey = canonicalAssetLabel(rawAsset)
  const asset = assetDisplayLabel(rawAsset) || rawAsset
  /*
   * Provider attribution and freshness ride on every matrix row so the table
   * can be filtered by company and reconciled against the Provider & Ecosystem
   * Readiness panel WITHOUT a second derivation — two derivations of the same
   * fact is how two panels start disagreeing about one estate.
   *
   * `providerAttributed: false` is preserved rather than smoothed away: an
   * unattributed row must stay visibly unattributed, never filed under a
   * guessed vendor.
   */
  const base = {
    occurrences: 1,
    detectionLabels: [rawAsset],
    severity: finding.severity,
    asset,
    assetKey,
    providerId: finding.attribution.attributed ? finding.attribution.providerId : null,
    providerName: finding.attribution.attributed ? finding.attribution.providerName : 'Unattributed',
    providerAttributed: finding.attribution.attributed,
    observedAt: finding.observedAt,
  }

  if (finding.edgeOrigin && finding.edgeOrigin.isProviderFronted && finding.edgeOrigin.edge && finding.edgeOrigin.origin) {
    const edge = finding.edgeOrigin.edge
    const origin = finding.edgeOrigin.origin
    return [
      {
        ...base,
        groupKey: `edge|${edge.owner.toLowerCase()}|${assetKey}`,
        specificity: 2,
        findingId: `${finding.id}:edge`,
        finding: 'Edge TLS',
        owner: edge.owner,
        action: 'Monitor provider roadmap',
        priority: 'informational',
        status: 'Provider Managed',
        domain: 'provider',
        customerActionable: 'no',
        migrationDependencyStatus: finding.migrationDependencyStatus,
      },
      {
        ...base,
        groupKey: `origin|${origin.owner.toLowerCase()}|${assetKey}`,
        specificity: 2,
        findingId: `${finding.id}:origin`,
        finding: 'Origin TLS',
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

  const stem = findingStem(finding)
  return [
    {
      ...base,
      // One row per cryptographic exposure per owner per asset. Detection
      // channel, scanner category and evidence text are deliberately excluded
      // from the key — they are what made one exposure repeat as identical rows.
      groupKey: `f|${finding.domain}|${finding.ownerType.toLowerCase()}|${stem.toLowerCase()}|${assetKey}`,
      specificity: actionSpecificity(finding.recommendedAction),
      findingId: finding.id,
      finding: stem,
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

/**
 * How specific a recommended action is.
 *
 * The classifier names the exact NIST replacement when it can identify the
 * primitive class (ML-KEM for key establishment, ML-DSA for signatures) and
 * falls back to generic guidance otherwise. When duplicate scanner records of
 * one exposure disagree — because they carry different `category` values — the
 * named-primitive action wins, so a report can never print two contradictory
 * remediations for the same finding.
 */
function actionSpecificity(action: string): number {
  if (/ML-KEM|ML-DSA|SLH-DSA/i.test(action)) return 2
  return 1
}

/**
 * Merge a seed into its group.
 *
 * The classifier can produce two different recommended actions for the same
 * exposure when duplicate scanner records disagree on `category` (one says
 * "migrate to the NIST replacement", the other "replace the key exchange with an
 * ML-KEM hybrid"). Consolidation resolves that deterministically in favour of
 * the transport-specific action, so a report can never print two contradictory
 * remediations for one finding.
 */
function mergeSeed(target: MatrixSeed, seed: MatrixSeed): void {
  target.occurrences += seed.occurrences
  for (const label of seed.detectionLabels) {
    if (target.detectionLabels.length < 8 && !target.detectionLabels.includes(label)) target.detectionLabels.push(label)
  }
  if (SEVERITY_RANK[seed.severity] > SEVERITY_RANK[target.severity]) target.severity = seed.severity
  if (PRIORITY_RANK[seed.priority] < PRIORITY_RANK[target.priority]) {
    target.priority = seed.priority
    target.status = seed.status
  }
  if (seed.specificity > target.specificity) {
    target.action = seed.action
    target.specificity = seed.specificity
  }
  // Actionability and dependency status take the most actionable observation:
  // if any instance is customer-fixable today, the group is.
  if (target.customerActionable === 'no' && seed.customerActionable !== 'no') {
    target.customerActionable = seed.customerActionable
  }
  if (target.migrationDependencyStatus !== 'ready' && seed.migrationDependencyStatus === 'ready') {
    target.migrationDependencyStatus = 'ready'
  }
  // Freshness: the group is as fresh as its NEWEST observation.
  if (seed.observedAt && (!target.observedAt || Date.parse(seed.observedAt) > Date.parse(target.observedAt))) {
    target.observedAt = seed.observedAt
  }
  // Attribution: an attributed instance upgrades an unattributed group, but an
  // unattributed instance never downgrades an attributed one.
  if (!target.providerAttributed && seed.providerAttributed) {
    target.providerAttributed = true
    target.providerId = seed.providerId
    target.providerName = seed.providerName
  }
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

  /* Work counters describe OPEN findings only. A SAFE finding is a PQC-ready
     confirmation — already done — so it can be neither "actionable now" nor
     "waiting on a dependency". Counting them published e.g. "Actionable Now 24"
     for an estate with 20 open findings (and a PQC-ready ML-KEM detection
     "waiting" on the ecosystem). */
  const open = findings.filter((f) => f.severity !== 'safe')
  const actionable = open.filter((f) => f.domain === 'customer' && f.customerActionable !== 'no')
  const waiting = open.filter((f) => isWaiting(f))
  const blocked = open.filter((f) => f.migrationDependencyStatus === 'blocked' || (f.domain === 'customer' && f.customerActionable === 'no'))
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

  // Matrix — CONSOLIDATED, then bounded.
  //
  // Consolidation runs over the whole finding population before the cap is
  // applied, so the bound now buys unique ownership rows instead of being
  // spent on repeats of the same exposure.
  const sortedForMatrix = [...findings].sort(
    (a, b) => PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority] || b.quantumRiskScore - a.quantumRiskScore,
  )
  const matrixGroups = new Map<string, MatrixSeed>()
  for (const f of sortedForMatrix) {
    for (const seed of matrixSeedsFor(f)) {
      const existing = matrixGroups.get(seed.groupKey)
      if (existing) mergeSeed(existing, seed)
      else matrixGroups.set(seed.groupKey, seed)
    }
  }
  const matrix: SharedResponsibilityMatrixRow[] = Array.from(matrixGroups.values())
    .sort(
      (a, b) =>
        PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority] ||
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
        b.occurrences - a.occurrences ||
        a.finding.localeCompare(b.finding),
    )
    .slice(0, maxMatrix)
    .map(({ groupKey: _groupKey, specificity: _specificity, ...row }) => row)

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
