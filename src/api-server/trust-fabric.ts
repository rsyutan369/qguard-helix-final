/**
 * Cryptographic Trust & Telemetry Command Center - the one backend behind four
 * pages.
 *
 * `/api/v1/dashboard/trust-dashboard`
 * `/api/v1/dashboard/trust-state-discovery`
 * `/api/v1/dashboard/certificate-telemetry`
 * `/api/v1/dashboard/multi-cloud-telemetry`
 *
 * All four are projections of a single per-tenant model computed once per
 * window. Before this module the four pages ran on three unrelated builders
 * (`observability-dashboard.ts` for two of them, a separate signal engine for
 * discovery, and no backend at all for the trust dashboard - its route was
 * missing from the router entirely), which is why the same certificate could be
 * counted differently on each.
 *
 * Caching contract, matching `buildSnapshot` / `buildPortfolio` /
 * `buildTlsPkiModel`: only the FETCH + derivation is cached, per tenant, for
 * 15s. Every connected dashboard and every SSE push of a tenant collapses onto
 * that one computation, so N open pages cost the same as one AND cannot
 * disagree within the window. Failures are never cached.
 */

import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { buildPortfolio } from './migration-planner'
import { buildTlsPkiModel } from './tls-pki'
import { buildTrustFabricIntelligence } from '@/lib/trust-fabric/intelligence'
import type {
  CertificateTrustRecord,
  CloudResource,
  PkiCertificate,
  TrustEvent,
  TrustFabricIntelligence,
  TrustNode,
  TrustRelationship,
} from '@/lib/trust-fabric/types'
import type { TlsFinding } from '@/lib/tls-pki/types'

type Row = Record<string, unknown>

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

export type TrustView = 'trust' | 'discovery' | 'certificate' | 'cloud'

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : value === null || value === undefined ? '' : String(value).trim()
}

function num(value: unknown, fallback = 0): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function safeRows(client: any, table: string, build: (query: any) => any): Promise<Row[]> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      console.warn(`[trust-fabric] ${table} query skipped:`, error.message || error)
      return []
    }
    return (data as Row[]) || []
  } catch (error) {
    console.warn(`[trust-fabric] ${table} query failed:`, (error as Error)?.message || error)
    return []
  }
}

/* ------------------------------------------------------------------ */
/* Auth                                                                */
/* ------------------------------------------------------------------ */

/**
 * EventSource cannot set headers, so legacy streams accepted `?token=`, which
 * writes a bearer token into access logs, proxies and browser history. The
 * hooks here stream over fetch + ReadableStream with an Authorization header.
 * The query fallback exists only so an already-open legacy tab does not
 * hard-fail during a deploy.
 */
function tokenFromRequest(req: Request): string | null {
  const header = getToken(req)
  if (header) return header
  const query = req.query.token
  return typeof query === 'string' && query.length > 0 ? query : null
}

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = tokenFromRequest(req)
  if (!token) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }
  const user = await getServerUser(token)
  if (!user) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  }
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}

/* ------------------------------------------------------------------ */
/* Row caps                                                            */
/* ------------------------------------------------------------------ */

const CAP = {
  assets: 2000,
  assetRelationships: 4000,
  connectorAccounts: 400,
  securityEvents: 1500,
  scanSessions: 300,
  migrationJobs: 1200,
  scannerAgents: 400,
  complianceEvidence: 1200,
  cryptoInventory: 3000,
  runtimeEvents: 3000,
} as const

/* ------------------------------------------------------------------ */
/* Model builder + cache                                               */
/* ------------------------------------------------------------------ */

const MODEL_TTL_MS = 15_000
const modelCache = new Map<string, { at: number; promise: Promise<TrustFabricIntelligence> }>()

async function computeModel(token: string, userId: string): Promise<TrustFabricIntelligence> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')

  // Canonical estate truth first. All three are themselves cached per tenant on
  // the same 15s window, so asking for them here is nearly free and is what
  // guarantees these four pages agree with PKI Visibility, TLS Telemetry,
  // Quantum Readiness, Assets, Migration Planner and every report.
  const [tlsPki, snapshot, portfolio] = await Promise.all([
    buildTlsPkiModel(token, userId),
    buildSnapshot(token, userId),
    buildPortfolio(token, userId),
  ])

  const [
    assetRows,
    assetRelationships,
    connectorAccounts,
    securityEvents,
    scanSessions,
    migrationJobs,
    scannerAgents,
    complianceEvidence,
    cryptoInventory,
    runtimeEvents,
  ] = await Promise.all([
    safeRows(client, 'assets', (q) =>
      q
        .select('id, name, type, environment, region, service_owner, criticality, status, metadata, created_at, updated_at')
        .eq('user_id', userId)
        .order('updated_at', { ascending: false })
        .limit(CAP.assets),
    ),
    safeRows(client, 'asset_relationships', (q) =>
      q.select('id, source_asset_id, target_asset_id, relationship_type, metadata, created_at').eq('user_id', userId).limit(CAP.assetRelationships),
    ),
    safeRows(client, 'connector_accounts', (q) =>
      q
        .select('id, provider, provider_account_id, display_name, status, capabilities, last_sync_at, metadata, created_at, updated_at')
        .eq('user_id', userId)
        .limit(CAP.connectorAccounts),
    ),
    safeRows(client, 'security_events', (q) =>
      q
        .select('id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, created_at')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(CAP.securityEvents),
    ),
    safeRows(client, 'pqc_scan_sessions', (q) =>
      q
        .select('id, status, progress, total_assets, scanned_assets, findings_count, started_at, completed_at, created_at, updated_at')
        .eq('user_id', userId)
        .order('updated_at', { ascending: false })
        .limit(CAP.scanSessions),
    ),
    safeRows(client, 'migration_jobs', (q) =>
      q
        .select('id, asset_id, name, job_type, status, target_algorithm, progress, metadata, started_at, completed_at, created_at, updated_at')
        .eq('user_id', userId)
        .order('updated_at', { ascending: false })
        .limit(CAP.migrationJobs),
    ),
    safeRows(client, 'scanner_agents', (q) =>
      q.select('id, name, status, hostname, platform, last_seen_at, metadata, created_at, updated_at').eq('user_id', userId).limit(CAP.scannerAgents),
    ),
    safeRows(client, 'compliance_evidence', (q) =>
      q
        .select('id, asset_id, framework, control_id, status, evidence_type, metadata, created_at, updated_at')
        .eq('user_id', userId)
        .order('updated_at', { ascending: false })
        .limit(CAP.complianceEvidence),
    ),
    safeRows(client, 'crypto_inventory', (q) =>
      q
        .select('id, asset_id, item_type, name, algorithm, key_size, protocol, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at')
        .eq('user_id', userId)
        .order('discovered_at', { ascending: false })
        .limit(CAP.cryptoInventory),
    ),
    safeRows(client, 'runtime_crypto_events', (q) =>
      q
        .select('id, asset_id, connector_account_id, asset_name, host, protocol, tls_version, algorithm, is_pqc, is_legacy, metadata, observed_at, created_at')
        .eq('user_id', userId)
        .order('observed_at', { ascending: false })
        .limit(CAP.runtimeEvents),
    ),
  ])

  /**
   * Compliance score: share of cryptographic control evidence recording a pass.
   * Returns null (not 0) when no evidence exists, so the tile reads
   * "Not measured" rather than implying total non-compliance.
   */
  const complianceScore = (() => {
    const graded = complianceEvidence.filter((row) => /pass|fail|compliant|violation|satisfied/i.test(str(row.status)))
    if (graded.length === 0) return null
    const passing = graded.filter((row) => /pass|compliant|satisfied/i.test(str(row.status)) && !/non[- ]?compliant/i.test(str(row.status)))
    return Math.round((passing.length / graded.length) * 100)
  })()

  return buildTrustFabricIntelligence({
    tlsPki,
    assets: portfolio.assets,
    snapshot: {
      quantumReadiness: snapshot.scores.quantumReadiness,
      quantumRisk: snapshot.scores.quantumRisk,
      quantumRiskLevel: snapshot.scores.quantumRiskLevel,
      assetsAssessed: snapshot.inventory.assetsAssessed,
      certificatesAnalyzed: snapshot.inventory.certificatesAnalyzed,
      complianceScore,
      // Component-level counts, taken from the readiness inventory so the
      // "quantum vulnerable" figure here is the same one CBOM, Assets and the
      // QR pages publish — the canonical unit is the COMPONENT, not the finding.
      vulnerableComponents: snapshot.inventory.vulnerableComponents,
      totalComponents: snapshot.inventory.cryptoComponents,
      pqcReadyComponents: snapshot.inventory.pqcReadyComponents,
    },
    assetRows,
    assetRelationships,
    connectorAccounts,
    securityEvents,
    scanSessions,
    migrationJobs,
    scannerAgents,
    complianceEvidence,
    cryptoInventory,
    runtimeEvents,
  })
}

export async function buildTrustFabricModel(token: string, userId: string, force = false): Promise<TrustFabricIntelligence> {
  const cached = modelCache.get(userId)
  if (!force && cached && Date.now() - cached.at < MODEL_TTL_MS) return cached.promise
  const promise = computeModel(token, userId)
  modelCache.set(userId, { at: Date.now(), promise })
  promise.catch(() => modelCache.delete(userId))
  if (modelCache.size > 500) {
    const now = Date.now()
    for (const [key, value] of modelCache) if (now - value.at > MODEL_TTL_MS) modelCache.delete(key)
  }
  return promise
}

/** Drops the tenant's cached model so the next read reflects a just-made write. */
export function invalidateTrustFabricModel(userId: string) {
  modelCache.delete(userId)
}

/* ------------------------------------------------------------------ */
/* Projections - bounded payloads, one per page                        */
/* ------------------------------------------------------------------ */

/** Rows shipped in the first paint. Deeper pages come from the paging routes. */
const PAGE = { nodes: 80, certificates: 60, resources: 60, events: 60, findings: 40, relationships: 220 } as const

/** Fields every page shares, so the header is identical on all four. */
function commonEnvelope(model: TrustFabricIntelligence) {
  return {
    generatedAt: model.generatedAt,
    latestEvidenceAt: model.latestEvidenceAt,
    hasData: model.hasData,
    stale: model.stale,
    staleSinceHours: model.staleSinceHours,
    scores: model.scores,
    telemetry: model.telemetry,
    reconciliation: model.reconciliation,
    facets: model.facets,
    /** Cross-page totals so a header count can never differ between pages. */
    totals: {
      nodes: model.nodes.length,
      measuredNodes: model.nodes.filter((node) => node.measured).length,
      relationships: model.relationships.length,
      certificates: model.certificates.length,
      endpoints: model.endpoints.length,
      measuredEndpoints: model.endpoints.filter((endpoint) => endpoint.hasTransportEvidence).length,
      findings: model.findings.length,
      cloudResources: model.cloud.totals.resources,
      attributedCloudResources: model.cloud.totals.attributedResources,
      events: model.events.length,
      chainPaths: model.chainPaths.length,
    },
  }
}

/** Node summary shipped alongside every view for drill-down labels. */
function nodeSummary(node: TrustNode) {
  return {
    id: node.id,
    kind: node.kind,
    label: node.label,
    subtitle: node.subtitle,
    state: node.state,
    stateReason: node.stateReason,
    posture: node.posture,
    riskLevel: node.riskLevel,
    riskScore: node.riskScore,
    assetId: node.assetId,
    certificateId: node.certificateId,
    endpointId: node.endpointId,
    environment: node.environment,
    provider: node.provider,
    providerLabel: node.providerLabel,
    region: node.region,
    dependentCount: node.dependentCount,
    daysToExpiry: node.daysToExpiry,
    measured: node.measured,
    href: node.href,
  }
}

export function projectView(model: TrustFabricIntelligence, view: TrustView) {
  const base = commonEnvelope(model)

  switch (view) {
    case 'trust':
      return {
        ...base,
        view: 'trust' as const,
        kpis: model.kpis,
        stateDistribution: model.stateDistribution,
        trend: model.trend,
        events: model.events.slice(0, PAGE.events),
        findings: model.findings.slice(0, PAGE.findings),
        /** Enough of the estate to render the command-center panels. */
        criticalNodes: model.nodes
          .filter((node) => node.state === 'critical' || node.state === 'expired' || node.state === 'invalid')
          .slice(0, 40)
          .map(nodeSummary),
        expiring: model.certificateTrust
          .filter((record) => record.band === 'critical' || record.band === 'high' || record.band === 'expired')
          .slice(0, 30),
        certificateIntel: {
          lifecycle: model.certificateIntel.lifecycle,
          bands: model.certificateIntel.bands,
          chainValidation: model.certificateIntel.chainValidation,
          expiryTimeline: model.certificateIntel.expiryTimeline.slice(0, 12),
        },
        cloudSummary: {
          hasCloudEvidence: model.cloud.hasCloudEvidence,
          connectorsConfigured: model.cloud.connectorsConfigured,
          connectorsActive: model.cloud.connectorsActive,
          providers: model.cloud.providers,
          totals: model.cloud.totals,
          topRegions: model.cloud.regions.slice(0, 8),
        },
        certificateIndex: model.certificates.slice(0, 200).map((certificate) => ({
          id: certificate.id,
          name: certificate.name,
          subject: certificate.subject,
          issuer: certificate.issuer,
          daysToExpiry: certificate.daysToExpiry,
          posture: certificate.posture,
        })),
      }

    case 'discovery':
      return {
        ...base,
        view: 'discovery' as const,
        nodes: model.nodes.slice(0, PAGE.nodes),
        relationships: model.relationships.slice(0, PAGE.relationships),
        chainPaths: model.chainPaths.slice(0, 60),
        trustChains: model.trustChains,
        stateDistribution: model.stateDistribution,
        kindDistribution: model.kindDistribution,
        findings: model.findings.slice(0, PAGE.findings),
        events: model.events.slice(0, 30),
        /** Every node id + label, so the graph can resolve an edge endpoint the
         * bounded `nodes` page did not include without a second request. */
        nodeIndex: model.nodes.map((node) => ({
          id: node.id,
          kind: node.kind,
          label: node.label,
          state: node.state,
          measured: node.measured,
          tier: node.kind,
        })),
      }

    case 'certificate':
      return {
        ...base,
        view: 'certificate' as const,
        certificates: model.certificates.slice(0, PAGE.certificates),
        certificateTrust: model.certificateTrust.slice(0, PAGE.certificates),
        certificateIntel: model.certificateIntel,
        chainPaths: model.chainPaths.slice(0, 60),
        trustChains: model.trustChains,
        findings: model.findings.filter((finding) => finding.category === 'certificate').slice(0, PAGE.findings),
        events: model.events
          .filter((event) => event.kind.startsWith('certificate') || event.kind === 'trust-chain-failure')
          .slice(0, 40),
        endpointIndex: model.endpoints.map((endpoint) => ({
          id: endpoint.id,
          assetId: endpoint.assetId,
          name: endpoint.name,
          host: endpoint.host,
          port: endpoint.port,
          environment: endpoint.environment,
          negotiatedVersion: endpoint.negotiatedVersion,
          posture: endpoint.posture,
        })),
      }

    case 'cloud':
    default:
      return {
        ...base,
        view: 'cloud' as const,
        cloud: {
          ...model.cloud,
          resources: model.cloud.resources.slice(0, PAGE.resources),
        },
        events: model.events.filter((event) => event.provider !== null || event.kind.startsWith('cloud')).slice(0, 40),
        findings: model.findings.slice(0, PAGE.findings),
        certificateTrust: model.certificateTrust
          .filter((record) => record.provider !== 'unattributed')
          .slice(0, PAGE.certificates),
      }
  }
}

/* ------------------------------------------------------------------ */
/* Server-side filtering for the paging routes (sections 10 and 15)    */
/* ------------------------------------------------------------------ */

function paginate<T>(rows: T[], req: Request) {
  const limit = Math.max(1, Math.min(200, num(req.query.limit) || 50))
  const offset = Math.max(0, num(req.query.offset))
  return { rows: rows.slice(offset, offset + limit), total: rows.length, limit, offset }
}

/** Applies a query filter only when it is present and not the "all" sentinel. */
function active(value: unknown): string {
  const text = str(value).toLowerCase()
  return text && text !== 'all' ? text : ''
}

/** Time-range filter shared by every list route - section 10. */
function withinRange(iso: string | null, range: string): boolean {
  if (!range || range === 'all') return true
  if (!iso) return false
  const ms = Date.parse(iso)
  if (!Number.isFinite(ms)) return false
  const days = range === '24h' ? 1 : range === '7d' ? 7 : range === '30d' ? 30 : range === '90d' ? 90 : 0
  if (!days) return true
  return Date.now() - ms <= days * 86_400_000
}

function filterNodes(nodes: TrustNode[], req: Request): TrustNode[] {
  const search = active(req.query.search)
  const kind = active(req.query.kind)
  const state = active(req.query.state)
  const environment = active(req.query.environment)
  const provider = active(req.query.provider)
  const account = active(req.query.account)
  const region = active(req.query.region)
  const risk = active(req.query.risk)
  const posture = active(req.query.posture)
  const owner = active(req.query.owner)
  const measured = active(req.query.measured)
  const range = active(req.query.range)
  const sort = str(req.query.sort) || 'state'

  const filtered = nodes.filter((node) => {
    if (kind && node.kind !== kind) return false
    if (state && node.state !== state) return false
    if (environment && node.environment.toLowerCase() !== environment) return false
    if (provider && node.provider.toLowerCase() !== provider) return false
    if (account && node.account.toLowerCase() !== account) return false
    if (region && node.region.toLowerCase() !== region) return false
    if (risk && node.riskLevel !== risk) return false
    if (posture && node.posture !== posture) return false
    if (owner && node.owner.toLowerCase() !== owner) return false
    if (measured === 'true' && !node.measured) return false
    if (measured === 'false' && node.measured) return false
    if (!withinRange(node.lastObservedAt, range)) return false
    if (search) {
      const haystack = `${node.label} ${node.subtitle} ${node.owner} ${node.region} ${node.providerLabel} ${node.environment}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })

  return filtered.sort((a, b) => {
    if (sort === 'risk') return b.riskScore - a.riskScore
    if (sort === 'blast') return b.dependentCount - a.dependentCount
    if (sort === 'expiry') {
      const left = a.daysToExpiry ?? Number.POSITIVE_INFINITY
      const right = b.daysToExpiry ?? Number.POSITIVE_INFINITY
      return left - right
    }
    if (sort === 'name') return a.label.localeCompare(b.label)
    return 0 // 'state' - already ordered worst-first by the engine
  })
}

interface CertificateRow {
  certificate: PkiCertificate
  trust: CertificateTrustRecord
}

function filterCertificates(rows: CertificateRow[], req: Request): CertificateRow[] {
  const search = active(req.query.search)
  const band = active(req.query.band)
  const state = active(req.query.state)
  const posture = active(req.query.posture)
  const issuer = active(req.query.issuer)
  const environment = active(req.query.environment)
  const provider = active(req.query.provider)
  const account = active(req.query.account)
  const region = active(req.query.region)
  const algorithm = active(req.query.algorithm)
  const tlsVersion = str(req.query.tlsVersion)
  const owner = active(req.query.owner)
  const issue = active(req.query.issue)
  const renewal = active(req.query.renewal)
  const range = active(req.query.range)
  const sort = str(req.query.sort) || 'expiry'

  const filtered = rows.filter(({ certificate, trust }) => {
    if (band && trust.band !== band) return false
    if (state && trust.state !== state) return false
    if (posture && certificate.posture !== posture) return false
    if (issuer && certificate.issuer.toLowerCase() !== issuer) return false
    if (environment && trust.environment.toLowerCase() !== environment) return false
    if (provider && trust.provider.toLowerCase() !== provider) return false
    if (account && trust.account.toLowerCase() !== account) return false
    if (region && trust.region.toLowerCase() !== region) return false
    if (algorithm && certificate.publicKeyAlgorithm.toLowerCase() !== algorithm) return false
    if (tlsVersion && !trust.tlsVersions.includes(tlsVersion)) return false
    if (owner && trust.owner.toLowerCase() !== owner) return false
    if (renewal && trust.renewal.status !== renewal) return false
    if (issue === 'orphan' && !trust.orphan) return false
    if (issue === 'ownerless' && trust.ownerKnown) return false
    if (issue === 'undeployed' && trust.deploymentKnown) return false
    if (issue === 'chain-failure' && trust.failedChecks === 0) return false
    if (!withinRange(certificate.lastObservedAt, range)) return false
    if (search) {
      const haystack = `${certificate.name} ${certificate.subject} ${certificate.issuer} ${certificate.serialNumber ?? ''} ${certificate.san.join(' ')} ${trust.owner}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })

  return filtered.sort((a, b) => {
    if (sort === 'risk') return b.certificate.riskScore - a.certificate.riskScore
    if (sort === 'blast') return b.trust.affectedAssetCount - a.trust.affectedAssetCount
    if (sort === 'name') return a.certificate.name.localeCompare(b.certificate.name)
    if (sort === 'issuer') return a.certificate.issuer.localeCompare(b.certificate.issuer)
    // 'expiry' - soonest first, unknown expiries last rather than pretending 0.
    const left = a.certificate.daysToExpiry ?? Number.POSITIVE_INFINITY
    const right = b.certificate.daysToExpiry ?? Number.POSITIVE_INFINITY
    return left - right
  })
}

function filterResources(resources: CloudResource[], req: Request): CloudResource[] {
  const search = active(req.query.search)
  const provider = active(req.query.provider)
  const account = active(req.query.account)
  const region = active(req.query.region)
  const environment = active(req.query.environment)
  const encryption = active(req.query.encryption)
  const state = active(req.query.state)
  const posture = active(req.query.posture)
  const compliance = active(req.query.compliance)
  const attribution = active(req.query.attribution)
  const risk = active(req.query.risk)
  const range = active(req.query.range)
  const sort = str(req.query.sort) || 'risk'

  const filtered = resources.filter((resource) => {
    if (provider && resource.provider.toLowerCase() !== provider) return false
    if (account && resource.account.toLowerCase() !== account) return false
    if (region && resource.region.toLowerCase() !== region) return false
    if (environment && resource.environment.toLowerCase() !== environment) return false
    if (encryption && resource.encryptionState !== encryption) return false
    if (state && resource.state !== state) return false
    if (posture && resource.posture !== posture) return false
    if (compliance && resource.complianceState !== compliance) return false
    if (risk && resource.riskLevel !== risk) return false
    if (attribution === 'attributed' && !resource.attribution.attributed) return false
    if (attribution === 'unattributed' && resource.attribution.attributed) return false
    if (!withinRange(resource.lastSeenAt, range)) return false
    if (search) {
      const haystack = `${resource.name} ${resource.resourceType} ${resource.service} ${resource.account} ${resource.region} ${resource.owner} ${resource.keyManagement}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })

  return filtered.sort((a, b) => {
    if (sort === 'name') return a.name.localeCompare(b.name)
    if (sort === 'region') return a.region.localeCompare(b.region)
    if (sort === 'provider') return a.providerLabel.localeCompare(b.providerLabel)
    return b.riskScore - a.riskScore
  })
}

function filterEvents(events: TrustEvent[], req: Request): TrustEvent[] {
  const search = active(req.query.search)
  const kind = active(req.query.kind)
  const severity = active(req.query.severity)
  const provider = active(req.query.provider)
  const region = active(req.query.region)
  const range = active(req.query.range)

  return events.filter((event) => {
    if (kind && event.kind !== kind) return false
    if (severity && event.severity !== severity) return false
    if (provider && (event.provider ?? '').toLowerCase() !== provider) return false
    if (region && event.region.toLowerCase() !== region) return false
    if (!withinRange(event.at, range)) return false
    if (search) {
      const haystack = `${event.title} ${event.detail} ${event.subject} ${event.source}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })
}

function filterFindings(findings: TlsFinding[], req: Request): TlsFinding[] {
  const search = active(req.query.search)
  const severity = active(req.query.severity)
  const category = active(req.query.category)
  const range = active(req.query.range)

  return findings.filter((finding) => {
    if (severity && finding.severity !== severity) return false
    if (category && finding.category !== category) return false
    if (!withinRange(finding.lastObservedAt, range)) return false
    if (search) {
      const haystack = `${finding.title} ${finding.observed} ${finding.assetName} ${finding.impact}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

function buildRouter(view: TrustView): Router {
  const router = Router()
  router.use(requireAuth)

  const model = (req: AuthedRequest, force = false) => buildTrustFabricModel(req.token!, req.user!.id, force)

  /* ---- GET / - the view payload -------------------------------- */
  router.get('/', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req, str(req.query.refresh) === '1')
      res.json({ data: projectView(data, view) })
    } catch (error) {
      console.error(`[trust-fabric:${view}] snapshot failed:`, error)
      res.status(500).json({
        error: {
          code: 'TRUST_FABRIC_ERROR',
          message: error instanceof Error ? error.message : 'Failed to compute trust intelligence',
        },
      })
    }
  })

  /**
   * GET /stream - Server-Sent Events carrying the WHOLE view payload.
   *
   * The client replaces state atomically rather than patching, which is what
   * stops the KPI strip, the tables and the charts from disagreeing mid-update.
   * Every connected client of a tenant collapses onto the one cached model, and
   * identical frames are suppressed so an idle dashboard costs nothing.
   */
  router.get('/stream', async (req: AuthedRequest, res: Response) => {
    res.status(200)
    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache, no-transform')
    res.setHeader('Connection', 'keep-alive')
    res.setHeader('X-Accel-Buffering', 'no')
    res.flushHeaders?.()

    let closed = false
    const send = (event: string, data: unknown) => {
      if (closed) return
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
    }

    send('connected', { at: new Date().toISOString(), view })

    let lastGeneratedAt = ''
    const push = async () => {
      try {
        const data = await model(req)
        // Suppress identical frames: within the cache window the model is the
        // same object, and re-sending it only burns bandwidth and re-renders.
        if (data.generatedAt === lastGeneratedAt) return
        lastGeneratedAt = data.generatedAt
        send('trust-fabric', projectView(data, view))
      } catch (error) {
        send('trust-fabric-error', {
          message: error instanceof Error ? error.message : 'Trust telemetry unavailable',
        })
      }
    }

    void push()
    const interval = setInterval(() => void push(), 10_000)
    const heartbeat = setInterval(() => {
      if (!closed) res.write(': heartbeat\n\n')
    }, 25_000)

    req.on('close', () => {
      closed = true
      clearInterval(interval)
      clearInterval(heartbeat)
    })
  })

  /* ---- Drill-down: shared across all four views ------------------ */

  router.get('/nodes', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const page = paginate(filterNodes(data.nodes, req), req)
      res.json({ data: { nodes: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      console.error(`[trust-fabric:${view}] nodes failed:`, error)
      res.status(500).json({ error: { code: 'TRUST_FABRIC_ERROR', message: 'Failed to load trust subjects' } })
    }
  })

  /**
   * One trust subject with everything needed to investigate it: its edges, the
   * chain it sits on, the certificates and findings attached, and the subjects
   * that depend on it. This is the "KPI -> asset -> finding -> remediation"
   * path from section 11.
   */
  router.get('/nodes/:id', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const id = str(req.params.id)
      const node = data.nodes.find((candidate) => candidate.id === id)
      if (!node) {
        return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Trust subject not found' } })
      }
      const edges = data.relationships.filter((edge) => edge.from === id || edge.to === id)
      const neighbourIds = new Set(edges.flatMap((edge) => [edge.from, edge.to]))
      neighbourIds.delete(id)
      const chain = data.chainPaths.find((path) => path.nodeIds.includes(id)) ?? null
      const certificates = data.certificates.filter(
        (certificate) => certificate.id === node.certificateId || (node.assetId ? certificate.assetId === node.assetId : false),
      )
      const findings = data.findings.filter((finding) => node.findingIds.includes(finding.id))
      res.json({
        data: {
          node,
          edges,
          neighbours: data.nodes.filter((candidate) => neighbourIds.has(candidate.id)).map(nodeSummary),
          chain,
          certificates,
          certificateTrust: data.certificateTrust.filter((record) => certificates.some((cert) => cert.id === record.certificateId)),
          findings,
          events: data.events.filter((event) => event.assetId === node.assetId || event.certificateId === node.certificateId).slice(0, 20),
        },
      })
    } catch (error) {
      console.error(`[trust-fabric:${view}] node detail failed:`, error)
      res.status(500).json({ error: { code: 'TRUST_FABRIC_ERROR', message: 'Failed to load trust subject' } })
    }
  })

  router.get('/relationships', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const kind = active(req.query.kind)
      const state = active(req.query.state)
      const nodeFilter = str(req.query.node)
      const filtered = data.relationships.filter((edge) => {
        if (kind && edge.kind !== kind) return false
        if (state && edge.state !== state) return false
        if (nodeFilter && edge.from !== nodeFilter && edge.to !== nodeFilter) return false
        return true
      })
      const page = paginate(filtered, req)
      res.json({ data: { relationships: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      console.error(`[trust-fabric:${view}] relationships failed:`, error)
      res.status(500).json({ error: { code: 'TRUST_FABRIC_ERROR', message: 'Failed to load trust relationships' } })
    }
  })

  router.get('/certificates', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const trustById = new Map(data.certificateTrust.map((record) => [record.certificateId, record]))
      const rows: CertificateRow[] = data.certificates
        .map((certificate) => ({ certificate, trust: trustById.get(certificate.id) }))
        .filter((row): row is CertificateRow => Boolean(row.trust))
      const page = paginate(filterCertificates(rows, req), req)
      res.json({
        data: {
          certificates: page.rows.map((row) => row.certificate),
          certificateTrust: page.rows.map((row) => row.trust),
          total: page.total,
          limit: page.limit,
          offset: page.offset,
        },
      })
    } catch (error) {
      console.error(`[trust-fabric:${view}] certificates failed:`, error)
      res.status(500).json({ error: { code: 'TRUST_FABRIC_ERROR', message: 'Failed to load certificates' } })
    }
  })

  router.get('/certificates/:id', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const id = str(req.params.id)
      const certificate = data.certificates.find((candidate) => candidate.id === id)
      if (!certificate) {
        return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Certificate not found' } })
      }
      const trust = data.certificateTrust.find((record) => record.certificateId === id) ?? null
      const chain = trust?.chainPathId ? data.chainPaths.find((path) => path.id === trust.chainPathId) ?? null : null
      const chainNodes = chain ? chain.nodeIds.map((nodeKey) => data.nodes.find((node) => node.id === nodeKey)).filter(Boolean) : []
      const affected = (trust?.affectedNodeIds ?? [])
        .map((nodeKey) => data.nodes.find((node) => node.id === nodeKey))
        .filter((node): node is TrustNode => Boolean(node))
      res.json({
        data: {
          certificate,
          trust,
          chain,
          chainNodes,
          affected: affected.map(nodeSummary),
          endpoint: certificate.endpointId ? data.endpoints.find((endpoint) => endpoint.id === certificate.endpointId) ?? null : null,
          findings: data.findings.filter(
            (finding) => finding.category === 'certificate' && (finding.assetId === certificate.assetId || finding.observed === certificate.algorithmLabel),
          ),
          events: data.events.filter((event) => event.certificateId === id).slice(0, 20),
        },
      })
    } catch (error) {
      console.error(`[trust-fabric:${view}] certificate detail failed:`, error)
      res.status(500).json({ error: { code: 'TRUST_FABRIC_ERROR', message: 'Failed to load certificate' } })
    }
  })

  router.get('/cloud-resources', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const page = paginate(filterResources(data.cloud.resources, req), req)
      res.json({ data: { resources: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      console.error(`[trust-fabric:${view}] cloud resources failed:`, error)
      res.status(500).json({ error: { code: 'TRUST_FABRIC_ERROR', message: 'Failed to load cloud resources' } })
    }
  })

  router.get('/cloud-resources/:id', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const id = str(req.params.id)
      const resource = data.cloud.resources.find((candidate) => candidate.id === id)
      if (!resource) {
        return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Cloud resource not found' } })
      }
      const certificates = data.certificates.filter((certificate) => resource.certificateIds.includes(certificate.id))
      res.json({
        data: {
          resource,
          certificates,
          certificateTrust: data.certificateTrust.filter((record) => resource.certificateIds.includes(record.certificateId)),
          endpoints: data.endpoints.filter((endpoint) => endpoint.assetId === resource.assetId),
          findings: data.findings.filter((finding) => resource.findingIds.includes(finding.id)),
          region: data.cloud.regions.find((region) => region.provider === resource.provider && region.region === resource.region) ?? null,
          events: data.events.filter((event) => event.assetId === resource.assetId).slice(0, 20),
        },
      })
    } catch (error) {
      console.error(`[trust-fabric:${view}] cloud resource detail failed:`, error)
      res.status(500).json({ error: { code: 'TRUST_FABRIC_ERROR', message: 'Failed to load cloud resource' } })
    }
  })

  router.get('/events', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const page = paginate(filterEvents(data.events, req), req)
      res.json({ data: { events: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      console.error(`[trust-fabric:${view}] events failed:`, error)
      res.status(500).json({ error: { code: 'TRUST_FABRIC_ERROR', message: 'Failed to load trust events' } })
    }
  })

  router.get('/findings', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const page = paginate(filterFindings(data.findings, req), req)
      res.json({ data: { findings: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      console.error(`[trust-fabric:${view}] findings failed:`, error)
      res.status(500).json({ error: { code: 'TRUST_FABRIC_ERROR', message: 'Failed to load findings' } })
    }
  })

  /** Section 16: the reconciliation report, on its own route for the drawer. */
  router.get('/reconciliation', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      res.json({ data: data.reconciliation })
    } catch (error) {
      console.error(`[trust-fabric:${view}] reconciliation failed:`, error)
      res.status(500).json({ error: { code: 'TRUST_FABRIC_ERROR', message: 'Failed to load reconciliation report' } })
    }
  })

  router.post('/invalidate', (req: AuthedRequest, res: Response) => {
    invalidateTrustFabricModel(req.user!.id)
    res.json({ data: { invalidated: true } })
  })

  return router
}

export const trustDashboardRoutes = buildRouter('trust')
export const trustStateDiscoveryRoutes = buildRouter('discovery')
export const certificateTelemetryRoutes = buildRouter('certificate')
export const multiCloudTelemetryRoutes = buildRouter('cloud')
