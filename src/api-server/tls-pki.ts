/**
 * TLS & PKI Intelligence Command Center — the one backend behind four pages.
 *
 * `/api/v1/dashboard/tls-telemetry`
 * `/api/v1/dashboard/pki-visibility`
 * `/api/v1/dashboard/protocol-analytics`
 * `/api/v1/dashboard/tls-orchestrator`
 *
 * All four are projections of a single per-tenant model computed once per
 * window. Before this module they were three unrelated builders (and the
 * orchestrator was mounted on the telemetry router, so it had no backend of its
 * own), which is why the same asset could read "PQC ready" on one page and
 * "quantum vulnerable" on the next.
 *
 * Caching contract, matching `buildSnapshot` / `buildPortfolio` /
 * `buildRuntimeIntel`: only the FETCH + derivation is cached, per tenant, for
 * 15s. Every connected dashboard and every SSE push of a tenant collapses onto
 * that one computation, so N open pages cost the same as one AND cannot
 * disagree within the window. Failures are never cached.
 */

import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { buildPortfolio } from './migration-planner'
import { buildTlsPkiIntelligence } from '@/lib/tls-pki/intelligence'
import { payloadFingerprint, streamLiveSnapshot } from './live-snapshot-stream'
import { createSingleFlightCache } from '@/lib/single-flight-cache'
import { compareTelemetryAssets, type TelemetryAsset } from '@/lib/telemetry/asset-comparison'
import { buildEncryptionModel } from './encryption-monitoring'
import { createSourceLedger, type SourceRead } from './source-ledger'
import { readTelemetrySource } from './telemetry-source-rows'
import type { TlsPkiIntelligence, TlsEndpoint, PkiCertificate, TlsFinding, OrchestrationItem } from '@/lib/tls-pki/types'

type Row = Record<string, unknown>

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

export type TlsPkiView = 'telemetry' | 'pki' | 'protocol' | 'orchestrator'

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

/** The model as published: the intelligence plus the outcome of every source read. */
export type TlsPkiModel = TlsPkiIntelligence & { reads: SourceRead[] }

/* ------------------------------------------------------------------ */
/* Auth                                                                */
/* ------------------------------------------------------------------ */

/**
 * Authorization header ONLY. The `?token=` fallback this replaced let a BASIC
 * tenant read all four Pro pages: the subscription gateway reads only the
 * header and passes a header-less request through for the router to answer,
 * and the router then accepted the token from the URL (common-issues #63/#66).
 * Every frontend hook already streams over fetch() with the header.
 */
function tokenFromRequest(req: Request): string | null {
  return getToken(req)
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
  runtimeEvents: 6000,
  cryptoInventory: 4000,
  certificates: 2500,
  scannerEvidence: 3000,
  scanResults: 2500,
  cryptoExposures: 2500,
  scannerAlerts: 1500,
  securityEvents: 1500,
  migrationJobs: 1200,
  migrationPlans: 200,
  scanSessions: 400,
  scannerAgents: 400,
  connectorAccounts: 400,
  agentHeartbeats: 600,
  validationLogs: 800,
} as const

/* ------------------------------------------------------------------ */
/* Model builder + cache                                               */
/* ------------------------------------------------------------------ */

const MODEL_TTL_MS = 15_000
const modelCache = createSingleFlightCache<TlsPkiModel>(MODEL_TTL_MS)

async function computeModel(token: string, userId: string, force: boolean): Promise<TlsPkiModel> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')
  // A failed read still degrades to [] (one broken table never blanks the
  // page) but is RECORDED as unavailable and published, so its zeros are never
  // read as measurements (common-issues #64).
  const ledger = createSourceLedger('tls-pki')

  // Canonical estate truth first: these two are themselves cached per tenant,
  // so asking for them here is nearly free and guarantees this page agrees with
  // Quantum Readiness, Assets, Migration Planner and every report.
  const [snapshot, portfolio] = await Promise.all([buildSnapshot(token, userId, undefined, force), buildPortfolio(token, userId, force)])

  const [
    runtimeEvents,
    cryptoInventory,
    certificates,
    scannerEvidence,
    scanResults,
    cryptoExposures,
    scannerAlerts,
    securityEvents,
    migrationJobs,
    migrationPlans,
    scanSessions,
    scannerAgents,
    connectorAccounts,
    agentHeartbeats,
    validationLogs,
  ] = await Promise.all([
    readTelemetrySource(
      ledger, client, 'runtime_crypto_events',
      'id, agent_id, connector_account_id, asset_id, source_type, event_type, operation_type, severity, risk_score, asset_name, asset_type, host, port, protocol, tls_version, cipher_suite, key_exchange_algorithm, algorithm, key_size, certificate_fingerprint, process_name, is_pqc, is_legacy, downgrade_detected, shadow_crypto, hndl_risk, metadata, observed_at, created_at',
      CAP.runtimeEvents, (q) => q
        .eq('user_id', userId)
        .order('observed_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'crypto_inventory',
      'id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, metadata, discovered_at, created_at',
      CAP.cryptoInventory, (q) => q
        .eq('user_id', userId)
        .order('discovered_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'certificates',
      'id, asset_id, name, algorithm, key_size, issuer, subject, serial_number, not_before, not_after, is_quantum_safe, is_expiring_soon, status, metadata, created_at, updated_at',
      CAP.certificates, (q) => q
        .eq('user_id', userId)
        .order('updated_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'scanner_evidence',
      'id, agent_id, connector_account_id, source_type, evidence_type, asset_name, asset_type, target, host, port, protocol, observed_algorithm, raw_evidence, processed_at, observed_at, created_at',
      CAP.scannerEvidence, (q) => q
        .eq('user_id', userId)
        .order('observed_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'pqc_scan_results',
      'id, scan_session_id, asset_id, finding_type, algorithm, threat_level, description, remediation, metadata, created_at',
      CAP.scanResults, (q) => q
        .eq('user_id', userId)
        .order('created_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'crypto_exposures',
      'id, asset_id, exposure_type, severity, description, detected_value, metadata, created_at, updated_at',
      CAP.cryptoExposures, (q) => q
        .eq('user_id', userId)
        .order('updated_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'scanner_alerts',
      'id, agent_id, evidence_id, severity, category, title, message, recommendation, status, metadata, created_at, updated_at',
      CAP.scannerAlerts, (q) => q
        .eq('user_id', userId)
        .order('created_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'security_events',
      'id, event_type, severity, message, asset_id, resource_name, resource_type, metadata, created_at',
      CAP.securityEvents, (q) => q
        .eq('user_id', userId)
        .order('created_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'migration_jobs',
      'id, asset_id, name, job_type, status, target_algorithm, progress, metadata, started_at, completed_at, created_at, updated_at',
      CAP.migrationJobs, (q) => q
        .eq('user_id', userId)
        .order('updated_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'migration_plans',
      'id, status, selected_asset_ids, metadata, created_at, updated_at',
      CAP.migrationPlans, (q) => q
        .eq('user_id', userId)
        .order('updated_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'pqc_scan_sessions',
      'id, status, progress, total_assets, scanned_assets, findings_count, started_at, completed_at, created_at, updated_at',
      CAP.scanSessions, (q) => q
        .eq('user_id', userId)
        .order('updated_at', { ascending: false }),
    ),
    readTelemetrySource(
      ledger, client, 'scanner_agents',
      'id, name, status, hostname, platform, last_seen_at, metadata, created_at, updated_at',
      CAP.scannerAgents, (q) => q.eq('user_id', userId),
    ),
    readTelemetrySource(
      ledger, client, 'connector_accounts',
      'id, provider, display_name, status, last_sync_at, created_at, updated_at',
      CAP.connectorAccounts, (q) => q.eq('user_id', userId),
    ),
    readTelemetrySource(
      ledger, client, 'agent_heartbeats',
      'id, agent_id, status, observed_at, created_at',
      CAP.agentHeartbeats, (q) => q.eq('user_id', userId).order('observed_at', { ascending: false }),
    ),
    // migration_validation_logs is JOB-scoped: its only FK is
    // migration_id -> migration_jobs(id). Asking for asset_id here made
    // PostgREST reject the whole query (42703) and silently return nothing,
    // which is the trap documented in migration-planner.ts. Resolve the asset
    // through the job below instead.
    readTelemetrySource(
      ledger, client, 'migration_validation_logs',
      'id, migration_id, status, created_at',
      CAP.validationLogs, (q) => q.eq('user_id', userId).order('created_at', { ascending: false }),
    ),
  ])

  const jobAssetById = new Map(migrationJobs.map((job) => [str(job.id), str(job.asset_id)]))
  const resolvedValidationLogs = validationLogs.map((log) => ({
    ...log,
    asset_id: jobAssetById.get(str(log.migration_id)) || '',
  }))

  const truncated = ledger.reads.some((read) => read.state === 'truncated')

  const intelligence = buildTlsPkiIntelligence({
    assets: portfolio.assets,
    snapshot: {
      quantumReadiness: snapshot.scores.quantumReadiness,
      quantumRisk: snapshot.scores.quantumRisk,
      quantumRiskLevel: snapshot.scores.quantumRiskLevel,
      assetsAssessed: snapshot.inventory.assetsAssessed,
    },
    runtimeEvents,
    cryptoInventory,
    certificates,
    scannerEvidence,
    scanResults,
    cryptoExposures,
    scannerAlerts,
    securityEvents,
    migrationJobs,
    migrationPlans,
    scanSessions,
    scannerAgents,
    connectorAccounts,
    agentHeartbeats,
    validationLogs: resolvedValidationLogs,
    queuedAssetIds: portfolio.assets.filter((asset) => asset.queued).map((asset) => asset.id),
    truncated,
  })
  return Object.assign(intelligence, { reads: ledger.reads })
}

export async function buildTlsPkiModel(token: string, userId: string, force = false): Promise<TlsPkiModel> {
  return modelCache.get(userId, () => computeModel(token, userId, force), force)
}

/** Drops the tenant's cached model so the next read reflects a just-made write. */
export function invalidateTlsPkiModel(userId: string) {
  modelCache.delete(userId)
}

/* ------------------------------------------------------------------ */
/* Projections — bounded payloads, one per page                        */
/* ------------------------------------------------------------------ */

/** Rows shipped in the first paint. Deeper pages come from the paging routes. */
const PAGE = { endpoints: 60, certificates: 60, findings: 40, items: 60 } as const

/** Fields every page shares, so the header is identical on all four. */
const inventoryRevisions = new WeakMap<TlsPkiModel, string>()
function tlsInventoryRevision(model: TlsPkiModel) {
  let revision = inventoryRevisions.get(model)
  if (!revision) {
    revision = payloadFingerprint({ endpoints: model.endpoints, certificates: model.certificates,
      findings: model.findings, observations: model.observations, orchestration: model.orchestration.items })
    inventoryRevisions.set(model, revision)
  }
  return revision
}

function commonEnvelope(model: TlsPkiModel) {
  return {
    generatedAt: model.generatedAt,
    inventoryRevision: tlsInventoryRevision(model),
    latestEvidenceAt: model.latestEvidenceAt,
    hasData: model.hasData,
    /** Outcome of every source read: `unavailable` means the query FAILED, not "none". */
    reads: model.reads,
    posture: model.posture,
    telemetry: model.telemetry,
    timeline: model.timeline,
    /** Cross-page totals so a header count can never differ between pages. */
    totals: {
      endpoints: model.endpoints.length,
      /**
       * Endpoints that have actually been observed negotiating something. This
       * is the denominator behind every TLS percentage; `endpoints` is the
       * wider set that also includes certificate-only records.
       */
      measuredEndpoints: model.endpoints.filter((endpoint) => endpoint.hasTransportEvidence).length,
      certificates: model.certificates.length,
      findings: model.findings.length,
      /**
       * Findings split by provenance so the number reconciles with the
       * Scanner's own count instead of appearing to contradict it: `scanner`
       * are rows the scanner reported, `derived` are weaknesses this engine
       * establishes from a measured observation (a CBC suite, a deprecated
       * version) that the scanner never filed as a separate finding.
       */
      findingsDerived: model.findings.filter((finding) => !finding.id.startsWith('tls-finding:scanner:')).length,
      findingsFromScanner: model.findings.filter((finding) => finding.id.startsWith('tls-finding:scanner:')).length,
      observations: model.observations.length,
      orchestrationItems: model.orchestration.items.length,
    },
  }
}

/** Endpoint summary shipped alongside every view for drill-down labels. */
function endpointSummary(endpoint: TlsEndpoint) {
  return {
    id: endpoint.id,
    assetId: endpoint.assetId,
    name: endpoint.name,
    host: endpoint.host,
    port: endpoint.port,
    environment: endpoint.environment,
    internetFacing: endpoint.internetFacing,
    posture: endpoint.posture,
    riskLevel: endpoint.riskLevel,
    riskScore: endpoint.riskScore,
    negotiatedVersion: endpoint.negotiatedVersion,
    transportBasis: endpoint.transportBasis,
  }
}

export function projectView(model: TlsPkiModel, view: TlsPkiView) {
  const base = commonEnvelope(model)

  switch (view) {
    case 'telemetry':
      return {
        ...base,
        view: 'telemetry' as const,
        // Matches the /endpoints default scope, so the first paint and the first
        // page of the table cannot show different rows.
        endpoints: model.endpoints.filter((endpoint) => endpoint.hasTransportEvidence).slice(0, PAGE.endpoints),
        versionDistribution: model.protocol.versionDistribution,
        keyExchangeDistribution: model.protocol.keyExchangeDistribution,
        cipherDistribution: model.protocol.cipherDistribution.slice(0, 10),
        forwardSecrecy: model.protocol.forwardSecrecy,
        findings: model.findings.slice(0, PAGE.findings),
        anomalies: model.protocol.anomalies,
        handshake: {
          failures: model.protocol.handshakeFailures,
          measured: model.protocol.handshakeFailuresMeasured,
          downgradeEndpoints: model.protocol.downgradeEndpointIds.length,
          downgradeMeasured: model.protocol.downgradeMeasured,
        },
      }

    case 'pki':
      return {
        ...base,
        view: 'pki' as const,
        certificates: model.certificates.slice(0, PAGE.certificates),
        lifecycle: model.pki.lifecycle,
        expiryBuckets: model.pki.expiryBuckets,
        issuers: model.pki.issuers,
        algorithmDistribution: model.pki.algorithmDistribution,
        trustChains: model.trustChains,
        findings: model.findings.filter((finding) => finding.category === 'certificate').slice(0, PAGE.findings),
        endpointIndex: model.endpoints.map(endpointSummary),
      }

    case 'protocol':
      return {
        ...base,
        view: 'protocol' as const,
        protocol: { ...model.protocol, ssh: model.protocol.ssh.slice(0, 25) },
        sshObservationCount: model.protocol.ssh.length,
        endpointIndex: model.endpoints.map(endpointSummary),
        findings: model.findings
          .filter((finding) => finding.category === 'protocol' || finding.category === 'cipher' || finding.category === 'key-exchange')
          .slice(0, PAGE.findings),
      }

    case 'orchestrator':
    default:
      return {
        ...base,
        view: 'orchestrator' as const,
        queuedAssetIds: model.orchestration.queuedAssetIds,
        orchestration: {
          ...model.orchestration,
          items: model.orchestration.items.slice(0, PAGE.items),
          drift: model.orchestration.drift.slice(0, 25),
        },
        endpointIndex: model.endpoints.map(endpointSummary),
        findings: model.findings.slice(0, PAGE.findings),
      }
  }
}

/**
 * One projection per (cached model, view): every open tab of a tenant shares the
 * object, so the stream's fingerprint is computed once per model, not per tab.
 */
const projectionMemo = new WeakMap<TlsPkiModel, Map<TlsPkiView, ReturnType<typeof projectView>>>()
function projectedView(model: TlsPkiModel, view: TlsPkiView) {
  let byView = projectionMemo.get(model)
  if (!byView) {
    byView = new Map()
    projectionMemo.set(model, byView)
  }
  let projected = byView.get(view)
  if (!projected) {
    projected = projectView(model, view)
    byView.set(view, projected)
  }
  return projected
}

/* ------------------------------------------------------------------ */
/* Server-side filtering for the paging routes                         */
/* ------------------------------------------------------------------ */

function paginate<T>(rows: T[], req: Request) {
  const limit = Math.max(1, Math.min(200, num(req.query.limit) || 50))
  const offset = Math.max(0, num(req.query.offset))
  return { rows: rows.slice(offset, offset + limit), total: rows.length, limit, offset }
}

function filterEndpoints(endpoints: TlsEndpoint[], req: Request): TlsEndpoint[] {
  const search = str(req.query.search).toLowerCase()
  const posture = str(req.query.posture).toLowerCase()
  const environment = str(req.query.environment).toLowerCase()
  const risk = str(req.query.risk).toLowerCase()
  const version = str(req.query.version)
  const sort = str(req.query.sort) || 'risk'
  /**
   * `transport` scopes the list to endpoints actually observed negotiating.
   * Default is 'measured' so a TLS console lists TLS endpoints; 'all' opts in
   * to certificate-only records rather than hiding them, and the UI states the
   * difference in the filter label so nothing is silently dropped.
   */
  const transport = str(req.query.transport) || 'measured'

  const filtered = endpoints.filter((endpoint) => {
    if (transport === 'measured' && !endpoint.hasTransportEvidence) return false
    if (transport === 'certificate-only' && endpoint.hasTransportEvidence) return false
    if (posture && posture !== 'all' && endpoint.posture !== posture) return false
    if (environment && environment !== 'all' && endpoint.environment.toLowerCase() !== environment) return false
    if (risk && risk !== 'all' && endpoint.riskLevel !== risk) return false
    if (version && version !== 'all' && endpoint.negotiatedVersion !== version) return false
    if (search) {
      const haystack = `${endpoint.name} ${endpoint.host} ${endpoint.owner} ${endpoint.assetType} ${endpoint.cipherSuites.join(' ')} ${endpoint.keyExchange.join(' ')}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })

  const direction = str(req.query.dir) === 'asc' ? 1 : -1
  filtered.sort((a, b) => {
    if (sort === 'name') return a.name.localeCompare(b.name) * (direction === -1 ? -1 : 1)
    if (sort === 'expiry') {
      const av = a.daysToExpiry ?? Number.MAX_SAFE_INTEGER
      const bv = b.daysToExpiry ?? Number.MAX_SAFE_INTEGER
      return (av - bv) * (direction === -1 ? 1 : -1)
    }
    if (sort === 'observed') return (Date.parse(b.lastObservedAt || '') - Date.parse(a.lastObservedAt || '')) * (direction === -1 ? 1 : -1)
    return (a.riskScore - b.riskScore) * direction
  })
  return filtered
}

function filterCertificates(certificates: PkiCertificate[], req: Request): PkiCertificate[] {
  const search = str(req.query.search).toLowerCase()
  const lifecycle = str(req.query.lifecycle).toLowerCase()
  const posture = str(req.query.posture).toLowerCase()
  const issuer = str(req.query.issuer).toLowerCase()
  const sort = str(req.query.sort) || 'risk'
  const direction = str(req.query.dir) === 'asc' ? 1 : -1

  const filtered = certificates.filter((cert) => {
    if (lifecycle && lifecycle !== 'all' && cert.lifecycle !== lifecycle) return false
    if (posture && posture !== 'all' && cert.posture !== posture) return false
    if (issuer && issuer !== 'all' && cert.issuer.toLowerCase() !== issuer) return false
    if (search) {
      const haystack = `${cert.subject} ${cert.issuer} ${cert.assetName} ${cert.publicKeyAlgorithm} ${cert.serialNumber || ''} ${cert.san.join(' ')}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })

  filtered.sort((a, b) => {
    if (sort === 'subject') return a.subject.localeCompare(b.subject) * (direction === -1 ? -1 : 1)
    if (sort === 'expiry') {
      const av = a.daysToExpiry ?? Number.MAX_SAFE_INTEGER
      const bv = b.daysToExpiry ?? Number.MAX_SAFE_INTEGER
      return (av - bv) * (direction === -1 ? 1 : -1)
    }
    if (sort === 'issuer') return a.issuer.localeCompare(b.issuer) * (direction === -1 ? -1 : 1)
    return (a.riskScore - b.riskScore) * direction
  })
  return filtered
}

function filterFindings(findings: TlsFinding[], req: Request): TlsFinding[] {
  const search = str(req.query.search).toLowerCase()
  const severity = str(req.query.severity).toLowerCase()
  const category = str(req.query.category).toLowerCase()
  const endpointId = str(req.query.endpointId)

  return findings.filter((finding) => {
    if (severity && severity !== 'all' && finding.severity !== severity) return false
    if (category && category !== 'all' && finding.category !== category) return false
    if (endpointId && finding.endpointId !== endpointId) return false
    if (search) {
      const haystack = `${finding.title} ${finding.assetName} ${finding.observed} ${finding.remediation}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })
}

function filterOrchestration(items: OrchestrationItem[], req: Request): OrchestrationItem[] {
  const search = str(req.query.search).toLowerCase()
  const status = str(req.query.status).toLowerCase()
  const action = str(req.query.action).toLowerCase()
  const severity = str(req.query.severity).toLowerCase()

  return items.filter((item) => {
    if (status && status !== 'all' && item.status !== status) return false
    if (action && action !== 'all' && item.action !== action) return false
    if (severity && severity !== 'all' && item.severity !== severity) return false
    if (search) {
      const haystack = `${item.assetName} ${item.host} ${item.actionLabel} ${item.changeSummary} ${item.currentState}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    return true
  })
}

/* ------------------------------------------------------------------ */
/* Router factory                                                      */
/* ------------------------------------------------------------------ */

function buildRouter(view: TlsPkiView): Router {
  const router = Router()
  router.use(requireAuth)
  router.use((_req, res, next) => { res.setHeader('Cache-Control', 'private, no-store'); next() })

  const model = (req: AuthedRequest, force = false) => buildTlsPkiModel(req.token!, req.user!.id, force)

  if (view === 'telemetry') {
    const inventory = (req: AuthedRequest) => {
      const client = createAuthClient(req.token!)
      if (!client) throw new Error('Asset inventory unavailable')
      return client.from('assets').select('id, name, type, environment', { count: 'exact' })
        .eq('user_id', req.user!.id).is('metadata->>consolidatedIntoAssetId', null)
    }
    const assetOption = (row: Record<string, unknown>): TelemetryAsset => ({
      id: str(row.id), name: str(row.name) || 'Unnamed asset', type: str(row.type) || 'Unrecorded',
      environment: str(row.environment) || 'Unrecorded',
    })
    router.get('/asset-options', async (req: AuthedRequest, res) => {
      try {
        const search = str(req.query.search).slice(0, 120)
        const offset = Math.max(0, Math.floor(num(req.query.offset)))
        const query = inventory(req)
        if (search) query.ilike('name', `%${search.replace(/[\\%_]/g, '\\$&')}%`)
        const { data, error, count } = await query.order('name').order('id').range(offset, offset + 19)
        if (error || count === null) throw new Error('Asset inventory unavailable')
        res.json({ data: { assets: (data ?? []).map(assetOption), total: count } })
      } catch {
        res.status(503).json({ error: { message: 'Registered asset inventory is unavailable.' } })
      }
    })

    function scope(req: AuthedRequest, res: Response) {
      const ids = [...new Set(str(req.query.assets).toLowerCase().split(',').filter(Boolean))].sort()
      if (ids.length < 1 || ids.length > 4 || ids.some((id) => !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(id))) {
        res.status(400).json({ error: { message: 'Select one to four registered assets.' } })
        return null
      }
      return ids
    }
    const compare = async (req: AuthedRequest, ids: string[]) => {
      const { data, error } = await inventory(req).in('id', ids).order('name').order('id')
      if (error) throw new Error('Registered asset inventory is unavailable.')
      if (!data || data.length !== ids.length) return null
      const force = req.query.refresh === '1'
      const tls = await model(req, force)
      const encryption = await buildEncryptionModel(req.token!, req.user!.id, force)
      return compareTelemetryAssets(data.map(assetOption), tls, encryption)
    }
    router.get('/asset-comparison', async (req: AuthedRequest, res) => {
      const ids = scope(req, res)
      if (!ids) return
      try {
        const data = await compare(req, ids)
        if (!data) return res.status(404).json({ error: { message: 'A selected asset is unavailable.' } })
        return res.json({ data: { ...data, fingerprint: payloadFingerprint(data) } })
      } catch {
        return res.status(503).json({ error: { message: 'Asset telemetry is temporarily unavailable.' } })
      }
    })
    router.get('/asset-comparison/stream', (req: AuthedRequest, res) => {
      const ids = scope(req, res)
      if (!ids) return
      streamLiveSnapshot(req, res, {
        event: 'asset-telemetry', intervalMs: 10_000, build: async () => {
          const data = await compare(req, ids)
          if (!data) throw new Error('A selected asset is unavailable.')
          return data
        },
      })
    })
  }

  /* ---- GET / — the view payload -------------------------------- */
  router.get('/', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req, str(req.query.refresh) === '1')
      const projection = projectedView(data, view)
      res.json({ data: { ...projection, fingerprint: payloadFingerprint(projection) } })
    } catch (error) {
      console.error(`[tls-pki:${view}] snapshot failed:`, error)
      res.status(500).json({
        error: { code: 'TLS_PKI_ERROR', message: error instanceof Error ? error.message : 'Failed to compute TLS/PKI intelligence' },
      })
    }
  })

  /**
   * GET /stream — Server-Sent Events carrying the WHOLE view payload.
   *
   * The client replaces state atomically rather than patching, which is what
   * stops the KPI strip, the tables and the charts from disagreeing mid-update.
   * Every connected client of a tenant collapses onto the one cached model.
   */
  router.get('/stream', (req: AuthedRequest, res: Response) => {
    // The platform stream: a full frame only when CONTENT changes (fingerprint
    // excludes generatedAt), otherwise a ~150-byte `tls-pki-unchanged` proof of
    // re-verification. Deduplicating on `generatedAt` re-sent the whole payload
    // every time the 15s cache recomputed, changed or not.
    streamLiveSnapshot(req, res, {
      event: 'tls-pki',
      build: async () => projectedView(await model(req), view),
      intervalMs: 10_000,
    })
  })

  /* ---- Drill-down: shared across all four views ------------------ */

  router.get('/endpoints', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const filtered = filterEndpoints(data.endpoints, req)
      const page = paginate(filtered, req)
      res.json({ data: { endpoints: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      console.error(`[tls-pki:${view}] endpoints failed:`, error)
      res.status(500).json({ error: { code: 'TLS_PKI_ERROR', message: 'Failed to load endpoints' } })
    }
  })

  /**
   * GET /endpoints/:id — the full investigation record for one endpoint.
   *
   * Shipped lazily: the dashboard payload deliberately does not carry every
   * observation for every endpoint, so the drawer fetches the one it needs.
   */
  router.get('/endpoints/:id', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const endpoint = data.endpoints.find((row) => row.id === req.params.id)
      if (!endpoint) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Endpoint not found' } })
      res.json({
        data: {
          endpoint,
          observations: data.observations.filter((row) => row.endpointId === endpoint.id),
          certificates: data.certificates.filter((cert) => endpoint.certificateIds.includes(cert.id)),
          findings: data.findings.filter((finding) => endpoint.findingIds.includes(finding.id)),
          orchestration: data.orchestration.items.filter((item) => item.endpointId === endpoint.id),
        },
      })
    } catch (error) {
      console.error(`[tls-pki:${view}] endpoint detail failed:`, error)
      res.status(500).json({ error: { code: 'TLS_PKI_ERROR', message: 'Failed to load endpoint detail' } })
    }
  })

  router.get('/certificates', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const filtered = filterCertificates(data.certificates, req)
      const page = paginate(filtered, req)
      res.json({ data: { certificates: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      console.error(`[tls-pki:${view}] certificates failed:`, error)
      res.status(500).json({ error: { code: 'TLS_PKI_ERROR', message: 'Failed to load certificates' } })
    }
  })

  router.get('/certificates/:id', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const certificate = data.certificates.find((cert) => cert.id === req.params.id)
      if (!certificate) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Certificate not found' } })
      const endpoint = certificate.endpointId ? data.endpoints.find((row) => row.id === certificate.endpointId) || null : null
      res.json({
        data: {
          certificate,
          endpoint,
          findings: data.findings.filter((finding) => finding.category === 'certificate' && finding.certificateId === certificate.id),
          chain: data.trustChains.filter(
            (node) => node.certificateIds.includes(certificate.id) || node.children.some((child) => child.certificateIds.includes(certificate.id)),
          ),
        },
      })
    } catch (error) {
      console.error(`[tls-pki:${view}] certificate detail failed:`, error)
      res.status(500).json({ error: { code: 'TLS_PKI_ERROR', message: 'Failed to load certificate detail' } })
    }
  })

  router.get('/findings', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const filtered = filterFindings(data.findings, req)
      const page = paginate(filtered, req)
      res.json({ data: { findings: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      console.error(`[tls-pki:${view}] findings failed:`, error)
      res.status(500).json({ error: { code: 'TLS_PKI_ERROR', message: 'Failed to load findings' } })
    }
  })

  router.get('/observations', async (req: AuthedRequest, res: Response) => {
    try {
      const data = await model(req)
      const endpointId = str(req.query.endpointId)
      const kind = str(req.query.kind)
      const search = str(req.query.search).toLowerCase()
      const filtered = data.observations.filter((row) => {
        if (endpointId && row.endpointId !== endpointId) return false
        if (kind && kind !== 'all' && row.kind !== kind) return false
        if (search && !`${row.observed} ${row.family}`.toLowerCase().includes(search)) return false
        return true
      })
      const page = paginate(filtered, req)
      res.json({ data: { observations: page.rows, total: page.total, limit: page.limit, offset: page.offset } })
    } catch (error) {
      console.error(`[tls-pki:${view}] observations failed:`, error)
      res.status(500).json({ error: { code: 'TLS_PKI_ERROR', message: 'Failed to load observations' } })
    }
  })

  /* ---- Orchestrator-only surfaces -------------------------------- */

  if (view === 'orchestrator') {
    router.get('/queue', async (req: AuthedRequest, res: Response) => {
      try {
        const data = await model(req)
        const filtered = filterOrchestration(data.orchestration.items, req)
        const page = paginate(filtered, req)
        res.json({
          data: {
            items: page.rows,
            total: page.total,
            limit: page.limit,
            offset: page.offset,
            statusCounts: data.orchestration.statusCounts,
          },
        })
      } catch (error) {
        console.error('[tls-pki:orchestrator] queue failed:', error)
        res.status(500).json({ error: { code: 'TLS_PKI_ERROR', message: 'Failed to load the remediation queue' } })
      }
    })

    /**
     * POST /invalidate — drop this tenant's cached model.
     *
     * Called by the UI immediately after it has made a real change through the
     * Migration Planner API, so the orchestrator reflects the new queue state
     * on the very next read instead of up to 15s later. It performs no write of
     * its own; the actual mutation happens on the planner's own tenant-verified
     * endpoints, which is where that logic already lives.
     */
    router.post('/invalidate', (req: AuthedRequest, res: Response) => {
      invalidateTlsPkiModel(req.user!.id)
      res.json({ data: { invalidated: true, at: new Date().toISOString() } })
    })
  }

  return router
}

export const tlsTelemetryRoutes = buildRouter('telemetry')
export const pkiVisibilityRoutes = buildRouter('pki')
export const protocolAnalyticsRoutes = buildRouter('protocol')
export const tlsOrchestratorRoutes = buildRouter('orchestrator')
