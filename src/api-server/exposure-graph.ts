import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { createSingleFlightCache } from '@/lib/single-flight-cache'
import { deriveAssetPostureModel, readinessPostureMeasured, recordOf } from '@/lib/migration/asset-intelligence'
import { SIMULATION_MARKER_SELECT, isSimulationRow } from '@/lib/migration/job-safety'
import { isCryptographicComponent, observationClass } from '@/lib/scanner/finding-identity'
import { evidenceTimestamp } from '@/lib/scanner/asset-components'
import { scannerFindingsFromEvidence } from './scanner'
import { buildSnapshot, isDeterministicReadGap, SnapshotReadError } from './quantum-readiness'
import { payloadFingerprint, streamLiveSnapshot } from './live-snapshot-stream'
import {
  classifyAlgorithmClass,
  classifyAssetCategory,
  classifyTrustClass,
  computeBlastRadius,
  computePriority,
  criticalityLabel,
  buildAdjacency,
  priorityFromScore,
  tierForCategory,
  MIGRATION_TIERS,
  TRUST_CHAIN_CLASSES,
} from '@/lib/exposure-graph-intel'
import type {
  AdvisorRecommendation,
  EdgeTrustClass,
  ExposureFinding,
  ExposureFindingPage,
  ExposureGraphEdge,
  ExposureGraphNode,
  ExposureIntelligence,
  MigrationBlocker,
  MigrationCluster,
  MigrationWaveEntry,
  NodeCertificate,
  NodePosture,
  PriorityLabel,
  RiskPriorityRow,
  ThirdPartyDependency,
} from '@/types/exposure-graph'
import { EMPTY_EXPOSURE_INTELLIGENCE } from '@/types/exposure-graph'

/**
 * Quantum Exposure Graph™ — Enterprise Cryptographic Dependency & Migration
 * Intelligence engine (/api/v1/exposure-graph).
 *
 * Derives the full dependency graph, trust-relationship map, third-party
 * dependency analysis, Migration Dependency Intelligence™ (waves / clusters /
 * blockers), risk prioritisation and the AI Migration Advisor™ panel from
 * real, tenant-scoped evidence: assets, asset_relationships, the CBOM
 * (crypto_inventory), certificates, runtime crypto telemetry, connector
 * accounts and migration jobs. External entities (certificate authorities,
 * cloud providers, third-party services) are only materialised when real
 * evidence links them to the tenant estate — never fabricated.
 *
 * Reuses the Quantum Readiness assessment scores and per-asset risk model.
 * Map counts describe the evidence loaded for this view.
 */

const router = Router()
type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }
type Row = Record<string, unknown>
type Snapshot = Awaited<ReturnType<typeof buildSnapshot>>

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  // Header-only auth for both GET / and the SSE GET /stream. The frontend
  // reads the event-stream via fetch() + ReadableStream with an Authorization
  // header, so the token never enters the URL/query string.
  const token = getToken(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}
router.use(requireAuth)

const str = (v: unknown) => (typeof v === 'string' ? v : v == null ? '' : String(v))
const num = (v: unknown) => { const n = Number(v); return Number.isFinite(n) ? n : 0 }
const clampPct = (n: number) => Math.max(0, Math.min(100, Math.round(n)))

async function safeRows(
  client: NonNullable<ReturnType<typeof createAuthClient>>,
  table: string,
  columns: string,
  userId: string,
  limit: number,
  orderColumn = 'created_at',
  coverage?: string[],
): Promise<Row[]> {
  const rows: Row[] = []
  const pageSize = 500
  for (let offset = 0; offset <= limit; offset += pageSize) {
    let result: { data: unknown; error: unknown }
    try {
      let query = client.from(table).select(columns).eq('user_id', userId)
      if (table === 'assets') query = query.is('metadata->>consolidatedIntoAssetId', null).or('status.is.null,status.not.in.(archived,deleted)')
      query = query.order(orderColumn, { ascending: false, nullsFirst: false })
      if (orderColumn !== 'id') query = query.order('id', { ascending: true })
      result = await query.range(offset, Math.min(limit, offset + pageSize - 1))
    } catch (error) {
      throw new SnapshotReadError(table, error)
    }
    if (result.error) {
      if (table === 'assets' || !isDeterministicReadGap(result.error)) throw new SnapshotReadError(table, result.error)
      coverage?.push(`${table} could not be read with the current schema.`)
      break
    }
    const page = (result.data as Row[] | null) ?? []
    rows.push(...page)
    if (page.length < pageSize) break
  }
  if (rows.length > limit) coverage?.push(`${table} is limited to ${limit.toLocaleString()} recent records in this view.`)
  return rows.slice(0, limit)
}

/* ================================================================== */
/* Raw evidence contract (exported for the offline verification tool)  */
/* ================================================================== */

export interface ExposureRawRows {
  assets: Row[]
  relationships: Row[]
  cryptoInventory: Row[]
  certificates: Row[]
  runtimeEvents: Row[]
  scanResults: Row[]
  cryptoExposures: Row[]
  connectorAccounts: Row[]
  migrationJobs: Row[]
  vulnerabilities?: Row[]
  limitations?: string[]
}

const MAX_ASSET_NODES = 220
const MAX_EXTERNAL_HOSTS = 20
const MAX_CA_NODES = 12
const MAX_EDGES = 600

const ACTIVE_JOB_STATUS = /^(running|in[ _-]progress|executing|migrating|validating)$/i

function currentAsset(row: Row) {
  return Boolean(str(row.id) && !['archived', 'deleted'].includes(str(row.status).toLowerCase()) && !recordOf(row.metadata).consolidatedIntoAssetId)
}

function hasRecordedInternetExposure(asset: Row) {
  const metadata = recordOf(asset.metadata)
  if (metadata.internet_facing === false || metadata.public === false) return false
  if (metadata.internet_facing === true || metadata.public === true) return true
  const exposure = str(metadata.exposure || metadata.exposure_level).trim()
  return /^(internet(?:[-_ ]facing)?|public|external|dmz)$/i.test(exposure || str(asset.environment).trim())
}

function indexAssetRows(rows: Row[]) {
  const index = new Map<string, Row[]>()
  for (const row of rows) {
    const id = str(row.asset_id)
    if (!id) continue
    const list = index.get(id) ?? []
    list.push(row)
    index.set(id, list)
  }
  return index
}

function assetFindings(rows: ExposureRawRows): Map<string, ExposureFinding[]> {
  const inventory = indexAssetRows(rows.cryptoInventory)
  const exposures = indexAssetRows(rows.cryptoExposures)
  const results = indexAssetRows(rows.scanResults)
  const vulnerabilities = indexAssetRows(rows.vulnerabilities ?? [])
  return new Map(rows.assets.filter(currentAsset).map((asset) => {
    const id = str(asset.id)
    const findings = scannerFindingsFromEvidence({ id, name: str(asset.name) }, {
      inventory: inventory.get(id) ?? [],
      exposures: exposures.get(id) ?? [],
      results: results.get(id) ?? [],
      vulnerabilities: vulnerabilities.get(id) ?? [],
    })
    return [id, findings.map((finding): ExposureFinding => ({
      id: finding.id,
      title: finding.algorithm || finding.category,
      category: finding.category,
      algorithm: finding.algorithm,
      severity: finding.threatLevel.toLowerCase(),
      description: finding.description,
      recommendation: finding.recommendation,
      detectedAt: finding.detectedAt && Number.isFinite(Date.parse(finding.detectedAt)) ? finding.detectedAt : null,
      sources: [...new Set(finding.sources)].sort(),
    }))]
  }))
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'unknown'
}

/** Normalize a certificate issuer DN to a display vendor name. */
function issuerName(raw: string): string {
  const cn = /CN=([^,/]+)/i.exec(raw)?.[1]
  const org = /O=([^,/]+)/i.exec(raw)?.[1]
  return (cn || org || raw).trim().slice(0, 80)
}

/** Categorize an external vendor/service by its name for the third-party table. */
function vendorServiceLabel(name: string): string {
  const n = name.toLowerCase()
  if (/stripe|paypal|adyen|braintree|checkout|payment/.test(n)) return 'Payment Gateway'
  if (/cloudflare|akamai|fastly|cdn/.test(n)) return 'CDN Provider'
  if (/okta|auth0|azuread|entra|ping|onelogin|identity|login/.test(n)) return 'Identity Provider'
  if (/aws|amazon|azure|microsoft|gcp|google|oracle.?cloud|alibaba/.test(n)) return 'Cloud Provider'
  if (/digicert|entrust|sectigo|globalsign|let'?s.?encrypt|letsencrypt|verisign|godaddy|amazon.?trust|issuing|\bca\b/.test(n)) return 'External PKI / CA'
  if (/sendgrid|mailgun|postmark|ses|smtp|mail/.test(n)) return 'Email Service'
  if (/route53|cloudns|dns|nsone/.test(n)) return 'DNS Provider'
  if (/mongodb.?atlas|rds|planetscale|supabase|database|redis.?cloud/.test(n)) return 'Managed Database'
  if (/api\./.test(n)) return 'External API'
  return 'SaaS Platform'
}

function posturesFromClasses(classes: Set<string>): NodePosture {
  if (classes.has('vulnerable')) return 'vulnerable'
  if (classes.has('hybrid')) return 'hybrid'
  if (classes.has('pqc')) return 'pqc'
  return 'unknown'
}

/* ================================================================== */
/* Pure assembler                                                      */
/* ================================================================== */

export function assembleExposureIntelligence(snapshot: Snapshot, rows: ExposureRawRows, findings = assetFindings(rows)): ExposureIntelligence {
  const { relationships, cryptoInventory, certificates, runtimeEvents, scanResults, cryptoExposures, connectorAccounts, migrationJobs } = rows
  const assets = rows.assets.filter(currentAsset)

  const hasData = snapshot.hasData || assets.length > 0
  if (!hasData) {
    return {
      ...EMPTY_EXPOSURE_INTELLIGENCE,
      generatedAt: new Date().toISOString(),
      evidence: {
        sources: [],
        note: 'No assessment evidence recorded for this tenant. Run a PQC discovery scan, register assets or connect cloud integrations to populate the dependency graph.',
        limitations: rows.limitations,
      },
    }
  }

  /* ---- Per-asset evidence maps ----------------------------------- */
  const assetById = new Map<string, Row>(assets.map((a) => [str(a.id), a]))
  const assetIdByName = new Map<string, string>()
  for (const a of assets) {
    const name = str(a.name).toLowerCase()
    if (name) assetIdByName.set(name, assetIdByName.has(name) ? '' : str(a.id))
  }
  const resolveAsset = (assetId: string) => assetById.has(assetId) ? assetId : ''

  // Use the same asset risk model as Quantum Readiness and Migration Planner.
  const postureModel = deriveAssetPostureModel({ assets, scanResults, cryptoExposures, cryptoInventory, runtimeEvents })
  const assetRisk = postureModel.assetRisk

  const algosByAsset = new Map<string, Set<string>>()
  const protosByAsset = new Map<string, Set<string>>()
  const latestEvidence = new Map<string, number>()
  for (const row of [...cryptoInventory, ...certificates, ...runtimeEvents, ...scanResults, ...cryptoExposures, ...(rows.vulnerabilities ?? [])]) {
    const id = resolveAsset(str(row.asset_id))
    if (id) latestEvidence.set(id, Math.max(latestEvidence.get(id) ?? 0, Date.parse(str(row.observed_at)) || evidenceTimestamp(row)))
  }
  const addAlgo = (assetId: string, algorithm: string, protocol: string) => {
    if (!assetId) return
    if (algorithm) {
      const set = algosByAsset.get(assetId) || new Set<string>()
      set.add(algorithm)
      algosByAsset.set(assetId, set)
    }
    if (protocol) {
      const set = protosByAsset.get(assetId) || new Set<string>()
      set.add(protocol)
      protosByAsset.set(assetId, set)
    }
  }
  // Map posture is determined from the cryptographic primitives recorded for
  // each asset. Configuration findings are kept in the finding inspector.
  const namesAlgorithm = (row: Row) => {
    const category = observationClass(recordOf(row.metadata).category || row.finding_type || row.name)
    return !['rule', 'dns security', 'certificate transparency', 'certificate revocation', 'nist compliance', 'security headers', 'connectivity'].includes(category)
      && isCryptographicComponent(row, classifyAlgorithmClass)
  }
  for (const i of cryptoInventory) if (namesAlgorithm(i)) addAlgo(resolveAsset(str(i.asset_id)), str(i.algorithm), str(i.protocol))
  for (const event of runtimeEvents) {
    const id = resolveAsset(str(event.asset_id))
    addAlgo(id, str(event.key_exchange_algorithm), str(event.tls_version || event.protocol))
    addAlgo(id, str(event.cipher_suite), str(event.protocol))
    addAlgo(id, str(event.algorithm), '')
  }
  for (const r of scanResults) if (namesAlgorithm(r)) addAlgo(resolveAsset(str(r.asset_id)), str(r.algorithm), '')

  const certsByAsset = new Map<string, NodeCertificate[]>()
  for (const c of certificates) {
    const id = resolveAsset(str(c.asset_id))
    if (!id) continue
    const cert: NodeCertificate = {
      name: str(c.name) || 'certificate',
      algorithm: str(c.algorithm) || 'unknown',
      issuer: issuerName(str(c.issuer)),
      notAfter: str(c.not_after) || null,
      quantumSafe: c.is_quantum_safe === true,
      expiringSoon: c.is_expiring_soon === true,
    }
    const list = certsByAsset.get(id) || []
    list.push(cert)
    certsByAsset.set(id, list)
    addAlgo(id, str(c.algorithm), '')
  }

  const migratingAssetIds = new Set<string>()
  const latestJobs = new Map<string, Row>()
  for (const j of migrationJobs) {
    const id = resolveAsset(str(j.asset_id))
    if (!id || isSimulationRow(j)) continue
    if (ACTIVE_JOB_STATUS.test(str(j.status))) migratingAssetIds.add(id)
    const previous = latestJobs.get(id)
    if (!previous || str(j.updated_at || j.created_at) > str(previous.updated_at || previous.created_at)) latestJobs.set(id, j)
  }

  const postureByAsset = new Map([...algosByAsset].map(([id, algorithms]) =>
    [id, posturesFromClasses(new Set([...algorithms].map(classifyAlgorithmClass)))]))
  const cryptoPostureFor = (assetId: string): NodePosture => postureByAsset.get(assetId) ?? 'unknown'

  /* ---- Asset nodes (bounded detail, exact headline elsewhere) ------ */
  const rankedAssets = [...assets].sort((a, b) => (assetRisk.get(str(b.id)) || 0) - (assetRisk.get(str(a.id)) || 0))
  const nodeAssets = rankedAssets.slice(0, MAX_ASSET_NODES)
  const nodes: ExposureGraphNode[] = []
  const nodeById = new Map<string, ExposureGraphNode>()

  for (const asset of nodeAssets) {
    const id = str(asset.id)
    const name = str(asset.name) || 'asset'
    const category = classifyAssetCategory(str(asset.type), name)
    const tier = tierForCategory(category)
    const node: ExposureGraphNode = {
      id,
      label: name,
      kind: 'asset',
      category,
      type: str(asset.type) || 'asset',
      environment: str(asset.environment) || 'unknown',
      region: str(asset.region) || '—',
      owner: str(asset.service_owner) || 'Unassigned',
      businessCriticality: criticalityLabel(str(asset.criticality)),
      posture: migratingAssetIds.has(id) ? 'migrating' : cryptoPostureFor(id),
      cryptoPosture: cryptoPostureFor(id),
      riskScore: Math.round(assetRisk.get(id) || 0),
      priority: 'Low',
      priorityScore: 0,
      priorityDrivers: [],
      internetFacing: hasRecordedInternetExposure(asset),
      migrationTier: tier.tier,
      tierLabel: tier.label,
      algorithms: [...(algosByAsset.get(id) ?? [])].slice(0, 20),
      algorithmCount: algosByAsset.get(id)?.size ?? 0,
      protocols: [...(protosByAsset.get(id) ?? [])],
      certificates: (certsByAsset.get(id) || []).slice(0, 6),
      dependencies: 0,
      dependents: 0,
      blastRadius: 0,
      findingsCount: findings.get(id)?.length ?? 0,
      findingsRevision: payloadFingerprint(findings.get(id) ?? []),
      assetStatus: str(asset.status) || null,
      migrationStatus: str(latestJobs.get(id)?.status) || null,
      riskMeasured: assetRisk.has(id),
      lastEvidenceAt: latestEvidence.get(id) ? new Date(latestEvidence.get(id)!).toISOString() : null,
      certificateCount: certsByAsset.get(id)?.length ?? 0,
    }
    nodes.push(node)
    nodeById.set(id, node)
  }

  /* ---- Edges: real asset relationships ----------------------------- */
  const edges: ExposureGraphEdge[] = []
  const edgeKeys = new Set<string>()
  let truncatedEdges = false
  const pushEdge = (source: string, target: string, type: string, trustClass: EdgeTrustClass, algorithm: string | null, provenance: NonNullable<ExposureGraphEdge['provenance']>, basis: string) => {
    if (!source || !target || source === target) return
    if (!nodeById.has(source) || !nodeById.has(target)) return
    const key = JSON.stringify([source, target, type, trustClass, algorithm, provenance])
    if (edgeKeys.has(key)) return
    if (edges.length >= MAX_EDGES) { truncatedEdges = true; return }
    edgeKeys.add(key)
    const algoClass = algorithm ? classifyAlgorithmClass(algorithm) : 'unknown'
    const posture: NodePosture = algorithm
      ? posturesFromClasses(new Set([algoClass]))
      : 'unknown'
    edges.push({ id: `link:${payloadFingerprint(key)}`, source, target, type, trustClass, algorithm, posture, critical: false, provenance, basis })
  }

  const relSource = (r: Row) => str(r.source_asset_id || r.parent_asset_id || r.from_asset_id)
  const relTarget = (r: Row) => str(r.target_asset_id || r.child_asset_id || r.to_asset_id)
  for (const r of relationships) {
    const type = str(r.relationship_type) || 'depends-on'
    pushEdge(relSource(r), relTarget(r), type, classifyTrustClass(type), null, 'explicit', 'Recorded asset relationship.')
  }

  /* ---- External certificate authorities (real issuers) ------------- */
  let ambiguousLinks = 0
  const issuerGroups = new Map<string, { name: string; certs: string[] }>()
  for (const c of certificates) {
    const rawIssuer = str(c.issuer)
    if (!rawIssuer.trim()) continue
    const name = issuerName(rawIssuer)
    const nameLower = name.toLowerCase()
    const ownerAssetId = resolveAsset(str(c.asset_id))
    if (!ownerAssetId || !nodeById.has(ownerAssetId)) continue
    const internal = assetIdByName.get(nameLower)
    if (internal && internal !== ownerAssetId) {
      pushEdge(ownerAssetId, internal, 'issued-by', 'certificate-chain', null, 'inferred', 'The certificate issuer name matches an inventory asset.')
      continue
    }
    if (assetIdByName.has(nameLower)) {
      if (!internal) ambiguousLinks += 1
      continue
    }
    const group = issuerGroups.get(nameLower) || { name, certs: [] }
    group.certs.push(ownerAssetId)
    issuerGroups.set(nameLower, group)
  }
  const topIssuers = [...issuerGroups.values()].sort((a, b) => b.certs.length - a.certs.length).slice(0, MAX_CA_NODES)
  for (const issuer of topIssuers) {
    const id = `ca:${encodeURIComponent(issuer.name.toLowerCase())}`
    const node: ExposureGraphNode = {
      id,
      label: issuer.name,
      kind: 'external',
      category: 'certificate-authority',
      type: 'external certificate authority',
      environment: 'external',
      region: '—',
      owner: 'Third-Party',
      businessCriticality: 'Unknown',
      posture: 'unknown',
      riskScore: 0,
      riskMeasured: false,
      priority: 'Low',
      priorityScore: 0,
      priorityDrivers: [],
      internetFacing: false,
      migrationTier: 1,
      tierLabel: 'Certificate Authorities',
      algorithms: [],
      protocols: [],
      certificates: [],
      dependencies: 0,
      dependents: 0,
      blastRadius: 0,
      findingsCount: 0,
      vendor: issuer.name,
    }
    nodes.push(node)
    nodeById.set(id, node)
    for (const ownerAssetId of issuer.certs) pushEdge(ownerAssetId, id, 'issued-by', 'certificate-chain', null, 'observed', 'Issuer named on the asset certificate.')
  }

  /* ---- External services observed in runtime telemetry ------------- */
  const externalHosts = new Map<string, {
    host: string; count: number; algorithms: Set<string>; protocols: Set<string>;
    links: Map<string, { ownerId: string; algorithm: string; observed: boolean }>; maxRisk: number | null;
  }>()
  for (const e of runtimeEvents) {
    const host = str(e.host).toLowerCase().trim()
    if (!host || !host.includes('.')) continue
    const ownerId = resolveAsset(str(e.asset_id))
    if (!ownerId || !nodeById.has(ownerId)) continue
    const observation = recordOf(e.metadata).observationKind
    const observed = observation === 'runtime-observation' && /^(tls|ssh)[-_ ]handshake$/i.test(str(e.event_type))
    const algorithm = str(e.key_exchange_algorithm || e.cipher_suite || e.algorithm)
    const internalTarget = assetIdByName.get(host)
    if (internalTarget && internalTarget !== ownerId) {
      pushEdge(ownerId, internalTarget, 'host association', 'communication', algorithm || null, 'inferred', 'The telemetry host name matches this inventory asset.')
      continue
    }
    if (assetIdByName.has(host)) {
      if (!internalTarget) ambiguousLinks += 1
      continue
    }
    const entry = externalHosts.get(host) ?? { host, count: 0, algorithms: new Set<string>(), protocols: new Set<string>(), links: new Map(), maxRisk: null }
    entry.count += 1
    if (algorithm) entry.algorithms.add(algorithm)
    const protocol = str(e.tls_version || e.protocol)
    if (protocol) entry.protocols.add(protocol)
    entry.links.set(JSON.stringify([ownerId, algorithm, observed]), { ownerId, algorithm, observed })
    if (typeof e.risk_score === 'number' && Number.isFinite(e.risk_score)) entry.maxRisk = Math.max(entry.maxRisk ?? 0, e.risk_score)
    externalHosts.set(host, entry)
  }
  const topHosts = [...externalHosts.values()].sort((a, b) => b.count - a.count).slice(0, MAX_EXTERNAL_HOSTS)
  for (const ext of topHosts) {
    const id = `ext:${encodeURIComponent(ext.host)}`
    const classes = new Set<string>([...ext.algorithms].map((a) => classifyAlgorithmClass(a)))
    const node: ExposureGraphNode = {
      id,
      label: ext.host,
      kind: 'external',
      category: 'vendor',
      type: vendorServiceLabel(ext.host).toLowerCase(),
      environment: 'external',
      region: '—',
      owner: 'Third-Party',
      businessCriticality: 'Unknown',
      posture: posturesFromClasses(classes),
      riskScore: clampPct(ext.maxRisk ?? 0),
      riskMeasured: ext.maxRisk !== null,
      priority: 'Low',
      priorityScore: 0,
      priorityDrivers: [],
      internetFacing: false,
      migrationTier: 12,
      tierLabel: 'External & Vendor Services',
      algorithms: [...ext.algorithms].slice(0, 6),
      protocols: [...ext.protocols],
      certificates: [],
      dependencies: 0,
      dependents: 0,
      blastRadius: 0,
      findingsCount: 0,
      vendor: ext.host,
    }
    nodes.push(node)
    nodeById.set(id, node)
    for (const { ownerId, algorithm, observed } of ext.links.values()) {
      pushEdge(ownerId, id, 'host association', 'communication', algorithm || null, observed ? 'observed' : 'inferred',
        observed ? 'Runtime handshake telemetry names this host.' : 'A telemetry record names this host. Its network relationship is unverified.')
    }
  }

  /* ---- Cloud provider connectors (graphed only with real links) ---- */
  const providerPatterns: Array<{ pattern: RegExp; label: string }> = [
    { pattern: /aws|amazon/i, label: 'AWS' },
    { pattern: /azure|microsoft/i, label: 'Microsoft Azure' },
    { pattern: /gcp|google/i, label: 'Google Cloud' },
    { pattern: /oracle/i, label: 'Oracle Cloud' },
    { pattern: /alibaba/i, label: 'Alibaba Cloud' },
  ]
  const connectorProviders = new Map<string, { provider: string; status: string; linkedAssets: string[] }>()
  for (const account of connectorAccounts) {
    const provider = str(account.provider)
    if (!provider) continue
    const match = providerPatterns.find((p) => p.pattern.test(provider))
    const label = match?.label || provider
    const entry = connectorProviders.get(label.toLowerCase()) || { provider: label, status: str(account.status) || 'unknown', linkedAssets: [] }
    connectorProviders.set(label.toLowerCase(), entry)
  }
  for (const entry of connectorProviders.values()) {
    const pattern = providerPatterns.find((p) => p.label === entry.provider)?.pattern
    for (const node of nodes) {
      if (node.kind !== 'asset') continue
      const asset = assetById.get(node.id)
      const metadata = recordOf(asset?.metadata)
      const provider = str(metadata.provider || metadata.cloudProvider || metadata.cloud_provider).toLowerCase()
      if (provider && (pattern ? pattern.test(provider) : provider === entry.provider.toLowerCase())) entry.linkedAssets.push(node.id)
    }
    if (!entry.linkedAssets.length) continue
    const id = `cloud:${slug(entry.provider)}`
    const node: ExposureGraphNode = {
      id,
      label: entry.provider,
      kind: 'external',
      category: 'cloud-resource',
      type: 'cloud provider',
      environment: 'external',
      region: '—',
      owner: 'Third-Party',
      businessCriticality: 'Unknown',
      posture: 'unknown',
      riskScore: 0,
      riskMeasured: false,
      priority: 'Low',
      priorityScore: 0,
      priorityDrivers: [],
      internetFacing: false,
      migrationTier: 12,
      tierLabel: 'External & Vendor Services',
      algorithms: [],
      protocols: [],
      certificates: [],
      dependencies: 0,
      dependents: 0,
      blastRadius: 0,
      findingsCount: 0,
      vendor: entry.provider,
    }
    nodes.push(node)
    nodeById.set(id, node)
    for (const assetId of entry.linkedAssets) pushEdge(assetId, id, 'hosted-on', 'cloud', null, 'inferred', 'Recorded asset provider matches a workspace connector. Account ownership has not been verified.')
  }

  /* ---- Degrees, blast radius, priority, edge criticality ----------- */
  const evidencedEdges = edges.filter((edge) => edge.provenance !== 'inferred')
  const assetPairs = new Set<string>()
  for (const edge of evidencedEdges) {
    const pair = JSON.stringify([edge.source, edge.target])
    if (assetPairs.has(pair)) continue
    assetPairs.add(pair)
    const source = nodeById.get(edge.source)
    const target = nodeById.get(edge.target)
    if (source) source.dependencies += 1
    if (target) target.dependents += 1
  }
  const adjacency = buildAdjacency(evidencedEdges)
  for (const node of nodes) {
    node.blastRadius = computeBlastRadius(nodes, evidencedEdges, node.id, 6, adjacency).totalAffected
    const expiringCerts = node.certificates.filter((c) => c.expiringSoon).length
    const vulnerableAlgos = node.algorithms.filter((a) => classifyAlgorithmClass(a) === 'vulnerable').length
    const { score, priority, drivers } = computePriority({
      posture: node.posture,
      riskScore: node.riskScore,
      internetFacing: node.internetFacing,
      businessCriticality: node.businessCriticality,
      dependents: node.dependents,
      dependencies: node.dependencies,
      expiringCertificates: expiringCerts,
      vulnerableAlgorithms: vulnerableAlgos,
      findingsCount: node.findingsCount,
    })
    node.priorityScore = score
    node.priority = priority
    node.priorityDrivers = drivers
  }
  for (const edge of edges) {
    const source = nodeById.get(edge.source)
    const target = nodeById.get(edge.target)
    const vulnerableLink = edge.posture === 'vulnerable' || (source?.cryptoPosture ?? source?.posture) === 'vulnerable' || (target?.cryptoPosture ?? target?.posture) === 'vulnerable'
    const criticalPair = (source?.businessCriticality === 'Critical' || target?.businessCriticality === 'Critical')
    edge.critical = edge.provenance !== 'inferred' && Boolean(vulnerableLink && (criticalPair || TRUST_CHAIN_CLASSES.has(edge.trustClass)))
  }

  /* ---- Summary metrics --------------------------------------------- */
  let vulnerableAssets = 0
  let hybridAssets = 0
  let pqcAssets = 0
  let migratingAssets = 0
  let unknownAssets = 0
  let internetFacingAssets = 0
  let legacyCryptoAssets = 0
  for (const asset of assets) {
    const id = str(asset.id)
    const posture = cryptoPostureFor(id)
    if (posture === 'vulnerable') vulnerableAssets += 1
    else if (posture === 'hybrid') hybridAssets += 1
    else if (posture === 'pqc') pqcAssets += 1
    else unknownAssets += 1
    if (migratingAssetIds.has(id)) migratingAssets += 1
    if (hasRecordedInternetExposure(asset)) internetFacingAssets += 1
    if ([...(algosByAsset.get(id) || [])].some((a) => classifyAlgorithmClass(a) === 'vulnerable')) legacyCryptoAssets += 1
  }
  const totalAssets = assets.length
  const assetNodes = nodes.filter((n) => n.kind === 'asset')
  const externalNodes = nodes.filter((n) => n.kind === 'external')
  const unlinkedConnectors = [...connectorProviders.values()].filter((c) => !c.linkedAssets.length)
  const migrationReadinessScore = assets.length
    ? clampPct(((pqcAssets + hybridAssets * 0.5) / assets.length) * 100)
    : 0

  const summary = {
    totalAssets,
    quantumVulnerable: vulnerableAssets,
    hybridAssets,
    pqcReadyAssets: pqcAssets,
    migrationInProgress: migratingAssets,
    unknownPosture: unknownAssets,
    thirdPartyDependencies: externalNodes.filter((node) => edges.some((edge) => edge.source === node.id || edge.target === node.id)).length,
    trustRelationships: evidencedEdges.length,
    inferredRelationships: edges.length - evidencedEdges.length,
    criticalTrustRelationships: edges.filter((e) => e.critical).length,
    internetFacingAssets,
    highRiskAssets: assetNodes.filter((n) => n.priority === 'Critical' || n.priority === 'High').length,
    legacyCryptoAssets,
    certificateChains: edges.filter((edge) => edge.trustClass === 'certificate-chain').length,
    pkiObjects: certificates.filter((cert) => assetById.has(str(cert.asset_id))).length,
    maxBlastRadius: nodes.reduce((max, n) => Math.max(max, n.blastRadius), 0),
    migrationReadinessScore,
    quantumReadinessScore: snapshot.scores.quantumReadiness,
    quantumRiskScore: snapshot.scores.quantumRisk,
    assessmentMeasured: readinessPostureMeasured({ cryptoComponents: snapshot.inventory.cryptoComponents, findings: snapshot.riskDistribution }) || snapshot.telemetry.runtimeEvents > 0,
    mappedAssets: assetNodes.length,
    assessedAssets: assets.filter((asset) => latestEvidence.has(str(asset.id))).length,
  }

  /* ---- Third-party dependency analysis ----------------------------- */
  const thirdParty: ThirdPartyDependency[] = []
  for (const node of externalNodes) {
    const connected = edges.filter((e) => e.source === node.id || e.target === node.id)
    const connectedAssets = [...new Set(connected.map((e) => e.source === node.id ? e.target : e.source))]
      .map((id) => nodeById.get(id)).filter((asset) => asset?.kind === 'asset')
    const protocols = new Set<string>()
    for (const value of [...node.protocols, ...node.algorithms, ...connected.map((edge) => edge.algorithm ?? '')]) {
      const version = /tlsv?\s?1\.[0-3]/i.exec(value)?.[0]
      if (version) protocols.add(version.toUpperCase().replace(/^TLSV?\s*/, 'TLS '))
    }
    thirdParty.push({
      id: node.id,
      vendor: node.vendor || node.label,
      category: node.category === 'certificate-authority' ? 'External PKI / CA' : node.category === 'cloud-resource' ? 'Cloud Provider' : vendorServiceLabel(node.label),
      connectedAssets: connectedAssets.length,
      connectedAssetNames: connectedAssets.slice(0, 6).map((asset) => asset!.label),
      algorithms: node.algorithms,
      tlsVersion: [...protocols].sort().pop() || null,
      certificate: node.category === 'certificate-authority' ? `${issuerGroups.get((node.vendor || '').toLowerCase())?.certs.length || 0} issued certificate(s)` : null,
      readiness: node.posture,
      riskLevel: node.riskMeasured ? priorityFromScore(node.riskScore) : 'Unknown',
      migrationCompatibility:
        node.posture === 'pqc' ? 'PQC observed. Verify interoperability before cutover.'
        : node.posture === 'hybrid' ? 'Hybrid observed. Verify support on each dependent asset.'
        : node.posture === 'vulnerable' ? 'Vulnerable crypto observed. Verify the vendor’s upgrade options.'
        : 'Validate vendor cryptography before cutover.',
      businessCriticality: node.businessCriticality,
    })
  }
  for (const c of unlinkedConnectors) {
    thirdParty.push({
      id: `cloud:${slug(c.provider)}`,
      vendor: c.provider,
      category: 'Cloud Provider',
      connectedAssets: 0,
      connectedAssetNames: [],
      algorithms: [],
      tlsVersion: null,
      certificate: null,
      readiness: 'unknown',
      riskLevel: 'Unknown',
      migrationCompatibility: 'Connected account — no linked assets discovered yet',
      businessCriticality: 'Unknown',
    })
  }
  thirdParty.sort((a, b) => b.connectedAssets - a.connectedAssets)

  /* ---- Migration Dependency Intelligence™ --------------------------- */
  const pendingNodes = assetNodes.filter((n) => n.posture === 'vulnerable' || n.posture === 'hybrid' || n.posture === 'unknown')
  const waves: MigrationWaveEntry[] = []
  for (const tier of MIGRATION_TIERS) {
    const members = pendingNodes
      .filter((n) => n.migrationTier === tier.tier)
      .sort((a, b) => b.dependents - a.dependents || b.riskScore - a.riskScore)
    const externalMembers = tier.tier === 12
      ? externalNodes.filter((n) => n.posture === 'vulnerable').sort((a, b) => b.dependents - a.dependents)
      : []
    const all = [...members, ...externalMembers]
    if (!all.length) continue
    waves.push({
      wave: waves.length + 1,
      tierLabel: tier.label,
      rationale: tier.rationale,
      nodes: all.slice(0, 12).map((n) => ({ id: n.id, label: n.label, posture: n.posture, riskScore: n.riskScore, dependents: n.dependents })),
    })
  }

  // Must-migrate-together: connected components over trust-chain edges whose
  // endpoints are both still pending (breaking one side strands the other).
  const parent = new Map<string, string>()
  const find = (x: string): string => {
    let root = x
    while (parent.get(root) && parent.get(root) !== root) root = parent.get(root)!
    parent.set(x, root)
    return root
  }
  const union = (a: string, b: string) => {
    if (!parent.has(a)) parent.set(a, a)
    if (!parent.has(b)) parent.set(b, b)
    const ra = find(a)
    const rb = find(b)
    if (ra !== rb) parent.set(ra, rb)
  }
  const pendingIds = new Set(pendingNodes.map((n) => n.id))
  const clusterEdgeClass = new Map<string, Map<EdgeTrustClass, number>>()
  for (const edge of evidencedEdges) {
    if (!TRUST_CHAIN_CLASSES.has(edge.trustClass)) continue
    if (!pendingIds.has(edge.source) || !pendingIds.has(edge.target)) continue
    union(edge.source, edge.target)
  }
  const componentMembers = new Map<string, string[]>()
  for (const id of parent.keys()) {
    const root = find(id)
    const list = componentMembers.get(root) || []
    list.push(id)
    componentMembers.set(root, list)
  }
  for (const edge of evidencedEdges) {
    if (!TRUST_CHAIN_CLASSES.has(edge.trustClass) || !pendingIds.has(edge.source) || !pendingIds.has(edge.target)) continue
    const root = find(edge.source)
    const classCounts = clusterEdgeClass.get(root) || new Map<EdgeTrustClass, number>()
    classCounts.set(edge.trustClass, (classCounts.get(edge.trustClass) || 0) + 1)
    clusterEdgeClass.set(root, classCounts)
  }
  const clusters: MigrationCluster[] = [...componentMembers.entries()]
    .filter(([, members]) => members.length >= 2)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 8)
    .map(([root, members], index) => {
      const classCounts = clusterEdgeClass.get(root)
      const dominant = classCounts ? [...classCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] : undefined
      const reasonByClass: Partial<Record<EdgeTrustClass, string>> = {
        mtls: 'Mutual TLS peers — both sides must present migrated certificates in the same window.',
        'certificate-chain': 'Shared certificate trust chain — chain members must re-issue together or trust breaks.',
        identity: 'Federated identity trust — token issuers and consumers must rotate keys in lock-step.',
        kms: 'Shared key-custody dependency — key consumers must adopt the migrated KMS algorithms together.',
      }
      return {
        id: `cluster-${index + 1}`,
        reason: (dominant && reasonByClass[dominant]) || 'Tightly-coupled cryptographic trust — migrate within one coordinated change window.',
        nodes: members
          .map((id) => nodeById.get(id))
          .filter((n): n is ExposureGraphNode => Boolean(n))
          .slice(0, 8)
          .map((n) => ({ id: n.id, label: n.label, posture: n.posture })),
      }
    })

  const blockers: MigrationBlocker[] = []
  for (const node of nodes) {
    const degree = node.dependents + node.dependencies
    if (node.kind === 'external' && node.posture === 'vulnerable' && degree >= 1) {
      blockers.push({
        id: node.id,
        label: node.label,
        reason: `Vulnerable cryptography was recorded on this service. Verify compatibility with its ${degree} connected asset(s) before cutover.`,
        blockedDependents: degree,
      })
    } else if (node.kind === 'asset' && (node.category === 'certificate-authority' || node.category === 'pki') && node.posture === 'vulnerable' && node.dependents + node.dependencies >= 1) {
      blockers.push({
        id: node.id,
        label: node.label,
        reason: `This trust anchor has classical crypto evidence. Verify certificate updates for its ${degree} connected asset(s).`,
        blockedDependents: degree,
      })
    } else if (node.kind === 'asset' && (node.category === 'kms' || node.category === 'hsm') && node.posture === 'vulnerable' && degree >= 1) {
      blockers.push({
        id: node.id,
        label: node.label,
        reason: `Classical cryptography was recorded on this key service. Verify PQC support with its ${degree} connected asset(s).`,
        blockedDependents: degree,
      })
    }
  }
  blockers.sort((a, b) => b.blockedDependents - a.blockedDependents)

  /* ---- AI Migration Advisor™ ---------------------------------------- */
  const recommendations: AdvisorRecommendation[] = []
  const pushRec = (rec: AdvisorRecommendation) => { if (recommendations.length < 8) recommendations.push(rec) }
  const vulnerableCAs = nodes.filter((n) => (n.category === 'certificate-authority' || n.category === 'pki') && n.posture === 'vulnerable')
  for (const ca of vulnerableCAs.slice(0, 2)) {
    const dependents = ca.dependents + ca.dependencies
    pushRec({
      id: `rec-ca-${slug(ca.label)}`,
      title: `Migrate ${ca.label} before dependent TLS endpoints`,
      detail: `${dependents} trust relationship(s) chain onto this authority. Re-issuing after the CA migrates avoids double certificate rotation.`,
      severity: 'critical',
      category: 'Sequencing',
    })
  }
  const vulnerableIdp = nodes.find((n) => (n.category === 'identity-provider' || n.category === 'directory') && n.posture === 'vulnerable')
  if (vulnerableIdp) {
    pushRec({
      id: 'rec-idp',
      title: `Upgrade ${vulnerableIdp.label} before rotating service certificates`,
      detail: 'Identity trust must be quantum-safe before dependent services re-issue credentials, or tokens signed by legacy keys are re-trusted.',
      severity: 'critical',
      category: 'Sequencing',
    })
  }
  for (const blocker of blockers.filter((b) => b.id.startsWith('ext:') || b.id.startsWith('cloud:')).slice(0, 2)) {
    pushRec({
      id: `rec-vendor-${slug(blocker.label)}`,
      title: `Delay hard cutover of ${blocker.label}-dependent services`,
      detail: `${blocker.reason} Track vendor PQC readiness and enforce hybrid TLS on the connecting assets in the interim.`,
      severity: 'high',
      category: 'Third-Party',
    })
  }
  const internetVulnApis = assetNodes.filter((n) => n.internetFacing && n.cryptoPosture === 'vulnerable' && (n.category === 'api' || n.category === 'load-balancer' || n.category === 'tls-endpoint' || n.category === 'web-application'))
  if (internetVulnApis.length) {
    pushRec({
      id: 'rec-hybrid-tls',
      title: `Deploy Hybrid TLS (X25519 + ML-KEM-768) on ${internetVulnApis.length} internet-facing endpoint(s)`,
      detail: 'Hybrid key establishment protects against harvest-now-decrypt-later immediately while preserving compatibility with legacy clients.',
      severity: 'high',
      category: 'Protection',
    })
  }
  const pinnedCertAssets = assetNodes.filter((n) => n.certificates.length > 0 && (n.category === 'web-application' || n.category === 'api') && n.posture === 'vulnerable')
  if (pinnedCertAssets.length) {
    pushRec({
      id: 'rec-pinning',
      title: 'Audit certificate pinning before deploying ML-DSA certificates',
      detail: `${pinnedCertAssets.length} application-tier asset(s) carry classical certificates. Pinned clients (mobile apps, SDKs) must ship updated pins before the chains rotate.`,
      severity: 'medium',
      category: 'Compatibility',
    })
  }
  if (clusters.length) {
    const first = clusters[0]
    pushRec({
      id: 'rec-cluster',
      title: `Migrate ${first.nodes.slice(0, 3).map((n) => n.label).join(', ')}${first.nodes.length > 3 ? '…' : ''} together`,
      detail: first.reason,
      severity: 'high',
      category: 'Coordination',
    })
  }
  const highRiskCritical = assetNodes.filter((n) => n.priority === 'Critical' && n.businessCriticality === 'Critical')
  if (highRiskCritical.length) {
    pushRec({
      id: 'rec-window',
      title: `Schedule ${highRiskCritical.length} business-critical migration(s) in maintenance windows`,
      detail: 'Critical-priority assets with critical business impact should migrate under change control with rollback snapshots pre-captured.',
      severity: 'medium',
      category: 'Change Management',
    })
  }
  const unknownShare = assets.length ? unknownAssets / assets.length : 0
  if (unknownShare > 0.3) {
    pushRec({
      id: 'rec-visibility',
      title: `Close the visibility gap — ${unknownAssets} asset(s) have unverified crypto posture`,
      detail: 'Run targeted discovery scans so migration sequencing is computed from evidence rather than assumptions.',
      severity: 'medium',
      category: 'Discovery',
    })
  }

  const compatibleEdges = evidencedEdges.filter((e) => {
    const s = nodeById.get(e.source)!
    const t = nodeById.get(e.target)!
    const ok = (p: NodePosture) => p === 'pqc' || p === 'hybrid'
    return ok(s.cryptoPosture ?? s.posture) && ok(t.cryptoPosture ?? t.posture)
  }).length
  const criticalAssets = assetNodes.filter((n) => n.businessCriticality === 'Critical' || n.businessCriticality === 'High')
  const criticalVulnShare = criticalAssets.length
    ? criticalAssets.filter((n) => n.posture === 'vulnerable').length / criticalAssets.length
    : vulnerableAssets / Math.max(1, assets.length)

  const advisorEstimates = {
    migrationComplexity: snapshot.scores.migrationComplexity,
    complexityLevel: snapshot.scores.migrationComplexityLevel,
    businessImpact: priorityFromScore(clampPct(criticalVulnShare * 100)),
    compatibilityScorePct: evidencedEdges.length ? clampPct((compatibleEdges / evidencedEdges.length) * 100) : 0,
    estimatedDurationWeeks: snapshot.estimates.migrationTimelineWeeks,
    parallelWorkstreams: snapshot.estimates.parallelWorkstreams,
  }

  /* ---- Risk prioritisation table ------------------------------------ */
  const riskPrioritization: RiskPriorityRow[] = [...assetNodes]
    .sort((a, b) => b.priorityScore - a.priorityScore)
    .slice(0, 20)
    .map((n) => ({
      id: n.id,
      label: n.label,
      category: n.category,
      environment: n.environment,
      posture: n.posture,
      priority: n.priority,
      priorityScore: n.priorityScore,
      drivers: n.priorityDrivers,
      riskScore: n.riskScore,
      internetFacing: n.internetFacing,
      dependents: n.dependents,
      certificateRisk: n.certificates.some((c) => c.expiringSoon || (!c.quantumSafe && classifyAlgorithmClass(c.algorithm) === 'vulnerable')),
    }))

  return {
    generatedAt: new Date().toISOString(),
    lastAssessmentAt: snapshot.lastAssessmentAt,
    hasData: true,
    summary,
    graph: { nodes, edges },
    thirdParty,
    migrationOrder: { waves, clusters, blockers: blockers.slice(0, 8) },
    advisor: { recommendations, estimates: advisorEstimates },
    riskPrioritization,
    evidence: {
      sources: [
        [assets, 'Asset Inventory'], [relationships, 'Asset Relationships'], [cryptoInventory, 'CBOM / Crypto Inventory'],
        [certificates, 'Certificate Inventory'], [runtimeEvents, 'Runtime Crypto Telemetry'], [scanResults, 'PQC Scan Findings'],
        [cryptoExposures, 'Crypto Exposure'], [rows.vulnerabilities ?? [], 'Vulnerabilities'],
        [connectorAccounts, 'Cloud Connectors'], [migrationJobs, 'Migration Jobs'],
      ].flatMap(([records, label]) => Array.isArray(records) && records.length ? [String(label)] : []),
      note: 'Asset counts use the loaded inventory. Migration progress can overlap any observed crypto posture. Blast radius uses stored and observed links.',
      limitations: [
        ...(rows.limitations ?? []),
        ...(nodeAssets.length < assets.length ? [`Map shows ${nodeAssets.length} of ${assets.length} loaded assets, prioritized by recorded risk.`] : []),
        ...(truncatedEdges ? [`Map links are limited to ${MAX_EDGES}.`] : []),
        ...(ambiguousLinks ? [`${ambiguousLinks} host or issuer observations match more than one workspace asset and were left unmapped.`] : []),
        ...(issuerGroups.size > MAX_CA_NODES || externalHosts.size > MAX_EXTERNAL_HOSTS ? ['External nodes show the most frequently observed issuers and destinations.'] : []),
      ].sort(),
    },
  }
}

/* ================================================================== */
/* Evidence loader + per-tenant single-flight cache                    */
/* ================================================================== */

async function computeExposureIntelligence(token: string, userId: string) {
  const client = createAuthClient(token)
  if (!client) throw new Error('The workspace data connection is unavailable.')
  const limitations: string[] = []
  const read = (table: string, columns: string, limit: number, order?: string) => safeRows(client, table, columns, userId, limit, order, limitations)
  const [snapshot, assets, relationships, cryptoInventory, certificates, runtimeEvents, scanResults, cryptoExposures, connectorAccounts, migrationJobs, vulnerabilities] = await Promise.all([
    buildSnapshot(token, userId),
    read('assets', 'id, name, type, environment, region, service_owner, criticality, status, metadata, created_at', 1500),
    read('asset_relationships', '*', 3000),
    read('crypto_inventory', 'id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, discovered_at, created_at, metadata', 2500),
    read('certificates', 'id, asset_id, name, algorithm, key_size, issuer, not_after, is_quantum_safe, is_expiring_soon, status, created_at', 1500),
    read('runtime_crypto_events', 'id, asset_id, event_type, algorithm, key_exchange_algorithm, cipher_suite, tls_version, protocol, severity, risk_score, host, is_pqc, is_legacy, hndl_risk, metadata, observed_at, created_at', 3000, 'observed_at'),
    read('pqc_scan_results', 'id, asset_id, algorithm, finding_type, threat_level, description, remediation, metadata, created_at', 2000),
    read('crypto_exposures', 'id, asset_id, exposure_type, severity, detected_value, description, metadata, created_at', 2000),
    read('connector_accounts', 'id, provider, status', 400, 'id'),
    read('migration_jobs', `id, status, asset_id, name, job_type, created_at, updated_at, ${SIMULATION_MARKER_SELECT}`, 1000, 'updated_at'),
    read('vulnerabilities', 'id, asset_id, title, severity, status, source, description, metadata, created_at, updated_at', 2000, 'updated_at'),
  ])
  const rows: ExposureRawRows = { assets, relationships, cryptoInventory, certificates, runtimeEvents, scanResults, cryptoExposures, connectorAccounts, migrationJobs, vulnerabilities, limitations }
  const findings = assetFindings(rows)
  const data = assembleExposureIntelligence(snapshot, rows, findings)
  return { data, findings }
}

// Per-tenant single-flight cache shared by the JSON endpoint, the SSE loop and
// every open tab. The previous hand-rolled Map stamped `at` at build START, so
// a build slower than its TTL was duplicated by the next tick — the exact
// amplifier lib/single-flight-cache.ts exists to remove. Failures are never cached.
const intelCache = createSingleFlightCache<Awaited<ReturnType<typeof computeExposureIntelligence>>>(10_000)

function exposureModel(token: string, userId: string) {
  return intelCache.get(userId, () => computeExposureIntelligence(token, userId))
}

export async function buildExposureIntelligence(token: string, userId: string): Promise<ExposureIntelligence> {
  return (await exposureModel(token, userId)).data
}

/* ================================================================== */
/* Routes                                                              */
/* ================================================================== */

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const data = await buildExposureIntelligence(token!, user!.id)
    res.setHeader('Cache-Control', 'private, no-store').json({ data: { ...data, fingerprint: payloadFingerprint(data) } })
  } catch (error) {
    console.error('Exposure graph intelligence error:', error)
    res.status(500).json({ error: { code: 'EXPOSURE_GRAPH_ERROR', message: 'Unable to refresh exposure graph evidence.' } })
  }
})

router.get('/stream', (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  streamLiveSnapshot(req, res, {
    event: 'exposure-intelligence',
    build: async () => {
      try { return await buildExposureIntelligence(token!, user!.id) }
      catch { throw new Error('Unable to refresh exposure graph evidence.') }
    },
    intervalMs: 15_000,
  })
})

router.get('/assets/:id/findings', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const { findings } = await exposureModel(token!, user!.id)
    const assetId = str(req.params.id)
    const rows = findings.get(assetId)
    if (!rows) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Asset is unavailable in this workspace snapshot.' } })
    const limit = Math.min(100, Math.max(1, Math.floor(num(req.query.limit) || 15)))
    const lastPage = Math.max(0, Math.floor((rows.length - 1) / limit) * limit)
    const offset = Math.min(lastPage, Math.max(0, Math.floor(num(req.query.offset))))
    const data: ExposureFindingPage = { assetId, revision: payloadFingerprint(rows), total: rows.length, offset, limit, findings: rows.slice(offset, offset + limit) }
    res.setHeader('Cache-Control', 'private, no-store').json({ data })
  } catch (error) {
    console.error('Exposure asset findings error:', error)
    res.status(500).json({ error: { code: 'EXPOSURE_FINDINGS_ERROR', message: 'Unable to load findings for this asset.' } })
  }
})

export default router
