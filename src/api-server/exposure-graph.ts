import { Router, Request, Response, NextFunction } from 'express'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { createSingleFlightCache } from '@/lib/single-flight-cache'
import { deriveAssetPostureModel } from '@/lib/migration/asset-intelligence'
import { buildSnapshot, isInternetFacing } from './quantum-readiness'
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
 * Reuses the shared Quantum Readiness snapshot (15s single-flight cache) for
 * scores/inventory floors so the graph can never contradict the other QR
 * pages, and mirrors its per-asset risk model for node risk scores.
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
): Promise<Row[]> {
  try {
    const { data, error } = await client.from(table).select(columns).eq('user_id', userId).order(orderColumn, { ascending: false }).limit(limit)
    if (error) return []
    return (data as unknown as Row[]) || []
  } catch {
    return []
  }
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
}

const MAX_ASSET_NODES = 220
const MAX_EXTERNAL_HOSTS = 20
const MAX_CA_NODES = 12
const MAX_EDGES = 600

const ACTIVE_JOB_STATUS = /running|in.?progress|executing|active|migrating/i

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
  if (classes.has('pqc') || classes.has('safe')) return 'pqc'
  return 'unknown'
}

/* ================================================================== */
/* Pure assembler                                                      */
/* ================================================================== */

export function assembleExposureIntelligence(snapshot: Snapshot, rows: ExposureRawRows): ExposureIntelligence {
  const { assets, relationships, cryptoInventory, certificates, runtimeEvents, scanResults, cryptoExposures, connectorAccounts, migrationJobs } = rows

  const hasData = snapshot.hasData || assets.length > 0
  if (!hasData) {
    return {
      ...EMPTY_EXPOSURE_INTELLIGENCE,
      generatedAt: new Date().toISOString(),
      evidence: {
        sources: [],
        note: 'No assessment evidence recorded for this tenant. Run a PQC discovery scan, register assets or connect cloud integrations to populate the dependency graph.',
      },
    }
  }

  /* ---- Per-asset evidence maps (mirrors the QR risk model) -------- */
  const assetById = new Map<string, Row>(assets.map((a) => [str(a.id), a]))
  const assetIdByName = new Map<string, string>()
  for (const a of assets) {
    const name = str(a.name).toLowerCase()
    if (name) assetIdByName.set(name, str(a.id))
  }
  const resolveAsset = (assetId: string, assetName: string): string => {
    if (assetId && assetById.has(assetId)) return assetId
    return assetIdByName.get(assetName.toLowerCase()) || ''
  }

  /*
   * Per-asset risk and posture come from THE canonical model
   * (deriveAssetPostureModel) — the same call the Quantum Readiness snapshot,
   * the Migration Planner and /dashboard/assets make. This graph used to keep
   * its own copy (it also counted classical certificates and name-matched rows
   * as vulnerability evidence), so its "Quantum Vulnerable" KPI could disagree
   * with the Quantum Readiness overview for the same estate.
   */
  const postureModel = deriveAssetPostureModel({ assets, scanResults, cryptoExposures, cryptoInventory, runtimeEvents })
  const assetRisk = postureModel.assetRisk

  const algosByAsset = new Map<string, Set<string>>()
  const protosByAsset = new Map<string, Set<string>>()
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
  // Algorithm / protocol detail for the node inspector (display only — posture
  // is decided by the canonical model above).
  for (const i of cryptoInventory) addAlgo(resolveAsset(str(i.asset_id), str(i.name)), str(i.algorithm), str(i.protocol))
  for (const e of runtimeEvents) addAlgo(resolveAsset(str(e.asset_id), str(e.asset_name)), str(e.algorithm), '')
  for (const r of scanResults) addAlgo(str(r.asset_id), str(r.algorithm), '')

  const certsByAsset = new Map<string, NodeCertificate[]>()
  for (const c of certificates) {
    const id = resolveAsset(str(c.asset_id), str(c.name))
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
  for (const j of migrationJobs) {
    if (ACTIVE_JOB_STATUS.test(str(j.status))) {
      const id = str(j.asset_id)
      if (assetById.has(id)) migratingAssetIds.add(id)
    }
  }

  const findingsByAsset = new Map<string, number>()
  for (const f of snapshot.criticalFindings) {
    const id = assetIdByName.get(f.asset.toLowerCase())
    if (id) findingsByAsset.set(id, (findingsByAsset.get(id) || 0) + (Number((f as { instances?: number }).instances) || 1))
  }

  /* ---- Five-state posture per asset -------------------------------- */
  // The canonical verdict, plus two states the graph can say more precisely:
  // an active migration job ('migrating'), and an asset nothing was measured on
  // ('unknown' — the canonical model files those under hybrid for its counts).
  const postureFor = (assetId: string): NodePosture => {
    if (migratingAssetIds.has(assetId)) return 'migrating'
    if (!postureModel.evidencedAssetIds.has(assetId)) return 'unknown'
    return postureModel.assetPosture.get(assetId) || 'unknown'
  }

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
      posture: postureFor(id),
      riskScore: Math.round(assetRisk.get(id) || 0),
      priority: 'Low',
      priorityScore: 0,
      priorityDrivers: [],
      internetFacing: isInternetFacing(asset),
      migrationTier: tier.tier,
      tierLabel: tier.label,
      algorithms: [...(algosByAsset.get(id) || [])].slice(0, 10),
      protocols: [...(protosByAsset.get(id) || [])].slice(0, 6),
      certificates: (certsByAsset.get(id) || []).slice(0, 6),
      dependencies: 0,
      dependents: 0,
      blastRadius: 0,
      findingsCount: findingsByAsset.get(id) || 0,
    }
    nodes.push(node)
    nodeById.set(id, node)
  }

  /* ---- Edges: real asset relationships ----------------------------- */
  const edges: ExposureGraphEdge[] = []
  const edgeKeys = new Set<string>()
  const pushEdge = (source: string, target: string, type: string, trustClass: EdgeTrustClass, algorithm: string | null) => {
    if (!source || !target || source === target) return
    if (!nodeById.has(source) || !nodeById.has(target)) return
    const key = `${source}|${target}|${trustClass}`
    const reverseKey = `${target}|${source}|${trustClass}`
    if (edgeKeys.has(key) || (trustClass === 'communication' && edgeKeys.has(reverseKey))) return
    if (edges.length >= MAX_EDGES) return
    edgeKeys.add(key)
    const algoClass = algorithm ? classifyAlgorithmClass(algorithm) : 'unknown'
    const posture: NodePosture = algorithm
      ? algoClass === 'vulnerable' ? 'vulnerable' : algoClass === 'hybrid' ? 'hybrid' : algoClass === 'unknown' ? 'unknown' : 'pqc'
      : 'unknown'
    edges.push({ id: `${slug(source)}~${slug(target)}~${trustClass}`, source, target, type, trustClass, algorithm, posture, critical: false })
  }

  const relSource = (r: Row) => str(r.source_asset_id || r.parent_asset_id || r.from_asset_id)
  const relTarget = (r: Row) => str(r.target_asset_id || r.child_asset_id || r.to_asset_id)
  for (const r of relationships) {
    const type = str(r.relationship_type) || 'depends-on'
    pushEdge(relSource(r), relTarget(r), type, classifyTrustClass(type), null)
  }

  /* ---- External certificate authorities (real issuers) ------------- */
  const issuerGroups = new Map<string, { name: string; certs: Array<{ ownerAssetId: string; algorithm: string; quantumSafe: boolean; certName: string }> }>()
  for (const c of certificates) {
    const rawIssuer = str(c.issuer)
    if (!rawIssuer.trim()) continue
    const name = issuerName(rawIssuer)
    const nameLower = name.toLowerCase()
    // Skip issuers that are themselves tenant assets (internal CA already a node).
    let internal = false
    for (const [assetName, assetId] of assetIdByName) {
      if (assetName && (assetName.includes(nameLower) || nameLower.includes(assetName))) {
        const ownerId = resolveAsset(str(c.asset_id), str(c.name))
        if (ownerId && ownerId !== assetId) pushEdge(ownerId, assetId, 'issued-by', 'certificate-chain', str(c.algorithm) || null)
        internal = true
        break
      }
    }
    if (internal) continue
    const ownerAssetId = resolveAsset(str(c.asset_id), str(c.name))
    if (!ownerAssetId || !nodeById.has(ownerAssetId)) continue
    const group = issuerGroups.get(nameLower) || { name, certs: [] }
    group.certs.push({ ownerAssetId, algorithm: str(c.algorithm), quantumSafe: c.is_quantum_safe === true, certName: str(c.name) })
    issuerGroups.set(nameLower, group)
  }
  const topIssuers = [...issuerGroups.values()].sort((a, b) => b.certs.length - a.certs.length).slice(0, MAX_CA_NODES)
  for (const issuer of topIssuers) {
    const id = `ca:${slug(issuer.name)}`
    const classes = new Set<string>(issuer.certs.map((c) => (c.quantumSafe ? 'pqc' : classifyAlgorithmClass(c.algorithm))))
    const node: ExposureGraphNode = {
      id,
      label: issuer.name,
      kind: 'external',
      category: 'certificate-authority',
      type: 'external certificate authority',
      environment: 'external',
      region: '—',
      owner: 'Third-Party',
      businessCriticality: issuer.certs.length >= 3 ? 'Critical' : 'High',
      posture: posturesFromClasses(classes),
      riskScore: classes.has('vulnerable') ? 70 : 20,
      priority: 'Low',
      priorityScore: 0,
      priorityDrivers: [],
      internetFacing: true,
      migrationTier: 1,
      tierLabel: 'Certificate Authorities',
      algorithms: [...new Set(issuer.certs.map((c) => c.algorithm).filter(Boolean))].slice(0, 6),
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
    for (const cert of issuer.certs) pushEdge(cert.ownerAssetId, id, 'issued-by', 'certificate-chain', cert.algorithm || null)
  }

  /* ---- External services observed in runtime telemetry ------------- */
  const externalHosts = new Map<string, { host: string; count: number; algorithms: Set<string>; owners: Set<string>; maxRisk: number }>()
  for (const e of runtimeEvents) {
    const host = str(e.host).toLowerCase().trim()
    if (!host || !host.includes('.')) continue
    const ownerId = resolveAsset(str(e.asset_id), str(e.asset_name))
    if (!ownerId || !nodeById.has(ownerId)) continue
    // Host that matches a tenant asset is an internal communication path.
    const internalTarget = assetIdByName.get(host)
    if (internalTarget && internalTarget !== ownerId) {
      pushEdge(ownerId, internalTarget, 'communicates-with', 'communication', str(e.algorithm) || null)
      continue
    }
    if (internalTarget) continue
    const entry = externalHosts.get(host) || { host, count: 0, algorithms: new Set<string>(), owners: new Set<string>(), maxRisk: 0 }
    entry.count += 1
    if (str(e.algorithm)) entry.algorithms.add(str(e.algorithm))
    entry.owners.add(ownerId)
    entry.maxRisk = Math.max(entry.maxRisk, num(e.risk_score), e.is_legacy === true ? 60 : 0)
    externalHosts.set(host, entry)
  }
  const topHosts = [...externalHosts.values()].sort((a, b) => b.count - a.count).slice(0, MAX_EXTERNAL_HOSTS)
  for (const ext of topHosts) {
    const id = `ext:${slug(ext.host)}`
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
      businessCriticality: ext.owners.size >= 3 ? 'High' : 'Medium',
      posture: posturesFromClasses(classes),
      riskScore: Math.round(Math.max(ext.maxRisk, classes.has('vulnerable') ? 60 : 15)),
      priority: 'Low',
      priorityScore: 0,
      priorityDrivers: [],
      internetFacing: true,
      migrationTier: 12,
      tierLabel: 'External & Vendor Services',
      algorithms: [...ext.algorithms].slice(0, 6),
      protocols: [],
      certificates: [],
      dependencies: 0,
      dependents: 0,
      blastRadius: 0,
      findingsCount: 0,
      vendor: ext.host,
    }
    nodes.push(node)
    nodeById.set(id, node)
    for (const ownerId of ext.owners) {
      const observed = [...ext.algorithms]
      pushEdge(ownerId, id, 'communicates-with', /tls|https/i.test(observed.join(' ')) ? 'tls' : 'communication', observed[0] || null)
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
    const entry = connectorProviders.get(label.toLowerCase()) || { provider: label, status: str(account.status) || 'connected', linkedAssets: [] }
    connectorProviders.set(label.toLowerCase(), entry)
  }
  for (const entry of connectorProviders.values()) {
    const pattern = providerPatterns.find((p) => p.label === entry.provider)?.pattern || new RegExp(entry.provider.split(' ')[0], 'i')
    for (const node of nodes) {
      if (node.kind !== 'asset') continue
      const asset = assetById.get(node.id)
      const haystack = `${node.type} ${node.region} ${node.label} ${JSON.stringify((asset?.metadata as Row) || {})}`
      if (pattern.test(haystack)) entry.linkedAssets.push(node.id)
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
      businessCriticality: 'High',
      posture: 'unknown',
      riskScore: 25,
      priority: 'Low',
      priorityScore: 0,
      priorityDrivers: [],
      internetFacing: true,
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
    for (const assetId of entry.linkedAssets.slice(0, 12)) pushEdge(assetId, id, 'hosted-on', 'cloud', null)
  }

  /* ---- Degrees, blast radius, priority, edge criticality ----------- */
  for (const edge of edges) {
    const source = nodeById.get(edge.source)
    const target = nodeById.get(edge.target)
    if (source) source.dependencies += 1
    if (target) target.dependents += 1
  }
  const adjacency = buildAdjacency(edges)
  for (const node of nodes) {
    node.blastRadius = computeBlastRadius(nodes, edges, node.id, 6, adjacency).totalAffected
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
    const vulnerableLink = edge.posture === 'vulnerable' || source?.posture === 'vulnerable' || target?.posture === 'vulnerable'
    const criticalPair = (source?.businessCriticality === 'Critical' || target?.businessCriticality === 'Critical')
    edge.critical = Boolean(vulnerableLink && (criticalPair || TRUST_CHAIN_CLASSES.has(edge.trustClass)))
  }

  /* ---- Summary metrics (exact-count floors from the snapshot) ------ */
  let vulnerableAssets = 0
  let hybridAssets = 0
  let pqcAssets = 0
  let migratingAssets = 0
  let unknownAssets = 0
  let internetFacingAssets = 0
  let legacyCryptoAssets = 0
  for (const asset of assets) {
    const id = str(asset.id)
    const posture = postureFor(id)
    if (posture === 'vulnerable') vulnerableAssets += 1
    else if (posture === 'hybrid') hybridAssets += 1
    else if (posture === 'pqc') pqcAssets += 1
    else if (posture === 'migrating') migratingAssets += 1
    else unknownAssets += 1
    if (isInternetFacing(asset)) internetFacingAssets += 1
    if ([...(algosByAsset.get(id) || [])].some((a) => classifyAlgorithmClass(a) === 'vulnerable')) legacyCryptoAssets += 1
  }
  const totalAssets = Math.max(assets.length, snapshot.inventory.assetsAssessed)
  const assetNodes = nodes.filter((n) => n.kind === 'asset')
  const externalNodes = nodes.filter((n) => n.kind === 'external')
  const unlinkedConnectors = [...connectorProviders.values()].filter((c) => !c.linkedAssets.length)
  const migrationReadinessScore = assets.length
    ? clampPct(((pqcAssets + hybridAssets * 0.5 + migratingAssets * 0.5) / assets.length) * 100)
    : 0

  const summary = {
    totalAssets,
    quantumVulnerable: vulnerableAssets,
    hybridAssets,
    pqcReadyAssets: pqcAssets,
    migrationInProgress: migratingAssets,
    unknownPosture: unknownAssets,
    thirdPartyDependencies: externalNodes.length + unlinkedConnectors.length,
    trustRelationships: Math.max(edges.length, snapshot.inventory.trustRelationships),
    criticalTrustRelationships: edges.filter((e) => e.critical).length,
    internetFacingAssets,
    highRiskAssets: assetNodes.filter((n) => n.priority === 'Critical' || n.priority === 'High').length,
    legacyCryptoAssets,
    certificateChains: issuerGroups.size,
    pkiObjects: Math.max(certificates.length, snapshot.inventory.certificatesAnalyzed) + topIssuers.length,
    maxBlastRadius: nodes.reduce((max, n) => Math.max(max, n.blastRadius), 0),
    migrationReadinessScore,
    quantumReadinessScore: snapshot.scores.quantumReadiness,
    quantumRiskScore: snapshot.scores.quantumRisk,
  }

  /* ---- Third-party dependency analysis ----------------------------- */
  const thirdParty: ThirdPartyDependency[] = []
  for (const node of externalNodes) {
    const connected = edges.filter((e) => e.source === node.id || e.target === node.id)
    const connectedNames = connected
      .map((e) => nodeById.get(e.source === node.id ? e.target : e.source)?.label || '')
      .filter(Boolean)
    const protocols = new Set<string>()
    for (const e of connected) if (e.algorithm && /tls\s?1\.[0-3]/i.test(e.algorithm)) protocols.add(/tls\s?1\.[0-3]/i.exec(e.algorithm)![0].toUpperCase())
    for (const a of node.algorithms) { const m = /tls\s?1\.[0-3]/i.exec(a); if (m) protocols.add(m[0].toUpperCase()) }
    thirdParty.push({
      id: node.id,
      vendor: node.vendor || node.label,
      category: node.category === 'certificate-authority' ? 'External PKI / CA' : node.category === 'cloud-resource' ? 'Cloud Provider' : vendorServiceLabel(node.label),
      connectedAssets: connectedNames.length,
      connectedAssetNames: [...new Set(connectedNames)].slice(0, 6),
      algorithms: node.algorithms,
      tlsVersion: [...protocols].sort().pop() || null,
      certificate: node.category === 'certificate-authority' ? `${issuerGroups.get((node.vendor || '').toLowerCase())?.certs.length || 0} issued certificate(s)` : null,
      readiness: node.posture,
      riskLevel: node.posture === 'vulnerable' ? (node.businessCriticality === 'Critical' ? 'Critical' : 'High') : node.posture === 'unknown' ? 'Medium' : 'Low',
      migrationCompatibility:
        node.posture === 'pqc' ? 'PQC-compatible — safe to migrate dependents'
        : node.posture === 'hybrid' ? 'Hybrid-capable — dependents may adopt hybrid TLS now'
        : node.posture === 'vulnerable' ? 'Requires vendor PQC support — restrict to hybrid until validated'
        : 'Compatibility unverified — validate vendor crypto before cutover',
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
      riskLevel: 'Medium',
      migrationCompatibility: 'Connected account — no linked assets discovered yet',
      businessCriticality: 'Medium',
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
  for (const edge of edges) {
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
  for (const edge of edges) {
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
        reason: `Third-party service still negotiates quantum-vulnerable cryptography — ${degree} dependent asset(s) are limited to hybrid protection until vendor PQC support ships.`,
        blockedDependents: degree,
      })
    } else if (node.kind === 'asset' && (node.category === 'certificate-authority' || node.category === 'pki') && node.posture === 'vulnerable' && node.dependents + node.dependencies >= 1) {
      blockers.push({
        id: node.id,
        label: node.label,
        reason: `Trust anchor issues classical certificates — ${degree} dependent chain(s) cannot complete migration until this authority migrates.`,
        blockedDependents: degree,
      })
    } else if (node.kind === 'asset' && (node.category === 'kms' || node.category === 'hsm') && node.posture === 'vulnerable' && degree >= 1) {
      blockers.push({
        id: node.id,
        label: node.label,
        reason: `Key management does not yet support ML-KEM / ML-DSA — ${degree} dependent system(s) cannot rotate onto PQC keys.`,
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
      confidencePct: 90,
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
      confidencePct: 85,
      category: 'Sequencing',
    })
  }
  for (const blocker of blockers.filter((b) => b.id.startsWith('ext:') || b.id.startsWith('cloud:')).slice(0, 2)) {
    pushRec({
      id: `rec-vendor-${slug(blocker.label)}`,
      title: `Delay hard cutover of ${blocker.label}-dependent services`,
      detail: `${blocker.reason} Track vendor PQC readiness and enforce hybrid TLS on the connecting assets in the interim.`,
      severity: 'high',
      confidencePct: 80,
      category: 'Third-Party',
    })
  }
  const internetVulnApis = assetNodes.filter((n) => n.internetFacing && n.posture === 'vulnerable' && (n.category === 'api' || n.category === 'load-balancer' || n.category === 'tls-endpoint' || n.category === 'web-application'))
  if (internetVulnApis.length) {
    pushRec({
      id: 'rec-hybrid-tls',
      title: `Deploy Hybrid TLS (X25519 + ML-KEM-768) on ${internetVulnApis.length} internet-facing endpoint(s)`,
      detail: 'Hybrid key establishment protects against harvest-now-decrypt-later immediately while preserving compatibility with legacy clients.',
      severity: 'high',
      confidencePct: 88,
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
      confidencePct: 70,
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
      confidencePct: 82,
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
      confidencePct: 78,
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
      confidencePct: 92,
      category: 'Discovery',
    })
  }

  const edgesWithKnownEnds = edges.filter((e) => nodeById.has(e.source) && nodeById.has(e.target))
  const compatibleEdges = edgesWithKnownEnds.filter((e) => {
    const s = nodeById.get(e.source)!
    const t = nodeById.get(e.target)!
    const ok = (p: NodePosture) => p === 'pqc' || p === 'hybrid' || p === 'migrating'
    return ok(s.posture) && ok(t.posture)
  }).length
  const evidencedAssets = assetNodes.filter((n) => n.algorithms.length > 0 || n.certificates.length > 0).length
  const coverage = assetNodes.length ? evidencedAssets / assetNodes.length : 0
  const criticalAssets = assetNodes.filter((n) => n.businessCriticality === 'Critical' || n.businessCriticality === 'High')
  const criticalVulnShare = criticalAssets.length
    ? criticalAssets.filter((n) => n.posture === 'vulnerable').length / criticalAssets.length
    : vulnerableAssets / Math.max(1, assets.length)

  const advisorEstimates = {
    migrationComplexity: snapshot.scores.migrationComplexity,
    complexityLevel: snapshot.scores.migrationComplexityLevel,
    businessImpact: priorityFromScore(clampPct(criticalVulnShare * 100)),
    compatibilityScorePct: edgesWithKnownEnds.length ? clampPct((compatibleEdges / edgesWithKnownEnds.length) * 100) : 0,
    estimatedDurationWeeks: snapshot.estimates.migrationTimelineWeeks,
    parallelWorkstreams: snapshot.estimates.parallelWorkstreams || 1,
    confidencePct: clampPct(30 + (coverage * 0.6 + snapshot.assessmentProgress / 100 * 0.4) * 65),
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
      sources: ['Asset Inventory', 'Asset Relationships', 'CBOM / Crypto Inventory', 'Certificate Inventory', 'Runtime Crypto Telemetry', 'PQC Scan Findings', 'Cloud Connectors', 'Migration Jobs'],
      note: `Dependency graph derived from ${assets.length} asset(s), ${relationships.length} recorded relationship(s), ${certificates.length} certificate(s), ${cryptoInventory.length} CBOM component(s) and ${runtimeEvents.length} runtime event(s). External entities are materialised only from observed evidence (issuers, hosts, connectors). Scores mirror the Quantum Readiness Assessment Engine™.`,
    },
  }
}

/* ================================================================== */
/* Evidence loader + per-tenant single-flight cache                    */
/* ================================================================== */

async function computeExposureIntelligence(token: string, userId: string): Promise<ExposureIntelligence> {
  const snapshot = await buildSnapshot(token, userId)
  const client = createAuthClient(token)
  const rows: ExposureRawRows = client
    ? {
        assets: await safeRows(client, 'assets', 'id, name, type, environment, region, service_owner, criticality, status, metadata, created_at', userId, 1500),
        relationships: await safeRows(client, 'asset_relationships', '*', userId, 3000),
        cryptoInventory: await safeRows(client, 'crypto_inventory', 'id, asset_id, item_type, name, algorithm, key_size, protocol, exposure_level, is_vulnerable, is_quantum_safe, created_at', userId, 2500),
        certificates: await safeRows(client, 'certificates', 'id, asset_id, name, algorithm, key_size, issuer, not_after, is_quantum_safe, is_expiring_soon, status, created_at', userId, 1500),
        runtimeEvents: await safeRows(client, 'runtime_crypto_events', 'id, asset_id, algorithm, severity, risk_score, asset_name, asset_type, host, is_pqc, is_legacy, hndl_risk, created_at', userId, 3000),
        scanResults: await safeRows(client, 'pqc_scan_results', 'id, asset_id, algorithm, threat_level, created_at', userId, 2000),
        cryptoExposures: await safeRows(client, 'crypto_exposures', 'id, asset_id, exposure_type, severity, created_at', userId, 2000),
        connectorAccounts: await safeRows(client, 'connector_accounts', 'id, provider, status', userId, 400, 'id'),
        migrationJobs: await safeRows(client, 'migration_jobs', 'id, status, progress, asset_id, job_type, created_at', userId, 300),
      }
    : { assets: [], relationships: [], cryptoInventory: [], certificates: [], runtimeEvents: [], scanResults: [], cryptoExposures: [], connectorAccounts: [], migrationJobs: [] }
  return assembleExposureIntelligence(snapshot, rows)
}

// Per-tenant single-flight cache shared by the JSON endpoint, the SSE loop and
// every open tab. The previous hand-rolled Map stamped `at` at build START, so
// a build slower than its TTL was duplicated by the next tick — the exact
// amplifier lib/single-flight-cache.ts exists to remove. Failures are never cached.
const intelCache = createSingleFlightCache<ExposureIntelligence>(15_000)

export async function buildExposureIntelligence(token: string, userId: string): Promise<ExposureIntelligence> {
  return intelCache.get(userId, () => computeExposureIntelligence(token, userId))
}

/* ================================================================== */
/* Routes                                                              */
/* ================================================================== */

router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const data = await buildExposureIntelligence(token!, user!.id)
    res.json({ data: { ...data, fingerprint: payloadFingerprint(data) } })
  } catch (error) {
    console.error('Exposure graph intelligence error:', error)
    res.status(500).json({ error: { code: 'EXPOSURE_GRAPH_ERROR', message: error instanceof Error ? error.message : 'Failed to build exposure graph intelligence' } })
  }
})

router.get('/stream', (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  streamLiveSnapshot(req, res, {
    event: 'exposure-intelligence',
    build: () => buildExposureIntelligence(token!, user!.id),
    intervalMs: 15_000,
  })
})

export default router
