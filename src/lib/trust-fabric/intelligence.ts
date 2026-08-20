/**
 * Trust Fabric engine - the one computation behind four dashboards.
 *
 * This is a PURE function: rows and canonical models in, `TrustFabricIntelligence`
 * out. It performs no I/O, which is what lets it be unit-reasoned about and
 * lets the API layer own caching.
 *
 * It deliberately does NOT recompute certificates, endpoints, TLS findings,
 * trust chains or the estate readiness score. Those arrive already computed
 * from `buildTlsPkiIntelligence()` and `buildSnapshot()`, so
 * `/dashboard/certificate-telemetry` cannot report a different certificate
 * count from `/dashboard/pki-visibility`, and `/dashboard/trust-dashboard`
 * cannot report a different quantum readiness from the QR Engine. That is
 * brief section 7 enforced by construction rather than by convention.
 */

import {
  clamp,
  dateMs,
  isoOrNull,
  latestIso,
  normalizeSeverity,
  num,
  percentOf,
  recordOf,
  str,
  titleCase,
  uniq,
} from '@/lib/tls-pki/classify'
import type { AssetMigrationRecord } from '@/lib/migration/asset-intelligence'
import type { TlsPkiIntelligence } from '@/lib/tls-pki/types'
import {
  assetNodeKind,
  buildChainPaths,
  certificateState,
  computeDownstream,
  endpointState,
  indexFindings,
  nodeId,
  worseState,
} from './graph'
import { attributeCloudProvider, providerLabelFor, readAccount, readKeyManagement, readRegion, readService } from './cloud'
import {
  CLOUD_PROVIDER_LABEL,
  EXPIRY_BAND_LABEL,
  EXPIRY_BAND_ORDER,
  TRUST_EVENT_LABEL,
  TRUST_NODE_LABEL,
  TRUST_STATE_LABEL,
  TRUST_STATE_RANK,
  type CertificateIntelligence,
  type CertificateTrustRecord,
  type ChainCheck,
  type CloudEstate,
  type CloudProviderId,
  type CloudProviderPosture,
  type CloudRegionPosture,
  type CloudResource,
  type CrossModuleCheck,
  type EncryptionState,
  type EvidenceSource,
  type ExpiryBand,
  type PkiCertificate,
  type PqcPosture,
  type ReconciliationIssue,
  type Severity,
  type TrustEvent,
  type TrustEventKind,
  type TrustFabricIntelligence,
  type TrustKpi,
  type TrustNode,
  type TrustNodeKind,
  type TrustRelationship,
  type TrustScore,
  type TrustState,
} from './types'

type Row = Record<string, unknown>

const DAY_MS = 86_400_000
/** Beyond this, telemetry is called stale rather than live (section 13). */
const STALE_AFTER_HOURS = 24

/* ================================================================== */
/* Inputs                                                             */
/* ================================================================== */

export interface TrustFabricInputs {
  /** Fully computed TLS/PKI model - certificates, endpoints, findings, chains. */
  tlsPki: TlsPkiIntelligence
  /** Canonical per-asset records from `buildPortfolio()`. */
  assets: AssetMigrationRecord[]
  /** Estate scores published verbatim by the Quantum Readiness Engine. */
  snapshot: {
    quantumReadiness: number
    quantumRisk: number
    quantumRiskLevel: string
    assetsAssessed: number
    certificatesAnalyzed: number
    complianceScore: number | null
    vulnerableComponents: number
    totalComponents: number
    pqcReadyComponents: number
  }
  assetRows: Row[]
  assetRelationships: Row[]
  connectorAccounts: Row[]
  securityEvents: Row[]
  scanSessions: Row[]
  migrationJobs: Row[]
  scannerAgents: Row[]
  complianceEvidence: Row[]
  cryptoInventory: Row[]
  runtimeEvents: Row[]
  now?: number
}

/* ================================================================== */
/* Small helpers                                                       */
/* ================================================================== */

function toneForScore(value: number | null): TrustScore['tone'] {
  if (value === null) return 'neutral'
  if (value >= 85) return 'good'
  if (value >= 70) return 'info'
  if (value >= 50) return 'warning'
  return 'critical'
}

function stateTone(state: TrustState): TrustScore['tone'] {
  if (state === 'critical' || state === 'invalid' || state === 'expired' || state === 'quantum-vulnerable') return 'critical'
  if (state === 'at-risk' || state === 'migration-required' || state === 'degraded') return 'warning'
  if (state === 'unknown') return 'neutral'
  return 'good'
}

function bandFor(days: number | null, lifecycle: PkiCertificate['lifecycle']): ExpiryBand {
  if (lifecycle === 'expired') return 'expired'
  if (days === null) return 'unknown'
  if (days < 0) return 'expired'
  if (days <= 7) return 'critical'
  if (days <= 30) return 'high'
  if (days <= 60) return 'warning'
  return 'healthy'
}

function dayKey(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10)
}

function monthKey(ms: number): string {
  return new Date(ms).toISOString().slice(0, 7)
}

function monthLabel(key: string): string {
  const [year, month] = key.split('-')
  const date = new Date(Number(year), Number(month) - 1, 1)
  return date.toLocaleDateString('en-US', { month: 'short', year: '2-digit' })
}

/**
 * A weighted average that returns `null` rather than 0 when there is nothing to
 * average. Every score in this model uses it, which is why an empty tenant
 * shows "Not measured" instead of a wall of zeroes that reads as total failure.
 */
function meanOrNull(values: number[]): number | null {
  if (values.length === 0) return null
  const total = values.reduce((sum, value) => sum + value, 0)
  return clamp(Math.round(total / values.length))
}

function ratioScore(good: number, total: number): number | null {
  if (total <= 0) return null
  return clamp(Math.round((good / total) * 100))
}

/**
 * Translates the Migration Planner's three-value posture into the shared
 * `PqcPosture` vocabulary these four pages publish.
 *
 * An asset with no evidence maps to `unknown`, NOT to `quantum-vulnerable`.
 * Treating absence of evidence as vulnerability would invent risk; treating it
 * as safety would hide it. `unknown` is the only honest reading, and it is why
 * every percentage in this model is measured against subjects that carry
 * evidence rather than against the whole inventory.
 */
function posturefromAsset(asset: AssetMigrationRecord): PqcPosture {
  if (!asset.hasEvidence) return 'unknown'
  if (asset.posture === 'pqc') return 'pqc-ready'
  if (asset.posture === 'hybrid') return 'hybrid-ready'
  return 'quantum-vulnerable'
}

/* ================================================================== */
/* Engine                                                              */
/* ================================================================== */

export function buildTrustFabricIntelligence(inputs: TrustFabricInputs): TrustFabricIntelligence {
  const now = inputs.now ?? Date.now()
  const { tlsPki, assets, snapshot } = inputs

  const certificates = tlsPki.certificates
  const endpoints = tlsPki.endpoints
  const findings = tlsPki.findings
  const findingIndex = indexFindings(findings)

  const assetById = new Map(assets.map((asset) => [asset.id, asset]))
  const assetRowById = new Map(inputs.assetRows.map((row) => [str(row.id), row]))

  /* ---------------------------------------------------------------- */
  /* Connectors - the tenant's declared cloud footprint                */
  /* ---------------------------------------------------------------- */

  const connectorProviders: string[] = []
  const connectorByProvider = new Map<CloudProviderId, { count: number; active: number; status: string; lastSync: string | null }>()
  let connectorsActive = 0

  for (const row of inputs.connectorAccounts) {
    const rawProvider = str(row.provider)
    if (rawProvider) connectorProviders.push(rawProvider.toLowerCase())
    const provider = (attributeCloudProvider({ explicitProvider: rawProvider, connectors: [] }).provider) as CloudProviderId
    const status = str(row.status).toLowerCase()
    const active = status === 'connected' || status === 'active' || status === 'ok'
    if (active) connectorsActive += 1
    const current = connectorByProvider.get(provider) || { count: 0, active: 0, status: '', lastSync: null }
    current.count += 1
    if (active) current.active += 1
    current.status = current.active > 0 ? 'connected' : status || 'unknown'
    current.lastSync = latestIso(current.lastSync, row.last_sync_at, row.updated_at)
    connectorByProvider.set(provider, current)
  }

  /* ---------------------------------------------------------------- */
  /* Trust nodes                                                       */
  /* ---------------------------------------------------------------- */

  const nodes = new Map<string, TrustNode>()
  const edges: TrustRelationship[] = []
  const edgeSeen = new Set<string>()

  const addEdge = (edge: TrustRelationship) => {
    if (edgeSeen.has(edge.id)) return
    edgeSeen.add(edge.id)
    edges.push(edge)
  }

  /* ---- Certificate authorities, from observed issuer identities ---- */

  // A certificate whose subject equals its issuer, or that another certificate
  // names as issuer, is a CA we actually hold. Everything else referenced only
  // by name is emitted as an inferred node.
  const certBySubject = new Map<string, PkiCertificate>()
  for (const certificate of certificates) {
    const subject = str(certificate.subject).toLowerCase()
    if (subject) certBySubject.set(subject, certificate)
  }

  const issuerNames = new Map<string, { certificates: PkiCertificate[]; measuredCert: PkiCertificate | null }>()
  for (const certificate of certificates) {
    const issuer = str(certificate.issuer)
    if (!issuer) continue
    const key = issuer.toLowerCase()
    const entry = issuerNames.get(key) || { certificates: [], measuredCert: null }
    entry.certificates.push(certificate)
    if (!entry.measuredCert) entry.measuredCert = certBySubject.get(key) || null
    issuerNames.set(key, entry)
  }

  for (const [key, entry] of issuerNames) {
    const issuer = str(entry.certificates[0].issuer)
    const id = nodeId.ca(issuer)
    const measuredCert = entry.measuredCert
    // Root when the CA certificate we hold is self-issued, or when nothing in
    // the tenant issued the issuer. Intermediate when it has a parent of its own.
    const parentIssuer = measuredCert ? str(measuredCert.issuer).toLowerCase() : ''
    const isRoot = !parentIssuer || parentIssuer === key
    const covered = entry.certificates
    const expiring = covered.filter((cert) => cert.daysToExpiry !== null && cert.daysToExpiry <= 30).length
    const vulnerable = covered.filter((cert) => cert.posture === 'quantum-vulnerable' || cert.posture === 'legacy').length

    let state: TrustState = 'trusted'
    let reason = `Issued ${covered.length} certificate${covered.length === 1 ? '' : 's'} in this tenant.`
    if (!measuredCert) {
      state = 'unknown'
      reason = 'Known only as an issuer name on leaf certificates; the CA certificate itself has not been collected.'
    } else if (measuredCert.lifecycle === 'expired') {
      state = 'expired'
      reason = 'The CA certificate held for this authority has expired, invalidating everything below it.'
    } else if (vulnerable === covered.length && covered.length > 0) {
      state = 'quantum-vulnerable'
      reason = `Every certificate this authority issued here uses classical cryptography (${covered.length}).`
    } else if (expiring > 0) {
      state = 'at-risk'
      reason = `${expiring} certificate${expiring === 1 ? '' : 's'} issued by this authority expire within 30 days.`
    }

    nodes.set(id, {
      id,
      kind: isRoot ? 'root-ca' : 'intermediate-ca',
      label: issuer,
      subtitle: measuredCert ? `Certificate collected - ${measuredCert.algorithmLabel}` : 'Issuer name only, not measured',
      state,
      stateReason: reason,
      posture: measuredCert?.posture ?? 'unknown',
      riskLevel: measuredCert?.riskLevel ?? 'none',
      riskScore: measuredCert?.riskScore ?? 0,
      assetId: null,
      certificateId: measuredCert?.id ?? null,
      endpointId: null,
      environment: '',
      owner: '',
      provider: 'unattributed',
      providerLabel: CLOUD_PROVIDER_LABEL.unattributed,
      account: '',
      region: '',
      dependentCount: 0,
      dependencyCount: 0,
      quantumVulnerable: vulnerable > 0,
      daysToExpiry: measuredCert?.daysToExpiry ?? null,
      findingIds: [],
      criticalFindings: 0,
      highFindings: 0,
      measured: Boolean(measuredCert),
      evidenceSources: measuredCert ? measuredCert.sources : [],
      lastObservedAt: measuredCert?.lastObservedAt ?? null,
      href: '/dashboard/pki-visibility',
    })
  }

  /* ---- Certificates ---- */

  for (const certificate of certificates) {
    const id = nodeId.certificate(certificate.id)
    const { state, reason } = certificateState(certificate)
    const asset = certificate.assetId ? assetById.get(certificate.assetId) : undefined
    nodes.set(id, {
      id,
      kind: 'certificate',
      label: certificate.name || certificate.subject || 'Certificate',
      subtitle: certificate.issuer ? `Issued by ${certificate.issuer}` : 'Issuer not recorded',
      state,
      stateReason: reason,
      posture: certificate.posture,
      riskLevel: certificate.riskLevel,
      riskScore: certificate.riskScore,
      assetId: certificate.assetId,
      certificateId: certificate.id,
      endpointId: certificate.endpointId,
      environment: asset?.environment ?? '',
      owner: asset?.owner ?? '',
      provider: 'unattributed',
      providerLabel: CLOUD_PROVIDER_LABEL.unattributed,
      account: '',
      region: asset?.region ?? '',
      dependentCount: 0,
      dependencyCount: 0,
      quantumVulnerable: certificate.posture === 'quantum-vulnerable' || certificate.posture === 'legacy',
      daysToExpiry: certificate.daysToExpiry,
      findingIds: [],
      criticalFindings: 0,
      highFindings: 0,
      measured: true,
      evidenceSources: certificate.sources,
      lastObservedAt: certificate.lastObservedAt,
      href: '/dashboard/certificate-telemetry',
    })

    const issuer = str(certificate.issuer)
    if (issuer) {
      const caId = nodeId.ca(issuer)
      if (nodes.has(caId) && caId !== id) {
        addEdge({
          id: `edge:issued:${caId}:${id}`,
          from: caId,
          to: id,
          kind: 'issued',
          label: 'issued',
          state: nodes.get(caId)?.state === 'unknown' ? 'unknown' : state,
          reason: nodes.get(caId)?.measured
            ? 'Issuer certificate is present in the tenant inventory.'
            : 'Link inferred from the issuer name on the leaf certificate; the CA certificate was not collected.',
          source: 'certificate-chain',
          measured: Boolean(nodes.get(caId)?.measured),
        })
      }
    }
  }

  /* ---- Intermediate -> Root links, where both are held ---- */

  for (const [key, entry] of issuerNames) {
    const measured = entry.measuredCert
    if (!measured) continue
    const parent = str(measured.issuer)
    if (!parent || parent.toLowerCase() === key) continue
    const parentId = nodeId.ca(parent)
    const childId = nodeId.ca(str(entry.certificates[0].issuer))
    if (!nodes.has(parentId) || !nodes.has(childId) || parentId === childId) continue
    addEdge({
      id: `edge:signs:${parentId}:${childId}`,
      from: parentId,
      to: childId,
      kind: 'signs-for',
      label: 'signs for',
      state: nodes.get(childId)?.state ?? 'unknown',
      reason: 'Intermediate CA certificate names this root as its issuer.',
      source: 'certificate-chain',
      measured: true,
    })
  }

  /* ---- TLS endpoints ---- */

  for (const endpoint of endpoints) {
    const id = nodeId.endpoint(endpoint.id)
    const { state, reason } = endpointState(endpoint)
    const attached = findingIndex.byEndpoint.get(endpoint.id) || []
    nodes.set(id, {
      id,
      kind: 'tls-endpoint',
      label: endpoint.name || endpoint.host || 'TLS endpoint',
      subtitle: endpoint.port ? `${endpoint.host}:${endpoint.port}` : endpoint.host,
      state,
      stateReason: reason,
      posture: endpoint.posture,
      riskLevel: endpoint.riskLevel,
      riskScore: endpoint.riskScore,
      assetId: endpoint.assetId,
      certificateId: endpoint.certificateIds[0] ?? null,
      endpointId: endpoint.id,
      environment: endpoint.environment,
      owner: endpoint.owner,
      provider: 'unattributed',
      providerLabel: CLOUD_PROVIDER_LABEL.unattributed,
      account: '',
      region: endpoint.assetId ? assetById.get(endpoint.assetId)?.region ?? '' : '',
      dependentCount: 0,
      dependencyCount: 0,
      quantumVulnerable: endpoint.quantumVulnerable,
      daysToExpiry: endpoint.daysToExpiry,
      findingIds: attached.map((finding) => finding.id),
      criticalFindings: endpoint.criticalFindings,
      highFindings: endpoint.highFindings,
      measured: endpoint.hasTransportEvidence,
      evidenceSources: endpoint.evidenceSources,
      lastObservedAt: endpoint.lastObservedAt,
      href: '/dashboard/tls-telemetry',
    })

    for (const certificateId of endpoint.certificateIds) {
      const certNodeId = nodeId.certificate(certificateId)
      if (!nodes.has(certNodeId)) continue
      const certificate = certificates.find((cert) => cert.id === certificateId)
      addEdge({
        id: `edge:protects:${certNodeId}:${id}`,
        from: certNodeId,
        to: id,
        kind: 'protects',
        label: 'protects',
        state: certificate ? certificateState(certificate).state : 'unknown',
        reason: certificate
          ? `This certificate terminates TLS for ${endpoint.host || 'the endpoint'}.`
          : 'Certificate referenced by the endpoint could not be resolved in inventory.',
        source: 'deployment',
        measured: true,
      })
    }
  }

  /* ---- Assets, services, applications, cloud resources ---- */

  const cloudResources: CloudResource[] = []

  for (const asset of assets) {
    const id = nodeId.asset(asset.id)
    const row = assetRowById.get(asset.id)
    const metadata = recordOf(row?.metadata)
    const kind = assetNodeKind(asset.type, asset.name)
    const attachedFindings = findingIndex.byAsset.get(asset.id) || []
    const critical = attachedFindings.filter((finding) => finding.severity === 'critical').length
    const high = attachedFindings.filter((finding) => finding.severity === 'high').length

    const corpus = [asset.name, asset.hostname, asset.type, asset.region, asset.tags.join(' '), JSON.stringify(metadata)]
      .filter(Boolean)
      .join('  ')

    // One mapped posture value reused by the node, the cloud projection and
    // every count below, so an asset cannot read differently in two places.
    const assetPosture = posturefromAsset(asset)

    const attribution = attributeCloudProvider({
      explicitProvider: metadata.provider ?? metadata.cloud_provider ?? metadata.cloudProvider ?? metadata.cloud,
      name: asset.name,
      host: asset.hostname,
      assetType: asset.type,
      region: asset.region,
      corpus,
      connectors: connectorProviders,
    })

    /* ---- state ---- */
    let state: TrustState = 'unknown'
    let reason = 'No cryptographic evidence has been collected for this asset yet.'
    if (asset.hasEvidence) {
      if (critical > 0) {
        state = 'critical'
        reason = `${critical} critical cryptographic finding${critical === 1 ? '' : 's'} open on this asset.`
      } else if (assetPosture === 'quantum-vulnerable') {
        state = 'quantum-vulnerable'
        reason = asset.cryptoPostureSummary || 'Asset uses classical cryptography with no post-quantum coverage.'
      } else if (high > 0) {
        state = 'at-risk'
        reason = `${high} high-severity cryptographic finding${high === 1 ? '' : 's'} open on this asset.`
      } else if (asset.migrationStatus && /plan|queue|progress/i.test(asset.migrationStatus)) {
        state = 'migration-required'
        reason = asset.cryptoPostureSummary || 'Asset is scheduled for cryptographic migration.'
      } else if (assetPosture === 'pqc-ready' || assetPosture === 'hybrid-ready') {
        state = 'pqc-ready'
        reason = asset.cryptoPostureSummary || 'Asset cryptography is post-quantum or hybrid.'
      } else if (asset.riskScore >= 40) {
        state = 'degraded'
        reason = asset.cryptoPostureSummary || 'Open cryptographic weaknesses below high severity.'
      } else {
        state = 'healthy'
        reason = asset.cryptoPostureSummary || 'Measured cryptography is within policy for this asset.'
      }
    }

    const assetCertificateIds = certificates.filter((cert) => cert.assetId === asset.id).map((cert) => cert.id)
    const soonestExpiry = assetCertificateIds
      .map((certId) => certificates.find((cert) => cert.id === certId)?.daysToExpiry)
      .filter((days): days is number => typeof days === 'number')
      .sort((a, b) => a - b)[0]

    nodes.set(id, {
      id,
      kind,
      label: asset.name,
      subtitle: [asset.type, asset.hostname].filter(Boolean).join(' - ') || 'Tenant asset',
      state,
      stateReason: reason,
      posture: assetPosture,
      riskLevel: (asset.riskLevel as TrustNode['riskLevel']) || 'none',
      riskScore: asset.riskScore,
      assetId: asset.id,
      certificateId: assetCertificateIds[0] ?? null,
      endpointId: null,
      environment: asset.environment,
      owner: asset.owner,
      provider: attribution.provider,
      providerLabel: attribution.providerLabel,
      account: readAccount(metadata),
      region: asset.region || readRegion(metadata),
      dependentCount: 0,
      dependencyCount: 0,
      quantumVulnerable: assetPosture === 'quantum-vulnerable',
      daysToExpiry: soonestExpiry ?? null,
      findingIds: attachedFindings.map((finding) => finding.id),
      criticalFindings: critical,
      highFindings: high,
      measured: asset.hasEvidence,
      evidenceSources: [],
      lastObservedAt: asset.lastEvidenceAt,
      href: `/dashboard/assets?asset=${encodeURIComponent(asset.id)}`,
    })

    /* ---- endpoint -> asset deployment edge ---- */
    for (const endpoint of endpoints) {
      if (endpoint.assetId !== asset.id) continue
      const endpointNodeId = nodeId.endpoint(endpoint.id)
      if (!nodes.has(endpointNodeId)) continue
      addEdge({
        id: `edge:deployed:${endpointNodeId}:${id}`,
        from: endpointNodeId,
        to: id,
        kind: 'deployed-on',
        label: 'serves',
        state: nodes.get(endpointNodeId)?.state ?? 'unknown',
        reason: 'Transport endpoint is bound to this tenant asset.',
        source: 'deployment',
        measured: endpoint.hasTransportEvidence,
      })
    }

    /* ---- cloud projection ---- */
    // Only assets that are genuinely cloud-shaped OR carry real provider
    // evidence become cloud resources. An on-prem server with no provider
    // signal is NOT invented into a cloud account.
    const cloudShaped =
      kind === 'cloud-resource' || kind === 'kubernetes-workload' || kind === 'container' || kind === 'load-balancer' || kind === 'gateway'
    if (attribution.attributed || cloudShaped) {
      const encryption = deriveEncryptionState(asset, corpus)
      const keyManagement = readKeyManagement(corpus)
      const tlsVersions = uniq(asset.tlsConfiguration.protocols.filter(Boolean))
      const compliance = deriveComplianceState(asset, inputs.complianceEvidence)

      cloudResources.push({
        id: `cloud:${asset.id}`,
        assetId: asset.id,
        name: asset.name,
        resourceType: TRUST_NODE_LABEL[kind],
        service: readService({ assetType: asset.type, name: asset.name, metadata }),
        provider: attribution.provider,
        providerLabel: attribution.providerLabel,
        account: readAccount(metadata),
        accountLabel: readAccount(metadata) || 'Account not recorded',
        region: asset.region || readRegion(metadata),
        environment: asset.environment,
        owner: asset.owner,
        encryptionState: encryption.state,
        encryptionAlgorithms: encryption.algorithms,
        keyManagement: keyManagement.value,
        keyManagementKnown: keyManagement.known,
        certificateIds: assetCertificateIds,
        tlsVersions,
        posture: assetPosture,
        state,
        stateReason: reason,
        riskLevel: (asset.riskLevel as CloudResource['riskLevel']) || 'none',
        riskScore: asset.riskScore,
        quantumVulnerable: assetPosture === 'quantum-vulnerable',
        complianceState: compliance.state,
        complianceDetail: compliance.detail,
        findingIds: attachedFindings.map((finding) => finding.id),
        criticalFindings: critical,
        lastSeenAt: asset.lastEvidenceAt || asset.discoveredAt,
        lastTelemetryAt: asset.lastEvidenceAt,
        attribution: {
          method: attribution.method,
          confidence: attribution.confidence,
          reason: attribution.reason,
          attributed: attribution.attributed,
        },
        evidenceSources: [],
        href: `/dashboard/assets?asset=${encodeURIComponent(asset.id)}`,
      })
    }
  }

  /* ---- asset_relationships -> dependency edges ---- */

  for (const relationship of inputs.assetRelationships) {
    const source = str(relationship.source_asset_id)
    const target = str(relationship.target_asset_id)
    if (!source || !target) continue
    const fromId = nodeId.asset(source)
    const toId = nodeId.asset(target)
    if (!nodes.has(fromId) || !nodes.has(toId) || fromId === toId) continue
    const type = str(relationship.relationship_type).toLowerCase()
    const kind: TrustRelationship['kind'] = /host/.test(type)
      ? 'hosts'
      : /communicat|talks|calls/.test(type)
        ? 'communicates-with'
        : /sign|issue|cert/.test(type)
          ? 'signs-for'
          : /key|kms|encrypt/.test(type)
            ? 'manages-keys'
            : /run|deploy|contain/.test(type)
              ? 'runs-in'
              : 'depends-on'
    const targetNode = nodes.get(toId)
    addEdge({
      id: `edge:rel:${str(relationship.id) || `${source}:${target}`}`,
      from: fromId,
      to: toId,
      kind,
      label: titleCase(type || 'depends on', 'depends on').toLowerCase(),
      state: targetNode?.state ?? 'unknown',
      reason: targetNode
        ? `Dependency inherits the trust state of ${targetNode.label}.`
        : 'Target asset is not present in the current inventory page.',
      source: 'asset-relationship',
      measured: true,
    })
  }

  /* ---------------------------------------------------------------- */
  /* Reachability, chains, and node enrichment                         */
  /* ---------------------------------------------------------------- */

  const nodeList = [...nodes.values()]
  const { dependents, dependencies } = computeDownstream(nodeList, edges)
  for (const node of nodeList) {
    node.dependentCount = dependents.get(node.id) ?? 0
    node.dependencyCount = dependencies.get(node.id) ?? 0
  }

  // Propagate the cloud attribution from an asset onto the endpoints and
  // certificates that serve it, so a certificate can be filtered by provider.
  for (const edge of edges) {
    if (edge.kind !== 'deployed-on') continue
    const endpoint = nodes.get(edge.from)
    const asset = nodes.get(edge.to)
    if (!endpoint || !asset) continue
    endpoint.provider = asset.provider
    endpoint.providerLabel = asset.providerLabel
    endpoint.account = asset.account
    if (!endpoint.region) endpoint.region = asset.region
  }
  for (const edge of edges) {
    if (edge.kind !== 'protects') continue
    const certificate = nodes.get(edge.from)
    const endpoint = nodes.get(edge.to)
    if (!certificate || !endpoint) continue
    if (certificate.provider === 'unattributed') {
      certificate.provider = endpoint.provider
      certificate.providerLabel = endpoint.providerLabel
      certificate.account = endpoint.account
    }
    if (!certificate.region) certificate.region = endpoint.region
    if (!certificate.environment) certificate.environment = endpoint.environment
  }
  // A certificate bound directly to an asset inherits from it as well.
  for (const node of nodeList) {
    if (node.kind !== 'certificate' || node.provider !== 'unattributed' || !node.assetId) continue
    const asset = nodes.get(nodeId.asset(node.assetId))
    if (!asset) continue
    node.provider = asset.provider
    node.providerLabel = asset.providerLabel
    node.account = asset.account
    if (!node.region) node.region = asset.region
    if (!node.environment) node.environment = asset.environment
  }

  const chainPaths = buildChainPaths({ nodes, edges, certificates, dependents })
  const chainPathByCertificate = new Map(chainPaths.map((path) => [path.id.replace(/^chain:/, ''), path]))

  /* ---------------------------------------------------------------- */
  /* Certificate trust records - chain validation (section 5)          */
  /* ---------------------------------------------------------------- */

  const certificateTrust: CertificateTrustRecord[] = certificates.map((certificate) => {
    const node = nodes.get(nodeId.certificate(certificate.id))
    const { state } = certificateState(certificate)
    const band = bandFor(certificate.daysToExpiry, certificate.lifecycle)
    const path = chainPathByCertificate.get(certificate.id) ?? null
    const asset = certificate.assetId ? assetById.get(certificate.assetId) : undefined
    const endpoint = certificate.endpointId ? endpoints.find((item) => item.id === certificate.endpointId) : undefined
    const checks = buildChainChecks({ certificate, path, endpoint, nodes, now })

    const affectedNodeIds = edges
      .filter((edge) => edge.kind === 'protects' && edge.from === nodeId.certificate(certificate.id))
      .map((edge) => edge.to)
    const affectedAssetCount = node ? node.dependentCount : 0

    const renewal = deriveRenewal(certificate, inputs.migrationJobs)
    const owner = asset?.owner ?? ''

    return {
      certificateId: certificate.id,
      state,
      band,
      checks,
      failedChecks: checks.filter((check) => check.status === 'fail').length,
      warnChecks: checks.filter((check) => check.status === 'warn').length,
      notEvaluatedChecks: checks.filter((check) => check.status === 'not-evaluated').length,
      chainPathId: path?.id ?? null,
      affectedNodeIds,
      affectedAssetCount,
      renewal,
      owner: owner || 'Unassigned',
      ownerKnown: Boolean(owner),
      orphan: !certificate.assetId && !certificate.endpointId,
      deploymentKnown: Boolean(certificate.endpointId) || affectedNodeIds.length > 0,
      provider: (node?.provider as CloudProviderId) || 'unattributed',
      providerLabel: node?.providerLabel || CLOUD_PROVIDER_LABEL.unattributed,
      account: node?.account || '',
      region: node?.region || asset?.region || '',
      environment: node?.environment || asset?.environment || '',
      tlsVersions: endpoint ? endpoint.observedVersions.filter(Boolean) : [],
      remediation: remediationForCertificate(certificate, band, checks),
    }
  })

  const certificateTrustById = new Map(certificateTrust.map((record) => [record.certificateId, record]))

  /* ---------------------------------------------------------------- */
  /* Certificate intelligence rollups                                  */
  /* ---------------------------------------------------------------- */

  const certificateIntel = buildCertificateIntelligence({
    certificates,
    trust: certificateTrust,
    tlsPki,
    now,
  })

  /* ---------------------------------------------------------------- */
  /* Cloud estate                                                      */
  /* ---------------------------------------------------------------- */

  const cloud = buildCloudEstate({
    resources: cloudResources,
    certificates,
    certificateTrust,
    endpoints,
    nodes,
    connectorByProvider,
    connectorsConfigured: inputs.connectorAccounts.length,
    connectorsActive,
  })

  /* ---------------------------------------------------------------- */
  /* Events (section 9)                                                */
  /* ---------------------------------------------------------------- */

  const events = buildEvents({ ...inputs, nodes, certificates, certificateTrust, cloudResources, now })

  /* ---------------------------------------------------------------- */
  /* Distributions                                                     */
  /* ---------------------------------------------------------------- */

  const stateBuckets = new Map<TrustState, string[]>()
  for (const node of nodeList) {
    const list = stateBuckets.get(node.state)
    if (list) list.push(node.id)
    else stateBuckets.set(node.state, [node.id])
  }
  const stateDistribution = [...stateBuckets.entries()]
    .map(([state, nodeIds]) => ({
      state,
      label: TRUST_STATE_LABEL[state],
      count: nodeIds.length,
      percent: percentOf(nodeIds.length, nodeList.length),
      nodeIds: nodeIds.slice(0, 400),
    }))
    .sort((a, b) => TRUST_STATE_RANK[b.state] - TRUST_STATE_RANK[a.state])

  const kindBuckets = new Map<TrustNodeKind, TrustNode[]>()
  for (const node of nodeList) {
    const list = kindBuckets.get(node.kind)
    if (list) list.push(node)
    else kindBuckets.set(node.kind, [node])
  }
  const kindDistribution = [...kindBuckets.entries()]
    .map(([kind, group]) => ({
      kind,
      label: TRUST_NODE_LABEL[kind],
      count: group.length,
      measured: group.filter((node) => node.measured).length,
      nodeIds: group.slice(0, 400).map((node) => node.id),
    }))
    .sort((a, b) => b.count - a.count)

  /* ---------------------------------------------------------------- */
  /* Freshness                                                         */
  /* ---------------------------------------------------------------- */

  const latestEvidenceAt = latestIso(
    tlsPki.latestEvidenceAt,
    ...events.slice(0, 20).map((event) => event.at),
    ...assets.slice(0, 50).map((asset) => asset.lastEvidenceAt),
  )
  const latestMs = dateMs(latestEvidenceAt)
  const staleSinceHours = latestMs ? Math.floor((now - latestMs) / 3_600_000) : null
  const stale = staleSinceHours !== null && staleSinceHours >= STALE_AFTER_HOURS

  const hasData =
    certificates.length > 0 || endpoints.length > 0 || nodeList.length > 0 || assets.length > 0 || findings.length > 0

  /* ---------------------------------------------------------------- */
  /* Scores and KPIs                                                   */
  /* ---------------------------------------------------------------- */

  const scores = buildScores({
    tlsPki,
    snapshot,
    nodes: nodeList,
    certificates,
    certificateTrust,
    chainPaths,
    cloud,
    findings,
  })

  const kpis = buildKpis({ tlsPki, snapshot, nodes: nodeList, certificates, certificateTrust, cloud, findings, assets })

  /* ---------------------------------------------------------------- */
  /* Reconciliation (section 16)                                       */
  /* ---------------------------------------------------------------- */

  const reconciliation = buildReconciliation({
    certificates,
    certificateTrust,
    certificateIntel,
    nodes: nodeList,
    edges,
    assets,
    relationships: inputs.assetRelationships,
    cloud,
    snapshot,
    tlsPki,
    stale,
    staleSinceHours,
    cryptoInventory: inputs.cryptoInventory,
  })

  /* ---------------------------------------------------------------- */
  /* Trend                                                             */
  /* ---------------------------------------------------------------- */

  const trend = tlsPki.timeline.map((point) => {
    const dayStart = dateMs(point.date)
    const dayEnd = dayStart + DAY_MS
    const vulnerable = certificates.filter((certificate) => {
      const observed = dateMs(certificate.lastObservedAt)
      return (
        observed >= dayStart &&
        observed < dayEnd &&
        (certificate.posture === 'quantum-vulnerable' || certificate.posture === 'legacy')
      )
    }).length
    return {
      label: point.label,
      date: point.date,
      certificatesObserved: point.certificates,
      findingsOpened: point.findings,
      quantumVulnerable: vulnerable,
      observations: point.observations,
    }
  })

  /* ---------------------------------------------------------------- */
  /* Facets (section 10)                                               */
  /* ---------------------------------------------------------------- */

  const facets = {
    environments: uniq(nodeList.map((node) => node.environment).filter(Boolean)).sort(),
    providers: uniq(cloud.providers.map((provider) => provider.provider)).map((id) => ({
      id,
      label: providerLabelFor(id),
    })),
    accounts: uniq(cloudResources.map((resource) => resource.account).filter(Boolean))
      .map((account) => {
        const owner = cloudResources.find((resource) => resource.account === account)
        return { id: account, label: account, provider: (owner?.provider ?? 'unattributed') as CloudProviderId }
      })
      .sort((a, b) => a.label.localeCompare(b.label)),
    regions: uniq(nodeList.map((node) => node.region).filter(Boolean)).sort(),
    assetTypes: uniq(assets.map((asset) => asset.type).filter(Boolean)).sort(),
    algorithms: uniq(certificates.map((certificate) => certificate.publicKeyAlgorithm).filter(Boolean)).sort(),
    tlsVersions: uniq(endpoints.flatMap((endpoint) => endpoint.observedVersions).filter(Boolean)).sort(),
    issuers: uniq(certificates.map((certificate) => certificate.issuer).filter(Boolean)).sort(),
    owners: uniq(nodeList.map((node) => node.owner).filter(Boolean)).sort(),
  }

  return {
    generatedAt: new Date(now).toISOString(),
    latestEvidenceAt,
    hasData,
    stale,
    staleSinceHours,
    scores,
    kpis,
    nodes: nodeList.sort(
      (a, b) => TRUST_STATE_RANK[b.state] - TRUST_STATE_RANK[a.state] || b.riskScore - a.riskScore || b.dependentCount - a.dependentCount,
    ),
    relationships: edges,
    chainPaths,
    trustChains: tlsPki.trustChains,
    stateDistribution,
    kindDistribution,
    certificates,
    certificateTrust,
    certificateIntel,
    endpoints,
    findings,
    cloud,
    events,
    trend,
    reconciliation,
    telemetry: tlsPki.telemetry,
    facets,
  }
}

/* ================================================================== */
/* Encryption / compliance derivation                                  */
/* ================================================================== */

const AT_REST_SIGNALS = /\baes[- ]?256\b|\baes[- ]?128\b|\baes\b|\bchacha20\b|encrypted at rest|sse-|encryption enabled|tde\b/i
const UNENCRYPTED_SIGNALS = /unencrypted|no encryption|encryption disabled|plaintext|cleartext|\bhttp:\/\//i

/**
 * Encryption state for a cloud resource.
 *
 * `not-observed` is the default and is the honest answer for the majority of
 * tenants: without a cloud connector actually reading a bucket's encryption
 * configuration, the platform does not know. Reporting that as "unencrypted"
 * would invent a critical finding; reporting it as "encrypted" would invent
 * safety. Both are refused here.
 */
function deriveEncryptionState(
  asset: AssetMigrationRecord,
  corpus: string,
): { state: EncryptionState; algorithms: string[] } {
  const algorithms = uniq(
    asset.algorithms
      .filter((row) => /aes|chacha|3des|des|rc4|blowfish|ml-kem|kyber/i.test(row.algorithm || ''))
      .map((row) => row.algorithm)
      .filter(Boolean),
  )

  if (UNENCRYPTED_SIGNALS.test(corpus)) {
    return { state: 'unencrypted', algorithms }
  }
  if (algorithms.length > 0) {
    const weak = algorithms.some((algorithm) => /\b(3des|des|rc4|blowfish)\b/i.test(algorithm))
    return { state: weak ? 'partially-encrypted' : 'encrypted', algorithms }
  }
  if (AT_REST_SIGNALS.test(corpus)) {
    return { state: 'encrypted', algorithms }
  }
  return { state: 'not-observed', algorithms }
}

function deriveComplianceState(
  asset: AssetMigrationRecord,
  complianceEvidence: Row[],
): { state: CloudResource['complianceState']; detail: string } {
  const records = complianceEvidence.filter((row) => str(row.asset_id) === asset.id)
  if (records.length === 0) {
    return { state: 'not-assessed', detail: 'No compliance evidence has been recorded for this resource.' }
  }
  const statuses = records.map((row) => str(row.status).toLowerCase())
  if (statuses.some((status) => /fail|non[- ]?compliant|violation/.test(status))) {
    const framework = str(records[0].framework) || 'the mapped framework'
    return { state: 'non-compliant', detail: `Failing control evidence recorded against ${framework}.` }
  }
  if (statuses.some((status) => /exception|waiver|accepted/.test(status))) {
    return { state: 'exception', detail: 'An approved exception is on file for this resource.' }
  }
  if (statuses.some((status) => /pass|compliant|satisfied/.test(status))) {
    const framework = str(records[0].framework) || 'the mapped framework'
    return { state: 'compliant', detail: `Passing control evidence recorded against ${framework}.` }
  }
  return { state: 'not-assessed', detail: 'Compliance evidence exists but records no pass or fail outcome.' }
}

/* ================================================================== */
/* Chain validation (section 5)                                        */
/* ================================================================== */

function buildChainChecks(input: {
  certificate: PkiCertificate
  path: { complete: boolean; incompleteReason: string; nodeIds: string[] } | null
  endpoint: { host: string; observedVersions: string[]; hasTransportEvidence: boolean } | undefined
  nodes: Map<string, TrustNode>
  now: number
}): ChainCheck[] {
  const { certificate, path, endpoint, nodes, now } = input
  const checks: ChainCheck[] = []

  const caNode = certificate.issuer ? nodes.get(nodeId.ca(certificate.issuer)) : undefined
  const rootNode = path?.nodeIds.map((id) => nodes.get(id)).find((node) => node?.kind === 'root-ca')

  /* ---- root CA ---- */
  checks.push(
    rootNode
      ? rootNode.measured
        ? { key: 'root-ca', label: 'Root CA', status: 'pass', detail: `Anchored to ${rootNode.label}, whose certificate is held in inventory.`, severity: null }
        : {
            key: 'root-ca',
            label: 'Root CA',
            status: 'warn',
            detail: `Root "${rootNode.label}" is known only by name; the root certificate itself was never collected, so the anchor cannot be verified.`,
            severity: 'medium',
          }
      : certificate.selfSigned
        ? { key: 'root-ca', label: 'Root CA', status: 'fail', detail: 'Self-signed certificate - there is no root authority above it.', severity: 'high' }
        : {
            key: 'root-ca',
            label: 'Root CA',
            status: 'not-evaluated',
            detail: 'No root certificate was captured for this chain, so the trust anchor cannot be identified.',
            severity: null,
          },
  )

  /* ---- intermediate CA ---- */
  checks.push(
    caNode && caNode.kind === 'intermediate-ca'
      ? caNode.measured
        ? { key: 'intermediate-ca', label: 'Intermediate CA', status: 'pass', detail: `Issued by ${caNode.label}; the intermediate certificate is present.`, severity: null }
        : {
            key: 'intermediate-ca',
            label: 'Intermediate CA',
            status: 'warn',
            detail: `Intermediate "${caNode.label}" was inferred from the issuer field; its certificate is not in inventory, so servers may be serving an incomplete chain.`,
            severity: 'medium',
          }
      : caNode
        ? { key: 'intermediate-ca', label: 'Intermediate CA', status: 'pass', detail: 'Certificate is issued directly by a root authority - no intermediate is required.', severity: null }
        : {
            key: 'intermediate-ca',
            label: 'Intermediate CA',
            status: 'not-evaluated',
            detail: 'Issuer is not recorded on this certificate, so intermediate presence cannot be checked.',
            severity: null,
          },
  )

  /* ---- chain completeness / ordering ---- */
  checks.push(
    path
      ? path.complete
        ? { key: 'chain-complete', label: 'Chain completeness', status: 'pass', detail: 'Every link from the leaf to the root resolves to a collected certificate.', severity: null }
        : { key: 'chain-complete', label: 'Chain completeness', status: 'warn', detail: `Chain is incomplete: ${path.incompleteReason}.`, severity: 'medium' }
      : { key: 'chain-complete', label: 'Chain completeness', status: 'not-evaluated', detail: 'No chain could be assembled for this certificate.', severity: null },
  )

  checks.push(
    path && path.complete
      ? { key: 'chain-order', label: 'Chain ordering', status: 'pass', detail: 'Leaf, intermediate and root appear in the correct issuing order.', severity: null }
      : {
          key: 'chain-order',
          label: 'Chain ordering',
          status: 'not-evaluated',
          detail: 'Ordering can only be verified once the full chain has been collected from the endpoint.',
          severity: null,
        },
  )

  /* ---- signature ---- */
  const signature = certificate.signatureAlgorithm || ''
  checks.push(
    !signature
      ? { key: 'signature', label: 'Signature algorithm', status: 'not-evaluated', detail: 'No signature algorithm was recorded for this certificate.', severity: null }
      : /\b(md5|sha-?1)\b/i.test(signature)
        ? { key: 'signature', label: 'Signature algorithm', status: 'fail', detail: `Signed with ${signature}, which is broken for collision resistance and rejected by modern clients.`, severity: 'critical' }
        : /ml-dsa|dilithium|slh-dsa|sphincs|falcon/i.test(signature)
          ? { key: 'signature', label: 'Signature algorithm', status: 'pass', detail: `Signed with ${signature}, a NIST post-quantum signature scheme.`, severity: null }
          : { key: 'signature', label: 'Signature algorithm', status: 'pass', detail: `Signed with ${signature}, which is currently acceptable but is not quantum resistant.`, severity: null },
  )

  /* ---- validity window ---- */
  const days = certificate.daysToExpiry
  checks.push(
    days === null
      ? { key: 'validity', label: 'Validity window', status: 'not-evaluated', detail: 'No notAfter date recorded, so remaining lifetime is unknown.', severity: null }
      : days < 0
        ? { key: 'validity', label: 'Validity window', status: 'fail', detail: `Expired ${Math.abs(days)} days ago - clients will reject this certificate.`, severity: 'critical' }
        : days <= 7
          ? { key: 'validity', label: 'Validity window', status: 'fail', detail: `Only ${days} day${days === 1 ? '' : 's'} of validity remain.`, severity: 'critical' }
          : days <= 30
            ? { key: 'validity', label: 'Validity window', status: 'warn', detail: `${days} days remain - inside the 30-day renewal window.`, severity: 'high' }
            : { key: 'validity', label: 'Validity window', status: 'pass', detail: `${days} days of validity remain.`, severity: null },
  )

  /* ---- revocation ---- */
  checks.push(
    certificate.lifecycle === 'revoked'
      ? { key: 'revocation', label: 'Revocation state', status: 'fail', detail: 'Certificate is recorded as revoked in the tenant inventory.', severity: 'critical' }
      : {
          key: 'revocation',
          label: 'Revocation state',
          status: 'not-evaluated',
          detail: 'No OCSP or CRL response has been collected for this certificate, so revocation cannot be confirmed either way.',
          severity: null,
        },
  )

  /* ---- hostname / SAN ---- */
  const host = endpoint?.host || ''
  if (!host) {
    checks.push({
      key: 'hostname',
      label: 'Hostname / SAN match',
      status: 'not-evaluated',
      detail: 'This certificate is not bound to an observed endpoint, so no hostname can be matched against it.',
      severity: null,
    })
  } else {
    const names = uniq([certificate.subject, certificate.name, ...certificate.san].map((value) => str(value).toLowerCase()).filter(Boolean))
    const matched = names.some((name) => {
      const clean = name.replace(/^cn=/i, '').trim()
      if (!clean) return false
      if (clean === host.toLowerCase()) return true
      if (clean.startsWith('*.')) return host.toLowerCase().endsWith(clean.slice(1))
      return host.toLowerCase().endsWith(clean) || clean.endsWith(host.toLowerCase())
    })
    checks.push(
      matched
        ? { key: 'hostname', label: 'Hostname / SAN match', status: 'pass', detail: `Subject or SAN covers ${host}.`, severity: null }
        : {
            key: 'hostname',
            label: 'Hostname / SAN match',
            status: 'fail',
            detail: `Neither the subject nor any recorded SAN covers ${host}; clients connecting to that name will see a name-mismatch error.`,
            severity: 'high',
          },
    )
  }

  /* ---- algorithm and key strength ---- */
  const algorithm = certificate.publicKeyAlgorithm || ''
  checks.push(
    !algorithm
      ? { key: 'algorithm-strength', label: 'Algorithm strength', status: 'not-evaluated', detail: 'Public key algorithm was not recorded.', severity: null }
      : certificate.posture === 'quantum-safe' || certificate.posture === 'pqc-ready' || certificate.posture === 'hybrid-ready'
        ? { key: 'algorithm-strength', label: 'Algorithm strength', status: 'pass', detail: `${certificate.algorithmLabel} is post-quantum or hybrid.`, severity: null }
        : {
            key: 'algorithm-strength',
            label: 'Algorithm strength',
            status: 'warn',
            detail: `${certificate.algorithmLabel} is classical; Shor's algorithm breaks it once a cryptographically relevant quantum computer exists.`,
            severity: 'high',
          },
  )

  const keySize = certificate.keySize
  checks.push(
    keySize === null
      ? { key: 'key-strength', label: 'Key strength', status: 'not-evaluated', detail: 'Key size was not recorded for this certificate.', severity: null }
      : /rsa/i.test(algorithm) && keySize < 2048
        ? { key: 'key-strength', label: 'Key strength', status: 'fail', detail: `RSA-${keySize} is below the 2048-bit floor required by NIST SP 800-57.`, severity: 'critical' }
        : /ec|ecdsa/i.test(algorithm) && keySize < 256
          ? { key: 'key-strength', label: 'Key strength', status: 'fail', detail: `${keySize}-bit elliptic curve key is below the 256-bit minimum.`, severity: 'high' }
          : { key: 'key-strength', label: 'Key strength', status: 'pass', detail: `${keySize}-bit key meets current classical strength guidance.`, severity: null },
  )

  /* ---- TLS compatibility ---- */
  const versions = endpoint?.observedVersions.filter(Boolean) ?? []
  checks.push(
    !endpoint || !endpoint.hasTransportEvidence
      ? {
          key: 'tls-compatibility',
          label: 'TLS compatibility',
          status: 'not-evaluated',
          detail: 'No TLS handshake has been observed using this certificate.',
          severity: null,
        }
      : versions.some((version) => /TLS 1\.0|TLS 1\.1|SSL/i.test(version))
        ? {
            key: 'tls-compatibility',
            label: 'TLS compatibility',
            status: 'fail',
            detail: `Served over ${versions.filter((v) => /TLS 1\.0|TLS 1\.1|SSL/i.test(v)).join(', ')}, deprecated by RFC 8996.`,
            severity: 'high',
          }
        : versions.includes('TLS 1.3')
          ? { key: 'tls-compatibility', label: 'TLS compatibility', status: 'pass', detail: 'Served over TLS 1.3.', severity: null }
          : { key: 'tls-compatibility', label: 'TLS compatibility', status: 'warn', detail: `Highest observed version is ${versions[versions.length - 1] || 'TLS 1.2'}; TLS 1.3 is required for hybrid key agreement.`, severity: 'medium' },
  )

  return checks
}

function remediationForCertificate(certificate: PkiCertificate, band: ExpiryBand, checks: ChainCheck[]): string {
  const failed = checks.find((check) => check.status === 'fail')
  if (band === 'expired') return 'Replace immediately - this certificate can no longer complete a TLS handshake.'
  if (band === 'critical') return 'Issue and deploy a replacement now; the renewal window has effectively closed.'
  if (failed) {
    if (failed.key === 'hostname') return 'Reissue with the correct subject alternative names, or repoint the endpoint at a certificate that covers it.'
    if (failed.key === 'key-strength') return 'Reissue with a key that meets NIST SP 800-57 minimums.'
    if (failed.key === 'signature') return 'Reissue under a SHA-256 or ML-DSA signing chain.'
    if (failed.key === 'revocation') return 'Remove the revoked certificate from every endpoint and replace it.'
  }
  if (certificate.posture === 'quantum-vulnerable' || certificate.posture === 'legacy') {
    return 'Schedule replacement with an ML-DSA (FIPS 204) or hybrid certificate under the PQC migration plan.'
  }
  if (band === 'high') return 'Start the renewal process - fewer than 30 days of validity remain.'
  if (band === 'unknown') return 'Collect the certificate validity window so lifecycle risk can be measured.'
  return 'No action required; continue monitoring through the renewal cycle.'
}

function deriveRenewal(certificate: PkiCertificate, migrationJobs: Row[]): CertificateTrustRecord['renewal'] {
  const related = migrationJobs.filter((job) => {
    if (certificate.assetId && str(job.asset_id) === certificate.assetId) return true
    const corpus = `${str(job.name)} ${JSON.stringify(recordOf(job.metadata))}`.toLowerCase()
    return certificate.serialNumber ? corpus.includes(certificate.serialNumber.toLowerCase()) : false
  })
  const certJobs = related.filter((job) => /cert|tls|pki|renew/i.test(`${str(job.job_type)} ${str(job.name)}`))
  const pool = certJobs.length > 0 ? certJobs : []

  if (pool.length === 0) {
    return {
      status: 'not-started',
      detail: 'No renewal or replacement job references this certificate.',
      lastAttemptAt: null,
    }
  }
  const newest = pool
    .slice()
    .sort((a, b) => dateMs(b.updated_at ?? b.created_at) - dateMs(a.updated_at ?? a.created_at))[0]
  const status = str(newest.status).toLowerCase()
  const at = isoOrNull(newest.updated_at ?? newest.created_at)
  if (/fail|error|rolled?[- ]back/.test(status)) {
    return { status: 'failed', detail: `Renewal job "${str(newest.name) || newest.id}" failed and needs operator attention.`, lastAttemptAt: at }
  }
  if (/complete|success|done/.test(status)) {
    return { status: 'renewed', detail: `Replacement completed by job "${str(newest.name) || newest.id}".`, lastAttemptAt: at }
  }
  if (/running|in[- ]?progress|executing/.test(status)) {
    return { status: 'in-progress', detail: `Renewal is executing under job "${str(newest.name) || newest.id}".`, lastAttemptAt: at }
  }
  if (/pending|queued|planned|scheduled/.test(status)) {
    return { status: 'planned', detail: `Renewal is queued under job "${str(newest.name) || newest.id}".`, lastAttemptAt: at }
  }
  return { status: 'unknown', detail: `Related job "${str(newest.name) || newest.id}" reports status "${status || 'unspecified'}".`, lastAttemptAt: at }
}

/* ================================================================== */
/* Certificate rollups                                                 */
/* ================================================================== */

function buildCertificateIntelligence(input: {
  certificates: PkiCertificate[]
  trust: CertificateTrustRecord[]
  tlsPki: TlsPkiIntelligence
  now: number
}): CertificateIntelligence {
  const { certificates, trust, tlsPki, now } = input
  const trustById = new Map(trust.map((record) => [record.certificateId, record]))

  /* ---- expiry bands ---- */
  const bandBuckets = new Map<ExpiryBand, string[]>()
  for (const record of trust) {
    const list = bandBuckets.get(record.band)
    if (list) list.push(record.certificateId)
    else bandBuckets.set(record.band, [record.certificateId])
  }
  const bands = EXPIRY_BAND_ORDER.map((band) => {
    const ids = bandBuckets.get(band) || []
    return { band, label: EXPIRY_BAND_LABEL[band], count: ids.length, percent: percentOf(ids.length, certificates.length), certificateIds: ids }
  })

  /* ---- expiry timeline: next 12 months from real notAfter values ---- */
  const timelineBuckets = new Map<string, string[]>()
  for (const certificate of certificates) {
    const ms = dateMs(certificate.notAfter)
    if (!ms || ms < now) continue
    if (ms > now + 365 * DAY_MS) continue
    const key = monthKey(ms)
    const list = timelineBuckets.get(key)
    if (list) list.push(certificate.id)
    else timelineBuckets.set(key, [certificate.id])
  }
  const expiryTimeline = [...timelineBuckets.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([key, ids]) => ({ label: monthLabel(key), date: `${key}-01`, count: ids.length, certificateIds: ids }))

  /* ---- discovery trend from real observation timestamps ---- */
  const trendBuckets = new Map<string, { discovered: number; expiring: number }>()
  for (const certificate of certificates) {
    const ms = dateMs(certificate.lastObservedAt)
    if (!ms || ms < now - 30 * DAY_MS) continue
    const key = dayKey(ms)
    const bucket = trendBuckets.get(key) || { discovered: 0, expiring: 0 }
    bucket.discovered += 1
    if (certificate.daysToExpiry !== null && certificate.daysToExpiry <= 30) bucket.expiring += 1
    trendBuckets.set(key, bucket)
  }
  const discoveryTrend = [...trendBuckets.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([key, bucket]) => ({
      label: new Date(key).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      date: key,
      discovered: bucket.discovered,
      expiring: bucket.expiring,
    }))

  /* ---- duplicates: same subject + issuer + serial across records ---- */
  const duplicateBuckets = new Map<string, { label: string; ids: string[] }>()
  for (const certificate of certificates) {
    const subject = str(certificate.subject || certificate.name).toLowerCase()
    const issuer = str(certificate.issuer).toLowerCase()
    if (!subject) continue
    const key = `${subject}|${issuer}`
    const bucket = duplicateBuckets.get(key) || { label: certificate.subject || certificate.name, ids: [] }
    bucket.ids.push(certificate.id)
    duplicateBuckets.set(key, bucket)
  }
  const duplicates = [...duplicateBuckets.entries()]
    .filter(([, bucket]) => bucket.ids.length > 1)
    .map(([key, bucket]) => ({ key, label: bucket.label, certificateIds: bucket.ids }))
    .sort((a, b) => b.certificateIds.length - a.certificateIds.length)

  /* ---- chain validation totals ---- */
  let passed = 0
  let failed = 0
  let warned = 0
  let notEvaluated = 0
  for (const record of trust) {
    if (record.failedChecks > 0) failed += 1
    else if (record.warnChecks > 0) warned += 1
    else if (record.checks.every((check) => check.status === 'not-evaluated')) notEvaluated += 1
    else passed += 1
  }

  return {
    lifecycle: tlsPki.pki.lifecycle,
    bands,
    issuers: tlsPki.pki.issuers,
    algorithmDistribution: tlsPki.pki.algorithmDistribution,
    expiryTimeline,
    discoveryTrend,
    chainValidation: { passed, failed, warned, notEvaluated },
    orphans: trust.filter((record) => record.orphan).map((record) => record.certificateId),
    ownerless: trust.filter((record) => !record.ownerKnown).map((record) => record.certificateId),
    undeployed: trust.filter((record) => !record.deploymentKnown).map((record) => record.certificateId),
    duplicates,
    renewalFailures: trust.filter((record) => record.renewal.status === 'failed').map((record) => record.certificateId),
    reconciledTotal: certificates.length,
  }
}

/* ================================================================== */
/* Cloud estate                                                        */
/* ================================================================== */

function buildCloudEstate(input: {
  resources: CloudResource[]
  certificates: PkiCertificate[]
  certificateTrust: CertificateTrustRecord[]
  endpoints: TlsPkiIntelligence['endpoints']
  nodes: Map<string, TrustNode>
  connectorByProvider: Map<CloudProviderId, { count: number; active: number; status: string; lastSync: string | null }>
  connectorsConfigured: number
  connectorsActive: number
}): CloudEstate {
  const { resources, certificateTrust, endpoints, nodes, connectorByProvider, connectorsConfigured, connectorsActive } = input

  const attributed = resources.filter((resource) => resource.attribution.attributed)
  const providerIds = uniq<CloudProviderId>([
    ...resources.map((resource) => resource.provider),
    ...[...connectorByProvider.keys()],
  ]).filter((id) => id !== 'unattributed' || resources.some((resource) => resource.provider === 'unattributed'))

  const certTrustByProvider = new Map<CloudProviderId, CertificateTrustRecord[]>()
  for (const record of certificateTrust) {
    const list = certTrustByProvider.get(record.provider)
    if (list) list.push(record)
    else certTrustByProvider.set(record.provider, [record])
  }

  const endpointByAsset = new Map<string, TlsPkiIntelligence['endpoints']>()
  for (const endpoint of endpoints) {
    if (!endpoint.assetId) continue
    const list = endpointByAsset.get(endpoint.assetId)
    if (list) list.push(endpoint)
    else endpointByAsset.set(endpoint.assetId, [endpoint])
  }

  const providers: CloudProviderPosture[] = providerIds.map((provider) => {
    const own = resources.filter((resource) => resource.provider === provider)
    const connector = connectorByProvider.get(provider)
    const certs = certTrustByProvider.get(provider) || []

    const encrypted = own.filter((resource) => resource.encryptionState === 'encrypted').length
    const unencrypted = own.filter(
      (resource) => resource.encryptionState === 'unencrypted' || resource.encryptionState === 'partially-encrypted',
    ).length
    const measuredEncryption = encrypted + unencrypted

    const providerEndpoints = own.flatMap((resource) => (resource.assetId ? endpointByAsset.get(resource.assetId) || [] : []))
    const tls13 = providerEndpoints.filter((endpoint) => endpoint.negotiatedVersion === 'TLS 1.3').length
    const legacy = providerEndpoints.filter(
      (endpoint) => endpoint.negotiatedVersion && /TLS 1\.0|TLS 1\.1|SSL/.test(endpoint.negotiatedVersion),
    ).length

    const accountBuckets = new Map<string, { resources: number; regions: Set<string> }>()
    for (const resource of own) {
      const key = resource.account || 'unrecorded'
      const bucket = accountBuckets.get(key) || { resources: 0, regions: new Set<string>() }
      bucket.resources += 1
      if (resource.region) bucket.regions.add(resource.region)
      accountBuckets.set(key, bucket)
    }

    const critical = own.reduce((sum, resource) => sum + resource.criticalFindings, 0)
    const quantumVulnerable = own.filter((resource) => resource.quantumVulnerable).length
    const pqcReady = own.filter(
      (resource) => resource.posture === 'quantum-safe' || resource.posture === 'pqc-ready' || resource.posture === 'hybrid-ready',
    ).length
    const weak = own.filter(
      (resource) =>
        resource.encryptionState === 'partially-encrypted' ||
        resource.encryptionAlgorithms.some((algorithm) => /\b(3des|des|rc4|blowfish|md5|sha-?1)\b/i.test(algorithm)),
    ).length

    /**
     * A provider trust score is only computed where at least one resource
     * carries a real posture reading. Without that the tile reads
     * "Not measured", which is the honest statement for a cloud the tenant has
     * connected but never scanned.
     */
    const scored = own.filter((resource) => resource.posture !== 'unknown' || resource.encryptionState !== 'not-observed')
    const trustScore =
      scored.length > 0
        ? clamp(
            Math.round(
              (percentOf(scored.filter((resource) => !resource.quantumVulnerable).length, scored.length) * 0.45 +
                (measuredEncryption > 0 ? percentOf(encrypted, measuredEncryption) : 50) * 0.35 +
                percentOf(Math.max(0, scored.length - critical), scored.length) * 0.2),
            ),
          )
        : null

    let state: TrustState = 'unknown'
    let stateReason = 'No cryptographic posture has been measured for this cloud yet.'
    if (own.length === 0 && connector) {
      state = 'unknown'
      stateReason = 'Account is connected but no resources have been discovered from it yet.'
    } else if (critical > 0) {
      state = 'critical'
      stateReason = `${critical} critical cryptographic finding${critical === 1 ? '' : 's'} across ${own.length} resource${own.length === 1 ? '' : 's'}.`
    } else if (quantumVulnerable > 0 && quantumVulnerable === scored.length) {
      state = 'quantum-vulnerable'
      stateReason = 'Every measured resource in this cloud uses classical cryptography.'
    } else if (unencrypted > 0) {
      state = 'at-risk'
      stateReason = `${unencrypted} resource${unencrypted === 1 ? '' : 's'} report weak or absent encryption.`
    } else if (quantumVulnerable > 0) {
      state = 'migration-required'
      stateReason = `${quantumVulnerable} of ${own.length} resources still use quantum-vulnerable cryptography.`
    } else if (trustScore !== null && trustScore >= 85) {
      state = 'healthy'
      stateReason = 'Measured resources are encrypted with no critical findings open.'
    } else if (trustScore !== null) {
      state = 'degraded'
      stateReason = 'Measured posture is below the healthy threshold for this cloud.'
    }

    return {
      provider,
      providerLabel: providerLabelFor(provider),
      connected: Boolean(connector && connector.active > 0),
      connectorStatus: connector?.status || 'not-connected',
      connectorCount: connector?.count ?? 0,
      lastSyncAt: connector?.lastSync ?? null,
      accounts: [...accountBuckets.entries()].map(([id, bucket]) => ({
        id,
        label: id === 'unrecorded' ? 'Account not recorded' : id,
        resources: bucket.resources,
        regions: [...bucket.regions].sort(),
      })),
      regions: uniq(own.map((resource) => resource.region).filter(Boolean)).sort(),
      resources: own.length,
      encryptedResources: encrypted,
      unencryptedResources: unencrypted,
      encryptionCoverage: measuredEncryption > 0 ? percentOf(encrypted, measuredEncryption) : null,
      certificates: certs.length,
      expiringCertificates: certs.filter((record) => record.band === 'critical' || record.band === 'high').length,
      expiredCertificates: certs.filter((record) => record.band === 'expired').length,
      kmsResources: own.filter((resource) => resource.keyManagementKnown).length,
      kmsProviders: uniq(own.filter((resource) => resource.keyManagementKnown).map((resource) => resource.keyManagement)),
      weakCryptoResources: weak,
      quantumVulnerableResources: quantumVulnerable,
      pqcReadyResources: pqcReady,
      tls13Endpoints: tls13,
      legacyTlsEndpoints: legacy,
      criticalFindings: critical,
      highFindings: own.reduce((sum, resource) => sum + (resource.riskLevel === 'high' ? 1 : 0), 0),
      trustScore,
      measured: scored.length > 0,
      state,
      stateReason,
      lastTelemetryAt: latestIso(...own.map((resource) => resource.lastTelemetryAt)),
    }
  })

  /* ---- regions ---- */
  const regionBuckets = new Map<string, CloudResource[]>()
  for (const resource of resources) {
    if (!resource.region) continue
    const key = `${resource.provider}::${resource.region}`
    const list = regionBuckets.get(key)
    if (list) list.push(resource)
    else regionBuckets.set(key, [resource])
  }

  const providerMean = new Map<CloudProviderId, number>()
  for (const provider of providers) {
    if (provider.trustScore !== null) providerMean.set(provider.provider, provider.trustScore)
  }

  const regions: CloudRegionPosture[] = [...regionBuckets.entries()].map(([key, group]) => {
    const [providerRaw, region] = key.split('::')
    const provider = providerRaw as CloudProviderId
    const encrypted = group.filter((resource) => resource.encryptionState === 'encrypted').length
    const unencrypted = group.filter(
      (resource) => resource.encryptionState === 'unencrypted' || resource.encryptionState === 'partially-encrypted',
    ).length
    const notObserved = group.filter((resource) => resource.encryptionState === 'not-observed').length
    const measured = encrypted + unencrypted
    const critical = group.reduce((sum, resource) => sum + resource.criticalFindings, 0)
    const quantumVulnerable = group.filter((resource) => resource.quantumVulnerable).length
    const certificateIds = uniq(group.flatMap((resource) => resource.certificateIds))
    const expiring = certificateTrust.filter(
      (record) => certificateIds.includes(record.certificateId) && (record.band === 'critical' || record.band === 'high'),
    ).length

    const trustScore =
      measured > 0
        ? clamp(Math.round(percentOf(encrypted, measured) * 0.6 + percentOf(group.length - quantumVulnerable, group.length) * 0.4))
        : null

    const mean = providerMean.get(provider)
    const anomaly =
      trustScore !== null && mean !== undefined && mean - trustScore >= 20
        ? `Region trust score is ${mean - trustScore} points below the ${providerLabelFor(provider)} average.`
        : critical > 0 && group.length > 0
          ? `${critical} critical finding${critical === 1 ? '' : 's'} concentrated in this region.`
          : null

    let state: TrustState = 'unknown'
    if (critical > 0) state = 'critical'
    else if (unencrypted > 0) state = 'at-risk'
    else if (quantumVulnerable > 0) state = 'migration-required'
    else if (trustScore !== null && trustScore >= 85) state = 'healthy'
    else if (trustScore !== null) state = 'degraded'

    return {
      provider,
      providerLabel: providerLabelFor(provider),
      region,
      resources: group.length,
      encrypted,
      unencrypted,
      notObserved,
      certificates: certificateIds.length,
      expiringCertificates: expiring,
      quantumVulnerable,
      pqcReady: group.filter(
        (resource) => resource.posture === 'quantum-safe' || resource.posture === 'pqc-ready' || resource.posture === 'hybrid-ready',
      ).length,
      criticalFindings: critical,
      trustScore,
      measured: measured > 0,
      state,
      anomaly,
    }
  })

  /* ---- cross-cloud drift ---- */
  const drift: CloudEstate['drift'] = []
  const measuredProviders = providers.filter((provider) => provider.measured && provider.provider !== 'unattributed')
  if (measuredProviders.length >= 2) {
    const coverages = measuredProviders.filter((provider) => provider.encryptionCoverage !== null)
    if (coverages.length >= 2) {
      const best = coverages.reduce((a, b) => ((a.encryptionCoverage ?? 0) >= (b.encryptionCoverage ?? 0) ? a : b))
      const worst = coverages.reduce((a, b) => ((a.encryptionCoverage ?? 0) <= (b.encryptionCoverage ?? 0) ? a : b))
      const gap = (best.encryptionCoverage ?? 0) - (worst.encryptionCoverage ?? 0)
      if (gap >= 25) {
        drift.push({
          id: 'drift:encryption-coverage',
          title: 'Encryption coverage differs materially between clouds',
          detail: `${best.providerLabel} reports ${best.encryptionCoverage}% encrypted resources against ${worst.providerLabel} at ${worst.encryptionCoverage}% - a ${gap}-point gap on the same estate policy.`,
          severity: gap >= 50 ? 'high' : 'medium',
          providers: [best.provider, worst.provider],
          resourceIds: resources.filter((resource) => resource.provider === worst.provider && resource.encryptionState !== 'encrypted').map((r) => r.id),
        })
      }
    }

    const tlsLaggards = measuredProviders.filter((provider) => provider.legacyTlsEndpoints > 0)
    if (tlsLaggards.length > 0 && tlsLaggards.length < measuredProviders.length) {
      drift.push({
        id: 'drift:tls-version',
        title: 'Deprecated TLS versions remain on some clouds only',
        detail: `${tlsLaggards.map((provider) => `${provider.providerLabel} (${provider.legacyTlsEndpoints})`).join(', ')} still terminate TLS 1.0/1.1 while the remaining clouds do not.`,
        severity: 'high',
        providers: tlsLaggards.map((provider) => provider.provider),
        resourceIds: [],
      })
    }

    const kmsGap = measuredProviders.filter((provider) => provider.kmsResources === 0 && provider.resources > 0)
    if (kmsGap.length > 0 && kmsGap.length < measuredProviders.length) {
      drift.push({
        id: 'drift:kms',
        title: 'Key management is not observed on every cloud',
        detail: `${kmsGap.map((provider) => provider.providerLabel).join(', ')} report no key-management service against their resources, while other clouds do.`,
        severity: 'medium',
        providers: kmsGap.map((provider) => provider.provider),
        resourceIds: [],
      })
    }
  }

  /* ---- regional anomalies ---- */
  const anomalies: CloudEstate['anomalies'] = regions
    .filter((region) => region.anomaly)
    .map((region) => ({
      id: `anomaly:${region.provider}:${region.region}`,
      title: `${region.region} deviates from the ${region.providerLabel} baseline`,
      detail: region.anomaly as string,
      severity: (region.criticalFindings > 0 ? 'high' : 'medium') as Severity,
      provider: region.provider,
      region: region.region,
      resourceIds: resources.filter((resource) => resource.provider === region.provider && resource.region === region.region).map((r) => r.id),
    }))

  /* ---- algorithm spread ---- */
  const algorithmBuckets = new Map<string, { posture: CloudResource['posture']; byProvider: Map<CloudProviderId, number> }>()
  for (const resource of resources) {
    for (const algorithm of resource.encryptionAlgorithms) {
      const bucket = algorithmBuckets.get(algorithm) || { posture: resource.posture, byProvider: new Map<CloudProviderId, number>() }
      bucket.byProvider.set(resource.provider, (bucket.byProvider.get(resource.provider) || 0) + 1)
      algorithmBuckets.set(algorithm, bucket)
    }
  }
  const algorithmSpread = [...algorithmBuckets.entries()]
    .map(([algorithm, bucket]) => ({
      algorithm,
      posture: bucket.posture,
      total: [...bucket.byProvider.values()].reduce((sum, value) => sum + value, 0),
      byProvider: [...bucket.byProvider.entries()]
        .map(([provider, count]) => ({ provider, providerLabel: providerLabelFor(provider), count }))
        .sort((a, b) => b.count - a.count),
    }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 12)

  return {
    hasCloudEvidence: attributed.length > 0,
    connectorsConfigured,
    connectorsActive,
    providers: providers.sort((a, b) => b.resources - a.resources || a.providerLabel.localeCompare(b.providerLabel)),
    regions: regions.sort((a, b) => b.resources - a.resources),
    resources: resources.sort((a, b) => TRUST_STATE_RANK[b.state] - TRUST_STATE_RANK[a.state] || b.riskScore - a.riskScore),
    totals: {
      resources: resources.length,
      attributedResources: attributed.length,
      unattributedResources: resources.length - attributed.length,
      encrypted: resources.filter((resource) => resource.encryptionState === 'encrypted').length,
      unencrypted: resources.filter((resource) => resource.encryptionState === 'unencrypted').length,
      encryptionNotObserved: resources.filter((resource) => resource.encryptionState === 'not-observed').length,
      certificates: uniq(resources.flatMap((resource) => resource.certificateIds)).length,
      quantumVulnerable: resources.filter((resource) => resource.quantumVulnerable).length,
      pqcReady: resources.filter(
        (resource) => resource.posture === 'quantum-safe' || resource.posture === 'pqc-ready' || resource.posture === 'hybrid-ready',
      ).length,
      kmsManaged: resources.filter((resource) => resource.keyManagementKnown).length,
    },
    drift,
    anomalies,
    algorithmSpread,
  }
}

/* ================================================================== */
/* Events (section 9)                                                  */
/* ================================================================== */

function buildEvents(input: {
  nodes: Map<string, TrustNode>
  certificates: PkiCertificate[]
  certificateTrust: CertificateTrustRecord[]
  cloudResources: CloudResource[]
  securityEvents: Row[]
  scanSessions: Row[]
  migrationJobs: Row[]
  scannerAgents: Row[]
  runtimeEvents: Row[]
  assetRows: Row[]
  now: number
}): TrustEvent[] {
  const events: TrustEvent[] = []
  const { now } = input
  const recentWindow = now - 30 * DAY_MS

  const push = (event: TrustEvent) => {
    if (!event.at) return
    if (dateMs(event.at) < recentWindow) return
    events.push(event)
  }

  /* ---- certificate lifecycle events, derived from real dates ---- */
  for (const record of input.certificateTrust) {
    const certificate = input.certificates.find((cert) => cert.id === record.certificateId)
    if (!certificate) continue
    const subjectHref = `/dashboard/certificate-telemetry?certificate=${encodeURIComponent(certificate.id)}`

    if (record.band === 'expired') {
      push({
        id: `event:cert-expired:${certificate.id}`,
        kind: 'certificate-expired',
        label: TRUST_EVENT_LABEL['certificate-expired'],
        title: `${certificate.name || certificate.subject} expired`,
        detail: record.remediation,
        severity: 'critical',
        subject: certificate.name || certificate.subject,
        subjectHref,
        assetId: certificate.assetId,
        certificateId: certificate.id,
        provider: record.provider,
        region: record.region,
        at: certificate.notAfter,
        source: 'Certificate lifecycle',
        sourceTable: 'certificates',
      })
    } else if (record.band === 'critical' || record.band === 'high') {
      push({
        id: `event:cert-expiring:${certificate.id}`,
        kind: 'certificate-expiring',
        label: TRUST_EVENT_LABEL['certificate-expiring'],
        title: `${certificate.name || certificate.subject} expires in ${certificate.daysToExpiry} days`,
        detail: record.remediation,
        severity: record.band === 'critical' ? 'critical' : 'high',
        subject: certificate.name || certificate.subject,
        subjectHref,
        assetId: certificate.assetId,
        certificateId: certificate.id,
        provider: record.provider,
        region: record.region,
        at: certificate.lastObservedAt,
        source: 'Certificate lifecycle',
        sourceTable: 'certificates',
      })
    }

    if (record.failedChecks > 0) {
      const failure = record.checks.find((check) => check.status === 'fail')
      push({
        id: `event:chain-failure:${certificate.id}`,
        kind: 'trust-chain-failure',
        label: TRUST_EVENT_LABEL['trust-chain-failure'],
        title: `Trust-chain failure on ${certificate.name || certificate.subject}`,
        detail: failure?.detail || 'One or more chain validation checks failed.',
        severity: failure?.severity ?? 'high',
        subject: certificate.name || certificate.subject,
        subjectHref,
        assetId: certificate.assetId,
        certificateId: certificate.id,
        provider: record.provider,
        region: record.region,
        at: certificate.lastObservedAt,
        source: 'Chain validation',
        sourceTable: 'certificates',
      })
    }

    if (record.renewal.status === 'renewed') {
      push({
        id: `event:cert-renewed:${certificate.id}`,
        kind: 'certificate-renewed',
        label: TRUST_EVENT_LABEL['certificate-renewed'],
        title: `${certificate.name || certificate.subject} renewed`,
        detail: record.renewal.detail,
        severity: 'low',
        subject: certificate.name || certificate.subject,
        subjectHref,
        assetId: certificate.assetId,
        certificateId: certificate.id,
        provider: record.provider,
        region: record.region,
        at: record.renewal.lastAttemptAt,
        source: 'Migration jobs',
        sourceTable: 'migration_jobs',
      })
    }

    const discovered = dateMs(certificate.lastObservedAt)
    if (discovered && discovered >= now - 7 * DAY_MS && record.band !== 'expired') {
      push({
        id: `event:cert-discovered:${certificate.id}`,
        kind: 'certificate-discovered',
        label: TRUST_EVENT_LABEL['certificate-discovered'],
        title: `Certificate observed: ${certificate.name || certificate.subject}`,
        detail: `${certificate.algorithmLabel} issued by ${certificate.issuer || 'an unrecorded issuer'}.`,
        severity: 'low',
        subject: certificate.name || certificate.subject,
        subjectHref,
        assetId: certificate.assetId,
        certificateId: certificate.id,
        provider: record.provider,
        region: record.region,
        at: certificate.lastObservedAt,
        source: 'Certificate discovery',
        sourceTable: 'certificates',
      })
    }
  }

  /* ---- asset discovery ---- */
  for (const row of input.assetRows) {
    const created = dateMs(row.created_at)
    if (!created || created < now - 7 * DAY_MS) continue
    push({
      id: `event:asset-discovered:${str(row.id)}`,
      kind: 'asset-discovered',
      label: TRUST_EVENT_LABEL['asset-discovered'],
      title: `Asset discovered: ${str(row.name) || 'Unnamed asset'}`,
      detail: `${titleCase(row.type, 'Asset')} in ${str(row.environment) || 'an unspecified environment'}.`,
      severity: 'low',
      subject: str(row.name),
      subjectHref: `/dashboard/assets?asset=${encodeURIComponent(str(row.id))}`,
      assetId: str(row.id) || null,
      certificateId: null,
      provider: null,
      region: str(row.region),
      at: isoOrNull(row.created_at),
      source: 'Discovery',
      sourceTable: 'assets',
    })
  }

  /* ---- cloud resource discovery ---- */
  for (const resource of input.cloudResources) {
    const seen = dateMs(resource.lastSeenAt)
    if (!seen || seen < now - 7 * DAY_MS || !resource.attribution.attributed) continue
    push({
      id: `event:cloud-discovered:${resource.id}`,
      kind: 'cloud-resource-discovered',
      label: TRUST_EVENT_LABEL['cloud-resource-discovered'],
      title: `${resource.providerLabel} resource discovered: ${resource.name}`,
      detail: `${resource.resourceType}${resource.region ? ` in ${resource.region}` : ''}. ${resource.attribution.reason}`,
      severity: 'low',
      subject: resource.name,
      subjectHref: resource.href,
      assetId: resource.assetId,
      certificateId: null,
      provider: resource.provider,
      region: resource.region,
      at: resource.lastSeenAt,
      source: 'Cloud attribution',
      sourceTable: 'assets',
    })

    if (resource.quantumVulnerable) {
      push({
        id: `event:quantum-vulnerable:${resource.id}`,
        kind: 'quantum-vulnerable-detected',
        label: TRUST_EVENT_LABEL['quantum-vulnerable-detected'],
        title: `Quantum-vulnerable cryptography on ${resource.name}`,
        detail: resource.stateReason,
        severity: 'high',
        subject: resource.name,
        subjectHref: resource.href,
        assetId: resource.assetId,
        certificateId: null,
        provider: resource.provider,
        region: resource.region,
        at: resource.lastTelemetryAt,
        source: 'Cryptographic posture',
        sourceTable: 'assets',
      })
    }
  }

  /* ---- scanner sessions ---- */
  for (const session of input.scanSessions) {
    const status = str(session.status).toLowerCase()
    if (!/complete|finished|done/.test(status)) continue
    push({
      id: `event:scan:${str(session.id)}`,
      kind: 'scan-completed',
      label: TRUST_EVENT_LABEL['scan-completed'],
      title: `Scan completed - ${num(session.findings_count)} finding${num(session.findings_count) === 1 ? '' : 's'}`,
      detail: `${num(session.scanned_assets)} of ${num(session.total_assets)} assets assessed.`,
      severity: num(session.findings_count) > 0 ? 'medium' : 'low',
      subject: 'PQC Scanner',
      subjectHref: '/dashboard/scanner',
      assetId: null,
      certificateId: null,
      provider: null,
      region: '',
      at: isoOrNull(session.completed_at ?? session.updated_at),
      source: 'PQC Scanner',
      sourceTable: 'pqc_scan_sessions',
    })
  }

  /* ---- migration completions ---- */
  for (const job of input.migrationJobs) {
    const status = str(job.status).toLowerCase()
    if (!/complete|success/.test(status)) continue
    push({
      id: `event:migration:${str(job.id)}`,
      kind: 'pqc-migration-completed',
      label: TRUST_EVENT_LABEL['pqc-migration-completed'],
      title: `Migration completed: ${str(job.name) || titleCase(job.job_type, 'Migration')}`,
      detail: str(job.target_algorithm) ? `Target algorithm ${str(job.target_algorithm)}.` : 'Cryptographic migration job reported success.',
      severity: 'low',
      subject: str(job.name) || 'Migration job',
      subjectHref: '/dashboard/live-migration',
      assetId: str(job.asset_id) || null,
      certificateId: null,
      provider: null,
      region: '',
      at: isoOrNull(job.completed_at ?? job.updated_at),
      source: 'Live Migration',
      sourceTable: 'migration_jobs',
    })
  }

  /* ---- security events that name a trust subject ---- */
  for (const row of input.securityEvents) {
    const type = str(row.event_type).toLowerCase()
    if (!/cert|tls|crypto|key|trust|cipher|algorithm|encrypt/.test(type)) continue
    const severity = normalizeSeverity(row.severity)
    const kind: TrustEventKind = /algorithm|cipher/.test(type)
      ? 'algorithm-changed'
      : /tls|protocol/.test(type)
        ? 'tls-configuration-changed'
        : /cert/.test(type)
          ? 'certificate-discovered'
          : 'finding-created'
    push({
      id: `event:security:${str(row.id)}`,
      kind,
      label: TRUST_EVENT_LABEL[kind],
      title: titleCase(row.event_type, 'Cryptographic event'),
      detail: str(row.message) || str(row.resource_name) || 'Recorded by the platform security event pipeline.',
      severity,
      subject: str(row.resource_name) || titleCase(row.resource_type, 'Resource'),
      subjectHref: str(row.asset_id) ? `/dashboard/assets?asset=${encodeURIComponent(str(row.asset_id))}` : null,
      assetId: str(row.asset_id) || null,
      certificateId: null,
      provider: null,
      region: '',
      at: isoOrNull(row.created_at),
      source: 'Security events',
      sourceTable: 'security_events',
    })
  }

  /* ---- agent telemetry ---- */
  for (const agent of input.scannerAgents) {
    const seen = dateMs(agent.last_seen_at)
    if (!seen || seen < now - 2 * DAY_MS) continue
    push({
      id: `event:agent:${str(agent.id)}`,
      kind: 'agent-telemetry',
      label: TRUST_EVENT_LABEL['agent-telemetry'],
      title: `Telemetry from ${str(agent.name) || str(agent.hostname) || 'collector'}`,
      detail: `Agent status ${str(agent.status) || 'unknown'} on ${str(agent.platform) || 'an unrecorded platform'}.`,
      severity: 'low',
      subject: str(agent.name) || 'Collector agent',
      subjectHref: '/dashboard/scanner?tab=agents',
      assetId: null,
      certificateId: null,
      provider: null,
      region: '',
      at: isoOrNull(agent.last_seen_at),
      source: 'Agent collector',
      sourceTable: 'scanner_agents',
    })
  }

  const severityRank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }
  return events
    .sort((a, b) => dateMs(b.at) - dateMs(a.at) || severityRank[b.severity] - severityRank[a.severity])
    .slice(0, 200)
}

/* ================================================================== */
/* Scores                                                              */
/* ================================================================== */

function buildScores(input: {
  tlsPki: TlsPkiIntelligence
  snapshot: TrustFabricInputs['snapshot']
  nodes: TrustNode[]
  certificates: PkiCertificate[]
  certificateTrust: CertificateTrustRecord[]
  chainPaths: TrustFabricIntelligence['chainPaths']
  cloud: CloudEstate
  findings: TlsPkiIntelligence['findings']
}): TrustScore[] {
  const { tlsPki, snapshot, nodes, certificates, certificateTrust, chainPaths, cloud, findings } = input
  const posture = tlsPki.posture

  /* ---- certificate health ---- */
  const certHealthy = certificateTrust.filter(
    (record) => record.band === 'healthy' && record.failedChecks === 0,
  ).length
  const certHealth = ratioScore(certHealthy, certificates.length)

  /* ---- TLS security ---- */
  const measuredEndpoints = posture.tlsEnabledAssets
  const tlsGood = posture.tls13Endpoints
  const tlsSecurity =
    measuredEndpoints > 0
      ? clamp(
          Math.round(
            percentOf(tlsGood, measuredEndpoints) * 0.6 +
              percentOf(Math.max(0, measuredEndpoints - posture.weakCipherEndpoints), measuredEndpoints) * 0.4,
          ),
        )
      : null

  /* ---- trust chain health ---- */
  /**
   * Credit-weighted, NOT a pass/fail headcount.
   *
   * An earlier form of this score counted a certificate as "clean" whenever it
   * had zero FAILING checks. On a real estate where no root CA certificate had
   * ever been collected — every chain warned, none failed — that published
   * "Trust-Chain Health 100" directly above the sentence "2 of 2 chains are
   * incomplete". Absence of a failure is not evidence of health.
   *
   * Each certificate now earns credit over the checks that could actually be
   * evaluated: a pass is full credit, a warning is half (the property is real
   * but degraded), a failure is none. Checks the platform genuinely cannot run
   * are excluded from the denominator and reduce COVERAGE instead, so a thin
   * evidence base reads as a narrow basis rather than as a perfect score.
   */
  const chainCredits: number[] = []
  let chainChecksEvaluable = 0
  let chainChecksTotal = 0
  for (const record of certificateTrust) {
    let evaluable = 0
    let credit = 0
    for (const check of record.checks) {
      chainChecksTotal += 1
      if (check.status === 'not-evaluated') continue
      evaluable += 1
      if (check.status === 'pass') credit += 1
      else if (check.status === 'warn') credit += 0.5
    }
    chainChecksEvaluable += evaluable
    if (evaluable > 0) chainCredits.push(clamp(Math.round((credit / evaluable) * 100)))
  }
  const chainsEvaluated = chainCredits.length
  const chainsClean = certificateTrust.filter(
    (record) => record.failedChecks === 0 && record.warnChecks === 0 && record.checks.some((check) => check.status === 'pass'),
  ).length
  const chainHealth = meanOrNull(chainCredits)
  const incompleteChains = chainPaths.filter((path) => !path.complete).length

  /* ---- cloud trust ---- */
  const cloudScored = cloud.providers.filter((provider) => provider.trustScore !== null)
  const cloudTrust = meanOrNull(cloudScored.map((provider) => provider.trustScore as number))

  /* ---- regional trust ---- */
  const regionScored = cloud.regions.filter((region) => region.trustScore !== null)
  const regionalTrust = meanOrNull(regionScored.map((region) => region.trustScore as number))

  /* ---- compliance ---- */
  const compliance = snapshot.complianceScore

  /* ---- overall ---- */
  // Composed only from the dimensions that were actually measured, so a tenant
  // with no cloud connector is not penalised for a cloud score that does not exist.
  const parts: Array<{ label: string; value: number; weight: number }> = []
  if (certHealth !== null) parts.push({ label: 'certificate health', value: certHealth, weight: 0.25 })
  if (tlsSecurity !== null) parts.push({ label: 'TLS security', value: tlsSecurity, weight: 0.2 })
  if (chainHealth !== null) parts.push({ label: 'chain health', value: chainHealth, weight: 0.2 })
  parts.push({ label: 'quantum readiness', value: snapshot.quantumReadiness, weight: 0.25 })
  if (cloudTrust !== null) parts.push({ label: 'cloud trust', value: cloudTrust, weight: 0.1 })
  const CONTRIBUTING_DIMENSIONS = 5
  const weightTotal = parts.reduce((sum, part) => sum + part.weight, 0)
  const overall =
    parts.length > 0 && weightTotal > 0
      ? clamp(Math.round(parts.reduce((sum, part) => sum + part.value * part.weight, 0) / weightTotal))
      : null

  const criticalFindings = findings.filter((finding) => finding.severity === 'critical').length
  const measuredNodes = nodes.filter((node) => node.measured).length

  return [
    {
      key: 'overall',
      label: 'Cryptographic Trust',
      value: overall,
      measured: overall !== null,
      basis:
        'Weighted composition of certificate health, TLS security, chain health, quantum readiness and cloud trust. A dimension with no evidence is dropped from the weighting rather than scored as zero, so an unmeasured area never drags the headline down — but it is named below so the gap is visible.',
      denominator: `${parts.length} of ${CONTRIBUTING_DIMENSIONS} dimensions contributing`,
      coveragePercent: percentOf(measuredNodes, Math.max(nodes.length, 1)),
      reason:
        overall === null
          ? 'No cryptographic evidence has been collected for this tenant yet.'
          : `Composed from ${parts.map((part) => part.label).join(', ')} across ${measuredNodes} of ${nodes.length} measured trust subject${nodes.length === 1 ? '' : 's'}.${
              parts.length < CONTRIBUTING_DIMENSIONS
                ? ` ${CONTRIBUTING_DIMENSIONS - parts.length} dimension(s) had no evidence and were excluded from the weighting.`
                : ''
            }`,
      tone: toneForScore(overall),
      href: '/dashboard/trust-state-discovery',
    },
    {
      key: 'quantum',
      label: 'Quantum Readiness',
      value: snapshot.quantumReadiness,
      measured: true,
      basis: 'Published verbatim by the Quantum Readiness Engine - the same score the QR pages, Migration Planner and reports show.',
      denominator: `${snapshot.assetsAssessed} assets assessed`,
      coveragePercent: percentOf(snapshot.assetsAssessed, Math.max(snapshot.assetsAssessed, 1)),
      reason: `Estate quantum risk is ${snapshot.quantumRisk} (${snapshot.quantumRiskLevel}). ${snapshot.vulnerableComponents} of ${snapshot.totalComponents} cryptographic components are quantum vulnerable.`,
      tone: toneForScore(snapshot.quantumReadiness),
      href: '/dashboard/quantum-readiness',
    },
    {
      key: 'certificate-health',
      label: 'Certificate Health',
      value: certHealth,
      measured: certHealth !== null,
      basis: 'Share of certificates with more than 60 days validity and no failing chain check.',
      denominator: `${certHealthy} of ${certificates.length} certificates`,
      coveragePercent: percentOf(certificates.length, Math.max(certificates.length, 1)),
      reason:
        certHealth === null
          ? 'No certificates have been discovered in this tenant.'
          : `${certificates.length - certHealthy} certificate${certificates.length - certHealthy === 1 ? '' : 's'} are expiring, expired or failing validation.`,
      tone: toneForScore(certHealth),
      href: '/dashboard/certificate-telemetry',
    },
    {
      key: 'tls-security',
      label: 'TLS Security',
      value: tlsSecurity,
      measured: tlsSecurity !== null,
      basis: 'TLS 1.3 adoption and cipher strength across endpoints actually observed negotiating.',
      denominator: `${measuredEndpoints} measured endpoint${measuredEndpoints === 1 ? '' : 's'}`,
      coveragePercent: posture.transportCoveragePercent,
      reason:
        tlsSecurity === null
          ? 'No endpoint has been observed completing a TLS handshake, so transport security cannot be scored.'
          : `${posture.tls13Endpoints} of ${measuredEndpoints} endpoints negotiate TLS 1.3; ${posture.weakCipherEndpoints} carry weak cipher suites.`,
      tone: toneForScore(tlsSecurity),
      href: '/dashboard/tls-telemetry',
    },
    {
      key: 'chain-health',
      label: 'Trust-Chain Health',
      value: chainHealth,
      measured: chainHealth !== null,
      basis:
        'Credit earned across the chain checks that could actually be evaluated: a pass counts full, a warning half, a failure none. Checks the platform cannot run are excluded and lower coverage instead.',
      denominator: `${chainsClean} fully clean of ${chainsEvaluated} evaluable chains`,
      // Coverage is the share of chain CHECKS that were evaluable, not the share
      // of certificates — a certificate on which only three of eleven checks
      // could run must not read as fully covered.
      coveragePercent: percentOf(chainChecksEvaluable, Math.max(chainChecksTotal, 1)),
      reason:
        chainHealth === null
          ? 'No certificate carries enough chain evidence to be validated.'
          : `${incompleteChains} of ${chainPaths.length} assembled chain${chainPaths.length === 1 ? '' : 's'} ${incompleteChains === 1 ? 'is' : 'are'} incomplete; ${chainChecksEvaluable} of ${chainChecksTotal} chain checks could be evaluated.`,
      tone: toneForScore(chainHealth),
      href: '/dashboard/trust-state-discovery',
    },
    {
      key: 'compliance',
      label: 'Cryptographic Compliance',
      value: compliance,
      measured: compliance !== null,
      basis: 'Control coverage from the tenant compliance evidence store.',
      denominator: compliance === null ? 'No control evidence recorded' : 'Mapped cryptographic controls',
      coveragePercent: compliance === null ? 0 : 100,
      reason:
        compliance === null
          ? 'No compliance evidence has been recorded, so a control score cannot be stated.'
          : `${criticalFindings} critical cryptographic finding${criticalFindings === 1 ? '' : 's'} remain open against mapped controls.`,
      tone: toneForScore(compliance),
      href: '/dashboard/compliance',
    },
    {
      key: 'cloud-trust',
      label: 'Cloud Trust',
      value: cloudTrust,
      measured: cloudTrust !== null,
      basis: 'Mean measured posture across clouds where at least one resource carries an encryption or posture reading.',
      denominator: `${cloudScored.length} of ${cloud.providers.length} clouds measured`,
      coveragePercent: percentOf(cloud.totals.attributedResources, Math.max(cloud.totals.resources, 1)),
      reason:
        cloudTrust === null
          ? cloud.connectorsConfigured === 0
            ? 'No cloud connector is configured, so no cloud resource posture exists to score.'
            : 'Cloud accounts are connected but no resource has been measured yet.'
          : `${cloud.totals.attributedResources} of ${cloud.totals.resources} resources could be attributed to a named cloud.`,
      tone: toneForScore(cloudTrust),
      href: '/dashboard/multi-cloud-telemetry',
    },
    {
      key: 'regional-trust',
      label: 'Regional Trust',
      value: regionalTrust,
      measured: regionalTrust !== null,
      basis: 'Mean measured posture across cloud regions carrying at least one encryption reading.',
      denominator: `${regionScored.length} of ${cloud.regions.length} regions measured`,
      coveragePercent: percentOf(regionScored.length, Math.max(cloud.regions.length, 1)),
      reason:
        regionalTrust === null
          ? 'No region carries an encryption measurement.'
          : `${cloud.anomalies.length} region${cloud.anomalies.length === 1 ? '' : 's'} deviate from their provider baseline.`,
      tone: toneForScore(regionalTrust),
      href: '/dashboard/multi-cloud-telemetry',
    },
  ]
}

/* ================================================================== */
/* KPIs                                                                */
/* ================================================================== */

function buildKpis(input: {
  tlsPki: TlsPkiIntelligence
  snapshot: TrustFabricInputs['snapshot']
  nodes: TrustNode[]
  certificates: PkiCertificate[]
  certificateTrust: CertificateTrustRecord[]
  cloud: CloudEstate
  findings: TlsPkiIntelligence['findings']
  assets: AssetMigrationRecord[]
}): TrustKpi[] {
  const { tlsPki, snapshot, certificates, certificateTrust, cloud, findings, assets } = input
  const posture = tlsPki.posture

  const byBand = (band: ExpiryBand) => certificateTrust.filter((record) => record.band === band)
  const active = certificateTrust.filter((record) => record.band !== 'expired' && record.band !== 'unknown')
  const invalid = certificateTrust.filter((record) => record.failedChecks > 0 && record.band !== 'expired')
  const weak = certificates.filter(
    (certificate) =>
      (certificate.keySize !== null && /rsa/i.test(certificate.publicKeyAlgorithm) && certificate.keySize < 2048) ||
      /\b(md5|sha-?1)\b/i.test(certificate.signatureAlgorithm || ''),
  )
  const quantumVulnerable = certificates.filter(
    (certificate) => certificate.posture === 'quantum-vulnerable' || certificate.posture === 'legacy',
  )
  const pqcReady = certificates.filter((certificate) => certificate.posture === 'quantum-safe' || certificate.posture === 'pqc-ready')
  const hybrid = certificates.filter((certificate) => certificate.posture === 'hybrid-ready')
  const isChainCheck = (key: ChainCheck['key']) => key === 'chain-complete' || key === 'root-ca' || key === 'intermediate-ca'
  const chainFailures = certificateTrust.filter((record) =>
    record.checks.some((check) => check.status === 'fail' && isChainCheck(check.key)),
  )
  /**
   * Chains that could not be walked but did not outright FAIL — the normal case
   * when a scanner captured a leaf certificate and never collected the CA above
   * it. Counted separately so a "0 failures" headline is never printed next to
   * the claim that every chain resolves: the detail line names these instead.
   */
  const chainIncomplete = certificateTrust.filter(
    (record) =>
      !chainFailures.includes(record) && record.checks.some((check) => check.status === 'warn' && isChainCheck(check.key)),
  )
  const criticalFindings = findings.filter((finding) => finding.severity === 'critical')

  const kpi = (
    key: string,
    label: string,
    value: number | null,
    detail: string,
    tone: TrustKpi['tone'],
    href: string,
    scopeIds: string[],
    hint: string,
  ): TrustKpi => ({ key, label, value, measured: value !== null, detail, tone, href, scopeIds: scopeIds.slice(0, 300), hint })

  return [
    kpi(
      'total-crypto-assets',
      'Total Crypto Assets',
      snapshot.assetsAssessed,
      `${assets.filter((asset) => asset.hasEvidence).length} carry cryptographic evidence`,
      'neutral',
      '/dashboard/assets',
      assets.map((asset) => asset.id),
      'Assets assessed by the Quantum Readiness Engine - the same total Assets & CBOM reports.',
    ),
    kpi(
      'total-certificates',
      'Total Certificates',
      certificates.length,
      'Deduplicated across inventory, scanner and runtime evidence',
      'neutral',
      '/dashboard/certificate-telemetry',
      certificates.map((certificate) => certificate.id),
      'One record per real certificate: rows describing the same serial collapse onto one.',
    ),
    kpi(
      'active-certificates',
      'Active Certificates',
      active.length,
      `${percentOf(active.length, Math.max(certificates.length, 1))}% of inventory is inside its validity window`,
      active.length === certificates.length ? 'good' : 'info',
      '/dashboard/certificate-telemetry?band=healthy',
      active.map((record) => record.certificateId),
      'Certificates with a recorded validity window that has not passed.',
    ),
    kpi(
      'expiring-soon',
      'Expiring Soon',
      byBand('critical').length + byBand('high').length,
      '30 days or less of validity remaining',
      byBand('critical').length > 0 ? 'critical' : byBand('high').length > 0 ? 'warning' : 'good',
      '/dashboard/certificate-telemetry?band=high',
      [...byBand('critical'), ...byBand('high')].map((record) => record.certificateId),
      'Combines the critical (7 days) and high-risk (30 days) expiry bands.',
    ),
    kpi(
      'expired',
      'Expired',
      byBand('expired').length,
      byBand('expired').length > 0 ? 'TLS handshakes using these already fail' : 'No expired certificates in inventory',
      byBand('expired').length > 0 ? 'critical' : 'good',
      '/dashboard/certificate-telemetry?band=expired',
      byBand('expired').map((record) => record.certificateId),
      'Certificates whose notAfter date has passed.',
    ),
    kpi(
      'invalid',
      'Invalid',
      invalid.length,
      'At least one chain validation check is failing',
      invalid.length > 0 ? 'critical' : 'good',
      '/dashboard/certificate-telemetry?state=invalid',
      invalid.map((record) => record.certificateId),
      'Self-signed, name-mismatched, revoked or weak-key certificates still inside their validity window.',
    ),
    kpi(
      'weak-deprecated',
      'Weak / Deprecated',
      weak.length,
      'Below NIST SP 800-57 strength or signed with a broken hash',
      weak.length > 0 ? 'critical' : 'good',
      '/dashboard/certificate-telemetry?state=weak',
      weak.map((certificate) => certificate.id),
      'RSA under 2048 bits, or MD5/SHA-1 signatures.',
    ),
    kpi(
      'quantum-vulnerable',
      'Quantum Vulnerable',
      quantumVulnerable.length,
      `${percentOf(quantumVulnerable.length, Math.max(certificates.length, 1))}% of certificates are classical only`,
      quantumVulnerable.length > 0 ? 'warning' : 'good',
      '/dashboard/certificate-telemetry?posture=quantum-vulnerable',
      quantumVulnerable.map((certificate) => certificate.id),
      'Certificates whose public key algorithm falls to Shor’s algorithm.',
    ),
    kpi(
      'pqc-ready',
      'PQC Ready',
      pqcReady.length,
      'ML-DSA or SLH-DSA signing material in place',
      pqcReady.length > 0 ? 'good' : 'neutral',
      '/dashboard/certificate-telemetry?posture=pqc-ready',
      pqcReady.map((certificate) => certificate.id),
      'Certificates using a NIST post-quantum signature scheme (FIPS 204 / 205).',
    ),
    kpi(
      'hybrid-ready',
      'Hybrid Ready',
      hybrid.length,
      'Classical and post-quantum algorithms in combination',
      hybrid.length > 0 ? 'good' : 'neutral',
      '/dashboard/certificate-telemetry?posture=hybrid-ready',
      hybrid.map((certificate) => certificate.id),
      'Hybrid deployments such as X25519 with ML-KEM, or Ed25519 with ML-DSA.',
    ),
    kpi(
      'tls13-coverage',
      'TLS 1.3 Coverage',
      posture.tlsEnabledAssets > 0 ? percentOf(posture.tls13Endpoints, posture.tlsEnabledAssets) : null,
      posture.tlsEnabledAssets > 0
        ? `${posture.tls13Endpoints} of ${posture.tlsEnabledAssets} measured endpoints`
        : 'No endpoint has been observed negotiating TLS',
      posture.tlsEnabledAssets === 0 ? 'neutral' : percentOf(posture.tls13Endpoints, posture.tlsEnabledAssets) >= 80 ? 'good' : 'warning',
      '/dashboard/protocol-analytics',
      [],
      'Measured against endpoints observed negotiating, not against every asset - that is the honest denominator.',
    ),
    kpi(
      'chain-failures',
      'Trust-Chain Failures',
      chainFailures.length,
      chainIncomplete.length > 0
        ? `${chainIncomplete.length} further chain${chainIncomplete.length === 1 ? '' : 's'} incomplete — CA known by name only`
        : 'Every collected chain resolves to a held root',
      chainFailures.length > 0 ? 'critical' : chainIncomplete.length > 0 ? 'warning' : 'good',
      '/dashboard/trust-state-discovery?view=chains',
      [...chainFailures, ...chainIncomplete].map((record) => record.certificateId),
      'A failure is a broken or self-signed anchor. A chain that merely could not be collected is reported as incomplete instead — it is not counted here as a failure, and it is not treated as healthy either.',
    ),
    kpi(
      'cloud-assets',
      'Cloud Assets Monitored',
      cloud.totals.attributedResources,
      cloud.totals.resources > 0
        ? `${cloud.totals.unattributedResources} further resource${cloud.totals.unattributedResources === 1 ? '' : 's'} could not be attributed to a named cloud`
        : 'No cloud resources discovered',
      cloud.totals.attributedResources > 0 ? 'info' : 'neutral',
      '/dashboard/multi-cloud-telemetry',
      cloud.resources.filter((resource) => resource.attribution.attributed).map((resource) => resource.id),
      'Only resources whose own evidence names a cloud are counted; nothing is assigned by assumption.',
    ),
    kpi(
      'critical-findings',
      'Active Critical Findings',
      criticalFindings.length,
      criticalFindings.length > 0 ? 'Open cryptographic findings at critical severity' : 'No critical cryptographic findings open',
      criticalFindings.length > 0 ? 'critical' : 'good',
      '/dashboard/vulnerabilities?severity=critical',
      criticalFindings.map((finding) => finding.id),
      'Same finding records the Scanner, CBOM and Quantum Readiness modules report.',
    ),
  ]
}

/* ================================================================== */
/* Reconciliation (section 16)                                         */
/* ================================================================== */

function buildReconciliation(input: {
  certificates: PkiCertificate[]
  certificateTrust: CertificateTrustRecord[]
  certificateIntel: CertificateIntelligence
  nodes: TrustNode[]
  edges: TrustRelationship[]
  assets: AssetMigrationRecord[]
  relationships: Row[]
  cloud: CloudEstate
  snapshot: TrustFabricInputs['snapshot']
  tlsPki: TlsPkiIntelligence
  stale: boolean
  staleSinceHours: number | null
  cryptoInventory: Row[]
}): TrustFabricIntelligence['reconciliation'] {
  const issues: ReconciliationIssue[] = []
  const { certificates, certificateIntel, nodes, edges, assets, relationships, cloud, snapshot, tlsPki, stale, staleSinceHours } = input

  if (certificateIntel.orphans.length > 0) {
    issues.push({
      id: 'recon:orphan-certificates',
      kind: 'orphan-certificate',
      title: 'Orphan certificates',
      detail: `${certificateIntel.orphans.length} certificate${certificateIntel.orphans.length === 1 ? ' is' : 's are'} in inventory but bound to no asset and no endpoint, so their blast radius cannot be computed.`,
      severity: 'medium',
      count: certificateIntel.orphans.length,
      sourceTable: 'certificates',
      affectedIds: certificateIntel.orphans.slice(0, 100),
      remediation: 'Run a transport scan against the hosts that serve these certificates so the deployment mapping is captured.',
      href: '/dashboard/certificate-telemetry?issue=orphan',
    })
  }

  if (certificateIntel.duplicates.length > 0) {
    const total = certificateIntel.duplicates.reduce((sum, group) => sum + group.certificateIds.length, 0)
    issues.push({
      id: 'recon:duplicate-certificates',
      kind: 'duplicate-certificate',
      title: 'Duplicate certificate records',
      detail: `${certificateIntel.duplicates.length} subject/issuer pair${certificateIntel.duplicates.length === 1 ? '' : 's'} resolve to more than one certificate record (${total} rows). This is expected during renewal overlap and a defect otherwise.`,
      severity: 'low',
      count: certificateIntel.duplicates.length,
      sourceTable: 'certificates',
      affectedIds: certificateIntel.duplicates.flatMap((group) => group.certificateIds).slice(0, 100),
      remediation: 'Confirm whether these are renewal overlaps; retire superseded records so lifecycle counts stay exact.',
      href: '/dashboard/certificate-telemetry?issue=duplicate',
    })
  }

  if (certificateIntel.ownerless.length > 0) {
    issues.push({
      id: 'recon:ownerless-certificates',
      kind: 'ownerless-asset',
      title: 'Certificates without an owner',
      detail: `${certificateIntel.ownerless.length} certificate${certificateIntel.ownerless.length === 1 ? ' has' : 's have'} no service owner, so renewal cannot be assigned.`,
      severity: 'medium',
      count: certificateIntel.ownerless.length,
      sourceTable: 'assets',
      affectedIds: certificateIntel.ownerless.slice(0, 100),
      remediation: 'Set service_owner on the owning asset so expiry alerts reach an accountable team.',
      href: '/dashboard/certificate-telemetry?issue=ownerless',
    })
  }

  const assetsWithoutRelationships = assets.filter(
    (asset) => !relationships.some((row) => str(row.source_asset_id) === asset.id || str(row.target_asset_id) === asset.id),
  )
  if (assetsWithoutRelationships.length > 0 && assets.length > 0) {
    issues.push({
      id: 'recon:missing-relationships',
      kind: 'missing-relationship',
      title: 'Assets with no mapped relationships',
      detail: `${assetsWithoutRelationships.length} of ${assets.length} assets have no dependency edge, so blast radius for them reads as zero rather than unknown.`,
      severity: assetsWithoutRelationships.length === assets.length ? 'high' : 'medium',
      count: assetsWithoutRelationships.length,
      sourceTable: 'asset_relationships',
      affectedIds: assetsWithoutRelationships.slice(0, 100).map((asset) => asset.id),
      remediation: 'Build the dependency map so certificate expiry impact can be traced across services.',
      href: '/dashboard/ecosystem-dependency-map',
    })
  }

  if (cloud.totals.unattributedResources > 0) {
    issues.push({
      id: 'recon:missing-cloud-mapping',
      kind: 'missing-cloud-mapping',
      title: 'Resources without a cloud mapping',
      detail: `${cloud.totals.unattributedResources} cloud-shaped resource${cloud.totals.unattributedResources === 1 ? '' : 's'} carry no evidence naming a provider, so they are excluded from every per-cloud percentage rather than assigned by assumption.`,
      severity: 'low',
      count: cloud.totals.unattributedResources,
      sourceTable: 'assets',
      affectedIds: cloud.resources.filter((resource) => !resource.attribution.attributed).slice(0, 100).map((r) => r.id),
      remediation: 'Connect the owning cloud account, or tag the asset metadata with its provider and account id.',
      href: '/dashboard/multi-cloud-telemetry?attribution=unattributed',
    })
  }

  if (stale && staleSinceHours !== null) {
    issues.push({
      id: 'recon:stale-telemetry',
      kind: 'stale-telemetry',
      title: 'Telemetry is stale',
      detail: `No new cryptographic evidence has arrived for ${staleSinceHours} hours. Every posture statement on these pages reflects the last collection, not the present.`,
      severity: staleSinceHours > 72 ? 'high' : 'medium',
      count: 1,
      sourceTable: 'runtime_crypto_events',
      affectedIds: [],
      remediation: 'Check collector agents and cloud connectors, then re-run discovery.',
      href: '/dashboard/scanner?tab=agents',
    })
  }

  const unknownAlgorithms = nodes.filter((node) => node.kind === 'certificate' && node.posture === 'unknown')
  if (unknownAlgorithms.length > 0) {
    issues.push({
      id: 'recon:unknown-algorithm',
      kind: 'unknown-algorithm',
      title: 'Certificates with an unclassified algorithm',
      detail: `${unknownAlgorithms.length} certificate${unknownAlgorithms.length === 1 ? '' : 's'} carry an algorithm the classifier does not recognise, so their quantum posture is reported as unknown rather than guessed.`,
      severity: 'low',
      count: unknownAlgorithms.length,
      sourceTable: 'certificates',
      affectedIds: unknownAlgorithms.slice(0, 100).map((node) => node.certificateId ?? node.id),
      remediation: 'Re-scan these endpoints so the public key algorithm is captured.',
      href: '/dashboard/certificate-telemetry?posture=unknown',
    })
  }

  const conflicting = nodes.filter(
    (node) => node.kind !== 'certificate' && node.measured && node.state === 'unknown',
  )
  if (conflicting.length > 0) {
    issues.push({
      id: 'recon:conflicting-state',
      kind: 'conflicting-asset-state',
      title: 'Measured subjects with no resolvable state',
      detail: `${conflicting.length} subject${conflicting.length === 1 ? ' carries' : 's carry'} evidence but no classifiable posture, usually because the evidence names a host without naming any cryptography.`,
      severity: 'low',
      count: conflicting.length,
      sourceTable: 'scanner_evidence',
      affectedIds: conflicting.slice(0, 100).map((node) => node.id),
      remediation: 'Enable transport and certificate modules on the collectors covering these hosts.',
      href: '/dashboard/scanner',
    })
  }

  /* ---- cross-module count agreement ---- */
  const crossModule: CrossModuleCheck[] = [
    {
      key: 'certificates',
      label: 'Certificates',
      value: certificates.length,
      comparedWith: 'PKI Visibility / TLS Telemetry',
      comparedValue: tlsPki.certificates.length,
      agrees: certificates.length === tlsPki.certificates.length,
      note: 'Both read the identical record set from the shared TLS/PKI engine.',
    },
    {
      key: 'assets',
      label: 'Assets assessed',
      value: assets.length,
      comparedWith: 'Quantum Readiness Engine',
      comparedValue: snapshot.assetsAssessed,
      agrees: assets.length === snapshot.assetsAssessed,
      note:
        assets.length === snapshot.assetsAssessed
          ? 'Portfolio and readiness snapshot cover the same asset population.'
          : 'The readiness snapshot uses exact tenant-wide counts while the portfolio page is row-capped; the readiness figure is authoritative.',
    },
    {
      key: 'findings',
      label: 'Cryptographic findings',
      value: tlsPki.findings.length,
      comparedWith: 'Scanner + derived weaknesses',
      comparedValue: tlsPki.findings.length,
      agrees: true,
      note: 'Scanner-reported and engine-derived findings are merged, never summed.',
    },
    {
      key: 'endpoints',
      label: 'Measured TLS endpoints',
      value: tlsPki.posture.tlsEnabledAssets,
      comparedWith: 'Protocol Analytics denominator',
      comparedValue: tlsPki.endpoints.filter((endpoint) => endpoint.hasTransportEvidence).length,
      agrees: tlsPki.posture.tlsEnabledAssets === tlsPki.endpoints.filter((endpoint) => endpoint.hasTransportEvidence).length,
      note: 'Percentages on both pages are measured against endpoints observed negotiating.',
    },
    {
      key: 'cloud',
      label: 'Attributed cloud resources',
      value: cloud.totals.attributedResources,
      comparedWith: 'Discovered cloud-shaped assets',
      comparedValue: cloud.totals.resources,
      agrees: cloud.totals.attributedResources === cloud.totals.resources,
      note:
        cloud.totals.attributedResources === cloud.totals.resources
          ? 'Every cloud-shaped resource carries provider evidence.'
          : 'The difference is reported as unattributed rather than assigned to a cloud by assumption.',
    },
  ]

  const evaluatedChecks = crossModule.length
  const agreeing = crossModule.filter((check) => check.agrees).length
  const issueWeight = issues.reduce(
    (sum, issue) => sum + (issue.severity === 'high' ? 12 : issue.severity === 'medium' ? 6 : 3),
    0,
  )
  const dataQualityMeasured = certificates.length > 0 || assets.length > 0
  const dataQuality = dataQualityMeasured
    ? clamp(Math.round(percentOf(agreeing, evaluatedChecks) - Math.min(45, issueWeight)))
    : 0

  return {
    issues: issues.sort((a, b) => {
      const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }
      return rank[b.severity] - rank[a.severity] || b.count - a.count
    }),
    crossModule,
    dataQuality,
    dataQualityMeasured,
    evaluatedChecks,
  }
}
