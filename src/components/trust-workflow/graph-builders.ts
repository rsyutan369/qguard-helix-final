import { classifyAlgorithm } from '@/lib/migration/asset-intelligence'
import {
  READINESS_LABEL, RISK_LABEL, TRUST_NODE_LABEL,
  type CertificateDetail, type EcosystemEdge, type EcosystemNode, type ExperimentCheck,
  type ExperimentConfiguration, type ExperimentRecord, type ExperimentTarget, type Readiness,
  type RiskLevel, type TrustChain, type TrustFinding, type TrustFindingKind, type TrustNode,
  type TrustState, type VendorRecord,
} from '@/lib/ecosystem/external-trust-intelligence'
import {
  monogramOf, searchTextOf, worstStatus,
  type TracedPath, type WorkflowBadge, type WorkflowEdge, type WorkflowGraph, type WorkflowIcon,
  type WorkflowNode, type WorkflowStatus,
} from './graph-model'

/**
 * Projections of the External Trust payloads into workflow graphs.
 *
 * Each builder reads ONLY fields the server computed from tenant records and
 * emits an edge only where the payload states a relationship. Where the
 * payload's relationship is itself an inference (an issuer name matching a
 * vendor name; a root CA inferred from an issuer), the edge is marked
 * `inferred` so the canvas draws it dashed and the side panel says why.
 */

const DAY = 86_400_000

/* ------------------------------------------------------------------ */
/* Shared classification                                               */
/* ------------------------------------------------------------------ */

const WEAK_RE = /\b(MD5|SHA-?1|RC4|3?DES)\b/i
const QUANTUM_RESISTANT_SYMMETRIC_RE = /AES-?256|SHA3|SHA-?384|SHA-?512|CHACHA20/i
/** Edwards/Montgomery curves the shared classifier's RSA/EC/DH prefixes miss — all Shor-breakable. */
const MODERN_CLASSICAL_CURVE_RE = /^(X25519|X448|ED25519|ED448|CURVE25519|CURVE448)$/i

/** Classification of an algorithm NAME — a property of the algorithm, not a test result. */
export function algorithmStatus(algorithm: string): { status: WorkflowStatus; label: string } {
  if (WEAK_RE.test(algorithm)) return { status: 'critical', label: 'Broken / disallowed' }
  const klass = classifyAlgorithm(algorithm)
  if (klass === 'hybrid') return { status: 'hybrid', label: 'Hybrid PQC' }
  if (klass === 'pqc') return { status: 'verified', label: 'Post-quantum' }
  if (klass === 'vulnerable' || MODERN_CLASSICAL_CURVE_RE.test(algorithm.trim())) return { status: 'attention', label: 'Quantum-vulnerable' }
  if (QUANTUM_RESISTANT_SYMMETRIC_RE.test(algorithm)) return { status: 'verified', label: 'Quantum-resistant symmetric' }
  return { status: 'unknown', label: 'Unclassified' }
}

const RISK_STATUS: Record<RiskLevel, WorkflowStatus> = {
  critical: 'critical', high: 'attention', medium: 'attention', low: 'verified', unknown: 'unknown',
}

export const riskBadge = (risk: RiskLevel): WorkflowBadge => ({ label: `${RISK_LABEL[risk]} risk`, status: RISK_STATUS[risk] })

/* ------------------------------------------------------------------ */
/* 1 — Vendor PQC Readiness                                            */
/* ------------------------------------------------------------------ */

export const VENDOR_LANES = ['Internal consumers', 'Internal systems', 'Vendors', 'Vendor surfaces', 'Crypto & PKI dependencies']

/**
 * Vendor readiness → status. Readiness on a VendorRecord is already the
 * conservative combination of claim and measurement, so `ready` here is never
 * a bare vendor promise. A stale positive assessment is downgraded to gray.
 */
export function vendorStatus(vendor: VendorRecord, now = Date.now()): { status: WorkflowStatus; label: string; stale: boolean } {
  const reviewOverdue = vendor.nextReviewAt ? new Date(vendor.nextReviewAt).getTime() < now : false
  const old = vendor.lastAssessmentAt ? now - new Date(vendor.lastAssessmentAt).getTime() > 180 * DAY : false
  const stale = Boolean(vendor.lastAssessmentAt) && (reviewOverdue || old)
  const byReadiness: Record<Readiness, { status: WorkflowStatus; label: string }> = {
    ready: { status: 'verified', label: 'PQC ready (measured)' },
    'hybrid-ready': { status: 'hybrid', label: 'Hybrid verified' },
    preparing: { status: 'attention', label: 'Migration in progress' },
    committed: { status: 'attention', label: 'Committed — not measured' },
    'not-ready': vendor.risk === 'critical'
      ? { status: 'critical', label: 'Critical exposure' }
      : { status: 'attention', label: 'Migration required' },
    unknown: { status: 'unknown', label: vendor.lastAssessmentAt ? 'Insufficient evidence' : 'Not assessed' },
  }
  const base = byReadiness[vendor.readiness]
  if (stale && (base.status === 'verified' || base.status === 'hybrid')) {
    return { status: 'unknown', label: `Stale — was ${READINESS_LABEL[vendor.readiness]}`, stale }
  }
  return { ...base, stale }
}

function ecosystemIcon(kind: EcosystemNode['kind']): WorkflowIcon {
  switch (kind) {
    case 'service': return 'service'
    case 'infrastructure': return 'infrastructure'
    case 'identity': return 'identity'
    case 'business-service': return 'business'
    case 'pki': return 'intermediate-ca'
    case 'crypto': return 'algorithm'
    case 'protocol': return 'handshake'
    case 'vendor': return 'vendor'
    default: return 'application'
  }
}

const ECOSYSTEM_KIND_LABEL: Record<EcosystemNode['kind'], string> = {
  vendor: 'Vendor', service: 'Service', application: 'Application', identity: 'Identity system',
  pki: 'Certificate authority', crypto: 'Crypto provider', protocol: 'Protocol',
  infrastructure: 'Infrastructure', 'business-service': 'Business service',
}

/** Internal asset status is DERIVED from the vendors it consumes — labelled as inherited. */
function inheritedStatus(node: EcosystemNode | undefined): { status: WorkflowStatus; label: string } {
  if (!node) return { status: 'unknown', label: 'Not in ecosystem snapshot' }
  if (node.risk === 'critical') return { status: 'critical', label: 'Inherits critical vendor risk' }
  switch (node.readiness) {
    case 'ready': return { status: 'verified', label: 'All vendors ready' }
    case 'hybrid-ready': return { status: 'hybrid', label: 'Vendors hybrid-ready' }
    case 'preparing':
    case 'committed':
    case 'not-ready': return { status: 'attention', label: 'Blocked by vendor readiness' }
    default: return { status: 'unknown', label: 'Vendor readiness unknown' }
  }
}

export interface VendorGraphInput {
  vendors: VendorRecord[]
  ecosystem: { nodes: EcosystemNode[]; edges: EcosystemEdge[] } | null
  maxVendors?: number
  maxHostsPerVendor?: number
  maxAssetsPerVendor?: number
  /** Vendors always drawn even beyond the cap — e.g. the one a cross-page link focused. */
  pinnedVendorIds?: string[]
  now?: number
}

export function buildVendorGraph(input: VendorGraphInput): WorkflowGraph {
  const { ecosystem } = input
  const now = input.now ?? Date.now()
  const maxVendors = input.maxVendors ?? 40
  const maxHosts = input.maxHostsPerVendor ?? 6
  const maxAssets = input.maxAssetsPerVendor ?? 10

  const riskOrder: Record<RiskLevel, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 }
  const ordered = [...input.vendors].sort((a, b) =>
    (riskOrder[b.risk] - riskOrder[a.risk]) || (b.linkedAssetCount - a.linkedAssetCount) || a.name.localeCompare(b.name))
  const vendors = ordered.slice(0, maxVendors)
  for (const id of input.pinnedVendorIds ?? []) {
    const pinned = ordered.find((vendor) => vendor.id === id)
    if (pinned && !vendors.includes(pinned)) vendors.push(pinned)
  }

  const nodes = new Map<string, WorkflowNode>()
  const edges = new Map<string, WorkflowEdge>()
  const groups: WorkflowGraph['groups'] = []
  const notices: string[] = []
  const ecoNode = new Map((ecosystem?.nodes ?? []).map((node) => [node.id, node]))
  const ecoEdges = ecosystem?.edges ?? []

  const addEdge = (edge: Omit<WorkflowEdge, 'id'>) => {
    const id = `${edge.source}→${edge.target}→${edge.relation}`
    if (!edges.has(id)) edges.set(id, { ...edge, id })
  }

  if (input.vendors.length > vendors.length) {
    notices.push(`Showing ${vendors.length} of ${input.vendors.length} vendors (highest risk first). Narrow the filters to see the rest.`)
  }
  if (!ecosystem) notices.push('Ecosystem relationships are still loading — internal systems are not drawn yet.')

  let hostsCut = 0
  let assetsCut = 0
  for (const vendor of vendors) {
    const vendorId = `vendor:${vendor.id}`
    const status = vendorStatus(vendor, now)
    const algorithms = vendor.position.currentAlgorithms
    nodes.set(vendorId, {
      id: vendorId,
      kind: 'vendor',
      kindLabel: 'Vendor',
      label: vendor.name,
      sublabel: vendor.category,
      status: status.status,
      statusLabel: status.label,
      stale: status.stale,
      icon: 'vendor',
      shape: 'card',
      layer: 2,
      monogram: monogramOf(vendor.name),
      badges: [
        riskBadge(vendor.risk),
        ...(vendor.overdueRequests ? [{ label: `${vendor.overdueRequests} evidence overdue`, status: 'critical' as const }] : []),
        ...(status.stale ? [{ label: 'Stale', status: 'unknown' as const }] : []),
      ],
      meta: [
        `${vendor.linkedAssetCount} linked system${vendor.linkedAssetCount === 1 ? '' : 's'}`,
        vendor.lastAssessmentAt ? `assessed ${relativeDays(vendor.lastAssessmentAt, now)}` : 'never assessed',
      ],
      entity: { type: 'vendor', id: vendor.id },
      searchText: searchTextOf(vendor.name, vendor.category, vendor.services, vendor.businessOwner, algorithms),
    })

    /* Vendor surfaces — hosts QGuard observed and attributed to this vendor. */
    const hosts = vendor.observedHosts.slice(0, maxHosts)
    hostsCut += Math.max(0, vendor.observedHosts.length - hosts.length)
    if (hosts.length) {
      const groupId = `surfaces:${vendor.id}`
      groups.push({ id: groupId, label: `${vendor.name} surfaces`, icon: 'surface' })
      for (const host of hosts) {
        const hostId = `host:${vendor.id}:${host}`
        nodes.set(hostId, {
          id: hostId, kind: 'surface', kindLabel: 'Vendor surface', label: host,
          sublabel: vendor.name, status: 'unknown', statusLabel: 'Observed — posture per host not measured',
          icon: 'surface', shape: 'pill', layer: 3, groupId,
          entity: { type: 'host', id: host },
          searchText: searchTextOf(host, vendor.name),
        })
        addEdge({
          source: vendorId, target: hostId, relation: 'operates', label: 'Operates', provenance: 'observed',
          basis: `Host ${host} observed in tenant evidence and attributed to ${vendor.name}.`,
        })
      }
    }

    /* Observed algorithms — shared nodes, so common dependencies become visible. */
    for (const algorithm of algorithms) {
      const algorithmId = `algo:${algorithm.toLowerCase()}`
      if (!nodes.has(algorithmId)) {
        const classification = algorithmStatus(algorithm)
        nodes.set(algorithmId, {
          id: algorithmId, kind: 'algorithm', kindLabel: 'Algorithm', label: algorithm,
          status: classification.status, statusLabel: classification.label,
          icon: 'algorithm', shape: 'pill', layer: 4,
          entity: { type: 'algorithm', id: algorithm },
          searchText: searchTextOf(algorithm, classification.label),
        })
      }
      addEdge({
        source: vendorId, target: algorithmId, relation: 'uses-algorithm', label: 'Uses algorithm',
        provenance: 'observed',
        status: nodes.get(algorithmId)!.status,
        basis: `${algorithm} observed on ${vendor.name}'s surfaces. ${vendor.position.basis}`,
      })
    }

    /* Certificate authorities the ecosystem attributes to this vendor (issuer name match). */
    for (const pki of (ecosystem?.nodes ?? []).filter((node) => node.kind === 'pki' && node.vendorId === vendor.id)) {
      const caId = pki.id
      if (!nodes.has(caId)) {
        nodes.set(caId, {
          id: caId, kind: 'ca', kindLabel: 'Certificate authority', label: pki.label,
          sublabel: pki.detail, status: pki.readiness === 'ready' ? 'verified' : RISK_STATUS[pki.risk],
          statusLabel: pki.readiness === 'ready' ? 'Issues PQC certificates' : `${RISK_LABEL[pki.risk]} issuer risk`,
          icon: 'intermediate-ca', shape: 'shield', layer: 4,
          entity: { type: 'ca', id: pki.label },
          searchText: searchTextOf(pki.label, 'certificate authority', pki.algorithms),
        })
      }
      addEdge({
        source: vendorId, target: caId, relation: 'operates-ca', label: 'Operates CA', provenance: 'inferred',
        basis: `Certificate issuer "${pki.label}" matches the vendor name ${vendor.name}; no explicit ownership record.`,
      })
    }

    /* Internal systems that consume this vendor — explicit `consumes` edges. */
    const linked = vendor.linkedAssetIds.slice(0, maxAssets)
    assetsCut += Math.max(0, vendor.linkedAssetIds.length - linked.length)
    for (const assetId of linked) {
      const id = `asset:${assetId}`
      const eco = ecoNode.get(id)
      if (!ecosystem) continue
      if (!nodes.has(id)) {
        const inherited = inheritedStatus(eco)
        nodes.set(id, {
          id, kind: eco?.kind ?? 'application', kindLabel: eco ? ECOSYSTEM_KIND_LABEL[eco.kind] : 'Asset',
          label: eco?.label ?? `Asset ${assetId.slice(0, 8)}`,
          sublabel: eco ? `${eco.owner} · ${eco.environment}` : 'Not present in the ecosystem snapshot',
          status: inherited.status, statusLabel: inherited.label,
          icon: eco ? ecosystemIcon(eco.kind) : 'application', shape: 'card', layer: 1,
          entity: { type: 'asset', id: assetId },
          searchText: searchTextOf(eco?.label, eco?.owner, eco?.environment, assetId),
        })
      }
      const stored = ecoEdges.find((edge) => edge.source === id && edge.target === vendorId)
      addEdge({
        source: id, target: vendorId, relation: 'consumes', label: 'Consumes',
        provenance: stored?.explicit === false ? 'inferred' : 'explicit',
        status: status.status === 'critical' ? 'critical' : undefined,
        basis: stored?.basis ?? `Vendor intelligence links this asset to ${vendor.name}.`,
      })
      /* The asset's certificate issuer, when it is one of this vendor's CAs. */
      for (const edge of ecoEdges.filter((candidate) => candidate.source === id && candidate.kind === 'issued-by' && nodes.has(candidate.target))) {
        addEdge({
          source: id, target: edge.target, relation: 'certificate-from', label: 'Certificate from',
          provenance: edge.explicit ? 'explicit' : 'inferred', basis: edge.basis,
        })
      }
    }
  }

  /* One hop of internal consumers: assets that depend on a vendor-linked asset. */
  let consumers = 0
  for (const edge of ecoEdges) {
    if (edge.kind !== 'depends-on' || !nodes.has(edge.target) || !edge.target.startsWith('asset:')) continue
    if (nodes.has(edge.source)) {
      addEdge({ source: edge.source, target: edge.target, relation: 'depends-on', label: 'Depends on', provenance: edge.explicit ? 'explicit' : 'inferred', basis: edge.basis })
      continue
    }
    if (consumers >= 30) continue
    const eco = ecoNode.get(edge.source)
    if (!eco) continue
    consumers += 1
    nodes.set(eco.id, {
      id: eco.id, kind: eco.kind, kindLabel: ECOSYSTEM_KIND_LABEL[eco.kind], label: eco.label,
      sublabel: `${eco.owner} · ${eco.environment}`, status: 'unknown', statusLabel: 'Indirect — via an internal dependency',
      icon: ecosystemIcon(eco.kind), shape: 'card', layer: 0,
      entity: { type: 'asset', id: eco.id.slice('asset:'.length) },
      searchText: searchTextOf(eco.label, eco.owner, eco.environment),
    })
    addEdge({ source: eco.id, target: edge.target, relation: 'depends-on', label: 'Depends on', provenance: edge.explicit ? 'explicit' : 'inferred', basis: edge.basis })
  }

  if (hostsCut) notices.push(`${hostsCut} additional vendor host(s) not drawn — see each vendor's full assessment.`)
  if (assetsCut) notices.push(`${assetsCut} additional linked system(s) not drawn — open the Ecosystem Dependency Map for the full set.`)

  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    groups,
    lanes: VENDOR_LANES,
    notices,
    legend: {
      verified: 'PQC ready — measured',
      hybrid: 'Hybrid cryptography verified',
      attention: 'Migration required / incomplete',
      critical: 'Confirmed critical exposure',
      unknown: 'Unknown, unassessed or stale',
    },
  }
}

function relativeDays(iso: string, now: number): string {
  const days = Math.floor((now - new Date(iso).getTime()) / DAY)
  if (!Number.isFinite(days)) return 'unknown'
  if (days <= 0) return 'today'
  return `${days}d ago`
}

/* ------------------------------------------------------------------ */
/* 1b — Ecosystem Dependency Map                                       */
/* ------------------------------------------------------------------ */

/** Reading order matches the stored edge direction: consumer → dependency. */
export const ECOSYSTEM_LAYER_ORDER: EcosystemNode['kind'][] = [
  'business-service', 'application', 'service', 'infrastructure',
  'crypto', 'protocol', 'identity', 'pki', 'vendor',
]

const ECOSYSTEM_EDGE_LABEL: Record<EcosystemEdge['kind'], string> = {
  consumes: 'Consumes',
  'authenticates-with': 'Authenticates with',
  'secured-by': 'Secured by',
  'issued-by': 'Certificate from',
  'anchored-by': 'Anchored by',
  implements: 'Uses library',
  'federates-with': 'Federates with',
  'hosted-on': 'Hosted on',
  'depends-on': 'Depends on',
}

const ECOSYSTEM_LANE_LABEL: Record<EcosystemNode['kind'], string> = {
  'business-service': 'Business services', application: 'Applications', service: 'Services',
  infrastructure: 'Infrastructure', crypto: 'Crypto providers', protocol: 'Protocols',
  identity: 'Identity systems', pki: 'Certificate authorities', vendor: 'Vendors',
}

/** Kinds whose columns may be collapsed into one stack on a large estate. */
const GROUPABLE_KINDS = new Set<EcosystemNode['kind']>(['crypto', 'protocol', 'pki'])

/**
 * Ecosystem node → status. An internal node's readiness is INHERITED from the
 * vendors it consumes, and says so; a node with no observed evidence is gray
 * whatever its readiness field holds.
 */
export function ecosystemStatus(node: EcosystemNode): { status: WorkflowStatus; label: string } {
  if (!node.hasEvidence) return { status: 'unknown', label: 'No evidence observed' }
  const inherited = !node.external && node.kind !== 'vendor' && node.readiness !== 'unknown' ? ' · via vendors' : ''
  switch (node.readiness) {
    case 'ready': return { status: 'verified', label: `PQC ready${inherited}` }
    case 'hybrid-ready': return { status: 'hybrid', label: `Hybrid ready${inherited}` }
    case 'preparing':
    case 'committed': return { status: 'attention', label: `${READINESS_LABEL[node.readiness]}${inherited}` }
    case 'not-ready': return node.risk === 'critical'
      ? { status: 'critical', label: `Critical exposure${inherited}` }
      : { status: 'attention', label: `Not PQC-ready${inherited}` }
    default: return { status: 'unknown', label: 'Readiness unknown' }
  }
}

export interface EcosystemGraphInput {
  nodes: EcosystemNode[]
  edges: EcosystemEdge[]
  kinds?: ReadonlySet<EcosystemNode['kind']>
  criticality?: RiskLevel | 'all'
  readiness?: Readiness | 'all'
  blastRadius?: { nodeId: string; affectedNodeIds: string[]; depths: Array<{ depth: number; nodeIds: string[] }> } | null
  singlePointOfFailureIds?: string[]
  bottleneckIds?: string[]
  maxNodes?: number
  groupAbove?: number
}

export function buildEcosystemGraph(input: EcosystemGraphInput): WorkflowGraph {
  const maxNodes = input.maxNodes ?? 180
  const groupAbove = input.groupAbove ?? 14
  const notices: string[] = []
  const spof = new Set(input.singlePointOfFailureIds ?? [])
  const blockers = new Set(input.bottleneckIds ?? [])
  const blast = input.blastRadius ?? null
  const depthOf = new Map<string, number>()
  for (const ring of blast?.depths ?? []) for (const id of ring.nodeIds) depthOf.set(id, ring.depth)

  const filtered = input.nodes.filter((node) => {
    if (input.kinds?.size && !input.kinds.has(node.kind)) return false
    if (input.criticality && input.criticality !== 'all' && node.criticality !== input.criticality) return false
    if (input.readiness && input.readiness !== 'all' && node.readiness !== input.readiness) return false
    return true
  })

  /* Bound the drawing: blast-radius members first, then the riskiest and best-connected. */
  const degree = new Map<string, number>()
  for (const edge of input.edges) {
    degree.set(edge.source, (degree.get(edge.source) ?? 0) + 1)
    degree.set(edge.target, (degree.get(edge.target) ?? 0) + 1)
  }
  const riskOrder: Record<RiskLevel, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 }
  const inBlast = (id: string) => (blast && (blast.nodeId === id || depthOf.has(id)) ? 1 : 0)
  const kept = filtered.length > maxNodes
    ? [...filtered].sort((a, b) =>
      (inBlast(b.id) - inBlast(a.id))
      || (riskOrder[b.risk] - riskOrder[a.risk])
      || (riskOrder[b.criticality] - riskOrder[a.criticality])
      || ((degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0))
      || a.label.localeCompare(b.label)).slice(0, maxNodes)
    : filtered
  if (kept.length < filtered.length) {
    notices.push(`Showing ${kept.length} of ${filtered.length} nodes (blast radius, highest risk and best-connected first). Filter by type to see the rest.`)
  }
  const keptIds = new Set(kept.map((node) => node.id))

  const perKind = new Map<EcosystemNode['kind'], number>()
  for (const node of kept) perKind.set(node.kind, (perKind.get(node.kind) ?? 0) + 1)
  const groups: WorkflowGraph['groups'] = []
  for (const [kind, count] of perKind) {
    if (GROUPABLE_KINDS.has(kind) && count > groupAbove) {
      groups.push({ id: `kind:${kind}`, label: ECOSYSTEM_LANE_LABEL[kind], icon: ecosystemIcon(kind) })
    }
  }
  const groupedKinds = new Set(groups.map((group) => group.id.slice('kind:'.length)))

  const nodes: WorkflowNode[] = kept.map((node) => {
    const status = ecosystemStatus(node)
    const badges: WorkflowBadge[] = []
    if (blast?.nodeId === node.id) badges.push({ label: 'Blast radius origin', status: 'attention' })
    else if (depthOf.has(node.id)) badges.push({ label: `Affected · depth ${depthOf.get(node.id)}`, status: 'attention' })
    if (blockers.has(node.id)) badges.push({ label: 'Migration blocker', status: 'critical' })
    if (spof.has(node.id)) badges.push({ label: 'Single point of failure', status: 'attention' })
    if (node.risk !== 'unknown') badges.push(riskBadge(node.risk))
    if (node.external) badges.push({ label: 'External', status: 'unknown' })
    return {
      id: node.id,
      kind: node.kind === 'pki' ? 'ca' : node.kind,
      kindLabel: ECOSYSTEM_KIND_LABEL[node.kind],
      label: node.label,
      sublabel: node.kind === 'vendor' ? node.detail : `${node.owner} · ${node.environment}`,
      status: status.status,
      statusLabel: status.label,
      icon: ecosystemIcon(node.kind),
      shape: node.kind === 'pki' ? 'shield' : node.kind === 'crypto' || node.kind === 'protocol' ? 'pill' : 'card',
      layer: ECOSYSTEM_LAYER_ORDER.indexOf(node.kind),
      groupId: groupedKinds.has(node.kind) ? `kind:${node.kind}` : undefined,
      monogram: node.kind === 'vendor' ? monogramOf(node.label) : undefined,
      badges,
      meta: [
        ...(node.algorithms.length ? [node.algorithms.slice(0, 2).join(', ')] : []),
        `${node.assetIds.length} asset${node.assetIds.length === 1 ? '' : 's'}`,
      ],
      entity: node.kind === 'vendor' && node.vendorId
        ? { type: 'vendor', id: node.vendorId }
        : node.id.startsWith('asset:')
          ? { type: 'asset', id: node.id.slice('asset:'.length) }
          : node.kind === 'pki'
            ? { type: 'ca', id: node.label }
            : { type: 'algorithm', id: node.label },
      searchText: searchTextOf(node.label, node.owner, node.environment, node.algorithms, node.detail),
    }
  })

  const seen = new Set<string>()
  const edges: WorkflowEdge[] = []
  for (const edge of input.edges) {
    if (!keptIds.has(edge.source) || !keptIds.has(edge.target)) continue
    const id = `${edge.source}→${edge.target}→${edge.kind}`
    if (seen.has(id)) continue
    seen.add(id)
    edges.push({
      id,
      source: edge.source,
      target: edge.target,
      relation: edge.kind,
      label: ECOSYSTEM_EDGE_LABEL[edge.kind],
      provenance: edge.explicit ? 'explicit' : 'inferred',
      status: edge.risk === 'unknown' ? undefined : RISK_STATUS[edge.risk],
      basis: edge.basis,
    })
  }

  return {
    nodes,
    edges,
    groups,
    lanes: ECOSYSTEM_LAYER_ORDER.map((kind) => ECOSYSTEM_LANE_LABEL[kind]),
    notices,
    legend: {
      verified: 'PQC ready — measured',
      hybrid: 'Hybrid ready',
      attention: 'Migration required or in progress',
      critical: 'Confirmed critical exposure',
      unknown: 'Unknown, or no evidence observed',
    },
  }
}

/* ------------------------------------------------------------------ */
/* 2 — Trust Chain Analyzer                                            */
/* ------------------------------------------------------------------ */

export const TRUST_LANES = ['Trust anchors & operators', 'Certificate authorities', 'Certificates', 'Relying systems · Algorithms']

const TRUST_STATUS: Record<TrustState, { status: WorkflowStatus; label: string }> = {
  trusted: { status: 'verified', label: 'Trusted' },
  valid: { status: 'verified', label: 'Valid' },
  expiring: { status: 'attention', label: 'Expiring' },
  weak: { status: 'attention', label: 'Weak cryptography' },
  broken: { status: 'critical', label: 'Broken / expired' },
  unknown: { status: 'unknown', label: 'Not validated' },
}

const TRUST_LAYER: Record<TrustNode['kind'], number> = {
  'trust-anchor': 0, vendor: 0, federation: 0, 'root-ca': 1, 'intermediate-ca': 1,
  'identity-provider': 1, certificate: 2, service: 3, application: 3,
}

const TRUST_ICON: Record<TrustNode['kind'], WorkflowIcon> = {
  'root-ca': 'root-ca', 'intermediate-ca': 'intermediate-ca', certificate: 'certificate',
  service: 'service', application: 'application', 'trust-anchor': 'anchor',
  'identity-provider': 'identity', federation: 'identity', vendor: 'vendor',
}

/** How a finding should be read: a fact, a rule breach, or a forward-looking risk. */
export type FindingNature = 'observed-fact' | 'policy-violation' | 'inferred-risk'

export const FINDING_NATURE: Record<TrustFindingKind, FindingNature> = {
  'broken-chain': 'observed-fact',
  'expiring-certificate': 'observed-fact',
  'unknown-ca': 'observed-fact',
  'weak-algorithm': 'policy-violation',
  'legacy-signature': 'policy-violation',
  'manual-renewal': 'policy-violation',
  'missing-automation': 'policy-violation',
  'pqc-compatibility': 'inferred-risk',
  'external-ca-dependency': 'inferred-risk',
  'static-trust-anchor': 'inferred-risk',
  'vendor-dependency': 'inferred-risk',
}

export const FINDING_NATURE_LABEL: Record<FindingNature, string> = {
  'observed-fact': 'Observed facts',
  'policy-violation': 'Policy violations',
  'inferred-risk': 'Inferred risks',
}

export interface TrustGraphInput {
  chains: TrustChain[]
  findings: TrustFinding[]
  certificates: CertificateDetail[]
  showAlgorithms: boolean
  showVendors: boolean
  maxChains?: number
}

/**
 * Merges every chain into one directed trust graph. Edges point the way trust
 * is DELEGATED — anchor → CA → certificate → relying system — which is the
 * reverse of the "issued by" pointers stored on each chain.
 */
export function buildTrustGraph(input: TrustGraphInput): WorkflowGraph {
  const maxChains = input.maxChains ?? 120
  const chains = input.chains.slice(0, maxChains)
  const notices: string[] = []
  if (input.chains.length > chains.length) {
    notices.push(`Showing ${chains.length} of ${input.chains.length} chains. Filter by risk or trust state to narrow the graph.`)
  }

  const certificateById = new Map(input.certificates.map((certificate) => [`cert:${certificate.id}`, certificate]))
  const findingsByChain = new Map<string, TrustFinding[]>()
  for (const finding of input.findings) {
    if (!finding.chainId) continue
    findingsByChain.set(finding.chainId, [...(findingsByChain.get(finding.chainId) ?? []), finding])
  }

  const nodes = new Map<string, WorkflowNode>()
  const edges = new Map<string, WorkflowEdge>()
  const addEdge = (edge: Omit<WorkflowEdge, 'id'>) => {
    const id = `${edge.source}→${edge.target}→${edge.relation}`
    if (!edges.has(id)) edges.set(id, { ...edge, id })
  }

  for (const chain of chains) {
    const chainFindings = findingsByChain.get(chain.id) ?? []
    for (const trustNode of chain.nodes) {
      if (nodes.has(trustNode.id)) continue
      const base = TRUST_STATUS[trustNode.state]
      const isCertificate = trustNode.kind === 'certificate'
      const certificate = isCertificate ? certificateById.get(trustNode.id) : undefined
      const badges: WorkflowBadge[] = []
      if (isCertificate) {
        const classification = algorithmStatus(trustNode.algorithm)
        if (classification.status === 'attention' || classification.status === 'critical') badges.push({ label: classification.label, status: classification.status })
        if (chainFindings.length) {
          const worst = worstStatus(chainFindings.map((finding) => RISK_STATUS[finding.severity]))
          badges.push({ label: `${chainFindings.length} finding${chainFindings.length === 1 ? '' : 's'}`, status: worst })
        }
      }
      if (trustNode.external && trustNode.kind !== 'certificate') badges.push({ label: 'External', status: 'unknown' })
      // The engine reports ONE state per certificate and ranks a weak signature
      // above expiry; an expired certificate must still read red here.
      const expired = (certificate?.daysToExpiry ?? 0) < 0
      const nodeStatus = expired ? 'critical' : base.status
      const statusLabel = trustNode.kind === 'application'
        ? 'Relying party — not validated'
        : expired && trustNode.state !== 'broken' ? `Expired · ${base.label.toLowerCase()}` : base.label
      nodes.set(trustNode.id, {
        id: trustNode.id,
        kind: trustNode.kind,
        kindLabel: TRUST_NODE_LABEL[trustNode.kind],
        label: trustNode.label,
        // A CA node carries the LEAF's algorithm in the payload, so it is not
        // shown as the CA's own key algorithm.
        sublabel: isCertificate ? trustNode.detail : trustNode.kind === 'application' ? trustNode.detail : undefined,
        status: nodeStatus,
        statusLabel,
        icon: TRUST_ICON[trustNode.kind],
        shape: trustNode.kind === 'certificate' ? 'document'
          : trustNode.kind === 'application' || trustNode.kind === 'service' ? 'card' : 'shield',
        layer: TRUST_LAYER[trustNode.kind],
        inferred: trustNode.kind === 'trust-anchor',
        badges,
        meta: certificate?.daysToExpiry !== null && certificate?.daysToExpiry !== undefined
          ? [certificate.daysToExpiry < 0 ? `expired ${Math.abs(certificate.daysToExpiry)}d ago` : `expires in ${certificate.daysToExpiry}d`]
          : undefined,
        entity: isCertificate
          ? { type: 'certificate', id: trustNode.id.slice('cert:'.length) }
          : trustNode.kind === 'application'
            ? { type: 'asset', id: trustNode.id.slice('asset:'.length) }
            : trustNode.kind === 'trust-anchor'
              ? { type: 'anchor', id: trustNode.label }
              : { type: 'ca', id: trustNode.label },
        // Only a certificate's own algorithm is searchable — CA nodes carry the leaf's.
        searchText: searchTextOf(trustNode.label, isCertificate ? trustNode.algorithm : '', trustNode.detail, certificate?.issuer, certificate?.owner),
      })
    }

    for (const stored of chain.edges) {
      const from = chain.nodes.find((node) => node.id === stored.source)
      const to = chain.nodes.find((node) => node.id === stored.target)
      if (!from || !to) continue
      if (from.kind === 'application' && to.kind === 'certificate') {
        addEdge({
          source: to.id, target: from.id, relation: 'authenticates', label: 'Authenticates', provenance: 'explicit',
          status: nodes.get(to.id)?.status,
          basis: `Certificate inventory binds "${to.label}" to asset "${from.label}" (certificates.asset_id).`,
        })
      } else if (from.kind === 'certificate') {
        const selfSigned = to.kind === 'root-ca'
        addEdge({
          source: to.id, target: from.id, relation: selfSigned ? 'self-signs' : 'issued', label: selfSigned ? 'Self-signs' : 'Issued',
          provenance: 'explicit', status: nodes.get(from.id)?.status,
          basis: `Issuer field of certificate "${from.label}" names "${to.label}".`,
        })
      } else if (to.kind === 'trust-anchor') {
        addEdge({
          source: to.id, target: from.id, relation: 'anchors', label: 'Anchors (inferred)', provenance: 'inferred',
          basis: `Root of trust inferred from issuer "${from.label}"; the root certificate itself was not captured.`,
        })
      }
    }

    if (input.showVendors) {
      for (const ca of chain.nodes.filter((node) => node.vendorId && (node.kind === 'intermediate-ca' || node.kind === 'root-ca'))) {
        const vendorNodeId = `vendor:${ca.vendorId}`
        if (!nodes.has(vendorNodeId)) {
          nodes.set(vendorNodeId, {
            id: vendorNodeId, kind: 'vendor', kindLabel: 'Vendor', label: ca.label, sublabel: 'Vendor register entry',
            status: 'unknown', statusLabel: 'See vendor readiness', icon: 'vendor', shape: 'card', layer: 0,
            monogram: monogramOf(ca.label), entity: { type: 'vendor', id: ca.vendorId! },
            searchText: searchTextOf(ca.label, 'vendor'),
          })
        }
        addEdge({
          source: vendorNodeId, target: ca.id, relation: 'operates', label: 'Operates (name match)', provenance: 'inferred',
          basis: `Issuer "${ca.label}" matches a vendor record by name; ownership is not explicitly recorded.`,
        })
      }
    }

    if (input.showAlgorithms) {
      const certificateNode = chain.nodes.find((node) => node.kind === 'certificate')
      const certificate = certificateNode ? certificateById.get(certificateNode.id) : undefined
      if (certificateNode && certificate) {
        const algorithms: Array<[string, string, string]> = [[certificate.publicKeyAlgorithm, 'public-key', 'Public key']]
        if (certificate.signatureAlgorithm && certificate.signatureAlgorithm !== certificate.publicKeyAlgorithm) {
          algorithms.push([certificate.signatureAlgorithm, 'signed-with', 'Signed with'])
        }
        for (const [algorithm, relation, label] of algorithms) {
          if (!algorithm || /unavailable/i.test(algorithm)) continue
          const id = `alg:${algorithm.toLowerCase()}`
          if (!nodes.has(id)) {
            const classification = algorithmStatus(algorithm)
            nodes.set(id, {
              id, kind: 'algorithm', kindLabel: 'Algorithm', label: algorithm,
              status: classification.status, statusLabel: classification.label,
              icon: 'algorithm', shape: 'pill', layer: 3,
              entity: { type: 'algorithm', id: algorithm },
              searchText: searchTextOf(algorithm, classification.label),
            })
          }
          addEdge({
            source: certificateNode.id, target: id, relation, label, provenance: 'observed',
            status: nodes.get(id)!.status,
            basis: relation === 'public-key'
              ? `Public-key algorithm recorded for "${certificate.subject}".`
              : `Signature algorithm recorded in scanner metadata for "${certificate.subject}".`,
          })
        }
      }
    }
  }

  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    groups: [],
    lanes: TRUST_LANES,
    notices,
    legend: {
      verified: 'Valid / trusted chain element',
      hybrid: 'Hybrid post-quantum element',
      attention: 'Expiring, weak or quantum-vulnerable',
      critical: 'Broken or expired',
      unknown: 'Not validated / inferred',
    },
  }
}

export type PathVerdict = 'trusted' | 'untrusted' | 'unknown'

export interface PathExplanation {
  verdict: PathVerdict
  summary: string
  reasons: Array<{ status: WorkflowStatus; text: string }>
}

/** Why a traced path is trusted, untrusted or unknown — every reason names its evidence. */
export function explainTrustPath(path: TracedPath, nodeById: Map<string, WorkflowNode>): PathExplanation {
  const reasons: PathExplanation['reasons'] = []
  const nodes = path.nodeIds.map((id) => nodeById.get(id)).filter((node): node is WorkflowNode => Boolean(node))
  if (!path.directed) {
    reasons.push({ status: 'unknown', text: 'No trust flows in this direction — the nodes are related, but neither delegates trust to the other along stored edges.' })
  }
  for (const node of nodes) {
    if (node.status === 'critical') reasons.push({ status: 'critical', text: `${node.kindLabel} "${node.label}" is ${node.statusLabel.toLowerCase()}.` })
    else if (node.status === 'attention') reasons.push({ status: 'attention', text: `${node.kindLabel} "${node.label}": ${node.statusLabel.toLowerCase()}.` })
    else if (node.inferred) reasons.push({ status: 'unknown', text: `${node.kindLabel} "${node.label}" is inferred — its certificate was not captured, so the anchor cannot be validated.` })
    else if (node.status === 'unknown' && node.kind !== 'application' && node.kind !== 'algorithm') {
      reasons.push({ status: 'unknown', text: `${node.kindLabel} "${node.label}" has not been validated.` })
    }
  }
  for (const edge of path.edges) {
    if (edge.provenance === 'inferred') reasons.push({ status: 'unknown', text: `"${edge.label}" is inferred: ${edge.basis}` })
  }
  const hasCritical = reasons.some((reason) => reason.status === 'critical')
  const hasUnknown = reasons.some((reason) => reason.status === 'unknown')
  const verdict: PathVerdict = hasCritical ? 'untrusted' : hasUnknown || !path.directed ? 'unknown' : 'trusted'
  const summary = verdict === 'untrusted'
    ? 'Untrusted — at least one element on this path is broken or expired.'
    : verdict === 'unknown'
      ? 'Unknown — the path depends on an element or relationship that has not been validated.'
      : reasons.length
        ? 'Trusted, with warnings — every element validates, but some need attention before migration.'
        : 'Trusted — every element on this path validates from stored certificate evidence.'
  if (verdict === 'trusted' && !reasons.length) {
    reasons.push({ status: 'verified', text: `${path.edges.length} hop(s), all backed by certificate inventory records.` })
  }
  return { verdict, summary, reasons }
}

/* ------------------------------------------------------------------ */
/* 3 — Hybrid Crypto Lab                                               */
/* ------------------------------------------------------------------ */

export type LabMode = 'classical' | 'hybrid' | 'post-quantum'

export const LAB_MODE_PROFILE: Record<LabMode, Pick<ExperimentConfiguration, 'keyExchange' | 'signature'>> = {
  classical: { keyExchange: 'X25519', signature: 'Ed25519' },
  hybrid: { keyExchange: 'X25519+ML-KEM-768', signature: 'Ed25519+ML-DSA-65' },
  'post-quantum': { keyExchange: 'ML-KEM-768', signature: 'ML-DSA-65' },
}

export function modeOf(config: Pick<ExperimentConfiguration, 'keyExchange' | 'signature'>): LabMode | 'custom' {
  for (const [mode, profile] of Object.entries(LAB_MODE_PROFILE) as Array<[LabMode, typeof LAB_MODE_PROFILE[LabMode]]>) {
    if (profile.keyExchange === config.keyExchange && profile.signature === config.signature) return mode
  }
  return 'custom'
}

/** Latest experiment for this target AND this key-establishment/signature profile. */
export function latestExperimentFor(
  experiments: ExperimentRecord[],
  targetId: string,
  config: Pick<ExperimentConfiguration, 'keyExchange' | 'signature'>,
): ExperimentRecord | null {
  return experiments
    .filter((experiment) => experiment.target.id === targetId
      && experiment.proposedConfiguration.keyExchange === config.keyExchange
      && experiment.proposedConfiguration.signature === config.signature)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0] ?? null
}

/** A check verdict → status. Green only for a MEASURED pass; evidence-derived passes are blue. */
export function checkStatus(check: ExperimentCheck | undefined, tested: boolean): { status: WorkflowStatus; label: string } {
  if (!tested) return { status: 'unknown', label: 'Not tested for this profile' }
  if (!check) return { status: 'unknown', label: 'Not covered by the test' }
  if (check.verdict === 'pass') return check.method === 'measured'
    ? { status: 'verified', label: 'Measured pass' }
    : { status: 'hybrid', label: 'Pass — evidence-derived' }
  if (check.verdict === 'fail') return { status: 'critical', label: check.method === 'measured' ? 'Measured failure' : 'Fails on stored evidence' }
  return { status: 'unknown', label: check.method === 'not-evaluated' ? 'Not evaluated' : 'Undetermined' }
}

export interface LabGraphInput {
  config: ExperimentConfiguration
  target: ExperimentTarget | null
  experiment: ExperimentRecord | null
  executionMode: 'simulation' | 'controlled-test'
}

/** Role notes keep key establishment, signatures and symmetric encryption visibly distinct. */
export const ALGORITHM_ROLE: Record<string, string> = {
  X25519: 'Classical elliptic-curve Diffie–Hellman key agreement. Broken by a cryptographically relevant quantum computer (Shor).',
  'ML-KEM-768': 'Module-lattice key ENCAPSULATION mechanism (FIPS 203). Establishes a shared secret — it does not sign anything.',
  Ed25519: 'Classical EdDSA signature. Authenticates the handshake; quantum-vulnerable (Shor).',
  'ML-DSA-65': 'Module-lattice digital SIGNATURE (FIPS 204). Authenticates — it does not establish keys.',
  'AES-256-GCM': 'Authenticated symmetric encryption for application data. 256-bit keys keep a quantum security margin against Grover.',
}

export function buildLabGraph(input: LabGraphInput): WorkflowGraph {
  const { config, experiment, target } = input
  const tested = Boolean(experiment)
  const checks = new Map((experiment?.checks ?? []).map((check) => [check.key, check]))
  const probe = experiment?.probe ?? null
  const kexParts = config.keyExchange.split('+')
  const sigParts = config.signature.split('+')
  const hybridKex = kexParts.length > 1
  const hybridSig = sigParts.length > 1
  const nodes: WorkflowNode[] = []
  const edges: WorkflowEdge[] = []

  const step = (node: Omit<WorkflowNode, 'searchText' | 'shape'> & { shape?: WorkflowNode['shape'] }) => {
    nodes.push({ shape: 'step', ...node, searchText: searchTextOf(node.label, node.sublabel, node.meta, node.kindLabel) })
  }
  const link = (source: string, target: string, label: string, basis: string, relation = label.toLowerCase().replace(/\s+/g, '-')) => {
    edges.push({ id: `${source}→${target}`, source, target, relation, label, provenance: 'configured', basis })
  }

  const protocolCheck = checkStatus(checks.get('protocol'), tested)
  const cryptoCheck = checkStatus(checks.get('crypto'), tested)
  const certificateCheck = checkStatus(checks.get('certificate'), tested)
  const chainCheck = checkStatus(checks.get('trust-chain'), tested)
  const policyCheck = checkStatus(checks.get('policy'), tested)
  const applicationCheck = checkStatus(checks.get('application'), tested)

  step({
    id: 'client', kind: 'client', kindLabel: 'Client', label: input.executionMode === 'controlled-test' ? 'QGuard probe client' : 'Relying client (modelled)',
    sublabel: input.executionMode === 'controlled-test' ? 'Read-only TLS handshake' : 'Simulation — no connection opened',
    status: 'unknown', statusLabel: input.executionMode === 'controlled-test' ? 'Initiates handshake' : 'Projection only',
    icon: 'client', layer: 0, entity: { type: 'step', id: 'client' },
  })
  step({
    id: 'handshake', kind: 'handshake', kindLabel: 'Protocol', label: `${config.protocol} handshake`,
    sublabel: target ? `${target.host}:${target.port}` : 'No target selected',
    status: protocolCheck.status, statusLabel: protocolCheck.label, icon: 'handshake', layer: 1,
    meta: probe?.measured && probe.negotiatedProtocol ? [`negotiated ${probe.negotiatedProtocol}`] : undefined,
    entity: { type: 'step', id: 'protocol' },
  })
  link('client', 'handshake', 'ClientHello', 'TLS 1.3 handshake order (RFC 8446).')

  /* Key establishment — the classical and post-quantum components are separate nodes. */
  const kexIds: string[] = []
  for (const part of kexParts) {
    const isKem = /ML-KEM/i.test(part)
    const id = isKem ? 'kem' : 'ecdh'
    kexIds.push(id)
    const classification = algorithmStatus(part)
    const accepted = probe?.measured ? [...probe.hybridGroups, ...probe.pureKemGroups] : []
    step({
      id, kind: isKem ? 'kem' : 'key-exchange', kindLabel: isKem ? 'Key encapsulation (KEM)' : 'Key agreement (ECDH)',
      label: part, sublabel: isKem ? 'FIPS 203 · encapsulation' : 'Ephemeral ECDHE',
      status: cryptoCheck.status, statusLabel: cryptoCheck.label, icon: isKem ? 'kem' : 'key-exchange', layer: 2,
      badges: [{ label: classification.label, status: classification.status }],
      meta: isKem && accepted.length ? [`accepted: ${accepted.join(', ')}`] : undefined,
      entity: { type: 'step', id: 'crypto' },
    })
    link('handshake', id, isKem ? 'key_share (KEM)' : 'key_share (ECDH)', 'Key share offered in the ClientHello supported_groups/key_share extensions.')
  }

  const secretId = 'secret'
  step({
    id: secretId, kind: 'secret', kindLabel: 'Shared secret',
    label: hybridKex ? 'Combined shared secret' : 'Shared secret',
    sublabel: hybridKex ? 'X25519 ‖ ML-KEM outputs concatenated' : kexParts[0] === 'ML-KEM-768' ? 'KEM decapsulation output' : 'ECDH output',
    status: cryptoCheck.status, statusLabel: cryptoCheck.label, icon: 'secret', layer: 3,
    entity: { type: 'step', id: 'crypto' },
  })
  for (const id of kexIds) link(id, secretId, hybridKex ? 'Contributes secret' : 'Produces secret', hybridKex
    ? 'Hybrid groups concatenate both component secrets so the session stays secure if either component holds.'
    : 'The key-establishment output becomes the handshake secret.')

  step({
    id: 'kdf', kind: 'kdf', kindLabel: 'Key derivation', label: 'HKDF key schedule',
    sublabel: `Configured ${config.kdf}`,
    status: policyCheck.status, statusLabel: policyCheck.label, icon: 'kdf', layer: 4,
    meta: ['TLS 1.3 traffic keys use the suite hash'],
    entity: { type: 'step', id: 'policy' },
  })
  link(secretId, 'kdf', 'Extract & expand', 'RFC 8446 §7.1 key schedule (HKDF-Extract / HKDF-Expand-Label).')

  /* Authentication — a separate branch: signatures authenticate, they do not establish keys. */
  const sigIds: string[] = []
  sigParts.forEach((part, index) => {
    const id = `sig-${index}`
    sigIds.push(id)
    const classification = algorithmStatus(part)
    step({
      id, kind: 'signature', kindLabel: 'Digital signature', label: part,
      sublabel: /ML-DSA/i.test(part) ? 'FIPS 204 · authentication' : 'Certificate / CertificateVerify',
      status: certificateCheck.status, statusLabel: certificateCheck.label, icon: 'signature', layer: 2,
      badges: [{ label: classification.label, status: classification.status }],
      meta: index === 0 && probe?.measured && probe.certificateAlgorithm ? [`served: ${probe.certificateAlgorithm}`] : undefined,
      entity: { type: 'step', id: 'certificate' },
    })
    link('handshake', id, 'Certificate', 'Server Certificate and CertificateVerify messages.')
  })
  step({
    id: 'chain', kind: 'chain', kindLabel: 'Certificate validation', label: 'Chain validation',
    sublabel: hybridSig ? 'Composite certificate — CA support unverified' : 'Issuer path to a trust anchor',
    status: chainCheck.status, statusLabel: chainCheck.label, icon: 'chain', layer: 3,
    meta: probe?.measured && probe.chainLength ? [`${probe.chainLength} cert(s) in chain`] : undefined,
    entity: { type: 'step', id: 'trust-chain' },
  })
  for (const id of sigIds) link(id, 'chain', 'Verify signature', 'Each signature in the chain is verified up to a trust anchor.')

  step({
    id: 'session', kind: 'session', kindLabel: 'Session', label: 'Authenticated session keys',
    sublabel: 'Client/server traffic secrets',
    // Only as good as the weaker of its two inputs — an unvalidated chain keeps it gray.
    status: tested ? worstStatus([cryptoCheck.status, chainCheck.status]) : 'unknown',
    statusLabel: tested ? 'Weaker of key exchange and authentication' : 'Not tested for this profile',
    icon: 'session', layer: 5, entity: { type: 'step', id: 'session' },
  })
  link('kdf', 'session', 'Derives traffic keys', 'Handshake and application traffic secrets are expanded from the key schedule.')
  link('chain', 'session', 'Authenticates handshake', 'CertificateVerify binds the server identity to the handshake transcript.')

  step({
    id: 'cipher', kind: 'cipher', kindLabel: 'Symmetric encryption', label: config.symmetric,
    sublabel: 'Encrypted application data',
    status: applicationCheck.status, statusLabel: applicationCheck.label, icon: 'cipher', layer: 6,
    badges: [{ label: algorithmStatus(config.symmetric).label, status: algorithmStatus(config.symmetric).status }],
    entity: { type: 'step', id: 'application' },
  })
  link('session', 'cipher', 'Encrypts records', 'AEAD record protection with the derived traffic keys.')

  const outcomeStatus: WorkflowStatus = !experiment ? 'unknown'
    : experiment.outcome === 'passed' ? 'verified'
      : experiment.outcome === 'failed' ? 'critical'
        : experiment.outcome === 'not-evaluated' ? 'unknown' : 'attention'
  step({
    id: 'telemetry', kind: 'telemetry', kindLabel: 'Validation & telemetry', label: 'Validation result',
    sublabel: experiment ? `${experiment.executionMode} · ${experiment.durationMs}ms` : 'No experiment recorded for this profile',
    status: outcomeStatus,
    statusLabel: experiment ? experiment.outcome.replace(/-/g, ' ') : 'Run a test to validate',
    icon: 'telemetry', layer: 7,
    meta: experiment ? [`${experiment.checks.filter((check) => check.method === 'measured').length} measured · ${experiment.findings.length} finding(s)`] : undefined,
    entity: { type: 'step', id: 'telemetry' },
  })
  link('cipher', 'telemetry', 'Validated by', 'Per-dimension verdicts recorded by the lab experiment.')

  const vendorCheck = checks.get('vendor')
  if (target?.vendorId) {
    const vendor = checkStatus(vendorCheck, tested)
    step({
      id: 'vendor', kind: 'vendor', kindLabel: 'Vendor dependency', label: 'Vendor readiness',
      sublabel: vendorCheck?.detail ?? 'Vendor attributed to this target',
      status: vendor.status, statusLabel: vendor.label, icon: 'vendor', shape: 'card', layer: 7,
      entity: { type: 'vendor', id: target.vendorId },
    })
    link('handshake', 'vendor', 'Terminated by', 'The target endpoint is attributed to this vendor in the register.')
  }

  return {
    nodes, edges, groups: [],
    lanes: ['Client', 'Handshake', 'Key exchange · Signature', 'Secret · Chain', 'Derivation', 'Session', 'Encryption', 'Validation'],
    notices: [],
    legend: {
      verified: 'Measured pass (live handshake)',
      hybrid: 'Pass derived from stored evidence',
      attention: 'Conditional / warnings',
      critical: 'Failed',
      unknown: 'Not tested or not evaluated',
    },
  }
}
