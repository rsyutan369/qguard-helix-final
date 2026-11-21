/**
 * Estate graphs for the shared workflow canvas.
 *
 * The canvas never receives the whole estate. Each level is a bounded,
 * server-built projection:
 *   - root-cause    issuer / library / algorithm → fix → owner   (≤ 40 fixes)
 *   - neighbourhood one fix or one asset and what it touches     (≤ 60 members)
 *   - campaign      the fix's migration pipeline as steps
 * Anything left out is disclosed in `notices`.
 */
import { searchTextOf, type WorkflowEdge, type WorkflowGraph, type WorkflowNode, type WorkflowStatus } from '@/components/trust-workflow/graph-model'
import type { FindingSeverity, QuantumStatus } from '@/lib/scanner/exposure/types'
import { OWNER_SOURCE_LABEL, SEVERITY_RANK, type CertificateIdentity, type EstateAsset, type Observation } from './model'
import { FIX_KIND_LABEL, MEMBER_STATUS_LABEL, type ClusterState, type MemberStatus } from './clusters'
import { mapGroupValue, type Campaign, type MapAsset } from './views'

export const ROOT_CAUSE_LIMIT = 40
export const NEIGHBOURHOOD_LIMIT = 60

const LEGEND: WorkflowGraph['legend'] = {
  critical: 'Critical exposure open',
  attention: 'Open — needs migration',
  unknown: 'Low / not yet classified',
  hybrid: 'In flight',
  verified: 'Validated / PQC-safe',
}

export function severityStatus(severity: FindingSeverity): WorkflowStatus {
  if (severity === 'critical') return 'critical'
  if (severity === 'high' || severity === 'medium') return 'attention'
  return 'unknown'
}

function memberStatus(status: MemberStatus, severity: FindingSeverity): WorkflowStatus {
  if (status === 'validated') return 'verified'
  if (status === 'planned' || status === 'running' || status === 'awaiting-validation') return 'hybrid'
  if (status === 'failed' || status === 'regressed') return 'critical'
  return severityStatus(severity)
}

const nodeKey = (value: string) => encodeURIComponent(value.toLowerCase())

const VERDICT_LABEL: Record<QuantumStatus, string> = {
  pqc: 'Post-quantum', hybrid: 'Hybrid', resistant: 'Quantum-resistant', vulnerable: 'Quantum-vulnerable',
  unknown: 'Unclassified', 'not-applicable': 'Not applicable',
}

class GraphBuilder {
  nodes = new Map<string, WorkflowNode>()
  edges = new Map<string, WorkflowEdge>()
  notices: string[] = []
  groups = new Map<string, { id: string; label: string; icon: WorkflowNode['icon'] }>()

  node(node: Omit<WorkflowNode, 'searchText'> & { searchText?: string }) {
    if (!this.nodes.has(node.id)) {
      this.nodes.set(node.id, { ...node, searchText: node.searchText ?? searchTextOf(node.label, node.sublabel, node.kindLabel, node.meta) })
    }
    return node.id
  }

  edge(source: string, target: string, relation: string, label: string, provenance: WorkflowEdge['provenance'], basis: string, status?: WorkflowStatus) {
    const id = `${source}->${target}:${relation}`
    if (!this.edges.has(id)) this.edges.set(id, { id, source, target, relation, label, provenance, basis, status })
  }

  build(lanes: string[]): WorkflowGraph {
    return { nodes: [...this.nodes.values()], edges: [...this.edges.values()], groups: [...this.groups.values()], lanes, notices: this.notices, legend: LEGEND }
  }
}

function fixNode(builder: GraphBuilder, state: ClusterState, layer: number) {
  const c = state.cluster
  const open = c.assets - c.progress.validated
  const status: WorkflowStatus = open === 0 ? 'verified' : severityStatus(c.severity)
  builder.groups.set(c.kind, { id: c.kind, label: FIX_KIND_LABEL[c.kind], icon: 'group' })
  return builder.node({
    id: `fix:${c.id}`,
    kind: 'fix',
    kindLabel: `Fix #${c.priorityRank} · ${c.kindLabel}`,
    label: c.title,
    sublabel: c.target ?? c.targetNote ?? undefined,
    status,
    statusLabel: open === 0 ? 'All validated' : `${open} of ${c.assets} assets open`,
    icon: 'chain',
    shape: 'step',
    layer,
    groupId: c.kind,
    badges: [{ label: `Priority ${c.priority}`, status }, { label: c.deadline.year === 0 ? 'Now' : c.deadline.year === null ? 'Review timing' : String(c.deadline.year), status: c.deadline.year === 0 ? 'critical' : 'attention' }],
    meta: [`${c.observations} findings`, `${c.uniqueComponents} unique`, `≈${c.effort.days} d`],
  })
}

function rootNode(builder: GraphBuilder, state: ClusterState, layer: number) {
  const { type, label } = state.cluster.rootCause
  const icon = type === 'issuer' ? 'intermediate-ca' : type === 'library' ? 'application' : 'algorithm'
  const kindLabel = type === 'issuer' ? 'Issuing CA' : type === 'library' ? 'Library' : 'Algorithm'
  return builder.node({
    id: `root:${type}:${nodeKey(label)}`,
    kind: `root-${type}`,
    kindLabel,
    label,
    status: severityStatus(state.cluster.severity),
    statusLabel: 'Root cause',
    icon,
    shape: type === 'issuer' ? 'shield' : 'pill',
    layer,
  })
}

function ownerNode(builder: GraphBuilder, owner: string | null, layer: number, source?: string) {
  return builder.node({
    id: owner ? `owner:recorded:${nodeKey(owner)}` : 'owner:unowned',
    kind: 'owner',
    kindLabel: owner ? 'Owner' : 'No owner recorded',
    label: owner ?? 'Unowned',
    sublabel: source,
    status: owner ? 'unknown' : 'attention',
    statusLabel: owner ? 'Accountable owner' : 'Assign an owner',
    icon: owner ? 'organization' : 'identity',
    shape: 'card',
    layer,
  })
}

/* ------------------------------------------------------------------ */
/* Level 1 — root causes                                               */
/* ------------------------------------------------------------------ */

export function rootCauseGraph(states: ClusterState[]): WorkflowGraph {
  const builder = new GraphBuilder()
  const shown = states.slice(0, ROOT_CAUSE_LIMIT)
  if (states.length > shown.length) builder.notices.push(`Showing the ${shown.length} highest-priority fixes of ${states.length}. Lower-priority fixes are listed in the Fix plan.`)
  for (const state of shown) {
    const root = rootNode(builder, state, 0)
    const fix = fixNode(builder, state, 1)
    const c = state.cluster
    builder.edge(root, fix, 'resolved-by', c.certificates ? `${c.certificates.unique} certs` : `${c.uniqueComponents} components`, 'configured',
      'Every finding with this root cause is routed to this fix (one finding → one fix).', severityStatus(c.severity))
    for (const owner of c.owners.slice(0, 3)) {
      builder.edge(fix, ownerNode(builder, owner.owner, 2), 'owned-by', `${owner.assets} assets`, 'explicit', 'Owner read from the asset record or its tags.')
    }
    if (c.owners.length > 3) {
      const rest = c.owners.slice(3).reduce((sum, owner) => sum + owner.assets, 0)
      const id = builder.node({ id: `owner-more:${c.id}`, kind: 'owner', kindLabel: 'Other owners', label: `${c.owners.length - 3}+ more owners`, status: 'unknown', statusLabel: `${rest} assets`, icon: 'group', shape: 'pill', layer: 2 })
      builder.edge(fix, id, 'owned-by', `${rest} assets`, 'explicit', 'Remaining owners of this fix, collapsed.')
    }
    if (c.unownedAssets) builder.edge(fix, ownerNode(builder, null, 2), 'owner-missing', `${c.unownedAssets} unassigned`, 'configured', 'No accountable owner was recorded for these fix members.', 'attention')
  }
  return builder.build(['Root cause', 'Fix', 'Accountable owner'])
}

/* ------------------------------------------------------------------ */
/* Level 2 — neighbourhood of a fix                                    */
/* ------------------------------------------------------------------ */

function assetNode(builder: GraphBuilder, asset: EstateAsset | undefined, assetId: string, layer: number, status: WorkflowStatus, statusLabel: string) {
  return builder.node({
    id: `asset:${assetId}`,
    kind: 'asset',
    kindLabel: asset ? [asset.type.replace(/[_-]+/g, ' '), mapGroupValue(asset, 'environment')].filter(Boolean).join(' · ') || 'Asset' : 'Asset',
    label: asset?.name ?? assetId,
    sublabel: asset?.service ?? undefined,
    status,
    statusLabel,
    icon: 'infrastructure',
    shape: 'card',
    layer,
    entity: { type: 'asset', id: assetId },
  })
}

function linkOwner(builder: GraphBuilder, asset: EstateAsset, id: string, layer: number) {
  if (!asset.owner) return
  const source = asset.ownerSource ? OWNER_SOURCE_LABEL[asset.ownerSource] : 'asset record'
  builder.edge(id, ownerNode(builder, asset.owner, layer, source), 'owned-by', 'Owned by', 'explicit', `Owner from ${source}.`)
}

function assetPosture(asset: MapAsset): [WorkflowStatus, string] {
  if (asset.openFixes) return [severityStatus(asset.severity ?? 'info'), `${asset.openFixes} open ${asset.openFixes === 1 ? 'fix' : 'fixes'}`]
  if (!asset.evidence.classified && !asset.evidence.unclassified) return ['unknown', 'No crypto evidence loaded']
  if (asset.evidence.unclassified) return ['unknown', 'Unclassified evidence']
  return ['unknown', 'No open fixes recorded']
}

export function fixNeighbourhood(state: ClusterState, assets: Map<string, EstateAsset>, certificates: CertificateIdentity[]): WorkflowGraph {
  const builder = new GraphBuilder()
  const isCa = state.cluster.kind === 'ca-reissue'
  const root = rootNode(builder, state, 0)
  const fix = fixNode(builder, state, isCa ? 2 : 1)
  const members = [...state.members.entries()].filter(([id]) => assets.has(id)).sort((a, b) => b[1].weight - a[1].weight)
  if (members.length < state.members.size) builder.notices.push(`${state.members.size - members.length} fix members have no asset record in this snapshot.`)
  const shown = members.slice(0, NEIGHBOURHOOD_LIMIT)
  if (members.length > shown.length) builder.notices.push(`Showing the ${shown.length} highest-risk assets of ${members.length}. Open the fix's asset list for the rest.`)

  if (isCa) {
    const certs = certificates.filter((certificate) => state.certificateKeys.has(certificate.key))
      .sort((a, b) => b.assetIds.size - a.assetIds.size)
    const certShown = certs.slice(0, 30)
    if (certs.length > certShown.length) builder.notices.push(`Showing 30 of ${certs.length} certificates (most widely deployed first).`)
    for (const certificate of certShown) {
      const id = builder.node({
        id: `cert:${nodeKey(certificate.key)}`,
        kind: 'certificate',
        kindLabel: certificate.assetIds.size > 1 ? `Certificate · reused on ${certificate.assetIds.size} assets` : 'Certificate',
        label: certificate.subject || certificate.key,
        sublabel: `${certificate.algorithm}${certificate.keySize ? `-${certificate.keySize}` : ''} · ${certificate.keyBasis}`,
        status: severityStatus(certificate.severity),
        statusLabel: certificate.notAfter ? `Expires ${new Date(certificate.notAfter).toISOString().slice(0, 10)}` : 'Expiry not recorded',
        icon: 'certificate',
        shape: 'document',
        layer: 1,
        entity: { type: 'certificate', id: certificate.key },
      })
      if (certificate.issuer) builder.edge(root, id, 'issued', 'Issued', 'observed', 'Issuer read from the certificate record.')
      builder.edge(id, fix, 'resolved-by', 'Re-issue', 'configured', 'This certificate is re-issued by the fix.')
    }
  } else {
    builder.edge(root, fix, 'resolved-by', `${state.cluster.uniqueComponents} components`, 'configured', 'Findings with this root cause are routed to this fix.')
  }

  for (const [assetId, member] of shown) {
    const asset = assets.get(assetId)
    const status = memberStatus(member.status, member.severity)
    const id = assetNode(builder, asset, assetId, isCa ? 3 : 2, status, MEMBER_STATUS_LABEL[member.status])
    builder.edge(fix, id, 'applies-to', `${member.observations} finding${member.observations === 1 ? '' : 's'}`, 'observed', 'Scan evidence on this asset is resolved by the fix.', status)
    if (asset) linkOwner(builder, asset, id, isCa ? 4 : 3)
  }
  return builder.build(isCa ? ['Issuing CA', 'Certificate', 'Fix', 'Asset', 'Owner'] : ['Root cause', 'Fix', 'Asset', 'Owner'])
}

/* ------------------------------------------------------------------ */
/* Level 2 — neighbourhood of an asset                                 */
/* ------------------------------------------------------------------ */

export function assetNeighbourhood(
  asset: EstateAsset,
  assets: Map<string, EstateAsset>,
  observations: Observation[],
  certificates: CertificateIdentity[],
  states: ClusterState[],
  relationships: Array<{ source: string; target: string; type: string }>,
  detail: (id: string) => MapAsset | null,
): WorkflowGraph {
  const builder = new GraphBuilder()
  const assetId = asset.id
  const fixes = states.filter((state) => state.members.has(assetId))
  const posture = detail(assetId)
  const [status, statusLabel] = posture ? assetPosture(posture) : ['unknown', 'Evidence unavailable'] as const
  const center = assetNode(builder, asset, assetId, 2, status, statusLabel)

  const assetCertificates = certificates.filter((c) => c.assetIds.has(assetId))
  for (const certificate of assetCertificates.slice(0, 12)) {
    const cert = builder.node({
      id: `cert:${nodeKey(certificate.key)}`, kind: 'certificate',
      kindLabel: certificate.assetIds.size > 1 ? `Certificate · also on ${certificate.assetIds.size - 1} other asset(s)` : 'Certificate',
      label: certificate.subject || certificate.key, sublabel: `${certificate.algorithm}${certificate.keySize ? `-${certificate.keySize}` : ''}`,
      status: certificate.actionability === 'unclassified' ? 'unknown' : certificate.verdict === 'hybrid' ? 'hybrid'
        : certificate.verdict === 'pqc' ? 'verified' : severityStatus(certificate.severity),
      statusLabel: certificate.actionability === 'classical' ? 'Classically weak' : VERDICT_LABEL[certificate.verdict], icon: 'certificate', shape: 'document', layer: 1,
    })
    if (certificate.issuer) {
      const issuer = builder.node({ id: `root:issuer:${nodeKey(certificate.issuer)}`, kind: 'root-issuer', kindLabel: 'Issuing CA', label: certificate.issuerName, status: 'unknown', statusLabel: 'Recorded issuer', icon: 'intermediate-ca', shape: 'shield', layer: 0 })
      builder.edge(issuer, cert, 'issued', 'Issued', 'observed', 'Issuer read from the certificate record.')
    }
    builder.edge(cert, center, 'authenticates', 'Presented by', 'observed', 'Certificate recorded on this asset.')
  }
  if (assetCertificates.length > 12) builder.notices.push(`Showing 12 of ${assetCertificates.length} recorded certificates.`)
  if (posture?.evidence.unclassified) builder.notices.push(`${posture.evidence.unclassified} evidence records could not be classified for this asset.`)

  const algorithms = new Map<string, Observation>()
  for (const observation of observations) {
    if (observation.assetId !== assetId || ['unclassified', 'context'].includes(observation.actionability)) continue
    const key = observation.componentKey
    const existing = algorithms.get(key)
    if (!existing || SEVERITY_RANK[observation.severity] > SEVERITY_RANK[existing.severity]) algorithms.set(key, observation)
  }
  const algoList = [...algorithms.values()]
  for (const observation of algoList.slice(0, 14)) {
    const name = observation.verdict === 'hybrid' ? observation.algorithm : observation.canonical?.canonical ?? observation.algorithm
    const id = builder.node({
      id: `algo:${nodeKey(name)}:${observation.role}:${observation.keySize ?? ''}`, kind: 'algorithm', kindLabel: `Algorithm · ${observation.role}`,
      label: observation.keySize ? `${name}-${observation.keySize}` : name,
      status: observation.verdict === 'hybrid' ? 'hybrid'
        : observation.verdict === 'pqc' || observation.verdict === 'resistant' ? 'verified' : severityStatus(observation.severity),
      statusLabel: observation.actionability === 'classical' ? 'Classically weak' : VERDICT_LABEL[observation.verdict],
      icon: observation.role === 'key-exchange' ? 'key-exchange' : observation.role === 'signature' ? 'signature' : 'algorithm', shape: 'pill', layer: 1,
    })
    builder.edge(id, center, 'used-by', 'Used by', 'observed', 'Recorded by a scan of this asset.')
  }
  if (algoList.length > 14) builder.notices.push(`Showing 14 of ${algoList.length} algorithm usages on this asset.`)

  for (const state of fixes.slice(0, 20)) {
    const fix = fixNode(builder, state, 3)
    const member = state.members.get(assetId)!
    builder.edge(center, fix, 'resolved-by', MEMBER_STATUS_LABEL[member.status], 'configured', 'This asset is in scope of the fix.', memberStatus(member.status, member.severity))
  }
  if (fixes.length > 20) builder.notices.push(`Showing the 20 highest-priority fixes of ${fixes.length} for this asset.`)
  linkOwner(builder, asset, center, 3)

  const related = relationships.filter((rel) => rel.source === assetId || rel.target === assetId)
  for (const rel of related.slice(0, 20)) {
    const otherId = rel.source === assetId ? rel.target : rel.source
    const otherPosture = detail(otherId)
    if (!otherPosture) continue
    const other = assetNode(builder, assets.get(otherId), otherId, 4, ...assetPosture(otherPosture))
    builder.edge(rel.source === assetId ? center : other, rel.source === assetId ? other : center, rel.type || 'recorded-relationship', rel.type.replace(/[_-]+/g, ' ') || 'Recorded relationship', 'explicit', 'Read from the asset relationships register.')
  }
  if (related.length > 20) builder.notices.push(`Showing 20 of ${related.length} related assets.`)
  return builder.build(['Issuing CA', 'Certificate / algorithm', 'Asset', 'Fixes & owner', 'Related assets'])
}

/* ------------------------------------------------------------------ */
/* Campaign pipeline                                                   */
/* ------------------------------------------------------------------ */

export function campaignGraph(state: ClusterState, campaign: Campaign): WorkflowGraph {
  const builder = new GraphBuilder()
  const stageStatus: Record<string, WorkflowStatus> = {
    scope: severityStatus(state.cluster.severity), open: 'attention', planned: 'hybrid', running: 'hybrid',
    'awaiting-validation': 'hybrid', validated: 'verified', exceptions: 'critical',
  }
  const order = ['scope', 'open', 'planned', 'running', 'awaiting-validation', 'validated']
  let previous: string | null = null
  campaign.stages.forEach((stage) => {
    const layer = stage.key === 'exceptions' ? 5 : order.indexOf(stage.key)
    const id = builder.node({
      id: `stage:${stage.key}`, kind: 'step', kindLabel: 'Pipeline step', label: stage.label, sublabel: stage.detail,
      status: stage.count === 0 && stage.key !== 'scope' ? 'unknown' : stageStatus[stage.key] ?? 'unknown',
      statusLabel: `${stage.count} asset${stage.count === 1 ? '' : 's'}`, icon: stage.key === 'validated' ? 'certificate' : 'telemetry',
      shape: 'step', layer: layer < 0 ? 0 : layer,
    })
    if (stage.key === 'exceptions') {
      // Both branches point forward, so the pipeline reads left to right; exceptions are
      // re-planned in the next wave (stated in the stage detail, not drawn as a loop).
      builder.edge('stage:running', id, 'fails-to', 'Failed / rolled back', 'configured', 'Jobs that failed or were rolled back.', 'critical')
      builder.edge('stage:awaiting-validation', id, 'fails-to', 'Rescan still vulnerable', 'configured', 'A rescan after completion still recorded the vulnerable component.', 'critical')
      return
    }
    if (previous) builder.edge(previous, id, 'next', '', 'configured', 'Pipeline order.')
    previous = id
  })
  return builder.build(['Scope', 'Not started', 'Queued', 'Executing', 'Awaiting evidence', 'Validated'])
}
