import { searchTextOf, type WorkflowGraph, type WorkflowIcon, type WorkflowStatus } from '@/components/trust-workflow/graph-model'
import type { BlastRadiusResult, ExposureGraphEdge, ExposureGraphNode, NodePosture } from '@/types/exposure-graph'

export const EXPOSURE_STATUS: Record<NodePosture, { status: WorkflowStatus; label: string }> = {
  vulnerable: { status: 'critical', label: 'Vulnerable cryptography' },
  hybrid: { status: 'hybrid', label: 'Hybrid observed' },
  migrating: { status: 'attention', label: 'Migration in progress' },
  pqc: { status: 'verified', label: 'PQC observed' },
  unknown: { status: 'unknown', label: 'Posture unknown' },
}

function iconFor(node: ExposureGraphNode): WorkflowIcon {
  if (node.category === 'certificate-authority') return 'root-ca'
  if (node.category === 'pki') return 'certificate'
  if (node.category === 'identity-provider' || node.category === 'directory') return 'identity'
  if (node.category === 'hsm' || node.category === 'kms') return 'kem'
  if (node.kind === 'external') return 'vendor'
  if (node.category === 'web-application') return 'application'
  if (node.category === 'api' || node.category === 'service') return 'service'
  return 'infrastructure'
}

/** Keep asset ids and stored link direction when adapting to the shared canvas. */
export function buildExposureWorkflowGraph(
  nodes: ExposureGraphNode[],
  edges: ExposureGraphEdge[],
  blast: BlastRadiusResult | null,
  notices: string[],
): WorkflowGraph {
  const ids = new Set(nodes.map((node) => node.id))
  const groups = new Map<string, WorkflowGraph['groups'][number]>()
  const lanes: string[] = []
  const projected = nodes.map((node): WorkflowGraph['nodes'][number] => {
    const layer = Math.max(0, node.migrationTier - 1)
    const groupId = `layer:${layer}:${node.kind}`
    const icon = iconFor(node)
    const { status, label } = EXPOSURE_STATUS[node.posture]
    lanes[layer] = node.tierLabel
    if (!groups.has(groupId)) groups.set(groupId, { id: groupId, label: node.tierLabel, icon })
    const depth = blast?.depths[node.id]
    return {
      id: node.id,
      label: node.label,
      kind: node.kind,
      kindLabel: node.kind === 'external' ? node.type : 'Asset',
      sublabel: node.kind === 'asset' ? [node.type, node.environment].filter(Boolean).join(' · ') : node.vendor,
      status,
      statusLabel: label,
      layer,
      groupId,
      icon,
      shape: node.category === 'certificate-authority' ? 'shield' : 'card',
      badges: depth !== undefined ? [{ label: depth ? `Affected · depth ${depth}` : 'Blast radius origin', status: 'attention' }] : undefined,
      meta: node.kind === 'asset' ? [`${node.findingsCount} recorded findings`, ...(node.assetStatus ? [node.assetStatus] : [])] : node.algorithms.slice(0, 2),
      entity: { type: node.kind === 'asset' ? 'asset' : node.category === 'certificate-authority' ? 'ca' : 'host', id: node.id },
      searchText: searchTextOf(node.label, node.type, node.category, node.environment, node.owner, node.region, node.algorithms, node.protocols),
    }
  })
  return {
    nodes: projected,
    edges: edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)).map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      relation: edge.trustClass,
      label: edge.type.replace(/[_-]+/g, ' '),
      provenance: edge.provenance ?? 'inferred',
      basis: edge.basis ?? 'The origin of this link is unconfirmed.',
      status: edge.critical ? 'critical' : EXPOSURE_STATUS[edge.posture].status,
    })),
    groups: [...groups.values()],
    lanes,
    notices,
    legend: { critical: 'Vulnerable crypto / critical link', hybrid: 'Hybrid observed', attention: 'Migration / affected node', verified: 'PQC observed', unknown: 'Unknown posture' },
  }
}
