'use client';

import { useMemo } from 'react';
import { Network, Search } from 'lucide-react';
import {
  DefaultEdgeDetail,
  DetailFacts,
  DetailLink,
  DetailSection,
  VendorTrustWorkflowCanvas,
} from '@/components/trust-workflow/VendorTrustWorkflowCanvas';
import type { WorkflowGraph, WorkflowIcon, WorkflowShape, WorkflowStatus } from '@/components/trust-workflow/graph-model';
import { TRUST_NODE_LABEL, TRUST_NODE_TIER, TRUST_STATE_LABEL } from '@/lib/trust-fabric/types';
import type { TrustNode, TrustNodeKind, TrustRelationship, TrustState } from '@/lib/trust-fabric/types';

const LAYERS = [
  'Root authorities', 'Issuing authorities', 'Certificates', 'Transport endpoints',
  'Services & platform', 'Applications & assets', 'Cloud resources',
];

const APPEARANCE: Record<TrustNodeKind, [WorkflowIcon, WorkflowShape]> = {
  'root-ca': ['root-ca', 'shield'],
  'intermediate-ca': ['intermediate-ca', 'shield'],
  certificate: ['certificate', 'document'],
  'tls-endpoint': ['surface', 'card'],
  domain: ['surface', 'card'],
  'load-balancer': ['infrastructure', 'card'],
  gateway: ['handshake', 'card'],
  service: ['service', 'card'],
  api: ['service', 'card'],
  'identity-system': ['identity', 'card'],
  'key-management': ['key-exchange', 'card'],
  'encryption-service': ['cipher', 'card'],
  application: ['application', 'card'],
  'kubernetes-workload': ['infrastructure', 'card'],
  container: ['infrastructure', 'card'],
  asset: ['infrastructure', 'card'],
  'cloud-resource': ['infrastructure', 'card'],
};

const STATUS: Record<TrustState, WorkflowStatus> = {
  trusted: 'verified',
  healthy: 'verified',
  'pqc-ready': 'verified',
  degraded: 'attention',
  'at-risk': 'attention',
  'migration-required': 'attention',
  'quantum-vulnerable': 'critical',
  critical: 'critical',
  expired: 'critical',
  invalid: 'critical',
  unknown: 'unknown',
};

const RELATIONSHIP_SOURCE: Record<TrustRelationship['source'], string> = {
  'asset-relationship': 'Asset inventory',
  'certificate-chain': 'Certificate inventory',
  deployment: 'Deployment attribution',
  runtime: 'Runtime telemetry',
  'cloud-attribution': 'Cloud attribution',
};

interface GraphProps {
  nodes: TrustNode[];
  relationships: TrustRelationship[];
  matchingNodes: number;
  matchingRelationships: number;
  loading: boolean;
  filtered: boolean;
  partialEvidence: boolean;
  error: string | null;
  onRetry: () => void;
  onInspect: (id: string) => void;
}

function buildGraph(
  nodes: TrustNode[],
  relationships: TrustRelationship[],
  matchingNodes: number,
  matchingRelationships: number,
): WorkflowGraph {
  const notices: string[] = [];
  if (nodes.length < matchingNodes) {
    notices.push(`Showing ${nodes.length} of ${matchingNodes} matching subjects. Narrow the inventory filters to see other subjects.`);
  }
  if (relationships.length < matchingRelationships) {
    notices.push(`Showing ${relationships.length} of ${matchingRelationships} links between the subjects in view.`);
  }

  return {
    lanes: LAYERS,
    groups: [],
    notices,
    legend: {
      verified: 'Trusted, Healthy or PQC Ready',
      attention: 'Degraded, At Risk or Migration Required',
      critical: 'Critical, Invalid, Expired or Quantum Vulnerable',
      unknown: 'Unknown',
    },
    nodes: nodes.map((node) => {
      const [icon, shape] = APPEARANCE[node.kind];
      const inferred = node.kind === 'intermediate-ca' && !node.measured;
      return {
        id: node.id,
        kind: node.kind,
        kindLabel: TRUST_NODE_LABEL[node.kind],
        label: node.label,
        sublabel: node.subtitle,
        status: STATUS[node.state],
        statusLabel: TRUST_STATE_LABEL[node.state],
        icon,
        shape,
        inferred,
        layer: TRUST_NODE_TIER[node.kind],
        badges: [{
          label: inferred ? 'Issuer inferred' : node.measured ? 'Evidence recorded' : 'No measurement',
          status: node.measured ? STATUS[node.state] : 'unknown',
        }],
        searchText: [node.label, node.subtitle, node.owner, node.environment, node.providerLabel, node.region, node.id]
          .join(' ').toLowerCase(),
      };
    }),
    edges: relationships.map((edge) => ({
      id: edge.id,
      source: edge.from,
      target: edge.to,
      relation: edge.kind,
      label: edge.label,
      status: STATUS[edge.state],
      provenance: !edge.measured ? 'inferred' : edge.source === 'asset-relationship' ? 'explicit' : 'observed',
      basis: edge.reason,
    })),
  };
}

export default function DiscoveryTrustGraph({
  nodes, relationships, matchingNodes, matchingRelationships, loading, filtered, partialEvidence, error, onRetry, onInspect,
}: GraphProps) {
  const graph = useMemo(
    () => buildGraph(nodes, relationships, matchingNodes, matchingRelationships),
    [nodes, relationships, matchingNodes, matchingRelationships],
  );
  const nodeById = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const relationshipById = useMemo(() => new Map(relationships.map((edge) => [edge.id, edge])), [relationships]);

  return (
    <>
      {partialEvidence && (
        <div className="qg-wf__notices mb-2" role="status">
          <span>Some evidence sources are unavailable or limited. See Evidence provenance below for coverage.</span>
        </div>
      )}
      {error && nodes.length > 0 && (
        <div className="qg-wf__notices mb-2" role="status">
          <span>Could not refresh these graph results. Showing the previous view.</span>
          <button type="button" className="qg-wf__btn" onClick={onRetry}>Retry</button>
        </div>
      )}
      <VendorTrustWorkflowCanvas
        ariaLabel="Trust relationship graph"
        searchPlaceholder="Find a subject in this graph…"
        graph={graph}
        status={error ? 'error' : loading ? 'loading' : 'ready'}
        error={error}
        onRetry={onRetry}
        enableTrace
        exportName="qguard-trust-discovery"
        empty={partialEvidence
          ? { title: 'No subjects in the available evidence', detail: 'See Evidence provenance for source coverage. You can refresh or broaden the filters.' }
          : filtered
          ? { title: 'No matching trust subjects', detail: 'Change the filters above to broaden the graph and inventory scope.' }
          : { title: 'No trust subjects discovered', detail: 'The graph uses subjects and relationships recorded by your collectors, connectors and authorized scans.' }}
        renderNodeDetail={(item) => {
          const node = nodeById.get(item.id);
          if (!node) return null;
          const observed = node.lastObservedAt ? new Date(node.lastObservedAt) : null;
          return (
            <>
              <DetailSection title="Trust evidence">
                <p className="qg-wf__text">{node.stateReason}</p>
                <DetailFacts items={[
                  ['Evidence', item.inferred ? 'Issuer inferred from certificate records' : node.measured ? 'Evidence recorded' : 'No measurement'],
                  ['Last observed', observed && Number.isFinite(observed.getTime()) ? observed.toLocaleString() : 'Unrecorded'],
                  ['Owner', node.owner || 'Unassigned'],
                  ['Environment', node.environment || 'Unrecorded'],
                  ['Cloud / region', [node.providerLabel, node.region].filter(Boolean).join(' · ') || 'Unrecorded'],
                  ['Posture', node.posture.replaceAll('-', ' ')],
                ]} />
              </DetailSection>
              <div className="flex flex-wrap gap-1.5">
                <DetailLink primary onClick={() => onInspect(node.id)}><Search /> Full subject evidence</DetailLink>
                {node.assetId && (
                  <DetailLink href={`/dashboard/trust-chain-analyzer?asset=${encodeURIComponent(node.assetId)}`}>
                    <Network /> Analyze asset chains
                  </DetailLink>
                )}
              </div>
            </>
          );
        }}
        renderEdgeDetail={(edge, context) => {
          const relationship = relationshipById.get(edge.id);
          return (
            <>
              <DefaultEdgeDetail edge={edge} nodeById={context.nodeById} statusLabel={relationship && TRUST_STATE_LABEL[relationship.state]} />
              {relationship && (
                <DetailSection title="Trust Fabric evidence">
                  <DetailFacts items={[[ 'Evidence source', RELATIONSHIP_SOURCE[relationship.source] ]]} />
                </DetailSection>
              )}
            </>
          );
        }}
      />
    </>
  );
}
