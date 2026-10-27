'use client'

import { useCallback, useMemo } from 'react'
import { BadgeCheck, ExternalLink, FlaskConical, Link2 } from 'lucide-react'
import {
  DetailFacts, DetailLink, DetailSection, StatusPill, VendorTrustWorkflowCanvas,
  type DetailContext,
} from '@/components/trust-workflow/VendorTrustWorkflowCanvas'
import { buildEcosystemGraph } from '@/components/trust-workflow/graph-builders'
import type { WorkflowNode } from '@/components/trust-workflow/graph-model'
import type { EcosystemPayload } from '@/hooks/use-external-trust'
import {
  DEPENDENCY_LABEL, NODE_KIND_LABEL, READINESS_LABEL, RISK_LABEL,
  type EcosystemNodeKind, type Readiness, type RiskLevel,
} from '@/lib/ecosystem/external-trust-intelligence'
import { AskSophiaButton, numberFmt, suiteHref } from '../_components/external-trust/_shared'

/**
 * Ecosystem dependency map — the tenant's assets, services, crypto, PKI and
 * vendors drawn as stored, consumer → dependency.
 *
 * Selecting a node asks the server for its blast radius (the same breadth-first
 * traversal the Blast Radius panel reports); affected nodes are badged with
 * their depth, so the picture and the numbers come from one computation.
 */

export interface EcosystemFilters {
  kinds: ReadonlySet<EcosystemNodeKind>
  criticality: RiskLevel | 'all'
  readiness: Readiness | 'all'
}

export interface EcosystemMapProps {
  data: EcosystemPayload
  filters: EcosystemFilters
  focusNodeId: string | null
  onSelectNode: (node: WorkflowNode | null) => void
  filtered: boolean
}

export function EcosystemMap({ data, filters, focusNodeId, onSelectNode, filtered }: EcosystemMapProps) {
  const spofIds = useMemo(() => data.singlePointsOfFailure.map((spof) => spof.nodeId), [data.singlePointsOfFailure])
  const blockerIds = useMemo(() => data.bottlenecks.map((bottleneck) => bottleneck.nodeId), [data.bottlenecks])
  const graph = useMemo(() => buildEcosystemGraph({
    nodes: data.nodes,
    edges: data.edges,
    kinds: filters.kinds,
    criticality: filters.criticality,
    readiness: filters.readiness,
    blastRadius: data.blastRadius,
    singlePointOfFailureIds: spofIds,
    bottleneckIds: blockerIds,
  }), [data.nodes, data.edges, data.blastRadius, filters, spofIds, blockerIds])

  const ecoById = useMemo(() => new Map(data.nodes.map((node) => [node.id, node])), [data.nodes])

  const renderNodeDetail = useCallback((node: WorkflowNode, context: DetailContext) => {
    const source = ecoById.get(node.id)
    if (!source) {
      return <p className="qg-wf__text">{node.sublabel} — expand the group to inspect each member.</p>
    }
    const blast = data.blastRadius?.nodeId === node.id ? data.blastRadius : null
    const spof = data.singlePointsOfFailure.find((candidate) => candidate.nodeId === node.id)
    const bottleneck = data.bottlenecks.find((candidate) => candidate.nodeId === node.id)
    const assetId = node.entity?.type === 'asset' ? node.entity.id : null
    return (
      <>
        <DetailFacts items={[
          ['Type', NODE_KIND_LABEL[source.kind]],
          ['Owner', source.owner],
          ['Environment', source.environment],
          ['Criticality', RISK_LABEL[source.criticality]],
          ['Dependency', DEPENDENCY_LABEL[source.dependencyKind]],
          ['PQC readiness', READINESS_LABEL[source.readiness]],
        ]} />

        <DetailSection title="Detail">
          <p className="qg-wf__text">{source.detail}</p>
          {source.algorithms.length > 0 && (
            <p className="qg-wf__text-muted" style={{ marginTop: 4 }}>Cryptography: <span className="font-mono">{source.algorithms.join(', ')}</span></p>
          )}
        </DetailSection>

        <DetailSection title="Blast radius">
          {blast ? (
            <>
              <DetailFacts items={[
                ['Direct dependents', numberFmt(blast.directDependencies), true],
                ['Indirect dependents', numberFmt(blast.indirectDependencies), true],
                ['Applications', numberFmt(blast.applicationsAffected), true],
                ['Critical services', numberFmt(blast.criticalServices), true],
                ['Trust relationships', numberFmt(blast.trustRelationships), true],
                ['Migration plans', numberFmt(blast.migrationPlans), true],
              ]} />
              <p className="qg-wf__text-muted" style={{ marginTop: 4 }}>
                Affected nodes carry an “Affected · depth” badge. Choose <b>Upstream</b> above to trace them on the map.
              </p>
              {data.dependencyChain.length > 1 && (
                <p className="qg-wf__text-muted" style={{ marginTop: 4 }}>
                  Chain: {data.dependencyChain.slice(0, 6).map((step) => step.label).join(' → ')}{data.dependencyChain.length > 6 ? ' → …' : ''}
                </p>
              )}
            </>
          ) : (
            <p className="qg-wf__text-muted">Computing from recorded relationships… ({context.upstreamCount} upstream in the current view)</p>
          )}
        </DetailSection>

        {spof && (
          <DetailSection title="Single point of failure">
            <StatusPill status="attention" label={`${spof.downstreamConsumers} consumer(s) · ${spof.alternativesObserved} alternative(s)`} />
            <ul className="qg-wf__list" style={{ marginTop: 6 }}>
              {spof.reasons.map((reason, index) => <li key={index} className="qg-wf__text">· {reason}</li>)}
            </ul>
          </DetailSection>
        )}

        {bottleneck && (
          <DetailSection title="Migration blocker">
            <p className="qg-wf__text">Prevents PQC migration for {numberFmt(bottleneck.blockedAssets)} asset(s). {bottleneck.reason}</p>
            <p className="qg-wf__text-muted" style={{ marginTop: 4 }}>→ {bottleneck.recommendedAction}</p>
          </DetailSection>
        )}

        <DetailSection title="Evidence">
          <p className="qg-wf__text-muted">
            {source.evidenceSources.join(', ') || 'No source recorded'} · {source.assetIds.length} tenant asset(s) transit this node.
            {!source.hasEvidence && ' No cryptographic evidence has been observed here — its behaviour under migration is undetermined.'}
          </p>
        </DetailSection>

        <div className="flex flex-wrap gap-1.5">
          {source.vendorId && <DetailLink primary href={suiteHref('vendor', { vendor: source.vendorId })}><BadgeCheck /> Vendor readiness</DetailLink>}
          <DetailLink href={suiteHref('trust', { vendor: source.vendorId, asset: assetId })}><Link2 /> Analyze trust</DetailLink>
          <DetailLink href={suiteHref('lab', assetId ? { asset: assetId } : { vendor: source.vendorId })}><FlaskConical /> Test configuration</DetailLink>
          <DetailLink href={source.route}><ExternalLink /> Source module</DetailLink>
          <AskSophiaButton question={`In our ecosystem dependency map, what depends on "${source.label}" and what breaks if it changes?`} context="Ecosystem Dependency Map" />
        </div>
      </>
    )
  }, [ecoById, data.blastRadius, data.singlePointsOfFailure, data.bottlenecks, data.dependencyChain])

  return (
    <VendorTrustWorkflowCanvas
      graph={graph}
      ariaLabel="Ecosystem dependency map"
      status="ready"
      focusNodeId={focusNodeId}
      onSelectNode={onSelectNode}
      renderNodeDetail={renderNodeDetail}
      enableTrace
      autoCollapseAbove={14}
      height={680}
      exportName="qguard-ecosystem-dependencies"
      empty={filtered
        ? { title: 'No dependencies match the current filters', detail: 'Turn node types back on or clear the filters above.' }
        : {
          title: 'No dependency map yet',
          detail: 'The map is projected from your asset inventory, recorded relationships, certificates and observed external hosts. Nothing is drawn until that evidence exists.',
          cta: { label: 'Run discovery', href: '/dashboard/scanner' },
        }}
    />
  )
}
