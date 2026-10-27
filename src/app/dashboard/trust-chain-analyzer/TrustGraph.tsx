'use client'

import { useCallback, useMemo, useState } from 'react'
import { BadgeCheck, Binary, Building2, FlaskConical, Globe2 } from 'lucide-react'
import {
  DefaultEdgeDetail, DetailFacts, DetailLink, DetailSection, StatusPill, VendorTrustWorkflowCanvas,
  type DetailContext,
} from '@/components/trust-workflow/VendorTrustWorkflowCanvas'
import {
  FINDING_NATURE, FINDING_NATURE_LABEL, algorithmStatus, buildTrustGraph, explainTrustPath,
  type FindingNature,
} from '@/components/trust-workflow/graph-builders'
import type { WorkflowEdge, WorkflowNode, WorkflowStatus } from '@/components/trust-workflow/graph-model'
import {
  RISK_LABEL, TRUST_FINDING_LABEL,
  type CertificateDetail, type RiskLevel, type TrustChain, type TrustFinding,
} from '@/lib/ecosystem/external-trust-intelligence'
import { dateFmt, relativeTime, suiteHref } from '../_components/external-trust/_shared'

/**
 * Trust graph — every discovered chain merged into one directed graph, with
 * edges pointing the way trust is delegated (anchor → CA → certificate →
 * relying system). Shared CAs, multiple roots and disconnected components are
 * drawn as they are; nothing is synthesised to make the picture look whole.
 */

const SEVERITY_STATUS: Record<RiskLevel, WorkflowStatus> = {
  critical: 'critical', high: 'attention', medium: 'attention', low: 'verified', unknown: 'unknown',
}

const EDGE_MEANING: Record<string, string> = {
  issued: 'The issuing CA signed this certificate. QGuard reads the issuer from the certificate inventory; the signature on this hop is verified only when a controlled test validates the live chain.',
  'self-signs': 'The certificate is its own issuer — it is a trust anchor every relying party must already hold.',
  authenticates: 'The relying system presents this certificate to authenticate itself to its clients.',
  anchors: 'Trust is assumed to terminate at this root. The root certificate was not captured, so the anchor is inferred and cannot be validated.',
  operates: 'The certificate authority is attributed to a vendor because the names match. Ownership is not explicitly recorded.',
  'public-key': 'The certificate binds this public-key algorithm. A quantum-vulnerable key means the certificate must be re-issued for PQC readiness.',
  'signed-with': 'The issuer signed the certificate with this algorithm.',
}

export interface TrustGraphProps {
  chains: TrustChain[]
  findings: TrustFinding[]
  certificates: CertificateDetail[]
  generatedAt: string | null
  status: 'loading' | 'ready' | 'error'
  error: string | null
  onRetry: () => void
  focusNodeId: string | null
  onSelectNode: (node: WorkflowNode | null) => void
  filtered: boolean
}

export function TrustGraph({
  chains, findings, certificates, generatedAt, status, error, onRetry, focusNodeId, onSelectNode, filtered,
}: TrustGraphProps) {
  const [showAlgorithms, setShowAlgorithms] = useState(false)
  const [showVendors, setShowVendors] = useState(true)

  const graph = useMemo(
    () => buildTrustGraph({ chains, findings, certificates, showAlgorithms, showVendors }),
    [chains, findings, certificates, showAlgorithms, showVendors],
  )
  const certificateByNode = useMemo(() => new Map(certificates.map((certificate) => [`cert:${certificate.id}`, certificate])), [certificates])
  const chainByCertNode = useMemo(() => new Map(chains.map((chain) => [`cert:${chain.id.slice('chain-'.length)}`, chain])), [chains])
  const trustNodeById = useMemo(() => {
    const map = new Map<string, TrustChain['nodes'][number]>()
    for (const chain of chains) for (const node of chain.nodes) if (!map.has(node.id)) map.set(node.id, node)
    return map
  }, [chains])

  const renderNodeDetail = useCallback((node: WorkflowNode, context: DetailContext) => {
    if (node.kind === 'certificate') {
      const certificate = certificateByNode.get(node.id)
      const chain = chainByCertNode.get(node.id)
      const chainFindings = chain ? findings.filter((finding) => finding.chainId === chain.id) : []
      return (
        <CertificateDetailView
          node={node} certificate={certificate} chain={chain} findings={chainFindings}
          context={context} generatedAt={generatedAt}
        />
      )
    }
    if (node.kind === 'root-ca' || node.kind === 'intermediate-ca' || node.kind === 'trust-anchor') {
      const trustNode = trustNodeById.get(node.id)
      const issued = context.outgoing.filter((entry) => entry.node.kind === 'certificate')
      const affected = context.downstreamCount
      return (
        <>
          <DetailFacts items={[
            ['Role', node.kindLabel],
            ['Operated', trustNode?.external ? 'Externally' : 'Internally'],
            ['Certificates issued (in view)', String(issued.length), true],
            ['Downstream elements', String(affected), true],
          ]} />
          <DetailSection title="Evidence">
            <p className="qg-wf__text">{trustNode?.detail ?? 'No detail recorded.'}</p>
            {node.inferred && (
              <p className="qg-wf__text-muted" style={{ marginTop: 4 }}>Inferred — the root certificate was not captured, so its key algorithm, validity and revocation state are unknown.</p>
            )}
          </DetailSection>
          <DetailSection title="Migration impact">
            <p className="qg-wf__text">
              Moving this authority to ML-DSA (FIPS 204) signing affects {affected} downstream element(s) in this view. Whether the CA can issue post-quantum certificates is not verified.
            </p>
          </DetailSection>
          {trustNode?.vendorId && (
            <div className="flex flex-wrap gap-1.5">
              <DetailLink primary href={suiteHref('vendor', { vendor: trustNode.vendorId })}><BadgeCheck /> Vendor readiness</DetailLink>
            </div>
          )}
        </>
      )
    }
    if (node.kind === 'application' || node.kind === 'service') {
      const assetId = node.entity?.type === 'asset' ? node.entity.id : null
      const relied = context.incoming.filter((entry) => entry.node.kind === 'certificate')
      return (
        <>
          <DetailFacts items={[
            ['Relies on', `${relied.length} certificate(s)`],
            ['Upstream trust elements', String(context.upstreamCount), true],
          ]} />
          <p className="qg-wf__text-muted">
            The TLS protocol and cipher this system negotiates are not part of the certificate inventory. A controlled test in the Hybrid Crypto Lab observes them directly.
          </p>
          {assetId && (
            <div className="flex flex-wrap gap-1.5">
              <DetailLink primary href={suiteHref('lab', { asset: assetId })}><FlaskConical /> Test this system</DetailLink>
              <DetailLink href={suiteHref('ecosystem', { asset: assetId })}><Globe2 /> Dependencies</DetailLink>
            </div>
          )}
        </>
      )
    }
    if (node.kind === 'algorithm') {
      const classification = algorithmStatus(node.label)
      return (
        <DetailSection title="Classification">
          <p className="qg-wf__text"><Binary className="mr-1 inline h-3 w-3" aria-hidden="true" /><b>{node.label}</b> — {classification.label.toLowerCase()}. {context.incoming.length} certificate(s) in view use it.</p>
        </DetailSection>
      )
    }
    if (node.kind === 'vendor' && node.entity?.type === 'vendor') {
      return (
        <>
          <p className="qg-wf__text">Vendor attributed to the certificate authorities it operates (by name match). Its PQC readiness lives in the vendor register.</p>
          <div className="flex flex-wrap gap-1.5">
            <DetailLink primary href={suiteHref('vendor', { vendor: node.entity.id })}><Building2 /> Vendor readiness</DetailLink>
            <DetailLink href={suiteHref('lab', { vendor: node.entity.id })}><FlaskConical /> Hybrid test</DetailLink>
          </div>
        </>
      )
    }
    return null
  }, [certificateByNode, chainByCertNode, findings, trustNodeById, generatedAt])

  const renderEdgeDetail = useCallback((edge: WorkflowEdge, context: DetailContext) => (
    <>
      <DefaultEdgeDetail edge={edge} nodeById={context.nodeById} />
      {EDGE_MEANING[edge.relation] && (
        <DetailSection title="What this relationship means">
          <p className="qg-wf__text">{EDGE_MEANING[edge.relation]}</p>
        </DetailSection>
      )}
    </>
  ), [])

  return (
    <VendorTrustWorkflowCanvas
      graph={graph}
      ariaLabel="Trust graph"
      status={status}
      error={error}
      onRetry={onRetry}
      focusNodeId={focusNodeId}
      onSelectNode={onSelectNode}
      renderNodeDetail={renderNodeDetail}
      renderEdgeDetail={renderEdgeDetail}
      enableTrace
      explainPath={explainTrustPath}
      exportName="qguard-trust-graph"
      toolbarExtras={(
        <div className="qg-wf__toolbar-group" role="group" aria-label="Node types">
          <button type="button" className="qg-wf__btn" aria-pressed={showVendors} onClick={() => setShowVendors((value) => !value)}>Vendors</button>
          <button type="button" className="qg-wf__btn" aria-pressed={showAlgorithms} onClick={() => setShowAlgorithms((value) => !value)}>Algorithms</button>
        </div>
      )}
      empty={filtered
        ? { title: 'No chains match the current filters', detail: 'Clear the filters above — the graph and the chain list share them.' }
        : {
          title: 'No trust chains discovered',
          detail: 'Chains are built from discovered certificates and their recorded issuers — none are synthesised. Scan TLS endpoints or connect a certificate source to populate the graph.',
          cta: { label: 'Analyze trust state', href: '/dashboard/trust-state-discovery' },
        }}
    />
  )
}

function CertificateDetailView({ node, certificate, chain, findings, context, generatedAt }: {
  node: WorkflowNode
  certificate: CertificateDetail | undefined
  chain: TrustChain | undefined
  findings: TrustFinding[]
  context: DetailContext
  generatedAt: string | null
}) {
  const grouped = new Map<FindingNature, TrustFinding[]>()
  for (const finding of findings) {
    const nature = FINDING_NATURE[finding.kind]
    grouped.set(nature, [...(grouped.get(nature) ?? []), finding])
  }
  const assetId = certificate?.assetId ?? null
  return (
    <>
      {certificate ? (
        <DetailFacts items={[
          ['Subject', certificate.subject],
          ['Issuer', certificate.issuer],
          ['Valid from', dateFmt(certificate.notBefore)],
          ['Valid to', dateFmt(certificate.notAfter)],
          ['Expiry', certificate.daysToExpiry === null ? 'Unknown' : certificate.daysToExpiry < 0 ? `Expired ${Math.abs(certificate.daysToExpiry)}d ago` : `${certificate.daysToExpiry} days`, true],
          ['Public key', `${certificate.publicKeyAlgorithm}${certificate.keySize ? ` ${certificate.keySize}-bit` : ''}`, true],
          ['Signature', certificate.signatureAlgorithm, true],
          ['Post-quantum', certificate.quantumSafe ? 'Yes (recorded)' : 'No', true],
          ['Renewal', certificate.renewalMechanism],
          ['Trust anchor', certificate.trustAnchor],
        ]} />
      ) : (
        <p className="qg-wf__text-muted">No certificate record is attached to this node.</p>
      )}

      <DetailSection title="Chain validation">
        <p className="qg-wf__text">
          State from inventory: <b>{node.statusLabel}</b>. This is derived from the recorded validity dates and algorithms — a live chain validation was not performed here.
        </p>
        <p className="qg-wf__text-muted" style={{ marginTop: 4 }}>
          Revocation status and the negotiated TLS protocol/cipher are not collected by the certificate inventory. Run a controlled test to observe them.
        </p>
      </DetailSection>

      <DetailSection title={`Findings (${findings.length})`}>
        {findings.length === 0 ? (
          <p className="qg-wf__text-muted">Nothing in the available certificate evidence flags this chain.</p>
        ) : (
          <div className="qg-wf__list">
            {(['observed-fact', 'policy-violation', 'inferred-risk'] as FindingNature[]).map((nature) => grouped.get(nature)?.length ? (
              <div key={nature}>
                <div className="qg-wf__row-kicker" style={{ margin: '4px 0' }}>{FINDING_NATURE_LABEL[nature]}</div>
                {grouped.get(nature)!.map((finding) => (
                  <div key={finding.id} className="qg-wf__row" style={{ alignItems: 'flex-start', marginBottom: 4 }}>
                    <span className="qg-wf__row-main" style={{ whiteSpace: 'normal' }}>
                      <StatusPill status={SEVERITY_STATUS[finding.severity]} label={`${RISK_LABEL[finding.severity]} · ${TRUST_FINDING_LABEL[finding.kind]}`} />
                      <span className="qg-wf__text" style={{ display: 'block', marginTop: 4, whiteSpace: 'normal' }}>{finding.evidence}</span>
                      <span className="qg-wf__text-muted" style={{ display: 'block', whiteSpace: 'normal' }}>→ {finding.recommendedAction}</span>
                    </span>
                  </div>
                ))}
              </div>
            ) : null)}
          </div>
        )}
      </DetailSection>

      <DetailSection title="Downstream impact">
        <p className="qg-wf__text">
          {context.downstreamCount} system(s) rely on this certificate in the current view
          {chain ? ` · ${chain.migrationImpact.applications} application(s), ${chain.migrationImpact.services} service(s) in the chain's migration impact` : ''}.
        </p>
      </DetailSection>

      <DetailSection title="Evidence source">
        <p className="qg-wf__text-muted">{certificate?.basis ?? 'Certificate inventory'} · observed in snapshot {relativeTime(generatedAt)}</p>
      </DetailSection>

      <div className="flex flex-wrap gap-1.5">
        {assetId && <DetailLink primary href={suiteHref('lab', { asset: assetId })}><FlaskConical /> Validate in lab</DetailLink>}
        {chain?.vendorId && <DetailLink href={suiteHref('vendor', { vendor: chain.vendorId })}><BadgeCheck /> Vendor evidence</DetailLink>}
      </div>
    </>
  )
}
