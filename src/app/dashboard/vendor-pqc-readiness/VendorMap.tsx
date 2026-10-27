'use client'

import { useCallback, useMemo } from 'react'
import { ArrowRight, FlaskConical, Globe2, Link2, ClipboardList } from 'lucide-react'
import {
  DetailFacts, DetailLink, DetailSection, StatusPill, VendorTrustWorkflowCanvas,
  type DetailContext,
} from '@/components/trust-workflow/VendorTrustWorkflowCanvas'
import { algorithmStatus, buildVendorGraph, vendorStatus } from '@/components/trust-workflow/graph-builders'
import type { WorkflowNode, WorkflowStatus } from '@/components/trust-workflow/graph-model'
import {
  EVIDENCE_LABEL, MIGRATION_SUPPORT_LABEL, OBLIGATION_LABEL, READINESS_LABEL, RISK_LABEL,
  type CheckVerdict, type EcosystemEdge, type EcosystemNode, type VendorRecord,
} from '@/lib/ecosystem/external-trust-intelligence'
import { dateFmt, relativeTime, suiteHref } from '../_components/external-trust/_shared'

/**
 * Vendor ecosystem map — Organization → internal systems → vendors →
 * vendor surfaces → crypto & PKI dependencies.
 *
 * The map draws the SAME filtered vendor set as the register below it, so a
 * filter can never show one population in the picture and another in the table.
 */

const VERDICT_STATUS: Record<CheckVerdict, WorkflowStatus> = { pass: 'verified', fail: 'critical', unknown: 'unknown' }
const PROVENANCE_WORD: Record<string, string> = { measured: 'measured', 'vendor-claim': 'vendor claim only', none: 'no evidence' }

export interface VendorMapProps {
  vendors: VendorRecord[]
  allVendors: VendorRecord[]
  ecosystem: { nodes: EcosystemNode[]; edges: EcosystemEdge[] } | null
  status: 'loading' | 'ready' | 'error'
  error: string | null
  onRetry: () => void
  focusNodeId: string | null
  onSelectVendor: (vendorId: string | null) => void
  onOpenAssessment: (vendor: VendorRecord) => void
  filtered: boolean
}

export function VendorMap({
  vendors, allVendors, ecosystem, status, error, onRetry, focusNodeId, onSelectVendor, onOpenAssessment, filtered,
}: VendorMapProps) {
  const pinned = focusNodeId?.startsWith('vendor:') ? [focusNodeId.slice('vendor:'.length)] : []
  const pinnedKey = pinned.join(',')
  const graph = useMemo(
    () => buildVendorGraph({ vendors, ecosystem, pinnedVendorIds: pinnedKey ? pinnedKey.split(',') : [] }),
    [vendors, ecosystem, pinnedKey],
  )
  const vendorById = useMemo(() => new Map(allVendors.map((vendor) => [vendor.id, vendor])), [allVendors])
  const ecoById = useMemo(() => new Map((ecosystem?.nodes ?? []).map((node) => [node.id, node])), [ecosystem])

  const handleSelect = useCallback((node: WorkflowNode | null) => {
    onSelectVendor(node?.entity?.type === 'vendor' ? node.entity.id : null)
  }, [onSelectVendor])

  const renderNodeDetail = useCallback((node: WorkflowNode, context: DetailContext) => {
    if (node.entity?.type === 'vendor') {
      const vendor = vendorById.get(node.entity.id)
      if (!vendor) return null
      return <VendorDetail vendor={vendor} context={context} onOpenAssessment={onOpenAssessment} />
    }
    if (node.entity?.type === 'asset') {
      const eco = ecoById.get(node.id)
      const assetId = node.entity.id
      return (
        <>
          <DetailFacts items={[
            ['Owner', eco?.owner ?? 'Unassigned'],
            ['Environment', eco?.environment ?? 'unknown'],
            ['Criticality', eco ? RISK_LABEL[eco.criticality] : 'Unknown'],
            ['Vendors consumed', String(context.outgoing.filter((entry) => entry.node.kind === 'vendor').length)],
          ]} />
          <DetailSection title="Why this status">
            <p className="qg-wf__text">
              {node.statusLabel}. An internal system's readiness here is inherited from the vendors it consumes — it is not an independent measurement of the system.
            </p>
          </DetailSection>
          <div className="flex flex-wrap gap-1.5">
            <DetailLink primary href={suiteHref('ecosystem', { asset: assetId })}><Globe2 /> Dependencies</DetailLink>
            <DetailLink href={suiteHref('trust', { asset: assetId })}><Link2 /> Trust chains</DetailLink>
            <DetailLink href={suiteHref('lab', { asset: assetId })}><FlaskConical /> Test in lab</DetailLink>
          </div>
        </>
      )
    }
    if (node.kind === 'algorithm') {
      const classification = algorithmStatus(node.label)
      return (
        <>
          <DetailSection title="Classification">
            <p className="qg-wf__text">
              <b>{node.label}</b> is classified as <b>{classification.label.toLowerCase()}</b>. This is a property of the algorithm itself, not a test result — each vendor using it is listed below.
            </p>
          </DetailSection>
          {classification.status === 'attention' && (
            <p className="qg-wf__text-muted">Plan a replacement: ML-KEM-768 (FIPS 203) for key establishment, ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) for signatures — or a hybrid such as X25519 + ML-KEM-768 during transition.</p>
          )}
        </>
      )
    }
    if (node.kind === 'surface') {
      const vendorId = context.incoming.find((entry) => entry.node.kind === 'vendor')?.node.entity?.id
      return (
        <>
          <p className="qg-wf__text">Host observed in tenant evidence and attributed to its vendor. QGuard has not measured this host individually — run a controlled test to observe its handshake.</p>
          {vendorId && (
            <div className="flex flex-wrap gap-1.5">
              <DetailLink primary href={`/dashboard/hybrid-crypto-lab?target=${encodeURIComponent(`${vendorId}:${node.label}`)}&vendor=${encodeURIComponent(vendorId)}`}><FlaskConical /> Test this host</DetailLink>
            </div>
          )}
        </>
      )
    }
    if (node.kind === 'ca') {
      const vendorId = context.incoming.find((entry) => entry.node.kind === 'vendor')?.node.entity?.id
      return (
        <>
          <p className="qg-wf__text">{node.sublabel}</p>
          <p className="qg-wf__text-muted">The link to the vendor is inferred from the issuer name. Confirm in the Trust Chain Analyzer which certificates this authority issued.</p>
          <div className="flex flex-wrap gap-1.5">
            <DetailLink primary href={suiteHref('trust', { vendor: vendorId })}><Link2 /> Analyze trust chains</DetailLink>
          </div>
        </>
      )
    }
    return null
  }, [vendorById, ecoById, onOpenAssessment])

  return (
    <VendorTrustWorkflowCanvas
      graph={graph}
      ariaLabel="Vendor ecosystem map"
      status={status}
      error={error}
      onRetry={onRetry}
      focusNodeId={focusNodeId}
      onSelectNode={handleSelect}
      renderNodeDetail={renderNodeDetail}
      exportName="qguard-vendor-ecosystem"
      empty={filtered
        ? { title: 'No vendors match the current filters', detail: 'Clear or widen the filters above — the map and the register share them.' }
        : {
          title: 'No vendor relationships discovered yet',
          detail: 'Vendors appear once connectors, certificate issuers or observed external hosts attribute cryptography to a provider. Nothing is drawn until that evidence exists.',
          cta: { label: 'Run discovery', href: '/dashboard/scanner' },
        }}
    />
  )
}

function VendorDetail({ vendor, context, onOpenAssessment }: {
  vendor: VendorRecord; context: DetailContext; onOpenAssessment: (vendor: VendorRecord) => void
}) {
  const status = vendorStatus(vendor)
  const blockers = [...vendor.riskFactors].sort((a, b) => b.contribution - a.contribution).slice(0, 3)
  const missingObligations = vendor.obligations.filter((obligation) => obligation.state === 'missing' || obligation.state === 'expired')
  const position = vendor.position
  const support: Array<[string, CheckVerdict, string]> = [
    ['ML-KEM key establishment', position.kemSupport, 'kem'],
    ['PQC signatures (ML-DSA / SLH-DSA)', position.signatureSupport, 'signature'],
    ['Hybrid key exchange', position.hybridSupport, 'hybrid'],
    ['TLS 1.3', position.tlsSupport, 'tls'],
    ['PQC certificates', position.certificateSupport, 'certificate'],
    ['Key management', position.keyManagementSupport, 'keyManagement'],
  ]
  const internal = context.incoming.filter((entry) => entry.edge.relation === 'consumes')

  return (
    <>
      <DetailFacts items={[
        ['Category', vendor.category],
        ['Business criticality', RISK_LABEL[vendor.criticality]],
        ['Risk score', `${vendor.riskScore}/100 · ${RISK_LABEL[vendor.risk]}`, true],
        ['Business owner', vendor.businessOwner],
        ['Connected systems', String(vendor.linkedAssetCount), true],
        ['Migration support', MIGRATION_SUPPORT_LABEL[vendor.migrationSupport]],
      ]} />

      <DetailSection title="Claim vs measurement">
        <DetailFacts items={[
          ['Vendor claims', READINESS_LABEL[vendor.vendorCommitment]],
          ['QGuard measured', READINESS_LABEL[vendor.assessedReadiness]],
        ]} />
        <p className="qg-wf__text-muted" style={{ marginTop: 4 }}>{vendor.assessedReadinessBasis}</p>
        {status.stale && <p className="qg-wf__text-muted" style={{ marginTop: 4 }}>This assessment is past its review window, so a positive result is shown gray until it is re-verified.</p>}
      </DetailSection>

      <DetailSection title="PQC support evidence">
        <div className="qg-wf__list">
          {support.map(([label, verdict, key]) => (
            <div key={key} className="qg-wf__row">
              <span className="qg-wf__row-main"><span style={{ display: 'block', fontWeight: 700 }}>{label}</span><span className="qg-wf__row-kicker">{PROVENANCE_WORD[position.provenance[key]] ?? 'no evidence'}</span></span>
              <StatusPill status={VERDICT_STATUS[verdict]} label={verdict === 'unknown' ? 'Unknown' : verdict.toUpperCase()} />
            </div>
          ))}
        </div>
        {position.currentAlgorithms.length > 0 && (
          <p className="qg-wf__text-muted" style={{ marginTop: 6 }}>Observed: <span className="font-mono">{position.currentAlgorithms.join(', ')}</span></p>
        )}
        <p className="qg-wf__text-muted" style={{ marginTop: 4 }}>A vendor claim never counts as support — only a measured pass is green.</p>
      </DetailSection>

      {internal.length > 0 && (
        <DetailSection title={`Connected internal systems (${internal.length})`}>
          <div className="qg-wf__list">
            {internal.slice(0, 6).map(({ node }) => (
              <button key={node.id} type="button" className="qg-wf__row" onClick={() => context.select(node.id)}>
                <span className="qg-wf__row-main"><span className="qg-wf__row-kicker">{node.kindLabel}</span><span style={{ display: 'block', fontWeight: 700 }}>{node.label}</span></span>
                <ArrowRight className="h-3 w-3" aria-hidden="true" />
              </button>
            ))}
          </div>
        </DetailSection>
      )}

      <DetailSection title="Migration blockers">
        <div className="qg-wf__list">
          {blockers.map((factor) => (
            <div key={factor.key} className="qg-wf__row" style={{ alignItems: 'flex-start' }}>
              <span className="qg-wf__row-main" style={{ whiteSpace: 'normal' }}>
                <span style={{ display: 'block', fontWeight: 700, whiteSpace: 'normal' }}>{factor.label} · {factor.score}</span>
                <span className="qg-wf__text-muted" style={{ display: 'block', whiteSpace: 'normal' }}>{factor.evidence}</span>
              </span>
            </div>
          ))}
          {vendor.overdueRequests > 0 && <div className="qg-wf__row"><StatusPill status="critical" label={`${vendor.overdueRequests} evidence request(s) overdue`} /></div>}
          {missingObligations.map((obligation) => (
            <div key={obligation.key} className="qg-wf__row"><StatusPill status="attention" label={`${obligation.label}: ${OBLIGATION_LABEL[obligation.state]}`} /></div>
          ))}
        </div>
      </DetailSection>

      <DetailSection title="Recommended actions">
        <ul className="qg-wf__list">
          {vendor.migrationSupportDetail.slice(0, 3).map((line, index) => <li key={index} className="qg-wf__text">· {line}</li>)}
          {vendor.evidenceState !== 'complete' && <li className="qg-wf__text">· Request PQC evidence — evidence is currently {EVIDENCE_LABEL[vendor.evidenceState].toLowerCase()}.</li>}
          {position.kemSupport !== 'pass' && vendor.observedHosts.length > 0 && <li className="qg-wf__text">· Run a controlled hybrid key-exchange test against an observed host.</li>}
        </ul>
      </DetailSection>

      <DetailSection title="Evidence source">
        <p className="qg-wf__text-muted">{vendor.evidenceBasis}</p>
        <p className="qg-wf__text-muted" style={{ marginTop: 4 }}>
          Last verified {relativeTime(vendor.lastAssessmentAt)} · next review {dateFmt(vendor.nextReviewAt)}
        </p>
      </DetailSection>

      <div className="flex flex-wrap gap-1.5">
        <DetailLink primary onClick={() => onOpenAssessment(vendor)}><ClipboardList /> Full assessment &amp; evidence</DetailLink>
        <DetailLink href={suiteHref('trust', { vendor: vendor.id })}><Link2 /> Trust chains</DetailLink>
        <DetailLink href={suiteHref('lab', { vendor: vendor.id })}><FlaskConical /> Hybrid test</DetailLink>
        <DetailLink href={suiteHref('ecosystem', { vendor: vendor.id })}><Globe2 /> Dependencies</DetailLink>
      </div>
    </>
  )
}
