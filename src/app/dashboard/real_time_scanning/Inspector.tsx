'use client'

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Copy, Crosshair, GripVertical, Maximize2, Minimize2, RotateCw, X } from 'lucide-react'
import { findingsForNode, type LiveGraphState } from '@/lib/live-scan/graph-reducer'
import type { LiveEdge, LiveEvent, LiveEvidence, LiveFinding, LiveNode } from '@/lib/live-scan/types'
import { EXPOSURE_LABEL, FINDING_TYPE_LABEL, SEVERITY_LABEL, SEVERITY_RANK } from '@/lib/live-scan/policy'
import { KIND_LABEL, STATUS_TONE, STATUS_WORD } from './LiveCanvas'

/**
 * Evidence drawer for a node, an edge or a finding. Everything shown is read
 * from the run's event log; an absent field renders "Not observed", never a
 * default that could pass for a measurement.
 */

const TABS = ['Overview', 'Cryptography', 'Certificate Chain', 'Relationships', 'Findings', 'Evidence', 'History'] as const
type Tab = (typeof TABS)[number]

const FIELD_LABEL: Record<string, string> = {
  assetType: 'Asset type', addresses: 'Resolved addresses', owner: 'Owner', environment: 'Environment', criticality: 'Recorded criticality',
  scanStatus: 'Scan status', riskScore: 'Engine risk score', riskLevel: 'Engine risk level', quantumReadinessScore: 'Quantum readiness score',
  quantumReadinessLevel: 'Quantum readiness level', durationMs: 'Scan duration (ms)', engineFindings: 'Engine findings', lastObserved: 'Last observed',
  handshake: 'Handshake', sni: 'SNI', tlsVersion: 'Negotiated protocol', cipher: 'Negotiated cipher', supportedProtocols: 'Supported protocols',
  legacyProtocols: 'Legacy protocols accepted', alpn: 'ALPN', forwardSecrecy: 'Forward secrecy', staticRsaAccepted: 'Static RSA accepted',
  handshakeMs: 'Handshake (ms)', chainTrusted: 'Trust-store validation', trustError: 'Trust error', hostnameMatches: 'Hostname matches',
  ocspStapled: 'OCSP stapled', sctPresent: 'SCTs present', quantumVerdict: 'Quantum verdict', quantumReason: 'Verdict basis',
  postQuantumReadiness: 'PQ readiness (edge)', subject: 'Subject', subjectAltNames: 'Subject alternative names', sanCount: 'SAN count',
  issuer: 'Issuer', fingerprint: 'SHA-256 fingerprint', serialNumber: 'Serial number', validFrom: 'Not before', validTo: 'Not after',
  daysRemaining: 'Days remaining', expirationStatus: 'Expiration status', publicKeyAlgorithm: 'Public-key algorithm', publicKeySize: 'Key size (bits)',
  signatureAlgorithm: 'Signature algorithm', signatureOid: 'Signature OID', selfSigned: 'Self-signed', validation: 'Path validation',
  chainDepth: 'Chain depth', caType: 'CA type', selfSignatureValid: 'Self-signature verifies', validationStatus: 'Validation status',
  trustStoreIdentity: 'Trust-store identity', identityBasis: 'Identity basis', role: 'Role', family: 'Family', parameters: 'Parameters',
  classification: 'Classification', quantumExposure: 'Quantum exposure', policyResult: 'Policy result', migrationTarget: 'Migration target',
  appType: 'Application type', statusCode: 'HTTP status', httpVersion: 'HTTP version', server: 'Server header', poweredBy: 'X-Powered-By',
  hsts: 'HSTS', dependencyType: 'Dependency basis', vendorRole: 'Vendor role', basis: 'Attribution basis', signals: 'Signals',
  store: 'Store', policy: 'Policy', note: 'Note', engines: 'Engines', family_: 'Family', resolvedFrom: 'Resolved from', target: 'Target', port: 'Port',
  inventoryAssetId: 'Inventory asset id', error: 'Error', analyzed: 'Analyzed', algorithmCount: 'Algorithms linked',
  finalUrl: 'Response URL', notAfter: 'Not after',
  notBefore: 'Not before', fingerprintSha256: 'SHA-256 fingerprint',
  signatureVerifiedByNext: 'Signature verified by next certificate',
}

/** Internal routing keys — not observations, never shown as facts. */
const HIDDEN_KEYS = new Set(['findingId', 'roleKey', 'cluster', 'memberIds', 'titles', 'trustStoreIdentity', 'algorithmCount'])

function fmt(value: unknown): ReactNode {
  if (value === null || value === undefined || value === '') return <span className="rt-muted">Not observed</span>
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  if (Array.isArray(value)) return value.length ? value.join(', ') : <span className="rt-muted">No values recorded</span>
  if (typeof value === 'object') return <code className="rt-mono">{JSON.stringify(value)}</code>
  return String(value)
}

function chainVerdict(value: unknown): ReactNode {
  if (value === true) return <span style={{ color: 'var(--rt-green)' }}>✓ Path validated (platform trust store)</span>
  if (value === false) return <span style={{ color: 'var(--rt-red)' }}>✕ Path validation failed</span>
  return <span className="rt-muted">? Not validated</span>
}

function KV({ data, keys }: { data: Record<string, unknown>; keys?: string[] }) {
  const entries = (keys ?? Object.keys(data)).filter((key) => key in data && !HIDDEN_KEYS.has(key))
  if (!entries.length) return <p className="rt-muted" style={{ fontSize: 12 }}>Nothing recorded for this section.</p>
  return (
    <dl className="rt-kv">
      {entries.map((key) => (
        <div key={key} style={{ display: 'contents' }}>
          <dt>{FIELD_LABEL[key] ?? key}</dt>
          <dd>{key === 'chainTrusted' ? chainVerdict(data[key]) : fmt(data[key])}</dd>
        </div>
      ))}
    </dl>
  )
}

function copy(text: string) {
  void navigator.clipboard?.writeText(text).catch(() => undefined)
}

function relationshipBasis(edge: LiveEdge): string {
  if (edge.type === 'TRUSTED_BY_STORE' || (edge.type === 'CHAIN_VALIDATED_TO' && !edge.target.startsWith('truststore:'))) {
    return 'The scan recorded a successful runtime path check. The specific trust anchor is unconfirmed.'
  }
  if (edge.type === 'MANAGED_BY_VENDOR' || edge.type === 'BACKED_BY') {
    return `${edge.basis} Vendor ownership and supply-chain exposure require independent verification.`
  }
  return edge.basis
}

function relationshipVerification(edge: LiveEdge): string {
  if (edge.type === 'MANAGED_BY_VENDOR' || edge.type === 'BACKED_BY') return 'Inferred attribution'
  if (edge.type === 'TRUSTED_BY_STORE' || (edge.type === 'CHAIN_VALIDATED_TO' && !edge.target.startsWith('truststore:'))) return 'Anchor unconfirmed'
  return edge.verification
}

export interface InspectorProps {
  graph: LiveGraphState
  events: LiveEvent[]
  nodeId: string | null
  edgeId: string | null
  onClose: () => void
  onSelectNode: (id: string) => void
  onSelectEdge: (id: string) => void
  onFocus: (id: string) => void
  onRescan: (target: string) => void
  canRescan: boolean
  replaying: boolean
  width: number
  expanded: boolean
  onResize: (width: number) => void
  onToggleExpanded: () => void
}

export function Inspector({ graph, events, nodeId, edgeId, onClose, onSelectNode, onSelectEdge, onFocus, onRescan, canRescan, replaying, width, expanded, onResize, onToggleExpanded }: InspectorProps) {
  const [tab, setTab] = useState<Tab>('Overview')
  const drawerRef = useRef<HTMLElement>(null)
  const stopDrag = useRef<(() => void) | null>(null)
  useEffect(() => () => stopDrag.current?.(), [])
  const node: LiveNode | null = nodeId ? graph.nodes[nodeId] ?? null : null
  const edge: LiveEdge | null = edgeId ? graph.edges[edgeId] ?? null : null
  const finding: LiveFinding | null = node?.kind === 'finding' ? graph.findings[String(node.data.findingId ?? node.id)] ?? null : null

  const related = useMemo(() => {
    if (!node) return [] as LiveEdge[]
    return Object.values(graph.edges).filter((item) => item.source === node.id || item.target === node.id)
  }, [graph.edges, node])

  const findings = useMemo(() => {
    if (!node) return [] as LiveFinding[]
    if (finding) return [finding]
    return findingsForNode(graph, node).sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
  }, [graph, node, finding])

  const evidence = useMemo(() => {
    const ids = new Set<string>([...(node?.evidenceIds ?? []), ...(finding?.evidenceIds ?? []), ...(edge?.evidenceId ? [edge.evidenceId] : [])])
    return [...ids].map((id) => graph.evidence[id]).filter((item): item is LiveEvidence => Boolean(item))
  }, [graph.evidence, node, finding, edge])

  const history = useMemo(() => {
    const id = node?.id ?? edge?.id
    if (!id) return []
    return events.filter((event) => event.seq <= graph.lastSeq && event.entityId === id)
  }, [events, node, edge, graph.lastSeq])

  const subjects = useMemo(() => {
    const ids = new Set(finding?.affectedNodeIds ?? (node ? [node.id] : edge ? [edge.source, edge.target] : []))
    const links = Object.values(graph.edges)
    for (const link of links) if (link.type === 'HOSTS_SERVICE' && ids.has(link.source)) ids.add(link.target)
    for (const link of links) if (link.type === 'PRESENTS_CERTIFICATE' && ids.has(link.source)) ids.add(link.target)
    return ids
  }, [finding, node, edge, graph.edges])

  const chain = useMemo(() => {
    const idsWithEvidence = new Set<string>()
    for (const item of Object.values(graph.edges)) {
      if (item.type === 'PRESENTS_CERTIFICATE' && (subjects.has(item.source) || subjects.has(item.target)) && item.evidenceId) {
        idsWithEvidence.add(item.evidenceId)
      }
    }
    for (const id of subjects) {
      const entity = graph.nodes[id]
      if (entity?.kind !== 'ca' && entity?.kind !== 'certificate') continue
      for (const evidenceId of entity.evidenceIds) idsWithEvidence.add(evidenceId)
    }
    return [...idsWithEvidence].flatMap((id) => {
      const record = graph.evidence[id]
      return record?.sourceType === 'certificate-chain' ? [record] : []
    })
  }, [subjects, graph])

  const crypto = useMemo(() => {
    return Object.values(graph.edges).flatMap((link) => {
      if (!subjects.has(link.source) || !['USES_PUBLIC_KEY_ALGORITHM', 'USES_SIGNATURE_ALGORITHM', 'NEGOTIATED_KEY_ESTABLISHMENT'].includes(link.type)) return []
      const algorithm = graph.nodes[link.target]
      return algorithm?.kind === 'algorithm' ? [{ edge: link, node: algorithm }] : []
    })
  }, [subjects, graph.edges, graph.nodes])

  if (!node && !edge) return null
  const title = node ? node.label : `${edge!.type.replace(/_/g, ' ')}`
  const target = node?.targets[0] ?? null

  return (
    <>
      <div className="rt-scrim rt-inspector-scrim" onClick={onClose} aria-hidden="true" />
      <aside ref={drawerRef} className={`rt-drawer${expanded ? ' is-expanded' : ''}`} role="dialog" aria-label={`Details for ${title}`} style={{ width: expanded ? '100%' : `min(${width}px, 100%)` }}>
        {!expanded && <div className="rt-drawer-resize" role="separator" aria-label="Resize details drawer"
          aria-orientation="vertical" aria-valuemin={320} aria-valuemax={1600} aria-valuenow={width} tabIndex={0}
          onKeyDown={(event) => {
            if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
            event.preventDefault()
            onResize(event.key === 'Home' ? 320 : event.key === 'End' ? 1600 : width + (event.key === 'ArrowLeft' ? 48 : -48))
          }}
          onPointerDown={(event) => {
            if (event.button !== 0) return
            event.preventDefault()
            event.currentTarget.focus()
            stopDrag.current?.()
            const { pointerId, clientX } = event
            const initialWidth = drawerRef.current?.offsetWidth ?? width
            const move = (next: PointerEvent) => {
              if (next.pointerId === pointerId) onResize(initialWidth + clientX - next.clientX)
            }
            const stop = () => {
              window.removeEventListener('pointermove', move)
              window.removeEventListener('pointerup', stop)
              window.removeEventListener('pointercancel', stop)
              window.removeEventListener('blur', stop)
              stopDrag.current = null
            }
            stopDrag.current = stop
            window.addEventListener('pointermove', move)
            window.addEventListener('pointerup', stop)
            window.addEventListener('pointercancel', stop)
            window.addEventListener('blur', stop)
          }}>
          <GripVertical size={13} aria-hidden />
        </div>}
        <div className="rt-drawer-head">
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="rt-node-kind">{node ? KIND_LABEL[node.kind] : 'Relationship'}</div>
              <h2 style={{ margin: '2px 0 0', fontSize: 16, fontWeight: 900, wordBreak: 'break-word' }}>{title}</h2>
              {node && <span className="rt-status" style={{ marginTop: 6, ['--tone' as string]: STATUS_TONE[node.status] }}>{STATUS_WORD[node.status]}</span>}
              {edge && (
                <p className="rt-soft" style={{ fontSize: 12, margin: '6px 0 0' }}>
                  <button type="button" className="rt-chip" onClick={() => onSelectNode(edge.source)}>{graph.nodes[edge.source]?.label ?? edge.source}</button>
                  {' → '}
                  <button type="button" className="rt-chip" onClick={() => onSelectNode(edge.target)}>{graph.nodes[edge.target]?.label ?? edge.target}</button>
                </p>
              )}
            </div>
            <button type="button" className="rt-btn" aria-expanded={expanded} onClick={onToggleExpanded}>
              {expanded ? <Minimize2 size={15} aria-hidden /> : <Maximize2 size={15} aria-hidden />} {expanded ? 'Restore width' : 'Expand'}
            </button>
            <button type="button" className="rt-btn is-icon" onClick={onClose} aria-label="Close details"><X size={15} /></button>
          </div>
          <p className="rt-inspector-source">{replaying ? `Replay · through event #${graph.lastSeq}` : `Scan record · through event #${graph.lastSeq}`}</p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 10 }}>
            <button type="button" className="rt-btn" onClick={() => copy(node?.id ?? edge!.id)}><Copy size={13} /> Copy ID</button>
            {node && <button type="button" className="rt-btn" onClick={() => onFocus(node.id)}><Crosshair size={13} /> Focus on canvas</button>}
            {node && target && canRescan && (node.kind === 'asset' || node.kind === 'endpoint') && (
              <button type="button" className="rt-btn" onClick={() => onRescan(target)}><RotateCw size={13} /> Rescan asset</button>
            )}
          </div>
        </div>

        <div className="rt-tabs" role="tablist">
          {TABS.map((name) => (
            <button key={name} type="button" role="tab" aria-selected={tab === name} className={`rt-tab${tab === name ? ' is-on' : ''}`} onClick={() => setTab(name)}>
              {name}
              {name === 'Findings' && findings.length ? ` (${findings.length})` : ''}
              {name === 'Evidence' && evidence.length ? ` (${evidence.length})` : ''}
            </button>
          ))}
        </div>

        <div className="rt-drawer-body">
          {tab === 'Overview' && node && !finding && (
            <>
              <div className="rt-block">
                <h4>Recorded facts</h4>
                <KV data={node.data} keys={node.kind === 'ca' ? Object.keys(node.data).filter((key) => key !== 'validationStatus' && key !== 'caType') : undefined} />
              </div>
              {node.kind === 'ca' && <p className="rt-banner">See Certificate Chain for the recorded path result for each endpoint and the checks on individual signatures.</p>}
              {node.kind === 'vendor' && <p className="rt-banner">Vendor attribution is based on the linked scan signals. Operational ownership and supply-chain exposure are unverified.</p>}
              {node.kind === 'certificate' && node.targets.length > 1 && <p className="rt-banner">Overview shows the latest recorded facts for this shared certificate. Certificate Chain lists each recorded endpoint observation.</p>}
              {findings.length > 0 && (
                <div className="rt-block">
                  <h4>Related findings</h4>
                  <div className="rt-related-findings">
                    {findings.filter((item) => item.status === 'open' && item.severity !== 'info').slice(0, 4).map((item) => (
                      <button type="button" key={item.id} className={`rt-chip tone-${item.severity}`} onClick={() => onSelectNode(item.id)}>
                        {SEVERITY_LABEL[item.severity]} · {item.title}
                      </button>
                    ))}
                    <button type="button" className="rt-chip" onClick={() => setTab('Findings')}>View all {findings.length}</button>
                  </div>
                </div>
              )}
              <div className="rt-block">
                <h4>Provenance</h4>
                <dl className="rt-kv">
                  <dt>Entity ID</dt><dd className="rt-mono">{node.id}</dd>
                  <dt>Scan targets</dt><dd>{node.targets.join(', ') || 'Scanner'}</dd>
                  <dt>First event</dt><dd className="rt-mono">#{node.firstSeq}</dd>
                  <dt>Latest update</dt><dd className="rt-mono">#{node.lastSeq}</dd>
                  <dt>Observation time</dt><dd>{new Date(node.observedAt).toLocaleString()}</dd>
                </dl>
              </div>
            </>
          )}
          {tab === 'Overview' && finding && (
            <>
              <div className={`rt-block tone-${finding.severity}`}>
                <h4>{FINDING_TYPE_LABEL[finding.type]}</h4>
                <p style={{ fontSize: 12.5, lineHeight: 1.55, margin: 0 }}>{finding.description}</p>
              </div>
              <div className="rt-block">
                <dl className="rt-kv">
                  <dt>Severity</dt><dd className={`tone-${finding.severity}`} style={{ color: 'var(--tone)', fontWeight: 800 }}>{SEVERITY_LABEL[finding.severity]}</dd>
                  <dt>Exposure class</dt><dd>{EXPOSURE_LABEL[finding.exposure]}</dd>
                  <dt>Status</dt><dd>{finding.status === 'unknown' ? 'Assessment gap' : finding.status[0].toUpperCase() + finding.status.slice(1)}</dd>
                  <dt>Rule</dt><dd className="rt-mono">{finding.ruleId} · v{finding.ruleVersion}</dd>
                  <dt>Source module</dt><dd className="rt-mono">{finding.sourceModule}</dd>
                  <dt>Affected targets</dt><dd>{finding.affectedTargets.join(', ')}</dd>
                  <dt>First seen</dt><dd>{new Date(finding.firstSeen).toLocaleString()}</dd>
                  <dt>Last seen</dt><dd>{new Date(finding.lastSeen).toLocaleString()}</dd>
                  <dt>Standards</dt><dd>{finding.standards.length ? finding.standards.join('; ') : <span className="rt-muted">None cited</span>}</dd>
                </dl>
              </div>
              <div className="rt-block"><h4>Recommended remediation</h4><p style={{ fontSize: 12.5, margin: 0, lineHeight: 1.55 }}>{finding.remediation}</p></div>
              <div className="rt-block"><h4>Observed values</h4><KV data={finding.observed} /></div>
              <div className="rt-block">
                <h4>Affected entities</h4>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {finding.affectedNodeIds.map((id) => graph.nodes[id] && (
                    <button key={id} type="button" className="rt-chip" onClick={() => onSelectNode(id)}>{KIND_LABEL[graph.nodes[id].kind]}: {graph.nodes[id].label}</button>
                  ))}
                </div>
              </div>
            </>
          )}
          {tab === 'Overview' && edge && (
            <div className="rt-block">
              <h4>Why this relationship exists</h4>
                <p style={{ fontSize: 12.5, margin: '0 0 10px', lineHeight: 1.55 }}>{relationshipBasis(edge)}</p>
              <dl className="rt-kv">
                <dt>Type</dt><dd className="rt-mono">{edge.type}</dd>
                <dt>Verification</dt><dd style={{ fontWeight: 800 }}>{relationshipVerification(edge)}</dd>
                <dt>Evidence source</dt><dd>{edge.evidenceSource}</dd>
                <dt>Evidence ID</dt><dd className="rt-mono">{edge.evidenceId ?? 'None'}</dd>
                <dt>Observed</dt><dd>{new Date(edge.observedAt).toLocaleString()}</dd>
                <dt>Confidence</dt><dd>{edge.confidence ?? <span className="rt-muted">Not applicable</span>}</dd>
                <dt>Scan</dt><dd className="rt-mono">{edge.scanId}</dd>
              </dl>
            </div>
          )}

          {tab === 'Cryptography' && (
            crypto.length ? crypto.map(({ edge: link, node: alg }) => (
              <button key={link.id} type="button" className="rt-block" style={{ display: 'block', width: '100%', textAlign: 'left', cursor: 'pointer', color: 'inherit' }} onClick={() => onSelectNode(alg.id)}>
                <h4>{String(alg.data.role ?? 'Algorithm')}</h4>
                <div style={{ fontSize: 14, fontWeight: 800 }}>{alg.label}</div>
                <p className="rt-muted">{graph.nodes[link.source]?.label ?? link.source} · {link.basis}</p>
              </button>
            )) : node?.kind === 'algorithm'
              ? <div className="rt-block"><KV data={node.data} /></div>
              : <p className="rt-muted" style={{ fontSize: 12 }}>No cryptographic algorithm is linked directly to this entity.</p>
          )}

          {tab === 'Certificate Chain' && (
            chain.length ? chain.map((record) => (
              <div key={record.id} className="rt-block">
                <h4>{record.sourceEndpoint}</h4>
                <p className="rt-soft">{chainVerdict(record.observed.chainTrusted)}</p>
                <p className="rt-muted">{new Date(record.observedAt).toLocaleString()}</p>
                {typeof record.observed.leaf === 'object' && record.observed.leaf !== null &&
                  <><h4>Leaf certificate</h4><KV data={record.observed.leaf as Record<string, unknown>} /></>}
                {Array.isArray(record.observed.chain) && record.observed.chain.slice(1).map((entry, index) => (
                  <div key={index} className="rt-chain-entry">
                    <h4>Presented CA certificate {index + 1}</h4>
                    <KV data={entry} />
                  </div>
                ))}
                <div className="rt-chain-entry">
                  <KV data={record.observed} keys={['trustError', 'hostnameMatches', 'subjectAltNames']} />
                </div>
              </div>
            )) : <p className="rt-muted" style={{ fontSize: 12 }}>No certificate chain is attached to this entity.</p>
          )}

          {tab === 'Relationships' && (
            related.length ? related.map((item) => {
              const other = graph.nodes[item.source === node?.id ? item.target : item.source]
              return (
                <button key={item.id} type="button" className="rt-block" style={{ display: 'block', width: '100%', textAlign: 'left', cursor: 'pointer', color: 'inherit' }} onClick={() => onSelectEdge(item.id)}>
                  <h4>{item.source === node?.id ? '→' : '←'} {item.type.replace(/_/g, ' ')} · {relationshipVerification(item)}</h4>
                  <div style={{ fontWeight: 800, fontSize: 12.5 }}>{other ? `${KIND_LABEL[other.kind]}: ${other.label}` : '—'}</div>
                  <div className="rt-muted" style={{ fontSize: 11, marginTop: 2 }}>{relationshipBasis(item)}</div>
                </button>
              )
            }) : <p className="rt-muted" style={{ fontSize: 12 }}>{edge ? 'Select an endpoint of this relationship to see its neighbours.' : 'No relationships recorded.'}</p>
          )}

          {tab === 'Findings' && (
            findings.length ? findings.map((item) => (
              <button key={item.id} type="button" className={`rt-block tone-${item.severity}`} style={{ display: 'block', width: '100%', textAlign: 'left', cursor: 'pointer', color: 'inherit' }} onClick={() => onSelectNode(item.id)}>
                <h4 style={{ color: 'var(--tone)' }}>{SEVERITY_LABEL[item.severity]} · {EXPOSURE_LABEL[item.exposure]}</h4>
                <div style={{ fontWeight: 800, fontSize: 12.5 }}>{item.title}</div>
                <div className="rt-muted" style={{ fontSize: 11, marginTop: 3 }}>{item.remediation}</div>
              </button>
            )) : <p className="rt-muted" style={{ fontSize: 12 }}>No findings reference this entity.</p>
          )}

          {tab === 'Evidence' && (
            evidence.length ? evidence.map((item) => (
              <div key={item.id} className="rt-block">
                <h4>{item.sourceType.replace(/-/g, ' ')} · {item.engine}</h4>
                <dl className="rt-kv" style={{ marginBottom: 8 }}>
                  <dt>Result</dt><dd>{item.validationResult}</dd>
                  <dt>Source</dt><dd className="rt-mono">{item.sourceEndpoint}</dd>
                  <dt>Observed</dt><dd>{new Date(item.observedAt).toLocaleString()}</dd>
                  <dt>Content SHA-256</dt><dd className="rt-mono" style={{ fontSize: 10 }}>{item.contentHash}</dd>
                </dl>
                <pre className="rt-pre">{JSON.stringify(item.observed, null, 2)}</pre>
                <button type="button" className="rt-btn" style={{ marginTop: 8 }} onClick={() => copy(JSON.stringify(item, null, 2))}><Copy size={13} /> Copy evidence</button>
              </div>
            )) : <p className="rt-muted" style={{ fontSize: 12 }}>No evidence record attached.</p>
          )}

          {tab === 'History' && (
            history.length ? (
              <div className="rt-block">
                {history.map((event) => (
                  <div key={event.seq} style={{ display: 'flex', gap: 10, fontSize: 11.5, padding: '3px 0' }}>
                    <span className="rt-mono rt-muted">#{event.seq}</span>
                    <span className="rt-mono">{event.type}</span>
                    <span className="rt-muted" style={{ marginLeft: 'auto' }}>{new Date(event.at).toLocaleTimeString()}</span>
                  </div>
                ))}
              </div>
            ) : <p className="rt-muted" style={{ fontSize: 12 }}>No events recorded for this entity.</p>
          )}
        </div>
      </aside>
    </>
  )
}
