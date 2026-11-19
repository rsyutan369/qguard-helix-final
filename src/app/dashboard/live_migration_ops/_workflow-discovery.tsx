import { Cable, Cpu, FileBadge2, X } from 'lucide-react'
import type { ReportedAgentDiscovery } from '@/lib/migration/agent-discovery'

export type CanvasDiscovery = ReportedAgentDiscovery & { agentName: string; order: number }

const discoveryMeta = {
  endpoint: { label: 'Endpoint', icon: Cable },
  certificate: { label: 'Certificate', icon: FileBadge2 },
  algorithm: { label: 'Algorithm', icon: Cpu },
}

function discoveryLabel(item: CanvasDiscovery) {
  if (item.kind === 'algorithm' && item.evidenceType === 'tls-cipher') return 'Cipher suite'
  if (item.kind === 'algorithm' && item.evidenceType === 'tls-key-exchange') return 'Key exchange'
  return discoveryMeta[item.kind].label
}

export function DiscoveryCard({ item, selected, onSelect }: {
  item: CanvasDiscovery
  selected: boolean
  onSelect: (id: string) => void
}) {
  const { icon: Icon } = discoveryMeta[item.kind]
  const label = discoveryLabel(item)
  return (
    <button
      type="button"
      className="nodrag qg-lw-discovery"
      data-severity={item.severity}
      aria-pressed={selected}
      onClick={() => onSelect(item.id)}
      title={`${label}: ${item.label} · ${item.agentName}`}
    >
      <span className="qg-lw-discovery-icon"><Icon size={15} aria-hidden="true" /></span>
      <span className="min-w-0">
        <span className="qg-lw-discovery-type">{label}</span>
        <strong className="block truncate text-xs">{item.label}</strong>
        <span className="block truncate text-[11px] text-[color:var(--lw-ink-soft)]">{item.agentName}</span>
      </span>
      <span className="qg-lw-discovery-badge">{item.severity || 'Observed'}</span>
    </button>
  )
}

export function DiscoveryInspector({ item, onClose, className }: {
  item: CanvasDiscovery
  onClose: () => void
  className?: string
}) {
  const fields = [
    ['Asset', item.asset],
    ['Reporting agent', item.agentName],
    ['Evidence type', item.evidenceType],
    ['Observed', item.observedAt ? new Date(item.observedAt).toLocaleString() : 'Time unavailable'],
    ['Received', new Date(item.receivedAt).toLocaleString()],
    ['Protocol', item.protocol],
    ['Algorithm', item.algorithm],
    ['Certificate fingerprint', item.fingerprint],
    ['Valid until', item.validUntil && new Date(item.validUntil).toLocaleString()],
  ]
  return (
    <section className={`qg-lw-discovery-inspector overflow-auto rounded-xl border p-4 ${className || ''}`} aria-label="Discovery evidence">
      <header className="mb-3 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="qg-lw-discovery-type">{discoveryLabel(item)} · {item.severity || 'Observed'}</div>
          <h3 className="break-words text-sm font-bold">{item.label}</h3>
        </div>
        <button type="button" title="Close evidence" aria-label="Close evidence" onClick={onClose} className="qg-lw-discovery-control shrink-0 rounded-md p-1.5"><X size={16} /></button>
      </header>
      {item.description && <p className="mb-3 text-xs leading-relaxed">{item.description}</p>}
      <dl className="grid gap-2 border-y border-[var(--lw-line)] py-3 text-xs">
        {fields.map(([label, value]) => value && (
          <div key={label} className="grid grid-cols-[7rem_minmax(0,1fr)] gap-2">
            <dt className="font-semibold text-[color:var(--lw-ink-soft)]">{label}</dt>
            <dd className="break-words">{value}</dd>
          </div>
        ))}
      </dl>
      {item.recommendation && (
        <div className="mt-3 text-xs leading-relaxed">
          <h4 className="font-bold">Recommended action</h4>
          <p>{item.recommendation}</p>
        </div>
      )}
    </section>
  )
}
