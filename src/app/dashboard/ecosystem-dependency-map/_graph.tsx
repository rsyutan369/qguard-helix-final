'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Crosshair, Filter, Minus, Plus, Search, Share2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  NODE_KIND_LABEL,
  type EcosystemEdge, type EcosystemNode, type EcosystemNodeKind, type Readiness, type RiskLevel,
} from '@/lib/ecosystem/external-trust-intelligence'
import { READINESS_GLYPH, RISK_GLYPH, TONE_HEX, READINESS_TONE, RISK_TONE } from '../_components/external-trust/_shared'

/**
 * Ecosystem dependency graph.
 *
 * Layered left→right by node kind so the reading order matches the real
 * dependency direction (application → service → crypto/protocol → PKI/identity
 * → vendor). Only the server-selected bounded node set is rendered.
 *
 * Controls: zoom, pan, search, kind/criticality/readiness filters, depth limit,
 * fit-to-view and focus. Keyboard: arrows pan, +/- zoom, 0 resets.
 */

const COL_WIDTH = 200
const ROW_HEIGHT = 44
const NODE_WIDTH = 164
const NODE_HEIGHT = 30
const PADDING = 26

const LAYER_ORDER: EcosystemNodeKind[] = [
  'business-service', 'application', 'service', 'infrastructure',
  'crypto', 'protocol', 'identity', 'pki', 'vendor',
]

interface Positioned extends EcosystemNode { x: number; y: number }

export interface GraphFilters {
  kinds: Set<EcosystemNodeKind>
  criticality: RiskLevel | 'all'
  readiness: Readiness | 'all'
  search: string
  maxDepth: number
}

export function EcosystemGraph({
  nodes, edges, focusId, highlighted, filters, onFiltersChange, onSelect,
}: {
  nodes: EcosystemNode[]
  edges: EcosystemEdge[]
  focusId: string | null
  highlighted: Set<string> | null
  filters: GraphFilters
  onFiltersChange: (patch: Partial<GraphFilters>) => void
  onSelect: (node: EcosystemNode | null) => void
}) {
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [hovered, setHovered] = useState<string | null>(null)
  const dragRef = useRef<{ x: number; y: number; panX: number; panY: number } | null>(null)
  const svgRef = useRef<SVGSVGElement>(null)

  const visibleNodes = useMemo(() => {
    const term = filters.search.trim().toLowerCase()
    return nodes.filter((node) => {
      if (filters.kinds.size && !filters.kinds.has(node.kind)) return false
      if (filters.criticality !== 'all' && node.criticality !== filters.criticality) return false
      if (filters.readiness !== 'all' && node.readiness !== filters.readiness) return false
      if (term && !`${node.label} ${node.owner} ${node.algorithms.join(' ')}`.toLowerCase().includes(term)) return false
      return true
    })
  }, [nodes, filters])

  const layout = useMemo(() => {
    const byLayer = new Map<EcosystemNodeKind, EcosystemNode[]>()
    for (const node of visibleNodes) {
      const list = byLayer.get(node.kind) || []
      list.push(node)
      byLayer.set(node.kind, list)
    }
    const activeLayers = LAYER_ORDER.filter((kind) => (byLayer.get(kind) || []).length > 0)
    const positioned: Positioned[] = []
    let maxRows = 0
    activeLayers.forEach((kind, columnIndex) => {
      // Cap each column so one dense layer cannot make the canvas unusable.
      const inLayer = (byLayer.get(kind) || [])
        .slice()
        .sort((a, b) => (b.criticality === 'critical' ? 1 : 0) - (a.criticality === 'critical' ? 1 : 0) || a.label.localeCompare(b.label))
        .slice(0, 26)
      maxRows = Math.max(maxRows, inLayer.length)
      inLayer.forEach((node, rowIndex) => {
        positioned.push({ ...node, x: PADDING + columnIndex * COL_WIDTH, y: PADDING + 28 + rowIndex * ROW_HEIGHT })
      })
    })
    return {
      nodes: positioned,
      activeLayers,
      width: PADDING * 2 + Math.max(1, activeLayers.length) * COL_WIDTH,
      height: PADDING * 2 + 40 + Math.max(1, maxRows) * ROW_HEIGHT,
    }
  }, [visibleNodes])

  const nodeById = useMemo(() => new Map(layout.nodes.map((node) => [node.id, node])), [layout.nodes])
  const visibleEdges = useMemo(
    () => edges.filter((edge) => nodeById.has(edge.source) && nodeById.has(edge.target)),
    [edges, nodeById],
  )

  const neighbours = useMemo(() => {
    const focus = hovered || focusId
    if (!focus) return null
    const ids = new Set<string>([focus])
    for (const edge of visibleEdges) {
      if (edge.source === focus) ids.add(edge.target)
      if (edge.target === focus) ids.add(edge.source)
    }
    return ids
  }, [hovered, focusId, visibleEdges])

  const emphasised = highlighted ?? neighbours

  const reset = useCallback(() => { setZoom(1); setPan({ x: 0, y: 0 }) }, [])

  const fitToView = useCallback(() => {
    const element = svgRef.current
    if (!element) return
    const box = element.getBoundingClientRect()
    if (!box.width || !layout.width) return
    setZoom(Math.max(0.35, Math.min(1.5, box.width / layout.width)))
    setPan({ x: 0, y: 0 })
  }, [layout.width])

  const onWheel = useCallback((event: React.WheelEvent) => {
    if (!event.ctrlKey && !event.metaKey) return
    event.preventDefault()
    setZoom((value) => Math.max(0.3, Math.min(2.5, value - event.deltaY * 0.0015)))
  }, [])

  useEffect(() => {
    const element = svgRef.current
    if (!element) return
    const onKey = (event: KeyboardEvent) => {
      if (document.activeElement !== element) return
      const step = 40
      if (event.key === 'ArrowLeft') setPan((p) => ({ ...p, x: p.x + step }))
      else if (event.key === 'ArrowRight') setPan((p) => ({ ...p, x: p.x - step }))
      else if (event.key === 'ArrowUp') setPan((p) => ({ ...p, y: p.y + step }))
      else if (event.key === 'ArrowDown') setPan((p) => ({ ...p, y: p.y - step }))
      else if (event.key === '+' || event.key === '=') setZoom((z) => Math.min(2.5, z + 0.15))
      else if (event.key === '-') setZoom((z) => Math.max(0.3, z - 0.15))
      else if (event.key === '0') reset()
      else return
      event.preventDefault()
    }
    element.addEventListener('keydown', onKey)
    return () => element.removeEventListener('keydown', onKey)
  }, [reset])

  const toggleKind = (kind: EcosystemNodeKind) => {
    const next = new Set(filters.kinds)
    if (next.has(kind)) next.delete(kind)
    else next.add(kind)
    onFiltersChange({ kinds: next })
  }

  if (!nodes.length) {
    return (
      <div className="flex min-h-[240px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-white/12 bg-white/[0.02] p-6 text-center">
        <Share2 className="h-7 w-7 text-white/25" />
        <p className="text-[13px] font-bold text-white/65">No Dependency Map</p>
        <p className="max-w-lg text-[11px] leading-relaxed text-white/35">
          QGuard Helix has not discovered sufficient ecosystem dependency evidence yet. The map is projected from your asset inventory, relationships, certificates and observed external hosts.
        </p>
        <a href="/dashboard/scanner" className="mt-1 rounded border border-cyan-400/40 bg-cyan-500/10 px-3.5 py-2 text-[10px] font-black uppercase tracking-wider text-cyan-200 no-underline">Run Discovery</a>
      </div>
    )
  }

  const kindsPresent = LAYER_ORDER.filter((kind) => nodes.some((node) => node.kind === kind))

  return (
    <div className="space-y-2">
      {/* Controls */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1 rounded-lg border border-white/10 bg-black/25 p-1">
          <IconButton label="Zoom out" onClick={() => setZoom((z) => Math.max(0.3, z - 0.15))}><Minus className="h-3 w-3" /></IconButton>
          <span className="min-w-[42px] text-center font-mono text-[9px] text-white/45">{Math.round(zoom * 100)}%</span>
          <IconButton label="Zoom in" onClick={() => setZoom((z) => Math.min(2.5, z + 0.15))}><Plus className="h-3 w-3" /></IconButton>
          <IconButton label="Fit to view" onClick={fitToView}><Crosshair className="h-3 w-3" /></IconButton>
        </div>

        <label className="relative min-w-[170px]">
          <span className="sr-only">Search nodes</span>
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-white/30" />
          <input
            value={filters.search}
            onChange={(event) => onFiltersChange({ search: event.target.value })}
            placeholder="Search nodes…"
            className="h-7 w-full rounded border border-white/10 bg-black/30 pl-7 pr-2 text-[10px] text-white/80 placeholder:text-white/25 focus:border-cyan-400/50 focus:outline-none"
          />
        </label>

        <select value={filters.criticality} onChange={(event) => onFiltersChange({ criticality: event.target.value as RiskLevel | 'all' })}
          aria-label="Criticality filter"
          className="h-7 rounded border border-white/10 bg-black/30 px-2 text-[10px] text-white/75 focus:border-cyan-400/50 focus:outline-none">
          <option value="all" className="bg-[#0b1120]">All criticality</option>
          {(['critical', 'high', 'medium', 'low', 'unknown'] as RiskLevel[]).map((value) => (
            <option key={value} value={value} className="bg-[#0b1120]">{value}</option>
          ))}
        </select>

        <select value={filters.readiness} onChange={(event) => onFiltersChange({ readiness: event.target.value as Readiness | 'all' })}
          aria-label="PQC readiness filter"
          className="h-7 rounded border border-white/10 bg-black/30 px-2 text-[10px] text-white/75 focus:border-cyan-400/50 focus:outline-none">
          <option value="all" className="bg-[#0b1120]">All PQC status</option>
          {(['ready', 'hybrid-ready', 'preparing', 'committed', 'not-ready', 'unknown'] as Readiness[]).map((value) => (
            <option key={value} value={value} className="bg-[#0b1120]">{value}</option>
          ))}
        </select>

        <label className="flex items-center gap-1.5 text-[9px] font-black uppercase tracking-wider text-white/45">
          Depth
          <input
            type="range" min={1} max={5} value={filters.maxDepth}
            onChange={(event) => onFiltersChange({ maxDepth: Number(event.target.value) })}
            aria-label="Dependency depth"
            className="h-1 w-20 accent-cyan-400"
          />
          <span className="font-mono text-white/60">{filters.maxDepth}</span>
        </label>

        <span className="ml-auto font-mono text-[9px] uppercase tracking-widest text-white/25">
          {layout.nodes.length} nodes · {visibleEdges.length} edges · ctrl+scroll to zoom
        </span>
      </div>

      {/* Kind filter chips (also the legend) */}
      <div className="flex flex-wrap items-center gap-1">
        <Filter className="h-3 w-3 text-white/30" />
        {kindsPresent.map((kind) => {
          const off = filters.kinds.size > 0 && !filters.kinds.has(kind)
          return (
            <button key={kind} type="button" onClick={() => toggleKind(kind)} aria-pressed={!off}
              className={cn(
                'rounded border px-2 py-1 text-[8.5px] font-black uppercase tracking-wider transition',
                off ? 'border-white/8 bg-transparent text-white/25 line-through' : 'border-cyan-400/25 bg-cyan-500/10 text-cyan-200',
              )}>
              {NODE_KIND_LABEL[kind]}
            </button>
          )
        })}
        {filters.kinds.size > 0 && (
          <button type="button" onClick={() => onFiltersChange({ kinds: new Set() })}
            className="rounded border border-white/10 px-2 py-1 text-[8.5px] font-black uppercase tracking-wider text-white/45">Show all</button>
        )}
      </div>

      {/* Canvas */}
      <div className="relative overflow-hidden rounded-lg border border-white/10 bg-[#060c17]">
        <svg
          ref={svgRef} tabIndex={0} role="application"
          aria-label={`Ecosystem dependency graph: ${layout.nodes.length} nodes across ${layout.activeLayers.length} layers. Arrow keys pan, plus and minus zoom, zero resets.`}
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          className="h-[440px] w-full cursor-grab touch-none outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/60 active:cursor-grabbing"
          onWheel={onWheel}
          onPointerDown={(event) => {
            if ((event.target as Element).closest('[data-node]')) return
            dragRef.current = { x: event.clientX, y: event.clientY, panX: pan.x, panY: pan.y }
            ;(event.currentTarget as Element).setPointerCapture(event.pointerId)
          }}
          onPointerMove={(event) => {
            const drag = dragRef.current
            if (!drag) return
            setPan({ x: drag.panX + (event.clientX - drag.x), y: drag.panY + (event.clientY - drag.y) })
          }}
          onPointerUp={(event) => { dragRef.current = null; (event.currentTarget as Element).releasePointerCapture?.(event.pointerId) }}
          onPointerLeave={() => { dragRef.current = null }}
        >
          <defs>
            <marker id="eco-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M0,0 L8,4 L0,8 z" fill="rgba(148,163,184,0.5)" />
            </marker>
          </defs>

          <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
            {layout.activeLayers.map((kind, index) => (
              <text key={kind} x={PADDING + index * COL_WIDTH} y={PADDING - 2}
                className="fill-cyan-300/55 font-mono" style={{ fontSize: 8.5, letterSpacing: '0.12em', textTransform: 'uppercase' }}>
                {NODE_KIND_LABEL[kind]}
              </text>
            ))}

            {visibleEdges.map((edge) => {
              const source = nodeById.get(edge.source)!
              const target = nodeById.get(edge.target)!
              const x1 = source.x + NODE_WIDTH
              const y1 = source.y + NODE_HEIGHT / 2
              const x2 = target.x
              const y2 = target.y + NODE_HEIGHT / 2
              const mid = (x1 + x2) / 2
              const dim = emphasised ? !(emphasised.has(edge.source) && emphasised.has(edge.target)) : false
              return (
                <path key={`${edge.source}->${edge.target}`}
                  d={`M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`}
                  fill="none"
                  stroke={TONE_HEX[RISK_TONE[edge.risk]]}
                  strokeOpacity={dim ? 0.07 : edge.explicit ? 0.45 : 0.22}
                  strokeDasharray={edge.explicit ? undefined : '3 3'}
                  strokeWidth={1.4}
                  markerEnd="url(#eco-arrow)"
                />
              )
            })}

            {layout.nodes.map((node) => {
              const dim = emphasised ? !emphasised.has(node.id) : false
              const selected = focusId === node.id
              const color = TONE_HEX[READINESS_TONE[node.readiness]]
              return (
                <g key={node.id} data-node transform={`translate(${node.x} ${node.y})`} opacity={dim ? 0.22 : 1}
                  className="cursor-pointer" role="button" tabIndex={0}
                  aria-label={`${node.label}, ${NODE_KIND_LABEL[node.kind]}, readiness ${node.readiness}, criticality ${node.criticality}`}
                  onMouseEnter={() => setHovered(node.id)} onMouseLeave={() => setHovered(null)}
                  onClick={() => onSelect(selected ? null : node)}
                  onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(selected ? null : node) } }}
                >
                  <rect width={NODE_WIDTH} height={NODE_HEIGHT} rx={5}
                    fill={selected ? 'rgba(34,211,238,0.16)' : 'rgba(255,255,255,0.035)'}
                    stroke={selected ? '#22d3ee' : color}
                    strokeOpacity={selected ? 1 : 0.5} strokeWidth={selected ? 1.8 : 1} />
                  <rect width={3} height={NODE_HEIGHT} rx={2} fill={color} />
                  <text x={11} y={12} className="fill-white" style={{ fontSize: 9.5, fontWeight: 700 }}>
                    {node.label.length > 21 ? `${node.label.slice(0, 20)}…` : node.label}
                  </text>
                  <text x={11} y={23} style={{ fontSize: 7.5, fill: color, fontWeight: 700 }}>
                    {READINESS_GLYPH[node.readiness]} {node.readiness} {node.external ? '· ext' : ''}
                  </text>
                  <text x={NODE_WIDTH - 7} y={23} textAnchor="end" style={{ fontSize: 7.5, fill: TONE_HEX[RISK_TONE[node.criticality]] }}>
                    {RISK_GLYPH[node.criticality]}
                  </text>
                </g>
              )
            })}
          </g>
        </svg>

        <div className="pointer-events-none absolute bottom-2 left-3 flex flex-wrap items-center gap-3">
          {(['ready', 'preparing', 'not-ready', 'unknown'] as Readiness[]).map((readiness) => (
            <span key={readiness} className="inline-flex items-center gap-1 text-[8px] font-bold uppercase tracking-wider text-white/40">
              <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: TONE_HEX[READINESS_TONE[readiness]] }} />
              {READINESS_GLYPH[readiness]} {readiness}
            </span>
          ))}
          <span className="inline-flex items-center gap-1 text-[8px] font-bold uppercase tracking-wider text-white/30">
            <span className="inline-block h-px w-4 border-t border-dashed border-white/40" /> inferred edge
          </span>
        </div>
      </div>
    </div>
  )
}

function IconButton({ children, onClick, label }: { children: React.ReactNode; onClick: () => void; label: string }) {
  return (
    <button type="button" onClick={onClick} aria-label={label} title={label}
      className="grid h-6 w-6 place-items-center rounded text-white/50 transition hover:bg-white/10 hover:text-cyan-300">
      {children}
    </button>
  )
}
