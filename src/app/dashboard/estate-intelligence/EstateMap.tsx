'use client'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Building2, Network, Search, Share2 } from 'lucide-react'
import {
  DetailFacts, DetailLink, DetailSection, RelationshipList, VendorTrustWorkflowCanvas, type DetailContext,
} from '@/components/trust-workflow/VendorTrustWorkflowCanvas'
import type { WorkflowNode } from '@/components/trust-workflow/graph-model'
import type { EstateOverview, MapDimension, MapGroup } from '@/lib/estate'
import { useEstateGraph, useEstateSearch, type AssetHit } from '@/hooks/use-estate-intelligence'

export type MapLevel = 'estate' | 'root-cause' | 'neighbourhood'

/* ------------------------------------------------------------------ */
/* Level 0 — squarified treemap                                        */
/* ------------------------------------------------------------------ */

interface Rect { x: number; y: number; w: number; h: number }

/** Squarified treemap (Bruls et al.) over normalised areas. */
function squarify(values: number[], rect: Rect): Rect[] {
  const total = values.reduce((a, b) => a + b, 0) || 1
  const scaled = values.map((v) => (v / total) * rect.w * rect.h)
  const out: Rect[] = new Array(values.length)
  let index = 0
  let area = { ...rect }
  const worst = (row: number[], side: number) => {
    const sum = row.reduce((a, b) => a + b, 0)
    const max = Math.max(...row)
    const min = Math.min(...row)
    return Math.max((side * side * max) / (sum * sum), (sum * sum) / (side * side * min))
  }
  while (index < scaled.length) {
    const side = Math.min(area.w, area.h)
    const row: number[] = [scaled[index]]
    let next = index + 1
    while (next < scaled.length && worst([...row, scaled[next]], side) <= worst(row, side)) { row.push(scaled[next]); next += 1 }
    const sum = row.reduce((a, b) => a + b, 0)
    if (area.w >= area.h) {
      const width = sum / area.h
      let y = area.y
      row.forEach((value, i) => { const h = value / width; out[index + i] = { x: area.x, y, w: width, h }; y += h })
      area = { x: area.x + width, y: area.y, w: area.w - width, h: area.h }
    } else {
      const height = sum / area.w
      let x = area.x
      row.forEach((value, i) => { const w = value / height; out[index + i] = { x, y: area.y, w, h: height }; x += w })
      area = { x: area.x, y: area.y + height, w: area.w, h: area.h - height }
    }
    index = next
  }
  return out
}

const SEVERITY_FILL: Record<string, string> = { critical: '220, 38, 38', high: '234, 88, 12', medium: '217, 119, 6', low: '100, 116, 139', info: '22, 163, 74' }

function Treemap({ groups, dimension }: { groups: MapGroup[]; dimension: MapDimension }) {
  const ref = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(900)
  const [hover, setHover] = useState<{ group: MapGroup; x: number; y: number } | null>(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const observer = new ResizeObserver(([entry]) => setWidth(Math.max(280, entry.contentRect.width)))
    observer.observe(el)
    return () => observer.disconnect()
  }, [])
  const height = width < 640 ? 420 : 460
  const shown = groups.slice(0, 40)
  const rest = groups.slice(40)
  const tiles = useMemo(() => {
    const list = rest.length ? [...shown, { key: '__rest', label: `${rest.length} smaller groups`, assets: rest.reduce((s, g) => s + g.assets, 0), affectedAssets: rest.reduce((s, g) => s + g.affectedAssets, 0), openFixes: rest.reduce((s, g) => s + g.openFixes, 0), criticalAssets: rest.reduce((s, g) => s + g.criticalAssets, 0), readiness: 0, worst: 'low' as const }] : shown
    const sorted = [...list].sort((a, b) => b.assets - a.assets)
    const rects = squarify(sorted.map((g) => Math.max(g.assets, 1)), { x: 0, y: 0, w: width, h: height })
    return sorted.map((group, i) => ({ group, rect: rects[i] }))
  }, [shown, rest, width, height])

  return (
    <div>
      <div ref={ref} className="qe-treemap" style={{ height }} onMouseLeave={() => setHover(null)}>
        {tiles.map(({ group, rect }) => {
          const share = group.assets ? group.affectedAssets / group.assets : 0
          const alpha = group.affectedAssets ? 0.14 + share * 0.5 : 0.08
          const fill = group.affectedAssets ? SEVERITY_FILL[group.worst] ?? SEVERITY_FILL.low : SEVERITY_FILL.info
          return (
            <button
              key={group.key}
              type="button"
              className="qe-tile"
              style={{ left: rect.x, top: rect.y, width: rect.w, height: rect.h, background: `rgba(${fill}, ${alpha})` }}
              aria-label={`${group.label}: ${group.assets} assets, ${group.affectedAssets} with open fixes, ${group.readiness}% clear`}
              onMouseMove={(e) => { const box = ref.current!.getBoundingClientRect(); setHover({ group, x: e.clientX - box.left, y: e.clientY - box.top }) }}
              onFocus={() => setHover({ group, x: rect.x + 12, y: rect.y + 12 })}
              onBlur={() => setHover(null)}
            >
              {rect.w > 70 && rect.h > 34 && <strong>{group.label}</strong>}
              {rect.w > 90 && rect.h > 52 && <span>{group.affectedAssets.toLocaleString()} of {group.assets.toLocaleString()} affected</span>}
              {rect.w > 90 && rect.h > 70 && <span>{group.readiness}% clear · {group.openFixes.toLocaleString()} open fixes</span>}
            </button>
          )
        })}
        {hover && (
          <div className="qe-tooltip" style={{ left: Math.min(hover.x + 14, width - 220), top: Math.min(hover.y + 14, height - 110) }}>
            <strong className="block">{hover.group.label}</strong>
            {hover.group.assets.toLocaleString()} assets · {hover.group.affectedAssets.toLocaleString()} with open fixes<br />
            {hover.group.criticalAssets.toLocaleString()} with a critical finding · {hover.group.readiness}% clear<br />
            {hover.group.openFixes.toLocaleString()} open asset × fix items
          </div>
        )}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-400">
        <span>Tile size = assets. Colour = worst open finding; stronger = larger share affected.</span>
        {(['critical', 'high', 'medium', 'info'] as const).map((key) => (
          <span key={key}><i className="qe-dot" style={{ background: `rgb(${SEVERITY_FILL[key]})` }} aria-hidden="true" />{key === 'info' ? 'No open fixes' : key[0].toUpperCase() + key.slice(1)}</span>
        ))}
      </div>
      <details className="mt-3">
        <summary className="cursor-pointer text-[12px] font-semibold text-slate-300">Table view ({groups.length} {dimension} groups)</summary>
        <div className="mt-2 max-h-80 overflow-auto">
          <table className="w-full text-left text-[12px]">
            <thead className="text-[11px] text-slate-500"><tr><th className="py-1.5 pr-3">Group</th><th className="py-1.5 pr-3">Assets</th><th className="py-1.5 pr-3">Affected</th><th className="py-1.5 pr-3">Critical</th><th className="py-1.5 pr-3">Open fixes</th><th className="py-1.5">Clear</th></tr></thead>
            <tbody>{groups.map((g) => (
              <tr key={g.key} className="border-t border-white/5 tabular-nums text-slate-300"><td className="py-1.5 pr-3 text-slate-200">{g.label}</td><td className="pr-3">{g.assets}</td><td className="pr-3">{g.affectedAssets}</td><td className="pr-3">{g.criticalAssets}</td><td className="pr-3">{g.openFixes}</td><td>{g.readiness}%</td></tr>
            ))}</tbody>
          </table>
        </div>
      </details>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Map shell                                                           */
/* ------------------------------------------------------------------ */

const DIMENSIONS: Array<[MapDimension, string]> = [['owner', 'Owner'], ['service', 'Business service'], ['environment', 'Environment'], ['type', 'Asset type']]

export function EstateMap({ overview, level, setLevel, focus, setFocus, onPlanCampaign }: {
  overview: EstateOverview
  level: MapLevel
  setLevel: (level: MapLevel) => void
  focus: string | null
  setFocus: (focus: string | null) => void
  onPlanCampaign: (fixId: string) => void
}) {
  const [dimension, setDimension] = useState<MapDimension>('owner')
  const graphLevel = level === 'estate' ? null : level
  const { data, state, error, refresh } = useEstateGraph(graphLevel ?? 'root-cause', level === 'neighbourhood' ? focus : null)
  const search = useEstateSearch()
  const [term, setTerm] = useState('')
  const [hits, setHits] = useState<AssetHit[]>([])

  useEffect(() => {
    const handle = window.setTimeout(() => { void search(term).then(setHits).catch(() => setHits([])) }, 250)
    return () => window.clearTimeout(handle)
  }, [term, search])

  const focusLabel = useMemo(() => {
    if (!focus) return null
    if (focus.startsWith('fix:')) return overview.clusters.find((c) => c.id === focus.slice(4))?.title ?? 'Selected fix'
    return data?.graph.nodes.find((n) => n.id === focus)?.label ?? 'Selected asset'
  }, [focus, overview.clusters, data])

  const drill = (node: WorkflowNode) => {
    if (node.id.startsWith('fix:')) { setFocus(node.id); setLevel('neighbourhood') }
    else if (node.entity?.type === 'asset') { setFocus(`asset:${node.entity.id}`); setLevel('neighbourhood') }
  }

  const renderNodeDetail = (node: WorkflowNode, context: DetailContext) => {
    const fixId = node.id.startsWith('fix:') ? node.id.slice(4) : null
    const fix = fixId ? overview.clusters.find((c) => c.id === fixId) : null
    return (
      <div className="space-y-3">
        <DetailSection title={node.kindLabel}>
          <p className="text-[13px] font-semibold">{node.label}</p>
          {node.sublabel && <p className="text-[12px] opacity-75">{node.sublabel}</p>}
        </DetailSection>
        {fix && (
          <DetailFacts items={[
            ['Open assets', `${fix.assets - fix.progress.validated} of ${fix.assets}`],
            ['Priority', `#${fix.priorityRank} (${fix.priority}/100)`],
            ['Deadline', fix.deadline.label],
            ['Effort', `≈${fix.effort.days} engineer-days (estimate)`],
            ['Replacement', fix.target ?? fix.targetNote ?? '—', true],
          ]} />
        )}
        {node.meta && node.meta.length > 0 && <p className="font-mono text-[11px] opacity-70">{node.meta.join(' · ')}</p>}
        <div className="flex flex-wrap gap-2">
          {(fixId || node.entity?.type === 'asset') && focus !== node.id && focus !== `asset:${node.entity?.id}` && (
            <DetailLink primary onClick={() => drill(node)}>Show its neighbourhood</DetailLink>
          )}
          {fixId && <DetailLink onClick={() => onPlanCampaign(fixId)}>Plan campaign</DetailLink>}
          {node.entity?.type === 'asset' && <DetailLink href={`/dashboard/assets?asset=${encodeURIComponent(node.entity.id)}`}>Open asset record</DetailLink>}
        </div>
        <RelationshipList context={context} />
      </div>
    )
  }

  return (
    <div className="space-y-4 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="qe-seg" role="group" aria-label="Map level">
          <button type="button" aria-pressed={level === 'estate'} onClick={() => setLevel('estate')}><Building2 className="mr-1.5 inline h-3.5 w-3.5" />Company map</button>
          <button type="button" aria-pressed={level === 'root-cause'} onClick={() => setLevel('root-cause')}><Share2 className="mr-1.5 inline h-3.5 w-3.5" />Root causes</button>
          <button type="button" aria-pressed={level === 'neighbourhood'} onClick={() => setLevel('neighbourhood')} disabled={!focus} title={focus ? undefined : 'Pick a fix or an asset first'} className="disabled:opacity-40"><Network className="mr-1.5 inline h-3.5 w-3.5" />Neighbourhood</button>
        </div>
        {level === 'estate' && (
          <div className="qe-seg" role="group" aria-label="Group assets by">
            {DIMENSIONS.map(([key, label]) => <button key={key} type="button" aria-pressed={dimension === key} onClick={() => setDimension(key)}>{label}</button>)}
          </div>
        )}
        <div className="relative ml-auto">
          <label className="relative block">
            <span className="sr-only">Jump to an asset</span>
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
            <input value={term} onChange={(e) => setTerm(e.target.value)} placeholder="Jump to an asset…" className="w-64 rounded-lg border border-white/12 bg-transparent py-2 pl-8 pr-3 text-[12px] text-slate-200 placeholder:text-slate-500" />
          </label>
          {hits.length > 0 && term.trim().length >= 2 && (
            <ul className="absolute right-0 z-20 mt-1 max-h-72 w-80 overflow-auto rounded-lg border border-white/12 bg-[var(--qg-card-bg,#0f172a)] p-1 shadow-xl" role="listbox">
              {hits.map((hit) => (
                <li key={hit.id}>
                  <button type="button" className="w-full rounded-md px-2.5 py-2 text-left text-[12px] hover:bg-white/5" onClick={() => { setFocus(`asset:${hit.id}`); setLevel('neighbourhood'); setTerm(''); setHits([]) }}>
                    <span className="block font-semibold text-slate-200">{hit.name}</span>
                    <span className="text-[11px] text-slate-500">{hit.owner ?? 'Unowned'} · {hit.environment || 'Unspecified'} · {hit.openFixes} open fix(es)</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {level === 'neighbourhood' && focusLabel && (
        <p className="text-[12px] text-slate-400">Neighbourhood of <span className="font-semibold text-slate-200">{focusLabel}</span>. Select a node, then “Show its neighbourhood” to walk the estate.</p>
      )}

      {level === 'estate' ? (
        <Treemap groups={overview.maps[dimension]} dimension={dimension} />
      ) : (
        <VendorTrustWorkflowCanvas
          graph={data?.graph ?? { nodes: [], edges: [], groups: [], notices: [], legend: {} }}
          ariaLabel={level === 'root-cause' ? 'Root causes, fixes and owners' : 'Neighbourhood map'}
          status={state === 'error' && !data ? 'error' : !data ? 'loading' : 'ready'}
          error={error}
          onRetry={() => void refresh()}
          empty={{ title: 'Nothing to map yet', detail: 'Run a scan or connect an agent so certificates, keys and algorithms are recorded for your assets.', cta: { label: 'Open the PQC Scanner', href: '/dashboard/scanner' } }}
          renderNodeDetail={renderNodeDetail}
          enableTrace
          autoCollapseAbove={14}
          height={640}
          exportName={level === 'root-cause' ? 'estate-root-causes' : 'estate-neighbourhood'}
        />
      )}
    </div>
  )
}
