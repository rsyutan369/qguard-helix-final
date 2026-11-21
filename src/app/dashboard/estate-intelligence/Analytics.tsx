'use client'
import { useMemo, useRef, useState } from 'react'
import { UserX } from 'lucide-react'
import type { EstateOverview } from '@/lib/estate'

function Card({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
      <h3 className="text-[15px] font-semibold text-slate-100">{title}</h3>
      {subtitle && <p className="mt-0.5 text-[12px] text-slate-400">{subtitle}</p>}
      <div className="mt-3">{children}</div>
    </section>
  )
}

/* ------------------------------------------------------------------ */
/* Heatmap — one sequential hue, value printed in every cell           */
/* ------------------------------------------------------------------ */

function Heatmap({ heatmap }: { heatmap: EstateOverview['heatmap'] }) {
  if (!heatmap.rows.length) return <p className="text-[12px] text-slate-500">No open quantum-vulnerable algorithms.</p>
  return (
    <div className="overflow-x-auto">
      <table className="qe-heat min-w-[520px]">
        <thead><tr><th scope="col">Algorithm</th>{heatmap.columns.map((c) => <th key={c.key} scope="col" className="text-center">{c.label}</th>)}</tr></thead>
        <tbody>
          {heatmap.rows.map((row, r) => (
            <tr key={row}>
              <th scope="row">{row}</th>
              {heatmap.cells[r].map((value, c) => {
                const t = heatmap.max ? value / heatmap.max : 0
                return (
                  <td key={heatmap.columns[c].key} data-strong={t > 0.55} title={`${row} in ${heatmap.columns[c].label}: ${value} asset(s) with it open`}
                    style={{ background: value ? `rgba(var(--qe-seq), ${0.1 + t * 0.85})` : 'transparent', border: value ? undefined : '1px dashed var(--qe-line)' }}>
                    {value ? value.toLocaleString() : '–'}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
      {heatmap.omittedRows > 0 && <p className="mt-2 text-[11px] text-slate-500">{heatmap.omittedRows} less common algorithm(s) not shown.</p>}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Sankey — current algorithm → replacement → status                   */
/* ------------------------------------------------------------------ */

const STATUS_STROKE: Record<string, string> = {
  Validated: 'var(--qe-valid)', 'In flight': 'var(--qe-open)', 'Awaiting evidence': 'var(--qe-open)', 'Not started': '#94a3b8', Exceptions: '#dc2626',
}

function Sankey({ sankey }: { sankey: EstateOverview['sankey'] }) {
  const width = 900
  const height = Math.max(320, Math.min(560, 40 + sankey.nodes.length * 26))
  const [active, setActive] = useState<number | null>(null)
  const layout = useMemo(() => {
    const value = sankey.nodes.map((node, i) => {
      const outgoing = sankey.links.filter((l) => l.source === i).reduce((s, l) => s + l.value, 0)
      const incoming = sankey.links.filter((l) => l.target === i).reduce((s, l) => s + l.value, 0)
      return node.column === 0 ? outgoing : incoming
    })
    const gap = 10
    const columnTotals = [0, 1, 2].map((col) => sankey.nodes.reduce((s, n, i) => (n.column === col ? s + value[i] : s), 0))
    const counts = [0, 1, 2].map((col) => sankey.nodes.filter((n) => n.column === col).length)
    const scale = Math.min(...[0, 1, 2].map((col) => (height - 20 - gap * Math.max(0, counts[col] - 1)) / Math.max(1, columnTotals[col])))
    const x = [150, width / 2 - 8, width - 166]
    const y: number[] = []
    for (const col of [0, 1, 2]) {
      let cursor = 10
      sankey.nodes.map((n, i) => ({ n, i })).filter(({ n }) => n.column === col).sort((a, b) => value[b.i] - value[a.i]).forEach(({ i }) => { y[i] = cursor; cursor += value[i] * scale + gap })
    }
    // Stack flows per node so they never cross needlessly: a node's outgoing
    // flows in the order of their targets, its incoming flows in the order of their sources.
    const sourceTop = new Map<typeof sankey.links[number], number>()
    const targetTop = new Map<typeof sankey.links[number], number>()
    sankey.nodes.forEach((_, i) => {
      let out = 0
      sankey.links.filter((l) => l.source === i).sort((a, b) => y[a.target] - y[b.target]).forEach((l) => { sourceTop.set(l, out); out += l.value * scale })
      let inn = 0
      sankey.links.filter((l) => l.target === i).sort((a, b) => y[a.source] - y[b.source]).forEach((l) => { targetTop.set(l, inn); inn += l.value * scale })
    })
    const links = sankey.links.map((link) => {
      const thickness = Math.max(1, link.value * scale)
      const sy = y[link.source] + sourceTop.get(link)! + thickness / 2
      const ty = y[link.target] + targetTop.get(link)! + thickness / 2
      const sx = x[sankey.nodes[link.source].column] + 14
      const tx = x[sankey.nodes[link.target].column]
      const mid = (sx + tx) / 2
      return { ...link, thickness, d: `M${sx},${sy} C${mid},${sy} ${mid},${ty} ${tx},${ty}` }
    })
    return { value, x, y, scale, links }
  }, [sankey, height])

  if (!sankey.links.length) return <p className="text-[12px] text-slate-500">No fixes to trace yet.</p>
  return (
    <div className="overflow-x-auto">
      <svg className="qe-chart min-w-[720px]" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`Flow of ${sankey.total} asset-fix items from current algorithm to replacement to status`}>
        {layout.links.map((link, i) => {
          const target = sankey.nodes[link.target]
          const stroke = target.column === 2 ? STATUS_STROKE[target.name] ?? 'var(--qe-open)' : 'var(--qe-open)'
          return (
            <path key={i} className="qe-flow" d={link.d} stroke={stroke} strokeWidth={link.thickness}
              data-active={active !== null && (link.source === active || link.target === active)}>
              <title>{`${sankey.nodes[link.source].name} → ${target.name}: ${link.value.toLocaleString()}`}</title>
            </path>
          )
        })}
        {sankey.nodes.map((node, i) => {
          const h = Math.max(2, layout.value[i] * layout.scale)
          const fill = node.column === 2 ? STATUS_STROKE[node.name] ?? 'var(--qe-open)' : 'var(--qe-ink-3)'
          const labelX = node.column === 0 ? layout.x[0] - 8 : node.column === 2 ? layout.x[2] + 22 : layout.x[1] + 22
          return (
            <g key={i} onMouseEnter={() => setActive(i)} onMouseLeave={() => setActive(null)}>
              <rect x={layout.x[node.column]} y={layout.y[i]} width={14} height={h} rx={3} fill={fill} />
              <text x={labelX} y={layout.y[i] + h / 2} dy="0.35em" textAnchor={node.column === 0 ? 'end' : 'start'} className="qe-strong">{node.name}</text>
              <text x={labelX} y={layout.y[i] + h / 2 + 14} dy="0.35em" textAnchor={node.column === 0 ? 'end' : 'start'}>{layout.value[i].toLocaleString()}</text>
            </g>
          )
        })}
        <text x={layout.x[0]} y={height - 2} textAnchor="middle">Current</text>
        <text x={layout.x[1] + 7} y={height - 2} textAnchor="middle">Replacement</text>
        <text x={layout.x[2] + 7} y={height - 2} textAnchor="middle">Status</text>
      </svg>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Burndown — two validated series, direct labels, crosshair tooltip   */
/* ------------------------------------------------------------------ */

function Burndown({ burndown }: { burndown: EstateOverview['burndown'] }) {
  const points = burndown.points
  const ref = useRef<SVGSVGElement>(null)
  const [hover, setHover] = useState<number | null>(null)
  const width = 900
  const height = 280
  const pad = { l: 52, r: 120, t: 14, b: 30 }
  if (points.length < 2) return <p className="text-[12px] text-slate-500">Not enough scan history yet — the burndown appears once findings span more than one month.</p>
  const max = Math.max(1, ...points.map((p) => Math.max(p.open, p.validated)))
  const xs = (i: number) => pad.l + (i / (points.length - 1)) * (width - pad.l - pad.r)
  const ys = (v: number) => pad.t + (1 - v / max) * (height - pad.t - pad.b)
  const line = (key: 'open' | 'validated') => points.map((p, i) => `${i ? 'L' : 'M'}${xs(i).toFixed(1)},${ys(p[key]).toFixed(1)}`).join(' ')
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((t) => Math.round(max * t))
  const last = points[points.length - 1]
  const onMove = (event: React.MouseEvent<SVGSVGElement>) => {
    const box = ref.current!.getBoundingClientRect()
    const x = ((event.clientX - box.left) / box.width) * width
    const i = Math.round(((x - pad.l) / (width - pad.l - pad.r)) * (points.length - 1))
    setHover(Math.max(0, Math.min(points.length - 1, i)))
  }
  const h = hover !== null ? points[hover] : null
  return (
    <div className="relative overflow-x-auto">
      <svg ref={ref} className="qe-chart min-w-[640px]" viewBox={`0 0 ${width} ${height}`} role="img" onMouseMove={onMove} onMouseLeave={() => setHover(null)}
        aria-label={`Open work items over time, now ${last.open}; validated ${last.validated}`}>
        {ticks.map((t) => (
          <g key={t}><line className="qe-grid" x1={pad.l} x2={width - pad.r} y1={ys(t)} y2={ys(t)} /><text x={pad.l - 8} y={ys(t)} dy="0.35em" textAnchor="end">{t.toLocaleString()}</text></g>
        ))}
        <line className="qe-axis" x1={pad.l} x2={width - pad.r} y1={height - pad.b} y2={height - pad.b} />
        {points.map((p, i) => (i % Math.ceil(points.length / 8) === 0 || i === points.length - 1)
          ? <text key={p.month} x={xs(i)} y={height - 10} textAnchor="middle">{p.month}</text> : null)}
        <path d={line('open')} fill="none" stroke="var(--qe-open)" strokeWidth={2} strokeLinejoin="round" />
        <path d={line('validated')} fill="none" stroke="var(--qe-valid)" strokeWidth={2} strokeLinejoin="round" />
        <circle cx={xs(points.length - 1)} cy={ys(last.open)} r={4} fill="var(--qe-open)" />
        <circle cx={xs(points.length - 1)} cy={ys(last.validated)} r={4} fill="var(--qe-valid)" />
        <text x={xs(points.length - 1) + 10} y={ys(last.open)} dy="0.35em" className="qe-strong">Open {last.open.toLocaleString()}</text>
        <text x={xs(points.length - 1) + 10} y={ys(last.validated) + (Math.abs(ys(last.validated) - ys(last.open)) < 16 ? 16 : 0)} dy="0.35em" className="qe-strong">Validated {last.validated.toLocaleString()}</text>
        {h && hover !== null && <line className="qe-axis" x1={xs(hover)} x2={xs(hover)} y1={pad.t} y2={height - pad.b} />}
        {/* Hit area larger than the marks */}
        <rect x={pad.l} y={pad.t} width={width - pad.l - pad.r} height={height - pad.t - pad.b} fill="transparent" />
      </svg>
      {h && hover !== null && (
        <div className="qe-tooltip" style={{ left: `${(xs(hover) / width) * 100}%`, top: 8, transform: 'translateX(12px)' }}>
          <strong className="block">{h.month}</strong>
          <span><i className="qe-dot" style={{ background: 'var(--qe-open)' }} />Open {h.open.toLocaleString()}</span><br />
          <span><i className="qe-dot" style={{ background: 'var(--qe-valid)' }} />Validated {h.validated.toLocaleString()}</span><br />
          <span className="opacity-70">Discovered to date {h.discovered.toLocaleString()}</span>
        </div>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Analytics tab                                                       */
/* ------------------------------------------------------------------ */

export function Analytics({ overview }: { overview: EstateOverview }) {
  const b = overview.burndown
  const o = overview.ownership
  return (
    <div className="grid gap-4 p-4 xl:grid-cols-2">
      <div className="xl:col-span-2">
        <Card title="Burndown toward the end-of-2030 planning target" subtitle={b.basis}>
          <dl className="mb-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              ['Open now', b.openNow.toLocaleString()],
              ['Validated, last 90 days', b.validatedLast90Days.toLocaleString()],
              ['Needed per month to finish by end of 2030', b.requiredPerMonth.toLocaleString()],
              ['Finish date at the current pace', b.projectedCompletion ?? (b.openNow ? 'No validations in 90 days' : 'Done')],
            ].map(([label, value]) => (
              <div key={label} className="rounded-lg border border-white/10 p-3">
                <dt className="text-[11px] text-slate-400">{label}</dt>
                <dd className="mt-1 text-[18px] font-semibold tabular-nums text-slate-100">{value}</dd>
              </div>
            ))}
          </dl>
          <Burndown burndown={b} />
        </Card>
      </div>
      <Card title="Where each algorithm is still open" subtitle="Distinct assets with an open fix, by primary algorithm and environment.">
        <Heatmap heatmap={overview.heatmap} />
      </Card>
      <Card title="Ownership" subtitle={`${o.ownedShare}% of assets have an owner on record. Unowned assets have no one to route a fix to.`}>
        <div className="max-h-[360px] overflow-auto">
          <table className="w-full text-left text-[12px]">
            <thead className="sticky top-0 bg-[var(--qg-card-bg,#0f172a)] text-[11px] text-slate-500">
              <tr><th className="py-1.5 pr-3">Owner</th><th className="py-1.5 pr-3">Assets</th><th className="py-1.5 pr-3">Affected</th><th className="py-1.5 pr-3">Open fixes</th><th className="py-1.5">Source</th></tr>
            </thead>
            <tbody>
              {o.unowned.assets > 0 && (
                <tr className="border-t border-white/5 tabular-nums text-amber-300">
                  <td className="py-1.5 pr-3 font-semibold"><UserX className="mr-1 inline h-3 w-3" />Unowned</td><td className="pr-3">{o.unowned.assets}</td><td className="pr-3">{o.unowned.affectedAssets}</td><td className="pr-3">{o.unowned.openFixes}</td><td className="text-[11px]">Assign in the asset record or with an owner tag</td>
                </tr>
              )}
              {o.rows.slice(0, 100).map((row) => (
                <tr key={row.owner} className="border-t border-white/5 tabular-nums text-slate-300">
                  <td className="py-1.5 pr-3 font-semibold text-slate-200">{row.owner}</td><td className="pr-3">{row.assets}</td><td className="pr-3">{row.affectedAssets}</td><td className="pr-3">{row.openFixes}</td><td className="text-[11px] text-slate-500">{row.sources.join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <div className="xl:col-span-2">
        <Card title="From vulnerable algorithm to validated replacement" subtitle="Each unit is one asset × one fix. Hover a column to follow its flows.">
          <Sankey sankey={overview.sankey} />
        </Card>
      </div>
    </div>
  )
}
