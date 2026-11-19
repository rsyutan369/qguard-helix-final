'use client'
import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Globe2, Map as MapIcon, Rocket, Search, UserX } from 'lucide-react'
import type { FixCluster, MemberStatus } from '@/lib/estate'
import { useEstateFix } from '@/hooks/use-estate-intelligence'
import { cn } from '@/lib/utils'

export const STATUS_ORDER: MemberStatus[] = ['validated', 'awaiting-validation', 'running', 'planned', 'open', 'failed', 'regressed']
export const STATUS_TEXT: Record<MemberStatus, string> = {
  open: 'Not started', planned: 'Queued / planned', running: 'Executing', failed: 'Failed / rolled back',
  'awaiting-validation': 'Awaiting rescan', validated: 'Validated', regressed: 'Still vulnerable after rescan',
}
const SEVERITY_TEXT: Record<string, string> = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-amber-300', low: 'text-slate-400', info: 'text-slate-400' }

export function ProgressBar({ progress, total, className }: { progress: Record<MemberStatus, number>; total: number; className?: string }) {
  const label = STATUS_ORDER.filter((s) => progress[s]).map((s) => `${progress[s]} ${STATUS_TEXT[s].toLowerCase()}`).join(', ')
  return (
    <div className={cn('qe-progress', className)} role="img" aria-label={`Progress: ${label || 'nothing recorded'}`} title={label}>
      {STATUS_ORDER.map((status) => (progress[status] ? (
        <i key={status} className={`qe-s-${status}`} style={{ width: `${(progress[status] / Math.max(total, 1)) * 100}%` }} />
      ) : null))}
    </div>
  )
}

export function StatusLegend() {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-400">
      {(['validated', 'running', 'open', 'failed'] as MemberStatus[]).map((status) => (
        <span key={status}><i className={`qe-dot qe-s-${status}`} aria-hidden="true" />
          {status === 'running' ? 'In flight (queued, executing, awaiting rescan)' : status === 'failed' ? 'Exceptions (failed or still vulnerable)' : STATUS_TEXT[status]}
        </span>
      ))}
    </div>
  )
}

function FixMembers({ cluster, onOpenMap, onOpenCampaign }: { cluster: FixCluster; onOpenMap: () => void; onOpenCampaign: () => void }) {
  const [status, setStatus] = useState('all')
  const [q, setQ] = useState('')
  const [offset, setOffset] = useState(0)
  const limit = 25
  const { data, state, error } = useEstateFix(cluster.id, { offset, limit, status, q })

  return (
    <div className="space-y-4 border-b border-white/10 bg-white/[0.02] px-4 py-4 lg:px-6">
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-1.5 lg:col-span-2">
          <p className="text-[13px] leading-relaxed text-slate-200">{cluster.action}</p>
          <p className="text-[12px] text-slate-400">
            <span className="font-semibold text-slate-300">Replacement: </span>
            {cluster.target ?? cluster.targetNote}
          </p>
          <p className="text-[12px] text-slate-400"><span className="font-semibold text-slate-300">Why this rank: </span>{cluster.priorityFactors.join(' · ')}</p>
          <p className="text-[11px] text-slate-500">{cluster.deadline.basis} {cluster.effort.basis}</p>
        </div>
        <div className="flex flex-wrap content-start gap-2 lg:justify-end">
          <button type="button" onClick={onOpenMap} className="inline-flex items-center gap-1.5 rounded-lg border border-white/15 px-3 py-2 text-[12px] font-semibold text-slate-200 hover:bg-white/5">
            <MapIcon className="h-3.5 w-3.5" /> Show in map
          </button>
          <button type="button" onClick={onOpenCampaign} className="inline-flex items-center gap-1.5 rounded-lg border border-blue-400/40 bg-blue-500/15 px-3 py-2 text-[12px] font-semibold text-blue-200 hover:bg-blue-500/25">
            <Rocket className="h-3.5 w-3.5" /> Plan campaign
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <label className="relative">
          <span className="sr-only">Search affected assets</span>
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
          <input value={q} onChange={(e) => { setQ(e.target.value); setOffset(0) }} placeholder="Search assets, owners, services"
            className="w-64 rounded-lg border border-white/12 bg-transparent py-2 pl-8 pr-3 text-[12px] text-slate-200 placeholder:text-slate-500" />
        </label>
        <label className="text-[12px] text-slate-400">
          <span className="sr-only">Filter by status</span>
          <select value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0) }} className="rounded-lg border border-white/12 bg-transparent px-2.5 py-2 text-[12px] text-slate-200">
            <option value="all">All statuses</option>
            {STATUS_ORDER.map((s) => <option key={s} value={s}>{STATUS_TEXT[s]} ({cluster.progress[s]})</option>)}
          </select>
        </label>
        <span className="ml-auto text-[11px] text-slate-500">{data ? `${data.total} matching asset(s)` : ''}</span>
      </div>

      {state === 'error' && <p role="alert" className="text-[12px] text-red-400">{error}</p>}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] text-left text-[12px]">
          <thead className="text-[11px] text-slate-500">
            <tr>
              <th className="py-2 pr-3 font-semibold">Asset</th>
              <th className="py-2 pr-3 font-semibold">Environment</th>
              <th className="py-2 pr-3 font-semibold">Owner</th>
              <th className="py-2 pr-3 font-semibold">Findings</th>
              <th className="py-2 pr-3 font-semibold">Severity</th>
              <th className="py-2 font-semibold">Status</th>
            </tr>
          </thead>
          <tbody>
            {(data?.members ?? []).map((row) => (
              <tr key={row.assetId} className="border-t border-white/5">
                <td className="py-2 pr-3">
                  <a href={`/dashboard/assets?asset=${encodeURIComponent(row.assetId)}`} className="font-semibold text-slate-200 hover:underline">{row.name}</a>
                  {row.internetFacing && <Globe2 className="ml-1.5 inline h-3 w-3 text-amber-300" aria-label="Internet-facing" />}
                  {row.service && <div className="text-[11px] text-slate-500">{row.service}</div>}
                </td>
                <td className="py-2 pr-3 text-slate-300">{row.environment || 'Unspecified'}</td>
                <td className="py-2 pr-3 text-slate-300">{row.owner ?? <span className="inline-flex items-center gap-1 text-amber-300"><UserX className="h-3 w-3" />Unowned</span>}</td>
                <td className="py-2 pr-3 tabular-nums text-slate-300">{row.observations}</td>
                <td className={cn('py-2 pr-3 font-semibold capitalize', SEVERITY_TEXT[row.severity])}>{row.severity}</td>
                <td className="py-2 text-slate-300"><i className={`qe-dot qe-s-${row.status}`} aria-hidden="true" />{row.statusLabel}</td>
              </tr>
            ))}
            {state === 'loading' && !data && <tr><td colSpan={6} className="py-6 text-center text-slate-500">Loading affected assets…</td></tr>}
            {data && data.members.length === 0 && <tr><td colSpan={6} className="py-6 text-center text-slate-500">No assets match these filters.</td></tr>}
          </tbody>
        </table>
      </div>
      {data && data.total > limit && (
        <div className="flex items-center justify-end gap-2 text-[12px] text-slate-400">
          <span>{offset + 1}–{Math.min(offset + limit, data.total)} of {data.total}</span>
          <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))} className="rounded-md border border-white/12 px-2.5 py-1 disabled:opacity-40">Previous</button>
          <button type="button" disabled={offset + limit >= data.total} onClick={() => setOffset(offset + limit)} className="rounded-md border border-white/12 px-2.5 py-1 disabled:opacity-40">Next</button>
        </div>
      )}
    </div>
  )
}

export function FixPlan({ clusters, selectedId, onSelect, onOpenMap, onOpenCampaign }: {
  clusters: FixCluster[]
  selectedId: string | null
  onSelect: (id: string | null) => void
  onOpenMap: (id: string) => void
  onOpenCampaign: (id: string) => void
}) {
  const [search, setSearch] = useState('')
  const [kind, setKind] = useState('all')
  const [deadline, setDeadline] = useState('all')
  const [showAll, setShowAll] = useState(false)
  const kinds = useMemo(() => [...new Map(clusters.map((c) => [c.kind, c.kindLabel])).entries()], [clusters])

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase()
    return clusters.filter((c) => {
      if (kind !== 'all' && c.kind !== kind) return false
      if (deadline === 'now' && c.deadline.year !== 0) return false
      if (deadline === '2030' && c.deadline.year !== 2030) return false
      if (deadline === 'review' && c.deadline.year !== null) return false
      if (term && !`${c.title} ${c.rootCause.label} ${c.algorithms.join(' ')} ${c.owners.map((o) => o.owner).join(' ')}`.toLowerCase().includes(term)) return false
      return true
    })
  }, [clusters, search, kind, deadline])
  const visible = showAll ? filtered : filtered.slice(0, 50)

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-white/10 p-4">
        <label className="relative">
          <span className="sr-only">Search fixes</span>
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search fixes, CAs, libraries, owners"
            className="w-72 rounded-lg border border-white/12 bg-transparent py-2 pl-8 pr-3 text-[12px] text-slate-200 placeholder:text-slate-500" />
        </label>
        <select aria-label="Fix type" value={kind} onChange={(e) => setKind(e.target.value)} className="rounded-lg border border-white/12 bg-transparent px-2.5 py-2 text-[12px] text-slate-200">
          <option value="all">All fix types</option>
          {kinds.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
        </select>
        <select aria-label="Deadline" value={deadline} onChange={(e) => setDeadline(e.target.value)} className="rounded-lg border border-white/12 bg-transparent px-2.5 py-2 text-[12px] text-slate-200">
          <option value="all">Any deadline</option>
          <option value="now">Broken today</option>
          <option value="2030">Deprecated after 2030 (NIST)</option>
          <option value="review">Timing needs review</option>
        </select>
        <div className="ml-auto"><StatusLegend /></div>
      </div>

      <div className="qe-fix hidden text-[11px] font-semibold text-slate-500 lg:grid" aria-hidden="true">
        <span>Rank</span><span>Fix</span><span>Open assets</span><span className="qe-col-wide">Progress</span><span className="qe-col-wide">Deadline</span><span className="qe-col-wide">Effort</span>
      </div>
      <ul>
        {visible.map((cluster) => {
          const open = cluster.assets - cluster.progress.validated
          const expanded = selectedId === cluster.id
          return (
            <li key={cluster.id}>
              <button type="button" className="qe-fix" aria-expanded={expanded} onClick={() => onSelect(expanded ? null : cluster.id)}>
                <span className="qe-rank">{cluster.priorityRank}</span>
                <span className="min-w-0">
                  <span className="flex items-center gap-2">
                    {expanded ? <ChevronDown className="h-3.5 w-3.5 shrink-0 text-slate-500" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0 text-slate-500" />}
                    <span className="truncate text-[14px] font-semibold text-slate-100">{cluster.title}</span>
                  </span>
                  <span className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 pl-5 text-[11px] text-slate-400">
                    <span>{cluster.kindLabel}</span>
                    <span className={cn('font-semibold capitalize', SEVERITY_TEXT[cluster.severity])}>{cluster.severity}</span>
                    <span>{cluster.certificates ? `${cluster.certificates.unique} certificates${cluster.certificates.reusedAcrossAssets ? ` (${cluster.certificates.reusedAcrossAssets} reused)` : ''}` : `${cluster.uniqueComponents} unique component(s)`}</span>
                    {cluster.internetFacingAssets > 0 && <span>{cluster.internetFacingAssets} internet-facing</span>}
                    {cluster.unownedAssets > 0 && <span className="text-amber-300">{cluster.unownedAssets} unowned</span>}
                  </span>
                  <span className="mt-2 block w-40 pl-5"><span className="qe-priority" aria-label={`Priority ${cluster.priority} of 100`}><i style={{ width: `${cluster.priority}%` }} /></span></span>
                </span>
                <span className="tabular-nums">
                  <span className="text-[15px] font-semibold text-slate-100">{open.toLocaleString()}</span>
                  <span className="text-[11px] text-slate-500"> / {cluster.assets.toLocaleString()}</span>
                  <span className="block text-[11px] text-slate-500">{cluster.shareOfAffectedAssets}% of affected</span>
                </span>
                <span className="qe-col-wide"><ProgressBar progress={cluster.progress} total={cluster.assets} /><span className="mt-1 block text-[11px] text-slate-500">{cluster.progress.validated} validated</span></span>
                <span title={cluster.deadline.basis} className={cn('qe-col-wide text-[12px] font-semibold', cluster.deadline.year === 0 ? 'text-red-400' : cluster.deadline.year === 2030 ? 'text-amber-300' : 'text-slate-300')}>{cluster.deadline.label}</span>
                <span className="qe-col-wide text-[12px] tabular-nums text-slate-300">≈{cluster.effort.days} d<span className="block text-[11px] text-slate-500">estimate</span></span>
              </button>
              {expanded && <FixMembers cluster={cluster} onOpenMap={() => onOpenMap(cluster.id)} onOpenCampaign={() => onOpenCampaign(cluster.id)} />}
            </li>
          )
        })}
      </ul>
      {filtered.length === 0 && <p className="p-8 text-center text-[13px] text-slate-500">No fixes match these filters.</p>}
      {filtered.length > visible.length && (
        <div className="p-4 text-center">
          <button type="button" onClick={() => setShowAll(true)} className="rounded-lg border border-white/12 px-4 py-2 text-[12px] font-semibold text-slate-200 hover:bg-white/5">Show all {filtered.length} fixes</button>
        </div>
      )}
    </div>
  )
}
