'use client'
import { useState } from 'react'
import { CheckCircle2, Lock, Loader2, Rocket, ShieldAlert } from 'lucide-react'
import { VendorTrustWorkflowCanvas } from '@/components/trust-workflow/VendorTrustWorkflowCanvas'
import type { FixCluster } from '@/lib/estate'
import { useEstateFix, useEstateGraph, useQueueWave } from '@/hooks/use-estate-intelligence'
import { ProgressBar, StatusLegend } from './FixPlan'

export function Campaigns({ clusters, revision, fixId, setFixId, onQueued }: { clusters: FixCluster[]; revision: string; fixId: string | null; setFixId: (id: string) => void; onQueued: () => void }) {
  const selected = clusters.find((c) => c.id === fixId) ?? clusters[0] ?? null
  const id = selected?.id ?? null
  const detail = useEstateFix(id, { offset: 0, limit: 1, status: 'all', q: '' }, revision)
  const pipeline = useEstateGraph('campaign', id ? `fix:${id}` : null, revision)
  const queueWave = useQueueWave()
  const [confirming, setConfirming] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<{ tone: 'ok' | 'error'; text: string } | null>(null)

  if (!selected) return <p className="p-8 text-center text-[13px] text-slate-500">No open fixes — there is no campaign to plan.</p>
  const campaign = detail.data?.campaign
  const waveCurrent = detail.data?.revision === revision && detail.state !== 'error' && !detail.refreshing

  const queue = async (waveIndex: number) => {
    const wave = campaign?.waves.find((w) => w.index === waveIndex)
    if (!wave?.ready || busy || !waveCurrent) return
    setBusy(true)
    setResult(null)
    try {
      const confirmed = await queueWave(wave.assetIds)
      setResult({ tone: 'ok', text: `${confirmed} of ${wave.assets} assets confirmed in the Migration Planner queue. Submit them for approval in Migration Planner.` })
      onQueued()
    } catch (error) {
      setResult({ tone: 'error', text: (error as Error).message })
    } finally {
      setBusy(false)
      setConfirming(null)
    }
  }

  return (
    <div className="space-y-5 p-4">
      <div className="flex flex-wrap items-end gap-3">
        <label className="min-w-0 flex-1">
          <span className="mb-1 block text-[11px] font-semibold text-slate-400">Campaign for fix</span>
          <select value={selected.id} onChange={(e) => { setFixId(e.target.value); setResult(null) }} className="w-full max-w-2xl rounded-lg border border-white/12 bg-transparent px-3 py-2 text-[13px] text-slate-200">
            {clusters.map((c) => <option key={c.id} value={c.id}>#{c.priorityRank} {c.title} — {c.assets - c.progress.validated} open</option>)}
          </select>
        </label>
        <div className="w-full max-w-xs">
          <div className="mb-1 flex justify-between text-[11px] text-slate-400"><span>Validated</span><span className="tabular-nums">{campaign ? `${campaign.completion}%` : '…'}</span></div>
          <ProgressBar progress={selected.progress} total={selected.assets} />
        </div>
      </div>
      <StatusLegend />

      <VendorTrustWorkflowCanvas
        graph={pipeline.data?.graph ?? { nodes: [], edges: [], groups: [], notices: [], legend: {} }}
        ariaLabel={`Migration pipeline for ${selected.title}`}
        status={pipeline.state === 'error' && !pipeline.data ? 'error' : !pipeline.data ? 'loading' : 'ready'}
        error={pipeline.error}
        onRetry={() => void pipeline.refresh()}
        empty={{ title: 'No pipeline', detail: 'This fix has no assets in scope.' }}
        height={420}
        exportName={`campaign-${selected.id}`}
      />

      <section aria-labelledby="qe-waves">
        <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
          <h3 id="qe-waves" className="text-[15px] font-semibold text-slate-100">Rollout waves</h3>
          <p className="text-[11px] text-slate-500">{campaign?.gate}</p>
        </div>
        {result && (
          <p role="status" className={`mb-3 rounded-lg border px-3 py-2 text-[12px] ${result.tone === 'ok' ? 'border-emerald-400/30 bg-emerald-500/10 text-emerald-300' : 'border-red-400/30 bg-red-500/10 text-red-300'}`}>
            {result.text} {result.tone === 'ok' && <a href="/dashboard/migration-planner" className="font-semibold underline">Open Migration Planner</a>}
          </p>
        )}
        {detail.state === 'error' && <p role="alert" className="text-[12px] text-red-400">Could not refresh rollout waves. <button type="button" className="underline" onClick={() => void detail.refresh()}>Retry</button></p>}
        {detail.state !== 'error' && !campaign && <p className="text-[12px] text-slate-500">Loading waves…</p>}
        {campaign && campaign.waves.length === 0 && (
          <p className="flex items-center gap-2 text-[13px] text-slate-400"><CheckCircle2 className="h-4 w-4 text-emerald-400" />No assets are ready to queue. Track their current status in the pipeline above.</p>
        )}
        <ol className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
          {campaign?.waves.slice(0, 12).map((wave) => (
            <li key={wave.index} className="rounded-xl border border-white/10 bg-white/[0.02] p-3.5">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[13px] font-semibold text-slate-100">{wave.label}{wave.canary && <span className="ml-2 rounded-full bg-blue-500/15 px-2 py-0.5 text-[10px] font-semibold text-blue-200">canary</span>}</span>
                <span className="text-[12px] tabular-nums text-slate-300">{wave.assets} assets</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-500">{wave.environments.join(' · ')}</p>
              <p className="mt-2 flex items-start gap-1.5 text-[11px] text-slate-400">
                {wave.ready ? <Rocket className="mt-0.5 h-3 w-3 shrink-0 text-blue-300" /> : wave.index === 1 ? <ShieldAlert className="mt-0.5 h-3 w-3 shrink-0 text-amber-300" /> : <Lock className="mt-0.5 h-3 w-3 shrink-0 text-slate-500" />}
                {wave.readinessNote}
              </p>
              {wave.ready && confirming !== wave.index && (
                <button type="button" onClick={() => setConfirming(wave.index)} className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-blue-400/40 bg-blue-500/15 px-3 py-1.5 text-[12px] font-semibold text-blue-200 hover:bg-blue-500/25">
                  <Rocket className="h-3.5 w-3.5" /> Queue in Migration Planner
                </button>
              )}
              {confirming === wave.index && (
                <div className="mt-3 rounded-lg border border-amber-400/30 bg-amber-500/10 p-2.5 text-[11px] text-amber-200">
                  Adds {wave.assets} asset(s) to your Migration Planner queue (it holds up to 200). Nothing runs until a plan is approved there.
                  <div className="mt-2 flex gap-2">
                    <button type="button" disabled={busy || !waveCurrent || !wave.ready} onClick={() => void queue(wave.index)} className="inline-flex items-center gap-1 rounded-md bg-blue-600 px-2.5 py-1 font-semibold text-white disabled:opacity-60">
                      {busy && <Loader2 className="h-3 w-3 animate-spin" />} Confirm
                    </button>
                    <button type="button" disabled={busy} onClick={() => setConfirming(null)} className="rounded-md border border-white/15 px-2.5 py-1 text-slate-200">Cancel</button>
                  </div>
                </div>
              )}
            </li>
          ))}
        </ol>
        {campaign && campaign.waves.length > 12 && <p className="mt-2 text-[11px] text-slate-500">Showing the first 12 of {campaign.waves.length} waves; later waves unlock in order.</p>}
      </section>
    </div>
  )
}
