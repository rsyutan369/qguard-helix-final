import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowRight, CheckCircle2, Clock3, Loader2, XCircle } from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import type { TrackedScan } from '@/lib/agent-installer/scan-tracking'
import type { WorkflowAgentId } from '@/lib/migration/agent-workflow'
import { PANEL } from './_workflow-ui'

type Receipt = TrackedScan & {
  agent: { id: string; name: string; hostname: string | null; role: WorkflowAgentId; platform: string | null }
  schedule: { enabled: boolean; intervalSeconds: number }
}

const LABEL = { queued: 'Queued', running: 'Running', completed: 'Completed', completed_with_errors: 'Completed with errors', failed: 'Failed', stalled: 'Progress interrupted' }
const date = (value: string | null) => value ? new Date(value).toLocaleString() : 'Not yet recorded'

/** The requested command's receipt is independent of the continuously scanning fleet. */
export default function ScanRunPanel({ agentId, commandId, onRole }: { agentId: string; commandId: string; onRole: (role: WorkflowAgentId) => void }) {
  const { session } = useAuth()
  const token = session?.access_token
  const [receipt, setReceipt] = useState<Receipt | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    if (!token) return
    const abort = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    setReceipt(null)
    setError('')
    const poll = async () => {
      let repeat = true
      try {
        const response = await fetch(`/api/v1/agent-installer/agents/${encodeURIComponent(agentId)}/scan-status?${new URLSearchParams({ commandId })}`, {
          headers: { Authorization: `Bearer ${token}` }, signal: abort.signal,
        })
        const json = await response.json()
        if (!response.ok || !json.data) {
          repeat = response.status !== 404 && response.status !== 403 && response.status !== 401
          throw new Error(json?.error?.message || 'Unable to read scan progress.')
        }
        const next = json.data as Receipt
        if (abort.signal.aborted) return
        setReceipt(next)
        setError('')
        repeat = !['completed', 'completed_with_errors', 'failed'].includes(next.state)
      } catch (cause) {
        if (!abort.signal.aborted) setError(cause instanceof Error ? cause.message : 'Unable to read scan progress.')
      } finally {
        if (!abort.signal.aborted && repeat) timer = setTimeout(poll, 2500)
      }
    }
    void poll()
    return () => { abort.abort(); if (timer) clearTimeout(timer) }
  }, [agentId, commandId, token])

  useEffect(() => { if (receipt?.agent.role) onRole(receipt.agent.role) }, [receipt?.agent.role, onRole])
  const finished = receipt && ['completed', 'completed_with_errors', 'failed'].includes(receipt.state)
  const Icon = receipt?.state === 'completed' ? CheckCircle2 : receipt?.state === 'failed' ? XCircle : receipt?.state === 'stalled' || receipt?.state === 'completed_with_errors' ? AlertTriangle : receipt?.state === 'running' ? Loader2 : Clock3

  return (
    <section className={`${PANEL} scroll-mt-5 border-cyan-400/30 p-4 sm:p-5`} aria-label="Requested scan progress" aria-live="polite">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-[10px] font-bold uppercase tracking-[0.16em] text-cyan-300">Requested scan · {receipt?.agent.name || 'Loading agent'}</div>
          <h2 className="mt-1 flex items-center gap-2 text-lg font-black text-white"><Icon className={`h-5 w-5 ${receipt?.state === 'running' ? 'animate-spin motion-reduce:animate-none' : ''}`} />{receipt ? LABEL[receipt.state] : error ? 'Progress unavailable' : 'Loading scan receipt…'}</h2>
          <p className="mt-1 text-sm text-white/70">{receipt?.message || 'Reading the command acknowledged by the control plane.'}</p>
        </div>
        <Link to={`/dashboard/assets?${new URLSearchParams({ agentId })}`} className="inline-flex items-center gap-2 rounded-lg border border-cyan-400/30 px-3 py-2 text-xs font-bold text-cyan-200">View collected assets &amp; CBOM <ArrowRight className="h-4 w-4" /></Link>
      </div>
      {error ? <p role="alert" className="mt-3 text-sm text-amber-200">{error} {receipt ? 'Showing the last confirmed receipt.' : ''}</p> : null}
      {receipt?.progress !== null && receipt?.progress !== undefined ? <div className="mt-4 flex items-center gap-3"><div className="h-2 flex-1 overflow-hidden rounded bg-white/10" role="progressbar" aria-label="Agent-reported scan progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={receipt.progress}><div className="h-full bg-cyan-400 transition-[width] motion-reduce:transition-none" style={{ width: `${receipt.progress}%` }} /></div><span className="font-mono text-xs text-cyan-200">{receipt.progress}%</span></div> : null}
      {receipt ? <>
        <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-3">
          {[['Queued', date(receipt.queuedAt)], ['Started', date(receipt.startedAt)], ['Finished', date(receipt.completedAt)]].map(([label, value]) => <div key={label}><dt className="text-white/45">{label}</dt><dd className="mt-1 text-white/85">{value}</dd></div>)}
        </dl>
        {finished ? <p className="mt-3 text-xs text-white/75">Control plane accepted <strong>{receipt.acceptedCount ?? '—'}</strong> records · {receipt.evidenceCount ?? '—'} evidence collected · {receipt.runtimeEventCount ?? '—'} runtime events · {receipt.rejectedByPolicy ?? '—'} outside authorized scope. Accepted records are published to Assets &amp; CBOM; counts describe records, not distinct assets.</p> : null}
        <div className="mt-4 border-t border-white/10 pt-3 text-xs text-white/55">
          <p>{receipt.schedule.enabled ? `Continuous collection is enabled: the agent checks for work and starts scheduled scans every ${receipt.schedule.intervalSeconds}s after a cycle finishes.` : 'Automatic collection is disabled by policy.'} {finished ? 'This receipt stays finished when a later scan begins.' : 'This panel follows only the scan you requested.'}</p>
          <p className="mt-1">Patcher and Migration Operator execute separately when an authorized, approved job is dispatched. <Link className="text-cyan-200 underline" to="/dashboard/agents?view=settings">Manage collector policy</Link></p>
          <p className="mt-2 font-mono text-[10px] text-white/35">Request {commandId} · Host {receipt.agent.hostname || 'not reported'}</p>
        </div>
      </> : null}
    </section>
  )
}
