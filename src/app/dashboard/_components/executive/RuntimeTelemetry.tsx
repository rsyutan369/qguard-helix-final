'use client'

import { Link } from 'react-router-dom'
import { Radio, Cpu, MemoryStick, Timer, Layers, Server, Wifi, Activity } from 'lucide-react'
import type { ExecutiveSnapshot } from '@/hooks/use-dashboard'
import { Panel, PanelHeader, cx, fmtNumber } from './primitives'

export default function RuntimeTelemetry({ runtime, sseConnected, loading }: { runtime: ExecutiveSnapshot['runtime'] | undefined; sseConnected: boolean; loading: boolean }) {
  if (loading && !runtime) {
    return <Panel><PanelHeader title="Live Runtime Telemetry" icon={Radio} /><div className="h-40 animate-pulse rounded-lg bg-white/[0.03]" /></Panel>
  }
  const r = runtime
  const workerPct = r && r.totalWorkers > 0 ? Math.round((r.activeWorkers / r.totalWorkers) * 100) : 0

  /*
   * Estate telemetry is only reported when something is actually observing it.
   * With no collector enrolled the panel used to read `0 events · 0 queue ·
   * 0/0 workers`, which is indistinguishable from a quiet, healthy estate —
   * the operator had no way to tell "we measured nothing happening" from
   * "nothing is measuring". Those cells now read "Not measured".
   *
   * The platform-process cells (CPU, heap, latency) are ALWAYS real: they are
   * this API server's own `process.cpuUsage()` / `memoryUsage()`, not a
   * per-host gauge, so they do not depend on tenant telemetry.
   */
  const measured = Boolean(r?.measured)
  const enrolled = Boolean(r?.agentsEnrolled)
  const NOT_MEASURED = '—'
  const estate = (value: string, ok: boolean) => (ok ? value : NOT_MEASURED)

  const cells = [
    { icon: Activity, label: 'Events / 24h', value: estate(fmtNumber(r?.events24h || 0), measured), tone: measured ? undefined : 'text-white/30' },
    { icon: Layers, label: 'Queue Depth', value: estate(fmtNumber(r?.queueDepth || 0), Boolean(r)), tone: (r?.queueDepth || 0) > 0 ? 'text-amber-400' : undefined },
    { icon: Server, label: 'Workers Online', value: enrolled ? `${fmtNumber(r?.activeWorkers || 0)}/${fmtNumber(r?.totalWorkers || 0)}` : NOT_MEASURED, tone: !enrolled ? 'text-white/30' : workerPct >= 50 ? 'text-emerald-400' : 'text-amber-400' },
    { icon: Timer, label: 'Scan / hr', value: estate(fmtNumber(r?.scanThroughput || 0), Boolean(r)) },
    { icon: Cpu, label: 'CPU (server)', value: `${fmtNumber(r?.process.cpuMs || 0)} ms` },
    { icon: MemoryStick, label: 'Heap Used', value: `${r?.process.heapUsedMb ?? 0} MB` },
    { icon: Timer, label: 'Agg. Latency', value: `${r?.process.aggregationLatencyMs ?? 0} ms`, tone: (r?.process.aggregationLatencyMs || 0) < 800 ? 'text-emerald-400' : 'text-amber-400' },
    { icon: Wifi, label: 'Realtime', value: sseConnected ? 'SSE up' : 'Reconnecting', tone: sseConnected ? 'text-emerald-400' : 'text-amber-400' },
  ]
  return (
    <Panel>
      <PanelHeader title="Live Runtime Telemetry" icon={Radio} href="/dashboard/runtime-telemetry" live={sseConnected} />
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {cells.map((c) => {
          const Icon = c.icon
          return (
            <div key={c.label} className="rounded-lg border border-white/5 bg-white/[0.02] p-2.5">
              <div className="flex items-center gap-1.5 text-[8px] font-bold uppercase tracking-wide text-white/40">
                <Icon className="h-3 w-3 text-cyan-300" />
                <span className="truncate">{c.label}</span>
              </div>
              <div className={cx('mt-1 truncate text-sm font-black tracking-tight', c.tone || 'text-white/85')}>{c.value}</div>
            </div>
          )
        })}
      </div>
      {!enrolled ? (
        <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border border-[var(--qg-notice-border)] bg-[var(--qg-notice-bg)] px-3 py-2 text-[10px] text-[var(--qg-notice-text)]">
          <span className="font-bold">No collector enrolled.</span>
          <span className="text-[var(--qg-notice-text-soft)]">Estate telemetry reads “—” because nothing is observing it yet.</span>
          <Link to="/dashboard/downloads" className="font-black underline-offset-2 hover:underline">Deploy an agent</Link>
        </div>
      ) : !measured ? (
        <div className="mt-3 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2 text-[10px] text-white/45">
          A collector is enrolled but has not reported a cryptographic event yet.
        </div>
      ) : null}
      <p className="mt-3 border-t border-white/5 pt-2 text-[8px] font-bold uppercase tracking-widest text-white/25">
        CPU · heap · latency reflect the platform aggregation service (real process telemetry) · estate cells require a collector
      </p>
    </Panel>
  )
}
