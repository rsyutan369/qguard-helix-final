'use client'

import { Radio, Cpu, MemoryStick, Timer, Layers, Server, Wifi, Activity } from 'lucide-react'
import type { ExecutiveSnapshot } from '@/hooks/use-dashboard'
import { Panel, PanelHeader, cx, fmtNumber } from './primitives'

export default function RuntimeTelemetry({ runtime, sseConnected, loading }: { runtime: ExecutiveSnapshot['runtime'] | undefined; sseConnected: boolean; loading: boolean }) {
  if (loading && !runtime) {
    return <Panel><PanelHeader title="Live Runtime Telemetry" icon={Radio} /><div className="h-40 animate-pulse rounded-lg bg-white/[0.03]" /></Panel>
  }
  const r = runtime
  const workerPct = r && r.totalWorkers > 0 ? Math.round((r.activeWorkers / r.totalWorkers) * 100) : 0
  const cells = [
    { icon: Activity, label: 'Events / 24h', value: fmtNumber(r?.events24h || 0) },
    { icon: Layers, label: 'Queue Depth', value: fmtNumber(r?.queueDepth || 0), tone: (r?.queueDepth || 0) > 0 ? 'text-amber-400' : undefined },
    { icon: Server, label: 'Workers Online', value: `${fmtNumber(r?.activeWorkers || 0)}/${fmtNumber(r?.totalWorkers || 0)}`, tone: workerPct >= 50 ? 'text-emerald-400' : r && r.totalWorkers > 0 ? 'text-amber-400' : undefined },
    { icon: Timer, label: 'Scan / hr', value: fmtNumber(r?.scanThroughput || 0) },
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
      <p className="mt-3 border-t border-white/5 pt-2 text-[8px] font-bold uppercase tracking-widest text-white/25">
        CPU · heap · latency reflect the platform aggregation service (real process telemetry)
      </p>
    </Panel>
  )
}
