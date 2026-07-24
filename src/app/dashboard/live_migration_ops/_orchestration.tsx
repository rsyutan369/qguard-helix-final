'use client'

import {
  Activity,
  Cpu,
  Gauge,
  Layers,
  Network,
  Server,
  ShieldCheck,
  Timer,
  TrendingUp,
  Workflow,
  Zap,
} from 'lucide-react'
import { useMigrationOrchestrator } from '@/hooks/use-migration-orchestrator'
import type { OrchestratorJobPhase } from '@/types/migration-orchestrator'

const PANEL = 'rounded-2xl border border-white/10 bg-white/[0.035] backdrop-blur-xl text-white shadow-[0_18px_60px_rgba(0,0,0,0.35)]'
const INNER = 'rounded-xl border border-white/10 bg-white/[0.02]'

function fmt(n: number) { return new Intl.NumberFormat('en-US').format(Math.round(n || 0)) }
function dur(s: number | null) {
  if (s == null) return '—'
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.round(s / 60)}m`
  return `${(s / 3600).toFixed(1)}h`
}

const PHASE_TONE: Record<OrchestratorJobPhase, string> = {
  blocked: '#94a3b8',
  queued: '#38bdf8',
  leased: '#22d3ee',
  running: '#22d3ee',
  validating: '#a78bfa',
  completed: '#34d399',
  retrying: '#f59e0b',
  failed: '#f87171',
  rolled_back: '#94a3b8',
  dead_letter: '#f87171',
  paused: '#94a3b8',
}

export default function OrchestrationPanel({ enabled }: { enabled: boolean }) {
  const { data, sseConnected } = useMigrationOrchestrator(enabled)
  const m = data.metrics

  const statusCells: Array<{ label: string; value: number; phase: OrchestratorJobPhase }> = [
    { label: 'Queued', value: m.queued, phase: 'queued' },
    { label: 'Blocked', value: m.blocked, phase: 'blocked' },
    { label: 'Leased', value: m.leased, phase: 'leased' },
    { label: 'Running', value: m.running, phase: 'running' },
    { label: 'Validating', value: m.validating, phase: 'validating' },
    { label: 'Completed', value: m.completed, phase: 'completed' },
    { label: 'Retrying', value: m.retrying, phase: 'retrying' },
    { label: 'Failed', value: m.failed, phase: 'failed' },
    { label: 'Rolled Back', value: m.rolledBack, phase: 'rolled_back' },
    { label: 'Dead-letter', value: m.deadLetter, phase: 'dead_letter' },
  ]

  const perf = [
    { label: 'Throughput', value: m.throughputPerMin != null ? `${m.throughputPerMin}` : '—', hint: 'assets / min', icon: TrendingUp, tone: '#34d399' },
    { label: 'Avg Duration', value: dur(m.avgDurationSeconds), hint: 'per completed job', icon: Timer, tone: '#38bdf8' },
    { label: 'Queue Depth', value: fmt(m.queueDepth), hint: 'awaiting execution', icon: Layers, tone: '#f59e0b' },
    { label: 'In-Flight', value: `${fmt(m.inFlight)}/${fmt(data.config.maxConcurrentPerTenant)}`, hint: 'concurrency cap', icon: Zap, tone: '#22d3ee' },
    { label: 'Worker Util.', value: `${m.workerUtilizationPct}%`, hint: `${fmt(m.activeWorkers)} active worker(s)`, icon: Cpu, tone: '#a78bfa' },
    { label: 'Validation', value: `${m.validationProgressPct}%`, hint: 'checks passed', icon: ShieldCheck, tone: '#34d399' },
  ]

  const health = [
    { label: 'Agents Online', value: fmt(m.agentsOnline), tone: '#34d399' },
    { label: 'Agents Degraded', value: fmt(m.agentsDegraded), tone: '#f59e0b' },
    { label: 'Agents Offline', value: fmt(m.agentsOffline), tone: '#94a3b8' },
    { label: 'Connectors', value: `${fmt(m.connectorsHealthy)}/${fmt(m.connectorsTotal)}`, tone: '#38bdf8' },
    { label: 'CPU (reported)', value: m.agentCpuPct != null ? `${m.agentCpuPct}%` : '—', tone: '#a78bfa' },
    { label: 'Memory (reported)', value: m.agentMemoryPct != null ? `${m.agentMemoryPct}%` : '—', tone: '#a78bfa' },
    { label: 'Net Latency', value: m.networkLatencyMs != null ? `${m.networkLatencyMs}ms` : '—', tone: '#38bdf8' },
    { label: 'Reclaimed Leases', value: fmt(m.reclaimedLeases), tone: '#f59e0b' },
  ]

  const maxSpark = Math.max(1, ...data.throughput.map((p) => p.completed))

  return (
    <section className={`${PANEL} p-5`}>
      <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="inline-flex items-center gap-2 text-sm font-black uppercase tracking-wide text-white/80"><Workflow className="h-4 w-4 text-cyan-300" /> Enterprise Migration Orchestrator</h3>
          <p className="mt-0.5 text-[11px] text-white/45">Distributed, fault-tolerant scheduling across stateless workers — priority queues, leases, back-pressure, retries &amp; auto-recovery.</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan-400/25 bg-cyan-400/10 px-2.5 py-0.5 text-[10px] font-black uppercase text-cyan-200"><Gauge className="h-3 w-3" /> Scale {data.scaleTier} assets</span>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.03] px-2.5 py-0.5 text-[10px] font-black uppercase text-white/55">
            <span className={`h-1.5 w-1.5 rounded-full ${sseConnected ? 'bg-emerald-400' : 'bg-amber-300'}`} /> {sseConnected ? 'Live' : 'Sync'}
          </span>
        </div>
      </div>

      {/* Overall progress + throughput sparkline */}
      <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(220px,300px)]">
        <div className={`${INNER} p-4`}>
          <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-wide text-white/45">
            <span>Overall Migration Progress</span>
            <span className="text-white/70">{fmt(m.assetsUpgraded)} upgraded · {fmt(m.assetsRemaining)} remaining</span>
          </div>
          <div className="mt-2 flex items-center gap-3">
            <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-white/10">
              <div className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-emerald-400 transition-all duration-1000" style={{ width: `${Math.min(100, m.overallProgressPct)}%` }} />
            </div>
            <span className="w-12 text-right text-lg font-black tabular-nums text-white">{m.overallProgressPct}%</span>
          </div>
        </div>
        <div className={`${INNER} p-4`}>
          <div className="mb-1.5 flex items-center justify-between text-[11px] font-bold uppercase tracking-wide text-white/45"><span>Throughput (15m)</span><Activity className="h-3.5 w-3.5 text-emerald-300" /></div>
          <div className="flex h-10 items-end gap-0.5">
            {data.throughput.map((p, i) => (
              <div key={i} className="flex-1 rounded-t bg-emerald-400/70" style={{ height: `${Math.max(4, (p.completed / maxSpark) * 100)}%` }} title={`${p.label}: ${p.completed}`} />
            ))}
          </div>
        </div>
      </div>

      {/* Job status breakdown */}
      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-5">
        {statusCells.map((c) => (
          <div key={c.label} className={`${INNER} p-3`}>
            <div className="text-xl font-black tabular-nums" style={{ color: PHASE_TONE[c.phase] }}>{fmt(c.value)}</div>
            <div className="mt-0.5 text-[10px] font-bold uppercase tracking-wide text-white/45">{c.label}</div>
          </div>
        ))}
      </div>

      {/* Performance metrics */}
      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6">
        {perf.map((p) => {
          const Icon = p.icon
          return (
            <div key={p.label} className={`${INNER} p-3`}>
              <div className="flex items-center gap-1.5 text-[9px] font-black uppercase tracking-wide" style={{ color: p.tone }}><Icon className="h-3 w-3" /> {p.label}</div>
              <div className="mt-1 text-lg font-black tabular-nums text-white">{p.value}</div>
              <div className="text-[10px] text-white/35">{p.hint}</div>
            </div>
          )
        })}
      </div>

      <div className="mt-3 grid gap-3 xl:grid-cols-[minmax(0,1.15fr)_minmax(300px,0.85fr)]">
        {/* Priority queue */}
        <div className={`${INNER} p-4`}>
          <div className="mb-2 flex items-center justify-between">
            <h4 className="inline-flex items-center gap-1.5 text-[11px] font-black uppercase tracking-wide text-white/60"><Layers className="h-3.5 w-3.5 text-cyan-300" /> Priority Queue</h4>
            <span className="text-[10px] text-white/35">highest priority first</span>
          </div>
          {data.priorityQueue.length ? (
            <div className="max-h-56 space-y-1 overflow-y-auto">
              {data.priorityQueue.map((j) => (
                <div key={j.id} className="grid grid-cols-[auto_1fr_auto] items-center gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-1.5 text-[11px]">
                  <span className="grid h-5 w-8 place-items-center rounded font-mono text-[10px] font-black" style={{ color: '#22d3ee', backgroundColor: '#22d3ee14' }}>{j.priority}</span>
                  <span className="min-w-0 truncate text-white/75">{j.asset}{j.blockedBy > 0 ? <span className="ml-1 text-white/35">· blocked ×{j.blockedBy}</span> : null}</span>
                  <span className="flex items-center gap-1.5">
                    {j.retryCount > 0 ? <span className="rounded bg-amber-400/10 px-1 text-[9px] font-black text-amber-300">retry {j.retryCount}</span> : null}
                    <span className="rounded-full px-1.5 py-0.5 text-[9px] font-black uppercase" style={{ color: PHASE_TONE[j.phase], backgroundColor: `${PHASE_TONE[j.phase]}14` }}>{j.phase.replace('_', ' ')}</span>
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="py-6 text-center text-[11px] text-white/35">No active jobs in the queue. Jobs appear here as migrations are dispatched.</p>
          )}
        </div>

        {/* Health + workers */}
        <div className={`${INNER} p-4`}>
          <h4 className="mb-2 inline-flex items-center gap-1.5 text-[11px] font-black uppercase tracking-wide text-white/60"><Network className="h-3.5 w-3.5 text-emerald-300" /> Fleet Health &amp; Telemetry</h4>
          <div className="grid grid-cols-2 gap-1.5">
            {health.map((h) => (
              <div key={h.label} className="rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-1.5">
                <div className="text-sm font-black tabular-nums" style={{ color: h.tone }}>{h.value}</div>
                <div className="text-[9px] font-bold uppercase tracking-wide text-white/40">{h.label}</div>
              </div>
            ))}
          </div>
          {data.agents.length ? (
            <div className="mt-2 max-h-24 space-y-1 overflow-y-auto">
              {data.agents.slice(0, 6).map((a) => (
                <div key={a.id} className="flex items-center justify-between gap-2 text-[10px]">
                  <span className="inline-flex min-w-0 items-center gap-1.5 truncate text-white/60"><Server className="h-3 w-3 shrink-0 text-white/35" /> {a.name}</span>
                  <span className="text-white/40">{a.leasedJobs > 0 ? `${a.leasedJobs} leased` : a.status}</span>
                </div>
              ))}
            </div>
          ) : null}
        </div>
      </div>

    </section>
  )
}
