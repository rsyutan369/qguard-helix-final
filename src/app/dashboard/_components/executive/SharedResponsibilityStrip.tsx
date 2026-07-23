'use client'

import { UserCog, Cloud, Globe, CheckCircle2, AlertTriangle, Scale } from 'lucide-react'
import { useMigrationIntelligence } from '@/hooks/use-migration-intelligence'
import { Panel, PanelHeader, RadialGauge, Bar, fmtNumber, cx } from './primitives'

/**
 * Executive Command Center — Shared Responsibility Overview.
 *
 * A compact strip that reuses the same tenant-scoped ownership model served at
 * /api/v1/migration-intelligence (15s single-flight cache). Shows the tri-part
 * readiness, ownership split and the actionable-vs-blocked balance so an
 * executive sees, at a glance, where their teams can actually drive progress.
 */
export default function SharedResponsibilityStrip() {
  const { data, state, sseConnected } = useMigrationIntelligence()
  const r = data.readiness
  const dist = data.domainDistribution
  const totalDist = Math.max(1, dist.customer + dist.provider + dist.ecosystem)

  return (
    <Panel>
      <PanelHeader title="Shared Responsibility Overview" icon={Scale} live={sseConnected} href="/dashboard/migration-intelligence" tone="neutral" />

      {!data.hasData ? (
        <div className="flex min-h-[120px] items-center justify-center text-center text-[11px] text-white/40">
          {state === 'loading' ? 'Classifying cryptographic ownership…' : 'No findings to classify yet — run a scan or connect a provider.'}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-[auto_1fr]">
          {/* Tri-part readiness gauges */}
          <div className="flex items-center justify-around gap-4 lg:justify-start">
            <GaugeCell label="Customer" score={r.customer.score} color="#22d3ee" />
            <GaugeCell label="Provider" score={r.provider.score} color="#60a5fa" />
            <GaugeCell label="Ecosystem" score={r.ecosystem.score} color="#a78bfa" />
          </div>

          {/* Ownership split + actionable balance */}
          <div className="flex flex-col justify-center gap-3">
            <div>
              <div className="mb-1.5 flex items-center justify-between text-[10px] font-black uppercase tracking-wide text-white/45">
                <span>Ownership Split</span>
                <span className="font-mono normal-case text-white/40">{fmtNumber(data.totals.findings)} findings</span>
              </div>
              <div className="flex h-2.5 overflow-hidden rounded-full bg-white/5">
                <div style={{ width: `${(dist.customer / totalDist) * 100}%`, backgroundColor: '#22d3ee' }} title={`Customer ${dist.customer}`} />
                <div style={{ width: `${(dist.provider / totalDist) * 100}%`, backgroundColor: '#60a5fa' }} title={`Provider ${dist.provider}`} />
                <div style={{ width: `${(dist.ecosystem / totalDist) * 100}%`, backgroundColor: '#a78bfa' }} title={`Ecosystem ${dist.ecosystem}`} />
              </div>
              <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-bold">
                <Legend color="#22d3ee" icon={UserCog} label="Customer" value={dist.customer} />
                <Legend color="#60a5fa" icon={Cloud} label="Provider" value={dist.provider} />
                <Legend color="#a78bfa" icon={Globe} label="Ecosystem" value={dist.ecosystem} />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <StatTile icon={CheckCircle2} tone="good" label="Actionable Now" value={data.widgets.actionableFindings} sub="You can remediate" />
              <StatTile icon={AlertTriangle} tone="bad" label="Migration Blockers" value={data.widgets.migrationBlockers} sub="Gated on a dependency" />
            </div>
          </div>
        </div>
      )}
    </Panel>
  )
}

function GaugeCell({ label, score, color }: { label: string; score: number; color: string }) {
  return (
    <div className="flex flex-col items-center gap-1">
      <RadialGauge value={score} color={color} size={72} label={String(Math.round(score))} sublabel="/100" />
      <span className="text-[9px] font-black uppercase tracking-widest text-white/50">{label}</span>
    </div>
  )
}

function Legend({ color, icon: Icon, label, value }: { color: string; icon: typeof UserCog; label: string; value: number }) {
  return (
    <span className="inline-flex items-center gap-1" style={{ color }}>
      <Icon className="h-3 w-3" /> {label} <span className="font-mono text-white/50">{fmtNumber(value)}</span>
    </span>
  )
}

function StatTile({ icon: Icon, tone, label, value, sub }: { icon: typeof UserCog; tone: 'good' | 'bad'; label: string; value: number; sub: string }) {
  const color = tone === 'good' ? '#34d399' : '#f87171'
  return (
    <div className={cx('rounded-lg border p-3', tone === 'good' ? 'border-emerald-500/20 bg-emerald-500/[0.05]' : 'border-red-500/20 bg-red-500/[0.05]')}>
      <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide" style={{ color }}>
        <Icon className="h-3.5 w-3.5" /> {label}
      </div>
      <div className="mt-1 text-xl font-black text-white">{fmtNumber(value)}</div>
      <div className="text-[10px] text-white/40">{sub}</div>
      <div className="mt-1.5"><Bar value={value > 0 ? Math.min(100, value * 8) : 0} color={color} height={4} /></div>
    </div>
  )
}
