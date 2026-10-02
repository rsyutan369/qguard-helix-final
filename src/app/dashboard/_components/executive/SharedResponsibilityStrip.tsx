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
  const openFindings = Math.max(0, data.totals.findings - data.totals.resolved)
  const openShare = (value: number) => (openFindings > 0 ? Math.min(100, (value / openFindings) * 100) : 0)

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
            <GaugeCell label="Customer" score={r.customer.score} total={r.customer.total} color="#22d3ee" />
            <GaugeCell label="Provider" score={r.provider.score} total={r.provider.total} color="#60a5fa" />
            <GaugeCell label="Ecosystem" score={r.ecosystem.score} total={r.ecosystem.total} color="#a78bfa" />
          </div>

          {/* Ownership split + actionable balance */}
          <div className="flex flex-col justify-center gap-3">
            <div>
              <div className="mb-1.5 flex items-center justify-between text-[10px] font-black uppercase tracking-wide text-white/45">
                <span>Ownership Split</span>
                {/* Split into open work and PQC-ready confirmations, so the total
                    here reconciles with the Open Findings KPI instead of
                    silently including observations that need no action. */}
                <span className="font-mono normal-case text-white/40" title="Ownership is classified over every scanner observation, including PQC-ready confirmations">
                  {fmtNumber(Math.max(0, data.totals.findings - data.totals.resolved))} open · {fmtNumber(data.totals.resolved)} PQC-ready
                </span>
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
              <StatTile icon={CheckCircle2} tone="good" label="Actionable Now" value={data.widgets.actionableFindings} sub="Open findings you can remediate" share={openShare(data.widgets.actionableFindings)} />
              <StatTile icon={AlertTriangle} tone="bad" label="Migration Blockers" value={data.widgets.migrationBlockers} sub="Critical/high gated on a dependency" share={openShare(data.widgets.migrationBlockers)} />
            </div>
          </div>
        </div>
      )}
    </Panel>
  )
}

/* A domain with NO findings classified to it has nothing measured. The engine
   scores it 100 ("Quantum-Ready"), which on this strip read as a verified pass
   for a provider estate nobody assessed — it renders as not applicable. */
function GaugeCell({ label, score, total, color }: { label: string; score: number; total: number; color: string }) {
  const measured = total > 0
  return (
    <div className="flex flex-col items-center gap-1" title={measured ? `${label} readiness over ${total} classified finding${total === 1 ? '' : 's'}` : `No findings are classified to the ${label.toLowerCase()} domain, so no readiness is published for it`}>
      <RadialGauge value={measured ? score : 0} color={measured ? color : '#475569'} size={72} label={measured ? String(Math.round(score)) : '—'} sublabel={measured ? '/100' : 'none owned'} />
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

/* The bar is a SHARE of the open findings when one is known — it used to be
   `value × 8`, a width with no unit that saturated at 13. */
function StatTile({ icon: Icon, tone, label, value, sub, share }: { icon: typeof UserCog; tone: 'good' | 'bad'; label: string; value: number; sub: string; share?: number }) {
  const color = tone === 'good' ? '#34d399' : '#f87171'
  return (
    <div className={cx('rounded-lg border p-3', tone === 'good' ? 'border-emerald-500/20 bg-emerald-500/[0.05]' : 'border-red-500/20 bg-red-500/[0.05]')}>
      <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide" style={{ color }}>
        <Icon className="h-3.5 w-3.5" /> {label}
      </div>
      <div className="mt-1 text-xl font-black text-white">{fmtNumber(value)}</div>
      <div className="text-[10px] text-white/40">{sub}</div>
      {share !== undefined && <div className="mt-1.5"><Bar value={share} color={color} height={4} /></div>}
    </div>
  )
}
