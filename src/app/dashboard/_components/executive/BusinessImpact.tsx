'use client'

import { useState } from 'react'
import { Briefcase, Info, TrendingDown, TrendingUp, Minus } from 'lucide-react'
import type { ExecutiveSnapshot } from '@/hooks/use-dashboard'
import { Panel, PanelHeader, cx, fmtCurrency, fmtNumber } from './primitives'

export default function BusinessImpact({ data, loading }: { data: ExecutiveSnapshot['businessImpact'] | undefined; loading: boolean }) {
  const [showAssumptions, setShowAssumptions] = useState(false)
  if (loading && !data) {
    return <Panel><PanelHeader title="Business Impact" icon={Briefcase} /><div className="h-56 animate-pulse rounded-lg bg-white/[0.03]" /></Panel>
  }
  if (!data) return null
  const trend = data.riskTrendDelta
  const trendImproving = trend !== null && trend < 0
  const roi = data.projectedRoiPct
  const cells: Array<{ label: string; value: string; tone?: string; title?: string }> = [
    { label: 'Financial Exposure', value: fmtCurrency(data.financialExposure), tone: data.financialExposure > 0 ? 'text-red-400' : 'text-white/85' },
    { label: 'Value Protected', value: fmtCurrency(data.revenueProtected), tone: data.revenueProtected > 0 ? 'text-emerald-400' : 'text-white/85', title: 'Modelled value of assets already PQC-ready' },
    { label: 'Quantum-Vulnerable Assets', value: fmtNumber(data.missionCriticalAssets), tone: data.missionCriticalAssets > 0 ? 'text-red-400' : 'text-white/85' },
    { label: 'Applications at Risk', value: `${fmtNumber(data.applicationsAtRisk)} of ${fmtNumber(data.applications)}`, tone: data.applicationsAtRisk > 0 ? 'text-red-400' : 'text-white/85' },
    { label: 'Migration Complexity', value: `${data.operationalImpact}/100`, tone: data.operationalImpact >= 60 ? 'text-amber-400' : 'text-white/85', title: 'Dependency depth, footprint and vulnerable share (0–100)' },
    { label: 'Est. Cutover Downtime', value: `${data.estimatedDowntimeHours} hrs`, title: '~15 minutes of planned cutover per quantum-vulnerable asset' },
    {
      label: 'ROI (upper bound)',
      value: roi === null ? 'Not modelled' : `${roi > 0 ? '+' : ''}${roi}%`,
      tone: roi === null ? 'text-white/45' : roi >= 0 ? 'text-cyan-300' : 'text-amber-400',
      title: '(loss avoided − cost) ÷ cost, where loss avoided cannot exceed the modelled exposure',
    },
    { label: 'Migration Cost', value: fmtCurrency(data.migrationCostUsd) },
  ]
  return (
    <Panel>
      <PanelHeader
        title="Business Impact" icon={Briefcase} href="/dashboard/revenue-intelligence"
        right={
          <button
            type="button"
            onClick={(e) => { e.preventDefault(); setShowAssumptions((s) => !s) }}
            className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-1.5 py-0.5 text-[8px] font-black uppercase tracking-wide text-white/45 transition-colors hover:text-cyan-300"
            title="Modelling assumptions"
          >
            <Info className="h-2.5 w-2.5" /> Modelled
          </button>
        }
      />
      <div className="grid grid-cols-2 gap-2.5 lg:grid-cols-4">
        {cells.map((c) => (
          <div key={c.label} title={c.title} className="rounded-lg border border-white/5 bg-white/[0.02] p-2.5">
            <div className="text-[8px] font-bold uppercase tracking-wide text-white/35">{c.label}</div>
            <div className={cx('mt-1 truncate text-base font-black tracking-tight', c.tone || 'text-white/85')}>{c.value}</div>
          </div>
        ))}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px]">
        {trend === null ? (
          <span className="inline-flex items-center gap-1 font-black uppercase tracking-wide text-white/30" title="No earlier exposure figure is stored, so no trend is published">
            <Minus className="h-3 w-3" /> No prior baseline
          </span>
        ) : (
          <span className={cx('inline-flex items-center gap-1 font-black uppercase tracking-wide', trendImproving ? 'text-emerald-400' : trend > 0 ? 'text-red-400' : 'text-white/35')}>
            {trendImproving ? <TrendingDown className="h-3 w-3" /> : <TrendingUp className="h-3 w-3" />}
            Exposure trend {trendImproving ? `down ${Math.abs(trend)}` : trend > 0 ? `up ${trend}` : 'unchanged'}
          </span>
        )}
        {data.criticalityTagged === false && (
          <span className="text-white/30">No assets tagged business-critical — every asset is valued at the standard rate, which understates exposure.</span>
        )}
      </div>

      {showAssumptions && (
        <div className="mt-2 rounded-lg border border-white/8 bg-black/30 p-2.5 text-[10px] leading-relaxed text-white/50">
          {data.assumptions}
        </div>
      )}
    </Panel>
  )
}
