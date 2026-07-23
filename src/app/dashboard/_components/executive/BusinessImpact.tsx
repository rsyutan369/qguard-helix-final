'use client'

import { useState } from 'react'
import { Briefcase, Info, TrendingDown, TrendingUp } from 'lucide-react'
import type { ExecutiveSnapshot } from '@/hooks/use-dashboard'
import { Panel, PanelHeader, cx, fmtCurrency, fmtNumber } from './primitives'

export default function BusinessImpact({ data, loading }: { data: ExecutiveSnapshot['businessImpact'] | undefined; loading: boolean }) {
  const [showAssumptions, setShowAssumptions] = useState(false)
  if (loading && !data) {
    return <Panel><PanelHeader title="Business Impact" icon={Briefcase} /><div className="h-56 animate-pulse rounded-lg bg-white/[0.03]" /></Panel>
  }
  if (!data) return null
  const trendImproving = data.riskTrendDelta < 0
  const cells: Array<{ label: string; value: string; tone?: string; icon?: boolean }> = [
    { label: 'Financial Exposure', value: fmtCurrency(data.financialExposure), tone: 'text-red-400' },
    { label: 'Revenue Protected', value: fmtCurrency(data.revenueProtected), tone: 'text-emerald-400' },
    { label: 'Critical Assets at Risk', value: fmtNumber(data.missionCriticalAssets), tone: data.missionCriticalAssets > 0 ? 'text-red-400' : 'text-white/85' },
    { label: 'Applications at Risk', value: fmtNumber(data.applicationsAtRisk) },
    { label: 'Operational Impact', value: `${data.operationalImpact}/100`, tone: data.operationalImpact >= 60 ? 'text-amber-400' : 'text-white/85' },
    { label: 'Est. Cutover Downtime', value: `${data.estimatedDowntimeHours} hrs` },
    { label: 'Projected ROI', value: `${data.projectedRoiPct}%`, tone: 'text-cyan-300' },
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
          <div key={c.label} className="rounded-lg border border-white/5 bg-white/[0.02] p-2.5">
            <div className="text-[8px] font-bold uppercase tracking-wide text-white/35">{c.label}</div>
            <div className={cx('mt-1 truncate text-base font-black tracking-tight', c.tone || 'text-white/85')}>{c.value}</div>
          </div>
        ))}
      </div>

      <div className="mt-3 flex items-center gap-2 text-[10px]">
        <span className={cx('inline-flex items-center gap-1 font-black uppercase tracking-wide', trendImproving ? 'text-emerald-400' : data.riskTrendDelta > 0 ? 'text-red-400' : 'text-white/35')}>
          {trendImproving ? <TrendingDown className="h-3 w-3" /> : <TrendingUp className="h-3 w-3" />}
          Risk trend {trendImproving ? `down ${Math.abs(data.riskTrendDelta)}` : data.riskTrendDelta > 0 ? `up ${data.riskTrendDelta}` : 'stable'}
        </span>
      </div>

      {showAssumptions && (
        <div className="mt-2 rounded-lg border border-white/8 bg-black/30 p-2.5 text-[10px] leading-relaxed text-white/50">
          {data.assumptions}
        </div>
      )}
    </Panel>
  )
}
