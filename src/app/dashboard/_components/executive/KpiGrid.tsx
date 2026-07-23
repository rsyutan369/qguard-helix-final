'use client'

import { motion, useReducedMotion } from 'framer-motion'
import type { ExecutiveKpi } from '@/hooks/use-dashboard'
import { PANEL, TONE, cx, fmtCompact, fmtCurrency, DeltaBadge, Sparkline, relativeTime, type Tone } from './primitives'

function formatValue(kpi: ExecutiveKpi): string {
  if (kpi.unmeasured) return '—'
  switch (kpi.format) {
    case 'currency': return fmtCurrency(kpi.value)
    case 'percent': return `${Math.round(kpi.value)}`
    case 'score': return `${Math.round(kpi.value)}`
    default: return fmtCompact(kpi.value)
  }
}

/** Tone from value vs target, honouring the metric's direction. */
function kpiTone(kpi: ExecutiveKpi): Tone {
  if (kpi.unmeasured) return 'neutral'
  if (kpi.level) {
    const l = kpi.level.toLowerCase()
    if (l.includes('critical')) return 'critical'
    if (l.includes('high')) return 'warning'
    if (l.includes('low') || l.includes('minimal')) return 'good'
  }
  if (kpi.format === 'score' || (kpi.direction === 'lower-better' && kpi.format !== 'currency' && kpi.format !== 'count')) {
    if (kpi.value <= kpi.target) return 'good'
    if (kpi.value <= kpi.target * 2.2) return 'warning'
    return 'critical'
  }
  if (kpi.direction === 'higher-better' && (kpi.format === 'percent')) {
    if (kpi.value >= 85) return 'good'
    if (kpi.value >= 50) return 'warning'
    return 'neutral'
  }
  return 'neutral'
}

function KpiCard({ kpi, index }: { kpi: ExecutiveKpi; index: number; key?: string | number }) {
  const reduce = useReducedMotion()
  const tone = kpiTone(kpi)
  const t = TONE[tone]

  return (
    <motion.a
      href={kpi.route}
      aria-label={`${kpi.label}: ${formatValue(kpi)}${kpi.unit}`}
      initial={reduce ? false : { opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.03 }}
      className={cx(PANEL, 'flex flex-col p-4 no-underline outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70')}
    >
      {/* accent rail */}
      <span className={cx('absolute left-0 top-0 h-full w-[3px]', t.dot)} aria-hidden="true" />

      <div className="flex items-start justify-between gap-2">
        <span className="text-[9px] font-black uppercase leading-tight tracking-[0.12em] text-white/45">{kpi.label}</span>
        {kpi.modeled && <span className="rounded bg-white/5 px-1 py-0.5 text-[7px] font-black uppercase tracking-wide text-white/35" title="Modelled estimate">model</span>}
      </div>

      <div className="mt-2 flex items-end gap-1.5">
        <span className={cx('text-[26px] font-black leading-none tracking-tighter', kpi.unmeasured ? 'text-white/40' : t.text)}>{formatValue(kpi)}</span>
        {!kpi.unmeasured && kpi.unit && kpi.unit !== 'USD' && <span className="mb-0.5 text-xs font-bold text-white/35">{kpi.unit}</span>}
      </div>

      <div className="mt-1.5">
        <DeltaBadge trend={kpi.trend} delta={kpi.deltaPercent} direction={kpi.direction} />
      </div>

      <div className="mt-3 -mx-1">
        <Sparkline values={kpi.sparkline} color={t.hex} />
      </div>

      <div className="mt-2 flex items-center justify-between border-t border-white/5 pt-2 text-[8px] font-bold uppercase tracking-wide text-white/30">
        <span>Target: {kpi.targetLabel}</span>
        <span>{relativeTime(kpi.lastUpdated)}</span>
      </div>

      {/* Hover analytics */}
      <div className="pointer-events-none absolute inset-x-0 bottom-0 translate-y-full bg-[#0b1327]/95 px-3 py-2 text-[10px] leading-snug text-white/70 opacity-0 backdrop-blur transition-all duration-200 group-hover:translate-y-0 group-hover:opacity-100">
        {kpi.hint}
      </div>
    </motion.a>
  )
}

export default function KpiGrid({ kpis, loading }: { kpis: ExecutiveKpi[] | undefined; loading: boolean }) {
  if (loading && (!kpis || kpis.length === 0)) {
    return (
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-6">
        {Array.from({ length: 12 }).map((_, i) => (
          <div key={i} className={cx(PANEL, 'h-[168px] animate-pulse p-4')} />
        ))}
      </div>
    )
  }
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-6">
      {(kpis || []).map((kpi, i) => <KpiCard key={kpi.id} kpi={kpi} index={i} />)}
    </div>
  )
}
