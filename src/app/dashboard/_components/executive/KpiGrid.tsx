'use client'

import { motion, useReducedMotion } from 'framer-motion'
import type { ExecutiveKpi } from '@/hooks/use-dashboard'
import { PANEL, TONE, cx, fmtCompact, fmtCurrency, fmtNumber, DeltaBadge, Sparkline, relativeTime, type Tone } from './primitives'

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
    if (l.includes('high') || l.includes('elevated')) return 'warning'
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

const BAR_TONE: Record<NonNullable<ExecutiveKpi['breakdown']>[number]['tone'], string> = {
  critical: 'bg-red-400',
  warning: 'bg-amber-400',
  info: 'bg-sky-400',
  good: 'bg-emerald-400',
  neutral: 'bg-slate-500/70',
}

/**
 * The value's real composition — findings by severity, components by verdict —
 * shown where there is no stored history to draw. A stacked bar of what the
 * number is MADE OF, never a line borrowed from a different metric.
 */
function Breakdown({ parts }: { parts: NonNullable<ExecutiveKpi['breakdown']> }) {
  const total = parts.reduce((sum, part) => sum + Math.max(0, part.value), 0)
  return (
    <div className="flex h-[34px] flex-col justify-center gap-1.5" aria-label={parts.map((p) => `${p.label} ${p.value}`).join(', ')}>
      <div className="flex h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
        {total > 0 && parts.map((part) => (
          part.value > 0 ? <span key={part.label} className={BAR_TONE[part.tone]} style={{ width: `${(part.value / total) * 100}%` }} /> : null
        ))}
      </div>
      <div className="flex flex-wrap gap-x-2 gap-y-0.5 text-[8px] font-bold uppercase tracking-wide text-white/40">
        {parts.map((part) => (
          <span key={part.label} className="inline-flex items-center gap-1">
            <span className={cx('h-1.5 w-1.5 rounded-full', BAR_TONE[part.tone])} aria-hidden="true" />
            {part.label} <span className="text-white/65">{fmtNumber(part.value)}</span>
          </span>
        ))}
      </div>
    </div>
  )
}

function KpiCard({ kpi, index }: { kpi: ExecutiveKpi; index: number; key?: string | number }) {
  const reduce = useReducedMotion()
  const tone = kpiTone(kpi)
  const t = TONE[tone]
  const hasHistory = kpi.trendBasis !== 'none' && kpi.sparkline.length >= 2

  return (
    <motion.a
      href={kpi.route}
      aria-label={`${kpi.label}: ${formatValue(kpi)}${kpi.unit}. ${kpi.hint}`}
      initial={reduce ? false : { opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.03 }}
      className={cx(PANEL, 'flex flex-col p-4 no-underline outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70')}
    >
      {/* accent rail */}
      <span className={cx('absolute left-0 top-0 h-full w-[3px]', t.dot)} aria-hidden="true" />

      <div className="flex items-start justify-between gap-2">
        <span className="text-[9px] font-black uppercase leading-tight tracking-[0.12em] text-white/45">{kpi.label}</span>
        {kpi.modeled && <span className="rounded bg-white/5 px-1 py-0.5 text-[7px] font-black uppercase tracking-wide text-white/35" title="Modelled estimate — planning assumptions, not a measurement">model</span>}
      </div>

      <div className="mt-2 flex items-end gap-1.5">
        <span className={cx('text-[26px] font-black leading-none tracking-tighter', kpi.unmeasured ? 'text-white/40' : t.text)}>{formatValue(kpi)}</span>
        {!kpi.unmeasured && kpi.unit && kpi.unit !== 'USD' && <span className="mb-0.5 text-xs font-bold text-white/35">{kpi.unit}</span>}
        {kpi.level && kpi.format === 'score' && !kpi.unmeasured && <span className={cx('mb-0.5 text-[9px] font-black uppercase tracking-wide', t.text)}>{kpi.level}</span>}
      </div>

      <div className="mt-1.5">
        <DeltaBadge trend={kpi.trend} delta={kpi.deltaPercent} direction={kpi.direction} basis={kpi.trendBasis} />
      </div>

      <div className="mt-3 -mx-0.5">
        {hasHistory ? (
          <Sparkline values={kpi.sparkline} color={t.hex} />
        ) : kpi.breakdown && kpi.breakdown.length > 0 && !kpi.unmeasured ? (
          <Breakdown parts={kpi.breakdown} />
        ) : (
          <div className="flex h-[34px] items-center text-[9px] font-medium leading-snug text-white/30">
            {kpi.unmeasured ? kpi.hint : kpi.modeled ? 'Planning estimate · see assumptions' : 'Single reading · history builds with each assessment'}
          </div>
        )}
      </div>

      <div className="mt-2 flex items-center justify-between border-t border-white/5 pt-2 text-[8px] font-bold uppercase tracking-wide text-white/30">
        <span>Target: {kpi.targetLabel}</span>
        <span title={kpi.lastUpdated}>{relativeTime(kpi.lastUpdated)}</span>
      </div>

      {/* Hover analytics — what the number is and where it comes from. */}
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
