'use client'

import type { ReactNode } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { TrendingUp, TrendingDown, Minus, type LucideIcon } from 'lucide-react'

/* ------------------------------------------------------------------ */
/* Shared design primitives for the Quantum Security Command Center.   */
/* Consistent with the platform theme: qg-executive-panel glass,       */
/* navy base, cyan/violet accents, mission-control typography.         */
/* ------------------------------------------------------------------ */

export const PANEL = 'qg-executive-panel group relative overflow-hidden rounded-xl text-white'

export type Tone = 'critical' | 'warning' | 'good' | 'neutral' | 'ai' | 'info'

export const TONE: Record<Tone, { text: string; hex: string; soft: string; border: string; dot: string }> = {
  critical: { text: 'text-red-400', hex: '#f87171', soft: 'bg-red-500/10', border: 'border-red-500/25', dot: 'bg-red-500' },
  warning: { text: 'text-amber-400', hex: '#fbbf24', soft: 'bg-amber-500/10', border: 'border-amber-500/25', dot: 'bg-amber-500' },
  good: { text: 'text-emerald-400', hex: '#34d399', soft: 'bg-emerald-500/10', border: 'border-emerald-500/25', dot: 'bg-emerald-500' },
  neutral: { text: 'text-cyan-300', hex: '#22d3ee', soft: 'bg-cyan-500/10', border: 'border-cyan-500/25', dot: 'bg-cyan-400' },
  info: { text: 'text-blue-300', hex: '#60a5fa', soft: 'bg-blue-500/10', border: 'border-blue-500/25', dot: 'bg-blue-400' },
  ai: { text: 'text-violet-300', hex: '#a78bfa', soft: 'bg-violet-500/10', border: 'border-violet-500/25', dot: 'bg-violet-400' },
}

export function cx(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(' ')
}

export function fmtNumber(value: number): string {
  return new Intl.NumberFormat('en-US').format(Math.round(value || 0))
}

export function fmtCompact(value: number): string {
  const v = value || 0
  if (Math.abs(v) >= 1000) return new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(v)
  return fmtNumber(v)
}

export function fmtCurrency(value: number): string {
  const v = value || 0
  if (Math.abs(v) >= 1000) {
    return '$' + new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(v)
  }
  return '$' + fmtNumber(v)
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return 'awaiting sync'
  const then = new Date(iso).getTime()
  if (!Number.isFinite(then)) return 'awaiting sync'
  const diff = Date.now() - then
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return `${Math.floor(diff / 86400000)}d ago`
}

/* ---- Panel + header ---------------------------------------------- */

export function Panel({ children, className, href, label }: { children: ReactNode; className?: string; href?: string; label?: string; key?: string | number }) {
  const classes = cx(
    PANEL,
    'p-5 no-underline outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70 focus-visible:ring-offset-2 focus-visible:ring-offset-[#0a1020]',
    className,
  )
  if (href) {
    return (
      <a href={href} aria-label={label} className={cx(classes, 'block transition-transform')}>
        {children}
      </a>
    )
  }
  return <div className={classes}>{children}</div>
}

export function PanelHeader({
  title, icon: Icon, live, right, href, tone = 'neutral',
}: {
  title: string
  icon?: LucideIcon
  live?: boolean
  right?: ReactNode
  href?: string
  tone?: Tone
}) {
  const t = TONE[tone]
  const heading = (
    <span className={cx('flex items-center gap-2 text-[11px] font-black uppercase tracking-[0.16em] text-white/85', href && 'transition-colors group-hover:text-cyan-300')}>
      {Icon && <Icon className={cx('h-3.5 w-3.5', t.text)} />}
      <span className="truncate">{title}</span>
    </span>
  )
  return (
    <div className="mb-4 flex items-center justify-between gap-3">
      {href ? <a href={href} className="no-underline">{heading}</a> : heading}
      <div className="flex items-center gap-2">
        {right}
        {live !== undefined && (
          <span className={cx('flex items-center gap-1.5 text-[8px] font-black uppercase tracking-widest', live ? 'text-emerald-400' : 'text-white/30')}>
            <span className={cx('h-1.5 w-1.5 rounded-full', live ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)] animate-pulse' : 'bg-white/25')} />
            {live ? 'Live' : 'Idle'}
          </span>
        )}
      </div>
    </div>
  )
}

/* ---- Delta badge ------------------------------------------------- */

export function DeltaBadge({ trend, delta, direction }: { trend: 'up' | 'down' | 'flat'; delta: number; direction: 'lower-better' | 'higher-better' }) {
  if (trend === 'flat' || delta === 0) {
    return (
      <span className="inline-flex items-center gap-0.5 text-[9px] font-black uppercase tracking-wide text-white/35">
        <Minus className="h-2.5 w-2.5" /> stable
      </span>
    )
  }
  // "Improved" when the movement is in the beneficial direction.
  const improving = direction === 'lower-better' ? trend === 'down' : trend === 'up'
  const Icon = trend === 'down' ? TrendingDown : TrendingUp
  return (
    <span className={cx('inline-flex items-center gap-0.5 text-[9px] font-black uppercase tracking-wide', improving ? 'text-emerald-400' : 'text-red-400')}>
      <Icon className="h-2.5 w-2.5" />
      {improving ? 'Improved' : 'Worse'} {delta}%
    </span>
  )
}

/* ---- Sparkline (real series only) -------------------------------- */

export function Sparkline({ values, color = '#22d3ee', height = 34, fill = true }: { values: number[]; color?: string; height?: number; fill?: boolean }) {
  if (!values || values.length < 2) {
    return <div className="flex h-[34px] items-center text-[9px] font-mono uppercase tracking-widest text-white/20">no trend series</div>
  }
  const w = 120
  const h = height
  const max = Math.max(1, ...values)
  const min = Math.min(0, ...values)
  const range = max - min || 1
  const pts = values.map((v, i) => {
    const x = values.length === 1 ? w : (i / (values.length - 1)) * w
    const y = h - 3 - ((v - min) / range) * (h - 6)
    return [x, y] as const
  })
  const line = pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ')
  const area = `${line} ${w},${h} 0,${h}`
  const gid = `spark-${color.replace('#', '')}`
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-[34px] w-full overflow-visible" preserveAspectRatio="none" aria-hidden="true">
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.28" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {fill && <polygon points={area} fill={`url(#${gid})`} />}
      <polyline points={line} fill="none" stroke={color} strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
      <circle cx={pts[pts.length - 1][0]} cy={pts[pts.length - 1][1]} r="2" fill={color} />
    </svg>
  )
}

/* ---- Radial gauge ------------------------------------------------ */

export function RadialGauge({ value, color = '#22d3ee', size = 72, label, sublabel }: { value: number; color?: string; size?: number; label?: string; sublabel?: string }) {
  const v = Math.max(0, Math.min(100, value))
  const stroke = 4
  const r = 18 - stroke / 2
  const c = 2 * Math.PI * r
  const reduce = useReducedMotion()
  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg viewBox="0 0 36 36" className="-rotate-90" width={size} height={size}>
        <circle cx="18" cy="18" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={stroke} />
        <motion.circle
          cx="18" cy="18" r={r} fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round"
          strokeDasharray={c}
          initial={reduce ? false : { strokeDashoffset: c }}
          animate={{ strokeDashoffset: c - (v / 100) * c }}
          transition={{ duration: reduce ? 0 : 0.9, ease: 'easeOut' }}
        />
      </svg>
      <div className="absolute flex flex-col items-center justify-center text-center leading-none">
        {label && <span className="text-sm font-black text-white">{label}</span>}
        {sublabel && <span className="mt-0.5 text-[7px] font-bold uppercase tracking-widest text-white/45">{sublabel}</span>}
      </div>
    </div>
  )
}

/* ---- Animated count ---------------------------------------------- */

export function CountUp({ value, className }: { value: number | string; className?: string }) {
  return <span className={className}>{typeof value === 'number' ? fmtCompact(value) : value}</span>
}

/* ---- Progress bar ------------------------------------------------ */

export function Bar({ value, color = '#22d3ee', height = 6 }: { value: number; color?: string; height?: number }) {
  const reduce = useReducedMotion()
  const v = Math.max(0, Math.min(100, value))
  return (
    <div className="w-full overflow-hidden rounded-full bg-white/10" style={{ height }}>
      <motion.div
        className="h-full rounded-full"
        style={{ backgroundColor: color }}
        initial={reduce ? false : { width: 0 }}
        animate={{ width: `${v}%` }}
        transition={{ duration: reduce ? 0 : 0.7, ease: 'easeOut' }}
      />
    </div>
  )
}

/* ---- Section heading (between rows) ------------------------------ */

/**
 * Discloses that a panel is showing only the head of a longer list.
 *
 * Renders nothing when the list fits. `rank` names WHY these are the ones
 * shown — "showing 6 of 40" without an ordering still misleads, because the
 * reader assumes the six that matter most are the six present.
 */
export function TruncationNote({
  shown, total, noun, rank,
}: { shown: number; total: number; noun: string; rank?: string }) {
  if (!Number.isFinite(total) || total <= shown) return null
  return (
    <div className="pt-2 text-[9px] font-bold uppercase tracking-wider text-white/30">
      Showing {rank ? `the ${fmtNumber(shown)} ${rank}` : fmtNumber(shown)} of {fmtNumber(total)} {noun}
    </div>
  )
}

export function SectionLabel({ children, href, meta }: { children: ReactNode; href?: string; meta?: ReactNode }) {
  const inner = (
    <span className="flex items-center gap-2 text-[11px] font-black uppercase tracking-[0.22em] text-white/55">
      {children}
    </span>
  )
  return (
    <div className="flex items-center justify-between px-1">
      {href ? <a href={href} className="no-underline transition-colors hover:text-cyan-300">{inner}</a> : inner}
      {meta && <span className="text-[9px] font-mono uppercase tracking-widest text-white/25">{meta}</span>}
    </div>
  )
}
