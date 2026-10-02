'use client'

import { motion, useReducedMotion } from 'framer-motion'
import { Sparkles, ArrowRight, ShieldCheck, Gauge } from 'lucide-react'
import type { ExecutiveSnapshot } from '@/hooks/use-dashboard'
import { PANEL, TONE, cx, relativeTime, type Tone } from './primitives'

interface Props {
  narrative: ExecutiveSnapshot['narrative'] | undefined
  userName?: string | null
  loading: boolean
}

function greeting(): string {
  const h = new Date().getHours()
  if (h < 12) return 'Good morning'
  if (h < 18) return 'Good afternoon'
  return 'Good evening'
}

/* Keyed by the platform's readiness bands (`levelFromReadiness`). The old keys
   ("Early", "Strong", "Moderate") matched none of them, so every posture
   rendered in the neutral tone whatever its band. */
const POSTURE_TONE: Record<string, Tone> = {
  'Quantum-Ready': 'good', Advanced: 'good', Developing: 'warning', 'Early Stage': 'warning', Initial: 'critical', 'Not Started': 'neutral',
}

export default function ExecutiveSummary({ narrative, userName, loading }: Props) {
  const reduce = useReducedMotion()

  if (loading && !narrative) {
    return (
      <div className={cx(PANEL, 'p-6')}>
        <div className="h-5 w-40 animate-pulse rounded bg-white/10" />
        <div className="mt-4 h-4 w-2/3 animate-pulse rounded bg-white/5" />
        <div className="mt-6 grid grid-cols-2 gap-3 md:grid-cols-6">
          {Array.from({ length: 6 }).map((_, i) => <div key={i} className="h-16 animate-pulse rounded-lg bg-white/[0.04]" />)}
        </div>
      </div>
    )
  }

  const n = narrative
  const postureTone = POSTURE_TONE[n?.posture || ''] || 'neutral'
  const pt = TONE[postureTone]
  const priorityTone = TONE[(n?.priority.severity === 'critical' ? 'critical' : n?.priority.severity === 'high' ? 'warning' : n?.priority.severity === 'low' ? 'good' : 'info') as Tone]

  return (
    <motion.div
      initial={reduce ? false : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className={cx(PANEL, 'p-6')}
    >
      {/* Ambient AI aura */}
      <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-[radial-gradient(circle,rgba(124,58,237,0.18),transparent_70%)]" aria-hidden="true" />
      <div className="pointer-events-none absolute -bottom-20 left-1/3 h-48 w-48 rounded-full bg-[radial-gradient(circle,rgba(6,182,212,0.12),transparent_70%)]" aria-hidden="true" />

      <div className="relative z-10 flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
        <div className="max-w-2xl">
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-violet-500/25 bg-violet-500/10 px-3 py-1">
            <Sparkles className="h-3 w-3 text-violet-300" />
            <span className="text-[9px] font-black uppercase tracking-[0.2em] text-violet-200">Sophia · Executive Briefing</span>
          </div>
          <h1 className="text-2xl font-black leading-tight tracking-tight text-white md:text-[28px]">
            {greeting()}{userName ? <>, <span className="text-cyan-300">{userName}</span></> : ''}
          </h1>
          <p className="mt-2 text-sm leading-relaxed text-white/60">{n?.summary}</p>

          {n?.priority && (
            <a
              href={n.priority.route}
              className={cx('mt-4 inline-flex max-w-full items-center gap-3 rounded-lg border px-4 py-2.5 no-underline transition-colors', priorityTone.border, priorityTone.soft, 'hover:border-cyan-400/40')}
            >
              <span className={cx('shrink-0 text-[8px] font-black uppercase tracking-widest', priorityTone.text)}>Priority</span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-xs font-black uppercase tracking-wide text-white">{n.priority.title}</span>
                <span className="block truncate text-[11px] text-white/50">{n.priority.detail}</span>
              </span>
              <ArrowRight className="h-4 w-4 shrink-0 text-cyan-300" />
            </a>
          )}
        </div>

        {/* Posture dial */}
        <div className="flex shrink-0 items-center gap-5 rounded-xl border border-white/8 bg-white/[0.02] p-4">
          <div className="text-center">
            <div className={cx('flex items-center justify-center gap-1.5 text-[8px] font-black uppercase tracking-widest', pt.text)}>
              <ShieldCheck className="h-3 w-3" /> Readiness
            </div>
            <div className={cx('mt-1 text-4xl font-black tracking-tighter', pt.text)}>{n?.readinessScore ?? '--'}</div>
            <div className="text-[9px] font-bold uppercase tracking-wide text-white/45">{n?.posture || 'No baseline'}</div>
          </div>
          <div className="h-12 w-px bg-white/10" />
          <div className="text-center">
            <div className="flex items-center justify-center gap-1.5 text-[8px] font-black uppercase tracking-widest text-white/50">
              <Gauge className="h-3 w-3" /> Risk
            </div>
            <div className="mt-1 text-4xl font-black tracking-tighter text-white">{n?.riskScore ?? '--'}<span className="text-lg text-white/35">/100</span></div>
            <div className="text-[9px] font-bold uppercase tracking-wide text-white/45">{n?.riskLevel || '—'}</div>
          </div>
        </div>
      </div>

      {/* Fact strip */}
      <div className="relative z-10 mt-6 grid grid-cols-2 gap-3 border-t border-white/8 pt-5 sm:grid-cols-3 md:grid-cols-6">
        {(n?.facts || []).map((f, i) => {
          const tone = TONE[(f.tone === 'good' ? 'good' : f.tone === 'critical' ? 'critical' : f.tone === 'warning' ? 'warning' : 'neutral') as Tone]
          const value = f.format === 'relative-time' ? (typeof f.value === 'string' && f.value !== 'Never' ? relativeTime(f.value) : 'Never') : f.value
          return (
            <motion.div
              key={f.id}
              title={f.hint}
              initial={reduce ? false : { opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 + i * 0.05 }}
            >
              <div className="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-wide text-white/40">
                {f.label}
                {f.modeled && <span className="rounded bg-white/5 px-1 py-px text-[7px] font-black tracking-wide text-white/35">model</span>}
              </div>
              <div className={cx('mt-1 text-base font-black tracking-tight', tone.text)}>{value}</div>
              {f.hint && <div className="mt-0.5 truncate text-[9px] text-white/30">{f.hint}</div>}
            </motion.div>
          )
        })}
      </div>

      {n && (
        <div className="relative z-10 mt-4 flex flex-wrap items-center gap-x-2 gap-y-1 text-[9px] font-bold uppercase tracking-widest text-white/30">
          <span className="h-1 w-1 rounded-full bg-violet-400" />
          <span>
            Evidence coverage {n.evidenceCoverage.present} of {n.evidenceCoverage.total} sources
          </span>
          {n.evidenceCoverage.missing.length > 0 && (
            <span className="normal-case tracking-normal text-white/25">
              · missing {n.evidenceCoverage.missing.join(', ')}
            </span>
          )}
          <span>· generated from tenant telemetry only</span>
        </div>
      )}
    </motion.div>
  )
}
