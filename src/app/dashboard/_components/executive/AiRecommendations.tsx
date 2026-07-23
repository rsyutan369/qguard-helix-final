'use client'

import { motion, useReducedMotion } from 'framer-motion'
import { Sparkles, Lock, Shield, Award, RefreshCw, FileSearch, Zap, ArrowRight, Clock, type LucideIcon } from 'lucide-react'
import type { Recommendation } from '@/hooks/use-dashboard'
import { Panel, PanelHeader, cx } from './primitives'

const CATEGORY: Record<string, { icon: LucideIcon; tint: string }> = {
  cryptography: { icon: Lock, tint: 'text-red-400' },
  protocol: { icon: Shield, tint: 'text-amber-400' },
  certificate: { icon: Award, tint: 'text-yellow-400' },
  migration: { icon: RefreshCw, tint: 'text-blue-400' },
  discovery: { icon: FileSearch, tint: 'text-emerald-400' },
  default: { icon: Zap, tint: 'text-cyan-300' },
}

function priorityMeta(priority: number) {
  if (priority <= 1) return { label: 'Critical', cls: 'text-red-400 bg-red-500/10 border-red-500/30', impact: 'High' }
  if (priority === 2) return { label: 'High', cls: 'text-amber-400 bg-amber-500/10 border-amber-500/30', impact: 'High' }
  return { label: 'Medium', cls: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30', impact: 'Moderate' }
}

// Planning estimates (disclosed), not measured durations.
const EFFORT_TIME: Record<string, string> = { low: '~45 min', medium: '~4 hrs', high: '~2 days' }

function actionRoute(rec: Recommendation): string {
  const action = String(rec.action || '').toLowerCase()
  const category = String(rec.category || '').toLowerCase()
  if (action.includes('scan') || category.includes('discover')) return '/dashboard/scanner'
  if (action.includes('migrat') || category.includes('migration')) return '/dashboard/live-migration'
  if (action.includes('cert') || category.includes('certificate')) return '/dashboard/certificate-telemetry'
  if (action.includes('tls') || action.includes('protocol') || category.includes('protocol')) return '/dashboard/encryption-monitoring'
  if (rec.assetId) return `/dashboard/assets?asset=${encodeURIComponent(rec.assetId)}`
  return '/dashboard/crypto-agility'
}

export default function AiRecommendations({ recommendations, loading }: { recommendations: Recommendation[]; loading: boolean }) {
  const reduce = useReducedMotion()
  return (
    <Panel className="flex h-full flex-col">
      <PanelHeader
        title="AI Recommendations" icon={Sparkles} tone="ai"
        right={<span className="text-[9px] font-black uppercase tracking-widest text-violet-300">Sophia-ranked</span>}
      />
      {loading && recommendations.length === 0 ? (
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-24 animate-pulse rounded-lg border border-white/5 bg-white/[0.03]" />)}
        </div>
      ) : recommendations.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center text-center">
          <Shield className="mb-3 h-8 w-8 text-emerald-400/50" />
          <p className="text-xs font-bold text-white/50">No active recommendations</p>
          <p className="mt-1 text-[10px] text-white/25">Your posture is stable. New actions appear as telemetry arrives.</p>
        </div>
      ) : (
        <div className="flex-1 space-y-2.5 overflow-y-auto pr-1 custom-scrollbar">
          {recommendations.slice(0, 6).map((rec, i) => {
            const cfg = CATEGORY[rec.category] || CATEGORY.default
            const Icon = cfg.icon
            const p = priorityMeta(rec.priority)
            const time = EFFORT_TIME[String(rec.estimatedEffort || '').toLowerCase()] || '~1 day'
            return (
              <motion.div
                key={rec.id}
                initial={reduce ? false : { opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
                className="rounded-lg border border-white/5 bg-white/[0.02] p-3 transition-colors hover:border-violet-400/25 hover:bg-violet-500/[0.03]"
              >
                <div className="flex items-start gap-3">
                  <div className={cx('mt-0.5 shrink-0', cfg.tint)}><Icon className="h-4 w-4" /></div>
                  <div className="min-w-0 flex-1">
                    <div className="mb-1 flex flex-wrap items-center gap-1.5">
                      <span className={cx('rounded border px-1.5 py-0.5 text-[8px] font-black uppercase', p.cls)}>{p.label}</span>
                      <span className="text-[8px] font-bold uppercase tracking-wide text-white/30">{rec.category}</span>
                    </div>
                    <h3 className="text-[12px] font-black uppercase leading-tight tracking-wide text-white">{rec.title}</h3>
                    <p className="mt-1 line-clamp-2 text-[11px] leading-snug text-white/45">{rec.description}</p>

                    <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[9px] font-bold uppercase tracking-wide text-white/40">
                      <span>Risk: <span className="text-white/70">{p.label}</span></span>
                      <span>Impact: <span className="text-white/70">{p.impact}</span></span>
                      <span>Effort: <span className="text-white/70">{rec.estimatedEffort || 'medium'}</span></span>
                      <span className="inline-flex items-center gap-0.5"><Clock className="h-2.5 w-2.5" /> {time}</span>
                    </div>

                    <a
                      href={actionRoute(rec)}
                      className="mt-2.5 inline-flex items-center gap-1.5 rounded-md border border-violet-400/30 bg-violet-500/10 px-2.5 py-1.5 text-[9px] font-black uppercase tracking-widest text-violet-200 no-underline transition-colors hover:bg-violet-500/20"
                    >
                      {String(rec.action || 'Resolve').replace(/_/g, ' ')} <ArrowRight className="h-3 w-3" />
                    </a>
                  </div>
                </div>
              </motion.div>
            )
          })}
        </div>
      )}
    </Panel>
  )
}
