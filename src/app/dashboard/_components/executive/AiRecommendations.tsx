'use client'

import { motion, useReducedMotion } from 'framer-motion'
import { Sparkles, Lock, Shield, Award, RefreshCw, FileSearch, Zap, ArrowRight, Settings2, type LucideIcon } from 'lucide-react'
import type { Recommendation } from '@/hooks/use-dashboard'
import { Panel, PanelHeader, cx, TruncationNote } from './primitives'

const CATEGORY: Record<string, { icon: LucideIcon; tint: string; label: string }> = {
  cryptography: { icon: Lock, tint: 'text-red-400', label: 'Cryptography' },
  protocol: { icon: Shield, tint: 'text-amber-400', label: 'Protocol' },
  configuration: { icon: Settings2, tint: 'text-sky-300', label: 'Configuration' },
  certificate: { icon: Award, tint: 'text-yellow-400', label: 'Certificate' },
  migration: { icon: RefreshCw, tint: 'text-blue-400', label: 'Migration' },
  discovery: { icon: FileSearch, tint: 'text-emerald-400', label: 'Discovery' },
  default: { icon: Zap, tint: 'text-cyan-300', label: 'Action' },
}

/** 1 critical · 2 high · 3 medium · 4 low — the recorded severity, never rounded up. */
function priorityMeta(priority: number) {
  if (priority <= 1) return { label: 'Critical', cls: 'text-red-400 bg-red-500/10 border-red-500/30' }
  if (priority === 2) return { label: 'High', cls: 'text-amber-400 bg-amber-500/10 border-amber-500/30' }
  if (priority === 3) return { label: 'Medium', cls: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30' }
  return { label: 'Low', cls: 'text-sky-300 bg-sky-500/10 border-sky-500/30' }
}

function actionRoute(rec: Recommendation): string {
  const action = String(rec.action || '').toLowerCase()
  const category = String(rec.category || '').toLowerCase()
  if (action.startsWith('/')) return action
  if (action.includes('scan') || category.includes('discover')) return '/dashboard/scanner'
  if (action.includes('cert') || category.includes('certificate')) return '/dashboard/certificate-telemetry'
  if (action.includes('migrat') || category.includes('migration')) return '/dashboard/migration-planner'
  if (action.includes('tls') || action.includes('protocol') || category.includes('protocol')) return '/dashboard/encryption-monitoring'
  if (action.includes('runtime')) return '/dashboard/runtime-telemetry'
  if (rec.assetId) return `/dashboard/assets?asset=${encodeURIComponent(rec.assetId)}`
  return '/dashboard/crypto-agility'
}

const ACTION_LABEL: Record<string, string> = {
  start_migration: 'Plan migration',
  upgrade_tls: 'Review TLS',
  harden_configuration: 'Open asset',
  transition_certificate: 'Certificate estate',
  renew_certificate: 'Renew certificate',
  review_migration: 'Review job',
  review_scanner_alert: 'Review alert',
  inspect_runtime_telemetry: 'Inspect telemetry',
  review_finding: 'Review finding',
  start_scan: 'Run scan',
}

const SHOWN = 6

export default function AiRecommendations({ recommendations, total, loading }: { recommendations: Recommendation[]; total?: number; loading: boolean }) {
  const reduce = useReducedMotion()
  const derived = Math.max(total ?? 0, recommendations.length)
  return (
    <Panel className="flex h-full flex-col">
      <PanelHeader
        title="AI Recommendations" icon={Sparkles} tone="ai"
        /* Ranked by the severity of the findings each action closes, then by how
           many it closes. It used to say "Sophia-ranked" — no model ranks this
           list, and the label claimed one did. */
        right={<span className="text-[9px] font-black uppercase tracking-widest text-violet-300" title="Ordered by the worst severity each action closes, then by how many findings it closes">Ranked by severity</span>}
      />
      {loading && recommendations.length === 0 ? (
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-24 animate-pulse rounded-lg border border-white/5 bg-white/[0.03]" />)}
        </div>
      ) : recommendations.length === 0 ? (
        /* ABSENCE IS NOT SAFETY (§43).
           This used to render a GREEN shield asserting that the estate's
           posture was fine — a verdict about the tenant, produced from the fact
           that this one panel had nothing to show. It was displayed on a tenant
           whose own engine held four recommended actions, one of them critical.
           An empty list means no action was DERIVED; it is not evidence that
           none is needed, and it is never a pass. Slate, not emerald, and no
           verdict. Guarded by tools/estate-workflow-check.ts. */
        <div className="flex flex-1 flex-col items-center justify-center text-center">
          <Shield className="mb-3 h-8 w-8 text-slate-500/50" />
          <p className="text-xs font-bold text-white/50">No recommended actions derived</p>
          <p className="mt-1 max-w-[15rem] text-[10px] leading-relaxed text-white/25">
            This is not an assessment of your posture. Actions appear once a scan or integration produces evidence to
            derive them from.
          </p>
        </div>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col">
          <div className="min-h-0 flex-1 space-y-2.5 overflow-y-auto pr-1 custom-scrollbar">
            {recommendations.slice(0, SHOWN).map((rec, i) => {
              const cfg = CATEGORY[rec.category] || CATEGORY.default
              const Icon = cfg.icon
              const p = priorityMeta(rec.priority)
              const findings = rec.findingCount ?? 0
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
                        <span className="text-[8px] font-bold uppercase tracking-wide text-white/30">{CATEGORY[rec.category]?.label || rec.category}</span>
                      </div>
                      <h3 className="line-clamp-2 text-[12px] font-black leading-snug tracking-wide text-white" title={rec.title}>{rec.title}</h3>
                      <p className="mt-1 line-clamp-2 text-[11px] leading-snug text-white/45" title={rec.description}>{rec.description}</p>

                      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[9px] font-bold uppercase tracking-wide text-white/40">
                        {findings > 0 && (
                          <span>{rec.source === 'findings' ? 'Closes' : 'Signals'}: <span className="text-white/70">{findings}</span></span>
                        )}
                        <span title="Planning heuristic by category — not a measured effort">Est. effort: <span className="text-white/70">{rec.estimatedEffort || 'medium'}</span></span>
                      </div>

                      <a
                        href={actionRoute(rec)}
                        className="mt-2.5 inline-flex items-center gap-1.5 rounded-md border border-violet-400/30 bg-violet-500/10 px-2.5 py-1.5 text-[9px] font-black uppercase tracking-widest text-violet-200 no-underline transition-colors hover:bg-violet-500/20"
                      >
                        {ACTION_LABEL[String(rec.action || '')] || String(rec.action || 'Resolve').replace(/^\/dashboard\//, '').replace(/[_/-]+/g, ' ')} <ArrowRight className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                </motion.div>
              )
            })}
          </div>
          {/* One disclosure for the whole list — it used to sit inside every card. */}
          <TruncationNote shown={Math.min(SHOWN, recommendations.length)} total={derived} noun="recommended actions" rank="highest-priority" />
        </div>
      )}
    </Panel>
  )
}
