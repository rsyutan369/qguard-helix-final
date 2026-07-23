import { motion } from 'framer-motion'
import { AlertTriangle, ArrowRight, Zap, Shield, Lock, FileSearch, RefreshCw, Award } from 'lucide-react'
import type { Recommendation } from '@/hooks/use-dashboard'

interface Props {
  recommendations: Recommendation[]
  loading: boolean
}

const GLASS_PANEL_CLASSES = 'qg-executive-panel group relative overflow-hidden rounded-lg text-white'

const categoryConfig: Record<string, { icon: any; color: string }> = {
  cryptography: { icon: Lock, color: 'text-red-400' },
  protocol: { icon: Shield, color: 'text-orange-400' },
  certificate: { icon: Award, color: 'text-yellow-400' },
  migration: { icon: RefreshCw, color: 'text-blue-400' },
  discovery: { icon: FileSearch, color: 'text-green-400' },
  default: { icon: Zap, color: 'text-gold' },
}

function priorityLabel(priority: number) {
  if (priority <= 1) return { label: 'Critical', color: 'text-red-500 bg-red-500/10 border-red-500/30' }
  if (priority === 2) return { label: 'High', color: 'text-orange-500 bg-orange-500/10 border-orange-500/30' }
  return { label: 'Medium', color: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30' }
}

function recommendationHref(rec: Recommendation) {
  const action = String(rec.action || '').toLowerCase()
  const category = String(rec.category || '').toLowerCase()
  let href = '/dashboard/quantum-risk-scoring'

  if (action.includes('scan') || category.includes('discover')) href = '/dashboard/scanner'
  else if (action.includes('migrat') || category.includes('migration')) href = '/dashboard/live-migration'
  else if (action.includes('cert') || category.includes('certificate')) href = '/dashboard/certificate-telemetry'
  else if (action.includes('tls') || action.includes('protocol') || category.includes('protocol')) href = '/dashboard/encryption-monitoring'
  else if (category.includes('crypto') || action.includes('key') || action.includes('algorithm')) href = '/dashboard/crypto-agility'

  if (rec.assetId && (href === '/dashboard/quantum-risk-scoring' || href === '/dashboard/crypto-agility')) {
    return `/dashboard/assets?asset=${encodeURIComponent(rec.assetId)}`
  }

  return href
}

export default function RecommendationsPanel({ recommendations, loading }: Props) {
  if (loading) {
    return (
      <div className={`p-6 ${GLASS_PANEL_CLASSES}`}>
        <h2 className="text-sm font-black uppercase tracking-[0.2em] text-white/80 mb-6">Prioritized Actions</h2>
        <div className="space-y-3">
          {Array.from({ length: 4 }, (_, index) => (
            <div key={index} className="h-20 rounded-xl border border-white/5 bg-white/[0.03] animate-pulse" />
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className={`p-6 ${GLASS_PANEL_CLASSES}`}>
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-sm font-black uppercase tracking-[0.2em] text-white/80 flex items-center gap-2">
          <Zap className="h-4 w-4 text-gold" />
          Prioritized Actions
        </h2>
        <span className="text-[10px] font-bold text-white/20 uppercase tracking-widest">API Generated</span>
      </div>

      {recommendations.length === 0 ? (
        <div className="flex min-h-[280px] flex-col items-center justify-center text-center">
          <Shield className="mb-3 h-8 w-8 text-green-500/50" />
          <p className="text-xs font-bold text-white/45">No active recommendations</p>
          <p className="mt-1 text-[10px] text-white/25">Run a scan or migration workflow to generate prioritized actions.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-1 gap-4 max-h-[420px] overflow-y-auto pr-1">
          {recommendations.slice(0, 6).map((rec, index) => {
            const config = categoryConfig[rec.category] || categoryConfig.default
            const Icon = config.icon
            const priority = priorityLabel(rec.priority)

            return (
              <motion.a
                key={rec.id}
                href={recommendationHref(rec)}
                aria-label={`Open action ${rec.title}`}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.05 }}
                className="block p-4 rounded-xl bg-white/[0.02] border border-white/5 hover:border-gold/30 hover:bg-gold/[0.04] transition-all group no-underline outline-none focus-visible:ring-2 focus-visible:ring-gold/70"
              >
                <div className="flex gap-4">
                  <div className={`mt-1 shrink-0 ${config.color}`}>
                    <Icon className="h-5 w-5" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="mb-2 flex flex-wrap items-center gap-2">
                      <span className={`rounded border px-1.5 py-0.5 text-[9px] font-black uppercase ${priority.color}`}>
                        {priority.label}
                      </span>
                      <span className="text-[9px] text-white/30 uppercase font-bold">{rec.category}</span>
                    </div>
                    <h3 className="text-xs font-black uppercase tracking-wider text-white group-hover:text-gold transition-colors mb-1">
                      {rec.title}
                    </h3>
                    <p className="text-[11px] text-white/40 leading-relaxed mb-3">{rec.description}</p>
                    <div className="flex items-center gap-3 text-[10px] font-black uppercase tracking-widest text-gold/70">
                      <span>Effort: {rec.estimatedEffort}</span>
                      <span className="flex items-center gap-1 group-hover:text-gold">
                        {rec.action.replace(/_/g, ' ')} <ArrowRight className="w-3 h-3" />
                      </span>
                    </div>
                  </div>
                </div>
              </motion.a>
            )
          })}
        </div>
      )}
    </div>
  )
}
