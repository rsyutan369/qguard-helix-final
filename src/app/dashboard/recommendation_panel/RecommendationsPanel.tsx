import { motion } from 'framer-motion'
import { AlertTriangle, ArrowRight, Zap, Shield, Lock, FileSearch, RefreshCw, Award } from 'lucide-react'
import type { Recommendation } from '@/hooks/use-dashboard'

interface Props {
  recommendations: Recommendation[]
  loading: boolean
}

const GLASS_PANEL_CLASSES = 'group relative overflow-hidden rounded-xl border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] group-hover:before:via-[#FFF4C0] after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-[#FFD36B]/25 group-hover:after:blur-[36px] text-white'

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
              <motion.div
                key={rec.id}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.05 }}
                className="p-4 rounded-xl bg-white/[0.02] border border-white/5 hover:border-gold/20 transition-all group"
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
              </motion.div>
            )
          })}
        </div>
      )}
    </div>
  )
}
