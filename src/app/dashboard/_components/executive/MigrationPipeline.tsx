'use client'

import { motion, useReducedMotion } from 'framer-motion'
import { GitBranch, ArrowRight } from 'lucide-react'
import type { ExecutiveSnapshot } from '@/hooks/use-dashboard'
import { Panel, PanelHeader, Bar, cx, fmtNumber } from './primitives'

const STAGE_COLOR = ['#22d3ee', '#38bdf8', '#818cf8', '#a78bfa', '#34d399', '#10b981']

export default function MigrationPipeline({ pipeline, loading }: { pipeline: ExecutiveSnapshot['pipeline'] | undefined; loading: boolean }) {
  const reduce = useReducedMotion()
  if (loading && !pipeline) {
    return <Panel><PanelHeader title="Migration Pipeline" icon={GitBranch} /><div className="h-56 animate-pulse rounded-lg bg-white/[0.03]" /></Panel>
  }
  const stages = pipeline?.stages || []
  return (
    <Panel>
      <PanelHeader
        title="Migration Pipeline" icon={GitBranch} href="/dashboard/migration-planner"
        right={<span className="text-[9px] font-black uppercase tracking-widest text-cyan-300">{pipeline?.overallCompletion ?? 0}% complete</span>}
      />
      <div className="space-y-3">
        {stages.map((s, i) => (
          <motion.div
            key={s.key}
            initial={reduce ? false : { opacity: 0, x: -12 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.05 }}
          >
            <div className="mb-1 flex items-center justify-between">
              <span className="flex items-center gap-2 text-[11px] font-bold text-white/75">
                <span className="text-[8px] font-mono text-white/25">{String(i + 1).padStart(2, '0')}</span>
                {s.label}
              </span>
              <span className="flex items-center gap-2 text-[10px]">
                <span className="font-black text-white">{s.completion}%</span>
                <span className="text-white/30">{fmtNumber(s.remaining)} left</span>
              </span>
            </div>
            <Bar value={s.completion} color={STAGE_COLOR[i % STAGE_COLOR.length]} />
          </motion.div>
        ))}
      </div>

      <div className="mt-4 grid grid-cols-3 gap-2 border-t border-white/5 pt-3">
        <Metric label="Remaining Assets" value={fmtNumber(pipeline?.remainingAssets || 0)} />
        <Metric label="Est. Finish" value={pipeline?.estimatedFinishWeeks ? `${pipeline.estimatedFinishWeeks} wks` : 'On track'} />
        <Metric label="Bottleneck" value={pipeline?.bottleneck || '—'} tone="warning" />
      </div>
    </Panel>
  )
}

function Metric({ label, value, tone }: { label: string; value: string; tone?: 'warning' }) {
  return (
    <div>
      <div className="text-[8px] font-bold uppercase tracking-wide text-white/35">{label}</div>
      <div className={cx('mt-0.5 truncate text-xs font-black', tone === 'warning' ? 'text-amber-400' : 'text-white/85')}>{value}</div>
    </div>
  )
}
