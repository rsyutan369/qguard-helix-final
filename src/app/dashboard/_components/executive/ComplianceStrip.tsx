'use client'

import { motion, useReducedMotion } from 'framer-motion'
import { ScrollText } from 'lucide-react'
import type { ExecutiveSnapshot } from '@/hooks/use-dashboard'
import { Panel, PanelHeader, RadialGauge, cx } from './primitives'

function tone(progress: number): string {
  if (progress >= 85) return '#34d399'
  if (progress >= 55) return '#fbbf24'
  if (progress > 0) return '#f87171'
  return '#475569'
}

export default function ComplianceStrip({ compliance, loading }: { compliance: ExecutiveSnapshot['compliance'] | undefined; loading: boolean }) {
  const reduce = useReducedMotion()
  if (loading && !compliance) {
    return <Panel><PanelHeader title="Compliance" icon={ScrollText} /><div className="h-56 animate-pulse rounded-lg bg-white/[0.03]" /></Panel>
  }
  const frameworks = compliance?.frameworks || []
  return (
    <Panel>
      <PanelHeader
        title="Compliance Frameworks" icon={ScrollText} href="/dashboard/compliance"
        right={<span className="text-[9px] font-black uppercase tracking-widest text-cyan-300">{compliance?.overall ?? 0}% overall</span>}
      />
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
        {frameworks.map((f, i) => (
          <motion.a
            key={f.id}
            href="/dashboard/compliance"
            initial={reduce ? false : { opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: i * 0.04 }}
            className="flex flex-col items-center rounded-lg border border-white/5 bg-white/[0.02] p-2.5 no-underline transition-colors hover:border-cyan-400/30"
          >
            <RadialGauge value={f.progress} color={tone(f.progress)} size={54} label={`${f.progress}`} />
            <div className="mt-1.5 text-center text-[9px] font-black uppercase tracking-wide text-white/75">{f.name}</div>
            <div className="mt-0.5 text-[8px] font-bold uppercase tracking-wide text-white/35">
              {f.modeled ? 'modelled' : `${f.evidenceCount} evidence`}
            </div>
            {f.missingControls > 0 && (
              <div className={cx('mt-1 rounded-full px-1.5 py-0.5 text-[7px] font-black uppercase tracking-wide', f.progress >= 55 ? 'bg-amber-500/10 text-amber-300' : 'bg-red-500/10 text-red-300')}>
                {f.missingControls} gaps
              </div>
            )}
          </motion.a>
        ))}
      </div>
    </Panel>
  )
}
