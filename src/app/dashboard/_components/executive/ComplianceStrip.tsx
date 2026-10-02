'use client'

import { motion, useReducedMotion } from 'framer-motion'
import { ScrollText } from 'lucide-react'
import type { ExecutiveSnapshot } from '@/hooks/use-dashboard'
import { Panel, PanelHeader, RadialGauge, cx, fmtNumber } from './primitives'

function tone(progress: number): string {
  if (progress >= 85) return '#34d399'
  if (progress >= 55) return '#fbbf24'
  if (progress > 0) return '#f87171'
  return '#475569'
}

/**
 * Framework compliance from the governance control model — the Compliance
 * dashboard's own numbers. Each gauge states how much of the framework was
 * actually MEASURED (coverage) and how many measured requirements are failing
 * or partially met (gaps). Nothing here is modelled from the readiness score.
 */
export default function ComplianceStrip({ compliance, loading }: { compliance: ExecutiveSnapshot['compliance'] | undefined; loading: boolean }) {
  const reduce = useReducedMotion()
  if (loading && !compliance) {
    return <Panel><PanelHeader title="Compliance" icon={ScrollText} /><div className="h-56 animate-pulse rounded-lg bg-white/[0.03]" /></Panel>
  }
  const frameworks = compliance?.frameworks || []
  const measured = Boolean(compliance?.measured) && frameworks.length > 0
  return (
    <Panel>
      <PanelHeader
        title="Compliance Frameworks" icon={ScrollText} href="/dashboard/compliance"
        right={
          <span className="text-[9px] font-black uppercase tracking-widest text-cyan-300">
            {measured ? `${compliance?.overall ?? 0}% overall` : 'Not measured'}
          </span>
        }
      />
      {!measured ? (
        <div className="flex h-40 flex-col items-center justify-center px-6 text-center">
          <ScrollText className="mb-3 h-8 w-8 text-white/20" />
          <p className="text-xs font-bold text-white/50">No framework has a measured control yet</p>
          <p className="mt-1 max-w-sm text-[10px] leading-relaxed text-white/30">
            Scores appear once scans, inventory or attested evidence cover a framework&apos;s controls. No score is
            estimated in the meantime.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
          {frameworks.map((f, i) => (
            <motion.a
              key={f.id}
              href="/dashboard/compliance"
              title={`${f.name}: ${f.progress}% over ${f.requirementsMeasured} of ${f.requirementsTotal} requirements measured · ${f.gaps} failing or partial · ${f.evidenceCount} evidence item${f.evidenceCount === 1 ? '' : 's'}`}
              initial={reduce ? false : { opacity: 0, scale: 0.96 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.04 }}
              className="flex flex-col items-center rounded-lg border border-white/5 bg-white/[0.02] p-2.5 no-underline transition-colors hover:border-cyan-400/30"
            >
              <RadialGauge value={f.progress} color={tone(f.progress)} size={54} label={`${f.progress}`} />
              <div className="mt-1.5 line-clamp-2 text-center text-[9px] font-black uppercase tracking-wide text-white/75">{f.name}</div>
              <div className="mt-0.5 text-[8px] font-bold uppercase tracking-wide text-white/35">
                {fmtNumber(f.requirementsMeasured)}/{fmtNumber(f.requirementsTotal)} measured
              </div>
              {f.gaps > 0 ? (
                <div className={cx('mt-1 rounded-full px-1.5 py-0.5 text-[7px] font-black uppercase tracking-wide', f.progress >= 55 ? 'bg-amber-500/10 text-amber-300' : 'bg-red-500/10 text-red-300')}>
                  {fmtNumber(f.gaps)} gap{f.gaps === 1 ? '' : 's'}
                </div>
              ) : (
                <div className="mt-1 rounded-full bg-emerald-500/10 px-1.5 py-0.5 text-[7px] font-black uppercase tracking-wide text-emerald-300">
                  No measured gaps
                </div>
              )}
            </motion.a>
          ))}
        </div>
      )}
    </Panel>
  )
}
