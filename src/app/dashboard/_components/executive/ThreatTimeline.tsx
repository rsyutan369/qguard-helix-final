'use client'

import { useMemo, useState } from 'react'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'
import { History, Search, AlertTriangle, ShieldAlert, Info, CheckCircle, type LucideIcon } from 'lucide-react'
import type { SecurityEvent } from '@/hooks/use-dashboard'
import { Panel, PanelHeader, cx, TONE, relativeTime, type Tone, TruncationNote} from './primitives'

const SEV_META: Record<SecurityEvent['severity'], { icon: LucideIcon; tone: Tone }> = {
  critical: { icon: AlertTriangle, tone: 'critical' },
  warning: { icon: ShieldAlert, tone: 'warning' },
  info: { icon: Info, tone: 'info' },
  success: { icon: CheckCircle, tone: 'good' },
}

const FILTERS: Array<{ key: 'all' | SecurityEvent['severity']; label: string }> = [
  { key: 'all', label: 'All' },
  { key: 'critical', label: 'Critical' },
  { key: 'warning', label: 'Warning' },
  { key: 'info', label: 'Info' },
  { key: 'success', label: 'Success' },
]

function eventHref(e: SecurityEvent): string {
  const type = `${e.eventType || ''} ${e.resourceType || ''}`.toLowerCase()
  if (e.assetId) return `/dashboard/assets?asset=${encodeURIComponent(e.assetId)}`
  if (type.includes('scan')) return '/dashboard/scanner'
  if (type.includes('runtime') || type.includes('crypto')) return '/dashboard/runtime-telemetry'
  if (type.includes('vulnerab') || type.includes('finding')) return '/dashboard/vulnerabilities'
  if (type.includes('migration')) return '/dashboard/live-migration'
  if (type.includes('cert')) return '/dashboard/certificate-telemetry'
  return '/dashboard/audit-vault'
}

export default function ThreatTimeline({ events, loading }: { events: SecurityEvent[]; loading: boolean }) {
  const reduce = useReducedMotion()
  const [filter, setFilter] = useState<'all' | SecurityEvent['severity']>('all')
  const [query, setQuery] = useState('')

  /*
   * Filter FIRST, then bound the render. Slicing before the filter would make
   * the severity tabs describe only whatever fell inside the first 60 rows,
   * so "Critical" could under-report on a busy estate.
   */
  const matching = useMemo(() => {
    const q = query.trim().toLowerCase()
    return events
      .filter((e) => filter === 'all' || e.severity === filter)
      .filter((e) => !q || `${e.message} ${e.eventType} ${e.resourceName || ''}`.toLowerCase().includes(q))
  }, [events, filter, query])
  const filtered = useMemo(() => matching.slice(0, 60), [matching])

  return (
    <Panel className="flex h-full flex-col">
      <PanelHeader title="Threat Timeline" icon={History} live={events.length > 0} />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[140px]">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-white/30" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search events…"
            className="w-full rounded-md border border-white/10 bg-white/[0.03] py-1.5 pl-7 pr-2 text-[11px] text-white/80 outline-none placeholder:text-white/25 focus:border-cyan-400/40"
          />
        </div>
        <div className="flex flex-wrap gap-1">
          {FILTERS.map((f) => (
            <button
              key={f.key}
              type="button"
              onClick={() => setFilter(f.key)}
              className={cx(
                'rounded px-2 py-1 text-[8px] font-black uppercase tracking-wide transition-colors',
                filter === f.key ? 'border border-cyan-400/40 bg-cyan-500/15 text-cyan-200' : 'border border-white/10 bg-white/[0.03] text-white/40 hover:text-white/70',
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      <div className="relative flex-1 overflow-y-auto pr-1 custom-scrollbar">
        {loading && events.length === 0 ? (
          <div className="flex h-40 items-center justify-center">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-cyan-400/30 border-t-cyan-400" />
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex h-40 flex-col items-center justify-center text-center opacity-40">
            <History className="mb-3 h-8 w-8 text-white/30" />
            <p className="text-[10px] font-black uppercase tracking-widest">No events match</p>
          </div>
        ) : (
          <div className="relative space-y-1 pl-4">
            {/* rail */}
            <span className="absolute left-[6px] top-1 bottom-1 w-px bg-white/8" aria-hidden="true" />
            <AnimatePresence initial={false}>
              {filtered.map((e, i) => {
                const meta = SEV_META[e.severity] || SEV_META.info
                const Icon = meta.icon
                const t = TONE[meta.tone]
                return (
                  <motion.a
                    key={e.id}
                    href={eventHref(e)}
                    initial={reduce ? false : { opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ delay: Math.min(i * 0.015, 0.3) }}
                    className="group/ev relative block rounded-lg py-2 pl-4 pr-2 no-underline transition-colors hover:bg-white/[0.03]"
                  >
                    <span className={cx('absolute -left-[11px] top-3 h-2.5 w-2.5 rounded-full ring-2 ring-[#0b1327]', t.dot)} aria-hidden="true" />
                    <div className="flex items-center justify-between gap-2">
                      <span className={cx('flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide', t.text)}>
                        <Icon className="h-3 w-3" />
                        {e.eventType.replace(/_/g, ' ')}
                      </span>
                      <span className="shrink-0 font-mono text-[8px] text-white/30">{relativeTime(e.timestamp)}</span>
                    </div>
                    <p className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-white/60">{e.message}</p>
                    {e.resourceName && (
                      <span className="mt-0.5 inline-block truncate text-[9px] font-bold uppercase tracking-tight text-white/30">{e.resourceType}: {e.resourceName}</span>
                    )}
                  </motion.a>
                )
              })}
            </AnimatePresence>
            <TruncationNote
              shown={filtered.length}
              total={matching.length}
              noun={filter === 'all' ? 'events' : `${filter} events`}
              rank="most recent"
            />
          </div>
        )}
      </div>
    </Panel>
  )
}
