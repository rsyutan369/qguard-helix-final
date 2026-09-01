'use client'

import { Crosshair, Radar, ShieldAlert } from 'lucide-react'
import type { ExecutiveSnapshot } from '@/hooks/use-dashboard'
import { Panel, PanelHeader, cx, fmtNumber, relativeTime, TONE, type Tone, TruncationNote} from './primitives'

export default function ThreatIntel({ intel, loading }: { intel: ExecutiveSnapshot['threatIntel'] | undefined; loading: boolean }) {
  if (loading && !intel) {
    return <Panel><PanelHeader title="Threat Intelligence" icon={Radar} /><div className="h-40 animate-pulse rounded-lg bg-white/[0.03]" /></Panel>
  }
  if (!intel) return null
  const chips: Array<{ label: string; value: number; tone: Tone }> = [
    { label: 'Shor-at-Risk', value: intel.shorAtRisk, tone: 'critical' },
    { label: 'Grover-Weakened', value: intel.groverWeakened, tone: 'warning' },
    { label: 'HNDL Signals', value: intel.hndl, tone: 'critical' },
    { label: 'Legacy Crypto', value: intel.legacyCrypto, tone: 'warning' },
    { label: 'Downgrade', value: intel.downgrade, tone: 'warning' },
    { label: 'Shadow Crypto', value: intel.shadowCrypto, tone: 'warning' },
    { label: 'KEV', value: intel.kev, tone: 'critical' },
    { label: 'CVEs', value: intel.cves, tone: 'info' },
  ]
  return (
    <Panel>
      <PanelHeader
        title="Threat Intelligence" icon={Radar} href="/dashboard/vulnerabilities"
        right={intel.epssMax > 0 ? <span className="text-[9px] font-black uppercase tracking-widest text-red-300">EPSS {intel.epssMax}%</span> : undefined}
      />
      <div className="grid grid-cols-4 gap-2">
        {chips.map((c) => {
          const t = TONE[c.tone]
          return (
            <div key={c.label} className={cx('rounded-lg border p-2 text-center', c.value > 0 ? t.border : 'border-white/5', c.value > 0 ? t.soft : 'bg-white/[0.02]')}>
              <div className={cx('text-lg font-black tracking-tighter', c.value > 0 ? t.text : 'text-white/40')}>{fmtNumber(c.value)}</div>
              <div className="mt-0.5 text-[7px] font-bold uppercase tracking-wide text-white/40">{c.label}</div>
            </div>
          )
        })}
      </div>

      <div className="mt-3 border-t border-white/5 pt-2">
        <div className="mb-1.5 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-white/45">
          <Crosshair className="h-3 w-3 text-cyan-300" /> Quantum-relevant feed
        </div>
        {intel.hasThreatFeed ? (
          <div className="space-y-1">
            {intel.feeds.slice(0, 5).map((f) => (
              <a key={f.id} href="/dashboard/vulnerabilities" className="flex items-center justify-between gap-2 rounded px-1.5 py-1 no-underline transition-colors hover:bg-white/[0.03]">
                <span className="flex min-w-0 items-center gap-1.5">
                  <ShieldAlert className={cx('h-3 w-3 shrink-0', f.severity.includes('critical') ? 'text-red-400' : 'text-amber-400')} />
                  <span className="truncate text-[11px] text-white/70">{f.title}</span>
                </span>
                <span className="shrink-0 font-mono text-[8px] text-white/30">{relativeTime(f.at)}</span>
              </a>
            ))}
            <TruncationNote
              shown={Math.min(5, intel.feeds.length)}
              total={intel.feeds.length}
              noun="intelligence feeds"
              rank="most recent"
            />
          </div>
        ) : (
          <p className="py-3 text-center text-[10px] text-white/30">
            No exploited-vulnerability feed connected. Enrichment (KEV / EPSS / MITRE) activates when a threat-intel source is integrated.
          </p>
        )}
      </div>
    </Panel>
  )
}
