'use client'

import { Crosshair, Radar, ShieldAlert } from 'lucide-react'
import type { ExecutiveSnapshot } from '@/hooks/use-dashboard'
import { Panel, PanelHeader, cx, fmtNumber, relativeTime, TONE, type Tone, TruncationNote} from './primitives'

export default function ThreatIntel({ intel, loading, runtimeMeasured }: { intel: ExecutiveSnapshot['threatIntel'] | undefined; loading: boolean; runtimeMeasured?: boolean }) {
  if (loading && !intel) {
    return <Panel><PanelHeader title="Threat Intelligence" icon={Radar} /><div className="h-40 animate-pulse rounded-lg bg-white/[0.03]" /></Panel>
  }
  if (!intel) return null
  /* Runtime-sourced tiles (HNDL / legacy / downgrade / shadow) are only a
     measurement when a collector reports runtime events. Without one they read
     "—", never a reassuring 0. */
  const runtime = runtimeMeasured !== false
  const chips: Array<{ label: string; value: number; tone: Tone; measured: boolean; title: string }> = [
    { label: 'Shor-at-Risk', value: intel.shorAtRisk, tone: 'critical', measured: true, title: 'Quantum-vulnerable CBOM components whose primitive (RSA, ECC, DH) is broken outright by Shor’s algorithm' },
    { label: 'Grover-Weakened', value: intel.groverWeakened, tone: 'warning', measured: true, title: 'Symmetric or hash primitives left below the 128-bit post-quantum margin (e.g. AES-128, SHA-1)' },
    { label: 'HNDL Signals', value: intel.hndl, tone: 'critical', measured: runtime, title: 'Runtime events flagged harvest-now-decrypt-later' },
    { label: 'Legacy Crypto', value: intel.legacyCrypto, tone: 'warning', measured: runtime, title: 'Runtime events using legacy cryptography' },
    { label: 'Downgrade', value: intel.downgrade, tone: 'warning', measured: runtime, title: 'Runtime protocol-downgrade detections' },
    { label: 'Shadow Crypto', value: intel.shadowCrypto, tone: 'warning', measured: runtime, title: 'Runtime cryptography outside the inventory' },
    { label: 'KEV', value: intel.kev, tone: 'critical', measured: true, title: 'Open findings flagged as known-exploited' },
    { label: 'CVEs', value: intel.cves, tone: 'info', measured: true, title: 'Open findings referencing a CVE identifier' },
  ]
  return (
    <Panel>
      <PanelHeader
        title="Threat Intelligence" icon={Radar} href="/dashboard/quantum-readiness/risk-analysis"
        right={intel.epssMax > 0 ? <span className="text-[9px] font-black uppercase tracking-widest text-red-300">EPSS {intel.epssMax}%</span> : undefined}
      />
      <div className="grid grid-cols-4 gap-2">
        {chips.map((c) => {
          const t = TONE[c.tone]
          return (
            <div key={c.label} title={c.measured ? c.title : `${c.title} — not measured: no runtime collector is reporting`} className={cx('rounded-lg border p-2 text-center', c.measured && c.value > 0 ? t.border : 'border-white/5', c.measured && c.value > 0 ? t.soft : 'bg-white/[0.02]')}>
              <div className={cx('text-lg font-black tracking-tighter', c.measured && c.value > 0 ? t.text : 'text-white/40')}>{c.measured ? fmtNumber(c.value) : '—'}</div>
              <div className="mt-0.5 text-[7px] font-bold uppercase tracking-wide text-white/40">{c.label}</div>
            </div>
          )
        })}
      </div>

      <div className="mt-3 border-t border-white/5 pt-2">
        <div className="mb-1.5 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-white/45">
          <Crosshair className="h-3 w-3 text-cyan-300" /> Critical &amp; high findings
        </div>
        {intel.hasThreatFeed ? (
          <div className="space-y-1">
            {intel.feeds.slice(0, 5).map((f) => (
              <a key={f.id} href="/dashboard/quantum-readiness/risk-analysis" className="flex items-center justify-between gap-2 rounded px-1.5 py-1 no-underline transition-colors hover:bg-white/[0.03]">
                <span className="flex min-w-0 items-center gap-1.5">
                  <ShieldAlert className={cx('h-3 w-3 shrink-0', f.severity.includes('critical') ? 'text-red-400' : 'text-amber-400')} />
                  <span className="truncate text-[11px] text-white/70" title={`${f.title} — ${f.severity} · ${f.source}`}>{f.title}</span>
                  <span className={cx('shrink-0 text-[8px] font-black uppercase', f.severity.includes('critical') ? 'text-red-400/80' : 'text-amber-400/80')}>{f.severity}</span>
                </span>
                <span className="shrink-0 font-mono text-[8px] text-white/30">{relativeTime(f.at)}</span>
              </a>
            ))}
            <TruncationNote
              shown={Math.min(5, intel.feeds.length)}
              total={intel.feeds.length}
              noun="critical and high findings"
              rank="highest-severity"
            />
          </div>
        ) : (
          <p className="py-3 text-center text-[10px] text-white/30">
            No critical or high findings are open. KEV / EPSS enrichment activates when a threat-intel source is integrated.
          </p>
        )}
      </div>
    </Panel>
  )
}
