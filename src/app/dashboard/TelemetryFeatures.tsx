'use client'

import type { ReactNode } from 'react'
import {
  Activity,
  AlertTriangle,
  Cloud,
  Database,
  Fingerprint,
  Globe,
  Lock,
  Map as MapIcon,
  Server,
  Shield,
  ShieldCheck,
  Target,
  Zap,
} from 'lucide-react'
import type {
  ActivityItem,
  DashboardSummary,
  ExposureMap,
  HealthStatus,
  Recommendation,
  SecurityEvent,
} from '@/hooks/use-dashboard'

const GLASS_PANEL_CLASSES = 'qg-executive-panel group relative overflow-hidden rounded-lg text-white'

type TelemetryProps = {
  summary: DashboardSummary | null
  events: SecurityEvent[]
  exposureMap: ExposureMap
  activities: ActivityItem[]
  recommendations: Recommendation[]
  health: HealthStatus | null
  lastSyncAt: string | null
  sseConnected: boolean
  loading: boolean
}

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(' ')
}

function clamp(value: number, max = 100) {
  if (!Number.isFinite(value)) return 0
  return Math.max(0, Math.min(max, Math.round(value)))
}

function percent(value: number, total: number) {
  if (!total) return 0
  return clamp((value / total) * 100)
}

function fmt(value: number) {
  return new Intl.NumberFormat('en-US').format(value || 0)
}

/* `riskTo100` used to live here: `clamp(score > 100 ? score / 10 : score)`.
   It guessed the scale of whatever the API sent and, because the API was
   actually sending a HIGHER-better posture composite on a 0–1000 scale, it
   rendered a Critical estate as "23/100" risk. The API now publishes risk and
   readiness under their real names on the canonical 0–100 scales, so there is
   nothing left to convert — read the field directly. */

function GlassPanel({ children, className, href, label }: { children: ReactNode; className?: string; href?: string; label?: string }) {
  const classes = cx(
    'p-4 min-h-[210px] no-underline outline-none focus-visible:ring-2 focus-visible:ring-[#06B6D4]/70 focus-visible:ring-offset-2 focus-visible:ring-offset-[#0A1020]',
    GLASS_PANEL_CLASSES,
    className,
  )
  const content = <div className="relative z-10 flex h-full flex-col">{children}</div>

  if (href) {
    return (
      <a href={href} aria-label={label || 'Open telemetry panel'} className={classes}>
        {content}
      </a>
    )
  }

  return <div className={classes}>{content}</div>
}

function PanelTitle({ title, live = true }: { title: string; live?: boolean }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-3">
      <h3 className="truncate text-[11px] font-black uppercase tracking-wider text-[#FFE8A8]">{title}</h3>
      <div className={cx('flex items-center gap-1.5 text-[9px] font-black uppercase', live ? 'text-[#4DFF88]' : 'text-white/35')}>
        <span className={cx('h-1.5 w-1.5 rounded-full', live ? 'bg-[#4DFF88] shadow-[0_0_8px_rgba(77,255,136,0.8)] animate-pulse' : 'bg-white/30')} />
        {live ? 'Live' : 'No stream'}
      </div>
    </div>
  )
}

function MiniLineChart({ values, color = '#06B6D4' }: { values: number[]; color?: string }) {
  const safeValues = values.length ? values : [0, 0, 0, 0, 0, 0, 0]
  const max = Math.max(1, ...safeValues)
  const points = safeValues.map((value, index) => {
    const x = safeValues.length === 1 ? 140 : (index / (safeValues.length - 1)) * 140
    const y = 48 - (value / max) * 42
    return `${x},${y}`
  }).join(' ')

  return (
    <svg viewBox="0 0 140 50" className="h-12 w-full overflow-visible" aria-hidden="true">
      <polyline points={points} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <polyline points={`${points} 140,50 0,50`} fill="rgba(6,182,212,0.1)" stroke="none" />
      {points.split(' ').map((point, index) => {
        const [x, y] = point.split(',')
        return <circle key={index} cx={x} cy={y} r="2" fill="#fff" stroke={color} strokeWidth="1" />
      })}
    </svg>
  )
}

function MiniBarChart({ values, color = '#3b82f6' }: { values: number[]; color?: string }) {
  const safeValues = values.length ? values : [0]
  const max = Math.max(1, ...safeValues)
  return (
    <div className="flex h-12 w-full items-end gap-1">
      {safeValues.map((value, index) => (
        <div key={index} className="flex-1 rounded-t-sm" style={{ height: `${Math.max(5, (value / max) * 100)}%`, backgroundColor: color }} />
      ))}
    </div>
  )
}

function DonutRing({ percentage, color, label }: { percentage: number; color: string; label?: string }) {
  const value = clamp(percentage)
  return (
    <div className="relative flex h-16 w-16 items-center justify-center">
      <svg viewBox="0 0 36 36" className="-rotate-90">
        <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="3" />
        <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke={color} strokeWidth="3" strokeDasharray={`${value} ${100 - value}`} />
      </svg>
      {label && <div className="absolute text-sm font-black text-white">{label}</div>}
    </div>
  )
}

function ProgressBarItem({ icon: Icon, label, value, percentValue }: { icon: any; label: string; value: string; percentValue: number }) {
  return (
    <div className="mb-2.5 flex items-center gap-3 text-xs last:mb-0">
      <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-[#06B6D4]/20 bg-[#06B6D4]/10 text-[#06B6D4]">
        <Icon className="h-3.5 w-3.5" />
      </div>
      <div className="flex-1">
        <div className="mb-1 flex items-center justify-between gap-2">
          <span className="truncate text-[10px] text-white/70">{label}</span>
          <span className="font-bold text-[10px]">{value}</span>
        </div>
        <div className="h-1 overflow-hidden rounded-full bg-white/10">
          <div className="h-full bg-[#06B6D4]" style={{ width: `${clamp(percentValue)}%` }} />
        </div>
      </div>
    </div>
  )
}

function TinyProgressBar({ label, percentValue, color }: { label: string; percentValue: number; color: string }) {
  return (
    <div className="mb-2 flex items-center gap-2 text-[10px]">
      <div className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
      <span className="w-20 truncate text-white/70">{label}</span>
      <div className="h-1 flex-1 overflow-hidden rounded-full bg-white/10">
        <div className="h-full" style={{ width: `${clamp(percentValue)}%`, backgroundColor: color }} />
      </div>
      <span className="w-8 text-right font-bold">{clamp(percentValue)}%</span>
    </div>
  )
}

function countBy<T extends string>(values: T[]) {
  return values.reduce<Record<string, number>>((acc, value) => {
    acc[value || 'unknown'] = (acc[value || 'unknown'] || 0) + 1
    return acc
  }, {})
}

function recentEventBuckets(events: SecurityEvent[]) {
  const days = Array.from({ length: 7 }, (_, index) => {
    const date = new Date()
    date.setHours(0, 0, 0, 0)
    date.setDate(date.getDate() - (6 - index))
    return { key: date.toISOString().slice(0, 10), count: 0 }
  })
  const byKey = new Map(days.map((day) => [day.key, day]))
  for (const event of events) {
    const key = new Date(event.timestamp).toISOString().slice(0, 10)
    const bucket = byKey.get(key)
    if (bucket) bucket.count += 1
  }
  return days.map((day) => day.count)
}

export default function TelemetryFeatures({
  summary,
  events,
  exposureMap,
  activities,
  recommendations,
  health,
  lastSyncAt,
  sseConnected,
  loading,
}: TelemetryProps) {
  const totalAssets = summary?.totalAssets || 0
  const vulnerableAssets = summary?.vulnerableAssetsCount || 0
  const totalCbomItems = summary?.totalCbomItems || 0
  const activeMigrations = summary?.activeMigrations || 0
  const failedMigrations = summary?.failedMigrations || 0
  const completedMigrations = summary?.completedMigrations || 0
  const criticalExposures = summary?.criticalExposures || 0
  const highExposures = summary?.highExposures || 0
  const unresolvedVulns = summary?.unresolvedVulns || 0
  const expiringCerts = summary?.expiringCerts || 0
  const hasBaseline = summary?.hasBaseline ?? false
  const riskScore = clamp(summary?.quantumRiskScore || 0)
  const safeAssets = Math.max(0, totalAssets - vulnerableAssets)
  const eventCounts = countBy(events.map((event) => event.severity))
  const environmentCounts = countBy(exposureMap.nodes.map((node) => node.environment || 'unknown'))
  const typeCounts = countBy(exposureMap.nodes.map((node) => node.type || 'unknown'))
  const environments = Object.entries(environmentCounts).sort((a, b) => b[1] - a[1]).slice(0, 4)
  const types = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).slice(0, 4)
  const eventTrend = recentEventBuckets(events)
  // Fall back to the API's readiness composite, never to `riskScore` — that
  // substituted a lower-better number into a higher-better meter.
  const readiness = totalAssets ? clamp((safeAssets / totalAssets) * 100) : clamp(summary?.quantumReadinessScore || 0)
  const cbomCoverage = totalAssets ? clamp((totalCbomItems / totalAssets) * 100) : 0
  const migrationTotal = completedMigrations + activeMigrations + failedMigrations
  const migrationCompletion = summary?.migrationCompletionRate ?? (migrationTotal ? percent(completedMigrations, migrationTotal) : 0)
  const latestEvent = events[0]

  return (
    <div className="mt-8 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
      <GlassPanel href="/dashboard/quantum-risk-scoring" label="Open quantum risk scoring">
        <PanelTitle title="Quantum Security Posture" live={sseConnected} />
        <div className="mt-2 flex flex-1 items-center gap-4">
          <div className="relative flex h-28 w-28 shrink-0 items-center justify-center">
            <div className="absolute inset-0 rounded-full border border-[#06B6D4]/20" />
            <div className="absolute inset-2 rounded-full border border-dashed border-[#06B6D4]/40" />
            <Shield className="h-12 w-12 text-[#06B6D4]" />
            <Lock className="absolute mt-2 h-4 w-4 rounded-sm bg-[#06B6D4] p-0.5 text-[#0A1020]" />
          </div>
          <div className="flex flex-1 flex-col items-center">
            <span className="text-[9px] font-bold uppercase tracking-widest text-white/50">Quantum Risk Score</span>
            {/* Nothing measured is a THIRD state — rendering the 0 here would
                read as a perfect score on a lower-better scale. */}
            <div className="mt-2 flex items-baseline gap-1">
              <span className="text-5xl font-black text-[#06B6D4]">{loading || !hasBaseline ? '--' : riskScore}</span>
              <span className="text-sm font-bold text-white/50">/100</span>
            </div>
            <div className="mt-2 text-[10px] font-bold tracking-widest text-white/70">
              Risk Band: <span className="text-[#06B6D4]">{hasBaseline ? summary?.riskBand : 'No scan baseline'}</span>
            </div>
            <div className="mt-4 w-full">
              <span className="text-[8px] uppercase text-white/40">Event Trend (7 Days)</span>
              <MiniLineChart values={eventTrend} color="#06B6D4" />
            </div>
          </div>
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/runtime-telemetry" label="Open runtime telemetry">
        <PanelTitle title="System Health" live={sseConnected} />
        <div className="mt-2 flex flex-1 flex-col justify-center">
          <ProgressBarItem icon={Target} label="Assets Monitored" value={fmt(totalAssets)} percentValue={totalAssets > 0 ? 100 : 0} />
          <ProgressBarItem icon={Lock} label="CBOM Coverage" value={`${fmt(totalCbomItems)} items`} percentValue={cbomCoverage} />
          <ProgressBarItem icon={Zap} label="PQC Readiness" value={`${readiness}%`} percentValue={readiness} />
          <ProgressBarItem icon={ShieldCheck} label="Risk Score" value={`${riskScore}/100`} percentValue={riskScore} />
          <ProgressBarItem icon={AlertTriangle} label="Open Detections" value={fmt(criticalExposures + highExposures + unresolvedVulns)} percentValue={percent(criticalExposures + highExposures + unresolvedVulns, Math.max(1, totalCbomItems + totalAssets))} />
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/assets" label="Open asset scope">
        <PanelTitle title="Asset Scope" live={!loading} />
        <div className="mb-4 grid grid-cols-2 gap-2">
          <div className="rounded-md border border-white/10 bg-white/5 p-2">
            <Server className="mb-1 h-3.5 w-3.5 text-[#06B6D4]" />
            <div className="text-[8px] uppercase text-white/50">Assets</div>
            <div className="text-sm font-black">{fmt(totalAssets)}</div>
          </div>
          <div className="rounded-md border border-white/10 bg-white/5 p-2">
            <Globe className="mb-1 h-3.5 w-3.5 text-[#06B6D4]" />
            <div className="text-[8px] uppercase text-white/50">Environments</div>
            <div className="text-sm font-black">{fmt(Object.keys(environmentCounts).length)}</div>
          </div>
          <div className="rounded-md border border-white/10 bg-white/5 p-2">
            <Database className="mb-1 h-3.5 w-3.5 text-[#06B6D4]" />
            <div className="text-[8px] uppercase text-white/50">Asset Types</div>
            <div className="text-sm font-black">{fmt(Object.keys(typeCounts).length)}</div>
          </div>
          <div className="rounded-md border border-white/10 bg-white/5 p-2">
            <MapIcon className="mb-1 h-3.5 w-3.5 text-[#06B6D4]" />
            <div className="text-[8px] uppercase text-white/50">Links</div>
            <div className="text-sm font-black">{fmt(exposureMap.edges.length)}</div>
          </div>
        </div>
        <div className="space-y-1.5">
          {environments.length ? environments.map(([name, count]) => (
            <div key={name}>
              <TinyProgressBar label={name} percentValue={percent(count, totalAssets)} color="#06B6D4" />
            </div>
          )) : <div className="text-xs text-white/35">No asset environments discovered yet.</div>}
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/live-migration" label="Open live migration">
        <PanelTitle title="Migration Progress" live={activeMigrations > 0} />
        <div className="mt-4 flex flex-1 items-center gap-6">
          <div className="relative flex w-20 shrink-0 flex-col items-center justify-center">
            <DonutRing percentage={migrationCompletion} color="#06B6D4" />
            <div className="absolute flex flex-col items-center justify-center">
              <span className="text-lg font-black text-[#06B6D4]">{migrationCompletion}%</span>
            </div>
            <span className="mt-3 text-center text-[8px] uppercase text-white/50">Overall Migration</span>
          </div>
          <div className="mt-1 flex-1 space-y-1">
            <TinyProgressBar label="Inventory" percentValue={cbomCoverage} color="#4DFF88" />
            <TinyProgressBar label="Planning" percentValue={recommendations.length ? 75 : 0} color="#3b82f6" />
            <TinyProgressBar label="Completed" percentValue={migrationCompletion} color="#06B6D4" />
            <TinyProgressBar label="Failures" percentValue={percent(failedMigrations, Math.max(1, migrationTotal))} color="#ef4444" />
          </div>
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/cbom" label="Open CBOM explorer">
        <PanelTitle title="Cryptographic Intelligence" live={sseConnected} />
        <div className="mb-4 mt-2 grid grid-cols-4 gap-2">
          <div><div className="text-[8px] uppercase text-white/50">CBOM</div><div className="mt-1 text-[13px] font-black">{fmt(totalCbomItems)}</div></div>
          <div><div className="text-[8px] uppercase text-white/50">Assets</div><div className="mt-1 text-[13px] font-black">{fmt(totalAssets)}</div></div>
          <div><div className="text-[8px] uppercase text-white/50">Critical</div><div className="mt-1 text-[13px] font-black text-red-500">{fmt(criticalExposures)}</div></div>
          <div><div className="text-[8px] uppercase text-white/50">High</div><div className="mt-1 text-[13px] font-black text-[#06B6D4]">{fmt(highExposures)}</div></div>
        </div>
        <div className="relative mt-auto h-[60px] w-full">
          <MiniBarChart values={[totalCbomItems, totalAssets, vulnerableAssets, criticalExposures, highExposures]} color="#06B6D4" />
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/audit-vault" label="Open audit vault">
        <PanelTitle title="Threat Intelligence" live={events.length > 0} />
        <div className="mt-2 flex flex-1 items-center gap-6">
          <div className="relative flex h-24 w-24 shrink-0 items-center justify-center">
            <div className="absolute inset-0 rounded-full border border-dashed border-[#06B6D4]/40" />
            <div className="absolute inset-2 rounded-full border border-dotted border-[#06B6D4]/60" />
            <AlertTriangle className="h-8 w-8 text-[#06B6D4]" />
          </div>
          <div className="flex-1 space-y-2.5">
            {[
              ['Critical Events', eventCounts.critical || 0, 'text-red-500'],
              ['Warnings', eventCounts.warning || 0, 'text-orange-500'],
              ['Info Events', eventCounts.info || 0, 'text-[#06B6D4]'],
              ['Success Events', eventCounts.success || 0, 'text-[#4DFF88]'],
            ].map(([label, count, color]) => (
              <div key={String(label)} className="flex items-center justify-between text-[11px]">
                <span className="text-white/80">{label}</span>
                <span className={`font-black ${color}`}>{fmt(Number(count))}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="mt-auto border-t border-white/5 pt-3 text-[9px]">
          <span className="text-white/50">Latest event: </span>
          <span className="text-white/80">{latestEvent?.message || 'No runtime events received yet'}</span>
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/runtime-telemetry" label="Open runtime telemetry">
        <PanelTitle title="Runtime Telemetry" live={sseConnected} />
        <MiniLineChart values={eventTrend} />
        <div className="mt-auto flex items-end justify-between">
          <div>
            <div className="text-[9px] font-bold uppercase text-white/50">Recent Events</div>
            <div className="text-xl font-black text-white">{fmt(events.length)}</div>
          </div>
          <div className="text-right">
            <div className="text-[9px] font-bold uppercase text-white/50">Activities</div>
            <div className="text-xl font-black text-white">{fmt(activities.length)}</div>
          </div>
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/vulnerabilities" label="Open vulnerabilities">
        <PanelTitle title="Exposure Severity" live={!loading} />
        <div className="mt-2 flex flex-1 items-center gap-4">
          <DonutRing percentage={percent(safeAssets, totalAssets)} color="#3b82f6" label={`${percent(safeAssets, totalAssets)}%`} />
          <div className="flex-1 space-y-2">
            <TinyProgressBar label="Safe Assets" percentValue={percent(safeAssets, totalAssets)} color="#3b82f6" />
            <TinyProgressBar label="Vulnerable" percentValue={percent(vulnerableAssets, totalAssets)} color="#06B6D4" />
            <TinyProgressBar label="Critical" percentValue={percent(criticalExposures, Math.max(1, criticalExposures + highExposures))} color="#ef4444" />
          </div>
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/certificate-telemetry" label="Open certificate telemetry">
        <PanelTitle title="Certificate Telemetry" live={!loading} />
        <div className="mt-2 flex flex-1 items-center justify-between">
          <div>
            <div className="text-[9px] font-bold uppercase text-white/50">Expiring Soon</div>
            <div className="text-xl font-black text-[#06B6D4]">{fmt(expiringCerts)}</div>
            <div className="mt-3 text-[9px] font-bold uppercase text-white/50">Related Risk Band</div>
            <div className="text-sm font-black text-white">{hasBaseline ? summary?.riskBand : 'No baseline'}</div>
          </div>
          <DonutRing percentage={expiringCerts ? clamp(100 - expiringCerts * 5) : 100} color="#06B6D4" />
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/encryption-monitoring" label="Open encryption monitoring">
        <PanelTitle title="Encryption Monitoring" live={!loading} />
        <div className="mt-2 flex flex-1 items-center gap-4">
          <div className="flex-1 space-y-2">
            <TinyProgressBar label="Protected" percentValue={percent(safeAssets, totalAssets)} color="#3b82f6" />
            <TinyProgressBar label="At Risk" percentValue={percent(vulnerableAssets, totalAssets)} color="#06B6D4" />
            <TinyProgressBar label="Critical" percentValue={percent(criticalExposures, Math.max(1, totalAssets))} color="#ef4444" />
          </div>
          <div className="relative flex h-16 w-16 items-center justify-center">
            <DonutRing percentage={readiness} color="#3b82f6" />
            <Lock className="absolute h-5 w-5 text-[#06B6D4]" />
          </div>
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/quantum-risk-scoring" label="Open quantum risk scoring">
        <PanelTitle title="Quantum Risk Scoring" live={sseConnected} />
        <div className="mt-2 flex flex-1 flex-col items-center justify-center">
          <div className="mt-2 flex items-baseline gap-1">
            <span className="text-5xl font-black text-[#06B6D4] drop-shadow-[0_0_12px_rgba(6,182,212,0.55)]">{riskScore}</span>
            <span className="text-sm font-bold text-white/50">/100</span>
          </div>
          <div className="mt-auto w-full">
            <MiniLineChart values={eventTrend} color="#06B6D4" />
          </div>
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/zero-trust" label="Open zero trust">
        <PanelTitle title="Trust Validation" live={sseConnected} />
        <div className="mt-4 flex flex-1 items-center gap-6">
          <div className="relative flex h-20 w-16 items-center justify-center">
            <ShieldCheck className="absolute h-full w-full text-[#06B6D4] opacity-20" />
            <Fingerprint className="relative h-8 w-8 text-[#06B6D4]" />
          </div>
          <div className="flex-1 space-y-2 text-xs">
            <div className="flex justify-between"><span className="text-white/70">Tenant Isolation</span><span className="font-bold text-[#06B6D4]">User scoped</span></div>
            <div className="flex justify-between"><span className="text-white/70">SSE Stream</span><span className="font-bold">{sseConnected ? 'Connected' : 'Disconnected'}</span></div>
            <div className="flex justify-between"><span className="text-white/70">Database Health</span><span className="font-bold">{health?.services.supabase || 'unknown'}</span></div>
            <div className="flex justify-between"><span className="text-white/70">Last Sync</span><span className="font-bold">{lastSyncAt ? new Date(lastSyncAt).toLocaleTimeString() : 'waiting'}</span></div>
          </div>
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/regulatory-mapping" label="Open regulatory mapping">
        <PanelTitle title="Policy Compliance" live={!loading} />
        <div className="mt-4 flex flex-1 items-center gap-6">
          <DonutRing percentage={riskScore} color="#4DFF88" label={`${riskScore}%`} />
          <div className="flex-1 space-y-3">
            <TinyProgressBar label="Compliant" percentValue={riskScore} color="#4DFF88" />
            <TinyProgressBar label="Warnings" percentValue={percent(highExposures + expiringCerts, Math.max(1, totalAssets + totalCbomItems))} color="#06B6D4" />
            <TinyProgressBar label="Critical" percentValue={percent(criticalExposures + failedMigrations, Math.max(1, totalAssets + activeMigrations + failedMigrations))} color="#ef4444" />
          </div>
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/telemetry-correlation" label="Open telemetry correlation">
        <PanelTitle title="Telemetry Overview" live={sseConnected} />
        <div className="mt-2 flex flex-1 flex-col justify-between space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="text-[9px] font-bold uppercase text-white/50">Recent Runtime Events</div>
              <div className="mt-1 text-xl font-black text-white">{fmt(events.length)}</div>
            </div>
            <div className="w-1/2">
              <MiniBarChart values={eventTrend} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <div className="text-[9px] font-bold uppercase text-white/50">Activities</div>
              <div className="mt-1 text-xl font-black text-[#06B6D4]">{fmt(activities.length)}</div>
            </div>
            <div>
              <div className="text-[9px] font-bold uppercase text-white/50">Open Actions</div>
              <div className="mt-1 text-xl font-black text-[#06B6D4]">{fmt(recommendations.length)}</div>
            </div>
          </div>
        </div>
      </GlassPanel>

      <GlassPanel href="/dashboard/multi-cloud-telemetry" label="Open multi-cloud telemetry">
        <PanelTitle title="Environment Telemetry" live={!loading} />
        <div className="mt-4 flex flex-1 items-center gap-4">
          <div className="flex-1 space-y-3">
            {(environments.length ? environments : types).map(([name, count], index) => (
              <div key={`${name}-${index}`} className="flex items-center justify-between text-xs">
                <span className="w-24 truncate text-white/80 capitalize">{name}</span>
                <div className="mx-2 h-1 flex-1 overflow-hidden rounded-full bg-white/10">
                  <div className="h-full bg-blue-500" style={{ width: `${percent(count, totalAssets || exposureMap.nodes.length)}%` }} />
                </div>
                <span className="font-bold text-blue-400">{fmt(count)}</span>
              </div>
            ))}
            {!environments.length && !types.length && (
              <div className="text-xs text-white/35">No environment telemetry available yet.</div>
            )}
          </div>
          <div className="relative flex h-16 w-16 items-center justify-center">
            <DonutRing percentage={Object.keys(environmentCounts).length ? 100 : 0} color="#3b82f6" />
            <Cloud className="absolute h-5 w-5 text-[#06B6D4]" />
          </div>
        </div>
      </GlassPanel>
    </div>
  )
}
