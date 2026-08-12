/**
 * Migration Sandbox — operations panels.
 *
 * SimulationBuilderTab — enterprise replacement for the New Simulation modal:
 *                        14 scenario types, live asset selection with
 *                        risk/environment/type/owner/region/readiness filters,
 *                        pipeline preview, dry-run control.
 * TelemetryTab         — real bucketed event series (SSE-refreshed) + labeled
 *                        modeled per-simulation load.
 * PerformanceTab       — before/after benchmark projection with methodology.
 * ValidationTab        — compatibility + security validation + failure
 *                        prediction engine + risk factors.
 * ReportsTab           — 9 enterprise report types × PDF / Word / JSON / CSV.
 */
import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Cpu,
  Download,
  FileText,
  FlaskConical,
  Gauge,
  Key,
  Play,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Target,
  Zap,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { cn } from '@/lib/utils'
import {
  ActionBtn,
  BLUE,
  CYAN,
  EmptyBlock,
  GOLD,
  GREEN,
  MetricTile,
  ORANGE,
  Panel,
  Pill,
  ProgressBar,
  PURPLE,
  RED,
  ScoreGauge,
  SectionHead,
  Sparkline,
  downloadBlob,
  fmt,
  pct,
  relTime,
  riskBadge,
  severityIcon,
  type FailurePredictionPayload,
  type PerformanceBenchmarkPayload,
  type PipelineStage,
  type RiskFactor,
  type SandboxSnapshot,
  type SandboxSummary,
  type SimulationAsset,
  type SimulationTypeDef,
  type SophiaPayload,
  type TelemetryFramePayload,
} from './_shared'
import { SANDBOX_REPORT_TYPES, buildSandboxReportDoc, renderSandboxReportDocx, renderSandboxReportPdf, type SandboxReportType } from './sandbox-report'

/* ═══════════════════════════════════════════════════════════════════════════
   SIMULATION BUILDER TAB
   ═══════════════════════════════════════════════════════════════════════════ */

export function SimulationBuilderTab({ simulationTypes, pipeline, pendingAction, onStart }: {
  simulationTypes: SimulationTypeDef[]
  pipeline: PipelineStage[]
  pendingAction: string | null
  onStart: (params: Record<string, unknown>) => Promise<unknown>
}) {
  const { session } = useAuth()
  const token = session?.access_token
  const [assets, setAssets] = useState<SimulationAsset[]>([])
  const [assetsLoading, setAssetsLoading] = useState(false)
  const [assetsError, setAssetsError] = useState<string | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [typeId, setTypeId] = useState('full_enterprise_migration')
  const [dryRun, setDryRun] = useState(true)
  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState('all')
  const [envFilter, setEnvFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')
  const [ownerFilter, setOwnerFilter] = useState('all')
  const [regionFilter, setRegionFilter] = useState('all')
  const [readinessFilter, setReadinessFilter] = useState('all')
  const [fromAlgo, setFromAlgo] = useState('RSA-2048')
  const [toAlgo, setToAlgo] = useState('ML-KEM-768')

  const loadAssets = () => {
    if (!token) return
    setAssetsLoading(true)
    setAssetsError(null)
    fetch('/api/v1/sandbox/assets', { headers: { Authorization: `Bearer ${token}` } })
      .then(async (r) => {
        const j = await r.json().catch(() => ({}))
        if (!r.ok) throw new Error(j?.error?.message || `HTTP ${r.status}`)
        setAssets(Array.isArray(j?.data?.assets) ? j.data.assets : [])
      })
      .catch((err) => setAssetsError(err instanceof Error ? err.message : 'Failed to load scanned assets'))
      .finally(() => setAssetsLoading(false))
  }
  // Load the tenant's real scanned assets whenever the builder mounts so
  // simulations always target current inventory.
  useEffect(loadAssets, [token])

  const selectedType = simulationTypes.find((t) => t.id === typeId) || simulationTypes[0]
  const isCustom = typeId === 'custom_scenario'

  const distinct = (values: Array<string | null | undefined>) => Array.from(new Set(values.map((v) => String(v || '').trim()).filter(Boolean))).sort()
  const environments = useMemo(() => distinct(assets.map((a) => a.environment)), [assets])
  const assetTypes = useMemo(() => distinct(assets.map((a) => a.type)), [assets])
  const owners = useMemo(() => distinct(assets.map((a) => a.owner)), [assets])
  const regions = useMemo(() => distinct(assets.map((a) => a.region)), [assets])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return assets.filter((a) => {
      if (q && !(`${a.name} ${a.type} ${a.environment} ${a.sourceAlgorithm} ${a.algorithms.join(' ')}`.toLowerCase().includes(q))) return false
      if (riskFilter !== 'all' && a.riskLevel !== riskFilter) return false
      if (envFilter !== 'all' && a.environment !== envFilter) return false
      if (typeFilter !== 'all' && a.type !== typeFilter) return false
      if (ownerFilter !== 'all' && a.owner !== ownerFilter) return false
      if (regionFilter !== 'all' && String(a.region || '') !== regionFilter) return false
      if (readinessFilter === 'vulnerable' && !(a.vulnerableItems > 0 || a.criticalExposures > 0)) return false
      if (readinessFilter === 'evidence' && !a.hasEvidence) return false
      if (readinessFilter === 'no_evidence' && a.hasEvidence) return false
      return true
    })
  }, [assets, search, riskFilter, envFilter, typeFilter, ownerFilter, regionFilter, readinessFilter])

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else if (next.size < 25) next.add(id)
      return next
    })
  }
  const selectAllFiltered = () => setSelected(new Set(filtered.slice(0, 25).map((a) => a.id)))
  const selectVulnerable = () => setSelected(new Set(assets.filter((a) => a.vulnerableItems > 0 || a.criticalExposures > 0).slice(0, 25).map((a) => a.id)))

  const launching = pendingAction === 'simulate'
  const startDisabled = launching || (isCustom ? !fromAlgo.trim() : selected.size === 0)
  const estimatedMinutes = Math.max(1, Math.round(((selectedType?.baseDurationMs || 220000) + (isCustom ? 0 : selected.size * (selectedType?.perAssetMs || 8000))) * (dryRun ? 0.55 : 1) / 60000))

  const launch = async () => {
    if (isCustom) {
      await onStart({ fromAlgo, toAlgo, migrationType: 'custom_scenario', simulationType: typeId, dryRun })
    } else {
      await onStart({ assetIds: Array.from(selected), simulationType: typeId, dryRun })
      setSelected(new Set())
    }
  }

  const filterSelect = (label: string, value: string, onChange: (v: string) => void, options: string[], allLabel: string) => (
    <label className="space-y-1">
      <span className="text-[9px] font-bold uppercase tracking-wider text-white/30">{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)} className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-2 text-[11px] font-bold text-white outline-none focus:border-gold/40">
        <option value="all">{allLabel}</option>
        {options.map((option) => <option key={option} value={option}>{option}</option>)}
      </select>
    </label>
  )

  return (
    <>
      <Panel className="p-5">
        <SectionHead icon={Zap} suffix={<Pill className="border-gold/25 bg-gold/10 text-gold">{selectedType?.label}</Pill>}>
          Step 1 — Choose Simulation Type
        </SectionHead>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {simulationTypes.map((type) => (
            <button
              key={type.id}
              type="button"
              onClick={() => setTypeId(type.id)}
              className={cn('rounded-xl border p-3.5 text-left transition',
                typeId === type.id ? 'border-gold/50 bg-gold/[0.08]' : 'border-white/8 bg-white/[0.015] hover:border-gold/25')}
            >
              <div className="flex items-center justify-between gap-2">
                <span className={cn('text-xs font-black', typeId === type.id ? 'text-gold' : 'text-white/80')}>{type.label}</span>
                {typeId === type.id && <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-gold" />}
              </div>
              <p className="mt-1.5 text-[10px] leading-relaxed text-white/40">{type.description}</p>
              <div className="mt-2 text-[9px] font-bold uppercase tracking-wider text-white/25">{type.recommendedFor}</div>
            </button>
          ))}
        </div>
      </Panel>

      {isCustom ? (
        <Panel className="p-5">
          <SectionHead icon={Key}>Step 2 — Define Custom Scenario</SectionHead>
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-white/40">Source Algorithm</label>
              <input value={fromAlgo} onChange={(e) => setFromAlgo(e.target.value)} className="w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2.5 font-mono text-sm text-white outline-none focus:border-gold/50" />
            </div>
            <div>
              <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-white/40">Target Algorithm (PQC)</label>
              <input value={toAlgo} onChange={(e) => setToAlgo(e.target.value)} className="w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2.5 font-mono text-sm text-white outline-none focus:border-gold/50" />
            </div>
          </div>
        </Panel>
      ) : (
        <Panel className="p-5">
          <SectionHead icon={Server} suffix={
            <div className="flex flex-wrap items-center gap-2">
              <Pill className="border-gold/25 bg-gold/10 text-gold">{selected.size} / 25 selected</Pill>
              <ActionBtn icon={RefreshCw} label={assetsLoading ? 'Loading' : 'Reload'} onClick={loadAssets} disabled={assetsLoading} small />
            </div>
          }>Step 2 — Select Live Assets</SectionHead>
          <p className="mb-3 text-[11px] leading-relaxed text-white/40">
            Simulation targets are your real scanned assets. Each job loads the asset's actual cryptographic evidence
            (inventory + exposures + certificates) into the digital twin and validates the migration against it.
          </p>

          <div className="mb-3 grid gap-2 sm:grid-cols-3 xl:grid-cols-6">
            {filterSelect('Risk', riskFilter, setRiskFilter, ['critical', 'high', 'medium', 'low'], 'All risk levels')}
            {filterSelect('Environment', envFilter, setEnvFilter, environments, 'All environments')}
            {filterSelect('Asset Type', typeFilter, setTypeFilter, assetTypes, 'All types')}
            {filterSelect('Business Unit / Owner', ownerFilter, setOwnerFilter, owners, 'All owners')}
            {filterSelect('Cloud / Region', regionFilter, setRegionFilter, regions, 'All regions')}
            <label className="space-y-1">
              <span className="text-[9px] font-bold uppercase tracking-wider text-white/30">Readiness</span>
              <select value={readinessFilter} onChange={(e) => setReadinessFilter(e.target.value)} className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-2 text-[11px] font-bold text-white outline-none focus:border-gold/40">
                <option value="all">All assets</option>
                <option value="vulnerable">Vulnerable only</option>
                <option value="evidence">With crypto evidence</option>
                <option value="no_evidence">Missing evidence</option>
              </select>
            </label>
          </div>

          <div className="mb-3 flex flex-wrap items-center gap-2">
            <div className="relative min-w-0 flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/25" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search assets, algorithms, environments…"
                className="w-full rounded-lg border border-white/10 bg-white/[0.04] py-2 pl-8 pr-3 text-xs text-white outline-none placeholder:text-white/25 focus:border-gold/40"
              />
            </div>
            <button type="button" onClick={selectAllFiltered} className="rounded-lg border border-gold/25 bg-gold/[0.06] px-2.5 py-2 text-[10px] font-bold text-gold transition hover:bg-gold/[0.12]">
              Select All Filtered ({Math.min(25, filtered.length)})
            </button>
            <button type="button" onClick={selectVulnerable} className="rounded-lg border border-red-500/25 bg-red-500/8 px-2.5 py-2 text-[10px] font-bold text-red-300 transition hover:bg-red-500/15">
              Select Vulnerable
            </button>
            <button type="button" onClick={() => setSelected(new Set())} className="rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-2 text-[10px] font-bold text-white/50 transition hover:bg-white/8">
              Clear
            </button>
          </div>

          {assetsLoading ? (
            <div className="flex items-center justify-center gap-3 rounded-lg border border-white/8 bg-white/[0.02] py-10">
              <div className="h-5 w-5 animate-spin rounded-full border-2 border-gold/20 border-t-gold" />
              <span className="text-xs font-bold text-white/45">Loading scanned assets…</span>
            </div>
          ) : assetsError ? (
            <EmptyBlock label={`Could not load scanned assets: ${assetsError}`} />
          ) : filtered.length === 0 ? (
            <EmptyBlock label={assets.length === 0 ? 'No scanned assets found. Run a discovery scan in the PQC Scanner first, then simulate migrations against the discovered assets.' : 'No assets match the current filters.'} />
          ) : (
            <div className="max-h-[380px] space-y-1.5 overflow-y-auto pr-1 scrollbar-thin scrollbar-track-transparent scrollbar-thumb-white/10">
              {filtered.map((asset) => {
                const checked = selected.has(asset.id)
                return (
                  <label key={asset.id} className={cn('flex cursor-pointer items-center gap-3 rounded-lg border px-3 py-2.5 transition',
                    checked ? 'border-gold/40 bg-gold/[0.06]' : 'border-white/8 bg-white/[0.015] hover:border-gold/20')}>
                    <input type="checkbox" checked={checked} onChange={() => toggle(asset.id)} className="h-4 w-4 shrink-0 rounded border-white/20 bg-white/5 accent-gold" />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="truncate text-xs font-bold text-white/85">{asset.name}</span>
                        <Pill className={riskBadge(asset.riskLevel)}>{asset.riskLevel}</Pill>
                        {asset.activeSimulations > 0 && <Pill className="border-sky-500/25 bg-sky-500/10 text-sky-300">{asset.activeSimulations} active</Pill>}
                      </div>
                      <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[10px] text-white/40">
                        <span className="font-mono">{asset.sourceAlgorithm}</span>
                        <span className="text-gold">→</span>
                        <span className="font-mono text-emerald-300">{asset.targetAlgorithm}</span>
                        <span className="text-white/20">|</span>
                        <span>{asset.type} · {asset.environment}{asset.region ? ` · ${asset.region}` : ''} · {asset.owner}</span>
                      </div>
                      <div className="mt-0.5 text-[9px] font-semibold text-white/30">
                        {asset.hasEvidence
                          ? `${fmt(asset.vulnerableItems)} vulnerable item(s) · ${fmt(asset.exposures)} exposure(s) · ${fmt(asset.inventoryItems)} inventory record(s)`
                          : 'No crypto evidence yet — simulation validates the recommended baseline migration'}
                      </div>
                    </div>
                  </label>
                )
              })}
            </div>
          )}
        </Panel>
      )}

      <Panel className="p-5">
        <SectionHead icon={FlaskConical}>Step 3 — Review & Launch</SectionHead>
        <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
          <div>
            <div className="mb-2 text-[9px] font-bold uppercase tracking-wider text-white/30">Enterprise Pipeline Preview — every simulation executes these stages inside the digital twin</div>
            <div className="flex flex-wrap gap-1.5">
              {pipeline.map((stage, index) => (
                <span key={stage.id}>
                  <Pill className={cn(stage.gate ? 'border-purple-500/25 bg-purple-500/10 text-purple-300' : 'border-white/10 bg-white/[0.03] text-white/50')}>
                    {index + 1}. {stage.label}
                  </Pill>
                </span>
              ))}
            </div>
            <label className="mt-4 flex cursor-pointer items-center gap-2 text-xs text-white/60">
              <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} className="h-4 w-4 rounded border-white/20 bg-white/5 accent-gold" />
              <span className="font-bold">Dry Run Mode</span>
              <span className="text-[10px] text-white/35">(faster validation pass, identical isolation guarantees)</span>
            </label>
          </div>
          <div className="rounded-xl border border-white/8 bg-black/20 p-4">
            <div className="text-[9px] font-bold uppercase tracking-wider text-white/30">Launch Summary</div>
            <div className="mt-2 space-y-1.5 text-[11px] font-semibold text-white/55">
              <div className="flex justify-between"><span>Scenario</span><span className="text-gold">{selectedType?.label}</span></div>
              <div className="flex justify-between"><span>Targets</span><span className="text-white">{isCustom ? `${fromAlgo} → ${toAlgo}` : `${selected.size} asset(s)`}</span></div>
              <div className="flex justify-between"><span>Mode</span><span className="text-white">{dryRun ? 'Dry run' : 'Full simulation'}</span></div>
              <div className="flex justify-between"><span>Est. duration</span><span className="text-white">~{estimatedMinutes} min</span></div>
              <div className="flex justify-between"><span>Production impact</span><span className="text-emerald-300">None — twin only</span></div>
            </div>
            <button
              type="button"
              onClick={launch}
              disabled={startDisabled}
              className={cn('mt-4 flex w-full items-center justify-center gap-2 rounded-lg border border-gold bg-gold px-5 py-2.5 text-xs font-black text-black shadow-[0_0_20px_rgba(251,191,36,0.3)] transition hover:bg-[#FFE08A]', startDisabled && 'pointer-events-none opacity-40')}
            >
              <Play className="h-3.5 w-3.5" />
              {launching ? 'Launching…' : isCustom ? 'Launch Custom Simulation' : `Simulate ${selected.size} Asset${selected.size === 1 ? '' : 's'}`}
            </button>
          </div>
        </div>
      </Panel>
    </>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   TELEMETRY TAB
   ═══════════════════════════════════════════════════════════════════════════ */

const SERIES_COLORS: Record<string, string> = {
  crypto_ops: CYAN,
  tls_signals: BLUE,
  cert_validations: PURPLE,
  migration_events: GOLD,
  errors: RED,
  warnings: ORANGE,
}

export function TelemetryTab({ frame, sseActive }: { frame: TelemetryFramePayload | undefined; sseActive: boolean }) {
  if (!frame) return <Panel className="p-8"><EmptyBlock label="Telemetry frame not yet streamed — the SSE channel delivers it with each snapshot." /></Panel>

  return (
    <>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricTile label="Crypto Ops (window)" value={fmt(frame.totals.cryptoOps)} detail={`${frame.windowMinutes}m rolling window`} icon={Cpu} color={CYAN} />
        <MetricTile label="Migration Events" value={fmt(frame.totals.migrationEvents)} detail="Engine + operator activity" icon={Activity} color={GOLD} />
        <MetricTile label="Errors" value={fmt(frame.totals.errors)} detail={frame.totals.errors > 0 ? 'Review execution logs' : 'Clean window'} icon={AlertTriangle} color={frame.totals.errors > 0 ? RED : GREEN} />
        <MetricTile label="Warnings" value={fmt(frame.totals.warnings)} detail={frame.totals.warnings > 0 ? 'Attention required' : 'Clean window'} icon={AlertTriangle} color={frame.totals.warnings > 0 ? ORANGE : GREEN} />
      </div>

      <Panel className="p-5">
        <SectionHead icon={Activity} suffix={
          <Pill className={cn(sseActive ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'border-amber-500/30 bg-amber-500/10 text-amber-300')}>
            {sseActive ? 'SSE streaming — no polling' : 'SSE reconnecting'}
          </Pill>
        }>Real-Time Telemetry Streams</SectionHead>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {frame.series.map((series) => {
            const color = SERIES_COLORS[series.id] || CYAN
            const total = series.values.reduce((a, b) => a + b, 0)
            return (
              <div key={series.id} className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
                <div className="flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="truncate text-xs font-bold text-white/80">{series.label}</div>
                    <div className="mt-0.5 font-mono text-[9px] text-white/30">{series.source}</div>
                  </div>
                  <span className="font-mono text-lg font-black" style={{ color }}>{fmt(total)}</span>
                </div>
                <div className="mt-2">
                  <Sparkline values={series.values} color={color} />
                </div>
                <div className="mt-1 flex justify-between font-mono text-[8px] text-white/25">
                  <span>-{frame.windowMinutes}m</span>
                  <span>{frame.bucketMinutes}m buckets</span>
                  <span>now</span>
                </div>
              </div>
            )
          })}
        </div>
      </Panel>

      <Panel className="p-5">
        <SectionHead icon={Gauge}>Active Simulation Load (Twin-Modeled)</SectionHead>
        {frame.simulatedLoad.length === 0 ? (
          <EmptyBlock label="No simulations running — per-simulation CPU/memory/latency load appears here during execution." />
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            {frame.simulatedLoad.map((load) => (
              <div key={load.jobId} className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-xs font-bold text-white/85">{load.jobName}</span>
                  <div className="flex items-center gap-2">
                    <Pill className="border-cyan-500/25 bg-cyan-500/10 text-cyan-300">modeled</Pill>
                    <Pill className="border-gold/25 bg-gold/10 text-gold">{load.phase}</Pill>
                  </div>
                </div>
                <div className="mt-3 space-y-2.5">
                  {[
                    { label: 'CPU', value: `${load.cpuPct}%`, bar: load.cpuPct, color: load.cpuPct > 75 ? RED : CYAN },
                    { label: 'Memory', value: `${fmt(load.memoryMb)} MB`, bar: Math.min(100, load.memoryMb / 8), color: PURPLE },
                    { label: 'Latency', value: `${load.latencyMs} ms`, bar: Math.min(100, load.latencyMs), color: GOLD },
                    { label: 'Progress', value: `${load.progress}%`, bar: load.progress, color: GREEN },
                  ].map((row) => (
                    <div key={row.label} className="grid grid-cols-[64px_1fr_70px] items-center gap-2">
                      <span className="text-[9px] font-bold uppercase tracking-wider text-white/35">{row.label}</span>
                      <ProgressBar value={row.bar} color={row.color} />
                      <span className="text-right font-mono text-[10px] font-bold text-white/60">{row.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
        <p className="mt-3 text-[10px] leading-relaxed text-white/30">{frame.note}</p>
      </Panel>
    </>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   PERFORMANCE TAB
   ═══════════════════════════════════════════════════════════════════════════ */

export function PerformanceTab({ benchmark }: { benchmark: PerformanceBenchmarkPayload | undefined }) {
  if (!benchmark || !benchmark.available) {
    return (
      <Panel className="p-8">
        <EmptyBlock label="Performance benchmark requires discovered crypto inventory. Run discovery scans so the projection can model your real algorithm mix." />
      </Panel>
    )
  }

  const mix = benchmark.algorithmMix
  return (
    <>
      <Panel className="border-sky-400/20 bg-sky-500/[0.02] p-5">
        <SectionHead icon={BarChart3} suffix={<Pill className="border-sky-400/25 bg-sky-500/10 text-sky-300">{fmt(benchmark.sampleSize)} inventory records</Pill>}>
          Benchmark Methodology
        </SectionHead>
        <p className="text-xs leading-relaxed text-white/55">{benchmark.methodology}</p>
        {/* These are PREVALENCE shares — the fraction of inventory records that
            mention each family — not a partition. One cipher suite record
            (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) counts toward RSA, ECC and
            symmetric at once, so they overlap and do not sum to 100%. Presenting
            them as a "mix" invited exactly that arithmetic. Rendered as
            independent bars rather than one stacked bar for the same reason. */}
        <div className="mt-4">
          <div className="mb-1.5 text-[9px] font-bold uppercase tracking-wider text-white/30">
            Algorithm Prevalence
            <span className="ml-1.5 normal-case tracking-normal text-white/25">· share of {fmt(benchmark.sampleSize)} inventory records mentioning each family (records can match more than one, so these overlap)</span>
          </div>
          <div className="space-y-1.5">
            {[
              { share: mix.rsaSharePct, color: RED, label: 'RSA' },
              { share: mix.eccSharePct, color: ORANGE, label: 'ECC / EC-DH' },
              { share: mix.pqcSharePct, color: GREEN, label: 'PQC (ML-KEM/ML-DSA)' },
              { share: mix.symmetricSharePct, color: BLUE, label: 'Symmetric (AES)' },
              ...(mix.weakSharePct ? [{ share: mix.weakSharePct, color: PURPLE, label: 'Deprecated (3DES/RC4/SHA-1)' }] : []),
            ].map((seg) => (
              <div key={seg.label} className="grid grid-cols-[150px_1fr_38px] items-center gap-2">
                <span className="flex items-center gap-1.5 text-[10px] font-bold text-white/45">
                  <span className="h-2 w-2 rounded-full" style={{ background: seg.color }} />
                  {seg.label}
                </span>
                <span className="h-2 w-full overflow-hidden rounded-full bg-white/5">
                  <span className="block h-full rounded-full" style={{ width: `${Math.max(0, Math.min(100, seg.share))}%`, background: seg.color }} />
                </span>
                <span className="text-right font-mono text-[10px] text-white/45">{seg.share}%</span>
              </div>
            ))}
          </div>
        </div>
      </Panel>

      <Panel className="p-5">
        <SectionHead icon={Gauge}>Before vs After Migration — Projected Impact</SectionHead>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {benchmark.metrics.map((metric) => {
            const worse = !metric.improved
            const maxValue = Math.max(metric.before, metric.after, 1)
            return (
              <div key={metric.id} className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="truncate text-xs font-bold text-white/85">{metric.label}</div>
                    <div className="mt-0.5 text-[9px] font-bold uppercase tracking-wider text-white/25">{metric.unit}</div>
                  </div>
                  <Pill className={cn(worse ? 'border-orange-500/25 bg-orange-500/10 text-orange-300' : 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300')}>
                    {metric.deltaPct > 0 ? '+' : ''}{metric.deltaPct}%
                  </Pill>
                </div>
                <div className="mt-3 space-y-2">
                  <div className="grid grid-cols-[52px_1fr_76px] items-center gap-2">
                    <span className="text-[9px] font-bold uppercase text-white/35">Before</span>
                    <ProgressBar value={(metric.before / maxValue) * 100} color={ORANGE} />
                    <span className="text-right font-mono text-[10px] font-bold text-white/60">{metric.before}</span>
                  </div>
                  <div className="grid grid-cols-[52px_1fr_76px] items-center gap-2">
                    <span className="text-[9px] font-bold uppercase text-white/35">After</span>
                    <ProgressBar value={(metric.after / maxValue) * 100} color={metric.improved ? GREEN : GOLD} />
                    <span className="text-right font-mono text-[10px] font-bold text-white/60">{metric.after}</span>
                  </div>
                </div>
                <p className="mt-2.5 text-[10px] leading-relaxed text-white/35">{metric.note}</p>
              </div>
            )
          })}
        </div>
      </Panel>
    </>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   VALIDATION TAB — compatibility + security validation + failure prediction
   ═══════════════════════════════════════════════════════════════════════════ */

export function ValidationTab({ summary, riskFactors, failurePrediction, sophia }: {
  summary: SandboxSummary
  riskFactors: RiskFactor[]
  failurePrediction: FailurePredictionPayload | undefined
  sophia: SophiaPayload | undefined
}) {
  const predictions = failurePrediction?.predictions || []
  return (
    <>
      <div className="grid gap-4 lg:grid-cols-[340px_1fr]">
        <Panel className="p-5">
          <SectionHead icon={Target}>Validation Scores</SectionHead>
          <div className="grid grid-cols-1 gap-2">
            <div className="relative flex justify-center py-2"><ScoreGauge value={sophia?.compatibilityScorePct ?? 0} size={120} label="Compatibility" /></div>
            <div className="grid grid-cols-2 gap-2">
              <div className="relative flex justify-center py-2"><ScoreGauge value={summary.quantumRiskScore} size={96} label="Quantum Risk ↓" lowerBetter /></div>
              <div className="relative flex justify-center py-2"><ScoreGauge value={100 - (failurePrediction?.overallFailureProbabilityPct ?? 0)} size={96} label="Success Odds" /></div>
            </div>
          </div>
          <div className="mt-3 rounded-lg border border-white/8 bg-white/[0.02] p-3 text-center">
            <div className="text-[9px] font-bold uppercase tracking-wider text-white/30">Predicted Migration Failure Probability</div>
            <div className="mt-1 font-mono text-2xl font-black" style={{ color: (failurePrediction?.overallFailureProbabilityPct ?? 0) > 50 ? RED : (failurePrediction?.overallFailureProbabilityPct ?? 0) > 25 ? ORANGE : GREEN }}>
              {pct(failurePrediction?.overallFailureProbabilityPct ?? 0)}
            </div>
          </div>
        </Panel>

        <Panel className="p-5">
          <SectionHead icon={ShieldAlert} suffix={<Pill className="border-white/10 bg-white/5 text-white/40">{fmt(predictions.length)} predictions</Pill>}>
            Failure Prediction Engine
          </SectionHead>
          {predictions.length === 0 ? (
            <EmptyBlock label="No failure predictions — either no evidence has been discovered yet, or no failure signatures were found in your inventory." />
          ) : (
            <div className="max-h-[520px] space-y-2.5 overflow-y-auto pr-1 scrollbar-thin scrollbar-track-transparent scrollbar-thumb-white/10">
              {predictions.map((prediction) => (
                <div key={prediction.id} className={cn('rounded-xl border p-4',
                  prediction.severity === 'critical' ? 'border-red-500/20 bg-red-500/[0.03]' : prediction.severity === 'high' ? 'border-orange-500/20 bg-orange-500/[0.03]' : 'border-white/8 bg-white/[0.015]')}>
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-bold text-white/90">{prediction.label}</span>
                        <Pill className={riskBadge(prediction.severity)}>{prediction.severity}</Pill>
                      </div>
                      <div className="mt-1 text-[11px] leading-relaxed text-white/45">{prediction.evidence}</div>
                    </div>
                    <div className="text-right">
                      <div className="font-mono text-xl font-black" style={{ color: prediction.probabilityPct >= 60 ? RED : prediction.probabilityPct >= 30 ? ORANGE : GOLD }}>{prediction.probabilityPct}%</div>
                      <div className="text-[8px] font-bold uppercase tracking-wider text-white/25">probability</div>
                    </div>
                  </div>
                  <div className="mt-2"><ProgressBar value={prediction.probabilityPct} color={prediction.probabilityPct >= 60 ? RED : prediction.probabilityPct >= 30 ? ORANGE : GOLD} /></div>
                  {prediction.affectedAssets.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {prediction.affectedAssets.map((asset) => <span key={asset}><Pill className="border-white/10 bg-white/5 text-white/45">{asset}</Pill></span>)}
                    </div>
                  )}
                  <div className="mt-2 flex items-start gap-2 rounded-lg border border-emerald-500/15 bg-emerald-500/[0.04] px-3 py-2 text-[11px] text-emerald-200/80">
                    <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                    {prediction.recommendation}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel className="p-5">
          <SectionHead icon={BarChart3}>Risk Factors & Impact Analysis</SectionHead>
          {riskFactors.length === 0 ? (
            <EmptyBlock label="No risk factors detected. Run discovery scans to identify quantum-vulnerable assets." />
          ) : (
            <div className="space-y-2.5">
              {riskFactors.map((rf) => (
                <div key={rf.label} className="flex items-center gap-3 rounded-lg border border-white/6 bg-white/[0.015] p-3">
                  <div className={cn('flex h-8 w-8 items-center justify-center rounded-lg border',
                    rf.severity === 'critical' ? 'border-red-500/30 bg-red-500/10' : rf.severity === 'high' ? 'border-orange-500/30 bg-orange-500/10' : 'border-amber-500/30 bg-amber-500/10')}>
                    <AlertTriangle className={cn('h-4 w-4', rf.severity === 'critical' ? 'text-red-400' : rf.severity === 'high' ? 'text-orange-400' : 'text-amber-400')} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-bold text-white/80">{rf.label}</div>
                    <div className="mt-0.5 flex items-center gap-2">
                      <Pill className={riskBadge(rf.severity)}>{rf.severity}</Pill>
                      <span className="text-[10px] text-white/35">Impact: {rf.impact}</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="font-mono text-2xl font-black" style={{ color: rf.severity === 'critical' ? RED : rf.severity === 'high' ? ORANGE : GOLD }}>{fmt(rf.count)}</div>
                    <div className="text-[9px] font-bold text-white/30">DETECTED</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel className="p-5">
          <SectionHead icon={ShieldCheck}>Security Validation Summary</SectionHead>
          <div className="grid gap-3 sm:grid-cols-2">
            {[
              { label: 'HNDL Exposure', value: summary.criticalExposures > 0 ? 'Active' : 'Mitigated', color: summary.criticalExposures > 0 ? RED : GREEN, detail: `${fmt(summary.criticalExposures)} critical exposure(s)` },
              { label: 'Downgrade Resistance', value: summary.highExposures > 2 ? 'Weak' : 'Validated', color: summary.highExposures > 2 ? ORANGE : GREEN, detail: `${fmt(summary.highExposures)} high exposure(s)` },
              { label: 'Certificate Posture', value: summary.certsNeedingRotation > 0 ? 'At Risk' : 'Healthy', color: summary.certsNeedingRotation > 0 ? GOLD : GREEN, detail: `${fmt(summary.expiringCerts)} expiring · ${fmt(summary.nonPqcCerts)} classical` },
              { label: 'Crypto Agility', value: pct(summary.pqcReadiness), color: summary.pqcReadiness >= 70 ? GREEN : GOLD, detail: 'PQC readiness across inventory' },
              { label: 'Open Vulnerabilities', value: fmt(summary.openVulnerabilities), color: summary.openVulnerabilities > 0 ? ORANGE : GREEN, detail: 'Unresolved scanner findings' },
              { label: 'Failed Workflows', value: fmt(summary.failedWorkflows), color: summary.failedWorkflows > 0 ? RED : GREEN, detail: summary.failedWorkflows > 0 ? 'Retry required before approval' : 'No failed migrations' },
            ].map((item) => (
              <div key={item.label} className="rounded-lg border border-white/8 bg-white/[0.02] p-3">
                <div className="text-[9px] font-bold uppercase tracking-wider text-white/30">{item.label}</div>
                <div className="mt-1 font-mono text-lg font-black" style={{ color: item.color }}>{item.value}</div>
                <div className="mt-0.5 text-[10px] text-white/35">{item.detail}</div>
              </div>
            ))}
          </div>
          {sophia && sophia.rootCauses.length > 0 && (
            <div className="mt-4">
              <div className="mb-1.5 text-[9px] font-bold uppercase tracking-wider text-white/30">Root Cause Analysis</div>
              <div className="space-y-1.5">
                {sophia.rootCauses.map((cause) => (
                  <div key={cause} className="flex items-start gap-2 rounded-lg border border-white/6 bg-white/[0.02] px-3 py-2 text-[11px] leading-relaxed text-white/55">
                    <Shield className="mt-0.5 h-3.5 w-3.5 shrink-0 text-gold" />
                    {cause}
                  </div>
                ))}
              </div>
            </div>
          )}
        </Panel>
      </div>
    </>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   REPORTS TAB — 9 report types × PDF / Word / JSON / CSV
   ═══════════════════════════════════════════════════════════════════════════ */

export function ReportsTab({ snapshot, onNotice }: {
  snapshot: SandboxSnapshot
  onNotice: (kind: 'success' | 'error' | 'info', message: string) => void
}) {
  const { session } = useAuth()
  const token = session?.access_token
  const [pending, setPending] = useState<string | null>(null)

  const stamp = new Date().toISOString().slice(0, 10)

  const exportServer = async (type: SandboxReportType, format: 'json' | 'csv') => {
    if (!token) return
    const key = `${type}:${format}`
    setPending(key)
    try {
      const r = await fetch(`/api/v1/sandbox/export?format=${format}&reportType=${type}`, { headers: { Authorization: `Bearer ${token}` } })
      if (!r.ok) {
        const payload = await r.json().catch(() => ({}))
        throw new Error(payload?.error?.message || `Export failed (${r.status})`)
      }
      downloadBlob(`qguard-sandbox-${type}-${stamp}.${format}`, await r.blob())
      onNotice('success', `${format.toUpperCase()} ${type} report generated.`)
    } catch (err) {
      onNotice('error', err instanceof Error ? err.message : 'Export failed')
    } finally {
      setPending(null)
    }
  }

  const exportClient = async (type: SandboxReportType, format: 'pdf' | 'docx') => {
    const key = `${type}:${format}`
    setPending(key)
    try {
      const doc = buildSandboxReportDoc(snapshot, type)
      const blob = format === 'pdf' ? await renderSandboxReportPdf(doc) : await renderSandboxReportDocx(doc)
      downloadBlob(`qguard-sandbox-${type}-${stamp}.${format}`, blob)
      onNotice('success', `${format === 'pdf' ? 'PDF' : 'Word'} ${type} report generated.`)
    } catch (err) {
      onNotice('error', err instanceof Error ? err.message : 'Report rendering failed')
    } finally {
      setPending(null)
    }
  }

  return (
    <>
      <Panel className="p-5">
        <SectionHead icon={FileText} suffix={<Pill className="border-white/10 bg-white/5 text-white/40">snapshot {relTime(snapshot.generatedAt)}</Pill>}>
          Enterprise Report Center
        </SectionHead>
        <p className="mb-4 text-xs leading-relaxed text-white/40">
          Every report is generated from the live sandbox snapshot — real assets, real simulations, real compliance evidence.
          PDF and Word render locally in your browser; JSON and CSV export from the API with full audit logging.
        </p>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {SANDBOX_REPORT_TYPES.map((report) => (
            <div key={report.id} className="rounded-xl border border-white/8 bg-white/[0.02] p-4 transition hover:border-gold/25">
              <div className="flex items-start gap-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-gold/25 bg-gold/10">
                  <FileText className="h-4.5 w-4.5 text-gold" />
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-bold text-white/90">{report.label}</div>
                  <div className="mt-0.5 text-[10px] leading-relaxed text-white/40">{report.description}</div>
                </div>
              </div>
              <div className="mt-3 grid grid-cols-4 gap-1.5">
                {([
                  { id: 'pdf', label: pending === `${report.id}:pdf` ? '…' : 'PDF', run: () => exportClient(report.id, 'pdf') },
                  { id: 'docx', label: pending === `${report.id}:docx` ? '…' : 'Word', run: () => exportClient(report.id, 'docx') },
                  { id: 'json', label: pending === `${report.id}:json` ? '…' : 'JSON', run: () => exportServer(report.id, 'json') },
                  { id: 'csv', label: pending === `${report.id}:csv` ? '…' : 'CSV', run: () => exportServer(report.id, 'csv') },
                ]).map((fmtBtn) => (
                  <button
                    key={fmtBtn.id}
                    type="button"
                    onClick={fmtBtn.run}
                    disabled={pending !== null}
                    className={cn('flex items-center justify-center gap-1 rounded-lg border border-white/10 bg-white/[0.03] py-1.5 text-[10px] font-bold text-white/60 transition hover:border-gold/35 hover:text-gold', pending !== null && 'pointer-events-none opacity-40')}
                  >
                    <Download className="h-3 w-3" />
                    {fmtBtn.label}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel className="p-5">
        <SectionHead icon={ShieldCheck}>Report Integrity</SectionHead>
        <div className="grid gap-3 sm:grid-cols-3">
          {[
            { label: 'Data Source', value: 'Live tenant snapshot', detail: 'Assets, simulations, compliance, and twin intelligence from the authenticated tenant scope only.' },
            { label: 'Audit Trail', value: 'Server-side logged', detail: 'JSON/CSV exports run through /api/v1/sandbox/export with authentication and tenant isolation.' },
            { label: 'Production Impact', value: 'None', detail: 'Reports read simulation evidence — no production system is queried or modified during generation.' },
          ].map((item) => (
            <div key={item.label} className="rounded-lg border border-white/8 bg-white/[0.02] p-4">
              <div className="text-[9px] font-bold uppercase tracking-wider text-white/30">{item.label}</div>
              <div className="mt-1 text-sm font-black text-emerald-300">{item.value}</div>
              <div className="mt-1 text-[10px] leading-relaxed text-white/35">{item.detail}</div>
            </div>
          ))}
        </div>
      </Panel>
    </>
  )
}
