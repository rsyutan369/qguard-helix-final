import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  Award,
  Calendar,
  Check,
  ChevronDown,
  ChevronRight,
  Clock,
  Download,
  FileSpreadsheet,
  FileText,
  GitBranch,
  Layers,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  Rocket,
  Search,
  Shield,
  Sparkles,
  Target,
  TrendingUp,
  Wifi,
  WifiOff,
} from 'lucide-react';
import {
  useMigrationPlanner,
  type MigrationPlannerPriority,
  type MigrationPlannerRangeKey,
  type MigrationPlannerScenario,
} from '@/hooks/use-migration-planner';

const rangeOptions: Array<{ key: MigrationPlannerRangeKey; label: string; detail: string }> = [
  { key: '7d', label: 'Last 7 Days', detail: 'Operational window' },
  { key: '30d', label: 'Last 30 Days', detail: 'Planning window' },
  { key: '90d', label: 'Last 90 Days', detail: 'Quarter view' },
  { key: 'all', label: 'All Time', detail: 'Full posture' },
];

const stepIcons = [Search, FileText, GitBranch, Rocket, Shield, Award];

const cx = (...classes: Array<string | false | null | undefined>) => classes.filter(Boolean).join(' ');

function integer(value: number) {
  return Math.round(Number(value) || 0).toLocaleString();
}

function pct(value: number) {
  return `${Math.max(0, Math.min(100, Math.round(Number(value) || 0)))}%`;
}

function readableTime(value?: string | null) {
  if (!value) return 'Awaiting telemetry';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Awaiting telemetry';
  return date.toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function panelClass(extra = '') {
  return cx(
    'relative isolate overflow-hidden rounded-xl border p-5 transition-all duration-300',
    'border-white/55 bg-white/68 text-slate-950 shadow-[0_14px_45px_rgba(15,23,42,0.10)] backdrop-blur-2xl',
    'hover:-translate-y-0.5 hover:border-cyan-300/70 hover:bg-white/78 hover:shadow-[0_20px_70px_rgba(34,211,238,0.22),0_0_0_1px_rgba(34,211,238,0.14)]',
    'dark:border-[#FFD36B]/20 dark:bg-[#0f1428]/52 dark:text-white dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.08),0_0_40px_rgba(255,211,107,0.12)]',
    'dark:hover:border-[#FFD36B]/48 dark:hover:bg-[#121a32]/68 dark:hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.12),0_22px_80px_rgba(255,211,107,0.20)]',
    'before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-cyan-300/60 before:to-transparent',
    'dark:before:via-[#FFF4C0]/70',
    'after:pointer-events-none after:absolute after:inset-0 after:bg-[radial-gradient(circle_at_50%_0%,rgba(34,211,238,0.16),transparent_58%)] after:opacity-0 after:transition-opacity after:duration-300 hover:after:opacity-100',
    'dark:after:bg-[radial-gradient(circle_at_50%_0%,rgba(255,211,107,0.18),transparent_58%)]',
    extra,
  );
}

function ActionButton({
  icon: Icon,
  title,
  subtitle,
  primary,
  busy,
  onClick,
}: {
  icon: typeof Plus;
  title: string;
  subtitle: string;
  primary?: boolean;
  busy?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      className={cx(
        'flex shrink-0 items-center gap-2 rounded-lg border px-4 py-2.5 text-left transition-all disabled:cursor-not-allowed disabled:opacity-60',
        primary
          ? 'border-cyan-400/55 bg-cyan-400/15 text-slate-950 hover:bg-cyan-400/25 dark:border-[#FFD36B]/35 dark:bg-[#FFD36B]/12 dark:text-white dark:hover:bg-[#FFD36B]/20'
          : 'border-slate-200 bg-white/70 text-slate-900 hover:border-cyan-400/50 hover:bg-cyan-50 dark:border-white/10 dark:bg-white/5 dark:text-white dark:hover:border-[#FFD36B]/30 dark:hover:bg-white/10',
      )}
    >
      {busy ? <Loader2 className="h-4 w-4 animate-spin text-cyan-500 dark:text-[#FFD36B]" /> : <Icon className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />}
      <span className="leading-none">
        <span className={cx('block text-[10px] font-black uppercase tracking-wider', primary ? 'text-cyan-700 dark:text-[#FFD36B]' : 'text-slate-900 dark:text-white')}>
          {title}
        </span>
        <span className="mt-0.5 block text-[9px] font-bold uppercase text-slate-500 dark:text-white/42">{subtitle}</span>
      </span>
    </button>
  );
}

function RoadmapArrow({ className = '' }: { className?: string }) {
  return (
    <div className={cx('hidden shrink-0 items-center justify-center sm:flex', className)}>
      <svg className="h-5 w-10 overflow-visible" viewBox="0 0 40 20" fill="none" aria-hidden="true">
        <path d="M 3 10 L 36 10" className="stroke-cyan-300/35 dark:stroke-[#FFD36B]/20" strokeWidth="2" strokeLinecap="round" />
        <path d="M 29 4 L 36 10 L 29 16" className="stroke-cyan-300/45 dark:stroke-[#FFD36B]/28" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        <path
          d="M 3 10 L 36 10"
          stroke="#10b981"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeDasharray="9 26"
          className="migration-planner-flow-line"
        />
        <path
          d="M 29 4 L 36 10 L 29 16"
          stroke="#10b981"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="migration-planner-flow-glow"
        />
      </svg>
    </div>
  );
}

function RoadmapCurve() {
  return (
    <div className="hidden h-10 items-center justify-center sm:flex">
      <svg className="h-full w-[88%] overflow-visible" viewBox="0 0 520 42" fill="none" preserveAspectRatio="none" aria-hidden="true">
        <path d="M 455 2 C 455 24 74 18 74 40" className="stroke-cyan-300/25 dark:stroke-[#FFD36B]/18" strokeWidth="2" strokeDasharray="7 8" />
        <path d="M 66 32 L 74 40 L 84 34" className="stroke-cyan-300/35 dark:stroke-[#FFD36B]/24" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
        <path
          d="M 455 2 C 455 24 74 18 74 40"
          stroke="#10b981"
          strokeWidth="2.5"
          strokeDasharray="16 70"
          className="migration-planner-flow-curve"
        />
        <path d="M 66 32 L 74 40 L 84 34" stroke="#10b981" strokeWidth="2.5" fill="none" strokeLinecap="round" strokeLinejoin="round" className="migration-planner-flow-glow" />
      </svg>
    </div>
  );
}

function MetricTile({
  title,
  value,
  subtitle,
  tone,
  icon: Icon,
  ring,
}: {
  title: string;
  value: string;
  subtitle: string;
  tone: 'green' | 'red' | 'gold' | 'muted';
  icon: typeof Shield;
  ring?: number;
}) {
  const toneClass = tone === 'red'
    ? 'text-red-500 dark:text-red-300'
    : tone === 'green'
      ? 'text-emerald-600 dark:text-emerald-300'
      : tone === 'gold'
        ? 'text-amber-600 dark:text-[#FFD36B]'
        : 'text-slate-500 dark:text-white/45';

  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className={panelClass('flex items-center justify-between gap-4')}>
      <div className="min-w-0 space-y-1">
        <span className="block text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/40">{title}</span>
        <span className="block truncate text-2xl font-black leading-none text-slate-950 dark:text-white">{value}</span>
        <span className={cx('block pt-1 text-[10px] font-black uppercase tracking-wider', toneClass)}>{subtitle}</span>
      </div>
      <div className="grid h-12 w-12 shrink-0 place-items-center rounded-lg border border-cyan-400/25 bg-cyan-400/10 dark:border-[#FFD36B]/25 dark:bg-[#FFD36B]/10">
        {typeof ring === 'number' ? (
          <svg className="h-11 w-11 -rotate-90">
            <circle cx="22" cy="22" r="17" stroke="currentColor" strokeWidth="4" fill="none" className="text-slate-200 dark:text-white/10" />
            <circle
              cx="22"
              cy="22"
              r="17"
              stroke="currentColor"
              strokeWidth="4"
              fill="none"
              strokeDasharray={`${2 * Math.PI * 17}`}
              strokeDashoffset={`${2 * Math.PI * 17 * (1 - Math.max(0, Math.min(100, ring)) / 100)}`}
              strokeLinecap="round"
              className="text-cyan-500 dark:text-[#FFD36B]"
            />
          </svg>
        ) : (
          <Icon className="h-5 w-5 text-cyan-500 dark:text-[#FFD36B]" />
        )}
      </div>
    </motion.div>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-5 text-center text-xs font-bold text-slate-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-white/42">
      {text}
    </div>
  );
}

function PriorityDonut({ data }: { data: MigrationPlannerPriority[] }) {
  const total = Math.max(1, data.reduce((sum, item) => sum + item.value, 0));
  const radius = 55;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="flex flex-col gap-6 md:flex-row md:items-center">
      <div className="relative h-40 w-40 shrink-0">
        <svg className="h-full w-full -rotate-90">
          {data.map((item) => {
            const length = circumference * (item.value / total);
            const current = offset;
            offset += length;
            return (
              <circle
                key={item.name}
                cx="80"
                cy="80"
                r={radius}
                fill="none"
                stroke={item.color}
                strokeWidth="14"
                strokeDasharray={`${length} ${circumference}`}
                strokeDashoffset={-current}
                strokeLinecap="round"
              />
            );
          })}
        </svg>
        <div className="absolute inset-0 grid place-items-center text-center">
          <div>
            <div className="text-2xl font-black text-slate-950 dark:text-white">{integer(total)}</div>
            <div className="text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">Assets</div>
          </div>
        </div>
      </div>
      <div className="min-w-0 flex-1 space-y-2">
        {data.length === 0 && <EmptyState text="No prioritized migration assets have been discovered yet." />}
        {data.map((item) => (
          <div key={item.name} className="flex items-center justify-between rounded-md border border-slate-200/70 bg-white/60 px-3 py-2 dark:border-white/8 dark:bg-white/[0.03]">
            <span className="inline-flex items-center gap-2 text-xs font-black uppercase text-slate-700 dark:text-white/70">
              <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: item.color }} />
              {item.name}
            </span>
            <span className="font-mono text-xs font-black text-slate-900 dark:text-white">
              {integer(item.value)} <span className="text-slate-400 dark:text-white/35">({item.percent})</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function TrendChart({ points }: { points: Array<{ day: string; value: number }> }) {
  const safePoints = points.length ? points : [{ day: 'Now', value: 0 }];
  const width = 420;
  const height = 160;
  const left = 24;
  const right = width - 24;
  const top = 14;
  const bottom = height - 28;
  const xFor = (index: number) => left + (safePoints.length <= 1 ? 0 : (index / (safePoints.length - 1)) * (right - left));
  const yFor = (value: number) => bottom - (Math.max(0, Math.min(100, value)) / 100) * (bottom - top);
  const line = safePoints.map((point, index) => `${xFor(index)},${yFor(point.value)}`).join(' ');
  const area = `${line} ${xFor(safePoints.length - 1)},${bottom} ${xFor(0)},${bottom}`;

  return (
    <div className="relative h-48 overflow-hidden rounded-xl border border-slate-200 bg-slate-50/80 p-3 dark:border-white/8 dark:bg-white/[0.02]">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(14,165,233,0.10)_1px,transparent_1px),linear-gradient(90deg,rgba(14,165,233,0.10)_1px,transparent_1px)] bg-[size:24px_24px] dark:bg-[linear-gradient(rgba(255,255,255,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.035)_1px,transparent_1px)]" />
      <svg className="relative h-full w-full" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none">
        <defs>
          <linearGradient id="plannerTrendArea" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#00c5eb" stopOpacity="0.24" />
            <stop offset="100%" stopColor="#00c5eb" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0, 25, 50, 75, 100].map((tick) => (
          <line key={tick} x1={left} x2={right} y1={yFor(tick)} y2={yFor(tick)} stroke="currentColor" className="text-slate-200 dark:text-white/8" strokeDasharray="4 6" />
        ))}
        <polygon points={area} fill="url(#plannerTrendArea)" />
        <polyline points={line} fill="none" stroke="#00c5eb" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" />
        {safePoints.map((point, index) => (
          <g key={`${point.day}-${index}`}>
            <circle cx={xFor(index)} cy={yFor(point.value)} r="4" fill="#ffffff" stroke="#00c5eb" strokeWidth="2" />
            <text x={xFor(index)} y={height - 6} textAnchor="middle" fontSize="9" fill="currentColor" className="text-slate-500 dark:text-white/42">
              {point.day.replace(' ', '\u00a0')}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}

export default function MigrationPlanner() {
  const [range, setRange] = useState<MigrationPlannerRangeKey>('7d');
  const [rangeOpen, setRangeOpen] = useState(false);
  const [targetMode, setTargetMode] = useState('hybrid');
  const [optimization, setOptimization] = useState('risk');
  const [scenario, setScenario] = useState<MigrationPlannerScenario | null>(null);
  const [busyAction, setBusyAction] = useState<'create' | 'scenario' | 'export' | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const {
    snapshot,
    loading,
    connected,
    error,
    actionMessage,
    createPlan,
    runScenario,
    exportRoadmap,
    clearActionMessage,
  } = useMigrationPlanner(range);

  const metrics = useMemo(() => [
    {
      title: 'OVERALL PROGRESS',
      value: pct(snapshot.metrics.overallProgress),
      subtitle: snapshot.metrics.failedJobs ? `${integer(snapshot.metrics.failedJobs)} blocked job(s)` : 'On track',
      tone: snapshot.metrics.failedJobs ? 'red' as const : 'green' as const,
      icon: Activity,
      ring: snapshot.metrics.overallProgress,
    },
    {
      title: 'ASSETS IN SCOPE',
      value: integer(snapshot.metrics.assetsInScope),
      subtitle: `${snapshot.metrics.assetsInScopeDelta} vs previous window`,
      tone: 'green' as const,
      icon: Layers,
    },
    {
      title: 'MIGRATED ASSETS',
      value: integer(snapshot.metrics.migratedAssets),
      subtitle: `${snapshot.metrics.migratedDelta} vs previous window`,
      tone: 'green' as const,
      icon: Shield,
    },
    {
      title: 'HIGH PRIORITY ASSETS',
      value: integer(snapshot.metrics.highPriorityAssets),
      subtitle: `${snapshot.metrics.highPriorityDelta} vs previous window`,
      tone: snapshot.metrics.highPriorityAssets ? 'red' as const : 'green' as const,
      icon: AlertTriangle,
    },
    {
      title: 'RISKS REDUCED',
      value: pct(snapshot.metrics.riskReduced),
      subtitle: `${snapshot.metrics.riskReducedDelta} vs previous window`,
      tone: 'gold' as const,
      icon: TrendingUp,
    },
    {
      title: 'EST. COMPLETION',
      value: snapshot.metrics.estimatedCompletion,
      subtitle: `${integer(snapshot.metrics.remainingDays)} days remaining`,
      tone: 'muted' as const,
      icon: Calendar,
    },
  ], [snapshot]);

  const selectedRange = rangeOptions.find((item) => item.key === range) || rangeOptions[0];

  const handleCreatePlan = async () => {
    setActionError(null);
    setBusyAction('create');
    try {
      await createPlan();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to create plan');
    } finally {
      setBusyAction(null);
    }
  };

  const handleScenario = async () => {
    setActionError(null);
    setBusyAction('scenario');
    try {
      setScenario(await runScenario({ targetMode, optimization }));
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to run scenario');
    } finally {
      setBusyAction(null);
    }
  };

  const handleExport = async () => {
    setActionError(null);
    setBusyAction('export');
    try {
      await exportRoadmap('json');
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to export roadmap');
    } finally {
      setBusyAction(null);
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden p-4 text-slate-950 dark:text-white lg:p-8">
      <div className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle_at_top_left,rgba(0,197,235,0.18),transparent_34%),radial-gradient(circle_at_80%_0%,rgba(212,175,55,0.13),transparent_30%)] dark:bg-[radial-gradient(circle_at_top_left,rgba(255,211,107,0.10),transparent_32%),radial-gradient(circle_at_80%_0%,rgba(0,197,235,0.08),transparent_30%)]" />
      <div className="pointer-events-none absolute inset-0 -z-10 bg-[linear-gradient(rgba(14,165,233,0.07)_1px,transparent_1px),linear-gradient(90deg,rgba(14,165,233,0.07)_1px,transparent_1px)] bg-[size:32px_32px] opacity-60 dark:bg-[linear-gradient(rgba(255,211,107,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(255,211,107,0.035)_1px,transparent_1px)]" />

      <div className="space-y-8">
        <header className="flex flex-col gap-6 xl:flex-row xl:items-end xl:justify-between">
          <div>
            <div className="mb-3 flex flex-wrap items-center gap-3">
              <div className="grid h-11 w-11 place-items-center rounded-lg border border-cyan-400/30 bg-cyan-400/10 dark:border-[#FFD36B]/25 dark:bg-[#FFD36B]/10">
                <Layers className="h-6 w-6 text-cyan-500 dark:text-[#FFD36B]" />
              </div>
              <div>
                <h1 className="text-3xl font-black uppercase leading-none tracking-tight text-slate-950 dark:text-white">
                  Migration <span className="text-cyan-500 dark:text-[#FFD36B]">Planner</span>
                </h1>
                <p className="mt-2 text-sm font-medium text-slate-600 dark:text-white/52">
                  Real-time post-quantum roadmap planning from tenant assets, CBOM, exposures, scans, migration jobs, and validation evidence.
                </p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2 text-[10px] font-black uppercase tracking-widest text-slate-500 dark:text-white/38">
              <span>Latest scan: {readableTime(snapshot.source.latestScanAt)}</span>
              <span>/</span>
              <span>Activity: {readableTime(snapshot.source.latestActivityAt)}</span>
              <span className={connected ? 'text-emerald-500 dark:text-emerald-300' : 'text-amber-500 dark:text-[#FFD36B]'}>
                {connected ? 'Live stream active' : 'Sync fallback active'}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3 overflow-x-auto pb-1 xl:pb-0">
            <ActionButton icon={Plus} title="Create Plan" subtitle="Queue migration jobs" primary busy={busyAction === 'create'} onClick={handleCreatePlan} />
            <ActionButton icon={GitBranch} title="Scenario Builder" subtitle="What-if analysis" busy={busyAction === 'scenario'} onClick={handleScenario} />
            <ActionButton icon={Download} title="Export Roadmap" subtitle="Download report" busy={busyAction === 'export'} onClick={handleExport} />

            <div className="relative shrink-0">
              <button
                type="button"
                onClick={() => setRangeOpen((value) => !value)}
                className="flex items-center gap-3 rounded-lg border border-slate-200 bg-white/70 px-4 py-2.5 text-left text-slate-900 transition hover:border-cyan-400/50 dark:border-white/10 dark:bg-white/5 dark:text-white dark:hover:border-[#FFD36B]/30"
              >
                <Calendar className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
                <span className="leading-none">
                  <span className="block text-[10px] font-black uppercase tracking-wider">{selectedRange.label}</span>
                  <span className="mt-0.5 block text-[9px] font-bold uppercase text-slate-500 dark:text-white/42">{selectedRange.detail}</span>
                </span>
                <ChevronDown className={cx('h-3.5 w-3.5 transition-transform', rangeOpen && 'rotate-180')} />
              </button>
              {rangeOpen && (
                <div className="absolute right-0 top-full z-40 mt-2 w-52 overflow-hidden rounded-lg border border-slate-200 bg-white shadow-xl dark:border-white/10 dark:bg-[#07111f]">
                  {rangeOptions.map((option) => (
                    <button
                      key={option.key}
                      type="button"
                      onClick={() => {
                        setRange(option.key);
                        setRangeOpen(false);
                        clearActionMessage();
                      }}
                      className={cx('block w-full px-4 py-3 text-left transition hover:bg-cyan-50 dark:hover:bg-white/8', option.key === range && 'bg-cyan-50 dark:bg-[#FFD36B]/10')}
                    >
                      <span className="block text-xs font-black uppercase text-slate-900 dark:text-white">{option.label}</span>
                      <span className="mt-1 block text-[10px] font-bold text-slate-500 dark:text-white/45">{option.detail}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            <div className="grid h-11 w-11 place-items-center rounded-lg border border-slate-200 bg-white/70 text-cyan-500 dark:border-white/10 dark:bg-white/5 dark:text-[#FFD36B]" title={connected ? 'Realtime connected' : 'Realtime reconnecting'}>
              {connected ? <Wifi className="h-5 w-5" /> : loading ? <RefreshCw className="h-5 w-5 animate-spin" /> : <WifiOff className="h-5 w-5" />}
            </div>
          </div>
        </header>

        {(error || actionError || actionMessage || loading) && (
          <div className={cx(panelClass('flex items-center gap-3 py-3'), error || actionError ? 'border-red-400/35 dark:border-red-400/35' : '')}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin text-cyan-500 dark:text-[#FFD36B]" /> : <Sparkles className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />}
            <span className={cx('text-xs font-black', error || actionError ? 'text-red-500 dark:text-red-300' : 'text-slate-700 dark:text-white/72')}>
              {error || actionError || actionMessage || 'Synchronizing migration planner telemetry...'}
            </span>
          </div>
        )}

        <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-6">
          {metrics.map((metric) => <MetricTile key={metric.title} {...metric} />)}
        </div>

        <div className="space-y-8">
          <section className={panelClass('min-h-[430px]')}>
            <style>{`
              @keyframes migration-planner-travel-light {
                from { stroke-dashoffset: 35; }
                to { stroke-dashoffset: 0; }
              }
              @keyframes migration-planner-travel-curve {
                from { stroke-dashoffset: 86; }
                to { stroke-dashoffset: 0; }
              }
              @keyframes migration-planner-pulse-glow {
                0%, 100% { filter: drop-shadow(0 0 3px rgba(16, 185, 129, 0.35)); opacity: 0.7; }
                50% { filter: drop-shadow(0 0 12px rgba(16, 185, 129, 0.95)); opacity: 1; }
              }
              .migration-planner-flow-line {
                animation: migration-planner-travel-light 1.15s linear infinite, migration-planner-pulse-glow 2s ease-in-out infinite;
              }
              .migration-planner-flow-curve {
                animation: migration-planner-travel-curve 2.4s linear infinite, migration-planner-pulse-glow 2.2s ease-in-out infinite;
              }
              .migration-planner-flow-glow {
                animation: migration-planner-pulse-glow 2s ease-in-out infinite;
              }
              @media (prefers-reduced-motion: reduce) {
                .migration-planner-flow-line,
                .migration-planner-flow-curve,
                .migration-planner-flow-glow {
                  animation: none;
                }
              }
            `}</style>
            <div className="mb-6 flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
                <GitBranch className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
                Migration Roadmap
              </h2>
              <a href="/dashboard/migration-timeline" className="inline-flex items-center gap-1 text-[10px] font-black uppercase tracking-widest text-cyan-600 hover:text-cyan-500 dark:text-[#FFD36B]">
                Full Roadmap <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
            <div className="space-y-4 pt-1">
              {[snapshot.roadmapSteps.slice(0, 3), snapshot.roadmapSteps.slice(3, 6)].filter((row) => row.length > 0).map((row, rowIndex) => (
                <div key={`roadmap-row-${rowIndex}`} className="space-y-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-stretch">
                    {row.map((step, rowStepIndex) => {
                      const index = rowIndex * 3 + rowStepIndex;
                      const Icon = stepIcons[index] || GitBranch;
                      const active = step.status === 'active';
                      const complete = step.status === 'completed';
                      return (
                        <div key={step.name} className="flex flex-1 items-stretch gap-3">
                          <button
                            type="button"
                            className={cx(
                              'group relative min-h-[180px] w-full rounded-lg border p-5 text-left transition-all duration-300 hover:-translate-y-0.5',
                              active
                                ? 'border-cyan-400 bg-cyan-400/12 shadow-[0_0_22px_rgba(0,197,235,0.14)] dark:border-[#FFD36B] dark:bg-[#FFD36B]/12 dark:shadow-[0_0_24px_rgba(255,211,107,0.16)]'
                                : complete
                                  ? 'border-emerald-400/40 bg-emerald-400/8'
                                  : 'border-slate-200 bg-white/45 dark:border-white/8 dark:bg-white/[0.02]',
                            )}
                          >
                            {active && <div className="pointer-events-none absolute inset-0 rounded-lg bg-cyan-400/5 dark:bg-[#FFD36B]/5" />}
                            <div className="relative z-10 flex items-center justify-between gap-2">
                              <div className="grid h-11 w-11 place-items-center rounded-md border border-slate-200 bg-white/60 dark:border-white/10 dark:bg-white/5">
                                <Icon className={cx('h-5 w-5', active ? 'text-cyan-500 dark:text-[#FFD36B]' : complete ? 'text-emerald-500' : 'text-slate-400 dark:text-white/35')} />
                              </div>
                              {complete && <Check className="h-4 w-4 text-emerald-500" />}
                            </div>
                            <div className="relative z-10 mt-5 text-[10px] font-black uppercase tracking-widest text-slate-900 dark:text-white">{step.name}</div>
                            <div className="relative z-10 mt-5 h-2 overflow-hidden rounded-full bg-slate-200 dark:bg-white/8">
                              <div className="h-full rounded-full bg-cyan-500 transition-all duration-500 dark:bg-[#FFD36B]" style={{ width: pct(step.progress) }} />
                            </div>
                            <div className="relative z-10 mt-3 font-mono text-sm font-black text-cyan-600 dark:text-[#FFD36B]">{pct(step.progress)}</div>
                          </button>
                          {rowStepIndex < row.length - 1 && <RoadmapArrow className="w-10" />}
                        </div>
                      );
                    })}
                  </div>
                  {rowIndex === 0 && snapshot.roadmapSteps.length > 3 && <RoadmapCurve />}
                </div>
              ))}
              {snapshot.roadmapSteps.length === 0 && <EmptyState text="Migration roadmap will appear once migration telemetry is available." />}
            </div>
          </section>

          <section className={panelClass('min-h-[320px]')}>
            <div className="mb-5 flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
                <Target className="h-4 w-4 animate-pulse text-cyan-500 dark:text-[#FFD36B]" />
                Scenario Builder
              </h2>
              <span className="rounded-full border border-emerald-400/30 bg-emerald-400/10 px-2 py-1 text-[8px] font-black uppercase tracking-widest text-emerald-500 dark:text-emerald-300">
                AI Engine Active
              </span>
            </div>
            <div className="space-y-5">
              <div>
                <span className="mb-2 block text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/40">Simulation Target Mode</span>
                <div className="grid grid-cols-3 gap-2">
                  {[
                    ['hybrid', 'Hybrid'],
                    ['pure', 'Pure PQC'],
                    ['dual', 'Dual-Key'],
                  ].map(([key, label]) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => setTargetMode(key)}
                      className={cx('rounded-lg border px-3 py-2 text-[9px] font-black uppercase tracking-wider transition', targetMode === key ? 'border-cyan-400 bg-cyan-400/12 text-cyan-700 dark:border-[#FFD36B]/40 dark:bg-[#FFD36B]/12 dark:text-[#FFD36B]' : 'border-slate-200 bg-white/45 text-slate-500 dark:border-white/8 dark:bg-white/[0.02] dark:text-white/50')}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <span className="mb-2 block text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/40">Optimization Parameter</span>
                <div className="grid grid-cols-3 gap-2">
                  {[
                    ['latency', 'Min Latency'],
                    ['risk', 'Risk First'],
                    ['cost', 'Cost Opt.'],
                  ].map(([key, label]) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => setOptimization(key)}
                      className={cx('rounded-lg border px-3 py-2 text-[9px] font-black uppercase tracking-wider transition', optimization === key ? 'border-cyan-400 bg-cyan-400/12 text-cyan-700 dark:border-[#FFD36B]/40 dark:bg-[#FFD36B]/12 dark:text-[#FFD36B]' : 'border-slate-200 bg-white/45 text-slate-500 dark:border-white/8 dark:bg-white/[0.02] dark:text-white/50')}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-4 dark:border-white/8 dark:bg-black/30">
                <div className="mb-3 flex items-center justify-between text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/40">
                  <span>Simulated Recommendation</span>
                  <span className="text-cyan-600 dark:text-[#FFD36B]">{scenario ? `${scenario.confidence}% Confidence` : `${snapshot.simulation.confidence}% Confidence`}</span>
                </div>
                <div className="space-y-3">
                  {(scenario?.recommendations || snapshot.simulation.recommendations).slice(0, 2).map((item) => (
                    <div key={item.title} className="flex gap-2.5">
                      <Check className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                      <div>
                        <div className="text-xs font-black text-slate-900 dark:text-white">{item.title}</div>
                        <div className="mt-1 text-[10px] font-mono text-slate-500 dark:text-white/42">{item.detail}</div>
                      </div>
                    </div>
                  ))}
                  {!scenario && snapshot.simulation.recommendations.length === 0 && (
                    <div className="text-xs font-bold text-slate-500 dark:text-white/42">Run scans or add assets to generate a migration scenario.</div>
                  )}
                </div>
              </div>
              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={handleScenario}
                  disabled={busyAction === 'scenario'}
                  className="inline-flex flex-1 items-center justify-center gap-2 rounded-lg border border-cyan-400/40 bg-cyan-400/14 py-2 text-[10px] font-black uppercase tracking-widest text-cyan-700 transition hover:bg-cyan-400/22 disabled:opacity-60 dark:border-[#FFD36B]/35 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]"
                >
                  {busyAction === 'scenario' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
                  Run AI Simulation
                </button>
                <button
                  type="button"
                  onClick={handleExport}
                  className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-200 bg-white/60 px-4 py-2 text-[10px] font-black uppercase tracking-widest text-slate-600 transition hover:border-cyan-400/40 dark:border-white/10 dark:bg-white/5 dark:text-white/60"
                >
                  <FileSpreadsheet className="h-3.5 w-3.5" />
                  Playbook
                </button>
              </div>
            </div>
          </section>

          {scenario && (
            <section className={panelClass('border-cyan-400/35 dark:border-[#FFD36B]/30')}>
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <h2 className="text-sm font-black uppercase tracking-widest text-slate-950 dark:text-white">Scenario Result: {scenario.mode}</h2>
                  <p className="mt-2 max-w-3xl text-sm text-slate-600 dark:text-white/58">
                    Optimized for {scenario.optimization}. Estimated duration {scenario.estimatedDuration}; projected mitigation {scenario.riskMitigation}%.
                  </p>
                </div>
                <span className="w-fit rounded-full border border-emerald-400/30 bg-emerald-400/10 px-3 py-1 text-xs font-black text-emerald-600 dark:text-emerald-300">
                  {scenario.confidence}% CONFIDENCE
                </span>
              </div>
              <div className="mt-5 grid gap-3 lg:grid-cols-2">
                {scenario.playbook.map((item) => (
                  <div key={item} className="flex gap-3 rounded-lg border border-slate-200 bg-white/58 p-3 dark:border-white/8 dark:bg-white/[0.03]">
                    <Check className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                    <span className="text-sm font-semibold text-slate-700 dark:text-white/68">{item}</span>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>

        <div className="grid gap-8 xl:grid-cols-2">
          <section className={panelClass('min-h-[430px]')}>
            <h2 className="mb-5 flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
              <Calendar className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
              Migration Timeline
            </h2>
            <div className="space-y-5">
              <div className="grid grid-cols-5 border-b border-slate-200 pb-2 text-center text-[8px] font-black uppercase tracking-widest text-slate-400 dark:border-white/8 dark:text-white/30">
                <span>Now</span><span>+14d</span><span>+30d</span><span>+60d</span><span>+90d</span>
              </div>
              {snapshot.timelinePhases.map((phase) => (
                <div key={phase.name} className="space-y-1.5">
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="font-black text-slate-800 dark:text-white/82">{phase.name}</span>
                    <span className="font-mono text-slate-500 dark:text-white/42">{phase.dates}</span>
                  </div>
                  <div className="relative h-4 overflow-hidden rounded-full border border-slate-200 bg-slate-100 dark:border-white/8 dark:bg-white/[0.03]">
                    <div className={cx('absolute top-1/2 h-2.5 -translate-y-1/2 rounded-full', phase.color)} style={{ left: `${phase.start}%`, width: `${phase.width}%` }}>
                      <span className="absolute right-1 top-1/2 -translate-y-1/2">
                        {phase.state === 'completed' ? <Check className="h-2.5 w-2.5 text-white" /> : <Clock className="h-2.5 w-2.5 animate-pulse text-white/85" />}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
              {snapshot.timelinePhases.length === 0 && <EmptyState text="Migration timeline will appear once asset posture or migration jobs are available." />}
            </div>
          </section>

          <section className={panelClass('min-h-[430px]')}>
            <div className="mb-5 flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
                <Layers className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
                Top Assets by Migration Priority
              </h2>
              <a href="/dashboard/cbom" className="text-[10px] font-black uppercase tracking-widest text-cyan-600 hover:text-cyan-500 dark:text-[#FFD36B]">CBOM <ChevronRight className="inline h-3 w-3" /></a>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-left">
                <thead>
                  <tr className="border-b border-slate-200 text-[9px] font-black uppercase tracking-widest text-slate-500 dark:border-white/8 dark:text-white/40">
                    <th className="py-2.5">Asset</th>
                    <th>Type</th>
                    <th className="text-center">Risk</th>
                    <th className="text-center">Priority</th>
                    <th>Target</th>
                    <th className="text-center">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-white/5">
                  {snapshot.topAssets.slice(0, 8).map((asset) => (
                    <tr key={asset.id} className="hover:bg-cyan-50/60 dark:hover:bg-white/[0.03]">
                      <td className="py-3 pr-3">
                        <div className="text-xs font-black text-slate-900 dark:text-white">{asset.name}</div>
                        <div className="mt-0.5 text-[10px] font-mono text-slate-500 dark:text-white/35">{asset.owner} / {asset.environment}</div>
                      </td>
                      <td className="text-xs text-slate-600 dark:text-white/55">{asset.type}</td>
                      <td className="text-center font-mono text-sm font-black text-red-500 dark:text-red-300">{asset.risk}</td>
                      <td className="text-center">
                        <span className={cx('inline-flex rounded border px-2 py-0.5 text-[8px] font-black uppercase', asset.priorityColor)}>{asset.priority}</span>
                      </td>
                      <td className="text-[10px] font-mono text-slate-700 dark:text-white/68">{asset.targetSolution}</td>
                      <td className="text-center">
                        <span className={cx('inline-flex rounded border px-2 py-0.5 text-[8px] font-black uppercase', asset.statusColor)}>{asset.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {snapshot.topAssets.length === 0 && <EmptyState text="No migration-priority assets are available yet. Run discovery or CBOM scans to populate this planner." />}
            </div>
          </section>
        </div>

        <div className="grid gap-8 xl:grid-cols-2">
          <section className={panelClass('min-h-[390px]')}>
            <h2 className="mb-6 flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
              <AlertTriangle className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
              Priority Distribution
            </h2>
            <PriorityDonut data={snapshot.priorityDistribution} />
          </section>

          <section className={panelClass('min-h-[390px]')}>
            <h2 className="mb-5 flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
              <TrendingUp className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
              Risk Reduction Trend
            </h2>
            <TrendChart points={snapshot.riskTrendPoints} />
            <div className="mt-4 grid grid-cols-3 gap-3">
              {[
                ['This Window', pct(snapshot.metrics.riskReduced), snapshot.metrics.riskReducedDelta],
                ['Quantum Ready', integer(snapshot.compliance.quantumReadyAssets), 'secured assets'],
                ['Open Blockers', integer(snapshot.compliance.openBlockers), 'needs review'],
              ].map(([label, value, detail]) => (
                <div key={label} className="rounded-lg border border-slate-200 bg-white/58 p-3 text-center dark:border-white/8 dark:bg-white/[0.03]">
                  <span className="mb-1 block text-[8px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">{label}</span>
                  <span className="block font-mono text-lg font-black text-slate-950 dark:text-white">{value}</span>
                  <span className="block pt-0.5 text-[8px] font-black uppercase tracking-wider text-emerald-600 dark:text-emerald-300">{detail}</span>
                </div>
              ))}
            </div>
          </section>
        </div>

        <footer className={panelClass('grid gap-4 md:grid-cols-2 xl:grid-cols-6')}>
          {[
            { title: 'QUANTUM READY', desc: `${integer(snapshot.compliance.quantumReadyAssets)} assets secured`, icon: Shield },
            { title: 'POST-QUANTUM', desc: `${pct(snapshot.compliance.nistPqc)} NIST alignment`, icon: GitBranch },
            { title: 'RISK AWARE', desc: `${integer(snapshot.metrics.highPriorityAssets)} high-priority assets`, icon: Target },
            { title: 'OPERATIONAL', desc: `${integer(snapshot.metrics.activeJobs)} active jobs`, icon: Rocket },
            { title: 'COMPLIANT', desc: `${integer(snapshot.compliance.policyEvidence)} evidence rows`, icon: Award },
            { title: 'LIVE SYNC', desc: connected ? 'Realtime telemetry active' : 'Polling fallback active', icon: connected ? Wifi : WifiOff },
          ].map((item) => {
            const Icon = item.icon;
            return (
              <div key={item.title} className="text-center">
                <div className="mx-auto mb-2 grid h-10 w-10 place-items-center rounded-lg border border-cyan-400/25 bg-cyan-400/10 dark:border-[#FFD36B]/20 dark:bg-[#FFD36B]/10">
                  <Icon className="h-5 w-5 text-cyan-500 dark:text-[#FFD36B]" />
                </div>
                <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-950 dark:text-white">{item.title}</h4>
                <p className="mt-1 text-[9px] font-semibold text-slate-500 dark:text-white/40">{item.desc}</p>
              </div>
            );
          })}
        </footer>
      </div>
    </div>
  );
}
