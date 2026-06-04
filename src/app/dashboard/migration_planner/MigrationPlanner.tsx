import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
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
  FlaskConical,
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
  X,
} from 'lucide-react';
import {
  useMigrationPlanner,
  type MigrationPlannerAsset,
  type MigrationPlannerCreatePlanInput,
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

const currentAlgorithmOptions = ['RSA-2048', 'RSA-4096', 'ECC', 'ECDSA', 'ECDH'];
const targetAlgorithmOptions = ['ML-KEM-768', 'ML-KEM-1024', 'ML-DSA-65', 'ML-DSA-87', 'Hybrid TLS', 'Hybrid PKI'];
const deploymentStrategies = ['Pilot Deployment', 'Staged Rollout', 'Department-Based Rollout', 'Environment-Based Rollout', 'Full Enterprise Rollout'];
const baselineTagOptions = ['Web Application', 'Tenant Scope', 'Critical', 'High', 'Medium', 'Low', 'Service'];
const controlOptions = [
  ['rollback', 'Rollback'],
  ['validation', 'Validation Checks'],
  ['compatibility', 'Compatibility Testing'],
  ['hybridMode', 'Hybrid Mode'],
  ['continuousMonitoring', 'Continuous Monitoring'],
  ['complianceValidation', 'Compliance Validation'],
] as const;

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

function downloadJson(name: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${name}-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function createPlannerHandoffId() {
  return `planner-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function planIdFromResult(result: any, fallback?: string) {
  return String(result?.planId || result?.plan?.id || fallback || '').trim();
}

function fallbackHandoffDestination(action: MigrationPlannerCreatePlanInput['action'], planId: string) {
  const encodedPlanId = encodeURIComponent(planId || createPlannerHandoffId());
  if (action === 'sandbox') return `/dashboard/migration-sandbox?planId=${encodedPlanId}&source=migration-planner`;
  if (action === 'start') return `/dashboard/pqc-orchestration?planId=${encodedPlanId}&source=migration-planner`;
  return null;
}

function sameOriginDestination(candidate: unknown, fallback: string) {
  const raw = String(candidate || '').trim();
  if (!raw) return fallback;
  try {
    const base = typeof window !== 'undefined' ? window.location.origin : 'http://localhost';
    const url = new URL(raw, base);
    return url.origin === base ? `${url.pathname}${url.search}${url.hash}` : fallback;
  } catch {
    return raw.startsWith('/dashboard/') ? raw : fallback;
  }
}

function handoffDestination(action: MigrationPlannerCreatePlanInput['action'], result: any, fallbackPlanId?: string) {
  const planId = planIdFromResult(result, fallbackPlanId);
  const fallback = fallbackHandoffDestination(action, planId);
  if (!fallback) return null;
  const confirmed = action === 'sandbox'
    ? result?.sandboxUrl || result?.plan?.sandboxUrl
    : result?.orchestrationUrl || result?.plan?.orchestrationUrl;
  return sameOriginDestination(confirmed, fallback);
}

function navigateWithBrowserFallback(navigate: (to: string) => void, destination: string) {
  navigate(destination);
  if (typeof window === 'undefined') return;
  window.setTimeout(() => {
    try {
      const target = new URL(destination, window.location.origin);
      const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
      const expected = `${target.pathname}${target.search}${target.hash}`;
      if (current !== expected) window.location.assign(expected);
    } catch {
      window.location.assign(destination);
    }
  }, 150);
}

function riskBucket(asset: MigrationPlannerAsset) {
  if (asset.risk >= 85 || asset.priority === 'Critical') return 'critical';
  if (asset.risk >= 70 || asset.priority === 'High') return 'high';
  if (asset.risk >= 40 || asset.priority === 'Medium') return 'medium';
  return 'low';
}

function readinessBucket(asset: MigrationPlannerAsset) {
  if (asset.progress >= 100 || /ready|completed/i.test(asset.status)) return 'ready';
  if (/blocked|failed|non/i.test(asset.status) || asset.risk >= 70) return 'non-compliant';
  return 'not-ready';
}

function complexityLabel(score: number) {
  if (score >= 75) return 'High';
  if (score >= 45) return 'Medium';
  return score > 0 ? 'Low' : 'None';
}

function tagLabel(value: string) {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
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

function PlanWizardModal({
  assets,
  busy,
  busyAction,
  onClose,
  onSubmit,
}: {
  assets: MigrationPlannerAsset[];
  busy: boolean;
  busyAction?: MigrationPlannerCreatePlanInput['action'] | null;
  onClose: () => void;
  onSubmit: (input: MigrationPlannerCreatePlanInput) => Promise<void>;
}) {
  const [step, setStep] = useState(1);
  const [search, setSearch] = useState('');
  const [risk, setRisk] = useState('all');
  const [readiness, setReadiness] = useState('all');
  const [environment, setEnvironment] = useState('all');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set(assets.slice(0, 6).map((asset) => asset.assetId || asset.id).filter((id): id is string => Boolean(id))));
  const [currentAlgorithms, setCurrentAlgorithms] = useState<string[]>(currentAlgorithmOptions.slice(0, 3));
  const [targetAlgorithms, setTargetAlgorithms] = useState<string[]>(['ML-KEM-768', 'ML-DSA-65', 'Hybrid TLS']);
  const [deploymentStrategy, setDeploymentStrategy] = useState('Staged Rollout');
  const [controls, setControls] = useState({
    rollback: true,
    validation: true,
    compatibility: true,
    hybridMode: true,
    continuousMonitoring: true,
    complianceValidation: true,
  });
  const [tags, setTags] = useState<string[]>([]);

  const environments = useMemo(() => Array.from(new Set(assets.map((asset) => asset.environment).filter(Boolean))).sort(), [assets]);
  const tagOptions = useMemo(() => {
    const values = new Set<string>(baselineTagOptions);
    for (const asset of assets) {
      if (asset.type) values.add(tagLabel(asset.type));
      if (asset.environment) values.add(tagLabel(asset.environment));
      if (asset.priority) values.add(asset.priority);
    }
    return Array.from(values).slice(0, 14);
  }, [assets]);

  const filteredAssets = useMemo(() => assets.filter((asset) => {
    const haystack = `${asset.name} ${asset.type} ${asset.environment} ${asset.owner} ${asset.currentAlgorithm} ${asset.targetSolution}`.toLowerCase();
    return (!search || haystack.includes(search.toLowerCase()))
      && (risk === 'all' || riskBucket(asset) === risk)
      && (readiness === 'all' || readinessBucket(asset) === readiness)
      && (environment === 'all' || asset.environment === environment);
  }), [assets, environment, readiness, risk, search]);

  const selectedAssets = useMemo(() => assets.filter((asset) => selectedIds.has(asset.assetId || asset.id)), [assets, selectedIds]);
  const highRisk = selectedAssets.filter((asset) => asset.risk >= 70).length;
  const pqcReady = selectedAssets.filter((asset) => readinessBucket(asset) === 'ready').length;
  const nonCompliant = selectedAssets.filter((asset) => readinessBucket(asset) === 'non-compliant').length;
  const complexity = selectedAssets.length
    ? Math.min(100, Math.round((selectedAssets.reduce((sum, asset) => sum + asset.risk, 0) / selectedAssets.length) * 0.62 + selectedAssets.length * 3 + targetAlgorithms.length * 4))
    : 0;

  const toggleSelected = (asset: MigrationPlannerAsset) => {
    const id = asset.assetId || asset.id;
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleListValue = (value: string, values: string[], setter: (next: string[]) => void) => {
    setter(values.includes(value) ? values.filter((item) => item !== value) : [...values, value]);
  };

  const submit = (action: MigrationPlannerCreatePlanInput['action']) => onSubmit({
    action,
    assetIds: Array.from(selectedIds),
    selectedAssets,
    limit: Math.max(1, selectedIds.size),
    configuration: {
      currentAlgorithms,
      targetAlgorithms,
      deploymentStrategy,
      controls,
      tags,
    },
  });

  return (
    <div className="fixed inset-0 z-[90] bg-slate-950/72 backdrop-blur-xl">
      <div className="absolute inset-y-0 left-0 right-0 flex items-center justify-center p-3 lg:left-[260px]">
        <motion.div
          initial={{ opacity: 0, y: 24, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          className="max-h-[92vh] w-full max-w-7xl overflow-hidden rounded-xl border border-cyan-300/40 bg-white/92 text-slate-950 shadow-[0_24px_110px_rgba(15,23,42,0.42)] dark:border-[#FFD36B]/30 dark:bg-[#090f1f]/94 dark:text-white"
        >
        <div className="flex items-start justify-between gap-4 border-b border-slate-200/80 p-5 dark:border-white/10">
          <div>
            <div className="text-[10px] font-black uppercase tracking-[0.22em] text-cyan-600 dark:text-[#FFD36B]">Migration Plan Approval</div>
            <h2 className="mt-1 text-2xl font-black uppercase tracking-tight">Create Enterprise PQC Plan</h2>
          </div>
          <button type="button" onClick={onClose} className="grid h-9 w-9 place-items-center rounded-md border border-slate-200 text-slate-500 transition hover:border-cyan-400 hover:text-cyan-600 dark:border-white/10 dark:text-white/50 dark:hover:border-[#FFD36B]/50 dark:hover:text-[#FFD36B]" aria-label="Close migration plan wizard">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="grid gap-0 lg:grid-cols-[220px_minmax(0,1fr)]">
          <aside className="border-b border-slate-200/80 p-4 dark:border-white/10 lg:border-b-0 lg:border-r">
            <div className="space-y-2">
              {[
                [1, 'Asset Selection'],
                [2, 'Configuration'],
                [3, 'Summary'],
                [4, 'Approval'],
              ].map(([id, label]) => (
                <button
                  key={label}
                  type="button"
                  onClick={() => setStep(Number(id))}
                  className={cx(
                    'flex w-full items-center gap-3 rounded-lg border px-3 py-3 text-left text-[10px] font-black uppercase tracking-wider transition',
                    step === id
                      ? 'border-cyan-400 bg-cyan-400/12 text-cyan-700 dark:border-[#FFD36B]/45 dark:bg-[#FFD36B]/12 dark:text-[#FFD36B]'
                      : 'border-slate-200 bg-white/50 text-slate-500 hover:border-cyan-300 dark:border-white/8 dark:bg-white/[0.03] dark:text-white/45 dark:hover:border-[#FFD36B]/25',
                  )}
                >
                  <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full border border-current font-mono">{id}</span>
                  {label}
                </button>
              ))}
            </div>
          </aside>

          <div className="max-h-[72vh] overflow-y-auto p-5">
            {step === 1 && (
              <div className="space-y-5">
                <div className="grid gap-3 lg:grid-cols-[1fr_130px_150px_150px_auto_auto]">
                  <label className="relative block">
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                    <input value={search} onChange={(event) => setSearch(event.target.value)} className="h-10 w-full rounded-lg border border-slate-200 bg-white/70 pl-10 pr-3 text-sm outline-none focus:border-cyan-400 dark:border-white/10 dark:bg-black/25 dark:text-white" placeholder="Search assets" />
                  </label>
                  <select value={risk} onChange={(event) => setRisk(event.target.value)} className="h-10 rounded-lg border border-slate-200 bg-white/70 px-3 text-xs font-bold dark:border-white/10 dark:bg-black/25 dark:text-white">
                    <option value="all">All Risk</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <select value={readiness} onChange={(event) => setReadiness(event.target.value)} className="h-10 rounded-lg border border-slate-200 bg-white/70 px-3 text-xs font-bold dark:border-white/10 dark:bg-black/25 dark:text-white">
                    <option value="all">All Readiness</option>
                    <option value="ready">PQC Ready</option>
                    <option value="not-ready">Not Ready</option>
                    <option value="non-compliant">Non-Compliant</option>
                  </select>
                  <select value={environment} onChange={(event) => setEnvironment(event.target.value)} className="h-10 rounded-lg border border-slate-200 bg-white/70 px-3 text-xs font-bold dark:border-white/10 dark:bg-black/25 dark:text-white">
                    <option value="all">All Environments</option>
                    {environments.map((item) => <option key={item} value={item}>{item}</option>)}
                  </select>
                  <button type="button" onClick={() => setSelectedIds(new Set(filteredAssets.map((asset) => asset.assetId || asset.id)))} className="h-10 rounded-lg border border-cyan-400/40 bg-cyan-400/12 px-3 text-[10px] font-black uppercase tracking-wider text-cyan-700 dark:border-[#FFD36B]/35 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">Select Filtered</button>
                  <button type="button" onClick={() => setSelectedIds(new Set())} className="h-10 rounded-lg border border-slate-200 bg-white/60 px-3 text-[10px] font-black uppercase tracking-wider text-slate-600 dark:border-white/10 dark:bg-white/5 dark:text-white/55">Clear</button>
                </div>

                <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
                  {[
                    ['Selected', selectedAssets.length],
                    ['High Risk', highRisk],
                    ['PQC Ready', pqcReady],
                    ['Non-Compliant', nonCompliant],
                    ['Complexity', complexityLabel(complexity)],
                  ].map(([label, value]) => (
                    <div key={label} className="rounded-lg border border-slate-200 bg-white/65 p-3 dark:border-white/10 dark:bg-white/[0.04]">
                      <div className="text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">{label}</div>
                      <div className="mt-1 text-xl font-black text-slate-950 dark:text-white">{value}</div>
                    </div>
                  ))}
                </div>

                <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white/50 dark:border-white/10 dark:bg-black/20">
                  <table className="w-full min-w-[880px] text-left">
                    <thead>
                      <tr className="border-b border-slate-200 text-[9px] font-black uppercase tracking-widest text-slate-500 dark:border-white/10 dark:text-white/35">
                        <th className="w-12 px-3 py-3">Select</th>
                        <th>Asset</th>
                        <th>Type</th>
                        <th>Environment</th>
                        <th>Risk</th>
                        <th>Readiness</th>
                        <th>Tags</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-white/5">
                      {filteredAssets.map((asset) => {
                        const id = asset.assetId || asset.id;
                        const selected = selectedIds.has(id);
                        const ready = readinessBucket(asset);
                        return (
                          <tr key={id} className="hover:bg-cyan-50/60 dark:hover:bg-white/[0.03]">
                            <td className="px-3 py-3">
                              <input type="checkbox" checked={selected} onChange={() => toggleSelected(asset)} className="h-4 w-4 rounded border-slate-300 text-cyan-500" />
                            </td>
                            <td className="py-3 pr-4">
                              <div className="text-xs font-black text-slate-950 dark:text-white">{asset.name}</div>
                              <div className="mt-0.5 text-[10px] font-mono text-slate-500 dark:text-white/38">{asset.currentAlgorithm} - {asset.targetSolution}</div>
                            </td>
                            <td className="text-xs font-bold text-slate-600 dark:text-white/60">{asset.type}</td>
                            <td className="text-xs font-bold text-slate-600 dark:text-white/60">{asset.environment}</td>
                            <td><span className={cx('rounded border px-2 py-1 text-[9px] font-black uppercase', asset.priorityColor)}>{asset.risk}</span></td>
                            <td className="text-[10px] font-black uppercase tracking-wider text-slate-600 dark:text-white/55">{ready.replace('-', ' ')}</td>
                            <td>
                              <div className="flex flex-wrap gap-1">
                                {[asset.priority, asset.type, asset.environment].filter(Boolean).slice(0, 3).map((tag) => (
                                  <span key={tag} className="rounded border border-cyan-400/25 bg-cyan-400/10 px-2 py-0.5 text-[8px] font-black uppercase text-cyan-700 dark:border-[#FFD36B]/25 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">{tag}</span>
                                ))}
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  {filteredAssets.length === 0 && <EmptyState text="No discovered assets match the current filters." />}
                </div>
              </div>
            )}

            {step === 2 && (
              <div className="grid gap-5 xl:grid-cols-2">
                <section className={panelClass('p-4')}>
                  <h3 className="mb-4 text-[10px] font-black uppercase tracking-widest text-slate-600 dark:text-white/55">Current Algorithms</h3>
                  <div className="grid grid-cols-2 gap-2">
                    {currentAlgorithmOptions.map((item) => (
                      <button key={item} type="button" onClick={() => toggleListValue(item, currentAlgorithms, setCurrentAlgorithms)} className={cx('rounded-lg border px-3 py-2 text-[10px] font-black uppercase tracking-wider transition', currentAlgorithms.includes(item) ? 'border-cyan-400 bg-cyan-400/12 text-cyan-700 dark:border-[#FFD36B]/40 dark:bg-[#FFD36B]/12 dark:text-[#FFD36B]' : 'border-slate-200 bg-white/50 text-slate-500 dark:border-white/8 dark:bg-white/[0.03] dark:text-white/45')}>{item}</button>
                    ))}
                  </div>
                </section>

                <section className={panelClass('p-4')}>
                  <h3 className="mb-4 text-[10px] font-black uppercase tracking-widest text-slate-600 dark:text-white/55">Target Algorithms</h3>
                  <div className="grid grid-cols-2 gap-2">
                    {targetAlgorithmOptions.map((item) => (
                      <button key={item} type="button" onClick={() => toggleListValue(item, targetAlgorithms, setTargetAlgorithms)} className={cx('rounded-lg border px-3 py-2 text-[10px] font-black uppercase tracking-wider transition', targetAlgorithms.includes(item) ? 'border-cyan-400 bg-cyan-400/12 text-cyan-700 dark:border-[#FFD36B]/40 dark:bg-[#FFD36B]/12 dark:text-[#FFD36B]' : 'border-slate-200 bg-white/50 text-slate-500 dark:border-white/8 dark:bg-white/[0.03] dark:text-white/45')}>{item}</button>
                    ))}
                  </div>
                </section>

                <section className={panelClass('p-4 xl:col-span-2')}>
                  <h3 className="mb-4 text-[10px] font-black uppercase tracking-widest text-slate-600 dark:text-white/55">Deployment Strategy</h3>
                  <div className="grid gap-2 md:grid-cols-5">
                    {deploymentStrategies.map((item) => (
                      <button key={item} type="button" onClick={() => setDeploymentStrategy(item)} className={cx('min-h-14 rounded-lg border px-3 py-2 text-[10px] font-black uppercase tracking-wider transition', deploymentStrategy === item ? 'border-cyan-400 bg-cyan-400/12 text-cyan-700 dark:border-[#FFD36B]/40 dark:bg-[#FFD36B]/12 dark:text-[#FFD36B]' : 'border-slate-200 bg-white/50 text-slate-500 dark:border-white/8 dark:bg-white/[0.03] dark:text-white/45')}>{item}</button>
                    ))}
                  </div>
                </section>

                <section className={panelClass('p-4')}>
                  <h3 className="mb-4 text-[10px] font-black uppercase tracking-widest text-slate-600 dark:text-white/55">Migration Controls</h3>
                  <div className="space-y-2">
                    {controlOptions.map(([key, label]) => (
                      <label key={key} className="flex items-center justify-between rounded-lg border border-slate-200 bg-white/50 px-3 py-2 text-xs font-black uppercase tracking-wider dark:border-white/8 dark:bg-white/[0.03]">
                        <span>{label}</span>
                        <input type="checkbox" checked={controls[key]} onChange={(event) => setControls((current) => ({ ...current, [key]: event.target.checked }))} className="h-4 w-4" />
                      </label>
                    ))}
                  </div>
                </section>

                <section className={panelClass('p-4')}>
                  <h3 className="mb-4 text-[10px] font-black uppercase tracking-widest text-slate-600 dark:text-white/55">Asset Tags</h3>
                  <div className="flex flex-wrap gap-2">
                    {tagOptions.map((tag) => (
                      <button key={tag} type="button" onClick={() => toggleListValue(tag, tags, setTags)} className={cx('rounded-full border px-3 py-1.5 text-[9px] font-black uppercase tracking-wider transition', tags.includes(tag) ? 'border-cyan-400 bg-cyan-400/12 text-cyan-700 dark:border-[#FFD36B]/40 dark:bg-[#FFD36B]/12 dark:text-[#FFD36B]' : 'border-slate-200 bg-white/50 text-slate-500 dark:border-white/8 dark:bg-white/[0.03] dark:text-white/45')}>{tag}</button>
                    ))}
                    {tagOptions.length === 0 && <div className="text-xs font-bold text-slate-500 dark:text-white/42">No asset tags available from current telemetry.</div>}
                  </div>
                </section>
              </div>
            )}

            {step === 3 && (
              <div className="grid gap-5 xl:grid-cols-3">
                {[
                  ['Total Assets', selectedAssets.length],
                  ['Critical Assets', selectedAssets.filter((asset) => asset.priority === 'Critical').length],
                  ['High-Risk Assets', highRisk],
                  ['PQC Ready Assets', pqcReady],
                  ['Legacy Assets', nonCompliant],
                  ['Complexity Score', `${complexity}/100`],
                ].map(([label, value]) => (
                  <div key={label} className={panelClass('p-4')}>
                    <div className="text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">{label}</div>
                    <div className="mt-2 text-2xl font-black text-slate-950 dark:text-white">{value}</div>
                  </div>
                ))}
                <section className={panelClass('p-4 xl:col-span-3')}>
                  <h3 className="mb-4 text-[10px] font-black uppercase tracking-widest text-slate-600 dark:text-white/55">Migration Scope</h3>
                  <div className="grid gap-3 md:grid-cols-3">
                    {[
                      ['Selected Assets', `${selectedAssets.length}`],
                      ['Target Algorithms', targetAlgorithms.join(', ') || 'None selected'],
                      ['Migration Strategy', deploymentStrategy],
                      ['Estimated Duration', selectedAssets.length ? `${Math.max(1, selectedAssets.length * 2)}-${Math.max(3, selectedAssets.length * 4)} days` : 'No assets'],
                      ['Expected Downtime', controls.hybridMode ? 'Near-zero with hybrid cutover' : 'Maintenance windows required'],
                      ['Rollback Availability', controls.rollback ? 'Enabled' : 'Disabled'],
                      ['Compliance Validation', controls.complianceValidation ? 'Enabled' : 'Disabled'],
                    ].map(([label, value]) => (
                      <div key={label} className="rounded-lg border border-slate-200 bg-white/55 p-3 dark:border-white/8 dark:bg-white/[0.03]">
                        <div className="text-[8px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">{label}</div>
                        <div className="mt-1 text-xs font-black text-slate-900 dark:text-white">{value}</div>
                      </div>
                    ))}
                  </div>
                </section>
              </div>
            )}

            {step === 4 && (
              <div className="space-y-5">
                <section className={panelClass('p-5')}>
                  <div className="grid gap-3 md:grid-cols-5">
                    {[
                      ['Current Risk', selectedAssets.length ? Math.round(selectedAssets.reduce((sum, asset) => sum + asset.risk, 0) / selectedAssets.length) : 0],
                      ['Projected Reduction', `${Math.min(96, Math.round(complexity * 0.78))}%`],
                      ['HNDL Exposure', highRisk],
                      ['Compliance Impact', nonCompliant],
                      ['Complexity', `${complexity}/100`],
                    ].map(([label, value]) => (
                      <div key={label} className="rounded-lg border border-slate-200 bg-white/55 p-3 text-center dark:border-white/8 dark:bg-white/[0.03]">
                        <div className="text-[8px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">{label}</div>
                        <div className="mt-2 text-xl font-black text-slate-950 dark:text-white">{value}</div>
                      </div>
                    ))}
                  </div>
                </section>
                <div className="grid gap-3 md:grid-cols-5">
                  {[
                    { action: 'save', label: 'Save Plan', icon: FileText },
                    { action: 'export', label: 'Export Plan', icon: Download },
                    { action: 'schedule', label: 'Schedule Migration', icon: Calendar },
                    { action: 'sandbox', label: 'Send to Migration Sandbox', icon: FlaskConical },
                    { action: 'start', label: 'Start Migration', icon: Rocket },
                  ].map(({ action, label, icon: Icon }) => {
                    const isBusy = busyAction === action;
                    return (
                      <button
                        key={action}
                        type="button"
                        disabled={busy || selectedIds.size === 0}
                        onClick={() => submit(action as MigrationPlannerCreatePlanInput['action'])}
                        className={cx(
                          'flex min-h-24 items-center justify-center gap-3 rounded-xl border px-4 py-3 text-[11px] font-black uppercase tracking-widest transition disabled:cursor-not-allowed disabled:opacity-50',
                          action === 'start' || action === 'sandbox'
                            ? 'border-cyan-400 bg-cyan-400/16 text-cyan-800 hover:bg-cyan-400/24 dark:border-[#FFD36B]/55 dark:bg-[#FFD36B]/14 dark:text-[#FFD36B]'
                            : 'border-slate-200 bg-white/60 text-slate-700 hover:border-cyan-400/45 dark:border-white/10 dark:bg-white/[0.04] dark:text-white/70 dark:hover:border-[#FFD36B]/35',
                        )}
                      >
                        {isBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Icon className="h-4 w-4" />}
                        {isBusy && action === 'sandbox' ? 'Opening Sandbox' : label}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center justify-between border-t border-slate-200/80 p-4 dark:border-white/10">
          <button type="button" onClick={() => setStep((current) => Math.max(1, current - 1))} disabled={step === 1} className="rounded-lg border border-slate-200 bg-white/60 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-slate-600 disabled:opacity-40 dark:border-white/10 dark:bg-white/5 dark:text-white/55">Back</button>
          <div className="text-[10px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">{selectedAssets.length} selected / {assets.length} available</div>
          {step < 4 ? (
            <button type="button" onClick={() => setStep((current) => Math.min(4, current + 1))} disabled={step === 1 && selectedIds.size === 0} className="rounded-lg border border-cyan-400/45 bg-cyan-400/12 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-cyan-700 disabled:opacity-40 dark:border-[#FFD36B]/35 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">Next</button>
          ) : (
            <button type="button" onClick={() => submit('start')} disabled={busy || selectedIds.size === 0} className="inline-flex items-center gap-2 rounded-lg border border-cyan-400 bg-cyan-400/16 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-cyan-700 disabled:opacity-40 dark:border-[#FFD36B]/45 dark:bg-[#FFD36B]/14 dark:text-[#FFD36B]">
              {busyAction === 'start' && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              Start Migration
            </button>
          )}
        </div>
        </motion.div>
      </div>
    </div>
  );
}

export default function MigrationPlanner() {
  const navigate = useNavigate();
  const [range, setRange] = useState<MigrationPlannerRangeKey>('7d');
  const [rangeOpen, setRangeOpen] = useState(false);
  const [targetMode, setTargetMode] = useState('hybrid');
  const [optimization, setOptimization] = useState('risk');
  const [scenario, setScenario] = useState<MigrationPlannerScenario | null>(null);
  const [busyAction, setBusyAction] = useState<'create' | 'scenario' | 'export' | null>(null);
  const [wizardBusyAction, setWizardBusyAction] = useState<MigrationPlannerCreatePlanInput['action'] | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);
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

  const openCreatePlan = () => {
    setActionError(null);
    clearActionMessage();
    setWizardOpen(true);
  };

  const handleWizardSubmit = async (input: MigrationPlannerCreatePlanInput) => {
    const isHandoff = input.action === 'sandbox' || input.action === 'start';
    const planId = input.planId || (isHandoff ? createPlannerHandoffId() : undefined);
    const request = planId ? { ...input, planId } : input;
    const destination = isHandoff ? handoffDestination(input.action, null, planId) : null;
    setActionError(null);
    setBusyAction('create');
    setWizardBusyAction(input.action || 'save');
    try {
      const planPromise = createPlan(request);
      if (destination) {
        setWizardOpen(false);
        navigateWithBrowserFallback(navigate, destination);
      }
      const result = await planPromise;
      if (input.action === 'export') {
        downloadJson('qguard-migration-plan', result?.plan || result);
      }
      if (!isHandoff) {
        setWizardOpen(false);
      } else {
        const confirmedDestination = handoffDestination(input.action, result, planId);
        if (confirmedDestination && confirmedDestination !== destination) {
          navigateWithBrowserFallback(navigate, confirmedDestination);
        }
      }
    } catch (err) {
      if (destination) {
        console.warn('[migration-planner] handoff request did not confirm before navigation:', err);
        setWizardOpen(false);
        navigateWithBrowserFallback(navigate, destination);
      } else {
        setActionError(err instanceof Error ? err.message : 'Failed to create plan');
      }
    } finally {
      setBusyAction(null);
      setWizardBusyAction(null);
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
      {wizardOpen && (
        <PlanWizardModal
          assets={snapshot.topAssets}
          busy={busyAction === 'create'}
          busyAction={wizardBusyAction}
          onClose={() => setWizardOpen(false)}
          onSubmit={handleWizardSubmit}
        />
      )}

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
            <ActionButton icon={Plus} title="Create Plan" subtitle="Queue migration jobs" primary busy={busyAction === 'create'} onClick={openCreatePlan} />
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
