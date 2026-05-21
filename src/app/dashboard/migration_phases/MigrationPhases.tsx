'use client';

import { useMemo, type ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  ArrowUp,
  Calendar,
  ChevronDown,
  CheckCircle2,
  Clock,
  Download,
  Layers,
  MoreVertical,
  Package,
  Server,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';

type PhaseDatum = {
  name: string;
  value: number;
  percent: string;
  color: string;
};

type InsightCard = {
  label: string;
  value: string;
  detail: string;
  icon: LucideIcon;
  tone: 'red' | 'orange' | 'yellow' | 'gold';
};

type AssetRow = {
  name: string;
  type: string;
  environment: string;
  phase: 'Discover & Assess' | 'In Progress' | 'Planned' | 'Validated' | 'Completed';
  risk: 'High' | 'Medium' | 'Low';
  progress: number;
  targetCompletion: string;
  owner: string;
};

type ActivityRow = {
  text: string;
  time: string;
  icon: LucideIcon;
  color: string;
  bg: string;
};

const phaseData: PhaseDatum[] = [
  { name: 'Discover & Assess', value: 0, percent: '0%', color: '#FFD36B' },
  { name: 'Planned', value: 0, percent: '0%', color: '#f97316' },
  { name: 'In Progress', value: 0, percent: '0%', color: '#20c997' },
  { name: 'Validated', value: 0, percent: '0%', color: '#c084fc' },
  { name: 'Completed', value: 0, percent: '0%', color: '#8b95a7' },
];

type TrendSeries = Array<{ name: string; color: string; values: number[] }>;

const toneStyles = {
  red: {
    ring: 'border-red-400/30 bg-red-500/10 text-red-300 shadow-[0_0_24px_rgba(248,113,113,0.16)]',
    arrow: 'text-red-500',
  },
  orange: {
    ring: 'border-orange-400/30 bg-orange-500/10 text-orange-300 shadow-[0_0_24px_rgba(251,146,60,0.16)]',
    arrow: 'text-orange-400',
  },
  yellow: {
    ring: 'border-amber-300/30 bg-amber-400/10 text-amber-300 shadow-[0_0_24px_rgba(251,191,36,0.16)]',
    arrow: 'text-amber-300',
  },
  gold: {
    ring: 'border-gold/30 bg-gold/10 text-gold shadow-[0_0_24px_rgba(255,211,107,0.16)]',
    arrow: 'text-green-400',
  },
};

const phaseStyles: Record<AssetRow['phase'], { text: string; bar: string; dot: string }> = {
  'Discover & Assess': { text: 'text-gold', bar: 'bg-gold', dot: '#FFD36B' },
  'In Progress': { text: 'text-teal-300', bar: 'bg-[#20c997]', dot: '#20c997' },
  Planned: { text: 'text-orange-300', bar: 'bg-[#f97316]', dot: '#f97316' },
  Validated: { text: 'text-purple-300', bar: 'bg-[#c084fc]', dot: '#c084fc' },
  Completed: { text: 'text-slate-300', bar: 'bg-[#8b95a7]', dot: '#8b95a7' },
};

const riskStyles: Record<AssetRow['risk'], string> = {
  High: 'text-red-400',
  Medium: 'text-amber-300',
  Low: 'text-green-400',
};

const panelClass =
  'group relative overflow-hidden rounded-xl border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] group-hover:before:via-[#FFF4C0] after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-[#FFD36B]/25 group-hover:after:blur-[36px] text-white';

function formatNumber(value: number) {
  return Math.max(0, Number(value) || 0).toLocaleString('en-US');
}

function formatPercent(value: number) {
  return `${Math.max(0, Math.min(100, Math.round(Number(value) || 0)))}%`;
}

function compactDate(value?: string) {
  if (!value) return 'No scans yet';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString([], { month: 'short', day: '2-digit', year: 'numeric' });
}

function addDays(value: string | undefined, days: number) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) return new Date().toISOString();
  date.setDate(date.getDate() + days);
  return date.toISOString();
}

function relativeTime(value?: string) {
  if (!value) return 'No timestamp';
  const time = Date.parse(value);
  if (Number.isNaN(time)) return value;
  const seconds = Math.max(0, Math.round((Date.now() - time) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function safeText(value: unknown, fallback: string) {
  const text = String(value ?? '').trim();
  return text.length > 0 ? text : fallback;
}

function downloadTextFile(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function riskFromScore(score: number): AssetRow['risk'] {
  if (score >= 60) return 'High';
  if (score >= 35) return 'Medium';
  return 'Low';
}

function deriveMigrationPhase(asset: any): { phase: AssetRow['phase']; progress: number } {
  const inventory = Array.isArray(asset.cryptoInventory) ? asset.cryptoInventory : [];
  const vulnerableCount = Number(asset.vulnerableCount || inventory.filter((entry: any) => entry.is_vulnerable || entry.isVulnerable).length);
  const safeCount = inventory.filter((entry: any) => entry.is_quantum_safe || entry.isQuantumSafe).length;

  if (inventory.length === 0) return { phase: 'Discover & Assess', progress: 10 };
  if (vulnerableCount > 0 && safeCount === 0) return { phase: 'Planned', progress: 25 };
  if (vulnerableCount > 0) return { phase: 'In Progress', progress: Math.max(35, Math.round((safeCount / Math.max(1, inventory.length)) * 100)) };
  if (safeCount >= inventory.length) return { phase: 'Completed', progress: 100 };
  return { phase: 'Validated', progress: 90 };
}

function entryExpiryDate(entry: any) {
  const raw = entry.notAfter || entry.expiresAt || entry.expiry || entry.validTo || entry.metadata?.notAfter || entry.metadata?.expiresAt || entry.metadata?.validTo;
  const time = Date.parse(String(raw || ''));
  return Number.isNaN(time) ? null : time;
}

function isCertificateEntry(entry: any) {
  return /cert|x509|certificate/i.test(`${entry.type || ''} ${entry.component || ''} ${entry.category || ''}`);
}

function DonutChart({
  data,
  size,
  strokeWidth,
  center,
  total = data.reduce((sum, item) => sum + item.value, 0),
}: {
  data: PhaseDatum[];
  size: number;
  strokeWidth: number;
  center: ReactNode;
  total?: number;
}) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  let runningOffset = 0;
  const safeTotal = Math.max(1, total);

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg className="h-full w-full -rotate-90" viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(148,163,184,0.16)"
          strokeWidth={strokeWidth}
        />
        {data.map((item) => {
          const arcLength = (item.value / safeTotal) * circumference;
          const dash = Math.max(arcLength - 2.6, 0);
          const segment = (
            <circle
              key={item.name}
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke={item.color}
              strokeWidth={strokeWidth}
              strokeDasharray={`${dash} ${circumference}`}
              strokeDashoffset={-runningOffset}
              strokeLinecap="butt"
              className="transition-all duration-300 hover:opacity-90"
              style={{ filter: `drop-shadow(0 0 7px ${item.color}70)` }}
            />
          );
          runningOffset += arcLength;
          return segment;
        })}
      </svg>
      <div className="absolute inset-0 flex items-center justify-center text-center">{center}</div>
    </div>
  );
}

function ProgressRing({ progress, connected }: { progress: number; connected: boolean }) {
  const size = 168;
  const strokeWidth = 16;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, Math.round(progress)));

  return (
    <div className="relative h-[168px] w-[168px] shrink-0">
      <svg className="h-full w-full -rotate-90" viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(148,163,184,0.18)"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#FFD36B"
          strokeWidth={strokeWidth}
          strokeDasharray={`${circumference * (clamped / 100)} ${circumference}`}
          strokeLinecap="round"
          className="drop-shadow-[0_0_14px_rgba(255,211,107,0.7)]"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-[40px] font-black leading-none text-white">{clamped}%</span>
        <span className="mt-3 flex items-center gap-2 text-xs font-semibold text-white/75">
          <span className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.9)]' : 'bg-gold shadow-[0_0_10px_rgba(255,211,107,0.9)]'}`} />
          {connected ? 'Live' : 'Snapshot'}
        </span>
      </div>
    </div>
  );
}

function TrendChart({ series, labels }: { series: TrendSeries; labels: string[] }) {
  const viewWidth = 690;
  const viewHeight = 230;
  const left = 44;
  const top = 16;
  const plotWidth = 610;
  const plotHeight = 162;
  const maxValue = Math.max(1, ...series.flatMap((item) => item.values));

  const pointsFor = (values: number[]) =>
    values
      .map((value, index) => {
        const x = left + (index / Math.max(1, values.length - 1)) * plotWidth;
        const y = top + plotHeight - (value / maxValue) * plotHeight;
        return `${x},${y}`;
      })
      .join(' ');

  const pointObjects = (values: number[]) =>
    values.map((value, index) => ({
      x: left + (index / Math.max(1, values.length - 1)) * plotWidth,
      y: top + plotHeight - (value / maxValue) * plotHeight,
    }));

  return (
    <div className="relative h-[236px] w-full">
      <svg className="h-full w-full overflow-visible" viewBox={`0 0 ${viewWidth} ${viewHeight}`} preserveAspectRatio="none">
        <defs>
          <linearGradient id="migrationTrendFade" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#FFD36B" stopOpacity="0.12" />
            <stop offset="100%" stopColor="#FFD36B" stopOpacity="0" />
          </linearGradient>
        </defs>

        {[0, 1, 2, 3, 4].map((tick) => {
          const y = top + (tick / 4) * plotHeight;
          const tickValue = Math.round(maxValue * (1 - tick / 4));
          const label = tickValue >= 1000 ? `${Math.round(tickValue / 100) / 10}K` : String(tickValue);

          return (
            <g key={tick}>
              <line
                x1={left}
                x2={left + plotWidth}
                y1={y}
                y2={y}
                stroke="rgba(148,163,184,0.12)"
                strokeWidth="1"
              />
              <text x="7" y={y + 4} fill="rgba(203,213,225,0.45)" fontSize="12" fontWeight="700">
                {label}
              </text>
            </g>
          );
        })}

        {[0, 2, 4, 6, 8, 10].map((index) => {
          const x = left + (index / 10) * plotWidth;
          return (
            <line
              key={index}
              x1={x}
              x2={x}
              y1={top}
              y2={top + plotHeight}
              stroke="rgba(148,163,184,0.08)"
              strokeWidth="1"
            />
          );
        })}

        {series.map((item) => (
          <g key={item.name}>
            <polyline
              points={pointsFor(item.values)}
              fill="none"
              stroke={item.color}
              strokeWidth="3"
              strokeLinecap="round"
              strokeLinejoin="round"
              vectorEffect="non-scaling-stroke"
              style={{ filter: `drop-shadow(0 0 6px ${item.color}55)` }}
            />
            {pointObjects(item.values).map((point, index) => (
              <circle
                key={`${item.name}-${index}`}
                cx={point.x}
                cy={point.y}
                r="4"
                fill={item.color}
                stroke="#0f1428"
                strokeWidth="2"
                vectorEffect="non-scaling-stroke"
              />
            ))}
          </g>
        ))}

        {(labels.length > 0 ? labels : ['No scans']).map((label, index, allLabels) => (
          <text
            key={`${label}-${index}`}
            x={left + (index / Math.max(1, allLabels.length - 1)) * plotWidth}
            y={viewHeight - 10}
            fill="rgba(203,213,225,0.45)"
            fontSize="12"
            fontWeight="700"
          >
            {label}
          </text>
        ))}
      </svg>
    </div>
  );
}

function PhaseLegend({ data = phaseData, compact = false }: { data?: PhaseDatum[]; compact?: boolean }) {
  return (
    <div className={compact ? 'space-y-4' : 'flex-1 space-y-5'}>
      {data.map((phase) => (
        <div key={phase.name} className="grid grid-cols-[1fr_auto_auto] items-center gap-4">
          <div className="flex min-w-0 items-center gap-3">
            <span
              className="h-3 w-3 shrink-0 rounded-full shadow-[0_0_10px_currentColor]"
              style={{ backgroundColor: phase.color, color: phase.color }}
            />
            <span className="truncate text-sm font-medium text-white/90">{phase.name}</span>
          </div>
          <span className="font-mono text-sm font-semibold text-white">{formatNumber(phase.value)}</span>
          <span className="w-11 text-right font-mono text-sm text-white/50">{phase.percent}</span>
        </div>
      ))}
    </div>
  );
}

export default function MigrationPhases() {
  const { data, loading, error, connected, refresh } = useScannerIntelligence();

  const assetRows = useMemo<AssetRow[]>(() => data.assets.assets.slice(0, 12).map((asset: any) => {
    const { phase, progress } = deriveMigrationPhase(asset);
    const riskScore = Number(asset.riskScore || 0);
    return {
      name: safeText(asset.name, 'Unknown asset'),
      type: safeText(asset.type, 'Asset'),
      environment: safeText(asset.metadata?.environment || (asset.metadata?.authorized_target ? 'Production' : ''), 'Tenant Scope'),
      phase,
      risk: riskFromScore(riskScore),
      progress,
      targetCompletion: compactDate(addDays(asset.lastScanned || asset.metadata?.last_scanned_at || data.generatedAt, Math.max(3, Number(asset.vulnerableCount || 0) * 7))),
      owner: safeText(asset.metadata?.owner || asset.metadata?.businessOwner, 'Unassigned'),
    };
  }), [data.assets.assets, data.generatedAt]);

  const phaseData = useMemo<PhaseDatum[]>(() => {
    const counts = new Map<AssetRow['phase'], number>([
      ['Discover & Assess', 0],
      ['Planned', 0],
      ['In Progress', 0],
      ['Validated', 0],
      ['Completed', 0],
    ]);
    for (const asset of data.assets.assets) {
      const phase = deriveMigrationPhase(asset).phase;
      counts.set(phase, (counts.get(phase) || 0) + 1);
    }
    const total = Math.max(1, data.summary.totalAssets);
    return [
      { name: 'Discover & Assess', value: counts.get('Discover & Assess') || 0, percent: formatPercent(((counts.get('Discover & Assess') || 0) / total) * 100), color: '#FFD36B' },
      { name: 'Planned', value: counts.get('Planned') || 0, percent: formatPercent(((counts.get('Planned') || 0) / total) * 100), color: '#f97316' },
      { name: 'In Progress', value: counts.get('In Progress') || 0, percent: formatPercent(((counts.get('In Progress') || 0) / total) * 100), color: '#20c997' },
      { name: 'Validated', value: counts.get('Validated') || 0, percent: formatPercent(((counts.get('Validated') || 0) / total) * 100), color: '#c084fc' },
      { name: 'Completed', value: counts.get('Completed') || 0, percent: formatPercent(((counts.get('Completed') || 0) / total) * 100), color: '#8b95a7' },
    ];
  }, [data.assets.assets, data.summary.totalAssets]);

  const latestScan = data.history.history[0];
  const previousScan = data.history.history[1];
  const previousAssetTotal = Number(previousScan?.summary?.totalAssets || previousScan?.summary?.targetsScanned || 0);
  const assetDelta = previousAssetTotal > 0
    ? Math.round(((data.summary.totalAssets - previousAssetTotal) / Math.max(1, previousAssetTotal)) * 100)
    : 0;
  const certificateEntries = data.cbom.entries.filter((entry: any) => isCertificateEntry(entry));
  const expiringCertificates = certificateEntries.filter((entry: any) => {
    const expiry = entryExpiryDate(entry);
    if (!expiry) return false;
    const days = (expiry - Date.now()) / 86_400_000;
    return days >= 0 && days <= 90;
  }).length;
  const highRiskAssets = data.assets.assets.filter((asset: any) => Number(asset.riskScore || 0) >= 60).length;
  const migratedAssets = phaseData.find((phase) => phase.name === 'Completed')?.value || 0;
  const remainingAssets = Math.max(0, data.summary.totalAssets - migratedAssets);
  const overallProgress = data.summary.totalAssets > 0
    ? Math.round((phaseData.reduce((sum, phase) => {
      const weight = phase.name === 'Completed' ? 1 : phase.name === 'Validated' ? 0.9 : phase.name === 'In Progress' ? 0.6 : phase.name === 'Planned' ? 0.25 : 0.1;
      return sum + phase.value * weight;
    }, 0) / data.summary.totalAssets) * 100)
    : 0;

  const insightCards = useMemo<InsightCard[]>(() => [
    {
      label: 'High Risk Assets',
      value: formatNumber(highRiskAssets),
      detail: `${formatNumber(data.summary.vulnerableAssets)} vulnerable assets`,
      icon: ShieldAlert,
      tone: highRiskAssets > 0 ? 'red' : 'gold',
    },
    {
      label: 'Critical Vulnerabilities',
      value: formatNumber(data.severityCounts.critical),
      detail: `Across ${formatNumber(data.summary.vulnerableAssets)} assets`,
      icon: AlertTriangle,
      tone: data.severityCounts.critical > 0 ? 'orange' : 'gold',
    },
    {
      label: 'Expiring Certificates',
      value: formatNumber(expiringCertificates),
      detail: `${formatNumber(certificateEntries.length)} certificate records`,
      icon: Clock,
      tone: expiringCertificates > 0 ? 'yellow' : 'gold',
    },
    {
      label: 'Compliance Score',
      value: formatPercent(data.runtime.complianceScore),
      detail: `${formatNumber(data.summary.pqcReadyComponents)} PQC-ready components`,
      icon: ShieldCheck,
      tone: data.runtime.complianceScore >= 80 ? 'gold' : 'orange',
    },
  ], [certificateEntries.length, data.runtime.complianceScore, data.severityCounts.critical, data.summary.pqcReadyComponents, data.summary.vulnerableAssets, expiringCertificates, highRiskAssets]);

  const historyPoints = useMemo(() => {
    const points = data.history.history.slice(0, 11).reverse();
    return points.length > 0 ? points : [latestScan || { startedAt: data.generatedAt, summary: data.summary, detectedComponents: data.summary.totalComponents, vulnerableFindings: data.summary.vulnerableComponents, pqcReadyFindings: data.summary.pqcReadyComponents }];
  }, [data.generatedAt, data.history.history, data.summary, latestScan]);

  const trendSeries = useMemo(() => [
    { name: 'Discover & Assess', color: '#FFD36B', values: historyPoints.map((entry: any) => Number(entry.summary?.totalFindings || entry.detectedComponents || data.summary.totalComponents || 0)) },
    { name: 'Planned', color: '#f97316', values: historyPoints.map((entry: any) => Number(entry.summary?.vulnerable || entry.vulnerableFindings || data.summary.vulnerableComponents || 0)) },
    { name: 'In Progress', color: '#20c997', values: historyPoints.map((entry: any) => ['running', 'queued', 'analyzing'].includes(String(entry.status)) ? Number(entry.liveProgress || 1) : 0) },
    { name: 'Validated', color: '#c084fc', values: historyPoints.map((entry: any) => Number(entry.summary?.safe || entry.summary?.low || data.severityCounts.safe || 0)) },
    { name: 'Completed', color: '#8b95a7', values: historyPoints.map((entry: any) => Number(entry.summary?.pqcReady || entry.pqcReadyFindings || data.summary.pqcReadyComponents || 0)) },
  ], [data.severityCounts.safe, data.summary.pqcReadyComponents, data.summary.totalComponents, data.summary.vulnerableComponents, historyPoints]);

  const trendLabels = useMemo(() => {
    const selected = historyPoints.filter((_, index) => index === 0 || index === historyPoints.length - 1 || index % Math.max(1, Math.ceil(historyPoints.length / 4)) === 0);
    return selected.map((entry: any) => compactDate(entry.startedAt || entry.completedAt || data.generatedAt).replace(',', ''));
  }, [data.generatedAt, historyPoints]);

  const recentActivity = useMemo<ActivityRow[]>(() => {
    const telemetryRows = data.telemetry.slice(0, 5).map((event: any) => {
      const message = safeText(event.message || event.type, 'Scanner telemetry update');
      const lower = message.toLowerCase();
      const isFinding = lower.includes('finding') || event.finding;
      const isComplete = lower.includes('complete') || event.status === 'completed';
      const isRisk = lower.includes('risk') || lower.includes('critical') || lower.includes('vulnerab');
      const icon = isComplete ? CheckCircle2 : isRisk || isFinding ? AlertTriangle : Activity;
      const color = isComplete ? '#d4af37' : isRisk || isFinding ? '#fb923c' : '#FFD36B';
      const bg = isComplete ? 'rgba(212,175,55,0.14)' : isRisk || isFinding ? 'rgba(251,146,60,0.15)' : 'rgba(255,211,107,0.14)';
      return { text: message, time: relativeTime(event.timestamp), icon, color, bg };
    });

    if (telemetryRows.length > 0) return telemetryRows;

    return data.history.history.slice(0, 5).map((entry: any) => ({
      text: `${safeText(entry.status, 'Scan')} scan for ${safeText(entry.target, 'authorized target')}`,
      time: relativeTime(entry.startedAt || entry.completedAt),
      icon: entry.status === 'completed' ? CheckCircle2 : Activity,
      color: entry.status === 'completed' ? '#d4af37' : '#FFD36B',
      bg: entry.status === 'completed' ? 'rgba(212,175,55,0.14)' : 'rgba(255,211,107,0.14)',
    }));
  }, [data.history.history, data.telemetry]);

  const rangeLabel = data.history.history.length > 0
    ? `${compactDate(data.history.history[data.history.history.length - 1]?.startedAt)} - ${compactDate(latestScan?.startedAt || data.generatedAt)}`
    : 'Awaiting scanner history';

  const exportReport = () => {
    const payload = {
      generatedAt: new Date().toISOString(),
      connected,
      summary: data.summary,
      severityCounts: data.severityCounts,
      phases: phaseData,
      assets: assetRows,
      recentActivity: recentActivity.map((item) => ({ text: item.text, time: item.time })),
    };
    downloadTextFile(`qguard-migration-phases-${Date.now()}.json`, JSON.stringify(payload, null, 2), 'application/json;charset=utf-8');
  };

  return (
    <div className="p-4 lg:p-8 space-y-6 animate-in fade-in duration-700 text-white">
      <div className="relative z-10 space-y-6">
          <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded bg-gold/10 border border-gold/20">
                  <Layers className="w-6 h-6 text-gold drop-shadow-[0_0_6px_rgba(255,211,107,0.4)]" />
                </div>
                <h1 className="text-3xl font-black uppercase tracking-tight text-white leading-none">
                  Migration <span className="text-gold">Phases</span>
                </h1>
              </div>
              <p className="text-white/50 text-sm font-medium">
                Track and manage your post-quantum migration journey in real-time.
              </p>
              <h2 className="sr-only">
                Migration Phases Overview
              </h2>
            </div>

            <div className="flex flex-wrap items-center gap-4">
              <button onClick={refresh} className="flex h-12 min-w-[290px] items-center justify-between rounded-lg border border-white/10 bg-white/5 px-4 text-sm font-medium text-slate-200 shadow-[inset_0_1px_0_rgba(255,255,255,0.05)] transition hover:border-gold/40 hover:bg-gold/10">
                <span>{loading ? 'Synchronizing scanner stream...' : rangeLabel}</span>
                <Calendar className="h-4 w-4 text-gold" />
              </button>

              <span className={`flex h-12 items-center gap-2 rounded-lg border px-4 text-xs font-black uppercase tracking-wider ${connected ? 'border-emerald-400/30 bg-emerald-500/10 text-emerald-300' : 'border-gold/25 bg-gold/10 text-gold'}`}>
                <span className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400' : 'bg-gold'}`} />
                {connected ? 'Live SSE' : 'Snapshot'}
              </span>

              <button onClick={exportReport} className="flex h-12 items-center gap-3 rounded-lg border border-gold/30 bg-gold/10 px-5 text-sm font-semibold text-gold shadow-[0_0_22px_rgba(255,211,107,0.14)] transition hover:border-gold/70 hover:bg-gold/20">
                Export Report
                <Download className="h-4 w-4" />
              </button>
            </div>
          </header>

          {error && (
            <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-4 text-sm font-semibold text-red-300">
              {error}
            </div>
          )}

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-[310px_minmax(0,1fr)_510px]">
            <aside className="space-y-4 xl:row-span-2">
              <section className={`${panelClass} p-6`}>
                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-base font-medium text-slate-200/85">Total Assets</p>
                    <p className="mt-5 text-4xl font-black leading-none tracking-tight text-white">{formatNumber(data.summary.totalAssets)}</p>
                    <p className="mt-4 text-sm text-slate-300/90">Across all environments</p>
                    <div className={`mt-5 flex items-center gap-2 text-xs font-semibold ${assetDelta >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                      <ArrowUp className="h-3.5 w-3.5" />
                      <span>{assetDelta >= 0 ? '+' : ''}{assetDelta}%</span>
                      <span className="font-medium text-slate-400">from previous scan</span>
                    </div>
                  </div>
                  <div className="rounded-md border border-gold/30 bg-gold/10 p-2 text-gold shadow-[0_0_20px_rgba(255,211,107,0.22)]">
                    <Server className="h-7 w-7" />
                  </div>
                </div>
              </section>

              {insightCards.map((card) => {
                const Icon = card.icon;
                const tone = toneStyles[card.tone];

                return (
                  <section key={card.label} className={`${panelClass} p-5`}>
                    <div className="flex items-center gap-4">
                      <div className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-full border ${tone.ring}`}>
                        <Icon className="h-7 w-7" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-xs font-medium text-slate-300/78">{card.label}</p>
                        <p className="mt-1 text-2xl font-black leading-none text-white">{card.value}</p>
                        <p className="mt-2 truncate text-xs text-slate-400">{card.detail}</p>
                      </div>
                      <ArrowRight className={`h-5 w-5 shrink-0 ${tone.arrow}`} />
                    </div>
                  </section>
                );
              })}
            </aside>

            <section className={`${panelClass} min-h-[304px] p-6`}>
              <h2 className="text-lg font-bold text-white">Migration Phases Overview</h2>
              <div className="mt-6 flex flex-col items-center gap-8 lg:flex-row lg:items-center">
                <DonutChart
                  data={phaseData}
                  size={190}
                  strokeWidth={25}
                  center={
                    <div>
                      <div className="text-3xl font-black leading-none text-white">{formatNumber(data.summary.totalAssets)}</div>
                      <div className="mt-2 text-xs font-semibold uppercase tracking-wide text-slate-400">Total Assets</div>
                    </div>
                  }
                />
                <PhaseLegend data={phaseData} />
              </div>
            </section>

            <section className={`${panelClass} min-h-[304px] p-6`}>
              <h2 className="text-lg font-bold text-white">Overall Progress</h2>
              <div className="mt-6 flex flex-col gap-8 sm:flex-row sm:items-center">
                <ProgressRing progress={overallProgress} connected={connected} />
                <div className="hidden h-[184px] w-px bg-slate-600/30 sm:block" />
                <div className="space-y-9">
                  <div>
                    <p className="text-sm font-medium text-slate-400">Assets Migrated</p>
                    <p className="mt-2 text-2xl font-black text-white">{formatNumber(migratedAssets)}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-slate-400">Remaining</p>
                    <p className="mt-2 text-2xl font-black text-white">{formatNumber(remainingAssets)}</p>
                  </div>
                  <a href="/dashboard/migration-timeline" className="flex items-center gap-3 text-sm font-medium text-gold transition hover:text-white">
                    View Migration Roadmap
                    <ArrowRight className="h-4 w-4" />
                  </a>
                </div>
              </div>
            </section>

            <section className={`${panelClass} min-h-[326px] p-5`}>
              <div className="flex items-center justify-between gap-4">
                <h2 className="text-lg font-bold text-white">Migration Trend</h2>
                <button className="flex h-9 items-center gap-2 rounded-md border border-white/10 bg-white/5 px-4 text-xs font-semibold text-slate-200 transition hover:border-gold/40 hover:bg-gold/10">
                  Last 30 Days
                  <ChevronDown className="h-3.5 w-3.5 text-gold/70" />
                </button>
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-x-8 gap-y-3">
                {trendSeries.map((series) => (
                  <div key={series.name} className="flex items-center gap-2">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: series.color }} />
                    <span className="text-xs font-medium text-slate-300">{series.name}</span>
                  </div>
                ))}
              </div>

              <TrendChart series={trendSeries} labels={trendLabels} />
            </section>

            <section className={`${panelClass} min-h-[326px] p-6`}>
              <h2 className="text-lg font-bold text-white">Phase Distribution</h2>
              <div className="mt-6 flex flex-col items-center gap-8 sm:flex-row">
                <DonutChart
                  data={phaseData}
                  size={170}
                  strokeWidth={22}
                  center={
                    <div className="flex flex-col items-center text-slate-400">
                      <Package className="h-12 w-12 text-slate-400/80" strokeWidth={1.6} />
                    </div>
                  }
                />
                <PhaseLegend data={phaseData} compact />
              </div>
            </section>

            <section className={`${panelClass} xl:col-span-2`}>
              <div className="flex items-center justify-between px-5 py-4">
                <h2 className="sr-only">Asset Migration Progress</h2>
                <div />
                <button className="flex items-center gap-2 text-sm font-medium text-gold transition hover:text-white">
                  View All Assets
                  <ArrowRight className="h-4 w-4" />
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full min-w-[970px] border-collapse text-left">
                  <thead>
                    <tr className="bg-white/[0.035] text-xs font-semibold text-slate-300">
                      <th className="px-5 py-3">Asset Name</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Environment</th>
                      <th className="px-4 py-3">Current Phase</th>
                      <th className="px-4 py-3">Risk Level</th>
                      <th className="px-4 py-3">Migration Progress</th>
                      <th className="px-4 py-3">Target Completion</th>
                      <th className="px-4 py-3">Owner</th>
                      <th className="px-3 py-3" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {assetRows.length === 0 ? (
                      <tr>
                        <td colSpan={9} className="px-5 py-10 text-center text-xs font-black uppercase tracking-widest text-slate-500">
                          No scanned assets yet. Run an authorized scanner job to populate migration phases.
                        </td>
                      </tr>
                    ) : assetRows.map((asset) => {
                      const phase = phaseStyles[asset.phase];

                      return (
                        <tr key={asset.name} className="text-xs text-slate-300 transition hover:bg-gold/[0.04]">
                          <td className="px-5 py-3.5 font-medium text-slate-100">{asset.name}</td>
                          <td className="px-4 py-3.5">{asset.type}</td>
                          <td className="px-4 py-3.5">{asset.environment}</td>
                          <td className="px-4 py-3.5">
                            <span className={`inline-flex items-center gap-2 font-medium ${phase.text}`}>
                              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: phase.dot }} />
                              {asset.phase}
                            </span>
                          </td>
                          <td className="px-4 py-3.5">
                            <span className={`inline-flex items-center gap-2 font-semibold ${riskStyles[asset.risk]}`}>
                              <span className="h-2 w-2 rounded-full bg-current" />
                              {asset.risk}
                            </span>
                          </td>
                          <td className="px-4 py-3.5">
                            <div className="flex items-center gap-3">
                              <div className="h-2 w-28 overflow-hidden rounded-full bg-slate-800">
                                <div className={`h-full rounded-full ${phase.bar}`} style={{ width: `${asset.progress}%` }} />
                              </div>
                              <span className="w-8 text-right font-mono text-slate-300">{asset.progress}%</span>
                            </div>
                          </td>
                          <td className="px-4 py-3.5">{asset.targetCompletion}</td>
                          <td className="px-4 py-3.5">{asset.owner}</td>
                          <td className="px-3 py-3.5 text-slate-400">
                            <button className="rounded p-1 transition hover:bg-white/10 hover:text-white" aria-label={`Open actions for ${asset.name}`}>
                              <MoreVertical className="h-4 w-4" />
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>

            <section className={`${panelClass} p-5`}>
              <div className="flex items-center justify-between gap-4">
                <h2 className="text-lg font-bold text-white">Recent Activity</h2>
                <button className="flex items-center gap-2 text-sm font-medium text-gold transition hover:text-white">
                  View All
                  <ArrowRight className="h-4 w-4" />
                </button>
              </div>

              <div className="mt-6 space-y-5">
                {recentActivity.length === 0 ? (
                  <div className="rounded-lg border border-white/5 bg-white/[0.02] p-8 text-center text-xs font-black uppercase tracking-widest text-slate-500">
                    No live scanner telemetry yet.
                  </div>
                ) : recentActivity.map((item) => {
                  const Icon = item.icon;

                  return (
                    <div key={item.text} className="grid grid-cols-[34px_1fr_auto] items-center gap-3">
                      <div
                        className="flex h-8 w-8 items-center justify-center rounded-full"
                        style={{ backgroundColor: item.bg, color: item.color }}
                      >
                        <Icon className="h-4 w-4" />
                      </div>
                      <p className="truncate text-sm font-medium text-slate-300">{item.text}</p>
                      <span className="whitespace-nowrap text-xs text-slate-400">{item.time}</span>
                    </div>
                  );
                })}
              </div>
            </section>
          </div>
      </div>
    </div>
  );
}
