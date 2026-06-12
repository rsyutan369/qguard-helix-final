import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  CheckCircle2,
  Cloud,
  Database,
  Download,
  ExternalLink,
  Eye,
  Filter,
  Globe,
  KeyRound,
  Layers,
  LineChart,
  Loader2,
  Lock,
  Network,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  TrendingDown,
  Unlock,
  Wifi,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { useScannerIntelligence, type ScannerFinding } from '@/lib/scanner/use-scanner-intelligence';

type MapNode = {
  id: string;
  label: string;
  x: number;
  y: number;
  size: number;
  type: string;
  assetType: string;
  algorithm: string;
  vulnerable: boolean;
  risk: number;
  connections: string[];
  pqcReadiness: string;
  linkedFindings: Array<{
    id: string;
    algorithm: string;
    category: string;
    status: string;
    evidence?: string;
  }>;
  recommendedMigrationPath: string | null;
};

type RiskDistribution = {
  critical: number;
  high: number;
  medium: number;
  low: number;
};

type RiskBand = 'critical' | 'high' | 'medium' | 'low' | 'all';

const severityOrder: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  moderate: 2,
  low: 1,
  safe: 0,
};

const riskBands = [
  { key: 'all', label: 'All Exposure' },
  { key: 'critical', label: 'Critical' },
  { key: 'high', label: 'High' },
  { key: 'medium', label: 'Medium' },
  { key: 'low', label: 'Low' },
] as const;

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(' ');
}

function numberFmt(value: number) {
  return Math.round(Number(value) || 0).toLocaleString();
}

function pct(value: number) {
  return `${Math.max(0, Math.min(100, Math.round(Number(value) || 0)))}%`;
}

function getRiskColor(risk: number) {
  if (risk >= 80) return '#ef4444';
  if (risk >= 60) return '#f97316';
  if (risk >= 40) return '#eab308';
  if (risk >= 20) return '#22c55e';
  return '#10b981';
}

function riskBandFor(risk: number): Exclude<RiskBand, 'all'> {
  if (risk >= 80) return 'critical';
  if (risk >= 60) return 'high';
  if (risk >= 40) return 'medium';
  return 'low';
}

function riskLabel(risk: number) {
  if (risk >= 80) return 'Critical';
  if (risk >= 60) return 'High';
  if (risk >= 40) return 'Medium';
  return 'Low';
}

function riskTone(risk: number) {
  if (risk >= 80) return 'border-red-400/45 bg-red-500/10 text-red-400 dark:text-red-300';
  if (risk >= 60) return 'border-orange-400/45 bg-orange-400/10 text-orange-500 dark:text-orange-300';
  if (risk >= 40) return 'border-amber-300/45 bg-amber-300/10 text-amber-600 dark:text-amber-200';
  return 'border-emerald-400/40 bg-emerald-400/10 text-emerald-600 dark:text-emerald-300';
}

function getNodeIcon(type: string): LucideIcon {
  const lower = String(type || '').toLowerCase();
  if (lower.includes('database')) return Database;
  if (lower.includes('cloud')) return Cloud;
  if (lower.includes('network') || lower.includes('ssh') || lower.includes('vpn')) return Wifi;
  if (lower.includes('endpoint') || lower.includes('device')) return Radio;
  if (lower.includes('certificate') || lower.includes('tls')) return Lock;
  if (lower.includes('api')) return Network;
  return Server;
}

function normalizeSeverity(value: unknown) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'moderate') return 'medium';
  return normalized || 'low';
}

function shortTime(value?: string | null) {
  if (!value) return 'Awaiting telemetry';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Awaiting telemetry';
  return date.toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function safeNumber(value: unknown, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeMapNode(rawNode: any, index: number, total: number): MapNode {
  const angle = (Math.PI * 2 * index) / Math.max(1, total) - Math.PI / 2;
  const fallbackX = 50 + Math.cos(angle) * 32;
  const fallbackY = 50 + Math.sin(angle) * 32;
  const rawFindings = Array.isArray(rawNode?.linkedFindings)
    ? rawNode.linkedFindings
    : Array.isArray(rawNode?.findings)
      ? rawNode.findings
      : [];
  const assetType = String(rawNode?.assetType || rawNode?.type || rawNode?.category || 'Asset');
  const algorithm = String(rawNode?.algorithm || rawNode?.primaryAlgorithm || rawNode?.cipher || 'Unknown');
  const risk = Math.max(0, Math.min(100, safeNumber(rawNode?.risk ?? rawNode?.riskScore, 0)));

  return {
    id: String(rawNode?.id || rawNode?.assetId || rawNode?.label || `exposure-node-${index}`),
    label: String(rawNode?.label || rawNode?.name || rawNode?.assetName || rawNode?.target || `Exposure Node ${index + 1}`),
    x: safeNumber(rawNode?.x, fallbackX),
    y: safeNumber(rawNode?.y, fallbackY),
    size: Math.max(8, Math.min(22, safeNumber(rawNode?.size, 10))),
    type: String(rawNode?.type || assetType),
    assetType,
    algorithm,
    vulnerable: Boolean(rawNode?.vulnerable || rawNode?.isVulnerable || risk >= 60),
    risk,
    connections: Array.isArray(rawNode?.connections) ? rawNode.connections.map(String).filter(Boolean) : [],
    pqcReadiness: String(rawNode?.pqcReadiness || rawNode?.pqc_readiness || (risk >= 60 ? 'Quantum-vulnerable' : 'Unknown / requires manual review')),
    linkedFindings: rawFindings.map((finding: any, findingIndex: number) => ({
      id: String(finding?.id || `${rawNode?.id || index}-finding-${findingIndex}`),
      algorithm: String(finding?.algorithm || algorithm || 'Detected crypto'),
      category: String(finding?.category || finding?.type || finding?.source || 'Exposure finding'),
      status: String(finding?.status || finding?.threatLevel || finding?.severity || 'Open'),
      evidence: finding?.evidence ? String(finding.evidence) : undefined,
    })),
    recommendedMigrationPath: rawNode?.recommendedMigrationPath || rawNode?.migrationPath || rawNode?.pqcReplacement || null,
  };
}

function normalizeDistribution(rawDistribution: any, nodes: MapNode[]): RiskDistribution {
  return {
    critical: Math.max(0, safeNumber(rawDistribution?.critical, nodes.filter((node) => node.risk >= 80).length)),
    high: Math.max(0, safeNumber(rawDistribution?.high, nodes.filter((node) => node.risk >= 60 && node.risk < 80).length)),
    medium: Math.max(0, safeNumber(rawDistribution?.medium, nodes.filter((node) => node.risk >= 40 && node.risk < 60).length)),
    low: Math.max(0, safeNumber(rawDistribution?.low, nodes.filter((node) => node.risk < 40).length)),
  };
}

function panelClass(extra = '') {
  return cx(
    'relative overflow-hidden rounded-xl border p-5 transition-all duration-300',
    'border-slate-200/80 bg-white/82 text-slate-950 shadow-[4px_4px_0_rgba(15,23,42,0.08)] backdrop-blur-xl',
    'dark:border-[#FFD36B]/20 dark:bg-[#0f1428]/52 dark:text-white dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.08),0_0_40px_rgba(255,211,107,0.12)]',
    'before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-cyan-300/60 before:to-transparent dark:before:via-[#FFF4C0]/70',
    extra,
  );
}

function MetricCard({
  title,
  value,
  detail,
  icon: Icon,
  tone,
  spark,
}: {
  title: string;
  value: string;
  detail: string;
  icon: LucideIcon;
  tone?: string;
  spark?: number[];
}) {
  const points = spark && spark.length > 1
    ? spark.map((item, index) => {
      const x = (index / Math.max(1, spark.length - 1)) * 100;
      const max = Math.max(1, ...spark);
      const y = 32 - (Math.max(0, item) / max) * 26;
      return `${x},${y}`;
    }).join(' ')
    : '';

  return (
    <div className={panelClass('min-h-[142px]')}>
      <div className="relative z-10 flex items-start justify-between gap-4">
        <div>
          <div className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 dark:text-white/42">{title}</div>
          <div className="mt-3 text-3xl font-black text-slate-950 dark:text-white">{value}</div>
          <div className="mt-2 text-xs font-semibold text-slate-500 dark:text-white/45">{detail}</div>
        </div>
        <div className={cx('grid h-12 w-12 place-items-center rounded-lg border bg-cyan-400/10 text-cyan-500 dark:border-white/10 dark:bg-white/5 dark:text-[#FFD36B]', tone)}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      {points && (
        <svg className="relative z-10 mt-4 h-9 w-full" viewBox="0 0 100 36" preserveAspectRatio="none" aria-hidden="true">
          <polyline points={points} fill="none" stroke="currentColor" strokeWidth="2" className="text-cyan-500/75 dark:text-[#FFD36B]/70" />
        </svg>
      )}
    </div>
  );
}

function EmptyState() {
  return (
    <div className="absolute inset-0 z-20 flex flex-col items-center justify-center px-6 text-center">
      <Globe className="mb-4 h-12 w-12 text-cyan-500/25 dark:text-[#FFD36B]/25" />
      <div className="mb-2 text-xs font-black uppercase tracking-widest text-slate-500 dark:text-white/35">
        No authorized crypto exposure data yet
      </div>
      <p className="max-w-md text-xs font-semibold leading-5 text-slate-500 dark:text-white/42">
        Start an authorized scanner run to populate asset trust paths, exposed algorithms, PQC readiness, and blast-radius intelligence.
      </p>
      <a href="/dashboard/scanner" className="mt-5 inline-flex items-center gap-2 rounded-lg border border-cyan-400/40 bg-cyan-400/12 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-cyan-700 no-underline dark:border-[#FFD36B]/30 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">
        <ExternalLink className="h-3.5 w-3.5" /> Start Authorized Scan
      </a>
    </div>
  );
}

export default function CryptoExposureMap() {
  const { data, loading, error, connected, refresh } = useScannerIntelligence();
  const summary = data.summary || {};
  const rawExposureNodes = Array.isArray(data.exposure?.nodes) ? data.exposure.nodes : [];
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const history = Array.isArray(data.history?.history) ? data.history.history : [];
  const telemetry = Array.isArray(data.telemetry) ? data.telemetry : [];
  const nodes = useMemo(() => rawExposureNodes.map((node, index) => normalizeMapNode(node, index, rawExposureNodes.length)), [rawExposureNodes]);
  const distribution = useMemo(() => normalizeDistribution(data.exposure?.distribution, nodes), [data.exposure?.distribution, nodes]);
  const [selectedNode, setSelectedNode] = useState<MapNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [riskFilter, setRiskFilter] = useState<RiskBand>('all');
  const [query, setQuery] = useState('');
  const [mapMode, setMapMode] = useState<'topology' | 'blast-radius'>('topology');
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);

  useEffect(() => {
    setSelectedNode((current) => {
      if (!current) return nodes[0] || null;
      return nodes.find((node) => node.id === current.id) || nodes[0] || null;
    });
  }, [nodes]);

  const drawParticles = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const w = canvas.width = canvas.offsetWidth;
    const h = canvas.height = canvas.offsetHeight;
    const t = Date.now() * 0.001;

    ctx.clearRect(0, 0, w, h);
    for (let i = 0; i < 95; i++) {
      const x = ((i * 37.7 + t * 18) % (w + 40)) - 20;
      const y = ((i * 53.3 + Math.sin(t + i) * 30) % h);
      const alpha = 0.04 + Math.sin(t * 2 + i) * 0.025;
      ctx.beginPath();
      ctx.arc(x, y, 1.15, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0,197,235,${alpha})`;
      ctx.fill();
    }
    animRef.current = requestAnimationFrame(drawParticles);
  }, []);

  useEffect(() => {
    drawParticles();
    return () => cancelAnimationFrame(animRef.current);
  }, [drawParticles]);

  const filteredNodes = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return nodes.filter((node) => {
      const riskMatches = riskFilter === 'all' || riskBandFor(Number(node.risk || 0)) === riskFilter;
      const text = `${node.label} ${node.type} ${node.assetType} ${node.algorithm} ${node.pqcReadiness}`.toLowerCase();
      return riskMatches && (!needle || text.includes(needle));
    });
  }, [nodes, query, riskFilter]);

  const visibleNodeIds = useMemo(() => new Set(filteredNodes.map((node) => node.id)), [filteredNodes]);

  const stats = useMemo(() => {
    const vulnerable = nodes.filter((node) => node.vulnerable).length;
    const secured = nodes.filter((node) => !node.vulnerable && node.linkedFindings.length > 0).length;
    const criticalHigh = nodes.filter((node) => node.risk >= 60).length;
    const averageRisk = nodes.length ? Math.round(nodes.reduce((sum, node) => sum + Number(node.risk || 0), 0) / nodes.length) : 0;
    const blastRadius = nodes
      .filter((node) => node.risk >= 60 || node.vulnerable)
      .reduce((sum, node) => sum + (Array.isArray(node.connections) ? node.connections.length : 0), 0);
    const totalFindings = nodes.reduce((sum, node) => sum + node.linkedFindings.length, 0);
    const vulnerableAlgorithms = new Set(nodes.filter((node) => node.vulnerable).map((node) => node.algorithm).filter(Boolean));

    return {
      vulnerable,
      secured,
      criticalHigh,
      averageRisk,
      blastRadius,
      totalFindings,
      vulnerableAlgorithms: vulnerableAlgorithms.size,
      pqcReadiness: safeNumber(summary.pqcReadiness, 0),
      qScore: safeNumber(summary.qScore, 0),
      totalAssets: safeNumber(summary.totalAssets, nodes.length) || nodes.length,
      totalComponents: safeNumber(summary.totalComponents, 0),
      activeScans: safeNumber(summary.activeScans, 0),
    };
  }, [nodes, summary]);

  const algorithmExposure = useMemo(() => {
    const rows = new Map<string, { name: string; count: number; vulnerable: number; maxRisk: number; assets: Set<string> }>();
    for (const node of nodes) {
      const algorithms = new Set([
        node.algorithm,
        ...node.linkedFindings.map((finding) => finding.algorithm),
      ].filter(Boolean));
      for (const algorithm of algorithms) {
        const key = String(algorithm || 'Unknown');
        const row = rows.get(key) || { name: key, count: 0, vulnerable: 0, maxRisk: 0, assets: new Set<string>() };
        row.count += 1;
        row.assets.add(node.label);
        row.maxRisk = Math.max(row.maxRisk, Number(node.risk || 0));
        if (node.vulnerable || node.linkedFindings.some((finding) => /vulnerable|legacy|weak/i.test(finding.status))) row.vulnerable += 1;
        rows.set(key, row);
      }
    }
    return [...rows.values()]
      .map((row) => ({ ...row, assetCount: row.assets.size }))
      .sort((a, b) => b.maxRisk - a.maxRisk || b.count - a.count)
      .slice(0, 8);
  }, [nodes]);

  const prioritizedNodes = useMemo(() => [...nodes].sort((a, b) => b.risk - a.risk).slice(0, 8), [nodes]);

  const prioritizedFindings = useMemo(() => {
    const nodeFindings = nodes.flatMap((node) =>
      node.linkedFindings.map((finding) => ({
        ...finding,
        asset: node.label,
        risk: node.risk,
        recommendedMigrationPath: node.recommendedMigrationPath,
        severity: riskLabel(node.risk),
      })),
    );
    const scannerFindings = findings.map((finding: ScannerFinding) => {
      const level = normalizeSeverity(finding.threatLevel || finding.severity || finding.status);
      const rank = severityOrder[level] ?? 1;
      return {
        id: String(finding.id || `${finding.algorithm}-${finding.location}`),
        algorithm: String(finding.algorithm || 'Detected crypto'),
        category: String(finding.category || finding.source || 'Scanner finding'),
        status: String(finding.status || finding.threatLevel || 'Open'),
        asset: String(finding.location || 'Unmapped asset'),
        risk: rank * 24,
        recommendedMigrationPath: String(finding.recommendation || 'Review remediation path'),
        severity: level.toUpperCase(),
      };
    });

    return [...nodeFindings, ...scannerFindings]
      .sort((a, b) => Number(b.risk || 0) - Number(a.risk || 0))
      .slice(0, 10);
  }, [findings, nodes]);

  const activity = useMemo(() => {
    const historyRows = history.slice(0, 4).map((item: any) => ({
      id: item.scanId || item.id || item.startedAt,
      title: `Scan ${item.status || 'recorded'}: ${item.target || 'authorized scope'}`,
      detail: `${numberFmt(item.summary?.totalFindings || item.findings?.length || 0)} findings`,
      time: item.completedAt || item.startedAt || item.createdAt,
    }));
    const telemetryRows = telemetry.slice(0, 4).map((item: any, index: number) => ({
      id: item.id || `${item.type}-${index}`,
      title: item.message || item.type || 'Runtime crypto event',
      detail: item.target || item.asset || item.scanId || 'Telemetry source',
      time: item.timestamp,
    }));
    return [...historyRows, ...telemetryRows]
      .sort((a, b) => Date.parse(b.time || '') - Date.parse(a.time || ''))
      .slice(0, 6);
  }, [history, telemetry]);

  const selectedIcon = selectedNode ? getNodeIcon(selectedNode.assetType || selectedNode.type) : Globe;
  const SelectedIcon = selectedIcon;

  return (
    <main className="min-h-screen bg-[#f8fafc] p-4 text-slate-950 dark:bg-[#02060d] dark:text-white lg:p-6">
      <style>{`
        @keyframes qg-exposure-flow {
          from { stroke-dashoffset: 28; }
          to { stroke-dashoffset: 0; }
        }
        @keyframes qg-exposure-pulse {
          0%, 100% { opacity: 0.45; filter: drop-shadow(0 0 4px rgba(0, 197, 235, 0.35)); }
          50% { opacity: 1; filter: drop-shadow(0 0 12px rgba(0, 197, 235, 0.9)); }
        }
        .qg-exposure-flow-line {
          animation: qg-exposure-flow 1.35s linear infinite, qg-exposure-pulse 2.2s ease-in-out infinite;
        }
        @media (prefers-reduced-motion: reduce) {
          .qg-exposure-flow-line { animation: none; }
        }
      `}</style>
      <div className="pointer-events-none fixed inset-0 opacity-80" aria-hidden="true">
        <div className="absolute inset-0 bg-[radial-gradient(#dbeafe_1px,transparent_1px)] bg-[size:24px_24px] dark:bg-[linear-gradient(rgba(255,211,107,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(0,217,255,0.025)_1px,transparent_1px)] dark:bg-[size:48px_48px]" />
        <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(0,197,235,0.12),transparent_35%,rgba(255,211,107,0.08)_100%)] dark:bg-[linear-gradient(180deg,rgba(255,211,107,0.08),transparent_36%,rgba(0,140,255,0.05)_100%)]" />
      </div>

      <div className="relative z-10 mx-auto max-w-[1680px] space-y-6">
        <header className={panelClass('p-6')}>
          <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
            <div className="max-w-4xl">
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/40 bg-cyan-400/10 px-3 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-cyan-600 dark:border-[#FFD36B]/35 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">
                <Globe className="h-3.5 w-3.5" />
                Live Cryptographic Exposure Command Center
              </div>
              <h1 className="mt-4 text-3xl font-black uppercase tracking-tight text-slate-950 dark:text-white md:text-4xl">
                Crypto Exposure <span className="text-cyan-500 dark:text-[#FFD36B]">Intelligence</span>
              </h1>
              <p className="mt-3 max-w-3xl text-sm font-semibold leading-6 text-slate-600 dark:text-white/55">
                Enterprise topology for quantum-vulnerable cryptography, asset blast radius, algorithm concentration, migration urgency, and PQC readiness across authorized scanner results.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div className="rounded-lg border border-slate-200 bg-white/70 px-4 py-3 dark:border-white/8 dark:bg-white/[0.04]">
                <div className="text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">Realtime State</div>
                <div className="mt-1 flex items-center gap-2 text-xs font-black text-slate-900 dark:text-white">
                  <span className={cx('h-2 w-2 rounded-full', connected ? 'bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.85)]' : 'bg-amber-400')} />
                  {connected ? 'Live SSE Connected' : 'Polling / Reconnecting'}
                </div>
              </div>
              <a href="/dashboard/scanner" className="inline-flex h-11 items-center gap-2 rounded-lg border border-slate-200 bg-white/70 px-4 text-[10px] font-black uppercase tracking-widest text-slate-700 no-underline transition hover:border-cyan-300 dark:border-white/10 dark:bg-white/5 dark:text-white/65">
                <Target className="h-4 w-4" /> Run Scan
              </a>
              <a href="/dashboard/migration-planner" className="inline-flex h-11 items-center gap-2 rounded-lg border border-cyan-400/40 bg-cyan-400/12 px-4 text-[10px] font-black uppercase tracking-widest text-cyan-700 no-underline transition hover:bg-cyan-400/20 dark:border-[#FFD36B]/35 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">
                <Sparkles className="h-4 w-4" /> Plan Migration
              </a>
              <button onClick={refresh} className="inline-flex h-11 items-center gap-2 rounded-lg border border-cyan-400/40 bg-cyan-400/12 px-4 text-[10px] font-black uppercase tracking-widest text-cyan-700 transition hover:bg-cyan-400/20 dark:border-[#FFD36B]/35 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">
                <RefreshCw className={cx('h-4 w-4', loading && 'animate-spin')} /> Refresh
              </button>
            </div>
          </div>
        </header>

        {error && (
          <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-4 text-sm font-semibold text-red-500 dark:text-red-300">
            <AlertTriangle className="mr-2 inline h-4 w-4" />
            {error}
          </div>
        )}

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
          <MetricCard title="Assets Mapped" value={numberFmt(stats.totalAssets)} detail={`${numberFmt(stats.totalComponents)} crypto components`} icon={Layers} spark={[2, 4, 6, stats.totalAssets || 1]} />
          <MetricCard title="Critical / High" value={numberFmt(stats.criticalHigh)} detail="priority exposure nodes" icon={ShieldAlert} tone="text-red-400" spark={[1, distribution.medium, distribution.high, distribution.critical]} />
          <MetricCard title="Avg Risk" value={`${stats.averageRisk}/100`} detail={`Q-Score ${numberFmt(stats.qScore)}`} icon={BarChart3} tone="text-amber-400" spark={[30, 45, 52, stats.averageRisk || 1]} />
          <MetricCard title="PQC Readiness" value={pct(stats.pqcReadiness)} detail={`${numberFmt(stats.secured)} monitored protected assets`} icon={ShieldCheck} tone="text-emerald-400" spark={[20, 34, 55, stats.pqcReadiness || 1]} />
          <MetricCard title="Blast Radius" value={numberFmt(stats.blastRadius)} detail="linked trust paths affected" icon={Network} tone="text-cyan-400" spark={[1, 3, 5, stats.blastRadius || 1]} />
          <MetricCard title="Active Scans" value={numberFmt(stats.activeScans)} detail={`${numberFmt(safeNumber(summary.completedScans, 0))} completed`} icon={Activity} tone="text-blue-400" spark={[0, 1, 1, stats.activeScans || 1]} />
        </div>

        <div className={panelClass('p-4')}>
          <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
            <div className="flex flex-wrap items-center gap-2">
              {riskBands.map((band) => (
                <button
                  key={band.key}
                  type="button"
                  onClick={() => setRiskFilter(band.key)}
                  className={cx(
                    'rounded-lg border px-3 py-2 text-[10px] font-black uppercase tracking-widest transition',
                    riskFilter === band.key
                      ? 'border-cyan-400 bg-cyan-400/12 text-cyan-700 dark:border-[#FFD36B]/45 dark:bg-[#FFD36B]/12 dark:text-[#FFD36B]'
                      : 'border-slate-200 bg-white/60 text-slate-500 hover:border-cyan-300 dark:border-white/8 dark:bg-white/[0.03] dark:text-white/45',
                  )}
                >
                  {band.label}
                </button>
              ))}
            </div>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
              <label className="relative block">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 dark:text-white/35" />
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search asset, algorithm, type..."
                  className="h-10 w-full rounded-lg border border-slate-200 bg-white/72 pl-9 pr-3 text-xs font-bold text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-cyan-400 dark:border-white/10 dark:bg-black/25 dark:text-white dark:placeholder:text-white/30 sm:w-[320px]"
                />
              </label>
              <div className="grid grid-cols-2 rounded-lg border border-slate-200 bg-white/60 p-1 dark:border-white/8 dark:bg-white/[0.03]">
                {[
                  ['topology', 'Topology'],
                  ['blast-radius', 'Blast Radius'],
                ].map(([key, label]) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setMapMode(key as typeof mapMode)}
                    className={cx('rounded-md px-3 py-2 text-[10px] font-black uppercase tracking-widest transition', mapMode === key ? 'bg-cyan-400 text-slate-950 dark:bg-[#FFD36B]' : 'text-slate-500 dark:text-white/45')}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_420px]">
          <section className={panelClass('min-h-[620px] p-0')}>
            <canvas ref={canvasRef} className="absolute inset-0 h-full w-full pointer-events-none" />
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_30%,rgba(0,197,235,0.10),transparent_58%)] dark:bg-[radial-gradient(circle_at_50%_30%,rgba(255,211,107,0.07),transparent_60%)]" />
            <div className="relative z-10 flex items-center justify-between gap-3 border-b border-slate-200/70 p-5 dark:border-white/8">
              <div>
                <h2 className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
                  <Globe className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
                  Enterprise Exposure Topology
                </h2>
                <div className="mt-2 text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-white/35">
                  {numberFmt(filteredNodes.length)} visible nodes | {mapMode === 'blast-radius' ? 'blast-radius overlay' : 'live dependency graph'}
                </div>
              </div>
              <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-widest text-slate-500 dark:text-white/40">
                <Filter className="h-4 w-4" /> {riskFilter}
              </div>
            </div>

            {loading && nodes.length === 0 ? (
              <div className="absolute inset-0 z-20 flex items-center justify-center text-cyan-600 dark:text-[#FFD36B]">
                <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                <span className="text-xs font-black uppercase tracking-widest">Loading exposure intelligence</span>
              </div>
            ) : nodes.length === 0 ? (
              <EmptyState />
            ) : (
              <svg className="relative z-10 h-[560px] w-full" viewBox="0 0 100 100" preserveAspectRatio="xMidYMid meet">
                {filteredNodes.flatMap((node) =>
                  node.connections.map((targetId) => {
                    const target = nodes.find((item) => item.id === targetId);
                    if (!target || !visibleNodeIds.has(target.id)) return null;
                    const isHighlighted = hoveredNode === node.id || hoveredNode === targetId || selectedNode?.id === node.id || selectedNode?.id === targetId;
                    const severe = node.risk >= 60 || target.risk >= 60;
                    return (
                      <g key={`${node.id}-${targetId}`}>
                        <line
                          x1={node.x}
                          y1={node.y}
                          x2={target.x}
                          y2={target.y}
                          stroke={isHighlighted ? (severe ? 'rgba(239,68,68,0.72)' : 'rgba(0,197,235,0.68)') : 'rgba(100,116,139,0.23)'}
                          strokeWidth={isHighlighted ? 0.45 : 0.18}
                          strokeDasharray={isHighlighted ? 'none' : '1 1'}
                        />
                        {isHighlighted && (
                          <line
                            x1={node.x}
                            y1={node.y}
                            x2={target.x}
                            y2={target.y}
                            stroke={severe ? '#ef4444' : '#00c5eb'}
                            strokeWidth="0.22"
                            strokeDasharray="4 24"
                            className="qg-exposure-flow-line"
                          />
                        )}
                      </g>
                    );
                  }),
                )}

                {filteredNodes.map((node) => {
                  const isHovered = hoveredNode === node.id;
                  const isSelected = selectedNode?.id === node.id;
                  const color = getRiskColor(node.risk);
                  const r = (node.size / 10) * (mapMode === 'blast-radius' ? 1.85 : 1.55);
                  const Icon = getNodeIcon(node.assetType || node.type);

                  return (
                    <g key={node.id} className="cursor-pointer" onMouseEnter={() => setHoveredNode(node.id)} onMouseLeave={() => setHoveredNode(null)} onClick={() => setSelectedNode(node)}>
                      {(node.vulnerable || mapMode === 'blast-radius') && (
                        <circle cx={node.x} cy={node.y} r={r * (node.risk >= 80 ? 3.4 : 2.6)} fill={color} opacity={node.risk >= 80 ? 0.08 : 0.04}>
                          <animate attributeName="r" values={`${r * 2.2};${r * 3.2};${r * 2.2}`} dur="3.2s" repeatCount="indefinite" />
                          <animate attributeName="opacity" values="0.18;0.03;0.18" dur="3.2s" repeatCount="indefinite" />
                        </circle>
                      )}
                      <circle cx={node.x} cy={node.y} r={r} fill={`${color}25`} stroke={isSelected ? '#FFD36B' : color} strokeWidth={isSelected ? 0.7 : 0.34} />
                      <circle cx={node.x} cy={node.y} r={r * 0.42} fill={color} opacity={isHovered || isSelected ? 1 : 0.72} />
                      <foreignObject x={node.x - 1.7} y={node.y - 1.7} width="3.4" height="3.4" className="pointer-events-none">
                        <div className="flex h-full w-full items-center justify-center text-white">
                          <Icon className="h-2.5 w-2.5" />
                        </div>
                      </foreignObject>
                      <text x={node.x} y={node.y + r + 2.8} textAnchor="middle" fill={isHovered || isSelected ? 'rgba(15,23,42,0.92)' : 'rgba(71,85,105,0.72)'} className="dark:fill-white" fontSize="2.05" fontFamily="monospace" fontWeight="bold">
                        {node.label}
                      </text>
                      <text x={node.x} y={node.y + r + 5} textAnchor="middle" fill={color} fontSize="1.65" fontFamily="monospace" fontWeight="bold">
                        {node.algorithm}
                      </text>
                    </g>
                  );
                })}
              </svg>
            )}
          </section>

          <aside className="space-y-6">
            <section className={panelClass()}>
              <div className="mb-4 flex items-center justify-between">
                <h2 className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
                  <Eye className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
                  Node Inspector
                </h2>
                {selectedNode && <span className={cx('rounded-full border px-2 py-1 text-[9px] font-black uppercase tracking-widest', riskTone(selectedNode.risk))}>{riskLabel(selectedNode.risk)}</span>}
              </div>
              {selectedNode ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-3">
                    <div className="grid h-12 w-12 place-items-center rounded-lg border border-cyan-400/30 bg-cyan-400/10 text-cyan-500 dark:border-[#FFD36B]/30 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">
                      <SelectedIcon className="h-6 w-6" />
                    </div>
                    <div className="min-w-0">
                      <div className="truncate text-lg font-black text-slate-950 dark:text-white">{selectedNode.label}</div>
                      <div className="mt-1 text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-white/40">{selectedNode.assetType || selectedNode.type}</div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3 dark:border-white/8 dark:bg-black/25">
                      <div className="text-2xl font-black" style={{ color: getRiskColor(selectedNode.risk) }}>{selectedNode.risk}</div>
                      <div className="text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">Risk Score</div>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3 dark:border-white/8 dark:bg-black/25">
                      <div className="text-2xl font-black text-slate-950 dark:text-white">{selectedNode.linkedFindings.length}</div>
                      <div className="text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">Linked Findings</div>
                    </div>
                  </div>

                  <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3 dark:border-white/8 dark:bg-black/25">
                    <div className="text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">Detected Algorithm</div>
                    <div className="mt-1 font-mono text-sm font-black text-slate-950 dark:text-white">{selectedNode.algorithm || 'Unknown'}</div>
                  </div>

                  <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3 dark:border-white/8 dark:bg-black/25">
                    <div className="text-[9px] font-black uppercase tracking-widest text-slate-500 dark:text-white/35">Recommended Migration Path</div>
                    <div className="mt-1 text-sm font-bold text-cyan-600 dark:text-[#FFD36B]">{selectedNode.recommendedMigrationPath || 'Manual review required'}</div>
                  </div>

                  <div className="flex items-center gap-2">
                    {selectedNode.vulnerable ? (
                      <span className="flex items-center gap-1 rounded-full border border-red-400/35 bg-red-500/10 px-3 py-1 text-[9px] font-black uppercase tracking-wider text-red-500 dark:text-red-300"><Unlock className="h-3 w-3" /> {selectedNode.pqcReadiness}</span>
                    ) : (
                      <span className="flex items-center gap-1 rounded-full border border-emerald-400/35 bg-emerald-400/10 px-3 py-1 text-[9px] font-black uppercase tracking-wider text-emerald-500 dark:text-emerald-300"><Shield className="h-3 w-3" /> {selectedNode.pqcReadiness}</span>
                    )}
                  </div>

                  <div className="max-h-56 space-y-2 overflow-y-auto pr-1">
                    {selectedNode.linkedFindings.map((finding) => (
                      <div key={finding.id} className="rounded-lg border border-slate-200 bg-white/65 p-3 dark:border-white/8 dark:bg-white/[0.03]">
                        <div className="text-xs font-black text-slate-900 dark:text-white">{finding.algorithm}</div>
                        <div className="mt-1 text-[10px] font-semibold text-slate-500 dark:text-white/40">{finding.category} | {finding.status}</div>
                        {finding.evidence && <div className="mt-2 text-[10px] text-slate-500 dark:text-white/35">{finding.evidence}</div>}
                      </div>
                    ))}
                    {selectedNode.linkedFindings.length === 0 && <div className="rounded-lg border border-dashed border-slate-200 p-4 text-center text-xs font-bold text-slate-500 dark:border-white/10 dark:text-white/35">No linked findings on this node.</div>}
                  </div>
                </div>
              ) : (
                <div className="grid min-h-[260px] place-items-center text-center">
                  <div>
                    <Globe className="mx-auto mb-3 h-9 w-9 text-cyan-500/25 dark:text-[#FFD36B]/25" />
                    <p className="text-[10px] font-black uppercase tracking-wider text-slate-400 dark:text-white/25">Select a node to inspect</p>
                  </div>
                </div>
              )}
            </section>

            <section className={panelClass()}>
              <h2 className="mb-4 flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
                <LineChart className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
                Risk Distribution
              </h2>
              <div className="space-y-3">
                {[
                  { label: 'Critical', count: distribution.critical, color: '#ef4444' },
                  { label: 'High', count: distribution.high, color: '#f97316' },
                  { label: 'Medium', count: distribution.medium, color: '#eab308' },
                  { label: 'Low', count: distribution.low, color: '#22c55e' },
                ].map((level) => {
                  const total = Math.max(1, distribution.critical + distribution.high + distribution.medium + distribution.low);
                  const width = (level.count / total) * 100;
                  return (
                    <div key={level.label}>
                      <div className="mb-1 flex items-center justify-between text-[10px] font-black uppercase tracking-widest text-slate-500 dark:text-white/40">
                        <span>{level.label}</span><span>{numberFmt(level.count)}</span>
                      </div>
                      <div className="h-2 rounded-full bg-slate-200 dark:bg-white/8">
                        <div className="h-full rounded-full" style={{ width: `${width}%`, backgroundColor: level.color }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>
          </aside>
        </div>

        <div className="grid gap-6 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
          <section className={panelClass()}>
            <div className="mb-4 flex items-center justify-between gap-3">
              <h2 className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
                <KeyRound className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
                Algorithm Exposure Concentration
              </h2>
              <a href="/dashboard/cbom" className="inline-flex items-center gap-1 text-[10px] font-black uppercase tracking-widest text-cyan-600 no-underline hover:text-cyan-500 dark:text-[#FFD36B]">
                Open CBOM <ArrowRight className="h-3.5 w-3.5" />
              </a>
            </div>
            <div className="space-y-3">
              {algorithmExposure.map((row) => (
                <div key={row.name} className="rounded-lg border border-slate-200 bg-white/60 p-3 dark:border-white/8 dark:bg-white/[0.03]">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="font-mono text-sm font-black text-slate-950 dark:text-white">{row.name}</div>
                      <div className="mt-1 text-[10px] font-semibold text-slate-500 dark:text-white/40">{numberFmt(row.assetCount)} assets | {numberFmt(row.vulnerable)} vulnerable observations</div>
                    </div>
                    <span className={cx('rounded-full border px-2 py-1 text-[9px] font-black uppercase tracking-widest', riskTone(row.maxRisk))}>{riskLabel(row.maxRisk)}</span>
                  </div>
                  <div className="mt-3 h-2 rounded-full bg-slate-200 dark:bg-white/8">
                    <div className="h-full rounded-full bg-cyan-500 dark:bg-[#FFD36B]" style={{ width: pct(row.maxRisk) }} />
                  </div>
                </div>
              ))}
              {algorithmExposure.length === 0 && <div className="rounded-lg border border-dashed border-slate-200 p-6 text-center text-xs font-bold text-slate-500 dark:border-white/10 dark:text-white/35">No algorithm exposure concentration available yet.</div>}
            </div>
          </section>

          <section className={panelClass()}>
            <div className="mb-4 flex items-center justify-between gap-3">
              <h2 className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
                <ShieldAlert className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
                Priority Remediation Queue
              </h2>
              <a href="/dashboard/pqc-orchestration" className="inline-flex items-center gap-1 text-[10px] font-black uppercase tracking-widest text-cyan-600 no-underline hover:text-cyan-500 dark:text-[#FFD36B]">
                Orchestrate <ArrowRight className="h-3.5 w-3.5" />
              </a>
            </div>
            <div className="overflow-hidden rounded-xl border border-slate-200 dark:border-white/8">
              <div className="grid grid-cols-[1.1fr_0.8fr_0.7fr_1fr] gap-3 border-b border-slate-200 bg-slate-50/90 px-4 py-3 text-[9px] font-black uppercase tracking-widest text-slate-500 dark:border-white/8 dark:bg-black/25 dark:text-white/35">
                <span>Asset</span><span>Algorithm</span><span>Risk</span><span>Migration Path</span>
              </div>
              {prioritizedNodes.slice(0, 6).map((node) => (
                <button key={node.id} type="button" onClick={() => setSelectedNode(node)} className="grid w-full grid-cols-[1.1fr_0.8fr_0.7fr_1fr] gap-3 border-b border-slate-200 px-4 py-3 text-left text-xs last:border-b-0 hover:bg-cyan-50 dark:border-white/8 dark:hover:bg-white/[0.03]">
                  <span className="truncate font-black text-slate-900 dark:text-white">{node.label}</span>
                  <span className="truncate font-mono font-bold text-slate-600 dark:text-white/55">{node.algorithm}</span>
                  <span className={cx('w-fit rounded-full border px-2 py-1 text-[9px] font-black uppercase', riskTone(node.risk))}>{node.risk}</span>
                  <span className="truncate font-semibold text-cyan-600 dark:text-[#FFD36B]">{node.recommendedMigrationPath || 'Manual review'}</span>
                </button>
              ))}
              {prioritizedNodes.length === 0 && <div className="p-6 text-center text-xs font-bold text-slate-500 dark:text-white/35">No prioritized remediation assets yet.</div>}
            </div>
          </section>
        </div>

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.15fr)_minmax(360px,0.85fr)]">
          <section className={panelClass()}>
            <div className="mb-4 flex items-center justify-between gap-3">
              <h2 className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
                <AlertTriangle className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
                Exposure Findings Evidence
              </h2>
              <a href="/dashboard/vulnerabilities" className="inline-flex items-center gap-1 text-[10px] font-black uppercase tracking-widest text-cyan-600 no-underline hover:text-cyan-500 dark:text-[#FFD36B]">
                View Vulnerabilities <ArrowRight className="h-3.5 w-3.5" />
              </a>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              {prioritizedFindings.slice(0, 8).map((finding) => (
                <div key={`${finding.id}-${finding.asset}`} className="rounded-xl border border-slate-200 bg-white/60 p-4 dark:border-white/8 dark:bg-white/[0.03]">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-black text-slate-950 dark:text-white">{finding.algorithm}</div>
                      <div className="mt-1 truncate text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-white/35">{finding.asset}</div>
                    </div>
                    <span className={cx('shrink-0 rounded-full border px-2 py-1 text-[8px] font-black uppercase tracking-widest', riskTone(finding.risk))}>{finding.severity}</span>
                  </div>
                  <div className="mt-3 text-xs font-semibold leading-5 text-slate-600 dark:text-white/50">{finding.category} | {finding.status}</div>
                  <div className="mt-3 rounded-lg border border-slate-200 bg-slate-50/80 p-3 text-[10px] font-semibold text-slate-500 dark:border-white/8 dark:bg-black/20 dark:text-white/40">
                    {finding.recommendedMigrationPath || 'Review migration path and owner before cutover.'}
                  </div>
                </div>
              ))}
              {prioritizedFindings.length === 0 && <div className="col-span-full rounded-lg border border-dashed border-slate-200 p-8 text-center text-xs font-bold text-slate-500 dark:border-white/10 dark:text-white/35">No exposure findings available yet.</div>}
            </div>
          </section>

          <section className={panelClass()}>
            <div className="mb-4 flex items-center justify-between gap-3">
              <h2 className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
                <Activity className="h-4 w-4 text-cyan-500 dark:text-[#FFD36B]" />
                Live Evidence Feed
              </h2>
              <span className="rounded-full border border-emerald-400/30 bg-emerald-400/10 px-2 py-1 text-[9px] font-black uppercase tracking-widest text-emerald-600 dark:text-emerald-300">Synchronized</span>
            </div>
            <div className="space-y-3">
              {activity.map((item) => (
                <div key={item.id} className="grid grid-cols-[34px_1fr] gap-3 rounded-lg border border-slate-200 bg-white/60 p-3 dark:border-white/8 dark:bg-white/[0.03]">
                  <div className="grid h-8 w-8 place-items-center rounded-full border border-cyan-400/30 bg-cyan-400/10 text-cyan-500 dark:border-[#FFD36B]/30 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">
                    <Zap className="h-4 w-4" />
                  </div>
                  <div className="min-w-0">
                    <div className="truncate text-xs font-black text-slate-950 dark:text-white">{item.title}</div>
                    <div className="mt-1 truncate text-[10px] font-semibold text-slate-500 dark:text-white/40">{item.detail}</div>
                    <div className="mt-2 text-[9px] font-black uppercase tracking-widest text-slate-400 dark:text-white/25">{shortTime(item.time)}</div>
                  </div>
                </div>
              ))}
              {activity.length === 0 && <div className="rounded-lg border border-dashed border-slate-200 p-8 text-center text-xs font-bold text-slate-500 dark:border-white/10 dark:text-white/35">Live evidence will appear after scan, runtime, or telemetry events.</div>}
            </div>
          </section>
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {[
            { title: 'Generate Remediation Plan', href: '/dashboard/migration-planner', icon: TrendingDown, detail: 'Convert priority exposure assets into migration jobs.' },
            { title: 'Validate In Sandbox', href: '/dashboard/migration-sandbox', icon: ShieldCheck, detail: 'Test hybrid TLS and PQC compatibility before rollout.' },
            { title: 'Review CBOM Evidence', href: '/dashboard/cbom', icon: Layers, detail: 'Inspect algorithm inventory and affected components.' },
            { title: 'Export Risk Evidence', href: '/dashboard/audit-vault', icon: Download, detail: 'Preserve exposure evidence for governance and audit.' },
          ].map((action) => {
            const Icon = action.icon;
            return (
              <a key={action.title} href={action.href} className={panelClass('min-h-[140px] no-underline hover:-translate-y-1')}>
                <div className="relative z-10 flex items-start justify-between gap-4">
                  <div>
                    <div className="text-sm font-black uppercase tracking-wider text-slate-950 dark:text-white">{action.title}</div>
                    <div className="mt-2 text-xs font-semibold leading-5 text-slate-500 dark:text-white/45">{action.detail}</div>
                  </div>
                  <div className="grid h-11 w-11 shrink-0 place-items-center rounded-lg border border-cyan-400/30 bg-cyan-400/10 text-cyan-500 dark:border-[#FFD36B]/30 dark:bg-[#FFD36B]/10 dark:text-[#FFD36B]">
                    <Icon className="h-5 w-5" />
                  </div>
                </div>
              </a>
            );
          })}
        </div>
      </div>
    </main>
  );
}
