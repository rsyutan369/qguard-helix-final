'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  AlertTriangle,
  Bell,
  CalendarDays,
  ChevronRight,
  Download,
  Eye,
  Filter,
  Info,
  Maximize2,
  Radio,
  RefreshCw,
  Settings,
  ShieldCheck,
  Sparkles,
  type LucideIcon,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import { cn } from '@/lib/utils';

type LoadState = 'loading' | 'success' | 'error';
type Severity = 'critical' | 'high' | 'medium' | 'low' | string;

type MetricSnapshot = {
  behaviorRiskScore: number;
  behaviorRiskLevel: string;
  riskDelta: number;
  anomalousEntities: number;
  anomalousEntitiesDelta: number;
  cryptoOpsPerSec: number;
  cryptoOpsDelta: number;
  unusualPatterns: number;
  unusualPatternsDelta: number;
  aiConfidence: number;
  totalOperations: number;
  totalAssets: number;
  totalFindings: number;
};

type TrendPoint = {
  label: string;
  normal: number;
  anomalous: number;
  predicted: number;
};

type DistributionRow = {
  label: string;
  count: number;
  percent: number;
};

type PatternScore = {
  label: string;
  you: number;
  baseline: number;
};

type InsightRow = {
  id: string;
  title: string;
  message: string;
  severity: Severity;
  timestamp: string | null;
};

type EntityRow = {
  entity: string;
  anomalyScore: number;
  change: number;
  latestSeenAt: string | null;
};

type EventRow = {
  id: string;
  time: string | null;
  entity: string;
  event: string;
  pattern: string;
  severity: Severity;
  confidence: number;
  status: string;
  action: string;
};

type BehavioralSnapshot = {
  generatedAt: string | null;
  latestEventAt: string | null;
  latestScanAt: string | null;
  filters: {
    environments: string[];
  };
  metrics: MetricSnapshot;
  behaviorTrend: TrendPoint[];
  behaviorDistribution: DistributionRow[];
  anomalyCategories: DistributionRow[];
  behavioralPatternScore: PatternScore[];
  insights: InsightRow[];
  topEntities: EntityRow[];
  events: EventRow[];
  modelPerformance: {
    modelAccuracy: number;
    falsePositiveRate: number;
    modelDrift: number;
    lastModelUpdate: string | null;
  };
  telemetry: {
    connectedAgents: number;
    totalAgents: number;
    runtimeEvents: number;
    eventPipelineStatus: string;
    sources: Record<string, number>;
  };
};

const EMPTY_SNAPSHOT: BehavioralSnapshot = {
  generatedAt: null,
  latestEventAt: null,
  latestScanAt: null,
  filters: { environments: [] },
  metrics: {
    behaviorRiskScore: 0,
    behaviorRiskLevel: 'No Runtime Data',
    riskDelta: 0,
    anomalousEntities: 0,
    anomalousEntitiesDelta: 0,
    cryptoOpsPerSec: 0,
    cryptoOpsDelta: 0,
    unusualPatterns: 0,
    unusualPatternsDelta: 0,
    aiConfidence: 0,
    totalOperations: 0,
    totalAssets: 0,
    totalFindings: 0,
  },
  behaviorTrend: [],
  behaviorDistribution: [
    { label: 'Normal', count: 0, percent: 0 },
    { label: 'Anomalous', count: 0, percent: 0 },
    { label: 'Potential Risk', count: 0, percent: 0 },
    { label: 'Unknown', count: 0, percent: 0 },
  ],
  anomalyCategories: [],
  behavioralPatternScore: [
    { label: 'Key Usage', you: 0, baseline: 0 },
    { label: 'Algorithm Strength', you: 0, baseline: 0 },
    { label: 'Time Pattern', you: 0, baseline: 0 },
    { label: 'Volume Pattern', you: 0, baseline: 0 },
    { label: 'Entity Reputation', you: 0, baseline: 0 },
  ],
  insights: [],
  topEntities: [],
  events: [],
  modelPerformance: {
    modelAccuracy: 0,
    falsePositiveRate: 0,
    modelDrift: 0,
    lastModelUpdate: null,
  },
  telemetry: {
    connectedAgents: 0,
    totalAgents: 0,
    runtimeEvents: 0,
    eventPipelineStatus: 'no_agents',
    sources: {},
  },
};

const GOLD = '#FBBF24';
const BLUE = '#2478FF';
const CYAN = '#22D3EE';
const PURPLE = '#A855F7';
const ORANGE = '#F59E0B';
const RED = '#EF4444';
const GREEN = '#22C55E';
const SLATE = '#64748B';

const GLASS_PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-gold/18 bg-[#07101D]/72 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(251,191,36,0.035),0_0_34px_rgba(0,0,0,0.32)] transition-all duration-500 hover:-translate-y-0.5 hover:border-gold/65 hover:bg-[#0A1728]/82 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.22),inset_0_-24px_60px_rgba(251,191,36,0.12),0_14px_42px_rgba(0,0,0,0.45),0_0_54px_rgba(251,191,36,0.32)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/70 before:to-transparent after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-52 after:w-52 after:rounded-full after:bg-gold/10 after:blur-3xl after:transition-all group-hover:after:bg-gold/20';

function integerFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(value || 0)));
}

function compactFmt(value: number) {
  return new Intl.NumberFormat('en-US', {
    maximumFractionDigits: value >= 10 ? 1 : 3,
  }).format(Math.max(0, Number(value) || 0));
}

function percentFmt(value: number) {
  return `${integerFmt(value)}%`;
}

function shortTime(value: string | null) {
  if (!value) return '--';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '--';
  return date.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
}

function longDate(value: string | null) {
  if (!value) return 'Awaiting telemetry';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Awaiting telemetry';
  return date.toLocaleString('en-US', { month: 'short', day: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function dateRangeLabel() {
  const end = new Date();
  const start = new Date(end);
  start.setDate(end.getDate() - 7);
  const format = (date: Date) => date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  return `${format(start)} - ${format(end)}, ${end.getFullYear()}`;
}

function severityClass(severity: Severity) {
  const value = String(severity || '').toLowerCase();
  if (value === 'critical') return 'border-red-500/35 bg-red-500/10 text-red-300';
  if (value === 'high') return 'border-orange-500/35 bg-orange-500/10 text-orange-300';
  if (value === 'medium' || value === 'warning') return 'border-gold/35 bg-gold/10 text-gold';
  return 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300';
}

function severityTone(severity: Severity) {
  const value = String(severity || '').toLowerCase();
  if (value === 'critical') return RED;
  if (value === 'high') return ORANGE;
  if (value === 'medium' || value === 'warning') return GOLD;
  return GREEN;
}

function deltaClass(value: number) {
  if (value > 0) return 'text-emerald-300';
  if (value < 0) return 'text-red-300';
  return 'text-white/45';
}

function deltaLabel(value: number) {
  if (value > 0) return `+ ${integerFmt(value)}% vs last 7 days`;
  if (value < 0) return `${integerFmt(value)}% vs last 7 days`;
  return '0% vs last 7 days';
}

function linePath(values: number[], width: number, height: number) {
  if (!values.length) return '';
  const max = Math.max(1, ...values);
  const min = Math.min(0, ...values);
  const range = Math.max(1, max - min);
  return values.map((value, index) => {
    const x = values.length === 1 ? width / 2 : (index / (values.length - 1)) * width;
    const y = height - ((value - min) / range) * (height - 10) - 5;
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(' ');
}

function polygonPoints(rows: PatternScore[], key: 'you' | 'baseline', radius: number, center: number) {
  const count = Math.max(1, rows.length);
  return rows.map((row, index) => {
    const angle = (-90 + (360 / count) * index) * (Math.PI / 180);
    const distance = (Math.max(0, Math.min(100, row[key])) / 100) * radius;
    return `${(center + Math.cos(angle) * distance).toFixed(1)},${(center + Math.sin(angle) * distance).toFixed(1)}`;
  }).join(' ');
}

function useBehavioralAnalytics() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<BehavioralSnapshot>(EMPTY_SNAPSHOT);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const streamsRef = useRef<EventSource[]>([]);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const closeStreams = useCallback(() => {
    for (const stream of streamsRef.current) stream.close();
    streamsRef.current = [];
    setSseConnected(false);
  }, []);

  const refresh = useCallback(async () => {
    if (!token) {
      setSnapshot(EMPTY_SNAPSHOT);
      setState('success');
      setError(null);
      return;
    }

    setState((current) => current === 'success' ? current : 'loading');
    try {
      const response = await fetch('/api/v1/dashboard/behavioral-analytics', {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      setSnapshot({ ...EMPTY_SNAPSHOT, ...(payload.data || {}) });
      setState('success');
      setError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to load behavioral analytics';
      console.error('Behavioral analytics telemetry failed:', err);
      setError(message);
      setState('error');
    }
  }, [token]);

  const queueRefresh = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null;
      void refresh();
    }, 250);
  }, [refresh]);

  useEffect(() => () => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
  }, []);

  useEffect(() => {
    if (!token || !user) {
      setSnapshot(EMPTY_SNAPSHOT);
      setState('success');
      return;
    }
    void refresh();
  }, [token, user, refresh]);

  useEffect(() => {
    if (!user) return;

    const tables = [
      'assets',
      'asset_relationships',
      'runtime_crypto_events',
      'crypto_inventory',
      'crypto_exposures',
      'pqc_scan_results',
      'pqc_scan_sessions',
      'security_events',
      'migration_jobs',
      'migration_events',
      'compliance_evidence',
      'generated_keys',
      'certificates',
      'scanner_alerts',
      'scanner_evidence',
      'scanner_agents',
      'agent_heartbeats',
      'connector_accounts',
      'qrng_events',
      'vault_audit_logs',
    ];

    const channels = tables.map((table) => supabase
      .channel(`behavioral-analytics-${table}`)
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` },
        queueRefresh,
      )
      .subscribe());

    return () => {
      for (const channel of channels) supabase.removeChannel(channel);
    };
  }, [user, queueRefresh]);

  useEffect(() => {
    if (!token) {
      closeStreams();
      return;
    }

    let retryTimer: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      closeStreams();
      const behavioralStream = new EventSource(`/api/v1/dashboard/behavioral-analytics/stream?token=${encodeURIComponent(token)}`);
      const metricsStream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`);
      const scannerStream = new EventSource(`/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`);
      streamsRef.current = [behavioralStream, metricsStream, scannerStream];

      const markOpen = () => setSseConnected(true);
      const scheduleReconnect = () => {
        setSseConnected(false);
        closeStreams();
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(connect, 10000);
      };
      const refreshFromStream = () => queueRefresh();

      behavioralStream.onopen = markOpen;
      metricsStream.onopen = markOpen;
      scannerStream.onopen = markOpen;
      behavioralStream.onerror = scheduleReconnect;
      metricsStream.onerror = scheduleReconnect;
      scannerStream.onerror = scheduleReconnect;
      behavioralStream.addEventListener('behavioral-analytics-connected', refreshFromStream);
      behavioralStream.addEventListener('behavioral-analytics-update', refreshFromStream);
      behavioralStream.addEventListener('behavioral-analytics-error', refreshFromStream);
      metricsStream.addEventListener('metrics-update', refreshFromStream);
      metricsStream.addEventListener('runtime-crypto-update', refreshFromStream);
      metricsStream.addEventListener('scan-complete', refreshFromStream);
      scannerStream.addEventListener('scanner-intelligence', refreshFromStream);
      scannerStream.addEventListener('scanner-error', refreshFromStream);
    };

    connect();
    return () => {
      if (retryTimer) clearTimeout(retryTimer);
      closeStreams();
    };
  }, [token, queueRefresh, closeStreams]);

  return { snapshot, state, error, sseConnected, refresh };
}

function GlassPanel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <section className={cn(GLASS_PANEL_CLASSES, className)}>
      <div className="relative z-10 h-full">{children}</div>
    </section>
  );
}

function HeaderButton({ icon: Icon, children, onClick }: { icon: LucideIcon; children: ReactNode; onClick?: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex h-10 items-center gap-2 rounded-md border border-white/10 bg-black/20 px-3 text-xs font-bold text-white/75 transition hover:border-gold/55 hover:bg-gold/10 hover:text-gold"
    >
      <Icon className="h-4 w-4" />
      {children}
    </button>
  );
}

function SectionTitle({ children, suffix }: { children: ReactNode; suffix?: ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-3">
      <h2 className="font-mono text-xs font-black uppercase tracking-[0.16em] text-white">{children}</h2>
      {suffix}
    </div>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex min-h-[120px] items-center justify-center rounded-md border border-dashed border-white/10 bg-white/[0.02] px-4 text-center text-xs font-medium text-white/35">
      {label}
    </div>
  );
}

function Sparkline({ values, color }: { values: number[]; color: string }) {
  const path = linePath(values, 112, 34);
  return (
    <svg className="h-9 w-28" viewBox="0 0 112 34" aria-hidden="true">
      <path d={path} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function MetricCard({
  label,
  value,
  unit,
  delta,
  tone,
  spark,
}: {
  label: string;
  value: string;
  unit?: string;
  delta?: number;
  tone: string;
  spark: number[];
}) {
  return (
    <GlassPanel className="min-h-[104px] p-4">
      <div className="flex h-full flex-col justify-between gap-2">
        <div className="text-[10px] font-black uppercase tracking-[0.14em] text-white/72">{label}</div>
        <div className="flex items-end justify-between gap-3">
          <div>
            <div className="flex items-baseline gap-1">
              <span className="text-3xl font-semibold text-white">{value}</span>
              {unit ? <span className="text-xs font-semibold text-white/48">{unit}</span> : null}
            </div>
            {typeof delta === 'number' ? (
              <div className={cn('mt-1 text-[10px] font-bold', deltaClass(delta))}>{deltaLabel(delta)}</div>
            ) : null}
          </div>
          <Sparkline values={spark} color={tone} />
        </div>
      </div>
    </GlassPanel>
  );
}

function ConfidenceRing({ value }: { value: number }) {
  const safe = Math.max(0, Math.min(100, value));
  return (
    <div className="relative grid h-14 w-14 place-items-center rounded-full" style={{ background: `conic-gradient(${BLUE} ${safe}%, rgba(255,255,255,0.08) 0)` }}>
      <div className="absolute inset-2 rounded-full bg-[#06101d]" />
      <div className="relative text-[10px] font-black text-white">{integerFmt(safe)}</div>
    </div>
  );
}

function MainLineChart({ points }: { points: TrendPoint[] }) {
  const width = 900;
  const height = 280;
  const chartHeight = 210;
  const padX = 38;
  const values = points.flatMap((point) => [point.normal, point.anomalous, point.predicted]);
  const max = Math.max(1, ...values);
  const xFor = (index: number) => padX + (points.length <= 1 ? 0 : (index / (points.length - 1)) * (width - padX - 18));
  const yFor = (value: number) => 24 + chartHeight - (value / max) * chartHeight;
  const pathFor = (key: keyof TrendPoint) => points.map((point, index) => {
    const value = typeof point[key] === 'number' ? point[key] as number : 0;
    return `${index === 0 ? 'M' : 'L'} ${xFor(index).toFixed(1)} ${yFor(value).toFixed(1)}`;
  }).join(' ');

  if (!points.length) return <EmptyState label="Awaiting authenticated runtime behavior telemetry." />;

  return (
    <svg className="h-full min-h-[260px] w-full" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Crypto usage behavior over time">
      {[0, 1, 2, 3, 4].map((line) => {
        const y = 24 + (chartHeight / 4) * line;
        const label = Math.round(max - (max / 4) * line);
        return (
          <g key={line}>
            <line x1={padX} x2={width - 18} y1={y} y2={y} stroke="rgba(255,255,255,0.06)" />
            <text x="4" y={y + 4} fill="rgba(255,255,255,0.36)" fontSize="10">{label}</text>
          </g>
        );
      })}
      {points.map((point, index) => (
        <g key={point.label}>
          <line x1={xFor(index)} x2={xFor(index)} y1="24" y2={24 + chartHeight} stroke="rgba(255,255,255,0.035)" />
          <text x={xFor(index)} y={height - 16} textAnchor="middle" fill="rgba(255,255,255,0.45)" fontSize="10">{point.label}</text>
        </g>
      ))}
      <path d={pathFor('normal')} fill="none" stroke={BLUE} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
      <path d={pathFor('anomalous')} fill="none" stroke={PURPLE} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
      <path d={pathFor('predicted')} fill="none" stroke={CYAN} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" strokeDasharray="6 7" />
      {points.map((point, index) => point.anomalous > 0 ? (
        <circle key={`${point.label}-anomaly`} cx={xFor(index)} cy={yFor(point.anomalous)} r="4" fill={PURPLE} stroke="#111827" strokeWidth="2" />
      ) : null)}
    </svg>
  );
}

function DonutChart({ rows, total }: { rows: DistributionRow[]; total: number }) {
  const colors = [BLUE, PURPLE, ORANGE, SLATE];
  let cursor = 0;
  const stops = rows.map((row, index) => {
    const start = cursor;
    cursor += row.percent;
    return `${colors[index] || GOLD} ${start}% ${cursor}%`;
  }).join(', ');
  const background = total > 0 ? `conic-gradient(${stops})` : 'conic-gradient(rgba(255,255,255,0.08) 0 100%)';

  return (
    <div className="grid gap-5 md:grid-cols-[132px_1fr] md:items-center">
      <div className="relative h-32 w-32 rounded-full" style={{ background }}>
        <div className="absolute inset-7 grid place-items-center rounded-full bg-[#07101D] text-center shadow-[inset_0_0_24px_rgba(0,0,0,0.65)]">
          <div className="text-2xl font-semibold text-white">{integerFmt(total)}</div>
          <div className="text-[10px] font-bold text-white/45">Total</div>
        </div>
      </div>
      <div className="space-y-3">
        {rows.map((row, index) => (
          <div key={row.label} className="grid grid-cols-[1fr_auto] items-center gap-3 text-xs">
            <div className="flex items-center gap-2 text-white/72">
              <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: colors[index] || GOLD }} />
              {row.label}
            </div>
            <div className="font-mono text-white/64">{integerFmt(row.count)} ({percentFmt(row.percent)})</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function CategoryBars({ rows }: { rows: DistributionRow[] }) {
  if (!rows.length) return <EmptyState label="No anomalous categories are present for this tenant window." />;
  const colors = [RED, ORANGE, GOLD, CYAN, BLUE, PURPLE];
  return (
    <div className="space-y-3">
      {rows.map((row, index) => (
        <div key={row.label} className="grid grid-cols-[128px_1fr_38px] items-center gap-3 text-xs">
          <span className="truncate text-white/70">{row.label}</span>
          <div className="h-2 overflow-hidden rounded-full bg-white/7">
            <div className="h-full rounded-full" style={{ width: `${row.percent}%`, backgroundColor: colors[index] || GOLD }} />
          </div>
          <span className="text-right font-mono text-white/70">{percentFmt(row.percent)}</span>
        </div>
      ))}
    </div>
  );
}

function RadarChart({ rows }: { rows: PatternScore[] }) {
  const center = 98;
  const radius = 72;
  const rings = [0.25, 0.5, 0.75, 1];
  const count = Math.max(1, rows.length);
  const axisPoints = rows.map((row, index) => {
    const angle = (-90 + (360 / count) * index) * (Math.PI / 180);
    return {
      label: row.label,
      x: center + Math.cos(angle) * radius,
      y: center + Math.sin(angle) * radius,
      lx: center + Math.cos(angle) * (radius + 22),
      ly: center + Math.sin(angle) * (radius + 22),
    };
  });

  return (
    <div className="flex items-center justify-center">
      <svg className="h-56 w-full max-w-[280px]" viewBox="0 0 196 196" aria-hidden="true">
        {rings.map((ring) => (
          <polygon
            key={ring}
            points={axisPoints.map((point) => `${center + (point.x - center) * ring},${center + (point.y - center) * ring}`).join(' ')}
            fill="none"
            stroke="rgba(255,255,255,0.10)"
          />
        ))}
        {axisPoints.map((point) => (
          <g key={point.label}>
            <line x1={center} y1={center} x2={point.x} y2={point.y} stroke="rgba(255,255,255,0.08)" />
            <text x={point.lx} y={point.ly} textAnchor="middle" dominantBaseline="middle" fill="rgba(255,255,255,0.55)" fontSize="8">{point.label}</text>
          </g>
        ))}
        <polygon points={polygonPoints(rows, 'baseline', radius, center)} fill="none" stroke={CYAN} strokeWidth="1.5" strokeDasharray="5 5" />
        <polygon points={polygonPoints(rows, 'you', radius, center)} fill="rgba(36,120,255,0.22)" stroke={BLUE} strokeWidth="2.5" />
        <circle cx={center} cy={center} r="3" fill={GOLD} />
      </svg>
    </div>
  );
}

function TopEntities({ rows }: { rows: EntityRow[] }) {
  if (!rows.length) return <EmptyState label="No anomalous entities are currently active." />;
  return (
    <div className="space-y-2">
      <div className="grid grid-cols-[1fr_80px_56px] gap-3 border-b border-white/7 pb-2 text-[9px] font-black uppercase tracking-[0.12em] text-white/35">
        <span>Entity</span>
        <span className="text-right">Anomaly Score</span>
        <span className="text-right">Change</span>
      </div>
      {rows.map((row) => (
        <div key={row.entity} className="grid grid-cols-[1fr_80px_56px] items-center gap-3 border-b border-white/5 py-2 text-xs">
          <span className="truncate text-white/75">{row.entity}</span>
          <span className="text-right font-mono text-white/78">{integerFmt(row.anomalyScore)}</span>
          <span className={cn('text-right font-mono font-bold', deltaClass(row.change))}>{row.change > 0 ? '+' : ''}{integerFmt(row.change)}%</span>
        </div>
      ))}
    </div>
  );
}

function Insights({ rows }: { rows: InsightRow[] }) {
  if (!rows.length) return <EmptyState label="No behavioral insight requires attention right now." />;
  return (
    <div className="space-y-3">
      {rows.map((row) => (
        <div key={row.id} className="grid grid-cols-[34px_1fr_auto] gap-3 rounded-md border border-white/8 bg-black/16 p-3">
          <div className="grid h-8 w-8 place-items-center rounded-full border" style={{ borderColor: `${severityTone(row.severity)}55`, backgroundColor: `${severityTone(row.severity)}18` }}>
            <AlertTriangle className="h-4 w-4" style={{ color: severityTone(row.severity) }} />
          </div>
          <div>
            <div className="text-xs font-black text-white">{row.title}</div>
            <div className="mt-1 text-[11px] leading-relaxed text-white/55">{row.message}</div>
          </div>
          <div className="flex flex-col items-end justify-between gap-2 text-right">
            <span className="font-mono text-[10px] text-white/42">{shortTime(row.timestamp)}</span>
            <span className={cn('rounded px-2 py-1 text-[10px] font-black', severityClass(row.severity))}>{String(row.severity || 'low')}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function EventsTable({ rows }: { rows: EventRow[] }) {
  if (!rows.length) return <EmptyState label="No authenticated behavioral events are available yet." />;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-[820px] w-full border-collapse text-left text-xs">
        <thead>
          <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.12em] text-white/35">
            <th className="pb-3 font-black">Time</th>
            <th className="pb-3 font-black">Entity</th>
            <th className="pb-3 font-black">Event</th>
            <th className="pb-3 font-black">Pattern</th>
            <th className="pb-3 font-black">Severity</th>
            <th className="pb-3 font-black">AI Confidence</th>
            <th className="pb-3 font-black">Status</th>
            <th className="pb-3 text-right font-black">Action</th>
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 8).map((row) => (
            <tr key={row.id} className="border-b border-white/5 text-white/68">
              <td className="py-3 font-mono text-[11px] text-white/45">{shortTime(row.time)}</td>
              <td className="max-w-[160px] truncate py-3">{row.entity}</td>
              <td className="max-w-[180px] truncate py-3">{row.event}</td>
              <td className="max-w-[170px] truncate py-3">{row.pattern}</td>
              <td className="py-3"><span className={cn('rounded px-2 py-1 text-[10px] font-black', severityClass(row.severity))}>{String(row.severity || 'low')}</span></td>
              <td className="py-3 font-mono">{integerFmt(row.confidence)}%</td>
              <td className="py-3 text-emerald-300">{row.status}</td>
              <td className="py-3 text-right">
                <a href="/dashboard/runtime-crypto-intel" className="inline-grid h-7 w-7 place-items-center rounded-md border border-white/10 text-white/55 transition hover:border-gold/55 hover:text-gold" title={row.action}>
                  <Eye className="h-3.5 w-3.5" />
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ModelPerformance({ snapshot }: { snapshot: BehavioralSnapshot }) {
  const rows = [
    { label: 'Model Accuracy', value: snapshot.modelPerformance.modelAccuracy, suffix: '%' },
    { label: 'False Positive Rate', value: snapshot.modelPerformance.falsePositiveRate, suffix: '%' },
    { label: 'Model Drift', value: snapshot.modelPerformance.modelDrift, suffix: '%' },
  ];

  return (
    <div className="space-y-5">
      {rows.map((row) => (
        <div key={row.label} className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-white/68">{row.label}</span>
            <span className="font-mono text-white/86">{compactFmt(row.value)}{row.suffix}</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-white/7">
            <div className="h-full rounded-full bg-gradient-to-r from-blue-500 to-gold" style={{ width: `${Math.max(0, Math.min(100, row.value))}%` }} />
          </div>
        </div>
      ))}
      <div className="flex items-center justify-between border-t border-white/8 pt-4 text-xs">
        <span className="text-white/55">Last Model Update</span>
        <span className="text-right font-mono text-white/78">{longDate(snapshot.modelPerformance.lastModelUpdate)}</span>
      </div>
    </div>
  );
}

export default function BehavioralAnalyticsPage() {
  const { snapshot, state, error, sseConnected, refresh } = useBehavioralAnalytics();

  const chartValues = useMemo(() => snapshot.behaviorTrend.map((point) => point.normal + point.anomalous), [snapshot.behaviorTrend]);
  const anomalyValues = useMemo(() => snapshot.behaviorTrend.map((point) => point.anomalous), [snapshot.behaviorTrend]);
  const totalDistribution = snapshot.behaviorDistribution.reduce((sum, row) => sum + row.count, 0);

  const exportReport = useCallback(() => {
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `behavioral-analytics-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }, [snapshot]);

  return (
    <div className="min-h-screen bg-[#030711] px-4 py-5 text-white sm:px-5 lg:px-6">
      <div className="mx-auto max-w-[1540px] space-y-4">
        <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-semibold tracking-normal text-white">Behavioral Analytics</h1>
              <Info className="h-4 w-4 text-white/42" />
            </div>
            <p className="mt-1 text-sm text-white/58">AI-driven analysis of cryptographic usage patterns</p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <HeaderButton icon={Filter}>All Environments</HeaderButton>
            <HeaderButton icon={CalendarDays}>{dateRangeLabel()}</HeaderButton>
            <HeaderButton icon={Radio}>{sseConnected ? 'Live' : 'Syncing'}</HeaderButton>
            <HeaderButton icon={Bell}>{snapshot.telemetry.eventPipelineStatus.replace(/_/g, ' ')}</HeaderButton>
            <HeaderButton icon={Settings}>Settings</HeaderButton>
            <button
              type="button"
              onClick={exportReport}
              className="inline-flex h-10 items-center gap-2 rounded-md border border-gold/35 bg-gold/10 px-4 text-xs font-black text-white transition hover:border-gold/80 hover:bg-gold/20 hover:text-gold"
            >
              <Download className="h-4 w-4" />
              Export Report
            </button>
          </div>
        </header>

        {error ? (
          <div className="rounded-md border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-200">
            {error}
          </div>
        ) : null}

        <motion.section
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-[1.08fr_1fr_1fr_1fr_0.72fr]"
        >
          <MetricCard
            label="Behavioral Risk Score"
            value={integerFmt(snapshot.metrics.behaviorRiskScore)}
            unit="/100"
            delta={snapshot.metrics.riskDelta}
            tone={snapshot.metrics.behaviorRiskScore >= 70 ? RED : ORANGE}
            spark={anomalyValues}
          />
          <MetricCard
            label="Anomalous Entities"
            value={integerFmt(snapshot.metrics.anomalousEntities)}
            delta={snapshot.metrics.anomalousEntitiesDelta}
            tone={PURPLE}
            spark={anomalyValues}
          />
          <MetricCard
            label="Crypto Operations / Sec"
            value={compactFmt(snapshot.metrics.cryptoOpsPerSec)}
            delta={snapshot.metrics.cryptoOpsDelta}
            tone={BLUE}
            spark={chartValues}
          />
          <MetricCard
            label="Unusual Patterns"
            value={integerFmt(snapshot.metrics.unusualPatterns)}
            delta={snapshot.metrics.unusualPatternsDelta}
            tone={CYAN}
            spark={anomalyValues}
          />
          <GlassPanel className="min-h-[104px] p-4">
            <div className="flex h-full items-center justify-between gap-3">
              <div>
                <div className="text-[10px] font-black uppercase tracking-[0.14em] text-white/72">AI Confidence</div>
                <div className="mt-3 text-3xl font-semibold text-white">{integerFmt(snapshot.metrics.aiConfidence)}%</div>
                <div className="mt-1 text-[10px] font-bold text-blue-300">{snapshot.metrics.behaviorRiskLevel}</div>
              </div>
              <ConfidenceRing value={snapshot.metrics.aiConfidence} />
            </div>
          </GlassPanel>
        </motion.section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-[2.1fr_1fr]">
          <GlassPanel className="min-h-[338px] p-5">
            <SectionTitle
              suffix={(
                <div className="flex items-center gap-2">
                  <button type="button" className="rounded border border-blue-500/45 bg-blue-500/10 px-3 py-1 text-[10px] font-black text-blue-300">7D</button>
                  <button type="button" className="rounded border border-white/8 px-3 py-1 text-[10px] font-black text-white/35">30D</button>
                  <button type="button" className="rounded border border-white/8 px-3 py-1 text-[10px] font-black text-white/35">90D</button>
                  <button type="button" className="rounded border border-white/8 p-1.5 text-white/45"><Maximize2 className="h-3.5 w-3.5" /></button>
                </div>
              )}
            >
              Crypto Usage Behavior Over Time
            </SectionTitle>
            <div className="mb-2 flex flex-wrap gap-5 text-[10px] text-white/55">
              <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-sm bg-blue-500" />Normal Behavior</span>
              <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-sm bg-purple-500" />Anomalous Behavior</span>
              <span className="inline-flex items-center gap-2"><span className="h-px w-5 border-t border-dashed border-cyan-300" />Predicted Trend</span>
            </div>
            <MainLineChart points={snapshot.behaviorTrend} />
          </GlassPanel>

          <GlassPanel className="min-h-[338px] p-5">
            <SectionTitle>Behavioral Insights</SectionTitle>
            <Insights rows={snapshot.insights} />
            <div className="mt-4 flex justify-end">
              <a href="/dashboard/runtime-crypto-intel" className="inline-flex items-center gap-1 text-xs font-bold text-blue-300 transition hover:text-gold">
                View All Insights <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </GlassPanel>
        </section>

        <section className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-4">
          <GlassPanel className="p-5">
            <SectionTitle>Behavior Distribution</SectionTitle>
            <DonutChart rows={snapshot.behaviorDistribution} total={totalDistribution} />
          </GlassPanel>

          <GlassPanel className="p-5">
            <SectionTitle>Anomaly Categories</SectionTitle>
            <CategoryBars rows={snapshot.anomalyCategories} />
          </GlassPanel>

          <GlassPanel className="p-5">
            <SectionTitle>Behavioral Pattern Score</SectionTitle>
            <RadarChart rows={snapshot.behavioralPatternScore} />
            <div className="mt-1 flex justify-center gap-6 text-[10px] font-bold text-white/55">
              <span className="inline-flex items-center gap-2"><span className="h-0.5 w-8 bg-blue-500" />You</span>
              <span className="inline-flex items-center gap-2"><span className="h-0.5 w-8 border-t border-dashed border-cyan-300" />Baseline</span>
            </div>
          </GlassPanel>

          <GlassPanel className="p-5">
            <SectionTitle>Top Anomalous Entities</SectionTitle>
            <TopEntities rows={snapshot.topEntities} />
            <div className="mt-4 flex justify-end">
              <a href="/dashboard/runtime-telemetry" className="inline-flex items-center gap-1 text-xs font-bold text-blue-300 transition hover:text-gold">
                View All Entities <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </GlassPanel>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-[2.1fr_1fr]">
          <GlassPanel className="p-5">
            <SectionTitle
              suffix={(
                <button
                  type="button"
                  onClick={() => void refresh()}
                  className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-black/20 px-3 py-1.5 text-[10px] font-black text-white/55 transition hover:border-gold/45 hover:text-gold"
                >
                  <RefreshCw className={cn('h-3.5 w-3.5', state === 'loading' && 'animate-spin')} />
                  Refresh
                </button>
              )}
            >
              Behavioral Events
            </SectionTitle>
            <EventsTable rows={snapshot.events} />
            <div className="mt-4 flex items-center justify-between text-xs text-white/38">
              <span>
                {integerFmt(snapshot.metrics.totalOperations)} operations, {integerFmt(snapshot.metrics.totalFindings)} findings, {integerFmt(snapshot.metrics.totalAssets)} assets synchronized
              </span>
              <a href="/dashboard/runtime-crypto-intel" className="inline-flex items-center gap-1 font-bold text-blue-300 transition hover:text-gold">
                View All Events <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </GlassPanel>

          <GlassPanel className="p-5">
            <SectionTitle
              suffix={<ShieldCheck className="h-4 w-4 text-white/36" />}
            >
              AI Model Performance
            </SectionTitle>
            <ModelPerformance snapshot={snapshot} />
            <div className="mt-5 rounded-md border border-white/8 bg-white/[0.03] p-3">
              <div className="flex items-center justify-between text-xs">
                <span className="text-white/55">Runtime agents</span>
                <span className="font-mono text-white/78">{integerFmt(snapshot.telemetry.connectedAgents)} / {integerFmt(snapshot.telemetry.totalAgents)}</span>
              </div>
              <div className="mt-2 flex items-center justify-between text-xs">
                <span className="text-white/55">Runtime events</span>
                <span className="font-mono text-white/78">{integerFmt(snapshot.telemetry.runtimeEvents)}</span>
              </div>
            </div>
            <button
              type="button"
              onClick={() => void refresh()}
              className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-md border border-blue-500/40 bg-blue-500/10 px-4 py-2 text-xs font-black text-blue-200 transition hover:border-gold/55 hover:bg-gold/10 hover:text-gold"
            >
              <Sparkles className="h-4 w-4" />
              Retrain Model
            </button>
          </GlassPanel>
        </section>

        <div className="flex flex-wrap items-center justify-between gap-3 text-[11px] text-white/35">
          <span className="inline-flex items-center gap-2">
            <span className={cn('h-2 w-2 rounded-full', sseConnected ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]' : 'bg-gold animate-pulse')} />
            {sseConnected ? 'SSE and live activity subscriptions connected' : 'Connecting live telemetry streams'}
          </span>
          <span>Latest synchronized event: {longDate(snapshot.latestEventAt || snapshot.latestScanAt)}</span>
        </div>

        {state === 'loading' && snapshot.metrics.totalOperations === 0 ? (
          <div className="fixed bottom-6 right-6 rounded-md border border-gold/30 bg-[#07101D]/90 px-4 py-3 text-xs font-bold text-gold shadow-[0_0_30px_rgba(251,191,36,0.18)]">
            Loading authenticated behavioral telemetry...
          </div>
        ) : null}
      </div>
    </div>
  );
}
