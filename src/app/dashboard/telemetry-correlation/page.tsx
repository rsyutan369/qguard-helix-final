'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  AlertTriangle,
  Bell,
  CalendarDays,
  ChevronRight,
  Cloud,
  Database,
  Download,
  Eye,
  Filter,
  Gauge,
  GitMerge,
  Info,
  LockKeyhole,
  Maximize2,
  MoreVertical,
  Network,
  Radio,
  RefreshCw,
  Search,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  type LucideIcon,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import { cn } from '@/lib/utils';

type LoadState = 'loading' | 'success' | 'error';
type Severity = 'critical' | 'high' | 'medium' | 'low' | string;

type Metrics = {
  telemetryEvents: number;
  telemetryEventsDelta: number;
  correlatedAlerts: number;
  correlatedAlertsDelta: number;
  endpointsMonitored: number;
  endpointsDelta: number;
  correlationMatches: number;
  correlationMatchesDelta: number;
  highRiskCorrelations: number;
  highRiskDelta: number;
  correlationScore: number;
  correlationScoreLevel: string;
};

type FlowNode = {
  label: string;
  count: number;
};

type TimelinePoint = {
  label: string;
  threatDetections: number;
  anomalies: number;
  policyViolations: number;
  cryptoWeakness: number;
  infoEvents: number;
};

type AlertRow = {
  id: string;
  alertName: string;
  correlationScore: number;
  endpoints: number;
  firstSeenAt: string | null;
  status: string;
  category: string;
  severity: Severity;
};

type CategoryRow = {
  label: string;
  count: number;
  percent: number;
};

type HeatmapRow = {
  label: string;
  values: Array<{ hour: string; value: number }>;
};

type SourceHealthRow = {
  source: string;
  status: string;
  events24h: number;
  lastSeenAt: string | null;
};

type RecentEventRow = {
  id: string;
  time: string | null;
  event: string;
  source: string;
  relatedEndpoints: number;
  correlationScore: number;
  category: string;
  severity: Severity;
  status: string;
};

type TelemetryCorrelationSnapshot = {
  generatedAt: string | null;
  latestEventAt: string | null;
  latestScanAt: string | null;
  filters: {
    environments: string[];
  };
  metrics: Metrics;
  flow: {
    sourceGroups: FlowNode[];
    outcomes: CategoryRow[];
    processingRate: number;
    correlationLatencyMs: number;
    dataSources: number;
    timeWindowHours: number;
  };
  timeline: TimelinePoint[];
  topAlerts: AlertRow[];
  categoryDistribution: CategoryRow[];
  heatmap: HeatmapRow[];
  dataSourcesHealth: SourceHealthRow[];
  recentEvents: RecentEventRow[];
  telemetry: {
    runtimeEvents: number;
    scannerEvidence: number;
    scannerAlerts: number;
    scanResults: number;
    securityEvents: number;
    assets: number;
    scannerAgents: number;
    connectors: number;
    eventPipelineStatus: string;
    latestRuntimeEventAt: string | null;
  };
};

const EMPTY_SNAPSHOT: TelemetryCorrelationSnapshot = {
  generatedAt: null,
  latestEventAt: null,
  latestScanAt: null,
  filters: { environments: [] },
  metrics: {
    telemetryEvents: 0,
    telemetryEventsDelta: 0,
    correlatedAlerts: 0,
    correlatedAlertsDelta: 0,
    endpointsMonitored: 0,
    endpointsDelta: 0,
    correlationMatches: 0,
    correlationMatchesDelta: 0,
    highRiskCorrelations: 0,
    highRiskDelta: 0,
    correlationScore: 0,
    correlationScoreLevel: 'No Runtime Data',
  },
  flow: {
    sourceGroups: [],
    outcomes: [],
    processingRate: 0,
    correlationLatencyMs: 0,
    dataSources: 0,
    timeWindowHours: 24,
  },
  timeline: [],
  topAlerts: [],
  categoryDistribution: [
    { label: 'Threat Detections', count: 0, percent: 0 },
    { label: 'Anomalies', count: 0, percent: 0 },
    { label: 'Policy Violations', count: 0, percent: 0 },
    { label: 'Crypto Weakness', count: 0, percent: 0 },
    { label: 'Informational', count: 0, percent: 0 },
  ],
  heatmap: [],
  dataSourcesHealth: [],
  recentEvents: [],
  telemetry: {
    runtimeEvents: 0,
    scannerEvidence: 0,
    scannerAlerts: 0,
    scanResults: 0,
    securityEvents: 0,
    assets: 0,
    scannerAgents: 0,
    connectors: 0,
    eventPipelineStatus: 'no_agents',
    latestRuntimeEventAt: null,
  },
};

const GOLD = '#FBBF24';
const BLUE = '#2478FF';
const CYAN = '#22D3EE';
const PURPLE = '#A855F7';
const ORANGE = '#F59E0B';
const RED = '#EF4444';
const GREEN = '#10B981';
const TEAL = '#14B8A6';
const SLATE = '#64748B';

const CATEGORY_COLORS: Record<string, string> = {
  'Threat Detections': RED,
  Anomalies: ORANGE,
  'Policy Violations': PURPLE,
  'Crypto Weakness': GOLD,
  Informational: BLUE,
};

const SOURCE_ICONS: Record<string, LucideIcon> = {
  'Web Applications': Server,
  'API Gateways': Network,
  Databases: Database,
  'Kubernetes Clusters': GitMerge,
  'Cloud Services': Cloud,
  'Network Devices': Network,
  Endpoints: Server,
};

const GLASS_PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-gold/18 bg-[#07101D]/72 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(251,191,36,0.035),0_0_34px_rgba(0,0,0,0.32)] transition-all duration-500 hover:-translate-y-0.5 hover:border-gold/65 hover:bg-[#0A1728]/82 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.22),inset_0_-24px_60px_rgba(251,191,36,0.12),0_14px_42px_rgba(0,0,0,0.45),0_0_54px_rgba(251,191,36,0.32)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/70 before:to-transparent after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-52 after:w-52 after:rounded-full after:bg-gold/10 after:blur-3xl after:transition-all group-hover:after:bg-gold/20';

function integerFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(value || 0)));
}

function compactFmt(value: number) {
  return new Intl.NumberFormat('en-US', {
    maximumFractionDigits: value >= 10 ? 1 : 3,
    notation: value >= 1000000 ? 'compact' : 'standard',
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

function timeAgo(value: string | null) {
  if (!value) return '--';
  const ms = new Date(value).getTime();
  if (!Number.isFinite(ms)) return '--';
  const seconds = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (seconds < 60) return `${seconds} sec ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} hr ago`;
  return `${Math.round(hours / 24)} days ago`;
}

function dateRangeLabel() {
  const end = new Date();
  const start = new Date(end);
  start.setDate(end.getDate() - 7);
  const format = (date: Date) => date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  return `${format(start)} - ${format(end)}, ${end.getFullYear()}`;
}

function severityTone(severity: Severity) {
  const value = String(severity || '').toLowerCase();
  if (value === 'critical') return RED;
  if (value === 'high') return RED;
  if (value === 'medium' || value === 'warning') return GOLD;
  return GREEN;
}

function severityClass(severity: Severity) {
  const value = String(severity || '').toLowerCase();
  if (value === 'critical') return 'border-red-500/35 bg-red-500/10 text-red-300';
  if (value === 'high') return 'border-red-500/35 bg-red-500/10 text-red-300';
  if (value === 'medium' || value === 'warning') return 'border-gold/35 bg-gold/10 text-gold';
  return 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300';
}

function healthClass(status: string) {
  const value = status.toLowerCase();
  if (value.includes('critical')) return 'text-red-300';
  if (value.includes('warning') || value.includes('stale')) return 'text-gold';
  return 'text-emerald-300';
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

function sparkPath(values: number[], width: number, height: number) {
  if (!values.length) return '';
  const max = Math.max(1, ...values);
  const min = Math.min(0, ...values);
  const range = Math.max(1, max - min);
  return values.map((value, index) => {
    const x = values.length === 1 ? width / 2 : (index / (values.length - 1)) * width;
    const y = height - ((value - min) / range) * (height - 8) - 4;
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(' ');
}

function useTelemetryCorrelation() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<TelemetryCorrelationSnapshot>(EMPTY_SNAPSHOT);
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
      const response = await fetch('/api/v1/dashboard/telemetry-correlation', {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      setSnapshot({
        ...EMPTY_SNAPSHOT,
        ...(payload.data || {}),
        metrics: { ...EMPTY_SNAPSHOT.metrics, ...(payload.data?.metrics || {}) },
        flow: { ...EMPTY_SNAPSHOT.flow, ...(payload.data?.flow || {}) },
        telemetry: { ...EMPTY_SNAPSHOT.telemetry, ...(payload.data?.telemetry || {}) },
      });
      setState('success');
      setError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to load telemetry correlation data';
      console.error('Telemetry correlation load failed:', err);
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
      'runtime_crypto_events',
      'scanner_alerts',
      'scanner_evidence',
      'scanner_agents',
      'connector_accounts',
      'pqc_scan_results',
      'pqc_scan_sessions',
      'crypto_exposures',
      'crypto_inventory',
      'security_events',
      'generated_keys',
      'certificates',
      'qrng_events',
      'vault_audit_logs',
      'agent_heartbeats',
    ];

    const channels = tables.map((table) => supabase
      .channel(`telemetry-correlation-${table}`)
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
      const metricsStream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`);
      const scannerStream = new EventSource(`/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`);
      const correlationStream = new EventSource(`/api/v1/dashboard/telemetry-correlation/stream?token=${encodeURIComponent(token)}`);
      streamsRef.current = [metricsStream, scannerStream, correlationStream];

      const markOpen = () => setSseConnected(true);
      const scheduleReconnect = () => {
        setSseConnected(false);
        closeStreams();
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(connect, 10000);
      };
      const refreshFromStream = () => queueRefresh();

      metricsStream.onopen = markOpen;
      scannerStream.onopen = markOpen;
      correlationStream.onopen = markOpen;
      metricsStream.onerror = scheduleReconnect;
      scannerStream.onerror = scheduleReconnect;
      correlationStream.onerror = scheduleReconnect;
      metricsStream.addEventListener('metrics-update', refreshFromStream);
      metricsStream.addEventListener('runtime-crypto-update', refreshFromStream);
      metricsStream.addEventListener('scan-complete', refreshFromStream);
      scannerStream.addEventListener('scanner-intelligence', refreshFromStream);
      scannerStream.addEventListener('scanner-error', refreshFromStream);
      correlationStream.addEventListener('telemetry-correlation-connected', refreshFromStream);
      correlationStream.addEventListener('telemetry-correlation-update', refreshFromStream);
      correlationStream.addEventListener('telemetry-correlation-error', refreshFromStream);
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
    <div className="flex min-h-[118px] items-center justify-center rounded-md border border-dashed border-white/10 bg-white/[0.02] px-4 text-center text-xs font-medium text-white/35">
      {label}
    </div>
  );
}

function Sparkline({ values, color }: { values: number[]; color: string }) {
  return (
    <svg className="h-9 w-28" viewBox="0 0 112 34" aria-hidden="true">
      <path d={sparkPath(values, 112, 34)} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function MetricCard({
  label,
  value,
  delta,
  color,
  spark,
  unit,
}: {
  label: string;
  value: string;
  delta?: number;
  color: string;
  spark: number[];
  unit?: string;
}) {
  return (
    <GlassPanel className="min-h-[104px] p-4">
      <div className="flex h-full flex-col justify-between gap-2">
        <div className="text-[10px] font-black uppercase tracking-[0.14em]" style={{ color }}>{label}</div>
        <div className="flex items-end justify-between gap-3">
          <div>
            <div className="flex items-baseline gap-1">
              <span className="text-3xl font-semibold text-white">{value}</span>
              {unit ? <span className="text-xs font-semibold text-white/48">{unit}</span> : null}
            </div>
            {typeof delta === 'number' ? <div className={cn('mt-1 text-[10px] font-bold', deltaClass(delta))}>{deltaLabel(delta)}</div> : null}
          </div>
          <Sparkline values={spark} color={color} />
        </div>
      </div>
    </GlassPanel>
  );
}

function ScoreRing({ value }: { value: number }) {
  const safe = Math.max(0, Math.min(100, value));
  return (
    <div className="relative grid h-14 w-14 place-items-center rounded-full" style={{ background: `conic-gradient(${BLUE} ${safe}%, rgba(255,255,255,0.08) 0)` }}>
      <div className="absolute inset-2 rounded-full bg-[#06101d]" />
      <div className="relative text-[10px] font-black text-white">{integerFmt(safe)}</div>
    </div>
  );
}

function FlowLine({ d, color, index }: { d: string; color: string; index: number }) {
  const duration = 3.8 + (index % 3) * 0.45;
  const delay = index * 0.22;

  return (
    <g>
      <path
        d={d}
        fill="none"
        stroke={color}
        strokeLinecap="round"
        strokeWidth="2.25"
        strokeOpacity="0.64"
        vectorEffect="non-scaling-stroke"
      />
      <path
        d={d}
        fill="none"
        filter="url(#correlation-flow-glow)"
        stroke={color}
        strokeLinecap="round"
        strokeDasharray="34 230"
        strokeDashoffset="260"
        strokeWidth="5.5"
        strokeOpacity="0.72"
        vectorEffect="non-scaling-stroke"
      >
        <animate attributeName="stroke-dashoffset" from="260" to="-40" dur={`${duration}s`} begin={`${delay}s`} repeatCount="indefinite" />
      </path>
      <path
        d={d}
        fill="none"
        stroke="#FFFFFF"
        strokeLinecap="round"
        strokeDasharray="10 254"
        strokeDashoffset="260"
        strokeWidth="1.3"
        strokeOpacity="0.88"
        vectorEffect="non-scaling-stroke"
      >
        <animate attributeName="stroke-dashoffset" from="260" to="-40" dur={`${duration}s`} begin={`${delay + 0.04}s`} repeatCount="indefinite" />
      </path>
    </g>
  );
}

function CorrelationFlow({ snapshot }: { snapshot: TelemetryCorrelationSnapshot }) {
  const sources = snapshot.flow.sourceGroups.slice(0, 6);
  const outcomes = snapshot.flow.outcomes.filter((item) => item.count > 0 || item.label !== 'Informational').slice(0, 5);
  const hasData = sources.some((source) => source.count > 0) || outcomes.some((outcome) => outcome.count > 0);

  if (!hasData) return <EmptyState label="Awaiting runtime telemetry, scanner evidence, and correlated events for this tenant." />;

  return (
    <div className="relative min-h-[350px]">
      <svg className="pointer-events-none absolute inset-0 h-full w-full" viewBox="0 0 900 350" preserveAspectRatio="none" aria-hidden="true">
        <defs>
          <filter id="correlation-flow-glow" x="-35%" y="-35%" width="170%" height="170%">
            <feGaussianBlur stdDeviation="3.2" result="blur" />
            <feColorMatrix in="blur" type="matrix" values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 1.65 0" result="glow" />
            <feMerge>
              <feMergeNode in="glow" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        {sources.map((source, index) => {
          const y = 52 + index * 45;
          const color = [BLUE, BLUE, BLUE, CYAN, ORANGE, RED][index] || GOLD;
          const d = `M 205 ${y} C 300 ${y}, 270 175, 410 175`;
          return (
            <g key={`source-path-${source.label}`}>
              <FlowLine d={d} color={color} index={index} />
            </g>
          );
        })}
        {outcomes.map((outcome, index) => {
          const y = 58 + index * 47;
          const d = `M 490 175 C 625 175, 600 ${y}, 700 ${y}`;
          return (
            <g key={`outcome-path-${outcome.label}`}>
              <FlowLine d={d} color={CATEGORY_COLORS[outcome.label] || GOLD} index={index + sources.length} />
            </g>
          );
        })}
      </svg>

      <div className="relative grid min-h-[350px] grid-cols-[210px_1fr_220px] items-center gap-5">
        <div className="space-y-2">
          <div className="mb-3 text-[10px] font-black uppercase tracking-[0.14em] text-cyan-300">Source Endpoints</div>
          {sources.map((source) => {
            const Icon = SOURCE_ICONS[source.label] || Server;
            return (
              <div key={source.label} className="grid grid-cols-[28px_1fr] items-center gap-2 rounded-md border border-white/8 bg-black/20 p-2">
                <div className="grid h-7 w-7 place-items-center rounded-md border border-blue-500/25 bg-blue-500/10 text-blue-300">
                  <Icon className="h-3.5 w-3.5" />
                </div>
                <div className="min-w-0">
                  <div className="truncate text-xs font-bold text-white/78">{source.label}</div>
                  <div className="text-[10px] text-white/42">{integerFmt(source.count)} events</div>
                </div>
              </div>
            );
          })}
        </div>

        <div className="mx-auto grid h-36 w-36 place-items-center rounded-xl border border-blue-500/35 bg-blue-500/10 shadow-[0_0_44px_rgba(36,120,255,0.22)]">
          <div className="grid h-16 w-16 place-items-center rounded-xl border border-purple-400/35 bg-purple-500/15 text-purple-200 shadow-[0_0_30px_rgba(168,85,247,0.25)]">
            <GitMerge className="h-8 w-8" />
          </div>
          <div className="text-center">
            <div className="text-[10px] font-black uppercase tracking-[0.14em] text-white">Correlation Engine</div>
            <div className="mt-1 text-[9px] text-white/45">Real-time Analysis</div>
          </div>
        </div>

        <div className="space-y-2">
          <div className="mb-3 text-[10px] font-black uppercase tracking-[0.14em] text-cyan-300">Correlated Outcomes</div>
          {outcomes.map((outcome) => (
            <div key={outcome.label} className="grid grid-cols-[28px_1fr] items-center gap-2 rounded-md border border-white/8 bg-black/20 p-2">
              <div className="grid h-7 w-7 place-items-center rounded-md border" style={{ borderColor: `${CATEGORY_COLORS[outcome.label] || GOLD}55`, backgroundColor: `${CATEGORY_COLORS[outcome.label] || GOLD}18`, color: CATEGORY_COLORS[outcome.label] || GOLD }}>
                {outcome.label === 'Threat Detections' ? <ShieldAlert className="h-3.5 w-3.5" /> : outcome.label === 'Crypto Weakness' ? <LockKeyhole className="h-3.5 w-3.5" /> : <AlertTriangle className="h-3.5 w-3.5" />}
              </div>
              <div className="min-w-0">
                <div className="truncate text-xs font-bold text-white/78">{outcome.label}</div>
                <div className="text-[10px] text-white/42">{integerFmt(outcome.count)} events</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-2 rounded-md border border-white/8 bg-black/18 p-3 md:grid-cols-4">
        <div className="border-r border-white/7 pr-3">
          <div className="text-[10px] text-white/42">Processing Rate</div>
          <div className="mt-1 text-xs font-bold text-white">{compactFmt(snapshot.flow.processingRate)} events/sec</div>
        </div>
        <div className="border-r border-white/7 pr-3">
          <div className="text-[10px] text-white/42">Correlation Latency</div>
          <div className="mt-1 text-xs font-bold text-white">{integerFmt(snapshot.flow.correlationLatencyMs)} ms</div>
        </div>
        <div className="border-r border-white/7 pr-3">
          <div className="text-[10px] text-white/42">Data Sources</div>
          <div className="mt-1 text-xs font-bold text-white">{integerFmt(snapshot.flow.dataSources)}</div>
        </div>
        <div>
          <div className="text-[10px] text-white/42">Time Window</div>
          <div className="mt-1 text-xs font-bold text-white">{integerFmt(snapshot.flow.timeWindowHours)} Hours</div>
        </div>
      </div>
    </div>
  );
}

function TimelineChart({ points }: { points: TimelinePoint[] }) {
  const width = 820;
  const height = 260;
  const chartHeight = 190;
  const padX = 38;
  const series = [
    { key: 'infoEvents', label: 'Info Events', color: BLUE },
    { key: 'cryptoWeakness', label: 'Crypto Weakness', color: GOLD },
    { key: 'policyViolations', label: 'Policy Violations', color: PURPLE },
    { key: 'anomalies', label: 'Anomalies', color: ORANGE },
    { key: 'threatDetections', label: 'Threat Detections', color: RED },
  ] as const;
  const max = Math.max(1, ...points.flatMap((point) => series.map((item) => Number(point[item.key]) || 0)));
  const xFor = (index: number) => padX + (points.length <= 1 ? 0 : (index / (points.length - 1)) * (width - padX - 14));
  const yFor = (value: number) => 20 + chartHeight - (value / max) * chartHeight;

  if (!points.length) return <EmptyState label="Awaiting correlated timeline telemetry." />;

  return (
    <svg className="h-full min-h-[260px] w-full" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Correlation timeline">
      {[0, 1, 2, 3, 4].map((line) => {
        const y = 20 + (chartHeight / 4) * line;
        const label = Math.round(max - (max / 4) * line);
        return (
          <g key={line}>
            <line x1={padX} x2={width - 14} y1={y} y2={y} stroke="rgba(255,255,255,0.06)" />
            <text x="4" y={y + 4} fill="rgba(255,255,255,0.36)" fontSize="10">{label}</text>
          </g>
        );
      })}
      {points.map((point, index) => (
        <g key={point.label}>
          <line x1={xFor(index)} x2={xFor(index)} y1="20" y2={20 + chartHeight} stroke="rgba(255,255,255,0.035)" />
          <text x={xFor(index)} y={height - 16} textAnchor="middle" fill="rgba(255,255,255,0.45)" fontSize="10">{point.label}</text>
        </g>
      ))}
      {series.map((item) => {
        const path = points.map((point, index) => `${index === 0 ? 'M' : 'L'} ${xFor(index).toFixed(1)} ${yFor(Number(point[item.key]) || 0).toFixed(1)}`).join(' ');
        return <path key={item.key} d={path} fill="none" stroke={item.color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />;
      })}
    </svg>
  );
}

function AlertsTable({ rows }: { rows: AlertRow[] }) {
  if (!rows.length) return <EmptyState label="No multi-source correlated alerts are active for this tenant." />;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-[620px] w-full border-collapse text-left text-xs">
        <thead>
          <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.12em] text-white/35">
            <th className="pb-3 font-black">Alert Name</th>
            <th className="pb-3 font-black">Correlation Score</th>
            <th className="pb-3 font-black">Endpoints</th>
            <th className="pb-3 font-black">First Seen</th>
            <th className="pb-3 text-right font-black">Status</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className="border-b border-white/5 text-white/68">
              <td className="max-w-[220px] truncate py-2.5">
                <span className="mr-2 inline-block h-2 w-2 rounded-full" style={{ backgroundColor: CATEGORY_COLORS[row.category] || severityTone(row.severity) }} />
                {row.alertName}
              </td>
              <td className="py-2.5 font-mono">{integerFmt(row.correlationScore)}</td>
              <td className="py-2.5 font-mono">{integerFmt(row.endpoints)}</td>
              <td className="py-2.5 font-mono text-white/52">{longDate(row.firstSeenAt)}</td>
              <td className="py-2.5 text-right"><span className={cn('rounded px-2 py-1 text-[10px] font-black', severityClass(row.severity))}>{row.status}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DonutChart({ rows }: { rows: CategoryRow[] }) {
  const total = rows.reduce((sum, row) => sum + row.count, 0);
  let cursor = 0;
  const stops = rows.map((row) => {
    const start = cursor;
    cursor += row.percent;
    return `${CATEGORY_COLORS[row.label] || SLATE} ${start}% ${cursor}%`;
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
      <div className="space-y-2.5">
        {rows.filter((row) => row.count > 0 || row.label !== 'Informational').map((row) => (
          <div key={row.label} className="grid grid-cols-[1fr_auto] items-center gap-3 text-xs">
            <div className="flex items-center gap-2 text-white/72">
              <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: CATEGORY_COLORS[row.label] || SLATE }} />
              {row.label}
            </div>
            <div className="font-mono text-white/64">{percentFmt(row.percent)} ({integerFmt(row.count)})</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Heatmap({ rows }: { rows: HeatmapRow[] }) {
  const max = Math.max(1, ...rows.flatMap((row) => row.values.map((item) => item.value)));
  if (!rows.length) return <EmptyState label="No source heatmap data is available for the selected 24 hour window." />;

  return (
    <div className="space-y-2">
      {rows.map((row) => (
        <div key={row.label} className="grid grid-cols-[90px_1fr] items-center gap-2">
          <div className="truncate text-[10px] text-white/55">{row.label}</div>
          <div className="grid gap-1" style={{ gridTemplateColumns: 'repeat(24, minmax(0, 1fr))' }}>
            {row.values.map((cell, index) => {
              const intensity = cell.value / max;
              const color = intensity > 0.72 ? ORANGE : intensity > 0.42 ? PURPLE : intensity > 0.12 ? BLUE : '#1E1B4B';
              return (
                <div
                  key={`${row.label}-${cell.hour}-${index}`}
                  title={`${row.label} ${cell.hour}: ${cell.value}`}
                  className="h-5 rounded-[2px] border border-white/5"
                  style={{ backgroundColor: color, opacity: 0.42 + intensity * 0.58 }}
                />
              );
            })}
          </div>
        </div>
      ))}
      <div className="mt-3 flex items-center justify-center gap-2 text-[10px] text-white/38">
        <span>Low</span>
        <div className="h-1.5 w-32 rounded-full bg-gradient-to-r from-[#1E1B4B] via-purple-500 to-orange-400" />
        <span>High</span>
      </div>
    </div>
  );
}

function SourceHealth({ rows }: { rows: SourceHealthRow[] }) {
  if (!rows.length) return <EmptyState label="No data sources have reported telemetry yet." />;
  return (
    <div className="space-y-2">
      <div className="grid grid-cols-[1fr_82px_88px_78px] gap-3 border-b border-white/8 pb-2 text-[9px] font-black uppercase tracking-[0.12em] text-white/35">
        <span>Source</span>
        <span>Status</span>
        <span className="text-right">Events (24h)</span>
        <span className="text-right">Last Seen</span>
      </div>
      {rows.slice(0, 7).map((row) => (
        <div key={row.source} className="grid grid-cols-[1fr_82px_88px_78px] items-center gap-3 border-b border-white/5 py-2 text-xs">
          <span className="truncate text-white/75"><ShieldCheck className="mr-2 inline h-3.5 w-3.5 text-white/35" />{row.source}</span>
          <span className={cn('font-bold', healthClass(row.status))}>{row.status}</span>
          <span className="text-right font-mono text-white/68">{compactFmt(row.events24h)}</span>
          <span className="text-right font-mono text-white/48">{timeAgo(row.lastSeenAt)}</span>
        </div>
      ))}
    </div>
  );
}

function RecentEvents({ rows }: { rows: RecentEventRow[] }) {
  if (!rows.length) return <EmptyState label="No correlation events have been emitted yet." />;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-[900px] w-full border-collapse text-left text-xs">
        <thead>
          <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.12em] text-white/35">
            <th className="pb-3 font-black">Time</th>
            <th className="pb-3 font-black">Event</th>
            <th className="pb-3 font-black">Source</th>
            <th className="pb-3 font-black">Related Endpoints</th>
            <th className="pb-3 font-black">Correlation Score</th>
            <th className="pb-3 font-black">Category</th>
            <th className="pb-3 font-black">Severity</th>
            <th className="pb-3 font-black">Status</th>
            <th className="pb-3 text-right font-black">Actions</th>
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 8).map((row) => (
            <tr key={row.id} className="border-b border-white/5 text-white/68">
              <td className="py-3 font-mono text-[11px] text-white/45">{shortTime(row.time)}</td>
              <td className="max-w-[220px] truncate py-3">{row.event}</td>
              <td className="max-w-[160px] truncate py-3">{row.source}</td>
              <td className="py-3 font-mono">{integerFmt(row.relatedEndpoints)}</td>
              <td className="py-3 font-mono">{integerFmt(row.correlationScore)}</td>
              <td className="py-3">{row.category}</td>
              <td className="py-3"><span className={cn('rounded px-2 py-1 text-[10px] font-black', severityClass(row.severity))}>{String(row.severity || 'low')}</span></td>
              <td className="py-3 text-emerald-300">{row.status}</td>
              <td className="py-3 text-right">
                <div className="inline-flex gap-1">
                  {[Search, Eye, MoreVertical].map((Icon, index) => (
                    <a key={index} href="/dashboard/runtime-crypto-intel" className="inline-grid h-7 w-7 place-items-center rounded-md border border-white/10 text-white/55 transition hover:border-gold/55 hover:text-gold">
                      <Icon className="h-3.5 w-3.5" />
                    </a>
                  ))}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CorrelationControls({ onRefresh }: { onRefresh: () => void }) {
  const rows = [
    { icon: SlidersHorizontal, label: 'Correlation Rules', detail: 'Manage correlation rules and conditions' },
    { icon: Database, label: 'Data Source Management', detail: 'Add, edit and monitor data sources' },
    { icon: AlertTriangle, label: 'Alert Aggregation', detail: 'Configure alert grouping and suppression' },
    { icon: Gauge, label: 'Time Window Settings', detail: 'Set correlation time windows' },
    { icon: Download, label: 'Export Correlation Data', detail: 'Export raw and correlated data' },
  ];

  return (
    <div className="space-y-2">
      {rows.map((row) => {
        const Icon = row.icon;
        return (
        <button
          type="button"
          key={row.label}
          onClick={row.label === 'Time Window Settings' ? onRefresh : undefined}
          className="grid w-full grid-cols-[28px_1fr_16px] items-center gap-3 rounded-md border border-white/8 bg-white/[0.02] p-3 text-left transition hover:border-gold/45 hover:bg-gold/10"
        >
          <Icon className="h-4 w-4 text-white/58" />
          <span>
            <span className="block text-xs font-bold text-white/80">{row.label}</span>
            <span className="block text-[10px] text-white/38">{row.detail}</span>
          </span>
          <ChevronRight className="h-4 w-4 text-white/35" />
        </button>
        );
      })}
    </div>
  );
}

export default function TelemetryCorrelationPage() {
  const { snapshot, state, error, sseConnected, refresh } = useTelemetryCorrelation();

  const timelineTotals = useMemo(
    () => snapshot.timeline.map((point) => point.threatDetections + point.anomalies + point.policyViolations + point.cryptoWeakness + point.infoEvents),
    [snapshot.timeline],
  );
  const threatSpark = useMemo(() => snapshot.timeline.map((point) => point.threatDetections), [snapshot.timeline]);
  const correlationSpark = useMemo(() => snapshot.timeline.map((point) => point.anomalies + point.policyViolations + point.cryptoWeakness), [snapshot.timeline]);

  const exportReport = useCallback(() => {
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `telemetry-correlation-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }, [snapshot]);

  return (
    <div className="min-h-screen bg-[#030711] px-4 py-5 text-white sm:px-5 lg:px-6">
      <div className="mx-auto max-w-[1540px] space-y-4">
        <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-semibold tracking-normal text-white">Telemetry Correlation</h1>
              <Info className="h-4 w-4 text-white/42" />
            </div>
            <p className="mt-1 text-sm text-white/58">Correlate telemetry data across multiple cryptographic endpoints in real time</p>
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
              className="inline-flex h-10 items-center gap-2 rounded-md border border-blue-500/55 bg-blue-500 px-4 text-xs font-black text-white transition hover:border-gold/80 hover:bg-gold hover:text-black"
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
          className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6"
        >
          <MetricCard label="Telemetry Events" value={compactFmt(snapshot.metrics.telemetryEvents)} delta={snapshot.metrics.telemetryEventsDelta} color={BLUE} spark={timelineTotals} />
          <MetricCard label="Correlated Alerts" value={integerFmt(snapshot.metrics.correlatedAlerts)} delta={snapshot.metrics.correlatedAlertsDelta} color={PURPLE} spark={correlationSpark} />
          <MetricCard label="Endpoints Monitored" value={integerFmt(snapshot.metrics.endpointsMonitored)} delta={snapshot.metrics.endpointsDelta} color={TEAL} spark={timelineTotals} />
          <MetricCard label="Correlation Matches" value={integerFmt(snapshot.metrics.correlationMatches)} delta={snapshot.metrics.correlationMatchesDelta} color={ORANGE} spark={correlationSpark} />
          <MetricCard label="High Risk Correlations" value={integerFmt(snapshot.metrics.highRiskCorrelations)} delta={snapshot.metrics.highRiskDelta} color={RED} spark={threatSpark} />
          <GlassPanel className="min-h-[104px] p-4">
            <div className="flex h-full items-center justify-between gap-3">
              <div>
                <div className="text-[10px] font-black uppercase tracking-[0.14em] text-white/72">Correlation Score</div>
                <div className="mt-3 flex items-baseline gap-1">
                  <span className="text-3xl font-semibold text-white">{integerFmt(snapshot.metrics.correlationScore)}</span>
                  <span className="text-xs font-semibold text-white/48">/100</span>
                </div>
                <div className="mt-1 text-[10px] font-bold text-blue-300">{snapshot.metrics.correlationScoreLevel}</div>
              </div>
              <ScoreRing value={snapshot.metrics.correlationScore} />
            </div>
          </GlassPanel>
        </motion.section>

        <section className="space-y-4">
          <GlassPanel className="min-h-[432px] p-5">
            <SectionTitle suffix={<div className="flex items-center gap-2"><RefreshCw className={cn('h-4 w-4 text-white/35', state === 'loading' && 'animate-spin')} /><Settings className="h-4 w-4 text-white/35" /></div>}>
              Telemetry Correlation Flow
            </SectionTitle>
            <CorrelationFlow snapshot={snapshot} />
          </GlassPanel>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.05fr_1fr]">
            <GlassPanel className="min-h-[255px] p-5">
              <SectionTitle
                suffix={(
                  <div className="flex items-center gap-2">
                    <HeaderButton icon={CalendarDays}>Last 7 Days</HeaderButton>
                    <button type="button" className="rounded border border-white/8 p-1.5 text-white/45"><Maximize2 className="h-3.5 w-3.5" /></button>
                  </div>
                )}
              >
                Correlation Timeline
              </SectionTitle>
              <div className="mb-2 flex flex-wrap gap-5 text-[10px] text-white/55">
                <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-sm" style={{ backgroundColor: RED }} />Threat Detections</span>
                <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-sm" style={{ backgroundColor: ORANGE }} />Anomalies</span>
                <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-sm" style={{ backgroundColor: PURPLE }} />Policy Violations</span>
                <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-sm" style={{ backgroundColor: GOLD }} />Crypto Weakness</span>
                <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-sm" style={{ backgroundColor: BLUE }} />Info Events</span>
              </div>
              <TimelineChart points={snapshot.timeline} />
            </GlassPanel>

            <GlassPanel className="p-5">
              <SectionTitle>Top Correlated Alerts</SectionTitle>
              <AlertsTable rows={snapshot.topAlerts} />
              <div className="mt-3 flex justify-end">
                <a href="/dashboard/runtime-crypto-intel" className="inline-flex items-center gap-1 text-xs font-bold text-blue-300 transition hover:text-gold">
                  View All Correlated Alerts <ChevronRight className="h-3.5 w-3.5" />
                </a>
              </div>
            </GlassPanel>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-[0.9fr_1.28fr_1.4fr]">
          <GlassPanel className="p-5">
            <SectionTitle>Correlation By Category</SectionTitle>
            <DonutChart rows={snapshot.categoryDistribution} />
            <div className="mt-4 flex justify-end">
              <a href="/dashboard/threat-intel" className="inline-flex items-center gap-1 text-xs font-bold text-blue-300 transition hover:text-gold">
                View All Categories <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </GlassPanel>

          <GlassPanel className="p-5">
            <SectionTitle
              suffix={<HeaderButton icon={CalendarDays}>Last 24 Hours</HeaderButton>}
            >
              Correlation Heatmap
            </SectionTitle>
            <Heatmap rows={snapshot.heatmap} />
          </GlassPanel>

          <GlassPanel className="p-5">
            <SectionTitle
              suffix={<a href="/dashboard/runtime-discovery" className="text-xs font-bold text-blue-300 transition hover:text-gold">View All Sources</a>}
            >
              Data Sources Health
            </SectionTitle>
            <SourceHealth rows={snapshot.dataSourcesHealth} />
          </GlassPanel>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-[2fr_0.68fr]">
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
              Recent Correlation Events
            </SectionTitle>
            <RecentEvents rows={snapshot.recentEvents} />
            <div className="mt-4 flex items-center justify-between text-xs text-white/38">
              <span>
                {integerFmt(snapshot.telemetry.runtimeEvents)} runtime events, {integerFmt(snapshot.telemetry.scannerEvidence)} evidence records, {integerFmt(snapshot.telemetry.assets)} assets synchronized
              </span>
              <a href="/dashboard/runtime-crypto-intel" className="inline-flex items-center gap-1 font-bold text-blue-300 transition hover:text-gold">
                View All Events <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </GlassPanel>

          <GlassPanel className="p-5">
            <SectionTitle>Correlation Controls</SectionTitle>
            <CorrelationControls onRefresh={() => void refresh()} />
          </GlassPanel>
        </section>

        <div className="flex flex-wrap items-center justify-between gap-3 text-[11px] text-white/35">
          <span className="inline-flex items-center gap-2">
            <span className={cn('h-2 w-2 rounded-full', sseConnected ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]' : 'bg-gold animate-pulse')} />
            {sseConnected ? 'Correlation SSE, metrics stream, scanner stream, and realtime table subscriptions connected' : 'Connecting live telemetry streams'}
          </span>
          <span>Latest synchronized event: {longDate(snapshot.latestEventAt || snapshot.latestScanAt || snapshot.telemetry.latestRuntimeEventAt)}</span>
        </div>
      </div>
    </div>
  );
}
