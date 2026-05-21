'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  BarChart3,
  ChevronRight,
  CircleGauge,
  Download,
  FileText,
  KeyRound,
  Layers,
  Lock,
  Network,
  Radar,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Workflow,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import { cn } from '@/lib/utils';

type Mode = 'protocol' | 'encryption';
type LoadState = 'loading' | 'success' | 'error';

type TimelinePoint = {
  label: string;
  primary: number;
  secure: number;
  weak: number;
  findings: number;
};

type DistributionRow = {
  label: string;
  count: number;
  percent: number;
};

type PostureRow = {
  label: string;
  events: number;
  assets: number;
  secure: number;
  weak: number;
  pqcReady: number;
  riskScore: number;
  latestSeen: string | null;
};

type InventoryRow = {
  id: string;
  name: string;
  category: string;
  assetName: string;
  assetType: string;
  protocol: string;
  version: string;
  algorithm: string;
  keySize: number;
  status: string;
  riskLevel: string;
  riskScore: number;
  pqcReady: boolean;
  weak: boolean;
  encrypted: boolean;
  source: string;
  lastSeen: string | null;
};

type AlertRow = {
  id: string;
  title: string;
  detail: string;
  severity: string;
  timestamp: string | null;
  source: string;
};

type RecommendationRow = {
  id: string;
  title: string;
  detail: string;
  impact: string;
  count: number;
  actionHref: string;
};

type ActivityRow = {
  id: string;
  title: string;
  detail: string;
  severity: string;
  timestamp: string | null;
  source: string;
};

type CryptoOperationsSnapshot = {
  generatedAt: string | null;
  latestActivityAt: string | null;
  metrics: {
    totalEvents: number;
    totalEventsDelta: number;
    assetsCovered: number;
    assetsDelta: number;
    secureEvents: number;
    weakEvents: number;
    pqcReady: number;
    pqcReadyPercent: number;
    highRiskFindings: number;
    healthScore: number;
    riskScore: number;
    activeProtocols: number;
    legacyProtocols: number;
    downgradeDetections: number;
    encryptedAssets: number;
    totalKeys: number;
    keyRotations: number;
    hndlExposure: number;
    activeSources: number;
  };
  timeline: TimelinePoint[];
  primaryDistribution: DistributionRow[];
  secondaryDistribution: DistributionRow[];
  statusDistribution: DistributionRow[];
  assetTypeDistribution: DistributionRow[];
  postureRows: PostureRow[];
  inventory: InventoryRow[];
  alerts: AlertRow[];
  recommendations: RecommendationRow[];
  activity: ActivityRow[];
  telemetry: {
    assets: number;
    runtimeEvents: number;
    scannerEvidence: number;
    scannerAlerts: number;
    scanResults: number;
    cryptoInventory: number;
    cryptoExposures: number;
    securityEvents: number;
    generatedKeys: number;
    certificates: number;
    qrngEvents: number;
    vaultAuditLogs: number;
    scannerAgents: number;
    connectors: number;
    agentHeartbeats: number;
    eventPipelineStatus: string;
    latestRuntimeEventAt: string | null;
  };
};

const EMPTY_SNAPSHOT: CryptoOperationsSnapshot = {
  generatedAt: null,
  latestActivityAt: null,
  metrics: {
    totalEvents: 0,
    totalEventsDelta: 0,
    assetsCovered: 0,
    assetsDelta: 0,
    secureEvents: 0,
    weakEvents: 0,
    pqcReady: 0,
    pqcReadyPercent: 0,
    highRiskFindings: 0,
    healthScore: 0,
    riskScore: 0,
    activeProtocols: 0,
    legacyProtocols: 0,
    downgradeDetections: 0,
    encryptedAssets: 0,
    totalKeys: 0,
    keyRotations: 0,
    hndlExposure: 0,
    activeSources: 0,
  },
  timeline: [],
  primaryDistribution: [],
  secondaryDistribution: [],
  statusDistribution: [],
  assetTypeDistribution: [],
  postureRows: [],
  inventory: [],
  alerts: [],
  recommendations: [],
  activity: [],
  telemetry: {
    assets: 0,
    runtimeEvents: 0,
    scannerEvidence: 0,
    scannerAlerts: 0,
    scanResults: 0,
    cryptoInventory: 0,
    cryptoExposures: 0,
    securityEvents: 0,
    generatedKeys: 0,
    certificates: 0,
    qrngEvents: 0,
    vaultAuditLogs: 0,
    scannerAgents: 0,
    connectors: 0,
    agentHeartbeats: 0,
    eventPipelineStatus: 'no_agents',
    latestRuntimeEventAt: null,
  },
};

const BLUE = '#2478FF';
const GREEN = '#22C55E';
const RED = '#EF4444';
const PURPLE = '#8B5CF6';
const CYAN = '#22D3EE';
const GOLD = '#FBBF24';
const ORANGE = '#F97316';
const TEAL = '#14B8A6';

const PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-blue-400/12 bg-[#07101D]/72 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(36,120,255,0.035),0_0_34px_rgba(0,0,0,0.34)] transition duration-500 hover:-translate-y-0.5 hover:border-gold/65 hover:bg-[#0A1728]/84 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.22),inset_0_-24px_60px_rgba(251,191,36,0.12),0_16px_46px_rgba(0,0,0,0.48),0_0_58px_rgba(251,191,36,0.28)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/55 before:to-transparent after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-52 after:w-52 after:rounded-full after:bg-gold/8 after:blur-3xl after:opacity-0 after:transition group-hover:after:opacity-100';

const MODE_COPY = {
  protocol: {
    segment: 'protocol-analytics',
    title: 'Protocol Analytics',
    subtitle: 'Cryptographic protocol posture, handshake health, downgrade signals, and quantum-safe adoption across tenant assets.',
    streamPrefix: 'protocol-analytics',
    Icon: Radar,
    primaryTitle: 'Protocol Distribution',
    secondaryTitle: 'Version And Cipher Posture',
    postureTitle: 'Protocol Risk Matrix',
    inventoryTitle: 'Protocol Observation Inventory',
    activityTitle: 'Recent Protocol Activity',
    actionHref: '/dashboard/tls-telemetry',
    actionLabel: 'TLS Telemetry',
    accent: BLUE,
  },
  encryption: {
    segment: 'encryption-monitoring',
    title: 'Encryption Monitoring',
    subtitle: 'Continuous encryption coverage, key lifecycle, PQC readiness, and runtime weakness monitoring across tenant assets.',
    streamPrefix: 'encryption-monitoring',
    Icon: Lock,
    primaryTitle: 'Encryption Contexts',
    secondaryTitle: 'Algorithm Distribution',
    postureTitle: 'Encryption Risk Matrix',
    inventoryTitle: 'Encryption Observation Inventory',
    activityTitle: 'Recent Encryption Activity',
    actionHref: '/dashboard/keys',
    actionLabel: 'Key Management',
    accent: GOLD,
  },
} as const;

function integerFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(Number(value) || 0)));
}

function compactFmt(value: number) {
  return new Intl.NumberFormat('en-US', {
    notation: Math.abs(value) >= 100000 ? 'compact' : 'standard',
    maximumFractionDigits: Math.abs(value) >= 100000 ? 2 : 0,
  }).format(Math.max(0, Number(value) || 0));
}

function percentFmt(value: number) {
  return `${Math.round(Number(value) || 0)}%`;
}

function signedPercent(value: number) {
  const safe = Math.round(Number(value) || 0);
  return `${safe > 0 ? '+' : ''}${safe}%`;
}

function shortTime(value: string | null) {
  if (!value) return 'just now';
  const ms = new Date(value).getTime();
  if (!Number.isFinite(ms)) return 'just now';
  const minutes = Math.max(0, Math.round((Date.now() - ms) / 60000));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function longDate(value: string | null) {
  if (!value) return 'Awaiting telemetry';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Awaiting telemetry';
  return date.toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function severityColor(value: string) {
  const lower = value.toLowerCase();
  if (lower.includes('critical')) return RED;
  if (lower.includes('high')) return ORANGE;
  if (lower.includes('medium') || lower.includes('warning')) return GOLD;
  if (lower.includes('low') || lower.includes('info')) return BLUE;
  return GREEN;
}

function trendClass(tone: 'good' | 'bad' | 'neutral') {
  if (tone === 'good') return 'text-emerald-300';
  if (tone === 'bad') return 'text-red-300';
  return 'text-white/45';
}

function linePath(values: number[], width: number, height: number, pad = 16) {
  if (!values.length) return '';
  const max = Math.max(1, ...values);
  return values.map((value, index) => {
    const x = pad + (values.length <= 1 ? 0 : (index / (values.length - 1)) * (width - pad * 2));
    const y = pad + (height - pad * 2) - ((Number(value) || 0) / max) * (height - pad * 2);
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(' ');
}

function useCryptoOperationsDashboard(mode: Mode) {
  const config = MODE_COPY[mode];
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<CryptoOperationsSnapshot>(EMPTY_SNAPSHOT);
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
      const response = await fetch(`/api/v1/dashboard/${config.segment}`, {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      const data = payload.data || {};
      setSnapshot({
        ...EMPTY_SNAPSHOT,
        ...data,
        metrics: { ...EMPTY_SNAPSHOT.metrics, ...(data.metrics || {}) },
        telemetry: { ...EMPTY_SNAPSHOT.telemetry, ...(data.telemetry || {}) },
      });
      setState('success');
      setError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : `Unable to load ${config.title.toLowerCase()} data`;
      console.error(`${config.title} load failed:`, err);
      setError(message);
      setState('error');
    }
  }, [config.segment, config.title, token]);

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
      'scanner_evidence',
      'scanner_alerts',
      'pqc_scan_results',
      'crypto_inventory',
      'crypto_exposures',
      'security_events',
      'generated_keys',
      'certificates',
      'scanner_agents',
      'connector_accounts',
      'agent_heartbeats',
      'qrng_events',
      'vault_audit_logs',
    ];

    const channels = tables.map((table) => supabase
      .channel(`${config.segment}-${table}`)
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` },
        queueRefresh,
      )
      .subscribe());

    return () => {
      for (const channel of channels) supabase.removeChannel(channel);
    };
  }, [config.segment, user, queueRefresh]);

  useEffect(() => {
    if (!token) {
      closeStreams();
      return;
    }

    let retryTimer: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      closeStreams();
      const dashboardStream = new EventSource(`/api/v1/dashboard/${config.segment}/stream?token=${encodeURIComponent(token)}`);
      const metricsStream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`);
      const scannerStream = new EventSource(`/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`);
      streamsRef.current = [dashboardStream, metricsStream, scannerStream];

      const markOpen = () => setSseConnected(true);
      const scheduleReconnect = () => {
        setSseConnected(false);
        closeStreams();
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(connect, 10000);
      };
      const refreshFromStream = () => queueRefresh();

      dashboardStream.onopen = markOpen;
      metricsStream.onopen = markOpen;
      scannerStream.onopen = markOpen;
      dashboardStream.onerror = scheduleReconnect;
      metricsStream.onerror = scheduleReconnect;
      scannerStream.onerror = scheduleReconnect;
      dashboardStream.addEventListener(`${config.streamPrefix}-connected`, refreshFromStream);
      dashboardStream.addEventListener(`${config.streamPrefix}-update`, refreshFromStream);
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
  }, [config.segment, config.streamPrefix, token, queueRefresh, closeStreams]);

  return { snapshot, state, error, sseConnected, refresh };
}

function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <section className={cn(PANEL_CLASSES, className)}>
      <div className="relative z-10 h-full">{children}</div>
    </section>
  );
}

function SectionTitle({ children, suffix }: { children: ReactNode; suffix?: ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-3">
      <h2 className="text-xs font-black uppercase tracking-[0.06em] text-white">{children}</h2>
      {suffix}
    </div>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex min-h-[118px] items-center justify-center rounded-md border border-dashed border-white/10 bg-white/[0.02] px-4 text-center text-xs text-white/38">
      {label}
    </div>
  );
}

function MiniSpark({ values, color }: { values: number[]; color: string }) {
  const safeValues = values.length ? values : [0, 0];
  return (
    <svg className="h-10 w-24" viewBox="0 0 92 38" aria-hidden="true">
      <path d={linePath(safeValues, 92, 38, 5)} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      {safeValues.map((value, index) => {
        const max = Math.max(1, ...safeValues);
        const x = 5 + (safeValues.length <= 1 ? 0 : (index / (safeValues.length - 1)) * 82);
        const y = 5 + 28 - ((Number(value) || 0) / max) * 28;
        return <circle key={`${index}-${value}`} cx={x} cy={y} r="2" fill={color} />;
      })}
    </svg>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  trend,
  trendTone,
  detail,
  color,
  spark,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  trend: string;
  trendTone: 'good' | 'bad' | 'neutral';
  detail: string;
  color: string;
  spark: number[];
}) {
  return (
    <Panel className="min-h-[126px] p-4">
      <div className="flex h-full flex-col justify-between gap-2">
        <div className="flex items-center gap-3">
          <span className="grid h-7 w-7 place-items-center rounded-md border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
            <Icon className="h-4 w-4" />
          </span>
          <span className="text-[10px] font-black uppercase tracking-[0.07em] text-white">{label}</span>
        </div>
        <div className="flex items-end justify-between gap-3">
          <div>
            <div className="text-2xl font-semibold text-white">{value}</div>
            <div className={cn('mt-1 text-xs font-bold', trendClass(trendTone))}>{trend}</div>
            <div className="mt-1 text-[10px] text-white/45">{detail}</div>
          </div>
          <MiniSpark values={spark} color={color} />
        </div>
      </div>
    </Panel>
  );
}

function TimelineChart({ points, mode }: { points: TimelinePoint[]; mode: Mode }) {
  const width = 760;
  const height = 230;
  const series = [
    { key: 'primary', label: mode === 'protocol' ? 'Protocol Events' : 'Encryption Events', color: BLUE },
    { key: 'secure', label: 'Secure', color: GREEN },
    { key: 'weak', label: 'Weak', color: RED },
    { key: 'findings', label: 'Findings', color: GOLD },
  ] as const;
  const hasData = points.some((point) => point.primary || point.secure || point.weak || point.findings);

  if (!points.length || !hasData) return <EmptyState label={`Awaiting ${mode === 'protocol' ? 'protocol' : 'encryption'} telemetry.`} />;

  const max = Math.max(1, ...points.flatMap((point) => series.map((item) => point[item.key])));
  const xFor = (index: number) => 34 + (points.length <= 1 ? 0 : (index / (points.length - 1)) * (width - 68));
  const yFor = (value: number) => 20 + 168 - (value / max) * 168;

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-5 text-[10px] text-white/65">
        {series.map((item) => (
          <span key={item.label} className="inline-flex items-center gap-2">
            <span className="h-2 w-3 rounded-sm" style={{ backgroundColor: item.color }} />
            {item.label}
          </span>
        ))}
      </div>
      <svg className="h-[230px] w-full" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${mode} timeline`}>
        {[0, 25, 50, 75, 100].map((tick) => {
          const y = 20 + (100 - tick) / 100 * 168;
          return (
            <g key={tick}>
              <line x1="34" x2="726" y1={y} y2={y} stroke="rgba(255,255,255,0.06)" />
              <text x="3" y={y + 4} fill="rgba(255,255,255,0.45)" fontSize="10">{tick === 0 ? '0' : `${tick}%`}</text>
            </g>
          );
        })}
        {series.map((item) => {
          const d = points.map((point, index) => {
            const x = xFor(index);
            const y = yFor(point[item.key]);
            return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
          }).join(' ');
          return (
            <g key={item.label}>
              <path d={d} fill="none" stroke={item.color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
              {points.map((point, index) => <circle key={`${item.label}-${point.label}`} cx={xFor(index)} cy={yFor(point[item.key])} r="3" fill={item.color} />)}
            </g>
          );
        })}
        {points.map((point, index) => (
          <text key={point.label} x={xFor(index)} y="220" textAnchor="middle" fill="rgba(255,255,255,0.5)" fontSize="10">{point.label}</text>
        ))}
      </svg>
    </div>
  );
}

function DonutChart({ rows, center }: { rows: DistributionRow[]; center: ReactNode }) {
  if (!rows.length) return <EmptyState label="No distribution data is available yet." />;
  const colors = [BLUE, GREEN, GOLD, PURPLE, CYAN, ORANGE, TEAL, RED];
  const total = Math.max(1, rows.reduce((sum, row) => sum + row.count, 0));
  let offset = 0;

  return (
    <div className="grid grid-cols-[160px_1fr] items-center gap-5">
      <div className="relative grid h-40 w-40 place-items-center">
        <svg className="h-40 w-40 -rotate-90" viewBox="0 0 120 120" aria-hidden="true">
          <circle cx="60" cy="60" r="42" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="17" />
          {rows.map((row, index) => {
            const circumference = 263.89;
            const length = (row.count / total) * circumference;
            const currentOffset = -offset;
            offset += length;
            return (
              <circle
                key={row.label}
                cx="60"
                cy="60"
                r="42"
                fill="none"
                stroke={colors[index % colors.length]}
                strokeWidth="17"
                strokeDasharray={`${length} ${circumference}`}
                strokeDashoffset={currentOffset}
              />
            );
          })}
        </svg>
        <div className="absolute text-center">{center}</div>
      </div>
      <div className="space-y-3">
        {rows.map((row, index) => (
          <div key={row.label} className="grid grid-cols-[12px_1fr_82px] items-center gap-2 text-xs">
            <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: colors[index % colors.length] }} />
            <span className="truncate text-white/76">{row.label}</span>
            <span className="text-right font-mono text-white/75">{percentFmt(row.percent)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DistributionBars({ rows, empty }: { rows: DistributionRow[]; empty: string }) {
  if (!rows.length) return <EmptyState label={empty} />;
  const colors = [BLUE, GREEN, GOLD, PURPLE, CYAN, ORANGE, TEAL, RED];
  return (
    <div className="space-y-3">
      {rows.map((row, index) => (
        <div key={row.label} className="grid grid-cols-[118px_1fr_84px] items-center gap-3 text-xs">
          <span className="truncate text-white/68">{row.label}</span>
          <span className="h-2.5 overflow-hidden rounded-full bg-white/5">
            <span className="block h-full rounded-full" style={{ width: `${Math.min(100, row.percent)}%`, backgroundColor: colors[index % colors.length] }} />
          </span>
          <span className="text-right font-mono text-white/76">{compactFmt(row.count)} ({percentFmt(row.percent)})</span>
        </div>
      ))}
    </div>
  );
}

function HealthGauge({ snapshot, mode }: { snapshot: CryptoOperationsSnapshot; mode: Mode }) {
  const score = snapshot.metrics.healthScore;
  const ringColor = score >= 75 ? GREEN : score >= 45 ? GOLD : RED;
  const ring = `conic-gradient(${ringColor} ${score}%, rgba(255,255,255,0.08) 0)`;

  return (
    <div className="grid h-full content-between gap-5">
      <div className="grid place-items-center">
        <div className="relative grid h-44 w-44 place-items-center rounded-full" style={{ background: ring }}>
          <div className="grid h-32 w-32 place-items-center rounded-full border border-white/10 bg-[#07101D] text-center shadow-[inset_0_0_28px_rgba(0,0,0,0.45)]">
            <div>
              <div className="text-4xl font-semibold text-white">{integerFmt(score)}</div>
              <div className="mt-1 text-[10px] uppercase tracking-[0.12em] text-white/52">Health</div>
            </div>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3 text-center text-xs">
        <div className="rounded-md border border-white/8 bg-white/[0.03] p-3">
          <div className="font-mono text-lg text-white">{integerFmt(snapshot.metrics.riskScore)}</div>
          <div className="mt-1 text-[10px] text-white/45">Risk</div>
        </div>
        <div className="rounded-md border border-white/8 bg-white/[0.03] p-3">
          <div className="font-mono text-lg text-white">{mode === 'protocol' ? integerFmt(snapshot.metrics.activeProtocols) : integerFmt(snapshot.metrics.encryptedAssets)}</div>
          <div className="mt-1 text-[10px] text-white/45">{mode === 'protocol' ? 'Protocols' : 'Assets'}</div>
        </div>
        <div className="rounded-md border border-white/8 bg-white/[0.03] p-3">
          <div className="font-mono text-lg text-white">{integerFmt(snapshot.metrics.highRiskFindings)}</div>
          <div className="mt-1 text-[10px] text-white/45">High Risk</div>
        </div>
      </div>
    </div>
  );
}

function PostureMatrix({ rows, mode }: { rows: PostureRow[]; mode: Mode }) {
  if (!rows.length) return <EmptyState label={`No ${mode === 'protocol' ? 'protocol' : 'encryption'} posture rows are available yet.`} />;
  return (
    <div className="space-y-2">
      <div className="grid grid-cols-[1fr_72px_72px_72px_72px] gap-3 border-b border-white/8 pb-2 text-[10px] text-white/42">
        <span>{mode === 'protocol' ? 'Protocol' : 'Context'}</span>
        <span className="text-right">Events</span>
        <span className="text-right">Assets</span>
        <span className="text-right">PQC</span>
        <span className="text-right">Risk</span>
      </div>
      {rows.map((row) => (
        <div key={row.label} className="grid grid-cols-[1fr_72px_72px_72px_72px] items-center gap-3 border-b border-white/5 py-2 text-xs">
          <span className="truncate text-white/78">{row.label}</span>
          <span className="text-right font-mono text-white/72">{compactFmt(row.events)}</span>
          <span className="text-right font-mono text-white/72">{compactFmt(row.assets)}</span>
          <span className="text-right font-mono text-white/72">{percentFmt(row.pqcReady)}</span>
          <span className="text-right font-mono" style={{ color: severityColor(row.riskScore >= 75 ? 'high' : row.riskScore >= 45 ? 'medium' : 'low') }}>{integerFmt(row.riskScore)}</span>
        </div>
      ))}
    </div>
  );
}

function InventoryTable({ rows, mode }: { rows: InventoryRow[]; mode: Mode }) {
  if (!rows.length) return <EmptyState label={`No ${mode === 'protocol' ? 'protocol' : 'encryption'} observations are available for this tenant yet.`} />;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-[980px] w-full text-left text-xs">
        <thead>
          <tr className="border-b border-white/8 text-[10px] text-white/42">
            <th className="pb-3 font-medium">Observation</th>
            <th className="pb-3 font-medium">Asset</th>
            <th className="pb-3 font-medium">{mode === 'protocol' ? 'Protocol' : 'Context'}</th>
            <th className="pb-3 font-medium">Algorithm</th>
            <th className="pb-3 text-center font-medium">PQC</th>
            <th className="pb-3 text-center font-medium">State</th>
            <th className="pb-3 text-right font-medium">Risk</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const color = severityColor(row.riskLevel);
            return (
              <tr key={row.id} className="border-b border-white/5 text-white/72">
                <td className="max-w-[250px] py-3">
                  <span className="block truncate font-semibold text-white/86">{row.name}</span>
                  <span className="block truncate text-[10px] text-white/42">{row.source} - {shortTime(row.lastSeen)}</span>
                </td>
                <td className="max-w-[170px] py-3">
                  <span className="block truncate">{row.assetName}</span>
                  <span className="block truncate text-[10px] text-white/42">{row.assetType}</span>
                </td>
                <td className="max-w-[150px] py-3">
                  <span className="block truncate">{mode === 'protocol' ? row.protocol : row.category}</span>
                  <span className="block truncate text-[10px] text-white/42">{row.version}</span>
                </td>
                <td className="max-w-[180px] truncate py-3 font-mono">
                  {row.algorithm || 'Unknown'}{row.keySize ? <span className="ml-1 text-white/38">{integerFmt(row.keySize)}</span> : null}
                </td>
                <td className="py-3 text-center">
                  <span className={cn('inline-flex rounded-md border px-2 py-1 text-[10px] font-black', row.pqcReady ? 'border-emerald-400/35 bg-emerald-400/10 text-emerald-300' : 'border-amber-400/35 bg-amber-400/10 text-amber-300')}>
                    {row.pqcReady ? 'Ready' : 'Pending'}
                  </span>
                </td>
                <td className="py-3 text-center">
                  <span className={cn('inline-flex rounded-md border px-2 py-1 text-[10px] font-black', row.weak ? 'border-red-400/35 bg-red-400/10 text-red-300' : 'border-emerald-400/35 bg-emerald-400/10 text-emerald-300')}>
                    {row.weak ? 'Review' : row.encrypted ? 'Secure' : 'Open'}
                  </span>
                </td>
                <td className="py-3 text-right">
                  <span className="rounded-md border px-2 py-1 text-[10px] font-black" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}10` }}>
                    {integerFmt(row.riskScore)}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function AlertList({ rows, mode }: { rows: AlertRow[]; mode: Mode }) {
  if (!rows.length) return <EmptyState label={`No active ${mode === 'protocol' ? 'protocol' : 'encryption'} alerts for this tenant.`} />;
  return (
    <div className="space-y-3">
      {rows.map((row) => {
        const color = severityColor(row.severity);
        const Icon = row.severity.toLowerCase().includes('critical') || row.severity.toLowerCase().includes('high') ? ShieldAlert : AlertTriangle;
        return (
          <div key={row.id} className="grid grid-cols-[34px_1fr_60px_auto] items-center gap-3 border-b border-white/5 pb-3 text-xs">
            <span className="grid h-8 w-8 place-items-center rounded-full border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
              <Icon className="h-4 w-4" style={{ color }} />
            </span>
            <span className="min-w-0">
              <span className="block truncate font-bold text-white/84">{row.title}</span>
              <span className="block truncate text-[10px] text-white/45">{row.detail}</span>
            </span>
            <span className="text-right text-[10px] text-white/48">{shortTime(row.timestamp)}</span>
            <span className="rounded-md border px-2 py-1 text-[10px] font-black" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}10` }}>{row.severity}</span>
          </div>
        );
      })}
    </div>
  );
}

function Recommendations({ rows }: { rows: RecommendationRow[] }) {
  if (!rows.length) return <EmptyState label="No remediation recommendations are active right now." />;
  return (
    <div className="space-y-3">
      {rows.map((row) => {
        const color = severityColor(row.impact);
        return (
          <a key={row.id} href={row.actionHref} className="grid grid-cols-[32px_1fr_auto] items-center gap-3 rounded-md border border-white/6 bg-white/[0.025] p-3 transition hover:border-gold/45 hover:bg-gold/8">
            <span className="grid h-8 w-8 place-items-center rounded-md border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
              <KeyRound className="h-4 w-4" style={{ color }} />
            </span>
            <span className="min-w-0">
              <span className="block truncate text-xs font-bold text-white/84">{row.title}</span>
              <span className="block truncate text-[10px] text-white/45">{row.detail}</span>
            </span>
            <span className="flex items-center gap-2">
              <span className="rounded-md border px-2 py-1 text-[10px] font-black" style={{ borderColor: `${color}45`, backgroundColor: `${color}10`, color }}>{row.impact}</span>
              <ChevronRight className="h-4 w-4 text-white/35" />
            </span>
          </a>
        );
      })}
    </div>
  );
}

function ActivityFeed({ rows, mode }: { rows: ActivityRow[]; mode: Mode }) {
  if (!rows.length) return <EmptyState label={`No recent ${mode === 'protocol' ? 'protocol' : 'encryption'} activity has been captured yet.`} />;
  return (
    <div className="space-y-3">
      {rows.map((row) => {
        const color = severityColor(row.severity);
        return (
          <div key={row.id} className="grid grid-cols-[34px_1fr_70px] gap-3 border-b border-white/5 pb-3 text-xs">
            <span className="grid h-8 w-8 place-items-center rounded-full border" style={{ borderColor: `${color}45`, backgroundColor: `${color}12` }}>
              <Activity className="h-4 w-4" style={{ color }} />
            </span>
            <span className="min-w-0">
              <span className="block truncate font-bold text-white/84">{row.title}</span>
              <span className="block truncate text-[10px] text-white/45">{row.detail}</span>
            </span>
            <span className="text-right text-[10px] text-white/48">{shortTime(row.timestamp)}</span>
          </div>
        );
      })}
    </div>
  );
}

function PipelineStatus({ snapshot, sseConnected }: { snapshot: CryptoOperationsSnapshot; sseConnected: boolean }) {
  const rows = [
    { label: 'Runtime Events', value: snapshot.telemetry.runtimeEvents, icon: Activity, color: GREEN },
    { label: 'Scanner Evidence', value: snapshot.telemetry.scannerEvidence, icon: Search, color: PURPLE },
    { label: 'Crypto Inventory', value: snapshot.telemetry.cryptoInventory, icon: FileText, color: BLUE },
    { label: 'Crypto Exposures', value: snapshot.telemetry.cryptoExposures, icon: ShieldAlert, color: RED },
    { label: 'Generated Keys', value: snapshot.telemetry.generatedKeys, icon: KeyRound, color: GOLD },
    { label: 'Certificates', value: snapshot.telemetry.certificates, icon: BadgeCheck, color: CYAN },
  ];

  return (
    <div className="grid gap-4">
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded-md border border-white/8 bg-white/[0.03] p-3">
          <div className="text-[10px] uppercase tracking-[0.1em] text-white/42">Live Sync</div>
          <div className={cn('mt-2 text-sm font-bold', sseConnected ? 'text-emerald-300' : 'text-amber-300')}>{sseConnected ? 'SSE Active' : 'SSE Connecting'}</div>
        </div>
        <div className="rounded-md border border-white/8 bg-white/[0.03] p-3">
          <div className="text-[10px] uppercase tracking-[0.1em] text-white/42">Pipeline</div>
          <div className="mt-2 truncate text-sm font-bold text-white/78">{snapshot.telemetry.eventPipelineStatus.replace(/_/g, ' ')}</div>
        </div>
      </div>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {rows.map((row) => {
          const Icon = row.icon;
          return (
            <div key={row.label} className="flex items-center justify-between gap-3 rounded-md border border-white/6 bg-white/[0.025] px-3 py-2">
              <span className="flex min-w-0 items-center gap-2">
                <Icon className="h-4 w-4 shrink-0" style={{ color: row.color }} />
                <span className="truncate text-xs text-white/62">{row.label}</span>
              </span>
              <span className="font-mono text-xs text-white/82">{compactFmt(row.value)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function buildCards(snapshot: CryptoOperationsSnapshot, mode: Mode, primarySpark: number[], weakSpark: number[]) {
  if (mode === 'protocol') {
    return [
      { icon: Network, label: 'Protocol Events', value: compactFmt(snapshot.metrics.totalEvents), trend: signedPercent(snapshot.metrics.totalEventsDelta), trendTone: snapshot.metrics.totalEventsDelta >= 0 ? 'good' : 'bad', detail: 'vs previous 7 days', color: BLUE, spark: primarySpark },
      { icon: Layers, label: 'Active Protocols', value: integerFmt(snapshot.metrics.activeProtocols), trend: `${integerFmt(snapshot.metrics.assetsCovered)} assets`, trendTone: 'neutral', detail: 'tenant protocol set', color: CYAN, spark: primarySpark },
      { icon: ShieldCheck, label: 'Secure Events', value: compactFmt(snapshot.metrics.secureEvents), trend: percentFmt(snapshot.metrics.pqcReadyPercent), trendTone: snapshot.metrics.pqcReadyPercent >= 80 ? 'good' : 'neutral', detail: 'PQC-ready coverage', color: GREEN, spark: primarySpark },
      { icon: AlertTriangle, label: 'Legacy Protocols', value: compactFmt(snapshot.metrics.legacyProtocols), trend: `${integerFmt(snapshot.metrics.downgradeDetections)} downgrades`, trendTone: snapshot.metrics.legacyProtocols ? 'bad' : 'good', detail: 'weak and outdated signals', color: GOLD, spark: weakSpark },
      { icon: ShieldAlert, label: 'High Risk Findings', value: compactFmt(snapshot.metrics.highRiskFindings), trend: `${compactFmt(snapshot.metrics.weakEvents)} weak events`, trendTone: snapshot.metrics.highRiskFindings ? 'bad' : 'good', detail: 'critical and high risk', color: RED, spark: weakSpark },
      { icon: CircleGauge, label: 'Protocol Health', value: integerFmt(snapshot.metrics.healthScore), trend: `${integerFmt(snapshot.metrics.riskScore)} risk`, trendTone: snapshot.metrics.healthScore >= 75 ? 'good' : snapshot.metrics.healthScore ? 'bad' : 'neutral', detail: 'calculated posture score', color: TEAL, spark: primarySpark },
    ] as const;
  }

  return [
    { icon: Lock, label: 'Encryption Events', value: compactFmt(snapshot.metrics.totalEvents), trend: signedPercent(snapshot.metrics.totalEventsDelta), trendTone: snapshot.metrics.totalEventsDelta >= 0 ? 'good' : 'bad', detail: 'vs previous 7 days', color: BLUE, spark: primarySpark },
    { icon: BadgeCheck, label: 'Encrypted Assets', value: compactFmt(snapshot.metrics.encryptedAssets), trend: `${integerFmt(snapshot.metrics.assetsCovered)} covered`, trendTone: 'good', detail: 'active encrypted surface', color: GREEN, spark: primarySpark },
    { icon: Sparkles, label: 'PQC Ready', value: percentFmt(snapshot.metrics.pqcReadyPercent), trend: `${compactFmt(snapshot.metrics.pqcReady)} events`, trendTone: snapshot.metrics.pqcReadyPercent >= 80 ? 'good' : 'neutral', detail: 'quantum-safe adoption', color: PURPLE, spark: primarySpark },
    { icon: ShieldAlert, label: 'Weak Encryption', value: compactFmt(snapshot.metrics.weakEvents), trend: `${compactFmt(snapshot.metrics.highRiskFindings)} high risk`, trendTone: snapshot.metrics.weakEvents ? 'bad' : 'good', detail: 'legacy or vulnerable usage', color: RED, spark: weakSpark },
    { icon: KeyRound, label: 'Key Rotations', value: compactFmt(snapshot.metrics.keyRotations), trend: `${compactFmt(snapshot.metrics.totalKeys)} keys`, trendTone: 'neutral', detail: 'lifecycle events', color: GOLD, spark: primarySpark },
    { icon: CircleGauge, label: 'Encryption Health', value: integerFmt(snapshot.metrics.healthScore), trend: `${integerFmt(snapshot.metrics.hndlExposure)} HNDL signals`, trendTone: snapshot.metrics.healthScore >= 75 ? 'good' : snapshot.metrics.healthScore ? 'bad' : 'neutral', detail: 'calculated posture score', color: TEAL, spark: primarySpark },
  ] as const;
}

export default function CryptoOperationsDashboard({ mode }: { mode: Mode }) {
  const config = MODE_COPY[mode];
  const { snapshot, state, error, sseConnected, refresh } = useCryptoOperationsDashboard(mode);
  const primarySpark = useMemo(() => snapshot.timeline.map((point) => point.primary), [snapshot.timeline]);
  const weakSpark = useMemo(() => snapshot.timeline.map((point) => point.weak + point.findings), [snapshot.timeline]);
  const cards = buildCards(snapshot, mode, primarySpark, weakSpark);
  const HeaderIcon = config.Icon;

  const exportReport = useCallback(() => {
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${config.segment}-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }, [config.segment, snapshot]);

  return (
    <div className="min-h-screen bg-[#030711] px-4 py-4 text-white sm:px-5 lg:px-6">
      <div className="mx-auto max-w-[1540px] space-y-4">
        <header className="flex flex-col gap-4 border-b border-gold/10 pb-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="flex items-center gap-4">
              <HeaderIcon className="h-10 w-10 text-gold drop-shadow-[0_0_16px_rgba(251,191,36,0.45)]" />
              <h1 className="font-mono text-3xl font-black uppercase tracking-[0.16em] text-gold drop-shadow-[0_0_16px_rgba(251,191,36,0.35)] md:text-4xl">
                {config.title}
              </h1>
            </div>
            <p className="mt-4 font-mono text-sm tracking-[0.08em] text-gold/70 md:text-base">
              {config.subtitle}
            </p>
            <div className="mt-3 flex flex-wrap gap-2 text-[10px] font-bold uppercase tracking-[0.08em] text-white/45">
              <span>Latest: {longDate(snapshot.latestActivityAt)}</span>
              <span className="text-white/20">/</span>
              <span>Backend synchronized</span>
              <span className="text-white/20">/</span>
              <span>{sseConnected ? 'Live stream active' : 'Live stream connecting'}</span>
            </div>
          </div>

          <div className="flex flex-wrap justify-start gap-2 xl:justify-end">
            <button type="button" onClick={() => void refresh()} className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 bg-black/24 px-3 text-xs font-bold text-white/75 transition hover:border-gold/55 hover:bg-gold hover:text-black">
              <RefreshCw className={cn('h-4 w-4', state === 'loading' && 'animate-spin')} />
              Refresh
            </button>
            <a href={config.actionHref} className="inline-flex h-9 items-center gap-2 rounded-md border border-blue-500/40 bg-blue-500 px-3 text-xs font-bold text-white transition hover:border-gold hover:bg-gold hover:text-black">
              <BarChart3 className="h-4 w-4" />
              {config.actionLabel}
            </a>
            <a href="/dashboard/scanner" className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 bg-black/24 px-3 text-xs font-bold text-white/75 transition hover:border-gold/55 hover:bg-gold hover:text-black">
              <Search className="h-4 w-4" />
              Run Scan
            </a>
            <button type="button" onClick={exportReport} className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 bg-black/24 px-3 text-xs font-bold text-white/75 transition hover:border-gold/55 hover:bg-gold hover:text-black">
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

        <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
          {cards.map((card) => (
            <div key={card.label}>
              <MetricCard {...card} />
            </div>
          ))}
        </motion.section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-5">
            <SectionTitle suffix={<span className="rounded-md border border-white/10 bg-black/20 px-3 py-1.5 text-[10px] font-bold text-white/55">7 Days</span>}>
              {mode === 'protocol' ? 'Protocol Events Over Time' : 'Encryption Events Over Time'}
            </SectionTitle>
            <TimelineChart points={snapshot.timeline} mode={mode} />
          </Panel>

          <Panel className="p-5 xl:col-span-4">
            <SectionTitle>{config.primaryTitle}</SectionTitle>
            <DonutChart
              rows={snapshot.primaryDistribution}
              center={(
                <>
                  <div className="text-3xl font-semibold text-white">{compactFmt(snapshot.metrics.totalEvents)}</div>
                  <div className="text-xs text-white/70">Events</div>
                </>
              )}
            />
          </Panel>

          <Panel className="p-5 xl:col-span-3">
            <SectionTitle>Posture Health</SectionTitle>
            <HealthGauge snapshot={snapshot} mode={mode} />
          </Panel>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-7">
            <SectionTitle suffix={<a href="/dashboard/runtime-crypto-intel" className="text-xs font-bold text-blue-300 transition hover:text-gold">Runtime intel</a>}>
              {config.inventoryTitle}
            </SectionTitle>
            <InventoryTable rows={snapshot.inventory} mode={mode} />
          </Panel>

          <Panel className="p-5 xl:col-span-5">
            <SectionTitle suffix={<a href="/dashboard/telemetry-correlation" className="text-xs font-bold text-blue-300 transition hover:text-gold">Correlation</a>}>
              {mode === 'protocol' ? 'Protocol Risk Alerts' : 'Encryption Risk Alerts'}
            </SectionTitle>
            <AlertList rows={snapshot.alerts} mode={mode} />
          </Panel>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-4">
            <SectionTitle>{config.postureTitle}</SectionTitle>
            <PostureMatrix rows={snapshot.postureRows} mode={mode} />
          </Panel>

          <Panel className="p-5 xl:col-span-4">
            <SectionTitle>{config.secondaryTitle}</SectionTitle>
            <DistributionBars rows={snapshot.secondaryDistribution} empty="No secondary distribution has been calculated yet." />
            <div className="mt-5 border-t border-white/8 pt-4">
              <SectionTitle>Asset Coverage</SectionTitle>
              <DistributionBars rows={snapshot.assetTypeDistribution} empty="No asset coverage telemetry is available yet." />
            </div>
          </Panel>

          <Panel className="p-5 xl:col-span-4">
            <SectionTitle suffix={<Zap className="h-4 w-4 text-gold" />}>
              Mitigation Recommendations
            </SectionTitle>
            <Recommendations rows={snapshot.recommendations} />
          </Panel>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-6">
            <SectionTitle>{config.activityTitle}</SectionTitle>
            <ActivityFeed rows={snapshot.activity} mode={mode} />
          </Panel>

          <Panel className="p-5 xl:col-span-6">
            <SectionTitle suffix={<Workflow className="h-4 w-4 text-gold" />}>
              Realtime Data Pipeline
            </SectionTitle>
            <PipelineStatus snapshot={snapshot} sseConnected={sseConnected} />
          </Panel>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-6">
            <SectionTitle>Status Distribution</SectionTitle>
            <DistributionBars rows={snapshot.statusDistribution} empty="No status distribution has been calculated yet." />
          </Panel>

          <Panel className="p-5 xl:col-span-6">
            <SectionTitle>Source Synchronization</SectionTitle>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              {[
                ['Assets', snapshot.telemetry.assets],
                ['Agents', snapshot.telemetry.scannerAgents],
                ['Connectors', snapshot.telemetry.connectors],
                ['Heartbeats', snapshot.telemetry.agentHeartbeats],
                ['QRNG', snapshot.telemetry.qrngEvents],
                ['Vault Logs', snapshot.telemetry.vaultAuditLogs],
                ['Security', snapshot.telemetry.securityEvents],
                ['Alerts', snapshot.telemetry.scannerAlerts],
              ].map(([label, value]) => (
                <div key={String(label)} className="rounded-md border border-white/8 bg-white/[0.03] p-3">
                  <div className="text-[10px] uppercase tracking-[0.08em] text-white/42">{label}</div>
                  <div className="mt-2 font-mono text-lg text-white">{compactFmt(Number(value))}</div>
                </div>
              ))}
            </div>
          </Panel>
        </section>
      </div>
    </div>
  );
}
