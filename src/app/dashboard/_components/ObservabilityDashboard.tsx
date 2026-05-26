'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  BarChart3,
  Boxes,
  ChevronRight,
  CircleGauge,
  Cloud,
  Cpu,
  Database,
  Download,
  FileWarning,
  Filter,
  Globe2,
  KeyRound,
  Layers,
  LineChart,
  Lock,
  Network,
  Radar,
  RefreshCw,
  ScanSearch,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Workflow,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import { cn } from '@/lib/utils';

type ObservabilityMode = 'runtime' | 'certificate' | 'keys' | 'api' | 'cloud';
type LoadState = 'loading' | 'success' | 'error';

type TimelinePoint = {
  label: string;
  runtime: number;
  secure: number;
  risk: number;
  certificates: number;
  keys: number;
  api: number;
  cloud: number;
};

type DistributionRow = {
  label: string;
  count: number;
  percent: number;
};

type MatrixRow = DistributionRow & {
  secure: number;
  weak: number;
  pqcReady: number;
  riskScore: number;
  latestSeen: string | null;
};

type AlertRow = {
  id: string;
  title: string;
  detail: string;
  severity: string;
  timestamp: string | null;
  source: string;
  pillar: string;
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

type InventoryRow = {
  id: string;
  pillar: string;
  title: string;
  subject: string;
  subjectType: string;
  provider: string;
  region: string;
  protocol: string;
  algorithm: string;
  keySize: number;
  status: string;
  severity: string;
  riskScore: number;
  encrypted: boolean;
  pqcReady: boolean;
  weak: boolean;
  expiring: boolean;
  source: string;
  timestamp: string | null;
  detail: string;
};

type ObservabilitySnapshot = {
  generatedAt: string | null;
  latestActivityAt: string | null;
  metrics: {
    totalSignals: number;
    signalDelta: number;
    runtimeEvents: number;
    activeProcesses: number;
    anomalies: number;
    encryptedCoverage: number;
    riskScore: number;
    assetsCovered: number;
    certificates: number;
    expiringCertificates: number;
    certificateCompliance: number;
    keys: number;
    activeKeys: number;
    rotatedKeys: number;
    weakKeys: number;
    keyPqcReadiness: number;
    apiEvents: number;
    apiSecureRate: number;
    apiPolicyViolations: number;
    cloudProviders: number;
    cloudRegions: number;
    cloudAssets: number;
    cloudTrustScore: number;
    highRiskFindings: number;
    activeSources: number;
    pqcReadiness: number;
    staleSignals: number;
  };
  timeline: TimelinePoint[];
  runtimeRows: MatrixRow[];
  certificateRows: MatrixRow[];
  keyRows: MatrixRow[];
  apiRows: MatrixRow[];
  cloudRows: MatrixRow[];
  regionRows: MatrixRow[];
  protocolDistribution: DistributionRow[];
  algorithmDistribution: DistributionRow[];
  providerDistribution: DistributionRow[];
  severityDistribution: DistributionRow[];
  statusDistribution: DistributionRow[];
  sourceDistribution: DistributionRow[];
  alerts: AlertRow[];
  recommendations: RecommendationRow[];
  activity: ActivityRow[];
  inventory: InventoryRow[];
  telemetry: {
    assets: number;
    runtimeEvents: number;
    scannerEvidence: number;
    scannerAlerts: number;
    scanSessions: number;
    scanResults: number;
    vulnerabilities: number;
    cryptoInventory: number;
    cryptoExposures: number;
    certificates: number;
    generatedKeys: number;
    scannerAgents: number;
    scannerPolicies: number;
    connectors: number;
    agentHeartbeats: number;
    vaultFiles: number;
    qrngEvents: number;
    vaultAuditLogs: number;
    auditLogs: number;
    complianceEvidence: number;
    migrationJobs: number;
    securityEvents: number;
    eventPipelineStatus: string;
    latestRuntimeEventAt: string | null;
  };
};

const EMPTY_SNAPSHOT: ObservabilitySnapshot = {
  generatedAt: null,
  latestActivityAt: null,
  metrics: {
    totalSignals: 0,
    signalDelta: 0,
    runtimeEvents: 0,
    activeProcesses: 0,
    anomalies: 0,
    encryptedCoverage: 0,
    riskScore: 0,
    assetsCovered: 0,
    certificates: 0,
    expiringCertificates: 0,
    certificateCompliance: 0,
    keys: 0,
    activeKeys: 0,
    rotatedKeys: 0,
    weakKeys: 0,
    keyPqcReadiness: 0,
    apiEvents: 0,
    apiSecureRate: 0,
    apiPolicyViolations: 0,
    cloudProviders: 0,
    cloudRegions: 0,
    cloudAssets: 0,
    cloudTrustScore: 0,
    highRiskFindings: 0,
    activeSources: 0,
    pqcReadiness: 0,
    staleSignals: 0,
  },
  timeline: [],
  runtimeRows: [],
  certificateRows: [],
  keyRows: [],
  apiRows: [],
  cloudRows: [],
  regionRows: [],
  protocolDistribution: [],
  algorithmDistribution: [],
  providerDistribution: [],
  severityDistribution: [],
  statusDistribution: [],
  sourceDistribution: [],
  alerts: [],
  recommendations: [],
  activity: [],
  inventory: [],
  telemetry: {
    assets: 0,
    runtimeEvents: 0,
    scannerEvidence: 0,
    scannerAlerts: 0,
    scanSessions: 0,
    scanResults: 0,
    vulnerabilities: 0,
    cryptoInventory: 0,
    cryptoExposures: 0,
    certificates: 0,
    generatedKeys: 0,
    scannerAgents: 0,
    scannerPolicies: 0,
    connectors: 0,
    agentHeartbeats: 0,
    vaultFiles: 0,
    qrngEvents: 0,
    vaultAuditLogs: 0,
    auditLogs: 0,
    complianceEvidence: 0,
    migrationJobs: 0,
    securityEvents: 0,
    eventPipelineStatus: 'no_sources',
    latestRuntimeEventAt: null,
  },
};

const BLUE = '#2478FF';
const GREEN = '#22C55E';
const RED = '#EF4444';
const GOLD = '#FBBF24';
const ORANGE = '#F97316';
const PURPLE = '#8B5CF6';
const CYAN = '#22D3EE';
const TEAL = '#14B8A6';

const PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-blue-400/12 bg-[#07101D]/76 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-20px_52px_rgba(36,120,255,0.035),0_14px_38px_rgba(0,0,0,0.34)] transition duration-500 hover:-translate-y-0.5 hover:border-gold/65 hover:bg-[#0A1728]/86 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.22),inset_0_-20px_52px_rgba(251,191,36,0.11),0_18px_48px_rgba(0,0,0,0.48),0_0_46px_rgba(251,191,36,0.22)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/55 before:to-transparent';

const MODE_COPY = {
  runtime: {
    segment: 'runtime-telemetry',
    streamPrefix: 'runtime-telemetry',
    title: 'Runtime Telemetry',
    subtitle: 'Process-level cryptographic operations, live event streams, runtime anomalies, and encryption execution visibility.',
    Icon: Activity,
    primaryHref: '/dashboard/runtime-crypto-intel',
    primaryLabel: 'Runtime Intel',
    accent: CYAN,
  },
  certificate: {
    segment: 'certificate-telemetry',
    streamPrefix: 'certificate-telemetry',
    title: 'Certificate Telemetry',
    subtitle: 'Certificate lifecycle monitoring, expiration intelligence, trust-chain validation, and TLS certificate compliance.',
    Icon: FileWarning,
    primaryHref: '/dashboard/pki-visibility',
    primaryLabel: 'PKI Visibility',
    accent: GOLD,
  },
  keys: {
    segment: 'key-analytics',
    streamPrefix: 'key-analytics',
    title: 'Key Analytics',
    subtitle: 'Key lifecycle, rotation telemetry, weak-key detection, PQC readiness, exposure monitoring, and entropy evidence.',
    Icon: KeyRound,
    primaryHref: '/dashboard/keys',
    primaryLabel: 'Key Management',
    accent: PURPLE,
  },
  api: {
    segment: 'api-encryption',
    streamPrefix: 'api-encryption',
    title: 'API Encryption',
    subtitle: 'API transport posture, TLS traffic analytics, cipher inspection, policy enforcement, and cryptographic compliance.',
    Icon: Network,
    primaryHref: '/dashboard/protocol-analytics',
    primaryLabel: 'Protocol Analytics',
    accent: BLUE,
  },
  cloud: {
    segment: 'multi-cloud-telemetry',
    streamPrefix: 'multi-cloud-telemetry',
    title: 'Multi-Cloud Telemetry',
    subtitle: 'Cross-cloud cryptographic visibility, distributed encryption monitoring, cloud-native events, and regional trust posture.',
    Icon: Cloud,
    primaryHref: '/dashboard/cloud',
    primaryLabel: 'Cloud Sources',
    accent: GREEN,
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
  if (!value) return 'awaiting telemetry';
  const ms = new Date(value).getTime();
  if (!Number.isFinite(ms)) return 'awaiting telemetry';
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

function linePath(values: number[], width: number, height: number, pad = 10) {
  if (!values.length) return '';
  const max = Math.max(1, ...values);
  return values.map((value, index) => {
    const x = pad + (values.length <= 1 ? 0 : (index / (values.length - 1)) * (width - pad * 2));
    const y = pad + (height - pad * 2) - ((Number(value) || 0) / max) * (height - pad * 2);
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(' ');
}

function useObservabilityDashboard(mode: ObservabilityMode) {
  const config = MODE_COPY[mode];
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<ObservabilitySnapshot>(EMPTY_SNAPSHOT);
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
      'pqc_scan_sessions',
      'pqc_scan_results',
      'vulnerabilities',
      'crypto_inventory',
      'crypto_exposures',
      'certificates',
      'generated_keys',
      'scanner_agents',
      'scanner_agent_policies',
      'connector_accounts',
      'agent_heartbeats',
      'vault_files',
      'qrng_events',
      'vault_audit_logs',
      'audit_logs',
      'compliance_evidence',
      'migration_jobs',
      'security_events',
      'user_security_events',
      'auth_events',
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
      const vaultStream = new EventSource(`/api/v1/vault/share/events?token=${encodeURIComponent(token)}`);
      streamsRef.current = [dashboardStream, metricsStream, scannerStream, vaultStream];

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
      vaultStream.onopen = markOpen;
      dashboardStream.onerror = scheduleReconnect;
      metricsStream.onerror = scheduleReconnect;
      scannerStream.onerror = scheduleReconnect;
      vaultStream.onerror = scheduleReconnect;
      dashboardStream.addEventListener(`${config.streamPrefix}-connected`, refreshFromStream);
      dashboardStream.addEventListener(`${config.streamPrefix}-update`, refreshFromStream);
      metricsStream.addEventListener('metrics-update', refreshFromStream);
      metricsStream.addEventListener('runtime-crypto-update', refreshFromStream);
      metricsStream.addEventListener('scan-complete', refreshFromStream);
      scannerStream.addEventListener('scanner-intelligence', refreshFromStream);
      scannerStream.addEventListener('scanner-error', refreshFromStream);
      vaultStream.addEventListener('failed_attempt', refreshFromStream);
      vaultStream.addEventListener('link_destroyed', refreshFromStream);
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

function MetricTile({
  icon: Icon,
  label,
  value,
  detail,
  trend,
  color,
  spark,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  detail: string;
  trend: string;
  color: string;
  spark: number[];
}) {
  return (
    <Panel className="min-h-[126px] p-4">
      <div className="flex h-full flex-col justify-between gap-2">
        <div className="flex items-center justify-between gap-3">
          <span className="grid h-8 w-8 place-items-center rounded-md border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
            <Icon className="h-4 w-4" />
          </span>
          <span className="text-right text-[10px] font-black uppercase tracking-[0.07em] text-white/72">{label}</span>
        </div>
        <div className="flex items-end justify-between gap-3">
          <div>
            <div className="text-2xl font-semibold text-white">{value}</div>
            <div className="mt-1 text-xs font-bold text-emerald-300">{trend}</div>
            <div className="mt-1 text-[10px] text-white/45">{detail}</div>
          </div>
          <MiniSpark values={spark} color={color} />
        </div>
      </div>
    </Panel>
  );
}

function ScoreDial({ value, label, color }: { value: number; label: string; color: string }) {
  const radius = 49;
  const circumference = 2 * Math.PI * radius;
  const dash = (Math.max(0, Math.min(100, value)) / 100) * circumference;
  return (
    <div className="grid place-items-center">
      <div className="relative grid h-40 w-40 place-items-center">
        <svg className="h-40 w-40 -rotate-90" viewBox="0 0 120 120" aria-hidden="true">
          <circle cx="60" cy="60" r={radius} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="12" />
          <circle cx="60" cy="60" r={radius} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round" strokeDasharray={`${dash} ${circumference - dash}`} />
        </svg>
        <div className="absolute text-center">
          <div className="text-3xl font-semibold text-white">{percentFmt(value)}</div>
          <div className="mt-1 text-[10px] font-black uppercase tracking-[0.06em] text-white/45">{label}</div>
        </div>
      </div>
    </div>
  );
}

function TimelineChart({ points, series }: { points: TimelinePoint[]; series: Array<{ key: keyof TimelinePoint; label: string; color: string }> }) {
  const width = 760;
  const height = 226;
  const hasData = points.some((point) => series.some((item) => Number(point[item.key]) > 0));
  if (!points.length || !hasData) return <EmptyState label="Awaiting live telemetry." />;

  const max = Math.max(1, ...points.flatMap((point) => series.map((item) => Number(point[item.key]) || 0)));
  const xFor = (index: number) => 34 + (points.length <= 1 ? 0 : (index / (points.length - 1)) * (width - 68));
  const yFor = (value: number) => 20 + 164 - (value / max) * 164;

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
      <svg className="h-[226px] w-full" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="telemetry timeline">
        {[0, 25, 50, 75, 100].map((tick) => {
          const y = 20 + (100 - tick) / 100 * 164;
          return (
            <g key={tick}>
              <line x1="34" x2="726" y1={y} y2={y} stroke="rgba(255,255,255,0.06)" />
              <text x="3" y={y + 4} fill="rgba(255,255,255,0.45)" fontSize="10">{tick === 0 ? '0' : `${tick}%`}</text>
            </g>
          );
        })}
        {series.map((item) => {
          const d = points.map((point, index) => `${index === 0 ? 'M' : 'L'} ${xFor(index).toFixed(1)} ${yFor(Number(point[item.key]) || 0).toFixed(1)}`).join(' ');
          return (
            <g key={item.label}>
              <path d={d} fill="none" stroke={item.color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
              {points.map((point, index) => <circle key={`${item.label}-${point.label}`} cx={xFor(index)} cy={yFor(Number(point[item.key]) || 0)} r="3" fill={item.color} />)}
            </g>
          );
        })}
        {points.map((point, index) => (
          <text key={point.label} x={xFor(index)} y="216" textAnchor="middle" fill="rgba(255,255,255,0.5)" fontSize="10">{point.label}</text>
        ))}
      </svg>
    </div>
  );
}

function Bars({ rows, empty }: { rows: DistributionRow[]; empty: string }) {
  if (!rows.length) return <EmptyState label={empty} />;
  const colors = [BLUE, GREEN, GOLD, PURPLE, CYAN, ORANGE, TEAL, RED];
  return (
    <div className="space-y-3">
      {rows.map((row, index) => (
        <div key={row.label} className="grid grid-cols-[130px_1fr_70px] items-center gap-3 text-xs">
          <div className="truncate text-white/72">{row.label}</div>
          <div className="h-2 overflow-hidden rounded-full bg-white/7">
            <div className="h-full rounded-full" style={{ width: `${Math.max(3, row.percent)}%`, backgroundColor: colors[index % colors.length] }} />
          </div>
          <div className="text-right font-mono text-white/72">{compactFmt(row.count)}</div>
        </div>
      ))}
    </div>
  );
}

function MatrixTable({ rows, title = 'Telemetry Matrix' }: { rows: MatrixRow[]; title?: string }) {
  if (!rows.length) return <EmptyState label={`No ${title.toLowerCase()} rows are available yet.`} />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] text-left text-xs">
        <thead>
          <tr className="border-b border-white/10 text-[10px] uppercase tracking-[0.06em] text-white/42">
            <th className="px-2 py-2">{title}</th>
            <th className="px-2 py-2">Events</th>
            <th className="px-2 py-2">Secure</th>
            <th className="px-2 py-2">Weak</th>
            <th className="px-2 py-2">PQC</th>
            <th className="px-2 py-2">Risk</th>
            <th className="px-2 py-2">Latest</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.label} className="border-b border-white/6 hover:bg-white/[0.025]">
              <td className="px-2 py-3 font-semibold text-white">{row.label}</td>
              <td className="px-2 py-3 font-mono text-white/72">{integerFmt(row.count)}</td>
              <td className="px-2 py-3 font-mono text-emerald-300">{integerFmt(row.secure)}</td>
              <td className="px-2 py-3 font-mono" style={{ color: row.weak ? ORANGE : GREEN }}>{integerFmt(row.weak)}</td>
              <td className="px-2 py-3 font-mono text-gold">{integerFmt(row.pqcReady)}</td>
              <td className="px-2 py-3 font-mono text-white/72">{row.riskScore}</td>
              <td className="px-2 py-3 text-white/48">{shortTime(row.latestSeen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AlertList({ rows }: { rows: AlertRow[] }) {
  if (!rows.length) return <EmptyState label="No active telemetry findings for the selected filters." />;
  return (
    <div className="space-y-0">
      {rows.slice(0, 10).map((row) => {
        const color = severityColor(row.severity);
        return (
          <div key={row.id} className="grid grid-cols-[32px_1fr_auto] gap-3 border-b border-white/6 py-3 last:border-b-0">
            <span className="grid h-8 w-8 place-items-center rounded-md border" style={{ borderColor: `${color}45`, backgroundColor: `${color}12` }}>
              <ShieldAlert className="h-4 w-4" style={{ color }} />
            </span>
            <div className="min-w-0">
              <div className="truncate text-sm font-semibold text-white">{row.title}</div>
              <div className="mt-1 truncate text-xs text-white/48">{row.detail}</div>
            </div>
            <div className="text-right">
              <div className="text-[10px] font-black uppercase" style={{ color }}>{row.severity}</div>
              <div className="mt-1 text-[10px] text-white/42">{shortTime(row.timestamp)}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Recommendations({ rows }: { rows: RecommendationRow[] }) {
  if (!rows.length) return <EmptyState label="No operational recommendations are active right now." />;
  return (
    <div className="space-y-0">
      {rows.slice(0, 6).map((row) => {
        const color = severityColor(row.impact);
        return (
          <a key={row.id} href={row.actionHref} className="grid grid-cols-[32px_1fr_auto] gap-3 border-b border-white/6 py-3 transition hover:bg-white/[0.025] last:border-b-0">
            <span className="grid h-8 w-8 place-items-center rounded-md border" style={{ borderColor: `${color}45`, backgroundColor: `${color}12` }}>
              <Zap className="h-4 w-4" style={{ color }} />
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-semibold text-white">{row.title}</span>
              <span className="mt-1 block text-xs text-white/48">{row.detail}</span>
            </span>
            <span className="flex items-center gap-2 text-right">
              <span className="font-mono text-xs text-white/65">{integerFmt(row.count)}</span>
              <ChevronRight className="h-4 w-4 text-gold" />
            </span>
          </a>
        );
      })}
    </div>
  );
}

function ActivityFeed({ rows }: { rows: ActivityRow[] }) {
  if (!rows.length) return <EmptyState label="No live activity for the selected filters." />;
  return (
    <div className="space-y-0">
      {rows.slice(0, 9).map((row) => (
        <div key={row.id} className="border-b border-white/6 py-3 last:border-b-0">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-white">{row.title}</div>
              <div className="mt-1 text-xs text-white/48">{row.detail}</div>
            </div>
            <div className="text-right text-[10px] text-white/42">{shortTime(row.timestamp)}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

function InventoryTable({ rows }: { rows: InventoryRow[] }) {
  if (!rows.length) return <EmptyState label="No telemetry inventory matches the selected filters." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[980px] text-left text-xs">
        <thead>
          <tr className="border-b border-white/10 text-[10px] uppercase tracking-[0.06em] text-white/42">
            <th className="px-2 py-2">Signal</th>
            <th className="px-2 py-2">Subject</th>
            <th className="px-2 py-2">Protocol</th>
            <th className="px-2 py-2">Algorithm</th>
            <th className="px-2 py-2">Cloud</th>
            <th className="px-2 py-2">Status</th>
            <th className="px-2 py-2">Risk</th>
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 16).map((row) => (
            <tr key={row.id} className="border-b border-white/6 hover:bg-white/[0.025]">
              <td className="px-2 py-3">
                <div className="font-semibold text-white">{row.title}</div>
                <div className="mt-1 text-[10px] uppercase text-white/42">{row.pillar} - {row.source}</div>
              </td>
              <td className="px-2 py-3">
                <div className="text-white/70">{row.subject}</div>
                <div className="mt-1 text-[10px] text-white/38">{row.subjectType}</div>
              </td>
              <td className="px-2 py-3 text-white/62">{row.protocol || 'Unknown'}</td>
              <td className="px-2 py-3">
                <div className="text-white/70">{row.algorithm || 'Unknown'}</div>
                <div className="mt-1 text-[10px] text-white/38">{row.keySize ? `${row.keySize} bits` : 'size unknown'}</div>
              </td>
              <td className="px-2 py-3">
                <div className="text-white/70">{row.provider}</div>
                <div className="mt-1 text-[10px] text-white/38">{row.region}</div>
              </td>
              <td className="px-2 py-3">
                <span className={cn('rounded border px-2 py-1 text-[10px] font-black uppercase', row.weak ? 'border-amber-400/30 bg-amber-400/10 text-amber-300' : 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300')}>
                  {row.status}
                </span>
              </td>
              <td className="px-2 py-3 font-mono text-white/72">{row.riskScore}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Header({
  mode,
  snapshot,
  state,
  sseConnected,
  refresh,
  search,
  setSearch,
  severity,
  setSeverity,
}: {
  mode: ObservabilityMode;
  snapshot: ObservabilitySnapshot;
  state: LoadState;
  sseConnected: boolean;
  refresh: () => void;
  search: string;
  setSearch: (value: string) => void;
  severity: string;
  setSeverity: (value: string) => void;
}) {
  const config = MODE_COPY[mode];
  const Icon = config.Icon;

  const exportReport = useCallback(() => {
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${config.segment}-observability-report.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }, [config.segment, snapshot]);

  return (
    <header className="grid gap-4 xl:grid-cols-[1fr_auto] xl:items-start">
      <div className="flex items-start gap-4">
        <span className="mt-1 grid h-11 w-11 place-items-center rounded-lg border border-gold/45 bg-gold/10 text-gold shadow-[0_0_24px_rgba(251,191,36,0.16)]">
          <Icon className="h-6 w-6" />
        </span>
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-black uppercase tracking-[0.11em] text-[#FFE8A8] md:text-3xl">{config.title}</h1>
            <span className={cn('inline-flex h-7 items-center gap-2 rounded-md border px-2.5 text-[10px] font-black uppercase tracking-[0.06em]', sseConnected ? 'border-emerald-400/35 bg-emerald-400/10 text-emerald-300' : 'border-amber-400/35 bg-amber-400/10 text-amber-300')}>
              <span className={cn('h-1.5 w-1.5 rounded-full', sseConnected ? 'bg-emerald-300' : 'bg-amber-300')} />
              {sseConnected ? 'Live' : state === 'loading' ? 'Syncing' : 'Ready'}
            </span>
          </div>
          <p className="mt-2 max-w-4xl text-sm leading-6 text-white/58">{config.subtitle}</p>
          <div className="mt-2 text-[10px] uppercase tracking-[0.06em] text-white/38">
            Latest event: <span className="font-mono text-white/62">{longDate(snapshot.latestActivityAt)}</span>
          </div>
        </div>
      </div>
      <div className="flex flex-wrap justify-start gap-2 xl:justify-end">
        <div className="relative h-9 min-w-[220px]">
          <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-white/38" />
          <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search telemetry" className="h-9 w-full rounded-md border border-white/10 bg-black/24 pl-9 pr-3 text-xs text-white outline-none transition placeholder:text-white/30 hover:border-gold/40 focus:border-gold/65" />
        </div>
        <label className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 bg-black/24 px-3 text-xs text-white/65">
          <Filter className="h-4 w-4" />
          <select value={severity} onChange={(event) => setSeverity(event.target.value)} className="bg-transparent text-xs font-bold outline-none">
            <option value="all" className="bg-[#07101D]">All severity</option>
            <option value="critical" className="bg-[#07101D]">Critical</option>
            <option value="high" className="bg-[#07101D]">High</option>
            <option value="medium" className="bg-[#07101D]">Medium</option>
            <option value="low" className="bg-[#07101D]">Low</option>
          </select>
        </label>
        <button type="button" onClick={() => void refresh()} className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 bg-black/24 px-3 text-xs font-bold text-white/75 transition hover:border-gold/55 hover:bg-gold hover:text-black">
          <RefreshCw className={cn('h-4 w-4', state === 'loading' && 'animate-spin')} />
          Refresh
        </button>
        <a href={config.primaryHref} className="inline-flex h-9 items-center gap-2 rounded-md border border-blue-500/40 bg-blue-500 px-3 text-xs font-bold text-white transition hover:border-gold hover:bg-gold hover:text-black">
          <Radar className="h-4 w-4" />
          {config.primaryLabel}
        </a>
        <a href="/dashboard/scanner" className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 bg-black/24 px-3 text-xs font-bold text-white/75 transition hover:border-gold/55 hover:bg-gold hover:text-black">
          <ScanSearch className="h-4 w-4" />
          Run Scan
        </a>
        <button type="button" onClick={exportReport} className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 bg-black/24 px-3 text-xs font-bold text-white/75 transition hover:border-gold/55 hover:bg-gold hover:text-black">
          <Download className="h-4 w-4" />
          Export
        </button>
      </div>
    </header>
  );
}

function RuntimeLayout({ snapshot, alerts, inventory }: { snapshot: ObservabilitySnapshot; alerts: AlertRow[]; inventory: InventoryRow[] }) {
  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
        <MetricTile icon={Activity} label="Runtime Events" value={compactFmt(snapshot.metrics.runtimeEvents)} trend={signedPercent(snapshot.metrics.signalDelta)} detail="live operations captured" color={CYAN} spark={snapshot.timeline.map((point) => point.runtime)} />
        <MetricTile icon={Cpu} label="Active Processes" value={integerFmt(snapshot.metrics.activeProcesses)} trend={`${integerFmt(snapshot.metrics.activeSources)} sources`} detail="process subjects observed" color={BLUE} spark={snapshot.timeline.map((point) => point.secure)} />
        <MetricTile icon={AlertTriangle} label="Anomalies" value={integerFmt(snapshot.metrics.anomalies)} trend={`${integerFmt(snapshot.metrics.highRiskFindings)} high risk`} detail="weak or unusual runtime signals" color={ORANGE} spark={snapshot.timeline.map((point) => point.risk)} />
        <MetricTile icon={Lock} label="Encrypted Coverage" value={percentFmt(snapshot.metrics.encryptedCoverage)} trend={percentFmt(snapshot.metrics.pqcReadiness)} detail="PQC-ready telemetry share" color={GREEN} spark={snapshot.timeline.map((point) => point.secure)} />
        <MetricTile icon={CircleGauge} label="Runtime Risk" value={integerFmt(snapshot.metrics.riskScore)} trend={`${integerFmt(snapshot.metrics.staleSignals)} stale`} detail="aggregated risk posture" color={RED} spark={snapshot.timeline.map((point) => point.risk)} />
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-8"><SectionTitle>Process Runtime Telemetry</SectionTitle><TimelineChart points={snapshot.timeline} series={[{ key: 'runtime', label: 'Runtime', color: CYAN }, { key: 'secure', label: 'Encrypted', color: GREEN }, { key: 'risk', label: 'Anomaly', color: ORANGE }]} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Runtime Health Dial</SectionTitle><ScoreDial value={Math.max(0, 100 - snapshot.metrics.riskScore)} label="Runtime Health" color={CYAN} /><Bars rows={snapshot.sourceDistribution.slice(0, 5)} empty="No runtime source data yet." /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Process And Operation Matrix</SectionTitle><MatrixTable rows={snapshot.runtimeRows} title="Process" /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Live Runtime Findings</SectionTitle><AlertList rows={alerts.filter((row) => /runtime|process|agent|crypto/i.test(`${row.pillar} ${row.source} ${row.detail}`))} /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Runtime Protocols</SectionTitle><Bars rows={snapshot.protocolDistribution.slice(0, 7)} empty="No protocol telemetry yet." /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Runtime Actions</SectionTitle><Recommendations rows={snapshot.recommendations} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Runtime Event Log</SectionTitle><ActivityFeed rows={snapshot.activity.filter((row) => /runtime|agent|crypto/i.test(`${row.detail} ${row.source}`))} /></Panel>
      </section>
      <Panel className="p-5"><SectionTitle>Runtime Telemetry Inventory</SectionTitle><InventoryTable rows={inventory.filter((row) => /runtime|process|agent|crypto|heartbeat/i.test(`${row.pillar} ${row.source} ${row.detail}`))} /></Panel>
    </>
  );
}

function CertificateLayout({ snapshot, alerts, inventory }: { snapshot: ObservabilitySnapshot; alerts: AlertRow[]; inventory: InventoryRow[] }) {
  const certInventory = inventory.filter((row) => /cert|certificate|tls|x509/i.test(`${row.pillar} ${row.title} ${row.detail}`));
  return (
    <>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-4">
          <SectionTitle>Certificate Compliance</SectionTitle>
          <ScoreDial value={snapshot.metrics.certificateCompliance} label="Trust Health" color={GOLD} />
          <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
            <div className="border-t border-white/8 pt-3"><div className="text-white/42">Certificates</div><div className="mt-1 font-mono text-lg text-white">{compactFmt(snapshot.metrics.certificates)}</div></div>
            <div className="border-t border-white/8 pt-3"><div className="text-white/42">Expiring</div><div className="mt-1 font-mono text-lg text-white">{integerFmt(snapshot.metrics.expiringCertificates)}</div></div>
            <div className="border-t border-white/8 pt-3"><div className="text-white/42">Encrypted</div><div className="mt-1 font-mono text-lg text-white">{percentFmt(snapshot.metrics.encryptedCoverage)}</div></div>
            <div className="border-t border-white/8 pt-3"><div className="text-white/42">PQC Ready</div><div className="mt-1 font-mono text-lg text-white">{percentFmt(snapshot.metrics.pqcReadiness)}</div></div>
          </div>
        </Panel>
        <Panel className="p-5 xl:col-span-8"><SectionTitle>Certificate Expiration And Trust Timeline</SectionTitle><TimelineChart points={snapshot.timeline} series={[{ key: 'certificates', label: 'Certificates', color: GOLD }, { key: 'secure', label: 'Valid Trust', color: GREEN }, { key: 'risk', label: 'Lifecycle Risk', color: ORANGE }]} /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile icon={FileWarning} label="Certificate Signals" value={compactFmt(snapshot.metrics.certificates)} trend={signedPercent(snapshot.metrics.signalDelta)} detail="certificate and TLS evidence" color={GOLD} spark={snapshot.timeline.map((point) => point.certificates)} />
        <MetricTile icon={AlertTriangle} label="Expiring" value={integerFmt(snapshot.metrics.expiringCertificates)} trend={`${integerFmt(snapshot.metrics.highRiskFindings)} high risk`} detail="expiry or revocation pressure" color={ORANGE} spark={snapshot.timeline.map((point) => point.risk)} />
        <MetricTile icon={ShieldCheck} label="Trust Chain" value={percentFmt(snapshot.metrics.certificateCompliance)} trend={percentFmt(snapshot.metrics.encryptedCoverage)} detail="valid encrypted coverage" color={GREEN} spark={snapshot.timeline.map((point) => point.secure)} />
        <MetricTile icon={Network} label="TLS Sources" value={integerFmt(snapshot.metrics.activeSources)} trend={snapshot.telemetry.eventPipelineStatus.replace(/_/g, ' ')} detail="live collectors and connectors" color={BLUE} spark={snapshot.timeline.map((point) => point.runtime)} />
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Certificate Lifecycle Matrix</SectionTitle><MatrixTable rows={snapshot.certificateRows} title="Certificate" /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Certificate Findings</SectionTitle><AlertList rows={alerts.filter((row) => /cert|certificate|tls|x509/i.test(`${row.pillar} ${row.detail}`))} /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Issuing Algorithms</SectionTitle><Bars rows={snapshot.algorithmDistribution.slice(0, 7)} empty="No certificate algorithm data yet." /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Lifecycle Actions</SectionTitle><Recommendations rows={snapshot.recommendations.filter((row) => /cert|risk|stale/i.test(`${row.title} ${row.detail}`))} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Certificate Audit Trail</SectionTitle><ActivityFeed rows={snapshot.activity.filter((row) => /cert|certificate|tls/i.test(`${row.detail} ${row.title}`))} /></Panel>
      </section>
      <Panel className="p-5"><SectionTitle>Certificate Telemetry Inventory</SectionTitle><InventoryTable rows={certInventory} /></Panel>
    </>
  );
}

function KeyLayout({ snapshot, alerts, inventory }: { snapshot: ObservabilitySnapshot; alerts: AlertRow[]; inventory: InventoryRow[] }) {
  const keyInventory = inventory.filter((row) => /key|kms|hsm|entropy|vault|rotation|sign|encrypt|decrypt|qrng/i.test(`${row.pillar} ${row.title} ${row.detail}`));
  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
        <Panel className="p-5 xl:col-span-2"><SectionTitle>PQC Key Readiness</SectionTitle><ScoreDial value={snapshot.metrics.keyPqcReadiness} label="Key PQC" color={PURPLE} /></Panel>
        <MetricTile icon={KeyRound} label="Key Signals" value={compactFmt(snapshot.metrics.keys)} trend={signedPercent(snapshot.metrics.signalDelta)} detail="key lifecycle records" color={PURPLE} spark={snapshot.timeline.map((point) => point.keys)} />
        <MetricTile icon={BadgeCheck} label="Active Keys" value={compactFmt(snapshot.metrics.activeKeys)} trend={percentFmt(snapshot.metrics.encryptedCoverage)} detail="protected active material" color={GREEN} spark={snapshot.timeline.map((point) => point.secure)} />
        <MetricTile icon={RefreshCw} label="Rotations" value={compactFmt(snapshot.metrics.rotatedKeys)} trend={`${integerFmt(snapshot.metrics.staleSignals)} stale`} detail="rotation telemetry" color={CYAN} spark={snapshot.timeline.map((point) => point.keys)} />
        <MetricTile icon={ShieldAlert} label="Weak Keys" value={integerFmt(snapshot.metrics.weakKeys)} trend={`${integerFmt(snapshot.metrics.highRiskFindings)} high risk`} detail="weak or exposed key posture" color={ORANGE} spark={snapshot.timeline.map((point) => point.risk)} />
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Key Algorithm Portfolio</SectionTitle><MatrixTable rows={snapshot.keyRows} title="Algorithm" /></Panel>
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Key Lifecycle Timeline</SectionTitle><TimelineChart points={snapshot.timeline} series={[{ key: 'keys', label: 'Keys', color: PURPLE }, { key: 'secure', label: 'Protected', color: GREEN }, { key: 'risk', label: 'Weak', color: ORANGE }]} /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Entropy And Source Mix</SectionTitle><Bars rows={snapshot.sourceDistribution.filter((row) => /key|qrng|vault|inventory|generated/i.test(row.label)).slice(0, 7)} empty="No key source telemetry yet." /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Key Findings</SectionTitle><AlertList rows={alerts.filter((row) => /key|kms|hsm|entropy|vault|rotation|qrng/i.test(`${row.pillar} ${row.detail}`))} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Key Actions</SectionTitle><Recommendations rows={snapshot.recommendations.filter((row) => /key|risk|stale/i.test(`${row.title} ${row.detail}`))} /></Panel>
      </section>
      <Panel className="p-5"><SectionTitle>Key Analytics Inventory</SectionTitle><InventoryTable rows={keyInventory} /></Panel>
    </>
  );
}

function ApiLayout({ snapshot, alerts, inventory }: { snapshot: ObservabilitySnapshot; alerts: AlertRow[]; inventory: InventoryRow[] }) {
  const apiInventory = inventory.filter((row) => /api|gateway|http|tls|grpc|graphql|webhook|transport|mtls/i.test(`${row.pillar} ${row.title} ${row.protocol} ${row.detail}`));
  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile icon={Network} label="API Crypto Events" value={compactFmt(snapshot.metrics.apiEvents)} trend={signedPercent(snapshot.metrics.signalDelta)} detail="API and transport signals" color={BLUE} spark={snapshot.timeline.map((point) => point.api)} />
        <MetricTile icon={Lock} label="Secure Rate" value={percentFmt(snapshot.metrics.apiSecureRate)} trend={percentFmt(snapshot.metrics.encryptedCoverage)} detail="encrypted API paths" color={GREEN} spark={snapshot.timeline.map((point) => point.secure)} />
        <MetricTile icon={ShieldAlert} label="Policy Violations" value={integerFmt(snapshot.metrics.apiPolicyViolations)} trend={`${integerFmt(snapshot.metrics.highRiskFindings)} high risk`} detail="weak API crypto posture" color={ORANGE} spark={snapshot.timeline.map((point) => point.risk)} />
        <MetricTile icon={Globe2} label="Assets Covered" value={integerFmt(snapshot.metrics.assetsCovered)} trend={`${integerFmt(snapshot.metrics.activeSources)} sources`} detail="API-visible subjects" color={CYAN} spark={snapshot.timeline.map((point) => point.runtime)} />
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Transport Enforcement</SectionTitle><ScoreDial value={snapshot.metrics.apiSecureRate} label="API Secure" color={BLUE} /><Bars rows={snapshot.protocolDistribution.slice(0, 6)} empty="No API protocol data yet." /></Panel>
        <Panel className="p-5 xl:col-span-8"><SectionTitle>API Transport Timeline</SectionTitle><TimelineChart points={snapshot.timeline} series={[{ key: 'api', label: 'API', color: BLUE }, { key: 'secure', label: 'Secure', color: GREEN }, { key: 'risk', label: 'Violations', color: ORANGE }]} /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7"><SectionTitle>API Protocol And Cipher Matrix</SectionTitle><MatrixTable rows={snapshot.apiRows} title="Protocol" /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle>API Encryption Findings</SectionTitle><AlertList rows={alerts.filter((row) => /api|gateway|http|tls|grpc|graphql|webhook|transport|mtls/i.test(`${row.pillar} ${row.detail}`))} /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Cipher And Algorithm Mix</SectionTitle><Bars rows={snapshot.algorithmDistribution.slice(0, 7)} empty="No API cipher data yet." /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>API Controls</SectionTitle><Recommendations rows={snapshot.recommendations.filter((row) => /api|transport|risk|stale/i.test(`${row.title} ${row.detail}`))} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>API Audit Events</SectionTitle><ActivityFeed rows={snapshot.activity.filter((row) => /api|tls|http|gateway|transport/i.test(`${row.detail} ${row.title}`))} /></Panel>
      </section>
      <Panel className="p-5"><SectionTitle>API Encryption Inventory</SectionTitle><InventoryTable rows={apiInventory} /></Panel>
    </>
  );
}

function CloudLayout({ snapshot, alerts, inventory }: { snapshot: ObservabilitySnapshot; alerts: AlertRow[]; inventory: InventoryRow[] }) {
  const cloudInventory = inventory.filter((row) => row.provider !== 'Private / Hybrid' || /cloud|aws|azure|gcp|region|connector/i.test(`${row.pillar} ${row.detail} ${row.provider}`));
  return (
    <>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-3">
          <SectionTitle>Multi-Cloud Trust</SectionTitle>
          <ScoreDial value={snapshot.metrics.cloudTrustScore} label="Cloud Trust" color={GREEN} />
        </Panel>
        <Panel className="p-5 xl:col-span-9">
          <SectionTitle>Cloud Provider Mesh</SectionTitle>
          <div className="grid gap-3 md:grid-cols-3">
            {(snapshot.cloudRows.length ? snapshot.cloudRows : [{ label: 'No cloud telemetry', count: 0, percent: 0, secure: 0, weak: 0, pqcReady: 0, riskScore: 0, latestSeen: null }]).map((row) => (
              <div key={row.label} className="rounded-md border border-white/8 bg-white/[0.025] p-4">
                <div className="flex items-center justify-between">
                  <span className="inline-flex items-center gap-2 text-sm font-semibold text-white"><Cloud className="h-4 w-4 text-gold" />{row.label}</span>
                  <span className="font-mono text-xs text-white/55">{shortTime(row.latestSeen)}</span>
                </div>
                <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs">
                  <div><div className="font-mono text-lg text-white">{compactFmt(row.count)}</div><div className="text-white/38">signals</div></div>
                  <div><div className="font-mono text-lg text-emerald-300">{compactFmt(row.secure)}</div><div className="text-white/38">secure</div></div>
                  <div><div className="font-mono text-lg text-amber-300">{compactFmt(row.weak)}</div><div className="text-white/38">risk</div></div>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile icon={Cloud} label="Cloud Assets" value={compactFmt(snapshot.metrics.cloudAssets)} trend={`${integerFmt(snapshot.metrics.cloudProviders)} providers`} detail="cloud crypto signals" color={GREEN} spark={snapshot.timeline.map((point) => point.cloud)} />
        <MetricTile icon={Globe2} label="Regions" value={integerFmt(snapshot.metrics.cloudRegions)} trend={snapshot.telemetry.eventPipelineStatus.replace(/_/g, ' ')} detail="regions observed" color={CYAN} spark={snapshot.timeline.map((point) => point.cloud)} />
        <MetricTile icon={Lock} label="Cloud Trust" value={percentFmt(snapshot.metrics.cloudTrustScore)} trend={percentFmt(snapshot.metrics.encryptedCoverage)} detail="encrypted cloud posture" color={BLUE} spark={snapshot.timeline.map((point) => point.secure)} />
        <MetricTile icon={ShieldAlert} label="Cloud Findings" value={integerFmt(alerts.filter((row) => /cloud|aws|azure|gcp|region|connector/i.test(`${row.pillar} ${row.detail}`)).length)} trend={`${integerFmt(snapshot.metrics.highRiskFindings)} high risk`} detail="distributed crypto risk" color={ORANGE} spark={snapshot.timeline.map((point) => point.risk)} />
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Distributed Cloud Timeline</SectionTitle><TimelineChart points={snapshot.timeline} series={[{ key: 'cloud', label: 'Cloud', color: GREEN }, { key: 'secure', label: 'Secure', color: BLUE }, { key: 'risk', label: 'Risk', color: ORANGE }]} /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Regional Trust Matrix</SectionTitle><MatrixTable rows={snapshot.regionRows} title="Region" /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Provider Distribution</SectionTitle><Bars rows={snapshot.providerDistribution.slice(0, 7)} empty="No provider telemetry yet." /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Cloud Findings</SectionTitle><AlertList rows={alerts.filter((row) => /cloud|aws|azure|gcp|region|connector/i.test(`${row.pillar} ${row.detail} ${row.source}`))} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Cloud Actions</SectionTitle><Recommendations rows={snapshot.recommendations} /></Panel>
      </section>
      <Panel className="p-5"><SectionTitle>Multi-Cloud Telemetry Inventory</SectionTitle><InventoryTable rows={cloudInventory} /></Panel>
    </>
  );
}

function Body({ mode, snapshot, alerts, inventory }: { mode: ObservabilityMode; snapshot: ObservabilitySnapshot; alerts: AlertRow[]; inventory: InventoryRow[] }) {
  if (mode === 'runtime') return <RuntimeLayout snapshot={snapshot} alerts={alerts} inventory={inventory} />;
  if (mode === 'certificate') return <CertificateLayout snapshot={snapshot} alerts={alerts} inventory={inventory} />;
  if (mode === 'keys') return <KeyLayout snapshot={snapshot} alerts={alerts} inventory={inventory} />;
  if (mode === 'api') return <ApiLayout snapshot={snapshot} alerts={alerts} inventory={inventory} />;
  return <CloudLayout snapshot={snapshot} alerts={alerts} inventory={inventory} />;
}

export default function ObservabilityDashboard({ mode }: { mode: ObservabilityMode }) {
  const { snapshot, state, error, sseConnected, refresh } = useObservabilityDashboard(mode);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('all');
  const config = MODE_COPY[mode];

  const filteredInventory = useMemo(() => {
    const query = search.trim().toLowerCase();
    return snapshot.inventory.filter((row) => {
      const matchesSeverity = severity === 'all' || row.severity.toLowerCase() === severity;
      const text = `${row.title} ${row.subject} ${row.subjectType} ${row.pillar} ${row.provider} ${row.region} ${row.protocol} ${row.algorithm} ${row.status} ${row.detail}`.toLowerCase();
      return matchesSeverity && (!query || text.includes(query));
    });
  }, [search, severity, snapshot.inventory]);

  const filteredAlerts = useMemo(() => {
    const query = search.trim().toLowerCase();
    return snapshot.alerts.filter((row) => {
      const matchesSeverity = severity === 'all' || row.severity.toLowerCase() === severity;
      const text = `${row.title} ${row.detail} ${row.pillar} ${row.source}`.toLowerCase();
      return matchesSeverity && (!query || text.includes(query));
    });
  }, [search, severity, snapshot.alerts]);

  const telemetrySummary = useMemo(() => [
    ['Runtime', snapshot.telemetry.runtimeEvents],
    ['Scanner', snapshot.telemetry.scanSessions + snapshot.telemetry.scanResults + snapshot.telemetry.scannerEvidence + snapshot.telemetry.scannerAlerts + snapshot.telemetry.vulnerabilities],
    ['Crypto', snapshot.telemetry.cryptoInventory + snapshot.telemetry.cryptoExposures],
    ['PKI/Keys', snapshot.telemetry.certificates + snapshot.telemetry.generatedKeys + snapshot.telemetry.vaultFiles],
    ['Cloud', snapshot.telemetry.connectors],
  ], [snapshot.telemetry]);

  return (
    <main className="min-h-screen bg-[#050914] px-4 py-5 text-white md:px-6">
      <div className="mx-auto max-w-[1540px] space-y-4">
        <Header
          mode={mode}
          snapshot={snapshot}
          state={state}
          sseConnected={sseConnected}
          refresh={refresh}
          search={search}
          setSearch={setSearch}
          severity={severity}
          setSeverity={setSeverity}
        />
        {error ? <div className="rounded-md border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-200">{error}</div> : null}
        <Panel className="p-3">
          <div className="grid gap-2 md:grid-cols-5">
            {telemetrySummary.map(([label, value]) => (
              <div key={label} className="flex items-center justify-between border-b border-white/6 px-2 py-2 last:border-b-0 md:border-b-0 md:border-r md:last:border-r-0">
                <span className="text-[10px] font-black uppercase tracking-[0.06em] text-white/38">{label}</span>
                <span className="font-mono text-sm text-white/75">{compactFmt(Number(value))}</span>
              </div>
            ))}
          </div>
        </Panel>
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
          <Body mode={mode} snapshot={snapshot} alerts={filteredAlerts} inventory={filteredInventory} />
        </motion.div>
        <div className="text-right text-[10px] uppercase tracking-[0.06em] text-white/28">
          {config.title} synchronized from authenticated tenant telemetry streams.
        </div>
      </div>
    </main>
  );
}
