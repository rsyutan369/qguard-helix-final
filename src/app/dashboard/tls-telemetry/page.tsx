'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Download,
  Info,
  Lock,
  Network,
  Plus,
  RefreshCw,
  Server,
  ShieldAlert,
  UserRound,
  XCircle,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import { cn } from '@/lib/utils';

type LoadState = 'loading' | 'success' | 'error';

type TimelinePoint = {
  label: string;
  total: number;
  successful: number;
  failed: number;
};

type DistributionRow = {
  label: string;
  count: number;
  percent: number;
};

type CipherSuiteRow = {
  cipherSuite: string;
  connections: number;
  percent: number;
};

type DomainRow = {
  domain: string;
  connections: number;
  percent: number;
};

type AlertRow = {
  id: string;
  title: string;
  detail: string;
  severity: string;
  time: string | null;
};

type ClientRow = {
  clientIp: string;
  connections: number;
  percent: number;
  bytes: number;
  ja3Fingerprint: string;
};

type ServerRow = {
  serverIp: string;
  connections: number;
  percent: number;
  bytes: number;
  certValidityDays: number | null;
};

type InsightRow = {
  id: string;
  title: string;
  detail: string;
  severity: string;
};

type TlsTelemetrySnapshot = {
  generatedAt: string | null;
  latestActivityAt: string | null;
  metrics: {
    totalConnections: number;
    totalConnectionsDelta: number;
    successfulHandshakes: number;
    successfulHandshakesDelta: number;
    failedHandshakes: number;
    failedHandshakesDelta: number;
    uniqueClients: number;
    uniqueClientsDelta: number;
    uniqueServers: number;
    uniqueServersDelta: number;
    encryptedTrafficBytes: number;
    encryptedTrafficDelta: number;
    quantumRiskScore: number;
    quantumRiskLevel: string;
    connectionsAtRiskPercent: number;
    weakAlgorithmsPercent: number;
  };
  timeline: TimelinePoint[];
  tlsVersionDistribution: DistributionRow[];
  topCipherSuites: CipherSuiteRow[];
  connectionTypes: DistributionRow[];
  topDomains: DomainRow[];
  recentAlerts: AlertRow[];
  topClients: ClientRow[];
  topServers: ServerRow[];
  insights: InsightRow[];
  telemetry: {
    runtimeEvents: number;
    scannerEvidence: number;
    scannerAlerts: number;
    scanResults: number;
    certificates: number;
    securityEvents: number;
    assets: number;
    scannerAgents: number;
    connectors: number;
    agentHeartbeats: number;
    eventPipelineStatus: string;
    latestRuntimeEventAt: string | null;
  };
};

const EMPTY_SNAPSHOT: TlsTelemetrySnapshot = {
  generatedAt: null,
  latestActivityAt: null,
  metrics: {
    totalConnections: 0,
    totalConnectionsDelta: 0,
    successfulHandshakes: 0,
    successfulHandshakesDelta: 0,
    failedHandshakes: 0,
    failedHandshakesDelta: 0,
    uniqueClients: 0,
    uniqueClientsDelta: 0,
    uniqueServers: 0,
    uniqueServersDelta: 0,
    encryptedTrafficBytes: 0,
    encryptedTrafficDelta: 0,
    quantumRiskScore: 0,
    quantumRiskLevel: 'No Risk',
    connectionsAtRiskPercent: 0,
    weakAlgorithmsPercent: 0,
  },
  timeline: [],
  tlsVersionDistribution: [],
  topCipherSuites: [],
  connectionTypes: [],
  topDomains: [],
  recentAlerts: [],
  topClients: [],
  topServers: [],
  insights: [],
  telemetry: {
    runtimeEvents: 0,
    scannerEvidence: 0,
    scannerAlerts: 0,
    scanResults: 0,
    certificates: 0,
    securityEvents: 0,
    assets: 0,
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
const PURPLE = '#7C3AED';
const CYAN = '#22D3EE';
const GOLD = '#FBBF24';
const ORANGE = '#F97316';
const TEAL = '#14B8A6';

const VERSION_COLORS: Record<string, string> = {
  'TLS 1.3': BLUE,
  'TLS 1.2': GREEN,
  'TLS 1.1': GOLD,
  'TLS 1.0': ORANGE,
  'SSL 3.0': RED,
  Unknown: '#64748B',
};

const TYPE_COLORS: Record<string, string> = {
  HTTPS: BLUE,
  LDAPS: GREEN,
  IMAPS: PURPLE,
  SMTPS: GOLD,
  Others: CYAN,
};

const PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-blue-400/12 bg-[#07101D]/72 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(36,120,255,0.035),0_0_34px_rgba(0,0,0,0.34)] transition duration-500 hover:-translate-y-0.5 hover:border-gold/65 hover:bg-[#0A1728]/84 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.22),inset_0_-24px_60px_rgba(251,191,36,0.12),0_16px_46px_rgba(0,0,0,0.48),0_0_58px_rgba(251,191,36,0.28)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/55 before:to-transparent after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-52 after:w-52 after:rounded-full after:bg-gold/8 after:blur-3xl after:opacity-0 after:transition group-hover:after:opacity-100';

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

function bytesFmt(value: number) {
  const safe = Math.max(0, Number(value) || 0);
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let index = 0;
  let current = safe;
  while (current >= 1024 && index < units.length - 1) {
    current /= 1024;
    index += 1;
  }
  return `${current >= 10 || index === 0 ? current.toFixed(0) : current.toFixed(2)} ${units[index]}`;
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
  if (!value) return 'Awaiting TLS telemetry';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Awaiting TLS telemetry';
  return date.toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function deltaClass(value: number, goodUp = true) {
  if (value === 0) return 'text-white/45';
  const good = goodUp ? value > 0 : value < 0;
  return good ? 'text-emerald-300' : 'text-red-300';
}

function severityColor(severity: string) {
  const value = severity.toLowerCase();
  if (value.includes('high') || value.includes('critical')) return RED;
  if (value.includes('medium') || value.includes('warning')) return GOLD;
  if (value.includes('low') || value.includes('info')) return BLUE;
  return GREEN;
}

function linePath(values: number[], width: number, height: number, pad = 18) {
  if (!values.length) return '';
  const max = Math.max(1, ...values);
  return values.map((value, index) => {
    const x = pad + (values.length <= 1 ? 0 : (index / (values.length - 1)) * (width - pad * 2));
    const y = pad + (height - pad * 2) - ((Number(value) || 0) / max) * (height - pad * 2);
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(' ');
}

function useTlsTelemetry() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<TlsTelemetrySnapshot>(EMPTY_SNAPSHOT);
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
      const response = await fetch('/api/v1/dashboard/tls-telemetry', {
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
      const message = err instanceof Error ? err.message : 'Unable to load TLS telemetry data';
      console.error('TLS telemetry load failed:', err);
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
      'scanner_evidence',
      'scanner_alerts',
      'pqc_scan_results',
      'certificates',
      'security_events',
      'scanner_agents',
      'connector_accounts',
      'agent_heartbeats',
    ];

    const channels = tables.map((table) => supabase
      .channel(`tls-telemetry-${table}`)
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
      const tlsStream = new EventSource(`/api/v1/dashboard/tls-telemetry/stream?token=${encodeURIComponent(token)}`);
      const metricsStream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`);
      const scannerStream = new EventSource(`/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`);
      streamsRef.current = [tlsStream, metricsStream, scannerStream];

      const markOpen = () => setSseConnected(true);
      const scheduleReconnect = () => {
        setSseConnected(false);
        closeStreams();
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(connect, 10000);
      };
      const refreshFromStream = () => queueRefresh();

      tlsStream.onopen = markOpen;
      metricsStream.onopen = markOpen;
      scannerStream.onopen = markOpen;
      tlsStream.onerror = scheduleReconnect;
      metricsStream.onerror = scheduleReconnect;
      scannerStream.onerror = scheduleReconnect;
      tlsStream.addEventListener('tls-telemetry-connected', refreshFromStream);
      tlsStream.addEventListener('tls-telemetry-update', refreshFromStream);
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
  return (
    <svg className="h-10 w-24" viewBox="0 0 92 38" aria-hidden="true">
      <path d={linePath(values.length ? values : [0, 0], 92, 38, 5)} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      {values.map((value, index) => {
        const max = Math.max(1, ...values);
        const x = 5 + (values.length <= 1 ? 0 : (index / (values.length - 1)) * 82);
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
  delta,
  detail,
  color,
  spark,
  goodUp = true,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  delta: number;
  detail: string;
  color: string;
  spark: number[];
  goodUp?: boolean;
}) {
  return (
    <Panel className="min-h-[124px] p-4">
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
            <div className={cn('mt-1 text-xs font-bold', deltaClass(delta, goodUp))}>{signedPercent(delta)}</div>
            <div className="mt-1 text-[10px] text-white/45">{detail}</div>
          </div>
          <MiniSpark values={spark} color={color} />
        </div>
      </div>
    </Panel>
  );
}

function DonutChart({ rows, colors, center }: { rows: DistributionRow[]; colors: Record<string, string>; center: ReactNode }) {
  const total = Math.max(1, rows.reduce((sum, row) => sum + row.count, 0));
  let offset = 0;

  return (
    <div className="grid grid-cols-[170px_1fr] items-center gap-5">
      <div className="relative grid h-40 w-40 place-items-center">
        <svg className="h-40 w-40 -rotate-90" viewBox="0 0 120 120" aria-hidden="true">
          <circle cx="60" cy="60" r="42" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="17" />
          {rows.map((row) => {
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
                stroke={colors[row.label] || BLUE}
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
        {rows.map((row) => (
          <div key={row.label} className="grid grid-cols-[12px_1fr_90px] items-center gap-2 text-xs">
            <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: colors[row.label] || BLUE }} />
            <span className="truncate text-white/76">{row.label}</span>
            <span className="text-right font-mono text-white/75">{percentFmt(row.percent)} ({compactFmt(row.count)})</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ConnectionsChart({ points }: { points: TimelinePoint[] }) {
  const width = 760;
  const height = 230;
  const series = [
    { key: 'total', label: 'Total', color: BLUE },
    { key: 'successful', label: 'Successful', color: GREEN },
    { key: 'failed', label: 'Failed', color: RED },
  ] as const;

  if (!points.length) return <EmptyState label="Awaiting TLS handshake telemetry." />;

  const max = Math.max(1, ...points.flatMap((point) => series.map((item) => point[item.key])));
  const xFor = (index: number) => 34 + (points.length <= 1 ? 0 : (index / (points.length - 1)) * (width - 68));
  const yFor = (value: number) => 20 + 168 - (value / max) * 168;

  return (
    <div>
      <div className="mb-3 flex items-center gap-5 text-[10px] text-white/65">
        {series.map((item) => (
          <span key={item.label} className="inline-flex items-center gap-2">
            <span className="h-2 w-3 rounded-sm" style={{ backgroundColor: item.color }} />
            {item.label}
          </span>
        ))}
      </div>
      <svg className="h-[230px] w-full" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="TLS connections over time">
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

function CipherSuites({ rows }: { rows: CipherSuiteRow[] }) {
  if (!rows.length) return <EmptyState label="No cipher-suite telemetry has been captured yet." />;
  const colors = [BLUE, GREEN, PURPLE, ORANGE, CYAN, '#64748B'];
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-[1fr_220px_86px_58px] gap-3 border-b border-white/8 pb-2 text-[10px] text-white/42">
        <span>Cipher Suite</span>
        <span />
        <span className="text-right">Connections</span>
        <span className="text-right">%</span>
      </div>
      {rows.map((row, index) => (
        <div key={row.cipherSuite} className="grid grid-cols-[1fr_220px_86px_58px] items-center gap-3 border-b border-white/5 py-2 text-xs">
          <span className="truncate font-mono text-white/76">{row.cipherSuite}</span>
          <span className="h-2 overflow-hidden rounded-full bg-white/5">
            <span className="block h-full rounded-full" style={{ width: `${Math.min(100, row.percent)}%`, backgroundColor: colors[index] || BLUE }} />
          </span>
          <span className="text-right font-mono text-white/75">{compactFmt(row.connections)}</span>
          <span className="text-right font-mono text-white/75">{percentFmt(row.percent)}</span>
        </div>
      ))}
    </div>
  );
}

function Domains({ rows }: { rows: DomainRow[] }) {
  if (!rows.length) return <EmptyState label="No SNI or domain telemetry is available yet." />;
  return (
    <div className="space-y-2">
      <div className="grid grid-cols-[1fr_92px_52px] gap-3 border-b border-white/8 pb-2 text-[10px] text-white/42">
        <span>Domain</span>
        <span className="text-right">Connections</span>
        <span className="text-right">%</span>
      </div>
      {rows.map((row) => (
        <div key={row.domain} className="grid grid-cols-[1fr_92px_52px] gap-3 border-b border-white/5 py-2 text-xs">
          <span className="truncate font-medium text-white/78">{row.domain}</span>
          <span className="text-right font-mono text-white/75">{compactFmt(row.connections)}</span>
          <span className="text-right font-mono text-white/75">{percentFmt(row.percent)}</span>
        </div>
      ))}
    </div>
  );
}

function Alerts({ rows }: { rows: AlertRow[] }) {
  if (!rows.length) return <EmptyState label="No TLS alerts are active for this tenant." />;
  return (
    <div className="space-y-3">
      {rows.map((row) => {
        const color = severityColor(row.severity);
        const Icon = row.severity.toLowerCase().includes('high') ? ShieldAlert : row.severity.toLowerCase().includes('medium') ? AlertTriangle : Info;
        return (
          <div key={row.id} className="grid grid-cols-[34px_1fr_58px_auto] items-center gap-3 border-b border-white/5 pb-3 text-xs">
            <span className="grid h-8 w-8 place-items-center rounded-full border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
              <Icon className="h-4 w-4" />
            </span>
            <span className="min-w-0">
              <span className="block truncate font-bold text-white/84">{row.title}</span>
              <span className="block truncate text-[10px] text-white/45">{row.detail}</span>
            </span>
            <span className="text-right text-[10px] text-white/48">{shortTime(row.time)}</span>
            <span className="rounded-md border px-2 py-1 text-[10px] font-black" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}10` }}>{row.severity}</span>
          </div>
        );
      })}
    </div>
  );
}

function TopClients({ rows }: { rows: ClientRow[] }) {
  if (!rows.length) return <EmptyState label="No client telemetry has been captured yet." />;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-[620px] w-full text-left text-xs">
        <thead>
          <tr className="border-b border-white/8 text-[10px] text-white/42">
            <th className="pb-3 font-medium">Client IP</th>
            <th className="pb-3 text-right font-medium">Connections</th>
            <th className="pb-3 text-right font-medium">%</th>
            <th className="pb-3 text-right font-medium">Bytes</th>
            <th className="pb-3 font-medium">JA3 Fingerprint</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.clientIp} className="border-b border-white/5 text-white/72">
              <td className="py-3 font-mono">{row.clientIp}</td>
              <td className="py-3 text-right font-mono">{compactFmt(row.connections)}</td>
              <td className="py-3 text-right font-mono">{percentFmt(row.percent)}</td>
              <td className="py-3 text-right font-mono">{bytesFmt(row.bytes)}</td>
              <td className="max-w-[190px] truncate py-3 font-mono text-white/55">{row.ja3Fingerprint}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TopServers({ rows }: { rows: ServerRow[] }) {
  if (!rows.length) return <EmptyState label="No server telemetry has been captured yet." />;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-[620px] w-full text-left text-xs">
        <thead>
          <tr className="border-b border-white/8 text-[10px] text-white/42">
            <th className="pb-3 font-medium">Server IP</th>
            <th className="pb-3 text-right font-medium">Connections</th>
            <th className="pb-3 text-right font-medium">%</th>
            <th className="pb-3 text-right font-medium">Bytes</th>
            <th className="pb-3 text-right font-medium">Cert Validity</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.serverIp} className="border-b border-white/5 text-white/72">
              <td className="py-3 font-mono">{row.serverIp}</td>
              <td className="py-3 text-right font-mono">{compactFmt(row.connections)}</td>
              <td className="py-3 text-right font-mono">{percentFmt(row.percent)}</td>
              <td className="py-3 text-right font-mono">{bytesFmt(row.bytes)}</td>
              <td className="py-3 text-right font-mono">{row.certValidityDays == null ? '--' : `${integerFmt(row.certValidityDays)} days`}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function QuantumRiskPanel({ snapshot }: { snapshot: TlsTelemetrySnapshot }) {
  const riskSpark = snapshot.timeline.map((point) => point.failed);
  return (
    <div className="grid h-full grid-cols-[96px_1fr] items-center gap-5">
      <div className="grid h-16 w-16 place-items-center rounded-full border border-red-500/20 bg-red-500/10 text-red-300">
        <ShieldAlert className="h-8 w-8" />
      </div>
      <div>
        <div className="flex items-baseline gap-1">
          <span className="text-4xl font-semibold" style={{ color: severityColor(snapshot.metrics.quantumRiskLevel) }}>{integerFmt(snapshot.metrics.quantumRiskScore)}</span>
          <span className="text-sm font-bold text-white/55">/100</span>
        </div>
        <div className="mt-1 text-xs font-bold" style={{ color: severityColor(snapshot.metrics.quantumRiskLevel) }}>{snapshot.metrics.quantumRiskLevel}</div>
        <MiniSpark values={riskSpark} color={RED} />
        <div className="mt-3 grid grid-cols-2 gap-4 text-xs">
          <div>
            <div className="text-white/45">Connections At Risk</div>
            <div className="mt-1 font-semibold text-white">{percentFmt(snapshot.metrics.connectionsAtRiskPercent)}</div>
          </div>
          <div>
            <div className="text-white/45">Weak Algorithms</div>
            <div className="mt-1 font-semibold text-white">{percentFmt(snapshot.metrics.weakAlgorithmsPercent)}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Insights({ rows }: { rows: InsightRow[] }) {
  if (!rows.length) return <EmptyState label="No TLS insights are available yet." />;
  return (
    <div className="space-y-4">
      {rows.map((row) => {
        const color = row.severity === 'success' ? GREEN : row.severity === 'warning' ? GOLD : BLUE;
        const Icon = row.severity === 'success' ? CheckCircle2 : row.severity === 'warning' ? AlertTriangle : Info;
        return (
          <div key={row.id} className="grid grid-cols-[34px_1fr] gap-3">
            <span className="grid h-8 w-8 place-items-center rounded-full border" style={{ borderColor: `${color}45`, backgroundColor: `${color}12`, color }}>
              <Icon className="h-4 w-4" />
            </span>
            <span className="min-w-0">
              <span className="block text-xs font-bold text-white/84">{row.title}</span>
              <span className="block text-[10px] text-white/45">{row.detail}</span>
            </span>
          </div>
        );
      })}
    </div>
  );
}

export default function TlsTelemetryPage() {
  const { snapshot, state, error, sseConnected, refresh } = useTlsTelemetry();
  const totalSpark = useMemo(() => snapshot.timeline.map((point) => point.total), [snapshot.timeline]);
  const successSpark = useMemo(() => snapshot.timeline.map((point) => point.successful), [snapshot.timeline]);
  const failedSpark = useMemo(() => snapshot.timeline.map((point) => point.failed), [snapshot.timeline]);

  const cards = [
    { icon: Network, label: 'Total Connections', value: compactFmt(snapshot.metrics.totalConnections), delta: snapshot.metrics.totalConnectionsDelta, detail: 'vs prev 7 days', color: BLUE, spark: totalSpark },
    { icon: CheckCircle2, label: 'Successful Handshakes', value: compactFmt(snapshot.metrics.successfulHandshakes), delta: snapshot.metrics.successfulHandshakesDelta, detail: 'success rate telemetry', color: GREEN, spark: successSpark },
    { icon: XCircle, label: 'Failed Handshakes', value: compactFmt(snapshot.metrics.failedHandshakes), delta: snapshot.metrics.failedHandshakesDelta, detail: 'failure telemetry', color: RED, spark: failedSpark, goodUp: false },
    { icon: UserRound, label: 'Unique Clients', value: compactFmt(snapshot.metrics.uniqueClients), delta: snapshot.metrics.uniqueClientsDelta, detail: 'tenant client set', color: PURPLE, spark: totalSpark },
    { icon: Server, label: 'Unique Servers', value: compactFmt(snapshot.metrics.uniqueServers), delta: snapshot.metrics.uniqueServersDelta, detail: 'tenant endpoint set', color: CYAN, spark: successSpark },
    { icon: Lock, label: 'Encrypted Traffic', value: bytesFmt(snapshot.metrics.encryptedTrafficBytes), delta: snapshot.metrics.encryptedTrafficDelta, detail: 'reported encrypted bytes', color: GOLD, spark: totalSpark },
  ];

  const exportReport = useCallback(() => {
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `tls-telemetry-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }, [snapshot]);

  return (
    <div className="min-h-screen bg-[#030711] px-4 py-4 text-white sm:px-5 lg:px-6">
      <div className="mx-auto max-w-[1540px] space-y-4">
        <header className="flex flex-col gap-4 border-b border-gold/10 pb-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="flex items-center gap-4">
              <Zap className="h-10 w-10 text-gold drop-shadow-[0_0_16px_rgba(251,191,36,0.45)]" />
              <h1 className="font-mono text-3xl font-black uppercase tracking-[0.22em] text-gold drop-shadow-[0_0_16px_rgba(251,191,36,0.35)] md:text-4xl">
                TLS Telemetry
              </h1>
            </div>
            <p className="mt-4 font-mono text-base tracking-[0.08em] text-gold/70">
              Deep inspection and telemetry for TLS/SSL connections.
            </p>
          </div>

          <div className="flex flex-wrap justify-start gap-2 xl:justify-end">
            <button type="button" className="inline-flex h-9 items-center gap-2 rounded-md border border-blue-500/40 bg-blue-500 px-3 text-xs font-bold text-white transition hover:border-gold hover:bg-gold hover:text-black">
              <Plus className="h-4 w-4" />
              Add Widget
            </button>
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
          <Panel className="p-5 xl:col-span-4">
            <SectionTitle
              suffix={(
                <button type="button" onClick={() => void refresh()} className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-black/20 px-3 py-1.5 text-[10px] font-bold text-white/55 transition hover:border-gold/45 hover:text-gold">
                  7 Days <ChevronDown className="h-3.5 w-3.5" />
                  <RefreshCw className={cn('h-3.5 w-3.5', state === 'loading' && 'animate-spin')} />
                </button>
              )}
            >
              TLS Connections Over Time
            </SectionTitle>
            <ConnectionsChart points={snapshot.timeline} />
          </Panel>

          <Panel className="p-5 xl:col-span-4">
            <SectionTitle>TLS Version Distribution</SectionTitle>
            <DonutChart
              rows={snapshot.tlsVersionDistribution}
              colors={VERSION_COLORS}
              center={(
                <>
                  <div className="text-3xl font-semibold text-white">{compactFmt(snapshot.metrics.totalConnections)}</div>
                  <div className="text-xs text-white/70">Total</div>
                </>
              )}
            />
          </Panel>

          <Panel className="p-5 xl:col-span-4">
            <SectionTitle suffix={<a href="/dashboard/runtime-crypto-intel" className="text-xs font-bold text-blue-300 transition hover:text-gold">View all</a>}>
              Top Cipher Suites
            </SectionTitle>
            <CipherSuites rows={snapshot.topCipherSuites} />
          </Panel>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-3">
            <SectionTitle>Connections By Type</SectionTitle>
            <DonutChart
              rows={snapshot.connectionTypes}
              colors={TYPE_COLORS}
              center={(
                <>
                  <div className="text-2xl font-semibold text-white">{compactFmt(snapshot.metrics.totalConnections)}</div>
                  <div className="text-xs text-white/70">Total</div>
                </>
              )}
            />
          </Panel>

          <Panel className="p-5 xl:col-span-3">
            <SectionTitle>Quantum Risk (PQC Readiness)</SectionTitle>
            <QuantumRiskPanel snapshot={snapshot} />
          </Panel>

          <Panel className="p-5 xl:col-span-3">
            <SectionTitle suffix={<a href="/dashboard/runtime-crypto-intel" className="text-xs font-bold text-blue-300 transition hover:text-gold">View all</a>}>
              SNI / Top Domains
            </SectionTitle>
            <Domains rows={snapshot.topDomains} />
          </Panel>

          <Panel className="p-5 xl:col-span-3">
            <SectionTitle suffix={<a href="/dashboard/telemetry-correlation" className="text-xs font-bold text-blue-300 transition hover:text-gold">View all</a>}>
              Recent Alerts
            </SectionTitle>
            <Alerts rows={snapshot.recentAlerts} />
          </Panel>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-4">
            <SectionTitle suffix={<a href="/dashboard/asset-intelligence" className="text-xs font-bold text-blue-300 transition hover:text-gold">View all</a>}>
              Top Clients
            </SectionTitle>
            <TopClients rows={snapshot.topClients} />
          </Panel>

          <Panel className="p-5 xl:col-span-4">
            <SectionTitle suffix={<a href="/dashboard/asset-intelligence" className="text-xs font-bold text-blue-300 transition hover:text-gold">View all</a>}>
              Top Servers
            </SectionTitle>
            <TopServers rows={snapshot.topServers} />
          </Panel>

          <Panel className="p-5 xl:col-span-4">
            <SectionTitle>TLS Insights</SectionTitle>
            <Insights rows={snapshot.insights} />
            <div className="mt-5 flex justify-end">
              <a href="/dashboard/protocol-analytics" className="inline-flex items-center gap-1 text-xs font-bold text-blue-300 transition hover:text-gold">
                View all insights <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </Panel>
        </section>

        <div className="flex flex-wrap items-center justify-between gap-3 text-[11px] text-white/35">
          <span className="inline-flex items-center gap-2">
            <span className={cn('h-2 w-2 rounded-full', sseConnected ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]' : 'bg-gold animate-pulse')} />
            {sseConnected ? 'TLS SSE, metrics stream, scanner stream, and live table subscriptions connected' : 'Connecting TLS telemetry streams'}
          </span>
          <span>Pipeline: {snapshot.telemetry.eventPipelineStatus.replace(/_/g, ' ')} - Latest activity: {longDate(snapshot.latestActivityAt || snapshot.telemetry.latestRuntimeEventAt)}</span>
        </div>
      </div>
    </div>
  );
}
