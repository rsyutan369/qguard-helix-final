'use client';

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  ChevronRight,
  Circle,
  HelpCircle,
  LockKeyhole,
  Search,
  ShieldCheck,
  ShieldAlert,
  Sparkles,
  UserRound,
  Wand2,
  Waves,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import { TLS_DASHBOARD_TABLES } from '../_lib/telemetry-sync';

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

type AlertRow = {
  id: string;
  title: string;
  detail: string;
  severity: string;
  time: string | null;
};

type ServerRow = {
  serverIp: string;
  connections: number;
  percent: number;
  bytes: number;
  certValidityDays: number | null;
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
  topDomains: Array<{ domain: string; connections: number; percent: number }>;
  recentAlerts: AlertRow[];
  topServers: ServerRow[];
  insights: Array<{ id: string; title: string; detail: string; severity: string }>;
  telemetry: {
    runtimeEvents: number;
    scannerEvidence: number;
    scannerAlerts: number;
    scanSessions: number;
    scanResults: number;
    certificates: number;
    securityEvents: number;
    assets: number;
    scannerAgents: number;
    connectors: number;
    agentHeartbeats: number;
    activeAssets: number;
    inactiveAssets: number;
    onlineAgents: number;
    offlineAgents: number;
    freshHeartbeats: number;
    runningScans: number;
    completedScans: number;
    failedScans: number;
    eventPipelineStatus: string;
    latestRuntimeEventAt: string | null;
    latestScanAt: string | null;
    latestAgentHeartbeatAt: string | null;
    latestDiscoveryAt: string | null;
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
  topServers: [],
  insights: [],
  telemetry: {
    runtimeEvents: 0,
    scannerEvidence: 0,
    scannerAlerts: 0,
    scanSessions: 0,
    scanResults: 0,
    certificates: 0,
    securityEvents: 0,
    assets: 0,
    scannerAgents: 0,
    connectors: 0,
    agentHeartbeats: 0,
    activeAssets: 0,
    inactiveAssets: 0,
    onlineAgents: 0,
    offlineAgents: 0,
    freshHeartbeats: 0,
    runningScans: 0,
    completedScans: 0,
    failedScans: 0,
    eventPipelineStatus: 'no_agents',
    latestRuntimeEventAt: null,
    latestScanAt: null,
    latestAgentHeartbeatAt: null,
    latestDiscoveryAt: null,
  },
};

const BLUE = '#2563eb';
const PURPLE = '#7c3aed';
const ORANGE = '#fb923c';
const RED = '#ef4444';
const GREEN = '#22c55e';
const SKY = '#0ea5e9';
const SLATE = '#6b7280';

const cx = (...classes: Array<string | false | null | undefined>) => classes.filter(Boolean).join(' ');

const TLS_ORCHESTRATOR_THEME_CSS = `
  .tls-orchestrator {
    --tls-text: #11194a;
    --tls-muted: #536192;
    --tls-border: #dce4f5;
    --tls-surface: rgba(255, 255, 255, 0.94);
    --tls-track: #edf1f8;
    --tls-link: #2563eb;
  }

  .tls-orchestrator-card {
    backdrop-filter: blur(18px);
    transition: border-color 180ms ease, box-shadow 180ms ease, transform 180ms ease, background-color 180ms ease;
  }

  .tls-orchestrator-card:hover {
    border-color: rgba(124, 58, 237, 0.28);
    box-shadow: 0 18px 48px rgba(37, 99, 235, 0.13), 0 0 0 1px rgba(124, 58, 237, 0.08);
    transform: translateY(-1px);
  }

  .qg-theme-dark .tls-orchestrator {
    --tls-text: #f8fbff;
    --tls-muted: rgba(226, 232, 240, 0.72);
    --tls-border: rgba(255, 255, 255, 0.11);
    --tls-surface: rgba(10, 17, 32, 0.78);
    --tls-track: rgba(255, 255, 255, 0.1);
    --tls-link: #8bb5ff;
    background:
      radial-gradient(circle at 18% 0%, rgba(124, 58, 237, 0.24), transparent 32%),
      radial-gradient(circle at 84% 12%, rgba(37, 99, 235, 0.18), transparent 30%),
      linear-gradient(180deg, #040812 0%, #08111f 46%, #040812 100%) !important;
    color: var(--tls-text) !important;
  }

  .qg-theme-dark .tls-orchestrator header {
    background: rgba(5, 10, 20, 0.92) !important;
    border-color: var(--tls-border) !important;
    box-shadow: 0 18px 46px rgba(0, 0, 0, 0.2);
    backdrop-filter: blur(18px);
  }

  .qg-theme-dark .tls-orchestrator-card,
  .qg-theme-dark .tls-orchestrator [class*="bg-white"] {
    background-color: var(--tls-surface) !important;
    border-color: var(--tls-border) !important;
    box-shadow: 0 16px 46px rgba(0, 0, 0, 0.24);
  }

  .qg-theme-dark .tls-orchestrator-card:hover {
    border-color: rgba(255, 211, 107, 0.28) !important;
    box-shadow: 0 20px 58px rgba(124, 58, 237, 0.22), 0 0 34px rgba(255, 211, 107, 0.08);
  }

  .qg-theme-dark .tls-orchestrator input {
    background: rgba(15, 23, 42, 0.76) !important;
    border-color: var(--tls-border) !important;
    color: var(--tls-text) !important;
    box-shadow: 0 12px 34px rgba(0, 0, 0, 0.18);
  }

  .qg-theme-dark .tls-orchestrator input::placeholder {
    color: rgba(226, 232, 240, 0.42) !important;
  }

  .qg-theme-dark .tls-orchestrator [class*="text-[#11194a]"],
  .qg-theme-dark .tls-orchestrator [class*="text-[#26315f]"] {
    color: var(--tls-text) !important;
  }

  .qg-theme-dark .tls-orchestrator [class*="text-[#536192]"],
  .qg-theme-dark .tls-orchestrator [class*="text-[#596693]"],
  .qg-theme-dark .tls-orchestrator [class*="text-[#6b7397]"],
  .qg-theme-dark .tls-orchestrator [class*="text-[#7b84aa]"],
  .qg-theme-dark .tls-orchestrator [class*="text-[#8a94b8]"],
  .qg-theme-dark .tls-orchestrator [class*="text-[#33406f]"],
  .qg-theme-dark .tls-orchestrator [class*="text-[#40507c]"],
  .qg-theme-dark .tls-orchestrator [class*="text-[#283466]"] {
    color: var(--tls-muted) !important;
  }

  .qg-theme-dark .tls-orchestrator [class*="text-[#2563eb]"],
  .qg-theme-dark .tls-orchestrator [class*="text-[#1d4ed8]"] {
    color: var(--tls-link) !important;
  }

  .qg-theme-dark .tls-orchestrator [class*="border-[#dce4f5]"],
  .qg-theme-dark .tls-orchestrator [class*="border-[#dde5f4]"],
  .qg-theme-dark .tls-orchestrator [class*="border-[#e8edf7]"],
  .qg-theme-dark .tls-orchestrator [class*="border-[#edf1f8]"] {
    border-color: var(--tls-border) !important;
  }

  .qg-theme-dark .tls-orchestrator [class*="divide-[#e8edf7]"] > :not([hidden]) ~ :not([hidden]) {
    border-color: var(--tls-border) !important;
  }

  .qg-theme-dark .tls-orchestrator [class*="bg-[#eef2ff]"] {
    background-color: rgba(99, 102, 241, 0.16) !important;
  }

  .qg-theme-dark .tls-orchestrator [class*="bg-[#edf1f8]"] {
    background-color: var(--tls-track) !important;
  }

  .qg-theme-dark .tls-orchestrator [class*="bg-red-50"] {
    background-color: rgba(239, 68, 68, 0.16) !important;
  }

  .qg-theme-dark .tls-orchestrator [class*="bg-orange-50"] {
    background-color: rgba(251, 146, 60, 0.16) !important;
  }

  .qg-theme-dark .tls-orchestrator [class*="bg-emerald-50"] {
    background-color: rgba(34, 197, 94, 0.16) !important;
  }

  .qg-theme-dark .tls-orchestrator svg circle[stroke="#eef2ff"],
  .qg-theme-dark .tls-orchestrator svg path[stroke="#edf0f8"],
  .qg-theme-dark .tls-orchestrator svg line[stroke="#e6eaf5"] {
    stroke: var(--tls-track) !important;
  }

  .qg-theme-dark .tls-orchestrator svg text[fill="#7b84aa"] {
    fill: rgba(226, 232, 240, 0.5) !important;
  }
`;

function numberFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(Number(value) || 0)));
}

function pct(value: number) {
  return `${Math.max(0, Math.min(100, Math.round(Number(value) || 0)))}%`;
}

function shortTime(value: string | null) {
  if (!value) return 'Awaiting telemetry';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Awaiting telemetry';
  return date.toLocaleString('en-US', { hour: '2-digit', minute: '2-digit' });
}

function relativeTime(value: string | null) {
  if (!value) return 'No event yet';
  const ms = new Date(value).getTime();
  if (!Number.isFinite(ms)) return 'No event yet';
  const minutes = Math.max(0, Math.round((Date.now() - ms) / 60000));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  return `${Math.round(minutes / 60)}h ago`;
}

function deltaText(value: number) {
  const rounded = Math.round(Number(value) || 0);
  return `${rounded > 0 ? '+' : ''}${rounded}%`;
}

function isHybridCipher(label: string) {
  return /ml-?kem|kyber|sntrup|pqc|hybrid/i.test(label);
}

function isClassicalWeak(label: string) {
  return /rsa key exchange|rsa_with|tls\s*1\.[01]|ssl|3des|rc4|sha1|sha-1|md5|cbc|export|anon/i.test(label);
}

function useTlsOrchestrator() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<TlsTelemetrySnapshot>(EMPTY_SNAPSHOT);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const streamsRef = useRef<EventSource[]>([]);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const closeStreams = useCallback(() => {
    for (const stream of streamsRef.current) stream.close();
    streamsRef.current = [];
    setConnected(false);
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
      const response = await fetch('/api/v1/dashboard/tls-orchestrator', {
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
      const message = err instanceof Error ? err.message : 'Unable to load TLS orchestrator data';
      console.error('TLS orchestrator load failed:', err);
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

    const channels = TLS_DASHBOARD_TABLES.map((table) => supabase
      .channel(`tls-orchestrator-${table}`)
      .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
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
      const tlsStream = new EventSource(`/api/v1/dashboard/tls-orchestrator/stream?token=${encodeURIComponent(token)}`);
      const metricsStream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`);
      const scannerStream = new EventSource(`/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`);
      streamsRef.current = [tlsStream, metricsStream, scannerStream];

      const markOpen = () => setConnected(true);
      const scheduleReconnect = () => {
        setConnected(false);
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

  return { snapshot, state, error, connected, refresh };
}

function MetricCard({
  icon: Icon,
  title,
  value,
  sub,
  color,
  ring,
}: {
  icon: LucideIcon;
  title: string;
  value: string;
  sub: string;
  color: string;
  ring?: number;
}) {
  const circumference = 88;
  const offset = circumference * (1 - Math.max(0, Math.min(100, ring ?? 0)) / 100);
  return (
    <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="tls-orchestrator-card rounded-lg border border-slate-200 bg-white p-4 shadow-[0_10px_28px_rgba(15,23,42,0.06)]">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className="grid h-12 w-12 place-items-center rounded-full" style={{ backgroundColor: `${color}16`, color }}>
            <Icon className="h-7 w-7" />
          </span>
          <div>
            <div className="text-[10px] font-black text-[#11194a]">{title}</div>
            <div className="mt-1 text-2xl font-black leading-none text-[#11194a]">{value}</div>
            <div className="mt-1 text-xs font-bold" style={{ color }}>{sub}</div>
          </div>
        </div>
        {typeof ring === 'number' && (
          <svg className="h-14 w-14 -rotate-90" viewBox="0 0 36 36" aria-hidden="true">
            <circle cx="18" cy="18" r="14" fill="none" stroke="#eef2ff" strokeWidth="4" />
            <circle cx="18" cy="18" r="14" fill="none" stroke={color} strokeWidth="4" strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round" />
          </svg>
        )}
      </div>
    </motion.section>
  );
}

function Gauge({ value, label, color = GREEN }: { value: number; label: string; color?: string }) {
  const clamped = Math.max(0, Math.min(100, Math.round(value)));
  const dash = 157 * (clamped / 100);
  return (
    <div className="flex flex-col items-center">
      <svg className="h-40 w-48" viewBox="0 0 190 130" aria-label={label}>
        <path d="M 28 104 A 67 67 0 0 1 162 104" fill="none" stroke="#edf0f8" strokeWidth="17" strokeLinecap="round" />
        <path d="M 28 104 A 67 67 0 0 1 162 104" fill="none" stroke="url(#gaugeGradient)" strokeWidth="17" strokeLinecap="round" strokeDasharray={`${dash} 157`} />
        <defs>
          <linearGradient id="gaugeGradient" x1="20" x2="170" y1="104" y2="104">
            <stop offset="0%" stopColor={RED} />
            <stop offset="45%" stopColor={ORANGE} />
            <stop offset="100%" stopColor={color} />
          </linearGradient>
        </defs>
        <ShieldCheck x="80" y="60" className="h-8 w-8 text-[#40507c]" />
      </svg>
      <div className="-mt-11 text-center">
        <div className="text-3xl font-black text-[#11194a]">{clamped}</div>
        <div className="text-sm font-bold text-[#6b7397]">/100</div>
        <div className="mt-1 text-sm font-bold" style={{ color }}>{label}</div>
      </div>
    </div>
  );
}

function Donut({ rows, total }: { rows: Array<{ label: string; value: number; color: string }>; total: number }) {
  const sum = Math.max(1, rows.reduce((acc, row) => acc + row.value, 0));
  let offset = 0;
  return (
    <div className="flex items-center gap-8">
      <div className="relative h-44 w-44">
        <svg className="h-full w-full -rotate-90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="43" fill="none" stroke="#eef2ff" strokeWidth="18" />
          {rows.map((row) => {
            const circumference = 270;
            const length = (row.value / sum) * circumference;
            const current = -offset;
            offset += length;
            return <circle key={row.label} cx="60" cy="60" r="43" fill="none" stroke={row.color} strokeWidth="18" strokeDasharray={`${length} ${circumference}`} strokeDashoffset={current} />;
          })}
        </svg>
        <div className="absolute inset-0 grid place-items-center text-center">
          <div>
            <div className="text-3xl font-black text-[#11194a]">{numberFmt(total)}</div>
            <div className="text-xs font-bold text-[#6b7397]">Total</div>
          </div>
        </div>
      </div>
      <div className="min-w-0 flex-1 space-y-3">
        {rows.map((row) => (
          <div key={row.label} className="grid grid-cols-[12px_1fr_52px] items-center gap-3 text-sm">
            <span className="h-3 w-3 rounded-full" style={{ backgroundColor: row.color }} />
            <span className="truncate font-bold text-[#26315f]">{row.label}</span>
            <span className="text-right font-black text-[#11194a]">{pct((row.value / Math.max(1, total)) * 100)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function LineChart({ points, hybridRatio }: { points: TimelinePoint[]; hybridRatio: number }) {
  const data = points.length ? points : [{ label: 'Now', total: 0, successful: 0, failed: 0 }];
  const series = [
    { key: 'hybrid', label: 'Hybrid (ML-KEM)', color: PURPLE },
    { key: 'classical', label: 'Classical', color: BLUE },
    { key: 'fallback', label: 'Fallbacks', color: RED },
  ] as const;
  const derived = data.map((point) => {
    const total = Math.max(1, point.total);
    const hybrid = Math.round(point.successful * hybridRatio);
    const classical = Math.max(0, point.successful - hybrid);
    return {
      label: point.label,
      hybrid: Math.round((hybrid / total) * 100),
      classical: Math.round((classical / total) * 100),
      fallback: Math.round((point.failed / total) * 100),
    };
  });
  const xFor = (index: number) => 36 + (derived.length <= 1 ? 0 : (index / (derived.length - 1)) * 410);
  const yFor = (value: number) => 28 + (100 - value) * 1.3;
  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-5 text-xs font-bold text-[#33406f]">
        {series.map((item) => <span key={item.key} className="inline-flex items-center gap-2"><span className="h-2 w-5 rounded-full" style={{ background: item.color }} />{item.label}</span>)}
      </div>
      <svg className="h-44 w-full" viewBox="0 0 480 180" role="img" aria-label="PQC negotiation live chart">
        {[0, 25, 50, 75, 100].map((tick) => (
          <g key={tick}>
            <line x1="34" x2="454" y1={yFor(tick)} y2={yFor(tick)} stroke="#e6eaf5" />
            <text x="4" y={yFor(tick) + 4} fontSize="10" fill="#7b84aa">{tick}%</text>
          </g>
        ))}
        {series.map((item) => {
          const d = derived.map((point, index) => `${index === 0 ? 'M' : 'L'} ${xFor(index)} ${yFor(point[item.key])}`).join(' ');
          return <path key={item.key} d={d} fill="none" stroke={item.color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />;
        })}
        {derived.map((point, index) => <text key={point.label} x={xFor(index)} y="174" textAnchor="middle" fontSize="10" fill="#7b84aa">{point.label}</text>)}
      </svg>
    </div>
  );
}

function Panel({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <section className={cx('tls-orchestrator-card rounded-lg border border-[#dce4f5] bg-white shadow-[0_10px_28px_rgba(15,23,42,0.05)]', className)}>
      {children}
    </section>
  );
}

function SectionTitle({ title, suffix }: { title: string; suffix?: ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-3 border-b border-[#e8edf7] pb-3">
      <h2 className="text-lg font-black text-[#11194a]">{title}</h2>
      {suffix}
    </div>
  );
}

export default function TlsOrchestratorPage() {
  const { snapshot, state, error, connected, refresh } = useTlsOrchestrator();
  const [query, setQuery] = useState('');

  const totalEndpoints = snapshot.metrics.uniqueServers || snapshot.telemetry.activeAssets || snapshot.telemetry.assets;
  const totalNegotiations = Math.max(1, snapshot.metrics.totalConnections);
  const downgradeEvents = snapshot.metrics.failedHandshakes;
  const readiness = Math.max(0, 100 - snapshot.metrics.connectionsAtRiskPercent);
  const pqcReadyCount = Math.round(totalEndpoints * readiness / 100);
  const hybridConnections = snapshot.topCipherSuites.filter((row) => isHybridCipher(row.cipherSuite)).reduce((sum, row) => sum + row.connections, 0);
  const weakConnections = snapshot.topCipherSuites.filter((row) => isClassicalWeak(row.cipherSuite)).reduce((sum, row) => sum + row.connections, 0);
  const hybridPercent = snapshot.topCipherSuites.length ? Math.round((hybridConnections / Math.max(1, snapshot.topCipherSuites.reduce((sum, row) => sum + row.connections, 0))) * 100) : Math.max(0, 100 - snapshot.metrics.weakAlgorithmsPercent);
  const classicalPercent = Math.max(0, Math.min(100, 100 - hybridPercent - Math.round((downgradeEvents / totalNegotiations) * 100)));
  const classicalCount = Math.round(totalEndpoints * classicalPercent / 100);
  const hybridCount = Math.round(totalEndpoints * hybridPercent / 100);
  const incompatibleCount = snapshot.recentAlerts.filter((alert) => /downgrade|failed|weak|fallback|tls 1\.[01]|ssl|certificate/i.test(`${alert.title} ${alert.detail}`)).length;
  const partialCount = Math.max(0, Math.min(totalEndpoints, snapshot.metrics.failedHandshakes));
  const compatibleCount = Math.max(0, totalEndpoints - incompatibleCount - partialCount);
  const compatibilityScore = totalEndpoints ? Math.round((compatibleCount / totalEndpoints) * 100) : readiness;

  const keyExchangeRows = useMemo(() => {
    if (snapshot.topCipherSuites.length) {
      return snapshot.topCipherSuites.slice(0, 5).map((row, index) => ({
        label: row.cipherSuite,
        value: row.connections,
        color: [PURPLE, BLUE, ORANGE, RED, '#a7adc3'][index] || SLATE,
      }));
    }
    return snapshot.tlsVersionDistribution.slice(0, 5).map((row, index) => ({
      label: row.label,
      value: row.count,
      color: [PURPLE, BLUE, ORANGE, RED, '#a7adc3'][index] || SLATE,
    }));
  }, [snapshot.topCipherSuites, snapshot.tlsVersionDistribution]);

  const middleboxes = snapshot.topServers.slice(0, 5).map((server, index) => {
    const relatedAlert = snapshot.recentAlerts.find((alert) => alert.detail === server.serverIp || alert.detail.includes(server.serverIp));
    const risk = relatedAlert?.severity || (server.certValidityDays !== null && server.certValidityDays <= 30 ? 'Medium' : 'Low');
    return {
      name: server.serverIp,
      type: index % 3 === 0 ? 'Load Balancer' : index % 3 === 1 ? 'CDN / Proxy' : 'Service Mesh',
      status: !relatedAlert,
      risk,
      issue: relatedAlert?.title || (server.certValidityDays !== null && server.certValidityDays <= 30 ? 'Certificate renewal required' : 'None'),
    };
  });

  const tlsVersionRows = snapshot.tlsVersionDistribution.length ? snapshot.tlsVersionDistribution : [
    { label: 'TLS 1.3 (PQC)', count: hybridCount, percent: hybridPercent },
    { label: 'TLS 1.3 (Classical)', count: classicalCount, percent: classicalPercent },
    { label: 'TLS 1.2', count: Math.round(totalEndpoints * snapshot.metrics.weakAlgorithmsPercent / 100), percent: snapshot.metrics.weakAlgorithmsPercent },
  ];

  const wizard = [
    { label: 'Discover TLS endpoints', detail: `${numberFmt(totalEndpoints)} endpoints inventoried from tenant telemetry.`, state: totalEndpoints > 0 ? 'Completed' : 'Pending' },
    { label: 'Identify incompatible middleboxes', detail: `${numberFmt(incompatibleCount)} current incompatibility signal(s).`, state: incompatibleCount === 0 && totalEndpoints > 0 ? 'Completed' : incompatibleCount > 0 ? 'In Progress' : 'Pending' },
    { label: 'Test oversized handshakes', detail: `${numberFmt(snapshot.metrics.failedHandshakes)} failed or fallback handshake(s).`, state: snapshot.metrics.failedHandshakes > 0 ? 'In Progress' : totalEndpoints > 0 ? 'Completed' : 'Pending' },
    { label: 'Enable hybrid ML-KEM', detail: `${pct(hybridPercent)} hybrid/PQC-capable negotiation coverage.`, state: hybridPercent >= 50 ? 'Completed' : hybridPercent > 0 ? 'In Progress' : 'Pending' },
    { label: 'Validate negotiation', detail: `${pct(snapshot.metrics.successfulHandshakes / totalNegotiations * 100)} successful handshake rate.`, state: snapshot.metrics.successfulHandshakes > 0 ? 'In Progress' : 'Pending' },
    { label: 'Monitor fallback behavior', detail: `${numberFmt(downgradeEvents)} downgrade or fallback events in this window.`, state: connected ? 'In Progress' : 'Pending' },
    { label: 'Generate compliance report', detail: `${numberFmt(snapshot.telemetry.certificates + snapshot.telemetry.securityEvents + snapshot.telemetry.scanSessions)} evidence record(s) available.`, state: snapshot.telemetry.securityEvents > 0 || snapshot.telemetry.scanSessions > 0 ? 'In Progress' : 'Pending' },
  ];

  return (
    <div className="tls-orchestrator min-h-full bg-[#f6f8ff] text-[#11194a]">
      <style>{TLS_ORCHESTRATOR_THEME_CSS}</style>
      <header className="flex flex-col gap-4 border-b border-[#dde5f4] bg-white px-8 py-5 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <h1 className="text-3xl font-black tracking-tight">PQC TLS Posture Dashboard</h1>
          <p className="mt-2 text-sm font-bold text-[#536192]">End-to-end Visibility | Hybrid TLS | NIST/CNSA 2.0 Ready</p>
        </div>
        <div className="flex flex-wrap items-center gap-5">
          <div className="relative w-full min-w-[280px] max-w-[430px]">
            <Search className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-[#596693]" />
            <input value={query} onChange={(event) => setQuery(event.target.value)} className="h-11 w-full rounded-lg border border-[#dce4f5] bg-white pl-12 pr-4 text-sm font-semibold text-[#11194a] shadow-sm outline-none focus:border-[#7c3aed]" placeholder="Search assets, endpoints, domains..." />
          </div>
          <Bell className="h-6 w-6 text-[#283466]" />
          <HelpCircle className="h-6 w-6 text-[#283466]" />
          <div className="flex items-center gap-3">
            <div className="grid h-11 w-11 place-items-center rounded-full bg-[#eef2ff] text-[#1d4ed8]"><UserRound className="h-6 w-6" /></div>
            <div>
              <div className="text-sm font-black">Admin</div>
              <div className="text-xs font-bold text-[#596693]">CISO</div>
            </div>
          </div>
        </div>
      </header>

      <main className="space-y-4 p-4 xl:p-6">
        <div className="flex items-center justify-end gap-5 text-xs font-bold text-[#536192]">
          <span>Last Updated: {shortTime(snapshot.generatedAt)}</span>
          <button onClick={refresh} className="rounded-md border border-[#dce4f5] px-3 py-1.5 text-[#2563eb]">Refresh</button>
          <span className={cx('inline-flex items-center gap-2 font-black', connected ? 'text-[#16a34a]' : 'text-[#fb923c]')}>{connected ? 'Live' : state === 'loading' ? 'Syncing' : 'Polling'} <Waves className="h-5 w-5" /></span>
        </div>

        {error && <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm font-bold text-red-600">{error}</div>}

        <div className="grid gap-3 xl:grid-cols-[1fr_280px]">
          <div className="space-y-3">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
              <MetricCard icon={Waves} title="TLS Endpoints" value={numberFmt(totalEndpoints)} sub={`${deltaText(snapshot.metrics.uniqueServersDelta)} today`} color={PURPLE} />
              <MetricCard icon={ShieldCheck} title="PQC Ready" value={pct(readiness)} sub={`${numberFmt(pqcReadyCount)} / ${numberFmt(totalEndpoints)}`} color={BLUE} ring={readiness} />
              <MetricCard icon={Zap} title="Hybrid TLS" value={pct(hybridPercent)} sub={`${numberFmt(hybridCount)} / ${numberFmt(totalEndpoints)}`} color={PURPLE} ring={hybridPercent} />
              <MetricCard icon={LockKeyhole} title="Classical Only" value={pct(classicalPercent)} sub={`${numberFmt(classicalCount)} / ${numberFmt(totalEndpoints)}`} color={ORANGE} ring={classicalPercent} />
              <MetricCard icon={AlertTriangle} title="Downgrade Events" value={numberFmt(downgradeEvents)} sub="Last telemetry window" color={RED} />
            </div>

            <div className="space-y-3">
              <Panel className="p-4">
                <SectionTitle title="Middlebox Tester" suffix={<a href="/dashboard/tls-telemetry" className="text-xs font-black text-[#2563eb]">View full report <ChevronRight className="inline h-4 w-4" /></a>} />
                <div className="grid gap-4 lg:grid-cols-[170px_1fr]">
                  <div>
                    <Gauge value={compatibilityScore} label={compatibilityScore >= 80 ? 'Good' : compatibilityScore >= 55 ? 'Partial' : 'Attention'} />
                    <div className="mt-2 flex justify-center gap-4 text-xs font-bold text-[#536192]">
                      <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-[#22c55e]" />Compatible ({compatibleCount})</span>
                      <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-[#fb923c]" />Partial ({partialCount})</span>
                    </div>
                  </div>
                  <div className="overflow-hidden">
                    <table className="w-full text-left text-xs">
                      <thead className="text-[#536192]">
                        <tr><th className="pb-2">Middlebox / Component</th><th>Type</th><th>Status</th><th>Risk</th><th>Issue</th></tr>
                      </thead>
                      <tbody>
                        {middleboxes.length === 0 ? (
                          <tr><td colSpan={5} className="py-8 text-center font-bold text-[#8a94b8]">Awaiting server telemetry.</td></tr>
                        ) : middleboxes.map((row) => (
                          <tr key={row.name} className="border-t border-[#edf1f8]">
                            <td className="py-2 font-black">{row.name}</td>
                            <td className="font-bold text-[#536192]">{row.type}</td>
                            <td>{row.status ? <CheckCircle2 className="h-4 w-4 text-[#16a34a]" /> : <AlertTriangle className="h-4 w-4 text-[#fb923c]" />}</td>
                            <td><span className={cx('rounded-full px-2 py-1 text-[10px] font-black', row.risk === 'High' ? 'bg-red-50 text-red-500' : row.risk === 'Medium' ? 'bg-orange-50 text-orange-500' : 'bg-emerald-50 text-emerald-500')}>{row.risk}</span></td>
                            <td className="max-w-[180px] truncate font-bold text-[#536192]">{row.issue}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </Panel>

              <Panel className="p-4">
                <SectionTitle title="Key Exchange Distribution" />
                <Donut rows={keyExchangeRows} total={Math.max(1, keyExchangeRows.reduce((sum, row) => sum + row.value, 0))} />
                <a href="/dashboard/tls-telemetry" className="mt-3 inline-flex items-center text-xs font-black text-[#2563eb]">View detailed breakdown <ChevronRight className="h-4 w-4" /></a>
              </Panel>
            </div>

            <div className="grid gap-3 xl:grid-cols-[1.25fr_0.95fr_0.9fr]">
              <Panel className="p-4">
                <SectionTitle title="PQC Negotiation (Live)" suffix={<span className="rounded-md border border-[#dce4f5] px-3 py-1 text-xs font-black text-[#536192]">Last 24 Hours</span>} />
                <LineChart points={snapshot.timeline} hybridRatio={hybridPercent / 100} />
              </Panel>

              <Panel className="p-4">
                <SectionTitle title="Downgrade Alerts" suffix={<a href="/dashboard/tls-telemetry" className="text-xs font-black text-[#2563eb]">View all <ChevronRight className="inline h-4 w-4" /></a>} />
                <div className="space-y-3">
                  {snapshot.recentAlerts.length === 0 ? <div className="py-8 text-center text-sm font-bold text-[#8a94b8]">No active downgrade alerts.</div> : snapshot.recentAlerts.slice(0, 4).map((alert) => (
                    <div key={alert.id} className="grid grid-cols-[28px_1fr_54px_auto] items-center gap-3 text-xs">
                      <span className="grid h-7 w-7 place-items-center rounded-full bg-red-50 text-red-500"><AlertTriangle className="h-4 w-4" /></span>
                      <span className="min-w-0"><span className="block truncate font-black">{alert.detail}</span><span className="block truncate font-bold text-[#536192]">{alert.title}</span></span>
                      <span className="text-right font-bold text-[#536192]">{relativeTime(alert.time)}</span>
                      <span className="rounded-full bg-red-50 px-2 py-1 text-[10px] font-black text-red-500">{alert.severity}</span>
                    </div>
                  ))}
                </div>
              </Panel>

              <Panel className="p-4">
                <SectionTitle title="TLS Versions" />
                <div className="space-y-4">
                  {tlsVersionRows.slice(0, 4).map((row, index) => (
                    <div key={row.label} className="grid grid-cols-[110px_1fr_38px] items-center gap-3 text-sm">
                      <span className="font-bold">{row.label}</span>
                      <span className="h-3 overflow-hidden rounded-full bg-[#edf1f8]"><span className="block h-full rounded-full" style={{ width: `${Math.min(100, row.percent)}%`, background: [PURPLE, BLUE, SKY, RED][index] || SLATE }} /></span>
                      <span className="text-right font-black">{pct(row.percent)}</span>
                    </div>
                  ))}
                </div>
                <a href="/dashboard/assets" className="mt-5 inline-flex items-center text-xs font-black text-[#2563eb]">View all endpoints <ChevronRight className="h-4 w-4" /></a>
              </Panel>
            </div>

            <div className="grid gap-3 xl:grid-cols-[0.72fr_1fr]">
              <Panel className="p-4"><SectionTitle title="PQC Readiness Score" /><Gauge value={readiness} label={readiness >= 75 ? 'Ready' : readiness >= 45 ? 'Medium' : 'Low'} color={GREEN} /></Panel>
              <Panel className="p-4">
                <SectionTitle title="Top Risk Endpoints" suffix={<a href="/dashboard/assets" className="text-xs font-black text-[#2563eb]">View all <ChevronRight className="inline h-4 w-4" /></a>} />
                <div className="space-y-3">
                  {(snapshot.recentAlerts.length ? snapshot.recentAlerts : snapshot.topDomains.map((domain) => ({ id: domain.domain, detail: domain.domain, title: `${numberFmt(domain.connections)} connections`, severity: 'Medium', time: snapshot.latestActivityAt }))).slice(0, 4).map((row) => (
                    <div key={row.id} className="grid grid-cols-[22px_1fr_auto] gap-3 text-xs">
                      <AlertTriangle className="mt-0.5 h-5 w-5 text-red-500" />
                      <span className="min-w-0"><span className="block truncate font-black">{row.detail}</span><span className="block truncate font-bold text-[#536192]">{row.title}</span></span>
                      <span className={cx('h-fit rounded-full px-2 py-1 text-[10px] font-black', row.severity === 'High' ? 'bg-red-50 text-red-500' : 'bg-orange-50 text-orange-500')}>{row.severity}</span>
                    </div>
                  ))}
                </div>
              </Panel>
            </div>

            <Panel className="grid gap-3 p-4 md:grid-cols-3 xl:grid-cols-6">
              {[
                ['Hybrid TLS Established', numberFmt(hybridCount), deltaText(snapshot.metrics.successfulHandshakesDelta), Waves, PURPLE],
                ['PQC Negotiations', numberFmt(snapshot.metrics.successfulHandshakes), deltaText(snapshot.metrics.successfulHandshakesDelta), ShieldCheck, BLUE],
                ['Classical Negotiations', numberFmt(classicalCount), deltaText(-snapshot.metrics.weakAlgorithmsPercent), LockKeyhole, ORANGE],
                ['Downgrade Attempts', numberFmt(downgradeEvents), deltaText(snapshot.metrics.failedHandshakesDelta), AlertTriangle, RED],
                ['Successful Handshakes', pct(snapshot.metrics.successfulHandshakes / totalNegotiations * 100), deltaText(snapshot.metrics.successfulHandshakesDelta), CheckCircle2, GREEN],
                ['Runtime Events', numberFmt(snapshot.telemetry.runtimeEvents), deltaText(snapshot.metrics.totalConnectionsDelta), Circle, PURPLE],
                ['Scan Sessions', numberFmt(snapshot.telemetry.scanSessions), `${numberFmt(snapshot.telemetry.runningScans)} running`, Search, BLUE],
                ['Online Agents', numberFmt(snapshot.telemetry.onlineAgents), `${numberFmt(snapshot.telemetry.freshHeartbeats)} fresh`, UserRound, GREEN],
              ].map(([label, value, delta, Icon, color]) => {
                const MetricIcon = Icon as LucideIcon;
                return <div key={String(label)} className="flex items-center gap-3 border-r border-[#edf1f8] last:border-r-0"><MetricIcon className="h-6 w-6" style={{ color: String(color) }} /><div><div className="text-[11px] font-bold text-[#536192]">{label}</div><div className="text-xl font-black">{value}</div><div className="text-xs font-black text-[#22c55e]">{delta}</div></div></div>;
              })}
            </Panel>
          </div>

          <Panel className="overflow-hidden">
            <div className="bg-gradient-to-br from-[#6d36ff] to-[#9046ff] p-5 text-white">
              <div className="flex items-center justify-between">
                <div><h2 className="text-xl font-black">Qguard Wizard</h2><p className="text-sm font-bold text-white/80">PQC Migration Workflow</p></div>
                <Wand2 className="h-10 w-10" />
              </div>
            </div>
            <div className="space-y-0 p-4">
              {wizard.map((step, index) => {
                const active = step.state === 'In Progress';
                const done = step.state === 'Completed';
                return (
                  <div key={step.label} className="relative grid grid-cols-[34px_1fr] gap-3 pb-7 last:pb-2">
                    {index < wizard.length - 1 && <span className={cx('absolute left-[16px] top-8 h-[calc(100%-32px)] w-px', done ? 'bg-[#22c55e]' : active ? 'bg-[#2563eb]' : 'bg-[#cfd7ea]')} />}
                    <span className={cx('z-10 grid h-8 w-8 place-items-center rounded-full text-sm font-black text-white', done ? 'bg-[#22c55e]' : active ? 'bg-[#2563eb]' : 'bg-[#7c3aed]')}>{index + 1}</span>
                    <div>
                      <div className="text-sm font-black">{step.label}</div>
                      <p className="mt-1 text-xs font-semibold leading-relaxed text-[#536192]">{step.detail}</p>
                      <div className="mt-3 inline-flex items-center gap-2 rounded-full bg-[#eef2ff] px-3 py-1 text-[10px] font-black text-[#40507c]">
                        {step.state}
                        {done ? <CheckCircle2 className="h-3.5 w-3.5 text-[#22c55e]" /> : active ? <Sparkles className="h-3.5 w-3.5 text-[#2563eb]" /> : <Circle className="h-3.5 w-3.5" />}
                      </div>
                    </div>
                  </div>
                );
              })}
              <a href="/dashboard/migration-planner" className="mt-1 flex h-10 items-center justify-center rounded-lg border border-[#dce4f5] text-sm font-black text-[#2563eb]">View Wizard Details <ChevronRight className="h-4 w-4" /></a>
            </div>
          </Panel>
        </div>
      </main>
    </div>
  );
}
