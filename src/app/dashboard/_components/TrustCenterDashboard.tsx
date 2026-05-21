'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  BarChart3,
  CheckCircle2,
  ChevronRight,
  CircleGauge,
  Cpu,
  Download,
  FileText,
  Fingerprint,
  KeyRound,
  Laptop,
  LineChart,
  Lock,
  MonitorCheck,
  Network,
  PieChart,
  Radar,
  RefreshCw,
  ScanSearch,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  UserCheck,
  Workflow,
  XCircle,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import { cn } from '@/lib/utils';

type TrustMode = 'continuous' | 'identity' | 'device' | 'analytics' | 'zero';
type LoadState = 'loading' | 'success' | 'error';

type TimelinePoint = {
  label: string;
  validations: number;
  trusted: number;
  review: number;
  highRisk: number;
};

type DomainRow = {
  label: string;
  count: number;
  percent: number;
  trusted: number;
  review: number;
  riskScore: number;
  latestSeen: string | null;
};

type SubjectRow = {
  subject: string;
  type: string;
  signals: number;
  trusted: number;
  riskScore: number;
  latestSeen: string | null;
};

type ControlRow = {
  id: string;
  label: string;
  score: number;
  passed: boolean;
  evidence: number;
  status: string;
};

type DistributionRow = {
  label: string;
  count: number;
  percent: number;
};

type AlertRow = {
  id: string;
  title: string;
  detail: string;
  severity: string;
  timestamp: string | null;
  source: string;
  domain: string;
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
  domain: string;
  title: string;
  subject: string;
  subjectType: string;
  status: string;
  severity: string;
  score: number;
  trusted: boolean;
  pqcReady: boolean;
  encrypted: boolean;
  timestamp: string | null;
  source: string;
  detail: string;
};

type TrustSnapshot = {
  generatedAt: string | null;
  latestActivityAt: string | null;
  metrics: {
    trustScore: number;
    trustScoreDelta: number;
    validations: number;
    validationsDelta: number;
    validationRate: number;
    trustedSignals: number;
    reviewSignals: number;
    highRiskSignals: number;
    assetsCovered: number;
    identities: number;
    devices: number;
    activeSessions: number;
    trustedDevices: number;
    mfaEnforced: boolean;
    pqcReadyPercent: number;
    encryptedPercent: number;
    staleSignals: number;
    zeroTrustPassRate: number;
    activeSources: number;
  };
  timeline: TimelinePoint[];
  domainRows: DomainRow[];
  subjectRows: SubjectRow[];
  zeroControls: ControlRow[];
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
    scanResults: number;
    cryptoInventory: number;
    cryptoExposures: number;
    certificates: number;
    generatedKeys: number;
    scannerAgents: number;
    connectors: number;
    agentHeartbeats: number;
    profileRecords: number;
    securitySettings: number;
    userDevices: number;
    userSessions: number;
    userSecurityEvents: number;
    authEvents: number;
    vaultAuditLogs: number;
    migrationJobs: number;
    complianceEvidence: number;
    eventPipelineStatus: string;
    latestRuntimeEventAt: string | null;
  };
};

const EMPTY_SNAPSHOT: TrustSnapshot = {
  generatedAt: null,
  latestActivityAt: null,
  metrics: {
    trustScore: 0,
    trustScoreDelta: 0,
    validations: 0,
    validationsDelta: 0,
    validationRate: 0,
    trustedSignals: 0,
    reviewSignals: 0,
    highRiskSignals: 0,
    assetsCovered: 0,
    identities: 0,
    devices: 0,
    activeSessions: 0,
    trustedDevices: 0,
    mfaEnforced: false,
    pqcReadyPercent: 0,
    encryptedPercent: 0,
    staleSignals: 0,
    zeroTrustPassRate: 0,
    activeSources: 0,
  },
  timeline: [],
  domainRows: [],
  subjectRows: [],
  zeroControls: [],
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
    scanResults: 0,
    cryptoInventory: 0,
    cryptoExposures: 0,
    certificates: 0,
    generatedKeys: 0,
    scannerAgents: 0,
    connectors: 0,
    agentHeartbeats: 0,
    profileRecords: 0,
    securitySettings: 0,
    userDevices: 0,
    userSessions: 0,
    userSecurityEvents: 0,
    authEvents: 0,
    vaultAuditLogs: 0,
    migrationJobs: 0,
    complianceEvidence: 0,
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

const MODE_COPY: Record<TrustMode, {
  segment: string;
  streamPrefix: string;
  title: string;
  subtitle: string;
  Icon: LucideIcon;
  primaryHref: string;
  primaryLabel: string;
}> = {
  continuous: {
    segment: 'continuous-trust',
    streamPrefix: 'continuous-trust',
    title: 'Continuous Trust Validation',
    subtitle: 'Ongoing trust-chain validation, runtime drift checks, and cryptographic assurance across tenant assets.',
    Icon: CheckCircle2,
    primaryHref: '/dashboard/telemetry-correlation',
    primaryLabel: 'Correlation',
  },
  identity: {
    segment: 'identity-trust',
    streamPrefix: 'identity-trust',
    title: 'Identity Trust',
    subtitle: 'Operator identity, sessions, MFA posture, trusted devices, and signature/key assurance in one cockpit.',
    Icon: UserCheck,
    primaryHref: '/dashboard/settings',
    primaryLabel: 'Security Settings',
  },
  device: {
    segment: 'device-trust',
    streamPrefix: 'device-trust',
    title: 'Device Trust',
    subtitle: 'Endpoint trust, collector health, trusted-device posture, and asset evidence for every tenant-controlled device.',
    Icon: MonitorCheck,
    primaryHref: '/dashboard/scanner',
    primaryLabel: 'Agent Scanners',
  },
  analytics: {
    segment: 'trust-analytics',
    streamPrefix: 'trust-analytics',
    title: 'Trust Analytics',
    subtitle: 'Portfolio-level trust trends, domain risk, evidence coverage, and realtime assurance analytics.',
    Icon: PieChart,
    primaryHref: '/dashboard/quantum-risk-scoring',
    primaryLabel: 'Risk Scoring',
  },
  zero: {
    segment: 'zero-trust',
    streamPrefix: 'zero-trust',
    title: 'Zero Trust Validation',
    subtitle: 'Control-plane validation for identity, device, crypto, telemetry, vault, and compliance trust gates.',
    Icon: ShieldCheck,
    primaryHref: '/dashboard/crypto-policies',
    primaryLabel: 'Policies',
  },
};

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
  if (!value) return 'Awaiting trust telemetry';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Awaiting trust telemetry';
  return date.toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function severityColor(value: string | number) {
  const lower = String(value).toLowerCase();
  if (typeof value === 'number') {
    if (value >= 75) return RED;
    if (value >= 45) return GOLD;
    return GREEN;
  }
  if (lower.includes('critical')) return RED;
  if (lower.includes('high')) return ORANGE;
  if (lower.includes('medium') || lower.includes('warning') || lower.includes('partial')) return GOLD;
  if (lower.includes('failed')) return RED;
  if (lower.includes('passed') || lower.includes('low')) return GREEN;
  return BLUE;
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

function useTrustDashboard(mode: TrustMode) {
  const config = MODE_COPY[mode];
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<TrustSnapshot>(EMPTY_SNAPSHOT);
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
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
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
      'certificates',
      'generated_keys',
      'scanner_agents',
      'connector_accounts',
      'agent_heartbeats',
      'profiles',
      'user_security_settings',
      'user_devices',
      'user_sessions',
      'user_security_events',
      'auth_events',
      'vault_audit_logs',
      'migration_jobs',
      'compliance_evidence',
    ];
    const channels = tables.map((table) => supabase
      .channel(`${config.segment}-${table}`)
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table, filter: table === 'profiles' ? `id=eq.${user.id}` : `user_id=eq.${user.id}` },
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

function ScoreRing({ value, label, size = 'lg' }: { value: number; label: string; size?: 'md' | 'lg' }) {
  const safe = Math.max(0, Math.min(100, Math.round(value || 0)));
  const color = safe >= 75 ? GREEN : safe >= 45 ? GOLD : RED;
  const diameter = size === 'lg' ? 'h-48 w-48' : 'h-32 w-32';
  const inner = size === 'lg' ? 'h-36 w-36' : 'h-24 w-24';
  return (
    <div className={cn('relative grid place-items-center rounded-full', diameter)} style={{ background: `conic-gradient(${color} ${safe}%, rgba(255,255,255,0.08) 0)` }}>
      <div className={cn('grid place-items-center rounded-full border border-white/10 bg-[#07101D] text-center shadow-[inset_0_0_28px_rgba(0,0,0,0.45)]', inner)}>
        <div>
          <div className={cn('font-semibold text-white', size === 'lg' ? 'text-5xl' : 'text-3xl')}>{integerFmt(safe)}</div>
          <div className="mt-1 text-[10px] uppercase tracking-[0.12em] text-white/52">{label}</div>
        </div>
      </div>
    </div>
  );
}

function MetricTile({ icon: Icon, label, value, detail, color = BLUE }: { icon: LucideIcon; label: string; value: string; detail: string; color?: string }) {
  return (
    <Panel className="p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[10px] font-black uppercase tracking-[0.08em] text-white/52">{label}</div>
          <div className="mt-3 text-2xl font-semibold text-white">{value}</div>
          <div className="mt-1 text-[10px] text-white/42">{detail}</div>
        </div>
        <span className="grid h-9 w-9 place-items-center rounded-md border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
          <Icon className="h-5 w-5" />
        </span>
      </div>
    </Panel>
  );
}

function TimelineChart({ points }: { points: TimelinePoint[] }) {
  const width = 760;
  const height = 220;
  const series = [
    { key: 'validations', label: 'Validations', color: BLUE },
    { key: 'trusted', label: 'Trusted', color: GREEN },
    { key: 'review', label: 'Review', color: GOLD },
    { key: 'highRisk', label: 'High Risk', color: RED },
  ] as const;
  const hasData = points.some((point) => point.validations || point.trusted || point.review || point.highRisk);
  if (!points.length || !hasData) return <EmptyState label="Awaiting trust validation telemetry." />;
  const max = Math.max(1, ...points.flatMap((point) => series.map((item) => point[item.key])));
  const xFor = (index: number) => 34 + (points.length <= 1 ? 0 : (index / (points.length - 1)) * (width - 68));
  const yFor = (value: number) => 20 + 158 - (value / max) * 158;

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
      <svg className="h-[220px] w-full" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Trust validation timeline">
        {[0, 25, 50, 75, 100].map((tick) => {
          const y = 20 + (100 - tick) / 100 * 158;
          return (
            <g key={tick}>
              <line x1="34" x2="726" y1={y} y2={y} stroke="rgba(255,255,255,0.06)" />
              <text x="3" y={y + 4} fill="rgba(255,255,255,0.45)" fontSize="10">{tick === 0 ? '0' : `${tick}%`}</text>
            </g>
          );
        })}
        {series.map((item) => {
          const d = points.map((point, index) => `${index === 0 ? 'M' : 'L'} ${xFor(index).toFixed(1)} ${yFor(point[item.key]).toFixed(1)}`).join(' ');
          return (
            <g key={item.label}>
              <path d={d} fill="none" stroke={item.color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
              {points.map((point, index) => <circle key={`${item.label}-${point.label}`} cx={xFor(index)} cy={yFor(point[item.key])} r="3" fill={item.color} />)}
            </g>
          );
        })}
        {points.map((point, index) => (
          <text key={point.label} x={xFor(index)} y="210" textAnchor="middle" fill="rgba(255,255,255,0.5)" fontSize="10">{point.label}</text>
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
        <div key={row.label} className="grid grid-cols-[124px_1fr_90px] items-center gap-3 text-xs">
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

function DomainRows({ rows, title = 'Trust Domains' }: { rows: DomainRow[]; title?: string }) {
  if (!rows.length) return <EmptyState label="No trust-domain evidence is available yet." />;
  return (
    <div className="space-y-2">
      <div className="grid grid-cols-[1fr_70px_70px_70px_70px] gap-3 border-b border-white/8 pb-2 text-[10px] text-white/42">
        <span>{title}</span>
        <span className="text-right">Signals</span>
        <span className="text-right">Trusted</span>
        <span className="text-right">Review</span>
        <span className="text-right">Risk</span>
      </div>
      {rows.map((row) => (
        <div key={row.label} className="grid grid-cols-[1fr_70px_70px_70px_70px] items-center gap-3 border-b border-white/5 py-2 text-xs">
          <span className="truncate text-white/78">{row.label}</span>
          <span className="text-right font-mono text-white/72">{compactFmt(row.count)}</span>
          <span className="text-right font-mono text-emerald-300">{compactFmt(row.trusted)}</span>
          <span className="text-right font-mono text-amber-300">{compactFmt(row.review)}</span>
          <span className="text-right font-mono" style={{ color: severityColor(row.riskScore) }}>{integerFmt(row.riskScore)}</span>
        </div>
      ))}
    </div>
  );
}

function SubjectTable({ rows, empty = 'No trust subjects are available yet.' }: { rows: SubjectRow[]; empty?: string }) {
  if (!rows.length) return <EmptyState label={empty} />;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-[720px] w-full text-left text-xs">
        <thead>
          <tr className="border-b border-white/8 text-[10px] text-white/42">
            <th className="pb-3 font-medium">Subject</th>
            <th className="pb-3 font-medium">Type</th>
            <th className="pb-3 text-right font-medium">Signals</th>
            <th className="pb-3 text-right font-medium">Trusted</th>
            <th className="pb-3 text-right font-medium">Risk</th>
            <th className="pb-3 text-right font-medium">Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={`${row.subject}-${row.type}`} className="border-b border-white/5 text-white/72">
              <td className="max-w-[220px] truncate py-3 font-semibold text-white/86">{row.subject}</td>
              <td className="max-w-[140px] truncate py-3 text-white/55">{row.type}</td>
              <td className="py-3 text-right font-mono">{compactFmt(row.signals)}</td>
              <td className="py-3 text-right font-mono text-emerald-300">{compactFmt(row.trusted)}</td>
              <td className="py-3 text-right font-mono" style={{ color: severityColor(row.riskScore) }}>{integerFmt(row.riskScore)}</td>
              <td className="py-3 text-right text-white/45">{shortTime(row.latestSeen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AlertList({ rows }: { rows: AlertRow[] }) {
  if (!rows.length) return <EmptyState label="No active trust alerts for this tenant." />;
  return (
    <div className="space-y-3">
      {rows.map((row) => {
        const color = severityColor(row.severity);
        return (
          <div key={row.id} className="grid grid-cols-[34px_1fr_60px_auto] items-center gap-3 border-b border-white/5 pb-3 text-xs">
            <span className="grid h-8 w-8 place-items-center rounded-full border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
              <ShieldAlert className="h-4 w-4" style={{ color }} />
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
  if (!rows.length) return <EmptyState label="No trust recommendations are active right now." />;
  return (
    <div className="space-y-3">
      {rows.map((row) => {
        const color = severityColor(row.impact);
        return (
          <a key={row.id} href={row.actionHref} className="grid grid-cols-[32px_1fr_auto] items-center gap-3 rounded-md border border-white/6 bg-white/[0.025] p-3 transition hover:border-gold/45 hover:bg-gold/8">
            <span className="grid h-8 w-8 place-items-center rounded-md border" style={{ borderColor: `${color}45`, backgroundColor: `${color}12` }}>
              <Zap className="h-4 w-4" style={{ color }} />
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

function ActivityFeed({ rows }: { rows: ActivityRow[] }) {
  if (!rows.length) return <EmptyState label="No trust activity has been captured yet." />;
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

function InventoryTable({ rows }: { rows: InventoryRow[] }) {
  if (!rows.length) return <EmptyState label="No trust inventory is available for this tenant yet." />;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-[920px] w-full text-left text-xs">
        <thead>
          <tr className="border-b border-white/8 text-[10px] text-white/42">
            <th className="pb-3 font-medium">Signal</th>
            <th className="pb-3 font-medium">Subject</th>
            <th className="pb-3 font-medium">Domain</th>
            <th className="pb-3 text-center font-medium">PQC</th>
            <th className="pb-3 text-center font-medium">Encrypted</th>
            <th className="pb-3 text-right font-medium">Score</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const color = severityColor(row.score);
            return (
              <tr key={row.id} className="border-b border-white/5 text-white/72">
                <td className="max-w-[240px] py-3">
                  <span className="block truncate font-semibold text-white/86">{row.title}</span>
                  <span className="block truncate text-[10px] text-white/42">{row.source} - {shortTime(row.timestamp)}</span>
                </td>
                <td className="max-w-[210px] py-3">
                  <span className="block truncate">{row.subject}</span>
                  <span className="block truncate text-[10px] text-white/42">{row.subjectType}</span>
                </td>
                <td className="max-w-[170px] truncate py-3 text-white/62">{row.domain}</td>
                <td className="py-3 text-center">
                  <span className={cn('rounded-md border px-2 py-1 text-[10px] font-black', row.pqcReady ? 'border-emerald-400/35 bg-emerald-400/10 text-emerald-300' : 'border-white/10 bg-white/5 text-white/40')}>{row.pqcReady ? 'Ready' : 'Pending'}</span>
                </td>
                <td className="py-3 text-center">
                  <span className={cn('rounded-md border px-2 py-1 text-[10px] font-black', row.encrypted ? 'border-emerald-400/35 bg-emerald-400/10 text-emerald-300' : 'border-red-400/35 bg-red-400/10 text-red-300')}>{row.encrypted ? 'Yes' : 'No'}</span>
                </td>
                <td className="py-3 text-right">
                  <span className="rounded-md border px-2 py-1 text-[10px] font-black" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}10` }}>{integerFmt(row.score)}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ControlGrid({ rows }: { rows: ControlRow[] }) {
  if (!rows.length) return <EmptyState label="No zero-trust controls have evidence yet." />;
  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
      {rows.map((row) => {
        const color = severityColor(row.status);
        const Icon = row.status === 'passed' ? CheckCircle2 : row.status === 'failed' ? XCircle : ShieldAlert;
        return (
          <div key={row.id} className="rounded-md border border-white/8 bg-white/[0.025] p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-xs font-bold text-white/84">{row.label}</div>
                <div className="mt-1 text-[10px] uppercase tracking-[0.08em] text-white/42">{row.evidence} evidence signals</div>
              </div>
              <Icon className="h-5 w-5" style={{ color }} />
            </div>
            <div className="mt-4 flex items-center gap-3">
              <span className="h-2 flex-1 overflow-hidden rounded-full bg-white/6">
                <span className="block h-full rounded-full" style={{ width: `${Math.min(100, row.score)}%`, backgroundColor: color }} />
              </span>
              <span className="font-mono text-xs text-white/82">{percentFmt(row.score)}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Pipeline({ snapshot, sseConnected }: { snapshot: TrustSnapshot; sseConnected: boolean }) {
  const rows = [
    ['Runtime', snapshot.telemetry.runtimeEvents, Activity, GREEN],
    ['Scanner', snapshot.telemetry.scannerEvidence + snapshot.telemetry.scannerAlerts, ScanSearch, PURPLE],
    ['Identity', snapshot.telemetry.userSessions + snapshot.telemetry.userSecurityEvents + snapshot.telemetry.authEvents, UserCheck, GOLD],
    ['Devices', snapshot.telemetry.userDevices + snapshot.telemetry.scannerAgents, Laptop, CYAN],
    ['Crypto', snapshot.telemetry.cryptoInventory + snapshot.telemetry.cryptoExposures, KeyRound, BLUE],
    ['Compliance', snapshot.telemetry.complianceEvidence, FileText, TEAL],
  ] as const;
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
        {rows.map(([label, value, Icon, color]) => (
          <div key={label} className="flex items-center justify-between gap-3 rounded-md border border-white/6 bg-white/[0.025] px-3 py-2">
            <span className="flex min-w-0 items-center gap-2">
              <Icon className="h-4 w-4 shrink-0" style={{ color }} />
              <span className="truncate text-xs text-white/62">{label}</span>
            </span>
            <span className="font-mono text-xs text-white/82">{compactFmt(value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Header({ mode, snapshot, state, sseConnected, refresh }: { mode: TrustMode; snapshot: TrustSnapshot; state: LoadState; sseConnected: boolean; refresh: () => void }) {
  const config = MODE_COPY[mode];
  const Icon = config.Icon;
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
    <header className="flex flex-col gap-4 border-b border-gold/10 pb-4 xl:flex-row xl:items-start xl:justify-between">
      <div>
        <div className="flex items-center gap-4">
          <Icon className="h-10 w-10 text-gold drop-shadow-[0_0_16px_rgba(251,191,36,0.45)]" />
          <h1 className="font-mono text-3xl font-black uppercase tracking-[0.14em] text-gold drop-shadow-[0_0_16px_rgba(251,191,36,0.35)] md:text-4xl">
            {config.title}
          </h1>
        </div>
        <p className="mt-4 font-mono text-sm tracking-[0.08em] text-gold/70 md:text-base">{config.subtitle}</p>
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

function ContinuousLayout({ snapshot, sseConnected }: { snapshot: TrustSnapshot; sseConnected: boolean }) {
  return (
    <>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-3">
          <SectionTitle>Validation Score</SectionTitle>
          <div className="grid place-items-center"><ScoreRing value={snapshot.metrics.trustScore} label="Trust" /></div>
          <div className="mt-5 grid grid-cols-2 gap-3 text-center text-xs">
            <div className="rounded-md border border-white/8 bg-white/[0.03] p-3"><div className="font-mono text-lg text-white">{signedPercent(snapshot.metrics.trustScoreDelta)}</div><div className="mt-1 text-white/42">7d delta</div></div>
            <div className="rounded-md border border-white/8 bg-white/[0.03] p-3"><div className="font-mono text-lg text-white">{percentFmt(snapshot.metrics.validationRate)}</div><div className="mt-1 text-white/42">pass rate</div></div>
          </div>
        </Panel>
        <Panel className="p-5 xl:col-span-6">
          <SectionTitle>Validation Timeline</SectionTitle>
          <TimelineChart points={snapshot.timeline} />
        </Panel>
        <Panel className="p-5 xl:col-span-3">
          <SectionTitle>Live Evidence Pipeline</SectionTitle>
          <Pipeline snapshot={snapshot} sseConnected={sseConnected} />
        </Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Validation Domains</SectionTitle><DomainRows rows={snapshot.domainRows.slice(0, 8)} title="Domain" /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Signals Requiring Review</SectionTitle><AlertList rows={snapshot.alerts.slice(0, 8)} /></Panel>
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Recommended Actions</SectionTitle><Recommendations rows={snapshot.recommendations} /></Panel>
      </section>
      <Panel className="p-5"><SectionTitle>Trust Validation Ledger</SectionTitle><InventoryTable rows={snapshot.inventory.slice(0, 12)} /></Panel>
    </>
  );
}

function IdentityLayout({ snapshot, sseConnected }: { snapshot: TrustSnapshot; sseConnected: boolean }) {
  return (
    <>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-4">
          <SectionTitle>Identity Assurance</SectionTitle>
          <div className="grid grid-cols-[150px_1fr] items-center gap-5">
            <ScoreRing value={snapshot.metrics.trustScore} label="Identity" size="md" />
            <div className="space-y-3 text-sm">
              <div className="flex justify-between border-b border-white/8 pb-2"><span className="text-white/45">MFA enforcement</span><span className={snapshot.metrics.mfaEnforced ? 'text-emerald-300' : 'text-amber-300'}>{snapshot.metrics.mfaEnforced ? 'Enabled' : 'Optional'}</span></div>
              <div className="flex justify-between border-b border-white/8 pb-2"><span className="text-white/45">Active sessions</span><span className="font-mono">{integerFmt(snapshot.metrics.activeSessions)}</span></div>
              <div className="flex justify-between"><span className="text-white/45">Identity signals</span><span className="font-mono">{integerFmt(snapshot.metrics.identities)}</span></div>
            </div>
          </div>
        </Panel>
        <MetricTile icon={Fingerprint} label="Trusted Signals" value={compactFmt(snapshot.metrics.trustedSignals)} detail="identity and access evidence" color={GREEN} />
        <MetricTile icon={Laptop} label="Trusted Devices" value={compactFmt(snapshot.metrics.trustedDevices)} detail="account device posture" color={CYAN} />
        <MetricTile icon={ShieldAlert} label="Review Queue" value={compactFmt(snapshot.metrics.reviewSignals)} detail="identity findings to inspect" color={GOLD} />
        <Panel className="p-5 xl:col-span-2">
          <SectionTitle>Sync</SectionTitle>
          <Pipeline snapshot={snapshot} sseConnected={sseConnected} />
        </Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Identity Subjects</SectionTitle><SubjectTable rows={snapshot.subjectRows.filter((row) => /identity|operator|session|security|device/i.test(`${row.type} ${row.subject}`)).slice(0, 10)} /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Identity Alerts</SectionTitle><AlertList rows={snapshot.alerts.filter((row) => /identity|device|session|profile|mfa/i.test(`${row.domain} ${row.detail}`)).slice(0, 10)} /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Identity Trust Domains</SectionTitle><DomainRows rows={snapshot.domainRows.filter((row) => /identity|device|vault/i.test(row.label)).slice(0, 8)} /></Panel>
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Status Mix</SectionTitle><Bars rows={snapshot.statusDistribution} empty="No identity status telemetry." /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Identity Activity</SectionTitle><ActivityFeed rows={snapshot.activity.filter((row) => /identity|session|device|profile|mfa/i.test(`${row.detail} ${row.title}`)).slice(0, 8)} /></Panel>
      </section>
    </>
  );
}

function DeviceLayout({ snapshot, sseConnected }: { snapshot: TrustSnapshot; sseConnected: boolean }) {
  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
        <MetricTile icon={MonitorCheck} label="Device Signals" value={compactFmt(snapshot.metrics.devices)} detail="devices, agents, endpoints" color={CYAN} />
        <MetricTile icon={BadgeCheck} label="Trusted Devices" value={compactFmt(snapshot.metrics.trustedDevices)} detail="trusted account devices" color={GREEN} />
        <MetricTile icon={Cpu} label="Active Sources" value={compactFmt(snapshot.metrics.activeSources)} detail="agents and connectors" color={BLUE} />
        <MetricTile icon={AlertTriangle} label="Device Review" value={compactFmt(snapshot.metrics.reviewSignals)} detail="posture checks requiring review" color={GOLD} />
        <Panel className="p-4"><div className="grid place-items-center"><ScoreRing value={snapshot.metrics.trustScore} label="Fleet" size="md" /></div></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Device And Collector Fleet</SectionTitle><SubjectTable rows={snapshot.subjectRows.filter((row) => /device|collector|agent|endpoint|asset|server|host/i.test(`${row.type} ${row.subject}`)).slice(0, 12)} /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Device Pipeline</SectionTitle><Pipeline snapshot={snapshot} sseConnected={sseConnected} /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Device Trust Domains</SectionTitle><DomainRows rows={snapshot.domainRows.filter((row) => /device|asset|scanner|continuous/i.test(row.label)).slice(0, 8)} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Device Alerts</SectionTitle><AlertList rows={snapshot.alerts.filter((row) => /device|agent|collector|asset|scanner/i.test(`${row.domain} ${row.detail}`)).slice(0, 8)} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Device Actions</SectionTitle><Recommendations rows={snapshot.recommendations} /></Panel>
      </section>
    </>
  );
}

function AnalyticsLayout({ snapshot, sseConnected }: { snapshot: TrustSnapshot; sseConnected: boolean }) {
  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
        <MetricTile icon={CircleGauge} label="Trust Score" value={integerFmt(snapshot.metrics.trustScore)} detail={`${signedPercent(snapshot.metrics.trustScoreDelta)} vs previous window`} color={TEAL} />
        <MetricTile icon={Activity} label="Validations" value={compactFmt(snapshot.metrics.validations)} detail={`${signedPercent(snapshot.metrics.validationsDelta)} validation delta`} color={BLUE} />
        <MetricTile icon={ShieldAlert} label="High Risk" value={compactFmt(snapshot.metrics.highRiskSignals)} detail="critical and high signals" color={RED} />
        <MetricTile icon={Sparkles} label="PQC Ready" value={percentFmt(snapshot.metrics.pqcReadyPercent)} detail="quantum-safe evidence" color={PURPLE} />
        <MetricTile icon={Lock} label="Encrypted" value={percentFmt(snapshot.metrics.encryptedPercent)} detail="encrypted trust evidence" color={GREEN} />
        <MetricTile icon={Network} label="Sources" value={compactFmt(snapshot.metrics.activeSources)} detail="agents and connectors" color={GOLD} />
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Trust Trend Analytics</SectionTitle><TimelineChart points={snapshot.timeline} /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Source Synchronization</SectionTitle><Pipeline snapshot={snapshot} sseConnected={sseConnected} /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Risk By Domain</SectionTitle><DomainRows rows={snapshot.domainRows.slice(0, 10)} /></Panel>
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Severity Mix</SectionTitle><Bars rows={snapshot.severityDistribution} empty="No severity distribution yet." /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Top Trust Subjects</SectionTitle><SubjectTable rows={snapshot.subjectRows.slice(0, 8)} /></Panel>
      </section>
    </>
  );
}

function ZeroTrustLayout({ snapshot, sseConnected }: { snapshot: TrustSnapshot; sseConnected: boolean }) {
  return (
    <>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-3">
          <SectionTitle>Zero Trust Pass Rate</SectionTitle>
          <div className="grid place-items-center"><ScoreRing value={snapshot.metrics.zeroTrustPassRate} label="Controls" /></div>
        </Panel>
        <Panel className="p-5 xl:col-span-6">
          <SectionTitle>Control Plane Gates</SectionTitle>
          <ControlGrid rows={snapshot.zeroControls} />
        </Panel>
        <Panel className="p-5 xl:col-span-3">
          <SectionTitle>Trust Streams</SectionTitle>
          <Pipeline snapshot={snapshot} sseConnected={sseConnected} />
        </Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Zero Trust Risk Domains</SectionTitle><DomainRows rows={snapshot.domainRows.slice(0, 8)} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Policy Breaks</SectionTitle><AlertList rows={snapshot.alerts.slice(0, 8)} /></Panel>
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Control Actions</SectionTitle><Recommendations rows={snapshot.recommendations} /></Panel>
      </section>
      <Panel className="p-5"><SectionTitle>Zero Trust Evidence Ledger</SectionTitle><InventoryTable rows={snapshot.inventory.slice(0, 14)} /></Panel>
    </>
  );
}

function renderModeLayout(mode: TrustMode, snapshot: TrustSnapshot, sseConnected: boolean) {
  if (mode === 'continuous') return <ContinuousLayout snapshot={snapshot} sseConnected={sseConnected} />;
  if (mode === 'identity') return <IdentityLayout snapshot={snapshot} sseConnected={sseConnected} />;
  if (mode === 'device') return <DeviceLayout snapshot={snapshot} sseConnected={sseConnected} />;
  if (mode === 'analytics') return <AnalyticsLayout snapshot={snapshot} sseConnected={sseConnected} />;
  return <ZeroTrustLayout snapshot={snapshot} sseConnected={sseConnected} />;
}

export default function TrustCenterDashboard({ mode }: { mode: TrustMode }) {
  const { snapshot, state, error, sseConnected, refresh } = useTrustDashboard(mode);

  return (
    <div className="min-h-screen bg-[#030711] px-4 py-4 text-white sm:px-5 lg:px-6">
      <div className="mx-auto max-w-[1540px] space-y-4">
        <Header mode={mode} snapshot={snapshot} state={state} sseConnected={sseConnected} refresh={refresh} />
        {error ? <div className="rounded-md border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-200">{error}</div> : null}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
          {renderModeLayout(mode, snapshot, sseConnected)}
        </motion.div>
      </div>
    </div>
  );
}
