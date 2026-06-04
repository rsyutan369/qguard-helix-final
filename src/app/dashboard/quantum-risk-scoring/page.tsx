'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  AlertTriangle,
  Bell,
  CalendarDays,
  ChevronDown,
  ChevronRight,
  Download,
  Eye,
  FileKey,
  Gauge,
  Globe2,
  Info,
  KeyRound,
  LockKeyhole,
  Network,
  Radio,
  RefreshCw,
  Settings,
  Shield,
  ShieldAlert,
  Target,
  UserCircle,
  Wrench,
  type LucideIcon,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import { cn } from '@/lib/utils';

type LoadState = 'loading' | 'success' | 'error';
type Severity = 'critical' | 'high' | 'medium' | 'low' | string;

type TimelinePoint = {
  label: string;
  riskScore: number;
  assetsAtRisk: number;
  assetsAtRiskPercent: number;
  pqcAdoption: number;
};

type BreakdownRow = {
  label: string;
  count: number;
  percent: number;
  score: number;
};

type DistributionRow = {
  label: string;
  count: number;
  percent: number;
};

type TopAssetRow = {
  asset: string;
  assetType: string;
  riskScore: number;
  riskLevel: string;
  primaryRiskFactor: string;
};

type HeatmapRegion = {
  region: string;
  riskScore: number;
  assets: number;
};

type RiskFactorRow = {
  factor: string;
  impact: string;
  score: number;
  trend: number;
};

type DriverRow = {
  key: string;
  label: string;
  detail: string;
  value: number;
  delta: number;
  severity: string;
};

type RecommendationRow = {
  id: string;
  title: string;
  detail: string;
  severity: string;
};

type ActivityRow = {
  id: string;
  time: string | null;
  event: string;
  source: string;
  asset: string;
  severity: Severity;
  score: number;
};

type QuantumRiskSnapshot = {
  generatedAt: string | null;
  latestActivityAt: string | null;
  latestScanAt: string | null;
  filters: {
    environments: string[];
  };
  metrics: {
    quantumRiskScore: number;
    riskScoreLevel: string;
    assetsAtRisk: number;
    assetsAtRiskPercent: number;
    criticalExposures: number;
    criticalExposurePercent: number;
    pqcAdoptionScore: number;
    pqcAdoptionLevel: string;
    riskTrendPercent: number;
    hndlExposureScore: number;
    hndlExposureLevel: string;
    totalAssets: number;
    findings: number;
  };
  timeline: TimelinePoint[];
  breakdown: BreakdownRow[];
  distribution: DistributionRow[];
  topAssets: TopAssetRow[];
  heatmap: HeatmapRegion[];
  riskFactors: RiskFactorRow[];
  drivers: DriverRow[];
  benchmark: Array<{ label: string; value: number }>;
  recommendations: RecommendationRow[];
  recentActivity: ActivityRow[];
  telemetry: {
    runtimeEvents: number;
    scannerEvidence: number;
    scannerAlerts: number;
    scanResults: number;
    securityEvents: number;
    assets: number;
    scannerAgents: number;
    connectors: number;
    certificates: number;
    keys: number;
    qrngEvents: number;
    vaultAuditLogs: number;
    eventPipelineStatus: string;
    latestRuntimeEventAt: string | null;
  };
};

const EMPTY_SNAPSHOT: QuantumRiskSnapshot = {
  generatedAt: null,
  latestActivityAt: null,
  latestScanAt: null,
  filters: { environments: [] },
  metrics: {
    quantumRiskScore: 0,
    riskScoreLevel: 'Minimal',
    assetsAtRisk: 0,
    assetsAtRiskPercent: 0,
    criticalExposures: 0,
    criticalExposurePercent: 0,
    pqcAdoptionScore: 0,
    pqcAdoptionLevel: 'No PQC telemetry',
    riskTrendPercent: 0,
    hndlExposureScore: 0,
    hndlExposureLevel: 'None',
    totalAssets: 0,
    findings: 0,
  },
  timeline: [],
  breakdown: [
    { label: 'Cryptographic Vulnerabilities', count: 0, percent: 0, score: 0 },
    { label: 'PQC Readiness', count: 0, percent: 0, score: 0 },
    { label: 'Protocol & TLS Security', count: 0, percent: 0, score: 0 },
    { label: 'Key & Certificate Health', count: 0, percent: 0, score: 0 },
    { label: 'Algorithm Strength', count: 0, percent: 0, score: 0 },
    { label: 'Other Factors', count: 0, percent: 0, score: 0 },
  ],
  distribution: [
    { label: 'Critical', count: 0, percent: 0 },
    { label: 'High', count: 0, percent: 0 },
    { label: 'Medium', count: 0, percent: 0 },
    { label: 'Low', count: 0, percent: 0 },
    { label: 'Minimal', count: 0, percent: 0 },
  ],
  topAssets: [],
  heatmap: [],
  riskFactors: [],
  drivers: [],
  benchmark: [
    { label: 'Your Organization', value: 0 },
    { label: 'Fleet Average', value: 0 },
    { label: 'Highest Risk 25%', value: 0 },
    { label: 'Lowest Risk 10%', value: 0 },
  ],
  recommendations: [],
  recentActivity: [],
  telemetry: {
    runtimeEvents: 0,
    scannerEvidence: 0,
    scannerAlerts: 0,
    scanResults: 0,
    securityEvents: 0,
    assets: 0,
    scannerAgents: 0,
    connectors: 0,
    certificates: 0,
    keys: 0,
    qrngEvents: 0,
    vaultAuditLogs: 0,
    eventPipelineStatus: 'no_agents',
    latestRuntimeEventAt: null,
  },
};

const RED = '#EF4444';
const ORANGE = '#F59E0B';
const GOLD = '#FBBF24';
const GREEN = '#22C55E';
const TEAL = '#14B8A6';
const BLUE = '#2478FF';
const PURPLE = '#A855F7';
const CYAN = '#22D3EE';

const CATEGORY_COLORS: Record<string, string> = {
  'Cryptographic Vulnerabilities': RED,
  'PQC Readiness': ORANGE,
  'Protocol & TLS Security': GOLD,
  'Key & Certificate Health': GREEN,
  'Algorithm Strength': CYAN,
  'Other Factors': BLUE,
};

const LEVEL_COLORS: Record<string, string> = {
  Critical: RED,
  High: '#F97316',
  Medium: GOLD,
  Low: GREEN,
  Minimal: TEAL,
};

const PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-blue-400/12 bg-[#07101D]/70 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(36,120,255,0.035),0_0_34px_rgba(0,0,0,0.34)] transition duration-500 hover:-translate-y-0.5 hover:border-gold/65 hover:bg-[#0A1728]/84 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.22),inset_0_-24px_60px_rgba(251,191,36,0.12),0_16px_46px_rgba(0,0,0,0.48),0_0_58px_rgba(251,191,36,0.28)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/55 before:to-transparent after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-52 after:w-52 after:rounded-full after:bg-gold/8 after:blur-3xl after:opacity-0 after:transition group-hover:after:opacity-100';

function integerFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(Number(value) || 0)));
}

function compactFmt(value: number) {
  return new Intl.NumberFormat('en-US', {
    notation: value >= 100000 ? 'compact' : 'standard',
    maximumFractionDigits: value >= 100000 ? 1 : 0,
  }).format(Math.max(0, Number(value) || 0));
}

function percentLabel(value: number) {
  return `${Math.round(Number(value) || 0)}%`;
}

function signedPercent(value: number) {
  const safe = Math.round(Number(value) || 0);
  if (safe > 0) return `+${safe}%`;
  return `${safe}%`;
}

function dateRangeLabel() {
  const end = new Date();
  const start = new Date(end);
  start.setDate(end.getDate() - 7);
  const format = (date: Date) => date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  return `${format(start)} - ${format(end)}, ${end.getFullYear()}`;
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

function deltaClass(value: number) {
  if (value > 0) return 'text-red-300';
  if (value < 0) return 'text-emerald-300';
  return 'text-white/45';
}

function severityColor(value: string) {
  const text = value.toLowerCase();
  if (text.includes('critical') || text.includes('high')) return RED;
  if (text.includes('medium') || text.includes('moderate')) return GOLD;
  if (text.includes('pqc')) return PURPLE;
  if (text.includes('info')) return BLUE;
  return GREEN;
}

function riskTone(score: number) {
  if (score >= 90) return RED;
  if (score >= 75) return '#F97316';
  if (score >= 55) return GOLD;
  if (score >= 30) return GREEN;
  return TEAL;
}

function linePath(values: number[], width: number, height: number, pad = 26) {
  if (!values.length) return '';
  const max = Math.max(100, ...values);
  return values.map((value, index) => {
    const x = pad + (values.length <= 1 ? 0 : (index / (values.length - 1)) * (width - pad * 2));
    const y = pad + (height - pad * 2) - ((Number(value) || 0) / max) * (height - pad * 2);
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(' ');
}

function useQuantumRiskScoring() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<QuantumRiskSnapshot>(EMPTY_SNAPSHOT);
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
      const response = await fetch('/api/v1/dashboard/quantum-risk-scoring', {
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
        filters: { ...EMPTY_SNAPSHOT.filters, ...(data.filters || {}) },
        metrics: { ...EMPTY_SNAPSHOT.metrics, ...(data.metrics || {}) },
        telemetry: { ...EMPTY_SNAPSHOT.telemetry, ...(data.telemetry || {}) },
      });
      setState('success');
      setError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to load quantum risk scoring data';
      console.error('Quantum risk scoring load failed:', err);
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
      'scanner_alerts',
      'scanner_evidence',
      'scanner_agents',
      'connector_accounts',
      'pqc_scan_results',
      'pqc_scan_sessions',
      'crypto_exposures',
      'crypto_inventory',
      'security_events',
      'migration_jobs',
      'migration_events',
      'compliance_evidence',
      'generated_keys',
      'certificates',
      'qrng_events',
      'vault_audit_logs',
      'agent_heartbeats',
    ];

    const channels = tables.map((table) => supabase
      .channel(`quantum-risk-scoring-${table}`)
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
      const riskStream = new EventSource(`/api/v1/dashboard/quantum-risk-scoring/stream?token=${encodeURIComponent(token)}`);
      const metricsStream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`);
      const scannerStream = new EventSource(`/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`);
      streamsRef.current = [riskStream, metricsStream, scannerStream];

      const markOpen = () => setSseConnected(true);
      const scheduleReconnect = () => {
        setSseConnected(false);
        closeStreams();
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(connect, 10000);
      };
      const refreshFromStream = () => queueRefresh();

      riskStream.onopen = markOpen;
      metricsStream.onopen = markOpen;
      scannerStream.onopen = markOpen;
      riskStream.onerror = scheduleReconnect;
      metricsStream.onerror = scheduleReconnect;
      scannerStream.onerror = scheduleReconnect;
      riskStream.addEventListener('quantum-risk-connected', refreshFromStream);
      riskStream.addEventListener('quantum-risk-update', refreshFromStream);
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

function HeaderButton({ icon: Icon, children }: { icon: LucideIcon; children: ReactNode }) {
  return (
    <button type="button" className="inline-flex h-10 items-center gap-2 rounded-md border border-white/10 bg-black/22 px-3 text-xs font-bold text-white/75 transition hover:border-gold/55 hover:bg-gold/10 hover:text-gold">
      <Icon className="h-4 w-4" />
      {children}
    </button>
  );
}

function IconButton({ icon: Icon, badge }: { icon: LucideIcon; badge?: number }) {
  return (
    <button type="button" className="relative grid h-10 w-10 place-items-center rounded-md border border-white/10 bg-black/22 text-white/75 transition hover:border-gold/55 hover:text-gold">
      <Icon className="h-4 w-4" />
      {badge ? <span className="absolute -right-1 -top-1 grid h-4 min-w-4 place-items-center rounded-full bg-red-500 px-1 text-[9px] font-black text-white">{badge}</span> : null}
    </button>
  );
}

function SectionTitle({ children, suffix }: { children: ReactNode; suffix?: ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-3">
      <h2 className="text-xs font-black uppercase tracking-[0.08em] text-white">{children}</h2>
      {suffix}
    </div>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex min-h-[120px] items-center justify-center rounded-md border border-dashed border-white/10 bg-white/[0.02] px-4 text-center text-xs text-white/38">
      {label}
    </div>
  );
}

function MiniSpark({ values, color }: { values: number[]; color: string }) {
  const path = linePath(values.length ? values : [0, 0], 82, 34, 4);
  return (
    <svg className="h-9 w-24" viewBox="0 0 82 34" aria-hidden="true">
      <path d={path} fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      {values.map((value, index) => {
        const x = 4 + (values.length <= 1 ? 0 : (index / (values.length - 1)) * 74);
        const y = 4 + 26 - ((Number(value) || 0) / Math.max(100, ...values)) * 26;
        return <circle key={`${index}-${value}`} cx={x} cy={y} r="1.4" fill={color} opacity="0.85" />;
      })}
    </svg>
  );
}

function Ring({ value, color, size = 64, stroke = 9 }: { value: number; color: string; size?: number; stroke?: number }) {
  const safe = Math.max(0, Math.min(100, Number(value) || 0));
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
      <circle cx={size / 2} cy={size / 2} r={radius} stroke="rgba(255,255,255,0.08)" strokeWidth={stroke} fill="none" />
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        stroke={color}
        strokeWidth={stroke}
        fill="none"
        strokeLinecap="round"
        strokeDasharray={`${circumference}`}
        strokeDashoffset={circumference - (safe / 100) * circumference}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
      />
    </svg>
  );
}

function MetricCard({
  label,
  value,
  suffix,
  detail,
  color,
  spark,
  ring,
}: {
  label: string;
  value: string;
  suffix?: string;
  detail: string;
  color: string;
  spark?: number[];
  ring?: number;
}) {
  return (
    <Panel className="min-h-[118px] p-4">
      <div className="flex h-full items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="text-[10px] font-black uppercase tracking-[0.08em]" style={{ color }}>{label}</div>
          <div className="mt-3 flex items-baseline gap-1">
            <span className="text-2xl font-semibold text-white">{value}</span>
            {suffix ? <span className="text-xs font-semibold text-white/50">{suffix}</span> : null}
          </div>
          <div className="mt-1 text-[10px] font-bold" style={{ color }}>{detail}</div>
        </div>
        {typeof ring === 'number' ? <Ring value={ring} color={color} /> : <MiniSpark values={spark || []} color={color} />}
      </div>
    </Panel>
  );
}

function RiskTrendChart({ points }: { points: TimelinePoint[] }) {
  const width = 820;
  const height = 250;
  const risk = points.map((point) => point.riskScore);
  const assets = points.map((point) => point.assetsAtRiskPercent);
  const pqc = points.map((point) => point.pqcAdoption);

  if (!points.length) return <EmptyState label="Awaiting scan and runtime telemetry for the risk trend." />;

  const series = [
    { label: 'Risk Score', values: risk, color: RED },
    { label: 'Assets at Risk', values: assets, color: ORANGE },
    { label: 'PQC Adoption', values: pqc, color: GREEN },
  ];

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-5 text-[10px] text-white/62">
        {series.map((item) => (
          <span key={item.label} className="inline-flex items-center gap-2">
            <span className="h-2 w-3 rounded-sm" style={{ backgroundColor: item.color }} />
            {item.label}
          </span>
        ))}
      </div>
      <svg className="h-[250px] w-full" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Risk score over time">
        <defs>
          <linearGradient id="risk-fill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor={RED} stopOpacity="0.28" />
            <stop offset="100%" stopColor={RED} stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0, 25, 50, 75, 100].map((tick) => {
          const y = 26 + (100 - tick) / 100 * 184;
          return (
            <g key={tick}>
              <line x1="38" x2="798" y1={y} y2={y} stroke="rgba(255,255,255,0.06)" />
              <text x="10" y={y + 4} fill="rgba(255,255,255,0.45)" fontSize="10">{tick}</text>
            </g>
          );
        })}
        <path d={`${linePath(risk, width, height, 34)} L 786 210 L 34 210 Z`} fill="url(#risk-fill)" opacity="0.8" />
        {series.map((item) => (
          <g key={item.label}>
            <path d={linePath(item.values, width, height, 34)} fill="none" stroke={item.color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            {item.values.map((value, index) => {
              const x = 34 + (item.values.length <= 1 ? 0 : (index / (item.values.length - 1)) * (width - 68));
              const y = 34 + (height - 68) - ((Number(value) || 0) / 100) * (height - 68);
              return <circle key={`${item.label}-${index}`} cx={x} cy={y} r="2.4" fill={item.color} />;
            })}
          </g>
        ))}
        {points.map((point, index) => {
          const x = 34 + (points.length <= 1 ? 0 : (index / (points.length - 1)) * (width - 68));
          return <text key={`${point.label}-${index}`} x={x} y="238" textAnchor="middle" fill="rgba(255,255,255,0.5)" fontSize="10">{point.label}</text>;
        })}
      </svg>
    </div>
  );
}

function DonutBreakdown({ rows, score, level }: { rows: BreakdownRow[]; score: number; level: string }) {
  const total = Math.max(1, rows.reduce((sum, row) => sum + row.percent, 0));
  let offset = 0;

  return (
    <div className="grid grid-cols-[160px_1fr] items-center gap-5">
      <div className="relative grid h-40 w-40 place-items-center">
        <svg className="h-40 w-40 -rotate-90" viewBox="0 0 120 120" aria-hidden="true">
          <circle cx="60" cy="60" r="42" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="16" />
          {rows.map((row) => {
            const value = Math.max(0, row.percent);
            const dash = `${(value / total) * 263.89} 263.89`;
            const strokeOffset = -offset;
            offset += (value / total) * 263.89;
            return (
              <circle
                key={row.label}
                cx="60"
                cy="60"
                r="42"
                fill="none"
                stroke={CATEGORY_COLORS[row.label] || BLUE}
                strokeWidth="16"
                strokeDasharray={dash}
                strokeDashoffset={strokeOffset}
              />
            );
          })}
        </svg>
        <div className="absolute text-center">
          <div className="text-3xl font-semibold text-white">{integerFmt(score)}</div>
          <div className="text-[10px] font-bold" style={{ color: riskTone(score) }}>{level}</div>
        </div>
      </div>
      <div className="space-y-2">
        {rows.map((row) => (
          <div key={row.label} className="grid grid-cols-[12px_1fr_40px] items-center gap-2 text-[11px]">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: CATEGORY_COLORS[row.label] || BLUE }} />
            <span className="truncate text-white/72">{row.label}</span>
            <span className="text-right font-mono text-white/72">{integerFmt(row.percent)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DistributionBars({ rows }: { rows: DistributionRow[] }) {
  return (
    <div className="space-y-4">
      {rows.map((row) => (
        <div key={row.label} className="grid grid-cols-[72px_1fr_82px] items-center gap-3 text-xs">
          <span className="text-white/72">{row.label}</span>
          <div className="h-2.5 overflow-hidden rounded-full bg-white/5">
            <div className="h-full rounded-full" style={{ width: `${Math.min(100, row.percent)}%`, backgroundColor: LEVEL_COLORS[row.label] || BLUE }} />
          </div>
          <span className="text-right font-mono text-white/70">{compactFmt(row.count)} ({integerFmt(row.percent)}%)</span>
        </div>
      ))}
    </div>
  );
}

function TopRiskyAssets({ rows }: { rows: TopAssetRow[] }) {
  if (!rows.length) return <EmptyState label="No risky assets found for this tenant." />;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-[540px] w-full text-left text-xs">
        <thead>
          <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
            <th className="pb-3 font-black">Asset</th>
            <th className="pb-3 font-black">Asset Type</th>
            <th className="pb-3 font-black">Risk Score</th>
            <th className="pb-3 font-black">Risk Level</th>
            <th className="pb-3 font-black">Primary Risk Factor</th>
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 6).map((row) => (
            <tr key={`${row.asset}-${row.primaryRiskFactor}`} className="border-b border-white/5 text-white/70">
              <td className="max-w-[160px] truncate py-3 font-medium text-white/78">{row.asset}</td>
              <td className="py-3">{row.assetType}</td>
              <td className="py-3 font-mono">{integerFmt(row.riskScore)}</td>
              <td className="py-3 font-bold" style={{ color: riskTone(row.riskScore) }}>{row.riskLevel}</td>
              <td className="max-w-[150px] truncate py-3">{row.primaryRiskFactor}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RiskFactorTable({ rows }: { rows: RiskFactorRow[] }) {
  if (!rows.length) return <EmptyState label="No risk factors detected yet." />;
  return (
    <div className="space-y-2">
      <div className="grid grid-cols-[1fr_70px_64px_44px] gap-3 border-b border-white/8 pb-2 text-[9px] font-black uppercase tracking-[0.08em] text-white/35">
        <span>Factor</span>
        <span>Impact</span>
        <span>Score</span>
        <span className="text-right">Trend</span>
      </div>
      {rows.map((row) => (
        <div key={row.factor} className="grid grid-cols-[1fr_70px_64px_44px] items-center gap-3 border-b border-white/5 py-2 text-xs">
          <span className="truncate text-white/72">{row.factor}</span>
          <span className="font-bold" style={{ color: severityColor(row.impact) }}>{row.impact}</span>
          <span className="font-mono text-white/70">{integerFmt(row.score)}</span>
          <span className={cn('text-right font-bold', deltaClass(row.trend))}>{row.trend >= 0 ? 'up' : 'down'}</span>
        </div>
      ))}
    </div>
  );
}

function DriverCard({ driver }: { driver: DriverRow }) {
  const icons: Record<string, LucideIcon> = {
    weakAlgorithms: Wrench,
    outdatedProtocols: Shield,
    certificateIssues: FileKey,
    keyManagement: KeyRound,
    cryptoSprawl: Network,
    pqcReadiness: Target,
  };
  const Icon = icons[driver.key] || Gauge;
  const color = severityColor(driver.severity);

  return (
    <div className="rounded-md border border-white/8 bg-white/[0.025] p-4 transition hover:border-gold/45 hover:bg-gold/8">
      <div className="mb-3 grid h-10 w-10 place-items-center rounded-md border" style={{ borderColor: `${color}55`, color, backgroundColor: `${color}14` }}>
        <Icon className="h-5 w-5" />
      </div>
      <div className="text-xs font-bold text-white">{driver.label}</div>
      <div className="mt-1 h-8 text-[10px] leading-4 text-white/45">{driver.detail}</div>
      <div className="mt-3 text-2xl font-semibold text-white">{compactFmt(driver.value)}</div>
      <div className={cn('mt-1 text-[10px] font-bold', deltaClass(driver.delta))}>{signedPercent(driver.delta)} vs last 7 days</div>
    </div>
  );
}

function Benchmark({ rows }: { rows: Array<{ label: string; value: number }> }) {
  const max = Math.max(100, ...rows.map((row) => row.value));
  const colors = [RED, '#F97316', GOLD, GREEN];

  return (
    <div className="space-y-5">
      {rows.map((row, index) => (
        <div key={row.label}>
          <div className="mb-2 flex items-center justify-between text-xs">
            <span className="text-white/72">{row.label}</span>
            <span className="font-mono text-lg text-white">{integerFmt(row.value)}</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-white/5">
            <div className="h-full rounded-full" style={{ width: `${Math.min(100, (row.value / max) * 100)}%`, backgroundColor: colors[index] || BLUE }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function Recommendations({ rows }: { rows: RecommendationRow[] }) {
  return (
    <div className="space-y-2">
      {rows.slice(0, 5).map((row) => {
        const color = severityColor(row.severity);
        return (
          <a key={row.id} href="/dashboard/runtime-crypto-intel" className="grid grid-cols-[28px_1fr_auto_18px] items-center gap-3 rounded-md border border-white/8 bg-white/[0.025] p-2.5 transition hover:border-gold/45 hover:bg-gold/8">
            <span className="grid h-7 w-7 place-items-center rounded-md border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
              <ShieldAlert className="h-3.5 w-3.5" />
            </span>
            <span className="min-w-0">
              <span className="block truncate text-xs font-bold text-white/82">{row.title}</span>
              <span className="block truncate text-[10px] text-white/42">{row.detail}</span>
            </span>
            <span className="rounded bg-white/5 px-2 py-1 text-[10px] font-black" style={{ color }}>{row.severity}</span>
            <ChevronRight className="h-4 w-4 text-white/38" />
          </a>
        );
      })}
    </div>
  );
}

function ActivityStrip({ rows }: { rows: ActivityRow[] }) {
  if (!rows.length) return null;
  return (
    <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-5">
      {rows.slice(0, 5).map((row) => (
        <div key={row.id} className="rounded-md border border-white/8 bg-black/18 p-3 text-xs">
          <div className="flex items-center justify-between gap-2">
            <span className="truncate font-bold text-white/75">{row.event}</span>
            <span className="font-mono" style={{ color: riskTone(row.score) }}>{integerFmt(row.score)}</span>
          </div>
          <div className="mt-1 truncate text-[10px] text-white/42">{row.asset} - {shortTime(row.time)}</div>
        </div>
      ))}
    </div>
  );
}

export default function QuantumRiskScoringPage() {
  const { snapshot, state, error, sseConnected, refresh } = useQuantumRiskScoring();

  const riskSpark = useMemo(() => snapshot.timeline.map((point) => point.riskScore), [snapshot.timeline]);
  const assetSpark = useMemo(() => snapshot.timeline.map((point) => point.assetsAtRiskPercent), [snapshot.timeline]);
  const pqcSpark = useMemo(() => snapshot.timeline.map((point) => point.pqcAdoption), [snapshot.timeline]);
  const criticalSpark = useMemo(() => snapshot.timeline.map((point) => Math.min(100, point.assetsAtRisk + snapshot.metrics.criticalExposures)), [snapshot.timeline, snapshot.metrics.criticalExposures]);

  const exportReport = useCallback(() => {
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `quantum-risk-scoring-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }, [snapshot]);

  const cards = [
    {
      label: 'Quantum Risk Score',
      value: integerFmt(snapshot.metrics.quantumRiskScore),
      suffix: '/100',
      detail: snapshot.metrics.riskScoreLevel,
      color: riskTone(snapshot.metrics.quantumRiskScore),
      ring: snapshot.metrics.quantumRiskScore,
    },
    {
      label: 'Assets at Risk',
      value: compactFmt(snapshot.metrics.assetsAtRisk),
      detail: `${percentLabel(snapshot.metrics.assetsAtRiskPercent)} of total assets`,
      color: BLUE,
      spark: assetSpark,
    },
    {
      label: 'Critical Exposures',
      value: compactFmt(snapshot.metrics.criticalExposures),
      detail: `${percentLabel(snapshot.metrics.criticalExposurePercent)} of findings`,
      color: RED,
      spark: criticalSpark,
    },
    {
      label: 'PQC Adoption Score',
      value: percentLabel(snapshot.metrics.pqcAdoptionScore),
      detail: snapshot.metrics.pqcAdoptionLevel,
      color: GOLD,
      spark: pqcSpark,
    },
    {
      label: 'Risk Trend (7 Days)',
      value: signedPercent(snapshot.metrics.riskTrendPercent),
      detail: snapshot.metrics.riskTrendPercent > 0 ? 'Increasing' : snapshot.metrics.riskTrendPercent < 0 ? 'Improving' : 'Stable',
      color: snapshot.metrics.riskTrendPercent > 0 ? RED : GREEN,
      spark: riskSpark,
    },
    {
      label: 'HNDL Exposure Score',
      value: integerFmt(snapshot.metrics.hndlExposureScore),
      suffix: '/100',
      detail: snapshot.metrics.hndlExposureLevel,
      color: PURPLE,
      ring: snapshot.metrics.hndlExposureScore,
    },
  ];

  return (
    <div className="min-h-screen bg-[#030711] px-4 py-5 text-white sm:px-5 lg:px-6">
      <div className="mx-auto max-w-[1540px] space-y-4">
        <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-semibold tracking-normal text-white">Quantum Risk Scoring</h1>
              <Info className="h-4 w-4 text-white/42" />
            </div>
            <p className="mt-1 text-sm text-white/58">Dynamic risk assessment of quantum vulnerability across your digital assets</p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <HeaderButton icon={ChevronDown}>All Environments</HeaderButton>
            <HeaderButton icon={CalendarDays}>{dateRangeLabel()}</HeaderButton>
            <HeaderButton icon={Radio}>{sseConnected ? 'Live' : 'Syncing'}</HeaderButton>
            <IconButton icon={Bell} badge={snapshot.metrics.criticalExposures ? Math.min(99, snapshot.metrics.criticalExposures) : undefined} />
            <IconButton icon={Settings} />
            <IconButton icon={UserCircle} />
            <button
              type="button"
              onClick={exportReport}
              className="inline-flex h-10 items-center gap-2 rounded-md border border-white/10 bg-black/22 px-3 text-xs font-bold text-white/75 transition hover:border-gold/55 hover:bg-gold hover:text-black"
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
          {cards.map((card) => (
            <div key={card.label}>
              <MetricCard {...card} />
            </div>
          ))}
        </motion.section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-12">
            <SectionTitle
              suffix={(
                <div className="flex items-center gap-2">
                  {['7D', '30D', '90D'].map((label) => (
                    <button key={label} type="button" className={cn('rounded border px-3 py-1 text-[10px] font-bold transition', label === '7D' ? 'border-blue-500 bg-blue-500/15 text-blue-300' : 'border-white/10 bg-black/20 text-white/42 hover:border-gold/45 hover:text-gold')}>
                      {label}
                    </button>
                  ))}
                  <button type="button" onClick={() => void refresh()} className="rounded border border-white/10 p-1.5 text-white/45 transition hover:border-gold/45 hover:text-gold">
                    <RefreshCw className={cn('h-3.5 w-3.5', state === 'loading' && 'animate-spin')} />
                  </button>
                </div>
              )}
            >
              Risk Score Over Time
            </SectionTitle>
            <RiskTrendChart points={snapshot.timeline} />
          </Panel>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-6">
            <SectionTitle>Risk Score Breakdown</SectionTitle>
            <DonutBreakdown rows={snapshot.breakdown} score={snapshot.metrics.quantumRiskScore} level={snapshot.metrics.riskScoreLevel} />
            <div className="mt-4 flex justify-end">
              <a href="/dashboard/runtime-crypto-intel" className="inline-flex items-center gap-1 text-xs font-bold text-blue-300 transition hover:text-gold">
                View All Factors <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </Panel>

          <Panel className="p-5 xl:col-span-6">
            <SectionTitle>Risk Distribution</SectionTitle>
            <DistributionBars rows={snapshot.distribution} />
            <div className="mt-5 flex justify-end">
              <a href="/dashboard/assets" className="inline-flex items-center gap-1 text-xs font-bold text-blue-300 transition hover:text-gold">
                View All Assets <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </Panel>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-12">
            <SectionTitle>Top Risky Assets</SectionTitle>
            <TopRiskyAssets rows={snapshot.topAssets} />
            <div className="mt-4 flex justify-end">
              <a href="/dashboard/assets" className="inline-flex items-center gap-1 text-xs font-bold text-blue-300 transition hover:text-gold">
                View All Risky Assets <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </Panel>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-12">
            <SectionTitle>Risk Factor Analysis</SectionTitle>
            <RiskFactorTable rows={snapshot.riskFactors} />
            <div className="mt-4 flex justify-end">
              <a href="/dashboard/runtime-crypto-intel" className="inline-flex items-center gap-1 text-xs font-bold text-blue-300 transition hover:text-gold">
                View All Factors <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </Panel>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-12">
            <SectionTitle>Risk Drivers</SectionTitle>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-6">
              {snapshot.drivers.map((driver) => (
                <div key={driver.key}>
                  <DriverCard driver={driver} />
                </div>
              ))}
            </div>
            <div className="mt-4 flex justify-end">
              <a href="/dashboard/telemetry-correlation" className="inline-flex items-center gap-1 text-xs font-bold text-blue-300 transition hover:text-gold">
                View All Risky Drivers <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </Panel>

          <Panel className="p-5 xl:col-span-6">
            <SectionTitle>Risk Score Benchmark</SectionTitle>
            <Benchmark rows={snapshot.benchmark} />
            <div className="mt-5 flex justify-end">
              <a href="/dashboard/runtime-crypto-intel" className="inline-flex items-center gap-1 text-xs font-bold text-blue-300 transition hover:text-gold">
                View Risk Evidence <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </Panel>

          <Panel className="p-5 xl:col-span-6">
            <SectionTitle>Risk Mitigation Recommendations</SectionTitle>
            <Recommendations rows={snapshot.recommendations} />
            <div className="mt-4 flex justify-end">
              <a href="/dashboard/crypto-agility" className="inline-flex items-center gap-1 text-xs font-bold text-blue-300 transition hover:text-gold">
                View All Recommendations <ChevronRight className="h-3.5 w-3.5" />
              </a>
            </div>
          </Panel>
        </section>

        <ActivityStrip rows={snapshot.recentActivity} />

        <div className="flex flex-wrap items-center justify-between gap-3 text-[11px] text-white/35">
          <span className="inline-flex items-center gap-2">
            <span className={cn('h-2 w-2 rounded-full', sseConnected ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]' : 'bg-gold animate-pulse')} />
            {sseConnected ? 'Quantum risk SSE, metrics stream, scanner stream, and live table subscriptions connected' : 'Connecting live quantum risk streams'}
          </span>
          <span className="inline-flex items-center gap-2">
            <Globe2 className="h-3.5 w-3.5 text-white/30" />
            Latest synchronized activity: {longDate(snapshot.latestActivityAt || snapshot.latestScanAt || snapshot.telemetry.latestRuntimeEventAt)}
          </span>
        </div>
      </div>
    </div>
  );
}
