'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  Archive,
  BadgeCheck,
  ChevronRight,
  ClipboardCheck,
  Database,
  Download,
  FileText,
  Layers,
  Lock,
  Map,
  Radar,
  RefreshCw,
  Scale,
  ScanSearch,
  Settings,
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

type GovernanceMode = 'quantum' | 'policies' | 'audit' | 'regulatory';
type LoadState = 'loading' | 'success' | 'error';

type TimelinePoint = {
  label: string;
  evidence: number;
  compliant: number;
  violations: number;
  audit: number;
};

type DistributionRow = {
  label: string;
  count: number;
  percent: number;
};

type DomainRow = DistributionRow & {
  compliant: number;
  violations: number;
  coverage: number;
  riskScore: number;
  latestSeen: string | null;
};

type PolicyRow = {
  label: string;
  scope: string;
  enforced: boolean;
  evidence: number;
  compliant: number;
  violations: number;
  coverage: number;
  riskScore: number;
  latestSeen: string | null;
  actionHref: string;
};

type RegulatoryRow = {
  framework: string;
  control: string;
  evidence: number;
  compliant: number;
  findings: number;
  coverage: number;
  latestSeen: string | null;
};

type SubjectRow = {
  subject: string;
  type: string;
  evidence: number;
  compliant: number;
  violations: number;
  riskScore: number;
  latestSeen: string | null;
};

type AuditRow = {
  id: string;
  event: string;
  actor: string;
  source: string;
  result: string;
  immutable: boolean;
  severity: string;
  timestamp: string | null;
  detail: string;
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
  framework: string;
  control: string;
  status: string;
  severity: string;
  score: number;
  compliant: boolean;
  evidence: boolean;
  policyEnforced: boolean;
  immutable: boolean;
  encrypted: boolean;
  pqcReady: boolean;
  timestamp: string | null;
  source: string;
  detail: string;
};

type GovernanceSnapshot = {
  generatedAt: string | null;
  latestActivityAt: string | null;
  metrics: {
    totalEvidence: number;
    evidenceDelta: number;
    policyScore: number;
    policyCoverage: number;
    activePolicies: number;
    policyViolations: number;
    auditEvents: number;
    immutableEvents: number;
    vaultObjects: number;
    vaultIntegrityScore: number;
    frameworksMapped: number;
    controlsMapped: number;
    complianceScore: number;
    evidenceGaps: number;
    highRiskFindings: number;
    assetsCovered: number;
    runtimeFindings: number;
    staleEvidence: number;
    activeSources: number;
    pqcReadiness: number;
    encryptedCoverage: number;
  };
  timeline: TimelinePoint[];
  domainRows: DomainRow[];
  policyRows: PolicyRow[];
  regulatoryRows: RegulatoryRow[];
  subjectRows: SubjectRow[];
  auditRows: AuditRow[];
  severityDistribution: DistributionRow[];
  statusDistribution: DistributionRow[];
  sourceDistribution: DistributionRow[];
  frameworkDistribution: DistributionRow[];
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
    vaultAuditLogs: number;
    auditLogs: number;
    complianceEvidence: number;
    migrationJobs: number;
    securityEvents: number;
    qrngEvents: number;
    eventPipelineStatus: string;
    latestRuntimeEventAt: string | null;
  };
};

const EMPTY_SNAPSHOT: GovernanceSnapshot = {
  generatedAt: null,
  latestActivityAt: null,
  metrics: {
    totalEvidence: 0,
    evidenceDelta: 0,
    policyScore: 0,
    policyCoverage: 0,
    activePolicies: 0,
    policyViolations: 0,
    auditEvents: 0,
    immutableEvents: 0,
    vaultObjects: 0,
    vaultIntegrityScore: 0,
    frameworksMapped: 0,
    controlsMapped: 0,
    complianceScore: 0,
    evidenceGaps: 0,
    highRiskFindings: 0,
    assetsCovered: 0,
    runtimeFindings: 0,
    staleEvidence: 0,
    activeSources: 0,
    pqcReadiness: 0,
    encryptedCoverage: 0,
  },
  timeline: [],
  domainRows: [],
  policyRows: [],
  regulatoryRows: [],
  subjectRows: [],
  auditRows: [],
  severityDistribution: [],
  statusDistribution: [],
  sourceDistribution: [],
  frameworkDistribution: [],
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
    vaultAuditLogs: 0,
    auditLogs: 0,
    complianceEvidence: 0,
    migrationJobs: 0,
    securityEvents: 0,
    qrngEvents: 0,
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
  'group relative overflow-hidden rounded-lg border border-blue-400/12 bg-[#07101D]/76 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-20px_48px_rgba(36,120,255,0.035),0_14px_36px_rgba(0,0,0,0.34)] transition duration-500 hover:-translate-y-0.5 hover:border-gold/65 hover:bg-[#0A1728]/86 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.22),inset_0_-20px_52px_rgba(251,191,36,0.11),0_18px_48px_rgba(0,0,0,0.48),0_0_46px_rgba(251,191,36,0.22)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/55 before:to-transparent';

const MODE_COPY = {
  quantum: {
    segment: 'quantum-governance',
    streamPrefix: 'quantum-governance',
    title: 'Quantum Governance',
    subtitle: 'Enterprise crypto governance, PQC readiness, audit evidence, policy control, and runtime risk synchronized from tenant telemetry.',
    Icon: ShieldCheck,
    primaryHref: '/dashboard/regulatory-mapping',
    primaryLabel: 'Control Map',
    accent: GOLD,
  },
  policies: {
    segment: 'crypto-policies',
    streamPrefix: 'crypto-policies',
    title: 'Crypto Policies',
    subtitle: 'Policy enforcement, algorithm allowlists, evidence scope, exceptions, and live cryptographic governance drift.',
    Icon: FileText,
    primaryHref: '/dashboard/scanner',
    primaryLabel: 'Policy Sources',
    accent: GOLD,
  },
  audit: {
    segment: 'audit-vault',
    streamPrefix: 'audit-vault',
    title: 'Audit Vault',
    subtitle: 'Immutable audit trail, vault integrity, access events, evidence retention, and cryptographic custody history.',
    Icon: Database,
    primaryHref: '/dashboard/vault',
    primaryLabel: 'Open Vault',
    accent: CYAN,
  },
  regulatory: {
    segment: 'regulatory-mapping',
    streamPrefix: 'regulatory-mapping',
    title: 'Regulatory Mapping',
    subtitle: 'Control coverage mapped to frameworks, evidence freshness, audit readiness, and cryptographic compliance gaps.',
    Icon: Map,
    primaryHref: '/dashboard/compliance',
    primaryLabel: 'Compliance Center',
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

function useGovernanceDashboard(mode: GovernanceMode) {
  const config = MODE_COPY[mode];
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<GovernanceSnapshot>(EMPTY_SNAPSHOT);
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
      'vault_audit_logs',
      'audit_logs',
      'compliance_evidence',
      'migration_jobs',
      'security_events',
      'user_security_events',
      'auth_events',
      'qrng_events',
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

function TimelineChart({ points }: { points: TimelinePoint[] }) {
  const width = 760;
  const height = 228;
  const series = [
    { key: 'evidence', label: 'Evidence', color: BLUE },
    { key: 'compliant', label: 'Compliant', color: GREEN },
    { key: 'violations', label: 'Violations', color: RED },
    { key: 'audit', label: 'Audit', color: GOLD },
  ] as const;
  const hasData = points.some((point) => point.evidence || point.compliant || point.violations || point.audit);

  if (!points.length || !hasData) return <EmptyState label="Awaiting governance telemetry." />;

  const max = Math.max(1, ...points.flatMap((point) => series.map((item) => point[item.key])));
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
      <svg className="h-[228px] w-full" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="governance evidence timeline">
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
          const d = points.map((point, index) => `${index === 0 ? 'M' : 'L'} ${xFor(index).toFixed(1)} ${yFor(point[item.key]).toFixed(1)}`).join(' ');
          return (
            <g key={item.label}>
              <path d={d} fill="none" stroke={item.color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
              {points.map((point, index) => <circle key={`${item.label}-${point.label}`} cx={xFor(index)} cy={yFor(point[item.key])} r="3" fill={item.color} />)}
            </g>
          );
        })}
        {points.map((point, index) => (
          <text key={point.label} x={xFor(index)} y="218" textAnchor="middle" fill="rgba(255,255,255,0.5)" fontSize="10">{point.label}</text>
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
        <div key={row.label} className="grid grid-cols-[120px_1fr_70px] items-center gap-3 text-xs">
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

function PolicyMatrix({ rows }: { rows: PolicyRow[] }) {
  if (!rows.length) return <EmptyState label="No policy evidence has been captured for this tenant yet." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] text-left text-xs">
        <thead>
          <tr className="border-b border-white/10 text-[10px] uppercase tracking-[0.06em] text-white/42">
            <th className="px-2 py-2">Policy Area</th>
            <th className="px-2 py-2">Scope</th>
            <th className="px-2 py-2">Coverage</th>
            <th className="px-2 py-2">Evidence</th>
            <th className="px-2 py-2">Violations</th>
            <th className="px-2 py-2">Risk</th>
            <th className="px-2 py-2 text-right">Action</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.label} className="border-b border-white/6 hover:bg-white/[0.025]">
              <td className="px-2 py-3">
                <div className="font-semibold text-white">{row.label}</div>
                <div className={cn('mt-1 text-[10px] font-bold uppercase', row.enforced ? 'text-emerald-300' : 'text-amber-300')}>
                  {row.enforced ? 'Enforced' : 'Evidence Only'}
                </div>
              </td>
              <td className="px-2 py-3 text-white/62">{row.scope}</td>
              <td className="px-2 py-3">
                <div className="flex items-center gap-2">
                  <div className="h-2 w-24 overflow-hidden rounded-full bg-white/7">
                    <div className="h-full rounded-full bg-emerald-400" style={{ width: `${row.coverage}%` }} />
                  </div>
                  <span className="font-mono text-white/70">{percentFmt(row.coverage)}</span>
                </div>
              </td>
              <td className="px-2 py-3 font-mono text-white/72">{integerFmt(row.evidence)}</td>
              <td className="px-2 py-3 font-mono" style={{ color: row.violations ? ORANGE : GREEN }}>{integerFmt(row.violations)}</td>
              <td className="px-2 py-3 font-mono text-white/72">{row.riskScore}</td>
              <td className="px-2 py-3 text-right">
                <a href={row.actionHref} className="inline-flex items-center gap-1 text-[10px] font-black uppercase tracking-[0.06em] text-gold hover:text-[#FFE8A8]">
                  Open <ChevronRight className="h-3 w-3" />
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RegulatoryMatrix({ rows }: { rows: RegulatoryRow[] }) {
  if (!rows.length) return <EmptyState label="No regulatory evidence is mapped for this tenant yet." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] text-left text-xs">
        <thead>
          <tr className="border-b border-white/10 text-[10px] uppercase tracking-[0.06em] text-white/42">
            <th className="px-2 py-2">Framework</th>
            <th className="px-2 py-2">Control</th>
            <th className="px-2 py-2">Coverage</th>
            <th className="px-2 py-2">Evidence</th>
            <th className="px-2 py-2">Findings</th>
            <th className="px-2 py-2">Last Evidence</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={`${row.framework}-${row.control}`} className="border-b border-white/6 hover:bg-white/[0.025]">
              <td className="px-2 py-3 font-semibold text-white">{row.framework}</td>
              <td className="px-2 py-3 text-white/65">{row.control}</td>
              <td className="px-2 py-3">
                <div className="flex items-center gap-2">
                  <div className="h-2 w-28 overflow-hidden rounded-full bg-white/7">
                    <div className="h-full rounded-full" style={{ width: `${row.coverage}%`, backgroundColor: row.findings ? GOLD : GREEN }} />
                  </div>
                  <span className="font-mono text-white/70">{percentFmt(row.coverage)}</span>
                </div>
              </td>
              <td className="px-2 py-3 font-mono text-white/72">{integerFmt(row.evidence)}</td>
              <td className="px-2 py-3 font-mono" style={{ color: row.findings ? ORANGE : GREEN }}>{integerFmt(row.findings)}</td>
              <td className="px-2 py-3 text-white/52">{shortTime(row.latestSeen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SubjectTable({ rows }: { rows: SubjectRow[] }) {
  if (!rows.length) return <EmptyState label="No governed subjects are available yet." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[680px] text-left text-xs">
        <thead>
          <tr className="border-b border-white/10 text-[10px] uppercase tracking-[0.06em] text-white/42">
            <th className="px-2 py-2">Subject</th>
            <th className="px-2 py-2">Type</th>
            <th className="px-2 py-2">Evidence</th>
            <th className="px-2 py-2">Violations</th>
            <th className="px-2 py-2">Risk</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.subject} className="border-b border-white/6 hover:bg-white/[0.025]">
              <td className="px-2 py-3 font-semibold text-white">{row.subject}</td>
              <td className="px-2 py-3 text-white/58">{row.type}</td>
              <td className="px-2 py-3 font-mono text-white/72">{integerFmt(row.evidence)}</td>
              <td className="px-2 py-3 font-mono" style={{ color: row.violations ? ORANGE : GREEN }}>{integerFmt(row.violations)}</td>
              <td className="px-2 py-3 font-mono text-white/72">{row.riskScore}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AuditLedger({ rows }: { rows: AuditRow[] }) {
  if (!rows.length) return <EmptyState label="No audit events are available for this tenant yet." />;
  return (
    <div className="space-y-0">
      {rows.slice(0, 12).map((row) => {
        const color = severityColor(row.severity);
        return (
          <div key={row.id} className="grid grid-cols-[36px_1fr_auto] gap-3 border-b border-white/6 py-3 last:border-b-0">
            <span className="mt-0.5 grid h-8 w-8 place-items-center rounded-md border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
              {row.immutable ? <BadgeCheck className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
            </span>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold text-white">{row.event}</span>
                <span className="rounded border border-white/10 px-1.5 py-0.5 text-[10px] uppercase text-white/45">{row.source}</span>
              </div>
              <div className="mt-1 truncate text-xs text-white/52">{row.actor} - {row.detail || row.result}</div>
            </div>
            <div className="text-right">
              <div className="font-mono text-xs text-white/65">{shortTime(row.timestamp)}</div>
              <div className={cn('mt-1 text-[10px] font-black uppercase', row.immutable ? 'text-emerald-300' : 'text-amber-300')}>
                {row.immutable ? 'Sealed' : 'Recorded'}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function AlertList({ rows }: { rows: AlertRow[] }) {
  if (!rows.length) return <EmptyState label="No open governance findings for this tenant." />;
  return (
    <div className="space-y-0">
      {rows.slice(0, 9).map((row) => {
        const color = severityColor(row.severity);
        return (
          <div key={row.id} className="grid grid-cols-[32px_1fr_auto] gap-3 border-b border-white/6 py-3 last:border-b-0">
            <span className="grid h-8 w-8 place-items-center rounded-md border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
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
  if (!rows.length) return <EmptyState label="No governance recommendations are active right now." />;
  return (
    <div className="space-y-0">
      {rows.slice(0, 6).map((row) => {
        const color = severityColor(row.impact);
        return (
          <a key={row.id} href={row.actionHref} className="grid grid-cols-[32px_1fr_auto] gap-3 border-b border-white/6 py-3 transition hover:bg-white/[0.025] last:border-b-0">
            <span className="grid h-8 w-8 place-items-center rounded-md border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
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

function InventoryTable({ rows }: { rows: InventoryRow[] }) {
  if (!rows.length) return <EmptyState label="No governance inventory is available yet." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[920px] text-left text-xs">
        <thead>
          <tr className="border-b border-white/10 text-[10px] uppercase tracking-[0.06em] text-white/42">
            <th className="px-2 py-2">Signal</th>
            <th className="px-2 py-2">Subject</th>
            <th className="px-2 py-2">Framework</th>
            <th className="px-2 py-2">Status</th>
            <th className="px-2 py-2">Score</th>
            <th className="px-2 py-2">Flags</th>
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 14).map((row) => (
            <tr key={row.id} className="border-b border-white/6 hover:bg-white/[0.025]">
              <td className="px-2 py-3">
                <div className="font-semibold text-white">{row.title}</div>
                <div className="mt-1 text-[10px] uppercase text-white/42">{row.domain} - {row.source}</div>
              </td>
              <td className="px-2 py-3">
                <div className="text-white/70">{row.subject}</div>
                <div className="mt-1 text-[10px] text-white/38">{row.subjectType}</div>
              </td>
              <td className="px-2 py-3">
                <div className="text-white/70">{row.framework}</div>
                <div className="mt-1 text-[10px] text-white/38">{row.control}</div>
              </td>
              <td className="px-2 py-3">
                <span className={cn('rounded border px-2 py-1 text-[10px] font-black uppercase', row.compliant ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300' : 'border-amber-400/30 bg-amber-400/10 text-amber-300')}>
                  {row.status}
                </span>
              </td>
              <td className="px-2 py-3 font-mono text-white/72">{row.score}</td>
              <td className="px-2 py-3">
                <div className="flex flex-wrap gap-1">
                  {row.policyEnforced ? <span className="rounded border border-blue-400/25 px-1.5 py-0.5 text-[10px] text-blue-200">policy</span> : null}
                  {row.immutable ? <span className="rounded border border-emerald-400/25 px-1.5 py-0.5 text-[10px] text-emerald-200">sealed</span> : null}
                  {row.pqcReady ? <span className="rounded border border-gold/25 px-1.5 py-0.5 text-[10px] text-gold">pqc</span> : null}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ActivityFeed({ rows }: { rows: ActivityRow[] }) {
  if (!rows.length) return <EmptyState label="No governance activity has been captured yet." />;
  return (
    <div className="space-y-0">
      {rows.slice(0, 8).map((row) => (
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

function Header({ mode, snapshot, state, sseConnected, refresh }: { mode: GovernanceMode; snapshot: GovernanceSnapshot; state: LoadState; sseConnected: boolean; refresh: () => void }) {
  const config = MODE_COPY[mode];
  const Icon = config.Icon;

  const exportReport = useCallback(() => {
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${config.segment}-governance-report.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }, [config.segment, snapshot]);

  return (
    <header className="grid gap-4 xl:grid-cols-[1fr_auto] xl:items-center">
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
            Latest evidence: <span className="font-mono text-white/62">{longDate(snapshot.latestActivityAt)}</span>
          </div>
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

function QuantumLayout({ snapshot }: { snapshot: GovernanceSnapshot }) {
  const spark = snapshot.timeline.map((point) => point.evidence);
  const auditReadiness = Math.min(
    snapshot.metrics.complianceScore || snapshot.metrics.policyScore,
    snapshot.metrics.vaultIntegrityScore || snapshot.metrics.policyScore,
  );
  const governanceScore = Math.round((
    snapshot.metrics.policyScore +
    snapshot.metrics.policyCoverage +
    snapshot.metrics.complianceScore +
    snapshot.metrics.vaultIntegrityScore +
    snapshot.metrics.pqcReadiness +
    snapshot.metrics.encryptedCoverage
  ) / 6);

  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
        <MetricTile icon={ShieldCheck} label="Governance Score" value={percentFmt(governanceScore)} trend={signedPercent(snapshot.metrics.evidenceDelta)} detail="policy, audit, and compliance" color={GOLD} spark={spark} />
        <MetricTile icon={Database} label="Evidence" value={compactFmt(snapshot.metrics.totalEvidence)} trend={snapshot.telemetry.eventPipelineStatus.replace(/_/g, ' ')} detail="deduplicated tenant signals" color={BLUE} spark={spark} />
        <MetricTile icon={Zap} label="PQC Readiness" value={percentFmt(snapshot.metrics.pqcReadiness)} trend={percentFmt(snapshot.metrics.encryptedCoverage)} detail="quantum-safe evidence" color={GREEN} spark={snapshot.timeline.map((point) => point.compliant)} />
        <MetricTile icon={ShieldAlert} label="Risk Findings" value={integerFmt(snapshot.metrics.highRiskFindings)} trend={`${integerFmt(snapshot.metrics.policyViolations)} violations`} detail="scan and runtime review" color={ORANGE} spark={snapshot.timeline.map((point) => point.violations)} />
        <MetricTile icon={Scale} label="Controls" value={integerFmt(snapshot.metrics.controlsMapped)} trend={`${integerFmt(snapshot.metrics.frameworksMapped)} frameworks`} detail="mapped regulatory scope" color={PURPLE} spark={snapshot.timeline.map((point) => point.compliant)} />
        <MetricTile icon={Archive} label="Audit Ready" value={percentFmt(auditReadiness)} trend={`${integerFmt(snapshot.metrics.immutableEvents)} sealed`} detail="vault and custody integrity" color={CYAN} spark={snapshot.timeline.map((point) => point.audit)} />
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-8">
          <SectionTitle suffix={<a href="/dashboard/quantum-governance" className="text-[10px] font-black uppercase tracking-[0.06em] text-gold hover:text-[#FFE8A8]">Quantum Governance</a>}>Governance Control Matrix</SectionTitle>
          <PolicyMatrix rows={snapshot.policyRows} />
        </Panel>
        <Panel className="p-5 xl:col-span-4">
          <SectionTitle>Readiness Command State</SectionTitle>
          <ScoreDial value={governanceScore} label="Governance" color={GOLD} />
          <div className="mt-3 grid grid-cols-2 gap-3 text-xs">
            <div className="border-t border-white/8 pt-3"><div className="text-white/42">Scan Signals</div><div className="mt-1 font-mono text-lg text-white">{compactFmt(snapshot.telemetry.scanSessions + snapshot.telemetry.scanResults + snapshot.telemetry.scannerEvidence + snapshot.telemetry.scannerAlerts)}</div></div>
            <div className="border-t border-white/8 pt-3"><div className="text-white/42">Vulnerabilities</div><div className="mt-1 font-mono text-lg text-white">{compactFmt(snapshot.telemetry.vulnerabilities)}</div></div>
            <div className="border-t border-white/8 pt-3"><div className="text-white/42">Crypto Objects</div><div className="mt-1 font-mono text-lg text-white">{compactFmt(snapshot.telemetry.cryptoInventory + snapshot.telemetry.certificates + snapshot.telemetry.generatedKeys)}</div></div>
            <div className="border-t border-white/8 pt-3"><div className="text-white/42">Evidence Gaps</div><div className="mt-1 font-mono text-lg text-white">{integerFmt(snapshot.metrics.evidenceGaps)}</div></div>
          </div>
        </Panel>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Governance Evidence Timeline</SectionTitle><TimelineChart points={snapshot.timeline} /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Framework Coverage</SectionTitle><Bars rows={snapshot.frameworkDistribution.slice(0, 8)} empty="No framework mapping is available yet." /></Panel>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Priority Findings</SectionTitle><AlertList rows={snapshot.alerts} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Recommended Actions</SectionTitle><Recommendations rows={snapshot.recommendations} /></Panel>
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Live Source Sync</SectionTitle><Bars rows={snapshot.sourceDistribution.slice(0, 8)} empty="No source telemetry is available yet." /></Panel>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Regulatory Control Mapping</SectionTitle><RegulatoryMatrix rows={snapshot.regulatoryRows} /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Immutable Audit Ledger</SectionTitle><AuditLedger rows={snapshot.auditRows} /></Panel>
      </section>

      <Panel className="p-5"><SectionTitle>Governance Evidence Inventory</SectionTitle><InventoryTable rows={snapshot.inventory} /></Panel>
    </>
  );
}

function PolicyLayout({ snapshot }: { snapshot: GovernanceSnapshot }) {
  const spark = snapshot.timeline.map((point) => point.evidence);
  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile icon={ShieldCheck} label="Policy Score" value={percentFmt(snapshot.metrics.policyScore)} trend={signedPercent(snapshot.metrics.evidenceDelta)} detail="compliant policy evidence" color={GREEN} spark={spark} />
        <MetricTile icon={Settings} label="Active Policies" value={integerFmt(snapshot.metrics.activePolicies)} trend={percentFmt(snapshot.metrics.policyCoverage)} detail="enforcement coverage" color={GOLD} spark={snapshot.timeline.map((point) => point.compliant)} />
        <MetricTile icon={ShieldAlert} label="Violations" value={integerFmt(snapshot.metrics.policyViolations)} trend={`${integerFmt(snapshot.metrics.highRiskFindings)} high risk`} detail="open governance breaks" color={ORANGE} spark={snapshot.timeline.map((point) => point.violations)} />
        <MetricTile icon={Layers} label="Assets Covered" value={integerFmt(snapshot.metrics.assetsCovered)} trend={percentFmt(snapshot.metrics.pqcReadiness)} detail="PQC readiness evidence" color={BLUE} spark={spark} />
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-8">
          <SectionTitle suffix={<a href="/dashboard/scanner" className="text-[10px] font-black uppercase tracking-[0.06em] text-gold hover:text-[#FFE8A8]">Manage Sources</a>}>Policy Enforcement Matrix</SectionTitle>
          <PolicyMatrix rows={snapshot.policyRows} />
        </Panel>
        <Panel className="p-5 xl:col-span-4">
          <SectionTitle>Policy Command State</SectionTitle>
          <ScoreDial value={snapshot.metrics.policyCoverage} label="Coverage" color={GOLD} />
          <div className="mt-3 grid grid-cols-2 gap-3 text-xs">
            <div className="border-t border-white/8 pt-3"><div className="text-white/42">Runtime Findings</div><div className="mt-1 font-mono text-lg text-white">{compactFmt(snapshot.metrics.runtimeFindings)}</div></div>
            <div className="border-t border-white/8 pt-3"><div className="text-white/42">Active Sources</div><div className="mt-1 font-mono text-lg text-white">{integerFmt(snapshot.metrics.activeSources)}</div></div>
            <div className="border-t border-white/8 pt-3"><div className="text-white/42">Encrypted</div><div className="mt-1 font-mono text-lg text-white">{percentFmt(snapshot.metrics.encryptedCoverage)}</div></div>
            <div className="border-t border-white/8 pt-3"><div className="text-white/42">Stale Evidence</div><div className="mt-1 font-mono text-lg text-white">{integerFmt(snapshot.metrics.staleEvidence)}</div></div>
          </div>
        </Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Policy Evidence Timeline</SectionTitle><TimelineChart points={snapshot.timeline} /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Policy Domains</SectionTitle><Bars rows={snapshot.domainRows.slice(0, 8)} empty="No policy domains are available yet." /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Open Policy Findings</SectionTitle><AlertList rows={snapshot.alerts.filter((row) => /policy|runtime|algorithm|certificate|key|scanner|scan|vulnerability/i.test(`${row.domain} ${row.source}`))} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Recommended Actions</SectionTitle><Recommendations rows={snapshot.recommendations} /></Panel>
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Source Synchronization</SectionTitle><Bars rows={snapshot.sourceDistribution.slice(0, 7)} empty="No source telemetry is available yet." /></Panel>
      </section>
    </>
  );
}

function AuditLayout({ snapshot }: { snapshot: GovernanceSnapshot }) {
  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
        <MetricTile icon={Archive} label="Audit Events" value={compactFmt(snapshot.metrics.auditEvents)} trend={signedPercent(snapshot.metrics.evidenceDelta)} detail="tenant-scoped records" color={CYAN} spark={snapshot.timeline.map((point) => point.audit)} />
        <MetricTile icon={BadgeCheck} label="Immutable Events" value={compactFmt(snapshot.metrics.immutableEvents)} trend={percentFmt(snapshot.metrics.vaultIntegrityScore)} detail="sealed or custody marked" color={GREEN} spark={snapshot.timeline.map((point) => point.compliant)} />
        <MetricTile icon={Database} label="Vault Objects" value={compactFmt(snapshot.metrics.vaultObjects)} trend={percentFmt(snapshot.metrics.encryptedCoverage)} detail="encrypted coverage" color={GOLD} spark={snapshot.timeline.map((point) => point.evidence)} />
        <MetricTile icon={AlertTriangle} label="Audit Findings" value={integerFmt(snapshot.alerts.filter((row) => /audit|vault|access/i.test(row.domain)).length)} trend={`${integerFmt(snapshot.metrics.highRiskFindings)} high risk`} detail="access and custody review" color={ORANGE} spark={snapshot.timeline.map((point) => point.violations)} />
        <MetricTile icon={Activity} label="Evidence Sources" value={integerFmt(snapshot.metrics.activeSources)} trend={snapshot.telemetry.eventPipelineStatus.replace(/_/g, ' ')} detail="live governance streams" color={BLUE} spark={snapshot.timeline.map((point) => point.evidence)} />
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7">
          <SectionTitle suffix={<a href="/dashboard/vault" className="text-[10px] font-black uppercase tracking-[0.06em] text-gold hover:text-[#FFE8A8]">Open Vault</a>}>Immutable Audit Ledger</SectionTitle>
          <AuditLedger rows={snapshot.auditRows} />
        </Panel>
        <Panel className="p-5 xl:col-span-5">
          <SectionTitle>Custody Integrity Stack</SectionTitle>
          <ScoreDial value={snapshot.metrics.vaultIntegrityScore} label="Integrity" color={CYAN} />
          <div className="mt-4 space-y-3">
            {[
              { label: 'Vault Audit Logs', value: snapshot.telemetry.vaultAuditLogs, icon: FileText },
              { label: 'General Audit Logs', value: snapshot.telemetry.auditLogs, icon: ClipboardCheck },
              { label: 'Vault Files', value: snapshot.telemetry.vaultFiles, icon: Database },
              { label: 'Security Events', value: snapshot.telemetry.securityEvents, icon: Lock },
            ].map((row) => {
              const Icon = row.icon;
              return (
                <div key={row.label} className="flex items-center justify-between border-b border-white/6 pb-2 last:border-b-0">
                  <span className="inline-flex items-center gap-2 text-xs text-white/65"><Icon className="h-4 w-4 text-gold" />{row.label}</span>
                  <span className="font-mono text-sm text-white">{compactFmt(row.value)}</span>
                </div>
              );
            })}
          </div>
        </Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-6"><SectionTitle>Audit Activity Timeline</SectionTitle><TimelineChart points={snapshot.timeline} /></Panel>
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Audit Sources</SectionTitle><Bars rows={snapshot.sourceDistribution.filter((row) => /audit|vault|security|auth/i.test(row.label)).slice(0, 7)} empty="No audit source telemetry is available yet." /></Panel>
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Audit Outcomes</SectionTitle><Bars rows={snapshot.statusDistribution.slice(0, 7)} empty="No audit outcomes are available yet." /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Audit Findings</SectionTitle><AlertList rows={snapshot.alerts.filter((row) => /audit|vault|access/i.test(row.domain))} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Custody Actions</SectionTitle><Recommendations rows={snapshot.recommendations} /></Panel>
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Recent Activity</SectionTitle><ActivityFeed rows={snapshot.activity.filter((row) => /audit|vault|access/i.test(row.detail))} /></Panel>
      </section>
    </>
  );
}

function RegulatoryLayout({ snapshot }: { snapshot: GovernanceSnapshot }) {
  const frameworkRows = snapshot.frameworkDistribution.length ? snapshot.frameworkDistribution : snapshot.regulatoryRows.map((row) => ({ label: row.framework, count: row.evidence, percent: row.coverage }));
  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile icon={Scale} label="Compliance Score" value={percentFmt(snapshot.metrics.complianceScore)} trend={signedPercent(snapshot.metrics.evidenceDelta)} detail="mapped evidence passing" color={GREEN} spark={snapshot.timeline.map((point) => point.compliant)} />
        <MetricTile icon={Map} label="Frameworks" value={integerFmt(snapshot.metrics.frameworksMapped)} trend={`${integerFmt(snapshot.metrics.controlsMapped)} controls`} detail="active mapped frameworks" color={BLUE} spark={snapshot.timeline.map((point) => point.evidence)} />
        <MetricTile icon={AlertTriangle} label="Evidence Gaps" value={integerFmt(snapshot.metrics.evidenceGaps)} trend={`${integerFmt(snapshot.metrics.staleEvidence)} stale`} detail="controls requiring review" color={ORANGE} spark={snapshot.timeline.map((point) => point.violations)} />
        <MetricTile icon={Workflow} label="Audit Readiness" value={percentFmt(Math.min(snapshot.metrics.complianceScore, snapshot.metrics.vaultIntegrityScore || snapshot.metrics.complianceScore))} trend={percentFmt(snapshot.metrics.policyScore)} detail="policy and vault alignment" color={GOLD} spark={snapshot.timeline.map((point) => point.audit)} />
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-8">
          <SectionTitle suffix={<a href="/dashboard/audit-vault" className="text-[10px] font-black uppercase tracking-[0.06em] text-gold hover:text-[#FFE8A8]">Audit Evidence</a>}>Framework Control Mapping</SectionTitle>
          <RegulatoryMatrix rows={snapshot.regulatoryRows} />
        </Panel>
        <Panel className="p-5 xl:col-span-4">
          <SectionTitle>Framework Coverage</SectionTitle>
          <Bars rows={frameworkRows.slice(0, 8)} empty="No framework mapping is available yet." />
        </Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Evidence Readiness Timeline</SectionTitle><TimelineChart points={snapshot.timeline} /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Highest Risk Subjects</SectionTitle><SubjectTable rows={snapshot.subjectRows} /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Regulatory Findings</SectionTitle><AlertList rows={snapshot.alerts.filter((row) => /regulatory|compliance|policy|audit/i.test(row.domain))} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Evidence Actions</SectionTitle><Recommendations rows={snapshot.recommendations} /></Panel>
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Severity Profile</SectionTitle><Bars rows={snapshot.severityDistribution} empty="No severity data is available yet." /></Panel>
      </section>
      <Panel className="p-5"><SectionTitle>Regulatory Evidence Inventory</SectionTitle><InventoryTable rows={snapshot.inventory} /></Panel>
    </>
  );
}

function Body({ mode, snapshot }: { mode: GovernanceMode; snapshot: GovernanceSnapshot }) {
  if (mode === 'quantum') return <QuantumLayout snapshot={snapshot} />;
  if (mode === 'policies') return <PolicyLayout snapshot={snapshot} />;
  if (mode === 'audit') return <AuditLayout snapshot={snapshot} />;
  return <RegulatoryLayout snapshot={snapshot} />;
}

export default function GovernanceDashboard({ mode }: { mode: GovernanceMode }) {
  const { snapshot, state, error, sseConnected, refresh } = useGovernanceDashboard(mode);
  const config = MODE_COPY[mode];
  const telemetrySummary = useMemo(() => [
    ['Assets', snapshot.telemetry.assets],
    ['Runtime', snapshot.telemetry.runtimeEvents],
    ['Scanner', snapshot.telemetry.scanSessions + snapshot.telemetry.scanResults + snapshot.telemetry.scannerEvidence + snapshot.telemetry.scannerAlerts + snapshot.telemetry.vulnerabilities],
    ['Vault', snapshot.telemetry.vaultFiles + snapshot.telemetry.vaultAuditLogs],
    ['Compliance', snapshot.telemetry.complianceEvidence],
  ], [snapshot.telemetry]);

  return (
    <main className="min-h-screen bg-[#050914] px-4 py-5 text-white md:px-6">
      <div className="mx-auto max-w-[1540px] space-y-4">
        <Header mode={mode} snapshot={snapshot} state={state} sseConnected={sseConnected} refresh={refresh} />
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
          <Body mode={mode} snapshot={snapshot} />
        </motion.div>
        <div className="text-right text-[10px] uppercase tracking-[0.06em] text-white/28">
          {config.title} synchronized from authenticated tenant evidence streams.
        </div>
      </div>
    </main>
  );
}
