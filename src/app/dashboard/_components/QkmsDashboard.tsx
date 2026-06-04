'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  AlertTriangle,
  BadgeCheck,
  Boxes,
  ChevronRight,
  CircleGauge,
  Database,
  Download,
  FileText,
  Fingerprint,
  GitBranch,
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
  type LucideIcon,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import { cn } from '@/lib/utils';
import { QKMS_TABLES } from '../_lib/telemetry-sync';

type QkmsMode = 'overview' | 'inventory' | 'governance' | 'readiness';
type LoadState = 'loading' | 'success' | 'error';

type KeyRecord = {
  id: string;
  source: string;
  name: string;
  keyAlias: string;
  keyType: string;
  algorithm: string;
  keySize: number;
  status: string;
  owner: string;
  assetId?: string | null;
  certificateId?: string | null;
  assetName: string;
  purpose: string;
  environment: string;
  backend: string;
  storageReference: string;
  entropySource: string;
  exportable: boolean;
  hsmBacked: boolean;
  quantumReady: boolean;
  pqcReadiness: string;
  weak: boolean;
  orphaned: boolean;
  rotationRequired: boolean;
  rotationStatus: string;
  nearExpiry: boolean;
  runtimeUsage: number;
  certificateLinks: number;
  trustScore: number;
  riskScore: number;
  complianceStatus: string;
  linkedAssets: Row[];
  linkedCertificates: Row[];
  linkedMigrationJobs: Row[];
  runtimeEvents: Row[];
  rotationHistory: Row[];
  accessPolicy: Row;
  auditTrail: Row[];
  riskExplanation: string;
  pqcExplanation: string;
  recommendedAction: string;
  createdAt: string | null;
  lastRotatedAt: string | null;
  updatedAt: string | null;
  expiresAt: string | null;
  metadata?: Row;
};

type Row = Record<string, any>;

type QkmsSnapshot = {
  generatedAt: string | null;
  latestActivityAt: string | null;
  metrics: {
    totalKeys: number;
    quantumReadyKeys: number;
    orphanedKeys: number;
    weakAlgorithms: number;
    rotationRequired: number;
    policyViolations: number;
    keysNearExpiry: number;
    hsmProtectedKeys: number;
    exportableProductionKeys: number;
    findings: number;
    detections: number;
    auditEvidenceCount: number;
    auditReadinessScore: number;
    migrationGateStatus: string;
    pqcReadinessScore: number;
    mlKemReadiness: number;
    mlDsaReadiness: number;
    symmetricReadiness: number;
    hashKdfReadiness: number;
    hybridTlsReadiness: number;
    certificateReadiness: number;
    migrationPrecheck: number;
    activeBackends: number;
    runtimeUsages: number;
    complianceReports: number;
  };
  inventory: KeyRecord[];
  policies: Row[];
  rotationJobs: Row[];
  storageBackends: Row[];
  qrng: { configured: boolean; events: number; latestAt: string | null; algorithms: Row[] };
  readiness: { mlKem: number; mlDsa: number; symmetric: number; hashKdf: number; hybridTls: number; certificate: number; migrationPrecheck: number };
  prechecks: Row[];
  decisions: Row[];
  auditEvidence: Row[];
  reports: Row[];
  runtimeUsage: Row[];
  trustGraph: { nodes: Row[]; edges: Row[] };
  distributions: { algorithms: Row[]; backends: Row[]; owners: Row[]; status: Row[] };
  alerts: Row[];
  telemetry: {
    activeAssets: number;
    inactiveAssets: number;
    onlineAgents: number;
    offlineAgents: number;
    freshHeartbeats: number;
    scanSessions: number;
    runningScans: number;
    completedScans: number;
    failedScans: number;
    latestScanAt: string | null;
    latestAgentHeartbeatAt: string | null;
    latestDiscoveryAt: string | null;
    assets: number;
    generatedKeys: number;
    cryptoInventory: number;
    cryptoExposures: number;
    certificates: number;
    runtimeEvents: number;
    scannerEvidence: number;
    scannerAlerts: number;
    scanResults: number;
    migrationJobs: number;
    complianceEvidence: number;
    vaultAuditLogs: number;
    qrngEvents: number;
    scannerAgents: number;
    connectors: number;
    activeSources: number;
    securityEvents: number;
    vulnerabilities: number;
    auditLogs: number;
    scannerPolicies: number;
    eventPipelineStatus: string;
    observedSources?: number;
    latestRuntimeEventAt: string | null;
  };
  sourceHealth: Array<{ id: string; label: string; table: string; count: number; latestAt: string | null; status: string; percent: number }>;
};

type QkmsAction = (path: string, options?: RequestInit) => Promise<any>;

const EMPTY_SNAPSHOT: QkmsSnapshot = {
  generatedAt: null,
  latestActivityAt: null,
  metrics: {
    totalKeys: 0,
    quantumReadyKeys: 0,
    orphanedKeys: 0,
    weakAlgorithms: 0,
    rotationRequired: 0,
    policyViolations: 0,
    keysNearExpiry: 0,
    hsmProtectedKeys: 0,
    exportableProductionKeys: 0,
    findings: 0,
    detections: 0,
    auditEvidenceCount: 0,
    auditReadinessScore: 0,
    migrationGateStatus: 'waiting',
    pqcReadinessScore: 0,
    mlKemReadiness: 0,
    mlDsaReadiness: 0,
    symmetricReadiness: 0,
    hashKdfReadiness: 0,
    hybridTlsReadiness: 0,
    certificateReadiness: 0,
    migrationPrecheck: 0,
    activeBackends: 0,
    runtimeUsages: 0,
    complianceReports: 0,
  },
  inventory: [],
  policies: [],
  rotationJobs: [],
  storageBackends: [],
  qrng: { configured: false, events: 0, latestAt: null, algorithms: [] },
  readiness: { mlKem: 0, mlDsa: 0, symmetric: 0, hashKdf: 0, hybridTls: 0, certificate: 0, migrationPrecheck: 0 },
  prechecks: [],
  decisions: [],
  auditEvidence: [],
  reports: [],
  runtimeUsage: [],
  trustGraph: { nodes: [], edges: [] },
  distributions: { algorithms: [], backends: [], owners: [], status: [] },
  alerts: [],
  telemetry: {
    activeAssets: 0,
    inactiveAssets: 0,
    onlineAgents: 0,
    offlineAgents: 0,
    freshHeartbeats: 0,
    scanSessions: 0,
    runningScans: 0,
    completedScans: 0,
    failedScans: 0,
    latestScanAt: null,
    latestAgentHeartbeatAt: null,
    latestDiscoveryAt: null,
    assets: 0,
    generatedKeys: 0,
    cryptoInventory: 0,
    cryptoExposures: 0,
    certificates: 0,
    runtimeEvents: 0,
    scannerEvidence: 0,
    scannerAlerts: 0,
    scanResults: 0,
    migrationJobs: 0,
    complianceEvidence: 0,
    vaultAuditLogs: 0,
    qrngEvents: 0,
    scannerAgents: 0,
    connectors: 0,
    activeSources: 0,
    securityEvents: 0,
    vulnerabilities: 0,
    auditLogs: 0,
    scannerPolicies: 0,
    eventPipelineStatus: 'no_sources',
    observedSources: 0,
    latestRuntimeEventAt: null,
  },
  sourceHealth: [],
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
  'group relative overflow-hidden rounded-lg border border-blue-400/12 bg-[#07101D]/72 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(36,120,255,0.035),0_0_34px_rgba(0,0,0,0.34)] transition duration-500 hover:-translate-y-0.5 hover:border-gold/55 hover:bg-[#0A1728]/84 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.18),inset_0_-24px_60px_rgba(251,191,36,0.10),0_16px_46px_rgba(0,0,0,0.46),0_0_52px_rgba(251,191,36,0.22)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/50 before:to-transparent';

const MODE_COPY: Record<QkmsMode, { segment: string; label: string; subtitle: string; Icon: LucideIcon }> = {
  overview: {
    segment: 'overview',
    label: 'Overview',
    subtitle: 'QKMS command center for key posture, audit readiness, and migration gate status.',
    Icon: CircleGauge,
  },
  inventory: {
    segment: 'inventory',
    label: 'Key Inventory',
    subtitle: 'Inventory, owner mapping, runtime usage, trust relationships, and key detail inspection.',
    Icon: KeyRound,
  },
  governance: {
    segment: 'governance',
    label: 'Governance',
    subtitle: 'Policies, rotation controls, storage backends, HSM/KMS/Vault readiness, and QRNG entropy.',
    Icon: Workflow,
  },
  readiness: {
    segment: 'readiness',
    label: 'PQC Readiness',
    subtitle: 'ML-KEM, ML-DSA, SLH-DSA, hybrid TLS, migration gate decisions, and audit evidence.',
    Icon: ShieldCheck,
  },
};

const WORKFLOW: Array<{ mode: QkmsMode; href: string }> = [
  { mode: 'overview', href: '/dashboard/qkms/overview' },
  { mode: 'inventory', href: '/dashboard/qkms/inventory' },
  { mode: 'governance', href: '/dashboard/qkms/governance' },
  { mode: 'readiness', href: '/dashboard/qkms/readiness' },
];

function integerFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(Number(value) || 0)));
}

function compactFmt(value: number) {
  return new Intl.NumberFormat('en-US', { notation: Math.abs(value) >= 100000 ? 'compact' : 'standard', maximumFractionDigits: 1 }).format(Math.max(0, Number(value) || 0));
}

function percentFmt(value: number) {
  return `${Math.round(Number(value) || 0)}%`;
}

function longDate(value: string | null) {
  if (!value) return 'Awaiting QKMS telemetry';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Awaiting QKMS telemetry';
  return date.toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function shortTime(value: string | null) {
  if (!value) return 'awaiting';
  const ms = new Date(value).getTime();
  if (!Number.isFinite(ms)) return 'awaiting';
  const minutes = Math.max(0, Math.round((Date.now() - ms) / 60000));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function gateColor(value: string) {
  const lower = value.toLowerCase();
  if (lower.includes('block') || lower.includes('critical') || lower.includes('failed')) return RED;
  if (lower.includes('warn') || lower.includes('review') || lower.includes('partial')) return GOLD;
  if (lower.includes('allow') || lower.includes('ready') || lower.includes('enforced')) return GREEN;
  return BLUE;
}

function useQkmsDashboard(mode: QkmsMode) {
  const config = MODE_COPY[mode];
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<QkmsSnapshot>(EMPTY_SNAPSHOT);
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
      const response = await fetch(`/api/v1/dashboard/qkms/${config.segment}`, {
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
        qrng: { ...EMPTY_SNAPSHOT.qrng, ...(data.qrng || {}) },
        readiness: { ...EMPTY_SNAPSHOT.readiness, ...(data.readiness || {}) },
        distributions: { ...EMPTY_SNAPSHOT.distributions, ...(data.distributions || {}) },
        trustGraph: { ...EMPTY_SNAPSHOT.trustGraph, ...(data.trustGraph || {}) },
        sourceHealth: data.sourceHealth || [],
      });
      setState('success');
      setError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to load QKMS data';
      console.error('QKMS load failed:', err);
      setError(message);
      setState('error');
    }
  }, [config.segment, token]);

  const queueRefresh = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null;
      void refresh();
    }, 250);
  }, [refresh]);

  const request = useCallback(async (path: string, options: RequestInit = {}) => {
    if (!token) throw new Error('Authentication required');
    const response = await fetch(`/api/v1/dashboard/qkms${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        ...(options.headers || {}),
      },
    });
    const contentType = response.headers.get('content-type') || '';
    const payload = contentType.includes('application/json') ? await response.json().catch(() => ({})) : await response.text();
    if (!response.ok) {
      const message = typeof payload === 'object' ? payload?.error?.message : payload;
      throw new Error(message || `HTTP ${response.status}`);
    }
    void refresh();
    return payload;
  }, [refresh, token]);

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
    const channels = QKMS_TABLES.map((table) => supabase
      .channel(`qkms-${config.segment}-${table}`)
      .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
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
      const dashboardStream = new EventSource(`/api/v1/dashboard/qkms/stream?token=${encodeURIComponent(token)}`);
      const metricsStream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`);
      const scannerStream = new EventSource(`/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`);
      const vaultStream = new EventSource(`/api/v1/vault/share/events?token=${encodeURIComponent(token)}`);
      streamsRef.current = [dashboardStream, metricsStream, scannerStream, vaultStream];

      const markOpen = () => setSseConnected(true);
      const reconnect = () => {
        setSseConnected(false);
        closeStreams();
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(connect, 10000);
      };
      const refreshFromStream = () => queueRefresh();

      for (const stream of streamsRef.current) {
        stream.onopen = markOpen;
        stream.onerror = reconnect;
      }
      dashboardStream.addEventListener('qkms-connected', refreshFromStream);
      dashboardStream.addEventListener('qkms-update', refreshFromStream);
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
  }, [token, queueRefresh, closeStreams]);

  return { snapshot, state, error, sseConnected, refresh, request };
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

function MetricTile({ icon: Icon, label, value, detail, color = BLUE }: { icon: LucideIcon; label: string; value: string; detail: string; color?: string }) {
  return (
    <Panel className="p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-[10px] font-black uppercase tracking-[0.08em] text-white/52">{label}</div>
          <div className="mt-3 text-2xl font-semibold text-white">{value}</div>
          <div className="mt-1 text-[10px] leading-4 text-white/42">{detail}</div>
        </div>
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-md border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
          <Icon className="h-5 w-5" />
        </span>
      </div>
    </Panel>
  );
}

function ScoreDial({ value, label, color = BLUE }: { value: number; label: string; color?: string }) {
  const safe = Math.max(0, Math.min(100, Math.round(value || 0)));
  return (
    <div className="grid place-items-center">
      <div className="grid h-40 w-40 place-items-center rounded-full" style={{ background: `conic-gradient(${color} ${safe}%, rgba(255,255,255,0.08) 0)` }}>
        <div className="grid h-32 w-32 place-items-center rounded-full border border-white/10 bg-[#07101D] text-center shadow-[inset_0_0_28px_rgba(0,0,0,0.45)]">
          <div>
            <div className="font-mono text-4xl font-semibold text-white">{integerFmt(safe)}</div>
            <div className="mt-1 text-[10px] uppercase tracking-[0.12em] text-white/52">{label}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Bars({ rows, empty }: { rows: Row[]; empty: string }) {
  if (!rows.length) return <div className="grid min-h-[130px] place-items-center rounded-md border border-dashed border-white/10 bg-white/[0.02] text-xs text-white/38">{empty}</div>;
  return (
    <div className="space-y-3">
      {rows.map((row) => (
        <div key={row.label}>
          <div className="mb-1 flex items-center justify-between gap-3 text-xs">
            <span className="truncate text-white/72">{row.label}</span>
            <span className="font-mono text-white/60">{compactFmt(row.count || row.keys || 0)}</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-white/6">
            <span className="block h-full rounded-full bg-gold" style={{ width: `${Math.max(4, Math.min(100, row.percent || row.coverage || 0))}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function StatusPill({ value }: { value: string }) {
  const color = gateColor(value);
  return (
    <span className="inline-flex items-center rounded-md border px-2 py-1 text-[10px] font-black uppercase tracking-[0.06em]" style={{ borderColor: `${color}55`, color, backgroundColor: `${color}12` }}>
      {value.replace(/_/g, ' ')}
    </span>
  );
}

function Header({ mode, snapshot, state, sseConnected, refresh }: { mode: QkmsMode; snapshot: QkmsSnapshot; state: LoadState; sseConnected: boolean; refresh: () => void }) {
  const config = MODE_COPY[mode];
  const Icon = config.Icon;
  const latest = snapshot.latestActivityAt || snapshot.telemetry.latestScanAt || snapshot.telemetry.latestDiscoveryAt || snapshot.telemetry.latestRuntimeEventAt;
  const exportReport = useCallback(() => {
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `qkms-${mode}-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }, [mode, snapshot]);

  return (
    <header className="space-y-4 border-b border-gold/10 pb-4">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <div className="flex items-center gap-4">
            <Icon className="h-10 w-10 text-gold drop-shadow-[0_0_16px_rgba(251,191,36,0.45)]" />
            <div>
              <h1 className="font-mono text-3xl font-black uppercase tracking-[0.12em] text-gold drop-shadow-[0_0_16px_rgba(251,191,36,0.35)] md:text-4xl">
                Qguard Helix QKMS
              </h1>
              <p className="mt-2 font-mono text-sm uppercase tracking-[0.08em] text-white/70">{config.label}</p>
            </div>
          </div>
          <p className="mt-4 max-w-4xl text-sm leading-6 text-white/58">{config.subtitle}</p>
          <div className="mt-3 flex flex-wrap gap-2 text-[10px] font-bold uppercase tracking-[0.08em] text-white/45">
            <span>Latest: {longDate(latest)}</span>
            <span className="text-white/20">/</span>
            <span>{sseConnected ? 'Live stream active' : 'Live stream connecting'}</span>
            <span className="text-white/20">/</span>
            <span>Pipeline: {snapshot.telemetry.eventPipelineStatus.replace(/_/g, ' ')}</span>
          </div>
        </div>
        <div className="flex flex-wrap justify-start gap-2 xl:justify-end">
          <button type="button" onClick={() => void refresh()} className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 bg-black/24 px-3 text-xs font-bold text-white/75 transition hover:border-gold/55 hover:bg-gold hover:text-black">
            <RefreshCw className={cn('h-4 w-4', state === 'loading' && 'animate-spin')} />
            Refresh
          </button>
          <a href="/dashboard/scanner" className="inline-flex h-9 items-center gap-2 rounded-md border border-blue-500/40 bg-blue-500 px-3 text-xs font-bold text-white transition hover:border-gold hover:bg-gold hover:text-black">
            <Radar className="h-4 w-4" />
            Run Scan
          </a>
          <button type="button" onClick={exportReport} className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 bg-black/24 px-3 text-xs font-bold text-white/75 transition hover:border-gold/55 hover:bg-gold hover:text-black">
            <Download className="h-4 w-4" />
            Export
          </button>
        </div>
      </div>
      <div className="grid gap-2 md:grid-cols-4">
        {WORKFLOW.map((step, index) => {
          const active = mode === step.mode;
          const copy = MODE_COPY[step.mode];
          return (
            <a key={step.mode} href={step.href} className={cn('flex items-center justify-between rounded-md border px-3 py-3 text-xs font-bold transition', active ? 'border-gold/55 bg-gold/12 text-gold' : 'border-white/8 bg-white/[0.025] text-white/52 hover:border-gold/35 hover:text-white')}>
              <span>{index + 1}. {copy.label}</span>
              <ChevronRight className="h-4 w-4" />
            </a>
          );
        })}
      </div>
    </header>
  );
}

function OverviewLayout({ snapshot }: { snapshot: QkmsSnapshot }) {
  const gateColorValue = gateColor(snapshot.metrics.migrationGateStatus);
  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile icon={KeyRound} label="Total Keys" value={compactFmt(snapshot.metrics.totalKeys)} detail={`${compactFmt(snapshot.telemetry.generatedKeys)} generated records`} color={PURPLE} />
        <MetricTile icon={Sparkles} label="Quantum-Ready Keys" value={compactFmt(snapshot.metrics.quantumReadyKeys)} detail={percentFmt(snapshot.metrics.pqcReadinessScore)} color={GREEN} />
        <MetricTile icon={CircleGauge} label="Keys Near Expiry" value={compactFmt(snapshot.metrics.keysNearExpiry)} detail="inside lifecycle warning window" color={GOLD} />
        <MetricTile icon={Fingerprint} label="Orphaned Keys" value={compactFmt(snapshot.metrics.orphanedKeys)} detail="missing owner or asset mapping" color={GOLD} />
        <MetricTile icon={ShieldAlert} label="Weak Algorithms" value={compactFmt(snapshot.metrics.weakAlgorithms)} detail="classical or exposed posture" color={ORANGE} />
        <MetricTile icon={RefreshCw} label="Rotation Required" value={compactFmt(snapshot.metrics.rotationRequired)} detail="expired, revoked, or weak keys" color={CYAN} />
        <MetricTile icon={Lock} label="HSM / Vault Protected" value={compactFmt(snapshot.metrics.hsmProtectedKeys)} detail={`${percentFmt(snapshot.metrics.totalKeys ? (snapshot.metrics.hsmProtectedKeys / snapshot.metrics.totalKeys) * 100 : 0)} protected`} color={TEAL} />
        <MetricTile icon={AlertTriangle} label="Policy Violations" value={compactFmt(snapshot.metrics.policyViolations)} detail={`${compactFmt(snapshot.metrics.findings)} synchronized findings`} color={RED} />
        <MetricTile icon={FileText} label="Audit Evidence" value={compactFmt(snapshot.metrics.auditEvidenceCount || snapshot.auditEvidence.length)} detail={`${percentFmt(snapshot.metrics.auditReadinessScore)} readiness`} color={BLUE} />
        <Panel className="p-4">
          <div className="text-[10px] font-black uppercase tracking-[0.08em] text-white/52">Migration Gate</div>
          <div className="mt-3 text-2xl font-semibold uppercase" style={{ color: gateColorValue }}>{snapshot.metrics.migrationGateStatus}</div>
          <div className="mt-1 text-[10px] leading-4 text-white/42">{percentFmt(snapshot.metrics.migrationPrecheck)} precheck score</div>
        </Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-4"><SectionTitle>PQC Posture</SectionTitle><ScoreDial value={snapshot.metrics.pqcReadinessScore} label="Ready" color={GREEN} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Algorithm Portfolio</SectionTitle><Bars rows={snapshot.distributions.algorithms} empty="No key algorithms discovered yet." /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Live Source Freshness</SectionTitle><SourceHealthList rows={snapshot.sourceHealth} /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7">
          <SectionTitle>Key Lifecycle Control Plane</SectionTitle>
          <LifecycleWorkflow snapshot={snapshot} />
        </Panel>
        <Panel className="p-5 xl:col-span-5">
          <SectionTitle>Risk Heatmap</SectionTitle>
          <Bars rows={[
            { label: 'Deprecated / weak', count: snapshot.metrics.weakAlgorithms, percent: snapshot.metrics.totalKeys ? (snapshot.metrics.weakAlgorithms / snapshot.metrics.totalKeys) * 100 : 0 },
            { label: 'Owner gaps', count: snapshot.metrics.orphanedKeys, percent: snapshot.metrics.totalKeys ? (snapshot.metrics.orphanedKeys / snapshot.metrics.totalKeys) * 100 : 0 },
            { label: 'Rotation due', count: snapshot.metrics.rotationRequired, percent: snapshot.metrics.totalKeys ? (snapshot.metrics.rotationRequired / snapshot.metrics.totalKeys) * 100 : 0 },
            { label: 'Exportable production', count: snapshot.metrics.exportableProductionKeys, percent: snapshot.metrics.totalKeys ? (snapshot.metrics.exportableProductionKeys / snapshot.metrics.totalKeys) * 100 : 0 },
          ]} empty="No QKMS risks detected yet." />
        </Panel>
      </section>
    </>
  );
}

function LifecycleWorkflow({ snapshot }: { snapshot: QkmsSnapshot }) {
  const steps = [
    { label: 'Discover Keys', count: snapshot.metrics.totalKeys, status: snapshot.metrics.totalKeys ? 'ready' : 'waiting' },
    { label: 'Classify Purpose', count: snapshot.distributions.algorithms.length, status: snapshot.distributions.algorithms.length ? 'ready' : 'waiting' },
    { label: 'Assign Owner', count: snapshot.metrics.orphanedKeys, status: snapshot.metrics.orphanedKeys ? 'review' : 'ready' },
    { label: 'Enforce Policy', count: snapshot.metrics.policyViolations, status: snapshot.metrics.policyViolations ? 'review' : 'ready' },
    { label: 'Rotate / Expire', count: snapshot.metrics.rotationRequired, status: snapshot.metrics.rotationRequired ? 'review' : 'ready' },
    { label: 'Validate PQC', count: snapshot.metrics.quantumReadyKeys, status: snapshot.metrics.pqcReadinessScore >= 75 ? 'ready' : 'review' },
    { label: 'Prove Evidence', count: snapshot.metrics.auditEvidenceCount || snapshot.auditEvidence.length, status: snapshot.auditEvidence.length ? 'ready' : 'waiting' },
  ];

  return (
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
      {steps.map((step) => (
        <div key={step.label} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
          <div className="flex items-start justify-between gap-3">
            <div className="text-sm font-semibold text-white">{step.label}</div>
            <StatusPill value={step.status} />
          </div>
          <div className="mt-3 font-mono text-2xl text-white">{compactFmt(step.count)}</div>
        </div>
      ))}
      <div className="rounded-md border border-gold/20 bg-gold/10 p-3 md:col-span-2 xl:col-span-4">
        <div className="text-sm font-semibold text-gold">Do not just become quantum-safe. Prove it.</div>
        <div className="mt-1 text-xs text-white/48">QKMS governs ownership, custody, rotation, policy evidence, and PQC migration gates.</div>
      </div>
    </div>
  );
}

function SourceHealthList({ rows }: { rows: QkmsSnapshot['sourceHealth'] }) {
  const visibleRows = rows.filter((row) => row.count > 0).slice(0, 8);
  if (!visibleRows.length) {
    return <div className="grid min-h-[130px] place-items-center rounded-md border border-dashed border-white/10 bg-white/[0.02] text-xs text-white/38">No live source telemetry yet.</div>;
  }

  return (
    <div className="space-y-3">
      {visibleRows.map((row) => (
        <div key={row.id}>
          <div className="mb-1 flex items-center justify-between gap-3 text-xs">
            <span className="min-w-0 truncate text-white/72">{row.label}</span>
            <span className="shrink-0 font-mono text-white/60">{compactFmt(row.count)}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="h-2 flex-1 overflow-hidden rounded-full bg-white/6">
              <span className={cn('block h-full rounded-full', row.status === 'live' ? 'bg-emerald-400' : row.status === 'stale' ? 'bg-gold' : 'bg-white/30')} style={{ width: `${Math.max(6, Math.min(100, row.percent || 0))}%` }} />
            </span>
            <span className="w-16 text-right text-[10px] uppercase tracking-[0.08em] text-white/38">{row.status}</span>
          </div>
          <div className="mt-1 text-[10px] text-white/34">{shortTime(row.latestAt)}</div>
        </div>
      ))}
    </div>
  );
}

function InventoryLayout({ snapshot, request, onNotice }: { snapshot: QkmsSnapshot; request: QkmsAction; onNotice: (message: string) => void }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({ type: 'all', backend: 'all', environment: 'all', readiness: 'all', rotation: 'all' });
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const pageSize = 7;
  const optionValues = useMemo(() => ({
    types: Array.from(new Set(snapshot.inventory.map((key) => key.keyType || 'Cryptographic key'))).sort(),
    backends: Array.from(new Set(snapshot.inventory.map((key) => key.backend || 'Application Key Store'))).sort(),
    environments: Array.from(new Set(snapshot.inventory.map((key) => key.environment || 'unknown'))).sort(),
    readiness: Array.from(new Set(snapshot.inventory.map((key) => key.pqcReadiness || (key.quantumReady ? 'Quantum-Ready' : 'Unknown')))).sort(),
    rotation: Array.from(new Set(snapshot.inventory.map((key) => key.rotationStatus || 'Healthy'))).sort(),
  }), [snapshot.inventory]);
  const filteredRows = useMemo(() => snapshot.inventory.filter((key) => (
    (filters.type === 'all' || key.keyType === filters.type)
    && (filters.backend === 'all' || key.backend === filters.backend)
    && (filters.environment === 'all' || key.environment === filters.environment)
    && (filters.readiness === 'all' || key.pqcReadiness === filters.readiness)
    && (filters.rotation === 'all' || key.rotationStatus === filters.rotation)
  )), [filters, snapshot.inventory]);
  const totalPages = Math.max(1, Math.ceil(filteredRows.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pageStart = (safePage - 1) * pageSize;
  const pageRows = filteredRows.slice(pageStart, pageStart + pageSize);
  const visiblePages = Array.from({ length: totalPages }, (_, index) => index + 1).filter((pageNumber) => (
    totalPages <= 7 || pageNumber === 1 || pageNumber === totalPages || Math.abs(pageNumber - safePage) <= 2
  ));
  const selected = filteredRows.find((row) => row.id === selectedId) || filteredRows[0] || null;

  useEffect(() => {
    setPage(1);
  }, [filters, snapshot.inventory.length]);

  const handleAction = useCallback(async (key: KeyRecord, action: 'rotate' | 'revoke' | 'assign-owner') => {
    const actionId = `${action}-${key.id}`;
    setPendingAction(actionId);
    try {
      if (action === 'assign-owner') {
        const owner = window.prompt('Assign owner/team for this key', key.owner && !/unassigned|unknown/i.test(key.owner) ? key.owner : '');
        if (!owner) return;
        await request(`/keys/${encodeURIComponent(key.id)}/assign-owner`, { method: 'POST', body: JSON.stringify({ owner }) });
        onNotice(`Owner assigned to ${key.keyAlias || key.name}`);
      } else if (action === 'rotate') {
        await request(`/keys/${encodeURIComponent(key.id)}/rotate`, { method: 'POST', body: JSON.stringify({ reason: `Rotate ${key.keyAlias || key.name}`, priority: key.riskScore >= 60 ? 'high' : 'medium' }) });
        onNotice(`Rotation job created for ${key.keyAlias || key.name}`);
      } else {
        await request(`/keys/${encodeURIComponent(key.id)}/revoke`, { method: 'POST', body: JSON.stringify({ reason: `Revoked from QKMS inventory action` }) });
        onNotice(`${key.keyAlias || key.name} marked for revocation`);
      }
    } catch (error) {
      onNotice(error instanceof Error ? error.message : 'QKMS action failed');
    } finally {
      setPendingAction(null);
    }
  }, [onNotice, request]);

  return (
    <>
      <section>
        <Panel className="p-5">
          <SectionTitle suffix={<span className="text-[10px] text-white/38">{compactFmt(filteredRows.length)} / {compactFmt(snapshot.inventory.length)} keys</span>}>Key Inventory And Trust Mapping</SectionTitle>
          <div className="mb-4 grid gap-2 md:grid-cols-5">
            {[
              ['type', 'Key type', optionValues.types],
              ['backend', 'Storage backend', optionValues.backends],
              ['environment', 'Environment', optionValues.environments],
              ['readiness', 'PQC readiness', optionValues.readiness],
              ['rotation', 'Rotation status', optionValues.rotation],
            ].map(([id, label, values]) => (
              <label key={id as string} className="rounded-md border border-white/8 bg-white/[0.025] px-3 py-2">
                <span className="block text-[10px] uppercase tracking-[0.08em] text-white/38">{label as string}</span>
                <select value={(filters as any)[id as string]} onChange={(event) => setFilters((current) => ({ ...current, [id as string]: event.target.value }))} className="mt-1 w-full bg-transparent text-xs text-white outline-none">
                  <option value="all">All</option>
                  {(values as string[]).map((value) => <option key={value} value={value}>{value}</option>)}
                </select>
              </label>
            ))}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1620px] text-left text-xs">
              <thead className="border-b border-white/10 text-[10px] uppercase tracking-[0.08em] text-white/38">
                <tr><th className="py-3">Key ID / Alias</th><th>Type</th><th>Algorithm</th><th>Purpose</th><th>Owner</th><th>System / Asset</th><th>Env</th><th>Storage</th><th>Created</th><th>Last Rotated</th><th>Expiry</th><th>Rotation</th><th>PQC</th><th>Risk</th><th>Compliance</th><th className="text-right">Actions</th></tr>
              </thead>
              <tbody className="divide-y divide-white/6">
                {pageRows.map((key) => (
                  <tr key={key.id} className={cn('cursor-pointer hover:bg-white/[0.035]', selected?.id === key.id && 'bg-gold/8')} onClick={() => setSelectedId(key.id)}>
                    <td className="py-3"><div className="font-semibold text-white">{key.keyAlias || key.name}</div><div className="font-mono text-[10px] text-white/38">{key.id}</div></td>
                    <td className="text-white/62">{key.keyType || 'Cryptographic key'}</td>
                    <td className="font-mono text-white/70">{key.algorithm || 'Unknown'}</td>
                    <td className="text-white/62">{key.purpose}</td>
                    <td className="text-white/62">{key.owner}</td>
                    <td className="text-white/62">{key.assetName}</td>
                    <td><StatusPill value={key.environment || 'unknown'} /></td>
                    <td className="text-white/62">{key.backend}</td>
                    <td className="text-white/50">{longDate(key.createdAt)}</td>
                    <td className="text-white/50">{longDate(key.lastRotatedAt)}</td>
                    <td className="text-white/50">{longDate(key.expiresAt)}</td>
                    <td><StatusPill value={key.rotationStatus || (key.rotationRequired ? 'Due Soon' : 'Healthy')} /></td>
                    <td><StatusPill value={key.pqcReadiness || (key.quantumReady ? 'Quantum-Ready' : 'Unknown')} /></td>
                    <td className="font-mono text-white">{integerFmt(key.riskScore || Math.max(0, 100 - key.trustScore))}</td>
                    <td><StatusPill value={key.complianceStatus || key.status} /></td>
                    <td className="text-right">
                      <div className="flex justify-end gap-1">
                        <button type="button" title="Create rotation job" disabled={pendingAction === `rotate-${key.id}`} onClick={(event) => { event.stopPropagation(); void handleAction(key, 'rotate'); }} className="inline-flex h-8 items-center gap-1 rounded-md border border-white/10 bg-white/[0.025] px-2 text-[10px] font-bold text-white/62 transition hover:border-gold/50 hover:text-gold disabled:opacity-40"><RefreshCw className="h-3.5 w-3.5" />Rotate</button>
                        <button type="button" title="Assign owner" disabled={pendingAction === `assign-owner-${key.id}`} onClick={(event) => { event.stopPropagation(); void handleAction(key, 'assign-owner'); }} className="inline-flex h-8 items-center gap-1 rounded-md border border-white/10 bg-white/[0.025] px-2 text-[10px] font-bold text-white/62 transition hover:border-gold/50 hover:text-gold disabled:opacity-40"><BadgeCheck className="h-3.5 w-3.5" />Owner</button>
                        <button type="button" title="Revoke metadata record" disabled={pendingAction === `revoke-${key.id}`} onClick={(event) => { event.stopPropagation(); void handleAction(key, 'revoke'); }} className="inline-flex h-8 items-center gap-1 rounded-md border border-red-500/20 bg-red-500/10 px-2 text-[10px] font-bold text-red-200 transition hover:border-red-300 disabled:opacity-40"><ShieldAlert className="h-3.5 w-3.5" />Revoke</button>
                      </div>
                    </td>
                  </tr>
                ))}
                {!pageRows.length ? (
                  <tr>
                    <td colSpan={16} className="py-10 text-center text-white/38">No QKMS key inventory has been discovered for the selected filters.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
          <div className="mt-4 flex flex-col gap-3 border-t border-white/8 pt-4 md:flex-row md:items-center md:justify-between">
            <div className="text-[10px] font-bold uppercase tracking-[0.08em] text-white/42">
              Showing {filteredRows.length ? integerFmt(pageStart + 1) : '0'}-{integerFmt(Math.min(pageStart + pageSize, filteredRows.length))} of {integerFmt(filteredRows.length)}
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              <button type="button" disabled={safePage <= 1} onClick={() => setPage((current) => Math.max(1, current - 1))} className="h-8 rounded-md border border-white/10 bg-white/[0.025] px-3 text-[10px] font-bold text-white/60 transition hover:border-gold/50 hover:text-gold disabled:cursor-not-allowed disabled:opacity-35">
                Prev
              </button>
              {visiblePages.map((pageNumber, index) => {
                const previous = visiblePages[index - 1];
                const gap = previous && pageNumber - previous > 1;
                return (
                  <span key={pageNumber} className="inline-flex items-center gap-1.5">
                    {gap ? <span className="px-1 text-[10px] text-white/28">...</span> : null}
                    <button type="button" onClick={() => setPage(pageNumber)} className={cn('grid h-8 min-w-8 place-items-center rounded-md border px-2 text-[10px] font-black transition', safePage === pageNumber ? 'border-gold/60 bg-gold/15 text-gold' : 'border-white/10 bg-white/[0.025] text-white/58 hover:border-gold/50 hover:text-gold')}>
                      {pageNumber}
                    </button>
                  </span>
                );
              })}
              <button type="button" disabled={safePage >= totalPages} onClick={() => setPage((current) => Math.min(totalPages, current + 1))} className="h-8 rounded-md border border-white/10 bg-white/[0.025] px-3 text-[10px] font-bold text-white/60 transition hover:border-gold/50 hover:text-gold disabled:cursor-not-allowed disabled:opacity-35">
                Next
              </button>
            </div>
          </div>
        </Panel>
      </section>
      <section>
        <Panel className="p-5">
          <SectionTitle>Key Detail Drawer</SectionTitle>
          {selected ? (
            <div className="grid gap-4 xl:grid-cols-[1.1fr_2fr]">
              <div className="rounded-md border border-white/8 bg-white/[0.025] p-4">
                <div className="text-lg font-semibold text-white">{selected.keyAlias || selected.name}</div>
                <div className="mt-1 break-all font-mono text-xs text-white/42">{selected.source} / {selected.id}</div>
                <div className="mt-4 flex flex-wrap gap-2"><StatusPill value={selected.rotationStatus || selected.status} /><StatusPill value={selected.pqcReadiness || 'Unknown'} /><StatusPill value={selected.complianceStatus || 'Evidence needed'} /></div>
                <div className="mt-5 grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-[10px] uppercase tracking-[0.08em] text-white/38">Trust score</div>
                    <div className="mt-1 font-mono text-4xl text-white">{integerFmt(selected.trustScore)}</div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-[0.08em] text-white/38">Risk score</div>
                    <div className="mt-1 font-mono text-4xl text-white">{integerFmt(selected.riskScore || Math.max(0, 100 - selected.trustScore))}</div>
                  </div>
                </div>
                <div className="mt-4 rounded-md border border-white/8 bg-black/20 p-3 text-xs leading-5 text-white/62">{selected.riskExplanation}</div>
                <div className="mt-3 rounded-md border border-gold/20 bg-gold/10 p-3 text-xs leading-5 text-gold">{selected.recommendedAction}</div>
              </div>
              <div className="grid gap-3 text-sm md:grid-cols-2 xl:grid-cols-4">
                {[
                  ['Algorithm', selected.algorithm],
                  ['Key Type', selected.keyType],
                  ['Owner', selected.owner],
                  ['Asset', selected.assetName],
                  ['Backend', selected.backend],
                  ['Storage Ref', selected.storageReference],
                  ['Purpose', selected.purpose],
                  ['Environment', selected.environment],
                  ['Entropy Source', selected.entropySource],
                  ['Exportable', selected.exportable ? 'Blocked for review' : 'No'],
                  ['HSM Backed', selected.hsmBacked ? 'Yes' : 'No'],
                  ['Runtime Usage', compactFmt(selected.runtimeUsage)],
                  ['Certificate Links', compactFmt(selected.certificateLinks)],
                  ['Created', longDate(selected.createdAt)],
                  ['Last Rotated', longDate(selected.lastRotatedAt)],
                  ['Expires', longDate(selected.expiresAt)],
                ].map(([label, value]) => (
                  <div key={label} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
                    <div className="text-[10px] uppercase tracking-[0.08em] text-white/38">{label}</div>
                    <div className="mt-2 break-words text-white/76">{value}</div>
                  </div>
                ))}
              </div>
              <div className="xl:col-span-2 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <EvidenceMiniList title="Linked Certificates" rows={selected.linkedCertificates} empty="No linked certificates." />
                <EvidenceMiniList title="Migration Jobs" rows={selected.linkedMigrationJobs} empty="No linked migration jobs." />
                <EvidenceMiniList title="Runtime Events" rows={selected.runtimeEvents} empty="No runtime usage events." />
                <EvidenceMiniList title="Audit Trail" rows={selected.auditTrail} empty="No audit trail evidence." />
              </div>
              <div className="xl:col-span-2 rounded-md border border-white/8 bg-white/[0.025] p-4">
                <div className="text-[10px] uppercase tracking-[0.08em] text-white/38">PQC readiness explanation</div>
                <div className="mt-2 text-sm leading-6 text-white/68">{selected.pqcExplanation}</div>
              </div>
            </div>
          ) : <div className="grid min-h-[220px] place-items-center text-xs text-white/38">No keys discovered yet.</div>}
        </Panel>
      </section>
      <section>
        <Panel className="p-5"><SectionTitle>Trust Graph</SectionTitle><TrustGraph graph={snapshot.trustGraph} /></Panel>
      </section>
      <section>
        <Panel className="p-5"><SectionTitle>Runtime Usage</SectionTitle><Bars rows={snapshot.runtimeUsage} empty="No runtime key usage has been observed yet." /></Panel>
      </section>
    </>
  );
}

function EvidenceMiniList({ title, rows, empty }: { title: string; rows: Row[]; empty: string }) {
  return (
    <div className="rounded-md border border-white/8 bg-white/[0.025] p-3">
      <div className="mb-3 text-[10px] uppercase tracking-[0.08em] text-white/38">{title}</div>
      <div className="space-y-2">
        {(rows || []).slice(0, 5).map((row, index) => (
          <div key={row.id || index} className="rounded border border-white/6 bg-black/15 p-2">
            <div className="truncate text-xs font-semibold text-white/78">{row.subject || row.reason || row.operation || row.summary || row.eventType || row.status || 'Evidence'}</div>
            <div className="mt-1 text-[10px] text-white/38">{shortTime(row.expiresAt || row.updatedAt || row.observedAt || row.createdAt || row.timestamp)}</div>
          </div>
        ))}
        {!rows?.length ? <div className="py-5 text-center text-xs text-white/34">{empty}</div> : null}
      </div>
    </div>
  );
}

function TrustGraph({ graph }: { graph: QkmsSnapshot['trustGraph'] }) {
  if (!graph.nodes.length) return <div className="grid min-h-[180px] place-items-center rounded-md border border-dashed border-white/10 bg-white/[0.02] text-xs text-white/38">No trust graph data yet.</div>;
  return (
    <div className="grid gap-3 md:grid-cols-3">
      {graph.nodes.slice(0, 18).map((node) => (
        <div key={node.id} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
          <div className="flex items-center justify-between gap-3">
            <span className="truncate text-sm font-semibold text-white">{node.label}</span>
            <StatusPill value={node.status || node.type} />
          </div>
          <div className="mt-2 text-[10px] uppercase tracking-[0.08em] text-white/38">{node.type}</div>
        </div>
      ))}
    </div>
  );
}

function GovernanceLayout({ snapshot, request, onNotice }: { snapshot: QkmsSnapshot; request: QkmsAction; onNotice: (message: string) => void }) {
  const [draft, setDraft] = useState({ name: 'Production QKMS custody policy', environmentScope: 'production', rotationIntervalDays: 180, requireHsm: true, severity: 'high' });
  const [saving, setSaving] = useState(false);

  const createPolicy = useCallback(async () => {
    setSaving(true);
    try {
      await request('/policies', {
        method: 'POST',
        body: JSON.stringify({
          name: draft.name,
          environmentScope: draft.environmentScope,
          rotationIntervalDays: draft.rotationIntervalDays,
          requireOwner: true,
          requireHsm: draft.requireHsm,
          allowExport: false,
          severity: draft.severity,
        }),
      });
      onNotice(`Policy created: ${draft.name}`);
    } catch (error) {
      onNotice(error instanceof Error ? error.message : 'Failed to create policy');
    } finally {
      setSaving(false);
    }
  }, [draft, onNotice, request]);

  return (
    <>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7"><SectionTitle>QKMS Policies</SectionTitle><PolicyTable rows={snapshot.policies} /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Policy Engine Controls</SectionTitle>
          <div className="grid gap-3">
            <label className="rounded-md border border-white/8 bg-white/[0.025] p-3">
              <span className="block text-[10px] uppercase tracking-[0.08em] text-white/38">Policy name</span>
              <input value={draft.name} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} className="mt-2 w-full bg-transparent text-sm text-white outline-none" />
            </label>
            <div className="grid gap-3 md:grid-cols-3">
              <label className="rounded-md border border-white/8 bg-white/[0.025] p-3">
                <span className="block text-[10px] uppercase tracking-[0.08em] text-white/38">Environment</span>
                <select value={draft.environmentScope} onChange={(event) => setDraft((current) => ({ ...current, environmentScope: event.target.value }))} className="mt-2 w-full bg-transparent text-sm text-white outline-none">
                  <option value="production">production</option>
                  <option value="staging">staging</option>
                  <option value="development">development</option>
                  <option value="all">all</option>
                </select>
              </label>
              <label className="rounded-md border border-white/8 bg-white/[0.025] p-3">
                <span className="block text-[10px] uppercase tracking-[0.08em] text-white/38">Rotation days</span>
                <input type="number" min={30} max={730} value={draft.rotationIntervalDays} onChange={(event) => setDraft((current) => ({ ...current, rotationIntervalDays: Number(event.target.value) || 180 }))} className="mt-2 w-full bg-transparent text-sm text-white outline-none" />
              </label>
              <label className="rounded-md border border-white/8 bg-white/[0.025] p-3">
                <span className="block text-[10px] uppercase tracking-[0.08em] text-white/38">Severity</span>
                <select value={draft.severity} onChange={(event) => setDraft((current) => ({ ...current, severity: event.target.value }))} className="mt-2 w-full bg-transparent text-sm text-white outline-none">
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                </select>
              </label>
            </div>
            <label className="flex items-center justify-between gap-3 rounded-md border border-white/8 bg-white/[0.025] p-3 text-sm text-white/70">
              <span>Require HSM / KMS / Vault custody</span>
              <input type="checkbox" checked={draft.requireHsm} onChange={(event) => setDraft((current) => ({ ...current, requireHsm: event.target.checked }))} />
            </label>
            <button type="button" disabled={saving} onClick={() => void createPolicy()} className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-gold/50 bg-gold px-4 text-sm font-black text-black transition hover:bg-[#FDE68A] disabled:opacity-45">
              <Workflow className="h-4 w-4" />
              Create Policy
            </button>
          </div>
        </Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Storage Backend Integrations</SectionTitle><BackendCards rows={snapshot.storageBackends} /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Rotation Jobs And Expiry Automation</SectionTitle><JobList rows={snapshot.rotationJobs} empty="No rotation jobs are required right now." /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5"><SectionTitle>QRNG Entropy Configuration</SectionTitle><QrngPanel snapshot={snapshot} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>HSM / KMS / Vault Readiness</SectionTitle><ScoreDial value={snapshot.policies.find((row) => row.id === 'custody-backend')?.coverage || 0} label="Custody" color={CYAN} /></Panel>
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Exportability Control</SectionTitle><ScoreDial value={snapshot.metrics.totalKeys ? 100 - ((snapshot.metrics.exportableProductionKeys / snapshot.metrics.totalKeys) * 100) : 0} label="Blocked" color={snapshot.metrics.exportableProductionKeys ? GOLD : GREEN} /></Panel>
      </section>
    </>
  );
}

function PolicyTable({ rows }: { rows: Row[] }) {
  if (!rows.length) return <div className="grid min-h-[160px] place-items-center text-xs text-white/38">No QKMS policies available.</div>;
  return (
    <div className="space-y-3">
      {rows.map((row) => (
        <div key={row.id} className="rounded-md border border-white/8 bg-white/[0.025] p-4">
          <div className="flex items-start justify-between gap-3">
            <div><div className="text-sm font-semibold text-white">{row.name}</div><div className="mt-1 text-[10px] uppercase tracking-[0.08em] text-white/38">{row.owner || row.environmentScope || 'Tenant policy'}</div></div>
            <StatusPill value={row.status} />
          </div>
          {row.description ? <div className="mt-3 text-xs leading-5 text-white/48">{row.description}</div> : null}
          <div className="mt-4 flex items-center gap-3">
            <span className="h-2 flex-1 overflow-hidden rounded-full bg-white/6"><span className="block h-full rounded-full bg-gold" style={{ width: `${Math.max(4, Math.min(100, row.coverage || 0))}%` }} /></span>
            <span className="font-mono text-xs text-white/72">{percentFmt(row.coverage || 0)}</span>
          </div>
          <div className="mt-3 grid gap-2 text-[10px] uppercase tracking-[0.08em] text-white/38 md:grid-cols-3">
            <span>Rotate {row.rotationIntervalDays || row.rotation_interval_days || 'n/a'}d</span>
            <span>{row.requireHsm || row.require_hsm ? 'HSM required' : 'HSM optional'}</span>
            <span>{row.allowExport || row.allow_export ? 'Export review' : 'Export blocked'}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function BackendCards({ rows }: { rows: Row[] }) {
  if (!rows.length) return <div className="grid min-h-[160px] place-items-center text-xs text-white/38">No storage backend evidence yet.</div>;
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {rows.map((row) => (
        <div key={row.id || row.label} className="rounded-md border border-white/8 bg-white/[0.025] p-4">
          <div className="flex items-center justify-between gap-3">
            <span className="truncate text-sm font-semibold text-white">{row.label || row.provider}</span>
            <StatusPill value={row.readiness || 'observed'} />
          </div>
          <div className="mt-4 font-mono text-2xl text-white">{compactFmt(row.keys || row.count || 0)}</div>
          <div className="text-[10px] uppercase tracking-[0.08em] text-white/38">key records</div>
          <div className="mt-3 grid gap-1 text-[10px] uppercase tracking-[0.08em] text-white/38">
            <span>{row.provider || row.label}</span>
            <span>{row.location || 'tenant default'}</span>
            <span>{row.hsmBacked || row.hsm_backed ? 'HSM backed' : row.protectionLevel || 'software custody'}</span>
            <span>verified {shortTime(row.lastVerifiedAt || row.last_verified_at)}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function JobList({ rows, empty }: { rows: Row[]; empty: string }) {
  if (!rows.length) return <div className="grid min-h-[160px] place-items-center text-xs text-white/38">{empty}</div>;
  return (
    <div className="space-y-3">
      {rows.slice(0, 10).map((row) => (
        <div key={row.id} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
          <div className="flex items-start justify-between gap-3">
            <div><div className="text-sm font-semibold text-white">{row.title}</div><div className="mt-1 text-xs text-white/42">{row.owner}</div></div>
            <StatusPill value={row.status} />
          </div>
          <div className="mt-2 text-[10px] uppercase tracking-[0.08em] text-white/38">{row.priority} priority / {shortTime(row.dueAt)}</div>
        </div>
      ))}
    </div>
  );
}

function QrngPanel({ snapshot }: { snapshot: QkmsSnapshot }) {
  return (
    <div className="space-y-4">
      <div className="rounded-md border border-white/8 bg-white/[0.025] p-4">
        <div className="flex items-center justify-between gap-3"><span className="text-sm font-semibold text-white">Entropy Source</span><StatusPill value={snapshot.qrng.configured ? 'configured' : 'waiting'} /></div>
        <div className="mt-4 font-mono text-3xl text-white">{compactFmt(snapshot.qrng.events)}</div>
        <div className="text-[10px] uppercase tracking-[0.08em] text-white/38">QRNG events</div>
        {!snapshot.qrng.configured ? <div className="mt-3 rounded-md border border-gold/20 bg-gold/10 p-3 text-xs leading-5 text-gold">QRNG not configured - using approved system CSPRNG.</div> : null}
      </div>
      <Bars rows={snapshot.qrng.algorithms} empty="No QRNG algorithm telemetry yet." />
    </div>
  );
}

function ReadinessLayout({ snapshot, request, onNotice }: { snapshot: QkmsSnapshot; request: QkmsAction; onNotice: (message: string) => void }) {
  const [exporting, setExporting] = useState<string | null>(null);
  const runPrecheck = useCallback(async () => {
    try {
      const payload = await request('/precheck', { method: 'POST', body: JSON.stringify({ scope: 'qkms-readiness' }) });
      onNotice(`Migration gate: ${payload?.data?.decision || snapshot.metrics.migrationGateStatus}`);
    } catch (error) {
      onNotice(error instanceof Error ? error.message : 'Precheck failed');
    }
  }, [onNotice, request, snapshot.metrics.migrationGateStatus]);

  const runExport = useCallback(async (format: 'json' | 'csv' | 'pdf') => {
    setExporting(format);
    try {
      const payload = await request('/export', { method: 'POST', body: JSON.stringify({ format }) });
      if (format === 'pdf') {
        onNotice(payload?.data?.message || 'PDF export queued');
      } else {
        onNotice(`${format.toUpperCase()} export generated by QKMS API`);
      }
    } catch (error) {
      onNotice(error instanceof Error ? error.message : 'Export failed');
    } finally {
      setExporting(null);
    }
  }, [onNotice, request]);

  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Panel className="p-5"><SectionTitle>ML-KEM Readiness</SectionTitle><ScoreDial value={snapshot.readiness.mlKem} label="KEM" color={GREEN} /></Panel>
        <Panel className="p-5"><SectionTitle>ML-DSA / SLH-DSA</SectionTitle><ScoreDial value={snapshot.readiness.mlDsa} label="Sign" color={PURPLE} /></Panel>
        <Panel className="p-5"><SectionTitle>AES-256-GCM</SectionTitle><ScoreDial value={snapshot.readiness.symmetric} label="Sym" color={TEAL} /></Panel>
        <Panel className="p-5"><SectionTitle>SHA3 / HKDF-SHA3</SectionTitle><ScoreDial value={snapshot.readiness.hashKdf} label="KDF" color={GOLD} /></Panel>
        <Panel className="p-5"><SectionTitle>Hybrid TLS</SectionTitle><ScoreDial value={snapshot.readiness.hybridTls} label="TLS" color={CYAN} /></Panel>
        <Panel className="p-5"><SectionTitle>Certificate Migration</SectionTitle><ScoreDial value={snapshot.readiness.certificate} label="Cert" color={BLUE} /></Panel>
        <Panel className="p-5"><SectionTitle>Migration Precheck</SectionTitle><ScoreDial value={snapshot.readiness.migrationPrecheck} label="Gate" color={gateColor(snapshot.metrics.migrationGateStatus)} /></Panel>
        <Panel className="p-5">
          <SectionTitle>Readiness Actions</SectionTitle>
          <div className="grid gap-2">
            <button type="button" onClick={() => void runPrecheck()} className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-blue-400/40 bg-blue-500 px-3 text-xs font-black text-white transition hover:border-gold hover:bg-gold hover:text-black">
              <ShieldCheck className="h-4 w-4" />
              Run Precheck
            </button>
            <div className="grid grid-cols-3 gap-2">
              {(['json', 'csv', 'pdf'] as const).map((format) => (
                <button key={format} type="button" disabled={exporting === format} onClick={() => void runExport(format)} className="h-9 rounded-md border border-white/10 bg-white/[0.025] text-[10px] font-black uppercase tracking-[0.08em] text-white/62 transition hover:border-gold/50 hover:text-gold disabled:opacity-45">
                  {format}
                </button>
              ))}
            </div>
          </div>
        </Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Block / Warn / Allow Decisions</SectionTitle><DecisionList rows={snapshot.decisions} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Audit Evidence Exports</SectionTitle><EvidenceList rows={snapshot.auditEvidence} /></Panel>
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Compliance Reports</SectionTitle><ReportList rows={snapshot.reports} /></Panel>
      </section>
    </>
  );
}

function DecisionList({ rows }: { rows: Row[] }) {
  if (!rows.length) return <div className="grid min-h-[160px] place-items-center text-xs text-white/38">No migration gate decisions yet.</div>;
  return (
    <div className="space-y-3">
      {rows.map((row) => (
        <div key={row.id} className="flex items-center justify-between gap-3 rounded-md border border-white/8 bg-white/[0.025] p-3">
          <div><div className="text-sm font-semibold text-white">{row.label}</div><div className="text-xs text-white/38">{compactFmt(row.count || 0)} related record(s)</div></div>
          <StatusPill value={row.decision} />
        </div>
      ))}
    </div>
  );
}

function EvidenceList({ rows }: { rows: Row[] }) {
  if (!rows.length) return <div className="grid min-h-[160px] place-items-center text-xs text-white/38">No audit evidence available yet.</div>;
  return (
    <div className="space-y-3">
      {rows.slice(0, 10).map((row) => (
        <div key={row.id} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
          <div className="flex items-center justify-between gap-3"><span className="truncate text-sm font-semibold text-white">{row.title}</span><StatusPill value={row.status} /></div>
          <div className="mt-2 text-[10px] uppercase tracking-[0.08em] text-white/38">{row.source} / {shortTime(row.timestamp)}</div>
        </div>
      ))}
    </div>
  );
}

function ReportList({ rows }: { rows: Row[] }) {
  if (!rows.length) return <div className="grid min-h-[160px] place-items-center text-xs text-white/38">No compliance reports yet.</div>;
  return (
    <div className="space-y-3">
      {rows.map((row) => (
        <div key={row.id} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
          <div className="flex items-start justify-between gap-3"><span className="text-sm font-semibold text-white">{row.title}</span><StatusPill value={row.status} /></div>
          <div className="mt-3 font-mono text-xl text-white">{compactFmt(row.records || 0)}</div>
        </div>
      ))}
    </div>
  );
}

function Body({ mode, snapshot, request, onNotice }: { mode: QkmsMode; snapshot: QkmsSnapshot; request: QkmsAction; onNotice: (message: string) => void }) {
  if (mode === 'overview') return <OverviewLayout snapshot={snapshot} />;
  if (mode === 'inventory') return <InventoryLayout snapshot={snapshot} request={request} onNotice={onNotice} />;
  if (mode === 'governance') return <GovernanceLayout snapshot={snapshot} request={request} onNotice={onNotice} />;
  return <ReadinessLayout snapshot={snapshot} request={request} onNotice={onNotice} />;
}

export default function QkmsDashboard({ mode }: { mode: QkmsMode }) {
  const { snapshot, state, error, sseConnected, refresh, request } = useQkmsDashboard(mode);
  const [query, setQuery] = useState('');
  const [notice, setNotice] = useState<string | null>(null);

  const filteredSnapshot = useMemo(() => {
    if (!query.trim()) return snapshot;
    const lower = query.toLowerCase();
    return {
      ...snapshot,
      inventory: snapshot.inventory.filter((row) => `${row.name} ${row.algorithm} ${row.owner} ${row.assetName} ${row.backend} ${row.status}`.toLowerCase().includes(lower)),
      alerts: snapshot.alerts.filter((row) => `${row.title} ${row.detail} ${row.source}`.toLowerCase().includes(lower)),
    };
  }, [query, snapshot]);

  return (
    <main className="min-h-screen bg-[#050914] px-4 py-5 text-white md:px-6">
      <div className="mx-auto max-w-[1540px] space-y-4">
        <Header mode={mode} snapshot={snapshot} state={state} sseConnected={sseConnected} refresh={refresh} />
        {error ? <div className="rounded-md border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-200">{error}</div> : null}
        {notice ? <div className="rounded-md border border-gold/25 bg-gold/10 px-4 py-3 text-sm text-gold">{notice}</div> : null}
        <div className="flex flex-col gap-3 rounded-lg border border-white/8 bg-white/[0.025] p-3 md:flex-row md:items-center">
          <div className="flex min-w-0 flex-1 items-center gap-2 rounded-md border border-white/10 bg-black/20 px-3 py-2">
            <Search className="h-4 w-4 text-white/35" />
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search QKMS keys, owners, assets, algorithms" className="min-w-0 flex-1 bg-transparent text-sm text-white outline-none placeholder:text-white/30" />
          </div>
          <div className="flex flex-wrap gap-2 text-[10px] font-bold uppercase tracking-[0.08em] text-white/45">
            <span>{compactFmt(snapshot.telemetry.activeSources)} active sources</span>
            <span className="text-white/18">/</span>
            <span>{compactFmt(snapshot.telemetry.runningScans)} scans running</span>
            <span className="text-white/18">/</span>
            <span>{compactFmt(snapshot.telemetry.freshHeartbeats)} fresh beats</span>
          </div>
        </div>
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
          <Body mode={mode} snapshot={filteredSnapshot} request={request} onNotice={setNotice} />
        </motion.div>
      </div>
    </main>
  );
}
