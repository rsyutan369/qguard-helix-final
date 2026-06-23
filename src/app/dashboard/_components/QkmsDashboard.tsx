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

type QkmsMode = 'overview' | 'inventory' | 'governance' | 'readiness' | 'lifecycle' | 'rotation' | 'risk-analysis';
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

const ONE_DAY_MS = 24 * 60 * 60 * 1000;

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
  lifecycle: {
    segment: 'lifecycle',
    label: 'Key Lifecycle',
    subtitle: 'Full key lifecycle control plane — creation, classification, ownership, age, expiry, and decommission posture.',
    Icon: GitBranch,
  },
  rotation: {
    segment: 'rotation',
    label: 'Rotation Center',
    subtitle: 'Rotation health, due/overdue detection, rotation jobs, and expiry automation with audit evidence.',
    Icon: RefreshCw,
  },
  'risk-analysis': {
    segment: 'risk-analysis',
    label: 'Key Risk Analysis',
    subtitle: 'Key risk scoring, weak/deprecated algorithm exposure, custody gaps, and prioritized remediation.',
    Icon: ShieldAlert,
  },
};

const WORKFLOW: Array<{ mode: QkmsMode; href: string }> = [
  { mode: 'overview', href: '/dashboard/qkms/overview' },
  { mode: 'inventory', href: '/dashboard/qkms/inventory' },
  { mode: 'lifecycle', href: '/dashboard/qkms/lifecycle' },
  { mode: 'governance', href: '/dashboard/qkms/governance' },
  { mode: 'rotation', href: '/dashboard/qkms/rotation' },
  { mode: 'readiness', href: '/dashboard/qkms/readiness' },
  { mode: 'risk-analysis', href: '/dashboard/qkms/risk-analysis' },
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
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-7">
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

function KeyRowsTable({ rows, columns, empty, actions, onRowClick, selectedId }: { rows: KeyRecord[]; columns: Array<{ label: string; render: (key: KeyRecord) => ReactNode }>; empty: string; actions?: (key: KeyRecord) => ReactNode; onRowClick?: (key: KeyRecord) => void; selectedId?: string | null }) {
  if (!rows.length) return <div className="grid min-h-[160px] place-items-center text-xs text-white/38">{empty}</div>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead className="border-b border-white/10 text-[10px] uppercase tracking-[0.08em] text-white/38">
          <tr>
            {columns.map((column) => <th key={column.label} className="py-3 pr-3">{column.label}</th>)}
            {actions ? <th className="py-3 text-right">Actions</th> : null}
          </tr>
        </thead>
        <tbody className="divide-y divide-white/6">
          {rows.map((key) => (
            <tr key={key.id} onClick={onRowClick ? () => onRowClick(key) : undefined} className={cn('hover:bg-white/[0.035]', onRowClick && 'cursor-pointer', selectedId === key.id && 'bg-gold/8')}>
              {columns.map((column) => <td key={column.label} className="py-3 pr-3 align-top">{column.render(key)}</td>)}
              {actions ? <td className="py-3 text-right">{actions(key)}</td> : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function expiryMs(value: string | null) {
  if (!value) return Number.POSITIVE_INFINITY;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : Number.POSITIVE_INFINITY;
}

function ageDays(value: string | null) {
  if (!value) return 0;
  const ms = new Date(value).getTime();
  if (!Number.isFinite(ms)) return 0;
  return Math.max(0, Math.round((Date.now() - ms) / ONE_DAY_MS));
}

function distributionRows(values: string[], total: number) {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) || 0) + 1);
  return Array.from(counts.entries())
    .map(([label, count]) => ({ label, count, percent: total ? (count / total) * 100 : 0 }))
    .sort((a, b) => b.count - a.count);
}

/* ---------------- Shared lifecycle / rotation / risk derivations ---------------- */

function lifecycleState(key: KeyRecord): string {
  const s = (key.status || '').toLowerCase();
  const rot = (key.rotationStatus || '').toLowerCase();
  if (s.includes('destroy')) return 'Destroyed';
  if (s.includes('archiv')) return 'Archived';
  if (s.includes('revok')) return 'Revoked';
  if (rot.includes('complete') || s.includes('rotated')) return 'Rotated';
  if (key.rotationRequired || /due|overdue|rotating|blocked/.test(rot)) return 'Pending Rotation';
  if (expiryMs(key.expiresAt) < Date.now() || key.weak || s.includes('deprecat') || s.includes('expired')) return 'Deprecated';
  if (s.includes('suspend') || s.includes('inactive') || s.includes('disabled')) return 'Suspended';
  if (s.includes('pending')) return 'Pending Activation';
  if (s.includes('generat')) return 'Generated';
  return 'Active';
}

const LIFECYCLE_STATES = ['Generated', 'Pending Activation', 'Active', 'Suspended', 'Deprecated', 'Pending Rotation', 'Rotated', 'Revoked', 'Destroyed', 'Archived'];

function rotationReason(key: KeyRecord): string {
  if (/compromis/i.test(key.status || '')) return 'Compromise Suspected';
  if (expiryMs(key.expiresAt) < Date.now()) return 'Key Expiration';
  if (key.weak) return 'Algorithm Deprecation';
  if (/classical|unknown/i.test(key.pqcReadiness || '') && !key.quantumReady) return 'PQC Migration';
  if (key.orphaned) return 'Owner Change';
  if (key.exportable) return 'Policy Violation';
  if (key.nearExpiry) return 'Key Expiration';
  if ((key.certificateLinks || 0) > 0) return 'Certificate Renewal';
  return 'Scheduled Rotation';
}

function quantumFamily(algorithm: string): string {
  const a = (algorithm || '').toUpperCase();
  if (/ML-KEM|KYBER/.test(a)) return 'ML-KEM';
  if (/ML-DSA|DILITHIUM|SLH-DSA|SPHINCS|FALCON/.test(a)) return 'ML-DSA / SLH-DSA';
  if (/HYBRID|X25519\+|ED25519\+/.test(a)) return 'Hybrid';
  if (/RSA/.test(a)) return 'RSA';
  if (/ECDSA/.test(a)) return 'ECDSA';
  if (/ECDH/.test(a)) return 'ECDH';
  if (/\bDSA\b/.test(a)) return 'DSA';
  if (/\bDH\b|DIFFIE/.test(a)) return 'DH';
  if (/ECC|P-256|P-384|P-521|SECP/.test(a)) return 'ECC';
  if (/AES/.test(a)) return 'AES (Symmetric)';
  if (/SHA3|HKDF/.test(a)) return 'SHA3 / HKDF';
  if (/X25519|ED25519|CURVE25519/.test(a)) return 'Curve25519';
  return 'Other / Unknown';
}

function quantumExposureStatus(key: KeyRecord): string {
  const p = (key.pqcReadiness || '').toLowerCase();
  if (key.quantumReady || p.includes('quantum-ready') || (p.includes('ready') && !p.includes('not'))) return 'PQC-Ready';
  if (p.includes('hybrid')) return 'Hybrid-Protected';
  if (p.includes('classical')) return 'Classical-Only';
  const fam = quantumFamily(key.algorithm);
  if (['RSA', 'ECDSA', 'ECDH', 'ECC', 'DSA', 'DH'].includes(fam)) return 'Classical-Only';
  if (fam === 'Hybrid') return 'Hybrid-Protected';
  if (fam === 'ML-KEM' || fam === 'ML-DSA / SLH-DSA') return 'PQC-Ready';
  return 'Unknown';
}

const RISK_WEIGHTS: Array<{ key: 'algorithm' | 'quantum' | 'lifecycle' | 'rotation' | 'ownership' | 'access' | 'dependency'; label: string; weight: number }> = [
  { key: 'algorithm', label: 'Algorithm Risk', weight: 0.25 },
  { key: 'quantum', label: 'Quantum Exposure', weight: 0.2 },
  { key: 'lifecycle', label: 'Lifecycle State', weight: 0.15 },
  { key: 'rotation', label: 'Rotation Compliance', weight: 0.15 },
  { key: 'ownership', label: 'Ownership & Governance', weight: 0.1 },
  { key: 'access', label: 'Access Pattern', weight: 0.1 },
  { key: 'dependency', label: 'Dependency Criticality', weight: 0.05 },
];

function keyRiskFactors(key: KeyRecord) {
  const algorithm = key.weak ? 90 : /rsa|ecc|ecdsa|ecdh|dsa|dh|sha-1|sha1|md5|3des|rc4/i.test(key.algorithm || '') ? 72 : key.quantumReady ? 8 : 32;
  const exposure = quantumExposureStatus(key);
  const quantum = exposure === 'PQC-Ready' ? 8 : exposure === 'Hybrid-Protected' ? 22 : exposure === 'Classical-Only' ? 85 : 55;
  const lifecycle = expiryMs(key.expiresAt) < Date.now() ? 90 : key.nearExpiry ? 58 : /deprecat|revok|suspend/i.test(key.status || '') ? 70 : key.orphaned ? 48 : 14;
  const rotation = /overdue|failed/i.test(key.rotationStatus || '') ? 88 : key.rotationRequired ? 78 : !key.lastRotatedAt ? 52 : 14;
  const ownership = key.orphaned ? 90 : /unassigned|unknown/i.test(key.owner || '') ? 68 : 10;
  const access = key.exportable ? 82 : (key.runtimeUsage || 0) > 1000 ? 56 : (key.runtimeUsage || 0) > 200 ? 34 : 12;
  const dependency = Math.min(100, (key.certificateLinks || 0) * 16 + (key.linkedAssets?.length || 0) * 10 + (key.environment === 'production' ? 28 : 0));
  const factors = { algorithm, quantum, lifecycle, rotation, ownership, access, dependency };
  const weighted = Math.round(algorithm * 0.25 + quantum * 0.2 + lifecycle * 0.15 + rotation * 0.15 + ownership * 0.1 + access * 0.1 + dependency * 0.05);
  return { factors, weighted };
}

function riskLevelLabel(score: number): string {
  if (score >= 75) return 'Critical';
  if (score >= 50) return 'High';
  if (score >= 25) return 'Medium';
  return 'Low';
}

function riskLevelColor(score: number): string {
  if (score >= 75) return RED;
  if (score >= 50) return ORANGE;
  if (score >= 25) return GOLD;
  return GREEN;
}

/* ---------------- Shared lifecycle / rotation / risk components ---------------- */

function LifecycleTimeline({ keyRecord }: { keyRecord: KeyRecord }) {
  const events = useMemo(() => {
    const list: Array<{ when: string; label: string; tone: string }> = [];
    const push = (when: unknown, label: string, tone: string) => { if (when) list.push({ when: String(when), label, tone }); };
    push(keyRecord.createdAt, 'Created / Generated', BLUE);
    push((keyRecord.metadata as Row)?.activated_at, 'Activated', GREEN);
    (keyRecord.rotationHistory || []).slice(0, 6).forEach((row) => push(row.created_at || row.timestamp || row.startedAt, row.reason || 'Rotation event', CYAN));
    push(keyRecord.lastRotatedAt, 'Last Rotated', TEAL);
    (keyRecord.runtimeEvents || []).slice(0, 4).forEach((row) => push(row.observed_at || row.created_at, 'Runtime usage observed', PURPLE));
    (keyRecord.auditTrail || []).slice(0, 6).forEach((row) => push(row.created_at || row.timestamp, row.event_type || row.summary || 'Audit event', GOLD));
    push(keyRecord.expiresAt, expiryMs(keyRecord.expiresAt) < Date.now() ? 'Expired' : 'Scheduled expiry', expiryMs(keyRecord.expiresAt) < Date.now() ? RED : GOLD);
    return list.filter((event) => Number.isFinite(new Date(event.when).getTime())).sort((a, b) => new Date(a.when).getTime() - new Date(b.when).getTime());
  }, [keyRecord]);
  if (!events.length) return <div className="grid min-h-[120px] place-items-center text-xs text-white/38">No lifecycle events recorded yet.</div>;
  return (
    <div className="space-y-3 border-l border-white/10 pl-4">
      {events.map((event, index) => (
        <div key={`${event.when}-${index}`} className="relative">
          <span className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full" style={{ backgroundColor: event.tone, boxShadow: `0 0 10px ${event.tone}99` }} />
          <div className="text-xs font-semibold text-white/80">{event.label}</div>
          <div className="text-[10px] text-white/38">{longDate(event.when)} · {shortTime(event.when)}</div>
        </div>
      ))}
    </div>
  );
}

function KeyActions({ keyRecord, request, onNotice }: { keyRecord: KeyRecord; request: QkmsAction; onNotice: (message: string) => void }) {
  const [pending, setPending] = useState<string | null>(null);
  const run = useCallback(async (action: 'assign-owner' | 'rotate' | 'revoke', confirmText?: string) => {
    if (confirmText && !window.confirm(confirmText)) return;
    setPending(action);
    try {
      if (action === 'assign-owner') {
        const owner = window.prompt('Assign owner / team for this key', /unassigned|unknown/i.test(keyRecord.owner || '') ? '' : keyRecord.owner);
        if (!owner) { setPending(null); return; }
        await request(`/keys/${encodeURIComponent(keyRecord.id)}/assign-owner`, { method: 'POST', body: JSON.stringify({ owner }) });
        onNotice(`Owner assigned to ${keyRecord.keyAlias || keyRecord.name}`);
      } else if (action === 'rotate') {
        await request(`/keys/${encodeURIComponent(keyRecord.id)}/rotate`, { method: 'POST', body: JSON.stringify({ reason: `Schedule rotation — ${rotationReason(keyRecord)}`, priority: keyRecord.riskScore >= 60 ? 'high' : 'medium' }) });
        onNotice(`Rotation scheduled for ${keyRecord.keyAlias || keyRecord.name}`);
      } else {
        await request(`/keys/${encodeURIComponent(keyRecord.id)}/revoke`, { method: 'POST', body: JSON.stringify({ reason: 'Revoked from QKMS lifecycle action' }) });
        onNotice(`${keyRecord.keyAlias || keyRecord.name} marked for revocation`);
      }
    } catch (error) {
      onNotice(error instanceof Error ? error.message : 'QKMS action failed');
    } finally {
      setPending(null);
    }
  }, [keyRecord, onNotice, request]);
  const base = 'inline-flex h-8 items-center gap-1 rounded-md border px-2.5 text-[10px] font-bold transition disabled:opacity-40';
  return (
    <div className="flex flex-wrap gap-1.5">
      <button type="button" disabled={pending === 'assign-owner'} onClick={() => void run('assign-owner')} className={cn(base, 'border-white/10 bg-white/[0.025] text-white/62 hover:border-gold/50 hover:text-gold')}><BadgeCheck className="h-3.5 w-3.5" />Assign Owner</button>
      <button type="button" disabled={pending === 'rotate'} onClick={() => void run('rotate')} className={cn(base, 'border-white/10 bg-white/[0.025] text-white/62 hover:border-gold/50 hover:text-gold')}><RefreshCw className={cn('h-3.5 w-3.5', pending === 'rotate' && 'animate-spin')} />Schedule Rotation</button>
      <a href="/dashboard/qkms/risk-analysis" className={cn(base, 'border-white/10 bg-white/[0.025] text-white/62 no-underline hover:border-gold/50 hover:text-gold')}><ShieldAlert className="h-3.5 w-3.5" />Risk Analysis</a>
      <button type="button" disabled={pending === 'revoke'} onClick={() => void run('revoke', `Revoke ${keyRecord.keyAlias || keyRecord.name}? This is a governed, audited action.`)} className={cn(base, 'border-red-500/20 bg-red-500/10 text-red-200 hover:border-red-300')}><ShieldAlert className="h-3.5 w-3.5" />Revoke</button>
    </div>
  );
}

function KeyDetailDrawer({ keyRecord, request, onNotice, variant }: { keyRecord: KeyRecord; request: QkmsAction; onNotice: (message: string) => void; variant: 'lifecycle' | 'risk' }) {
  const state = lifecycleState(keyRecord);
  const { factors, weighted } = keyRiskFactors(keyRecord);
  const lastUsed = (keyRecord.runtimeEvents?.[0]?.observed_at as string) || (keyRecord.runtimeEvents?.[0]?.created_at as string) || keyRecord.updatedAt;
  return (
    <div className="grid gap-4 xl:grid-cols-[1.05fr_2fr]">
      <div className="rounded-md border border-white/8 bg-white/[0.025] p-4">
        <div className="text-lg font-semibold text-white">{keyRecord.keyAlias || keyRecord.name}</div>
        <div className="mt-1 break-all font-mono text-[10px] text-white/42">{keyRecord.source} / {keyRecord.id}</div>
        <div className="mt-4 flex flex-wrap gap-2">
          <StatusPill value={state} />
          <StatusPill value={quantumExposureStatus(keyRecord)} />
          <StatusPill value={keyRecord.complianceStatus || 'Evidence needed'} />
        </div>
        <div className="mt-5 grid grid-cols-2 gap-3">
          <div>
            <div className="text-[10px] uppercase tracking-[0.08em] text-white/38">Weighted risk</div>
            <div className="mt-1 font-mono text-4xl" style={{ color: riskLevelColor(weighted) }}>{integerFmt(weighted)}</div>
            <div className="text-[10px] font-bold" style={{ color: riskLevelColor(weighted) }}>{riskLevelLabel(weighted)}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-[0.08em] text-white/38">Trust score</div>
            <div className="mt-1 font-mono text-4xl text-white">{integerFmt(keyRecord.trustScore)}</div>
          </div>
        </div>
        <div className="mt-4 rounded-md border border-white/8 bg-black/20 p-3 text-xs leading-5 text-white/62">{keyRecord.riskExplanation || 'No risk explanation evidence recorded.'}</div>
        <div className="mt-3 rounded-md border border-gold/20 bg-gold/10 p-3 text-xs leading-5 text-gold">{keyRecord.recommendedAction || 'No recommended action.'}</div>
        <div className="mt-4"><KeyActions keyRecord={keyRecord} request={request} onNotice={onNotice} /></div>
      </div>
      <div className="grid gap-4">
        <div className="grid gap-3 text-sm md:grid-cols-2 xl:grid-cols-4">
          {([
            ['Algorithm', keyRecord.algorithm || 'Unknown'],
            ['Key Type', keyRecord.keyType || 'Cryptographic key'],
            ['Owner', keyRecord.owner],
            ['Environment', keyRecord.environment],
            ['Purpose', keyRecord.purpose],
            ['Backend', keyRecord.backend],
            ['Quantum Exposure', quantumExposureStatus(keyRecord)],
            ['Entropy Source', keyRecord.entropySource],
            ['Created', longDate(keyRecord.createdAt)],
            ['Last Rotated', keyRecord.lastRotatedAt ? longDate(keyRecord.lastRotatedAt) : 'Never'],
            ['Expires', keyRecord.expiresAt ? longDate(keyRecord.expiresAt) : 'No expiry'],
            ['Last Used', lastUsed ? shortTime(lastUsed) : 'No usage'],
          ] as Array<[string, string]>).map(([label, value]) => (
            <div key={label} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
              <div className="text-[10px] uppercase tracking-[0.08em] text-white/38">{label}</div>
              <div className="mt-2 break-words text-white/76">{value}</div>
            </div>
          ))}
        </div>
        {variant === 'risk' ? (
          <div className="rounded-md border border-white/8 bg-white/[0.025] p-4">
            <div className="mb-3 text-[10px] uppercase tracking-[0.08em] text-white/38">Weighted Risk Factor Breakdown</div>
            <Bars rows={RISK_WEIGHTS.map((weight) => ({ label: `${weight.label} (${Math.round(weight.weight * 100)}%)`, count: factors[weight.key], percent: factors[weight.key] }))} empty="No risk factors." />
          </div>
        ) : (
          <div className="rounded-md border border-white/8 bg-white/[0.025] p-4">
            <div className="mb-3 text-[10px] uppercase tracking-[0.08em] text-white/38">Lifecycle Timeline</div>
            <LifecycleTimeline keyRecord={keyRecord} />
          </div>
        )}
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <EvidenceMiniList title="Linked Certificates" rows={keyRecord.linkedCertificates} empty="No linked certificates." />
          <EvidenceMiniList title="Workloads / Migration" rows={keyRecord.linkedMigrationJobs} empty="No linked workloads." />
          <EvidenceMiniList title="Runtime / Access" rows={keyRecord.runtimeEvents} empty="No usage / access events." />
          <EvidenceMiniList title="Audit History" rows={keyRecord.auditTrail} empty="No audit history." />
        </div>
        <div className="rounded-md border border-white/8 bg-white/[0.025] p-4">
          <div className="text-[10px] uppercase tracking-[0.08em] text-white/38">PQC readiness explanation</div>
          <div className="mt-2 text-sm leading-6 text-white/68">{keyRecord.pqcExplanation || 'No PQC readiness explanation recorded.'}</div>
        </div>
      </div>
    </div>
  );
}

const ROTATION_WORKFLOW = ['Select key', 'Analyze dependencies', 'Validate compatibility', 'Generate replacement key', 'Update linked assets', 'Validate trust chains', 'Monitor usage', 'Retire old key', 'Confirm completion'];

function WorkflowStepper({ keyRecord, jobs }: { keyRecord: KeyRecord | null; jobs: Row[] }) {
  const job = keyRecord ? jobs.find((row) => String(row.key_id || row.keyId || '').includes(keyRecord.id) || String(row.title || '').includes(keyRecord.keyAlias || keyRecord.name)) : null;
  const status = String(job?.status || '').toLowerCase();
  const completedSteps = !keyRecord ? 0 : /complete|done/.test(status) ? 9 : /progress|rotating/.test(status) ? 6 : /pending/.test(status) || keyRecord.rotationRequired ? 2 : 1;
  return (
    <ol className="grid gap-2 md:grid-cols-3">
      {ROTATION_WORKFLOW.map((step, index) => {
        const done = index < completedSteps;
        const active = index === completedSteps;
        return (
          <li key={step} className={cn('flex items-center gap-2 rounded-md border px-3 py-2 text-xs', done ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-100' : active ? 'border-gold/40 bg-gold/10 text-gold' : 'border-white/8 bg-white/[0.025] text-white/45')}>
            <span className={cn('grid h-5 w-5 shrink-0 place-items-center rounded-full text-[10px] font-black', done ? 'bg-emerald-400 text-black' : active ? 'bg-gold text-black' : 'bg-white/10 text-white/50')}>{done ? '✓' : index + 1}</span>
            {step}
          </li>
        );
      })}
    </ol>
  );
}

function RotationImpactPanel({ keyRecord }: { keyRecord: KeyRecord | null }) {
  if (!keyRecord) return <div className="grid min-h-[160px] place-items-center text-xs text-white/38">Select a key from the rotation queue to analyze impact.</div>;
  const certs = keyRecord.linkedCertificates?.length || keyRecord.certificateLinks || 0;
  const assets = keyRecord.linkedAssets?.length || 0;
  const workloads = keyRecord.linkedMigrationJobs?.length || 0;
  const runtime = keyRecord.runtimeUsage || keyRecord.runtimeEvents?.length || 0;
  const blast = certs + assets + workloads;
  const downtime = keyRecord.environment === 'production' && blast > 2 ? 'High' : blast > 0 ? 'Medium' : 'Low';
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        {([['Certificates', certs], ['Assets', assets], ['Workloads', workloads], ['Runtime usage', runtime]] as Array<[string, number]>).map(([label, value]) => (
          <div key={label} className="rounded-md border border-white/8 bg-white/[0.025] p-3"><div className="font-mono text-2xl text-white">{compactFmt(value)}</div><div className="text-[10px] uppercase tracking-[0.08em] text-white/38">{label}</div></div>
        ))}
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div className="rounded-md border border-white/8 bg-black/20 p-3"><div className="text-[10px] uppercase tracking-[0.08em] text-white/38">Blast radius</div><div className="mt-1 font-mono text-xl text-white">{integerFmt(blast)} dependents</div></div>
        <div className="rounded-md border border-white/8 bg-black/20 p-3"><div className="text-[10px] uppercase tracking-[0.08em] text-white/38">Downtime risk</div><div className="mt-1 text-xl font-bold" style={{ color: gateColor(downtime === 'High' ? 'block' : downtime === 'Medium' ? 'warn' : 'allow') }}>{downtime}</div></div>
      </div>
      <div className="rounded-md border border-gold/20 bg-gold/10 p-3 text-xs leading-5 text-gold">Rollback plan: retain the previous key in deprecated state until the replacement is validated across all {integerFmt(blast)} dependents and trust chains; auto-rollback on failed crypto operations or trust-chain breakage.</div>
    </div>
  );
}

function RotationValidationPanel({ keyRecord }: { keyRecord: KeyRecord | null }) {
  if (!keyRecord) return <div className="grid min-h-[120px] place-items-center text-xs text-white/38">Select a key to view post-rotation validation.</div>;
  const checks = [
    { label: 'New key active', ok: !keyRecord.rotationRequired },
    { label: 'Old key deprecated / retired', ok: Boolean(keyRecord.lastRotatedAt) },
    { label: 'Linked certificates valid', ok: (keyRecord.linkedCertificates?.length || 0) === 0 || !keyRecord.weak },
    { label: 'Trust chains intact', ok: keyRecord.trustScore >= 50 },
    { label: 'No failed crypto operations', ok: !/failed/i.test(keyRecord.rotationStatus || '') },
    { label: 'Telemetry confirms usage', ok: (keyRecord.runtimeUsage || 0) > 0 },
  ];
  return (
    <div className="space-y-2">
      {checks.map((check) => (
        <div key={check.label} className="flex items-center justify-between gap-3 rounded-md border border-white/8 bg-white/[0.025] px-3 py-2 text-xs">
          <span className="text-white/72">{check.label}</span>
          <StatusPill value={check.ok ? 'validated' : 'review'} />
        </div>
      ))}
    </div>
  );
}

/* ---------------- Lifecycle layout ---------------- */

function LifecycleLayout({ snapshot, request, onNotice }: { snapshot: QkmsSnapshot; request: QkmsAction; onNotice: (message: string) => void }) {
  const inventory = snapshot.inventory;
  const total = inventory.length;
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [stateFilter, setStateFilter] = useState<string>('all');

  const stateOf = useCallback((key: KeyRecord) => lifecycleState(key), []);
  const stateCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const key of inventory) counts.set(stateOf(key), (counts.get(stateOf(key)) || 0) + 1);
    return counts;
  }, [inventory, stateOf]);

  const counts = useMemo(() => {
    const get = (state: string) => stateCounts.get(state) || 0;
    return {
      active: get('Active'),
      pending: get('Pending Activation') + get('Generated'),
      deprecated: get('Deprecated'),
      expired: inventory.filter((key) => expiryMs(key.expiresAt) < Date.now()).length,
      revoked: get('Revoked') + get('Destroyed'),
      orphaned: snapshot.metrics.orphanedKeys,
      noPolicy: inventory.filter((key) => !key.lastRotatedAt && !key.rotationStatus).length,
    };
  }, [stateCounts, inventory, snapshot.metrics.orphanedKeys]);

  const filtered = useMemo(() => (stateFilter === 'all' ? inventory : inventory.filter((key) => stateOf(key) === stateFilter)), [inventory, stateFilter, stateOf]);
  const selected = filtered.find((key) => key.id === selectedId) || filtered[0] || null;
  const typeRows = distributionRows(inventory.map((key) => key.keyType || 'Cryptographic key'), total).slice(0, 8);

  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile icon={KeyRound} label="Total Keys" value={compactFmt(total)} detail="under lifecycle control" color={PURPLE} />
        <MetricTile icon={ShieldCheck} label="Active Keys" value={compactFmt(counts.active)} detail={`${percentFmt(total ? (counts.active / total) * 100 : 0)} of inventory`} color={GREEN} />
        <MetricTile icon={Sparkles} label="Pending Activation" value={compactFmt(counts.pending)} detail="generated / awaiting activation" color={BLUE} />
        <MetricTile icon={AlertTriangle} label="Deprecated Keys" value={compactFmt(counts.deprecated)} detail="weak or end-of-life" color={GOLD} />
        <MetricTile icon={CircleGauge} label="Expired Keys" value={compactFmt(counts.expired)} detail="past expiry date" color={RED} />
        <MetricTile icon={ShieldAlert} label="Revoked / Destroyed" value={compactFmt(counts.revoked)} detail="terminated key material" color={RED} />
        <MetricTile icon={Fingerprint} label="Orphaned Keys" value={compactFmt(counts.orphaned)} detail="no owner mapping" color={ORANGE} />
        <MetricTile icon={RefreshCw} label="No Rotation Policy" value={compactFmt(counts.noPolicy)} detail="missing rotation governance" color={CYAN} />
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7">
          <SectionTitle suffix={<span className="text-[10px] text-white/38">Discover → Classify → Own → Enforce → Rotate → Validate → Prove</span>}>Key Lifecycle Control Plane</SectionTitle>
          <LifecycleWorkflow snapshot={snapshot} />
        </Panel>
        <Panel className="p-5 xl:col-span-5">
          <SectionTitle suffix={<button type="button" onClick={() => setStateFilter('all')} className="text-[10px] text-white/45 hover:text-gold">Clear filter</button>}>Lifecycle State Distribution</SectionTitle>
          <div className="grid grid-cols-2 gap-2">
            {LIFECYCLE_STATES.map((state) => {
              const count = stateCounts.get(state) || 0;
              const active = stateFilter === state;
              return (
                <button key={state} type="button" onClick={() => setStateFilter(active ? 'all' : state)} className={cn('flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-left text-xs transition', active ? 'border-gold/55 bg-gold/12' : 'border-white/8 bg-white/[0.025] hover:border-gold/35')}>
                  <span className="flex items-center gap-2 truncate text-white/70"><span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: gateColor(state.toLowerCase().includes('revok') || state.toLowerCase().includes('destroy') ? 'block' : state.toLowerCase().includes('deprecat') || state.toLowerCase().includes('suspend') || state.toLowerCase().includes('pending rotation') ? 'warn' : state === 'Active' || state === 'Rotated' ? 'allow' : 'info') }} />{state}</span>
                  <span className="font-mono text-white/80">{compactFmt(count)}</span>
                </button>
              );
            })}
          </div>
        </Panel>
      </section>

      <section>
        <Panel className="p-5">
          <SectionTitle suffix={<span className="text-[10px] text-white/38">{compactFmt(filtered.length)} / {compactFmt(total)} keys{stateFilter !== 'all' ? ` · ${stateFilter}` : ''}</span>}>Key Inventory & Lifecycle State</SectionTitle>
          <KeyRowsTable
            rows={filtered.slice(0, 14)}
            empty="No keys discovered for this lifecycle filter."
            onRowClick={(key) => setSelectedId(key.id)}
            selectedId={selected?.id}
            columns={[
              { label: 'Key / Alias', render: (key) => <div><div className="font-semibold text-white">{key.keyAlias || key.name}</div><div className="font-mono text-[10px] text-white/38">{key.algorithm || 'Unknown'}</div></div> },
              { label: 'Owner', render: (key) => <span className="text-white/62">{key.owner}</span> },
              { label: 'Env', render: (key) => <StatusPill value={key.environment || 'unknown'} /> },
              { label: 'Created', render: (key) => <span className="text-white/55">{longDate(key.createdAt)}</span> },
              { label: 'Expiry', render: (key) => <span className="text-white/55">{key.expiresAt ? longDate(key.expiresAt) : 'No expiry'}</span> },
              { label: 'Lifecycle State', render: (key) => <StatusPill value={stateOf(key)} /> },
              { label: 'PQC', render: (key) => <StatusPill value={quantumExposureStatus(key)} /> },
              { label: 'Risk', render: (key) => <span className="font-mono font-bold" style={{ color: riskLevelColor(keyRiskFactors(key).weighted) }}>{integerFmt(keyRiskFactors(key).weighted)}</span> },
            ]}
          />
        </Panel>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-9">
          <SectionTitle>Key Detail & Lifecycle Timeline</SectionTitle>
          {selected ? <KeyDetailDrawer keyRecord={selected} request={request} onNotice={onNotice} variant="lifecycle" /> : <div className="grid min-h-[200px] place-items-center text-xs text-white/38">No keys discovered yet.</div>}
        </Panel>
        <Panel className="p-5 xl:col-span-3">
          <SectionTitle>Key Type Portfolio</SectionTitle>
          <Bars rows={typeRows} empty="No key categories classified yet." />
        </Panel>
      </section>
    </>
  );
}

/* ---------------- Rotation layout ---------------- */

function RotationLayout({ snapshot, request, onNotice }: { snapshot: QkmsSnapshot; request: QkmsAction; onNotice: (message: string) => void }) {
  const inventory = snapshot.inventory;
  const total = inventory.length;
  const [pendingId, setPendingId] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [workflowBusy, setWorkflowBusy] = useState<string | null>(null);

  const statusOf = useCallback((key: KeyRecord) => (key.rotationStatus || (key.rotationRequired ? 'Due Soon' : 'Healthy')).toString(), []);
  const grouped = useMemo(() => distributionRows(inventory.map((key) => statusOf(key)), total), [inventory, total, statusOf]);

  const overdue = inventory.filter((key) => /overdue|expired|failed/i.test(statusOf(key)));
  const dueSoon = inventory.filter((key) => /due|rotating|blocked/i.test(statusOf(key)));
  const healthy = inventory.filter((key) => /healthy|completed/i.test(statusOf(key)));
  const noPolicy = inventory.filter((key) => !key.lastRotatedAt && !key.rotationStatus).length;
  const appsImpacted = inventory.reduce((sum, key) => sum + (key.linkedMigrationJobs?.length || 0) + (key.linkedAssets?.length || 0), 0);

  const dueForRotation = useMemo(
    () => [...inventory].filter((key) => key.rotationRequired || /due|overdue|blocked|failed/i.test(statusOf(key))).sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0)).slice(0, 14),
    [inventory, statusOf],
  );
  const selected = dueForRotation.find((key) => key.id === selectedId) || dueForRotation[0] || null;

  const activeJobs = snapshot.rotationJobs.filter((row) => !/completed|failed|done/i.test(String(row.status || ''))).length;
  const completedJobs = snapshot.rotationJobs.filter((row) => /completed|done/i.test(String(row.status || ''))).length;
  const failedJobs = snapshot.rotationJobs.filter((row) => /failed/i.test(String(row.status || ''))).length;
  const rotationHealth = total ? Math.round((healthy.length / total) * 100) : 0;

  const rotateKey = useCallback(async (key: KeyRecord) => {
    setPendingId(key.id);
    try {
      await request(`/keys/${encodeURIComponent(key.id)}/rotate`, { method: 'POST', body: JSON.stringify({ reason: `Rotate ${key.keyAlias || key.name} — ${rotationReason(key)}`, priority: key.riskScore >= 60 ? 'high' : 'medium' }) });
      onNotice(`Rotation job created for ${key.keyAlias || key.name}`);
    } catch (error) {
      onNotice(error instanceof Error ? error.message : 'Rotation failed');
    } finally {
      setPendingId(null);
    }
  }, [onNotice, request]);

  const runWorkflowAction = useCallback(async (action: 'precheck' | 'dry-run' | 'start' | 'export') => {
    if (!selected && action !== 'precheck') { onNotice('Select a key from the rotation queue first.'); return; }
    setWorkflowBusy(action);
    try {
      if (action === 'precheck' || action === 'dry-run') {
        const payload = await request('/precheck', { method: 'POST', body: JSON.stringify({ scope: action === 'dry-run' ? 'rotation-dry-run' : 'rotation-precheck', keyId: selected?.id }) });
        onNotice(`${action === 'dry-run' ? 'Dry run' : 'Precheck'}: ${payload?.data?.decision || snapshot.metrics.migrationGateStatus}`);
      } else if (action === 'start' && selected) {
        await rotateKey(selected);
      } else if (action === 'export') {
        await request('/export', { method: 'POST', body: JSON.stringify({ format: 'json', scope: 'rotation-evidence' }) });
        onNotice('Rotation evidence exported by QKMS API');
      }
    } catch (error) {
      onNotice(error instanceof Error ? error.message : 'Rotation workflow action failed');
    } finally {
      setWorkflowBusy(null);
    }
  }, [selected, request, onNotice, rotateKey, snapshot.metrics.migrationGateStatus]);

  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile icon={RefreshCw} label="Keys Due For Rotation" value={compactFmt(dueSoon.length + overdue.length)} detail="due or overdue" color={CYAN} />
        <MetricTile icon={AlertTriangle} label="Overdue Rotations" value={compactFmt(overdue.length)} detail="past rotation deadline" color={RED} />
        <MetricTile icon={Workflow} label="In Progress" value={compactFmt(activeJobs)} detail="rotation jobs in flight" color={BLUE} />
        <MetricTile icon={BadgeCheck} label="Successful Rotations" value={compactFmt(completedJobs)} detail="rotation evidence recorded" color={GREEN} />
        <MetricTile icon={ShieldAlert} label="Failed Rotations" value={compactFmt(failedJobs)} detail="require retry / rollback" color={RED} />
        <MetricTile icon={CircleGauge} label="No Rotation Policy" value={compactFmt(noPolicy)} detail="missing rotation governance" color={GOLD} />
        <MetricTile icon={Network} label="Apps / Assets Impacted" value={compactFmt(appsImpacted)} detail="rotation blast radius" color={PURPLE} />
        <MetricTile icon={ShieldCheck} label="Rotation Health" value={percentFmt(rotationHealth)} detail="healthy of inventory" color={rotationHealth >= 70 ? GREEN : rotationHealth >= 40 ? GOLD : RED} />
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Rotation Health</SectionTitle><ScoreDial value={rotationHealth} label="Healthy" color={rotationHealth >= 70 ? GREEN : rotationHealth >= 40 ? GOLD : RED} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Rotation Status Distribution</SectionTitle><Bars rows={grouped} empty="No rotation statuses available yet." /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Rotation Jobs & Expiry Automation</SectionTitle><JobList rows={snapshot.rotationJobs} empty="No rotation jobs are queued right now." /></Panel>
      </section>

      <section>
        <Panel className="p-5">
          <SectionTitle suffix={<span className="text-[10px] text-white/38">Highest risk first · select a key to plan rotation</span>}>Rotation Queue</SectionTitle>
          <KeyRowsTable
            rows={dueForRotation}
            empty="No keys currently require rotation."
            onRowClick={(key) => setSelectedId(key.id)}
            selectedId={selected?.id}
            actions={(key) => (
              <button type="button" disabled={pendingId === key.id} onClick={(event) => { event.stopPropagation(); void rotateKey(key); }} className="inline-flex h-8 items-center gap-1 rounded-md border border-white/10 bg-white/[0.025] px-2 text-[10px] font-bold text-white/62 transition hover:border-gold/50 hover:text-gold disabled:opacity-40">
                <RefreshCw className={cn('h-3.5 w-3.5', pendingId === key.id && 'animate-spin')} />Rotate
              </button>
            )}
            columns={[
              { label: 'Key / Alias', render: (key) => <div><div className="font-semibold text-white">{key.keyAlias || key.name}</div><div className="font-mono text-[10px] text-white/38">{key.algorithm || 'Unknown'}</div></div> },
              { label: 'Owner', render: (key) => <span className="text-white/62">{key.owner}</span> },
              { label: 'Env', render: (key) => <StatusPill value={key.environment || 'unknown'} /> },
              { label: 'Reason', render: (key) => <span className="text-white/60">{rotationReason(key)}</span> },
              { label: 'Due', render: (key) => <span className="text-white/55">{key.expiresAt ? longDate(key.expiresAt) : 'Policy-driven'}</span> },
              { label: 'Dependencies', render: (key) => <span className="font-mono text-white/70">{integerFmt((key.certificateLinks || 0) + (key.linkedAssets?.length || 0) + (key.linkedMigrationJobs?.length || 0))}</span> },
              { label: 'Compatibility', render: (key) => <StatusPill value={quantumExposureStatus(key) === 'Classical-Only' ? 'review' : 'compatible'} /> },
              { label: 'Approval', render: (key) => <StatusPill value={key.environment === 'production' || key.riskScore >= 60 ? 'required' : 'auto'} /> },
              { label: 'Rotation', render: (key) => <StatusPill value={statusOf(key)} /> },
            ]}
          />
        </Panel>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-8">
          <SectionTitle suffix={selected ? <span className="text-[10px] text-white/38">{selected.keyAlias || selected.name}</span> : undefined}>Rotation Workflow</SectionTitle>
          <WorkflowStepper keyRecord={selected} jobs={snapshot.rotationJobs} />
          <div className="mt-4 flex flex-wrap gap-2">
            {([['precheck', 'Run Precheck', ShieldCheck], ['dry-run', 'Start Dry Run', Radar], ['start', 'Start Rotation', RefreshCw], ['export', 'Export Evidence', Download]] as Array<['precheck' | 'dry-run' | 'start' | 'export', string, LucideIcon]>).map(([action, label, Icon]) => (
              <button key={action} type="button" disabled={workflowBusy === action} onClick={() => void runWorkflowAction(action)} className={cn('inline-flex h-9 items-center gap-2 rounded-md border px-3 text-xs font-bold transition disabled:opacity-45', action === 'start' ? 'border-blue-400/40 bg-blue-500 text-white hover:border-gold hover:bg-gold hover:text-black' : 'border-white/10 bg-white/[0.025] text-white/70 hover:border-gold/50 hover:text-gold')}>
                <Icon className={cn('h-4 w-4', workflowBusy === action && 'animate-spin')} />{label}
              </button>
            ))}
          </div>
        </Panel>
        <Panel className="p-5 xl:col-span-4">
          <SectionTitle>Post-Rotation Validation</SectionTitle>
          <RotationValidationPanel keyRecord={selected} />
        </Panel>
      </section>

      <section>
        <Panel className="p-5"><SectionTitle>Rotation Impact Analysis</SectionTitle><RotationImpactPanel keyRecord={selected} /></Panel>
      </section>
    </>
  );
}

/* ---------------- Risk analysis layout ---------------- */

function RiskAnalysisLayout({ snapshot, request, onNotice }: { snapshot: QkmsSnapshot; request: QkmsAction; onNotice: (message: string) => void }) {
  const inventory = snapshot.inventory;
  const total = inventory.length;
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  const riskOf = useCallback((key: KeyRecord) => keyRiskFactors(key).weighted, []);

  const buckets = useMemo(() => {
    const scored = inventory.map((key) => riskOf(key));
    const critical = scored.filter((value) => value >= 75).length;
    const high = scored.filter((value) => value >= 50 && value < 75).length;
    const medium = scored.filter((value) => value >= 25 && value < 50).length;
    const low = scored.filter((value) => value < 25).length;
    const avg = scored.length ? Math.round(scored.reduce((sum, value) => sum + value, 0) / scored.length) : 0;
    return { critical, high, medium, low, avg, highRisk: critical + high };
  }, [inventory, riskOf]);

  const categoryRows = useMemo(() => {
    if (!inventory.length) return [];
    const sums = { algorithm: 0, quantum: 0, lifecycle: 0, rotation: 0, ownership: 0, access: 0, dependency: 0 };
    for (const key of inventory) {
      const { factors } = keyRiskFactors(key);
      sums.algorithm += factors.algorithm; sums.quantum += factors.quantum; sums.lifecycle += factors.lifecycle;
      sums.rotation += factors.rotation; sums.ownership += factors.ownership; sums.access += factors.access; sums.dependency += factors.dependency;
    }
    const n = inventory.length;
    return [
      { label: 'Algorithm Risk', count: Math.round(sums.algorithm / n), percent: Math.round(sums.algorithm / n) },
      { label: 'Quantum Exposure Risk', count: Math.round(sums.quantum / n), percent: Math.round(sums.quantum / n) },
      { label: 'Lifecycle Risk', count: Math.round(sums.lifecycle / n), percent: Math.round(sums.lifecycle / n) },
      { label: 'Rotation Risk', count: Math.round(sums.rotation / n), percent: Math.round(sums.rotation / n) },
      { label: 'Ownership Risk', count: Math.round(sums.ownership / n), percent: Math.round(sums.ownership / n) },
      { label: 'Access Risk', count: Math.round(sums.access / n), percent: Math.round(sums.access / n) },
      { label: 'Dependency Risk', count: Math.round(sums.dependency / n), percent: Math.round(sums.dependency / n) },
    ];
  }, [inventory]);

  const riskRows = [
    { label: 'Critical (75-100)', count: buckets.critical, percent: total ? (buckets.critical / total) * 100 : 0 },
    { label: 'High (50-74)', count: buckets.high, percent: total ? (buckets.high / total) * 100 : 0 },
    { label: 'Medium (25-49)', count: buckets.medium, percent: total ? (buckets.medium / total) * 100 : 0 },
    { label: 'Low (0-24)', count: buckets.low, percent: total ? (buckets.low / total) * 100 : 0 },
  ];

  const quantumFamilyRows = distributionRows(inventory.map((key) => quantumFamily(key.algorithm)), total).slice(0, 8);
  const exposureRows = distributionRows(inventory.map((key) => quantumExposureStatus(key)), total);

  const topRisk = useMemo(() => [...inventory].sort((a, b) => riskOf(b) - riskOf(a)).slice(0, 14), [inventory, riskOf]);
  const selected = topRisk.find((key) => key.id === selectedId) || topRisk[0] || null;

  const remediation = useMemo(() => {
    return [...inventory].sort((a, b) => riskOf(b) - riskOf(a)).slice(0, 10).map((key) => {
      let action = 'Validate trust chain';
      if (key.weak) action = 'Replace weak algorithm';
      else if (quantumExposureStatus(key) === 'Classical-Only') action = 'Migrate to PQC / hybrid';
      else if (key.orphaned) action = 'Assign owner';
      else if (key.rotationRequired) action = 'Rotate key';
      else if (key.exportable) action = 'Reduce excessive access';
      else if (!key.lastRotatedAt) action = 'Attach rotation policy';
      else if (expiryMs(key.expiresAt) < Date.now()) action = 'Revoke / replace expired key';
      return { key, action, score: riskOf(key) };
    });
  }, [inventory, riskOf]);

  const exportRiskReport = useCallback(async () => {
    setExporting(true);
    try {
      await request('/export', { method: 'POST', body: JSON.stringify({ format: 'csv', scope: 'key-risk-report' }) });
      onNotice('Key risk report exported by QKMS API');
    } catch (error) {
      onNotice(error instanceof Error ? error.message : 'Risk export failed');
    } finally {
      setExporting(false);
    }
  }, [request, onNotice]);

  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile icon={ShieldAlert} label="Critical-Risk Keys" value={compactFmt(buckets.critical)} detail="weighted risk >= 75" color={RED} />
        <MetricTile icon={AlertTriangle} label="High-Risk Keys" value={compactFmt(buckets.high)} detail="weighted risk 50-74" color={ORANGE} />
        <MetricTile icon={Layers} label="Medium-Risk Keys" value={compactFmt(buckets.medium)} detail="weighted risk 25-49" color={GOLD} />
        <MetricTile icon={ShieldCheck} label="Low-Risk Keys" value={compactFmt(buckets.low)} detail="weighted risk 0-24" color={GREEN} />
        <MetricTile icon={Sparkles} label="Weak Algorithms" value={compactFmt(snapshot.metrics.weakAlgorithms)} detail="classical or deprecated" color={ORANGE} />
        <MetricTile icon={Fingerprint} label="Orphaned Keys" value={compactFmt(snapshot.metrics.orphanedKeys)} detail="missing owner / asset" color={GOLD} />
        <MetricTile icon={Download} label="Exportable Production" value={compactFmt(snapshot.metrics.exportableProductionKeys)} detail="excessive access exposure" color={RED} />
        <MetricTile icon={CircleGauge} label="Average Risk" value={integerFmt(buckets.avg)} detail={riskLevelLabel(buckets.avg)} color={riskLevelColor(buckets.avg)} />
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Risk Posture</SectionTitle><ScoreDial value={buckets.avg} label="Avg Risk" color={riskLevelColor(buckets.avg)} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Risk Score Distribution</SectionTitle><Bars rows={riskRows} empty="No key risk telemetry yet." /></Panel>
        <Panel className="p-5 xl:col-span-5"><SectionTitle suffix={<span className="text-[10px] text-white/38">Weighted model avg</span>}>Risk Categories</SectionTitle><Bars rows={categoryRows} empty="No risk categories yet." /></Panel>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-6"><SectionTitle>Quantum Exposure — Algorithm Family</SectionTitle><Bars rows={quantumFamilyRows} empty="No key algorithms discovered yet." /></Panel>
        <Panel className="p-5 xl:col-span-6"><SectionTitle>Quantum Exposure — Readiness</SectionTitle><Bars rows={exposureRows} empty="No PQC readiness telemetry yet." /></Panel>
      </section>

      <section>
        <Panel className="p-5">
          <SectionTitle suffix={<button type="button" disabled={exporting} onClick={() => void exportRiskReport()} className="inline-flex h-8 items-center gap-1 rounded-md border border-white/10 bg-white/[0.025] px-2.5 text-[10px] font-bold text-white/62 transition hover:border-gold/50 hover:text-gold disabled:opacity-45"><Download className="h-3.5 w-3.5" />Export Risk Report</button>}>Key Risk Table</SectionTitle>
          <KeyRowsTable
            rows={topRisk}
            empty="No key risk records have been discovered yet."
            onRowClick={(key) => setSelectedId(key.id)}
            selectedId={selected?.id}
            columns={[
              { label: 'Key / Alias', render: (key) => <div><div className="font-semibold text-white">{key.keyAlias || key.name}</div><div className="font-mono text-[10px] text-white/38">{key.algorithm || 'Unknown'}</div></div> },
              { label: 'Owner', render: (key) => <span className="text-white/62">{key.owner}</span> },
              { label: 'Env', render: (key) => <StatusPill value={key.environment || 'unknown'} /> },
              { label: 'Quantum Exposure', render: (key) => <StatusPill value={quantumExposureStatus(key)} /> },
              { label: 'Risk Factors', render: (key) => <span className="block max-w-[240px] truncate text-white/60" title={key.riskExplanation}>{key.riskExplanation || (key.weak ? 'Deprecated algorithm' : key.orphaned ? 'No owner assigned' : 'Rotation / custody gap')}</span> },
              { label: 'Recommended', render: (key) => <span className="text-white/60">{key.recommendedAction ? (key.recommendedAction.length > 28 ? `${key.recommendedAction.slice(0, 28)}…` : key.recommendedAction) : 'Review key'}</span> },
              { label: 'Risk', render: (key) => <span className="font-mono text-sm font-bold" style={{ color: riskLevelColor(riskOf(key)) }}>{integerFmt(riskOf(key))}</span> },
              { label: 'Level', render: (key) => <StatusPill value={riskLevelLabel(riskOf(key))} /> },
            ]}
          />
        </Panel>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-8">
          <SectionTitle>Risk Detail & Evidence</SectionTitle>
          {selected ? <KeyDetailDrawer keyRecord={selected} request={request} onNotice={onNotice} variant="risk" /> : <div className="grid min-h-[200px] place-items-center text-xs text-white/38">No key risk records yet.</div>}
        </Panel>
        <Panel className="p-5 xl:col-span-4">
          <SectionTitle suffix={<span className="text-[10px] text-white/38">Prioritized</span>}>Remediation Queue</SectionTitle>
          {remediation.length ? (
            <div className="space-y-2">
              {remediation.map(({ key, action, score }) => (
                <button key={key.id} type="button" onClick={() => setSelectedId(key.id)} className="flex w-full items-center justify-between gap-3 rounded-md border border-white/8 bg-white/[0.025] p-3 text-left transition hover:border-gold/45">
                  <div className="min-w-0">
                    <div className="truncate text-xs font-semibold text-white/82">{action}</div>
                    <div className="truncate text-[10px] text-white/42">{key.keyAlias || key.name}</div>
                  </div>
                  <span className="shrink-0 font-mono text-sm font-bold" style={{ color: riskLevelColor(score) }}>{integerFmt(score)}</span>
                </button>
              ))}
            </div>
          ) : <div className="grid min-h-[160px] place-items-center text-xs text-white/38">No remediation items.</div>}
        </Panel>
      </section>
    </>
  );
}

function Body({ mode, snapshot, request, onNotice }: { mode: QkmsMode; snapshot: QkmsSnapshot; request: QkmsAction; onNotice: (message: string) => void }) {
  if (mode === 'overview') return <OverviewLayout snapshot={snapshot} />;
  if (mode === 'inventory') return <InventoryLayout snapshot={snapshot} request={request} onNotice={onNotice} />;
  if (mode === 'lifecycle') return <LifecycleLayout snapshot={snapshot} request={request} onNotice={onNotice} />;
  if (mode === 'governance') return <GovernanceLayout snapshot={snapshot} request={request} onNotice={onNotice} />;
  if (mode === 'rotation') return <RotationLayout snapshot={snapshot} request={request} onNotice={onNotice} />;
  if (mode === 'risk-analysis') return <RiskAnalysisLayout snapshot={snapshot} request={request} onNotice={onNotice} />;
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
