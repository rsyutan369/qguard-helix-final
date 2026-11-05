'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  Cpu,
  Download,
  Gauge,
  HardDrive,
  Heart,
  HelpCircle,
  Info,
  KeyRound,
  Link2,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  Radar,
  Server,
  Settings2,
  Shield,
  ShieldCheck,
  Terminal,
  Trash2,
  TriangleAlert,
  Wifi,
  WifiOff,
  X,
  XCircle,
  Zap,
} from 'lucide-react';
import { useAuth } from '@/contexts/auth-context';
import {
  AGENT_PLATFORMS,
  AGENT_ROLLBACK_MIN_VERSION,
  agentRole,
  agentVersionAtLeast,
  type AgentPlatform,
} from '@/lib/agent-installer/agent-release';
import {
  agentDisplayStatus,
  agentHealthScore,
  connectionQuality,
  isAgentOnline,
  useAgentCollector,
  type AgentPolicyInput,
  type BindingConflict,
  type CollectorAgent,
  type ScannerAlertRow,
  type ScannerEvidenceRow,
} from '@/hooks/use-agent-collector';
import { agentBindingFromMetadata, bindingKind, type AgentBinding } from '@/lib/agent-installer/agent-binding';
import { PATH_ISSUE_COPY, agentPathIssue } from '@/lib/agent-installer/agent-scope';
import {
  AssetBindingPicker,
  EMPTY_BINDING_DRAFT,
  bindingDraftIssue,
  bindingIcon,
  bindingRequestFromDraft,
  type BindingDraft,
} from './AssetBindingPicker';
import { CollectorSettings } from './AgentSettingsConsole';

/* ------------------------------------------------------------------ */
/* Constants — scan types, environments, install tabs                  */
/* ------------------------------------------------------------------ */
const ENVIRONMENTS = [
  { id: 'windows', label: 'Windows' },
  { id: 'linux', label: 'Linux' },
  { id: 'docker', label: 'Docker' },
  { id: 'kubernetes', label: 'Kubernetes' },
  { id: 'vm', label: 'Virtual Machine' },
  { id: 'cloud-connector', label: 'Cloud Connector' },
];

const SCAN_TYPES = [
  { id: 'quick', label: 'Quick Scan', detail: 'Fast posture snapshot of assigned targets' },
  { id: 'full', label: 'Full Scan', detail: 'Complete cryptographic discovery' },
  { id: 'discovery', label: 'Discovery Scan', detail: 'Enumerate assets and endpoints' },
  { id: 'cloud', label: 'Cloud Scan', detail: 'Cloud services, KMS, load balancers' },
  { id: 'tls', label: 'TLS Assessment', detail: 'Protocols, ciphers, key exchange' },
  { id: 'certificates', label: 'Certificate Discovery', detail: 'X.509 chains and expiry' },
  { id: 'pki', label: 'PKI Inventory', detail: 'Trust stores and issuers' },
  { id: 'crypto', label: 'Crypto Inventory', detail: 'Algorithms, keys, libraries' },
  { id: 'quantum', label: 'Quantum Readiness Scan', detail: 'HNDL and PQC posture' },
];

// Backend policy scan-type ids the console maps its friendly scan intents onto.
const DEFAULT_POLICY_SCAN_TYPES = ['tls', 'certificates', 'pki', 'ssh', 'libraries', 'configs', 'runtime'];

const NAV = [
  { id: 'overview', label: 'Overview', icon: Gauge },
  { id: 'collectors', label: 'Collectors', icon: Server },
  { id: 'scans', label: 'Scans', icon: Radar },
  { id: 'operations', label: 'Operations', icon: Zap },
  { id: 'settings', label: 'Settings', icon: Settings2 },
  { id: 'help', label: 'Help', icon: HelpCircle },
] as const;
type NavId = (typeof NAV)[number]['id'];

/* ------------------------------------------------------------------ */
/* Small presentational primitives                                     */
/* ------------------------------------------------------------------ */
const PANEL = 'rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl shadow-[0_1px_0_rgba(255,255,255,0.04)_inset]';

function StatusDot({ tone }: { tone: 'ok' | 'warn' | 'bad' | 'idle' }) {
  const color = tone === 'ok' ? 'bg-emerald-400' : tone === 'warn' ? 'bg-amber-400' : tone === 'bad' ? 'bg-red-400' : 'bg-slate-500';
  const glow = tone === 'ok' ? 'shadow-[0_0_10px_rgba(52,211,153,0.7)]' : '';
  return <span className={`inline-block h-2 w-2 rounded-full ${color} ${glow}`} aria-hidden="true" />;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    Online: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
    Offline: 'border-red-400/30 bg-red-400/10 text-red-300',
    Waiting: 'border-amber-400/30 bg-amber-400/10 text-amber-200',
    Unhealthy: 'border-orange-400/30 bg-orange-400/10 text-orange-300',
    Updating: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-300',
    Revoked: 'border-white/10 bg-white/[0.04] text-white/40',
    Completed: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
    Running: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-300',
    Failed: 'border-red-400/30 bg-red-400/10 text-red-300',
  };
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-bold ${map[status] || 'border-white/10 bg-white/[0.04] text-white/55'}`}>
      {status}
    </span>
  );
}

/**
 * The agent's server-resolved role and what it is therefore allowed to do.
 *
 * The role is the single most consequential property of an agent — it decides
 * whether the thing running on a customer's host can WRITE to it — and the
 * fleet table did not show it at all. It is read from `metadata.role`, which is
 * written by the backend at enrolment (never from caller-supplied JSON), so
 * what is displayed here is the authority actually in force.
 */
function RoleChip({ agent }: { agent: CollectorAgent }) {
  const resolved = typeof agent.metadata?.role === 'string' ? (agent.metadata.role as string) : '';
  const role = agentRole(resolved);
  const unresolved = !resolved;
  const tone = unresolved
    ? 'border-white/12 bg-white/[0.04] text-white/45'
    : role.mutatesTargets
      ? 'border-amber-400/35 bg-amber-400/10 text-amber-200'
      : 'border-cyan-400/30 bg-cyan-400/10 text-cyan-200';
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-bold ${tone}`}
      title={unresolved
        ? 'This agent has no server-resolved role, so no host-modifying work is dispatched to it.'
        : `${role.authority}${role.mutatesTargets ? '' : ' It is never handed remediation or migration work.'}`}
    >
      {unresolved ? 'Role unresolved' : role.label}
      {!unresolved && (
        <span className="text-[9px] font-black uppercase opacity-70">{role.mutatesTargets ? 'writes' : 'read-only'}</span>
      )}
    </span>
  );
}

function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse rounded-lg bg-white/[0.05] ${className}`} />;
}

function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => { navigator.clipboard?.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1600); }}
      className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[11px] font-bold text-white/75 transition hover:border-cyan-400/40 hover:text-cyan-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400"
      aria-label={copied ? 'Copied' : label}
    >
      {copied ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-300" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? 'Copied' : label}
    </button>
  );
}

/* ------------------------------------------------------------------ */
/* Asset binding — read from the rows themselves                       */
/* ------------------------------------------------------------------ */

/** The binding a stored evidence row or alert was filed under (not the agent's current one). */
function filedBindingId(row: ScannerEvidenceRow | ScannerAlertRow): string | null {
  const source = 'raw_evidence' in row ? row.raw_evidence : (row as ScannerAlertRow).metadata;
  const binding = source && typeof source === 'object' ? (source as Record<string, unknown>).binding : null;
  const id = binding && typeof binding === 'object' ? (binding as Record<string, unknown>).assetId : null;
  return typeof id === 'string' ? id : null;
}

const isOpenAlert = (a: ScannerAlertRow) => !['resolved', 'closed', 'suppressed'].includes(String(a.status || 'open').toLowerCase());

function BindingChip({ binding, compact = false }: { binding: AgentBinding | null; compact?: boolean }) {
  if (!binding) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-white/10 bg-white/[0.03] px-2 py-0.5 text-[10px] font-bold text-white/45" title="Observations will be filed inside this machine’s device profile.">
        <Radar className="h-3 w-3" /> Device profile
      </span>
    );
  }
  const Icon = bindingIcon(binding.kind);
  return (
    <span
      className="inline-flex max-w-[220px] items-center gap-1 rounded-full border border-cyan-400/30 bg-cyan-400/10 px-2 py-0.5 text-[10px] font-bold text-cyan-100"
      title={`${bindingKind(binding.kind)?.label || binding.kind || 'Asset'} · ${binding.attribution === 'bound' ? 'all findings filed here' : 'discovered assets grouped here'}${binding.path ? ` · ${binding.path}` : ''}`}
    >
      <Icon className="h-3 w-3 shrink-0" />
      <span className="truncate">{binding.assetName}</span>
      {!compact ? <span className="shrink-0 text-[9px] font-black uppercase opacity-60">{binding.attribution === 'bound' ? 'filed' : 'grouped'}</span> : null}
    </span>
  );
}

function fmtDate(value?: string | null): string {
  if (!value) return 'Never';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Unknown';
  return d.toLocaleString();
}
function relTime(value?: string | null): string {
  if (!value) return '—';
  const diff = Date.now() - Date.parse(value);
  if (!Number.isFinite(diff)) return '—';
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

/* ------------------------------------------------------------------ */
/* Console                                                             */
/* ------------------------------------------------------------------ */
const isNavId = (value: string | null): value is NavId => NAV.some((item) => item.id === value);

export default function AgentCollectorConsole() {
  const { user } = useAuth();
  const collector = useAgentCollector(true);
  // The section lives in ?view= so every section is deep-linkable and survives a reload.
  const [searchParams, setSearchParams] = useSearchParams();
  const viewParam = searchParams.get('view');
  const nav: NavId = isNavId(viewParam) ? viewParam : 'overview';
  const setNav = useCallback((next: NavId) => {
    setSearchParams((current) => {
      const params = new URLSearchParams(current);
      if (next === 'overview') params.delete('view');
      else params.set('view', next);
      return params;
    }, { replace: true });
  }, [setSearchParams]);
  const [drawerAgentId, setDrawerAgentId] = useState<string | null>(null);
  const [toast, setToast] = useState<{ tone: 'ok' | 'bad'; text: string } | null>(null);

  const showToast = useCallback((tone: 'ok' | 'bad', text: string) => {
    setToast({ tone, text });
    setTimeout(() => setToast(null), 3500);
  }, []);

  const tenantId = user?.id || 'tenant_id_here';
  const apiUrl = typeof window !== 'undefined' ? window.location.origin : 'https://api.yourdomain.com';
  const drawerAgent = collector.agents.find((a) => a.id === drawerAgentId) || null;

  return (
    <div className="space-y-5">
      {/* Toast */}
      {toast ? (
        <div
          role="status"
          className={`fixed bottom-6 right-6 z-50 flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-semibold shadow-2xl backdrop-blur-xl ${
            toast.tone === 'ok' ? 'border-emerald-400/30 bg-emerald-500/15 text-emerald-100' : 'border-red-400/30 bg-red-500/15 text-red-100'
          }`}
        >
          {toast.tone === 'ok' ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
          {toast.text}
        </div>
      ) : null}

      <ConsoleHeader
        collector={collector}
        onDeploy={() => {
          setNav('overview');
          // The wizard mounts with the Overview section; scroll once it has.
          requestAnimationFrame(() => document.getElementById('agents-quick-start')?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
        }}
      />

      <nav className="flex gap-1 overflow-x-auto rounded-2xl border border-white/8 bg-white/[0.02] p-1" aria-label="Agents Collector sections">
        {NAV.map((item) => {
          const Icon = item.icon;
          const active = nav === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setNav(item.id)}
              aria-current={active ? 'page' : undefined}
              className={`inline-flex shrink-0 items-center gap-2 rounded-xl border px-3.5 py-2 text-sm font-bold transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400 ${
                active ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200 shadow-[0_0_0_1px_rgba(34,211,238,0.12)]' : 'border-transparent text-white/55 hover:bg-white/[0.03] hover:text-white/80'
              }`}
            >
              <Icon className="h-4 w-4" /> {item.label}
            </button>
          );
        })}
      </nav>

      {collector.error ? (
        <div className="flex items-start gap-2 rounded-xl border border-red-400/25 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          <XCircle className="mt-0.5 h-4 w-4 shrink-0" /> <span>{collector.error}</span>
        </div>
      ) : null}

      {nav === 'overview' && <OverviewSection collector={collector} onCreated={(t) => showToast('ok', t)} onView={setDrawerAgentId} />}
      {nav === 'collectors' && <CollectorsSection collector={collector} onView={setDrawerAgentId} />}
      {nav === 'scans' && <ScansSection collector={collector} onToast={showToast} />}
      {nav === 'operations' && <OperationsSection collector={collector} onToast={showToast} />}
      {nav === 'settings' && <CollectorSettings collector={collector} onToast={showToast} />}
      {nav === 'help' && <HelpSection />}

      {drawerAgent ? (
        <CollectorDrawer
          agent={drawerAgent}
          tenantId={tenantId}
          apiUrl={apiUrl}
          collector={collector}
          onClose={() => setDrawerAgentId(null)}
          onToast={showToast}
        />
      ) : null}
    </div>
  );
}

type CollectorApi = ReturnType<typeof useAgentCollector>;

/* ------------------------------------------------------------------ */
/* Page header — identity, live fleet status, primary actions          */
/* ------------------------------------------------------------------ */
function ConsoleHeader({ collector, onDeploy }: { collector: CollectorApi; onDeploy: () => void }) {
  const s = collector.summary;
  const loading = collector.state === 'loading';
  const active = collector.agents.filter((a) => !a.revoked_at && a.status !== 'revoked');
  const bound = active.filter((a) => agentBindingFromMetadata(a.metadata)).length;
  // Every figure is read from the live fleet; nothing is shown until it has loaded.
  const status: Array<{ label: string; value: string; hint: string; tone: 'ok' | 'warn' | 'bad' | 'idle' }> = [
    { label: 'Fleet', value: String(s.registered), hint: `${s.revoked} revoked`, tone: 'idle' },
    { label: 'Online', value: `${s.online}/${active.length}`, hint: `${s.awaitingInstall} awaiting install · ${s.offline} offline`, tone: s.online > 0 ? 'ok' : active.length ? 'warn' : 'idle' },
    { label: 'Bound to assets', value: `${bound}/${active.length}`, hint: `${active.length - bound} on open discovery`, tone: active.length && bound === active.length ? 'ok' : 'idle' },
    // Open alerts include collector health (offline) alerts, so they are not labelled as quantum risk alone.
    { label: 'Open alerts', value: String(s.quantumRisks), hint: 'Findings and collector health', tone: s.quantumRisks > 0 ? 'warn' : 'ok' },
    { label: 'Last heartbeat', value: relTime(s.lastHeartbeat), hint: s.lastHeartbeat ? fmtDate(s.lastHeartbeat) : 'No collector has checked in yet', tone: s.lastHeartbeat ? 'ok' : 'idle' },
  ];

  return (
    <header className={`${PANEL} relative overflow-hidden`}>
      <div aria-hidden="true" className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent" />
      <div className="px-5 pb-4 pt-4 sm:px-6">
        <nav aria-label="Breadcrumb" className="flex flex-wrap items-center gap-1 text-[11px] font-bold text-white/40">
          <span>Discovery</span>
          <ChevronRight className="h-3 w-3" />
          <Link to="/dashboard/scanner" className="text-white/50 no-underline transition hover:text-cyan-200">PQC Scanner</Link>
          <ChevronRight className="h-3 w-3" />
          <span aria-current="page" className="text-cyan-200">Agents Collector</span>
        </nav>

        <div className="mt-3 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex min-w-0 items-start gap-3.5">
            <span className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl border border-cyan-400/30 bg-gradient-to-br from-cyan-400/15 to-blue-500/10 text-cyan-200 shadow-[0_0_24px_rgba(34,211,238,0.15)]">
              <Server className="h-6 w-6" />
            </span>
            <div className="min-w-0">
              <h1 className="text-2xl font-black tracking-tight text-white">Agents Collector</h1>
              <p className="mt-1 max-w-2xl text-sm leading-relaxed text-white/55">
                Deploy collectors onto your hosts, bind each one to the asset, folder, file or profile its findings belong to,
                and watch the fleet report back in real time. Collectors only read what their policy allows.
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 text-[11px] font-bold text-white/60" role="status">
              {collector.sseConnected ? <Wifi className="h-3.5 w-3.5 text-emerald-300" /> : <WifiOff className="h-3.5 w-3.5 text-amber-300" />}
              {collector.sseConnected ? 'Live' : 'Reconnecting'}
            </span>
            <button
              type="button"
              onClick={() => void collector.refresh()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-xs font-bold text-white/75 transition hover:border-cyan-400/40 hover:text-cyan-200"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${collector.busy ? 'animate-spin' : ''}`} /> Refresh
            </button>
            <Link
              to="/downloads"
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-xs font-bold text-white/75 no-underline transition hover:border-cyan-400/40 hover:text-cyan-200"
            >
              <Download className="h-3.5 w-3.5" /> Agent downloads
            </Link>
            <button
              type="button"
              onClick={onDeploy}
              className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/40 bg-gradient-to-r from-cyan-500/80 to-blue-500/70 px-3.5 py-2 text-xs font-black text-white shadow-lg transition hover:from-cyan-400 hover:to-blue-400"
            >
              <Plus className="h-3.5 w-3.5" /> Deploy agent
            </button>
          </div>
        </div>
      </div>

      <dl className="grid grid-cols-2 border-t border-white/8 sm:grid-cols-3 lg:grid-cols-5">
        {status.map((item, i) => (
          <div key={item.label} className={`px-5 py-3 sm:px-6 ${i > 0 ? 'border-l border-white/8' : ''}`}>
            <dt className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-[0.12em] text-white/40">
              <StatusDot tone={item.tone} /> {item.label}
            </dt>
            <dd className="mt-1">
              {loading ? <Skeleton className="h-6 w-14" /> : <span className="text-lg font-black tabular-nums text-white">{item.value}</span>}
              <span className="mt-0.5 block truncate text-[11px] text-white/40" title={item.hint}>{loading ? ' ' : item.hint}</span>
            </dd>
          </div>
        ))}
      </dl>
    </header>
  );
}

/* ------------------------------------------------------------------ */
/* Overview — summary cards + Quick Start wizard                       */
/* ------------------------------------------------------------------ */
function OverviewSection({ collector, onCreated, onView }: { collector: CollectorApi; onCreated: (t: string) => void; onView: (id: string) => void }) {
  const s = collector.summary;
  const loading = collector.state === 'loading';
  const cards = [
    { label: 'Registered Collectors', value: s.registered, icon: Server, tone: 'idle' as const },
    { label: 'Online', value: s.online, icon: Wifi, tone: s.online > 0 ? ('ok' as const) : ('idle' as const) },
    // Awaiting install (never checked in) is deliberately separate from Offline
    // (checked in, then stopped) — see the summary derivation in the hook.
    { label: 'Awaiting Install', value: s.awaitingInstall, icon: Download, tone: 'idle' as const },
    { label: 'Offline', value: s.offline, icon: WifiOff, tone: s.offline > 0 ? ('warn' as const) : ('idle' as const) },
    { label: 'Assets Discovered', value: s.assetsDiscovered, icon: HardDrive, tone: 'idle' as const },
    { label: 'Quantum Risks', value: s.quantumRisks, icon: Shield, tone: s.quantumRisks > 0 ? ('bad' as const) : ('ok' as const) },
    { label: 'Pending Remediation', value: s.pendingRemediation, icon: Zap, tone: s.pendingRemediation > 0 ? ('warn' as const) : ('idle' as const) },
  ];

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        {cards.map((c) => {
          const Icon = c.icon;
          return (
            <div key={c.label} className={`${PANEL} p-4`}>
              <div className="flex items-center justify-between">
                <Icon className="h-4 w-4 text-white/40" />
                <StatusDot tone={c.tone} />
              </div>
              {loading ? <Skeleton className="mt-3 h-7 w-12" /> : <div className="mt-2 text-3xl font-black tabular-nums text-white">{c.value}</div>}
              <div className="mt-1 text-[11px] font-bold uppercase tracking-wide text-white/40">{c.label}</div>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className={`${PANEL} flex items-center gap-3 px-4 py-3`}>
          <Heart className="h-5 w-5 text-rose-300" />
          <div>
            <div className="text-[11px] font-bold uppercase tracking-wide text-white/40">Last Heartbeat</div>
            <div className="text-sm font-semibold text-white/85">{relTime(s.lastHeartbeat)} · {fmtDate(s.lastHeartbeat)}</div>
          </div>
        </div>
        <div className={`${PANEL} flex items-center gap-3 px-4 py-3`}>
          <Radar className="h-5 w-5 text-cyan-300" />
          <div>
            <div className="text-[11px] font-bold uppercase tracking-wide text-white/40">Recent Scan Evidence</div>
            <div className="text-sm font-semibold text-white/85">{s.evidenceCount} record(s) · {relTime(s.lastEvidence)}</div>
          </div>
        </div>
      </div>

      <QuickStartWizard collector={collector} onCreated={onCreated} onView={onView} />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Quick Start — clean 4-step wizard                                   */
/* ------------------------------------------------------------------ */
type WizardStep = 0 | 1 | 2 | 3;
const STEP_LABELS = ['Create Collector', 'Install Collector', 'Verify Connection', 'Run First Scan'];

function QuickStartWizard({ collector, onCreated, onView }: { collector: CollectorApi; onCreated: (t: string) => void; onView: (id: string) => void }) {
  const { user } = useAuth();
  const [step, setStep] = useState<WizardStep>(0);
  const [name, setName] = useState('Production Collector');
  const [environment, setEnvironment] = useState('linux');
  const [description, setDescription] = useState('');
  const [tags, setTags] = useState('');
  const [targets, setTargets] = useState('');
  const [bindingDraft, setBindingDraft] = useState<BindingDraft>(EMPTY_BINDING_DRAFT);
  const [bindingConflict, setBindingConflict] = useState<BindingConflict | null>(null);
  const [scanBoundPath, setScanBoundPath] = useState(true);
  const [submitted, setSubmitted] = useState(false);
  const [createdAgentId, setCreatedAgentId] = useState<string | null>(null);

  /* An inventory with nothing in it has nothing to pick: start on "create new". */
  useEffect(() => {
    if (collector.bindingTargetsState === 'success' && collector.bindingTargets.length === 0) {
      setBindingDraft((current) => (current.mode === 'existing' && !current.assetId ? { ...current, mode: 'new' } : current));
    }
  }, [collector.bindingTargetsState, collector.bindingTargets.length]);

  const bindingIssue = bindingDraftIssue(bindingDraft, collector.bindingTargets);
  // A folder or file target is only scanned if it is also in the agent's allowed paths.
  const boundPath = bindingDraft.mode === 'new' && bindingKind(bindingDraft.kind)?.needsPath && bindingDraft.kind !== 'repository'
    ? bindingDraft.path.trim()
    : '';
  const boundPathIssue = boundPath ? agentPathIssue(boundPath) : null;

  const tenantId = user?.id || 'tenant_id_here';
  const apiUrl = typeof window !== 'undefined' ? window.location.origin : 'https://api.yourdomain.com';
  const createdAgent = collector.agents.find((a) => a.id === createdAgentId) || null;
  const stepStatus = useCallback(
    (i: WizardStep): 'Completed' | 'Running' | 'Waiting' => {
      if (i === 0) return createdAgentId ? 'Completed' : step === 0 ? 'Running' : 'Waiting';
      if (i === 1) return createdAgentId ? (step > 1 ? 'Completed' : 'Running') : 'Waiting';
      if (i === 2) return createdAgent && isAgentOnline(createdAgent) ? 'Completed' : createdAgentId && step >= 2 ? 'Running' : 'Waiting';
      return createdAgent && collector.summary.evidenceCount > 0 ? 'Completed' : step === 3 ? 'Running' : 'Waiting';
    },
    [createdAgentId, createdAgent, step, collector.summary.evidenceCount],
  );

  const handleCreate = useCallback(async () => {
    setSubmitted(true);
    if (bindingIssue) return;
    setBindingConflict(null);
    const policy: AgentPolicyInput = {
      enabled: true,
      intervalSeconds: 60,
      allowedTargets: targets.split(/\r?\n|,/).map((t) => t.trim()).filter(Boolean),
      allowedPaths: boundPath && scanBoundPath && !boundPathIssue ? [boundPath] : [],
      scanTypes: DEFAULT_POLICY_SCAN_TYPES,
      alertThreshold: 'moderate',
    };
    const result = await collector.createCollector({
      name: name.trim() || 'Production Collector',
      environment,
      description: description.trim(),
      tags: tags.split(/,/).map((t) => t.trim()).filter(Boolean),
      policy,
      binding: bindingRequestFromDraft(bindingDraft),
    });
    if (result.conflict) {
      setBindingConflict(result.conflict);
      return;
    }
    if (result.ok && result.token) {
      setCreatedAgentId(result.token.agentId);
      setStep(1);
      onCreated('Collector created — copy the enrollment token now.');
    }
  }, [collector, name, environment, description, tags, targets, onCreated, bindingDraft, bindingIssue, boundPath, boundPathIssue, scanBoundPath]);

  return (
    <div id="agents-quick-start" className={`${PANEL} scroll-mt-4 overflow-hidden`}>
      <div className="border-b border-white/8 px-5 py-4">
        <div className="flex items-center gap-2">
          <Zap className="h-4 w-4 text-cyan-300" />
          <h3 className="text-sm font-black uppercase tracking-wide text-white/80">Quick Start</h3>
        </div>
        {/* Step indicator */}
        <div className="mt-4 flex items-center">
          {STEP_LABELS.map((label, i) => {
            const status = stepStatus(i as WizardStep);
            const done = status === 'Completed';
            const running = status === 'Running';
            return (
              <div key={label} className="flex flex-1 items-center">
                <button
                  type="button"
                  onClick={() => setStep(i as WizardStep)}
                  className="flex items-center gap-2 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400"
                >
                  <span
                    className={`grid h-8 w-8 shrink-0 place-items-center rounded-full border text-xs font-black ${
                      done ? 'border-emerald-400/50 bg-emerald-400/15 text-emerald-300' : running ? 'border-cyan-400/50 bg-cyan-400/15 text-cyan-200' : 'border-white/12 bg-white/[0.03] text-white/40'
                    }`}
                  >
                    {done ? <CheckCircle2 className="h-4 w-4" /> : i + 1}
                  </span>
                  <span className={`hidden text-xs font-bold sm:inline ${step === i ? 'text-white' : 'text-white/50'}`}>{label}</span>
                </button>
                {i < STEP_LABELS.length - 1 ? <span className={`mx-2 h-px flex-1 ${done ? 'bg-emerald-400/40' : 'bg-white/10'}`} /> : null}
              </div>
            );
          })}
        </div>
      </div>

      <div className="p-5">
        {step === 0 ? (
          <div className="max-w-3xl space-y-4">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <label className="block">
                <span className="mb-1.5 block text-xs font-bold text-white/60">Collector Name</span>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full rounded-xl border border-white/12 bg-white/[0.03] px-3.5 py-2.5 text-sm text-white outline-none transition placeholder:text-white/25 focus:border-cyan-400/50"
                  placeholder="Production Collector"
                />
              </label>
              <label className="block">
                <span className="mb-1.5 block text-xs font-bold text-white/60">Environment</span>
                <div className="relative">
                  <select
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value)}
                    className="w-full appearance-none rounded-xl border border-white/12 bg-white/[0.03] px-3.5 py-2.5 text-sm text-white outline-none transition focus:border-cyan-400/50"
                  >
                    {ENVIRONMENTS.map((env) => (
                      <option key={env.id} value={env.id} className="bg-[#0b1120]">{env.label}</option>
                    ))}
                  </select>
                  <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/40" />
                </div>
              </label>
            </div>
            <label className="block">
              <span className="mb-1.5 block text-xs font-bold text-white/60">Description <span className="font-normal text-white/30">(optional)</span></span>
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full rounded-xl border border-white/12 bg-white/[0.03] px-3.5 py-2.5 text-sm text-white outline-none transition placeholder:text-white/25 focus:border-cyan-400/50"
                placeholder="East-region web tier"
              />
            </label>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <label className="block">
                <span className="mb-1.5 block text-xs font-bold text-white/60">Assigned Tags <span className="font-normal text-white/30">(comma separated)</span></span>
                <input
                  value={tags}
                  onChange={(e) => setTags(e.target.value)}
                  className="w-full rounded-xl border border-white/12 bg-white/[0.03] px-3.5 py-2.5 text-sm text-white outline-none transition placeholder:text-white/25 focus:border-cyan-400/50"
                  placeholder="prod, web, pci"
                />
              </label>
              <label className="block">
                <span className="mb-1.5 block text-xs font-bold text-white/60">Allowed Targets <span className="font-normal text-white/30">(one per line)</span></span>
                <input
                  value={targets}
                  onChange={(e) => setTargets(e.target.value)}
                  className="w-full rounded-xl border border-white/12 bg-white/[0.03] px-3.5 py-2.5 text-sm text-white outline-none transition placeholder:text-white/25 focus:border-cyan-400/50"
                  placeholder="api.customer.com:443"
                />
              </label>
            </div>

            <div className="border-t border-white/8 pt-4">
              <AssetBindingPicker
                value={bindingDraft}
                onChange={(next) => { setBindingDraft(next); setBindingConflict(null); }}
                targets={collector.bindingTargets}
                targetsState={collector.bindingTargetsState}
                onReloadTargets={() => void collector.loadBindingTargets()}
                conflict={bindingConflict}
                agentName={name}
              />
              {boundPath ? (
                <label className="mt-3 flex items-start gap-2.5 rounded-xl border border-white/8 bg-white/[0.02] px-3.5 py-2.5">
                  <input
                    type="checkbox"
                    checked={scanBoundPath}
                    onChange={(e) => setScanBoundPath(e.target.checked)}
                    disabled={Boolean(boundPathIssue)}
                    className="mt-0.5 h-4 w-4 accent-cyan-400"
                  />
                  <span className="text-[12px] leading-relaxed text-white/65">
                    Authorize this agent to scan <code className="font-mono text-cyan-200">{boundPath}</code> (adds it to the agent&apos;s allowed paths).
                    {boundPathIssue ? <span className="mt-0.5 block text-[var(--qg-notice-text)]">{PATH_ISSUE_COPY[boundPathIssue]}</span> : null}
                  </span>
                </label>
              ) : null}
            </div>

            {submitted && bindingIssue ? (
              <div role="alert" className="flex items-center gap-2 rounded-lg border border-[var(--qg-notice-border)] bg-[var(--qg-notice-bg)] px-3 py-2 text-[12px] text-[var(--qg-notice-text)]">
                <TriangleAlert className="h-4 w-4 shrink-0 text-amber-300" /> {bindingIssue}
              </div>
            ) : null}

            <button
              type="button"
              onClick={() => void handleCreate()}
              disabled={collector.busy}
              className="inline-flex items-center gap-2 rounded-xl border border-cyan-400/40 bg-gradient-to-r from-cyan-500/80 to-blue-500/70 px-5 py-2.5 text-sm font-black text-white shadow-lg transition hover:from-cyan-400 hover:to-blue-400 disabled:opacity-50"
            >
              {collector.busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              Create Collector
            </button>
          </div>
        ) : null}

        {step === 1 ? (
          <InstallStep
            token={collector.oneTimeToken}
            agentId={createdAgentId}
            tenantId={tenantId}
            apiUrl={apiUrl}
            onRotate={async () => { if (createdAgentId) await collector.rotateToken(createdAgentId); }}
            onNext={() => setStep(2)}
          />
        ) : null}

        {step === 2 ? (
          <VerifyStep agent={createdAgent} onNext={() => setStep(3)} onView={() => createdAgentId && onView(createdAgentId)} />
        ) : null}

        {step === 3 ? (
          <div className="max-w-xl space-y-3">
            <p className="text-sm text-white/70">
              Your collector is connected. It scans only its assigned targets and paths from policy, then streams evidence
              back to every module — Assets, CBOM, Risk Analysis, Remediation and Certification update automatically.
            </p>
            {/* What the server stored, not what the form asked for. */}
            <div className="flex flex-wrap items-center gap-2 text-[12px] text-white/55">
              <Link2 className="h-3.5 w-3.5 text-cyan-300" /> Findings filed under
              <BindingChip binding={agentBindingFromMetadata(createdAgent?.metadata)} />
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={async () => {
                  if (!createdAgentId) return;
                  const result = await collector.requestScan(createdAgentId);
                  if (!result.ok) collector.setError(result.message || 'Unable to queue the scan.');
                }}
                disabled={collector.busy}
                className="inline-flex items-center gap-2 rounded-xl border border-cyan-400/40 bg-cyan-400/10 px-4 py-2.5 text-sm font-black text-cyan-200 transition hover:bg-cyan-400/20"
              >
                <Play className="h-4 w-4" /> Start Scan
              </button>
              <a href="/dashboard/assets" className="inline-flex items-center gap-2 rounded-xl border border-white/12 bg-white/[0.03] px-4 py-2.5 text-sm font-bold text-white/75 no-underline transition hover:border-white/25">
                View discovered assets <ArrowRight className="h-4 w-4" />
              </a>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

function InstallStep({ token, agentId, tenantId, apiUrl, onRotate, onNext }: {
  token: ReturnType<typeof useAgentCollector>['oneTimeToken'];
  agentId: string | null;
  tenantId: string;
  apiUrl: string;
  onRotate: () => Promise<void>;
  onNext: () => void;
}) {
  const { session } = useAuth();
  const [platform, setPlatform] = useState<AgentPlatform>('linux');
  const [pkg, setPkg] = useState<GeneratedInstallerPackage | null>(null);
  const [generating, setGenerating] = useState(false);
  const [installError, setInstallError] = useState<string | null>(null);

  /*
   * The installer is generated by the backend and bound to THIS agent: it embeds
   * the enrollment credential, the configured scope and the SHA-256 of the
   * published runtime, which the script verifies on the host before executing.
   * Nothing here is a display-only template.
   */
  const generate = useCallback(async () => {
    if (!agentId || !token?.token || !session?.access_token) {
      setInstallError('Create the collector first — the installer must embed a live enrollment token.');
      return;
    }
    setGenerating(true);
    setInstallError(null);
    try {
      const response = await fetch('/api/v1/agent-installer/package', {
        method: 'POST',
        headers: { Authorization: `Bearer ${session.access_token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId, platform, token: token.token }),
      });
      const json = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(json?.error?.message || `Installer generation failed (${response.status})`);
      setPkg(json.data as GeneratedInstallerPackage);
    } catch (error) {
      setPkg(null);
      setInstallError(error instanceof Error ? error.message : 'Installer generation failed');
    } finally {
      setGenerating(false);
    }
  }, [agentId, token, session, platform]);

  const download = useCallback(() => {
    if (!pkg) return;
    const blob = new Blob([pkg.content], { type: `${pkg.contentType};charset=utf-8` });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = pkg.filename;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }, [pkg]);

  const platforms = AGENT_PLATFORMS;
  void tenantId;
  void apiUrl;

  return (
    <div className="space-y-5">
      {/* Token panel */}
      <div className="rounded-xl border border-amber-400/25 bg-amber-400/[0.06] p-4">
        <div className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-amber-300" />
          <span className="text-sm font-black text-amber-100">Enrollment Token</span>
          {token ? <span className="rounded-full border border-amber-400/30 bg-amber-400/10 px-2 py-0.5 text-[10px] font-black uppercase text-amber-200">Shown once</span> : null}
        </div>
        {token ? (
          <>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <code className="flex-1 break-all rounded-lg border border-white/12 bg-black/40 px-3 py-2 font-mono text-xs text-emerald-200">{token.token}</code>
              <CopyButton value={token.token} label="Copy Token" />
              <button type="button" onClick={() => void onRotate()} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[11px] font-bold text-white/70 transition hover:border-amber-400/40 hover:text-amber-200">
                <RefreshCw className="h-3.5 w-3.5" /> Rotate
              </button>
            </div>
            <p className="mt-2 text-[11px] text-amber-100/70">
              Store this now — it cannot be recovered. Expires with the collector; rotate any time to invalidate the old token.
            </p>
          </>
        ) : (
          <p className="mt-2 text-sm text-amber-100/70">Create the collector to generate a one-time enrollment token.</p>
        )}
      </div>

      {/* Platform selection + real installer generation */}
      <div>
        <div className="mb-3 flex flex-wrap gap-1.5">
          {platforms.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                setPlatform(item.id);
                setPkg(null);
                setInstallError(null);
              }}
              className={`rounded-lg border px-3 py-1.5 text-xs font-bold transition ${platform === item.id ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200' : 'border-white/8 bg-white/[0.02] text-white/55 hover:text-white/80'}`}
            >
              {item.label}
            </button>
          ))}
        </div>

        {installError ? (
          <div className="mb-3 rounded-lg border border-rose-400/25 bg-rose-400/[0.06] px-3 py-2 text-[11px] text-rose-100">{installError}</div>
        ) : null}

        {pkg ? (
          <div className="space-y-3">
            <div className="rounded-xl border border-white/10 bg-black/40">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/8 px-3 py-2">
                <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-white/55">
                  <Terminal className="h-3.5 w-3.5" /> {pkg.filename}
                </span>
                <div className="flex items-center gap-2">
                  <CopyButton value={pkg.content} label="Copy file" />
                  <button
                    type="button"
                    onClick={download}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/40 bg-cyan-400/10 px-3 py-1.5 text-[11px] font-black text-cyan-100 transition hover:bg-cyan-400/20"
                  >
                    <Download className="h-3.5 w-3.5" /> Download installer
                  </button>
                </div>
              </div>
              <pre className="max-h-64 overflow-auto p-4 text-[12px] leading-relaxed text-white/80"><code>{pkg.content}</code></pre>
            </div>

            <div className="grid gap-2 sm:grid-cols-2">
              <div className="rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2 text-[11px]">
                <div className="text-white/40">Run it ({pkg.instructions.privileges})</div>
                <code className="mt-1 block break-all font-mono text-cyan-200">{pkg.instructions.runCommand}</code>
              </div>
              <div className="rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2 text-[11px]">
                <div className="text-white/40">Runtime v{pkg.runtime.version} SHA-256 (verified on the host)</div>
                <code className="mt-1 block break-all font-mono text-white/65">{pkg.runtime.sha256}</code>
              </div>
            </div>

            <p className="text-[11px] leading-relaxed text-amber-100/70">
              This file carries a live enrollment credential — transfer it over a trusted channel and keep it out of source control.
            </p>
          </div>
        ) : (
          <div className="rounded-xl border border-white/10 bg-black/30 p-5 text-center">
            <Terminal className="mx-auto h-5 w-5 text-cyan-300" />
            <p className="mx-auto mt-2.5 max-w-md text-[11px] leading-relaxed text-white/55">
              The installer is generated server-side and bound to this collector. It downloads the published agent runtime,
              verifies its SHA-256, writes a 0600 configuration file and registers a supervised service.
            </p>
            <div className="mt-3 flex flex-wrap items-center justify-center gap-2">
              <button
                type="button"
                onClick={() => void generate()}
                disabled={generating || !token?.token || !agentId}
                className="inline-flex items-center gap-2 rounded-lg border border-cyan-400/40 bg-cyan-400/10 px-3.5 py-2 text-xs font-black text-cyan-100 transition hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {generating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
                Generate installer
              </button>
              <a
                href="/downloads"
                className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[11px] font-bold text-white/65 no-underline transition hover:text-cyan-200"
              >
                Open Agent Center
              </a>
            </div>
          </div>
        )}
      </div>

      <button type="button" onClick={onNext} className="inline-flex items-center gap-2 rounded-xl border border-white/12 bg-white/[0.04] px-4 py-2.5 text-sm font-bold text-white/80 transition hover:border-cyan-400/40 hover:text-cyan-200">
        I've installed it — verify connection <ArrowRight className="h-4 w-4" />
      </button>
    </div>
  );
}

/** Shape returned by POST /api/v1/agent-installer/package. */
type GeneratedInstallerPackage = {
  filename: string;
  contentType: string;
  content: string;
  installerSha256: string;
  runtime: { version: string; sha256: string; bytes: number; requiresNode: string };
  instructions: { runCommand: string; privileges: string; service: string };
};

function VerifyStep({ agent, onNext, onView }: { agent: CollectorAgent | null; onNext: () => void; onView: () => void }) {
  const connected = agent ? isAgentOnline(agent) : false;
  const rows = agent
    ? [
        ['Collector Status', agentDisplayStatus(agent)],
        ['Hostname', agent.hostname || 'Pending'],
        ['Version', agent.version || '—'],
        ['Environment', String(agent.metadata?.environment || '—')],
        ['Heartbeat', relTime(agent.last_seen_at)],
        ['Connection Quality', connectionQuality(agent)],
        ['Last Seen', fmtDate(agent.last_seen_at)],
        ['Health Score', `${agentHealthScore(agent)}/100`],
      ]
    : [];

  return (
    <div className="max-w-2xl space-y-4">
      {!connected ? (
        <div className="flex items-center gap-3 rounded-xl border border-amber-400/25 bg-amber-400/[0.06] px-4 py-3 text-sm text-amber-100">
          <Loader2 className="h-4 w-4 animate-spin" /> Waiting for first heartbeat… this panel refreshes automatically.
        </div>
      ) : (
        <div className="flex items-center gap-3 rounded-xl border border-emerald-400/25 bg-emerald-400/[0.06] px-4 py-3 text-sm text-emerald-100">
          <ShieldCheck className="h-4 w-4" /> Collector connected and healthy.
        </div>
      )}
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {rows.map(([k, v]) => (
          <div key={k} className="flex items-center justify-between rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
            <span className="text-[11px] font-bold uppercase tracking-wide text-white/40">{k}</span>
            <span className="text-sm font-semibold text-white/85">{v}</span>
          </div>
        ))}
      </div>
      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={onNext} disabled={!connected} className="inline-flex items-center gap-2 rounded-xl border border-cyan-400/40 bg-cyan-400/10 px-4 py-2.5 text-sm font-black text-cyan-200 transition hover:bg-cyan-400/20 disabled:opacity-50">
          Continue <ArrowRight className="h-4 w-4" />
        </button>
        <button type="button" onClick={onView} className="inline-flex items-center gap-2 rounded-xl border border-white/12 bg-white/[0.04] px-4 py-2.5 text-sm font-bold text-white/75 transition hover:border-white/25">
          Open collector details
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Collectors — simplified table                                       */
/* ------------------------------------------------------------------ */
function CollectorsSection({ collector, onView }: { collector: CollectorApi; onView: (id: string) => void }) {
  if (collector.state === 'loading') {
    return <div className={`${PANEL} p-5`}><Skeleton className="h-40 w-full" /></div>;
  }
  if (!collector.agents.length) {
    return (
      <div className={`${PANEL} flex flex-col items-center gap-3 px-6 py-14 text-center`}>
        <Server className="h-8 w-8 text-white/25" />
        <p className="text-sm text-white/55">No collectors yet. Create one from the Overview tab to start discovering cryptographic assets.</p>
      </div>
    );
  }
  return (
    <div className="space-y-4">
      <BindingsOverview collector={collector} onView={onView} />
      <div className={`${PANEL} overflow-hidden`}>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[1120px] text-left text-sm">
            <thead>
              <tr className="border-b border-white/8 text-[10px] uppercase tracking-[0.12em] text-white/40">
                <th className="px-5 py-3 font-black">Collector</th>
                <th className="px-4 py-3 font-black">Bound To</th>
                <th className="px-4 py-3 font-black">Agent Type</th>
                <th className="px-4 py-3 font-black">Environment</th>
                <th className="px-4 py-3 font-black">Status</th>
                <th className="px-4 py-3 font-black">Version</th>
                <th className="px-4 py-3 font-black">Last Seen</th>
                <th className="px-4 py-3 font-black">Assets</th>
                <th className="px-4 py-3 font-black">Health</th>
                <th className="px-4 py-3 font-black">Actions</th>
              </tr>
            </thead>
            <tbody>
              {collector.agents.map((agent) => {
                const assetsForAgent = new Set(collector.evidence.filter((e) => e.agent_id === agent.id).map((e) => e.asset_name || e.host || e.id)).size;
                const health = agentHealthScore(agent);
                const healthColor = health >= 70 ? 'text-emerald-300' : health >= 40 ? 'text-amber-300' : 'text-red-300';
                return (
                  <tr key={agent.id} className="border-b border-white/5 transition hover:bg-white/[0.02]">
                    <td className="px-5 py-3">
                      <button type="button" onClick={() => onView(agent.id)} className="text-left font-bold text-white/90 hover:text-cyan-200">
                        {agent.name}
                      </button>
                    </td>
                    <td className="px-4 py-3"><BindingChip binding={agentBindingFromMetadata(agent.metadata)} /></td>
                    <td className="px-4 py-3"><RoleChip agent={agent} /></td>
                    <td className="px-4 py-3 capitalize text-white/60">{String(agent.metadata?.environment || '—')}</td>
                    <td className="px-4 py-3"><StatusBadge status={agentDisplayStatus(agent)} /></td>
                    <td className="px-4 py-3 font-mono text-white/55">
                      <span className="whitespace-nowrap">{agent.version || '—'}</span>
                      {/* Rollback needs a runtime that understands the command; an
                          older host is told so here rather than at the moment an
                          operator needs the rollback to work. */}
                      {agent.version && !agentVersionAtLeast(agent.version, AGENT_ROLLBACK_MIN_VERSION) && (
                        <span
                          className="ml-1.5 inline-block whitespace-nowrap rounded border border-amber-400/30 bg-amber-400/10 px-1 py-0.5 font-sans text-[9px] font-bold text-amber-200"
                          title={`Rollback execution requires agent ${AGENT_ROLLBACK_MIN_VERSION} or later. Upgrade this host to make snapshot restore available on it.`}
                        >
                          no rollback
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-white/55">{relTime(agent.last_seen_at)}</td>
                    <td className="px-4 py-3 tabular-nums text-white/70">{assetsForAgent}</td>
                    <td className={`px-4 py-3 font-bold tabular-nums ${healthColor}`}>{health}/100</td>
                    <td className="px-4 py-3">
                      <button type="button" onClick={() => onView(agent.id)} className="rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1 text-[11px] font-bold text-white/70 transition hover:border-cyan-400/40 hover:text-cyan-200">
                        Details
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

/**
 * Every binding target with the agents reporting into it and what has been
 * filed under it. Counts come from the binding stamped on each evidence row
 * and alert when it was recorded — so a rebind moves future findings, never
 * past ones — and cover the recent records the console has loaded.
 */
function BindingsOverview({ collector, onView }: { collector: CollectorApi; onView: (id: string) => void }) {
  const groups = useMemo(() => {
    const byAsset = new Map<string, { binding: AgentBinding; agents: CollectorAgent[]; evidence: number; openAlerts: number; critical: number }>();
    for (const agent of collector.agents) {
      const binding = agentBindingFromMetadata(agent.metadata);
      if (!binding || agent.revoked_at || agent.status === 'revoked') continue;
      const group = byAsset.get(binding.assetId) || { binding, agents: [], evidence: 0, openAlerts: 0, critical: 0 };
      group.agents.push(agent);
      byAsset.set(binding.assetId, group);
    }
    for (const row of collector.evidence) {
      const group = byAsset.get(filedBindingId(row) || '');
      if (group) group.evidence += 1;
    }
    for (const alert of collector.alerts) {
      const group = byAsset.get(filedBindingId(alert) || '');
      if (!group || !isOpenAlert(alert)) continue;
      group.openAlerts += 1;
      if (String(alert.severity).toLowerCase() === 'critical') group.critical += 1;
    }
    return Array.from(byAsset.values()).sort((a, b) => b.openAlerts - a.openAlerts || a.binding.assetName.localeCompare(b.binding.assetName));
  }, [collector.agents, collector.evidence, collector.alerts]);

  const active = collector.agents.filter((a) => !a.revoked_at && a.status !== 'revoked');
  const unbound = active.filter((a) => !agentBindingFromMetadata(a.metadata));

  return (
    <div className={`${PANEL} p-5`}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Link2 className="h-4 w-4 text-cyan-300" />
          <h3 className="text-sm font-black uppercase tracking-wide text-white/80">Asset Bindings</h3>
        </div>
        <span className="text-[11px] text-white/45">
          {active.length - unbound.length} of {active.length} active collector{active.length === 1 ? '' : 's'} bound · {unbound.length} on open discovery
        </span>
      </div>
      {groups.length ? (
        <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2 xl:grid-cols-3">
          {groups.map(({ binding, agents, evidence, openAlerts, critical }) => {
            const Icon = bindingIcon(binding.kind);
            return (
              <div key={binding.assetId} className="rounded-xl border border-white/8 bg-white/[0.02] p-3.5">
                <div className="flex items-start gap-2.5">
                  <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-cyan-400/25 bg-cyan-400/10 text-cyan-200">
                    <Icon className="h-4 w-4" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-bold text-white/90">{binding.assetName}</div>
                    <div className="truncate text-[11px] text-white/40">
                      {bindingKind(binding.kind)?.label || binding.kind || 'Asset'}
                      {binding.path ? ` · ${binding.path}` : ''}
                    </div>
                  </div>
                </div>
                <div className="mt-3 grid grid-cols-3 gap-1.5 text-center">
                  {[
                    ['Agents', agents.length, 'text-white/85'],
                    ['Evidence', evidence, 'text-white/85'],
                    ['Open alerts', openAlerts, critical > 0 ? 'text-red-300' : openAlerts > 0 ? 'text-amber-300' : 'text-emerald-300'],
                  ].map(([label, value, tone]) => (
                    <div key={String(label)} className="rounded-lg border border-white/8 bg-white/[0.02] px-2 py-1.5">
                      <div className={`text-base font-black tabular-nums ${tone}`}>{value as number}</div>
                      <div className="text-[9px] font-bold uppercase tracking-wide text-white/35">{label}</div>
                    </div>
                  ))}
                </div>
                <div className="mt-2.5 flex flex-wrap gap-1">
                  {agents.map((agent) => (
                    <button
                      key={agent.id}
                      type="button"
                      onClick={() => onView(agent.id)}
                      className="inline-flex items-center gap-1 rounded-full border border-white/10 px-2 py-0.5 text-[10px] font-bold text-white/60 transition hover:border-cyan-400/40 hover:text-cyan-200"
                    >
                      <StatusDot tone={isAgentOnline(agent) ? 'ok' : 'idle'} /> {agent.name}
                    </button>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <p className="text-sm text-white/45">
          No collector is bound to an asset yet. Bind one from its details drawer, or choose a target when you create a collector,
          to file its findings under an application, folder, file or profile of your choosing.
        </p>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Scans / Findings summary                                            */
/* ------------------------------------------------------------------ */
function ScansSection({ collector, onToast }: { collector: CollectorApi; onToast: (tone: 'ok' | 'bad', text: string) => void }) {
  const s = collector.summary;
  const findings = [
    { label: 'Assets Scanned', value: s.assetsDiscovered },
    { label: 'Evidence Records', value: s.evidenceCount },
    { label: 'Quantum Vulnerabilities', value: s.quantumRisks },
    { label: 'Pending Remediation', value: s.pendingRemediation },
  ];
  const openAlerts = collector.alerts.filter((a) => !['resolved', 'closed', 'suppressed'].includes(String(a.status || 'open').toLowerCase()));
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {findings.map((f) => (
          <div key={f.label} className={`${PANEL} p-4`}>
            <div className="text-3xl font-black tabular-nums text-white">{f.value}</div>
            <div className="mt-1 text-[11px] font-bold uppercase tracking-wide text-white/40">{f.label}</div>
          </div>
        ))}
      </div>
      <div className={`${PANEL} p-5`}>
        <h3 className="mb-1 text-sm font-black uppercase tracking-wide text-white/80">Scan Types</h3>
        <p className="mb-4 text-xs text-white/45">Collectors run these against their assigned targets. Start a scan from a collector's detail drawer.</p>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {SCAN_TYPES.map((st) => (
            <div key={st.id} className="rounded-xl border border-white/8 bg-white/[0.02] px-4 py-3">
              <div className="text-sm font-bold text-white/85">{st.label}</div>
              <div className="mt-0.5 text-[11px] text-white/45">{st.detail}</div>
            </div>
          ))}
        </div>
      </div>
      <div className={`${PANEL} p-5`}>
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-black uppercase tracking-wide text-white/80">Recent Findings</h3>
          <span className="text-[11px] text-white/40">{openAlerts.length} open</span>
        </div>
        {openAlerts.length ? (
          <div className="space-y-2">
            {openAlerts.slice(0, 8).map((alert) => (
              <div key={alert.id} className="flex items-center justify-between gap-3 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold text-white/85">{alert.title || alert.category || 'Finding'}</div>
                  <div className="truncate text-[11px] text-white/45">{alert.message || '—'}</div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <span className={`rounded-full border px-2 py-0.5 text-[10px] font-black uppercase ${String(alert.severity).toLowerCase() === 'critical' ? 'border-red-400/30 text-red-300' : String(alert.severity).toLowerCase() === 'high' ? 'border-orange-400/30 text-orange-300' : 'border-amber-400/30 text-amber-200'}`}>{alert.severity || 'info'}</span>
                  <button type="button" onClick={async () => { const r = await collector.acknowledgeAlert(alert.id); onToast(r.ok ? 'ok' : 'bad', r.message || (r.ok ? 'Acknowledged' : 'Failed')); }} className="rounded-lg border border-white/12 px-2 py-1 text-[10px] font-bold text-white/60 hover:text-white/90">Ack</button>
                  <button type="button" onClick={async () => { const r = await collector.resolveAlert(alert.id); onToast(r.ok ? 'ok' : 'bad', r.message || (r.ok ? 'Resolved' : 'Failed')); }} className="rounded-lg border border-emerald-400/25 px-2 py-1 text-[10px] font-bold text-emerald-300 hover:bg-emerald-400/10">Resolve</button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-white/45">No open findings. Collectors report cryptographic risks here as they scan.</p>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Operations Center — connectors + operator remediation               */
/* ------------------------------------------------------------------ */
function OperationsSection({ collector, onToast }: { collector: CollectorApi; onToast: (tone: 'ok' | 'bad', text: string) => void }) {
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const stats = {
    total: collector.operatorActions.length,
    active: collector.operatorActions.filter((a) => ['planned', 'approved', 'applying', 'applied', 'validating'].includes(String(a.status))).length,
    validated: collector.operatorActions.filter((a) => a.status === 'validated').length,
    blocked: collector.operatorActions.filter((a) => ['blocked', 'rejected', 'scheduled'].includes(String(a.status))).length,
  };

  return (
    <div className="space-y-4">
      <div className={`${PANEL} p-5`}>
        <div className="flex items-center gap-2">
          <Zap className="h-4 w-4 text-cyan-300" />
          <h3 className="text-sm font-black uppercase tracking-wide text-white/80">Operations Center</h3>
        </div>
        <p className="mt-1 text-sm text-white/50">
          Automated remediation with guarded change control — RBAC approval, pre-change snapshots, post-change validation,
          and automatic rollback on failure. Cloud, web and SaaS changes use least-privilege scoped connectors.
        </p>
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            ['Total Actions', stats.total, 'text-white'],
            ['In Progress', stats.active, 'text-cyan-300'],
            ['Validated', stats.validated, 'text-emerald-300'],
            ['Blocked / Rejected', stats.blocked, 'text-amber-300'],
          ].map(([label, value, color]) => (
            <div key={String(label)} className="rounded-xl border border-white/8 bg-white/[0.02] p-3">
              <div className={`text-2xl font-black tabular-nums ${color}`}>{value as number}</div>
              <div className="mt-0.5 text-[10px] font-bold uppercase tracking-wide text-white/40">{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Cloud Connections */}
      <div className={`${PANEL} p-5`}>
        <h3 className="mb-3 text-sm font-black uppercase tracking-wide text-white/80">Cloud Connections</h3>
        {collector.connectors.length ? (
          <div className="space-y-2">
            {collector.connectors.map((c) => (
              <div key={c.id} className="flex items-center justify-between gap-3 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2.5">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold capitalize text-white/85">{c.display_name || c.provider}</span>
                    <span className="rounded-full border border-white/10 px-2 py-0.5 text-[10px] font-bold uppercase text-white/45">{c.provider}</span>
                  </div>
                  <div className="truncate text-[11px] text-white/40">{(c.scopes || []).length} scope(s) · synced {relTime(c.last_sync_at)}</div>
                </div>
                <StatusDot tone={c.status === 'active' ? 'ok' : 'idle'} />
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-white/45">No cloud connections registered. Add one to enable scoped, approval-gated remote remediation.</p>
        )}
      </div>

      {/* QGuard Messaging (same login): the server reads this account's device rows. */}
      <div className={`${PANEL} p-5`}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0">
            <h3 className="text-sm font-black uppercase tracking-wide text-white/80">QGuard Messaging</h3>
            <p className="mt-1 text-sm text-white/50">
              Import the key-establishment, signature and encryption algorithms your messenger devices publish. Read from your own
              account on the server — no message content, contacts or conversations.
            </p>
            <p className="mt-1 text-[11px] text-white/40">
              {(() => {
                const rows = collector.evidence.filter((e) => e.evidence_type === 'messaging-device-crypto');
                if (!rows.length) return 'Not imported yet.';
                const devices = new Set(rows.map((e) => e.asset_name)).size;
                const latest = rows.map((e) => e.observed_at || e.created_at).filter(Boolean).sort().pop();
                return `${devices} device${devices === 1 ? '' : 's'} · last imported ${relTime(latest)}`;
              })()}
            </p>
          </div>
          <button
            type="button"
            disabled={collector.busy}
            onClick={async () => {
              const result = await collector.syncMessagingPosture();
              onToast(result.ok ? 'ok' : 'bad', result.message || (result.ok ? 'Imported.' : 'Import failed.'));
            }}
            className="rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-2 text-xs font-bold text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-50"
          >
            Import messenger devices
          </button>
        </div>
      </div>

      {/* Recent operator actions */}
      <div className={`${PANEL} p-5`}>
        <h3 className="mb-3 text-sm font-black uppercase tracking-wide text-white/80">Remediation Actions</h3>
        {collector.operatorActions.length ? (
          <div className="space-y-2">
            {collector.operatorActions.slice(0, 8).map((action) => (
              <div key={action.id} className="flex items-center justify-between gap-3 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2.5">
                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold text-white/85">{action.action_type || 'Patch action'} · <span className="capitalize text-white/50">{action.asset_class}</span></div>
                  <div className="text-[11px] text-white/40">Requested {relTime(action.requested_at || action.created_at)}</div>
                </div>
                <StatusBadge status={String(action.status || 'planned')} />
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-white/45">No remediation actions yet. These are created from the Migration Planner and validated here.</p>
        )}
      </div>

      {/* Progressive disclosure — advanced */}
      <div className={`${PANEL} overflow-hidden`}>
        <button type="button" onClick={() => setAdvancedOpen((v) => !v)} className="flex w-full items-center justify-between px-5 py-4 text-left">
          <span className="inline-flex items-center gap-2 text-sm font-black uppercase tracking-wide text-white/70"><Settings2 className="h-4 w-4" /> Advanced Settings</span>
          <ChevronDown className={`h-4 w-4 text-white/45 transition ${advancedOpen ? 'rotate-180' : ''}`} />
        </button>
        {advancedOpen ? (
          <div className="border-t border-white/8 px-5 py-4">
            <p className="mb-3 text-xs text-white/45">Enterprise operator capabilities — connector credentials, cloud SDK patching, JSON patch payloads, dry-run, approval gates, snapshots, rollback and evidence upload — remain fully supported through the API and are surfaced here for advanced operators.</p>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
              {['RBAC', 'Snapshots', 'Rollback', 'Connector Credentials', 'Cloud SDK', 'JSON Configuration', 'Patch Stack', 'Dry Run', 'Approval Gates', 'Evidence Upload', 'Operator Permissions', 'Cloud Provider APIs'].map((cap) => (
                <div key={cap} className="rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2 text-[11px] font-bold text-white/55">{cap}</div>
              ))}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Help — How Collectors Work                                          */
/* ------------------------------------------------------------------ */
function HelpSection() {
  const faqs = [
    ['Where do collectors run?', 'On a tenant-owned endpoint, server, VM, container, sidecar, or controlled jump host that you install and control.'],
    ['What can collectors scan?', 'Local OS crypto (when authorized), plus allow-listed network targets: TLS endpoints, certificates, PKI, SSH, VPN, load balancers, APIs, web apps, databases and — through scoped cloud connectors — cloud KMS/HSM and managed services.'],
    ['What can collectors NOT scan?', 'Anything outside their allow-listed targets and paths. They never scan arbitrary hosts, and remote mutation always requires an approved, scoped connector.'],
    ['How do cloud connections work?', 'You explicitly authorize a least-privilege, scoped connector. Remote changes go through approval, pre-change snapshots, validation and audit logging.'],
    ['What is the security model?', 'Least privilege by default. The backend stores only a hash of each token; every action is tenant-scoped, RBAC-gated and audit-logged.'],
  ];
  return (
    <div className="space-y-4">
      <div className={`${PANEL} p-5`}>
        <div className="flex items-center gap-2">
          <Info className="h-4 w-4 text-cyan-300" />
          <h3 className="text-sm font-black uppercase tracking-wide text-white/80">How Collectors Work</h3>
        </div>
        {/* Simple architecture diagram */}
        <div className="mt-4 flex flex-wrap items-center gap-2 text-[11px] font-bold">
          {['Collector (your infra)', 'Allow-listed targets', 'QGuard API', 'Assets / CBOM / Risk', 'Certification'].map((node, i, arr) => (
            <div key={node} className="flex items-center gap-2">
              <span className="rounded-lg border border-white/12 bg-white/[0.03] px-3 py-2 text-white/70">{node}</span>
              {i < arr.length - 1 ? <ArrowRight className="h-3.5 w-3.5 text-white/30" /> : null}
            </div>
          ))}
        </div>
      </div>
      <div className={`${PANEL} divide-y divide-white/8`}>
        {faqs.map(([q, a]) => (
          <details key={q} className="group px-5 py-4">
            <summary className="flex cursor-pointer items-center justify-between text-sm font-bold text-white/85">
              {q}
              <ChevronDown className="h-4 w-4 text-white/40 transition group-open:rotate-180" />
            </summary>
            <p className="mt-2 text-sm text-white/55">{a}</p>
          </details>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Drawer — asset binding                                              */
/* ------------------------------------------------------------------ */
function draftFromBinding(binding: AgentBinding | null): BindingDraft {
  return binding
    ? { ...EMPTY_BINDING_DRAFT, mode: 'existing', assetId: binding.assetId, attribution: binding.attribution }
    : { ...EMPTY_BINDING_DRAFT };
}

function BindingSection({ agent, collector, isRevoked, onToast }: {
  agent: CollectorAgent;
  collector: CollectorApi;
  isRevoked: boolean;
  onToast: (tone: 'ok' | 'bad', text: string) => void;
}) {
  const binding = agentBindingFromMetadata(agent.metadata);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<BindingDraft>(() => draftFromBinding(binding));
  const [conflict, setConflict] = useState<BindingConflict | null>(null);
  const [issue, setIssue] = useState<string | null>(null);

  const filedEvidence = binding ? collector.evidence.filter((e) => e.agent_id === agent.id && filedBindingId(e) === binding.assetId).length : 0;
  const filedOpenAlerts = binding ? collector.alerts.filter((a) => a.agent_id === agent.id && filedBindingId(a) === binding.assetId && isOpenAlert(a)).length : 0;
  const Icon = bindingIcon(binding?.kind);
  const unchanged = (draft.mode === 'none' && !binding)
    || (draft.mode === 'existing' && binding && draft.assetId === binding.assetId && draft.attribution === binding.attribution);

  const save = async () => {
    const problem = bindingDraftIssue(draft, collector.bindingTargets);
    setIssue(problem);
    if (problem) return;
    const result = await collector.updateBinding(agent.id, bindingRequestFromDraft(draft));
    if (result.conflict) {
      setConflict(result.conflict);
      return;
    }
    onToast(result.ok ? 'ok' : 'bad', result.message || (result.ok ? 'Binding updated.' : 'Binding update failed.'));
    if (result.ok) setEditing(false);
  };

  return (
    <section>
      <div className="mb-2 flex items-center justify-between">
        <h4 className="text-[11px] font-black uppercase tracking-wide text-white/40">Asset Binding</h4>
        {!isRevoked && !editing ? (
          <button
            type="button"
            onClick={() => { setDraft(draftFromBinding(binding)); setConflict(null); setIssue(null); setEditing(true); }}
            className="inline-flex items-center gap-1 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1 text-[11px] font-bold text-white/70 transition hover:border-cyan-400/40 hover:text-cyan-200"
          >
            <Link2 className="h-3.5 w-3.5" /> {binding ? 'Change binding' : 'Bind to asset'}
          </button>
        ) : null}
      </div>

      {!editing ? (
        binding ? (
          <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/[0.05] p-4">
            <div className="flex items-start gap-3">
              <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-cyan-400/30 bg-cyan-400/10 text-cyan-200">
                <Icon className="h-5 w-5" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-black text-white">{binding.assetName}</div>
                <div className="truncate text-[11px] text-white/50">
                  {bindingKind(binding.kind)?.label || binding.kind || 'Asset'}
                  {binding.path ? <> · <span className="font-mono">{binding.path}</span></> : null}
                </div>
                <div className="mt-1 text-[11px] text-white/55">
                  {binding.attribution === 'bound' ? 'Every finding is filed under this target.' : 'Discovered assets are grouped under this target.'}
                </div>
              </div>
            </div>
            <div className="mt-3 grid grid-cols-3 gap-2 text-center">
              {[
                ['Filed evidence', String(filedEvidence)],
                ['Open alerts', String(filedOpenAlerts)],
                ['Bound', binding.boundAt ? relTime(binding.boundAt) : '—'],
              ].map(([k, v]) => (
                <div key={k} className="rounded-lg border border-white/8 bg-white/[0.02] px-2 py-2">
                  <div className="text-[9px] font-bold uppercase tracking-wide text-white/35">{k}</div>
                  <div className="mt-0.5 text-[12px] font-bold tabular-nums text-white/80">{v}</div>
                </div>
              ))}
            </div>
            <a
              href="/dashboard/assets"
              className="mt-3 inline-flex items-center gap-1 text-[11px] font-bold text-cyan-200 no-underline hover:text-cyan-100"
            >
              Open in Assets <ArrowRight className="h-3 w-3" />
            </a>
          </div>
        ) : (
          <div className="rounded-xl border border-white/8 bg-white/[0.02] px-4 py-3 text-[12px] leading-relaxed text-white/55">
            <span className="mb-1 flex items-center gap-1.5 font-bold text-white/75"><Radar className="h-3.5 w-3.5" /> Device profile</span>
            Certificates, components and findings are kept together under this machine’s profile. You can select an existing
            application profile to file them under another target you own.
          </div>
        )
      ) : (
        <div className="space-y-3 rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <AssetBindingPicker
            value={draft}
            onChange={(next) => { setDraft(next); setConflict(null); setIssue(null); }}
            targets={collector.bindingTargets}
            targetsState={collector.bindingTargetsState}
            onReloadTargets={() => void collector.loadBindingTargets()}
            conflict={conflict}
            agentName={agent.name}
            currentAssetId={binding?.assetId || null}
          />
          <p className="text-[11px] leading-relaxed text-white/40">
            Applies to evidence this collector uploads from now on. Findings already recorded stay filed where they were, so the
            audit trail is never rewritten.
          </p>
          {issue ? (
            <div role="alert" className="flex items-center gap-2 rounded-lg border border-[var(--qg-notice-border)] bg-[var(--qg-notice-bg)] px-3 py-2 text-[12px] text-[var(--qg-notice-text)]">
              <TriangleAlert className="h-4 w-4 shrink-0 text-amber-300" /> {issue}
            </div>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => void save()}
              disabled={collector.busy || Boolean(unchanged)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/40 bg-cyan-400/10 px-3.5 py-2 text-xs font-black text-cyan-100 transition hover:bg-cyan-400/20 disabled:opacity-40"
            >
              {collector.busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
              {draft.mode === 'none' ? 'Remove binding' : 'Save binding'}
            </button>
            <button
              type="button"
              onClick={() => setEditing(false)}
              className="rounded-lg border border-white/12 bg-white/[0.04] px-3.5 py-2 text-xs font-bold text-white/70 transition hover:text-white"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Collector Details Drawer                                            */
/* ------------------------------------------------------------------ */
function CollectorDrawer({ agent, tenantId, apiUrl, collector, onClose, onToast }: {
  agent: CollectorAgent;
  tenantId: string;
  apiUrl: string;
  collector: CollectorApi;
  onClose: () => void;
  onToast: (tone: 'ok' | 'bad', text: string) => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => { closeRef.current?.focus(); }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const evidence = collector.evidence.filter((e) => e.agent_id === agent.id);
  const alerts = collector.alerts.filter((a) => a.agent_id === agent.id);
  const assetCount = new Set(evidence.map((e) => e.asset_name || e.host || e.id)).size;
  const health = agentHealthScore(agent);
  const policy = (agent.policy || {}) as Record<string, unknown>;
  const overview = [
    ['Platform', String(agent.platform || 'customer-managed')],
    ['OS / Hostname', String(agent.hostname || 'Pending install')],
    ['Version', String(agent.version || '—')],
    ['Environment', String(agent.metadata?.environment || '—')],
    ['Health Score', `${health}/100`],
    ['Connection', connectionQuality(agent)],
    ['Last Seen', fmtDate(agent.last_seen_at)],
    ['Assets Discovered', String(assetCount)],
  ];
  const isRevoked = Boolean(agent.revoked_at || agent.status === 'revoked');

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-label={`Collector ${agent.name}`}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
      <div className="relative flex h-full w-full max-w-xl flex-col overflow-hidden border-l border-white/10 bg-[#0b1120] shadow-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-white/8 px-5 py-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h3 className="truncate text-lg font-black text-white">{agent.name}</h3>
              <StatusBadge status={agentDisplayStatus(agent)} />
            </div>
            <p className="mt-0.5 text-[11px] text-white/40">Heartbeat {relTime(agent.last_seen_at)}</p>
          </div>
          <button ref={closeRef} type="button" onClick={onClose} className="rounded-lg border border-white/12 bg-white/[0.04] p-2 text-white/60 transition hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5">
          {/* Overview */}
          <section>
            <h4 className="mb-2 text-[11px] font-black uppercase tracking-wide text-white/40">Overview</h4>
            <div className="grid grid-cols-2 gap-2">
              {overview.map(([k, v]) => (
                <div key={k} className="rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
                  <div className="text-[10px] font-bold uppercase tracking-wide text-white/35">{k}</div>
                  <div className="mt-0.5 truncate text-sm font-semibold text-white/85">{v}</div>
                </div>
              ))}
            </div>
          </section>

          <BindingSection agent={agent} collector={collector} isRevoked={isRevoked} onToast={onToast} />

          {/* Health */}
          <section>
            <h4 className="mb-2 text-[11px] font-black uppercase tracking-wide text-white/40">Agent Health</h4>
            <div className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
              <div className="mb-2 flex items-center justify-between">
                <span className="inline-flex items-center gap-1.5 text-sm font-bold text-white/85"><Heart className="h-4 w-4 text-rose-300" /> {agentDisplayStatus(agent)}</span>
                <span className={`text-sm font-black tabular-nums ${health >= 70 ? 'text-emerald-300' : health >= 40 ? 'text-amber-300' : 'text-red-300'}`}>{health}/100</span>
              </div>
              <div className="h-1.5 overflow-hidden rounded-full bg-white/10">
                <div className={`h-full rounded-full ${health >= 70 ? 'bg-emerald-400' : health >= 40 ? 'bg-amber-400' : 'bg-red-400'}`} style={{ width: `${health}%` }} />
              </div>
              <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                {[['Heartbeat', relTime(agent.last_seen_at)], ['Version', agent.version || '—'], ['Interval', `${Number(policy.intervalSeconds || policy.interval_seconds || 60)}s`]].map(([k, v]) => (
                  <div key={k} className="rounded-lg border border-white/8 bg-white/[0.02] px-2 py-2">
                    <div className="text-[9px] font-bold uppercase tracking-wide text-white/35">{k}</div>
                    <div className="mt-0.5 text-[11px] font-semibold text-white/75">{v}</div>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* Scan action */}
          {!isRevoked ? (
            <section>
              <h4 className="mb-2 text-[11px] font-black uppercase tracking-wide text-white/40">Start Scan</h4>
              <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={async () => {
                      const r = await collector.requestScan(agent.id);
                      if (!r.ok) onToast('bad', r.message || 'Unable to queue the scan.');
                    }}
                    disabled={collector.busy || policy.enabled === false}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-400/[0.08] px-3 py-2 text-xs font-bold text-cyan-200 transition hover:bg-cyan-400/15"
                  >
                    <Play className="h-3.5 w-3.5" /> Scan authorized scope
                  </button>
              </div>
              <p className="mt-2 text-[11px] text-white/40">Scans respect the collector's authorized targets and paths from policy.</p>
            </section>
          ) : null}

          {/* Findings */}
          <section>
            <h4 className="mb-2 text-[11px] font-black uppercase tracking-wide text-white/40">Quantum Findings ({alerts.length})</h4>
            {alerts.length ? (
              <div className="space-y-1.5">
                {alerts.slice(0, 6).map((a) => (
                  <div key={a.id} className="rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
                    <div className="truncate text-sm font-semibold text-white/80">{a.title || a.category || 'Finding'}</div>
                    <div className="text-[10px] uppercase tracking-wide text-white/35">{a.severity || 'info'} · {relTime(a.created_at)}</div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-white/40">No findings reported by this collector yet.</p>
            )}
          </section>

          {/* Recent telemetry */}
          <section>
            <h4 className="mb-2 text-[11px] font-black uppercase tracking-wide text-white/40">Recent Telemetry ({evidence.length})</h4>
            {evidence.length ? (
              <div className="space-y-1.5">
                {evidence.slice(0, 6).map((e) => (
                  <div key={e.id} className="flex items-center justify-between gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold text-white/80">{e.asset_name || e.host || 'Asset'}</div>
                      <div className="truncate text-[10px] text-white/40">{e.observed_algorithm || e.evidence_type || '—'}</div>
                    </div>
                    <span className="shrink-0 text-[10px] text-white/35">{relTime(e.observed_at || e.created_at)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-white/40">No telemetry received yet.</p>
            )}
          </section>
        </div>

        {/* Sticky action bar */}
        <div className="flex flex-wrap items-center gap-2 border-t border-white/8 bg-[#0b1120]/95 px-5 py-3">
          {!isRevoked ? (
            <>
              <button type="button" onClick={async () => { const r = await collector.rotateToken(agent.id); onToast(r.ok ? 'ok' : 'bad', r.ok ? 'New token generated — copy it now.' : r.message || 'Failed'); }} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-xs font-bold text-white/75 transition hover:border-amber-400/40 hover:text-amber-200">
                <KeyRound className="h-3.5 w-3.5" /> Rotate Token
              </button>
              <button type="button" onClick={async () => { const r = await collector.revokeCollector(agent.id); onToast(r.ok ? 'ok' : 'bad', r.message || (r.ok ? 'Revoked' : 'Failed')); if (r.ok) onClose(); }} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-xs font-bold text-white/75 transition hover:border-orange-400/40 hover:text-orange-200">
                <Shield className="h-3.5 w-3.5" /> Revoke
              </button>
            </>
          ) : null}
          <button type="button" onClick={async () => { if (!window.confirm('Delete this collector permanently? This cannot be undone.')) return; const r = await collector.deleteCollector(agent.id); onToast(r.ok ? 'ok' : 'bad', r.message || (r.ok ? 'Deleted' : 'Failed')); if (r.ok) onClose(); }} className="ml-auto inline-flex items-center gap-1.5 rounded-lg border border-red-400/25 bg-red-500/10 px-3 py-2 text-xs font-bold text-red-300 transition hover:bg-red-500/20">
            <Trash2 className="h-3.5 w-3.5" /> Delete
          </button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Install command builder                                             */
/* ------------------------------------------------------------------ */
