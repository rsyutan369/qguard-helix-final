'use client';

import { Fragment, useCallback } from 'react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  Boxes,
  CheckCircle2,
  CircleGauge,
  Cpu,
  Database,
  Download,
  FileText,
  Fingerprint,
  GitBranch,
  Globe,
  KeyRound,
  Layers,
  LineChart,
  Lock,
  Network,
  Radar,
  RefreshCw,
  Scale,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  Workflow,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { usePQAuthDashboard } from '@/hooks/use-pqauth-dashboard';
import type { PQAuthMode, PQAuthRow, PQAuthSnapshot } from '@/types/pqauth-dashboard';

const BLUE = '#2478FF';
const CYAN = '#22D3EE';
const GOLD = '#FBBF24';
const GREEN = '#22C55E';
const ORANGE = '#F97316';
const PURPLE = '#8B5CF6';
const RED = '#EF4444';
const TEAL = '#14B8A6';

const PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-blue-400/12 bg-[#07101D]/72 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(36,120,255,0.035),0_0_34px_rgba(0,0,0,0.34)] transition duration-500 hover:-translate-y-0.5 hover:border-gold/60 hover:bg-[#0A1728]/84 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.18),inset_0_-24px_60px_rgba(251,191,36,0.10),0_16px_46px_rgba(0,0,0,0.46),0_0_52px_rgba(251,191,36,0.22)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FDE68A]/50 before:to-transparent';

const MODE_COPY = {
  overview: {
    title: 'PQC-Auth Identity Migration Engine',
    eyebrow: 'PQAuth Command Center',
    subtitle: 'Enterprise command center for post-quantum OAuth, OIDC, SAML, JWT, machine identity, API authentication, and trust migration.',
    Icon: Fingerprint,
  },
  discovery: {
    title: 'Identity Discovery Engine',
    eyebrow: 'Discover',
    subtitle: 'Provider discovery, identity inventory, signing-key capture, authentication flow mapping, and dependency evidence.',
    Icon: ScanSearch,
  },
  'trust-graph': {
    title: 'Identity Trust Fabric',
    eyebrow: 'Map Trust',
    subtitle: 'Authentication trust graph for users, machines, applications, APIs, certificates, issuers, gateways, and resource servers.',
    Icon: Network,
  },
  'token-intelligence': {
    title: 'JWT & Token Intelligence',
    eyebrow: 'Analyze Tokens',
    subtitle: 'JWT, JWS, JWE, opaque-token, access-token, ID-token, and refresh-token readiness with post-quantum size-impact planning.',
    Icon: KeyRound,
  },
  'exposure-analysis': {
    title: 'Quantum Exposure Analyzer',
    eyebrow: 'Assess Risk',
    subtitle: 'Identity quantum risk scoring across RSA, ECC, ECDSA, EdDSA, DH, ECDH, trust dependencies, and HNDL exposure.',
    Icon: ShieldAlert,
  },
  compatibility: {
    title: 'PQC Compatibility Assessment',
    eyebrow: 'Validate Readiness',
    subtitle: 'Compatibility checks for applications, APIs, gateways, mobile apps, service meshes, WAFs, load balancers, and cloud platforms.',
    Icon: CheckCircle2,
  },
  'digital-twin': {
    title: 'Identity Digital Twin',
    eyebrow: 'Simulate',
    subtitle: 'Migration twin for IdPs, JWT flows, trust chains, certificates, keys, OAuth flows, and failure prediction.',
    Icon: GitBranch,
  },
  'migration-center': {
    title: 'Autonomous Identity Migration Orchestrator',
    eyebrow: 'Execute Migration',
    subtitle: 'Phased migration operations from discovery through full PQC rollout, validation, continuous monitoring, and rollback gates.',
    Icon: Workflow,
  },
  'runtime-telemetry': {
    title: 'Runtime Identity Telemetry',
    eyebrow: 'Monitor Runtime',
    subtitle: 'Realtime authentication, authorization, token validation, certificate usage, trust failure, and identity drift telemetry.',
    Icon: Activity,
  },
  compliance: {
    title: 'Governance & Compliance',
    eyebrow: 'Govern & Audit',
    subtitle: 'Evidence-backed readiness scoring for NIST, CNSA 2.0, PCI-DSS, ISO 27001, SOC 2, and FedRAMP programs.',
    Icon: Scale,
  },
  qkms: {
    title: 'QKMS Integration',
    eyebrow: 'Key Lifecycle',
    subtitle: 'Signing, verification, TLS, certificate, identity, and machine-identity key ownership, rotation, expiration, revocation, and readiness.',
    Icon: Database,
  },
} satisfies Record<PQAuthMode, { title: string; eyebrow: string; subtitle: string; Icon: LucideIcon }>;

const WORKFLOW: Array<{ mode: PQAuthMode; href: string }> = [
  { mode: 'overview', href: '/dashboard/pqauth' },
  { mode: 'discovery', href: '/dashboard/pqauth/discovery' },
  { mode: 'exposure-analysis', href: '/dashboard/pqauth/exposure-analysis' },
  { mode: 'trust-graph', href: '/dashboard/pqauth/trust-graph' },
  { mode: 'token-intelligence', href: '/dashboard/pqauth/token-intelligence' },
  { mode: 'compatibility', href: '/dashboard/pqauth/compatibility' },
  { mode: 'digital-twin', href: '/dashboard/pqauth/digital-twin' },
  { mode: 'migration-center', href: '/dashboard/pqauth/migration-center' },
  { mode: 'runtime-telemetry', href: '/dashboard/pqauth/runtime-telemetry' },
  { mode: 'compliance', href: '/dashboard/pqauth/compliance' },
  { mode: 'qkms', href: '/dashboard/pqauth/qkms' },
];

const ICON_MAP: Record<string, LucideIcon> = {
  Activity,
  AlertTriangle,
  BadgeCheck,
  Boxes,
  CheckCircle2,
  CircleGauge,
  Cpu,
  Database,
  FileText,
  Fingerprint,
  GitBranch,
  Globe,
  KeyRound,
  Layers,
  LineChart,
  Lock,
  Network,
  Radar,
  Scale,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  Workflow,
  Zap,
};

function compactFmt(value: number) {
  return new Intl.NumberFormat('en-US', {
    notation: Math.abs(value) >= 100000 ? 'compact' : 'standard',
    maximumFractionDigits: Math.abs(value) >= 100000 ? 1 : 0,
  }).format(Math.max(0, Number(value) || 0));
}

function integerFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(Number(value) || 0)));
}

function percentFmt(value: number) {
  return `${Math.round(Number(value) || 0)}%`;
}

function clampScore(value: number) {
  return Math.max(0, Math.min(100, Math.round(Number(value) || 0)));
}

function longDate(value: string | null) {
  if (!value) return 'Awaiting identity evidence';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Awaiting identity evidence';
  return date.toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function shortTime(value: unknown) {
  const text = String(value || '');
  if (!text) return 'awaiting';
  const ms = new Date(text).getTime();
  if (!Number.isFinite(ms)) return 'awaiting';
  const minutes = Math.max(0, Math.round((Date.now() - ms) / 60000));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function scoreColor(value: number, inverse = false) {
  const score = clampScore(value);
  if (inverse) {
    if (score >= 75) return RED;
    if (score >= 45) return GOLD;
    return GREEN;
  }
  if (score >= 75) return GREEN;
  if (score >= 45) return GOLD;
  return RED;
}

function statusColor(status: string) {
  if (status === 'complete' || status === 'ready' || status === 'live') return GREEN;
  if (status === 'active') return BLUE;
  if (status === 'review' || status === 'partial' || status === 'stale') return GOLD;
  return '#64748B';
}

function rowLabel(row: PQAuthRow, fallback: string) {
  return String(row.name || row.title || row.assetName || row.asset_name || row.target || row.host || row.location || row.source || fallback);
}

function rowDetail(row: PQAuthRow) {
  return String(row.detail || row.evidence || row.recommendation || row.type || row.category || row.status || 'identity evidence');
}

function iconFor(name: string | undefined, fallback: LucideIcon = Network) {
  return name && ICON_MAP[name] ? ICON_MAP[name] : fallback;
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

function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="grid min-h-[136px] place-items-center rounded-md border border-dashed border-white/10 bg-white/[0.02] px-4 text-center text-xs leading-5 text-white/38">
      {children}
    </div>
  );
}

function StatusPill({ value }: { value: string }) {
  const color = statusColor(value);
  return (
    <span className="inline-flex items-center rounded-md border px-2 py-1 text-[10px] font-black uppercase tracking-[0.06em]" style={{ borderColor: `${color}55`, color, backgroundColor: `${color}12` }}>
      {value.replace(/-/g, ' ')}
    </span>
  );
}

function ScoreRing({ value, label, inverse = false }: { value: number; label: string; inverse?: boolean }) {
  const safe = clampScore(value);
  const color = scoreColor(safe, inverse);
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

function MetricTile({ icon: Icon, label, value, detail, color = BLUE, className, unmeasured, unmeasuredLabel = 'Awaiting telemetry' }: { icon: LucideIcon; label: string; value: string; detail: string; color?: string; className?: string; unmeasured?: boolean; unmeasuredLabel?: string }) {
  return (
    <Panel className={cn('p-4', className)}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-[10px] font-black uppercase tracking-[0.08em] text-white/52">{label}</div>
          {unmeasured ? (
            <div className="mt-3 text-sm font-semibold text-white/45">{unmeasuredLabel}</div>
          ) : (
            <div className="mt-3 text-2xl font-semibold text-white">{value}</div>
          )}
          <div className="mt-1 text-[10px] leading-4 text-white/42">{detail}</div>
        </div>
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-md border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
          <Icon className="h-5 w-5" />
        </span>
      </div>
    </Panel>
  );
}

function WorkflowTabs({ active }: { active: PQAuthMode }) {
  return (
    <nav className="flex gap-2 overflow-x-auto rounded-lg border border-white/8 bg-white/[0.025] p-2" aria-label="PQAuth workflow">
      {WORKFLOW.map(({ mode, href }) => {
        const config = MODE_COPY[mode];
        const isActive = mode === active;
        return (
          <Link
            key={mode}
            to={href}
            className={cn(
              'inline-flex h-9 shrink-0 items-center gap-2 rounded-md border px-3 text-[10px] font-black uppercase tracking-[0.08em] no-underline transition',
              isActive
                ? 'border-gold/55 bg-gold text-black shadow-[0_0_24px_rgba(251,191,36,0.2)]'
                : 'border-white/10 bg-black/20 text-white/55 hover:border-gold/45 hover:text-gold',
            )}
          >
            <config.Icon className="h-3.5 w-3.5" />
            {config.eyebrow}
          </Link>
        );
      })}
    </nav>
  );
}

function Header({ mode, snapshot, loading, connected, refresh }: { mode: PQAuthMode; snapshot: PQAuthSnapshot; loading: boolean; connected: boolean; refresh: () => void }) {
  const config = MODE_COPY[mode];
  const Icon = config.Icon;
  const exportReport = useCallback(() => {
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `pqauth-${mode}-${new Date().toISOString().slice(0, 10)}.json`;
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
              <div className="text-[10px] font-black uppercase tracking-[0.18em] text-cyan-300/70">{config.eyebrow}</div>
              <h1 className="mt-1 font-mono text-2xl font-black uppercase tracking-[0.08em] text-gold drop-shadow-[0_0_16px_rgba(251,191,36,0.35)] md:text-4xl">
                {config.title}
              </h1>
            </div>
          </div>
          <p className="mt-4 max-w-5xl text-sm leading-6 text-gold/72 md:text-base">{config.subtitle}</p>
          <div className="mt-3 flex flex-wrap gap-2 text-[10px] font-bold uppercase tracking-[0.08em] text-white/45">
            <span>Latest: {longDate(snapshot.generatedAt)}</span>
            <span className="text-white/20">/</span>
            <span>{connected ? 'PQAuth SSE active' : loading ? 'Synchronizing backend snapshot' : 'PQAuth backend polling'}</span>
            <span className="text-white/20">/</span>
            <span>Correlation: {snapshot.lineage.correlationId || 'awaiting'}</span>
          </div>
        </div>
        <div className="flex flex-wrap justify-start gap-2 xl:justify-end">
          <button type="button" onClick={() => void refresh()} className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 bg-black/24 px-3 text-xs font-bold text-white/75 transition hover:border-gold/55 hover:bg-gold hover:text-black">
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
            Refresh
          </button>
          <Link to="/dashboard/scanner" className="inline-flex h-9 items-center gap-2 rounded-md border border-blue-500/40 bg-blue-500 px-3 text-xs font-bold text-white no-underline transition hover:border-gold hover:bg-gold hover:text-black">
            <ScanSearch className="h-4 w-4" />
            Discovery
          </Link>
          <Link to="/dashboard/qkms/overview" className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 bg-black/24 px-3 text-xs font-bold text-white/75 no-underline transition hover:border-gold/55 hover:bg-gold hover:text-black">
            <Database className="h-4 w-4" />
            QKMS
          </Link>
          <button type="button" onClick={exportReport} className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 bg-black/24 px-3 text-xs font-bold text-white/75 transition hover:border-gold/55 hover:bg-gold hover:text-black">
            <Download className="h-4 w-4" />
            Export
          </button>
        </div>
      </div>
      <WorkflowTabs active={mode} />
    </header>
  );
}

function MetricStrip({ snapshot }: { snapshot: PQAuthSnapshot }) {
  return (
    <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
      <MetricTile icon={CircleGauge} label="Identity Risk" value={integerFmt(snapshot.metrics.identityRiskScore)} detail={`${integerFmt(snapshot.metrics.criticalFindings)} critical identity finding(s)`} color={scoreColor(snapshot.metrics.identityRiskScore, true)} />
      <MetricTile icon={ShieldCheck} label="PQC Readiness" value={percentFmt(snapshot.metrics.readinessScore)} detail={`${integerFmt(snapshot.metrics.pqcReadyComponents)} ready component(s)`} color={scoreColor(snapshot.metrics.readinessScore)} />
      <MetricTile icon={Fingerprint} label="Identity Providers" value={compactFmt(snapshot.metrics.totalIdentityProviders)} detail={`${compactFmt(snapshot.metrics.authenticationFlows)} auth flow family/families`} color={CYAN} />
      <MetricTile icon={KeyRound} label="Token Records" value={compactFmt(snapshot.metrics.tokenRecords)} detail={`${compactFmt(snapshot.metrics.tokenImpactBlockers)} size-impact blocker(s)`} color={GOLD} />
      <MetricTile icon={Network} label="Trust Dependencies" value={compactFmt(snapshot.metrics.trustDependencies)} detail={`${compactFmt(snapshot.metrics.gatewaySignals)} gateway signal(s)`} color={PURPLE} />
      <MetricTile icon={Radar} label="Runtime Signals" value={compactFmt(snapshot.metrics.runtimeSignals)} detail={`${compactFmt(snapshot.metrics.totalFindings)} evidence finding(s)`} color={GREEN} />
    </section>
  );
}

function TelemetryLineage({ snapshot, connected }: { snapshot: PQAuthSnapshot; connected: boolean }) {
  const freshnessRows = [
    ['Last Telemetry', snapshot.freshness.lastTelemetryReceived],
    ['Last Scan', snapshot.freshness.lastScanTimestamp],
    ['Identity Sync', snapshot.freshness.lastIdentitySync],
    ['OAuth Discovery', snapshot.freshness.lastOAuthDiscovery],
    ['JWT Analysis', snapshot.freshness.lastJwtAnalysis],
    ['Risk Calculation', snapshot.freshness.lastRiskCalculation],
    ['Compliance Eval', snapshot.freshness.lastComplianceEvaluation],
  ] as const;

  return (
    <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
      <Panel className="p-4 xl:col-span-5">
        <SectionTitle>Telemetry Lineage</SectionTitle>
        <div className="grid gap-2 text-xs">
          <div className="flex items-center justify-between gap-3 rounded-md border border-white/8 bg-white/[0.03] px-3 py-2">
            <span className="text-white/45">Origin service</span>
            <span className="truncate font-semibold text-white">{snapshot.lineage.originService || 'PQAuth Identity Migration Engine'}</span>
          </div>
          <div className="flex items-center justify-between gap-3 rounded-md border border-white/8 bg-white/[0.03] px-3 py-2">
            <span className="text-white/45">Stream</span>
            <span className={connected ? 'text-emerald-300' : 'text-gold'}>{connected ? 'live' : 'connecting'}</span>
          </div>
          <div className="flex items-center justify-between gap-3 rounded-md border border-white/8 bg-white/[0.03] px-3 py-2">
            <span className="text-white/45">Normalized records</span>
            <span className="font-mono text-white">{integerFmt(snapshot.integrity.normalizedRecords)}</span>
          </div>
          <div className="flex items-center justify-between gap-3 rounded-md border border-white/8 bg-white/[0.03] px-3 py-2">
            <span className="text-white/45">Duplicate records</span>
            <span className={snapshot.integrity.duplicateRecords ? 'font-mono text-gold' : 'font-mono text-emerald-300'}>{integerFmt(snapshot.integrity.duplicateRecords)}</span>
          </div>
        </div>
      </Panel>
      <Panel className="p-4 xl:col-span-7">
        <SectionTitle>Freshness</SectionTitle>
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-4">
          {freshnessRows.map(([label, value]) => (
            <div key={label} className="rounded-md border border-white/8 bg-white/[0.03] p-3">
              <div className="text-[10px] uppercase tracking-[0.1em] text-white/38">{label}</div>
              <div className="mt-2 text-xs font-semibold text-white">{shortTime(value)}</div>
            </div>
          ))}
        </div>
      </Panel>
    </section>
  );
}

function SourceHealthPanel({ snapshot }: { snapshot: PQAuthSnapshot }) {
  return (
    <Panel className="p-5">
      <SectionTitle>Source Health</SectionTitle>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {snapshot.sourceHealth.slice(0, 12).map((source) => {
          const color = statusColor(source.status);
          return (
            <div key={source.id} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
              <div className="flex items-center justify-between gap-3">
                <span className="truncate text-xs font-semibold text-white">{source.label}</span>
                <StatusPill value={source.status} />
              </div>
              <div className="mt-3 flex items-end justify-between gap-3">
                <span className="font-mono text-lg text-white">{compactFmt(source.count)}</span>
                <span className="text-[10px] uppercase tracking-[0.08em] text-white/38">{shortTime(source.latestAt)}</span>
              </div>
              <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/8">
                <span className="block h-full rounded-full" style={{ width: `${Math.max(4, source.percent)}%`, backgroundColor: color }} />
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

function LifecycleFlow() {
  const steps = [
    ['Discover', ScanSearch, CYAN],
    ['Inventory', Boxes, BLUE],
    ['Assess', ShieldAlert, RED],
    ['Map Trust', Network, PURPLE],
    ['Analyze', LineChart, GOLD],
    ['Simulate', GitBranch, TEAL],
    ['Validate', CheckCircle2, GREEN],
    ['Execute', Workflow, ORANGE],
    ['Monitor', Activity, CYAN],
    ['Govern', Scale, GOLD],
  ] as const;
  return (
    <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-5">
      {steps.map(([label, Icon, color]) => (
        <div key={label} className="flex items-center gap-3 rounded-md border border-white/8 bg-white/[0.03] p-3">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-md border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
            <Icon className="h-4 w-4" />
          </span>
          <span className="text-xs font-black uppercase tracking-[0.08em] text-white/72">{label}</span>
        </div>
      ))}
    </div>
  );
}

function SignalList({ rows, empty }: { rows: PQAuthSnapshot['providers']; empty: string }) {
  if (!rows.length) return <EmptyState>{empty}</EmptyState>;
  return (
    <div className="space-y-3">
      {rows.map((row) => (
        <div key={row.id} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="truncate text-sm font-semibold text-white">{row.label}</div>
              <div className="mt-1 text-[10px] uppercase tracking-[0.08em] text-white/38">{row.category} / {row.sourceTables.join(', ') || 'backend'}</div>
            </div>
            <span className="font-mono text-lg text-white">{integerFmt(row.count)}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function AlgorithmList({ rows }: { rows: PQAuthSnapshot['algorithms'] }) {
  if (!rows.length) return <EmptyState>No RSA, ECC, ECDSA, EdDSA, DH, or ECDH identity exposure detected in the current backend snapshot.</EmptyState>;
  return (
    <div className="space-y-3">
      {rows.map((row) => (
        <div key={row.id} className="rounded-md border border-white/8 bg-white/[0.025] p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-white">{row.label}</div>
              <div className="mt-1 text-[10px] uppercase tracking-[0.08em] text-white/38">{row.family} / {row.sourceTables.join(', ') || 'backend'}</div>
            </div>
            <StatusPill value="review" />
          </div>
          <div className="mt-3 grid gap-3 text-xs text-white/52 md:grid-cols-[110px_1fr]">
            <span className="font-mono text-xl text-white">{integerFmt(row.count)}</span>
            <span>{row.replacement}</span>
          </div>
          <div className="mt-3 text-[10px] uppercase tracking-[0.08em] text-red-300/80">{row.risk}</div>
        </div>
      ))}
    </div>
  );
}

function EvidenceTable({ rows, empty }: { rows: PQAuthRow[]; empty: string }) {
  if (!rows.length) return <EmptyState>{empty}</EmptyState>;
  return (
    <div className="overflow-hidden rounded-md border border-white/8">
      <div className="grid grid-cols-[1.4fr_1fr_1fr_1fr] border-b border-white/8 bg-white/[0.04] px-3 py-2 text-[10px] font-black uppercase tracking-[0.08em] text-white/42">
        <span>Subject</span>
        <span>Type / Source</span>
        <span>Status</span>
        <span>Lineage</span>
      </div>
      <div className="max-h-[360px] overflow-y-auto">
        {rows.slice(0, 14).map((row, index) => (
          <div key={`${String(row.sourceTable || 'row')}-${String(row.id || index)}`} className="grid grid-cols-[1.4fr_1fr_1fr_1fr] gap-3 border-b border-white/6 px-3 py-3 text-xs last:border-b-0">
            <span className="min-w-0 truncate font-semibold text-white">{rowLabel(row, `Identity record ${index + 1}`)}</span>
            <span className="min-w-0 truncate text-white/45">{String(row.type || row.category || row.source || row.algorithm || row.sourceTable || 'identity')}</span>
            <span className="min-w-0 truncate text-white/55">{String(row.status || row.threatLevel || row.severity || row.riskSeverity || 'observed')}</span>
            <span className="min-w-0 truncate text-white/35">{String(row.sourceTable || 'backend')} / {shortTime(row.lastUpdated || row.timestamp || row.created_at)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function OverviewLayout({ snapshot }: { snapshot: PQAuthSnapshot }) {
  return (
    <>
      <MetricStrip snapshot={snapshot} />
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-8">
          <SectionTitle>Post-Quantum Identity Migration Lifecycle</SectionTitle>
          <LifecycleFlow />
        </Panel>
        <Panel className="p-5 xl:col-span-4">
          <SectionTitle>Readiness Command Scores</SectionTitle>
          <div className="grid grid-cols-2 gap-4">
            <ScoreRing value={snapshot.metrics.oauthReadiness} label="OAuth" />
            <ScoreRing value={snapshot.metrics.jwtMigrationScore} label="JWT" />
          </div>
        </Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Discovered Identity Providers</SectionTitle><SignalList rows={snapshot.providers} empty="No named identity provider evidence yet." /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Quantum-Vulnerable Algorithms</SectionTitle><AlgorithmList rows={snapshot.algorithms.slice(0, 4)} /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Migration Phases</SectionTitle><PhaseList rows={snapshot.phases.slice(0, 5)} /></Panel>
      </section>
      <SourceHealthPanel snapshot={snapshot} />
    </>
  );
}

function DiscoveryLayout({ snapshot }: { snapshot: PQAuthSnapshot }) {
  return (
    <>
      <MetricStrip snapshot={snapshot} />
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-4"><SectionTitle>OAuth / OIDC / SAML Providers</SectionTitle><SignalList rows={snapshot.providers} empty="Provider discovery is awaiting matching backend evidence." /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>API Gateways And Proxies</SectionTitle><SignalList rows={snapshot.gateways} empty="Gateway, proxy, WAF, and service-mesh evidence has not been observed yet." /></Panel>
        <Panel className="p-5 xl:col-span-4"><SectionTitle>Authentication Services</SectionTitle><SignalList rows={snapshot.authServices} empty="JWT issuers, validators, authorization servers, and resource servers are awaiting evidence." /></Panel>
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Authentication Flow Inventory</SectionTitle><SignalList rows={snapshot.flows} empty="OAuth, OIDC, SAML, and token-flow evidence has not been captured yet." /></Panel>
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Identity Evidence Ledger</SectionTitle><EvidenceTable rows={snapshot.identityRows} empty="No identity-specific inventory rows are available." /></Panel>
      </section>
    </>
  );
}

function ExposureLayout({ snapshot }: { snapshot: PQAuthSnapshot }) {
  return (
    <>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-3"><SectionTitle>Identity Quantum Risk Score</SectionTitle><ScoreRing value={snapshot.metrics.identityRiskScore} label="Risk" inverse /></Panel>
        <MetricTile className="xl:col-span-3" icon={ShieldAlert} label="Vulnerable Components" value={compactFmt(snapshot.metrics.vulnerableComponents)} detail="classical or weak cryptographic evidence" color={RED} />
        <MetricTile className="xl:col-span-3" icon={AlertTriangle} label="Critical Findings" value={compactFmt(snapshot.metrics.criticalFindings)} detail="urgent identity or crypto findings" color={ORANGE} />
        <MetricTile className="xl:col-span-3" icon={Zap} label="HNDL Exposure" value={compactFmt(snapshot.metrics.classicalExposureSignals)} detail="Shor-vulnerable identity signals" color={GOLD} />
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5"><SectionTitle>Classical Algorithm Exposure</SectionTitle><AlgorithmList rows={snapshot.algorithms} /></Panel>
        <Panel className="p-5 xl:col-span-7"><SectionTitle>Exposure Evidence</SectionTitle><EvidenceTable rows={snapshot.exposureRows} empty="No identity exposure records are available." /></Panel>
      </section>
    </>
  );
}

function TrustGraphLayout({ snapshot }: { snapshot: PQAuthSnapshot }) {
  const nodeMap = new Map(snapshot.trustNodes.map((node) => [node.id, node]));
  if (!snapshot.trustNodes.length) {
    return (
      <>
        <MetricStrip snapshot={snapshot} />
        <Panel className="p-5"><SectionTitle>Authentication Trust Graph</SectionTitle><EmptyState>No validated trust relationships are available in the backend snapshot.</EmptyState></Panel>
      </>
    );
  }
  return (
    <>
      <MetricStrip snapshot={snapshot} />
      <Panel className="p-5">
        <SectionTitle>Authentication Trust Graph</SectionTitle>
        <div className="relative min-h-[520px] overflow-hidden rounded-lg border border-white/8 bg-[#030711]">
          <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
            {snapshot.trustEdges.map((edge) => {
              const from = nodeMap.get(edge.from);
              const to = nodeMap.get(edge.to);
              if (!from || !to) return null;
              return (
                <g key={edge.id}>
                  <line x1={from.x} y1={from.y} x2={to.x} y2={to.y} stroke="rgba(251,191,36,0.35)" strokeWidth="0.4" />
                  <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 1} fill="rgba(255,255,255,0.42)" fontSize="2.4" textAnchor="middle">{edge.label}</text>
                </g>
              );
            })}
          </svg>
          {snapshot.trustNodes.map((node) => {
            const NodeIcon = iconFor(node.icon);
            return (
              <div key={node.id} className="absolute w-44 -translate-x-1/2 -translate-y-1/2 rounded-lg border border-white/10 bg-[#07101D]/94 p-3 shadow-[0_18px_46px_rgba(0,0,0,0.42)]" style={{ left: `${node.x}%`, top: `${node.y}%` }}>
                <div className="flex items-center gap-2">
                  <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md border" style={{ color: node.color, borderColor: `${node.color}55`, backgroundColor: `${node.color}12` }}>
                    <NodeIcon className="h-4 w-4" />
                  </span>
                  <div className="min-w-0">
                    <div className="truncate text-xs font-bold text-white">{node.label}</div>
                    <div className="mt-1 truncate text-[10px] text-white/42">{node.detail}</div>
                    <div className="mt-1 truncate text-[9px] uppercase tracking-[0.08em] text-white/30">{node.sourceTable}</div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </Panel>
    </>
  );
}

function TokenLayout({ snapshot }: { snapshot: PQAuthSnapshot }) {
  return (
    <>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <MetricTile className="xl:col-span-3" icon={KeyRound} label="Token Evidence" value={compactFmt(snapshot.metrics.tokenRecords)} detail="JWT, JWS, JWE, opaque, refresh, access, or ID tokens" color={GOLD} />
        <MetricTile className="xl:col-span-3" icon={AlertTriangle} label="Size Blockers" value={compactFmt(snapshot.metrics.tokenImpactBlockers)} detail="proxy, gateway, cookie, browser, or mobile constraints" color={ORANGE} />
        <MetricTile className="xl:col-span-3" icon={ShieldCheck} label="JWT Migration Score" value={percentFmt(snapshot.metrics.jwtMigrationScore)} detail="token-signing migration readiness" color={scoreColor(snapshot.metrics.jwtMigrationScore)} />
        <MetricTile className="xl:col-span-3" icon={Lock} label="Active JWT Signatures" value={compactFmt(snapshot.metrics.activeJwtSignatures)} detail="runtime or scan-derived signing signals" color={PURPLE} />
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5">
          <SectionTitle>Token Size Impact</SectionTitle>
          {snapshot.tokenImpacts.length ? (
            <div className="space-y-4">
              {snapshot.tokenImpacts.map((row) => (
                <div key={row.id} className="rounded-md border border-white/8 bg-white/[0.025] p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-sm font-semibold text-white">{row.current} to {row.target}</div>
                      <div className="mt-1 text-[10px] uppercase tracking-[0.08em] text-white/38">{row.risk}</div>
                    </div>
                    <span className="font-mono text-lg text-gold">{row.expansion ? `${row.expansion}x` : 'n/a'}</span>
                  </div>
                  <div className="mt-3 grid grid-cols-[1fr_1fr] gap-2 text-xs text-white/52">
                    <span>Current {integerFmt(row.currentSize)} bytes</span>
                    <span>{row.projected ? 'Projected ' : ''}PQC {integerFmt(row.pqcSize)} bytes</span>
                  </div>
                  <div className="mt-2 text-[10px] uppercase tracking-[0.08em] text-white/32">{row.sourceTable} / {shortTime(row.latestAt)}</div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState>No JWT or token size evidence is available from backend telemetry.</EmptyState>
          )}
        </Panel>
        <Panel className="p-5 xl:col-span-7"><SectionTitle>JWT And Token Ledger</SectionTitle><EvidenceTable rows={snapshot.tokenRows} empty="No token-specific rows are available." /></Panel>
      </section>
    </>
  );
}

function CompatibilityLayout({ snapshot }: { snapshot: PQAuthSnapshot }) {
  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Panel className="p-5"><SectionTitle>ML-KEM / FIPS 203</SectionTitle><ScoreRing value={snapshot.metrics.trustReadiness} label="KEX" /></Panel>
        <Panel className="p-5"><SectionTitle>ML-DSA / FIPS 204</SectionTitle><ScoreRing value={snapshot.metrics.jwtMigrationScore} label="Sign" /></Panel>
        <Panel className="p-5"><SectionTitle>SLH-DSA / FIPS 205</SectionTitle><ScoreRing value={snapshot.metrics.slhDsaReadiness} label="Anchor" /></Panel>
        {/* A blocker COUNT, shown as a count. It was previously multiplied by 12
            and drawn as a percentage ring, which invented a risk percentage the
            engine never produced and saturated at nine blockers. */}
        <Panel className="p-5">
          <SectionTitle>Compatibility Blockers</SectionTitle>
          <div className="grid h-40 place-items-center text-center">
            <div>
              <div className="font-mono text-5xl font-semibold" style={{ color: snapshot.metrics.compatibilityBlockers > 0 ? ORANGE : GREEN }}>
                {integerFmt(snapshot.metrics.compatibilityBlockers)}
              </div>
              <div className="mt-2 text-[10px] uppercase tracking-[0.12em] text-white/52">
                {snapshot.metrics.compatibilityBlockers === 1 ? 'Blocker' : 'Blockers'}
              </div>
              <div className="mt-1 text-[10px] leading-4 text-white/38">Quantum-vulnerable algorithms and token size-impact blockers</div>
            </div>
          </div>
        </Panel>
      </section>
      <Panel className="p-5">
        <SectionTitle>Compatibility Surface Assessment</SectionTitle>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {snapshot.compatibilitySurfaces.map((surface) => {
            const SurfaceIcon = iconFor(surface.icon, Boxes);
            const color = surface.assessed ? scoreColor(surface.score) : 'rgba(255,255,255,0.35)';
            return (
              <div key={surface.id} className="rounded-md border border-white/8 bg-white/[0.025] p-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <span className="grid h-9 w-9 shrink-0 place-items-center rounded-md border" style={{ color, borderColor: `${color}55`, backgroundColor: `${color}12` }}>
                      <SurfaceIcon className="h-4 w-4" />
                    </span>
                    <span className="truncate text-sm font-semibold text-white">{surface.label}</span>
                  </div>
                  {surface.assessed ? (
                    <span className="font-mono text-sm text-white">{percentFmt(surface.score)}</span>
                  ) : (
                    <span className="text-[10px] font-bold uppercase tracking-[0.08em] text-white/45">Not Assessed</span>
                  )}
                </div>
                <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/8">
                  {surface.assessed ? (
                    <span className="block h-full rounded-full" style={{ width: `${Math.max(4, surface.score)}%`, backgroundColor: color }} />
                  ) : null}
                </div>
                <div className="mt-2 text-[10px] uppercase tracking-[0.08em] text-white/38">
                  {surface.assessed
                    ? `${integerFmt(surface.count)} matched evidence row(s)`
                    : 'No evidence discovered for this surface'}
                </div>
              </div>
            );
          })}
        </div>
      </Panel>
    </>
  );
}

function DigitalTwinLayout({ snapshot }: { snapshot: PQAuthSnapshot }) {
  return (
    <>
      <MetricStrip snapshot={snapshot} />
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7">
          <SectionTitle>Migration Scenario Twin</SectionTitle>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {snapshot.digitalTwinScenarios.map((scenario) => (
              <div key={scenario.id} className="rounded-md border border-white/8 bg-white/[0.025] p-4">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm font-semibold text-white">{scenario.label}</span>
                  <StatusPill value={scenario.status} />
                </div>
                <div className="mt-3 text-xs leading-5 text-white/48">{scenario.detail}</div>
                <div className="mt-2 text-[10px] uppercase tracking-[0.08em] text-white/32">{integerFmt(scenario.evidence)} evidence signal(s)</div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel className="p-5 xl:col-span-5">
          <SectionTitle>Predicted Failure Classes</SectionTitle>
          <CountBars rows={snapshot.failurePredictions} />
        </Panel>
      </section>
    </>
  );
}

function CountBars({ rows }: { rows: PQAuthSnapshot['failurePredictions'] }) {
  if (!rows.length) return <EmptyState>No backend evidence is available for this panel.</EmptyState>;
  const max = Math.max(1, ...rows.map((row) => Number(row.count) || 0));
  return (
    <div className="space-y-3">
      {rows.map((row) => (
        <div key={row.id}>
          <div className="mb-1 flex items-center justify-between gap-3 text-xs">
            <span className="text-white/72">{row.label}</span>
            <span className="font-mono text-white/60">{integerFmt(Number(row.count))}</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-white/8">
            <span className="block h-full rounded-full bg-gold" style={{ width: `${Math.max(4, Math.min(100, (Number(row.count) / max) * 100))}%` }} />
          </div>
          <div className="mt-1 text-[10px] text-white/34">{row.detail}</div>
        </div>
      ))}
    </div>
  );
}

function PhaseList({ rows }: { rows: PQAuthSnapshot['phases'] }) {
  return (
    <div className="space-y-3">
      {rows.map((phase) => {
        const color = statusColor(phase.status);
        return (
          <div key={phase.id} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-sm font-semibold text-white">{phase.label}</div>
                <div className="mt-1 text-xs leading-5 text-white/42">{phase.objective}</div>
                <div className="mt-1 text-[10px] uppercase tracking-[0.08em] text-white/30">{integerFmt(phase.evidence)} evidence signal(s)</div>
              </div>
              <StatusPill value={phase.status} />
            </div>
            <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/8">
              <span className="block h-full rounded-full" style={{ width: `${Math.max(4, phase.score)}%`, backgroundColor: color }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function MigrationLayout({ snapshot }: { snapshot: PQAuthSnapshot }) {
  return (
    <>
      <MetricStrip snapshot={snapshot} />
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-8"><SectionTitle>Autonomous Migration Phases</SectionTitle><PhaseList rows={snapshot.phases} /></Panel>
        <Panel className="p-5 xl:col-span-4">
          <SectionTitle>Rollback Gates</SectionTitle>
          <div className="space-y-3">
            {snapshot.rollbackGates.map((row) => (
              <div key={row.id} className="flex items-center justify-between gap-3 rounded-md border border-white/8 bg-white/[0.025] p-3">
                <div>
                  <div className="text-sm text-white/72">{row.label}</div>
                  <div className="mt-1 text-[10px] text-white/34">{row.detail}</div>
                </div>
                <span className={cn('font-mono text-sm', row.count ? 'text-gold' : 'text-emerald-300')}>{integerFmt(row.count)}</span>
              </div>
            ))}
          </div>
        </Panel>
      </section>
    </>
  );
}

function RuntimeLayout({ snapshot }: { snapshot: PQAuthSnapshot }) {
  const runtimeIcons: Record<string, LucideIcon> = {
    'runtime-events': Activity,
    'token-validation': KeyRound,
    'certificate-usage': Lock,
    'trust-failures': AlertTriangle,
    'identity-drift': Radar,
  };
  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
        {snapshot.runtimeMetrics.map((metric) => (
          <Fragment key={metric.id}>
            <MetricTile
              icon={runtimeIcons[metric.id] || Activity}
              label={metric.label}
              value={compactFmt(metric.value)}
              detail={metric.detail}
              color={metric.id === 'trust-failures' ? ORANGE : metric.id === 'identity-drift' ? RED : GOLD}
              unmeasured={!metric.measured}
            />
          </Fragment>
        ))}
      </section>
      <Panel className="p-5">
        <SectionTitle>Runtime Identity Telemetry Ledger</SectionTitle>
        {snapshot.runtimeEvents.length ? (
          <div className="space-y-3">
            {snapshot.runtimeEvents.map((row, index) => (
              <div key={`${String(row.sourceTable || 'event')}-${String(row.id || index)}`} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
                <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                  <div>
                    <div className="text-sm font-semibold text-white">{rowLabel(row, `Runtime event ${index + 1}`)}</div>
                    <div className="mt-1 text-xs leading-5 text-white/44">{rowDetail(row)}</div>
                    <div className="mt-1 text-[10px] uppercase tracking-[0.08em] text-white/30">{String(row.sourceTable || 'backend')} / {String(row.correlationId || snapshot.lineage.correlationId || 'correlated')}</div>
                  </div>
                  <span className="shrink-0 text-[10px] font-bold uppercase tracking-[0.08em] text-white/38">{shortTime(row.lastUpdated || row.timestamp || row.created_at || row.startedAt)}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState>No runtime identity telemetry events are available.</EmptyState>
        )}
      </Panel>
    </>
  );
}

function ComplianceLayout({ snapshot }: { snapshot: PQAuthSnapshot }) {
  return (
    <>
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
        <Panel className="p-5"><SectionTitle>Identity PQC Readiness</SectionTitle><ScoreRing value={snapshot.metrics.readinessScore} label="PQC" /></Panel>
        <Panel className="p-5"><SectionTitle>OAuth Readiness</SectionTitle><ScoreRing value={snapshot.metrics.oauthReadiness} label="OAuth" /></Panel>
        <Panel className="p-5"><SectionTitle>OIDC Readiness</SectionTitle><ScoreRing value={snapshot.metrics.oidcReadiness} label="OIDC" /></Panel>
        <Panel className="p-5"><SectionTitle>JWT Migration</SectionTitle><ScoreRing value={snapshot.metrics.jwtMigrationScore} label="JWT" /></Panel>
        <Panel className="p-5"><SectionTitle>Trust Readiness</SectionTitle><ScoreRing value={snapshot.metrics.trustReadiness} label="Trust" /></Panel>
      </section>
      <Panel className="p-5">
        <SectionTitle>Compliance Framework Coverage</SectionTitle>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          {snapshot.complianceRows.map((row) => {
            const color = row.assessed ? scoreColor(row.score) : 'rgba(255,255,255,0.35)';
            return (
              <div key={row.id} className="rounded-md border border-white/8 bg-white/[0.025] p-4">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm font-semibold text-white">{row.label}</span>
                  {row.assessed ? (
                    <span className="font-mono text-sm" style={{ color }}>{percentFmt(row.score)}</span>
                  ) : (
                    <span className="text-[10px] font-bold uppercase tracking-[0.08em] text-white/45">Not Assessed</span>
                  )}
                </div>
                <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/8">
                  {row.assessed ? (
                    <span className="block h-full rounded-full" style={{ width: `${Math.max(4, row.score)}%`, backgroundColor: color }} />
                  ) : null}
                </div>
                <div className="mt-2 text-[10px] uppercase tracking-[0.08em] text-white/38">
                  {row.assessed ? `${row.evidence} / ${row.sourceTables.join(', ')}` : 'Evidence required — no record names this framework'}
                </div>
              </div>
            );
          })}
        </div>
      </Panel>
    </>
  );
}

function QkmsLayout({ snapshot }: { snapshot: PQAuthSnapshot }) {
  return (
    <>
      <MetricStrip snapshot={snapshot} />
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-8">
          <SectionTitle suffix={<Link to="/dashboard/qkms/overview" className="text-xs font-bold text-gold no-underline hover:text-white">Open QKMS</Link>}>QKMS Identity Key Domains</SectionTitle>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {snapshot.qkmsKeyDomains.map((row) => (
              <div key={row.id} className="rounded-md border border-white/8 bg-white/[0.025] p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold text-white">{row.label}</div>
                    <div className="mt-1 text-xs leading-5 text-white/42">{row.detail}</div>
                    <div className="mt-1 text-[10px] uppercase tracking-[0.08em] text-white/30">{row.sourceTables?.join(', ') || 'qkms backend'}</div>
                  </div>
                  <span className="font-mono text-xl text-gold">{integerFmt(row.count)}</span>
                </div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel className="p-5 xl:col-span-4">
          <SectionTitle>Lifecycle Controls</SectionTitle>
          <div className="space-y-3">
            {snapshot.lifecycleControls.map((row) => (
              <div key={row.id} className="flex items-center justify-between gap-3 rounded-md border border-white/8 bg-white/[0.025] p-3">
                <div>
                  <div className="text-sm text-white/72">{row.label}</div>
                  <div className="mt-1 text-[10px] text-white/34">{row.detail}</div>
                </div>
                <StatusPill value={row.status || 'waiting'} />
              </div>
            ))}
          </div>
        </Panel>
      </section>
    </>
  );
}

function renderBody(mode: PQAuthMode, snapshot: PQAuthSnapshot) {
  if (mode === 'discovery') return <DiscoveryLayout snapshot={snapshot} />;
  if (mode === 'trust-graph') return <TrustGraphLayout snapshot={snapshot} />;
  if (mode === 'token-intelligence') return <TokenLayout snapshot={snapshot} />;
  if (mode === 'exposure-analysis') return <ExposureLayout snapshot={snapshot} />;
  if (mode === 'compatibility') return <CompatibilityLayout snapshot={snapshot} />;
  if (mode === 'digital-twin') return <DigitalTwinLayout snapshot={snapshot} />;
  if (mode === 'migration-center') return <MigrationLayout snapshot={snapshot} />;
  if (mode === 'runtime-telemetry') return <RuntimeLayout snapshot={snapshot} />;
  if (mode === 'compliance') return <ComplianceLayout snapshot={snapshot} />;
  if (mode === 'qkms') return <QkmsLayout snapshot={snapshot} />;
  return <OverviewLayout snapshot={snapshot} />;
}

export default function PQAuthDashboard({ mode }: { mode: PQAuthMode }) {
  const { snapshot, state, error, sseConnected, refresh } = usePQAuthDashboard(mode);
  const loading = state === 'loading';

  return (
    <main className="min-h-screen bg-[#030711] px-4 py-5 text-white md:px-6">
      <div className="mx-auto max-w-[1540px] space-y-4">
        <Header mode={mode} snapshot={snapshot} loading={loading} connected={sseConnected} refresh={refresh} />
        {error ? <div className="rounded-md border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-200">{error}</div> : null}
        <TelemetryLineage snapshot={snapshot} connected={sseConnected} />
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
          {renderBody(mode, snapshot)}
        </motion.div>
      </div>
    </main>
  );
}
