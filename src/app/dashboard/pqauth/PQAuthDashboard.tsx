'use client';

import { useCallback } from 'react';
import { NavLink } from 'react-router-dom';
import {
  Activity, CheckCircle2, Database, Download, Fingerprint, GitBranch, KeyRound, Network, Play, RefreshCw, Scale, ScanSearch, ShieldAlert, Workflow,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { downloadJsonFile } from '@/hooks/use-live-resource';
import { usePQAuthDashboard } from '@/hooks/use-pqauth-dashboard';
import type { PQAuthMode, PQAuthSnapshot } from '@/types/pqauth-dashboard';
import {
  ConnectionLostBanner, HardErrorPanel, HeaderButton, IntelHeader, IntelShell, ModuleBrief, SkeletonGrid, SourceHealth, SourceNote,
} from '../_components/intel/kit';
import { PQAuthInk } from './_ui';
import { OverviewView } from './_overview';
import { DiscoveryView } from './_discovery';
import { TrustGraphView } from './_trust-graph';
import { TokensView } from './_tokens';
import { CompatibilityView } from './_compatibility';
import { MigrationView } from './_migration';
import { TwinView } from './_twin';
import { ComplianceView, ExposureView, QkmsView, RuntimeView } from './_estate';

type ModeCopy = {
  title: string;
  accent: string;
  nav: string;
  subtitle: string;
  icon: LucideIcon;
  href: string;
  what: string;
  why: string;
  scope: string;
};

const MODES: Record<PQAuthMode, ModeCopy> = {
  overview: {
    title: 'PQAuth', accent: 'Command Center', nav: 'Command Center', icon: Fingerprint, href: '/dashboard/pqauth',
    subtitle: 'Post-quantum readiness of your authentication layer — identity providers, the keys that sign their tokens, who trusts them, and the migration that makes them quantum-safe.',
    what: 'A summary of the six PQAuth modules. Every card is the same number its own module shows, and opens it.',
    why: 'Identity tokens are signed with RSA, ECDSA or EdDSA. A quantum computer that can forge those signatures can impersonate any user or service that trusts the issuer.',
    scope: 'identity metadata discovered on hosts you own, plus their certificates, migration jobs and runtime telemetry',
  },
  discovery: {
    title: 'Identity', accent: 'Discovery', nav: 'Discovery', icon: ScanSearch, href: '/dashboard/pqauth/discovery',
    subtitle: 'Probes your authorized hosts for OIDC, OAuth 2.0 and SAML metadata at their standard locations, reads the signing keys they publish, and records every probe — including the misses.',
    what: 'The discovery workflow, its scope, every host verdict with the probes behind it, and the identity providers it recorded.',
    why: 'Everything else in PQAuth is built from these records. A miss is recorded too, so "no provider here" is proven rather than assumed.',
    scope: 'public hostnames from your asset inventory',
  },
  'trust-graph': {
    title: 'Identity', accent: 'Trust Graph', nav: 'Trust Graph', icon: Network, href: '/dashboard/pqauth/trust-graph',
    subtitle: 'Who hosts, trusts and signs for whom — drawn only from recorded relationships, each with its evidence and confidence.',
    what: 'Assets, identity providers, their signing keys and certificates, joined only by relationships that were observed, declared or recorded.',
    why: 'The blast radius of a forgeable signing key is every asset that trusts its issuer. You cannot plan a migration without seeing it.',
    scope: 'identity discovery records, certificates and asset relationships',
  },
  'token-intelligence': {
    title: 'JWT & Token', accent: 'Intelligence', nav: 'Token Intelligence', icon: KeyRound, href: '/dashboard/pqauth/token-intelligence',
    subtitle: 'The keys that sign your identity tokens, what the providers advertise, their lifecycle, and the projected size impact of ML-DSA.',
    what: 'Every published JWKS signing key with its algorithm, size, posture and post-quantum target; advertised algorithms; and token size projections.',
    why: 'ML-DSA signatures are 10–50× larger than RSA or ECDSA signatures. Token, header and cookie limits must be checked before the switch.',
    scope: 'public JWKS keys and discovery documents; runtime token operations where agents report them',
  },
  compatibility: {
    title: 'PQC', accent: 'Compatibility', nav: 'Compatibility', icon: CheckCircle2, href: '/dashboard/pqauth/compatibility',
    subtitle: 'Per-provider compatibility across token signing, advertised algorithms, encrypted tokens, endpoint transport and host certificates — concluded from configuration evidence only.',
    what: 'A provider × capability matrix and, for each gap, what is affected, why it matters, what causes it and the supported remediation.',
    why: 'Appearing in an inventory does not make an integration compatible. Only observed configuration can.',
    scope: 'identity providers discovered on your hosts',
  },
  'migration-center': {
    title: 'Identity', accent: 'Migration Center', nav: 'Migration Center', icon: Workflow, href: '/dashboard/pqauth/migration-center',
    subtitle: 'Migration jobs on identity assets, from proposal to validation — where "validated" requires a later discovery to observe the post-quantum keys.',
    what: 'Evidence-gated workflow steps, identity-scoped migration jobs with before/after configuration, validation, role checks and rollback.',
    why: 'A submitted or "completed" job is a claim. Only re-discovery proves the provider now signs with ML-DSA.',
    scope: 'migration jobs on assets that host or trust a discovered identity provider',
  },
  'digital-twin': {
    title: 'Identity', accent: 'Digital Twin', nav: 'Digital Twin', icon: GitBranch, href: '/dashboard/pqauth/digital-twin',
    subtitle: 'A read model of your identity environment rebuilt from discovery records, with clearly-labelled simulations of ML-DSA, hybrid, SLH-DSA and ML-KEM migrations.',
    what: 'The modelled topology and its synchronisation with what discovery last observed, plus a simulation workbench.',
    why: 'Simulating token growth and blast radius first prevents a migration that breaks gateways, cookies or relying parties.',
    scope: 'observed state from discovery; simulations are projections and never applied',
  },
  'exposure-analysis': {
    title: 'Quantum', accent: 'Exposure', nav: 'Exposure', icon: ShieldAlert, href: '/dashboard/pqauth/exposure-analysis',
    subtitle: 'Classical algorithms across your crypto inventory, certificates and findings, alongside the identity signing keys.',
    what: 'Estate-wide classical algorithm signals and the newest exposure evidence.',
    why: 'Identity keys are one part of the estate; the same algorithms elsewhere share the migration path.',
    scope: 'crypto inventory, certificates, keys and findings',
  },
  'runtime-telemetry': {
    title: 'Runtime Identity', accent: 'Telemetry', nav: 'Runtime', icon: Activity, href: '/dashboard/pqauth/runtime-telemetry',
    subtitle: 'What the identity layer actually did at runtime — authentication, token and certificate operations reported by agents.',
    what: 'Runtime identity tiles, each measured from runtime events only, and the newest events.',
    why: 'Discovery shows what can sign; runtime shows what does. Unmeasured tiles say so instead of showing zero.',
    scope: 'runtime crypto events, auth events and sessions',
  },
  compliance: {
    title: 'Identity', accent: 'Governance', nav: 'Governance', icon: Scale, href: '/dashboard/pqauth/compliance',
    subtitle: 'Which frameworks identity evidence exists for, and the measured post-quantum signing coverage.',
    what: 'Framework evidence coverage — a framework with no evidence is Not Assessed.',
    why: 'Governance findings must link back to evidence; borrowed evidence is not evidence.',
    scope: 'compliance evidence records',
  },
  qkms: {
    title: 'QKMS', accent: 'Integration', nav: 'QKMS', icon: Database, href: '/dashboard/pqauth/qkms',
    subtitle: 'Identity-relevant key domains and lifecycle controls from the key tables.',
    what: 'Key domain counts and lifecycle control evidence from QKMS and generated keys.',
    why: 'Identity migration needs owned, rotatable keys; QKMS is the trust anchor.',
    scope: 'QKMS keys, generated keys and certificates',
  },
};

const CORE: PQAuthMode[] = ['overview', 'discovery', 'trust-graph', 'token-intelligence', 'compatibility', 'migration-center', 'digital-twin'];
const MORE: PQAuthMode[] = ['exposure-analysis', 'runtime-telemetry', 'compliance', 'qkms'];

function navBadge(mode: PQAuthMode, snapshot: PQAuthSnapshot | null): { value: number; tone: 'alert' | 'info' } | null {
  if (!snapshot) return null;
  const id = snapshot.identity;
  switch (mode) {
    case 'discovery': return id.discovery.activeRun?.status === 'running' ? { value: id.discovery.activeRun.hostsTotal - id.discovery.activeRun.hostsDone, tone: 'info' } : null;
    case 'token-intelligence': {
      const n = id.readiness.vulnerableKeys;
      return n ? { value: n, tone: 'alert' } : null;
    }
    case 'compatibility': {
      const n = id.compatibility.issues.filter((i) => i.severity === 'critical' || i.severity === 'high').length;
      return n ? { value: n, tone: 'alert' } : null;
    }
    case 'migration-center': {
      const n = id.migration.jobs.filter((j) => j.roleCheck.ok === false || j.validation.status === 'regressed' || j.state === 'failed').length;
      return n ? { value: n, tone: 'alert' } : null;
    }
    case 'digital-twin': return id.twin.conflicts.length ? { value: id.twin.conflicts.length, tone: 'alert' } : null;
    default: return null;
  }
}

function ModuleNav({ snapshot }: { snapshot: PQAuthSnapshot | null }) {
  const item = (mode: PQAuthMode) => {
    const copy = MODES[mode];
    const badge = navBadge(mode, snapshot);
    return (
      <NavLink
        key={mode}
        to={copy.href}
        end
        className={({ isActive }) => cn(
          'inline-flex shrink-0 items-center gap-1.5 rounded-lg border px-3 py-2 text-[9.5px] font-black uppercase tracking-wider no-underline transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
          isActive ? 'border-cyan-400/55 bg-gradient-to-r from-cyan-500/20 to-violet-500/15 text-cyan-200' : 'border-white/10 bg-white/[0.03] text-white/55 hover:border-white/20 hover:text-white/85',
        )}
      >
        <copy.icon className="h-3.5 w-3.5" aria-hidden="true" />
        {copy.nav}
        {badge ? (
          <span className={cn('rounded-full px-1.5 py-0.5 font-mono text-[9px]', badge.tone === 'alert' ? 'bg-red-500/20 text-red-300' : 'bg-cyan-500/20 text-cyan-200')} aria-label={`${badge.value} items need attention`}>
            {badge.value}
          </span>
        ) : null}
      </NavLink>
    );
  };
  return (
    <nav aria-label="PQAuth modules" className="flex flex-wrap items-center gap-1.5">
      {CORE.map(item)}
      <span className="mx-1 hidden h-5 w-px bg-white/10 md:inline-block" aria-hidden="true" />
      {MORE.map(item)}
    </nav>
  );
}

export default function PQAuthDashboard({ mode }: { mode: PQAuthMode }) {
  const live = usePQAuthDashboard();
  const { data: snapshot, state, error, transport, lastVerifiedAt, lastGoodAt, refreshing, refresh, reconnect, startDiscovery, discoveryStarting, discoveryError } = live;
  const copy = MODES[mode];

  const exportEvidence = useCallback(() => {
    // The snapshot is already an allow-listed projection: no token hashes, IPs or raw rows.
    if (snapshot) downloadJsonFile(`pqauth-${mode}`, { mode, exportedAt: new Date().toISOString(), ...snapshot });
  }, [mode, snapshot]);

  const running = snapshot?.identity.discovery.activeRun?.status === 'running';
  const showRun = mode === 'overview' || mode === 'discovery';
  const eligible = snapshot?.identity.discovery.scope.filter((s) => s.eligible).length ?? 0;
  const next = snapshot
    ? snapshot.identity.nextActions.find((a) => a.href === copy.href) ?? snapshot.identity.nextActions[0]
    : null;

  return (
    <IntelShell name="pqauth">
      <PQAuthInk />
      <style>{`
        .qg-theme-light .pqauth [class*="bg-[#0b1424]"] { background-color: rgba(255,255,255,0.97) !important; }
      `}</style>
      <IntelHeader
        title={copy.title}
        accent={copy.accent}
        subtitle={copy.subtitle}
        icon={copy.icon}
        lastUpdated={snapshot?.generatedAt ?? null}
        transport={transport}
        lastVerifiedAt={lastVerifiedAt}
      >
        <HeaderButton onClick={() => void refresh(true)} icon={RefreshCw} spin={refreshing} disabled={refreshing}>Refresh</HeaderButton>
        <HeaderButton onClick={exportEvidence} icon={Download} disabled={!snapshot}>Export evidence</HeaderButton>
        {showRun ? (
          <HeaderButton onClick={() => void startDiscovery()} icon={Play} active disabled={!snapshot || running || discoveryStarting || !eligible} spin={false}>
            {running ? 'Discovery running' : discoveryStarting ? 'Starting…' : 'Run discovery'}
          </HeaderButton>
        ) : null}
      </IntelHeader>

      <ModuleNav snapshot={snapshot} />

      {state === 'loading' && !snapshot ? <SkeletonGrid cards={6} panels={2} /> : null}

      {state === 'error' && !snapshot ? (
        <HardErrorPanel
          title="PQAuth could not load"
          message={/pro plan/i.test(error ?? '') ? 'PQAuth is part of the Pro plan. Your current plan does not include it.' : 'The identity snapshot could not be built. No figures are shown rather than showing zeros.'}
          error={error}
          onRetry={() => void refresh(true)}
        />
      ) : null}

      {snapshot ? (
        <>
          {(transport === 'polling' || transport === 'offline') ? (
            <ConnectionLostBanner lastGoodAt={lastGoodAt} error={error} onReconnect={reconnect} transport={transport} lastVerifiedAt={lastVerifiedAt} />
          ) : null}

          <ModuleBrief
            what={copy.what}
            why={copy.why}
            scope={copy.scope}
            next={next
              ? { label: next.title, detail: next.detail || undefined, href: next.href, tone: next.priority === 'critical' || next.priority === 'high' ? 'warning' : next.priority === 'low' ? 'calm' : 'action' }
              : { label: 'Loading recommendations', tone: 'calm' }}
          />

          {discoveryError && mode !== 'discovery' ? (
            <div role="alert" className="rounded-xl border border-red-400/30 bg-red-500/[0.06] px-4 py-3 text-[11.5px] text-red-200">Identity discovery could not start: {discoveryError}</div>
          ) : null}

          {mode === 'overview' ? <OverviewView snapshot={snapshot} /> : null}
          {mode === 'discovery' ? <DiscoveryView snapshot={snapshot} startDiscovery={startDiscovery} starting={discoveryStarting} startError={discoveryError} /> : null}
          {mode === 'trust-graph' ? <TrustGraphView snapshot={snapshot} /> : null}
          {mode === 'token-intelligence' ? <TokensView snapshot={snapshot} /> : null}
          {mode === 'compatibility' ? <CompatibilityView snapshot={snapshot} /> : null}
          {mode === 'migration-center' ? <MigrationView snapshot={snapshot} /> : null}
          {mode === 'digital-twin' ? <TwinView snapshot={snapshot} /> : null}
          {mode === 'exposure-analysis' ? <ExposureView snapshot={snapshot} /> : null}
          {mode === 'runtime-telemetry' ? <RuntimeView snapshot={snapshot} /> : null}
          {mode === 'compliance' ? <ComplianceView snapshot={snapshot} /> : null}
          {mode === 'qkms' ? <QkmsView snapshot={snapshot} /> : null}

          <SourceHealth
            sources={snapshot.sourceHealth.map((s) => ({ label: s.label, state: s.state, detail: `${s.table}: ${s.count.toLocaleString('en-US')} row(s)${s.latestAt ? `, newest ${new Date(s.latestAt).toLocaleString()}` : ''}` }))}
            note="Capped sources are read newest-first up to their limit."
          />
          <SourceNote>
            Source: /api/v1/dashboard/pqauth · tenant-scoped (RLS + user filter) · one snapshot shared by all PQAuth modules · computed {snapshot.generatedAt ? new Date(snapshot.generatedAt).toLocaleString() : '—'}.
          </SourceNote>
        </>
      ) : null}
    </IntelShell>
  );
}
