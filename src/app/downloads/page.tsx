import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, Navigate, useLocation, useSearchParams } from 'react-router-dom';
import {
  ArrowLeft,
  Check,
  CircleAlert,
  Download,
  Loader2,
  Lock,
  Plus,
  RadioTower,
  RefreshCw,
  ScanLine,
  ShieldCheck,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { useAuth } from '@/contexts/auth-context';
import { useSubscription } from '@/hooks/use-subscription';
import { isOwnerEmail } from '@/lib/admin-access';
import { tierMeets } from '@/lib/subscription-access';
import { useAgentInstaller, type DeployedAgent } from '@/hooks/use-agent-installer';
import { DeployWizard } from '@/components/agent-installer/DeployWizard';
import { AGENT_ROLES, type AgentRole } from '@/lib/agent-installer/agent-release';
import { agentRolePlanCopy, useAgentEntitlement } from '@/hooks/use-agent-entitlement';
import { AgentDetailDrawer } from '@/components/agent-installer/AgentDetailDrawer';
import ThemeToggle from '@/components/theme/ThemeToggle';
import {
  Card,
  EmptyState,
  ErrorState,
  Panel,
  Skeleton,
  StatusChip,
  fmtBytes,
  fmtDate,
  relTime,
} from '@/components/agent-installer/primitives';

/**
 * Qguard Helix Agent Center — /downloads
 *
 * The deployment control plane for lightweight collectors, scanners, patchers
 * and migration operators (spec §5, §31). Everything on this page is derived
 * from backend state: agent rows, heartbeat recency, the published release
 * manifest and the live `agent.*` event stream. There is no client-side
 * simulation of connection, scan or install progress anywhere in this file.
 */

const STREAM_LABEL: Record<string, { label: string; className: string; icon: typeof Wifi }> = {
  connected: { label: 'Live', className: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-200', icon: Wifi },
  connecting: { label: 'Connecting', className: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-200', icon: RadioTower },
  reconnecting: { label: 'Reconnecting', className: 'border-amber-400/30 bg-amber-400/10 text-amber-200', icon: RadioTower },
  offline: { label: 'Stream offline', className: 'border-white/15 bg-white/[0.04] text-white/50', icon: WifiOff },
};

export default function DownloadsPage() {
  const { user, loading: authLoading } = useAuth();
  const subscription = useSubscription();

  const owner = isOwnerEmail(user?.email);
  /* The Agent Center is BASIC, not Pro. A Basic tenant deploys the two
     read-only roles (Collector, Scanner) that feed the Quantum Readiness engine
     they already pay for; the two host-modifying roles stay Pro and are gated
     per role inside the wizard and again server-side. */
  const entitled = owner || (subscription.isActive && tierMeets(subscription.tier, 'basic'));
  const gateReady = !authLoading && !subscription.loading;

  const installer = useAgentInstaller(Boolean(user) && entitled);
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();

  /* Deep link from elsewhere in the platform — the Local Assessment "Local
     Agent" option sends ?deploy=1&source=local-assessment&profile=<id>[&role=<id>].
     Read once into state: the wizard owns the choice from then on, and the
     `deploy` flag is dropped from the URL so a refresh does not reopen it. */
  const [deployIntent] = useState(() => {
    const requestedRole = searchParams.get('role');
    return {
      open: searchParams.get('deploy') === '1',
      role: AGENT_ROLES.some((item) => item.id === requestedRole) ? (requestedRole as AgentRole) : null,
      source: searchParams.get('source'),
      profile: searchParams.get('profile'),
    };
  });

  const [wizardOpen, setWizardOpen] = useState(deployIntent.open);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const wizardRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!deployIntent.open || !entitled || !gateReady) return;
    wizardRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (searchParams.has('deploy')) {
      const next = new URLSearchParams(searchParams);
      next.delete('deploy');
      setSearchParams(next, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deployIntent.open, entitled, gateReady]);
  const [filter, setFilter] = useState<'all' | 'connected' | 'offline' | 'waiting' | 'updates'>('all');

  const selected = useMemo(
    () => installer.agents.find((agent) => agent.id === selectedId) || null,
    [installer.agents, selectedId],
  );

  const visible = useMemo(() => {
    switch (filter) {
      case 'connected':
        return installer.agents.filter((agent) => agent.connectionState === 'Connected');
      case 'offline':
        return installer.agents.filter((agent) => agent.connectionState === 'Offline' || agent.connectionState === 'Error');
      case 'waiting':
        return installer.agents.filter((agent) => agent.connectionState === 'Waiting' || agent.connectionState === 'Connecting');
      case 'updates':
        return installer.agents.filter((agent) => agent.upgradeAvailable);
      default:
        return installer.agents;
    }
  }, [installer.agents, filter]);

  if (!gateReady) {
    return (
      <Shell>
        <div className="flex items-center gap-3 text-sm text-white/50">
          <Loader2 className="h-4 w-4 animate-spin" /> Checking your access…
        </div>
      </Shell>
    );
  }

  /* The login page reads `next` (not `redirect`, which it ignored — signed-out
     visitors landed on /dashboard). The query string is kept so a deep link
     into the deployment wizard survives the sign-in. */
  if (!user) return <Navigate to={`/login?next=${encodeURIComponent(`/downloads${location.search}`)}`} replace />;

  if (!entitled) {
    return (
      <Shell>
        <div className="ac-surface mx-auto max-w-xl rounded-2xl border border-white/10 bg-white/[0.02] p-8 text-center">
          <ShieldCheck className="mx-auto h-7 w-7 text-cyan-300" />
          <h1 className="mt-4 text-lg font-black text-white">Agent Center requires a plan</h1>
          <p className="mx-auto mt-2 max-w-md text-sm leading-relaxed text-white/50">
            Deploying read-only Collector and Scanner agents to your own infrastructure is included from the{' '}
            <span className="font-bold text-white/70">Basic</span> plan. Patcher and Migration Operator — the roles that
            change host configuration — require <span className="font-bold text-white/70">Pro</span>. Your current plan is{' '}
            <span className="font-bold text-white/70">{subscription.tier}</span>.
          </p>
          <Link
            to="/dashboard/settings"
            className="mt-5 inline-flex items-center gap-2 rounded-xl border border-cyan-400/40 bg-cyan-400/10 px-4 py-2.5 text-sm font-bold text-cyan-100 no-underline transition hover:bg-cyan-400/20"
          >
            View plans
          </Link>
        </div>
      </Shell>
    );
  }

  const stream = STREAM_LABEL[installer.streamState] || STREAM_LABEL.offline;
  const StreamIcon = stream.icon;
  const summary = installer.summary;
  const release = installer.release;

  return (
    <Shell
      leading={
        <Link
          to="/dashboard/agents"
          className="inline-flex items-center gap-1.5 text-[11px] font-bold text-white/40 no-underline transition hover:text-cyan-200"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Agents Collector
        </Link>
      }
    >
      <header className="mb-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-black tracking-tight text-white sm:text-3xl">Qguard Helix Agent Center</h1>
            <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-white/50">
              Deploy lightweight collectors and operators to discover, validate, and protect your cryptographic environment.
            </p>
            <AgentRoleEntitlementRibbon />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span
              title={
                installer.streamState === 'connected'
                  ? `Live event stream open. Last event ${relTime(installer.lastEventAt)}.`
                  : 'The realtime stream is not currently delivering events.'
              }
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-bold ${stream.className}`}
            >
              <StreamIcon className="h-3.5 w-3.5" /> {stream.label}
            </span>
            <button
              type="button"
              onClick={() => void installer.refresh()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-1.5 text-[11px] font-bold text-white/65 transition hover:text-white"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Refresh
            </button>
            <button
              type="button"
              onClick={() => setWizardOpen(true)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/40 bg-cyan-400/10 px-3.5 py-1.5 text-[11px] font-black text-cyan-100 transition hover:bg-cyan-400/20"
            >
              <Plus className="h-3.5 w-3.5" /> Create agent
            </button>
          </div>
        </div>
      </header>

      {/*
        A failed load is only a page failure when the page has nothing to show.
        One slow call on a cold start used to paint "Agent Center could not
        load" across a console that had in fact rendered the runtime, the
        platforms and every enrolled agent — an error louder than the truth.
        With data present the failure is reported as what it is: this view is
        showing the last good data and one refresh did not complete.
      */}
      {installer.error ? (
        <div className="mb-5">
          {installer.agents.length === 0 && !release ? (
            <ErrorState title="Agent Center could not load" message={installer.error} onRetry={() => void installer.refresh()} />
          ) : (
            <div className="rounded-xl border border-amber-400/25 bg-amber-400/[0.06] px-4 py-3">
              <div className="flex items-start gap-2.5">
                <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
                <div className="flex-1">
                  <div className="text-sm font-bold text-amber-100">Showing the last successful load</div>
                  <p className="mt-1 text-[11px] leading-relaxed text-amber-100/70">
                    A refresh did not complete ({installer.error}), so the figures below may be out of date.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => void installer.refresh()}
                  className="shrink-0 rounded-lg border border-amber-400/40 bg-amber-400/10 px-3 py-1.5 text-[11px] font-black text-amber-100 transition hover:bg-amber-400/20"
                >
                  Retry
                </button>
              </div>
            </div>
          )}
        </div>
      ) : null}

      {release && !release.available ? (
        <div className="mb-5 rounded-xl border border-amber-400/25 bg-amber-400/[0.06] px-4 py-3">
          <div className="flex items-start gap-2.5">
            <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
            <div>
              <div className="text-sm font-bold text-amber-100">No agent runtime is published</div>
              <p className="mt-1 text-[11px] leading-relaxed text-amber-100/70">
                {release.reason} Installers cannot be generated until a verified runtime exists, because every installer must
                embed a checksum the platform can prove.
              </p>
            </div>
          </div>
        </div>
      ) : null}

      {/* ---------------- Deployment summary ---------------- */}
      <div className="mb-6 grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Card label="Agents" value={summary?.total ?? '—'} hint="Enrolled for this tenant" />
        <Card label="Connected" value={summary?.connected ?? '—'} tone="good" hint="Heartbeat within 10 min" />
        <Card
          label="Awaiting install"
          value={summary?.waiting ?? '—'}
          hint="Created, never checked in"
        />
        <Card label="Offline" value={summary?.offline ?? '—'} tone={summary && summary.offline > 0 ? 'warn' : 'default'} hint="Heartbeat stopped" />
        <Card label="Updates available" value={summary?.updatesAvailable ?? '—'} tone="accent" hint="Older than published build" />
        <Card label="Active jobs" value={summary?.activeJobs ?? '—'} hint="Queued commands awaiting pickup" />
      </div>

      {wizardOpen ? (
        <div ref={wizardRef} className="mb-6 scroll-mt-6">
          <DeployWizard
            installer={installer}
            initial={{ role: deployIntent.role, source: deployIntent.source, localProfile: deployIntent.profile }}
            onClose={() => setWizardOpen(false)}
            onOpenAgent={(agentId) => {
              setSelectedId(agentId);
              setWizardOpen(false);
            }}
          />
        </div>
      ) : null}

      {/* ---------------- Published release ---------------- */}
      <div className="mb-6">
        <Panel
          title="Published runtime"
          subtitle="The single-file agent every installer downloads and verifies before it runs."
        >
          {!release ? (
            <Skeleton rows={2} />
          ) : (
            <div className="grid gap-3 lg:grid-cols-3">
              <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
                <div className="text-[11px] font-bold uppercase tracking-wide text-white/45">Build</div>
                <dl className="mt-2 space-y-1.5 text-[11px]">
                  <Row label="Version" value={release.version} />
                  <Row label="Channel" value={release.channel} />
                  <Row label="Size" value={fmtBytes(release.bytes)} />
                  <Row label="Requires" value={`Node ${release.requiresNode}`} />
                  <Row label="Built" value={release.builtAt ? fmtDate(release.builtAt) : '—'} />
                  <Row label="Dependencies" value="None (Node core only)" />
                </dl>
              </div>
              <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4 lg:col-span-2">
                <div className="text-[11px] font-bold uppercase tracking-wide text-white/45">Integrity anchors</div>
                <dl className="mt-2 space-y-2 text-[11px]">
                  <div>
                    <dt className="text-white/40">SHA-256</dt>
                    <dd className="break-all font-mono text-white/70">{release.sha256 || '—'}</dd>
                  </div>
                  <div>
                    <dt className="text-white/40">SHA3-256</dt>
                    <dd className="break-all font-mono text-white/70">{release.sha3_256 || '—'}</dd>
                  </div>
                </dl>
                <p className="mt-3 text-[11px] leading-relaxed text-white/40">
                  The runtime is served only to an enrolled agent presenting its own credential, and every generated installer
                  refuses to execute a download whose digest does not match the value above.
                </p>
              </div>
            </div>
          )}
        </Panel>
      </div>

      {/* ---------------- Platform matrix ---------------- */}
      <div className="mb-6">
        <Panel title="Supported platforms" subtitle="Each option produces a real, runnable artifact bound to the agent you select.">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {installer.platforms.map((platform) => (
              <div key={platform.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
                <div className="text-sm font-black text-white">{platform.label}</div>
                <div className="mt-1 text-[11px] leading-relaxed text-white/45">{platform.service}</div>
                <div className="mt-2.5 flex flex-wrap gap-1">
                  {platform.architectures.map((arch) => (
                    <span key={arch} className="rounded border border-white/10 bg-white/[0.03] px-1.5 py-0.5 text-[10px] text-white/45">
                      {arch}
                    </span>
                  ))}
                </div>
                <code className="qg-force-dark mt-3 block break-all rounded-lg border border-white/8 bg-black/40 px-2.5 py-1.5 font-mono text-[10.5px] text-cyan-200/80">
                  {platform.quickCommand}
                </code>
              </div>
            ))}
            {installer.platforms.length === 0 && installer.loading ? <Skeleton rows={3} /> : null}
          </div>
        </Panel>
      </div>

      {/* ---------------- Asset coverage ---------------- */}
      <div className="mb-6">
        <Panel
          title="Your asset coverage"
          subtitle="Which of your own assets have an agent reporting on them. Agents can only ever be bound to assets in your tenant."
          actions={
            <span className="rounded-lg border border-white/10 bg-white/[0.02] px-2.5 py-1 text-[11px] font-bold text-white/45">
              Tenant {installer.tenantId.slice(0, 8)}…
            </span>
          }
        >
          {installer.loading ? (
            <Skeleton rows={2} />
          ) : installer.assets.length === 0 ? (
            <EmptyState
              title="No assets in your inventory yet"
              body="Agents you deploy will create assets as they discover them, and this panel will show which of your assets are covered. You can also run a scan from the Scanner to seed the inventory first."
            />
          ) : (
            <>
              <div className="mb-4 grid gap-3 sm:grid-cols-3">
                <Card label="Your assets" value={installer.assets.length} hint="In your tenant inventory" />
                <Card
                  label="Covered by an agent"
                  value={installer.assets.filter((asset) => asset.agents.length > 0).length}
                  tone="good"
                  hint="At least one agent bound"
                />
                <Card
                  label="Agents not bound to an asset"
                  value={installer.unassignedAgents.length}
                  tone={installer.unassignedAgents.length > 0 ? 'warn' : 'default'}
                  hint="Findings will attribute by discovered name"
                />
              </div>
              <div className="max-h-72 overflow-auto rounded-xl border border-white/8">
                <table className="w-full min-w-[520px] text-left text-xs">
                  <thead className="sticky top-0 bg-[#0a1020]">
                    <tr className="text-[11px] text-white/35">
                      <th className="px-3 py-2 font-bold">Asset</th>
                      <th className="px-3 py-2 font-bold">Type</th>
                      <th className="px-3 py-2 font-bold">Environment</th>
                      <th className="px-3 py-2 font-bold">Criticality</th>
                      <th className="px-3 py-2 font-bold">Agent coverage</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {installer.assets.map((asset) => (
                      <tr key={asset.id} className="text-white/65">
                        <td className="px-3 py-2 font-bold text-white/85">{asset.name}</td>
                        <td className="px-3 py-2 text-white/50">{asset.type || '—'}</td>
                        <td className="px-3 py-2 text-white/50">{asset.environment || '—'}</td>
                        <td className="px-3 py-2 text-white/50">{asset.criticality || '—'}</td>
                        <td className="px-3 py-2">
                          {asset.agents.length === 0 ? (
                            <span className="text-white/30">No agent</span>
                          ) : (
                            <span className="inline-flex flex-wrap gap-1">
                              {asset.agents.map((agent) => (
                                <button
                                  key={agent.id}
                                  type="button"
                                  onClick={() => setSelectedId(agent.id)}
                                  className="rounded border border-white/12 bg-white/[0.03] px-1.5 py-0.5 text-[10px] font-bold text-white/70 transition hover:border-cyan-400/40 hover:text-cyan-200"
                                >
                                  {agent.name}
                                </button>
                              ))}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </Panel>
      </div>

      {/* ---------------- Agents table ---------------- */}
      <Panel
        title="Deployed agents"
        subtitle="Status is derived from real heartbeats. An agent that has never checked in reads as awaiting install — never as healthy."
        actions={
          <div className="flex flex-wrap gap-1">
            {([
              ['all', `All ${installer.agents.length}`],
              ['connected', 'Connected'],
              ['waiting', 'Awaiting install'],
              ['offline', 'Offline'],
              ['updates', 'Updates'],
            ] as const).map(([id, label]) => (
              <button
                key={id}
                type="button"
                onClick={() => setFilter(id)}
                className={`rounded-lg border px-2.5 py-1 text-[11px] font-bold transition ${
                  filter === id
                    ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200'
                    : 'border-white/8 bg-white/[0.02] text-white/45 hover:text-white/75'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        }
      >
        {installer.loading ? (
          <Skeleton rows={4} />
        ) : installer.agents.length === 0 ? (
          <EmptyState
            title="No agents deployed yet"
            body="Create an agent to generate a signed installer for your host, container or cluster. It enrolls automatically, verifies its own runtime and begins streaming cryptographic evidence into your dashboards."
            action={
              <button
                type="button"
                onClick={() => setWizardOpen(true)}
                className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/40 bg-cyan-400/10 px-3.5 py-2 text-xs font-black text-cyan-100 transition hover:bg-cyan-400/20"
              >
                <Plus className="h-3.5 w-3.5" /> Create your first agent
              </button>
            }
          />
        ) : visible.length === 0 ? (
          <EmptyState title="No agents match this filter" body="Switch to “All” to see every agent enrolled for this tenant." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[880px] text-left text-xs">
              <thead>
                <tr className="text-[11px] text-white/35">
                  <th className="pb-2.5 font-bold">Agent</th>
                  <th className="pb-2.5 font-bold">Type</th>
                  <th className="pb-2.5 font-bold">Host</th>
                  <th className="pb-2.5 font-bold">Platform</th>
                  <th className="pb-2.5 font-bold">Version</th>
                  <th className="pb-2.5 font-bold">Status</th>
                  <th className="pb-2.5 font-bold">Last seen</th>
                  <th className="pb-2.5 font-bold">Task</th>
                  <th className="pb-2.5 text-right font-bold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {visible.map((agent) => (
                  <AgentRow
                    key={agent.id}
                    agent={agent}
                    progress={installer.scanProgress[agent.id]?.progress}
                    busy={installer.busy || installer.scanning}
                    onOpen={() => setSelectedId(agent.id)}
                    onScan={() => void installer.requestScan(agent.id)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {selected ? (
        <AgentDetailDrawer agent={selected} installer={installer} onClose={() => setSelectedId(null)} />
      ) : null}
    </Shell>
  );
}

/**
 * Which agent roles this plan includes, stated on the page rather than
 * discovered when the wizard refuses one.
 *
 * Shows all four with the unentitled ones marked, for the same reason the
 * wizard does: a Basic tenant should leave knowing that Patcher and Migration
 * Operator exist and what they would do, because that is the argument for Pro.
 */
function AgentRoleEntitlementRibbon() {
  const entitlement = useAgentEntitlement();
  if (entitlement.loading) return null;

  return (
    <div className="mt-3 flex flex-wrap items-center gap-1.5">
      {AGENT_ROLES.map((role) => {
        const access = entitlement.byRole[role.id];
        const allowed = access?.allowed ?? false;
        return (
          <span
            key={role.id}
            title={allowed ? role.tagline : `${access?.message ?? ''} ${agentRolePlanCopy(role.id)}.`}
            className={
              allowed
                ? 'inline-flex items-center gap-1 rounded-md border border-emerald-400/25 bg-emerald-400/[0.07] px-2 py-0.5 text-[10px] font-black uppercase tracking-[0.12em] text-emerald-200'
                : 'inline-flex items-center gap-1 rounded-md border border-white/10 bg-white/[0.02] px-2 py-0.5 text-[10px] font-black uppercase tracking-[0.12em] text-white/35'
            }
          >
            {allowed ? <Check aria-hidden className="h-2.5 w-2.5" /> : <Lock aria-hidden className="h-2.5 w-2.5" />}
            {role.label}
          </span>
        );
      })}
      <span className="ml-1 text-[10.5px] text-white/35">
        {entitlement.canWrite
          ? 'Your plan includes the host-modifying roles.'
          : 'Patcher and Migration Operator require Pro.'}
      </span>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-white/40">{label}</dt>
      <dd className="truncate text-right font-mono text-white/70">{value}</dd>
    </div>
  );
}

function AgentRow({
  agent,
  progress,
  busy,
  onOpen,
  onScan,
}: {
  agent: DeployedAgent;
  progress?: number;
  busy: boolean;
  onOpen: () => void;
  onScan: () => void;
}) {
  const revoked = Boolean(agent.revoked_at || agent.status === 'revoked');
  return (
    <tr className="text-white/70 transition hover:bg-white/[0.02]">
      <td className="py-2.5 pr-3">
        <button type="button" onClick={onOpen} className="text-left">
          <span className="block font-bold text-white hover:text-cyan-200">{agent.name}</span>
          <span className="block font-mono text-[10px] text-white/30">{agent.id.slice(0, 8)}…</span>
        </button>
      </td>
      <td className="py-2.5 pr-3 capitalize text-white/55">{agent.role}</td>
      <td className="py-2.5 pr-3 text-white/55">{agent.hostname || <span className="text-white/25">Pending</span>}</td>
      <td className="py-2.5 pr-3 text-white/55">{agent.platform || '—'}</td>
      <td className="py-2.5 pr-3 font-mono text-white/55">
        {agent.version || '—'}
        {agent.upgradeAvailable ? <span className="ml-1.5 text-[10px] text-cyan-300">update</span> : null}
      </td>
      <td className="py-2.5 pr-3">
        {revoked ? (
          <span className="rounded-full border border-rose-400/30 bg-rose-400/10 px-2 py-0.5 text-[10px] font-black uppercase text-rose-200">
            Revoked
          </span>
        ) : (
          <StatusChip state={agent.connectionState} />
        )}
      </td>
      <td className="py-2.5 pr-3 text-white/45">{relTime(agent.last_seen_at)}</td>
      <td className="py-2.5 pr-3">
        {progress != null && progress < 100 ? (
          <span className="inline-flex items-center gap-1.5 text-[11px] text-cyan-300">
            <Loader2 className="h-3 w-3 animate-spin" /> {progress}%
          </span>
        ) : agent.currentTask ? (
          <span className="text-[11px] capitalize text-cyan-300">{agent.currentTask}</span>
        ) : agent.pendingCommands > 0 ? (
          <span className="text-[11px] text-white/45">{agent.pendingCommands} queued</span>
        ) : (
          <span className="text-[11px] text-white/25">Idle</span>
        )}
      </td>
      <td className="py-2.5 text-right">
        <div className="inline-flex items-center gap-1.5">
          <button
            type="button"
            disabled={busy || revoked}
            onClick={onScan}
            title="Queue a scan for this agent"
            aria-label={`Scan ${agent.name}`}
            className="rounded-lg border border-white/12 bg-white/[0.04] p-1.5 text-white/55 transition hover:border-cyan-400/40 hover:text-cyan-200 disabled:opacity-30"
          >
            <ScanLine className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={onOpen}
            title="Open agent, generate installer"
            className="rounded-lg border border-white/12 bg-white/[0.04] p-1.5 text-white/55 transition hover:border-cyan-400/40 hover:text-cyan-200"
          >
            <Download className="h-3.5 w-3.5" />
          </button>
        </div>
      </td>
    </tr>
  );
}

/**
 * Page chrome. `qg-agent-center` is the theme scope (see the AGENT CENTER block
 * in index.css): inside it the page's dark-first palette is remapped for light
 * mode, so no component below needs a theme prop or a `dark:` variant.
 *
 * The utility bar renders in every state — loading, plan gate and the console —
 * so the theme can always be changed. It is the same control and the same
 * provider as the dashboard, so the choice is shared, persisted and applied
 * before first paint.
 */
function Shell({ children, leading }: { children: React.ReactNode; leading?: React.ReactNode }) {
  return (
    <div className="qg-agent-center min-h-screen bg-[#050810] text-white">
      <div className="mx-auto w-full max-w-[1400px] px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-5 flex min-h-[38px] items-center justify-between gap-3">
          <div className="min-w-0">{leading}</div>
          {/* Compact below `sm` so the toggle never pushes the back link onto a second line. */}
          <div className="sm:hidden">
            <ThemeToggle compact showSystem={false} />
          </div>
          <div className="hidden sm:block">
            <ThemeToggle />
          </div>
        </div>
        {children}
      </div>
    </div>
  );
}
