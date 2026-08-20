import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Ban,
  Cpu,
  Download,
  FileSearch,
  Loader2,
  Pause,
  Play,
  RefreshCw,
  ScanLine,
  Trash2,
  X,
} from 'lucide-react';
import { CAPABILITY_LABELS, type AgentPlatform } from '@/lib/agent-installer/agent-release';
import {
  digestOfPackage,
  downloadGeneratedPackage,
  type AgentActivityEntry,
  type AgentFindings,
  type AgentHealth,
  type AgentScanRecord,
  type DeployedAgent,
  type GeneratedPackage,
  type useAgentInstaller,
} from '@/hooks/use-agent-installer';
import { CopyButton, NotAssessed, StatusChip, fmtBytes, fmtDate, relTime } from './primitives';

type Installer = ReturnType<typeof useAgentInstaller>;
type Tab = 'overview' | 'capabilities' | 'activity' | 'findings' | 'installer';

const TABS: Array<{ id: Tab; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'capabilities', label: 'Capabilities' },
  { id: 'activity', label: 'Activity' },
  { id: 'findings', label: 'Findings' },
  { id: 'installer', label: 'Installer' },
];

/**
 * Agent detail drawer (spec §12). Focus is trapped, ESC closes, and every panel
 * distinguishes "no data yet" from "measured zero" — an agent that never scanned
 * shows Not Yet Assessed, never a clean bill of health.
 */
export function AgentDetailDrawer({
  agent,
  installer,
  onClose,
}: {
  agent: DeployedAgent;
  installer: Installer;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<Tab>('overview');
  const [health, setHealth] = useState<AgentHealth | null>(null);
  const [activity, setActivity] = useState<AgentActivityEntry[]>([]);
  const [findings, setFindings] = useState<AgentFindings | null>(null);
  const [scans, setScans] = useState<AgentScanRecord[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const [platform, setPlatform] = useState<AgentPlatform>('linux');
  const [pkg, setPkg] = useState<GeneratedPackage | null>(null);
  const [digestOk, setDigestOk] = useState<boolean | null>(null);

  const panelRef = useRef<HTMLDivElement>(null);
  const oneTimeToken = installer.oneTimeToken?.agentId === agent.id ? installer.oneTimeToken : null;
  const scan = installer.scanProgress[agent.id];

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    panelRef.current?.focus();
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  const reload = useCallback(async () => {
    setLoadError(null);
    const [healthResult, activityResult, findingsResult, scansResult] = await Promise.all([
      installer.loadHealth(agent.id),
      installer.loadActivity(agent.id),
      installer.loadFindings(agent.id),
      installer.loadScans(agent.id),
    ]);
    if (healthResult.ok && healthResult.data) setHealth(healthResult.data);
    else if (healthResult.message) setLoadError(healthResult.message);
    if (activityResult.ok && activityResult.data) setActivity(activityResult.data.activity);
    if (findingsResult.ok && findingsResult.data) setFindings(findingsResult.data);
    if (scansResult.ok && scansResult.data) setScans(scansResult.data.scans);
  }, [agent.id, installer]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // Re-read detail whenever the stream reports something new for this tenant.
  useEffect(() => {
    if (!installer.lastEventAt) return;
    void reload();
  }, [installer.lastEventAt, reload]);

  const act = useCallback(
    async (label: string, run: () => Promise<{ ok: boolean; message?: string; data?: unknown }>) => {
      setWorking(true);
      setNotice(null);
      const result = await run();
      setWorking(false);
      const delivery = (result.data as { delivery?: string } | undefined)?.delivery;
      setNotice(result.ok ? delivery || `${label} requested.` : result.message || `${label} failed.`);
      if (result.ok) void reload();
    },
    [reload],
  );

  const generate = useCallback(async () => {
    if (!oneTimeToken) {
      setNotice('Rotate the enrollment token first — an installer must embed a live credential.');
      return;
    }
    setWorking(true);
    const result = await installer.generatePackage(agent.id, platform, oneTimeToken.token);
    setWorking(false);
    if (!result.ok || !result.data) {
      setNotice(result.message || 'Installer generation failed.');
      return;
    }
    setPkg(result.data);
    try {
      setDigestOk((await digestOfPackage(result.data)) === result.data.installerSha256);
    } catch {
      setDigestOk(null);
    }
  }, [agent.id, installer, oneTimeToken, platform]);

  const capabilities = useMemo(
    () => Object.entries(agent.capabilities || {}).filter(([, enabled]) => enabled === true),
    [agent.capabilities],
  );

  const revoked = Boolean(agent.revoked_at || agent.status === 'revoked');
  const policy = (agent.policy || {}) as Record<string, unknown>;
  const allowedTargets = Array.isArray(policy.allowedTargets) ? (policy.allowedTargets as string[]) : [];
  const allowedPaths = Array.isArray(policy.allowedPaths) ? (policy.allowedPaths as string[]) : [];

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label={`Agent ${agent.name}`}>
      <button type="button" className="flex-1 cursor-default" aria-label="Close agent details" onClick={onClose} />
      <div
        ref={panelRef}
        tabIndex={-1}
        className="flex h-full w-full max-w-2xl flex-col border-l border-white/10 bg-[#080d16] outline-none"
      >
        <header className="flex items-start justify-between gap-3 border-b border-white/10 px-5 py-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="truncate text-base font-black text-white">{agent.name}</h2>
              <StatusChip state={agent.connectionState} />
              {revoked ? (
                <span className="rounded-full border border-rose-400/30 bg-rose-400/10 px-2 py-0.5 text-[10px] font-black uppercase text-rose-200">
                  Revoked
                </span>
              ) : null}
              {agent.upgradeAvailable ? (
                <span className="rounded-full border border-cyan-400/30 bg-cyan-400/10 px-2 py-0.5 text-[10px] font-black uppercase text-cyan-200">
                  Update available
                </span>
              ) : null}
            </div>
            <p className="mt-1 break-all font-mono text-[11px] text-white/35">{agent.id}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-white/12 bg-white/[0.04] p-1.5 text-white/60 transition hover:text-white"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </header>

        <nav className="flex gap-1 border-b border-white/8 px-5 py-2">
          {TABS.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setTab(item.id)}
              className={`rounded-lg px-3 py-1.5 text-xs font-bold transition ${
                tab === item.id ? 'bg-cyan-400/10 text-cyan-200' : 'text-white/45 hover:text-white/75'
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className="flex-1 overflow-y-auto px-5 py-4">
          {loadError ? (
            <div className="mb-4 rounded-lg border border-rose-400/25 bg-rose-400/[0.06] px-3 py-2 text-xs text-rose-100">{loadError}</div>
          ) : null}
          {notice ? (
            <div className="mb-4 rounded-lg border border-cyan-400/25 bg-cyan-400/[0.06] px-3 py-2 text-xs text-cyan-100">{notice}</div>
          ) : null}

          {scan && scan.progress < 100 ? (
            <div className="mb-4 rounded-xl border border-cyan-400/25 bg-cyan-400/[0.05] p-3">
              <div className="flex items-center justify-between gap-3 text-xs">
                <span className="font-bold text-cyan-100">{scan.message || scan.stage}</span>
                <span className="font-mono text-cyan-200">{scan.progress}%</span>
              </div>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/10">
                <div className="h-full rounded-full bg-cyan-400 transition-all duration-500" style={{ width: `${scan.progress}%` }} />
              </div>
            </div>
          ) : null}

          {tab === 'overview' ? (
            <OverviewTab agent={agent} health={health} scans={scans} allowedTargets={allowedTargets} allowedPaths={allowedPaths} />
          ) : null}

          {tab === 'capabilities' ? (
            <div className="space-y-4">
              <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
                <div className="text-[11px] font-bold uppercase tracking-wide text-white/45">Granted capabilities</div>
                {capabilities.length === 0 ? (
                  <p className="mt-2 text-xs text-white/40">No capabilities are enabled for this agent.</p>
                ) : (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {capabilities.map(([key]) => (
                      <span key={key} className="rounded-lg border border-emerald-400/25 bg-emerald-400/10 px-2.5 py-1 text-[11px] font-bold text-emerald-200">
                        {CAPABILITY_LABELS[key] || key}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
                <div className="text-[11px] font-bold uppercase tracking-wide text-white/45">Authorized scope</div>
                <div className="mt-2 grid gap-3 sm:grid-cols-2">
                  <ScopeList title="Allowed targets" items={allowedTargets} empty="No network targets authorized." />
                  <ScopeList title="Allowed paths" items={allowedPaths} empty="No filesystem paths authorized." />
                </div>
                <p className="mt-3 text-[11px] leading-relaxed text-white/35">
                  The agent refuses evidence and configuration changes outside this scope; the backend rejects them a second
                  time on upload.
                </p>
              </div>
            </div>
          ) : null}

          {tab === 'activity' ? <ActivityTab activity={activity} /> : null}
          {tab === 'findings' ? <FindingsTab findings={findings} /> : null}

          {tab === 'installer' ? (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-1.5">
                {installer.platforms.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setPlatform(item.id);
                      setPkg(null);
                      setDigestOk(null);
                    }}
                    className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-bold transition ${
                      platform === item.id
                        ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200'
                        : 'border-white/8 bg-white/[0.02] text-white/45 hover:text-white/75'
                    }`}
                  >
                    {item.label}
                  </button>
                ))}
              </div>

              {oneTimeToken ? (
                <div className="rounded-xl border border-amber-400/25 bg-amber-400/[0.05] p-3">
                  <div className="text-[11px] font-bold text-amber-100">
                    Live enrollment token held ({oneTimeToken.mode === 'rotated' ? 'rotated' : 'created'} {relTime(oneTimeToken.createdAt)})
                  </div>
                  <p className="mt-1 text-[11px] leading-relaxed text-amber-100/65">
                    Generate the installer now — this page holds the credential only until you navigate away.
                  </p>
                </div>
              ) : (
                <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                  <p className="text-[11px] leading-relaxed text-white/50">
                    The enrollment token is stored only as a hash and cannot be recovered. Rotate it to issue a fresh credential
                    and generate a new installer — this immediately invalidates any installer that carries the old token.
                  </p>
                  <button
                    type="button"
                    disabled={working || revoked}
                    onClick={() => void act('Token rotation', () => installer.rotateToken(agent.id))}
                    className="mt-2.5 inline-flex items-center gap-1.5 rounded-lg border border-amber-400/35 bg-amber-400/10 px-3 py-1.5 text-[11px] font-bold text-amber-100 transition hover:bg-amber-400/20 disabled:opacity-40"
                  >
                    <RefreshCw className="h-3.5 w-3.5" /> Rotate token
                  </button>
                </div>
              )}

              {pkg ? (
                <div className="space-y-3">
                  <div className="rounded-xl border border-white/10 bg-black/40">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/8 px-3 py-2">
                      <span className="font-mono text-[11px] text-white/55">{pkg.filename}</span>
                      <div className="flex items-center gap-2">
                        <CopyButton value={pkg.content} label="Copy" />
                        <button
                          type="button"
                          onClick={() => downloadGeneratedPackage(pkg)}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/40 bg-cyan-400/10 px-3 py-1.5 text-[11px] font-black text-cyan-100 transition hover:bg-cyan-400/20"
                        >
                          <Download className="h-3.5 w-3.5" /> Download
                        </button>
                      </div>
                    </div>
                    <pre className="max-h-64 overflow-auto p-3 text-[11px] leading-relaxed text-white/70">
                      <code>{pkg.content}</code>
                    </pre>
                  </div>
                  <div className="rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2 text-[11px]">
                    <div className="text-white/40">Installer SHA-256</div>
                    <div className="break-all font-mono text-white/70">{pkg.installerSha256}</div>
                    <div className="mt-1.5 text-white/40">Runtime SHA-256 (verified on the host)</div>
                    <div className="break-all font-mono text-white/70">{pkg.runtime.sha256}</div>
                    {digestOk === true ? <div className="mt-1.5 text-emerald-300">Digest verified in this browser.</div> : null}
                    {digestOk === false ? <div className="mt-1.5 text-rose-300">Digest mismatch — regenerate before running.</div> : null}
                  </div>
                  <div className="rounded-lg border border-white/10 bg-black/40 px-3 py-2">
                    <code className="break-all font-mono text-[11px] text-cyan-200">{pkg.instructions.runCommand}</code>
                  </div>
                </div>
              ) : (
                <button
                  type="button"
                  disabled={working || !oneTimeToken || revoked}
                  onClick={() => void generate()}
                  className="inline-flex items-center gap-2 rounded-xl border border-cyan-400/40 bg-cyan-400/10 px-4 py-2.5 text-sm font-bold text-cyan-100 transition hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {working ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                  Generate installer
                </button>
              )}
            </div>
          ) : null}
        </div>

        <footer className="flex flex-wrap items-center gap-2 border-t border-white/10 bg-black/30 px-5 py-3">
          <button
            type="button"
            disabled={working || revoked}
            onClick={() => void act('Scan', () => installer.requestScan(agent.id))}
            className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/35 bg-cyan-400/10 px-3 py-1.5 text-[11px] font-bold text-cyan-100 transition hover:bg-cyan-400/20 disabled:opacity-40"
          >
            <ScanLine className="h-3.5 w-3.5" /> Run scan
          </button>
          <button
            type="button"
            disabled={working || revoked || !agent.upgradeAvailable}
            title={agent.upgradeAvailable ? 'Queue an upgrade' : 'Agent is already on the published version'}
            onClick={() => void act('Upgrade', () => installer.requestUpgrade(agent.id))}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-1.5 text-[11px] font-bold text-white/65 transition hover:text-white disabled:opacity-30"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Upgrade
          </button>
          <button
            type="button"
            disabled={working || revoked}
            onClick={() => void act(agent.status === 'disabled' ? 'Enable' : 'Pause', () => installer.setAgentEnabled(agent.id, agent.status === 'disabled'))}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-1.5 text-[11px] font-bold text-white/65 transition hover:text-white disabled:opacity-40"
          >
            {agent.status === 'disabled' ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
            {agent.status === 'disabled' ? 'Enable' : 'Pause'}
          </button>
          <div className="flex-1" />
          <button
            type="button"
            disabled={working || revoked}
            onClick={() => void act('Revoke', () => installer.revokeAgent(agent.id))}
            className="inline-flex items-center gap-1.5 rounded-lg border border-amber-400/30 bg-amber-400/10 px-3 py-1.5 text-[11px] font-bold text-amber-100 transition hover:bg-amber-400/20 disabled:opacity-40"
          >
            <Ban className="h-3.5 w-3.5" /> Revoke
          </button>
          {confirmDelete ? (
            <button
              type="button"
              disabled={working}
              onClick={() =>
                void act('Delete', async () => {
                  const result = await installer.deleteAgent(agent.id);
                  if (result.ok) onClose();
                  return result;
                })
              }
              className="inline-flex items-center gap-1.5 rounded-lg border border-rose-400/40 bg-rose-400/20 px-3 py-1.5 text-[11px] font-black text-rose-100"
            >
              <AlertTriangle className="h-3.5 w-3.5" /> Confirm delete
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setConfirmDelete(true)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-rose-400/25 bg-rose-400/10 px-3 py-1.5 text-[11px] font-bold text-rose-200 transition hover:bg-rose-400/20"
            >
              <Trash2 className="h-3.5 w-3.5" /> Delete
            </button>
          )}
        </footer>
      </div>
    </div>
  );
}

function ScopeList({ title, items, empty }: { title: string; items: string[]; empty: string }) {
  return (
    <div>
      <div className="text-[10px] font-bold uppercase tracking-wide text-white/35">{title}</div>
      {items.length === 0 ? (
        <p className="mt-1 text-[11px] text-white/35">{empty}</p>
      ) : (
        <ul className="mt-1 space-y-1">
          {items.map((item) => (
            <li key={item} className="break-all font-mono text-[11px] text-white/65">{item}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function OverviewTab({
  agent,
  health,
  scans,
  allowedTargets,
  allowedPaths,
}: {
  agent: DeployedAgent;
  health: AgentHealth | null;
  scans: AgentScanRecord[];
  allowedTargets: string[];
  allowedPaths: string[];
}) {
  const lastScan = scans.find((item) => item.status === 'completed');
  const host = (health?.host || {}) as Record<string, unknown>;
  const memory = (health?.memory || {}) as Record<string, unknown>;
  const counters = (health?.counters || {}) as Record<string, unknown>;

  const rows: Array<[string, string]> = [
    ['Role', String(agent.role || 'collector')],
    ['Environment', String(agent.environment || '—')],
    ['Assigned asset', String(agent.assignedAssetName || 'Not assigned')],
    ['Hostname', String(agent.hostname || 'Pending install')],
    ['Platform', String(agent.platform || 'customer-managed')],
    ['Installed version', String(agent.version || '—')],
    ['Latest version', String(health?.latestVersion || '—')],
    ['Last heartbeat', relTime(agent.last_seen_at)],
    ['Last seen', fmtDate(agent.last_seen_at)],
    ['Created', fmtDate(agent.created_at)],
    ['Authorized targets', String(allowedTargets.length)],
    ['Authorized paths', String(allowedPaths.length)],
  ];

  return (
    <div className="space-y-4">
      <dl className="grid gap-2 sm:grid-cols-2">
        {rows.map(([label, value]) => (
          <div key={label} className="flex items-center justify-between gap-3 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
            <dt className="text-[11px] text-white/40">{label}</dt>
            <dd className="truncate text-right text-[11px] font-bold text-white/75">{value}</dd>
          </div>
        ))}
      </dl>

      <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
        <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wide text-white/45">
          <Cpu className="h-3.5 w-3.5" /> Host health
        </div>
        {!health?.telemetryAvailable ? (
          <p className="mt-2 text-[11px] leading-relaxed text-white/40">
            No resource telemetry reported yet. The agent sends CPU, memory and uptime with its first heartbeat.
          </p>
        ) : (
          <dl className="mt-2 grid gap-2 sm:grid-cols-2">
            {[
              ['Host', `${host.hostname ?? '—'}`],
              ['OS', `${host.platform ?? '—'} ${host.release ?? ''}`.trim()],
              ['Architecture', `${host.arch ?? '—'}`],
              ['CPU cores', `${host.cpuCount ?? '—'}`],
              ['Load (1m)', `${host.loadAverage1m ?? '—'}`],
              ['Host uptime', host.uptimeSeconds ? `${Math.round(Number(host.uptimeSeconds) / 3600)}h` : '—'],
              ['Memory used', memory.usedPercent != null ? `${memory.usedPercent}%` : '—'],
              ['Agent RSS', fmtBytes(Number(memory.agentRssBytes) || null)],
              ['Scans completed', `${counters.scanCount ?? 0}`],
              ['Errors', `${counters.errorCount ?? 0}`],
              ['Queue depth', `${counters.queueDepth ?? 0}`],
              ['Current job', `${counters.currentJob ?? 'Idle'}`],
            ].map(([label, value]) => (
              <div key={label} className="flex items-center justify-between gap-3 text-[11px]">
                <dt className="text-white/40">{label}</dt>
                <dd className="truncate text-right font-mono text-white/70">{value}</dd>
              </div>
            ))}
          </dl>
        )}
      </div>

      <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
        <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wide text-white/45">
          <Activity className="h-3.5 w-3.5" /> Scan history
        </div>
        {scans.length === 0 ? (
          <p className="mt-2 text-[11px] text-white/40">This agent has not completed a scan yet.</p>
        ) : (
          <>
            {lastScan ? (
              <p className="mt-2 text-[11px] text-white/55">
                Last completed {relTime(lastScan.completedAt)} · {lastScan.evidenceCount ?? 0} evidence record(s)
                {lastScan.durationMs ? ` · ${Math.round(lastScan.durationMs / 1000)}s` : ''}
              </p>
            ) : null}
            <ul className="mt-2 max-h-40 space-y-1 overflow-auto">
              {scans.slice(0, 12).map((item, index) => (
                <li key={`${item.startedAt}-${index}`} className="flex items-center justify-between gap-3 text-[11px]">
                  <span className="text-white/45">{fmtDate(item.startedAt)}</span>
                  <span className={item.status === 'completed' ? 'text-emerald-300' : 'text-cyan-300'}>
                    {item.status === 'completed' ? `${item.evidenceCount ?? 0} evidence` : 'Running'}
                  </span>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    </div>
  );
}

function ActivityTab({ activity }: { activity: AgentActivityEntry[] }) {
  if (activity.length === 0) {
    return (
      <p className="rounded-xl border border-dashed border-white/15 px-4 py-8 text-center text-xs text-white/40">
        No activity has been recorded for this agent.
      </p>
    );
  }
  return (
    <ol className="space-y-1.5">
      {activity.map((entry) => (
        <li key={entry.id} className="flex items-start gap-3 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
          <span className="w-16 shrink-0 font-mono text-[11px] text-white/35">
            {entry.at ? new Date(entry.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—'}
          </span>
          <span className="min-w-0 flex-1">
            <span className="block text-[11px] text-white/75">{entry.message || entry.phase || entry.stage || entry.status}</span>
            {entry.progress != null ? (
              <span className="mt-0.5 block font-mono text-[10px] text-cyan-300/70">{entry.progress}%</span>
            ) : null}
          </span>
        </li>
      ))}
    </ol>
  );
}

function FindingsTab({ findings }: { findings: AgentFindings | null }) {
  if (!findings) {
    return <p className="text-xs text-white/40">Loading findings…</p>;
  }
  if (!findings.scanned) {
    return (
      <NotAssessed hint="This agent has not uploaded any evidence, so no cryptographic finding — safe or unsafe — can be attributed to it. Run a scan once it is connected." />
    );
  }

  return (
    <div className="space-y-4">
      {findings.alerts.length > 0 ? (
        <div className="rounded-xl border border-amber-400/25 bg-amber-400/[0.05] p-4">
          <div className="text-[11px] font-bold uppercase tracking-wide text-amber-100/80">Open alerts</div>
          <ul className="mt-2 space-y-2">
            {findings.alerts.slice(0, 10).map((alert) => (
              <li key={alert.id} className="rounded-lg border border-white/8 bg-black/30 px-3 py-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[11px] font-bold text-white/80">{alert.title || alert.category}</span>
                  <span className="rounded border border-white/12 px-1.5 py-0.5 text-[10px] font-black uppercase text-white/55">
                    {alert.severity || 'unknown'}
                  </span>
                </div>
                {alert.message ? <p className="mt-1 text-[11px] leading-relaxed text-white/50">{alert.message}</p> : null}
                {alert.recommendation ? (
                  <p className="mt-1 text-[11px] leading-relaxed text-cyan-200/70">{alert.recommendation}</p>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
        <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wide text-white/45">
          <FileSearch className="h-3.5 w-3.5" /> Evidence ({findings.evidence.length})
        </div>
        <p className="mt-1 text-[11px] text-white/35">
          Every row below is a direct observation by collector {findings.collectorVersion || 'agent'} — algorithm, location and
          time as measured, not inferred.
        </p>
        <div className="mt-3 overflow-x-auto">
          <table className="w-full min-w-[520px] text-left text-[11px]">
            <thead>
              <tr className="text-white/35">
                <th className="pb-2 font-bold">Algorithm</th>
                <th className="pb-2 font-bold">Asset</th>
                <th className="pb-2 font-bold">Source</th>
                <th className="pb-2 font-bold">Confidence</th>
                <th className="pb-2 font-bold">Observed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {findings.evidence.slice(0, 60).map((row) => (
                <tr key={row.id} className="text-white/65">
                  <td className="py-1.5 pr-3 font-mono">{row.observed_algorithm || '—'}{row.key_size ? ` (${row.key_size})` : ''}</td>
                  <td className="py-1.5 pr-3">{row.asset_name || row.host || '—'}</td>
                  <td className="py-1.5 pr-3 text-white/45">{row.evidence_type || '—'}</td>
                  <td className="py-1.5 pr-3 text-white/45">{row.confidence || '—'}</td>
                  <td className="py-1.5 text-white/40">{relTime(row.observed_at || row.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
