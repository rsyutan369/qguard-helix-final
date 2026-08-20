import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Download,
  FileTerminal,
  KeyRound,
  Loader2,
  RefreshCw,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import {
  AGENT_ROLES,
  INSTALL_PHASES,
  type AgentPlatform,
  type AgentRole,
} from '@/lib/agent-installer/agent-release';
import {
  digestOfPackage,
  downloadGeneratedPackage,
  type CreateAgentInput,
  type GeneratedPackage,
  type useAgentInstaller,
} from '@/hooks/use-agent-installer';
import { CopyButton, StatusChip, fmtBytes, relTime } from './primitives';

/**
 * Deployment wizard — Agent Type → Platform → Scope → Permissions → Enrollment →
 * Install → Verify (spec §6, §31, §32).
 *
 * Each step is gated on a real precondition: you cannot reach Enrollment without
 * a created agent, cannot reach Install without a live one-time token, and the
 * Verify step reflects heartbeat truth rather than the fact that a download
 * happened.
 */

type Installer = ReturnType<typeof useAgentInstaller>;

const STEPS = ['Agent Type', 'Platform', 'Scope', 'Permissions', 'Enrollment', 'Install', 'Verify'] as const;
type StepIndex = 0 | 1 | 2 | 3 | 4 | 5 | 6;

const ENVIRONMENTS = ['production', 'staging', 'development', 'dr', 'lab'];

const SCAN_TYPE_GROUPS: Array<{ group: string; types: Array<{ id: string; label: string }> }> = [
  {
    group: 'Transport & PKI',
    types: [
      { id: 'tls', label: 'TLS endpoints' },
      { id: 'certificates', label: 'Certificates' },
      { id: 'pki', label: 'PKI metadata' },
      { id: 'ssh', label: 'SSH key exchange' },
    ],
  },
  {
    group: 'Host & application',
    types: [
      { id: 'configs', label: 'Config files' },
      { id: 'packages', label: 'Package manifests' },
      { id: 'libraries', label: 'Crypto libraries' },
      { id: 'runtime', label: 'Runtime crypto' },
    ],
  },
  {
    group: 'Platform surfaces',
    types: [
      { id: 'kubernetes', label: 'Kubernetes' },
      { id: 'container', label: 'Containers' },
      { id: 'service_mesh', label: 'Service mesh' },
      { id: 'api_gateway', label: 'API gateway' },
      { id: 'load_balancer', label: 'Load balancer' },
      { id: 'vpn', label: 'VPN profiles' },
      { id: 'database', label: 'Database crypto' },
      { id: 'hsm', label: 'HSM integration' },
    ],
  },
];

function StepRail({ step, reached }: { step: StepIndex; reached: number }) {
  return (
    <ol className="flex flex-wrap items-center gap-1.5">
      {STEPS.map((label, index) => {
        const isCurrent = index === step;
        const isDone = index < reached;
        return (
          <li key={label} className="flex items-center gap-1.5">
            <span
              className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[11px] font-bold transition ${
                isCurrent
                  ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200'
                  : isDone
                    ? 'border-emerald-400/25 bg-emerald-400/[0.07] text-emerald-200/80'
                    : 'border-white/10 bg-white/[0.02] text-white/40'
              }`}
            >
              {isDone ? <CheckCircle2 className="h-3.5 w-3.5" /> : <span className="tabular-nums">{index + 1}</span>}
              <span className="hidden sm:inline">{label}</span>
            </span>
            {index < STEPS.length - 1 ? <span className="h-px w-3 bg-white/10" /> : null}
          </li>
        );
      })}
    </ol>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-[11px] font-bold uppercase tracking-wide text-white/50">{label}</span>
      {children}
      {hint ? <span className="mt-1 block text-[11px] leading-snug text-white/35">{hint}</span> : null}
    </label>
  );
}

const inputClass =
  'mt-1.5 w-full rounded-lg border border-white/12 bg-black/40 px-3 py-2 text-sm text-white outline-none transition placeholder:text-white/25 focus:border-cyan-400/50';

export function DeployWizard({
  installer,
  onClose,
  onOpenAgent,
}: {
  installer: Installer;
  onClose: () => void;
  onOpenAgent: (agentId: string) => void;
}) {
  const [step, setStep] = useState<StepIndex>(0);
  const [reached, setReached] = useState(0);

  const [role, setRole] = useState<AgentRole>('collector');
  const [platform, setPlatform] = useState<AgentPlatform>('linux');
  const [name, setName] = useState('');
  const [environment, setEnvironment] = useState('production');
  const [description, setDescription] = useState('');
  const [assetName, setAssetName] = useState('');
  const [assetId, setAssetId] = useState<string | null>(null);
  const [targetsText, setTargetsText] = useState('');
  const [pathsText, setPathsText] = useState('');
  const [intervalSeconds, setIntervalSeconds] = useState(60);
  const [alertThreshold, setAlertThreshold] = useState('moderate');
  const [scanTypes, setScanTypes] = useState<string[]>(AGENT_ROLES[0].scanTypes);
  const [remediationAuthorized, setRemediationAuthorized] = useState(false);
  const [migrationAuthorized, setMigrationAuthorized] = useState(false);

  const [agentId, setAgentId] = useState<string | null>(null);
  const [pkg, setPkg] = useState<GeneratedPackage | null>(null);
  const [localDigest, setLocalDigest] = useState<string | null>(null);
  const [downloaded, setDownloaded] = useState(false);
  const [working, setWorking] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const roleDefinition = useMemo(() => AGENT_ROLES.find((item) => item.id === role) || AGENT_ROLES[0], [role]);
  const platformInfo = useMemo(
    () => installer.platforms.find((item) => item.id === platform),
    [installer.platforms, platform],
  );
  const createdAgent = useMemo(
    () => installer.agents.find((item) => item.id === agentId) || null,
    [installer.agents, agentId],
  );
  const oneTimeToken = installer.oneTimeToken?.agentId === agentId ? installer.oneTimeToken : null;

  // Selecting a role resets scope to that role's module set — a Scanner should
  // not silently inherit an Operator's surface list.
  useEffect(() => {
    setScanTypes(roleDefinition.scanTypes);
    if (!roleDefinition.mutatesTargets) {
      setRemediationAuthorized(false);
      setMigrationAuthorized(false);
    }
  }, [roleDefinition]);

  const go = useCallback((next: StepIndex) => {
    setStep(next);
    setReached((prev) => Math.max(prev, next));
    setMessage(null);
  }, []);

  const toggleScanType = (id: string) =>
    setScanTypes((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));

  const parsedTargets = useMemo(
    () => targetsText.split(/[\n,]/).map((item) => item.trim()).filter(Boolean),
    [targetsText],
  );
  const parsedPaths = useMemo(
    () => pathsText.split(/\n/).map((item) => item.trim()).filter(Boolean),
    [pathsText],
  );

  const canCreate = name.trim().length >= 2 && scanTypes.length > 0;

  const handleCreate = useCallback(async () => {
    setWorking(true);
    setMessage(null);
    const input: CreateAgentInput = {
      name: name.trim(),
      role,
      environment,
      description: description.trim(),
      assetName: assetName.trim() || null,
      assetId,
      allowedTargets: parsedTargets,
      allowedPaths: parsedPaths,
      scanTypes,
      intervalSeconds,
      alertThreshold,
      remediationAuthorized,
      migrationAuthorized,
    };
    const result = await installer.createAgent(input);
    setWorking(false);
    if (!result.ok || !result.data?.agentId) {
      setMessage(result.message || 'Agent creation failed.');
      return;
    }
    setAgentId(result.data.agentId);
    go(4);
  }, [
    installer, name, role, environment, description, assetName, assetId, parsedTargets, parsedPaths,
    scanTypes, intervalSeconds, alertThreshold, remediationAuthorized, migrationAuthorized, go,
  ]);

  const handleGenerate = useCallback(async () => {
    if (!agentId || !oneTimeToken) return;
    setWorking(true);
    setMessage(null);
    const result = await installer.generatePackage(agentId, platform, oneTimeToken.token);
    setWorking(false);
    if (!result.ok || !result.data) {
      setMessage(result.message || 'Installer generation failed.');
      return;
    }
    setPkg(result.data);
    setDownloaded(false);
    // Hash what the browser actually received and show it beside the server's
    // digest, so the operator verifies the artifact rather than trusting a label.
    try {
      setLocalDigest(await digestOfPackage(result.data));
    } catch {
      setLocalDigest(null);
    }
  }, [agentId, oneTimeToken, installer, platform]);

  const handleDownload = useCallback(() => {
    if (!pkg) return;
    downloadGeneratedPackage(pkg);
    setDownloaded(true);
  }, [pkg]);

  const handleRotate = useCallback(async () => {
    if (!agentId) return;
    setWorking(true);
    const result = await installer.rotateToken(agentId);
    setWorking(false);
    if (!result.ok) {
      setMessage(result.message || 'Token rotation failed.');
      return;
    }
    setPkg(null);
    setLocalDigest(null);
    setDownloaded(false);
    setMessage('Token rotated. Previously generated installers no longer authenticate — generate a new one.');
  }, [agentId, installer]);

  const digestMatches = pkg && localDigest ? localDigest === pkg.installerSha256 : null;

  return (
    <div className="rounded-2xl border border-cyan-400/20 bg-gradient-to-b from-cyan-400/[0.04] to-transparent">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-white/8 px-5 py-4">
        <div className="flex items-center gap-2.5">
          <Sparkles className="h-4 w-4 text-cyan-300" />
          <h2 className="text-sm font-black uppercase tracking-wide text-white/85">Deploy new agent</h2>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded-lg border border-white/12 bg-white/[0.04] px-3 py-1.5 text-[11px] font-bold text-white/60 transition hover:text-white"
        >
          Close
        </button>
      </header>

      <div className="border-b border-white/8 px-5 py-3">
        <StepRail step={step} reached={reached} />
      </div>

      <div className="p-5">
        {message ? (
          <div className="mb-4 rounded-lg border border-amber-400/25 bg-amber-400/[0.07] px-3 py-2 text-xs text-amber-100">
            {message}
          </div>
        ) : null}

        {/* ---------------- Step 0 — Agent type ---------------- */}
        {step === 0 ? (
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              {AGENT_ROLES.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setRole(item.id)}
                  className={`rounded-xl border p-4 text-left transition ${
                    role === item.id
                      ? 'border-cyan-400/40 bg-cyan-400/[0.07]'
                      : 'border-white/10 bg-white/[0.02] hover:border-white/20'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-black text-white">{item.label}</span>
                    {item.mutatesTargets ? (
                      <span className="rounded-full border border-amber-400/30 bg-amber-400/10 px-2 py-0.5 text-[10px] font-black uppercase text-amber-200">
                        Can change config
                      </span>
                    ) : (
                      <span className="rounded-full border border-emerald-400/25 bg-emerald-400/10 px-2 py-0.5 text-[10px] font-black uppercase text-emerald-200">
                        Read-only
                      </span>
                    )}
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-white/55">{item.tagline}</p>
                  <p className="mt-2 text-[11px] leading-relaxed text-white/35">{item.authority}</p>
                </button>
              ))}
            </div>
            <div className="flex justify-end">
              <NextButton onClick={() => go(1)} />
            </div>
          </div>
        ) : null}

        {/* ---------------- Step 1 — Platform ---------------- */}
        {step === 1 ? (
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {installer.platforms.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setPlatform(item.id)}
                  className={`rounded-xl border p-4 text-left transition ${
                    platform === item.id
                      ? 'border-cyan-400/40 bg-cyan-400/[0.07]'
                      : 'border-white/10 bg-white/[0.02] hover:border-white/20'
                  }`}
                >
                  <div className="text-sm font-black text-white">{item.label}</div>
                  <div className="mt-1.5 text-[11px] leading-relaxed text-white/45">{item.service}</div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {item.architectures.map((arch) => (
                      <span key={arch} className="rounded border border-white/10 bg-white/[0.03] px-1.5 py-0.5 text-[10px] text-white/45">
                        {arch}
                      </span>
                    ))}
                  </div>
                </button>
              ))}
            </div>
            {platformInfo ? (
              <div className="rounded-xl border border-white/10 bg-black/30 p-4">
                <div className="text-[11px] font-bold uppercase tracking-wide text-white/45">Prerequisites</div>
                <ul className="mt-2 space-y-1">
                  {platformInfo.prerequisites.map((item) => (
                    <li key={item} className="text-xs text-white/60">• {item}</li>
                  ))}
                </ul>
                <div className="mt-3 text-[11px] text-amber-200/80">
                  <AlertTriangle className="mr-1 inline h-3.5 w-3.5" />
                  {platformInfo.privileges}
                </div>
              </div>
            ) : null}
            <StepNav onBack={() => go(0)} onNext={() => go(2)} />
          </div>
        ) : null}

        {/* ---------------- Step 2 — Scope ---------------- */}
        {step === 2 ? (
          <div className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Agent name" hint="Shown across the Agent Center, findings and audit trail.">
                <input className={inputClass} value={name} onChange={(event) => setName(event.target.value)} placeholder="edge-gateway-collector-01" />
              </Field>
              <Field label="Environment">
                <select className={inputClass} value={environment} onChange={(event) => setEnvironment(event.target.value)}>
                  {ENVIRONMENTS.map((item) => (
                    <option key={item} value={item} className="bg-slate-900">{item}</option>
                  ))}
                </select>
              </Field>
              <Field
                label="Assigned asset"
                hint={
                  installer.assets.length === 0
                    ? 'No assets in your inventory yet. The agent will be created unassigned and its findings will create assets as it discovers them.'
                    : "Binds this agent's findings to one of your own assets. Only assets in your tenant are listed, and the binding is re-verified server-side."
                }
              >
                <select
                  className={inputClass}
                  value={assetId || ''}
                  onChange={(event) => {
                    const next = event.target.value || null;
                    setAssetId(next);
                    setAssetName(installer.assets.find((asset) => asset.id === next)?.name || '');
                  }}
                  disabled={installer.assets.length === 0}
                >
                  <option value="" className="bg-slate-900">
                    {installer.assets.length === 0 ? 'No assets available' : 'Not linked to an asset'}
                  </option>
                  {installer.assets.map((asset) => (
                    <option key={asset.id} value={asset.id} className="bg-slate-900">
                      {asset.name}
                      {asset.type ? ` · ${asset.type}` : ''}
                      {asset.agents.length > 0 ? ` · ${asset.agents.length} agent${asset.agents.length === 1 ? '' : 's'}` : ''}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Heartbeat / scan interval" hint="30–60 seconds. Bounded server-side.">
                <input
                  type="number"
                  min={30}
                  max={60}
                  className={inputClass}
                  value={intervalSeconds}
                  onChange={(event) => setIntervalSeconds(Math.max(30, Math.min(60, Number(event.target.value) || 60)))}
                />
              </Field>
            </div>

            <Field label="Allowed targets" hint="One per line or comma separated: host:port, https://host, ssh://host:22. The agent scans nothing outside this list.">
              <textarea
                className={`${inputClass} min-h-[84px] font-mono text-xs`}
                value={targetsText}
                onChange={(event) => setTargetsText(event.target.value)}
                placeholder={'api.example.com:443\nssh://build-01.internal:22'}
              />
            </Field>

            <Field label="Allowed paths" hint="One per line. The agent reads configuration and manifests only inside these roots — and, for a Patcher, may only write inside them.">
              <textarea
                className={`${inputClass} min-h-[84px] font-mono text-xs`}
                value={pathsText}
                onChange={(event) => setPathsText(event.target.value)}
                placeholder={'/etc/nginx\n/opt/app/config'}
              />
            </Field>

            <div>
              <span className="text-[11px] font-bold uppercase tracking-wide text-white/50">Discovery scope</span>
              <div className="mt-2 space-y-3">
                {SCAN_TYPE_GROUPS.map((group) => (
                  <div key={group.group}>
                    <div className="text-[10px] font-bold uppercase tracking-wide text-white/30">{group.group}</div>
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      {group.types.map((type) => {
                        const active = scanTypes.includes(type.id);
                        return (
                          <button
                            key={type.id}
                            type="button"
                            onClick={() => toggleScanType(type.id)}
                            className={`rounded-lg border px-2.5 py-1 text-[11px] font-bold transition ${
                              active
                                ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200'
                                : 'border-white/10 bg-white/[0.02] text-white/45 hover:text-white/75'
                            }`}
                          >
                            {type.label}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
              {scanTypes.length === 0 ? (
                <p className="mt-2 text-[11px] text-rose-300">Select at least one discovery scope.</p>
              ) : null}
            </div>

            <StepNav onBack={() => go(1)} onNext={() => go(3)} nextDisabled={scanTypes.length === 0 || name.trim().length < 2} />
          </div>
        ) : null}

        {/* ---------------- Step 3 — Permissions ---------------- */}
        {step === 3 ? (
          <div className="space-y-4">
            <div className="rounded-xl border border-white/10 bg-black/30 p-4">
              <div className="text-sm font-black text-white">{roleDefinition.label} authority</div>
              <p className="mt-1.5 text-xs leading-relaxed text-white/55">{roleDefinition.authority}</p>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {roleDefinition.modules.map((module) => (
                  <span key={module} className="rounded border border-white/10 bg-white/[0.03] px-2 py-0.5 text-[10px] font-mono text-white/45">
                    {module}
                  </span>
                ))}
              </div>
            </div>

            {roleDefinition.mutatesTargets ? (
              <div className="space-y-3">
                <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-amber-400/25 bg-amber-400/[0.05] p-4">
                  <input
                    type="checkbox"
                    checked={remediationAuthorized}
                    onChange={(event) => setRemediationAuthorized(event.target.checked)}
                    className="mt-0.5 h-4 w-4 accent-amber-400"
                  />
                  <span>
                    <span className="block text-sm font-bold text-amber-100">Authorize configuration remediation</span>
                    <span className="mt-1 block text-[11px] leading-relaxed text-amber-100/65">
                      The agent may apply approved cryptographic changes inside the allowed paths above. Every change takes a
                      snapshot first, is validated afterwards and rolls back automatically on failure. Leave this off and the
                      agent stays read-only regardless of role.
                    </span>
                  </span>
                </label>

                {role === 'operator' ? (
                  <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-rose-400/25 bg-rose-400/[0.05] p-4">
                    <input
                      type="checkbox"
                      checked={migrationAuthorized}
                      onChange={(event) => setMigrationAuthorized(event.target.checked)}
                      className="mt-0.5 h-4 w-4 accent-rose-400"
                    />
                    <span>
                      <span className="block text-sm font-bold text-rose-100">Authorize Live Migration execution</span>
                      <span className="mt-1 block text-[11px] leading-relaxed text-rose-100/65">
                        The agent may claim approved migration jobs whose target asset, capability, policy and allowed paths all
                        match. It never executes a job merely because one exists.
                      </span>
                    </span>
                  </label>
                ) : null}
              </div>
            ) : (
              <div className="rounded-xl border border-emerald-400/25 bg-emerald-400/[0.05] p-4">
                <div className="flex items-center gap-2 text-sm font-bold text-emerald-100">
                  <ShieldCheck className="h-4 w-4" /> Read-only agent
                </div>
                <p className="mt-1.5 text-[11px] leading-relaxed text-emerald-100/65">
                  This role never writes to the host. It collects evidence from the allowed targets and paths and uploads it
                  over an authenticated channel.
                </p>
              </div>
            )}

            <Field label="Alert threshold" hint="Findings at or above this severity raise an alert.">
              <select className={inputClass} value={alertThreshold} onChange={(event) => setAlertThreshold(event.target.value)}>
                {['low', 'moderate', 'high', 'critical'].map((item) => (
                  <option key={item} value={item} className="bg-slate-900">{item}</option>
                ))}
              </select>
            </Field>

            <Field label="Description" hint="Optional operator note stored with the agent record.">
              <input className={inputClass} value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Edge TLS + certificate inventory for the public API tier" />
            </Field>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <BackButton onClick={() => go(2)} />
              <button
                type="button"
                disabled={!canCreate || working}
                onClick={() => void handleCreate()}
                className="inline-flex items-center gap-2 rounded-xl border border-cyan-400/40 bg-cyan-400/10 px-4 py-2.5 text-sm font-bold text-cyan-100 transition hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {working ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
                Create agent &amp; issue enrollment token
              </button>
            </div>
          </div>
        ) : null}

        {/* ---------------- Step 4 — Enrollment ---------------- */}
        {step === 4 ? (
          <div className="space-y-4">
            {oneTimeToken ? (
              <div className="rounded-xl border border-amber-400/30 bg-amber-400/[0.06] p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <KeyRound className="h-4 w-4 text-amber-300" />
                  <span className="text-sm font-black text-amber-100">Enrollment token</span>
                  <span className="rounded-full border border-amber-400/30 bg-amber-400/10 px-2 py-0.5 text-[10px] font-black uppercase text-amber-200">
                    Shown once
                  </span>
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <code className="flex-1 break-all rounded-lg border border-white/12 bg-black/50 px-3 py-2 font-mono text-xs text-emerald-200">
                    {oneTimeToken.token}
                  </code>
                  <CopyButton value={oneTimeToken.token} label="Copy token" />
                  <button
                    type="button"
                    onClick={() => void handleRotate()}
                    disabled={working}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[11px] font-bold text-white/70 transition hover:border-amber-400/40 hover:text-amber-200 disabled:opacity-40"
                  >
                    <RefreshCw className="h-3.5 w-3.5" /> Rotate
                  </button>
                </div>
                <p className="mt-2 text-[11px] leading-relaxed text-amber-100/70">
                  This value is stored only as a hash — it cannot be recovered. The generated installer embeds it for you, so
                  you do not need to copy it unless you are configuring the agent by hand. Rotating invalidates it immediately
                  and every installer that carries it.
                </p>
              </div>
            ) : (
              <div className="rounded-xl border border-rose-400/25 bg-rose-400/[0.06] p-4 text-xs text-rose-100">
                The one-time token for this agent is no longer held by this page. Rotate the token from the agent's detail view
                to issue a fresh credential and generate a new installer.
              </div>
            )}

            <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {[
                ['Agent ID', agentId || '—'],
                ['Role', roleDefinition.label],
                ['Environment', environment],
                ['Platform', platformInfo?.label || platform],
                ['Assigned asset', assetName || 'Not linked'],
              ].map(([label, value]) => (
                <div key={label} className="rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2">
                  <dt className="text-[10px] font-bold uppercase tracking-wide text-white/40">{label}</dt>
                  <dd className="mt-0.5 break-all font-mono text-[11px] text-white/75">{value}</dd>
                </div>
              ))}
            </dl>

            <StepNav onBack={() => go(3)} onNext={() => go(5)} nextDisabled={!oneTimeToken} nextLabel="Generate installer" />
          </div>
        ) : null}

        {/* ---------------- Step 5 — Install ---------------- */}
        {step === 5 ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              {installer.platforms.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setPlatform(item.id);
                    setPkg(null);
                    setLocalDigest(null);
                    setDownloaded(false);
                  }}
                  className={`rounded-lg border px-3 py-1.5 text-xs font-bold transition ${
                    platform === item.id
                      ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200'
                      : 'border-white/8 bg-white/[0.02] text-white/50 hover:text-white/80'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>

            {!pkg ? (
              <div className="rounded-xl border border-white/10 bg-black/30 p-6 text-center">
                <FileTerminal className="mx-auto h-6 w-6 text-cyan-300" />
                <p className="mx-auto mt-3 max-w-md text-xs leading-relaxed text-white/55">
                  The installer is generated on the server and bound to this agent: it carries the enrollment credential, the
                  scope you configured and the SHA-256 of the published runtime, which it verifies before executing anything.
                </p>
                <button
                  type="button"
                  onClick={() => void handleGenerate()}
                  disabled={working || !oneTimeToken}
                  className="mt-4 inline-flex items-center gap-2 rounded-xl border border-cyan-400/40 bg-cyan-400/10 px-4 py-2.5 text-sm font-bold text-cyan-100 transition hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {working ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                  Generate {platformInfo?.label} installer
                </button>
                {!oneTimeToken ? (
                  <p className="mt-3 text-[11px] text-amber-200/80">Rotate the enrollment token first — the installer must embed a live credential.</p>
                ) : null}
              </div>
            ) : (
              <InstallerPanel
                pkg={pkg}
                localDigest={localDigest}
                digestMatches={digestMatches}
                downloaded={downloaded}
                onDownload={handleDownload}
                onRegenerate={() => void handleGenerate()}
              />
            )}

            <StepNav onBack={() => go(4)} onNext={() => go(6)} nextDisabled={!pkg} nextLabel="Verify connection" />
          </div>
        ) : null}

        {/* ---------------- Step 6 — Verify ---------------- */}
        {step === 6 ? (
          <VerifyPanel
            installer={installer}
            agentId={agentId}
            createdAgent={createdAgent}
            onOpenAgent={onOpenAgent}
          />
        ) : null}
      </div>
    </div>
  );
}

function NextButton({ onClick, disabled, label = 'Continue' }: { onClick: () => void; disabled?: boolean; label?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex items-center gap-2 rounded-xl border border-cyan-400/40 bg-cyan-400/10 px-4 py-2.5 text-sm font-bold text-cyan-100 transition hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-40"
    >
      {label} <ArrowRight className="h-4 w-4" />
    </button>
  );
}

function BackButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-2 rounded-xl border border-white/12 bg-white/[0.04] px-4 py-2.5 text-sm font-bold text-white/70 transition hover:text-white"
    >
      <ArrowLeft className="h-4 w-4" /> Back
    </button>
  );
}

function StepNav({
  onBack,
  onNext,
  nextDisabled,
  nextLabel,
}: {
  onBack: () => void;
  onNext: () => void;
  nextDisabled?: boolean;
  nextLabel?: string;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <BackButton onClick={onBack} />
      <NextButton onClick={onNext} disabled={nextDisabled} label={nextLabel} />
    </div>
  );
}

function InstallerPanel({
  pkg,
  localDigest,
  digestMatches,
  downloaded,
  onDownload,
  onRegenerate,
}: {
  pkg: GeneratedPackage;
  localDigest: string | null;
  digestMatches: boolean | null;
  downloaded: boolean;
  onDownload: () => void;
  onRegenerate: () => void;
}) {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-white/10 bg-black/40">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/8 px-4 py-2.5">
          <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-white/60">
            <FileTerminal className="h-3.5 w-3.5" /> {pkg.filename}
          </span>
          <div className="flex flex-wrap items-center gap-2">
            <CopyButton value={pkg.content} label="Copy file" />
            <button
              type="button"
              onClick={onRegenerate}
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[11px] font-bold text-white/60 transition hover:text-white"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Regenerate
            </button>
            <button
              type="button"
              onClick={onDownload}
              className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/40 bg-cyan-400/10 px-3 py-1.5 text-[11px] font-black text-cyan-100 transition hover:bg-cyan-400/20"
            >
              <Download className="h-3.5 w-3.5" /> Download installer
            </button>
          </div>
        </div>
        <pre className="max-h-72 overflow-auto p-4 text-[11.5px] leading-relaxed text-white/75">
          <code>{pkg.content}</code>
        </pre>
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <div className="text-[11px] font-bold uppercase tracking-wide text-white/45">Integrity</div>
          <dl className="mt-2 space-y-2 text-[11px]">
            <div>
              <dt className="text-white/40">Installer SHA-256 (server)</dt>
              <dd className="break-all font-mono text-white/75">{pkg.installerSha256}</dd>
            </div>
            <div>
              <dt className="text-white/40">Installer SHA-256 (this browser)</dt>
              <dd className="break-all font-mono text-white/75">{localDigest || 'computing…'}</dd>
            </div>
            <div>
              <dt className="text-white/40">Runtime SHA-256 (verified by the installer)</dt>
              <dd className="break-all font-mono text-white/75">{pkg.runtime.sha256}</dd>
            </div>
          </dl>
          {digestMatches === true ? (
            <div className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-emerald-400/25 bg-emerald-400/10 px-2.5 py-1 text-[11px] font-bold text-emerald-200">
              <CheckCircle2 className="h-3.5 w-3.5" /> Digest matches — artifact intact in transit
            </div>
          ) : digestMatches === false ? (
            <div className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-rose-400/30 bg-rose-400/10 px-2.5 py-1 text-[11px] font-bold text-rose-200">
              <AlertTriangle className="h-3.5 w-3.5" /> Digest mismatch — do not run this file. Regenerate it.
            </div>
          ) : null}
        </div>

        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <div className="text-[11px] font-bold uppercase tracking-wide text-white/45">Run it</div>
          <div className="mt-2 rounded-lg border border-white/10 bg-black/50 px-3 py-2">
            <code className="break-all font-mono text-[11px] text-cyan-200">{pkg.instructions.runCommand}</code>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <CopyButton value={pkg.instructions.runCommand} label="Copy command" />
            <span className="text-[11px] text-white/40">{pkg.instructions.privileges}</span>
          </div>
          <dl className="mt-3 space-y-1.5 text-[11px]">
            <div className="flex justify-between gap-3">
              <dt className="text-white/40">Runtime version</dt>
              <dd className="font-mono text-white/70">{pkg.runtime.version}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-white/40">Runtime size</dt>
              <dd className="font-mono text-white/70">{fmtBytes(pkg.runtime.bytes)}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-white/40">Requires</dt>
              <dd className="font-mono text-white/70">Node {pkg.runtime.requiresNode}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-white/40">Service</dt>
              <dd className="text-right text-white/70">{pkg.instructions.service}</dd>
            </div>
          </dl>
        </div>
      </div>

      <div className="rounded-xl border border-amber-400/20 bg-amber-400/[0.04] px-4 py-3 text-[11px] leading-relaxed text-amber-100/75">
        This file contains a live enrollment credential. Transfer it over a trusted channel, keep it out of source control, and
        delete it from the host once the agent is installed. {downloaded ? 'Saved to your downloads folder.' : ''}
      </div>
    </div>
  );
}

function VerifyPanel({
  installer,
  agentId,
  createdAgent,
  onOpenAgent,
}: {
  installer: Installer;
  agentId: string | null;
  createdAgent: Installer['agents'][number] | null;
  onOpenAgent: (agentId: string) => void;
}) {
  const [activity, setActivity] = useState<Array<{ id: string; at: string; status: string; phase: string | null; message: string | null }>>([]);

  useEffect(() => {
    if (!agentId) return;
    let cancelled = false;
    const load = async () => {
      const result = await installer.loadActivity(agentId);
      if (!cancelled && result.ok && result.data) setActivity(result.data.activity);
    };
    void load();
    const timer = setInterval(() => void load(), 5000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [agentId, installer]);

  const phaseSeen = useMemo(() => {
    const seen = new Set<string>();
    for (const entry of activity) {
      if (entry.status?.startsWith('install:')) seen.add(entry.status.slice('install:'.length));
      if (entry.phase) seen.add(entry.phase);
    }
    if (createdAgent?.last_seen_at) {
      seen.add('enrolled');
      seen.add('connected');
    }
    return seen;
  }, [activity, createdAgent]);

  const connection = createdAgent?.connectionState || 'Waiting';
  const scan = agentId ? installer.scanProgress[agentId] : undefined;

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-sm font-black text-white">{createdAgent?.name || 'Agent'}</div>
            <div className="mt-0.5 font-mono text-[11px] text-white/40">{agentId}</div>
          </div>
          <StatusChip state={connection} />
        </div>

        <ol className="mt-4 space-y-1.5">
          {INSTALL_PHASES.map((phase) => {
            const done = phaseSeen.has(phase.id);
            return (
              <li key={phase.id} className="flex items-center gap-2.5 text-xs">
                {done ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
                ) : (
                  <span className="h-4 w-4 shrink-0 rounded-full border border-white/15" />
                )}
                <span className={done ? 'text-white/80' : 'text-white/35'}>{phase.label}</span>
              </li>
            );
          })}
        </ol>

        {connection !== 'Connected' ? (
          <p className="mt-4 rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-[11px] leading-relaxed text-white/50">
            Waiting for the first heartbeat. Run the installer on the target host — it reports each phase here as it goes. This
            panel updates live; nothing needs to be refreshed.
          </p>
        ) : null}
      </div>

      {scan ? (
        <div className="rounded-xl border border-cyan-400/25 bg-cyan-400/[0.05] p-4">
          <div className="flex items-center justify-between gap-3">
            <span className="text-xs font-bold text-cyan-100">{scan.message || scan.stage}</span>
            <span className="font-mono text-xs text-cyan-200">{scan.progress}%</span>
          </div>
          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/10">
            <div className="h-full rounded-full bg-cyan-400 transition-all duration-500" style={{ width: `${scan.progress}%` }} />
          </div>
        </div>
      ) : null}

      <div className="rounded-xl border border-white/10 bg-black/30 p-4">
        <div className="text-[11px] font-bold uppercase tracking-wide text-white/45">Activity</div>
        {activity.length === 0 ? (
          <p className="mt-2 text-[11px] text-white/35">No activity recorded for this agent yet.</p>
        ) : (
          <ul className="mt-2 max-h-56 space-y-1.5 overflow-auto">
            {activity.slice(0, 30).map((entry) => (
              <li key={entry.id} className="flex items-start gap-3 text-[11px]">
                <span className="shrink-0 font-mono text-white/35">{relTime(entry.at)}</span>
                <span className="text-white/65">{entry.message || entry.phase || entry.status}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <span className="text-[11px] text-white/40">
          {connection === 'Connected'
            ? 'The agent is connected. Run its first scan from the agent detail view.'
            : 'You can close this wizard — installation continues and the agent appears in the table below.'}
        </span>
        {agentId ? (
          <button
            type="button"
            onClick={() => onOpenAgent(agentId)}
            className="inline-flex items-center gap-2 rounded-xl border border-cyan-400/40 bg-cyan-400/10 px-4 py-2.5 text-sm font-bold text-cyan-100 transition hover:bg-cyan-400/20"
          >
            Open agent <ArrowRight className="h-4 w-4" />
          </button>
        ) : null}
      </div>
    </div>
  );
}
