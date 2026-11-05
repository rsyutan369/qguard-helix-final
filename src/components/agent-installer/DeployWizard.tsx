import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Download,
  FileTerminal,
  KeyRound,
  Loader2,
  Lock,
  Radar,
  RefreshCw,
  ScanSearch,
  ShieldCheck,
  Sparkles,
  Workflow,
  Wrench,
  type LucideIcon,
} from 'lucide-react';
import {
  AGENT_ROLES,
  INSTALL_PHASES,
  type AgentPlatform,
  type AgentRole,
} from '@/lib/agent-installer/agent-release';
import {
  AGENT_SCAN_PRESETS,
  matchScanPreset,
  planAgentScope,
  presetForLocalProfile,
  resolveScanPreset,
} from '@/lib/agent-installer/agent-scope';
import {
  digestOfPackage,
  downloadGeneratedPackage,
  type CreateAgentInput,
  type EnrolledAgentRecord,
  type GeneratedPackage,
  type useAgentInstaller,
} from '@/hooks/use-agent-installer';
import { agentRolePlanCopy, useAgentEntitlement } from '@/hooks/use-agent-entitlement';
import { CopyButton, StatusChip, fmtBytes, relTime } from './primitives';
import { installationAttention } from '@/lib/agent-installer/installation-status';
import {
  AppliedConfigurationCheck,
  ModuleScopeGrid,
  PathPreviewList,
  ScanPresetRail,
  ScopeContractPanel,
  TargetPreviewList,
  WriteAuthorityBadges,
  type RequestedConfiguration,
} from './ScopeContract';

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

/**
 * How each agent type is presented at the choice. The authority statements
 * restate what the control plane enforces — role ceiling, write authority,
 * approval gates — so the card never promises more than the server allows.
 */
const ROLE_PRESENTATION: Record<AgentRole, { icon: LucideIcon; bestFor: string; does: string[]; never: string[] }> = {
  collector: {
    icon: Radar,
    bestFor: 'Continuous cryptographic inventory and CBOM evidence',
    does: ['Inventories TLS, certificates, keys, SSH, configs and dependencies in scope', 'Observes runtime crypto on its own host'],
    never: ['Writes to the host'],
  },
  scanner: {
    icon: ScanSearch,
    bestFor: 'Targeted quantum-vulnerability assessment',
    does: ['Probes endpoints and reads files in scope', 'Classifies against FIPS 203 / 204 / 205'],
    never: ['Runs process or certificate-store collectors', 'Writes to the host'],
  },
  patcher: {
    icon: Wrench,
    bestFor: 'Approved PQC configuration remediation',
    does: ['Applies approved changes inside allowed paths only', 'Snapshots first, validates after, rolls back on failure'],
    never: ['Writes unless you authorise it below', 'Executes Live Migration cutovers'],
  },
  operator: {
    icon: Workflow,
    bestFor: 'Executing approved Live Migration cutovers',
    does: ['Claims approved migration jobs matching its asset and scope', 'Everything an authorised Patcher can do'],
    never: ['Claims unapproved or simulated jobs', 'Writes unless you authorise it below'],
  },
};

export interface DeployWizardInitial {
  /** Pre-selected agent type (still subject to the plan). */
  role?: AgentRole | null;
  /** Where the operator came from, e.g. `local-assessment`. */
  source?: string | null;
  /** Local assessment scan profile id, mapped to an agent scan preset. */
  localProfile?: string | null;
}

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
  initial,
}: {
  installer: Installer;
  onClose: () => void;
  onOpenAgent: (agentId: string) => void;
  initial?: DeployWizardInitial;
}) {
  const [step, setStep] = useState<StepIndex>(0);
  const [reached, setReached] = useState(0);

  /* Which roles this tenant's plan includes. Read here rather than passed in,
     so every mount of the wizard gets the same answer without each caller
     having to remember to thread it through. */
  const entitlement = useAgentEntitlement();
  const fromLocalAssessment = initial?.source === 'local-assessment';
  const [role, setRole] = useState<AgentRole>(initial?.role || 'collector');
  /* The Local assessment profile the operator already chose becomes the
     starting scan preset; the preset is re-resolved for each role and plan. */
  const carriedPreset = presetForLocalProfile(initial?.localProfile);
  const [presetId, setPresetId] = useState<string>(carriedPreset || 'role-default');
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
  /* What was requested and what the control plane stored, side by side on the
     Enrollment step — the proof that every selection was applied. */
  const [requestedConfig, setRequestedConfig] = useState<RequestedConfiguration | null>(null);
  const [storedAgent, setStoredAgent] = useState<EnrolledAgentRecord | null>(null);
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

  const planPermitted = entitlement.scanTypes.length ? entitlement.scanTypes : null;

  // Selecting a role re-resolves the chosen preset for THAT role — a Scanner
  // must not silently inherit an Operator's module list — narrowed to what the
  // PLAN includes, so the wizard never offers a scope the API will strip out.
  // A hand-built (custom) selection falls back to the role's default.
  useEffect(() => {
    setScanTypes(resolveScanPreset(presetId === 'custom' ? 'role-default' : presetId, roleDefinition.id, planPermitted).modules);
    if (!roleDefinition.mutatesTargets) {
      setRemediationAuthorized(false);
      setMigrationAuthorized(false);
    }
    if (roleDefinition.id !== 'operator') setMigrationAuthorized(false);
    // presetId is deliberately absent: choosing a preset applies it directly.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [roleDefinition, entitlement.scanTypes]);

  const applyPreset = useCallback(
    (id: string) => {
      setPresetId(id);
      setScanTypes(resolveScanPreset(id, roleDefinition.id, planPermitted).modules);
    },
    [roleDefinition.id, planPermitted],
  );

  /* A requested type the plan does not include is refused visibly, not
     swapped silently — the fallback below picks a type the plan does include,
     and this says why. */
  const initialRoleRefused = useRef(false);
  useEffect(() => {
    if (entitlement.loading || initialRoleRefused.current || !initial?.role) return;
    initialRoleRefused.current = true;
    const access = entitlement.byRole[initial.role];
    if (access && !access.allowed) {
      setMessage(`${access.message} ${agentRolePlanCopy(initial.role)}. Choose an agent type your plan includes.`);
    }
  }, [entitlement.loading, entitlement.byRole, initial?.role]);

  /* A role the plan no longer includes must not stay selected — for instance
     when a Pro subscription lapses while the wizard is open. Falls back to the
     first role this plan does include rather than to a hard-coded 'collector',
     so a tenant with an unusual entitlement still lands somewhere valid. */
  useEffect(() => {
    if (entitlement.loading) return;
    if (entitlement.roles.includes(role)) return;
    const fallback = entitlement.roles[0];
    if (fallback) setRole(fallback);
  }, [entitlement.loading, entitlement.roles, role]);

  const go = useCallback((next: StepIndex) => {
    setStep(next);
    setReached((prev) => Math.max(prev, next));
    setMessage(null);
  }, []);

  const toggleScanType = (id: string) => {
    setPresetId('custom');
    setScanTypes((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));
  };

  const parsedTargets = useMemo(
    () => [...new Set(targetsText.split(/[\n,]/).map((item) => item.trim()).filter(Boolean))],
    [targetsText],
  );
  const parsedPaths = useMemo(
    () => [...new Set(pathsText.split(/\n/).map((item) => item.trim()).filter(Boolean))],
    [pathsText],
  );

  /* The scope contract — the same pure function the drawer runs over the
     persisted policy, re-evaluated on every keystroke here. */
  const scopePlan = useMemo(
    () =>
      planAgentScope({
        role,
        scanTypes,
        allowedTargets: parsedTargets,
        allowedPaths: parsedPaths,
        planPermitted,
        remediationAuthorized,
        migrationAuthorized,
      }),
    [role, scanTypes, parsedTargets, parsedPaths, planPermitted, remediationAuthorized, migrationAuthorized],
  );
  const shownPreset = presetId === 'custom' ? matchScanPreset(scanTypes, role, planPermitted) : presetId;
  const carriedLabel = carriedPreset && shownPreset === carriedPreset && initial?.localProfile
    ? initial.localProfile.replace(/-/g, ' ')
    : null;

  const canCreate = name.trim().length >= 2 && scanTypes.length > 0 && scopePlan.blockers.length === 0;

  const handleCreate = useCallback(async () => {
    setWorking(true);
    setMessage(null);
    const requested: RequestedConfiguration = {
      role,
      scanTypes: [...scanTypes],
      allowedTargets: parsedTargets,
      allowedPaths: parsedPaths,
      intervalSeconds,
      alertThreshold,
      remediationAuthorized: scopePlan.authority.remediation,
      migrationAuthorized: scopePlan.authority.migration,
      assetId,
      assetName: assetName.trim() || null,
    };
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
      remediationAuthorized: scopePlan.authority.remediation,
      migrationAuthorized: scopePlan.authority.migration,
      source: fromLocalAssessment ? 'local-assessment' : 'agent-center',
      scanPreset: shownPreset,
    };
    const result = await installer.createAgent(input);
    setWorking(false);
    if (!result.ok || !result.data?.agentId) {
      setMessage(result.message || 'Agent creation failed.');
      return;
    }
    setAgentId(result.data.agentId);
    setRequestedConfig(requested);
    setStoredAgent(result.data.agent);
    go(4);
  }, [
    installer, name, role, environment, description, assetName, assetId, parsedTargets, parsedPaths,
    scanTypes, intervalSeconds, alertThreshold, scopePlan.authority, fromLocalAssessment, shownPreset, go,
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
    <div className="ac-surface rounded-2xl border border-cyan-400/20 bg-gradient-to-b from-cyan-400/[0.04] to-transparent">
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
            {fromLocalAssessment ? (
              <div className="flex flex-wrap items-start gap-3 rounded-xl border border-violet-400/25 bg-violet-400/[0.06] px-4 py-3">
                <Cpu aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-violet-200" />
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-black text-violet-50">Continuing from Local Assessment</div>
                  <p className="mt-1 text-[11.5px] leading-relaxed text-violet-100/70">
                    The browser assessment reads one folder you pick, once. A Local Agent runs on the host itself — on a
                    schedule — and reaches what the browser cannot: the system certificate store, running processes, live
                    TLS and SSH endpoints and protected configuration paths. Choose the agent type for this host.
                    {carriedPreset ? ' Your assessment profile has been carried over as the starting scan preset.' : ''}
                  </p>
                </div>
              </div>
            ) : null}

            {/* Roles are shown in FULL, with the ones this plan does not include
                marked and unselectable. Hiding them would make the wizard
                silently shorter on Basic, which reads as a missing feature
                rather than a plan boundary and teaches the operator nothing
                about what Pro adds. */}
            <div className="grid gap-3 sm:grid-cols-2" role="radiogroup" aria-label="Agent type">
              {AGENT_ROLES.map((item) => {
                const roleAccess = entitlement.byRole[item.id];
                const locked = !entitlement.loading && roleAccess && !roleAccess.allowed;
                const presentation = ROLE_PRESENTATION[item.id];
                const RoleIcon = presentation.icon;
                const selected = role === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    role="radio"
                    aria-checked={selected}
                    disabled={Boolean(locked)}
                    aria-disabled={Boolean(locked)}
                    title={locked ? roleAccess.message : item.tagline}
                    onClick={() => !locked && setRole(item.id)}
                    className={`rounded-xl border p-4 text-left transition ${
                      locked
                        ? 'cursor-not-allowed border-white/[0.07] bg-white/[0.01] opacity-60'
                        : selected
                          ? 'border-cyan-400/45 bg-cyan-400/[0.07] shadow-[0_0_0_1px_rgba(34,211,238,0.15)]'
                          : 'border-white/10 bg-white/[0.02] hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className="flex min-w-0 items-center gap-2.5">
                        <span
                          className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg border ${
                            selected ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200' : 'border-white/10 bg-white/[0.03] text-white/55'
                          }`}
                        >
                          <RoleIcon aria-hidden className="h-4 w-4" />
                        </span>
                        <span className="min-w-0">
                          <span className="flex items-center gap-1.5 text-sm font-black text-white">
                            {item.label}
                            {locked ? <Lock aria-hidden className="h-3 w-3 text-amber-300/80" /> : null}
                          </span>
                          <span className="block truncate text-[11px] text-white/40">{presentation.bestFor}</span>
                        </span>
                      </span>
                      <span className="flex shrink-0 flex-col items-end gap-1">
                        {item.mutatesTargets ? (
                          <span className="rounded-full border border-amber-400/30 bg-amber-400/10 px-2 py-0.5 text-[10px] font-black uppercase text-amber-200">
                            Can change config
                          </span>
                        ) : (
                          <span className="rounded-full border border-emerald-400/25 bg-emerald-400/10 px-2 py-0.5 text-[10px] font-black uppercase text-emerald-200">
                            Read-only
                          </span>
                        )}
                        {fromLocalAssessment && item.id === 'collector' ? (
                          <span className="rounded-full border border-violet-400/30 bg-violet-400/10 px-2 py-0.5 text-[10px] font-black uppercase text-violet-200">
                            Recommended
                          </span>
                        ) : null}
                      </span>
                    </div>
                    <p className="mt-2 text-xs leading-relaxed text-white/55">{item.tagline}</p>
                    <ul className="mt-2 space-y-0.5">
                      {presentation.does.map((line) => (
                        <li key={line} className="flex gap-1.5 text-[11px] leading-snug text-white/55">
                          <CheckCircle2 aria-hidden className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400/80" />
                          {line}
                        </li>
                      ))}
                      {presentation.never.map((line) => (
                        <li key={line} className="flex gap-1.5 text-[11px] leading-snug text-white/40">
                          <span aria-hidden className="mt-[3px] grid h-2.5 w-2.5 shrink-0 place-items-center rounded-full border border-white/25 text-[7px] leading-none">×</span>
                          Never: {line.charAt(0).toLowerCase() + line.slice(1)}
                        </li>
                      ))}
                    </ul>
                    {locked ? (
                      <p className="mt-2 rounded-lg border border-amber-400/25 bg-amber-400/[0.06] px-2 py-1.5 text-[11px] leading-relaxed text-amber-100/85">
                        {roleAccess.message} {agentRolePlanCopy(item.id)}.
                      </p>
                    ) : null}
                  </button>
                );
              })}
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
                    ? 'The agent will use one device profile for its machine. Its certificates, components and findings will appear inside that profile.'
                    : "Binds this agent's findings to one of your own assets. Adding a role to a machine that already reports? Select that machine's asset so it stays one device — left unlinked, this agent creates a second profile for the same host. Only your tenant's assets are listed, and the binding is re-verified server-side."
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

            <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,22rem)]">
              <div className="min-w-0 space-y-4">
                <Field label="Allowed targets" hint="One per line or comma separated: host:port, https://host, ssh://host:22. The agent contacts nothing outside this list.">
                  <textarea
                    className={`${inputClass} min-h-[84px] font-mono text-xs`}
                    value={targetsText}
                    onChange={(event) => setTargetsText(event.target.value)}
                    placeholder={'api.example.com:443\nssh://build-01.internal:22'}
                  />
                </Field>
                <TargetPreviewList plan={scopePlan} />

                <Field label="Allowed paths" hint="Absolute paths, one per line. The agent reads configuration and manifests only inside these roots — and a Patcher may only write inside them.">
                  <textarea
                    className={`${inputClass} min-h-[84px] font-mono text-xs`}
                    value={pathsText}
                    onChange={(event) => setPathsText(event.target.value)}
                    placeholder={platform === 'windows' || platform === 'powershell' ? 'C:\\ProgramData\\nginx\\conf\nC:\\inetpub\\app\\config' : '/etc/nginx\n/opt/app/config'}
                  />
                </Field>
                <PathPreviewList plan={scopePlan} />

                <div>
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <span className="text-[11px] font-bold uppercase tracking-wide text-white/50">Scan preset</span>
                    <span className="font-mono text-[10px] text-white/35">
                      {scanTypes.length} module{scanTypes.length === 1 ? '' : 's'} selected
                    </span>
                  </div>
                  <div className="mt-2">
                    <ScanPresetRail current={shownPreset} onSelect={applyPreset} carriedFrom={carriedLabel} />
                  </div>
                </div>

                <div>
                  <span className="text-[11px] font-bold uppercase tracking-wide text-white/50">Scan modules</span>
                  <p className="mt-0.5 text-[11px] text-white/35">
                    Hover a module to see exactly what the agent does with it. Modules outside your plan or this role are shown,
                    not hidden.
                  </p>
                  <div className="mt-2">
                    <ModuleScopeGrid plan={scopePlan} onToggle={toggleScanType} />
                  </div>
                </div>
              </div>

              <div className="min-w-0 xl:sticky xl:top-4 xl:self-start">
                <ScopeContractPanel plan={scopePlan} role={role} />
              </div>
            </div>

            <StepNav
              onBack={() => go(1)}
              onNext={() => go(3)}
              nextDisabled={name.trim().length < 2 || scanTypes.length === 0 || scopePlan.collectsNothing}
            />
            {name.trim().length < 2 ? <p className="text-right text-[11px] text-white/40">Name the agent to continue.</p> : null}
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
                {!assetId ? (
                  <div role="note" className="flex items-start gap-3 rounded-xl border border-amber-400/25 bg-amber-400/[0.05] p-4">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
                    <span className="text-[11px] leading-relaxed text-amber-100/75">
                      <span className="block text-sm font-bold text-amber-100">No assigned asset</span>
                      A {roleDefinition.label} only executes jobs for the asset it is assigned to — a matching file path
                      alone cannot prove which machine a job is for. Without an assignment it gets its own device profile and
                      will decline jobs raised from your other agents' findings on this host.
                      {installer.assets.length > 0
                        ? ' Select the asset your Collector or Scanner reports into above (usually this host\'s device profile).'
                        : ' Once a Collector or Scanner reports from this host, assign this agent to that asset in the Agent Center.'}
                    </span>
                  </div>
                ) : null}
                <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-amber-400/25 bg-amber-400/[0.05] p-4">
                  <input
                    type="checkbox"
                    checked={remediationAuthorized}
                    onChange={(event) => {
                      setRemediationAuthorized(event.target.checked);
                      // A cutover is a configuration change: no remediation, no migration.
                      if (!event.target.checked) setMigrationAuthorized(false);
                    }}
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
                  <label
                    className={`flex items-start gap-3 rounded-xl border border-rose-400/25 bg-rose-400/[0.05] p-4 ${
                      remediationAuthorized ? 'cursor-pointer' : 'cursor-not-allowed opacity-55'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={migrationAuthorized}
                      disabled={!remediationAuthorized}
                      onChange={(event) => setMigrationAuthorized(event.target.checked)}
                      className="mt-0.5 h-4 w-4 accent-rose-400"
                    />
                    <span>
                      <span className="block text-sm font-bold text-rose-100">Authorize Live Migration execution</span>
                      <span className="mt-1 block text-[11px] leading-relaxed text-rose-100/65">
                        The agent may claim approved migration jobs whose target asset, capability, policy and allowed paths all
                        match. It never executes a job merely because one exists.
                        {!remediationAuthorized ? ' Requires configuration remediation above — a cutover is a configuration change.' : ''}
                      </span>
                    </span>
                  </label>
                ) : null}

                <p className="text-[11px] leading-relaxed text-white/40">
                  Leave both unticked and this {roleDefinition.label} is deployed read-only: the control plane hands it no
                  remediation or migration jobs and its installer ships with host writes switched off. You can grant or revoke
                  this later from the agent’s Capabilities tab.
                </p>
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

            {/* ---- Review: exactly what will be created ---- */}
            <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/[0.03]">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/8 px-4 py-2.5">
                <span className="text-[11px] font-black uppercase tracking-[0.14em] text-cyan-100/80">Review before creating</span>
                <WriteAuthorityBadges
                  remediation={scopePlan.authority.remediation}
                  migration={scopePlan.authority.migration}
                  mutates={roleDefinition.mutatesTargets}
                  operator={role === 'operator'}
                />
              </div>
              <dl className="grid gap-x-4 gap-y-2 px-4 py-3 text-[11.5px] sm:grid-cols-2 lg:grid-cols-4">
                {[
                  ['Agent', name.trim() || '—'],
                  ['Type', roleDefinition.label],
                  ['Platform', platformInfo?.label || platform],
                  ['Environment', environment],
                  ['Scan preset', shownPreset === 'custom' ? 'Custom' : AGENT_SCAN_PRESETS.find((preset) => preset.id === shownPreset)?.label || '—'],
                  ['Modules', `${scopePlan.activeModules} active · ${scopePlan.idleModules} idle`],
                  ['Targets', `${scopePlan.tlsTargets} TLS · ${scopePlan.sshTargets} SSH`],
                  ['Paths', String(scopePlan.paths.length)],
                  ['Interval', `${intervalSeconds}s`],
                  ['Alert threshold', alertThreshold],
                  ['Asset', assetName || 'Not linked'],
                ].map(([label, value]) => (
                  <div key={label} className="min-w-0">
                    <dt className="text-[10px] font-bold uppercase tracking-wide text-white/35">{label}</dt>
                    <dd className="truncate font-mono text-white/80">{value}</dd>
                  </div>
                ))}
              </dl>
              <div className="border-t border-white/8 p-3">
                <ScopeContractPanel plan={scopePlan} role={role} compact />
              </div>
            </div>

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
                  <code className="qg-force-dark flex-1 break-all rounded-lg border border-white/12 bg-black/50 px-3 py-2 font-mono text-xs text-emerald-200">
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

            {requestedConfig ? <AppliedConfigurationCheck requested={requestedConfig} agent={storedAgent} /> : null}

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
      <div className="qg-force-dark rounded-xl border border-white/10 bg-black/40">
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
          <div className="qg-force-dark mt-2 rounded-lg border border-white/10 bg-black/50 px-3 py-2">
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
  const [checkedAt, setCheckedAt] = useState(Date.now);

  /* Depends on the loader, never on `installer` itself: the hook returns a new
     object every render and every load toggles its `busy` state, so an effect
     keyed on the object re-ran on its own result — an unbounded request loop
     instead of a 5-second poll. */
  const { loadActivity } = installer;
  useEffect(() => {
    if (!agentId) return;
    let cancelled = false;
    let loading = false;
    const load = async () => {
      if (loading) return;
      loading = true;
      try {
        const result = await loadActivity(agentId);
        if (!cancelled) {
          setCheckedAt(Date.now());
          if (result.ok && result.data) setActivity(result.data.activity);
        }
      } finally {
        loading = false;
      }
    };
    void load();
    const timer = setInterval(() => void load(), 5000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [agentId, loadActivity]);

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
  const attention = installationAttention(activity, connection === 'Connected', checkedAt);
  const scan = agentId ? installer.scanProgress[agentId] : undefined;

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-sm font-black text-white">{createdAgent?.name || 'Agent'}</div>
            <div className="mt-0.5 font-mono text-[11px] text-white/40">{agentId}</div>
          </div>
          {attention ? (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-400/30 bg-amber-400/10 px-2.5 py-0.5 text-[11px] font-bold text-amber-200">
              <AlertTriangle className="h-3.5 w-3.5" />{attention.kind === 'failed' ? 'Verification failed' : 'Needs attention'}
            </span>
          ) : <StatusChip state={connection} />}
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
          <p role={attention ? 'alert' : 'status'} className={`mt-4 rounded-lg border px-3 py-2 text-[11px] leading-relaxed ${attention ? 'border-amber-400/25 bg-amber-400/5 text-amber-100' : 'border-white/10 bg-black/30 text-white/50'}`}>
            {attention?.message || 'Waiting for the first heartbeat. Run the installer on the target host. This panel updates automatically as installation and connection events arrive.'}
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
            : attention ? 'Connection has not been verified. Follow the diagnostics above; you can reopen this agent from the table.'
            : 'You can close this wizard and reopen the agent from the table to check its connection.'}
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
