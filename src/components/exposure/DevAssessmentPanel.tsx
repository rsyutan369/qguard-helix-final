'use client';

/**
 * Dev Assessment Panel (§17-21, §49, §68, §69, Spec-2 §2, §33, §34, §36).
 *
 * The Dev mode surface: provider selection, repository validation and branch
 * selection, connected clusters / cloud accounts / registries with their real
 * verified status, scan profile, engine selection, the live ledger, and the
 * cloud-native posture dashboard.
 *
 * The connector section is where Spec-2 §33/§34 land in the UI: a connection is
 * useless until the operator picks an explicit SCOPE — namespaces for a
 * cluster, regions for a cloud account — and the Start button says so rather
 * than quietly scanning everything.
 */

import React from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  AlertTriangle, Boxes, Check, ChevronDown, Cloud, Container, GitBranch, Github,
  Gitlab, Link2, Loader2, Play, Plus, Search, Server, Settings2, ShieldCheck, X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { ACCENT, Panel, SectionLabel } from '@/components/quantum-scan/ui';
import { useExposureConnections, useExposureScan, type PublicConnectionView } from '@/hooks/use-exposure-scan';
import { defaultExclusions, type ScanExclusions } from '@/lib/scanner/exposure/types';
import { profilesForMode, resolveProfile } from '@/lib/scanner/exposure/profiles';
import { descriptorsForMode } from '@/lib/scanner/exposure/registry';
import {
  AssessmentStatusBar,
  CbomViewer,
  CorrelatedExposures,
  CoveragePanel,
  EngineLedger,
  ExposureRecommendations,
  ExposureScorecard,
  FindingExplorer,
  QuantumExposureSummary,
  ScanEngineSelector,
  ScanProfileRail,
} from './shared';
import { EngineHealthPanel, ScannerIntelligenceSection } from './ScannerIntelligence';
import { ScanTheatre, type TheatreStatus } from './ScanTheatre';
import { ExposureWorkflowGraph } from './ExposureWorkflowGraph';
import { useScannerEngines } from '@/hooks/use-scanner-engines';
import { useExposureAccess } from '@/hooks/use-exposure-access';
import { ModeAccessGate, ModeAccessSkeleton } from './ModeAccessGate';

/* ────────────────────────────────────────────────────────────── providers ─── */

const PROVIDERS: Array<{ id: string; label: string; icon: typeof Github; example: string }> = [
  { id: 'github', label: 'GitHub', icon: Github, example: 'https://github.com/org/repository' },
  { id: 'gitlab', label: 'GitLab', icon: Gitlab, example: 'https://gitlab.com/group/project' },
  { id: 'bitbucket', label: 'Bitbucket', icon: GitBranch, example: 'https://bitbucket.org/workspace/repo' },
  { id: 'azure-devops', label: 'Azure DevOps', icon: GitBranch, example: 'https://dev.azure.com/org/project/_git/repo' },
  { id: 'gitea', label: 'Self-hosted Git', icon: Server, example: 'https://git.example.com/team/service' },
];

/** The Dev scanning categories from Spec-2 §2 — each maps to a real engine. */
const DEV_CATEGORIES: Array<{ id: string; label: string; engineId: string }> = [
  { id: 'repositories', label: 'Repositories', engineId: 'source-crypto' },
  { id: 'dependencies', label: 'Dependencies', engineId: 'dependency-analysis' },
  { id: 'secrets', label: 'Secrets', engineId: 'secret-discovery' },
  { id: 'cicd', label: 'CI/CD', engineId: 'cicd-security' },
  { id: 'containers', label: 'Containers', engineId: 'container-security' },
  { id: 'kubernetes', label: 'Kubernetes', engineId: 'kubernetes-security' },
  { id: 'cloud', label: 'Cloud', engineId: 'cloud-crypto' },
  { id: 'iac', label: 'IaC', engineId: 'iac-security' },
  { id: 'crypto', label: 'Crypto', engineId: 'source-crypto' },
  { id: 'cbom', label: 'SBOM/CBOM', engineId: 'cbom-generator' },
  { id: 'supply-chain', label: 'Supply Chain', engineId: 'supply-chain' },
  { id: 'quantum', label: 'Quantum', engineId: 'quantum-assessment' },
];

export interface DevAssessmentPanelProps {
  /** True when the visitor is signed in; gates the connector section. */
  authenticated?: boolean;
  upsellSlot?: React.ReactNode;
  onSync?: (scanId: string) => Promise<void>;
}

export function DevAssessmentPanel({ authenticated = false, upsellSlot, onSync }: DevAssessmentPanelProps) {
  /* Entitlement is resolved INSIDE the panel rather than by each page that
     mounts it, so /public-scan and /dashboard/scanner cannot drift apart on who
     may scan. Dev sits a tier above Local because it executes server-side and
     holds connector credentials. */
  const access = useExposureAccess('dev');
  const scan = useExposureScan();
  const { connections, notice: connectionNotice, refresh } = useExposureConnections();

  const [provider, setProvider] = React.useState('github');
  const [repositoryUrl, setRepositoryUrl] = React.useState('');
  const [branch, setBranch] = React.useState('');
  const [profileId, setProfileId] = React.useState('standard');
  const [customEngines, setCustomEngines] = React.useState<Set<string>>(new Set());
  const [exclusions, setExclusions] = React.useState<ScanExclusions>(defaultExclusions);
  const [showAdvanced, setShowAdvanced] = React.useState(false);
  const [selectedConnections, setSelectedConnections] = React.useState<Set<string>>(new Set());
  const [namespaces, setNamespaces] = React.useState<Set<string>>(new Set());
  const [regions, setRegions] = React.useState<Set<string>>(new Set());
  const [showConnect, setShowConnect] = React.useState(false);
  const [syncState, setSyncState] = React.useState<'idle' | 'syncing' | 'synced' | 'error'>('idle');
  /* The live scan theatre is dismissible once the scan settles; a new run
     always brings it back. */
  const [theatreHidden, setTheatreHidden] = React.useState(false);
  const theatreRef = React.useRef<HTMLDivElement>(null);
  const resultsRef = React.useRef<HTMLDivElement>(null);

  const profiles = React.useMemo(() => profilesForMode('dev'), []);
  const registry = useScannerEngines('dev');
  const engines = React.useMemo(() => descriptorsForMode('dev'), []);
  const resolvedEngines = React.useMemo(
    () => resolveProfile('dev', profileId, [...customEngines]).engines,
    [profileId, customEngines],
  );

  const busy = scan.state === 'starting' || scan.state === 'scanning';
  const validation = scan.validation;
  const canStart = Boolean(repositoryUrl.trim()) || selectedConnections.size > 0;

  /* ── live scan theatre (§ Scanning UI/UX) ──────────────────────────────
     Driven entirely by the SSE stream: nothing here can move without a real
     frame from the server. */
  const theatreStatus: TheatreStatus | null =
    scan.state === 'starting' ? 'starting'
      : scan.state === 'scanning' ? 'scanning'
        : scan.state === 'complete' ? 'complete'
          : scan.state === 'cancelled' ? 'cancelled'
            : scan.state === 'error' && scan.startedAt !== null ? 'error'
              : null;
  const theatreVisible = theatreStatus !== null && !theatreHidden;

  /* The corpus tile only exists once Repository Discovery has reported real
     unit counts. Before that the theatre says "not measured" rather than
     guessing at a repository it has not finished reading. */
  const corpus = React.useMemo(() => {
    const discovery = scan.runs.find((run) => run.engineId === 'repository-discovery');
    if (!discovery?.units || discovery.units.total <= 0) return null;
    return {
      label: 'Corpus',
      value: `${discovery.units.done.toLocaleString()} / ${discovery.units.total.toLocaleString()}`,
      sublabel: `${discovery.units.unit} collected`,
    };
  }, [scan.runs]);

  const theatreTarget = React.useMemo(() => {
    const repository = repositoryUrl.trim();
    if (repository) {
      const reference = scan.validation?.ref;
      return {
        label: reference ? `${reference.owner}/${reference.repo}` : repository,
        detail: scan.validation?.defaultBranch ? `branch ${branch.trim() || scan.validation.defaultBranch}` : null,
      };
    }
    const chosen = connections.filter((connection) => selectedConnections.has(connection.id));
    if (chosen.length === 1) return { label: chosen[0].label, detail: chosen[0].kind };
    if (chosen.length > 1) return { label: `${chosen.length} connected environments`, detail: null };
    return { label: 'Development target', detail: null };
  }, [repositoryUrl, branch, scan.validation, connections, selectedConnections]);

  React.useEffect(() => {
    if (scan.state !== 'scanning' && scan.state !== 'starting') return;
    setTheatreHidden(false);
    const node = theatreRef.current;
    if (!node) return;
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    node.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
  }, [scan.state]);

  const activeConnections = React.useMemo(
    () => connections.filter((connection) => selectedConnections.has(connection.id)),
    [connections, selectedConnections],
  );
  const clusterSelected = activeConnections.some((connection) => connection.kind === 'kubernetes');
  const cloudSelected = activeConnections.some((connection) => ['aws', 'azure', 'gcp'].includes(connection.kind));
  const scopeMissing = (clusterSelected && namespaces.size === 0) || (cloudSelected && regions.size === 0);

  const handleStart = React.useCallback(() => {
    void scan.start({
      repositoryUrl: repositoryUrl.trim() || undefined,
      branch: branch.trim() || undefined,
      connectionIds: [...selectedConnections],
      namespaces: [...namespaces],
      regions: [...regions],
      profileId,
      customEngines: [...customEngines],
      exclusions,
    });
  }, [scan, repositoryUrl, branch, selectedConnections, namespaces, regions, profileId, customEngines, exclusions]);

  const handleSync = React.useCallback(async () => {
    if (!scan.scanId || !onSync) return;
    setSyncState('syncing');
    try {
      await onSync(scan.scanId);
      setSyncState('synced');
    } catch {
      setSyncState('error');
    }
  }, [scan.scanId, onSync]);

  /* Locked: show the mode in full, minus the controls that would run it.
     Placed after every hook above so the hook order is stable whichever branch
     this takes, and gated on `loading` first so a paying customer never sees
     "upgrade" flash on mount. */
  if (access.loading) return <ModeAccessSkeleton />;
  if (!access.allowed) return <ModeAccessGate mode="dev" access={access} upsellSlot={upsellSlot} />;

  return (
    <div className="space-y-5">
      {/* ── the Dev category strip (Spec-2 §2) ─────────────────────────── */}
      <Panel className="overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
          <SectionLabel>Development Security Assessment</SectionLabel>
          <span className="font-mono text-[10px] text-slate-500">{engines.length} engines available</span>
        </div>
        <div className="flex flex-wrap gap-1.5 px-5 py-3.5">
          {DEV_CATEGORIES.map((category) => {
            const active = resolvedEngines.includes(category.engineId);
            return (
              <span
                key={category.id}
                title={active ? 'This engine is in the selected profile.' : 'Not in the selected profile — switch to Custom to enable it.'}
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[11.5px] font-semibold transition-colors',
                  active ? 'border-cyan-400/30 bg-cyan-400/[0.07] text-cyan-300' : 'border-white/[0.07] text-slate-500',
                )}
              >
                {active && <Check aria-hidden className="h-3 w-3" />}
                {category.label}
              </span>
            );
          })}
        </div>
        <p className="border-t border-white/[0.06] px-5 py-2.5 text-[11px] leading-relaxed text-slate-500">
          These are engines, not filters. Only the ones highlighted will execute, and any that finds nothing to read in the
          target reports <span className="font-mono text-[10.5px]">Not Applicable</span> with the reason.
        </p>
      </Panel>

      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1.45fr)_minmax(0,1fr)]">
        <div className="space-y-5">
          {/* ── repository target (§19, §20) ─────────────────────────────── */}
          <Panel className="overflow-hidden">
            <div className="border-b border-white/[0.06] px-5 py-3">
              <SectionLabel>Repository</SectionLabel>
            </div>

            <div className="px-5 py-4">
              <div className="flex flex-wrap gap-1.5">
                {PROVIDERS.map((entry) => (
                  <button
                    key={entry.id}
                    type="button"
                    onClick={() => setProvider(entry.id)}
                    className={cn(
                      'inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[11.5px] font-bold transition-colors',
                      provider === entry.id
                        ? 'border-cyan-400/30 bg-cyan-400/[0.07] text-cyan-300'
                        : 'border-white/[0.07] text-slate-400 hover:text-slate-200',
                    )}
                  >
                    <entry.icon className="h-3.5 w-3.5" /> {entry.label}
                  </button>
                ))}
              </div>

              <div className="mt-3 flex items-center gap-2 rounded-xl border border-cyan-400/25 bg-[#040810]/85 p-1.5 focus-within:border-cyan-400/55">
                <Link2 aria-hidden className="ml-2.5 h-4 w-4 shrink-0 text-slate-500" />
                <input
                  value={repositoryUrl}
                  onChange={(event) => setRepositoryUrl(event.target.value)}
                  onBlur={() => repositoryUrl.trim() && void scan.validate(repositoryUrl)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter') {
                      event.preventDefault();
                      void scan.validate(repositoryUrl);
                    }
                  }}
                  placeholder={PROVIDERS.find((entry) => entry.id === provider)?.example}
                  aria-label="Repository URL"
                  spellCheck={false}
                  className="min-w-0 flex-1 bg-transparent py-2 text-[13.5px] text-white outline-none placeholder:text-slate-600"
                />
                <button
                  type="button"
                  onClick={() => void scan.validate(repositoryUrl)}
                  disabled={!repositoryUrl.trim() || scan.validating}
                  className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-white/[0.1] px-3 py-2 text-[12px] font-bold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300 disabled:opacity-50"
                >
                  {scan.validating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
                  Validate
                </button>
              </div>

              {/* ── validation result ─────────────────────────────────── */}
              <AnimatePresence>
                {validation && (
                  <motion.div
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    className={cn(
                      'mt-3 rounded-xl border px-4 py-3',
                      validation.ok ? 'border-emerald-400/25 bg-emerald-400/[0.05]' : 'border-amber-400/25 bg-amber-400/[0.05]',
                    )}
                  >
                    {validation.ok ? (
                      <>
                        <p className="flex flex-wrap items-center gap-2 text-[12.5px] font-bold text-emerald-200">
                          <ShieldCheck className="h-4 w-4" />
                          {validation.providerLabel} repository resolved
                          {validation.visibility && (
                            <span className="rounded bg-white/[0.07] px-1.5 py-0.5 font-mono text-[9.5px] uppercase tracking-widest text-slate-300">
                              {validation.visibility}
                            </span>
                          )}
                        </p>
                        <div className="mt-2 flex flex-wrap items-center gap-2">
                          <label className="flex items-center gap-1.5 text-[11.5px] text-slate-400">
                            <GitBranch aria-hidden className="h-3.5 w-3.5" />
                            Branch
                            <input
                              value={branch}
                              onChange={(event) => setBranch(event.target.value)}
                              placeholder={validation.defaultBranch ?? 'main'}
                              className="w-40 rounded border border-white/[0.1] bg-[#050a15] px-2 py-1 font-mono text-[11px] text-slate-200 outline-none focus:border-cyan-400/40"
                            />
                          </label>
                          <span className="font-mono text-[10.5px] text-slate-500">
                            default: {validation.defaultBranch ?? 'unknown'}
                          </span>
                        </div>
                        <p className="mt-2 text-[11px] leading-relaxed text-slate-500">
                          Only this branch is analysed. Other branches, tags and unmerged pull requests are not read, and the
                          coverage panel states that.
                        </p>
                      </>
                    ) : (
                      <>
                        <p className="flex items-center gap-2 text-[12.5px] font-bold text-amber-200">
                          <AlertTriangle className="h-4 w-4" /> {validation.notice ?? 'The repository could not be resolved.'}
                        </p>
                        {validation.recommendation && (
                          <p className="mt-1.5 text-[11.5px] leading-relaxed text-amber-100/80">{validation.recommendation}</p>
                        )}
                        {validation.requiresToken && !authenticated && (
                          <p className="mt-1.5 text-[11.5px] leading-relaxed text-amber-100/80">
                            Private repository assessment requires an account with the provider connected. Public
                            repositories work with no credentials at all.
                          </p>
                        )}
                      </>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </Panel>

          {/* ── connectors (Spec-2 §33, §34) ─────────────────────────────── */}
          <Panel className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
              <SectionLabel accent={ACCENT.violet}>Clusters, Cloud &amp; Registries</SectionLabel>
              {authenticated && (
                <button
                  type="button"
                  onClick={() => setShowConnect((current) => !current)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-2.5 py-1 text-[11px] font-bold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
                >
                  <Plus className="h-3 w-3" /> Connect
                </button>
              )}
            </div>

            {!authenticated ? (
              <div className="px-5 py-6 text-center">
                <Cloud aria-hidden className="mx-auto h-7 w-7 text-slate-700" />
                <p className="mt-2 text-[12.5px] font-bold text-slate-300">Sign in to connect a cluster or cloud account</p>
                <p className="mt-1 text-[11.5px] leading-relaxed text-slate-500">
                  Live Kubernetes, AWS, Azure, Google Cloud and container registry assessments use read-only credentials
                  that belong to your tenant. Public repository assessment needs no account.
                </p>
              </div>
            ) : connections.length === 0 ? (
              <div className="px-5 py-6 text-center">
                <Boxes aria-hidden className="mx-auto h-7 w-7 text-slate-700" />
                <p className="mt-2 text-[12.5px] font-bold text-slate-300">No connections yet</p>
                <p className="mt-1 text-[11.5px] leading-relaxed text-slate-500">
                  Connect a read-only Kubernetes ServiceAccount, cloud principal or registry credential to extend the
                  assessment beyond the repository.
                </p>
              </div>
            ) : (
              <ul className="divide-y divide-white/[0.04]">
                {connections.map((connection) => (
                  <ConnectionRow
                    key={connection.id}
                    connection={connection}
                    selected={selectedConnections.has(connection.id)}
                    onToggle={() => {
                      setSelectedConnections((current) => {
                        const next = new Set(current);
                        if (next.has(connection.id)) next.delete(connection.id);
                        else next.add(connection.id);
                        return next;
                      });
                    }}
                    namespaces={namespaces}
                    onNamespaceToggle={(namespace) => {
                      setNamespaces((current) => {
                        const next = new Set(current);
                        if (next.has(namespace)) next.delete(namespace);
                        else next.add(namespace);
                        return next;
                      });
                    }}
                    regions={regions}
                    onRegionToggle={(region) => {
                      setRegions((current) => {
                        const next = new Set(current);
                        if (next.has(region)) next.delete(region);
                        else next.add(region);
                        return next;
                      });
                    }}
                  />
                ))}
              </ul>
            )}

            {connectionNotice && authenticated && (
              <p className="border-t border-white/[0.06] px-5 py-2.5 text-[11px] leading-relaxed text-slate-500">
                {connectionNotice}
              </p>
            )}

            <AnimatePresence>
              {showConnect && authenticated && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="overflow-hidden border-t border-white/[0.06]"
                >
                  <ConnectionForm
                    onClose={() => setShowConnect(false)}
                    onCreated={() => {
                      setShowConnect(false);
                      void refresh();
                    }}
                  />
                </motion.div>
              )}
            </AnimatePresence>
          </Panel>
        </div>

        {/* ── rail ─────────────────────────────────────────────────────── */}
        <div className="space-y-5">
          {scan.runs.length > 0 ? (
            <EngineLedger
              runs={scan.runs}
              progress={scan.progress}
              status={busy ? 'scanning' : 'idle'}
              currentStep={scan.currentStep}
              onCancel={() => void scan.cancel()}
            />
          ) : (
            <DevEmptyRail />
          )}
          <EngineHealthPanel engines={registry.engines} knowledgeBase={registry.knowledgeBase} />
          {upsellSlot}
        </div>
      </div>

      {/* ── profile + launch ───────────────────────────────────────────────
           Full width, deliberately. Twelve profiles stacked two-across inside
           the configuration column pushed the start button far below the fold,
           so choosing a profile and running it became two separate journeys.
           Across the whole page they are one band: pick, read, launch. */}
      <Panel className="overflow-hidden" glow={!busy && canStart && !scopeMissing}>
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
          <SectionLabel>Scan Profile</SectionLabel>
          <span className="font-mono text-[10px] text-slate-500">
            {profiles.length} profiles · {engines.length} engines available
          </span>
        </div>
        <div className="px-5 py-4">
          <ScanProfileRail
            profiles={profiles}
            value={profileId}
            onChange={setProfileId}
            disabledIds={authenticated ? undefined : new Set(profiles.filter((entry) => entry.minTier).map((entry) => entry.id))}
            engineCount={resolvedEngines.length}
            launchSlot={
              <div className="flex h-full flex-col justify-center rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-3.5">
                <button
                  type="button"
                  disabled={busy || !canStart || scopeMissing}
                  onClick={handleStart}
                  className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-500 px-4 py-3 text-[13.5px] font-black leading-tight text-[#04060e] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {busy ? (
                    <>
                      <Loader2 className="h-4 w-4 shrink-0 animate-spin" /> Assessing {scan.progress}%
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4 shrink-0" /> Start development assessment
                    </>
                  )}
                </button>
                {scopeMissing ? (
                  <p className="mt-2 text-center text-[11px] leading-snug text-amber-300/85">
                    {clusterSelected && namespaces.size === 0
                      ? 'Select at least one namespace — this scanner never enumerates a whole cluster implicitly.'
                      : 'Select at least one region — this scanner never enumerates a whole account implicitly.'}
                  </p>
                ) : !canStart ? (
                  <p className="mt-2 text-center font-mono text-[10px] uppercase tracking-[0.14em] text-slate-600">
                    Enter a repository URL or select a connection
                  </p>
                ) : (
                  <p className="mt-2 truncate text-center font-mono text-[10px] uppercase tracking-[0.14em] text-slate-600">
                    {theatreTarget.label}
                  </p>
                )}
              </div>
            }
          />
        </div>

        <div className="border-t border-white/[0.06]">
          <button
            type="button"
            onClick={() => setShowAdvanced((current) => !current)}
            aria-expanded={showAdvanced}
            className="flex w-full items-center justify-between gap-2 px-5 py-3 text-left transition-colors hover:bg-white/[0.02]"
          >
            <span className="flex items-center gap-2 text-[12.5px] font-bold text-slate-300">
              <Settings2 className="h-3.5 w-3.5" /> Engines and exclusions
            </span>
            <ChevronDown className={cn('h-4 w-4 text-slate-500 transition-transform', showAdvanced && 'rotate-180')} />
          </button>
          <AnimatePresence initial={false}>
            {showAdvanced && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.28 }}
                className="overflow-hidden"
              >
                <div className="px-5 pb-5">
                  <ScanEngineSelector
                    engines={engines}
                    selected={profileId === 'custom' ? customEngines : new Set(resolvedEngines)}
                    onToggle={(id) => {
                      setProfileId('custom');
                      setCustomEngines((current) => {
                        const next = new Set(current.size ? current : resolvedEngines);
                        if (next.has(id)) next.delete(id);
                        else next.add(id);
                        return next;
                      });
                    }}
                  />
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </Panel>

      {/* ── live scan theatre ──────────────────────────────────────────────
           Directly below the repository and configuration surface, so the run
           the operator just started is the next thing they see. */}
      {theatreVisible && theatreStatus && (
        <div ref={theatreRef} className="scroll-mt-24">
          <ScanTheatre
            mode="dev"
            status={theatreStatus}
            progress={scan.progress}
            runs={scan.runs}
            findings={scan.findings}
            telemetry={scan.telemetry}
            currentStep={scan.currentStep}
            startedAt={scan.startedAt}
            streamOpen={scan.streamOpen}
            target={{ label: theatreTarget.label, detail: theatreTarget.detail }}
            /* Dev learns its corpus size only once the repository resolves, so
               the tile stays honest about not knowing until it does. */
            volume={corpus}
            assessment={scan.assessment}
            knowledgeBase={registry.knowledgeBase}
            engineHealth={registry.engines}
            error={scan.error ? [scan.error, scan.errorDetail].filter(Boolean).join(' — ') : null}
            onCancel={() => void scan.cancel()}
            onViewAll={() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
            onDismiss={() => setTheatreHidden(true)}
          />
        </div>
      )}

      {scan.error && !theatreVisible && (
        <div className="flex items-start gap-3 rounded-xl border border-rose-400/25 bg-rose-500/[0.07] px-4 py-3">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
          <div>
            <p className="text-[12.5px] leading-relaxed text-rose-100/85">{scan.error}</p>
            {scan.errorDetail && <p className="mt-1 text-[11.5px] leading-relaxed text-rose-100/65">{scan.errorDetail}</p>}
          </div>
        </div>
      )}

      {scan.assessment && (
        <div ref={resultsRef} className="space-y-5 scroll-mt-24">
          <AssessmentStatusBar
            assessment={scan.assessment}
            onReset={scan.reset}
            onSync={authenticated && onSync ? handleSync : undefined}
            syncState={syncState}
            extra={
              scan.scanId ? (
                <a
                  href={`/api/v1/exposure/scans/${encodeURIComponent(scan.scanId)}/cbom?format=cyclonedx`}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11.5px] font-semibold text-slate-300 no-underline transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
                >
                  CycloneDX CBOM
                </a>
              ) : null
            }
          />
          <DevPostureDashboard assessment={scan.assessment} />
          <ExposureScorecard assessment={scan.assessment} />
          <QuantumExposureSummary assessment={scan.assessment} />
          <ScannerIntelligenceSection assessment={scan.assessment} synced={syncState === 'synced'} />
          <CorrelatedExposures exposures={scan.assessment.exposures} />
          <FindingExplorer assessment={scan.assessment} />
          {/* The findings table says WHAT was found; the workflow map says how
              the assessment reached it and what each finding is connected to.
              Dev mode carries the connector engines too, so the process tree
              here spans repository, container, cluster and cloud acquisition. */}
          <ExposureWorkflowGraph assessment={scan.assessment} mode="dev" />
          <ExposureRecommendations assessment={scan.assessment} />
          <CbomViewer
            components={scan.assessment.cbom}
            onExport={(format) => {
              if (!scan.scanId) return;
              window.open(`/api/v1/exposure/scans/${encodeURIComponent(scan.scanId)}/cbom?format=${format}`, '_blank');
            }}
          />
          <CoveragePanel coverage={scan.assessment.task.coverage} mode="dev" />
        </div>
      )}

      {!scan.assessment && scan.state === 'idle' && <DevEmptyState />}
    </div>
  );
}

/* ────────────────────────────────────────────────────── posture dashboard ─── */

/** Spec-2 §36. Every number here is a count from the completed assessment. */
function DevPostureDashboard({ assessment }: { assessment: NonNullable<ReturnType<typeof useExposureScan>['assessment']> }) {
  const { coverage } = assessment.task;
  const { intelligence } = assessment;

  /* Every tile names its UNIT, because this strip mixes three of them: the
     estate the scan read, the cryptographic components it inventoried, and the
     findings it raised. Read side by side without labels, "Quantum vulnerable
     6" (components) beside "Critical findings 1" (findings) invites the reader
     to treat them as one series. */
  const tiles: Array<{ label: string; unit: string; value: number; accent?: string; engineId?: string }> = [
    { label: 'Repositories', unit: 'in scope', value: coverage.repositories || (assessment.task.target.kind === 'repository' ? 1 : 0) },
    { label: 'Files analysed', unit: `of ${coverage.filesDiscovered.toLocaleString()} discovered`, value: coverage.filesAnalyzed },
    { label: 'Dependencies', unit: 'resolved', value: coverage.dependencies, engineId: 'dependency-analysis' },
    { label: 'Containers', unit: 'definitions read', value: coverage.containers, engineId: 'container-security' },
    { label: 'Images', unit: 'inspected', value: coverage.images, engineId: 'registry-scan' },
    { label: 'K8s workloads', unit: 'read', value: coverage.kubernetesWorkloads, engineId: 'kubernetes-security' },
    { label: 'Cloud resources', unit: 'enumerated', value: coverage.cloudResources, engineId: 'cloud-inventory' },
    { label: 'Crypto components', unit: 'in the CBOM', value: assessment.cbom.length, engineId: 'cbom-generator' },
    { label: 'Quantum vulnerable', unit: 'components', value: intelligence.quantum.vulnerable, accent: ACCENT.rose, engineId: 'quantum-assessment' },
    { label: 'Secrets', unit: 'findings', value: intelligence.secrets.length, accent: ACCENT.amber, engineId: 'secret-discovery' },
    { label: 'Critical findings', unit: 'findings', value: intelligence.severity.critical, accent: ACCENT.rose },
    { label: 'High findings', unit: 'findings', value: intelligence.severity.high, accent: '#fb923c' },
  ];

  /* A dimension whose engine never reported is NOT zero — it is unmeasured, and
     the two must stay distinguishable (§43). Hiding both behind `value > 0`
     made "no containers in this repository" and "the container engine never
     ran" render identically: as absence. */
  const measured = new Set(
    assessment.task.runs
      .filter((run) => run.state === 'completed' || run.state === 'not-applicable')
      .map((run) => run.engineId),
  );
  const visible = tiles.filter((tile) => tile.value > 0 || !tile.engineId || measured.has(tile.engineId));
  const unmeasured = tiles.filter((tile) => tile.value === 0 && tile.engineId && !measured.has(tile.engineId));

  if (visible.length === 0 && unmeasured.length === 0) return null;

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
        <SectionLabel>Dev Security Posture</SectionLabel>
        <span className="font-mono text-[10px] text-slate-500">Across this assessment</span>
      </div>
      <div className="grid grid-cols-2 gap-px bg-white/[0.05] sm:grid-cols-3 lg:grid-cols-6">
        {visible.map((tile) => (
          <div key={tile.label} className="bg-[#080d1a] px-4 py-3.5">
            <p className="font-mono text-[9px] font-bold uppercase tracking-[0.14em] text-slate-500">{tile.label}</p>
            <p className="mt-1 font-mono text-[20px] font-black leading-none" style={{ color: tile.accent ?? '#e2e8f0' }}>
              {tile.value.toLocaleString()}
            </p>
            <p className="mt-1 font-mono text-[9px] uppercase tracking-[0.12em] text-slate-600">{tile.unit}</p>
          </div>
        ))}
      </div>

      {unmeasured.length > 0 && (
        <p className="border-t border-amber-400/20 bg-amber-400/[0.05] px-5 py-2.5 text-[11px] leading-relaxed text-amber-100/85">
          Not measured, so not shown as zero:{' '}
          <strong className="font-bold">{unmeasured.map((tile) => tile.label).join(', ')}</strong>. The engine that would
          have read {unmeasured.length === 1 ? 'it' : 'them'} did not reach a reporting state in this run.
        </p>
      )}
      {(intelligence.languages.length > 0 || intelligence.frameworks.length > 0) && (
        <div className="flex flex-wrap gap-4 border-t border-white/[0.06] px-5 py-3">
          {intelligence.languages.length > 0 && (
            <div className="min-w-0">
              <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-slate-500">Languages</p>
              <p className="mt-0.5 text-[11.5px] text-slate-300">
                {intelligence.languages.slice(0, 6).map((entry) => `${entry.language} (${entry.files})`).join(' · ')}
              </p>
            </div>
          )}
          {intelligence.frameworks.length > 0 && (
            <div className="min-w-0">
              <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-slate-500">Frameworks</p>
              <p className="mt-0.5 text-[11.5px] text-slate-300">{intelligence.frameworks.join(' · ')}</p>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

/* ───────────────────────────────────────────────────────── connection rows ── */

const CONNECTION_ICON: Record<string, typeof Cloud> = {
  kubernetes: Boxes,
  aws: Cloud,
  azure: Cloud,
  gcp: Cloud,
  registry: Container,
  'git-provider': Github,
};

const STATUS_COLOR: Record<string, string> = {
  connected: ACCENT.emerald,
  degraded: ACCENT.amber,
  unauthorized: ACCENT.rose,
  unreachable: ACCENT.rose,
  unverified: ACCENT.slate,
};

function ConnectionRow({
  connection,
  selected,
  onToggle,
  namespaces,
  onNamespaceToggle,
  regions,
  onRegionToggle,
}: {
  connection: PublicConnectionView;
  selected: boolean;
  onToggle: () => void;
  namespaces: Set<string>;
  onNamespaceToggle: (namespace: string) => void;
  regions: Set<string>;
  onRegionToggle: (region: string) => void;
}) {
  const Icon = CONNECTION_ICON[connection.kind] ?? Cloud;
  const color = STATUS_COLOR[connection.status] ?? ACCENT.slate;
  const availableNamespaces = connection.scope.namespaces ?? [];
  const availableRegions = connection.scope.regions ?? [];

  return (
    <li className="px-5 py-3">
      <label className="flex cursor-pointer items-start gap-3">
        <input type="checkbox" checked={selected} onChange={onToggle} className="mt-1 h-3.5 w-3.5 shrink-0 accent-cyan-400" />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <Icon aria-hidden className="h-4 w-4 shrink-0 text-slate-400" />
            <span className="text-[12.5px] font-bold text-white">{connection.label}</span>
            <span
              className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-widest"
              style={{ backgroundColor: `${color}18`, color }}
            >
              {connection.status}
            </span>
            <span className="rounded bg-emerald-400/12 px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-widest text-emerald-300">
              read-only
            </span>
          </span>
          <span className="mt-1 block text-[11.5px] leading-relaxed text-slate-500">{connection.statusDetail}</span>
          {connection.deniedPermissions.length > 0 && (
            <span className="mt-1 block text-[11px] leading-relaxed text-amber-300/80">
              Denied: {connection.deniedPermissions.join(', ')} — those dimensions will be reported as Not Assessed.
            </span>
          )}
        </span>
      </label>

      {selected && availableNamespaces.length > 0 && (
        <ScopePicker label="Namespaces" options={availableNamespaces} selected={namespaces} onToggle={onNamespaceToggle} />
      )}
      {selected && availableRegions.length > 0 && (
        <ScopePicker label="Regions" options={availableRegions} selected={regions} onToggle={onRegionToggle} />
      )}
      {selected && availableNamespaces.length === 0 && connection.kind === 'kubernetes' && (
        <p className="mt-2 pl-6 text-[11px] leading-relaxed text-amber-300/80">
          No namespaces are recorded on this connection&apos;s scope. Re-verify the connection so the scanner can enumerate
          them, then choose the ones to assess.
        </p>
      )}
    </li>
  );
}

function ScopePicker({
  label,
  options,
  selected,
  onToggle,
}: {
  label: string;
  options: string[];
  selected: Set<string>;
  onToggle: (value: string) => void;
}) {
  return (
    <div className="mt-2 pl-6">
      <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-slate-500">{label} to assess</p>
      <div className="mt-1.5 flex flex-wrap gap-1.5">
        {options.map((option) => {
          const active = selected.has(option);
          return (
            <button
              key={option}
              type="button"
              onClick={() => onToggle(option)}
              aria-pressed={active}
              className={cn(
                'rounded border px-2 py-0.5 font-mono text-[10px] transition-colors',
                active ? 'border-cyan-400/40 bg-cyan-400/[0.08] text-cyan-300' : 'border-white/[0.08] text-slate-400 hover:text-slate-200',
              )}
            >
              {option}
            </button>
          );
        })}
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────────────── connection form ─── */

const CONNECTION_KINDS: Array<{ id: string; label: string; fields: Array<{ key: string; label: string; type?: string; placeholder?: string; textarea?: boolean }> }> = [
  {
    id: 'kubernetes',
    label: 'Kubernetes cluster',
    fields: [
      { key: 'endpoint', label: 'API server URL', placeholder: 'https://cluster.example.com:6443' },
      { key: 'token', label: 'Read-only ServiceAccount token', type: 'password' },
    ],
  },
  {
    id: 'aws',
    label: 'AWS account',
    fields: [
      { key: 'accessKeyId', label: 'Access key id', placeholder: 'AKIA…' },
      { key: 'secretAccessKey', label: 'Secret access key', type: 'password' },
      { key: 'sessionToken', label: 'Session token (optional)', type: 'password' },
    ],
  },
  {
    id: 'azure',
    label: 'Azure subscription',
    fields: [
      { key: 'tenantId', label: 'Tenant id' },
      { key: 'clientId', label: 'Client id' },
      { key: 'clientSecret', label: 'Client secret', type: 'password' },
      { key: 'subscriptionId', label: 'Subscription id' },
    ],
  },
  {
    id: 'gcp',
    label: 'Google Cloud project',
    fields: [{ key: 'serviceAccountJson', label: 'Service account key JSON', textarea: true }],
  },
  {
    id: 'git-provider',
    label: 'Git provider (private repositories)',
    fields: [{ key: 'token', label: 'Read-only access token', type: 'password' }],
  },
  {
    id: 'registry',
    label: 'Container registry',
    fields: [
      { key: 'endpoint', label: 'Registry host', placeholder: 'ghcr.io' },
      { key: 'username', label: 'Username' },
      { key: 'password', label: 'Password or pull token', type: 'password' },
    ],
  },
];

function ConnectionForm({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [kind, setKind] = React.useState('kubernetes');
  const [label, setLabel] = React.useState('');
  const [values, setValues] = React.useState<Record<string, string>>({});
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [requirements, setRequirements] = React.useState<Array<{ kind: string; permissions: Array<{ permission: string; why: string }> }>>([]);

  React.useEffect(() => {
    void fetch('/api/v1/exposure/dev/connection-requirements')
      .then((response) => response.json())
      .then((payload) => setRequirements(payload.data ?? []))
      .catch(() => setRequirements([]));
  }, []);

  const definition = CONNECTION_KINDS.find((entry) => entry.id === kind)!;
  const permissions = requirements.find((entry) => entry.kind === kind)?.permissions ?? [];

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      const { endpoint, ...secret } = values;
      const response = await fetch('/api/v1/exposure/dev/connections', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeader() },
        body: JSON.stringify({
          kind,
          label: label.trim() || definition.label,
          endpoint: endpoint ?? '',
          secret: kind === 'kubernetes' ? { ...secret, endpoint: endpoint ?? '' } : secret,
        }),
      });
      const payload = await response.json();
      if (!response.ok) {
        setError(payload?.error?.message ?? 'The connection could not be created.');
        return;
      }
      onCreated();
    } catch (caught) {
      setError((caught as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-3 px-5 py-4">
      <div className="flex items-center justify-between gap-2">
        <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.18em] text-slate-500">New connection</p>
        <button type="button" onClick={onClose} aria-label="Close" className="text-slate-500 hover:text-white">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {CONNECTION_KINDS.map((entry) => (
          <button
            key={entry.id}
            type="button"
            onClick={() => {
              setKind(entry.id);
              setValues({});
            }}
            className={cn(
              'rounded-lg border px-2.5 py-1 text-[11px] font-bold transition-colors',
              kind === entry.id ? 'border-cyan-400/30 bg-cyan-400/[0.07] text-cyan-300' : 'border-white/[0.07] text-slate-400 hover:text-slate-200',
            )}
          >
            {entry.label}
          </button>
        ))}
      </div>

      {permissions.length > 0 && (
        <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] px-3.5 py-3">
          <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-slate-500">
            Permissions this connection needs
          </p>
          <ul className="mt-1.5 space-y-1">
            {permissions.map((permission) => (
              <li key={permission.permission} className="text-[11.5px] leading-relaxed text-slate-400">
                <code className="font-mono text-[10.5px] text-cyan-300">{permission.permission}</code> — {permission.why}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[11px] italic text-emerald-300/70">
            No write permission is ever requested, and no connected resource is ever modified.
          </p>
        </div>
      )}

      <label className="block">
        <span className="font-mono text-[9.5px] uppercase tracking-wider text-slate-500">Connection name</span>
        <input
          value={label}
          onChange={(event) => setLabel(event.target.value)}
          placeholder={definition.label}
          className="mt-1 w-full rounded-lg border border-white/[0.08] bg-[#050a15] px-2.5 py-2 text-[12px] text-slate-200 outline-none focus:border-cyan-400/40"
        />
      </label>

      {definition.fields.map((field) => (
        <label key={field.key} className="block">
          <span className="font-mono text-[9.5px] uppercase tracking-wider text-slate-500">{field.label}</span>
          {field.textarea ? (
            <textarea
              value={values[field.key] ?? ''}
              onChange={(event) => setValues((current) => ({ ...current, [field.key]: event.target.value }))}
              rows={5}
              spellCheck={false}
              className="mt-1 w-full rounded-lg border border-white/[0.08] bg-[#050a15] px-2.5 py-2 font-mono text-[10.5px] text-slate-200 outline-none focus:border-cyan-400/40"
            />
          ) : (
            <input
              type={field.type ?? 'text'}
              autoComplete="off"
              value={values[field.key] ?? ''}
              onChange={(event) => setValues((current) => ({ ...current, [field.key]: event.target.value }))}
              placeholder={field.placeholder}
              className="mt-1 w-full rounded-lg border border-white/[0.08] bg-[#050a15] px-2.5 py-2 font-mono text-[11.5px] text-slate-200 outline-none placeholder:text-slate-700 focus:border-cyan-400/40"
            />
          )}
        </label>
      ))}

      {error && <p className="rounded-lg border border-rose-400/25 bg-rose-500/[0.07] px-3 py-2 text-[11.5px] text-rose-100/85">{error}</p>}

      <button
        type="button"
        onClick={() => void submit()}
        disabled={submitting}
        className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-400 px-3.5 py-2 text-[12px] font-black text-[#04060e] transition-opacity hover:opacity-90 disabled:opacity-50"
      >
        {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
        Connect and verify
      </button>
      <p className="text-[11px] leading-relaxed text-slate-500">
        Credentials are held by the API server for the lifetime of its process, are never written to the database, and are
        never returned to this browser. The connection is verified with a real read-only call before it is usable.
      </p>
    </div>
  );
}

function authHeader(): Record<string, string> {
  try {
    for (let index = 0; index < localStorage.length; index += 1) {
      const key = localStorage.key(index);
      if (!key || !key.startsWith('sb-') || !key.endsWith('-auth-token')) continue;
      const raw = localStorage.getItem(key);
      if (!raw) continue;
      const parsed = JSON.parse(raw);
      const token = parsed?.access_token ?? parsed?.currentSession?.access_token;
      if (token) return { Authorization: `Bearer ${token}` };
    }
  } catch {
    /* anonymous */
  }
  return {};
}

/* ─────────────────────────────────────────────────────────── empty states ─── */

/** The Engine Ledger before there is anything to record. Titled to match the
 *  ledger it becomes, so the rail does not rename itself mid-workflow. */
function DevEmptyRail() {
  return (
    <Panel className="overflow-hidden">
      <div className="border-b border-white/[0.06] px-4 py-3">
        <SectionLabel>Engine Ledger</SectionLabel>
      </div>
      <div className="px-4 py-6 text-center">
        <Github aria-hidden className="mx-auto h-7 w-7 text-slate-700" />
        <p className="mt-2 text-[12.5px] font-bold text-slate-300">No repository selected</p>
        <p className="mt-1 text-[11.5px] leading-relaxed text-slate-500">
          Paste a public repository URL, or connect a provider, cluster or cloud account to extend the assessment.
        </p>
      </div>
    </Panel>
  );
}

function DevEmptyState() {
  const cards = [
    {
      icon: Github,
      title: 'Five platforms, one catalogue',
      body: 'GitHub, GitLab, Bitbucket, Azure DevOps and self-hosted Git are read through one adapter, so a repository is assessed identically wherever it lives.',
    },
    {
      icon: Boxes,
      title: 'Code to cluster to cloud',
      body: 'Source, dependencies, containers, Kubernetes, IaC, CI/CD and connected cloud accounts are correlated into one cryptographic path, not twelve unrelated lists.',
    },
    {
      icon: ShieldCheck,
      title: 'Read-only, always',
      body: 'No repository is written to, no cluster is modified, no image is pushed, and repository code is never executed. Scanning and remediation stay separate workflows.',
    },
  ];

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-3">
      {cards.map((card, index) => (
        <motion.div key={card.title} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.07 }}>
          <Panel className="h-full px-5 py-5">
            <span className="grid h-10 w-10 place-items-center rounded-xl border border-violet-400/25 bg-violet-400/[0.08] text-violet-300">
              <card.icon className="h-5 w-5" />
            </span>
            <h3 className="mt-3.5 text-[15px] font-black text-white">{card.title}</h3>
            <p className="mt-1.5 text-[12.5px] leading-relaxed text-slate-400">{card.body}</p>
          </Panel>
        </motion.div>
      ))}
    </div>
  );
}
