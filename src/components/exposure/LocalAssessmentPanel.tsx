'use client';

/**
 * Local Assessment Panel (§7, §48, §68, §69).
 *
 * The full Local mode surface: browser capability disclosure, authorisation,
 * project fingerprint, planner proposal, profile and engine selection,
 * exclusions, the live engine ledger and every result panel.
 *
 * §43 is presented, not just implemented. The local-only banner is the first
 * thing on the panel, because a user being asked to point a security product at
 * their source tree deserves to know — before they click — exactly where those
 * files go. The answer here is: nowhere.
 */

import React from 'react';
import { Link } from 'react-router-dom';
import { AnimatePresence, motion } from 'motion/react';
import {
  AlertTriangle, ArrowUpRight, ChevronDown, Cpu, FolderOpen, HardDrive, Loader2, Lock, MonitorSmartphone,
  Play, RotateCcw, Settings2, ShieldCheck,
} from 'lucide-react';
import { AGENT_ROLES } from '@/lib/agent-installer/agent-release';
import { AGENT_ROLE_MIN_TIER, TIER_LABEL } from '@/lib/subscription-access';
import { cn } from '@/lib/utils';
import { ACCENT, Panel, SectionLabel } from '@/components/quantum-scan/ui';
import { useLocalScan } from '@/hooks/use-local-scan';
import { defaultExclusions, type ScanExclusions } from '@/lib/scanner/exposure/types';
import { profilesForMode, resolveProfile, FACET_LABEL } from '@/lib/scanner/exposure/profiles';
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
import { ScanTheatre, formatBytes, type TheatreStatus } from './ScanTheatre';
import { ExposureWorkflowGraph } from './ExposureWorkflowGraph';
import { useScannerEngines } from '@/hooks/use-scanner-engines';
import { useExposureAccess } from '@/hooks/use-exposure-access';
import { ModeAccessGate, ModeAccessSkeleton } from './ModeAccessGate';
import { cbomToCsv, cbomToCycloneDx, cbomToJson } from '@/lib/scanner/exposure/cbom';

/* ─────────────────────────────────────────────────────────────── download ─── */

function downloadBlob(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

/* ──────────────────────────────────────────────────────────────── the panel ── */

export interface LocalAssessmentPanelProps {
  /** When set, the "Sync to platform" action is offered on completion. */
  onSync?: (assessment: NonNullable<ReturnType<typeof useLocalScan>['assessment']>) => Promise<void>;
  /** Shown in the enterprise upsell slot on the anonymous page. */
  upsellSlot?: React.ReactNode;
}

export function LocalAssessmentPanel({ onSync, upsellSlot }: LocalAssessmentPanelProps) {
  /* Entitlement is resolved INSIDE the panel rather than by each page that
     mounts it, so /public-scan and /dashboard/scanner cannot drift apart on who
     may scan. The hook is called unconditionally — hooks always are — and the
     gate replaces the panel body below. */
  const access = useExposureAccess('local');
  const scan = useLocalScan();
  const [profileId, setProfileId] = React.useState('standard');
  const [customEngines, setCustomEngines] = React.useState<Set<string>>(new Set());
  const [exclusions, setExclusions] = React.useState<ScanExclusions>(defaultExclusions);
  const [showAdvanced, setShowAdvanced] = React.useState(false);
  const [syncState, setSyncState] = React.useState<'idle' | 'syncing' | 'synced' | 'error'>('idle');
  const [syncError, setSyncError] = React.useState<string | null>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);
  /* The live scan theatre is dismissible once the scan settles; a new run
     always brings it back. */
  const [theatreHidden, setTheatreHidden] = React.useState(false);
  const theatreRef = React.useRef<HTMLDivElement>(null);
  const resultsRef = React.useRef<HTMLDivElement>(null);

  const profiles = React.useMemo(() => profilesForMode('local'), []);
  const registry = useScannerEngines('local');
  const engines = React.useMemo(() => descriptorsForMode('local'), []);
  const recommendedMap = React.useMemo(
    () => new Map((scan.plan?.recommended ?? []).map((entry) => [entry.engineId, entry.reason])),
    [scan.plan],
  );

  /* The planner PROPOSES; the operator disposes (Spec-2 §32). When a plan
     arrives, the suggested profile is pre-selected and the custom engine set is
     seeded from the recommendation — but both remain fully editable. */
  React.useEffect(() => {
    if (!scan.plan) return;
    setProfileId((current) => (current === 'standard' ? scan.plan!.suggestedProfile : current));
    setCustomEngines(new Set(scan.plan.recommended.map((entry) => entry.engineId)));
  }, [scan.plan]);

  const resolvedEngines = React.useMemo(
    () => resolveProfile('local', profileId, [...customEngines]).engines,
    [profileId, customEngines],
  );

  const handleSync = React.useCallback(async () => {
    if (!scan.assessment || !onSync) return;
    setSyncState('syncing');
    setSyncError(null);
    try {
      await onSync(scan.assessment);
      setSyncState('synced');
    } catch (error) {
      setSyncState('error');
      setSyncError((error as Error).message);
    }
  }, [scan.assessment, onSync]);

  const busy = scan.state === 'authorizing' || scan.state === 'collecting' || scan.state === 'scanning';

  /* ── live scan theatre (§ Scanning UI/UX) ──────────────────────────────
     Shown from the moment the operator starts a run, and driven entirely by
     the hook: the worker is the only thing that can move it. */
  const theatreStatus: TheatreStatus | null =
    scan.state === 'scanning' ? 'scanning'
      : scan.state === 'complete' ? 'complete'
        : scan.state === 'cancelled' ? 'cancelled'
          : scan.state === 'error' && scan.startedAt !== null ? 'error'
            : null;
  const theatreVisible = theatreStatus !== null && !theatreHidden;

  /* A scan that has just started deserves the operator's eye. The stage is
     brought into view once per run, and never under reduced motion rules the
     browser is enforcing for the user. */
  React.useEffect(() => {
    if (scan.state !== 'scanning') return;
    setTheatreHidden(false);
    const node = theatreRef.current;
    if (!node) return;
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    node.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
  }, [scan.state]);

  /* Locked: show the mode in full, minus the controls that would run it.
     Rendered after every hook above has run, so the hook order is stable
     whichever branch this takes. While the entitlement is still resolving we
     render the gate's own loading-free locked state only once we KNOW — a
     paying customer must not see "upgrade" flash on mount. */
  if (access.loading) return <ModeAccessSkeleton />;
  if (!access.allowed) return <ModeAccessGate mode="local" access={access} upsellSlot={upsellSlot} />;

  return (
    <div className="space-y-5">
      {/* ── privacy banner (§43) ────────────────────────────────────────── */}
      <Panel className="overflow-hidden border-emerald-400/20">
        <div className="flex flex-wrap items-start gap-3 px-5 py-4">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-emerald-400/25 bg-emerald-400/[0.08] text-emerald-300">
            <Lock className="h-4.5 w-4.5" />
          </span>
          <div className="min-w-0 flex-1">
            <h3 className="text-[14px] font-black text-white">Local-only processing</h3>
            <p className="mt-1 text-[12.5px] leading-relaxed text-slate-400">
              Files are read through your browser&apos;s own file picker after you authorise a folder, and are analysed by a
              Web Worker inside this tab. <strong className="font-bold text-emerald-300">No file content, secret value or
              Git object is uploaded</strong> — this panel contains no network code at all. Only a sanitised assessment can
              be synchronised, and only when you explicitly choose to.
            </p>
          </div>
        </div>
      </Panel>

      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1.45fr)_minmax(0,1fr)]">
        {/* ── target selector (§7) ──────────────────────────────────────── */}
        <Panel className="overflow-hidden">
          <div className="border-b border-white/[0.06] px-5 py-3">
            <SectionLabel>Local Assessment Target</SectionLabel>
          </div>

          <div className="px-5 py-4">
            {!scan.capability.picker && !scan.capability.input ? (
              <div className="rounded-xl border border-rose-400/25 bg-rose-500/[0.06] px-4 py-3.5">
                <p className="flex items-center gap-1.5 text-[12.5px] font-bold text-rose-200">
                  <AlertTriangle className="h-4 w-4" /> This browser cannot read local folders
                </p>
                <p className="mt-1.5 text-[11.5px] leading-relaxed text-rose-100/75">
                  Neither the File System Access API nor directory input is available here. Open this page in a
                  Chromium-based browser (Chrome, Edge, Brave, Arc) to run a Local assessment.
                </p>
              </div>
            ) : (
              <>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    disabled={busy || !scan.capability.picker}
                    onClick={() => void scan.selectDirectory()}
                    className={cn(
                      'inline-flex items-center gap-2 rounded-lg px-4 py-2.5 text-[13px] font-black transition-opacity',
                      'bg-gradient-to-r from-cyan-400 to-violet-500 text-[#04060e] hover:opacity-90',
                      'disabled:cursor-not-allowed disabled:opacity-50',
                    )}
                    title={scan.capability.picker ? 'Authorise a folder with the OS picker' : 'This browser does not support the File System Access API'}
                  >
                    {scan.state === 'authorizing' ? <Loader2 className="h-4 w-4 animate-spin" /> : <FolderOpen className="h-4 w-4" />}
                    Select folder
                  </button>

                  <button
                    type="button"
                    disabled={busy || !scan.capability.input}
                    onClick={() => fileInputRef.current?.click()}
                    className="inline-flex items-center gap-2 rounded-lg border border-white/[0.1] px-4 py-2.5 text-[13px] font-bold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <HardDrive className="h-4 w-4" /> Select files
                  </button>

                  {/* The browser reads one folder, once. An agent runs on the host
                      itself — continuously, and against what the browser sandbox
                      cannot reach. Deploying one starts in the Agent Center with
                      the agent-type choice open. */}
                  <Link
                    to={localAgentHref(profileId)}
                    aria-disabled={busy}
                    onClick={(event) => { if (busy) event.preventDefault(); }}
                    title="Deploy a Collector, Scanner, Patcher or Migration Operator agent from the Agent Center"
                    className={cn(
                      'inline-flex items-center gap-2 rounded-lg border border-violet-400/35 bg-violet-400/[0.08] px-4 py-2.5 text-[13px] font-bold text-violet-100 no-underline transition-colors',
                      'hover:border-violet-300/60 hover:bg-violet-400/[0.14]',
                      busy && 'pointer-events-none opacity-50',
                    )}
                  >
                    <Cpu className="h-4 w-4" /> Local Agent
                  </Link>
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    // @ts-expect-error — non-standard but universally supported.
                    webkitdirectory=""
                    directory=""
                    className="hidden"
                    onChange={(event) => {
                      if (event.target.files?.length) void scan.selectFiles(event.target.files);
                      event.target.value = '';
                    }}
                  />

                  {scan.collection && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={scan.reset}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-2.5 text-[12px] font-semibold text-slate-400 transition-colors hover:text-white disabled:opacity-50"
                    >
                      <RotateCcw className="h-3.5 w-3.5" /> Clear
                    </button>
                  )}
                </div>

                {!scan.capability.picker && scan.capability.input && (
                  <p className="mt-2.5 text-[11px] leading-relaxed text-amber-200/70">
                    This browser only offers directory input, which cannot see dot-directories. <code>.git</code>,{' '}
                    <code>.github</code> and <code>.circleci</code> will not be readable, so repository history and CI/CD
                    pipelines will be reported as not assessed.
                  </p>
                )}

                {scan.state === 'collecting' && (
                  <p className="mt-3 flex items-center gap-2 font-mono text-[11px] text-cyan-300">
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    {scan.currentStep ?? 'Reading selected files…'}
                  </p>
                )}
              </>
            )}

            {/* Shown whether or not this browser can read folders — when it
                cannot, the agent is the way to assess this machine at all. */}
            {!scan.collection && <LocalAgentOption profileId={profileId} />}

            {/* ── project fingerprint (§7) ─────────────────────────────── */}
            {scan.fingerprint && (
              <motion.div
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                className="mt-4 rounded-xl border border-cyan-400/20 bg-cyan-400/[0.04] px-4 py-3.5"
              >
                <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.18em] text-cyan-300">Detected project</p>
                <p className="mt-1.5 text-[14px] font-black text-white">{scan.fingerprint.rootName}</p>
                <dl className="mt-2.5 grid grid-cols-2 gap-2 sm:grid-cols-4">
                  <Stat label="Files" value={scan.fingerprint.totalFiles.toLocaleString()} />
                  <Stat label="Source files" value={scan.fingerprint.sourceFiles.toLocaleString()} />
                  <Stat label="Manifests" value={String(scan.fingerprint.manifests.length)} />
                  <Stat label="Git repository" value={scan.fingerprint.gitRepository ? 'Yes' : 'No'} />
                </dl>
                {scan.fingerprint.detected.length > 0 && (
                  <div className="mt-2.5 flex flex-wrap gap-1.5">
                    {scan.fingerprint.detected.map((item) => (
                      <span key={item} className="rounded bg-white/[0.06] px-2 py-0.5 font-mono text-[10px] text-slate-300">
                        {item}
                      </span>
                    ))}
                  </div>
                )}
              </motion.div>
            )}

            {/* ── collection limitations ────────────────────────────────── */}
            {scan.limitations.length > 0 && (
              <div className="mt-3 rounded-xl border border-amber-400/20 bg-amber-400/[0.05] px-4 py-3">
                <p className="flex items-center gap-1.5 font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-amber-300">
                  <AlertTriangle className="h-3 w-3" /> Collection limits
                </p>
                <ul className="mt-1.5 space-y-1">
                  {scan.limitations.map((limitation, index) => (
                    <li key={index} className="text-[11.5px] leading-relaxed text-amber-100/80">
                      <strong className="font-bold">{limitation.dimension}:</strong> {limitation.reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* ── planner facets (Spec-2 §32) ───────────────────────────── */}
            {scan.plan && scan.plan.facets.length > 0 && (
              <div className="mt-3">
                <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-slate-500">
                  Smart Scan Planner detected
                </p>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {scan.plan.facets.map((facet) => (
                    <span key={facet} className="rounded-lg border border-violet-400/25 bg-violet-400/[0.06] px-2 py-0.5 text-[10.5px] text-violet-200">
                      {FACET_LABEL[facet]}
                    </span>
                  ))}
                </div>
                <p className="mt-2 text-[11px] leading-relaxed text-slate-500">
                  {scan.plan.recommended.length} engine{scan.plan.recommended.length === 1 ? '' : 's'} recommended for this
                  target. The planner proposes; you decide what actually runs.
                </p>
              </div>
            )}
          </div>
        </Panel>

        {/* ── rail ─────────────────────────────────────────────────────── */}
        <div className="space-y-5">
          {scan.runs.length > 0 ? (
            <EngineLedger
              runs={scan.runs}
              progress={scan.progress}
              status={scan.state === 'scanning' ? 'scanning' : 'idle'}
              currentStep={scan.currentStep}
              onCancel={scan.cancel}
            />
          ) : (
            <LocalEmptyRail />
          )}
          <EngineHealthPanel engines={registry.engines} knowledgeBase={registry.knowledgeBase} />
          {upsellSlot}
        </div>
      </div>

      {/* ── profile + launch ───────────────────────────────────────────────
           Full width, deliberately. Ten profiles stacked two-across inside the
           configuration column pushed the start button below the fold, so
           choosing a profile and running it became two separate journeys.
           Across the whole page they are one band: pick, read, launch.

           Still gated on a collection: a profile describes what will be read,
           and until a folder is authorised there is nothing to read. */}
      {scan.collection && (
        <Panel className="overflow-hidden" glow={scan.state !== 'scanning' && !busy}>
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
              suggested={scan.plan?.suggestedProfile ?? null}
              engineCount={resolvedEngines.length}
              launchSlot={
                <div className="flex h-full flex-col justify-center rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-3.5">
                  <button
                    type="button"
                    disabled={busy || scan.state === 'scanning'}
                    onClick={() => scan.start({ profileId, customEngines: [...customEngines], exclusions })}
                    className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-500 px-4 py-3 text-[13.5px] font-black leading-tight text-[#04060e] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {scan.state === 'scanning' ? (
                      <>
                        <Loader2 className="h-4 w-4 shrink-0 animate-spin" /> Assessing {scan.progress}%
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4 shrink-0" /> Start local assessment
                      </>
                    )}
                  </button>
                  <p className="mt-2 truncate text-center font-mono text-[10px] uppercase tracking-[0.14em] text-slate-400">
                    {scan.collection.rootName}
                  </p>
                  <p className="mt-0.5 text-center font-mono text-[10px] uppercase tracking-[0.14em] text-slate-600">
                    {scan.collection.files.length.toLocaleString()} files in scope
                  </p>
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
                  <div className="space-y-4 px-5 pb-5">
                    {profileId !== 'custom' && (
                      <p className="rounded-lg border border-white/[0.07] bg-white/[0.02] px-3 py-2 text-[11.5px] leading-relaxed text-slate-400">
                        The <strong className="font-bold text-slate-200">{profiles.find((entry) => entry.id === profileId)?.label}</strong>{' '}
                        profile will run {resolvedEngines.length} engine{resolvedEngines.length === 1 ? '' : 's'}. Switch
                        to <strong className="font-bold text-slate-200">Custom</strong> to choose them individually.
                      </p>
                    )}

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
                      recommended={recommendedMap}
                    />

                    <ExclusionEditor exclusions={exclusions} onChange={setExclusions} />
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </Panel>
      )}

      {/* ── live scan theatre ──────────────────────────────────────────────
           Directly below the target and configuration surface, so the run the
           operator just authorised is the next thing they see. */}
      {theatreVisible && theatreStatus && (
        <div ref={theatreRef} className="scroll-mt-24">
          <ScanTheatre
            mode="local"
            status={theatreStatus}
            progress={scan.progress}
            runs={scan.runs}
            findings={scan.findings}
            telemetry={scan.telemetry}
            currentStep={scan.currentStep}
            startedAt={scan.startedAt}
            streamOpen={scan.streamOpen}
            target={{
              label: scan.collection?.rootName ?? scan.fingerprint?.rootName ?? 'Authorised folder',
              detail: scan.collection ? `${scan.collection.files.length.toLocaleString()} files in scope` : null,
            }}
            /* Local knows exactly how many bytes it read, because it read them. */
            volume={
              scan.collection
                ? {
                    label: 'Data analysed',
                    value: formatBytes(scan.collection.stats.totalBytes),
                    sublabel: `${scan.collection.stats.read.toLocaleString()} files read`,
                  }
                : null
            }
            assessment={scan.assessment}
            knowledgeBase={registry.knowledgeBase}
            engineHealth={registry.engines}
            error={scan.error}
            onCancel={scan.cancel}
            onViewAll={() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
            onDismiss={() => setTheatreHidden(true)}
          />
        </div>
      )}

      {/* ── error ──────────────────────────────────────────────────────── */}
      {scan.error && !theatreVisible && (
        <div className="flex items-start gap-3 rounded-xl border border-rose-400/25 bg-rose-500/[0.07] px-4 py-3">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
          <p className="text-[12.5px] leading-relaxed text-rose-100/85">{scan.error}</p>
        </div>
      )}

      {/* ── results ────────────────────────────────────────────────────── */}
      {scan.assessment && (
        <div ref={resultsRef} className="space-y-5 scroll-mt-24">
          <AssessmentStatusBar
            assessment={scan.assessment}
            onReset={scan.reset}
            onSync={onSync ? handleSync : undefined}
            syncState={syncState}
            extra={
              <>
                <ExportRow assessment={scan.assessment} />
              </>
            }
          />
          {syncError && (
            <p className="rounded-xl border border-rose-400/25 bg-rose-500/[0.07] px-4 py-2.5 text-[12px] text-rose-100/85">
              Synchronisation failed: {syncError}
            </p>
          )}

          <ExposureScorecard assessment={scan.assessment} />
          <QuantumExposureSummary assessment={scan.assessment} />
          <ScannerIntelligenceSection assessment={scan.assessment} synced={syncState === 'synced'} />
          <CorrelatedExposures exposures={scan.assessment.exposures} />
          <FindingExplorer assessment={scan.assessment} />
          {/* The findings table says WHAT was found; the workflow map says how
              the assessment reached it and what each finding is connected to. */}
          <ExposureWorkflowGraph assessment={scan.assessment} mode="local" />
          <ExposureRecommendations assessment={scan.assessment} />
          <CbomViewer
            components={scan.assessment.cbom}
            onExport={(format) => {
              const meta = {
                scanId: scan.assessment!.task.scanId,
                target: scan.fingerprint?.rootName ?? 'local',
                generatedAt: scan.assessment!.generatedAt,
              };
              const slug = meta.target.replace(/[^a-z0-9.-]/gi, '_');
              if (format === 'csv') downloadBlob(`qguard-cbom-${slug}.csv`, cbomToCsv(scan.assessment!.cbom), 'text/csv');
              else if (format === 'cyclonedx') downloadBlob(`qguard-cbom-${slug}.cdx.json`, cbomToCycloneDx(scan.assessment!.cbom, meta), 'application/json');
              else downloadBlob(`qguard-cbom-${slug}.json`, cbomToJson(scan.assessment!.cbom, meta), 'application/json');
            }}
          />
          <CoveragePanel coverage={scan.assessment.task.coverage} mode="local" />
        </div>
      )}

      {/* ── empty state (§69) ──────────────────────────────────────────── */}
      {!scan.collection && !scan.assessment && <LocalEmptyState />}
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────── fragments ── */

/**
 * Where the Local Agent option lands: the Agent Center, with the deployment
 * wizard open on the agent-type step. The selected scan profile travels with
 * it so the wizard can pre-select the matching agent scan preset — the operator
 * does not have to express the same intent twice.
 */
function localAgentHref(profileId: string, role?: string): string {
  const params = new URLSearchParams({ deploy: '1', source: 'local-assessment', profile: profileId });
  if (role) params.set('role', role);
  return `/downloads?${params.toString()}`;
}

/**
 * The four agent types, each a direct entry into the wizard with that type
 * pre-selected. Plan labels are the static policy matrix; the Agent Center
 * re-checks the tenant's actual plan and refuses a type it does not include.
 */
function LocalAgentOption({ profileId }: { profileId: string }) {
  return (
    <div className="mt-4 overflow-hidden rounded-xl border border-violet-400/20 bg-gradient-to-br from-violet-500/[0.07] via-transparent to-cyan-400/[0.04]">
      <div className="flex flex-wrap items-start gap-3 px-4 py-3.5">
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-violet-400/30 bg-violet-400/[0.1] text-violet-200">
          <Cpu className="h-4.5 w-4.5" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="flex flex-wrap items-center gap-2">
            <span className="text-[13.5px] font-black text-white">Local Agent</span>
            <span className="rounded-full border border-violet-400/30 bg-violet-400/10 px-2 py-0.5 font-mono text-[9px] font-bold uppercase tracking-[0.14em] text-violet-200">
              Continuous · on-host
            </span>
          </p>
          <p className="mt-1 text-[12px] leading-relaxed text-slate-400">
            Install a Qguard agent on this machine or a server to assess what a browser cannot reach — system certificate
            stores, running processes, live TLS and SSH endpoints and protected configuration paths — on a schedule, not once.
            Choose the agent type next.
          </p>
        </div>
      </div>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-1.5 border-t border-white/[0.06] px-4 py-3 sm:grid-cols-2">
        {AGENT_ROLES.map((role) => (
          <Link
            key={role.id}
            to={localAgentHref(profileId, role.id)}
            className="group flex min-w-0 items-center justify-between gap-2 rounded-lg border border-white/[0.08] bg-white/[0.02] px-3 py-2 no-underline transition-colors hover:border-violet-400/40 hover:bg-violet-400/[0.06]"
          >
            <span className="min-w-0">
              <span className="block truncate text-[12px] font-bold text-slate-100">{role.label}</span>
              <span className="block truncate text-[10.5px] text-slate-500">
                {role.mutatesTargets ? 'Can change config' : 'Read-only'} · {TIER_LABEL[AGENT_ROLE_MIN_TIER[role.id]]}+
              </span>
            </span>
            <ArrowUpRight aria-hidden className="h-3.5 w-3.5 shrink-0 text-slate-500 transition-colors group-hover:text-violet-200" />
          </Link>
        ))}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="font-mono text-[9px] uppercase tracking-wider text-slate-500">{label}</dt>
      <dd className="truncate font-mono text-[13px] font-bold text-slate-200">{value}</dd>
    </div>
  );
}

function ExportRow({ assessment }: { assessment: NonNullable<ReturnType<typeof useLocalScan>['assessment']> }) {
  const slug = assessment.task.scanId;
  return (
    <button
      type="button"
      onClick={() => downloadBlob(`qguard-local-assessment-${slug}.json`, JSON.stringify(assessment, null, 2), 'application/json')}
      className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11.5px] font-semibold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
    >
      Export assessment JSON
    </button>
  );
}

function ExclusionEditor({ exclusions, onChange }: { exclusions: ScanExclusions; onChange: (next: ScanExclusions) => void }) {
  const asText = (list: string[]) => list.join('\n');
  const fromText = (text: string) => text.split('\n').map((line) => line.trim()).filter(Boolean);

  return (
    <div className="space-y-2.5">
      <p className="font-mono text-[9.5px] font-bold uppercase tracking-[0.18em] text-slate-500">Exclusions</p>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-2.5 sm:grid-cols-2">
        <label className="block">
          <span className="font-mono text-[9.5px] uppercase tracking-wider text-slate-500">Directories</span>
          <textarea
            value={asText(exclusions.directories)}
            onChange={(event) => onChange({ ...exclusions, directories: fromText(event.target.value) })}
            rows={4}
            spellCheck={false}
            className="mt-1 w-full rounded-lg border border-white/[0.08] bg-[#050a15] px-2.5 py-2 font-mono text-[11px] text-slate-300 outline-none focus:border-cyan-400/40"
          />
        </label>
        <label className="block">
          <span className="font-mono text-[9.5px] uppercase tracking-wider text-slate-500">Glob patterns</span>
          <textarea
            value={asText(exclusions.patterns)}
            onChange={(event) => onChange({ ...exclusions, patterns: fromText(event.target.value) })}
            rows={4}
            spellCheck={false}
            placeholder={'**/*.min.js\ndocs/**'}
            className="mt-1 w-full rounded-lg border border-white/[0.08] bg-[#050a15] px-2.5 py-2 font-mono text-[11px] text-slate-300 outline-none placeholder:text-slate-700 focus:border-cyan-400/40"
          />
        </label>
      </div>
      <p className="text-[11px] leading-relaxed text-slate-500">
        Excluded paths are counted in coverage as skipped, so the report always states what was left out.
      </p>
    </div>
  );
}

/** The Engine Ledger before there is anything to record. Titled to match the
 *  ledger it becomes, so the rail does not rename itself mid-workflow. */
function LocalEmptyRail() {
  return (
    <Panel className="overflow-hidden">
      <div className="border-b border-white/[0.06] px-4 py-3">
        <SectionLabel>Engine Ledger</SectionLabel>
      </div>
      <div className="px-4 py-6 text-center">
        <MonitorSmartphone aria-hidden className="mx-auto h-7 w-7 text-slate-700" />
        <p className="mt-2 text-[12.5px] font-bold text-slate-300">No target selected</p>
        <p className="mt-1 text-[11.5px] leading-relaxed text-slate-500">
          Authorise a folder to see which engines apply to it. Engines that have nothing to read report{' '}
          <span className="font-mono text-[10.5px]">Not Applicable</span> rather than a clean result.
        </p>
      </div>
    </Panel>
  );
}

function LocalEmptyState() {
  const cards = [
    {
      icon: ShieldCheck,
      title: 'Your source never leaves the device',
      body: 'The browser grants access to exactly the folder you pick. Analysis runs in a Web Worker in this tab, and this panel contains no upload path.',
    },
    {
      icon: HardDrive,
      title: 'Fourteen engines, one corpus',
      body: 'Cryptography, secrets, dependencies, configuration, certificates, containers, Kubernetes, IaC, CI/CD and Git history all read the same set of files.',
    },
    {
      icon: AlertTriangle,
      title: 'Honest about what it could not read',
      body: 'Packed Git history, binaries and excluded paths are reported as Not Assessed with the reason — never as a passing control.',
    },
  ];

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-3">
      {cards.map((card, index) => (
        <motion.div
          key={card.title}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: index * 0.07 }}
        >
          <Panel className="h-full px-5 py-5">
            <span className="grid h-10 w-10 place-items-center rounded-xl border border-cyan-400/25 bg-cyan-400/[0.08] text-cyan-300">
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
