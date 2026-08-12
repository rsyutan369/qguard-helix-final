/**
 * Dashboard Scanner — enterprise hero.
 *
 * The authenticated counterpart to the /public-scan hero: the same Quantum
 * Visualization Engine™ (holographic core, beam network, GPU packet engine,
 * live event timeline, infrastructure strip) mounted with the estate-discovery
 * node ring instead of the public-edge one, and driven by the authenticated
 * `/api/v1/scanner/stream` run.
 *
 * The composition, spacing, motion and chrome deliberately mirror the public
 * hero one-for-one. What differs is what an authenticated scan actually is: the
 * target field accepts a multi-asset queue with an explicit authorization
 * acknowledgement rather than a single domain, and the visualization reports
 * the estate's own six discovery surfaces.
 */
'use client';

import React from 'react';
import { AnimatePresence, motion } from 'motion/react';
import useMeasure from 'react-use-measure';
import {
  Boxes,
  Cpu,
  Layers,
  Loader2,
  Network,
  Pause,
  Play,
  Radar,
  RotateCcw,
  Server,
  ShieldCheck,
  Volume2,
  VolumeX,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  BeamNetwork,
  CategoryNode,
  CoreStage,
  cueForSeverity,
  InfrastructureStrip,
  PacketEngine,
  QuantumBackdrop,
  QveProvider,
  QVE_COLOR,
  ScanTicker,
  ScanTimeline,
  beamColor,
  isAlertSeverity,
  useQve,
  useQveAudio,
  useQveBudget,
  type BeamAnchor,
  type BeamPath,
  type BeamTarget,
  type InfraTile,
  type PacketEngineHandle,
  type QveNodeKey,
} from '@/app/public-scan/_qve';
import { Panel } from '@/components/quantum-scan/ui';
import {
  buildNodeEvidence,
  SCANNER_LEFT_NODES,
  SCANNER_NODE_BLUEPRINTS,
  SCANNER_RIGHT_NODES,
  type ScoreComponent,
} from './_intel';
import { ScannerNodeInspector } from './_node-inspector';
import { useDashboardScanBridge } from './_qve-bridge';
import type {
  DefensiveFinding,
  EnterpriseScanner2,
  ModuleState,
  ScanResultRecord,
  ScanStatus,
  ScanSummary,
} from './_types';

/* -------------------------------------------------------------------- helpers - */

/** Tailwind's `lg` breakpoint, as a hook. Drives the beam layer on/off. */
function useIsWide(): boolean {
  const [wide, setWide] = React.useState(false);
  React.useEffect(() => {
    const query = window.matchMedia('(min-width: 1024px)');
    const sync = () => setWide(query.matches);
    sync();
    query.addEventListener('change', sync);
    return () => query.removeEventListener('change', sync);
  }, []);
  return wide;
}

function packetsForSeverity(severity: string): number {
  if (severity === 'critical') return 7;
  if (severity === 'high') return 5;
  if (severity === 'medium') return 3;
  return 2;
}

/**
 * Infrastructure strip tiles — every value read from the run that is happening,
 * never a placeholder. `measured: false` keeps a tile in its idle legend until
 * the scanner has something real to put in it.
 */
function buildScannerInfraTiles(input: {
  targets: number;
  modules: ModuleState[];
  findings: number;
  components: number;
  cbom: number;
  exposures: number;
  hasEvidence: boolean;
}): InfraTile[] {
  const executed = input.modules.filter((module) => module.status !== 'Queued').length;
  const measured = input.hasEvidence;
  return [
    {
      key: 'targets',
      label: 'Authorized Targets',
      value: measured ? String(input.targets) : '—',
      basis: 'Assets explicitly authorized for this scan queue',
      icon: Server,
      measured,
    },
    {
      key: 'modules',
      label: 'Modules Executed',
      value: input.modules.length ? `${executed}/${input.modules.length}` : '—',
      basis: 'Scanner modules that reported state during this run',
      icon: Cpu,
      measured: input.modules.length > 0,
    },
    {
      key: 'components',
      label: 'Crypto Components',
      value: measured ? String(input.components) : '—',
      basis: 'Distinct cryptographic observations recorded as findings',
      icon: Layers,
      measured,
    },
    {
      key: 'findings',
      label: 'Vulnerable',
      value: measured ? String(input.findings) : '—',
      basis: 'Findings the risk model rated above SAFE',
      icon: Radar,
      measured,
      tone: input.findings > 0 ? QVE_COLOR.critical : QVE_COLOR.pass,
    },
    {
      key: 'cbom',
      label: 'CBOM Records',
      value: measured ? String(input.cbom) : '—',
      basis: 'Rows written to the cryptographic bill of materials',
      icon: Boxes,
      measured,
    },
    {
      key: 'exposures',
      label: 'Exposure Nodes',
      value: measured ? String(input.exposures) : '—',
      basis: 'Nodes added to the crypto exposure graph',
      icon: Network,
      measured,
    },
  ];
}

/* ---------------------------------------------------------------------- props - */

export interface ScannerHeroProps {
  status: ScanStatus;
  progress: number;
  modules: ModuleState[];
  findings: DefensiveFinding[];
  summary: ScanSummary | null;
  error: string | null;
  /** Normalized target strings currently queued. */
  targets: string[];
  /**
   * Findings the evidence panels read. Distinct from `findings` on purpose:
   * `findings` is the LIVE stream the visualization animates, which is empty
   * between runs, while this is the reconciled view (live, else the persisted
   * scan being reviewed) so a node card still opens with real evidence after a
   * reload.
   */
  evidenceFindings: DefensiveFinding[];
  /**
   * Module states the node inspector reads. Distinct from `modules` for the
   * same reason `evidenceFindings` is distinct from `findings`: `modules` is
   * the live stream the ring animates, this is the reconciled view, so opening
   * a node card after a reload still shows the real execution states.
   */
  evidenceModules: ModuleState[];
  /** Per-target scan records — the evidence the node inspector reads. */
  results: ScanResultRecord[];
  /** The Scanner_2 enterprise pass, when one has been produced. */
  scanner2: EnterpriseScanner2 | null;
  /** Headline counters, already reconciled with Scanner Intelligence. */
  counters: { components: number; vulnerable: number; cbom: number; assets: number; exposures: number };
  hasEvidence: boolean;
  /** Grade letter + colour once the run settles, for the core's verdict bar. */
  gradeLabel: string | null;
  /**
   * The assessment's verdict, so the core settles on the same composite score
   * and post-quantum readiness the result panels publish. Null before an
   * assessment exists.
   */
  verdict: {
    score: number;
    postQuantumReadiness: number;
    gradeable: boolean;
    nodeScores: Record<string, number>;
  } | null;
  /**
   * The assessment's published category decomposition.
   *
   * The node inspector states which categories and weights produced a surface's
   * score, so an operator can trace the number rather than trust it. It is the
   * SAME array the Encryption Score panel renders — never a second derivation.
   */
  scoreComponents: ScoreComponent[];
  /** Target composer (textarea, authorization, queue) rendered under the ring. */
  composerSlot: React.ReactNode;
  /** Workflow rail + platform-sync panel, rendered in the left column. */
  railSlot: React.ReactNode;
  onStart: () => void;
  onCancel: () => void;
  canStart: boolean;
  /**
   * Clears the page and starts a fresh assessment. The hero owns the button
   * because the visualization band is visible from every tab, so "New Scan" is
   * reachable wherever the operator happens to be reviewing.
   */
  onNewScan: () => void;
  /**
   * Incremented by the page's New Scan action. The engine's reducer state is
   * private to the provider below, so an external reset has to arrive as a
   * signal the hero can observe rather than as a method the page can call.
   */
  resetSignal: number;
}

/* ---------------------------------------------------------------------- inner - */

function HeroInner({
  status,
  progress,
  modules,
  findings,
  summary,
  error,
  targets,
  evidenceFindings,
  evidenceModules,
  results,
  scanner2,
  counters,
  hasEvidence,
  gradeLabel,
  verdict,
  scoreComponents,
  composerSlot,
  railSlot,
  onStart,
  onCancel,
  canStart,
  onNewScan,
  resetSignal,
}: ScannerHeroProps) {
  const budget = useQveBudget();
  const wide = useIsWide();
  const audio = useQveAudio();
  const { state, dispatch } = useQve();

  const asset = targets.length ? targets.join(', ') : 'authorized estate';
  const isRunning = status === 'queued' || status === 'running' || status === 'analyzing';

  useDashboardScanBridge({
    status,
    progress,
    modules,
    findings,
    summary,
    asset,
    error,
    reducedMotion: !budget.animate,
    verdict,
  });

  /* ── Geometry ──────────────────────────────────────────────────────────── */

  const [measureBand, bandBounds] = useMeasure({ debounce: 40 });
  const [bandElement, setBandElement] = React.useState<HTMLDivElement | null>(null);
  const [coreElement, setCoreElement] = React.useState<HTMLDivElement | null>(null);
  const anchorElements = React.useRef(new Map<QveNodeKey, HTMLElement>());
  const [geometryVersion, setGeometryVersion] = React.useState(0);

  const attachBand = React.useCallback(
    (element: HTMLDivElement | null) => {
      setBandElement(element);
      measureBand(element);
    },
    [measureBand],
  );

  const registerAnchor = React.useCallback((key: QveNodeKey, element: HTMLElement | null) => {
    if (element) anchorElements.current.set(key, element);
    else anchorElements.current.delete(key);
    setGeometryVersion((version) => version + 1);
  }, []);

  const [geometry, setGeometry] = React.useState<{
    width: number;
    height: number;
    anchors: BeamAnchor[];
    target: BeamTarget;
  }>({ width: 0, height: 0, anchors: [], target: { x: 0, y: 0, radius: 0 } });

  React.useLayoutEffect(() => {
    if (!bandElement || !coreElement || !wide) return;

    const bandRect = bandElement.getBoundingClientRect();
    const coreRect = coreElement.getBoundingClientRect();
    if (bandRect.width < 1 || coreRect.width < 1) return;

    const anchors: BeamAnchor[] = [];
    for (const [key, element] of anchorElements.current) {
      const rect = element.getBoundingClientRect();
      const side: BeamAnchor['side'] = (SCANNER_LEFT_NODES as readonly string[]).includes(key) ? 'left' : 'right';
      anchors.push({
        key,
        x: (side === 'left' ? rect.right : rect.left) - bandRect.left,
        y: rect.top - bandRect.top + rect.height / 2,
        side,
      });
    }

    const next = {
      width: bandRect.width,
      height: bandRect.height,
      anchors,
      target: {
        x: coreRect.left - bandRect.left + coreRect.width / 2,
        y: coreRect.top - bandRect.top + coreRect.height / 2,
        radius: Math.min(coreRect.width, coreRect.height) * 0.47,
      },
    };

    // Bail out when nothing moved — this effect runs on every scan event.
    setGeometry((current) => {
      const same =
        Math.abs(current.width - next.width) < 0.5 &&
        Math.abs(current.height - next.height) < 0.5 &&
        Math.abs(current.target.x - next.target.x) < 0.5 &&
        Math.abs(current.target.y - next.target.y) < 0.5 &&
        current.anchors.length === next.anchors.length &&
        current.anchors.every((anchor, index) => {
          const candidate = next.anchors[index];
          return (
            anchor.key === candidate.key &&
            Math.abs(anchor.x - candidate.x) < 0.5 &&
            Math.abs(anchor.y - candidate.y) < 0.5
          );
        });
      return same ? current : next;
    });
  }, [bandElement, coreElement, bandBounds.width, bandBounds.height, geometryVersion, wide, state.tick]);

  /* ── Packet + audio reactions to real events ───────────────────────────── */

  const packetHandle = React.useRef<PacketEngineHandle | null>(null);
  const [beamPaths, setBeamPaths] = React.useState<BeamPath[]>([]);
  const consumed = React.useRef(0);
  const [alertKey, setAlertKey] = React.useState(0);

  const onPaths = React.useCallback((paths: BeamPath[]) => setBeamPaths(paths), []);

  React.useEffect(() => {
    const events = state.events;
    if (events.length < consumed.current) consumed.current = 0;

    for (let index = consumed.current; index < events.length; index += 1) {
      const event = events[index];
      const alert = isAlertSeverity(event.severity);

      if (event.category !== 'scan') {
        const node = state.nodes[event.category];
        packetHandle.current?.burst({
          beam: event.category,
          color: node ? beamColor(node) : QVE_COLOR.scanning,
          count: packetsForSeverity(event.severity),
          alert,
        });
      } else if (alert) {
        for (const path of beamPaths) {
          const node = state.nodes[path.key];
          if (!node || node.state === 'idle') continue;
          packetHandle.current?.burst({ beam: path.key, color: QVE_COLOR.critical, count: 3, alert: true });
        }
      }

      if (alert) setAlertKey((current) => current + 1);

      if (event.type === 'SCAN_COMPLETED') audio.play('complete', 400);
      else {
        const cue = cueForSeverity(event.severity);
        if (cue) audio.play(cue, 220);
        else if (event.status === 'pass') audio.play('pass', 220);
        else audio.play('packet', 90);
      }
    }
    consumed.current = events.length;
    // `beamPaths` and `audio` are read, not tracked — see the public hero.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.events, state.nodes]);

  /* ── Derived presentation ──────────────────────────────────────────────── */

  const [selected, setSelected] = React.useState<QveNodeKey | null>(null);
  const onSelectNode = React.useCallback(
    (key: QveNodeKey) => setSelected((current) => (current === key ? null : key)),
    [],
  );

  /* External reset — "New Scan" clears the page, and the engine's node
     verdicts, timeline and score ring have to go with it, or the hero would
     keep certifying an estate the rest of the page no longer shows. The engine
     state lives in the provider's reducer, so the page signals rather than
     reaches in. */
  const seenReset = React.useRef(resetSignal);
  React.useEffect(() => {
    if (seenReset.current === resetSignal) return;
    seenReset.current = resetSignal;
    setSelected(null);
    consumed.current = 0;
    dispatch({ type: 'reset' });
  }, [resetSignal, dispatch]);

  /* Per-node evidence for the open card, derived only when a card is open so a
     closed inspector costs nothing during a live scan. */
  const selectedEvidence = React.useMemo(
    () =>
      selected
        ? buildNodeEvidence(selected, {
            results,
            findings: evidenceFindings,
            modules: evidenceModules,
            scanner2,
            targets,
            linked: { cbom: counters.cbom, assets: counters.assets, exposures: counters.exposures },
            scoreComponents,
          })
        : null,
    [selected, results, evidenceFindings, evidenceModules, scanner2, targets, counters, scoreComponents],
  );

  const accent = state.quantumDetected ? QVE_COLOR.quantum : QVE_COLOR.cyan;

  const verdictColor = React.useMemo(() => {
    if (state.run === 'error') return QVE_COLOR.critical;
    if (state.run === 'complete' && state.gradeColor) return state.gradeColor;
    if (state.run === 'complete') return QVE_COLOR.pass;
    return QVE_COLOR.cyan;
  }, [state.run, state.gradeColor]);

  const runningModule = modules.find((module) => module.status === 'Running');

  const statusLabel =
    state.run === 'complete'
      ? 'Scan Complete'
      : state.run === 'error'
        ? 'Scan Failed'
        : state.run === 'scanning'
          ? 'Scanning'
          : 'Standby';

  const statusDetail =
    state.run === 'complete'
      ? state.grade
        ? `Grade ${state.grade}${gradeLabel ? ` · ${gradeLabel}` : ''}`
        : null
      : state.run === 'error'
        ? (state.errorMessage ?? error)
        : state.run === 'scanning'
          ? (runningModule?.name ?? 'Collecting cryptographic evidence')
          : 'Queue an authorized target to begin';

  const latestEntry = state.timeline.length ? state.timeline[state.timeline.length - 1] : null;
  const infraTiles = React.useMemo(
    () =>
      buildScannerInfraTiles({
        targets: summary?.targetsScanned ?? targets.length,
        modules,
        findings: counters.vulnerable,
        components: counters.components,
        cbom: counters.cbom,
        exposures: counters.exposures,
        hasEvidence,
      }),
    [summary?.targetsScanned, targets.length, modules, counters, hasEvidence],
  );
  const consoleOpen = state.run === 'scanning' || state.run === 'complete' || state.run === 'error';

  const leftNodes = SCANNER_LEFT_NODES.map((key) => state.nodes[key]).filter(Boolean);
  const rightNodes = SCANNER_RIGHT_NODES.map((key) => state.nodes[key]).filter(Boolean);

  return (
    <>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[19rem_minmax(0,1fr)]">
        {/* The rail is supporting detail — on a phone the hero comes first. */}
        <div className="order-2 space-y-5 lg:order-1">{railSlot}</div>

        <Panel className="relative order-1 overflow-hidden lg:order-2" glow>
          <QuantumBackdrop
            run={state.run}
            progress={state.run === 'idle' ? 0 : state.progress}
            accent={accent}
            quantum={state.quantumDetected}
            animate={budget.animate}
            dust={budget.dust}
            dustCount={budget.dustCount}
          />

          <div className="relative z-10 px-4 pb-5 pt-5 sm:px-7 sm:pb-6 sm:pt-6">
            {/* ── Header: badge + title | divider | promise ───────────────── */}
            <div className="grid grid-cols-[minmax(0,1fr)] items-start gap-4 lg:grid-cols-[minmax(0,1.12fr)_1px_minmax(0,0.88fr)] lg:gap-7">
              <div className="min-w-0">
                <span className="inline-flex items-center gap-2 rounded-full border border-cyan-400/25 bg-cyan-400/[0.08] px-3 py-1 font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-cyan-300">
                  <ShieldCheck className="h-3 w-3" /> Authenticated enterprise scan
                </span>
                <h1 className="mt-3.5 text-[2rem] font-black leading-[1.06] tracking-tight text-white sm:text-[2.6rem]">
                  Cryptographic Discovery
                </h1>
              </div>

              <div
                aria-hidden
                className="hidden self-stretch bg-gradient-to-b from-transparent via-white/[0.12] to-transparent lg:block"
              />

              <div className="flex min-w-0 flex-col">
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={audio.toggle}
                    aria-pressed={audio.enabled}
                    title={audio.enabled ? 'Mute engine audio cues' : 'Enable engine audio cues'}
                    className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-white/[0.08] bg-[#050a15]/70 px-2.5 py-1.5 font-mono text-[9px] font-bold uppercase tracking-[0.16em] text-slate-500 backdrop-blur transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
                  >
                    {audio.enabled ? <Volume2 className="h-3 w-3" /> : <VolumeX className="h-3 w-3" />}
                    <span className="hidden sm:inline">Audio {audio.enabled ? 'on' : 'off'}</span>
                  </button>
                </div>

                <p className="mt-2.5 min-w-0 max-w-md text-[13.5px] leading-relaxed text-slate-400">
                  Run the platform&apos;s full discovery, TLS, certificate, cipher, code and Scanner_2 enterprise
                  modules across your authorized estate — then feed CBOM, Assets, Exposure and Quantum Readiness from
                  the same evidence.
                </p>
              </div>
            </div>

            {/* ── Visualization band ─────────────────────────────────────── */}
            <div ref={attachBand} className="relative mt-5">
              {wide && geometry.anchors.length > 0 && (
                <>
                  <BeamNetwork
                    width={geometry.width}
                    height={geometry.height}
                    anchors={geometry.anchors}
                    target={geometry.target}
                    nodes={state.nodes}
                    animate={budget.animate}
                    density={budget.tier === 'full' ? 3 : budget.tier === 'balanced' ? 2 : 0}
                    running={state.run === 'scanning'}
                    onPaths={onPaths}
                  />
                  {budget.packets && (
                    <PacketEngine
                      width={Math.round(geometry.width)}
                      height={Math.round(geometry.height)}
                      paths={beamPaths}
                      core={geometry.target}
                      maxPackets={budget.maxPackets}
                      dpr={budget.maxDpr}
                      handleRef={packetHandle}
                    />
                  )}
                </>
              )}

              <div className="relative grid grid-cols-[minmax(0,1fr)] items-center gap-3 lg:grid-cols-[minmax(0,15rem)_minmax(0,1fr)_minmax(0,15rem)] lg:gap-3">
                <div className="order-1 lg:order-2">
                  <CoreStage
                    run={state.run}
                    progress={state.run === 'idle' ? 0 : state.progress}
                    score={state.score}
                    grade={state.grade}
                    accent={accent}
                    verdictColor={verdictColor}
                    quantum={state.quantumDetected}
                    alertKey={alertKey}
                    budget={budget}
                    statusLabel={statusLabel}
                    statusDetail={statusDetail}
                    orbRef={setCoreElement}
                  />
                </div>

                <div className="order-2 grid grid-cols-2 gap-2.5 lg:order-1 lg:grid-cols-[minmax(0,1fr)] lg:gap-3">
                  {leftNodes.map((node) => (
                    <CategoryNode
                      key={node.key}
                      node={node}
                      side="left"
                      selected={selected === node.key}
                      onSelect={onSelectNode}
                      registerAnchor={registerAnchor}
                      animate={budget.animate}
                    />
                  ))}
                </div>

                <div className="order-3 grid grid-cols-2 gap-2.5 lg:grid-cols-[minmax(0,1fr)] lg:gap-3">
                  {rightNodes.map((node) => (
                    <CategoryNode
                      key={node.key}
                      node={node}
                      side="right"
                      selected={selected === node.key}
                      onSelect={onSelectNode}
                      registerAnchor={registerAnchor}
                      animate={budget.animate}
                    />
                  ))}
                </div>
              </div>

              <ScannerNodeInspector
                node={selected ? (state.nodes[selected] ?? null) : null}
                evidence={selectedEvidence}
                onClose={() => setSelected(null)}
                animate={budget.animate}
              />
            </div>

            {/* ── Target composer + run control ──────────────────────────── */}
            <div className="mt-5">{composerSlot}</div>

            <div className="mt-3 flex flex-wrap items-center gap-2">
              {isRunning ? (
                <button
                  type="button"
                  onClick={onCancel}
                  className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-amber-400/40 bg-amber-400/10 px-4 py-2 text-[13px] font-black text-amber-300 transition-colors hover:bg-amber-400/20"
                >
                  <Pause className="h-4 w-4" /> Stop scan
                </button>
              ) : (
                <button
                  type="button"
                  onClick={onStart}
                  disabled={!canStart}
                  className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-emerald-500 px-5 py-2 text-[13px] font-black text-[#04060e] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Play className="h-4 w-4" /> Start Authorized Scan
                </button>
              )}
              {/* New Scan lives beside the run control and is reachable from
                  every tab, because the visualization band is always on screen.
                  Offered only when there is something to clear — an already
                  empty scanner has nothing to reset. */}
              {!isRunning && (hasEvidence || targets.length > 0 || state.run !== 'idle') && (
                <button
                  type="button"
                  onClick={onNewScan}
                  title="Clear this assessment and return the scanner to its ready state. Results stay in History."
                  className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-400/[0.07] px-4 py-2 text-[13px] font-black text-cyan-300 transition-colors hover:border-cyan-400/55 hover:bg-cyan-400/[0.14]"
                >
                  <RotateCcw className="h-4 w-4" /> New Scan
                </button>
              )}
              {isRunning && (
                <span className="inline-flex items-center gap-1.5 font-mono text-[11px] font-bold text-cyan-300">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  {progress}%
                </span>
              )}
            </div>

            {/* ── Strapline, replaced by the live ticker during a scan ───── */}
            <div className="mt-3 min-h-[16px]">
              <AnimatePresence mode="wait" initial={false}>
                {state.run === 'idle' || !latestEntry ? (
                  <motion.p
                    key="strapline"
                    initial={budget.animate ? { opacity: 0 } : false}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[10px] uppercase tracking-[0.14em] text-slate-600"
                  >
                    <span>Authorized targets only</span>
                    <span aria-hidden>·</span>
                    <span>Defensive inventory — no exploitation</span>
                    <span aria-hidden>·</span>
                    <span>Tenant-isolated evidence</span>
                  </motion.p>
                ) : (
                  <motion.div
                    key="ticker"
                    initial={budget.animate ? { opacity: 0 } : false}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.2 }}
                  >
                    <ScanTicker entry={latestEntry} animate={budget.animate} />
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </Panel>
      </div>

      {/* ── Infrastructure strip + live console ─────────────────────────────── */}
      <Panel className="mt-5 overflow-hidden">
        <InfrastructureStrip tiles={infraTiles} animate={budget.animate} />

        <AnimatePresence initial={false}>
          {consoleOpen && (
            <motion.div
              initial={budget.animate ? { height: 0, opacity: 0 } : false}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.32, ease: [0.22, 1, 0.36, 1] }}
              className="overflow-hidden border-t border-white/[0.06]"
            >
              <div className="px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <p className="flex items-center gap-2 font-mono text-[9.5px] font-bold uppercase tracking-[0.2em] text-slate-400">
                    <span
                      className={cn(
                        'h-1.5 w-1.5 rounded-full',
                        state.run === 'scanning' && budget.animate && 'animate-pulse',
                      )}
                      style={{ backgroundColor: verdictColor }}
                    />
                    Live assessment log
                  </p>
                  <p className="font-mono text-[9.5px] uppercase tracking-[0.16em] text-slate-600">
                    {state.timeline.length} event{state.timeline.length === 1 ? '' : 's'}
                  </p>
                </div>
                <div className="mt-2">
                  <ScanTimeline
                    entries={state.timeline}
                    animate={budget.animate}
                    emptyHint="Events appear here as the scanner reports them."
                  />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </Panel>
    </>
  );
}

/* --------------------------------------------------------------------- export - */

export function ScannerHero(props: ScannerHeroProps) {
  return (
    <QveProvider blueprints={SCANNER_NODE_BLUEPRINTS}>
      <HeroInner {...props} />
    </QveProvider>
  );
}
