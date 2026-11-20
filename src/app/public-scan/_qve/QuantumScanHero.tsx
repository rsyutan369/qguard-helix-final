/**
 * Quantum Visualization Engine™ — Public Scan hero.
 *
 * The composition root for the /public-scan hero: workflow rail, live
 * visualization band (six category nodes ringed around the holographic Quantum
 * Core, joined by SVG beams carrying GPU energy packets), target input, live
 * event ticker, and the infrastructure strip.
 *
 * Contract with the page: this component owns ONLY the hero. It takes the scan
 * state it should visualise, the target input it should drive, and the existing
 * rail as a slot — every results panel below stays exactly where it was, with
 * its own logic untouched.
 *
 * Layout note: beams are rendered only at `lg` and above, where the three-column
 * ring actually exists. On a phone the nodes stack beneath the core in a 2-up
 * grid and the beam layer is not mounted at all — drawing connectors across a
 * stacked layout produces noise, not information.
 */
'use client';

import React from 'react';
import { AnimatePresence, motion } from 'motion/react';
import useMeasure from 'react-use-measure';
import { Globe, Loader2, Search, Volume2, VolumeX } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { PublicScanReport } from '@/lib/scanner/public-scan/types';
import type { UsePublicScanResult } from '@/hooks/use-public-scan';
import { Panel } from '../_ui';
import { QuantumBackdrop } from './background/QuantumBackdrop';
import type { BeamAnchor, BeamPath, BeamTarget } from './beams/beam-geometry';
import { BeamNetwork } from './beams/BeamNetwork';
import { CoreStage } from './core/CoreStage';
import { CategoryNode } from './nodes/CategoryNode';
import { NodeInspector } from './nodes/NodeInspector';
import { PacketEngine, type PacketEngineHandle } from './packets/PacketEngine';
import { useQveBudget } from './performance-manager';
import { cueForSeverity, useQveAudio } from './audio-manager';
import {
  QVE_LEFT_NODES,
  QVE_RIGHT_NODES,
  QveProvider,
  useQveState,
} from './scan-event-store';
import { buildInfraTiles, InfrastructureStrip } from './strip/InfrastructureStrip';
import { ScanTicker, ScanTimeline } from './timeline/ScanTimeline';
import { useScanEventBridge } from './use-scan-event-bridge';
import { beamColor, isAlertSeverity, QVE_COLOR, readableOn, type QveNodeKey } from './types';
import { qveAccentOn, useQvePalette } from './theme';

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

/** How many packets an observation is worth — alerts burst harder. */
function packetsForSeverity(severity: string): number {
  if (severity === 'critical') return 7;
  if (severity === 'high') return 5;
  if (severity === 'medium') return 3;
  return 2;
}

export interface QuantumScanHeroProps {
  scan: UsePublicScanResult;
  report: PublicScanReport | null;
  /** Controlled target input. */
  target: string;
  onTargetChange: (value: string) => void;
  onSubmit: (event: React.FormEvent) => void;
  disabled: boolean;
  targetRequired: boolean;
  targetError?: string;
  accessStatus: React.ReactNode;
  /** The existing workflow rail + enterprise CTA, rendered in the left column. */
  railSlot: React.ReactNode;
}

/* ---------------------------------------------------------------------- inner - */

function HeroInner({
  scan, report, target, onTargetChange, onSubmit, disabled, targetRequired, targetError, accessStatus, railSlot,
}: QuantumScanHeroProps) {
  const budget = useQveBudget();
  const wide = useIsWide();
  const audio = useQveAudio();
  const state = useQveState();
  const palette = useQvePalette();

  // Bind the real SSE stream into the engine's event store.
  useScanEventBridge({
    state: scan.state,
    stages: scan.stages,
    report,
    observations: scan.observations,
    progress: scan.progress,
    error: scan.error,
    refused: scan.refusal !== null,
    asset: report?.target.displayUrl ?? target.trim(),
    reducedMotion: !budget.animate,
  });

  /* ── Geometry ──────────────────────────────────────────────────────────── */

  // `react-use-measure` observes the band and is the *trigger* for a re-measure
  // on resize and scroll. It is deliberately NOT the source of the numbers: a
  // ResizeObserver only delivers during a rendering opportunity, so gating the
  // beam layer on its bounds means the beams never appear in an environment that
  // is laid out but not compositing (a background tab, a hidden preview pane, a
  // print pass). The geometry below is read straight from the live layout in a
  // layout effect, which is always available, and `bandBounds` only nudges it.
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
      const side: BeamAnchor['side'] = QVE_LEFT_NODES.includes(key) ? 'left' : 'right';
      anchors.push({
        key,
        // Tap the card edge that faces the core, vertically centred.
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
        // Beams terminate on the score ring's outer bezel, not the canvas edge.
        radius: Math.min(coreRect.width, coreRect.height) * 0.47,
      },
    };

    // Bail out when nothing moved: this effect runs on every scan event, and an
    // unconditional setState would re-render the whole hero ~25 times per scan
    // for no visual change.
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
    // `state.tick` is here on purpose: node cards grow and shrink as their
    // evidence lines populate, which moves the beam taps. Six
    // getBoundingClientRect reads per event is far cheaper than a ResizeObserver
    // per card, and it keeps the beams welded to the cards at every state change.
  }, [bandElement, coreElement, bandBounds.width, bandBounds.height, geometryVersion, wide, state.tick]);

  /* ── Packet + audio reactions to real events ───────────────────────────── */

  const packetHandle = React.useRef<PacketEngineHandle | null>(null);
  const [beamPaths, setBeamPaths] = React.useState<BeamPath[]>([]);
  const consumed = React.useRef(0);
  const [alertKey, setAlertKey] = React.useState(0);

  const onPaths = React.useCallback((paths: BeamPath[]) => setBeamPaths(paths), []);

  React.useEffect(() => {
    const events = state.events;
    // A reset shrinks the array — rewind rather than replaying history.
    if (events.length < consumed.current) consumed.current = 0;

    for (let index = consumed.current; index < events.length; index += 1) {
      const event = events[index];
      const alert = isAlertSeverity(event.severity);

      if (event.category !== 'scan') {
        const node = state.nodes[event.category];
        packetHandle.current?.burst({
          beam: event.category,
          color: node ? beamColor(node, palette.surface) : qveAccentOn(QVE_COLOR.scanning, palette),
          count: packetsForSeverity(event.severity),
          alert,
        });
      } else if (alert) {
        // A run-level finding energises every live beam at once.
        for (const path of beamPaths) {
          const node = state.nodes[path.key as QveNodeKey];
          if (!node || node.state === 'idle') continue;
          packetHandle.current?.burst({ beam: path.key, color: QVE_COLOR.critical, count: 3, alert: true });
        }
      }

      if (alert) setAlertKey((current) => current + 1);

      // Audio: severity cue when there is one, otherwise a soft packet blip.
      if (event.type === 'SCAN_COMPLETED') audio.play('complete', 400);
      else {
        const cue = cueForSeverity(event.severity);
        if (cue) audio.play(cue, 220);
        else if (event.status === 'pass') audio.play('pass', 220);
        else audio.play('packet', 90);
      }
    }
    consumed.current = events.length;
    // `beamPaths` and `audio` are read, not tracked: re-running on a geometry
    // change would replay bursts for events already consumed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.events, state.nodes]);

  /* ── Derived presentation ──────────────────────────────────────────────── */

  const [selected, setSelected] = React.useState<QveNodeKey | null>(null);
  const onSelectNode = React.useCallback(
    (key: QveNodeKey) => setSelected((current) => (current === key ? null : key)),
    [],
  );

  /**
   * TWO accents, deliberately.
   *
   * `accent` is structural — the hologram, beams, backdrop and node chrome. The
   * design language restricts the engine to blue / violet / cyan, so it only
   * ever shifts to violet, and only when hybrid post-quantum evidence has
   * actually been observed. A C- grade must not repaint the whole hero amber.
   *
   * `verdictColor` is informational — the score arc, the readout and the grade
   * line. There the colour IS the finding, so it follows the published grade
   * table exactly.
   */
  const accent = qveAccentOn(state.quantumDetected ? QVE_COLOR.quantum : QVE_COLOR.cyan, palette);

  /* Neither waiting in line nor being refused is a finding about the target,
     so neither may wear a verdict colour or claim evidence is being collected. */
  const refused = state.run === 'error' && scan.refusal !== null;
  const waiting = state.run === 'scanning' && scan.queue !== null;

  const verdictColor = React.useMemo(() => {
    const published =
      refused
        ? QVE_COLOR.idle
        : state.run === 'error'
          ? QVE_COLOR.critical
          : state.run === 'complete'
            ? (state.gradeColor ?? QVE_COLOR.pass)
            : QVE_COLOR.cyan;
    /* The published grade colour, re-lit for the ground it is printed on. The
       grade itself never changes — only the lightness it is rendered at. */
    return readableOn(published, palette.surface);
  }, [refused, state.run, state.gradeColor, palette.surface]);

  const runningStage = scan.stages.find((stage) => stage.state === 'running');

  const statusLabel =
    state.run === 'complete'
      ? 'Scan Complete'
      : refused
        ? 'Not Started'
        : state.run === 'error'
          ? 'Scan Failed'
          : waiting
            ? 'Waiting in Line'
            : state.run === 'scanning'
              ? 'Scanning'
              : 'Standby';

  const statusDetail =
    state.run === 'complete'
      ? report
        ? `Grade ${report.executive.grade} · ${report.executive.gradeLabel}`
        : null
      : state.run === 'error'
        ? (state.errorMessage ?? scan.error)
        : waiting && scan.queue
          ? `${scan.queue.position === 1 ? 'Next in line' : `#${scan.queue.position} in line`} · ${scan.queue.running} of ${scan.queue.capacity} assessments running`
          : state.run === 'scanning'
            ? (runningStage?.label ?? 'Collecting edge evidence')
            : 'Enter a domain to begin';

  const latestEntry = state.timeline.length ? state.timeline[state.timeline.length - 1] : null;
  const infraTiles = React.useMemo(() => buildInfraTiles(report), [report]);
  const consoleOpen = state.run === 'scanning' || state.run === 'complete' || state.run === 'error';

  const leftNodes = QVE_LEFT_NODES.map((key) => state.nodes[key]);
  const rightNodes = QVE_RIGHT_NODES.map((key) => state.nodes[key]);

  return (
    <>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[19rem_minmax(0,1fr)]">
        {/* The rail is supporting detail — on a phone the hero and its input
            must come first. Order is preserved from the original layout. */}
        <div className="order-2 space-y-5 lg:order-1" data-lp-reveal>{railSlot}</div>

        <Panel className="public-scan-console relative order-1 overflow-hidden lg:order-2" glow>
          <QuantumBackdrop
            run={state.run}
            progress={state.run === 'idle' ? 0 : state.progress}
            accent={accent}
            quantum={state.quantumDetected}
            animate={budget.animate}
            dust={budget.dust}
            dustCount={budget.dustCount}
          />

          <div className="relative z-10 px-4 pb-5 pt-5 sm:px-7 sm:pb-7 sm:pt-7">
            <div className="grid grid-cols-[minmax(0,1fr)] items-start gap-4 lg:grid-cols-[minmax(0,1.12fr)_1px_minmax(0,0.88fr)] lg:gap-7">
              <h1 className="public-scan-title text-white">Quantum Exposure Assessment</h1>

              <div aria-hidden className="hidden self-stretch bg-gradient-to-b from-transparent via-white/[0.12] to-transparent lg:block" />

              {/* Engine audio is opt-in and out of the reading path. It gets its
                  own row at the top of this column rather than floating over
                  the panel corner: as an overlay it landed on the first line of
                  the promise copy, and a control that obscures the explanation
                  of what the scan does is worse than no control at all. */}
              <div className="flex min-w-0 flex-col">
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={audio.toggle}
                    aria-pressed={audio.enabled}
                    aria-label="Engine audio cues"
                    title={audio.enabled ? 'Mute engine audio cues' : 'Enable engine audio cues'}
                    className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-white/[0.08] bg-[#050a15]/70 px-2.5 py-1.5 font-mono text-[9px] font-bold uppercase tracking-[0.16em] text-slate-500 backdrop-blur transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
                  >
                    {audio.enabled ? <Volume2 className="h-3 w-3" /> : <VolumeX className="h-3 w-3" />}
                    <span className="hidden sm:inline">Audio {audio.enabled ? 'on' : 'off'}</span>
                  </button>
                </div>

                <p className="mt-2.5 min-w-0 max-w-md text-[13.5px] leading-relaxed text-slate-400">
                  Analyze your Internet-facing cryptographic posture, identify post-quantum migration readiness,
                  and estimate enterprise risk — from publicly observable evidence only.
                </p>
              </div>
            </div>

            {/* ── Target input ───────────────────────────────────────────── */}
            <form onSubmit={onSubmit} className="mt-5">
              <label htmlFor="public-scan-target" className="public-scan-target-label">Domain or HTTPS URL</label>
              <div className="public-scan-form">
                <div className="public-scan-target">
                  <Globe aria-hidden="true" className="h-4 w-4 shrink-0" />
                  <input
                    id="public-scan-target"
                    className="public-scan-target-input"
                    value={target}
                    onChange={(event) => onTargetChange(event.target.value)}
                    placeholder="https://company.com"
                    autoComplete="url"
                    inputMode="url"
                    spellCheck={false}
                    maxLength={269}
                    required={targetRequired}
                    aria-invalid={targetError ? true : undefined}
                    aria-describedby={targetError ? 'public-scan-target-error' : undefined}
                  />
                </div>
                <button
                  type="submit"
                  disabled={disabled || scan.state === 'scanning'}
                  className="public-scan-primary inline-flex items-center justify-center gap-1.5 rounded-lg px-3.5 text-[13px] font-bold disabled:cursor-not-allowed disabled:opacity-60 sm:px-5"
                >
                  {scan.state === 'scanning' ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" /> Analyzing
                    </>
                  ) : (
                    <>
                      <Search className="h-4 w-4" /> Analyze Now
                    </>
                  )}
                </button>
              </div>
              {targetError && <p className="public-scan-target-error" id="public-scan-target-error" role="alert">{targetError}</p>}
              {accessStatus}
            </form>

            {/* ── Visualization band ─────────────────────────────────────── */}
            <div ref={attachBand} className="relative mt-5">
              {/* Beam + packet layers sit behind the cards but above the
                  backdrop, and only exist in the three-column ring layout. */}
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
                      palette={palette}
                    />
                  )}
                </>
              )}

              {/* 15rem columns are the minimum that fits "QUANTUM READINESS"
                  and "OCSP STAPLING" without the title ellipsing — the card
                  titles are the labels for the whole visualization and must
                  never be truncated. */}
              <div className="relative grid grid-cols-[minmax(0,1fr)] items-center gap-3 lg:grid-cols-[minmax(0,15rem)_minmax(0,1fr)_minmax(0,15rem)] lg:gap-3">
                {/* Core first in DOM order so it leads on a phone, then
                    re-ordered into the middle column at lg. */}
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
                    // Beams aim at the ORB, not the whole stage — the verdict
                    // bar above it must not drag the beam target off-centre.
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

              <NodeInspector
                node={selected ? state.nodes[selected] : null}
                report={report}
                onClose={() => setSelected(null)}
                animate={budget.animate}
              />
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
                    <span>Results in seconds</span>
                    <span aria-hidden>·</span>
                    <span>Public evidence only</span>
                    <span aria-hidden>·</span>
                    <span>Privacy-first logging</span>
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
                      className={cn('h-1.5 w-1.5 rounded-full', state.run === 'scanning' && budget.animate && 'animate-pulse')}
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

export function QuantumScanHero(props: QuantumScanHeroProps) {
  return (
    <QveProvider>
      <HeroInner {...props} />
    </QveProvider>
  );
}
