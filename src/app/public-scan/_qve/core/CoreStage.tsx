/**
 * Quantum Visualization Engine™ — Core Stage.
 *
 * Composes the centre of the hero: the live verdict readout, the holographic
 * Quantum Core (WebGL, lazy), and the SVG score ring / quantum wave over it.
 *
 * Three guarantees this component exists to provide:
 *  1. NEVER BLANK. If WebGL is unavailable, the module fails to load, or the
 *     GL context is lost, an error boundary swaps in a fully-styled SVG core.
 *     The hero's data layer is unaffected either way.
 *  2. NEVER LIE. The readout is derived from engine state only — "Standby"
 *     until a scan starts, real progress while it runs, the published grade
 *     when it lands, and the failure reason when it does not.
 *  3. NEVER STATIC. Per the engine spec the core stays alive at rest; the idle
 *     state runs a reduced drift rather than freezing.
 *
 * Readout placement: the verdict sits in its own instrument bar ABOVE the orb
 * rather than floating inside the ring. Overlaying the hologram cost the core
 * its most legible region and forced a scrim over the very thing the engine
 * renders; a dedicated bar keeps the number unambiguous, keeps the orb whole,
 * and gives the grade somewhere to live that is not competing with geometry.
 */
'use client';

import React from 'react';
import { motion } from 'motion/react';
import { cn } from '@/lib/utils';
import type { QveBudget } from '../performance-manager';
import { useAdaptiveDpr } from '../performance-manager';
import { QVE_COLOR, type QveRunState } from '../types';
import { ScoreRing } from './ScoreRing';

const QuantumCore3D = React.lazy(() => import('./QuantumCore3D'));

export interface CoreStageProps {
  run: QveRunState;
  progress: number;
  score: number;
  grade: string | null;
  /**
   * Structural accent for the hologram itself. Restricted to the engine's
   * blue / violet / cyan band — the design language forbids anything else in
   * the core, so a poor grade must not turn the whole shield amber.
   */
  accent: string;
  /**
   * Verdict colour. Drives ONLY the score arc, the readout and the grade line —
   * the three places where a number is being reported and the colour is
   * therefore information rather than decoration.
   */
  verdictColor: string;
  quantum: boolean;
  /** Increments on each genuine high/critical finding. */
  alertKey: number;
  budget: QveBudget;
  /** Status line, e.g. "Scan Complete". */
  statusLabel: string;
  /** Secondary line, e.g. the grade band or failure reason. */
  statusDetail: string | null;
  /**
   * Ref onto the ORB itself — deliberately not the whole stage. The hero
   * measures this element to aim the beam network at the score ring's bezel,
   * so it must stay the square that contains the ring and nothing else. Handing
   * it the outer wrapper would drag the beam target up into the verdict bar.
   */
  orbRef?: React.Ref<HTMLDivElement>;
}

/* ------------------------------------------------------------ error boundary - */

interface BoundaryState {
  failed: boolean;
}

/**
 * Contains anything WebGL can throw — a lost context, a shader compile failure,
 * a postprocessing effect that a driver refuses. The hero must degrade, never
 * white-screen, because this is the anonymous front door.
 */
class CoreBoundary extends React.Component<{ fallback: React.ReactNode; children: React.ReactNode }, BoundaryState> {
  state: BoundaryState = { failed: false };

  static getDerivedStateFromError(): BoundaryState {
    return { failed: true };
  }

  componentDidCatch(error: unknown) {
    // Diagnostic only — never surfaced to the visitor.
    console.warn('[qve] quantum core unavailable, using SVG fallback', error);
  }

  render() {
    return this.state.failed ? this.props.fallback : this.props.children;
  }
}

/* ----------------------------------------------------------- svg fallback core - */

const SHIELD_PATH =
  'M100 14 C124 15 141 24 149 32 L149 82 C149 122 126 150 100 166 C74 150 51 122 51 82 L51 32 C59 24 76 15 100 14 Z';

function FallbackCore({ accent, animate, quantum }: { accent: string; animate: boolean; quantum: boolean }) {
  return (
    <svg viewBox="0 0 200 200" className="h-full w-full" aria-hidden>
      <defs>
        <radialGradient id="qve-fallback-globe">
          <stop offset="0%" stopColor="#1d5fd0" />
          <stop offset="70%" stopColor="#0a2f6d" />
          <stop offset="100%" stopColor="#04122e" />
        </radialGradient>
        <linearGradient id="qve-fallback-shield" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={accent} stopOpacity="0.22" />
          <stop offset="100%" stopColor={quantum ? QVE_COLOR.quantum : '#1e40af'} stopOpacity="0.08" />
        </linearGradient>
      </defs>

      <path d={SHIELD_PATH} fill="url(#qve-fallback-shield)" stroke={accent} strokeWidth={1.6} opacity={0.9} />

      <g transform="translate(100 88)">
        <circle r={31} fill="url(#qve-fallback-globe)" />
        <circle r={31} fill="none" stroke={accent} strokeWidth={0.7} opacity={0.55} />
        {/* Latitudes */}
        {[-18, -9, 0, 9, 18].map((offset) => (
          <ellipse key={offset} cy={offset} rx={Math.sqrt(Math.max(1, 31 * 31 - offset * offset))} ry={4.4} fill="none" stroke={accent} strokeWidth={0.5} opacity={0.35} />
        ))}
        {/* Longitudes */}
        {[6, 14, 22, 31].map((radius) => (
          <ellipse key={radius} rx={radius} ry={31} fill="none" stroke={accent} strokeWidth={0.5} opacity={0.3} />
        ))}
        {animate && (
          <circle r={31} fill="none" stroke={accent} strokeWidth={1.2} opacity={0.5}>
            <animate attributeName="r" values="14;34;14" dur="4s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.5;0;0.5" dur="4s" repeatCount="indefinite" />
          </circle>
        )}
      </g>
    </svg>
  );
}

/* --------------------------------------------------------------------- stage - */

export const CoreStage = React.memo(function CoreStage({
  run,
  progress,
  score,
  grade,
  accent,
  verdictColor,
  quantum,
  alertKey,
  budget,
  statusLabel,
  statusDetail,
  orbRef,
}: CoreStageProps) {
  const active = run === 'scanning';
  const dpr = useAdaptiveDpr(budget.maxDpr, budget.core3d);
  // The SVG core stays visible until WebGL confirms it is live, then cross-fades
  // out. See `onReady` in QuantumCore3D for why "mounted" is not "running".
  const [coreReady, setCoreReady] = React.useState(false);
  const onCoreReady = React.useCallback(() => setCoreReady(true), []);

  const fallback = (
    <div className="absolute inset-[19%] grid place-items-center">
      <FallbackCore accent={accent} animate={budget.animate} quantum={quantum} />
    </div>
  );

  // The headline number: live progress while scanning, the settled score
  // afterwards. Rounded from engine state — never counted by a timer.
  const readout = run === 'complete' ? score : progress;

  return (
    // `@container`: the stage sits in the ring's middle column, which is the
    // first thing to lose width at the bottom of the lg range. The verdict bar
    // therefore responds to ITS OWN width, not the viewport's — a media query
    // cannot see that a 1024px viewport leaves this column under 6rem.
    <div className="@container flex w-full flex-col items-center">
      {/* ── Verdict bar ──────────────────────────────────────────────────────
          The engine's headline instrument: run state, the live number, and the
          published grade band, read left-to-right in one pass. Sits above the
          orb so the hologram is never obscured by the value it is reporting. */}
      <div
        className="relative z-10 mx-auto w-full max-w-[26rem] rounded-2xl border bg-[#040810]/80 px-2.5 py-2.5 backdrop-blur-md @[15rem]:px-3.5"
        style={{
          borderColor: `${verdictColor}33`,
          boxShadow: `0 0 34px -20px ${verdictColor}, inset 0 1px 0 rgba(255,255,255,0.05)`,
        }}
      >
        {/* Hairline that fills with real progress — the bar reads as an
            instrument face rather than a label. */}
        <span
          aria-hidden
          className="pointer-events-none absolute inset-x-3 top-0 h-px overflow-hidden rounded-full"
        >
          <span
            className="block h-full transition-[width] duration-500 ease-out"
            style={{
              width: `${Math.max(0, Math.min(100, run === 'idle' ? 0 : progress))}%`,
              background: `linear-gradient(90deg, ${accent}, ${verdictColor})`,
            }}
          />
        </span>

        <div className="flex flex-col gap-1 @[15rem]:flex-row @[15rem]:items-center @[15rem]:gap-3">
          <div className="min-w-0 flex-1">
            <motion.p
              key={statusLabel}
              initial={budget.animate ? { opacity: 0, y: -4 } : false}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35 }}
              className="flex items-center gap-1.5 font-mono text-[9.5px] font-bold uppercase tracking-[0.24em]"
              style={{ color: verdictColor }}
            >
              <span
                aria-hidden
                className={cn('h-1.5 w-1.5 shrink-0 rounded-full', active && budget.animate && 'animate-pulse')}
                style={{ backgroundColor: verdictColor, boxShadow: `0 0 8px ${verdictColor}` }}
              />
              <span className="truncate">{statusLabel}</span>
            </motion.p>
            {statusDetail && (
              <p
                title={statusDetail}
                className="mt-1 line-clamp-2 text-[11px] font-semibold leading-tight text-slate-300"
              >
                {statusDetail}
              </p>
            )}
          </div>

          <span aria-hidden className="hidden h-9 w-px shrink-0 bg-white/[0.09] @[15rem]:block" />

          <div className="flex shrink-0 items-baseline">
            <span
              className="text-[1.7rem] font-black leading-none tracking-tighter tabular-nums @[15rem]:text-[2.35rem]"
              style={{ color: verdictColor, textShadow: `0 0 30px ${verdictColor}55, 0 2px 12px rgba(0,0,0,0.9)` }}
            >
              {Math.round(readout)}
            </span>
            <span className="text-[0.95rem] font-bold" style={{ color: verdictColor, opacity: 0.7 }}>
              %
            </span>
          </div>
        </div>
      </div>

      {/* ── Orb ─────────────────────────────────────────────────────────────
          Measured by the hero for beam geometry — keep it the ring's square. */}
      <div ref={orbRef} className="relative mt-3 aspect-square w-full max-w-[26rem]">
        {/* Ambient bloom bed so the core sits in light rather than on top of it. */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 rounded-full"
          style={{
            background: `radial-gradient(circle at 50% 48%, ${accent}22, transparent 62%)`,
            filter: 'blur(18px)',
          }}
        />

        {budget.core3d ? (
          <CoreBoundary fallback={fallback}>
            {/* Base layer: never an empty core, whatever WebGL decides to do. */}
            <div
              aria-hidden
              className="pointer-events-none transition-opacity duration-700"
              style={{ opacity: coreReady ? 0 : 1 }}
            >
              {fallback}
            </div>
            <React.Suspense fallback={null}>
              <div className="qve-surface absolute inset-[6%]">
                <QuantumCore3D
                  intensity={Math.max(0, Math.min(1, progress / 100))}
                  accent={accent}
                  quantum={quantum}
                  alertKey={alertKey}
                  active={active}
                  budget={budget}
                  dpr={dpr}
                  onReady={onCoreReady}
                />
              </div>
            </React.Suspense>
          </CoreBoundary>
        ) : (
          fallback
        )}

        <ScoreRing
          progress={progress}
          score={run === 'complete' ? score : progress}
          grade={grade}
          accent={accent}
          verdictColor={verdictColor}
          active={active}
          animate={budget.animate}
        />

      </div>
    </div>
  );
});
