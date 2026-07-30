/**
 * Quantum Visualization Engine™ — Core Stage.
 *
 * Composes the centre of the hero: the holographic Quantum Core (WebGL, lazy),
 * the SVG score ring / quantum wave over it, and the live status readout.
 *
 * Three guarantees this component exists to provide:
 *  1. NEVER BLANK. If WebGL is unavailable, the module fails to load, or the
 *     GL context is lost, an error boundary swaps in a fully-styled SVG core.
 *     The hero's data layer is unaffected either way.
 *  2. NEVER LIE. The readout under the core is derived from engine state only —
 *     "Standby" until a scan starts, real progress while it runs, the published
 *     grade when it lands, and the failure reason when it does not.
 *  3. NEVER STATIC. Per the engine spec the core stays alive at rest; the idle
 *     state runs a reduced drift rather than freezing.
 */
'use client';

import React from 'react';
import { motion } from 'motion/react';
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
  accent: string;
  quantum: boolean;
  /** Increments on each genuine high/critical finding. */
  alertKey: number;
  budget: QveBudget;
  /** Status line under the core, e.g. "Scan Complete". */
  statusLabel: string;
  /** Secondary line, e.g. the grade band or failure reason. */
  statusDetail: string | null;
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
  quantum,
  alertKey,
  budget,
  statusLabel,
  statusDetail,
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

  // The number under the core: live progress while scanning, the settled score
  // afterwards. Rounded from engine state — never counted by a timer.
  const readout = run === 'complete' ? score : progress;

  return (
    <div className="relative mx-auto aspect-square w-full max-w-[26rem]">
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
        active={active}
        animate={budget.animate}
      />

      {/* Live readout. Sits in the lower third of the ring, exactly as the
          reference hero, and is real text so it stays crisp and readable. */}
      <div className="pointer-events-none absolute inset-x-0 bottom-[16%] flex flex-col items-center gap-1 text-center">
        <motion.span
          key={statusLabel}
          initial={budget.animate ? { opacity: 0, y: 6 } : false}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
          className="font-mono text-[10.5px] font-bold uppercase tracking-[0.28em]"
          style={{ color: accent }}
        >
          {statusLabel}
        </motion.span>
        <span
          className="text-[2.35rem] font-black leading-none tracking-tighter"
          style={{ color: accent, textShadow: `0 0 26px ${accent}66` }}
        >
          {Math.round(readout)}
          <span className="align-super text-[0.42em] font-bold opacity-70">%</span>
        </span>
        {statusDetail && (
          <span className="max-w-[12rem] text-[10.5px] font-semibold leading-tight text-slate-400">
            {statusDetail}
          </span>
        )}
      </div>
    </div>
  );
});
