/**
 * Quantum Simulation Range — run state.
 *
 * WHY THIS EXISTS
 * ---------------
 * The page this replaces drove itself from five independent `setInterval`
 * timers — one advancing the stage, one incrementing a packet counter, one
 * appending log lines, one animating a sparkline, one closing a dropdown. They
 * never agreed with each other, and pausing the simulation stopped only some of
 * them.
 *
 * One reducer owns the run. One requestAnimationFrame loop advances it, so the
 * progress bar, the 3D stage and the evidence panels are reading the same
 * number in the same frame, and "pause" means paused.
 */

import React from 'react';
import { SCENARIOS, type Scenario } from '@/data/scenario';
import { ATTACK_CHAIN, scenarioCrypto, type ScenarioCryptoProfile } from '@/lib/quantum-sim';

/** Seconds each stage holds before auto-advancing. */
export const STAGE_DURATION_SECONDS = 16;

export interface RangeState {
  scenarioId: string;
  /** 1-based stage ordinal. */
  stage: number;
  /** 0..1 through the current stage. */
  progress: number;
  running: boolean;
  /** Set when the user drove the stage by hand; suppresses one auto-advance. */
  manual: boolean;
}

type RangeAction =
  | { type: 'tick'; delta: number }
  | { type: 'set-stage'; stage: number }
  | { type: 'next-stage' }
  | { type: 'previous-stage' }
  | { type: 'toggle-running' }
  | { type: 'set-running'; running: boolean }
  | { type: 'select-scenario'; scenarioId: string };

function clampStage(stage: number): number {
  if (stage < 1) return ATTACK_CHAIN.length;
  if (stage > ATTACK_CHAIN.length) return 1;
  return stage;
}

export function rangeReducer(state: RangeState, action: RangeAction): RangeState {
  switch (action.type) {
    case 'tick': {
      if (!state.running) return state;
      const next = state.progress + action.delta / STAGE_DURATION_SECONDS;
      if (next < 1) return { ...state, progress: next };
      return { ...state, stage: clampStage(state.stage + 1), progress: 0, manual: false };
    }
    case 'set-stage':
      return { ...state, stage: clampStage(action.stage), progress: 0, manual: true };
    case 'next-stage':
      return { ...state, stage: clampStage(state.stage + 1), progress: 0, manual: true };
    case 'previous-stage':
      return { ...state, stage: clampStage(state.stage - 1), progress: 0, manual: true };
    case 'toggle-running':
      return { ...state, running: !state.running };
    case 'set-running':
      return { ...state, running: action.running };
    case 'select-scenario':
      return { ...state, scenarioId: action.scenarioId, stage: 1, progress: 0, manual: true };
    default:
      return state;
  }
}

export interface RangeController {
  state: RangeState;
  scenario: Scenario;
  crypto: ScenarioCryptoProfile;
  setStage: (stage: number) => void;
  nextStage: () => void;
  previousStage: () => void;
  toggleRunning: () => void;
  selectScenario: (scenarioId: string) => void;
}

/**
 * @param animate false under prefers-reduced-motion — the run still advances
 *                when the user asks, but nothing auto-plays.
 */
export function useQuantumRange(animate: boolean): RangeController {
  const [state, dispatch] = React.useReducer(rangeReducer, {
    scenarioId: SCENARIOS[0].id,
    stage: 1,
    progress: 0,
    running: animate,
    manual: false,
  });

  // A single rAF loop. Nothing else on this page owns a timer.
  React.useEffect(() => {
    if (!state.running) return;
    let frame = 0;
    let last = performance.now();
    const tick = (now: number) => {
      const delta = Math.min(0.1, (now - last) / 1000); // clamp: a backgrounded tab must not jump stages
      last = now;
      dispatch({ type: 'tick', delta });
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [state.running]);

  // Auto-play is a motion effect. Honour the preference.
  React.useEffect(() => {
    if (!animate) dispatch({ type: 'set-running', running: false });
  }, [animate]);

  const scenario = React.useMemo(() => SCENARIOS.find((s) => s.id === state.scenarioId) ?? SCENARIOS[0], [state.scenarioId]);
  const crypto = React.useMemo(() => scenarioCrypto(state.scenarioId), [state.scenarioId]);

  return {
    state,
    scenario,
    crypto,
    setStage: React.useCallback((stage: number) => dispatch({ type: 'set-stage', stage }), []),
    nextStage: React.useCallback(() => dispatch({ type: 'next-stage' }), []),
    previousStage: React.useCallback(() => dispatch({ type: 'previous-stage' }), []),
    toggleRunning: React.useCallback(() => dispatch({ type: 'toggle-running' }), []),
    selectScenario: React.useCallback((scenarioId: string) => dispatch({ type: 'select-scenario', scenarioId }), []),
  };
}

/* ═══════════════════════════════════════════════════════════════ live clock */

/**
 * A once-per-second clock for the milestone countdown. One interval for the
 * whole page rather than one per counter.
 */
export function useSecondsClock(enabled = true): number {
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    if (!enabled) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [enabled]);
  return now;
}

/**
 * Defer heavy work until the section scrolls into view. The Shor simulator, the
 * PQC benchmark and the WebGL stage all cost real CPU; none of them should run
 * for a visitor who never scrolls that far.
 *
 * WHY THIS IS NOT JUST AN INTERSECTION OBSERVER
 * ---------------------------------------------
 * IntersectionObserver callbacks are delivered by the rendering pipeline, so a
 * context that never composites — a background tab, a hidden pane, an embedded
 * webview, a print render — can leave them silent indefinitely. A section whose
 * only activation path is an observer callback then shows its "not run yet"
 * empty state forever, which is exactly the failure this page must not have:
 * its whole claim is that the numbers are computed, not typed.
 *
 * So the observer is the fast path, and a geometry check on scroll is the
 * guarantee. Whichever fires first wins, and both are torn down together.
 */
export function useInView<T extends HTMLElement>(rootMargin = '200px'): [React.RefObject<T | null>, boolean] {
  const ref = React.useRef<T>(null);
  const [visible, setVisible] = React.useState(false);
  const margin = Number.parseInt(rootMargin, 10) || 0;

  React.useEffect(() => {
    if (visible) return;
    const node = ref.current;
    if (!node) return;

    let cancelled = false;
    const reveal = () => {
      if (cancelled) return;
      cancelled = true;
      setVisible(true);
    };

    /** The guarantee: pure geometry, no dependency on the compositor. */
    const check = () => {
      if (cancelled) return;
      const rect = node.getBoundingClientRect();
      const viewport = window.innerHeight || document.documentElement.clientHeight;
      if (rect.top - margin < viewport && rect.bottom + margin > 0) reveal();
    };

    let observer: IntersectionObserver | undefined;
    if (typeof IntersectionObserver !== 'undefined') {
      observer = new IntersectionObserver(
        (entries) => {
          if (entries.some((entry) => entry.isIntersecting)) reveal();
        },
        { rootMargin },
      );
      observer.observe(node);
    }

    window.addEventListener('scroll', check, { passive: true });
    window.addEventListener('resize', check, { passive: true });
    // Also check once on the next frame, for a section already in view at load.
    const frame = requestAnimationFrame(check);

    return () => {
      cancelled = true;
      cancelAnimationFrame(frame);
      observer?.disconnect();
      window.removeEventListener('scroll', check);
      window.removeEventListener('resize', check);
    };
  }, [margin, rootMargin, visible]);

  return [ref, visible];
}

/* ═══════════════════════════════════════════════════════════════════ run log */

/**
 * The live telemetry feed.
 *
 * The page this replaces had a beautiful terminal panel that printed invented
 * shell sessions — `sys@qstack:~$ shor-solver --derive-private-key`, followed
 * by a period for RSA-2048 that was not the period of anything. The panel was
 * the best-looking thing on the page and the least true.
 *
 * The aesthetic is worth keeping; the fabrication is not. This feed carries
 * only events that actually happened in this session, with the numbers those
 * events actually produced: gate counts from the simulator, byte lengths from
 * FIPS 203 key generation, milliseconds from `performance.now()`. Nothing is
 * emitted on a timer, so a quiet feed means nothing is happening — which is
 * itself information the old one could never convey.
 */

export type RunLogLevel = 'info' | 'measure' | 'alert' | 'good';

export interface RunLogEntry {
  id: number;
  /** Wall-clock time the event occurred. */
  at: Date;
  level: RunLogLevel;
  /** Which engine produced it. */
  source: string;
  text: string;
}

export interface RunLogEmit {
  (level: RunLogLevel, source: string, text: string): void;
}

/** Panels emit through context so the feed does not have to be prop-drilled. */
export const RunLogContext = React.createContext<RunLogEmit>(() => {});

export function useEmit(): RunLogEmit {
  return React.useContext(RunLogContext);
}

const MAX_ENTRIES = 60;

export function useRunLog(): { entries: RunLogEntry[]; emit: RunLogEmit; clear: () => void } {
  const [entries, setEntries] = React.useState<RunLogEntry[]>([]);
  const nextId = React.useRef(1);

  const emit = React.useCallback<RunLogEmit>((level, source, text) => {
    setEntries((previous) => {
      const entry: RunLogEntry = { id: nextId.current++, at: new Date(), level, source, text };
      return [entry, ...previous].slice(0, MAX_ENTRIES);
    });
  }, []);

  const clear = React.useCallback(() => setEntries([]), []);

  return { entries, emit, clear };
}
