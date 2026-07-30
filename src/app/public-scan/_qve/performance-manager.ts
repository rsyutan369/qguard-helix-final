/**
 * Quantum Visualization Engine™ — Performance Manager.
 *
 * One place decides how much of the engine runs, so a low-end phone or a user
 * who asked for reduced motion never pays for effects they cannot use. Every
 * heavy subsystem (Three.js core, PixiJS packets, tsParticles field) reads its
 * budget from here rather than deciding for itself.
 *
 * Tiers:
 *   full     — WebGL2, ≥8 logical cores or ≥8GB RAM, desktop pointer.
 *   balanced — WebGL available, mid-range device. Fewer particles, no god rays.
 *   light    — no WebGL, low memory, or a small touch device. SVG/CSS only.
 *   static   — prefers-reduced-motion. Nothing animates; all state still renders.
 */
'use client';

import React from 'react';

export type QveTier = 'full' | 'balanced' | 'light' | 'static';

export interface QveBudget {
  tier: QveTier;
  /** Mount the Three.js holographic core. */
  core3d: boolean;
  /** Mount the PixiJS packet engine. */
  packets: boolean;
  /** Mount the tsParticles quantum-dust field. */
  dust: boolean;
  /** Bloom / god rays in the 3D core. */
  postFx: boolean;
  /** Device pixel ratio ceiling for WebGL canvases. */
  maxDpr: number;
  /** Instanced quantum particles inside the core. */
  coreParticles: number;
  /** Simultaneous energy packets in flight. */
  maxPackets: number;
  /** Background dust particle count. */
  dustCount: number;
  /** Emit the 3-second radar sweep. */
  radar: boolean;
  /** Any motion at all. */
  animate: boolean;
}

const BUDGETS: Record<QveTier, Omit<QveBudget, 'tier'>> = {
  full: {
    core3d: true,
    packets: true,
    dust: true,
    postFx: true,
    maxDpr: 2,
    coreParticles: 900,
    maxPackets: 90,
    dustCount: 70,
    radar: true,
    animate: true,
  },
  balanced: {
    core3d: true,
    packets: true,
    dust: true,
    postFx: true,
    maxDpr: 1.5,
    coreParticles: 380,
    maxPackets: 40,
    dustCount: 34,
    radar: true,
    animate: true,
  },
  light: {
    core3d: false,
    packets: false,
    dust: false,
    postFx: false,
    maxDpr: 1,
    coreParticles: 0,
    maxPackets: 0,
    dustCount: 0,
    radar: true,
    animate: true,
  },
  static: {
    core3d: false,
    packets: false,
    dust: false,
    postFx: false,
    maxDpr: 1,
    coreParticles: 0,
    maxPackets: 0,
    dustCount: 0,
    radar: false,
    animate: false,
  },
};

/**
 * Device-capability hints that are not in the standard `Navigator` lib types.
 * `deviceMemory` and `connection` are Chromium-only, so both are optional and
 * every read below has a fallback.
 */
interface NavigatorWithHints {
  deviceMemory?: number;
  hardwareConcurrency?: number;
  connection?: { saveData?: boolean; effectiveType?: string };
}

/** Cheap, one-shot WebGL2 probe. The context is released immediately. */
function detectWebgl(): 'webgl2' | 'webgl' | 'none' {
  try {
    const canvas = document.createElement('canvas');
    if (canvas.getContext('webgl2')) return 'webgl2';
    if (canvas.getContext('webgl')) return 'webgl';
    return 'none';
  } catch {
    return 'none';
  }
}

function detectTier(): QveTier {
  if (typeof window === 'undefined') return 'light';

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return 'static';

  const nav = navigator as Navigator & NavigatorWithHints;
  if (nav.connection?.saveData) return 'light';

  const webgl = detectWebgl();
  if (webgl === 'none') return 'light';

  const cores = nav.hardwareConcurrency ?? 4;
  const memory = nav.deviceMemory ?? 4;
  const coarsePointer = window.matchMedia('(pointer: coarse)').matches;
  const smallViewport = Math.min(window.innerWidth, window.innerHeight) < 700;

  if (webgl === 'webgl2' && cores >= 8 && memory >= 8 && !coarsePointer) return 'full';
  if (cores <= 2 || memory <= 2) return 'light';
  if (coarsePointer && smallViewport) return 'balanced';
  return 'balanced';
}

/**
 * Resolve the render budget. Recomputes only when the reduced-motion preference
 * changes — device capability does not change during a session, and re-probing
 * WebGL on resize would allocate a context on every drag.
 */
export function useQveBudget(): QveBudget {
  const [tier, setTier] = React.useState<QveTier>('light');

  React.useEffect(() => {
    setTier(detectTier());
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    const onChange = () => setTier(detectTier());
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, []);

  return React.useMemo(() => ({ tier, ...BUDGETS[tier] }), [tier]);
}

/**
 * Frame-budget guard: drops the WebGL device pixel ratio once sustained frame
 * time exceeds the 60 FPS budget. Returns the DPR the core should render at.
 */
export function useAdaptiveDpr(maxDpr: number, enabled: boolean): number {
  const [dpr, setDpr] = React.useState(() => Math.min(maxDpr, typeof window === 'undefined' ? 1 : window.devicePixelRatio || 1));

  React.useEffect(() => {
    if (!enabled) return;
    let frame = 0;
    let last = performance.now();
    let slow = 0;
    let settled = false;

    const tick = (now: number) => {
      const delta = now - last;
      last = now;
      // 22ms ≈ below 45 FPS. Three consecutive slow seconds is a real problem,
      // not a GC blip.
      if (delta > 22) slow += 1;
      else slow = Math.max(0, slow - 1);
      if (!settled && slow > 90) {
        settled = true;
        setDpr(1);
        return;
      }
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [enabled]);

  return Math.min(dpr, maxDpr);
}
