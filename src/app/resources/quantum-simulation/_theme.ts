/**
 * Quantum Simulation Range — design tokens.
 *
 * WHY THIS EXISTS
 * ---------------
 * The page this replaces mixed two design systems: `.qs-page` painted a light
 * gradient ground while the components inside it were `bg-slate-950` and
 * `bg-white/70`. The result read as three different products stacked.
 *
 * One ground, one type scale, one accent system. The accents are not
 * decorative — each one carries a fixed meaning that holds across every panel
 * on the page, so a reader learns the colour language once:
 *
 *   cyan     live, measured in this browser, right now
 *   violet   post-quantum, lattice-based, the thing that survives
 *   rose     quantum-broken — Shor solves it
 *   amber    a modelled estimate, or a deadline
 *   emerald  safe as it stands, no action required
 *   slate    structure, chrome, published reference material
 *
 * Values are literals rather than Tailwind classes wherever they have to reach
 * a canvas fillStyle, an SVG attribute or a Three.js material — those are
 * values, not styles, and a stylesheet cannot reach them.
 */

import type { Provenance } from '@/lib/quantum-sim';

export const QSR = {
  /** Page ground and the panel stack that sits on it. */
  ground: '#05070f',
  groundDeep: '#03040a',
  panel: 'rgba(10, 14, 28, 0.72)',
  panelSolid: '#0a0e1c',
  panelRaised: 'rgba(16, 22, 42, 0.82)',
  hairline: 'rgba(56, 189, 248, 0.10)',
  hairlineStrong: 'rgba(56, 189, 248, 0.22)',

  /** Semantic accents. Each has one meaning, everywhere. */
  live: '#22d3ee',
  quantum: '#a78bfa',
  broken: '#f43f5e',
  model: '#f59e0b',
  safe: '#34d399',

  /** Ink. */
  ink: '#e2e8f0',
  inkSoft: '#94a3b8',
  inkMuted: '#5b6b85',
  inkFaint: '#3b4761',
} as const;

/** Verdict colour for a classical primitive. */
export const VERDICT_COLOR: Record<'broken' | 'reduced' | 'safe', string> = {
  broken: QSR.broken,
  reduced: QSR.model,
  safe: QSR.safe,
};

export const VERDICT_LABEL: Record<'broken' | 'reduced' | 'safe', string> = {
  broken: 'Broken by Shor',
  reduced: 'Reduced by Grover',
  safe: 'Quantum-safe',
};

/**
 * Provenance styling. Every number on the page wears one of these, because the
 * distinction between "a standards document says this", "a model computed
 * this" and "your browser just did this" is the difference between the page
 * being useful and being decoration.
 */
export const PROVENANCE: Record<Provenance, { label: string; color: string; description: string }> = {
  published: {
    label: 'PUBLISHED',
    color: QSR.inkSoft,
    description: 'Stated exactly by a standards document, an IANA registry, or a cited paper.',
  },
  model: {
    label: 'MODEL',
    color: QSR.model,
    description: 'Output of a named resource-estimation model that reproduces its own published anchor points.',
  },
  measured: {
    label: 'MEASURED',
    color: QSR.live,
    description: 'Computed in this browser during this session. Re-run it and the number moves.',
  },
};

/** Stage accent: the first two stages are happening today; three need a CRQC. */
export const TENSE_COLOR: Record<'present' | 'future' | 'remedy', string> = {
  present: QSR.broken,
  future: QSR.quantum,
  remedy: QSR.safe,
};

/** Byte-field highlight colours for the TLS hex dump. */
export const FIELD_COLOR: Record<'structure' | 'classical' | 'quantum-safe' | 'symmetric' | 'random', string> = {
  structure: QSR.inkMuted,
  classical: QSR.broken,
  'quantum-safe': QSR.quantum,
  symmetric: QSR.safe,
  random: QSR.inkSoft,
};

/** Alpha-blend a hex colour against the page ground. */
export function tint(hex: string, alpha: number): string {
  const value = hex.replace('#', '');
  const r = parseInt(value.slice(0, 2), 16);
  const g = parseInt(value.slice(2, 4), 16);
  const b = parseInt(value.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}
