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
 *   blue     live, measured in this browser
 *   violet   post-quantum, lattice-based, the thing that survives
 *   rose     quantum-broken — Shor solves it
 *   amber    a modelled estimate, or a deadline
 *   emerald  safe as it stands, no action required
 *   slate    structure, chrome, published reference material
 *
 * TWO THEMES, ONE MEANING
 * -----------------------
 * The page ships a dark instrument theme and a light one. The semantic accents
 * keep their meaning in both; what changes is the lightness they are rendered
 * at. Bright accents sit on navy, and deeper shades keep text readable on the
 * light panel.
 *
 * HOW A THEME REACHES A COLOUR
 * ----------------------------
 * `QSR.x` is NOT a colour literal — it is `var(--qsr-x)`. `QsrThemeScope`
 * (see `_theme-toggle.tsx`) writes the active palette's variables onto the
 * page root, so every inline `style={{ color: QSR.ink }}` re-resolves when the
 * theme flips, with no per-component plumbing and no re-render.
 *
 * Canvas `fillStyle` and Three.js materials cannot read a CSS variable, so
 * they take the literal palette instead: `useQsrPalette()` returns the active
 * `QsrPalette`, and `alpha()` blends one of its hex values. Both views come
 * from the single `PALETTES` table below, so they cannot drift apart.
 */

import React from 'react';
import type { Provenance } from '@/lib/quantum-sim';
import type { ThemeMode } from '@/contexts/theme-context';

export type QsrTheme = 'dark' | 'light';

/** Every colour the page paints, by role. */
export interface QsrPalette {
  theme: QsrTheme;

  /** Page ground and the panel stack that sits on it. */
  ground: string;
  groundDeep: string;
  panel: string;
  panelSolid: string;
  panelRaised: string;
  hairline: string;
  hairlineStrong: string;
  /** An inset well on a panel: the quiet fill behind a table, a tile, a code block. */
  well: string;
  /** A well that has to hold its own over the 3D stage or a busy backdrop. */
  wellStrong: string;
  /** The deepest solid fill: hex dumps, the run log. */
  wellSolid: string;
  /** Row dividers inside a panel. */
  rule: string;
  /** The empty part of a meter or slider. */
  track: string;

  /** Semantic accents. Each has one meaning, everywhere. */
  live: string;
  quantum: string;
  broken: string;
  model: string;
  safe: string;
  /** The ink that sits ON a solid accent fill (a primary button). */
  onAccent: string;

  /** Ink. */
  heading: string;
  ink: string;
  inkSoft: string;
  inkMuted: string;
  inkFaint: string;

  /** Page backdrop: the instrument grid and the two corner glows. */
  grid: string;
  glowA: string;
  glowB: string;
  selection: string;
  scrollThumb: string;

  /** The 3D stage / fallback diagram ground. */
  stageGround: string;
  /** Unlit geometry in the 3D scene and the fallback diagram. */
  plateOff: string;
  plateOffEmissive: string;
  plateOffStroke: string;
  /** Halo behind a floating 3D label, so it stays legible over geometry. */
  labelShadow: string;
}

const DARK: QsrPalette = {
  theme: 'dark',

  ground: '#0e1f3d',
  groundDeep: '#0b1d3a',
  panel: '#13264a',
  panelSolid: '#13264a',
  panelRaised: '#1a2f58',
  hairline: 'rgba(255, 255, 255, 0.12)',
  hairlineStrong: 'rgba(255, 255, 255, 0.24)',
  well: 'rgba(5, 14, 33, 0.32)',
  wellStrong: '#0b1d3a',
  wellSolid: '#0e1f3d',
  rule: 'rgba(255, 255, 255, 0.09)',
  track: 'rgba(180, 192, 216, 0.17)',

  live: '#99b5ff',
  quantum: '#c0aef9',
  broken: '#fda6a2',
  model: '#ffd084',
  safe: '#72d8a7',
  onAccent: '#04060e',

  heading: '#ffffff',
  ink: '#edf1fb',
  inkSoft: '#b4c0d8',
  inkMuted: '#a4b3cf',
  inkFaint: '#a4b3cf',

  grid: 'rgba(56, 189, 248, 0.035)',
  glowA: 'rgba(34, 211, 238, 0.10)',
  glowB: 'rgba(167, 139, 250, 0.07)',
  selection: 'rgba(34, 211, 238, 0.28)',
  scrollThumb: 'rgba(34, 211, 238, 0.28)',

  stageGround: 'radial-gradient(ellipse 80% 70% at 50% 40%, rgba(12, 20, 42, 0.9), rgba(3, 4, 10, 0.98))',
  plateOff: '#16203a',
  plateOffEmissive: '#0a1120',
  plateOffStroke: 'rgba(56, 189, 248, 0.12)',
  labelShadow: 'rgba(0, 0, 0, 0.95)',
};

/**
 * The light instrument palette: a cool paper ground, white panels, and the
 * 700-shade accents. Ink is slate-900 down to slate-600 so that even the
 * quietest label holds contrast on the ground.
 */
const LIGHT: QsrPalette = {
  theme: 'light',

  ground: '#ffffff',
  groundDeep: '#f6f8fd',
  panel: '#ffffff',
  panelSolid: '#ffffff',
  panelRaised: '#edf1fb',
  hairline: 'rgba(11, 29, 58, 0.1)',
  hairlineStrong: 'rgba(11, 29, 58, 0.2)',
  well: '#f6f8fd',
  wellStrong: 'rgba(255, 255, 255, 0.9)',
  wellSolid: '#edf1fb',
  rule: 'rgba(15, 23, 42, 0.07)',
  track: 'rgba(15, 23, 42, 0.10)',

  live: '#3654c0',
  quantum: '#6d28d9',
  broken: '#be123c',
  model: '#a84c07',
  safe: '#047857',
  onAccent: '#ffffff',

  heading: '#0b1d3a',
  ink: '#0b1d3a',
  inkSoft: '#33435f',
  inkMuted: '#55637d',
  inkFaint: '#55637d',

  grid: 'rgba(15, 23, 42, 0.045)',
  glowA: 'rgba(14, 116, 144, 0.10)',
  glowB: 'rgba(109, 40, 217, 0.06)',
  selection: 'rgba(14, 116, 144, 0.22)',
  scrollThumb: 'rgba(15, 23, 42, 0.28)',

  stageGround: 'radial-gradient(ellipse 80% 70% at 50% 40%, #ffffff, #e3eaf4)',
  plateOff: '#c3cfe0',
  plateOffEmissive: '#dde5f0',
  plateOffStroke: 'rgba(15, 23, 42, 0.16)',
  labelShadow: 'rgba(255, 255, 255, 0.95)',
};

export const PALETTES: Record<QsrTheme, QsrPalette> = { dark: DARK, light: LIGHT };

/* ═══════════════════════════════════════════════════════════ CSS variables */

type ColourToken = Exclude<keyof QsrPalette, 'theme'>;

const TOKEN_KEYS = (Object.keys(DARK) as Array<keyof QsrPalette>).filter((key): key is ColourToken => key !== 'theme');

const cssVarName = (token: ColourToken) => `--qsr-${token.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)}`;

/**
 * Colour roles as CSS values. Falls back to the dark value so a node rendered
 * outside `QsrThemeScope` (a portal, a test harness) is still legible.
 */
export const QSR = Object.fromEntries(
  TOKEN_KEYS.map((token) => [token, `var(${cssVarName(token)}, ${DARK[token]})`]),
) as Record<ColourToken, string>;

/** The variables for one theme, ready to spread into a root element's `style`. */
export function qsrThemeVars(theme: QsrTheme): React.CSSProperties {
  const palette = PALETTES[theme];
  const vars: Record<string, string> = {};
  for (const token of TOKEN_KEYS) vars[cssVarName(token)] = palette[token];
  return vars as React.CSSProperties;
}

/* ═══════════════════════════════════════════════════════ palette for values */

const QsrThemeContext = React.createContext<QsrTheme>('dark');

export const QsrThemeProvider = QsrThemeContext.Provider;

const THEME_KEY = 'qguard-simulation-theme';

export function useSimulationTheme() {
  const [mode, setMode] = React.useState<ThemeMode>(() => {
    if (typeof window === 'undefined') return 'light';
    try {
      const saved = window.localStorage.getItem(THEME_KEY);
      if (saved === 'light' || saved === 'dark' || saved === 'system') return saved;
    } catch { /* The theme remains usable when storage is unavailable. */ }
    return 'light';
  });
  const [systemTheme, setSystemTheme] = React.useState<QsrTheme>('light');

  React.useEffect(() => {
    if (mode !== 'system') return;
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const sync = () => setSystemTheme(media.matches ? 'dark' : 'light');
    sync();
    media.addEventListener('change', sync);
    return () => media.removeEventListener('change', sync);
  }, [mode]);

  const selectMode = React.useCallback((next: ThemeMode) => {
    setMode(next);
    try { window.localStorage.setItem(THEME_KEY, next); } catch { /* In-memory selection still works. */ }
  }, []);

  return { mode, theme: mode === 'system' ? systemTheme : mode, setMode: selectMode };
}

export function useQsrTheme(): QsrTheme {
  return React.useContext(QsrThemeContext);
}

/**
 * The literal palette for the active theme — for the places a CSS variable
 * cannot reach: canvas `fillStyle`, Three.js materials, post-processing.
 *
 * The provider has to be re-mounted inside the R3F `<Canvas>`, because React
 * context does not cross the reconciler boundary.
 */
export function useQsrPalette(): QsrPalette {
  return PALETTES[useQsrTheme()];
}

/* ═══════════════════════════════════════════════════════════════ semantics */

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

/**
 * Translucent version of a colour. Accepts a theme variable (`QSR.live`) as
 * readily as a hex — `color-mix` resolves at paint time, so a tint of a
 * variable follows the theme. Not usable in canvas; use `alpha()` there.
 */
export function tint(color: string, opacity: number): string {
  const percent = Math.round(Math.max(0, Math.min(1, opacity)) * 1000) / 10;
  return `color-mix(in srgb, ${color} ${percent}%, transparent)`;
}

/**
 * The literal colour behind a `QSR.*` value, read from the element's cascade.
 * For canvas, which cannot evaluate `var()`. Anything that is not a `QSR`
 * variable reference is returned untouched.
 */
export function resolveColour(element: Element, value: string): string {
  const match = /^var\((--[\w-]+),\s*(.+)\)$/.exec(value.trim());
  if (!match) return value;
  const resolved = getComputedStyle(element).getPropertyValue(match[1]).trim();
  return resolved || match[2];
}

/** Literal `rgba()` of a hex colour — for canvas, where `tint` cannot be used. */
export function alpha(hex: string, opacity: number): string {
  const value = hex.replace('#', '');
  const r = parseInt(value.slice(0, 2), 16);
  const g = parseInt(value.slice(2, 4), 16);
  const b = parseInt(value.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${opacity})`;
}
