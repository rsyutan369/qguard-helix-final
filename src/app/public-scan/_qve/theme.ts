/**
 * Quantum Visualization Engine™ — theme surface.
 *
 * WHY THIS EXISTS
 * ---------------
 * The engine originally shipped with a dark-only /public-scan, so its instrument
 * layer is painted in literals chosen against a deep-navy ground: a #334768
 * world-dot, a white packet head, an rgba(4,6,14,.55) vignette, additive glow
 * in the 3D core, and cyan/violet accents that measure 1.7-2.2:1 on white.
 *
 * The authenticated scanner reuses that engine inside a dashboard the user can
 * switch to light. A stylesheet can re-surface the engine's DOM chrome — the
 * light-theme compatibility layer in index.css already does — but it cannot
 * reach an SVG `fill`, an inline gradient, a canvas `fillStyle` or a Three.js
 * material. Those are values, not styles, so they need a value source. This is
 * it.
 *
 * WHAT IT IS NOT
 * --------------
 * Not a second palette. The engine's SEMANTIC colours (`QVE_COLOR`, the
 * published grade colours) are unchanged and keep their meaning; what changes
 * is only the lightness they are rendered at, derived by `readableOn` from the
 * surface they will actually be drawn on. Grade F stays the same red in both
 * themes — it is simply a darker red on white, because a lighter one is not
 * legible there.
 *
 * DEFAULT IS DARK
 * ---------------
 * `useQveTheme()` returns 'dark' without a provider. The public scanner and
 * dashboard opt in with `QveThemeProvider`.
 */
'use client';

import React from 'react';
import { QVE_DARK_SURFACE, readableOn } from './types';

export type QveTheme = 'dark' | 'light';

/**
 * WCAG 1.4.11: a graphical object that carries meaning needs 3:1, not the 4.5:1
 * a text label needs. Holding rings, beams and grid lines to the text floor
 * would flatten the engine's whole colour range into near-black on light.
 */
const GRAPHIC_CONTRAST = 3;

export interface QvePalette {
  theme: QveTheme;
  /** Card fill the verdict colours are graded against. Feeds `readableOn`. */
  surface: string;
  /** Fill of the instrument well the 3D core sits in. */
  coreWell: string;
  /**
   * Opacity of the shield body. The shield is glass on navy, where its glow
   * carries it; on white a glass shell at 0.2 is a smudge, so it is rendered
   * as a solid-enough object to read as one.
   */
  shieldOpacity: number;
  /** Perspective floor grid. */
  gridLine: string;
  /** World-map dot that the scan sweep has not reached yet. */
  worldDotIdle: string;
  /** Opacity of the counter-rotating hex rings. */
  hexRingOpacity: number;
  /** Vignette that keeps the data layer winning over the backdrop. */
  vignette: string;
  /** Particle-mesh colours: [primary, link, quantum]. */
  particle: [string, string, string];
  /** Solid globe body / emissive / atmosphere in the 3D core. */
  globeBody: string;
  globeEmissive: string;
  globeShell: string;
  /** Fallback (non-WebGL) globe gradient stops. */
  fallbackGlobe: [string, string, string];
  /** Ring track and inspector hairlines. */
  track: string;
  /** The engine cyan, corrected for this ground. Used where cyan means live. */
  accentCyan: string;
  /** Inline text tones for places a Tailwind class cannot be used. */
  ink: string;
  inkSoft: string;
  inkMuted: string;
  /** Drop shadow under the big readout. */
  readoutShadow: string;
  /**
   * How strongly the additive glow layers (hex field, bloom, packet trails)
   * contribute. Additive blending adds light: on white there is no headroom, so
   * the same layer that reads as energy on navy reads as nothing at all.
   */
  glow: number;
}

const DARK: QvePalette = {
  theme: 'dark',
  surface: QVE_DARK_SURFACE,
  coreWell: 'transparent',
  shieldOpacity: 0.2,
  gridLine: 'rgba(56,189,248,0.07)',
  worldDotIdle: '#334768',
  hexRingOpacity: 0.16,
  vignette: 'radial-gradient(ellipse 70% 60% at 50% 45%, transparent 30%, rgba(4,6,14,0.55) 100%)',
  particle: ['#22d3ee', '#60a5fa', '#a78bfa'],
  globeBody: '#04204f',
  globeEmissive: '#0a3170',
  globeShell: '#081a35',
  fallbackGlobe: ['#1d5fd0', '#0a2f6d', '#04122e'],
  track: 'rgba(148,163,184,0.35)',
  accentCyan: '#22d3ee',
  ink: '#cbd5e1',
  inkSoft: '#94a3b8',
  inkMuted: '#64748b',
  readoutShadow: 'rgba(0,0,0,0.9)',
  glow: 1,
};

/**
 * The light instrument palette.
 *
 * The globe stays a solid dark body. That is not an oversight: it is a physical
 * object in the scene, and a dark object on a light ground is the highest
 * contrast available to it — inverting it to white would erase it. What changes
 * is everything that was drawn as EMITTED LIGHT (glow, additive fields, white
 * packet heads), because emitted light cannot brighten a white page.
 */
const LIGHT: QvePalette = {
  theme: 'light',
  surface: '#f1f6fc',
  coreWell: 'rgba(15,23,42,0.10)',
  shieldOpacity: 0.46,
  gridLine: 'rgba(15,23,42,0.075)',
  worldDotIdle: '#9db2cc',
  hexRingOpacity: 0.24,
  vignette: 'radial-gradient(ellipse 70% 60% at 50% 45%, transparent 30%, rgba(241,246,252,0.72) 100%)',
  particle: ['#0891b2', '#2563eb', '#7c3aed'],
  globeBody: '#0b2f63',
  globeEmissive: '#123f80',
  globeShell: '#12294a',
  fallbackGlobe: ['#2b6fd8', '#12417f', '#0a1f42'],
  track: 'rgba(71,85,105,0.28)',
  accentCyan: '#0e7490',
  ink: '#0f172a',
  inkSoft: '#334155',
  inkMuted: '#5a6b81',
  readoutShadow: 'rgba(148,163,184,0.55)',
  glow: 0.34,
};

export const QVE_PALETTE: Record<QveTheme, QvePalette> = { dark: DARK, light: LIGHT };

const QveThemeContext = React.createContext<QveTheme>('dark');

export function QveThemeProvider({ theme, children }: { theme: QveTheme; children: React.ReactNode }) {
  return React.createElement(QveThemeContext.Provider, { value: theme }, children);
}

/** 'dark' with no provider — every existing embed is unaffected. */
export function useQveTheme(): QveTheme {
  return React.useContext(QveThemeContext);
}

export function useQvePalette(): QvePalette {
  return QVE_PALETTE[useQveTheme()];
}

/** Preserve the semantic hue while making verdict text readable on light cards. */
export function useQveInk() {
  const { theme, surface } = useQvePalette();
  return React.useCallback((hex: string) => (
    theme === 'light' ? readableOn(hex, surface) : hex
  ), [theme, surface]);
}

/**
 * A structural accent (hologram, beams, backdrop, node chrome) corrected for
 * the surface it is drawn on, at the 3:1 GRAPHIC floor rather than the 4.5:1
 * text floor.
 *
 * `#22d3ee` is the engine's cyan and measures 1.68:1 on white — as a ring or a
 * beam it is not merely subtle there, it is absent. This returns the same cyan
 * at a lightness that can actually be seen, and returns it unchanged on dark.
 */
export function qveAccentOn(hex: string, palette: QvePalette): string {
  return palette.theme === 'dark' ? hex : readableOn(hex, palette.surface, GRAPHIC_CONTRAST);
}

/** Hook form: the corrected accent for the active theme. */
export function useQveAccent(hex: string): string {
  const palette = useQvePalette();
  return React.useMemo(() => qveAccentOn(hex, palette), [hex, palette]);
}
