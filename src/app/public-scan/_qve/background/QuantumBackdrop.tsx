/**
 * Quantum Visualization Engine™ — animated cyber-world backdrop.
 *
 * Five layers, back to front, all in the blue / violet / cyan band the design
 * language restricts the engine to:
 *
 *   1. Cyber grid        — perspective floor grid, masked to the hero.
 *   2. Dot-matrix world  — SVG, generated from lon/lat polygons (see world-grid).
 *   3. Digital mesh      — neural-network links via tsParticles (GPU-composited).
 *   4. Quantum wave      — two travelling sine bands under the core.
 *   5. Rotating hexagons — slow counter-rotating hex field for depth.
 *
 * Everything here reacts to scan activity: while a scan is live the world map
 * pulses along a scanning sweep, the particle field speeds up and gains links,
 * and the quantum wave gains amplitude. At rest the backdrop breathes slowly
 * rather than freezing, and under `prefers-reduced-motion` it renders as a still
 * image with no rAF loops at all.
 */
'use client';

import React from 'react';
import type { QveRunState } from '../types';
import { qveAccentOn, useQvePalette, type QvePalette } from '../theme';
import { buildWorldDots } from './world-grid';

const ParticleField = React.lazy(() => import('./ParticleField'));

export interface QuantumBackdropProps {
  run: QveRunState;
  /** 0-100 real scan progress — drives the map sweep position. */
  progress: number;
  accent: string;
  quantum: boolean;
  animate: boolean;
  /** Mount the tsParticles layer (Performance Manager decision). */
  dust: boolean;
  dustCount: number;
}

/* ------------------------------------------------------------------- world -- */

const WorldMap = React.memo(function WorldMap({
  accent,
  active,
  progress,
  animate,
  palette,
}: {
  accent: string;
  active: boolean;
  progress: number;
  animate: boolean;
  palette: QvePalette;
}) {
  // Rasterised once per session; the grid is resolution-independent from here.
  const dots = React.useMemo(() => buildWorldDots(104, 42), []);
  const sweep = active ? progress / 100 : 1;

  return (
    <svg
      className="absolute inset-0 h-full w-full"
      viewBox="0 0 1040 420"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden
    >
      <defs>
        <linearGradient id="qve-world-sweep" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor={accent} stopOpacity="0.9" />
          <stop offset="100%" stopColor={accent} stopOpacity="0.25" />
        </linearGradient>
        <radialGradient id="qve-world-mask" cx="50%" cy="45%" r="62%">
          <stop offset="0%" stopColor="#fff" stopOpacity="1" />
          <stop offset="100%" stopColor="#fff" stopOpacity="0" />
        </radialGradient>
        <mask id="qve-world-fade">
          <rect width="1040" height="420" fill="url(#qve-world-mask)" />
        </mask>
      </defs>

      <g mask="url(#qve-world-fade)">
        {dots.map((dot, index) => {
          const x = dot.u * 1040;
          const y = dot.v * 420;
          // Dots ahead of the sweep stay dim: the map fills in as the scan runs.
          const scanned = dot.u <= sweep;
          return (
            <circle
              key={index}
              cx={x.toFixed(1)}
              cy={y.toFixed(1)}
              r={scanned ? 1.5 : 1.1}
              fill={scanned ? accent : palette.worldDotIdle}
              opacity={(scanned ? 0.42 : 0.2) * dot.weight}
            />
          );
        })}
      </g>

      {/* Scan meridian — sits exactly at real progress, so it is a readout. */}
      {active && (
        <g mask="url(#qve-world-fade)">
          <line
            x1={sweep * 1040}
            y1={0}
            x2={sweep * 1040}
            y2={420}
            stroke="url(#qve-world-sweep)"
            strokeWidth={1.4}
            opacity={0.65}
          />
          {animate && (
            <circle cx={sweep * 1040} cy={210} r={5} fill={accent} opacity={0.7}>
              <animate attributeName="r" values="4;12;4" dur="2s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0.7;0;0.7" dur="2s" repeatCount="indefinite" />
            </circle>
          )}
        </g>
      )}
    </svg>
  );
});

/* ------------------------------------------------------------------ hexagons - */

/** Two counter-rotating hexagon rings. CSS-driven, so it costs no JS frames. */
function HexRings({ accent, animate, palette }: { accent: string; animate: boolean; palette: QvePalette }) {
  const hexPoints = React.useMemo(() => {
    const points: string[] = [];
    for (let index = 0; index < 6; index += 1) {
      const angle = (index / 6) * Math.PI * 2 - Math.PI / 2;
      points.push(`${(Math.cos(angle) * 100).toFixed(2)},${(Math.sin(angle) * 100).toFixed(2)}`);
    }
    return points.join(' ');
  }, []);

  return (
    <svg className="absolute inset-0 h-full w-full" viewBox="-260 -260 520 520" aria-hidden>
      <g opacity={palette.hexRingOpacity}>
        {/* Scale lives on the outer <g> as an SVG attribute and the CSS spin on
            the inner one. A CSS `transform` on an SVG element REPLACES its
            transform attribute, so animating the same node would silently drop
            the scale and collapse every ring onto the same radius. */}
        {[0.55, 0.85, 1.15, 1.5, 1.9].map((scale, index) => (
          <g key={scale} transform={`scale(${scale})`}>
            <g
              style={
                animate
                  ? { animation: `qve-hex-spin ${52 + index * 13}s linear infinite${index % 2 ? ' reverse' : ''}` }
                  : { transform: `rotate(${index * 9}deg)` }
              }
            >
              <polygon points={hexPoints} fill="none" stroke={accent} strokeWidth={0.9 / scale} />
            </g>
          </g>
        ))}
      </g>
    </svg>
  );
}

/* ---------------------------------------------------------------- quantum wave */

function WaveBands({ accent, quantum, animate, active, palette }: { accent: string; quantum: boolean; animate: boolean; active: boolean; palette: QvePalette }) {
  const amplitude = active ? 26 : 14;
  // The second band's hue is fixed (violet when PQ was detected, blue otherwise);
  // only its lightness follows the ground it is drawn on.
  const bandB = qveAccentOn(quantum ? '#a78bfa' : '#3b82f6', palette);
  const path = (offset: number, lobes: number) => {
    const samples = 64;
    const points: string[] = [];
    for (let index = 0; index <= samples; index += 1) {
      const t = index / samples;
      const x = t * 1200;
      const y = 100 + Math.sin(t * Math.PI * lobes + offset) * amplitude;
      points.push(`${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`);
    }
    return points.join(' ');
  };

  return (
    <svg className="absolute inset-x-0 bottom-0 h-40 w-full" viewBox="0 0 1200 200" preserveAspectRatio="none" aria-hidden>
      <defs>
        <linearGradient id="qve-wave-a" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor={accent} stopOpacity="0" />
          <stop offset="50%" stopColor={accent} stopOpacity="0.55" />
          <stop offset="100%" stopColor={accent} stopOpacity="0" />
        </linearGradient>
        <linearGradient id="qve-wave-b" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor={bandB} stopOpacity="0" />
          <stop offset="50%" stopColor={bandB} stopOpacity="0.4" />
          <stop offset="100%" stopColor={bandB} stopOpacity="0" />
        </linearGradient>
      </defs>
      <g style={animate ? { animation: 'qve-wave-drift 11s ease-in-out infinite' } : undefined}>
        <path d={path(0, 4)} fill="none" stroke="url(#qve-wave-a)" strokeWidth={1.6} />
        <path d={path(1.9, 6)} fill="none" stroke="url(#qve-wave-b)" strokeWidth={1.2} />
      </g>
    </svg>
  );
}

/* -------------------------------------------------------------------- export - */

export const QuantumBackdrop = React.memo(function QuantumBackdrop({
  run,
  progress,
  accent,
  quantum,
  animate,
  dust,
  dustCount,
}: QuantumBackdropProps) {
  const active = run === 'scanning';
  const palette = useQvePalette();

  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden>
      {/* 1 · Cyber grid, perspective-warped and masked toward the horizon. */}
      <div
        className="absolute inset-0 opacity-[0.5]"
        style={{
          backgroundImage:
            `linear-gradient(${palette.gridLine} 1px, transparent 1px), linear-gradient(90deg, ${palette.gridLine} 1px, transparent 1px)`,
          backgroundSize: '42px 42px',
          maskImage: 'radial-gradient(ellipse 78% 74% at 50% 46%, #000 20%, transparent 78%)',
          WebkitMaskImage: 'radial-gradient(ellipse 78% 74% at 50% 46%, #000 20%, transparent 78%)',
        }}
      />

      {/* 2 · Dot-matrix world. */}
      <div className="absolute inset-0 opacity-90">
        <WorldMap accent={accent} active={active} progress={progress} animate={animate} palette={palette} />
      </div>

      {/* 3 · Digital mesh / neural links. */}
      {dust && animate && (
        <React.Suspense fallback={null}>
          <ParticleField accent={accent} quantum={quantum} count={dustCount} active={active} palette={palette} />
        </React.Suspense>
      )}

      {/* 4 · Rotating hexagon field, centred behind the core. */}
      <div className="absolute left-1/2 top-1/2 h-[38rem] w-[38rem] -translate-x-1/2 -translate-y-1/2">
        <HexRings accent={accent} animate={animate} palette={palette} />
      </div>

      {/* 5 · Quantum wave bands along the lower edge. */}
      <WaveBands accent={accent} quantum={quantum} animate={animate} active={active} palette={palette} />

      {/* Vignette so the data layer above always wins on contrast. */}
      <div
        className="absolute inset-0"
        style={{
          background: palette.vignette,
        }}
      />
    </div>
  );
});
