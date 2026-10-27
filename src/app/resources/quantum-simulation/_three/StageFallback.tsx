/**
 * Quantum Simulation Range — the non-WebGL stage.
 *
 * Rendered instead of `QuantumStage3D` on devices the Performance Manager does
 * not clear for WebGL, and whenever the visitor has asked for reduced motion.
 *
 * It is not a placeholder: it carries the same five sites, the same four links
 * and the same stage logic, and it plots the SAME real Born-rule distribution
 * along the bottom of the core. A visitor on a low-end phone gets the whole
 * argument, just drawn in SVG.
 */

import React from 'react';
import { QSR, tint } from '../_theme';
import type { StageSites } from './QuantumStage3D';

export interface StageFallbackProps {
  stage: number;
  progress: number;
  sites: StageSites;
  distribution: Float64Array | null;
  resolved: boolean;
  quantumSafe: boolean;
  /** False under prefers-reduced-motion: nothing moves, everything still renders. */
  animate: boolean;
}

const NODES = {
  client: { x: 90, y: 150 },
  transit: { x: 300, y: 190 },
  server: { x: 710, y: 150 },
  archive: { x: 300, y: 350 },
  crqc: { x: 545, y: 70 },
} as const;

function Node({
  x,
  y,
  label,
  sublabel,
  accent,
  active,
  compromised,
  animate,
}: {
  x: number;
  y: number;
  label: string;
  sublabel: string;
  accent: string;
  active: boolean;
  compromised: boolean;
  animate: boolean;
}) {
  const colour = compromised ? QSR.broken : accent;
  return (
    <g transform={`translate(${x} ${y})`}>
      {active && (
        <circle r={30} fill="none" stroke={colour} strokeWidth={1} opacity={0.35}>
          {animate && <animate attributeName="r" values="26;38;26" dur="2.6s" repeatCount="indefinite" />}
          {animate && <animate attributeName="opacity" values="0.4;0.05;0.4" dur="2.6s" repeatCount="indefinite" />}
        </circle>
      )}
      <circle r={19} fill={tint(colour, 0.14)} stroke={colour} strokeWidth={1.5} />
      <circle r={7} fill={colour} opacity={active ? 1 : 0.55} />
      <text x={0} y={40} textAnchor="middle" fill={active ? QSR.ink : QSR.inkSoft} fontSize={12} fontWeight={700} fontFamily='"JetBrains Mono", monospace'>
        {label.length > 22 ? `${label.slice(0, 21)}…` : label}
      </text>
      <text x={0} y={54} textAnchor="middle" fill={colour} fontSize={8.5} letterSpacing="1.6" fontFamily='"JetBrains Mono", monospace'>
        {sublabel.toUpperCase()}
      </text>
    </g>
  );
}

function Link({
  from,
  to,
  bow,
  accent,
  live,
  animate,
  dashed = false,
}: {
  from: { x: number; y: number };
  to: { x: number; y: number };
  bow: number;
  accent: string;
  live: boolean;
  animate: boolean;
  dashed?: boolean;
}) {
  const midX = (from.x + to.x) / 2;
  const midY = (from.y + to.y) / 2 + bow;
  const path = `M ${from.x} ${from.y} Q ${midX} ${midY} ${to.x} ${to.y}`;
  return (
    <g>
      <path d={path} fill="none" stroke={accent} strokeWidth={live ? 2 : 1} opacity={live ? 0.35 : 0.1} strokeDasharray={dashed ? '5 6' : undefined} />
      {live && (
        <>
          <path d={path} fill="none" stroke={accent} strokeWidth={1} opacity={0.85} strokeDasharray="14 220" strokeLinecap="round">
            {animate && <animate attributeName="stroke-dashoffset" values="234;0" dur="2.4s" repeatCount="indefinite" />}
          </path>
          <path d={path} fill="none" stroke={accent} strokeWidth={1} opacity={0.6} strokeDasharray="8 226" strokeLinecap="round">
            {animate && <animate attributeName="stroke-dashoffset" values="234;0" dur="2.4s" begin="0.8s" repeatCount="indefinite" />}
          </path>
        </>
      )}
    </g>
  );
}

export default function StageFallback({ stage, progress, sites, distribution, resolved, quantumSafe, animate }: StageFallbackProps) {
  const recovered = stage >= 4;
  const shielded = stage >= 6;
  const linkAccent = quantumSafe || shielded ? QSR.quantum : recovered ? QSR.broken : QSR.live;
  const coreAccent = resolved ? QSR.quantum : QSR.live;

  /** Same downsample the 3D ring uses, so both stages plot the same statistics. */
  const bins = React.useMemo(() => {
    const count = 64;
    const out = new Array<number>(count).fill(0.1);
    if (!distribution || distribution.length === 0) return out;
    const perBin = distribution.length / count;
    let peak = 0;
    for (let i = 0; i < count; i += 1) {
      let sum = 0;
      const start = Math.floor(i * perBin);
      const end = Math.max(start + 1, Math.floor((i + 1) * perBin));
      for (let j = start; j < end && j < distribution.length; j += 1) sum += distribution[j];
      out[i] = sum;
      peak = Math.max(peak, sum);
    }
    return peak > 0 ? out.map((v) => v / peak) : out;
  }, [distribution]);

  const archiveFill = stage <= 1 ? progress * 0.2 : Math.min(1, 0.2 + (stage - 1) * 0.25);

  return (
    <svg viewBox="0 0 800 440" className="h-full w-full" role="img" aria-label="Attack topology">
      <defs>
        <radialGradient id="qsr-fallback-glow" cx="50%" cy="50%">
          <stop offset="0%" stopColor={tint(coreAccent, 0.28)} />
          <stop offset="100%" stopColor="transparent" />
        </radialGradient>
      </defs>

      <circle cx={NODES.crqc.x} cy={NODES.crqc.y} r={120} fill="url(#qsr-fallback-glow)" opacity={stage >= 3 ? 1 : 0.2} />

      <Link from={NODES.client} to={NODES.server} bow={-70} accent={linkAccent} live animate={animate} />
      <Link from={NODES.transit} to={NODES.archive} bow={0} accent={QSR.broken} live={stage >= 1} animate={animate} />
      <Link from={NODES.archive} to={NODES.crqc} bow={40} accent={QSR.quantum} live={stage >= 3} animate={animate} dashed />
      <Link from={NODES.crqc} to={NODES.server} bow={20} accent={shielded ? QSR.safe : QSR.broken} live={recovered && !shielded} animate={animate} dashed />

      {/* Archive silo */}
      <g transform={`translate(${NODES.archive.x} ${NODES.archive.y})`}>
        {Array.from({ length: 7 }, (_, i) => {
          const lit = i / 7 <= archiveFill;
          return (
            <rect
              key={i}
              x={-30 + i * 1.5}
              y={-6 - i * 8}
              width={60 - i * 3}
              height={6}
              rx={1.5}
              fill={lit ? tint(QSR.broken, 0.55) : QSR.plateOff}
              stroke={lit ? QSR.broken : QSR.plateOffStroke}
              strokeWidth={0.6}
            />
          );
        })}
      </g>

      {/* Quantum core with the real interference comb under it */}
      <g transform={`translate(${NODES.crqc.x} ${NODES.crqc.y})`}>
        <circle r={26} fill="none" stroke={coreAccent} strokeWidth={1} opacity={stage >= 3 ? 0.7 : 0.2} />
        <circle r={16} fill={tint(coreAccent, 0.2)} stroke={coreAccent} strokeWidth={1.2} opacity={stage >= 3 ? 1 : 0.35} />
        {stage >= 3 && animate && <circle r={16} fill="none" stroke={coreAccent} strokeWidth={1}>
          <animate attributeName="r" values="16;34;16" dur="3s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.6;0;0.6" dur="3s" repeatCount="indefinite" />
        </circle>}
        {bins.map((height, i) => (
          <rect
            key={i}
            x={-63 + i * 2}
            y={44 - height * 34}
            width={1.4}
            height={Math.max(1, height * 34)}
            fill={coreAccent}
            opacity={stage >= 3 ? 0.85 : 0.28}
          />
        ))}
        <text x={0} y={62} textAnchor="middle" fill={QSR.inkFaint} fontSize={7.5} letterSpacing="1.4" fontFamily='"JetBrains Mono", monospace'>
          {distribution ? 'MEASURED |ψ|² OVER CONTROL REGISTER' : 'REGISTER NOT YET PREPARED'}
        </text>
      </g>

      {shielded && (
        <circle cx={NODES.server.x} cy={NODES.server.y} r={52} fill={tint(QSR.quantum, 0.06)} stroke={QSR.quantum} strokeWidth={1.2} strokeDasharray="4 5">
          {animate && <animate attributeName="r" values="46;54;46" dur="4s" repeatCount="indefinite" />}
        </circle>
      )}

      <Node {...NODES.client} label={sites.client} sublabel="Initiator" accent={QSR.live} active={stage === 1} compromised={false} animate={animate} />
      <Node {...NODES.transit} label={sites.transit} sublabel="Passive tap" accent={QSR.broken} active={stage <= 2} compromised animate={animate} />
      <Node
        {...NODES.server}
        label={sites.server}
        sublabel={shielded ? 'ML-KEM protected' : recovered ? 'Keys recovered' : 'Responder'}
        accent={shielded ? QSR.quantum : QSR.live}
        active={stage >= 4}
        compromised={recovered && !shielded}
        animate={animate}
      />
      <text x={NODES.archive.x} y={NODES.archive.y + 30} textAnchor="middle" fill={QSR.ink} fontSize={12} fontWeight={700} fontFamily='"JetBrains Mono", monospace'>
        {sites.archive.length > 22 ? `${sites.archive.slice(0, 21)}…` : sites.archive}
      </text>
      <text x={NODES.archive.x} y={NODES.archive.y + 44} textAnchor="middle" fill={QSR.broken} fontSize={8.5} letterSpacing="1.6" fontFamily='"JetBrains Mono", monospace'>
        CIPHERTEXT ARCHIVE
      </text>
      <text x={NODES.crqc.x} y={NODES.crqc.y - 36} textAnchor="middle" fill={QSR.ink} fontSize={12} fontWeight={700} fontFamily='"JetBrains Mono", monospace'>
        {sites.crqc.length > 22 ? `${sites.crqc.slice(0, 21)}…` : sites.crqc}
      </text>
    </svg>
  );
}
