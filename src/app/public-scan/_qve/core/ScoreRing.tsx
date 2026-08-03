/**
 * Quantum Visualization Engine™ — Score Ring + Quantum Wave.
 *
 * The crisp, accessible layer over the WebGL core: a graduated progress ring
 * that fills from real scan progress, a counter-rotating activity arc, and a
 * radial waveform whose colour is keyed to the published grade.
 *
 * Deliberately SVG rather than more Three.js: this layer carries numbers and a
 * grade, so it must stay resolution-independent, selectable by the accessibility
 * tree, and readable when WebGL is unavailable. All motion is a single rAF loop
 * that stops when the engine is idle or motion is disabled.
 */
'use client';

import React from 'react';
import { gradeWaveColors } from '../types';

export interface ScoreRingProps {
  /** 0-100 real scan progress — drives the outer fill. */
  progress: number;
  /** 0-100 composite score once graded; drives wave amplitude. */
  score: number;
  grade: string | null;
  /** Structural accent — blue / violet / cyan only. */
  accent: string;
  /** Verdict colour, applied to the graduated bezel and the progress arc only. */
  verdictColor: string;
  /** True while the scan is live — enables the activity arc. */
  active: boolean;
  /** Master motion switch from the Performance Manager. */
  animate: boolean;
  size?: number;
}

const VIEW = 400;

/** Polar → cartesian in the ring's own viewBox space. */
function polar(radius: number, degrees: number): [number, number] {
  const radians = ((degrees - 90) * Math.PI) / 180;
  return [VIEW / 2 + radius * Math.cos(radians), VIEW / 2 + radius * Math.sin(radians)];
}

function arcPath(radius: number, fromDeg: number, toDeg: number): string {
  const [x1, y1] = polar(radius, fromDeg);
  const [x2, y2] = polar(radius, toDeg);
  const large = Math.abs(toDeg - fromDeg) > 180 ? 1 : 0;
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${radius} ${radius} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

/**
 * Radial waveform. `phase` animates the travelling crest; `amplitude` comes from
 * the score, so a weak posture produces a shallow, unsettled wave and a strong
 * one a deep, confident wave.
 */
function wavePath(radius: number, amplitude: number, phase: number, lobes: number): string {
  const samples = 144;
  const points: string[] = [];
  for (let index = 0; index <= samples; index += 1) {
    const t = index / samples;
    const degrees = t * 360;
    const radians = (degrees * Math.PI) / 180;
    const modulation =
      Math.sin(radians * lobes + phase) * 0.62 + Math.sin(radians * (lobes * 2.5) - phase * 1.4) * 0.38;
    const [x, y] = polar(radius + modulation * amplitude, degrees);
    points.push(`${index === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`);
  }
  return `${points.join(' ')} Z`;
}

const TICK_COUNT = 72;

export const ScoreRing = React.memo(function ScoreRing({
  progress,
  score,
  grade,
  accent,
  verdictColor,
  active,
  animate,
  size = 400,
}: ScoreRingProps) {
  const [phase, setPhase] = React.useState(0);
  const [spin, setSpin] = React.useState(0);
  /** Eased progress — the ring must sweep 0→100, never jump. */
  const [easedProgress, setEasedProgress] = React.useState(0);
  const [easedScore, setEasedScore] = React.useState(0);

  const targetProgress = Math.max(0, Math.min(100, progress));
  const targetScore = Math.max(0, Math.min(100, score));

  React.useEffect(() => {
    if (!animate) {
      setEasedProgress(targetProgress);
      setEasedScore(targetScore);
      setPhase(0);
      return;
    }

    let frame = 0;
    let last = performance.now();
    let localPhase = 0;
    let localSpin = 0;
    let localProgress = 0;
    let localScore = 0;
    let progressSnapshot = -1;

    const tick = (now: number) => {
      const delta = Math.min(0.05, (now - last) / 1000);
      last = now;

      localPhase += delta * (active ? 2.6 : 1.1);
      localSpin += delta * (active ? 46 : 14);
      // Critically-damped approach: fast enough to feel responsive, slow enough
      // that a 17% SSE step still reads as a sweep.
      localProgress += (targetProgress - localProgress) * Math.min(1, delta * 2.2);
      localScore += (targetScore - localScore) * Math.min(1, delta * 2);

      setPhase(localPhase);
      setSpin(localSpin % 360);
      // Throttle React updates for the numeric rings to whole percent steps.
      const rounded = Math.round(localProgress);
      if (rounded !== progressSnapshot) {
        progressSnapshot = rounded;
        setEasedProgress(localProgress);
        setEasedScore(localScore);
      }
      frame = requestAnimationFrame(tick);
    };

    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [animate, active, targetProgress, targetScore]);

  const [waveFrom, waveTo] = React.useMemo(() => gradeWaveColors(grade), [grade]);

  const progressSweep = (easedProgress / 100) * 359.9;
  const waveAmplitude = 3 + (easedScore / 100) * 9 + (active ? 2.5 : 0);

  const gradientId = React.useId();

  return (
    <svg
      viewBox={`0 0 ${VIEW} ${VIEW}`}
      width={size}
      height={size}
      className="pointer-events-none absolute inset-0 h-full w-full"
      aria-hidden
    >
      <defs>
        <linearGradient id={`${gradientId}-progress`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor={accent} />
          <stop offset="55%" stopColor={verdictColor} />
          <stop offset="100%" stopColor={waveTo} />
        </linearGradient>
        <radialGradient id={`${gradientId}-wave`}>
          <stop offset="60%" stopColor={waveFrom} stopOpacity="0" />
          <stop offset="100%" stopColor={waveTo} stopOpacity="0.4" />
        </radialGradient>
        <filter id={`${gradientId}-glow`} x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Graduated bezel — 72 ticks, every sixth long. A ring without a scale is
          decoration; with one it reads as an instrument. */}
      <g opacity={0.5}>
        {Array.from({ length: TICK_COUNT }, (_unused, index) => {
          const degrees = (index / TICK_COUNT) * 360;
          const major = index % 6 === 0;
          const [x1, y1] = polar(major ? 186 : 189, degrees);
          const [x2, y2] = polar(194, degrees);
          const reached = degrees <= progressSweep;
          return (
            <line
              key={degrees}
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke={reached ? verdictColor : 'rgba(148,163,184,0.35)'}
              strokeWidth={major ? 1.6 : 0.9}
              opacity={reached ? 0.9 : 0.4}
            />
          );
        })}
      </g>

      {/* Outer track + real progress arc. */}
      <circle cx={VIEW / 2} cy={VIEW / 2} r={176} fill="none" stroke="rgba(148,163,184,0.14)" strokeWidth={3} />
      {easedProgress > 0.4 && (
        <path
          d={arcPath(176, 0, Math.min(359.9, progressSweep))}
          fill="none"
          stroke={`url(#${gradientId}-progress)`}
          strokeWidth={3}
          strokeLinecap="round"
          filter={`url(#${gradientId}-glow)`}
        />
      )}

      {/* Activity arc — counter-rotating, present only while the scan is live. */}
      {active && (
        <g transform={`rotate(${-spin} ${VIEW / 2} ${VIEW / 2})`}>
          <path
            d={arcPath(158, 0, 96)}
            fill="none"
            stroke="#e879f9"
            strokeWidth={2.6}
            strokeLinecap="round"
            opacity={0.75}
            filter={`url(#${gradientId}-glow)`}
          />
          <path d={arcPath(158, 150, 196)} fill="none" stroke={accent} strokeWidth={2} strokeLinecap="round" opacity={0.6} />
        </g>
      )}
      {!active && <circle cx={VIEW / 2} cy={VIEW / 2} r={158} fill="none" stroke="rgba(148,163,184,0.1)" strokeWidth={1.5} />}

      {/* Forward-spinning fine ring for depth. */}
      <g transform={`rotate(${spin * 0.55} ${VIEW / 2} ${VIEW / 2})`} opacity={0.55}>
        <circle
          cx={VIEW / 2}
          cy={VIEW / 2}
          r={144}
          fill="none"
          stroke={accent}
          strokeWidth={1}
          strokeDasharray="2 14"
          opacity={0.7}
        />
      </g>

      {/* Quantum wave — colour keyed to the grade, amplitude to the score. */}
      <path
        d={wavePath(126, waveAmplitude, phase, 6)}
        fill={`url(#${gradientId}-wave)`}
        stroke={waveFrom}
        strokeWidth={1.4}
        opacity={0.72}
      />
      <path
        d={wavePath(126, waveAmplitude * 0.72, -phase * 0.8, 9)}
        fill="none"
        stroke={waveTo}
        strokeWidth={1}
        opacity={0.45}
      />
    </svg>
  );
});
