/**
 * Quantum Visualization Engine™ — quantum-dust particle field (tsParticles).
 *
 * The "digital particles / floating bits / neural network" layer of the backdrop.
 * Linked particles give the mesh; the drift gives the dust.
 *
 * Reacts to scan activity, which is the whole reason it is wired to engine state
 * rather than left as ambient decoration: while a scan is live the field speeds
 * up, links reach further and the dust brightens. At rest it drifts slowly.
 *
 * Lazy-loaded (see QuantumBackdrop) so neither tsParticles nor its slim bundle is
 * fetched on devices the Performance Manager excludes.
 */
'use client';

import React from 'react';
import type { Engine, ISourceOptions } from '@tsparticles/engine';
import { Particles, ParticlesProvider } from '@tsparticles/react';

export interface ParticleFieldProps {
  accent: string;
  quantum: boolean;
  count: number;
  active: boolean;
}

/** Registers only the slim feature set — the full bundle is ~3× the size. */
const registerEngine = async (engine: Engine): Promise<void> => {
  const { loadSlim } = await import('@tsparticles/slim');
  await loadSlim(engine);
};

function buildOptions(accent: string, quantum: boolean, count: number, active: boolean): ISourceOptions {
  const linkColor = quantum ? '#a78bfa' : accent;
  return {
    fullScreen: { enable: false },
    detectRetina: true,
    fpsLimit: 60,
    background: { color: 'transparent' },
    particles: {
      number: { value: count, density: { enable: true, width: 1600, height: 900 } },
      color: { value: [accent, linkColor, '#60a5fa'] },
      shape: { type: 'circle' },
      opacity: {
        value: { min: 0.12, max: active ? 0.6 : 0.38 },
        animation: { enable: true, speed: active ? 0.8 : 0.35, sync: false },
      },
      size: { value: { min: 0.6, max: active ? 2.2 : 1.6 } },
      links: {
        enable: true,
        color: linkColor,
        distance: active ? 148 : 118,
        opacity: active ? 0.2 : 0.11,
        width: 0.7,
      },
      move: {
        enable: true,
        speed: active ? 0.85 : 0.28,
        direction: 'none',
        random: true,
        straight: false,
        outModes: { default: 'out' },
      },
    },
    // No pointer interactivity: the field sits behind a data layer the visitor
    // needs to click, and grabbing particles would fight the input for focus.
    interactivity: { events: { onHover: { enable: false }, onClick: { enable: false } } },
  };
}

export default function ParticleField({ accent, quantum, count, active }: ParticleFieldProps) {
  const options = React.useMemo(
    () => buildOptions(accent, quantum, count, active),
    [accent, quantum, count, active],
  );

  return (
    <ParticlesProvider init={registerEngine}>
      <Particles
        id="qve-quantum-dust"
        options={options}
        className="absolute inset-0 h-full w-full"
        style={{ position: 'absolute', inset: 0 }}
      />
    </ParticlesProvider>
  );
}
