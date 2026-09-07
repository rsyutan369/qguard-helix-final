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
import type { Container, Engine, ISourceOptions } from '@tsparticles/engine';
import { Particles, ParticlesProvider } from '@tsparticles/react';
import type { QvePalette } from '../theme';

export interface ParticleFieldProps {
  accent: string;
  quantum: boolean;
  count: number;
  active: boolean;
  /* Passed down rather than read from context: this component is lazily loaded
     inside a Suspense boundary, and taking it as a prop keeps the option set
     memoised on one value the parent already has. */
  palette: QvePalette;
}

/** Registers only the slim feature set — the full bundle is ~3× the size. */
const registerEngine = async (engine: Engine): Promise<void> => {
  const { loadSlim } = await import('@tsparticles/slim');
  await loadSlim(engine);
};

/**
 * OPTIONS MUST STAY REFERENTIALLY STABLE.
 *
 * `<Particles>` tears the container down and rebuilds it whenever `options`
 * changes identity, which blanks the canvas for a frame or two. Rebuilding it on
 * scan start and again on completion — precisely the two moments the visitor is
 * watching — produced a visible blink. So the option set is built once from
 * `count` alone, and scan reactivity is applied to the *live* container instead
 * (see the effect below), which needs no rebuild.
 */
function buildOptions(count: number, palette: QvePalette): ISourceOptions {
  /* Palette, not literals: the mesh is drawn as emitted light, and #22d3ee over
     white is 1.68:1 — on the light hero the field simply was not there. */
  const [accent, linkColor, quantumColor] = palette.particle;
  const active = false;
  return {
    fullScreen: { enable: false },
    detectRetina: true,
    fpsLimit: 60,
    background: { color: 'transparent' },
    particles: {
      number: { value: count, density: { enable: true, width: 1600, height: 900 } },
      color: { value: [accent, linkColor, quantumColor] },
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

export default function ParticleField({ accent, quantum, count, active, palette }: ParticleFieldProps) {
  /* The palette is read through a REF for the initial build and applied to the
     live container afterwards — the same discipline the option set already
     follows for scan reactivity, and for the same reason stated above: putting
     it in the memo's dependencies would rebuild the whole tsParticles container
     on a theme toggle, blanking the field exactly when the user is watching it
     change. */
  const paletteRef = React.useRef(palette);
  const options = React.useMemo(() => buildOptions(count, paletteRef.current), [count]);
  const container = React.useRef<Container | null>(null);

  const onLoaded = React.useCallback((instance?: Container) => {
    container.current = instance ?? null;
  }, []);

  // Scan reactivity applied in place: new particles adopt the faster drift and
  // longer link reach, and the wrapper brightens. No rebuild, no blink.
  React.useEffect(() => {
    paletteRef.current = palette;
    const instance = container.current;
    if (!instance) return;
    try {
      const particles = instance.actualOptions.particles;
      particles.move.speed = active ? 0.9 : 0.28;
      // Theme applied in place too: newly spawned dust adopts the ground's
      // palette, and the links — which are redrawn every frame — change at once.
      (particles.color as { value: string[] }).value = [...palette.particle];
      // `links` is contributed by the interaction plugin, so the engine types it
      // as `unknown` on the base particle options. Narrowed here rather than
      // reaching into plugin internals.
      const links = particles.links as { distance: number; color: { value: string } } | undefined;
      if (links) {
        links.distance = active ? 148 : 118;
        links.color.value = quantum ? palette.particle[2] : palette.particle[1];
      }
    } catch {
      // tsParticles internals are best-effort enrichment; the field is
      // decorative and must never break the hero if the shape changes.
    }
  }, [active, quantum, accent, palette]);

  return (
    <ParticlesProvider init={registerEngine}>
      <div
        className="absolute inset-0 transition-opacity duration-700"
        style={{ opacity: active ? 1 : 0.55 }}
      >
        <Particles
          id="qve-quantum-dust"
          options={options}
          particlesLoaded={onLoaded}
          className="absolute inset-0 h-full w-full"
          style={{ position: 'absolute', inset: 0 }}
        />
      </div>
    </ParticlesProvider>
  );
}
