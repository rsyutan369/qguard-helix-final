/**
 * Quantum Visualization Engine™ — GPU Particle / Energy Packet Engine (PixiJS).
 *
 * The additive-blended glow layer that sits between the SVG beams and the core.
 * Where the SVG beams provide the *structure* (always-visible topology, crisp at
 * any DPI), this engine provides the *energy*: on every real scan event a burst
 * of glowing packets accelerates from the reporting node into the Quantum Core,
 * leaving a fading trail. Critical findings additionally throw radial sparks off
 * the core rim.
 *
 * Strictly event-driven. `spawnFor` is called from the event store's tick — no
 * packet exists that does not correspond to an observation the scanner made.
 *
 * Lifecycle discipline: PixiJS `Application.init()` is async, so an unmount can
 * land mid-initialisation. The `disposed` flag and the destroy path below are the
 * reason this component does not leak a WebGL context on Fast Refresh.
 */
'use client';

import React from 'react';
import type { Application, Sprite, Texture } from 'pixi.js';
import type { BeamPath } from '../beams/beam-geometry';
import { pointOnPolyline } from '../beams/beam-geometry';

export interface PacketBurst {
  /** Beam key the packets travel along. */
  beam: string;
  color: string;
  /** How many packets this observation is worth. */
  count: number;
  /** True for high/critical findings — adds sparks and a faster, hotter burst. */
  alert: boolean;
}

export interface PacketEngineHandle {
  burst: (burst: PacketBurst) => void;
}

export interface PacketEngineProps {
  width: number;
  height: number;
  paths: BeamPath[];
  /** Core centre + radius, for spark origin. */
  core: { x: number; y: number; radius: number };
  maxPackets: number;
  dpr: number;
  handleRef: React.MutableRefObject<PacketEngineHandle | null>;
}

const TRAIL_LENGTH = 7;

interface LivePacket {
  beam: string;
  /** Normalised travel position, 0 at the node, 1 at the core rim. */
  t: number;
  velocity: number;
  acceleration: number;
  head: Sprite;
  trail: Sprite[];
  history: Array<[number, number]>;
  alive: boolean;
}

interface LiveSpark {
  sprite: Sprite;
  x: number;
  y: number;
  vx: number;
  vy: number;
  life: number;
  maxLife: number;
}

/** Soft radial glow, drawn once into a canvas and tinted per packet. */
function createGlowCanvas(): HTMLCanvasElement {
  const canvas = document.createElement('canvas');
  canvas.width = 64;
  canvas.height = 64;
  const context = canvas.getContext('2d');
  if (context) {
    const gradient = context.createRadialGradient(32, 32, 0, 32, 32, 32);
    gradient.addColorStop(0, 'rgba(255,255,255,1)');
    gradient.addColorStop(0.28, 'rgba(255,255,255,0.62)');
    gradient.addColorStop(0.62, 'rgba(255,255,255,0.18)');
    gradient.addColorStop(1, 'rgba(255,255,255,0)');
    context.fillStyle = gradient;
    context.fillRect(0, 0, 64, 64);
  }
  return canvas;
}

export function PacketEngine({
  width,
  height,
  paths,
  core,
  maxPackets,
  dpr,
  handleRef,
}: PacketEngineProps) {
  const canvasRef = React.useRef<HTMLCanvasElement>(null);
  const appRef = React.useRef<Application | null>(null);
  const packetsRef = React.useRef<LivePacket[]>([]);
  const sparksRef = React.useRef<LiveSpark[]>([]);
  const pathsRef = React.useRef<BeamPath[]>(paths);
  const coreRef = React.useRef(core);
  const readyRef = React.useRef(false);

  pathsRef.current = paths;
  coreRef.current = core;

  /* ── Boot / teardown ───────────────────────────────────────────────────── */

  React.useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || maxPackets <= 0) return;

    let disposed = false;
    let app: Application | null = null;
    let texture: Texture | null = null;

    (async () => {
      const pixi = await import('pixi.js');
      if (disposed) return;

      app = new pixi.Application();
      await app.init({
        canvas,
        width: Math.max(1, width),
        height: Math.max(1, height),
        backgroundAlpha: 0,
        antialias: false,
        resolution: dpr,
        autoDensity: true,
        preference: 'webgl',
      });
      if (disposed) {
        app.destroy(true, { children: true, texture: true });
        return;
      }

      texture = pixi.Texture.from(createGlowCanvas());
      const layer = new pixi.Container();
      // One additive layer: overlapping packets brighten rather than occlude,
      // which is what makes the beams read as light instead of paint.
      layer.blendMode = 'add';
      app.stage.addChild(layer);

      const acquire = (): Sprite => {
        const sprite = new pixi.Sprite(texture!);
        sprite.anchor.set(0.5);
        sprite.blendMode = 'add';
        sprite.visible = false;
        layer.addChild(sprite);
        return sprite;
      };

      // Pre-allocate the entire pool up front: allocating sprites mid-scan is
      // exactly when a frame drop would be most visible.
      const headPool: Sprite[] = [];
      const trailPool: Sprite[] = [];
      const sparkPool: Sprite[] = [];
      for (let index = 0; index < maxPackets; index += 1) headPool.push(acquire());
      for (let index = 0; index < maxPackets * TRAIL_LENGTH; index += 1) trailPool.push(acquire());
      for (let index = 0; index < 48; index += 1) sparkPool.push(acquire());

      const takeHead = () => headPool.pop() ?? null;
      const takeTrail = (count: number) => trailPool.splice(0, count);
      const takeSpark = () => sparkPool.pop() ?? null;

      const releasePacket = (packet: LivePacket) => {
        packet.head.visible = false;
        headPool.push(packet.head);
        for (const sprite of packet.trail) {
          sprite.visible = false;
          trailPool.push(sprite);
        }
      };

      const releaseSpark = (spark: LiveSpark) => {
        spark.sprite.visible = false;
        sparkPool.push(spark.sprite);
      };

      handleRef.current = {
        burst: ({ beam, color, count, alert }: PacketBurst) => {
          const path = pathsRef.current.find((candidate) => candidate.key === beam);
          if (!path) return;
          const tint = Number.parseInt(color.replace('#', ''), 16);

          for (let index = 0; index < count; index += 1) {
            if (packetsRef.current.length >= maxPackets) break;
            const head = takeHead();
            if (!head) break;
            const trail = takeTrail(TRAIL_LENGTH);
            head.tint = tint;
            head.visible = true;
            head.scale.set(alert ? 0.42 : 0.34);
            for (const sprite of trail) {
              sprite.tint = tint;
              sprite.visible = false;
            }
            packetsRef.current.push({
              beam,
              t: 0,
              // Normalised units per second. Longer beams travel no slower —
              // speed is divided by length so arrival timing is consistent.
              velocity: ((alert ? 340 : 210) + Math.random() * 60) / Math.max(120, path.length),
              acceleration: ((alert ? 520 : 300) + Math.random() * 120) / Math.max(120, path.length),
              head,
              trail,
              history: [],
              alive: true,
            });
          }

          if (alert) {
            const centre = coreRef.current;
            for (let index = 0; index < 14; index += 1) {
              const sprite = takeSpark();
              if (!sprite) break;
              const angle = Math.random() * Math.PI * 2;
              const speed = 60 + Math.random() * 190;
              sprite.tint = tint;
              sprite.visible = true;
              sprite.scale.set(0.16 + Math.random() * 0.16);
              sparksRef.current.push({
                sprite,
                x: centre.x + Math.cos(angle) * centre.radius * 0.9,
                y: centre.y + Math.sin(angle) * centre.radius * 0.9,
                vx: Math.cos(angle) * speed,
                vy: Math.sin(angle) * speed,
                life: 0,
                maxLife: 0.5 + Math.random() * 0.4,
              });
            }
          }
        },
      };

      app.ticker.add((ticker) => {
        const delta = Math.min(0.05, ticker.deltaMS / 1000);

        /* Packets */
        for (const packet of packetsRef.current) {
          const path = pathsRef.current.find((candidate) => candidate.key === packet.beam);
          if (!path) {
            packet.alive = false;
            continue;
          }
          packet.velocity += packet.acceleration * delta;
          packet.t += packet.velocity * delta;

          if (packet.t >= 1) {
            packet.alive = false;
            continue;
          }

          const [x, y] = pointOnPolyline(path.points, packet.t);
          packet.head.position.set(x, y);
          // Fade in over the first 12% and out over the last 18% of the run so
          // packets never pop into or out of existence.
          const fadeIn = Math.min(1, packet.t / 0.12);
          const fadeOut = Math.min(1, (1 - packet.t) / 0.18);
          packet.head.alpha = Math.min(fadeIn, fadeOut);

          packet.history.unshift([x, y]);
          if (packet.history.length > TRAIL_LENGTH) packet.history.length = TRAIL_LENGTH;
          for (let index = 0; index < packet.trail.length; index += 1) {
            const sample = packet.history[index + 1];
            const sprite = packet.trail[index];
            if (!sample) {
              sprite.visible = false;
              continue;
            }
            sprite.visible = true;
            sprite.position.set(sample[0], sample[1]);
            const decay = 1 - index / TRAIL_LENGTH;
            sprite.alpha = packet.head.alpha * decay * 0.5;
            sprite.scale.set(packet.head.scale.x * decay * 0.8);
          }
        }

        const survivors: LivePacket[] = [];
        for (const packet of packetsRef.current) {
          if (packet.alive) survivors.push(packet);
          else releasePacket(packet);
        }
        packetsRef.current = survivors;

        /* Sparks */
        const liveSparks: LiveSpark[] = [];
        for (const spark of sparksRef.current) {
          spark.life += delta;
          if (spark.life >= spark.maxLife) {
            releaseSpark(spark);
            continue;
          }
          spark.x += spark.vx * delta;
          spark.y += spark.vy * delta;
          // Drag, so sparks decelerate rather than fly off screen.
          spark.vx *= 1 - 2.4 * delta;
          spark.vy *= 1 - 2.4 * delta;
          spark.sprite.position.set(spark.x, spark.y);
          spark.sprite.alpha = 1 - spark.life / spark.maxLife;
          liveSparks.push(spark);
        }
        sparksRef.current = liveSparks;
      });

      appRef.current = app;
      readyRef.current = true;
    })().catch((error) => {
      // A GPU that refuses the context is not a page failure — the SVG beams
      // already carry the information; the glow is enrichment.
      console.warn('[qve] packet engine unavailable', error);
    });

    return () => {
      disposed = true;
      readyRef.current = false;
      handleRef.current = null;
      packetsRef.current = [];
      sparksRef.current = [];
      const current = app ?? appRef.current;
      if (current) {
        current.ticker.stop();
        current.destroy(true, { children: true, texture: true });
      }
      appRef.current = null;
    };
    // Intentionally not re-running on width/height: the renderer is resized
    // below instead of being torn down and rebuilt on every layout tick.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [maxPackets, dpr, handleRef]);

  /* ── Resize ────────────────────────────────────────────────────────────── */

  React.useEffect(() => {
    const app = appRef.current;
    if (!app || !readyRef.current || width <= 0 || height <= 0) return;
    app.renderer.resize(width, height);
  }, [width, height]);

  if (maxPackets <= 0) return null;

  return (
    <canvas
      ref={canvasRef}
      className="pointer-events-none absolute inset-0 h-full w-full"
      style={{ width, height }}
      aria-hidden
    />
  );
}
