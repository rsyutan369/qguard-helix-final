/**
 * Quantum Visualization Engine™ — Beam Renderer.
 *
 * SVG connection beams from every category node into the Quantum Core, animated
 * with GSAP's MotionPathPlugin.
 *
 * Why SVG and not images: the beams have to reflow with the layout at every
 * breakpoint and recolour per verdict. A raster line cannot do either, and the
 * engine spec forbids it outright.
 *
 * What is real here: beam colour and packet cadence come from the node's own
 * state in the event store. Colour follows the node's measured grade band once
 * it has one, and escalates to red for any high or critical observation.
 *
 * DIRECTION CARRIES MEANING
 * -------------------------
 * Every beam is duplex, and the two directions are different statements:
 *
 *   outbound (core → card)   The core dispatching an interrogation at that
 *                            surface. Present while a node is dormant or being
 *                            probed — this is why a Standby card is still lit
 *                            and still connected, rather than looking broken.
 *   inbound  (card → core)   Evidence returning. Present the moment a node has
 *                            something real to report, and continuing as a slow
 *                            confirmation pulse once it has settled.
 *
 * A dormant node therefore shows outbound light only: the scanner is reaching
 * for it and nothing has come back yet. That is an accurate picture of the run,
 * and it is the reason no card is ever drawn as an island.
 */
'use client';

import React from 'react';
import gsap from 'gsap';
import { MotionPathPlugin } from 'gsap/MotionPathPlugin';
import { beamColor, type QveNode, type QveNodeKey } from '../types';
import { buildBeamPath, type BeamAnchor, type BeamPath, type BeamTarget } from './beam-geometry';

gsap.registerPlugin(MotionPathPlugin);

export interface BeamNetworkProps {
  width: number;
  height: number;
  anchors: BeamAnchor[];
  target: BeamTarget;
  nodes: Record<QveNodeKey, QveNode>;
  /** Master motion switch. */
  animate: boolean;
  /** Packets per beam in flight. Scaled by the Performance Manager. */
  density: number;
  /** True while the assessment is live — keeps outbound interrogation flowing. */
  running: boolean;
  /** Exposes the computed geometry so the Pixi packet engine can reuse it. */
  onPaths?: (paths: BeamPath[]) => void;
}

/**
 * How many packets each direction of a beam carries.
 *
 * `outbound` never falls to zero while the run is live: the core is querying
 * every surface it knows about for the whole assessment, and a node that has
 * already settled still sits on an active conduit.
 */
function packetPlan(
  node: QveNode,
  density: number,
  running: boolean,
): { inbound: number; outbound: number } {
  if (density <= 0) return { inbound: 0, outbound: 0 };
  const unit = Math.max(1, Math.round(density));

  switch (node.state) {
    case 'scanning':
      // Duplex and busy: probes going out, evidence coming back.
      return { inbound: unit, outbound: Math.max(1, Math.round(density * 0.6)) };
    case 'critical':
    case 'failed':
      return { inbound: Math.max(1, Math.round(density * 0.75)), outbound: running ? 1 : 0 };
    case 'pass':
    case 'warning':
      return { inbound: 1, outbound: running ? 1 : 0 };
    default:
      // Dormant. Outbound only — the core is reaching for a surface that has
      // not answered yet. This is the case that used to render as nothing.
      return { inbound: 0, outbound: 1 };
  }
}

/** Travel time in seconds — scanning is urgent, a settled beam is a slow pulse. */
function packetDuration(node: QveNode): number {
  switch (node.state) {
    case 'scanning':
      return 1.5;
    case 'critical':
    case 'failed':
      return 0.85;
    case 'idle':
      // A dormant conduit breathes rather than streams.
      return 4.6;
    default:
      return 3.4;
  }
}

export const BeamNetwork = React.memo(function BeamNetwork({
  width,
  height,
  anchors,
  target,
  nodes,
  animate,
  density,
  running,
  onPaths,
}: BeamNetworkProps) {
  const paths = React.useMemo(
    () => anchors.map((anchor) => buildBeamPath(anchor, target)),
    [anchors, target],
  );

  React.useEffect(() => {
    onPaths?.(paths);
  }, [paths, onPaths]);

  const gradientId = React.useId();

  if (!width || !height) return null;

  return (
    <svg
      className="pointer-events-none absolute inset-0 h-full w-full"
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      aria-hidden
    >
      <defs>
        <filter id={`${gradientId}-beamglow`} x="-20%" y="-40%" width="140%" height="180%">
          <feGaussianBlur stdDeviation="2.4" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {paths.map((path) => {
        const node = nodes[path.key as QveNodeKey];
        if (!node) return null;
        const color = beamColor(node);
        const live = node.state !== 'idle';
        const plan = packetPlan(node, density, running);
        const duration = packetDuration(node);

        return (
          <g key={path.key}>
            {/* Conduit. Always drawn, always visible: every card is physically
                attached to the core whether or not it has reported yet. A
                dormant conduit is dashed so "connected but silent" and
                "connected and carrying" are distinguishable at a glance. */}
            <path
              d={path.d}
              fill="none"
              stroke={color}
              strokeWidth={live ? 1.1 : 1}
              opacity={live ? 0.34 : 0.4}
              strokeLinecap="round"
              strokeDasharray={live ? undefined : '4 7'}
            />
            {/* Energised core of the beam. */}
            {live && (
              <path
                d={path.d}
                fill="none"
                stroke={color}
                strokeWidth={2}
                opacity={0.75}
                strokeLinecap="round"
                filter={`url(#${gradientId}-beamglow)`}
              />
            )}
            {/* Junction on the core rim. */}
            <circle
              cx={path.tip[0]}
              cy={path.tip[1]}
              r={live ? 3.6 : 2.8}
              fill={color}
              opacity={live ? 0.95 : 0.7}
              filter={`url(#${gradientId}-beamglow)`}
            />
            {/* Tap on the card edge. */}
            <circle
              cx={path.points[0][0]}
              cy={path.points[0][1]}
              r={2.6}
              fill={color}
              opacity={live ? 0.85 : 0.6}
            />

            {animate && (
              <>
                {/* Evidence returning to the core. */}
                <BeamPackets
                  path={path}
                  color={color}
                  count={plan.inbound}
                  duration={duration}
                  direction="inbound"
                  jitter={node.state === 'critical' || node.state === 'failed'}
                />
                {/* Interrogation leaving the core. */}
                <BeamPackets
                  path={path}
                  color={color}
                  count={plan.outbound}
                  duration={duration * (node.state === 'idle' ? 1 : 1.25)}
                  direction="outbound"
                  jitter={false}
                />
              </>
            )}
          </g>
        );
      })}
    </svg>
  );
});

/* ------------------------------------------------------------------- packets - */

/**
 * GSAP MotionPath packets. Each packet is a real SVG element tweened along the
 * beam's path data with `autoRotate`, easing in so it accelerates out of the
 * node — the "packets should accelerate" requirement — and repeating with a
 * stagger so the beam reads as a continuous flow rather than a metronome.
 *
 * `direction` runs the SAME path backwards via MotionPath's `start`/`end`
 * rather than a second reversed path string. Two path strings would be two
 * sources of truth for one curve, and they would drift apart the moment the
 * layout moved.
 */
function BeamPackets({
  path,
  color,
  count,
  duration,
  direction,
  jitter,
}: {
  path: BeamPath;
  color: string;
  count: number;
  duration: number;
  direction: 'inbound' | 'outbound';
  jitter: boolean;
}) {
  const group = React.useRef<SVGGElement>(null);
  const outbound = direction === 'outbound';

  React.useEffect(() => {
    const container = group.current;
    if (!container || count <= 0) return;

    const packets = Array.from(container.querySelectorAll<SVGElement>('[data-packet]'));
    if (!packets.length) return;

    const context = gsap.context(() => {
      packets.forEach((packet, index) => {
        gsap.set(packet, { opacity: 0 });
        gsap
          .timeline({ repeat: -1, delay: (index * duration) / packets.length })
          .to(packet, { opacity: 1, duration: duration * 0.12, ease: 'none' }, 0)
          .to(
            packet,
            {
              // No `align`: the packet is already authored in the same viewBox
              // coordinate space as the path, so aligning it to another element
              // would double-apply the offset.
              motionPath: {
                path: path.d,
                autoRotate: true,
                // The stored curve runs card → core. An outbound probe is that
                // same curve traversed from the core end.
                start: outbound ? 1 : 0,
                end: outbound ? 0 : 1,
              },
              duration,
              // Accelerating departure, decelerating arrival.
              ease: 'power1.inOut',
            },
            0,
          )
          .to(packet, { opacity: 0, duration: duration * 0.18, ease: 'none' }, duration * 0.82);

        if (jitter) {
          gsap.to(packet, {
            scale: 1.5,
            duration: 0.12,
            repeat: -1,
            yoyo: true,
            ease: 'none',
            transformOrigin: 'center',
          });
        }
      });
    }, container);

    return () => context.revert();
  }, [path.d, count, duration, jitter, outbound]);

  return (
    <g ref={group}>
      {Array.from({ length: count }, (_unused, index) => (
        <g key={index} data-packet>
          {/* Motion trail: a short tapered tail behind the head. `autoRotate`
              turns the packet along the direction of travel, so the tail is
              authored once and trails correctly both ways. Outbound probes are
              smaller and dimmer than returning evidence — a query is not a
              finding, and the visual weight should say so. */}
          <path
            d="M -13 0 L 0 -1.6 L 0 1.6 Z"
            fill={color}
            opacity={outbound ? 0.3 : 0.45}
          />
          <circle r={outbound ? 1.9 : 2.6} fill={color} opacity={outbound ? 0.8 : 1} />
          <circle r={outbound ? 4 : 5.2} fill={color} opacity={outbound ? 0.16 : 0.22} />
        </g>
      ))}
    </g>
  );
}
