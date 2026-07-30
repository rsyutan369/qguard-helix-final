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
 * state in the event store. An idle node's beam is dark and carries nothing; a
 * scanning node carries continuous packets; a settled node carries a slow
 * confirmation pulse in its verdict colour; a critical node turns red and emits
 * fast, jittering packets.
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
  /** Exposes the computed geometry so the Pixi packet engine can reuse it. */
  onPaths?: (paths: BeamPath[]) => void;
}

/** How many packets a beam carries, by node state. */
function packetCount(node: QveNode, density: number): number {
  if (density <= 0) return 0;
  switch (node.state) {
    case 'scanning':
      return Math.max(1, Math.round(density));
    case 'critical':
    case 'failed':
      return Math.max(1, Math.round(density * 0.75));
    case 'pass':
    case 'warning':
      return 1;
    default:
      return 0;
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

        return (
          <g key={path.key}>
            {/* Conduit — always visible so the topology reads before a scan. */}
            <path
              d={path.d}
              fill="none"
              stroke={color}
              strokeWidth={1}
              opacity={live ? 0.28 : 0.16}
              strokeLinecap="round"
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
              r={live ? 3.6 : 2.4}
              fill={color}
              opacity={live ? 0.95 : 0.35}
              filter={live ? `url(#${gradientId}-beamglow)` : undefined}
            />
            {/* Tap on the card edge. */}
            <circle cx={path.points[0][0]} cy={path.points[0][1]} r={2.6} fill={color} opacity={live ? 0.85 : 0.3} />

            {animate && (
              <BeamPackets
                path={path}
                color={color}
                count={packetCount(node, density)}
                duration={packetDuration(node)}
                jitter={node.state === 'critical' || node.state === 'failed'}
              />
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
 */
function BeamPackets({
  path,
  color,
  count,
  duration,
  jitter,
}: {
  path: BeamPath;
  color: string;
  count: number;
  duration: number;
  jitter: boolean;
}) {
  const group = React.useRef<SVGGElement>(null);

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
              motionPath: { path: path.d, autoRotate: true },
              duration,
              // Accelerating departure, decelerating arrival into the core.
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
  }, [path.d, count, duration, jitter]);

  return (
    <g ref={group}>
      {Array.from({ length: count }, (_unused, index) => (
        <g key={index} data-packet>
          {/* Motion trail: a short tapered tail behind the head. */}
          <path d="M -13 0 L 0 -1.6 L 0 1.6 Z" fill={color} opacity={0.45} />
          <circle r={2.6} fill={color} />
          <circle r={5.2} fill={color} opacity={0.22} />
        </g>
      ))}
    </g>
  );
}
