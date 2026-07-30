/**
 * Quantum Visualization Engine™ — beam geometry (pure).
 *
 * Every connection between a category node and the Quantum Core is one cubic
 * Bézier, expressed twice from the same control points:
 *
 *   • `d`      — an SVG path string, for the rendered beam and GSAP MotionPath.
 *   • `points` — the same curve sampled to a polyline, for the PixiJS packet
 *                engine, which has no DOM to read a path out of.
 *
 * Deriving both from one control-point set is what keeps the glowing packets
 * exactly on the drawn line. Sampling the DOM path separately would drift the
 * moment the layout changed.
 */

export interface BeamAnchor {
  key: string;
  /** Anchor point on the node card, in band-local pixels. */
  x: number;
  y: number;
  /** Which side of the core the node sits on. */
  side: 'left' | 'right';
}

export interface BeamTarget {
  /** Core centre, band-local pixels. */
  x: number;
  y: number;
  /** Radius at which beams terminate — the core's outer rim. */
  radius: number;
}

export interface BeamPath {
  key: string;
  d: string;
  /** Sampled polyline, ordered node → core. */
  points: Array<[number, number]>;
  /** Termination point on the core rim, for the junction node. */
  tip: [number, number];
  /** Total polyline length in pixels — used to normalise packet speed. */
  length: number;
}

const SAMPLES = 56;

function cubicAt(
  t: number,
  p0: [number, number],
  p1: [number, number],
  p2: [number, number],
  p3: [number, number],
): [number, number] {
  const u = 1 - t;
  const a = u * u * u;
  const b = 3 * u * u * t;
  const c = 3 * u * t * t;
  const d = t * t * t;
  return [
    a * p0[0] + b * p1[0] + c * p2[0] + d * p3[0],
    a * p0[1] + b * p1[1] + c * p2[1] + d * p3[1],
  ];
}

/**
 * Build the beam for one anchor.
 *
 * The curve leaves the card horizontally (so it reads as a bus tap rather than a
 * random diagonal), then bends toward the core and lands perpendicular to the
 * rim. The termination point is computed from the true bearing to the core, so
 * beams fan around it instead of all hitting the same spot.
 */
export function buildBeamPath(anchor: BeamAnchor, target: BeamTarget): BeamPath {
  const dx = target.x - anchor.x;
  const dy = target.y - anchor.y;
  const bearing = Math.atan2(dy, dx);

  // Land on the rim along the bearing from the node to the core centre.
  const tipX = target.x - Math.cos(bearing) * target.radius;
  const tipY = target.y - Math.sin(bearing) * target.radius;

  const p0: [number, number] = [anchor.x, anchor.y];
  const p3: [number, number] = [tipX, tipY];
  // Horizontal departure and arrival handles: length scales with the run so
  // short beams do not overshoot.
  const run = Math.abs(dx);
  const handle = Math.max(24, run * 0.42);
  const p1: [number, number] = [anchor.x + (anchor.side === 'left' ? handle : -handle), anchor.y];
  const p2: [number, number] = [tipX - Math.cos(bearing) * handle * 0.6, tipY - Math.sin(bearing) * handle * 0.6];

  const points: Array<[number, number]> = [];
  let length = 0;
  for (let index = 0; index <= SAMPLES; index += 1) {
    const point = cubicAt(index / SAMPLES, p0, p1, p2, p3);
    if (index > 0) {
      const previous = points[index - 1];
      length += Math.hypot(point[0] - previous[0], point[1] - previous[1]);
    }
    points.push(point);
  }

  const round = (value: number) => Number(value.toFixed(2));
  const d = `M ${round(p0[0])} ${round(p0[1])} C ${round(p1[0])} ${round(p1[1])} ${round(p2[0])} ${round(p2[1])} ${round(p3[0])} ${round(p3[1])}`;

  return { key: anchor.key, d, points, tip: p3, length };
}

/** Position along a sampled polyline at normalised distance `t` (0-1). */
export function pointOnPolyline(points: Array<[number, number]>, t: number): [number, number] {
  if (points.length === 0) return [0, 0];
  const clamped = Math.max(0, Math.min(1, t));
  const scaled = clamped * (points.length - 1);
  const index = Math.floor(scaled);
  const next = Math.min(points.length - 1, index + 1);
  const fraction = scaled - index;
  const a = points[index];
  const b = points[next];
  return [a[0] + (b[0] - a[0]) * fraction, a[1] + (b[1] - a[1]) * fraction];
}
