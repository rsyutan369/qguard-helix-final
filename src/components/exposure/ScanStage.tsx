'use client';

/**
 * Quantum Scan Stage — the live scanning canvas.
 *
 * WHAT IS REAL HERE, AND WHY IT MATTERS
 * -------------------------------------
 * This is a visualisation, not a decoration, so every element that could be
 * read as a claim is driven by the running scan:
 *
 *  - the vertical sweep line sits at the scan's REAL progress, and the tinted
 *    region behind it is the part of the estate the engines have actually
 *    finished;
 *  - the lens travels to, and reads out, the REAL artefact the current engine
 *    named in its last progress event;
 *  - the token stream on the right is the REAL algorithms and artefacts this
 *    scan has observed, coloured by their real quantum verdict;
 *  - every detection marker is a REAL finding, placed at the progress point it
 *    was discovered at, and opens that finding when clicked.
 *
 * The only ambient element is the binary field, and even that is not noise: the
 * bits are the FNV hashes of the artefacts currently in the read queue, so the
 * field literally moves with the corpus. Nothing on this canvas is a
 * placeholder, a fabricated metric or an invented algorithm name.
 *
 * PERFORMANCE
 * -----------
 * One rAF loop, one offscreen field buffer, device pixel ratio capped at 2. The
 * lens magnifies by blitting the field buffer rather than repainting it, so the
 * optical effect costs a single `drawImage`. The loop suspends when the tab is
 * hidden or the stage scrolls out of view, and never starts at all under
 * `prefers-reduced-motion` — that path paints one composed still frame.
 */

import React from 'react';
import { useReducedMotion } from 'motion/react';
import { stableHash } from '@/lib/scanner/exposure/types';
import type { FindingSeverity } from '@/lib/scanner/exposure/types';

/* ──────────────────────────────────────────────────────────────── contract ── */

export interface StageToken {
  /** Real observed text: an algorithm name, a component, an artefact path. */
  text: string;
  /** Quantum-verdict colour. Never decorative. */
  color: string;
}

export interface StageDetection {
  id: string;
  severity: FindingSeverity;
  color: string;
  title: string;
  detail: string;
  /** Scan progress, 0-100, at the moment this finding arrived. */
  atProgress: number;
}

export interface ScanStageProps {
  /** True while engines are executing. False freezes the field. */
  running: boolean;
  /** Real 0-100 progress. Drives the sweep line and the scanned region. */
  progress: number;
  /** The artefact the current engine last named, if it named one. */
  focus: string | null;
  /** Engine label for the readout under the caption. */
  engineLabel: string | null;
  /** Caption verb — reflects the real lifecycle state. */
  caption: string;
  tokens: StageToken[];
  detections: StageDetection[];
  /** Severity colour of the newest finding, for the lens flash. */
  onSelectDetection?: (id: string) => void;
  className?: string;
}

/* ───────────────────────────────────────────────────────────────── helpers ── */

const CYAN = '#22d3ee';
const VIOLET = '#a78bfa';
const BLUE = '#38bdf8';

/** 32 bits of a real artefact path, as the characters the field will rain. */
function bitsFor(source: string): string {
  const hash = parseInt(stableHash(source), 16) >>> 0;
  return hash.toString(2).padStart(32, '0');
}

/**
 * Deterministic 0..1 from a string — same finding, same lane, every render.
 *
 * The FNV hash is avalanched again before use. FNV-1a over near-identical
 * inputs (`off0`, `off1`, `off2`…) walks its high bits almost linearly, which
 * laid every rain column out on a diagonal instead of scattering them.
 */
function unitHash(source: string, salt = ''): number {
  let x = parseInt(stableHash(`${salt}${source}`), 16) >>> 0;
  x ^= x >>> 15;
  x = Math.imul(x, 2246822519) >>> 0;
  x ^= x >>> 13;
  x = Math.imul(x, 3266489917) >>> 0;
  x ^= x >>> 16;
  return (x >>> 0) / 0xffffffff;
}

function basename(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `…${value.slice(value.length - max + 1)}`;
}

/* ───────────────────────────────────────────────────────────────── the view ── */

export function ScanStage({
  running,
  progress,
  focus,
  engineLabel,
  caption,
  tokens,
  detections,
  onSelectDetection,
  className,
}: ScanStageProps) {
  const reduceMotion = useReducedMotion();
  const hostRef = React.useRef<HTMLDivElement | null>(null);
  const canvasRef = React.useRef<HTMLCanvasElement | null>(null);
  const [size, setSize] = React.useState({ width: 0, height: 0 });
  const [hovered, setHovered] = React.useState<StageDetection | null>(null);

  /* Latest props, read by the render loop without restarting it. A loop that
     tears down on every progress event would stutter once a second. */
  const live = React.useRef({ running, progress, focus, tokens, detections });
  live.current = { running, progress, focus, tokens, detections };

  /* ── measurement ─────────────────────────────────────────────────────── */
  React.useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const observer = new ResizeObserver((entries) => {
      const box = entries[0]?.contentRect;
      if (box) setSize({ width: Math.round(box.width), height: Math.round(box.height) });
    });
    observer.observe(host);
    setSize({ width: host.clientWidth, height: host.clientHeight });
    return () => observer.disconnect();
  }, []);

  /* ── the painter ─────────────────────────────────────────────────────── */
  React.useEffect(() => {
    const canvas = canvasRef.current;
    const host = hostRef.current;
    if (!canvas || !host || size.width < 2 || size.height < 2) return;

    const dpr = Math.min(2, typeof window === 'undefined' ? 1 : window.devicePixelRatio || 1);
    const width = size.width;
    const height = size.height;

    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    /* Offscreen field buffer: painted once per frame, then blitted twice —
       once flat, once magnified inside the lens. */
    const field = document.createElement('canvas');
    field.width = canvas.width;
    field.height = canvas.height;
    const fieldCtx = field.getContext('2d');
    if (!fieldCtx) return;

    const CELL = 14;
    const COLUMN = 13;
    const columnCount = Math.max(6, Math.ceil(width / COLUMN));
    const TAIL = 22;

    /* Column cadence is deterministic per column, so the field does not
       reshuffle itself every time React re-renders the stage. */
    const cycle = height + TAIL * CELL;
    const rowCount = Math.ceil(height / CELL) + 1;
    const columns = Array.from({ length: columnCount }, (_, index) => ({
      x: index * COLUMN + 6,
      speed: 26 + unitHash(String(index), 'col') * 46,
      /* Seeded across the WHOLE cycle, not just the visible height, so the
         field is already full on the first painted frame. */
      offset: unitHash(String(index), 'off') * cycle,
    }));

    /* Token lanes on the right third. Each lane holds one real observation and
       recycles to the next when it leaves the stage. */
    const laneCount = Math.max(3, Math.min(9, Math.floor(height / 34)));
    const lanes = Array.from({ length: laneCount }, (_, index) => ({
      y: (index / laneCount) * height,
      speed: 12 + unitHash(String(index), 'lane') * 16,
      cursor: index,
    }));

    /* Lens physics: a position that eases toward the artefact currently being
       read. Real events move the glass — a timer never does. */
    const lens = {
      x: width * 0.5,
      y: height * 0.5,
      targetX: width * 0.5,
      targetY: height * 0.5,
      radius: Math.max(66, Math.min(108, Math.min(width, height) * 0.27)),
    };
    let focusKey = '';
    let flashUntil = 0;
    let flashColor = CYAN;
    let seenDetections = new Set<string>();
    const ripples: Array<{ x: number; y: number; start: number; color: string }> = [];

    const paintField = (elapsed: number) => {
      const fc = fieldCtx;
      fc.setTransform(dpr, 0, 0, dpr, 0, 0);
      fc.clearRect(0, 0, width, height);

      const { tokens: liveTokens, focus: liveFocus } = live.current;

      /* ── binary rain, seeded from the real read queue ───────────────── */
      const sources = liveTokens.length
        ? liveTokens.map((token) => token.text)
        : [liveFocus ?? 'qguard-helix'];
      fc.font = '600 11px ui-monospace, SFMono-Regular, Menlo, monospace';
      fc.textBaseline = 'top';

      /* The resting matrix: every cell carries a bit, so the field reads as a
         continuous surface being interrogated rather than a few falling
         streaks. It turns over about once a second, slowly enough to read. */
      const turn = Math.floor(elapsed / 850);
      for (let index = 0; index < columns.length; index += 1) {
        const column = columns[index];
        const rightward = column.x / width;
        if (rightward > 0.58 && index % 2 === 1) continue;
        const bits = bitsFor(sources[index % sources.length] + index);
        fc.fillStyle = `rgba(${Math.round(56 + rightward * 111)},${Math.round(189 - rightward * 50)},${Math.round(248 - rightward * 8)},${rightward > 0.58 ? 0.13 : 0.2})`;
        for (let row = 0; row < rowCount; row += 1) {
          fc.fillText(bits[(index + row + turn) % bits.length], column.x, row * CELL);
        }
      }

      for (let index = 0; index < columns.length; index += 1) {
        const column = columns[index];
        /* The right third belongs to the observed-token stream, so the field
           thins out there rather than competing with the words. */
        const rightward = column.x / width;
        if (rightward > 0.58 && index % 2 === 1) continue;

        const bits = bitsFor(sources[index % sources.length] + index);
        const head = ((elapsed / 1000) * column.speed + column.offset) % cycle;
        const density = rightward > 0.58 ? 0.5 : 1;

        for (let step = 0; step < TAIL; step += 1) {
          const y = head - step * CELL;
          if (y < -CELL || y > height) continue;
          const bit = bits[(index + step + Math.floor(head / CELL)) % bits.length];
          const strength = 1 - step / TAIL;
          if (step === 0) {
            fc.fillStyle = `rgba(224,253,255,${0.95 * density})`;
          } else if (step < 4) {
            fc.fillStyle = `rgba(165,243,252,${(0.8 - step * 0.13) * density})`;
          } else {
            /* Cool blue on the left warming toward violet on the right — the
               same two-tone split the platform uses to separate classical
               evidence from quantum verdicts. The floor keeps a long trail
               legible instead of letting it fade into the resting matrix. */
            fc.fillStyle = `rgba(${Math.round(56 + rightward * 111)},${Math.round(189 - rightward * 50)},${Math.round(248 - rightward * 8)},${(0.2 + 0.5 * strength) * density})`;
          }
          fc.fillText(bit, column.x, y);
        }
      }

      /* ── observed-token stream, right side ──────────────────────────── */
      if (liveTokens.length) {
        fc.font = '700 12px ui-monospace, SFMono-Regular, Menlo, monospace';
        const left = width * 0.56;
        for (let index = 0; index < lanes.length; index += 1) {
          const lane = lanes[index];
          lane.y += lane.speed / 60;
          if (lane.y > height + 20) {
            lane.y = -20;
            lane.cursor = (lane.cursor + lanes.length) % Math.max(1, liveTokens.length);
          }
          const token = liveTokens[(lane.cursor + index) % liveTokens.length];
          if (!token) continue;
          const x = left + unitHash(token.text, `lane${index}`) * Math.max(40, width * 0.36);
          fc.globalAlpha = 0.62;
          fc.fillStyle = token.color;
          fc.fillText(truncate(token.text, 34), Math.min(x, width - 12), lane.y);
          fc.globalAlpha = 1;
        }
      }
    };

    const paintFingerprint = (cx: number, cy: number, radius: number, elapsed: number) => {
      /* Concentric broken arcs — the scanner reading a surface, drawn rather
         than imported so it inherits the stage tint and costs no asset. */
      ctx.save();
      ctx.lineWidth = 1.7;
      ctx.lineCap = 'round';
      const drift = reduceMotion ? 0 : (elapsed / 4200) % (Math.PI * 2);
      /* The core sits slightly off centre, the way a real ridge pattern does —
         perfectly concentric circles read as a target, not a fingerprint. */
      const coreX = cx - radius * 0.08;
      const coreY = cy - radius * 0.06;
      for (let ring = 0; ring < 11; ring += 1) {
        const r = radius * (0.1 + ring * 0.082);
        const gap = 0.42 + (ring % 3) * 0.26;
        const rotation = drift * (ring % 2 === 0 ? 1 : -1) + ring * 0.62;
        ctx.strokeStyle = `rgba(${ring % 4 === 0 ? '150,246,255' : '34,211,238'},${0.72 - ring * 0.042})`;
        ctx.beginPath();
        ctx.arc(coreX, coreY, r, rotation + gap, rotation + Math.PI * 2 - gap);
        ctx.stroke();
      }
      ctx.restore();
    };

    const paint = (elapsed: number) => {
      const { progress: liveProgress, focus: liveFocus, detections: liveDetections } = live.current;

      paintField(elapsed);

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);

      /* ── ground + grid ────────────────────────────────────────────── */
      ctx.fillStyle = '#04060e';
      ctx.fillRect(0, 0, width, height);
      ctx.strokeStyle = 'rgba(56,189,248,0.055)';
      ctx.lineWidth = 1;
      for (let x = 0; x <= width; x += 54) {
        ctx.beginPath();
        ctx.moveTo(x + 0.5, 0);
        ctx.lineTo(x + 0.5, height);
        ctx.stroke();
      }
      for (let y = 0; y <= height; y += 54) {
        ctx.beginPath();
        ctx.moveTo(0, y + 0.5);
        ctx.lineTo(width, y + 0.5);
        ctx.stroke();
      }

      /* ── the field ────────────────────────────────────────────────── */
      ctx.drawImage(field, 0, 0, field.width, field.height, 0, 0, width, height);

      /* ── completed region + sweep line, both at REAL progress ─────── */
      const sweepX = Math.max(0, Math.min(width, (liveProgress / 100) * width));
      ctx.fillStyle = 'rgba(34,211,238,0.045)';
      ctx.fillRect(0, 0, sweepX, height);
      if (liveProgress > 0 && liveProgress < 100) {
        const glow = ctx.createLinearGradient(sweepX - 46, 0, sweepX + 6, 0);
        glow.addColorStop(0, 'rgba(34,211,238,0)');
        glow.addColorStop(1, 'rgba(34,211,238,0.20)');
        ctx.fillStyle = glow;
        ctx.fillRect(sweepX - 46, 0, 46, height);
        ctx.strokeStyle = 'rgba(140,245,255,0.85)';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(sweepX + 0.5, 0);
        ctx.lineTo(sweepX + 0.5, height);
        ctx.stroke();
      }

      /* ── horizontal interrogation beam ────────────────────────────── */
      const beamY = height * 0.46;
      const beam = ctx.createLinearGradient(0, 0, width, 0);
      beam.addColorStop(0, 'rgba(56,189,248,0)');
      beam.addColorStop(0.22, 'rgba(56,189,248,0.55)');
      beam.addColorStop(0.5, 'rgba(226,252,255,0.85)');
      beam.addColorStop(0.78, 'rgba(167,139,250,0.55)');
      beam.addColorStop(1, 'rgba(167,139,250,0)');
      ctx.save();
      ctx.globalCompositeOperation = 'lighter';
      for (const [thickness, alpha] of [[26, 0.10], [10, 0.20], [2.2, 0.9]] as const) {
        ctx.globalAlpha = alpha;
        ctx.fillStyle = beam;
        ctx.fillRect(0, beamY - thickness / 2, width, thickness);
      }
      ctx.restore();

      /* ── lens target follows the real artefact under analysis ─────── */
      const key = liveFocus ?? engineLabel ?? '';
      if (key !== focusKey) {
        focusKey = key;
        lens.targetX = width * (0.22 + unitHash(key, 'lx') * 0.5);
        lens.targetY = height * (0.26 + unitHash(key, 'ly') * 0.36);
      }
      const ease = reduceMotion ? 1 : 0.045;
      lens.x += (lens.targetX - lens.x) * ease;
      lens.y += (lens.targetY - lens.y) * ease;

      /* ── detection flashes, from real findings ────────────────────── */
      for (const detection of liveDetections) {
        if (seenDetections.has(detection.id)) continue;
        seenDetections.add(detection.id);
        flashUntil = elapsed + 900;
        flashColor = detection.color;
        ripples.push({ x: lens.x, y: lens.y, start: elapsed, color: detection.color });
      }
      if (seenDetections.size > 400) seenDetections = new Set(liveDetections.map((entry) => entry.id));

      for (let index = ripples.length - 1; index >= 0; index -= 1) {
        const ripple = ripples[index];
        const age = (elapsed - ripple.start) / 1100;
        if (age > 1) {
          ripples.splice(index, 1);
          continue;
        }
        /* A ripple from "the future" has nothing to draw yet. Painted anyway, a
           negative age gave `arc()` a negative radius, which THROWS — every
           frame, aborting the rest of the frame (the lens never painted). */
        if (age < 0) continue;
        ctx.strokeStyle = ripple.color;
        ctx.globalAlpha = (1 - age) * 0.5;
        ctx.lineWidth = 2 - age;
        ctx.beginPath();
        ctx.arc(ripple.x, ripple.y, lens.radius + age * lens.radius * 1.9, 0, Math.PI * 2);
        ctx.stroke();
        ctx.globalAlpha = 1;
      }

      /* ── the lens ─────────────────────────────────────────────────── */
      const flashing = elapsed < flashUntil;
      const rim = flashing ? flashColor : CYAN;

      ctx.save();
      ctx.beginPath();
      ctx.arc(lens.x, lens.y, lens.radius, 0, Math.PI * 2);
      ctx.clip();

      // Optical magnification: the same field, blitted at 2.3x about the lens.
      const zoom = 2.3;
      const sw = (lens.radius * 2) / zoom;
      ctx.drawImage(
        field,
        (lens.x - sw / 2) * dpr,
        (lens.y - sw / 2) * dpr,
        sw * dpr,
        sw * dpr,
        lens.x - lens.radius,
        lens.y - lens.radius,
        lens.radius * 2,
        lens.radius * 2,
      );

      const glass = ctx.createRadialGradient(
        lens.x - lens.radius * 0.35, lens.y - lens.radius * 0.4, lens.radius * 0.1,
        lens.x, lens.y, lens.radius,
      );
      glass.addColorStop(0, 'rgba(226,252,255,0.16)');
      glass.addColorStop(0.55, 'rgba(34,211,238,0.05)');
      glass.addColorStop(1, 'rgba(4,6,14,0.55)');
      ctx.fillStyle = glass;
      ctx.fillRect(lens.x - lens.radius, lens.y - lens.radius, lens.radius * 2, lens.radius * 2);

      paintFingerprint(lens.x, lens.y, lens.radius, elapsed);

      // The real artefact under the glass, named.
      if (liveFocus) {
        ctx.font = '700 10px ui-monospace, SFMono-Regular, Menlo, monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = 'rgba(4,6,14,0.72)';
        const label = truncate(basename(liveFocus), 22);
        const textWidth = ctx.measureText(label).width;
        ctx.fillRect(lens.x - textWidth / 2 - 6, lens.y + lens.radius * 0.46, textWidth + 12, 16);
        ctx.fillStyle = flashing ? flashColor : '#a5f3fc';
        ctx.fillText(label, lens.x, lens.y + lens.radius * 0.46 + 8);
        ctx.textAlign = 'start';
        ctx.textBaseline = 'top';
      }
      ctx.restore();

      // Rim: brushed outer ring, luminous inner ring.
      const metal = ctx.createLinearGradient(
        lens.x - lens.radius, lens.y - lens.radius,
        lens.x + lens.radius, lens.y + lens.radius,
      );
      metal.addColorStop(0, 'rgba(203,213,225,0.85)');
      metal.addColorStop(0.4, 'rgba(71,85,105,0.75)');
      metal.addColorStop(0.62, 'rgba(226,232,240,0.9)');
      metal.addColorStop(1, 'rgba(51,65,85,0.8)');
      ctx.lineWidth = 7;
      ctx.strokeStyle = metal;
      ctx.beginPath();
      ctx.arc(lens.x, lens.y, lens.radius + 3, 0, Math.PI * 2);
      ctx.stroke();

      ctx.save();
      ctx.shadowColor = rim;
      ctx.shadowBlur = flashing ? 26 : 14;
      ctx.lineWidth = 2;
      ctx.strokeStyle = rim;
      ctx.beginPath();
      ctx.arc(lens.x, lens.y, lens.radius, 0, Math.PI * 2);
      ctx.stroke();
      ctx.restore();

      // Handle, angled away from the stage centre so it never covers the lens.
      const handleAngle = lens.x > width / 2 ? Math.PI * 0.75 : Math.PI * 0.25;
      const hx = lens.x + Math.cos(handleAngle) * (lens.radius + 6);
      const hy = lens.y + Math.sin(handleAngle) * (lens.radius + 6);
      ctx.save();
      ctx.lineCap = 'round';
      ctx.lineWidth = 11;
      ctx.strokeStyle = metal;
      ctx.beginPath();
      ctx.moveTo(hx, hy);
      ctx.lineTo(hx + Math.cos(handleAngle) * lens.radius * 0.85, hy + Math.sin(handleAngle) * lens.radius * 0.85);
      ctx.stroke();
      ctx.restore();

      /* ── vignette ─────────────────────────────────────────────────── */
      const vignette = ctx.createRadialGradient(
        width / 2, height / 2, Math.min(width, height) * 0.42,
        width / 2, height / 2, Math.max(width, height) * 0.78,
      );
      vignette.addColorStop(0, 'rgba(4,6,14,0)');
      vignette.addColorStop(1, 'rgba(4,6,14,0.62)');
      ctx.fillStyle = vignette;
      ctx.fillRect(0, 0, width, height);
    };

    /* ── loop ──────────────────────────────────────────────────────── */
    if (reduceMotion) {
      paint(0);
      return;
    }

    let frame = 0;
    /* Two INDEPENDENT gates, deliberately. Folding them into one boolean means
       whichever turns false last can never be undone by the other, and the
       stage stays black after the tab comes back. */
    let inView = true;
    let pageVisible = typeof document === 'undefined' ? true : !document.hidden;
    const start = performance.now();

    /* ONE monotonic clock. `start` and the visibility repaint read
       `performance.now()`, while rAF hands the loop the time its FRAME began —
       which can precede `start`, and by seconds when the browser throttles a
       background or headless tab. Elapsed time therefore ran backwards, ripples
       were stamped in the future, and their radius went negative. */
    let lastElapsed = 0;
    const paintAt = (elapsed: number) => {
      lastElapsed = Math.max(lastElapsed, elapsed);
      paint(lastElapsed);
    };

    const tick = (now: number) => {
      if (inView && pageVisible && (live.current.running || ripples.length > 0)) paintAt(now - start);
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);

    // A stage nobody is looking at should not cost a frame budget.
    const observer = new IntersectionObserver(
      (entries) => {
        inView = entries[0]?.isIntersecting ?? true;
      },
      { threshold: 0.02 },
    );
    observer.observe(host);

    const onVisibility = () => {
      pageVisible = !document.hidden;
      if (pageVisible) paintAt(performance.now() - start);
    };
    document.addEventListener('visibilitychange', onVisibility);

    // One frame immediately, so a paused or finished scan is never a black box.
    paintAt(0);

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      document.removeEventListener('visibilitychange', onVisibility);
    };
    // `engineLabel` participates only through the ref; size and motion mode own the loop.
  }, [size.width, size.height, reduceMotion, engineLabel]);

  /* Under reduced motion the loop does not run, so a real progress or focus
     change must still repaint. Bumping a key remounts the effect above.
     Progress is coarsened to 5% steps: a remount per percent would rebuild the
     canvas a hundred times over one scan for no visible gain. */
  const staticKey = reduceMotion ? `${Math.round(progress / 5)}:${focus ?? ''}` : 'live';

  /* ── detection markers ─────────────────────────────────────────────── */
  const markers = React.useMemo(
    () =>
      detections.slice(-10).map((detection) => ({
        detection,
        left: `${Math.max(3, Math.min(96, detection.atProgress))}%`,
        top: `${18 + unitHash(detection.id, 'y') * 58}%`,
      })),
    [detections],
  );

  return (
    <div
      ref={hostRef}
      key={staticKey}
      className={className}
      style={{ position: 'relative', overflow: 'hidden' }}
    >
      <canvas
        ref={canvasRef}
        aria-hidden
        style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', display: 'block' }}
      />

      {/* ── detection markers: real findings, placed at the progress point
             they were discovered at ─────────────────────────────────────── */}
      {markers.map(({ detection, left, top }) => (
        <button
          key={detection.id}
          type="button"
          onClick={() => onSelectDetection?.(detection.id)}
          onMouseEnter={() => setHovered(detection)}
          onMouseLeave={() => setHovered((current) => (current?.id === detection.id ? null : current))}
          onFocus={() => setHovered(detection)}
          onBlur={() => setHovered((current) => (current?.id === detection.id ? null : current))}
          className="group absolute grid h-5 w-5 -translate-x-1/2 -translate-y-1/2 place-items-center rounded-full transition-transform hover:scale-125 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300"
          style={{ left, top, backgroundColor: `${detection.color}22`, border: `1px solid ${detection.color}` }}
          title={`${detection.title} — open finding`}
        >
          <span className="sr-only">{`${detection.severity} finding: ${detection.title}`}</span>
          <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: detection.color }} />
          <span
            aria-hidden
            className="absolute inset-0 animate-ping rounded-full opacity-40 motion-reduce:animate-none"
            style={{ backgroundColor: detection.color }}
          />
        </button>
      ))}

      {/* ── hover readout ──────────────────────────────────────────────── */}
      {hovered && (
        <div
          role="status"
          className="pointer-events-none absolute bottom-3 left-1/2 z-10 max-w-[min(30rem,88%)] -translate-x-1/2 rounded-lg border bg-[#04060e]/95 px-3 py-2 backdrop-blur"
          style={{ borderColor: `${hovered.color}55` }}
        >
          <p className="flex items-center gap-2 text-[12px] font-bold text-white">
            <span aria-hidden className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: hovered.color }} />
            <span className="truncate">{hovered.title}</span>
          </p>
          <p className="mt-0.5 truncate font-mono text-[10.5px] text-slate-400">{hovered.detail}</p>
        </div>
      )}

      {/* ── caption ────────────────────────────────────────────────────── */}
      <div className="pointer-events-none absolute inset-x-0 bottom-0 flex flex-col items-center gap-1 pb-5">
        <p className="font-mono text-[13px] font-black uppercase tracking-[0.42em] text-cyan-200/90 drop-shadow-[0_0_18px_rgba(34,211,238,0.55)]">
          {caption}
        </p>
        {/* Only while work is in flight: a settled scan naming the last file it
            happened to touch reads as though it were still reading it. */}
        {running && (engineLabel || focus) && (
          <p className="max-w-[88%] truncate font-mono text-[10.5px] text-slate-400">
            {engineLabel ? `${engineLabel}` : ''}
            {engineLabel && focus ? ' · ' : ''}
            {focus ?? ''}
          </p>
        )}
      </div>
    </div>
  );
}
