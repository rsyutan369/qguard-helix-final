import { useCallback, useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { PATTERN_DOTS, PATTERN_GRID, extendPattern } from "@/lib/pattern";

// A 4 × 4 pattern pad. Pointer events cover mouse, pen and touch alike;
// `touch-action: none` keeps the page from scrolling while a pattern is drawn.
// The pad only reports dots — it never decides whether a pattern is right.

export type PatternPadState = "idle" | "error" | "success";

/** Share of a cell, around each dot, that counts as touching it. */
const HIT_RADIUS = 0.34;

function dotCenter(dot: number, size: number): { x: number; y: number } {
  const cell = size / PATTERN_GRID;
  return { x: ((dot % PATTERN_GRID) + 0.5) * cell, y: (Math.floor(dot / PATTERN_GRID) + 0.5) * cell };
}

/** The dot under a point, if any (within `HIT_RADIUS` of its center). */
export function dotAt(x: number, y: number, size: number): number | null {
  const cell = size / PATTERN_GRID;
  const col = Math.floor(x / cell);
  const row = Math.floor(y / cell);
  if (col < 0 || row < 0 || col >= PATTERN_GRID || row >= PATTERN_GRID) return null;
  const dot = row * PATTERN_GRID + col;
  const center = dotCenter(dot, size);
  return Math.hypot(x - center.x, y - center.y) <= cell * HIT_RADIUS ? dot : null;
}

export function PatternPad({
  onComplete,
  disabled = false,
  state = "idle",
  hideTrail = false,
  label = "Pattern pad: connect at least 6 dots",
}: {
  onComplete: (dots: number[]) => void;
  disabled?: boolean;
  state?: PatternPadState;
  /** Draw without showing the lines or the dots touched (onlookers). */
  hideTrail?: boolean;
  label?: string;
}) {
  const padRef = useRef<HTMLDivElement | null>(null);
  const [size, setSize] = useState(280);
  const [dots, setDots] = useState<number[]>([]);
  const [pointer, setPointer] = useState<{ x: number; y: number } | null>(null);
  const drawing = useRef(false);
  const dotsRef = useRef<number[]>([]);

  useEffect(() => {
    const pad = padRef.current;
    if (!pad) return;
    const measure = () => setSize(pad.getBoundingClientRect().width || 280);
    measure();
    const observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(measure);
    observer?.observe(pad);
    return () => observer?.disconnect();
  }, []);

  // A finished attempt stays on screen briefly in its result colour, then clears.
  useEffect(() => {
    if (state === "idle") return;
    const timer = window.setTimeout(() => {
      dotsRef.current = [];
      setDots([]);
    }, state === "error" ? 900 : 600);
    return () => window.clearTimeout(timer);
  }, [state]);

  const locate = (event: ReactPointerEvent<HTMLDivElement>) => {
    const rect = event.currentTarget.getBoundingClientRect();
    return { x: event.clientX - rect.left, y: event.clientY - rect.top };
  };

  const reach = useCallback(
    (point: { x: number; y: number }) => {
      const dot = dotAt(point.x, point.y, size);
      if (dot === null) return;
      const next = extendPattern(dotsRef.current, dot);
      if (next !== dotsRef.current) {
        dotsRef.current = next;
        setDots(next);
      }
    },
    [size],
  );

  const start = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (disabled) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture?.(event.pointerId);
    drawing.current = true;
    dotsRef.current = [];
    setDots([]);
    const point = locate(event);
    setPointer(point);
    reach(point);
  };

  const move = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!drawing.current || disabled) return;
    const point = locate(event);
    setPointer(point);
    reach(point);
  };

  const finish = () => {
    if (!drawing.current) return;
    drawing.current = false;
    setPointer(null);
    const drawn = dotsRef.current;
    if (drawn.length > 0) onComplete(drawn);
  };

  const tone = state === "error" ? "#f43f5e" : state === "success" ? "#10b981" : "#0891b2";
  // A hidden trail stays hidden after the attempt too; the border carries the result.
  const showTrail = !hideTrail;
  const points = dots.map((dot) => dotCenter(dot, size));
  const last = points[points.length - 1];
  const border = state === "error" ? "border-rose-400" : state === "success" ? "border-emerald-400" : "border-line";

  return (
    <div
      ref={padRef}
      role="application"
      aria-label={label}
      aria-disabled={disabled}
      onPointerDown={start}
      onPointerMove={move}
      onPointerUp={finish}
      onPointerCancel={finish}
      onLostPointerCapture={finish}
      className={`relative mx-auto aspect-square w-full max-w-[18rem] select-none rounded-2xl border-2 bg-canvas transition-colors ${border} ${disabled ? "opacity-60" : "cursor-pointer"}`}
      style={{ touchAction: "none" }}
    >
      <svg className="pointer-events-none absolute inset-0 h-full w-full" viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        {showTrail && points.length > 1 && (
          <polyline points={points.map((p) => `${p.x},${p.y}`).join(" ")} fill="none" stroke={tone} strokeWidth={5} strokeLinecap="round" strokeLinejoin="round" opacity={0.75} />
        )}
        {showTrail && last && pointer && drawing.current && (
          <line x1={last.x} y1={last.y} x2={pointer.x} y2={pointer.y} stroke={tone} strokeWidth={4} strokeLinecap="round" opacity={0.45} />
        )}
        {Array.from({ length: PATTERN_DOTS }, (_, dot) => {
          const center = dotCenter(dot, size);
          const active = showTrail && dots.includes(dot);
          return (
            <g key={dot}>
              {active && <circle cx={center.x} cy={center.y} r={size / PATTERN_GRID / 4.2} fill={tone} opacity={0.18} />}
              <circle cx={center.x} cy={center.y} r={active ? 8 : 6} fill={active ? tone : "currentColor"} className={active ? "" : "text-ink-400"} />
            </g>
          );
        })}
      </svg>
    </div>
  );
}
