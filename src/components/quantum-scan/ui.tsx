/**
 * Public Quantum Exposure Assessment™ — design atoms.
 *
 * A self-contained dark enterprise system (quantum blue / violet on deep navy,
 * glassmorphic panels, animated grid field) built for this surface. Kept local
 * to /public-scan because the platform's other public pages run the light
 * marketing theme and must not inherit these tokens.
 */
import React from 'react';
import { createPortal } from 'react-dom';
import { AnimatePresence, motion, useInView, useReducedMotion } from 'motion/react';
import { Lock, X, type LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useQveInk, useQvePalette } from '@/app/public-scan/_qve/theme';

/* ------------------------------------------------------------------ tokens - */

export const ACCENT = {
  cyan: '#22d3ee',
  blue: '#38bdf8',
  violet: '#a78bfa',
  emerald: '#34d399',
  amber: '#fbbf24',
  rose: '#fb7185',
  slate: '#94a3b8',
} as const;

/**
 * Maps a 0-100 score onto the platform's risk ramp.
 *
 * `null` means the dimension was never measured and is painted slate — NOT the
 * rose that a 0 would get. An unmeasured control rendered in the failure colour
 * is a fabricated verdict, and on this ramp the two are only one falsy value
 * apart, so the null case is handled here rather than at each of the ~20 call
 * sites.
 */
export function scoreColor(score: number | null | undefined): string {
  if (score === null || score === undefined || Number.isNaN(score)) return ACCENT.slate;
  if (score >= 85) return ACCENT.emerald;
  if (score >= 70) return ACCENT.cyan;
  if (score >= 50) return ACCENT.amber;
  return ACCENT.rose;
}

/* ------------------------------------------------------------- background -- */

/**
 * Layered page field: radial cyan/violet auroras over a fine grid, plus a slow
 * scanline sweep. Pure CSS + one rAF-free motion loop so it costs nothing on
 * low-end devices and disappears entirely under prefers-reduced-motion.
 */
export function QuantumField({ scoped = false }: {
  /**
   * `scoped` pins the field to the nearest positioned ancestor instead of the
   * viewport. The authenticated dashboard shell paints its own opaque
   * background inside a `relative` <main>, so a viewport-fixed field at -z-10
   * would render *behind* that background and never be seen. Public pages own
   * the whole viewport and keep the default.
   */
  scoped?: boolean;
} = {}) {
  const reduce = useReducedMotion();
  return (
    <div
      className={cn(
        'pointer-events-none overflow-hidden bg-[#04060e]',
        scoped ? 'absolute inset-0 z-0 rounded-2xl' : 'fixed inset-0 -z-10',
      )}
      aria-hidden
    >
      <div
        className="absolute inset-0 opacity-[0.35]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(56,189,248,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,0.06) 1px, transparent 1px)',
          backgroundSize: '54px 54px',
          maskImage: 'radial-gradient(ellipse 90% 60% at 50% 0%, #000 40%, transparent 100%)',
          WebkitMaskImage: 'radial-gradient(ellipse 90% 60% at 50% 0%, #000 40%, transparent 100%)',
        }}
      />
      <div
        className="absolute -top-[22rem] left-1/2 h-[46rem] w-[76rem] -translate-x-1/2 rounded-full blur-[130px]"
        style={{ background: 'radial-gradient(circle, rgba(34,211,238,0.16), transparent 65%)' }}
      />
      <div
        className="absolute -right-40 top-[38rem] h-[34rem] w-[34rem] rounded-full blur-[130px]"
        style={{ background: 'radial-gradient(circle, rgba(167,139,250,0.14), transparent 68%)' }}
      />
      <div
        className="absolute -left-40 top-[86rem] h-[32rem] w-[32rem] rounded-full blur-[130px]"
        style={{ background: 'radial-gradient(circle, rgba(56,189,248,0.10), transparent 68%)' }}
      />
      {!reduce && (
        <motion.div
          className="absolute inset-x-0 h-40"
          style={{
            background: 'linear-gradient(180deg, transparent, rgba(34,211,238,0.055), transparent)',
          }}
          initial={{ top: '-10%' }}
          animate={{ top: ['-10%', '110%'] }}
          transition={{ duration: 14, repeat: Infinity, ease: 'linear' }}
        />
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ reveal - */

export function Reveal({
  children,
  delay = 0,
  className,
  y = 18,
}: {
  children: React.ReactNode;
  delay?: number;
  className?: string;
  y?: number;
  /** React 19 types require `key` to be declared when spread onto a custom component. */
  key?: React.Key;
}) {
  const reduce = useReducedMotion();
  return (
    <motion.div
      className={className}
      initial={reduce ? false : { opacity: 0, y }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-70px' }}
      transition={{ duration: 0.55, delay, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  );
}

/* ------------------------------------------------------------------ count --- */

export function CountUp({
  value,
  decimals = 0,
  suffix = '',
  prefix = '',
  duration = 1400,
  className,
  nullLabel = '—',
}: {
  /**
   * `null` renders `nullLabel` instead of a number. Animating up to 0 for an
   * unmeasured dimension is the most convincing possible way to present a
   * fabricated value: the count-up motion itself implies a measurement.
   */
  value: number | null;
  decimals?: number;
  suffix?: string;
  prefix?: string;
  duration?: number;
  className?: string;
  nullLabel?: string;
}) {
  const ref = React.useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, margin: '-40px' });
  const reduce = useReducedMotion();
  const [display, setDisplay] = React.useState(0);

  React.useEffect(() => {
    if (!inView || value === null) return;
    if (reduce) {
      setDisplay(value);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      setDisplay(value * (1 - Math.pow(1 - t, 3)));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, value, duration, reduce]);

  if (value === null) {
    return (
      <span ref={ref} className={className}>
        {nullLabel}
      </span>
    );
  }

  return (
    <span ref={ref} className={className}>
      {prefix}
      {decimals > 0 ? display.toFixed(decimals) : Math.round(display).toLocaleString('en-US')}
      {suffix}
    </span>
  );
}

/* ------------------------------------------------------------------ panel --- */

export const Panel = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & { glow?: boolean; inset?: boolean }
>(function Panel({ className, glow = false, inset = false, children, ...rest }, ref) {
  return (
    <div
      ref={ref}
      className={cn(
        /* NOTE for the light theme: this fill is `bg-[#080d1a]/80`, and the
           dashboard's light-theme compatibility layer (index.css, group 1)
           matches dark hex fills as a class SUBSTRING precisely so an opacity
           modifier like this one is still covered. Keep new fills to a hex the
           layer lists — tools/dashboard-contrast-check.ts enforces it. */
        // min-w-0 so a panel never forces its grid track wider than the viewport.
        'qg-scan-panel relative min-w-0 rounded-2xl border border-white/[0.07] bg-[#080d1a]/80 backdrop-blur-xl',
        'shadow-[0_1px_0_0_rgba(255,255,255,0.04)_inset,0_24px_60px_-30px_rgba(0,0,0,0.9)]',
        glow && 'border-cyan-400/20 shadow-[0_0_50px_-20px_rgba(34,211,238,0.4)]',
        inset && 'bg-white/[0.02]',
        className,
      )}
      {...rest}
    >
      {children}
    </div>
  );
});

export function SectionLabel({
  children,
  accent = ACCENT.cyan,
  className,
}: {
  children: React.ReactNode;
  accent?: string;
  className?: string;
}) {
  const ink = useQveInk();
  return (
    <div className={cn('flex items-center gap-2.5', className)}>
      <span className="h-3.5 w-[3px] rounded-full" style={{ backgroundColor: ink(accent) }} />
      <h2 className="font-mono text-[11px] font-bold uppercase tracking-[0.22em] text-slate-300">{children}</h2>
    </div>
  );
}

/* ------------------------------------------------------------------- ring --- */

/** Progress ring that draws once in view. Used for every KPI in the summary. */
export function Ring({
  value,
  size = 62,
  stroke = 5,
  color,
  track,
  children,
  className,
}: {
  value: number;
  size?: number;
  stroke?: number;
  color?: string;
  track?: string;
  children?: React.ReactNode;
  className?: string;
}) {
  const palette = useQvePalette();
  const ink = useQveInk();
  const ref = React.useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: '-30px' });
  const clamped = Math.max(0, Math.min(100, value));
  const stroked = ink(color ?? scoreColor(clamped));
  const r = (size - stroke) / 2;
  const circumference = 2 * Math.PI * r;

  return (
    <div
      ref={ref}
      className={cn('relative grid shrink-0 place-items-center', className)}
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} className="-rotate-90" aria-hidden>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={track ?? (palette.theme === 'light' ? palette.track : 'rgba(255,255,255,0.08)')} strokeWidth={stroke} />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={stroked}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: inView ? circumference * (1 - clamped / 100) : circumference }}
          transition={{ duration: 1.3, ease: [0.22, 1, 0.36, 1] }}
          style={{ filter: `drop-shadow(0 0 6px ${stroked}77)` }}
        />
      </svg>
      {children && <div className="absolute inset-0 grid place-items-center text-center">{children}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ gauge --- */

/**
 * Tween a number from `from` to `to` once the element scrolls into view.
 *
 * Used for the gauge pointer instead of a Framer `rotate` transform: rotating an
 * SVG `<g>` through CSS depends on `transform-box`/`transform-origin` resolving
 * against the viewBox, which is exactly the ambiguity that put the pointer below
 * the hub. Driving the angle as a plain number lets the pointer use SVG's own
 * `rotate(angle cx cy)`, which pivots about an explicit point with no CSS
 * involved and therefore cannot drift.
 */
function useTween(
  to: number,
  { from = 0, duration = 1600, enabled = true }: { from?: number; duration?: number; enabled?: boolean } = {},
): { ref: React.RefObject<HTMLDivElement | null>; value: number; inView: boolean } {
  const ref = React.useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: '-40px' });
  const reduce = useReducedMotion();
  const [value, setValue] = React.useState(from);

  React.useEffect(() => {
    if (!enabled || !inView) return;
    if (reduce) {
      setValue(to);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setValue(from + (to - from) * eased);
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, to, from, duration, reduce, enabled]);

  return { ref, value, inView };
}

/** Fixed risk ramp — the needle reads the same across every scan. */
const GAUGE_BANDS = [
  { from: 0, to: 25, color: '#f43f5e', label: 'Weak' },
  { from: 25, to: 45, color: '#fb923c', label: 'Fair' },
  { from: 45, to: 65, color: '#fbbf24', label: 'Good' },
  { from: 65, to: 82, color: '#a3e635', label: 'Strong' },
  { from: 82, to: 100, color: '#22d3ee', label: 'Excellent' },
] as const;

/**
 * Half-circle gauge with a tapered pointer.
 *
 * GEOMETRY NOTES — two separate causes of the old overlap, both fixed here:
 *
 * 1. LAYOUT. The hub sits on the arc's *diameter*, so the arc occupies the space
 *    above it and everything below is free. The value is rendered in that
 *    reserved band beneath the hub, and the pointer is capped well short of the
 *    arc, so the sweep and the number cannot overlap at any value. The previous
 *    version pulled the readout up into the sweep with a negative margin.
 *
 * 2. PIVOT. The pointer rotates via SVG's own `rotate(angle cx cy)` about an
 *    explicit point, driven by a plain animated number. A CSS `rotate` on an
 *    SVG `<g>` depends on the browser resolving `transform-box`/
 *    `transform-origin` against the viewBox; when that did not resolve, the
 *    pointer pivoted about the wrong point and landed below the hub, on top of
 *    the band label. An explicit pivot cannot drift.
 */
export function Gauge({
  value,
  size = 300,
  band,
  bandColor,
  bands = GAUGE_BANDS,
}: {
  /** `null` withholds the reading entirely — see `unmeasured` below. */
  value: number | null;
  size?: number;
  /** Band name shown under the value, e.g. "Strong". */
  band?: string;
  bandColor?: string;
  /** Arc segments, ascending 0→100. Defaults to the generic 5-band ramp;
   * pass the grade table's own bands (GAUGE_ARC_BANDS) when the gauge is
   * grading something, so the colored arc can never disagree with the
   * rating text it displays. */
  bands?: ReadonlyArray<{ from: number; to: number; color: string }>;
}) {
  /**
   * `value === null` means the score was withheld. The reference arc and its
   * scale still render — they are the published grade table and are useful
   * context — but the pointer, the band marker and the numeric readout are
   * suppressed, because a gauge pointing at 0 IS an assertion. This surface used
   * to publish "N/A · Insufficient evidence" in the badge while the gauge beside
   * it swung to 0 and its legend read "Critical" for the same assessment.
   */
  const unmeasured = value === null;
  const clamped = Math.max(0, Math.min(100, value ?? 0));

  // Layout: arc above the hub, numeric scale outside the arc, readout below.
  const cx = size / 2;
  const radius = size * 0.335;
  const stroke = Math.max(11, size * 0.045);
  // The scale sits OUTSIDE the coloured band. Inside, the pointer shaft would
  // pass straight through the "50" label at mid-scale.
  const tickInner = radius + stroke / 2 + 3;
  const tickOuter = radius + stroke / 2 + 8;
  const labelRadius = radius + stroke / 2 + 17;
  const cy = labelRadius + 8; // hub on the diameter; leaves room for the top label
  // Reserved band for the readout. The pointer's lowest point across the whole
  // -180°→0° sweep is cy + 9.62 (the tail corner at ≈-111°, not the arrowhead),
  // so a 20px offset leaves ~10px of clearance at every possible value.
  const readoutTop = cy + 20;
  const height = cy + size * 0.33;

  // SVG rotation is clockwise-positive, so it negates the maths angle.
  // 0 score → -180° (points left), 100 → 0° (points right).
  const targetRotation = 1.8 * clamped - 180;
  const { ref, value: rotation, inView } = useTween(targetRotation, { from: -180, duration: 1700 });

  // Cap the pointer short of the arc so tip and track stay visually distinct.
  const needleLength = radius - stroke - 12;
  const ink = useQveInk();
  const valueColor = ink(unmeasured ? ACCENT.slate : (bandColor ?? scoreColor(clamped)));

  /** Degrees: 180° = 0 score (left), 0° = 100 score (right). */
  const degFor = (score: number) => 180 - (score / 100) * 180;
  const pointAt = (deg: number, r: number) => {
    const rad = (deg * Math.PI) / 180;
    return [cx + r * Math.cos(rad), cy - r * Math.sin(rad)] as const;
  };

  const arcPath = (from: number, to: number) => {
    const [x1, y1] = pointAt(degFor(from), radius);
    const [x2, y2] = pointAt(degFor(to), radius);
    return `M ${x1} ${y1} A ${radius} ${radius} 0 0 1 ${x2} ${y2}`;
  };

  const [markerX, markerY] = pointAt(degFor(clamped), radius);

  /**
   * Tapered pointer drawn along +x and rotated into place: a shaft that narrows
   * into a distinct arrowhead, so it reads as a gauge hand rather than a line.
   */
  const head = 15;
  const pointer = [
    `M ${cx - 9} ${cy - 3.4}`,
    `L ${cx + needleLength - head} ${cy - 2.2}`,
    `L ${cx + needleLength - head} ${cy - 7.5}`,
    `L ${cx + needleLength} ${cy}`,
    `L ${cx + needleLength - head} ${cy + 7.5}`,
    `L ${cx + needleLength - head} ${cy + 2.2}`,
    `L ${cx - 9} ${cy + 3.4}`,
    'Z',
  ].join(' ');

  return (
    <div ref={ref} className="relative select-none" style={{ width: size, height }}>
      <svg width={size} height={height} viewBox={`0 0 ${size} ${height}`} aria-hidden>
        <defs>
          <filter id="gauge-pointer-glow" x="-60%" y="-60%" width="220%" height="220%">
            <feDropShadow dx="0" dy="0" stdDeviation="3.5" floodColor={valueColor} floodOpacity="0.55" />
          </filter>
        </defs>

        {/* Recessed track behind the bands gives the arc physical depth. */}
        <path
          d={arcPath(0, 100)}
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth={stroke + 7}
          strokeLinecap="round"
        />

        {bands.map((segment) => (
          <path
            key={segment.from}
            d={arcPath(segment.from, segment.to)}
            fill="none"
            stroke={segment.color}
            strokeWidth={stroke}
            strokeLinecap="butt"
            opacity={0.92}
          />
        ))}

        {/* Scale ticks, outside the band — a gauge without a scale is
            decoration, not a reading. */}
        {[0, 25, 50, 75, 100].map((tick) => {
          const [x1, y1] = pointAt(degFor(tick), tickInner);
          const [x2, y2] = pointAt(degFor(tick), tickOuter);
          const [lx, ly] = pointAt(degFor(tick), labelRadius);
          return (
            <g key={tick}>
              <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="rgba(226,232,240,0.3)" strokeWidth={1.5} />
              <text
                x={lx}
                y={ly}
                textAnchor="middle"
                dominantBaseline="middle"
                fill="rgba(148,163,184,0.75)"
                style={{ font: '600 9px ui-monospace, monospace' }}
              >
                {tick}
              </text>
            </g>
          );
        })}

        {/* Marker on the band the score actually lands in. */}
        {!unmeasured && (
          <circle
            cx={markerX}
            cy={markerY}
            r={4.5}
            fill="#e2e8f0"
            stroke={valueColor}
            strokeWidth={2.5}
            opacity={inView ? 1 : 0}
            style={{ transition: 'opacity 400ms ease-out 900ms' }}
          />
        )}

        {/* SVG rotate() about an explicit pivot — the hub — so the pointer
            cannot drift regardless of how the browser resolves transform-box.
            Suppressed entirely when there is no score: a pointer resting at the
            left stop is not a neutral position, it is a reading of zero. */}
        {!unmeasured && (
          <g transform={`rotate(${rotation.toFixed(3)} ${cx} ${cy})`}>
            <path d={pointer} fill="#f1f5f9" filter="url(#gauge-pointer-glow)" />
          </g>
        )}

        {/* Hub, drawn after the pointer so the pivot reads as a cap over it. */}
        <circle cx={cx} cy={cy} r={11} fill="#0b1220" stroke="rgba(226,232,240,0.22)" strokeWidth={1.5} />
        <circle cx={cx} cy={cy} r={4.5} fill={valueColor} />
      </svg>

      {/* Readout in the reserved band below the hub — never under the sweep. */}
      <div className="absolute inset-x-0 text-center" style={{ top: readoutTop }}>
        {/* `text-white` as a CLASS, not an inline colour: the dashboard's light
            theme remaps the class to ink, and an inline #ffffff rendered the
            score white-on-parchment. Dark surfaces are unchanged. */}
        <p
          className={cn('font-black leading-none tracking-tighter', !unmeasured && 'text-white')}
          style={{ fontSize: size * 0.155, color: unmeasured ? valueColor : undefined }}
        >
          <CountUp value={unmeasured ? null : clamped} />
          {!unmeasured && <span className="ml-1 align-super text-[0.42em] font-bold text-slate-500">/100</span>}
        </p>
        {band && (
          <p
            className="mt-1.5 font-mono text-[10px] font-bold uppercase tracking-[0.22em]"
            style={{ color: valueColor }}
          >
            {band}
          </p>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ status -- */

/**
 * Seven-state status palette.
 *
 * The three "no verdict" states (Unknown / Not Observable / Not Applicable) all
 * render neutral grey and must never be mistaken for a failure — that visual
 * distinction is the whole reason the model has seven states rather than three.
 * `Not Supported` is red because it IS a failure: the control was expected and
 * is genuinely absent.
 */
const GREEN = { bg: 'rgba(52,211,153,0.12)', text: '#34d399', ring: 'rgba(52,211,153,0.35)' }
const AMBER = { bg: 'rgba(251,191,36,0.12)', text: '#fbbf24', ring: 'rgba(251,191,36,0.35)' }
const ROSE = { bg: 'rgba(251,113,133,0.12)', text: '#fb7185', ring: 'rgba(251,113,133,0.35)' }
const GREY = { bg: 'rgba(148,163,184,0.12)', text: '#94a3b8', ring: 'rgba(148,163,184,0.3)' }
/* Between AMBER and ROSE: a serious failure that is not catastrophic. Measured
   at 4.9:1 on the panel ground, above the 4.5:1 floor for small bold text. */
const ORANGE = { bg: 'rgba(251,146,60,0.12)', text: '#fb923c', ring: 'rgba(251,146,60,0.35)' }
const BLUE = { bg: 'rgba(56,189,248,0.12)', text: '#38bdf8', ring: 'rgba(56,189,248,0.35)' }

const STATUS_STYLES: Record<string, { bg: string; text: string; ring: string }> = {
  // Measured verdicts
  healthy: GREEN,
  pass: GREEN,
  warning: AMBER,
  partial: AMBER,
  /* A serious failure that is not catastrophic. Distinct from both amber
     (warning) and rose (critical) so the pill carries the severity faithfully
     — see reconcileStatus() in public-scan/controls.ts. */
  high: ORANGE,
  critical: ROSE,
  fail: ROSE,
  'not supported': ROSE,
  // No verdict established
  unknown: GREY,
  'not observable': GREY,
  'not applicable': GREY,
  'n/a': GREY,
  // Neutral inventory
  info: BLUE,
};

export function StatusPill({ status, label }: { status: string; label?: string }) {
  const ink = useQveInk();
  const style = STATUS_STYLES[status.toLowerCase()] ?? STATUS_STYLES.unknown;
  return (
    <span
      className="inline-flex items-center rounded-md px-2 py-[3px] text-[11px] font-bold leading-none ring-1"
      style={{ backgroundColor: style.bg, color: ink(style.text), boxShadow: `inset 0 0 0 1px ${style.ring}` }}
    >
      {label ?? status}
    </span>
  );
}

/* --------------------------------------------------------------- locked ----- */

export type LockTier = 'Basic' | 'Pro' | 'Elite';

const TIER_COLOR: Record<LockTier, string> = {
  Basic: ACCENT.cyan,
  Pro: ACCENT.violet,
  Elite: ACCENT.amber,
};

/**
 * Enterprise capability preview: the content renders for real but is blurred
 * and non-interactive, with a tier badge naming the plan that unlocks it. The
 * blur is applied to a wrapper (not the text) so no data is ever readable.
 */
export function LockedPanel({
  tier,
  title,
  description,
  icon: Icon,
  href = '/register',
  children,
  className,
  blur = 5,
}: {
  tier: LockTier;
  title: string;
  description: string;
  icon?: LucideIcon;
  href?: string;
  children: React.ReactNode;
  className?: string;
  blur?: number;
}) {
  const ink = useQveInk();
  const color = ink(TIER_COLOR[tier]);
  return (
    <Panel className={cn('overflow-hidden', className)}>
      <div className="relative">
        <div
          aria-hidden
          className="pointer-events-none select-none opacity-45"
          style={{ filter: `blur(${blur}px)` }}
        >
          {children}
        </div>

        <div className="qg-scan-locked-overlay absolute inset-0 grid place-items-center bg-gradient-to-b from-[#060b16]/50 via-[#060b16]/80 to-[#060b16]/95 px-5 text-center">
          <div className="max-w-xs">
            <span
              className="mx-auto grid h-11 w-11 place-items-center rounded-xl border"
              style={{ borderColor: `${color}44`, backgroundColor: `${color}14`, color }}
            >
              {Icon ? <Icon className="h-5 w-5" /> : <Lock className="h-5 w-5" />}
            </span>
            <div className="mt-3 flex items-center justify-center gap-2">
              <h3 className="text-sm font-bold text-white">{title}</h3>
              <span
                className="rounded-md px-1.5 py-0.5 font-mono text-[9px] font-black uppercase tracking-widest"
                style={{ backgroundColor: `${color}1f`, color }}
              >
                {tier}+
              </span>
            </div>
            <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">{description}</p>
            <a
              href={href}
              className="mt-3 inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-[11px] font-bold no-underline transition-colors"
              style={{ borderColor: `${color}44`, color }}
            >
              <Lock className="h-3 w-3" /> Unlock with {tier}
            </a>
          </div>
        </div>
      </div>
    </Panel>
  );
}

/* ------------------------------------------------------------------ meter --- */

export function Meter({
  value,
  color,
  className,
}: {
  /** `null` renders an empty, dashed track — a 0%-wide bar looks measured. */
  value: number | null;
  color?: string;
  className?: string;
}) {
  const ref = React.useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: '-30px' });

  if (value === null) {
    return (
      <div
        ref={ref}
        className={cn('h-1.5 w-full rounded-full border border-dashed border-white/[0.14]', className)}
        title="Not measured"
      />
    );
  }

  const clamped = Math.max(0, Math.min(100, value));
  return (
    <div ref={ref} className={cn('h-1.5 w-full overflow-hidden rounded-full bg-white/[0.07]', className)}>
      <motion.div
        className="h-full rounded-full"
        style={{ backgroundColor: color ?? scoreColor(clamped) }}
        initial={{ width: 0 }}
        animate={{ width: inView ? `${clamped}%` : 0 }}
        transition={{ duration: 1.2, ease: [0.22, 1, 0.36, 1] }}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ modal --- */

/**
 * Generic overlay modal: dark scrim, Escape + backdrop-click to close, body
 * scroll locked while open. Content scrolls inside a capped-height panel so a
 * tall image (the grading reference) never pushes the close button off screen.
 */
export function Modal({
  open,
  onClose,
  title,
  children,
  maxWidthClassName = 'max-w-3xl',
  surfaceClassName,
}: {
  open: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  maxWidthClassName?: string;
  surfaceClassName?: string;
}) {
  React.useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [open, onClose]);

  // Rendered via a portal straight onto document.body. This page uses
  // whileInView `<Reveal>` wrappers extensively, and once a Framer Motion
  // element finishes animating it leaves a `transform` value on the element
  // (e.g. translateY(0px)) rather than clearing it — and per the CSS spec ANY
  // non-none `transform` on an ancestor creates a containing block, which
  // makes a descendant's `position: fixed` resolve against that ancestor's
  // box instead of the viewport. A modal nested under a Reveal would render
  // pinned to wherever that panel happens to scroll to instead of centered
  // over the whole page. The portal sidesteps the ancestor chain entirely.
  return createPortal(
    <AnimatePresence>
      {open && (
        <motion.div
          className={cn('fixed inset-0 z-[95] flex items-center justify-center p-4 sm:p-8', surfaceClassName)}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.18 }}
          role="dialog"
          aria-modal="true"
          aria-label={title}
        >
          <motion.div
            className="absolute inset-0 bg-[#03050c]/88 backdrop-blur-sm"
            onClick={onClose}
            aria-hidden
          />
          <motion.div
            initial={{ opacity: 0, scale: 0.96, y: 14 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.97, y: 8 }}
            transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
            className={cn(
              'relative flex max-h-[88vh] w-full flex-col overflow-hidden rounded-2xl border border-white/[0.1] bg-[#080d1a] shadow-[0_50px_140px_-25px_rgba(0,0,0,0.9)]',
              maxWidthClassName,
            )}
          >
            {title && (
              <div className="flex shrink-0 items-center justify-between border-b border-white/[0.07] px-5 py-3.5">
                <h3 className="text-[13px] font-bold uppercase tracking-[0.08em] text-white">{title}</h3>
                <button
                  type="button"
                  onClick={onClose}
                  aria-label="Close"
                  className="grid h-8 w-8 shrink-0 place-items-center rounded-lg text-slate-400 transition-colors hover:bg-white/[0.07] hover:text-white"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            )}
            <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  );
}
