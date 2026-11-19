/**
 * Motion + 3D primitives for the QGuard Messaging marketing pages.
 *
 * Rules these obey (qguard-enterprise-ux "Animation discipline"):
 *  - Animation paces the presentation of facts already stated on the page. It
 *    never reports progress, status or telemetry of a real system.
 *  - Every stage that draws a mechanism says so ("Illustration") — nothing in
 *    here is live data.
 *  - `prefers-reduced-motion` is honoured twice: CSS stops keyframes, and the
 *    JS-driven motion (tilt, tickers, count-up) falls back to the final state.
 */
import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import {
  animate,
  motion,
  useInView,
  useMotionValue,
  useReducedMotion,
  useScroll,
  useSpring,
  useTransform,
} from 'motion/react';
import type { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import './messaging-motion.css';

/* --------------------------------------------------------------- hooks ----- */

/** True when the visitor asked the OS for less motion. */
export function useCalm(): boolean {
  return Boolean(useReducedMotion());
}

/**
 * Advances 0..count-1 on an interval while `active`. Under reduced motion it
 * holds step 0 (the viewer drives it with the controls instead).
 */
export function useTicker(count: number, ms: number, active = true): [number, (n: number) => void] {
  const calm = useCalm();
  const [step, setStep] = useState(0);
  useEffect(() => {
    if (!active || calm || count < 2) return;
    const id = window.setInterval(() => setStep((s) => (s + 1) % count), ms);
    return () => window.clearInterval(id);
  }, [active, calm, count, ms]);
  return [step, setStep];
}

/** Pauses work while the stage is scrolled out of view. */
export function useStageVisible<T extends HTMLElement>(): [React.RefObject<T | null>, boolean] {
  const ref = useRef<T | null>(null);
  const visible = useInView(ref, { margin: '120px 0px 120px 0px' });
  return [ref, visible];
}

/* ------------------------------------------------------------ layout ------- */

/**
 * Lays a fixed-size design canvas (baseW × baseH) out at any container width by
 * scaling it. The 3D scenes are authored in absolute pixels; this keeps them
 * crisp and uncropped from a 360 px phone to a wide desktop column.
 */
export function FitBox({
  baseW,
  baseH,
  children,
  className,
  maxScale = 1.25,
}: {
  baseW: number;
  baseH: number;
  children: React.ReactNode;
  className?: string;
  maxScale?: number;
}) {
  const outer = useRef<HTMLDivElement>(null);
  const [scale, setScale] = useState(1);

  useLayoutEffect(() => {
    const el = outer.current;
    if (!el) return;
    const measure = () => setScale(Math.min(maxScale, Math.max(0.3, el.clientWidth / baseW)));
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [baseW, maxScale]);

  return (
    <div ref={outer} className={cn('w-full min-w-0 overflow-hidden', className)} style={{ height: baseH * scale }}>
      <div style={{ width: baseW, height: baseH, transform: `scale(${scale})`, transformOrigin: '0 0' }}>{children}</div>
    </div>
  );
}

/** Pointer-driven 3D tilt. Children should use `transform-style: preserve-3d`. */
export function Tilt3D({
  children,
  className,
  max = 9,
  style,
}: {
  children: React.ReactNode;
  className?: string;
  max?: number;
  style?: React.CSSProperties;
}) {
  const calm = useCalm();
  const rx = useMotionValue(0);
  const ry = useMotionValue(0);
  const srx = useSpring(rx, { stiffness: 110, damping: 16, mass: 0.6 });
  const sry = useSpring(ry, { stiffness: 110, damping: 16, mass: 0.6 });

  const onMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (calm) return;
    const r = e.currentTarget.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width - 0.5;
    const py = (e.clientY - r.top) / r.height - 0.5;
    ry.set(px * 2 * max);
    rx.set(-py * 2 * max);
  };
  const onLeave = () => {
    rx.set(0);
    ry.set(0);
  };

  return (
    <div className={cn('qm-scene', className)} onPointerMove={onMove} onPointerLeave={onLeave} style={style}>
      <motion.div className="qm-3d" style={{ rotateX: srx, rotateY: sry, width: '100%', height: '100%' }}>
        {children}
      </motion.div>
    </div>
  );
}

/** A tilt-on-hover wrapper for ordinary light cards (feature atlas, etc.). */
export function TiltCard({ children, className }: { children: React.ReactNode; className?: string }) {
  const calm = useCalm();
  const rx = useMotionValue(0);
  const ry = useMotionValue(0);
  const srx = useSpring(rx, { stiffness: 160, damping: 18 });
  const sry = useSpring(ry, { stiffness: 160, damping: 18 });
  const glow = useMotionValue('50% 50%');
  const bg = useTransform(glow, (v) => `radial-gradient(260px circle at ${v}, rgba(34,211,238,0.14), transparent 60%)`);

  return (
    <div style={{ perspective: 900 }} className={className}>
      <motion.div
        className="relative h-full"
        style={{ rotateX: srx, rotateY: sry, transformStyle: 'preserve-3d' }}
        onPointerMove={(e) => {
          if (calm) return;
          const r = e.currentTarget.getBoundingClientRect();
          const px = (e.clientX - r.left) / r.width;
          const py = (e.clientY - r.top) / r.height;
          ry.set((px - 0.5) * 7);
          rx.set(-(py - 0.5) * 7);
          glow.set(`${px * 100}% ${py * 100}%`);
        }}
        onPointerLeave={() => {
          rx.set(0);
          ry.set(0);
        }}
      >
        {children}
        {!calm && <motion.span aria-hidden className="pointer-events-none absolute inset-0 rounded-2xl" style={{ background: bg }} />}
      </motion.div>
    </div>
  );
}

/* ------------------------------------------------------------ chrome ------- */

/**
 * The dark frame every illustration sits in. `note` states what the picture is
 * and, where it matters, what it is not.
 */
export function StageFrame({
  title,
  icon: Icon,
  note,
  children,
  className,
  bodyClassName,
  label = 'Illustration',
}: {
  title: string;
  icon?: LucideIcon;
  note?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
  label?: string;
}) {
  return (
    <div className={cn('qm-stage', className)}>
      <div className="qm-stage-head">
        <div className="qm-stage-title">
          {Icon ? <Icon className="h-4 w-4 qm-t-cyan" aria-hidden /> : <span className="qm-live-dot" aria-hidden />}
          {title}
        </div>
        <span className="qm-illus">{label}</span>
      </div>
      <div className={cn('qm-stage-body', bodyClassName)}>{children}</div>
      {note && <div className="qm-stage-foot">{note}</div>}
    </div>
  );
}

export type TagKind = 'ready' | 'optin' | 'android' | 'desktop' | 'setup' | 'planned';

const TAG_LABEL: Record<TagKind, string> = {
  ready: 'In reviewed source',
  optin: 'Opt-in',
  android: 'Android',
  desktop: 'Desktop',
  setup: 'Needs setup',
  planned: 'Planned',
};

/** Availability tag. `children` overrides the default label for the kind. */
export function Tag({ kind, children }: { kind: TagKind; children?: React.ReactNode }) {
  return (
    <span className="qm-tag" data-kind={kind}>
      {children ?? TAG_LABEL[kind]}
    </span>
  );
}

export function Chip({
  tone = 'cyan',
  children,
  className,
  style,
}: {
  tone?: 'cyan' | 'gold' | 'violet' | 'green' | 'rose' | 'amber' | 'mute';
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    <span className={cn('qm-chip', className)} data-tone={tone} style={style}>
      {children}
    </span>
  );
}

/** Thin gradient bar that fills as the page scrolls. */
export function ScrollProgress() {
  const calm = useCalm();
  const { scrollYProgress } = useScroll();
  const scaleX = useSpring(scrollYProgress, { stiffness: 140, damping: 28, mass: 0.4 });
  if (calm) return null;
  return <motion.div aria-hidden className="qm-progress" style={{ scaleX }} />;
}

/** Slow colour wash behind a section. Place as the first child of a `relative` section. */
export function Aurora() {
  return <div aria-hidden className="qm-aurora" />;
}

/** Counts up to `to` once it scrolls into view. */
export function CountUp({
  to,
  suffix = '',
  prefix = '',
  duration = 1.4,
  className,
}: {
  to: number;
  suffix?: string;
  prefix?: string;
  duration?: number;
  className?: string;
}) {
  const calm = useCalm();
  const ref = useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, margin: '-60px' });
  const [value, setValue] = useState(calm ? to : 0);

  useEffect(() => {
    if (calm) {
      setValue(to);
      return;
    }
    if (!inView) return;
    const controls = animate(0, to, { duration, ease: [0.22, 1, 0.36, 1], onUpdate: (v) => setValue(Math.round(v)) });
    return () => controls.stop();
  }, [inView, to, duration, calm]);

  return (
    <span ref={ref} className={className}>
      {prefix}
      {value.toLocaleString('en-US')}
      {suffix}
    </span>
  );
}

/** Infinite horizontal ticker of short items. Duplicated so the loop is seamless. */
export function Marquee({ items }: { items: string[] }) {
  const row = (suffix: string) =>
    items.map((t) => (
      <span
        key={`${t}${suffix}`}
        className="mx-2 inline-flex shrink-0 items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 font-mono text-[11px] font-bold uppercase tracking-wider text-slate-700"
      >
        <span className="h-1.5 w-1.5 rounded-full bg-cyan-500" aria-hidden />
        {t}
      </span>
    ));
  return (
    <div
      className="qm-marquee-wrap relative overflow-hidden py-1"
      style={{ WebkitMaskImage: 'linear-gradient(90deg, transparent, #000 8%, #000 92%, transparent)', maskImage: 'linear-gradient(90deg, transparent, #000 8%, #000 92%, transparent)' }}
    >
      <div className="qm-marquee" aria-hidden={false}>
        <div className="flex">{row('a')}</div>
        <div className="flex" aria-hidden>{row('b')}</div>
      </div>
    </div>
  );
}

/** Fades/slides children in when they enter the viewport; stagger via `index`. */
export function Rise({ children, index = 0, className }: { children: React.ReactNode; index?: number; className?: string }) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 18 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-60px' }}
      transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1], delay: Math.min(index, 8) * 0.05 }}
    >
      {children}
    </motion.div>
  );
}

