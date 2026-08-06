/**
 * Section components for the QGuard Helix Features showcase (/qguard-helix-features).
 *
 * Built on the shared marketing design language (SolutionLayout + the messaging /
 * quantum-readiness atoms) so this page is a sibling of /pqc-solutions,
 * /post-quantum-migration-platform and /quantum-trust-governance-center rather than
 * a one-off. Everything here is presentation only — the copy lives in the page.
 *
 * LIGHT-THEME OVERRIDE NOTE: the page runs inside `.qguard-home--light`, whose
 * override sheet rewrites any class containing text-white / text-gold / bg-gold /
 * border-gold / bg-white\/ / bg-black. Dark panels therefore use arbitrary hex
 * classes (bg-[#070d1a], text-[#e2e8f0]) or explicit slate-* shades, never those.
 */
import React from 'react';
import { motion, useInView, useReducedMotion, useScroll, useTransform } from 'motion/react';
import { Link } from 'react-router-dom';
import { ArrowRight, Check, Quote, Sparkles, type LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Reveal, GlassCard, CountUp } from './_solution-shared';

export const CYAN = '#06b6d4';
export const GOLD = '#d4af37';
export const VIOLET = '#8b5cf6';
export const EMERALD = '#10b981';
export const AMBER = '#f59e0b';
export const BLUE = '#2563eb';
export const ROSE = '#f43f5e';

/* ------------------------------------------------------------------ types -- */

export type ModuleEntry = {
  /** Anchor id + navigator key. */
  id: string;
  index: number;
  chapter: string;
  eyebrow: string;
  title: string;
  /** One-line plain-English description of what the module is. */
  blurb: string;
  /** The business reason it exists — written for an executive, not an engineer. */
  value: string;
  /** What it actually does (drawn from the shipped module). */
  capabilities: string[];
  /** Short benefit phrases shown as pills. */
  benefits: string[];
  /** A concrete "you'd use this when…" scenario. */
  useCase: string;
  image: string;
  icon: LucideIcon;
  accent: string;
  /** Live dashboard route. */
  to: string;
};

/* ------------------------------------------------------------------- hero -- */

/**
 * Cinematic hero: a Higgsfield-generated quantum-migration film framed as a dark
 * keynote stage inside the light page. The video is muted/looped/inline so it can
 * autoplay everywhere, carries a poster for the first paint, and degrades to the
 * poster image when prefers-reduced-motion is set.
 */
export function HeroStage({
  video,
  poster,
  children,
}: {
  video: string;
  poster: string;
  children: React.ReactNode;
}) {
  const ref = React.useRef<HTMLDivElement>(null);
  const reduce = useReducedMotion();
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start start', 'end start'] });
  const y = useTransform(scrollYProgress, [0, 1], ['0%', '18%']);
  const scale = useTransform(scrollYProgress, [0, 1], [1, 1.12]);
  const fade = useTransform(scrollYProgress, [0, 0.85], [1, 0.35]);

  return (
    <section ref={ref} id="top" className="qguard-dark-stage relative isolate overflow-hidden">
      <motion.div
        className="absolute inset-0 -z-10"
        style={reduce ? undefined : { y, scale, opacity: fade }}
      >
        {reduce ? (
          <img src={poster} alt="" aria-hidden className="h-full w-full object-cover" />
        ) : (
          <video
            className="h-full w-full object-cover"
            src={video}
            poster={poster}
            autoPlay
            muted
            loop
            playsInline
            preload="metadata"
            aria-hidden
          />
        )}
        {/* Legibility scrim — dark at the edges so white type always reads. */}
        <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(2,6,23,0.78)_0%,rgba(2,6,23,0.55)_45%,rgba(2,6,23,0.92)_100%)]" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_50%_28%,transparent_0%,rgba(2,6,23,0.55)_78%)]" />
      </motion.div>

      <div className="relative z-10 mx-auto max-w-[96rem] px-4 pb-24 pt-32 sm:px-6 sm:pb-28 sm:pt-40 lg:pb-36 lg:pt-48">
        {children}
      </div>

      {/* Soft hand-off into the white page body. */}
      <div className="pointer-events-none absolute inset-x-0 bottom-0 z-10 h-32 bg-[linear-gradient(180deg,transparent,rgba(255,255,255,0.86)_62%,#fff_100%)]" />
    </section>
  );
}

/** Kicker chip for use on the dark hero (override-proof colours). */
export function HeroKicker({ children }: { children: React.ReactNode }) {
  return (
    <motion.span
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
      className="inline-flex items-center gap-2 rounded-full border border-[#d4af37]/40 bg-[#d4af37]/12 px-3.5 py-1.5 font-mono text-[11px] font-bold uppercase tracking-[0.24em] text-[#f3d98b] backdrop-blur-xl"
    >
      <Sparkles className="h-3.5 w-3.5 text-[#f3d98b]" />
      {children}
    </motion.span>
  );
}

/** Animated KPI tile for the hero stat row. */
export function HeroStat({
  value,
  suffix,
  prefix,
  label,
  detail,
  grouping = true,
  delay = 0,
}: {
  value: number;
  suffix?: string;
  prefix?: string;
  label: string;
  detail: string;
  /** Off for year values, which must not render as "2,035". */
  grouping?: boolean;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay, ease: [0.22, 1, 0.36, 1] }}
      className="rounded-xl border border-[#22d3ee]/18 bg-[#050b16]/55 p-4 backdrop-blur-xl sm:p-5"
    >
      <div className="flex items-baseline gap-0.5">
        <CountUp
          value={value}
          prefix={prefix}
          suffix={suffix}
          grouping={grouping}
          className="text-2xl font-black tracking-tight text-[#f8fafc] sm:text-3xl"
        />
      </div>
      <div className="mt-1.5 text-[13px] font-bold text-[#cbd5e1]">{label}</div>
      <div className="mt-0.5 text-[11px] leading-snug text-[#94a3b8]">{detail}</div>
    </motion.div>
  );
}

/* -------------------------------------------------------------- lifecycle -- */

/**
 * The platform lifecycle rail (Discover → Govern). Each stage draws itself in as
 * the rail scrolls into view, and the connecting line fills with it.
 */
export function LifecycleRail({
  stages,
}: {
  stages: Array<{ label: string; body: string; icon: LucideIcon; color: string }>;
}) {
  const ref = React.useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: '-90px' });

  return (
    <div ref={ref} className="relative">
      {/* Connecting rail (desktop only). */}
      <div className="pointer-events-none absolute inset-x-0 top-[27px] hidden h-px bg-slate-200 lg:block">
        <motion.div
          className="h-full origin-left bg-gradient-to-r from-cyan-400 via-[#d4af37] to-violet-500"
          initial={{ scaleX: 0 }}
          animate={{ scaleX: inView ? 1 : 0 }}
          transition={{ duration: 1.8, ease: [0.22, 1, 0.36, 1] }}
        />
      </div>

      <ol className="grid list-none grid-cols-2 gap-x-4 gap-y-8 p-0 sm:grid-cols-4 lg:grid-cols-7">
        {stages.map((stage, i) => {
          const Icon = stage.icon;
          return (
            <motion.li
              key={stage.label}
              initial={{ opacity: 0, y: 18 }}
              animate={inView ? { opacity: 1, y: 0 } : undefined}
              transition={{ duration: 0.5, delay: i * 0.12, ease: [0.22, 1, 0.36, 1] }}
              className="relative text-center"
            >
              <span
                className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border bg-white shadow-[0_10px_30px_rgba(2,6,23,0.08)]"
                style={{ borderColor: `${stage.color}44`, color: stage.color }}
              >
                <Icon className="h-6 w-6" />
              </span>
              <div className="mt-3 font-mono text-[11px] font-black uppercase tracking-[0.18em] text-slate-900">
                {stage.label}
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-slate-600">{stage.body}</p>
            </motion.li>
          );
        })}
      </ol>
    </div>
  );
}

/* -------------------------------------------------------------- navigator -- */

/**
 * Sticky module navigator. Tracks which module section is on screen and scrolls
 * the active chip into view so the row stays oriented on narrow screens.
 */
export function ModuleNavigator({ modules }: { modules: ModuleEntry[] }) {
  const [active, setActive] = React.useState(modules[0]?.id ?? '');
  const railRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    const targets = modules
      .map((m) => document.getElementById(m.id))
      .filter((el): el is HTMLElement => Boolean(el));
    if (!targets.length) return;

    const io = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (visible?.target.id) setActive(visible.target.id);
      },
      { rootMargin: '-45% 0px -45% 0px', threshold: 0 },
    );
    targets.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, [modules]);

  React.useEffect(() => {
    const rail = railRef.current;
    const chip = rail?.querySelector<HTMLElement>(`[data-chip="${active}"]`);
    if (!rail || !chip) return;

    /*
     * Centre the active chip by moving the rail's OWN horizontal scroll only.
     *
     * Do not use chip.scrollIntoView() here: it scrolls every scrollable
     * ancestor including the document, which fights the user's own scrolling.
     * Because `active` is driven by an IntersectionObserver on scroll, that
     * turned into a feedback loop (scroll → active changes → page scrolls
     * itself → observer fires again) which trapped the page around the first
     * module sections.
     */
    const overflow = rail.scrollWidth - rail.clientWidth;
    if (overflow <= 0) return; // nothing to scroll — leave the page alone

    const target = chip.offsetLeft - (rail.clientWidth - chip.offsetWidth) / 2;
    const left = Math.max(0, Math.min(overflow, target));
    if (Math.abs(left - rail.scrollLeft) < 2) return; // already there

    rail.scrollTo({ left, behavior: 'smooth' });
  }, [active]);

  return (
    <div className="sticky top-16 z-40 border-y border-slate-200 bg-white/85 backdrop-blur-2xl">
      <div
        ref={railRef}
        className="mx-auto flex max-w-[96rem] gap-2 overflow-x-auto px-4 py-2.5 sm:px-6 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
      >
        {modules.map((m) => {
          const on = active === m.id;
          return (
            <a
              key={m.id}
              href={`#${m.id}`}
              data-chip={m.id}
              className={cn(
                'shrink-0 rounded-full border px-3 py-1.5 font-mono text-[11px] font-bold uppercase tracking-wide no-underline transition-all duration-200',
                on
                  ? 'border-transparent text-slate-50 shadow-[0_6px_18px_rgba(2,6,23,0.18)]'
                  : 'border-slate-200 bg-white text-slate-500 hover:border-slate-300 hover:text-slate-900',
              )}
              style={on ? { backgroundColor: m.accent } : undefined}
            >
              <span className="mr-1.5 opacity-60">{String(m.index).padStart(2, '0')}</span>
              {m.eyebrow}
            </a>
          );
        })}
      </div>
    </div>
  );
}

/* ----------------------------------------------------------------- chapter -- */

export function ChapterMarker({
  number,
  title,
  body,
  color,
}: {
  number: string;
  title: string;
  body: string;
  color: string;
}) {
  return (
    <Reveal>
      <div className="mx-auto max-w-3xl text-center">
        <div className="flex items-center justify-center gap-3">
          <span className="h-px w-10 bg-slate-200" />
          <span
            className="font-mono text-[11px] font-black uppercase tracking-[0.32em]"
            style={{ color }}
          >
            Chapter {number}
          </span>
          <span className="h-px w-10 bg-slate-200" />
        </div>
        <h2 className="mt-4 text-3xl font-black tracking-tight text-slate-900 sm:text-4xl">{title}</h2>
        <p className="mt-3 text-base leading-relaxed text-slate-600">{body}</p>
      </div>
    </Reveal>
  );
}

/* ----------------------------------------------------------- module block -- */

/**
 * One module showcase: image stage on one side, business-first copy on the other.
 * Alternates sides so the page reads as a sequence rather than a list.
 */
export function ModuleShowcase({ module: m }: { module: ModuleEntry }) {
  const Icon = m.icon;
  const reverse = m.index % 2 === 0;

  return (
    <Reveal>
      <section id={m.id} className="scroll-mt-32">
        <GlassCard className="grid overflow-hidden p-0 lg:grid-cols-2" hover={false}>
          {/* ---- visual stage ---- */}
          <div className={cn('relative min-h-[260px] bg-[#050b16]', reverse && 'lg:order-2')}>
            <div
              className="absolute inset-x-0 top-0 z-20 h-[3px]"
              style={{ background: `linear-gradient(90deg, transparent, ${m.accent}, transparent)` }}
            />
            <motion.img
              src={m.image}
              alt={`${m.title} — illustration`}
              loading="lazy"
              decoding="async"
              className="h-full w-full object-cover"
              initial={{ scale: 1.06, opacity: 0.7 }}
              whileInView={{ scale: 1, opacity: 1 }}
              viewport={{ once: true, margin: '-60px' }}
              transition={{ duration: 1.1, ease: [0.22, 1, 0.36, 1] }}
            />
            <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(5,11,22,0.15)_0%,transparent_35%,rgba(5,11,22,0.72)_100%)]" />

            {/* Module number + icon badge. */}
            <div className="absolute inset-x-0 bottom-0 z-20 flex items-end justify-between gap-3 p-5">
              <span
                className="flex h-11 w-11 items-center justify-center rounded-xl border backdrop-blur-xl"
                style={{
                  borderColor: `${m.accent}55`,
                  backgroundColor: `${m.accent}1f`,
                  color: m.accent,
                }}
              >
                <Icon className="h-5 w-5" />
              </span>
              <span className="font-mono text-4xl font-black leading-none text-[#f8fafc]/25">
                {String(m.index).padStart(2, '0')}
              </span>
            </div>
          </div>

          {/* ---- copy ---- */}
          <div className={cn('p-6 sm:p-8 lg:p-10', reverse && 'lg:order-1')}>
            <span
              className="inline-flex items-center gap-2 rounded-full border px-3 py-1 font-mono text-[10px] font-bold uppercase tracking-[0.2em]"
              style={{ borderColor: `${m.accent}44`, backgroundColor: `${m.accent}12`, color: m.accent }}
            >
              {m.eyebrow}
            </span>

            <h3 className="mt-4 text-2xl font-black tracking-tight text-slate-900 sm:text-3xl">
              {m.title}
            </h3>
            <p className="mt-3 text-[15px] leading-relaxed text-slate-600">{m.blurb}</p>

            {/* Business value callout — the "why it matters" line. */}
            <div
              className="mt-5 rounded-xl border-l-[3px] bg-slate-50/80 px-4 py-3"
              style={{ borderLeftColor: m.accent }}
            >
              <div className="font-mono text-[10px] font-black uppercase tracking-[0.2em] text-slate-500">
                Why it matters
              </div>
              <p className="mt-1 text-sm font-semibold leading-relaxed text-slate-800">{m.value}</p>
            </div>

            <div className="mt-5">
              <div className="font-mono text-[10px] font-black uppercase tracking-[0.2em] text-slate-500">
                What it does
              </div>
              <ul className="mt-2.5 grid list-none grid-cols-1 gap-x-5 gap-y-2 p-0 sm:grid-cols-2">
                {m.capabilities.map((c) => (
                  <li key={c} className="flex items-start gap-2 text-[13px] leading-snug text-slate-700">
                    <Check className="mt-0.5 h-3.5 w-3.5 shrink-0" style={{ color: m.accent }} />
                    <span>{c}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="mt-5 flex flex-wrap gap-2">
              {m.benefits.map((b) => (
                <span
                  key={b}
                  className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-bold text-slate-700"
                >
                  {b}
                </span>
              ))}
            </div>

            <figure className="mt-5 flex gap-3 rounded-xl border border-slate-200 bg-white/70 p-4">
              <Quote className="h-4 w-4 shrink-0 text-slate-300" />
              <figcaption className="text-[13px] italic leading-relaxed text-slate-600">
                {m.useCase}
              </figcaption>
            </figure>

            <Link
              to={m.to}
              className="group mt-6 inline-flex items-center gap-2 text-sm font-bold uppercase tracking-wide no-underline transition-colors"
              style={{ color: m.accent }}
            >
              Explore {m.eyebrow}
              <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
            </Link>
          </div>
        </GlassCard>
      </section>
    </Reveal>
  );
}

/* --------------------------------------------------------------- benefits -- */

/** Hover-reveal benefit card: the plain-English payoff, expanded on hover/focus. */
export function BenefitCard({
  icon: Icon,
  title,
  body,
  color,
  delay = 0,
}: {
  icon: LucideIcon;
  title: string;
  body: string;
  color: string;
  delay?: number;
}) {
  return (
    <Reveal delay={delay} className="h-full">
      <div
        tabIndex={0}
        className="group relative h-full overflow-hidden rounded-2xl border border-slate-200 bg-white/85 p-6 backdrop-blur-xl transition-all duration-300 hover:-translate-y-1 hover:shadow-[0_26px_70px_rgba(2,6,23,0.12)] focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
      >
        <span
          className="pointer-events-none absolute -right-10 -top-10 h-28 w-28 rounded-full opacity-0 blur-[42px] transition-opacity duration-500 group-hover:opacity-100 group-focus:opacity-100"
          style={{ backgroundColor: color }}
        />
        <span
          className="relative flex h-11 w-11 items-center justify-center rounded-xl border transition-transform duration-300 group-hover:scale-110"
          style={{ borderColor: `${color}33`, backgroundColor: `${color}12`, color }}
        >
          <Icon className="h-5 w-5" />
        </span>
        <h3 className="relative mt-4 text-base font-bold text-slate-900">{title}</h3>
        <p className="relative mt-2 text-sm leading-relaxed text-slate-600">{body}</p>
        <span
          className="absolute inset-x-0 bottom-0 h-[3px] origin-left scale-x-0 transition-transform duration-500 group-hover:scale-x-100 group-focus:scale-x-100"
          style={{ backgroundColor: color }}
        />
      </div>
    </Reveal>
  );
}

/* ------------------------------------------------------------ before/after -- */

export type ShiftRow = { dimension: string; before: string; after: string };

/**
 * Before/after comparison of running a PQC programme without and with the
 * platform. Toggling swaps the highlighted column; both are always readable so
 * the comparison stands on its own for keyboard and screen-reader users.
 */
export function ShiftPanel({ rows }: { rows: ShiftRow[] }) {
  const [side, setSide] = React.useState<'before' | 'after'>('after');

  return (
    <div>
      <div className="flex justify-center">
        <div
          className="inline-flex rounded-full border border-slate-200 bg-white p-1"
          role="radiogroup"
          aria-label="Comparison view"
        >
          {(['before', 'after'] as const).map((option) => (
            <button
              key={option}
              type="button"
              role="radio"
              aria-checked={side === option}
              onClick={() => setSide(option)}
              className={cn(
                'rounded-full px-5 py-1.5 text-xs font-black uppercase tracking-wide transition',
                side === option
                  ? option === 'after'
                    ? 'bg-cyan-600 text-slate-50 shadow'
                    : 'bg-slate-800 text-slate-50 shadow'
                  : 'text-slate-500 hover:text-slate-800',
              )}
            >
              {option === 'before' ? 'Without QGuard Helix' : 'With QGuard Helix'}
            </button>
          ))}
        </div>
      </div>

      <div className="mt-6 overflow-hidden rounded-2xl border border-slate-200 bg-white/85 backdrop-blur-xl">
        <div className="grid grid-cols-[1.1fr_1fr_1fr] gap-px bg-slate-200 sm:grid-cols-[1fr_1fr_1fr]">
          <div className="bg-slate-50 px-4 py-3 font-mono text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">
            Dimension
          </div>
          <div
            className={cn(
              'px-4 py-3 font-mono text-[10px] font-black uppercase tracking-[0.18em] transition-colors',
              side === 'before' ? 'bg-slate-800 text-slate-100' : 'bg-slate-50 text-slate-400',
            )}
          >
            Without
          </div>
          <div
            className={cn(
              'px-4 py-3 font-mono text-[10px] font-black uppercase tracking-[0.18em] transition-colors',
              side === 'after' ? 'bg-cyan-600 text-slate-50' : 'bg-slate-50 text-slate-400',
            )}
          >
            With QGuard Helix
          </div>

          {rows.map((row) => (
            <React.Fragment key={row.dimension}>
              <div className="bg-white px-4 py-4 text-[13px] font-bold text-slate-900">
                {row.dimension}
              </div>
              <div
                className={cn(
                  'px-4 py-4 text-[13px] leading-snug transition-colors',
                  side === 'before' ? 'bg-slate-50 text-slate-800' : 'bg-white text-slate-400',
                )}
              >
                {row.before}
              </div>
              <div
                className={cn(
                  'px-4 py-4 text-[13px] leading-snug transition-colors',
                  side === 'after' ? 'bg-cyan-50/70 font-semibold text-slate-900' : 'bg-white text-slate-400',
                )}
              >
                {row.after}
              </div>
            </React.Fragment>
          ))}
        </div>
      </div>
    </div>
  );
}

/* --------------------------------------------------------------- final CTA -- */

export function FinalCTA({
  image,
  title,
  body,
  actions,
}: {
  image: string;
  title: React.ReactNode;
  body: string;
  actions: Array<{ label: string; to?: string; href?: string; tone: 'primary' | 'gold' | 'ghost' }>;
}) {
  return (
    <section className="qguard-dark-stage mx-auto max-w-[96rem] px-4 py-20 sm:px-6">
      <Reveal>
        <div className="relative isolate overflow-hidden rounded-3xl border border-slate-200 shadow-[0_30px_90px_rgba(2,6,23,0.18)]">
          <img
            src={image}
            alt=""
            aria-hidden
            loading="lazy"
            decoding="async"
            className="absolute inset-0 -z-10 h-full w-full object-cover"
          />
          <div className="absolute inset-0 -z-10 bg-[linear-gradient(120deg,rgba(2,6,23,0.94)_0%,rgba(2,6,23,0.80)_48%,rgba(2,6,23,0.62)_100%)]" />

          <div className="max-w-3xl px-6 py-16 sm:px-12 sm:py-20">
            <h2 className="text-3xl font-black leading-tight tracking-tight text-[#f8fafc] sm:text-4xl lg:text-5xl">
              {title}
            </h2>
            <p className="mt-4 text-base leading-relaxed text-[#cbd5e1] sm:text-lg">{body}</p>

            <div className="mt-8 flex flex-wrap gap-3">
              {actions.map((a) => {
                const base =
                  'inline-flex items-center justify-center gap-2 rounded-lg px-6 py-3 text-sm font-bold uppercase tracking-wide no-underline transition-all duration-200 hover:-translate-y-0.5';
                const tone =
                  a.tone === 'primary'
                    ? 'bg-[#0891b2] text-[#f8fafc] shadow-[0_12px_34px_rgba(8,145,178,0.42)] hover:bg-[#0e7490]'
                    : a.tone === 'gold'
                      ? 'bg-[#d4af37] text-[#0b1120] shadow-[0_12px_34px_rgba(212,175,55,0.38)] hover:brightness-110'
                      : 'border border-[#475569] bg-[#0f172a]/60 text-[#e2e8f0] backdrop-blur-xl hover:border-[#94a3b8]';
                const inner = (
                  <>
                    {a.label}
                    <ArrowRight className="h-4 w-4" />
                  </>
                );
                return a.to ? (
                  <Link key={a.label} to={a.to} className={cn(base, tone)}>
                    {inner}
                  </Link>
                ) : (
                  <a key={a.label} href={a.href} className={cn(base, tone)}>
                    {inner}
                  </a>
                );
              })}
            </div>
          </div>
        </div>
      </Reveal>
    </section>
  );
}
