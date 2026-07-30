/**
 * Shared chrome + QR-specific UI for the Quantum Readiness Assessment marketing page
 * (/quantum-readiness-assessment).
 *
 * Reuses the exact QGuard Messaging marketing design language (light theme, white +
 * dot-grid background, CyberBackground particle field, gold #d4af37 + cyan + violet
 * accents, GlassCard system, Framer Motion reveals) but branded for the Quantum
 * Readiness Assessment Engine, with its own anchor nav + footer.
 *
 * The base atoms (Reveal, Highlight, GlassCard, buttons, etc.) are imported straight
 * from the messaging _shared so the two surfaces stay pixel-identical by construction.
 */
import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion, useInView, useReducedMotion } from 'motion/react';
import {
  ArrowRight,
  ChevronDown,
  Github,
  Globe,
  Linkedin,
  Twitter,
  ShieldCheck,
  Radar,
  type LucideIcon,
} from 'lucide-react';
import { CyberBackground } from '../../components/CyberBackground';
import { cn } from '@/lib/utils';
import {
  Reveal,
  Highlight,
  Kicker,
  SectionHeading,
  GlassCard,
  FeatureCard,
  TrustStrip,
  DarkButton,
  GoldButton,
  GhostButton,
  CTASection,
  type Feature,
} from '../qguard-messaging/_shared';

/* ------------------------------------------------------------ re-exports ---- */
/* One import surface for the page: everything it needs comes from ./_shared.  */
export {
  Reveal,
  Highlight,
  Kicker,
  SectionHeading,
  GlassCard,
  FeatureCard,
  TrustStrip,
  DarkButton,
  GoldButton,
  GhostButton,
  CTASection,
};
export type { Feature };

/* ---------------------------------------------------------- count-up value -- */

/**
 * Animated number that counts up from 0 → target the first time it scrolls into
 * view (respecting prefers-reduced-motion). easeOutCubic for a decisive settle.
 */
export function CountUp({
  value,
  decimals = 0,
  prefix = '',
  suffix = '',
  duration = 1500,
  className,
}: {
  value: number;
  decimals?: number;
  prefix?: string;
  suffix?: string;
  duration?: number;
  className?: string;
}) {
  const ref = React.useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, margin: '-60px' });
  const reduce = useReducedMotion();
  const [display, setDisplay] = React.useState(0);

  React.useEffect(() => {
    if (!inView) return;
    if (reduce) {
      setDisplay(value);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(value * eased);
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, value, duration, reduce]);

  const formatted =
    decimals > 0
      ? display.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals })
      : Math.round(display).toLocaleString('en-US');

  return (
    <span ref={ref} className={className}>
      {prefix}
      {formatted}
      {suffix}
    </span>
  );
}

/* --------------------------------------------------------- readiness ring --- */

/** SVG progress ring that draws itself when scrolled into view. */
export function ReadinessRing({
  value,
  size = 148,
  stroke = 12,
  color = '#22c55e',
  trackColor = 'rgba(255,255,255,0.09)',
  children,
}: {
  value: number;
  size?: number;
  stroke?: number;
  color?: string;
  trackColor?: string;
  children?: React.ReactNode;
}) {
  const ref = React.useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: '-40px' });
  const r = (size - stroke) / 2;
  const circumference = 2 * Math.PI * r;
  const offset = circumference * (1 - Math.max(0, Math.min(100, value)) / 100);

  return (
    <div ref={ref} className="relative grid shrink-0 place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90" aria-hidden>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={trackColor} strokeWidth={stroke} />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: inView ? offset : circumference }}
          transition={{ duration: 1.5, ease: [0.22, 1, 0.36, 1] }}
          style={{ filter: `drop-shadow(0 0 10px ${color}66)` }}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">{children}</div>
    </div>
  );
}

/* ----------------------------------------------------------- score card ----- */

export type Score = {
  label: string;
  value: number;
  suffix?: string;
  decimals?: number;
  detail: string;
  color: string;
  ring?: number; // 0-100; omit for a big-number card
  icon: LucideIcon;
};

/** KPI card mirroring the dashboard MetricCard — animated count + slim meter. */
export const ScoreCard: React.FC<{ score: Score; delay?: number }> = ({ score, delay = 0 }) => {
  const { label, value, suffix, decimals, detail, color, ring, icon: Icon } = score;
  const barRef = React.useRef<HTMLDivElement>(null);
  const inView = useInView(barRef, { once: true, margin: '-40px' });
  return (
    <Reveal delay={delay} className="h-full">
      <GlassCard className="h-full p-5">
        <div className="flex items-start justify-between">
          <span
            className="grid h-10 w-10 place-items-center rounded-xl border"
            style={{ borderColor: `${color}33`, color, backgroundColor: `${color}12` }}
          >
            <Icon className="h-5 w-5" />
          </span>
          {typeof ring === 'number' && (
            <span className="font-mono text-[10px] font-bold uppercase tracking-widest" style={{ color }}>
              {ring}%
            </span>
          )}
        </div>
        <div className="mt-4 flex items-end gap-1">
          <CountUp value={value} decimals={decimals} suffix={suffix} className="text-3xl font-black tracking-tight text-slate-900" />
        </div>
        <div className="mt-1 text-[13px] font-bold text-slate-800">{label}</div>
        <div className="mt-0.5 text-xs leading-snug text-slate-500">{detail}</div>
        {typeof ring === 'number' && (
          <div ref={barRef} className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-slate-200/70">
            <motion.div
              className="h-full rounded-full"
              style={{ backgroundColor: color }}
              initial={{ width: 0 }}
              animate={{ width: inView ? `${Math.max(0, Math.min(100, ring))}%` : 0 }}
              transition={{ duration: 1.3, ease: [0.22, 1, 0.36, 1] }}
            />
          </div>
        )}
      </GlassCard>
    </Reveal>
  );
};

/* -------------------------------------------------------- module spotlight -- */

/** Image + copy showcase row (alternating), matching the messaging ProductSpotlight. */
export function ModuleSpotlight({
  eyebrow,
  title,
  blurb,
  bullets,
  image,
  icon: Icon,
  reverse = false,
}: {
  eyebrow: string;
  title: string;
  blurb: string;
  bullets: string[];
  image: string;
  icon: LucideIcon;
  reverse?: boolean;
}) {
  return (
    <Reveal>
      <GlassCard className="grid items-center gap-8 overflow-hidden p-6 sm:p-8 lg:grid-cols-2" hover={false}>
        <div className={reverse ? 'lg:order-2' : ''}>
          <span className="inline-flex items-center gap-2 rounded-full border border-gold/40 bg-gold/10 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-[#b8860b]">
            <Icon className="h-3.5 w-3.5 text-gold" /> {eyebrow}
          </span>
          <h3 className="mt-4 text-2xl font-black tracking-tight text-slate-900 sm:text-3xl">{title}</h3>
          <p className="mt-3 text-sm leading-relaxed text-slate-600">{blurb}</p>
          <ul className="mt-5 space-y-2.5">
            {bullets.map((b) => (
              <li key={b} className="flex items-start gap-2.5 text-sm text-slate-700">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-gold" />
                <span>{b}</span>
              </li>
            ))}
          </ul>
        </div>
        <div className={reverse ? 'lg:order-1' : ''}>
          <motion.div
            whileHover={{ scale: 1.02 }}
            transition={{ duration: 0.4 }}
            className="relative overflow-hidden rounded-xl border border-slate-200 bg-slate-950 shadow-[0_24px_70px_rgba(2,6,23,0.25)]"
          >
            <div className="absolute inset-x-0 top-0 z-10 h-[3px] bg-gradient-to-r from-cyan-400 via-gold to-violet-500" />
            <img src={image} alt={title} className="h-full max-h-[340px] w-full object-cover opacity-95" />
          </motion.div>
        </div>
      </GlassCard>
    </Reveal>
  );
}

/* ---------------------------------------------------------------- chrome ---- */

const NAV_LINKS = [
  { label: 'Overview', href: '#top' },
  { label: 'Scoring', href: '#scoring' },
  { label: 'Modules', href: '#modules' },
  { label: 'Standards', href: '#standards' },
];

function QRNav() {
  const [scrolled, setScrolled] = React.useState(false);
  React.useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 16);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <header
      className={cn(
        'fixed inset-x-0 top-0 z-50 border-b transition-all duration-300',
        scrolled
          ? 'border-slate-200 bg-white/85 shadow-[0_10px_40px_rgba(2,6,23,0.08)] backdrop-blur-2xl'
          : 'border-transparent bg-white/55 backdrop-blur-xl',
      )}
    >
      <div className="mx-auto flex h-16 max-w-[96rem] items-center justify-between px-4 sm:px-6">
        <Link to="/quantum-readiness-assessment" className="group flex min-w-0 items-center gap-3 no-underline">
          <img src="/NEW_LOGO.png" alt="QGuard logo" className="h-12 w-auto shrink-0 object-contain" />
          <span className="hidden flex-col leading-none sm:flex">
            <span className="whitespace-nowrap text-base font-black tracking-[0.02em] text-gold gold-glow">Quantum Readiness</span>
            <span className="mt-1 whitespace-nowrap bg-gradient-to-r from-cyan-500 via-slate-600 to-violet-600 bg-clip-text font-mono text-[9px] font-black uppercase tracking-[0.3em] text-transparent">
              Assessment Engine
            </span>
          </span>
        </Link>

        <nav className="hidden items-center gap-1 lg:flex">
          {NAV_LINKS.map((item) => (
            <a
              key={item.href}
              href={item.href}
              className="rounded-lg px-3.5 py-2 text-sm font-semibold text-slate-600 no-underline transition-colors hover:text-gold"
            >
              {item.label}
            </a>
          ))}
          <Link to="/public-scan" className="rounded-lg px-3.5 py-2 text-sm font-semibold text-slate-600 no-underline transition-colors hover:text-gold">
            Free Scan
          </Link>
          <Link to="/dashboard/quantum-readiness" className="rounded-lg px-3.5 py-2 text-sm font-semibold text-slate-600 no-underline transition-colors hover:text-gold">
            Live Dashboard
          </Link>
          <a href="/" className="rounded-lg px-3.5 py-2 text-sm font-semibold text-slate-600 no-underline transition-colors hover:text-gold">
            Home
          </a>
        </nav>

        <GoldButton href="/login" className="px-4 py-2 text-xs">Launch App</GoldButton>
      </div>
    </header>
  );
}

function FooterCol({
  title,
  links,
}: {
  title: string;
  links: Array<{ label: string; to?: string; href?: string }>;
}) {
  return (
    <div>
      <h3 className="font-mono text-[11px] font-bold uppercase tracking-widest text-slate-900">{title}</h3>
      <ul className="mt-3 space-y-2">
        {links.map((l) => (
          <li key={l.label}>
            {l.to ? (
              <Link to={l.to} className="text-sm text-slate-600 no-underline transition-colors hover:text-gold">{l.label}</Link>
            ) : (
              <a href={l.href} className="text-sm text-slate-600 no-underline transition-colors hover:text-gold">{l.label}</a>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function QRFooter() {
  return (
    <footer className="relative z-10 mt-24 border-t border-slate-200 bg-white/70 px-6 py-14 backdrop-blur-xl">
      <div className="mx-auto grid max-w-[96rem] gap-10 lg:grid-cols-[1.6fr_2fr]">
        <div className="space-y-5">
          <Link to="/quantum-readiness-assessment" className="flex items-center gap-3 no-underline">
            <img src="/NEW_LOGO.png" alt="QGuard logo" className="h-12 w-auto object-contain" />
            <span className="flex flex-col leading-none">
              <strong className="text-base font-black tracking-wide text-gold">QUANTUM READINESS</strong>
              <small className="mt-1 font-mono text-[9px] uppercase tracking-[0.3em] text-slate-500">// Assessment Engine</small>
            </span>
          </Link>
          <p className="max-w-md text-sm leading-relaxed text-slate-600">
            The Quantum Readiness Assessment Engine turns cryptographic inventory, runtime telemetry and trust intelligence
            into board-ready readiness scoring, AI advisory and evidence-driven migration planning &mdash; measured against
            the NIST post-quantum standards (FIPS&nbsp;203/204/205).
          </p>
          <div className="flex items-center gap-2">
            {[Twitter, Linkedin, Github].map((Icon, i) => (
              <a key={i} href="#" aria-label="social" className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-500 transition-colors hover:border-gold hover:text-gold">
                <Icon className="h-4 w-4" />
              </a>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-8 sm:grid-cols-3">
          <FooterCol title="Assessment" links={[
            { label: 'Command Center', to: '/dashboard/quantum-readiness/command-center' },
            { label: 'Executive Dashboard', to: '/dashboard/quantum-readiness/executive' },
            { label: 'Risk Analysis', to: '/dashboard/quantum-readiness/risk-analysis' },
            { label: 'Report Center', to: '/dashboard/quantum-readiness/reports' },
          ]} />
          <FooterCol title="Platform" links={[
            { label: 'QGuard Helix', href: '/' },
            { label: 'QGuard Messaging', to: '/qguard-messaging' },
            { label: 'Documentation', href: '/docs' },
            { label: 'Live Dashboard', to: '/dashboard/quantum-readiness' },
          ]} />
          <FooterCol title="Company" links={[
            { label: 'Sign in', href: '/login' },
            { label: 'Get started', href: '/register' },
            { label: 'Contact', href: '/docs' },
          ]} />
        </div>
      </div>

      <div className="mx-auto mt-12 flex max-w-[96rem] flex-col gap-4 border-t border-slate-200 pt-6 text-xs text-slate-500 md:flex-row md:items-center md:justify-between">
        <p>&copy; {new Date().getFullYear()} QGuard Helix. All rights reserved.</p>
        <div className="flex items-center gap-4">
          <a href="/docs" className="no-underline hover:text-gold">Privacy</a>
          <a href="/docs" className="no-underline hover:text-gold">Terms</a>
          <span className="inline-flex items-center gap-1.5"><Globe className="h-3.5 w-3.5" /> English <ChevronDown className="h-3.5 w-3.5" /></span>
        </div>
      </div>
    </footer>
  );
}

export function QuantumReadinessLayout({ children }: { children: React.ReactNode }) {
  const { pathname } = useLocation();
  React.useEffect(() => { window.scrollTo({ top: 0 }); }, [pathname]);

  return (
    <div className="qguard-home qguard-home--light relative min-h-screen overflow-x-hidden bg-white text-slate-900">
      {/* Subtle light grid wash to match the homepage / messaging hero. */}
      <div
        className="pointer-events-none fixed inset-0 -z-10 opacity-60"
        style={{
          backgroundImage: 'radial-gradient(rgba(148,163,184,0.18) 1px, transparent 1px)',
          backgroundSize: '26px 26px',
        }}
      />
      <CyberBackground variant="light" />
      <QRNav />
      <main className="relative z-10">{children}</main>
      <QRFooter />
    </div>
  );
}

export { ArrowRight, Radar };
