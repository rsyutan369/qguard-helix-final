/**
 * Shared chrome for the standalone solution marketing pages
 * (/post-quantum-migration-platform and /quantum-trust-governance-center).
 *
 * Reuses the EXACT QGuard Messaging + Quantum Readiness Assessment design
 * language (light theme, white + dot-grid background, CyberBackground particle
 * field, gold #d4af37 / cyan / violet accents, GlassCard system, Framer Motion
 * reveals) so all four marketing surfaces stay visually identical by
 * construction. The navigation is parameterized per product.
 */
import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { SkyAtmosphere } from '@/components/sky/SkyAtmosphere';
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
  StepCard,
  type Feature,
} from '../app/qguard-messaging/_shared';
import {
  CountUp,
  ReadinessRing,
  ScoreCard,
  ModuleSpotlight,
  type Score,
} from '../app/quantum-readiness-assessment/_shared';

/* One import surface for the pages: re-export every atom they need. */
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
  StepCard,
  CountUp,
  ReadinessRing,
  ScoreCard,
  ModuleSpotlight,
};
export type { Feature, Score };

export type NavLink = { label: string; href: string };

function SolutionNav({
  homePath,
  brandTitle,
  brandSubtitle,
  navLinks,
}: {
  homePath: string;
  brandTitle: string;
  brandSubtitle: string;
  navLinks: NavLink[];
}) {
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
        <Link to={homePath} className="group flex min-w-0 items-center gap-3 no-underline">
          <img src="/NEW_LOGO.png" alt="QGuard logo" className="h-12 w-auto shrink-0 object-contain" />
          <span className="hidden flex-col leading-none sm:flex">
            <span className="whitespace-nowrap text-base font-black tracking-[0.02em] text-gold gold-glow">{brandTitle}</span>
            <span className="mt-1 whitespace-nowrap bg-gradient-to-r from-cyan-500 via-slate-600 to-violet-600 bg-clip-text font-mono text-[9px] font-black uppercase tracking-[0.3em] text-transparent">
              {brandSubtitle}
            </span>
          </span>
        </Link>

        <nav className="hidden items-center gap-1 lg:flex">
          {navLinks.map((item) => (
            <a
              key={item.href}
              href={item.href}
              className="rounded-lg px-3.5 py-2 text-sm font-semibold text-slate-600 no-underline transition-colors hover:text-gold"
            >
              {item.label}
            </a>
          ))}
          <a href="/#pricing" className="rounded-lg px-3.5 py-2 text-sm font-semibold text-slate-600 no-underline transition-colors hover:text-gold">
            Pricing
          </a>
          <a href="/" className="rounded-lg px-3.5 py-2 text-sm font-semibold text-slate-600 no-underline transition-colors hover:text-gold">
            Home
          </a>
        </nav>

        <GoldButton href="/login" className="px-4 py-2 text-xs">Launch App</GoldButton>
      </div>
    </header>
  );
}

export function SolutionLayout({
  homePath,
  brandTitle,
  brandSubtitle,
  navLinks,
  children,
}: {
  homePath: string;
  brandTitle: string;
  brandSubtitle: string;
  navLinks: NavLink[];
  children: React.ReactNode;
}) {
  const { pathname } = useLocation();
  React.useEffect(() => { window.scrollTo({ top: 0 }); }, [pathname]);

  return (
    <div className="qguard-home qguard-home--light qh-sky relative min-h-screen overflow-x-hidden bg-white text-slate-900">
      <SkyAtmosphere routeKey={pathname} />
      <SolutionNav homePath={homePath} brandTitle={brandTitle} brandSubtitle={brandSubtitle} navLinks={navLinks} />
      <main className="relative z-10">{children}</main>
    </div>
  );
}

/* Small dark instrument-panel tile for the hero "console" signature. Uses
   explicit slate/cyan colours so the light-theme override sheet leaves the dark
   panel intact (see the qr-assessment-marketing-page memory note). */
export function ConsoleTile({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }>;
  label: string;
  value: string;
  tone: string;
}) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.04] p-4">
      <Icon className="h-5 w-5" style={{ color: tone }} />
      <div className="mt-2 font-mono text-[10px] uppercase tracking-widest text-slate-400">{label}</div>
      <div className="font-mono text-sm font-bold text-white">{value}</div>
    </div>
  );
}

/* Animated horizontal meter for the console panels (draws on view). */
export function ConsoleMeter({ label, value, color }: { label: string; value: number; color: string }) {
  const ref = React.useRef<HTMLDivElement>(null);
  const [seen, setSeen] = React.useState(false);
  React.useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(
      ([e]) => { if (e.isIntersecting) { setSeen(true); io.disconnect(); } },
      { rootMargin: '-40px' },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);
  return (
    <div ref={ref}>
      <div className="flex items-center justify-between font-mono text-[9px] font-bold uppercase tracking-widest text-slate-400">
        <span>{label}</span>
        <span style={{ color }}>{value}%</span>
      </div>
      <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
        <div
          className="h-full rounded-full transition-[width] duration-[1400ms] ease-out"
          style={{ width: seen ? `${value}%` : '0%', backgroundColor: color, filter: `drop-shadow(0 0 6px ${color}66)` }}
        />
      </div>
    </div>
  );
}
