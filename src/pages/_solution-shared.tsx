/**
 * Shared chrome for the standalone solution marketing pages
 * (/post-quantum-migration-platform and /quantum-trust-governance-center).
 *
 * Reuses the EXACT QGuard Messaging + Quantum Readiness Assessment design
 * language (light theme, white + dot-grid background, CyberBackground particle
 * field, gold #d4af37 / cyan / violet accents, GlassCard system, Framer Motion
 * reveals) so all four marketing surfaces stay visually identical by
 * construction. The nav/footer are parameterized per product.
 */
import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { ChevronDown, Github, Globe, Linkedin, Twitter } from 'lucide-react';
import { CyberBackground } from '../components/CyberBackground';
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
export type FooterLink = { label: string; to?: string; href?: string };
export type FooterGroup = { title: string; links: FooterLink[] };

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

const FooterCol: React.FC<{ title: string; links: FooterLink[] }> = ({ title, links }) => {
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

function SolutionFooter({
  homePath,
  brandTitle,
  brandTagline,
  footerBlurb,
  footerGroups,
}: {
  homePath: string;
  brandTitle: string;
  brandTagline: string;
  footerBlurb: React.ReactNode;
  footerGroups: FooterGroup[];
}) {
  return (
    <footer className="relative z-10 mt-24 border-t border-slate-200 bg-white/70 px-6 py-14 backdrop-blur-xl">
      <div className="mx-auto grid max-w-[96rem] gap-10 lg:grid-cols-[1.6fr_2fr]">
        <div className="space-y-5">
          <Link to={homePath} className="flex items-center gap-3 no-underline">
            <img src="/NEW_LOGO.png" alt="QGuard logo" className="h-12 w-auto object-contain" />
            <span className="flex flex-col leading-none">
              <strong className="text-base font-black tracking-wide text-gold">{brandTitle}</strong>
              <small className="mt-1 font-mono text-[9px] uppercase tracking-[0.3em] text-slate-500">// {brandTagline}</small>
            </span>
          </Link>
          <p className="max-w-md text-sm leading-relaxed text-slate-600">{footerBlurb}</p>
          <div className="flex items-center gap-2">
            {[Twitter, Linkedin, Github].map((Icon, i) => (
              <a key={i} href="#" aria-label="social" className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-500 transition-colors hover:border-gold hover:text-gold">
                <Icon className="h-4 w-4" />
              </a>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-8 sm:grid-cols-3">
          {footerGroups.map((group) => (
            <FooterCol key={group.title} title={group.title} links={group.links} />
          ))}
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

export function SolutionLayout({
  homePath,
  brandTitle,
  brandSubtitle,
  brandTagline,
  navLinks,
  footerBlurb,
  footerGroups,
  children,
}: {
  homePath: string;
  brandTitle: string;
  brandSubtitle: string;
  brandTagline: string;
  navLinks: NavLink[];
  footerBlurb: React.ReactNode;
  footerGroups: FooterGroup[];
  children: React.ReactNode;
}) {
  const { pathname } = useLocation();
  React.useEffect(() => { window.scrollTo({ top: 0 }); }, [pathname]);

  return (
    <div className="qguard-home qguard-home--light relative min-h-screen overflow-x-hidden bg-white text-slate-900">
      <div
        className="pointer-events-none fixed inset-0 -z-10 opacity-60"
        style={{
          backgroundImage: 'radial-gradient(rgba(148,163,184,0.18) 1px, transparent 1px)',
          backgroundSize: '26px 26px',
        }}
      />
      <CyberBackground variant="light" />
      <SolutionNav homePath={homePath} brandTitle={brandTitle} brandSubtitle={brandSubtitle} navLinks={navLinks} />
      <main className="relative z-10">{children}</main>
      <SolutionFooter
        homePath={homePath}
        brandTitle={brandTitle.toUpperCase()}
        brandTagline={brandTagline}
        footerBlurb={footerBlurb}
        footerGroups={footerGroups}
      />
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
