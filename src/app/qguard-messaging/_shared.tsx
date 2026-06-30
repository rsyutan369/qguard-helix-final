/**
 * Shared chrome + UI atoms for the QGuard Messaging marketing pages.
 * Matches the homepage LIGHT theme: white/grid background, near-black headings,
 * slate body text, with cyan (#00c5eb) + gold (#d4af37) accents and the
 * CyberBackground particle field. Copy is drawn from the verified marketing docs
 * in docs/secure-chat and docs/quantum-vault.
 */
import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion } from 'motion/react';
import {
  ArrowRight,
  ChevronDown,
  Github,
  Globe,
  Linkedin,
  Lock,
  MessageSquareLock,
  ShieldCheck,
  Twitter,
  type LucideIcon,
} from 'lucide-react';
import { CyberBackground } from '../../components/CyberBackground';
import { cn } from '@/lib/utils';

/* ---------------------------------------------------------------- motion ---- */

export const Reveal: React.FC<{
  children: React.ReactNode;
  delay?: number;
  className?: string;
}> = ({ children, delay = 0, className }) => {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-80px' }}
      transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1], delay }}
    >
      {children}
    </motion.div>
  );
};

/** Cyan gradient highlight for emphasis words in headings. */
export function Highlight({ children }: { children: React.ReactNode }) {
  return (
    <span className="bg-gradient-to-r from-cyan-500 via-cyan-400 to-violet-500 bg-clip-text text-transparent">
      {children}
    </span>
  );
}

/* -------------------------------------------------------------- buttons ----- */

export function DarkButton({
  to,
  href,
  children,
  className,
}: {
  to?: string;
  href?: string;
  children: React.ReactNode;
  className?: string;
}) {
  const cls = cn(
    'group inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-6 py-3 text-sm font-bold uppercase tracking-wide !text-white [&_*]:!text-white no-underline shadow-[0_12px_34px_rgba(37,99,235,0.35)] transition-all duration-200 hover:-translate-y-0.5 hover:bg-blue-700 active:translate-y-0',
    className,
  );
  const inner = (
    <>
      {children}
      <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
    </>
  );
  if (to) return <Link to={to} className={cls}>{inner}</Link>;
  return <a href={href ?? '#'} className={cls}>{inner}</a>;
}

export function GoldButton({
  to,
  href,
  children,
  className,
}: {
  to?: string;
  href?: string;
  children: React.ReactNode;
  className?: string;
}) {
  const cls = cn(
    'group inline-flex items-center justify-center gap-2 rounded-lg bg-gold px-6 py-3 text-sm font-bold uppercase tracking-wide text-slate-950 no-underline shadow-[0_0_28px_rgba(212,175,55,0.35)] transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[0_0_44px_rgba(212,175,55,0.55)] active:translate-y-0',
    className,
  );
  const inner = (
    <>
      {children}
      <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
    </>
  );
  if (to) return <Link to={to} className={cls}>{inner}</Link>;
  return <a href={href ?? '#'} className={cls}>{inner}</a>;
}

export function GhostButton({
  to,
  href,
  children,
  className,
}: {
  to?: string;
  href?: string;
  children: React.ReactNode;
  className?: string;
}) {
  const cls = cn(
    'inline-flex items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-6 py-3 text-sm font-bold uppercase tracking-wide text-slate-900 no-underline transition-all duration-200 hover:border-gold hover:text-gold',
    className,
  );
  if (to) return <Link to={to} className={cls}>{children}</Link>;
  return <a href={href ?? '#'} className={cls}>{children}</a>;
}

/* ------------------------------------------------------------- primitives --- */

export function Kicker({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-gold/40 bg-gold/10 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.22em] text-[#b8860b]">
      <ShieldCheck className="h-3.5 w-3.5 text-gold" />
      {children}
    </span>
  );
}

export function SectionHeading({
  kicker,
  title,
  subtitle,
  center = true,
}: {
  kicker?: string;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  center?: boolean;
}) {
  return (
    <div className={cn('max-w-3xl space-y-4', center && 'mx-auto text-center')}>
      {kicker && <Kicker>{kicker}</Kicker>}
      <h2 className="text-3xl font-black tracking-tight text-slate-900 sm:text-4xl">{title}</h2>
      {subtitle && <p className="text-base leading-relaxed text-slate-600">{subtitle}</p>}
    </div>
  );
}

export function GlassCard({
  children,
  className,
  hover = true,
}: {
  children: React.ReactNode;
  className?: string;
  hover?: boolean;
}) {
  return (
    <div
      className={cn(
        'rounded-2xl border border-slate-200 bg-white/85 backdrop-blur-xl shadow-[0_18px_50px_rgba(2,6,23,0.08)] transition-all duration-300',
        hover && 'hover:-translate-y-1 hover:border-gold/50 hover:shadow-[0_26px_80px_rgba(212,175,55,0.20)]',
        className,
      )}
    >
      {children}
    </div>
  );
}

export type Feature = { icon: LucideIcon; title: string; body: string };

export const FeatureCard: React.FC<{ feature: Feature; delay?: number }> = ({ feature, delay = 0 }) => {
  const { icon: Icon, title, body } = feature;
  return (
    <Reveal delay={delay} className="h-full">
      <GlassCard className="group h-full p-6">
        <span className="flex h-11 w-11 items-center justify-center rounded-xl border border-gold/30 bg-gold/10 text-[#b8860b] shadow-[0_0_22px_rgba(212,175,55,0.18)] transition-transform duration-300 group-hover:scale-110">
          <Icon className="h-5 w-5" />
        </span>
        <h3 className="mt-4 text-base font-bold text-slate-900">{title}</h3>
        <p className="mt-2 text-sm leading-relaxed text-slate-600">{body}</p>
      </GlassCard>
    </Reveal>
  );
};

export function TrustStrip({ items }: { items: string[] }) {
  return (
    <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-2">
      {items.map((item) => (
        <span
          key={item}
          className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-white/85 px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-wide text-slate-700 backdrop-blur-xl"
        >
          <ShieldCheck className="h-3 w-3 text-gold" />
          {item}
        </span>
      ))}
    </div>
  );
}

export const StepCard: React.FC<{ index: number; title: string; body: string }> = ({ index, title, body }) => {
  return (
    <Reveal delay={index * 0.08} className="h-full">
      <GlassCard className="h-full p-6" hover={false}>
        <span className="font-mono text-3xl font-black text-gold/50">{String(index + 1).padStart(2, '0')}</span>
        <h3 className="mt-2 text-base font-bold text-slate-900">{title}</h3>
        <p className="mt-2 text-sm leading-relaxed text-slate-600">{body}</p>
      </GlassCard>
    </Reveal>
  );
};

export const ALGO_SUITE: Array<{ purpose: string; algo: string; standard: string }> = [
  { purpose: 'Key encapsulation (hybrid)', algo: 'ML-KEM-1024 + X25519', standard: 'NIST FIPS 203' },
  { purpose: 'Digital signatures (dual)', algo: 'ML-DSA + Ed25519', standard: 'NIST FIPS 204' },
  { purpose: 'Symmetric / AEAD', algo: 'AES-256-GCM', standard: 'FIPS 197' },
  { purpose: 'Key derivation / hashing', algo: 'HKDF-SHA3-256', standard: 'FIPS 202' },
];

export function AlgoSuiteTable() {
  return (
    <GlassCard className="overflow-hidden" hover={false}>
      <div className="grid grid-cols-1 divide-y divide-slate-200 sm:grid-cols-2 sm:divide-x lg:grid-cols-4 lg:divide-y-0">
        {ALGO_SUITE.map((row) => (
          <div key={row.purpose} className="p-5">
            <div className="font-mono text-[10px] font-bold uppercase tracking-widest text-slate-500">{row.purpose}</div>
            <div className="mt-2 font-mono text-sm font-bold text-slate-900">{row.algo}</div>
            <div className="mt-2 inline-flex rounded-full border border-gold/30 bg-gold/10 px-2 py-0.5 font-mono text-[10px] font-bold text-[#b8860b]">{row.standard}</div>
          </div>
        ))}
      </div>
    </GlassCard>
  );
}

/* ---------------------------------------------------------------- chrome ---- */

const NAV_LINKS = [
  { label: 'Overview', to: '/qguard-messaging' },
  { label: 'Secure Chat', to: '/qguard-messaging/secure-chat' },
  { label: 'Quantum Vault', to: '/qguard-messaging/quantum-vault' },
];

function MessagingNav() {
  const { pathname } = useLocation();
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
        <Link to="/qguard-messaging" className="group flex min-w-0 items-center gap-3 no-underline">
          <img src="/NEW_LOGO.png" alt="QGuard logo" className="h-12 w-auto shrink-0 object-contain" />
          <span className="hidden flex-col leading-none sm:flex">
            <span className="whitespace-nowrap text-base font-black tracking-[0.02em] text-gold gold-glow">QGuard Messaging</span>
            <span className="mt-1 whitespace-nowrap bg-gradient-to-r from-cyan-500 via-slate-600 to-violet-600 bg-clip-text font-mono text-[9px] font-black uppercase tracking-[0.3em] text-transparent">
              Secure Chat · Quantum Vault
            </span>
          </span>
        </Link>

        <nav className="hidden items-center gap-1 lg:flex">
          {NAV_LINKS.map((item) => {
            const active = pathname === item.to;
            return (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  'rounded-lg px-3.5 py-2 text-sm font-semibold no-underline transition-colors',
                  active ? 'bg-gold/12 text-[#b8860b]' : 'text-slate-600 hover:text-gold',
                )}
              >
                {item.label}
              </Link>
            );
          })}
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

function MessagingFooter() {
  return (
    <footer className="relative z-10 mt-24 border-t border-slate-200 bg-white/70 px-6 py-14 backdrop-blur-xl">
      <div className="mx-auto grid max-w-[96rem] gap-10 lg:grid-cols-[1.6fr_2fr]">
        <div className="space-y-5">
          <Link to="/qguard-messaging" className="flex items-center gap-3 no-underline">
            <img src="/NEW_LOGO.png" alt="QGuard logo" className="h-12 w-auto object-contain" />
            <span className="flex flex-col leading-none">
              <strong className="text-base font-black tracking-wide text-gold">QGUARD MESSAGING</strong>
              <small className="mt-1 font-mono text-[9px] uppercase tracking-[0.3em] text-slate-500">// Quantum Cyber Defense</small>
            </span>
          </Link>
          <p className="max-w-md text-sm leading-relaxed text-slate-600">
            Post-quantum, end-to-end encrypted messaging and a strictly on-device file vault — built on NIST-standardized cryptography (FIPS 203 &amp; 204).
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
          <FooterCol title="Product" links={[
            { label: 'Overview', to: '/qguard-messaging' },
            { label: 'Secure Chat', to: '/qguard-messaging/secure-chat' },
            { label: 'Quantum Vault', to: '/qguard-messaging/quantum-vault' },
          ]} />
          <FooterCol title="Platform" links={[
            { label: 'QGuard Helix', href: '/' },
            { label: 'Documentation', href: '/docs' },
            { label: 'Dashboard', href: '/dashboard' },
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

export function MessagingLayout({ children }: { children: React.ReactNode }) {
  const { pathname } = useLocation();
  React.useEffect(() => { window.scrollTo({ top: 0 }); }, [pathname]);

  return (
    <div className="qguard-home qguard-home--light relative min-h-screen overflow-x-hidden bg-white text-slate-900">
      {/* Subtle light grid wash to match the homepage hero. */}
      <div
        className="pointer-events-none fixed inset-0 -z-10 opacity-60"
        style={{
          backgroundImage:
            'radial-gradient(rgba(148,163,184,0.18) 1px, transparent 1px)',
          backgroundSize: '26px 26px',
        }}
      />
      <CyberBackground variant="light" />
      <MessagingNav />
      <main className="relative z-10">{children}</main>
      <MessagingFooter />
    </div>
  );
}

export function CTASection({
  title,
  body,
  primary,
  secondary,
}: {
  title: string;
  body: string;
  primary: { label: string; to?: string; href?: string };
  secondary?: { label: string; to?: string; href?: string };
}) {
  return (
    <section className="mx-auto max-w-5xl px-6 py-20">
      <Reveal>
        <GlassCard className="relative overflow-hidden p-10 text-center sm:p-14" hover={false}>
          <div className="pointer-events-none absolute -right-16 -top-16 h-56 w-56 rounded-full bg-gold/20 blur-[80px]" />
          <div className="pointer-events-none absolute -bottom-16 -left-16 h-56 w-56 rounded-full bg-cyan-300/25 blur-[80px]" />
          <div className="relative z-10 mx-auto max-w-2xl space-y-5">
            <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-gold/30 bg-gold/10 text-[#b8860b]">
              <Lock className="h-6 w-6" />
            </span>
            <h2 className="text-3xl font-black tracking-tight text-slate-900 sm:text-4xl">{title}</h2>
            <p className="text-base leading-relaxed text-slate-600">{body}</p>
            <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
              <DarkButton to={primary.to} href={primary.href}>{primary.label}</DarkButton>
              {secondary && <GhostButton to={secondary.to} href={secondary.href}>{secondary.label}</GhostButton>}
            </div>
          </div>
        </GlassCard>
      </Reveal>
    </section>
  );
}

export { MessageSquareLock, Lock };
