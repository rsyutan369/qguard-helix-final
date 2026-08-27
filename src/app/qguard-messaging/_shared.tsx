/**
 * Shared chrome + UI atoms for the QGuard Messaging marketing pages.
 * Matches the homepage LIGHT theme: white/grid background, near-black headings,
 * slate body text, with cyan (#00c5eb) + gold (#d4af37) accents and the
 * CyberBackground particle field. Copy is drawn from the verified marketing docs
 * in docs/secure-chat and docs/quantum-vault.
 */
import React, { useId, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'motion/react';
import {
  ArrowRight,
  Check,
  ChevronDown,
  Copy,
  Download,
  FileCheck2,
  Github,
  Globe,
  Linkedin,
  Loader2,
  Lock,
  MessageSquareLock,
  ShieldCheck,
  Sparkles,
  Terminal,
  Twitter,
  X,
  type LucideIcon,
} from 'lucide-react';
import { CyberBackground } from '../../components/CyberBackground';
import { cn } from '@/lib/utils';
import { useAuth } from '@/contexts/auth-context';
import { useSubscription } from '@/hooks/use-subscription';

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

/* --------------------------------------------------------------- download --- */

/**
 * Windows installer served from public/downloads (built by `npx tauri build`
 * in qguard-messaging — see Qguard_Wiki/Messaging_Installer_Distribution).
 * `version`, `sizeMb` and `sha256` are all rewritten by tools/release.ps1 on
 * each release, so they stay in lock-step with the binary actually published.
 */
export const MESSAGING_INSTALLER = {
  href: '/downloads/QGuard-Messaging-Setup.exe',
  version: '1.3.2',
  sizeMb: 6,
  requirements: 'Windows 10/11 · 64-bit',
  /**
   * SHA-256 of the exact file served from `href`, shown to users so they can
   * confirm their download was not altered or corrupted.
   *
   * Written automatically by tools/release.ps1 on every release - do NOT edit it
   * by hand and never let it drift from the published binary. A stale hash tells
   * an honest user their legitimate download was tampered with, which is worse
   * than publishing no hash at all.
   */
  sha256: 'BAC7B2B0BD5067EFC7269BE80671C2E73541A3D257F240AAB325FBDF2CA542E7',
};

/**
 * Plans shown in the download gate modal. Prices mirror the landing pricing
 * section; each choice routes into the existing auth-gated checkout → PayPal
 * flow (`/checkout?plan=&cycle=`).
 */
const DOWNLOAD_PLANS = [
  { name: 'Starter', priceMonthly: 3, priceYearly: 3, tagline: 'QGuard Messaging — Secure Chat & Quantum Vault' },
  { name: 'Basic', priceMonthly: 8, priceYearly: 5, tagline: '+ Quantum Readiness Assessment Engine, Migration Planner & Sandbox', featured: true },
  { name: 'Pro', priceMonthly: 30, priceYearly: 20, tagline: '+ Discovery, Operations, Ecosystem, Intelligence, PQAuth, Observability, Trust' },
  { name: 'Elite', priceMonthly: 199, priceYearly: 150, tagline: 'Everything — all modules' },
] as const;

/** Actually fetch the installer (only reached once the user is entitled). */
function startInstallerDownload() {
  const anchor = document.createElement('a');
  anchor.href = MESSAGING_INSTALLER.href;
  anchor.download = '';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}

/**
 * Plan-selection modal: shows every plan with a monthly/annual toggle and sends
 * the choice to the auth-gated checkout, which redirects to PayPal to pay before
 * access unlocks. Reused by the download gate and the Starter dashboard upgrade
 * button — copy is configurable so it reads correctly in each context.
 */
export function PlanGateModal({
  onClose,
  badge = 'Choose a plan to download',
  title = 'Subscribe to unlock QGuard Messaging',
  subtitle = 'An active subscription (Starter or above) is required to download and use the app.',
}: {
  onClose: () => void;
  badge?: string;
  title?: string;
  subtitle?: string;
}) {
  const [cycle, setCycle] = useState<'monthly' | 'annual'>('monthly');
  const choose = (plan: string) => {
    window.location.href = `/checkout?plan=${encodeURIComponent(plan)}&cycle=${cycle}`;
  };
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/70 p-4 backdrop-blur-sm" onClick={onClose}>
      <div
        className="relative max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl sm:p-8"
        onClick={(event) => event.stopPropagation()}
      >
        <button type="button" onClick={onClose} aria-label="Close" className="absolute right-4 top-4 rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-100 hover:text-slate-700">
          <X className="h-5 w-5" />
        </button>

        <div className="text-center">
          <div className="mx-auto inline-flex items-center gap-1.5 rounded-full border border-cyan-200 bg-cyan-50 px-3 py-1 text-[11px] font-black uppercase tracking-wide text-cyan-700">
            <Sparkles className="h-3 w-3" /> {badge}
          </div>
          <h2 className="mt-3 text-2xl font-black tracking-tight text-slate-900">{title}</h2>
          <p className="mt-1 text-sm text-slate-500">{subtitle}</p>
        </div>

        <div className="mt-5 flex justify-center">
          <div className="inline-flex rounded-full border border-slate-200 bg-slate-50 p-1" role="radiogroup" aria-label="Billing cycle">
            {(['monthly', 'annual'] as const).map((option) => (
              <button
                key={option}
                type="button"
                role="radio"
                aria-checked={cycle === option}
                onClick={() => setCycle(option)}
                className={cn(
                  'rounded-full px-4 py-1.5 text-xs font-bold capitalize transition',
                  cycle === option ? 'bg-blue-600 text-slate-50 shadow' : 'text-slate-500 hover:text-slate-800',
                )}
              >
                {option}{option === 'annual' ? ' · save' : ''}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-6 grid gap-3 sm:grid-cols-2">
          {DOWNLOAD_PLANS.map((plan) => {
            const price = cycle === 'annual' ? plan.priceYearly : plan.priceMonthly;
            const featured = 'featured' in plan && plan.featured;
            return (
              <div
                key={plan.name}
                className={cn(
                  'flex flex-col rounded-xl border p-5 transition',
                  featured ? 'border-blue-300 bg-blue-50/50 ring-1 ring-blue-200' : 'border-slate-200 bg-white',
                )}
              >
                <div className="flex items-baseline justify-between">
                  <span className="text-sm font-black uppercase tracking-wide text-slate-900">{plan.name}</span>
                  {featured && <span className="rounded-full bg-blue-600 px-2 py-0.5 text-[9px] font-black uppercase text-slate-50">Popular</span>}
                </div>
                <div className="mt-2 flex items-end gap-1">
                  <span className="text-3xl font-black text-slate-900">${price}</span>
                  <span className="pb-1 text-xs font-semibold text-slate-400">/mo{cycle === 'annual' ? ', billed yearly' : ''}</span>
                </div>
                <p className="mt-2 flex-1 text-xs leading-relaxed text-slate-500">{plan.tagline}</p>
                <button
                  type="button"
                  onClick={() => choose(plan.name)}
                  className={cn(
                    'mt-4 inline-flex items-center justify-center gap-1.5 rounded-lg px-4 py-2.5 text-xs font-black uppercase tracking-wide transition',
                    featured ? 'bg-blue-600 text-slate-50 hover:bg-blue-700' : 'border border-slate-300 text-slate-800 hover:border-blue-400 hover:text-blue-700',
                  )}
                >
                  Choose {plan.name} <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </div>
            );
          })}
        </div>

        <p className="mt-5 flex items-center justify-center gap-1.5 text-center text-[11px] text-slate-400">
          <Lock className="h-3 w-3" /> Secure checkout via PayPal. Your subscription unlocks the download instantly after payment.
        </p>
      </div>
    </div>
  );
}

/**
 * Primary "Download for Windows" CTA used on all QGuard Messaging pages.
 * Feature-gated: the installer only downloads for a signed-in user with an
 * active subscription. Guests are sent to login; signed-in users without a plan
 * see the plan-selection modal (→ PayPal).
 */
export function DownloadButton({ className }: { className?: string }) {
  const { user } = useAuth();
  const subscription = useSubscription();
  const navigate = useNavigate();
  const location = useLocation();
  const [planModalOpen, setPlanModalOpen] = useState(false);

  const gating = Boolean(user) && subscription.loading;

  const handleClick = () => {
    if (!user) {
      // Send guests to sign in / register, returning to this page afterwards.
      navigate(`/login?next=${encodeURIComponent(location.pathname)}`);
      return;
    }
    if (subscription.loading) return; // entitlement still resolving
    if (!subscription.isActive) {
      setPlanModalOpen(true);
      return;
    }
    startInstallerDownload();
  };

  return (
    <>
      <button
        type="button"
        onClick={handleClick}
        disabled={gating}
        title={`QGuard Messaging v${MESSAGING_INSTALLER.version} · ${MESSAGING_INSTALLER.requirements}`}
        className={cn(
          'group inline-flex cursor-pointer items-center justify-center gap-2 rounded-lg bg-blue-600 px-6 py-3 text-sm font-bold uppercase tracking-wide !text-white [&_*]:!text-white no-underline shadow-[0_12px_34px_rgba(37,99,235,0.35)] transition-all duration-200 hover:-translate-y-0.5 hover:bg-blue-700 active:translate-y-0 disabled:cursor-wait disabled:opacity-70',
          className,
        )}
      >
        {gating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4 transition-transform group-hover:translate-y-0.5" />}
        Download for Windows
        {/*
          Background written as an arbitrary rgb() value on purpose. The light-theme
          sheet in index.css matches `[class*="bg-white/"]` and repaints any such
          element as a near-opaque white glass panel - which, combined with this
          button's `[&_*]:!text-white`, rendered the version as white-on-white and
          made it unreadable. An arbitrary value carries the same 15-18% white wash
          without matching that selector. Do not "tidy" this back to bg-white/15.
        */}
        <span className="ml-1 hidden rounded bg-[rgb(255_255_255_/_0.18)] px-2 py-0.5 font-mono text-[10px] font-bold normal-case tracking-normal sm:inline">
          v{MESSAGING_INSTALLER.version} · ~{MESSAGING_INSTALLER.sizeMb} MB
        </span>
      </button>
      {planModalOpen && <PlanGateModal onClose={() => setPlanModalOpen(false)} />}
    </>
  );
}

/**
 * Copy-to-clipboard with a short "copied" acknowledgement, keyed by field id so
 * several buttons can share one hook. Falls back to a hidden textarea + execCommand
 * when the async Clipboard API is unavailable (non-secure origin, older browser).
 */
function useCopyField(resetMs = 2000) {
  const [copied, setCopied] = useState<string | null>(null);

  const copy = async (value: string, id: string) => {
    const ack = () => {
      setCopied(id);
      window.setTimeout(() => setCopied((current) => (current === id ? null : current)), resetMs);
    };
    try {
      await navigator.clipboard.writeText(value);
      ack();
      return;
    } catch {
      /* Clipboard API blocked - fall through to the legacy path. */
    }
    try {
      const scratch = document.createElement('textarea');
      scratch.value = value;
      scratch.setAttribute('readonly', '');
      scratch.style.position = 'fixed';
      scratch.style.opacity = '0';
      document.body.appendChild(scratch);
      scratch.select();
      document.execCommand('copy');
      scratch.remove();
      ack();
    } catch {
      setCopied(null); // leave the button in its idle state rather than lying
    }
  };

  return { copied, copy };
}

/** Small square copy button used inside the integrity panel. */
function CopyIconButton({ value, id, label, copied, onCopy }: {
  value: string;
  id: string;
  label: string;
  copied: string | null;
  onCopy: (value: string, id: string) => void;
}) {
  const done = copied === id;
  return (
    <button
      type="button"
      onClick={() => onCopy(value, id)}
      aria-label={done ? `${label} copied` : `Copy ${label}`}
      className={cn(
        'inline-flex shrink-0 items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[10px] font-bold uppercase tracking-wide transition-colors duration-150',
        done
          ? 'border-emerald-300 bg-emerald-50 text-emerald-700'
          : 'border-slate-300 bg-white text-slate-500 hover:border-cyan-400 hover:text-cyan-700',
      )}
    >
      {done ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
      {done ? 'Copied' : 'Copy'}
    </button>
  );
}

/**
 * Collapsible integrity panel shown beneath the download CTA.
 *
 * Purpose: let someone confirm the installer they received is byte-for-byte the
 * build we published, so a corrupted transfer, a bad mirror, or a file swapped
 * after download is visible rather than silent.
 *
 * Scope is stated honestly in the UI. A checksum published on the same origin as
 * the download proves INTEGRITY, not origin - anyone who could alter the binary
 * on this server could alter the hash beside it. The claim in the copy is
 * therefore limited to what the check actually establishes, and the panel points
 * at the updater signature, which is the authenticity check that does not depend
 * on trusting this page: its public key is compiled into the installed app, so a
 * forged update fails verification on the user's machine.
 */
export function InstallerIntegrity({
  className,
  defaultOpen = false,
}: {
  className?: string;
  /** Opt-in for contexts where verification is the point of the page. */
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const { copied, copy } = useCopyField();
  const { sha256, version, href } = MESSAGING_INSTALLER;
  const bodyId = useId();
  const fileName = href.split('/').pop() || 'QGuard-Messaging-Setup.exe';
  // Compare inside PowerShell rather than asking the reader to eyeball 64 hex
  // characters - people skim the middle of a hash and miss exactly the kind of
  // targeted substitution this check exists to catch. This prints True or False.
  // Deliberately free of backslash escapes: `.\` is not needed (Get-FileHash
  // resolves a bare relative path) and `\$` inside a template literal silently
  // suppresses interpolation, which is easy to ship without noticing.
  const verifyCommand = `(Get-FileHash ${fileName} -Algorithm SHA256).Hash -eq '${sha256}'`;

  return (
    <div
      className={cn(
        'max-w-xl overflow-hidden rounded-xl border border-slate-200 bg-white/85 shadow-[0_8px_28px_rgba(15,23,42,0.06)] backdrop-blur-sm',
        className,
      )}
    >
      {/*
        Collapsed by default so the hero stays readable. The trigger still names
        the checksum and the version, so the verification path is advertised even
        when shut - a security affordance nobody can see is not much of one.
      */}
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-controls={bodyId}
        className="flex w-full cursor-pointer items-center gap-2.5 px-3.5 py-2.5 text-left transition-colors duration-150 hover:bg-slate-50"
      >
        <FileCheck2 className="h-4 w-4 shrink-0 text-cyan-600" />
        <span className="font-mono text-[11px] font-black uppercase tracking-[0.16em] text-slate-600">
          Verify your download
        </span>
        <span className="hidden rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[9.5px] font-bold uppercase tracking-wide text-slate-500 sm:inline">
          SHA-256
        </span>
        <span className="ml-auto shrink-0 font-mono text-[10px] font-bold text-slate-400">v{version}</span>
        <ChevronDown
          className={cn(
            'h-4 w-4 shrink-0 text-slate-400 transition-transform duration-200',
            open && 'rotate-180',
          )}
        />
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="integrity-body"
            id={bodyId}
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: 'easeOut' }}
            className="overflow-hidden"
          >
            <div className="border-t border-slate-200 px-3.5 pb-4 pt-3">
              <p className="text-[12.5px] leading-relaxed text-slate-600">
                Check the installer you downloaded against the checksum we published for this build. A
                match means the file is byte-for-byte ours and was not altered or corrupted on its way
                to you.
              </p>

              <div className="mt-3.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[10px] font-black uppercase tracking-[0.18em] text-slate-400">
                    SHA-256
                  </span>
                  <CopyIconButton value={sha256} id="hash" label="checksum" copied={copied} onCopy={copy} />
                </div>
                <code className="mt-1.5 block break-all rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5 font-mono text-[11.5px] font-semibold leading-[1.7] tracking-tight text-slate-800 sm:text-[13px]">
                  {sha256}
                </code>
              </div>

              <div className="mt-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 font-mono text-[10px] font-black uppercase tracking-[0.18em] text-slate-400">
                    <Terminal className="h-3 w-3" />
                    Windows PowerShell &mdash; prints True if it matches
                  </span>
                  <CopyIconButton value={verifyCommand} id="cmd" label="command" copied={copied} onCopy={copy} />
                </div>
                <code className="mt-1.5 block whitespace-pre-wrap break-all rounded-lg border border-slate-900 bg-[#040810] px-3 py-2.5 font-mono text-[11.5px] font-semibold leading-relaxed text-cyan-300 sm:text-[12px]">
                  {verifyCommand}
                </code>
                <p className="mt-1.5 text-[11.5px] leading-relaxed text-slate-500">
                  Run it in the folder you saved the installer to (usually{' '}
                  <span className="font-mono font-semibold text-slate-600">Downloads</span>). A result of{' '}
                  <span className="font-mono font-bold text-emerald-600">True</span> means the file matches;{' '}
                  <span className="font-mono font-bold text-rose-600">False</span> means do not run it &mdash;
                  download again.
                </p>
              </div>

              <p className="mt-3 border-t border-slate-200 pt-3 text-[11.5px] leading-relaxed text-slate-500">
                This checksum confirms the file is intact. Because it is served from this same site, it
                is not by itself proof of origin &mdash; the stronger guarantee is that in-app updates are
                signed, and the verification key ships inside the installed application, so an update we
                did not sign is rejected on your machine.
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
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
