'use client';

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { ChevronLeft, ChevronRight, ExternalLink, Search, X, type LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Panel } from '../_components/executive/primitives';
import { AMBER, CYAN, GREEN, RED, SLATE, VIOLET, fullTimestamp, relativeTime } from '../_components/intel/kit';
import type {
  EvidenceAge,
  IdentityQuantumClass,
  PQAuthCompatStatus,
  PQAuthEdgeConfidence,
  PQAuthGateStatus,
  PQAuthJobState,
  PQAuthStageStatus,
} from '@/types/pqauth-dashboard';

/**
 * PQAuth presentation primitives on top of the shared Intel kit.
 *
 * Every status here ships a glyph AND a word as well as a colour, so meaning
 * never rests on colour alone. Nothing in this file computes a number — all
 * values arrive from the server-side identity model.
 */

/* ------------------------------------------------------------------ */
/* Text ink                                                            */
/* ------------------------------------------------------------------ */

/*
 * The status hues are tuned for the dark navy shell. Used as TEXT on the light
 * theme they measured 1.3–2.8:1 (a WCAG audit of every PQAuth view) — and the
 * shell's light overrides only reach Tailwind classes, not inline colours.
 * `ink(hex)` resolves to a CSS variable that the light theme redefines with a
 * darker, ≥4.5:1 shade, falling back to the original hex on dark. Borders and
 * tinted washes keep the raw hex: the contrast rule is about text.
 */
const INK_NAME: Record<string, string> = {
  [GREEN]: 'green', [CYAN]: 'cyan', [AMBER]: 'amber', [RED]: 'red', [SLATE]: 'slate', [VIOLET]: 'violet', '#fb923c': 'orange',
};

export function ink(hex: string): string {
  const name = INK_NAME[hex];
  return name ? `var(--pq-ink-${name}, ${hex})` : hex;
}

/** Rendered once by the page shell. */
export function PQAuthInk() {
  return (
    <style>{`
      .qg-theme-light .pqauth { --pq-ink-green:#065f46; --pq-ink-cyan:#155e75; --pq-ink-amber:#92400e; --pq-ink-red:#b91c1c; --pq-ink-slate:#475569; --pq-ink-violet:#5b21b6; --pq-ink-orange:#9a3412; }
      /* The shell's light hue overrides measured 3.6–4.3:1 on the beige surface; PQAuth uses the same ≥4.5:1 inks. */
      .qg-theme-light .pqauth .text-cyan-200, .qg-theme-light .pqauth .text-cyan-300 { color: #155e75 !important; }
      .qg-theme-light .pqauth .text-emerald-200, .qg-theme-light .pqauth .text-emerald-300 { color: #065f46 !important; }
      .qg-theme-light .pqauth .text-amber-200, .qg-theme-light .pqauth .text-amber-300 { color: #92400e !important; }
      .qg-theme-light .pqauth .text-red-200, .qg-theme-light .pqauth .text-red-300 { color: #b91c1c !important; }
      .qg-theme-light .pqauth .text-violet-200, .qg-theme-light .pqauth .text-violet-300 { color: #5b21b6 !important; }
    `}</style>
  );
}

/* ------------------------------------------------------------------ */
/* Status vocabularies                                                 */
/* ------------------------------------------------------------------ */

type Meta = { label: string; hex: string; glyph: string; hint: string };

export const CLASS_META: Record<IdentityQuantumClass, Meta> = {
  safe: { label: 'Post-quantum', hex: GREEN, glyph: '✓', hint: 'A NIST post-quantum primitive (FIPS 203 / 204 / 205), or symmetric at a quantum-safe size.' },
  hybrid: { label: 'Hybrid', hex: CYAN, glyph: '◐', hint: 'Classical and post-quantum combined — safe while either holds.' },
  vulnerable: { label: 'Quantum-vulnerable', hex: RED, glyph: '●', hint: "Broken by Shor's algorithm (RSA, ECDSA, EdDSA, ECDH) or flawed today." },
  unknown: { label: 'Undetermined', hex: SLATE, glyph: '?', hint: 'The evidence does not state enough to classify. Undetermined is never treated as safe.' },
};

export const COMPAT_META: Record<PQAuthCompatStatus, Meta> = {
  supported: { label: 'Supported', hex: GREEN, glyph: '✓', hint: 'Evidence shows a post-quantum-ready configuration.' },
  conditional: { label: 'Conditional', hex: AMBER, glyph: '◐', hint: 'Works only if a stated condition holds (e.g. relying parties accept a hybrid format).' },
  unsupported: { label: 'Unsupported', hex: RED, glyph: '✕', hint: 'Evidence shows a configuration that is not post-quantum ready.' },
  'not-verified': { label: 'Not verified', hex: SLATE, glyph: '?', hint: 'No evidence has been observed. Not verified is not a pass.' },
  'not-applicable': { label: 'Not applicable', hex: SLATE, glyph: '–', hint: 'The capability is not used by this provider.' },
};

export const CONFIDENCE_META: Record<PQAuthEdgeConfidence, Meta & { dash: string }> = {
  observed: { label: 'Observed', hex: CYAN, glyph: '━', dash: '', hint: 'Read directly from a protocol document or a recorded foreign key.' },
  declared: { label: 'Declared', hex: VIOLET, glyph: '╍', dash: '7 4', hint: 'A document published by one party names the other.' },
  inferred: { label: 'Inferred', hex: AMBER, glyph: '┄', dash: '2 4', hint: 'Recorded without direct protocol evidence.' },
  unresolved: { label: 'Unresolved', hex: RED, glyph: '╳', dash: '3 3', hint: 'A recorded relationship whose endpoint is not in the inventory.' },
};

export const JOB_META: Record<PQAuthJobState, Meta> = {
  proposed: { label: 'Proposed', hex: SLATE, glyph: '○', hint: 'Planned; not yet approved for execution.' },
  queued: { label: 'Approved · queued', hex: CYAN, glyph: '◔', hint: 'Approved and waiting for the executor.' },
  executing: { label: 'Executing', hex: VIOLET, glyph: '◑', hint: 'The executor reports it running.' },
  completed: { label: 'Reported complete', hex: AMBER, glyph: '◕', hint: 'The executor says it finished. Not yet confirmed by re-discovery.' },
  validated: { label: 'Validated', hex: GREEN, glyph: '✓', hint: 'Completed AND a later discovery observed the target posture.' },
  failed: { label: 'Failed', hex: RED, glyph: '✕', hint: 'Failed, cancelled, blocked or rolled back.' },
};

export const GATE_META: Record<PQAuthGateStatus | PQAuthStageStatus, Meta> = {
  complete: { label: 'Complete', hex: GREEN, glyph: '✓', hint: 'Evidence satisfies this step.' },
  'in-progress': { label: 'In progress', hex: CYAN, glyph: '◑', hint: 'Partly satisfied by evidence.' },
  blocked: { label: 'Blocked', hex: RED, glyph: '✕', hint: 'Evidence shows a failure that must be resolved.' },
  attention: { label: 'Needs attention', hex: AMBER, glyph: '!', hint: 'Ran, but some results need review.' },
  pending: { label: 'Pending', hex: CYAN, glyph: '◔', hint: 'Waiting on an earlier step.' },
  'not-started': { label: 'Not started', hex: SLATE, glyph: '○', hint: 'No evidence yet.' },
};

export function Badge({ meta, label, className }: { meta: Meta; label?: string; className?: string }) {
  return (
    <span
      title={meta.hint}
      className={cn('inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[9.5px] font-black uppercase tracking-wider', className)}
      style={{ borderColor: `${meta.hex}55`, backgroundColor: `${meta.hex}16`, color: ink(meta.hex) }}
    >
      <span aria-hidden="true">{meta.glyph}</span>
      {label ?? meta.label}
    </span>
  );
}

export const ClassBadge = ({ value, label }: { value: IdentityQuantumClass; label?: string }) => <Badge meta={CLASS_META[value]} label={label} />;
export const CompatBadge = ({ value }: { value: PQAuthCompatStatus }) => <Badge meta={COMPAT_META[value]} />;
export const JobBadge = ({ value }: { value: PQAuthJobState }) => <Badge meta={JOB_META[value]} />;
export const GateBadge = ({ value }: { value: PQAuthGateStatus | PQAuthStageStatus }) => <Badge meta={GATE_META[value]} />;

export function AgeBadge({ age, at }: { age: EvidenceAge; at: string | null }) {
  const meta: Meta = age === 'fresh'
    ? { label: `Seen ${relativeTime(at)}`, hex: GREEN, glyph: '●', hint: `Observed ${fullTimestamp(at)}` }
    : age === 'stale'
      ? { label: `Stale · ${relativeTime(at)}`, hex: AMBER, glyph: '◐', hint: `Last observed ${fullTimestamp(at)} — older than 7 days` }
      : { label: 'Never observed', hex: SLATE, glyph: '○', hint: 'No observation recorded' };
  return <Badge meta={meta} />;
}

/* ------------------------------------------------------------------ */
/* Layout                                                              */
/* ------------------------------------------------------------------ */

export function Card({
  title, icon: Icon, meta, action, children, className, id, padded = true,
}: {
  title: string;
  icon: LucideIcon;
  meta?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  id?: string;
  padded?: boolean;
}) {
  return (
    <Panel className={cn(padded ? 'p-4 lg:p-5' : 'p-0', className)}>
      <section aria-labelledby={id}>
        <div className={cn('mb-3 flex flex-wrap items-center justify-between gap-2', !padded && 'px-4 pt-4 lg:px-5 lg:pt-5')}>
          <h2 id={id} className="flex items-center gap-2 text-[11px] font-black uppercase tracking-[0.18em] text-white/70">
            <Icon className="h-3.5 w-3.5 text-cyan-300" aria-hidden="true" />
            {title}
            {meta ? <span className="ml-1 font-mono text-[10px] font-medium normal-case tracking-normal text-white/50">{meta}</span> : null}
          </h2>
          {action}
        </div>
        {children}
      </section>
    </Panel>
  );
}

/** Section entrance. Honours prefers-reduced-motion; never loops. */
export function Reveal({ children, delay = 0, className }: { children: ReactNode; delay?: number; className?: string }) {
  const reduce = useReducedMotion();
  if (reduce) return <div className={className}>{children}</div>;
  return (
    <motion.div className={className} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.32, delay, ease: 'easeOut' }}>
      {children}
    </motion.div>
  );
}

export function StatLink({
  label, value, detail, color, to, footnote, icon: Icon,
}: {
  label: string;
  value: string;
  detail: string;
  color: string;
  to: string;
  footnote?: string;
  icon: LucideIcon;
}) {
  return (
    <Link
      to={to}
      className="qg-executive-panel group relative block overflow-hidden rounded-xl p-4 text-white no-underline outline-none transition hover:-translate-y-0.5 focus-visible:ring-2 focus-visible:ring-cyan-300/70 motion-reduce:transition-none motion-reduce:hover:translate-y-0"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="text-[9px] font-black uppercase tracking-[0.16em] text-white/45">{label}</div>
        <Icon className="h-4 w-4 shrink-0 opacity-70" style={{ color: ink(color) }} aria-hidden="true" />
      </div>
      <div className="mt-2 font-mono text-[28px] font-black leading-none tracking-tight" style={{ color: ink(color) }}>{value}</div>
      <div className="mt-2 text-[10.5px] leading-snug text-white/50">{detail}</div>
      {footnote ? <div className="mt-1.5 text-[9.5px] leading-snug text-white/50">{footnote}</div> : null}
      <span className="mt-2 inline-flex items-center gap-1 text-[9px] font-black uppercase tracking-wider text-cyan-300 group-hover:text-cyan-200">
        Open <ChevronRight className="h-3 w-3" aria-hidden="true" />
      </span>
    </Link>
  );
}

export function RouteLink({ to, children, tone = 'neutral' }: { to: string; children: ReactNode; tone?: 'neutral' | 'ghost' }) {
  return (
    <Link
      to={to}
      className={cn(
        'inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider no-underline transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
        tone === 'neutral' ? 'border border-cyan-400/40 bg-cyan-500/10 text-cyan-200 hover:bg-cyan-500/20' : 'border border-white/12 bg-white/[0.04] text-white/60 hover:bg-white/[0.08]',
      )}
    >
      {children}
      <ChevronRight className="h-3 w-3" aria-hidden="true" />
    </Link>
  );
}

/** A public evidence URL (discovery document, JWKS). Opens in a new tab without a referrer. */
export function EvidenceUrl({ url, className }: { url: string | null; className?: string }) {
  if (!url) return <span className="text-white/50">Not recorded</span>;
  const safe = /^https?:\/\//i.test(url);
  if (!safe) return <span className={cn('break-all font-mono text-[10.5px] text-white/55', className)}>{url}</span>;
  return (
    <a href={url} target="_blank" rel="noopener noreferrer" title={url} className={cn('inline-flex max-w-full items-center gap-1 break-all font-mono text-[10.5px] text-cyan-300 no-underline hover:underline', className)}>
      <span className="truncate">{url}</span>
      <ExternalLink className="h-3 w-3 shrink-0" aria-hidden="true" />
    </a>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[120px_minmax(0,1fr)] gap-3 border-b border-white/[0.06] py-2 last:border-b-0">
      <dt className="text-[9.5px] font-black uppercase tracking-[0.14em] text-white/50">{label}</dt>
      <dd className="min-w-0 text-[11.5px] leading-relaxed text-white/75">{children}</dd>
    </div>
  );
}

export function Notice({ tone = 'info', icon: Icon, title, children }: { tone?: 'info' | 'warning' | 'simulation' | 'critical'; icon: LucideIcon; title: string; children?: ReactNode }) {
  const tones = {
    info: 'border-cyan-400/30 bg-cyan-500/[0.06] text-cyan-200',
    warning: 'border-amber-400/35 bg-amber-500/[0.07] text-amber-200',
    simulation: 'border-violet-400/45 border-dashed bg-violet-500/[0.07] text-violet-200',
    critical: 'border-red-400/35 bg-red-500/[0.07] text-red-200',
  } as const;
  return (
    <div role={tone === 'critical' ? 'alert' : 'note'} className={cn('flex gap-3 rounded-xl border p-3.5', tones[tone])}>
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <div className="min-w-0">
        <div className="text-[11.5px] font-black">{title}</div>
        {children ? <div className="mt-1 text-[11px] leading-relaxed text-white/60">{children}</div> : null}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Search, filters, pagination                                         */
/* ------------------------------------------------------------------ */

export function SearchBox({ value, onChange, placeholder, label }: { value: string; onChange: (v: string) => void; placeholder: string; label: string }) {
  return (
    <label className="relative block min-w-[200px] flex-1">
      <span className="sr-only">{label}</span>
      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/50" aria-hidden="true" />
      <input
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-8 w-full rounded-lg border border-white/12 bg-black/25 pl-8 pr-3 text-[11.5px] text-white outline-none transition placeholder:text-white/50 focus:border-cyan-400/50 focus-visible:ring-2 focus-visible:ring-cyan-300/40"
      />
    </label>
  );
}

// T is inferred from `value` only — option literals would otherwise widen it to string.
export function FilterChips<T extends string>({ options, value, onChange, label }: { options: Array<{ key: NoInfer<T>; label: string; count?: number }>; value: T; onChange: (key: NoInfer<T>) => void; label: string }) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-1.5">
      {options.map((option) => (
        <button
          key={option.key}
          type="button"
          aria-pressed={value === option.key}
          onClick={() => onChange(option.key)}
          className={cn(
            'rounded-full border px-2.5 py-1 text-[9.5px] font-black uppercase tracking-wider transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70',
            value === option.key ? 'border-cyan-400/55 bg-cyan-500/15 text-cyan-200' : 'border-white/12 bg-white/[0.03] text-white/50 hover:text-white/75',
          )}
        >
          {option.label}
          {option.count !== undefined ? <span className="ml-1 font-mono text-white/50">{option.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

export function usePaged<T>(items: T[], pageSize = 10) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(items.length / pageSize));
  useEffect(() => {
    if (page > pages - 1) setPage(0);
  }, [page, pages]);
  const slice = useMemo(() => items.slice(page * pageSize, page * pageSize + pageSize), [items, page, pageSize]);
  return { slice, page, pages, setPage, total: items.length };
}

export function Pager({ page, pages, total, setPage }: { page: number; pages: number; total: number; setPage: (n: number) => void }) {
  if (pages <= 1) return null;
  return (
    <nav aria-label="Pagination" className="mt-3 flex items-center justify-between gap-2 text-[10.5px] text-white/45">
      <span>Page {page + 1} of {pages} · {total.toLocaleString('en-US')} rows</span>
      <span className="flex gap-1.5">
        <button type="button" onClick={() => setPage(Math.max(0, page - 1))} disabled={page === 0} aria-label="Previous page" className="grid h-7 w-7 place-items-center rounded-md border border-white/12 bg-white/[0.04] disabled:opacity-30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
          <ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
        <button type="button" onClick={() => setPage(Math.min(pages - 1, page + 1))} disabled={page >= pages - 1} aria-label="Next page" className="grid h-7 w-7 place-items-center rounded-md border border-white/12 bg-white/[0.04] disabled:opacity-30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
          <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </span>
    </nav>
  );
}

/* ------------------------------------------------------------------ */
/* Detail drawer                                                       */
/* ------------------------------------------------------------------ */

/** Accessible side panel: Esc closes, focus moves in on open and back on close. */
export function DetailDrawer({ open, onClose, title, subtitle, children }: { open: boolean; onClose: () => void; title: string; subtitle?: ReactNode; children: ReactNode }) {
  const closeRef = useRef<HTMLButtonElement | null>(null);
  const reduce = useReducedMotion();
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
      previous?.focus?.();
    };
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[80] flex justify-end">
      <button type="button" aria-label="Close details" onClick={onClose} className="absolute inset-0 bg-black/55 backdrop-blur-[2px]" />
      <motion.aside
        role="dialog"
        aria-modal="true"
        aria-label={title}
        initial={reduce ? false : { x: 32, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        transition={{ duration: 0.22, ease: 'easeOut' }}
        className="intel-shell relative h-full w-full max-w-[560px] overflow-y-auto border-l border-white/10 bg-[#0b1424] p-5 shadow-2xl"
      >
        <div className="mb-4 flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="break-words text-[15px] font-black text-white">{title}</h2>
            {subtitle ? <div className="mt-1 text-[11px] text-white/45">{subtitle}</div> : null}
          </div>
          <button ref={closeRef} type="button" onClick={onClose} aria-label="Close" className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-white/12 bg-white/[0.04] text-white/60 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
        {children}
      </motion.aside>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Formatting                                                          */
/* ------------------------------------------------------------------ */

export function fmtBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  const sign = value < 0 ? '−' : '';
  const abs = Math.abs(value);
  if (abs >= 1024) return `${sign}${(abs / 1024).toFixed(abs >= 10240 ? 0 : 1)} KB`;
  return `${sign}${abs.toLocaleString('en-US')} B`;
}

export const PROTOCOL_LABEL: Record<string, string> = { oidc: 'OpenID Connect', oauth2: 'OAuth 2.0', saml2: 'SAML 2.0' };

export function th(className?: string) {
  return cn('px-3 py-2 text-left text-[9px] font-black uppercase tracking-[0.14em] text-white/50', className);
}
export function td(className?: string) {
  return cn('px-3 py-2.5 align-top text-[11.5px] text-white/70', className);
}
