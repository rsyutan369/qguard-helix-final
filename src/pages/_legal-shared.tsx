/**
 * Shared chrome for the public legal surfaces (/terms, /privacy, /refund),
 * whose navigation /contact reuses too.
 *
 * Reuses the marketing design language via SolutionLayout so the legal pages
 * are unmistakably part of the same product, then adds what a policy document
 * needs and a marketing page does not: a stable section anchor per clause, a
 * sticky table of contents, and a plain-language summary box at the top.
 *
 * Every party name, address, email, jurisdiction and date comes from
 * src/lib/site-identity.ts — never hardcode them in a document.
 */
import React from 'react';
import { Link } from 'react-router-dom';
import { SolutionLayout, Reveal } from './_solution-shared';
import { SITE, LEGAL_PAGES, formatLegalDate } from '@/lib/site-identity';

export type LegalSection = {
  /** Stable anchor id — keep it forever once published; people link to it. */
  id: string;
  heading: string;
  body: React.ReactNode;
};

export const NAV_LINKS = [
  { label: 'Platform', href: '/qguard-helix-features' },
  { label: 'Downloads', href: '/downloads' },
  { label: 'Docs', href: '/docs' },
];

/** Inline paragraph + list primitives so every document reads identically. */
export const P: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <p className="mb-4 text-[15px] leading-relaxed text-slate-600 last:mb-0">{children}</p>
);

export const UL: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <ul className="mb-4 space-y-2 last:mb-0">{children}</ul>
);

export const LI: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <li className="flex gap-3 text-[15px] leading-relaxed text-slate-600">
    <span className="mt-[9px] h-1.5 w-1.5 shrink-0 rounded-full bg-gold" />
    <span className="min-w-0">{children}</span>
  </li>
);

export const Term: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <strong className="font-semibold text-slate-900">{children}</strong>
);

/** Callout for the clauses a reader must not miss (zero-knowledge, refunds). */
export const Notice: React.FC<{ tone?: 'gold' | 'cyan'; title: string; children: React.ReactNode }> = ({
  tone = 'gold',
  title,
  children,
}) => (
  <div
    className={`mb-4 rounded-xl border p-4 last:mb-0 ${
      tone === 'gold' ? 'border-gold/30 bg-gold/[0.06]' : 'border-cyan-300/50 bg-cyan-50/70'
    }`}
  >
    <p className="mb-1.5 font-mono text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">{title}</p>
    <div className="text-[15px] leading-relaxed text-slate-700">{children}</div>
  </div>
);

export function LegalLayout({
  title,
  kicker,
  summary,
  sections,
}: {
  title: string;
  kicker: string;
  /** 2-4 plain-language bullets: what this document actually means for them. */
  summary: string[];
  sections: LegalSection[];
}) {
  return (
    <SolutionLayout
      homePath="/"
      brandTitle="QGuard Helix"
      brandSubtitle="Legal"
      navLinks={NAV_LINKS}
    >
      <section className="relative px-6 pb-8 pt-16 md:pt-24">
        <div className="mx-auto max-w-[72rem]">
          <Reveal>
            <p className="font-mono text-[10px] font-bold uppercase tracking-[0.35em] text-gold">{kicker}</p>
            <h1 className="mt-4 text-3xl font-black tracking-tight text-slate-900 md:text-5xl">{title}</h1>
            <div className="mt-4 flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-slate-500">
              <span>
                Effective <Term>{formatLegalDate()}</Term>
              </span>
              <span>
                Provider <Term>{SITE.providerName}</Term>
              </span>
              <span>
                {SITE.city}, {SITE.province}, {SITE.country}
              </span>
            </div>
          </Reveal>

          <Reveal delay={0.08}>
            <div className="mt-8 rounded-2xl border border-slate-200 bg-white/80 p-6 backdrop-blur-xl">
              <p className="mb-3 font-mono text-[10px] font-bold uppercase tracking-[0.25em] text-slate-500">
                In plain language
              </p>
              <ul className="space-y-2">
                {summary.map((line) => (
                  <li key={line} className="flex gap-3 text-[15px] leading-relaxed text-slate-700">
                    <span className="mt-[9px] h-1.5 w-1.5 shrink-0 rounded-full bg-gold" />
                    <span className="min-w-0">{line}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-4 text-xs leading-relaxed text-slate-400">
                This summary is for orientation only. The numbered sections below are the binding text.
              </p>
            </div>
          </Reveal>
        </div>
      </section>

      <section className="relative px-6 pb-24">
        <div className="mx-auto grid max-w-[72rem] gap-10 lg:grid-cols-[16rem_minmax(0,1fr)]">
          <aside className="lg:sticky lg:top-24 lg:self-start">
            <nav aria-label="Document sections" className="rounded-2xl border border-slate-200 bg-white/80 p-5 backdrop-blur-xl">
              <p className="mb-3 font-mono text-[10px] font-bold uppercase tracking-[0.25em] text-slate-500">Contents</p>
              <ol className="space-y-2">
                {sections.map((section, index) => (
                  <li key={section.id}>
                    <a
                      href={`#${section.id}`}
                      className="flex gap-2 text-[13px] leading-snug text-slate-600 no-underline transition-colors hover:text-gold"
                    >
                      <span className="font-mono text-[11px] text-slate-400">{String(index + 1).padStart(2, '0')}</span>
                      <span className="min-w-0">{section.heading}</span>
                    </a>
                  </li>
                ))}
              </ol>
              <div className="mt-5 border-t border-slate-200 pt-4">
                <p className="mb-2 font-mono text-[10px] font-bold uppercase tracking-[0.25em] text-slate-500">Related</p>
                <ul className="space-y-1.5">
                  {LEGAL_PAGES.map((page) => (
                    <li key={page.path}>
                      <Link to={page.path} className="text-[13px] text-slate-600 no-underline transition-colors hover:text-gold">
                        {page.label}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            </nav>
          </aside>

          <div className="min-w-0 space-y-8">
            {sections.map((section, index) => (
              <Reveal key={section.id} delay={Math.min(index * 0.03, 0.2)}>
                <article
                  id={section.id}
                  className="scroll-mt-24 rounded-2xl border border-slate-200 bg-white/80 p-6 backdrop-blur-xl md:p-8"
                >
                  <h2 className="mb-4 flex items-baseline gap-3 text-xl font-black tracking-tight text-slate-900">
                    <span className="font-mono text-sm text-gold">{String(index + 1).padStart(2, '0')}</span>
                    {section.heading}
                  </h2>
                  {section.body}
                </article>
              </Reveal>
            ))}

            <div className="rounded-2xl border border-slate-200 bg-white/80 p-6 text-sm text-slate-600 backdrop-blur-xl">
              Questions about this document? Email{' '}
              <a href={`mailto:${SITE.supportEmail}`} className="font-semibold text-gold no-underline hover:underline">
                {SITE.supportEmail}
              </a>{' '}
              or use the{' '}
              <Link to="/contact" className="font-semibold text-gold no-underline hover:underline">
                contact page
              </Link>
              . We aim to respond within {SITE.supportResponseTarget}.
            </div>
          </div>
        </div>
      </section>
    </SolutionLayout>
  );
}
