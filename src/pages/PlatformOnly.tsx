/**
 * Website edition catch-all (src/PublicApp.tsx).
 *
 * The public website ships the marketing pages and the free Web assessment
 * only. Sign-in, the dashboard, checkout and the Agent Center belong to the
 * full platform, which is not part of this build. Every link to them lands
 * here — and so does any unknown path — so a visitor gets a clear answer and a
 * next step instead of a blank page.
 */
import { Link, useLocation } from 'react-router-dom';
import { ArrowRight, Mail, Radar } from 'lucide-react';
import { GhostButton, GoldButton, Reveal, SolutionLayout } from './_solution-shared';
import { FOOTER_GROUPS, NAV_LINKS } from './_legal-shared';
import { SITE } from '@/lib/site-identity';

/** Paths that are platform features, as opposed to a mistyped address. */
const PLATFORM_PREFIXES = [
  '/login',
  '/register',
  '/auth',
  '/authentication',
  '/reset-password',
  '/dashboard',
  '/checkout',
  '/subscription',
  '/downloads',
  '/agent-center',
  '/vault',
  '/verify-report',
  '/verify-certificate',
];

export default function PlatformOnly() {
  const { pathname } = useLocation();
  const isPlatformPath = PLATFORM_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));

  return (
    <SolutionLayout
      homePath="/"
      brandTitle="QGuard Helix"
      brandSubtitle="Platform"
      brandTagline="Post-Quantum Security Platform"
      navLinks={NAV_LINKS}
      footerBlurb={
        <>
          Questions go to{' '}
          <a href={`mailto:${SITE.salesEmail}`} className="font-semibold text-gold no-underline hover:underline">
            {SITE.salesEmail}
          </a>
          .
        </>
      }
      footerGroups={FOOTER_GROUPS}
    >
      <section className="relative px-6 pb-24 pt-20 md:pt-28">
        <div className="mx-auto max-w-[48rem] text-center">
          <Reveal>
            <p className="font-mono text-[10px] font-bold uppercase tracking-[0.35em] text-gold">
              {isPlatformPath ? 'Qguard Helix Platform' : 'Page not found'}
            </p>
            <h1 className="mt-4 text-3xl font-black tracking-tight text-slate-900 md:text-5xl">
              {isPlatformPath ? 'This part of Qguard Helix is not on the website' : 'We could not find that page'}
            </h1>
            <p className="mx-auto mt-5 max-w-[36rem] text-[15px] leading-relaxed text-slate-600">
              {isPlatformPath
                ? 'Sign-in, the dashboard and the full discovery, migration and governance modules are available to customers directly. Run the free public assessment now, or talk to us about access for your organization.'
                : 'The address may be mistyped, or the page may have moved. You can start from the homepage or run the free public assessment.'}
            </p>
          </Reveal>

          <Reveal delay={0.08}>
            <div className="mt-10 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <GoldButton to="/public-scan">
                <Radar className="h-4 w-4" />
                Run a free public scan
              </GoldButton>
              <GhostButton href={`mailto:${SITE.salesEmail}?subject=${encodeURIComponent('Qguard Helix platform access')}`}>
                <Mail className="h-4 w-4" />
                Contact us
              </GhostButton>
              <Link
                to="/"
                className="inline-flex items-center gap-1.5 px-3 py-3 text-sm font-semibold text-slate-600 no-underline hover:text-slate-900"
              >
                Homepage
                <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          </Reveal>
        </div>
      </section>
    </SolutionLayout>
  );
}
