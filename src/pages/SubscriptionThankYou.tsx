import { Link, useSearchParams } from 'react-router-dom';
import { CheckCircle2, ArrowRight } from 'lucide-react';

/**
 * Landing page after a buyer approves a PayPal subscription
 * (application_context.return_url). The subscription is confirmed by PayPal and
 * recorded server-side via the PayPal webhook; this page just confirms success
 * and points the user to sign in / create their account.
 */
export default function SubscriptionThankYou() {
  const [params] = useSearchParams();
  const plan = params.get('plan') || 'your';
  const cycle = params.get('cycle') === 'yearly' ? 'yearly' : 'monthly';

  return (
    <div className="flex min-h-screen items-center justify-center bg-cyber-black px-6 py-24 text-white">
      <div className="w-full max-w-lg rounded-2xl border border-gold/20 bg-cyber-navy/40 p-10 text-center shadow-[0_30px_120px_rgba(0,0,0,0.5)] backdrop-blur-2xl">
        <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full border border-emerald-400/40 bg-emerald-400/10">
          <CheckCircle2 className="h-9 w-9 text-emerald-400" />
        </div>

        <h1 className="text-2xl font-black tracking-tight text-white md:text-3xl">
          Subscription confirmed
        </h1>
        <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
          Thank you — your <span className="font-semibold text-gold">{plan}</span> ({cycle}) subscription
          has been approved through PayPal. A receipt has been sent to your PayPal email.
        </p>

        <div className="mt-6 rounded-xl border border-white/10 bg-white/[0.04] p-4 text-left">
          <p className="font-mono text-[11px] uppercase tracking-widest text-gold">Activating your plan</p>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
            PayPal is confirming your first payment now. Your plan and renewal date will appear in your
            billing dashboard within a moment — this page does not need to stay open.
          </p>
        </div>

        <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
          <Link
            to="/dashboard/settings?tab=billing"
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-gold bg-gold px-6 py-3 font-mono text-xs font-bold uppercase tracking-wider text-cyber-black transition-colors hover:bg-gold/90"
          >
            View my subscription <ArrowRight className="h-4 w-4" />
          </Link>
          <Link
            to="/dashboard"
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/15 px-6 py-3 font-mono text-xs font-bold uppercase tracking-wider text-white transition-colors hover:border-white/40"
          >
            Go to dashboard
          </Link>
        </div>

        <Link
          to="/"
          className="mt-6 inline-block font-mono text-[11px] uppercase tracking-widest text-muted-foreground transition-colors hover:text-gold"
        >
          Back to home
        </Link>
      </div>
    </div>
  );
}
