import { useEffect, useRef, useState } from 'react';
import { Link, useLocation, useSearchParams } from 'react-router-dom';
import { CheckCircle2, ArrowRight, Loader2, Clock, AlertTriangle } from 'lucide-react';
import { useAuth } from '@/contexts/auth-context';
import { billingApiUrl } from '@/lib/billing/billing-api';

/**
 * Landing page after a buyer approves a PayPal subscription
 * (application_context.return_url). PayPal appends `subscription_id`; this page
 * asks the billing service to confirm it straight from PayPal
 * (POST /api/v1/paypal/confirm), so the plan unlocks within seconds even when
 * the webhook is delayed. Both paths write the same row, so whichever lands
 * first wins. Success is only announced once PayPal reports the subscription
 * ACTIVE — opening this URL without paying shows nothing as confirmed.
 */

const POLL_MS = 3_000;
const WATCH_MS = 60_000;
const PAYPAL_SUBSCRIPTION_ID = /^I-[A-Z0-9]{6,32}$/;

type Phase =
  | { kind: 'confirming' }
  | { kind: 'active'; plan: string }
  | { kind: 'pending' }
  | { kind: 'signin' }
  | { kind: 'missing' }
  | { kind: 'error'; message: string };

export default function SubscriptionThankYou() {
  const [params] = useSearchParams();
  const location = useLocation();
  const { session, loading } = useAuth();
  const plan = params.get('plan') || 'your';
  const cycle = params.get('cycle') === 'yearly' ? 'yearly' : 'monthly';
  const subscriptionId = params.get('subscription_id') || '';
  const [phase, setPhase] = useState<Phase>({ kind: 'confirming' });

  const tokenRef = useRef<string | null>(null);
  tokenRef.current = session?.access_token ?? null;
  const signedIn = Boolean(session?.access_token);

  useEffect(() => {
    if (!PAYPAL_SUBSCRIPTION_ID.test(subscriptionId)) {
      setPhase({ kind: 'missing' });
      return;
    }
    if (loading) return;
    if (!signedIn) {
      setPhase({ kind: 'signin' });
      return;
    }

    let stopped = false;
    let timer: number | undefined;
    const startedAt = Date.now();

    const attempt = async () => {
      if (stopped) return;
      try {
        const response = await fetch(billingApiUrl('/api/v1/paypal/confirm'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenRef.current}` },
          body: JSON.stringify({ subscriptionId }),
        });
        const payload = await response.json().catch(() => ({}));
        if (stopped) return;
        if (response.ok && payload?.data?.activated) {
          setPhase({ kind: 'active', plan: String(payload.data.plan || plan) });
          return;
        }
        const status = String(payload?.data?.status || '');
        if (response.ok && ['cancelled', 'expired', 'suspended'].includes(status)) {
          setPhase({ kind: 'error', message: `PayPal reports this subscription as ${status}. No plan was activated.` });
          return;
        }
        // 401/403/400 will not change by retrying.
        if (response.status === 401 || response.status === 403 || response.status === 400) {
          setPhase({ kind: 'error', message: payload?.error?.message || 'This subscription could not be confirmed for your account.' });
          return;
        }
      } catch {
        // Offline or PayPal busy: keep trying until the deadline.
      }
      if (Date.now() - startedAt >= WATCH_MS) {
        setPhase({ kind: 'pending' });
        return;
      }
      timer = window.setTimeout(attempt, POLL_MS);
    };

    setPhase({ kind: 'confirming' });
    void attempt();
    return () => {
      stopped = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [subscriptionId, loading, signedIn, plan]);

  const loginHref = `/login?next=${encodeURIComponent(`${location.pathname}${location.search}`)}`;

  const view = (() => {
    switch (phase.kind) {
      case 'active':
        return {
          icon: <CheckCircle2 className="h-9 w-9 text-emerald-400" />,
          ring: 'border-emerald-400/40 bg-emerald-400/10',
          title: 'Subscription active',
          body: (
            <>
              Thank you — PayPal confirmed your <span className="font-semibold text-gold">{phase.plan}</span> ({cycle})
              subscription and your plan is now active. PayPal emails the receipt to your PayPal address.
            </>
          ),
        };
      case 'pending':
        return {
          icon: <Clock className="h-9 w-9 text-gold" />,
          ring: 'border-gold/40 bg-gold/10',
          title: 'Waiting for PayPal',
          body: (
            <>
              PayPal has not confirmed the payment for your <span className="font-semibold text-gold">{plan}</span> plan
              yet. That usually takes under a minute. Your plan appears in your billing settings automatically once it
              does — this page does not need to stay open.
            </>
          ),
        };
      case 'signin':
        return {
          icon: <Clock className="h-9 w-9 text-gold" />,
          ring: 'border-gold/40 bg-gold/10',
          title: 'Sign in to finish',
          body: <>Sign in with the account you subscribed from, and we will confirm the subscription with PayPal.</>,
        };
      case 'missing':
        return {
          icon: <AlertTriangle className="h-9 w-9 text-gold" />,
          ring: 'border-gold/40 bg-gold/10',
          title: 'No subscription to confirm',
          body: (
            <>
              This link does not carry a PayPal subscription reference. If you completed checkout, your plan appears in
              your billing settings within a few minutes.
            </>
          ),
        };
      case 'error':
        return {
          icon: <AlertTriangle className="h-9 w-9 text-red-400" />,
          ring: 'border-red-400/40 bg-red-400/10',
          title: 'Subscription not confirmed',
          body: <>{phase.message} Contact support if PayPal charged you.</>,
        };
      default:
        return {
          icon: <Loader2 className="h-9 w-9 animate-spin text-gold" />,
          ring: 'border-gold/40 bg-gold/10',
          title: 'Confirming with PayPal…',
          body: (
            <>
              Checking your <span className="font-semibold text-gold">{plan}</span> ({cycle}) subscription with PayPal.
              This takes a few seconds.
            </>
          ),
        };
    }
  })();

  return (
    <div className="flex min-h-screen items-center justify-center bg-cyber-black px-6 py-24 text-white">
      <div className="w-full max-w-lg rounded-2xl border border-gold/20 bg-cyber-navy/40 p-10 text-center shadow-[0_30px_120px_rgba(0,0,0,0.5)] backdrop-blur-2xl">
        <div className={`mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full border ${view.ring}`}>
          {view.icon}
        </div>

        <h1 className="text-2xl font-black tracking-tight text-white md:text-3xl" aria-live="polite">
          {view.title}
        </h1>
        <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{view.body}</p>

        <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
          {phase.kind === 'signin' ? (
            <Link
              to={loginHref}
              className="inline-flex items-center justify-center gap-2 rounded-lg border border-gold bg-gold px-6 py-3 font-mono text-xs font-bold uppercase tracking-wider text-cyber-black transition-colors hover:bg-gold/90"
            >
              Sign in <ArrowRight className="h-4 w-4" />
            </Link>
          ) : (
            <Link
              to="/dashboard/settings?tab=billing"
              className="inline-flex items-center justify-center gap-2 rounded-lg border border-gold bg-gold px-6 py-3 font-mono text-xs font-bold uppercase tracking-wider text-cyber-black transition-colors hover:bg-gold/90"
            >
              View my subscription <ArrowRight className="h-4 w-4" />
            </Link>
          )}
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
