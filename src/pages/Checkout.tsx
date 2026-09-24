import { useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/contexts/auth-context';
import { billingApiUrl } from '@/lib/billing/billing-api';

/**
 * Auth-gated checkout bridge. Reached from the landing pricing buttons
 * (/checkout?plan=Pro&cycle=monthly).
 *
 * Flow: if the visitor is not signed in, send them to /login (preserving this
 * checkout target via ?next=). Once authenticated, create a PayPal subscription
 * for the signed-in user and redirect to PayPal's approval page.
 */

const VALID_PLANS = ['Starter', 'Basic', 'Pro', 'Elite'] as const;
export const PENDING_CHECKOUT_KEY = 'qguard.pendingCheckout';

function normalizePlanName(value: string | null | undefined): string | null {
  if (!value) return null;
  const text = value.trim().toLowerCase();
  return VALID_PLANS.find((plan) => plan.toLowerCase() === text) || null;
}

function readPendingCheckout(): { plan: string; cycle: string } | null {
  try {
    const raw = localStorage.getItem(PENDING_CHECKOUT_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export default function Checkout() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const { user, session, loading } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const startedRef = useRef(false);

  // Resolve the target from the URL, falling back to a pending intent stashed
  // before an auth hop (e.g. register -> verify email -> sign in).
  const pending = readPendingCheckout();
  const plan = normalizePlanName(params.get('plan')) || normalizePlanName(pending?.plan);
  const cycle = (params.get('cycle') || pending?.cycle) === 'yearly' ? 'yearly' : 'monthly';

  useEffect(() => {
    if (loading) return;
    if (!plan) {
      setError('Unknown or missing plan.');
      return;
    }

    // Persist the intent so it survives the sign-in / email-verification hop.
    try {
      localStorage.setItem(PENDING_CHECKOUT_KEY, JSON.stringify({ plan, cycle }));
    } catch {
      // Non-fatal: the ?next= query param also carries the target.
    }

    // Not signed in — send to login, preserving the checkout target.
    if (!user || !session?.access_token) {
      const next = `/checkout?plan=${encodeURIComponent(plan)}&cycle=${cycle}`;
      navigate(`/login?next=${encodeURIComponent(next)}`, { replace: true });
      return;
    }

    if (startedRef.current) return;
    startedRef.current = true;

    (async () => {
      try {
        // The billing Edge Function, not a same-origin route: the static site has no /api.
        const response = await fetch(billingApiUrl('/api/v1/paypal/subscribe'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${session.access_token}`,
          },
          body: JSON.stringify({ plan, cycle }),
        }).catch(() => {
          throw new Error("Can't reach the billing service. Check your connection and try again.");
        });
        const payload = await response.json().catch(() => ({}));
        const approvalUrl = payload?.data?.approvalUrl;
        if (!response.ok || !approvalUrl) {
          throw new Error(payload?.error?.message || 'Unable to start PayPal checkout. Please try again.');
        }
        try {
          localStorage.removeItem(PENDING_CHECKOUT_KEY);
        } catch {
          // ignore
        }
        window.location.href = approvalUrl;
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Checkout failed. Please try again.');
        startedRef.current = false;
      }
    })();
  }, [loading, user, session, plan, cycle, navigate]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-cyber-black px-6 text-white">
      <div className="w-full max-w-md rounded-2xl border border-gold/20 bg-cyber-navy/40 p-10 text-center shadow-[0_30px_120px_rgba(0,0,0,0.5)] backdrop-blur-2xl">
        {error ? (
          <>
            <h1 className="text-xl font-black tracking-tight text-white">Checkout could not start</h1>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{error}</p>
            <div className="mt-6 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <button
                type="button"
                onClick={() => window.location.reload()}
                className="rounded-lg border border-gold bg-gold px-6 py-3 font-mono text-xs font-bold uppercase tracking-wider text-cyber-black transition-colors hover:bg-gold/90"
              >
                Try again
              </button>
              <button
                type="button"
                onClick={() => navigate('/#pricing')}
                className="rounded-lg border border-white/15 px-6 py-3 font-mono text-xs font-bold uppercase tracking-wider text-white transition-colors hover:border-white/40"
              >
                Back to pricing
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="mx-auto mb-5 h-10 w-10 animate-spin rounded-full border-2 border-gold border-t-transparent" />
            <h1 className="text-xl font-black tracking-tight text-white">
              Preparing your {plan ?? ''} subscription…
            </h1>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
              Redirecting you to PayPal to complete checkout securely.
            </p>
          </>
        )}
      </div>
    </div>
  );
}
