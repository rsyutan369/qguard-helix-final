import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Lock, ArrowUpRight, Sparkles } from 'lucide-react';
import { TIER_LABEL, type AccessTier, type PlanTier } from '@/lib/subscription-access';
import { PlanGateModal } from '@/app/qguard-messaging/_shared';

// Shown when a signed-in user reaches a module above their plan, or has no
// active subscription at all. Never renders the underlying module — the gate
// swaps this in instead, so unauthorized functionality is never mounted.

const TIER_BLURB: Record<PlanTier, string> = {
  starter: 'QGuard Messaging — Secure Chat, Quantum Vault, and the desktop app.',
  basic: 'the Quantum Readiness & Assessment Engine, Migration Planner, and Migration Sandbox.',
  pro: 'Discovery, Operations, Ecosystem, Intelligence, PQAuth, Observability, and Trust Center.',
  elite: 'the entire QGuard Helix platform — every current and future module.',
};

export function UpgradeRequired({
  requiredTier,
  currentTier,
  moduleName,
  variant = 'upgrade',
}: {
  requiredTier: PlanTier;
  currentTier: AccessTier;
  moduleName?: string;
  variant?: 'upgrade' | 'no-subscription';
}) {
  const required = TIER_LABEL[requiredTier];
  const noSub = variant === 'no-subscription' || currentTier === 'none';
  // The CTA opens the plan-selection modal in place (choose a plan → PayPal),
  // instead of bouncing to the marketing homepage pricing section.
  const [planOpen, setPlanOpen] = useState(false);

  return (
    <div className="grid min-h-[70vh] place-items-center p-6">
      <div className="w-full max-w-lg rounded-2xl border border-blue-400/25 bg-slate-900/70 p-8 text-center shadow-[0_24px_80px_rgba(0,0,0,0.4)] backdrop-blur-xl">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-blue-400/30 bg-blue-500/10 text-cyan-300">
          <Lock className="h-6 w-6" />
        </div>
        <div className="mt-4 inline-flex items-center gap-1.5 rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-cyan-200">
          <Sparkles className="h-3 w-3" />
          {required} plan required
        </div>
        <h1 className="mt-4 text-xl font-black tracking-tight text-slate-50">
          {noSub ? 'Subscription required' : `${moduleName || 'This module'} needs the ${required} plan`}
        </h1>
        <p className="mt-2 text-sm leading-relaxed text-slate-400">
          {noSub
            ? 'Your account does not have an active subscription. Choose a plan to unlock the platform.'
            : `Upgrade to ${required} to unlock ${TIER_BLURB[requiredTier]}`}
        </p>

        <div className="mt-6 flex flex-col items-center justify-center gap-2.5 sm:flex-row">
          <button
            type="button"
            onClick={() => setPlanOpen(true)}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-500 px-6 py-3 text-sm font-black uppercase tracking-wide text-white shadow-[0_14px_38px_rgba(37,99,235,0.35)] transition-transform hover:-translate-y-0.5"
          >
            {noSub ? 'View plans' : `Upgrade to ${required}`}
            <ArrowUpRight className="h-4 w-4" />
          </button>
          <Link
            to="/dashboard/settings"
            className="inline-flex items-center justify-center rounded-xl border border-slate-600/50 px-6 py-3 text-sm font-bold text-slate-300 no-underline transition-colors hover:border-cyan-400/40 hover:text-cyan-200"
          >
            Manage subscription
          </Link>
        </div>

        <p className="mt-5 text-[11px] text-slate-500">
          Each higher tier includes everything in the tiers below it. Access is verified on every request.
        </p>
      </div>

      {planOpen && (
        <PlanGateModal
          onClose={() => setPlanOpen(false)}
          badge={noSub ? 'Choose a plan' : 'Upgrade your plan'}
          title={noSub ? 'Choose a plan to get started' : `Upgrade to ${required} or higher`}
          subtitle="Pick a plan below — you'll be redirected to PayPal to complete payment before access unlocks."
        />
      )}
    </div>
  );
}
