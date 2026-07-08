import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldCheck, LogOut, Download, MessageSquareLock, Database, Crown,
  RefreshCw, XCircle, CheckCircle2, CalendarClock, Loader2, ArrowUpRight, Repeat,
} from 'lucide-react';
import { supabase } from '@/lib/supabase';
import { useAuth } from '@/contexts/auth-context';
import { useBillingSettings } from '@/hooks/use-billing-settings';
import { MESSAGING_INSTALLER, PlanGateModal } from '@/app/qguard-messaging/_shared';
import ThemeToggle from '@/components/theme/ThemeToggle';

// Dedicated dashboard for STARTER subscribers. STARTER is scoped to QGuard
// Messaging only, so this replaces the enterprise sidebar entirely: profile,
// full subscription management, and the messaging downloads — nothing else.

function initials(email: string): string {
  return (email.split('@')[0].slice(0, 2) || 'QG').toUpperCase();
}

function fmtDate(value: string | null): string {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  } catch {
    return '—';
  }
}

const STATUS_TONE: Record<string, string> = {
  active: 'text-emerald-300 border-emerald-400/30 bg-emerald-500/10',
  trial: 'text-cyan-300 border-cyan-400/30 bg-cyan-500/10',
  pending_renewal: 'text-amber-300 border-amber-400/30 bg-amber-500/10',
  past_due: 'text-rose-300 border-rose-400/30 bg-rose-500/10',
  cancelled: 'text-slate-300 border-slate-400/30 bg-slate-500/10',
  expired: 'text-rose-300 border-rose-400/30 bg-rose-500/10',
};

export function StarterDashboard() {
  const { user } = useAuth();
  const { billing, loading, saving, error, runSubscriptionAction } = useBillingSettings();
  const [actionError, setActionError] = useState<string | null>(null);
  const [upgradeOpen, setUpgradeOpen] = useState(false);
  const sub = billing?.subscription;
  const email = user?.email ?? '';

  async function act(action: Parameters<typeof runSubscriptionAction>[0], payload?: Parameters<typeof runSubscriptionAction>[1]) {
    setActionError(null);
    try {
      const res = await runSubscriptionAction(action, payload);
      if (res && (res as { redirectUrl?: string }).redirectUrl) {
        window.location.href = (res as { redirectUrl?: string }).redirectUrl!;
      }
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Action failed');
    }
  }

  const statusKey = (sub?.status ?? 'active').toLowerCase();
  const cycle = sub?.billingCycle ?? 'monthly';
  const otherCycle = cycle === 'monthly' ? 'annual' : 'monthly';

  return (
    <div className="qg-dashboard-shell min-h-screen bg-[var(--qg-dashboard-bg)] text-slate-100">
      {/* Header */}
      <header className="sticky top-0 z-20 flex items-center justify-between border-b border-slate-700/40 bg-slate-950/85 px-5 py-3.5 backdrop-blur-xl">
        <Link to="/" className="flex items-center gap-2.5 no-underline">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-blue-400/30 bg-blue-500/10">
            <ShieldCheck className="h-5 w-5 text-cyan-300" />
          </div>
          <div>
            <span className="block text-sm font-black uppercase tracking-[0.06em] text-slate-50">Qguard Helix</span>
            <span className="block text-[9px] font-bold uppercase tracking-[0.2em] text-cyan-300/60">Starter Workspace</span>
          </div>
        </Link>
        <div className="flex items-center gap-2">
          <ThemeToggle compact showSystem={false} />
          <button
            onClick={async () => { await supabase.auth.signOut(); window.location.href = '/'; }}
            className="flex items-center gap-2 rounded-lg px-3 py-2 text-[11px] font-bold text-white/40 transition-colors hover:bg-red-500/10 hover:text-red-400"
          >
            <LogOut className="h-4 w-4" /> Sign out
          </button>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-5 py-8">
        <div className="mb-6">
          <h1 className="text-2xl font-black tracking-tight text-slate-50">Welcome back</h1>
          <p className="mt-1 text-sm text-slate-400">Your Starter plan includes QGuard Messaging — Secure Chat and the Quantum Vault.</p>
        </div>

        <div className="grid gap-5 lg:grid-cols-2">
          {/* Profile */}
          <section className="rounded-2xl border border-slate-700/40 bg-slate-900/60 p-6">
            <h2 className="mb-4 text-[11px] font-black uppercase tracking-[0.2em] text-slate-500">Profile</h2>
            <div className="flex items-center gap-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-full bg-gradient-to-br from-blue-600 to-cyan-500 text-lg font-black text-white">
                {initials(email)}
              </div>
              <div className="min-w-0">
                <div className="truncate text-sm font-bold text-slate-100">{email || 'Your account'}</div>
                <div className="mt-1 inline-flex items-center gap-1.5 rounded-full border border-emerald-400/30 bg-emerald-500/10 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-emerald-300">
                  <CheckCircle2 className="h-3 w-3" /> Account active
                </div>
              </div>
            </div>
          </section>

          {/* Subscription */}
          <section className="rounded-2xl border border-slate-700/40 bg-slate-900/60 p-6">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-[11px] font-black uppercase tracking-[0.2em] text-slate-500">Subscription</h2>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-blue-400/30 bg-blue-500/10 px-2.5 py-0.5 text-[10px] font-black uppercase tracking-wide text-cyan-200">
                <Crown className="h-3 w-3" /> {sub?.currentPlan ?? 'Starter'}
              </span>
            </div>

            {loading ? (
              <div className="flex items-center gap-2 py-6 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading subscription…</div>
            ) : (
              <>
                <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
                  <div>
                    <dt className="text-[11px] uppercase tracking-wide text-slate-500">Status</dt>
                    <dd className={`mt-1 inline-flex rounded-md border px-2 py-0.5 text-[11px] font-bold capitalize ${STATUS_TONE[statusKey] ?? STATUS_TONE.cancelled}`}>
                      {(sub?.status ?? 'active').replace(/_/g, ' ')}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[11px] uppercase tracking-wide text-slate-500">Billing</dt>
                    <dd className="mt-1 font-bold capitalize text-slate-200">{cycle}</dd>
                  </div>
                  <div>
                    <dt className="text-[11px] uppercase tracking-wide text-slate-500">Renews</dt>
                    <dd className="mt-1 flex items-center gap-1.5 font-bold text-slate-200"><CalendarClock className="h-3.5 w-3.5 text-slate-500" />{fmtDate(sub?.renewalDate ?? null)}</dd>
                  </div>
                  <div>
                    <dt className="text-[11px] uppercase tracking-wide text-slate-500">Auto-renew</dt>
                    <dd className="mt-1 font-bold text-slate-200">{sub?.autoRenew ? 'On' : 'Off'}</dd>
                  </div>
                </dl>

                {(actionError || error) && (
                  <div className="mt-3 rounded-lg border border-rose-400/30 bg-rose-500/10 px-3 py-2 text-[11px] font-semibold text-rose-300">{actionError || error}</div>
                )}

                <div className="mt-5 flex flex-wrap gap-2">
                  <button disabled={saving} onClick={() => act(sub?.autoRenew ? 'disable-auto-renew' : 'enable-auto-renew')}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-600/50 px-3 py-2 text-[11px] font-bold text-slate-200 transition-colors hover:border-cyan-400/40 hover:text-cyan-200 disabled:opacity-50">
                    <RefreshCw className="h-3.5 w-3.5" /> {sub?.autoRenew ? 'Disable' : 'Enable'} auto-renew
                  </button>
                  <button disabled={saving} onClick={() => act('switch-cycle', { billingCycle: otherCycle })}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-600/50 px-3 py-2 text-[11px] font-bold text-slate-200 transition-colors hover:border-cyan-400/40 hover:text-cyan-200 disabled:opacity-50">
                    <Repeat className="h-3.5 w-3.5" /> Switch to {otherCycle}
                  </button>
                  {statusKey === 'cancelled' ? (
                    <button disabled={saving} onClick={() => act('reactivate')}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-[11px] font-bold text-emerald-300 transition-colors hover:bg-emerald-500/20 disabled:opacity-50">
                      <CheckCircle2 className="h-3.5 w-3.5" /> Reactivate
                    </button>
                  ) : (
                    <button disabled={saving} onClick={() => act('cancel')}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 px-3 py-2 text-[11px] font-bold text-rose-300 transition-colors hover:bg-rose-500/10 disabled:opacity-50">
                      <XCircle className="h-3.5 w-3.5" /> Cancel
                    </button>
                  )}
                  <button type="button" onClick={() => setUpgradeOpen(true)}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-500 px-3 py-2 text-[11px] font-black uppercase tracking-wide text-white transition-transform hover:-translate-y-0.5">
                    <ArrowUpRight className="h-3.5 w-3.5" /> Upgrade plan
                  </button>
                </div>
                {saving && <div className="mt-3 flex items-center gap-2 text-[11px] text-slate-400"><Loader2 className="h-3 w-3 animate-spin" /> Applying…</div>}
              </>
            )}
          </section>
        </div>

        {/* Downloads */}
        <section className="mt-5 rounded-2xl border border-slate-700/40 bg-slate-900/60 p-6">
          <h2 className="mb-1 text-[11px] font-black uppercase tracking-[0.2em] text-slate-500">Downloads</h2>
          <p className="mb-4 text-sm text-slate-400">Install QGuard Messaging and open Secure Chat or the Quantum Vault.</p>

          <div className="grid gap-3 sm:grid-cols-3">
            <a href={MESSAGING_INSTALLER.href} download
              className="group flex flex-col rounded-xl border border-blue-400/25 bg-blue-500/[0.06] p-4 no-underline transition-colors hover:border-cyan-400/40">
              <Download className="h-5 w-5 text-cyan-300" />
              <span className="mt-3 text-sm font-bold text-slate-100">Windows installer</span>
              <span className="mt-0.5 text-[11px] text-slate-400">v{MESSAGING_INSTALLER.version} · ~{MESSAGING_INSTALLER.sizeMb} MB · {MESSAGING_INSTALLER.requirements}</span>
            </a>
            <Link to="/qguard-messaging/secure-chat"
              className="group flex flex-col rounded-xl border border-slate-700/40 bg-slate-800/40 p-4 no-underline transition-colors hover:border-cyan-400/40">
              <MessageSquareLock className="h-5 w-5 text-cyan-300" />
              <span className="mt-3 text-sm font-bold text-slate-100">Secure Chat</span>
              <span className="mt-0.5 text-[11px] text-slate-400">Post-quantum end-to-end messaging</span>
            </Link>
            <Link to="/qguard-messaging/quantum-vault"
              className="group flex flex-col rounded-xl border border-slate-700/40 bg-slate-800/40 p-4 no-underline transition-colors hover:border-cyan-400/40">
              <Database className="h-5 w-5 text-cyan-300" />
              <span className="mt-3 text-sm font-bold text-slate-100">Quantum Vault</span>
              <span className="mt-0.5 text-[11px] text-slate-400">On-device encrypted file vault</span>
            </Link>
          </div>
          <p className="mt-4 text-[11px] text-slate-500">
            macOS, Linux, and mobile builds appear here as they become available.
          </p>
        </section>
      </main>

      {upgradeOpen && (
        <PlanGateModal
          onClose={() => setUpgradeOpen(false)}
          badge="Upgrade your plan"
          title="Choose a new plan"
          subtitle="Pick a plan below — you'll be redirected to PayPal to complete payment before the new features unlock."
        />
      )}
    </div>
  );
}
