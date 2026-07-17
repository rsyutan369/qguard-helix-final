'use client';

import { useMemo, useState } from 'react';
import { Download, RefreshCw, Search } from 'lucide-react';
import {
  AMBER, CYAN, EMERALD, GOLD, RED, SLATE,
  BarList, EmptyState, HeaderButton, MetricCard, Panel, SectionTitle,
} from '@/app/dashboard/quantum-readiness/_shared';
import {
  DataTable, PLAN_COLORS, RevenueShell, StatusPill, dateFmt, moneyFmt, useRevenueIntelligence,
} from '../_shared';

/** Subscription Analytics — plan mix, status board, rates, and subscriber roster. */
export default function SubscriptionAnalyticsPage() {
  const { snapshot, state, sseConnected, refresh, exportReport } = useRevenueIntelligence();
  const subs = snapshot.subscriptionAnalytics;
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  const filtered = useMemo(() => {
    const text = query.trim().toLowerCase();
    return snapshot.subscribers.filter((subscriber) => {
      if (statusFilter !== 'all' && String(subscriber.status).toLowerCase() !== statusFilter) return false;
      if (!text) return true;
      return [subscriber.email, subscriber.plan, subscriber.provider].some((field) => String(field || '').toLowerCase().includes(text));
    });
  }, [snapshot.subscribers, query, statusFilter]);

  const statusBoard = [
    { label: 'Active', value: subs.active, color: EMERALD },
    { label: 'Trial', value: subs.trial, color: CYAN },
    { label: 'Renewing', value: subs.renewing, color: EMERALD },
    { label: 'Renewal pending', value: subs.pendingRenewal, color: AMBER },
    { label: 'Payment failed', value: subs.pastDue, color: RED },
    { label: 'Suspended', value: subs.suspended, color: RED },
    { label: 'Ending at period end', value: subs.endingAtPeriodEnd, color: AMBER },
    { label: 'Cancelled', value: subs.cancelled, color: SLATE },
    { label: 'Expired', value: subs.expired, color: RED },
    { label: 'Awaiting payment', value: subs.incomplete, color: SLATE },
  ];

  return (
    <RevenueShell
      title="Subscription Analytics"
      subtitle="Plan-by-plan health for STARTER, BASIC, PRO, and ELITE: statuses, renewal intent, churn, and every subscriber on the account ledger."
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>Refresh</HeaderButton>
          <HeaderButton icon={Download} onClick={() => exportReport('subscriptions', 'csv')}>Export CSV</HeaderButton>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <MetricCard label="Total Subscriptions" value={String(subs.total)} detail="all providers" color={CYAN} />
        <MetricCard label="Active" value={String(subs.active)} detail={`${subs.renewing} auto-renewing`} color={EMERALD} />
        <MetricCard label="Renewal Rate" value={subs.renewalRatePct === null ? '—' : `${subs.renewalRatePct}%`} detail="auto-renew share of active" color={EMERALD} ring={subs.renewalRatePct ?? undefined} />
        <MetricCard label="Churn (30d)" value={subs.churnPct === null ? '—' : `${subs.churnPct}%`} detail={subs.retentionPct === null ? 'needs history' : `${subs.retentionPct}% retention`} color={subs.churnPct !== null && subs.churnPct > 5 ? RED : EMERALD} />
        <MetricCard label="Upgrades (30d)" value={String(subs.upgrades30d)} detail={`${subs.downgrades30d} downgrades`} color={GOLD} />
        <MetricCard label="Health Score" value={subs.healthScore === null ? '—' : String(subs.healthScore)} detail="evidence-based composite" color={subs.healthScore !== null && subs.healthScore >= 70 ? EMERALD : AMBER} ring={subs.healthScore ?? undefined} />
      </div>

      <div className="grid gap-3 xl:grid-cols-[1.2fr_1fr_1fr]">
        <Panel className="p-4">
          <SectionTitle>Status Board</SectionTitle>
          <div className="grid grid-cols-2 gap-2">
            {statusBoard.map((status) => (
              <div key={status.label} className="flex items-center justify-between rounded-md border border-white/6 bg-white/[0.02] px-3 py-2">
                <span className="inline-flex items-center gap-2 text-[11px] text-white/65">
                  <span className="h-2 w-2 rounded-full" style={{ backgroundColor: status.color }} />
                  {status.label}
                </span>
                <span className="font-mono text-sm font-bold text-white/90">{status.value}</span>
              </div>
            ))}
          </div>
        </Panel>
        <Panel className="p-4">
          <SectionTitle>MRR by Plan</SectionTitle>
          <BarList
            rows={subs.planBreakdown.filter((plan) => plan.mrrCents > 0).map((plan) => ({ label: plan.plan, value: Math.round(plan.mrrCents / 100) }))}
            colorFor={(row) => PLAN_COLORS[row.label] ?? SLATE}
            unit=" USD"
          />
          {subs.planBreakdown.every((plan) => plan.mrrCents === 0) ? null : (
            <p className="mt-3 text-[10px] text-white/35">Monthly-equivalent value of access-granting subscriptions, priced from the plan catalog.</p>
          )}
        </Panel>
        <Panel className="p-4">
          <SectionTitle>Subscribers by Plan</SectionTitle>
          <BarList
            rows={subs.planBreakdown.filter((plan) => plan.total > 0).map((plan) => ({ label: plan.plan, value: plan.active }))}
            colorFor={(row) => PLAN_COLORS[row.label] ?? SLATE}
            unit=" active"
          />
        </Panel>
      </div>

      <Panel className="p-4">
        <SectionTitle
          suffix={
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/30" />
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search email / plan / provider"
                  className="h-8 w-56 rounded-md border border-white/10 bg-black/30 pl-8 pr-2 text-[11px] text-white/85 outline-none placeholder:text-white/25 focus:border-emerald-400/50"
                />
              </div>
              <select
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value)}
                className="h-8 rounded-md border border-white/10 bg-black/30 px-2 text-[11px] text-white/75 outline-none focus:border-emerald-400/50"
              >
                {['all', 'active', 'trial', 'pending_renewal', 'past_due', 'suspended', 'cancelled', 'expired', 'incomplete'].map((status) => (
                  <option key={status} value={status} className="bg-[#0B1526]">{status === 'all' ? 'All statuses' : status.replace(/_/g, ' ')}</option>
                ))}
              </select>
            </div>
          }
        >
          Subscribers ({filtered.length})
        </SectionTitle>
        <DataTable
          headers={['Subscriber', 'Plan', 'Status', 'Provider', 'Cycle', 'Auto-renew', 'Since', 'Renews / Ends', 'MRR']}
          rows={filtered.map((subscriber) => [
            <span key="e" className="font-semibold text-white/85">{subscriber.email ?? subscriber.userId.slice(0, 8)}</span>,
            <span key="p" className="font-bold" style={{ color: PLAN_COLORS[subscriber.plan] ?? SLATE }}>{subscriber.plan}</span>,
            <StatusPill value={subscriber.status} />,
            <span key="pr">{subscriber.provider === 'google_play' ? 'Google Play' : subscriber.provider === 'paypal' ? 'PayPal' : subscriber.provider ?? '—'}</span>,
            <span key="c">{subscriber.billingCycle === 'annual' ? 'Yearly' : 'Monthly'}</span>,
            <span key="a" style={{ color: subscriber.autoRenew && !subscriber.cancelAtPeriodEnd ? EMERALD : AMBER }}>{subscriber.autoRenew && !subscriber.cancelAtPeriodEnd ? 'Yes' : subscriber.cancelAtPeriodEnd ? 'Ends' : 'No'}</span>,
            <span key="d">{dateFmt(subscriber.since)}</span>,
            <span key="r">{dateFmt(subscriber.renewalDate)}</span>,
            <span key="m" className="font-mono font-bold text-emerald-300">{subscriber.mrrCents > 0 ? moneyFmt(subscriber.mrrCents) : '—'}</span>,
          ])}
          empty="No subscribers yet — the roster fills from billing_subscriptions."
        />
        {snapshot.subscribers.length >= 200 ? <p className="mt-2 text-[10px] text-white/35">Showing the 200 most recently updated subscriptions.</p> : null}
      </Panel>

      {!snapshot.hasData ? <EmptyState label="Subscription analytics activate with your first subscriber." /> : null}
    </RevenueShell>
  );
}
