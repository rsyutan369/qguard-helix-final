'use client';

import { BadgeDollarSign, Banknote, Download, Infinity as InfinityIcon, RefreshCw, Repeat, TrendingUp, Users } from 'lucide-react';
import {
  AMBER, BLUE, CYAN, EMERALD, GOLD, GREEN, RED, SLATE, VIOLET,
  BarList, Donut, EmptyState, HeaderButton, MetricCard, Panel, SectionTitle, ViewAllLink,
} from '@/app/dashboard/quantum-readiness/_shared';
import {
  ActivityFeed, AlertsPanel, Chart, DataGapsPanel, PLAN_COLORS,
  RevenueShell, forecastOption, growthBarsOption, moneyFmt, pctFmt, revenueTimelineOption, useRevenueIntelligence,
} from './_shared';

/**
 * Revenue Intelligence™ — Executive Overview. The owner's command center:
 * live KPIs, revenue trend, plan mix, provider mix, activity, alerts, health,
 * and the forecast — all computed from real billing evidence and streamed
 * over the owner SSE channel.
 */
export default function RevenueOverviewPage() {
  const { snapshot, state, sseConnected, refresh, exportReport } = useRevenueIntelligence();
  const { kpis, windows, subscriptionAnalytics: subs, customerAnalytics: customers } = snapshot;

  const planSegments = subs.planBreakdown
    .filter((plan) => plan.invoicedCents > 0 || plan.active > 0)
    .map((plan) => ({ label: plan.plan, value: Math.max(plan.invoicedCents / 100, plan.active), color: PLAN_COLORS[plan.plan] ?? SLATE }));

  const summaryRows = [
    { label: 'Today', cents: windows.todayCents },
    { label: 'Yesterday', cents: windows.yesterdayCents },
    { label: 'This Week', cents: windows.thisWeekCents },
    { label: 'This Month', cents: windows.thisMonthCents },
    { label: 'This Quarter', cents: windows.thisQuarterCents },
    { label: 'This Year', cents: windows.thisYearCents },
    { label: 'All Time', cents: windows.allTimeCents },
  ];

  return (
    <RevenueShell
      title="Executive Revenue Overview"
      subtitle="Real-time insight into revenue, customers, subscriptions, and growth across QGuard Helix and QGuard Messaging — one command center for every payment provider."
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>Refresh</HeaderButton>
          <HeaderButton icon={Download} onClick={() => exportReport('summary', 'csv')}>Export Summary</HeaderButton>
        </>
      }
    >
      {/* KPI hero row */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <MetricCard label="Total Revenue" value={moneyFmt(kpis.totalRevenueCents)} detail={kpis.revenueGrowthPct === null ? 'net of refunds' : `${pctFmt(kpis.revenueGrowthPct)} vs last month`} color={EMERALD} icon={BadgeDollarSign} />
        <MetricCard label="MRR" value={moneyFmt(kpis.mrrCents)} detail="monthly recurring revenue" color={CYAN} icon={Repeat} />
        <MetricCard label="ARR" value={moneyFmt(kpis.arrCents)} detail="annual recurring revenue" color={VIOLET} icon={TrendingUp} />
        <MetricCard label="Active Subscribers" value={String(kpis.activeSubscribers)} detail={customers.customerGrowthPct === null ? 'across all plans' : `${pctFmt(customers.customerGrowthPct)} new-customer MoM`} color={AMBER} icon={Users} />
        <MetricCard label="Net Revenue" value={moneyFmt(kpis.netRevenueCents)} detail={`${moneyFmt(kpis.refundedCents)} refunded`} color={GREEN} icon={Banknote} />
        <MetricCard label="Lifetime Revenue" value={moneyFmt(kpis.lifetimeRevenueCents)} detail="all time" color={BLUE} icon={InfinityIcon} />
      </div>

      {/* Trend + plan mix + live activity */}
      <div className="grid gap-3 xl:grid-cols-[1.5fr_1fr_1fr]">
        <Panel className="p-4">
          <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/revenue">Revenue analytics</ViewAllLink>}>Revenue Overview</SectionTitle>
          {snapshot.timeline.some((bucket) => bucket.netCents !== 0 || bucket.payments > 0)
            ? <Chart option={revenueTimelineOption(snapshot.timeline)} height={280} />
            : <EmptyState label="No invoiced revenue yet." hint="The trend renders from real billing_invoices rows as payments land." />}
        </Panel>
        <Panel className="p-4">
          <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/subscriptions">Plans</ViewAllLink>}>Revenue by Plan</SectionTitle>
          {planSegments.length ? (
            <Donut segments={planSegments} centerValue={moneyFmt(kpis.netRevenueCents)} centerLabel={kpis.revenueGrowthPct === null ? 'net revenue' : pctFmt(kpis.revenueGrowthPct)} centerColor={EMERALD} />
          ) : (
            <EmptyState label="No plan revenue yet." />
          )}
          <div className="mt-4 grid grid-cols-3 gap-2">
            {[
              { label: 'Churn (30d)', value: kpis.churnPct === null ? '—' : `${kpis.churnPct}%`, color: kpis.churnPct !== null && kpis.churnPct > 5 ? RED : EMERALD },
              { label: 'LTV', value: moneyFmt(kpis.ltvCents), color: CYAN },
              { label: 'ARPU', value: moneyFmt(kpis.arpuCents), color: VIOLET },
            ].map((chip) => (
              <div key={chip.label} className="rounded-md border border-white/8 bg-white/[0.02] px-2.5 py-2 text-center">
                <div className="text-sm font-semibold text-white">{chip.value}</div>
                <div className="mt-0.5 text-[10px] font-bold" style={{ color: chip.color }}>{chip.label}</div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel className="p-4">
          <SectionTitle suffix={<span className="inline-flex items-center gap-1.5 text-[10px] font-bold text-emerald-300"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />Live</span>}>Real-Time Activity</SectionTitle>
          <ActivityFeed activity={snapshot.activity} limit={7} />
        </Panel>
      </div>

      {/* Growth + alerts + providers/summary */}
      <div className="grid gap-3 xl:grid-cols-[1.5fr_1fr_1fr]">
        <Panel className="p-4">
          <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/customers">Customers</ViewAllLink>}>New Customers vs New Subscriptions</SectionTitle>
          {snapshot.timeline.some((bucket) => bucket.newCustomers > 0 || bucket.newSubscriptions > 0)
            ? <Chart option={growthBarsOption(snapshot.timeline)} height={250} />
            : <EmptyState label="No signups recorded in the last 12 months." />}
        </Panel>
        <Panel className="p-4">
          <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/forecast">View all</ViewAllLink>}>Alerts & Notifications</SectionTitle>
          <AlertsPanel alerts={snapshot.alerts} limit={6} />
        </Panel>
        <div className="grid gap-3">
          <Panel className="p-4">
            <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/payments">Payments</ViewAllLink>}>Top Payment Providers</SectionTitle>
            <BarList
              rows={snapshot.revenueByProvider.map((provider) => ({ label: provider.label, value: Math.round(provider.cents / 100), sub: `${provider.count} payments` }))}
              colorFor={(row) => (row.label === 'PayPal' ? BLUE : row.label === 'Google Play' ? GREEN : SLATE)}
              unit=" USD"
            />
          </Panel>
          <Panel className="p-4">
            <SectionTitle>Revenue Summary</SectionTitle>
            <div className="space-y-1.5">
              {summaryRows.map((row) => (
                <div key={row.label} className="flex items-center justify-between rounded-md border border-white/6 bg-white/[0.02] px-3 py-1.5 text-[11px]">
                  <span className="text-white/60">{row.label}</span>
                  <span className="font-mono font-bold text-white/85">{moneyFmt(row.cents)}</span>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>

      {/* Health + forecast + honesty */}
      <div className="grid gap-3 xl:grid-cols-[1fr_1.5fr_1fr]">
        <Panel className="p-4">
          <SectionTitle>Subscription Health</SectionTitle>
          {subs.total > 0 ? (
            <Donut
              segments={[
                { label: 'Active', value: subs.active, color: EMERALD },
                { label: 'Trial', value: subs.trial, color: CYAN },
                { label: 'Renewal pending', value: subs.pendingRenewal, color: AMBER },
                { label: 'Payment failed', value: subs.pastDue + subs.suspended, color: RED },
                { label: 'Cancelled', value: subs.cancelled, color: SLATE },
                { label: 'Expired', value: subs.expired, color: RED },
              ].filter((segment) => segment.value > 0)}
              centerValue={subs.healthScore === null ? '—' : String(subs.healthScore)}
              centerLabel="health score"
              centerColor={subs.healthScore !== null && subs.healthScore >= 70 ? EMERALD : AMBER}
            />
          ) : (
            <EmptyState label="No subscriptions yet." hint="Health scoring starts with the first subscriber." />
          )}
          <p className="mt-3 text-[10px] leading-relaxed text-white/35">
            Composite of active share (30%), renewal intent (25%), payment success (25%), retention (20%) — every input measured from billing evidence.
          </p>
        </Panel>
        <Panel className="p-4">
          <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/forecast">Forecast engine</ViewAllLink>}>Revenue Forecast — next 6 months</SectionTitle>
          {snapshot.forecast.horizon.length && snapshot.hasData
            ? <Chart option={forecastOption(snapshot)} height={250} />
            : <EmptyState label="Not enough history to project yet." hint="The forecast needs invoiced revenue history to extend." />}
        </Panel>
        <DataGapsPanel gaps={snapshot.dataGaps} />
      </div>

      {/* Top plans strip */}
      <Panel className="p-4">
        <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/subscriptions">Subscription analytics</ViewAllLink>}>Plan Performance</SectionTitle>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {subs.planBreakdown.map((plan) => (
            <div key={plan.plan} className="rounded-md border border-white/8 bg-white/[0.02] p-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-black uppercase tracking-wide" style={{ color: PLAN_COLORS[plan.plan] ?? GOLD }}>{plan.plan}</span>
                <span className="text-[10px] text-white/40">{plan.active} active</span>
              </div>
              <div className="mt-2 text-lg font-semibold text-white">{moneyFmt(plan.mrrCents)}<span className="ml-1 text-[10px] font-bold text-white/40">MRR</span></div>
              <div className="mt-0.5 text-[10px] text-white/45">{moneyFmt(plan.invoicedCents)} invoiced lifetime · {plan.trial} trial · {plan.cancelled} cancelled</div>
            </div>
          ))}
        </div>
      </Panel>
    </RevenueShell>
  );
}
