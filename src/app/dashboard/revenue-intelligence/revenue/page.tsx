'use client';

import { Download, RefreshCw } from 'lucide-react';
import {
  AMBER, BLUE, CYAN, EMERALD, GREEN, RED, SLATE, VIOLET,
  BarList, EmptyState, HeaderButton, MetricCard, Panel, SectionTitle,
} from '@/app/dashboard/quantum-readiness/_shared';
import {
  Chart, DataGapsPanel, DataTable, PLAN_COLORS,
  RevenueShell, moneyFmt, pctFmt, revenueTimelineOption, useRevenueIntelligence,
} from '../_shared';

/** Revenue Analytics — timeline, plan/provider/currency mix, refunds, windows. */
export default function RevenueAnalyticsPage() {
  const { snapshot, state, sseConnected, refresh, exportReport } = useRevenueIntelligence();
  const { kpis, windows, paymentAnalytics } = snapshot;

  const timelineRows = [...snapshot.timeline].reverse().map((bucket) => [
    <span key="m" className="font-bold text-white/85">{bucket.label}</span>,
    <span key="g" className="font-mono">{moneyFmt(bucket.grossCents)}</span>,
    <span key="r" className="font-mono" style={{ color: bucket.refundedCents > 0 ? RED : undefined }}>{moneyFmt(bucket.refundedCents)}</span>,
    <span key="n" className="font-mono font-bold text-emerald-300">{moneyFmt(bucket.netCents)}</span>,
    <span key="p">{bucket.payments}</span>,
    <span key="s">{bucket.newSubscriptions}</span>,
  ]);

  return (
    <RevenueShell
      title="Revenue Analytics"
      subtitle="Where every dollar comes from: monthly timeline, plan and provider composition, recurring versus refunded revenue — all traced to real invoices."
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>Refresh</HeaderButton>
          <HeaderButton icon={Download} onClick={() => exportReport('revenue', 'csv')}>Export CSV</HeaderButton>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <MetricCard label="Gross Revenue" value={moneyFmt(kpis.grossRevenueCents)} detail="all successful charges" color={BLUE} />
        <MetricCard label="Net Revenue" value={moneyFmt(kpis.netRevenueCents)} detail="after refunds" color={EMERALD} />
        <MetricCard label="Refunded" value={moneyFmt(kpis.refundedCents)} detail={`${paymentAnalytics.refunds} refunds`} color={RED} />
        <MetricCard label="Recurring (MRR)" value={moneyFmt(kpis.mrrCents)} detail="active subscriptions" color={CYAN} />
        <MetricCard label="MoM Growth" value={pctFmt(kpis.revenueGrowthPct)} detail={`vs ${moneyFmt(windows.lastMonthCents)} last month`} color={kpis.revenueGrowthPct !== null && kpis.revenueGrowthPct < 0 ? RED : GREEN} />
        <MetricCard label="Avg Payment" value={moneyFmt(paymentAnalytics.averagePaymentCents)} detail={`${paymentAnalytics.successful} successful payments`} color={VIOLET} />
      </div>

      <Panel className="p-4">
        <SectionTitle>Revenue Timeline — last 12 months</SectionTitle>
        {snapshot.timeline.some((bucket) => bucket.netCents !== 0 || bucket.payments > 0)
          ? <Chart option={revenueTimelineOption(snapshot.timeline)} height={300} />
          : <EmptyState label="No invoiced revenue in the last 12 months." hint="Charts populate from billing_invoices as payments arrive." />}
      </Panel>

      <div className="grid gap-3 xl:grid-cols-3">
        <Panel className="p-4">
          <SectionTitle>Revenue by Subscription Plan</SectionTitle>
          <BarList
            rows={snapshot.revenueByPlanInvoiced.map((plan) => ({ label: plan.label, value: Math.round(plan.cents / 100) }))}
            colorFor={(row) => PLAN_COLORS[row.label] ?? SLATE}
            unit=" USD"
          />
        </Panel>
        <Panel className="p-4">
          <SectionTitle>Revenue by Payment Provider</SectionTitle>
          <BarList
            rows={snapshot.revenueByProvider.map((provider) => ({ label: provider.label, value: Math.round(provider.cents / 100) }))}
            colorFor={(row) => (row.label === 'PayPal' ? BLUE : row.label === 'Google Play' ? GREEN : SLATE)}
            unit=" USD"
          />
        </Panel>
        <Panel className="p-4">
          <SectionTitle>Revenue by Currency</SectionTitle>
          <BarList
            rows={snapshot.revenueByCurrency.map((currency) => ({ label: currency.label, value: Math.round(currency.cents / 100) }))}
            colorFor={() => AMBER}
            unit=""
          />
        </Panel>
      </div>

      <div className="grid gap-3 xl:grid-cols-[2fr_1fr]">
        <Panel className="p-4">
          <SectionTitle>Revenue by Month</SectionTitle>
          <DataTable
            headers={['Month', 'Gross', 'Refunded', 'Net', 'Payments', 'New Subscriptions']}
            rows={timelineRows}
            empty="No monthly revenue rows yet."
          />
        </Panel>
        <div className="grid gap-3 content-start">
          <Panel className="p-4">
            <SectionTitle>Period Windows</SectionTitle>
            <div className="space-y-1.5">
              {[
                { label: 'Today', cents: windows.todayCents },
                { label: 'Yesterday', cents: windows.yesterdayCents },
                { label: 'This Week', cents: windows.thisWeekCents },
                { label: 'This Month', cents: windows.thisMonthCents },
                { label: 'This Quarter', cents: windows.thisQuarterCents },
                { label: 'This Year', cents: windows.thisYearCents },
              ].map((row) => (
                <div key={row.label} className="flex items-center justify-between rounded-md border border-white/6 bg-white/[0.02] px-3 py-1.5 text-[11px]">
                  <span className="text-white/60">{row.label}</span>
                  <span className="font-mono font-bold text-white/85">{moneyFmt(row.cents)}</span>
                </div>
              ))}
            </div>
          </Panel>
          <DataGapsPanel gaps={snapshot.dataGaps.filter((gap) => gap.metric.includes('Country') || gap.metric.includes('Stripe'))} />
        </div>
      </div>
    </RevenueShell>
  );
}
