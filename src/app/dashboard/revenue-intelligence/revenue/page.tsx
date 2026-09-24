'use client';

import { BadgeDollarSign, Banknote, Coins, Receipt, Repeat, TrendingUp } from 'lucide-react';
import { AMBER, BLUE, CYAN, EMERALD, GREEN, RED, SLATE, VIOLET, EmptyState, Panel, SectionTitle } from '@/app/dashboard/quantum-readiness/_shared';
import {
  Chart, DataGapsPanel, DataTable, Kpi, MoneyBars, PLAN_COLORS, RevenuePage,
  countFmt, moneyFmt, mrrTrendOption, pctFmt, providerColor, revenueTimelineOption,
  type TimelineBucket,
} from '../_shared';

/** Revenue Analytics — where every dollar came from, when, and what was refunded. */
export default function RevenueAnalyticsPage() {
  return (
    <RevenuePage
      title="Revenue Analytics"
      subtitle="Collected, refunded and net revenue by month, plan, provider and currency — every figure traced to billing_invoices, refunds recognised on the day they happened."
      report="revenue"
    >
      {(snapshot) => {
        const { kpis, windows, paymentAnalytics } = snapshot;
        const hasTimeline = snapshot.timeline.some((bucket) => bucket.payments > 0 || bucket.refundedCents > 0);
        const hasMrrHistory = snapshot.timeline.some((bucket) => bucket.endingMrrCents > 0 || bucket.newMrrCents > 0);
        const collected = paymentAnalytics.successful + paymentAnalytics.refunds;
        return (
          <>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
              <Kpi label="Gross Collected" value={moneyFmt(kpis.grossRevenueCents)} detail={`${countFmt(collected)} successful charges`} color={BLUE} icon={Receipt}
                unmeasured={collected === 0 ? 'No collected payment recorded yet' : null} />
              <Kpi label="Net Revenue" value={moneyFmt(kpis.netRevenueCents)} detail="gross − refunds" color={EMERALD} icon={BadgeDollarSign}
                unmeasured={collected === 0 ? 'No collected payment recorded yet' : null} />
              <Kpi label="Refunded" value={moneyFmt(kpis.refundedCents)} detail={`${countFmt(paymentAnalytics.refunds)} refunded payment${paymentAnalytics.refunds === 1 ? '' : 's'}`} color={RED} icon={Coins} />
              <Kpi label="MRR" value={moneyFmt(kpis.mrrCents)} detail="provider-billed recurring" color={CYAN} icon={Repeat}
                unmeasured={snapshot.subscriptionAnalytics.byClass.provider === 0 ? 'No provider-billed subscription yet' : null} />
              <Kpi label="Month-over-Month" value={pctFmt(kpis.revenueGrowthPct)} detail="last completed month vs prior" color={kpis.revenueGrowthPct !== null && kpis.revenueGrowthPct < 0 ? RED : GREEN} icon={TrendingUp}
                unmeasured={kpis.revenueGrowthPct === null ? 'Needs two completed months with revenue' : null} />
              <Kpi label="Month to Date" value={moneyFmt(windows.thisMonthCents)} detail={kpis.mtdGrowthPct === null ? 'vs same days last month: no baseline' : `${pctFmt(kpis.mtdGrowthPct)} vs same days last month`} color={VIOLET} icon={Banknote} />
            </div>

            <Panel className="p-4">
              <SectionTitle>Revenue Timeline — last 12 months (UTC)</SectionTitle>
              {hasTimeline
                ? <Chart label="Monthly net revenue, gross collected and refunds for the last 12 months" option={revenueTimelineOption(snapshot.timeline)} height={300} />
                : <EmptyState label="No collected revenue in the last 12 months." hint="The chart populates from billing_invoices as payments arrive." />}
            </Panel>

            <div className="grid gap-3 xl:grid-cols-3">
              <Panel className="p-4">
                <SectionTitle>Revenue by Plan</SectionTitle>
                <MoneyBars rows={snapshot.revenueByPlan.map((row) => ({ label: row.label, cents: row.cents, sub: `${countFmt(row.count)} payments` }))} colorFor={(label) => PLAN_COLORS[label] ?? SLATE} empty="No plan has collected revenue yet." />
              </Panel>
              <Panel className="p-4">
                <SectionTitle>Revenue by Payment Provider</SectionTitle>
                <MoneyBars rows={snapshot.revenueByProvider.map((row) => ({ label: row.label, cents: row.cents, sub: `${countFmt(row.count)} payments` }))} colorFor={providerColor} empty="No provider has collected a payment yet." />
              </Panel>
              <Panel className="p-4">
                <SectionTitle>Revenue by Currency</SectionTitle>
                {snapshot.revenueByCurrency.length ? (
                  <ul className="space-y-2">
                    {snapshot.revenueByCurrency.map((row) => (
                      <li key={row.currency} className="flex items-center justify-between rounded-md border border-white/6 bg-white/[0.02] px-3 py-2 text-[11px]">
                        <span className="font-bold text-white/80">{row.currency} <span className="font-normal text-white/40">· {countFmt(row.count)} payments</span></span>
                        <span className="text-right">
                          <span className="font-mono font-bold text-white/85">{moneyFmt(row.cents, row.currency)}</span>
                          <span className="ml-2 text-[10px]" style={{ color: row.inReportingCurrency ? EMERALD : AMBER }}>{row.inReportingCurrency ? 'in USD totals' : 'excluded (no FX)'}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : <EmptyState label="No collected payments yet." />}
              </Panel>
            </div>

            <div className="grid gap-3 xl:grid-cols-[2fr_1fr]">
              <Panel className="p-4">
                <SectionTitle>Revenue by Month</SectionTitle>
                <DataTable<TimelineBucket>
                  rows={[...snapshot.timeline].reverse()}
                  rowKey={(bucket) => bucket.month}
                  pageSize={12}
                  empty="No monthly revenue rows yet."
                  columns={[
                    { key: 'month', header: 'Month', render: (bucket) => <span className="font-bold text-white/85">{bucket.label}{bucket.complete ? '' : <span className="ml-1.5 text-[10px] font-normal text-amber-300">to date</span>}</span>, sortValue: (bucket) => bucket.month },
                    { key: 'gross', header: 'Gross', align: 'right', render: (bucket) => <span className="font-mono">{moneyFmt(bucket.grossCents)}</span>, sortValue: (bucket) => bucket.grossCents },
                    { key: 'refunds', header: 'Refunds', align: 'right', render: (bucket) => <span className="font-mono" style={{ color: bucket.refundedCents > 0 ? RED : undefined }}>{moneyFmt(bucket.refundedCents)}</span>, sortValue: (bucket) => bucket.refundedCents },
                    { key: 'net', header: 'Net', align: 'right', render: (bucket) => <span className="font-mono font-bold text-emerald-300">{moneyFmt(bucket.netCents)}</span>, sortValue: (bucket) => bucket.netCents },
                    { key: 'payments', header: 'Payments', align: 'right', render: (bucket) => countFmt(bucket.payments), sortValue: (bucket) => bucket.payments },
                    { key: 'failed', header: 'Failed', align: 'right', render: (bucket) => <span style={{ color: bucket.failedPayments > 0 ? RED : undefined }}>{countFmt(bucket.failedPayments)}</span>, sortValue: (bucket) => bucket.failedPayments },
                    { key: 'mrr', header: 'Month-end MRR', align: 'right', render: (bucket) => <span className="font-mono">{moneyFmt(bucket.endingMrrCents)}</span>, sortValue: (bucket) => bucket.endingMrrCents },
                  ]}
                />
                <p className="mt-2 text-[10px] text-white/35">Month-end MRR is reconstructed from subscription start/end dates at current plan prices.</p>
              </Panel>
              <div className="grid content-start gap-3">
                <Panel className="p-4">
                  <SectionTitle>Net Revenue Windows (UTC)</SectionTitle>
                  <dl className="space-y-1.5">
                    {[
                      { label: 'Today', cents: windows.todayCents },
                      { label: 'Yesterday', cents: windows.yesterdayCents },
                      { label: 'This week (from Monday)', cents: windows.thisWeekCents },
                      { label: 'This month to date', cents: windows.thisMonthCents },
                      { label: 'Last month', cents: windows.lastMonthCents },
                      { label: 'This quarter', cents: windows.thisQuarterCents },
                      { label: 'This year', cents: windows.thisYearCents },
                      { label: 'Trailing 12 months', cents: windows.last12MonthsCents },
                    ].map((row) => (
                      <div key={row.label} className="flex items-center justify-between rounded-md border border-white/6 bg-white/[0.02] px-3 py-1.5 text-[11px]">
                        <dt className="text-white/60">{row.label}</dt>
                        <dd className="font-mono font-bold text-white/85">{moneyFmt(row.cents)}</dd>
                      </div>
                    ))}
                  </dl>
                </Panel>
                <Panel className="p-4">
                  <SectionTitle>Recurring Revenue Trend</SectionTitle>
                  {hasMrrHistory
                    ? <Chart label="Reconstructed month-end MRR and new MRR per month" option={mrrTrendOption(snapshot.timeline)} height={200} />
                    : <EmptyState label="No provider-billed subscription history yet." />}
                </Panel>
                <DataGapsPanel title="Revenue dimensions not measured" gaps={snapshot.dataGaps.filter((gap) => /Country|Product|Stripe|Google Play|tax/i.test(gap.metric))} />
              </div>
            </div>
            {snapshot.paymentAnalytics.failed > 0 ? (
              <p className="text-[11px]" style={{ color: AMBER }}>
                {countFmt(snapshot.paymentAnalytics.failed)} failed payment attempt{snapshot.paymentAnalytics.failed === 1 ? '' : 's'} totalling {moneyFmt(snapshot.paymentAnalytics.failedAttemptCents)} {snapshot.paymentAnalytics.failed === 1 ? 'was' : 'were'} never collected and {snapshot.paymentAnalytics.failed === 1 ? 'is' : 'are'} not in any revenue figure.
              </p>
            ) : null}
          </>
        );
      }}
    </RevenuePage>
  );
}
