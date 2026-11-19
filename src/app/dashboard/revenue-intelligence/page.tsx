'use client';

import { BadgeDollarSign, Banknote, HeartPulse, Repeat, TrendingUp, Users } from 'lucide-react';
import {
  AMBER, CYAN, EMERALD, GOLD, GREEN, RED, SLATE, VIOLET,
  Donut, EmptyState, Panel, SectionTitle, ViewAllLink,
} from '@/app/dashboard/quantum-readiness/_shared';
import {
  ActivityFeed, AlertsPanel, Chart, DataGapsPanel, Kpi, MoneyBars, PLAN_COLORS, RevenuePage,
  countFmt, forecastOption, growthBarsOption, moneyFmt, pctFmt, providerColor, revenueTimelineOption,
} from './_shared';

/**
 * Revenue Intelligence™ — Executive Overview. Every figure is read from the
 * shared revenue model (src/lib/billing/revenue-model.ts); the other five pages
 * read the same snapshot, so a number here equals the same number there.
 */
export default function RevenueOverviewPage() {
  return (
    <RevenuePage
      title="Executive Revenue Overview"
      subtitle="Revenue, recurring revenue, customers and subscription health across QGuard Helix and QGuard Messaging — computed live from provider-verified billing records."
      report="summary"
    >
      {(snapshot) => {
        const { kpis, windows, subscriptionAnalytics: subs, customerAnalytics: customers } = snapshot;
        const hasTimeline = snapshot.timeline.some((bucket) => bucket.payments > 0 || bucket.refundedCents > 0);
        const hasSignups = snapshot.timeline.some((bucket) => bucket.newSignups > 0 || bucket.newSubscriptions > 0 || bucket.churnedSubscriptions > 0);
        const planMrr = subs.planBreakdown.filter((plan) => plan.mrrCents > 0);
        const noBilled = subs.byClass.provider === 0;
        const movement = snapshot.mrrMovement;

        return (
          <>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
              <Kpi label="Net Revenue" value={moneyFmt(kpis.netRevenueCents)} detail={`${moneyFmt(kpis.grossRevenueCents)} collected · ${moneyFmt(kpis.refundedCents)} refunded`} color={EMERALD} icon={BadgeDollarSign}
                unmeasured={snapshot.paymentAnalytics.successful + snapshot.paymentAnalytics.refunds === 0 ? 'No collected payment recorded yet' : null} />
              <Kpi label="MRR" value={moneyFmt(kpis.mrrCents)} detail={kpis.mrrAtRiskCents > 0 ? `${moneyFmt(kpis.mrrAtRiskCents)} set to end at period end` : 'provider-billed, access-granting'} color={CYAN} icon={Repeat}
                unmeasured={noBilled ? 'No provider-billed subscription yet' : null} />
              <Kpi label="ARR" value={moneyFmt(kpis.arrCents)} detail="MRR × 12 (run rate)" color={VIOLET} icon={TrendingUp}
                unmeasured={noBilled ? 'No provider-billed subscription yet' : null} />
              <Kpi label="Paying Customers" value={countFmt(kpis.payingCustomers)} detail={`${countFmt(customers.registeredUsers)} registered · ${countFmt(customers.complimentaryAccounts + customers.manualAccounts)} unbilled access`} color={AMBER} icon={Users} />
              <Kpi label="Revenue Growth" value={pctFmt(kpis.revenueGrowthPct)} detail="last completed month vs the one before" color={kpis.revenueGrowthPct !== null && kpis.revenueGrowthPct < 0 ? RED : GREEN} icon={Banknote}
                unmeasured={kpis.revenueGrowthPct === null ? 'Needs two completed months with revenue' : null} />
              <Kpi label="Subscription Health" value={kpis.subscriptionHealthScore === null ? '—' : `${kpis.subscriptionHealthScore}/100`} detail={`${subs.health.measuredWeightPct}% of the score's weight is measured`} color={kpis.subscriptionHealthScore !== null && kpis.subscriptionHealthScore >= 70 ? EMERALD : AMBER} icon={HeartPulse}
                unmeasured={subs.healthReason} />
            </div>

            <div className="grid gap-3 xl:grid-cols-[1.5fr_1fr_1fr]">
              <Panel className="p-4">
                <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/revenue">Revenue analytics</ViewAllLink>}>Revenue — last 12 months (UTC)</SectionTitle>
                {hasTimeline
                  ? <Chart label="Monthly net revenue, gross collected and refunds for the last 12 months" option={revenueTimelineOption(snapshot.timeline)} height={280} />
                  : <EmptyState label="No collected revenue in the last 12 months." hint="The trend renders from billing_invoices as payments land." />}
              </Panel>
              <Panel className="p-4">
                <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/subscriptions">Plans</ViewAllLink>}>MRR by Plan</SectionTitle>
                {planMrr.length ? (
                  <Donut
                    segments={planMrr.map((plan) => ({ label: `${plan.plan} · ${moneyFmt(plan.mrrCents)}`, value: plan.paying, color: PLAN_COLORS[plan.plan] ?? SLATE }))}
                    centerValue={moneyFmt(kpis.mrrCents)}
                    centerLabel="MRR · segments = paying subs"
                    centerColor={CYAN}
                  />
                ) : (
                  <EmptyState label="No recurring revenue yet." hint={subs.total > 0 ? `${countFmt(subs.total)} subscription(s) exist, none provider-billed.` : 'MRR starts with the first provider-billed subscription.'} />
                )}
                <div className="mt-4 grid grid-cols-3 gap-2">
                  {[
                    { label: 'Churn (30d)', value: kpis.churnPct === null ? '—' : `${kpis.churnPct}%`, color: kpis.churnPct !== null && kpis.churnPct > 5 ? RED : EMERALD, title: kpis.churnPct === null ? 'Needs billed subscriptions older than 30 days' : `${subs.churnWindow.churned} of ${subs.churnWindow.base}` },
                    { label: 'LTV', value: moneyFmt(kpis.ltvCents), color: CYAN, title: kpis.ltvCents === null ? 'Needs a measured, non-zero churn rate' : 'ARPU ÷ monthly churn' },
                    { label: 'ARPU', value: moneyFmt(kpis.arpuCents), color: VIOLET, title: kpis.arpuCents === null ? 'No paying customers' : 'MRR ÷ paying customers' },
                  ].map((chip) => (
                    <div key={chip.label} className="rounded-md border border-white/8 bg-white/[0.02] px-2.5 py-2 text-center" title={chip.title}>
                      <div className="text-sm font-semibold text-white">{chip.value}</div>
                      <div className="mt-0.5 text-[10px] font-bold" style={{ color: chip.color }}>{chip.label}</div>
                    </div>
                  ))}
                </div>
              </Panel>
              <Panel className="p-4">
                <SectionTitle suffix={<span className="inline-flex items-center gap-1.5 text-[10px] font-bold text-emerald-300"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" aria-hidden="true" />Live</span>}>Real-Time Billing Activity</SectionTitle>
                <ActivityFeed activity={snapshot.activity} limit={7} />
              </Panel>
            </div>

            <div className="grid gap-3 xl:grid-cols-[1.5fr_1fr_1fr]">
              <Panel className="p-4">
                <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/customers">Customers</ViewAllLink>}>Sign-ups, New Billed Subscriptions & Churn</SectionTitle>
                {hasSignups
                  ? <Chart label="Monthly new sign-ups, new billed subscriptions and churned subscriptions" option={growthBarsOption(snapshot.timeline)} height={250} />
                  : <EmptyState label="No sign-ups or billed subscriptions in the last 12 months." />}
              </Panel>
              <Panel className="p-4">
                <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/forecast">Notification center</ViewAllLink>}>Billing Alerts</SectionTitle>
                <AlertsPanel alerts={snapshot.alerts} limit={6} />
              </Panel>
              <div className="grid content-start gap-3">
                <Panel className="p-4">
                  <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/payments">Payments</ViewAllLink>}>Revenue by Payment Provider</SectionTitle>
                  <MoneyBars rows={snapshot.revenueByProvider.map((row) => ({ label: row.label, cents: row.cents, sub: `${countFmt(row.count)} payments` }))} colorFor={providerColor} empty="No provider has collected a payment yet." />
                </Panel>
                <Panel className="p-4">
                  <SectionTitle>Net Revenue Windows (UTC)</SectionTitle>
                  <dl className="space-y-1.5">
                    {[
                      { label: 'Today', cents: windows.todayCents },
                      { label: 'Yesterday', cents: windows.yesterdayCents },
                      { label: 'This week (from Monday)', cents: windows.thisWeekCents },
                      { label: 'This month to date', cents: windows.thisMonthCents },
                      { label: 'This quarter', cents: windows.thisQuarterCents },
                      { label: 'This year', cents: windows.thisYearCents },
                      { label: 'All time', cents: windows.allTimeCents },
                    ].map((row) => (
                      <div key={row.label} className="flex items-center justify-between rounded-md border border-white/6 bg-white/[0.02] px-3 py-1.5 text-[11px]">
                        <dt className="text-white/60">{row.label}</dt>
                        <dd className="font-mono font-bold text-white/85">{moneyFmt(row.cents)}</dd>
                      </div>
                    ))}
                  </dl>
                </Panel>
              </div>
            </div>

            <Panel className="p-4">
              <SectionTitle suffix={<span className="text-[10px] font-bold text-white/40">trailing {movement.windowDays} days · provider-billed, USD</span>}>MRR Movement & Net Revenue Retention</SectionTitle>
              {noBilled ? (
                <EmptyState label="No recurring-revenue movement to report." hint="Movement is measured from provider-billed subscriptions; none exists yet." />
              ) : (
                <>
                  <div className="grid gap-2 sm:grid-cols-3 xl:grid-cols-7">
                    {[
                      { label: 'Starting MRR', value: moneyFmt(movement.startingMrrCents), color: SLATE, title: `Subscriptions live ${movement.windowDays} days ago, at the price they had then` },
                      { label: 'New', value: `+${moneyFmt(movement.newMrrCents)}`, color: EMERALD, title: `${countFmt(movement.newSubscriptions)} new provider-billed subscription(s)` },
                      { label: 'Expansion', value: `+${moneyFmt(movement.expansionMrrCents)}`, color: GREEN, title: 'Upgrades, re-priced from the billing audit trail at list price' },
                      { label: 'Contraction', value: `−${moneyFmt(movement.contractionMrrCents)}`, color: AMBER, title: 'Downgrades, re-priced from the billing audit trail at list price' },
                      { label: 'Churned', value: `−${moneyFmt(movement.churnedMrrCents)}`, color: RED, title: `${countFmt(movement.churnedSubscriptions)} subscription(s) stopped granting access` },
                      { label: 'MRR today', value: moneyFmt(movement.endingMrrCents), color: CYAN, title: 'Starting + new + expansion − contraction − churned' },
                      { label: 'Net revenue retention', value: movement.nrrPct === null ? '—' : `${movement.nrrPct}%`, color: movement.nrrPct !== null && movement.nrrPct < 100 ? AMBER : EMERALD, title: movement.nrrPct === null ? `Needs provider-billed MRR that already existed ${movement.windowDays} days ago` : `(starting + expansion − contraction − churned) ÷ starting · gross retention ${movement.grrPct}%` },
                    ].map((cell) => (
                      <div key={cell.label} className="rounded-md border border-white/8 bg-white/[0.02] px-3 py-2.5" title={cell.title}>
                        <div className="font-mono text-base font-semibold text-white">{cell.value}</div>
                        <div className="mt-0.5 text-[10px] font-bold" style={{ color: cell.color }}>{cell.label}</div>
                      </div>
                    ))}
                  </div>
                  <p className="mt-2 text-[10px] leading-relaxed text-white/35">
                    {movement.nrrPct === null ? `Retention is not measurable yet: no provider-billed MRR existed ${movement.windowDays} days ago. ` : ''}
                    Expansion and contraction are re-priced from recorded plan changes at list price
                    {movement.unpricedChanges > 0 ? ` — ${countFmt(movement.unpricedChanges)} change(s) could not be re-priced and are shown as no movement` : ''}.
                    A subscription row that was cancelled and re-activated inside the window counts as retained.
                  </p>
                </>
              )}
            </Panel>

            <div className="grid gap-3 xl:grid-cols-[1fr_1.5fr_1fr]">
              <Panel className="p-4">
                <SectionTitle>Subscription Health</SectionTitle>
                {subs.total > 0 ? (
                  <Donut
                    segments={[
                      { label: 'Active', value: subs.active, color: EMERALD },
                      { label: 'Trial', value: subs.trial, color: CYAN },
                      { label: 'Renewal pending', value: subs.pendingRenewal, color: AMBER },
                      { label: 'Payment failed', value: subs.pastDue, color: RED },
                      { label: 'Suspended', value: subs.suspended, color: RED },
                      { label: 'Cancelled', value: subs.cancelled, color: SLATE },
                      { label: 'Expired', value: subs.expired, color: '#7F1D1D' },
                      { label: 'Awaiting payment', value: subs.incomplete, color: GOLD },
                    ].filter((segment) => segment.value > 0)}
                    centerValue={subs.healthScore === null ? '—' : String(subs.healthScore)}
                    centerLabel={subs.healthScore === null ? 'not scorable yet' : 'health score'}
                    centerColor={subs.healthScore !== null && subs.healthScore >= 70 ? EMERALD : AMBER}
                  />
                ) : (
                  <EmptyState label="No subscriptions yet." hint="Health scoring starts with the first provider-billed subscription." />
                )}
                <ul className="mt-3 space-y-1 text-[10px] text-white/45">
                  {subs.health.components.map((component) => (
                    <li key={component.key} className="flex justify-between gap-2">
                      <span>{component.label} ({component.weight}%)</span>
                      <span className="font-mono text-white/65">{component.valuePct === null ? `not measured` : `${component.valuePct}%`}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-2 text-[10px] leading-relaxed text-white/30">Unmeasured components are left out and their weight redistributed — they are never scored as 0 or 100.</p>
              </Panel>
              <Panel className="p-4">
                <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/forecast">Forecast engine</ViewAllLink>}>Revenue Forecast — actual vs projected</SectionTitle>
                {snapshot.forecast.revenueProjectionAvailable ? (
                  <Chart label="Actual completed-month revenue, month-to-date and linear forecast" option={forecastOption(snapshot)} height={250} />
                ) : (
                  <EmptyState label="Forecast withheld — not enough history." hint={snapshot.forecast.confidenceReason} />
                )}
              </Panel>
              <DataGapsPanel gaps={snapshot.dataGaps} />
            </div>

            <Panel className="p-4">
              <SectionTitle suffix={<ViewAllLink to="/dashboard/revenue-intelligence/subscriptions">Subscription analytics</ViewAllLink>}>Plan Performance</SectionTitle>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                {subs.planBreakdown.map((plan) => (
                  <div key={plan.plan} className="rounded-md border border-white/8 bg-white/[0.02] p-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-black uppercase tracking-wide" style={{ color: PLAN_COLORS[plan.plan] ?? GOLD }}>{plan.plan}</span>
                      <span className="text-[10px] text-white/40">{countFmt(plan.paying)} paying · {countFmt(plan.accessGranting)} with access</span>
                    </div>
                    <div className="mt-2 text-lg font-semibold text-white">{moneyFmt(plan.mrrCents)}<span className="ml-1 text-[10px] font-bold text-white/40">MRR</span></div>
                    <div className="mt-0.5 text-[10px] text-white/45">{moneyFmt(plan.collectedCents)} collected lifetime · {countFmt(plan.trial)} trial · {countFmt(plan.cancelled)} cancelled</div>
                  </div>
                ))}
              </div>
            </Panel>
          </>
        );
      }}
    </RevenuePage>
  );
}
