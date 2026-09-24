'use client';

import { useMemo, useState } from 'react';
import { ArrowDownUp, CalendarClock, HeartPulse, Layers, Repeat, UserMinus } from 'lucide-react';
import { AMBER, CYAN, EMERALD, GOLD, RED, SLATE, VIOLET, Panel, SectionTitle } from '@/app/dashboard/quantum-readiness/_shared';
import {
  ClassPill, CountBars, DataTable, Kpi, LedgerLimitNote, MoneyBars, PLAN_COLORS, RevenuePage, SearchBox, SelectBox, StatusPill,
  countFmt, dateFmt, moneyFmt, useRevenue,
  type SubscriberRow,
} from '../_shared';

const STATUS_OPTIONS = ['all', 'active', 'trial', 'pending_renewal', 'past_due', 'suspended', 'cancelled', 'expired', 'incomplete'];
const CLASS_OPTIONS = [
  { value: 'all', label: 'All revenue classes' },
  { value: 'provider', label: 'Provider-billed' },
  { value: 'manual', label: 'Manually managed' },
  { value: 'complimentary', label: 'Complimentary / test' },
];

/** Subscription Analytics — lifecycle, renewal intent, churn and the subscriber ledger. */
export default function SubscriptionAnalyticsPage() {
  const { openCustomer } = useRevenue();
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [classFilter, setClassFilter] = useState('all');

  return (
    <RevenuePage
      title="Subscription Analytics"
      subtitle="Every subscription on the ledger — status, renewal intent, churn, plan changes and MRR contribution — with provider-billed, manual and complimentary grants kept apart."
      report="subscriptions"
    >
      {(snapshot) => {
        const subs = snapshot.subscriptionAnalytics;
        const billed = subs.byClass.provider;
        return (
          <>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
              <Kpi label="Subscriptions" value={countFmt(subs.total)} detail={`${countFmt(billed)} billed · ${countFmt(subs.byClass.manual)} manual · ${countFmt(subs.byClass.complimentary)} comp/test`} color={CYAN} icon={Layers} />
              <Kpi label="Paying Active" value={countFmt(subs.payingActive)} detail={`${countFmt(subs.renewing)} auto-renewing · ${countFmt(subs.endingAtPeriodEnd)} ending`} color={EMERALD} icon={Repeat} />
              <Kpi label="Renewal Intent" value={subs.renewalRatePct === null ? '—' : `${subs.renewalRatePct}%`} detail="auto-renew share of paying subscriptions" color={EMERALD} icon={CalendarClock}
                unmeasured={subs.renewalRatePct === null ? 'No active provider-billed subscription' : null} />
              <Kpi label="Churn (30d)" value={subs.churnPct === null ? '—' : `${subs.churnPct}%`} detail={`${countFmt(subs.churnWindow.churned)} of ${countFmt(subs.churnWindow.base)} billed subs · retention ${subs.retentionPct}%`} color={subs.churnPct !== null && subs.churnPct > 5 ? RED : EMERALD} icon={UserMinus}
                unmeasured={subs.churnPct === null ? 'Needs billed subscriptions older than 30 days' : null} />
              <Kpi label="Plan Changes (30d)" value={`${countFmt(subs.upgrades30d)} ↑ · ${countFmt(subs.downgrades30d)} ↓`} detail="completed upgrades · downgrades (audit trail)" color={GOLD} icon={ArrowDownUp} />
              <Kpi label="Health Score" value={subs.healthScore === null ? '—' : `${subs.healthScore}/100`} detail={`${subs.health.measuredWeightPct}% of weight measured`} color={subs.healthScore !== null && subs.healthScore >= 70 ? EMERALD : AMBER} icon={HeartPulse}
                unmeasured={subs.healthReason} />
            </div>

            <div className="grid gap-3 xl:grid-cols-[1.2fr_1fr_1fr]">
              <Panel className="p-4">
                <SectionTitle>Status Board (all subscriptions)</SectionTitle>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { label: 'Active', value: subs.active, color: EMERALD },
                    { label: 'Trial', value: subs.trial, color: CYAN },
                    { label: 'Renewal pending', value: subs.pendingRenewal, color: AMBER },
                    { label: 'Payment failed (past due)', value: subs.pastDue, color: RED },
                    { label: 'Suspended', value: subs.suspended, color: RED },
                    { label: 'Cancelled', value: subs.cancelled, color: SLATE },
                    { label: 'Expired', value: subs.expired, color: RED },
                    { label: 'Awaiting payment', value: subs.incomplete, color: AMBER },
                    ...(subs.otherStatus ? [{ label: 'Other status', value: subs.otherStatus, color: SLATE }] : []),
                  ].map((status) => (
                    <div key={status.label} className="flex items-center justify-between rounded-md border border-white/6 bg-white/[0.02] px-3 py-2">
                      <span className="inline-flex items-center gap-2 text-[11px] text-white/65">
                        <span className="h-2 w-2 rounded-full" style={{ backgroundColor: status.color }} aria-hidden="true" />
                        {status.label}
                      </span>
                      <span className="font-mono text-sm font-bold text-white/90">{countFmt(status.value)}</span>
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-[10px] text-white/35">Counts sum to {countFmt(subs.total)} subscriptions. Access is granted by active, trial and pending-renewal only.</p>
              </Panel>
              <Panel className="p-4">
                <SectionTitle>MRR by Plan</SectionTitle>
                <MoneyBars rows={subs.planBreakdown.filter((plan) => plan.mrrCents > 0).map((plan) => ({ label: plan.plan, cents: plan.mrrCents, sub: `${countFmt(plan.paying)} paying` }))} colorFor={(label) => PLAN_COLORS[label] ?? SLATE} empty="No provider-billed recurring revenue yet." />
                {subs.manualContractMonthlyCents > 0 ? (
                  <p className="mt-3 text-[10px] leading-relaxed" style={{ color: AMBER }}>
                    Manually managed subscriptions carry {moneyFmt(subs.manualContractMonthlyCents)}/month of contract value that no provider has billed — excluded from MRR.
                  </p>
                ) : null}
              </Panel>
              <Panel className="p-4">
                <SectionTitle>Subscriptions with Access, by Plan</SectionTitle>
                <CountBars rows={subs.planBreakdown.filter((plan) => plan.accessGranting > 0).map((plan) => ({ label: plan.plan, value: plan.accessGranting }))} colorFor={(label) => PLAN_COLORS[label] ?? SLATE} empty="No subscription currently grants access." unit="with access" />
                <div className="mt-4 grid grid-cols-3 gap-2 text-center text-[10px]">
                  {([
                    ['Billed', subs.accessGrantingByClass.provider, EMERALD],
                    ['Manual', subs.accessGrantingByClass.manual, AMBER],
                    ['Comp/test', subs.accessGrantingByClass.complimentary, VIOLET],
                  ] as const).map(([label, value, color]) => (
                    <div key={label} className="rounded-md border border-white/8 bg-white/[0.02] px-2 py-2">
                      <div className="font-mono text-sm font-semibold text-white">{countFmt(value)}</div>
                      <div className="font-bold" style={{ color }}>{label}</div>
                    </div>
                  ))}
                </div>
              </Panel>
            </div>

            <SubscriberLedger rows={snapshot.subscribers} totals={snapshot.ledgerTotals} query={query} setQuery={setQuery} statusFilter={statusFilter} setStatusFilter={setStatusFilter} classFilter={classFilter} setClassFilter={setClassFilter} openCustomer={openCustomer} />
          </>
        );
      }}
    </RevenuePage>
  );
}

function SubscriberLedger({
  rows, totals, query, setQuery, statusFilter, setStatusFilter, classFilter, setClassFilter, openCustomer,
}: {
  rows: SubscriberRow[];
  totals: { subscribers: number; limit: number };
  query: string; setQuery: (value: string) => void;
  statusFilter: string; setStatusFilter: (value: string) => void;
  classFilter: string; setClassFilter: (value: string) => void;
  openCustomer: (userId: string) => void;
}) {
  const filtered = useMemo(() => {
    const text = query.trim().toLowerCase();
    return rows.filter((row) => {
      if (statusFilter !== 'all' && String(row.status).toLowerCase() !== statusFilter) return false;
      if (classFilter !== 'all' && row.revenueClass !== classFilter) return false;
      if (!text) return true;
      return [row.email, row.plan, row.providerLabel, row.userId].some((field) => String(field || '').toLowerCase().includes(text));
    });
  }, [rows, query, statusFilter, classFilter]);

  return (
    <Panel className="p-4">
      <SectionTitle
        suffix={
          <div className="flex flex-wrap items-center gap-2">
            <SearchBox value={query} onChange={setQuery} placeholder="Search email, plan, provider" label="Search subscribers" />
            <SelectBox value={statusFilter} onChange={setStatusFilter} label="Filter by status" options={STATUS_OPTIONS.map((status) => ({ value: status, label: status === 'all' ? 'All statuses' : status.replace(/_/g, ' ') }))} />
            <SelectBox value={classFilter} onChange={setClassFilter} label="Filter by revenue class" options={CLASS_OPTIONS} />
          </div>
        }
      >
        Subscriber Ledger ({countFmt(filtered.length)})
      </SectionTitle>
      <DataTable<SubscriberRow>
        rows={filtered}
        rowKey={(row) => row.id}
        empty={rows.length ? 'No subscriber matches these filters.' : 'No subscriptions yet — the ledger fills from billing_subscriptions.'}
        initialSort={{ key: 'updated', direction: 'desc' }}
        onRowClick={(row) => openCustomer(row.userId)}
        rowLabel={(row) => `Open customer ${row.email || row.userId}`}
        columns={[
          { key: 'email', header: 'Subscriber', render: (row) => <span className="font-semibold text-white/85">{row.email ?? row.userId.slice(0, 8)}</span>, sortValue: (row) => row.email || row.userId },
          { key: 'plan', header: 'Plan', render: (row) => <span className="font-bold" style={{ color: PLAN_COLORS[row.plan || ''] ?? SLATE }}>{row.plan || '—'}</span>, sortValue: (row) => row.plan },
          { key: 'status', header: 'Status', render: (row) => <StatusPill value={row.status} />, sortValue: (row) => row.status },
          { key: 'class', header: 'Revenue', render: (row) => <ClassPill value={row.revenueClass} title={row.classReason} />, sortValue: (row) => row.revenueClass },
          { key: 'provider', header: 'Provider', render: (row) => row.providerLabel, sortValue: (row) => row.providerLabel },
          { key: 'cycle', header: 'Cycle', render: (row) => (row.billingCycle === 'annual' ? 'Yearly' : 'Monthly'), sortValue: (row) => row.billingCycle },
          { key: 'renew', header: 'Auto-renew', render: (row) => <span style={{ color: row.autoRenew && !row.cancelAtPeriodEnd ? EMERALD : AMBER }}>{row.cancelAtPeriodEnd ? 'Ends' : row.autoRenew ? 'Yes' : 'No'}</span>, sortValue: (row) => (row.autoRenew ? 1 : 0) },
          { key: 'since', header: 'Since', render: (row) => dateFmt(row.since), sortValue: (row) => row.since },
          { key: 'renewal', header: 'Renews / Ends', render: (row) => dateFmt(row.renewalDate), sortValue: (row) => row.renewalDate },
          { key: 'mrr', header: 'MRR', align: 'right', render: (row) => <span className="font-mono font-bold" style={{ color: row.mrrCents > 0 ? EMERALD : 'rgba(255,255,255,0.35)' }} title={row.mrrCents > 0 ? undefined : `${moneyFmt(row.monthlyValueCents)}/mo list value, not counted: ${row.classReason}`}>{row.mrrCents > 0 ? moneyFmt(row.mrrCents) : '—'}</span>, sortValue: (row) => row.mrrCents },
          { key: 'updated', header: 'Updated', render: (row) => dateFmt(row.updatedAt), sortValue: (row) => row.updatedAt },
        ]}
      />
      <LedgerLimitNote shown={rows.length} total={totals.subscribers} noun="subscriptions" report="subscriptions" />
    </Panel>
  );
}
