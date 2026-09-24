'use client';

import { useMemo, useState } from 'react';
import { Crown, Gem, UserCheck, UserPlus, Users, Wallet } from 'lucide-react';
import { AMBER, BLUE, CYAN, EMERALD, GOLD, RED, SLATE, VIOLET, EmptyState, Panel, SectionTitle } from '@/app/dashboard/quantum-readiness/_shared';
import {
  Chart, ClassPill, DataGapsPanel, DataTable, Kpi, LedgerLimitNote, PLAN_COLORS, RevenuePage, SearchBox, SelectBox, StatusPill,
  countFmt, dateFmt, growthBarsOption, moneyFmt, pctFmt, providerLabel, useRevenue,
  type CustomerRow,
} from '../_shared';

const SEGMENTS = [
  { value: 'all', label: 'All customers' },
  { value: 'paying', label: 'Paying now' },
  { value: 'lapsed', label: 'Lapsed / cancelled' },
  { value: 'unbilled', label: 'Unbilled access (manual / comp)' },
];

/** Customer Analytics — who pays, what they are worth, and the customer ledger. */
export default function CustomerAnalyticsPage() {
  const { openCustomer } = useRevenue();
  const [query, setQuery] = useState('');
  const [segment, setSegment] = useState('all');

  return (
    <RevenuePage
      title="Customer Analytics"
      subtitle="Registered accounts, paying customers and customer value — every figure from real accounts, subscriptions and invoices. Select a customer for their full billing record."
      report="customers"
    >
      {(snapshot) => {
        const customers = snapshot.customerAnalytics;
        const hasGrowth = snapshot.timeline.some((bucket) => bucket.newSignups > 0 || bucket.newSubscriptions > 0 || bucket.churnedSubscriptions > 0);
        return (
          <>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
              <Kpi label="Registered Users" value={countFmt(customers.registeredUsers)} detail="accounts on the platform" color={BLUE} icon={Users} />
              <Kpi label="Paying Customers" value={countFmt(customers.payingCustomers)} detail={`${countFmt(customers.customersWithBilling)} ever billed · ${countFmt(customers.lapsedCustomers)} lapsed`} color={EMERALD} icon={UserCheck} />
              <Kpi label="New Sign-ups (30d)" value={countFmt(customers.newSignups30d)} detail={customers.signupGrowthPct === null ? 'no prior 30-day baseline' : `${pctFmt(customers.signupGrowthPct)} vs prior 30 days`} color={GOLD} icon={UserPlus} />
              <Kpi label="ARPU" value={moneyFmt(customers.arpuCents)} detail="MRR ÷ paying customers" color={VIOLET} icon={Wallet}
                unmeasured={customers.arpuCents === null ? 'No paying customers yet' : null} />
              <Kpi label="LTV" value={moneyFmt(customers.ltvCents)} detail="ARPU ÷ monthly churn" color={CYAN} icon={Gem}
                unmeasured={customers.ltvCents === null ? (snapshot.kpis.churnPct === 0 ? 'Zero churn measured — LTV is unbounded' : 'Needs a measured churn rate') : null} />
              <Kpi label="Avg Lifetime Value" value={moneyFmt(customers.averageLifetimeValueCents)} detail="net revenue ÷ customers who paid" color={AMBER} icon={Crown}
                unmeasured={customers.averageLifetimeValueCents === null ? 'No customer has paid yet' : null} />
            </div>

            <div className="grid gap-3 xl:grid-cols-[1.5fr_1fr]">
              <Panel className="p-4">
                <SectionTitle>Sign-ups, New Billed Subscriptions & Churn — last 12 months</SectionTitle>
                {hasGrowth
                  ? <Chart label="Monthly new sign-ups, new billed subscriptions and churned subscriptions" option={growthBarsOption(snapshot.timeline)} height={270} />
                  : <EmptyState label="No sign-ups or subscriptions in the last 12 months." />}
              </Panel>
              <div className="grid content-start gap-3">
                <Panel className="p-4">
                  <SectionTitle>Customer Segments</SectionTitle>
                  <dl className="space-y-1.5">
                    {[
                      { label: 'Paying customers', value: customers.payingCustomers, color: EMERALD },
                      { label: 'Enterprise (paying Elite)', value: customers.enterpriseCustomers, color: GOLD },
                      { label: 'Trial users', value: customers.trialUsers, color: CYAN },
                      { label: 'Lapsed (billed before, not now)', value: customers.lapsedCustomers, color: RED },
                      { label: 'Cancelled / expired (billed)', value: customers.cancelledCustomers, color: SLATE },
                      { label: 'Manually managed access', value: customers.manualAccounts, color: AMBER },
                      { label: 'Complimentary / test access', value: customers.complimentaryAccounts, color: VIOLET },
                    ].map((row) => (
                      <div key={row.label} className="flex items-center justify-between rounded-md border border-white/6 bg-white/[0.02] px-3 py-2 text-[11px]">
                        <dt className="inline-flex items-center gap-2 text-white/65">
                          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: row.color }} aria-hidden="true" />
                          {row.label}
                        </dt>
                        <dd className="font-mono font-bold text-white/90">{countFmt(row.value)}</dd>
                      </div>
                    ))}
                  </dl>
                  <div className="mt-3 grid grid-cols-2 gap-2 text-center">
                    <div className="rounded-md border border-white/8 bg-white/[0.02] px-2.5 py-2" title={snapshot.kpis.retentionPct === null ? 'Needs billed subscriptions older than 30 days' : undefined}>
                      <div className="text-sm font-semibold text-white">{snapshot.kpis.retentionPct === null ? '—' : `${snapshot.kpis.retentionPct}%`}</div>
                      <div className="mt-0.5 text-[10px] font-bold" style={{ color: EMERALD }}>30-day retention</div>
                    </div>
                    <div className="rounded-md border border-white/8 bg-white/[0.02] px-2.5 py-2">
                      <div className="text-sm font-semibold text-white">{moneyFmt(snapshot.kpis.netRevenueCents)}</div>
                      <div className="mt-0.5 text-[10px] font-bold" style={{ color: AMBER }}>Lifetime net revenue</div>
                    </div>
                  </div>
                </Panel>
                <DataGapsPanel title="Customer dimensions not measured" gaps={snapshot.dataGaps.filter((gap) => /DAU|CAC|Country/.test(gap.metric))} />
              </div>
            </div>

            <CustomerLedger rows={snapshot.customers} total={snapshot.ledgerTotals.customers} query={query} setQuery={setQuery} segment={segment} setSegment={setSegment} openCustomer={openCustomer} />
          </>
        );
      }}
    </RevenuePage>
  );
}

function CustomerLedger({
  rows, total, query, setQuery, segment, setSegment, openCustomer,
}: {
  rows: CustomerRow[];
  total: number;
  query: string; setQuery: (value: string) => void;
  segment: string; setSegment: (value: string) => void;
  openCustomer: (userId: string) => void;
}) {
  const filtered = useMemo(() => {
    const text = query.trim().toLowerCase();
    return rows.filter((row) => {
      if (segment === 'paying' && row.mrrCents <= 0) return false;
      if (segment === 'lapsed' && (row.mrrCents > 0 || (row.paidInvoices === 0 && row.revenueClass !== 'provider'))) return false;
      if (segment === 'unbilled' && row.revenueClass !== 'manual' && row.revenueClass !== 'complimentary') return false;
      if (!text) return true;
      return [row.email, row.name, row.plan, row.userId].some((field) => String(field || '').toLowerCase().includes(text));
    });
  }, [rows, query, segment]);

  return (
    <Panel className="p-4">
      <SectionTitle
        suffix={
          <div className="flex flex-wrap items-center gap-2">
            <SearchBox value={query} onChange={setQuery} placeholder="Search email, name, plan" label="Search customers" />
            <SelectBox value={segment} onChange={setSegment} label="Customer segment" options={SEGMENTS} />
          </div>
        }
      >
        Customer Ledger ({countFmt(filtered.length)})
      </SectionTitle>
      <DataTable<CustomerRow>
        rows={filtered}
        rowKey={(row) => row.userId}
        empty={rows.length ? 'No customer matches these filters.' : 'No customers with a subscription or payment yet.'}
        initialSort={{ key: 'lifetime', direction: 'desc' }}
        onRowClick={(row) => openCustomer(row.userId)}
        rowLabel={(row) => `Open customer ${row.email || row.userId}`}
        columns={[
          {
            key: 'customer', header: 'Customer', sortValue: (row) => row.email || row.userId,
            render: (row) => (
              <div className="min-w-0">
                <div className="truncate font-semibold text-white/85">{row.email ?? row.userId.slice(0, 8)}</div>
                {row.name ? <div className="truncate text-[10px] text-white/40">{row.name}</div> : null}
              </div>
            ),
          },
          { key: 'plan', header: 'Plan', render: (row) => (row.plan ? <span className="font-bold" style={{ color: PLAN_COLORS[row.plan] ?? SLATE }}>{row.plan}</span> : <span className="text-white/35">—</span>), sortValue: (row) => row.plan },
          { key: 'status', header: 'Status', render: (row) => <StatusPill value={row.status} />, sortValue: (row) => row.status },
          { key: 'class', header: 'Revenue', render: (row) => <ClassPill value={row.revenueClass} />, sortValue: (row) => row.revenueClass },
          { key: 'provider', header: 'Provider', render: (row) => (row.provider ? providerLabel(row.provider) : '—'), sortValue: (row) => row.provider },
          { key: 'since', header: 'Customer Since', render: (row) => dateFmt(row.since), sortValue: (row) => row.since },
          { key: 'last', header: 'Last Payment', render: (row) => dateFmt(row.lastPaymentAt), sortValue: (row) => row.lastPaymentAt },
          { key: 'failed', header: 'Failed', align: 'right', render: (row) => <span style={{ color: row.failedPayments > 0 ? RED : undefined }}>{countFmt(row.failedPayments)}</span>, sortValue: (row) => row.failedPayments },
          { key: 'mrr', header: 'MRR', align: 'right', render: (row) => <span className="font-mono">{row.mrrCents > 0 ? moneyFmt(row.mrrCents) : '—'}</span>, sortValue: (row) => row.mrrCents },
          { key: 'lifetime', header: 'Lifetime Net', align: 'right', render: (row) => <span className="font-mono font-bold" style={{ color: row.lifetimeNetCents > 0 ? EMERALD : row.lifetimeNetCents < 0 ? RED : undefined }}>{moneyFmt(row.lifetimeNetCents)}</span>, sortValue: (row) => row.lifetimeNetCents },
        ]}
      />
      <LedgerLimitNote shown={rows.length} total={total} noun="customers" report="customers" />
    </Panel>
  );
}
