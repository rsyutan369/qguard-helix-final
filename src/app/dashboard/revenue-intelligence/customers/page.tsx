'use client';

import { useMemo, useState } from 'react';
import { Download, RefreshCw, Search } from 'lucide-react';
import {
  AMBER, BLUE, CYAN, EMERALD, GOLD, RED, SLATE, VIOLET,
  EmptyState, HeaderButton, MetricCard, Panel, SectionTitle,
} from '@/app/dashboard/quantum-readiness/_shared';
import {
  Chart, DataGapsPanel, DataTable, PLAN_COLORS, RevenueShell, StatusPill,
  dateFmt, growthBarsOption, moneyFmt, pctFmt, useRevenueIntelligence,
} from '../_shared';

/** Customer Analytics — acquisition, value, retention, and the customer ledger. */
export default function CustomerAnalyticsPage() {
  const { snapshot, state, sseConnected, refresh, exportReport } = useRevenueIntelligence();
  const customers = snapshot.customerAnalytics;
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    const text = query.trim().toLowerCase();
    if (!text) return snapshot.customers;
    return snapshot.customers.filter((customer) =>
      [customer.email, customer.name, customer.plan].some((field) => String(field || '').toLowerCase().includes(text)),
    );
  }, [snapshot.customers, query]);

  return (
    <RevenueShell
      title="Customer Analytics"
      subtitle="Who pays, what they are worth, and how the customer base is growing — every figure from real accounts and invoices."
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>Refresh</HeaderButton>
          <HeaderButton icon={Download} onClick={() => exportReport('customers', 'csv')}>Export CSV</HeaderButton>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <MetricCard label="Total Users" value={String(customers.totalUsers)} detail="registered accounts" color={BLUE} />
        <MetricCard label="Customers" value={String(customers.totalCustomers)} detail="with billing history" color={CYAN} />
        <MetricCard label="Active Customers" value={String(customers.activeCustomers)} detail={`${customers.inactiveCustomers} inactive`} color={EMERALD} />
        <MetricCard label="New (30d)" value={String(customers.newCustomers30d)} detail={customers.customerGrowthPct === null ? 'recent signups' : `${pctFmt(customers.customerGrowthPct)} MoM`} color={GOLD} />
        <MetricCard label="ARPU" value={moneyFmt(customers.arpuCents)} detail="avg revenue / active customer" color={VIOLET} />
        <MetricCard label="LTV" value={moneyFmt(customers.ltvCents)} detail={customers.ltvCents === null ? 'needs churn history' : 'ARPU ÷ monthly churn'} color={CYAN} />
      </div>

      <div className="grid gap-3 xl:grid-cols-[1.5fr_1fr]">
        <Panel className="p-4">
          <SectionTitle>Customer & Subscription Growth — last 12 months</SectionTitle>
          {snapshot.timeline.some((bucket) => bucket.newCustomers > 0 || bucket.newSubscriptions > 0)
            ? <Chart option={growthBarsOption(snapshot.timeline)} height={270} />
            : <EmptyState label="No signups recorded in the last 12 months." />}
        </Panel>
        <div className="grid content-start gap-3">
          <Panel className="p-4">
            <SectionTitle>Customer Segments</SectionTitle>
            <div className="space-y-1.5">
              {[
                { label: 'Trial users', value: customers.trialUsers, color: CYAN },
                { label: 'Enterprise (Elite)', value: customers.enterpriseCustomers, color: GOLD },
                { label: 'Individual (Starter–Pro)', value: Math.max(0, customers.activeCustomers - customers.enterpriseCustomers), color: BLUE },
                { label: 'Cancelled / expired', value: customers.cancelledCustomers, color: SLATE },
              ].map((segment) => (
                <div key={segment.label} className="flex items-center justify-between rounded-md border border-white/6 bg-white/[0.02] px-3 py-2 text-[11px]">
                  <span className="inline-flex items-center gap-2 text-white/65">
                    <span className="h-2 w-2 rounded-full" style={{ backgroundColor: segment.color }} />
                    {segment.label}
                  </span>
                  <span className="font-mono font-bold text-white/90">{segment.value}</span>
                </div>
              ))}
            </div>
            <div className="mt-3 grid grid-cols-2 gap-2">
              <div className="rounded-md border border-white/8 bg-white/[0.02] px-2.5 py-2 text-center">
                <div className="text-sm font-semibold text-white">{customers.churnPct !== null || snapshot.kpis.retentionPct !== null ? `${snapshot.kpis.retentionPct ?? '—'}%` : '—'}</div>
                <div className="mt-0.5 text-[10px] font-bold" style={{ color: EMERALD }}>Retention</div>
              </div>
              <div className="rounded-md border border-white/8 bg-white/[0.02] px-2.5 py-2 text-center">
                <div className="text-sm font-semibold text-white">{moneyFmt(customers.averageCustomerValueCents)}</div>
                <div className="mt-0.5 text-[10px] font-bold" style={{ color: AMBER }}>Avg lifetime value paid</div>
              </div>
            </div>
          </Panel>
          <DataGapsPanel gaps={snapshot.dataGaps.filter((gap) => gap.metric.includes('DAU') || gap.metric.includes('CAC'))} />
        </div>
      </div>

      <Panel className="p-4">
        <SectionTitle
          suffix={
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/30" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search customers"
                className="h-8 w-56 rounded-md border border-white/10 bg-black/30 pl-8 pr-2 text-[11px] text-white/85 outline-none placeholder:text-white/25 focus:border-emerald-400/50"
              />
            </div>
          }
        >
          Customers by Lifetime Revenue ({filtered.length})
        </SectionTitle>
        <DataTable
          headers={['Customer', 'Plan', 'Status', 'Provider', 'Customer Since', 'Renews / Ends', 'Lifetime Revenue']}
          rows={filtered.map((customer) => [
            <div key="c" className="min-w-0">
              <div className="truncate font-semibold text-white/85">{customer.email ?? customer.userId.slice(0, 8)}</div>
              {customer.name ? <div className="truncate text-[10px] text-white/40">{customer.name}</div> : null}
            </div>,
            customer.plan ? <span key="p" className="font-bold" style={{ color: PLAN_COLORS[customer.plan] ?? SLATE }}>{customer.plan}</span> : <span key="p" className="text-white/35">—</span>,
            <StatusPill value={customer.status} />,
            <span key="pr">{customer.provider === 'google_play' ? 'Google Play' : customer.provider === 'paypal' ? 'PayPal' : customer.provider ?? '—'}</span>,
            <span key="d">{dateFmt(customer.since)}</span>,
            <span key="r">{dateFmt(customer.renewalDate)}</span>,
            <span key="v" className="font-mono font-bold" style={{ color: customer.lifetimeCents > 0 ? EMERALD : customer.lifetimeCents < 0 ? RED : undefined }}>{moneyFmt(customer.lifetimeCents)}</span>,
          ])}
          empty="No customers with billing history yet."
        />
      </Panel>
    </RevenueShell>
  );
}
