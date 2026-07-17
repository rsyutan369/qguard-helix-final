'use client';

import { useMemo, useState } from 'react';
import { Download, RefreshCw, Search } from 'lucide-react';
import {
  AMBER, BLUE, CYAN, EMERALD, GREEN, RED, SLATE, VIOLET,
  BarList, Donut, EmptyState, HeaderButton, MetricCard, Panel, SectionTitle,
} from '@/app/dashboard/quantum-readiness/_shared';
import {
  DataGapsPanel, DataTable, RevenueShell, StatusPill, dateFmt, moneyFmt, timeAgo, useRevenueIntelligence,
} from '../_shared';

/** Payment Analytics — provider aggregation, success rates, and the payment ledger. */
export default function PaymentAnalyticsPage() {
  const { snapshot, state, sseConnected, refresh, exportReport } = useRevenueIntelligence();
  const payments = snapshot.paymentAnalytics;
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  const filtered = useMemo(() => {
    const text = query.trim().toLowerCase();
    return snapshot.invoices.filter((invoice) => {
      if (statusFilter !== 'all' && invoice.status !== statusFilter) return false;
      if (!text) return true;
      return [invoice.email, invoice.invoiceId, invoice.plan, invoice.method].some((field) => String(field || '').toLowerCase().includes(text));
    });
  }, [snapshot.invoices, query, statusFilter]);

  return (
    <RevenueShell
      title="Payment Analytics"
      subtitle="Every charge across PayPal, Google Play, and manual billing — success rates, failures, refunds, and the full payment ledger."
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>Refresh</HeaderButton>
          <HeaderButton icon={Download} onClick={() => exportReport('payments', 'csv')}>Export CSV</HeaderButton>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <MetricCard label="Successful" value={String(payments.successful)} detail="completed payments" color={EMERALD} />
        <MetricCard label="Failed" value={String(payments.failed)} detail="declined / errored" color={payments.failed > 0 ? RED : SLATE} />
        <MetricCard label="Refunds" value={String(payments.refunds)} detail={moneyFmt(payments.refundedCents)} color={AMBER} />
        <MetricCard label="Pending" value={String(payments.pending)} detail="awaiting settlement" color={CYAN} />
        <MetricCard label="Success Rate" value={payments.successRatePct === null ? '—' : `${payments.successRatePct}%`} detail="of attempted charges" color={payments.successRatePct !== null && payments.successRatePct < 90 ? AMBER : EMERALD} ring={payments.successRatePct ?? undefined} />
        <MetricCard label="Avg Payment" value={moneyFmt(payments.averagePaymentCents)} detail={`${payments.totalPayments} total records`} color={VIOLET} />
      </div>

      <div className="grid gap-3 xl:grid-cols-3">
        <Panel className="p-4">
          <SectionTitle>Payment Outcomes</SectionTitle>
          {payments.totalPayments > 0 ? (
            <Donut
              segments={[
                { label: 'Successful', value: payments.successful, color: EMERALD },
                { label: 'Failed', value: payments.failed, color: RED },
                { label: 'Refunded', value: payments.refunds, color: AMBER },
                { label: 'Pending', value: payments.pending, color: SLATE },
              ].filter((segment) => segment.value > 0)}
              centerValue={String(payments.totalPayments)}
              centerLabel="payments"
              centerColor={EMERALD}
            />
          ) : (
            <EmptyState label="No payments recorded yet." />
          )}
        </Panel>
        <Panel className="p-4">
          <SectionTitle>Providers by Revenue</SectionTitle>
          <BarList
            rows={snapshot.revenueByProvider.map((provider) => ({ label: provider.label, value: Math.round(provider.cents / 100) }))}
            colorFor={(row) => (row.label === 'PayPal' ? BLUE : row.label === 'Google Play' ? GREEN : SLATE)}
            unit=" USD"
          />
          <p className="mt-3 text-[10px] leading-relaxed text-white/35">
            Providers appear as soon as they process a real payment. PayPal settles via verified webhooks; Google Play via server-verified purchase tokens + RTDN.
          </p>
        </Panel>
        <DataGapsPanel gaps={snapshot.dataGaps.filter((gap) => gap.metric.includes('Stripe'))} />
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
                  placeholder="Search invoice / email / plan"
                  className="h-8 w-56 rounded-md border border-white/10 bg-black/30 pl-8 pr-2 text-[11px] text-white/85 outline-none placeholder:text-white/25 focus:border-emerald-400/50"
                />
              </div>
              <select
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value)}
                className="h-8 rounded-md border border-white/10 bg-black/30 px-2 text-[11px] text-white/75 outline-none focus:border-emerald-400/50"
              >
                {['all', 'paid', 'failed', 'refunded', 'pending'].map((status) => (
                  <option key={status} value={status} className="bg-[#0B1526]">{status === 'all' ? 'All statuses' : status}</option>
                ))}
              </select>
            </div>
          }
        >
          Payment Ledger ({filtered.length})
        </SectionTitle>
        <DataTable
          headers={['When', 'Invoice', 'Customer', 'Plan', 'Method', 'Amount', 'Status']}
          rows={filtered.map((invoice) => [
            <div key="w">
              <div className="text-white/80">{dateFmt(invoice.at)}</div>
              <div className="text-[10px] text-white/35">{timeAgo(invoice.at)}</div>
            </div>,
            <span key="i" className="font-mono text-[10px] text-white/55">{invoice.invoiceId.slice(0, 22)}</span>,
            <span key="c" className="font-semibold text-white/85">{invoice.email ?? invoice.userId.slice(0, 8)}</span>,
            <span key="p">{invoice.plan}</span>,
            <span key="m">{invoice.method ?? '—'}</span>,
            <span key="a" className="font-mono font-bold" style={{ color: invoice.status === 'paid' ? EMERALD : invoice.status === 'refunded' ? AMBER : invoice.status === 'failed' ? RED : undefined }}>
              {moneyFmt(invoice.amountCents)} {invoice.currency !== 'USD' ? invoice.currency : ''}
            </span>,
            <StatusPill value={invoice.status} />,
          ])}
          empty="No payments in the ledger yet — rows appear with the first real charge."
        />
        {snapshot.invoices.length >= 200 ? <p className="mt-2 text-[10px] text-white/35">Showing the 200 most recent payment records.</p> : null}
      </Panel>
    </RevenueShell>
  );
}
