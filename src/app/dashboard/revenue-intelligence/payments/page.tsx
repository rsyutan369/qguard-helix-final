'use client';

import { useMemo, useState } from 'react';
import { CheckCircle2, Clock, Gauge, ReceiptText, RotateCcw, XCircle } from 'lucide-react';
import { AMBER, CYAN, EMERALD, RED, SLATE, VIOLET, Donut, EmptyState, Panel, SectionTitle } from '@/app/dashboard/quantum-readiness/_shared';
import {
  DataGapsPanel, DataTable, Kpi, LedgerLimitNote, MoneyBars, RevenuePage, SearchBox, SelectBox, StatusPill,
  countFmt, dateTimeFmt, moneyFmt, providerColor, timeAgo, useRevenue,
  type InvoiceLedgerRow,
} from '../_shared';

const STATUS_OPTIONS = [
  { value: 'all', label: 'All outcomes' },
  { value: 'paid', label: 'Paid' },
  { value: 'failed', label: 'Failed' },
  { value: 'refunded', label: 'Refunded' },
  { value: 'pending', label: 'Pending' },
];

/** Payment Analytics — outcomes, success rate, refunds and the payment ledger. */
export default function PaymentAnalyticsPage() {
  const { openCustomer } = useRevenue();
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [methodFilter, setMethodFilter] = useState('all');

  return (
    <RevenuePage
      title="Payment Analytics"
      subtitle="Every recorded charge across PayPal and Google Play — collected, failed, refunded and pending — with webhook-verified outcomes and the full payment ledger."
      report="payments"
    >
      {(snapshot) => {
        const payments = snapshot.paymentAnalytics;
        const methods = Array.from(new Set(snapshot.invoices.map((row) => row.method || 'Other'))).sort();
        return (
          <>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
              <Kpi label="Collected" value={countFmt(payments.successful)} detail={`${moneyFmt(snapshot.kpis.grossRevenueCents)} gross`} color={EMERALD} icon={CheckCircle2} />
              <Kpi label="Failed" value={countFmt(payments.failed)} detail={payments.failed ? `${moneyFmt(payments.failedAttemptCents)} attempted, not collected` : 'declined or errored charges'} color={payments.failed > 0 ? RED : SLATE} icon={XCircle} />
              <Kpi label="Refunded" value={countFmt(payments.refunds)} detail={moneyFmt(payments.refundedCents)} color={AMBER} icon={RotateCcw} />
              <Kpi label="Pending" value={countFmt(payments.pending)} detail="awaiting settlement" color={CYAN} icon={Clock} />
              <Kpi label="Success Rate" value={payments.successRatePct === null ? '—' : `${payments.successRatePct}%`} detail={`collected ÷ ${countFmt(payments.attempted)} attempts`} color={payments.successRatePct !== null && payments.successRatePct < 90 ? AMBER : EMERALD} icon={Gauge}
                unmeasured={payments.successRatePct === null ? 'No payment attempt recorded yet' : null} />
              <Kpi label="Average Payment" value={moneyFmt(payments.averagePaymentCents)} detail={`${countFmt(payments.totalRecords)} payment records`} color={VIOLET} icon={ReceiptText}
                unmeasured={payments.averagePaymentCents === null ? 'No collected payment yet' : null} />
            </div>

            <div className="grid gap-3 xl:grid-cols-3">
              <Panel className="p-4">
                <SectionTitle>Payment Outcomes</SectionTitle>
                {payments.totalRecords > 0 ? (
                  <Donut
                    segments={[
                      { label: 'Paid', value: payments.successful, color: EMERALD },
                      { label: 'Failed', value: payments.failed, color: RED },
                      { label: 'Refunded', value: payments.refunds, color: AMBER },
                      { label: 'Pending', value: payments.pending, color: SLATE },
                    ].filter((segment) => segment.value > 0)}
                    centerValue={countFmt(payments.totalRecords)}
                    centerLabel="payment records"
                    centerColor={EMERALD}
                  />
                ) : (
                  <EmptyState label="No payments recorded yet." hint="PayPal PAYMENT.SALE.* and BILLING.SUBSCRIPTION.PAYMENT.FAILED webhooks write this ledger." />
                )}
              </Panel>
              <Panel className="p-4">
                <SectionTitle>Collected Revenue by Provider</SectionTitle>
                <MoneyBars rows={snapshot.revenueByProvider.map((row) => ({ label: row.label, cents: row.cents, sub: `${countFmt(row.count)} payments` }))} colorFor={providerColor} empty="No provider has collected a payment yet." />
                <p className="mt-3 text-[10px] leading-relaxed text-white/35">
                  PayPal outcomes arrive by signature-verified webhook, claimed once per event id (duplicates and concurrent redeliveries are ignored). Google Play purchases are verified server-side with the Play Developer API.
                </p>
              </Panel>
              <DataGapsPanel title="Payment data not captured" gaps={snapshot.dataGaps.filter((gap) => /Stripe|Google Play|tax/i.test(gap.metric))} />
            </div>

            <PaymentLedger rows={snapshot.invoices} total={snapshot.ledgerTotals.invoices} methods={methods} query={query} setQuery={setQuery} statusFilter={statusFilter} setStatusFilter={setStatusFilter} methodFilter={methodFilter} setMethodFilter={setMethodFilter} openCustomer={openCustomer} />
          </>
        );
      }}
    </RevenuePage>
  );
}

function PaymentLedger({
  rows, total, methods, query, setQuery, statusFilter, setStatusFilter, methodFilter, setMethodFilter, openCustomer,
}: {
  rows: InvoiceLedgerRow[];
  total: number;
  methods: string[];
  query: string; setQuery: (value: string) => void;
  statusFilter: string; setStatusFilter: (value: string) => void;
  methodFilter: string; setMethodFilter: (value: string) => void;
  openCustomer: (userId: string) => void;
}) {
  const filtered = useMemo(() => {
    const text = query.trim().toLowerCase();
    return rows.filter((row) => {
      if (statusFilter !== 'all' && row.status !== statusFilter) return false;
      if (methodFilter !== 'all' && (row.method || 'Other') !== methodFilter) return false;
      if (!text) return true;
      return [row.email, row.invoiceId, row.transactionId, row.plan, row.method].some((field) => String(field || '').toLowerCase().includes(text));
    });
  }, [rows, query, statusFilter, methodFilter]);

  return (
    <Panel className="p-4">
      <SectionTitle
        suffix={
          <div className="flex flex-wrap items-center gap-2">
            <SearchBox value={query} onChange={setQuery} placeholder="Search invoice, transaction, email" label="Search payments" />
            <SelectBox value={statusFilter} onChange={setStatusFilter} label="Filter by outcome" options={STATUS_OPTIONS} />
            <SelectBox value={methodFilter} onChange={setMethodFilter} label="Filter by provider" options={[{ value: 'all', label: 'All providers' }, ...methods.map((method) => ({ value: method, label: method }))]} />
          </div>
        }
      >
        Payment Ledger ({countFmt(filtered.length)})
      </SectionTitle>
      <DataTable<InvoiceLedgerRow>
        rows={filtered}
        rowKey={(row) => row.id}
        empty={rows.length ? 'No payment matches these filters.' : 'No payments in the ledger yet — rows appear with the first real charge.'}
        initialSort={{ key: 'when', direction: 'desc' }}
        onRowClick={(row) => openCustomer(row.userId)}
        rowLabel={(row) => `Open customer for invoice ${row.invoiceId}`}
        columns={[
          { key: 'when', header: 'When (UTC)', sortValue: (row) => row.paidAt, render: (row) => (<div><div className="whitespace-nowrap text-white/80">{dateTimeFmt(row.paidAt)}</div><div className="text-[10px] text-white/35">{timeAgo(row.paidAt)}</div></div>) },
          { key: 'invoice', header: 'Invoice', sortValue: (row) => row.invoiceId, render: (row) => <span className="font-mono text-[10px] text-white/55" title={row.transactionId || row.invoiceId}>{row.invoiceId.length > 26 ? `${row.invoiceId.slice(0, 26)}…` : row.invoiceId}</span> },
          { key: 'customer', header: 'Customer', sortValue: (row) => row.email || row.userId, render: (row) => <span className="font-semibold text-white/85">{row.email ?? row.userId.slice(0, 8)}</span> },
          { key: 'plan', header: 'Plan', sortValue: (row) => row.plan, render: (row) => row.plan || '—' },
          { key: 'method', header: 'Provider', sortValue: (row) => row.method, render: (row) => row.method || '—' },
          {
            key: 'amount', header: 'Amount', align: 'right', sortValue: (row) => row.amountCents,
            render: (row) => (
              <span className="whitespace-nowrap font-mono font-bold" style={{ color: row.status === 'paid' ? EMERALD : row.status === 'refunded' ? AMBER : row.status === 'failed' ? RED : undefined }}>
                {moneyFmt(row.amountCents, row.currency)}
                {row.refundedCents > 0 ? <span className="ml-1 text-[10px] text-amber-300">(−{moneyFmt(row.refundedCents, row.currency)})</span> : null}
                {!row.inReportingCurrency ? <span className="ml-1 text-[10px] text-amber-300">not in USD totals</span> : null}
              </span>
            ),
          },
          { key: 'status', header: 'Outcome', sortValue: (row) => row.status, render: (row) => <StatusPill value={row.status} /> },
        ]}
      />
      <LedgerLimitNote shown={rows.length} total={total} noun="payment records" report="payments" />
      <p className="mt-2 text-[10px] text-white/30">A failed row shows the amount PayPal attempted to charge; nothing was collected and it is excluded from every revenue total.</p>
    </Panel>
  );
}
