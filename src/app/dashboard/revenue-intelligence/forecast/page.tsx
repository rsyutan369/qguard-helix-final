'use client';

import { Download, FileJson, FileSpreadsheet, RefreshCw } from 'lucide-react';
import {
  AMBER, CYAN, EMERALD, GOLD, VIOLET,
  Badge, EmptyState, HeaderButton, MetricCard, Panel, SectionTitle,
} from '@/app/dashboard/quantum-readiness/_shared';
import {
  AlertsPanel, Chart, DataTable, RevenueShell, forecastOption, moneyFmt, useRevenueIntelligence,
} from '../_shared';

const REPORTS: Array<{ id: string; label: string; description: string }> = [
  { id: 'summary', label: 'Executive Summary', description: 'Every KPI on one sheet: revenue, MRR/ARR, ARPU, LTV, churn, health, payment success, period windows.' },
  { id: 'revenue', label: 'Revenue Report', description: 'Monthly gross / refunded / net revenue with payment volume and subscriber adds (12 months).' },
  { id: 'subscriptions', label: 'Subscription Report', description: 'Full subscriber roster: plan, status, provider, cycle, renewal dates, MRR contribution.' },
  { id: 'customers', label: 'Customer Report', description: 'Customers ranked by lifetime revenue with plan, provider, and tenure.' },
  { id: 'payments', label: 'Payment Report', description: 'The payment ledger: every charge, refund, and failure with method and status.' },
];

/** Forecast engine + Report Center + notification history. */
export default function ForecastReportsPage() {
  const { snapshot, state, sseConnected, refresh, exportReport } = useRevenueIntelligence();
  const { forecast, kpis } = snapshot;

  const lastHorizon = forecast.horizon[forecast.horizon.length - 1] ?? null;
  const confidenceColor = forecast.confidence === 'medium' ? EMERALD : forecast.confidence === 'low' ? AMBER : '#94A3B8';

  return (
    <RevenueShell
      title="Forecast & Report Center"
      subtitle="Deterministic, evidence-based projections of revenue and subscriber growth — plus downloadable reports for finance, tax, and board reviews."
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={<HeaderButton icon={RefreshCw} onClick={() => void refresh()}>Refresh</HeaderButton>}
    >
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <MetricCard label="Current MRR" value={moneyFmt(kpis.mrrCents)} detail="baseline for projection" color={CYAN} />
        <MetricCard label="Projected MRR (+6mo)" value={lastHorizon ? moneyFmt(lastHorizon.projectedMrrCents) : '—'} detail="growth-rate extension" color={VIOLET} />
        <MetricCard label="Projected ARR" value={forecast.projectedArrCents ? moneyFmt(forecast.projectedArrCents) : '—'} detail="6-month trajectory × 12" color={GOLD} />
        <MetricCard label="Projected Revenue (+6mo)" value={lastHorizon ? moneyFmt(lastHorizon.projectedNetCents) : '—'} detail="monthly net, month 6" color={EMERALD} />
        <MetricCard label="Forecast Confidence" value={forecast.confidence.replace(/-/g, ' ')} detail={`${forecast.observedMonths} observed month${forecast.observedMonths === 1 ? '' : 's'}`} color={confidenceColor} />
      </div>

      <div className="grid gap-3 xl:grid-cols-[1.6fr_1fr]">
        <Panel className="p-4">
          <SectionTitle suffix={<Badge color={confidenceColor}>{forecast.confidence.replace(/-/g, ' ')}</Badge>}>Revenue Forecast — actual + 6-month projection</SectionTitle>
          {snapshot.hasData && forecast.horizon.length
            ? <Chart option={forecastOption(snapshot)} height={300} />
            : <EmptyState label="Not enough billing history to project." hint="Projections start once invoiced revenue exists." />}
          <p className="mt-3 rounded-md border border-white/8 bg-white/[0.02] px-3 py-2 text-[10px] leading-relaxed text-white/45">
            <strong className="text-white/65">Methodology:</strong> {forecast.methodology || 'Least-squares linear trend of actual invoiced net revenue.'}
          </p>
        </Panel>
        <Panel className="p-4">
          <SectionTitle>Projection Table</SectionTitle>
          <DataTable
            headers={['Month', 'Projected Net', 'Projected MRR', 'New Subs']}
            rows={forecast.horizon.map((month) => [
              <span key="m" className="font-bold text-white/85">{month.label}</span>,
              <span key="n" className="font-mono text-emerald-300">{moneyFmt(month.projectedNetCents)}</span>,
              <span key="r" className="font-mono">{moneyFmt(month.projectedMrrCents)}</span>,
              <span key="s">{month.projectedNewSubscriptions}</span>,
            ])}
            empty="Projections appear once revenue history exists."
          />
        </Panel>
      </div>

      <Panel className="p-4">
        <SectionTitle>Report Center</SectionTitle>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          {REPORTS.map((report) => (
            <div key={report.id} className="flex flex-col rounded-md border border-white/8 bg-white/[0.02] p-3">
              <div className="text-[11px] font-black uppercase tracking-wide text-white/80">{report.label}</div>
              <p className="mt-1 flex-1 text-[10px] leading-relaxed text-white/45">{report.description}</p>
              <div className="mt-3 flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => exportReport(report.id, 'csv')}
                  className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-md border border-emerald-400/30 bg-emerald-500/10 px-2 py-1.5 text-[10px] font-bold text-emerald-200 transition hover:bg-emerald-500/20"
                >
                  <FileSpreadsheet className="h-3.5 w-3.5" /> CSV / Excel
                </button>
                <button
                  type="button"
                  onClick={() => exportReport(report.id, 'json')}
                  className="inline-flex items-center justify-center gap-1.5 rounded-md border border-white/10 bg-black/25 px-2 py-1.5 text-[10px] font-bold text-white/65 transition hover:border-cyan-400/40 hover:text-cyan-200"
                  title="JSON for API integrations"
                >
                  <FileJson className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
        <p className="mt-3 text-[10px] text-white/35">
          <Download className="mr-1 inline h-3 w-3" />
          CSV opens directly in Excel; JSON is integration-ready (same schema as GET /api/v1/revenue/export). All exports are owner-authenticated and generated live from the billing database.
        </p>
      </Panel>

      <div className="grid gap-3 xl:grid-cols-2">
        <Panel className="p-4">
          <SectionTitle>Notification Center</SectionTitle>
          <AlertsPanel alerts={snapshot.alerts} limit={10} />
        </Panel>
        <Panel className="p-4">
          <SectionTitle>Forecast Inputs (transparency)</SectionTitle>
          <div className="space-y-1.5 text-[11px]">
            {[
              { label: 'Observed revenue months', value: String(forecast.observedMonths) },
              { label: 'Active subscribers (baseline)', value: String(kpis.activeSubscribers) },
              { label: 'Current MRR (baseline)', value: moneyFmt(kpis.mrrCents) },
              { label: 'MoM revenue growth', value: kpis.revenueGrowthPct === null ? 'insufficient history' : `${kpis.revenueGrowthPct}%` },
              { label: 'Churn (30d)', value: kpis.churnPct === null ? 'insufficient history' : `${kpis.churnPct}%` },
            ].map((row) => (
              <div key={row.label} className="flex items-center justify-between rounded-md border border-white/6 bg-white/[0.02] px-3 py-2">
                <span className="text-white/60">{row.label}</span>
                <span className="font-mono font-bold text-white/85">{row.value}</span>
              </div>
            ))}
          </div>
          <p className="mt-3 text-[10px] leading-relaxed text-white/35">
            No AI guesswork is presented as fact: projections are a disclosed linear model over real invoices, and they carry a confidence grade tied to how much history exists.
          </p>
        </Panel>
      </div>
    </RevenueShell>
  );
}
