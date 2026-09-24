'use client';

import { Activity, FileJson, FileSpreadsheet, Gauge, LineChart, Repeat, Target, TrendingUp } from 'lucide-react';
import { AMBER, CYAN, EMERALD, GOLD, VIOLET, Badge, EmptyState, Panel, SectionTitle } from '@/app/dashboard/quantum-readiness/_shared';
import {
  AlertsPanel, Chart, Kpi, RevenuePage,
  countFmt, forecastOption, moneyFmt, mrrForecastOption, useRevenue,
} from '../_shared';

const REPORTS: Array<{ id: string; label: string; description: string }> = [
  { id: 'summary', label: 'Executive Summary', description: 'Every KPI with its basis: revenue, MRR/ARR, ARPU, LTV, churn, health, payment success, excluded subscriptions and the reconciliation result.' },
  { id: 'revenue', label: 'Revenue Report', description: 'Twelve UTC months of gross, refunded and net revenue, payments, failures, billed adds, churn and reconstructed month-end MRR.' },
  { id: 'subscriptions', label: 'Subscription Report', description: 'The full subscription ledger — plan, status, revenue class, provider, renewal, price source and MRR contribution.' },
  { id: 'customers', label: 'Customer Report', description: 'Every customer with a subscription or payment, ranked by lifetime net revenue, with MRR and failed payments.' },
  { id: 'payments', label: 'Payment Report', description: 'The complete payment ledger: every charge, failure and refund with transaction ids, currency and refund time.' },
];

const KIND_COLOR: Record<string, string> = { measured: EMERALD, derived: CYAN, assumption: AMBER };
const CONFIDENCE_COLOR: Record<string, string> = { high: EMERALD, medium: EMERALD, low: AMBER, 'insufficient-history': '#94A3B8' };

/** Forecast engine, report center and notification history. */
export default function ForecastReportsPage() {
  const { exportReport, exportState } = useRevenue();
  const exporting = exportState?.status === 'running';

  return (
    <RevenuePage
      title="Forecast & Report Center"
      subtitle="Projections built from completed months of real billing history, with every assumption labelled — plus audited, owner-only exports for finance, tax and board reviews."
    >
      {(snapshot) => {
        const { forecast, kpis } = snapshot;
        const last = forecast.horizon[forecast.horizon.length - 1] ?? null;
        const confidenceColor = CONFIDENCE_COLOR[forecast.confidence] ?? '#94A3B8';
        return (
          <>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
              <Kpi label="Current MRR (actual)" value={moneyFmt(kpis.mrrCents)} detail="projection baseline" color={CYAN} icon={Repeat}
                unmeasured={snapshot.subscriptionAnalytics.byClass.provider === 0 ? 'No provider-billed subscription yet' : null} />
              <Kpi label="Projected MRR (+6 mo)" value={moneyFmt(last?.projectedMrrCents ?? null)} detail={last ? `range ${moneyFmt(last.projectedMrrLowCents)} – ${moneyFmt(last.projectedMrrHighCents)}` : ''} color={VIOLET} icon={TrendingUp}
                unmeasured={forecast.mrrProjectionAvailable ? null : forecast.mrrProjectionReason} />
              <Kpi label="Projected ARR" value={moneyFmt(forecast.projectedArrCents)} detail="month-6 base MRR × 12" color={GOLD} icon={Target}
                unmeasured={forecast.projectedArrCents === null ? forecast.mrrProjectionReason : null} />
              <Kpi label="Projected Net (month 6)" value={moneyFmt(last?.projectedNetCents ?? null)} detail={`${last?.label ?? ''} · linear trend`} color={EMERALD} icon={LineChart}
                unmeasured={forecast.revenueProjectionAvailable ? null : forecast.revenueProjectionReason} />
              <Kpi label="Forecast Confidence" value={forecast.confidence.replace(/-/g, ' ')} detail={forecast.confidenceReason} color={confidenceColor} icon={Gauge} />
              <Kpi label="Backtest Error (MAPE)" value={forecast.backtest.mapePct === null ? '—' : `${forecast.backtest.mapePct}%`} detail={`${countFmt(forecast.backtest.points.length)} month(s) re-predicted`} color={forecast.backtest.mapePct !== null && forecast.backtest.mapePct > 25 ? AMBER : EMERALD} icon={Activity}
                unmeasured={forecast.backtest.mapePct === null ? forecast.backtest.reason || 'No month with revenue to score yet' : null} />
            </div>

            <div className="grid gap-3 xl:grid-cols-[1.6fr_1fr]">
              <Panel className="p-4">
                <SectionTitle suffix={<Badge color={confidenceColor}>{forecast.confidence.replace(/-/g, ' ')}</Badge>}>Net Revenue — actual vs forecast</SectionTitle>
                {snapshot.timeline.some((bucket) => bucket.payments > 0 || bucket.refundedCents > 0) || forecast.revenueProjectionAvailable
                  ? <Chart label="Actual completed-month net revenue, current month to date, and the linear forecast" option={forecastOption(snapshot)} height={300} />
                  : <EmptyState label="No revenue history to chart or project yet." hint={forecast.confidenceReason} />}
                {!forecast.revenueProjectionAvailable ? (
                  <p className="mt-3 rounded-md border border-amber-400/20 bg-amber-400/[0.05] px-3 py-2 text-[11px] text-amber-100/85">
                    Forecast withheld: {forecast.revenueProjectionReason} Only actuals are shown — a projection over too few points would present noise as a trend.
                  </p>
                ) : null}
              </Panel>
              <Panel className="p-4">
                <SectionTitle>Recurring Revenue Scenarios</SectionTitle>
                {forecast.mrrProjectionAvailable
                  ? <Chart label="Conservative, base and optimistic MRR projections for six months" option={mrrForecastOption(snapshot)} height={220} />
                  : <EmptyState label="MRR projection withheld." hint={forecast.mrrProjectionReason || undefined} />}
                <table className="mt-3 w-full text-left text-[11px]">
                  <thead>
                    <tr className="border-b border-white/10 text-[10px] uppercase tracking-[0.08em] text-white/40">
                      <th scope="col" className="pb-1.5 font-black">Scenario</th>
                      <th scope="col" className="pb-1.5 font-black">New × / Churn ×</th>
                      <th scope="col" className="pb-1.5 text-right font-black">MRR +6 mo</th>
                      <th scope="col" className="pb-1.5 text-right font-black">ARR</th>
                    </tr>
                  </thead>
                  <tbody>
                    {forecast.scenarios.map((scenario) => (
                      <tr key={scenario.key} className="border-b border-white/5 text-white/75">
                        <td className="py-1.5 font-semibold">{scenario.label}</td>
                        <td className="py-1.5 font-mono text-white/55">{scenario.newMultiplier} / {scenario.churnMultiplier}</td>
                        <td className="py-1.5 text-right font-mono">{moneyFmt(scenario.month6MrrCents)}</td>
                        <td className="py-1.5 text-right font-mono">{moneyFmt(scenario.month6ArrCents)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Panel>
            </div>

            <div className="grid gap-3 xl:grid-cols-[1.4fr_1fr]">
              <Panel className="p-4">
                <SectionTitle>Projection Table — forecast, not actual revenue</SectionTitle>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[640px] text-left text-xs">
                    <thead>
                      <tr className="border-b border-white/10 text-[10px] uppercase tracking-[0.08em] text-white/40">
                        <th scope="col" className="pb-2 pr-4 font-black">Month (UTC)</th>
                        <th scope="col" className="pb-2 pr-4 text-right font-black">Actual to date</th>
                        <th scope="col" className="pb-2 pr-4 text-right font-black">Forecast net</th>
                        <th scope="col" className="pb-2 pr-4 text-right font-black">Forecast MRR (low – high)</th>
                        <th scope="col" className="pb-2 text-right font-black">Paying subs</th>
                      </tr>
                    </thead>
                    <tbody>
                      {forecast.horizon.map((month) => (
                        <tr key={month.month} className="border-b border-white/5 text-white/75">
                          <td className="py-2 pr-4 font-bold text-white/85">{month.label}{month.isCurrentMonth ? <span className="ml-1.5 text-[10px] font-normal text-amber-300">in progress</span> : null}</td>
                          <td className="py-2 pr-4 text-right font-mono text-emerald-300">{month.isCurrentMonth ? moneyFmt(month.actualToDateCents) : <span className="text-white/25">—</span>}</td>
                          <td className="py-2 pr-4 text-right font-mono text-cyan-200">{moneyFmt(month.projectedNetCents)}</td>
                          <td className="py-2 pr-4 text-right font-mono">{month.projectedMrrCents === null ? '—' : <>{moneyFmt(month.projectedMrrCents)} <span className="text-[10px] text-white/35">({moneyFmt(month.projectedMrrLowCents)} – {moneyFmt(month.projectedMrrHighCents)})</span></>}</td>
                          <td className="py-2 text-right">{month.projectedSubscribers === null ? '—' : countFmt(month.projectedSubscribers)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>
              <Panel className="p-4">
                <SectionTitle>Forecast Inputs — measured vs assumed</SectionTitle>
                <ul className="space-y-1.5">
                  {forecast.assumptions.map((assumption) => (
                    <li key={assumption.label} className="rounded-md border border-white/6 bg-white/[0.02] px-3 py-2 text-[11px]">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-white/70">{assumption.label}</span>
                        <span className="flex items-center gap-2">
                          <span className="font-mono font-bold text-white/85">{assumption.value}</span>
                          <Badge color={KIND_COLOR[assumption.kind] ?? CYAN}>{assumption.kind}</Badge>
                        </span>
                      </div>
                      <div className="mt-0.5 text-[10px] text-white/40">{assumption.detail}</div>
                    </li>
                  ))}
                </ul>
              </Panel>
            </div>

            <div className="grid gap-3 xl:grid-cols-2">
              <Panel className="p-4">
                <SectionTitle>Forecast Accuracy — backtest</SectionTitle>
                {forecast.backtest.points.length ? (
                  <table className="w-full text-left text-[11px]">
                    <thead>
                      <tr className="border-b border-white/10 text-[10px] uppercase tracking-[0.08em] text-white/40">
                        <th scope="col" className="pb-1.5 font-black">Month</th>
                        <th scope="col" className="pb-1.5 text-right font-black">Predicted</th>
                        <th scope="col" className="pb-1.5 text-right font-black">Actual</th>
                        <th scope="col" className="pb-1.5 text-right font-black">Error</th>
                      </tr>
                    </thead>
                    <tbody>
                      {forecast.backtest.points.map((point) => (
                        <tr key={point.month} className="border-b border-white/5 text-white/75">
                          <td className="py-1.5">{point.label}</td>
                          <td className="py-1.5 text-right font-mono text-cyan-200">{moneyFmt(point.predictedCents)}</td>
                          <td className="py-1.5 text-right font-mono text-emerald-300">{moneyFmt(point.actualCents)}</td>
                          <td className="py-1.5 text-right font-mono">{point.absErrorPct === null ? '—' : `${point.absErrorPct}%`}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : <EmptyState label="Not enough history to backtest yet." hint={forecast.backtest.reason || undefined} />}
              </Panel>
              <Panel className="p-4">
                <SectionTitle>Methodology</SectionTitle>
                <ul className="list-disc space-y-1.5 pl-4 text-[11px] leading-relaxed text-white/55">
                  {forecast.methodology.map((line) => <li key={line}>{line}</li>)}
                </ul>
                <p className="mt-3 text-[10px] text-white/35">
                  History: {countFmt(forecast.historyMonths)} completed month{forecast.historyMonths === 1 ? '' : 's'}{forecast.firstEvidenceMonth ? ` since ${forecast.firstEvidenceMonth}` : ''}. Forecast values are never added to any actual revenue figure on this dashboard.
                </p>
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
                        disabled={exporting}
                        onClick={() => void exportReport(report.id, 'csv')}
                        className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-md border border-emerald-400/30 bg-emerald-500/10 px-2 py-1.5 text-[10px] font-bold text-emerald-200 transition hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <FileSpreadsheet className="h-3.5 w-3.5" aria-hidden="true" /> CSV / Excel
                      </button>
                      <button
                        type="button"
                        disabled={exporting}
                        onClick={() => void exportReport(report.id, 'json')}
                        aria-label={`Download ${report.label} as JSON`}
                        title="JSON for integrations"
                        className="inline-flex items-center justify-center gap-1.5 rounded-md border border-white/10 bg-black/25 px-2 py-1.5 text-[10px] font-bold text-white/65 transition hover:border-cyan-400/40 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <FileJson className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
              <p className="mt-3 text-[10px] text-white/35">
                Exports are generated from the complete billing dataset (not the on-screen page), carry a UTF-8 BOM for Excel, neutralise spreadsheet formulas in customer-supplied text, and are recorded in the owner audit trail.
              </p>
            </Panel>

            <Panel className="p-4">
              <SectionTitle>Notification Center</SectionTitle>
              <AlertsPanel alerts={snapshot.alerts} limit={12} />
            </Panel>
          </>
        );
      }}
    </RevenuePage>
  );
}
