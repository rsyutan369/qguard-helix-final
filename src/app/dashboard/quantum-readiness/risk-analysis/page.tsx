'use client';

import { useMemo } from 'react';
import { motion } from 'framer-motion';
import { Download, ListChecks, RefreshCw, ShieldAlert } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import {
  Badge,
  BarList,
  Donut,
  EmptyState,
  HeaderButton,
  MetricCard,
  Panel,
  QuantumReadinessShell,
  SectionTitle,
  TrendChart,
  ViewAllLink,
  integerFmt,
  percentLabel,
  riskTone,
  severityColor,
  useQuantumReadiness,
  BLUE,
  GOLD,
  GREEN,
  ORANGE,
  RED,
} from '../_shared';

export default function RiskAnalysisPage() {
  const navigate = useNavigate();
  const { snapshot, state, sseConnected, refresh, downloadJson } = useQuantumReadiness();
  const { scores, riskDistribution } = snapshot;

  const totalFindings = riskDistribution.critical + riskDistribution.high + riskDistribution.medium + riskDistribution.low;

  const severitySegments = [
    { label: 'Critical', value: riskDistribution.critical, color: RED },
    { label: 'High', value: riskDistribution.high, color: ORANGE },
    { label: 'Medium', value: riskDistribution.medium, color: GOLD },
    { label: 'Low', value: riskDistribution.low, color: GREEN },
  ];

  // Domain breakdowns derived from the risk factor model.
  const breakdowns = useMemo(() => {
    const factor = (label: string) => snapshot.riskFactors.find((f) => f.label.includes(label))?.score ?? 0;
    return [
      { label: 'HNDL Exposure', value: scores.hndlRisk },
      { label: 'Crypto Exposure', value: scores.cryptoExposure },
      { label: 'RSA / ECC Exposure', value: factor('RSA') },
      { label: 'Internet-Facing', value: factor('Internet') },
      { label: 'Critical Dependency', value: factor('Dependency') },
      { label: 'Severity Pressure', value: factor('Severity') },
    ];
  }, [snapshot.riskFactors, scores.hndlRisk, scores.cryptoExposure]);

  const kpis = [
    { label: 'Quantum Risk', value: integerFmt(scores.quantumRisk), suffix: '/100', detail: scores.quantumRiskLevel, color: riskTone(scores.quantumRisk), ring: scores.quantumRisk },
    { label: 'HNDL Risk', value: integerFmt(scores.hndlRisk), suffix: '/100', detail: scores.hndlRiskLevel, color: riskTone(scores.hndlRisk), ring: scores.hndlRisk },
    { label: 'Crypto Exposure', value: integerFmt(scores.cryptoExposure), suffix: '/100', detail: scores.cryptoExposureLevel, color: riskTone(scores.cryptoExposure), ring: scores.cryptoExposure },
    { label: 'Critical Findings', value: integerFmt(riskDistribution.critical), detail: `${integerFmt(riskDistribution.high)} high`, color: RED, icon: ShieldAlert },
    { label: 'Total Findings', value: integerFmt(totalFindings), detail: 'Across all sources', color: BLUE, icon: ListChecks },
    { label: 'PQC Adoption', value: percentLabel(scores.pqcAdoption), detail: 'Quantum-safe coverage', color: GREEN, ring: scores.pqcAdoption },
  ];

  return (
    <QuantumReadinessShell
      title="Quantum Risk Analysis"
      subtitle="Technical risk center for prioritizing cryptographic exposure and Harvest-Now-Decrypt-Later risk. Every score traces to scan, certificate, key and runtime evidence."
      badge={<Badge color={riskTone(scores.quantumRisk)}>{scores.quantumRiskLevel} Risk</Badge>}
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>
            Refresh
          </HeaderButton>
          <HeaderButton icon={Download} onClick={() => downloadJson('quantum-risk-analysis')}>
            Export Evidence
          </HeaderButton>
        </>
      }
    >
      {/* KPIs */}
      <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
        {kpis.map((kpi) => (
          <div key={kpi.label}>
            <MetricCard {...kpi} />
          </div>
        ))}
      </motion.section>

      {/* Severity distribution + domain breakdown */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5">
          <SectionTitle>Risk Severity Distribution</SectionTitle>
          {totalFindings > 0 ? (
            <Donut segments={severitySegments} centerValue={integerFmt(totalFindings)} centerLabel="Findings" centerColor={riskTone(scores.quantumRisk)} />
          ) : (
            <EmptyState label="No findings recorded." hint="Run a discovery scan to populate severity distribution." />
          )}
        </Panel>

        <Panel className="p-5 xl:col-span-7">
          <SectionTitle suffix={<span className="text-[11px] text-white/40">Score per domain (0–100)</span>}>Risk Domain Breakdown</SectionTitle>
          <BarList rows={breakdowns} colorFor={(row) => riskTone(row.value)} max={100} />
        </Panel>
      </section>

      {/* Risk factors + trend */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-5">
          <SectionTitle>Risk Factor Analysis</SectionTitle>
          {snapshot.riskFactors.length ? (
            <div className="space-y-2">
              <div className="grid grid-cols-[1fr_72px_56px] gap-3 border-b border-white/8 pb-2 text-[9px] font-black uppercase tracking-[0.08em] text-white/35">
                <span>Factor</span>
                <span>Severity</span>
                <span className="text-right">Score</span>
              </div>
              {snapshot.riskFactors.map((factor) => (
                <div key={factor.label} className="grid grid-cols-[1fr_72px_56px] items-center gap-3 border-b border-white/5 py-2 text-xs">
                  <span className="truncate text-white/72">{factor.label}</span>
                  <span className="font-bold" style={{ color: severityColor(factor.severity) }}>
                    {factor.severity}
                  </span>
                  <span className="text-right font-mono text-white/70">{integerFmt(factor.score)}</span>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState label="No risk factors detected yet." />
          )}
        </Panel>

        <Panel className="p-5 xl:col-span-7">
          <SectionTitle suffix={<ViewAllLink to="/dashboard/quantum-readiness/command-center">Command Center</ViewAllLink>}>Risk Trend</SectionTitle>
          <TrendChart points={snapshot.riskTrend} />
        </Panel>
      </section>

      {/* Top risk assets + remediation queue */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7">
          <SectionTitle suffix={<ViewAllLink to="/dashboard/assets">View All Assets</ViewAllLink>}>Top-Risk Assets</SectionTitle>
          {snapshot.topRiskAssets.length ? (
            <div className="overflow-x-auto">
              <table className="min-w-[560px] w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                    <th className="pb-3 font-black">Asset</th>
                    <th className="pb-3 font-black">Type</th>
                    <th className="pb-3 font-black">Owner</th>
                    <th className="pb-3 font-black">Risk</th>
                    <th className="pb-3 font-black">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {snapshot.topRiskAssets.map((asset) => (
                    <tr key={`${asset.asset}-${asset.owner}`} className="border-b border-white/5 text-white/70">
                      <td className="max-w-[160px] truncate py-2.5 font-medium text-white/82">{asset.asset}</td>
                      <td className="py-2.5">{asset.assetType}</td>
                      <td className="max-w-[120px] truncate py-2.5">{asset.owner}</td>
                      <td className="py-2.5 font-mono font-bold" style={{ color: riskTone(asset.riskScore) }}>
                        {integerFmt(asset.riskScore)}
                      </td>
                      <td className="py-2.5">{asset.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState label="No asset risk data." hint="Connect an asset inventory or run discovery." />
          )}
        </Panel>

        <Panel className="p-5 xl:col-span-5">
          <SectionTitle suffix={<Badge color={ORANGE}>Priority</Badge>}>Remediation Priority Queue</SectionTitle>
          {snapshot.recommendedActions.length ? (
            <div className="space-y-2.5">
              {snapshot.recommendedActions.map((action, index) => {
                const color = severityColor(action.severity);
                return (
                  <button
                    key={action.id}
                    type="button"
                    onClick={() => navigate(action.route)}
                    className="flex w-full items-start gap-3 rounded-md border border-white/8 bg-white/[0.025] p-3 text-left transition hover:border-blue-400/40 hover:bg-blue-500/[0.06]"
                  >
                    <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md border text-xs font-black" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
                      {index + 1}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="text-xs font-bold text-white/85">{action.title}</div>
                      <div className="text-[11px] leading-snug text-white/50">{action.detail}</div>
                    </div>
                  </button>
                );
              })}
            </div>
          ) : (
            <EmptyState label="Remediation queue is clear." />
          )}
        </Panel>
      </section>

      {/* Evidence table */}
      <Panel className="p-5">
        <SectionTitle suffix={<span className="text-[11px] text-white/40">{snapshot.criticalFindings.length} evidence records</span>}>Critical / High Evidence</SectionTitle>
        {snapshot.criticalFindings.length ? (
          <div className="overflow-x-auto">
            <table className="min-w-[680px] w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                  <th className="pb-3 font-black">Finding</th>
                  <th className="pb-3 font-black">Algorithm</th>
                  <th className="pb-3 font-black">Asset</th>
                  <th className="pb-3 font-black">Environment</th>
                  <th className="pb-3 font-black">Severity</th>
                </tr>
              </thead>
              <tbody>
                {snapshot.criticalFindings.map((finding) => (
                  <tr key={finding.id} className="border-b border-white/5 text-white/70">
                    <td className="max-w-[200px] truncate py-2.5 text-white/82">{finding.title}</td>
                    <td className="py-2.5 font-mono">{finding.algorithm}</td>
                    <td className="max-w-[150px] truncate py-2.5">{finding.asset}</td>
                    <td className="py-2.5">{finding.environment}</td>
                    <td className="py-2.5 font-bold" style={{ color: severityColor(finding.severity) }}>
                      {finding.severity}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState label="No critical evidence records." hint="Findings appear here once a scan completes." />
        )}
      </Panel>
    </QuantumReadinessShell>
  );
}
