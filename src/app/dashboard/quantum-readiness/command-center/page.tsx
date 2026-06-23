'use client';

import { motion } from 'framer-motion';
import {
  Boxes,
  Cloud,
  Database,
  Download,
  Fingerprint,
  Gauge,
  Globe2,
  KeyRound,
  RefreshCw,
  Radio,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Target,
  Workflow,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import {
  Badge,
  EmptyState,
  HeaderButton,
  MetricCard,
  Panel,
  QuantumReadinessShell,
  SectionTitle,
  TrendChart,
  ViewAllLink,
  integerFmt,
  longDate,
  relativeTime,
  riskTone,
  readinessTone,
  severityColor,
  useQuantumReadiness,
  BLUE,
  CYAN,
  GREEN,
  ORANGE,
  RED,
  VIOLET,
  AMBER,
  GOLD,
  TEAL,
} from '../_shared';

export default function CommandCenterPage() {
  const navigate = useNavigate();
  const { snapshot, state, sseConnected, refresh, downloadJson } = useQuantumReadiness();
  const { scores, inventory, telemetry } = snapshot;

  const scoreCards = [
    { label: 'Quantum Readiness', value: integerFmt(scores.quantumReadiness), suffix: '/100', detail: scores.quantumReadinessLevel, color: readinessTone(scores.quantumReadiness), ring: scores.quantumReadiness },
    { label: 'Quantum Risk', value: integerFmt(scores.quantumRisk), suffix: '/100', detail: scores.quantumRiskLevel, color: riskTone(scores.quantumRisk), ring: scores.quantumRisk },
    { label: 'HNDL Risk', value: integerFmt(scores.hndlRisk), suffix: '/100', detail: scores.hndlRiskLevel, color: riskTone(scores.hndlRisk), ring: scores.hndlRisk },
    { label: 'Crypto Exposure', value: integerFmt(scores.cryptoExposure), suffix: '/100', detail: scores.cryptoExposureLevel, color: riskTone(scores.cryptoExposure), ring: scores.cryptoExposure },
    { label: 'Migration Complexity', value: integerFmt(scores.migrationComplexity), suffix: '/100', detail: scores.migrationComplexityLevel, color: riskTone(scores.migrationComplexity), ring: scores.migrationComplexity },
    { label: 'Migration Effort', value: integerFmt(scores.migrationEffort), suffix: '/100', detail: `${integerFmt(snapshot.estimates.migrationTimelineWeeks)}w est.`, color: GOLD, ring: scores.migrationEffort },
  ];

  const scope = [
    { label: 'Assets Scanned', value: inventory.assetsAssessed, icon: Boxes, color: BLUE },
    { label: 'Domains Scanned', value: inventory.domainsScanned, icon: Globe2, color: CYAN },
    { label: 'Certificates Analyzed', value: inventory.certificatesAnalyzed, icon: ShieldCheck, color: GREEN },
    { label: 'Keys Discovered', value: inventory.keysDiscovered, icon: KeyRound, color: GOLD },
    { label: 'Identities Analyzed', value: inventory.identitiesAnalyzed, icon: Fingerprint, color: VIOLET },
    { label: 'Cloud Accounts', value: inventory.cloudAccounts, icon: Cloud, color: ORANGE },
    { label: 'Data Repositories', value: inventory.dataRepositories, icon: Database, color: TEAL },
    { label: 'Trust Relationships', value: inventory.trustRelationships, icon: Workflow, color: BLUE },
  ];

  const health = healthState(snapshot.assessmentProgress, scores.quantumRisk);

  return (
    <QuantumReadinessShell
      title="Assessment Command Center"
      subtitle="Primary operational dashboard for the Quantum Readiness Assessment Engine™ — real-time scope, scoring, critical findings and recommended next actions."
      badge={<Badge color={health.color}>{health.label}</Badge>}
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <>
          <HeaderButton icon={Radio} active={sseConnected}>
            {sseConnected ? 'Live' : 'Syncing'}
          </HeaderButton>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>
            Refresh
          </HeaderButton>
          <HeaderButton icon={Download} onClick={() => downloadJson('quantum-readiness-command-center')}>
            Export
          </HeaderButton>
        </>
      }
    >
      {/* Score grid */}
      <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
        {scoreCards.map((card) => (
          <div key={card.label}>
            <MetricCard {...card} />
          </div>
        ))}
      </motion.section>

      {/* Scope + telemetry */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-8">
          <SectionTitle suffix={<span className="text-[11px] text-white/40">Assessment scope</span>}>Assessment Scope</SectionTitle>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {scope.map((item) => {
              const Icon = item.icon;
              return (
                <div key={item.label} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
                  <span className="grid h-9 w-9 place-items-center rounded-md border" style={{ borderColor: `${item.color}40`, color: item.color, backgroundColor: `${item.color}12` }}>
                    <Icon className="h-4 w-4" />
                  </span>
                  <div className="mt-2.5 text-xl font-semibold text-white">{integerFmt(item.value)}</div>
                  <div className="text-[10px] font-bold uppercase tracking-wide text-white/45">{item.label}</div>
                </div>
              );
            })}
          </div>
        </Panel>

        <Panel className="p-5 xl:col-span-4">
          <SectionTitle suffix={<Radio className={`h-3.5 w-3.5 ${sseConnected ? 'text-emerald-400' : 'text-amber-300'}`} />}>Active Telemetry Feed</SectionTitle>
          <div className="space-y-2.5">
            {[
              { label: 'Scan Sessions', value: telemetry.scanSessions, color: BLUE },
              { label: 'Scan Results', value: telemetry.scanResults, color: CYAN },
              { label: 'Runtime Crypto Events', value: telemetry.runtimeEvents, color: GREEN },
              { label: 'Security Events', value: telemetry.securityEvents, color: ORANGE },
              { label: 'Connected Sources', value: telemetry.connectors, color: VIOLET },
            ].map((row) => (
              <div key={row.label} className="flex items-center justify-between rounded-md border border-white/8 bg-black/20 px-3 py-2 text-xs">
                <span className="text-white/65">{row.label}</span>
                <span className="font-mono font-bold" style={{ color: row.color }}>
                  {integerFmt(row.value)}
                </span>
              </div>
            ))}
          </div>
          <div className="mt-3 rounded-md border border-white/8 bg-black/20 px-3 py-2 text-[11px] text-white/45">
            Latest event: {relativeTime(telemetry.latestEventAt)} · {longDate(telemetry.latestEventAt)}
          </div>
        </Panel>
      </section>

      {/* Trend */}
      <Panel className="p-5">
        <SectionTitle suffix={<ViewAllLink to="/dashboard/quantum-readiness/risk-analysis">View Risk Analysis</ViewAllLink>}>Assessment Timeline — Readiness vs Risk</SectionTitle>
        <TrendChart points={snapshot.riskTrend} />
      </Panel>

      {/* Critical findings + recommended actions */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-5 xl:col-span-7">
          <SectionTitle suffix={<span className="text-[11px] text-white/40">{snapshot.criticalFindings.length} critical / high</span>}>Critical Findings</SectionTitle>
          {snapshot.criticalFindings.length ? (
            <div className="overflow-x-auto">
              <table className="min-w-[560px] w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                    <th className="pb-3 font-black">Algorithm</th>
                    <th className="pb-3 font-black">Asset</th>
                    <th className="pb-3 font-black">Environment</th>
                    <th className="pb-3 font-black">Severity</th>
                    <th className="pb-3 font-black">Detected</th>
                  </tr>
                </thead>
                <tbody>
                  {snapshot.criticalFindings.slice(0, 8).map((finding) => (
                    <tr key={finding.id} className="border-b border-white/5 text-white/70">
                      <td className="py-2.5 font-medium text-white/82">{finding.algorithm}</td>
                      <td className="max-w-[160px] truncate py-2.5">{finding.asset}</td>
                      <td className="py-2.5">{finding.environment}</td>
                      <td className="py-2.5 font-bold" style={{ color: severityColor(finding.severity) }}>
                        {finding.severity}
                      </td>
                      <td className="py-2.5 text-white/45">{relativeTime(finding.detectedAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState label="No critical findings." hint="Run a discovery scan to surface quantum-vulnerable cryptography." />
          )}
          <div className="mt-4 flex justify-end">
            <ViewAllLink to="/dashboard/quantum-readiness/exposure-graph">Open Exposure Graph</ViewAllLink>
          </div>
        </Panel>

        <Panel className="p-5 xl:col-span-5">
          <SectionTitle>Recommended Next Actions</SectionTitle>
          {snapshot.recommendedActions.length ? (
            <div className="space-y-2.5">
              {snapshot.recommendedActions.map((action) => {
                const color = severityColor(action.severity);
                return (
                  <button
                    key={action.id}
                    type="button"
                    onClick={() => navigate(action.route)}
                    className="flex w-full items-start gap-3 rounded-md border border-white/8 bg-white/[0.025] p-3 text-left transition hover:border-blue-400/40 hover:bg-blue-500/[0.06]"
                  >
                    <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-md border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
                      <ShieldAlert className="h-3.5 w-3.5" />
                    </span>
                    <span className="min-w-0">
                      <span className="block text-xs font-bold text-white/85">{action.title}</span>
                      <span className="block text-[11px] leading-snug text-white/50">{action.detail}</span>
                    </span>
                    <span className="rounded px-1.5 py-0.5 text-[9px] font-black uppercase" style={{ color, backgroundColor: `${color}1a` }}>
                      {action.severity}
                    </span>
                  </button>
                );
              })}
            </div>
          ) : (
            <EmptyState label="No outstanding actions." />
          )}
        </Panel>
      </section>
    </QuantumReadinessShell>
  );
}

function healthState(progress: number, risk: number): { label: string; color: string } {
  if (progress === 0) return { label: 'Awaiting Data', color: BLUE };
  if (risk >= 70) return { label: 'Action Required', color: RED };
  if (risk >= 40) return { label: 'Monitoring', color: AMBER };
  return { label: 'Healthy', color: GREEN };
}
