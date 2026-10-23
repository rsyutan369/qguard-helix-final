'use client';

import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  ArrowRight,
  Award,
  Boxes,
  BrainCircuit,
  EyeOff,
  FileText,
  Gauge,
  KeyRound,
  Network,
  Play,
  RefreshCw,
  Rocket,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  Wrench,
} from 'lucide-react';
import {
  Badge,
  EmptyState,
  HeaderButton,
  MetricCard,
  Panel,
  PrimaryButton,
  QuantumReadinessShell,
  Ring,
  SectionTitle,
  ViewAllLink,
  integerFmt,
  longDate,
  percentLabel,
  readinessTone,
  riskTone,
  severityColor,
  useQuantumReadiness,
  useReadinessMemo,
  BLUE,
  CYAN,
  GREEN,
  ORANGE,
  RED,
  VIOLET,
  AMBER,
  GOLD,
  TruncationNote,
} from './_shared';

const MODULES = [
  { label: 'Quantum Exposure Graph™', detail: 'Dependency & blast-radius visualization', path: '/dashboard/quantum-readiness/exposure-graph', icon: Network, color: CYAN },
  { label: 'Quantum Risk Analysis', detail: 'Technical risk prioritization & evidence', path: '/dashboard/quantum-readiness/risk-analysis', icon: ShieldAlert, color: RED },
  { label: 'Quantum Remediation Engine™', detail: 'Asset-level remediation roadmap to certification', path: '/dashboard/quantum-readiness/remediation', icon: Wrench, color: CYAN },
  { label: 'AI Executive Advisor™', detail: 'Evidence-grounded executive advisory', path: '/dashboard/quantum-readiness/ai-executive-advisor', icon: Sparkles, color: VIOLET },
  { label: 'AI Migration Advisor™', detail: 'Migration waves, sequencing & rollback', path: '/dashboard/quantum-readiness/ai-migration-advisor', icon: BrainCircuit, color: ORANGE },
  { label: 'Harvest Now (HNDL)', detail: 'Harvest-now-decrypt-later threat operations & exposure', path: '/dashboard/harvest-now', icon: EyeOff, color: AMBER },
  { label: 'Quantum Trust Certification™', detail: 'Issue signed, publicly verifiable PQC readiness certificates', path: '/dashboard/quantum-certification', icon: Award, color: GOLD },
  { label: 'Report Center', detail: 'Customer-facing reports & evidence packages', path: '/dashboard/quantum-readiness/reports', icon: FileText, color: GREEN },
];

export default function QuantumReadinessLandingPage() {
  const navigate = useNavigate();
  const { snapshot, state, error, sseConnected, lastVerifiedAt, refresh } = useQuantumReadiness();
  const memo = useReadinessMemo(snapshot);
  const { scores, inventory } = snapshot;

  const statusBadge = useMemo(() => {
    if (snapshot.assessmentStatus === 'complete') return <Badge color={GREEN}>Assessment Complete</Badge>;
    if (snapshot.assessmentStatus === 'in_progress') return <Badge color={AMBER}>Assessment In Progress</Badge>;
    return <Badge color={BLUE}>Not Started</Badge>;
  }, [snapshot.assessmentStatus]);

  const kpis = [
    { label: 'Quantum Readiness', value: integerFmt(scores.quantumReadiness), suffix: '/100', detail: scores.quantumReadinessLevel, color: readinessTone(scores.quantumReadiness), ring: scores.quantumReadiness, icon: ShieldCheck },
    { label: 'Quantum Risk', value: integerFmt(scores.quantumRisk), suffix: '/100', detail: scores.quantumRiskLevel, color: riskTone(scores.quantumRisk), ring: scores.quantumRisk, icon: ShieldAlert },
    { label: 'HNDL Risk', value: integerFmt(scores.hndlRisk), suffix: '/100', detail: scores.hndlRiskLevel, color: riskTone(scores.hndlRisk), ring: scores.hndlRisk, icon: Target },
    // PQC Adoption is a COMPONENT share — its detail names components, not the
    // asset count it used to print beside a component percentage.
    { label: 'PQC Adoption', value: percentLabel(scores.pqcAdoption), detail: inventory.cryptoComponents ? `${integerFmt(inventory.pqcReadyComponents)} of ${integerFmt(inventory.cryptoComponents)} components` : 'No CBOM yet', color: GREEN, ring: scores.pqcAdoption, icon: Gauge },
    {
      label: 'Assets Assessed',
      value: integerFmt(inventory.assetsAssessed),
      detail: inventory.unassessedAssets
        ? `${integerFmt(inventory.quantumVulnerableAssets)} vulnerable · ${integerFmt(inventory.unassessedAssets)} no crypto evidence`
        : `${integerFmt(inventory.quantumVulnerableAssets)} vulnerable`,
      color: BLUE,
      icon: Boxes,
    },
    { label: 'Keys Discovered', value: integerFmt(inventory.keysDiscovered), detail: `${integerFmt(inventory.certificatesAnalyzed)} certificates`, color: CYAN, icon: KeyRound },
  ];

  return (
    <QuantumReadinessShell
      title="Quantum Readiness Assessment Engine™"
      subtitle="The central QGuard Helix assessment layer — transform cryptographic inventory, runtime telemetry and trust intelligence into executive-ready quantum readiness scoring, AI advisory and migration planning."
      badge={statusBadge}
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      error={error}
      lastVerifiedAt={lastVerifiedAt}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>
            Refresh
          </HeaderButton>
          <PrimaryButton icon={Play} onClick={() => navigate('/dashboard/scanner')}>
            {snapshot.hasData ? 'Continue Assessment' : 'Start New Assessment'}
          </PrimaryButton>
          <HeaderButton icon={FileText} onClick={() => navigate('/dashboard/quantum-readiness/reports')}>
            Generate Report
          </HeaderButton>
        </>
      }
    >
      {/* Hero status band */}
      <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-6 xl:col-span-5">
          <SectionTitle>Current Assessment Status</SectionTitle>
          <div className="flex items-center gap-6">
            <Ring value={snapshot.assessmentProgress} color={readinessTone(scores.quantumReadiness)} size={132} stroke={12}>
              <div>
                <div className="text-3xl font-semibold text-white">{percentLabel(snapshot.assessmentProgress)}</div>
                <div className="text-[10px] font-bold uppercase tracking-wide text-white/45">Coverage</div>
              </div>
            </Ring>
            <div className="space-y-3 text-sm">
              <div>
                <div className="text-[10px] font-black uppercase tracking-wide text-white/40">Readiness Level</div>
                <div className="text-lg font-bold" style={{ color: readinessTone(scores.quantumReadiness) }}>
                  {scores.quantumReadinessLevel}
                </div>
              </div>
              <div>
                <div className="text-[10px] font-black uppercase tracking-wide text-white/40">Last Assessment</div>
                <div className="font-semibold text-white/80">{longDate(snapshot.lastAssessmentAt)}</div>
              </div>
              <div className="flex gap-4">
                <div>
                  <div className="text-[10px] font-black uppercase tracking-wide text-white/40">Critical</div>
                  <div className="font-mono text-lg" style={{ color: RED }}>
                    {integerFmt(snapshot.riskDistribution.critical)}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] font-black uppercase tracking-wide text-white/40">High</div>
                  <div className="font-mono text-lg" style={{ color: ORANGE }}>
                    {integerFmt(snapshot.riskDistribution.high)}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] font-black uppercase tracking-wide text-white/40">Findings</div>
                  <div className="font-mono text-lg text-white/80">{integerFmt(memo.totalFindings)}</div>
                </div>
              </div>
            </div>
          </div>
        </Panel>

        <Panel className="p-6 xl:col-span-4">
          <SectionTitle suffix={<Badge color={VIOLET}>Evidence-derived</Badge>}>Recommended Next Actions</SectionTitle>
          {snapshot.recommendedActions.length ? (
            <div className="space-y-3">
              {snapshot.recommendedActions.slice(0, 3).map((action) => {
                const color = severityColor(action.severity);
                return (
                  <button
                    key={action.id}
                    type="button"
                    onClick={() => navigate(action.route)}
                    className="flex w-full items-start gap-3 rounded-md border border-white/8 bg-white/[0.025] p-3 text-left transition hover:border-blue-400/40 hover:bg-blue-500/[0.06]"
                  >
                    <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-md border" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
                      <Sparkles className="h-3.5 w-3.5" />
                    </span>
                    <span className="min-w-0">
                      <span className="block text-xs font-bold text-white/85">{action.title}</span>
                      <span className="block text-[11px] leading-snug text-white/50">{action.detail}</span>
                    </span>
                  </button>
                );
              })}
              <TruncationNote
                shown={3}
                total={snapshot.recommendedActions.length}
                noun="recommendations"
                rank="highest-priority"
                to="/dashboard/quantum-readiness/ai-executive-advisor"
              />
            </div>
          ) : (
            <EmptyState label="No recommendations yet." hint="Run an assessment to generate AI guidance." />
          )}
          <div className="mt-4 flex justify-end">
            <ViewAllLink to="/dashboard/quantum-readiness/ai-executive-advisor">Open AI Executive Advisor</ViewAllLink>
          </div>
        </Panel>

        <Panel className="p-6 xl:col-span-3">
          <SectionTitle>Latest Critical Risks</SectionTitle>
          {snapshot.criticalFindings.length ? (
            <div className="space-y-2.5">
              {snapshot.criticalFindings.slice(0, 4).map((finding) => (
                <div key={finding.id} className="rounded-md border border-white/8 bg-black/20 p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-xs font-bold text-white/82">{finding.algorithm}</span>
                    <span className="rounded px-1.5 py-0.5 text-[9px] font-black uppercase" style={{ color: severityColor(finding.severity), backgroundColor: `${severityColor(finding.severity)}1a` }}>
                      {finding.severity}
                    </span>
                  </div>
                  <div className="mt-0.5 truncate text-[10px] text-white/45">{finding.asset}</div>
                </div>
              ))}
              <TruncationNote
                shown={4}
                total={snapshot.criticalFindings.length}
                noun="critical findings"
                rank="highest-severity"
                to="/dashboard/quantum-readiness/risk-analysis"
              />
            </div>
          ) : (
            <EmptyState label="No critical risks detected." />
          )}
          <div className="mt-4 flex justify-end">
            <ViewAllLink to="/dashboard/quantum-readiness/risk-analysis">View Risk Analysis</ViewAllLink>
          </div>
        </Panel>
      </motion.section>

      {/* KPI snapshot */}
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
        {kpis.map((kpi) => (
          <div key={kpi.label}>
            <MetricCard {...kpi} />
          </div>
        ))}
      </section>

      {/* Readiness factor breakdown — every factor states the population it was
          computed over; an unmeasured factor says so and is excluded from the score. */}
      {snapshot.hasData && snapshot.readinessFactors.length ? (
        <Panel className="p-5">
          <SectionTitle
            suffix={
              <span className="text-[11px] text-white/40">
                Readiness = PQC adoption · risk posture · runtime visibility — unmeasured factors excluded, weights renormalised
              </span>
            }
          >
            What Drives the Readiness Score
          </SectionTitle>
          <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2 xl:grid-cols-4">
            {snapshot.readinessFactors.map((factor) => {
              const measured = factor.measured !== false;
              const color = measured ? readinessTone(factor.score) : '#64748B';
              return (
                <div key={factor.label} className="rounded-md border border-white/8 bg-black/20 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-[11px] font-bold text-white/80">{factor.label}</span>
                    <span className="font-mono text-sm font-bold" style={{ color }}>
                      {measured ? `${integerFmt(factor.score)}` : '—'}
                    </span>
                  </div>
                  <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/5">
                    {measured ? <div className="h-full rounded-full" style={{ width: `${Math.min(100, factor.score)}%`, backgroundColor: color }} /> : null}
                  </div>
                  <p className="mt-1.5 text-[10px] leading-snug text-white/42">
                    {measured ? null : <span className="font-bold text-white/55">Not measured · </span>}
                    {factor.basis || (measured ? 'Measured from assessment evidence' : 'No evidence for this factor')}
                  </p>
                </div>
              );
            })}
          </div>
        </Panel>
      ) : null}

      {/* Module hub */}
      <Panel className="p-5">
        <SectionTitle suffix={<span className="text-[11px] text-white/40">{MODULES.length} assessment modules</span>}>Assessment Modules</SectionTitle>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {MODULES.map((mod) => {
            const Icon = mod.icon;
            return (
              <button
                key={mod.path}
                type="button"
                onClick={() => navigate(mod.path)}
                className="group/card flex items-start gap-3 rounded-lg border border-white/8 bg-white/[0.025] p-4 text-left transition hover:-translate-y-0.5 hover:border-blue-400/40 hover:bg-blue-500/[0.06]"
              >
                <span className="grid h-10 w-10 shrink-0 place-items-center rounded-md border" style={{ borderColor: `${mod.color}40`, color: mod.color, backgroundColor: `${mod.color}12` }}>
                  <Icon className="h-5 w-5" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="flex items-center justify-between gap-2">
                    <span className="text-sm font-bold text-white/88">{mod.label}</span>
                    <ArrowRight className="h-4 w-4 shrink-0 text-white/25 transition group-hover/card:translate-x-0.5 group-hover/card:text-blue-300" />
                  </span>
                  <span className="mt-0.5 block text-[11px] leading-snug text-white/50">{mod.detail}</span>
                </span>
              </button>
            );
          })}
        </div>
      </Panel>

      {/* Quick start CTA */}
      <Panel className="p-6">
        <div className="flex flex-col items-start justify-between gap-4 md:flex-row md:items-center">
          <div className="flex items-center gap-4">
            <span className="grid h-12 w-12 place-items-center rounded-lg border border-blue-400/30 bg-blue-500/10 text-blue-300">
              <Rocket className="h-6 w-6" />
            </span>
            <div>
              <div className="text-base font-bold text-white">Ready to advance your quantum posture?</div>
              <div className="text-sm text-white/55">
                {!snapshot.hasData
                  ? 'Begin with a PQC discovery scan to inventory your cryptographic assets.'
                  : inventory.quantumVulnerableAssets > 0
                    ? `${integerFmt(inventory.quantumVulnerableAssets)} quantum-vulnerable asset${inventory.quantumVulnerableAssets === 1 ? '' : 's'} identified — generate a migration plan or executive report.`
                    : 'No quantum-vulnerable assets in the current evidence — keep scanning to hold that position.'}
              </div>
            </div>
          </div>
          <div className="flex flex-wrap gap-2.5">
            <PrimaryButton icon={ScanSearch} onClick={() => navigate('/dashboard/scanner')}>
              Run Discovery Scan
            </PrimaryButton>
            <HeaderButton icon={BrainCircuit} onClick={() => navigate('/dashboard/quantum-readiness/ai-migration-advisor')}>
              Plan Migration
            </HeaderButton>
            <HeaderButton icon={Sparkles} onClick={() => navigate('/dashboard/quantum-readiness/ai-executive-advisor')}>
              Executive Advisor
            </HeaderButton>
          </div>
        </div>
      </Panel>
    </QuantumReadinessShell>
  );
}
