'use client';

import { useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  AlertTriangle,
  Banknote,
  CalendarClock,
  Download,
  FileText,
  Landmark,
  RefreshCw,
  ShieldCheck,
  Target,
  TrendingDown,
  TrendingUp,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { describeCostAssumptions } from '@/lib/migration/cost-model';
import {
  Badge,
  EmptyState,
  HeaderButton,
  Panel,
  PrimaryButton,
  QuantumReadinessShell,
  Ring,
  SectionTitle,
  TrendChart,
  currencyFmt,
  integerFmt,
  percentLabel,
  readinessTone,
  riskTone,
  severityColor,
  useQuantumReadiness,
  AMBER,
  BLUE,
  EMERALD,
  GREEN,
  ORANGE,
  RED,
} from '../_shared';

export default function ExecutiveDashboardPage() {
  const navigate = useNavigate();
  const { snapshot, state, sseConnected, refresh, downloadJson } = useQuantumReadiness();
  const { scores, inventory, estimates } = snapshot;

  const businessRisk = useMemo(() => {
    const r = scores.quantumRisk;
    if (r >= 70) return { label: 'Severe', color: RED, statement: 'Material quantum exposure requires immediate executive sponsorship and funded remediation.' };
    if (r >= 45) return { label: 'Elevated', color: ORANGE, statement: 'Significant quantum risk concentrated in vulnerable assets — prioritize a funded migration program.' };
    if (r >= 20) return { label: 'Moderate', color: AMBER, statement: 'Manageable quantum risk — maintain momentum on the migration roadmap.' };
    if (r > 0) return { label: 'Low', color: GREEN, statement: 'Quantum risk is well controlled relative to peers.' };
    return { label: 'Unassessed', color: BLUE, statement: 'Insufficient evidence to determine business risk. Complete a discovery assessment.' };
  }, [scores.quantumRisk]);

  const executiveFindings = useMemo(() => {
    const out: Array<{ title: string; detail: string; severity: string }> = [];
    if (inventory.quantumVulnerableAssets > 0)
      out.push({ title: `${integerFmt(inventory.quantumVulnerableAssets)} quantum-vulnerable assets`, detail: 'Classical RSA/ECC cryptography is exposed to future quantum decryption.', severity: 'critical' });
    if (scores.hndlRisk >= 40)
      out.push({ title: 'Harvest-Now-Decrypt-Later exposure', detail: 'Long-lived sensitive data could be captured today and decrypted post-quantum.', severity: 'high' });
    if (snapshot.riskDistribution.critical > 0)
      out.push({ title: `${integerFmt(snapshot.riskDistribution.critical)} critical findings open`, detail: 'Critical cryptographic weaknesses require remediation this quarter.', severity: 'critical' });
    if (inventory.certificatesAnalyzed > 0 && scores.cryptoExposure >= 40)
      out.push({ title: 'PKI modernization required', detail: 'Certificate estate relies on quantum-vulnerable signature algorithms.', severity: 'high' });
    if (scores.pqcAdoption < 30 && snapshot.hasData)
      out.push({ title: 'Low PQC adoption', detail: `Only ${percentLabel(scores.pqcAdoption)} of cryptography is quantum-safe or hybrid.`, severity: 'medium' });
    return out.slice(0, 5);
  }, [snapshot, inventory, scores]);

  const executiveActions = useMemo(() => snapshot.recommendedActions.slice(0, 5), [snapshot.recommendedActions]);

  return (
    <QuantumReadinessShell
      title="Executive Dashboard"
      subtitle="Board-ready quantum posture for CISOs, CIOs and executive stakeholders — business risk, strategic forecast, estimated investment and the actions that move the needle."
      badge={<Badge color={businessRisk.color}>Business Risk: {businessRisk.label}</Badge>}
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>
            Refresh
          </HeaderButton>
          <HeaderButton icon={Download} onClick={() => downloadJson('quantum-readiness-executive-brief')}>
            Export Brief
          </HeaderButton>
          <PrimaryButton icon={FileText} onClick={() => navigate('/dashboard/quantum-readiness/reports')}>
            Generate Board Report
          </PrimaryButton>
        </>
      }
    >
      {/* Hero */}
      <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="p-6 xl:col-span-4">
          <SectionTitle>Executive Readiness Score</SectionTitle>
          <div className="flex items-center gap-5">
            <Ring value={scores.quantumReadiness} color={readinessTone(scores.quantumReadiness)} size={128} stroke={12}>
              <div>
                <div className="text-4xl font-semibold text-white">{integerFmt(scores.quantumReadiness)}</div>
                <div className="text-[10px] font-bold uppercase tracking-wide text-white/45">of 100</div>
              </div>
            </Ring>
            <div>
              <div className="text-lg font-bold" style={{ color: readinessTone(scores.quantumReadiness) }}>
                {scores.quantumReadinessLevel}
              </div>
              <p className="mt-2 max-w-[200px] text-xs leading-relaxed text-white/55">{businessRisk.statement}</p>
            </div>
          </div>
        </Panel>

        <Panel className="p-6 xl:col-span-8">
          <SectionTitle>Strategic Snapshot</SectionTitle>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <BigStat icon={Target} label="Business Risk" value={businessRisk.label} color={businessRisk.color} sub={`Risk score ${integerFmt(scores.quantumRisk)}`} />
            <BigStat icon={AlertTriangle} label="HNDL Exposure" value={scores.hndlRiskLevel} color={riskTone(scores.hndlRisk)} sub={`${integerFmt(scores.hndlRisk)}/100`} />
            <BigStat icon={CalendarClock} label="Est. Timeline" value={estimates.migrationTimelineWeeks ? `${integerFmt(estimates.migrationTimelineWeeks)}w` : '—'} color={BLUE} sub="To quantum-safe" />
            <BigStat icon={Banknote} label="Est. Investment" value={estimates.migrationCostUsd ? currencyFmt(estimates.migrationCostUsd) : '—'} color={EMERALD} sub="Migration program" />
          </div>
          {/* A currency figure without its inputs is indistinguishable from a
              measurement. Publish the assumptions beside it, everywhere. */}
          {estimates.migrationCostUsd ? (
            <p className="mt-3 text-[9.5px] leading-relaxed text-white/35">{describeCostAssumptions(snapshot.costAssumptions)}</p>
          ) : null}
          <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <MiniStat label="PQC Adoption" value={percentLabel(scores.pqcAdoption)} color={GREEN} />
            <MiniStat label="Vulnerable Assets" value={integerFmt(inventory.quantumVulnerableAssets)} color={RED} />
            <MiniStat label="Assets Assessed" value={integerFmt(inventory.assetsAssessed)} color={BLUE} />
            <MiniStat label="Critical Findings" value={integerFmt(snapshot.riskDistribution.critical)} color={ORANGE} />
          </div>
        </Panel>
      </motion.section>

      {/* Risk trend forecast */}
      <Panel className="p-5">
        <SectionTitle
          suffix={
            <span className="inline-flex items-center gap-1.5 text-[11px] font-bold" style={{ color: snapshot.riskTrend.length >= 2 && snapshot.riskTrend[snapshot.riskTrend.length - 1].risk < snapshot.riskTrend[0].risk ? GREEN : ORANGE }}>
              {snapshot.riskTrend.length >= 2 && snapshot.riskTrend[snapshot.riskTrend.length - 1].risk < snapshot.riskTrend[0].risk ? <TrendingDown className="h-3.5 w-3.5" /> : <TrendingUp className="h-3.5 w-3.5" />}
              Strategic risk forecast
            </span>
          }
        >
          Risk Trend Over Time
        </SectionTitle>
        <TrendChart points={snapshot.riskTrend} />
      </Panel>

      {/* Findings + actions */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel className="p-5">
          <SectionTitle suffix={<Badge color={RED}>Top 5</Badge>}>Top Executive Findings</SectionTitle>
          {executiveFindings.length ? (
            <div className="space-y-2.5">
              {executiveFindings.map((finding, index) => {
                const color = severityColor(finding.severity);
                return (
                  <div key={finding.title} className="flex items-start gap-3 rounded-md border border-white/8 bg-white/[0.025] p-3">
                    <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md border text-xs font-black" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
                      {index + 1}
                    </span>
                    <div className="min-w-0">
                      <div className="text-sm font-bold text-white/85">{finding.title}</div>
                      <div className="text-[11px] leading-snug text-white/50">{finding.detail}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <EmptyState label="No executive findings." hint="Complete an assessment to surface board-level risks." />
          )}
        </Panel>

        <Panel className="p-5">
          <SectionTitle suffix={<Badge color={GREEN}>Top 5</Badge>}>Recommended Actions</SectionTitle>
          {executiveActions.length ? (
            <div className="space-y-2.5">
              {executiveActions.map((action, index) => {
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
                    <div className="min-w-0">
                      <div className="text-sm font-bold text-white/85">{action.title}</div>
                      <div className="text-[11px] leading-snug text-white/50">{action.detail}</div>
                    </div>
                  </button>
                );
              })}
            </div>
          ) : (
            <EmptyState label="No outstanding actions." />
          )}
        </Panel>
      </section>

      {/* Board summary */}
      <Panel className="p-6">
        <SectionTitle suffix={<Landmark className="h-4 w-4 text-white/40" />}>Board Summary</SectionTitle>
        {snapshot.hasData ? (
          <p className="text-sm leading-relaxed text-white/70">
            The organization holds a quantum readiness score of{' '}
            <strong style={{ color: readinessTone(scores.quantumReadiness) }}>{integerFmt(scores.quantumReadiness)}/100</strong> ({scores.quantumReadinessLevel}) against a quantum risk score of{' '}
            <strong style={{ color: riskTone(scores.quantumRisk) }}>{integerFmt(scores.quantumRisk)}/100</strong>. Discovery has assessed{' '}
            <strong className="text-white">{integerFmt(inventory.assetsAssessed)}</strong> assets, identifying{' '}
            <strong style={{ color: RED }}>{integerFmt(inventory.quantumVulnerableAssets)}</strong> as quantum-vulnerable with{' '}
            <strong style={{ color: GREEN }}>{percentLabel(scores.pqcAdoption)}</strong> PQC adoption. Harvest-Now-Decrypt-Later exposure is rated{' '}
            <strong style={{ color: riskTone(scores.hndlRisk) }}>{scores.hndlRiskLevel}</strong>. The estimated path to a quantum-safe posture is{' '}
            <strong className="text-white">{estimates.migrationTimelineWeeks ? `${integerFmt(estimates.migrationTimelineWeeks)} weeks` : 'to be determined'}</strong>
            {estimates.migrationCostUsd ? (
              <>
                {' '}at an estimated investment of <strong style={{ color: EMERALD }}>{currencyFmt(estimates.migrationCostUsd)}</strong>
              </>
            ) : null}
            . {businessRisk.statement}
          </p>
        ) : (
          <EmptyState label="Board summary unavailable." hint="Evidence-grounded summary generates once an assessment runs." />
        )}
        <div className="mt-4 flex flex-wrap gap-2.5">
          <PrimaryButton icon={ShieldCheck} onClick={() => navigate('/dashboard/quantum-readiness/ai-executive-advisor')}>
            Open AI Executive Advisor
          </PrimaryButton>
          <HeaderButton icon={Download} onClick={() => downloadJson('quantum-readiness-board-summary')}>
            Download Summary
          </HeaderButton>
        </div>
      </Panel>
    </QuantumReadinessShell>
  );
}

function BigStat({ icon: Icon, label, value, color, sub }: { icon: typeof Target; label: string; value: string; color: string; sub: string }) {
  return (
    <div className="rounded-md border border-white/8 bg-white/[0.025] p-3.5">
      <span className="grid h-9 w-9 place-items-center rounded-md border" style={{ borderColor: `${color}40`, color, backgroundColor: `${color}12` }}>
        <Icon className="h-4 w-4" />
      </span>
      <div className="mt-2.5 text-lg font-bold text-white">{value}</div>
      <div className="text-[10px] font-bold uppercase tracking-wide text-white/45">{label}</div>
      <div className="mt-0.5 text-[10px] text-white/35">{sub}</div>
    </div>
  );
}

function MiniStat({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="rounded-md border border-white/8 bg-black/20 px-3 py-2">
      <div className="text-base font-semibold" style={{ color }}>
        {value}
      </div>
      <div className="text-[10px] font-bold uppercase tracking-wide text-white/45">{label}</div>
    </div>
  );
}
