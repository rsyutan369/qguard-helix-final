'use client';

import { useCallback, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  ArrowRight,
  BadgeCheck,
  Banknote,
  Building2,
  CheckCircle2,
  Download,
  FileText,
  Gauge,
  History,
  Landmark,
  ListChecks,
  RefreshCw,
  ScrollText,
  ShieldAlert,
  Sparkles,
  TrendingUp,
  XCircle,
} from 'lucide-react';
import {
  Badge,
  EmptyState,
  HeaderButton,
  Panel,
  PrimaryButton,
  QuantumReadinessShell,
  SectionTitle,
  currencyFmt,
  integerFmt,
  longDate,
  readinessTone,
  riskTone,
  severityColor,
  useQuantumReadiness,
  BLUE,
  EMERALD,
  GREEN,
  ORANGE,
  RED,
  VIOLET,
} from '../_shared';
import { useAuth } from '@/contexts/auth-context';
import type { EnterpriseAssessmentReport } from '@/services/reporting/schemas/ReportSchema';
import { riskBandFor } from '@/lib/migration/asset-intelligence';
import { useReportAuditTrail } from '@/hooks/use-report-audit-trail';
import { useAdvisorModel } from '../_advisor';

/**
 * AI Executive Advisor™ — the executive intelligence layer.
 *
 * Every section renders from the SAME unified enterprise report model the
 * Report Center exports (buildReportModel): risk decomposition, business
 * risks, ROI, decisions, confidence and the evidence chain all reconcile and
 * self-validate. The advisor translates that validated evidence into board
 * language — it never invents findings the assessment did not produce.
 */

interface Advisory {
  id: string;
  generatedAt: string;
  approved: boolean;
  readiness: number;
  risk: number;
  validation: 'PASS' | 'FAIL';
  model: EnterpriseAssessmentReport;
}

function EvidenceChips({ items }: { items: string[] }) {
  if (!items.length) return null;
  return (
    <div className="mt-3 flex flex-wrap gap-1.5">
      {items.filter(Boolean).map((item) => (
        <span key={item} className="inline-flex items-center gap-1 rounded border border-emerald-400/20 bg-emerald-400/[0.07] px-2 py-0.5 text-[10px] font-semibold text-emerald-200/80">
          <CheckCircle2 className="h-3 w-3" /> {item}
        </span>
      ))}
    </div>
  );
}

function StateRow({ label, current, target, betterHigh }: { label: string; current: number; target: number; betterHigh: boolean }) {
  const currentColor = betterHigh ? readinessTone(current) : riskTone(current);
  const targetColor = betterHigh ? readinessTone(target) : riskTone(target);
  return (
    <div className="rounded-md border border-white/8 bg-black/20 px-3 py-2.5">
      <div className="text-[9px] font-black uppercase tracking-wide text-white/40">{label}</div>
      <div className="mt-1 flex items-center gap-2 font-mono text-lg font-bold">
        <span style={{ color: currentColor }}>{integerFmt(current)}</span>
        <ArrowRight className="h-3.5 w-3.5 text-white/30" />
        <span style={{ color: targetColor }}>{integerFmt(target)}</span>
        <span className="text-[10px] font-semibold text-white/35">/100</span>
      </div>
    </div>
  );
}

export default function AiExecutiveAdvisorPage() {
  const { user } = useAuth();
  const { snapshot, state, error, sseConnected, lastVerifiedAt, refresh, downloadJson } = useQuantumReadiness();
  const model = useAdvisorModel(snapshot, user?.email || 'QGuard Helix');
  const [advisory, setAdvisory] = useState<Advisory | null>(null);
  // Models generated in THIS session, so a trail entry can be reopened. The
  // trail itself is the tenant's audit log and survives reloads and devices.
  const [sessionModels, setSessionModels] = useState<Record<string, Advisory>>({});
  const trail = useReportAuditTrail('advisory');
  const recordAdvisory = trail.record;
  const [approving, setApproving] = useState(false);

  /* Deterministic synthesis from the validated report model — the same engine
     as the Report Center, so the advisory can never contradict the report. It
     is instant; the 450ms "Generating…" delay this replaced was theatre. */
  const generate = useCallback(() => {
    if (!snapshot.hasData) return;
    const next: Advisory = {
      id: `adv-${Date.now()}`,
      generatedAt: new Date().toISOString(),
      approved: false,
      readiness: snapshot.scores.quantumReadiness,
      risk: snapshot.scores.quantumRisk,
      validation: model.reportValidation.overall,
      model,
    };
    setAdvisory(next);
    setSessionModels((prev) => ({ ...prev, [next.id]: next }));
    void recordAdvisory({
      action: 'generated',
      advisoryId: next.id,
      readiness: next.readiness,
      risk: next.risk,
      validation: next.validation,
      assessmentAt: snapshot.lastAssessmentAt || snapshot.generatedAt,
    });
  }, [snapshot, model, recordAdvisory]);

  const approve = useCallback(async () => {
    if (!advisory || advisory.approved) return;
    setApproving(true);
    // Approval is an auditable decision: it only shows as approved once the
    // tenant's audit log has accepted the record.
    const recorded = await recordAdvisory({
      action: 'approved',
      advisoryId: advisory.id,
      readiness: advisory.readiness,
      risk: advisory.risk,
      validation: advisory.validation,
      assessmentAt: snapshot.lastAssessmentAt || snapshot.generatedAt,
    });
    setApproving(false);
    if (!recorded) return;
    const approved = { ...advisory, approved: true };
    setAdvisory(approved);
    setSessionModels((prev) => ({ ...prev, [approved.id]: approved }));
  }, [advisory, recordAdvisory, snapshot.lastAssessmentAt, snapshot.generatedAt]);

  /** One row per advisory: generation merged with its approval, newest first. */
  const auditRows = useMemo(() => {
    const byId = new Map<string, { id: string; generatedAt: string; readiness: number | null; risk: number | null; validation: string; approved: boolean; approvedBy?: string }>();
    for (const entry of [...trail.entries].reverse()) {
      if (!entry.advisoryId) continue;
      const row = byId.get(entry.advisoryId) || {
        id: entry.advisoryId,
        generatedAt: entry.createdAt,
        readiness: entry.readiness ?? null,
        risk: entry.risk ?? null,
        validation: entry.validation || 'FAIL',
        approved: false,
      };
      if (entry.action === 'executive_advisory_approved') {
        row.approved = true;
        row.approvedBy = entry.actor;
      }
      byId.set(entry.advisoryId, row);
    }
    return [...byId.values()].sort((a, b) => Date.parse(b.generatedAt) - Date.parse(a.generatedAt)).slice(0, 12);
  }, [trail.entries]);

  const exportAdvisory = useCallback(() => {
    if (!advisory) return;
    const m = advisory.model;
    downloadJson('ai-executive-advisory', {
      generatedAt: advisory.generatedAt,
      approved: advisory.approved,
      reportValidation: m.reportValidation,
      executiveSummary: m.executiveSummary,
      executiveBlock: m.executiveBlock,
      impactReasons: m.impactReasons,
      roiAnalysis: m.roiAnalysis,
      riskScenarios: m.riskForecast.scenarios,
      executiveDecisions: m.executiveDecisions,
      riskAcceptance: m.riskAcceptance,
      decisionChain: m.decisionChain,
      confidenceSummary: m.confidenceSummary,
      benchmarking: m.benchmarking,
      certification: m.certification,
    });
  }, [advisory, downloadJson]);

  const inputs = useMemo(
    () => [
      { label: 'Assets', value: integerFmt(snapshot.inventory.assetsAssessed) },
      { label: 'CBOM Components', value: integerFmt(snapshot.inventory.cryptoComponents) },
      { label: 'Certificates', value: integerFmt(snapshot.inventory.certificatesAnalyzed) },
      { label: 'Keys', value: integerFmt(snapshot.inventory.keysDiscovered) },
      { label: 'Critical Findings', value: integerFmt(snapshot.riskDistribution.critical) },
      { label: 'Evidence Confidence', value: `${integerFmt(model.confidenceSummary.assessmentConfidencePct)}%` },
      { label: 'Self-Validation', value: model.reportValidation.overall },
    ],
    [snapshot, model],
  );

  const m = advisory?.model;
  const ex = m?.executiveBlock;

  // Worded from the CANONICAL band of the risk score (RISK_BANDS), so the board
  // statement can never call a score "ELEVATED" that every other surface bands
  // "High" — the private 70/45/20 ladder this replaced did exactly that at 60–69.
  const boardStatement = useMemo(() => {
    if (!advisory) return '';
    const band = riskBandFor(advisory.risk);
    switch (band.key) {
      case 'critical':
        return `Quantum risk is CRITICAL (${advisory.risk}/100) — a material exposure requiring board oversight and immediate, funded remediation.`;
      case 'high':
        return `Quantum risk is HIGH (${advisory.risk}/100) and warrants a board-approved migration mandate with quarterly progress reporting.`;
      case 'elevated':
        return `Quantum risk is ELEVATED (${advisory.risk}/100); fund the migration programme and report progress to the risk committee.`;
      case 'moderate':
        return `Quantum risk is MODERATE (${advisory.risk}/100) and is being actively managed; sustain the funded migration trajectory.`;
      default:
        return `Quantum risk is ${band.label.toUpperCase()} (${advisory.risk}/100) relative to the assessed evidence; sustain governance, monitoring and crypto-agility investment.`;
    }
  }, [advisory]);

  return (
    <QuantumReadinessShell
      title="AI Executive Advisor™"
      subtitle="Generates business-level explanations and board-ready recommendations from the same validated evidence engine that powers the enterprise reports. Every statement is grounded in assessment evidence — the advisor never invents unsupported findings."
      badge={advisory?.approved ? <Badge color={GREEN}>Approved for Report</Badge> : <Badge color={VIOLET}>AI Advisory</Badge>}
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      error={error}
      lastVerifiedAt={lastVerifiedAt}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>
            Refresh Evidence
          </HeaderButton>
          {advisory ? (
            <>
              <HeaderButton icon={Sparkles} onClick={generate}>
                Regenerate
              </HeaderButton>
              <HeaderButton icon={Download} onClick={exportAdvisory}>
                Export
              </HeaderButton>
              <PrimaryButton icon={BadgeCheck} onClick={() => void approve()} disabled={advisory.approved || approving}>
                {advisory.approved ? 'Approved' : approving ? 'Recording approval…' : 'Approve for Report'}
              </PrimaryButton>
            </>
          ) : (
            <PrimaryButton icon={Sparkles} onClick={generate} disabled={!snapshot.hasData || state !== 'success'}>
              Generate Advisory
            </PrimaryButton>
          )}
        </>
      }
    >
      {trail.error ? (
        <div className="rounded-md border border-[var(--qg-notice-border)] bg-[var(--qg-notice-bg)] px-4 py-2.5 text-xs text-[var(--qg-notice-text)]">
          Advisory audit trail: {trail.error}. Generation still works; approval is not recorded until the audit log accepts it.
        </div>
      ) : null}
      {/* Evidence inputs strip */}
      <Panel className="p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <span className="inline-flex items-center gap-2 text-[11px] font-black uppercase tracking-wide text-white/45">
            <BadgeCheck className="h-4 w-4 text-emerald-400" /> Advisory grounded in
          </span>
          <div className="flex flex-wrap gap-2">
            {inputs.map((input) => (
              <span key={input.label} className="inline-flex items-center gap-1.5 rounded-md border border-white/8 bg-black/20 px-2.5 py-1 text-[11px]">
                <span className="text-white/45">{input.label}</span>
                <span className="font-mono font-bold text-white/80">{input.value}</span>
              </span>
            ))}
          </div>
        </div>
      </Panel>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        {/* Advisory body */}
        <div className="space-y-4 xl:col-span-8">
          {advisory && m && ex ? (
            <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
              {/* Header card */}
              <Panel className="p-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span className="grid h-10 w-10 place-items-center rounded-md border border-violet-400/40 bg-violet-500/10 text-violet-300">
                      <Sparkles className="h-5 w-5" />
                    </span>
                    <div>
                      <div className="text-sm font-bold text-white">Executive Advisory</div>
                      <div className="text-[11px] text-white/45">Generated {longDate(advisory.generatedAt)} · self-validated at generation time</div>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge color={readinessTone(advisory.readiness)}>Readiness {advisory.readiness}</Badge>
                    <Badge color={riskTone(advisory.risk)}>Risk {advisory.risk}</Badge>
                    <Badge color={advisory.validation === 'PASS' ? GREEN : RED}>Validation {advisory.validation}</Badge>
                  </div>
                </div>
              </Panel>

              {/* Executive Summary */}
              <Panel className="p-5">
                <div className="mb-3 flex items-center gap-2.5">
                  <span className="grid h-8 w-8 place-items-center rounded-md border border-blue-400/40 bg-blue-500/10 text-blue-300">
                    <Building2 className="h-4 w-4" />
                  </span>
                  <h3 className="text-sm font-bold text-white">Executive Summary</h3>
                </div>
                <p className="text-sm leading-relaxed text-white/70">{m.executiveSummary}</p>
                <div className="mt-4 grid grid-cols-1 gap-2.5 sm:grid-cols-3">
                  <StateRow label="Quantum Readiness" current={ex.currentReadiness} target={ex.targetReadiness} betterHigh />
                  <StateRow label="Quantum Risk" current={ex.currentRisk} target={ex.targetRisk} betterHigh={false} />
                  <StateRow label="HNDL Exposure" current={ex.currentHndl} target={ex.targetHndl} betterHigh={false} />
                </div>
                <div className="mt-3 rounded-md border border-blue-400/20 bg-blue-500/[0.06] px-3.5 py-2.5 text-xs leading-relaxed text-white/70">
                  <span className="font-bold text-blue-200">Recommendation: </span>
                  {ex.executiveRecommendation}
                </div>
                <EvidenceChips
                  items={[
                    `${integerFmt(snapshot.inventory.assetsAssessed)} assets assessed`,
                    `${integerFmt(snapshot.inventory.quantumVulnerableAssets)} quantum-vulnerable`,
                    ex.estimatedDurationWeeks ? `${integerFmt(ex.estimatedDurationWeeks)}-week programme` : '',
                    ex.estimatedCostUsd ? `Investment ${currencyFmt(ex.estimatedCostUsd)}` : '',
                    `Expected risk reduction ${integerFmt(ex.expectedRiskReductionPct)}%`,
                  ]}
                />
              </Panel>

              {/* Top Business Risks */}
              <Panel className="p-5">
                <div className="mb-3 flex items-center gap-2.5">
                  <span className="grid h-8 w-8 place-items-center rounded-md border border-orange-400/40 bg-orange-500/10 text-orange-300">
                    <ShieldAlert className="h-4 w-4" />
                  </span>
                  <h3 className="text-sm font-bold text-white">Top Business Risks</h3>
                  <span className="ml-auto text-[10px] text-white/35">Board language · each risk cites its evidence driver</span>
                </div>
                {ex.topBusinessRisks.length ? (
                  <div className="space-y-2.5">
                    {ex.topBusinessRisks.map((risk, index) => (
                      <div key={risk.risk} className="rounded-md border border-white/8 bg-black/20 p-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="grid h-6 w-6 place-items-center rounded border border-white/15 bg-white/[0.04] font-mono text-[11px] font-black text-white/60">{index + 1}</span>
                          <span className="text-xs font-bold text-white/85">{risk.risk}</span>
                          <Badge color={severityColor(risk.level)}>{risk.level}</Badge>
                        </div>
                        <p className="mt-1.5 pl-8 text-[11px] leading-snug text-white/55">
                          <span className="font-bold text-emerald-300/80">Evidence: </span>
                          {risk.driver}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState label="No evidence-backed business risks derived." />
                )}
              </Panel>

              {/* Business Impact Intelligence */}
              <Panel className="p-5">
                <div className="mb-3 flex items-center gap-2.5">
                  <span className="grid h-8 w-8 place-items-center rounded-md border border-amber-400/40 bg-amber-500/10 text-amber-300">
                    <TrendingUp className="h-4 w-4" />
                  </span>
                  <h3 className="text-sm font-bold text-white">Business Impact Intelligence</h3>
                </div>
                <div className="space-y-2.5">
                  {m.impactReasons.map((impact) => (
                    <div key={impact.dimension} className="rounded-md border border-white/8 bg-black/20 p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-bold text-white/85">{impact.dimension}</span>
                        <Badge color={severityColor(impact.level)}>{impact.level}</Badge>
                      </div>
                      <p className="mt-1 text-[11px] leading-snug text-white/60">{impact.reason}</p>
                      <EvidenceChips items={impact.evidence} />
                    </div>
                  ))}
                </div>
              </Panel>

              {/* Investment & ROI */}
              <Panel className="p-5">
                <div className="mb-3 flex items-center gap-2.5">
                  <span className="grid h-8 w-8 place-items-center rounded-md border border-emerald-400/40 bg-emerald-500/10 text-emerald-300">
                    <Banknote className="h-4 w-4" />
                  </span>
                  <h3 className="text-sm font-bold text-white">Investment & Value Intelligence</h3>
                </div>
                <div className="rounded-md border border-emerald-400/20 bg-emerald-500/[0.05] px-3.5 py-2.5 text-xs leading-relaxed text-white/70">
                  {m.roiAnalysis.paybackNarrative}
                </div>
                {m.roiAnalysis.lines.length ? (
                  <div className="mt-3 overflow-x-auto">
                    <table className="min-w-[540px] w-full text-left text-xs">
                      <thead>
                        <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                          <th className="pb-2 font-black">Value Metric</th>
                          <th className="pb-2 font-black">Expected Outcome</th>
                          <th className="pb-2 font-black">Basis / Formula</th>
                        </tr>
                      </thead>
                      <tbody>
                        {m.roiAnalysis.lines.map((line) => (
                          <tr key={line.metric} className="border-b border-white/5 text-white/65 align-top">
                            <td className="py-2 pr-3 font-semibold text-white/80">{line.metric}</td>
                            <td className="py-2 pr-3">{line.value}</td>
                            <td className="py-2 text-white/45">{line.basis}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="mt-3">
                    <EmptyState label="Run a discovery scan to model migration investment and ROI." />
                  </div>
                )}
              </Panel>

              {/* Strategic scenarios */}
              <Panel className="p-5">
                <div className="mb-3 flex items-center gap-2.5">
                  <span className="grid h-8 w-8 place-items-center rounded-md border border-blue-400/40 bg-blue-500/10 text-blue-300">
                    <Gauge className="h-4 w-4" />
                  </span>
                  <h3 className="text-sm font-bold text-white">Strategic Scenarios</h3>
                  <span className="ml-auto text-[10px] text-white/35">Quantum risk trajectory /100 — evidence-derived planning bands</span>
                </div>
                <div className="space-y-2.5">
                  <div className="rounded-md border p-3" style={{ borderColor: `${RED}30`, backgroundColor: `${RED}0d` }}>
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className="font-bold text-white/85">Do Nothing</span>
                      <Badge color={RED}>Not Recommended</Badge>
                    </div>
                    <p className="mt-1 text-[11px] leading-snug text-white/60">
                      Quantum risk remains at {snapshot.scores.quantumRisk}/100 with {integerFmt(snapshot.inventory.vulnerableComponents)} quantum-vulnerable component(s) in place, while
                      Harvest-Now-Decrypt-Later exposure ({snapshot.scores.hndlRiskLevel}) accumulates on every day of captured traffic.
                    </p>
                  </div>
                  {m.riskForecast.scenarios.filter((scenario) => !/no funded|baseline/i.test(scenario.scenario)).map((scenario) => {
                    // Scenario labels are schedule-anchored ("Funded Programme (Expected)" /
                    // "…(Worst Case — 2× slippage)"); match on keywords so legacy saved
                    // reports ("Best Case" / "Expected" / "Worst Case") still color correctly.
                    // The no-programme baseline is excluded — the "Do Nothing" card above
                    // already presents it with richer evidence copy.
                    const isBest = /best/i.test(scenario.scenario);
                    const isExpected = /expected/i.test(scenario.scenario) && !/worst/i.test(scenario.scenario);
                    const color = isBest ? EMERALD : isExpected ? BLUE : ORANGE;
                    const label = isBest ? 'Accelerated Programme' : isExpected ? 'Recommended Programme' : 'Constrained / Slipped';
                    return (
                      <div key={scenario.scenario} className="rounded-md border p-3" style={{ borderColor: `${color}30`, backgroundColor: `${color}0d` }}>
                        <div className="flex flex-wrap items-center gap-2 text-xs">
                          <span className="font-bold text-white/85">{label}</span>
                          <Badge color={color}>{scenario.scenario}</Badge>
                          <span className="ml-auto font-mono text-[11px] text-white/60">
                            12mo {scenario.month12} · 24mo {scenario.month24} · 36mo {scenario.month36}
                          </span>
                        </div>
                        <p className="mt-1 text-[11px] leading-snug text-white/55">{scenario.assumption}</p>
                      </div>
                    );
                  })}
                </div>
              </Panel>

              {/* Executive Decision Register */}
              <Panel className="p-5">
                <div className="mb-3 flex items-center gap-2.5">
                  <span className="grid h-8 w-8 place-items-center rounded-md border border-violet-400/40 bg-violet-500/10 text-violet-300">
                    <ListChecks className="h-4 w-4" />
                  </span>
                  <h3 className="text-sm font-bold text-white">Executive Decision Register</h3>
                  <span className="ml-auto text-[10px] text-white/35">Decisions leadership must make today</span>
                </div>
                <div className="space-y-2.5">
                  {m.executiveDecisions.map((decision) => (
                    <div key={decision.decision} className="rounded-md border border-white/8 bg-black/20 p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-bold text-white/85">{decision.decision}</span>
                        <Badge color={VIOLET}>{decision.type}</Badge>
                        <span className="ml-auto text-[10px] font-bold text-white/45">Owner: {decision.owner}</span>
                      </div>
                      <p className="mt-1 text-[11px] leading-snug text-white/55">{decision.rationale}</p>
                    </div>
                  ))}
                </div>
              </Panel>

              {/* Decision traceability */}
              <Panel className="p-5">
                <div className="mb-3 flex items-center gap-2.5">
                  <span className="grid h-8 w-8 place-items-center rounded-md border border-emerald-400/40 bg-emerald-500/10 text-emerald-300">
                    <ScrollText className="h-4 w-4" />
                  </span>
                  <h3 className="text-sm font-bold text-white">Decision Traceability</h3>
                </div>
                <p className="mb-3 text-[11px] text-white/45">{m.decisionChain.headline}</p>
                <div className="space-y-1.5">
                  {m.decisionChain.steps.map((step, index) => (
                    <div key={step.stage} className="grid grid-cols-[24px_130px_1fr] items-start gap-2 rounded border border-white/5 bg-black/15 px-2.5 py-1.5 text-[11px]">
                      <span className="font-mono font-black text-white/35">{index + 1}</span>
                      <span className="font-bold text-blue-200/90">{step.stage}</span>
                      <span className="leading-snug text-white/60">{step.detail}</span>
                    </div>
                  ))}
                </div>
              </Panel>
            </motion.div>
          ) : (
            <Panel className="p-10">
              <div className="flex flex-col items-center justify-center gap-4 text-center">
                <span className="grid h-16 w-16 place-items-center rounded-full border border-violet-400/30 bg-violet-500/10 text-violet-300">
                  <Sparkles className="h-8 w-8" />
                </span>
                <div>
                  <div className="text-base font-bold text-white">{snapshot.hasData ? 'Generate an executive advisory' : 'Assessment evidence required'}</div>
                  <p className="mx-auto mt-1 max-w-md text-sm text-white/55">
                    {snapshot.hasData
                      ? 'Synthesize board-ready business risks, investment guidance, strategic scenarios and the executive decision register — every statement grounded in your assessment evidence and self-validated before display.'
                      : 'Run a discovery scan to collect the evidence the advisor requires before it can generate guidance.'}
                  </p>
                </div>
                {snapshot.hasData ? (
                  <PrimaryButton icon={Sparkles} onClick={generate}>
                    Generate Advisory
                  </PrimaryButton>
                ) : null}
              </div>
            </Panel>
          )}
        </div>

        {/* Right rail: board statement, confidence, benchmarking, guardrails, audit */}
        <div className="space-y-4 xl:col-span-4">
          {advisory && m ? (
            <>
              <Panel className="p-5">
                <SectionTitle suffix={<ScrollText className="h-4 w-4 text-white/40" />}>Board-Level Risk Statement</SectionTitle>
                <p className="text-sm leading-relaxed" style={{ color: advisory.risk >= 40 ? '#FCA5A5' : '#86EFAC' }}>
                  {boardStatement}
                </p>
                <p className="mt-2 text-[11px] leading-snug text-white/45">{m.benchmarking.percentileNarrative}</p>
                <p className="mt-2 text-[10px] leading-snug text-white/30">{m.benchmarking.note}</p>
              </Panel>

              <Panel className="p-5">
                <SectionTitle suffix={<Gauge className="h-4 w-4 text-white/40" />}>Advisory Confidence</SectionTitle>
                <div className="space-y-2.5">
                  {[
                    { label: 'Assessment Evidence Confidence', value: m.confidenceSummary.assessmentConfidencePct },
                    { label: 'Migration Plan Confidence', value: m.confidenceSummary.migrationPlanConfidencePct },
                    { label: 'Migration Forecast Confidence', value: m.confidenceSummary.migrationForecastConfidencePct },
                    { label: 'Evidence Source Confidence', value: m.confidenceSummary.evidenceConfidencePct },
                  ].map((row) => (
                    <div key={row.label} className="text-[11px]">
                      <div className="flex items-center justify-between text-white/60">
                        <span>{row.label}</span>
                        <span className="font-mono font-bold text-white/80">{integerFmt(row.value)}%</span>
                      </div>
                      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-white/5">
                        <div className="h-full rounded-full" style={{ width: `${Math.min(100, row.value)}%`, backgroundColor: row.value >= 75 ? GREEN : row.value >= 40 ? ORANGE : RED }} />
                      </div>
                    </div>
                  ))}
                  <div className="flex items-center justify-between text-[11px] text-white/60">
                    <span>Wave Confidence (range)</span>
                    <span className="font-mono font-bold text-white/80">{m.confidenceSummary.waveConfidenceRange}</span>
                  </div>
                </div>
                <p className="mt-3 text-[10px] leading-snug text-white/35">{m.confidenceSummary.note}</p>
              </Panel>

              <Panel className="p-5">
                <SectionTitle suffix={<Landmark className="h-4 w-4 text-white/40" />}>Risk Acceptance Positions</SectionTitle>
                <div className="space-y-2">
                  {m.riskAcceptance.length > 4 ? (
                    <div className="text-[10px] text-white/35">
                      Showing the 4 highest-exposure of {m.riskAcceptance.length} risk-acceptance positions.
                    </div>
                  ) : null}
                  {m.riskAcceptance.slice(0, 4).map((item) => (
                    <div key={item.risk} className="rounded border border-white/8 bg-black/20 px-2.5 py-2 text-[11px]">
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate font-semibold text-white/75">{item.risk}</span>
                        <Badge color={item.decision === 'Mitigate' ? GREEN : item.decision === 'Accept' ? ORANGE : item.decision === 'Transfer' ? BLUE : VIOLET}>{item.decision}</Badge>
                      </div>
                      <div className="mt-1 text-[10px] text-white/40">
                        {item.approver} · {item.approvalStatus}
                      </div>
                    </div>
                  ))}
                </div>
              </Panel>
            </>
          ) : null}

          <Panel className="p-5">
            <SectionTitle suffix={<BadgeCheck className="h-4 w-4 text-emerald-400" />}>Guardrails</SectionTitle>
            <ul className="space-y-2 text-xs text-white/60">
              {[
                'Same evidence engine as the enterprise reports — the advisory can never contradict them',
                'No unsupported findings: every statement traces to scan, CBOM, certificate, key or runtime evidence',
                'Arithmetic and cross-section consistency self-validate at generation time (PASS/FAIL badge)',
                'Target algorithms resolve through the active crypto-policy profile (NIST FIPS 203/204/205)',
                'Peer benchmarks are labelled modeled reference points — never presented as tenant telemetry',
                'Every generation and approval is written to the tenant audit log, with the approver',
              ].map((rule) => (
                <li key={rule} className="flex items-start gap-2">
                  <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                  {rule}
                </li>
              ))}
            </ul>
          </Panel>

          <Panel className="p-5">
            <SectionTitle suffix={<History className="h-4 w-4 text-white/40" />}>Advisory Audit Trail</SectionTitle>
            {auditRows.length ? (
              <div className="space-y-2">
                {auditRows.map((item) => {
                  const reopenable = sessionModels[item.id];
                  return (
                    <button
                      key={item.id}
                      type="button"
                      disabled={!reopenable}
                      onClick={() => reopenable && setAdvisory(reopenable)}
                      title={reopenable ? 'Reopen this advisory' : 'Recorded in the audit log — regenerate to view current figures'}
                      className={`flex w-full items-center justify-between gap-2 rounded-md border px-3 py-2 text-left text-xs transition disabled:cursor-default ${
                        advisory?.id === item.id ? 'border-violet-400/45 bg-violet-500/10' : 'border-white/8 bg-black/20 enabled:hover:border-blue-400/35'
                      }`}
                    >
                      <span className="min-w-0">
                        <span className="block truncate font-semibold text-white/80">{longDate(item.generatedAt)}</span>
                        <span className="inline-flex items-center gap-1.5 text-[10px] text-white/40">
                          Readiness {item.readiness ?? '—'} · Risk {item.risk ?? '—'} ·
                          {item.validation === 'PASS' ? <CheckCircle2 className="h-3 w-3 text-emerald-400" /> : <XCircle className="h-3 w-3 text-red-400" />}
                          {item.validation}
                        </span>
                        {item.approved && item.approvedBy ? <span className="block truncate text-[10px] text-white/30">Approved by {item.approvedBy}</span> : null}
                      </span>
                      {item.approved ? <Badge color={GREEN}>Approved</Badge> : <Badge color={BLUE}>Draft</Badge>}
                    </button>
                  );
                })}
              </div>
            ) : (
              <EmptyState label={trail.loaded ? 'No advisories generated yet.' : 'Loading audit trail…'} hint="Every generation and approval is recorded in your tenant audit log." />
            )}
          </Panel>

          <Panel className="p-4">
            <Link to="/dashboard/quantum-readiness/reports" className="inline-flex items-center gap-2 text-xs font-bold text-blue-300 no-underline transition hover:text-blue-200">
              <FileText className="h-4 w-4" /> Generate the full board report in the Report Center
            </Link>
          </Panel>
        </div>
      </section>
    </QuantumReadinessShell>
  );
}
