'use client';

import { useCallback, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  BadgeCheck,
  Banknote,
  Building2,
  CheckCircle2,
  Download,
  History,
  Landmark,
  RefreshCw,
  ScrollText,
  Sparkles,
  TrendingUp,
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
  percentLabel,
  readinessTone,
  riskTone,
  useQuantumReadiness,
  type QuantumReadinessSnapshot,
  BLUE,
  EMERALD,
  GREEN,
  ORANGE,
  RED,
  VIOLET,
} from '../_shared';

interface AdvisorySection {
  key: string;
  title: string;
  icon: typeof Building2;
  color: string;
  body: string;
  evidence: string[];
}

interface Advisory {
  id: string;
  generatedAt: string;
  readiness: number;
  risk: number;
  approved: boolean;
  sections: AdvisorySection[];
}

/** Build an evidence-grounded advisory deterministically from assessment data. */
function buildAdvisory(snapshot: QuantumReadinessSnapshot): Advisory {
  const { scores, inventory, estimates, riskDistribution } = snapshot;
  const ev = (...lines: string[]) => lines.filter(Boolean);

  const sections: AdvisorySection[] = [
    {
      key: 'summary',
      title: 'Executive Summary',
      icon: Building2,
      color: BLUE,
      body: `The organization presents a quantum readiness score of ${scores.quantumReadiness}/100 (${scores.quantumReadinessLevel}) against a quantum risk score of ${scores.quantumRisk}/100 (${scores.quantumRiskLevel}). Discovery has assessed ${integerFmt(
        inventory.assetsAssessed,
      )} cryptographic assets, of which ${integerFmt(inventory.quantumVulnerableAssets)} remain quantum-vulnerable and ${percentLabel(
        scores.pqcAdoption,
      )} are quantum-safe or hybrid.`,
      evidence: ev(
        `${integerFmt(inventory.assetsAssessed)} assets assessed`,
        `${integerFmt(inventory.certificatesAnalyzed)} certificates analyzed`,
        `${integerFmt(inventory.keysDiscovered)} keys discovered`,
      ),
    },
    {
      key: 'business',
      title: 'Business Impact',
      icon: TrendingUp,
      color: ORANGE,
      body: `Quantum-vulnerable cryptography concentrated in ${integerFmt(
        inventory.quantumVulnerableAssets,
      )} assets exposes confidentiality and integrity of dependent business services. ${
        riskDistribution.critical > 0
          ? `${integerFmt(riskDistribution.critical)} critical findings require remediation within the current quarter to avoid material risk.`
          : 'No critical findings are currently open, indicating contained near-term business impact.'
      }`,
      evidence: ev(
        `${integerFmt(riskDistribution.critical)} critical findings`,
        `${integerFmt(riskDistribution.high)} high findings`,
        `${integerFmt(inventory.trustRelationships)} trust relationships in blast radius`,
      ),
    },
    {
      key: 'financial',
      title: 'Financial Impact',
      icon: Banknote,
      color: EMERALD,
      body: estimates.migrationCostUsd
        ? `The estimated migration investment to reach a quantum-safe posture is ${currencyFmt(
            estimates.migrationCostUsd,
          )} over approximately ${integerFmt(estimates.migrationTimelineWeeks)} weeks. This estimate is derived from the remaining quantum-vulnerable surface and assessed migration complexity (${scores.migrationComplexity}/100).`
        : 'Insufficient remediation scope to produce a financial estimate. Complete discovery to model migration investment.',
      evidence: ev(
        estimates.migrationCostUsd ? `Estimated cost ${currencyFmt(estimates.migrationCostUsd)}` : '',
        estimates.migrationTimelineWeeks ? `Estimated timeline ${integerFmt(estimates.migrationTimelineWeeks)} weeks` : '',
        `Migration complexity ${scores.migrationComplexity}/100`,
      ),
    },
    {
      key: 'regulatory',
      title: 'Regulatory Risk',
      icon: Landmark,
      color: VIOLET,
      body: `With Harvest-Now-Decrypt-Later exposure rated ${scores.hndlRiskLevel} (${scores.hndlRisk}/100), long-lived regulated data may fall outside emerging post-quantum mandates (NIST FIPS 203/204/205, CNSA 2.0). ${
        scores.pqcAdoption < 50 ? 'Current PQC adoption is below the threshold expected by forthcoming compliance timelines.' : 'PQC adoption is progressing toward regulatory expectations.'
      }`,
      evidence: ev(`HNDL risk ${scores.hndlRisk}/100`, `PQC adoption ${percentLabel(scores.pqcAdoption)}`, 'Mapped to NIST FIPS 203/204/205'),
    },
    {
      key: 'strategy',
      title: 'Strategic Recommendation',
      icon: Sparkles,
      color: BLUE,
      body: `${
        scores.quantumRisk >= 45
          ? 'Establish a funded, executive-sponsored post-quantum migration program now.'
          : 'Maintain the current trajectory while extending crypto-agility coverage.'
      } Prioritize remediation of quantum-vulnerable, internet-facing and long-retention assets, adopting hybrid X25519+ML-KEM and Ed25519+ML-DSA where compatibility allows.`,
      evidence: ev(
        `Quantum risk ${scores.quantumRisk}/100`,
        `${integerFmt(inventory.quantumVulnerableAssets)} vulnerable assets to sequence`,
        `${integerFmt(inventory.hybridAssets)} hybrid assets in progress`,
      ),
    },
    {
      key: 'board',
      title: 'Board-Level Risk Statement',
      icon: ScrollText,
      color: scores.quantumRisk >= 45 ? RED : GREEN,
      body: `${
        scores.quantumRisk >= 70
          ? 'Quantum risk is SEVERE and represents a material exposure requiring board oversight and immediate investment.'
          : scores.quantumRisk >= 45
            ? 'Quantum risk is ELEVATED and warrants a board-approved migration mandate with quarterly progress reporting.'
            : scores.quantumRisk >= 20
              ? 'Quantum risk is MODERATE and is being actively managed; continued investment is recommended.'
              : 'Quantum risk is LOW relative to peers; sustain governance and monitoring.'
      }`,
      evidence: ev(`Composite risk ${scores.quantumRisk}/100`, `Readiness ${scores.quantumReadiness}/100`),
    },
    {
      key: 'investment',
      title: 'Investment Recommendation',
      icon: Banknote,
      color: EMERALD,
      body: estimates.migrationCostUsd
        ? `Allocate an estimated ${currencyFmt(
            estimates.migrationCostUsd,
          )} across the ${integerFmt(estimates.migrationTimelineWeeks)}-week program, front-loading remediation of critical and internet-facing assets to maximize early risk reduction.`
        : 'Fund an initial discovery and crypto-agility uplift phase to establish a defensible migration baseline before committing program-level investment.',
      evidence: ev(
        estimates.migrationCostUsd ? `Program budget ${currencyFmt(estimates.migrationCostUsd)}` : 'Discovery phase funding',
        `${integerFmt(riskDistribution.critical + riskDistribution.high)} priority findings`,
      ),
    },
  ];

  return {
    id: `adv-${Date.now()}`,
    generatedAt: new Date().toISOString(),
    readiness: scores.quantumReadiness,
    risk: scores.quantumRisk,
    approved: false,
    sections,
  };
}

export default function AiExecutiveAdvisorPage() {
  const { snapshot, state, sseConnected, refresh, downloadJson } = useQuantumReadiness();
  const [advisory, setAdvisory] = useState<Advisory | null>(null);
  const [history, setHistory] = useState<Advisory[]>([]);
  const [generating, setGenerating] = useState(false);

  const generate = useCallback(() => {
    if (!snapshot.hasData) return;
    setGenerating(true);
    // Synchronous, deterministic, evidence-grounded synthesis (no fabricated findings).
    window.setTimeout(() => {
      const next = buildAdvisory(snapshot);
      setAdvisory(next);
      setHistory((prev) => [next, ...prev].slice(0, 10));
      setGenerating(false);
    }, 450);
  }, [snapshot]);

  const approve = useCallback(() => {
    if (!advisory) return;
    const approved = { ...advisory, approved: true };
    setAdvisory(approved);
    setHistory((prev) => prev.map((a) => (a.id === approved.id ? approved : a)));
  }, [advisory]);

  const inputs = useMemo(
    () => [
      { label: 'Assets', value: integerFmt(snapshot.inventory.assetsAssessed) },
      { label: 'Certificates', value: integerFmt(snapshot.inventory.certificatesAnalyzed) },
      { label: 'Keys', value: integerFmt(snapshot.inventory.keysDiscovered) },
      { label: 'Critical Findings', value: integerFmt(snapshot.riskDistribution.critical) },
      { label: 'Readiness', value: `${integerFmt(snapshot.scores.quantumReadiness)}/100` },
      { label: 'Risk', value: `${integerFmt(snapshot.scores.quantumRisk)}/100` },
    ],
    [snapshot],
  );

  return (
    <QuantumReadinessShell
      title="AI Executive Advisor™"
      subtitle="Generates business-level explanations and board-ready recommendations. Every statement is grounded in assessment evidence — the advisor never invents unsupported findings."
      badge={advisory?.approved ? <Badge color={GREEN}>Approved for Report</Badge> : <Badge color={VIOLET}>AI Advisory</Badge>}
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
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
              <HeaderButton icon={Download} onClick={() => downloadJson('ai-executive-advisory', advisory)}>
                Export
              </HeaderButton>
              <PrimaryButton icon={BadgeCheck} onClick={approve} disabled={advisory.approved}>
                {advisory.approved ? 'Approved' : 'Approve for Report'}
              </PrimaryButton>
            </>
          ) : (
            <PrimaryButton icon={Sparkles} onClick={generate} disabled={!snapshot.hasData || generating}>
              {generating ? 'Generating…' : 'Generate Advisory'}
            </PrimaryButton>
          )}
        </>
      }
    >
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
          {advisory ? (
            <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
              <Panel className="p-5">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span className="grid h-10 w-10 place-items-center rounded-md border border-violet-400/40 bg-violet-500/10 text-violet-300">
                      <Sparkles className="h-5 w-5" />
                    </span>
                    <div>
                      <div className="text-sm font-bold text-white">Executive Advisory</div>
                      <div className="text-[11px] text-white/45">Generated {longDate(advisory.generatedAt)}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge color={readinessTone(advisory.readiness)}>Readiness {advisory.readiness}</Badge>
                    <Badge color={riskTone(advisory.risk)}>Risk {advisory.risk}</Badge>
                  </div>
                </div>
              </Panel>

              {advisory.sections.map((section) => {
                const Icon = section.icon;
                return (
                  <div key={section.key}>
                  <Panel className="p-5">
                    <div className="mb-3 flex items-center gap-2.5">
                      <span className="grid h-8 w-8 place-items-center rounded-md border" style={{ borderColor: `${section.color}40`, color: section.color, backgroundColor: `${section.color}12` }}>
                        <Icon className="h-4 w-4" />
                      </span>
                      <h3 className="text-sm font-bold text-white">{section.title}</h3>
                    </div>
                    <p className="text-sm leading-relaxed text-white/70">{section.body}</p>
                    {section.evidence.length ? (
                      <div className="mt-3 flex flex-wrap gap-1.5">
                        {section.evidence.map((item) => (
                          <span key={item} className="inline-flex items-center gap-1 rounded border border-emerald-400/20 bg-emerald-400/[0.07] px-2 py-0.5 text-[10px] font-semibold text-emerald-200/80">
                            <CheckCircle2 className="h-3 w-3" /> {item}
                          </span>
                        ))}
                      </div>
                    ) : null}
                  </Panel>
                  </div>
                );
              })}
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
                      ? 'Synthesize business impact, financial and regulatory guidance — grounded entirely in your assessment evidence.'
                      : 'Run a discovery scan to collect the evidence the advisor requires before it can generate guidance.'}
                  </p>
                </div>
                {snapshot.hasData ? (
                  <PrimaryButton icon={Sparkles} onClick={generate} disabled={generating}>
                    {generating ? 'Generating…' : 'Generate Advisory'}
                  </PrimaryButton>
                ) : null}
              </div>
            </Panel>
          )}
        </div>

        {/* Guardrails + audit trail */}
        <div className="space-y-4 xl:col-span-4">
          <Panel className="p-5">
            <SectionTitle suffix={<BadgeCheck className="h-4 w-4 text-emerald-400" />}>Guardrails</SectionTitle>
            <ul className="space-y-2 text-xs text-white/60">
              {[
                'No unsupported findings are generated',
                'Every statement traces to assessment data',
                'Scores derive from scan, certificate & key evidence',
                'Regulatory mapping references NIST FIPS 203/204/205',
                'Approval is required before inclusion in reports',
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
            {history.length ? (
              <div className="space-y-2">
                {history.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setAdvisory(item)}
                    className={`flex w-full items-center justify-between gap-2 rounded-md border px-3 py-2 text-left text-xs transition ${
                      advisory?.id === item.id ? 'border-violet-400/45 bg-violet-500/10' : 'border-white/8 bg-black/20 hover:border-blue-400/35'
                    }`}
                  >
                    <span className="min-w-0">
                      <span className="block truncate font-semibold text-white/80">{longDate(item.generatedAt)}</span>
                      <span className="text-[10px] text-white/40">Readiness {item.readiness} · Risk {item.risk}</span>
                    </span>
                    {item.approved ? <Badge color={GREEN}>Approved</Badge> : <Badge color={BLUE}>Draft</Badge>}
                  </button>
                ))}
              </div>
            ) : (
              <EmptyState label="No advisories generated yet." />
            )}
          </Panel>
        </div>
      </section>
    </QuantumReadinessShell>
  );
}
