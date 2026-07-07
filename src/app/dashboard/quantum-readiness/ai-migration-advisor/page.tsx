'use client';

import { useCallback, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Boxes,
  BrainCircuit,
  CalendarClock,
  CheckCircle2,
  Download,
  FlaskConical,
  GitBranch,
  Layers,
  Network,
  RefreshCw,
  Rocket,
  RotateCcw,
  Sparkles,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import {
  Badge,
  EmptyState,
  HeaderButton,
  MetricCard,
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
  AMBER,
  BLUE,
  EMERALD,
  GREEN,
  ORANGE,
  RED,
  GOLD,
  VIOLET,
} from '../_shared';
import { useAuth } from '@/contexts/auth-context';
import { buildMigrationHandoff, useAdvisorModel, waveForAsset, writeMigrationHandoff } from '../_advisor';

/**
 * AI Migration Advisor™ — enterprise migration decision support.
 *
 * The roadmap, waves, prioritization, dependency analysis and rollback
 * strategy all come from the SAME unified report engine the Report Center
 * exports (buildReportModel): evidence-scoped adaptive waves whose risk
 * reductions reconcile with the executive block and risk forecast, target
 * algorithms resolved through the active crypto-policy profile, and per-
 * finding rollback runbooks with change-management fields. Handoff writes
 * the exact displayed roadmap for the Migration Planner / Sandbox.
 */

const WAVE_COLORS = [RED, ORANGE, GOLD, BLUE, VIOLET];

export default function AiMigrationAdvisorPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { snapshot, state, sseConnected, refresh, downloadJson } = useQuantumReadiness();
  const model = useAdvisorModel(snapshot, user?.email || 'QGuard Helix');
  const [generated, setGenerated] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [handoffNote, setHandoffNote] = useState<string | null>(null);

  const generate = useCallback(() => {
    if (!snapshot.hasData) return;
    setGenerating(true);
    window.setTimeout(() => {
      setGenerated(true);
      setGenerating(false);
    }, 450);
  }, [snapshot.hasData]);

  const { scores, inventory, estimates } = snapshot;
  const advisor = model.migrationAdvisor;
  const waves = model.migrationWaves;
  const deps = model.dependencyAnalysis;

  const handoff = useCallback(
    (target: 'planner' | 'sandbox') => {
      const payload = buildMigrationHandoff(snapshot, model, user?.email || 'QGuard Helix');
      const ok = writeMigrationHandoff(payload);
      setHandoffNote(ok ? `Roadmap handed off (${payload.waves.length} waves) — opening ${target === 'planner' ? 'Migration Planner' : 'Migration Sandbox'}…` : 'Handoff storage unavailable — continuing with navigation only.');
      window.setTimeout(() => navigate(target === 'planner' ? '/dashboard/migration-planner' : '/dashboard/migration-sandbox'), 350);
    },
    [snapshot, model, user, navigate],
  );

  const exportRoadmap = useCallback(() => {
    downloadJson('ai-migration-roadmap', buildMigrationHandoff(snapshot, model, user?.email || 'QGuard Helix'));
  }, [downloadJson, snapshot, model, user]);

  const kpis = [
    { label: 'Migration Complexity', value: integerFmt(scores.migrationComplexity), suffix: '/100', detail: scores.migrationComplexityLevel, color: riskTone(scores.migrationComplexity), ring: scores.migrationComplexity },
    { label: 'Migration Effort', value: integerFmt(scores.migrationEffort), suffix: '/100', detail: 'Remaining surface', color: GOLD, ring: scores.migrationEffort },
    { label: 'Est. Timeline', value: estimates.migrationTimelineWeeks ? `${integerFmt(estimates.migrationTimelineWeeks)}w` : '—', detail: 'To quantum-safe', color: BLUE, icon: CalendarClock },
    { label: 'Est. Cost', value: estimates.migrationCostUsd ? currencyFmt(estimates.migrationCostUsd) : '—', detail: 'Programme investment', color: EMERALD, icon: Boxes },
    { label: 'Vulnerable Assets', value: integerFmt(inventory.quantumVulnerableAssets), detail: 'To migrate', color: RED, icon: AlertTriangle },
    { label: 'Hybrid In-Progress', value: integerFmt(inventory.hybridAssets), detail: 'Transitioning', color: AMBER, icon: Layers },
  ];

  // Evidence-gated compatibility considerations — each renders ONLY when the
  // evidence it references exists in this tenant's assessment.
  const compatibility = useMemo(() => {
    const internetNodes = snapshot.exposureGraph.nodes.filter((n) => n.internetFacing).length;
    const out: Array<{ level: 'high' | 'medium'; text: string; evidence: string }> = [];
    if (internetNodes > 0 || inventory.domainsScanned > 0) {
      out.push({
        level: 'high',
        text: 'Public clients without ML-KEM support require hybrid mode (X25519 + ML-KEM) during the transition window.',
        evidence: `${integerFmt(Math.max(internetNodes, 1))} internet-facing asset(s) / ${integerFmt(inventory.domainsScanned)} scanned domain(s)`,
      });
    }
    if (inventory.keysDiscovered > 0) {
      out.push({
        level: 'medium',
        text: 'HSM / KMS firmware must support PQC algorithms before key-generation cutover.',
        evidence: `${integerFmt(inventory.keysDiscovered)} key(s) in inventory`,
      });
    }
    if (inventory.certificatesAnalyzed > 0) {
      out.push({
        level: 'medium',
        text: 'Hybrid certificate chains are larger — verify MTU, TLS record and client buffer limits before PKI cutover.',
        evidence: `${integerFmt(inventory.certificatesAnalyzed)} certificate(s) analysed`,
      });
    }
    if (snapshot.exposureGraph.edges.length === 0 && inventory.trustRelationships === 0) {
      out.push({
        level: 'medium',
        text: 'No explicit dependency edges discovered — sequencing uses the inferred transport topology. Map asset relationships to raise plan confidence.',
        evidence: 'Dependency visibility limited',
      });
    }
    return out;
  }, [snapshot, inventory]);

  return (
    <QuantumReadinessShell
      title="AI Migration Advisor™"
      subtitle="Generates a dependency-aware migration roadmap, wave plan, prioritization and rollback strategy from the same validated evidence engine as the enterprise reports — ready to hand off to the Migration Planner or Sandbox."
      badge={generated ? <Badge color={EMERALD}>Roadmap Ready</Badge> : <Badge color={ORANGE}>AI Migration</Badge>}
      sseConnected={sseConnected}
      state={state}
      snapshot={snapshot}
      actions={
        <>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>
            Refresh
          </HeaderButton>
          {generated ? (
            <>
              <HeaderButton icon={Sparkles} onClick={generate}>
                Regenerate
              </HeaderButton>
              <HeaderButton icon={Download} onClick={exportRoadmap}>
                Export Roadmap
              </HeaderButton>
            </>
          ) : (
            <PrimaryButton icon={BrainCircuit} onClick={generate} disabled={!snapshot.hasData || generating}>
              {generating ? 'Generating…' : 'Generate Migration Advisory'}
            </PrimaryButton>
          )}
        </>
      }
    >
      <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
        {kpis.map((kpi) => (
          <div key={kpi.label}>
            <MetricCard {...kpi} />
          </div>
        ))}
      </motion.section>

      {generated ? (
        <>
          {/* Primary recommendation */}
          <Panel className="p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="grid h-9 w-9 place-items-center rounded-md border border-orange-400/40 bg-orange-500/10 text-orange-300">
                    <BrainCircuit className="h-4.5 w-4.5" />
                  </span>
                  <h3 className="text-base font-bold text-white">{advisor.recommendation}</h3>
                  <Badge color={advisor.confidencePct >= 80 ? GREEN : advisor.confidencePct >= 60 ? GOLD : ORANGE}>Confidence {advisor.confidencePct}%</Badge>
                </div>
                <p className="mt-2 max-w-3xl text-sm leading-relaxed text-white/65">{advisor.reason}</p>
                <p className="mt-2 max-w-3xl text-[11px] leading-snug text-white/45">
                  <span className="font-bold text-emerald-300/80">Why this recommendation: </span>
                  {model.advisorValidation.why}
                </p>
              </div>
              <div className="grid shrink-0 grid-cols-2 gap-2 sm:grid-cols-4">
                {[
                  { k: 'Risk Reduction', v: `${advisor.riskReductionPct}%` },
                  { k: 'Wave 1 Cost', v: advisor.costUsd ? currencyFmt(advisor.costUsd) : '—' },
                  { k: 'Wave 1 Timeline', v: `${advisor.timelineWeeks}w` },
                  { k: 'Success Probability', v: `${advisor.successProbabilityPct}%` },
                ].map((item) => (
                  <div key={item.k} className="rounded-md border border-white/8 bg-black/20 px-2.5 py-2 text-center">
                    <div className="font-mono text-sm font-bold text-white">{item.v}</div>
                    <div className="text-[9px] uppercase tracking-wide text-white/40">{item.k}</div>
                  </div>
                ))}
              </div>
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {[
                `Primary exposure: ${model.advisorValidation.primaryExposureDomain}`,
                `${integerFmt(snapshot.criticalFindings.length)} graded finding(s)`,
                `${integerFmt(inventory.assetsAssessed)} asset(s) in scope`,
                ...(advisor.affectedAssets.length ? [`Affects: ${advisor.affectedAssets.slice(0, 3).join(', ')}${advisor.affectedAssets.length > 3 ? '…' : ''}`] : []),
              ].map((chip) => (
                <span key={chip} className="inline-flex items-center gap-1 rounded border border-emerald-400/20 bg-emerald-400/[0.07] px-2 py-0.5 text-[10px] font-semibold text-emerald-200/80">
                  <CheckCircle2 className="h-3 w-3" /> {chip}
                </span>
              ))}
            </div>
          </Panel>

          {/* Wave planner — engine-generated, reconciled */}
          <Panel className="p-5">
            <SectionTitle suffix={<span className="text-[11px] text-white/40">Σ wave risk reductions = programme target ({model.executiveBlock.expectedRiskReductionPct}%) — reconciled with the executive block</span>}>
              Migration Wave Planner
            </SectionTitle>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
              {waves.map((wave) => {
                const color = WAVE_COLORS[(wave.wave - 1) % WAVE_COLORS.length];
                return (
                  <div key={wave.wave} className="rounded-lg border border-white/8 bg-white/[0.025] p-4">
                    <div className="flex items-center justify-between">
                      <span className="inline-flex items-center gap-2">
                        <span className="grid h-7 w-7 place-items-center rounded-md border text-xs font-black" style={{ borderColor: `${color}45`, color, backgroundColor: `${color}12` }}>
                          {wave.wave}
                        </span>
                        <span className="text-sm font-bold text-white">{wave.name}</span>
                      </span>
                      <Badge color={color}>{wave.priority}</Badge>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] text-white/45">
                      <span>Owner: <span className="font-bold text-white/70">{wave.owner}</span></span>
                      <span>·</span>
                      <span>Status: <span className="font-bold text-white/70">{wave.status}</span></span>
                    </div>
                    <div className="mt-3 grid grid-cols-3 gap-2 text-[11px]">
                      <div className="rounded border border-white/8 bg-black/20 px-2 py-1.5">
                        <div className="font-mono text-sm text-white">{integerFmt(wave.durationWeeks)}w</div>
                        <div className="text-[9px] uppercase tracking-wide text-white/40">Duration</div>
                      </div>
                      <div className="rounded border border-white/8 bg-black/20 px-2 py-1.5">
                        <div className="font-mono text-sm text-white">{wave.costUsd ? currencyFmt(wave.costUsd) : '—'}</div>
                        <div className="text-[9px] uppercase tracking-wide text-white/40">Cost</div>
                      </div>
                      <div className="rounded border border-white/8 bg-black/20 px-2 py-1.5">
                        <div className="font-mono text-sm" style={{ color: EMERALD }}>−{integerFmt(wave.riskReductionPct)}%</div>
                        <div className="text-[9px] uppercase tracking-wide text-white/40">Risk</div>
                      </div>
                    </div>
                    <div className="mt-3 rounded border border-white/8 bg-black/20 px-2.5 py-2 text-[11px] leading-snug text-white/55">
                      <span className="font-bold text-white/70">Scope: </span>
                      {wave.assets.slice(0, 4).join(', ')}
                      {wave.assets.length > 4 ? ` +${wave.assets.length - 4} more` : ''}
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {wave.dependencies.map((dep) => (
                        <span key={dep} className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/[0.03] px-1.5 py-0.5 text-[9px] font-semibold text-white/50">
                          <GitBranch className="h-2.5 w-2.5" /> {dep}
                        </span>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Readiness progression ladder */}
            {model.readinessProgression.length ? (
              <div className="mt-5 rounded-lg border border-white/8 bg-black/20 p-4">
                <div className="mb-3 text-[10px] font-black uppercase tracking-[0.08em] text-white/45">Projected Readiness Progression</div>
                <div className="flex flex-wrap items-center gap-2">
                  {model.readinessProgression.map((step, index) => (
                    <div key={step.stage} className="flex items-center gap-2">
                      {index > 0 ? <ArrowRight className="h-4 w-4 text-white/25" /> : null}
                      <div
                        className="rounded-md border px-3 py-2 text-center"
                        style={{ borderColor: `${readinessTone(step.readiness)}35`, backgroundColor: `${readinessTone(step.readiness)}0d` }}
                        title={step.detail}
                      >
                        <div className="font-mono text-lg font-bold" style={{ color: readinessTone(step.readiness) }}>
                          {step.readiness}
                        </div>
                        <div className="max-w-[150px] text-[9px] leading-tight text-white/50">{step.stage.replace(' — Entire Programme (+ Validation, Optimization & Governance)', ' (Entire Programme)')}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </Panel>

          {/* Dependency analysis */}
          <Panel className="p-5">
            <SectionTitle suffix={<Network className="h-4 w-4 text-white/40" />}>Dependency Analysis & Blast Radius</SectionTitle>
            <p className="mb-3 text-[11px] leading-snug text-white/50">{deps.summary}</p>
            <div className="space-y-2">
              {deps.chains.map((chain) => (
                <div key={chain.path} className="rounded-md border border-white/8 bg-black/20 p-3">
                  <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-white/70">
                    {chain.path.split('->').map((hop, index, arr) => (
                      <span key={`${hop}-${index}`} className="inline-flex items-center gap-2">
                        <span className="rounded border border-blue-400/20 bg-blue-500/[0.07] px-1.5 py-0.5">{hop.trim()}</span>
                        {index < arr.length - 1 ? <ArrowRight className="h-3 w-3 text-white/25" /> : null}
                      </span>
                    ))}
                  </div>
                  <div className="mt-2 flex items-center gap-3 text-[10px] text-white/45">
                    <span>
                      Blast radius: <span className="font-mono font-bold text-white/70">{chain.blastRadius}</span>
                    </span>
                    <Badge color={severityColor(chain.complexity)}>{chain.complexity} complexity</Badge>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-1.5 text-[11px] text-white/45">
              <span className="font-bold text-white/60">Failure points:</span>
              {deps.failurePoints.map((point) => (
                <span key={point} className="rounded border border-red-400/20 bg-red-500/[0.07] px-1.5 py-0.5 text-[10px] font-semibold text-red-200/80">
                  {point}
                </span>
              ))}
            </div>
          </Panel>

          {/* Prioritization + algorithm targets */}
          <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
            <Panel className="p-5 xl:col-span-7">
              <SectionTitle suffix={<span className="text-[11px] text-white/40">Sequenced by evidence — wave membership, risk, criticality</span>}>Asset Prioritization</SectionTitle>
              {model.assetReadiness.length ? (
                <div className="overflow-x-auto">
                  <table className="min-w-[680px] w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                        <th className="pb-3 font-black">#</th>
                        <th className="pb-3 font-black">Asset</th>
                        <th className="pb-3 font-black">Criticality</th>
                        <th className="pb-3 font-black">Risk</th>
                        <th className="pb-3 font-black">PQC Status</th>
                        <th className="pb-3 font-black">HNDL</th>
                        <th className="pb-3 font-black">Primary Driver</th>
                        <th className="pb-3 font-black">Wave</th>
                      </tr>
                    </thead>
                    <tbody>
                      {model.assetReadiness.map((asset, index) => {
                        const wave = waveForAsset(asset.asset, asset.risk, waves);
                        const waveColor = WAVE_COLORS[(wave - 1) % WAVE_COLORS.length];
                        return (
                          <tr key={`${asset.asset}-${index}`} className="border-b border-white/5 text-white/70">
                            <td className="py-2.5 font-mono text-white/45">{index + 1}</td>
                            <td className="max-w-[170px] truncate py-2.5 font-medium text-white/82">{asset.asset}</td>
                            <td className="py-2.5">
                              <Badge color={severityColor(asset.criticality)}>{asset.criticality}</Badge>
                            </td>
                            <td className="py-2.5 font-mono font-bold" style={{ color: riskTone(asset.risk) }}>
                              {integerFmt(asset.risk)}
                            </td>
                            <td className="max-w-[130px] truncate py-2.5 text-white/60">{asset.pqcStatus}</td>
                            <td className="max-w-[120px] truncate py-2.5 text-white/60">{asset.hndlExposure}</td>
                            <td className="max-w-[190px] truncate py-2.5 text-white/55">{asset.primaryDriver}</td>
                            <td className="py-2.5">
                              <span className="rounded px-1.5 py-0.5 text-[10px] font-black" style={{ color: waveColor, backgroundColor: `${waveColor}1a` }}>
                                W{wave}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <EmptyState label="No assets to prioritize." hint="Connect an asset inventory to sequence migration." />
              )}
            </Panel>

            <Panel className="p-5 xl:col-span-5">
              <SectionTitle suffix={<Badge color={EMERALD}>{model.cryptoPolicy.activeProfile} profile</Badge>}>Target Algorithm Recommendations</SectionTitle>
              <p className="mb-3 text-[11px] leading-snug text-white/45">
                Detected quantum-vulnerable cryptography mapped to its policy-driven target state. Targets resolve through the active crypto-policy profile (NIST FIPS 203/204/205) — never a hard-coded universal algorithm.
              </p>
              {model.playbookDetail.length ? (
                <div className="space-y-2.5">
                  {model.playbookDetail.slice(0, 5).map((playbook) => (
                    <div key={playbook.finding} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
                      <div className="text-[10px] font-bold uppercase tracking-wide text-white/40">{playbook.finding}</div>
                      <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs">
                        <span className="max-w-full break-words font-mono text-[11px] text-white/55 line-through decoration-red-400/60">{playbook.currentState}</span>
                        <GitBranch className="h-3.5 w-3.5 shrink-0 text-white/30" />
                        <span className="max-w-full break-words font-mono text-[11px] font-bold text-emerald-300">{playbook.targetState}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState label="No quantum-vulnerable findings to map." hint="Run a discovery scan to derive algorithm targets." />
              )}
            </Panel>
          </section>

          {/* Rollback + compatibility + handoff */}
          <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
            <Panel className="p-5 xl:col-span-7">
              <SectionTitle suffix={<RotateCcw className="h-4 w-4 text-white/40" />}>Rollback Strategy</SectionTitle>
              <p className="mb-3 text-[11px] leading-snug text-white/45">
                Per-finding rollback runbooks with change-management execution fields — derived from the change class of each finding family, identical to the Enterprise Remediation Playbook™ in the reports.
              </p>
              {model.playbookDetail.length ? (
                <div className="space-y-3">
                  {model.playbookDetail.slice(0, 4).map((playbook, index) => (
                    <div key={playbook.finding} className="rounded-md border border-white/8 bg-black/20 p-3.5">
                      <div className="flex items-start gap-3">
                        <span className="grid h-6 w-6 shrink-0 place-items-center rounded border border-blue-400/30 bg-blue-500/10 text-[11px] font-black text-blue-300">{index + 1}</span>
                        <div className="min-w-0 flex-1">
                          <div className="text-xs font-bold text-white/85">{playbook.finding}</div>
                          <ol className="mt-1.5 space-y-0.5 text-[11px] leading-snug text-white/55">
                            {playbook.rollbackSteps.map((step, stepIndex) => (
                              <li key={step}>
                                {stepIndex + 1}. {step}
                              </li>
                            ))}
                          </ol>
                          <div className="mt-2 flex flex-wrap gap-1.5 text-[9px]">
                            {[
                              `Rollback ${playbook.rollbackDuration}`,
                              `Downtime ${playbook.estimatedDowntime}`,
                              `Window: ${playbook.maintenanceWindow}`,
                              `Validation: ${playbook.validationOwner}`,
                              `SLA: ${playbook.slaImpact}`,
                            ].map((chip) => (
                              <span key={chip} className="rounded border border-white/10 bg-white/[0.03] px-1.5 py-0.5 font-semibold text-white/50">
                                {chip}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState label="No rollback runbooks yet." hint="Rollback plans derive from detected finding families." />
              )}
            </Panel>

            <div className="space-y-4 xl:col-span-5">
              <Panel className="p-5">
                <SectionTitle suffix={<AlertTriangle className="h-4 w-4 text-amber-300" />}>Compatibility Considerations</SectionTitle>
                {compatibility.length ? (
                  <div className="space-y-2.5">
                    {compatibility.map((warn) => {
                      const color = warn.level === 'high' ? ORANGE : GOLD;
                      return (
                        <div key={warn.text} className="rounded-md border p-3" style={{ borderColor: `${color}30`, backgroundColor: `${color}0d` }}>
                          <div className="flex items-start gap-2.5">
                            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" style={{ color }} />
                            <div>
                              <span className="text-xs leading-snug text-white/70">{warn.text}</span>
                              <div className="mt-1 text-[10px] font-semibold text-emerald-200/70">Evidence: {warn.evidence}</div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <EmptyState label="No compatibility risks derived from current evidence." />
                )}
              </Panel>

              <Panel className="p-5">
                <SectionTitle suffix={<BadgeCheck className="h-4 w-4 text-emerald-400" />}>Hand Off This Roadmap</SectionTitle>
                <p className="mb-3 text-[11px] leading-snug text-white/50">
                  Hands off exactly what is displayed: {waves.length} wave(s), readiness progression, dependency chains, {model.assetReadiness.length} prioritized asset(s) and {model.playbookDetail.length} rollback runbook(s).
                </p>
                <div className="flex flex-col gap-2.5">
                  <PrimaryButton icon={Rocket} onClick={() => handoff('planner')}>
                    Send to Migration Planner
                  </PrimaryButton>
                  <HeaderButton icon={FlaskConical} onClick={() => handoff('sandbox')}>
                    Open in Migration Sandbox
                  </HeaderButton>
                  <HeaderButton icon={Download} onClick={exportRoadmap}>
                    Export Roadmap JSON
                  </HeaderButton>
                </div>
                {handoffNote ? <p className="mt-2 text-[11px] font-semibold text-emerald-200/80">{handoffNote}</p> : null}
                <p className="mt-3 text-[10px] leading-snug text-white/35">
                  Generated {longDate(model.meta.generatedAt)} · engine self-validation {model.reportValidation.overall} · forecast confidence {model.confidenceSummary.migrationForecastConfidencePct}%
                </p>
              </Panel>
            </div>
          </section>
        </>
      ) : (
        <Panel className="p-10">
          <div className="flex flex-col items-center justify-center gap-4 text-center">
            <span className="grid h-16 w-16 place-items-center rounded-full border border-orange-400/30 bg-orange-500/10 text-orange-300">
              <BrainCircuit className="h-8 w-8" />
            </span>
            <div>
              <div className="text-base font-bold text-white">{snapshot.hasData ? 'Generate a migration roadmap' : 'Assessment evidence required'}</div>
              <p className="mx-auto mt-1 max-w-md text-sm text-white/55">
                {snapshot.hasData
                  ? 'Produce dependency-aware migration waves, evidence-sequenced asset prioritization, policy-driven algorithm targets and per-finding rollback runbooks — reconciled with the enterprise report engine.'
                  : 'Run a discovery scan first — the advisor sequences migration from real asset and risk evidence.'}
              </p>
            </div>
            {snapshot.hasData ? (
              <PrimaryButton icon={BrainCircuit} onClick={generate} disabled={generating}>
                {generating ? 'Generating…' : 'Generate Migration Advisory'}
              </PrimaryButton>
            ) : null}
          </div>
        </Panel>
      )}
    </QuantumReadinessShell>
  );
}
