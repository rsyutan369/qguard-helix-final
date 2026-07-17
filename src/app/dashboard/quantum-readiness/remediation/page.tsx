'use client';

import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowRight,
  Award,
  Bot,
  Building2,
  CalendarClock,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  ClipboardList,
  ExternalLink,
  Gauge,
  ListChecks,
  Network,
  Radar,
  RefreshCw,
  Replace,
  Route as RouteIcon,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
  Wrench,
  XCircle,
  Zap,
} from 'lucide-react';
import { useQuantumRemediation } from '@/hooks/use-quantum-remediation';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import type { RemediationAction, RemediationPriority } from '@/types/quantum-remediation';
import {
  Badge,
  BarList,
  EmptyState,
  HeaderButton,
  MetricCard,
  Panel,
  QuantumReadinessSubnav,
  Ring,
  SectionTitle,
  TrendChart,
  integerFmt,
  longDate,
  relativeTime,
  AMBER,
  BLUE,
  CYAN,
  EMERALD,
  GOLD,
  GREEN,
  ORANGE,
  RED,
  SLATE,
  VIOLET,
} from '../_shared';

const PRIORITY_META: Record<RemediationPriority, { color: string; label: string }> = {
  critical: { color: RED, label: 'Critical' },
  high: { color: ORANGE, label: 'High' },
  medium: { color: AMBER, label: 'Medium' },
  low: { color: SLATE, label: 'Low' },
};

const EFFORT_COLORS: Record<string, string> = { low: EMERALD, medium: AMBER, high: ORANGE };

type QueueFilter = RemediationPriority | 'all' | 'quick-wins';

function readinessColor(pct: number): string {
  if (pct >= 100) return EMERALD;
  if (pct >= 75) return GREEN;
  if (pct >= 50) return AMBER;
  if (pct >= 25) return ORANGE;
  return RED;
}

function severityBadgeColor(severity: string): string {
  const s = severity.toLowerCase();
  if (s.includes('critical')) return RED;
  if (s.includes('high')) return ORANGE;
  if (s.includes('low')) return SLATE;
  return AMBER;
}

export default function QuantumRemediationPage() {
  const { plan, state, error, sseConnected, refresh } = useQuantumRemediation();
  const [queue, setQueue] = useState<QueueFilter>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [advisorOpen, setAdvisorOpen] = useState<number | null>(0);

  const quickWinSet = useMemo(() => new Set(plan.quickWins), [plan.quickWins]);
  const filteredActions = useMemo(() => {
    if (queue === 'all') return plan.actions;
    if (queue === 'quick-wins') return plan.actions.filter((a) => quickWinSet.has(a.id));
    return plan.actions.filter((a) => a.priority === queue);
  }, [plan.actions, queue, quickWinSet]);

  const unmetRequirements = plan.requirements.filter((r) => r.status === 'unmet');
  const metRequirements = plan.requirements.filter((r) => r.status === 'met');
  const scoreColor = readinessColor(plan.certificationReadinessPct);
  const finalLadderPct = plan.ladder.length ? plan.ladder[plan.ladder.length - 1].readinessPct : plan.certificationReadinessPct;
  const vendorSet = useMemo(() => new Set(plan.vendorActions), [plan.vendorActions]);
  const replacementSet = useMemo(() => new Set(plan.replacementsRequired), [plan.replacementsRequired]);
  const blockerActions = plan.criticalBlockers
    .map((id) => plan.actions.find((a) => a.id === id))
    .filter((a): a is RemediationAction => Boolean(a));

  return (
    <div className="min-h-screen bg-[#030711] px-4 py-5 text-white sm:px-5 lg:px-6">
      <div className="mx-auto max-w-[1560px] space-y-4">
        <QuantumReadinessSubnav />
        <WorkflowRail activeStage="remediation" />

        {/* Header */}
        <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <Wrench className="h-6 w-6 text-cyan-300" />
              <h1 className="text-2xl font-semibold tracking-normal text-white">Intelligent Quantum Remediation Engine™</h1>
              <Badge color={CYAN}>Q-REMEDY v{plan.methodology.version || '1.0.0'}</Badge>
              {sseConnected ? <Badge color={EMERALD}>Live</Badge> : null}
            </div>
            <p className="mt-1 max-w-3xl text-sm text-white/58">
              Here’s exactly how to become Quantum Ready: every discovered asset analyzed, every vulnerability mapped to a
              NIST-aligned remediation action, and the live Certification Readiness Score™ projected after each fix — until
              the Quantum Trust Certification™ unlocks.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>
              Refresh
            </HeaderButton>
            <Link to="/dashboard/scanner" className="no-underline">
              <HeaderButton icon={Radar}>Rescan Environment</HeaderButton>
            </Link>
            <Link to="/dashboard/quantum-certification" className="no-underline">
              <HeaderButton icon={Award}>Certification Engine</HeaderButton>
            </Link>
          </div>
        </header>

        {error && state === 'error' ? (
          <div className="rounded-md border border-red-400/30 bg-red-400/[0.08] px-4 py-3 text-sm text-red-100/90">
            Failed to load the remediation engine: {error}
          </div>
        ) : null}

        {!plan.hasData && state === 'success' ? (
          <Panel className="p-6">
            <div className="flex flex-col items-start gap-3">
              <Badge color={AMBER}>No assessment evidence yet</Badge>
              <p className="max-w-2xl text-sm text-white/65">
                The remediation roadmap is generated from measured evidence, never asserted. Run a PQC discovery scan to
                populate the Quantum Readiness Assessment Engine™ — the engine will then analyze every discovered asset and
                produce your step-by-step path to certification.
              </p>
              <Link to="/dashboard/scanner" className="no-underline">
                <HeaderButton icon={Radar}>Run your first discovery scan</HeaderButton>
              </Link>
            </div>
          </Panel>
        ) : null}

        {/* Hero — live Certification Readiness Score */}
        <div className="grid gap-3 xl:grid-cols-[minmax(320px,380px)_1fr]">
          <Panel className="p-5">
            <SectionTitle>Certification Readiness Score™</SectionTitle>
            <div className="flex items-center gap-5">
              <Ring value={plan.certificationReadinessPct} color={scoreColor} size={128} stroke={12}>
                <div>
                  <div className="text-3xl font-semibold text-white">{plan.certificationReadinessPct}%</div>
                  <div className="text-[9px] font-bold uppercase tracking-wide text-white/45">to certification</div>
                </div>
              </Ring>
              <div className="min-w-0 space-y-2">
                <div className="flex items-center gap-2">
                  {plan.certificationEligible ? (
                    <ShieldCheck className="h-5 w-5 shrink-0 text-emerald-300" />
                  ) : (
                    <ShieldAlert className="h-5 w-5 shrink-0 text-amber-300" />
                  )}
                  <span className="text-sm font-bold" style={{ color: plan.certificationEligible ? EMERALD : AMBER }}>
                    {plan.certificationEligible ? 'Certification Eligible' : 'Not Yet Eligible'}
                  </span>
                </div>
                <div className="text-xs text-white/60">
                  {plan.requiredMet}/{plan.requiredTotal} required criteria met · Trust score {integerFmt(plan.trustScore)}/1000
                </div>
                <div className="text-xs text-white/60">
                  {plan.certificationEligible ? (
                    <>Issue the certificate from the Certification Engine.</>
                  ) : plan.estimatedCertificationDate ? (
                    <>
                      Estimated certification date:{' '}
                      <span className="font-bold text-cyan-200">{longDate(plan.estimatedCertificationDate)}</span> (~
                      {integerFmt(plan.estimatedCompletionWeeks)} wk across {plan.parallelWorkstreams} workstream
                      {plan.parallelWorkstreams === 1 ? '' : 's'})
                    </>
                  ) : (
                    <>Run a scan to generate a certification timeline.</>
                  )}
                </div>
                <div className="flex flex-wrap gap-1.5 pt-1">
                  <Badge color={RED}>{plan.queues.critical} critical</Badge>
                  <Badge color={ORANGE}>{plan.queues.high} high</Badge>
                  <Badge color={AMBER}>{plan.queues.medium} medium</Badge>
                  <Badge color={SLATE}>{plan.queues.low} low</Badge>
                </div>
              </div>
            </div>
          </Panel>

          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <MetricCard
              label="Quantum Readiness"
              value={integerFmt(plan.quantumReadiness)}
              suffix="/100"
              detail="QR Assessment Engine snapshot"
              color={readinessColor(plan.quantumReadiness)}
              ring={plan.quantumReadiness}
            />
            <MetricCard
              label="Remaining Vulnerabilities"
              value={integerFmt(plan.remainingVulnerabilities.total)}
              detail={`${plan.remainingVulnerabilities.critical} critical · ${plan.remainingVulnerabilities.high} high`}
              color={plan.remainingVulnerabilities.total > 0 ? RED : EMERALD}
              icon={AlertTriangle}
            />
            <MetricCard
              label="Remediation Actions"
              value={integerFmt(plan.progress.totalActions)}
              detail={`${plan.progress.openActions} open · ${plan.progress.inProgressActions} in progress`}
              color={BLUE}
              icon={ClipboardList}
            />
            <MetricCard
              label="Quick Wins"
              value={integerFmt(plan.quickWins.length)}
              detail="High certification gain, low effort"
              color={GOLD}
              icon={Zap}
            />
          </div>
        </div>

        {/* Automation opportunities — orchestrate automatable playbooks via Live Migration */}
        {plan.hasData && plan.actions.some((a) => a.automatable && a.status !== 'resolved') ? (
          <div className="flex flex-col gap-3 rounded-md border border-emerald-400/25 bg-emerald-400/[0.05] px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-2.5 text-sm text-emerald-100/90">
              <Zap className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
              <span>
                <strong className="font-bold">
                  {plan.actions.filter((a) => a.automatable && a.status !== 'resolved').length} of {plan.progress.totalActions} actions
                </strong>{' '}
                follow automatable playbooks (TLS hybrid rollout, SSH KEX, certificate rotation, KMS re-wrap, cloud
                configuration). Orchestrate them through managed agents with validation and rollback.
              </span>
            </div>
            <Link to="/dashboard/live-migration" className="shrink-0 no-underline">
              <HeaderButton icon={RouteIcon}>Open Live Migration Ops</HeaderButton>
            </Link>
          </div>
        ) : null}

        {/* Readiness Projection Ladder */}
        <Panel className="p-5">
          <SectionTitle
            suffix={
              <span className="text-[11px] text-white/40">
                Q-REMEDY marginal-gain simulation · projects to {finalLadderPct}%
              </span>
            }
          >
            Readiness Projection Ladder™
          </SectionTitle>
          {plan.ladder.length ? (
            <div className="space-y-2.5">
              {plan.ladder.map((step, index) => {
                const isFirst = index === 0;
                const isLast = index === plan.ladder.length - 1;
                const color = isFirst ? CYAN : isLast ? (step.readinessPct >= 100 ? EMERALD : AMBER) : BLUE;
                return (
                  <div key={`${step.stage}-${index}`} className="grid grid-cols-[minmax(150px,220px)_1fr_auto] items-center gap-3 text-xs">
                    <div className="min-w-0">
                      <div className="truncate font-bold" style={{ color }}>
                        {step.stage}
                      </div>
                      <div className="truncate text-[10px] text-white/45">{step.actionTitle}</div>
                    </div>
                    <div className="h-2.5 overflow-hidden rounded-full bg-white/5">
                      <div
                        className="h-full rounded-full transition-all duration-700"
                        style={{ width: `${Math.min(100, step.readinessPct)}%`, backgroundColor: color }}
                      />
                    </div>
                    <div className="flex items-center gap-2 text-right">
                      <span className="w-12 font-mono font-bold text-white">{step.readinessPct}%</span>
                      {step.gainPct > 0 ? <Badge color={EMERALD}>+{step.gainPct}%</Badge> : null}
                      {step.effortWeeks > 0 ? <span className="w-14 text-[10px] text-white/45">{step.effortWeeks} wk</span> : null}
                    </div>
                  </div>
                );
              })}
              <p className="pt-1 text-[11px] text-white/40">
                Projections are simulations over measured evidence — the live score only moves when a rescan verifies each
                remediation. {plan.ladder[plan.ladder.length - 1]?.detail}
              </p>
            </div>
          ) : (
            <EmptyState label="No projection available yet." hint="Run a discovery scan to generate the remediation ladder." />
          )}
        </Panel>

        {/* Certification requirements */}
        <Panel className="p-5">
          <SectionTitle
            suffix={
              <span className="text-[11px] text-white/40">
                {metRequirements.length} met · {unmetRequirements.length} unmet
              </span>
            }
          >
            Certification Requirements
          </SectionTitle>
          {plan.requirements.length ? (
            <div className="grid gap-3 lg:grid-cols-2">
              {[...unmetRequirements, ...metRequirements].map((req) => (
                <div
                  key={req.id}
                  className="rounded-md border p-4"
                  style={{
                    borderColor: req.status === 'unmet' ? `${RED}35` : `${EMERALD}30`,
                    backgroundColor: req.status === 'unmet' ? `${RED}08` : `${EMERALD}06`,
                  }}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                      {req.status === 'unmet' ? (
                        <XCircle className="h-4 w-4 shrink-0 text-red-300" />
                      ) : (
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-300" />
                      )}
                      <span className="text-sm font-bold text-white">{req.requirement}</span>
                    </div>
                    {req.status === 'unmet' && req.estimatedScoreIncreasePct > 0 ? (
                      <Badge color={EMERALD}>+{req.estimatedScoreIncreasePct}% score</Badge>
                    ) : null}
                  </div>
                  <p className="mt-2 text-xs text-white/60">{req.description}</p>
                  {req.status === 'unmet' ? (
                    <div className="mt-3 space-y-2 text-[11px]">
                      <div>
                        <span className="font-black uppercase tracking-wide text-white/40">Business impact — </span>
                        <span className="text-white/65">{req.businessImpact}</span>
                      </div>
                      <div>
                        <span className="font-black uppercase tracking-wide text-white/40">Technical impact — </span>
                        <span className="text-white/65">{req.technicalImpact}</span>
                      </div>
                      <div>
                        <span className="font-black uppercase tracking-wide text-white/40">Solution — </span>
                        <span className="text-white/65">{req.recommendedSolution}</span>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 pt-1">
                        {req.estimatedCompletionWeeks > 0 ? (
                          <Badge color={AMBER}>~{req.estimatedCompletionWeeks} wk</Badge>
                        ) : null}
                        {req.relatedAssets.length ? (
                          <Badge color={BLUE}>
                            {req.relatedAssets.length} asset{req.relatedAssets.length === 1 ? '' : 's'}
                          </Badge>
                        ) : null}
                        {req.relatedActionIds.length ? (
                          <Badge color={VIOLET}>
                            {req.relatedActionIds.length} action{req.relatedActionIds.length === 1 ? '' : 's'}
                          </Badge>
                        ) : null}
                        <Link
                          to={req.integration.route}
                          className="inline-flex items-center gap-1 text-[11px] font-bold text-cyan-300 no-underline hover:text-cyan-200"
                        >
                          {req.integration.label} <ArrowRight className="h-3 w-3" />
                        </Link>
                      </div>
                      {req.relatedAssets.length ? (
                        <div className="truncate pt-0.5 text-[10px] text-white/40">
                          Related: {req.relatedAssets.slice(0, 6).join(', ')}
                          {req.relatedAssets.length > 6 ? '…' : ''}
                        </div>
                      ) : null}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          ) : (
            <EmptyState label="Requirements appear once assessment evidence exists." />
          )}
        </Panel>

        {/* Priority queues + remediation actions */}
        <Panel className="p-5">
          <SectionTitle
            suffix={
              <span className="text-[11px] text-white/40">
                {filteredActions.length} of {plan.actions.length} action{plan.actions.length === 1 ? '' : 's'} shown
              </span>
            }
          >
            Asset-Level Remediation Queue
          </SectionTitle>
          <div className="-mx-1 mb-4 flex gap-1.5 overflow-x-auto pb-1">
            {(
              [
                { id: 'all' as QueueFilter, label: `All (${plan.actions.length})`, color: BLUE },
                { id: 'critical' as QueueFilter, label: `Critical (${plan.queues.critical})`, color: RED },
                { id: 'high' as QueueFilter, label: `High (${plan.queues.high})`, color: ORANGE },
                { id: 'medium' as QueueFilter, label: `Medium (${plan.queues.medium})`, color: AMBER },
                { id: 'low' as QueueFilter, label: `Low (${plan.queues.low})`, color: SLATE },
                { id: 'quick-wins' as QueueFilter, label: `Quick Wins (${plan.quickWins.length})`, color: GOLD },
              ]
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setQueue(tab.id)}
                className="whitespace-nowrap rounded-md border px-3 py-1.5 text-[11px] font-bold transition"
                style={
                  queue === tab.id
                    ? { borderColor: `${tab.color}60`, backgroundColor: `${tab.color}1f`, color: tab.color }
                    : { borderColor: 'rgba(255,255,255,0.08)', backgroundColor: 'rgba(0,0,0,0.2)', color: 'rgba(255,255,255,0.55)' }
                }
              >
                {tab.label}
              </button>
            ))}
          </div>

          {filteredActions.length ? (
            <div className="space-y-2">
              {filteredActions.map((action) => {
                const meta = PRIORITY_META[action.priority];
                const expanded = expandedId === action.id;
                return (
                  <div key={action.id} className="rounded-md border border-white/8 bg-black/20">
                    <button
                      type="button"
                      onClick={() => setExpandedId(expanded ? null : action.id)}
                      className="grid w-full grid-cols-[auto_1fr_auto] items-center gap-3 px-3 py-2.5 text-left"
                    >
                      <span
                        className="grid h-7 w-7 shrink-0 place-items-center rounded font-mono text-[11px] font-black"
                        style={{ color: meta.color, backgroundColor: `${meta.color}15`, border: `1px solid ${meta.color}40` }}
                      >
                        {action.rank}
                      </span>
                      <span className="min-w-0">
                        <span className="flex flex-wrap items-center gap-2">
                          <span className="truncate text-sm font-bold text-white">{action.asset}</span>
                          <Badge color={meta.color}>{meta.label}</Badge>
                          <Badge color={CYAN}>{action.domainLabel}</Badge>
                          {quickWinSet.has(action.id) ? <Badge color={GOLD}>Quick win</Badge> : null}
                          {action.status === 'in_progress' ? <Badge color={BLUE}>In progress</Badge> : null}
                          {replacementSet.has(action.id) ? <Badge color={RED}>Replacement required</Badge> : null}
                          {vendorSet.has(action.id) ? <Badge color={VIOLET}>Third party</Badge> : null}
                        </span>
                        <span className="mt-0.5 block truncate text-xs text-white/55">{action.problem}</span>
                      </span>
                      <span className="flex shrink-0 items-center gap-3 text-right">
                        <span className="hidden sm:block">
                          <span className="block text-[10px] font-black uppercase tracking-wide text-white/40">Cert gain</span>
                          <span className="font-mono text-sm font-bold text-emerald-300">+{action.certificationGainPct}%</span>
                        </span>
                        <span className="hidden md:block">
                          <span className="block text-[10px] font-black uppercase tracking-wide text-white/40">Effort</span>
                          <span className="font-mono text-sm font-bold" style={{ color: EFFORT_COLORS[action.effort] }}>
                            {action.effortWeeks} wk
                          </span>
                        </span>
                        {expanded ? <ChevronUp className="h-4 w-4 text-white/45" /> : <ChevronDown className="h-4 w-4 text-white/45" />}
                      </span>
                    </button>

                    {expanded ? (
                      <div className="space-y-4 border-t border-white/8 px-4 py-4 text-xs">
                        <div className="grid gap-4 lg:grid-cols-2">
                          <div className="space-y-3">
                            <div>
                              <div className="mb-1 font-black uppercase tracking-wide text-white/40">Why this asset is not quantum ready</div>
                              <ul className="space-y-1 text-white/65">
                                {action.whyNotReady.map((reason, i) => (
                                  <li key={i} className="flex gap-2">
                                    <span className="text-red-300">•</span>
                                    <span>{reason}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                            <div>
                              <div className="mb-1 font-black uppercase tracking-wide text-white/40">Risk</div>
                              <p className="text-white/65">{action.risk}</p>
                            </div>
                            <div className="grid grid-cols-2 gap-3">
                              <div>
                                <div className="mb-1 font-black uppercase tracking-wide text-white/40">Current state</div>
                                <p className="font-mono text-red-200/90">{action.currentState}</p>
                              </div>
                              <div>
                                <div className="mb-1 font-black uppercase tracking-wide text-white/40">Target state</div>
                                <p className="font-mono text-emerald-200/90">{action.targetState}</p>
                              </div>
                            </div>
                            <div className="flex flex-wrap gap-1.5">
                              {action.standards.map((standard) => (
                                <span key={standard}>
                                  <Badge color={BLUE}>{standard}</Badge>
                                </span>
                              ))}
                            </div>
                            {action.findings.length ? (
                              <div>
                                <div className="mb-1 font-black uppercase tracking-wide text-white/40">Evidence ({action.findings.length})</div>
                                <div className="space-y-1">
                                  {action.findings.slice(0, 6).map((finding) => (
                                    <div key={finding.id || finding.algorithm} className="flex flex-wrap items-center gap-2 text-white/60">
                                      <span className="font-mono text-white/80">{finding.algorithm}</span>
                                      <span className="text-white/40">{finding.category}</span>
                                      <Badge color={severityBadgeColor(finding.severity)}>{finding.severity}</Badge>
                                      {finding.instances > 1 ? <span className="text-white/40">{finding.instances}×</span> : null}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            ) : null}
                          </div>

                          <div className="space-y-3">
                            <div>
                              <div className="mb-1 font-black uppercase tracking-wide text-white/40">Remediation plan</div>
                              <p className="mb-2 font-bold text-cyan-200">{action.recommendation}</p>
                              <ol className="space-y-1.5 text-white/65">
                                {action.steps.map((step, i) => (
                                  <li key={i} className="flex gap-2">
                                    <span className="font-mono font-bold text-cyan-300/80">{i + 1}.</span>
                                    <span>{step}</span>
                                  </li>
                                ))}
                              </ol>
                            </div>
                            <div className="grid grid-cols-2 gap-3">
                              <div>
                                <div className="mb-1 font-black uppercase tracking-wide text-white/40">Downtime</div>
                                <p className="text-white/65">{action.estimatedDowntime}</p>
                              </div>
                              <div>
                                <div className="mb-1 font-black uppercase tracking-wide text-white/40">Rollback</div>
                                <p className="text-white/65">{action.rollback}</p>
                              </div>
                            </div>
                            {action.breakingChangeWarning ? (
                              <div className="rounded border border-amber-400/30 bg-amber-400/[0.07] px-3 py-2 text-amber-100/85">
                                <AlertTriangle className="mr-1.5 inline h-3.5 w-3.5" />
                                {action.breakingChangeWarning}
                              </div>
                            ) : null}
                            {action.blastRadius.degree > 0 ? (
                              <div>
                                <div className="mb-1 font-black uppercase tracking-wide text-white/40">
                                  <Network className="mr-1 inline h-3.5 w-3.5" />
                                  Blast radius ({action.blastRadius.degree} relationship{action.blastRadius.degree === 1 ? '' : 's'})
                                </div>
                                {action.blastRadius.dependents.length ? (
                                  <p className="text-white/60">
                                    <span className="text-white/40">May break: </span>
                                    {action.blastRadius.dependents.join(', ')}
                                  </p>
                                ) : null}
                                {action.blastRadius.dependencies.length ? (
                                  <p className="text-white/60">
                                    <span className="text-white/40">Sequence first: </span>
                                    {action.blastRadius.dependencies.join(', ')}
                                  </p>
                                ) : null}
                                {action.blastRadius.vendorParties.length ? (
                                  <p className="text-white/60">
                                    <span className="text-white/40">Third parties affected: </span>
                                    {action.blastRadius.vendorParties.join(', ')}
                                  </p>
                                ) : null}
                              </div>
                            ) : null}
                            <div>
                              <div className="mb-1 font-black uppercase tracking-wide text-white/40">Priority factors ({action.priorityScore}/100)</div>
                              <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                                {action.priorityBreakdown.map((factor) => (
                                  <div key={factor.factor} className="flex items-center justify-between gap-2 text-[11px]">
                                    <span className="truncate text-white/50">{factor.factor}</span>
                                    <span className="font-mono text-white/70">
                                      {factor.score} <span className="text-white/35">×{factor.weightPct}%</span>
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                            <div className="flex flex-wrap items-center gap-2 pt-1">
                              <Link to={action.integration.route} className="no-underline">
                                <HeaderButton icon={ExternalLink}>{action.integration.label}</HeaderButton>
                              </Link>
                              <Link to="/dashboard/migration-sandbox" className="no-underline">
                                <HeaderButton icon={RouteIcon}>Validate in Sandbox</HeaderButton>
                              </Link>
                              <span className="text-[10px] text-white/40">
                                Owner: {action.owner} · {action.environment} · {action.statusEvidence}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    ) : null}
                  </div>
                );
              })}
            </div>
          ) : (
            <EmptyState
              label={plan.hasData ? 'No actions in this queue.' : 'No remediation actions yet.'}
              hint={plan.hasData ? 'Every queue is clear — rescan to verify.' : 'Run a discovery scan to generate the remediation queue.'}
            />
          )}
        </Panel>

        {/* Blockers + progress + assets by risk */}
        <div className="grid gap-3 xl:grid-cols-3">
          <Panel className="p-5">
            <SectionTitle suffix={<AlertTriangle className="h-4 w-4 text-red-300" />}>Critical Blockers</SectionTitle>
            {blockerActions.length ? (
              <div className="space-y-2.5">
                {blockerActions.map((action) => (
                  <button
                    key={action.id}
                    type="button"
                    onClick={() => {
                      setQueue('all');
                      setExpandedId(action.id);
                    }}
                    className="w-full rounded-md border border-red-400/20 bg-red-400/[0.05] px-3 py-2 text-left transition hover:border-red-400/45"
                  >
                    <div className="truncate text-xs font-bold text-white">{action.asset}</div>
                    <div className="truncate text-[11px] text-white/55">{action.problem}</div>
                    <div className="mt-1 flex items-center gap-2 text-[10px] text-white/45">
                      <Badge color={RED}>{action.priorityScore}/100</Badge>
                      <span>+{action.certificationGainPct}% cert readiness</span>
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <EmptyState label="No critical blockers." hint="Nothing in the critical queue — keep evidence current." />
            )}
          </Panel>

          <Panel className="p-5">
            <SectionTitle suffix={<TrendingUp className="h-4 w-4 text-emerald-300" />}>Remediation Progress</SectionTitle>
            <div className="mb-4 flex items-center gap-4">
              <Ring value={plan.progress.completionPct} color={EMERALD} size={72} stroke={9}>
                <span className="text-sm font-bold text-white">{plan.progress.completionPct}%</span>
              </Ring>
              <div className="text-xs text-white/60">
                <div>{plan.progress.resolvedActions} completed migration job{plan.progress.resolvedActions === 1 ? '' : 's'}</div>
                <div>{plan.progress.migrationJobsRunning} running now</div>
                <div>{plan.progress.openActions} action{plan.progress.openActions === 1 ? '' : 's'} remaining</div>
              </div>
            </div>
            <div className="mb-1 text-[10px] font-black uppercase tracking-wide text-white/40">Recently fixed</div>
            {plan.progress.recentlyFixed.length ? (
              <div className="space-y-1.5">
                {plan.progress.recentlyFixed.slice(0, 5).map((fix, i) => (
                  <div key={i} className="flex items-start gap-2 text-[11px]">
                    <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-300" />
                    <div className="min-w-0">
                      <div className="truncate text-white/70">{fix.title}</div>
                      <div className="text-white/40">{relativeTime(fix.completedAt)}</div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-[11px] text-white/40">No completed migration jobs recorded yet.</p>
            )}
            <div className="mb-1 mt-3 text-[10px] font-black uppercase tracking-wide text-white/40">Upcoming tasks</div>
            {plan.progress.upcomingTasks.length ? (
              <div className="space-y-1.5">
                {plan.progress.upcomingTasks.slice(0, 5).map((task) => (
                  <div key={task.actionId} className="flex items-center gap-2 text-[11px]">
                    <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: PRIORITY_META[task.priority].color }} />
                    <span className="min-w-0 flex-1 truncate text-white/65">{task.title}</span>
                    <span className="shrink-0 font-mono text-white/40">{task.effortWeeks} wk</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-[11px] text-white/40">Queue is clear.</p>
            )}
          </Panel>

          <Panel className="p-5">
            <SectionTitle suffix={<Gauge className="h-4 w-4 text-cyan-300" />}>Assets by Risk</SectionTitle>
            <BarList
              rows={plan.assetsByRisk.map((band) => ({ label: band.label, value: band.count }))}
              colorFor={(row) =>
                row.label.startsWith('Critical') ? RED : row.label.startsWith('High') ? ORANGE : row.label.startsWith('Elevated') ? AMBER : row.label.startsWith('Moderate') ? BLUE : EMERALD
              }
              max={Math.max(1, ...plan.assetsByRisk.map((b) => b.count))}
            />
            {plan.vendorActions.length || plan.replacementsRequired.length ? (
              <div className="mt-4 space-y-2 border-t border-white/8 pt-3 text-[11px] text-white/60">
                {plan.vendorActions.length ? (
                  <div className="flex items-center gap-2">
                    <Building2 className="h-3.5 w-3.5 text-violet-300" />
                    {plan.vendorActions.length} action{plan.vendorActions.length === 1 ? '' : 's'} require third-party / vendor coordination
                  </div>
                ) : null}
                {plan.replacementsRequired.length ? (
                  <div className="flex items-center gap-2">
                    <Replace className="h-3.5 w-3.5 text-red-300" />
                    {plan.replacementsRequired.length} system{plan.replacementsRequired.length === 1 ? '' : 's'} cannot support PQC and need replacement
                  </div>
                ) : null}
              </div>
            ) : null}
          </Panel>
        </div>

        {/* Readiness trend */}
        {plan.readinessTrend.length > 1 ? (
          <Panel className="p-5">
            <SectionTitle suffix={<span className="text-[11px] text-white/40">from completed scan sessions</span>}>
              Readiness Trend
            </SectionTitle>
            <TrendChart points={plan.readinessTrend} />
          </Panel>
        ) : null}

        {/* AI Quantum Advisor */}
        <Panel className="p-5">
          <SectionTitle suffix={<Bot className="h-4 w-4 text-violet-300" />}>AI Quantum Advisor™</SectionTitle>
          {plan.advisor.length ? (
            <div className="space-y-2">
              {plan.advisor.map((qa, index) => {
                const open = advisorOpen === index;
                return (
                  <div key={qa.question} className="rounded-md border border-white/8 bg-black/20">
                    <button
                      type="button"
                      onClick={() => setAdvisorOpen(open ? null : index)}
                      className="flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left"
                    >
                      <span className="text-sm font-bold text-white/85">{qa.question}</span>
                      {open ? <ChevronUp className="h-4 w-4 shrink-0 text-white/45" /> : <ChevronDown className="h-4 w-4 shrink-0 text-white/45" />}
                    </button>
                    {open ? (
                      <div className="space-y-2 border-t border-white/8 px-4 py-3 text-xs">
                        <p className="text-white/70">{qa.answer}</p>
                        {qa.evidence.length ? (
                          <div className="flex flex-wrap gap-1.5">
                            {qa.evidence.map((chip, i) => (
                              <span key={i} className="rounded border border-white/10 bg-white/[0.04] px-2 py-0.5 text-[10px] text-white/50">
                                {chip}
                              </span>
                            ))}
                          </div>
                        ) : null}
                        {qa.route ? (
                          <Link to={qa.route} className="inline-flex items-center gap-1 text-[11px] font-bold text-cyan-300 no-underline hover:text-cyan-200">
                            Open workflow <ArrowRight className="h-3 w-3" />
                          </Link>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                );
              })}
            </div>
          ) : (
            <EmptyState label="Advisor answers appear once assessment evidence exists." />
          )}
        </Panel>

        {/* Methodology */}
        <Panel className="p-5">
          <SectionTitle suffix={<ListChecks className="h-4 w-4 text-blue-300" />}>Methodology & Evidence Honesty</SectionTitle>
          <div className="grid gap-4 text-xs text-white/60 lg:grid-cols-2">
            <div className="space-y-3">
              <div>
                <div className="mb-1 font-black uppercase tracking-wide text-white/40">{plan.methodology.name}</div>
                <p>{plan.methodology.summary}</p>
              </div>
              <div>
                <div className="mb-1 font-black uppercase tracking-wide text-white/40">Certification Readiness Score</div>
                <p>{plan.methodology.scoreFormula}</p>
              </div>
              <div>
                <div className="mb-1 font-black uppercase tracking-wide text-white/40">Simulation model</div>
                <p>{plan.methodology.simulation}</p>
              </div>
              <div>
                <div className="mb-1 font-black uppercase tracking-wide text-white/40">Evidence honesty</div>
                <p>{plan.methodology.honesty}</p>
              </div>
            </div>
            <div>
              <div className="mb-2 font-black uppercase tracking-wide text-white/40">Priority factor weights</div>
              <BarList
                rows={plan.methodology.priorityFactors.map((factor) => ({ label: `${factor.factor} — ${factor.basis}`, value: factor.weightPct }))}
                colorFor={() => BLUE}
                max={25}
                unit="%"
              />
              {plan.criteria.length ? (
                <>
                  <div className="mb-2 mt-4 font-black uppercase tracking-wide text-white/40">Per-criterion progress</div>
                  <BarList
                    rows={plan.criteria.map((criterion) => ({ label: criterion.criterion, value: criterion.progressPct }))}
                    colorFor={(row) => (row.value >= 100 ? EMERALD : row.value >= 60 ? AMBER : RED)}
                    max={100}
                    unit="%"
                  />
                </>
              ) : null}
            </div>
          </div>
        </Panel>

        {/* Footer */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1 text-[11px] text-white/35">
          <span className="inline-flex items-center gap-2">
            <span
              className={`h-2 w-2 rounded-full ${sseConnected ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]' : 'animate-pulse bg-amber-300'}`}
            />
            {sseConnected ? 'Live remediation stream & evidence subscriptions connected' : 'Connecting live remediation stream'}
          </span>
          <span>
            <CalendarClock className="mr-1 inline h-3 w-3" />
            Plan generated: {longDate(plan.generatedAt || null)}
          </span>
        </div>
      </div>
    </div>
  );
}
